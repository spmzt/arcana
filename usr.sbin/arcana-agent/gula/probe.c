/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula, the tunnels: each target an address pinged again and again
 * (ICMP echo, as Mplify 119 §11.4 has an SD-WAN edge measure its
 * tunnels), from a thread of its own, through the routing table it
 * says.  Of each eval interval it keeps a sample: the one-way delay,
 * half the mean round trip (MEF 105 §7.2.4); the delay variation, the
 * mean difference between one round trip and the next; the loss; the
 * least and the most.  So many misses in a row and the target is down,
 * so many answers and it is up again, each an event (sdwan-tunnel).
 *
 * The targets come from the console (sdwan-probes, a JSON array), and
 * are kept in a file beside history.conf for the next start.  Each
 * says its id and address, and may say its fib, interval (ms), size
 * (bytes), count (0: without end), dscp, down and up (misses and
 * answers), timeout (ms), eval (ms), history (samples kept) and report.
 * A raw socket needs root: without it the target says so.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	PROBE_FILE	"sdwan-probes.json"
#define	TARGETS_MAX	256
#define	OUT_MAX		64	/* probes in the air, each */
#define	SAMPLES_MAX	100000
#define	PKT_MAX		10000

enum { ST_UNKNOWN = PROBE_UNKNOWN, ST_UP = PROBE_UP, ST_DOWN = PROBE_DOWN,
    ST_ENDED = PROBE_ENDED, ST_ERROR = PROBE_ERROR };
static const char *const state_names[] = { "unknown", "up", "down", "ended",
    "error" };

struct sample {
	double	t, delay, ipdv, loss, min, max;
	int	sent, recv;
};

struct target {
	char			 id[128];
	char			 address[64];
	int			 af;
	struct sockaddr_storage	 sa;
	int			 fib, interval, size, count, dscp, down, up;
	int			 timeout, eval, history, report;
	int			 sock;
	uint16_t		 ident, seq;
	struct {
		uint16_t	 seq;
		double		 sent;
		bool		 live;
	}			 out[OUT_MAX];
	int			 state;
	char			 error[128];
	int			 misses, hits;	/* in a row */
	uint64_t		 sent, received;
	double			 last_rtt;
	time_t			 since;
	double			 next_send, win_start;
	/* The eval interval in progress. */
	int			 w_sent, w_recv, w_ipdv_n;
	double			 w_sum, w_min, w_max, w_ipdv_sum, w_prev;
	bool			 w_has_prev;
	struct sample		*samples;
	int			 nsamples, head;
};

static pthread_mutex_t	 lock = PTHREAD_MUTEX_INITIALIZER;
static struct target	*targets;
static int		 ntargets;
static bool		 started;
static bool		 changed;	/* a state did, since the steering looked */

static double
now_s(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((double)ts.tv_sec + (double)ts.tv_nsec / 1e9);
}

static const char *
conf_path(char *buf, size_t len)
{
	const char	*slash;

	if ((slash = strrchr(opts.history_conf, '/')) != NULL)
		snprintf(buf, len, "%.*s/%s", (int)(slash - opts.history_conf),
		    opts.history_conf, PROBE_FILE);
	else
		snprintf(buf, len, "%s", PROBE_FILE);
	return (buf);
}

/* ---- One target --------------------------------------------------- */

static void
target_close(struct target *t)
{

	if (t->sock != -1)
		close(t->sock);
	t->sock = -1;
}

static void
target_free(struct target *t)
{

	target_close(t);
	free(t->samples);
	t->samples = NULL;
}

static uint16_t
cksum(const void *p, size_t len)
{
	const uint16_t	*w = p;
	uint32_t	 sum;

	sum = 0;
	while (len > 1) {
		sum += *w++;
		len -= 2;
	}
	if (len == 1)
		sum += *(const uint8_t *)w;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return ((uint16_t)~sum);
}

static bool
target_open(struct target *t)
{
	int	v;

	t->sock = socket(t->af, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    t->af == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6);
	if (t->sock == -1) {
		snprintf(t->error, sizeof(t->error), "socket: %s%s",
		    strerror(errno), errno == EPERM || errno == EACCES ?
		    " (probing needs root)" : "");
		return (false);
	}
	v = t->fib;
	if (setsockopt(t->sock, SOL_SOCKET, SO_SETFIB, &v, sizeof(v)) == -1) {
		snprintf(t->error, sizeof(t->error), "fib %d: %s", t->fib,
		    strerror(errno));
		target_close(t);
		return (false);
	}
	v = t->dscp << 2;
	if (t->af == AF_INET)
		(void)setsockopt(t->sock, IPPROTO_IP, IP_TOS, &v, sizeof(v));
	else {
		(void)setsockopt(t->sock, IPPROTO_IPV6, IPV6_TCLASS, &v,
		    sizeof(v));
		if (t->af == AF_INET6) {
			struct icmp6_filter	f;

			ICMP6_FILTER_SETBLOCKALL(&f);
			ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &f);
			(void)setsockopt(t->sock, IPPROTO_ICMPV6, ICMP6_FILTER,
			    &f, sizeof(f));
		}
	}
	t->error[0] = '\0';
	return (true);
}

static void
state_set(struct target *t, int state)
{
	char	id[300], *p;
	size_t	i;

	if (t->state == state)
		return;
	t->state = state;
	t->since = time(NULL);
	changed = true;
	if (state != ST_UP && state != ST_DOWN)
		return;
	/* Its id as JSON: a quote or a backslash in it escaped. */
	for (i = 0, p = id; t->id[i] != '\0' && p < id + sizeof(id) - 3; i++) {
		if (t->id[i] == '"' || t->id[i] == '\\')
			*p++ = '\\';
		*p++ = t->id[i];
	}
	*p = '\0';
	event_add("sdwan-tunnel", "{\"id\":\"%s\",\"address\":\"%s\",\"state\":"
	    "\"%s\",\"misses\":%d}", id, t->address, state_names[state],
	    t->misses);
	logmsg(state == ST_UP ? LOG_NOTICE : LOG_WARNING, "sdwan: %s (%s) is "
	    "%s", t->id, t->address, state_names[state]);
}

static void
window_end(struct target *t, double now)
{
	struct sample	*s;

	if (t->history <= 0)
		goto reset;
	if (t->samples == NULL && (t->samples = calloc((size_t)t->history,
	    sizeof(*t->samples))) == NULL)
		goto reset;
	s = &t->samples[(t->head + t->nsamples) % t->history];
	if (t->nsamples == t->history)
		t->head = (t->head + 1) % t->history;
	else
		t->nsamples++;
	s->t = (double)time(NULL);
	s->sent = t->w_sent;
	s->recv = t->w_recv;
	s->delay = t->w_recv > 0 ? t->w_sum / t->w_recv / 2 : 0;
	s->ipdv = t->w_ipdv_n > 0 ? t->w_ipdv_sum / t->w_ipdv_n : 0;
	s->loss = t->w_sent > 0 ? (double)(t->w_sent - t->w_recv) / t->w_sent :
	    0;
	s->min = t->w_recv > 0 ? t->w_min / 2 : 0;
	s->max = t->w_recv > 0 ? t->w_max / 2 : 0;
reset:
	t->w_sent = t->w_recv = t->w_ipdv_n = 0;
	t->w_sum = t->w_ipdv_sum = 0;
	t->w_min = t->w_max = 0;
	t->win_start = now;
}

static void
miss(struct target *t)
{

	t->w_sent++;
	t->hits = 0;
	if (++t->misses >= t->down && t->state != ST_DOWN)
		state_set(t, ST_DOWN);
}

static void
hit(struct target *t, double rtt_ms)
{

	t->w_sent++;
	t->w_recv++;
	t->received++;
	t->last_rtt = rtt_ms;
	t->w_sum += rtt_ms;
	if (t->w_recv == 1 || rtt_ms < t->w_min)
		t->w_min = rtt_ms;
	if (t->w_recv == 1 || rtt_ms > t->w_max)
		t->w_max = rtt_ms;
	if (t->w_has_prev) {
		t->w_ipdv_sum += rtt_ms > t->w_prev ? rtt_ms - t->w_prev :
		    t->w_prev - rtt_ms;
		t->w_ipdv_n++;
	}
	t->w_prev = rtt_ms;
	t->w_has_prev = true;
	t->misses = 0;
	if (++t->hits >= t->up && t->state != ST_UP)
		state_set(t, ST_UP);
}

static void
target_send(struct target *t, double now)
{
	unsigned char	pkt[PKT_MAX];
	size_t		len;
	int		i, slot;

	/* A slot: the oldest in the air gone, if none is free. */
	slot = -1;
	for (i = 0; i < OUT_MAX; i++)
		if (!t->out[i].live) {
			slot = i;
			break;
		}
	if (slot == -1) {
		slot = 0;
		for (i = 1; i < OUT_MAX; i++)
			if (t->out[i].sent < t->out[slot].sent)
				slot = i;
		miss(t);
	}
	len = (size_t)t->size;
	if (len < 8)
		len = 8;
	memset(pkt, 0, len);
	t->seq++;
	if (t->af == AF_INET) {
		struct icmp	*ic = (struct icmp *)(void *)pkt;

		ic->icmp_type = ICMP_ECHO;
		ic->icmp_code = 0;
		ic->icmp_id = htons(t->ident);
		ic->icmp_seq = htons(t->seq);
		ic->icmp_cksum = 0;
		ic->icmp_cksum = cksum(pkt, len);
	} else {
		struct icmp6_hdr	*ic = (struct icmp6_hdr *)(void *)pkt;

		ic->icmp6_type = ICMP6_ECHO_REQUEST;
		ic->icmp6_code = 0;
		ic->icmp6_id = htons(t->ident);
		ic->icmp6_seq = htons(t->seq);
	}
	t->out[slot].seq = t->seq;
	t->out[slot].sent = now;
	t->out[slot].live = true;
	t->sent++;
	if (sendto(t->sock, pkt, len, 0, (const struct sockaddr *)&t->sa,
	    t->sa.ss_len) == -1) {
		t->out[slot].live = false;
		miss(t);
		snprintf(t->error, sizeof(t->error), "sendto: %s",
		    strerror(errno));
	} else
		t->error[0] = '\0';
	if (t->count > 0 && t->sent >= (uint64_t)t->count)
		t->next_send = -1;
	else
		t->next_send = now + t->interval / 1000.0;
}

static void
target_recv(struct target *t, double now)
{
	unsigned char		 pkt[PKT_MAX + 64];
	struct sockaddr_storage	 from;
	socklen_t		 flen;
	ssize_t			 n;
	uint16_t		 id, seq;
	int			 i, hl;

	for (;;) {
		flen = sizeof(from);
		n = recvfrom(t->sock, pkt, sizeof(pkt), 0, (struct sockaddr *)
		    &from, &flen);
		if (n <= 0)
			return;
		if (t->af == AF_INET) {
			const struct ip		*ip = (const struct ip *)(void *)pkt;
			const struct icmp	*ic;

			hl = ip->ip_hl << 2;
			if (n < hl + ICMP_MINLEN)
				continue;
			ic = (const struct icmp *)(const void *)(pkt + hl);
			if (ic->icmp_type != ICMP_ECHOREPLY)
				continue;
			id = ntohs(ic->icmp_id);
			seq = ntohs(ic->icmp_seq);
		} else {
			const struct icmp6_hdr	*ic = (const struct icmp6_hdr *)
			    (void *)pkt;

			if (n < (ssize_t)sizeof(*ic) || ic->icmp6_type !=
			    ICMP6_ECHO_REPLY)
				continue;
			id = ntohs(ic->icmp6_id);
			seq = ntohs(ic->icmp6_seq);
		}
		if (id != t->ident)
			continue;
		for (i = 0; i < OUT_MAX; i++)
			if (t->out[i].live && t->out[i].seq == seq) {
				t->out[i].live = false;
				hit(t, (now - t->out[i].sent) * 1000);
				break;
			}
	}
}

/* Probes in the air too long are lost; an eval interval over is kept. */
static void
target_timers(struct target *t, double now)
{
	int	i;

	for (i = 0; i < OUT_MAX; i++)
		if (t->out[i].live && now - t->out[i].sent > t->timeout /
		    1000.0) {
			t->out[i].live = false;
			miss(t);
		}
	if (now - t->win_start >= t->eval / 1000.0)
		window_end(t, now);
	if (t->next_send < 0 && t->state != ST_ENDED && t->state != ST_ERROR) {
		bool	air = false;

		for (i = 0; i < OUT_MAX; i++)
			air = air || t->out[i].live;
		if (!air)
			state_set(t, ST_ENDED);
	}
}

/* ---- The thread --------------------------------------------------- */

static void *
prober(void *arg __unused)
{
	struct pollfd	*pfd;
	struct target	*t;
	double		 now, wait, d;
	int		 i, n, ms;
	bool		 moved;

	pfd = calloc(TARGETS_MAX, sizeof(*pfd));
	for (;;) {
		pthread_mutex_lock(&lock);
		now = now_s();
		wait = 0.2;
		n = 0;
		for (i = 0; i < ntargets; i++) {
			t = &targets[i];
			if (t->state == ST_ERROR && t->sock == -1 &&
			    !target_open(t))
				continue;
			if (t->state == ST_ERROR)
				state_set(t, ST_UNKNOWN);
			if (t->next_send >= 0 && t->next_send <= now)
				target_send(t, now);
			target_timers(t, now);
			if (t->next_send >= 0 && (d = t->next_send - now) < wait)
				wait = d;
			if ((d = t->win_start + t->eval / 1000.0 - now) < wait)
				wait = d;
			pfd[n].fd = t->sock;
			pfd[n].events = POLLIN;
			pfd[n].revents = 0;
			n++;
		}
		moved = changed;
		changed = false;
		pthread_mutex_unlock(&lock);
		/* A tunnel down or up: the steering made again, outside the
		 * lock, as it asks the states back. */
		if (moved)
			sdwan_probe_changed();
		ms = wait > 0 ? (int)(wait * 1000) : 0;
		if (poll(pfd, (nfds_t)n, ms < 1 ? 1 : ms) <= 0)
			continue;
		pthread_mutex_lock(&lock);
		now = now_s();
		n = 0;
		for (i = 0; i < ntargets; i++) {
			t = &targets[i];
			if (t->sock == -1)
				continue;
			if (pfd[n].fd == t->sock && (pfd[n].revents & POLLIN))
				target_recv(t, now);
			n++;
		}
		pthread_mutex_unlock(&lock);
	}
	return (NULL);
}

/* ---- The targets, as told ------------------------------------------ */

static int64_t
num(const ucl_object_t *o, const char *key, int64_t dflt, int64_t lo,
    int64_t hi, const char **errp)
{
	const ucl_object_t	*v;
	int64_t			 n;

	if ((v = ucl_object_lookup(o, key)) == NULL)
		return (dflt);
	if (ucl_object_type(v) != UCL_INT || (n = ucl_object_toint(v)) < lo ||
	    n > hi) {
		if (*errp == NULL)
			*errp = "bad";
		return (dflt);
	}
	return (n);
}

/*
 * The targets parsed from json into new (TARGETS_MAX at most); the
 * number, or -1 and why.
 */
static int
targets_parse(struct work *w, const char *json, struct target *new,
    const char **errp)
{
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*o, *v;
	ucl_object_iter_t	 it;
	struct target		*t;
	struct sockaddr_in	*s4;
	struct sockaddr_in6	*s6;
	const char		*id, *addr, *bad;
	int			 n, k;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	if (top == NULL || ucl_object_type(top) != UCL_ARRAY) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the targets are a JSON array";
		return (-1);
	}
	n = 0;
	it = NULL;
	while ((o = ucl_object_iterate(top, &it, true)) != NULL) {
		if (n == TARGETS_MAX) {
			*errp = wfmt(w, "%d targets at most", TARGETS_MAX);
			goto bad;
		}
		t = &new[n];
		memset(t, 0, sizeof(*t));
		t->sock = -1;
		id = (v = ucl_object_lookup(o, "id")) != NULL && ucl_object_type(
		    v) == UCL_STRING ? ucl_object_tostring(v) : NULL;
		addr = (v = ucl_object_lookup(o, "address")) != NULL &&
		    ucl_object_type(v) == UCL_STRING ? ucl_object_tostring(v) :
		    NULL;
		if (id == NULL || id[0] == '\0' || strlen(id) >= sizeof(t->id) ||
		    addr == NULL || strlen(addr) >= sizeof(t->address)) {
			*errp = "each target has an id and an address";
			goto bad;
		}
		for (k = 0; k < n; k++)
			if (strcmp(new[k].id, id) == 0) {
				*errp = wfmt(w, "target %s is there twice", id);
				goto bad;
			}
		snprintf(t->id, sizeof(t->id), "%s", id);
		snprintf(t->address, sizeof(t->address), "%s", addr);
		s4 = (struct sockaddr_in *)&t->sa;
		s6 = (struct sockaddr_in6 *)&t->sa;
		if (inet_pton(AF_INET, addr, &s4->sin_addr) == 1) {
			t->af = AF_INET;
			s4->sin_family = AF_INET;
			s4->sin_len = sizeof(*s4);
		} else if (inet_pton(AF_INET6, addr, &s6->sin6_addr) == 1) {
			t->af = AF_INET6;
			s6->sin6_family = AF_INET6;
			s6->sin6_len = sizeof(*s6);
		} else {
			*errp = wfmt(w, "target %s: %s is not an address", id,
			    addr);
			goto bad;
		}
		bad = NULL;
		t->fib = (int)num(o, "fib", 0, 0, 65535, &bad);
		t->interval = (int)num(o, "interval", 100, 10, 60000, &bad);
		t->size = (int)num(o, "size", 64, 8, PKT_MAX, &bad);
		t->count = (int)num(o, "count", 0, 0, INT32_MAX, &bad);
		t->dscp = (int)num(o, "dscp", 0, 0, 63, &bad);
		t->down = (int)num(o, "down", 3, 1, 100, &bad);
		t->up = (int)num(o, "up", 3, 1, 100, &bad);
		t->timeout = (int)num(o, "timeout", 1000, 10, 60000, &bad);
		t->eval = (int)num(o, "eval", 1000, 100, 86400000, &bad);
		t->history = (int)num(o, "history", 3600, 0, SAMPLES_MAX, &bad);
		t->report = (int)num(o, "report", 1, 1, 1000, &bad);
		if (bad != NULL) {
			*errp = wfmt(w, "target %s: fib, interval (10-60000 ms), "
			    "size (8-%d), count, dscp (0-63), down and up "
			    "(1-100), timeout (10-60000 ms), eval (100 ms or "
			    "more), history (0-%d) and report (1-1000) are "
			    "numbers in those bounds", id, PKT_MAX, SAMPLES_MAX);
			goto bad;
		}
		n++;
	}
	ucl_object_unref(top);
	return (n);
bad:
	ucl_object_unref(top);
	return (-1);
}

/*
 * The new targets in the old ones' place: one that is the same target
 * (address, fib, dscp, size) keeps its socket, state and samples.
 */
static void
targets_swap(struct target *new, int n)
{
	struct target	*old, *t, *o;
	int		 nold, i, k;
	double		 now;

	pthread_mutex_lock(&lock);
	old = targets;
	nold = ntargets;
	now = now_s();
	for (i = 0; i < n; i++) {
		t = &new[i];
		for (k = 0; k < nold; k++) {
			o = &old[k];
			if (o->id[0] != '\0' && strcmp(o->id, t->id) == 0 &&
			    strcmp(o->address, t->address) == 0 && o->fib ==
			    t->fib && o->dscp == t->dscp && o->size == t->size)
				break;
		}
		if (k < nold) {
			int	iv = t->interval, cnt = t->count, dn = t->down;
			int	up = t->up, to = t->timeout, ev = t->eval;
			int	hi = t->history, rp = t->report;

			/* As it was, with what may change under it. */
			*t = *o;
			memset(o, 0, sizeof(*o));
			o->sock = -1;
			t->interval = iv;
			t->count = cnt;
			t->down = dn;
			t->up = up;
			t->timeout = to;
			t->eval = ev;
			t->report = rp;
			if (t->history != hi) {
				free(t->samples);
				t->samples = NULL;
				t->nsamples = t->head = 0;
				t->history = hi;
			}
			if (t->state == ST_ENDED && cnt == 0) {
				t->next_send = now;
				state_set(t, ST_UNKNOWN);
			}
			continue;
		}
		t->ident = (uint16_t)((getpid() + i * 7919 + (int)now) & 0xffff);
		t->since = time(NULL);
		t->win_start = now;
		t->next_send = now;
		t->state = target_open(t) ? ST_UNKNOWN : ST_ERROR;
	}
	targets = new;
	ntargets = n;
	for (k = 0; k < nold; k++)
		target_free(&old[k]);
	free(old);
	pthread_mutex_unlock(&lock);
}

static int
conf_write(const char *json, const char **errp)
{
	char	path[MAXPATHLEN], tmp[MAXPATHLEN];
	FILE	*fp;

	conf_path(path, sizeof(path));
	/* Its directory, where the host has none yet. */
	if (strrchr(path, '/') != NULL) {
		snprintf(tmp, sizeof(tmp), "%.*s", (int)(strrchr(path, '/') -
		    path), path);
		(void)mkdir(tmp, 0755);
	}
	snprintf(tmp, sizeof(tmp), "%s.new", path);
	if ((fp = fopen(tmp, "we")) == NULL || fputs(json, fp) == EOF ||
	    fclose(fp) != 0 || rename(tmp, path) == -1) {
		*errp = strerror(errno);
		if (fp != NULL)
			fclose(fp);
		unlink(tmp);
		return (-1);
	}
	return (0);
}

/* The targets set: checked, kept, and probed from now on. */
int
do_probes_set(struct work *w, const char *json, const char **errp)
{
	struct target	*new;
	int		 n, step;
	const char	*e;
	char		 path[MAXPATHLEN];

	if ((new = calloc(TARGETS_MAX, sizeof(*new))) == NULL) {
		*errp = strerror(errno);
		return (-1);
	}
	if ((n = targets_parse(w, json, new, errp)) < 0) {
		free(new);
		return (-1);
	}
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", conf_path(path,
	    sizeof(path)));
	e = NULL;
	if (conf_write(json, &e) != 0) {
		step_end(w, step, false, "%s", e);
		*errp = wfmt(w, "%s: %s", path, e);
		free(new);
		return (-1);
	}
	step_end(w, step, true, "%d target%s", n, n == 1 ? "" : "s");
	targets_swap(new, n);
	return (0);
}

/* At the start: the targets kept, probed; the thread. */
void
probe_start(void)
{
	struct work	 w;
	struct target	*new;
	pthread_t	 tid;
	const char	*e;
	char		 path[MAXPATHLEN], *json;
	FILE		*fp;
	long		 len;
	int		 n;

	started = true;
	conf_path(path, sizeof(path));
	if ((fp = fopen(path, "re")) != NULL) {
		if (fseek(fp, 0, SEEK_END) == 0 && (len = ftell(fp)) > 0 &&
		    len < 4 * 1024 * 1024 && (json = malloc((size_t)len + 1)) !=
		    NULL) {
			rewind(fp);
			json[fread(json, 1, (size_t)len, fp)] = '\0';
			work_init(&w);
			new = calloc(TARGETS_MAX, sizeof(*new));
			e = NULL;
			if (new != NULL && (n = targets_parse(&w, json, new,
			    &e)) >= 0)
				targets_swap(new, n);
			else {
				logmsg(LOG_WARNING, "%s: %s", path, e != NULL ?
				    e : "not read");
				free(new);
			}
			work_free(&w);
			free(json);
		}
		fclose(fp);
	}
	if (pthread_create(&tid, NULL, prober, NULL) == 0)
		(void)pthread_detach(tid);
	else
		logmsg(LOG_ERR, "sdwan probes: no thread: %s", strerror(errno));
}

/* A target's state by its id; PROBE_NONE when it is none. */
int
probe_state_of(const char *id)
{
	int	i, st;

	st = PROBE_NONE;
	pthread_mutex_lock(&lock);
	for (i = 0; i < ntargets; i++)
		if (strcmp(targets[i].id, id) == 0) {
			st = targets[i].state;
			break;
		}
	pthread_mutex_unlock(&lock);
	return (st);
}

/* What the probes have seen, as JSON. */
int
do_sdwan(struct work *w, uint64_t after, struct arc_sdwan_rsp *rsp)
{
	ucl_object_t	*top, *arr, *o, *s, *row, *cur;
	struct target	*t;
	struct sample	*sm;
	unsigned char	*json;
	double		 now;
	int		 i, k, from;

	rsp->has_ok = true;
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	now = now_s();
	pthread_mutex_lock(&lock);
	for (i = 0; i < ntargets; i++) {
		t = &targets[i];
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(t->id), "id", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(t->address),
		    "address", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(t->af == AF_INET ?
		    "inet" : "inet6"), "family", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(t->fib), "fib", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(state_names[
		    t->state]), "state", 0, false);
		if (t->error[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromstring(t->error),
			    "error", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(t->since), "since",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromint(t->interval),
		    "interval", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(t->size), "size", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromint(t->eval), "eval", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromint(t->dscp), "dscp", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)t->sent),
		    "sent", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)
		    t->received), "received", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(t->misses), "misses",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromdouble(t->last_rtt),
		    "last_rtt", 0, false);
		/* The interval in progress, so far. */
		cur = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(cur, ucl_object_fromint(t->w_sent), "sent",
		    0, false);
		ucl_object_insert_key(cur, ucl_object_fromint(t->w_recv), "recv",
		    0, false);
		ucl_object_insert_key(cur, ucl_object_fromdouble(t->w_recv > 0 ?
		    t->w_sum / t->w_recv / 2 : 0), "delay", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromdouble(t->w_ipdv_n >
		    0 ? t->w_ipdv_sum / t->w_ipdv_n : 0), "ipdv", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromdouble(t->w_sent > 0 ?
		    (double)(t->w_sent - t->w_recv) / t->w_sent : 0), "loss", 0,
		    false);
		ucl_object_insert_key(cur, ucl_object_fromdouble(now -
		    t->win_start), "age", 0, false);
		ucl_object_insert_key(o, cur, "now", 0, false);
		/* The samples, the oldest first: t, delay, ipdv, loss, min,
		 * max, sent, received; the last report * eval ms are the
		 * report's. */
		s = ucl_object_typed_new(UCL_ARRAY);
		from = t->nsamples > 3600 ? t->nsamples - 3600 : 0;
		for (k = from; k < t->nsamples; k++) {
			sm = &t->samples[(t->head + k) % t->history];
			if ((uint64_t)sm->t <= after)
				continue;
			row = ucl_object_typed_new(UCL_ARRAY);
			ucl_array_append(row, ucl_object_fromint((int64_t)
			    sm->t));
			ucl_array_append(row, ucl_object_fromdouble(sm->delay));
			ucl_array_append(row, ucl_object_fromdouble(sm->ipdv));
			ucl_array_append(row, ucl_object_fromdouble(sm->loss));
			ucl_array_append(row, ucl_object_fromdouble(sm->min));
			ucl_array_append(row, ucl_object_fromdouble(sm->max));
			ucl_array_append(row, ucl_object_fromint(sm->sent));
			ucl_array_append(row, ucl_object_fromint(sm->recv));
			ucl_array_append(s, row);
		}
		ucl_object_insert_key(o, s, "samples", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(t->nsamples),
		    "kept", 0, false);
		ucl_array_append(arr, o);
	}
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(top, arr, "targets", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(time(NULL)), "time", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_frombool(started), "probing", 0,
	    false);
	sdwan_json(top);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->ok = false;
		rsp->error = "no memory";
		return (0);
	}
	rsp->json = wadopt(w, (char *)json);
	rsp->ok = true;
	return (0);
}
