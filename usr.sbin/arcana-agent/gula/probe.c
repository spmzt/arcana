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
 * The targets come from the console (sdwan-probes): a JSON array, the
 * host's own, or {"jail": "j", "targets": [...]}, those of an edge that
 * is the vnet jail j, probed from its network.  Each edge's list
 * replaces its own only, and is kept in a file of its own beside
 * history.conf (sdwan-probes.json, sdwan-probes@j.json) for the next
 * start.  Each
 * says its id and address, and may say its fib, interval (ms), size
 * (bytes), count (0: without end), dscp, down and up (misses and
 * answers), timeout (ms), eval (ms), history (samples kept) and report.
 * A raw socket needs root: without it the target says so.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
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
	char			 jail[64];	/* its network's; "" the host's */
	int			 af;
	struct sockaddr_storage	 sa;
	int			 fib, interval, size, count, dscp, down, up;
	int			 timeout, eval, history, report;
	/* Threshold crossing alerts (Mplify 119 §11.4, MEF 105 §7.4): a
	 * threshold a metric, 0 for none; damping, intervals in a row. */
	double			 tca[3];
	int			 damping, tca_over[3], tca_under[3];
	bool			 tca_on[3];
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

/*
 * The links an edge watches (Mplify 119's interface faults): its UCS
 * end points' and UNIs' interfaces, each a fault while it has no link
 * (down, or its carrier gone), told by the console beside the targets
 * ("links": [{"interface", "id", "role"}]).
 */
#define	LINKS_MAX	128
struct link {
	char	jail[64];	/* the edge's; "" the host's */
	char	ifname[IFNAMSIZ];
	char	id[96];		/* the UNI's or UCS end point's */
	char	role[8];	/* uni, ucs */
	int	state;		/* -1 not known, 0 down, 1 up */
};
static struct link	 links[LINKS_MAX];
static int		 nlinks;

static int	links_set(struct work *, const char *, const char *,
		    const char **);
static bool	has_links(const char *);
static bool		 started;
static bool		 changed;	/* a state did, since the steering looked */

static double
now_s(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((double)ts.tv_sec + (double)ts.tv_nsec / 1e9);
}

/* The file of an edge's targets: the host's, or jail's. */
static const char *
conf_path(char *buf, size_t len, const char *jail)
{
	const char	*slash;
	char		 base[128];

	if (jail != NULL && jail[0] != '\0')
		snprintf(base, sizeof(base), "sdwan-probes@%s.json", jail);
	else
		snprintf(base, sizeof(base), "%s", PROBE_FILE);
	if ((slash = strrchr(opts.history_conf, '/')) != NULL)
		snprintf(buf, len, "%.*s/%s", (int)(slash - opts.history_conf),
		    opts.history_conf, base);
	else
		snprintf(buf, len, "%s", base);
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
	int	v, jid;

	if (t->jail[0] != '\0') {
		/* A jail's: its socket made in its network by the helper,
		 * so that its routing tables carry the probes. */
		if ((jid = jail_getid(t->jail)) < 0) {
			snprintf(t->error, sizeof(t->error), "jail %s is not "
			    "running", t->jail);
			return (false);
		}
		if ((t->sock = helper_icmp_socket(jid, t->af)) == -1) {
			snprintf(t->error, sizeof(t->error), "no socket in jail "
			    "%s (probing needs root)", t->jail);
			return (false);
		}
		(void)fcntl(t->sock, F_SETFL, fcntl(t->sock, F_GETFL) |
		    O_NONBLOCK);
	} else if ((t->sock = socket(t->af, SOCK_RAW | SOCK_CLOEXEC |
	    SOCK_NONBLOCK, t->af == AF_INET ? IPPROTO_ICMP :
	    IPPROTO_ICMPV6)) == -1) {
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

/* Its name in faults and the log: its id, and id@jail at a jail's
 * edge, so that both ends of a tunnel on one host are told apart. */
static const char *
target_name(const struct target *t, char *buf, size_t len)
{

	if (t->jail[0] != '\0')
		snprintf(buf, len, "%s@%s", t->id, t->jail);
	else
		snprintf(buf, len, "%s", t->id);
	return (buf);
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
	/* A jail's: said, its name a jail's (letters, digits, - _ .). */
	event_add("sdwan-tunnel", "{\"id\":\"%s\",\"address\":\"%s\",\"state\":"
	    "\"%s\",\"misses\":%d%s%s%s}", id, t->address, state_names[state],
	    t->misses, t->jail[0] != '\0' ? ",\"jail\":\"" : "", t->jail,
	    t->jail[0] != '\0' ? "\"" : "");
	logmsg(state == ST_UP ? LOG_NOTICE : LOG_WARNING, "sdwan: %s (%s) is "
	    "%s", target_name(t, id, sizeof(id)), t->address,
	    state_names[state]);
	if (state == ST_DOWN)
		fault_set("tunnel", "Major", id, "probe", "no answer from %s "
		    "after %d probes", t->address, t->misses);
	else
		fault_clear("tunnel", id, "%s answers again", t->address);
}

/* The sample against the thresholds: an alert set or cleared. */
static void
tca_check(struct target *t, const struct sample *s)
{
	static const char *const names[] = { "delay", "ipdv", "loss" };
	static const char *const units[] = { " ms", " ms", "" };
	double		v[3];
	char		obj[260], name[200];
	int		i;

	v[0] = s->delay;
	v[1] = s->ipdv;
	v[2] = s->loss;
	for (i = 0; i < 3; i++) {
		if (t->tca[i] <= 0)
			continue;
		snprintf(obj, sizeof(obj), "%s/%s", target_name(t, name,
		    sizeof(name)), names[i]);
		if (v[i] > t->tca[i]) {
			t->tca_under[i] = 0;
			if (!t->tca_on[i] && ++t->tca_over[i] >= t->damping) {
				t->tca_on[i] = true;
				fault_set("tca", "Minor", obj, "probe", "%s %.3g%s "
				    "over the threshold %.3g%s", names[i], v[i],
				    units[i], t->tca[i], units[i]);
			}
		} else {
			t->tca_over[i] = 0;
			if (t->tca_on[i] && ++t->tca_under[i] >= t->damping) {
				t->tca_on[i] = false;
				fault_clear("tca", obj, "%s %.3g%s, under the "
				    "threshold %.3g%s again", names[i], v[i],
				    units[i], t->tca[i], units[i]);
			}
		}
	}
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
	if (t->w_sent > 0)
		tca_check(t, s);
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
    char *jail, size_t jlen, const char **errp)
{
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*o, *v;
	ucl_object_iter_t	 it;
	struct target		*t;
	struct sockaddr_in	*s4;
	struct sockaddr_in6	*s6;
	const ucl_object_t	*list;
	const char		*id, *addr, *bad;
	int			 n, k;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	/* An edge that is a vnet jail: {"jail", "targets"}. */
	jail[0] = '\0';
	list = top;
	if (top != NULL && ucl_object_type(top) == UCL_OBJECT) {
		/* {"targets", "links"}, a jail's with "jail". */
		if ((v = ucl_object_lookup(top, "jail")) != NULL && (ucl_object_type(
		    v) != UCL_STRING || !valid_jail(ucl_object_tostring(v)) ||
		    strlen(ucl_object_tostring(v)) >= jlen)) {
			ucl_object_unref(top);
			*errp = "invalid jail name";
			return (-1);
		}
		if (v != NULL)
			snprintf(jail, jlen, "%s", ucl_object_tostring(v));
		list = ucl_object_lookup(top, "targets");
	}
	if (list == NULL || ucl_object_type(list) != UCL_ARRAY) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the targets are a JSON array, or an object with them "
		    "as targets (and links, jail)";
		return (-1);
	}
	n = 0;
	it = NULL;
	while ((o = ucl_object_iterate(list, &it, true)) != NULL) {
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
		/* At an edge that is a vnet jail: probed from its network. */
		snprintf(t->jail, sizeof(t->jail), "%s", jail);
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
		/* Thresholds: delay and ipdv in ms, loss a fraction. */
		{
			const ucl_object_t	*tc = ucl_object_lookup(o, "tca");

			t->tca[0] = tc != NULL ? ucl_object_todouble(
			    ucl_object_lookup(tc, "delay")) : 0;
			t->tca[1] = tc != NULL ? ucl_object_todouble(
			    ucl_object_lookup(tc, "ipdv")) : 0;
			t->tca[2] = tc != NULL ? ucl_object_todouble(
			    ucl_object_lookup(tc, "loss")) : 0;
			t->damping = tc != NULL ? (int)num(tc, "damping", 1, 1, 100,
			    &bad) : 1;
			if (t->tca[0] < 0 || t->tca[1] < 0 || t->tca[2] < 0 ||
			    t->tca[2] > 1)
				bad = "tca";
		}
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
 * The new targets in the place of the old ones of their edge (jail, ""
 * the host): one that is the same target (address, fib, dscp, size)
 * keeps its socket, state and samples; the other edges' stay as they
 * are, after them.  False, with nothing changed, when all of them are
 * more than TARGETS_MAX (new has room for that many).
 */
static bool
targets_swap(struct target *new, int n, const char *jail)
{
	struct target	*old, *t, *o;
	int		 nold, i, k, total;
	double		 now;

	pthread_mutex_lock(&lock);
	old = targets;
	nold = ntargets;
	total = n;
	for (k = 0; k < nold; k++)
		if (strcmp(old[k].jail, jail) != 0)
			total++;
	if (total > TARGETS_MAX) {
		pthread_mutex_unlock(&lock);
		return (false);
	}
	now = now_s();
	for (i = 0; i < n; i++) {
		t = &new[i];
		for (k = 0; k < nold; k++) {
			o = &old[k];
			if (o->id[0] != '\0' && strcmp(o->jail, jail) == 0 &&
			    strcmp(o->id, t->id) == 0 &&
			    strcmp(o->address, t->address) == 0 && o->fib ==
			    t->fib && o->dscp == t->dscp && o->size == t->size)
				break;
		}
		if (k < nold) {
			int	iv = t->interval, cnt = t->count, dn = t->down;
			int	up = t->up, to = t->timeout, ev = t->eval;
			int	hi = t->history, rp = t->report, dm = t->damping;
			double	tc[3] = { t->tca[0], t->tca[1], t->tca[2] };

			/* As it was, with what may change under it. */
			*t = *o;
			memcpy(t->tca, tc, sizeof(tc));
			t->damping = dm;
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
	/* The other edges', moved over as they are. */
	for (k = 0; k < nold; k++)
		if (strcmp(old[k].jail, jail) != 0) {
			new[n++] = old[k];
			memset(&old[k], 0, sizeof(old[k]));
			old[k].sock = -1;
		}
	targets = new;
	ntargets = n;
	for (k = 0; k < nold; k++)
		target_free(&old[k]);
	free(old);
	pthread_mutex_unlock(&lock);
	return (true);
}

static int
conf_write(const char *json, const char *jail, const char **errp)
{
	char	path[MAXPATHLEN], tmp[MAXPATHLEN];
	FILE	*fp;

	conf_path(path, sizeof(path), jail);
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
	char		 path[MAXPATHLEN], jail[64];

	if ((new = calloc(TARGETS_MAX, sizeof(*new))) == NULL) {
		*errp = strerror(errno);
		return (-1);
	}
	if ((n = targets_parse(w, json, new, jail, sizeof(jail), errp)) < 0) {
		free(new);
		return (-1);
	}
	if (!targets_swap(new, n, jail)) {
		*errp = wfmt(w, "%d targets at most, all edges' together",
		    TARGETS_MAX);
		for (n--; n >= 0; n--)
			target_free(&new[n]);
		free(new);
		return (-1);
	}
	if (links_set(w, json, jail, errp) != 0)
		return (-1);
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", conf_path(path,
	    sizeof(path), jail));
	e = NULL;
	/* None left: no file, so that a start makes no edge of it. */
	if (n == 0 && jail[0] != '\0' && !has_links(json) ? unlink(path) ==
	    -1 && errno != ENOENT &&
	    (e = strerror(errno)) != NULL : conf_write(json, jail, &e) != 0) {
		step_end(w, step, false, "%s", e);
		*errp = wfmt(w, "%s: %s", path, e);
		return (-1);
	}
	step_end(w, step, true, "%d target%s", n, n == 1 ? "" : "s");
	return (0);
}

/* Does the payload watch any link? */
static bool
has_links(const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*top;
	bool			 yes;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	yes = top != NULL && ucl_object_type(top) == UCL_OBJECT &&
	    ucl_array_size(ucl_object_lookup(top, "links")) > 0;
	if (top != NULL)
		ucl_object_unref(top);
	return (yes);
}

/* An edge's kept targets, probed again. */
static void
start_file(const char *path)
{
	struct work	 w;
	struct target	*new;
	const char	*e;
	char		*json, jail[64];
	FILE		*fp;
	long		 len;
	int		 n;

	if ((fp = fopen(path, "re")) == NULL)
		return;
	if (fseek(fp, 0, SEEK_END) == 0 && (len = ftell(fp)) > 0 &&
	    len < 4 * 1024 * 1024 && (json = malloc((size_t)len + 1)) != NULL) {
		rewind(fp);
		json[fread(json, 1, (size_t)len, fp)] = '\0';
		work_init(&w);
		new = calloc(TARGETS_MAX, sizeof(*new));
		e = NULL;
		if (new != NULL && (n = targets_parse(&w, json, new, jail,
		    sizeof(jail), &e)) >= 0) {
			if (!targets_swap(new, n, jail)) {
				logmsg(LOG_WARNING, "%s: more than %d targets",
				    path, TARGETS_MAX);
				free(new);
			} else if (links_set(&w, json, jail, &e) != 0)
				logmsg(LOG_WARNING, "%s: %s", path, e);
		} else {
			logmsg(LOG_WARNING, "%s: %s", path, e != NULL ? e :
			    "not read");
			free(new);
		}
		work_free(&w);
		free(json);
	}
	fclose(fp);
}

/* A link's fault object: its id, id@jail at a jail's edge. */
static const char *
link_name(const struct link *l, char *buf, size_t len)
{

	if (l->jail[0] != '\0')
		snprintf(buf, len, "%s@%s", l->id, l->jail);
	else
		snprintf(buf, len, "%s", l->id);
	return (buf);
}

/* A link's state as now seen: a fault when it goes, cleared when back. */
static void
link_state(struct link *l, int up)
{
	char	obj[200];

	if (l->state == up)
		return;
	l->state = up;
	if (up == 0)
		fault_set("interface", "Major", link_name(l, obj, sizeof(obj)),
		    "link", "the %s %s has no link on %s", strcmp(l->role,
		    "uni") == 0 ? "UNI" : "UCS end point", l->id, l->ifname);
	else
		fault_clear("interface", link_name(l, obj, sizeof(obj)),
		    "the %s %s has its link on %s again", strcmp(l->role, "uni")
		    == 0 ? "UNI" : "UCS end point", l->id, l->ifname);
}

/*
 * An edge's links from its payload, in place of those it had; each
 * looked at now (later the interface's own changes tell).  A link no
 * longer watched has its fault cleared.  -1 and why when bad.
 */
static int
links_set(struct work *w, const char *json, const char *jail,
    const char **errp)
{
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*o, *v;
	ucl_object_iter_t	 it;
	struct link		 nl[LINKS_MAX], *l;
	struct work		 jw;
	char			 obj[200];
	const char		*s, *e;
	int			 n, k, i;
	bool			 ok;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	n = 0;
	it = NULL;
	while (top != NULL && ucl_object_type(top) == UCL_OBJECT && (o =
	    ucl_object_iterate(ucl_object_lookup(top, "links"), &it, true)) !=
	    NULL) {
		if (n == LINKS_MAX) {
			*errp = wfmt(w, "%d links at most", LINKS_MAX);
			ucl_object_unref(top);
			return (-1);
		}
		l = &nl[n];
		memset(l, 0, sizeof(*l));
		l->state = -1;
		snprintf(l->jail, sizeof(l->jail), "%s", jail);
		if ((v = ucl_object_lookup(o, "interface")) == NULL ||
		    ucl_object_type(v) != UCL_STRING || (s =
		    ucl_object_tostring(v))[0] == '\0' || strlen(s) >=
		    sizeof(l->ifname) || !valid_ifname(s) || (v =
		    ucl_object_lookup(o, "id")) == NULL || ucl_object_type(v) !=
		    UCL_STRING || ucl_object_tostring(v)[0] == '\0' ||
		    strlen(ucl_object_tostring(v)) >= sizeof(l->id)) {
			*errp = "each link has an interface and an id";
			ucl_object_unref(top);
			return (-1);
		}
		snprintf(l->ifname, sizeof(l->ifname), "%s", s);
		snprintf(l->id, sizeof(l->id), "%s", ucl_object_tostring(v));
		v = ucl_object_lookup(o, "role");
		snprintf(l->role, sizeof(l->role), "%s", v != NULL &&
		    ucl_object_type(v) == UCL_STRING && strcmp(
		    ucl_object_tostring(v), "uni") == 0 ? "uni" : "ucs");
		n++;
	}
	if (top != NULL)
		ucl_object_unref(top);
	/* Each as it is now, where the edge is. */
	work_init(&jw);
	e = NULL;
	if (jail[0] != '\0' && scope_enter(&jw, jail, &e) != 0)
		jw.jail = NULL;
	for (i = 0; i < n; i++)
		if (jail[0] == '\0' || jw.jail != NULL)
			nl[i].state = if_link(&jw, nl[i].ifname, &ok) ? ok :
			    0;
	work_free(&jw);
	pthread_mutex_lock(&lock);
	/* Those of the edge no longer watched: their faults cleared. */
	for (k = 0; k < nlinks; k++) {
		if (strcmp(links[k].jail, jail) != 0)
			continue;
		for (i = 0; i < n; i++)
			if (strcmp(nl[i].id, links[k].id) == 0 && strcmp(
			    nl[i].ifname, links[k].ifname) == 0)
				break;
		if (i == n && links[k].state == 0)
			fault_clear("interface", link_name(&links[k], obj,
			    sizeof(obj)), "%s is watched no more",
			    links[k].ifname);
	}
	/* The others' kept, the edge's new after them. */
	for (i = k = 0; k < nlinks; k++)
		if (strcmp(links[k].jail, jail) != 0)
			links[i++] = links[k];
	if (i + n > LINKS_MAX) {
		pthread_mutex_unlock(&lock);
		*errp = wfmt(w, "%d links at most, all edges' together",
		    LINKS_MAX);
		return (-1);
	}
	for (k = 0; k < n; k++) {
		int	st = nl[k].state;

		links[i] = nl[k];
		links[i].state = -1;
		/* Not known (no such interface yet): down until it is. */
		link_state(&links[i], st == 1 ? 1 : 0);
		i++;
	}
	nlinks = i;
	pthread_mutex_unlock(&lock);
	return (0);
}

/*
 * An interface's link as the kernel tells it changed (netlink, on the
 * host's or a jail's network): a watched link's fault set or cleared.
 */
void
probe_link(const char *jail, const char *ifname, bool ok)
{
	int	k;

	pthread_mutex_lock(&lock);
	for (k = 0; k < nlinks; k++)
		if (strcmp(links[k].jail, jail != NULL ? jail : "") == 0 &&
		    strcmp(links[k].ifname, ifname) == 0)
			link_state(&links[k], ok ? 1 : 0);
	pthread_mutex_unlock(&lock);
}

/* At the start: the targets kept, probed; the thread. */
void
probe_start(void)
{
	struct dirent	*de;
	DIR		*d;
	pthread_t	 tid;
	char		 path[MAXPATHLEN], *slash;

	started = true;
	/* The host's, and each jail's beside it. */
	start_file(conf_path(path, sizeof(path), NULL));
	if ((slash = strrchr(path, '/')) != NULL)
		*slash = '\0';
	else
		snprintf(path, sizeof(path), ".");
	if ((d = opendir(path)) != NULL) {
		char	f[MAXPATHLEN];

		while ((de = readdir(d)) != NULL)
			if (strncmp(de->d_name, "sdwan-probes@", 13) == 0) {
				snprintf(f, sizeof(f), "%s/%s", path, de->d_name);
				start_file(f);
			}
		closedir(d);
	}
	if (pthread_create(&tid, NULL, prober, NULL) == 0)
		(void)pthread_detach(tid);
	else
		logmsg(LOG_ERR, "sdwan probes: no thread: %s", strerror(errno));
}

/* A target's state by its edge (jail, "" the host) and id; PROBE_NONE
 * when it is none. */
int
probe_state_of(const char *jail, const char *id)
{
	int	i, st;

	st = PROBE_NONE;
	pthread_mutex_lock(&lock);
	for (i = 0; i < ntargets; i++)
		if (strcmp(targets[i].jail, jail) == 0 && strcmp(targets[i].id,
		    id) == 0) {
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
		if (t->jail[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromstring(t->jail),
			    "jail", 0, false);
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
	sdwan_json(w, top);
	sdwan_bird_json(w, top);
	sdwan_dhcp_json(w, top);
	sdwan_dns_json(w, top);
	sdwan_proxy_json(w, top);
	sdwan_ids_json(w, top);
	record_json(top);
	sa_keys_json(w, top);
	faults_json(top);
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
