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
 *
 * The same prober measures tunnels outside SD-WAN too: the monitors an
 * admin puts on any tunnel interface (the monitor job), each target's
 * owner "monitor" rather than "sdwan".  An owner's list is replaced by
 * its own alone, so an SD-WAN apply never takes a monitor away, and is
 * kept in its own file (monitors.json, monitors@j.json).  A monitor's
 * state and thresholds are events (monitor, monitor-threshold), not
 * SD-WAN's faults.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <dirent.h>
#include <ifaddrs.h>
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
#define	MONITOR_FILE	"monitors.json"
#define	OWN_SDWAN	"sdwan"
#define	OWN_MONITOR	"monitor"
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
	char			 owner[8];	/* sdwan, monitor */
	char			 ifname[IFNAMSIZ];	/* a monitor's tunnel */
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
 * The kernel hands an ICMP reply to the raw sockets of the FIB of the
 * interface it came in on: a probe sent in a tunnel's table (its
 * tunnelfib) over an uplink in another never hears its reply on its own
 * socket.  So replies are listened for on a socket a FIB, a family,
 * the host's, and told to the target by the echo's id.
 */
#define	RX_FIBS		16
static int		 rx[2][RX_FIBS];
static int		 nfibs = -1;

static void
rx_open(int af)
{
	struct icmp6_filter	f;
	size_t			len = sizeof(nfibs);
	int			k = af == AF_INET6, v;

	if (nfibs < 0 && (sysctlbyname("net.fibs", &nfibs, &len, NULL, 0) != 0 ||
	    nfibs < 1))
		nfibs = 1;
	for (int fib = 0; fib < nfibs && fib < RX_FIBS; fib++) {
		if (rx[k][fib] > 0)
			continue;
		if ((v = socket(af, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    af == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6)) == -1)
			continue;
		if (setsockopt(v, SOL_SOCKET, SO_SETFIB, &fib, sizeof(fib)) ==
		    -1) {
			close(v);
			continue;
		}
		if (af == AF_INET6) {
			ICMP6_FILTER_SETBLOCKALL(&f);
			ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &f);
			(void)setsockopt(v, IPPROTO_ICMPV6, ICMP6_FILTER, &f,
			    sizeof(f));
		}
		rx[k][fib] = v;
	}
}

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

static bool
is_monitor(const struct target *t)
{

	return (strcmp(t->owner, OWN_MONITOR) == 0);
}

/* The file of an owner's targets at an edge: the host's, or jail's. */
static const char *
conf_path(char *buf, size_t len, const char *jail, const char *owner)
{
	const char	*slash;
	char		 base[128];
	bool		 mon;

	mon = owner != NULL && strcmp(owner, OWN_MONITOR) == 0;
	if (jail != NULL && jail[0] != '\0')
		snprintf(base, sizeof(base), "%s@%s.json", mon ? "monitors" :
		    "sdwan-probes", jail);
	else
		snprintf(base, sizeof(base), "%s", mon ? MONITOR_FILE :
		    PROBE_FILE);
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
	/* Its reply may come in on an interface of another table. */
	if (t->jail[0] == '\0' && t->fib != 0)
		rx_open(t->af);
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
	event_add(is_monitor(t) ? "monitor" : "sdwan-tunnel", "{\"id\":\"%s\","
	    "\"address\":\"%s\",\"state\":\"%s\",\"misses\":%d%s%s%s%s%s%s}",
	    id, t->address, state_names[state], t->misses, t->jail[0] != '\0' ?
	    ",\"jail\":\"" : "", t->jail, t->jail[0] != '\0' ? "\"" : "",
	    t->ifname[0] != '\0' ? ",\"interface\":\"" : "", t->ifname,
	    t->ifname[0] != '\0' ? "\"" : "");
	logmsg(state == ST_UP ? LOG_NOTICE : LOG_WARNING, "%s: %s (%s) is "
	    "%s", is_monitor(t) ? "monitor" : "sdwan", target_name(t, id,
	    sizeof(id)), t->address, state_names[state]);
	/* A monitor is the admin's own: an event, not SD-WAN's fault. */
	if (is_monitor(t))
		return;
	if (state == ST_DOWN)
		fault_set("tunnel", "Major", id, "probe", "no answer from %s "
		    "after %d probes", t->address, t->misses);
	else
		fault_clear("tunnel", id, "%s answers again", t->address);
}

/* A monitor's metric over its threshold, or under it again: an event. */
static void
monitor_tca(const struct target *t, const char *metric, double v, bool over)
{
	char	name[200];

	event_add("monitor-threshold", "{\"id\":\"%s\",\"metric\":\"%s\","
	    "\"value\":%.6g,\"threshold\":%.6g,\"over\":%s%s%s%s}",
	    target_name(t, name, sizeof(name)), metric, v,
	    t->tca[strcmp(metric, "delay") == 0 ? 0 : strcmp(metric, "ipdv") ==
	    0 ? 1 : 2], over ? "true" : "false", t->ifname[0] != '\0' ?
	    ",\"interface\":\"" : "", t->ifname, t->ifname[0] != '\0' ? "\"" :
	    "");
	logmsg(over ? LOG_WARNING : LOG_NOTICE, "monitor: %s: %s %.3g %s the "
	    "threshold", name, metric, v, over ? "over" : "under");
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
				if (is_monitor(t))
					monitor_tca(t, names[i], v[i], true);
				else
					fault_set("tca", "Minor", obj, "probe",
					    "%s %.3g%s over the threshold %.3g%s",
					    names[i], v[i], units[i], t->tca[i],
					    units[i]);
			}
		} else {
			t->tca_over[i] = 0;
			if (t->tca_on[i] && ++t->tca_under[i] >= t->damping) {
				t->tca_on[i] = false;
				if (is_monitor(t))
					monitor_tca(t, names[i], v[i], false);
				else
					fault_clear("tca", obj, "%s %.3g%s, under "
					    "the threshold %.3g%s again", names[i],
					    v[i], units[i], t->tca[i], units[i]);
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

/*
 * What a socket of family af has: each echo reply to the target t, or
 * with t NULL to the target of its id (a FIB's listener's).
 */
static void
sock_recv(int sock, int af, struct target *t, double now)
{
	unsigned char		 pkt[PKT_MAX + 64];
	struct sockaddr_storage	 from;
	struct target		*x;
	socklen_t		 flen;
	ssize_t			 n;
	uint16_t		 id, seq;
	int			 i, hl;

	for (;;) {
		flen = sizeof(from);
		n = recvfrom(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)
		    &from, &flen);
		if (n <= 0)
			return;
		if (af == AF_INET) {
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
		x = t;
		for (i = 0; x == NULL && i < ntargets; i++)
			if (targets[i].af == af && targets[i].sock != -1 &&
			    targets[i].ident == id && targets[i].jail[0] == '\0')
				x = &targets[i];
		if (x == NULL || id != x->ident)
			continue;
		for (i = 0; i < OUT_MAX; i++)
			if (x->out[i].live && x->out[i].seq == seq) {
				x->out[i].live = false;
				hit(x, (now - x->out[i].sent) * 1000);
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

	pfd = calloc(TARGETS_MAX + 2 * RX_FIBS, sizeof(*pfd));
	for (int k = 0; k < 2; k++)
		for (int fib = 0; fib < RX_FIBS; fib++)
			rx[k][fib] = -1;
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
		for (int k = 0; k < 2; k++)
			for (int fib = 0; fib < RX_FIBS; fib++)
				if (rx[k][fib] != -1) {
					pfd[n].fd = rx[k][fib];
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
				sock_recv(t->sock, t->af, t, now);
			n++;
		}
		for (int k = 0; k < 2; k++)
			for (int fib = 0; fib < RX_FIBS; fib++)
				if (rx[k][fib] != -1) {
					if (pfd[n].fd == rx[k][fib] &&
					    (pfd[n].revents & POLLIN))
						sock_recv(rx[k][fib], k == 0 ?
						    AF_INET : AF_INET6, NULL, now);
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
    char *jail, size_t jlen, const char *owner, const char **errp)
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
		snprintf(t->owner, sizeof(t->owner), "%s", owner);
		if ((v = ucl_object_lookup(o, "interface")) != NULL &&
		    ucl_object_type(v) == UCL_STRING && strlen(
		    ucl_object_tostring(v)) < sizeof(t->ifname))
			snprintf(t->ifname, sizeof(t->ifname), "%s",
			    ucl_object_tostring(v));
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
targets_swap(struct target *new, int n, const char *jail, const char *owner)
{
	struct target	*old, *t, *o;
	int		 nold, i, k, total;
	double		 now;

	pthread_mutex_lock(&lock);
	old = targets;
	nold = ntargets;
	total = n;
	for (k = 0; k < nold; k++)
		if (strcmp(old[k].jail, jail) != 0 || strcmp(old[k].owner,
		    owner) != 0)
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
			    strcmp(o->owner, owner) == 0 &&
			    strcmp(o->id, t->id) == 0 &&
			    strcmp(o->address, t->address) == 0 && o->fib ==
			    t->fib && o->dscp == t->dscp && o->size == t->size)
				break;
		}
		if (k < nold) {
			int	iv = t->interval, cnt = t->count, dn = t->down;
			int	up = t->up, to = t->timeout, ev = t->eval;
			int	hi = t->history, rp = t->report, dm = t->damping;
			char	ifn[IFNAMSIZ];

			snprintf(ifn, sizeof(ifn), "%s", t->ifname);
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
			snprintf(t->ifname, sizeof(t->ifname), "%s", ifn);
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
	/* The other edges' and owners', moved over as they are. */
	for (k = 0; k < nold; k++)
		if (strcmp(old[k].jail, jail) != 0 || strcmp(old[k].owner,
		    owner) != 0) {
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
conf_write(const char *json, const char *jail, const char *owner,
    const char **errp)
{
	char	path[MAXPATHLEN], tmp[MAXPATHLEN];
	FILE	*fp;

	conf_path(path, sizeof(path), jail, owner);
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
	if ((n = targets_parse(w, json, new, jail, sizeof(jail), OWN_SDWAN,
	    errp)) < 0) {
		free(new);
		return (-1);
	}
	if (!targets_swap(new, n, jail, OWN_SDWAN)) {
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
	    sizeof(path), jail, OWN_SDWAN));
	e = NULL;
	/* None left: no file, so that a start makes no edge of it. */
	if (n == 0 && jail[0] != '\0' && !has_links(json) ? unlink(path) ==
	    -1 && errno != ENOENT &&
	    (e = strerror(errno)) != NULL : conf_write(json, jail, OWN_SDWAN,
	    &e) != 0) {
		step_end(w, step, false, "%s", e);
		*errp = wfmt(w, "%s: %s", path, e);
		return (-1);
	}
	step_end(w, step, true, "%d target%s", n, n == 1 ? "" : "s");
	return (0);
}

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

/* An edge's kept targets, an owner's, probed again. */
static void
start_file(const char *path, const char *owner)
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
		    sizeof(jail), owner, &e)) >= 0) {
			if (!targets_swap(new, n, jail, owner)) {
				logmsg(LOG_WARNING, "%s: more than %d targets",
				    path, TARGETS_MAX);
				free(new);
			} else if (strcmp(owner, OWN_SDWAN) == 0 &&
			    links_set(&w, json, jail, &e) != 0)
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
	/* The host's, and each jail's beside it; the monitors likewise. */
	start_file(conf_path(path, sizeof(path), NULL, OWN_MONITOR),
	    OWN_MONITOR);
	start_file(conf_path(path, sizeof(path), NULL, OWN_SDWAN), OWN_SDWAN);
	if ((slash = strrchr(path, '/')) != NULL)
		*slash = '\0';
	else
		snprintf(path, sizeof(path), ".");
	if ((d = opendir(path)) != NULL) {
		char	f[MAXPATHLEN];

		while ((de = readdir(d)) != NULL)
			if (strncmp(de->d_name, "sdwan-probes@", 13) == 0) {
				snprintf(f, sizeof(f), "%s/%s", path, de->d_name);
				start_file(f, OWN_SDWAN);
			} else if (strncmp(de->d_name, "monitors@", 9) == 0) {
				snprintf(f, sizeof(f), "%s/%s", path, de->d_name);
				start_file(f, OWN_MONITOR);
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
		if (!is_monitor(&targets[i]) && strcmp(targets[i].jail, jail) ==
		    0 && strcmp(targets[i].id, id) == 0) {
			st = targets[i].state;
			break;
		}
	pthread_mutex_unlock(&lock);
	return (st);
}

/* A target as JSON: what it is, its state, the sample in progress and
 * those kept after the time after.  The lock is held. */
static ucl_object_t *
target_json(const struct target *t, double now, uint64_t after)
{
	ucl_object_t	*o, *s, *row, *cur;
	struct sample	*sm;
	int		 k, from;

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
	if (t->ifname[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(t->ifname),
		    "interface", 0, false);
	if (t->tca[0] > 0 || t->tca[1] > 0 || t->tca[2] > 0) {
		cur = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(cur, ucl_object_fromdouble(t->tca[0]),
		    "delay", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromdouble(t->tca[1]),
		    "ipdv", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromdouble(t->tca[2]),
		    "loss", 0, false);
		ucl_object_insert_key(cur, ucl_object_fromint(t->damping),
		    "damping", 0, false);
		ucl_object_insert_key(o, cur, "tca", 0, false);
	}
	ucl_object_insert_key(o, ucl_object_fromint(t->history), "history", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->down), "down", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->up), "up", 0, false);
	return (o);
}

/* What the probes have seen, as JSON. */
int
do_sdwan(struct work *w, uint64_t after, struct arc_sdwan_rsp *rsp)
{
	ucl_object_t	*top, *arr;
	struct target	*t;
	unsigned char	*json;
	double		 now;
	int		 i;

	rsp->has_ok = true;
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	now = now_s();
	pthread_mutex_lock(&lock);
	for (i = 0; i < ntargets; i++) {
		t = &targets[i];
		/* The admin's monitors are read apart (do_monitors). */
		if (is_monitor(t))
			continue;
		ucl_array_append(arr, target_json(t, now, after));
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

/* ---- Monitors: the admin's own, on any tunnel ----------------------- */

/* What the monitors have seen, as JSON, the host's and the jails'. */
int
do_monitors(struct work *w, uint64_t after, struct arc_monitors_rsp *rsp)
{
	ucl_object_t	*top, *arr;
	unsigned char	*json;
	double		 now;
	int		 i;

	rsp->has_ok = true;
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	now = now_s();
	pthread_mutex_lock(&lock);
	for (i = 0; i < ntargets; i++)
		if (is_monitor(&targets[i]))
			ucl_array_append(arr, target_json(&targets[i], now,
			    after));
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(top, arr, "monitors", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(time(NULL)), "time", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_frombool(started), "probing", 0,
	    false);
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

/* A monitor's name: letters, digits and _ . @ -, 63 at most. */
static bool
mon_name_ok(const char *s)
{
	size_t	n;

	return (s != NULL && (n = strlen(s)) > 0 && n < 64 && strspn(s,
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	    "_.@-") == n);
}

static const char *
arg_of(const char *word, const char *name)
{
	size_t	n;

	n = strlen(name);
	return (strncmp(word, name, n) == 0 && word[n] == '=' ? word + n + 1 :
	    NULL);
}

/* The name a monitor job is for (name=), or NULL. */
static const char *
mon_name(const struct arc_job_spec *sp)
{
	const char	*v;
	size_t		 i;

	for (i = 0; i < sp->names.n; i++)
		if ((v = arg_of(sp->names.v[i], "name")) != NULL)
			return (v);
	return (NULL);
}

/* A target's settings, as targets_parse takes them back. */
static ucl_object_t *
target_conf(const struct target *t)
{
	ucl_object_t	*o, *tc;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(t->id), "id", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->address), "address",
	    0, false);
	if (t->ifname[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(t->ifname),
		    "interface", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->fib), "fib", 0, false);
	if (!is_monitor(t)) {
		ucl_object_insert_key(o, ucl_object_fromint(t->count), "count",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromint(t->report),
		    "report", 0, false);
	}
	ucl_object_insert_key(o, ucl_object_fromint(t->interval), "interval",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->size), "size", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->dscp), "dscp", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->down), "down", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->up), "up", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->timeout), "timeout", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->eval), "eval", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(t->history), "history", 0,
	    false);
	if (t->tca[0] > 0 || t->tca[1] > 0 || t->tca[2] > 0) {
		tc = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(tc, ucl_object_fromdouble(t->tca[0]),
		    "delay", 0, false);
		ucl_object_insert_key(tc, ucl_object_fromdouble(t->tca[1]),
		    "ipdv", 0, false);
		ucl_object_insert_key(tc, ucl_object_fromdouble(t->tca[2]),
		    "loss", 0, false);
		ucl_object_insert_key(tc, ucl_object_fromint(t->damping),
		    "damping", 0, false);
		ucl_object_insert_key(o, tc, "tca", 0, false);
	}
	return (o);
}

/*
 * The far end of a point-to-point interface of the host (a gre's or a
 * gif's inner address): its first inet destination, else its first
 * inet6 one that is not link-local.  NULL with none.
 */
static const char *
ptp_dst(struct work *w, const char *ifname)
{
	struct ifaddrs	*ifap, *i;
	const char	*v4, *v6;
	char		 buf[INET6_ADDRSTRLEN];

	if (getifaddrs(&ifap) == -1)
		return (NULL);
	v4 = v6 = NULL;
	for (i = ifap; i != NULL; i = i->ifa_next) {
		if (strcmp(i->ifa_name, ifname) != 0 || (i->ifa_flags &
		    IFF_POINTOPOINT) == 0 || i->ifa_dstaddr == NULL)
			continue;
		if (i->ifa_dstaddr->sa_family == AF_INET && v4 == NULL &&
		    inet_ntop(AF_INET, &((struct sockaddr_in *)(void *)
		    i->ifa_dstaddr)->sin_addr, buf, sizeof(buf)) != NULL)
			v4 = wstrdup(w, buf);
		else if (i->ifa_dstaddr->sa_family == AF_INET6 && v6 == NULL &&
		    !IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *)(void *)
		    i->ifa_dstaddr)->sin6_addr) && inet_ntop(AF_INET6,
		    &((struct sockaddr_in6 *)(void *)i->ifa_dstaddr)->sin6_addr,
		    buf, sizeof(buf)) != NULL)
			v6 = wstrdup(w, buf);
	}
	freeifaddrs(ifap);
	return (v4 != NULL ? v4 : v6);
}

static const char *const mon_keys[] = { "name", "interface", "address",
    "fib", "interval", "size", "dscp", "eval", "history", "down", "up",
    "timeout", "delay-max", "ipdv-max", "loss-max", "damping", NULL };

const char *
monitor_check(const struct arc_job_spec *sp)
{
	const char	*v;
	char		*end;
	double		 d;
	size_t		 i, k;

	if (sp->verb == NULL || (strcmp(sp->verb, "set") != 0 && strcmp(
	    sp->verb, "remove") != 0))
		return ("a monitor job is set or remove");
	if (sp->safe)
		return ("a monitor measures, it changes nothing to undo: not in "
		    "safe mode");
	if (!mon_name_ok(mon_name(sp)))
		return ("a monitor has a name: name=, letters, digits and _ . "
		    "@ -, 63 at most");
	for (i = 0; i < sp->names.n; i++) {
		for (k = 0; mon_keys[k] != NULL; k++)
			if (arg_of(sp->names.v[i], mon_keys[k]) != NULL)
				break;
		if (mon_keys[k] == NULL || (strcmp(sp->verb, "remove") == 0 &&
		    k != 0))
			return (strcmp(sp->verb, "remove") == 0 ? "remove takes "
			    "the monitor's name= alone" : "set takes name=, "
			    "interface=, address=, fib=, interval=, size=, dscp=, "
			    "eval=, history=, down=, up=, timeout=, delay-max=, "
			    "ipdv-max=, loss-max= and damping=");
		/* The numbers' form here; their bounds where they are kept. */
		v = strchr(sp->names.v[i], '=') + 1;
		if (k >= 12 && k <= 14) {
			d = strtod(v, &end);
			if (*v == '\0' || *end != '\0' || d < 0 || (k == 14 &&
			    d > 100))
				return ("a threshold is a number, loss-max a per "
				    "cent");
		} else if (k >= 3) {
			(void)strtol(v, &end, 10);
			if (*v == '\0' || *end != '\0')
				return ("fib=, interval=, size=, dscp=, eval=, "
				    "history=, down=, up=, timeout= and damping= "
				    "are whole numbers");
		}
	}
	return (NULL);
}

char *
monitor_title(const struct arc_job_spec *sp)
{
	const char	*v;
	size_t		 i;
	char		*t;

	v = NULL;
	for (i = 0; i < sp->names.n && v == NULL; i++)
		v = arg_of(sp->names.v[i], "interface");
	if (asprintf(&t, "monitor %s %s%s%s%s%s", sp->verb, mon_name(sp),
	    v != NULL ? " on " : "", v != NULL ? v : "", sp->jail != NULL &&
	    sp->jail[0] != '\0' ? " in " : "", sp->jail != NULL ? sp->jail :
	    "") == -1)
		return (NULL);
	return (t);
}

/* A whole number argument into o's key, checked by targets_parse after. */
static int
put_num(ucl_object_t *o, const char *key, const char *v, const char **errp)
{
	char	*end;
	long	 n;

	errno = 0;
	n = strtol(v, &end, 10);
	if (errno != 0 || *v == '\0' || *end != '\0') {
		*errp = "is not a whole number";
		return (-1);
	}
	ucl_object_insert_key(o, ucl_object_fromint(n), key, 0, true);
	return (0);
}

/*
 * An edge's monitors in the place of those it had: arr, the targets as
 * targets_parse takes them (taken), the owner's file written again.
 */
static int
monitors_put(struct work *w, ucl_object_t *arr, const char *jail,
    const char **errp)
{
	struct target	*new;
	ucl_object_t	*top;
	const char	*e;
	char		*json, path[MAXPATHLEN], jbuf[64];
	int		 n, step;

	if (jail[0] != '\0') {
		top = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(top, ucl_object_fromstring(jail), "jail", 0,
		    false);
		ucl_object_insert_key(top, arr, "targets", 0, false);
	} else
		top = arr;
	n = (int)ucl_array_size(ucl_object_lookup(top, "targets") != NULL ?
	    ucl_object_lookup(top, "targets") : top);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		*errp = "no memory";
		return (-1);
	}
	if ((new = calloc(TARGETS_MAX, sizeof(*new))) == NULL) {
		free(json);
		*errp = strerror(errno);
		return (-1);
	}
	if ((n = targets_parse(w, json, new, jbuf, sizeof(jbuf), OWN_MONITOR,
	    errp)) < 0) {
		free(new);
		free(json);
		return (-1);
	}
	if (!targets_swap(new, n, jail, OWN_MONITOR)) {
		*errp = wfmt(w, "%d targets at most, monitors and SD-WAN's "
		    "together", TARGETS_MAX);
		for (n--; n >= 0; n--)
			target_free(&new[n]);
		free(new);
		free(json);
		return (-1);
	}
	conf_path(path, sizeof(path), jail, OWN_MONITOR);
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", path);
	e = NULL;
	if (n == 0 ? unlink(path) == -1 && errno != ENOENT && (e = strerror(
	    errno)) != NULL : conf_write(json, jail, OWN_MONITOR, &e) != 0) {
		step_end(w, step, false, "%s", e);
		*errp = wfmt(w, "%s: %s", path, e);
		free(json);
		return (-1);
	}
	step_end(w, step, true, "%d monitor%s", n, n == 1 ? "" : "s");
	free(json);
	return (0);
}

/*
 * A monitor set (added, or changed in place: its samples kept when it
 * probes the same address the same way) or removed, at the host or at
 * the vnet jail sp->jail; the owner's file written again.
 */
int
do_monitor_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	ucl_object_t	*arr, *o, *tc;
	const char	*name, *jail, *a, *v, *ifname, *e;
	double		 d;
	size_t		 i;
	int		 k;
	bool		 found;

	name = mon_name(sp);
	jail = sp->jail != NULL ? sp->jail : "";
	if (jail[0] != '\0' && !valid_jail(jail)) {
		*errp = "invalid jail name";
		return (-1);
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	found = false;
	pthread_mutex_lock(&lock);
	for (k = 0; k < ntargets; k++) {
		if (!is_monitor(&targets[k]) || strcmp(targets[k].jail, jail) !=
		    0)
			continue;
		if (strcmp(targets[k].id, name) == 0) {
			found = true;
			continue;
		}
		ucl_array_append(arr, target_conf(&targets[k]));
	}
	pthread_mutex_unlock(&lock);
	if (strcmp(sp->verb, "remove") == 0 && !found) {
		ucl_object_unref(arr);
		*errp = wfmt(w, "no monitor %s%s%s", name, jail[0] != '\0' ?
		    " in jail " : "", jail);
		return (-1);
	}
	if (strcmp(sp->verb, "set") == 0) {
		o = ucl_object_typed_new(UCL_OBJECT);
		tc = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(name), "id", 0,
		    false);
		ifname = NULL;
		e = NULL;
		for (i = 0; i < sp->names.n && e == NULL; i++) {
			a = sp->names.v[i];
			if (arg_of(a, "name") != NULL)
				continue;
			if ((v = arg_of(a, "interface")) != NULL) {
				if (*v == '\0' || strlen(v) >= IFNAMSIZ)
					e = "interface= is an interface's name";
				ifname = v;
				ucl_object_insert_key(o, ucl_object_fromstring(v),
				    "interface", 0, true);
			} else if ((v = arg_of(a, "address")) != NULL)
				ucl_object_insert_key(o, ucl_object_fromstring(v),
				    "address", 0, true);
			else if ((v = arg_of(a, "delay-max")) != NULL ||
			    (v = arg_of(a, "ipdv-max")) != NULL ||
			    (v = arg_of(a, "loss-max")) != NULL) {
				char	*end;

				d = strtod(v, &end);
				if (*v == '\0' || *end != '\0' || d < 0 ||
				    (arg_of(a, "loss-max") != NULL && d > 100))
					e = "a threshold is a number, loss-max a "
					    "per cent";
				ucl_object_insert_key(tc, ucl_object_fromdouble(
				    arg_of(a, "loss-max") != NULL ? d / 100 : d),
				    arg_of(a, "delay-max") != NULL ? "delay" :
				    arg_of(a, "ipdv-max") != NULL ? "ipdv" : "loss",
				    0, true);
			} else if ((v = arg_of(a, "damping")) != NULL) {
				if (put_num(tc, "damping", v, &e) != 0)
					e = wfmt(w, "damping %s", e);
			} else {
				const char	*key = wstrndup(w, a, strcspn(a,
				    "="));

				if (put_num(o, key, strchr(a, '=') + 1, &e) != 0)
					e = wfmt(w, "%s %s", key, e);
			}
		}
		/* On the host, a tunnel's far end and its table found. */
		if (e == NULL && ucl_object_lookup(o, "address") == NULL) {
			if (ifname != NULL && jail[0] == '\0' && (v = ptp_dst(w,
			    ifname)) != NULL)
				ucl_object_insert_key(o, ucl_object_fromstring(v),
				    "address", 0, true);
			else
				e = ifname != NULL && jail[0] == '\0' ? wfmt(w,
				    "%s has no far end to probe (not point to "
				    "point): give address=", ifname) : "address= "
				    "is needed";
		}
		if (e == NULL && ucl_object_lookup(o, "fib") == NULL && ifname !=
		    NULL && jail[0] == '\0' && if_fib(ifname) > 0)
			ucl_object_insert_key(o, ucl_object_fromint(if_fib(
			    ifname)), "fib", 0, true);
		if (e != NULL) {
			ucl_object_unref(o);
			ucl_object_unref(tc);
			ucl_object_unref(arr);
			*errp = e;
			return (-1);
		}
		if (ucl_object_lookup(tc, "delay") != NULL || ucl_object_lookup(
		    tc, "ipdv") != NULL || ucl_object_lookup(tc, "loss") != NULL)
			ucl_object_insert_key(o, tc, "tca", 0, false);
		else
			ucl_object_unref(tc);
		ucl_array_append(arr, o);
	}
	return (monitors_put(w, arr, jail, errp));
}

/*
 * The configuration of the probes as arcana-probe has it: each edge
 * (the host's first, "" its jail) with its SD-WAN targets, the links it
 * watches and the admin's monitors, as JSON
 * {"edges": [{"jail", "targets", "links", "monitors"}]}; malloc'd, NULL
 * for no memory.
 */
char *
probe_conf_json(void)
{
	ucl_object_t		*top, *edges, *e, *l;
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	const char		*jail, *key;
	char			*json;
	int			 k;

	top = ucl_object_typed_new(UCL_OBJECT);
	edges = ucl_object_typed_new(UCL_OBJECT);
	/* The host's, always. */
	e = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(edges, e, "", 0, true);
	pthread_mutex_lock(&lock);
	for (k = 0; k < ntargets + nlinks; k++) {
		/* A target's place left empty is none. */
		if (k < ntargets && targets[k].id[0] == '\0')
			continue;
		jail = k < ntargets ? targets[k].jail : links[k - ntargets].jail;
		if ((o = ucl_object_lookup(edges, jail)) == NULL) {
			e = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(edges, e, jail, 0, true);
		} else
			e = (ucl_object_t *)(uintptr_t)o;
		key = k >= ntargets ? "links" : is_monitor(&targets[k]) ?
		    "monitors" : "targets";
		if ((o = ucl_object_lookup(e, key)) == NULL) {
			l = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(e, l, key, 0, true);
		} else
			l = (ucl_object_t *)(uintptr_t)o;
		if (k < ntargets)
			ucl_array_append(l, target_conf(&targets[k]));
		else {
			o = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key((ucl_object_t *)(uintptr_t)o,
			    ucl_object_fromstring(links[k - ntargets].id), "id",
			    0, false);
			ucl_object_insert_key((ucl_object_t *)(uintptr_t)o,
			    ucl_object_fromstring(links[k - ntargets].ifname),
			    "interface", 0, false);
			ucl_object_insert_key((ucl_object_t *)(uintptr_t)o,
			    ucl_object_fromstring(links[k - ntargets].role),
			    "role", 0, false);
			ucl_array_append(l, (ucl_object_t *)(uintptr_t)o);
		}
	}
	pthread_mutex_unlock(&lock);
	l = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((o = ucl_object_iterate(edges, &it, true)) != NULL) {
		e = ucl_object_copy(o);
		ucl_object_insert_key(e, ucl_object_fromstring(ucl_object_key(o)),
		    "jail", 0, true);
		ucl_array_append(l, e);
	}
	ucl_object_unref(edges);
	ucl_object_insert_key(top, l, "edges", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (json);
}

/*
 * An edge's monitors set together, json {"jail", "targets"} (a
 * monitor's id its name): on the host one without an address probes
 * its interface's far end, through the interface's FIB when it names
 * none.
 */
int
do_monitors_set(struct work *w, const char *json, const char **errp)
{
	struct ucl_parser	*p;
	ucl_object_t		*top, *arr, *o;
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;
	const char		*jail, *ifname, *dst;
	int			 rc;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	if (top == NULL || ucl_object_type(top) != UCL_OBJECT) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the monitors are a JSON object";
		return (-1);
	}
	jail = (v = ucl_object_lookup(top, "jail")) != NULL &&
	    ucl_object_type(v) == UCL_STRING ? ucl_object_tostring(v) : "";
	if (jail[0] != '\0' && !valid_jail(jail)) {
		ucl_object_unref(top);
		*errp = "invalid jail name";
		return (-1);
	}
	jail = wstrdup(w, jail);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(top, "targets"), &it,
	    true)) != NULL) {
		o = ucl_object_copy(e);
		ifname = (v = ucl_object_lookup(o, "interface")) != NULL &&
		    ucl_object_type(v) == UCL_STRING ? ucl_object_tostring(v) :
		    NULL;
		if (ifname != NULL && (ifname[0] == '\0' || strlen(ifname) >=
		    IFNAMSIZ || !valid_ifname(ifname))) {
			ucl_object_unref(o);
			ucl_object_unref(arr);
			ucl_object_unref(top);
			*errp = "a monitor's interface is an interface's name";
			return (-1);
		}
		if (ucl_object_lookup(o, "address") == NULL) {
			if (ifname == NULL || jail[0] != '\0' || (dst = ptp_dst(w,
			    ifname)) == NULL) {
				*errp = ifname != NULL && jail[0] == '\0' ?
				    wfmt(w, "%s has no far end to probe (not "
				    "point to point): give an address", ifname) :
				    "a monitor needs an address";
				ucl_object_unref(o);
				ucl_object_unref(arr);
				ucl_object_unref(top);
				return (-1);
			}
			ucl_object_insert_key(o, ucl_object_fromstring(dst),
			    "address", 0, true);
			if (ucl_object_lookup(o, "fib") == NULL && if_fib(ifname) >
			    0)
				ucl_object_insert_key(o, ucl_object_fromint(
				    if_fib(ifname)), "fib", 0, true);
		}
		ucl_array_append(arr, o);
	}
	ucl_object_unref(top);
	rc = monitors_put(w, arr, jail, errp);
	return (rc);
}
