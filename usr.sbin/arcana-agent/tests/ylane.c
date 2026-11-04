/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ylane uri ca cert key secs [cmd [arg ...]]: the NETCONF stream
 * subscribed over mutual TLS (DTLS over SCTP for an sctp:// uri) while
 * GET-SID dumps, 32 at a time, fill the same association, read a part
 * a millisecond through a 256 KiB socket buffer, as a slow path would.
 * Once the bulk is under way cmd is run; for secs seconds on (two after
 * cmd ended, at most), each arcana-steer steer-changed and arcana-events
 * tunnel event is printed with how late it came (its event-time to
 * now), in the order it came:
 *
 *	steer-changed to=lo reason=failover ms=3.2
 *	tunnel id=void state=down ms=2.9
 *
 * then "bulk <MiB> MiB, <n> dumps, ..." and "max <ms> ms".  For the
 * control lane (PLAN-SDN-YANG 3.5.2): agent_tls_test.sh and
 * agent_root_test.sh.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "ymodel.h"

#define	RCVBUF		(256 * 1024)
#define	SLOW_US		1000
#define	UNDER_WAY_US	1000000
#define	DONE_US		2000000
#define	DUMPS		32	/* in flight: more than the socket holds */

extern char	**environ;

static const struct cbl_ynode	*n_steer, *n_event;
static bool			 opened, closed;
static int			 dumping;
static uint64_t			 bulk_bytes, bulk_parts, bulk_start;
static int			 dumps;
static double			 max_ms;

static uint64_t
mono_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000);
}

/* How long ago an RFC 3339 UTC time with microseconds was, in ms. */
static double
late_ms(const char *t)
{
	struct timespec now;
	struct tm tm;
	const char *p;
	double frac = 0;

	memset(&tm, 0, sizeof(tm));
	if (t == NULL || (p = strptime(t, "%Y-%m-%dT%H:%M:%S", &tm)) == NULL)
		return (-1);
	if (*p == '.')
		frac = strtod(p, NULL);
	clock_gettime(CLOCK_REALTIME, &now);
	return (((double)now.tv_sec - (double)timegm(&tm) - frac) * 1000 +
	    (double)now.tv_nsec / 1000000);
}

static const struct cbl_ynode *
top(const char *mod, const char *name)
{
	const struct cbl_ymodule *m;

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, mod) != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++)
			if (strcmp(m->top[k]->name, name) == 0)
				return (m->top[k]);
	}
	return (NULL);
}

static void
told(const struct cbl_ynotif *nt, cbl_yarena *a)
{
	static const char *const reasons[] = { "preference", "first-up",
	    "failover", "override", "none" };
	static const char *const states[] = { "up", "down", "unknown" };
	struct arcana_steer_steer_changed sc;
	struct arcana_events_event ev;
	double ms;

	ms = late_ms(nt->event_time);
	if (nt->sid == n_steer->sid) {
		memset(&sc, 0, sizeof(sc));
		if (cbl_ydecode(n_steer, nt->content, nt->len, &sc, a, 0, NULL,
		    0) != 0)
			return;
		printf("steer-changed to=%s reason=%s ms=%.1f\n",
		    sc.to != NULL ? sc.to : "-", sc.has_reason &&
		    (size_t)sc.reason < nitems(reasons) ? reasons[sc.reason] :
		    "-", ms);
	} else if (nt->sid == n_event->sid) {
		memset(&ev, 0, sizeof(ev));
		if (cbl_ydecode(n_event, nt->content, nt->len, &ev, a, 0, NULL,
		    0) != 0 || ev.data != ARCANA_EVENTS_EVENT_DATA_TUNNEL ||
		    ev.tunnel == NULL)
			return;
		printf("tunnel id=%s state=%s ms=%.1f\n", ev.tunnel->id !=
		    NULL ? ev.tunnel->id : "-", ev.tunnel->has_state &&
		    (size_t)ev.tunnel->state < nitems(states) ?
		    states[ev.tunnel->state] : "-", ms);
	} else
		return;
	if (ms > max_ms)
		max_ms = ms;
	fflush(stdout);
}

static void
sub_open(cbl_stream *s, cbl_msg *accept, int error, void *arg)
{

	(void)s;
	(void)arg;
	if (error != 0)
		errx(1, "subscribe: %s", accept != NULL &&
		    cbl_msg_err_str(accept) != NULL ? cbl_msg_err_str(accept) :
		    strerror(error));
	opened = true;
}

static void
sub_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct cbl_ynotif nt;
	cbl_yarena *a;

	(void)s;
	(void)arg;
	if ((a = cbl_yarena_new()) == NULL)
		return;
	if (cbl_msg_ynotif(data, &nt, a) == 0)
		told(&nt, a);
	cbl_yarena_free(a);
}

static void
sub_close(cbl_stream *s, int code, const char *text, void *arg)
{

	(void)s;
	(void)code;
	(void)text;
	(void)arg;
	closed = true;
}

static const struct cbl_stream_cbs sub_cbs = {
	.on_open = sub_open,
	.on_data = sub_data,
	.on_close = sub_close,
};

static void
dump_part(cbl_conn *c, cbl_msg *reply, bool final, int error, void *arg)
{

	(void)c;
	(void)error;
	(void)arg;
	if (reply != NULL && !final) {
		bulk_bytes += cbl_msg_len(reply);
		if (bulk_parts++ == 0)
			bulk_start = mono_us();
		usleep(SLOW_US);
	}
	if (final) {
		dumps++;
		dumping--;
	}
}

static void
dump_next(cbl_conn *c)
{
	cbl_msg *m;
	int error;

	if ((error = cbl_msg_new(cbl_conn_ctx(c), CBL_YANG_FAMILY,
	    CBL_YCMD_GET_SID, CBL_F_DUMP, &m)) != 0 ||
	    (error = cbl_request_async(c, m, dump_part, NULL)) != 0)
		errc(1, error, "GET-SID");
	dumping++;
}

static void
drive(cbl_conn *c, int ms)
{
	struct pollfd pfd;
	int ev, tmo;

	ev = 0;
	tmo = -1;
	(void)cbl_conn_interest(c, &ev, &tmo);
	pfd.fd = cbl_conn_fd(c);
	pfd.events = ((ev & CBL_EV_READ) != 0 ? POLLIN : 0) |
	    ((ev & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
	pfd.revents = 0;
	(void)poll(&pfd, 1, tmo >= 0 && tmo < ms ? tmo : ms);
	ev = ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0 ?
	    CBL_EV_READ : 0) | ((pfd.revents & POLLOUT) != 0 ? CBL_EV_WRITE :
	    0);
	if (cbl_conn_process(c, ev) != 0)
		errx(1, "the host is gone: %s", cbl_conn_errstr(c));
	while (dumping < DUMPS)
		dump_next(c);
}

int
main(int argc, char **argv)
{
	struct ietf_subscribed_notifications_establish_subscription_input in;
	const struct cbl_ynode *rpc, *nin = NULL;
	cbl_ctx *ctx;
	cbl_conn *c;
	cbl_tls *tls;
	cbl_stream *s;
	cbl_msg *m;
	uint64_t end;
	pid_t pid = -1;
	int error, st;

	if (argc < 6)
		errx(2, "usage: ylane uri ca cert key secs [cmd [arg ...]]");
	if ((rpc = top("ietf-subscribed-notifications",
	    "establish-subscription")) != NULL)
		for (uint32_t i = 0; i < rpc->nchild; i++)
			if (rpc->child[i]->kind == CBL_YN_INPUT)
				nin = rpc->child[i];
	if (nin == NULL || (n_steer = top("arcana-steer", "steer-changed")) ==
	    NULL || (n_event = top("arcana-events", "event")) == NULL)
		errx(1, "not in the tables");
	if ((error = cbl_ctx_new(&ctx)) != 0 || (error = cbl_conn_new(ctx,
	    argv[1], 0, &c)) != 0)
		errc(1, error, "%s", argv[1]);
	if (cbl_tls_new(&tls) != 0 || cbl_tls_set_cert(tls, argv[3],
	    argv[4]) != 0 || cbl_tls_set_ca(tls, argv[2], NULL) != 0)
		errx(1, "tls: %s", tls != NULL ? cbl_tls_errstr(tls) : "none");
	(void)cbl_conn_set_tls(c, tls);
	if ((error = cbl_conn_connect(c)) != 0)
		errx(1, "%s: %s", argv[1], cbl_conn_errstr(c));
	(void)setsockopt(cbl_conn_fd(c), SOL_SOCKET, SO_RCVBUF,
	    &(int){ RCVBUF }, sizeof(int));

	memset(&in, 0, sizeof(in));
#define	SN(x)	IETF_SUBSCRIBED_NOTIFICATIONS_ESTABLISH_SUBSCRIPTION_INPUT_##x
	in.target = SN(TARGET_STREAM);
#undef SN
	in.stream = "NETCONF";
	if ((error = cbl_msg_new(ctx, CBL_YANG_FAMILY, CBL_YCMD_SUBSCRIBE, 0,
	    &m)) != 0 || (error = cbl_msg_put_ynode(m, nin, &in)) != 0 ||
	    (error = cbl_stream_open(c, m, CBL_SF_PUSH, &sub_cbs, NULL,
	    &s)) != 0)
		errc(1, error, "subscribe");
	while (!opened)
		drive(c, 100);

	/* The bulk well under way: the agent's queue full. */
	while (bulk_parts == 0 || mono_us() - bulk_start < UNDER_WAY_US)
		drive(c, 10);
	if (argc > 6 && (error = posix_spawnp(&pid, argv[6], NULL, NULL,
	    &argv[6], environ)) != 0)
		errc(1, error, "%s", argv[6]);
	end = mono_us() + (uint64_t)atoi(argv[5]) * 1000000;
	while (mono_us() < end && !closed) {
		drive(c, 10);
		if (pid != -1 && waitpid(pid, &st, WNOHANG) == pid) {
			pid = -1;
			if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
				errx(1, "%s failed", argv[6]);
			/* What it set off told by now, or late. */
			if (end > mono_us() + DONE_US)
				end = mono_us() + DONE_US;
		}
	}
	if (pid != -1)
		(void)waitpid(pid, &st, 0);
	printf("bulk %.1f MiB, %d dumps, %ju parts, %.1f s\n",
	    (double)bulk_bytes / 1048576, dumps, (uintmax_t)bulk_parts,
	    (double)(mono_us() - bulk_start) / 1000000);
	printf("max %.1f ms\n", max_ms);
	cbl_conn_free(c);
	cbl_ctx_free(ctx);
	return (0);
}
