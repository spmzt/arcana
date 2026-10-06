/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What is too large to wait for whole, sent to the page in parts as the
 * host gives them: a WebSocket at /api/stream, on which the page asks
 *
 *	{"id": 7, "server": "<id>", "what": "sysctl", "filter": "kern."}
 *	{"id": 8, "server": "<id>", "what": "routes", "family": "inet",
 *	    "fib": 0, "jail": "", "filter": "10."}
 *
 * what is sysctl, routes, connections or sockets, *
 * and is answered, for that id, with any number of
 *
 *	{"id": 7, "rows": [ ... ]}
 *
 * and then one {"id": 7, "done": true, "total": n}, or
 * {"id": 7, "error": "why"} in its place.  {"id": 7, "stop": true} from
 * the page ends one early.
 *
 * Each request is a task in a thread of its own, which reads the host's
 * dump item by item and writes each to the task's channel; the worker
 * passes them on to the socket.  The host sends an item only when the
 * one before was taken, so a slow page slows the host down and nothing
 * piles up between them.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/queue.h>

#include <ctype.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "console.h"

#define	STREAMS_MAX	16		/* at once, on all sockets */
#define	STREAM_PART	(1024 * 1024)	/* one part's text, at most */

struct stream {
	struct kore_task	 task;	/* first */
	LIST_ENTRY(stream)	 list;
	struct connection	*c;	/* NULL once the socket is gone */
	atomic_bool		 stop;
	uint64_t		 id;
	char			 sid[9];
	char			*uri;
	char			*peer;
	char			 filter[201];
	uint8_t			 kind;		/* ARC_NET_KIND_*, or 255 for sysctl */
	uint8_t			 family;
	uint32_t		 fib;
	char			 jail[256];
};

static LIST_HEAD(, stream)	streams = LIST_HEAD_INITIALIZER(streams);
static int			nstreams;
static char			*part;	/* what the worker reads a part into */

static void
say(struct kore_task *t, const char *fmt, ...) __printflike(2, 3);

static void
say(struct kore_task *t, const char *fmt, ...)
{
	va_list	 ap;
	char	*s;
	int	 n;

	va_start(ap, fmt);
	n = vasprintf(&s, fmt, ap);
	va_end(ap);
	if (n == -1)
		return;
	kore_task_channel_write(t, s, (u_int32_t)n);
	free(s);
}

/* In a task thread: the host's dump, item by item, into the channel. */
static int
stream_run(struct kore_task *t)
{
	struct stream			*s;
	struct arc_client		 cl;
	struct arc_sysctl_dump_req	 dq;
	struct arc_sysctl_dump_rsp	*item;
	cbl_conn			*conn;
	cbl_tls				*tls;
	cbl_dump			*d;
	const char			*msg;
	uint64_t			 total;
	int				 error;
	bool				 ended;

	s = (struct stream *)t;
	if ((msg = hosts_connect(s->uri, s->peer, &conn, &tls, &cl)) != NULL) {
		say(t, "{\"id\":%ju,\"error\":\"the host does not answer\"}",
		    (uintmax_t)s->id);
		kore_log(LOG_NOTICE, "stream %s: %s", s->sid, msg);
		return (KORE_RESULT_OK);
	}
	if (s->kind != 255) {
		struct arc_network_dump_req	 nq;
		struct arc_network_dump_rsp	*nitem;

		memset(&nq, 0, sizeof(nq));
		nq.has_net_kind = true;
		nq.net_kind = s->kind;
		nq.has_net_family = true;
		nq.net_family = s->family;
		nq.has_net_fib = s->fib != 0;
		nq.net_fib = s->fib;
		nq.jail = s->jail[0] != '\0' ? s->jail : NULL;
		nq.net_filter = s->filter[0] != '\0' ? s->filter : NULL;
		if ((error = arc_network_dump(&cl, &nq, &d)) != 0) {
			say(t, "{\"id\":%ju,\"error\":\"the host refused: %s\"}",
			    (uintmax_t)s->id, strerror(error));
			hosts_release(s->uri, s->peer, conn, tls, &cl, false);
			return (KORE_RESULT_OK);
		}
		total = 0;
		ended = false;
		while (!atomic_load(&s->stop)) {
			if ((error = arc_network_dump_next(d, &nitem)) != 0)
				break;
			if (nitem == NULL) {
				ended = true;
				break;
			}
			if (nitem->has_total)
				total = nitem->total;
			if (nitem->json != NULL && nitem->json[0] == '[' &&
			    strlen(nitem->json) < STREAM_PART - 64 &&
			    nitem->json[1] != ']')
				say(t, "{\"id\":%ju,\"rows\":%s}",
				    (uintmax_t)s->id, nitem->json);
		}
		cbl_dump_free(d);
		if (ended)
			say(t, "{\"id\":%ju,\"done\":true,\"total\":%ju}",
			    (uintmax_t)s->id, (uintmax_t)total);
		else if (!atomic_load(&s->stop))
			say(t, "{\"id\":%ju,\"error\":\"the host stopped "
			    "answering: %s\"}", (uintmax_t)s->id,
			    strerror(error));
		hosts_release(s->uri, s->peer, conn, tls, &cl, ended);
		return (KORE_RESULT_OK);
	}
	memset(&dq, 0, sizeof(dq));
	dq.net_filter = s->filter[0] != '\0' ? s->filter : NULL;
	if ((error = arc_sysctl_dump(&cl, &dq, &d)) != 0) {
		say(t, "{\"id\":%ju,\"error\":\"the host refused: %s\"}",
		    (uintmax_t)s->id, strerror(error));
		hosts_release(s->uri, s->peer, conn, tls, &cl, false);
		return (KORE_RESULT_OK);
	}
	total = 0;
	ended = false;
	while (!atomic_load(&s->stop)) {
		if ((error = arc_sysctl_dump_next(d, &item)) != 0)
			break;
		if (item == NULL) {
			ended = true;
			break;
		}
		if (item->has_total)
			total = item->total;
		/* The host's JSON is passed on as it is: an array. */
		if (item->json != NULL && item->json[0] == '[' &&
		    strlen(item->json) < STREAM_PART - 64)
			say(t, "{\"id\":%ju,\"rows\":%s}", (uintmax_t)s->id,
			    item->json);
	}
	cbl_dump_free(d);
	if (ended)
		say(t, "{\"id\":%ju,\"done\":true,\"total\":%ju}",
		    (uintmax_t)s->id, (uintmax_t)total);
	else if (!atomic_load(&s->stop))
		say(t, "{\"id\":%ju,\"error\":\"the host stopped answering: "
		    "%s\"}", (uintmax_t)s->id, strerror(error));
	/* A dump that ended is a connection as good as before. */
	hosts_release(s->uri, s->peer, conn, tls, &cl, ended);
	return (KORE_RESULT_OK);
}

static void
stream_free(struct stream *s)
{

	LIST_REMOVE(s, list);
	nstreams--;
	kore_task_destroy(&s->task);
	kore_free(s->uri);
	kore_free(s->peer);
	kore_free(s);
}

/* In the worker: what the task wrote goes to the socket, if it is there. */
static void
stream_ready(struct kore_task *t)
{
	struct stream	*s;
	u_int32_t	 len;
	int		 avail;

	s = (struct stream *)t;
	/* Every part that is there: the event comes once for several. */
	for (;;) {
		avail = 0;
		if (t->fds[0] == -1 || ioctl(t->fds[0], FIONREAD, &avail) ==
		    -1 || avail < (int)sizeof(u_int32_t))
			break;
		len = kore_task_channel_read(t, part, STREAM_PART);
		if (len > STREAM_PART)
			continue;
		if (s->c != NULL)
			kore_websocket_send(s->c, WEBSOCKET_OP_TEXT, part,
			    len);
	}
	if (kore_task_finished(t))
		stream_free(s);
}

void
stream_connect(struct connection *c)
{

	(void)c;
}

/* The socket went: its requests stop, and end with nobody to tell. */
void
stream_disconnect(struct connection *c)
{
	struct stream	*s;

	LIST_FOREACH(s, &streams, list)
		if (s->c == c) {
			s->c = NULL;
			atomic_store(&s->stop, true);
		}
}

static void
refuse(struct connection *c, uint64_t id, const char *why)
{
	char	buf[256];
	int	n;

	n = snprintf(buf, sizeof(buf), "{\"id\":%ju,\"error\":\"%s\"}",
	    (uintmax_t)id, why);
	kore_websocket_send(c, WEBSOCKET_OP_TEXT, buf, (size_t)n);
}

void
stream_message(struct connection *c, u_int8_t op, void *data, size_t len)
{
	const struct server	*sv;
	struct ucl_parser	*p;
	ucl_object_t		*o;
	struct stream		*s;
	const char		*sid, *what, *filter, *q, *jail, *q2, *fam;
	uint64_t		 id;
	uint8_t			 kind;

	if (op != WEBSOCKET_OP_TEXT || len == 0 || len > 1024)
		return;
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_chunk(p, data, len))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	if (o == NULL)
		return;
	id = (uint64_t)ucl_object_toint(ucl_object_lookup(o, "id"));
	if (ucl_flag(o, "stop")) {
		LIST_FOREACH(s, &streams, list)
			if (s->c == c && s->id == id)
				atomic_store(&s->stop, true);
		ucl_object_unref(o);
		return;
	}
	sid = ucl_str(o, "server");
	what = ucl_str(o, "what");
	filter = ucl_str(o, "filter");
	if (filter == NULL)
		filter = "";
	kind = 255;
	if (what != NULL && strcmp(what, "routes") == 0)
		kind = ARC_NET_KIND_ROUTES;
	else if (what != NULL && strcmp(what, "connections") == 0)
		kind = ARC_NET_KIND_CONNECTIONS;
	else if (what != NULL && strcmp(what, "sockets") == 0)
		kind = ARC_NET_KIND_SOCKETS;
	for (q = filter; *q != '\0'; q++)
		if (!isalnum((unsigned char)*q) && strchr(kind == 255 ? "._-%" :
		    ".:/_-", *q) == NULL)
			break;
	jail = ucl_str(o, "jail");
	if (jail != NULL)
		for (q2 = jail; *q2 != '\0'; q2++)
			if (!isalnum((unsigned char)*q2) && strchr("._-", *q2)
			    == NULL)
				break;
	if (sid == NULL || what == NULL || (strcmp(what, "sysctl") != 0 &&
	    kind == 255) || *q != '\0' || strlen(filter) > 128 || (jail !=
	    NULL && (*q2 != '\0' || strlen(jail) > 255)))
		refuse(c, id, "what is sysctl, routes, connections or sockets, "
		    "of a server, with a filter of letters, digits and "
		    ". _ - % : /");
	else if ((sv = server_find(sid)) == NULL)
		refuse(c, id, "no such server");
	else if (nstreams >= STREAMS_MAX)
		refuse(c, id, "too much is being read at once: try again");
	else {
		if (part == NULL)
			part = kore_malloc(STREAM_PART);
		s = kore_calloc(1, sizeof(*s));
		s->c = c;
		s->id = id;
		atomic_init(&s->stop, false);
		strlcpy(s->sid, sv->id, sizeof(s->sid));
		s->uri = kore_strdup(sv->uri);
		s->peer = sv->peer_name != NULL ? kore_strdup(sv->peer_name) :
		    NULL;
		strlcpy(s->filter, filter, sizeof(s->filter));
		s->kind = kind;
		fam = ucl_str(o, "family");
		s->family = fam != NULL && strcmp(fam, "inet6") == 0 ?
		    ARC_NET_FAMILY_INET6 : fam != NULL && strcmp(fam, "inet") ==
		    0 ? ARC_NET_FAMILY_INET : ARC_NET_FAMILY_ALL;
		s->fib = (uint32_t)ucl_object_toint(ucl_object_lookup(o, "fib"));
		if (jail != NULL)
			strlcpy(s->jail, jail, sizeof(s->jail));
		LIST_INSERT_HEAD(&streams, s, list);
		nstreams++;
		kore_task_create(&s->task, stream_run);
		kore_task_bind_callback(&s->task, stream_ready);
		kore_task_run(&s->task);
	}
	ucl_object_unref(o);
}

/*
 * GET /api/stream, to become a WebSocket.  It needs the session, and a
 * page of ours asking: a browser sends the cookie along from any page,
 * and the Origin is what tells them apart.
 */
int
api_stream(struct http_request *req)
{
	const char	*v;

	if (!guard(req, false))
		return (KORE_RESULT_OK);
	if (!http_request_header(req, "origin", &v) || strcmp(v, cfg.origin) !=
	    0)
		return (reply_error(req, 403, "csrf", "not from the console's "
		    "own page"));
	kore_websocket_handshake(req, "stream_connect", "stream_message",
	    "stream_disconnect");
	return (KORE_RESULT_OK);
}
