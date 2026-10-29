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
 * what is sysctl, routes, connections or sockets,
 * and is answered, for that id, with any number of
 *
 *	{"id": 7, "rows": [ ... ]}
 *
 * and then one {"id": 7, "done": true, "total": n}, or
 * {"id": 7, "error": "why"} in its place.  {"id": 7, "stop": true} from
 * the page ends one early.
 *
 * Each request is a task in a thread of its own, which opens a stream
 * of the host's parts on the connection the console shares with it, and
 * writes each part to the task's channel as it comes; the worker passes
 * them on to the socket.  The host sends ahead only as far as the
 * stream's window, which a part gives back once it was written, so a
 * slow page slows the host down, nothing piles up between them, and
 * the other requests to the host go on beside it.  The sysctls come by
 * arcana-sysctl's read action instead (ytrans.c), a part asked for
 * once the one before was written.
 *
 * what is events too: the host's events as they happen, which do not
 * end (follow.c).
 *
 * And what is read: a read the page would make with GET, done here so
 * that its steps reach the page while the host takes them,
 *
 *	{"id": 9, "server": "<id>", "what": "read", "read": "services"}
 *
 * answered with any number of {"id": 9, "step": {...}}, each step of the
 * trace as it begins and again as it ends (its id that of the whole
 * trace), then {"id": 9, "status": 200, "reply": {...}}, what GET
 * /api/servers/<id>/services answers.  read is the path after
 * /api/servers/<id>/ of any read of a host's (hosts.c's hreads), its
 * query string with it: "net/routes?fib=1", "storage/pools".
 */

#include <sys/param.h>
#include <sys/queue.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "console.h"
#include "ynet.h"
#include "ytrans.h"
#include "ymodel.h"

#define	STREAMS_MAX	16		/* at once, on all sockets */
#define	STREAM_PART	(1024 * 1024)	/* one part's text, at most */
#define	STREAM_WINDOW	(2 * 1024 * 1024)	/* the host sends ahead */
#define	SYSCTL_PART	120		/* values asked for at once */

struct stream {
	struct task	 task;	/* first */
	LIST_ENTRY(stream)	 list;
	struct conn	*c;	/* NULL once the socket is gone */
	atomic_bool		 stop;
	uint64_t		 id;
	char			 sid[9];
	char			*uri;
	char			*peer;
	char			 filter[201];
	uint8_t			 kind;		/* ARC_NET_KIND_*, or 255 for sysctl */
	char			 read[256];	/* a read's: its path and query */
	char			*name;		/* a read's: the server's name */
	uint8_t			 family;
	uint32_t		 fib;
	char			 jail[256];
};

static LIST_HEAD(, stream)	streams = LIST_HEAD_INITIALIZER(streams);
static int			nstreams;
static char			*part;	/* what the worker reads a part into */

static void
say(struct task *t, const char *fmt, ...) __printflike(2, 3);

static void
say(struct task *t, const char *fmt, ...)
{
	va_list	 ap;
	char	*s;
	int	 n;

	va_start(ap, fmt);
	n = vasprintf(&s, fmt, ap);
	va_end(ap);
	if (n == -1)
		return;
	task_channel_write(t, s, (u_int32_t)n);
	free(s);
}

/*
 * The parts as they come, from the loop that runs the shared connection
 * (hosts_shared()): each queued as the text for the page, with what it
 * took of the stream's window, which is given back only once the task
 * wrote it to its channel.  A page that does not keep up so holds its
 * own stream, and neither the loop nor the other requests to the host.
 */
struct qpart {
	STAILQ_ENTRY(qpart)	 next;
	char			*text;
	size_t			 len;	/* bytes of the window it took */
};

struct reader {
	pthread_mutex_t		 lock;
	pthread_cond_t		 wake;
	STAILQ_HEAD(, qpart)	 parts;
	uint64_t		 id;
	uint64_t		 total;
	bool			 opened, ended, closed;
	int			 code;
	char			 why[160];
};

static void
r_open(cbl_stream *st __unused, cbl_msg *accept __unused, int error,
    void *arg)
{
	struct reader	*r = arg;

	pthread_mutex_lock(&r->lock);
	r->opened = error == 0;
	if (error != 0) {
		r->code = error;
		snprintf(r->why, sizeof(r->why), "the host refused: %s",
		    strerror(error));
	}
	pthread_cond_signal(&r->wake);
	pthread_mutex_unlock(&r->lock);
}

static void
r_data(cbl_stream *st, cbl_msg *data, void *arg)
{
	struct reader				*r = arg;
	struct arcana_network_network_part	 d;
	struct qpart				*q;
	ucl_object_t				*o;
	const ucl_object_t			*list;
	char					*rows, *text;
	cbl_yarena				*a;

	if ((a = cbl_yarena_new()) == NULL) {
		(void)cbl_stream_reset(st, ENOMEM);
		return;
	}
	memset(&d, 0, sizeof(d));
	if (arcana_network_network_part_parse(data, &d, a, CBL_YD_STRICT,
	    NULL, 0) != 0) {
		cbl_yarena_free(a);
		(void)cbl_stream_reset(st, EBADMSG);
		return;
	}
	/* The rows typed, as the tools wrote them (ynet.c). */
	rows = NULL;
	if ((o = ynet_part_json(&d)) != NULL) {
		list = ucl_object_lookup(o, d.route.n > 0 ? "route" :
		    d.connection.n > 0 ? "connection" : "socket");
		if (ucl_array_size(list) > 0)
			rows = (char *)ucl_object_emit(list,
			    UCL_EMIT_JSON_COMPACT);
		ucl_object_unref(o);
	}
	text = NULL;
	if (rows != NULL && strlen(rows) < STREAM_PART - 64 && asprintf(&text,
	    "{\"id\":%ju,\"rows\":%s}", (uintmax_t)r->id, rows) == -1)
		text = NULL;
	free(rows);
	if ((q = calloc(1, sizeof(*q))) == NULL) {
		free(text);
		cbl_yarena_free(a);
		(void)cbl_stream_reset(st, ENOMEM);
		return;
	}
	q->text = text;
	q->len = cbl_msg_len(data);
	pthread_mutex_lock(&r->lock);
	if (d.has_total)
		r->total = d.total;
	STAILQ_INSERT_TAIL(&r->parts, q, next);
	pthread_cond_signal(&r->wake);
	pthread_mutex_unlock(&r->lock);
	cbl_yarena_free(a);
}

static void
r_hclose(cbl_stream *st __unused, void *arg)
{
	struct reader	*r = arg;

	pthread_mutex_lock(&r->lock);
	r->ended = true;
	pthread_cond_signal(&r->wake);
	pthread_mutex_unlock(&r->lock);
}

static void
r_close(cbl_stream *st __unused, int code, const char *text, void *arg)
{
	struct reader	*r = arg;

	pthread_mutex_lock(&r->lock);
	r->closed = true;
	if (!r->ended && code != 0) {
		r->code = code;
		snprintf(r->why, sizeof(r->why), "%s", text != NULL &&
		    text[0] != '\0' ? text : strerror(code));
	}
	pthread_cond_signal(&r->wake);
	pthread_mutex_unlock(&r->lock);
}

static const struct cbl_stream_cbs reader_cbs = {
	.on_open = r_open,
	.on_data = r_data,
	.on_hclose = r_hclose,
	.on_close = r_close,
};

/* The stream asked for, with the room given back by hand. */
static int
open_parts(struct stream *s, cbl_conn *conn, struct reader *r,
    cbl_stream **sp)
{
	struct arcana_network_network_part	 nq;
	cbl_family_info				*info;
	cbl_msg					*msg;
	uint16_t				 fam;
	int					 error;

	/* The agent's arcana-parts family, its network-parts stream. */
	if ((error = cbl_resolve(conn, YNET_PARTS_FAMILY, &info)) != 0)
		return (error);
	fam = cbl_family_info_id(info);
	cbl_family_info_free(info);
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), fam,
	    YNET_PARTS_NETWORK, CBL_F_REQUEST | CBL_F_S_OPEN, &msg)) != 0)
		return (error);
	memset(&nq, 0, sizeof(nq));
	nq.has_kind = true;
	nq.kind = s->kind == ARC_NET_KIND_CONNECTIONS ?
	    ARCANA_NETWORK_NETWORK_PART_KIND_CONNECTIONS : s->kind ==
	    ARC_NET_KIND_SOCKETS ? ARCANA_NETWORK_NETWORK_PART_KIND_SOCKETS :
	    ARCANA_NETWORK_NETWORK_PART_KIND_ROUTES;
	nq.has_family = true;
	nq.family = s->family == ARC_NET_FAMILY_INET ?
	    ARCANA_NETWORK_NETWORK_PART_FAMILY_INET : s->family ==
	    ARC_NET_FAMILY_INET6 ? ARCANA_NETWORK_NETWORK_PART_FAMILY_INET6 :
	    ARCANA_NETWORK_NETWORK_PART_FAMILY_ALL;
	nq.has_fib = s->fib != 0;
	nq.fib = s->fib;
	nq.jail = s->jail[0] != '\0' ? s->jail : NULL;
	nq.filter = s->filter[0] != '\0' ? s->filter : NULL;
	if ((error = arcana_network_network_part_put(msg, &nq)) != 0) {
		cbl_msg_free(msg);
		return (error);
	}
	(void)cbl_msg_set_window(msg, STREAM_WINDOW);
	return (cbl_stream_open(conn, msg, CBL_SF_MANUAL_CREDIT,
	    &reader_cbs, r, sp));
}

/* A step of a read, as the host tells it: to the page at once. */
static void
read_step(const char *json, void *arg)
{
	struct stream	*s = arg;

	if (!atomic_load(&s->stop))
		say(&s->task, "{\"id\":%ju,\"step\":%s}", (uintmax_t)s->id,
		    json);
}

/* In a task thread: a read, its steps as they come, then its answer. */
static int
read_run(struct task *t)
{
	struct stream	*s;
	char		*json;
	int		 status;

	s = (struct stream *)t;
	json = hosts_read_live(s->sid, s->uri, s->peer, s->name, s->read,
	    read_step, s, &status);
	if (atomic_load(&s->stop))
		;
	else if (json == NULL)
		say(t, "{\"id\":%ju,\"error\":\"the host does not answer\"}",
		    (uintmax_t)s->id);
	else if (strlen(json) + 64 > STREAM_PART)
		say(t, "{\"id\":%ju,\"error\":\"too large for the socket: "
		    "read it with GET\"}", (uintmax_t)s->id);
	else
		say(t, "{\"id\":%ju,\"status\":%d,\"reply\":%s}",
		    (uintmax_t)s->id, status, json);
	free(json);
	return (WEB_OK);
}

/*
 * In a task thread: the kernel's values by arcana-sysctl's read action,
 * a part at a time, each asked for once the one before was written.
 */
static int
sysctl_run(struct task *t)
{
	struct stream		*s;
	ucl_object_t		*rows;
	cbl_conn		*conn;
	const char		*msg;
	unsigned char		*json;
	char			*after = NULL, *next, err[256];
	uint64_t		 total, sent = 0;
	int			 error = 0;

	s = (struct stream *)t;
	if ((msg = hosts_shared(s->uri, s->peer, &conn)) != NULL) {
		say(t, "{\"id\":%ju,\"error\":\"the host does not answer\"}",
		    (uintmax_t)s->id);
		log_msg(LOG_NOTICE, "stream %s: %s", s->sid, msg);
		return (WEB_OK);
	}
	do {
		if ((error = ytrans_sysctl_part(conn, s->filter, s->jail[0] !=
		    '\0' ? s->jail : NULL, after, SYSCTL_PART, &rows, &next,
		    &total, err, sizeof(err))) != 0)
			break;
		free(after);
		after = next;
		sent += ucl_array_size(rows);
		json = ucl_object_emit(rows, UCL_EMIT_JSON_COMPACT);
		ucl_object_unref(rows);
		if (json != NULL && strlen((char *)json) < STREAM_PART - 64 &&
		    !atomic_load(&s->stop))
			say(t, "{\"id\":%ju,\"rows\":%s}", (uintmax_t)s->id,
			    (char *)json);
		free(json);
	} while (after != NULL && !atomic_load(&s->stop));
	free(after);
	hosts_shared_done(conn, error == 0);
	if (atomic_load(&s->stop))
		;
	else if (error == 0)
		say(t, "{\"id\":%ju,\"done\":true,\"total\":%ju}",
		    (uintmax_t)s->id, (uintmax_t)sent);
	else {
		for (char *p = err; *p != '\0'; p++)
			if (*p == '"' || *p == '\\')
				*p = '\'';
		say(t, "{\"id\":%ju,\"error\":\"%s\"}", (uintmax_t)s->id,
		    err);
	}
	return (WEB_OK);
}

/* In a task thread: the host's parts, as they come, into the channel. */
static int
stream_run(struct task *t)
{
	struct stream		*s;
	struct reader		 r;
	struct qpart		*q;
	cbl_conn		*conn;
	cbl_stream		*st;
	const char		*msg;
	struct timespec		 until;
	bool			 good;

	s = (struct stream *)t;
	if ((msg = hosts_shared(s->uri, s->peer, &conn)) != NULL) {
		say(t, "{\"id\":%ju,\"error\":\"the host does not answer\"}",
		    (uintmax_t)s->id);
		log_msg(LOG_NOTICE, "stream %s: %s", s->sid, msg);
		return (WEB_OK);
	}
	memset(&r, 0, sizeof(r));
	pthread_mutex_init(&r.lock, NULL);
	pthread_cond_init(&r.wake, NULL);
	STAILQ_INIT(&r.parts);
	r.id = s->id;
	st = NULL;
	pthread_mutex_lock(&r.lock);
	if (open_parts(s, conn, &r, &st) != 0) {
		pthread_mutex_unlock(&r.lock);
		say(t, "{\"id\":%ju,\"error\":\"the host refused\"}",
		    (uintmax_t)s->id);
		hosts_shared_done(conn, false);
		goto out;
	}
	/* Ours until we are done, whenever it ends. */
	cbl_stream_ref(st);
	for (;;) {
		/* Woken by a part, its end, or a second to look at stop. */
		while (STAILQ_EMPTY(&r.parts) && !r.ended && !r.closed &&
		    !atomic_load(&s->stop)) {
			clock_gettime(CLOCK_REALTIME, &until);
			until.tv_sec += 1;
			(void)pthread_cond_timedwait(&r.wake, &r.lock, &until);
		}
		if (atomic_load(&s->stop) || (STAILQ_EMPTY(&r.parts) &&
		    (r.ended || r.closed)))
			break;
		q = STAILQ_FIRST(&r.parts);
		STAILQ_REMOVE_HEAD(&r.parts, next);
		pthread_mutex_unlock(&r.lock);
		/* Written, then its room given back: the host sends on. */
		if (q->text != NULL)
			say(t, "%s", q->text);
		(void)cbl_stream_consumed(st, q->len);
		free(q->text);
		free(q);
		pthread_mutex_lock(&r.lock);
	}
	good = r.ended && r.code == 0;
	if (atomic_load(&s->stop))
		;
	else if (good)
		say(t, "{\"id\":%ju,\"done\":true,\"total\":%ju}",
		    (uintmax_t)s->id, (uintmax_t)r.total);
	else
		say(t, "{\"id\":%ju,\"error\":\"%s\"}", (uintmax_t)s->id,
		    r.why[0] != '\0' ? r.why : "the host stopped answering");
	pthread_mutex_unlock(&r.lock);
	/* Stopped, or what the host sent ended: the stream goes. */
	if (!r.closed && good)
		(void)cbl_stream_close(st, 0, NULL);
	else if (!r.closed)
		(void)cbl_stream_reset(st, ECANCELED);
	/* Until it is closed its callbacks still look at r. */
	pthread_mutex_lock(&r.lock);
	while (!r.closed) {
		clock_gettime(CLOCK_REALTIME, &until);
		until.tv_sec += 5;
		if (pthread_cond_timedwait(&r.wake, &r.lock, &until) ==
		    ETIMEDOUT)
			break;
	}
	pthread_mutex_unlock(&r.lock);
	cbl_stream_rele(st);
	hosts_shared_done(conn, true);
out:
	while ((q = STAILQ_FIRST(&r.parts)) != NULL) {
		STAILQ_REMOVE_HEAD(&r.parts, next);
		free(q->text);
		free(q);
	}
	pthread_mutex_destroy(&r.lock);
	pthread_cond_destroy(&r.wake);
	return (WEB_OK);
}

static void
stream_free(struct stream *s)
{

	LIST_REMOVE(s, list);
	nstreams--;
	task_destroy(&s->task);
	free(s->uri);
	free(s->peer);
	free(s->name);
	free(s);
}

/* In the worker: what the task wrote goes to the socket, if it is there. */
static void
stream_ready(struct task *t)
{
	struct stream	*s;
	u_int32_t	 len;

	s = (struct stream *)t;
	/* Every part that is there: the event comes once for several. */
	while (task_channel_pending(t)) {
		len = task_channel_read(t, part, STREAM_PART);
		if (len > STREAM_PART)
			continue;
		if (s->c != NULL)
			ws_send(s->c, WS_OP_TEXT, part,
			    len);
	}
	if (task_finished(t))
		stream_free(s);
}

void
stream_connect(struct conn *c)
{

	(void)c;
}

/*
 * The console user the socket was opened by (users.c), kept on the
 * connection by api_stream(); NULL for a session with none.  Each
 * host asked for is theirs to read, or refused as if it were not.
 */
static bool
stream_host_ok(struct conn *c, const char *sid)
{

	return (user_host(c->hdlr_extra, sid) != ROLE_NONE);
}

/* The socket went: its requests stop, and end with nobody to tell. */
void
stream_disconnect(struct conn *c)
{
	struct stream	*s;

	LIST_FOREACH(s, &streams, list)
		if (s->c == c) {
			s->c = NULL;
			atomic_store(&s->stop, true);
		}
	(void)follow_stop(c, 0, true);
	free(c->hdlr_extra);
	c->hdlr_extra = NULL;
}

static void
refuse(struct conn *c, uint64_t id, const char *why)
{
	char	buf[256];
	int	n;

	n = snprintf(buf, sizeof(buf), "{\"id\":%ju,\"error\":\"%s\"}",
	    (uintmax_t)id, why);
	ws_send(c, WS_OP_TEXT, buf, (size_t)n);
}

void
stream_message(struct conn *c, u_int8_t op, void *data, size_t len)
{
	const struct server	*sv;
	struct ucl_parser	*p;
	ucl_object_t		*o;
	struct stream		*s;
	const char		*sid, *what, *filter, *q, *jail, *q2, *fam;
	uint64_t		 id;
	uint8_t			 kind;

	if (op != WS_OP_TEXT || len == 0 || len > 1024)
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
		(void)follow_stop(c, id, false);
		ucl_object_unref(o);
		return;
	}
	sid = ucl_str(o, "server");
	what = ucl_str(o, "what");
	if (sid != NULL && what != NULL && strcmp(what, "events") == 0) {
		const char	*why;

		if ((sv = server_find(sid)) == NULL || !stream_host_ok(c, sid))
			refuse(c, id, "no such server");
		else if ((why = follow_start(c, id, sv)) != NULL)
			refuse(c, id, why);
		ucl_object_unref(o);
		return;
	}
	if (sid != NULL && what != NULL && strcmp(what, "read") == 0) {
		const char	*rd = ucl_str(o, "read");

		if (rd == NULL || strlen(rd) >= sizeof(s->read) ||
		    !hosts_read_known(rd))
			refuse(c, id, "read is the path of a read of a host's, "
			    "after /api/servers/<id>/");
		else if ((sv = server_find(sid)) == NULL || !stream_host_ok(c,
		    sid))
			refuse(c, id, "no such server");
		else if (nstreams >= STREAMS_MAX)
			refuse(c, id, "too much is being read at once: try "
			    "again");
		else {
			if (part == NULL)
				part = xmalloc(STREAM_PART);
			s = xcalloc(1, sizeof(*s));
			s->c = c;
			s->id = id;
			atomic_init(&s->stop, false);
			strlcpy(s->sid, sv->id, sizeof(s->sid));
			strlcpy(s->read, rd, sizeof(s->read));
			s->uri = xstrdup(sv->uri);
			s->peer = sv->peer_name != NULL ?
			    xstrdup(sv->peer_name) : NULL;
			s->name = xstrdup(sv->name);
			LIST_INSERT_HEAD(&streams, s, list);
			nstreams++;
			task_create(&s->task, read_run);
			task_bind_callback(&s->task, stream_ready);
			task_run(&s->task);
		}
		ucl_object_unref(o);
		return;
	}
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
	else if ((sv = server_find(sid)) == NULL || !stream_host_ok(c, sid))
		refuse(c, id, "no such server");
	else if (nstreams >= STREAMS_MAX)
		refuse(c, id, "too much is being read at once: try again");
	else {
		if (part == NULL)
			part = xmalloc(STREAM_PART);
		s = xcalloc(1, sizeof(*s));
		s->c = c;
		s->id = id;
		atomic_init(&s->stop, false);
		strlcpy(s->sid, sv->id, sizeof(s->sid));
		s->uri = xstrdup(sv->uri);
		s->peer = sv->peer_name != NULL ? xstrdup(sv->peer_name) :
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
		task_create(&s->task, kind == 255 ? sysctl_run : stream_run);
		task_bind_callback(&s->task, stream_ready);
		task_run(&s->task);
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
		return (WEB_OK);
	if (!http_request_header(req, "origin", &v) || (strcmp(v,
	    cfg.origin) != 0 && !cluster_origin(v)))
		return (reply_error(req, 403, "csrf", "not from the console's "
		    "own page"));
	/* Whose socket: the user's name stays with the connection. */
	free(req->owner->hdlr_extra);
	req->owner->hdlr_extra = session_user(req) != NULL ? xstrdup(
	    session_user(req)) : NULL;
	ws_handshake(req, stream_connect, stream_message, stream_disconnect);
	return (WEB_OK);
}
