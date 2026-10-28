/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * RESTCONF's event streams (RFC 8040 section 6): a host's NETCONF
 * stream, every event its agent tells, as Server-Sent Events at
 * /restconf/streams/<id>/json, each record RFC 8040's notification JSON
 * on a data line, its event time its id: a client that comes back with
 * Last-Event-ID is sent what the agent kept since that time first (RFC
 * 8639's replay), the last one it had among them again.
 *
 * Each client is a thread of its own, as follow.c's: it subscribes to
 * the host's stream (cblink's YANG family, SUBSCRIBE, RFC 8639's
 * establish-subscription) on a connection nothing else uses, and puts
 * what it hears in a buffer; a timer of the worker's passes the buffers
 * on to the replies, which only the worker may write to.  A comment line
 * every so often keeps the connection from being taken for idle.  The
 * host's stream ending ends the reply, with an error event saying why;
 * the client going stops the thread.
 *
 * The fleet's stream, /restconf/streams/fleet/json: every host's this
 * user may read, on one thread and one reply, each record its
 * notification nested in its host's entry of arcana-fleet (RFC 8528's
 * mount point; RFC 7950 section 7.16.2's notification in a list).  A
 * host whose stream ends is said in an error event naming it; the
 * reply ends with the last of them.
 *
 * A subscription of one's own (RFC 8650, RESTCONF's transport of RFC
 * 8639 and RFC 8641): establish-subscription POSTed under a host's
 * entry, a stream or the operational datastore, periodic or on-change,
 * filtered by XPath, answers with its id and the URI whose GET is its
 * stream, /restconf/subscriptions/<id>; the same client takes it within
 * a minute, once.
 */

#include <sys/param.h>
#include <sys/queue.h>

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "console.h"
#include "restconf.h"
#include "ymodel.h"

#define	RCS_MAX		32		/* at once, of every client */
#define	RCS_OUT_MAX	(4 * 1024 * 1024)	/* not yet passed on */
#define	RCS_TICK_MS	200
#define	RCS_WAKE_MS	250		/* how soon a stop is seen */
#define	RCS_KEEP_S	15		/* a comment line, so often */
#define	SUBS_MAX	64		/* established, not yet taken */
#define	SUB_WAIT_S	60		/* how long one waits to be taken */

/* An establish-subscription's input, as the POST said it. */
struct rcsub {
	uint32_t	 id;		/* 0: the slot is free */
	char		 sid[9];
	char		 who[128];	/* who made it, alone may take it */
	time_t		 made;
	bool		 datastore;	/* else the NETCONF stream */
	bool		 onchange;
	uint32_t	 period, damp;	/* centiseconds */
	char		*xpath, *replay, *stop, *anchor;
};

static struct rcsub	subs[SUBS_MAX];

struct rcs;

/* A host a stream hears, its connection the thread's alone. */
struct rch {
	struct rcs		*rs;
	char			 sid[9];
	char			*uri;
	char			*peer;
	cbl_conn		*conn;	/* NULL: not connected, or let go */
	cbl_tls			*tls;
	struct arc_client	 cl;
	cbl_stream		*s;
	bool			 closed;	/* its stream ended */
	char			 why[200];	/* why */
};

struct rcs {
	LIST_ENTRY(rcs)		 list;
	struct http_request	*req;	/* NULL once the client went */
	struct rch		*h;
	size_t			 nh;
	bool			 fleet;	/* records nested in their hosts */
	pthread_t		 thread;
	atomic_bool		 stop;
	atomic_bool		 ended;	/* the thread is done */
	pthread_mutex_t		 lock;
	struct buf		*out;
	bool			 lost;
	char			 since[40];	/* replay from, or "" */
	struct rcsub		 sub;	/* its input: id 0, the NETCONF stream */
	char			 why[200];	/* why the stream ended */
	time_t			 said;	/* when the reply had a line last */
};

static LIST_HEAD(, rcs)	streams = LIST_HEAD_INITIALIZER(streams);
static int		nstreams;
static struct timer	*ticker;

/* A notification as RFC 8040's JSON (section 6.4): its event time, the
 * notification qualified by its module, in host's entry of the fleet
 * when host is not NULL; malloc'd, or NULL.  Its event time in when. */
static char *
notif_json(const cbl_msg *msg, const char *host, char *when, size_t wlen)
{
	const struct cbl_ynode	*n;
	struct cbl_ynotif	 nt;
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	cbl_yarena		*a;
	void			*data;
	char			*json = NULL;

	if ((a = cbl_yarena_new()) == NULL)
		return (NULL);
	if (cbl_msg_ynotif(msg, &nt, a) != 0)
		goto out;
	snprintf(when, wlen, "%s", nt.event_time);
	if ((n = cbl_yschema_node(&ymodel_schema, nt.sid)) == NULL ||
	    (data = cbl_yarena_alloc(a, n->size)) == NULL ||
	    cbl_ydecode(n, nt.content, nt.len, data, a, 0, NULL, 0) != 0 ||
	    cbl_yjson(n, data, &b) != 0) {
		if (asprintf(&json, "{\"ietf-restconf:notification\":{"
		    "\"eventTime\":\"%s\",\"sid\":\"%ju\"}}", nt.event_time,
		    (uintmax_t)nt.sid) == -1)
			json = NULL;
	} else if (host != NULL ? asprintf(&json,
	    "{\"ietf-restconf:notification\":{\"eventTime\":\"%s\","
	    "\"arcana-fleet:fleet\":{\"host\":[{\"id\":\"%s\",\"%s:%s\":"
	    "%.*s}]}}}", nt.event_time, host, n->module->name, n->name,
	    (int)b.len, (const char *)b.p) == -1 : asprintf(&json,
	    "{\"ietf-restconf:notification\":{\"eventTime\":\"%s\","
	    "\"%s:%s\":%.*s}}", nt.event_time, n->module->name, n->name,
	    (int)b.len, (const char *)b.p) == -1)
		json = NULL;
out:
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
	return (json);
}

static void
rcs_open(cbl_stream *s, cbl_msg *accept, int error, void *arg)
{
	struct rch	*h = arg;

	(void)s;
	if (error != 0) {
		snprintf(h->why, sizeof(h->why), "the host refused: %s",
		    accept != NULL && cbl_msg_err_str(accept) != NULL ?
		    cbl_msg_err_str(accept) : strerror(error));
		h->closed = true;
	}
}

static void
rcs_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct rch	*h = arg;
	struct rcs	*rs = h->rs;
	char		*json, when[64];

	(void)s;
	when[0] = '\0';
	if ((json = notif_json(data, rs->fleet ? h->sid : NULL, when,
	    sizeof(when))) == NULL)
		return;
	/* Its event time its id, where it has one. */
	pthread_mutex_lock(&rs->lock);
	if (rs->out->offset + strlen(json) > RCS_OUT_MAX)
		rs->lost = true;
	else if (when[0] != '\0' && strchr(when, '\n') == NULL)
		buf_appendf(rs->out, "id: %s\ndata: %s\n\n", when, json);
	else
		buf_appendf(rs->out, "data: %s\n\n", json);
	pthread_mutex_unlock(&rs->lock);
	free(json);
}

static void
rcs_close(cbl_stream *s, int code, const char *text, void *arg)
{
	struct rch	*h = arg;

	(void)s;
	(void)code;
	h->closed = true;
	snprintf(h->why, sizeof(h->why), "%s", text != NULL && text[0] !=
	    '\0' ? text : "the host ended the stream");
}

static const struct cbl_stream_cbs rcs_cbs = {
	.on_open = rcs_open,
	.on_data = rcs_data,
	.on_close = rcs_close,
};

/* establish-subscription's input node, in the tables. */
static const struct cbl_ynode *
est_input(void)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*rpc;

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, "ietf-subscribed-notifications") != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++) {
			rpc = m->top[k];
			if (strcmp(rpc->name, "establish-subscription") != 0)
				continue;
			for (uint32_t c = 0; c < rpc->nchild; c++)
				if (rpc->child[c]->kind == CBL_YN_INPUT)
					return (rpc->child[c]);
		}
	}
	return (NULL);
}

#define	SN(x)	IETF_SUBSCRIBED_NOTIFICATIONS_ESTABLISH_SUBSCRIPTION_INPUT_##x

/* establish-subscription's input of the stream rs is: the NETCONF stream,
 * or what a POST said. */
static void
sub_input(const struct rcs *rs,
    struct ietf_subscribed_notifications_establish_subscription_input *in,
    struct ietf_subscribed_notifications_establish_subscription_input_yp_periodic
    *per,
    struct ietf_subscribed_notifications_establish_subscription_input_yp_on_change
    *oc)
{
	const struct cbl_yident	*id;
	const struct rcsub	*sb = &rs->sub;

	memset(in, 0, sizeof(*in));
	memset(per, 0, sizeof(*per));
	memset(oc, 0, sizeof(*oc));
	if (!sb->datastore) {
		in->target = SN(TARGET_STREAM);
		in->stream = "NETCONF";
		if (sb->xpath != NULL) {
			in->stream_filter = SN(STREAM_FILTER_WITHIN_SUBSCRIPTION);
			in->filter_spec = SN(FILTER_SPEC_STREAM_XPATH_FILTER);
			in->stream_xpath_filter = sb->xpath;
		}
		in->replay_start_time = sb->replay != NULL ? sb->replay :
		    rs->since[0] != '\0' ? rs->since : NULL;
	} else {
		in->target = SN(TARGET_DATASTORE);
		for (uint32_t i = 0; i < ymodel_schema.nident; i++) {
			id = &ymodel_schema.ident[i];
			if (strcmp(id->name, "operational") == 0 &&
			    strcmp(id->module->name, "ietf-datastores") == 0) {
				in->has_yp_datastore = true;
				in->yp_datastore = id->sid;
			}
		}
		if (sb->xpath != NULL) {
			in->yp_selection_filter =
			    SN(YP_SELECTION_FILTER_WITHIN_SUBSCRIPTION);
			in->yp_filter_spec =
			    SN(YP_FILTER_SPEC_DATASTORE_XPATH_FILTER);
			in->yp_datastore_xpath_filter = sb->xpath;
		}
		if (sb->onchange) {
			oc->has_dampening_period = true;
			oc->dampening_period = sb->damp;
			in->yp_update_trigger = SN(YP_UPDATE_TRIGGER_ON_CHANGE);
			in->yp_on_change = oc;
		} else {
			per->has_period = true;
			per->period = sb->period;
			per->anchor_time = sb->anchor;
			in->yp_update_trigger = SN(YP_UPDATE_TRIGGER_PERIODIC);
			in->yp_periodic = per;
		}
	}
	in->stop_time = sb->stop;
}

#undef SN

static void
sub_clear(struct rcsub *sb)
{

	free(sb->xpath);
	free(sb->replay);
	free(sb->stop);
	free(sb->anchor);
	memset(sb, 0, sizeof(*sb));
}

/* Host h's stream opened on a connection of its own; false, why in h. */
static bool
rch_open(struct rch *h)
{
	struct ietf_subscribed_notifications_establish_subscription_input in;
	struct ietf_subscribed_notifications_establish_subscription_input_yp_periodic
				 per;
	struct ietf_subscribed_notifications_establish_subscription_input_yp_on_change
				 oc;
	const struct cbl_ynode	*inode;
	const char		*msg;
	cbl_msg			*m;

	if ((msg = hosts_connect(h->uri, h->peer, &h->conn, &h->tls,
	    &h->cl)) != NULL) {
		h->conn = NULL;
		snprintf(h->why, sizeof(h->why), "the host does not answer: %s",
		    msg);
		return (false);
	}
	sub_input(h->rs, &in, &per, &oc);
	if ((inode = est_input()) == NULL || cbl_msg_new(cbl_conn_ctx(h->conn),
	    CBL_YANG_FAMILY, CBL_YCMD_SUBSCRIBE, 0, &m) != 0 ||
	    cbl_msg_put_ynode(m, inode, &in) != 0 || cbl_stream_open(h->conn, m,
	    CBL_SF_PUSH, &rcs_cbs, h, &h->s) != 0) {
		snprintf(h->why, sizeof(h->why), "the host's stream could not "
		    "be opened");
		hosts_release(h->uri, h->peer, h->conn, h->tls, &h->cl, false);
		h->conn = NULL;
		return (false);
	}
	return (true);
}

/* Host h let go, its stream closed first while it is open and its
 * connection whole; in the fleet's, said in an error event naming it. */
static void
rch_done(struct rch *h, bool broken)
{
	struct rcs	*rs = h->rs;
	char		*why, text[260];

	if (h->conn != NULL) {
		/* A connection with a stream on it is no one else's. */
		if (!h->closed && !broken)
			(void)cbl_stream_close(h->s, 0, NULL);
		hosts_release(h->uri, h->peer, h->conn, h->tls, &h->cl, false);
		h->conn = NULL;
	}
	h->closed = true;
	if (!rs->fleet || atomic_load(&rs->stop))
		return;
	snprintf(text, sizeof(text), "host %s: %s", h->sid, h->why);
	if ((why = restconf_errors(502, text)) == NULL)
		return;
	pthread_mutex_lock(&rs->lock);
	buf_appendf(rs->out, "event: error\ndata: %s\n\n", why);
	pthread_mutex_unlock(&rs->lock);
	free(why);
}

static void *
rcs_run(void *arg)
{
	struct rcs	*rs = arg;
	struct pollfd	*pfd;
	struct rch	*h;
	size_t		 i, n, *at;
	int		 error, ev, ms, wait;

	pfd = xcalloc(rs->nh, sizeof(*pfd));
	at = xcalloc(rs->nh, sizeof(*at));
	for (i = 0; i < rs->nh && !atomic_load(&rs->stop); i++)
		if (!rch_open(&rs->h[i]))
			rch_done(&rs->h[i], true);
	while (!atomic_load(&rs->stop)) {
		wait = RCS_WAKE_MS;
		for (i = n = 0; i < rs->nh; i++) {
			h = &rs->h[i];
			if (h->conn == NULL)
				continue;
			if (h->closed) {
				rch_done(h, false);
				continue;
			}
			ev = 0;
			ms = -1;
			(void)cbl_conn_interest(h->conn, &ev, &ms);
			if (ms >= 0 && ms < wait)
				wait = ms;
			pfd[n].fd = cbl_conn_fd(h->conn);
			pfd[n].events = ((ev & CBL_EV_READ) != 0 ? POLLIN : 0) |
			    ((ev & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
			pfd[n].revents = 0;
			at[n++] = i;
		}
		if (n == 0)
			break;
		if (poll(pfd, n, wait) == -1)
			continue;
		for (i = 0; i < n; i++) {
			h = &rs->h[at[i]];
			ev = ((pfd[i].revents & (POLLIN | POLLHUP | POLLERR)) !=
			    0 ? CBL_EV_READ : 0) | ((pfd[i].revents & POLLOUT) !=
			    0 ? CBL_EV_WRITE : 0);
			if ((error = cbl_conn_process(h->conn, ev)) != 0) {
				snprintf(h->why, sizeof(h->why), "the host stopped "
				    "answering: %s", strerror(error));
				rch_done(h, true);
			}
		}
	}
	for (i = 0; i < rs->nh; i++)
		if (rs->h[i].conn != NULL)
			rch_done(&rs->h[i], false);
	snprintf(rs->why, sizeof(rs->why), "%s", rs->fleet ?
	    "every host's stream ended" : rs->h[0].why);
	free(pfd);
	free(at);
	atomic_store(&rs->ended, true);
	return (NULL);
}

static void
rcs_clear(struct rcs *rs)
{

	pthread_mutex_destroy(&rs->lock);
	buf_free(rs->out);
	sub_clear(&rs->sub);
	for (size_t i = 0; i < rs->nh; i++) {
		free(rs->h[i].uri);
		free(rs->h[i].peer);
	}
	free(rs->h);
	free(rs);
}

static void
rcs_free(struct rcs *rs)
{

	(void)pthread_join(rs->thread, NULL);
	LIST_REMOVE(rs, list);
	nstreams--;
	rcs_clear(rs);
}

static void
put(struct http_request *req, const char *s)
{

	http_stream_put(req, s, strlen(s));
}

/* In the worker: what each thread heard, to its reply. */
static void
rcs_tick(void *arg, uint64_t now)
{
	struct rcs	*rs, *next;
	struct buf	*b;
	char		*why;
	time_t		 t;
	bool		 lost;

	(void)arg;
	(void)now;
	t = time(NULL);
	LIST_FOREACH_SAFE(rs, &streams, list, next) {
		pthread_mutex_lock(&rs->lock);
		b = rs->out;
		rs->out = buf_alloc(512);
		lost = rs->lost;
		rs->lost = false;
		pthread_mutex_unlock(&rs->lock);
		if (rs->req != NULL) {
			if (lost)
				put(rs->req, ": some records were left out, the "
				    "client being slow\n\n");
			if (b->offset > 0) {
				http_stream_put(rs->req, b->data, b->offset);
				rs->said = t;
			} else if (t - rs->said >= RCS_KEEP_S) {
				put(rs->req, ": keep-alive\n\n");
				rs->said = t;
			}
		}
		buf_free(b);
		if (!atomic_load(&rs->ended))
			continue;
		/* The host's side ended: so does the reply, saying why. */
		if (rs->req != NULL) {
			if (!atomic_load(&rs->stop) && (why = restconf_errors(
			    502, rs->why)) != NULL) {
				put(rs->req, "event: error\ndata: ");
				put(rs->req, why);
				put(rs->req, "\n\n");
				free(why);
			}
			http_stream_end(rs->req);
			rs->req->hdlr_extra = NULL;
			rs->req = NULL;
		}
		rcs_free(rs);
	}
}

/* The route's on_free: the client went, the thread is stopped. */
void
api_restconf_stream_free(struct http_request *req)
{
	struct rcs	*rs;

	if ((rs = req->hdlr_extra) == NULL)
		return;
	req->hdlr_extra = NULL;
	rs->req = NULL;
	atomic_store(&rs->stop, true);
}

/* The stream of the n hosts sv to req, the fleet's (records nested in
 * their hosts) or one host's, of sb's input (NULL: the NETCONF stream),
 * from since when it is not NULL; the reply begun. */
static int
rcs_start(struct http_request *req, const struct server *const *sv,
    size_t n, bool fleet, struct rcsub *sb, const char *since)
{
	struct rcs	*rs;

	if (nstreams >= RCS_MAX)
		return (restconf_error(req, 503, "too many streams are open: "
		    "try again"));
	rs = xcalloc(1, sizeof(*rs));
	rs->h = xcalloc(n, sizeof(*rs->h));
	rs->nh = n;
	rs->fleet = fleet;
	for (size_t i = 0; i < n; i++) {
		rs->h[i].rs = rs;
		strlcpy(rs->h[i].sid, sv[i]->id, sizeof(rs->h[i].sid));
		rs->h[i].uri = xstrdup(sv[i]->uri);
		rs->h[i].peer = sv[i]->peer_name != NULL ?
		    xstrdup(sv[i]->peer_name) : NULL;
	}
	rs->out = buf_alloc(512);
	rs->said = time(NULL);
	if (sb != NULL) {
		rs->sub = *sb;		/* its strings now the stream's */
		memset(sb, 0, sizeof(*sb));
	}
	if (since != NULL)
		snprintf(rs->since, sizeof(rs->since), "%s", since);
	atomic_init(&rs->stop, false);
	atomic_init(&rs->ended, false);
	pthread_mutex_init(&rs->lock, NULL);
	if (hosts_thread(&rs->thread, rcs_run, rs) != 0) {
		rcs_clear(rs);
		return (restconf_error(req, 503, "no thread for it"));
	}
	LIST_INSERT_HEAD(&streams, rs, list);
	nstreams++;
	rs->req = req;
	req->hdlr_extra = rs;
	http_response_header(req, "content-type", "text/event-stream");
	http_response_header(req, "cache-control", "no-store");
	http_response_header(req, "x-content-type-options", "nosniff");
	http_stream(req, 200);
	/* A first line at once: the client knows it is open. */
	put(req, sb != NULL || rs->sub.datastore ? ": the subscription\n\n" :
	    fleet ? ": the fleet's stream\n\n" :
	    ": the host's NETCONF stream\n\n");
	if (ticker == NULL)
		ticker = timer_add(rcs_tick, RCS_TICK_MS, NULL, 0);
	return (WEB_OK);
}

/* Back after a cut: what came meanwhile first.  An id is an event time,
 * RFC 3339's characters alone; NULL: none. */
static const char *
last_event(struct http_request *req)
{
	const char	*leid;

	if (!http_request_header(req, "last-event-id", &leid) || leid[0] ==
	    '\0' || strlen(leid) >= 40 || leid[strspn(leid,
	    "0123456789-:.TZ+")] != '\0')
		return (NULL);
	return (leid);
}

/* GET /restconf/streams/<id>/json: the host's NETCONF stream as events. */
int
api_restconf_stream(struct http_request *req)
{
	const struct server	*s;
	char			 sid[16];

	if (!guard(req, false))
		return (WEB_OK);
	if (!capture(req, 3, sid, sizeof(sid)) || (s = server_find(sid)) ==
	    NULL)
		return (restconf_error(req, 404, "no such host"));
	if (!host_allowed(req, sid, false, false))
		return (WEB_OK);
	return (rcs_start(req, &s, 1, false, NULL, last_event(req)));
}

/* GET /restconf/streams/fleet/json: every host's this user may read. */
int
api_restconf_fleet_stream(struct http_request *req)
{
	const struct server	*s, **sv;
	size_t			 n = 0;
	int			 rv;

	if (!guard(req, false))
		return (WEB_OK);
	for (int i = 0; server_at(i) != NULL; i++)
		n++;
	sv = xcalloc(n + 1, sizeof(*sv));
	n = 0;
	for (int i = 0; (s = server_at(i)) != NULL; i++)
		if (host_role_ok(req, s->id, false, false))
			sv[n++] = s;
	rv = n == 0 ? restconf_error(req, 404, "no host to hear") :
	    rcs_start(req, sv, n, true, NULL, last_event(req));
	free(sv);
	return (rv);
}

/* A string member of o, a copy; NULL when there is none. */
static char *
str_of(const ucl_object_t *o, const char *key, bool *bad)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(o, key)) == NULL)
		return (NULL);
	if (ucl_object_type(v) != UCL_STRING || strlen(ucl_object_tostring(v))
	    > 1024) {
		*bad = true;
		return (NULL);
	}
	return (xstrdup(ucl_object_tostring(v)));
}

/* A number member of o, lo to hi (a string, as RFC 7951 has uint32's
 * sometimes); false when it is not one. */
static bool
num_of(const ucl_object_t *o, const char *key, int64_t lo, int64_t hi,
    uint32_t *out)
{
	const ucl_object_t	*v;
	char			*end;
	int64_t			 n;

	if ((v = ucl_object_lookup(o, key)) == NULL)
		return (false);
	if (ucl_object_type(v) == UCL_INT)
		n = ucl_object_toint(v);
	else if (ucl_object_type(v) == UCL_STRING) {
		n = strtoll(ucl_object_tostring(v), &end, 10);
		if (*end != '\0' || end == ucl_object_tostring(v))
			return (false);
	} else
		return (false);
	if (n < lo || n > hi)
		return (false);
	*out = (uint32_t)n;
	return (true);
}

/*
 * POST .../host=<id>/ietf-subscribed-notifications:establish-subscription
 * (RFC 8650 section 3.2): the input kept for its stream, its id and URI
 * answered.
 */
int
restconf_establish(struct http_request *req, const char *sid)
{
	const ucl_object_t	*in, *p;
	const struct server	*s;
	struct rcsub		 sb, *slot;
	ucl_object_t		*body, *top, *out;
	const char		*v;
	char			 uri[512];
	time_t			 now;
	bool			 bad = false;

	if (!guard(req, false))
		return (WEB_OK);
	if ((s = server_find(sid)) == NULL)
		return (restconf_error(req, 404, "no such host"));
	if (!host_allowed(req, sid, false, false))
		return (WEB_OK);
	if ((body = read_json(req)) == NULL || (in = ucl_object_lookup(body,
	    "ietf-subscribed-notifications:input")) == NULL ||
	    ucl_object_type(in) != UCL_OBJECT) {
		if (body != NULL)
			ucl_object_unref(body);
		return (restconf_error(req, 400, "the body is {\"ietf-"
		    "subscribed-notifications:input\": {...}}"));
	}
	memset(&sb, 0, sizeof(sb));
	strlcpy(sb.sid, s->id, sizeof(sb.sid));
	snprintf(sb.who, sizeof(sb.who), "%s", session_who(req) != NULL ?
	    session_who(req) : "");
	sb.stop = str_of(in, "stop-time", &bad);
	if ((v = ucl_object_tostring(ucl_object_lookup(in, "stream"))) != NULL) {
		/* A stream: the agent's one, NETCONF. */
		if (strcmp(v, "NETCONF") != 0)
			bad = true;
		sb.xpath = str_of(in, "stream-xpath-filter", &bad);
		sb.replay = str_of(in, "replay-start-time", &bad);
	} else if ((v = ucl_object_tostring(ucl_object_lookup(in,
	    "ietf-yang-push:datastore"))) != NULL) {
		if (strcmp(v, "ietf-datastores:operational") != 0)
			bad = true;
		sb.datastore = true;
		sb.xpath = str_of(in, "ietf-yang-push:datastore-xpath-filter",
		    &bad);
		if ((p = ucl_object_lookup(in, "ietf-yang-push:periodic")) !=
		    NULL) {
			if (!num_of(p, "period", 10, UINT32_MAX, &sb.period))
				bad = true;
			sb.anchor = str_of(p, "anchor-time", &bad);
		} else if ((p = ucl_object_lookup(in,
		    "ietf-yang-push:on-change")) != NULL) {
			sb.onchange = true;
			if (ucl_object_lookup(p, "dampening-period") != NULL &&
			    !num_of(p, "dampening-period", 0, UINT32_MAX,
			    &sb.damp))
				bad = true;
		} else
			bad = true;
	} else
		bad = true;
	ucl_object_unref(body);
	if (bad) {
		sub_clear(&sb);
		return (restconf_error(req, 400, "a subscription is of the "
		    "NETCONF stream, or of ietf-datastores:operational, "
		    "periodic (its period, centiseconds, 10 at least) or "
		    "on-change; its filter an XPath"));
	}
	/* A slot: a free one, or one whose time to be taken is past. */
	now = time(NULL);
	slot = NULL;
	for (int i = 0; i < SUBS_MAX && slot == NULL; i++)
		if (subs[i].id == 0 || now - subs[i].made > SUB_WAIT_S)
			slot = &subs[i];
	if (slot == NULL) {
		sub_clear(&sb);
		return (restconf_error(req, 503, "too many subscriptions wait "
		    "to be taken"));
	}
	sub_clear(slot);
	*slot = sb;
	slot->made = now;
	do
		slot->id = arc4random() & 0x7fffffff;
	while (slot->id == 0);
	snprintf(uri, sizeof(uri), "%s/restconf/subscriptions/%u",
	    cfg.origin != NULL ? cfg.origin : "", slot->id);
	out = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(out, ucl_object_fromint(slot->id), "id", 0,
	    false);
	ucl_object_insert_key(out, ucl_object_fromstring(uri),
	    "ietf-restconf-subscribed-notifications:uri", 0, false);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, out, "ietf-subscribed-notifications:output",
	    0, false);
	return (restconf_reply(req, top));
}

/* GET /restconf/subscriptions/<id>: an established subscription's stream,
 * to whoever made it, once. */
int
api_restconf_subscription(struct http_request *req)
{
	const struct server	*s;
	char			 num[16], *end;
	unsigned long		 id;
	const char		*who;

	if (!guard(req, false))
		return (WEB_OK);
	if (!capture(req, 3, num, sizeof(num)) || (id = strtoul(num, &end,
	    10)) == 0 || *end != '\0')
		return (restconf_error(req, 404, "no such subscription"));
	who = session_who(req) != NULL ? session_who(req) : "";
	for (int i = 0; i < SUBS_MAX; i++) {
		if (subs[i].id != id || strcmp(subs[i].who, who) != 0 ||
		    time(NULL) - subs[i].made > SUB_WAIT_S)
			continue;
		if ((s = server_find(subs[i].sid)) == NULL)
			break;
		if (!host_allowed(req, subs[i].sid, false, false))
			return (WEB_OK);
		subs[i].id = 0;
		return (rcs_start(req, &s, 1, false, &subs[i], NULL));
	}
	return (restconf_error(req, 404, "no such subscription"));
}
