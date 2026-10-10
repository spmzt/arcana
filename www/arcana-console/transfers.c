/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A snapshot sent from one host to another, the console carrying the
 * bytes: a zfs-send stream from the one, a zfs-receive stream to the
 * other, both on the connections the console shares with them.  What
 * comes from the sender is passed on, and the room it took is given
 * back to the sender only once the receiver took it, so the two go as
 * fast as the slower and nothing piles up here.
 *
 *	POST /api/transfers {"from", "snapshot", "since", "recursive",
 *	    "to", "dataset"}: one begun, its id said.
 *	GET /api/transfers: each with its state (running, done, failed,
 *	    cancelled, interrupted), bytes, error, started and ended.
 *	DELETE /api/transfers/<id>: one running stopped.
 *
 * A transfer has a thread of its own in the worker that began it, and
 * outlives the request.  What each has done is kept in transfers.json,
 * written as it goes, so that every worker lists them and one that
 * the console's restart cut is said to be; a stop asked of another
 * worker is a mark in that file, which the thread looks for.
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "console.h"

#define	XF_FILE		"transfers.json"
#define	XF_KEEP		32	/* the last of them listed */
#define	XF_RUNNING_MAX	4
#define	XF_WINDOW	(4 * 1024 * 1024)

enum { XF_RUNNING, XF_DONE, XF_FAILED, XF_CANCELLED, XF_INTERRUPTED };
static const char *const xf_states[] = { "running", "done", "failed",
    "cancelled", "interrupted" };

struct xfchunk {
	STAILQ_ENTRY(xfchunk)	 next;
	unsigned char		*p;
	size_t			 len, took;
};

/* One end: the sender's stream or the receiver's. */
struct xfside {
	struct relay		*r;
	cbl_stream		*s;
	bool			 opened, hclosed, closed;
	int			 code;
	char			 why[256];
};

struct relay {
	pthread_mutex_t		 lock;
	pthread_cond_t		 wake;
	STAILQ_HEAD(, xfchunk)	 chunks;
	struct xfside		 from, to;
	/* What the transfer is. */
	uint32_t		 id;
	char			 from_sid[9], to_sid[9];
	char			 from_uri[256], to_uri[256];
	char			 from_peer[256], to_peer[256];	/* "" none */
	char			 snapshot[256], since[256], dataset[256];
	bool			 recursive;
	uint64_t		 bytes;
	time_t			 started;
};

static pthread_mutex_t	xf_lock = PTHREAD_MUTEX_INITIALIZER;
static int		xf_running;

/* A key set: what it was is let go, inserting would keep both. */
static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	(void)ucl_object_delete_key(o, key);
	ucl_object_insert_key(o, v, key, 0, true);
}

/*
 * One transfer's line in the file, made or changed; with cancel,
 * whether a stop was asked is said into *cancel.  The file is read and
 * written under xf_lock, by this worker; another's writes land between.
 */
static void
xf_record(const struct relay *r, int state, const char *error, time_t ended,
    bool *cancel)
{
	ucl_object_t		*top, *arr, *keep, *o;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	size_t			 n;
	bool			 found;

	pthread_mutex_lock(&xf_lock);
	if ((top = store_load(XF_FILE)) == NULL)
		top = ucl_object_typed_new(UCL_OBJECT);
	keep = ucl_object_typed_new(UCL_ARRAY);
	found = false;
	n = 0;
	it = NULL;
	arr = (ucl_object_t *)(uintptr_t)ucl_object_lookup(top, "transfers");
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL) {
		o = ucl_object_copy(e);
		if (ucl_object_toint(ucl_object_lookup(o, "id")) == r->id) {
			found = true;
			if (cancel != NULL)
				*cancel = ucl_object_toboolean(
				    ucl_object_lookup(o, "cancel"));
			put(o, "state", ucl_object_fromstring(xf_states[state]));
			put(o, "bytes", ucl_object_fromint((int64_t)r->bytes));
			if (error != NULL)
				put(o, "error", ucl_object_fromstring(error));
			if (ended != 0)
				put(o, "ended", ucl_object_fromint(ended));
		}
		ucl_array_append(keep, o);
		n++;
	}
	if (!found) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "id", ucl_object_fromint(r->id));
		put(o, "from", ucl_object_fromstring(r->from_sid));
		put(o, "snapshot", ucl_object_fromstring(r->snapshot));
		if (r->since[0] != '\0')
			put(o, "since", ucl_object_fromstring(r->since));
		put(o, "recursive", ucl_object_frombool(r->recursive));
		put(o, "to", ucl_object_fromstring(r->to_sid));
		put(o, "dataset", ucl_object_fromstring(r->dataset));
		put(o, "state", ucl_object_fromstring(xf_states[state]));
		put(o, "bytes", ucl_object_fromint((int64_t)r->bytes));
		put(o, "started", ucl_object_fromint(r->started));
		put(o, "worker", ucl_object_fromint((int64_t)getpid()));
		ucl_array_append(keep, o);
		n++;
	}
	/* The oldest of those that ended go first. */
	while (n > XF_KEEP) {
		ucl_object_unref(ucl_array_pop_first(keep));
		n--;
	}
	put(top, "transfers", keep);
	(void)store_save(XF_FILE, top);
	ucl_object_unref(top);
	pthread_mutex_unlock(&xf_lock);
}

/* The callbacks, on the loop that runs the shared connections. */
static void
side_open(cbl_stream *s __unused, cbl_msg *accept __unused, int error,
    void *arg)
{
	struct xfside	*x = arg;

	pthread_mutex_lock(&x->r->lock);
	x->opened = error == 0;
	if (error != 0) {
		x->closed = true;
		x->code = error;
		snprintf(x->why, sizeof(x->why), "refused: %s",
		    strerror(error));
	}
	pthread_cond_signal(&x->r->wake);
	pthread_mutex_unlock(&x->r->lock);
}

static void
side_hclose(cbl_stream *s __unused, void *arg)
{
	struct xfside	*x = arg;

	pthread_mutex_lock(&x->r->lock);
	x->hclosed = true;
	pthread_cond_signal(&x->r->wake);
	pthread_mutex_unlock(&x->r->lock);
}

static void
side_close(cbl_stream *s __unused, int code, const char *text, void *arg)
{
	struct xfside	*x = arg;

	pthread_mutex_lock(&x->r->lock);
	x->closed = true;
	if (code != 0 && x->code == 0) {
		x->code = code;
		snprintf(x->why, sizeof(x->why), "%s", text != NULL &&
		    text[0] != '\0' ? text : strerror(code));
	}
	pthread_cond_signal(&x->r->wake);
	pthread_mutex_unlock(&x->r->lock);
}

static void
side_writable(cbl_stream *s __unused, size_t credit __unused, void *arg)
{
	struct xfside	*x = arg;

	pthread_mutex_lock(&x->r->lock);
	pthread_cond_signal(&x->r->wake);
	pthread_mutex_unlock(&x->r->lock);
}

/* What the sender sent, kept until the receiver has it. */
static void
from_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct xfside		*x = arg;
	struct arc_chunk	 d;
	struct xfchunk		*c;

	if (cbl_validate(cbl_msg_body(data), &arc_chunk_policy, NULL) != 0 ||
	    arc_chunk_parse(data, cbl_msg_body(data), &d) != 0) {
		(void)cbl_stream_reset(s, EBADMSG);
		return;
	}
	if ((c = calloc(1, sizeof(*c))) == NULL || (c->p = malloc(d.data.len +
	    1)) == NULL) {
		free(c);
		(void)cbl_stream_reset(s, ENOMEM);
		return;
	}
	memcpy(c->p, d.data.p, d.data.len);
	c->len = d.data.len;
	c->took = cbl_msg_len(data);
	pthread_mutex_lock(&x->r->lock);
	STAILQ_INSERT_TAIL(&x->r->chunks, c, next);
	pthread_cond_signal(&x->r->wake);
	pthread_mutex_unlock(&x->r->lock);
}

static const struct cbl_stream_cbs from_cbs = {
	.on_open = side_open,
	.on_data = from_data,
	.on_hclose = side_hclose,
	.on_close = side_close,
};

static const struct cbl_stream_cbs to_cbs = {
	.on_open = side_open,
	.on_hclose = side_hclose,
	.on_close = side_close,
	.on_writable = side_writable,
};

/* A stream opened on cl: the send's from, the receive's to. */
static int
xf_open(struct relay *r, struct arc_client *cl, bool send)
{
	struct arc_zfs_send_req		 sq;
	struct arc_zfs_receive_req	 rq;
	const char			*names[2];
	cbl_msg				*msg;
	int				 error;

	if ((error = cbl_msg_new(cbl_conn_ctx(cl->conn), cl->family, send ?
	    ARC_CMD_ZFS_SEND : ARC_CMD_ZFS_RECEIVE, CBL_F_REQUEST |
	    CBL_F_S_OPEN, &msg)) != 0)
		return (error);
	if (send) {
		memset(&sq, 0, sizeof(sq));
		names[0] = r->snapshot;
		names[1] = r->since;
		sq.names.v = names;
		sq.names.n = r->since[0] != '\0' ? 2 : 1;
		sq.zfs_recursive = r->recursive;
		error = arc_zfs_send_req_put_fields(msg, &sq);
	} else {
		memset(&rq, 0, sizeof(rq));
		names[0] = r->dataset;
		rq.names.v = names;
		rq.names.n = 1;
		error = arc_zfs_receive_req_put_fields(msg, &rq);
	}
	if (error != 0) {
		cbl_msg_free(msg);
		return (error);
	}
	(void)cbl_msg_set_window(msg, XF_WINDOW);
	/* The sender's room comes back by hand, as the receiver takes. */
	return (cbl_stream_open(cl->conn, msg, send ? CBL_SF_MANUAL_CREDIT : 0,
	    send ? &from_cbs : &to_cbs, send ? (void *)&r->from :
	    (void *)&r->to, send ? &r->from.s : &r->to.s));
}

/* Did another worker ask for a stop?  Looked at once in a while. */
static bool
xf_cancelled(struct relay *r)
{
	bool	cancel;

	cancel = false;
	xf_record(r, XF_RUNNING, NULL, 0, &cancel);
	return (cancel);
}

static void *
xf_run(void *arg)
{
	struct relay		*r = arg;
	struct arc_client	 fcl, tcl;
	struct arc_chunk	 c;
	struct xfchunk		*q;
	struct timespec		 until;
	cbl_conn		*fconn, *tconn;
	char			 why[300];
	time_t			 looked;
	int			 state, error;

	fconn = tconn = NULL;
	why[0] = '\0';
	state = XF_FAILED;
	if (hosts_shared(r->from_uri, r->from_peer[0] != '\0' ? r->from_peer :
	    NULL, &fconn, &fcl) != NULL) {
		snprintf(why, sizeof(why), "the sending host does not answer");
		fconn = NULL;
		goto out;
	}
	if (hosts_shared(r->to_uri, r->to_peer[0] != '\0' ? r->to_peer : NULL,
	    &tconn, &tcl) != NULL) {
		snprintf(why, sizeof(why), "the receiving host does not "
		    "answer");
		tconn = NULL;
		goto out;
	}
	/* The receiver first: what is sent has somewhere to go. */
	pthread_mutex_lock(&r->lock);
	if (xf_open(r, &tcl, false) != 0) {
		pthread_mutex_unlock(&r->lock);
		snprintf(why, sizeof(why), "the receiving host refused");
		goto out;
	}
	cbl_stream_ref(r->to.s);
	while (!r->to.opened && !r->to.closed)
		pthread_cond_wait(&r->wake, &r->lock);
	if (r->to.closed) {
		snprintf(why, sizeof(why), "%s", r->to.why);
		pthread_mutex_unlock(&r->lock);
		goto out;
	}
	if (xf_open(r, &fcl, true) != 0) {
		pthread_mutex_unlock(&r->lock);
		snprintf(why, sizeof(why), "the sending host refused");
		goto out;
	}
	cbl_stream_ref(r->from.s);
	looked = time(NULL);
	error = 0;
	for (;;) {
		while (STAILQ_EMPTY(&r->chunks) && !r->from.hclosed &&
		    !r->from.closed && !r->to.closed) {
			clock_gettime(CLOCK_REALTIME, &until);
			until.tv_sec += 1;
			(void)pthread_cond_timedwait(&r->wake, &r->lock, &until);
			if (time(NULL) - looked >= 2)
				break;
		}
		/* The sender or the receiver ended badly: both go. */
		if ((r->from.closed && r->from.code != 0) || (r->to.closed &&
		    !r->from.hclosed) || r->to.code != 0) {
			snprintf(why, sizeof(why), "%s", r->from.code != 0 ?
			    r->from.why : r->to.why[0] != '\0' ? r->to.why :
			    "the receiving host stopped");
			break;
		}
		if (time(NULL) - looked >= 2) {
			pthread_mutex_unlock(&r->lock);
			looked = time(NULL);
			if (xf_cancelled(r))
				error = ECANCELED;
			pthread_mutex_lock(&r->lock);
			if (error != 0)
				break;
			continue;
		}
		if ((q = STAILQ_FIRST(&r->chunks)) == NULL) {
			if (!r->from.hclosed)
				continue;
			/* All was sent: the receiver says how it ended. */
			pthread_mutex_unlock(&r->lock);
			(void)cbl_stream_half_close(r->to.s);
			pthread_mutex_lock(&r->lock);
			while (!r->to.closed)
				pthread_cond_wait(&r->wake, &r->lock);
			if (r->to.code == 0)
				state = XF_DONE;
			else
				snprintf(why, sizeof(why), "%s", r->to.why);
			break;
		}
		STAILQ_REMOVE_HEAD(&r->chunks, next);
		pthread_mutex_unlock(&r->lock);
		memset(&c, 0, sizeof(c));
		c.data.p = q->p;
		c.data.len = q->len;
		while ((error = arc_zfs_receive_send(r->to.s, &c)) == EAGAIN) {
			pthread_mutex_lock(&r->lock);
			while (!r->to.closed && cbl_stream_credit(r->to.s) == 0)
				pthread_cond_wait(&r->wake, &r->lock);
			error = r->to.closed ? EPIPE : 0;
			pthread_mutex_unlock(&r->lock);
			if (error != 0)
				break;
		}
		/* Taken: the sender has its room back. */
		if (error == 0) {
			(void)cbl_stream_consumed(r->from.s, q->took);
			r->bytes += q->len;
		}
		free(q->p);
		free(q);
		pthread_mutex_lock(&r->lock);
		if (error != 0) {
			snprintf(why, sizeof(why), "%s", r->to.why[0] != '\0' ?
			    r->to.why : strerror(error));
			break;
		}
	}
	if (error == ECANCELED)
		state = XF_CANCELLED;
	pthread_mutex_unlock(&r->lock);
	/* What is still open goes. */
	if (state != XF_DONE) {
		if (!r->from.closed)
			(void)cbl_stream_reset(r->from.s, ECANCELED);
		if (!r->to.closed)
			(void)cbl_stream_reset(r->to.s, ECANCELED);
	} else if (!r->from.closed)
		(void)cbl_stream_close(r->from.s, 0, NULL);
out:
	/* Until a stream is closed, its callbacks still look at r. */
	pthread_mutex_lock(&r->lock);
	for (int k = 0; k < 2; k++) {
		struct xfside	*x = k == 0 ? &r->from : &r->to;

		while (x->s != NULL && !x->closed) {
			clock_gettime(CLOCK_REALTIME, &until);
			until.tv_sec += 10;
			if (pthread_cond_timedwait(&r->wake, &r->lock,
			    &until) == ETIMEDOUT)
				break;
		}
	}
	pthread_mutex_unlock(&r->lock);
	if (r->from.s != NULL)
		cbl_stream_rele(r->from.s);
	if (r->to.s != NULL)
		cbl_stream_rele(r->to.s);
	if (fconn != NULL)
		hosts_shared_done(fconn, true);
	if (tconn != NULL)
		hosts_shared_done(tconn, true);
	xf_record(r, state, why[0] != '\0' ? why : NULL, time(NULL), NULL);
	thread_log(LOG_NOTICE, "transfer %u %s: %s to %s%s%s", r->id,
	    xf_states[state], r->snapshot, r->dataset, why[0] != '\0' ? ": " :
	    "", why);
	while ((q = STAILQ_FIRST(&r->chunks)) != NULL) {
		STAILQ_REMOVE_HEAD(&r->chunks, next);
		free(q->p);
		free(q);
	}
	pthread_mutex_destroy(&r->lock);
	pthread_cond_destroy(&r->wake);
	free(r);
	pthread_mutex_lock(&xf_lock);
	xf_running--;
	pthread_mutex_unlock(&xf_lock);
	return (NULL);
}

/* What the console's restart cut: interrupted, once, at start. */
void
transfers_init(void)
{
	ucl_object_t		*top;
	ucl_object_iter_t	 it;
	ucl_object_t		*o;
	bool			 changed;

	if ((top = store_load(XF_FILE)) == NULL)
		return;
	changed = false;
	it = NULL;
	while ((o = (ucl_object_t *)(uintptr_t)ucl_object_iterate(
	    ucl_object_lookup(top, "transfers"), &it, true)) != NULL) {
		const char	*st = ucl_object_tostring(ucl_object_lookup(o,
		    "state"));

		if (st != NULL && strcmp(st, "running") == 0) {
			put(o, "state", ucl_object_fromstring("interrupted"));
			put(o, "ended", ucl_object_fromint(time(NULL)));
			changed = true;
		}
	}
	if (changed)
		(void)store_save(XF_FILE, top);
	ucl_object_unref(top);
}

static bool
name_ok(const char *s, bool snap)
{
	const char	*at;

	if (s == NULL || s[0] == '\0' || s[0] == '-' || strlen(s) > 255)
		return (false);
	at = strchr(s, '@');
	if (snap != (at != NULL))
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.:/-@", *s) ==
		    NULL)
			return (false);
	return (true);
}

int
api_transfers(struct http_request *req)
{
	ucl_object_t		*body, *top, *o;
	const struct server	*fs, *ts;
	struct relay		*r;
	const char		*from, *to, *snap, *since, *ds, *id;
	pthread_t		 tid;
	uint32_t		 n;

	if (req->method == HTTP_METHOD_GET) {
		if (!guard(req, false))
			return (KORE_RESULT_OK);
		pthread_mutex_lock(&xf_lock);
		top = store_load(XF_FILE);
		pthread_mutex_unlock(&xf_lock);
		if (top == NULL)
			top = ucl_object_typed_new(UCL_OBJECT);
		if (ucl_object_lookup(top, "transfers") == NULL)
			put(top, "transfers", ucl_object_typed_new(UCL_ARRAY));
		return (reply_json(req, 200, top));
	}
	if (!guard(req, true))
		return (KORE_RESULT_OK);
	if (req->method == HTTP_METHOD_DELETE) {
		/* A stop: a mark the transfer's thread looks for. */
		id = strrchr(req->path, '/') + 1;
		n = (uint32_t)strtoul(id, NULL, 10);
		pthread_mutex_lock(&xf_lock);
		top = store_load(XF_FILE);
		o = NULL;
		if (top != NULL) {
			ucl_object_iter_t	 it = NULL;
			ucl_object_t		*e;

			while ((e = (ucl_object_t *)(uintptr_t)
			    ucl_object_iterate(ucl_object_lookup(top,
			    "transfers"), &it, true)) != NULL)
				if ((uint32_t)ucl_object_toint(
				    ucl_object_lookup(e, "id")) == n)
					o = e;
		}
		if (o == NULL || strcmp(ucl_object_tostring_forced(
		    ucl_object_lookup(o, "state")), "running") != 0) {
			pthread_mutex_unlock(&xf_lock);
			if (top != NULL)
				ucl_object_unref(top);
			return (reply_error(req, 404, "not-found", "no such "
			    "transfer running"));
		}
		put(o, "cancel", ucl_object_frombool(true));
		(void)store_save(XF_FILE, top);
		pthread_mutex_unlock(&xf_lock);
		ucl_object_unref(top);
		top = ucl_object_typed_new(UCL_OBJECT);
		put(top, "ok", ucl_object_frombool(true));
		return (reply_json(req, 200, top));
	}
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "a JSON object"));
	from = ucl_str(body, "from");
	to = ucl_str(body, "to");
	snap = ucl_str(body, "snapshot");
	since = ucl_str(body, "since");
	ds = ucl_str(body, "dataset");
	if (from == NULL || to == NULL || server_find(from) == NULL ||
	    server_find(to) == NULL) {
		ucl_object_unref(body);
		return (reply_error(req, 404, "not_found", "no such server"));
	}
	if (strcmp(from, to) == 0) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "two hosts: on one, "
		    "replicate the snapshot"));
	}
	if (!name_ok(snap, true) || (since != NULL && since[0] != '\0' &&
	    !name_ok(since, true)) || !name_ok(ds, false) || strchr(ds, '/') ==
	    NULL) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "a snapshot, "
		    "dataset@name, and a dataset under a pool to receive it"));
	}
	pthread_mutex_lock(&xf_lock);
	if (xf_running >= XF_RUNNING_MAX) {
		pthread_mutex_unlock(&xf_lock);
		ucl_object_unref(body);
		return (reply_error(req, 409, "busy", "%d transfers at most, "
		    "at once", XF_RUNNING_MAX));
	}
	xf_running++;
	pthread_mutex_unlock(&xf_lock);
	if ((r = calloc(1, sizeof(*r))) == NULL) {
		ucl_object_unref(body);
		return (reply_error(req, 500, "memory", "out of memory"));
	}
	pthread_mutex_init(&r->lock, NULL);
	pthread_cond_init(&r->wake, NULL);
	STAILQ_INIT(&r->chunks);
	r->from.r = r->to.r = r;
	arc4random_buf(&r->id, sizeof(r->id));
	r->id &= 0x7fffffff;
	snprintf(r->from_sid, sizeof(r->from_sid), "%s", from);
	snprintf(r->to_sid, sizeof(r->to_sid), "%s", to);
	/* Where each is reached, now: the thread does not look again. */
	fs = server_find(from);
	ts = server_find(to);
	snprintf(r->from_uri, sizeof(r->from_uri), "%s", fs->uri);
	snprintf(r->to_uri, sizeof(r->to_uri), "%s", ts->uri);
	snprintf(r->from_peer, sizeof(r->from_peer), "%s", fs->peer_name !=
	    NULL ? fs->peer_name : "");
	snprintf(r->to_peer, sizeof(r->to_peer), "%s", ts->peer_name != NULL ?
	    ts->peer_name : "");
	snprintf(r->snapshot, sizeof(r->snapshot), "%s", snap);
	snprintf(r->since, sizeof(r->since), "%s", since != NULL ? since : "");
	snprintf(r->dataset, sizeof(r->dataset), "%s", ds);
	r->recursive = ucl_flag(body, "recursive");
	r->started = time(NULL);
	ucl_object_unref(body);
	xf_record(r, XF_RUNNING, NULL, 0, NULL);
	n = r->id;
	if (pthread_create(&tid, NULL, xf_run, r) != 0) {
		xf_record(r, XF_FAILED, "no thread for it", time(NULL), NULL);
		pthread_mutex_lock(&xf_lock);
		xf_running--;
		pthread_mutex_unlock(&xf_lock);
		free(r);
		return (reply_error(req, 500, "thread", "no thread for it"));
	}
	(void)pthread_detach(tid);
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "id", ucl_object_fromint(n));
	put(top, "state", ucl_object_fromstring("running"));
	return (reply_json(req, 200, top));
}
