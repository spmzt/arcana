/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What the console holds of each agent by subscription (PLAN-SDN-YANG
 * 3.4): one long-lived connection to it, beside the requests' pool,
 * on a thread of its own, carrying RFC 8639's dynamic subscriptions
 * (cblink's SUBSCRIBE streams):
 *
 *	jobs	arcana-jobs, on-change: the agent tells each job queued,
 *		begun, confirmed, finished or forgotten (RFC 8641);
 *	stats	arcana-host's stats, periodic;
 *	jails	arcana-jails, periodic;
 *	sdwan	arcana-sdwan's state, periodic, and arcana-probe's
 *		targets and samples, read by the thread at the same
 *		period (their samples are a list too long to push whole);
 *	events	the NETCONF stream, each of arcana-events' events
 *		relayed to the pages that follow the host (follow.c).
 *
 * A topic is subscribed once a read of it asks (watch_held(), from a
 * request's task) for the user it is asked for, whose access rules
 * (NACM) the host holds the subscription to, and let go when nothing
 * asked for it for a while.  The first read of a topic, and every read
 * while there is nothing held of it, goes to the host as before; once
 * the first push came, the reads are answered from it.  A push-update
 * is the whole of it, a push-change-update a YANG Patch applied to a
 * copy of the last, each made the module's struct (cbl_dtree_to_module)
 * that the reads take a reference to.
 *
 * The connection lost (the agent restarted, updated, gone), what is
 * held goes with it and the reads go to the host again; it is made
 * again a second on, then two, doubling to a minute, and the topics
 * still asked for are subscribed anew.  An agent that has no such
 * subscription (one of the release before) refuses it, and its reads
 * go to it as they always did.
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
#include <cbl_data.h>
#include <cbl_schema.h>

#include "console.h"
#include "ygula.h"
#include "yhostjson.h"
#include "ymodel.h"
#include "yqueue.h"

#define	WATCH_MAX	64		/* hosts at once */
#define	WATCH_WAKE_MS	250	/* how soon a stop or a want is seen */
#define	WATCH_IDLE_US	(120 * 1000000ULL)	/* a topic nobody asked for */
#define	WATCH_GONE_US	(600 * 1000000ULL)	/* the connection, likewise */
#define	WATCH_BACKOFF_S	60		/* reconnect at most this far apart */
#define	WATCH_WINDOW	(4 * 1024 * 1024)	/* a push's room on the stream */

struct wtopic {
	const char	*name;
	const char	*mod, *top;	/* its module and top-level node */
	const char	*xpath;		/* what of it; NULL: all of it */
	bool		 onchange;
	uint32_t	 cs;		/* the period, or the dampening period */
};

static const struct wtopic topics[WATCH_NTOPIC] = {
	[WATCH_JOBS] = { "jobs", "arcana-jobs", "jobs", NULL, true, 100 },
	[WATCH_STATS] = { "stats", "arcana-host", "host",
	    "/arcana-host:host/stats", false, 500 },
	[WATCH_JAILS] = { "jails", "arcana-jails", "jails", NULL, false, 500 },
	[WATCH_SDWAN] = { "sdwan", "arcana-sdwan", "sdwan", NULL, false, 200 },
	[WATCH_EVENTS] = { "events", NULL, NULL, NULL, false, 0 },
};

/* A topic subscribed for one user; wlock's but for the thread's s. */
struct wsub {
	LIST_ENTRY(wsub)	 link;
	struct watch		*w;
	int			 topic;
	char			 user[64];	/* "": the console's own */
	cbl_stream		*s;		/* the thread's */
	int			 state;		/* WATCH_S_* */
	uint64_t		 wanted;	/* µs, when last asked for */
	struct held		*held;		/* the last push, or NULL */
	uint64_t		 pushes;
	int			 bad;		/* pushes not read, in a row */
	char			 why[160];	/* why it was refused */
	/* The sdwan's: arcana-probe, read by the thread for this user, as
	 * this user. */
	struct held		*probes;
	uint64_t		 read_at;	/* µs, probes read last */
};

struct watch {
	LIST_ENTRY(watch)	 link;
	char			 sid[9];
	char			*uri;
	char			*peer;
	atomic_bool		 stop;
	/* The thread's. */
	cbl_conn		*conn;
	cbl_tls			*tls;
	uint64_t		 retry;		/* µs, connect again then */
	unsigned		 backoff;	/* s */
	/* wlock's. */
	bool			 up;
	time_t			 since;		/* up since, or down since */
	unsigned		 reconnects;
	char			 why[200];	/* why it is down */
	uint64_t		 changed;	/* µs, the host changed last */
	uint64_t		 mine;		/* µs, the console changed it */
	LIST_HEAD(, wsub)	 subs;
	uint64_t		 wanted;
};

static LIST_HEAD(, watch)	watches = LIST_HEAD_INITIALIZER(watches);
static pthread_mutex_t		wlock = PTHREAD_MUTEX_INITIALIZER;

/* The nodes the records are read by, found once. */
static const struct cbl_ynode	*n_pu, *n_pu_dc, *n_pcu, *n_value, *n_susp,
				*n_est_in;
static pthread_once_t		 nodes_once = PTHREAD_ONCE_INIT;

static uint64_t
mono_us(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000);
}

static void
nodes_find(void)
{
	const struct cbl_ynode	*est;

	n_pu = yq_top("ietf-yang-push", "push-update");
	n_pu_dc = yq_child(n_pu, "datastore-contents");
	n_pcu = yq_top("ietf-yang-push", "push-change-update");
	n_value = yq_child(yq_child(yq_child(yq_child(n_pcu,
	    "datastore-changes"), "yang-patch"), "edit"), "value");
	n_susp = yq_top("ietf-subscribed-notifications",
	    "subscription-suspended");
	est = yq_top("ietf-subscribed-notifications", "establish-subscription");
	for (uint32_t i = 0; est != NULL && i < est->nchild; i++)
		if (est->child[i]->kind == CBL_YN_INPUT)
			n_est_in = est->child[i];
}

static const struct cbl_ymodule *
module_named(const char *name)
{

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++)
		if (strcmp(ymodel_schema.mod[i]->name, name) == 0)
			return (ymodel_schema.mod[i]);
	return (NULL);
}

/*
 * What is held: a tree that is never changed again, its module's struct
 * made of it, and a reference for each that reads it.
 */
static struct held *
held_new(cbl_dtree *t, const struct cbl_ymodule *m)
{
	struct held	*h;

	if ((h = calloc(1, sizeof(*h))) == NULL) {
		cbl_dtree_free(t);
		return (NULL);
	}
	atomic_init(&h->refs, 1);
	h->tree = t;
	h->at = mono_us();
	h->wall = time(NULL);
	if (t != NULL && m != NULL && ((h->a = cbl_yarena_new()) == NULL ||
	    (h->data = cbl_yarena_alloc(h->a, m->size)) == NULL ||
	    cbl_dtree_to_module(t, m, h->data, h->a) != 0)) {
		held_rele(h);
		return (NULL);
	}
	return (h);
}

void
held_rele(struct held *h)
{

	if (h == NULL || atomic_fetch_sub(&h->refs, 1) != 1)
		return;
	cbl_dtree_free(h->tree);
	if (h->a != NULL)
		cbl_yarena_free(h->a);
	free(h);
}

/*
 * CBOR as cblink writes it: an item's head (its major type and count or
 * value), and an item's length; 0: not one.
 */
static bool
cbor_head(const uint8_t **pp, const uint8_t *end, int *major, uint64_t *v)
{
	const uint8_t	*p = *pp;
	unsigned	 ai, k;

	if (p >= end)
		return (false);
	*major = *p >> 5;
	ai = *p++ & 0x1f;
	if (ai < 24)
		*v = ai;
	else if (ai <= 27) {
		k = 1u << (ai - 24);
		if ((size_t)(end - p) < k)
			return (false);
		for (*v = 0; k > 0; k--)
			*v = *v << 8 | *p++;
	} else if (ai == 31 && *major >= 2 && *major <= 5)
		*v = UINT64_MAX;	/* indefinite: to its break */
	else
		return (false);
	*pp = p;
	return (true);
}

static size_t
cbor_len(const uint8_t *p, const uint8_t *end, int depth)
{
	const uint8_t	*q = p;
	uint64_t	 v, n;
	size_t		 l;
	int		 major;

	if (depth > 64 || !cbor_head(&q, end, &major, &v))
		return (0);
	switch (major) {
	case 2:
	case 3:
		if (v == UINT64_MAX) {
			while (q < end && *q != 0xff) {
				if ((l = cbor_len(q, end, depth + 1)) == 0)
					return (0);
				q += l;
			}
			return (q < end ? (size_t)(q + 1 - p) : 0);
		}
		if ((uint64_t)(end - q) < v)
			return (0);
		return ((size_t)(q + v - p));
	case 4:
	case 5:
		n = v == UINT64_MAX ? UINT64_MAX : major == 5 ? v * 2 : v;
		for (uint64_t i = 0; i < n; i++) {
			if (n == UINT64_MAX && q < end && *q == 0xff)
				return ((size_t)(q + 1 - p));
			if ((l = cbor_len(q, end, depth + 1)) == 0)
				return (0);
			q += l;
		}
		return ((size_t)(q - p));
	case 6:
		return ((l = cbor_len(q, end, depth + 1)) == 0 ? 0 :
		    (size_t)(q + l - p));
	default:
		return ((size_t)(q - p));
	}
}

/* Member sn's value at p, len bytes, made under parent: a list's or a
 * leaf-list's entries, each, when it is an array of them. */
static int
member_decode(cbl_dnode *parent, const struct cbl_ynode *sn, const uint8_t *p,
    size_t len)
{
	const uint8_t	*q = p, *end = p + len;
	uint64_t	 n;
	size_t		 l;
	int		 major, error;
	char		 why[160];

	if ((sn->kind == CBL_YN_LIST || sn->kind == CBL_YN_LEAFLIST) &&
	    cbor_head(&q, end, &major, &n) && major == 4 && n != UINT64_MAX) {
		for (uint64_t i = 0; i < n; i++) {
			if ((l = cbor_len(q, end, 0)) == 0)
				return (EINVAL);
			if ((error = cbl_dnode_decode(parent, sn, q, l, 0, why,
			    sizeof(why), NULL)) != 0)
				return (error);
			q += l;
		}
		return (0);
	}
	return (cbl_dnode_decode(parent, sn, p, len, 0, why, sizeof(why),
	    NULL));
}

/* Anydata's {delta: value} (RFC 9254), its members made under parent,
 * each keyed from base's SID. */
static int
anydata_decode(cbl_dnode *parent, const struct cbl_ynode *base,
    const struct cbl_bytes *b)
{
	const struct cbl_ynode	*sn;
	const uint8_t		*p, *end;
	uint64_t		 n, d;
	int64_t			 delta;
	size_t			 l;
	int			 major, error;

	if (b->p == NULL)
		return (0);
	p = b->p;
	end = p + b->len;
	if (!cbor_head(&p, end, &major, &n) || major != 5 || n == UINT64_MAX)
		return (EINVAL);
	for (uint64_t i = 0; i < n; i++) {
		if (!cbor_head(&p, end, &major, &d) || major > 1 ||
		    d > INT64_MAX)
			return (EINVAL);
		delta = major == 0 ? (int64_t)d : -1 - (int64_t)d;
		if ((sn = cbl_yschema_node(&ymodel_schema, (uint64_t)
		    ((int64_t)base->sid + delta))) == NULL ||
		    (l = cbor_len(p, end, 0)) == 0)
			return (EINVAL);
		if ((error = member_decode(parent, sn, p, l)) != 0)
			return (error);
		p += l;
	}
	return (0);
}

/* The node of tree t whose api-path is path (len bytes); NULL: none. */
static cbl_dnode *
node_at(cbl_dnode *n, const char *path, size_t len)
{
	struct cbl_ybuf	 b;
	cbl_dnode	*c, *found;

	for (c = cbl_dnode_first(n); c != NULL; c = cbl_dnode_next(c)) {
		memset(&b, 0, sizeof(b));
		if (cbl_dnode_apipath(c, &b) != 0) {
			cbl_ybuf_free(&b);
			continue;
		}
		found = NULL;
		if (b.len == len && memcmp(b.p, path, len) == 0)
			found = c;
		else if (b.len < len && memcmp(b.p, path, b.len) == 0 &&
		    path[b.len] == '/')
			found = node_at(c, path, len);
		cbl_ybuf_free(&b);
		if (found != NULL)
			return (found);
	}
	return (NULL);
}

#define	EOP(x)	IETF_YANG_PUSH_PUSH_CHANGE_UPDATE_DATASTORE_CHANGES_YANG_PATCH_EDIT_OPERATION_##x

/* A YANG Patch's edits (RFC 8072) applied to tree t. */
static int
patch_apply(cbl_dtree *t,
    const struct ietf_yang_push_push_change_update_datastore_changes_yang_patch
    *yp)
{
	const struct ietf_yang_push_push_change_update_datastore_changes_yang_patch_edit
			*e;
	cbl_dnode	*root, *n, *parent;
	const char	*slash;
	int		 error;

	root = cbl_dtree_root(t);
	for (size_t i = 0; yp != NULL && i < yp->edit.n; i++) {
		e = &yp->edit.v[i];
		if (e->target == NULL || e->target[0] != '/' || !e->has_operation)
			return (EINVAL);
		n = node_at(root, e->target, strlen(e->target));
		switch (e->operation) {
		case EOP(DELETE):
		case EOP(REMOVE):
			if (n != NULL && (error = cbl_dnode_remove(n)) != 0)
				return (error);
			break;
		case EOP(MOVE):
			break;
		default:
			/* Made anew where it was, or under its parent. */
			if (n != NULL && (error = cbl_dnode_remove(n)) != 0)
				return (error);
			slash = strrchr(e->target, '/');
			parent = slash == e->target ? root : node_at(root,
			    e->target, (size_t)(slash - e->target));
			if (parent == NULL)
				return (ENOENT);
			if ((error = anydata_decode(parent, n_value, &e->value)) !=
			    0)
				return (error);
			break;
		}
	}
	return (0);
}

#undef EOP

/* A topic's last push replaced: wlock held. */
static void
held_set(struct wsub *ws, struct held *h)
{

	held_rele(ws->held);
	ws->held = h;
	if (h != NULL)
		ws->pushes++;
}

/*
 * What is pushed periodically let go until its next push, the host
 * changed meanwhile: a read is not answered with what was before.
 * wlock held.
 */
static void
stale(struct watch *w)
{
	struct wsub	*ws;

	w->changed = mono_us();
	LIST_FOREACH(ws, &w->subs, link)
		if (ws->topic == WATCH_STATS || ws->topic == WATCH_JAILS ||
		    ws->topic == WATCH_SDWAN)
			held_set(ws, NULL);
}

/* All a topic holds let go: wlock held. */
static void
held_drop(struct wsub *ws)
{

	held_set(ws, NULL);
	held_rele(ws->probes);
	ws->probes = NULL;
}

/* A record of a datastore's subscription: what is held made anew. */
static void
pushed(struct wsub *ws, const struct cbl_ynotif *nt, cbl_yarena *a)
{
	const struct cbl_ymodule	*m;
	struct ietf_yang_push_push_update	 pu;
	struct ietf_yang_push_push_change_update pcu;
	const cbl_dnode			*root;
	cbl_dtree			*t;
	struct held			*h;
	char				 why[160];
	bool				 bad;
	int				 error;

	m = module_named(topics[ws->topic].mod);
	t = NULL;
	bad = false;
	if (nt->sid == n_pu->sid) {
		memset(&pu, 0, sizeof(pu));
		error = ietf_yang_push_push_update_decode(nt->content, nt->len,
		    &pu, a, 0, why, sizeof(why));
		if (error == 0 && pu.incomplete_update) {
			/* A read of the host's failed: nothing held until
			 * one does not. */
			pthread_mutex_lock(&wlock);
			held_set(ws, NULL);
			pthread_mutex_unlock(&wlock);
			return;
		}
		if (error != 0 || (t = cbl_dtree_new(&ymodel_schema)) == NULL ||
		    anydata_decode(cbl_dtree_root(t), n_pu_dc,
		    &pu.datastore_contents) != 0)
			bad = true;
	} else if (nt->sid == n_pcu->sid) {
		memset(&pcu, 0, sizeof(pcu));
		/* Changes to what is held: of a copy, the held one never
		 * changes under a read. */
		pthread_mutex_lock(&wlock);
		root = ws->held != NULL ? cbl_dtree_root(ws->held->tree) : NULL;
		t = root != NULL ? cbl_dtree_select(ws->held->tree, &root, 1) :
		    NULL;
		pthread_mutex_unlock(&wlock);
		if (t == NULL || ietf_yang_push_push_change_update_decode(
		    nt->content, nt->len, &pcu, a, 0, why, sizeof(why)) != 0 ||
		    pcu.datastore_changes == NULL ||
		    patch_apply(t, pcu.datastore_changes->yang_patch) != 0)
			bad = true;
	} else if (nt->sid == n_susp->sid) {
		/* Records left out until it is resumed with the whole. */
		pthread_mutex_lock(&wlock);
		held_set(ws, NULL);
		pthread_mutex_unlock(&wlock);
		return;
	} else
		return;
	h = bad ? NULL : held_new(t, m);
	if (bad)
		cbl_dtree_free(t);
	pthread_mutex_lock(&wlock);
	/* A job changed, which may have changed the rest. */
	if (ws->topic == WATCH_JOBS && nt->sid == n_pcu->sid)
		stale(ws->w);
	/*
	 * A periodic push within a period of a change may have been read
	 * before it (an SD-WAN read takes a while): not held, the next
	 * read after it is.
	 */
	if (h != NULL && !topics[ws->topic].onchange && mono_us() -
	    ws->w->changed < (uint64_t)topics[ws->topic].cs * 10000) {
		pthread_mutex_unlock(&wlock);
		held_rele(h);
		return;
	}
	held_set(ws, h);
	ws->bad = h != NULL ? 0 : ws->bad + 1;
	/* Three in a row not read: asked of the host as before, until the
	 * connection is made again. */
	if (ws->bad >= 3) {
		ws->state = WATCH_S_REFUSED;
		snprintf(ws->why, sizeof(ws->why), "its pushes could not be "
		    "read");
	}
	pthread_mutex_unlock(&wlock);
	/* Not followed: subscribed again, the first push the whole. */
	if (h == NULL && ws->s != NULL) {
		thread_log(LOG_NOTICE, "%s: %s: a push not followed, %s",
		    ws->w->sid, topics[ws->topic].name, ws->bad >= 3 ?
		    "the host asked again" : "subscribed again");
		(void)cbl_stream_close(ws->s, 0, NULL);
	}
}

static void
sub_open(cbl_stream *s, cbl_msg *accept, int error, void *arg)
{
	struct wsub	*ws = arg;

	(void)s;
	pthread_mutex_lock(&wlock);
	if (error != 0) {
		ws->state = WATCH_S_REFUSED;
		snprintf(ws->why, sizeof(ws->why), "%s", accept != NULL &&
		    cbl_msg_err_str(accept) != NULL ? cbl_msg_err_str(accept) :
		    strerror(error));
	} else
		ws->state = WATCH_S_OPEN;
	pthread_mutex_unlock(&wlock);
}

static void
sub_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct wsub		*ws = arg;
	struct cbl_ynotif	 nt;
	ucl_object_t		*o;
	unsigned char		*json;
	cbl_yarena		*a;

	(void)s;
	if (ws->topic == WATCH_EVENTS) {
		if ((o = ygula_event_of(data)) == NULL)
			return;
		json = ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
		ucl_object_unref(o);
		if (json != NULL)
			follow_told(ws->w->sid, ws->user, (const char *)json);
		free(json);
		return;
	}
	if ((a = cbl_yarena_new()) == NULL)
		return;
	if (cbl_msg_ynotif(data, &nt, a) == 0)
		pushed(ws, &nt, a);
	cbl_yarena_free(a);
}

static void
sub_close(cbl_stream *s, int code, const char *text, void *arg)
{
	struct wsub	*ws = arg;

	(void)s;
	(void)code;
	pthread_mutex_lock(&wlock);
	ws->s = NULL;
	if (ws->state != WATCH_S_REFUSED) {
		ws->state = WATCH_S_NONE;
		if (text != NULL && text[0] != '\0')
			snprintf(ws->why, sizeof(ws->why), "%s", text);
	}
	held_set(ws, NULL);
	pthread_mutex_unlock(&wlock);
}

static const struct cbl_stream_cbs sub_cbs = {
	.on_open = sub_open,
	.on_data = sub_data,
	.on_close = sub_close,
};

#define	SN(x)	IETF_SUBSCRIBED_NOTIFICATIONS_ESTABLISH_SUBSCRIPTION_INPUT_##x

/* Topic ws asked of the host: its SUBSCRIBE stream opened. */
static void
sub_start(struct watch *w, struct wsub *ws)
{
	const struct wtopic	*tp = &topics[ws->topic];
	struct ietf_subscribed_notifications_establish_subscription_input in;
	struct ietf_subscribed_notifications_establish_subscription_input_yp_periodic
				 per;
	struct ietf_subscribed_notifications_establish_subscription_input_yp_on_change
				 oc;
	const struct cbl_ynode	*top;
	char			 xpath[160];
	cbl_msg			*m;

	memset(&in, 0, sizeof(in));
	memset(&per, 0, sizeof(per));
	memset(&oc, 0, sizeof(oc));
	if (tp->mod == NULL) {
		in.target = SN(TARGET_STREAM);
		in.stream = "NETCONF";
	} else {
		in.target = SN(TARGET_DATASTORE);
		for (uint32_t i = 0; i < ymodel_schema.nident; i++)
			if (strcmp(ymodel_schema.ident[i].name, "operational") ==
			    0 && strcmp(ymodel_schema.ident[i].module->name,
			    "ietf-datastores") == 0) {
				in.has_yp_datastore = true;
				in.yp_datastore = ymodel_schema.ident[i].sid;
			}
		if ((top = yq_top(tp->mod, tp->top)) == NULL) {
			ws->state = WATCH_S_REFUSED;
			snprintf(ws->why, sizeof(ws->why), "%s is not in the "
			    "tables", tp->mod);
			return;
		}
		snprintf(xpath, sizeof(xpath), "%s", tp->xpath != NULL ?
		    tp->xpath : "");
		if (tp->xpath == NULL)
			snprintf(xpath, sizeof(xpath), "/%s:%s", tp->mod,
			    tp->top);
		in.yp_selection_filter =
		    SN(YP_SELECTION_FILTER_WITHIN_SUBSCRIPTION);
		in.yp_filter_spec = SN(YP_FILTER_SPEC_DATASTORE_XPATH_FILTER);
		in.yp_datastore_xpath_filter = xpath;
		if (tp->onchange) {
			oc.has_dampening_period = true;
			oc.dampening_period = tp->cs;
			in.yp_update_trigger = SN(YP_UPDATE_TRIGGER_ON_CHANGE);
			in.yp_on_change = &oc;
		} else {
			per.has_period = true;
			per.period = tp->cs;
			in.yp_update_trigger = SN(YP_UPDATE_TRIGGER_PERIODIC);
			in.yp_periodic = &per;
		}
	}
	m = NULL;
	if (n_est_in == NULL || cbl_msg_new(cbl_conn_ctx(w->conn),
	    CBL_YANG_FAMILY, CBL_YCMD_SUBSCRIBE, 0, &m) != 0 ||
	    cbl_msg_put_ynode(m, n_est_in, &in) != 0 ||
	    (ws->user[0] != '\0' && cbl_msg_set_user(m, ws->user) != 0) ||
	    cbl_msg_set_window(m, WATCH_WINDOW) != 0 ||
	    cbl_stream_open(w->conn, m, CBL_SF_PUSH, &sub_cbs, ws, &ws->s) !=
	    0) {
		cbl_msg_free(m);
		ws->s = NULL;
		ws->state = WATCH_S_REFUSED;
		snprintf(ws->why, sizeof(ws->why), "its subscription could not "
		    "be asked");
		return;
	}
	hosts_count(false);
	ws->state = WATCH_S_OPENING;
}

#undef SN

/* The connection, made; false: not now. */
static bool
watch_up(struct watch *w)
{
	ucl_object_t		*host = NULL;
	const char		*msg;
	struct wsub		*ws;
	char			 why[160];

	/* Its hello: arcana-host's host read, as the console. */
	if ((msg = hosts_connect(w->uri, w->peer, &w->conn, &w->tls)) ==
	    NULL && yh_hello(w->conn, &host, why, sizeof(why)) != 0) {
		hosts_release(w->uri, w->peer, w->conn, w->tls, false);
		msg = "no hello";
	}
	ucl_object_unref(host);
	pthread_mutex_lock(&wlock);
	if (msg != NULL) {
		w->conn = NULL;
		w->up = false;
		snprintf(w->why, sizeof(w->why), "%s", msg);
		/* Those that wait for it are told it is not there. */
		LIST_FOREACH(ws, &w->subs, link)
			if (ws->state == WATCH_S_NONE)
				ws->state = WATCH_S_LOST;
		pthread_mutex_unlock(&wlock);
		return (false);
	}
	/* Its own: a topic's is asked as its user (watch_reads()). */
	hosts_count(false);
	w->up = true;
	w->since = time(NULL);
	w->why[0] = '\0';
	w->backoff = 0;
	/* Asked anew, those an agent before refused too. */
	LIST_FOREACH(ws, &w->subs, link) {
		ws->state = WATCH_S_NONE;
		ws->bad = 0;
	}
	pthread_mutex_unlock(&wlock);
	return (true);
}

/* The connection gone, or let go: what is held goes with it. */
static void
watch_down(struct watch *w, const char *why)
{
	struct wsub	*ws;
	cbl_conn	*conn;

	if ((conn = w->conn) == NULL)
		return;
	w->conn = NULL;
	/* The streams' closes come as it goes. */
	hosts_release(w->uri, w->peer, conn, w->tls, false);
	pthread_mutex_lock(&wlock);
	w->up = false;
	w->since = time(NULL);
	w->reconnects++;
	snprintf(w->why, sizeof(w->why), "%s", why != NULL ? why : "let go");
	LIST_FOREACH(ws, &w->subs, link) {
		ws->s = NULL;
		held_drop(ws);
		if (ws->state != WATCH_S_REFUSED || why != NULL)
			ws->state = why != NULL ? WATCH_S_LOST : WATCH_S_NONE;
	}
	pthread_mutex_unlock(&wlock);
	if (why != NULL)
		follow_gone(w->sid, why);
	w->backoff = w->backoff == 0 ? 1 : MIN(w->backoff * 2,
	    WATCH_BACKOFF_S);
	w->retry = mono_us() + (uint64_t)w->backoff * 1000000;
}

/*
 * The topics as asked: those asked for subscribed, those nobody asked
 * for a while let go.  False when nothing is asked of the host at all.
 */
static bool
watch_topics(struct watch *w, uint64_t now)
{
	struct wsub	*ws, *next;
	cbl_stream	*close[WATCH_NTOPIC * 8];
	size_t		 nclose = 0;
	bool		 any;

	pthread_mutex_lock(&wlock);
	any = now - w->wanted < WATCH_GONE_US;
	LIST_FOREACH_SAFE(ws, &w->subs, link, next) {
		if (now - ws->wanted >= WATCH_IDLE_US) {
			if (ws->s != NULL) {
				if (nclose < nitems(close))
					close[nclose++] = ws->s;
				continue;	/* freed once closed */
			}
			LIST_REMOVE(ws, link);
			held_drop(ws);
			free(ws);
			continue;
		}
		if (w->conn != NULL && ws->state == WATCH_S_NONE &&
		    ws->s == NULL)
			sub_start(w, ws);
	}
	pthread_mutex_unlock(&wlock);
	for (size_t i = 0; i < nclose; i++)
		(void)cbl_stream_close(close[i], 0, NULL);
	return (any);
}

/* A date-and-time as the agent writes them, UTC; 0: not one. */
static time_t
ytime_of(const char *s)
{
	struct tm	 tm;

	memset(&tm, 0, sizeof(tm));
	if (s == NULL || strptime(s, "%Y-%m-%dT%H:%M:%S", &tm) == NULL)
		return (0);
	return (timegm(&tm));
}

/*
 * The targets as rd has them now, each with the samples old had of it
 * not before cutoff and rd's after them, made in a; the newest sample's
 * time in *newest.  A target is the same by its edge (jail) and id.
 */
static struct arcana_probe_probes_read_output *
probes_merge(cbl_yarena *a, const struct arcana_probe_probes_read_output *old,
    const struct arcana_probe_probes_read_output *rd, time_t cutoff,
    time_t *newest)
{
	struct arcana_probe_probes_read_output	*m;
	struct arcana_probe_target_state	*v;
	const struct arcana_probe_target_state	*o, *t;
	struct arcana_probe_sample		*s;
	size_t					 n, k;
	time_t					 at;
	char					*p;

	if ((m = cbl_yarena_alloc(a, sizeof(*m))) == NULL || (v =
	    cbl_yarena_alloc(a, (rd->target.n + 1) * sizeof(*v))) == NULL)
		return (NULL);
	*m = *rd;
	for (size_t i = 0; i < rd->target.n; i++) {
		t = &rd->target.v[i];
		v[i] = *t;
		o = NULL;
		for (k = 0; old != NULL && k < old->target.n; k++)
			if (old->target.v[k].id != NULL && t->id != NULL &&
			    strcmp(old->target.v[k].id, t->id) == 0 &&
			    (old->target.v[k].jail == NULL ? t->jail == NULL :
			    t->jail != NULL && strcmp(old->target.v[k].jail,
			    t->jail) == 0))
				o = &old->target.v[k];
		n = t->sample.n + (o != NULL ? o->sample.n : 0);
		if ((s = cbl_yarena_alloc(a, (n + 1) * sizeof(*s))) == NULL)
			return (NULL);
		n = 0;
		/* The old ones' times copied: their arena goes with them. */
		for (k = 0; o != NULL && k < o->sample.n; k++) {
			if (ytime_of(o->sample.v[k].time) < cutoff)
				continue;
			s[n] = o->sample.v[k];
			if (s[n].time != NULL) {
				if ((p = cbl_yarena_alloc(a, strlen(s[n].time) +
				    1)) == NULL)
					return (NULL);
				memcpy(p, s[n].time, strlen(s[n].time) + 1);
				s[n].time = p;
			}
			n++;
		}
		for (k = 0; k < t->sample.n; k++)
			s[n++] = t->sample.v[k];
		for (k = 0; k < n; k++)
			if ((at = ytime_of(s[k].time)) > *newest)
				*newest = at;
		v[i].sample.n = n;
		v[i].sample.v = s;
	}
	m->target.v = v;
	return (m);
}

/*
 * arcana-probe's edges and what its probes saw, for a sdwan topic,
 * read at its period: the samples after those held (its samples are a
 * list kept longer than a push would carry whole), held for
 * PROBES_KEEP_S.  As the topic's user, by the caller.
 */
#define	PROBES_KEEP_S	600
static struct held *
probes_read(struct watch *w, const struct held *old)
{
	struct arcana_probe_probes_read_input in;
	struct arcana_probe_probes_read_output rd;
	struct arcana_probe	*pr;
	const struct cbl_ynode	*np, *act;
	struct held		*h;
	struct tm		 tm;
	time_t			 t, after;
	char			 err[256], when[32];

	t = time(NULL);
	after = old != NULL ? old->newest : t - PROBES_KEEP_S;
	if ((np = yq_top("arcana-probe", "probes")) == NULL || (act =
	    yq_child(np, "read")) == NULL || (h = held_new(NULL, NULL)) ==
	    NULL)
		return (NULL);
	memset(&in, 0, sizeof(in));
	memset(&rd, 0, sizeof(rd));
	if (gmtime_r(&after, &tm) != NULL && strftime(when, sizeof(when),
	    "%Y-%m-%dT%H:%M:%SZ", &tm) > 0)
		in.after = when;
	h->newest = after;
	h->from = old != NULL && old->from > t - PROBES_KEEP_S ? old->from :
	    t - PROBES_KEEP_S;
	if ((h->a = cbl_yarena_new()) == NULL || (pr = cbl_yarena_alloc(h->a,
	    sizeof(*pr))) == NULL) {
		held_rele(h);
		return (NULL);
	}
	h->data = pr;
	hosts_count(false);
	if (yq_get(w->conn, np, CBL_YDS_RUNNING, pr, h->a, err,
	    sizeof(err)) != 0 || yq_call(w->conn, np, NULL, act, &in, &rd,
	    h->a, err, sizeof(err)) != 0 || (h->more = probes_merge(h->a,
	    old != NULL ? old->more : NULL, &rd, h->from, &h->newest)) ==
	    NULL) {
		held_rele(h);
		return (NULL);
	}
	return (h);
}

/*
 * What the sdwan topics need beside their pushes, arcana-probe at their
 * period, each read for its user and as its user, whose access rules
 * the host holds the read to: a topic's own is never another user's.
 */
#define	READS_MAX	32
static void
watch_reads(struct watch *w, uint64_t now)
{
	struct wsub	*v[READS_MAX], *ws;
	struct held	*h, *old;
	size_t		 n = 0;

	pthread_mutex_lock(&wlock);
	LIST_FOREACH(ws, &w->subs, link) {
		if (ws->state != WATCH_S_OPEN || now - ws->wanted >=
		    WATCH_IDLE_US) {
			held_rele(ws->probes);
			ws->probes = NULL;
			continue;
		}
		if (n < nitems(v) && ws->topic == WATCH_SDWAN && now -
		    ws->read_at >= (uint64_t)topics[WATCH_SDWAN].cs * 10000)
			v[n++] = ws;
	}
	pthread_mutex_unlock(&wlock);
	/* Each still there: only this thread takes one away. */
	for (size_t i = 0; i < n && w->conn != NULL; i++) {
		ws = v[i];
		hosts_act_as(ws->user[0] != '\0' ? ws->user : NULL);
		ws->read_at = now;
		h = probes_read(w, ws->probes);
		hosts_act_as(NULL);
		pthread_mutex_lock(&wlock);
		old = ws->probes;
		ws->probes = h;
		pthread_mutex_unlock(&wlock);
		held_rele(old);
	}
}

static void
watch_free(struct watch *w)
{
	struct wsub	*ws;

	while ((ws = LIST_FIRST(&w->subs)) != NULL) {
		LIST_REMOVE(ws, link);
		held_drop(ws);
		free(ws);
	}
	free(w->uri);
	free(w->peer);
	free(w);
}

static void *
watch_run(void *arg)
{
	struct watch	*w = arg;
	struct pollfd	 pfd;
	uint64_t	 now;
	int		 error, ev, ms;

	hosts_act_as(NULL);
	while (!atomic_load(&w->stop)) {
		now = mono_us();
		if (!watch_topics(w, now))
			break;
		if (w->conn == NULL) {
			if (now >= w->retry && !watch_up(w)) {
				w->backoff = w->backoff == 0 ? 1 :
				    MIN(w->backoff * 2, WATCH_BACKOFF_S);
				w->retry = now + (uint64_t)w->backoff * 1000000;
			}
			if (w->conn == NULL) {
				(void)poll(NULL, 0, WATCH_WAKE_MS);
				continue;
			}
			continue;
		}
		watch_reads(w, now);
		if (w->conn == NULL || !cbl_conn_is_open(w->conn)) {
			watch_down(w, "the host closed the connection");
			continue;
		}
		ev = 0;
		ms = -1;
		(void)cbl_conn_interest(w->conn, &ev, &ms);
		pfd.fd = cbl_conn_fd(w->conn);
		pfd.events = ((ev & CBL_EV_READ) != 0 ? POLLIN : 0) |
		    ((ev & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
		pfd.revents = 0;
		if (poll(&pfd, 1, ms < 0 || ms > WATCH_WAKE_MS ?
		    WATCH_WAKE_MS : ms) == -1)
			continue;
		ev = ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0 ?
		    CBL_EV_READ : 0) | ((pfd.revents & POLLOUT) != 0 ?
		    CBL_EV_WRITE : 0);
		if ((error = cbl_conn_process(w->conn, ev)) != 0) {
			char	why[120];

			snprintf(why, sizeof(why), "the host stopped "
			    "answering: %s", strerror(error));
			watch_down(w, why);
		}
	}
	watch_down(w, NULL);
	pthread_mutex_lock(&wlock);
	LIST_REMOVE(w, link);
	pthread_mutex_unlock(&wlock);
	watch_free(w);
	return (NULL);
}

/* The watch of a host, made and started where there is none; wlock
 * held.  NULL: none can be. */
static struct watch *
watch_of(const char *sid, const char *uri, const char *peer)
{
	struct watch	*w;
	pthread_attr_t	 attr;
	pthread_t	 tid;
	int		 n = 0;

	LIST_FOREACH(w, &watches, link) {
		if (!atomic_load(&w->stop) && strcmp(w->uri, uri) == 0 &&
		    (w->peer == NULL ? peer == NULL : peer != NULL &&
		    strcmp(w->peer, peer) == 0))
			return (w);
		n++;
	}
	if (n >= WATCH_MAX || (w = calloc(1, sizeof(*w))) == NULL)
		return (NULL);
	snprintf(w->sid, sizeof(w->sid), "%s", sid);
	w->uri = strdup(uri);
	w->peer = peer != NULL ? strdup(peer) : NULL;
	atomic_init(&w->stop, false);
	LIST_INIT(&w->subs);
	w->since = time(NULL);
	w->wanted = mono_us();
	snprintf(w->why, sizeof(w->why), "connecting");
	pthread_once(&nodes_once, nodes_find);
	(void)pthread_attr_init(&attr);
	(void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (w->uri == NULL || (peer != NULL && w->peer == NULL) ||
	    n_pu == NULL || n_pcu == NULL || n_value == NULL ||
	    n_susp == NULL || pthread_create(&tid, &attr, watch_run, w) != 0) {
		(void)pthread_attr_destroy(&attr);
		free(w->uri);
		free(w->peer);
		free(w);
		return (NULL);
	}
	(void)pthread_attr_destroy(&attr);
	LIST_INSERT_HEAD(&watches, w, link);
	return (w);
}

/* Topic of user at w, made where there is none; wlock held. */
static struct wsub *
sub_of(struct watch *w, int topic, const char *user)
{
	struct wsub	*ws;

	if (user == NULL)
		user = "";
	LIST_FOREACH(ws, &w->subs, link)
		if (ws->topic == topic && strcmp(ws->user, user) == 0)
			return (ws);
	if ((ws = calloc(1, sizeof(*ws))) == NULL)
		return (NULL);
	ws->w = w;
	ws->topic = topic;
	snprintf(ws->user, sizeof(ws->user), "%s", user);
	ws->state = WATCH_S_NONE;
	LIST_INSERT_HEAD(&w->subs, ws, link);
	return (ws);
}

/*
 * What the console holds of topic at the host for user, with a
 * reference (held_rele()); NULL: nothing yet, the read goes to the
 * host.  Asking keeps the topic subscribed.
 */
struct held *
watch_held(const char *sid, const char *uri, const char *peer, int topic,
    const char *user)
{
	struct watch	*w;
	struct wsub	*ws;
	struct held	*h;
	uint64_t	 now;

	if (topic < 0 || topic >= WATCH_NTOPIC)
		return (NULL);
	now = mono_us();
	h = NULL;
	pthread_mutex_lock(&wlock);
	if ((w = watch_of(sid, uri, peer)) != NULL && (ws = sub_of(w, topic,
	    user)) != NULL) {
		w->wanted = ws->wanted = now;
		/* The jobs as pushed before the console's last change on
		 * the host are not what it has: asked of the host until
		 * the push after it. */
		if (w->up && ws->state == WATCH_S_OPEN && ws->held != NULL &&
		    (ws->topic != WATCH_JOBS || ws->held->at >= w->mine)) {
			h = ws->held;
			atomic_fetch_add(&h->refs, 1);
		}
	}
	pthread_mutex_unlock(&wlock);
	if (h != NULL)
		hosts_count(true);
	return (h);
}

/*
 * arcana-probe as the thread read it last for user's sdwan topic, as
 * user; NULL: none.  Never another user's.
 */
struct held *
watch_probes_held(const char *uri, const char *peer, const char *user)
{
	struct watch	*w;
	struct wsub	*ws;
	struct held	*h;

	h = NULL;
	if (user == NULL)
		user = "";
	pthread_mutex_lock(&wlock);
	LIST_FOREACH(w, &watches, link) {
		if (atomic_load(&w->stop) || strcmp(w->uri, uri) != 0 ||
		    (w->peer == NULL ? peer != NULL : peer == NULL ||
		    strcmp(w->peer, peer) != 0) || !w->up)
			continue;
		LIST_FOREACH(ws, &w->subs, link)
			if (ws->topic == WATCH_SDWAN && strcmp(ws->user,
			    user) == 0 && ws->state == WATCH_S_OPEN &&
			    (h = ws->probes) != NULL) {
				atomic_fetch_add(&h->refs, 1);
				break;
			}
		break;
	}
	pthread_mutex_unlock(&wlock);
	return (h);
}

/*
 * The host's events asked for user, kept subscribed while asked: its
 * subscription's state, WATCH_S_*.
 */
int
watch_events(const char *sid, const char *uri, const char *peer,
    const char *user)
{
	struct watch	*w;
	struct wsub	*ws;
	int		 state;

	state = WATCH_S_REFUSED;
	pthread_mutex_lock(&wlock);
	if ((w = watch_of(sid, uri, peer)) != NULL && (ws = sub_of(w,
	    WATCH_EVENTS, user)) != NULL) {
		w->wanted = ws->wanted = mono_us();
		state = ws->state;
		/* Lost is said once: asked again, it is tried again. */
		if (state == WATCH_S_LOST)
			ws->state = WATCH_S_NONE;
	}
	pthread_mutex_unlock(&wlock);
	return (state);
}

/* The console changed something on the host at uri. */
void
watch_changed(const char *uri)
{
	struct watch	*w;

	pthread_mutex_lock(&wlock);
	LIST_FOREACH(w, &watches, link)
		if (strcmp(w->uri, uri) == 0) {
			stale(w);
			w->mine = w->changed;
		}
	pthread_mutex_unlock(&wlock);
}

/* A host gone, or reached another way: its subscriptions go. */
void
watch_forget(const char *uri)
{
	struct watch	*w;

	pthread_mutex_lock(&wlock);
	LIST_FOREACH(w, &watches, link)
		if (strcmp(w->uri, uri) == 0)
			atomic_store(&w->stop, true);
	pthread_mutex_unlock(&wlock);
}

static const char *const state_names[] = {
	[WATCH_S_NONE] = "asking",
	[WATCH_S_OPENING] = "opening",
	[WATCH_S_OPEN] = "open",
	[WATCH_S_REFUSED] = "refused",
	[WATCH_S_LOST] = "lost",
};

/*
 * GET /api/servers/<id>/watch: the console's connection for the host's
 * subscriptions, each topic subscribed, and how often the console went
 * to the agents and answered from what it holds.
 */
int
api_watch(struct http_request *req)
{
	const struct server	*s;
	struct watch		*w;
	struct wsub		*ws;
	ucl_object_t		*top, *arr, *o;
	uint64_t		 asked, held, secs, now;
	char			 id[17];
	const char		*p, *e;

	if (!guard(req, false))
		return (WEB_OK);
	p = req->path + strlen("/api/servers/");
	e = strchr(p, '/');
	snprintf(id, sizeof(id), "%.*s", e != NULL ? (int)(e - p) : 0, p);
	if ((s = server_find(id)) == NULL)
		return (reply_error(req, 404, "not_found", "no such server"));
	if (!host_allowed(req, id, false, false))
		return (WEB_OK);
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	now = mono_us();
	pthread_mutex_lock(&wlock);
	LIST_FOREACH(w, &watches, link) {
		if (atomic_load(&w->stop) || strcmp(w->uri, s->uri) != 0)
			continue;
		ucl_object_insert_key(top, ucl_object_frombool(w->up),
		    "connected", 0, false);
		ucl_object_insert_key(top, ucl_object_fromint(w->since),
		    "since", 0, false);
		ucl_object_insert_key(top, ucl_object_fromint(w->reconnects),
		    "reconnects", 0, false);
		if (w->why[0] != '\0')
			ucl_object_insert_key(top, ucl_object_fromstring(
			    w->why), "why", 0, false);
		LIST_FOREACH(ws, &w->subs, link) {
			o = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(o, ucl_object_fromstring(
			    topics[ws->topic].name), "topic", 0, false);
			ucl_object_insert_key(o, ucl_object_fromstring(
			    ws->user), "user", 0, false);
			ucl_object_insert_key(o, ucl_object_fromstring(
			    topics[ws->topic].onchange ? "on-change" :
			    topics[ws->topic].mod != NULL ? "periodic" :
			    "stream"), "trigger", 0, false);
			ucl_object_insert_key(o, ucl_object_fromstring(
			    state_names[ws->state]), "state", 0, false);
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)
			    ws->pushes), "pushes", 0, false);
			if (ws->held != NULL)
				ucl_object_insert_key(o, ucl_object_fromint(
				    ws->held->wall), "pushed", 0, false);
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)
			    ((now - ws->wanted) / 1000000)), "asked_s", 0,
			    false);
			if (ws->why[0] != '\0')
				ucl_object_insert_key(o, ucl_object_fromstring(
				    ws->why), "why", 0, false);
			ucl_array_append(arr, o);
		}
		break;
	}
	pthread_mutex_unlock(&wlock);
	if (ucl_object_lookup(top, "connected") == NULL)
		ucl_object_insert_key(top, ucl_object_frombool(false),
		    "connected", 0, false);
	ucl_object_insert_key(top, arr, "topics", 0, false);
	hosts_tally(&asked, &held, &secs);
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)asked), "asked",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)held), "held", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)secs), "seconds",
	    0, false);
	ucl_object_insert_key(top, o, "requests", 0, false);
	return (reply_json(req, 200, top));
}
