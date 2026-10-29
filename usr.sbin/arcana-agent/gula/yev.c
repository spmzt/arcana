/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the events as YANG, arcana-events: the
 * events operation's JSON (events.c) read back into the module's
 * structs, each event's kind an identity and its data the case of
 * that kind, typed; one event's JSON (the event mcast) the same, as
 * the notification.  The three places an event stands (the list
 * kept, a read's output, the notification) have one layout.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

typedef struct arcana_events_event_entry yevent;

static char *
datetime(cbl_yarena *a, int64_t t)
{
	char		buf[32], *p;
	struct tm	tm;
	time_t		tt = (time_t)t;

	if (gmtime_r(&tt, &tm) == NULL || strftime(buf, sizeof(buf),
	    "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		return (NULL);
	if ((p = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL)
		memcpy(p, buf, strlen(buf) + 1);
	return (p);
}

/* An identity's SID, by its module and name; 0: none. */
static uint64_t
ident(const char *mod, const char *name)
{

	for (uint32_t i = 0; i < ymodel_schema.nident; i++) {
		const struct cbl_yident *id = &ymodel_schema.ident[i];

		if (strcmp(id->name, name) == 0 &&
		    strcmp(id->module->name, mod) == 0)
			return (id->sid);
	}
	return (0);
}

static bool
addr_union(cbl_yarena *a, const ucl_object_t *o, const char *key, void *u)
{
	struct arcana_events_event_entry_address_address	*s = u;
	const char						*v;

	if ((v = yj_str(a, o, key)) == NULL)
		return (false);
	s->which = strchr(v, ':') != NULL ? 1 : 0;
	s->v.m0 = v;
	return (true);
}

/* A string of o's, by key, or else by other. */
static const char *
str_or(cbl_yarena *a, const ucl_object_t *o, const char *key,
    const char *other)
{
	const char	*v;

	return ((v = yj_str(a, o, key)) != NULL ? v : yj_str(a, o, other));
}

/* A number of o's, written as one or as a string of one. */
static bool
num_or_str(const ucl_object_t *o, const char *key, int64_t *v)
{
	const ucl_object_t	*x;
	const char		*e;

	if ((x = ucl_object_lookup(o, key)) != NULL && ucl_object_type(x) ==
	    UCL_STRING) {
		*v = strtonum(ucl_object_tostring(x), 0, INT64_MAX, &e);
		return (e == NULL);
	}
	return (yj_num(o, key, v));
}

/* A number of o's, a double the agent printed, in thousandths. */
static bool
thousandths(const ucl_object_t *o, const char *key, int64_t *v)
{
	const ucl_object_t	*x;
	double			 d;

	if ((x = ucl_object_lookup(o, key)) == NULL ||
	    !ucl_object_todouble_safe(x, &d))
		return (false);
	*v = (int64_t)(d * 1000 + (d < 0 ? -0.5 : 0.5));
	return (true);
}

#define	ALLOC(a, p)	(((p) = cbl_yarena_alloc((a), sizeof(*(p)))) != NULL && \
			    memset((p), 0, sizeof(*(p))) != NULL)

/* One event's data, by its kind. */
static int
data_of(cbl_yarena *a, const char *kind, const ucl_object_t *d, yevent *y)
{
	const char	*v;

	y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_NONE;
	if (d == NULL)
		return (0);
	if (strcmp(kind, "route-add") == 0 || strcmp(kind, "route-del") == 0) {
		struct arcana_events_event_entry_route	*r;
		int64_t					 n;

		if (!ALLOC(a, r))
			return (ENOMEM);
		r->destination = yj_str(a, d, "destination");
		YJ_NUM(d, "prefixlen", r, prefix_length);
		r->gateway = yj_str(a, d, "gateway");
		/* nlroute.c's rows name it interface-name. */
		r->interface = str_or(a, d, "interface-name", "interface");
		if ((v = yj_str(a, d, "fib")) != NULL) {
			r->has_fib = true;
			r->fib = (uint16_t)strtoul(v, NULL, 10);
		} else if (yj_num(d, "fib", &n)) {
			r->has_fib = true;
			r->fib = (uint16_t)n;
		}
		r->flags = yj_str(a, d, "flags");
		YJ_NUM(d, "metric", r, metric);
		YJ_NUM(d, "weight", r, weight);
		YJ_NUM(d, "mtu", r, mtu);
		r->source = yj_str(a, d, "source");
		YJ_NUM(d, "nhop", r, nhop);
		YJ_NUM(d, "path", r, path);
		YJ_NUM(d, "paths", r, paths);
		if ((r->has_expire_time = num_or_str(d, "expire-time", &n)))
			r->expire_time = (uint32_t)n;
		y->route = r;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_ROUTE;
	} else if (strcmp(kind, "routes") == 0) {
		struct arcana_events_event_entry_routes	*r;

		if (!ALLOC(a, r))
			return (ENOMEM);
		YJ_NUM(d, "changed", r, changed);
		y->routes = r;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_ROUTES;
	} else if (strcmp(kind, "link") == 0 || strcmp(kind, "link-del") == 0) {
		struct arcana_events_event_entry_link	*l;

		if (!ALLOC(a, l))
			return (ENOMEM);
		l->interface = yj_str(a, d, "interface");
		l->up = yj_yes(d, "up", &l->has_up);
		l->carrier = yj_yes(d, "carrier", &l->has_carrier);
		YJ_NUM(d, "mtu", l, mtu);
		y->link = l;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_LINK;
	} else if (strcmp(kind, "address-add") == 0 || strcmp(kind,
	    "address-del") == 0) {
		struct arcana_events_event_entry_address	*ad;

		if (!ALLOC(a, ad))
			return (ENOMEM);
		ad->interface = yj_str(a, d, "interface");
		ad->has_address = addr_union(a, d, "address", &ad->address);
		YJ_NUM(d, "prefixlen", ad, prefix_length);
		y->address = ad;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_ADDRESS;
	} else if (strcmp(kind, "neigh") == 0 || strcmp(kind, "neigh-del") ==
	    0) {
		struct arcana_events_event_entry_neighbor	*nb;

		if (!ALLOC(a, nb))
			return (ENOMEM);
		nb->interface = str_or(a, d, "interface-name", "interface");
		nb->has_address = addr_union(a, d, "address", &nb->address);
		nb->link_address = yj_str(a, d, "lladdr");
		nb->state = yj_str(a, d, "state");
		nb->router = yj_yes(d, "router", &nb->has_router);
		nb->family = yj_str(a, d, "family");
		YJ_NUM(d, "next", nb, next);
		y->neighbor = nb;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_NEIGHBOR;
	} else if (strcmp(kind, "threshold") == 0) {
		static const char *const whats[] = { "cpu", "mem", "swap",
		    "net", "disk", "jail-cpu", "jail-mem", "storage" };
		struct arcana_events_event_entry_threshold	*t;
		size_t						 i;

		if (!ALLOC(a, t))
			return (ENOMEM);
		if ((v = yj_str(a, d, "what")) != NULL)
			for (i = 0; i < nitems(whats); i++)
				if (strcmp(v, whats[i]) == 0) {
					t->has_what = true;
					t->what = (int)i;
				}
		t->name = yj_str(a, d, "name");
		YJ_NUM(d, "value", t, value);
		YJ_NUM(d, "limit", t, limit);
		t->over = yj_yes(d, "over", &t->has_over);
		y->threshold = t;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_THRESHOLD;
	} else if (strcmp(kind, "kmsg") == 0) {
		struct arcana_events_event_entry_kmsg	*k;

		if (!ALLOC(a, k))
			return (ENOMEM);
		YJ_NUM(d, "seq", k, sequence);
		k->text = yj_str(a, d, "text");
		YJ_NUM(d, "more", k, more);
		y->kmsg = k;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_KMSG;
	} else if (strcmp(kind, "sdwan-tunnel") == 0 || strcmp(kind,
	    "monitor") == 0) {
		struct arcana_events_event_entry_tunnel	*t;

		if (!ALLOC(a, t))
			return (ENOMEM);
		t->id = yj_str(a, d, "id");
		t->has_address = addr_union(a, d, "address", &t->address);
		t->interface = yj_str(a, d, "interface");
		if ((v = yj_str(a, d, "state")) != NULL) {
			t->has_state = true;
			t->state = strcmp(v, "up") == 0 ?
			    ARCANA_EVENTS_EVENT_ENTRY_TUNNEL_STATE_UP :
			    strcmp(v, "down") == 0 ?
			    ARCANA_EVENTS_EVENT_ENTRY_TUNNEL_STATE_DOWN :
			    ARCANA_EVENTS_EVENT_ENTRY_TUNNEL_STATE_UNKNOWN;
		}
		YJ_NUM(d, "misses", t, misses);
		t->by = yj_str(a, d, "by");
		t->jail = yj_str(a, d, "jail");
		y->tunnel = t;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_TUNNEL;
	} else if (strcmp(kind, "sdwan-fault") == 0) {
		struct arcana_events_event_entry_fault	*f;

		if (!ALLOC(a, f))
			return (ENOMEM);
		f->type = yj_str(a, d, "type");
		f->severity = yj_str(a, d, "severity");
		f->object = yj_str(a, d, "object");
		f->by = yj_str(a, d, "by");
		f->description = yj_str(a, d, "description");
		if ((v = yj_str(a, d, "state")) != NULL) {
			f->has_state = true;
			f->state = strcmp(v, "cleared") == 0 ?
			    ARCANA_EVENTS_EVENT_ENTRY_FAULT_STATE_CLEARED :
			    ARCANA_EVENTS_EVENT_ENTRY_FAULT_STATE_SET;
		}
		y->fault = f;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_FAULT;
	} else if (strcmp(kind, "sdwan-security") == 0) {
		struct arcana_events_event_entry_security	*s;

		if (!ALLOC(a, s))
			return (ENOMEM);
		YJ_NUM(d, "seq", s, sequence);
		YJ_NUM(d, "rule", s, rule);
		s->action = yj_str(a, d, "action");
		s->source = yj_str(a, d, "src");
		s->destination = yj_str(a, d, "dst");
		s->interface = yj_str(a, d, "iface");
		s->comment = yj_str(a, d, "comment");
		y->security = s;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_SECURITY;
	} else if (strcmp(kind, "job") == 0) {
		struct arcana_events_event_entry_job	*j;

		if (!ALLOC(a, j))
			return (ENOMEM);
		YJ_NUM(d, "id", j, id);
		j->title = yj_str(a, d, "title");
		j->ok = yj_yes(d, "ok", &j->has_ok);
		j->error = yj_str(a, d, "error");
		y->job = j;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_JOB;
	} else if (strcmp(kind, "jail-state") == 0) {
		struct arcana_events_event_entry_jail_state	*j;

		if (!ALLOC(a, j))
			return (ENOMEM);
		j->jail = yj_str(a, d, "jail");
		if ((v = yj_str(a, d, "state")) != NULL) {
			j->has_state = true;
			j->state = strcmp(v, "running") == 0 ?
			    ARCANA_EVENTS_EVENT_ENTRY_JAIL_STATE_STATE_RUNNING :
			    ARCANA_EVENTS_EVENT_ENTRY_JAIL_STATE_STATE_STOPPED;
		}
		YJ_NUM(d, "jid", j, jid);
		y->jail_state = j;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_JAIL_STATE;
	} else if (strcmp(kind, "crash") == 0) {
		struct arcana_events_event_entry_crash	*c;

		if (!ALLOC(a, c))
			return (ENOMEM);
		YJ_NUM(d, "pid", c, pid);
		c->process = yj_str(a, d, "process");
		YJ_NUM(d, "jid", c, jid);
		c->jail = yj_str(a, d, "jail");
		YJ_NUM(d, "uid", c, uid);
		YJ_NUM(d, "signal", c, signal);
		c->core = yj_yes(d, "core", &c->has_core);
		c->reason = yj_str(a, d, "reason");
		y->crash = c;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_CRASH;
	} else if (strcmp(kind, "conf") == 0) {
		struct arcana_events_event_entry_conf	*c;

		if (!ALLOC(a, c))
			return (ENOMEM);
		c->file = yj_str(a, d, "file");
		y->conf = c;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_CONF;
	} else if (strcmp(kind, "device") == 0) {
		struct arcana_events_event_entry_device	*c;

		if (!ALLOC(a, c))
			return (ENOMEM);
		c->cdev = yj_str(a, d, "cdev");
		c->state = yj_str(a, d, "state");
		y->device = c;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_DEVICE;
	} else if (strcmp(kind, "zfs") == 0) {
		struct arcana_events_event_entry_zfs	*c;

		if (!ALLOC(a, c))
			return (ENOMEM);
		c->type = yj_str(a, d, "type");
		c->pool = yj_str(a, d, "pool");
		y->zfs = c;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_ZFS;
	} else if (strcmp(kind, "procs") == 0) {
		struct arcana_events_event_entry_procs	*c;

		if (!ALLOC(a, c))
			return (ENOMEM);
		YJ_NUM(d, "started", c, started);
		YJ_NUM(d, "exited", c, exited);
		y->procs = c;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_PROCS;
	} else if (strcmp(kind, "monitor-threshold") == 0) {
		struct arcana_events_event_entry_monitor	*c;

		if (!ALLOC(a, c))
			return (ENOMEM);
		c->id = yj_str(a, d, "id");
		c->metric = yj_str(a, d, "metric");
		c->has_value = thousandths(d, "value", &c->value);
		c->has_threshold = thousandths(d, "threshold", &c->threshold);
		c->over = yj_yes(d, "over", &c->has_over);
		c->interface = yj_str(a, d, "interface");
		y->monitor = c;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_MONITOR;
	} else if (strcmp(kind, "sdwan-ids") == 0) {
		struct arcana_events_event_entry_alert	*c;

		if (!ALLOC(a, c))
			return (ENOMEM);
		c->instance = yj_str(a, d, "name");
		c->time = yj_str(a, d, "time");
		c->src = yj_str(a, d, "src");
		YJ_NUM(d, "sport", c, sport);
		c->dst = yj_str(a, d, "dst");
		YJ_NUM(d, "dport", c, dport);
		c->proto = yj_str(a, d, "proto");
		c->interface = yj_str(a, d, "iface");
		YJ_NUM(d, "sid", c, sid);
		YJ_NUM(d, "rev", c, rev);
		c->signature = yj_str(a, d, "signature");
		c->category = yj_str(a, d, "category");
		YJ_NUM(d, "severity", c, severity);
		c->action = yj_str(a, d, "action");
		y->alert = c;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_ALERT;
	} else if (strcmp(kind, "undo-failed") == 0) {
		struct arcana_events_event_entry_undo	*c;

		if (!ALLOC(a, c))
			return (ENOMEM);
		c->node = yj_str(a, d, "node");
		YJ_NUM(d, "errno", c, errno_);
		c->message = yj_str(a, d, "message");
		c->report = yj_str(a, d, "report");
		y->undo = c;
		y->data = ARCANA_EVENTS_EVENT_ENTRY_DATA_UNDO;
	}
	return (0);
}

/* One event, {"n","t","kind","jail","data"}, into y. */
static int
event_of(cbl_yarena *a, const ucl_object_t *e, yevent *y)
{
	const char	*kind;
	int64_t		 n;

	memset(y, 0, sizeof(*y));
	if (yj_num(e, "n", &n))
		y->number = (uint64_t)n;
	if (yj_num(e, "t", &n))
		y->time = datetime(a, n);
	if ((kind = yj_str(a, e, "kind")) == NULL)
		return (EINVAL);
	y->kind = ident("arcana-events", kind);
	y->has_kind = y->kind != 0;
	y->jail = yj_str(a, e, "jail");
	return (data_of(a, kind, ucl_object_lookup(e, "data"), y));
}

int
yev_from_json(const char *json, cbl_yarena *a,
    struct arcana_events_events *out)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*top;
	yevent			*v;
	size_t			 n = 0;
	int			 error;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	YJ_NUM(top, "last", out, last);
	YJ_NUM(top, "first", out, first);
	YJ_NUM(top, "kept", out, kept);
	if ((v = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "events")) + 1) * sizeof(*v))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "events"), it, e) {
		if ((error = event_of(a, e, &v[n])) == ENOMEM) {
			ucl_object_unref(top);
			return (error);
		}
		if (error == 0)
			n++;
	}
	out->event.n = n;
	out->event.v = v;
	ucl_object_unref(top);
	return (0);
}

int
yev_one_from_json(const char *json, cbl_yarena *a,
    struct arcana_events_event *out)
{
	ucl_object_t	*top;
	yevent		 y;
	int		 error;

	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	error = event_of(a, top, &y);
	ucl_object_unref(top);
	if (error != 0)
		return (error);
	/* The notification's number is no key: it has its has_; the
	 * cases' structs have the list entry's layouts. */
	memset(out, 0, sizeof(*out));
	out->has_number = true;
	out->number = y.number;
	out->time = y.time;
	out->has_kind = y.has_kind;
	out->kind = y.kind;
	out->jail = y.jail;
	out->data = (enum arcana_events_event_data)y.data;
	out->route = (const void *)y.route;
	out->routes = (const void *)y.routes;
	out->link = (const void *)y.link;
	out->address = (const void *)y.address;
	out->neighbor = (const void *)y.neighbor;
	out->threshold = (const void *)y.threshold;
	out->kmsg = (const void *)y.kmsg;
	out->tunnel = (const void *)y.tunnel;
	out->fault = (const void *)y.fault;
	out->security = (const void *)y.security;
	out->job = (const void *)y.job;
	out->jail_state = (const void *)y.jail_state;
	out->crash = (const void *)y.crash;
	out->conf = (const void *)y.conf;
	out->device = (const void *)y.device;
	out->zfs = (const void *)y.zfs;
	out->procs = (const void *)y.procs;
	out->monitor = (const void *)y.monitor;
	out->alert = (const void *)y.alert;
	out->undo = (const void *)y.undo;
	return (0);
}
