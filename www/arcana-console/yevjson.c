/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An event of arcana-events as the events operation gave it,
 * {"n","t","kind","jail","data"}, its data's members in the order each
 * of the agent's sources writes them (nlroute.c, history.c, probe.c,
 * sdbird.c, faults.c, ...): the console's pages, its mail and arcanactl
 * read them so.  Apart from ygula.c, which asks for them, so that the
 * agent's tests take an event there and back.
 */

#include <sys/param.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "ymodel.h"
#include "yevjson.h"

typedef struct arcana_events_event_entry yevent;

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		put(o, key, ucl_object_fromstring(v));
}

#define	PUT_NUM(o, key, y, m) do {					\
	if ((y)->has_##m)						\
		put((o), (key), ucl_object_fromint((int64_t)(y)->m));	\
} while (0)

#define	PUT_YES(o, key, y, m) do {					\
	if ((y)->has_##m)						\
		put((o), (key), ucl_object_frombool((y)->m));		\
} while (0)

/* A decimal64 of 3 digits as %.6g printed it: whole, a whole number. */
static void
put_dec3(ucl_object_t *o, const char *key, bool has, int64_t v)
{

	if (!has)
		return;
	put(o, key, v % 1000 == 0 ? ucl_object_fromint(v / 1000) :
	    ucl_object_fromdouble((double)v / 1000));
}

/* An identity's name, by its SID; NULL: none. */
static const char *
ident_name(uint64_t sid)
{

	for (uint32_t i = 0; i < ymodel_schema.nident; i++)
		if (ymodel_schema.ident[i].sid == sid)
			return (ymodel_schema.ident[i].name);
	return (NULL);
}

/* A yang:date-and-time the agent wrote (UTC), as seconds; -1: none. */
static int64_t
epoch(const char *s)
{
	struct tm	tm;

	memset(&tm, 0, sizeof(tm));
	if (s == NULL || strptime(s, "%Y-%m-%dT%H:%M:%S", &tm) == NULL)
		return (-1);
	return ((int64_t)timegm(&tm));
}

static ucl_object_t *
data_of(const yevent *e)
{
	static const char *const whats[] = { "cpu", "mem", "swap", "net",
	    "disk", "jail-cpu", "jail-mem", "storage" };
	static const char *const tstates[] = { "up", "down", "unknown" };
	ucl_object_t	*d;
	char		 num[16];

	d = ucl_object_typed_new(UCL_OBJECT);
	switch (e->data) {
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_ROUTE: {
		const struct arcana_events_event_entry_route *r = e->route;

		put_str(d, "destination", r->destination);
		put_str(d, "gateway", r->gateway);
		put_str(d, "flags", r->flags);
		PUT_NUM(d, "nhop", r, nhop);
		PUT_NUM(d, "mtu", r, mtu);
		put_str(d, "interface-name", r->interface);
		PUT_NUM(d, "metric", r, metric);
		PUT_NUM(d, "weight", r, weight);
		PUT_NUM(d, "fib", r, fib);
		PUT_NUM(d, "prefixlen", r, prefix_length);
		put_str(d, "source", r->source);
		PUT_NUM(d, "path", r, path);
		PUT_NUM(d, "paths", r, paths);
		if (r->has_expire_time) {
			snprintf(num, sizeof(num), "%u", r->expire_time);
			put_str(d, "expire-time", num);
		}
		break;
	}
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_ROUTES:
		PUT_NUM(d, "changed", e->routes, changed);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_LINK:
		put_str(d, "interface", e->link->interface);
		PUT_YES(d, "up", e->link, up);
		PUT_YES(d, "carrier", e->link, carrier);
		PUT_NUM(d, "mtu", e->link, mtu);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_ADDRESS:
		put_str(d, "interface", e->address->interface);
		if (e->address->has_address)
			put_str(d, "address", e->address->address.v.m0);
		PUT_NUM(d, "prefixlen", e->address, prefix_length);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_NEIGHBOR: {
		const struct arcana_events_event_entry_neighbor *n =
		    e->neighbor;

		put_str(d, "family", n->family);
		if (n->has_address)
			put_str(d, "address", n->address.v.m0);
		put_str(d, "lladdr", n->link_address);
		put_str(d, "interface-name", n->interface);
		put_str(d, "state", n->state);
		/* Said only when it is one. */
		if (n->has_router && n->router)
			put(d, "router", ucl_object_frombool(true));
		PUT_NUM(d, "next", n, next);
		break;
	}
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_THRESHOLD: {
		const struct arcana_events_event_entry_threshold *t =
		    e->threshold;

		if (t->has_what && (size_t)t->what < nitems(whats))
			put_str(d, "what", whats[t->what]);
		put_str(d, "name", t->name);
		PUT_NUM(d, "value", t, value);
		PUT_NUM(d, "limit", t, limit);
		PUT_YES(d, "over", t, over);
		break;
	}
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_KMSG:
		PUT_NUM(d, "seq", e->kmsg, sequence);
		put_str(d, "text", e->kmsg->text);
		PUT_NUM(d, "more", e->kmsg, more);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_TUNNEL: {
		const struct arcana_events_event_entry_tunnel *t = e->tunnel;
		const char *st;

		st = t->has_state && (size_t)t->state < nitems(tstates) ?
		    tstates[t->state] : NULL;
		put_str(d, "id", t->id);
		if (t->has_address)
			put_str(d, "address", t->address.v.m0);
		/* BFD's (sdbird.c), by bfd; the probes' (probe.c). */
		if (t->by != NULL) {
			put_str(d, "interface", t->interface);
			put_str(d, "state", st);
			PUT_NUM(d, "misses", t, misses);
			put_str(d, "by", t->by);
			put_str(d, "jail", t->jail);
		} else {
			put_str(d, "state", st);
			PUT_NUM(d, "misses", t, misses);
			put_str(d, "jail", t->jail);
			put_str(d, "interface", t->interface);
		}
		break;
	}
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_FAULT:
		put_str(d, "type", e->fault->type);
		put_str(d, "severity", e->fault->severity);
		put_str(d, "object", e->fault->object);
		put_str(d, "by", e->fault->by);
		put_str(d, "description", e->fault->description);
		if (e->fault->has_state)
			put_str(d, "state", e->fault->state ==
			    ARCANA_EVENTS_EVENT_ENTRY_FAULT_STATE_CLEARED ?
			    "cleared" : "set");
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_SECURITY:
		PUT_NUM(d, "seq", e->security, sequence);
		PUT_NUM(d, "rule", e->security, rule);
		put_str(d, "action", e->security->action);
		put_str(d, "src", e->security->source);
		put_str(d, "dst", e->security->destination);
		put_str(d, "iface", e->security->interface);
		put_str(d, "comment", e->security->comment);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_JOB:
		PUT_NUM(d, "id", e->job, id);
		put_str(d, "title", e->job->title);
		PUT_YES(d, "ok", e->job, ok);
		put_str(d, "error", e->job->error);
		put_str(d, "user", e->job->user);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_JAIL_STATE:
		put_str(d, "jail", e->jail_state->jail);
		if (e->jail_state->has_state)
			put_str(d, "state", e->jail_state->state ==
			    ARCANA_EVENTS_EVENT_ENTRY_JAIL_STATE_STATE_RUNNING ?
			    "running" : "stopped");
		PUT_NUM(d, "jid", e->jail_state, jid);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_CRASH:
		PUT_NUM(d, "pid", e->crash, pid);
		put_str(d, "process", e->crash->process);
		PUT_NUM(d, "jid", e->crash, jid);
		put_str(d, "jail", e->crash->jail);
		PUT_NUM(d, "uid", e->crash, uid);
		PUT_NUM(d, "signal", e->crash, signal);
		PUT_YES(d, "core", e->crash, core);
		put_str(d, "reason", e->crash->reason);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_CONF:
		put_str(d, "file", e->conf->file);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_DEVICE:
		put_str(d, "cdev", e->device->cdev);
		put_str(d, "state", e->device->state);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_ZFS:
		put_str(d, "type", e->zfs->type);
		put_str(d, "pool", e->zfs->pool);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_PROCS:
		PUT_NUM(d, "started", e->procs, started);
		PUT_NUM(d, "exited", e->procs, exited);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_MONITOR:
		put_str(d, "id", e->monitor->id);
		put_str(d, "metric", e->monitor->metric);
		put_dec3(d, "value", e->monitor->has_value, e->monitor->value);
		put_dec3(d, "threshold", e->monitor->has_threshold,
		    e->monitor->threshold);
		PUT_YES(d, "over", e->monitor, over);
		put_str(d, "interface", e->monitor->interface);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_ALERT: {
		const struct arcana_events_event_entry_alert *l = e->alert;

		put_str(d, "name", l->instance);
		put_str(d, "time", l->time);
		put_str(d, "src", l->src);
		PUT_NUM(d, "sport", l, sport);
		put_str(d, "dst", l->dst);
		PUT_NUM(d, "dport", l, dport);
		put_str(d, "proto", l->proto);
		put_str(d, "iface", l->interface);
		PUT_NUM(d, "sid", l, sid);
		PUT_NUM(d, "rev", l, rev);
		put_str(d, "signature", l->signature);
		put_str(d, "category", l->category);
		PUT_NUM(d, "severity", l, severity);
		put_str(d, "action", l->action);
		break;
	}
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_UNDO:
		put_str(d, "node", e->undo->node);
		PUT_NUM(d, "errno", e->undo, errno_);
		put_str(d, "message", e->undo->message);
		put_str(d, "report", e->undo->report);
		break;
	default:
		break;
	}
	return (d);
}

ucl_object_t *
yev_json(const yevent *e)
{
	ucl_object_t	*o;
	const char	*kind;
	int64_t		 t;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "n", ucl_object_fromint((int64_t)e->number));
	if ((t = epoch(e->time)) >= 0)
		put(o, "t", ucl_object_fromint(t));
	if (e->has_kind && (kind = ident_name(e->kind)) != NULL)
		put_str(o, "kind", kind);
	put_str(o, "jail", e->jail);
	put(o, "data", data_of(e));
	return (o);
}

ucl_object_t *
yev_ntf_json(const struct arcana_events_event *n)
{
	yevent	e;

	/* The cases' structs have the list entry's layouts. */
	memset(&e, 0, sizeof(e));
	e.number = n->has_number ? n->number : 0;
	e.time = n->time;
	e.has_kind = n->has_kind;
	e.kind = n->kind;
	e.jail = n->jail;
	e.data = (enum arcana_events_event_entry_data)n->data;
	e.route = (const void *)n->route;
	e.routes = (const void *)n->routes;
	e.link = (const void *)n->link;
	e.address = (const void *)n->address;
	e.neighbor = (const void *)n->neighbor;
	e.threshold = (const void *)n->threshold;
	e.kmsg = (const void *)n->kmsg;
	e.tunnel = (const void *)n->tunnel;
	e.fault = (const void *)n->fault;
	e.security = (const void *)n->security;
	e.job = (const void *)n->job;
	e.jail_state = (const void *)n->jail_state;
	e.crash = (const void *)n->crash;
	e.conf = (const void *)n->conf;
	e.device = (const void *)n->device;
	e.zfs = (const void *)n->zfs;
	e.procs = (const void *)n->procs;
	e.monitor = (const void *)n->monitor;
	e.alert = (const void *)n->alert;
	e.undo = (const void *)n->undo;
	return (yev_json(&e));
}

ucl_object_t *
yev_list_json(bool has_last, uint64_t last, bool has_first, uint64_t first,
    bool has_kept, uint16_t kept, const yevent *v, size_t n)
{
	ucl_object_t	*top, *arr;

	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "last", ucl_object_fromint(has_last ? (int64_t)last : 0));
	put(top, "first", ucl_object_fromint(has_first ? (int64_t)first : 0));
	put(top, "kept", ucl_object_fromint(has_kept ? kept : 0));
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < n; i++)
		ucl_array_append(arr, yev_json(&v[i]));
	put(top, "events", arr);
	return (top);
}
