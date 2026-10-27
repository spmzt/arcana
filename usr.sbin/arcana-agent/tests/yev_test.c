/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yev: the events operation's reply, and one event, as arcana-events
 * has them (yev.c), for agent_test.sh.
 *
 *	yev list reply.json	the events kept
 *	yev one event.json	one event, the notification
 *
 * Through YANG-CBOR and back, the same bytes.
 */

#include <stddef.h>

#include "ycommon.h"

static const char *
ident(bool has, uint64_t sid)
{

	if (!has)
		return ("-");
	for (uint32_t i = 0; i < ymodel_schema.nident; i++)
		if (ymodel_schema.ident[i].sid == sid)
			return (ymodel_schema.ident[i].name);
	return ("?");
}

static const char *const whats[] = { "cpu", "mem", "swap", "net", "disk",
    "jail-cpu", "jail-mem" };

static void
event(const struct arcana_events_event_entry *e)
{

	printf("%ju %s %s%s%s: ", (uintmax_t)e->number, str(e->time), ident(
	    e->has_kind, e->kind), e->jail != NULL ? " jail=" : "", e->jail !=
	    NULL ? e->jail : "");
	switch (e->data) {
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_ROUTE:
		printf("route %s/%u via %s on %s fib=%d flags=%s source=%s",
		    e->route->has_destination ? e->route->destination.v.m0 :
		    "-", e->route->prefix_length, str(e->route->gateway), str(
		    e->route->interface), e->route->has_fib ? e->route->fib :
		    -1, str(e->route->flags), str(e->route->source));
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_ROUTES:
		printf("routes changed=%u", e->routes->changed);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_LINK:
		printf("link %s up=%s carrier=%s mtu=%u", str(
		    e->link->interface), e->link->up ? "yes" : "no",
		    e->link->carrier ? "yes" : "no", e->link->mtu);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_ADDRESS:
		printf("address %s %s/%u", str(e->address->interface),
		    e->address->has_address ? e->address->address.v.m0 : "-",
		    e->address->prefix_length);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_NEIGHBOR:
		printf("neighbor %s %s lladdr=%s state=%s router=%s", str(
		    e->neighbor->interface), e->neighbor->has_address ?
		    e->neighbor->address.v.m0 : "-", str(
		    e->neighbor->link_address), str(e->neighbor->state),
		    e->neighbor->router ? "yes" : "no");
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_THRESHOLD:
		printf("threshold %s name=%s value=%ju limit=%ju over=%s",
		    e->threshold->has_what ? whats[e->threshold->what] : "-",
		    str(e->threshold->name), (uintmax_t)e->threshold->value,
		    (uintmax_t)e->threshold->limit, e->threshold->over ? "yes"
		    : "no");
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_KMSG:
		printf("kmsg seq=%ju text=%s more=%u", (uintmax_t)
		    e->kmsg->sequence, str(e->kmsg->text), e->kmsg->more);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_TUNNEL:
		printf("tunnel %s %s %s misses=%u by=%s", str(e->tunnel->id),
		    e->tunnel->has_address ? e->tunnel->address.v.m0 : "-",
		    e->tunnel->has_state ? (e->tunnel->state == 0 ? "up" :
		    "down") : "-", e->tunnel->misses, str(e->tunnel->by));
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_FAULT:
		printf("fault %s %s %s by=%s %s: %s", str(e->fault->type), str(
		    e->fault->severity), str(e->fault->object), str(
		    e->fault->by), e->fault->has_state ? (e->fault->state == 0 ?
		    "set" : "cleared") : "-", str(e->fault->description));
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_SECURITY:
		printf("security seq=%ju rule=%u %s %s -> %s on %s (%s)",
		    (uintmax_t)e->security->sequence, e->security->rule, str(
		    e->security->action), str(e->security->source), str(
		    e->security->destination), str(e->security->interface),
		    str(e->security->comment));
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_JOB:
		printf("job %ju %s ok=%s error=%s", (uintmax_t)e->job->id, str(
		    e->job->title), e->job->ok ? "yes" : "no", str(
		    e->job->error));
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_JAIL_STATE:
		printf("jail-state %s %s jid=%u", str(e->jail_state->jail),
		    e->jail_state->has_state ? (e->jail_state->state == 0 ?
		    "running" : "stopped") : "-", e->jail_state->jid);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_CRASH:
		printf("crash pid=%u %s jid=%u jail=%s uid=%u signal=%u core=%s "
		    "reason=%s", e->crash->pid, str(e->crash->process),
		    e->crash->jid, str(e->crash->jail), e->crash->uid,
		    e->crash->signal, e->crash->core ? "yes" : "no", str(
		    e->crash->reason));
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_CONF:
		printf("conf %s", str(e->conf->file));
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_DEVICE:
		printf("device %s %s", str(e->device->cdev),
		    str(e->device->state));
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_ZFS:
		printf("zfs %s pool=%s", str(e->zfs->type), str(e->zfs->pool));
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_PROCS:
		printf("procs started=%u exited=%u", e->procs->started,
		    e->procs->exited);
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_MONITOR:
		printf("monitor %s %s value=%jd threshold=%jd over=%s on %s",
		    str(e->monitor->id), str(e->monitor->metric),
		    (intmax_t)e->monitor->value, (intmax_t)e->monitor->threshold,
		    e->monitor->over ? "yes" : "no", str(e->monitor->interface));
		break;
	case ARCANA_EVENTS_EVENT_ENTRY_DATA_ALERT:
		printf("alert %s sid=%u rev=%u %s:%u -> %s:%u %s on %s "
		    "severity=%u %s: %s", str(e->alert->instance), e->alert->sid,
		    e->alert->rev, str(e->alert->src), e->alert->sport,
		    str(e->alert->dst), e->alert->dport, str(e->alert->proto),
		    str(e->alert->interface), e->alert->severity,
		    str(e->alert->action), str(e->alert->signature));
		break;
	default:
		printf("no data");
	}
	printf("\n");
}

int
main(int argc, char **argv)
{
	cbl_yarena *a;
	int error;

	if (argc != 3)
		errx(2, "usage: yev list|one reply.json");
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if (strcmp(argv[1], "list") == 0) {
		struct arcana_events_events l, back;

		if ((error = yev_from_json(slurp(argv[2]), a, &l)) != 0)
			errc(1, error, "yev_from_json");
		printf("events last=%ju first=%ju kept=%u\n", (uintmax_t)l.last,
		    (uintmax_t)l.first, l.kept);
		for (size_t i = 0; i < l.event.n; i++)
			event(&l.event.v[i]);
		same((void *)arcana_events_events_encode, (void *)
		    arcana_events_events_decode, &l, &back, a);
	} else if (strcmp(argv[1], "one") == 0) {
		struct arcana_events_event e, back;

		if ((error = yev_one_from_json(slurp(argv[2]), a, &e)) != 0)
			errc(1, error, "yev_one_from_json");
		/* Shown as a list entry, which has no has_number. */
		{
			struct arcana_events_event_entry l;

			memset(&l, 0, sizeof(l));
			l.number = e.number;
			l.time = e.time;
			l.has_kind = e.has_kind;
			l.kind = e.kind;
			l.jail = e.jail;
			l.data = (enum arcana_events_event_entry_data)e.data;
			memcpy(&l.route, &e.route, sizeof(l) - offsetof(
			    struct arcana_events_event_entry, route));
			event(&l);
		}
		same((void *)arcana_events_event_encode, (void *)
		    arcana_events_event_decode, &e, &back, a);
	} else
		errx(2, "%s: list or one", argv[1]);
	return (0);
}
