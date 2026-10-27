/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the agent's faults (faults.c) as RFC 8632's alarms.  A
 * fault is an alarm: its object the
 * resource, as a string; its kind arcana-alarms' alarm type, no
 * qualifier; raised once, cleared once, its history those two status
 * changes (alarm-history); its severity Warning, Minor, Major or
 * Critical.  The inventory is every kind the agent raises, with the
 * severities it raises it with; the summary counts by severity.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "collect.h"
#include "yjson.h"

typedef struct ietf_alarms_alarms_alarm_list_alarm yalarm;

/* Each kind of fault, as faults.c's callers raise it. */
static const struct kind {
	const char	*name;
	int		 sev[2];	/* 0 ends */
	const char	*descr;
} kinds[] = {
	{ "tunnel", { 5, 0 }, "an SD-WAN tunnel's far end did not answer" },
	{ "tca", { 4, 0 }, "a probe's metric crossed its threshold" },
	{ "bfd", { 5, 0 }, "a BFD session went down" },
	{ "bgp-neighbor", { 4, 5 }, "a BGP session left Established" },
	{ "ospf-neighbor", { 5, 0 }, "an OSPF neighbour left Full" },
	{ "bird-instance", { 6, 0 }, "BIRD does not answer" },
	{ "interface", { 5, 0 }, "an SD-WAN interface has no link" },
	{ "ids", { 3, 6 }, "a Suricata instance that prevents is not running" },
	{ "key-rotation", { 5, 0 }, "manual IPsec keys were not rotated" },
	{ "storage", { 5, 0 }, "a pool or file system is too full" },
	{ "cpu", { 5, 0 }, "the CPU has been too busy" },
	{ "memory", { 5, 0 }, "the memory has been too full" },
	{ "crash", { 5, 0 }, "a process died of a signal that dumps core" },
	{ "mail", { 4, 5 }, "smtpd stopped, or too much queued" },
};

/* An identity's SID, by its module and name; 0: none. */
static uint64_t
ident_sid(const char *mod, const char *name)
{
	const struct cbl_yident	*id;
	uint32_t		 i;

	for (i = 0; i < ymodel_schema.nident; i++) {
		id = &ymodel_schema.ident[i];
		if (strcmp(id->name, name) == 0 &&
		    strcmp(id->module->name, mod) == 0)
			return (id->sid);
	}
	return (0);
}

/* A severity's value (RFC 8632's enumeration), by faults.c's word. */
static int
severity(const char *s)
{

	if (s == NULL)
		return (2);
	if (strcasecmp(s, "Warning") == 0)
		return (3);
	if (strcasecmp(s, "Minor") == 0)
		return (4);
	if (strcasecmp(s, "Major") == 0)
		return (5);
	if (strcasecmp(s, "Critical") == 0)
		return (6);
	return (2);		/* indeterminate */
}

static const char *
datetime(cbl_yarena *a, int64_t t)
{
	char		 buf[32];
	struct tm	 tm;
	time_t		 tt = (time_t)t;
	char		*p;

	if (gmtime_r(&tt, &tm) == NULL)
		return (NULL);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
	if ((p = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL)
		memcpy(p, buf, strlen(buf) + 1);
	return (p);
}

/* The alarm inventory: every kind, as the agent raises it. */
static int
inventory(cbl_yarena *a, struct ietf_alarms_alarms *al)
{
	struct ietf_alarms_alarms_alarm_inventory		*inv;
	struct ietf_alarms_alarms_alarm_inventory_alarm_type	*t;
	enum ietf_alarms_alarms_alarm_inventory_alarm_type_severity_level *sv;
	size_t							 i, k;

	if ((inv = cbl_yarena_alloc(a, sizeof(*inv))) == NULL ||
	    (t = cbl_yarena_alloc(a, nitems(kinds) * sizeof(*t))) == NULL)
		return (ENOMEM);
	for (i = 0; i < nitems(kinds); i++) {
		t[i].alarm_type_id = ident_sid("arcana-alarms", kinds[i].name);
		t[i].alarm_type_qualifier = "";
		t[i].has_will_clear = true;
		t[i].will_clear = true;
		for (k = 0; k < 2 && kinds[i].sev[k] != 0; k++)
			;
		if ((sv = cbl_yarena_alloc(a, k * sizeof(*sv))) == NULL)
			return (ENOMEM);
		for (k = 0; k < 2 && kinds[i].sev[k] != 0; k++)
			sv[k] = kinds[i].sev[k];
		t[i].severity_level.n = k;
		t[i].severity_level.v = sv;
		t[i].description = kinds[i].descr;
	}
	inv->alarm_type.n = nitems(kinds);
	inv->alarm_type.v = t;
	al->alarm_inventory = inv;
	return (0);
}

int
yalarms_from_json(const char *json, cbl_yarena *a, struct ietf_alarms *out)
{
	struct ietf_alarms_alarms			*al;
	struct ietf_alarms_alarms_alarm_list		*list;
	struct ietf_alarms_alarms_alarm_list_alarm_status_change *sc;
	struct ietf_alarms_alarms_summary		*sum;
	struct ietf_alarms_alarms_summary_alarm_summary	*sv;
	const ucl_object_t				*arr, *e;
	ucl_object_iter_t				 it;
	ucl_object_t					*top;
	yalarm						*v;
	const char					*type, *last;
	int64_t						 t, cl, lastt;
	size_t						 n, i;
	bool						 has;
	int						 sev, error;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	error = ENOMEM;
	arr = ucl_object_lookup(top, "faults");
	if ((al = cbl_yarena_alloc(a, sizeof(*al))) == NULL ||
	    (list = cbl_yarena_alloc(a, sizeof(*list))) == NULL ||
	    (sum = cbl_yarena_alloc(a, sizeof(*sum))) == NULL ||
	    (sv = cbl_yarena_alloc(a, 5 * sizeof(*sv))) == NULL ||
	    (v = cbl_yarena_alloc(a, (yj_count(arr) + 1) * sizeof(*v))) ==
	    NULL)
		goto out;
	if ((error = inventory(a, al)) != 0)
		goto out;
	/* The summary: each severity, those cleared and not. */
	for (i = 0; i < 5; i++) {
		sv[i].severity = (int)i + 2;
		sv[i].has_total = sv[i].has_not_cleared = sv[i].has_cleared =
		    true;
	}
	n = 0;
	lastt = 0;
	last = NULL;
	YJ_EACH(arr, it, e) {
		if ((type = yj_str(a, e, "type")) == NULL ||
		    !yj_num(e, "t", &t))
			continue;
		memset(&v[n], 0, sizeof(v[n]));
		v[n].resource.which = 2;	/* its string member */
		v[n].resource.v.m2 = yj_str(a, e, "object");
		v[n].alarm_type_id = ident_sid("arcana-alarms", type);
		v[n].alarm_type_qualifier = "";
		v[n].time_created = v[n].last_raised = datetime(a, t);
		v[n].has_is_cleared = true;
		v[n].is_cleared = yj_yes(e, "cleared", &has);
		cl = 0;
		if (v[n].is_cleared && yj_num(e, "cleared_at", &cl))
			v[n].last_changed = datetime(a, cl);
		else
			v[n].last_changed = v[n].last_raised;
		/* Its severity when raised: "was" keeps it once cleared. */
		sev = severity(yj_str(a, e, "was"));
		v[n].has_perceived_severity = true;
		v[n].perceived_severity = sev;
		v[n].alarm_text = yj_str(a, e, "description");
		if (v[n].alarm_text == NULL)
			v[n].alarm_text = "";
		/* Its history: raised, and cleared when it was; compressed,
		 * the clearing alone. */
		if ((sc = cbl_yarena_alloc(a, 2 * sizeof(*sc))) == NULL)
			goto nomem;
		sc[0].time = v[n].last_raised;
		sc[0].has_perceived_severity = true;
		sc[0].perceived_severity.which = 1;
		sc[0].perceived_severity.v.m1 = sev;
		sc[0].alarm_text = v[n].alarm_text;
		if (v[n].is_cleared && cl != 0) {
			sc[1].time = v[n].last_changed;
			sc[1].has_perceived_severity = true;
			sc[1].perceived_severity.which = 0;
			sc[1].perceived_severity.v.m0 =
			    IETF_ALARMS_ALARMS_ALARM_LIST_ALARM_STATUS_CHANGE_PERCEIVED_SEVERITY_M0_CLEARED;
			sc[1].alarm_text = v[n].alarm_text;
		}
		v[n].status_change.n = v[n].is_cleared && cl != 0 ? 2 : 1;
		v[n].status_change.v = sc;
		if (v[n].status_change.n == 2 && yj_yes(e, "compressed",
		    &has)) {
			v[n].status_change.n = 1;
			v[n].status_change.v = &sc[1];
		}
		sv[sev - 2].total++;
		if (v[n].is_cleared)
			sv[sev - 2].cleared++;
		else
			sv[sev - 2].not_cleared++;
		if ((cl != 0 ? cl : t) >= lastt) {
			lastt = cl != 0 ? cl : t;
			last = v[n].last_changed;
		}
		n++;
	}
	list->has_number_of_alarms = true;
	list->number_of_alarms = (uint32_t)n;
	list->last_changed = last;
	list->alarm.n = n;
	list->alarm.v = n > 0 ? v : NULL;
	sum->alarm_summary.n = 5;
	sum->alarm_summary.v = sv;
	al->alarm_list = list;
	al->summary = sum;
	out->alarms = al;
	error = 0;
	goto out;
nomem:
	error = ENOMEM;
out:
	ucl_object_unref(top);
	return (error);
}
