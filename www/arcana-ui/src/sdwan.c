/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * SD-WAN: the services the console keeps (sdwan.c of the console), as
 * MEF 70.2 says them.  Overview has the underlays, the edges and the
 * services in tables; Services has one service's parts, each in its
 * own; Document is the whole of it as JSON, checked by the console
 * against the standard before it is kept, its refusals naming the
 * requirement.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	nitems(x)	(sizeof(x) / sizeof((x)[0]))

enum { SD_OVERVIEW, SD_SERVICES, SD_EDGES, SD_DOCUMENT };

static struct {
	int		 tab;
	ucl_object_t	*doc;		/* /api/sdwan */
	char		*text;		/* the Document tab's box */
	char		 swvc[72];	/* the service shown */
	char		 error[600];
	char		 note[200];
	bool		 loading, busy;
	ucl_object_t	*plan;		/* /api/sdwan/plan */
	ucl_object_t	*applied;	/* /api/sdwan/apply */
	char		 plan_error[600];
	double		 plan_at, apply_at;
	bool		 applying;
} sd;

/* ---- Reading -------------------------------------------------------- */

static char *
pretty(const ucl_object_t *o)
{
	ucl_object_t	*c;
	char		*s;

	/* The version is said beside the box, not in it. */
	c = ucl_object_copy(o);
	(void)ucl_object_delete_key(c, "version");
	(void)ucl_object_delete_key(c, "changed");
	s = (char *)ucl_object_emit(c, UCL_EMIT_JSON);
	ucl_object_unref(c);
	return (s);
}

static void
doc_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	sd.loading = false;
	if (status != 200) {
		snprintf(sd.error, sizeof(sd.error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
		return;
	}
	if (sd.doc != NULL)
		ucl_object_unref(sd.doc);
	sd.doc = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	free(sd.text);
	sd.text = pretty(sd.doc);
	if (sd.swvc[0] == '\0' || jget(sd.doc, "swvcs") == NULL)
		snprintf(sd.swvc, sizeof(sd.swvc), "%s", jstr(sd.doc,
		    "swvcs.0.id") != NULL ? jstr(sd.doc, "swvcs.0.id") : "");
}

static void
sd_load(void)
{

	sd.loading = true;
	api("GET", "/api/sdwan", NULL, doc_cb, NULL);
}

void
sdwan_open(void)
{

	app.node = NODE_SDWAN;
	app.jail[0] = '\0';
	app.rail_open = false;
	sd_load();
}

static void
plan_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200) {
		snprintf(sd.plan_error, sizeof(sd.plan_error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
		if (sd.plan != NULL)
			ucl_object_unref(sd.plan);
		sd.plan = NULL;
		return;
	}
	sd.plan_error[0] = '\0';
	if (sd.plan != NULL)
		ucl_object_unref(sd.plan);
	sd.plan = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
}

static void
applied_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	bool	was;

	(void)arg;
	(void)err;
	if (status != 200)
		return;
	if (sd.applied != NULL)
		ucl_object_unref(sd.applied);
	sd.applied = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	was = sd.applying;
	sd.applying = jbool(o, "applying");
	/* It ended: what is left to do now. */
	if (was && !sd.applying) {
		toast(strcmp(jstr(o, "apply.state") != NULL ? jstr(o,
		    "apply.state") : "", "done") != 0, "SD-WAN apply %s",
		    jstr(o, "apply.state") != NULL ? jstr(o, "apply.state") :
		    "ended");
		api("GET", "/api/sdwan/plan", NULL, plan_cb, NULL);
	}
}

static void
plan_load(void)
{

	sd.plan_at = sd.apply_at = arc_now();
	api("GET", "/api/sdwan/plan", NULL, plan_cb, NULL);
	api("GET", "/api/sdwan/apply", NULL, applied_cb, NULL);
}

/* ---- Small things ---------------------------------------------------- */

static const char *
host_name(const char *id)
{
	int	i;

	for (i = 0; id != NULL && i < app.nservers; i++)
		if (strcmp(app.servers[i].id, id) == 0)
			return (app.servers[i].name);
	return (id != NULL ? id : "?");
}

/* A list's values joined by ", ", or what to say when there are none. */
static void
joined(struct html *h, const ucl_object_t *arr, const char *none)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	int			 n;

	if (arr != NULL && ucl_object_type(arr) == UCL_STRING) {
		h_txt(h, ucl_object_tostring(arr));
		return;
	}
	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (n++ > 0)
			h_raw(h, ", ");
		h_txt(h, ucl_object_tostring_forced(v));
	}
	if (n == 0)
		h_raw(h, none);
}

/* An object's keys and values, "key value; key value". */
static void
criteria(struct html *h, const ucl_object_t *cr)
{
	const ucl_object_t	*v, *p;
	ucl_object_iter_t	 it;
	int			 n;
	char			*s;

	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(cr, &it, true)) != NULL) {
		if (n++ > 0)
			h_raw(h, " ");
		if (strcmp(ucl_object_key(v), "any") == 0) {
			h_raw(h, "<span class=\"crit\">everything</span>");
			continue;
		}
		h_raw(h, "<span class=\"crit\"><b>");
		h_txt(h, ucl_object_key(v));
		h_raw(h, "</b> ");
		if (strcmp(ucl_object_key(v), "performance") == 0 &&
		    (p = jget(v, "primary")) != NULL) {
			h_txt(h, jstr(p, "metric") != NULL ? jstr(p, "metric") :
			    "");
			if (jget(p, "threshold") != NULL)
				h_fmt(h, " ≤ %g", jnum(p, "threshold", 0));
			if (jget(p, "ceiling") != NULL)
				h_fmt(h, ", moved at %g", jnum(p, "ceiling", 0));
		} else if (ucl_object_type(v) == UCL_ARRAY)
			joined(h, v, "none");
		else if (ucl_object_type(v) == UCL_OBJECT) {
			s = (char *)ucl_object_emit(v, UCL_EMIT_JSON_COMPACT);
			h_txt(h, s);
			free(s);
		} else
			h_txt(h, ucl_object_tostring_forced(v));
		h_raw(h, "</span>");
	}
	if (n == 0)
		h_raw(h, "<span class=\"dim\">none</span>");
}

static const char *
bits(int64_t b)
{
	static char	buf[32];

	if (b >= 1000000000)
		snprintf(buf, sizeof(buf), "%g Gbit/s", (double)b / 1e9);
	else if (b >= 1000000)
		snprintf(buf, sizeof(buf), "%g Mbit/s", (double)b / 1e6);
	else if (b >= 1000)
		snprintf(buf, sizeof(buf), "%g kbit/s", (double)b / 1e3);
	else
		snprintf(buf, sizeof(buf), "%lld bit/s", (long long)b);
	return (buf);
}

/* ---- Overview --------------------------------------------------------- */

static void
view_overview(struct html *h)
{
	const ucl_object_t	*v, *e, *t, *sw;
	ucl_object_iter_t	 it, eit;
	int			 n;
	bool			 first;

	/* The underlays. */
	h_raw(h, "<div class=\"sd-block\"><h3>Underlays <small class=\"dim\">"
	    "UCS, MEF 70.2 §12</small></h3><table class=\"net sd\"><thead><tr>"
	    "<th>Id</th><th>Type</th><th>Billing</th><th>Tunnels over it</th>"
	    "</tr></thead><tbody>");
	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(jget(sd.doc, "ucs"), &it, true)) !=
	    NULL) {
		n++;
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(v, "id"));
		h_fmt(h, "</td><td><span class=\"chip %s\">%s</span></td><td>",
		    jstr(v, "type") != NULL && strcmp(jstr(v, "type"),
		    "public") == 0 ? "warn" : "", jstr(v, "type") != NULL &&
		    strcmp(jstr(v, "type"), "public") == 0 ? "public" :
		    "private");
		h_txt(h, jstr(v, "billing") != NULL ? jstr(v, "billing") : "—");
		h_raw(h, "</td><td>");
		t = jget(v, "tunnel");
		if (t == NULL)
			h_raw(h, "<span class=\"dim\">the default</span>");
		else {
			h_txt(h, jstr(t, "kind"));
			if (jbool(t, "ipsec"))
				h_raw(h, " + IPsec IKEv2");
		}
		h_raw(h, "</td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"4\" class=\"dim\">None yet.</td>"
		    "</tr>");
	h_raw(h, "</tbody></table></div>");

	/* The edges and where each meets its underlays. */
	h_raw(h, "<div class=\"sd-block\"><h3>Edges <small class=\"dim\">"
	    "SD-WAN Edges and their UCS End Points, §7.8, §12.3</small></h3>"
	    "<table class=\"net sd\"><thead><tr><th>Host</th><th>End point</th>"
	    "<th>Underlay</th><th>Interface</th><th>Bandwidth</th><th></th>"
	    "</tr></thead><tbody>");
	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(jget(sd.doc, "edges"), &it, true)) !=
	    NULL) {
		first = true;
		eit = NULL;
		while ((e = ucl_object_iterate(jget(v, "ucs_end_points"), &eit,
		    true)) != NULL) {
			n++;
			h_raw(h, "<tr><td>");
			if (first)
				h_txt(h, host_name(jstr(v, "server")));
			first = false;
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(e, "id"));
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(e, "ucs"));
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(e, "interface"));
			h_raw(h, "</td><td>");
			if (jget(e, "bandwidth") != NULL)
				h_txt(h, bits(jint(e, "bandwidth", 0)));
			h_raw(h, "</td><td>");
			if (jbool(e, "breakout"))
				h_raw(h, "<span class=\"chip\" title=\"Traffic "
				    "for the Internet leaves here\">breakout"
				    "</span> ");
			if (jbool(e, "backup"))
				h_raw(h, "<span class=\"chip\" title=\"Used "
				    "only when nothing else is left\">backup"
				    "</span>");
			h_raw(h, "</td></tr>");
		}
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"6\" class=\"dim\">None yet.</td>"
		    "</tr>");
	h_raw(h, "</tbody></table></div>");

	/* The services. */
	h_raw(h, "<div class=\"sd-block\"><h3>Services <small class=\"dim\">"
	    "SWVCs, §9</small></h3><table class=\"net sd\"><thead><tr><th>Id"
	    "</th><th>FIB</th><th>End points</th><th>Underlays</th><th>Zones"
	    "</th><th>Flows</th><th>Policies</th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while ((sw = ucl_object_iterate(jget(sd.doc, "swvcs"), &it, true)) !=
	    NULL) {
		n++;
		h_raw(h, "<tr><td><button class=\"cell-link\" data-act=\""
		    "sd-swvc\"");
		h_attr(h, "data-arg", jstr(sw, "id"));
		h_raw(h, ">");
		h_txt(h, jstr(sw, "id"));
		h_fmt(h, "</button></td><td class=\"num\">%lld</td><td>",
		    (long long)jint(sw, "fib", 0));
		eit = NULL;
		while ((e = ucl_object_iterate(jget(sw, "end_points"), &eit,
		    true)) != NULL) {
			h_raw(h, "<span class=\"chip\">");
			h_txt(h, jstr(e, "id"));
			h_raw(h, " · ");
			h_txt(h, host_name(jstr(e, "edge")));
			h_raw(h, "</span> ");
		}
		h_raw(h, "</td><td>");
		joined(h, jget(sw, "ucs"), "—");
		h_fmt(h, "</td><td class=\"num\">%u</td><td class=\"num\">%u</td>"
		    "<td class=\"num\">%u</td></tr>",
		    jget(sw, "zones") != NULL ? ucl_array_size(jget(sw,
		    "zones")) : 0, jget(sw, "flows") != NULL ? ucl_array_size(
		    jget(sw, "flows")) : 0, jget(sw, "policies") != NULL ?
		    ucl_array_size(jget(sw, "policies")) : 0);
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"7\" class=\"dim\">None yet. Write "
		    "one in <b>Document</b>, or start from the example there."
		    "</td></tr>");
	h_raw(h, "</tbody></table></div>");
}

/* ---- One service ------------------------------------------------------ */

static const ucl_object_t *
swvc_shown(void)
{
	const ucl_object_t	*sw;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((sw = ucl_object_iterate(jget(sd.doc, "swvcs"), &it, true)) !=
	    NULL)
		if (jstr(sw, "id") != NULL && strcmp(jstr(sw, "id"), sd.swvc) ==
		    0)
			return (sw);
	return (NULL);
}

static void
addressing(struct html *h, const ucl_object_t *v)
{
	const char	*mode;

	mode = jstr(v, "mode");
	if (v == NULL || mode == NULL || strcmp(mode, "none") == 0) {
		h_raw(h, "<span class=\"dim\">none</span>");
		return;
	}
	if (strcmp(mode, "static") != 0) {
		h_txt(h, mode);
		return;
	}
	/* One span: a card keeps the prefix and its gateway together. */
	h_raw(h, "<span><span class=\"mono\">");
	h_txt(h, jstr(v, "prefix"));
	h_raw(h, "</span> <span class=\"dim\">via ");
	joined(h, jget(v, "provider"), "—");
	h_raw(h, "</span></span>");
}

static void
view_service(struct html *h)
{
	const ucl_object_t	*sw, *v, *e, *u, *m;
	ucl_object_iter_t	 it, mit;
	int			 n;

	h_raw(h, "<div class=\"toolbar\"><label class=\"inline\">Service "
	    "<select data-input=\"sd-swvc\">");
	it = NULL;
	while ((v = ucl_object_iterate(jget(sd.doc, "swvcs"), &it, true)) !=
	    NULL) {
		h_raw(h, "<option");
		h_attr(h, "value", jstr(v, "id"));
		if (strcmp(jstr(v, "id"), sd.swvc) == 0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, jstr(v, "id"));
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label>");
	if ((sw = swvc_shown()) == NULL) {
		h_raw(h, "</div><p class=\"dim\">No service yet.</p>");
		return;
	}
	h_fmt(h, "<span class=\"age\">FIB %lld on its edges · ", (long long)
	    jint(sw, "fib", 0));
	joined(h, jget(sw, "reserved_prefixes"), "no reserved prefixes");
	h_raw(h, "</span></div>");

	/* End points: where the subscriber meets it. */
	h_raw(h, "<div class=\"sd-block\"><h3>End points <small class=\"dim\">"
	    "each at an SD-WAN UNI, §10, §11</small></h3><table class=\"net sd\">"
	    "<thead><tr><th>Id</th><th>Edge</th><th>UNI</th><th>IPv4</th>"
	    "<th>IPv6</th><th>Static routes</th><th>Policy map</th></tr>"
	    "</thead><tbody>");
	it = NULL;
	while ((e = ucl_object_iterate(jget(sw, "end_points"), &it, true)) !=
	    NULL) {
		u = jget(e, "uni");
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(e, "id"));
		h_raw(h, "</td><td>");
		h_txt(h, host_name(jstr(e, "edge")));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(u, "interface"));
		if (jint(u, "vlan", 0) > 0)
			h_fmt(h, " <span class=\"dim\">vlan %lld</span>",
			    (long long)jint(u, "vlan", 0));
		h_raw(h, "</td><td>");
		addressing(h, jget(u, "ipv4"));
		h_raw(h, "</td><td>");
		addressing(h, jget(u, "ipv6"));
		h_fmt(h, "</td><td class=\"num\">%u</td><td>", jget(u, "routes")
		    != NULL ? ucl_array_size(jget(u, "routes")) : 0);
		n = 0;
		mit = NULL;
		while ((m = ucl_object_iterate(jget(e, "policy_map"), &mit,
		    true)) != NULL) {
			n++;
			h_raw(h, "<div class=\"pmap\"><span class=\"mono\">");
			h_txt(h, jstr(m, "zone"));
			h_raw(h, " · ");
			h_txt(h, jstr(m, "app"));
			h_raw(h, "</span> → ");
			h_txt(h, jstr(m, "ingress") != NULL ? jstr(m,
			    "ingress") : "none");
			if (jstr(m, "egress") != NULL) {
				h_raw(h, " <span class=\"dim\">out</span> ");
				h_txt(h, jstr(m, "egress"));
			}
			h_raw(h, "</div>");
		}
		if (n == 0)
			h_raw(h, "<span class=\"dim\">the zones' own</span>");
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table></div>");

	/* Zones. */
	h_raw(h, "<div class=\"sd-block\"><h3>Zones <small class=\"dim\">"
	    "by source address, §9.5</small></h3><table class=\"net sd\"><thead>"
	    "<tr><th>Name</th><th>Prefixes</th><th>Policies, zone-wide</th>"
	    "</tr></thead><tbody>");
	it = NULL;
	while ((v = ucl_object_iterate(jget(sw, "zones"), &it, true)) != NULL) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(v, "name"));
		h_raw(h, "</td><td class=\"mono\">");
		joined(h, jget(v, "prefixes"), "—");
		h_raw(h, "</td><td>");
		n = 0;
		mit = NULL;
		while ((m = ucl_object_iterate(jget(v, "policies"), &mit,
		    true)) != NULL) {
			if (n++ > 0)
				h_raw(h, ", ");
			h_txt(h, jstr(m, "app"));
			h_raw(h, " → ");
			h_txt(h, jstr(m, "policy"));
		}
		if (n == 0)
			h_raw(h, "<span class=\"dim\">none: dropped unless an end "
			    "point's map says (R112)</span>");
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table></div>");

	/* Application flows, in the order they are matched. */
	h_raw(h, "<div class=\"sd-block\"><h3>Application flows <small class="
	    "\"dim\">the first that matches, §9.14</small></h3><table class=\""
	    "net sd\"><thead><tr><th>#</th><th>Name</th><th>Matches</th><th>Group"
	    "</th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(jget(sw, "flows"), &it, true)) != NULL) {
		h_fmt(h, "<tr><td class=\"num\">%d</td><td class=\"mono\">", ++n);
		h_txt(h, jstr(v, "name"));
		h_raw(h, "</td><td>");
		criteria(h, jget(v, "criteria"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(v, "group") != NULL ? jstr(v, "group") : "");
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table></div>");

	/* Policies. */
	h_raw(h, "<div class=\"sd-block\"><h3>Policies <small class=\"dim\">"
	    "§9.12</small></h3><table class=\"net sd\"><thead><tr><th>Name</th>"
	    "<th>Direction</th><th>Criteria</th></tr></thead><tbody>");
	it = NULL;
	while ((v = ucl_object_iterate(jget(sw, "policies"), &it, true)) !=
	    NULL) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(v, "name"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(v, "direction"));
		h_raw(h, "</td><td>");
		criteria(h, jget(v, "criteria"));
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table></div>");

	/* Virtual topologies and rate limiters, when there are any. */
	if (jget(sw, "topologies") != NULL && ucl_array_size(jget(sw,
	    "topologies")) > 0) {
		h_raw(h, "<div class=\"sd-block\"><h3>Virtual topologies <small "
		    "class=\"dim\">§9.6; Swvc, all to all, is always there"
		    "</small></h3><table class=\"net sd\"><thead><tr><th>Name</th>"
		    "<th>Type</th><th>End points</th></tr></thead><tbody>");
		it = NULL;
		while ((v = ucl_object_iterate(jget(sw, "topologies"), &it,
		    true)) != NULL) {
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(v, "name"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(v, "type"));
			h_raw(h, "</td><td>");
			if (jget(v, "roots") != NULL) {
				h_raw(h, "roots ");
				joined(h, jget(v, "roots"), "—");
				h_raw(h, "; leaves ");
				joined(h, jget(v, "leaves"), "—");
			} else
				joined(h, jget(v, "end_points"), "—");
			h_raw(h, "</td></tr>");
		}
		h_raw(h, "</tbody></table></div>");
	}
	if (jget(sw, "rate_limiters") != NULL && ucl_array_size(jget(sw,
	    "rate_limiters")) > 0) {
		h_raw(h, "<div class=\"sd-block\"><h3>Rate limiters <small "
		    "class=\"dim\">shared per end point, §9.9</small></h3>"
		    "<table class=\"net sd\"><thead><tr><th>Name</th><th>Commit"
		    "</th><th>Limit</th></tr></thead><tbody>");
		it = NULL;
		while ((v = ucl_object_iterate(jget(sw, "rate_limiters"), &it,
		    true)) != NULL) {
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(v, "name"));
			h_raw(h, "</td><td>");
			h_txt(h, bits(jint(v, "commit", 0)));
			h_raw(h, "</td><td>");
			h_txt(h, jget(v, "limit") != NULL && ucl_object_type(
			    jget(v, "limit")) == UCL_INT ? bits(jint(v, "limit",
			    0)) : "none");
			h_raw(h, "</td></tr>");
		}
		h_raw(h, "</tbody></table></div>");
	}
}

/* ---- The edges -------------------------------------------------------- */

static int
count_change(const char *change)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((c = ucl_object_iterate(jget(sd.plan, "changes"), &it, true)) !=
	    NULL)
		if (strcmp(jstr(c, "change"), change) == 0)
			n++;
	return (n);
}

static const char *
change_word(const char *c)
{

	return (strcmp(c, "make") == 0 ? "to make" : strcmp(c, "remake") ==
	    0 ? "to make again" : strcmp(c, "unmake") == 0 ? "to take away" :
	    "as it is");
}

/* A job as a line: its kind and its fields. */
static void
job_line(struct html *h, const ucl_object_t *j)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	char			*s;

	h_raw(h, "<li><b>");
	h_txt(h, jstr(j, "kind"));
	h_raw(h, "</b>");
	it = NULL;
	while ((v = ucl_object_iterate(j, &it, true)) != NULL) {
		if (strcmp(ucl_object_key(v), "kind") == 0 ||
		    ucl_object_key(v)[0] == '_')
			continue;
		h_raw(h, " <span class=\"dim\">");
		h_txt(h, ucl_object_key(v));
		h_raw(h, "</span> ");
		if (ucl_object_type(v) == UCL_ARRAY) {
			s = (char *)ucl_object_emit(v, UCL_EMIT_JSON_COMPACT);
			h_txt(h, s);
			free(s);
		} else
			h_txt(h, ucl_object_tostring_forced(v));
	}
	h_raw(h, "</li>");
}

static void
view_tunnels(struct html *h, const ucl_object_t *tunnels)
{
	const ucl_object_t	*t, *e;
	ucl_object_iter_t	 it;
	int			 k;

	h_raw(h, "<div class=\"sd-block\"><h3>Tunnels <small class=\"dim\">"
	    "TVCs, §7.10: between each two edges of a service, over each two "
	    "of their underlays that reach each other</small></h3><table "
	    "class=\"net sd\"><thead><tr><th>Tunnel</th><th>Kind</th><th>End"
	    "</th><th>End</th><th></th></tr></thead><tbody>");
	it = NULL;
	while ((t = ucl_object_iterate(tunnels, &it, true)) != NULL) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(t, "id"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(t, "kind"));
		if (jbool(t, "ipsec"))
			h_raw(h, " + IPsec");
		h_fmt(h, " <span class=\"dim\">fib %lld</span></td>",
		    (long long)jint(t, "fib", 0));
		for (k = 0; k < 2; k++) {
			e = ucl_array_find_index(jget(t, "ends"),
			    (unsigned int)k);
			h_raw(h, "<td><b>");
			h_txt(h, host_name(jstr(e, "edge")));
			h_raw(h, "</b> <span class=\"mono\">");
			h_txt(h, jstr(e, "ifname"));
			h_raw(h, "</span><small class=\"dim\"> ");
			h_txt(h, jstr(e, "inner4") != NULL ? jstr(e, "inner4") :
			    jstr(e, "inner6") != NULL ? jstr(e, "inner6") : "");
			h_raw(h, " over ");
			h_txt(h, jstr(e, "underlay"));
			h_raw(h, "</small></td>");
		}
		h_raw(h, "<td>");
		h_raw(h, jbool(t, "encrypted") ? "<span class=\"chip\">"
		    "encrypted</span> " : "<span class=\"chip warn\">clear"
		    "</span> ");
		if (jbool(t, "public"))
			h_raw(h, "<span class=\"chip\">public</span> ");
		if (jbool(t, "backup"))
			h_raw(h, "<span class=\"chip\">backup</span>");
		h_raw(h, "</td></tr>");
	}
	if (ucl_array_size(tunnels) == 0)
		h_raw(h, "<tr><td colspan=\"5\" class=\"dim\">None: a service "
		    "with end points on two edges or more has them.</td></tr>");
	h_raw(h, "</tbody></table></div>");
}

/* The last apply: how far it went, each step and how it ended. */
static void
view_applied(struct html *h)
{
	const ucl_object_t	*ap, *s;
	ucl_object_iter_t	 it;
	char			 age[32];
	int			 n, done, failed;

	ap = jget(sd.applied, "apply");
	if (ap == NULL || jstr(ap, "state") == NULL)
		return;
	n = done = failed = 0;
	it = NULL;
	while ((s = ucl_object_iterate(jget(ap, "steps"), &it, true)) != NULL) {
		n++;
		if (strcmp(jstr(s, "state"), "done") == 0)
			done++;
		else if (strcmp(jstr(s, "state"), "failed") == 0)
			failed++;
	}
	fmt_age(age, sizeof(age), (double)jint(ap, "started", 0) * 1000);
	h_fmt(h, "<div class=\"sd-block sd-applied %s\"><h3>%s <small class="
	    "\"dim\">", jstr(ap, "state"), sd.applying ? "Applying" :
	    strcmp(jstr(ap, "state"), "done") == 0 ? "Last apply: done" :
	    "Last apply: failed");
	h_txt(h, age);
	h_fmt(h, " · %d of %d steps done%s</small></h3>", done, n,
	    failed > 0 ? ", some failed" : "");
	if (sd.applying || failed > 0) {
		h_raw(h, "<ul class=\"sd-steps\">");
		it = NULL;
		while ((s = ucl_object_iterate(jget(ap, "steps"), &it,
		    true)) != NULL) {
			h_fmt(h, "<li class=\"%s\"><span class=\"led\"></span>"
			    "<b>", jstr(s, "state"));
			h_txt(h, jstr(s, "name"));
			h_raw(h, "</b> ");
			h_txt(h, jstr(s, "title"));
			h_fmt(h, " <span class=\"dim\">%s · %s</span>",
			    change_word(jstr(s, "change")), jstr(s, "state"));
			if (jstr(s, "detail") != NULL) {
				h_raw(h, "<small>");
				h_txt(h, jstr(s, "detail"));
				h_raw(h, "</small>");
			}
			h_raw(h, "</li>");
		}
		h_raw(h, "</ul>");
	}
	h_raw(h, "</div>");
}

static void
view_edges(struct html *h)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it, jit;
	const ucl_object_t	*j;
	const char		*last;
	int			 todo;

	if (sd.plan == NULL && sd.plan_error[0] == '\0') {
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	todo = sd.plan != NULL ? count_change("make") + count_change(
	    "remake") + count_change("unmake") : 0;
	h_fmt(h, "<div class=\"toolbar\"><button class=\"primary small\" "
	    "data-act=\"sd-apply\"%s title=\"Make on the edges what the "
	    "services say, in Mplify 119's order: FIBs, IPsec, tunnels, their "
	    "far ends, routes, and the UNIs last\">Apply%s</button><button "
	    "class=\"ghost small\" data-act=\"sd-apply-fresh\"%s title=\""
	    "Everything the console made taken away and made again\">Make "
	    "all again</button><span class=\"age\">",
	    todo == 0 || sd.applying ? " disabled" : "", todo > 0 ?
	    "" : ": nothing to do", sd.applying ? " disabled" : "");
	if (sd.plan != NULL)
		h_fmt(h, "%d to make, %d to make again, %d to take away, %d as "
		    "they are", count_change("make"), count_change("remake"),
		    count_change("unmake"), count_change("keep"));
	h_raw(h, "</span></div>");
	if (sd.plan_error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, sd.plan_error);
		h_raw(h, "</div>");
		return;
	}
	view_applied(h);
	view_tunnels(h, jget(sd.plan, "tunnels"));
	/* What each edge is to have, and what becomes of it. */
	h_raw(h, "<div class=\"sd-block\"><h3>On the edges <small class=\"dim"
	    "\">what each is to have, as jobs</small></h3><table class=\"net "
	    "sd sd-plan\"><thead><tr><th>Edge</th><th>What</th><th>Change</th>"
	    "<th>Jobs</th></tr></thead><tbody>");
	last = "";
	it = NULL;
	while ((c = ucl_object_iterate(jget(sd.plan, "changes"), &it, true)) !=
	    NULL) {
		h_fmt(h, "<tr class=\"ch-%s\"><td>", jstr(c, "change"));
		if (strcmp(last, jstr(c, "server")) != 0)
			h_txt(h, jstr(c, "name"));
		last = jstr(c, "server");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(c, "title"));
		h_fmt(h, "</td><td><span class=\"chip ch-%s\">%s</span></td>"
		    "<td><details><summary>%u</summary><ul class=\"sd-jobs\">",
		    jstr(c, "change"), change_word(jstr(c, "change")),
		    strcmp(jstr(c, "change"), "unmake") == 0 ?
		    ucl_array_size(jget(c, "unmake")) : ucl_array_size(jget(c,
		    "make")));
		jit = NULL;
		while ((j = ucl_object_iterate(jget(c, strcmp(jstr(c, "change"),
		    "unmake") == 0 ? "unmake" : "make"), &jit, true)) != NULL)
			job_line(h, j);
		h_raw(h, "</ul></details></td></tr>");
	}
	h_raw(h, "</tbody></table></div>");
}

/* ---- The document ----------------------------------------------------- */

static void
view_document(struct html *h)
{

	h_fmt(h, "<p class=\"dim\">The whole of it as JSON: <code>ucs</code>, "
	    "<code>edges</code> and <code>swvcs</code>, named as MEF 70.2 names "
	    "them. <b>Check</b> asks the console whether it is one the "
	    "standard allows; <b>Keep</b> keeps it as version %lld. What it "
	    "says no to names the requirement.</p>", (long long)jint(sd.doc,
	    "version", 0) + 1);
	if (sd.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, sd.error);
		h_raw(h, "</div>");
	} else if (sd.note[0] != '\0') {
		h_raw(h, "<div class=\"notice info\">");
		h_txt(h, sd.note);
		h_raw(h, "</div>");
	}
	h_raw(h, "<form data-form=\"sd-doc\" class=\"sd-doc\"><textarea name="
	    "\"text\" rows=\"28\" spellcheck=\"false\" class=\"mono\">");
	h_txt(h, sd.text != NULL ? sd.text : "");
	h_fmt(h, "</textarea><div class=\"actions\"><button class=\"ghost "
	    "small\" name=\"how\" value=\"check\"%s>Check</button><button "
	    "class=\"small\" name=\"how\" value=\"keep\"%s>Keep</button>"
	    "<button type=\"button\" class=\"ghost small\" data-act=\""
	    "sd-example\" title=\"A service with two edges, written out, to "
	    "be made your own before it is kept\">Start from an example"
	    "</button><button type=\"button\" class=\"ghost small\" "
	    "data-act=\"sd-revert\">Back to the kept one</button></div>"
	    "</form>", sd.busy ? " disabled" : "", sd.busy ? " disabled" : "");
}

void
view_sdwan(struct html *h)
{

	h_raw(h, "<section class=\"sdwan\">");
	h_fmt(h, "<nav class=\"tabs\"><button class=\"tab%s\" data-act=\""
	    "sd-tab\" data-arg=\"overview\">Overview</button><button class=\""
	    "tab%s\" data-act=\"sd-tab\" data-arg=\"services\">Services"
	    "</button><button class=\"tab%s\" data-act=\"sd-tab\" data-arg=\""
	    "edges\" title=\"What the edges are to have, and Apply\">Edges"
	    "</button><button class=\"tab%s\" data-act=\"sd-tab\" data-arg=\""
	    "document\" title=\"All of it as JSON, checked against MEF 70.2"
	    "\">Document</button></nav>", sd.tab == SD_OVERVIEW ? " on" : "",
	    sd.tab == SD_SERVICES ? " on" : "", sd.tab == SD_EDGES ? " on" : "",
	    sd.tab == SD_DOCUMENT ? " on" : "");
	if (sd.doc == NULL) {
		if (sd.error[0] != '\0') {
			h_raw(h, "<div class=\"notice bad\">");
			h_txt(h, sd.error);
			h_raw(h, "</div>");
		} else
			h_raw(h, "<div class=\"loader\"></div>");
	} else if (sd.tab == SD_SERVICES)
		view_service(h);
	else if (sd.tab == SD_EDGES)
		view_edges(h);
	else if (sd.tab == SD_DOCUMENT)
		view_document(h);
	else
		view_overview(h);
	h_raw(h, "</section>");
}

/* ---- What is done ---------------------------------------------------- */

static void
sent_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	bool	keep = arg != NULL;

	sd.busy = false;
	if (status != 200) {
		snprintf(sd.error, sizeof(sd.error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
		sd.note[0] = '\0';
		return;
	}
	sd.error[0] = '\0';
	if (!keep) {
		snprintf(sd.note, sizeof(sd.note), "It is one MEF 70.2 allows, "
		    "as far as the console checks.");
		return;
	}
	snprintf(sd.note, sizeof(sd.note), "Kept as version %lld.",
	    (long long)jint(o, "version", 0));
	toast(false, "SD-WAN kept");
	doc_cb(status, o, err, NULL);
}

/* The box's text sent, with the version it was made from. */
static void
send(const char *text, bool keep)
{
	ucl_object_t	*o;
	unsigned char	*json;

	if ((o = json_parse(text)) == NULL || ucl_object_type(o) !=
	    UCL_OBJECT) {
		if (o != NULL)
			ucl_object_unref(o);
		snprintf(sd.error, sizeof(sd.error), "It is not JSON, or not an "
		    "object.");
		sd.note[0] = '\0';
		return;
	}
	(void)ucl_object_delete_key(o, "version");
	ucl_object_insert_key(o, ucl_object_fromint(jint(sd.doc, "version",
	    0)), "version", 0, false);
	json = ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	sd.busy = true;
	api(keep ? "PUT" : "POST", keep ? "/api/sdwan" : "/api/sdwan/check",
	    (char *)json, sent_cb, keep ? (void *)1 : NULL);
	free(json);
}

/* An example to start from: two edges, each a host the console has. */
static void
example(void)
{
	struct html	 b;
	const char	*a, *z;

	a = app.nservers > 0 ? app.servers[0].id : "HOST-A";
	z = app.nservers > 1 ? app.servers[1].id : a;
	memset(&b, 0, sizeof(b));
	h_fmt(&b, "{\n"
	    "\t\"ucs\": [\n"
	    "\t\t{\"id\": \"internet\", \"type\": \"public\", \"billing\": "
	    "\"flat-rate\",\n\t\t \"tunnel\": {\"kind\": \"gre\", \"ipsec\": "
	    "true}},\n"
	    "\t\t{\"id\": \"mpls\", \"type\": \"private\", \"billing\": "
	    "\"usage-based\",\n\t\t \"tunnel\": {\"kind\": \"geneve\"}}\n"
	    "\t],\n"
	    "\t\"edges\": [\n"
	    "\t\t{\"server\": \"%s\", \"ucs_end_points\": [\n"
	    "\t\t\t{\"id\": \"hq-inet\", \"ucs\": \"internet\", \"interface\": "
	    "\"vtnet0\", \"address\": \"192.0.2.10\",\n\t\t\t \"breakout\": "
	    "true},\n"
	    "\t\t\t{\"id\": \"hq-mpls\", \"ucs\": \"mpls\", \"interface\": "
	    "\"vtnet1\", \"address\": \"10.99.0.1\"}]},\n"
	    "\t\t{\"server\": \"%s\", \"ucs_end_points\": [\n"
	    "\t\t\t{\"id\": \"br-inet\", \"ucs\": \"internet\", \"interface\": "
	    "\"vtnet0\", \"address\": \"198.51.100.20\"},\n"
	    "\t\t\t{\"id\": \"br-mpls\", \"ucs\": \"mpls\", \"interface\": "
	    "\"vtnet1\", \"address\": \"10.99.0.2\",\n\t\t\t \"backup\": true}]}\n"
	    "\t],\n"
	    "\t\"swvcs\": [{\n"
	    "\t\t\"id\": \"office\", \"fib\": 1, \"ucs\": [\"internet\", "
	    "\"mpls\"],\n"
	    "\t\t\"reserved_prefixes\": [\"100.64.0.0/24\", \"fd00:64::/64\"],\n"
	    "\t\t\"intervals\": {\"eval\": 1000, \"arrival\": 100, \"ir\": 500},\n"
	    "\t\t\"zones\": [{\"name\": \"staff\", \"prefixes\": \"Default\",\n"
	    "\t\t\t\"policies\": [{\"app\": \"voice\", \"policy\": \"realtime\"},"
	    "\n\t\t\t\t{\"app\": \"rest\", \"policy\": \"standard\"}]}],\n"
	    "\t\t\"flows\": [\n"
	    "\t\t\t{\"name\": \"voice\", \"criteria\": {\"dscp\": [46]}},\n"
	    "\t\t\t{\"name\": \"rest\", \"criteria\": {\"any\": true}}\n"
	    "\t\t],\n"
	    "\t\t\"policies\": [\n"
	    "\t\t\t{\"name\": \"realtime\", \"direction\": \"ingress\", "
	    "\"criteria\": {\n"
	    "\t\t\t\t\"encryption\": \"required-public-only\",\n"
	    "\t\t\t\t\"allowed-destination-zones\": \"All\",\n"
	    "\t\t\t\t\"performance\": {\"primary\": {\"metric\": \"delay\", "
	    "\"threshold\": 30, \"ceiling\": 50},\n"
	    "\t\t\t\t\t\"secondary\": [{\"metric\": \"loss\", \"threshold\": "
	    "0.01}]}}},\n"
	    "\t\t\t{\"name\": \"standard\", \"direction\": \"ingress\", "
	    "\"criteria\": {\n"
	    "\t\t\t\t\"encryption\": \"required-public-only\",\n"
	    "\t\t\t\t\"allowed-destination-zones\": \"All\",\n"
	    "\t\t\t\t\"internet-breakout\": \"enabled\"}}\n"
	    "\t\t],\n"
	    "\t\t\"end_points\": [\n"
	    "\t\t\t{\"id\": \"hq\", \"edge\": \"%s\", \"uni\": {\"id\": "
	    "\"hq-lan\", \"interface\": \"vtnet2\",\n"
	    "\t\t\t\t\"ipv4\": {\"mode\": \"static\", \"prefix\": "
	    "\"10.10.0.0/24\", \"provider\": [\"10.10.0.1\"]}},\n"
	    "\t\t\t \"nat\": {\"ip_version\": \"ipv4\", \"public_prefix\": "
	    "\"192.0.2.8/30\"}},\n"
	    "\t\t\t{\"id\": \"branch\", \"edge\": \"%s\", \"uni\": {\"id\": "
	    "\"br-lan\", \"interface\": \"vtnet2\",\n"
	    "\t\t\t\t\"ipv4\": {\"mode\": \"static\", \"prefix\": "
	    "\"10.20.0.0/24\", \"provider\": [\"10.20.0.1\"]}}}\n"
	    "\t\t]\n"
	    "\t}]\n"
	    "}\n", a, z, a, z);
	free(sd.text);
	sd.text = b.s;
	sd.error[0] = '\0';
	snprintf(sd.note, sizeof(sd.note), "An example, not kept: interfaces "
	    "and addresses are to be made your own.");
}

static void
apply_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200) {
		sd.applying = false;
		toast(true, "Not applied: %s", jstr(o, "error.message") != NULL ?
		    jstr(o, "error.message") : err != NULL ? err : "no answer");
		return;
	}
	api("GET", "/api/sdwan/apply", NULL, applied_cb, NULL);
}

bool
sdwan_form(const char *form, const ucl_object_t *f)
{
	const char	*text;

	if (strcmp(form, "sd-doc") != 0)
		return (false);
	text = jstr(f, "text") != NULL ? jstr(f, "text") : "";
	/* What was typed stays in the box while it is asked. */
	free(sd.text);
	sd.text = strdup(text);
	send(text, jstr(f, "how") != NULL && strcmp(jstr(f, "how"), "keep") ==
	    0);
	return (true);
}

bool
sdwan_action(const char *act, const char *arg, const char *value)
{

	if (strcmp(act, "select-sdwan") == 0) {
		sdwan_open();
		return (true);
	}
	if (strncmp(act, "sd-", 3) != 0 && strcmp(act, "input:sd-swvc") != 0 &&
	    strcmp(act, "do-sd-apply-fresh") != 0)
		return (false);
	if (strcmp(act, "sd-tab") == 0) {
		sd.tab = strcmp(arg, "services") == 0 ? SD_SERVICES :
		    strcmp(arg, "edges") == 0 ? SD_EDGES : strcmp(arg,
		    "document") == 0 ? SD_DOCUMENT : SD_OVERVIEW;
		if (sd.tab == SD_EDGES)
			plan_load();
		sd.note[0] = '\0';
		if (sd.tab != SD_DOCUMENT)
			sd.error[0] = '\0';
	} else if (strcmp(act, "sd-swvc") == 0) {
		snprintf(sd.swvc, sizeof(sd.swvc), "%s", arg);
		sd.tab = SD_SERVICES;
	} else if (strcmp(act, "input:sd-swvc") == 0)
		snprintf(sd.swvc, sizeof(sd.swvc), "%s", value);
	else if (strcmp(act, "sd-example") == 0)
		example();
	else if (strcmp(act, "sd-apply") == 0 || strcmp(act,
	    "do-sd-apply-fresh") == 0) {
		sd.applying = true;
		api("POST", "/api/sdwan/apply", strcmp(act, "sd-apply") == 0 ?
		    "{}" : "{\"fresh\":true}", apply_cb, NULL);
	} else if (strcmp(act, "sd-apply-fresh") == 0)
		confirm("Make all again", "Everything the console made on the "
		    "edges is taken away and made again: tunnels go down for a "
		    "while.", "Make all again", true, "", "do-sd-apply-fresh",
		    "", "");
	else if (strcmp(act, "sd-revert") == 0) {
		free(sd.text);
		sd.text = sd.doc != NULL ? pretty(sd.doc) : NULL;
		sd.error[0] = sd.note[0] = '\0';
	}
	return (true);
}

void
sdwan_tick(double now)
{
	static double	at;

	if (app.node == NODE_SDWAN && app.visible && sd.tab == SD_EDGES &&
	    sd.applying && now - sd.apply_at > 1000) {
		sd.apply_at = now;
		api("GET", "/api/sdwan/apply", NULL, applied_cb, NULL);
	}
	/* Kept elsewhere meanwhile: read again, unless a change is typed. */
	if (app.node != NODE_SDWAN || !app.visible || sd.tab == SD_DOCUMENT ||
	    sd.loading || now - at < 30000)
		return;
	at = now;
	sd_load();
}
