/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Troubleshoot, a page of its own in the side bar: a packet from one
 * address to another followed across the hosts and their vnet jails,
 * and what stops it (the console's troubleshoot.c, each place's
 * path-check).  Its tab, Packet path: the source, the destination, the
 * protocol and port, and where to look; then what is wrong, worst
 * first, and the way there and the way back drawn place by place: where
 * it comes in, what the firewall does, the route it takes, where it
 * goes next.  Nothing is sent to find it out.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	char		 src[64], dst[64], proto[8], port[8];
	char		 places[64][80];	/* "sid" or "sid/jail" */
	int		 nplaces;		/* 0: every host */
	bool		 busy;
	char		 error[400];
	ucl_object_t	*result;
} ts = { .proto = "tcp" };

static void
path_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	ts.busy = false;
	if (status != 200 || o == NULL || !jbool(o, "ok")) {
		snprintf(ts.error, sizeof(ts.error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
		return;
	}
	ts.error[0] = '\0';
	if (ts.result != NULL)
		ucl_object_unref(ts.result);
	ts.result = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
}

static void
ask(void)
{
	ucl_object_t	*b, *pl, *p;
	char		*json, *slash, sid[16];
	int		 i;

	b = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(b, ucl_object_fromstring(ts.src), "src", 0,
	    true);
	ucl_object_insert_key(b, ucl_object_fromstring(ts.dst), "dst", 0,
	    true);
	ucl_object_insert_key(b, ucl_object_fromstring(ts.proto), "proto", 0,
	    true);
	if ((strcmp(ts.proto, "tcp") == 0 || strcmp(ts.proto, "udp") == 0) &&
	    ts.port[0] != '\0')
		ucl_object_insert_key(b, ucl_object_fromint(atoi(ts.port)),
		    "port", 0, true);
	if (ts.nplaces > 0) {
		pl = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < ts.nplaces; i++) {
			p = ucl_object_typed_new(UCL_OBJECT);
			snprintf(sid, sizeof(sid), "%.*s", (int)strcspn(
			    ts.places[i], "/"), ts.places[i]);
			ucl_object_insert_key(p, ucl_object_fromstring(sid),
			    "server", 0, true);
			if ((slash = strchr(ts.places[i], '/')) != NULL)
				ucl_object_insert_key(p, ucl_object_fromstring(
				    slash + 1), "jail", 0, true);
			ucl_array_append(pl, p);
		}
		ucl_object_insert_key(b, pl, "places", 0, true);
	}
	json = (char *)ucl_object_emit(b, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(b);
	ts.busy = true;
	ts.error[0] = '\0';
	api("POST", "/api/troubleshoot/path", json, path_cb, NULL);
	free(json);
}

static bool
picked(const char *key)
{
	int	i;

	for (i = 0; i < ts.nplaces; i++)
		if (strcmp(ts.places[i], key) == 0)
			return (true);
	return (false);
}

static void
place_box(struct html *h, const char *key, const char *label, bool jail)
{

	h_fmt(h, "<label class=\"toggle%s\"><input type=\"checkbox\"",
	    jail ? " tsjail" : "");
	h_attr(h, "name", key);
	h_fmt(h, "%s> ", picked(key) ? " checked" : "");
	h_txt(h, label);
	h_raw(h, "</label>");
}

/* A firewall's verdict, as a chip: its rule on hover. */
static void
verdict(struct html *h, const char *where, const ucl_object_t *v)
{
	const char	*vd = jstr(v, "verdict");

	/* An empty ruleset decides nothing: the kernel's default does. */
	if (v == NULL || vd == NULL || strcmp(vd, "none") == 0)
		return;
	h_fmt(h, "<span class=\"chip fw %s\"", strcmp(vd, "deny") == 0 ? "bad" :
	    strcmp(vd, "allow") == 0 ? "good" : "warn");
	h_attr(h, "title", jstr(v, "text") != NULL ? jstr(v, "text") :
	    "no rule");
	h_raw(h, ">");
	h_txt(h, where);
	h_raw(h, " ");
	h_txt(h, strcmp(vd, "allow") == 0 ? (jbool(v, "by_state") ?
	    "let by its state" : "allowed") : strcmp(vd, "deny") == 0 ?
	    "dropped" : vd);
	if (jint(v, "rule", 0) != 0)
		h_fmt(h, " · %lld", (long long)jint(v, "rule", 0));
	h_raw(h, "</span>");
}

/* One way, place by place. */
static void
way(struct html *h, const char *title, const ucl_object_t *hops,
    const ucl_object_t *end, bool reply)
{
	const ucl_object_t	*hop, *c;
	ucl_object_iter_t	 it;
	char			*text;

	h_raw(h, "<h4 class=\"family\">");
	h_txt(h, title);
	h_raw(h, "</h4><ol class=\"tsway\">");
	it = NULL;
	while ((hop = ucl_object_iterate(hops, &it, true)) != NULL) {
		c = jget(hop, "check");
		h_raw(h, "<li class=\"tshop\"><b>");
		h_txt(h, jstr(hop, "place"));
		h_raw(h, "</b>");
		if (jstr(hop, "error") != NULL) {
			h_raw(h, "<span class=\"bad\">");
			h_txt(h, jstr(hop, "error"));
			h_raw(h, "</span></li>");
			continue;
		}
		h_raw(h, "<span class=\"dim\">in on ");
		h_txt(h, jstr(hop, "ingress") != NULL ? jstr(hop, "ingress") :
		    jbool(c, "src.local") ? "(made here)" : "?");
		h_raw(h, "</span>");
		if (jget(c, "firewall.on") != NULL && !jbool(c, "firewall.on"))
			h_raw(h, "<span class=\"chip\">no firewall</span>");
		verdict(h, "in", jget(c, "firewall.in"));
		if (jbool(c, "dst.local"))
			h_raw(h, "<span class=\"chip good\">here: delivered"
			    "</span>");
		else if (jget(c, "route") != NULL) {
			h_raw(h, "<span class=\"tsroute\">route ");
			h_txt(h, jstr(c, "route.destination"));
			h_fmt(h, "/%lld", (long long)jint(c, "route.prefixlen", 0));
			h_raw(h, " via ");
			h_txt(h, jstr(c, "route.gateway"));
			h_raw(h, " on ");
			h_txt(h, jstr(c, "route.interface"));
			h_fmt(h, ", FIB %lld</span>", (long long)jint(c, "fib",
			    0));
		} else
			h_raw(h, "<span class=\"chip bad\">no route</span>");
		verdict(h, "out", jget(c, "firewall.out"));
		if (jstr(hop, "next_hop") != NULL) {
			h_raw(h, "<span class=\"dim\">→ ");
			h_txt(h, jstr(hop, "next_hop"));
			h_raw(h, "</span>");
		}
		/* What it found, the place's own words and its check. */
		text = data_emit(c, false);
		h_raw(h, "<details><summary>What it checked</summary><pre>");
		h_txt(h, text);
		h_raw(h, "</pre></details></li>");
		free(text);
	}
	h_fmt(h, "<li class=\"tsend %s\">", jstr(end, "how") != NULL ?
	    jstr(end, "how") : "");
	h_txt(h, jstr(end, "what"));
	h_raw(h, "</li></ol>");
	(void)reply;
}

static void
result(struct html *h)
{
	const ucl_object_t	*r = ts.result, *f;
	ucl_object_iter_t	 it;
	const char		*sev;

	if (r == NULL)
		return;
	f = ucl_array_find_index(jget(r, "findings"), 0);
	sev = jstr(f, "severity") != NULL ? jstr(f, "severity") : "ok";
	h_fmt(h, "<div class=\"tsverdict %s\">", sev);
	if (strcmp(sev, "bad") == 0) {
		h_raw(h, "<b>Stopped");
		if (jstr(f, "place") != NULL) {
			h_raw(h, " at ");
			h_txt(h, jstr(f, "place"));
		}
		h_raw(h, ":</b> ");
		h_txt(h, jstr(f, "what"));
	} else if (strcmp(sev, "warn") == 0) {
		h_raw(h, "<b>It gets through, with a doubt:</b> ");
		h_txt(h, jstr(f, "what"));
	} else if (jstr(r, "end.how") != NULL && strcmp(jstr(r, "end.how"),
	    "leaves") == 0) {
		h_raw(h, "<b>Nothing found that stops it here.</b> ");
		h_txt(h, jstr(r, "end.what"));
	} else
		h_raw(h, "<b>Nothing found that stops it.</b> The places "
		    "asked would let it through, and its reply back.");
	h_raw(h, "<span class=\"tabexport\">Export <button class=\"ghost "
	    "small\" data-act=\"ts-export\" data-arg=\"json\">JSON</button>"
	    "<button class=\"ghost small\" data-act=\"ts-export\" data-arg=\""
	    "yaml\">YAML</button></span></div>");
	h_raw(h, "<ul class=\"tsfindings\">");
	it = NULL;
	while ((f = ucl_object_iterate(jget(r, "findings"), &it, true)) !=
	    NULL) {
		/* What the banner says already. */
		if (strcmp(jstr(f, "severity"), "ok") == 0)
			continue;
		h_fmt(h, "<li class=\"%s\"><span class=\"chip %s\">%s</span>",
		    jstr(f, "severity"), strcmp(jstr(f, "severity"), "bad") ==
		    0 ? "bad" : strcmp(jstr(f, "severity"), "warn") == 0 ?
		    "warn" : "", jstr(f, "severity"));
		if (jstr(f, "place") != NULL) {
			h_raw(h, "<b>");
			h_txt(h, jstr(f, "place"));
			h_raw(h, "</b> ");
		}
		h_txt(h, jstr(f, "what"));
		h_raw(h, "</li>");
	}
	h_raw(h, "</ul>");
	way(h, "The way there", jget(r, "hops"), jget(r, "end"), false);
	if (jget(r, "return") != NULL)
		way(h, "The way back, the reply's", jget(r, "return"), jget(r,
		    "return_end"), true);
}

void
view_trouble(struct html *h)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;
	char			 key[80];
	int			 i;

	h_raw(h, "<section class=\"trouble\"><div class=\"set-head\"><h2>"
	    "Troubleshoot</h2></div><nav class=\"tabs\"><button class=\"tab "
	    "on\" data-act=\"ts-tab\" data-arg=\"path\">Packet path</button>"
	    "</nav>");
	h_raw(h, "<p class=\"dim\">A packet from one address to another, "
	    "followed across the hosts and their vnet jails: where it comes "
	    "in, what each firewall (ipfw) does with it, the route each sends "
	    "it by, and the reply's way back. Nothing is sent: each place says "
	    "what it would do, from its routes, its ARP and NDP entries, its "
	    "sysctls and its ruleset as the kernel has them.</p>");
	h_fmt(h, "<form class=\"tsform\" data-form=\"ts-path\"><div "
	    "class=\"two\"><label>From<input name=\"src\" required "
	    "placeholder=\"10.1.0.2\" maxlength=\"63\"");
	h_attr(h, "value", ts.src);
	h_raw(h, "></label><label>To<input name=\"dst\" required "
	    "placeholder=\"10.3.0.2\" maxlength=\"63\"");
	h_attr(h, "value", ts.dst);
	h_raw(h, "></label></div><div class=\"two\"><label>Protocol<select "
	    "name=\"proto\">");
	{
		static const char *const pr[] = { "tcp", "udp", "icmp", "ip" };

		for (i = 0; i < 4; i++)
			h_fmt(h, "<option value=\"%s\"%s>%s</option>", pr[i],
			    strcmp(ts.proto, pr[i]) == 0 ? " selected" : "",
			    i == 2 ? "icmp (ping)" : i == 3 ? "ip (any)" :
			    pr[i]);
	}
	h_raw(h, "</select></label><label>Port, of tcp or udp<input "
	    "name=\"port\" type=\"number\" min=\"1\" max=\"65535\" "
	    "placeholder=\"22\"");
	h_attr(h, "value", ts.port);
	h_fmt(h, "></label></div><details class=\"tsplaces\"%s><summary>"
	    "Where to look: %s</summary><p class=\"dim\">The hosts asked, and "
	    "the vnet jails that route as routers do. None ticked: every "
	    "host.</p>", ts.nplaces > 0 ? " open" : "", ts.nplaces > 0 ?
	    "those ticked" : "every host");
	for (i = 0; i < app.nservers; i++) {
		struct server	*s = &app.servers[i];

		h_raw(h, "<div class=\"tsplace\">");
		place_box(h, s->id, s->name, false);
		it = NULL;
		while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
		    "jails"), &it, true)) != NULL) {
			if (jstr(j, "name") == NULL || !jbool(j, "vnet") ||
			    jstr(j, "state") == NULL || strcmp(jstr(j, "state"),
			    "running") != 0)
				continue;
			snprintf(key, sizeof(key), "%s/%s", s->id, jstr(j,
			    "name"));
			place_box(h, key, jstr(j, "name"), true);
		}
		h_raw(h, "</div>");
	}
	h_fmt(h, "</details><div class=\"actions\"><button class=\"primary\""
	    "%s>Follow it</button></div></form>", ts.busy ? " disabled" : "");
	if (ts.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, ts.error);
		h_raw(h, "</div>");
	}
	if (ts.busy)
		h_raw(h, "<div class=\"loader\"></div>");
	else
		result(h);
	h_raw(h, "</section>");
}

bool
trouble_form(const char *form, const ucl_object_t *f)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;

	if (strcmp(form, "ts-path") != 0)
		return (false);
	snprintf(ts.src, sizeof(ts.src), "%s", jstr(f, "src") != NULL ?
	    jstr(f, "src") : "");
	snprintf(ts.dst, sizeof(ts.dst), "%s", jstr(f, "dst") != NULL ?
	    jstr(f, "dst") : "");
	snprintf(ts.proto, sizeof(ts.proto), "%s", jstr(f, "proto") != NULL ?
	    jstr(f, "proto") : "ip");
	snprintf(ts.port, sizeof(ts.port), "%s", jstr(f, "port") != NULL ?
	    jstr(f, "port") : "");
	/* The ticked places: every field that is not one of the above. */
	ts.nplaces = 0;
	it = NULL;
	while ((v = ucl_object_iterate(f, &it, true)) != NULL &&
	    ts.nplaces < 64) {
		const char *k = ucl_object_key(v);

		if (strcmp(k, "src") == 0 || strcmp(k, "dst") == 0 ||
		    strcmp(k, "proto") == 0 || strcmp(k, "port") == 0 ||
		    !ucl_object_toboolean(v))
			continue;
		snprintf(ts.places[ts.nplaces++], sizeof(ts.places[0]), "%s",
		    k);
	}
	ask();
	return (true);
}

bool
trouble_action(const char *act, const char *arg, const char *value)
{
	char	base[200];

	(void)value;
	if (strcmp(act, "select-trouble") == 0) {
		app.node = NODE_TROUBLE;
		app.jail[0] = '\0';
		app.rail_open = false;
		return (true);
	}
	if (strcmp(act, "ts-tab") == 0)
		return (true);
	if (strcmp(act, "ts-export") == 0 && ts.result != NULL) {
		snprintf(base, sizeof(base), "path-%s-to-%s", ts.src, ts.dst);
		for (char *p = base; *p != '\0'; p++)
			if (*p == ':' || *p == '/')
				*p = '-';
		export_save(base, ts.result, strcmp(arg, "yaml") == 0);
		return (true);
	}
	return (false);
}
