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

#include <sys/socket.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	char		 src[64], dst[64], proto[8], port[8];
	char		 places[64][80];	/* "sid" or "sid/jail" */
	int		 nplaces;		/* 0: every host */
	bool		 busy;
	unsigned	 asked;		/* the latest ask's number */
	char		 error[400];
	ucl_object_t	*result;
} ts = { .proto = "tcp" };

static void
path_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	/* An answer to an ask made before the latest is not shown: a swap
	 * pressed twice must not show the first's answer last. */
	if ((unsigned)(uintptr_t)arg != ts.asked)
		return;
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

/* Is it an address, and of which family: 4, 6, or 0 for neither. */
static int
family(const char *s)
{
	unsigned char	raw[16];

	if (inet_pton(AF_INET, s, raw) == 1)
		return (4);
	if (inet_pton(AF_INET6, s, raw) == 1)
		return (6);
	return (0);
}

static void
ask(void)
{
	ucl_object_t	*b, *pl, *p;
	char		*json, *slash, sid[16];
	int		 i, fs, fd;

	/* What is not an address is said here, not asked of every host. */
	fs = family(ts.src);
	fd = family(ts.dst);
	if (fs == 0 || fd == 0 || fs != fd) {
		snprintf(ts.error, sizeof(ts.error), "%s", fs == 0 ? "From is "
		    "not an IPv4 or IPv6 address" : fd == 0 ? "To is not an "
		    "IPv4 or IPv6 address" : "From and To are of two families: "
		    "a packet is IPv4 or IPv6 end to end");
		return;
	}

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
	api("POST", "/api/troubleshoot/path", json, path_cb, (void *)(uintptr_t)
	    ++ts.asked);
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


/* A firewall's verdict as a dot on the graph, its rule in the title. */
static void
dot(struct html *h, double x, double y, const char *where,
    const ucl_object_t *v)
{
	const char	*vd = jstr(v, "verdict");

	if (v == NULL || vd == NULL || strcmp(vd, "none") == 0)
		return;
	h_fmt(h, "<circle class=\"fw %s\" cx=\"%.0f\" cy=\"%.0f\" r=\"4\">"
	    "<title>", strcmp(vd, "deny") == 0 ? "bad" : strcmp(vd, "allow")
	    == 0 ? "good" : "warn", x, y);
	h_txt(h, where);
	h_raw(h, ": ");
	h_txt(h, strcmp(vd, "allow") == 0 ? (jbool(v, "by_state") ? "let by "
	    "its state" : "allowed") : strcmp(vd, "deny") == 0 ? "dropped" :
	    vd);
	if (jint(v, "rule", 0) != 0)
		h_fmt(h, " by rule %lld", (long long)jint(v, "rule", 0));
	if (jstr(v, "text") != NULL) {
		h_raw(h, "\n");
		h_txt(h, jstr(v, "text"));
	}
	h_raw(h, "</title></circle>");
}

#define	TS_BW	150		/* a place's box */
#define	TS_BH	50
#define	TS_COL	190		/* a column's pitch */
#define	TS_X0	170		/* the first column, after the source */

/* One place's box. */
static void
place_node(struct html *h, double x, double y, const ucl_object_t *hop,
    bool blocked_here)
{
	const ucl_object_t	*c = jget(hop, "check");
	char			 arg[120];

	snprintf(arg, sizeof(arg), "%s", jstr(hop, "key") != NULL ? jstr(hop,
	    "key") : "");
	h_fmt(h, "<g class=\"tsnode%s%s\" transform=\"translate(%.0f,%.0f)\" "
	    "data-act=\"ts-host\"", blocked_here ? " blocked" : "", jstr(hop,
	    "error") != NULL ? " dead" : "", x, y);
	h_attr(h, "data-arg", arg);
	h_fmt(h, "><rect width=\"%d\" height=\"%d\" rx=\"8\"/><text class=\""
	    "name\" x=\"8\" y=\"17\">", TS_BW, TS_BH);
	h_txt(h, jstr(hop, "place"));
	h_raw(h, "</text><text class=\"sub\" x=\"8\" y=\"33\">");
	if (jstr(hop, "error") != NULL)
		h_txt(h, "did not answer");
	else {
		h_txt(h, jstr(hop, "ingress") != NULL ? jstr(hop, "ingress") :
		    jbool(c, "src.local") ? "made here" : "?");
		h_raw(h, " → ");
		h_txt(h, jbool(c, "dst.local") ? "here" : jstr(hop, "egress") !=
		    NULL ? jstr(hop, "egress") : "no route");
	}
	h_raw(h, "</text>");
	if (jget(c, "fib") != NULL)
		h_fmt(h, "<text class=\"sub\" x=\"%d\" y=\"33\" text-anchor=\""
		    "end\">FIB %lld</text>", TS_BW - 8, (long long)jint(c, "fib",
		    0));
	dot(h, 8, TS_BH - 6, "firewall in", jget(c, "firewall.in"));
	dot(h, 20, TS_BH - 6, "firewall out", jget(c, "firewall.out"));
	if (jget(c, "return.symmetric") != NULL && !jbool(c, "return.symmetric"))
		h_fmt(h, "<text class=\"asym\" x=\"%d\" y=\"%d\" text-anchor=\""
		    "end\"><title>The reply goes back by another interface "
		    "than the request came in on</title>asymmetric</text>",
		    TS_BW - 8, TS_BH - 3);
	h_raw(h, "</g>");
}

/* An arrow from one column to the next, what it carries written on it. */
static void
arrow(struct html *h, double x1, double x2, double y, bool reply,
    const char *label, const char *cls)
{

	h_fmt(h, "<path class=\"way %s%s\" d=\"M%.0f %.0fL%.0f %.0f\" "
	    "marker-end=\"url(#tsarrow%s)\"/>", reply ? "reply" : "", cls,
	    x1, y, x2, y, cls[0] != '\0' ? cls : "");
	if (label != NULL && label[0] != '\0') {
		h_fmt(h, "<text class=\"lbl\" x=\"%.0f\" y=\"%.0f\" text-anchor="
		    "\"middle\">", (x1 + x2) / 2, y - 5);
		h_txt(h, label);
		h_raw(h, "</text>");
	}
}

/*
 * The way drawn: the source at the left, the destination at the right,
 * the request's places as boxes left to right above, the reply's as
 * boxes right to left below, each row in the order its packet goes,
 * so that a reply that takes another way reads as it is.  Where either
 * is stopped, a bar; where it leaves the hosts asked, a dotted arrow
 * on, with the next hop.
 */
static void
path_graph(struct html *h, const ucl_object_t *r)
{
	const ucl_object_t	*hops = jget(r, "hops"), *ret = jget(r, "return");
	const ucl_object_t	*hop, *end = jget(r, "end"), *rend = jget(r,
	    "return_end");
	ucl_object_iter_t	 it;
	const char		*how;
	int			 nf, nr, ncol, i;
	double			 w, y1, y2, ym, x, xp, xdst, xsrc;

	nf = (int)ucl_array_size(hops);
	nr = (int)ucl_array_size(ret);
	if (nf == 0)
		return;
	ncol = nf > nr ? nf : nr;
	w = TS_X0 + ncol * TS_COL + 170;
	y1 = 24;
	y2 = nr > 0 ? y1 + TS_BH + 50 : y1;
	ym = y1 + (y2 - y1) / 2;
	xsrc = 102;
	xdst = TS_X0 + ncol * TS_COL + 50;
	h_fmt(h, "<div class=\"tsgraph-wrap\"><svg class=\"tsgraph\" viewBox=\""
	    "0 0 %.0f %.0f\" role=\"img\" aria-label=\"The packet's way, and "
	    "its reply's\"><defs><marker id=\"tsarrow\" viewBox=\"0 0 8 8\" "
	    "refX=\"7\" refY=\"4\" markerWidth=\"7\" markerHeight=\"7\" orient="
	    "\"auto\"><path d=\"M0 0L8 4L0 8z\"/></marker><marker id=\""
	    "tsarrowbad\" viewBox=\"0 0 8 8\" refX=\"4\" refY=\"4\" markerWidth="
	    "\"8\" markerHeight=\"8\" orient=\"auto\"><path d=\"M3 0h2v8h-2z\"/>"
	    "</marker></defs>", w, y2 + TS_BH + 24);
	/* The ends, between the two rows. */
	h_fmt(h, "<g class=\"tsend src\" transform=\"translate(8,%.0f)\"><rect "
	    "width=\"94\" height=\"%d\" rx=\"%d\"/><text x=\"47\" y=\"%d\" "
	    "text-anchor=\"middle\">", ym, TS_BH, TS_BH / 2, TS_BH / 2 + 4);
	h_txt(h, ts.src);
	h_raw(h, "</text></g>");
	h_fmt(h, "<g class=\"tsend dst\" transform=\"translate(%.0f,%.0f)\">"
	    "<rect width=\"94\" height=\"%d\" rx=\"%d\"/><text x=\"47\" y=\"%d\" "
	    "text-anchor=\"middle\">", xdst, ym, TS_BH, TS_BH / 2, TS_BH / 2 + 4);
	h_txt(h, ts.dst);
	h_raw(h, "</text></g>");
	/* The request: left to right. */
	how = jstr(end, "how") != NULL ? jstr(end, "how") : "";
	xp = xsrc;
	it = NULL;
	for (i = 0; (hop = ucl_object_iterate(hops, &it, true)) != NULL; i++) {
		x = TS_X0 + i * TS_COL;
		arrow(h, xp, x, y1 + TS_BH / 2, false, i == 0 ? jstr(hop,
		    "ingress") : NULL, "");
		place_node(h, x, y1, hop, i == nf - 1 && (strcmp(how, "blocked")
		    == 0 || strcmp(how, "loop") == 0 || strcmp(how, "unknown")
		    == 0));
		xp = x + TS_BW;
	}
	if (strcmp(how, "delivered") == 0)
		arrow(h, xp, xdst, y1 + TS_BH / 2, false, NULL, "");
	else if (strcmp(how, "leaves") == 0)
		arrow(h, xp, xdst, y1 + TS_BH / 2, false, jstr(
		    ucl_array_find_index(hops, (unsigned)nf - 1), "next_hop"),
		    "leaves");
	else
		arrow(h, xp, xp + 24, y1 + TS_BH / 2, false, NULL, "bad");
	if (nr == 0) {
		h_raw(h, "</svg></div>");
		return;
	}
	/* The reply: from the destination's side, right to left, a slot
	 * each in the order it goes. */
	how = jstr(rend, "how") != NULL ? jstr(rend, "how") : "";
	xp = xdst;
	it = NULL;
	for (i = 0; (hop = ucl_object_iterate(ret, &it, true)) != NULL; i++) {
		x = TS_X0 + (ncol - 1 - i) * TS_COL;
		arrow(h, xp, x + TS_BW, y2 + TS_BH / 2, true, i == 0 ? jstr(hop,
		    "ingress") : NULL, "");
		place_node(h, x, y2, hop, i == nr - 1 && strcmp(how,
		    "delivered") != 0 && strcmp(how, "leaves") != 0);
		xp = x;
	}
	if (strcmp(how, "delivered") == 0)
		arrow(h, xp, xsrc, y2 + TS_BH / 2, true, NULL, "");
	else if (strcmp(how, "leaves") == 0)
		arrow(h, xp, xsrc, y2 + TS_BH / 2, true, jstr(ucl_array_find_index(
		    ret, (unsigned)nr - 1), "next_hop"), "leaves");
	else
		arrow(h, xp, xp - 24, y2 + TS_BH / 2, true, NULL, "bad");
	h_raw(h, "</svg></div>");
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
	if (strcmp(sev, "bad") != 0 && jstr(r, "end.how") != NULL &&
	    strcmp(jstr(r, "end.how"), "unknown") == 0)
		sev = "warn";
	h_fmt(h, "<div class=\"tsverdict %s\">", sev);
	if (strcmp(sev, "bad") == 0) {
		h_raw(h, "<b>Stopped");
		if (jstr(f, "place") != NULL) {
			h_raw(h, " at ");
			h_txt(h, jstr(f, "place"));
		}
		h_raw(h, ":</b> ");
		h_txt(h, jstr(f, "what"));
	} else if (jstr(r, "end.how") != NULL && strcmp(jstr(r, "end.how"),
	    "unknown") == 0) {
		/* Not followed: nothing found is not nothing there. */
		h_raw(h, "<b>Could not follow it.</b> ");
		h_txt(h, jstr(r, "end.what"));
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
		/* A firewall's finding: its rule, a press away. */
		if (jstr(f, "server") != NULL && strstr(jstr(f, "what"),
		    "firewall") != NULL) {
			const char	*rule = strstr(jstr(f, "what"), "rule ");
			char		 arg[120];

			snprintf(arg, sizeof(arg), "%s/%s/%ld", jstr(f, "server"),
			    jstr(f, "jail") != NULL ? jstr(f, "jail") : "", rule !=
			    NULL ? strtol(rule + 5, NULL, 10) : 0L);
			h_raw(h, " <button class=\"ghost small\" data-act=\""
			    "ts-firewall\"");
			h_attr(h, "data-arg", arg);
			h_raw(h, ">Its firewall ›</button>");
		}
		h_raw(h, "</li>");
	}
	h_raw(h, "</ul>");
	path_graph(h, r);
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
	topo_addr_list(h, "ts-addrs");
	h_fmt(h, "<form class=\"tsform\" data-form=\"ts-path\" id=\"ts-path\">"
	    "<div class=\"two\"><label>From<input name=\"src\" required "
	    "placeholder=\"10.1.0.2\" maxlength=\"63\" list=\"ts-addrs\" "
	    "spellcheck=\"false\" autocomplete=\"off\"");
	h_attr(h, "value", ts.src);
	h_raw(h, "></label><label><span class=\"lblrow\">To<button type=\""
	    "button\" class=\"ghost small swap\" data-act=\"ts-swap\" title="
	    "\"The other way round: from the destination to the source\"><svg "
	    "class=\"ti\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d="
	    "\"M7 7h12l-3-3M17 17H5l3 3\"/></svg> swap</button></span><input "
	    "name=\"dst\" required placeholder=\"10.3.0.2\" maxlength=\"63\" "
	    "list=\"ts-addrs\" spellcheck=\"false\" autocomplete=\"off\"");
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
		/* The hosts' addresses, to offer. */
		topo_poll_all();
		return (true);
	}
	if (strcmp(act, "ts-tab") == 0)
		return (true);
	if (strcmp(act, "ts-swap") == 0) {
		char	t[sizeof(ts.src)];

		snprintf(t, sizeof(t), "%s", ts.src);
		snprintf(ts.src, sizeof(ts.src), "%s", ts.dst);
		snprintf(ts.dst, sizeof(ts.dst), "%s", t);
		if (ts.src[0] != '\0' && ts.dst[0] != '\0')
			ask();
		return (true);
	}
	/* A place on the graph: its host's page, its jail's. */
	if (strcmp(act, "ts-host") == 0 || strcmp(act, "ts-firewall") == 0) {
		char	sid[16], jail[64], *p;
		long	rule;

		snprintf(sid, sizeof(sid), "%.*s", (int)strcspn(arg, "/"), arg);
		p = strchr(arg, '/');
		snprintf(jail, sizeof(jail), "%.*s", p != NULL ? (int)strcspn(
		    p + 1, "/") : 0, p != NULL ? p + 1 : "");
		rule = p != NULL && (p = strchr(p + 1, '/')) != NULL ? strtol(
		    p + 1, NULL, 10) : 0;
		dispatch("select-server", sid, "");
		if (strcmp(act, "ts-firewall") == 0) {
			dispatch("tab", "firewall", "");
			dispatch("fw-jail", jail, "");
			if (rule > 0) {
				char	num[16];

				snprintf(num, sizeof(num), "%ld", rule);
				dispatch("fw-goto", num, "");
			}
		} else if (jail[0] != '\0')
			dispatch("open-jail", jail, sid);
		return (true);
	}
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

/* The page's address, with what is asked. */
void
trouble_loc(char *buf, size_t len)
{
	char	src[200], dst[200];

	if (ts.src[0] == '\0' || ts.dst[0] == '\0') {
		snprintf(buf, len, "#/troubleshoot");
		return;
	}
	loc_enc(src, sizeof(src), ts.src);
	loc_enc(dst, sizeof(dst), ts.dst);
	snprintf(buf, len, "#/troubleshoot?src=%s&dst=%s&proto=%s&port=%s", src,
	    dst, ts.proto, ts.port);
}

/* Opened at an address naming a packet: asked at once. */
void
trouble_open(const char *query)
{
	char	buf[512], *p, *q, *v, val[200];

	if (query == NULL || *query == '\0')
		return;
	snprintf(buf, sizeof(buf), "%s", query);
	for (p = buf; p != NULL && *p != '\0'; p = q) {
		if ((q = strchr(p, '&')) != NULL)
			*q++ = '\0';
		if ((v = strchr(p, '=')) == NULL)
			continue;
		*v++ = '\0';
		loc_dec(val, sizeof(val), v);
		if (strcmp(p, "src") == 0)
			snprintf(ts.src, sizeof(ts.src), "%s", val);
		else if (strcmp(p, "dst") == 0)
			snprintf(ts.dst, sizeof(ts.dst), "%s", val);
		else if (strcmp(p, "proto") == 0 && (strcmp(val, "tcp") == 0 ||
		    strcmp(val, "udp") == 0 || strcmp(val, "icmp") == 0 ||
		    strcmp(val, "ip") == 0))
			snprintf(ts.proto, sizeof(ts.proto), "%s", val);
		else if (strcmp(p, "port") == 0)
			snprintf(ts.port, sizeof(ts.port), "%.5s", val[strspn(
			    val, "0123456789")] == '\0' ? val : "");
	}
	if (ts.src[0] != '\0' && ts.dst[0] != '\0' && !ts.busy)
		ask();
}
