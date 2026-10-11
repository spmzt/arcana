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

#include <math.h>

#include "app.h"

#define	nitems(x)	(sizeof(x) / sizeof((x)[0]))

enum { SD_OVERVIEW, SD_SERVICES, SD_EDGES, SD_PATHS, SD_DOCUMENT };

#define	PATHS_EVERY_MS	2000	/* the probes read again, on the Paths tab */
#define	DASH_EVERY_MS	5000	/* and on the dashboard */
#define	SPARK_N		120	/* samples a spark line shows */

static const ucl_object_t *target_of(const char *, const char *);
static void	 paths_load(void);
static void	 plan_load(void);
static void	 applied_cb(int, const ucl_object_t *, const char *, void *);
static const char *ms(double, char *, size_t);
static void	 view_overview(struct html *);

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
	ucl_object_t	*paths;		/* sid: /api/servers/<sid>/sdwan data */
	ucl_object_t	*faults;	/* sid: the sdwan-tunnel events */
	double		 paths_at;
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
	if (sd.tab == SD_OVERVIEW)
		plan_load();
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
	/* The dashboard and Paths want the probes as soon as the plan
	 * says which edges to ask. */
	if (app.node == NODE_SDWAN && (sd.tab == SD_OVERVIEW || sd.tab ==
	    SD_PATHS))
		paths_load();
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

/* What one edge's probes have seen, under its id. */
static void
paths_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid = arg;

	(void)err;
	if (status == 200 && jget(o, "data") != NULL) {
		if (sd.paths == NULL)
			sd.paths = ucl_object_typed_new(UCL_OBJECT);
		(void)ucl_object_delete_key(sd.paths, sid);
		ucl_object_insert_key(sd.paths, ucl_object_copy(jget(o,
		    "data")), sid, 0, true);
	}
	free(sid);
}

static void
faults_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char			*sid = arg;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*mine;

	(void)err;
	if (status == 200) {
		if (sd.faults == NULL)
			sd.faults = ucl_object_typed_new(UCL_OBJECT);
		mine = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((e = ucl_object_iterate(jget(o, "events"), &it, true)) !=
		    NULL)
			if (jstr(e, "kind") != NULL && strcmp(jstr(e, "kind"),
			    "sdwan-tunnel") == 0)
				ucl_array_append(mine, ucl_object_copy(e));
		(void)ucl_object_delete_key(sd.faults, sid);
		ucl_object_insert_key(sd.faults, mine, sid, 0, true);
	}
	free(sid);
}

/* Every edge of the plan's tunnels asked what its probes saw. */
static void
paths_load(void)
{
	const ucl_object_t	*t, *e;
	ucl_object_iter_t	 it, eit;
	ucl_object_t		*asked;
	char			 url[96];

	sd.paths_at = arc_now();
	if (sd.plan == NULL) {
		api("GET", "/api/sdwan/plan", NULL, plan_cb, NULL);
		return;
	}
	asked = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while ((t = ucl_object_iterate(jget(sd.plan, "tunnels"), &it, true)) !=
	    NULL) {
		eit = NULL;
		while ((e = ucl_object_iterate(jget(t, "ends"), &eit, true)) !=
		    NULL) {
			if (jstr(e, "edge") == NULL || ucl_object_lookup(asked,
			    jstr(e, "edge")) != NULL)
				continue;
			ucl_object_insert_key(asked, ucl_object_frombool(true),
			    jstr(e, "edge"), 0, true);
			snprintf(url, sizeof(url), "/api/servers/%s/sdwan",
			    jstr(e, "edge"));
			api("GET", url, NULL, paths_cb, strdup(jstr(e, "edge")));
			snprintf(url, sizeof(url), "/api/servers/%s/events",
			    jstr(e, "edge"));
			api("GET", url, NULL, faults_cb, strdup(jstr(e, "edge")));
		}
	}
	ucl_object_unref(asked);
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

/* A tunnel's state from its two ends' probes: up, down, or unknown. */
static const char *
tunnel_state(const ucl_object_t *t, double *delay, double *loss)
{
	const ucl_object_t	*e, *tg, *sm, *now;
	unsigned int		 n;
	int			 k, up, down;

	up = down = 0;
	*delay = -1;
	*loss = 0;
	for (k = 0; k < 2; k++) {
		e = ucl_array_find_index(jget(t, "ends"), (unsigned int)k);
		if ((tg = target_of(jstr(e, "edge"), jstr(t, "id"))) == NULL ||
		    jstr(tg, "state") == NULL)
			continue;
		if (strcmp(jstr(tg, "state"), "up") == 0)
			up++;
		else if (strcmp(jstr(tg, "state"), "down") == 0)
			down++;
		n = jget(tg, "samples") != NULL ? ucl_array_size(jget(tg,
		    "samples")) : 0;
		sm = n > 0 ? ucl_array_find_index(jget(tg, "samples"), n - 1) :
		    NULL;
		now = jget(tg, "now");
		if (sm != NULL) {
			if (ucl_object_todouble(ucl_array_find_index(sm, 1)) >
			    *delay)
				*delay = ucl_object_todouble(ucl_array_find_index(
				    sm, 1));
			if (ucl_object_todouble(ucl_array_find_index(sm, 3)) >
			    *loss)
				*loss = ucl_object_todouble(ucl_array_find_index(
				    sm, 3));
		} else if (now != NULL && jint(now, "sent", 0) > 0 && jnum(now,
		    "delay", 0) > *delay)
			*delay = jnum(now, "delay", 0);
	}
	return (down > 0 ? "down" : up == 2 ? "up" : up == 1 ? "half" :
	    "unknown");
}

/*
 * The dashboard: what there is and how it is, in numbers; the edges
 * and their tunnels drawn, each tunnel as its probes see it; then the
 * underlays, edges and services listed.  Every number names the
 * FreeBSD piece that does the work.
 */
static void
view_dashboard(struct html *h)
{
	const ucl_object_t	*v, *e, *t, *ap, *s, *f;
	ucl_object_iter_t	 it, eit;
	const char		*st;
	char			 age[32], b1[32];
	double			 delay, loss, cx, cy, r, ang, x[64], y[64];
	int			 nedges, nlinks, nucs, nsw, nfibs, nt, tup, tdown;
	int			 nfaults, ndone, nsteps, i, k, a, b, prev;

	nedges = nlinks = nucs = nsw = nfibs = nt = tup = tdown = 0;
	it = NULL;
	while ((v = ucl_object_iterate(jget(sd.doc, "ucs"), &it, true)) !=
	    NULL)
		nucs++;
	it = NULL;
	while ((v = ucl_object_iterate(jget(sd.doc, "edges"), &it, true)) !=
	    NULL) {
		if (nedges < 64) {
			nedges++;
			eit = NULL;
			while ((e = ucl_object_iterate(jget(v, "ucs_end_points"),
			    &eit, true)) != NULL)
				nlinks++;
		}
	}
	it = NULL;
	while ((v = ucl_object_iterate(jget(sd.doc, "swvcs"), &it, true)) !=
	    NULL) {
		nsw++;
		if (jint(v, "fib", 0) > nfibs)
			nfibs = (int)jint(v, "fib", 0);
	}
	it = NULL;
	while (sd.plan != NULL && (t = ucl_object_iterate(jget(sd.plan,
	    "tunnels"), &it, true)) != NULL) {
		nt++;
		st = tunnel_state(t, &delay, &loss);
		if (strcmp(st, "up") == 0)
			tup++;
		else if (strcmp(st, "down") == 0)
			tdown++;
	}
	nfaults = 0;
	it = NULL;
	while (sd.faults != NULL && (f = ucl_object_iterate(sd.faults, &it,
	    true)) != NULL) {
		eit = NULL;
		while ((e = ucl_object_iterate(f, &eit, true)) != NULL)
			if ((double)jint(e, "t", 0) * 1000 > arc_now() - 86400 *
			    1000.0)
				nfaults++;
	}
	ap = jget(sd.applied, "apply");
	ndone = nsteps = 0;
	it = NULL;
	while (ap != NULL && (s = ucl_object_iterate(jget(ap, "steps"), &it,
	    true)) != NULL) {
		nsteps++;
		if (jstr(s, "state") != NULL && strcmp(jstr(s, "state"), "done")
		    == 0)
			ndone++;
	}
	h_raw(h, "<div class=\"tiles sd-tiles\">");
	h_fmt(h, "<div class=\"tile\"><b>%d</b><span>edge%s · FreeBSD hosts "
	    "running arcana-agent</span></div>", nedges, nedges == 1 ? "" : "s");
	h_fmt(h, "<div class=\"tile\"><b>%d</b><span>WAN link%s on %d "
	    "underlay%s · the edges' interfaces</span></div>", nlinks, nlinks ==
	    1 ? "" : "s", nucs, nucs == 1 ? "" : "s");
	h_fmt(h, "<div class=\"tile %s\"><b>%d</b><span>service%s · a routing "
	    "table each, setfib(1), up to fib %d</span></div>", nsw > 0 ? "ok" :
	    "", nsw, nsw == 1 ? "" : "s", nfibs);
	h_fmt(h, "<div class=\"tile %s\"><b>%d</b><span>tunnel%s · %d up, %d "
	    "down · gre, gif, geneve, wg; IPsec by strongSwan</span></div>",
	    tdown > 0 ? "warn" : nt > 0 && tup == nt ? "ok" : "", nt, nt == 1 ?
	    "" : "s", tup, tdown);
	h_fmt(h, "<div class=\"tile %s\"><b>%d</b><span>fault%s in 24 h · "
	    "tunnels down or up again</span></div>", nfaults > 0 ? "warn" : "",
	    nfaults, nfaults == 1 ? "" : "s");
	if (ap != NULL && jstr(ap, "state") != NULL) {
		fmt_age(age, sizeof(age), (double)jint(ap, "started", 0) * 1000);
		h_fmt(h, "<div class=\"tile %s\"><b>%s</b><span>last apply, %s · "
		    "%d of %d steps · ipfw set %d, routes, interfaces</span>"
		    "</div>", strcmp(jstr(ap, "state"), "done") == 0 ? "ok" :
		    "warn", sd.applying ? "applying" : jstr(ap, "state"), age,
		    ndone, nsteps, 30);
	} else
		h_raw(h, "<div class=\"tile\"><b>—</b><span>not applied yet · "
		    "Edges, then Apply</span></div>");
	h_raw(h, "</div>");

	/* The topology: edges around a circle, tunnels between them. */
	if (nedges > 0) {
		h_raw(h, "<div class=\"sd-block\"><h3>Topology <small class=\""
		    "dim\">the edges and the tunnels between them, each as its "
		    "probes see it: green up, red down, dashed a backup, a lock "
		    "encrypted</small></h3><div class=\"sd-topo-wrap\"><svg "
		    "class=\"sd-topo\" viewBox=\"0 0 640 300\" role=\"img\">");
		cx = 320;
		cy = 150;
		r = nedges > 2 ? 110 : 0;
		i = 0;
		it = NULL;
		while ((v = ucl_object_iterate(jget(sd.doc, "edges"), &it, true))
		    != NULL && i < nedges) {
			if (nedges == 1) {
				x[i] = cx;
				y[i] = cy;
			} else if (nedges == 2) {
				x[i] = i == 0 ? 160 : 480;
				y[i] = cy;
			} else {
				ang = -M_PI / 2 + 2 * M_PI * i / nedges;
				x[i] = cx + r * cos(ang);
				y[i] = cy + r * sin(ang);
			}
			i++;
		}
		/* The tunnels first, under the nodes; a pair's second and
		 * later bow out a little. */
		prev = -1;
		it = NULL;
		while (sd.plan != NULL && (t = ucl_object_iterate(jget(sd.plan,
		    "tunnels"), &it, true)) != NULL) {
			const ucl_object_t	*ea, *eb;
			double			 mx, my, dx, dy, len, ox, oy;

			ea = ucl_array_find_index(jget(t, "ends"), 0);
			eb = ucl_array_find_index(jget(t, "ends"), 1);
			a = b = -1;
			i = 0;
			eit = NULL;
			while ((v = ucl_object_iterate(jget(sd.doc, "edges"),
			    &eit, true)) != NULL && i < nedges) {
				if (jstr(v, "server") != NULL && jstr(ea, "edge")
				    != NULL && strcmp(jstr(v, "server"), jstr(ea,
				    "edge")) == 0)
					a = i;
				if (jstr(v, "server") != NULL && jstr(eb, "edge")
				    != NULL && strcmp(jstr(v, "server"), jstr(eb,
				    "edge")) == 0)
					b = i;
				i++;
			}
			if (a < 0 || b < 0)
				continue;
			st = tunnel_state(t, &delay, &loss);
			k = a * 64 + b;
			prev = prev == k ? prev : -1;
			mx = (x[a] + x[b]) / 2;
			my = (y[a] + y[b]) / 2;
			dx = x[b] - x[a];
			dy = y[b] - y[a];
			len = sqrt(dx * dx + dy * dy);
			ox = len > 0 ? -dy / len * 22 : 0;
			oy = len > 0 ? dx / len * 22 : 0;
			/* Count the tunnels of this pair seen so far. */
			{
				const ucl_object_t	*t2;
				ucl_object_iter_t	 it2 = NULL;
				int			 same = 0;

				while ((t2 = ucl_object_iterate(jget(sd.plan,
				    "tunnels"), &it2, true)) != NULL && t2 != t) {
					const ucl_object_t *fa = ucl_array_find_index(
					    jget(t2, "ends"), 0);
					const ucl_object_t *fb = ucl_array_find_index(
					    jget(t2, "ends"), 1);

					if (jstr(fa, "edge") != NULL && jstr(fb,
					    "edge") != NULL && ((strcmp(jstr(fa,
					    "edge"), jstr(ea, "edge")) == 0 &&
					    strcmp(jstr(fb, "edge"), jstr(eb,
					    "edge")) == 0) || (strcmp(jstr(fa,
					    "edge"), jstr(eb, "edge")) == 0 &&
					    strcmp(jstr(fb, "edge"), jstr(ea,
					    "edge")) == 0)))
						same++;
				}
				ox *= same % 2 == 0 ? same / 2 : -(same + 1) / 2;
				oy *= same % 2 == 0 ? same / 2 : -(same + 1) / 2;
			}
			h_fmt(h, "<g class=\"tun st-%s%s\"><title>", st, jbool(t,
			    "backup") ? " backup" : "");
			h_txt(h, jstr(t, "id"));
			h_fmt(h, ": %s%s%s", st, delay >= 0 ? ", " : "", delay >= 0
			    ? ms(delay, b1, sizeof(b1)) : "");
			if (loss > 0)
				h_fmt(h, ", %.1f%% loss", loss * 100);
			h_fmt(h, "</title><path d=\"M%.0f %.0f Q%.0f %.0f %.0f "
			    "%.0f\"/>", x[a], y[a], mx + ox * 2, my + oy * 2, x[b],
			    y[b]);
			if (jbool(t, "encrypted"))
				h_fmt(h, "<text class=\"lock\" x=\"%.0f\" y=\"%.0f\">"
				    "&#x1F512;</text>", mx + ox - 16, my + oy + 4);
			if (delay >= 0)
				h_fmt(h, "<text class=\"lbl\" x=\"%.0f\" y=\"%.0f\">"
				    "%s%s</text>", mx + ox, my + oy + 4, ms(delay,
				    b1, sizeof(b1)), loss > 0 ? " · loss" : "");
			else
				h_fmt(h, "<text class=\"lbl\" x=\"%.0f\" y=\"%.0f\">"
				    "%s</text>", mx + ox, my + oy + 4, strcmp(st,
				    "unknown") == 0 ? "not measured" : st);
			h_raw(h, "</g>");
		}
		/* Before a plan: the pairs each service joins, as planned. */
		if (sd.plan == NULL || jget(sd.plan, "tunnels") == NULL ||
		    ucl_array_size(jget(sd.plan, "tunnels")) == 0) {
			const ucl_object_t	*sw, *ea, *eb;
			ucl_object_iter_t	 sit, ait, bit;

			sit = NULL;
			while ((sw = ucl_object_iterate(jget(sd.doc, "swvcs"),
			    &sit, true)) != NULL) {
				ait = NULL;
				while ((ea = ucl_object_iterate(jget(sw,
				    "end_points"), &ait, true)) != NULL) {
					bit = NULL;
					while ((eb = ucl_object_iterate(jget(sw,
					    "end_points"), &bit, true)) != NULL) {
						if (eb == ea || jstr(ea, "edge") ==
						    NULL || jstr(eb, "edge") == NULL
						    || strcmp(jstr(ea, "edge"),
						    jstr(eb, "edge")) >= 0)
							continue;
						a = b = -1;
						i = 0;
						eit = NULL;
						while ((v = ucl_object_iterate(jget(
						    sd.doc, "edges"), &eit, true)) !=
						    NULL && i < nedges) {
							if (strcmp(jstr(v, "server"),
							    jstr(ea, "edge")) == 0)
								a = i;
							if (strcmp(jstr(v, "server"),
							    jstr(eb, "edge")) == 0)
								b = i;
							i++;
						}
						if (a < 0 || b < 0)
							continue;
						h_fmt(h, "<g class=\"tun st-unknown\">"
						    "<title>%s: planned</title><path "
						    "d=\"M%.0f %.0f L%.0f %.0f\"/><text "
						    "class=\"lbl\" x=\"%.0f\" y=\"%.0f\">"
						    "planned</text></g>", jstr(sw, "id"),
						    x[a], y[a], x[b], y[b], (x[a] +
						    x[b]) / 2, (y[a] + y[b]) / 2 - 6);
					}
				}
			}
		}
		i = 0;
		it = NULL;
		while ((v = ucl_object_iterate(jget(sd.doc, "edges"), &it, true))
		    != NULL && i < nedges) {
			int	nl = 0, nbo = 0;

			eit = NULL;
			while ((e = ucl_object_iterate(jget(v, "ucs_end_points"),
			    &eit, true)) != NULL) {
				nl++;
				if (jbool(e, "breakout"))
					nbo++;
			}
			h_fmt(h, "<g class=\"node\" transform=\"translate(%.0f "
			    "%.0f)\"><title>", x[i], y[i]);
			h_txt(h, host_name(jstr(v, "server")));
			h_fmt(h, ": %d WAN link%s%s</title><circle r=\"22\"/>"
			    "<text class=\"name\" y=\"4\">", nl, nl == 1 ? "" :
			    "s", nbo > 0 ? ", breaks out" : "");
			h_txt(h, host_name(jstr(v, "server")));
			h_fmt(h, "</text><text class=\"sub\" y=\"36\">%d link%s%s"
			    "</text></g>", nl, nl == 1 ? "" : "s", nbo > 0 ?
			    " · breakout" : "");
			i++;
		}
		h_raw(h, "</svg></div></div>");
	} else
		h_raw(h, "<div class=\"sd-block sd-start\"><h3>Start here</h3><ol>"
		    "<li><b>Underlays</b>: the carriers the edges reach each "
		    "other over, public or private, and the tunnel each "
		    "carries.</li><li><b>Edges</b>: the FreeBSD hosts, and the "
		    "interface each has on each underlay.</li><li><b>A service"
		    "</b>: its UNIs, zones, application flows and policies.</li>"
		    "<li><b>Edges, Apply</b>: the console plans what each host "
		    "is to have and makes it.</li></ol><p class=\"dim\">The "
		    "example in <b>Document</b> has all four, written for the "
		    "first two hosts.</p></div>");
	view_overview(h);
}

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
	/* What the plan leaves out, and why. */
	{
		const ucl_object_t	*n;
		ucl_object_iter_t	 nit;

		nit = NULL;
		while ((n = ucl_object_iterate(jget(sd.plan, "notes"), &nit,
		    true)) != NULL) {
			h_raw(h, "<div class=\"notice warn\">");
			h_txt(h, ucl_object_tostring_forced(n));
			h_raw(h, "</div>");
		}
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

/* ---- The paths: what the probes see of each tunnel ------------------- */

/* The target an edge probes for a tunnel: its id is the tunnel's. */
static const ucl_object_t *
target_of(const char *sid, const char *tid)
{
	const ucl_object_t	*t;
	ucl_object_iter_t	 it;

	if (sd.paths == NULL || sid == NULL)
		return (NULL);
	it = NULL;
	while ((t = ucl_object_iterate(jget(jget(sd.paths, sid), "targets"),
	    &it, true)) != NULL)
		if (jstr(t, "id") != NULL && strcmp(jstr(t, "id"), tid) == 0)
			return (t);
	return (NULL);
}

static const char *
ms(double v, char *buf, size_t len)
{

	snprintf(buf, len, v >= 100 ? "%.0f ms" : v >= 10 ? "%.1f ms" :
	    "%.2f ms", v);
	return (buf);
}

/* The last samples' delay as a line, loss as marks under it. */
static void
spark(struct html *h, const ucl_object_t *samples)
{
	const ucl_object_t	*s;
	double			 max, v, loss;
	unsigned int		 n, from, i;

	n = samples != NULL ? ucl_array_size(samples) : 0;
	if (n == 0) {
		h_raw(h, "<span class=\"dim\">no sample yet</span>");
		return;
	}
	from = n > SPARK_N ? n - SPARK_N : 0;
	max = 0;
	for (i = from; i < n; i++) {
		s = ucl_array_find_index(samples, i);
		v = ucl_object_todouble(ucl_array_find_index(s, 5));
		if (v > max)
			max = v;
	}
	if (max <= 0)
		max = 1;
	h_fmt(h, "<svg class=\"spark\" viewBox=\"0 0 %d 24\" preserveAspectRatio="
	    "\"none\" aria-hidden=\"true\"><path d=\"", SPARK_N);
	for (i = from; i < n; i++) {
		s = ucl_array_find_index(samples, i);
		v = ucl_object_todouble(ucl_array_find_index(s, 1));
		h_fmt(h, "%c%u %.1f ", i == from ? 'M' : 'L', i - from, 22 -
		    v / max * 20);
	}
	h_raw(h, "\"/>");
	for (i = from; i < n; i++) {
		s = ucl_array_find_index(samples, i);
		loss = ucl_object_todouble(ucl_array_find_index(s, 3));
		if (loss > 0)
			h_fmt(h, "<rect class=\"loss\" x=\"%u\" y=\"22\" width=\"1\""
			    " height=\"2\"/>", i - from);
	}
	h_fmt(h, "</svg><small class=\"dim\">%u samples, up to %s</small>", n -
	    from, ms(max, (char[32]){ 0 }, 32));
}

static void
view_paths(struct html *h)
{
	const ucl_object_t	*t, *e, *tg, *now, *sm, *f, *d;
	ucl_object_iter_t	 it, eit, fit;
	const char		*st;
	char			 b1[32], b2[32], b3[32], age[32];
	unsigned int		 n;
	int			 k, nf;

	if (sd.plan == NULL) {
		h_raw(h, sd.plan_error[0] != '\0' ? "<div class=\"notice bad\">" :
		    "<div class=\"loader\"></div>");
		if (sd.plan_error[0] != '\0') {
			h_txt(h, sd.plan_error);
			h_raw(h, "</div>");
		}
		return;
	}
	h_raw(h, "<p class=\"dim\">Each edge pings the far end of each of its "
	    "tunnels through the service's table, as its probe settings say; "
	    "of each eval interval it keeps the one-way delay (half the round "
	    "trip), its variation, the loss, the least and the most. Read "
	    "every two seconds while this is open.</p>");
	it = NULL;
	while ((t = ucl_object_iterate(jget(sd.plan, "tunnels"), &it, true)) !=
	    NULL) {
		h_raw(h, "<div class=\"sd-block sd-path\"><h3><span class=\"mono"
		    "\">");
		h_txt(h, jstr(t, "id"));
		h_fmt(h, "</span> <small class=\"dim\">%s%s%s%s</small></h3>"
		    "<table class=\"net sd\"><thead><tr><th>From</th><th>State"
		    "</th><th>Delay</th><th>Variation</th><th>Loss</th><th>"
		    "Least / most</th><th>Probes</th><th>Last samples</th></tr>"
		    "</thead><tbody>", jstr(t, "kind"), jbool(t, "ipsec") ?
		    " + IPsec" : "", jbool(t, "public") ? ", public" : "",
		    jbool(t, "backup") ? ", backup" : "");
		for (k = 0; k < 2; k++) {
			e = ucl_array_find_index(jget(t, "ends"), (unsigned int)k);
			tg = target_of(jstr(e, "edge"), jstr(t, "id"));
			h_raw(h, "<tr><td><b>");
			h_txt(h, host_name(jstr(e, "edge")));
			h_raw(h, "</b> <span class=\"mono dim\">");
			h_txt(h, jstr(e, "ifname"));
			h_raw(h, "</span></td>");
			if (tg == NULL) {
				h_raw(h, "<td colspan=\"7\" class=\"dim\">not "
				    "probed: not applied, or not read yet</td>"
				    "</tr>");
				continue;
			}
			st = jstr(tg, "state") != NULL ? jstr(tg, "state") :
			    "unknown";
			fmt_age(age, sizeof(age), (double)jint(tg, "since", 0) *
			    1000);
			h_fmt(h, "<td><span class=\"chip st-%s\">%s</span> <small "
			    "class=\"dim\">", st, st);
			h_txt(h, age);
			h_raw(h, "</small>");
			if (jstr(tg, "error") != NULL) {
				h_raw(h, "<small class=\"bad\">");
				h_txt(h, jstr(tg, "error"));
				h_raw(h, "</small>");
			}
			/* The last whole sample, with the one in progress. */
			n = jget(tg, "samples") != NULL ? ucl_array_size(jget(tg,
			    "samples")) : 0;
			sm = n > 0 ? ucl_array_find_index(jget(tg, "samples"),
			    n - 1) : NULL;
			now = jget(tg, "now");
			if (sm != NULL) {
				h_fmt(h, "</td><td class=\"num\">%s</td><td "
				    "class=\"num\">%s</td><td class=\"num\">%.1f%%"
				    "</td><td class=\"num\">%s / %s</td>",
				    ms(ucl_object_todouble(ucl_array_find_index(
				    sm, 1)), b1, sizeof(b1)), ms(
				    ucl_object_todouble(ucl_array_find_index(sm,
				    2)), b2, sizeof(b2)), ucl_object_todouble(
				    ucl_array_find_index(sm, 3)) * 100, ms(
				    ucl_object_todouble(ucl_array_find_index(sm,
				    4)), b3, sizeof(b3)), ms(ucl_object_todouble(
				    ucl_array_find_index(sm, 5)), (char[32]){ 0 },
				    32));
			} else if (now != NULL && jint(now, "sent", 0) > 0) {
				h_fmt(h, "</td><td class=\"num\">%s</td><td "
				    "class=\"num\">%s</td><td class=\"num\">%.1f%%"
				    "</td><td class=\"dim\">so far</td>", ms(jnum(
				    now, "delay", 0), b1, sizeof(b1)), ms(jnum(now,
				    "ipdv", 0), b2, sizeof(b2)), jnum(now, "loss",
				    0) * 100);
			} else
				h_raw(h, "</td><td class=\"dim\" colspan=\"4\">"
				    "nothing yet</td>");
			h_fmt(h, "<td class=\"num\">%lld / %lld</td><td>",
			    (long long)jint(tg, "received", 0), (long long)jint(
			    tg, "sent", 0));
			spark(h, jget(tg, "samples"));
			h_raw(h, "</td></tr>");
		}
		h_raw(h, "</tbody></table></div>");
	}
	if (jget(sd.plan, "tunnels") == NULL || ucl_array_size(jget(sd.plan,
	    "tunnels")) == 0)
		h_raw(h, "<p class=\"dim\">No tunnel: a service with end points "
		    "on two edges or more has them.</p>");
	/* The steering: each edge's far prefixes, by which tunnel each goes
	 * now, and the others in the order the console gave. */
	h_raw(h, "<div class=\"sd-block\"><h3>Steering <small class=\"dim\">"
	    "each far prefix by the first tunnel of its policy's order that "
	    "is not down, chosen on the edge; the order is the console's, by "
	    "the policy's performance criteria</small></h3><table class=\"net "
	    "sd\"><thead><tr><th>Edge</th><th>Prefix</th><th>Policy</th><th>"
	    "Goes by</th><th>Then</th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while (sd.paths != NULL && (f = ucl_object_iterate(sd.paths, &it,
	    true)) != NULL) {
		fit = NULL;
		while ((e = ucl_object_iterate(jget(f, "steer"), &fit, true)) !=
		    NULL) {
			const ucl_object_t	*c;
			ucl_object_iter_t	 cit;
			long long		 chosen;
			int			 i;

			n++;
			chosen = jint(e, "chosen", -1);
			h_raw(h, "<tr><td><b>");
			h_txt(h, host_name(ucl_object_key(f)));
			h_raw(h, "</b></td><td class=\"mono\">");
			h_txt(h, jstr(e, "prefix"));
			h_raw(h, "</td><td class=\"mono dim\">");
			h_txt(h, jstr(e, "table") != NULL ? jstr(e, "table") : "");
			h_raw(h, "</td><td>");
			if (chosen < 0)
				h_raw(h, "<span class=\"chip st-down\">no tunnel "
				    "up</span>");
			h_raw(h, "</td><td class=\"dim\">");
			i = 0;
			cit = NULL;
			while ((c = ucl_object_iterate(jget(e, "candidates"),
			    &cit, true)) != NULL) {
				if (i == chosen) {
					/* Into the Goes by cell: drawn in place
					 * of the empty one above. */
					;
				}
				h_fmt(h, "%s<span class=\"%s\">", i > 0 ? ", " : "",
				    i == chosen ? "chosen" : "");
				h_txt(h, jstr(c, "id"));
				h_fmt(h, " <small>%s</small></span>", jstr(c,
				    "state") != NULL ? jstr(c, "state") : "");
				i++;
			}
			h_raw(h, "</td></tr>");
		}
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"5\" class=\"dim\">None: a policy "
		    "with a far prefix to reach has entries once applied.</td>"
		    "</tr>");
	h_raw(h, "</tbody></table></div>");
	/* The faults: tunnels that went down or came up, the newest first. */
	h_raw(h, "<div class=\"sd-block\"><h3>Faults <small class=\"dim\">a "
	    "tunnel down or up again, as the edges told it</small></h3><ul "
	    "class=\"sd-faults\">");
	nf = 0;
	it = NULL;
	while (sd.faults != NULL && (f = ucl_object_iterate(sd.faults, &it,
	    true)) != NULL) {
		fit = NULL;
		while ((e = ucl_object_iterate(f, &fit, true)) != NULL) {
			d = jget(e, "data");
			if (nf++ >= 40)
				break;
			fmt_age(age, sizeof(age), (double)jint(e, "t", 0) * 1000);
			h_fmt(h, "<li class=\"st-%s\"><span class=\"led\"></span>"
			    "<b>", jstr(d, "state") != NULL ? jstr(d, "state") :
			    "unknown");
			h_txt(h, host_name(ucl_object_key(f)));
			h_raw(h, "</b> <span class=\"mono\">");
			h_txt(h, jstr(d, "id") != NULL ? jstr(d, "id") : "?");
			h_raw(h, "</span> ");
			h_txt(h, jstr(d, "state") != NULL ? jstr(d, "state") :
			    "");
			h_raw(h, " <span class=\"dim\">");
			h_txt(h, age);
			h_raw(h, "</span></li>");
		}
	}
	(void)eit;
	if (nf == 0)
		h_raw(h, "<li class=\"dim\">None.</li>");
	h_raw(h, "</ul></div>");
	/* Routing at the UNIs: each edge's BIRD instances, a service each,
	 * and their protocols as birdc lists them. */
	h_raw(h, "<div class=\"sd-block\"><h3>Routing <small class=\"dim\">BGP "
	    "or OSPF with the subscriber at a UNI, iBGP between the edges: a "
	    "BIRD instance of each service on each edge, in the service's "
	    "table</small></h3><table class=\"net sd sd-bird\"><thead><tr><th>"
	    "Edge</th><th>Instance</th><th>Protocol</th><th>State</th><th>"
	    "Info</th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while (sd.paths != NULL && (f = ucl_object_iterate(sd.paths, &it,
	    true)) != NULL) {
		fit = NULL;
		while ((e = ucl_object_iterate(jget(f, "bird"), &fit, true)) !=
		    NULL) {
			const ucl_object_t	*pr;
			ucl_object_iter_t	 pit;
			bool			 first = true;

			n++;
			pit = NULL;
			while ((pr = ucl_object_iterate(jget(e, "protocols"), &pit,
			    true)) != NULL || first) {
				h_raw(h, "<tr><td><b>");
				h_txt(h, first ? host_name(ucl_object_key(f)) : "");
				h_raw(h, "</b></td><td class=\"mono\">");
				if (first) {
					h_txt(h, jstr(e, "name"));
					h_fmt(h, " <small class=\"dim\">fib %lld%s"
					    "</small>", jint(e, "fib", 0), jbool(e,
					    "running") ? "" : ", not running");
				}
				h_raw(h, "</td><td class=\"mono\">");
				if (pr != NULL) {
					h_txt(h, jstr(pr, "name") != NULL ? jstr(pr,
					    "name") : "");
					h_raw(h, " <small class=\"dim\">");
					h_txt(h, jstr(pr, "proto") != NULL ? jstr(pr,
					    "proto") : "");
					h_raw(h, "</small>");
				}
				h_fmt(h, "</td><td><span class=\"chip st-%s\">", pr !=
				    NULL && jstr(pr, "state") != NULL && strcmp(jstr(
				    pr, "state"), "up") == 0 ? "up" : "down");
				h_txt(h, pr != NULL && jstr(pr, "state") != NULL ?
				    jstr(pr, "state") : jbool(e, "running") ? "no "
				    "protocol" : "down");
				h_raw(h, "</span></td><td class=\"dim\">");
				h_txt(h, pr != NULL && jstr(pr, "info") != NULL ? jstr(
				    pr, "info") : "");
				h_raw(h, "</td></tr>");
				first = false;
				if (pr == NULL)
					break;
			}
		}
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"5\" class=\"dim\">None: a UNI with "
		    "bgp or ospf in its service has one once applied.</td></tr>");
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
	    "sd-tab\" data-arg=\"overview\">Dashboard</button><button class=\""
	    "tab%s\" data-act=\"sd-tab\" data-arg=\"services\">Services"
	    "</button><button class=\"tab%s\" data-act=\"sd-tab\" data-arg=\""
	    "edges\" title=\"What the edges are to have, and Apply\">Edges"
	    "</button><button class=\"tab%s\" data-act=\"sd-tab\" data-arg=\""
	    "paths\" title=\"What the edges' probes see of each tunnel: "
	    "delay, variation, loss\">Paths</button><button class=\"tab%s\" "
	    "data-act=\"sd-tab\" data-arg=\"document\" title=\"All of it as "
	    "JSON, checked against MEF 70.2\">Document</button></nav>",
	    sd.tab == SD_OVERVIEW ? " on" : "", sd.tab == SD_SERVICES ? " on" :
	    "", sd.tab == SD_EDGES ? " on" : "", sd.tab == SD_PATHS ? " on" :
	    "", sd.tab == SD_DOCUMENT ? " on" : "");
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
	else if (sd.tab == SD_PATHS)
		view_paths(h);
	else if (sd.tab == SD_DOCUMENT)
		view_document(h);
	else
		view_dashboard(h);
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
	/* The plan was of the document before: made again when wanted. */
	if (sd.plan != NULL)
		ucl_object_unref(sd.plan);
	sd.plan = NULL;
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
	    "\"vtnet0\", \"address\": \"192.0.2.10\",\n\t\t\t \"gateway\": "
	    "\"192.0.2.1\", \"breakout\": true},\n"
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
		    "paths") == 0 ? SD_PATHS : strcmp(arg, "document") == 0 ?
		    SD_DOCUMENT : SD_OVERVIEW;
		if (sd.tab == SD_EDGES || sd.tab == SD_OVERVIEW)
			plan_load();
		else if (sd.tab == SD_PATHS)
			paths_load();
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

	if (app.node == NODE_SDWAN && app.visible && ((sd.tab == SD_PATHS &&
	    now - sd.paths_at > PATHS_EVERY_MS) || (sd.tab == SD_OVERVIEW &&
	    now - sd.paths_at > DASH_EVERY_MS)))
		paths_load();
	if (app.node == NODE_SDWAN && app.visible && sd.tab == SD_OVERVIEW &&
	    sd.applied == NULL && now - sd.apply_at > 5000) {
		sd.apply_at = now;
		api("GET", "/api/sdwan/apply", NULL, applied_cb, NULL);
	}
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
