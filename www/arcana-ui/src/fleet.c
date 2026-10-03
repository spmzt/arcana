/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The pages for what the tree selects above a single table: the fleet
 * (every host at a glance), a host's summary (usage, counts and its
 * jails as a graph), and a host's own list of jobs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	T_NODE_W	150
#define	T_NODE_H	34
#define	T_GAP_X		56
#define	T_GAP_Y		8
#define	T_PAD		10
#define	T_MAX_JAILS	24	/* per host; the rest is one "+N" node */

static void	tile(struct html *, const char *, const char *, const char *);
static void	bar(struct html *, const char *, float);
static int	topology(struct html *, struct server *, int, int, int);
static int	jail_rows(const struct server *);

/* A figure with its caption, for the summary. */
static void
tile(struct html *h, const char *value, const char *label, const char *cls)
{

	h_fmt(h, "<div class=\"tile %s\"><b>", cls);
	h_txt(h, value);
	h_raw(h, "</b><span>");
	h_txt(h, label);
	h_raw(h, "</span></div>");
}

/* A thin labelled bar, 0..100. */
static void
bar(struct html *h, const char *label, float pct)
{
	char	buf[48];

	h_raw(h, "<div class=\"mini\"><span>");
	h_txt(h, label);
	snprintf(buf, sizeof(buf), "--v:%.3f", (pct > 100 ? 100 : pct < 0 ? 0 :
	    pct) / 100);
	h_raw(h, "</span><i class=\"bar\"");
	h_attr(h, "style", buf);
	snprintf(buf, sizeof(buf), "%.0f%%", pct);
	h_raw(h, "></i><em>");
	h_txt(h, buf);
	h_raw(h, "</em></div>");
}

/* Rows the jails of s take in a topology: one each, capped. */
static int
jail_rows(const struct server *s)
{
	unsigned int	n;

	n = s->list != NULL ? ucl_array_size(jget(s->list, "jails")) : 0;
	if (n == 0)
		return (1);
	return (n > T_MAX_JAILS ? T_MAX_JAILS + 1 : (int)n);
}

/*
 * The host and its jails as nodes at column col, from row row on, with
 * an edge from (px, py) when px >= 0.  Returns the rows used.  Nodes are
 * buttons: a host opens its page, a jail its own.
 */
static int
topology(struct html *h, struct server *s, int col, int row, int parent_y)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;
	const char		*name, *st;
	int			 x, y, jx, jy, n, rows, shown;
	unsigned int		 total;

	rows = jail_rows(s);
	x = T_PAD + col * (T_NODE_W + T_GAP_X);
	y = T_PAD + row * (T_NODE_H + T_GAP_Y);
	if (parent_y >= 0)
		h_fmt(h, "<svg class=\"edges\" style=\"left:0;top:0\" "
		    "aria-hidden=\"true\"><path class=\"e-ok\" d=\"M%d %d C%d %d "
		    "%d %d %d %d\"/></svg>", x - T_GAP_X, parent_y,
		    x - T_GAP_X / 2, parent_y, x - T_GAP_X / 2,
		    y + T_NODE_H / 2, x, y + T_NODE_H / 2);
	h_fmt(h, "<div class=\"tnode host %s\" style=\"left:%dpx;top:%dpx\" "
	    "data-act=\"select-server\"", s->failed ? "down" : s->list != NULL ?
	    "up" : "unknown", x, y);
	h_attr(h, "data-arg", s->id);
	h_raw(h, "><i class=\"led\"></i>");
	h_txt(h, s->name);
	h_raw(h, "</div>");
	jx = x + T_NODE_W + T_GAP_X;
	n = shown = 0;
	total = s->list != NULL ? ucl_array_size(jget(s->list, "jails")) : 0;
	it = NULL;
	while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		if ((name = jstr(j, "name")) == NULL)
			continue;
		jy = T_PAD + (row + n) * (T_NODE_H + T_GAP_Y);
		h_fmt(h, "<svg class=\"edges\" style=\"left:0;top:0\" "
		    "aria-hidden=\"true\"><path class=\"e-ok\" d=\"M%d %d C%d %d "
		    "%d %d %d %d\"/></svg>", x + T_NODE_W, y + T_NODE_H / 2,
		    x + T_NODE_W + T_GAP_X / 2, y + T_NODE_H / 2,
		    jx - T_GAP_X / 2, jy + T_NODE_H / 2, jx, jy + T_NODE_H / 2);
		if (shown == T_MAX_JAILS) {
			h_fmt(h, "<div class=\"tnode more\" style=\"left:%dpx;"
			    "top:%dpx\" data-act=\"select-server\"", jx, jy);
			h_attr(h, "data-arg", s->id);
			h_fmt(h, ">+%u more</div>", total - T_MAX_JAILS);
			break;
		}
		st = s->failed ? "unknown" : h_word(jstr(j, "state"), "unknown");
		h_fmt(h, "<div class=\"tnode s-%s\" style=\"left:%dpx;top:%dpx\" "
		    "data-act=\"open-jail\"", st, jx, jy);
		h_attr(h, "data-arg", name);
		h_attr(h, "data-value", s->id);
		h_raw(h, "><i class=\"led\"></i>");
		h_txt(h, name);
		h_raw(h, "</div>");
		n++;
		shown++;
	}
	return (rows);
}

/* Every host at a glance, and the fleet as a graph. */
void
view_fleet(struct html *h)
{
	struct server	*s;
	char		 buf[64];
	int		 i, row, rows, up, jails, running;

	up = jails = running = 0;
	rows = 0;
	for (i = 0; i < app.nservers; i++) {
		s = &app.servers[i];
		if (s->list != NULL && !s->failed)
			up++;
		if (s->list != NULL) {
			const ucl_object_t *j;
			ucl_object_iter_t it = NULL;

			while ((j = ucl_object_iterate(jget(s->list, "jails"),
			    &it, true)) != NULL) {
				jails++;
				if (jstr(j, "state") != NULL &&
				    strcmp(jstr(j, "state"), "running") == 0)
					running++;
			}
		}
		rows += jail_rows(s);
	}
	h_raw(h, "<section class=\"hostbar\"><div class=\"host-id\"><h1>Fleet"
	    "</h1><div class=\"facts\"><span>The Seven Archives of FreeBSD"
	    "</span></div></div></section><div class=\"tiles\">");
	snprintf(buf, sizeof(buf), "%d/%d", up, app.nservers);
	tile(h, buf, "hosts answering", up == app.nservers ? "ok" : "warn");
	snprintf(buf, sizeof(buf), "%d/%d", running, jails);
	tile(h, buf, "jails running", "ok");
	snprintf(buf, sizeof(buf), "%d", app.nops);
	tile(h, buf, "tasks this session", "");
	h_raw(h, "</div><div class=\"hosts\">");
	for (i = 0; i < app.nservers; i++) {
		s = &app.servers[i];
		h_fmt(h, "<article class=\"hostcard %s\" data-act=\"select-server\"",
		    s->failed ? "down" : s->list != NULL ? "up" : "unknown");
		h_attr(h, "data-arg", s->id);
		h_raw(h, "><header><i class=\"led\"></i><h3>");
		h_txt(h, s->name);
		h_raw(h, "</h3><span class=\"dim\">");
		h_txt(h, s->list != NULL && jstr(s->list, "host.release") !=
		    NULL ? jstr(s->list, "host.release") : s->uri);
		h_raw(h, "</span></header>");
		if (s->failed) {
			h_raw(h, "<p class=\"err\">");
			h_txt(h, s->error);
			h_raw(h, "</p>");
		} else if (s->nhist > 0) {
			bar(h, "CPU", s->hist[0][s->nhist - 1]);
			bar(h, "RAM", s->hist[1][s->nhist - 1]);
			bar(h, "ZFS", s->hist[2][s->nhist - 1]);
		} else
			h_raw(h, "<p class=\"dim\">waiting for the host…</p>");
		if (s->list != NULL) {
			int r = 0, a = 0;
			const ucl_object_t *j;
			ucl_object_iter_t it = NULL;

			while ((j = ucl_object_iterate(jget(s->list, "jails"),
			    &it, true)) != NULL) {
				a++;
				if (jstr(j, "state") != NULL &&
				    strcmp(jstr(j, "state"), "running") == 0)
					r++;
			}
			h_fmt(h, "<footer><b>%d</b>/%d jails running</footer>", r,
			    a);
		}
		h_raw(h, "</article>");
	}
	h_raw(h, "</div><h4>Topology</h4>");
	h_fmt(h, "<div class=\"graph-scroll\"><div class=\"topo\" "
	    "style=\"width:%dpx;height:%dpx\">", T_PAD * 2 + 3 * T_NODE_W +
	    2 * T_GAP_X, T_PAD * 2 + (rows > 0 ? rows : 1) * (T_NODE_H +
	    T_GAP_Y));
	h_fmt(h, "<div class=\"tnode root\" style=\"left:%dpx;top:%dpx\" "
	    "data-act=\"select-fleet\">console</div>", T_PAD, T_PAD);
	row = 0;
	for (i = 0; i < app.nservers; i++)
		row += topology(h, &app.servers[i], 1, row, T_PAD +
		    T_NODE_H / 2);
	h_raw(h, "</div></div>");
}

/* A host's summary: usage, what it holds, and its jails as a graph. */
void
view_summary(struct html *h, struct server *s)
{
	const ucl_object_t	*sv, *st, *p;
	ucl_object_iter_t	 it;
	char			 buf[64];
	int			 run, all, sen, srun, njobs;

	view_gauges(h, s);
	run = all = 0;
	it = NULL;
	while (s->list != NULL && (p = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		all++;
		if (jstr(p, "state") != NULL && strcmp(jstr(p, "state"),
		    "running") == 0)
			run++;
	}
	h_raw(h, "<div class=\"tiles\">");
	snprintf(buf, sizeof(buf), "%d/%d", run, all);
	tile(h, buf, "jails running", "ok");
	if (s->services != NULL) {
		sen = srun = 0;
		it = NULL;
		while ((sv = ucl_object_iterate(jget(s->services, "services"),
		    &it, true)) != NULL) {
			if (jbool(sv, "enabled"))
				sen++;
			if (jbool(sv, "running"))
				srun++;
		}
		snprintf(buf, sizeof(buf), "%d/%d", srun, sen);
		tile(h, buf, "enabled services running", srun == sen ? "ok" :
		    "warn");
	} else
		tile(h, "–", "services: open the tab", "");
	if (app.pkg.data != NULL && strcmp(app.pkg.sid, s->id) == 0 &&
	    app.pkg.jail[0] == '\0') {
		snprintf(buf, sizeof(buf), "%u", ucl_array_size(jget(
		    app.pkg.data, "packages")));
		tile(h, buf, "packages to upgrade", buf[0] == '0' ? "ok" :
		    "warn");
	} else
		tile(h, "–", "packages: open the tab", "");
	njobs = s->jobs != NULL ? (int)ucl_array_size(jget(s->jobs, "jobs")) :
	    0;
	snprintf(buf, sizeof(buf), "%d", njobs);
	tile(h, s->jobs != NULL ? buf : "–", "jobs on record", "");
	st = s->stats != NULL ? jget(s->stats, "stats") : NULL;
	if (st != NULL) {
		snprintf(buf, sizeof(buf), "%.2f", jnum(st, "load1", 0));
		tile(h, buf, "load, 1 min", "");
	}
	h_raw(h, "</div>");
	/* The pools, one line each. */
	if (st != NULL && ucl_array_size(jget(st, "pools")) > 0) {
		h_raw(h, "<h4>ZFS pools</h4><div class=\"pools\">");
		it = NULL;
		while ((p = ucl_object_iterate(jget(st, "pools"), &it,
		    true)) != NULL) {
			double size = jnum(p, "size", 0);

			snprintf(buf, sizeof(buf), "%s  %.0f/%.0f GiB  %s",
			    jstr(p, "name") != NULL ? jstr(p, "name") : "?",
			    jnum(p, "alloc", 0) / 1073741824, size / 1073741824,
			    jstr(p, "health") != NULL ? jstr(p, "health") : "");
			bar(h, buf, size > 0 ? (float)(100 * jnum(p, "alloc",
			    0) / size) : 0);
		}
		h_raw(h, "</div>");
	}
	h_raw(h, "<h4>Jails</h4>");
	h_fmt(h, "<div class=\"graph-scroll\"><div class=\"topo\" "
	    "style=\"width:%dpx;height:%dpx\">", T_PAD * 2 + 2 * T_NODE_W +
	    T_GAP_X, T_PAD * 2 + jail_rows(s) * (T_NODE_H + T_GAP_Y));
	topology(h, s, 0, 0, -1);
	h_raw(h, "</div></div>");
}

/* The host's own record of jobs, whoever queued them. */
void
view_jobs(struct html *h, struct server *s)
{
	const ucl_object_t	*j, *arr;
	const char		*st;
	char			 buf[48], id[24];
	unsigned int		 n, i;

	h_raw(h, "<div class=\"toolbar\"><span class=\"tally\">What this host "
	    "was asked to change, by the console or with arcanactl -q; it "
	    "keeps the last 64 and forgets them when the agent restarts."
	    "</span></div>");
	if (s->jobs == NULL) {
		h_raw(h, "<div class=\"empty\"><div class=\"loader\"></div></div>");
		return;
	}
	arr = jget(s->jobs, "jobs");
	if ((n = ucl_array_size(arr)) == 0) {
		h_raw(h, "<div class=\"empty\"><p>No jobs yet.</p></div>");
		return;
	}
	h_raw(h, "<table class=\"net jobs\"><thead><tr><th>#</th><th>State</th>"
	    "<th>Job</th><th>By</th><th>Queued</th><th>Took</th></tr></thead>"
	    "<tbody>");
	/* Newest first. */
	for (i = n; i > 0; i--) {
		j = ucl_array_find_index(arr, i - 1);
		st = jstr(j, "state") != NULL ? jstr(j, "state") : "unknown";
		if (strcmp(st, "done") == 0 && !jbool(j, "ok"))
			st = "failed";
		snprintf(id, sizeof(id), "%lld", (long long)jint(j, "id", 0));
		h_fmt(h, "<tr class=\"job j-%s\" data-act=\"open-job\"",
		    h_word(st, "unknown"));
		h_attr(h, "data-arg", id);
		h_attr(h, "data-value", jstr(j, "title"));
		h_raw(h, "><td>");
		h_txt(h, id);
		h_raw(h, "</td><td class=\"st\">");
		h_txt(h, st);
		h_raw(h, "</td><td>");
		h_txt(h, jstr(j, "title"));
		if (jstr(j, "error") != NULL) {
			h_raw(h, " <span class=\"err\">");
			h_txt(h, jstr(j, "error"));
			h_raw(h, "</span>");
		}
		h_raw(h, "</td><td>");
		h_txt(h, jstr(j, "peer"));
		h_raw(h, "</td><td>");
		fmt_age(buf, sizeof(buf), (double)jint(j, "created", 0) * 1000);
		h_txt(h, buf);
		h_raw(h, "</td><td>");
		if (jget(j, "finished") != NULL && ucl_object_type(jget(j,
		    "finished")) == UCL_INT && ucl_object_type(jget(j,
		    "started")) == UCL_INT) {
			snprintf(buf, sizeof(buf), "%lld s", (long long)(jint(j,
			    "finished", 0) - jint(j, "started", 0)));
			h_txt(h, buf);
		}
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table>");
}
