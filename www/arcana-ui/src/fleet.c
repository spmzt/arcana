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
#define	T_MAX_JAILS	64	/* per host; the rest is one "+N" node */
#define	T_COLS		4	/* a host's jails in at most so many columns */
#define	T_PER_COL	10	/* a column more for each so many */
#define	T_CELL_X	12	/* between a host's columns of jails */
#define	T_RAIL		14	/* the rail the jails hang on, before them */

static void	tile(struct html *, const char *, const char *, const char *);
static void	bar(struct html *, const char *, float);
static int	topology(struct html *, struct server *, int, int, int, bool);
static int	jail_rows(const struct server *, bool);
static int	jail_cols(int);
static int	jails_width(const struct server *, bool);

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

/* Is the jail one a graph of only what runs leaves out? */
static bool
stopped(const ucl_object_t *j)
{

	return (jstr(j, "state") != NULL && strcmp(jstr(j, "state"),
	    "stopped") == 0);
}

/* The jails of s a topology shows: all, or all but the stopped. */
static unsigned int
jail_count(const struct server *s, bool live)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;
	unsigned int		 n;

	n = 0;
	it = NULL;
	while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL)
		if (jstr(j, "name") != NULL && !(live && stopped(j)))
			n++;
	return (n);
}

/* Rows the jails of s take in a topology: one each, capped. */
static int
jail_rows(const struct server *s, bool live)
{
	unsigned int	n;
	int		cells;

	n = jail_count(s, live);
	if (n == 0)
		return (1);
	cells = n > T_MAX_JAILS ? T_MAX_JAILS + 1 : (int)n;
	return ((cells + jail_cols(cells) - 1) / jail_cols(cells));
}

/* The width a host's grid of jails takes. */
static int
jails_width(const struct server *s, bool live)
{
	unsigned int	n;
	int		cols;

	n = jail_count(s, live);
	cols = jail_cols(n > T_MAX_JAILS ? T_MAX_JAILS + 1 : (int)n);
	return (cols * T_NODE_W + (cols - 1) * T_CELL_X);
}

/* The columns a host's cells of jails take: one for ten, at most four. */
static int
jail_cols(int cells)
{
	int	c;

	c = (cells + T_PER_COL - 1) / T_PER_COL;
	return (c < 1 ? 1 : c > T_COLS ? T_COLS : c);
}

/*
 * The host and its jails as nodes at column col, from row row on, with
 * an edge from (px, py) when px >= 0.  Returns the rows used.  Nodes are
 * buttons: a host opens its page, a jail its own.  With live, only the
 * jails that are not stopped: the fleet's graph is of what runs.
 */
static int
topology(struct html *h, struct server *s, int col, int row, int parent_y,
    bool live)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;
	const char		*name, *st;
	int			 x, y, jx, jy, n, rows, shown, cols, cells, rx,
				 last;
	unsigned int		 total;

	rows = jail_rows(s, live);
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
	total = jail_count(s, live);
	if (total == 0)
		return (rows);
	/*
	 * The jails in a grid, a column for each ten of them: one line
	 * from the host to a rail beside the grid, a tick from the rail to
	 * each row; a hundred jails are a block, not a fan of a hundred
	 * curves down the page.
	 */
	cells = total > T_MAX_JAILS ? T_MAX_JAILS + 1 : (int)total;
	cols = jail_cols(cells);
	rx = x + T_NODE_W + T_GAP_X - T_RAIL;
	last = T_PAD + (row + rows - 1) * (T_NODE_H + T_GAP_Y) + T_NODE_H / 2;
	h_fmt(h, "<svg class=\"edges\" style=\"left:0;top:0\" "
	    "aria-hidden=\"true\"><path class=\"e-ok\" d=\"M%d %d C%d %d %d %d "
	    "%d %d", x + T_NODE_W, y + T_NODE_H / 2, rx - 10, y + T_NODE_H / 2,
	    rx - 10, y + T_NODE_H / 2, rx, y + T_NODE_H / 2);
	if (rows > 1)
		h_fmt(h, " M%d %d L%d %d", rx, y + T_NODE_H / 2, rx, last);
	for (n = 0; n < rows; n++) {
		jy = T_PAD + (row + n) * (T_NODE_H + T_GAP_Y) + T_NODE_H / 2;
		h_fmt(h, " M%d %d L%d %d", rx, jy, rx + T_RAIL, jy);
	}
	h_raw(h, "\"/></svg>");
	n = shown = 0;
	it = NULL;
	while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		if ((name = jstr(j, "name")) == NULL || (live && stopped(j)))
			continue;
		/* Row by row, so a row reads from left to right. */
		jx = x + T_NODE_W + T_GAP_X + (n % cols) * (T_NODE_W + T_CELL_X);
		jy = T_PAD + (row + n / cols) * (T_NODE_H + T_GAP_Y);
		if (shown == T_MAX_JAILS) {
			h_fmt(h, "<div class=\"tnode more\" style=\"left:%dpx;"
			    "top:%dpx\" data-act=\"select-server\"", jx, jy);
			h_attr(h, "data-arg", s->id);
			h_fmt(h, ">+%u more</div>", total - T_MAX_JAILS);
			break;
		}
		st = s->failed ? "unknown" : h_word(jstr(j, "state"), "unknown");
		/* In a graph a jail opens in a box over the page. */
		h_fmt(h, "<div class=\"tnode s-%s\" style=\"left:%dpx;top:%dpx\" "
		    "data-act=\"peek-jail\"", st, jx, jy);
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
	int		 i, row, rows, up, jails, running, behind;

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
		rows += jail_rows(s, true);
	}
	h_raw(h, "<section class=\"hostbar\"><div class=\"host-id\"><h1>Fleet"
	    "</h1><div class=\"facts\"><span>The Seven Archives of FreeBSD"
	    "</span>");
	behind = 0;
	for (i = 0; i < app.nservers; i++)
		if (agent_outdated(&app.servers[i]))
			behind++;
	if (behind > 0)
		h_fmt(h, "<button class=\"ghost small\" data-act=\""
		    "agent-update\" title=\"Send the console's arcana-agent to "
		    "the hosts that run another version\">Update %d agent%s"
		    "</button>", behind, behind == 1 ? "" : "s");
	h_raw(h, "</div></div></section><div class=\"tiles\">");
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
		} else if (s->loading && arc_now() - s->loading_since > 15000)
			/* Its agent took the connection and says nothing. */
			h_fmt(h, "<p class=\"warn\" title=\"Asked, and no "
			    "answer yet: the connection is up and the agent "
			    "says nothing, or a proxy holds it\">no answer for "
			    "%.0f s</p>", (arc_now() - s->loading_since) / 1000);
		else
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
	{
		int	w, wmax;

		for (wmax = T_NODE_W, i = 0; i < app.nservers; i++)
			if ((w = jails_width(&app.servers[i], true)) > wmax)
				wmax = w;
		h_fmt(h, "<div class=\"graph-scroll\"><div class=\"topo\" "
		    "style=\"width:%dpx;height:%dpx\">", T_PAD * 2 + 2 *
		    (T_NODE_W + T_GAP_X) + wmax, T_PAD * 2 + (rows > 0 ? rows :
		    1) * (T_NODE_H + T_GAP_Y));
	}
	h_fmt(h, "<div class=\"tnode root\" style=\"left:%dpx;top:%dpx\" "
	    "data-act=\"select-fleet\">console</div>", T_PAD, T_PAD);
	row = 0;
	for (i = 0; i < app.nservers; i++)
		row += topology(h, &app.servers[i], 1, row, T_PAD +
		    T_NODE_H / 2, true);
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
	    "style=\"width:%dpx;height:%dpx\">", T_PAD * 2 + T_NODE_W +
	    T_GAP_X + jails_width(s, false), T_PAD * 2 + jail_rows(s, false) *
	    (T_NODE_H + T_GAP_Y));
	topology(h, s, 0, 0, -1, false);
	h_raw(h, "</div></div>");
}

/* The host's own record of jobs, whoever queued them. */
void
view_jobs(struct html *h, struct server *s)
{
	static const struct tcol jcols[] = {
		{ "#", "id", true }, { "State", "state", false },
		{ "Job", "title", false }, { "By", "peer", false },
		{ "Queued", "created", true }, { "Took", NULL, false },
	};
	const ucl_object_t	*j, *arr, **rows;
	const char		*st;
	char			 buf[48], id[24];
	unsigned int		 n, i;

	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\"filter\" "
	    "data-input=\"filter\" placeholder=\"Filter rows\" autocomplete=\""
	    "off\" spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "><span class=\"tally\">What this host "
	    "was asked to change, by the console or with arcanactl -q; it "
	    "keeps the last 64 and forgets them when the agent restarts."
	    "</span></div>");
	if (s->jobs == NULL) {
		h_raw(h, "<div class=\"empty\"><div class=\"loader\"></div></div>");
		return;
	}
	/*
	 * What the agent is at now that is not a job: a request somebody
	 * waits for.  It holds up the jobs, and a stop, as a job does.
	 */
	if (jstr(s->jobs, "activity") != NULL || jbool(s->jobs, "stopping")) {
		h_raw(h, "<div class=\"notice warn now\">");
		if (jstr(s->jobs, "activity") != NULL) {
			h_raw(h, "<b>Under way now:</b> ");
			h_txt(h, jstr(s->jobs, "activity"));
			fmt_age(buf, sizeof(buf), (double)jint(s->jobs, "since",
			    0) * 1000);
			h_raw(h, " <span class=\"dim\">· since ");
			h_txt(h, buf);
			h_raw(h, " · not a job: it ends when its program does, "
			    "and jobs wait for it</span>");
		}
		if (jbool(s->jobs, "stopping"))
			h_raw(h, "<br><b>The agent was told to stop</b> and "
			    "does when this has ended; it takes nothing new.");
		h_raw(h, "</div>");
	}
	arr = jget(s->jobs, "jobs");
	if ((n = ucl_array_size(arr)) == 0) {
		h_raw(h, "<div class=\"empty\"><p>No jobs yet.</p></div>");
		return;
	}
	h_raw(h, "<table class=\"net jobs\">");
	tbl_head(h, "jobs", jcols, 6, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("jobs", arr, jcols, 6, app.filter);
	for (n = 0; rows[n] != NULL; n++)
		;
	/* Newest first, unless an order was asked for. */
	for (i = n; i > 0; i--) {
		j = rows[tbl_sorted("jobs") ? n - i : i - 1];
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
	free(rows);
	h_raw(h, "</tbody></table>");
}

/*
 * The hosts as a table: each its name and address, its state, its
 * agent's version and the release of FreeBSD it runs, its jails, and
 * how busy it is now; sorted and filtered like every table, a row
 * opening the host.  Updating the agents is here: each host's in its
 * row, all that are behind at once at the top.
 */
void
view_devices(struct html *h)
{
	static const struct tcol	cols[] = {
		{ "Host", "name", false }, { "Address", "uri", false },
		{ "State", "state", false }, { "Agent", "version", false },
		{ "FreeBSD", "release", false }, { "Jails running", "running",
		true }, { "Jails", "jails", true }, { "CPU %", "cpu", true },
		{ "Memory %", "mem", true }, { "ZFS %", "zfs", true },
		{ "", NULL, false },
	};
	struct server		*s;
	ucl_object_t		*arr, *o;
	const ucl_object_t	**rows, *r;
	int			 i, k, behind = 0;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < app.nservers; i++) {
		s = &app.servers[i];
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(s->id), "id", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(s->name), "name",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(s->uri), "uri", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(s->failed ? "down" :
		    s->list != NULL ? "up" : "unknown"), "state", 0, false);
		if (agent_outdated(s)) {
			ucl_object_insert_key(o, ucl_object_frombool(true),
			    "behind", 0, false);
			behind++;
		}
		if (s->list != NULL && jstr(s->list, "host.version") != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(jstr(
			    s->list, "host.version")), "version", 0, false);
		if (s->list != NULL && jstr(s->list, "host.release") != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(jstr(
			    s->list, "host.release")), "release", 0, false);
		if (s->list != NULL) {
			ucl_object_insert_key(o, ucl_object_fromint(count_state(s,
			    "running")), "running", 0, false);
			ucl_object_insert_key(o, ucl_object_fromint(count_state(s,
			    NULL)), "jails", 0, false);
		}
		if (s->nhist > 0) {
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)
			    s->hist[0][s->nhist - 1]), "cpu", 0, false);
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)
			    s->hist[1][s->nhist - 1]), "mem", 0, false);
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)
			    s->hist[2][s->nhist - 1]), "zfs", 0, false);
		}
		ucl_array_append(arr, o);
	}
	h_raw(h, "<section class=\"hostbar\"><div class=\"host-id\"><h1>Devices"
	    "</h1><div class=\"facts\">");
	h_fmt(h, "<span>%d host%s</span>", app.nservers, app.nservers == 1 ?
	    "" : "s");
	if (app.agent_version[0] != '\0') {
		h_raw(h, "<span>the console sends arcana-agent ");
		h_txt(h, app.agent_version);
		h_raw(h, "</span>");
	}
	h_raw(h, "</div></div><div class=\"pane-actions\">");
	/* Updating the agents: every host behind at once, or each one in
	 * its row. */
	if (behind > 0)
		h_fmt(h, "<button class=\"small primary\" data-act=\""
		    "agent-update\" title=\"Send the console's arcana-agent to "
		    "the hosts that run another version\">Update %d agent%s"
		    "</button>", behind, behind == 1 ? "" : "s");
	h_raw(h, "<button class=\"ghost small\" data-act=\"enrol\">Enrol a "
	    "host</button><button class=\"ghost small\" data-act=\""
	    "add-server\">Add a server</button></div></section>");
	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\"filter\" "
	    "data-input=\"filter\" placeholder=\"Filter hosts\" "
	    "autocomplete=\"off\" spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "></div><table class=\"net devices\">");
	tbl_head(h, "devices", cols, 11, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("devices", arr, cols, 11, app.filter);
	for (k = 0; (r = rows[k]) != NULL; k++) {
		h_raw(h, "<tr class=\"pick\" data-act=\"select-server\"");
		h_attr(h, "data-arg", jstr(r, "id"));
		h_raw(h, "><td><b>");
		h_txt(h, jstr(r, "name"));
		h_raw(h, "</b></td><td class=\"mono addr\"");
		h_attr(h, "title", jstr(r, "uri"));
		h_raw(h, ">");
		h_txt(h, jstr(r, "uri"));
		h_fmt(h, "</td><td><span class=\"chip st-%s\">%s</span></td><td",
		    jstr(r, "state"), jstr(r, "state"));
		if (jbool(r, "behind"))
			h_raw(h, " class=\"warn\" title=\"Not the arcana-agent "
			    "this console sends: another build, or another "
			    "version\"");
		h_raw(h, ">");
		h_txt(h, jstr(r, "version") != NULL ? jstr(r, "version") : "—");
		if (jbool(r, "behind")) {
			h_raw(h, " <button class=\"small primary\" data-act=\""
			    "agent-update\" title=\"Send this host the "
			    "console's arcana-agent\"");
			h_attr(h, "data-arg", jstr(r, "id"));
			h_raw(h, ">Update</button>");
		}
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "release") != NULL ? jstr(r, "release") : "—");
		if (jget(r, "jails") != NULL)
			h_fmt(h, "</td><td>%lld</td><td>%lld</td>", (long long)jint(r,
			    "running", 0), (long long)jint(r, "jails", 0));
		else
			h_raw(h, "</td><td>—</td><td>—</td>");
		if (jget(r, "cpu") != NULL)
			h_fmt(h, "<td>%lld</td><td>%lld</td><td>%lld</td>",
			    (long long)jint(r, "cpu", 0), (long long)jint(r, "mem",
			    0), (long long)jint(r, "zfs", 0));
		else
			h_raw(h, "<td>—</td><td>—</td><td>—</td>");
		h_raw(h, "<td class=\"acts\">");
		if (app.agent_source[0] != '\0' && strcmp(jstr(r, "state"),
		    "up") == 0) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "agent-build\" title=\"Build arcana-agent on this "
			    "host from the repository, without installing it\"");
			h_attr(h, "data-arg", jstr(r, "id"));
			h_raw(h, ">Build</button>");
		}
		h_raw(h, "<button class=\"icon del\" "
		    "data-act=\"delete-server\" title=\"Remove it from the "
		    "console\"");
		h_attr(h, "data-arg", jstr(r, "id"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (k == 0)
		h_raw(h, "<tr><td colspan=\"11\" class=\"dim\">No host matches."
		    "</td></tr>");
	free(rows);
	h_raw(h, "</tbody></table>");
	ucl_object_unref(arr);
}
