/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * How busy every host has been, drawn as lines over time: the CPUs,
 * the memory, the load, the network and the disks.  Each agent keeps
 * the last hour by itself, so the lines are there when the page is
 * opened; while it is shown, what came since is asked for and added.
 * The hosts are drawn over one another to be compared, and then each
 * by itself.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	nitems(x)	(sizeof(x) / sizeof((x)[0]))

#define	USAGE_EVERY	5000	/* ms between two looks */
#define	USAGE_KEPT	720	/* samples of a host, an hour of them */
#define	NF		9	/* what a sample holds */
#define	PW		300	/* a plot's box */
#define	PH		70

enum { F_T, F_CPU, F_LOAD, F_MEM, F_SWAP, F_RX, F_TX, F_RD, F_WR };

struct uhost {
	char	 sid[9];
	double	(*v)[NF];
	int	 n;
	double	 mem_total, swap_total;
	int	 ncpu, step;
	bool	 loading;
	double	 asked;
	char	 error[160];
};

static struct uhost	uh[MAX_SERVERS];
static int		window = 900;	/* s shown */

static const char *const palette[] = { "var(--cyan)", "var(--green)",
    "var(--amber)", "var(--violet)", "var(--magenta)", "var(--blue)",
    "var(--teal)", "var(--red)" };

static struct uhost *
uhost(const char *sid, bool make)
{
	int	i, j, free_i;

	free_i = -1;
	for (i = 0; i < MAX_SERVERS; i++) {
		if (strcmp(uh[i].sid, sid) == 0)
			return (&uh[i]);
		if (free_i == -1 && uh[i].sid[0] == '\0')
			free_i = i;
	}
	if (!make)
		return (NULL);
	/* A host that is gone leaves its place to one that is here. */
	for (i = 0; free_i == -1 && i < MAX_SERVERS; i++) {
		for (j = 0; j < app.nservers; j++)
			if (strcmp(app.servers[j].id, uh[i].sid) == 0)
				break;
		if (j == app.nservers)
			free_i = i;
	}
	if (free_i == -1)
		return (NULL);
	free(uh[free_i].v);
	memset(&uh[free_i], 0, sizeof(uh[0]));
	snprintf(uh[free_i].sid, sizeof(uh[0].sid), "%s", sid);
	return (&uh[free_i]);
}

static void
usage_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*d, *row, *f;
	ucl_object_iter_t	 it, fit;
	struct uhost		*u;
	char			*sid;
	double			 s[NF];
	int			 k;

	sid = arg;
	u = uhost(sid, false);
	free(sid);
	if (u == NULL)
		return;
	u->loading = false;
	if (status != 200 || !jbool(o, "ok") || (d = jget(o, "data")) ==
	    NULL) {
		snprintf(u->error, sizeof(u->error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	u->error[0] = '\0';
	u->mem_total = jnum(d, "mem_total", 0);
	u->swap_total = jnum(d, "swap_total", 0);
	u->ncpu = (int)jint(d, "ncpu", 1);
	u->step = (int)jint(d, "step", 5);
	if (u->v == NULL && (u->v = calloc(USAGE_KEPT, sizeof(*u->v))) == NULL)
		abort();
	it = NULL;
	while ((row = ucl_object_iterate(jget(d, "samples"), &it, true)) !=
	    NULL) {
		memset(s, 0, sizeof(s));
		fit = NULL;
		for (k = 0; k < NF && (f = ucl_object_iterate(row, &fit,
		    true)) != NULL; k++)
			s[k] = ucl_object_todouble(f);
		if (k < NF || (u->n > 0 && s[F_T] <= u->v[u->n - 1][F_T]))
			continue;
		if (u->n == USAGE_KEPT) {
			memmove(u->v, u->v + 1, (USAGE_KEPT - 1) *
			    sizeof(*u->v));
			u->n--;
		}
		memcpy(u->v[u->n++], s, sizeof(s));
	}
}

static void
usage_poll(struct server *s, double now)
{
	struct uhost	*u;
	char		 url[96];

	if ((u = uhost(s->id, true)) == NULL || u->loading)
		return;
	u->loading = true;
	u->asked = now;
	snprintf(url, sizeof(url), "/api/servers/%s/history?after=%.0f", s->id,
	    u->n > 0 ? u->v[u->n - 1][F_T] : 0.0);
	api("GET", url, NULL, usage_cb, strdup(s->id));
}

/* Called when the section is opened: ask every host at once. */
void
usage_open(void)
{
	int	i;

	app.node = NODE_USAGE;
	app.jail[0] = '\0';
	app.rail_open = false;
	for (i = 0; i < app.nservers; i++)
		usage_poll(&app.servers[i], arc_now());
}

void
usage_tick(double now)
{
	struct uhost	*u;
	int		 i;

	if (app.node != NODE_USAGE || !app.visible)
		return;
	for (i = 0; i < app.nservers; i++) {
		u = uhost(app.servers[i].id, false);
		/* A request nobody answered is given up after a while. */
		if (u != NULL && u->loading && now - u->asked > 30000)
			u->loading = false;
		if (u == NULL || (!u->loading && now - u->asked >=
		    USAGE_EVERY))
			usage_poll(&app.servers[i], now);
	}
}

/* What field f of sample i is, in what it is drawn in. */
static double
value(const struct uhost *u, int i, int f)
{

	switch (f) {
	case F_MEM:
		return (u->mem_total > 0 ? 100 * u->v[i][F_MEM] /
		    u->mem_total : 0);
	case F_SWAP:
		return (u->swap_total > 0 ? 100 * u->v[i][F_SWAP] /
		    u->swap_total : 0);
	default:
		return (u->v[i][f]);
	}
}

/* The first sample of the window that ends at t1. */
static int
first(const struct uhost *u, double t1)
{
	int	i;

	for (i = u->n; i > 0 && u->v[i - 1][F_T] >= t1 - window; i--)
		;
	return (i);
}

static void
stats(const struct uhost *u, int f, double t1, double *last, double *avg,
    double *peak)
{
	double	v;
	int	i, n;

	*last = *avg = *peak = 0;
	for (n = 0, i = first(u, t1); i < u->n; i++, n++) {
		v = value(u, i, f);
		*avg += v;
		if (v > *peak)
			*peak = v;
		*last = v;
	}
	if (n > 0)
		*avg /= n;
}

/* A round figure not under v, for the top of a plot. */
static double
ceiling(double v)
{
	double	p;

	if (v <= 0)
		return (1);
	p = pow(10, floor(log10(v)));
	return (v <= p ? p : v <= 2 * p ? 2 * p : v <= 5 * p ? 5 * p : 10 * p);
}

/*
 * Field f of the host as a line, and with area the ground under it,
 * in a box of PW by PH whose right edge is t1 and whose top is top.
 * Where the host did not answer for a while the line is broken.
 */
static void
line(struct html *h, const struct uhost *u, int f, double t1, double top,
    const char *colour, bool area, bool dashed)
{
	double	x, y, x0, px;
	int	i, i0;
	bool	open;

	i0 = first(u, t1);
	if (u->n - i0 < 2)
		return;
	for (i = area ? 0 : 1; i < 2; i++) {
		h_fmt(h, "<path class=\"%s%s\" style=\"%s:%s\" d=\"", i == 0 ?
		    "area" : "line", dashed ? " dash" : "", i == 0 ? "fill" :
		    "stroke", colour);
		open = false;
		x0 = px = 0;
		for (int k = i0; k < u->n; k++) {
			x = PW * (1 - (t1 - u->v[k][F_T]) / window);
			y = value(u, k, f) / top;
			y = PH - (PH - 2) * (y > 1 ? 1 : y < 0 ? 0 : y);
			if (open && u->v[k][F_T] - u->v[k - 1][F_T] > 4 *
			    (u->step > 0 ? u->step : 5)) {
				if (i == 0)
					h_fmt(h, "L%.1f %d Z ", px, PH);
				open = false;
			}
			if (!open) {
				if (i == 0)
					h_fmt(h, "M%.1f %d L%.1f %.1f ", x, PH,
					    x, y);
				else
					h_fmt(h, "M%.1f %.1f ", x, y);
				x0 = x;
				open = true;
			} else
				h_fmt(h, "L%.1f %.1f ", x, y);
			px = x;
		}
		if (i == 0 && open)
			h_fmt(h, "L%.1f %d Z", px, PH);
		(void)x0;
		h_raw(h, "\"/>");
	}
}

static void
plot_open(struct html *h, const char *label, const char *top)
{

	h_raw(h, "<figure class=\"uplot\"><figcaption><b>");
	h_txt(h, label);
	h_raw(h, "</b><span class=\"dim\">");
	h_txt(h, top);
	h_fmt(h, "</span></figcaption><svg viewBox=\"0 0 %d %d\" "
	    "preserveAspectRatio=\"none\" aria-hidden=\"true\"><path class=\""
	    "grid\" d=\"M0 %.1f H%d M0 %.1f H%d M0 %.1f H%d\"/>", PW, PH,
	    PH * .25, PW, PH * .5, PW, PH * .75, PW);
}

static void
key(struct html *h, const char *colour, const char *name, const char *v)
{

	h_fmt(h, "<span class=\"ukey\"><i style=\"background:%s\"></i>",
	    colour);
	h_txt(h, name);
	h_raw(h, " <b>");
	h_txt(h, v);
	h_raw(h, "</b></span>");
}

/* Every host's field f in one plot, a line each. */
static void
compare(struct html *h, const char *label, int f, double t1, bool pct)
{
	const struct uhost	*u;
	char			 buf[48];
	double			 last, avg, peak, top;
	int			 i;

	top = 0;
	for (i = 0; i < app.nservers; i++)
		if ((u = uhost(app.servers[i].id, false)) != NULL && u->n >
		    0) {
			stats(u, f, t1, &last, &avg, &peak);
			if (peak > top)
				top = peak;
		}
	top = pct ? 100 : ceiling(top);
	snprintf(buf, sizeof(buf), pct ? "of 100%%" : "to %.4g", top);
	plot_open(h, label, pct ? "of 100%" : buf);
	for (i = 0; i < app.nservers; i++)
		if ((u = uhost(app.servers[i].id, false)) != NULL)
			line(h, u, f, t1, top, palette[i % nitems(palette)],
			    false, false);
	h_raw(h, "</svg><div class=\"ukeys\">");
	for (i = 0; i < app.nservers; i++) {
		if ((u = uhost(app.servers[i].id, false)) == NULL || u->n == 0)
			continue;
		stats(u, f, t1, &last, &avg, &peak);
		snprintf(buf, sizeof(buf), pct ? "%.0f%%" : "%.2f", last);
		key(h, palette[i % nitems(palette)], app.servers[i].name, buf);
	}
	h_raw(h, "</div></figure>");
}

/* One or two fields of one host, the first with its ground filled. */
static void
single(struct html *h, const struct uhost *u, const char *label, int f1,
    const char *n1, int f2, const char *n2, double t1, int unit)
{
	char	buf[64], a[24], b[24];
	double	last1, avg1, peak1, last2, avg2, peak2, top;

	stats(u, f1, t1, &last1, &avg1, &peak1);
	last2 = avg2 = peak2 = 0;
	if (f2 >= 0)
		stats(u, f2, t1, &last2, &avg2, &peak2);
	top = unit == 0 ? 100 : ceiling(peak1 > peak2 ? peak1 : peak2);
	if (unit == 0)
		snprintf(buf, sizeof(buf), "avg %.0f%% · peak %.0f%%", avg1,
		    peak1);
	else if (unit == 1)
		snprintf(buf, sizeof(buf), "avg %.2f · peak %.2f", avg1, peak1);
	else {
		if (unit == 2) {
			fmt_rate(a, sizeof(a), peak1 > peak2 ? peak1 : peak2);
		} else {
			fmt_size(a, sizeof(a), peak1 > peak2 ? peak1 : peak2);
			strlcat(a, "/s", sizeof(a));
		}
		snprintf(buf, sizeof(buf), "peak %s", a);
	}
	plot_open(h, label, buf);
	line(h, u, f1, t1, top, "var(--c1)", true, false);
	if (f2 >= 0)
		line(h, u, f2, t1, top, "var(--c2)", false, f1 == F_MEM);
	h_raw(h, "</svg><div class=\"ukeys\">");
	if (unit == 0) {
		snprintf(a, sizeof(a), "%.0f%%", last1);
		snprintf(b, sizeof(b), "%.0f%%", last2);
	} else if (unit == 1) {
		snprintf(a, sizeof(a), "%.2f", last1);
		snprintf(b, sizeof(b), "%.2f", last2);
	} else if (unit == 2) {
		fmt_rate(a, sizeof(a), last1);
		fmt_rate(b, sizeof(b), last2);
	} else {
		fmt_size(a, sizeof(a), last1);
		strlcat(a, "/s", sizeof(a));
		fmt_size(b, sizeof(b), last2);
		strlcat(b, "/s", sizeof(b));
	}
	key(h, "var(--c1)", n1, a);
	if (f2 >= 0 && !(f2 == F_SWAP && u->swap_total <= 0))
		key(h, "var(--c2)", n2, b);
	h_raw(h, "</div></figure>");
}

void
view_usage(struct html *h)
{
	static const struct {
		int		 secs;
		const char	*title;
	} windows[] = { { 300, "5 min" }, { 900, "15 min" }, { 3600, "1 hour" } };
	const struct uhost	*u;
	struct server		*s;
	char			 key_[32], buf[48];
	double			 t1;
	size_t			 w;
	int			 i, have;

	h_raw(h, "<section class=\"util\"><div class=\"toolbar\"><h3>"
	    "Utilization</h3><nav class=\"sub\">");
	for (w = 0; w < nitems(windows); w++)
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"usage-"
		    "window\" data-arg=\"%d\">%s</button>", window ==
		    windows[w].secs ? " on" : "", windows[w].secs,
		    windows[w].title);
	h_raw(h, "</nav><span class=\"age\">each agent samples itself every "
	    "5 s and keeps an hour</span></div>");
	if (app.nservers == 0) {
		h_raw(h, "<div class=\"empty\"><p>No host yet.</p></div>"
		    "</section>");
		return;
	}
	/* The plots end now, by the newest sample any host has. */
	t1 = 0;
	have = 0;
	for (i = 0; i < app.nservers; i++)
		if ((u = uhost(app.servers[i].id, false)) != NULL && u->n >
		    0) {
			have++;
			if (u->v[u->n - 1][F_T] > t1)
				t1 = u->v[u->n - 1][F_T];
		}
	if (have > 1) {
		h_raw(h, "<h4 class=\"family\">All hosts, over one another"
		    "</h4><div class=\"uplots compare\">");
		compare(h, "CPU", F_CPU, t1, true);
		compare(h, "Memory", F_MEM, t1, true);
		compare(h, "Load", F_LOAD, t1, false);
		h_raw(h, "</div>");
	}
	for (i = 0; i < app.nservers; i++) {
		s = &app.servers[i];
		u = uhost(s->id, false);
		snprintf(key_, sizeof(key_), "usage:%s", s->id);
		h_raw(h, "<section class=\"pane ucard\">");
		box_head(h, key_, "h4");
		h_raw(h, "<span class=\"uname\" data-act=\"select-server\"");
		h_attr(h, "data-arg", s->id);
		h_raw(h, " title=\"Open the host\">");
		h_txt(h, s->name);
		h_raw(h, "</span>");
		if (u != NULL && u->n > 0) {
			fmt_size(buf, sizeof(buf), u->mem_total);
			h_fmt(h, "<small class=\"dim\">%d CPUs · %s memory"
			    "</small>", u->ncpu, buf);
		}
		h_raw(h, "</h4>");
		if (box_shut(key_)) {
			h_raw(h, "</section>");
			continue;
		}
		if (u == NULL || u->n == 0) {
			h_raw(h, "<p class=\"dim\">");
			h_txt(h, u != NULL && u->error[0] != '\0' ? u->error :
			    s->failed ? "The host does not answer." :
			    "Reading…");
			h_raw(h, "</p></section>");
			continue;
		}
		if (u->error[0] != '\0') {
			h_raw(h, "<p class=\"dim\">Not read since: ");
			h_txt(h, u->error);
			h_raw(h, "</p>");
		}
		h_raw(h, "<div class=\"uplots\">");
		single(h, u, "CPU", F_CPU, "busy", -1, NULL, t1, 0);
		single(h, u, "Memory", F_MEM, "in use", F_SWAP, "swap", t1, 0);
		single(h, u, "Load", F_LOAD, "1 min", -1, NULL, t1, 1);
		single(h, u, "Network", F_RX, "in", F_TX, "out", t1, 2);
		single(h, u, "Disks", F_RD, "read", F_WR, "written", t1, 3);
		h_raw(h, "</div></section>");
	}
	h_raw(h, "</section>");
}

bool
usage_action(const char *act, const char *arg, const char *value)
{

	(void)value;
	if (strcmp(act, "select-usage") == 0) {
		usage_open();
		return (true);
	}
	if (strcmp(act, "usage-window") != 0)
		return (false);
	if (atoi(arg) == 300 || atoi(arg) == 900 || atoi(arg) == 3600)
		window = atoi(arg);
	return (true);
}
