/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * How busy every host has been, drawn as lines over time: the CPUs,
 * the memory, the load, the network and the disks.  Each agent keeps
 * the last of it by itself, so the lines are there when the page is
 * opened; while it is shown, what came since is asked for and added.
 * The hosts are drawn over one another to be compared, and then each
 * by itself, where the network is all its interfaces or one of them,
 * and the disks likewise.  How often an agent samples and how much it
 * keeps is set here, with what that takes of its memory.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	nitems(x)	(sizeof(x) / sizeof((x)[0]))

#define	USAGE_EVERY	5000	/* ms between two looks */
#define	NF		9	/* what a sample begins with */
#define	DEVS		16	/* interfaces, and disks, told apart */
#define	DEVNAME		24
#define	PW		300	/* a plot's box */
#define	PH		70

enum { F_T, F_CPU, F_LOAD, F_MEM, F_SWAP, F_RX, F_TX, F_RD, F_WR };

struct uhost {
	char	 sid[9];
	double	*v;		/* keep rows of stride */
	int	 n, stride;
	double	 mem_total, swap_total, bytes;
	int	 ncpu, step, keep;
	int	 lim[3];	/* cpu, mem, swap, in percent; 0 none */
	char	 nets[DEVS][DEVNAME], disks[DEVS][DEVNAME];
	char	 jails[DEVS][DEVNAME];	/* told apart when racct is on */
	int	 nn, nd, nj;
	char	 net[DEVNAME], disk[DEVNAME];	/* the one drawn, "" all */
	char	 jail[DEVNAME];		/* the jail drawn, "" the first */
	bool	 racct;			/* the kernel accounts for jails */
	char	 rules[1024];		/* limits of devices and jails, a line
					   each */
	bool	 known;		/* how it samples was said */
	bool	 cfg;		/* how it samples is being set */
	bool	 loading;
	double	 asked;
	char	 error[160];
};

static struct uhost	uh[MAX_SERVERS];
static int		window = 900;	/* s shown; 0 all that is kept */
static int		span = 900;	/* what that is now */

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

/* The names of arr into v; true when they are not what was there. */
static bool
devs(const ucl_object_t *arr, char v[DEVS][DEVNAME], int *n)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	const char		*name;
	int			 k;
	bool			 other;

	other = false;
	k = 0;
	it = NULL;
	while ((o = ucl_object_iterate(arr, &it, true)) != NULL && k < DEVS) {
		name = ucl_object_tostring_forced(o);
		if (k >= *n || strcmp(v[k], name) != 0)
			other = true;
		snprintf(v[k++], DEVNAME, "%s", name);
	}
	if (k != *n)
		other = true;
	*n = k;
	return (other);
}

static void
usage_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*d, *row, *f;
	ucl_object_iter_t	 it, fit;
	struct uhost		*u;
	char			*sid;
	double			*s;
	int			 k, keep;
	bool			 other;

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
	u->known = true;
	u->mem_total = jnum(d, "mem_total", 0);
	u->swap_total = jnum(d, "swap_total", 0);
	u->bytes = jnum(d, "bytes", 0);
	u->ncpu = (int)jint(d, "ncpu", 1);
	u->step = (int)jint(d, "step", 5);
	u->lim[0] = (int)jint(jget(d, "limits"), "cpu", 0);
	u->lim[1] = (int)jint(jget(d, "limits"), "mem", 0);
	u->lim[2] = (int)jint(jget(d, "limits"), "swap", 0);
	keep = (int)jint(d, "keep", 720);
	other = devs(jget(d, "nets"), u->nets, &u->nn);
	other = devs(jget(d, "disks"), u->disks, &u->nd) || other;
	other = devs(jget(d, "jails"), u->jails, &u->nj) || other;
	u->racct = jbool(d, "racct");
	/* The rules as they are typed: "net:igb0=125000000", a line each. */
	{
		const ucl_object_t	*r;
		ucl_object_iter_t	 rit;
		size_t			 len;

		u->rules[0] = '\0';
		rit = NULL;
		while ((r = ucl_object_iterate(jget(d, "rules"), &rit,
		    true)) != NULL) {
			len = strlen(u->rules);
			snprintf(u->rules + len, sizeof(u->rules) - len,
			    "%s%s:%s=%.0f", len > 0 ? "\n" : "", jstr(r,
			    "kind"), jstr(r, "name"), jnum(r, "limit", 0));
		}
	}
	/*
	 * Rows of another width, or another number of them: what is
	 * here is let go, and all of it asked for anew.
	 */
	if (other || keep != u->keep || u->v == NULL) {
		free(u->v);
		u->keep = keep;
		u->stride = NF + 2 * (u->nn + u->nd + u->nj);
		u->v = calloc((size_t)(keep > 0 ? keep : 1) *
		    (size_t)u->stride, sizeof(*u->v));
		if (u->v == NULL)
			abort();
		other = u->n > 0;
		u->n = 0;
		if (other) {
			u->asked = 0;
			return;
		}
	}
	it = NULL;
	while (u->keep > 0 && (row = ucl_object_iterate(jget(d, "samples"),
	    &it, true)) != NULL) {
		if ((int)ucl_array_size(row) != u->stride)
			continue;
		if (u->n == u->keep) {
			memmove(u->v, u->v + u->stride, (size_t)(u->keep - 1) *
			    (size_t)u->stride * sizeof(*u->v));
			u->n--;
		}
		s = u->v + (size_t)u->n * (size_t)u->stride;
		fit = NULL;
		for (k = 0; k < u->stride && (f = ucl_object_iterate(row,
		    &fit, true)) != NULL; k++)
			s[k] = ucl_object_todouble(f);
		if (u->n > 0 && s[F_T] <= s[F_T - u->stride])
			continue;
		u->n++;
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
	    u->n > 0 ? u->v[(u->n - 1) * u->stride + F_T] : 0.0);
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

	/* Also while a nexthop group's shares are drawn from them. */
	if ((app.node != NODE_USAGE && !ecmp_shown()) || !app.visible)
		return;
	for (i = 0; i < app.nservers; i++) {
		u = uhost(app.servers[i].id, false);
		/* A request nobody answered is given up after a while. */
		if (u != NULL && u->loading && now - u->asked > 30000)
			u->loading = false;
		/* No oftener than the agent itself looks. */
		if (u == NULL || (!u->loading && now - u->asked >=
		    (u->step * 1000 > USAGE_EVERY && u->asked != 0 ?
		    u->step * 1000 : USAGE_EVERY)))
			usage_poll(&app.servers[i], now);
	}
}

/* Sample i of the host: its time first. */
#define	T(u, i)	((u)->v + (size_t)(i) * (size_t)(u)->stride)

/*
 * The samples of one interface of a host since t0 (seconds), bytes a
 * second in or out, the oldest first, at most max of them: how many,
 * or -1 when the agent does not sample that interface (or has not said
 * yet what it samples).
 */
int
usage_if_rates(const char *sid, const char *ifname, bool out, double t0,
    double *t, double *v, int max)
{
	const struct uhost	*u;
	int			 k, i, n;

	if ((u = uhost(sid, false)) == NULL || !u->known)
		return (-1);
	for (k = 0; k < u->nn && strcmp(u->nets[k], ifname) != 0; k++)
		;
	if (k == u->nn)
		return (-1);
	n = 0;
	for (i = 0; i < u->n && n < max; i++) {
		if (T(u, i)[F_T] < t0)
			continue;
		t[n] = T(u, i)[F_T];
		v[n++] = T(u, i)[NF + 2 * k + (out ? 1 : 0)];
	}
	return (n);
}

/* How often a host's agent samples, in seconds; 0 not known yet. */
int
usage_step(const char *sid)
{
	const struct uhost	*u;

	return ((u = uhost(sid, false)) != NULL && u->known ? u->step : 0);
}

/* What field f of sample i is, in what it is drawn in. */
static double
value(const struct uhost *u, int i, int f)
{

	switch (f) {
	case F_MEM:
		return (u->mem_total > 0 ? 100 * T(u, i)[F_MEM] /
		    u->mem_total : 0);
	case F_SWAP:
		return (u->swap_total > 0 ? 100 * T(u, i)[F_SWAP] /
		    u->swap_total : 0);
	default:
		return (T(u, i)[f]);
	}
}

/* The first sample of the window that ends at t1. */
static int
first(const struct uhost *u, double t1)
{
	int	i;

	for (i = u->n; i > 0 && T(u, i - 1)[F_T] >= t1 - span; i--)
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
			x = PW * (1 - (t1 - T(u, k)[F_T]) / span);
			y = value(u, k, f) / top;
			y = PH - (PH - 2) * (y > 1 ? 1 : y < 0 ? 0 : y);
			/* A gap the host was away: wider than the looks
			 * around it, which further back are thinned. */
			if (open && T(u, k)[F_T] - T(u, k - 1)[F_T] > 4 *
			    fmax(u->step > 0 ? u->step : 5, k >= 2 ?
			    T(u, k - 1)[F_T] - T(u, k - 2)[F_T] : 0)) {
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
	top = unit == 0 ? 100 : unit == 4 ? (peak1 > 100 ? ceiling(peak1) :
	    100) : ceiling(peak1 > peak2 ? peak1 : peak2);
	if (unit == 0)
		snprintf(buf, sizeof(buf), "avg %.0f%% · peak %.0f%%", avg1,
		    peak1);
	else if (unit == 1)
		snprintf(buf, sizeof(buf), "avg %.2f · peak %.2f", avg1, peak1);
	else if (unit == 4)
		snprintf(buf, sizeof(buf), "avg %.0f%% · peak %.0f%% of a CPU",
		    avg1, peak1);
	else if (unit == 5) {
		fmt_size(a, sizeof(a), peak1);
		snprintf(buf, sizeof(buf), "peak %s", a);
	} else {
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
	if (unit == 0 || unit == 4) {
		snprintf(a, sizeof(a), "%.0f%%", last1);
		snprintf(b, sizeof(b), "%.0f%%", last2);
	} else if (unit == 5) {
		fmt_size(a, sizeof(a), last1);
		fmt_size(b, sizeof(b), last2);
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

/* The interfaces or the disks of a host, to pick the one drawn. */
static void
picker(struct html *h, const struct uhost *u, const char *act,
    char names[DEVS][DEVNAME], int n, int base, const char *picked,
    double t1, bool rate)
{
	char	buf[32];
	double	last, avg, peak, l2;
	int	k;

	h_fmt(h, "<div class=\"upick\"><button class=\"ghost small%s\" "
	    "data-act=\"%s\" data-value=\"\"", picked[0] == '\0' ? " on" : "",
	    act);
	h_attr(h, "data-arg", u->sid);
	h_fmt(h, " title=\"All %d of them, added up\">all %d</button>", n, n);
	for (k = 0; k < n; k++) {
		stats(u, base + 2 * k, t1, &last, &avg, &peak);
		l2 = last;
		stats(u, base + 2 * k + 1, t1, &last, &avg, &peak);
		h_fmt(h, "<button class=\"ghost small%s%s\" data-act=\"%s\"",
		    strcmp(picked, names[k]) == 0 ? " on" : "", l2 + last <=
		    0 ? " idle" : "", act);
		h_attr(h, "data-arg", u->sid);
		h_attr(h, "data-value", names[k]);
		h_raw(h, ">");
		h_txt(h, names[k]);
		if (l2 + last > 0) {
			if (rate)
				fmt_rate(buf, sizeof(buf), l2 + last);
			else {
				fmt_size(buf, sizeof(buf), l2 + last);
				strlcat(buf, "/s", sizeof(buf));
			}
			h_raw(h, " <small>");
			h_txt(h, buf);
			h_raw(h, "</small>");
		}
		h_raw(h, "</button>");
	}
	h_raw(h, "</div>");
}

/* The place of the one picked among the names, or -1 for all. */
static int
picked_at(char names[DEVS][DEVNAME], int n, const char *picked)
{
	int	k;

	for (k = 0; k < n; k++)
		if (picked[0] != '\0' && strcmp(names[k], picked) == 0)
			return (k);
	return (-1);
}

/* The jails, to pick the one drawn: each with its CPU now. */
static void
jail_picker(struct html *h, const struct uhost *u, int on, double t1)
{
	char	buf[48], mem[24];
	double	last, avg, peak, m;
	int	k, base;

	base = NF + 2 * (u->nn + u->nd);
	h_raw(h, "<div class=\"upick\">");
	for (k = 0; k < u->nj; k++) {
		stats(u, base + 2 * k + 1, t1, &m, &avg, &peak);
		stats(u, base + 2 * k, t1, &last, &avg, &peak);
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\""
		    "usage-jail\"", k == on ? " on" : "");
		h_attr(h, "data-arg", u->sid);
		h_attr(h, "data-value", u->jails[k]);
		h_raw(h, ">");
		h_txt(h, u->jails[k]);
		fmt_size(mem, sizeof(mem), m);
		snprintf(buf, sizeof(buf), " %.0f%% · %s", last, mem);
		h_raw(h, "<small>");
		h_txt(h, buf);
		h_raw(h, "</small></button>");
	}
	h_raw(h, "</div>");
}

/* How the agent samples the host, said and set. */
static void
sampling(struct html *h, const struct uhost *u)
{
	char	buf[32];

	h_raw(h, "<form data-form=\"usage-set\" class=\"usample\"><input "
	    "type=\"hidden\" name=\"sid\"");
	h_attr(h, "value", u->sid);
	h_fmt(h, "><label>Sample every<input name=\"step\" type=\"number\" "
	    "min=\"1\" max=\"3600\" value=\"%d\">s</label><label>and keep"
	    "<input name=\"keep\" type=\"number\" min=\"0\" max=\"5000\" "
	    "value=\"%d\">samples</label><label>An event when CPU is over"
	    "<input name=\"cpu\" type=\"number\" min=\"0\" max=\"100\" "
	    "value=\"%d\">%%</label><label>memory over<input name=\"mem\" "
	    "type=\"number\" min=\"0\" max=\"100\" value=\"%d\">%%</label>"
	    "<label>swap over<input name=\"swap\" type=\"number\" min=\"0\" "
	    "max=\"100\" value=\"%d\">%%</label>", u->step, u->keep,
	    u->lim[0], u->lim[1], u->lim[2]);
	/* The limits of one interface, disk or jail each. */
	h_raw(h, "<label class=\"rules\">Limits of an interface, a disk or a "
	    "jail<textarea name=\"rules\" rows=\"3\" spellcheck=\"false\" "
	    "placeholder=\"net:igb0=125000000&#10;disk:ada0=50000000&#10;"
	    "jail-cpu:web=80&#10;jail-mem:web=1073741824\">");
	h_txt(h, u->rules);
	h_raw(h, "</textarea><small>One a line: <code>net:</code> and an "
	    "interface, bytes a second in and out; <code>disk:</code> and a "
	    "disk, bytes a second read and written; <code>jail-cpu:</code> "
	    "and a jail, percent of one CPU; <code>jail-mem:</code> and a "
	    "jail, bytes.</small></label><button class=\"small\">Set"
	    "</button><button type=\"button\" class=\"ghost small\" "
	    "data-act=\"usage-cfg\"");
	h_attr(h, "data-arg", u->sid);
	fmt_size(buf, sizeof(buf), u->bytes);
	h_fmt(h, ">Close</button><small class=\"dim\">Now %s of the agent's "
	    "memory: 8 bytes a sample, and 4 for each figure in it, of "
	    "which there are %d here with %d interfaces, %d disks and %d "
	    "jails. With 0 kept the agent does not sample and holds nothing. "
	    "It keeps this for its next start, and the samples with it. A "
	    "limit crossed, either way, is an event, listed under events in "
	    "the Log tab; 0 is no limit.</small></form>", buf, u->stride - 1,
	    u->nn, u->nd, u->nj);
}

void
view_usage(struct html *h)
{
	static const struct {
		int		 secs;
		const char	*title;
	} windows[] = { { 300, "5 min" }, { 900, "15 min" },
	    { 3600, "1 hour" }, { 0, "all kept" } };
	struct uhost		*u;
	struct server		*s;
	char			 key_[32], buf[48], label[64];
	double			 t1;
	size_t			 w;
	int			 i, have, k;

	h_raw(h, "<section class=\"util\"><div class=\"toolbar\"><h3>"
	    "Utilization</h3><nav class=\"sub\">");
	for (w = 0; w < nitems(windows); w++)
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"usage-"
		    "window\" data-arg=\"%d\">%s</button>", window ==
		    windows[w].secs ? " on" : "", windows[w].secs,
		    windows[w].title);
	h_raw(h, "</nav><span class=\"age\">each agent samples its host by "
	    "itself; how often and how much is set at each host</span>"
	    "</div>");
	if (app.nservers == 0) {
		h_raw(h, "<div class=\"empty\"><p>No host yet.</p></div>"
		    "</section>");
		return;
	}
	/* The plots end now, by the newest sample any host has. */
	t1 = 0;
	have = 0;
	span = window;
	for (i = 0; i < app.nservers; i++)
		if ((u = uhost(app.servers[i].id, false)) != NULL && u->n >
		    0) {
			have++;
			if (T(u, u->n - 1)[F_T] > t1)
				t1 = T(u, u->n - 1)[F_T];
			if (window == 0 && u->step * u->keep > span)
				span = u->step * u->keep;
			/* Thinned, the oldest look is further back. */
			if (window == 0 && t1 - T(u, 0)[F_T] > span)
				span = t1 - T(u, 0)[F_T];
		}
	if (span <= 0)
		span = 900;
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
		if (u != NULL && u->known) {
			fmt_size(buf, sizeof(buf), u->bytes);
			if (u->keep > 0)
				h_fmt(h, "<small class=\"dim\">%d CPUs · every "
				    "%d s, %d kept (%.3g h) · %s in the agent"
				    "</small>", u->ncpu, u->step, u->keep,
				    (double)u->step * u->keep / 3600, buf);
			else
				h_raw(h, "<small class=\"dim\">not sampled"
				    "</small>");
			h_fmt(h, "<button class=\"ghost small%s\" data-act=\""
			    "usage-cfg\"", u->cfg ? " on" : "");
			h_attr(h, "data-arg", s->id);
			h_raw(h, " title=\"How often the agent samples this "
			    "host, and how much it keeps\">Sampling</button>");
		}
		h_raw(h, "</h4>");
		if (box_shut(key_)) {
			h_raw(h, "</section>");
			continue;
		}
		if (u != NULL && u->known && (u->cfg || u->keep == 0))
			sampling(h, u);
		if (u == NULL || u->n == 0) {
			h_raw(h, "<p class=\"dim\">");
			h_txt(h, u != NULL && u->error[0] != '\0' ? u->error :
			    s->failed ? "The host does not answer." :
			    u != NULL && u->known && u->keep == 0 ?
			    "The agent keeps no samples of this host: say "
			    "how many it should." : u != NULL && u->known ?
			    "No sample yet." : "Reading…");
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
		h_raw(h, "</div><div class=\"uplots wide\"><div>");
		k = picked_at(u->nets, u->nn, u->net);
		if (k >= 0)
			snprintf(label, sizeof(label), "Network · %s",
			    u->nets[k]);
		else
			snprintf(label, sizeof(label), "Network · all %d "
			    "interfaces", u->nn);
		single(h, u, label, k >= 0 ? NF + 2 * k : F_RX, "in", k >= 0 ?
		    NF + 2 * k + 1 : F_TX, "out", t1, 2);
		picker(h, u, "usage-net", u->nets, u->nn, NF, k >= 0 ? u->net :
		    "", t1, true);
		h_raw(h, "</div><div>");
		k = picked_at(u->disks, u->nd, u->disk);
		if (k >= 0)
			snprintf(label, sizeof(label), "Disks · %s",
			    u->disks[k]);
		else
			snprintf(label, sizeof(label), "Disks · all %d",
			    u->nd);
		single(h, u, label, k >= 0 ? NF + 2 * (u->nn + k) : F_RD,
		    "read", k >= 0 ? NF + 2 * (u->nn + k) + 1 : F_WR,
		    "written", t1, 3);
		picker(h, u, "usage-disk", u->disks, u->nd, NF + 2 * u->nn,
		    k >= 0 ? u->disk : "", t1, false);
		h_raw(h, "</div></div>");
		/* Each jail's own, as the kernel accounts for it. */
		if (!u->racct)
			h_raw(h, "<p class=\"dim ujails\">Each jail's share of "
			    "the CPUs and its memory are shown once the kernel "
			    "accounts for them: <code>kern.racct.enable=1</code> "
			    "in <code>/boot/loader.conf</code>, and a reboot.</p>");
		else if (u->nj > 0) {
			k = picked_at(u->jails, u->nj, u->jail);
			if (k < 0)
				k = 0;
			h_raw(h, "<div class=\"uplots wide ujails\"><div>");
			snprintf(label, sizeof(label), "Jail CPU · %s",
			    u->jails[k]);
			single(h, u, label, NF + 2 * (u->nn + u->nd + k), "busy",
			    -1, NULL, t1, 4);
			h_raw(h, "</div><div>");
			snprintf(label, sizeof(label), "Jail memory · %s",
			    u->jails[k]);
			single(h, u, label, NF + 2 * (u->nn + u->nd + k) + 1,
			    "in use", -1, NULL, t1, 5);
			h_raw(h, "</div></div>");
			jail_picker(h, u, k, t1);
		}
		h_raw(h, "</section>");
	}
	h_raw(h, "</section>");
}

bool
usage_form(const char *form, const ucl_object_t *f)
{
	struct uhost	*u;
	const char	*sid;
	char		 url[96], body[1300];
	int		 step, keep, lim[3], k;

	if (strcmp(form, "usage-set") != 0)
		return (false);
	sid = jstr(f, "sid") != NULL ? jstr(f, "sid") : "";
	if ((u = uhost(sid, false)) == NULL)
		return (true);
	step = atoi(jstr(f, "step") != NULL ? jstr(f, "step") : "");
	keep = jstr(f, "keep") != NULL && jstr(f, "keep")[0] != '\0' ?
	    atoi(jstr(f, "keep")) : -1;
	if (step < 1 || step > 3600 || keep < 0 || keep > 5000) {
		toast(true, "Every 1 to 3600 seconds, and 0 to 5000 kept");
		return (true);
	}
	for (k = 0; k < 3; k++) {
		const char	*v = jstr(f, k == 0 ? "cpu" : k == 1 ? "mem" :
		    "swap");

		lim[k] = v != NULL && v[0] != '\0' ? atoi(v) : 0;
		if (lim[k] < 0 || lim[k] > 100) {
			toast(true, "A limit is 0 to 100 percent");
			return (true);
		}
	}
	/* The rules a line each, as the agent takes them: with commas. */
	{
		const char	*r;
		char		 list[1100], *q;
		size_t		 n;

		r = jstr(f, "rules") != NULL ? jstr(f, "rules") : "";
		for (n = 0; *r != '\0' && n < sizeof(list) - 1; r++)
			if (*r == '\n' || *r == '\r' || *r == ',') {
				if (n > 0 && list[n - 1] != ',')
					list[n++] = ',';
			} else if (*r != ' ' && *r != '\t')
				list[n++] = *r;
		while (n > 0 && list[n - 1] == ',')
			n--;
		list[n] = '\0';
		q = json_quote(list);
		snprintf(url, sizeof(url), "/api/servers/%s/history", u->sid);
		snprintf(body, sizeof(body), "{\"step\":%d,\"keep\":%d,"
		    "\"cpu\":%d,\"mem\":%d,\"swap\":%d,\"rules\":%s}", step,
		    keep, lim[0], lim[1], lim[2], q);
		free(q);
	}
	u->loading = true;
	u->asked = arc_now();
	u->cfg = false;
	api("POST", url, body, usage_cb, strdup(u->sid));
	return (true);
}

bool
usage_action(const char *act, const char *arg, const char *value)
{
	struct uhost	*u;

	if (strcmp(act, "select-usage") == 0) {
		usage_open();
		return (true);
	}
	if (strncmp(act, "usage-", 6) != 0)
		return (false);
	if (strcmp(act, "usage-window") == 0) {
		if (atoi(arg) == 300 || atoi(arg) == 900 || atoi(arg) ==
		    3600 || atoi(arg) == 0)
			window = atoi(arg);
	} else if ((u = uhost(arg, false)) == NULL) {
		;
	} else if (strcmp(act, "usage-cfg") == 0) {
		u->cfg = !u->cfg;
	} else if (strcmp(act, "usage-net") == 0) {
		snprintf(u->net, sizeof(u->net), "%s", value);
	} else if (strcmp(act, "usage-disk") == 0) {
		snprintf(u->disk, sizeof(u->disk), "%s", value);
	} else if (strcmp(act, "usage-jail") == 0) {
		snprintf(u->jail, sizeof(u->jail), "%s", value);
	}
	return (true);
}
