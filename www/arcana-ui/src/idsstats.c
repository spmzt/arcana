/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Security, IDS/IPS: an intrusion detection's statistics, from the
 * stats records Suricata writes to eve.json (every 10 s unless told),
 * which the agent keeps an hour of: packets and drops, throughput,
 * alerts, memory and TCP sessions over time, its flows by protocol, and
 * of its latest alerts the signatures, sources and destinations seen
 * most.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	PW	300
#define	PH	70
#define	TOPS	8
#define	STATS_POINTS	400	/* the agent keeps 360 */

static char	open_name[40];

bool
idsstats_active(void)
{

	return (open_name[0] != '\0');
}

/* The index of a field in the agent's points; -1 when it has none. */
static int
field_at(const ucl_object_t *st, const char *name)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int			 i;

	i = 0;
	it = NULL;
	while ((e = ucl_object_iterate(jget(st, "fields"), &it, true)) !=
	    NULL) {
		if (strcmp(ucl_object_tostring(e), name) == 0)
			return (i);
		i++;
	}
	return (-1);
}

static double
pt(const ucl_object_t *p, int i)
{
	const ucl_object_t	*v;

	if (i < 0 || (v = ucl_array_find_index(p, (unsigned)i)) == NULL)
		return (-1);
	return ((double)ucl_object_toint(v));
}

/* A field's rate a second between points, or its value (rate false);
 * NAN where there is none (a restart: the totals went back). */
static int
series(const ucl_object_t *st, const char *name, bool rate, double mul,
    double *t, double *v, int max)
{
	const ucl_object_t	*arr, *a, *b;
	int			 f, ft, n, i, k;
	double			 dt, dv;

	arr = jget(st, "series");
	f = field_at(st, name);
	ft = field_at(st, "t");
	n = (int)ucl_array_size(arr);
	k = 0;
	for (i = rate ? 1 : 0; i < n && k < max; i++) {
		b = ucl_array_find_index(arr, (unsigned)i);
		t[k] = pt(b, ft);
		if (!rate) {
			v[k++] = pt(b, f) < 0 ? NAN : pt(b, f) * mul;
			continue;
		}
		a = ucl_array_find_index(arr, (unsigned)i - 1);
		dt = pt(b, ft) - pt(a, ft);
		dv = pt(b, f) - pt(a, f);
		v[k++] = dt <= 0 || dv < 0 || pt(a, f) < 0 || pt(b, f) < 0 ?
		    NAN : dv / dt * mul;
	}
	return (k);
}

static double
ceiling(double v)
{
	double	p;

	if (!(v > 0))
		return (1);
	p = pow(10, floor(log10(v)));
	return (v <= p ? p : v <= 2 * p ? 2 * p : v <= 5 * p ? 5 * p : 10 * p);
}

static void
human(char *buf, size_t len, double v, const char *unit)
{
	static const char *const si[] = { "", "k", "M", "G", "T" };
	int	i;

	if (isnan(v)) {
		snprintf(buf, len, "—");
		return;
	}
	for (i = 0; v >= 1000 && i < 4; i++)
		v /= 1000;
	snprintf(buf, len, v < 10 && v != floor(v) ? "%.1f %s%s" :
	    "%.0f %s%s", v, si[i], unit);
}

/* A line of the points, broken where there is none. */
static void
draw(struct html *h, const double *t, const double *v, int n, double t0,
    double t1, double top, const char *colour, bool area)
{
	double	x, y, px;
	int	i, k;
	bool	open;

	for (k = area ? 0 : 1; k < 2; k++) {
		h_fmt(h, "<path class=\"%s\" style=\"%s:%s\" d=\"", k == 0 ?
		    "area" : "line", k == 0 ? "fill" : "stroke", colour);
		open = false;
		px = 0;
		for (i = 0; i < n; i++) {
			if (isnan(v[i])) {
				if (open && k == 0)
					h_fmt(h, "L%.1f %d Z ", px, PH);
				open = false;
				continue;
			}
			x = t1 > t0 ? PW * (t[i] - t0) / (t1 - t0) : PW;
			y = v[i] / top;
			y = PH - (PH - 2) * (y > 1 ? 1 : y < 0 ? 0 : y);
			if (!open) {
				if (k == 0)
					h_fmt(h, "M%.1f %d L%.1f %.1f ", x, PH, x,
					    y);
				else
					h_fmt(h, "M%.1f %.1f ", x, y);
				open = true;
			} else
				h_fmt(h, "L%.1f %.1f ", x, y);
			px = x;
		}
		if (k == 0 && open)
			h_fmt(h, "L%.1f %d Z", px, PH);
		h_raw(h, "\"/>");
	}
}

static double
last_of(const double *v, int n)
{
	int	i;

	for (i = n - 1; i >= 0; i--)
		if (!isnan(v[i]))
			return (v[i]);
	return (NAN);
}

static double
max_of(const double *v, int n)
{
	double	m;
	int	i;

	m = 0;
	for (i = 0; i < n; i++)
		if (!isnan(v[i]) && v[i] > m)
			m = v[i];
	return (m);
}

/* A plot of one field, or two (the second a dashed line of its own). */
static void
plot(struct html *h, const ucl_object_t *st, const char *label,
    const char *f1, const char *n1, const char *f2, const char *n2,
    bool rate, double mul, const char *unit)
{
	double	t1v[STATS_POINTS], v1[STATS_POINTS], t2v[STATS_POINTS];
	double	v2[STATS_POINTS], top, t0, t1;
	char	a[32], b[32], tops[32];
	int	n, m;

	n = series(st, f1, rate, mul, t1v, v1, STATS_POINTS);
	m = f2 != NULL ? series(st, f2, rate, mul, t2v, v2, STATS_POINTS) :
	    0;
	top = ceiling(fmax(max_of(v1, n), max_of(v2, m)));
	t0 = n > 0 ? t1v[0] : 0;
	t1 = n > 0 ? t1v[n - 1] : 0;
	human(tops, sizeof(tops), top, unit);
	h_raw(h, "<figure class=\"uplot\"><figcaption><b>");
	h_txt(h, label);
	h_raw(h, "</b><span class=\"dim\">");
	h_txt(h, tops);
	h_fmt(h, "</span></figcaption><svg viewBox=\"0 0 %d %d\" "
	    "preserveAspectRatio=\"none\" aria-hidden=\"true\"><path class=\""
	    "grid\" d=\"M0 %.1f H%d M0 %.1f H%d M0 %.1f H%d\"/>", PW, PH,
	    PH * .25, PW, PH * .5, PW, PH * .75, PW);
	draw(h, t1v, v1, n, t0, t1, top, "var(--c1)", true);
	if (m > 0)
		draw(h, t2v, v2, m, t0, t1, top, "var(--c2)", false);
	h_raw(h, "</svg><div class=\"ukeys\">");
	human(a, sizeof(a), last_of(v1, n), unit);
	h_fmt(h, "<span class=\"ukey\"><i style=\"background:var(--c1)\"></i>"
	    "%s <b>%s</b></span>", n1, a);
	if (f2 != NULL) {
		human(b, sizeof(b), last_of(v2, m), unit);
		h_fmt(h, "<span class=\"ukey\"><i style=\"background:var(--c2)\">"
		    "</i>%s <b>%s</b></span>", n2, b);
	}
	h_raw(h, "</div></figure>");
}

/* The most seen of a key of the alerts, counted. */
static void
tops(struct html *h, const ucl_object_t *alerts, const char *key,
    const char *title)
{
	const ucl_object_t	*a;
	ucl_object_iter_t	 it;
	const char		*names[64];
	int			 counts[64], n, i, j, best;
	bool			 used[64];

	n = 0;
	it = NULL;
	while ((a = ucl_object_iterate(alerts, &it, true)) != NULL) {
		if (jstr(a, key) == NULL)
			continue;
		for (i = 0; i < n; i++)
			if (strcmp(names[i], jstr(a, key)) == 0)
				break;
		if (i == n && n < 64) {
			names[n] = jstr(a, key);
			counts[n++] = 0;
		}
		if (i < 64)
			counts[i]++;
	}
	h_raw(h, "<div class=\"idstop\"><h4>");
	h_txt(h, title);
	h_raw(h, "</h4>");
	if (n == 0) {
		h_raw(h, "<p class=\"dim\">None among its latest alerts.</p>"
		    "</div>");
		return;
	}
	memset(used, 0, sizeof(used));
	h_raw(h, "<ol>");
	for (j = 0; j < TOPS && j < n; j++) {
		best = -1;
		for (i = 0; i < n; i++)
			if (!used[i] && (best < 0 || counts[i] > counts[best]))
				best = i;
		used[best] = true;
		h_raw(h, "<li><span class=\"mono\">");
		h_txt(h, names[best]);
		h_fmt(h, "</span> <b>%d</b></li>", counts[best]);
	}
	h_raw(h, "</ol></div>");
}

/* Its flows by protocol, as bars, the most first. */
static void
flows(struct html *h, const ucl_object_t *fl)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*names[64];
	int64_t			 v[64], max;
	int			 n, i, j, best;
	bool			 used[64];

	n = 0;
	max = 1;
	it = NULL;
	while ((e = ucl_object_iterate(fl, &it, true)) != NULL && n < 64) {
		if (ucl_object_toint(e) <= 0)
			continue;
		names[n] = ucl_object_key(e);
		v[n] = ucl_object_toint(e);
		if (v[n] > max)
			max = v[n];
		n++;
	}
	h_raw(h, "<div class=\"idstop\"><h4>Flows by protocol</h4>");
	if (n == 0) {
		h_raw(h, "<p class=\"dim\">None told yet.</p></div>");
		return;
	}
	memset(used, 0, sizeof(used));
	h_raw(h, "<ul class=\"idsbars\">");
	for (j = 0; j < 12 && j < n; j++) {
		best = -1;
		for (i = 0; i < n; i++)
			if (!used[i] && (best < 0 || v[i] > v[best]))
				best = i;
		used[best] = true;
		h_raw(h, "<li><span class=\"mono\">");
		h_txt(h, names[best]);
		h_fmt(h, "</span><i style=\"width:%.1f%%\"></i><b>%lld</b></li>",
		    100.0 * (double)v[best] / (double)max, (long long)v[best]);
	}
	h_raw(h, "</ul></div>");
}

void
view_idsstats(struct html *h)
{
	const ucl_object_t	*l, *st, *last;
	char			 a[32], b[32];
	double			 pk, dr;
	int			 n;

	h_raw(h, "<div class=\"toolbar\"><button class=\"ghost\" data-act=\""
	    "ist-back\">← Instances</button><strong>");
	h_txt(h, open_name);
	h_raw(h, ": statistics</strong></div>");
	if ((l = sec_ids_live(open_name)) == NULL || (st = jget(l, "stats")) ==
	    NULL || (n = (int)ucl_array_size(jget(st, "series"))) == 0) {
		h_raw(h, "<div class=\"empty\"><p>No statistics yet.</p><p "
		    "class=\"dim\">Suricata writes them to eve.json every so "
		    "many seconds (Logging, in its form; 10 unless told), once "
		    "it runs.</p></div>");
		return;
	}
	last = ucl_array_find_index(jget(st, "series"), (unsigned)n - 1);
	pk = pt(last, field_at(st, "packets"));
	dr = pt(last, field_at(st, "drops"));
	human(a, sizeof(a), pk, "");
	human(b, sizeof(b), pt(last, field_at(st, "bytes")), "B");
	h_fmt(h, "<p class=\"dim\">Up %lld s: %s packets, %s; ",
	    (long long)pt(last, field_at(st, "uptime")), a, b);
	if (pk > 0 && dr >= 0)
		h_fmt(h, "%.2f%% dropped by the kernel before it saw them. ",
		    100.0 * dr / (pk + dr));
	h_raw(h, "Points every few seconds, the last hour's.</p>"
	    "<div class=\"uplots\">");
	plot(h, st, "Packets a second", "packets", "seen", "drops", "dropped",
	    true, 1, "/s");
	plot(h, st, "Throughput", "bytes", "bits", NULL, NULL, true, 8,
	    "b/s");
	plot(h, st, "Alerts a second", "alerts", "alerts", NULL, NULL, true,
	    1, "/s");
	plot(h, st, "Memory in use", "memuse", "flows, TCP, HTTP", NULL,
	    NULL, false, 1, "B");
	plot(h, st, "TCP sessions a second", "sessions", "new", "flows",
	    "flows", true, 1, "/s");
	h_raw(h, "</div><div class=\"idstops\">");
	flows(h, jget(st, "flows"));
	tops(h, jget(l, "alerts"), "signature", "Signatures");
	tops(h, jget(l, "alerts"), "src", "Sources");
	tops(h, jget(l, "alerts"), "dst", "Destinations");
	h_raw(h, "</div>");
}

bool
idsstats_action(const char *act, const char *arg)
{

	if (strcmp(act, "ist-open") == 0) {
		snprintf(open_name, sizeof(open_name), "%s", arg);
		render();
		return (true);
	}
	if (strcmp(act, "ist-back") == 0) {
		open_name[0] = '\0';
		render();
		return (true);
	}
	return (false);
}
