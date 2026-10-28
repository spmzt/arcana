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
 * most.  Where Suricata is built with --enable-profiling, its packets'
 * ticks per protocol and per stage, and its rules', as its profiling
 * wrote them; a capture from this computer sent to the host and
 * replayed; the files of its pcap-log to download.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "app.h"

#define	PW	300
#define	PH	70
#define	TOPS	8
#define	STATS_POINTS	400	/* the agent keeps 360 */

static char	open_name[40];

static void	view_engine(struct html *, const ucl_object_t *,
		    const ucl_object_t *);
static void	view_replay(struct html *, const ucl_object_t *);
static void	view_profiling(struct html *);

/* What its profiling wrote, as the host read it; the rows of its
 * packets' tables and its rules', one table each, made when it came. */
static struct {
	ucl_object_t	*o;
	ucl_object_t	*rows[2];	/* packets: running, replay */
	ucl_object_t	*rules[2];
	char		 error[256];
	char		 filter[64];
	bool		 loading;
	unsigned	 gen;
} prof;

/* A capture going up from this computer, then replayed. */
static struct {
	char		 name[160];
	long long	 sent, size;
	char		 error[256];
	bool		 busy;
} up;

/* Suricata's answers by its socket, a command each, of open_name. */
static const char *const asks[] = { "memcap-list", "ruleset-stats",
    "ruleset-failed-rules", "uptime" };
static struct {
	ucl_object_t	*ans[8];	/* asks', then ruleset-profile */
	ucl_object_t	*ifs;		/* iface-stat of each, an object */
	char		 error[256];
	unsigned	 gen;
} eng;

static void
eng_clear(void)
{
	size_t	i;

	for (i = 0; i < nitems(eng.ans); i++) {
		if (eng.ans[i] != NULL)
			ucl_object_unref(eng.ans[i]);
		eng.ans[i] = NULL;
	}
	if (eng.ifs != NULL)
		ucl_object_unref(eng.ifs);
	eng.ifs = NULL;
	eng.error[0] = '\0';
	eng.gen++;
}

/* arg: the slot (0.. of asks, 7 the profile, 100+ an interface's). */
static void
eng_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	uintptr_t		 a = (uintptr_t)arg;
	unsigned		 gen = (unsigned)(a >> 16), slot = a & 0xffff;
	const ucl_object_t	*d;

	if (gen != (eng.gen & 0xffff))
		return;
	if (status != 200 || !jbool(o, "ok")) {
		snprintf(eng.error, sizeof(eng.error), "%s", jstr(o, "error") !=
		    NULL ? jstr(o, "error") : err != NULL ? err :
		    "the host did not answer");
		render();
		return;
	}
	d = jget(o, "data");
	if (slot >= 100) {
		if (eng.ifs == NULL)
			eng.ifs = ucl_object_typed_new(UCL_ARRAY);
		if (d != NULL)
			ucl_array_append(eng.ifs, ucl_object_copy(d));
	} else if (slot < nitems(eng.ans) && d != NULL) {
		if (eng.ans[slot] != NULL)
			ucl_object_unref(eng.ans[slot]);
		eng.ans[slot] = ucl_object_copy(d);
	}
	render();
}

static void
eng_ask(const char *cmd, const char *ifn, unsigned slot)
{
	char	url[256];

	snprintf(url, sizeof(url), "/api/servers/%s/suricata/rules?instance="
	    "%s&command=%s%s%s", sec_host_id(), open_name, cmd, ifn != NULL ?
	    "&iface=" : "", ifn != NULL ? ifn : "");
	api("GET", url, NULL, eng_cb, (void *)(uintptr_t)(((uintptr_t)(
	    eng.gen & 0xffff) << 16) | slot));
}

static void
prof_clear(void)
{
	size_t	i;

	if (prof.o != NULL)
		ucl_object_unref(prof.o);
	prof.o = NULL;
	for (i = 0; i < 2; i++) {
		if (prof.rows[i] != NULL)
			ucl_object_unref(prof.rows[i]);
		if (prof.rules[i] != NULL)
			ucl_object_unref(prof.rules[i]);
		prof.rows[i] = prof.rules[i] = NULL;
	}
	prof.error[0] = '\0';
	prof.loading = false;
	prof.gen++;
}

/* The host changed: no instance of the one before is open. */
void
idsstats_reset(void)
{

	open_name[0] = '\0';
	eng_clear();
	prof_clear();
	memset(&up, 0, sizeof(up));
}

/* Each table of a dump's packets, its rows as one, each with its
 * table's title. */
static ucl_object_t *
prof_flat(const ucl_object_t *packets)
{
	const ucl_object_t	*s, *r;
	ucl_object_iter_t	 it, rit;
	ucl_object_t		*arr, *c;

	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((s = ucl_object_iterate(jget(packets, "sections"), &it,
	    true)) != NULL) {
		rit = NULL;
		while ((r = ucl_object_iterate(jget(s, "rows"), &rit, true)) !=
		    NULL) {
			c = ucl_object_copy(r);
			ucl_object_insert_key(c, ucl_object_fromstring(jstr(s,
			    "title")), "section", 0, true);
			ucl_array_append(arr, c);
		}
	}
	return (arr);
}

static void
prof_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*d, *w;
	size_t			 i;

	if ((unsigned)(uintptr_t)arg != prof.gen)
		return;
	prof.loading = false;
	if (status != 200 || !jbool(o, "ok") || (d = jget(o, "data")) ==
	    NULL) {
		snprintf(prof.error, sizeof(prof.error), "%s", jstr(o, "error")
		    != NULL ? jstr(o, "error") : err != NULL ? err :
		    "the host did not answer");
		render();
		return;
	}
	prof.o = ucl_object_copy(d);
	for (i = 0; i < 2; i++) {
		w = jget(prof.o, i == 0 ? "running" : "replay");
		prof.rows[i] = prof_flat(jget(w, "packets"));
		prof.rules[i] = jget(jget(w, "rules"), "rules") != NULL ?
		    ucl_object_copy(jget(jget(w, "rules"), "rules")) :
		    ucl_object_typed_new(UCL_ARRAY);
	}
	render();
}

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
	view_engine(h, l, st);
	view_profiling(h);
	view_replay(h, l);
}

/* A capture's replay through the open instance, a suricata job. */
static void
replay_job(const char *file)
{
	char	*json, *a, *b, *qa, *qb, title[300];

	if (asprintf(&a, "instance=%s", open_name) == -1 || asprintf(&b,
	    "file=%s", file) == -1)
		abort();
	qa = json_quote(a);
	qb = json_quote(b);
	if (asprintf(&json, "{\"kind\":\"suricata\",\"verb\":\"pcap\","
	    "\"args\":[%s,%s]}", qa, qb) == -1)
		abort();
	free(qa);
	free(qb);
	snprintf(title, sizeof(title), "suricata replays %s through %s", file,
	    open_name);
	sec_job(json, title);
	free(a);
	free(b);
}

/* A capture going up: its progress, the console's word on it, and its
 * replay once it is there. */
static void
upload_said(const char *name, const char *value)
{
	ucl_object_t	*o;
	char		 err[128];

	err[0] = '\0';
	if ((o = data_parse(value, err, sizeof(err))) == NULL)
		return;
	snprintf(up.name, sizeof(up.name), "%s", name);
	if (jstr(o, "error") != NULL) {
		snprintf(up.error, sizeof(up.error), "%s", jstr(o, "error"));
		up.busy = false;
	} else if (jget(o, "sent") != NULL) {
		up.error[0] = '\0';
		up.busy = true;
		up.sent = jint(o, "sent", 0);
		up.size = jint(o, "size", 0);
	} else if (jbool(o, "ok") && jstr(o, "path") != NULL) {
		up.busy = false;
		up.sent = up.size;
		replay_job(jstr(o, "path"));
	}
	ucl_object_unref(o);
	render();
}

bool
idsstats_action(const char *act, const char *arg, const char *value)
{
	const ucl_object_t	*l, *e;
	ucl_object_iter_t	 it;
	char			 url[256];
	size_t			 i;
	unsigned		 k;

	if (strcmp(act, "ist-open") == 0) {
		snprintf(open_name, sizeof(open_name), "%s", arg);
		eng_clear();
		prof_clear();
		memset(&up, 0, sizeof(up));
		render();
		return (true);
	}
	if (strcmp(act, "ist-back") == 0) {
		open_name[0] = '\0';
		eng_clear();
		prof_clear();
		render();
		return (true);
	}
	if (strcmp(act, "ist-prof") == 0) {
		prof_clear();
		prof.loading = true;
		snprintf(url, sizeof(url), "/api/servers/%s/suricata/rules?"
		    "instance=%s&profiling=1", sec_host_id(), open_name);
		api("GET", url, NULL, prof_cb, (void *)(uintptr_t)prof.gen);
		render();
		return (true);
	}
	if (strcmp(act, "input:ist-pfilter") == 0) {
		snprintf(prof.filter, sizeof(prof.filter), "%s", value);
		render();
		return (true);
	}
	if (strcmp(act, "upload:ist-capture") == 0) {
		upload_said(arg, value);
		return (true);
	}
	if (strcmp(act, "ist-replay-cap") == 0) {
		replay_job(arg);
		return (true);
	}
	if (strcmp(act, "ist-ask") == 0) {
		eng_clear();
		for (i = 0; i < nitems(asks); i++)
			eng_ask(asks[i], NULL, (unsigned)i);
		k = 100;
		if ((l = sec_ids_live(open_name)) != NULL) {
			it = NULL;
			while ((e = ucl_object_iterate(jget(l, "interfaces"),
			    &it, true)) != NULL)
				eng_ask("iface-stat", ucl_object_tostring(e), k++);
		}
		render();
		return (true);
	}
	if (strcmp(act, "ist-profile") == 0) {
		eng_ask("ruleset-profile", NULL, 7);
		return (true);
	}
	return (false);
}

/* A size Suricata says (64mb, 1gb, unlimited) in bytes; 0 none. */
static double
size_of(const char *v)
{
	double	n;
	char	*end;

	if (v == NULL || (n = strtod(v, &end)) <= 0)
		return (0);
	if (strcasecmp(end, "kb") == 0)
		n *= 1024;
	else if (strcasecmp(end, "mb") == 0)
		n *= 1024 * 1024;
	else if (strcasecmp(end, "gb") == 0)
		n *= 1024.0 * 1024 * 1024;
	return (n);
}

/* A list of objects as a table, the first's keys its columns. */
static void
obj_table(struct html *h, const ucl_object_t *arr, int max)
{
	const ucl_object_t	*first, *e, *v;
	ucl_object_iter_t	 it, kit;
	int			 n;

	if ((first = ucl_array_find_index(arr, 0)) == NULL ||
	    ucl_object_type(first) != UCL_OBJECT) {
		h_raw(h, "<pre class=\"mono surule\">");
		if (arr != NULL) {
			char	*t = (char *)ucl_object_emit(arr,
			    UCL_EMIT_JSON_COMPACT);

			h_txt(h, t);
			free(t);
		}
		h_raw(h, "</pre>");
		return;
	}
	h_raw(h, "<table class=\"net\"><thead><tr>");
	kit = NULL;
	while ((v = ucl_object_iterate(first, &kit, true)) != NULL) {
		h_raw(h, "<th>");
		h_txt(h, ucl_object_key(v));
		h_raw(h, "</th>");
	}
	h_raw(h, "</tr></thead><tbody>");
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL && n++ < max) {
		h_raw(h, "<tr>");
		kit = NULL;
		while ((v = ucl_object_iterate(first, &kit, true)) != NULL) {
			h_raw(h, "<td class=\"mono\">");
			h_txt(h, ucl_object_tostring_forced(ucl_object_lookup(e,
			    ucl_object_key(v))));
			h_raw(h, "</td>");
		}
		h_raw(h, "</tr>");
	}
	h_raw(h, "</tbody></table>");
}

/*
 * Suricata itself, asked by its socket, and what to make of it all: the
 * advice of its drops, invalid packets, memory, rules that failed and
 * the alerts most told; and its rules' profile where it is built with
 * it.
 */
static void
view_engine(struct html *h, const ucl_object_t *l, const ucl_object_t *st)
{
	const ucl_object_t	*b, *m, *e, *last, *first;
	ucl_object_iter_t	 it;
	double			 pk, dr, inv, caps, mem, secs, al;
	int			 n, advice;
	bool			 asked;

	b = jget(sec_state(), "ids_build");
	asked = eng.ans[0] != NULL || eng.ans[1] != NULL;
	h_raw(h, "<div class=\"toolbar\"><strong>Suricata itself</strong>"
	    "<span class=\"grow\"></span><button class=\"ghost\" data-act="
	    "\"ist-ask\" title=\"By its unix command socket: its memcaps, "
	    "its rules loaded and failed, its interfaces' counters\">");
	h_raw(h, asked ? "Ask again" : "Ask Suricata");
	h_raw(h, "</button></div>");
	if (b != NULL) {
		h_raw(h, "<p class=\"dim\">Suricata ");
		h_txt(h, jstr(b, "version"));
		h_fmt(h, ": netmap %s, ipfw %s, Hyperscan %s, Lua %s, plugins "
		    "%s, rule profiling %s.</p>", jbool(b, "netmap") ? "yes" :
		    "no", jbool(b, "ipfw") ? "yes" : "no", jbool(b,
		    "hyperscan") ? "yes" : "no", jbool(b, "lua") ? "yes" : "no",
		    jbool(b, "plugins") ? "yes" : "no", jbool(b,
		    "profiling_rules") ? "yes" : "no");
	}
	if (eng.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, eng.error);
		h_raw(h, "</div>");
	}
	if (asked) {
		h_raw(h, "<div class=\"idstops\">");
		if ((m = jget(eng.ans[0], "message")) != NULL) {
			h_raw(h, "<div class=\"idstop\"><h4>Memcaps</h4>");
			obj_table(h, m, 40);
			h_raw(h, "</div>");
		}
		if ((m = jget(eng.ans[1], "message")) != NULL) {
			h_raw(h, "<div class=\"idstop\"><h4>Rules loaded</h4>");
			obj_table(h, m, 10);
			h_raw(h, "</div>");
		}
		if (eng.ifs != NULL) {
			ucl_object_t	*rows = ucl_object_typed_new(UCL_ARRAY);

			it = NULL;
			while ((e = ucl_object_iterate(eng.ifs, &it, true)) !=
			    NULL)
				if (jget(e, "message") != NULL)
					ucl_array_append(rows, ucl_object_copy(
					    jget(e, "message")));
			h_raw(h, "<div class=\"idstop\"><h4>Interfaces</h4>");
			obj_table(h, rows, 16);
			h_raw(h, "</div>");
			ucl_object_unref(rows);
		}
		h_raw(h, "</div>");
		if ((m = jget(eng.ans[2], "message")) != NULL &&
		    ucl_array_size(m) > 0) {
			h_raw(h, "<h4>Rules that failed to load</h4>");
			obj_table(h, m, 50);
		}
	}

	/* Advice, of the last hour. */
	h_raw(h, "<h4>What to look at</h4><ul class=\"advice\">");
	advice = 0;
	n = (int)ucl_array_size(jget(st, "series"));
	first = ucl_array_find_index(jget(st, "series"), 0);
	last = ucl_array_find_index(jget(st, "series"), (unsigned)n - 1);
	pk = pt(last, field_at(st, "packets")) - pt(first, field_at(st,
	    "packets"));
	dr = pt(last, field_at(st, "drops")) - pt(first, field_at(st,
	    "drops"));
	inv = pt(last, field_at(st, "invalid")) - pt(first, field_at(st,
	    "invalid"));
	al = pt(last, field_at(st, "alerts")) - pt(first, field_at(st,
	    "alerts"));
	secs = pt(last, field_at(st, "t")) - pt(first, field_at(st, "t"));
	if (n > 1 && pk > 0 && dr > 0 && dr / (pk + dr) > 0.01) {
		h_fmt(h, "<li class=\"warn\">The kernel dropped %.1f%% of the "
		    "packets before Suricata saw them. Give it more: the "
		    "workers runmode and more worker CPUs (Performance), "
		    "netmap(4) instead of pcap(3) (Capture), more pending "
		    "packets; with pcap, a larger BPF buffer "
		    "(net.bpf.maxbufsize) or net.bpf.zerocopy_enable.</li>",
		    100 * dr / (pk + dr));
		advice++;
	}
	if (n > 1 && pk > 0 && inv / pk > 0.01) {
		h_fmt(h, "<li class=\"warn\">%.1f%% of the packets are "
		    "invalid as Suricata decodes them: checksums not yet "
		    "made or segments merged by the NIC. Turn its "
		    "interfaces' offloading off (Capture).</li>", 100 * inv /
		    pk);
		advice++;
	}
	caps = 0;
	it = NULL;
	while ((e = ucl_object_iterate(jget(eng.ans[0], "message"), &it,
	    true)) != NULL)
		if (jstr(e, "name") != NULL && (strcmp(jstr(e, "name"),
		    "flow") == 0 || strcmp(jstr(e, "name"), "stream") == 0 ||
		    strcmp(jstr(e, "name"), "stream-reassembly") == 0))
			caps += size_of(jstr(e, "value"));
	mem = pt(last, field_at(st, "memuse"));
	if (caps > 0 && mem > 0.8 * caps) {
		h_fmt(h, "<li class=\"warn\">It uses %.0f%% of its flow, "
		    "stream and reassembly memcaps: past them it drops or "
		    "passes (its exception policy). Raise them (Memory).</li>",
		    100 * mem / caps);
		advice++;
	}
	if ((m = jget(eng.ans[1], "message")) != NULL && (e =
	    ucl_array_find_index(m, 0)) != NULL && jint(e, "rules_failed", 0) >
	    0) {
		h_fmt(h, "<li class=\"warn\">%lld of its rules failed to "
		    "load: see them above.</li>", (long long)jint(e,
		    "rules_failed", 0));
		advice++;
	}
	if (n > 1 && secs > 0 && al / secs > 1) {
		h_fmt(h, "<li>%.1f alerts a second: the signatures told most, "
		    "below, may want a threshold or a suppression (Own "
		    "rules).</li>", al / secs);
		advice++;
	}
	if (advice == 0)
		h_raw(h, "<li class=\"dim\">Nothing: it keeps up, in memory, "
		    "with every rule loaded as far as it was asked.</li>");
	h_raw(h, "</ul>");

	/* Its rules' profile: where the time goes, rule by rule. */
	h_raw(h, "<h4>Rule profiling</h4>");
	if (b != NULL && !jbool(b, "profiling_rules")) {
		h_raw(h, "<p class=\"dim\">This Suricata is built without rule "
		    "profiling, as the port builds it. poudriere (Builder) "
		    "builds it with profiling given, in the build's "
		    "make.conf:</p><pre class=\"mono surule\">.if ${.CURDIR:M"
		    "*/security/suricata}\nCONFIGURE_ARGS+=--enable-profiling-"
		    "rules\n.endif</pre><p class=\"dim\">and installed in its "
		    "place; <code>--enable-profiling</code> profiles packets "
		    "too, at a cost.</p>");
		return;
	}
	h_raw(h, "<div class=\"toolbar\"><button class=\"ghost\" data-act="
	    "\"ist-profile\">Profile its rules</button></div>");
	if ((m = jget(eng.ans[7], "message")) != NULL) {
		if (ucl_object_type(m) == UCL_STRING)
			h_txt(h, ucl_object_tostring(m));
		else
			obj_table(h, jget(m, "rules") != NULL ? jget(m, "rules") :
			    m, 50);
	}
	(void)l;
}

/*
 * A capture run through it, offline (a suricata job, verb pcap): the
 * last one's alerts; and the packets of its alerts it keeps (pcap-log).
 */
static void
view_replay(struct html *h, const ucl_object_t *l)
{
	const ucl_object_t	*r, *a, *p;
	ucl_object_iter_t	 it;
	char			 sz[32], age[32], url[200];
	int			 n;

	h_raw(h, "<h4>Replay a capture</h4><form class=\"secform\" "
	    "data-form=\"ist-replay\"><div class=\"rowform\"><label>A "
	    "capture the host has <input name=\"file\" required spellcheck="
	    "\"false\" placeholder=\"/var/tmp/suspect.pcap\"><small class=\""
	    "help\">a .pcap, .pcapng or .cap, by its whole path: run through "
	    "this instance's configuration and rules (suricata -r), offline"
	    "</small></label></div><div class=\"actions\"><button type=\""
	    "submit\" class=\"primary\">Replay</button></div></form>");
	if ((r = jget(l, "replay")) != NULL) {
		fmt_age(age, sizeof(age), (double)jint(r, "at", 0) * 1000);
		h_raw(h, "<p class=\"dim\">");
		h_txt(h, jstr(r, "file"));
		h_fmt(h, ", replayed %s in %lld s: %lld alert%s%s.</p>", age,
		    (long long)jint(r, "seconds", 0), (long long)jint(r,
		    "alerts_total", 0), jint(r, "alerts_total", 0) == 1 ? "" :
		    "s", jint(r, "status", 0) != 0 ? " (Suricata failed)" : "");
		n = 0;
		h_raw(h, "<ul class=\"secalerts\">");
		it = NULL;
		while ((a = ucl_object_iterate(jget(r, "alerts"), &it, true)) !=
		    NULL && n++ < 50) {
			h_raw(h, "<li><b>");
			h_txt(h, jstr(a, "signature"));
			h_fmt(h, "</b> <small class=\"dim\">sid %lld</small> "
			    "<span class=\"mono\">", (long long)jint(a, "sid", 0));
			h_txt(h, jstr(a, "src"));
			h_raw(h, " → ");
			h_txt(h, jstr(a, "dst"));
			h_raw(h, "</span></li>");
		}
		h_raw(h, "</ul>");
	}
	/* A capture this computer has: sent to the host, then replayed. */
	h_raw(h, "<div class=\"toolbar\"><label class=\"button ghost small\" "
	    "title=\"Sent to the host, in parts of 4 MB, kept beside its "
	    "replay (eight at most, 1 GiB each), then replayed\">Replay a "
	    "capture from this computer<input type=\"file\" accept=\".pcap,"
	    ".pcapng,.cap,application/vnd.tcpdump.pcap\" data-upload=\""
	    "ist-capture\"");
	snprintf(url, sizeof(url), "/api/servers/%s/ids/pcap?instance=%s",
	    sec_host_id(), open_name);
	h_attr(h, "data-url", url);
	h_raw(h, " hidden></label>");
	if (up.busy && up.size > 0) {
		h_raw(h, "<span class=\"dim\">");
		h_txt(h, up.name);
		h_fmt(h, ": %lld%% sent</span>", up.sent * 100 / up.size);
	}
	h_raw(h, "</div>");
	if (up.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, up.name);
		h_raw(h, ": ");
		h_txt(h, up.error);
		h_raw(h, "</div>");
	}
	if (ucl_array_size(jget(l, "captures")) > 0) {
		h_raw(h, "<h4>Captures sent to the host</h4><ul class=\""
		    "secalerts\">");
		it = NULL;
		while ((p = ucl_object_iterate(jget(l, "captures"), &it,
		    true)) != NULL) {
			fmt_bytes(sz, sizeof(sz), jint(p, "size", 0));
			fmt_age(age, sizeof(age), (double)jint(p, "at", 0) * 1000);
			h_raw(h, "<li><span class=\"mono\">");
			h_txt(h, jstr(p, "path"));
			h_fmt(h, "</span> <small class=\"dim\">%s, %s</small> "
			    "<button class=\"ghost small\" data-act=\""
			    "ist-replay-cap\"", sz, age);
			h_attr(h, "data-arg", jstr(p, "path"));
			h_raw(h, ">Replay</button></li>");
		}
		h_raw(h, "</ul>");
	}
	if (ucl_array_size(jget(l, "pcaps")) > 0) {
		h_raw(h, "<h4>The packets of its alerts</h4><p class=\"dim\">"
		    "Suricata's pcap-log, a file at a time, for Wireshark or a "
		    "replay; an alert's row links the file of its packets."
		    "</p><ul class=\"secalerts\">");
		it = NULL;
		while ((p = ucl_object_iterate(jget(l, "pcaps"), &it, true)) !=
		    NULL) {
			const char	*base;

			fmt_bytes(sz, sizeof(sz), jint(p, "size", 0));
			fmt_age(age, sizeof(age), (double)jint(p, "at", 0) * 1000);
			base = jstr(p, "path") != NULL && strrchr(jstr(p, "path"),
			    '/') != NULL ? strrchr(jstr(p, "path"), '/') + 1 :
			    jstr(p, "path");
			h_raw(h, "<li>");
			ids_pcap_link(h, open_name, base, base);
			h_fmt(h, " <small class=\"dim\">%s, last written %s"
			    "</small></li>", sz, age);
		}
		h_raw(h, "</ul>");
	}
}

/* A link that downloads a file of an instance's pcap-log, through the
 * console (GET /api/servers/<id>/ids/pcap-log). */
void
ids_pcap_link(struct html *h, const char *inst, const char *file,
    const char *label)
{
	char	url[300], name[200];

	if (file == NULL || inst == NULL)
		return;
	snprintf(url, sizeof(url), "/api/servers/%s/ids/pcap-log?instance=%s&"
	    "file=%s", sec_host_id(), inst, file);
	snprintf(name, sizeof(name), "%s-%s.pcap", inst, file);
	h_raw(h, "<a class=\"mono\" title=\"The packets Suricata logged for "
	    "its alerts (pcap-log), downloaded through the console\"");
	h_attr(h, "href", url);
	h_attr(h, "download", name);
	h_raw(h, ">");
	h_txt(h, label);
	h_raw(h, "</a>");
}

/* A time as Suricata writes it, 2026-10-19T10:00:00.000000+0000, in
 * seconds since the epoch; -1 for none. */
static long long
eve_time(const char *s)
{
	int		 y, mo, d, hh, mm, ss, oh, om, n;
	long long	 days, era, yoe, doy, doe;
	const char	*z;
	char		 sign;

	if (s == NULL || sscanf(s, "%d-%d-%dT%d:%d:%d%n", &y, &mo, &d, &hh,
	    &mm, &ss, &n) != 6)
		return (-1);
	/* Days from the civil date (Howard Hinnant's). */
	y -= mo <= 2;
	era = (y >= 0 ? y : y - 399) / 400;
	yoe = y - era * 400;
	doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
	doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	days = era * 146097 + doe - 719468;
	z = s + n + strspn(s + n, ".0123456789");
	oh = om = 0;
	sign = '+';
	if ((*z == '+' || *z == '-') && sscanf(z + 1, "%2d%2d", &oh, &om) ==
	    2)
		sign = *z;
	return (days * 86400 + hh * 3600 + mm * 60 + ss - (sign == '-' ? -1 :
	    1) * (oh * 3600 + om * 60));
}

/*
 * The file of an instance's pcap-log that holds an alert's packets: the
 * one begun last before the alert's time (log.pcap.<seconds>) and
 * written since; NULL when none is kept.
 */
const char *
ids_pcap_of(const ucl_object_t *live, const char *when)
{
	const ucl_object_t	*p, *best;
	ucl_object_iter_t	 it;
	long long		 t;
	const char		*path;

	if ((t = eve_time(when)) < 0)
		return (NULL);
	best = NULL;
	it = NULL;
	while ((p = ucl_object_iterate(jget(live, "pcaps"), &it, true)) !=
	    NULL) {
		if (jget(p, "from") == NULL || jint(p, "from", 0) > t ||
		    jint(p, "at", 0) + 1 < t)
			continue;
		if (best == NULL || jint(p, "from", 0) > jint(best, "from", 0))
			best = p;
	}
	if (best == NULL || (path = jstr(best, "path")) == NULL)
		return (NULL);
	return (strrchr(path, '/') != NULL ? strrchr(path, '/') + 1 : path);
}

/* The columns of its packets' ticks, and of its rules'. */
static const struct tcol pcols[] = {
	{ "Stage", "section", false }, { "Name", "name", false },
	{ "IP", "ip", false }, { "Proto", "proto", true },
	{ "Count", "cnt", true }, { "Min", "min", true },
	{ "Max", "max", true }, { "Avg", "avg", true },
	{ "Total", "tot", false }, { "%", "pct", true },
};
static const struct tcol rcols[] = {
	{ "Sid", "signature_id", true }, { "Gid", "gid", true },
	{ "Rev", "rev", true }, { "Checks", "checks", true },
	{ "Matches", "matches", true }, { "Ticks", "ticks_total", true },
	{ "Max", "ticks_max", true }, { "Avg", "ticks_avg", true },
	{ "Avg match", "ticks_avg_match", true },
	{ "Avg no match", "ticks_avg_nomatch", true },
	{ "%", "percent", true },
};

static const char *
proto_name(int64_t p)
{

	switch (p) {
	case 1:
		return ("icmp");
	case 6:
		return ("tcp");
	case 17:
		return ("udp");
	case 47:
		return ("gre");
	case 50:
		return ("esp");
	case 58:
		return ("ipv6-icmp");
	case 132:
		return ("sctp");
	case 256:
		return ("tunnel");
	default:
		return ("");
	}
}

/* One dump's tables: its packets' ticks, its rules', the rest as text. */
static void
prof_one(struct html *h, int which, const char *title)
{
	static const struct {
		const char	*key, *title;
	} texts[] = {
		{ "keywords", "Keywords" }, { "prefilter", "Prefilter" },
		{ "rulegroups", "Rule groups" }, { "locks", "Locks" },
	};
	const ucl_object_t	*w, **rows, *r;
	char			 age[32], id[24];
	size_t			 i;
	int			 k;

	w = jget(prof.o, which == 0 ? "running" : "replay");
	h_raw(h, "<h5>");
	h_txt(h, title);
	h_raw(h, "</h5>");
	if (w == NULL) {
		h_raw(h, which == 0 ? "<p class=\"dim\">Nothing written yet: "
		    "Suricata writes its profiling as it stops. Stop and Start "
		    "it (Instances), or replay a capture.</p>" : "<p class=\""
		    "dim\">No replay since its profiling was on.</p>");
		return;
	}
	if (ucl_array_size(prof.rows[which]) > 0) {
		fmt_age(age, sizeof(age), (double)jint(jget(w, "packets"), "at",
		    0) * 1000);
		h_fmt(h, "<p class=\"dim\">Packets, CPU ticks per protocol and "
		    "per stage (packet_stats.log, written %s).</p>", age);
		snprintf(id, sizeof(id), "istprof-%d", which);
		h_raw(h, "<div class=\"tablewrap\"><table class=\"net\">");
		tbl_head(h, id, pcols, (int)nitems(pcols), 0);
		h_raw(h, "<tbody>");
		rows = tbl_rows(id, prof.rows[which], pcols, (int)nitems(pcols),
		    prof.filter);
		for (k = 0; (r = rows[k]) != NULL && k < 1000; k++) {
			h_raw(h, "<tr><td>");
			h_txt(h, jstr(r, "section"));
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(r, "name"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(r, "ip"));
			h_fmt(h, "</td><td>%lld <small class=\"dim\">%s</small>"
			    "</td><td>%lld</td><td>%lld</td><td>%lld</td><td>"
			    "%lld</td><td>", (long long)jint(r, "proto", 0),
			    proto_name(jint(r, "proto", 0)), (long long)jint(r,
			    "cnt", 0), (long long)jint(r, "min", 0), (long long)
			    jint(r, "max", 0), (long long)jint(r, "avg", 0));
			h_txt(h, jstr(r, "tot"));
			h_fmt(h, "</td><td>%.2f</td></tr>", jnum(r, "pct", 0));
		}
		free(rows);
		h_raw(h, "</tbody></table></div>");
	}
	if (ucl_array_size(prof.rules[which]) > 0) {
		h_raw(h, "<p class=\"dim\">Rules, by ticks (rule_perf.log).</p>");
		snprintf(id, sizeof(id), "istprofr-%d", which);
		h_raw(h, "<div class=\"tablewrap\"><table class=\"net\">");
		tbl_head(h, id, rcols, (int)nitems(rcols), 0);
		h_raw(h, "<tbody>");
		rows = tbl_rows(id, prof.rules[which], rcols, (int)nitems(rcols),
		    prof.filter);
		for (k = 0; (r = rows[k]) != NULL; k++) {
			h_fmt(h, "<tr><td>%lld</td><td>%lld</td><td>%lld</td><td>"
			    "%lld</td><td>%lld</td><td>%lld</td><td>%lld</td><td>"
			    "%lld</td><td>%.0f</td><td>%.0f</td><td>%.2f</td>"
			    "</tr>", (long long)jint(r, "signature_id", 0),
			    (long long)jint(r, "gid", 0), (long long)jint(r, "rev",
			    0), (long long)jint(r, "checks", 0), (long long)jint(r,
			    "matches", 0), (long long)jint(r, "ticks_total", 0),
			    (long long)jint(r, "ticks_max", 0), (long long)jint(r,
			    "ticks_avg", 0), jnum(r, "ticks_avg_match", 0),
			    jnum(r, "ticks_avg_nomatch", 0), jnum(r, "percent", 0));
		}
		free(rows);
		h_raw(h, "</tbody></table></div>");
	}
	for (i = 0; i < nitems(texts); i++) {
		if (jstr(jget(w, texts[i].key), "text") == NULL)
			continue;
		h_fmt(h, "<details class=\"wfmore\"><summary>%s</summary>"
		    "<pre class=\"mono surule\">", texts[i].title);
		h_txt(h, jstr(jget(w, texts[i].key), "text"));
		h_raw(h, "</pre></details>");
	}
}

/*
 * Packet profiling, Suricata built with --enable-profiling: where the
 * time goes, per protocol and per stage of each packet's way through
 * it, and per rule, as its profiling wrote it (as it stops, or at the
 * end of a replay).  Where it is built without, how to get it: the
 * port has no option for it, the admin builds it so.
 */
static void
view_profiling(struct html *h)
{
	const ucl_object_t	*b;

	b = jget(sec_state(), "ids_build");
	h_raw(h, "<div class=\"toolbar\"><strong>Packet profiling</strong>"
	    "<span class=\"grow\"></span>");
	if (b == NULL || jbool(b, "profiling") || jbool(b, "profiling_rules")) {
		h_raw(h, "<input class=\"filter\" id=\"ist-pfilter\" data-input="
		    "\"ist-pfilter\" placeholder=\"Filter\" autocomplete=\"off\" "
		    "spellcheck=\"false\"");
		h_attr(h, "value", prof.filter);
		h_raw(h, "><button class=\"ghost\" data-act=\"ist-prof\" title="
		    "\"What its profiling wrote: packet_stats.log, "
		    "rule_perf.log and the others, in its log directory and "
		    "its replay's\">");
		h_raw(h, prof.o != NULL ? "Read again" : "Read its profiling");
		h_raw(h, "</button>");
	}
	h_raw(h, "</div>");
	if (b != NULL && !jbool(b, "profiling")) {
		h_raw(h, "<p class=\"dim\">This Suricata is built without packet "
		    "profiling: CPU ticks per protocol and per stage need it "
		    "built with <code>--enable-profiling</code>, which the "
		    "security/suricata port has no option for. Build it so with "
		    "poudriere (Builder), in the build's make.conf, and install "
		    "it in its place; Arcana installs nothing:</p><pre class=\""
		    "mono surule\">.if ${.CURDIR:M*/security/suricata}\n"
		    "CONFIGURE_ARGS+=--enable-profiling\n.endif</pre><p class=\""
		    "dim\">Then turn its sections on in its form (Logging, "
		    "Profiling). Profiling costs CPU while it is built in; a "
		    "sample rate lowers it.</p>");
		if (!jbool(b, "profiling_rules"))
			return;
	}
	if (prof.loading)
		h_raw(h, "<div class=\"loader\"></div>");
	if (prof.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, prof.error);
		h_raw(h, "</div>");
	}
	if (prof.o == NULL)
		return;
	prof_one(h, 0, "Running");
	prof_one(h, 1, "Its last replay");
}

bool
idsstats_form(const char *form, const ucl_object_t *f)
{

	if (strcmp(form, "ist-replay") != 0 || jstr(f, "file") == NULL)
		return (false);
	replay_job(jstr(f, "file"));
	return (true);
}
