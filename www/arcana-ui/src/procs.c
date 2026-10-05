/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What runs on a host, as top(1) shows it: every process with what it
 * uses of the CPUs, the memory and the disks, in the order of any of
 * them, read again every few seconds.  A process picked is sent a
 * signal or given another nice value.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	nitems(x)	(sizeof(x) / sizeof((x)[0]))

#define	PROCS_EVERY	3000	/* ms between two looks, while live */
#define	PROCS_ROWS	400	/* drawn at once, at most */

enum { C_PID, C_USER, C_JAIL, C_STATE, C_NICE, C_THR, C_RSS, C_SIZE, C_CPU,
    C_WCPU, C_IO, C_TIME, C_COMM, C_N };

static const struct tcol cols[C_N] = {
	{ "PID", "pid", true }, { "User", "user", false },
	{ "Jail", "jail", false }, { "State", "state", false },
	{ "Nice", "nice", true }, { "Thr", "threads", true },
	{ "Res", "rss", true }, { "Size", "size", true },
	{ "CPU", "cpu", true }, { "WCPU", "wcpu", true },
	{ "I/O", "io", true }, { "Time", "time", true },
	{ "Command", "comm", false },
};

static const char *const signals[] = { "TERM", "KILL", "HUP", "INT", "QUIT",
    "STOP", "CONT", "USR1", "USR2", "ABRT" };

static struct {
	char		 sid[9];
	char		 jail[256];	/* only its processes, or "" */
	ucl_object_t	*data;
	bool		 loading;
	bool		 paused;
	bool		 kernel;	/* the kernel's own are shown too */
	char		 error[300];
	double		 fetched;
	long long	 open;		/* the process picked, or 0 */
} pr;

/* 1536 as "1.50 KiB". */
void
fmt_size(char *buf, size_t len, double v)
{
	static const char *const units[] = { "B", "K", "M", "G", "T" };
	int	u;

	for (u = 0; v >= 1024 && u < 4; u++)
		v /= 1024;
	snprintf(buf, len, u == 0 ? "%.0f%s" : v < 10 ? "%.2f%s" : v < 100 ?
	    "%.1f%s" : "%.0f%s", v, units[u]);
}

/* CPU seconds as top(1) has them: 1:02:03, or 2:03.45. */
static void
fmt_cputime(char *buf, size_t len, double s)
{
	long long	t;

	t = (long long)s;
	if (t >= 3600)
		snprintf(buf, len, "%lld:%02lld:%02lld", t / 3600, t % 3600 /
		    60, t % 60);
	else
		snprintf(buf, len, "%lld:%05.2f", t / 60, s - (double)(t / 60 *
		    60));
}

static void
procs_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid;

	sid = arg;
	if (strcmp(sid, pr.sid) != 0) {
		free(sid);
		return;
	}
	free(sid);
	pr.loading = false;
	pr.fetched = arc_now();
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(pr.error, sizeof(pr.error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	pr.error[0] = '\0';
	if (pr.data != NULL)
		ucl_object_unref(pr.data);
	pr.data = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
}

/* Read what runs on the host; again asks though it is here already. */
void
refresh_procs(struct server *s, bool again)
{
	char	url[400];

	if (!app.online || pr.loading)
		return;
	if (strcmp(pr.sid, s->id) != 0) {
		if (pr.data != NULL)
			ucl_object_unref(pr.data);
		pr.data = NULL;
		pr.error[0] = '\0';
		pr.jail[0] = '\0';
		pr.open = 0;
	} else if (!again && (pr.data != NULL || pr.error[0] != '\0'))
		return;
	snprintf(pr.sid, sizeof(pr.sid), "%s", s->id);
	pr.loading = true;
	if (pr.jail[0] != '\0')
		snprintf(url, sizeof(url), "/api/servers/%s/processes?jail=%s",
		    s->id, pr.jail);
	else
		snprintf(url, sizeof(url), "/api/servers/%s/processes", s->id);
	api("GET", url, NULL, procs_cb, strdup(s->id));
}

/* What runs changes by itself: read again while it is shown. */
void
procs_tick(double now)
{
	struct server	*s;

	if (app.node != NODE_HOST || app.tab != TAB_PROCESSES || pr.paused ||
	    !app.visible || pr.loading || (s = cur_server()) == NULL ||
	    strcmp(pr.sid, s->id) != 0 || now - pr.fetched < PROCS_EVERY)
		return;
	/* Not under somebody who is choosing what to do to one. */
	if (app.modal != MODAL_NONE || pr.open != 0)
		return;
	refresh_procs(s, true);
}

static const ucl_object_t *
proc_find(long long pid)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while (pr.data != NULL && (o = ucl_object_iterate(jget(pr.data,
	    "processes"), &it, true)) != NULL)
		if (jint(o, "pid", 0) == pid)
			return (o);
	return (NULL);
}

/* A share of one CPU, with the colour of how much it is. */
static void
pct(struct html *h, double v)
{

	h_fmt(h, "<td class=\"num%s\">%.1f%%</td>", v >= 80 ? " hot" : v >=
	    20 ? " warm" : v < 0.05 ? " dim" : "", v);
}

/* The row under a process picked: what can be done to it. */
static void
picked(struct html *h, const ucl_object_t *o)
{
	char	buf[32];
	double	age;
	size_t	i;

	h_fmt(h, "<tr class=\"editing ps-act\"><td colspan=\"%d\"><div class="
	    "\"ps-what\"><code>", C_N);
	h_txt(h, jstr(o, "args") != NULL ? jstr(o, "args") : jstr(o, "comm"));
	h_fmt(h, "</code><small class=\"dim\">child of %lld", (long long)jint(
	    o, "ppid", 0));
	if (jstr(o, "wait") != NULL) {
		h_raw(h, " · waits on ");
		h_txt(h, jstr(o, "wait"));
	}
	age = arc_now() / 1000 - (double)jint(o, "start", 0);
	if (age >= 172800)
		snprintf(buf, sizeof(buf), "%.0f days ago", age / 86400);
	else
		fmt_age(buf, sizeof(buf), (double)jint(o, "start", 0) * 1000);
	h_raw(h, " · started ");
	h_txt(h, buf);
	h_fmt(h, " · priority %lld · read %lld, wrote %lld blocks</small>"
	    "</div>", (long long)jint(o, "pri", 0), (long long)jint(o, "in",
	    0), (long long)jint(o, "out", 0));
	if (jbool(o, "kernel")) {
		h_raw(h, "<p class=\"dim\">The kernel's own: it takes no "
		    "signal and no nice value from here.</p><button type=\""
		    "button\" class=\"ghost small\" data-act=\"ps-open\" "
		    "data-arg=\"0\">Close</button></td></tr>");
		return;
	}
	h_raw(h, "<form data-form=\"ps-signal\" class=\"ps-form\"><label>"
	    "Signal<select name=\"signal\">");
	for (i = 0; i < nitems(signals); i++)
		h_fmt(h, "<option>%s</option>", signals[i]);
	h_raw(h, "</select></label><button class=\"small danger\">Send"
	    "</button></form><form data-form=\"ps-renice\" class=\"ps-form\">"
	    "<label>Nice<input name=\"nice\" type=\"number\" min=\"-20\" "
	    "max=\"20\" step=\"1\"");
	snprintf(buf, sizeof(buf), "%lld", (long long)jint(o, "nice", 0));
	h_attr(h, "value", buf);
	h_raw(h, "></label><button class=\"small\">Renice</button></form>"
	    "<button type=\"button\" class=\"ghost small\" data-act=\""
	    "ps-open\" data-arg=\"0\">Close</button></td></tr>");
}

void
view_procs(struct html *h, struct server *s)
{
	static const struct {
		const char	*title, *hint;
		int		 col;
	} orders[] = {
		{ "CPU", "What each used of a CPU since the look before", C_CPU },
		{ "WCPU", "The kernel's own, slower figure, as top shows it",
		    C_WCPU },
		{ "Memory", "What each holds of the memory", C_RSS },
		{ "I/O", "Blocks read and written a second", C_IO },
	};
	const ucl_object_t	**rows, *o, *j;
	ucl_object_iter_t	  it;
	char			  buf[32], age[32];
	double			  cpu, rss;
	long long		  thr;
	size_t			  i;
	int			  r, n, col, shown;
	bool			  mine, desc;

	mine = pr.data != NULL && strcmp(pr.sid, s->id) == 0;
	desc = false;
	col = tbl_col("procs", &desc);
	h_raw(h, "<div class=\"toolbar\"><nav class=\"sub\">");
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"ps-jail\" "
	    "data-arg=\"\" title=\"Every process, of the host and of its "
	    "jails\">all</button>", pr.jail[0] == '\0' ? " on" : "");
	it = NULL;
	while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		if (jstr(j, "name") == NULL || jstr(j, "state") == NULL ||
		    strcmp(jstr(j, "state"), "running") != 0)
			continue;
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"ps-jail\"",
		    strcmp(pr.jail, jstr(j, "name")) == 0 ? " on" : "");
		h_attr(h, "data-arg", jstr(j, "name"));
		h_raw(h, ">");
		h_txt(h, jstr(j, "name"));
		h_raw(h, "</button>");
	}
	h_raw(h, "</nav><nav class=\"sub ps-order\"><span class=\"dim\">by"
	    "</span>");
	for (i = 0; i < nitems(orders); i++)
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"ps-sort\" "
		    "data-arg=\"%d\" title=\"%s, the most first\">%s</button>",
		    (col == orders[i].col && desc) || (col == -1 &&
		    orders[i].col == C_CPU) ? " on" : "", orders[i].col,
		    orders[i].hint, orders[i].title);
	h_fmt(h, "</nav><button class=\"ghost small%s\" data-act=\"ps-kernel\" "
	    "title=\"The kernel's own processes too\">kernel</button>",
	    pr.kernel ? " on" : "");
	h_raw(h, "<input class=\"filter\" id=\"filter\" data-input=\"filter\" "
	    "placeholder=\"Filter rows\" autocomplete=\"off\" spellcheck=\""
	    "false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "><span class=\"age\">");
	if (mine) {
		fmt_age(age, sizeof(age), pr.fetched);
		h_txt(h, age);
	} else if (pr.loading)
		h_raw(h, "reading…");
	h_fmt(h, "</span><button class=\"ghost small live%s\" data-act=\""
	    "ps-live\" title=\"Read again every three seconds while this is "
	    "shown, and no process is picked\"><span class=\"led\"></span>Live</button><button class=\""
	    "icon\" data-act=\"refresh\" title=\"Read again\">⟳</button>"
	    "</div>", pr.paused ? "" : " on");
	if (strcmp(pr.sid, s->id) == 0 && pr.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, pr.error);
		h_raw(h, "</div>");
	}
	if (!mine) {
		h_raw(h, "<div class=\"empty\"><p>Reading what runs…</p>"
		    "</div>");
		return;
	}

	/* The whole of it, whatever is filtered away below. */
	cpu = rss = 0;
	thr = 0;
	n = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(pr.data, "processes"), &it,
	    true)) != NULL) {
		n++;
		/* The idle process is the CPUs nobody uses. */
		if (!(jbool(o, "kernel") && jstr(o, "comm") != NULL &&
		    strcmp(jstr(o, "comm"), "idle") == 0))
			cpu += jnum(o, "cpu", 0);
		thr += jint(o, "threads", 0);
		if (!jbool(o, "kernel"))
			rss += jnum(o, "rss", 0);
	}
	fmt_size(buf, sizeof(buf), rss);
	h_fmt(h, "<div class=\"ps-sum\"><span><b>%d</b> processes</span><span>"
	    "<b>%lld</b> threads</span><span><b>%.1f</b> of %lld CPUs "
	    "busy</span><span><b>%s</b> resident</span><span class="
	    "\"dim\">over %.1f s</span></div>", n, thr, cpu / 100, (long long)jint(
	    pr.data, "ncpu", 1), buf, jnum(pr.data, "elapsed", 0));

	h_raw(h, "<table class=\"net procs\">");
	tbl_head(h, "procs", cols, C_N, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("procs", jget(pr.data, "processes"), cols, C_N,
	    app.filter);
	shown = 0;
	for (r = 0; (o = rows[r]) != NULL; r++) {
		if (jbool(o, "kernel") && !pr.kernel && jint(o, "pid", 0) !=
		    pr.open)
			continue;
		if (++shown > PROCS_ROWS)
			continue;
		h_fmt(h, "<tr class=\"pick%s%s\" data-act=\"ps-open\" "
		    "data-arg=\"%lld\" title=\"Press for what can be done to "
		    "it\"><td class=\"num\">%lld</td><td>", jint(o, "pid", 0) ==
		    pr.open ? " sel" : "", jbool(o, "kernel") ? " kproc" : "",
		    (long long)jint(o, "pid", 0), (long long)jint(o, "pid",
		    0));
		h_txt(h, jstr(o, "user"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(o, "jail"));
		h_fmt(h, "</td><td class=\"st-%s\">", h_word(jstr(o, "state"),
		    "x"));
		h_txt(h, jstr(o, "state"));
		h_fmt(h, "</td><td class=\"num\">%lld</td><td class=\"num\">"
		    "%lld</td>", (long long)jint(o, "nice", 0), (long long)
		    jint(o, "threads", 0));
		fmt_size(buf, sizeof(buf), jnum(o, "rss", 0));
		h_fmt(h, "<td class=\"num\">%s</td>", buf);
		fmt_size(buf, sizeof(buf), jnum(o, "size", 0));
		h_fmt(h, "<td class=\"num dim\">%s</td>", buf);
		pct(h, jnum(o, "cpu", 0));
		pct(h, jnum(o, "wcpu", 0));
		h_fmt(h, "<td class=\"num%s\">%.0f</td>", jnum(o, "io", 0) <
		    0.5 ? " dim" : "", jnum(o, "io", 0));
		fmt_cputime(buf, sizeof(buf), jnum(o, "time", 0));
		h_fmt(h, "<td class=\"num\">%s</td><td class=\"cmd\"", buf);
		h_attr(h, "title", jstr(o, "args"));
		h_raw(h, "><b>");
		h_txt(h, jstr(o, "comm"));
		h_raw(h, "</b></td></tr>");
		if (jint(o, "pid", 0) == pr.open)
			picked(h, o);
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (shown == 0)
		h_raw(h, "<div class=\"empty\"><p>Nothing of that name runs."
		    "</p></div>");
	else if (shown > PROCS_ROWS)
		h_fmt(h, "<p class=\"dim\">%d more: the filter narrows them."
		    "</p>", shown - PROCS_ROWS);
	h_raw(h, "<p class=\"dim\">CPU is what a process used between the two "
	    "last looks, in percent of one CPU; WCPU is the kernel's own "
	    "figure, which follows more slowly, as <code>top</code> shows "
	    "it. I/O is blocks read and written a second. Res is the "
	    "memory it holds now, Size what it has mapped.</p>");
}

static void
proc_job(struct server *s, const ucl_object_t *o, const char *verb,
    const char *word)
{
	char	*json, title[160];

	if (asprintf(&json, "{\"kind\":\"process\",\"verb\":\"%s\",\"args\":["
	    "\"%lld\",\"%s\",\"%lld\"]}", verb, (long long)jint(o, "pid", 0),
	    word, (long long)jint(o, "start", 0)) == -1)
		abort();
	if (strcmp(verb, "signal") == 0)
		snprintf(title, sizeof(title), "kill -%s %lld (%s)", word,
		    (long long)jint(o, "pid", 0), jstr(o, "comm") != NULL ?
		    jstr(o, "comm") : "?");
	else
		snprintf(title, sizeof(title), "renice %s %lld (%s)", word,
		    (long long)jint(o, "pid", 0), jstr(o, "comm") != NULL ?
		    jstr(o, "comm") : "?");
	job_send_host(s, json, title, JOB_PROCESS, "");
}

static bool
signal_ok(const char *name)
{
	size_t	i;

	for (i = 0; i < nitems(signals); i++)
		if (strcmp(name, signals[i]) == 0)
			return (true);
	return (false);
}

bool
procs_form(const char *form, const ucl_object_t *f)
{
	const ucl_object_t	*o;
	struct server		*s;
	const char		*v;
	char			 body[500], arg[32];
	int			 n;

	if (strcmp(form, "ps-signal") != 0 && strcmp(form, "ps-renice") != 0)
		return (false);
	if ((s = cur_server()) == NULL || (o = proc_find(pr.open)) == NULL) {
		toast(true, "That process is gone");
		pr.open = 0;
		return (true);
	}
	if (strcmp(form, "ps-renice") == 0) {
		v = jstr(f, "nice") != NULL ? jstr(f, "nice") : "";
		n = atoi(v);
		if (v[0] == '\0' || n < -20 || n > 20 || v[strspn(v,
		    "-0123456789")] != '\0') {
			toast(true, "A nice value is from -20 to 20");
			return (true);
		}
		snprintf(arg, sizeof(arg), "%d", n);
		proc_job(s, o, "renice", arg);
		return (true);
	}
	v = jstr(f, "signal") != NULL ? jstr(f, "signal") : "";
	if (!signal_ok(v))
		return (true);
	snprintf(body, sizeof(body), "SIG%s to process %lld, %s of %s, on %s."
	    "%s", v, (long long)jint(o, "pid", 0), jstr(o, "comm") != NULL ?
	    jstr(o, "comm") : "?", jstr(o, "user") != NULL ? jstr(o, "user") :
	    "?", s->name, strcmp(v, "KILL") == 0 ? " It ends at once, with "
	    "nothing saved." : strcmp(v, "STOP") == 0 ? " It stands still "
	    "until it is sent CONT." : "");
	snprintf(arg, sizeof(arg), "%lld", (long long)jint(o, "pid", 0));
	confirm("Send the signal", body, "Send", strcmp(v, "CONT") != 0, NULL,
	    "do-ps-signal", arg, v);
	return (true);
}

bool
procs_action(const char *act, const char *arg, const char *value)
{
	const ucl_object_t	*o;
	struct server		*s;
	int			 col;
	bool			 desc;

	if (strncmp(act, "ps-", 3) != 0 && strcmp(act, "do-ps-signal") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "ps-open") == 0) {
		pr.open = pr.open == atoll(arg) ? 0 : atoll(arg);
	} else if (strcmp(act, "ps-live") == 0) {
		pr.paused = !pr.paused;
		if (!pr.paused)
			refresh_procs(s, true);
	} else if (strcmp(act, "ps-kernel") == 0) {
		pr.kernel = !pr.kernel;
	} else if (strcmp(act, "ps-sort") == 0) {
		/* The most first; pressed again, as the host gave them. */
		desc = false;
		col = tbl_col("procs", &desc);
		if (col == atoi(arg) && desc)
			tbl_set("procs", -1, false);
		else if (atoi(arg) >= 0 && atoi(arg) < C_N)
			tbl_set("procs", atoi(arg), true);
	} else if (strcmp(act, "ps-jail") == 0) {
		snprintf(pr.jail, sizeof(pr.jail), "%s", arg);
		pr.open = 0;
		pr.loading = false;
		refresh_procs(s, true);
	} else if (strcmp(act, "do-ps-signal") == 0) {
		if ((o = proc_find(atoll(arg))) == NULL || !signal_ok(value))
			toast(true, "That process is gone");
		else
			proc_job(s, o, "signal", value);
	}
	return (true);
}
