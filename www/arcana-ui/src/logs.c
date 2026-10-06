/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What a host wrote down: the logs of its syslogd(8), one at a time,
 * the newest line first.  The end of the file is read, and then only
 * what was written since, every few seconds, so the page follows the
 * log as tail -f does.  A text is searched for on the host, where the
 * whole file is; the filter narrows what is here.
 */

#define	_GNU_SOURCE		/* strcasestr(3) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "app.h"

#define	nitems(x)	(sizeof(x) / sizeof((x)[0]))

#define	LOGS_EVERY	3000	/* ms between two looks, while live */
#define	LOGS_FIRST	200	/* lines asked for at first */
#define	LOGS_MAX	5000	/* and at most, which is also what is held */
#define	EVENTS		"@events"	/* not a file: what the agent saw happen */

enum { C_N_, C_TIME, C_LEVEL, C_HOST, C_TAG, C_PID, C_TEXT, C_N };

static const struct tcol cols[C_N] = {
	{ "#", "n", true }, { "Time", "time", false },
	{ "Level", "level", false },
	{ "Host", "host", false }, { "Program", "tag", false },
	{ "PID", "pid", true }, { "Message", "text", false },
};

static struct {
	char		 sid[9];
	char		 name[129];	/* the file, "" for messages */
	char		 jail[256];	/* whose logs: "" the host's */
	char		 text[129];	/* searched for on the host */
	ucl_object_t	*lines;		/* an array, the oldest first */
	ucl_object_t	*files;
	long long	 position;	/* where the file ended */
	long long	 seq;		/* the last line's number */
	int		 want;		/* lines asked for */
	bool		 loading;
	bool		 following;	/* the request under way reads on */
	bool		 paused;
	bool		 rotated;
	char		 error[300];
	double		 fetched;
} lg;

static void
forget(void)
{

	if (lg.lines != NULL)
		ucl_object_unref(lg.lines);
	lg.lines = NULL;
	lg.position = -1;
	lg.seq = 0;
	lg.rotated = false;
}

/* An event as a line: its time, its kind, and what it is about. */
static ucl_object_t *
event_line(const ucl_object_t *e)
{
	const ucl_object_t	*d;
	ucl_object_t		*l;
	struct tm		 tm;
	const char		*kind;
	char			 buf[400];
	time_t			 t;

	l = ucl_object_typed_new(UCL_OBJECT);
	t = (time_t)jint(e, "t", 0);
	localtime_r(&t, &tm);
	strftime(buf, sizeof(buf), "%b %e %H:%M:%S", &tm);
	ucl_object_insert_key(l, ucl_object_fromstring(buf), "time", 0, false);
	kind = jstr(e, "kind") != NULL ? jstr(e, "kind") : "";
	ucl_object_insert_key(l, ucl_object_fromstring(kind), "tag", 0, false);
	d = jget(e, "data");
	if (strncmp(kind, "route-", 6) == 0)
		snprintf(buf, sizeof(buf), "%s via %s on %s, metric %lld, "
		    "weight %lld, table %lld%s", jstr(d, "destination") !=
		    NULL ? jstr(d, "destination") : "?", jstr(d, "gateway") !=
		    NULL ? jstr(d, "gateway") : "?", jstr(d,
		    "interface-name") != NULL ? jstr(d, "interface-name") :
		    "?", (long long)jint(d, "metric", 0), (long long)jint(d,
		    "weight", 0), (long long)jint(d, "fib", 0), kind[6] ==
		    'd' ? ": gone" : "");
	else if (strcmp(kind, "routes") == 0)
		snprintf(buf, sizeof(buf), "%lld more routes changed in that "
		    "second", (long long)jint(d, "changed", 0));
	else if (strncmp(kind, "link", 4) == 0)
		snprintf(buf, sizeof(buf), "%s %s, %s, mtu %lld%s", jstr(d,
		    "interface") != NULL ? jstr(d, "interface") : "?",
		    jbool(d, "up") ? "up" : "down", jbool(d, "carrier") ?
		    "link state up" : "link state changed to down",
		    (long long)jint(d, "mtu", 0), kind[4] == '-' ? ": gone" :
		    "");
	else if (strcmp(kind, "threshold") == 0)
		snprintf(buf, sizeof(buf), "%s at %lld%%, %s its limit of "
		    "%lld%%", jstr(d, "what") != NULL ? jstr(d, "what") : "?",
		    (long long)jint(d, "value", 0), jbool(d, "over") ? "over" :
		    "back under", (long long)jint(d, "limit", 0));
	else if (strncmp(kind, "address-", 8) == 0)
		snprintf(buf, sizeof(buf), "%s/%lld %s %s", jstr(d,
		    "address") != NULL ? jstr(d, "address") : "?",
		    (long long)jint(d, "prefixlen", 0), kind[8] == 'd' ?
		    "taken off" : "on", jstr(d, "interface") != NULL ?
		    jstr(d, "interface") : "?");
	else
		buf[0] = '\0';
	ucl_object_insert_key(l, ucl_object_fromstring(buf), "text", 0, false);
	return (l);
}

static void
logs_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*d, *l;
	ucl_object_iter_t	 it;
	ucl_object_t		*c;
	char			*sid;

	sid = arg;
	if (strcmp(sid, lg.sid) != 0) {
		free(sid);
		return;
	}
	free(sid);
	lg.loading = false;
	lg.fetched = arc_now();
	if (status != 200 || !jbool(o, "ok") || (d = jget(o, "data")) ==
	    NULL) {
		snprintf(lg.error, sizeof(lg.error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	lg.error[0] = '\0';
	/* A file turned over is read from its start: what was is old. */
	if (!lg.following || jbool(d, "rotated")) {
		if (lg.lines != NULL)
			ucl_object_unref(lg.lines);
		lg.lines = NULL;
		lg.rotated = jbool(d, "rotated");
	}
	if (lg.lines == NULL)
		lg.lines = ucl_object_typed_new(UCL_ARRAY);
	/* The agent's events: its numbers are theirs, last is where to
	 * go on from. */
	it = NULL;
	while ((l = ucl_object_iterate(jget(d, "events"), &it, true)) !=
	    NULL) {
		c = event_line(l);
		ucl_object_insert_key(c, ucl_object_fromint(jint(l, "n", 0)),
		    "n", 0, false);
		ucl_array_append(lg.lines, c);
	}
	it = NULL;
	while ((l = ucl_object_iterate(jget(d, "lines"), &it, true)) != NULL) {
		c = ucl_object_copy(l);
		ucl_object_insert_key(c, ucl_object_fromint(++lg.seq), "n", 0,
		    false);
		ucl_array_append(lg.lines, c);
	}
	while (ucl_array_size(lg.lines) > LOGS_MAX)
		ucl_object_unref(ucl_array_pop_first(lg.lines));
	lg.position = jget(d, "events") != NULL ? jint(d, "last", 0) :
	    jint(d, "position", -1);
	if (jget(d, "files") != NULL) {
		if (lg.files != NULL)
			ucl_object_unref(lg.files);
		lg.files = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(d,
		    "files"));
	}
	if (lg.name[0] == '\0' && jstr(d, "name") != NULL)
		snprintf(lg.name, sizeof(lg.name), "%s", jstr(d, "name"));
}

/*
 * Read the log.  Again reads its end anew; without it, what is here
 * stays, and on a tick what came since is added.
 */
static void
logs_read(struct server *s, bool follow)
{
	struct html	 u;
	const char	*p;
	char		*url;

	if (!app.online || lg.loading)
		return;
	if (strcmp(lg.sid, s->id) != 0) {
		forget();
		if (lg.files != NULL)
			ucl_object_unref(lg.files);
		lg.files = NULL;
		lg.error[0] = '\0';
		lg.name[0] = lg.text[0] = lg.jail[0] = '\0';
		lg.want = LOGS_FIRST;
		follow = false;
	}
	if (lg.want == 0)
		lg.want = LOGS_FIRST;
	if (follow && (lg.lines == NULL || lg.position < 0))
		follow = false;
	snprintf(lg.sid, sizeof(lg.sid), "%s", s->id);
	lg.loading = true;
	lg.following = follow;
	if (!follow)
		lg.seq = 0;
	memset(&u, 0, sizeof(u));
	if (strcmp(lg.name, EVENTS) == 0) {
		h_fmt(&u, "/api/servers/%s/events?after=%lld", s->id, follow ?
		    lg.position : 0LL);
		url = h_take(&u);
		api("GET", url, NULL, logs_cb, strdup(s->id));
		free(url);
		return;
	}
	h_fmt(&u, "/api/servers/%s/log?lines=%d", s->id, follow ? LOGS_MAX :
	    lg.want);
	if (lg.name[0] != '\0')
		h_fmt(&u, "&name=%s", lg.name);
	if (lg.jail[0] != '\0')
		h_fmt(&u, "&jail=%s", lg.jail);
	if (lg.text[0] != '\0') {
		/* Any text: escaped, as a URL has it. */
		h_raw(&u, "&filter=");
		for (p = lg.text; *p != '\0'; p++)
			h_fmt(&u, "%%%02X", (unsigned int)(unsigned char)*p);
	}
	if (follow)
		h_fmt(&u, "&position=%lld", lg.position);
	url = h_take(&u);
	api("GET", url, NULL, logs_cb, strdup(s->id));
	free(url);
}

void
refresh_logs(struct server *s, bool again)
{

	if (!again && strcmp(lg.sid, s->id) == 0 && (lg.lines != NULL ||
	    lg.error[0] != '\0'))
		return;
	logs_read(s, false);
}

void
logs_tick(double now)
{
	struct server	*s;

	if (app.node != NODE_HOST || app.tab != TAB_LOG || lg.paused ||
	    !app.visible || lg.loading || (s = cur_server()) == NULL ||
	    strcmp(lg.sid, s->id) != 0 || now - lg.fetched < LOGS_EVERY)
		return;
	logs_read(s, true);
}

/* Is it a line somebody should see?  By its words: syslog's file has
 * no level in it. */
static const char *
line_class(const char *text)
{
	static const char *const bad[] = { "panic", "fatal", "error", "fail",
	    "denied", "refused", "segfault", "core dumped", "timed out",
	    "timeout" };
	static const char *const warn[] = { "warn", "retry", "retrying",
	    "invalid", "unable", "cannot", "not found",
	    "changed to down" };
	size_t	i;

	if (text == NULL)
		return ("");
	for (i = 0; i < nitems(bad); i++)
		if (strcasestr(text, bad[i]) != NULL)
			return (" l-bad");
	for (i = 0; i < nitems(warn); i++)
		if (strcasestr(text, warn[i]) != NULL)
			return (" l-warn");
	return ("");
}

void
view_logs(struct html *h, struct server *s)
{
	const ucl_object_t	**rows, *o;
	ucl_object_iter_t	  it;
	const char		 *name;
	char			  buf[32];
	int			  r, n, i;
	bool			  mine, asc;

	mine = lg.lines != NULL && strcmp(lg.sid, s->id) == 0;
	h_raw(h, "<div class=\"toolbar\"><nav class=\"sub\">");
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"lg-jail\" "
	    "data-arg=\"\" title=\"The host's own logs\">host</button>",
	    lg.jail[0] == '\0' ? " on" : "");
	it = NULL;
	while (s->list != NULL && (o = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		if (jstr(o, "name") == NULL || jstr(o, "state") == NULL ||
		    strcmp(jstr(o, "state"), "running") != 0)
			continue;
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"lg-jail\"",
		    strcmp(lg.jail, jstr(o, "name")) == 0 ? " on" : "");
		h_attr(h, "data-arg", jstr(o, "name"));
		h_raw(h, " title=\"The jail's own /var/log\">");
		h_txt(h, jstr(o, "name"));
		h_raw(h, "</button>");
	}
	h_raw(h, "</nav><label class=\"lg-file\">Log<select "
	    "data-input=\"lg-file\">");
	n = 0;
	it = NULL;
	while (mine && (o = ucl_object_iterate(lg.files, &it, true)) != NULL) {
		if ((name = jstr(o, "name")) == NULL)
			continue;
		n++;
		fmt_size(buf, sizeof(buf), jnum(o, "size", 0));
		h_raw(h, "<option");
		h_attr(h, "value", name);
		h_raw(h, strcmp(name, lg.name) == 0 ? " selected>" : ">");
		h_txt(h, name);
		h_fmt(h, " · %s%s</option>", buf, jbool(o, "packed") ?
		    " · packed" : "");
	}
	if (n == 0 && strcmp(lg.name, EVENTS) != 0) {
		h_raw(h, "<option>");
		h_txt(h, lg.name[0] != '\0' ? lg.name : "messages");
		h_raw(h, "</option>");
	}
	h_fmt(h, "<option value=\"@dmesg\"%s>dmesg · the kernel's messages"
	    "</option><option value=\"@audit\"%s>audit · the trail of now"
	    "</option><option value=\"" EVENTS "\"%s>events · routes, "
	    "interfaces, addresses, limits</option>", strcmp(lg.name,
	    "@dmesg") == 0 ? " selected" : "", strcmp(lg.name, "@audit") ==
	    0 ? " selected" : "", strcmp(lg.name, EVENTS) == 0 ?
	    " selected" : "");
	h_raw(h, "</select></label><form data-form=\"lg-find\" class=\""
	    "kmod-load\"><input name=\"text\" spellcheck=\"false\" "
	    "autocomplete=\"off\" placeholder=\"search the whole file: sshd, "
	    "em0, denied\"");
	h_attr(h, "value", lg.text);
	h_raw(h, "><button class=\"ghost small\">Search</button></form>"
	    "<input class=\"filter\" id=\"filter\" data-input=\"filter\" "
	    "placeholder=\"Filter rows\" autocomplete=\"off\" spellcheck=\""
	    "false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "><span class=\"age\">");
	if (lg.loading && !lg.following)
		h_raw(h, "reading…");
	else if (mine) {
		fmt_age(buf, sizeof(buf), lg.fetched);
		h_txt(h, buf);
	}
	h_fmt(h, "</span><button class=\"ghost small live%s\" data-act=\""
	    "lg-live\" title=\"Follow the log: what is written is read every "
	    "three seconds while this is shown\"><span class=\"led\"></span>"
	    "Live</button><button class=\"icon\" data-act=\"refresh\" title="
	    "\"Read again\">⟳</button></div>", lg.paused ? "" : " on");
	if (strcmp(lg.sid, s->id) == 0 && lg.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, lg.error);
		h_raw(h, "</div>");
	}
	if (!mine) {
		h_raw(h, strcmp(lg.sid, s->id) == 0 && lg.error[0] != '\0' ?
		    "" : "<div class=\"empty\"><p>Reading the log…</p></div>");
		return;
	}
	if (lg.rotated)
		h_raw(h, "<div class=\"notice\">The file was turned over "
		    "while it was followed: this is the new one, from its "
		    "start.</div>");
	h_raw(h, "<table class=\"net logs\">");
	tbl_head(h, "logs", cols, C_N, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("logs", lg.lines, cols, C_N, app.filter);
	for (n = 0; rows[n] != NULL; n++)
		;
	/* The newest first, unless an order was asked for. */
	asc = tbl_sorted("logs");
	for (i = 0; i < n; i++) {
		r = asc ? i : n - 1 - i;
		o = rows[r];
		h_fmt(h, "<tr class=\"lg%s\"><td class=\"num dim\">%lld</td>"
		    "<td class=\"when\">", line_class(jstr(o, "text")),
		    (long long)jint(o, "n", 0));
		h_txt(h, jstr(o, "time"));
		h_raw(h, "</td><td class=\"dim\">");
		h_txt(h, jstr(o, "level"));
		h_raw(h, "</td><td class=\"dim\">");
		h_txt(h, jstr(o, "host"));
		h_raw(h, "</td><td><b>");
		h_txt(h, jstr(o, "tag"));
		h_raw(h, "</b></td><td class=\"num dim\">");
		h_txt(h, jstr(o, "pid"));
		h_raw(h, "</td><td class=\"msg\">");
		h_txt(h, jstr(o, "text"));
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (n == 0)
		h_raw(h, lg.text[0] != '\0' || app.filter[0] != '\0' ?
		    "<div class=\"empty\"><p>No line with that in it.</p>"
		    "</div>" : "<div class=\"empty\"><p>The log is empty.</p>"
		    "</div>");
	if (strcmp(lg.name, EVENTS) == 0) {
		h_fmt(h, "<p class=\"dim\">%d events, the newest first, as the "
		    "kernel told the agent of them through netlink: every "
		    "route, interface and address of the host that came, "
		    "went or changed since the agent started, the last 512 "
		    "kept. A storm of routes is counted, not listed. A "
		    "jail's own network is not in it.</p>",
		    (int)ucl_array_size(lg.lines));
		return;
	}
	if ((int)ucl_array_size(lg.lines) >= lg.want && lg.want < LOGS_MAX)
		h_fmt(h, "<p class=\"more\"><button class=\"ghost small\" "
		    "data-act=\"lg-more\" title=\"Read further back in the "
		    "file\">Older: the last %d lines</button></p>", lg.want *
		    5 > LOGS_MAX ? LOGS_MAX : lg.want * 5);
	h_fmt(h, "<p class=\"dim\">%d lines of <code>", (int)ucl_array_size(
	    lg.lines));
	h_txt(h, lg.name[0] != '\0' ? lg.name : "messages");
	h_raw(h, "</code>, as syslogd wrote them, the newest first. A file "
	    "newsyslog has packed is not read from here. The file has no "
	    "level in it: a line is marked by its words.</p>");
}

bool
logs_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*v;

	if (strcmp(form, "lg-find") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	v = jstr(f, "text") != NULL ? jstr(f, "text") : "";
	if (strlen(v) > 128) {
		toast(true, "At most 128 letters are searched for");
		return (true);
	}
	snprintf(lg.text, sizeof(lg.text), "%s", v);
	lg.loading = false;
	logs_read(s, false);
	return (true);
}

static bool
name_ok(const char *s)
{

	if (s[0] == '\0' || s[0] == '.' || strlen(s) > 128)
		return (false);
	return (s[strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
	    "YZ0123456789_.-")] == '\0');
}

bool
logs_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;

	(void)arg;
	if (strncmp(act, "lg-", 3) != 0 && strcmp(act, "input:lg-file") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "lg-jail") == 0) {
		snprintf(lg.jail, sizeof(lg.jail), "%s", arg);
		if (lg.name[0] == '@')
			lg.name[0] = '\0';
		lg.want = LOGS_FIRST;
		lg.loading = false;
		forget();
		if (lg.files != NULL)
			ucl_object_unref(lg.files);
		lg.files = NULL;
		logs_read(s, false);
	} else if (strcmp(act, "lg-live") == 0) {
		lg.paused = !lg.paused;
		if (!lg.paused)
			logs_read(s, true);
	} else if (strcmp(act, "lg-more") == 0) {
		lg.want = lg.want * 5 > LOGS_MAX ? LOGS_MAX : lg.want * 5;
		lg.loading = false;
		logs_read(s, false);
	} else if (strcmp(act, "input:lg-file") == 0 && (name_ok(value) ||
	    strcmp(value, EVENTS) == 0 || strcmp(value, "@dmesg") == 0 ||
	    strcmp(value, "@audit") == 0) && strcmp(value, lg.name) != 0) {
		snprintf(lg.name, sizeof(lg.name), "%s", value);
		lg.want = LOGS_FIRST;
		lg.loading = false;
		forget();
		logs_read(s, false);
	}
	return (true);
}
