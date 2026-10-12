/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's kernel state, sysctl(8): a part of the tree at a time, with
 * what each value is said to be, one set and kept for the next boot;
 * and how the host is reached: the agent's listeners, who is connected
 * to it now, and the console's own way to it changed from TCP to SCTP
 * and back.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#ifndef nitems
#define	nitems(x)	(sizeof(x) / sizeof((x)[0]))
#endif

#define	SYSCTL_ROWS	500	/* drawn at once, at most */
#define	TRANSPORT_MS	4000	/* how often the sessions are read again */

static struct {
	char		 sid[9];
	ucl_object_t	*data;
	bool		 loading;
	char		 error[300];
	double		 fetched;
	char		 prefix[64];	/* where in the tree */
	char		 asked[64];	/* what data is the answer for */
	char		 edit[204];	/* the one being set */
	int64_t		 total;
	bool		 truncated;
	int		 stream;	/* the id of what is coming in parts */
	bool		 streaming;
	bool		 nostream;	/* no socket for it: asked for whole */
} sy = { .prefix = "kern." };

static struct {
	char		 sid[9];
	ucl_object_t	*o;
	bool		 loading;
	bool		 busy;		/* a retry or a switch is on its way */
	char		 error[300];
	double		 fetched;
} tr;

static const char *const trees[] = { "kern.", "vm.", "vfs.", "net.", "hw.",
    "security.", "kstat.", "dev.", "debug.", "machdep.", "user.", "compat." };

static bool
name_ok(const char *s)
{

	if (s[0] == '\0' || s[0] == '-' || s[0] == '.' || strlen(s) > 200)
		return (false);
	return (s[strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
	    "YZ0123456789_.-%")] == '\0');
}

static void
sysctl_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*key;

	key = arg;
	if (strncmp(key, sy.sid, strlen(sy.sid)) != 0 || strcmp(key +
	    strlen(sy.sid) + 1, sy.prefix) != 0) {
		free(key);
		return;
	}
	free(key);
	sy.loading = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(sy.error, sizeof(sy.error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	sy.error[0] = '\0';
	if (sy.data != NULL)
		ucl_object_unref(sy.data);
	sy.data = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
	snprintf(sy.asked, sizeof(sy.asked), "%s", sy.prefix);
	sy.total = jint(o, "total", 0);
	sy.truncated = jbool(o, "truncated");
	sy.fetched = arc_now();
}

/* What sysctl.conf keeps, beside the values that come in parts. */
static void
kept_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*key;

	(void)err;
	key = arg;
	if (strncmp(key, sy.sid, strlen(sy.sid)) == 0 && status == 200 &&
	    sy.data != NULL && !sy.nostream && jget(o, "data.kept") != NULL) {
		ucl_object_delete_key(sy.data, "kept");
		ucl_object_insert_key(sy.data, ucl_object_ref(jget(o,
		    "data.kept")), "kept", 0, false);
	}
	free(key);
}

/* Read the part of the tree shown; again asks though it is here. */
void
refresh_sysctl(struct server *s, bool again)
{
	char	url[200], msg[400], *key;

	if (!app.online || (sy.loading && !sy.streaming))
		return;
	/* What is coming in parts is not asked for again, but another
	 * part of the tree is, and ends it. */
	if (sy.streaming && strcmp(sy.sid, s->id) == 0 && strcmp(sy.asked,
	    sy.prefix) == 0)
		return;
	if (strcmp(sy.sid, s->id) != 0) {
		if (sy.data != NULL)
			ucl_object_unref(sy.data);
		sy.data = NULL;
		sy.error[0] = '\0';
		sy.edit[0] = '\0';
	} else if (!again && strcmp(sy.asked, sy.prefix) == 0 && (sy.data !=
	    NULL || sy.error[0] != '\0'))
		return;
	snprintf(sy.sid, sizeof(sy.sid), "%s", s->id);
	sy.loading = true;
	if (asprintf(&key, "%s %s", s->id, sy.prefix) == -1)
		abort();
	if (sy.nostream) {
		snprintf(url, sizeof(url), "/api/servers/%s/sysctl%s%s", s->id,
		    sy.prefix[0] != '\0' ? "?filter=" : "", sy.prefix);
		api("GET", url, NULL, sysctl_cb, key);
		return;
	}
	/*
	 * The values come in parts, each shown as it arrives, and none
	 * is left out for size.  What sysctl.conf keeps comes with an
	 * ordinary answer, asked for with one value.
	 */
	if (sy.streaming) {
		snprintf(msg, sizeof(msg), "{\"id\":%d,\"stop\":true}",
		    sy.stream);
		arc_stream_send(msg);
	}
	if (sy.data != NULL)
		ucl_object_unref(sy.data);
	sy.data = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(sy.data, ucl_object_typed_new(UCL_ARRAY),
	    "values", 0, false);
	snprintf(sy.asked, sizeof(sy.asked), "%s", sy.prefix);
	sy.error[0] = '\0';
	sy.truncated = false;
	sy.total = 0;
	sy.streaming = true;
	snprintf(msg, sizeof(msg), "{\"id\":%d,\"server\":\"%s\",\"what\":"
	    "\"sysctl\",\"filter\":\"%s\"}", ++sy.stream, s->id, sy.prefix);
	arc_stream_send(msg);
	snprintf(url, sizeof(url), "/api/servers/%s/sysctl?filter=kern.ostype",
	    s->id);
	api("GET", url, NULL, kept_cb, key);
}

/* A part of the values, their end, or the socket's. */
void
sysctl_stream(const ucl_object_t *o)
{
	const ucl_object_t	*r;
	ucl_object_t		*vals;
	ucl_object_iter_t	 it;
	struct server		*s;

	if (jbool(o, "closed")) {
		/* No socket, or it went: asked for whole, as before. */
		if (sy.streaming) {
			sy.streaming = sy.loading = false;
			sy.nostream = true;
			if ((s = cur_server()) != NULL && strcmp(s->id,
			    sy.sid) == 0)
				refresh_sysctl(s, true);
		}
		return;
	}
	if (!sy.streaming || jint(o, "id", -1) != sy.stream || sy.data == NULL)
		return;
	vals = (ucl_object_t *)(uintptr_t)jget(sy.data, "values");
	it = NULL;
	while ((r = ucl_object_iterate(jget(o, "rows"), &it, true)) != NULL)
		ucl_array_append(vals, ucl_object_ref(r));
	sy.fetched = arc_now();
	if (jbool(o, "done") || jstr(o, "error") != NULL) {
		sy.streaming = sy.loading = false;
		sy.total = (int64_t)ucl_array_size(vals);
		if (jstr(o, "error") != NULL)
			snprintf(sy.error, sizeof(sy.error), "%s", jstr(o,
			    "error"));
	}
}

static const char *
kept_value(const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(jget(sy.data, "kept"), &it, true)) !=
	    NULL)
		if (jstr(o, "name") != NULL && strcmp(jstr(o, "name"), name) ==
		    0)
			return (jstr(o, "value") != NULL ? jstr(o, "value") :
			    "");
	return (NULL);
}

void
view_sysctl(struct html *h, struct server *s)
{
	static const struct tcol	cols[] = {
		{ "Name", "name", false }, { "Value", "value", false },
		{ "Type", "type", false }, { "", NULL, false },
		{ "What it is", "descr", false },
	};
	const ucl_object_t		**rows, *o;
	ucl_object_iter_t		  it;
	const char			 *name, *kv;
	size_t				  i;
	bool				  mine;
	int				  r, n;

	mine = sy.data != NULL && strcmp(sy.sid, s->id) == 0;
	h_raw(h, "<div class=\"toolbar\"><nav class=\"sub\">");
	for (i = 0; i < nitems(trees); i++) {
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"sy-tree\"",
		    strcmp(sy.prefix, trees[i]) == 0 ? " on" : "");
		h_attr(h, "data-arg", trees[i]);
		h_fmt(h, ">%.*s</button>", (int)strlen(trees[i]) - 1, trees[i]);
	}
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"sy-tree\" "
	    "data-arg=\"\" title=\"The whole tree, which comes in parts\">all"
	    "</button></nav>", sy.prefix[0] ==
	    '\0' ? " on" : "");
	h_raw(h, "<form data-form=\"sy-from\" class=\"kmod-load\"><input name="
	    "\"name\" spellcheck=\"false\" autocomplete=\"off\" placeholder="
	    "\"or from a name: net.inet.tcp\"");
	for (i = 0; i < nitems(trees); i++)
		if (strcmp(sy.prefix, trees[i]) == 0)
			break;
	if (i == nitems(trees) && sy.prefix[0] != '\0')
		h_attr(h, "value", sy.prefix);
	h_raw(h, "><button class=\"ghost small\">Read</button></form>"
	    "<input class=\"filter\" id=\"filter\" data-input=\"filter\" "
	    "placeholder=\"Filter rows\" autocomplete=\"off\" spellcheck=\""
	    "false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "><span class=\"age\">");
	if (sy.streaming && strcmp(sy.sid, s->id) == 0)
		h_fmt(h, "reading… %d so far", (int)ucl_array_size(jget(
		    sy.data, "values")));
	else if (sy.loading && strcmp(sy.sid, s->id) == 0)
		h_raw(h, "reading…");
	else if (mine) {
		char	age[32];

		fmt_age(age, sizeof(age), sy.fetched);
		h_txt(h, age);
	}
	h_raw(h, "</span><button class=\"icon\" data-act=\"refresh\" title=\""
	    "Read again\"><svg class=\"ti\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M20 12a8 8 0 1 1-2.3-5.7M20 4v4h-4\"/></svg></button></div>");
	if (strcmp(sy.sid, s->id) == 0 && sy.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, sy.error);
		h_raw(h, "</div>");
	}
	if (!mine || (sy.streaming && ucl_array_size(jget(sy.data,
	    "values")) == 0)) {
		h_raw(h, "<div class=\"empty\"><p>Reading the kernel's state…"
		    "</p></div>");
		return;
	}
	/* What the next boot sets, whichever part of the tree is shown. */
	if (ucl_array_size(jget(sy.data, "kept")) > 0) {
		h_raw(h, "<p class=\"sy-kept\"><b>Kept in sysctl.conf</b> ");
		it = NULL;
		while ((o = ucl_object_iterate(jget(sy.data, "kept"), &it,
		    true)) != NULL) {
			h_raw(h, "<span class=\"chip\" data-act=\"sy-edit\"");
			h_attr(h, "data-arg", jstr(o, "name"));
			h_raw(h, ">");
			h_txt(h, jstr(o, "name"));
			h_raw(h, "=");
			h_txt(h, jstr(o, "value"));
			h_raw(h, "</span> ");
		}
		h_raw(h, "</p>");
	}
	if (sy.truncated)
		h_fmt(h, "<div class=\"notice\">The first %d of %lld values: "
		    "pick a part of the tree, or name where to begin.</div>",
		    (int)ucl_array_size(jget(sy.data, "values")), (long long)
		    sy.total);
	h_raw(h, "<table class=\"net sysctl\">");
	tbl_head(h, "sysctl", cols, 5, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("sysctl", jget(sy.data, "values"), cols, 5, app.filter);
	for (n = 0; rows[n] != NULL; n++)
		;
	for (r = 0; (o = rows[r]) != NULL && r < SYSCTL_ROWS; r++) {
		name = jstr(o, "name") != NULL ? jstr(o, "name") : "";
		kv = kept_value(name);
		if (strcmp(sy.edit, name) == 0) {
			/* Being set: its value in a field, in its row. */
			h_raw(h, "<tr class=\"editing\"><td><b>");
			h_txt(h, name);
			h_raw(h, "</b></td><td colspan=\"5\"><form data-form="
			    "\"sy-set\" class=\"sy-set\"><input name=\"value\" "
			    "spellcheck=\"false\" autocomplete=\"off\"");
			h_attr(h, "value", jstr(o, "value"));
			h_fmt(h, "><label class=\"toggle\" title=\"Also in "
			    "sysctl.conf: set again when the host starts\">"
			    "<input type=\"checkbox\" name=\"persist\"%s><span>"
			    "at boot too</span></label><button class=\"small\">"
			    "Set</button><button type=\"button\" class=\"ghost "
			    "small\" data-act=\"sy-edit\" data-arg=\"\">Cancel"
			    "</button></form><small class=\"dim\">", kv != NULL ?
			    " checked" : "");
			h_txt(h, jstr(o, "descr"));
			h_raw(h, "</small></td></tr>");
			continue;
		}
		if (jbool(o, "rw")) {
			h_raw(h, "<tr class=\"pick\" data-act=\"sy-edit\" title="
			    "\"Press to set it\"");
			h_attr(h, "data-arg", name);
			h_raw(h, "><td><b>");
		} else
			h_raw(h, "<tr class=\"ro\" title=\"The kernel does not "
			    "let it be set\"><td><b>");
		h_txt(h, name);
		h_raw(h, "</b></td><td class=\"val\">");
		h_txt(h, jstr(o, "value"));
		h_raw(h, "</td><td class=\"dim\">");
		h_txt(h, jstr(o, "type"));
		h_raw(h, "</td><td>");
		if (kv != NULL) {
			h_raw(h, "<span class=\"chip\" title=\"sysctl.conf sets "
			    "it when the host starts, to ");
			h_txt(h, kv);
			h_raw(h, "\">kept</span>");
		}
		if (jbool(o, "tun"))
			h_raw(h, "<span class=\"chip dim\" title=\"Can be set "
			    "before the kernel starts, in loader.conf\">"
			    "tunable</span>");
		h_raw(h, "</td><td class=\"dim\">");
		h_txt(h, jstr(o, "descr"));
		h_raw(h, "</td><td class=\"acts\">");
		if (jbool(o, "rw")) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "sy-edit\"");
			h_attr(h, "data-arg", name);
			h_raw(h, ">Set</button>");
		}
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (n == 0)
		h_raw(h, "<div class=\"empty\"><p>Nothing of that name."
		    "</p></div>");
	else if (n > SYSCTL_ROWS)
		h_fmt(h, "<p class=\"dim\">%d more: the filter narrows them."
		    "</p>", n - SYSCTL_ROWS);
	h_raw(h, "<p class=\"dim\">As <code>sysctl -a</code> has them, read "
	    "from the kernel; values that are not numbers or text are left "
	    "out. One is set with <code>sysctl name=value</code>, by a job; "
	    "kept, it is also written to <code>/etc/sysctl.conf</code>.</p>");
}

static void	safe_cb(int, const ucl_object_t *, const char *, void *);

bool
sysctl_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*v;
	char		*qn, *qv, *json, title[300];

	if (strcmp(form, "sy-set") != 0 && strcmp(form, "sy-from") != 0 &&
	    strcmp(form, "tr-safe") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(form, "tr-safe") == 0) {
		char	*end, url[64], body[48];
		long	 k;

		v = jstr(f, "wait") != NULL ? jstr(f, "wait") : "";
		k = v[0] == '\0' ? 0 : strtol(v, &end, 10);
		if ((v[0] != '\0' && *end != '\0') || (k != 0 && (k < 10 ||
		    k > 3600))) {
			toast(true, "The rollback timer is 10 to 3600 seconds, "
			    "or empty for the agent's own");
			return (true);
		}
		snprintf(url, sizeof(url), "/api/servers/%s", s->id);
		snprintf(body, sizeof(body), "{\"safe_wait\":%ld}", k);
		api("POST", url, body, safe_cb, NULL);
		return (true);
	}
	if (strcmp(form, "sy-from") == 0) {
		v = jstr(f, "name") != NULL ? jstr(f, "name") : "";
		if (v[0] != '\0' && !name_ok(v)) {
			toast(true, "A sysctl is named with letters, digits "
			    "and . _ - %%");
			return (true);
		}
		snprintf(sy.prefix, sizeof(sy.prefix), "%s", v);
		sy.edit[0] = '\0';
		refresh_sysctl(s, true);
		return (true);
	}
	v = jstr(f, "value") != NULL ? jstr(f, "value") : "";
	if (!name_ok(sy.edit) || strlen(v) > 1024 || strchr(v, '\n') != NULL) {
		toast(true, "A value is one line");
		return (true);
	}
	qn = json_quote(sy.edit);
	qv = json_quote(v);
	if (asprintf(&json, "{\"kind\":\"sysctl\",\"args\":[%s,%s],"
	    "\"persist\":%s}", qn, qv, jbool(f, "persist") ? "true" : "false")
	    == -1)
		abort();
	free(qn);
	free(qv);
	snprintf(title, sizeof(title), "sysctl %s=%s", sy.edit, v);
	job_send_host(s, json, title, JOB_SYSCTL, sy.edit);
	sy.edit[0] = '\0';
	return (true);
}

static void
transport_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid;

	sid = arg;
	if (strcmp(sid, tr.sid) != 0) {
		free(sid);
		return;
	}
	free(sid);
	tr.loading = false;
	tr.busy = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(tr.error, sizeof(tr.error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		/* What it said before is still what there is to show. */
		if (status != 200)
			return;
	} else
		tr.error[0] = '\0';
	if (jget(o, "data") == NULL)
		return;
	if (tr.o != NULL)
		ucl_object_unref(tr.o);
	tr.o = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	tr.fetched = arc_now();
}

/* How the host is reached and who is connected; retry has it try SCTP. */
void
refresh_transport(struct server *s, bool again, bool retry)
{
	char	url[96];

	if (!app.online || (tr.loading && strcmp(tr.sid, s->id) == 0))
		return;
	if (strcmp(tr.sid, s->id) != 0) {
		if (tr.o != NULL)
			ucl_object_unref(tr.o);
		tr.o = NULL;
		tr.error[0] = '\0';
	} else if (!again && tr.o != NULL)
		return;
	snprintf(tr.sid, sizeof(tr.sid), "%s", s->id);
	tr.loading = true;
	snprintf(url, sizeof(url), "/api/servers/%s/transport", s->id);
	api(retry ? "POST" : "GET", url, retry ? "{\"retry\":true}" : NULL,
	    transport_cb, strdup(s->id));
}

/* The sessions change by themselves: read again while they are shown. */
void
transport_tick(double now)
{
	struct server	*s;

	if (app.node != NODE_HOST || app.tab != TAB_SUMMARY || !app.visible ||
	    (s = cur_server()) == NULL || s->failed)
		return;
	if (strcmp(tr.sid, s->id) != 0 || now - tr.fetched > TRANSPORT_MS)
		refresh_transport(s, true, false);
}

static void
switch_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*to;

	to = arg;
	tr.busy = false;
	if (status == 200 && jbool(o, "ok")) {
		toast(false, "Reached over %s from now on", to);
		tr.sid[0] = '\0';
		refresh_servers();
	} else
		toast(true, "It does not answer over %s (%s): the host is "
		    "reached as before.", to, jstr(o, "error.message") != NULL ?
		    jstr(o, "error.message") : err != NULL ? err :
		    "no answer");
	free(to);
}

/*
 * Are the two the same way in?  The agent says what it was told to
 * listen on, which may be every address (0.0.0.0, ::) where the
 * console names one: the transport and the port are what tell.
 */
static bool
same_way(const char *theirs, const char *ours)
{
	const char	*tp, *op;
	size_t		 n;

	if (strcmp(theirs, ours) == 0)
		return (true);
	n = strcspn(ours, ":");
	if (strncmp(theirs, ours, n + 1) != 0 || strncmp(ours, "unix:", 5) ==
	    0)
		return (false);
	tp = strrchr(theirs, ':');
	op = strrchr(ours, ':');
	return (tp != NULL && op != NULL && strcmp(tp, op) == 0);
}

static void
safe_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	if (status != 200) {
		toast(true, "The rollback timer was not saved: %s", err != NULL ?
		    err : "the console refused");
		return;
	}
	toast(false, "Rollback timer saved");
	servers_cb(status, o, err, arg);
}

/*
 * The host's rollback timer: how long a change made in safe mode waits
 * for the console to be heard from again before the agent undoes it.
 */
void
view_safe(struct html *h, struct server *s)
{

	h_raw(h, "<section class=\"transport\">");
	box_head(h, "safe", "h3");
	h_raw(h, "Rollback timer</h3>");
	if (box_shut("safe")) {
		h_raw(h, "</section>");
		return;
	}
	h_raw(h, "<p class=\"dim\">A change made in safe mode (an address, a "
	    "route, an interface, a service, BIRD's configuration) is undone "
	    "by the agent unless the console reaches the host again within "
	    "this time: a change that cut the host off puts itself back. ");
	if (s->safe_wait > 0)
		h_fmt(h, "This host waits %d s.", s->safe_wait);
	else
		h_raw(h, "This host waits as long as its agent's own "
		    "<code>-w</code> says, 60 s unless set.");
	h_raw(h, "</p><form class=\"toolbar\" data-form=\"tr-safe\">"
	    "<label>Seconds <input name=\"wait\" type=\"number\" min=\"10\" "
	    "max=\"3600\" placeholder=\"the agent's own\"");
	if (s->safe_wait > 0)
		h_fmt(h, " value=\"%d\"", s->safe_wait);
	h_raw(h, "></label><button class=\"ghost small\">Save</button>"
	    "</form></section>");
}

/* The pane of the summary: listeners, the console's way in, sessions. */
void
view_transport(struct html *h, struct server *s)
{
	static const struct tcol	cols[] = {
		{ "Over", "transport", false }, { "From", "address", false },
		{ "Certificate", "subject", false },
		{ "Since", "since", true },
	};
	const ucl_object_t		**rows, *o, *d;
	ucl_object_iter_t		  it;
	const char			 *uri, *e;
	char				  buf[40];
	bool				  sctp, tcp, has_sctp, sctp_up;
	int				  r;
	int64_t				  t;

	/*
	 * A host reached over SCTP that does not answer: the way back to
	 * TCP is offered where its listeners would be, since they cannot
	 * be read.  The console asks over TCP first there too.
	 */
	if (tr.o == NULL || strcmp(tr.sid, s->id) != 0) {
		if (strncmp(s->uri, "sctp:", 5) != 0 || !s->failed)
			return;
		h_fmt(h, "<section class=\"transport\"><h3>How it is reached"
		    "</h3><p class=\"dim\">Over SCTP, and it does not answer. "
		    "If SCTP is blocked on the way, the host may still answer "
		    "over TCP.</p><div class=\"toolbar\"><button class=\""
		    "ghost small\" data-act=\"tr-switch\" data-arg=\"tcp\"%s>"
		    "Go back to TCP</button></div></section>", tr.busy ?
		    " disabled" : "");
		return;
	}
	d = jget(tr.o, "data");
	uri = jstr(tr.o, "uri") != NULL ? jstr(tr.o, "uri") : s->uri;
	sctp = strncmp(uri, "sctp:", 5) == 0;
	tcp = strncmp(uri, "tcp:", 4) == 0;
	has_sctp = sctp_up = false;
	h_raw(h, "<section class=\"transport\">");
	box_head(h, "transport", "h3");
	h_raw(h, "How it is reached</h3>");
	if (box_shut("transport")) {
		h_raw(h, "</section>");
		return;
	}
	h_raw(h, "<p class=\"dim\">The console's connection to the agent is kept "
	    "open and used again for the next request. ");
	h_raw(h, sctp ? "It is an SCTP association: every request is a "
	    "message of its own, and one that is lost does not hold up the "
	    "others." : tcp ? "It is a TCP connection." : "It is the "
	    "agent's local socket.");
	h_raw(h, "</p><ul class=\"listeners\">");
	it = NULL;
	while ((o = ucl_object_iterate(jget(d, "listeners"), &it, true)) !=
	    NULL) {
		bool	up = jbool(o, "up");

		bool	mine = jstr(o, "uri") != NULL && same_way(jstr(o,
		    "uri"), uri);

		if (jstr(o, "transport") != NULL && strcmp(jstr(o,
		    "transport"), "sctp") == 0) {
			has_sctp = true;
			sctp_up = sctp_up || up;
		}
		/*
		 * The agent's local socket is of use to who is on the
		 * host: shown only when it is how the console gets in.
		 */
		if (jstr(o, "transport") != NULL && strcmp(jstr(o,
		    "transport"), "unix") == 0 && !mine)
			continue;
		/*
		 * Green is what the console reaches, which it knows of
		 * its own way in alone; another the agent listens on is
		 * that, and no more, until it is tried.
		 */
		h_fmt(h, "<li class=\"%s\"", mine ? "up" : up ? "idle" :
		    "down");
		h_attr(h, "title", mine ? "The console reaches the agent "
		    "this way now" : up ? "The agent listens here; the console "
		    "has not tried it" : "The agent does not listen here");
		h_raw(h, "><span class=\"led\"></span><code>");
		h_txt(h, jstr(o, "uri"));
		h_raw(h, "</code>");
		if (mine)
			h_raw(h, "<span class=\"chip\">the console's way in"
			    "</span>");
		else if (up)
			h_raw(h, "<span class=\"dim\">listening, not tried "
			    "from here</span>");
		if (!up && (e = jstr(o, "error")) != NULL) {
			h_raw(h, "<span class=\"dim\">");
			h_txt(h, e);
			h_raw(h, "</span>");
		}
		h_raw(h, "</li>");
	}
	h_raw(h, "</ul><div class=\"toolbar\">");
	if (has_sctp && !sctp_up)
		h_fmt(h, "<button class=\"ghost small\" data-act=\"tr-retry\"%s "
		    "title=\"The agent does not try by itself again: once the "
		    "sctp module is loaded (the Kernel tab), have it try\">Try "
		    "SCTP again</button>", tr.busy ? " disabled" : "");
	if (tcp && sctp_up)
		h_fmt(h, "<button class=\"ghost small\" data-act=\"tr-switch\" "
		    "data-arg=\"sctp\"%s>Switch to SCTP</button>", tr.busy ?
		    " disabled" : "");
	if (sctp)
		h_fmt(h, "<button class=\"ghost small\" data-act=\"tr-switch\" "
		    "data-arg=\"tcp\"%s>Go back to TCP</button>", tr.busy ?
		    " disabled" : "");
	if (tcp && has_sctp && !jbool(d, "sctp"))
		h_raw(h, "<span class=\"dim\">The kernel has no SCTP: load "
		    "the <code>sctp</code> module from the Kernel tab.</span>");
	h_raw(h, "</div>");
	if (tr.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, tr.error);
		h_raw(h, "</div>");
	}
	h_fmt(h, "<h4 class=\"family\">Connected now <small class=\"dim\">%lld "
	    "since the agent started</small></h4><table class=\"net sessions\">",
	    (long long)jint(d, "seen", 0));
	tbl_head(h, "sessions", cols, 4, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("sessions", jget(d, "sessions"), cols, 4, NULL);
	for (r = 0; (o = rows[r]) != NULL; r++) {
		h_raw(h, "<tr><td><span class=\"chip\">");
		h_txt(h, jstr(o, "transport"));
		h_raw(h, "</span></td><td>");
		h_txt(h, jstr(o, "address") != NULL && jstr(o, "address")[0] !=
		    '\0' ? jstr(o, "address") : "this host");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(o, "subject"));
		h_raw(h, "</td><td class=\"dim\">");
		t = jint(d, "time", 0) - jint(o, "since", 0);
		if (t < 0)
			t = 0;
		snprintf(buf, sizeof(buf), t < 120 ? "%lld s" : t < 7200 ?
		    "%lld min" : "%lld h", (long long)(t < 120 ? t : t < 7200 ?
		    t / 60 : t / 3600));
		h_txt(h, buf);
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table></section>");
}

bool
sysctl_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 url[96], body[64], text[400];

	if (strncmp(act, "sy-", 3) != 0 && strncmp(act, "tr-", 3) != 0 &&
	    strcmp(act, "do-tr-switch") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "sy-tree") == 0) {
		snprintf(sy.prefix, sizeof(sy.prefix), "%s", arg);
		sy.edit[0] = '\0';
		refresh_sysctl(s, true);
	} else if (strcmp(act, "sy-edit") == 0) {
		if (arg[0] != '\0' && !name_ok(arg))
			return (true);
		snprintf(sy.edit, sizeof(sy.edit), "%s", arg);
		/* One kept that is not in the part shown: go to it. */
		if (arg[0] != '\0' && strncmp(arg, sy.prefix, strlen(
		    sy.prefix)) != 0) {
			snprintf(sy.prefix, sizeof(sy.prefix), "%s", arg);
			refresh_sysctl(s, true);
		}
	} else if (strcmp(act, "tr-retry") == 0) {
		tr.busy = true;
		tr.loading = false;
		refresh_transport(s, true, true);
	} else if (strcmp(act, "tr-switch") == 0 && (strcmp(arg, "sctp") ==
	    0 || strcmp(arg, "tcp") == 0)) {
		snprintf(text, sizeof(text), "The console asks %s over %s "
		    "first, at the same address and port. Only when the agent "
		    "answers there is the host reached that way from then on; "
		    "when it does not, nothing is changed.", s->name, arg[0] ==
		    's' ? "SCTP" : "TCP");
		confirm(arg[0] == 's' ? "Switch to SCTP" : "Switch to TCP",
		    text, "Test and switch", false, "", "do-tr-switch", arg, "");
	} else if (strcmp(act, "do-tr-switch") == 0 && (strcmp(arg, "sctp") ==
	    0 || strcmp(arg, "tcp") == 0)) {
		tr.busy = true;
		snprintf(url, sizeof(url), "/api/servers/%s/transport/switch",
		    s->id);
		snprintf(body, sizeof(body), "{\"transport\":\"%s\"}", arg);
		api("POST", url, body, switch_cb, strdup(arg[0] == 's' ?
		    "SCTP" : "TCP"));
	}
	(void)value;
	return (true);
}
