/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Threat feeds: the Network section's tab of the lists of scanners',
 * spammers' and abusers' prefixes the console fetches from the internet
 * and keeps on the hosts chosen as ipfw(8) tables (GET /api/feeds, PUT,
 * DELETE /api/feeds/<id>, POST .../fetch and .../preview).  The presets
 * with their sources and terms, each enabled by an operator; every feed
 * with its last fetch, its entries and what it dropped and why; a
 * feed's preview, each host's dry run.  No rule is made here: the
 * host's Firewall page offers one for each feed's table.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	FD_POLL_MS	2000		/* between reads while one is asked */
#define	FD_POLL_FOR	90000		/* ms an ask is waited for */

static struct {
	ucl_object_t	*all;		/* {presets, feeds, floor, max_entries} */
	bool		 loading;
	double		 fetched;
	char		 open[32];	/* the feed shown whole; "" none */
	ucl_object_t	*detail;
	bool		 dloading;
	char		 edit[32];	/* the feed or preset in the form */
	bool		 is_preset;	/* the form is a preset's, new */
	bool		 adding;	/* the form is a new list of one's own */
	double		 poll_until;
	char		 filter[64];
	char		 dfilter[64];
} fd;

static void
all_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	fd.loading = false;
	fd.fetched = arc_now();
	if (status != 200)
		return;
	if (fd.all != NULL)
		ucl_object_unref(fd.all);
	fd.all = ucl_object_copy(o);
	render();
}

static void
detail_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	fd.dloading = false;
	if (status != 200)
		return;
	if (fd.detail != NULL)
		ucl_object_unref(fd.detail);
	fd.detail = ucl_object_copy(o);
	render();
}

void
feeds_load(void)
{
	char	url[80];

	if (!fd.loading) {
		fd.loading = true;
		api("GET", "/api/feeds", NULL, all_cb, NULL);
	}
	if (fd.open[0] != '\0' && !fd.dloading) {
		fd.dloading = true;
		snprintf(url, sizeof(url), "/api/feeds/%s", fd.open);
		api("GET", url, NULL, detail_cb, NULL);
	}
}

/* While a fetch or a preview is asked: read again now and then. */
void
feeds_tick(double now)
{

	if (app.node != NODE_NETWORK || app.netsect != NETSECT_FEEDS ||
	    !app.visible || now > fd.poll_until || now - fd.fetched <
	    FD_POLL_MS)
		return;
	feeds_load();
}

static const ucl_object_t *
by_id(const ucl_object_t *arr, const char *id)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(arr, &it, true)) != NULL)
		if (jstr(o, "id") != NULL && strcmp(jstr(o, "id"), id) == 0)
			return (o);
	return (NULL);
}

static const char *
host_name(const char *sid)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sid) == 0)
			return (app.servers[i].name);
	return (sid);
}

static void
saved_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200 && status != 202) {
		toast(true, "Not done: %s", err != NULL ? err : jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") :
		    "no answer");
		render();
		return;
	}
	fd.edit[0] = '\0';
	fd.adding = fd.is_preset = false;
	fd.poll_until = arc_now() + FD_POLL_FOR;
	feeds_load();
	render();
}

/* The form: a preset's (new, its source given), a feed's, or a new one. */
static void
form(struct html *h, const ucl_object_t *f, const ucl_object_t *pr)
{
	static const char *const fmts[] = { "plain", "spamhaus-json",
	    "dshield" };
	const ucl_object_t	*src, *e;
	ucl_object_iter_t	 it;
	const char		*fmt;
	bool			 on;
	size_t			 i;
	int			 k;

	src = f != NULL ? f : pr;
	h_raw(h, "<form data-form=\"feed\" class=\"secform feed-form\"><h4>");
	h_txt(h, f != NULL ? "The feed, changed" : pr != NULL ? jstr(pr,
	    "name") : "A list of one's own");
	h_raw(h, "</h4>");
	if (pr != NULL && f == NULL) {
		h_raw(h, "<input type=\"hidden\" name=\"preset\"");
		h_attr(h, "value", jstr(pr, "id"));
		h_raw(h, "><p class=\"dim\">");
		h_txt(h, jstr(pr, "what"));
		h_raw(h, " <b>Terms:</b> ");
		h_txt(h, jstr(pr, "terms"));
		h_raw(h, " <a target=\"_blank\" rel=\"noopener\"");
		h_attr(h, "href", jstr(pr, "terms_url"));
		h_raw(h, ">Read them</a>.</p>");
	}
	h_raw(h, "<label>Id<input name=\"id\" required pattern=\"[a-z0-9]"
	    "[a-z0-9-]{0,23}\" spellcheck=\"false\" autocomplete=\"off\"");
	h_attr(h, "value", f != NULL ? jstr(f, "id") : pr != NULL ? jstr(pr,
	    "id") : "");
	if (f != NULL || pr != NULL)
		h_raw(h, " readonly");
	h_raw(h, "></label><label>Name<input name=\"name\" maxlength=\"80\"");
	h_attr(h, "value", src != NULL && jstr(src, "name") != NULL ? jstr(src,
	    "name") : "");
	h_raw(h, "></label><label class=\"wide\">Source<input name=\"url\" "
	    "required spellcheck=\"false\" placeholder=\"https://example.org/"
	    "list.txt\"");
	h_attr(h, "value", src != NULL && jstr(src, "url") != NULL ? jstr(src,
	    "url") : "");
	h_raw(h, "><small class=\"help\">Fetched by the console with libfetch, "
	    "TLS verified; the hosts need no way out.</small></label><label>"
	    "Format<select name=\"format\">");
	fmt = src != NULL && jstr(src, "format") != NULL ? jstr(src, "format") :
	    "plain";
	for (i = 0; i < nitems(fmts); i++)
		h_fmt(h, "<option%s>%s</option>", strcmp(fmt, fmts[i]) == 0 ?
		    " selected" : "", fmts[i]);
	h_fmt(h, "</select></label><label>Every<input name=\"interval\" "
	    "type=\"number\" min=\"%lld\" max=\"720\" value=\"%lld\"> hours"
	    "</label><label>ipfw table<input name=\"table\" spellcheck=\"false\""
	    " pattern=\"[A-Za-z0-9_.-]{1,48}\" placeholder=\"feed_&lt;id&gt;\"",
	    (long long)jint(fd.all, "floor", 1), (long long)(src != NULL ?
	    jint(src, "interval", 6) : 6));
	h_attr(h, "value", f != NULL && jstr(f, "table") != NULL ? jstr(f,
	    "table") : "");
	h_fmt(h, "></label><label class=\"toggle\" title=\"Private and reserved "
	    "space (RFC 1918, loopback, multicast...) is dropped unless the "
	    "list holds it on purpose\"><input type=\"checkbox\" name=\""
	    "bogons\"%s><span>it lists private space on purpose</span></label>"
	    "<label class=\"toggle\"><input type=\"checkbox\" name=\"enabled\""
	    "%s><span>enabled</span></label><fieldset class=\"wide\"><legend>"
	    "On the hosts</legend>", src != NULL && jbool(src, "bogons") ?
	    " checked" : "", f == NULL || jbool(f, "enabled") ? " checked" : "");
	for (k = 0; k < app.nservers; k++) {
		on = false;
		it = NULL;
		while (f != NULL && (e = ucl_object_iterate(jget(f, "hosts"),
		    &it, true)) != NULL)
			if (strcmp(ucl_object_tostring(e), app.servers[k].id) ==
			    0)
				on = true;
		h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" "
		    "name=\"host_%s\"%s><span>", app.servers[k].id, on ?
		    " checked" : "");
		h_txt(h, app.servers[k].name);
		h_raw(h, "</span></label>");
	}
	h_raw(h, "</fieldset><div class=\"actions\"><button class=\"primary\">"
	    "Keep</button> <button type=\"button\" class=\"ghost\" data-act=\""
	    "fd-cancel\">Cancel</button></div></form>");
}

static void
when(struct html *h, int64_t s)
{
	char	buf[48];

	if (s <= 0) {
		h_raw(h, "<span class=\"dim\">never</span>");
		return;
	}
	fmt_age(buf, sizeof(buf), (double)s * 1000);
	h_txt(h, buf);
}

/* A feed whole: its hosts, what it dropped and why, its updates. */
static void
detail(struct html *h, const ucl_object_t *f)
{
	static const struct tcol dcols[] = {
		{ "Entry", "entry", false }, { "Why it was dropped", "reason",
		    false },
	};
	static const struct tcol hcols[] = {
		{ "Host", "name", false }, { "Table", "table", false },
		{ "Entries", "count", true }, { "Added", "added", true },
		{ "Removed", "removed", true }, { "Set", "set", true },
		{ "Sent", "at", true }, { "Error", "error", false },
	};
	const ucl_object_t	*d, *o, **rows, *pv;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr, *row;
	char			 key[64];
	int			 r;

	d = fd.detail != NULL && jstr(fd.detail, "id") != NULL && strcmp(jstr(
	    fd.detail, "id"), jstr(f, "id")) == 0 ? fd.detail : NULL;
	h_raw(h, "<section class=\"pane feed-detail\"><h4>");
	h_txt(h, jstr(f, "name"));
	h_raw(h, " <button class=\"ghost small\" data-act=\"fd-fetch\"");
	h_attr(h, "data-arg", jstr(f, "id"));
	h_raw(h, " title=\"Fetch it now, if it changed since\">Fetch now</button>"
	    "<button class=\"ghost small\" data-act=\"fd-preview\"");
	h_attr(h, "data-arg", jstr(f, "id"));
	h_raw(h, " title=\"Fetch it whole and ask each host what would change; "
	    "nothing is changed\">Preview</button><button class=\"ghost small\" "
	    "data-act=\"fd-close\">Close</button></h4>");
	if (d == NULL) {
		h_raw(h, "<div class=\"loader\"></div></section>");
		return;
	}
	if (jget(d, "alarm") != NULL) {
		h_raw(h, "<div class=\"notice error\"><b>Alarm:</b> it failed "
		    "three times in a row, ");
		when(h, jint(d, "alarm.since", 0));
		h_raw(h, ": ");
		h_txt(h, jstr(d, "alarm.text"));
		h_raw(h, ". The hosts keep its last entries.</div>");
	}
	/* The preview, when one was asked. */
	if ((pv = jget(d, "preview")) != NULL) {
		h_raw(h, "<div class=\"notice info\"><b>Preview</b>, ");
		when(h, jint(pv, "at", 0));
		if (jstr(pv, "error") != NULL) {
			h_raw(h, ": ");
			h_txt(h, jstr(pv, "error"));
		} else {
			h_fmt(h, ": %lld entries, %lld dropped, %lld within "
			    "another.", (long long)jint(pv, "count", 0),
			    (long long)jint(pv, "dropped_count", 0), (long long)
			    jint(pv, "covered", 0));
			it = NULL;
			while ((o = ucl_object_iterate(jget(pv, "hosts"), &it,
			    true)) != NULL) {
				h_raw(h, "<br>");
				h_txt(h, host_name(ucl_object_key(o)));
				if (jstr(o, "error") != NULL) {
					h_raw(h, ": ");
					h_txt(h, jstr(o, "error"));
				} else
					h_fmt(h, ": %lld added, %lld removed, "
					    "%lld after, in set %lld",
					    (long long)jint(o, "added", 0),
					    (long long)jint(o, "removed", 0),
					    (long long)jint(o, "count", 0),
					    (long long)jint(o, "set", 0));
			}
		}
		h_raw(h, "</div>");
	}
	/* Its hosts, as each has it. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((o = ucl_object_iterate(jget(d, "delivered"), &it, true)) !=
	    NULL) {
		row = ucl_object_copy(o);
		ucl_object_replace_key(row, ucl_object_fromstring(host_name(
		    ucl_object_key(o))), "name", 0, false);
		ucl_array_append(arr, row);
	}
	snprintf(key, sizeof(key), "fdh-%.40s", jstr(f, "id"));
	h_raw(h, "<h5>On the hosts</h5><table class=\"net\">");
	tbl_head(h, key, hcols, 8, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows(key, arr, hcols, 8, "");
	for (r = 0; (o = rows[r]) != NULL; r++) {
		h_raw(h, "<tr><td>");
		h_txt(h, jstr(o, "name"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(o, "table"));
		h_fmt(h, "</td><td>%lld</td><td>%lld</td><td>%lld</td><td>%lld"
		    "</td><td>", (long long)jint(o, "count", 0), (long long)jint(
		    o, "added", 0), (long long)jint(o, "removed", 0), (long long)
		    jint(o, "set", 0));
		when(h, jint(o, "at", 0));
		h_raw(h, "</td><td class=\"error\">");
		h_txt(h, jstr(o, "error") != NULL ? jstr(o, "error") : "");
		h_raw(h, "</td></tr>");
	}
	if (r == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"8\">Not sent to "
		    "any host yet.</td></tr>");
	free(rows);
	ucl_object_unref(arr);
	h_raw(h, "</tbody></table>");
	/* What it dropped, and why. */
	h_fmt(h, "<h5>Dropped <small class=\"dim\">%lld, the first %u "
	    "shown; %lld more within another entry, left out</small></h5>",
	    (long long)jint(d, "dropped_count", 0), ucl_array_size(jget(d,
	    "dropped")), (long long)jint(d, "covered", 0));
	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" data-input=\""
	    "fd-dfilter\" placeholder=\"Filter\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", fd.dfilter);
	h_raw(h, "></div><table class=\"net feed-dropped\">");
	snprintf(key, sizeof(key), "fdd-%.40s", jstr(f, "id"));
	tbl_head(h, key, dcols, 2, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows(key, jget(d, "dropped"), dcols, 2, fd.dfilter);
	for (r = 0; (o = rows[r]) != NULL; r++) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(o, "entry"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(o, "reason"));
		/* Which and whose, to whom may see it. */
		if (jstr(o, "detail") != NULL) {
			h_raw(h, "<small class=\"dim\"> ");
			h_txt(h, jstr(o, "detail"));
			h_raw(h, "</small>");
		}
		h_raw(h, "</td></tr>");
	}
	if (r == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"2\">Nothing "
		    "dropped.</td></tr>");
	free(rows);
	h_raw(h, "</tbody></table>");
	/* Its updates: each fetch whose entries changed. */
	h_raw(h, "<h5>Updates</h5><ul class=\"feed-events\">");
	r = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(d, "events"), &it, true)) != NULL) {
		h_raw(h, "<li>");
		when(h, jint(o, "at", 0));
		h_fmt(h, ": %lld entries, %lld before</li>", (long long)jint(o,
		    "count", 0), (long long)jint(o, "was", 0));
		r++;
	}
	if (r == 0)
		h_raw(h, "<li class=\"dim\">None yet.</li>");
	h_raw(h, "</ul><h5>The first entries</h5><p class=\"mono dim\">");
	r = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(d, "sample"), &it, true)) != NULL &&
	    r < 40) {
		h_fmt(h, "%s", r++ > 0 ? " " : "");
		h_txt(h, ucl_object_tostring(o));
	}
	h_raw(h, "</p></section>");
}

void
view_feeds(struct html *h)
{
	static const struct tcol cols[] = {
		{ "Feed", "name", false }, { "Table", "table", false },
		{ "Hosts", "nhosts", true }, { "Every", "interval", true },
		{ "Fetched", "fetched_at", true }, { "Entries", "count", true },
		{ "Dropped", "dropped_count", true }, { "State", "status",
		    false },
	};
	static const struct tcol pcols[] = {
		{ "Preset", "name", false }, { "What it lists", "what", false },
		{ "Terms", "terms", false },
	};
	const ucl_object_t	*f, *pr, **rows;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr, *row;
	const char		*status;
	int			 r;

	if (fd.all == NULL && !fd.loading)
		feeds_load();
	h_raw(h, "<p class=\"dim rt-note\">Lists of scanners', spammers' and "
	    "abusers' addresses, fetched from the internet by the console, "
	    "once for the fleet, and kept on the hosts chosen as <b>ipfw(8) "
	    "tables</b> of type addr, IPv4 and IPv6 in one: the agent fills "
	    "a scratch table and swaps it in (<code>ipfw table T swap S</code>"
	    "), so a lookup sees the old list or the new one. What would cut "
	    "off the console, a host or a user's last sign-in is dropped, and "
	    "said. No rule is added: a host's Firewall page offers <code>deny "
	    "ip from table(T) to any in</code> for each feed's table, kept or "
	    "not as any rule.</p>");
	if (fd.all == NULL) {
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	if (fd.edit[0] != '\0')
		form(h, fd.is_preset ? NULL : by_id(jget(fd.all, "feeds"),
		    fd.edit), fd.is_preset ? by_id(jget(fd.all, "presets"),
		    fd.edit) : NULL);
	else if (fd.adding)
		form(h, NULL, NULL);
	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" data-input=\""
	    "fd-filter\" placeholder=\"Filter\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", fd.filter);
	h_raw(h, "><button class=\"primary\" data-act=\"fd-add\">+ a list of "
	    "one's own</button></div>");
	/* The feeds. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((f = ucl_object_iterate(jget(fd.all, "feeds"), &it, true)) !=
	    NULL) {
		row = ucl_object_copy(f);
		ucl_object_replace_key(row, ucl_object_fromint((int64_t)
		    ucl_array_size(jget(f, "hosts"))), "nhosts", 0, false);
		status = jget(f, "alarm") != NULL ? "alarm" : jstr(f, "error") !=
		    NULL ? "failing" : !jbool(f, "enabled") ? "off" :
		    jint(f, "fetched_at", 0) == 0 ? "to fetch" : "ok";
		ucl_object_replace_key(row, ucl_object_fromstring(status),
		    "status", 0, false);
		ucl_array_append(arr, row);
	}
	h_raw(h, "<table class=\"net feeds\">");
	tbl_head(h, "feeds", cols, 8, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("feeds", arr, cols, 8, fd.filter);
	for (r = 0; (f = rows[r]) != NULL; r++) {
		status = jstr(f, "status");
		h_raw(h, "<tr class=\"pick\" data-act=\"fd-open\"");
		h_attr(h, "data-arg", jstr(f, "id"));
		h_raw(h, "><td><b>");
		h_txt(h, jstr(f, "name"));
		h_raw(h, "</b><small class=\"dim mono\"> ");
		h_txt(h, jstr(f, "url"));
		h_raw(h, "</small></td><td class=\"mono\">");
		h_txt(h, jstr(f, "table"));
		h_fmt(h, "</td><td>%lld</td><td>%lld h</td><td>", (long long)jint(
		    f, "nhosts", 0), (long long)jint(f, "interval", 0));
		when(h, jint(f, "fetched_at", 0));
		h_fmt(h, "</td><td>%lld</td><td>%lld</td><td><span class=\"chip"
		    "%s\"", (long long)jint(f, "count", 0), (long long)jint(f,
		    "dropped_count", 0), strcmp(status, "ok") == 0 ? "" :
		    strcmp(status, "off") == 0 || strcmp(status, "to fetch") ==
		    0 ? " dim" : " danger");
		h_attr(h, "title", jstr(f, "error") != NULL ? jstr(f, "error") :
		    "");
		h_raw(h, ">");
		h_txt(h, status);
		h_raw(h, "</span></td><td class=\"acts\"><button class=\"icon\" "
		    "data-act=\"fd-edit\" title=\"Change it\"");
		h_attr(h, "data-arg", jstr(f, "id"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "fd-del\" title=\"Take the feed away, and its tables\"");
		h_attr(h, "data-arg", jstr(f, "id"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (r == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"9\">No feed yet: "
		    "enable a preset below, or add a list of your own.</td></tr>");
	free(rows);
	ucl_object_unref(arr);
	h_raw(h, "</tbody></table>");
	if (fd.open[0] != '\0' && (f = by_id(jget(fd.all, "feeds"), fd.open)) !=
	    NULL)
		detail(h, f);
	/* The presets, each with its source and terms. */
	h_raw(h, "<h4 class=\"family\">Presets</h4><table class=\"net "
	    "feed-presets\">");
	tbl_head(h, "feed-presets", pcols, 3, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("feed-presets", jget(fd.all, "presets"), pcols, 3,
	    fd.filter);
	for (r = 0; (pr = rows[r]) != NULL; r++) {
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(pr, "name"));
		h_raw(h, "</b><small class=\"dim mono\"> ");
		h_txt(h, jstr(pr, "url"));
		h_fmt(h, "</small><small class=\"dim\"> %s, every %lld h</small>"
		    "</td><td>", jstr(pr, "format"), (long long)jint(pr,
		    "interval", 0));
		h_txt(h, jstr(pr, "what"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(pr, "terms"));
		h_raw(h, " <a target=\"_blank\" rel=\"noopener\"");
		h_attr(h, "href", jstr(pr, "terms_url"));
		h_raw(h, ">terms</a></td><td class=\"acts\">");
		if (by_id(jget(fd.all, "feeds"), jstr(pr, "id")) != NULL)
			h_raw(h, "<span class=\"chip dim\">in use</span>");
		else {
			h_raw(h, "<button class=\"small\" data-act=\"fd-preset\"");
			h_attr(h, "data-arg", jstr(pr, "id"));
			h_raw(h, ">Use</button>");
		}
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
}

bool
feeds_form(const char *form_name, const ucl_object_t *f)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct html		 b;
	char			*q, url[80];
	const char		*id;
	bool			 first;

	if (strcmp(form_name, "feed") != 0)
		return (false);
	id = jstr(f, "id") != NULL ? jstr(f, "id") : "";
	if (id[0] == '\0') {
		toast(true, "A feed has an id");
		return (true);
	}
	memset(&b, 0, sizeof(b));
	h_raw(&b, "{");
	if (jstr(f, "preset") != NULL) {
		q = json_quote(jstr(f, "preset"));
		h_fmt(&b, "\"preset\":%s,", q);
		free(q);
	}
	q = json_quote(jstr(f, "name") != NULL ? jstr(f, "name") : id);
	h_fmt(&b, "\"name\":%s,", q);
	free(q);
	q = json_quote(jstr(f, "url") != NULL ? jstr(f, "url") : "");
	h_fmt(&b, "\"url\":%s,", q);
	free(q);
	q = json_quote(jstr(f, "format") != NULL ? jstr(f, "format") : "plain");
	h_fmt(&b, "\"format\":%s,", q);
	free(q);
	q = json_quote(jstr(f, "table") != NULL ? jstr(f, "table") : "");
	h_fmt(&b, "\"table\":%s,\"interval\":%d,\"bogons\":%s,\"enabled\":%s,"
	    "\"hosts\":[", q, jstr(f, "interval") != NULL ? atoi(jstr(f,
	    "interval")) : 6, jbool(f, "bogons") ? "true" : "false", jbool(f,
	    "enabled") ? "true" : "false");
	free(q);
	first = true;
	it = NULL;
	while ((e = ucl_object_iterate(f, &it, true)) != NULL) {
		if (strncmp(ucl_object_key(e), "host_", 5) != 0 || !jbool(f,
		    ucl_object_key(e)))
			continue;
		q = json_quote(ucl_object_key(e) + 5);
		h_fmt(&b, "%s%s", first ? "" : ",", q);
		free(q);
		first = false;
	}
	h_raw(&b, "]}");
	snprintf(url, sizeof(url), "/api/feeds/%s", id);
	api("PUT", url, b.s, saved_cb, NULL);
	free(b.s);
	return (true);
}

bool
feeds_action(const char *act, const char *arg, const char *value)
{
	char	url[96], body[300];

	if (strcmp(act, "input:fd-filter") == 0) {
		snprintf(fd.filter, sizeof(fd.filter), "%s", value != NULL ?
		    value : "");
		return (true);
	}
	if (strcmp(act, "input:fd-dfilter") == 0) {
		snprintf(fd.dfilter, sizeof(fd.dfilter), "%s", value != NULL ?
		    value : "");
		return (true);
	}
	if (strncmp(act, "fd-", 3) != 0)
		return (false);
	if (strcmp(act, "fd-add") == 0) {
		fd.adding = true;
		fd.edit[0] = '\0';
		fd.is_preset = false;
	} else if (strcmp(act, "fd-preset") == 0 || strcmp(act, "fd-edit") ==
	    0) {
		snprintf(fd.edit, sizeof(fd.edit), "%s", arg);
		fd.is_preset = strcmp(act, "fd-preset") == 0;
		fd.adding = false;
	} else if (strcmp(act, "fd-cancel") == 0) {
		fd.adding = fd.is_preset = false;
		fd.edit[0] = '\0';
	} else if (strcmp(act, "fd-open") == 0) {
		snprintf(fd.open, sizeof(fd.open), "%s", strcmp(fd.open, arg) ==
		    0 ? "" : arg);
		feeds_load();
	} else if (strcmp(act, "fd-close") == 0)
		fd.open[0] = '\0';
	else if (strcmp(act, "fd-fetch") == 0 || strcmp(act, "fd-preview") ==
	    0) {
		snprintf(url, sizeof(url), "/api/feeds/%s/%s", arg, strcmp(act,
		    "fd-fetch") == 0 ? "fetch" : "preview");
		api("POST", url, NULL, saved_cb, NULL);
	} else if (strcmp(act, "fd-del") == 0) {
		snprintf(body, sizeof(body), "The feed %s goes, and the hosts "
		    "give up its tables; a rule that names one matches nothing "
		    "after, and stays.", arg);
		confirm("Take the feed away", body, "Take away", true, "",
		    "fd-del-do", arg, "");
	} else if (strcmp(act, "fd-del-do") == 0) {
		snprintf(url, sizeof(url), "/api/feeds/%s", arg);
		if (strcmp(fd.open, arg) == 0)
			fd.open[0] = '\0';
		api("DELETE", url, NULL, saved_cb, NULL);
	} else
		return (false);
	return (true);
}
