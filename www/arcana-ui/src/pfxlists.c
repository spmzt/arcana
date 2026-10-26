/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Prefix lists of the console's: named lists of IPv4 and IPv6
 * prefixes, kept once (GET /api/prefix-lists, PUT and DELETE
 * /api/prefix-lists/<name>) and used on any host: the Network
 * section's Prefix lists tab makes them, and the forms that take
 * prefixes (an ipfw table's entries, a BIRD set, an SD-WAN zone or
 * list) pick one by name and take its prefixes in.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	ucl_object_t	*all;		/* {name: {description, prefixes}} */
	bool		 loading, loaded;
	char		 edit[40];	/* the list open in the form; "" none */
	bool		 adding;
	char		 filter[64];
} px;

static void
px_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	px.loading = false;
	if (status != 200)
		return;
	if (px.all != NULL)
		ucl_object_unref(px.all);
	px.all = jget(o, "lists") != NULL ? ucl_object_copy(jget(o, "lists")) :
	    ucl_object_typed_new(UCL_OBJECT);
	px.loaded = true;
	render();
}

void
pfxlists_load(void)
{

	if (px.loading)
		return;
	px.loading = true;
	api("GET", "/api/prefix-lists", NULL, px_cb, NULL);
}

/* The list named, or NULL; read once when first wanted. */
const ucl_object_t *
pfxlist_get(const char *name)
{

	if (!px.loaded && !px.loading)
		pfxlists_load();
	return (px.all != NULL && name != NULL && name[0] != '\0' ?
	    ucl_object_lookup(px.all, name) : NULL);
}

/*
 * The prefixes of the lists named, one or several by commas (what a
 * select of several gives), joined by sep; NULL when none is a list; to
 * be freed.
 */
char *
pfxlist_joined(const char *names, const char *sep)
{
	const ucl_object_t	*l, *e;
	ucl_object_iter_t	 it;
	struct html		 b;
	char			 one[128];
	const char		*p, *q;
	size_t			 n;
	bool			 first, any;

	if (names == NULL)
		return (NULL);
	memset(&b, 0, sizeof(b));
	first = true;
	any = false;
	for (p = names; *p != '\0'; p = *q != '\0' ? q + 1 : q) {
		while (*p == ' ')
			p++;
		q = strchr(p, ',') != NULL ? strchr(p, ',') : p + strlen(p);
		n = (size_t)(q - p);
		while (n > 0 && p[n - 1] == ' ')
			n--;
		if (n == 0 || n >= sizeof(one))
			continue;
		snprintf(one, sizeof(one), "%.*s", (int)n, p);
		if ((l = pfxlist_get(one)) == NULL)
			continue;
		any = true;
		it = NULL;
		while ((e = ucl_object_iterate(jget(l, "prefixes"), &it,
		    true)) != NULL) {
			h_fmt(&b, "%s%s", first ? "" : sep,
			    ucl_object_tostring_forced(e));
			first = false;
		}
	}
	if (!any)
		return (NULL);
	return (b.s != NULL ? b.s : strdup(""));
}

/*
 * A select of the lists for a form, named field: "none" first, or, with
 * multi, several to pick (a form gives them by commas).  The form takes
 * their prefixes in with what else it says.
 */
void
pfxlist_select(struct html *h, const char *label, const char *field,
    const char *hint, bool multi)
{
	const ucl_object_t	*l;
	ucl_object_iter_t	 it;

	if (!px.loaded && !px.loading)
		pfxlists_load();
	h_raw(h, "<label class=\"pfx-pick\">");
	h_txt(h, label);
	h_raw(h, "<select");
	h_attr(h, "name", field);
	/* Several at once where the form takes them: no "none" then,
	 * none picked says it. */
	if (multi) {
		unsigned	n = 0;

		it = NULL;
		while (ucl_object_iterate(px.all, &it, true) != NULL)
			n++;
		h_fmt(h, " multiple size=\"%u\">", n < 2 ? 2 : n > 6 ? 6 : n);
	} else
		h_raw(h, "><option value=\"\">none</option>");
	it = NULL;
	while ((l = ucl_object_iterate(px.all, &it, true)) != NULL) {
		h_raw(h, "<option");
		h_attr(h, "value", ucl_object_key(l));
		h_raw(h, ">");
		h_txt(h, ucl_object_key(l));
		h_fmt(h, " (%u)</option>", ucl_array_size(jget(l, "prefixes")));
	}
	h_raw(h, "</select>");
	if (hint != NULL) {
		h_raw(h, "<small class=\"help\">");
		h_txt(h, hint);
		h_raw(h, "</small>");
	}
	h_raw(h, "</label>");
}

static void
saved_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200) {
		toast(true, "Not kept: %s", err != NULL ? err : jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") :
		    "no answer");
		render();
		return;
	}
	px.edit[0] = '\0';
	px.adding = false;
	px_cb(status, o, err, NULL);
}

static void
form(struct html *h, const ucl_object_t *l, const char *name)
{
	char	*text;

	text = l != NULL ? pfxlist_joined(name, "\n") : NULL;
	h_fmt(h, "<form data-form=\"px-list\" class=\"secform px-form\"><h4>%s"
	    "</h4><input type=\"hidden\" name=\"was\"", l != NULL ? "The list, "
	    "changed" : "A prefix list");
	h_attr(h, "value", name != NULL ? name : "");
	h_raw(h, "><label>Name<input name=\"name\" required pattern=\""
	    "[A-Za-z0-9_-]{1,32}\" spellcheck=\"false\" autocomplete=\"off\"");
	h_attr(h, "value", name != NULL ? name : "");
	h_raw(h, "></label><label>Description<input name=\"description\" "
	    "maxlength=\"200\"");
	h_attr(h, "value", jstr(l, "description") != NULL ? jstr(l,
	    "description") : "");
	h_raw(h, "></label><label class=\"wide\">Prefixes<textarea name=\""
	    "prefixes\" rows=\"8\" class=\"mono\" spellcheck=\"false\" "
	    "placeholder=\"10.1.8.0/22&#10;2001:db8:9::/48\">");
	h_txt(h, text != NULL ? text : "");
	h_raw(h, "</textarea><small class=\"help\">One a line, or with commas: "
	    "a.b.c.d/n or x::/n, with no host bits.</small></label><div class=\""
	    "actions\"><button class=\"primary\">Keep</button> <button type=\""
	    "button\" class=\"ghost\" data-act=\"px-cancel\">Cancel</button>"
	    "</div></form>");
	free(text);
}

void
view_pfxlists(struct html *h)
{
	static const struct tcol cols[] = {
		{ "Name", "name", false }, { "Description", "description", false },
		{ "Prefixes", "count", true }, { "Of", "sample", false },
	};
	const ucl_object_t	*l, *e, **rows, *r;
	ucl_object_iter_t	 it, eit;
	ucl_object_t		*arr, *o;
	char			 sample[200];
	size_t			 so;
	int			 k;

	if (!px.loaded && !px.loading)
		pfxlists_load();
	h_raw(h, "<p class=\"dim rt-note\">Lists of prefixes kept by the console "
	    "and used on any host: an ipfw table filled from one, a BIRD set "
	    "made of one, an SD-WAN zone's or list's prefixes. A change here "
	    "changes nothing on a host by itself: the forms take a list's "
	    "prefixes in when they are used.</p>");
	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\"filter\" "
	    "data-input=\"px-filter\" placeholder=\"Filter\" autocomplete=\"off\""
	    " spellcheck=\"false\"");
	h_attr(h, "value", px.filter);
	h_raw(h, "><button class=\"primary\" data-act=\"px-add\">+ prefix list"
	    "</button></div>");
	if (px.adding)
		form(h, NULL, NULL);
	else if (px.edit[0] != '\0')
		form(h, pfxlist_get(px.edit), px.edit);
	if (px.all == NULL) {
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((l = ucl_object_iterate(px.all, &it, true)) != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(ucl_object_key(l)),
		    "name", 0, true);
		ucl_object_insert_key(o, ucl_object_fromstring(jstr(l,
		    "description") != NULL ? jstr(l, "description") : ""),
		    "description", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(ucl_array_size(
		    jget(l, "prefixes"))), "count", 0, false);
		sample[0] = '\0';
		so = 0;
		k = 0;
		eit = NULL;
		while ((e = ucl_object_iterate(jget(l, "prefixes"), &eit, true))
		    != NULL && k < 4)
			so += (size_t)snprintf(sample + so, sizeof(sample) - so,
			    "%s%s", k++ > 0 ? ", " : "",
			    ucl_object_tostring_forced(e));
		if (ucl_array_size(jget(l, "prefixes")) > 4)
			snprintf(sample + so, sizeof(sample) - so, ", …");
		ucl_object_insert_key(o, ucl_object_fromstring(sample), "sample",
		    0, false);
		ucl_array_append(arr, o);
	}
	h_raw(h, "<table class=\"net pfxlists\">");
	tbl_head(h, "pfxlists", cols, 4, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("pfxlists", arr, cols, 4, px.filter);
	for (k = 0; (r = rows[k]) != NULL; k++) {
		h_raw(h, "<tr><td class=\"mono\"><b>");
		h_txt(h, jstr(r, "name"));
		h_raw(h, "</b></td><td>");
		h_txt(h, jstr(r, "description"));
		h_fmt(h, "</td><td>%lld</td><td class=\"mono dim\">", (long long)
		    jint(r, "count", 0));
		h_txt(h, jstr(r, "sample"));
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" data-act="
		    "\"px-edit\" title=\"Change it\"");
		h_attr(h, "data-arg", jstr(r, "name"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "px-del\" title=\"Take the list away\"");
		h_attr(h, "data-arg", jstr(r, "name"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (k == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"5\">No prefix "
		    "list yet.</td></tr>");
	free(rows);
	ucl_object_unref(arr);
	h_raw(h, "</tbody></table>");
}

bool
pfxlists_form(const char *form_name, const ucl_object_t *f)
{
	const char	*name, *was, *text, *desc;
	char		*json, *q, *qd, url[96], *copy, *it, *w;
	struct html	 b;
	bool		 first;

	if (strcmp(form_name, "px-list") != 0)
		return (false);
	name = jstr(f, "name") != NULL ? jstr(f, "name") : "";
	was = jstr(f, "was") != NULL ? jstr(f, "was") : "";
	text = jstr(f, "prefixes") != NULL ? jstr(f, "prefixes") : "";
	desc = jstr(f, "description") != NULL ? jstr(f, "description") : "";
	if (name[0] == '\0') {
		toast(true, "A list has a name");
		return (true);
	}
	memset(&b, 0, sizeof(b));
	h_raw(&b, "[");
	first = true;
	if ((copy = strdup(text)) == NULL)
		abort();
	for (it = copy; (w = strsep(&it, "\n, \t\r")) != NULL; ) {
		if (w[0] == '\0')
			continue;
		q = json_quote(w);
		h_fmt(&b, "%s%s", first ? "" : ",", q);
		free(q);
		first = false;
	}
	free(copy);
	h_raw(&b, "]");
	qd = json_quote(desc);
	if (asprintf(&json, "{\"description\":%s,\"prefixes\":%s}", qd, b.s !=
	    NULL ? b.s : "[]") == -1)
		abort();
	free(qd);
	free(b.s);
	snprintf(url, sizeof(url), "/api/prefix-lists/%s", name);
	api("PUT", url, json, saved_cb, NULL);
	free(json);
	/* Renamed: the old name goes. */
	if (was[0] != '\0' && strcmp(was, name) != 0) {
		snprintf(url, sizeof(url), "/api/prefix-lists/%s", was);
		api("DELETE", url, NULL, px_cb, NULL);
	}
	return (true);
}

bool
pfxlists_action(const char *act, const char *arg, const char *value)
{
	char	url[96], body[200];

	if (strcmp(act, "input:px-filter") == 0) {
		snprintf(px.filter, sizeof(px.filter), "%s", value != NULL ?
		    value : "");
		return (true);
	}
	if (strncmp(act, "px-", 3) != 0)
		return (false);
	if (strcmp(act, "px-add") == 0) {
		px.adding = true;
		px.edit[0] = '\0';
		return (true);
	}
	if (strcmp(act, "px-edit") == 0) {
		snprintf(px.edit, sizeof(px.edit), "%s", arg);
		px.adding = false;
		return (true);
	}
	if (strcmp(act, "px-cancel") == 0) {
		px.adding = false;
		px.edit[0] = '\0';
		return (true);
	}
	if (strcmp(act, "px-del") == 0) {
		snprintf(body, sizeof(body), "The list %s goes; what was made "
		    "from it on the hosts stays as it is.", arg);
		confirm("Take the list away", body, "Take away", true, "",
		    "px-del-do", arg, "");
		return (true);
	}
	if (strcmp(act, "px-del-do") == 0) {
		snprintf(url, sizeof(url), "/api/prefix-lists/%s", arg);
		api("DELETE", url, NULL, px_cb, NULL);
		return (true);
	}
	return (false);
}
