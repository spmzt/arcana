/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Configuration templates, the Devices page's second tab: a host's
 * setup kept by the console under a name (its bundle without secrets,
 * {{name}} where each host has a value of its own), opened and changed
 * here, saved as YAML or JSON and taken in again, and applied to a
 * host with its values: checked first (what each file would become),
 * then written, as a host's bundle is.  A host's Summary saves one
 * (hostconf.c, Save as a template).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	ucl_object_t	*list;		/* GET /api/templates's */
	bool		 loading;
	char		 filter[64];
	char		 open[65];	/* the one opened, or "" */
	ucl_object_t	*doc;		/* it, as it is changed here */
	bool		 dirty;
	bool		 busy;
	char		 error[400];
	/* Applied: to which host, with which values; its report. */
	char		 target[9];
	ucl_object_t	*values;
	ucl_object_t	*report;
	char		 rsid[9];
	bool		 rdry;
	bool		 anyway;
} tp;

static const char *
why(int status, const ucl_object_t *o, const char *err)
{

	return (jstr(o, "error.message") != NULL ? jstr(o, "error.message") :
	    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ? err :
	    status == 0 ? "no answer" : "it failed");
}

/* ---- arcana-console's templates as the page's documents ------------ */

static const char *const fkeys[] = { "path", "mode", "owner", "group",
    "text", NULL };
static const char *const pkeys[] = { "name", "origin", "version", NULL };
static const char *const vkeys[] = { "description", "default", NULL };

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

/* Each element of list, those of keys it has as text, into an array. */
static ucl_object_t *
each(const ucl_object_t *list, const char *const *keys)
{
	ucl_object_t		*a, *x;
	const ucl_object_t	*f;
	const char *const	*k;
	ucl_object_iter_t	 it = NULL;

	a = ucl_object_typed_new(UCL_ARRAY);
	while ((f = ucl_object_iterate(list, &it, true)) != NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		for (k = keys; *k != NULL; k++)
			if (jstr(f, *k) != NULL)
				put(x, *k, ucl_object_fromstring(jstr(f, *k)));
		ucl_array_append(a, x);
	}
	return (a);
}

/* A template's entry as /api had it: {name, description, from, files,
 * packages, facts, variables: {name: {...}}, placeholders, updated}. */
static ucl_object_t *
tpl_doc(const ucl_object_t *y)
{
	ucl_object_t		*d, *v, *x;
	const ucl_object_t	*f;
	ucl_object_iter_t	 it = NULL;
	const char *const	*k;
	char			 err[80];

	d = ucl_object_typed_new(UCL_OBJECT);
	put(d, "name", ucl_object_fromstring(jstr(y, "name")));
	if (jstr(y, "description") != NULL)
		put(d, "description", ucl_object_fromstring(jstr(y,
		    "description")));
	if (jstr(y, "from") != NULL)
		put(d, "from", ucl_object_fromstring(jstr(y, "from")));
	put(d, "files", each(jget(y, "file"), fkeys));
	put(d, "packages", each(jget(y, "package"), pkeys));
	if (jstr(y, "facts") != NULL && (x = data_parse(jstr(y, "facts"), err,
	    sizeof(err))) != NULL)
		put(d, "facts", x);
	if (jget(y, "variable") != NULL) {
		v = ucl_object_typed_new(UCL_OBJECT);
		while ((f = ucl_object_iterate(jget(y, "variable"), &it,
		    true)) != NULL) {
			if (jstr(f, "name") == NULL)
				continue;
			x = ucl_object_typed_new(UCL_OBJECT);
			for (k = vkeys; *k != NULL; k++)
				if (jstr(f, *k) != NULL)
					put(x, *k, ucl_object_fromstring(
					    jstr(f, *k)));
			put(v, jstr(f, "name"), x);
		}
		put(d, "variables", v);
	}
	put(d, "placeholders", jget(y, "placeholder") != NULL ?
	    ucl_object_copy(jget(y, "placeholder")) : ucl_object_typed_new(
	    UCL_ARRAY));
	if (jstr(y, "updated") != NULL)
		put(d, "updated", ucl_object_fromint(rc_time(jstr(y,
		    "updated"))));
	return (d);
}

/* The page's document of template name as its entry, to be put. */
static ucl_object_t *
tpl_entry(const char *name, const ucl_object_t *d)
{
	ucl_object_t		*e, *a, *x;
	const ucl_object_t	*f;
	ucl_object_iter_t	 it = NULL;
	const char *const	*k;
	unsigned char		*json;

	e = ucl_object_typed_new(UCL_OBJECT);
	put(e, "name", ucl_object_fromstring(name));
	if (jstr(d, "description") != NULL && jstr(d, "description")[0] !=
	    '\0')
		put(e, "description", ucl_object_fromstring(jstr(d,
		    "description")));
	if (jstr(d, "from") != NULL)
		put(e, "from", ucl_object_fromstring(jstr(d, "from")));
	put(e, "file", each(jget(d, "files"), fkeys));
	put(e, "package", each(jget(d, "packages"), pkeys));
	if (jget(d, "facts") != NULL && (json = ucl_object_emit(jget(d,
	    "facts"), UCL_EMIT_JSON_COMPACT)) != NULL) {
		put(e, "facts", ucl_object_fromstring((char *)json));
		free(json);
	}
	a = ucl_object_typed_new(UCL_ARRAY);
	while ((f = ucl_object_iterate(jget(d, "variables"), &it, true)) !=
	    NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		put(x, "name", ucl_object_fromstring(ucl_object_key(f)));
		for (k = vkeys; *k != NULL; k++)
			if (jstr(f, *k) != NULL)
				put(x, *k, ucl_object_fromstring(jstr(f, *k)));
		ucl_array_append(a, x);
	}
	put(e, "variable", a);
	return (e);
}

static struct server *
host_of(const char *sid)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sid) == 0)
			return (&app.servers[i]);
	return (NULL);
}

static void
list_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*d;

	(void)arg;
	tp.loading = false;
	if (status != 200) {
		snprintf(tp.error, sizeof(tp.error), "The templates were not "
		    "read: %s", why(status, o, err));
		return;
	}
	if (tp.list != NULL)
		ucl_object_unref(tp.list);
	/* Each one's row: its files and packages counted. */
	tp.list = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(jget(o, "template"), &it, true)) !=
	    NULL) {
		d = tpl_doc(e);
		put(d, "files", ucl_object_fromint((int64_t)ucl_array_size(
		    jget(e, "file"))));
		put(d, "packages", ucl_object_fromint((int64_t)ucl_array_size(
		    jget(e, "package"))));
		ucl_object_delete_key(d, "facts");
		ucl_object_delete_key(d, "variables");
		if (jget(d, "description") == NULL)
			put(d, "description", ucl_object_fromstring(""));
		ucl_array_append(tp.list, d);
	}
}

void
templates_load(void)
{

	tp.loading = true;
	rc_get(RC_C "templates", NULL, list_cb, NULL);
}

static void
open_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	tp.busy = false;
	if (status != 200 || o == NULL) {
		snprintf(tp.error, sizeof(tp.error), "%s", why(status, o, err));
		tp.open[0] = '\0';
		return;
	}
	if (tp.doc != NULL)
		ucl_object_unref(tp.doc);
	tp.doc = tpl_doc(o);
	tp.dirty = false;
	tp.error[0] = '\0';
}

static void
open_one(const char *name)
{
	char	url[300];

	snprintf(tp.open, sizeof(tp.open), "%s", name);
	if (tp.report != NULL)
		ucl_object_unref(tp.report);
	tp.report = NULL;
	if (tp.values != NULL)
		ucl_object_unref(tp.values);
	tp.values = ucl_object_typed_new(UCL_OBJECT);
	tp.busy = true;
	rc_get(rc_c(url, sizeof(url), "templates/template=%s", rc_key(name)),
	    NULL, open_cb, NULL);
}

/* Opened by name, from elsewhere (a host's Save as a template). */
void
templates_open(const char *name)
{

	app.node = NODE_DEVICES;
	app.devtab = 1;
	templates_load();
	open_one(name);
}

static void
saved_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*name = arg;

	tp.busy = false;
	if (status < 200 || status > 299)
		snprintf(tp.error, sizeof(tp.error), "%s was not kept: %s", name,
		    why(status, o, err));
	else {
		tp.error[0] = '\0';
		toast(false, "Template %s kept", name);
		templates_load();
		open_one(name);
	}
	free(name);
}

/* name kept as doc says (what the server adds left out). */
void
template_put(const char *name, const ucl_object_t *doc)
{
	ucl_object_t	*b, *a;
	char		 url[300], *json;

	a = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(a, tpl_entry(name, doc));
	b = ucl_object_typed_new(UCL_OBJECT);
	put(b, "arcana-console:template", a);
	json = (char *)ucl_object_emit(b, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(b);
	rc_c(url, sizeof(url), "templates/template=%s", rc_key(name));
	tp.busy = true;
	rc_edit("PUT", url, json, saved_cb, strdup(name));
	free(json);
}

static void
deleted_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	tp.busy = false;
	if (status < 200 || status > 299) {
		snprintf(tp.error, sizeof(tp.error), "%s", why(status, o, err));
		return;
	}
	tp.open[0] = '\0';
	if (tp.doc != NULL)
		ucl_object_unref(tp.doc);
	tp.doc = NULL;
	templates_load();
}

static void
apply_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	tp.busy = false;
	if (tp.report != NULL)
		ucl_object_unref(tp.report);
	tp.report = jget(o, "data") != NULL ? ucl_object_copy(jget(o,
	    "data")) : NULL;
	if (status != 200 || !jbool(o, "ok"))
		snprintf(tp.error, sizeof(tp.error), "%s", why(status, o, err));
	else
		tp.error[0] = '\0';
}

/* Check (dry) or Apply the opened template to the host picked. */
static void
send(bool dry)
{
	ucl_object_t	*b;
	char		 url[200], *json;

	if (tp.open[0] == '\0' || tp.target[0] == '\0')
		return;
	b = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(b, ucl_object_fromstring(tp.open), "template",
	    0, true);
	ucl_object_insert_key(b, ucl_object_ref(tp.values), "values", 0,
	    true);
	ucl_object_insert_key(b, ucl_object_frombool(dry), "dry-run", 0, true);
	ucl_object_insert_key(b, ucl_object_frombool(tp.anyway), "anyway", 0,
	    true);
	json = (char *)ucl_object_emit(b, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(b);
	rc_c(url, sizeof(url), "hosts/host=%s/apply-configuration",
	    rc_key(tp.target));
	snprintf(tp.rsid, sizeof(tp.rsid), "%s", tp.target);
	tp.rdry = dry;
	tp.busy = true;
	tp.error[0] = '\0';
	rc_verb(url, json, NULL, apply_cb, NULL);
	free(json);
}

/* The opened one's variable name's, made when it is not there yet. */
static ucl_object_t *
var_of(const char *name)
{
	ucl_object_t	*vars, *v;

	if ((vars = (ucl_object_t *)(uintptr_t)jget(tp.doc, "variables")) ==
	    NULL) {
		vars = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(tp.doc, vars, "variables", 0, true);
	}
	if ((v = (ucl_object_t *)(uintptr_t)ucl_object_lookup(vars, name)) ==
	    NULL) {
		v = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(vars, v, name, 0, true);
	}
	return (v);
}

static void
set_str(ucl_object_t *o, const char *key, const char *value)
{

	ucl_object_replace_key(o, ucl_object_fromstring(value), key, 0, true);
}

/* The list: each template, sorted and filtered. */
static void
view_list(struct html *h)
{
	static const struct tcol	cols[] = {
		{ "Template", "name", false }, { "Description", "description",
		false }, { "Files", "files", true }, { "Packages", "packages",
		true }, { "Values", "values", false }, { "Made from", "from",
		false }, { "Changed", "updated", true },
	};
	const ucl_object_t	**rows, *r, *p;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr, *o;
	char			 age[32], vals[300];
	int			 k;

	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" data-input="
	    "\"tp-filter\" placeholder=\"Filter templates\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", tp.filter);
	h_raw(h, "><label class=\"button ghost small\" title=\"A template "
	    "saved before, YAML or JSON\">From a file<input type=\"file\" "
	    "accept=\"application/json,.json,application/yaml,.yaml,.yml\" "
	    "data-file=\"tp-upload\" hidden></label></div>");
	if (tp.list == NULL) {
		h_raw(h, tp.loading ? "<div class=\"loader\"></div>" : "");
		return;
	}
	if (ucl_array_size(tp.list) == 0) {
		h_raw(h, "<div class=\"empty\"><h2>No template yet</h2><p>A "
		    "host's setup kept by name, for other hosts to be made the "
		    "same: on a host's Summary, <b>Configuration, as a whole</b>, "
		    "Save as a template. Its hostname becomes <code>{{hostname}}"
		    "</code>, which each host it is applied to gives its own."
		    "</p></div>");
		return;
	}
	/* Each row's placeholders as one cell, for the filter too. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((r = ucl_object_iterate(tp.list, &it, true)) != NULL) {
		ucl_object_iter_t	pit = NULL;

		o = ucl_object_copy(r);
		vals[0] = '\0';
		while ((p = ucl_object_iterate(jget(r, "placeholders"), &pit,
		    true)) != NULL)
			snprintf(vals + strlen(vals), sizeof(vals) - strlen(vals),
			    "%s%s", vals[0] != '\0' ? ", " : "",
			    ucl_object_tostring_forced(p));
		ucl_object_insert_key(o, ucl_object_fromstring(vals), "values",
		    0, true);
		ucl_array_append(arr, o);
	}
	h_raw(h, "<table class=\"net templates\">");
	tbl_head(h, "templates", cols, 7, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("templates", arr, cols, 7, tp.filter);
	for (k = 0; (r = rows[k]) != NULL; k++) {
		h_raw(h, "<tr class=\"pick\" data-act=\"tp-open\"");
		h_attr(h, "data-arg", jstr(r, "name"));
		h_raw(h, "><td><b>");
		h_txt(h, jstr(r, "name"));
		h_raw(h, "</b></td><td>");
		h_txt(h, jstr(r, "description"));
		h_fmt(h, "</td><td>%lld</td><td>%lld</td><td class=\"mono\">",
		    (long long)jint(r, "files", 0), (long long)jint(r,
		    "packages", 0));
		h_txt(h, jstr(r, "values"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "from") != NULL ? jstr(r, "from") : "—");
		fmt_age(age, sizeof(age), jint(r, "updated", 0) * 1000.0);
		h_raw(h, "</td><td>");
		h_txt(h, age);
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	ucl_object_unref(arr);
}

/* One opened: its text and its values changed, saved, applied. */
static void
view_one(struct html *h)
{
	const ucl_object_t	*f, *p, *v;
	ucl_object_iter_t	 it;
	int			 i, k;

	h_raw(h, "<section class=\"transport template\"><div class=\"toolbar\">"
	    "<button class=\"ghost small\" data-act=\"tp-close\">&larr; the "
	    "templates</button><h3>");
	h_txt(h, tp.open);
	h_fmt(h, "</h3><button class=\"small primary\" data-act=\"tp-save\""
	    "%s>Save</button><button class=\"ghost small\" data-act=\""
	    "tp-download\" data-arg=\"yaml\">YAML</button><button class=\""
	    "ghost small\" data-act=\"tp-download\" data-arg=\"json\">JSON"
	    "</button><button class=\"ghost small danger\" data-act=\""
	    "tp-delete\">Delete</button></div>", !tp.dirty || tp.busy ?
	    " disabled" : "");
	if (tp.doc == NULL) {
		h_raw(h, "<div class=\"loader\"></div></section>");
		return;
	}
	h_raw(h, "<label>Description<input data-input=\"tp-desc\" maxlength="
	    "\"512\"");
	h_attr(h, "value", jstr(tp.doc, "description") != NULL ? jstr(tp.doc,
	    "description") : "");
	h_raw(h, "></label>");
	/* Its values: each placeholder its description and default. */
	h_raw(h, "<h4>Values each host gives</h4>");
	if (ucl_array_size(jget(tp.doc, "placeholders")) == 0)
		h_raw(h, "<p class=\"dim\">None: every host it is applied to "
		    "gets the same files. Write <code>{{name}}</code> in a "
		    "file where each host has its own.</p>");
	else {
		h_raw(h, "<table class=\"net tpvars\"><thead><tr><th>Value</th>"
		    "<th>What it is</th><th>Unless a host says</th></tr></thead>"
		    "<tbody>");
		it = NULL;
		while ((p = ucl_object_iterate(jget(tp.doc, "placeholders"), &it,
		    true)) != NULL) {
			const char	*n = ucl_object_tostring_forced(p);

			v = jget(jget(tp.doc, "variables"), n);
			h_raw(h, "<tr><td><code>{{");
			h_txt(h, n);
			h_raw(h, "}}</code></td><td><input data-input=\"tp-vdesc\"");
			h_attr(h, "data-arg", n);
			h_attr(h, "value", jstr(v, "description") != NULL ?
			    jstr(v, "description") : "");
			h_raw(h, "></td><td><input data-input=\"tp-vdef\" "
			    "placeholder=\"none: each host says\"");
			h_attr(h, "data-arg", n);
			h_attr(h, "value", jstr(v, "default") != NULL ? jstr(v,
			    "default") : "");
			h_raw(h, "></td></tr>");
		}
		h_raw(h, "</tbody></table>");
	}
	/* Its files. */
	h_fmt(h, "<h4>Files (%u)</h4>", ucl_array_size(jget(tp.doc, "files")));
	i = 0;
	it = NULL;
	while ((f = ucl_object_iterate(jget(tp.doc, "files"), &it, true)) !=
	    NULL) {
		h_raw(h, "<details class=\"tpfile\"><summary><code>");
		h_txt(h, jstr(f, "path"));
		h_raw(h, "</code> <span class=\"dim\">");
		h_txt(h, jstr(f, "mode"));
		h_raw(h, " ");
		h_txt(h, jstr(f, "owner"));
		h_raw(h, ":");
		h_txt(h, jstr(f, "group"));
		h_fmt(h, "</span></summary><textarea class=\"mono\" rows=\"12\" "
		    "spellcheck=\"false\" data-input=\"tp-text\" data-arg=\"%d\">",
		    i);
		h_txt(h, jstr(f, "text"));
		h_raw(h, "</textarea></details>");
		i++;
	}
	if (ucl_array_size(jget(tp.doc, "packages")) > 0) {
		h_raw(h, "<p>Packages it wants: ");
		k = 0;
		it = NULL;
		while ((p = ucl_object_iterate(jget(tp.doc, "packages"), &it,
		    true)) != NULL) {
			h_raw(h, k++ > 0 ? ", <code>" : "<code>");
			h_txt(h, jstr(p, "name"));
			h_raw(h, "</code>");
		}
		h_raw(h, ". A host without them is told; Arcana installs none "
		    "by itself.</p>");
	}
	/* Applied to a host, with its values. */
	h_raw(h, "<h4>Apply to a host</h4><div class=\"toolbar\"><label>Host "
	    "<select data-input=\"tp-target\"><option value=\"\">pick one…"
	    "</option>");
	for (i = 0; i < app.nservers; i++) {
		h_raw(h, "<option");
		h_attr(h, "value", app.servers[i].id);
		if (strcmp(tp.target, app.servers[i].id) == 0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, app.servers[i].name);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label>");
	it = NULL;
	while ((p = ucl_object_iterate(jget(tp.doc, "placeholders"), &it,
	    true)) != NULL) {
		const char	*n = ucl_object_tostring_forced(p);

		v = jget(jget(tp.doc, "variables"), n);
		h_raw(h, "<label><code>");
		h_txt(h, n);
		h_raw(h, "</code><input data-input=\"tp-val\"");
		h_attr(h, "data-arg", n);
		h_attr(h, "value", jstr(tp.values, n) != NULL ? jstr(tp.values,
		    n) : "");
		h_attr(h, "placeholder", jstr(v, "default") != NULL &&
		    jstr(v, "default")[0] != '\0' ? jstr(v, "default") :
		    "this host's");
		h_raw(h, "></label>");
	}
	h_fmt(h, "<button class=\"small\" data-act=\"tp-check\" title=\"What "
	    "the host would change, before anything is written\"%s>Check"
	    "</button></div>", tp.target[0] == '\0' || tp.busy || tp.dirty ?
	    " disabled" : "");
	if (tp.dirty)
		h_raw(h, "<p class=\"dim\">Save it first: a host is given the "
		    "template as the console keeps it.</p>");
	if (tp.busy)
		h_raw(h, "<div class=\"loader\"></div>");
	if (tp.report != NULL)
		config_report(h, tp.report, host_of(tp.rsid) != NULL ?
		    host_of(tp.rsid)->name : NULL, tp.rdry, tp.busy, tp.anyway,
		    "tp");
	h_raw(h, "</section>");
}

void
view_templates(struct html *h)
{

	if (tp.list == NULL && !tp.loading)
		templates_load();
	if (tp.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, tp.error);
		h_raw(h, "</div>");
	}
	if (tp.open[0] != '\0')
		view_one(h);
	else
		view_list(h);
}

bool
templates_action(const char *act, const char *arg, const char *value)
{
	ucl_object_t	*f, *o;
	char		 base[300], err[300], name[65], *dot;
	struct server	*t;

	if (strncmp(act, "tp-", 3) != 0 && strncmp(act, "input:tp-", 9) != 0 &&
	    strcmp(act, "file:tp-upload") != 0)
		return (false);
	if (strcmp(act, "input:tp-filter") == 0)
		snprintf(tp.filter, sizeof(tp.filter), "%s", value);
	else if (strcmp(act, "tp-open") == 0)
		open_one(arg);
	else if (strcmp(act, "tp-close") == 0) {
		tp.open[0] = '\0';
		tp.error[0] = '\0';
		templates_load();
	} else if (strcmp(act, "input:tp-desc") == 0 && tp.doc != NULL) {
		set_str(tp.doc, "description", value);
		tp.dirty = true;
	} else if (strcmp(act, "input:tp-vdesc") == 0 && tp.doc != NULL) {
		set_str(var_of(arg), "description", value);
		tp.dirty = true;
	} else if (strcmp(act, "input:tp-vdef") == 0 && tp.doc != NULL) {
		set_str(var_of(arg), "default", value);
		tp.dirty = true;
	} else if (strcmp(act, "input:tp-text") == 0 && tp.doc != NULL &&
	    (f = (ucl_object_t *)(uintptr_t)ucl_array_find_index(jget(tp.doc,
	    "files"), (unsigned int)atoi(arg))) != NULL) {
		set_str(f, "text", value);
		tp.dirty = true;
	} else if (strcmp(act, "tp-save") == 0 && tp.doc != NULL)
		template_put(tp.open, tp.doc);
	else if (strcmp(act, "tp-download") == 0 && tp.doc != NULL) {
		o = ucl_object_copy(tp.doc);
		(void)ucl_object_delete_key(o, "placeholders");
		(void)ucl_object_delete_key(o, "updated");
		ucl_object_replace_key(o, ucl_object_fromstring("template"),
		    "arcana", 0, true);
		export_base(base, sizeof(base), tp.open, "template");
		export_save(base, o, strcmp(arg, "yaml") == 0);
		ucl_object_unref(o);
	} else if (strcmp(act, "tp-delete") == 0 && tp.open[0] != '\0') {
		snprintf(base, sizeof(base), "The template %s is forgotten by the "
		    "console. Hosts it was applied to keep their files.", tp.open);
		confirm("Delete the template", base, "Delete", true, "",
		    "tp-delete-do", tp.open, "");
	} else if (strcmp(act, "tp-delete-do") == 0) {
		rc_c(base, sizeof(base), "templates/template=%s", rc_key(arg));
		tp.busy = true;
		rc_edit("DELETE", base, NULL, deleted_cb, NULL);
	} else if (strcmp(act, "file:tp-upload") == 0) {
		/* A template saved before: kept under its file's name. */
		err[0] = '\0';
		o = value[0] != '\0' ? data_parse(value, err, sizeof(err)) : NULL;
		if (o == NULL || jget(o, "files") == NULL) {
			snprintf(tp.error, sizeof(tp.error), "%s: not a template"
			    "%s%s", arg, err[0] != '\0' ? ": " : "", err);
			if (o != NULL)
				ucl_object_unref(o);
			return (true);
		}
		(void)ucl_object_delete_key(o, "arcana");
		snprintf(name, sizeof(name), "%s", jstr(o, "name") != NULL ?
		    jstr(o, "name") : arg);
		if ((dot = strrchr(name, '.')) != NULL && dot != name)
			*dot = '\0';
		template_put(name, o);
		ucl_object_unref(o);
	} else if (strcmp(act, "input:tp-target") == 0) {
		snprintf(tp.target, sizeof(tp.target), "%s", value);
		if (tp.report != NULL)
			ucl_object_unref(tp.report);
		tp.report = NULL;
	} else if (strcmp(act, "input:tp-val") == 0) {
		if (tp.values == NULL)
			tp.values = ucl_object_typed_new(UCL_OBJECT);
		if (value[0] != '\0')
			set_str(tp.values, arg, value);
		else
			(void)ucl_object_delete_key(tp.values, arg);
	} else if (strcmp(act, "input:tp-anyway") == 0)
		tp.anyway = strcmp(value, "true") == 0;
	else if (strcmp(act, "tp-check") == 0) {
		tp.anyway = false;
		send(true);
	} else if (strcmp(act, "tp-apply") == 0)
		send(false);
	else if (strcmp(act, "tp-pkgs") == 0 && tp.report != NULL &&
	    (t = host_of(tp.rsid)) != NULL)
		config_pkgs(t, tp.report, "the template's packages");
	return (true);
}
