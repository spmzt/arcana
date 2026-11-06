/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The files a commit writes on a host, arcana-agent's config-files
 * through the fleet mount (docs/notes/config-files.md): Arcana's own
 * (rc.conf.d/arcana, named in rc.conf(5)'s rc_conf_files, and
 * loader.conf.d/arcana.conf) or the system's (rc.conf and
 * loader.conf(5) themselves).  The System tab's row says which, its
 * Switch a dry run first, every variable both set in a table that
 * sorts and filters (tbl.c), a choice each: Additive (sysrc(8)'s +=,
 * a word list's), Arcana's, Yours or an edited value; then the switch
 * as a task.  And the merge editor: a commit refused with rc-conf-merge
 * (ycommit.c) shows each value side by side, the words of each marked,
 * the result edited; resolve takes it and the commit goes again.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static const struct tcol cf_cols[] = {
	{ "Variable", "variable", false },
	{ "File", "file", false },
	{ "Yours", "yours", false },
	{ "Arcana's", "arcana", false },
	{ "Choice", NULL, false },
};

static struct {
	char		 sid[16];	/* the host the state is of */
	ucl_object_t	*state;		/* config-files */
	bool		 loading;
	/* The switch's box: its dry run's output. */
	bool		 merge;		/* the merge editor, not the switch */
	ucl_object_t	*dry;
	char		 to[8];
	char		 filter[64];
	bool		 busy;
	int		 op;		/* the switch's task, its id */
	/* The merge editor: the commit refused, pending's rows. */
	struct ycommit	*yc;
	ucl_object_t	*pending;
} cf;

static struct server *
host_of(const char *sid)
{

	for (int i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sid) == 0)
			return (&app.servers[i]);
	return (NULL);
}

/* config-files as the host has it, the node or under its name. */
static const ucl_object_t *
node(const ucl_object_t *o)
{
	const ucl_object_t	*n;

	if ((n = jget(o, "arcana-agent:config-files")) != NULL ||
	    (n = jget(o, "config-files")) != NULL)
		return (n);
	return (o);
}

static void
state_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid = arg;

	(void)err;
	cf.loading = false;
	if (strcmp(sid, cf.sid) == 0 && status == 200 && o != NULL) {
		if (cf.state != NULL)
			ucl_object_unref(cf.state);
		cf.state = ucl_object_ref(node(o));
	}
	free(sid);
	render();
}

static void
load(const struct server *s, bool again)
{
	char	*sid;

	if (strcmp(cf.sid, s->id) != 0) {
		if (cf.state != NULL)
			ucl_object_unref(cf.state);
		cf.state = NULL;
		snprintf(cf.sid, sizeof(cf.sid), "%s", s->id);
	} else if ((cf.state != NULL && !again) || cf.loading)
		return;
	if ((sid = strdup(s->id)) == NULL)
		abort();
	cf.loading = true;
	host_yread(s, "arcana-agent:agent/config-files", NULL, NULL, false,
	    state_cb, sid);
}

static bool
is_system(void)
{
	const char	*m = jstr(cf.state, "mode");

	return (m != NULL && strcmp(m, "system") == 0);
}

/* The System tab's row. */
void
cfgfiles_view(struct html *h, struct server *s)
{

	load(s, false);
	h_raw(h, "<section class=\"sysview cfgfiles\"><h3 class=\"secsub\">"
	    "Configuration files</h3><p>");
	if (cf.state == NULL) {
		h_raw(h, "<span class=\"dim\">Reading…</span></p></section>");
		return;
	}
	if (is_system())
		h_raw(h, "<b>The system's</b>: <code>rc.conf</code>, "
		    "<code>loader.conf</code>. <span class=\"dim\">A commit "
		    "writes each variable where your files set it (the last "
		    "file rc(8) reads it from), else in /etc/rc.conf; a "
		    "tunable in loader.conf(5).</span>");
	else
		h_raw(h, "<b>Arcana's own files</b>: <code>rc.conf.d/arcana"
		    "</code>, <code>loader.conf.d/arcana.conf</code>. <span "
		    "class=\"dim\">rc(8) reads Arcana's file after yours, "
		    "named in rc.conf(5)'s rc_conf_files; your lines stay as "
		    "they are.</span>");
	h_raw(h, " <button class=\"ghost small\" data-act=\"cfg-switch\" "
	    "title=\"Switch the files a commit writes: a dry run first\">"
	    "Switch</button></p>");
	if (jstr(cf.state, "firewall-rules") != NULL) {
		h_raw(h, "<p class=\"dim\">Kept firewall rules: <code>");
		h_txt(h, jstr(cf.state, "firewall-rules"));
		h_raw(h, "</code>, booted by the script beside them "
		    "(firewall_script).</p>");
	}
	h_raw(h, "</section>");
}

/* Words of a marked against b's: those b has not, in mark. */
static void
words_marked(struct html *h, const char *a, const char *b, const char *mark)
{
	char	*ca, *cb, *w, *p, *q, *x;
	bool	 found, first = true;

	if (a == NULL)
		return;
	if ((ca = strdup(a)) == NULL || (cb = strdup(b != NULL ? b : "")) ==
	    NULL)
		abort();
	for (p = ca; (w = strsep(&p, " \t")) != NULL; ) {
		if (*w == '\0')
			continue;
		found = false;
		strcpy(cb, b != NULL ? b : "");
		for (q = cb; !found && (x = strsep(&q, " \t")) != NULL; )
			found = strcmp(x, w) == 0;
		if (!first)
			h_raw(h, " ");
		first = false;
		if (!found)
			h_fmt(h, "<%s>", mark);
		h_txt(h, w);
		if (!found)
			h_fmt(h, "</%s>", mark);
	}
	free(ca);
	free(cb);
}

static void
dry_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	cf.busy = false;
	if (status != 200 || o == NULL) {
		snprintf(app.modal_error, sizeof(app.modal_error), "%s",
		    err != NULL ? err : "the dry run failed");
		render();
		return;
	}
	if (cf.dry != NULL)
		ucl_object_unref(cf.dry);
	cf.dry = ucl_object_ref(o);
	render();
}

static void
dry_run(struct server *s)
{
	char	in[64];

	snprintf(in, sizeof(in), "{\"to\":\"%s\",\"dry-run\":true}", cf.to);
	cf.busy = true;
	host_yread(s, "arcana-agent:agent/config-files/switch", in, NULL,
	    false, dry_cb, NULL);
}

static void
switched_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct server	*s;

	(void)arg;
	cf.busy = false;
	if (status != 200 || o == NULL || !jbool(o, "done")) {
		snprintf(app.modal_error, sizeof(app.modal_error), "%s",
		    err != NULL ? err : "not switched");
		if (op_find(cf.op) != NULL)
			op_end(op_find(cf.op), false, app.modal_error);
		cf.op = 0;
		render();
		return;
	}
	if (op_find(cf.op) != NULL)
		op_end(op_find(cf.op), true, NULL);
	cf.op = 0;
	toast(false, "Configuration files: %s from now on%s%s",
	    strcmp(cf.to, "system") == 0 ? "the system's" : "Arcana's own",
	    jstr(o, "backup") != NULL ? "; the files before in " : "",
	    jstr(o, "backup") != NULL ? jstr(o, "backup") : "");
	app.modal = MODAL_NONE;
	if ((s = cur_server()) != NULL)
		load(s, true);
	render();
}

/* A row's choices: Additive for a word list alone. */
static void
choice_select(struct html *h, const ucl_object_t *r)
{
	static const char *const ch[] = { "additive", "Additive",
	    "arcana", "Arcana's", "yours", "Yours", "edit", "Edit" };
	const char	*kind = jstr(r, "kind"), *var = jstr(r, "variable");
	const char	*c = jstr(r, "choice");
	bool		 list = jbool(r, "list");
	char		 name[160];

	if (c != NULL && strcmp(c, "clone") == 0) {
		h_raw(h, "<span class=\"dim\">cloned</span>");
		return;
	}
	if (jstr(r, "yours") == NULL) {
		h_raw(h, "<span class=\"dim\">Arcana's: yours sets none"
		    "</span>");
		return;
	}
	snprintf(name, sizeof(name), "c:%s:%s", kind, var);
	h_raw(h, "<select");
	h_attr(h, "name", name);
	h_raw(h, ">");
	if (c == NULL)
		h_raw(h, "<option value=\"\" selected>Choose…</option>");
	for (size_t i = 0; i < nitems(ch); i += 2) {
		if (i == 0 && !list)
			continue;
		h_fmt(h, "<option value=\"%s\"%s>%s</option>", ch[i], c !=
		    NULL && strcmp(c, ch[i]) == 0 ? " selected" : "",
		    ch[i + 1]);
	}
	h_raw(h, "</select> ");
	snprintf(name, sizeof(name), "v:%s:%s", kind, var);
	h_raw(h, "<input class=\"cfg-edit\" spellcheck=\"false\" "
	    "placeholder=\"with Edit: the value\"");
	h_attr(h, "name", name);
	h_attr(h, "value", jstr(r, "result") != NULL ? jstr(r, "result") :
	    "");
	h_raw(h, ">");
}

static void
switch_modal(struct html *h)
{
	const ucl_object_t	**rows, *v;
	ucl_object_iter_t	  it;

	h_fmt(h, "<form data-form=\"cfg-switch\" class=\"wide\"><h2>Switch "
	    "to %s</h2>", strcmp(cf.to, "system") == 0 ? "the system's "
	    "files" : "Arcana's own files");
	if (strcmp(cf.to, "system") == 0)
		h_raw(h, "<p>Each variable of Arcana's files goes where yours "
		    "is (the last file rc(8) reads it from), else into "
		    "<code>/etc/rc.conf</code>; a tunable into loader.conf(5). "
		    "Where both set one: <b>Additive</b> keeps your words and "
		    "adds Arcana's, as <code>sysrc var+=</code> does (a word "
		    "list's alone), <b>Arcana's</b> is what boots now, "
		    "<b>Yours</b> your line's, <b>Edit</b> a value of your "
		    "own. A line Arcana commented out (\"taken by Arcana\") "
		    "is put back where it is. Then Arcana's files are gone, "
		    "rc_conf_files as it was.</p>");
	else
		h_raw(h, "<p>Every variable your rc.conf files set, and the "
		    "loader's tunables, cloned into Arcana's files, which "
		    "rc(8) and the loader read after yours: what boots stays "
		    "the same, your files as they are but rc_conf_files, "
		    "which names Arcana's.</p>");
	if (cf.dry == NULL) {
		h_raw(h, "<p class=\"dim\">The dry run…</p>");
		return;
	}
	h_raw(h, "<input class=\"filter\" data-input=\"cfg-filter\" "
	    "placeholder=\"Filter rows\"");
	h_attr(h, "value", cf.filter);
	h_raw(h, "><table class=\"net cfg-rows\">");
	tbl_head(h, "cfg-rows", cf_cols, (int)nitems(cf_cols), 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("cfg-rows", jget(cf.dry, "row"), cf_cols,
	    (int)nitems(cf_cols) - 1, cf.filter);
	for (size_t i = 0; rows[i] != NULL; i++) {
		const ucl_object_t *r = rows[i];

		h_raw(h, "<tr");
		h_attr(h, "data-var", jstr(r, "variable"));
		h_raw(h, "><td><code>");
		h_txt(h, jstr(r, "variable"));
		h_raw(h, "</code>");
		if (strcmp(jstr(r, "kind") != NULL ? jstr(r, "kind") : "",
		    "loader") == 0)
			h_raw(h, " <small class=\"dim\">tunable</small>");
		if (jbool(r, "list"))
			h_raw(h, " <small class=\"dim\">list</small>");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "file"));
		h_raw(h, "</td><td class=\"diff\">");
		words_marked(h, jstr(r, "yours"), jstr(r, "arcana"), "del");
		h_raw(h, "</td><td class=\"diff\">");
		words_marked(h, jstr(r, "arcana"), jstr(r, "yours"), "ins");
		h_raw(h, "</td><td>");
		choice_select(h, r);
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	it = NULL;
	while ((v = ucl_object_iterate(jget(cf.dry, "moved"), &it, true)) !=
	    NULL) {
		h_raw(h, "<p>Firewall: ");
		h_txt(h, ucl_object_tostring(v));
		h_raw(h, "</p>");
	}
	it = NULL;
	while ((v = ucl_object_iterate(jget(cf.dry, "note"), &it, true)) !=
	    NULL) {
		h_raw(h, "<p class=\"dim\">");
		h_txt(h, ucl_object_tostring(v));
		h_raw(h, "</p>");
	}
	h_raw(h, "<p class=\"dim\">Before anything is written, every file it "
	    "changes is copied into /var/db/arcana/config-switch/&lt;time&gt;"
	    "; a failure puts every file back. Nothing is loaded: rc(8) "
	    "and the loader read them at the next start or boot.</p>");
}

static void
merge_modal(struct html *h)
{
	const ucl_object_t	*r;
	ucl_object_iter_t	 it = NULL;
	char			 name[160];

	h_raw(h, "<form data-form=\"cfg-merge\" class=\"wide\"><h2>Merge by "
	    "hand</h2><p>Your files set these to values no merge of words "
	    "gives (a word list's would be <code>sysrc var+=</code>'s). "
	    "Each side by side, what the other has not marked; the result "
	    "is written ");
	h_raw(h, is_system() ? "where your line is" : "in Arcana's file, "
	    "which rc(8) reads after yours (rc_conf_files)");
	h_raw(h, ", and the commit goes again.</p>");
	if (cf.pending == NULL) {
		h_raw(h, "<p class=\"dim\">Reading what the host asks…</p>");
		return;
	}
	while ((r = ucl_object_iterate(jget(cf.pending, "pending"), &it,
	    true)) != NULL) {
		h_raw(h, "<fieldset class=\"cfg-merge\"><legend><code>");
		h_txt(h, jstr(r, "variable"));
		h_raw(h, "</code> <small class=\"dim\">");
		h_txt(h, jstr(r, "file"));
		h_fmt(h, " line %d</small></legend><div class=\"two\">"
		    "<div><small>Yours</small><pre class=\"diff y\">",
		    (int)jint(r, "line", 0));
		words_marked(h, jstr(r, "yours"), jstr(r, "proposed"), "del");
		h_raw(h, "</pre></div><div><small>Arcana's</small><pre "
		    "class=\"diff a\">");
		words_marked(h, jstr(r, "proposed"), jstr(r, "yours"), "ins");
		h_raw(h, "</pre></div></div><label>Result<textarea rows=\"2\" "
		    "spellcheck=\"false\"");
		snprintf(name, sizeof(name), "r:%s:%s", jstr(r, "kind"),
		    jstr(r, "variable"));
		h_attr(h, "name", name);
		h_raw(h, ">");
		h_txt(h, jstr(r, "value") != NULL ? jstr(r, "value") :
		    jstr(r, "proposed"));
		h_raw(h, "</textarea></label></fieldset>");
	}
}

bool
cfg_modal(struct html *h)
{

	if (app.modal != MODAL_CFG)
		return (false);
	if (cf.merge)
		merge_modal(h);
	else
		switch_modal(h);
	return (true);
}

void
cfg_modal_buttons(struct html *h)
{

	if (cf.merge)
		h_fmt(h, "<button class=\"primary\"%s>Save the merge and "
		    "commit</button>", cf.busy || cf.pending == NULL ?
		    " disabled" : "");
	else
		h_fmt(h, "<button class=\"primary\"%s>Switch</button>",
		    cf.busy || cf.dry == NULL ? " disabled" : "");
}

static void
pending_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200 || o == NULL) {
		snprintf(app.modal_error, sizeof(app.modal_error), "%s",
		    err != NULL ? err : "not read");
		render();
		return;
	}
	if (cf.pending != NULL)
		ucl_object_unref(cf.pending);
	cf.pending = ucl_object_ref(node(o));
	render();
}

/* The merge editor for yc's commit, refused with rc-conf-merge. */
void
cfg_merge_open(struct ycommit *yc)
{
	struct server	*s;

	if ((s = host_of(yc->sid)) == NULL)
		return;
	cf.yc = yc;
	cf.merge = true;
	cf.busy = false;
	if (cf.pending != NULL)
		ucl_object_unref(cf.pending);
	cf.pending = NULL;
	app.modal_error[0] = '\0';
	app.modal = MODAL_CFG;
	load(s, false);
	host_yread(s, "arcana-agent:agent/config-files", NULL, NULL, false,
	    pending_cb, NULL);
	render();
}

static void
resolved_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	(void)o;
	cf.busy = false;
	if (status != 200 && status != 204) {
		snprintf(app.modal_error, sizeof(app.modal_error), "%s",
		    err != NULL ? err : "not taken");
		render();
		return;
	}
	app.modal = MODAL_NONE;
	if (cf.yc != NULL)
		ycommit_accept(cf.yc, "rc-conf-merge");
	render();
}

static const char *
field(const ucl_object_t *f, const char *name)
{
	const ucl_object_t	*v = ucl_object_lookup(f, name);

	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

bool
cfg_form(const char *form, const ucl_object_t *f)
{
	const ucl_object_t	*r;
	ucl_object_iter_t	 it = NULL;
	struct server		*s;
	struct html		 b;
	char			 name[160], url[300], *q;
	bool			 first = true;

	if (strcmp(form, "cfg-merge") != 0 && strcmp(form, "cfg-switch") != 0)
		return (false);
	if ((s = cur_server()) == NULL || (cf.merge && cf.yc != NULL &&
	    (s = host_of(cf.yc->sid)) == NULL) || cf.busy)
		return (true);
	memset(&b, 0, sizeof(b));
	app.modal_error[0] = '\0';
	if (strcmp(form, "cfg-merge") == 0) {
		h_raw(&b, "{\"row\":[");
		while ((r = ucl_object_iterate(jget(cf.pending, "pending"),
		    &it, true)) != NULL) {
			snprintf(name, sizeof(name), "r:%s:%s", jstr(r, "kind"),
			    jstr(r, "variable"));
			h_fmt(&b, "%s{\"kind\":\"%s\",\"variable\":", first ? "" :
			    ",", jstr(r, "kind"));
			q = json_quote(jstr(r, "variable"));
			h_raw(&b, q);
			free(q);
			q = json_quote(field(f, name) != NULL ? field(f, name) :
			    jstr(r, "proposed"));
			h_raw(&b, ",\"value\":");
			h_raw(&b, q);
			free(q);
			h_raw(&b, "}");
			first = false;
		}
		h_raw(&b, "]}");
		rc_h(url, sizeof(url), s->id, "arcana-agent:agent/config-files/"
		    "resolve");
		cf.busy = true;
		rc_action(url, b.s, NULL, resolved_cb, NULL);
		free(b.s);
		render();
		return (true);
	}
	/* The switch: each row's choice. */
	h_fmt(&b, "{\"to\":\"%s\",\"merge\":[", cf.to);
	while ((r = ucl_object_iterate(jget(cf.dry, "row"), &it, true)) !=
	    NULL) {
		const char *c, *v;

		snprintf(name, sizeof(name), "c:%s:%s", jstr(r, "kind"),
		    jstr(r, "variable"));
		if ((c = field(f, name)) == NULL || c[0] == '\0')
			continue;
		snprintf(name, sizeof(name), "v:%s:%s", jstr(r, "kind"),
		    jstr(r, "variable"));
		v = field(f, name);
		h_fmt(&b, "%s{\"kind\":\"%s\",\"variable\":", first ? "" : ",",
		    jstr(r, "kind"));
		q = json_quote(jstr(r, "variable"));
		h_raw(&b, q);
		free(q);
		h_fmt(&b, ",\"choice\":\"%s\"", strcmp(c, "additive") == 0 ?
		    "additive" : strcmp(c, "yours") == 0 ? "yours" :
		    strcmp(c, "edit") == 0 ? "edit" : "arcana");
		if (strcmp(c, "edit") == 0) {
			q = json_quote(v != NULL ? v : "");
			h_raw(&b, ",\"value\":");
			h_raw(&b, q);
			free(q);
		}
		h_raw(&b, "}");
		first = false;
	}
	h_raw(&b, "]}");
	/* A change, not a read: a task of its own, the action posted. */
	cf.busy = true;
	cf.op = op_begin("config-files switch", s->name)->id;
	rc_h(url, sizeof(url), s->id, "arcana-agent:agent/config-files/"
	    "switch");
	rc_action(url, b.s, NULL, switched_cb, NULL);
	free(b.s);
	render();
	return (true);
}

bool
cfg_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;

	(void)arg;
	if (strcmp(act, "input:cfg-filter") == 0) {
		snprintf(cf.filter, sizeof(cf.filter), "%s", value != NULL ?
		    value : "");
		render();
		return (true);
	}
	if (strcmp(act, "cfg-switch") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	cf.merge = false;
	cf.busy = false;
	cf.filter[0] = '\0';
	if (cf.dry != NULL)
		ucl_object_unref(cf.dry);
	cf.dry = NULL;
	snprintf(cf.to, sizeof(cf.to), "%s", is_system() ? "arcana" :
	    "system");
	app.modal_error[0] = '\0';
	app.modal = MODAL_CFG;
	dry_run(s);
	render();
	return (true);
}
