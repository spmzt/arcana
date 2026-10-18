/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Settings, Users: who signs in and what each may (RBAC, users.c of
 * the console).  A user has a role on the console (owner, operator,
 * member), a role on each host or on all (viewer, operator, admin),
 * and may belong to a tenant, a fleet of its own.  The owner adds
 * users here, invites one (a one-time link for their first key) and
 * takes one away, keys and all.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	ucl_object_t	*all;		/* {"users": [...]} */
	bool		 loading;
	char		 edit[72];	/* the user edited, "" a new one */
	char		 invite_user[72];
	char		 invite[120];	/* the token issued, shown once */
} us;

static void
users_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	us.loading = false;
	if (status != 200) {
		if (err != NULL)
			snprintf(app.modal_error, sizeof(app.modal_error), "%s",
			    err);
		return;
	}
	if (us.all != NULL)
		ucl_object_unref(us.all);
	us.all = ucl_object_copy(o);
	render();
}

void
users_load(void)
{

	if (us.loading)
		return;
	us.loading = true;
	api("GET", "/api/users", NULL, users_cb, NULL);
}

static void
saved_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	app.modal_busy = false;
	if (status != 200) {
		snprintf(app.modal_error, sizeof(app.modal_error), "%s", err !=
		    NULL ? err : jstr(o, "error.message") != NULL ? jstr(o,
		    "error.message") : "not kept");
		render();
		return;
	}
	app.modal = MODAL_NONE;
	app.modal_error[0] = '\0';
	users_cb(status, o, err, NULL);
}

static void
invited_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200) {
		toast(true, "No invitation: %s", err != NULL ? err : jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : "no "
		    "answer");
		return;
	}
	snprintf(us.invite_user, sizeof(us.invite_user), "%s", jstr(o, "user")
	    != NULL ? jstr(o, "user") : "");
	snprintf(us.invite, sizeof(us.invite), "%s", jstr(o, "token") != NULL ?
	    jstr(o, "token") : "");
	users_load();
	render();
}

/* The user of the name among them, or NULL. */
static const ucl_object_t *
user_find(const char *name)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;

	it = NULL;
	while (us.all != NULL && (u = ucl_object_iterate(jget(us.all, "users"),
	    &it, true)) != NULL)
		if (jstr(u, "name") != NULL && strcmp(jstr(u, "name"), name) == 0)
			return (u);
	return (NULL);
}

/* The name of a host, for a role said by its id. */
static const char *
host_label(const char *sid)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sid) == 0)
			return (app.servers[i].name);
	return (sid);
}

/* Settings, Users: the table, and the invitation just made. */
void
set_users(struct html *h)
{
	const ucl_object_t	*u, *r;
	ucl_object_iter_t	 it, hit;
	int			 n;

	if (us.all == NULL && !us.loading)
		users_load();
	h_raw(h, "<p class=\"dim\">Who signs in, and what each may. An "
	    "<b>owner</b> does everything, these settings among it; an "
	    "<b>operator</b> also uses the fleet's tools, SD-WAN, workflows, "
	    "templates and transfers; a <b>member</b> has the hosts alone. On "
	    "a host, a <b>viewer</b> reads, an <b>operator</b> changes, an "
	    "<b>admin</b> also updates, moves and removes it. A user of a "
	    "<b>tenant</b> sees that fleet's hosts alone. A user's first key "
	    "is registered with an invitation, a one-time link.</p>");
	if (us.invite[0] != '\0') {
		h_raw(h, "<div class=\"notice info\"><b>Give ");
		h_txt(h, us.invite_user);
		h_raw(h, " this link, once: it registers their first key and is "
		    "good for a day.</b><pre class=\"out token\">");
		h_txt(h, app.console_origin[0] != '\0' ? app.console_origin : "");
		h_raw(h, "/#/invite/");
		h_txt(h, us.invite);
		h_raw(h, "</pre><button type=\"button\" class=\"small ghost\" "
		    "data-act=\"user-invite-done\">Done, I have it</button></div>");
	}
	h_raw(h, "<table class=\"net users\"><thead><tr><th>User</th><th>On the "
	    "console</th><th>Tenant</th><th>On the hosts</th><th>Keys</th>"
	    "<th></th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while (us.all != NULL && (u = ucl_object_iterate(jget(us.all, "users"),
	    &it, true)) != NULL) {
		n++;
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(u, "name"));
		h_raw(h, "</b>");
		if (app.user[0] != '\0' && jstr(u, "name") != NULL && strcmp(
		    app.user, jstr(u, "name")) == 0)
			h_raw(h, " <span class=\"dim\">you</span>");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(u, "console") != NULL ? jstr(u, "console") :
		    "member");
		h_raw(h, "</td><td>");
		if (jstr(u, "tenant") != NULL)
			h_txt(h, jstr(u, "tenant"));
		else
			h_raw(h, "<span class=\"dim\">every fleet</span>");
		h_raw(h, "</td><td>");
		hit = NULL;
		while ((r = ucl_object_iterate(jget(u, "hosts"), &hit, true)) !=
		    NULL) {
			h_raw(h, "<span class=\"chip\">");
			h_txt(h, strcmp(ucl_object_key(r), "*") == 0 ? "all" :
			    host_label(ucl_object_key(r)));
			h_raw(h, ": ");
			h_txt(h, ucl_object_tostring_forced(r));
			h_raw(h, "</span> ");
		}
		if (jget(u, "hosts") == NULL || ucl_object_lookup(jget(u, "hosts"),
		    "*") == NULL)
			h_raw(h, "<span class=\"dim\">no other</span>");
		h_raw(h, "</td><td class=\"num\">");
		h_fmt(h, "%lld", (long long)jint(u, "keys", 0));
		if (jint(u, "invites", 0) > 0)
			h_fmt(h, " <span class=\"dim\">· %lld invited</span>",
			    (long long)jint(u, "invites", 0));
		h_raw(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
		    "data-act=\"user-invite\" title=\"A one-time link for their "
		    "first key\"");
		h_attr(h, "data-arg", jstr(u, "name"));
		h_raw(h, ">Invite</button> <button class=\"icon\" data-act=\""
		    "user-edit\" title=\"Change the roles\"");
		h_attr(h, "data-arg", jstr(u, "name"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "user-del\" title=\"Take the user away, keys and all\"");
		h_attr(h, "data-arg", jstr(u, "name"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"6\">Asking the "
		    "console…</td></tr>");
	h_raw(h, "</tbody></table><div class=\"token-new\"><button type=\""
	    "button\" class=\"small\" data-act=\"user-add\">Add a user</button>"
	    "</div>");
}

/* The user form: the roles. */
bool
user_modal(struct html *h)
{
	const ucl_object_t	*u, *hosts, *r;
	const char		*cr, *all;
	char			 field[32];
	int			 i;

	if (app.modal != MODAL_USER)
		return (false);
	u = us.edit[0] != '\0' ? user_find(us.edit) : NULL;
	hosts = jget(u, "hosts");
	cr = jstr(u, "console") != NULL ? jstr(u, "console") : "member";
	all = jstr(hosts, "*") != NULL ? jstr(hosts, "*") : "";
	h_fmt(h, "<form data-form=\"user\"><h2>%s</h2><p>Their role on the "
	    "console, their tenant, and their role on the hosts: on all, or "
	    "host by host.</p><input type=\"hidden\" name=\"was\"", u != NULL ?
	    "A user, changed" : "A user");
	h_attr(h, "value", us.edit);
	h_raw(h, "><div class=\"two\"><label>Name<input name=\"name\" required "
	    "maxlength=\"64\" spellcheck=\"false\" autocomplete=\"off\" "
	    "placeholder=\"alice\"");
	h_attr(h, "value", jstr(u, "name") != NULL ? jstr(u, "name") : "");
	if (u != NULL)
		h_raw(h, " readonly");
	h_raw(h, "></label><label>On the console<select name=\"console\">");
	h_fmt(h, "<option value=\"member\"%s>Member: the hosts alone</option>"
	    "<option value=\"operator\"%s>Operator: the fleet's tools too"
	    "</option><option value=\"owner\"%s>Owner: everything</option>",
	    strcmp(cr, "member") == 0 ? " selected" : "", strcmp(cr, "operator")
	    == 0 ? " selected" : "", strcmp(cr, "owner") == 0 ? " selected" :
	    "");
	h_raw(h, "</select></label></div><div class=\"two\"><label>Tenant "
	    "<small class=\"dim\">a fleet of its own; empty: every fleet"
	    "</small><input name=\"tenant\" maxlength=\"64\" spellcheck=\""
	    "false\" autocomplete=\"off\" placeholder=\"acme\"");
	h_attr(h, "value", jstr(u, "tenant") != NULL ? jstr(u, "tenant") : "");
	h_raw(h, "></label><label>On every host<select name=\"all\">");
	h_fmt(h, "<option value=\"\"%s>No role: host by host below</option>"
	    "<option value=\"viewer\"%s>Viewer: reads</option><option value=\""
	    "operator\"%s>Operator: changes</option><option value=\"admin\"%s>"
	    "Admin: updates, moves, removes too</option>", all[0] == '\0' ?
	    " selected" : "", strcmp(all, "viewer") == 0 ? " selected" : "",
	    strcmp(all, "operator") == 0 ? " selected" : "", strcmp(all,
	    "admin") == 0 ? " selected" : "");
	h_raw(h, "</select></label></div>");
	if (app.nservers > 0) {
		h_raw(h, "<fieldset class=\"roles\"><legend>Host by host <small "
		    "class=\"dim\">over the role on every host</small></legend>");
		for (i = 0; i < app.nservers; i++) {
			snprintf(field, sizeof(field), "h_%s", app.servers[i].id);
			r = hosts != NULL ? ucl_object_lookup(hosts,
			    app.servers[i].id) : NULL;
			h_raw(h, "<label class=\"role\"><span>");
			h_txt(h, app.servers[i].name);
			h_fmt(h, "</span><select name=\"%s\"><option value=\"\">as "
			    "on every host</option><option value=\"viewer\"%s>viewer"
			    "</option><option value=\"operator\"%s>operator</option>"
			    "<option value=\"admin\"%s>admin</option></select>"
			    "</label>", field, r != NULL && strcmp(
			    ucl_object_tostring_forced(r), "viewer") == 0 ?
			    " selected" : "", r != NULL && strcmp(
			    ucl_object_tostring_forced(r), "operator") == 0 ?
			    " selected" : "", r != NULL && strcmp(
			    ucl_object_tostring_forced(r), "admin") == 0 ?
			    " selected" : "");
		}
		h_raw(h, "</fieldset>");
	}
	return (true);
}

bool
user_form(const char *form, const ucl_object_t *f)
{
	ucl_object_t		*b, *hosts;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	unsigned char		*json;
	char			 url[200];
	const char		*name;

	if (strcmp(form, "user") != 0)
		return (false);
	name = jstr(f, "name") != NULL ? jstr(f, "name") : "";
	if (name[0] == '\0') {
		snprintf(app.modal_error, sizeof(app.modal_error), "A user has a "
		    "name");
		return (true);
	}
	b = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(b, ucl_object_fromstring(jstr(f, "console") !=
	    NULL ? jstr(f, "console") : "member"), "console", 0, false);
	ucl_object_insert_key(b, ucl_object_fromstring(jstr(f, "tenant") != NULL
	    ? jstr(f, "tenant") : ""), "tenant", 0, false);
	hosts = ucl_object_typed_new(UCL_OBJECT);
	if (jstr(f, "all") != NULL && jstr(f, "all")[0] != '\0')
		ucl_object_insert_key(hosts, ucl_object_fromstring(jstr(f,
		    "all")), "*", 0, false);
	it = NULL;
	while ((v = ucl_object_iterate(f, &it, true)) != NULL)
		if (strncmp(ucl_object_key(v), "h_", 2) == 0 &&
		    ucl_object_type(v) == UCL_STRING && ucl_object_tostring(v)[0]
		    != '\0')
			ucl_object_insert_key(hosts, ucl_object_fromstring(
			    ucl_object_tostring(v)), ucl_object_key(v) + 2, 0,
			    false);
	ucl_object_insert_key(b, hosts, "hosts", 0, false);
	json = ucl_object_emit(b, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(b);
	snprintf(url, sizeof(url), "/api/users/%s", name);
	app.modal_busy = true;
	api("PUT", url, (const char *)json, saved_cb, NULL);
	free(json);
	return (true);
}

bool
user_action(const char *act, const char *arg)
{
	char	url[200], body[300];

	if (strcmp(act, "user-add") == 0 || strcmp(act, "user-edit") == 0) {
		snprintf(us.edit, sizeof(us.edit), "%s", strcmp(act, "user-edit")
		    == 0 && arg != NULL ? arg : "");
		app.modal = MODAL_USER;
		app.modal_error[0] = '\0';
		return (true);
	}
	if (strcmp(act, "user-invite") == 0) {
		if (arg == NULL)
			return (true);
		snprintf(url, sizeof(url), "/api/users/%s/invite", arg);
		api("POST", url, "{}", invited_cb, NULL);
		return (true);
	}
	if (strcmp(act, "user-invite-done") == 0) {
		us.invite[0] = '\0';
		us.invite_user[0] = '\0';
		return (true);
	}
	if (strcmp(act, "user-del") == 0) {
		if (arg == NULL)
			return (true);
		snprintf(body, sizeof(body), "%s goes, with their keys and "
		    "invitations; their sessions end.", arg);
		confirm("Take the user away", body, "Take away", true, "",
		    "do-user-del", arg, "");
		return (true);
	}
	if (strcmp(act, "do-user-del") == 0) {
		if (arg == NULL)
			return (true);
		snprintf(url, sizeof(url), "/api/users/%s", arg);
		api("DELETE", url, NULL, saved_cb, NULL);
		return (true);
	}
	return (false);
}
