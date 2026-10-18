/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Settings, AAA: who signs in and what each may (RBAC, users.c of the
 * console), in sub-tabs.  Users have roles, one or more, and a tenant
 * perhaps, a fleet of its own; roles say what may be done on the
 * console (owner, operator, member) and on the hosts, on all or host
 * by host (viewer, operator, admin).  The sign-in keys, the directory
 * (LDAP) and the API tokens have their sub-tabs here too.  The owner
 * adds users and roles here, invites a user (a one-time link for their
 * first key) and takes users and roles away.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	ucl_object_t	*all;		/* {"users": [...], "roles": [...]} */
	bool		 loading;
	char		 edit[72];	/* the user or role edited, "" a new one */
	char		 invite_user[72];
	char		 invite[120];	/* the token issued, shown once */
} us;

static const struct {
	int		 tab;
	const char	*arg, *title;
} aaatabs[] = {
	{ AAA_USERS, "users", "Users" },
	{ AAA_ROLES, "roles", "Roles" },
	{ AAA_KEYS, "keys", "Sign-in keys" },
	{ AAA_LDAP, "ldap", "Directory (LDAP)" },
	{ AAA_TOKENS, "tokens", "API tokens" },
};

const char *
aaatab_arg(int tab)
{
	size_t	i;

	for (i = 0; i < sizeof(aaatabs) / sizeof(aaatabs[0]); i++)
		if (aaatabs[i].tab == tab)
			return (aaatabs[i].arg);
	return (aaatabs[0].arg);
}

int
aaatab_of(const char *arg)
{
	size_t	i;

	for (i = 0; arg != NULL && i < sizeof(aaatabs) / sizeof(aaatabs[0]);
	    i++)
		if (strcmp(aaatabs[i].arg, arg) == 0)
			return (aaatabs[i].tab);
	return (AAA_USERS);
}

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

/* The user or role of the name among them, or NULL. */
static const ucl_object_t *
find_in(const char *list, const char *name)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;

	it = NULL;
	while (us.all != NULL && name != NULL && (u = ucl_object_iterate(jget(
	    us.all, list), &it, true)) != NULL)
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

/* The users: who, their tenant, their roles and keys. */
static void
set_users(struct html *h)
{
	const ucl_object_t	*u, *r;
	ucl_object_iter_t	 it, rit;
	int			 n;

	h_raw(h, "<p class=\"dim\">Who signs in. Each user has roles (the next "
	    "sub-tab), which together say what they may do on the console and "
	    "on which hosts, and may belong to a <b>tenant</b>, a fleet of its "
	    "own: they then see that fleet's hosts alone. A user's first key is "
	    "registered with an invitation, a one-time link.</p>");
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
	h_raw(h, "<table class=\"net users\"><thead><tr><th>User</th><th>Roles"
	    "</th><th>On the console</th><th>Tenant</th><th>Keys</th><th></th>"
	    "</tr></thead><tbody>");
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
		rit = NULL;
		while ((r = ucl_object_iterate(jget(u, "roles"), &rit, true)) !=
		    NULL) {
			h_raw(h, "<span class=\"chip\">");
			h_txt(h, ucl_object_tostring_forced(r));
			h_raw(h, "</span> ");
		}
		h_raw(h, "</td><td>");
		h_txt(h, jstr(u, "console") != NULL ? jstr(u, "console") : "none");
		h_raw(h, "</td><td>");
		if (jstr(u, "tenant") != NULL)
			h_txt(h, jstr(u, "tenant"));
		else
			h_raw(h, "<span class=\"dim\">every fleet</span>");
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
		    "user-edit\" title=\"Change the roles or the tenant\"");
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

/* The roles: what each allows, and how many have it. */
static void
set_roles(struct html *h)
{
	const ucl_object_t	*r, *v;
	ucl_object_iter_t	 it, hit;
	int			 n;

	h_raw(h, "<p class=\"dim\">What may be done, named once and given to "
	    "users. On the console an <b>owner</b> does everything, these "
	    "settings among it; an <b>operator</b> also uses the fleet's "
	    "tools, SD-WAN, workflows, templates and transfers; a <b>member"
	    "</b> has the hosts alone. On a host, a <b>viewer</b> reads, an "
	    "<b>operator</b> changes, an <b>admin</b> also updates, moves and "
	    "removes it: on every host, or host by host. A user with several "
	    "roles may what any of them allows. Three come built in: owner, "
	    "operator and viewer.</p><table class=\"net roles\"><thead><tr><th>"
	    "Role</th><th>On the console</th><th>On the hosts</th><th>Users"
	    "</th><th></th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while (us.all != NULL && (r = ucl_object_iterate(jget(us.all, "roles"),
	    &it, true)) != NULL) {
		n++;
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(r, "name"));
		h_raw(h, "</b></td><td>");
		h_txt(h, jstr(r, "console") != NULL ? jstr(r, "console") :
		    "member");
		h_raw(h, "</td><td>");
		hit = NULL;
		while ((v = ucl_object_iterate(jget(r, "hosts"), &hit, true)) !=
		    NULL) {
			h_raw(h, "<span class=\"chip\">");
			h_txt(h, strcmp(ucl_object_key(v), "*") == 0 ? "all" :
			    host_label(ucl_object_key(v)));
			h_raw(h, ": ");
			h_txt(h, ucl_object_tostring_forced(v));
			h_raw(h, "</span> ");
		}
		if (jget(r, "hosts") == NULL || ucl_array_size(jget(r, "hosts"))
		    == 0)
			h_raw(h, "<span class=\"dim\">none</span>");
		h_raw(h, "</td><td class=\"num\">");
		h_fmt(h, "%lld", (long long)jint(r, "users", 0));
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" "
		    "data-act=\"role-edit\" title=\"Change what it allows\"");
		h_attr(h, "data-arg", jstr(r, "name"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "role-del\" title=\"Take the role away: no user may have it\"");
		h_attr(h, "data-arg", jstr(r, "name"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"5\">Asking the "
		    "console…</td></tr>");
	h_raw(h, "</tbody></table><div class=\"token-new\"><button type=\""
	    "button\" class=\"small\" data-act=\"role-add\">Add a role</button>"
	    "</div>");
}

/* Settings, AAA: the sub-tabs. */
void
set_aaa(struct html *h)
{
	size_t	i;

	if (us.all == NULL && !us.loading && (app.aaatab == AAA_USERS ||
	    app.aaatab == AAA_ROLES))
		users_load();
	h_raw(h, "<nav class=\"tabs sub\">");
	for (i = 0; i < sizeof(aaatabs) / sizeof(aaatabs[0]); i++)
		h_fmt(h, "<button class=\"tab%s\" data-act=\"aaa-tab\" "
		    "data-arg=\"%s\">%s</button>", app.aaatab == aaatabs[i].tab ?
		    " on" : "", aaatabs[i].arg, aaatabs[i].title);
	h_raw(h, "</nav>");
	switch (app.aaatab) {
	case AAA_ROLES:
		set_roles(h);
		break;
	case AAA_KEYS:
		set_keys(h);
		break;
	case AAA_LDAP:
		set_ldap(h);
		break;
	case AAA_TOKENS:
		set_tokens(h);
		break;
	default:
		set_users(h);
		break;
	}
}

/* The user form: tenant and roles; the role form: what it allows. */
bool
user_modal(struct html *h)
{
	const ucl_object_t	*u, *hosts, *r, *e;
	ucl_object_iter_t	 it, rit;
	const char		*cr, *all;
	char			 field[32];
	int			 i;
	bool			 has;

	if (app.modal == MODAL_USER) {
		u = us.edit[0] != '\0' ? find_in("users", us.edit) : NULL;
		h_fmt(h, "<form data-form=\"user\"><h2>%s</h2><p>Their roles, one "
		    "or more, say what they may; a tenant keeps them to one "
		    "fleet's hosts.</p><input type=\"hidden\" name=\"was\"", u !=
		    NULL ? "A user, changed" : "A user");
		h_attr(h, "value", us.edit);
		h_raw(h, "><div class=\"two\"><label>Name<input name=\"name\" "
		    "required maxlength=\"64\" spellcheck=\"false\" autocomplete=\""
		    "off\" placeholder=\"alice\"");
		h_attr(h, "value", jstr(u, "name") != NULL ? jstr(u, "name") : "");
		if (u != NULL)
			h_raw(h, " readonly");
		h_raw(h, "></label><label>Tenant <small class=\"dim\">a fleet of "
		    "its own; empty: every fleet</small><input name=\"tenant\" "
		    "maxlength=\"64\" spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"acme\"");
		h_attr(h, "value", jstr(u, "tenant") != NULL ? jstr(u, "tenant") :
		    "");
		h_raw(h, "></label></div><fieldset class=\"toggles roles\"><legend>"
		    "Roles</legend>");
		it = NULL;
		while (us.all != NULL && (r = ucl_object_iterate(jget(us.all,
		    "roles"), &it, true)) != NULL) {
			has = false;
			rit = NULL;
			while (!has && (e = ucl_object_iterate(jget(u, "roles"), &rit,
			    true)) != NULL)
				has = strcmp(ucl_object_tostring_forced(e), jstr(r,
				    "name")) == 0;
			h_raw(h, "<label class=\"toggle\"><input type=\"checkbox\" "
			    "name=\"r_");
			h_txt(h, jstr(r, "name"));
			h_fmt(h, "\"%s><span>", has ? " checked" : "");
			h_txt(h, jstr(r, "name"));
			h_raw(h, " <em>");
			h_txt(h, jstr(r, "console") != NULL ? jstr(r, "console") :
			    "member");
			h_raw(h, "</em></span></label>");
		}
		h_raw(h, "</fieldset>");
		return (true);
	}
	if (app.modal != MODAL_ROLE)
		return (false);
	r = us.edit[0] != '\0' ? find_in("roles", us.edit) : NULL;
	hosts = jget(r, "hosts");
	cr = jstr(r, "console") != NULL ? jstr(r, "console") : "member";
	all = jstr(hosts, "*") != NULL ? jstr(hosts, "*") : "";
	h_fmt(h, "<form data-form=\"role\"><h2>%s</h2><p>What it allows on the "
	    "console, and on the hosts: on all, or host by host.</p><input "
	    "type=\"hidden\" name=\"was\"", r != NULL ? "A role, changed" :
	    "A role");
	h_attr(h, "value", us.edit);
	h_raw(h, "><div class=\"two\"><label>Name<input name=\"name\" required "
	    "maxlength=\"64\" spellcheck=\"false\" autocomplete=\"off\" "
	    "placeholder=\"noc\"");
	h_attr(h, "value", jstr(r, "name") != NULL ? jstr(r, "name") : "");
	if (r != NULL)
		h_raw(h, " readonly");
	h_raw(h, "></label><label>On the console<select name=\"console\">");
	h_fmt(h, "<option value=\"member\"%s>Member: the hosts alone</option>"
	    "<option value=\"operator\"%s>Operator: the fleet's tools too"
	    "</option><option value=\"owner\"%s>Owner: everything</option>",
	    strcmp(cr, "member") == 0 ? " selected" : "", strcmp(cr, "operator")
	    == 0 ? " selected" : "", strcmp(cr, "owner") == 0 ? " selected" :
	    "");
	h_raw(h, "</select></label></div><label>On every host<select name=\""
	    "all\">");
	h_fmt(h, "<option value=\"\"%s>No role: host by host below</option>"
	    "<option value=\"viewer\"%s>Viewer: reads</option><option value=\""
	    "operator\"%s>Operator: changes</option><option value=\"admin\"%s>"
	    "Admin: updates, moves, removes too</option>", all[0] == '\0' ?
	    " selected" : "", strcmp(all, "viewer") == 0 ? " selected" : "",
	    strcmp(all, "operator") == 0 ? " selected" : "", strcmp(all,
	    "admin") == 0 ? " selected" : "");
	h_raw(h, "</select></label>");
	if (app.nservers > 0) {
		h_raw(h, "<fieldset class=\"roles\"><legend>Host by host <small "
		    "class=\"dim\">over the role on every host</small></legend>");
		for (i = 0; i < app.nservers; i++) {
			snprintf(field, sizeof(field), "h_%s", app.servers[i].id);
			e = hosts != NULL ? ucl_object_lookup(hosts, app.servers[i].id)
			    : NULL;
			h_raw(h, "<label class=\"role\"><span>");
			h_txt(h, app.servers[i].name);
			h_fmt(h, "</span><select name=\"%s\"><option value=\"\">as "
			    "on every host</option><option value=\"viewer\"%s>viewer"
			    "</option><option value=\"operator\"%s>operator</option>"
			    "<option value=\"admin\"%s>admin</option></select>"
			    "</label>", field, e != NULL && strcmp(
			    ucl_object_tostring_forced(e), "viewer") == 0 ?
			    " selected" : "", e != NULL && strcmp(
			    ucl_object_tostring_forced(e), "operator") == 0 ?
			    " selected" : "", e != NULL && strcmp(
			    ucl_object_tostring_forced(e), "admin") == 0 ?
			    " selected" : "");
		}
		h_raw(h, "</fieldset>");
	}
	return (true);
}

bool
user_form(const char *form, const ucl_object_t *f)
{
	ucl_object_t		*b, *hosts, *roles;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	unsigned char		*json;
	char			 url[200];
	const char		*name;

	if (strcmp(form, "user") != 0 && strcmp(form, "role") != 0)
		return (false);
	name = jstr(f, "name") != NULL ? jstr(f, "name") : "";
	if (name[0] == '\0') {
		snprintf(app.modal_error, sizeof(app.modal_error), "%s has a "
		    "name", strcmp(form, "user") == 0 ? "A user" : "A role");
		return (true);
	}
	b = ucl_object_typed_new(UCL_OBJECT);
	if (strcmp(form, "user") == 0) {
		ucl_object_insert_key(b, ucl_object_fromstring(jstr(f, "tenant")
		    != NULL ? jstr(f, "tenant") : ""), "tenant", 0, false);
		roles = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((v = ucl_object_iterate(f, &it, true)) != NULL)
			if (strncmp(ucl_object_key(v), "r_", 2) == 0 && jbool(f,
			    ucl_object_key(v)))
				ucl_array_append(roles, ucl_object_fromstring(
				    ucl_object_key(v) + 2));
		if (ucl_array_size(roles) == 0) {
			ucl_object_unref(roles);
			ucl_object_unref(b);
			snprintf(app.modal_error, sizeof(app.modal_error), "A user "
			    "has a role, one at least");
			return (true);
		}
		ucl_object_insert_key(b, roles, "roles", 0, false);
		snprintf(url, sizeof(url), "/api/users/%s", name);
	} else {
		ucl_object_insert_key(b, ucl_object_fromstring(jstr(f, "console")
		    != NULL ? jstr(f, "console") : "member"), "console", 0, false);
		hosts = ucl_object_typed_new(UCL_OBJECT);
		if (jstr(f, "all") != NULL && jstr(f, "all")[0] != '\0')
			ucl_object_insert_key(hosts, ucl_object_fromstring(jstr(f,
			    "all")), "*", 0, false);
		it = NULL;
		while ((v = ucl_object_iterate(f, &it, true)) != NULL)
			if (strncmp(ucl_object_key(v), "h_", 2) == 0 &&
			    ucl_object_type(v) == UCL_STRING &&
			    ucl_object_tostring(v)[0] != '\0')
				ucl_object_insert_key(hosts, ucl_object_fromstring(
				    ucl_object_tostring(v)), ucl_object_key(v) + 2, 0,
				    false);
		ucl_object_insert_key(b, hosts, "hosts", 0, false);
		snprintf(url, sizeof(url), "/api/roles/%s", name);
	}
	json = ucl_object_emit(b, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(b);
	app.modal_busy = true;
	api("PUT", url, (const char *)json, saved_cb, NULL);
	free(json);
	return (true);
}

bool
user_action(const char *act, const char *arg)
{
	char	url[200], body[300];

	if (strcmp(act, "user-add") == 0 || strcmp(act, "user-edit") == 0 ||
	    strcmp(act, "role-add") == 0 || strcmp(act, "role-edit") == 0) {
		snprintf(us.edit, sizeof(us.edit), "%s", strstr(act, "-edit") !=
		    NULL && arg != NULL ? arg : "");
		app.modal = strncmp(act, "user-", 5) == 0 ? MODAL_USER :
		    MODAL_ROLE;
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
	if (strcmp(act, "user-del") == 0 || strcmp(act, "role-del") == 0) {
		if (arg == NULL)
			return (true);
		if (act[0] == 'u')
			snprintf(body, sizeof(body), "%s goes, with their keys and "
			    "invitations; their sessions end.", arg);
		else
			snprintf(body, sizeof(body), "The role %s goes; a user that "
			    "has it keeps it from going until given another.", arg);
		confirm(act[0] == 'u' ? "Take the user away" : "Take the role away",
		    body, "Take away", true, "", act[0] == 'u' ? "do-user-del" :
		    "do-role-del", arg, "");
		return (true);
	}
	if (strcmp(act, "do-user-del") == 0 || strcmp(act, "do-role-del") == 0) {
		if (arg == NULL)
			return (true);
		snprintf(url, sizeof(url), "/api/%s/%s", strcmp(act,
		    "do-user-del") == 0 ? "users" : "roles", arg);
		api("DELETE", url, NULL, saved_cb, NULL);
		return (true);
	}
	return (false);
}
