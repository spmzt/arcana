/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Console plugins, the page's side (the console's is cplug.c there):
 * the list read after sign-in and again with the health, handed to
 * bridge.js, which loads each enabled plugin's files with the integrity
 * listed and gives its scripts window.Arcana.  Here: Settings' Plugins
 * tab, the entries plugins add to the account menu, the screen of a
 * plugin's the address names (#/p/<plugin>/<screen>[/rest]), and what
 * the page saw of each plugin (loaded, or why not).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	ucl_object_t	*o;		/* GET /api/plugins */
	char		*text;		/* as handed to the page */
	bool		 loading;
	double		 fetched;	/* 0: to be read */
	char		 error[300];
	char		 busy[48];	/* being enabled or disabled */
	ucl_object_t	*page;		/* by id: "loaded", or the error */
	ucl_object_t	*menu;		/* [{plugin, label, screen}] */
	char		 screen[160];	/* <plugin>/<screen>[/rest], or "" */
	char		*servers;	/* the hosts as last told the plugins */
} pl;

static const struct tcol pcols[] = {
	{ "Plugin", "name", false }, { "Version", "version", false },
	{ "Author", "author", false }, { "Provides", NULL, false },
	{ "Enabled", "enabled", false }, { "State", NULL, false },
};

/* The list to the page, which loads what is new in it. */
static void
give(void)
{
	char	*t;

	if (pl.o == NULL)
		return;
	t = (char *)ucl_object_emit(pl.o, UCL_EMIT_JSON_COMPACT);
	free(pl.text);
	pl.text = t;
	arc_plugins_set(pl.text, app.version, app.user, app.console_role);
}

static void
list_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	pl.loading = false;
	pl.busy[0] = '\0';
	if (status != 200 || o == NULL) {
		snprintf(pl.error, sizeof(pl.error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
		return;
	}
	pl.error[0] = '\0';
	if (pl.o != NULL)
		ucl_object_unref(pl.o);
	pl.o = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	pl.fetched = arc_now();
	give();
}

static void
list_load(void)
{

	if (pl.loading || !app.online)
		return;
	pl.loading = true;
	api("GET", "/api/plugins", NULL, list_cb, NULL);
}

/*
 * Signed in: read once at once, then with the health while the page is
 * looked at; the page loads only what is new, so a read that changed
 * nothing costs it a comparison.
 */
void
plugins_tick(double now)
{

	if (!app.servers_loaded)
		return;
	if (pl.fetched == 0 || (app.visible && now - pl.fetched > HEALTH_MS))
		list_load();
}

/* The page is looked at again: the list is read at the next tick. */
void
plugins_poke(void)
{

	if (pl.fetched != 0)
		pl.fetched = 1;
}

/* What a plugin said to the page, kept by its id. */
static void
page_set(const char *id, const char *what)
{

	if (pl.page == NULL)
		pl.page = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_replace_key(pl.page, ucl_object_fromstring(what), id, 0,
	    true);
}

static const char *
page_get(const char *id)
{

	return (pl.page != NULL ? jstr(pl.page, id) : NULL);
}

static bool
word_ok(const char *s, bool upper)
{

	if (*s == '\0')
		return (false);
	for (; *s != '\0'; s++)
		if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') ||
		    *s == '-' || (upper && ((*s >= 'A' && *s <= 'Z') ||
		    *s == '_'))))
			return (false);
	return (true);
}

/* A plugin's screen, as the address names it after #/p/. */
void
plugins_open(const char *spec)
{
	const char	*s;
	char		 id[48], name[48];
	size_t		 n;

	n = strcspn(spec, "/");
	snprintf(id, sizeof(id), "%.*s", (int)n, spec);
	s = spec[n] == '/' ? spec + n + 1 : spec + n;
	snprintf(name, sizeof(name), "%.*s", (int)strcspn(s, "/"), s);
	if (!word_ok(id, false) || !word_ok(name, true)) {
		toast(true, "No plugin's screen is #/p/%s", spec);
		pl.screen[0] = '\0';
		return;
	}
	snprintf(pl.screen, sizeof(pl.screen), "%s", spec);
}

/* Back to the console's own pages, as they were. */
void
plugins_close(void)
{

	pl.screen[0] = '\0';
}

/* The address of the plugin's screen shown, if one is. */
bool
plugins_loc(char *buf, size_t len)
{

	if (pl.screen[0] == '\0')
		return (false);
	snprintf(buf, len, "#/p/%s", pl.screen);
	return (true);
}

/* After each drawing: the page shows the plugin's screen, or none. */
void
plugins_render(void)
{

	arc_plug_screen(app.screen == SCREEN_CONSOLE ? pl.screen : "");
}

/* The hosts changed: told to the plugins, by id and name. */
void
plugins_servers(void)
{
	ucl_object_t	*a, *o;
	char		*t;
	int		 i;

	a = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < app.nservers; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(
		    app.servers[i].id), "id", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(
		    app.servers[i].name), "name", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(
		    app.servers[i].local), "local", 0, false);
		ucl_array_append(a, o);
	}
	t = (char *)ucl_object_emit(a, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(a);
	if (pl.servers != NULL && strcmp(pl.servers, t) == 0) {
		free(t);
		return;
	}
	free(pl.servers);
	pl.servers = t;
	arc_plug_event("servers", t);
}

/* Signed out: the plugins told, their screen put away; read again at
 * the next sign-in. */
void
plugins_signed_out(void)
{

	pl.screen[0] = '\0';
	pl.fetched = 0;
	arc_plug_event("signed-out", "{}");
}

/* The entries plugins add to the account menu. */
void
plugins_menu(struct html *h)
{
	const ucl_object_t	*m;
	ucl_object_iter_t	 it;
	char			 arg[100];

	it = NULL;
	while ((m = ucl_object_iterate(pl.menu, &it, true)) != NULL) {
		snprintf(arg, sizeof(arg), "%s/%s", jstr(m, "plugin"), jstr(m,
		    "screen"));
		h_raw(h, "<button class=\"ghost\" data-act=\"plugin-open\"");
		h_attr(h, "data-arg", arg);
		h_raw(h, ">");
		h_txt(h, jstr(m, "label"));
		h_raw(h, "</button>");
	}
}

/* A plugin's entries for the menu, as it registered them: kept valid. */
static void
menu_set(const char *id, const char *json)
{
	ucl_object_t		*in, *keep, *e;
	const ucl_object_t	*m;
	ucl_object_iter_t	 it;
	const char		*label, *screen;

	keep = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((m = ucl_object_iterate(pl.menu, &it, true)) != NULL)
		if (strcmp(jstr(m, "plugin"), id) != 0)
			ucl_array_append(keep, ucl_object_ref(
			    (ucl_object_t *)(uintptr_t)m));
	in = json_parse(json);
	it = NULL;
	while ((m = ucl_object_iterate(in, &it, true)) != NULL) {
		label = jstr(m, "label");
		screen = jstr(m, "screen");
		if (label == NULL || screen == NULL || !word_ok(screen, true) ||
		    strlen(label) > 64 || strlen(screen) > 40)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromstring(id), "plugin", 0,
		    false);
		ucl_object_insert_key(e, ucl_object_fromstring(label), "label",
		    0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(screen),
		    "screen", 0, false);
		ucl_array_append(keep, e);
	}
	if (in != NULL)
		ucl_object_unref(in);
	if (pl.menu != NULL)
		ucl_object_unref(pl.menu);
	pl.menu = keep;
}

bool
plugins_action(const char *act, const char *arg, const char *value)
{
	char	body[32], url[96];

	if (strcmp(act, "plugin-open") == 0) {
		plugins_open(arg);
	} else if (strcmp(act, "plugin-exit") == 0) {
		/* ctx.exit(): its screen, if it is the one shown. */
		if (strncmp(pl.screen, arg, strlen(arg)) == 0 &&
		    (pl.screen[strlen(arg)] == '\0' ||
		    pl.screen[strlen(arg)] == '/'))
			pl.screen[0] = '\0';
	} else if (strcmp(act, "plugin-missing") == 0) {
		if (strcmp(pl.screen, arg) == 0) {
			pl.screen[0] = '\0';
			toast(true, "No plugin's screen is #/p/%s", arg);
		}
	} else if (strcmp(act, "plugin-loaded") == 0) {
		if (page_get(arg) == NULL)
			page_set(arg, "loaded");
	} else if (strcmp(act, "plugin-error") == 0) {
		/* The first error is the one to read; a toast says it. */
		if (page_get(arg) == NULL || strcmp(page_get(arg), "loaded") ==
		    0)
			toast(true, "Plugin %s: %s", arg, value);
		page_set(arg, value);
	} else if (strcmp(act, "plugin-menu") == 0) {
		menu_set(arg, value);
	} else if (strcmp(act, "plugin-toast") == 0) {
		toast(arg[0] != '\0', "%s", value);
	} else if (strcmp(act, "plugin-enable") == 0) {
		/* A console owner's alone; the reply is the list. */
		if (pl.busy[0] != '\0' || !word_ok(arg, false) || strlen(arg) >
		    40)
			return (true);
		snprintf(pl.busy, sizeof(pl.busy), "%s", arg);
		snprintf(url, sizeof(url), "/api/plugins/%s", arg);
		snprintf(body, sizeof(body), "{\"enabled\":%s}",
		    strcmp(value, "1") == 0 ? "true" : "false");
		pl.loading = true;
		api("POST", url, body, list_cb, NULL);
	} else
		return (false);
	return (true);
}

/* What the page made of a plugin: running, failed, or put away at the
 * next reload. */
static void
state_cell(struct html *h, const ucl_object_t *p)
{
	const char	*id, *page;
	bool		 on;

	id = jstr(p, "id");
	page = page_get(id);
	on = jbool(p, "enabled");
	if (jstr(p, "error") != NULL) {
		h_raw(h, "<span class=\"err\">");
		h_txt(h, jstr(p, "error"));
		h_raw(h, "</span>");
	} else if (page != NULL && strcmp(page, "loaded") != 0) {
		h_raw(h, "<span class=\"err\">In this page: ");
		h_txt(h, page);
		h_raw(h, "</span>");
	} else if (page != NULL && on)
		h_raw(h, "<span class=\"chip st-up\">running here</span>");
	else if (page != NULL)
		h_raw(h, "<span class=\"chip warn\">running here until this "
		    "page is reloaded</span>");
	else if (on)
		h_raw(h, "<span class=\"dim\">loading…</span>");
	else
		h_raw(h, "<span class=\"dim\">off</span>");
}

void
set_plugins(struct html *h)
{
	const ucl_object_t	**rows, *p, *w;
	ucl_object_iter_t	  it;
	bool			  owner;
	int			  r, n;

	if (pl.o == NULL)
		list_load();
	owner = !app.by_token && strcmp(app.console_role, "owner") == 0;
	h_raw(h, "<p class=\"dim\">Extensions of this page that the console "
	    "host's administrator installed: their scripts run in the page "
	    "with your rights, so only a console owner enables one. Enabled, "
	    "a plugin is loaded at once in every signed-in page; disabled, it "
	    "is gone from a page once that page is reloaded.</p>");
	if (owner && jstr(pl.o, "dir") != NULL) {
		h_raw(h, "<p class=\"dim\">Installed under <code>");
		h_txt(h, jstr(pl.o, "dir"));
		h_raw(h, "</code>, a directory each (web.conf's "
		    "<code>plugins_dir</code>).</p>");
	}
	if (pl.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, pl.error);
		h_raw(h, "</div>");
	}
	if (pl.o == NULL) {
		h_raw(h, "<p class=\"dim\">Reading…</p>");
		return;
	}
	if (ucl_array_size(jget(pl.o, "plugins")) == 0) {
		h_raw(h, "<div class=\"empty\"><p>No console plugin is "
		    "installed.</p></div>");
		return;
	}
	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\"filter\" "
	    "data-input=\"filter\" placeholder=\"Filter\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "></div><table class=\"net cplugs\">");
	tbl_head(h, "cplugs", pcols, nitems(pcols), owner ? 1 : 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("cplugs", jget(pl.o, "plugins"), pcols, nitems(pcols),
	    app.filter);
	for (r = 0; (p = rows[r]) != NULL; r++) {
		h_raw(h, "<tr");
		h_attr(h, "data-plugin", jstr(p, "id"));
		h_raw(h, "><td><b>");
		h_txt(h, jstr(p, "name") != NULL ? jstr(p, "name") :
		    jstr(p, "id"));
		h_raw(h, "</b> <small class=\"dim mono\">");
		h_txt(h, jstr(p, "id"));
		h_raw(h, "</small>");
		if (jstr(p, "description") != NULL) {
			h_raw(h, "<br><small class=\"dim\">");
			h_txt(h, jstr(p, "description"));
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(p, "version") != NULL ? jstr(p, "version") : "");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(p, "author") != NULL ? jstr(p, "author") : "");
		h_raw(h, "</td><td>");
		n = 0;
		it = NULL;
		while ((w = ucl_object_iterate(jget(p, "provides"), &it,
		    true)) != NULL) {
			h_raw(h, "<span class=\"chip\">");
			h_txt(h, ucl_object_tostring_forced(w));
			h_raw(h, "</span> ");
			n++;
		}
		h_fmt(h, "%s</td><td>%s</td><td>", n == 0 ?
		    "<span class=\"dim\">—</span>" : "", jbool(p, "enabled") ?
		    "yes" : "no");
		state_cell(h, p);
		h_raw(h, "</td>");
		if (owner) {
			h_raw(h, "<td>");
			if (jstr(p, "error") == NULL || jbool(p, "enabled")) {
				h_fmt(h, "<button class=\"ghost small\" "
				    "data-act=\"plugin-enable\" "
				    "data-value=\"%s\"%s",
				    jbool(p, "enabled") ? "0" : "1",
				    pl.busy[0] != '\0' ? " disabled" : "");
				h_attr(h, "data-arg", jstr(p, "id"));
				h_fmt(h, ">%s</button>", jbool(p, "enabled") ?
				    "Disable" : "Enable");
			}
			h_raw(h, "</td>");
		}
		h_raw(h, "</tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (!owner)
		h_raw(h, "<p class=\"dim\">A console owner enables and "
		    "disables them.</p>");
}
