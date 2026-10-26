/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console's own API, as docs/openapi.yaml documents it: every
 * route with what it is for, what it takes and what it answers, to be
 * searched.  The build makes openapi.json of the document; the
 * document itself is served beside it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	ucl_object_t	*doc;
	bool		 loading;
	bool		 failed;
	char		 tag[32];	/* the group shown, or "" for all */
	char		 open[160];	/* "method path" of the one unfolded */
} ad;

static void
apidoc_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	ad.loading = false;
	if (status == 200 && o != NULL && jget(o, "ops") != NULL)
		ad.doc = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	else
		ad.failed = true;
}

void
apidoc_open(void)
{

	app.node = NODE_API;
	app.jail[0] = '\0';
	app.rail_open = false;
	if (ad.doc != NULL || ad.loading)
		return;
	ad.failed = false;
	ad.loading = true;
	api("GET", "/openapi.json", NULL, apidoc_cb, NULL);
}

static bool
has(const char *s, const char *needle)
{

	return (s != NULL && strstr(s, needle) != NULL);
}

void
view_apidoc(struct html *h)
{
	static const char *const tags[] = { "health", "auth", "servers",
	    "jails", "console" };
	const ucl_object_t	*o, *p;
	ucl_object_iter_t	 it, pit;
	const char		*tag, *method, *path;
	char			 key[160];
	size_t			 i;
	int			 shown;
	bool			 first;

	h_raw(h, "<div class=\"apidoc\"><header><h2>API</h2>");
	if (ad.doc != NULL) {
		h_raw(h, "<span class=\"chip\">");
		h_txt(h, jstr(ad.doc, "version"));
		h_raw(h, "</span>");
	}
	h_raw(h, "<a class=\"ghost small\" href=\"/openapi.yaml\" target=\""
	    "_blank\" rel=\"noopener\" title=\"The document itself, OpenAPI "
	    "3.1, for a client generator or another viewer\">openapi.yaml</a>"
	    "</header>");
	if (ad.doc == NULL) {
		h_fmt(h, "<div class=\"empty\"><p>%s</p></div></div>",
		    ad.failed ? "This console has no openapi.json." :
		    "Reading the API's description…");
		return;
	}
	h_raw(h, "<p class=\"about\">");
	h_txt(h, jstr(ad.doc, "about"));
	h_raw(h, "</p><div class=\"toolbar\"><nav class=\"sub\">");
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"api-tag\" "
	    "data-arg=\"\">all</button>", ad.tag[0] == '\0' ? " on" : "");
	for (i = 0; i < sizeof(tags) / sizeof(tags[0]); i++)
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"api-tag\" "
		    "data-arg=\"%s\">%s</button>", strcmp(ad.tag, tags[i]) ==
		    0 ? " on" : "", tags[i], tags[i]);
	h_raw(h, "</nav><input class=\"filter\" id=\"filter\" data-input=\""
	    "filter\" placeholder=\"Filter: a path, a word\" autocomplete=\""
	    "off\" spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "></div><ul class=\"apiops\">");
	shown = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(ad.doc, "ops"), &it, true)) !=
	    NULL) {
		tag = jstr(o, "tag") != NULL ? jstr(o, "tag") : "";
		method = jstr(o, "method") != NULL ? jstr(o, "method") : "";
		path = jstr(o, "path") != NULL ? jstr(o, "path") : "";
		if (ad.tag[0] != '\0' && strcmp(ad.tag, tag) != 0)
			continue;
		if (app.filter[0] != '\0' && !has(path, app.filter) && !has(
		    jstr(o, "summary"), app.filter) && !has(jstr(o, "about"),
		    app.filter) && !has(method, app.filter))
			continue;
		shown++;
		snprintf(key, sizeof(key), "%s %s", method, path);
		h_fmt(h, "<li class=\"apiop m-%s%s\" data-act=\"api-open\"",
		    method, strcmp(ad.open, key) == 0 ? " open" : "");
		h_attr(h, "data-arg", key);
		h_raw(h, "><div class=\"line\"><b class=\"method\">");
		h_txt(h, method);
		h_raw(h, "</b><code>");
		h_txt(h, path);
		h_raw(h, "</code><span>");
		h_txt(h, jstr(o, "summary"));
		h_raw(h, "</span>");
		if (jbool(o, "open"))
			h_raw(h, "<span class=\"chip dim\" title=\"Answers "
			    "without a session\">open</span>");
		h_raw(h, "</div>");
		if (strcmp(ad.open, key) == 0) {
			h_raw(h, "<div class=\"more\">");
			if (jstr(o, "about") != NULL && jstr(o, "about")[0] !=
			    '\0') {
				h_raw(h, "<p>");
				h_txt(h, jstr(o, "about"));
				h_raw(h, "</p>");
			}
			if (ucl_array_size(jget(o, "params")) > 0) {
				h_raw(h, "<p><b>Takes</b> ");
				first = true;
				pit = NULL;
				while ((p = ucl_object_iterate(jget(o,
				    "params"), &pit, true)) != NULL) {
					h_raw(h, first ? "<code>" :
					    ", <code>");
					h_txt(h, ucl_object_tostring_forced(p));
					h_raw(h, "</code>");
					first = false;
				}
				h_raw(h, "</p>");
			}
			if (ucl_array_size(jget(o, "codes")) > 0) {
				h_raw(h, "<p><b>Answers</b> ");
				pit = NULL;
				while ((p = ucl_object_iterate(jget(o,
				    "codes"), &pit, true)) != NULL) {
					h_raw(h, "<span class=\"chip\">");
					h_txt(h, ucl_object_tostring_forced(p));
					h_raw(h, "</span> ");
				}
				h_raw(h, "</p>");
			}
			if (strcmp(method, "get") != 0)
				h_raw(h, "<p class=\"dim\">It changes "
				    "something: beside the session, the "
				    "console's own Origin (a browser sends it) "
				    "or, from a client without one, the header "
				    "<code>X-Arcana: 1</code>."
				    "</p>");
			h_raw(h, "</div>");
		}
		h_raw(h, "</li>");
	}
	h_raw(h, "</ul>");
	if (shown == 0)
		h_raw(h, "<div class=\"empty\"><p>No route of that name."
		    "</p></div>");
	h_raw(h, "</div>");
}

bool
apidoc_action(const char *act, const char *arg, const char *value)
{

	(void)value;
	if (strcmp(act, "select-api") == 0) {
		apidoc_open();
		return (true);
	}
	if (strcmp(act, "api-tag") == 0) {
		snprintf(ad.tag, sizeof(ad.tag), "%s", arg);
		return (true);
	}
	if (strcmp(act, "api-open") == 0) {
		if (strcmp(ad.open, arg) == 0)
			ad.open[0] = '\0';
		else
			snprintf(ad.open, sizeof(ad.open), "%s", arg);
		return (true);
	}
	return (false);
}
