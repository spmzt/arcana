/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What an operation is on the wire: the YANG module it is a part of
 * (share/arcana/yang-ops), as its RFC 8340 tree (yang.json, made by the
 * build).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static void
yang_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	app.yang_loading = false;
	if (status == 200 && o != NULL && jget(o, "ops") != NULL)
		app.yang = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	else
		app.yang_failed = true;
}

void
load_schema(void)
{

	if (app.yang != NULL || app.yang_loading || app.yang_failed)
		return;
	app.yang_loading = true;
	api("GET", "/yang.json", NULL, yang_cb, NULL);
}

/* Operation op's YANG model. */
static const ucl_object_t *
yang_of(const char *op)
{
	char key[96];

	if (op == NULL || app.yang == NULL)
		return (NULL);
	snprintf(key, sizeof(key), "ops.%s", op);
	return (jget(app.yang, key));
}

static void
view_yang(struct html *h, const ucl_object_t *o)
{

	h_raw(h, "<div class=\"schema\"><h4>YANG model <span class=\"dim\">");
	h_txt(h, jstr(o, "module"));
	h_raw(h, "@");
	h_txt(h, jstr(o, "revision"));
	h_raw(h, "</span></h4><pre class=\"cddl\">");
	h_txt(h, jstr(o, "tree"));
	h_raw(h, "</pre><p class=\"dim note\">The tree as RFC 8340 draws it: "
	    "rw configuration, ro state, x an action, * a list or "
	    "leaf-list, ? what may be absent.</p></div>");
}

/*
 * The operation a trace is of: the call it names, as "libcblink YANG
 * service-action", is the operation service-action.
 */
const char *
schema_op(const ucl_object_t *trace)
{
	static char		 name[64];
	const ucl_object_t	*s;
	ucl_object_iter_t	 it;
	const char		*l, *p;
	size_t			 i;

	it = NULL;
	while ((s = ucl_object_iterate(trace, &it, true)) != NULL) {
		if ((l = jstr(s, "label")) == NULL || (p = strstr(l,
		    "libcblink YANG ")) == NULL)
			continue;
		p += 15;
		for (i = 0; p[i] != '\0' && p[i] != ' ' && i <
		    sizeof(name) - 1; i++)
			name[i] = p[i];
		name[i] = '\0';
		return (name);
	}
	return (NULL);
}

/* The YANG model of operation op, or of what is known of it. */
void
view_schema(struct html *h, const char *op)
{
	const ucl_object_t	*y;

	if ((y = yang_of(op)) != NULL) {
		view_yang(h, y);
		return;
	}
	h_raw(h, "<div class=\"schema\"><h4>YANG model");
	if (app.yang == NULL) {
		load_schema();
		h_raw(h, app.yang_failed ? "</h4><p class=\"dim\">The "
		    "console has no yang.json.</p></div>" :
		    "</h4><div class=\"loader\"></div></div>");
		return;
	}
	h_raw(h, "</h4><p class=\"dim\">This entry is not one operation "
	    "of a module.</p></div>");
}
