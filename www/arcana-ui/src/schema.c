/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What an operation looks like on the wire: its request and reply as
 * CBOR maps keyed by attribute number, written the way CDDL writes
 * them, with the attribute sets they nest.  The schema is the family's
 * own (share/arcana/arcana.yaml), made into schema.json by the build.
 * Beside it, for an operation converted to YANG (PLAN-SDN-YANG Y-3,
 * share/arcana/yang-ops), the module it is now, as its RFC 8340 tree
 * (yang.json).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	MAX_SETS	24

static const char	*cddl_type(const char *, char *, size_t, const char **);
static void		 members(struct html *, const ucl_object_t *,
			    const ucl_object_t *, const char **, int *);
static void		 set_block(struct html *, const char *, const char **,
			    int *);

static void
schema_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	app.schema_loading = false;
	if (status == 200 && o != NULL && jget(o, "ops") != NULL)
		app.schema = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	else
		app.schema_failed = true;
}

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

	if (app.yang == NULL && !app.yang_loading && !app.yang_failed) {
		app.yang_loading = true;
		api("GET", "/yang.json", NULL, yang_cb, NULL);
	}
	if (app.schema != NULL || app.schema_loading || app.schema_failed)
		return;
	app.schema_loading = true;
	api("GET", "/schema.json", NULL, schema_cb, NULL);
}

/* Operation op's YANG model, if it has been converted to one. */
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
 * The operation a trace is of: the client call it names, as
 * "libcblink arc_service_action()", is the operation service-action.
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
		    "arc_")) == NULL)
			continue;
		p += 4;
		for (i = 0; p[i] != '\0' && p[i] != '(' && i <
		    sizeof(name) - 1; i++)
			name[i] = p[i] == '_' ? '-' : p[i];
		name[i] = '\0';
		return (name);
	}
	return (NULL);
}

/*
 * A spec type in CDDL; *nestp is the attribute set it nests, if any.
 */
static const char *
cddl_type(const char *t, char *buf, size_t len, const char **nestp)
{
	static char	 nest[64];
	const char	*base;
	size_t		 n;
	bool		 multi;

	*nestp = NULL;
	n = strlen(t);
	multi = n > 2 && strcmp(t + n - 2, "[]") == 0;
	if (multi)
		n -= 2;
	if (strncmp(t, "nest ", 5) == 0) {
		snprintf(nest, sizeof(nest), "%.*s", (int)(n - 5), t + 5);
		*nestp = base = nest;
	} else if (strncmp(t, "text", 4) == 0)
		base = "tstr";
	else if (strncmp(t, "bytes", 5) == 0)
		base = "bstr";
	else if (t[0] == 'u' && t[1] >= '0' && t[1] <= '9')
		base = "uint";
	else if (t[0] == 's' && t[1] >= '0' && t[1] <= '9')
		base = "int";
	else if (strncmp(t, "flag", 4) == 0)
		base = "true";
	else if (strncmp(t, "float", 5) == 0)
		base = "float";
	else
		base = "bool";
	snprintf(buf, len, multi ? "[* %s]" : "%s", base);
	return (buf);
}

/*
 * The members of a map: every attribute of set when list is NULL, and
 * otherwise those list names, with "?" before the ones not required.
 * Sets they nest are added to seen, to be written after.
 */
static void
members(struct html *h, const ucl_object_t *set, const ucl_object_t *list,
    const char **seen, int *nseen)
{
	const ucl_object_t	*a, *m;
	ucl_object_iter_t	 it, it2;
	const char		*nest, *ck, *doc;
	char			 type[96], line[96];
	bool			 req;
	int			 i;

	it = NULL;
	while ((a = ucl_object_iterate(set, &it, true)) != NULL) {
		req = false;
		if (list != NULL) {
			it2 = NULL;
			while ((m = ucl_object_iterate(list, &it2, true)) != NULL)
				if (jstr(m, "name") != NULL && strcmp(jstr(m,
				    "name"), jstr(a, "name")) == 0)
					break;
			if (m == NULL)
				continue;
			req = jbool(m, "required");
		}
		cddl_type(jstr(a, "type"), type, sizeof(type), &nest);
		snprintf(line, sizeof(line), "  %s %2lld => %s,", req ? " " :
		    "?", (long long)jint(a, "id", 0), type);
		h_raw(h, "<span class=\"m\">");
		h_txt(h, line);
		h_raw(h, "</span>");
		for (i = (int)strlen(line); i < 28; i++)
			h_raw(h, " ");
		h_raw(h, " <span class=\"c\">; ");
		h_txt(h, jstr(a, "name"));
		if (list != NULL && m != NULL && jget(m, "sid") != NULL)
			h_fmt(h, " SID %lld", (long long)jint(m, "sid", 0));
		ck = jstr(a, "checks");
		if (ck != NULL && ck[0] != '\0') {
			h_raw(h, " (");
			h_txt(h, ck);
			h_raw(h, ")");
		}
		doc = jstr(a, "doc");
		if (doc != NULL && doc[0] != '\0') {
			h_raw(h, ": ");
			h_txt(h, doc);
		}
		h_raw(h, "</span>\n");
		if (nest == NULL)
			continue;
		for (i = 0; i < *nseen; i++)
			if (strcmp(seen[i], nest) == 0)
				break;
		if (i == *nseen && *nseen < MAX_SETS)
			seen[(*nseen)++] = strdup(nest);
	}
}

static void
set_block(struct html *h, const char *name, const char **seen, int *nseen)
{
	const ucl_object_t	*set;
	char			 key[96];

	snprintf(key, sizeof(key), "sets.%s", name);
	if ((set = jget(app.schema, key)) == NULL)
		return;
	h_raw(h, "<b>");
	h_txt(h, name);
	h_raw(h, "</b> = {\n");
	members(h, set, NULL, seen, nseen);
	h_raw(h, "}\n");
}

/* The schema of operation op, or of what is known of it. */
void
view_schema(struct html *h, const char *op)
{
	const ucl_object_t	*o, *set, *y;
	const char		*seen[MAX_SETS];
	char			 key[96];
	int			 nseen, i;

	/* Converted to YANG: the module beside the CBOR, a tab each. */
	if ((y = yang_of(op)) != NULL) {
		h_fmt(h, "<nav class=\"tabs schema-tabs\"><button class=\"tab%s\" "
		    "data-act=\"schema-tab\" data-arg=\"cbor\">CBOR</button>"
		    "<button class=\"tab%s\" data-act=\"schema-tab\" "
		    "data-arg=\"yang\">YANG</button></nav>", app.schema_yang ?
		    "" : " on", app.schema_yang ? " on" : "");
		if (app.schema_yang) {
			view_yang(h, y);
			return;
		}
	}
	h_raw(h, "<div class=\"schema\"><h4>CBOR schema");
	if (app.schema == NULL) {
		load_schema();
		h_raw(h, app.schema_failed ? "</h4><p class=\"dim\">The "
		    "console has no schema.json.</p></div>" :
		    "</h4><div class=\"loader\"></div></div>");
		return;
	}
	snprintf(key, sizeof(key), "ops.%s", op != NULL ? op : "");
	if (op == NULL || (o = jget(app.schema, key)) == NULL) {
		h_raw(h, "</h4><p class=\"dim\">This entry is not one "
		    "operation of the family.</p></div>");
		return;
	}
	h_raw(h, " <span class=\"dim\">");
	h_txt(h, jstr(app.schema, "family"));
	h_raw(h, " · ");
	h_txt(h, op);
	h_fmt(h, " · command %lld", (long long)jint(o, "cmd", 0));
	if (jget(o, "sid") != NULL)
		h_fmt(h, " · SID %lld", (long long)jint(o, "sid", 0));
	h_raw(h, "</span></h4>");
	if (jstr(o, "doc") != NULL && jstr(o, "doc")[0] != '\0') {
		h_raw(h, "<p class=\"dim\">");
		h_txt(h, jstr(o, "doc"));
		h_raw(h, "</p>");
	}
	snprintf(key, sizeof(key), "sets.%s", jstr(o, "set") != NULL ?
	    jstr(o, "set") : "");
	set = jget(app.schema, key);
	nseen = 0;
	h_raw(h, "<pre class=\"cddl\"><b>request</b> = {\n");
	members(h, set, jget(o, "request"), seen, &nseen);
	h_raw(h, "}\n<b>reply</b> = {\n");
	members(h, set, jget(o, "reply"), seen, &nseen);
	h_raw(h, "}\n");
	/* The sets nested, and those they nest in turn. */
	for (i = 0; i < nseen; i++)
		set_block(h, seen[i], seen, &nseen);
	h_raw(h, "</pre><p class=\"dim note\">A message is a CBOR map keyed "
	    "by SID (RFC 9254): the rpc's input or output at the top, each "
	    "member by its own, the number at the left its place in the set; "
	    "? marks what may be absent.</p></div>");
	for (i = 0; i < nseen; i++)
		free((void *)(uintptr_t)seen[i]);
}
