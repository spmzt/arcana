/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * JSON with libucl, the same library the console and arcana-agent use,
 * compiled here from the base system's sources.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

ucl_object_t *
json_parse(const char *s)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	if (s == NULL || *s == '\0')
		return (NULL);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_string(p, s, 0))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

/* "a.b.0.c" */
const ucl_object_t *
jget(const ucl_object_t *o, const char *path)
{

	if (o == NULL)
		return (NULL);
	return (ucl_object_lookup_path(o, path));
}

/* A string, or NULL for anything else (null included). */
const char *
jstr(const ucl_object_t *o, const char *path)
{
	const ucl_object_t	*v;

	if ((v = jget(o, path)) == NULL || ucl_object_type(v) != UCL_STRING)
		return (NULL);
	return (ucl_object_tostring(v));
}

int64_t
jint(const ucl_object_t *o, const char *path, int64_t def)
{
	const ucl_object_t	*v;
	const char		*s;
	char			*end;
	int64_t			 i;

	if ((v = jget(o, path)) == NULL)
		return (def);
	/* RFC 7951's 64-bit integers are strings. */
	if (ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		i = strtoll(s, &end, 10);
		return (s[0] != '\0' && *end == '\0' ? i : def);
	}
	if (!ucl_object_toint_safe(v, &i))
		return (def);
	return (i);
}

double
jnum(const ucl_object_t *o, const char *path, double def)
{
	const ucl_object_t	*v;
	const char		*s;
	char			*end;
	double			 d;

	if ((v = jget(o, path)) == NULL)
		return (def);
	/* RFC 7951's 64-bit integers and decimal64 are strings. */
	if (ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		d = strtod(s, &end);
		return (s[0] != '\0' && *end == '\0' ? d : def);
	}
	if (!ucl_object_todouble_safe(v, &d))
		return (def);
	return (d);
}

bool
jbool(const ucl_object_t *o, const char *path)
{
	const ucl_object_t	*v;

	return ((v = jget(o, path)) != NULL &&
	    ucl_object_type(v) == UCL_BOOLEAN && ucl_object_toboolean(v));
}

/*
 * A YANG node's members as a screen names them: map is pairs of a
 * path in o ("state.run-state") and the name it gets, NULL ended; the
 * members it does not name are left out.
 */
ucl_object_t *
jmap(const ucl_object_t *o, const char *const *map)
{
	const ucl_object_t	*v;
	ucl_object_t		*r;

	r = ucl_object_typed_new(UCL_OBJECT);
	for (; map[0] != NULL; map += 2)
		if ((v = jget(o, map[0])) != NULL)
			ucl_object_insert_key(r, ucl_object_copy(v), map[1], 0,
			    true);
	return (r);
}

/* The same of each entry of a list, as an array. */
ucl_object_t *
jmap_each(const ucl_object_t *list, const char *const *map)
{
	const ucl_object_t	*e;
	ucl_object_t		*r;
	ucl_object_iter_t	 it = NULL;

	r = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(list, &it, true)) != NULL)
		ucl_array_append(r, jmap(e, map));
	return (r);
}

/*
 * A read's YANG JSON with the names a screen reads it by: each member's
 * - as _, but where names (NULL ended) says otherwise of a node's name:
 *	node=key	its key is key
 *	node{k}		a list as an object keyed by its entries' k, each
 *			value its entry's one other node, or its others
 *	node[a,b]	a list as an array of arrays of a's and b's values
 *	node^		a container's members are its parent's
 * as "node{k}=key".
 */
static const char *
jflat_rule(const char *const *names, const char *node, char *key, size_t
    klen, char *list, size_t llen, char *how)
{
	const char	*r, *p;
	size_t		 n;

	*how = '\0';
	list[0] = '\0';
	snprintf(key, klen, "%s", node);
	for (p = key; (p = strchr(p, '-')) != NULL; p++)
		key[p - key] = '_';
	for (; names != NULL && *names != NULL; names++) {
		r = *names;
		n = strcspn(r, "{[^=");
		if (strlen(node) != n || strncmp(node, r, n) != 0)
			continue;
		r += n;
		if (*r == '{' || *r == '[') {
			*how = *r;
			n = strcspn(r + 1, "}]");
			snprintf(list, llen, "%.*s", (int)n, r + 1);
			r += n + 2;
		}
		if (*r == '^')
			*how = *r++;
		if (*r == '=')
			snprintf(key, klen, "%s", r + 1);
		return (*names);
	}
	return (NULL);
}

static ucl_object_t *jflat_v(const ucl_object_t *, const char *const *);

/* The members of o into r, flattened. */
static void
jflat_into(ucl_object_t *r, const ucl_object_t *o, const char *const *names)
{
	const ucl_object_t	*v, *e, *m;
	ucl_object_t		*x, *t;
	ucl_object_iter_t	 it = NULL, eit, mit;
	const char		*node, *c;
	char			 key[128], list[128], how, *w, *ws;
	size_t			 others;

	while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
		node = ucl_object_key(v);
		if ((c = strchr(node, ':')) != NULL)
			node = c + 1;
		jflat_rule(names, node, key, sizeof(key), list, sizeof(list),
		    &how);
		if (how == '^' && ucl_object_type(v) == UCL_OBJECT) {
			jflat_into(r, v, names);
			continue;
		}
		if (how == '{') {
			x = ucl_object_typed_new(UCL_OBJECT);
			eit = NULL;
			while ((e = ucl_object_iterate(v, &eit, true)) != NULL) {
				if ((m = ucl_object_lookup(e, list)) == NULL)
					continue;
				t = ucl_object_typed_new(UCL_OBJECT);
				jflat_into(t, e, names);
				ucl_object_delete_key(t, list);
				others = t->len;
				mit = NULL;
				if (others == 1 && (m = ucl_object_iterate(t, &mit,
				    true)) != NULL) {
					ucl_object_insert_key(x, ucl_object_copy(m),
					    ucl_object_tostring_forced(ucl_object_lookup(
					    e, list)), 0, true);
					ucl_object_unref(t);
				} else
					ucl_object_insert_key(x, t,
					    ucl_object_tostring_forced(ucl_object_lookup(
					    e, list)), 0, true);
			}
		} else if (how == '[') {
			x = ucl_object_typed_new(UCL_ARRAY);
			eit = NULL;
			while ((e = ucl_object_iterate(v, &eit, true)) != NULL) {
				t = ucl_object_typed_new(UCL_ARRAY);
				if ((ws = strdup(list)) == NULL)
					abort();
				for (c = ws; (w = strsep(&ws, ",")) != NULL;)
					ucl_array_append(t, ucl_object_lookup(e,
					    w) != NULL ? ucl_object_copy(
					    ucl_object_lookup(e, w)) :
					    ucl_object_typed_new(UCL_NULL));
				free((void *)(uintptr_t)c);
				ucl_array_append(x, t);
			}
		} else
			x = jflat_v(v, names);
		ucl_object_replace_key(r, x, key, 0, true);
	}
}

static ucl_object_t *
jflat_v(const ucl_object_t *v, const char *const *names)
{
	const ucl_object_t	*e;
	ucl_object_t		*x;
	ucl_object_iter_t	 it = NULL;

	if (ucl_object_type(v) == UCL_OBJECT) {
		x = ucl_object_typed_new(UCL_OBJECT);
		jflat_into(x, v, names);
		return (x);
	}
	if (ucl_object_type(v) != UCL_ARRAY)
		return (ucl_object_copy(v));
	x = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		ucl_array_append(x, jflat_v(e, names));
	return (x);
}

ucl_object_t *
jflat(const ucl_object_t *o, const char *const *names)
{

	return (jflat_v(o, names));
}

/* s as a JSON string literal, quotes included; free() it. */
char *
json_quote(const char *s)
{
	ucl_object_t	*o;
	char		*q;

	o = ucl_object_fromstring(s != NULL ? s : "");
	q = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	return (q);
}
