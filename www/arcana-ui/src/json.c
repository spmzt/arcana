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
