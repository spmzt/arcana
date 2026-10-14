/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An operation's JSON object read back into a YANG module's structs:
 * what the converters of the operations that answer in JSON share
 * (ystorage.c, ysystem.c).
 */

#include <errno.h>
#include <string.h>

#include "yjson.h"

/* json parsed; NULL: not JSON. */
ucl_object_t *
yj_parse(const char *json)
{
	struct ucl_parser *p;
	ucl_object_t *top = NULL;

	if (json == NULL || (p = ucl_parser_new(UCL_PARSER_NO_TIME)) == NULL)
		return (NULL);
	if (ucl_parser_add_string(p, json, 0))
		top = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (top);
}

/* A string of o's, the arena's; NULL: none. */
const char *
yj_str(cbl_yarena *a, const ucl_object_t *o, const char *key)
{
	const ucl_object_t *v = ucl_object_lookup(o, key);
	const char *t;
	size_t len;
	char *p;

	if (v == NULL || ucl_object_type(v) != UCL_STRING ||
	    (t = ucl_object_tostring(v)) == NULL)
		return (NULL);
	len = strlen(t) + 1;
	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, t, len);
	return (p);
}

/* A number of o's; false: none. */
bool
yj_num(const ucl_object_t *o, const char *key, int64_t *v)
{
	const ucl_object_t *x = ucl_object_lookup(o, key);

	if (x == NULL || (ucl_object_type(x) != UCL_INT &&
	    ucl_object_type(x) != UCL_FLOAT))
		return (false);
	*v = ucl_object_toint(x);
	return (true);
}

/* true, "yes", "on": true; false, "no", "off": false; else none. */
bool
yj_yes(const ucl_object_t *o, const char *key, bool *has)
{
	const ucl_object_t *x = ucl_object_lookup(o, key);
	const char *t;

	*has = false;
	if (x == NULL)
		return (false);
	if (ucl_object_type(x) == UCL_BOOLEAN) {
		*has = true;
		return (ucl_object_toboolean(x));
	}
	if ((t = ucl_object_tostring(x)) == NULL)
		return (false);
	if (strcmp(t, "yes") == 0 || strcmp(t, "on") == 0) {
		*has = true;
		return (true);
	}
	if (strcmp(t, "no") == 0 || strcmp(t, "off") == 0)
		*has = true;
	return (false);
}

size_t
yj_count(const ucl_object_t *arr)
{

	return (arr != NULL && ucl_object_type(arr) == UCL_ARRAY ?
	    arr->len : 0);
}

/* An array of strings, the arena's. */
int
yj_strs(cbl_yarena *a, const ucl_object_t *arr, size_t *n,
    const char *const **v)
{
	const ucl_object_t *e;
	ucl_object_iter_t it;
	const char **p;
	size_t k = 0;

	*n = 0;
	*v = NULL;
	if (yj_count(arr) == 0)
		return (0);
	if ((p = cbl_yarena_alloc(a, yj_count(arr) * sizeof(*p))) == NULL)
		return (ENOMEM);
	YJ_EACH(arr, it, e) {
		const char *t;
		size_t len;
		char *c;

		if ((t = ucl_object_tostring(e)) == NULL)
			continue;
		len = strlen(t) + 1;
		if ((c = cbl_yarena_alloc(a, len)) == NULL)
			return (ENOMEM);
		memcpy(c, t, len);
		p[k++] = c;
	}
	*n = k;
	*v = p;
	return (0);
}
