/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An operation's JSON object read back into a YANG module's structs
 * (yjson.c): its strings copied into the arena, its numbers, its "yes"
 * and "on", its arrays.
 */

#ifndef _ARCANA_YJSON_H_
#define	_ARCANA_YJSON_H_

#include <stdbool.h>
#include <stdint.h>

#include <ucl.h>

#include "cbl_schema.h"

ucl_object_t	*yj_parse(const char *json);
const char	*yj_str(cbl_yarena *a, const ucl_object_t *o, const char *key);
bool		 yj_num(const ucl_object_t *o, const char *key, int64_t *v);
bool		 yj_yes(const ucl_object_t *o, const char *key, bool *has);
size_t		 yj_count(const ucl_object_t *arr);
int		 yj_strs(cbl_yarena *a, const ucl_object_t *arr, size_t *n,
		    const char *const **v);

/* A number of o's into y's member f and its has_f. */
#define	YJ_NUM(o, key, y, f)	do {					\
	int64_t v_;							\
									\
	if (((y)->has_##f = yj_num((o), (key), &v_)))			\
		(y)->f = (__typeof__((y)->f))v_;			\
} while (0)

#define	YJ_EACH(arr, it, e)						\
	for ((it) = NULL; ((e) = ucl_object_iterate((arr), &(it),	\
	    true)) != NULL;)

#endif /* !_ARCANA_YJSON_H_ */
