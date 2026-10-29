/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: the files jails are made with, as YANG, arcana-jail-files (an
 * augment of arcana-jails): the jail-files operation's JSON
 * (jailmake.c) read back.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

int
yjf_from_json(const char *json, cbl_yarena *a,
    struct arcana_jails_jails_arcjf_read_files_output *out)
{
	struct arcana_jails_jails_arcjf_read_files_output_defaults	*d;
	struct arcana_jails_jails_arcjf_read_files_output_template	*t;
	struct arcana_jails_jails_arcjf_read_files_output_jail	*j;
	const ucl_object_t				*e, *o;
	ucl_object_iter_t				 it;
	ucl_object_t					*top;
	size_t						 k;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->directory = yj_str(a, top, "dir");
	if ((o = ucl_object_lookup(top, "defaults")) != NULL) {
		if ((d = cbl_yarena_alloc(a, sizeof(*d))) == NULL) {
			ucl_object_unref(top);
			return (ENOMEM);
		}
		d->path = yj_str(a, o, "path");
		d->text = yj_str(a, o, "text");
		out->defaults = d;
	}
	if ((t = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "templates")) + 1) * sizeof(*t))) == NULL || (j = cbl_yarena_alloc(
	    a, (yj_count(ucl_object_lookup(top, "jails")) + 1) * sizeof(*j)))
	    == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "templates"), it, e) {
		if ((t[k].name = yj_str(a, e, "name")) == NULL)
			continue;
		t[k].text = yj_str(a, e, "text");
		k++;
	}
	out->template.n = k;
	out->template.v = t;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "jails"), it, e) {
		if ((j[k].name = yj_str(a, e, "name")) == NULL)
			continue;
		j[k].text = yj_str(a, e, "text");
		k++;
	}
	out->jail.n = k;
	out->jail.v = j;
	ucl_object_unref(top);
	return (0);
}
