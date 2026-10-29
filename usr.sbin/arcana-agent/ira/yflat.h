/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YFLAT_H_
#define	_ARCANA_YFLAT_H_

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

/*
 * A read's JSON, as the operation of arcana.yaml it was gave it, and its
 * module's struct, by the schema tables (yflat.c): the agent's and the
 * console's, for the modules whose nodes are named as the JSON's keys
 * are, '-' for '_', names saying where they differ (yflat.c's rules).
 * A container is an object, a list an array of objects; a
 * yang:date-and-time is the JSON's seconds of the epoch, an enumeration
 * its name, a decimal64 a number.  What either has and the other does
 * not is left out.
 *
 * yflat_find(): the node path names in module mod of schema s, its
 * names by '/' from the top ("crashes/read/output"); NULL: none.
 * yflat_in(): o into p, n's struct (a container's, an input's or an
 * output's), its strings a's; 0 or ENOMEM.  yflat_out(): p as JSON.
 */
const struct cbl_ynode *yflat_find(const struct cbl_yschema *s,
	    const char *mod, const char *path);
int	yflat_in(const struct cbl_ynode *n, const ucl_object_t *o, void *p,
	    cbl_yarena *a, const char *const *names);
ucl_object_t *yflat_out(const struct cbl_ynode *n, const void *p,
	    const char *const *names);

#endif	/* !_ARCANA_YFLAT_H_ */
