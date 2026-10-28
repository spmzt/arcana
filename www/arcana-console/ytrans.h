/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YTRANS_H_
#define	_ARCANA_YTRANS_H_

#include <stdbool.h>
#include <stdint.h>

#include <cblink.h>
#include <ucl.h>

/*
 * The Network tab's interfaces, {"interfaces": [...], "time": ms}, from
 * a GET of the standard models over conn (ytrans.c): addresses of IPv4
 * with v4, of IPv6 with v6.  0, or an errno and err says why.
 */
int	ytrans_interfaces(cbl_conn *conn, bool v4, bool v6,
	    ucl_object_t **out, char *err, size_t errlen);
/*
 * The top-level nodes named, by commas (none: all of them), as RFC
 * 7951's JSON, one object, from a GET of the agent's models over conn.
 * 0, or an errno and err says why.
 */
int	ytrans_data(cbl_conn *conn, const char *names, ucl_object_t **out,
	    char *err, size_t errlen);
/* The same of the nodes by SID (none: all), what xpath selects of them
 * when it is not NULL; refused, the node at fault's SID in *errsid (0:
 * none said) when errsid is not NULL. */
int	ytrans_get(cbl_conn *conn, const uint64_t *sids, size_t ns,
	    const char *xpath, ucl_object_t **out, char *err, size_t errlen,
	    uint64_t *errsid);
/* The same of datastore ds (CBL_YDS_*; -1, none said: the agent's
 * default). */
int	ytrans_get_ds(cbl_conn *conn, const uint64_t *sids, size_t ns,
	    const char *xpath, int ds, ucl_object_t **out, char *err,
	    size_t errlen, uint64_t *errsid);

#include "yjsonin.h"

#endif	/* !_ARCANA_YTRANS_H_ */
