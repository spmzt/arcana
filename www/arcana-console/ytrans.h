/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YTRANS_H_
#define	_ARCANA_YTRANS_H_

#include <stdbool.h>

#include <cblink.h>
#include <ucl.h>

/*
 * The Network tab's interfaces, {"interfaces": [...], "time": ms}, from
 * a GET of the standard models over conn (ytrans.c): addresses of IPv4
 * with v4, of IPv6 with v6.  0, or an errno and err says why.
 */
int	ytrans_interfaces(cbl_conn *conn, bool v4, bool v6,
	    ucl_object_t **out, char *err, size_t errlen);

#endif	/* !_ARCANA_YTRANS_H_ */
