/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YPROBES_H_
#define	_ARCANA_YPROBES_H_

#include <stdint.h>

#include <cblink.h>

/*
 * An edge's SD-WAN targets and links in arcana-probe's candidate over
 * conn (yprobes.c, the console's and arcanactl's): json as the
 * sdwan-probes operation took it, an array the host's targets, or
 * {"jail", "targets", "links"}, in place of that edge's lists, the
 * other edges and the monitors as running has them.  0, or an errno,
 * err (the agent's words), *errsid (the node at fault) and tag (an
 * error-app-tag); the candidate is then to be committed.
 */
int	yprobes_edit(cbl_conn *conn, const char *json, char *err,
	    size_t errlen, uint64_t *errsid, char *tag, size_t taglen);

#endif	/* !_ARCANA_YPROBES_H_ */
