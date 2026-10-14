/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The YANG collectors (PLAN-SDN-YANG 1.9, 1.10): the host's state as the
 * IETF modules model it, into the structs cblink-gen made of them
 * (ymodel.h, ymodel_schema.c, from share/yang).  What a collector
 * allocates is the arena's.  0, or an errno.
 */

#ifndef _ARCANA_COLLECT_H_
#define	_ARCANA_COLLECT_H_

#include "ymodel.h"

/*
 * ietf-interfaces (RFC 8343): /interfaces, operational (invidia/yif.c),
 * with the modules that augment it: arcana-interfaces, ietf-ip.
 */
int	yif_interfaces(struct ietf_interfaces *data, cbl_yarena *a);

/* ietf-ip (RFC 8344): the n interfaces' ipv4 and ipv6 (invidia/yip.c). */
int	yip_interfaces(struct ietf_interfaces_interfaces_interface *v,
	    size_t n, cbl_yarena *a);

#endif /* !_ARCANA_COLLECT_H_ */
