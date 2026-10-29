/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YPLUG_H_
#define	_ARCANA_YPLUG_H_

#include <stdbool.h>
#include <stdint.h>

#include <cblink.h>
#include <ucl.h>

/*
 * What the plugins' programs say, through their modules over conn
 * (yplug.c), as the network operation's kind (ARC_NET_KIND_*) had it,
 * the host's or the vnet jail's (jail NULL or ""), filter the kind's
 * (birdc's words): netgraph {"nodes"}, wireguard {"interfaces",
 * "now"}, bird {"status", "protocols", "ospf", "bfd", "tables"},
 * bird-routes {"routes", "count"}, bird-ospf {"protocols"}.  *data the
 * JSON; or an errno
 * and err says why (the agent's words).  yplug_kind: whether kind is
 * one of them, read so and not by the network operation.
 */
bool	yplug_kind(int kind);
int	yplug_net(cbl_conn *conn, int kind, const char *jail,
	    const char *filter, ucl_object_t **data, char *err, size_t errlen);

/*
 * BIRD's configuration, the host's or the jail's, as the bird-config
 * operation answered, path, text, sha256, files (and confirm_by) put in
 * top: without text the file of path (none: the main one) read from
 * running; with text, made from the file whose SHA-256 is sha256, put
 * in its place by a commit (with safe a confirmed one left waiting
 * wait s, 0 a minute, for a confirm of host's), or with check only
 * parsed;
 * confirm, the change that waits confirmed.  0, or an errno and err
 * says why.
 */
int	yplug_bird_config(cbl_conn *conn, const char *host, const char *jail,
	    const char *path, const char *text, const char *sha256, bool check,
	    bool safe, int wait, bool confirm, ucl_object_t *top, char *err,
	    size_t errlen);

#endif	/* !_ARCANA_YPLUG_H_ */
