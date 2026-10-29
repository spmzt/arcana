/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YNET_H_
#define	_ARCANA_YNET_H_

#include <stdbool.h>
#include <stdint.h>

#include <cblink.h>
#include <ucl.h>

/*
 * The network tables through arcana-network's read actions over conn
 * (ynet.c), as the network operation's kind (ARC_NET_KIND_*) had them,
 * the host's or a vnet jail's (jail NULL or ""): *data the JSON, and
 * for the routes *total and *truncated; the ipfw kind arcana-firewall's
 * state (the host's, or the jail's by arcana-jails).  ynet_kind():
 * whether kind is read so.  0, or an errno and err says why.
 */
bool	ynet_kind(int kind);
int	ynet_read(cbl_conn *conn, int kind, int family, const char *filter,
	    uint32_t fib, uint32_t offset, const char *jail, ucl_object_t **data,
	    uint64_t *total, bool *has_total, bool *truncated, char *err,
	    size_t errlen);
/* The route to address, and the routes that cover it (lookup). */
int	ynet_lookup(cbl_conn *conn, const char *address, uint32_t fib,
	    const char *jail, ucl_object_t **data, char *err, size_t errlen);
/* An address of a jail, by arcana-jails' address action: *diff, malloc'd. */
int	ynet_address(cbl_conn *conn, const char *jail, const char *address,
	    const char *ifname, bool remove, bool live, bool persist,
	    bool dry_run, char **diff, char *err, size_t errlen);

/*
 * The kept rules of the firewall, the host's or a vnet jail's, as the
 * ipfw-rules operation answered, "text", "sha256" (and "rc_file") put
 * in top: read from arcana-firewall; with from_rc, its from-rc action
 * (the migration's dry run); with text, made from the file whose
 * SHA-256 is sha256, checked by its check action (check), or put in
 * place by a commit, confirmed at once, the warnings acc (nacc) accepted
 * (tag the one to accept where refused), "migrated" what a host's first
 * commit moved its boot from.
 */
int	ynet_rules(cbl_conn *conn, const char *jail, bool from_rc,
	    const char *text, const char *sha256, bool check,
	    const char *const *acc, size_t nacc, ucl_object_t *top, char *err,
	    size_t errlen, char *tag, size_t taglen);

/*
 * The routes, connections and sockets in parts: the agent's own family
 * and its network-parts stream, every message arcana-network's
 * network-part structure; ynet_part_json(), a part as plain JSON, its
 * rows as the tools wrote them (NULL: no memory).
 */
#define	YNET_PARTS_FAMILY	"arcana-parts"
#define	YNET_PARTS_NETWORK	1
struct arcana_network_network_part;
ucl_object_t *ynet_part_json(const struct arcana_network_network_part *p);

#endif	/* !_ARCANA_YNET_H_ */
