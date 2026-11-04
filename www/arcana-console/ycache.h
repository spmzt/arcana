/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YCACHE_H_
#define	_ARCANA_YCACHE_H_

#include <stdbool.h>
#include <stddef.h>

#include <cblink.h>

/*
 * Each host's schema as its agent has it (ycache.c, PLAN-SDN-YANG
 * 4.3.1, 4.3.2): the modules of its YANG library and their SIDs (its
 * GET-SID's .sid files, struct ysids), kept by the agent's URI.
 *
 * ycache_get(): the host's, read over conn where none is kept or where
 * the kept one is to be checked (its library's content-id read again,
 * its SIDs again only where that changed); NULL and why where its agent
 * gives none.  ycache_peek(): the one kept, never read.  Each one given
 * is the caller's until ycache_put().  ycache_stale(): the host's to be
 * checked at its next use, as when a new connection reaches its agent
 * (it may be another program now) or it says its library changed
 * (yang-library-update).  ycache_reads(): how many times the SIDs were
 * read, of every host.
 */
struct yview;
struct ysids;

struct yview	*ycache_get(cbl_conn *conn, const char *uri, char *why,
		    size_t whylen);
struct yview	*ycache_peek(const char *uri);
void		 ycache_put(struct yview *v);
void		 ycache_stale(const char *uri);
const struct ysids *yview_sids(const struct yview *v);
unsigned	 ycache_reads(void);

#endif	/* !_ARCANA_YCACHE_H_ */
