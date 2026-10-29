/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ZPROG_H_
#define	_ZPROG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * An arcana-agent as agent-update carries it compressed: gzip (RFC
 * 1952), by the base system's zlib.  The agent, the console and
 * arcanactl build the same file.
 */

/* What arcana-host's agent feature names for it. */
#define	ZPROG_FEATURE	"gzip-update"

/*
 * The most bytes of program an update carries, compressed or not: an
 * agent's frame is 8 MiB, the rest of the request well within the
 * 64 KiB left.  An agent without ZPROG_FEATURE takes the program as it
 * is, so no bigger.  The most a compressed one inflates to.
 */
#define	ZPROG_MAX_BINARY	(8 * 1024 * 1024 - 64 * 1024)
#define	ZPROG_MAX_PROGRAM	(32 * 1024 * 1024)

/* Whether the n features of a host's agent have ZPROG_FEATURE. */
bool		 zprog_taken(const char *const *v, size_t n);

/* len bytes of in compressed into *outp (malloc(3)): 0, or an errno. */
int		 zprog_deflate(const void *in, size_t len, uint8_t **outp,
		    size_t *outlenp);

/*
 * len bytes of in inflated into *outp (malloc(3)), which has to come
 * to size bytes, no more than max: NULL, or why not.  It stops a byte
 * past size.
 */
const char	*zprog_inflate(const void *in, size_t len, size_t size,
		    size_t max, uint8_t **outp);

#endif /* !_ZPROG_H_ */
