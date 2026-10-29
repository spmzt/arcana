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

/* What hello's features name for it, and the first agent with it. */
#define	ZPROG_FEATURE	"gzip-update"
#define	ZPROG_SINCE	"0.235.0"

/* Whether the n features of a hello's host have ZPROG_FEATURE. */
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
