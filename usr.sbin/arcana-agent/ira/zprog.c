/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An arcana-agent compressed for agent-update, and inflated where it
 * arrives: a frame carries max-binary bytes, the program grows past
 * them, and gzip -9 takes it to a quarter.  Inflating is bounded by the
 * size the sender gave, itself bounded by the caller's limit: what
 * would inflate past it is refused once a byte more has come out.
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "zprog.h"

/* deflateInit2(3)'s and inflateInit2(3)'s window: 32 KB, gzip's header. */
#define	ZPROG_WBITS	(15 + 16)

bool
zprog_taken(const char *const *v, size_t n)
{
	size_t	i;

	for (i = 0; i < n; i++)
		if (strcmp(v[i], ZPROG_FEATURE) == 0)
			return (true);
	return (false);
}

int
zprog_deflate(const void *in, size_t len, uint8_t **outp, size_t *outlenp)
{
	z_stream	 z = { 0 };
	uint8_t		*out;
	uLong		 bound;
	int		 rc;

	if (len == 0 || len > UINT_MAX)
		return (EINVAL);
	if (deflateInit2(&z, Z_BEST_COMPRESSION, Z_DEFLATED, ZPROG_WBITS, 9,
	    Z_DEFAULT_STRATEGY) != Z_OK)
		return (ENOMEM);
	bound = deflateBound(&z, (uLong)len);
	if (bound > UINT_MAX || (out = malloc(bound)) == NULL) {
		(void)deflateEnd(&z);
		return (ENOMEM);
	}
	z.next_in = (Bytef *)(uintptr_t)in;
	z.avail_in = (uInt)len;
	z.next_out = out;
	z.avail_out = (uInt)bound;
	rc = deflate(&z, Z_FINISH);
	*outlenp = z.total_out;
	(void)deflateEnd(&z);
	if (rc != Z_STREAM_END) {
		free(out);
		return (EIO);
	}
	*outp = out;
	return (0);
}

const char *
zprog_inflate(const void *in, size_t len, size_t size, size_t max,
    uint8_t **outp)
{
	z_stream	 z = { 0 };
	uint8_t		*out;
	const char	*why;
	int		 rc;

	if (size == 0 || size > max || size >= UINT_MAX)
		return ("the program would inflate past what this host takes");
	if (len == 0 || len > UINT_MAX)
		return ("the compressed program is empty");
	/* A byte more than size: one that comes out is refused. */
	if ((out = malloc(size + 1)) == NULL)
		return ("no memory for the program inflated");
	if (inflateInit2(&z, ZPROG_WBITS) != Z_OK) {
		free(out);
		return ("no memory to inflate the program");
	}
	z.next_in = (Bytef *)(uintptr_t)in;
	z.avail_in = (uInt)len;
	z.next_out = out;
	z.avail_out = (uInt)(size + 1);
	rc = inflate(&z, Z_FINISH);
	if (z.total_out > size)
		why = "the program inflates past the size it came with";
	else if (rc != Z_STREAM_END)
		why = rc == Z_DATA_ERROR || rc == Z_NEED_DICT ?
		    "the compressed program is not gzip" :
		    "the compressed program ends short";
	else if (z.avail_in != 0)
		why = "the compressed program has bytes past its end";
	else if (z.total_out != size)
		why = "the program inflates short of the size it came with";
	else
		why = NULL;
	(void)inflateEnd(&z);
	if (why != NULL) {
		free(out);
		return (why);
	}
	*outp = out;
	return (NULL);
}
