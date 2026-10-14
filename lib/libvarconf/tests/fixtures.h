/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* The fixtures, compiled in (tests/Makefile makes fixtures.c). */

struct fixture {
	const char	*name;
	const char	*text;
	size_t		 len;
};

extern const struct fixture fixtures[];
