/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* When each route last changed, as route events tell it (rtimes.c). */

#ifndef _ARCANA_RTIMES_H_
#define	_ARCANA_RTIMES_H_

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

struct sockaddr;

void	rt_prefix(char *buf, size_t len, const struct sockaddr *dst, int af,
	    uint8_t plen);
void	rt_touched(uint32_t fib, const char *prefix, time_t when, bool gone);
bool	rt_last(uint32_t fib, const char *prefix, time_t *when);

#endif /* !_ARCANA_RTIMES_H_ */
