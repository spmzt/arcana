/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: how the host is doing, observed.  The figures are Avaritia's
 * (CPU, memory, swap) and Acedia's (the pools); this gathers them.
 */

#include <sys/types.h>

#include <string.h>

#include "agent.h"

void
do_stats(struct work *w, struct host_stats *st)
{

	memset(st, 0, sizeof(*st));
	resources_measure(w, st);
	pools_measure(w, st);
}
