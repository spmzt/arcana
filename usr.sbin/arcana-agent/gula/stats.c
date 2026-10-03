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

#include "agent.h"

int
do_stats(struct work *w, struct arc_stats_rsp *rsp)
{
	struct arc_stats	*st;

	rsp->has_ok = true;
	rsp->ok = true;
	st = wcalloc(w, 1, sizeof(*st));
	rsp->stats = st;
	resources_measure(w, st);
	pools_measure(w, st);
	return (0);
}
