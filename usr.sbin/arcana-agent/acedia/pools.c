/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Acedia: what holds the host's data.  The ZFS pools, from zpool(8).
 */

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/sysctl.h>

#include <err.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"

/* "zpool list -Hp": name size alloc free health, tab separated. */
void
pools_measure(struct work *w, struct host_stats *st)
{
	struct host_pool	*v;
	struct execres	 res;
	char		*argv[6], *copy, *line, *it, *f[5];
	size_t		 n, i;

	argv[0] = (char *)(uintptr_t)opts.zpool_bin;
	argv[1] = (char *)(uintptr_t)"list";
	argv[2] = (char *)(uintptr_t)"-Hp";
	argv[3] = (char *)(uintptr_t)"-o";
	argv[4] = (char *)(uintptr_t)"name,size,alloc,free,health";
	argv[5] = NULL;
	if (access(opts.zpool_bin, X_OK) == -1 ||
	    run_exec(w, argv, &res) != 0)
		return;
	v = NULL;
	n = 0;
	copy = wstrndup(w, res.out, res.outlen);
	for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
		for (i = 0; i < 5; i++)
			if ((f[i] = strsep(&line, "\t")) == NULL)
				break;
		if (i < 5)
			continue;
		if ((v = reallocarray(v, n + 1, sizeof(*v))) == NULL)
			err(1, "reallocarray");
		memset(&v[n], 0, sizeof(v[n]));
		v[n].name = wtext(w, f[0]);
		v[n].has_size = v[n].has_alloc = v[n].has_free = true;
		v[n].size = strtoull(f[1], NULL, 10);
		v[n].alloc = strtoull(f[2], NULL, 10);
		v[n].free = strtoull(f[3], NULL, 10);
		v[n].health = wtext(w, f[4]);
		n++;
	}
	st->pools.v = wadopt(w, v);
	st->pools.n = n;
}
