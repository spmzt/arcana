/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Avaritia: the finite resources of the host and how much of each is
 * taken.  CPU from kern.cp_time between two samples, memory from the
 * vm.stats counters, swap from swapinfo(8).  The CPU figure is since
 * the previous request, whoever made it; the first one samples twice,
 * 200 ms apart.
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

static pthread_mutex_t	cpu_lock = PTHREAD_MUTEX_INITIALIZER;
static long		cpu_last[CPUSTATES];
static bool		cpu_have;

static int	cp_time(long *);
static uint64_t	vmstat(const char *);
static double	cpu_pct(struct work *);
static void	swap(struct work *, struct host_stats *);

static int
cp_time(long *v)
{
	size_t	len;

	len = sizeof(long) * CPUSTATES;
	return (sysctlbyname("kern.cp_time", v, &len, NULL, 0));
}

static uint64_t
vmstat(const char *name)
{
	unsigned int	v;
	size_t		len;

	len = sizeof(v);
	if (sysctlbyname(name, &v, &len, NULL, 0) == -1)
		return (0);
	return (v);
}

/* Busy time share since the last call, over all CPUs. */
static double
cpu_pct(struct work *w)
{
	long	now[CPUSTATES], total, idle;
	int	i, step;

	step = step_begin(w, ARC_STEP_KIND_LIB, "sysctlbyname(3)",
	    "kern.cp_time, against the previous sample");
	pthread_mutex_lock(&cpu_lock);
	if (!cpu_have) {
		if (cp_time(cpu_last) == 0) {
			cpu_have = true;
			usleep(200000);
		}
	}
	if (!cpu_have || cp_time(now) == -1) {
		pthread_mutex_unlock(&cpu_lock);
		step_end(w, step, false, "kern.cp_time unavailable");
		return (0);
	}
	total = idle = 0;
	for (i = 0; i < CPUSTATES; i++) {
		total += now[i] - cpu_last[i];
		if (i == CP_IDLE)
			idle = now[i] - cpu_last[i];
	}
	memcpy(cpu_last, now, sizeof(now));
	pthread_mutex_unlock(&cpu_lock);
	step_end(w, step, true, "%ld ticks, %ld idle", total, idle);
	return (total > 0 ? 100.0 * (double)(total - idle) / (double)total :
	    0);
}

/* "swapinfo -k": the Total line, or the one device. */
static void
swap(struct work *w, struct host_stats *st)
{
	struct execres	 res;
	char		*argv[3], *copy, *line, *it, *dev, *size, *used;
	uint64_t	 total, inuse;

	argv[0] = (char *)(uintptr_t)opts.swapinfo_bin;
	argv[1] = (char *)(uintptr_t)"-k";
	argv[2] = NULL;
	if (run_exec(w, argv, &res) != 0)
		return;
	total = inuse = 0;
	copy = wstrndup(w, res.out, res.outlen);
	for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
		if (strncmp(line, "Device", 6) == 0 || *line == '\0')
			continue;
		dev = strsep(&line, " \t");
		while (line != NULL && (size = strsep(&line, " \t")) != NULL &&
		    *size == '\0')
			;
		while (line != NULL && (used = strsep(&line, " \t")) != NULL &&
		    *used == '\0')
			;
		if (dev == NULL || line == NULL)
			continue;
		if (strcmp(dev, "Total") == 0) {
			total = strtoull(size, NULL, 10) * 1024;
			inuse = strtoull(used, NULL, 10) * 1024;
			break;
		}
		total += strtoull(size, NULL, 10) * 1024;
		inuse += strtoull(used, NULL, 10) * 1024;
	}
	st->has_swap_total = st->has_swap_used = true;
	st->swap_total = total;
	st->swap_used = inuse;
}

void
resources_measure(struct work *w, struct host_stats *st)
{
	struct loadavg	 la;
	uint64_t	 page;
	size_t		 len;
	int		 step;

	st->has_cpu_pct = true;
	/* Hundredths on the wire (decimal64, 2 digits), the loads too. */
	st->cpu_pct = (int64_t)(cpu_pct(w) * 100.0);

	step = step_begin(w, ARC_STEP_KIND_LIB, "sysctlbyname(3)",
	    "vm.loadavg, vm.stats.vm.*");
	len = sizeof(la);
	if (sysctlbyname("vm.loadavg", &la, &len, NULL, 0) == 0 &&
	    la.fscale > 0) {
		st->has_load1 = st->has_load5 = st->has_load15 = true;
		st->load1 = (int64_t)((double)la.ldavg[0] * 100.0 / la.fscale);
		st->load5 = (int64_t)((double)la.ldavg[1] * 100.0 / la.fscale);
		st->load15 = (int64_t)((double)la.ldavg[2] * 100.0 / la.fscale);
	}
	page = (uint64_t)getpagesize();
	st->has_mem_total = st->has_mem_used = st->has_mem_inactive =
	    st->has_mem_free = true;
	st->mem_total = vmstat("vm.stats.vm.v_page_count") * page;
	st->mem_used = (vmstat("vm.stats.vm.v_active_count") +
	    vmstat("vm.stats.vm.v_wire_count") +
	    vmstat("vm.stats.vm.v_laundry_count")) * page;
	st->mem_inactive = vmstat("vm.stats.vm.v_inactive_count") * page;
	st->mem_free = vmstat("vm.stats.vm.v_free_count") * page;
	step_end(w, step, true, "%jd%% CPU, %ju of %ju MiB in use",
	    (intmax_t)(st->cpu_pct / 100), (uintmax_t)(st->mem_used >> 20),
	    (uintmax_t)(st->mem_total >> 20));
	swap(w, st);
}
