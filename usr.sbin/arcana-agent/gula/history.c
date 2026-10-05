/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: how busy the host has been.  A thread of its own looks every
 * few seconds, whether anybody asks or not, and keeps an hour of what
 * it saw: the CPUs' busy share (kern.cp_time), the load, the memory and
 * the swap in use, and what went over the network (getifaddrs(3)) and
 * to and from the disks (devstat(3)) between two looks.
 */

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <vm/vm_param.h>

#include <devstat.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"

#define	HIST_STEP	5		/* s between two looks */
#define	HIST_KEPT	720		/* an hour of them */

struct sample {
	time_t		t;
	double		cpu;		/* percent */
	double		load;
	uint64_t	mem;		/* bytes in use */
	uint64_t	swap;
	uint64_t	rx, tx;		/* bytes a second */
	uint64_t	rd, wr;
};

/* The counters a rate is the difference of. */
struct counters {
	long		cp[CPUSTATES];
	uint64_t	rx, tx, rd, wr;
	struct timespec	at;
};

static pthread_mutex_t	hist_lock = PTHREAD_MUTEX_INITIALIZER;
static struct sample	ring[HIST_KEPT];
static size_t		ring_first, ring_n;
static uint64_t		mem_total, swap_total;
static struct statinfo	disks;
static bool		disks_ok;

static uint64_t
pages(const char *name)
{
	unsigned int	v;
	size_t		len;

	len = sizeof(v);
	if (sysctlbyname(name, &v, &len, NULL, 0) == -1)
		return (0);
	return ((uint64_t)v * (uint64_t)getpagesize());
}

/* Every swap device's size and what of it is taken. */
static void
swap(uint64_t *total, uint64_t *used)
{
	struct xswdev	xsw;
	int		mib[16];
	size_t		miblen, len;
	int		i;

	*total = *used = 0;
	miblen = nitems(mib) - 1;
	if (sysctlnametomib("vm.swap_info", mib, &miblen) == -1)
		return;
	for (i = 0; i < 64; i++) {
		mib[miblen] = i;
		len = sizeof(xsw);
		if (sysctl(mib, (u_int)miblen + 1, &xsw, &len, NULL, 0) == -1)
			break;
		*total += (uint64_t)xsw.xsw_nblks * (uint64_t)getpagesize();
		*used += (uint64_t)xsw.xsw_used * (uint64_t)getpagesize();
	}
}

static void
count(struct counters *c)
{
	struct ifaddrs		*ifa0, *ifa;
	const struct if_data	*ifd;
	const struct devstat	*ds;
	size_t			 len;
	int			 i;

	memset(c, 0, sizeof(*c));
	clock_gettime(CLOCK_MONOTONIC, &c->at);
	len = sizeof(c->cp);
	(void)sysctlbyname("kern.cp_time", c->cp, &len, NULL, 0);
	if (getifaddrs(&ifa0) == 0) {
		for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family !=
			    AF_LINK || ifa->ifa_data == NULL ||
			    (ifa->ifa_flags & IFF_LOOPBACK) != 0)
				continue;
			ifd = ifa->ifa_data;
			c->rx += ifd->ifi_ibytes;
			c->tx += ifd->ifi_obytes;
		}
		freeifaddrs(ifa0);
	}
	if (disks_ok && devstat_getdevs(NULL, &disks) != -1)
		for (i = 0; i < disks.dinfo->numdevs; i++) {
			ds = &disks.dinfo->devices[i];
			/* A pass(4) device is another name for a disk. */
			if (strcmp(ds->device_name, "pass") == 0)
				continue;
			c->rd += ds->bytes[DEVSTAT_READ];
			c->wr += ds->bytes[DEVSTAT_WRITE];
		}
}

static uint64_t
rate(uint64_t now, uint64_t was, double secs)
{

	return (now >= was ? (uint64_t)((double)(now - was) / secs) : 0);
}

static void
look(const struct counters *was, const struct counters *now)
{
	struct sample	 s;
	struct loadavg	 la;
	uint64_t	 st, su;
	double		 secs;
	long		 total, idle;
	size_t		 len;
	int		 i;

	memset(&s, 0, sizeof(s));
	s.t = time(NULL);
	secs = (double)(now->at.tv_sec - was->at.tv_sec) +
	    (double)(now->at.tv_nsec - was->at.tv_nsec) / 1e9;
	if (secs < 0.1)
		secs = 0.1;
	total = idle = 0;
	for (i = 0; i < CPUSTATES; i++) {
		total += now->cp[i] - was->cp[i];
		if (i == CP_IDLE)
			idle = now->cp[i] - was->cp[i];
	}
	s.cpu = total > 0 ? 100.0 * (double)(total - idle) / (double)total : 0;
	len = sizeof(la);
	if (sysctlbyname("vm.loadavg", &la, &len, NULL, 0) == 0 && la.fscale >
	    0)
		s.load = (double)la.ldavg[0] / la.fscale;
	s.mem = pages("vm.stats.vm.v_active_count") +
	    pages("vm.stats.vm.v_wire_count") +
	    pages("vm.stats.vm.v_laundry_count");
	swap(&st, &su);
	s.swap = su;
	s.rx = rate(now->rx, was->rx, secs);
	s.tx = rate(now->tx, was->tx, secs);
	s.rd = rate(now->rd, was->rd, secs);
	s.wr = rate(now->wr, was->wr, secs);
	pthread_mutex_lock(&hist_lock);
	mem_total = pages("vm.stats.vm.v_page_count");
	swap_total = st;
	if (ring_n < HIST_KEPT)
		ring[(ring_first + ring_n++) % HIST_KEPT] = s;
	else {
		ring[ring_first] = s;
		ring_first = (ring_first + 1) % HIST_KEPT;
	}
	pthread_mutex_unlock(&hist_lock);
}

static void *
sampler(void *arg __unused)
{
	struct counters	 a, b;
	struct timespec	 ts;

	if (devstat_checkversion(NULL) != -1 && (disks.dinfo = calloc(1,
	    sizeof(*disks.dinfo))) != NULL)
		disks_ok = true;
	count(&a);
	/* The first after a second, for there to be one to show soon. */
	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	for (;;) {
		nanosleep(&ts, NULL);
		count(&b);
		look(&a, &b);
		a = b;
		ts.tv_sec = HIST_STEP;
	}
	return (NULL);
}

void
history_start(void)
{
	pthread_t	tid;
	int		error;

	if ((error = pthread_create(&tid, NULL, sampler, NULL)) != 0) {
		logmsg(LOG_WARNING, "no history is kept: pthread_create: %s",
		    strerror(error));
		return;
	}
	(void)pthread_detach(tid);
}

/* {"step":5,"fields":[...],"samples":[[...]],...}; after since, if set. */
int
do_history(struct work *w, uint64_t since, struct arc_history_rsp *rsp)
{
	const struct sample	*s;
	FILE			*fp;
	char			*json;
	size_t			 len, i, n;
	int			 step, ncpu;

	rsp->has_ok = true;
	rsp->ok = false;
	step = step_begin(w, ARC_STEP_KIND_DAEMON, "history",
	    "the samples kept, one every %d s", HIST_STEP);
	json = NULL;
	if ((fp = open_memstream(&json, &len)) == NULL) {
		step_end(w, step, false, "open_memstream");
		rsp->error = "out of memory";
		return (0);
	}
	ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	pthread_mutex_lock(&hist_lock);
	fprintf(fp, "{\"step\":%d,\"ncpu\":%d,\"mem_total\":%ju,"
	    "\"swap_total\":%ju,\"fields\":[\"t\",\"cpu\",\"load\",\"mem\","
	    "\"swap\",\"rx\",\"tx\",\"read\",\"write\"],\"samples\":[",
	    HIST_STEP, ncpu > 0 ? ncpu : 1, (uintmax_t)mem_total,
	    (uintmax_t)swap_total);
	for (i = n = 0; i < ring_n; i++) {
		s = &ring[(ring_first + i) % HIST_KEPT];
		if ((uint64_t)s->t <= since)
			continue;
		fprintf(fp, "%s[%jd,%.1f,%.2f,%ju,%ju,%ju,%ju,%ju,%ju]",
		    n++ > 0 ? "," : "", (intmax_t)s->t, s->cpu, s->load,
		    (uintmax_t)s->mem, (uintmax_t)s->swap, (uintmax_t)s->rx,
		    (uintmax_t)s->tx, (uintmax_t)s->rd, (uintmax_t)s->wr);
	}
	pthread_mutex_unlock(&hist_lock);
	fprintf(fp, "]}");
	if (fclose(fp) != 0 || json == NULL) {
		free(json);
		step_end(w, step, false, "out of memory");
		rsp->error = "out of memory";
		return (0);
	}
	step_end(w, step, true, "%zu samples", n);
	rsp->json = wadopt(w, json);
	rsp->ok = true;
	return (0);
}
