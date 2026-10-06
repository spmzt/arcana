/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: how busy the host has been.  A thread of its own looks every
 * few seconds, whether anybody asks or not, and keeps the last of what
 * it saw: the CPUs' busy share (kern.cp_time), the load, the memory and
 * the swap in use, and what went over each interface (getifaddrs(3))
 * and to and from each disk (devstat(3)) between two looks.
 *
 * How often it looks and how many looks it keeps is set by whoever
 * manages the host, and kept in a file for the next start; with none
 * kept nothing is sampled and no memory is held.  A sample is a time
 * and a row of floats, as wide as there are interfaces and disks, so
 * what is held is known: it is said with the samples.
 */

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <vm/vm_param.h>

#include <ctype.h>
#include <devstat.h>
#include <errno.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"

#define	HIST_STEP	5		/* s between two looks, at first */
#define	HIST_KEEP	720		/* looks kept, at first: an hour */
#define	HIST_STEP_MAX	3600
#define	HIST_KEEP_MAX	5000
#define	HIST_DEVS	16		/* interfaces, and disks, told apart */
#define	HIST_NAME	24

/* What every row begins with; then in and out of each interface, and
 * read and written of each disk. */
enum { H_CPU, H_LOAD, H_MEM, H_SWAP, H_RX, H_TX, H_RD, H_WR, H_BASE };

struct dev {
	char		name[HIST_NAME];
	uint64_t	a, b;		/* its counters at the look before */
	bool		was;		/* and whether it had any */
	bool		now;
};

static void	thresholds(const float *);

static pthread_mutex_t	hist_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	hist_wake = PTHREAD_COND_INITIALIZER;
static unsigned int	hist_step = HIST_STEP;
static unsigned int	hist_keep = HIST_KEEP;
/* Above which an event is made: cpu, mem, swap in percent; 0 none. */
static unsigned int	limits[3] = { 90, 90, 50 };
static bool		over[3];
static time_t		saved;		/* when the samples were last written */
#define	HIST_SAVE_EVERY	300
static double		*times;		/* hist_keep of them, when any */
static float		*rows;		/* hist_keep rows of width */
static size_t		 nrows, width = H_BASE;
static struct dev	 nets[HIST_DEVS], disks[HIST_DEVS];
static size_t		 nnets, ndisks;
static uint64_t		 mem_total, swap_total;
static long		 cp_was[CPUSTATES];
static struct timespec	 at_was;
static bool		 have_was;
static struct statinfo	 dstat;
static bool		 dstat_ok;

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

/* The memory for keep rows of w floats; false when there is none. */
static bool
room(size_t keep, size_t w, double **tp, float **rp)
{

	*tp = NULL;
	*rp = NULL;
	if (keep == 0)
		return (true);
	*tp = calloc(keep, sizeof(**tp));
	*rp = calloc(keep * w, sizeof(**rp));
	if (*tp == NULL || *rp == NULL) {
		free(*tp);
		free(*rp);
		*tp = NULL;
		*rp = NULL;
		return (false);
	}
	return (true);
}

/*
 * The rows as keep of them, each w wide, with nn interfaces where
 * there were nnets: the newest stay, and a new column begins at zero.
 * Called with the lock held.
 */
static void
reshape(size_t keep, size_t nn, size_t nd)
{
	double	*t;
	float	*r, *from, *to;
	size_t	 w, n, i, skip;

	w = H_BASE + 2 * nn + 2 * nd;
	if (!room(keep, w, &t, &r)) {
		logmsg(LOG_WARNING, "history: no memory for %zu samples",
		    keep);
		keep = 0;
	}
	n = nrows < keep ? nrows : keep;
	skip = nrows - n;
	for (i = 0; i < n && rows != NULL; i++) {
		from = rows + (skip + i) * width;
		to = r + i * w;
		t[i] = times[skip + i];
		memcpy(to, from, (H_BASE + 2 * nnets) * sizeof(float));
		memcpy(to + H_BASE + 2 * nn, from + H_BASE + 2 * nnets,
		    2 * ndisks * sizeof(float));
	}
	free(times);
	free(rows);
	times = t;
	rows = r;
	nrows = rows != NULL ? n : 0;
	width = w;
	nnets = nn;
	ndisks = nd;
	hist_keep = (unsigned int)keep;
}

/* The place of the device named, made when there is room; or -1. */
static int
slot(struct dev *v, size_t *n, const char *given)
{
	char	name[HIST_NAME];
	size_t	i;

	/* An interface can be given any name: only what a name needs. */
	strlcpy(name, given, sizeof(name));
	for (i = 0; name[i] != '\0'; i++)
		if (!isalnum((unsigned char)name[i]) && strchr("._-:",
		    name[i]) == NULL)
			name[i] = '_';
	for (i = 0; i < *n; i++)
		if (strcmp(v[i].name, name) == 0)
			return ((int)i);
	if (*n == HIST_DEVS)
		return (-1);
	if (v == nets)
		reshape(hist_keep, nnets + 1, ndisks);
	else
		reshape(hist_keep, nnets, ndisks + 1);
	memset(&v[i], 0, sizeof(v[i]));
	strlcpy(v[i].name, name, sizeof(v[i].name));
	return ((int)i);
}

/* What one device did since the look before, into its two columns. */
static void
moved(struct dev *d, float *col, uint64_t a, uint64_t b, double secs,
    float *suma, float *sumb)
{

	if (d->was && a >= d->a && b >= d->b) {
		col[0] = (float)((double)(a - d->a) / secs);
		col[1] = (float)((double)(b - d->b) / secs);
		*suma += col[0];
		*sumb += col[1];
	}
	d->a = a;
	d->b = b;
	d->was = d->now = true;
}

/* One look: a row more, the oldest dropped when there is no room. */
static void
look(void)
{
	struct ifaddrs		*ifa0, *ifa;
	const struct if_data	*ifd;
	const struct devstat	*ds;
	struct timespec		 at;
	struct loadavg		 la;
	char			 name[HIST_NAME];
	float			*row;
	uint64_t		 st, su;
	double			 secs;
	long			 cp[CPUSTATES], total, idle;
	size_t			 len, k;
	int			 i, s;
	bool			 first;

	clock_gettime(CLOCK_MONOTONIC, &at);
	len = sizeof(cp);
	if (sysctlbyname("kern.cp_time", cp, &len, NULL, 0) == -1)
		memset(cp, 0, sizeof(cp));
	ifa0 = NULL;
	(void)getifaddrs(&ifa0);
	if (dstat_ok && devstat_getdevs(NULL, &dstat) == -1)
		dstat.dinfo->numdevs = 0;
	swap(&st, &su);

	pthread_mutex_lock(&hist_lock);
	first = !have_was;
	secs = (double)(at.tv_sec - at_was.tv_sec) +
	    (double)(at.tv_nsec - at_was.tv_nsec) / 1e9;
	if (secs < 0.1)
		secs = 0.1;
	/* The places first: a new device makes every row wider. */
	for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next)
		if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family ==
		    AF_LINK && ifa->ifa_data != NULL && (ifa->ifa_flags &
		    IFF_LOOPBACK) == 0)
			(void)slot(nets, &nnets, ifa->ifa_name);
	for (i = 0; dstat_ok && i < dstat.dinfo->numdevs; i++) {
		ds = &dstat.dinfo->devices[i];
		/* A pass(4) device is another name for a disk. */
		if (strcmp(ds->device_name, "pass") == 0)
			continue;
		snprintf(name, sizeof(name), "%s%d", ds->device_name,
		    ds->unit_number);
		(void)slot(disks, &ndisks, name);
	}
	if (rows == NULL || hist_keep == 0) {
		pthread_mutex_unlock(&hist_lock);
		if (ifa0 != NULL)
			freeifaddrs(ifa0);
		return;
	}
	if (nrows == hist_keep) {
		memmove(times, times + 1, (nrows - 1) * sizeof(*times));
		memmove(rows, rows + width, (nrows - 1) * width *
		    sizeof(*rows));
		nrows--;
	}
	row = rows + nrows * width;
	memset(row, 0, width * sizeof(*row));
	total = idle = 0;
	for (i = 0; i < CPUSTATES; i++) {
		total += cp[i] - cp_was[i];
		if (i == CP_IDLE)
			idle = cp[i] - cp_was[i];
	}
	row[H_CPU] = total > 0 ? (float)(100.0 * (double)(total - idle) /
	    (double)total) : 0;
	len = sizeof(la);
	if (sysctlbyname("vm.loadavg", &la, &len, NULL, 0) == 0 && la.fscale >
	    0)
		row[H_LOAD] = (float)la.ldavg[0] / (float)la.fscale;
	row[H_MEM] = (float)(pages("vm.stats.vm.v_active_count") +
	    pages("vm.stats.vm.v_wire_count") +
	    pages("vm.stats.vm.v_laundry_count"));
	row[H_SWAP] = (float)su;
	mem_total = pages("vm.stats.vm.v_page_count");
	swap_total = st;
	for (k = 0; k < nnets; k++)
		nets[k].now = false;
	for (k = 0; k < ndisks; k++)
		disks[k].now = false;
	for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family !=
		    AF_LINK || ifa->ifa_data == NULL || (ifa->ifa_flags &
		    IFF_LOOPBACK) != 0 || (s = slot(nets, &nnets,
		    ifa->ifa_name)) == -1)
			continue;
		ifd = ifa->ifa_data;
		moved(&nets[s], row + H_BASE + 2 * s, ifd->ifi_ibytes,
		    ifd->ifi_obytes, secs, &row[H_RX], &row[H_TX]);
	}
	for (i = 0; dstat_ok && i < dstat.dinfo->numdevs; i++) {
		ds = &dstat.dinfo->devices[i];
		if (strcmp(ds->device_name, "pass") == 0)
			continue;
		snprintf(name, sizeof(name), "%s%d", ds->device_name,
		    ds->unit_number);
		if ((s = slot(disks, &ndisks, name)) == -1)
			continue;
		moved(&disks[s], row + H_BASE + 2 * nnets + 2 * s,
		    ds->bytes[DEVSTAT_READ], ds->bytes[DEVSTAT_WRITE], secs,
		    &row[H_RD], &row[H_WR]);
	}
	/* One that went away and comes back begins anew. */
	for (k = 0; k < nnets; k++)
		nets[k].was = nets[k].now;
	for (k = 0; k < ndisks; k++)
		disks[k].was = disks[k].now;
	memcpy(cp_was, cp, sizeof(cp));
	at_was = at;
	have_was = true;
	/* The first look has nothing to be the difference from. */
	if (!first)
		times[nrows++] = (double)time(NULL);
	if (!first)
		thresholds(row);
	pthread_mutex_unlock(&hist_lock);
	if (ifa0 != NULL)
		freeifaddrs(ifa0);
}

/*
 * A figure over its limit, or under it again: an event each time it
 * crosses, and not for every look it stays there.
 */
static void
thresholds(const float *row)
{
	static const char *const what[] = { "cpu", "mem", "swap" };
	double	v[3];
	size_t	i;

	v[0] = row[H_CPU];
	v[1] = mem_total > 0 ? 100.0 * row[H_MEM] / (double)mem_total : 0;
	v[2] = swap_total > 0 ? 100.0 * row[H_SWAP] / (double)swap_total : 0;
	for (i = 0; i < 3; i++) {
		if (limits[i] == 0)
			continue;
		if (!over[i] && v[i] > limits[i])
			over[i] = true;
		else if (over[i] && v[i] < (double)limits[i] - 5)
			over[i] = false;
		else
			continue;
		event_add("threshold", "{\"what\":\"%s\",\"value\":%.0f,"
		    "\"limit\":%u,\"over\":%s}", what[i], v[i], limits[i],
		    over[i] ? "true" : "false");
	}
}

/*
 * The samples written down, to be read again at the next start: a
 * header of what a row holds, then a row a line.  Beside the file
 * that keeps how the host is sampled.
 */
static void
samples_write(void)
{
	char	path[MAXPATHLEN], tmp[MAXPATHLEN];
	FILE	*fp;
	size_t	i, k;

	snprintf(path, sizeof(path), "%s.samples", opts.history_conf);
	snprintf(tmp, sizeof(tmp), "%s.new", path);
	if (rows == NULL || nrows == 0) {
		(void)unlink(path);
		return;
	}
	if ((fp = fopen(tmp, "we")) == NULL)
		return;
	fprintf(fp, "# arcana-agent samples: step keep nets disks\n%u %u", hist_step,
	    hist_keep);
	for (k = 0; k < nnets; k++)
		fprintf(fp, " %s", nets[k].name);
	fprintf(fp, " |");
	for (k = 0; k < ndisks; k++)
		fprintf(fp, " %s", disks[k].name);
	fprintf(fp, "\n");
	for (i = 0; i < nrows; i++) {
		fprintf(fp, "%.0f", times[i]);
		for (k = 0; k < width; k++)
			fprintf(fp, " %.2f", rows[i * width + k]);
		fprintf(fp, "\n");
	}
	if (fclose(fp) != 0 || rename(tmp, path) == -1)
		(void)unlink(tmp);
	saved = time(NULL);
}

/* What was written down by the agent that ran before: read, if it is
 * of the same devices, and not older than is kept. */
static void
samples_read(void)
{
	char	path[MAXPATHLEN], *line, *p, *w;
	FILE	*fp;
	size_t	cap, k, n;
	double	t;
	unsigned int	step, keep;

	snprintf(path, sizeof(path), "%s.samples", opts.history_conf);
	if ((fp = fopen(path, "re")) == NULL)
		return;
	line = NULL;
	cap = 0;
	if (getline(&line, &cap, fp) == -1 || getline(&line, &cap, fp) == -1) {
		free(line);
		fclose(fp);
		return;
	}
	p = line;
	step = (unsigned int)strtoul(strsep(&p, " "), NULL, 10);
	keep = (unsigned int)strtoul(strsep(&p, " "), NULL, 10);
	(void)step;
	(void)keep;
	/* The devices, in the order the rows have them. */
	n = 0;
	while ((w = strsep(&p, " \n")) != NULL && strcmp(w, "|") != 0)
		if (w[0] != '\0' && (int)n < HIST_DEVS)
			strlcpy(nets[n++].name, w, sizeof(nets[0].name));
	nnets = n;
	n = 0;
	while ((w = strsep(&p, " \n")) != NULL)
		if (w[0] != '\0' && (int)n < HIST_DEVS)
			strlcpy(disks[n++].name, w, sizeof(disks[0].name));
	ndisks = n;
	reshape(hist_keep, nnets, ndisks);
	while (rows != NULL && getline(&line, &cap, fp) != -1) {
		p = line;
		t = strtod(strsep(&p, " "), NULL);
		if (t <= 0 || t < (double)time(NULL) - (double)hist_step *
		    hist_keep)
			continue;
		if (nrows == hist_keep) {
			memmove(times, times + 1, (nrows - 1) * sizeof(*times));
			memmove(rows, rows + width, (nrows - 1) * width *
			    sizeof(*rows));
			nrows--;
		}
		times[nrows] = t;
		for (k = 0; k < width; k++)
			rows[nrows * width + k] = (w = strsep(&p, " \n")) !=
			    NULL ? (float)strtod(w, NULL) : 0;
		nrows++;
	}
	free(line);
	fclose(fp);
	logmsg(LOG_INFO, "history: %zu samples read from %s", nrows, path);
}

/* Written down, for the next start: called when the agent stops. */
void
history_save(void)
{

	pthread_mutex_lock(&hist_lock);
	samples_write();
	pthread_mutex_unlock(&hist_lock);
}

static void *
sampler(void *arg __unused)
{
	struct timespec	 until;
	unsigned int	 wait;

	if (devstat_checkversion(NULL) != -1 && (dstat.dinfo = calloc(1,
	    sizeof(*dstat.dinfo))) != NULL)
		dstat_ok = true;
	for (;;) {
		pthread_mutex_lock(&hist_lock);
		/* With none kept there is nothing to do, and no look. */
		while (hist_keep == 0) {
			have_was = false;
			pthread_cond_wait(&hist_wake, &hist_lock);
		}
		pthread_mutex_unlock(&hist_lock);
		look();
		pthread_mutex_lock(&hist_lock);
		if (time(NULL) - saved >= HIST_SAVE_EVERY)
			samples_write();
		/* The first after a second, for one to show soon. */
		wait = nrows == 0 ? 1 : hist_step;
		clock_gettime(CLOCK_REALTIME, &until);
		until.tv_sec += wait;
		/* Woken early when how it samples was changed. */
		(void)pthread_cond_timedwait(&hist_wake, &hist_lock, &until);
		pthread_mutex_unlock(&hist_lock);
	}
	return (NULL);
}

/* "step=5" and "keep=720", as they were set: read at start. */
static void
hconf_read(void)
{
	FILE		*fp;
	char		 line[64];
	const char	*e;
	long long	 v;

	if ((fp = fopen(opts.history_conf, "re")) == NULL)
		return;
	while (fgets(line, sizeof(line), fp) != NULL) {
		line[strcspn(line, "\r\n")] = '\0';
		if (strncmp(line, "step=", 5) == 0) {
			v = strtonum(line + 5, 1, HIST_STEP_MAX, &e);
			if (e == NULL)
				hist_step = (unsigned int)v;
		} else if (strncmp(line, "keep=", 5) == 0) {
			v = strtonum(line + 5, 0, HIST_KEEP_MAX, &e);
			if (e == NULL)
				hist_keep = (unsigned int)v;
		} else if (strncmp(line, "cpu=", 4) == 0 || strncmp(line,
		    "mem=", 4) == 0 || strncmp(line, "swap=", 5) == 0) {
			v = strtonum(strchr(line, '=') + 1, 0, 100, &e);
			if (e == NULL)
				limits[line[0] == 'c' ? 0 : line[0] == 'm' ? 1 :
				    2] = (unsigned int)v;
		}
	}
	fclose(fp);
}

static int
hconf_write(unsigned int step, unsigned int keep)
{
	char	tmp[MAXPATHLEN];
	FILE	*fp;

	snprintf(tmp, sizeof(tmp), "%s.new", opts.history_conf);
	if ((fp = fopen(tmp, "we")) == NULL)
		return (-1);
	fprintf(fp, "# How arcana-agent samples the host: set from the "
	    "console.\nstep=%u\nkeep=%u\ncpu=%u\nmem=%u\nswap=%u\n", step,
	    keep, limits[0], limits[1], limits[2]);
	if (fclose(fp) != 0 || rename(tmp, opts.history_conf) == -1) {
		(void)unlink(tmp);
		return (-1);
	}
	return (0);
}

void
history_start(void)
{
	pthread_t	tid;
	int		error;

	hconf_read();
	pthread_mutex_lock(&hist_lock);
	reshape(hist_keep, 0, 0);
	samples_read();
	saved = time(NULL);
	pthread_mutex_unlock(&hist_lock);
	if ((error = pthread_create(&tid, NULL, sampler, NULL)) != 0) {
		logmsg(LOG_WARNING, "no history is kept: pthread_create: %s",
		    strerror(error));
		return;
	}
	(void)pthread_detach(tid);
}

static void
names(FILE *fp, const char *key, const struct dev *v, size_t n)
{
	size_t	i;

	/* An interface's or a disk's name needs no escaping. */
	fprintf(fp, "\"%s\":[", key);
	for (i = 0; i < n; i++)
		fprintf(fp, "%s\"%s\"", i > 0 ? "," : "", v[i].name);
	fprintf(fp, "],");
}

/*
 * {"step":5,"keep":720,"samples":[[...]],...}: the samples after the
 * time after.  With set, first sampled every step seconds from now on,
 * and keep of them kept, which is written down for the next start.
 */
int
do_history(struct work *w, uint64_t after, bool set, uint32_t step,
    uint32_t keep, const uint32_t lim[3], struct arc_history_rsp *rsp)
{
	const float	*row;
	FILE		*fp;
	char		*json;
	size_t		 len, i, k, n;
	int		 st, ncpu;

	rsp->has_ok = true;
	rsp->ok = false;
	if (set) {
		if (step < 1 || step > HIST_STEP_MAX || keep > HIST_KEEP_MAX ||
		    (lim != NULL && (lim[0] > 100 || lim[1] > 100 || lim[2] >
		    100))) {
			rsp->error = wfmt(w, "sampled every 1 to %d seconds, "
			    "0 to %d samples kept, and limits of 0 to 100",
			    HIST_STEP_MAX, HIST_KEEP_MAX);
			return (0);
		}
		if (lim != NULL) {
			pthread_mutex_lock(&hist_lock);
			memcpy(limits, lim, sizeof(limits));
			pthread_mutex_unlock(&hist_lock);
		}
		st = step_begin(w, ARC_STEP_KIND_DAEMON, "history",
		    "every %u s, %u kept, into %s", step, keep,
		    opts.history_conf);
		if (hconf_write(step, keep) == -1) {
			rsp->error = wfmt(w, "%s: %s", opts.history_conf,
			    strerror(errno));
			step_end(w, st, false, "%s", strerror(errno));
			return (0);
		}
		pthread_mutex_lock(&hist_lock);
		hist_step = step;
		reshape(keep, nnets, ndisks);
		pthread_cond_broadcast(&hist_wake);
		pthread_mutex_unlock(&hist_lock);
		step_end(w, st, true, NULL);
	}
	st = step_begin(w, ARC_STEP_KIND_DAEMON, "history",
	    "the samples kept");
	json = NULL;
	if ((fp = open_memstream(&json, &len)) == NULL) {
		step_end(w, st, false, "open_memstream");
		rsp->error = "out of memory";
		return (0);
	}
	ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	pthread_mutex_lock(&hist_lock);
	fprintf(fp, "{\"limits\":{\"cpu\":%u,\"mem\":%u,\"swap\":%u},", limits[0],
	    limits[1], limits[2]);
	fprintf(fp, "\"step\":%u,\"keep\":%u,\"bytes\":%zu,\"ncpu\":%d,"
	    "\"mem_total\":%ju,\"swap_total\":%ju,\"fields\":[\"t\",\"cpu\","
	    "\"load\",\"mem\",\"swap\",\"rx\",\"tx\",\"read\",\"write\"],",
	    hist_step, hist_keep, rows != NULL ? hist_keep * (sizeof(*times) +
	    width * sizeof(*rows)) : 0, ncpu > 0 ? ncpu : 1,
	    (uintmax_t)mem_total, (uintmax_t)swap_total);
	names(fp, "nets", nets, nnets);
	names(fp, "disks", disks, ndisks);
	fprintf(fp, "\"samples\":[");
	for (i = n = 0; i < nrows; i++) {
		if (times[i] <= (double)after)
			continue;
		row = rows + i * width;
		fprintf(fp, "%s[%.0f,%.1f,%.2f", n++ > 0 ? "," : "", times[i],
		    row[H_CPU], row[H_LOAD]);
		for (k = H_MEM; k < width; k++)
			fprintf(fp, ",%.0f", row[k]);
		fprintf(fp, "]");
	}
	pthread_mutex_unlock(&hist_lock);
	fprintf(fp, "]}");
	if (fclose(fp) != 0 || json == NULL || len > ARC_MAX_JSON) {
		free(json);
		step_end(w, st, false, NULL);
		rsp->error = len > ARC_MAX_JSON ? "more samples than a reply "
		    "carries: ask for those after a time" : "out of memory";
		return (0);
	}
	step_end(w, st, true, "%zu samples", n);
	rsp->json = wadopt(w, json);
	rsp->ok = true;
	return (0);
}
