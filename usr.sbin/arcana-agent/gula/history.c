/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: how busy the host has been.  A thread of its own looks every
 * few seconds, whether anybody asks or not, and keeps the last of what
 * it saw: the CPUs' busy share (kern.cp_time), the load, the memory and
 * the swap in use, what went over each interface (getifaddrs(3)) and
 * to and from each disk (devstat(3)) between two looks, and each
 * running jail's share of the CPUs and its memory as the kernel's
 * resource accounting has them (rctl_get_racct(2)), when it is on
 * (kern.racct.enable, a tunable of loader.conf).  And each FEC relay's
 * (UDPspeeder, luxuria/speeder.c) bytes taken in plain, the tunnel's
 * rate as it carries it, and the bytes its FEC adds to them, both ways
 * over its last --report interval, read from its lines in syslog: the
 * overhead, beside the rate of the tunnel's interface.
 *
 * Besides the limits of the CPU, the memory and the swap, rules set
 * limits of one interface (bytes a second, both ways), one disk (bytes
 * a second, read and written), one jail's CPU (percent of one CPU, as
 * racct says it) or memory (bytes): an event when the figure crosses
 * its limit, either way.
 *
 * How often it looks and how many looks it keeps is set by whoever
 * manages the host, and kept in a file for the next start; when they
 * are all there, the older are thinned rather than dropped (thin()); with none
 * kept nothing is sampled and no memory is held.  A sample is a time
 * and a row of floats, as wide as there are interfaces and disks, so
 * what is held is known: it is said with the samples.
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/mount.h>
#include <sys/rctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <vm/vm_param.h>

#include <ctype.h>
#include <devstat.h>
#include <errno.h>
#include <ifaddrs.h>
#include <jail.h>
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
#define	HIST_RULES	32
#define	JAIL_NAME	HIST_NAME	/* a jail's column, named for it */

/* What every row begins with; then in and out of each interface,
 * read and written of each disk, each jail's CPU and memory, and each
 * FEC relay's bytes a second taken in plain and added by its FEC. */
enum { H_CPU, H_LOAD, H_MEM, H_SWAP, H_RX, H_TX, H_RD, H_WR, H_BASE };

struct dev {
	char		name[HIST_NAME];
	uint64_t	a, b;		/* its counters at the look before */
	bool		was;		/* and whether it had any */
	bool		now;
};

static void	thresholds(const float *);
static void	storage_fullness(void);
static void	thin(void);
static void	rules_check(const float *);

/* A limit of one device or jail: an event when it is crossed. */
enum rule_kind { R_NET, R_DISK, R_JAIL_CPU, R_JAIL_MEM, R_KINDS };
static const char *const rule_kinds[R_KINDS] = { "net", "disk", "jail-cpu",
    "jail-mem" };
struct rule {
	enum rule_kind	kind;
	char		name[HIST_NAME];
	double		limit;
	bool		over;
};
static struct rule	rules[HIST_RULES];
static size_t		nrules;

static pthread_mutex_t	hist_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	hist_wake = PTHREAD_COND_INITIALIZER;
static unsigned int	hist_step = HIST_STEP;
static unsigned int	hist_keep = HIST_KEEP;
/* Above which an event is made: cpu, mem, swap in percent; 0 none. */
static unsigned int	limits[4] = { 90, 90, 50, 90 };	/* + storage */
static bool		over[3];

/*
 * The file systems over the storage limit: a ZFS pool by its name, any
 * other local one by where it is mounted.  Looked at each minute.
 */
#define	STORAGE_EVERY	60
#define	STORAGE_MAX	64
static struct {
	char	name[MNAMELEN];
	bool	seen;
}			storage_over[STORAGE_MAX];
static int		nstorage_over;
static time_t		storage_at;
static time_t		saved;		/* when the samples were last written */
#define	HIST_SAVE_EVERY	300
static double		*times;		/* hist_keep of them, when any */
static float		*rows;		/* hist_keep rows of width */
static size_t		 nrows, width = H_BASE;
static struct dev	 nets[HIST_DEVS], disks[HIST_DEVS], jails[HIST_DEVS];
static struct dev	 relays[HIST_DEVS];
static size_t		 nnets, ndisks, njails, nrelays;
static bool		 racct;		/* the kernel accounts for jails */
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
reshape(size_t keep, size_t nn, size_t nd, size_t nj, size_t nr)
{
	double	*t;
	float	*r, *from, *to;
	size_t	 w, n, i, skip;

	w = H_BASE + 2 * nn + 2 * nd + 2 * nj + 2 * nr;
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
		memcpy(to + H_BASE + 2 * nn + 2 * nd, from + H_BASE + 2 *
		    nnets + 2 * ndisks, 2 * njails * sizeof(float));
		memcpy(to + H_BASE + 2 * nn + 2 * nd + 2 * nj, from + H_BASE +
		    2 * nnets + 2 * ndisks + 2 * njails, 2 * nrelays *
		    sizeof(float));
	}
	free(times);
	free(rows);
	times = t;
	rows = r;
	nrows = rows != NULL ? n : 0;
	width = w;
	nnets = nn;
	ndisks = nd;
	njails = nj;
	nrelays = nr;
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
		reshape(hist_keep, nnets + 1, ndisks, njails, nrelays);
	else if (v == disks)
		reshape(hist_keep, nnets, ndisks + 1, njails, nrelays);
	else if (v == jails)
		reshape(hist_keep, nnets, ndisks, njails + 1, nrelays);
	else
		reshape(hist_keep, nnets, ndisks, njails, nrelays + 1);
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

/* One jail's figures: "pcpu=12,memoryuse=1048576,...". */
static bool
jail_racct(const char *name, double *pcpu, double *mem)
{
	char	 filter[MAXHOSTNAMELEN + 8], out[4096], *p, *kv;

	snprintf(filter, sizeof(filter), "jail:%s:", name);
	if (rctl_get_racct(filter, strlen(filter) + 1, out, sizeof(out)) ==
	    -1)
		return (false);
	*pcpu = *mem = 0;
	p = out;
	while ((kv = strsep(&p, ",")) != NULL) {
		if (strncmp(kv, "pcpu=", 5) == 0)
			*pcpu = strtod(kv + 5, NULL);
		else if (strncmp(kv, "memoryuse=", 10) == 0)
			*mem = strtod(kv + 10, NULL);
	}
	return (true);
}

/* The running jails, by name, and what racct says of each. */
struct jfig {
	char	name[JAIL_NAME];
	double	pcpu, mem;
};

static size_t
jail_figures(struct jfig *v, size_t max)
{
	char	last[16], name[MAXHOSTNAMELEN];
	size_t	n;
	int	jid;
	int	on;
	size_t	len;

	len = sizeof(on);
	racct = sysctlbyname("kern.racct.enable", &on, &len, NULL, 0) == 0 &&
	    on != 0;
	if (!racct)
		return (0);
	n = 0;
	strlcpy(last, "0", sizeof(last));
	while (n < max) {
		name[0] = '\0';
		if ((jid = jail_getv(0, "lastjid", last, "name", name,
		    NULL)) <= 0)
			break;
		snprintf(last, sizeof(last), "%d", jid);
		if (strlen(name) >= sizeof(v[n].name) || !jail_racct(name,
		    &v[n].pcpu, &v[n].mem))
			continue;
		strlcpy(v[n].name, name, sizeof(v[n].name));
		n++;
	}
	return (n);
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
	struct jfig		 jf[HIST_DEVS];
	struct speeder_rate	 fr[HIST_DEVS];
	char			 name[HIST_NAME];
	float			*row;
	uint64_t		 st, su;
	double			 secs;
	long			 cp[CPUSTATES], total, idle;
	size_t			 len, k, nj, nr;
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
	nj = jail_figures(jf, nitems(jf));
	nr = speeder_rates(fr, nitems(fr), hist_step);

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
	for (k = 0; k < nj; k++)
		(void)slot(jails, &njails, jf[k].name);
	for (k = 0; k < nr; k++)
		(void)slot(relays, &nrelays, fr[k].tag);
	if (rows == NULL || hist_keep == 0) {
		pthread_mutex_unlock(&hist_lock);
		if (ifa0 != NULL)
			freeifaddrs(ifa0);
		return;
	}
	if (nrows == hist_keep)
		thin();
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
	/* A jail's figures are what they are now, not differences. */
	for (k = 0; k < nj; k++) {
		if ((s = slot(jails, &njails, jf[k].name)) == -1)
			continue;
		row[H_BASE + 2 * nnets + 2 * ndisks + 2 * s] = (float)jf[k].pcpu;
		row[H_BASE + 2 * nnets + 2 * ndisks + 2 * s + 1] =
		    (float)jf[k].mem;
	}
	/* And a relay's, those of its last interval. */
	for (k = 0; k < nr; k++) {
		if ((s = slot(relays, &nrelays, fr[k].tag)) == -1)
			continue;
		row[H_BASE + 2 * nnets + 2 * ndisks + 2 * njails + 2 * s] =
		    (float)fr[k].plain;
		row[H_BASE + 2 * nnets + 2 * ndisks + 2 * njails + 2 * s + 1] =
		    (float)fr[k].added;
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
	/* Out of the lock: it may run zpool(8). */
	if (!first)
		storage_fullness();
}

/*
 * Room for one more, the older thinned rather than dropped.  A look
 * stands for the time since the one before it; of the older half, the
 * two closest together after the oldest become one, at the later's
 * time, each figure the mean of theirs weighed by the time each stood
 * for.  The newer half keeps every look, the older are fewer and
 * further apart the older they are, and the same rows reach further
 * back: until they are HIST_THIN steps apart, when the oldest goes.
 */
#define	HIST_THIN	64

static void
thin(void)
{
	float	*a, *b;
	double	 gap, best_gap, wa, wb;
	size_t	 half, i, best, c;

	half = nrows / 2;
	best = SIZE_MAX;
	best_gap = 0;
	for (i = 1; i + 1 < half; i++) {
		gap = times[i + 1] - times[i];
		if (best == SIZE_MAX || gap < best_gap) {
			best = i;
			best_gap = gap;
		}
	}
	if (best == SIZE_MAX || best_gap >= (double)HIST_THIN * hist_step) {
		/* Too few to thin, or thin enough: the oldest goes. */
		memmove(times, times + 1, (nrows - 1) * sizeof(*times));
		memmove(rows, rows + width, (nrows - 1) * width *
		    sizeof(*rows));
		nrows--;
		return;
	}
	wa = times[best] - times[best - 1];
	wb = best_gap;
	if (wa <= 0 || wb <= 0)
		wa = wb = 1;
	a = rows + best * width;
	b = a + width;
	for (c = 0; c < width; c++)
		b[c] = (float)((a[c] * wa + b[c] * wb) / (wa + wb));
	memmove(times + best, times + best + 1, (nrows - best - 1) *
	    sizeof(*times));
	memmove(a, b, (nrows - best - 1) * width * sizeof(*rows));
	nrows--;
}

/* The column of a device or a jail by its name, or -1. */
static int
col_of(const struct dev *v, size_t n, const char *name)
{
	size_t	i;

	for (i = 0; i < n; i++)
		if (strcmp(v[i].name, name) == 0)
			return ((int)i);
	return (-1);
}

/*
 * The rules' figures, each against its limit: an event when it
 * crosses, and under it again only once it is a tenth below, so that
 * a figure about its limit does not make one at every look.
 */
static void
rules_check(const float *row)
{
	struct rule	*r;
	const float	*base;
	double		 v;
	size_t		 i;
	int		 c;

	for (i = 0; i < nrules; i++) {
		r = &rules[i];
		switch (r->kind) {
		case R_NET:
			if ((c = col_of(nets, nnets, r->name)) == -1)
				continue;
			base = row + H_BASE + 2 * c;
			v = (double)base[0] + base[1];
			break;
		case R_DISK:
			if ((c = col_of(disks, ndisks, r->name)) == -1)
				continue;
			base = row + H_BASE + 2 * nnets + 2 * c;
			v = (double)base[0] + base[1];
			break;
		default:
			if ((c = col_of(jails, njails, r->name)) == -1)
				continue;
			base = row + H_BASE + 2 * nnets + 2 * ndisks + 2 * c;
			v = r->kind == R_JAIL_CPU ? base[0] : base[1];
			break;
		}
		if (!r->over && v > r->limit)
			r->over = true;
		else if (r->over && v < r->limit * 0.9)
			r->over = false;
		else
			continue;
		/* A device's or a jail's name needs no escaping. */
		event_add("threshold", "{\"what\":\"%s\",\"name\":\"%s\","
		    "\"value\":%.0f,\"limit\":%.0f,\"over\":%s}",
		    rule_kinds[r->kind], r->name, v, r->limit, r->over ? "true" :
		    "false");
	}
}

/*
 * One rule as it is written: "net:igb0=125000000", "disk:ada0=5e7",
 * "jail-cpu:web=80", "jail-mem:web=1073741824".  false for one that
 * is not.
 */
static bool
rule_parse(const char *s, struct rule *r)
{
	const char	*colon, *eq;
	char		*end;
	size_t		 k, n;

	if ((colon = strchr(s, ':')) == NULL || (eq = strchr(colon, '=')) ==
	    NULL)
		return (false);
	for (k = 0; k < R_KINDS; k++)
		if (strlen(rule_kinds[k]) == (size_t)(colon - s) &&
		    strncmp(s, rule_kinds[k], (size_t)(colon - s)) == 0)
			break;
	n = (size_t)(eq - colon - 1);
	if (k == R_KINDS || n == 0 || n >= sizeof(r->name))
		return (false);
	memset(r, 0, sizeof(*r));
	r->kind = (enum rule_kind)k;
	memcpy(r->name, colon + 1, n);
	for (k = 0; k < n; k++)
		if (!isalnum((unsigned char)r->name[k]) && strchr("._-:",
		    r->name[k]) == NULL)
			return (false);
	r->limit = strtod(eq + 1, &end);
	return (end != eq + 1 && *end == '\0' && r->limit > 0 &&
	    r->limit < 1e15);
}

/*
 * The rules as a list with commas, each as rule_parse() takes it; an
 * empty one takes them all away.  NULL when they are set, or what is
 * wrong.
 */
static const char *
rules_set(const char *list)
{
	struct rule	 next[HIST_RULES];
	char		*copy, *p, *tok;
	size_t		 n, i, k;

	if ((copy = strdup(list)) == NULL)
		return ("out of memory");
	n = 0;
	p = copy;
	while ((tok = strsep(&p, ", ")) != NULL) {
		if (tok[0] == '\0')
			continue;
		if (n == HIST_RULES || !rule_parse(tok, &next[n])) {
			free(copy);
			return (n == HIST_RULES ? "32 rules at most" : "a rule "
			    "is net:, disk:, jail-cpu: or jail-mem:, a name, = "
			    "and its limit");
		}
		/* One that was over and stays the same stays over. */
		for (i = 0; i < nrules; i++)
			if (rules[i].kind == next[n].kind && strcmp(
			    rules[i].name, next[n].name) == 0)
				next[n].over = rules[i].over;
		n++;
	}
	free(copy);
	for (k = 0; k < n; k++)
		rules[k] = next[k];
	nrules = n;
	return (NULL);
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
		/* And a fault of the host's resources (Mplify 119, Table 4). */
		if (over[i])
			fault_set(i == 0 ? "cpu" : "memory", "Major", what[i],
			    "sampler", "%s at %.0f%%, over %u%%", what[i], v[i],
			    limits[i]);
		else
			fault_clear(i == 0 ? "cpu" : "memory", what[i], "%s at "
			    "%.0f%%, under %u%% again", what[i], v[i], limits[i]);
	}
	rules_check(row);
}

/* A file system's share in use against the limit: a fault either way. */
static void
storage_one(const char *name, double pct, unsigned int limit)
{
	int	i;

	for (i = 0; i < nstorage_over; i++)
		if (strcmp(storage_over[i].name, name) == 0)
			break;
	if (i < nstorage_over) {
		storage_over[i].seen = true;
		if (pct >= (double)limit - 5 && limit != 0)
			return;
		storage_over[i] = storage_over[--nstorage_over];
		event_add("threshold", "{\"what\":\"storage\",\"name\":\"%s\","
		    "\"value\":%.0f,\"limit\":%u,\"over\":false}", name, pct,
		    limit);
		fault_clear("storage", name, "%s at %.0f%%, under %u%% again",
		    name, pct, limit);
		return;
	}
	if (limit == 0 || pct <= (double)limit || nstorage_over == STORAGE_MAX)
		return;
	snprintf(storage_over[nstorage_over].name, sizeof(
	    storage_over[nstorage_over].name), "%s", name);
	storage_over[nstorage_over++].seen = true;
	event_add("threshold", "{\"what\":\"storage\",\"name\":\"%s\","
	    "\"value\":%.0f,\"limit\":%u,\"over\":true}", name, pct, limit);
	fault_set("storage", "Major", name, "sampler", "%s %.0f%% full, over "
	    "%u%%", name, pct, limit);
}

/*
 * The host's storage against its limit (Mplify 119, Table 4): each ZFS
 * pool, its allocated share of its size (zpool list), and each other
 * local file system that holds data, its share as df(1) has it.  One
 * gone or under the limit again is cleared.
 */
static void
storage_fullness(void)
{
	static const char *const skip[] = { "zfs", "devfs", "fdescfs",
	    "procfs", "linprocfs", "linsysfs", "tmpfs", "nullfs", "autofs",
	    "mqueuefs", "fusefs" };
	struct statfs	*mnt;
	struct execres	 res;
	struct work	 w;
	unsigned int	 limit;
	char		*argv[6], *copy, *line, *it, *f[3];
	double		 used, pct, size;
	size_t		 k;
	time_t		 now;
	int		 i, n;

	now = time(NULL);
	pthread_mutex_lock(&hist_lock);
	limit = limits[3];
	if (storage_at != 0 && now - storage_at < STORAGE_EVERY) {
		pthread_mutex_unlock(&hist_lock);
		return;
	}
	storage_at = now;
	pthread_mutex_unlock(&hist_lock);
	for (i = 0; i < nstorage_over; i++)
		storage_over[i].seen = false;
	if (limit != 0) {
		work_init(&w);
		w.nice = true;
		argv[0] = (char *)(uintptr_t)opts.zpool_bin;
		argv[1] = (char *)(uintptr_t)"list";
		argv[2] = (char *)(uintptr_t)"-Hp";
		argv[3] = (char *)(uintptr_t)"-o";
		argv[4] = (char *)(uintptr_t)"name,size,alloc";
		argv[5] = NULL;
		if (access(opts.zpool_bin, X_OK) == 0 && run_exec(&w, argv,
		    &res) == 0 && res.out != NULL) {
			copy = wstrndup(&w, res.out, res.outlen);
			for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
				for (k = 0; k < 3; k++)
					if ((f[k] = strsep(&line, "\t")) == NULL)
						break;
				if (k < 3 || (size = strtod(f[1], NULL)) <= 0)
					continue;
				storage_one(f[0], 100.0 * strtod(f[2], NULL) /
				    size, limit);
			}
		}
		work_free(&w);
		n = getmntinfo(&mnt, MNT_NOWAIT);
		for (i = 0; i < n; i++) {
			for (k = 0; k < nitems(skip); k++)
				if (strcmp(mnt[i].f_fstypename, skip[k]) == 0)
					break;
			if (k < nitems(skip) || (mnt[i].f_flags & MNT_LOCAL) ==
			    0 || (mnt[i].f_flags & MNT_RDONLY) != 0 ||
			    mnt[i].f_blocks == 0)
				continue;
			/* As df(1): used of used and what users may have. */
			used = (double)(mnt[i].f_blocks - mnt[i].f_bfree);
			if (used + (double)mnt[i].f_bavail <= 0)
				continue;
			pct = 100.0 * used / (used + (double)mnt[i].f_bavail);
			storage_one(mnt[i].f_mntonname, pct, limit);
		}
	}
	/* Over before, and not seen now (or no limit): cleared. */
	for (i = nstorage_over - 1; i >= 0; i--) {
		if (storage_over[i].seen)
			continue;
		event_add("threshold", "{\"what\":\"storage\",\"name\":\"%s\","
		    "\"limit\":%u,\"over\":false}", storage_over[i].name, limit);
		fault_clear("storage", storage_over[i].name, limit == 0 ?
		    "%s: no storage limit now" : "%s is gone", storage_over[i].name);
		storage_over[i] = storage_over[--nstorage_over];
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
	fprintf(fp, "# arcana-agent samples: step keep nets | disks | jails | "
	    "relays\n%u %u", hist_step, hist_keep);
	for (k = 0; k < nnets; k++)
		fprintf(fp, " %s", nets[k].name);
	fprintf(fp, " |");
	for (k = 0; k < ndisks; k++)
		fprintf(fp, " %s", disks[k].name);
	fprintf(fp, " |");
	for (k = 0; k < njails; k++)
		fprintf(fp, " %s", jails[k].name);
	fprintf(fp, " |");
	for (k = 0; k < nrelays; k++)
		fprintf(fp, " %s", relays[k].name);
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
	while ((w = strsep(&p, " \n")) != NULL && strcmp(w, "|") != 0)
		if (w[0] != '\0' && (int)n < HIST_DEVS)
			strlcpy(disks[n++].name, w, sizeof(disks[0].name));
	ndisks = n;
	n = 0;
	while ((w = strsep(&p, " \n")) != NULL && strcmp(w, "|") != 0)
		if (w[0] != '\0' && (int)n < HIST_DEVS)
			strlcpy(jails[n++].name, w, sizeof(jails[0].name));
	njails = n;
	n = 0;
	while ((w = strsep(&p, " \n")) != NULL)
		if (w[0] != '\0' && (int)n < HIST_DEVS)
			strlcpy(relays[n++].name, w, sizeof(relays[0].name));
	nrelays = n;
	reshape(hist_keep, nnets, ndisks, njails, nrelays);
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
		} else if (strncmp(line, "rule=", 5) == 0) {
			if (nrules < HIST_RULES && rule_parse(line + 5,
			    &rules[nrules]))
				nrules++;
		} else if (strncmp(line, "cpu=", 4) == 0 || strncmp(line,
		    "mem=", 4) == 0 || strncmp(line, "swap=", 5) == 0 ||
		    strncmp(line, "storage=", 8) == 0) {
			v = strtonum(strchr(line, '=') + 1, 0, 100, &e);
			if (e == NULL)
				limits[line[0] == 'c' ? 0 : line[0] == 'm' ? 1 :
				    line[1] == 'w' ? 2 : 3] = (unsigned int)v;
		}
	}
	fclose(fp);
}

static int
hconf_write(unsigned int step, unsigned int keep)
{
	char	tmp[MAXPATHLEN];
	FILE	*fp;
	size_t	i;

	snprintf(tmp, sizeof(tmp), "%s.new", opts.history_conf);
	if ((fp = fopen(tmp, "we")) == NULL)
		return (-1);
	fprintf(fp, "# How arcana-agent samples the host: set from the "
	    "console.\nstep=%u\nkeep=%u\ncpu=%u\nmem=%u\nswap=%u\n"
	    "storage=%u\n", step, keep, limits[0], limits[1], limits[2],
	    limits[3]);
	for (i = 0; i < nrules; i++)
		fprintf(fp, "rule=%s:%s=%.0f\n", rule_kinds[rules[i].kind],
		    rules[i].name, rules[i].limit);
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
	reshape(hist_keep, 0, 0, 0, 0);
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
    uint32_t keep, const uint32_t lim[4], const char *rlist,
    struct arc_history_rsp *rsp)
{
	struct rule	 was[HIST_RULES];
	size_t		 nwas;
	const char	*e;
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
		    100 || (lim[3] > 100 && lim[3] != UINT32_MAX)))) {
			rsp->error = wfmt(w, "sampled every 1 to %d seconds, "
			    "0 to %d samples kept, and limits of 0 to 100",
			    HIST_STEP_MAX, HIST_KEEP_MAX);
			return (0);
		}
		pthread_mutex_lock(&hist_lock);
		memcpy(was, rules, sizeof(was));
		nwas = nrules;
		e = rlist != NULL ? rules_set(rlist) : NULL;
		pthread_mutex_unlock(&hist_lock);
		if (e != NULL) {
			rsp->error = wtext(w, e);
			return (0);
		}
		if (lim != NULL) {
			pthread_mutex_lock(&hist_lock);
			memcpy(limits, lim, 3 * sizeof(limits[0]));
			if (lim[3] != UINT32_MAX) {
				limits[3] = lim[3];
				storage_at = 0;	/* looked at again now */
			}
			pthread_mutex_unlock(&hist_lock);
		}
		st = step_begin(w, ARC_STEP_KIND_DAEMON, "history",
		    "every %u s, %u kept, into %s", step, keep,
		    opts.history_conf);
		if (hconf_write(step, keep) == -1) {
			/* Not kept: the rules as they were. */
			pthread_mutex_lock(&hist_lock);
			memcpy(rules, was, sizeof(rules));
			nrules = nwas;
			pthread_mutex_unlock(&hist_lock);
			rsp->error = wfmt(w, "%s: %s", opts.history_conf,
			    strerror(errno));
			step_end(w, st, false, "%s", strerror(errno));
			return (0);
		}
		pthread_mutex_lock(&hist_lock);
		hist_step = step;
		reshape(keep, nnets, ndisks, njails, nrelays);
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
	fprintf(fp, "{\"limits\":{\"cpu\":%u,\"mem\":%u,\"swap\":%u,"
	    "\"storage\":%u},", limits[0], limits[1], limits[2], limits[3]);
	fprintf(fp, "\"rules\":[");
	for (i = 0; i < nrules; i++)
		fprintf(fp, "%s{\"kind\":\"%s\",\"name\":\"%s\",\"limit\":%.0f,"
		    "\"over\":%s}", i > 0 ? "," : "", rule_kinds[rules[i].kind],
		    rules[i].name, rules[i].limit, rules[i].over ? "true" :
		    "false");
	fprintf(fp, "],\"racct\":%s,", racct ? "true" : "false");
	fprintf(fp, "\"step\":%u,\"keep\":%u,\"bytes\":%zu,\"ncpu\":%d,"
	    "\"mem_total\":%ju,\"swap_total\":%ju,\"fields\":[\"t\",\"cpu\","
	    "\"load\",\"mem\",\"swap\",\"rx\",\"tx\",\"read\",\"write\"],",
	    hist_step, hist_keep, rows != NULL ? hist_keep * (sizeof(*times) +
	    width * sizeof(*rows)) : 0, ncpu > 0 ? ncpu : 1,
	    (uintmax_t)mem_total, (uintmax_t)swap_total);
	names(fp, "nets", nets, nnets);
	names(fp, "disks", disks, ndisks);
	names(fp, "jails", jails, njails);
	names(fp, "relays", relays, nrelays);
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
