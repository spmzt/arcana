/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The intrusion detection of the SD-WAN services at this edge (the ids
 * criterion of a security policy, Arcana's own: neither MEF 88 nor MEF
 * 138 has intrusion detection among its Security Functions): Suricata,
 * a plugin the host has installed (nothing is installed by Arcana), one
 * instance per service, watching the service's UNIs, its configuration
 * written by the console with places for what the agent knows: its log
 * directory, its rules file and its pid file.  What it finds it writes
 * as eve.json, which a thread of the agent reads every second: each
 * alert an event, sdwan-ids, and the latest kept for the sdwan
 * read.  One that prevents (a divert port given) takes the UNIs' packets
 * from ipfw's divert rules instead and gives back those its rules let
 * by: while it is not running they pass nothing, so the thread says it,
 * a fault, until it runs again.  One the admin stopped (stopped: true)
 * stays in the list, kept for the next start, but is not run until it
 * is started again. Like the proxies of sdproxy.c: those named are
 * started (again when their files changed), those not named any more
 * are stopped, and the list is kept for the next start.
 */

#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <net/if.h>

#include <ctype.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	IDS_FILE	"sdwan-ids.json"
/* The Security section's own, apart: named sec-, kept in a file of
 * their own, neither group's list stopping the other's. */
#define	SEC_FILE	"security-ids.json"
/* The ruleset suricata-update keeps, in --suricata-rules. */
#define	SURICATA_RULESET	ruleset_path()
#define	IS_SEC(name)	(strncmp((name), "sec-", 4) == 0)
#define	INSTANCES_MAX	64
#define	IFS_MAX		16
#define	START_WAIT	180	/* s, for its engine to start */
#define	DIVERT_EVERY	10	/* s, ipfw read again for one down */
#define	CONF_MAX	(256 * 1024)
#define	RULES_MAX	(4 * 1024 * 1024)
#define	ALERTS_KEPT	200	/* an instance's latest, for the read */
#define	ALERTS_READ	50	/* of them, in the sdwan read */
#define	ALERTS_SECOND	50	/* events a second, at most, per instance */
#define	LINE_MAX_EVE	(64 * 1024)

/* Its statistics, each eve.json stats record a point (totals), the
 * latest STATS_KEPT of them: an hour at the 10 s Suricata is told. */
#define	STATS_KEPT	360
static const char *const stat_fields[] = { "t", "uptime", "packets",
    "drops", "bytes", "alerts", "invalid", "sessions", "flows", "memuse" };
#define	STATS_N		nitems(stat_fields)
struct spoint {
	int64_t	v[10];
};

struct instance {
	char	 name[40];
	char	 ifs[IFS_MAX][IFNAMSIZ];
	int	 nifs;
	int	 divert;		/* its divert port, prevent; 0 detect */
	bool	 down;			/* one that prevents, told not running */
	int	 sev;			/* told as: 0 not, 1 Warning, 2 Critical */
	time_t	 checked;		/* when ipfw was read for its port */
	bool	 diverted;		/* a rule of ipfw's diverts to its port */
	bool	 stopped;		/* stopped by the admin, kept */
	bool	 netmap;		/* by netmap(4), not pcap(3) */
	bool	 nooffload;		/* its interfaces' offloading off */
	off_t	 off;			/* how far its eve.json is read */
	char	*alerts[ALERTS_KEPT];	/* a ring, newest at head - 1 */
	int	 head, nalerts;
	uint64_t seen;			/* alerts read since it started */
	struct spoint *stats;		/* a ring, STATS_KEPT, or NULL */
	int	 shead, nstats;
	char	*app;			/* app_layer.flow of the latest, JSON */
};

static ucl_object_t	*parse(const char *);
static const char	*suricata_replay_check(const struct arc_job_spec *);
static int		 suricata_replay(struct work *,
			    const struct arc_job_spec *, const char **);
static bool		 lua_ok(struct work *, const char *,
			    const ucl_object_t *, const char **);
static bool		 lua_sync(struct work *, const char *,
			    const ucl_object_t *);
static bool		 plugins_ok(struct work *, const char *,
			    const ucl_object_t *, const char **);

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
/* One apply at a time, the table's lock taken only to read or change
 * the table: the slow work (suricata -T, a start) holds no reader. */
static pthread_mutex_t	apply_lock = PTHREAD_MUTEX_INITIALIZER;
static bool		applying;	/* instances stop and start: no fault */

/* What the table held of a group when an apply began: its names and
 * divert ports, read under the lock, used without it. */
struct was {
	char	name[40];
	int	divert;
};
static struct instance	instances[INSTANCES_MAX];
static int		ninstances;
static bool		reading;

static bool
name_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 32)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '-')
			return (false);
	return (true);
}

static bool
ifname_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) >= IFNAMSIZ)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '.' && s[i] != '_' &&
		    !(s[i] == '^' && s[i + 1] == '\0' && i > 0))
			return (false);
	return (true);
}

/*
 * Its interfaces' checksum, segmentation and receive offloading off,
 * as Suricata needs to see packets as they are on the wire (netmap(4)
 * the more so); ifconfig(8), each at its start.  em0^, netmap's name
 * of em0's host stack, is em0.
 */
static void
offload_off(struct work *w, const struct instance *in)
{
	struct execres	 res;
	char		*argv[12], ifn[IFNAMSIZ];
	int		 i, step;

	for (i = 0; i < in->nifs; i++) {
		snprintf(ifn, sizeof(ifn), "%.*s", (int)strcspn(in->ifs[i], "^"),
		    in->ifs[i]);
		step = step_begin(w, ARC_STEP_KIND_EXEC, "ifconfig",
		    "%s: checksum, TSO and LRO offloading off", ifn);
		argv[0] = (char *)(uintptr_t)opts.ifconfig_bin;
		argv[1] = ifn;
		argv[2] = (char *)(uintptr_t)"-rxcsum";
		argv[3] = (char *)(uintptr_t)"-txcsum";
		argv[4] = (char *)(uintptr_t)"-rxcsum6";
		argv[5] = (char *)(uintptr_t)"-txcsum6";
		argv[6] = (char *)(uintptr_t)"-tso";
		argv[7] = (char *)(uintptr_t)"-lro";
		argv[8] = (char *)(uintptr_t)"-vlanhwtso";
		argv[9] = NULL;
		step_end(w, step, run_exec(w, argv, &res) == 0, NULL);
	}
}

/* Where an instance's files are: beside the agent's kept files. */
static void
ids_pathbuf(const char *name, const char *ext, char *buf, size_t len)
{
	char	f[96], rel[MAXPATHLEN], cwd[MAXPATHLEN];

	snprintf(f, sizeof(f), "sdwan-ids-%s.%s", name, ext);
	sdwan_conf_path(f, rel, sizeof(rel));
	/* Whole: Suricata reads a relative rule file as of its
	 * default-rule-path, not of where it runs. */
	if (rel[0] != '/' && getcwd(cwd, sizeof(cwd)) != NULL)
		snprintf(buf, len, "%s/%s", cwd, rel);
	else
		snprintf(buf, len, "%s", rel);
}

static const char *
inst_path(struct work *w, const char *name, const char *ext)
{
	char	buf[MAXPATHLEN];

	ids_pathbuf(name, ext, buf, sizeof(buf));
	return (wstrdup(w, buf));
}

static const char *
suricata_bin(struct work *w)
{
	const char	*p;

	if ((p = tool(w, "suricata")) != NULL)
		return (p);
	return (opts.suricata_bin);
}

/* Whether an instance's process is there, by its pid file. */
static bool
running(const char *name)
{
	FILE	*fp;
	char	 path[MAXPATHLEN];
	long	 pid = 0;

	ids_pathbuf(name, "pid", path, sizeof(path));
	if ((fp = fopen(path, "r")) == NULL)
		return (false);
	if (fscanf(fp, "%ld", &pid) != 1)
		pid = 0;
	fclose(fp);
	return (pid_alive((pid_t)pid));
}

static pid_t
inst_pid(struct work *w, const char *name)
{

	return (pidfile_of(inst_path(w, name, "pid"), suricata_bin(w)));
}

static void
inst_stop(struct work *w, const char *name)
{
	pid_t	pid;

	if ((pid = inst_pid(w, name)) == 0)
		return;
	pid_stop(pid, suricata_bin(w), 5000);
	(void)unlink(inst_path(w, name, "pid"));
}

/*
 * One of Suricata's own files in its etc directory: as it is named, or
 * the port's sample of it, which is all a fresh install has.
 */
static const char *
suricata_etc(struct work *w, const char *file)
{
	const char	*p;

	p = wfmt(w, "%s/%s", SURICATA_ETC, file);
	if (access(p, R_OK) == 0)
		return (p);
	if (access(wfmt(w, "%s.sample", p), R_OK) == 0)
		return (wfmt(w, "%s.sample", p));
	return (p);
}

/*
 * Why suricata -T refused, from what it said: its error lines (E:), or
 * the end of what it wrote, or that it said nothing.
 */
/* What suricata said, both of its outputs: its errors go to the one,
 * the rest to the other. */
static char *
said(struct work *w, const struct execres *res)
{

	return (wfmt(w, "%.*s\n%.*s", (int)res->outlen, res->outlen > 0 ?
	    res->out : "", (int)res->errlen, res->errlen > 0 ? res->err : ""));
}

static const char *
suricata_errors(struct work *w, const struct execres *res)
{
	const char	*t;
	char		*out, *copy, *line;
	size_t		 n;
	int		 pass;

	t = said(w, res);
	if (t[strspn(t, " \n")] == '\0')
		return ("no reason given");
	out = wcalloc(w, 1, 1024);
	n = 0;
	/* Its errors; else what it warned of (a rule file not there). */
	for (pass = 0; pass < 2 && n == 0; pass++) {
		copy = wstrdup(w, t);
		while ((line = strsep(&copy, "\n")) != NULL && n < 1000) {
			if (pass == 0 ? strncmp(line, "E: ", 3) == 0 ||
			    strstr(line, "Error:") != NULL || strstr(line,
			    "could not open") != NULL : strncmp(line, "W: ", 3) ==
			    0 && strstr(line, "stats are enabled") == NULL)
				n += (size_t)snprintf(out + n, 1024 - n, "%s%s",
				    n > 0 ? "; " : "", line);
		}
	}
	if (n > 0)
		return (out);
	n = strlen(t);
	return (n > 600 ? t + n - 600 : t);
}

static char		ruleset_buf[MAXPATHLEN];
static pthread_once_t	ruleset_once = PTHREAD_ONCE_INIT;

static void
ruleset_init(void)
{

	snprintf(ruleset_buf, sizeof(ruleset_buf), "%s/suricata.rules",
	    opts.suricata_rules);
}

static const char *
ruleset_path(void)
{

	(void)pthread_once(&ruleset_once, ruleset_init);
	return (ruleset_buf);
}

/* For surules.c: an instance's name, and its command socket. */
bool
suricata_name_ok(const char *s)
{

	return (name_ok(s));
}

const char *
suricata_socket(struct work *w, const char *name)
{

	return (inst_path(w, name, "sock"));
}

/* Where suricata-update writes the ruleset, for surules.c. */
const char *
suricata_ruleset(void)
{

	return (ruleset_path());
}

/*
 * Did suricata -T refuse only rules of the ruleset it cannot parse here
 * (those that negate a HOME_NET of any: !any is nothing)?  Running, it
 * leaves such rules out and goes on, so they do not stop the instance;
 * their count and the first reason, for the step.  A rule of the
 * instance's own that does not parse, or anything else, refuses it.
 */
static const char *
ruleset_only(struct work *w, const struct execres *res)
{
	const char	*from, *why;
	char		*copy, *line;
	size_t		 bad;
	bool		 failed;

	copy = said(w, res);
	from = wfmt(w, "from file %s ", SURICATA_RULESET);
	bad = 0;
	failed = false;
	why = NULL;
	while ((line = strsep(&copy, "\n")) != NULL) {
		if (strncmp(line, "E: ", 3) != 0)
			continue;
		if (strstr(line, "error parsing signature") != NULL) {
			if (strstr(line, from) == NULL)
				return (NULL);
			bad++;
		} else if (strncmp(line, "E: suricata: Loading signatures "
		    "failed", 38) == 0)
			failed = true;
		else if (strncmp(line, "E: detect", 9) == 0) {
			if (why == NULL)
				why = line + 3;
		} else
			return (NULL);
	}
	if (bad == 0 || !failed)
		return (NULL);
	if (why != NULL && strstr(why, "Complete IP space negated") != NULL)
		why = "they say what is outside HOME_NET, and with home any "
		    "nothing is (give the networks it guards to keep them)";
	return (wfmt(w, "%zu rule%s of the ruleset left out, as Suricata does "
	    "when it runs: %s", bad, bad == 1 ? "" : "s", why != NULL ? why :
	    "they do not parse with these networks"));
}

/* An instance's configuration: the console's text, the places filled. */
static char *
inst_conf(struct work *w, const char *name, const char *conf)
{
	const char	*from[] = { "@LOGDIR@", "@RULES@", "@PID@",
			    "@CLASSIFICATION@", "@REFERENCE@", "@RULESET@",
			    "@THRESHOLD@", "@SOCKET@", "@LUADIR@" },
			*to[9];
	char		*p, *l, *e;

	/* The ruleset not fetched yet: its line out, the instance's own
	 * rules alone. */
	if (access(SURICATA_RULESET, R_OK) != 0 && (l = strstr(conf,
	    "@RULESET@")) != NULL) {
		p = wstrdup(w, conf);
		l = p + (l - conf);
		while (l > p && l[-1] != '\n')
			l--;
		e = strchr(l, '\n');
		memmove(l, e != NULL ? e + 1 : l + strlen(l), strlen(e != NULL ?
		    e + 1 : l + strlen(l)) + 1);
		conf = p;
	}
	to[0] = inst_path(w, name, "d");
	to[1] = inst_path(w, name, "rules");
	to[2] = inst_path(w, name, "pid");
	to[3] = suricata_etc(w, "classification.config");
	to[4] = suricata_etc(w, "reference.config");
	to[5] = SURICATA_RULESET;
	to[6] = inst_path(w, name, "threshold");
	to[7] = inst_path(w, name, "sock");
	to[8] = inst_path(w, name, "lua");
	return ((char *)(uintptr_t)sdwan_subst(w, conf, from, to,
	    nitems(from)));
}

/* A file's whole text, or NULL. */
static char *
file_text(struct work *w, const char *path)
{
	FILE	*fp;
	char	*t;
	long	 n;

	if ((fp = fopen(path, "r")) == NULL)
		return (NULL);
	if (fseek(fp, 0, SEEK_END) != 0 || (n = ftell(fp)) < 0 || n >
	    RULES_MAX + CONF_MAX || fseek(fp, 0, SEEK_SET) != 0) {
		fclose(fp);
		return (NULL);
	}
	t = wcalloc(w, 1, (size_t)n + 1);
	if (fread(t, 1, (size_t)n, fp) != (size_t)n) {
		fclose(fp);
		return (NULL);
	}
	fclose(fp);
	return (t);
}

/*
 * Started, as a daemon: on the interfaces its configuration names by
 * libpcap (detect), or on its divert port, where ipfw's divert rules
 * hand it the UNIs' packets (prevent).
 */
/*
 * Interface any, alone, in the pcap list: FreeBSD's libpcap has no any
 * device, so it is every interface that is up, but the loopback, pflog,
 * pfsync and enc.  NULL, with errp,
 * when there is none.
 */
static char *
expand_any(struct work *w, char *conf, const char **errp)
{
	static const char *const skip[] = { "lo", "pflog", "pfsync", "enc" };
	struct ifaddrs	*ifa, *i;
	char		*at, *out, *list;
	size_t		 k, n;
	const char	*line = "  - interface: any\n";

	if ((at = strstr(conf, line)) == NULL || (at != conf && at[-1] !=
	    '\n'))
		return (conf);
	if (getifaddrs(&ifa) == -1) {
		*errp = wfmt(w, "getifaddrs: %s", strerror(errno));
		return (NULL);
	}
	list = wstrdup(w, "");
	n = 0;
	for (i = ifa; i != NULL; i = i->ifa_next) {
		if (i->ifa_addr == NULL || i->ifa_addr->sa_family != AF_LINK ||
		    (i->ifa_flags & IFF_UP) == 0)
			continue;
		for (k = 0; k < nitems(skip); k++)
			if (strncmp(i->ifa_name, skip[k], strlen(skip[k])) == 0 &&
			    isdigit((unsigned char)i->ifa_name[strlen(skip[k])]))
				break;
		if (k < nitems(skip))
			continue;
		list = wfmt(w, "%s  - interface: %s\n", list, i->ifa_name);
		n++;
	}
	freeifaddrs(ifa);
	if (n == 0) {
		*errp = "interface any: no interface is up here but the "
		    "loopback";
		return (NULL);
	}
	out = wfmt(w, "%.*s%s%s", (int)(at - conf), conf, list, at +
	    strlen(line));
	return (out);
}

/* How long the instance's suricata.log is: where a start's lines begin. */
static long
log_size(struct work *w, const char *name)
{
	struct stat	sb;

	return (stat(wfmt(w, "%s/suricata.log", inst_path(w, name, "d")),
	    &sb) == 0 ? (long)sb.st_size : 0);
}

/*
 * Why an instance did not start, as its suricata.log says: the first
 * and the last errors written from from on, by this start (not -T's
 * before it, which logs there too, nor an earlier start's), or NULL.
 * The rules it left out are not why: it goes on without them.
 */
static const char *
log_errors(struct work *w, const char *name, long from)
{
	FILE		*fp;
	char		 buf[512], *first, *last;
	const char	*p;
	long		 size;
	int		 n;

	if ((fp = fopen(wfmt(w, "%s/suricata.log", inst_path(w, name, "d")),
	    "r")) == NULL)
		return (NULL);
	if (fseek(fp, 0, SEEK_END) == 0 && (size = ftell(fp)) > from + 65536)
		from = size - 65536;
	(void)fseek(fp, from, SEEK_SET);
	first = last = NULL;
	n = 0;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		buf[strcspn(buf, "\n")] = '\0';
		if ((p = strstr(buf, "Error: ")) == NULL && (p = strstr(buf,
		    "<Error>")) == NULL && strncmp(p = buf, "E: ", 3) != 0)
			continue;
		if (strstr(p, "error parsing signature") != NULL ||
		    strstr(p, "Complete IP space negated") != NULL ||
		    strstr(p, "Loading signatures failed") != NULL)
			continue;
		last = wstrdup(w, p);
		if (n++ == 0)
			first = last;
	}
	fclose(fp);
	if (n == 0)
		return (NULL);
	return (n > 1 ? wfmt(w, "%s; %s", first, last) : last);
}

/* Did its log say, from from on, that its engine started, or failed? */
static int
log_started(struct work *w, const char *name, long from)
{
	FILE	*fp;
	char	 buf[512];
	int	 r;

	if ((fp = fopen(wfmt(w, "%s/suricata.log", inst_path(w, name, "d")),
	    "r")) == NULL)
		return (0);
	(void)fseek(fp, from, SEEK_SET);
	r = 0;
	while (r == 0 && fgets(buf, sizeof(buf), fp) != NULL)
		if (strstr(buf, "Engine started") != NULL)
			r = 1;
		else if (strstr(buf, "initialization failed") != NULL ||
		    strstr(buf, "aborting") != NULL)
			r = -1;
	fclose(fp);
	return (r);
}

/*
 * ipfw's divert sockets, divert(4), are ipdivert.ko's: loaded for one
 * that prevents, as Suricata cannot open its port without them (it
 * says "Address family not supported" and stops).  Not kept in
 * kld_list: the agent loads it again when it starts the instance.
 */
static int
divert_ready(struct work *w, const char **errp)
{
	struct execres	 res;
	char		*argv[4];
	int		 step;

	if (kmod_loaded("ipdivert"))
		return (0);
	step = step_begin(w, ARC_STEP_KIND_EXEC, "kldload",
	    "ipdivert, for ipfw divert");
	argv[0] = (char *)(uintptr_t)opts.kldload_bin;
	argv[1] = (char *)(uintptr_t)"-n";
	argv[2] = (char *)(uintptr_t)"ipdivert";
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wfmt(w, "ipfw divert needs ipdivert.ko: %s",
		    exec_error(w, &res, "kldload"));
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, NULL);
	return (0);
}

static int
inst_start(struct work *w, const char *name, int divert, bool netmap,
    const char **errp)
{
	struct execres	 res;
	char		*argv[10];
	long		 from;
	int		 n, i, started;

	started = 0;
	(void)mkdir(inst_path(w, name, "d"), 0750);
	if (divert > 0 && divert_ready(w, errp) != 0)
		return (-1);
	/* A pid file of one that is not running (a start that failed, a
	 * crash) keeps Suricata from starting: it is not ours to keep. */
	if (inst_pid(w, name) == 0)
		(void)unlink(inst_path(w, name, "pid"));
	from = log_size(w, name);
	n = 0;
	argv[n++] = (char *)(uintptr_t)suricata_bin(w);
	argv[n++] = (char *)(uintptr_t)"-c";
	argv[n++] = (char *)(uintptr_t)inst_path(w, name, "yaml");
	argv[n++] = (char *)(uintptr_t)"--pidfile";
	argv[n++] = (char *)(uintptr_t)inst_path(w, name, "pid");
	if (divert > 0) {
		argv[n++] = (char *)(uintptr_t)"-d";
		argv[n++] = wfmt(w, "%d", divert);
	} else
		argv[n++] = (char *)(uintptr_t)(netmap ? "--netmap" : "--pcap");
	argv[n++] = (char *)(uintptr_t)"-D";
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		/* Daemonized, it says why in its own log, not here. */
		if ((*errp = log_errors(w, name, from)) != NULL)
			*errp = wfmt(w, "suricata did not start: %s", *errp);
		else
			*errp = wtext(w, exec_error(w, &res, "suricata"));
		return (-1);
	}
	/*
	 * It forks and writes its pid file, then loads its rules and opens
	 * its capture or its divert port: up once its log says its engine
	 * started, not when the pid file is there (it may stop after).
	 * One still loading after START_WAIT is taken as up; the reader
	 * says so if it stops.
	 */
	for (i = 0; i < START_WAIT * 10; i++) {
		if ((started = log_started(w, name, from)) != 0)
			break;
		if (i >= 30 && inst_pid(w, name) == 0)
			break;
		usleep(100000);
	}
	if (started < 0 || inst_pid(w, name) == 0) {
		*errp = (*errp = log_errors(w, name, from)) != NULL ? wfmt(w,
		    "suricata did not start: %s", *errp) : wfmt(w, "suricata "
		    "did not start: see %s", inst_path(w, name, "d"));
		return (-1);
	}
	return (0);
}

static void
alerts_free(struct instance *in)
{
	int	i;

	for (i = 0; i < ALERTS_KEPT; i++) {
		free(in->alerts[i]);
		in->alerts[i] = NULL;
	}
	in->head = in->nalerts = 0;
	free(in->stats);
	in->stats = NULL;
	in->shead = in->nstats = 0;
	free(in->app);
	in->app = NULL;
}

static int64_t
stat_num(const ucl_object_t *o, const char *path)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup_path(o, path);
	return (v != NULL && (ucl_object_type(v) == UCL_INT ||
	    ucl_object_type(v) == UCL_FLOAT) ? ucl_object_toint(v) : -1);
}

/*
 * A stats record of eve.json into the instance's ring: what it
 * captured (or decoded, where it takes packets by divert), dropped,
 * alerted on and holds, Suricata's totals since it started.
 */
static bool
stats_take(struct instance *in, const char *line)
{
	ucl_object_t		*o;
	const ucl_object_t	*st, *app;
	struct spoint		*p;
	struct tm		 tm;
	const char		*ts;
	int64_t			 v;

	if (strstr(line, "\"event_type\":\"stats\"") == NULL ||
	    (o = parse(line)) == NULL)
		return (false);
	if ((st = ucl_object_lookup(o, "stats")) == NULL) {
		ucl_object_unref(o);
		return (false);
	}
	if (in->stats == NULL && (in->stats = calloc(STATS_KEPT,
	    sizeof(*in->stats))) == NULL) {
		ucl_object_unref(o);
		return (true);
	}
	p = &in->stats[in->shead];
	memset(&tm, 0, sizeof(tm));
	ts = ucl_object_tostring_forced(ucl_object_lookup(o, "timestamp"));
	p->v[0] = ts != NULL && strptime(ts, "%Y-%m-%dT%H:%M:%S", &tm) !=
	    NULL ? (int64_t)timegm(&tm) : (int64_t)time(NULL);
	p->v[1] = stat_num(st, "uptime");
	p->v[2] = (v = stat_num(st, "capture.kernel_packets")) >= 0 ? v :
	    stat_num(st, "decoder.pkts");
	p->v[3] = stat_num(st, "capture.kernel_drops");
	p->v[4] = stat_num(st, "decoder.bytes");
	p->v[5] = stat_num(st, "detect.alert");
	p->v[6] = stat_num(st, "decoder.invalid");
	p->v[7] = stat_num(st, "tcp.sessions");
	p->v[8] = stat_num(st, "flow.total");
	p->v[9] = 0;
	if ((v = stat_num(st, "flow.memuse")) > 0)
		p->v[9] += v;
	if ((v = stat_num(st, "tcp.memuse")) > 0)
		p->v[9] += v;
	if ((v = stat_num(st, "tcp.reassembly_memuse")) > 0)
		p->v[9] += v;
	if ((v = stat_num(st, "http.memuse")) > 0)
		p->v[9] += v;
	in->shead = (in->shead + 1) % STATS_KEPT;
	if (in->nstats < STATS_KEPT)
		in->nstats++;
	/* Its flows by protocol, as the latest says. */
	if ((app = ucl_object_lookup_path(st, "app_layer.flow")) != NULL) {
		free(in->app);
		in->app = (char *)ucl_object_emit(app, UCL_EMIT_JSON_COMPACT);
	}
	ucl_object_unref(o);
	return (true);
}

static ucl_object_t *
parse(const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	return (o);
}

/* A string of eve.json's, made safe for the JSON of an event. */
static void
jstr(char *out, size_t len, const ucl_object_t *o, const char *key)
{
	const char	*s;
	size_t		 n;

	s = ucl_object_lookup(o, key) != NULL ? ucl_object_tostring_forced(
	    ucl_object_lookup(o, key)) : "";
	for (n = 0; *s != '\0' && n + 2 < len; s++)
		if ((unsigned char)*s >= 0x20 && *s != '"' && *s != '\\')
			out[n++] = *s;
	out[n] = '\0';
}

/*
 * One line of eve.json: an alert, as the JSON the event and the read
 * carry ({"name", "time", "src", "sport", "dst", "dport", "proto",
 * "iface", "sid", "rev", "signature", "category", "severity",
 * "action"}); NULL for any other line.
 */
static char *
alert_json(const char *name, const char *line)
{
	ucl_object_t		*o;
	const ucl_object_t	*a;
	char			 t[64], src[64], dst[64], proto[16], ifc[32];
	char			 sig[512], cat[256], act[16], *out;

	if ((o = parse(line)) == NULL)
		return (NULL);
	if (ucl_object_lookup(o, "event_type") == NULL || strcmp(
	    ucl_object_tostring_forced(ucl_object_lookup(o, "event_type")),
	    "alert") != 0 || (a = ucl_object_lookup(o, "alert")) == NULL) {
		ucl_object_unref(o);
		return (NULL);
	}
	jstr(t, sizeof(t), o, "timestamp");
	jstr(src, sizeof(src), o, "src_ip");
	jstr(dst, sizeof(dst), o, "dest_ip");
	jstr(proto, sizeof(proto), o, "proto");
	jstr(ifc, sizeof(ifc), o, "in_iface");
	jstr(sig, sizeof(sig), a, "signature");
	jstr(cat, sizeof(cat), a, "category");
	jstr(act, sizeof(act), a, "action");
	if (asprintf(&out, "{\"name\":\"%s\",\"time\":\"%s\",\"src\":\"%s\","
	    "\"sport\":%jd,\"dst\":\"%s\",\"dport\":%jd,\"proto\":\"%s\","
	    "\"iface\":\"%s\",\"sid\":%jd,\"rev\":%jd,\"signature\":\"%s\","
	    "\"category\":\"%s\",\"severity\":%jd,\"action\":\"%s\"}", name, t,
	    src, (intmax_t)ucl_object_toint(ucl_object_lookup(o, "src_port")),
	    dst, (intmax_t)ucl_object_toint(ucl_object_lookup(o, "dest_port")),
	    proto, ifc, (intmax_t)ucl_object_toint(ucl_object_lookup(a,
	    "signature_id")), (intmax_t)ucl_object_toint(ucl_object_lookup(a,
	    "rev")), sig, cat, (intmax_t)ucl_object_toint(ucl_object_lookup(a,
	    "severity")), act) == -1)
		out = NULL;
	ucl_object_unref(o);
	return (out);
}

static void
eve_path(const char *name, char *buf, size_t len)
{

	ids_pathbuf(name, "d", buf, len);
	strlcat(buf, "/eve.json", len);
}

/* How long an instance's eve.json is, 0 when it has none. */
static off_t
eve_size(const char *name)
{
	struct stat	st;
	char		path[MAXPATHLEN];

	eve_path(name, path, sizeof(path));
	return (stat(path, &st) == 0 ? st.st_size : 0);
}

/* What an instance wrote since it was last read: its alerts. */
static void
read_eve(struct instance *in)
{
	struct stat	 st;
	FILE		*fp;
	char		 path[MAXPATHLEN], *line, *a;
	size_t		 cap;
	ssize_t		 n;
	int		 told;

	/* Opened first, then sized: the file read is the file sized. */
	eve_path(in->name, path, sizeof(path));
	if ((fp = fopen(path, "r")) == NULL)
		return;
	if (fstat(fileno(fp), &st) != 0) {
		fclose(fp);
		return;
	}
	if (st.st_size < in->off)	/* turned over, or made anew */
		in->off = 0;
	if (st.st_size == in->off || fseeko(fp, in->off, SEEK_SET) != 0) {
		fclose(fp);
		return;
	}
	line = NULL;
	cap = 0;
	told = 0;
	while ((n = getline(&line, &cap, fp)) > 0) {
		if (line[n - 1] != '\n')	/* half written: next time */
			break;
		in->off += n;
		if (n > LINE_MAX_EVE || stats_take(in, line) ||
		    (a = alert_json(in->name, line)) == NULL)
			continue;
		in->seen++;
		if (told++ < ALERTS_SECOND)
			event_add("sdwan-ids", "%s", a);
		free(in->alerts[in->head]);
		in->alerts[in->head] = a;
		in->head = (in->head + 1) % ALERTS_KEPT;
		if (in->nalerts < ALERTS_KEPT)
			in->nalerts++;
	}
	free(line);
	fclose(fp);
}

/* Does a rule of ipfw's divert (or tee) to port? */
static bool
diverts_to(int port)
{
	struct work	 w;
	struct execres	 res;
	char		*argv[3], *p, *line, *want[2];
	bool		 found;

	work_init(&w);
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"list";
	argv[2] = NULL;
	found = false;
	want[0] = wfmt(&w, " divert %d ", port);
	want[1] = wfmt(&w, " tee %d ", port);
	if (run_exec_max(&w, argv, &res, 16 * 1024 * 1024) == 0 &&
	    res.out != NULL) {
		p = wstrndup(&w, res.out, res.outlen);
		while (!found && (line = strsep(&p, "\n")) != NULL)
			found = strstr(line, want[0]) != NULL ||
			    strstr(line, want[1]) != NULL;
	}
	work_free(&w);
	return (found);
}

/*
 * One that prevents and is not running: what ipfw diverts to its port
 * goes to no one and passes not, which is said as a Critical fault
 * until it runs again; while no rule diverts to it, nothing is held
 * up, and it is a Warning.  ipfw is read again every DIVERT_EVERY s
 * while it is down, so a rule added meanwhile makes it Critical.
 */
static void
guard(struct instance *in)
{
	time_t	now;
	bool	up;
	int	sev;

	/* Stopped and started again by an apply: not down. */
	if (applying)
		return;
	if (in->divert == 0)
		return;
	up = running(in->name);
	if (up) {
		if (in->sev != 0)
			fault_clear("ids", in->name, "Suricata %s runs again",
			    in->name);
		in->sev = 0;
		in->down = false;
		return;
	}
	now = time(NULL);
	if (!in->down || now - in->checked >= DIVERT_EVERY) {
		in->diverted = diverts_to(in->divert);
		in->checked = now;
	}
	in->down = true;
	sev = in->diverted ? 2 : 1;
	if (sev == in->sev)
		return;
	/* Told before at another severity (by this agent or, kept, by
	 * the one before it): cleared, and told again. */
	fault_clear("ids", in->name, "Suricata %s: %s", in->name, sev == 2 ?
	    "ipfw diverts to it now" : "ipfw diverts nothing to it now");
	if (sev == 2)
		fault_set("ids", "Critical", in->name, "suricata", "Suricata %s, "
		    "which prevents, is not running: what ipfw diverts to it "
		    "passes not (divert %d)", in->name, in->divert);
	else
		fault_set("ids", "Warning", in->name, "suricata", "Suricata %s, "
		    "which prevents, is not running; no rule of ipfw's diverts "
		    "to it (divert %d), so nothing is held up yet", in->name,
		    in->divert);
	in->sev = sev;
}

static void *
reader(void *arg __unused)
{
	int	i;

	for (;;) {
		sleep(1);
		pthread_mutex_lock(&lock);
		for (i = 0; i < ninstances; i++) {
			read_eve(&instances[i]);
			guard(&instances[i]);
		}
		pthread_mutex_unlock(&lock);
	}
	return (NULL);
}

/* The divert port an instance runs with now (the lock held); -1 when
 * it is not one of them. */
static int
divert_was(const struct was *was, int nwas, const char *name)
{
	int	i;

	for (i = 0; i < nwas; i++)
		if (strcmp(was[i].name, name) == 0)
			return (was[i].divert);
	return (-1);
}

/* A file of the instance's, written whole: a new one moved over it. */
static int
put_text(const char *path, const char *text, const char **errp)
{
	char	tmp[MAXPATHLEN];
	FILE	*fp;

	snprintf(tmp, sizeof(tmp), "%s.new", path);
	if ((fp = fopen(tmp, "we")) == NULL || fputs(text, fp) == EOF ||
	    fclose(fp) != 0 || rename(tmp, path) != 0) {
		*errp = strerror(errno);
		(void)unlink(tmp);
		return (-1);
	}
	return (0);
}

/* Its Lua scripts: 16 at most, each NAME.lua of 64 KB at most. */
static bool
lua_ok(struct work *w, const char *name, const ucl_object_t *lua,
    const char **errp)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*k;
	size_t			 n, len;

	if (lua == NULL)
		return (true);
	if (ucl_object_type(lua) != UCL_OBJECT) {
		*errp = wfmt(w, "%s: its lua is scripts by name", name);
		return (false);
	}
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(lua, &it, true)) != NULL) {
		k = ucl_object_key(e);
		len = strlen(k);
		if (++n > 16 || len < 5 || len > 36 || strcmp(k + len - 4,
		    ".lua") != 0 || strspn(k, "abcdefghijklmnopqrstuvwxyz"
		    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != len - 4 ||
		    ucl_object_type(e) != UCL_STRING ||
		    strlen(ucl_object_tostring(e)) > 64 * 1024) {
			*errp = wfmt(w, "%s: its Lua scripts are NAME.lua of "
			    "letters, digits, _ and -, 64 KB each, 16 at most",
			    name);
			return (false);
		}
	}
	return (true);
}

/*
 * Its Lua scripts into its own directory, those not named any more
 * taken away (lua NULL: all of them).  True when one changed.
 */
static bool
lua_sync(struct work *w, const char *name, const ucl_object_t *lua)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct dirent		*de;
	DIR			*d;
	const char		*dir, *path, *was, *e2;
	bool			 changed;

	changed = false;
	dir = inst_path(w, name, "lua");
	if ((d = opendir(dir)) != NULL) {
		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] == '.')
				continue;
			if (lua != NULL && ucl_object_lookup(lua, de->d_name) !=
			    NULL)
				continue;
			(void)unlink(wfmt(w, "%s/%s", dir, de->d_name));
			changed = true;
		}
		closedir(d);
	}
	if (lua == NULL || ucl_object_type(lua) != UCL_OBJECT)
		return (changed);
	(void)mkdir(dir, 0750);
	it = NULL;
	while ((e = ucl_object_iterate(lua, &it, true)) != NULL) {
		path = wfmt(w, "%s/%s", dir, ucl_object_key(e));
		was = file_text(w, path);
		if (was != NULL && strcmp(was, ucl_object_tostring(e)) == 0)
			continue;
		e2 = NULL;
		if (put_text(path, ucl_object_tostring(e), &e2) == 0)
			changed = true;
	}
	return (changed);
}

/*
 * Its plugins: shared objects under /usr/local/lib, root's alone and
 * written by none but root, else none is loaded.
 */
static bool
plugins_ok(struct work *w, const char *name, const ucl_object_t *pl,
    const char **errp)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct stat		 sb;
	const char		*p;

	if (pl == NULL)
		return (true);
	it = NULL;
	while ((e = ucl_object_iterate(pl, &it, true)) != NULL) {
		p = ucl_object_type(e) == UCL_STRING ? ucl_object_tostring(e) :
		    "";
		if (strncmp(p, "/usr/local/lib/", 15) != 0 || strstr(p,
		    "/../") != NULL || strlen(p) < 19 || strcmp(p + strlen(p) -
		    3, ".so") != 0) {
			*errp = wfmt(w, "%s: a plugin is a .so under "
			    "/usr/local/lib", name);
			return (false);
		}
		if (lstat(p, &sb) != 0 || !S_ISREG(sb.st_mode) ||
		    sb.st_uid != 0 || (sb.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
			*errp = wfmt(w, "%s: the plugin %s is not there, or not "
			    "root's alone", name, p);
			return (false);
		}
	}
	return (true);
}

/*
 * The instances applied: {"instances": [{"name", "interfaces", "conf",
 * "rules", "thresholds", "stopped"}, ...]}.  Suricata must be there (a plugin); each instance's
 * files are written, checked by suricata -T, and it is started, again
 * when they changed; those not named any more are stopped.  Kept for
 * the next start.
 */
int
do_sdwan_ids(struct work *w, const char *json, const char **errp)
{
	ucl_object_t		*top;
	const ucl_object_t	*in, *v, *f;
	ucl_object_iter_t	 it, fit;
	struct instance		 ni[INSTANCES_MAX];
	struct execres		 res;
	char			*argv[8], *conf, *was;
	const char		*rules, *thr, *e, *note, *what;
	const char		*raw;
	struct was		 held[INSTANCES_MAX];
	int			 n, i, k, step, nkeep, nheld;
	bool			 ok, same, samerun, sec, luach;

	if ((top = parse(json)) == NULL || ucl_object_type(top) != UCL_OBJECT) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the instances are an object: instances, each a name, "
		    "its interfaces, its conf and its rules";
		return (-1);
	}
	sec = ucl_object_lookup(top, "group") != NULL && strcmp(
	    ucl_object_tostring_forced(ucl_object_lookup(top, "group")),
	    "security") == 0;
	memset(ni, 0, sizeof(ni));
	n = 0;
	it = NULL;
	while ((in = ucl_object_iterate(ucl_object_lookup(top, "instances"),
	    &it, true)) != NULL) {
		v = ucl_object_lookup(in, "name");
		/* Its settings (the form, rendered here), or its YAML whole
		 * with the agent's places, as arcanactl gives it. */
		if (n == INSTANCES_MAX || v == NULL || ucl_object_type(v) !=
		    UCL_STRING || !name_ok(ucl_object_tostring(v)) ||
		    (ucl_object_type(ucl_object_lookup(in, "spec")) != UCL_OBJECT
		    && (ucl_object_tostring(ucl_object_lookup(in, "conf")) == NULL
		    || strlen(ucl_object_tostring(ucl_object_lookup(in, "conf")))
		    > CONF_MAX)) || (ucl_object_lookup(in, "rules") != NULL &&
		    (ucl_object_type(ucl_object_lookup(in, "rules")) !=
		    UCL_STRING || strlen(ucl_object_tostring(ucl_object_lookup(
		    in, "rules"))) > RULES_MAX)) ||
		    (ucl_object_lookup(in, "thresholds") != NULL &&
		    (ucl_object_type(ucl_object_lookup(in, "thresholds")) !=
		    UCL_STRING || strlen(ucl_object_tostring(ucl_object_lookup(
		    in, "thresholds"))) > CONF_MAX))) {
			ucl_object_unref(top);
			*errp = wfmt(w, "an instance is a name of letters, digits, "
			    "_ and -, 32 at most, its interfaces, its conf and its "
			    "rules, %d of them at most", INSTANCES_MAX);
			return (-1);
		}
		snprintf(ni[n].name, sizeof(ni[n].name), "%s",
		    ucl_object_tostring(v));
		if (IS_SEC(ni[n].name) != sec) {
			ucl_object_unref(top);
			*errp = wfmt(w, "instance %s: the Security section's are "
			    "named sec-, SD-WAN's not", ni[n].name);
			return (-1);
		}
		if ((f = ucl_object_lookup(in, "divert")) != NULL) {
			if (ucl_object_type(f) != UCL_INT || ucl_object_toint(f) <
			    1 || ucl_object_toint(f) > 65535) {
				ucl_object_unref(top);
				*errp = wfmt(w, "%s: its divert is a port, 1 to 65535",
				    ni[n].name);
				return (-1);
			}
			ni[n].divert = (int)ucl_object_toint(f);
		}
		/* netmap(4): its interfaces, or em0^ host stacks; one that
		 * prevents at L2 by copy-mode ips, as its YAML says. */
		if ((f = ucl_object_lookup(in, "capture")) != NULL) {
			if (ucl_object_type(f) != UCL_STRING || (strcmp(
			    ucl_object_tostring(f), "pcap") != 0 && strcmp(
			    ucl_object_tostring(f), "netmap") != 0)) {
				ucl_object_unref(top);
				*errp = wfmt(w, "%s: capture is pcap or netmap",
				    ni[n].name);
				return (-1);
			}
			ni[n].netmap = strcmp(ucl_object_tostring(f), "netmap") ==
			    0;
		}
		if (!lua_ok(w, ni[n].name, ucl_object_lookup(in, "lua"), errp) ||
		    !plugins_ok(w, ni[n].name, ucl_object_lookup(in, "plugins"),
		    errp)) {
			ucl_object_unref(top);
			return (-1);
		}
		if ((f = ucl_object_lookup(in, "offload")) != NULL)
			ni[n].nooffload = ucl_object_type(f) == UCL_BOOLEAN &&
			    !ucl_object_toboolean(f);
		if ((f = ucl_object_lookup(in, "stopped")) != NULL) {
			if (ucl_object_type(f) != UCL_BOOLEAN) {
				ucl_object_unref(top);
				*errp = wfmt(w, "%s: stopped is true or false",
				    ni[n].name);
				return (-1);
			}
			ni[n].stopped = ucl_object_toboolean(f);
		}
		fit = NULL;
		while ((f = ucl_object_iterate(ucl_object_lookup(in,
		    "interfaces"), &fit, true)) != NULL) {
			if (ni[n].nifs == IFS_MAX || ucl_object_type(f) !=
			    UCL_STRING || !ifname_ok(ucl_object_tostring(f)) ||
			    (strchr(ucl_object_tostring(f), '^') != NULL &&
			    !ni[n].netmap)) {
				ucl_object_unref(top);
				*errp = wfmt(w, "%s: its interfaces are names, %d "
				    "at most (em0^, a host stack, netmap's alone)",
				    ni[n].name, IFS_MAX);
				return (-1);
			}
			snprintf(ni[n].ifs[ni[n].nifs++], IFNAMSIZ, "%s",
			    ucl_object_tostring(f));
		}
		if (ni[n].nifs == 0) {
			ucl_object_unref(top);
			*errp = wfmt(w, "%s watches no interface", ni[n].name);
			return (-1);
		}
		for (i = 0; i < n; i++)
			if (strcmp(ni[i].name, ni[n].name) == 0) {
				ucl_object_unref(top);
				*errp = wfmt(w, "instance %s is named twice",
				    ni[n].name);
				return (-1);
			}
		n++;
	}
	/* The two groups' together within the table: refused before any
	 * is started, none started and then not kept. */
	pthread_mutex_lock(&lock);
	for (i = nkeep = 0; i < ninstances; i++)
		if (IS_SEC(instances[i].name) != sec)
			nkeep++;
	pthread_mutex_unlock(&lock);
	if (nkeep + n > INSTANCES_MAX) {
		ucl_object_unref(top);
		*errp = wfmt(w, "%d instances at most, SD-WAN's and the Security "
		    "section's together: the other has %d", INSTANCES_MAX,
		    nkeep);
		return (-1);
	}
	if (n > 0 && access(suricata_bin(w), X_OK) != 0) {
		ucl_object_unref(top);
		*errp = wfmt(w, "the host has no suricata (%s): it is a plugin, "
		    "installed by hand (pkg install suricata)", suricata_bin(w));
		return (-1);
	}
	/* One apply at a time; the table read, then left to its readers
	 * while the slow work is done. */
	pthread_mutex_lock(&apply_lock);
	pthread_mutex_lock(&lock);
	applying = true;
	for (i = nheld = 0; i < ninstances; i++) {
		if (IS_SEC(instances[i].name) != sec)
			continue;
		snprintf(held[nheld].name, sizeof(held[nheld].name), "%s",
		    instances[i].name);
		held[nheld++].divert = instances[i].divert;
	}
	pthread_mutex_unlock(&lock);
	/* Those not named any more: stopped, their files gone; the other
	 * group's are not this list's. */
	for (i = 0; i < nheld; i++) {
		for (k = 0; k < n; k++)
			if (strcmp(ni[k].name, held[i].name) == 0)
				break;
		if (k == n) {
			step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
			    "suricata %s stopped", held[i].name);
			inst_stop(w, held[i].name);
			fault_clear("ids", held[i].name, "Suricata %s taken "
			    "away", held[i].name);
			(void)unlink(inst_path(w, held[i].name, "yaml"));
			(void)unlink(inst_path(w, held[i].name, "rules"));
			(void)unlink(inst_path(w, held[i].name,
			    "threshold"));
			(void)unlink(inst_path(w, held[i].name, "sock"));
			(void)lua_sync(w, held[i].name, NULL);
			(void)rmdir(inst_path(w, held[i].name, "lua"));
			step_end(w, step, true, NULL);
		}
	}
	/* One new here is read from where its eve.json ends before it
	 * starts: what was there was told before, by this agent or one
	 * before it.  Those that stay keep where they were read to. */
	for (k = 0; k < n; k++)
		ni[k].off = eve_size(ni[k].name);
	ok = true;
	it = NULL;
	for (k = 0; k < n; k++) {
		in = ucl_object_iterate(ucl_object_lookup(top, "instances"), &it,
		    true);
		/* Stopped by the admin: not run, its place kept. */
		if (ni[k].stopped) {
			step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
			    "suricata %s stopped, kept", ni[k].name);
			inst_stop(w, ni[k].name);
			step_end(w, step, true, NULL);
			continue;
		}
		/* Its YAML: given whole (arcanactl's way), or rendered from
		 * its settings, the console's. */
		e = NULL;
		if (ucl_object_tostring(ucl_object_lookup(in, "conf")) == NULL &&
		    ucl_object_type(ucl_object_lookup(in, "spec")) == UCL_OBJECT) {
			const ucl_object_t	*spec = ucl_object_lookup(in, "spec");
			ucl_object_t		*seen = ucl_object_typed_new(UCL_ARRAY);
			const char		*host, *flavor;
			char			 hn[MAXHOSTNAMELEN];

			host = ucl_object_tostring(ucl_object_lookup(in, "host"));
			if (host == NULL || strlen(host) > 64) {
				if (gethostname(hn, sizeof(hn)) != 0)
					snprintf(hn, sizeof(hn), "this host");
				host = wstrdup(w, hn);
			}
			flavor = ucl_object_tostring(ucl_object_lookup(spec,
			    "flavor"));
			conf = flavor != NULL && strcmp(flavor, "sdwan") == 0 ?
			    ids_conf_sdwan(w, spec, ni[k].name, host, seen, &e) :
			    ids_conf_render(w, spec, ni[k].name, host,
			    ni[k].divert, seen, &e);
			ucl_object_unref(seen);
			if (conf == NULL) {
				step_end(w, step_begin(w, ARC_STEP_KIND_DAEMON,
				    "arcana-agent", "suricata %s", ni[k].name),
				    false, "%s", e);
				*errp = e;
				ok = false;
				break;
			}
		} else
			conf = (char *)(uintptr_t)ucl_object_tostring(
			    ucl_object_lookup(in, "conf"));
		raw = conf;
		conf = inst_conf(w, ni[k].name, conf);
		if ((conf = expand_any(w, conf, &e)) == NULL) {
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		rules = ucl_object_lookup(in, "rules") != NULL ?
		    ucl_object_tostring(ucl_object_lookup(in, "rules")) : "";
		/* Its thresholds and suppressions, threshold.config's lines. */
		thr = ucl_object_lookup(in, "thresholds") != NULL ?
		    ucl_object_tostring(ucl_object_lookup(in, "thresholds")) :
		    "";
		/* Its Lua scripts written first: suricata -T loads them. */
		luach = lua_sync(w, ni[k].name, ucl_object_lookup(in, "lua"));
		/* Running with the same files: left as it is.  With only
		 * its rules or thresholds new: they are read again live
		 * (SIGUSR2, as after the ruleset's update), not a restart. */
		was = file_text(w, inst_path(w, ni[k].name, "yaml"));
		samerun = was != NULL && strcmp(was, conf) == 0 &&
		    inst_pid(w, ni[k].name) != 0 && divert_was(held, nheld,
		    ni[k].name) == ni[k].divert && !luach;
		same = samerun && (was = file_text(w, inst_path(w, ni[k].name,
		    "rules"))) != NULL && strcmp(was, rules) == 0 &&
		    strcmp((was = file_text(w, inst_path(w, ni[k].name,
		    "threshold"))) != NULL ? was : "", thr) == 0;
		what = wfmt(w, "suricata %s on %d interface%s, %s: %s",
		    ni[k].name, ni[k].nifs, ni[k].nifs == 1 ? "" : "s",
		    ni[k].divert > 0 ? wfmt(w, "prevents by divert %d",
		    ni[k].divert) : "detects", same ? "as it was" : samerun ?
		    "its rules read again" : "started");
		step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		if (same) {
			step_end(w, step, true, NULL);
			continue;
		}
		e = NULL;
		if (sdwan_conf_write(wfmt(w, "sdwan-ids-%s.rules", ni[k].name),
		    rules, &e) != 0 || sdwan_conf_write(wfmt(w,
		    "sdwan-ids-%s.threshold", ni[k].name), thr, &e) != 0 ||
		    sdwan_conf_write(wfmt(w,
		    "sdwan-ids-%s.yaml", ni[k].name), conf, &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		(void)mkdir(inst_path(w, ni[k].name, "d"), 0750);
		/* Checked first: what suricata refuses is not run. */
		argv[0] = (char *)(uintptr_t)suricata_bin(w);
		argv[1] = (char *)(uintptr_t)"-T";
		argv[2] = (char *)(uintptr_t)"-c";
		argv[3] = (char *)(uintptr_t)inst_path(w, ni[k].name, "yaml");
		/* What it refuses said where it can be read: the file it
		 * logs to otherwise is the instance's, not the answer. */
		argv[4] = (char *)(uintptr_t)"--set";
		argv[5] = (char *)(uintptr_t)
		    "logging.outputs.0.console.enabled=yes";
		argv[6] = NULL;
		note = NULL;
		if (run_exec(w, argv, &res) != 0 && (note = ruleset_only(w,
		    &res)) == NULL) {
			step_end(w, step, false, "suricata does not take it");
			*errp = wfmt(w, "%s: suricata does not take it: %s",
			    ni[k].name, suricata_errors(w, &res));
			ok = false;
			break;
		}
		if (note == NULL && strstr(raw, "@RULESET@") != NULL &&
		    strstr(conf, SURICATA_RULESET) == NULL)
			note = "the ruleset is not fetched yet (suricata-update): "
			    "its own rules alone until it is";
		if (samerun && kill((pid_t)inst_pid(w, ni[k].name), SIGUSR2) ==
		    0) {
			if (note != NULL)
				step_end(w, step, true, "%s; %s", what, note);
			else
				step_end(w, step, true, NULL);
			continue;
		}
		inst_stop(w, ni[k].name);
		if (ni[k].nooffload)
			offload_off(w, &ni[k]);
		if (inst_start(w, ni[k].name, ni[k].divert, ni[k].netmap, &e) !=
		    0) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		if (note != NULL)
			step_end(w, step, true, "%s; %s", what, note);
		else
			step_end(w, step, true, NULL);
	}
	pthread_mutex_lock(&lock);
	if (!ok) {
		/* Those not named were stopped all the same: out of the
		 * table, or the reader would say a divert one is down. */
		for (i = nkeep = 0; i < ninstances; i++) {
			for (k = 0; k < n; k++)
				if (strcmp(ni[k].name, instances[i].name) == 0)
					break;
			if (IS_SEC(instances[i].name) != sec || k < n)
				instances[nkeep++] = instances[i];
			else
				alerts_free(&instances[i]);
		}
		ninstances = nkeep;
	}
	if (ok) {
		/* What was read of those that stay is kept with them. */
		for (k = 0; k < n; k++)
			for (i = 0; i < ninstances; i++)
				if (strcmp(ni[k].name, instances[i].name) == 0) {
					memcpy(ni[k].alerts, instances[i].alerts,
					    sizeof(ni[k].alerts));
					memset(instances[i].alerts, 0,
					    sizeof(instances[i].alerts));
					ni[k].head = instances[i].head;
					ni[k].nalerts = instances[i].nalerts;
					/* Its statistics too, moved. */
					ni[k].stats = instances[i].stats;
					ni[k].shead = instances[i].shead;
					ni[k].nstats = instances[i].nstats;
					ni[k].app = instances[i].app;
					instances[i].stats = NULL;
					instances[i].app = NULL;
					instances[i].nstats = 0;
					ni[k].off = instances[i].off;
					ni[k].seen = instances[i].seen;
					ni[k].down = instances[i].down &&
					    ni[k].divert > 0;
					ni[k].sev = ni[k].divert > 0 ?
					    instances[i].sev : 0;
					ni[k].diverted = instances[i].diverted;
					ni[k].checked = instances[i].checked;
					if (instances[i].divert > 0 &&
					    ni[k].divert == 0)
						fault_clear("ids", ni[k].name,
						    "Suricata %s detects now, "
						    "nothing diverted", ni[k].name);
				}
		/* The other group's kept as they are, this group's
		 * replaced by the list. */
		nkeep = 0;
		for (i = 0; i < ninstances; i++) {
			if (IS_SEC(instances[i].name) != sec)
				instances[nkeep++] = instances[i];
			else
				alerts_free(&instances[i]);
		}
		memcpy(instances + nkeep, ni, sizeof(*ni) * (size_t)n);
		ninstances = nkeep + n;
	}
	if (!reading && ninstances > 0) {
		pthread_t	tid;

		if (pthread_create(&tid, NULL, reader, NULL) == 0) {
			pthread_detach(tid);
			reading = true;
		}
	}
	applying = false;
	pthread_mutex_unlock(&lock);
	pthread_mutex_unlock(&apply_lock);
	ucl_object_unref(top);
	if (!ok)
		return (-1);
	e = NULL;
	if (sdwan_conf_write(sec ? SEC_FILE : IDS_FILE, json, &e) != 0) {
		*errp = wfmt(w, "%s: %s", sec ? SEC_FILE : IDS_FILE, e);
		return (-1);
	}
	return (0);
}

/* At the start: the instances kept, started again. */
void
sdwan_ids_start(void)
{
	struct work	 w;
	char		*json;
	const char	*e;

	work_init(&w);
	if ((json = sdwan_kept_read(IDS_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_ids(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "sdwan ids: %s", e);
		free(json);
	}
	if ((json = sdwan_kept_read(SEC_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_ids(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "security ids: %s", e);
		free(json);
	}
	work_free(&w);
}

/*
 * What this Suricata is built with (suricata --build-info), kept while
 * its program is the same: its version, and whether it profiles
 * packets and rules, has Hyperscan, netmap, ipfw, Lua and plugins.
 */
static ucl_object_t *
build_json(struct work *w)
{
	static pthread_mutex_t	kept_lock = PTHREAD_MUTEX_INITIALIZER;
	static char	*kept;
	static time_t	 kept_mtime;
	static const struct {
		const char	*line, *key;
	} yes[] = {
		{ "Profiling enabled:", "profiling" },
		{ "Profiling rules enabled:", "profiling_rules" },
		{ "Hyperscan support:", "hyperscan" },
		{ "Netmap support:", "netmap" },
		{ "IPFW support:", "ipfw" },
		{ "Plugin support (experimental):", "plugins" },
	};
	struct execres	 res;
	struct stat	 sb;
	ucl_object_t	*o;
	char		*argv[3], *copy, *it, *line, *v;
	size_t		 i;

	if (stat(suricata_bin(w), &sb) != 0)
		return (NULL);
	/* Two reads at once: the cache is one's at a time. */
	pthread_mutex_lock(&kept_lock);
	if (kept == NULL || sb.st_mtime != kept_mtime) {
		argv[0] = (char *)(uintptr_t)suricata_bin(w);
		argv[1] = (char *)(uintptr_t)"--build-info";
		argv[2] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			pthread_mutex_unlock(&kept_lock);
			return (NULL);
		}
		free(kept);
		kept = strdup(res.out);
		kept_mtime = sb.st_mtime;
	}
	copy = kept != NULL ? wstrdup(w, kept) : NULL;
	pthread_mutex_unlock(&kept_lock);
	if (copy == NULL)
		return (NULL);
	o = ucl_object_typed_new(UCL_OBJECT);
	for (it = copy; (line = strsep(&it, "\n")) != NULL;) {
		line += strspn(line, " \t");
		if ((v = strstr(line, "Suricata version ")) != NULL) {
			v += 17;
			v[strcspn(v, " ")] = '\0';
			ucl_object_insert_key(o, ucl_object_fromstring(v),
			    "version", 0, true);
			continue;
		}
		if (strncmp(line, "Features:", 9) == 0)
			ucl_object_insert_key(o, ucl_object_frombool(strstr(line,
			    "HAVE_LUA") != NULL), "lua", 0, true);
		for (i = 0; i < nitems(yes); i++)
			if (strncmp(line, yes[i].line, strlen(yes[i].line)) ==
			    0) {
				v = line + strlen(yes[i].line);
				v += strspn(v, " ");
				ucl_object_insert_key(o, ucl_object_frombool(
				    strncmp(v, "yes", 3) == 0), yes[i].key, 0,
				    true);
			}
	}
	return (o);
}

/* The offloading an interface has on: what Suricata would rather it
 * had not (SIOCGIFCAP). */
static ucl_object_t *
caps_json(const char *name)
{
	static const struct {
		int		 bit;
		const char	*word;
	} caps[] = {
		{ IFCAP_RXCSUM, "rxcsum" }, { IFCAP_TXCSUM, "txcsum" },
		{ IFCAP_RXCSUM_IPV6, "rxcsum6" }, { IFCAP_TXCSUM_IPV6, "txcsum6" },
		{ IFCAP_TSO4, "tso4" }, { IFCAP_TSO6, "tso6" },
		{ IFCAP_LRO, "lro" }, { IFCAP_VLAN_HWTSO, "vlanhwtso" },
	};
	struct ifreq	 ifr;
	ucl_object_t	*arr;
	size_t		 i;
	int		 s;

	if ((s = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		return (NULL);
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%.*s", (int)strcspn(
	    name, "^"), name);
	if (ioctl(s, SIOCGIFCAP, &ifr) == -1) {
		close(s);
		return (NULL);
	}
	close(s);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nitems(caps); i++)
		if (ifr.ifr_curcap & caps[i].bit)
			ucl_array_append(arr, ucl_object_fromstring(caps[i].word));
	return (arr);
}

/* The packets it logged for its alerts (pcap-log), in its directory. */
static ucl_object_t *
pcaps_json(struct work *w, const char *name)
{
	ucl_object_t	*arr, *o;
	struct dirent	*de;
	struct stat	 sb;
	const char	*dir, *p;
	DIR		*d;

	arr = ucl_object_typed_new(UCL_ARRAY);
	dir = inst_path(w, name, "d");
	if ((d = opendir(dir)) == NULL)
		return (arr);
	while ((de = readdir(d)) != NULL) {
		if (strncmp(de->d_name, "log.pcap", 8) != 0)
			continue;
		p = wfmt(w, "%s/%s", dir, de->d_name);
		if (stat(p, &sb) != 0 || !S_ISREG(sb.st_mode))
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(p), "path", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)
		    sb.st_size), "size", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)
		    sb.st_mtime), "at", 0, false);
		ucl_array_append(arr, o);
	}
	closedir(d);
	return (arr);
}

/* An instance's statistics: the fields, the points oldest first (each
 * the fields' values, -1 where Suricata had none), its flows by
 * protocol. */
static ucl_object_t *
stats_json(const struct instance *in)
{
	ucl_object_t	*o, *f, *ser, *pt, *app;
	size_t		 k;
	int		 i, j;

	o = ucl_object_typed_new(UCL_OBJECT);
	f = ucl_object_typed_new(UCL_ARRAY);
	for (k = 0; k < STATS_N; k++)
		ucl_array_append(f, ucl_object_fromstring(stat_fields[k]));
	ucl_object_insert_key(o, f, "fields", 0, false);
	ser = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < in->nstats; i++) {
		j = (in->shead - in->nstats + i + STATS_KEPT) % STATS_KEPT;
		pt = ucl_object_typed_new(UCL_ARRAY);
		for (k = 0; k < STATS_N; k++)
			ucl_array_append(pt, ucl_object_fromint(
			    in->stats[j].v[k]));
		ucl_array_append(ser, pt);
	}
	ucl_object_insert_key(o, ser, "series", 0, false);
	if (in->app != NULL && (app = parse(in->app)) != NULL)
		ucl_object_insert_key(o, app, "flows", 0, false);
	return (o);
}

/* A CPU set as cpuset(1) writes one: 0-3,6. */
static const char *
cpus_text(struct work *w, const cpuset_t *set)
{
	char	*t = wstrdup(w, "");
	int	 c, from;

	for (c = 0; c < CPU_SETSIZE; c++) {
		if (!CPU_ISSET(c, set))
			continue;
		for (from = c; c + 1 < CPU_SETSIZE && CPU_ISSET(c + 1, set); c++)
			;
		t = wfmt(w, "%s%s%d", t, t[0] != '\0' ? "," : "", from);
		if (c > from)
			t = wfmt(w, "%s-%d", t, c);
	}
	return (t);
}

/*
 * The interrupts of the instances' interfaces (hw.intrnames, as vmstat
 * -i reads them: "irq264: ix0:rxq0"), each with the CPUs it may run on
 * (cpuset -g -x): beside the threads' sets, a queue's interrupt and its
 * worker best on the same CPU.  The lock is held.
 */
static ucl_object_t *
irqs_json(struct work *w)
{
	ucl_object_t	*arr, *o;
	cpuset_t	 set;
	char		*names, *p, *desc, *end;
	size_t		 len, n;
	long		 irq;
	int		 i, k;
	bool		 ours;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (sysctlbyname("hw.intrnames", NULL, &len, NULL, 0) != 0 ||
	    len == 0 || (names = wcalloc(w, len + 1, 1)) == NULL ||
	    sysctlbyname("hw.intrnames", names, &len, NULL, 0) != 0)
		return (arr);
	for (p = names; p < names + len && ucl_array_size(arr) < 256;
	    p += strlen(p) + 1) {
		if (strncmp(p, "irq", 3) != 0)
			continue;
		irq = strtol(p + 3, &end, 10);
		if (end == p + 3 || *end != ':')
			continue;
		desc = end + 1 + strspn(end + 1, " ");
		ours = false;
		for (i = 0; !ours && i < ninstances; i++)
			for (k = 0; !ours && k < instances[i].nifs; k++) {
				n = strlen(instances[i].ifs[k]);
				ours = n > 0 && strncmp(desc, instances[i].ifs[k],
				    n) == 0 && (desc[n] == '\0' || desc[n] ==
				    ':' || desc[n] == ' ');
			}
		if (!ours)
			continue;
		CPU_ZERO(&set);
		if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_IRQ, irq,
		    sizeof(set), &set) != 0)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromint(irq), "irq", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(desc), "name", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(cpus_text(w,
		    &set)), "cpus", 0, false);
		ucl_array_append(arr, o);
	}
	return (arr);
}

/* The instances as they are, into the sdwan reply: each its name, its
 * interfaces, whether it runs, how many alerts were read, the latest. */
void
sdwan_ids_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*arr, *o, *ifs, *al, *a;
	struct stat	 sb;
	int		 i, k, j;

	pthread_mutex_lock(&lock);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < ninstances; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(instances[i].name),
		    "name", 0, false);
		ifs = ucl_object_typed_new(UCL_ARRAY);
		for (k = 0; k < instances[i].nifs; k++)
			ucl_array_append(ifs, ucl_object_fromstring(
			    instances[i].ifs[k]));
		ucl_object_insert_key(o, ifs, "interfaces", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(instances[i].divert >
		    0 ? "prevent" : "detect"), "mode", 0, false);
		if (instances[i].divert > 0)
			ucl_object_insert_key(o, ucl_object_fromint(
			    instances[i].divert), "divert", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(inst_pid(w,
		    instances[i].name) != 0), "running", 0, false);
		if (instances[i].stopped)
			ucl_object_insert_key(o, ucl_object_frombool(true),
			    "stopped", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)
		    instances[i].seen), "alerts_seen", 0, false);
		al = ucl_object_typed_new(UCL_ARRAY);
		for (k = 0; k < instances[i].nalerts && k < ALERTS_READ; k++) {
			j = (instances[i].head - 1 - k + ALERTS_KEPT) %
			    ALERTS_KEPT;
			if (instances[i].alerts[j] != NULL &&
			    (a = parse(instances[i].alerts[j])) != NULL)
				ucl_array_append(al, a);
		}
		ucl_object_insert_key(o, al, "alerts", 0, false);
		if (instances[i].nstats > 0)
			ucl_object_insert_key(o, stats_json(&instances[i]),
			    "stats", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(
		    instances[i].netmap ? "netmap" : instances[i].divert > 0 ?
		    "divert" : "pcap"), "capture", 0, false);
		ucl_object_insert_key(o, pcaps_json(w, instances[i].name),
		    "pcaps", 0, false);
		/* The last capture replayed through it. */
		{
			const char	*t;
			ucl_object_t	*r;

			if ((t = file_text(w, inst_path(w, instances[i].name,
			    "replay.json"))) != NULL && (r = parse(t)) != NULL)
				ucl_object_insert_key(o, r, "replay", 0, false);
		}
		/* Each interface's offloading still on. */
		{
			ucl_object_t	*off, *c;

			off = ucl_object_typed_new(UCL_OBJECT);
			for (k = 0; k < instances[i].nifs; k++)
				if ((c = caps_json(instances[i].ifs[k])) != NULL)
					ucl_object_insert_key(off, c,
					    instances[i].ifs[k], 0, true);
			ucl_object_insert_key(o, off, "offload", 0, false);
		}
		ucl_object_insert_key(o, ucl_object_fromstring(IS_SEC(
		    instances[i].name) ? "security" : "sdwan"), "group", 0,
		    false);
		ucl_array_append(arr, o);
	}
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(top, arr, "ids", 0, false);
	/* What its Suricata is built with. */
	if ((o = build_json(w)) != NULL)
		ucl_object_insert_key(top, o, "ids_build", 0, false);
	/* The host's CPUs and memory domains, for its threads' sets. */
	{
		int	ncpu, ndom;
		size_t	len;

		len = sizeof(ncpu);
		if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) != 0)
			ncpu = 0;
		len = sizeof(ndom);
		if (sysctlbyname("vm.ndomains", &ndom, &len, NULL, 0) != 0)
			ndom = 1;
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromint(ncpu), "ncpu", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromint(ndom), "ndomains", 0,
		    false);
		pthread_mutex_lock(&lock);
		ucl_object_insert_key(o, irqs_json(w), "irqs", 0, false);
		pthread_mutex_unlock(&lock);
		ucl_object_insert_key(top, o, "ids_host", 0, false);
	}
	/* The ruleset, when suricata-update has fetched it: when, and its
	 * size. */
	if (stat(SURICATA_RULESET, &sb) == 0) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(SURICATA_RULESET),
		    "path", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)
		    sb.st_mtime), "at", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)
		    sb.st_size), "size", 0, false);
		ucl_object_insert_key(top, o, "ids_ruleset", 0, false);
	}
	security_specs(SEC_FILE, top, "security_ids");
}

/*
 * The suricata job: verb update runs suricata-update, which fetches the
 * ruleset (Emerging Threats Open unless it is told of other sources) to
 * suricata.rules in --suricata-rules.  Then the instances are applied again from what was
 * kept of them, so that one started without the ruleset takes it, and
 * those that read it already are told to read their rules again
 * (SIGUSR2).  The host's only; never in safe mode.
 */
const char *
suricata_check(const struct arc_job_spec *sp)
{

	if (sp->jail != NULL && sp->jail[0] != '\0')
		return ("Suricata's ruleset is the host's");
	if (sp->safe)
		return ("a fetched ruleset is not undone: not in safe mode");
	if (sp->verb != NULL && strcmp(sp->verb, "rule") == 0)
		return (suricata_rule_check(sp));
	if (sp->verb != NULL && (strcmp(sp->verb, "sources") == 0 ||
	    strncmp(sp->verb, "source-", 7) == 0))
		return (suricata_source_check(sp));
	if (sp->verb != NULL && strcmp(sp->verb, "pcap") == 0)
		return (suricata_replay_check(sp));
	if (sp->verb == NULL || strcmp(sp->verb, "update") != 0)
		return ("a suricata job's verb is update, rule, sources, "
		    "source-enable, source-disable, source-remove, source-add "
		    "or pcap");
	if (sp->names.n > 0)
		return ("update takes no words");
	return (NULL);
}

char *
suricata_title(const struct arc_job_spec *sp)
{
	char	*t;

	if (strcmp(sp->verb, "sources") == 0 || strncmp(sp->verb, "source-",
	    7) == 0)
		return (suricata_source_title(sp));
	if (strcmp(sp->verb, "pcap") == 0) {
		const char	*f = "", *in = "";
		size_t		 i;

		for (i = 0; i < sp->names.n; i++)
			if (strncmp(sp->names.v[i], "file=", 5) == 0)
				f = sp->names.v[i] + 5;
			else if (strncmp(sp->names.v[i], "instance=", 9) == 0)
				in = sp->names.v[i] + 9;
		if (asprintf(&t, "suricata replays %s through %s", f, in) == -1)
			return (NULL);
		return (t);
	}
	if (sp->verb != NULL && strcmp(sp->verb, "rule") == 0) {
		if (asprintf(&t, "suricata rules set: %s%s", sp->names.v[0],
		    sp->names.n > 1 ? " ..." : "") == -1)
			return (NULL);
		return (t);
	}
	return (strdup("suricata-update: the ruleset fetched"));
}

int
do_suricata_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct execres	 res;
	char		*argv[20], *json;
	const char	*bin, *e, *t;
	pid_t		 pid;
	size_t		 n;
	int		 step, i, na, rc;
	bool		 rule, secret;

	if ((*errp = suricata_check(sp)) != NULL)
		return (-1);
	/* The sources: their files, or their index fetched. */
	if (strcmp(sp->verb, "sources") == 0 || strncmp(sp->verb, "source-",
	    7) == 0)
		return (suricata_source_job(w, sp, errp));
	/* A capture run through an instance, offline. */
	if (strcmp(sp->verb, "pcap") == 0)
		return (suricata_replay(w, sp, errp));
	rule = strcmp(sp->verb, "rule") == 0;
	/* The rules set are made into the ruleset already fetched. */
	if (rule && access(SURICATA_RULESET, R_OK) != 0) {
		*errp = "the ruleset is not fetched yet: fetch it first "
		    "(suricata update)";
		return (-1);
	}
	if ((bin = tool(w, "suricata-update")) == NULL)
		bin = "/usr/local/bin/suricata-update";
	if (access(bin, X_OK) != 0) {
		*errp = wfmt(w, "no %s: it comes with Suricata (pkg install "
		    "suricata)", bin);
		return (-1);
	}
	if (rule) {
		step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "the rules set kept");
		if (suricata_rule_set(w, sp, errp) != 0) {
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
		step_end(w, step, true, NULL);
	}
	step = step_begin(w, ARC_STEP_KIND_EXEC, "suricata-update",
	    rule ? "the ruleset made again, from what was fetched, to %s" :
	    "the ruleset fetched to %s", SURICATA_RULESET);
	/* Each instance is checked by suricata -T as it is applied: the
	 * ruleset's own test would read a suricata.yaml of the port's,
	 * which is not the instances'. */
	argv[0] = (char *)(uintptr_t)bin;
	argv[1] = (char *)(uintptr_t)"--no-test";
	argv[2] = (char *)(uintptr_t)"--no-reload";
	argv[3] = (char *)(uintptr_t)"--suricata";
	argv[4] = (char *)(uintptr_t)suricata_bin(w);
	argv[5] = (char *)(uintptr_t)"-o";
	argv[6] = (char *)(uintptr_t)opts.suricata_rules;
	/* Its data directory, where its sources and cache are. */
	argv[7] = (char *)(uintptr_t)"-D";
	argv[8] = (char *)(uintptr_t)suricata_data_dir(w);
	na = 9;
	/* The admin's rules by sid, every time: they hold across updates. */
	if (suricata_rule_args(w, argv, &na, errp) != 0) {
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	if (rule)
		argv[na++] = (char *)(uintptr_t)"--offline";
	argv[na] = NULL;
	/* A source with a secret code has it in the URLs suricata-update
	 * logs: its output is then kept nowhere. */
	secret = suricata_sources_secret(w);
	exec_set_secret(secret);
	rc = run_exec(w, argv, &res);
	exec_set_secret(false);
	if (rc != 0) {
		if (secret) {
			step_end(w, step, false, "suricata-update failed");
			*errp = "suricata-update failed (its output is not kept: "
			    "a source's secret code is in it); run it by hand to "
			    "see why";
			return (-1);
		}
		t = res.outlen > 0 ? wstrndup(w, res.out, res.outlen) :
		    res.errlen > 0 ? wstrndup(w, res.err, res.errlen) : "";
		n = strlen(t);
		step_end(w, step, false, "suricata-update failed");
		*errp = wfmt(w, "suricata-update: %s", n > 400 ? t + n - 400 :
		    n > 0 ? t : "failed");
		return (-1);
	}
	step_end(w, step, true, NULL);
	if ((json = sdwan_kept_read(IDS_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_ids(w, json, &e) != 0) {
			free(json);
			*errp = wfmt(w, "fetched, but SD-WAN's: %s", e);
			return (-1);
		}
		free(json);
	}
	if ((json = sdwan_kept_read(SEC_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_ids(w, json, &e) != 0) {
			free(json);
			*errp = wfmt(w, "fetched, but %s", e);
			return (-1);
		}
		free(json);
	}
	pthread_mutex_lock(&lock);
	for (i = 0; i < ninstances; i++) {
		t = file_text(w, inst_path(w, instances[i].name, "yaml"));
		if (t == NULL || strstr(t, SURICATA_RULESET) == NULL ||
		    (pid = (pid_t)inst_pid(w, instances[i].name)) <= 1)
			continue;
		step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "suricata %s reads its rules again", instances[i].name);
		step_end(w, step, kill(pid, SIGUSR2) == 0, NULL);
	}
	pthread_mutex_unlock(&lock);
	return (0);
}

/*
 * The suricata job's verb pcap: a capture file (instance=NAME
 * file=PATH, a .pcap, .pcapng or .cap the host has) run through an
 * instance's configuration and rules by suricata -r, offline, into a
 * directory of its own; the alerts it raised kept for the read.
 */
static const char *
suricata_replay_check(const struct arc_job_spec *sp)
{
	const char	*inst, *file, *v;
	size_t		 i, len;

	inst = file = NULL;
	for (i = 0; i < sp->names.n; i++) {
		v = sp->names.v[i];
		if (v != NULL && strncmp(v, "instance=", 9) == 0)
			inst = v + 9;
		else if (v != NULL && strncmp(v, "file=", 5) == 0)
			file = v + 5;
		else
			return ("pcap takes instance= and file=");
	}
	if (inst == NULL || !name_ok(inst))
		return ("pcap names its instance=");
	if (file == NULL || file[0] != '/' || strstr(file, "/../") != NULL ||
	    (len = strlen(file)) < 8 || len > 512 || (strcmp(file + len - 5,
	    ".pcap") != 0 && strcmp(file + len - 7, ".pcapng") != 0 &&
	    strcmp(file + len - 4, ".cap") != 0))
		return ("pcap's file= is a .pcap, .pcapng or .cap the host "
		    "has, by its whole path");
	return (NULL);
}

static int
suricata_replay(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct execres	 res;
	struct stat	 sb;
	ucl_object_t	*top, *arr;
	const char	*inst, *file, *dir, *a;
	char		*argv[16], *line, *json;
	struct dirent	*de;
	size_t		 i, cap;
	ssize_t		 n;
	int64_t		 total;
	FILE		*fp;
	DIR		*d;
	int		 step, rc;
	time_t		 t0;

	if ((*errp = suricata_replay_check(sp)) != NULL)
		return (-1);
	inst = file = NULL;
	for (i = 0; i < sp->names.n; i++)
		if (strncmp(sp->names.v[i], "instance=", 9) == 0)
			inst = sp->names.v[i] + 9;
		else
			file = sp->names.v[i] + 5;
	if (access(inst_path(w, inst, "yaml"), R_OK) != 0) {
		*errp = wfmt(w, "there is no instance %s here", inst);
		return (-1);
	}
	if (lstat(file, &sb) != 0 || !S_ISREG(sb.st_mode)) {
		*errp = wfmt(w, "%s is not a file the host has (a link is not "
		    "followed)", file);
		return (-1);
	}
	/* Its own directory, emptied: what this run writes alone. */
	dir = inst_path(w, inst, "replay.d");
	if ((d = opendir(dir)) != NULL) {
		while ((de = readdir(d)) != NULL)
			if (de->d_name[0] != '.')
				(void)unlink(wfmt(w, "%s/%s", dir, de->d_name));
		closedir(d);
	}
	(void)mkdir(dir, 0750);
	step = step_begin(w, ARC_STEP_KIND_EXEC, "suricata", "%s through %s, "
	    "offline", file, inst);
	argv[0] = (char *)(uintptr_t)suricata_bin(w);
	argv[1] = (char *)(uintptr_t)"-c";
	argv[2] = (char *)(uintptr_t)inst_path(w, inst, "yaml");
	argv[3] = (char *)(uintptr_t)"-r";
	argv[4] = (char *)(uintptr_t)file;
	argv[5] = (char *)(uintptr_t)"-l";
	argv[6] = (char *)(uintptr_t)dir;
	argv[7] = (char *)(uintptr_t)"-k";
	argv[8] = (char *)(uintptr_t)"none";
	/* Not the running one's socket, nor its log directory. */
	argv[9] = (char *)(uintptr_t)"--set";
	argv[10] = (char *)(uintptr_t)"unix-command.enabled=no";
	argv[11] = (char *)(uintptr_t)"--set";
	argv[12] = wfmt(w, "default-log-dir=%s", dir);
	argv[13] = NULL;
	t0 = time(NULL);
	rc = run_exec(w, argv, &res);
	/* Its alerts: told how many, the first 200 kept. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	total = 0;
	if ((fp = fopen(wfmt(w, "%s/eve.json", dir), "re")) != NULL) {
		line = NULL;
		cap = 0;
		while ((n = getline(&line, &cap, fp)) > 0) {
			if (n > LINE_MAX_EVE || (json = alert_json(inst, line)) ==
			    NULL)
				continue;
			total++;
			if (ucl_array_size(arr) < 200) {
				ucl_object_t	*o;

				if ((o = parse(json)) != NULL)
					ucl_array_append(arr, o);
			}
			free(json);
		}
		free(line);
		fclose(fp);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_fromstring(file), "file", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)t0), "at", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)(time(NULL) -
	    t0)), "seconds", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(rc), "status", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(total), "alerts_total", 0,
	    false);
	ucl_object_insert_key(top, arr, "alerts", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	a = NULL;
	if (json != NULL) {
		(void)put_text(inst_path(w, inst, "replay.json"), json, &a);
		free(json);
	}
	if (rc != 0) {
		*errp = wfmt(w, "suricata did not read %s: %s", file, (a =
		    log_errors(w, inst, 0)) != NULL ? a : wtext(w, exec_error(w,
		    &res, "suricata")));
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, "%jd alert%s", (intmax_t)total, total == 1 ?
	    "" : "s");
	return (0);
}
