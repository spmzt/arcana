/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The intrusion detection of the SD-WAN services at this edge (the ids
 * criterion of a security policy, Arcana's own: neither MEF 88 nor MEF
 * 138 has intrusion detection among its Security Functions): Suricata, a plugin the host has
 * installed (nothing is installed by Arcana), one instance per service,
 * watching the service's UNIs, its configuration written by the
 * console with places for what the agent knows: its log directory, its
 * rules file and its pid file.  What it finds it writes as eve.json,
 * which a thread of the agent reads every second: each alert an event,
 * sdwan-ids, and the latest kept for the sdwan read.  One that prevents
 * (a divert port given) takes the UNIs' packets from ipfw's divert rules
 * instead and gives back those its rules let by: while it is not
 * running they pass nothing, so the thread says it, a fault, until it
 * runs again.  Like the proxies
 * of sdproxy.c: those named are started (again when their files
 * changed), those not named any more are stopped, and the list is kept
 * for the next start.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <net/if.h>

#include <ctype.h>
#include <ifaddrs.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
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
#define	CONF_MAX	(256 * 1024)
#define	RULES_MAX	(4 * 1024 * 1024)
#define	ALERTS_KEPT	200	/* an instance's latest, for the read */
#define	ALERTS_READ	50	/* of them, in the sdwan read */
#define	ALERTS_SECOND	50	/* events a second, at most, per instance */
#define	LINE_MAX_EVE	(64 * 1024)

struct instance {
	char	 name[40];
	char	 ifs[IFS_MAX][IFNAMSIZ];
	int	 nifs;
	int	 divert;		/* its divert port, prevent; 0 detect */
	bool	 down;			/* one that prevents, told not running */
	off_t	 off;			/* how far its eve.json is read */
	char	*alerts[ALERTS_KEPT];	/* a ring, newest at head - 1 */
	int	 head, nalerts;
	uint64_t seen;			/* alerts read since it started */
};

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
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
		if (!isalnum((unsigned char)s[i]) && s[i] != '.' && s[i] != '_')
			return (false);
	return (true);
}

/* Where an instance's files are: beside the agent's kept files. */
static void
ids_pathbuf(const char *name, const char *ext, char *buf, size_t len)
{
	char	f[96];

	snprintf(f, sizeof(f), "sdwan-ids-%s.%s", name, ext);
	sdwan_conf_path(f, buf, len);
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
	return (pid > 1 && kill((pid_t)pid, 0) == 0);
}

static pid_t
inst_pid(struct work *w, const char *name)
{
	FILE	*fp;
	long	 pid = 0;

	if ((fp = fopen(inst_path(w, name, "pid"), "r")) == NULL)
		return (0);
	if (fscanf(fp, "%ld", &pid) != 1)
		pid = 0;
	fclose(fp);
	if (pid <= 1 || kill((pid_t)pid, 0) != 0)
		return (0);
	return ((pid_t)pid);
}

static void
inst_stop(struct work *w, const char *name)
{
	pid_t	pid;
	int	i;

	if ((pid = inst_pid(w, name)) == 0)
		return;
	(void)kill(pid, SIGTERM);
	for (i = 0; i < 250 && kill(pid, 0) == 0; i++)
		usleep(20000);
	if (kill(pid, 0) == 0)
		(void)kill(pid, SIGKILL);
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
	return (wfmt(w, "%zu rule%s of the ruleset left out, as Suricata does "
	    "when it runs: %s", bad, bad == 1 ? "" : "s", why != NULL ? why :
	    "they do not parse with these networks"));
}

/* An instance's configuration: the console's text, the places filled. */
static char *
inst_conf(struct work *w, const char *name, const char *conf)
{
	const char	*from[] = { "@LOGDIR@", "@RULES@", "@PID@",
			    "@CLASSIFICATION@", "@REFERENCE@", "@RULESET@" },
			*to[6];
	char		*out, *p, *q, *l, *e;
	size_t		 i, n, len;

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
	len = strlen(conf) + 8 * MAXPATHLEN + 1;
	out = wcalloc(w, 1, len);
	for (p = (char *)(uintptr_t)conf, q = out; *p != '\0';) {
		for (i = 0; i < nitems(from); i++) {
			n = strlen(from[i]);
			if (strncmp(p, from[i], n) == 0 && (size_t)(q - out) +
			    strlen(to[i]) < len - 1) {
				q = stpcpy(q, to[i]);
				p += n;
				break;
			}
		}
		if (i == nitems(from) && (size_t)(q - out) < len - 1)
			*q++ = *p++;
	}
	*q = '\0';
	return (out);
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
 * pfsync and enc, as arcana_snort makes it for Snort.  NULL, with errp,
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

/* Why an instance did not start, as its suricata.log says: its last
 * errors, or NULL. */
static const char *
log_errors(struct work *w, const char *name)
{
	FILE		*fp;
	char		 buf[512], *last[2];
	const char	*p;
	long		 size;
	int		 n;

	if ((fp = fopen(wfmt(w, "%s/suricata.log", inst_path(w, name, "d")),
	    "r")) == NULL)
		return (NULL);
	if (fseek(fp, 0, SEEK_END) == 0 && (size = ftell(fp)) > 65536)
		(void)fseek(fp, size - 65536, SEEK_SET);
	else
		rewind(fp);
	last[0] = last[1] = NULL;
	n = 0;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		buf[strcspn(buf, "\n")] = '\0';
		if ((p = strstr(buf, "Error: ")) == NULL && (p = strstr(buf,
		    "<Error>")) == NULL && strncmp(p = buf, "E: ", 3) != 0)
			continue;
		last[0] = last[1];
		last[1] = wstrdup(w, p);
		n++;
	}
	fclose(fp);
	if (n == 0)
		return (NULL);
	return (last[0] != NULL ? wfmt(w, "%s; %s", last[0], last[1]) :
	    last[1]);
}

static int
inst_start(struct work *w, const char *name, int divert, const char **errp)
{
	struct execres	 res;
	char		*argv[10];
	int		 n, i;

	(void)mkdir(inst_path(w, name, "d"), 0750);
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
		argv[n++] = (char *)(uintptr_t)"--pcap";
	argv[n++] = (char *)(uintptr_t)"-D";
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		/* Daemonized, it says why in its own log, not here. */
		if ((*errp = log_errors(w, name)) != NULL)
			*errp = wfmt(w, "suricata did not start: %s", *errp);
		else
			*errp = wtext(w, exec_error(w, &res, "suricata"));
		return (-1);
	}
	/* It forks, and loads its rules first: up once its pid file is. */
	for (i = 0; i < 300 && inst_pid(w, name) == 0; i++)
		usleep(100000);
	if (inst_pid(w, name) == 0) {
		*errp = (*errp = log_errors(w, name)) != NULL ? wfmt(w,
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

	eve_path(in->name, path, sizeof(path));
	if (stat(path, &st) != 0)
		return;
	if (st.st_size < in->off)	/* turned over, or made anew */
		in->off = 0;
	if (st.st_size == in->off || (fp = fopen(path, "r")) == NULL)
		return;
	if (fseeko(fp, in->off, SEEK_SET) != 0) {
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
		if (n > LINE_MAX_EVE || (a = alert_json(in->name, line)) ==
		    NULL)
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

/*
 * One that prevents and is not running: what its UNIs send and get is
 * diverted to no one and passes not, which is said as a fault until it
 * runs again.
 */
static void
guard(struct instance *in)
{
	bool	up;

	if (in->divert == 0)
		return;
	up = running(in->name);
	if (!up && !in->down)
		fault_set("ids", "Critical", in->name, "suricata", "Suricata %s, "
		    "which prevents, is not running: the UNIs it guards pass "
		    "nothing (ipfw divert %d)", in->name, in->divert);
	else if (up && in->down)
		fault_clear("ids", in->name, "Suricata %s runs again", in->name);
	in->down = !up;
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
divert_was(const char *name)
{
	int	i;

	for (i = 0; i < ninstances; i++)
		if (strcmp(instances[i].name, name) == 0)
			return (instances[i].divert);
	return (-1);
}

/*
 * The instances applied: {"instances": [{"name", "interfaces", "conf",
 * "rules"}, ...]}.  Suricata must be there (a plugin); each instance's
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
	const char		*rules, *e, *note, *what;
	int			 n, i, k, step, nkeep;
	bool			 ok, same, sec;

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
		if (n == INSTANCES_MAX || v == NULL || ucl_object_type(v) !=
		    UCL_STRING || !name_ok(ucl_object_tostring(v)) ||
		    ucl_object_tostring(ucl_object_lookup(in, "conf")) == NULL ||
		    strlen(ucl_object_tostring(ucl_object_lookup(in, "conf"))) >
		    CONF_MAX || (ucl_object_lookup(in, "rules") != NULL &&
		    (ucl_object_type(ucl_object_lookup(in, "rules")) !=
		    UCL_STRING || strlen(ucl_object_tostring(ucl_object_lookup(
		    in, "rules"))) > RULES_MAX))) {
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
		fit = NULL;
		while ((f = ucl_object_iterate(ucl_object_lookup(in,
		    "interfaces"), &fit, true)) != NULL) {
			if (ni[n].nifs == IFS_MAX || ucl_object_type(f) !=
			    UCL_STRING || !ifname_ok(ucl_object_tostring(f))) {
				ucl_object_unref(top);
				*errp = wfmt(w, "%s: its interfaces are names, %d "
				    "at most", ni[n].name, IFS_MAX);
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
	pthread_mutex_lock(&lock);
	/* Those not named any more: stopped, their files gone; the other
	 * group's are not this list's. */
	for (i = 0; i < ninstances; i++) {
		if (IS_SEC(instances[i].name) != sec)
			continue;
		for (k = 0; k < n; k++)
			if (strcmp(ni[k].name, instances[i].name) == 0)
				break;
		if (k == n) {
			step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
			    "suricata %s stopped", instances[i].name);
			inst_stop(w, instances[i].name);
			fault_clear("ids", instances[i].name, "Suricata %s taken "
			    "away", instances[i].name);
			(void)unlink(inst_path(w, instances[i].name, "yaml"));
			(void)unlink(inst_path(w, instances[i].name, "rules"));
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
		conf = inst_conf(w, ni[k].name, ucl_object_tostring(
		    ucl_object_lookup(in, "conf")));
		e = NULL;
		if ((conf = expand_any(w, conf, &e)) == NULL) {
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		rules = ucl_object_lookup(in, "rules") != NULL ?
		    ucl_object_tostring(ucl_object_lookup(in, "rules")) : "";
		/* Running with the same files: left as it is. */
		was = file_text(w, inst_path(w, ni[k].name, "yaml"));
		same = was != NULL && strcmp(was, conf) == 0 && (was = file_text(w,
		    inst_path(w, ni[k].name, "rules"))) != NULL && strcmp(was,
		    rules) == 0 && inst_pid(w, ni[k].name) != 0 && divert_was(
		    ni[k].name) == ni[k].divert;
		what = wfmt(w, "suricata %s on %d interface%s, %s: %s",
		    ni[k].name, ni[k].nifs, ni[k].nifs == 1 ? "" : "s",
		    ni[k].divert > 0 ? wfmt(w, "prevents by divert %d",
		    ni[k].divert) : "detects", same ? "as it was" : "started");
		step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		if (same) {
			step_end(w, step, true, NULL);
			continue;
		}
		e = NULL;
		if (sdwan_conf_write(wfmt(w, "sdwan-ids-%s.rules", ni[k].name),
		    rules, &e) != 0 || sdwan_conf_write(wfmt(w,
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
		if (note == NULL && strstr(ucl_object_tostring(ucl_object_lookup(
		    in, "conf")), "@RULESET@") != NULL && strstr(conf,
		    SURICATA_RULESET) == NULL)
			note = "the ruleset is not fetched yet (suricata-update): "
			    "its own rules alone until it is";
		inst_stop(w, ni[k].name);
		if (inst_start(w, ni[k].name, ni[k].divert, &e) != 0) {
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
					ni[k].off = instances[i].off;
					ni[k].seen = instances[i].seen;
					ni[k].down = instances[i].down &&
					    ni[k].divert > 0;
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
	pthread_mutex_unlock(&lock);
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
		ucl_object_insert_key(o, ucl_object_fromstring(IS_SEC(
		    instances[i].name) ? "security" : "sdwan"), "group", 0,
		    false);
		ucl_array_append(arr, o);
	}
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(top, arr, "ids", 0, false);
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
	if (sp->verb == NULL || strcmp(sp->verb, "update") != 0)
		return ("a suricata job's verb is update");
	if (sp->names.n > 0)
		return ("update takes no words");
	return (NULL);
}

char *
suricata_title(const struct arc_job_spec *sp __unused)
{

	return (strdup("suricata-update: the ruleset fetched"));
}

int
do_suricata_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct execres	 res;
	char		*argv[8], *json;
	const char	*bin, *e, *t;
	pid_t		 pid;
	size_t		 n;
	int		 step, i;

	if ((*errp = suricata_check(sp)) != NULL)
		return (-1);
	if ((bin = tool(w, "suricata-update")) == NULL)
		bin = "/usr/local/bin/suricata-update";
	if (access(bin, X_OK) != 0) {
		*errp = wfmt(w, "no %s: it comes with Suricata (pkg install "
		    "suricata)", bin);
		return (-1);
	}
	step = step_begin(w, ARC_STEP_KIND_EXEC, "suricata-update",
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
	argv[7] = NULL;
	if (run_exec(w, argv, &res) != 0) {
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
