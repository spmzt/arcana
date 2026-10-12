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

/* An instance's configuration: the console's text, the places filled. */
static char *
inst_conf(struct work *w, const char *name, const char *conf)
{
	const char	*from[] = { "@LOGDIR@", "@RULES@", "@PID@" }, *to[3];
	char		*out, *p, *q;
	size_t		 i, n, len;

	to[0] = inst_path(w, name, "d");
	to[1] = inst_path(w, name, "rules");
	to[2] = inst_path(w, name, "pid");
	len = strlen(conf) + 8 * MAXPATHLEN + 1;
	out = wcalloc(w, 1, len);
	for (p = (char *)(uintptr_t)conf, q = out; *p != '\0';) {
		for (i = 0; i < 3; i++) {
			n = strlen(from[i]);
			if (strncmp(p, from[i], n) == 0 && (size_t)(q - out) +
			    strlen(to[i]) < len - 1) {
				q = stpcpy(q, to[i]);
				p += n;
				break;
			}
		}
		if (i == 3 && (size_t)(q - out) < len - 1)
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
		*errp = wtext(w, exec_error(w, &res, "suricata"));
		return (-1);
	}
	/* It forks, and loads its rules first: up once its pid file is. */
	for (i = 0; i < 300 && inst_pid(w, name) == 0; i++)
		usleep(100000);
	if (inst_pid(w, name) == 0) {
		*errp = wfmt(w, "suricata did not start: see %s",
		    inst_path(w, name, "d"));
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
	char			*argv[6], *conf, *was;
	const char		*rules, *e;
	int			 n, i, k, step;
	bool			 ok, same;

	if ((top = parse(json)) == NULL || ucl_object_type(top) != UCL_OBJECT) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the instances are an object: instances, each a name, "
		    "its interfaces, its conf and its rules";
		return (-1);
	}
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
	if (n > 0 && access(suricata_bin(w), X_OK) != 0) {
		ucl_object_unref(top);
		*errp = wfmt(w, "the host has no suricata (%s): it is a plugin, "
		    "installed by hand (pkg install suricata)", suricata_bin(w));
		return (-1);
	}
	pthread_mutex_lock(&lock);
	/* Those not named any more: stopped, their files gone. */
	for (i = 0; i < ninstances; i++) {
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
		rules = ucl_object_lookup(in, "rules") != NULL ?
		    ucl_object_tostring(ucl_object_lookup(in, "rules")) : "";
		/* Running with the same files: left as it is. */
		was = file_text(w, inst_path(w, ni[k].name, "yaml"));
		same = was != NULL && strcmp(was, conf) == 0 && (was = file_text(w,
		    inst_path(w, ni[k].name, "rules"))) != NULL && strcmp(was,
		    rules) == 0 && inst_pid(w, ni[k].name) != 0 && divert_was(
		    ni[k].name) == ni[k].divert;
		step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "suricata %s on %d interface%s, %s: %s", ni[k].name, ni[k].nifs,
		    ni[k].nifs == 1 ? "" : "s", ni[k].divert > 0 ? wfmt(w,
		    "prevents by divert %d", ni[k].divert) : "detects", same ?
		    "as it was" : "started");
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
		argv[4] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			step_end(w, step, false, "suricata does not take it");
			*errp = wfmt(w, "%s: suricata does not take it: %s",
			    ni[k].name, res.errlen > 0 ? res.err : res.out !=
			    NULL ? res.out : "no reason given");
			ok = false;
			break;
		}
		inst_stop(w, ni[k].name);
		if (inst_start(w, ni[k].name, ni[k].divert, &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
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
		for (i = 0; i < ninstances; i++)
			alerts_free(&instances[i]);
		memcpy(instances, ni, sizeof(*ni) * (size_t)n);
		ninstances = n;
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
	if (sdwan_conf_write(IDS_FILE, json, &e) != 0) {
		*errp = wfmt(w, "%s: %s", IDS_FILE, e);
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
	work_free(&w);
}

/* The instances as they are, into the sdwan reply: each its name, its
 * interfaces, whether it runs, how many alerts were read, the latest. */
void
sdwan_ids_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*arr, *o, *ifs, *al, *a;
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
		ucl_array_append(arr, o);
	}
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(top, arr, "ids", 0, false);
}
