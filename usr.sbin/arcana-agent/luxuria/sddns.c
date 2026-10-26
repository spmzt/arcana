/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The resolvers of the SD-WAN services at this edge (MEF 138's DNF and
 * PDNS, the function policies of a zone, and where a DPF redirects):
 * the base system's unbound(8), local-unbound, one instance
 * per service run in the service's routing table (setfib), its
 * configuration written by the console (the UNIs' provider addresses
 * it listens on, the domains denied as local zones), its pid file
 * beside the agent's kept files.  Like the DHCP instances of sddhcp.c:
 * those named are started or started again, those not named any more
 * are stopped, and the list is kept for the next start.
 */

#include <sys/param.h>
#include <sys/stat.h>

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

#define	DNS_FILE	"sdwan-dns.json"
#define	INSTANCES_MAX	64
#define	CONF_MAX	(256 * 1024)

struct instance {
	char	name[40];
	int	fib;
};

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
static struct instance	instances[INSTANCES_MAX];
static int		ninstances;

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

/* Where an instance's files are: beside the agent's kept files. */
static const char *
inst_path(struct work *w, const char *name, const char *ext)
{
	char	buf[MAXPATHLEN];

	sdwan_conf_path(wfmt(w, "sdwan-dns-%s.%s", name, ext), buf,
	    sizeof(buf));
	return (wstrdup(w, buf));
}

/* The pid in an instance's pid file, when that process is there. */
static pid_t
inst_pid(struct work *w, const char *name)
{

	return (pidfile_of(inst_path(w, name, "pid"), opts.unbound_bin));
}

/* An instance stopped: its process signalled and waited for, briefly. */
static void
inst_stop(struct work *w, const char *name)
{
	pid_t	pid;

	if ((pid = inst_pid(w, name)) == 0)
		return;
	pid_stop(pid, opts.unbound_bin, 1000);
}

/* An instance started in its table, by setfib, on its file. */
static int
inst_start(struct work *w, const struct instance *in, const char **errp)
{
	struct execres	 res;
	char		*argv[8];
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.setfib_bin;
	argv[n++] = (char *)(uintptr_t)"-F";
	argv[n++] = wfmt(w, "%d", in->fib);
	argv[n++] = (char *)(uintptr_t)opts.unbound_bin;
	argv[n++] = (char *)(uintptr_t)"-c";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in->name, "conf");
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "local-unbound"));
		return (-1);
	}
	return (0);
}

/* An instance stopped and its files gone. */
static void
inst_down(struct work *w, const char *name)
{

	inst_stop(w, name);
	(void)unlink(inst_path(w, name, "conf"));
	(void)unlink(inst_path(w, name, "pid"));
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

/*
 * The instances applied: {"instances": [{"name", "fib", "conf"}, ...]}.
 * Each file, with the pid file and the run as root added (no chroot,
 * the kept files being where they are), is checked by
 * local-unbound-checkconf before it is made the instance's; a running
 * instance is stopped and started again on it; those not named any
 * more are stopped.  Kept for the next start.
 */
int
do_sdwan_dns(struct work *w, const char *json, const char **errp)
{
	ucl_object_t		*top;
	const ucl_object_t	*in, *v;
	ucl_object_iter_t	 it;
	struct instance		 ni[INSTANCES_MAX];
	struct execres		 res;
	char			*argv[3], *text;
	const char		*conf, *e;
	int			 n, i, k, step;
	bool			 was, ok;

	if ((top = parse(json)) == NULL || ucl_object_type(top) != UCL_OBJECT) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the instances are an object: instances, each a name, "
		    "a fib and its conf";
		return (-1);
	}
	n = 0;
	it = NULL;
	while ((in = ucl_object_iterate(ucl_object_lookup(top, "instances"),
	    &it, true)) != NULL) {
		v = ucl_object_lookup(in, "name");
		conf = ucl_object_tostring(ucl_object_lookup(in, "conf"));
		if (n == INSTANCES_MAX || v == NULL || ucl_object_type(v) !=
		    UCL_STRING || !name_ok(ucl_object_tostring(v)) ||
		    ucl_object_lookup(in, "fib") == NULL || ucl_object_toint(
		    ucl_object_lookup(in, "fib")) < 0 || ucl_object_toint(
		    ucl_object_lookup(in, "fib")) > 65535 || conf == NULL ||
		    strlen(conf) > CONF_MAX) {
			ucl_object_unref(top);
			*errp = wfmt(w, "an instance is a name of letters, digits, "
			    "_ and -, 32 at most, a fib and its conf, %d of them "
			    "at most", INSTANCES_MAX);
			return (-1);
		}
		for (i = 0; i < n; i++)
			if (strcmp(ni[i].name, ucl_object_tostring(v)) == 0) {
				ucl_object_unref(top);
				*errp = wfmt(w, "instance %s is named twice",
				    ni[i].name);
				return (-1);
			}
		snprintf(ni[n].name, sizeof(ni[n].name), "%s",
		    ucl_object_tostring(v));
		ni[n].fib = (int)ucl_object_toint(ucl_object_lookup(in, "fib"));
		n++;
	}
	pthread_mutex_lock(&lock);
	for (i = 0; i < ninstances; i++) {
		for (k = 0; k < n; k++)
			if (strcmp(ni[k].name, instances[i].name) == 0)
				break;
		if (k == n) {
			step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
			    "unbound %s stopped", instances[i].name);
			inst_down(w, instances[i].name);
			step_end(w, step, true, NULL);
		}
	}
	ok = true;
	it = NULL;
	for (k = 0; k < n; k++) {
		in = ucl_object_iterate(ucl_object_lookup(top, "instances"), &it,
		    true);
		conf = ucl_object_tostring(ucl_object_lookup(in, "conf"));
		was = inst_pid(w, ni[k].name) != 0;
		step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "unbound %s in fib %d: %s", ni[k].name, ni[k].fib, was ?
		    "started again" : "started");
		/* The agent's own clause after the console's: the pid file,
		 * no chroot and the user it runs as. */
		text = wfmt(w, "%s%sserver:\n\tpidfile: \"%s\"\n\tchroot: \"\"\n\t"
		    "username: \"\"\n", conf, conf[0] != '\0' && conf[strlen(conf)
		    - 1] != '\n' ? "\n" : "", inst_path(w, ni[k].name, "pid"));
		e = NULL;
		if (sdwan_conf_write(wfmt(w, "sdwan-dns-%s.conf", ni[k].name),
		    text, &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		/* Checked first: what unbound refuses is not run. */
		argv[0] = wfmt(w, "%s-checkconf", opts.unbound_bin);
		argv[1] = (char *)(uintptr_t)inst_path(w, ni[k].name, "conf");
		argv[2] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			step_end(w, step, false, "unbound does not take it");
			*errp = wfmt(w, "%s: unbound does not take it: %s",
			    ni[k].name, res.errlen > 0 ? res.err : res.out !=
			    NULL ? res.out : "no reason given");
			ok = false;
			break;
		}
		if (was)
			inst_stop(w, ni[k].name);
		if (inst_start(w, &ni[k], &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = e;
			ok = false;
			break;
		}
		step_end(w, step, true, NULL);
	}
	if (ok) {
		memcpy(instances, ni, sizeof(*ni) * (size_t)n);
		ninstances = n;
	}
	pthread_mutex_unlock(&lock);
	ucl_object_unref(top);
	if (!ok)
		return (-1);
	e = NULL;
	if (sdwan_conf_write(DNS_FILE, json, &e) != 0) {
		*errp = wfmt(w, "%s: %s", DNS_FILE, e);
		return (-1);
	}
	return (0);
}

/* At the start: the instances kept, started again. */
void
sdwan_dns_start(void)
{
	struct work	 w;
	char		*json;
	const char	*e;

	work_init(&w);
	if ((json = sdwan_kept_read(DNS_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_dns(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "sdwan dns: %s", e);
		free(json);
	}
	work_free(&w);
}

/* The instances as they are, into the sdwan reply: each its name, fib,
 * and whether its process is there. */
void
sdwan_dns_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*arr, *o;
	int		 i;

	pthread_mutex_lock(&lock);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < ninstances; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(instances[i].name),
		    "name", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(instances[i].fib),
		    "fib", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(inst_pid(w,
		    instances[i].name) != 0), "running", 0, false);
		ucl_array_append(arr, o);
	}
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(top, arr, "dns", 0, false);
}
