/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The DHCP servers of the SD-WAN services at this edge (MEF 70.2 §11.4,
 * §11.5): FreeBSD's base has no DHCP server, so dnsmasq from packages,
 * one instance per service run in the service's routing table
 * (setfib), its configuration rendered here from the console's form
 * (sdconf.c), its pid and lease files beside the agent's kept files.  Like the BIRD instances
 * of sdbird.c: those named are started or started again, those not
 * named any more are stopped, and the list is kept for the next start.
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

#define	DHCP_FILE	"sdwan-dhcp.json"
#define	INSTANCES_MAX	64

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

/* A string of the instance's, as a comment takes it: "" for none. */
static const char *
sstr(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, k);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : "");
}

/* Where an instance's files are: beside the agent's kept files. */
static const char *
inst_path(struct work *w, const char *name, const char *ext)
{
	char	buf[MAXPATHLEN];

	sdwan_conf_path(wfmt(w, "sdwan-dhcp-%s.%s", name, ext), buf,
	    sizeof(buf));
	return (wstrdup(w, buf));
}

/* The pid in an instance's pid file, when that process is there. */
static pid_t
inst_pid(struct work *w, const char *name)
{

	return (pidfile_of(inst_path(w, name, "pid"), opts.dnsmasq_bin));
}

/* An instance stopped: its process signalled and waited for, briefly. */
static void
inst_stop(struct work *w, const char *name)
{
	pid_t	pid;

	if ((pid = inst_pid(w, name)) == 0)
		return;
	pid_stop(pid, opts.dnsmasq_bin, 1000);
}

/* An instance started in its table, by setfib, on its file. */
static int
inst_start(struct work *w, const struct instance *in, const char **errp)
{
	struct execres	 res;
	char		*argv[10];
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.setfib_bin;
	argv[n++] = (char *)(uintptr_t)"-F";
	argv[n++] = wfmt(w, "%d", in->fib);
	argv[n++] = (char *)(uintptr_t)opts.dnsmasq_bin;
	argv[n++] = (char *)(uintptr_t)"-C";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in->name, "conf");
	argv[n++] = (char *)(uintptr_t)"-x";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in->name, "pid");
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "dnsmasq"));
		return (-1);
	}
	return (0);
}

/* An instance stopped, its files gone but the leases, kept for next time. */
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
 * The instances applied: {"instances": [{"name", "fib", "host",
 * "spec"}, ...]}, spec the service's form, rendered by
 * dhcp_conf_render() (host names the host in its comment), every one
 * before any is changed.  Each file, with the pid and lease files
 * added, is checked by dnsmasq --test before it is made the
 * instance's; a running instance is stopped and started again on it;
 * those not named any more are stopped.  Kept for the next start.
 */
int
do_sdwan_dhcp(struct work *w, const char *json, const char **errp)
{
	ucl_object_t		*top;
	const ucl_object_t	*in, *v;
	ucl_object_iter_t	 it;
	struct instance		 ni[INSTANCES_MAX];
	struct execres		 res;
	char			*argv[5], *text, *confs[INSTANCES_MAX];
	const char		*conf, *e;
	int			 n, i, k, step;
	bool			 was, ok;

	if ((top = parse(json)) == NULL || ucl_object_type(top) != UCL_OBJECT) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the instances are an object: instances, each a name, "
		    "a fib, a host and its spec";
		return (-1);
	}
	n = 0;
	it = NULL;
	while ((in = ucl_object_iterate(ucl_object_lookup(top, "instances"),
	    &it, true)) != NULL) {
		v = ucl_object_lookup(in, "name");
		if (n == INSTANCES_MAX || v == NULL || ucl_object_type(v) !=
		    UCL_STRING || !name_ok(ucl_object_tostring(v)) ||
		    ucl_object_lookup(in, "fib") == NULL || ucl_object_toint(
		    ucl_object_lookup(in, "fib")) < 0 || ucl_object_toint(
		    ucl_object_lookup(in, "fib")) > 65535 || ucl_object_type(
		    ucl_object_lookup(in, "spec")) != UCL_OBJECT) {
			ucl_object_unref(top);
			*errp = wfmt(w, "an instance is a name of letters, digits, "
			    "_ and -, 32 at most, a fib, a host and its spec, %d "
			    "of them at most", INSTANCES_MAX);
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
		e = NULL;
		if ((confs[n] = dhcp_conf_render(w, ucl_object_lookup(in,
		    "spec"), sstr(in, "host"), &e)) == NULL) {
			ucl_object_unref(top);
			*errp = wfmt(w, "%s: %s", ni[n].name, e);
			return (-1);
		}
		n++;
	}
	pthread_mutex_lock(&lock);
	for (i = 0; i < ninstances; i++) {
		for (k = 0; k < n; k++)
			if (strcmp(ni[k].name, instances[i].name) == 0)
				break;
		if (k == n) {
			step = step_begin(w, STEP_DAEMON, "arcana-agent",
			    "dnsmasq %s stopped", instances[i].name);
			inst_down(w, instances[i].name);
			step_end(w, step, true, NULL);
		}
	}
	ok = true;
	for (k = 0; k < n; k++) {
		conf = confs[k];
		was = inst_pid(w, ni[k].name) != 0;
		step = step_begin(w, STEP_DAEMON, "arcana-agent",
		    "dnsmasq %s in fib %d: %s", ni[k].name, ni[k].fib, was ?
		    "started again" : "started");
		/* The agent's own lines after the console's: where the pid
		 * and the leases go. */
		text = wfmt(w, "%s%spid-file=%s\ndhcp-leasefile=%s\n", conf,
		    conf[0] != '\0' && conf[strlen(conf) - 1] != '\n' ? "\n" :
		    "", inst_path(w, ni[k].name, "pid"), inst_path(w, ni[k].name,
		    "leases"));
		e = NULL;
		if (sdwan_conf_write(wfmt(w, "sdwan-dhcp-%s.conf", ni[k].name),
		    text, &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		/* Checked first: what dnsmasq refuses is not run. */
		argv[0] = (char *)(uintptr_t)opts.dnsmasq_bin;
		argv[1] = (char *)(uintptr_t)"--test";
		argv[2] = (char *)(uintptr_t)"-C";
		argv[3] = (char *)(uintptr_t)inst_path(w, ni[k].name, "conf");
		argv[4] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			step_end(w, step, false, "dnsmasq does not take it");
			*errp = wfmt(w, "%s: dnsmasq does not take it: %s",
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
	if (sdwan_conf_write(DHCP_FILE, json, &e) != 0) {
		*errp = wfmt(w, "%s: %s", DHCP_FILE, e);
		return (-1);
	}
	return (0);
}

/* At the start: the instances kept, started again. */
void
sdwan_dhcp_start(void)
{
	struct work	 w;
	char		*json;
	const char	*e;

	work_init(&w);
	if ((json = sdwan_kept_read(DHCP_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_dhcp(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "sdwan dhcp: %s", e);
		free(json);
	}
	work_free(&w);
}

/*
 * The instances as they are, into the sdwan reply: each its name, fib,
 * whether its process is there, and the leases it gave, as dnsmasq
 * keeps them (expires, the client's hardware address or IAID, the
 * address, the host name).
 */
void
sdwan_dhcp_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*arr, *o, *ls, *l;
	char		*text, *line, *word, *rest;
	size_t		 len;
	int		 i, k;

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
		ls = ucl_object_typed_new(UCL_ARRAY);
		if ((text = scope_slurp(w, inst_path(w, instances[i].name,
		    "leases"), &len)) != NULL) {
			while ((line = strsep(&text, "\n")) != NULL) {
				/* expires id address name client-id */
				if (line[0] == '\0' || strncmp(line, "duid ", 5)
				    == 0)
					continue;
				l = ucl_object_typed_new(UCL_OBJECT);
				rest = line;
				for (k = 0; k < 4 && (word = strsep(&rest, " "))
				    != NULL; k++)
					ucl_object_insert_key(l, k == 0 ?
					    ucl_object_fromint(strtoll(word, NULL,
					    10)) : ucl_object_fromstring(word), k ==
					    0 ? "expires" : k == 1 ? "id" : k == 2 ?
					    "address" : "name", 0, false);
				ucl_array_append(ls, l);
			}
		}
		ucl_object_insert_key(o, ls, "leases", 0, false);
		ucl_array_append(arr, o);
	}
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(top, arr, "dhcp", 0, false);
}
