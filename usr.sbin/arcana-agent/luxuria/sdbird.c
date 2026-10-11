/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * SD-WAN routing at the UNIs (MEF 70.2 §11.6): a BIRD instance of each
 * service on the edge, as the console writes its configuration, run in
 * the service's routing table with a control socket of its own, kept
 * beside the probes and the rules and started again with the agent.
 * It talks BGP or OSPF with the subscriber at the UNI, and iBGP with
 * the other edges by the tunnels, so what one UNI learns reaches them
 * all.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	BIRD_FILE	"sdwan-bird.json"
#define	INSTANCES_MAX	64
#define	CONF_MAX	(256 * 1024)

struct instance {
	char	name[40];
	int	fib;
};

/* A BFD session as an instance lists it: the far address, where. */
struct bfd {
	char	instance[40];
	char	address[64];
	char	iface[32];
	char	since[32];
	int	state;		/* PROBE_UP, PROBE_DOWN, else PROBE_UNKNOWN */
};

#define	BFD_MAX		512
#define	BFD_EVERY_S	1

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
static struct instance	instances[INSTANCES_MAX];
static int		ninstances;
static struct bfd	bfds[BFD_MAX];
static int		nbfds;

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

	sdwan_conf_path(wfmt(w, "sdwan-bird-%s.%s", name, ext), buf,
	    sizeof(buf));
	return (wstrdup(w, buf));
}

/* birdc on an instance's socket; 0 and its output when it answered. */
static int
inst_birdc(struct work *w, const char *name, const char *a, const char *b,
    struct execres *res)
{
	char	*argv[7];
	int	 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.birdc_bin;
	argv[n++] = (char *)(uintptr_t)"-s";
	argv[n++] = (char *)(uintptr_t)inst_path(w, name, "ctl");
	argv[n++] = (char *)(uintptr_t)a;
	if (b != NULL)
		argv[n++] = (char *)(uintptr_t)b;
	argv[n] = NULL;
	return (run_exec(w, argv, res));
}

static bool
inst_alive(struct work *w, const char *name)
{
	struct execres	res;

	return (inst_birdc(w, name, "show", "status", &res) == 0 && res.out !=
	    NULL && strstr(res.out, "BIRD") != NULL && strstr(res.out,
	    "Shutdown") == NULL);
}

/* An instance started in its table, or told to read its file again. */
static int
inst_up(struct work *w, const struct instance *in, bool was,
    const char **errp)
{
	struct execres	 res;
	char		*argv[10];
	int		 n;

	if (was && inst_alive(w, in->name)) {
		if (inst_birdc(w, in->name, "configure", NULL, &res) != 0 ||
		    res.out == NULL || strstr(res.out, "Reconfigured") == NULL) {
			*errp = wfmt(w, "%s: bird did not take its "
			    "configuration: %s", in->name, res.out != NULL ?
			    res.out : "no answer");
			return (-1);
		}
		return (0);
	}
	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.setfib_bin;
	argv[n++] = (char *)(uintptr_t)"-F";
	argv[n++] = wfmt(w, "%d", in->fib);
	argv[n++] = (char *)(uintptr_t)opts.bird_bin;
	argv[n++] = (char *)(uintptr_t)"-c";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in->name, "conf");
	argv[n++] = (char *)(uintptr_t)"-s";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in->name, "ctl");
	argv[n++] = (char *)(uintptr_t)"-P";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in->name, "pid");
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "bird"));
		return (-1);
	}
	return (0);
}

/* An instance stopped, its files gone. */
static void
inst_down(struct work *w, const char *name)
{
	struct execres	res;

	(void)inst_birdc(w, name, "down", NULL, &res);
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
 * Each file is parsed by bird before it is made the instance's; those
 * not named any more are stopped.  Kept for the next start.
 */
int
do_sdwan_bird(struct work *w, const char *json, const char **errp)
{
	ucl_object_t		*top;
	const ucl_object_t	*in, *v;
	ucl_object_iter_t	 it;
	struct instance		 ni[INSTANCES_MAX];
	struct execres		 res;
	char			*argv[5];
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
	/* Those that go, first. */
	for (i = 0; i < ninstances; i++) {
		for (k = 0; k < n; k++)
			if (strcmp(ni[k].name, instances[i].name) == 0)
				break;
		if (k == n) {
			step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
			    "bird %s stopped", instances[i].name);
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
		was = false;
		for (i = 0; i < ninstances; i++)
			if (strcmp(ni[k].name, instances[i].name) == 0)
				was = true;
		step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent", "bird "
		    "%s in fib %d: %s", ni[k].name, ni[k].fib, was ?
		    "configured again" : "started");
		e = NULL;
		if (sdwan_conf_write(wfmt(w, "sdwan-bird-%s.conf", ni[k].name),
		    conf, &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		/* Parsed first: what bird refuses is not run. */
		argv[0] = (char *)(uintptr_t)opts.bird_bin;
		argv[1] = (char *)(uintptr_t)"-p";
		argv[2] = (char *)(uintptr_t)"-c";
		argv[3] = (char *)(uintptr_t)inst_path(w, ni[k].name, "conf");
		argv[4] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			step_end(w, step, false, "bird does not take it");
			*errp = wfmt(w, "%s: bird does not take it: %s",
			    ni[k].name, res.errlen > 0 ? res.err : res.out !=
			    NULL ? res.out : "no reason given");
			ok = false;
			break;
		}
		if (inst_up(w, &ni[k], was, &e) != 0) {
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
	if (sdwan_conf_write(BIRD_FILE, json, &e) != 0) {
		*errp = wfmt(w, "%s: %s", BIRD_FILE, e);
		return (-1);
	}
	return (0);
}

/*
 * The BFD sessions of an instance, as "show bfd sessions" lists them:
 * a heading, then a line each of address, interface, state, since,
 * interval, timeout; into out, at most max; how many.
 */
static int
bfd_read(struct work *w, const char *name, struct bfd *out, int max)
{
	struct execres	 res;
	char		*text, *line, *p, *f[6];
	int		 n, k;

	if (inst_birdc(w, name, "show", "bfd sessions", &res) != 0 || res.out ==
	    NULL)
		return (0);
	n = 0;
	text = wstrdup(w, res.out);
	while (n < max && (line = strsep(&text, "\n")) != NULL) {
		if (line[0] == '\0' || line[0] == ' ' || strncmp(line, "BIRD", 4)
		    == 0 || strncmp(line, "IP address", 10) == 0 || line[strlen(
		    line) - 1] == ':')
			continue;
		p = line;
		for (k = 0; k < 6; k++) {
			while (*p == ' ' || *p == '\t')
				p++;
			f[k] = p;
			while (*p != '\0' && *p != ' ' && *p != '\t')
				p++;
			if (*p != '\0')
				*p++ = '\0';
		}
		if (f[2][0] == '\0')
			continue;
		snprintf(out[n].instance, sizeof(out[n].instance), "%s", name);
		snprintf(out[n].address, sizeof(out[n].address), "%s", f[0]);
		snprintf(out[n].iface, sizeof(out[n].iface), "%s", f[1]);
		snprintf(out[n].since, sizeof(out[n].since), "%s", f[3]);
		out[n].state = strcasecmp(f[2], "up") == 0 ? PROBE_UP : strcasecmp(
		    f[2], "down") == 0 ? PROBE_DOWN : PROBE_UNKNOWN;
		n++;
	}
	return (n);
}

/*
 * The sessions read again every second, each change an event
 * (sdwan-tunnel, by bfd, R60), and the steering told, which takes
 * BFD's word over the probe's where there is a session.
 */
static void *
bfd_watch(void *arg __unused)
{
	struct work	 w;
	struct instance	 in[INSTANCES_MAX];
	struct bfd	*now, *chg;
	int		 n, i, k, m, was, nchg;
	bool		 changed;

	if ((now = calloc(BFD_MAX, sizeof(*now))) == NULL || (chg = calloc(
	    BFD_MAX, sizeof(*chg))) == NULL)
		return (NULL);
	for (;;) {
		sleep(BFD_EVERY_S);
		pthread_mutex_lock(&lock);
		n = ninstances;
		memcpy(in, instances, sizeof(*in) * (size_t)n);
		pthread_mutex_unlock(&lock);
		if (n == 0)
			continue;
		work_init(&w);
		m = 0;
		for (i = 0; i < n && m < BFD_MAX; i++)
			m += bfd_read(&w, in[i].name, now + m, BFD_MAX - m);
		changed = false;
		nchg = 0;
		pthread_mutex_lock(&lock);
		for (k = 0; k < m; k++) {
			was = PROBE_NONE;
			for (i = 0; i < nbfds; i++)
				if (strcmp(bfds[i].address, now[k].address) == 0 &&
				    strcmp(bfds[i].iface, now[k].iface) == 0) {
					was = bfds[i].state;
					break;
				}
			if (was != now[k].state && (was != PROBE_NONE || now[k].
			    state == PROBE_DOWN)) {
				chg[nchg++] = now[k];
				changed = true;
			}
		}
		if (m != nbfds)
			changed = true;
		memcpy(bfds, now, sizeof(*now) * (size_t)m);
		nbfds = m;
		pthread_mutex_unlock(&lock);
		/* Told without the lock: the steering has a lock of its own,
		 * taken the other way round when it asks BFD. */
		for (k = 0; k < nchg; k++) {
			const char	*id = sdwan_tunnel_by_via(chg[k].address);

			event_add("sdwan-tunnel", "{\"id\":\"%s\",\"address\":\"%s\","
			    "\"interface\":\"%s\",\"state\":\"%s\",\"by\":\"bfd\"}",
			    id != NULL ? id : chg[k].iface, chg[k].address,
			    chg[k].iface, chg[k].state == PROBE_UP ? "up" :
			    chg[k].state == PROBE_DOWN ? "down" : "unknown");
		}
		work_free(&w);
		if (changed)
			sdwan_probe_changed();
	}
	return (NULL);
}

/* What BFD says of the tunnel whose far address this is; NONE without. */
int
sdwan_bfd_state(const char *address)
{
	int	i, st;

	st = PROBE_NONE;
	pthread_mutex_lock(&lock);
	for (i = 0; address != NULL && i < nbfds; i++)
		if (strcmp(bfds[i].address, address) == 0) {
			st = bfds[i].state;
			break;
		}
	pthread_mutex_unlock(&lock);
	return (st);
}

/* At the start: the instances kept, started again; the sessions watched. */
void
sdwan_bird_start(void)
{
	struct work	 w;
	char		*json;
	const char	*e;
	pthread_t	 tid;
	int		 error;

	work_init(&w);
	if ((json = sdwan_kept_read(BIRD_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_bird(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "sdwan bird: %s", e);
		free(json);
	}
	work_free(&w);
	if ((error = pthread_create(&tid, NULL, bfd_watch, NULL)) != 0)
		logmsg(LOG_WARNING, "sdwan bird: no BFD watch: %s", strerror(
		    error));
	else
		pthread_detach(tid);
}

/*
 * The instances as they are, into the sdwan reply: each its name, fib,
 * whether it answers, and its protocols as birdc lists them (name,
 * kind, state, what it says).
 */
void
sdwan_bird_json(struct work *w, ucl_object_t *top)
{
	struct execres	 res;
	ucl_object_t	*arr, *o, *ps, *p;
	char		*text, *line, *word, *rest;
	int		 i, k;

	pthread_mutex_lock(&lock);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < ninstances; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(instances[i].name),
		    "name", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(instances[i].fib),
		    "fib", 0, false);
		ps = ucl_object_typed_new(UCL_ARRAY);
		if (inst_birdc(w, instances[i].name, "show", "protocols",
		    &res) == 0 && res.out != NULL) {
			ucl_object_insert_key(o, ucl_object_frombool(true),
			    "running", 0, false);
			text = wstrdup(w, res.out);
			while ((line = strsep(&text, "\n")) != NULL) {
				/* Name Proto Table State Since Info */
				if (line[0] == '\0' || line[0] == ' ' ||
				    strncmp(line, "BIRD", 4) == 0 || strncmp(line,
				    "Name ", 5) == 0)
					continue;
				p = ucl_object_typed_new(UCL_OBJECT);
				rest = line;
				for (k = 0; k < 5 && (word = strsep(&rest, " "))
				    != NULL; k++) {
					while (rest != NULL && *rest == ' ')
						rest++;
					if (k == 0)
						ucl_object_insert_key(p,
						    ucl_object_fromstring(word),
						    "name", 0, false);
					else if (k == 1)
						ucl_object_insert_key(p,
						    ucl_object_fromstring(word),
						    "proto", 0, false);
					else if (k == 3)
						ucl_object_insert_key(p,
						    ucl_object_fromstring(word),
						    "state", 0, false);
				}
				if (rest != NULL && rest[0] != '\0')
					ucl_object_insert_key(p,
					    ucl_object_fromstring(rest), "info",
					    0, false);
				ucl_array_append(ps, p);
			}
		} else
			ucl_object_insert_key(o, ucl_object_frombool(false),
			    "running", 0, false);
		ucl_object_insert_key(o, ps, "protocols", 0, false);
		/* Its BFD sessions, as last read. */
		ps = ucl_object_typed_new(UCL_ARRAY);
		for (k = 0; k < nbfds; k++) {
			if (strcmp(bfds[k].instance, instances[i].name) != 0)
				continue;
			p = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(p, ucl_object_fromstring(
			    bfds[k].address), "address", 0, false);
			ucl_object_insert_key(p, ucl_object_fromstring(
			    bfds[k].iface), "interface", 0, false);
			ucl_object_insert_key(p, ucl_object_fromstring(
			    bfds[k].state == PROBE_UP ? "up" : bfds[k].state ==
			    PROBE_DOWN ? "down" : "unknown"), "state", 0, false);
			ucl_object_insert_key(p, ucl_object_fromstring(
			    bfds[k].since), "since", 0, false);
			ucl_array_append(ps, p);
		}
		ucl_object_insert_key(o, ps, "bfd", 0, false);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, "bird", 0, false);
	pthread_mutex_unlock(&lock);
}
