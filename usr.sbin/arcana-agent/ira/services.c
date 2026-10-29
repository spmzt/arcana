/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * rc.d services, through service(8) and sysrc(8) so that what the host
 * does is what an administrator at the console would do: the scripts of
 * the rc.d directories, whether rc.conf enables them (<name>_enable in
 * "sysrc -A", which reads the configuration without running a single
 * script: "service -e" runs them all, and scripts without a default
 * for their rcvar warn each time), whether the enabled ones run
 * ("service x status"), and their rc.conf variables read and written by
 * sysrc(8).  Every program run is a step in the trace with its output.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"

struct script {
	const char	*name;
	const char	*path;
};

static int	cmp_script(const void *, const void *);
static bool	valid_name(const char *);
static bool	valid_var(const char *);
static void	scan_scripts(struct work *, struct script **, size_t *);
static const struct script *script_find(const struct script *, size_t,
		    const char *);
static int	svc_run(struct work *, const char *, const char *,
		    struct execres *);
static void	svc_status(struct work *, struct arc_service *);
static const char *svc_rcvar(struct work *, const char *, const char **);
static bool	enabled_in(const struct execres *, const char *);
static int	sysrc_all(struct work *, struct execres *);
static const char *last_line(struct work *, const char *, size_t);
static void	svc_about(struct work *, const char *,
		    struct service_config_rsp *);

static int
cmp_script(const void *a, const void *b)
{

	return (strcmp(((const struct script *)a)->name,
	    ((const struct script *)b)->name));
}

/* Script names: letters, digits, '_', '-', '.'; not hidden. */
static bool
valid_name(const char *s)
{

	if (*s == '\0' || *s == '.' || *s == '-' || strlen(s) > 64)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.-", *s) == NULL)
			return (false);
	return (true);
}

/* rc.conf variable names, as sh(1) takes them. */
static bool
valid_var(const char *s)
{

	if (*s == '\0' || isdigit((unsigned char)*s) || strlen(s) > 128)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && *s != '_')
			return (false);
	return (true);
}

/* The executable scripts of the rc.d directories, sorted by name. */
static void
scan_scripts(struct work *w, struct script **outp, size_t *np)
{
	struct script	*v;
	struct dirent	*de;
	struct stat	 st;
	DIR		*d;
	char		*dirs, *it, *dir, *path;
	size_t		 n, cap;
	int		 step;

	v = NULL;
	n = cap = 0;
	if ((dirs = strdup(opts.rc_dirs)) == NULL)
		err(1, "strdup");
	for (it = dirs; (dir = strsep(&it, ":")) != NULL; ) {
		if (*dir == '\0')
			continue;
		step = step_begin(w, STEP_FILE, "read", "scripts in %s",
		    dir);
		if ((d = opendir(dir)) == NULL) {
			step_end(w, step, false, "%s: %s", dir, strerror(errno));
			continue;
		}
		while ((de = readdir(d)) != NULL) {
			if (!valid_name(de->d_name))
				continue;
			path = wfmt(w, "%s/%s", dir, de->d_name);
			if (stat(path, &st) == -1 || !S_ISREG(st.st_mode) ||
			    (st.st_mode & S_IXUSR) == 0)
				continue;
			if (n == cap) {
				cap = cap == 0 ? 64 : cap * 2;
				if ((v = reallocarray(v, cap, sizeof(*v))) ==
				    NULL)
					err(1, "reallocarray");
			}
			v[n].name = wstrdup(w, de->d_name);
			v[n].path = path;
			n++;
		}
		closedir(d);
		step_end(w, step, true, "%zu scripts", n);
	}
	free(dirs);
	if (n > 1)
		qsort(v, n, sizeof(*v), cmp_script);
	*outp = wadopt(w, v);
	*np = n;
}

static const struct script *
script_find(const struct script *v, size_t n, const char *name)
{
	size_t	i;

	for (i = 0; i < n; i++)
		if (strcmp(v[i].name, name) == 0)
			return (&v[i]);
	return (NULL);
}

/* "service <name> <verb>", or "service <verb>" with name NULL. */
static int
svc_run(struct work *w, const char *name, const char *verb,
    struct execres *res)
{
	char	*argv[4];
	int	 i;

	i = 0;
	argv[i++] = (char *)(uintptr_t)opts.service_bin;
	if (name != NULL)
		argv[i++] = (char *)(uintptr_t)name;
	argv[i++] = (char *)(uintptr_t)verb;
	argv[i] = NULL;
	/* What only asks is run in a dry run too. */
	if (strcmp(verb, "status") == 0 || strcmp(verb, "rcvar") == 0 ||
	    strcmp(verb, "enabled") == 0 || strcmp(verb, "describe") == 0 ||
	    strcmp(verb, "extracommands") == 0)
		return (run_read(w, argv, res));
	return (run_exec(w, argv, res));
}

/* The last non-empty line of a program's output, fit for a text. */
static const char *
last_line(struct work *w, const char *s, size_t len)
{
	const char	*p;

	while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r'))
		len--;
	if (len == 0)
		return (NULL);
	for (p = s + len; p > s && p[-1] != '\n'; p--)
		;
	return (wtext(w, wstrndup(w, p, (size_t)(s + len - p))));
}

/* "sysrc -A": every variable with its value, defaults included. */
static int
sysrc_all(struct work *w, struct execres *res)
{
	char	*argv[3];

	argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
	argv[1] = (char *)(uintptr_t)"-A";
	argv[2] = NULL;
	return (run_read(w, argv, res));
}

/*
 * Does "sysrc -A" ("key: value" lines) say <name>_enable is yes?  The
 * rcvar of nearly every script is its name and _enable; the few that
 * differ show as disabled until looked at, where rcvar is asked.
 */
static bool
enabled_in(const struct execres *res, const char *name)
{
	const char	*p, *e, *v;
	size_t		 len;

	len = strlen(name);
	for (p = res->out; p != NULL && *p != '\0'; p = e != NULL ? e + 1 :
	    NULL) {
		e = strchr(p, '\n');
		if (strncmp(p, name, len) != 0 || strncmp(p + len, "_enable: ",
		    9) != 0)
			continue;
		v = p + len + 9;
		return (strncasecmp(v, "yes", 3) == 0 ||
		    strncasecmp(v, "true", 4) == 0 || strncasecmp(v, "on", 2) ==
		    0 || *v == '1');
	}
	return (false);
}

/* "service <name> status": running, and the pid if it says one. */
static void
svc_status(struct work *w, struct arc_service *s)
{
	struct execres	 res;
	const char	*p;

	svc_run(w, s->name, "status", &res);
	s->has_running = res.status != -1;
	s->running = res.status == 0;
	s->status = last_line(w, res.out, res.outlen);
	if (s->status == NULL)
		s->status = last_line(w, res.err, res.errlen);
	if (s->status != NULL && (p = strstr(s->status, "pid ")) != NULL &&
	    isdigit((unsigned char)p[4])) {
		s->has_pid = true;
		s->pid = (uint32_t)strtoul(p + 4, NULL, 10);
	}
}

/*
 * Whether a service runs and whether it is enabled, now: what a change
 * made in safe mode is put back to.
 */
void
service_state(struct work *w, const char *name, bool *running, bool *enabled)
{
	struct arc_service	s;
	struct execres		res;

	memset(&s, 0, sizeof(s));
	s.name = name;
	svc_status(w, &s);
	*running = s.running;
	/* rc.subr's own answer, by the script's real rcvar: one quick run,
	 * not sysrc -A's every variable with the defaults (seconds). */
	*enabled = svc_run(w, name, "enabled", &res) == 0;
}

/* "service <name> rcvar": the first variable it names, or NULL. */
static const char *
svc_rcvar(struct work *w, const char *name, const char **errp)
{
	struct execres	 res;
	const char	*p, *e;

	if (svc_run(w, name, "rcvar", &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "service"));
		return (NULL);
	}
	for (p = res.out; *p != '\0'; p = e != NULL ? e + 1 : p + strlen(p)) {
		e = strchr(p, '\n');
		if (*p != '#' && isalpha((unsigned char)*p) &&
		    strchr(p, '=') != NULL && (e == NULL || strchr(p, '=') < e))
			return (wstrndup(w, p, (size_t)(strchr(p, '=') - p)));
	}
	*errp = wfmt(w, "%s has no rcvar; it cannot be enabled or disabled",
	    name);
	return (NULL);
}

/* The scripts there are, with their names and paths alone: running's. */
void
service_scripts(struct work *w, struct services_rsp *rsp)
{
	struct arc_service	*v;
	struct script		*sc;
	size_t			 n, i;

	rsp->has_ok = true;
	rsp->ok = true;
	scan_scripts(w, &sc, &n);
	v = wcalloc(w, n + 1, sizeof(*v));
	for (i = 0; i < n; i++) {
		v[i].name = wtext(w, sc[i].name);
		v[i].path = wtext(w, sc[i].path);
	}
	rsp->services.v = v;
	rsp->services.n = n;
}

const char *
service_rcvar(struct work *w, const char *name, const char **errp)
{

	return (svc_rcvar(w, name, errp));
}

bool
valid_var_name(const char *s)
{

	return (valid_var(s));
}

int
do_services(struct work *w, struct services_rsp *rsp)
{
	struct arc_service	*v;
	struct script		*sc;
	struct execres		 res;
	size_t			 n, i;

	rsp->has_ok = true;
	rsp->ok = true;
	scan_scripts(w, &sc, &n);
	if (sysrc_all(w, &res) != 0) {
		rsp->ok = false;
		rsp->error = wtext(w, exec_error(w, &res, "sysrc -A"));
		return (0);
	}
	v = wcalloc(w, n + 1, sizeof(*v));
	for (i = 0; i < n; i++) {
		v[i].name = wtext(w, sc[i].name);
		v[i].path = wtext(w, sc[i].path);
		v[i].has_enabled = true;
		v[i].enabled = enabled_in(&res, sc[i].name);
		if (v[i].enabled)
			svc_status(w, &v[i]);
	}
	rsp->services.v = v;
	rsp->services.n = n;
	return (0);
}

/* The service as it is now, for a reply. */
static struct arc_service *
svc_current(struct work *w, const struct script *sc)
{
	struct arc_service	*s;
	struct execres		 res;

	s = wcalloc(w, 1, sizeof(*s));
	s->name = wtext(w, sc->name);
	s->path = wtext(w, sc->path);
	if (sysrc_all(w, &res) == 0) {
		s->has_enabled = true;
		s->enabled = enabled_in(&res, sc->name);
	}
	svc_status(w, s);
	return (s);
}

int
do_service_action(struct work *w, const char *name, uint8_t action,
    struct service_action_rsp *rsp)
{
	const struct script	*sc;
	struct script		*all;
	struct execres		 res;
	const char		*verb, *rcvar, *e;
	char			*argv[3];
	size_t			 n;

	rsp->has_ok = true;
	rsp->ok = false;
	/* Whoever asks (the operation, a YANG action): service(8) gets it. */
	if (name == NULL || !valid_service(name)) {
		rsp->error = "invalid service name";
		return (0);
	}
	scan_scripts(w, &all, &n);
	if ((sc = script_find(all, n, name)) == NULL) {
		rsp->error = wfmt(w, "no rc.d script '%s' in %s", name,
		    opts.rc_dirs);
		return (0);
	}
	switch (action) {
	case ARC_SERVICE_ACTION_ENABLE:
	case ARC_SERVICE_ACTION_DISABLE:
		if ((rcvar = svc_rcvar(w, name, &e)) == NULL) {
			rsp->error = e;
			goto out;
		}
		argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
		argv[1] = wfmt(w, "%s=%s", rcvar,
		    action == ARC_SERVICE_ACTION_ENABLE ? "YES" : "NO");
		argv[2] = NULL;
		if (run_exec(w, argv, &res) == 0)
			rsp->ok = true;
		else
			rsp->error = wtext(w, exec_error(w, &res, "sysrc"));
		break;
	default:
		verb = action == ARC_SERVICE_ACTION_START ? "start" :
		    action == ARC_SERVICE_ACTION_STOP ? "stop" :
		    action == ARC_SERVICE_ACTION_RESTART ? "restart" : "reload";
		/*
		 * The daemon's own service, stopped or restarted: service(8)
		 * waits for the daemon to go, and the daemon would wait for
		 * service(8), which it runs, to end.  So it is handed to a
		 * process of its own, and this is answered first.
		 */
		if (strcmp(name, OWN_SERVICE) == 0 && (action ==
		    ARC_SERVICE_ACTION_STOP || action ==
		    ARC_SERVICE_ACTION_RESTART)) {
			n = (size_t)step_begin(w, STEP_DAEMON,
			    "own service", "service %s %s: arcana-agent %s",
			    name, verb, action == ARC_SERVICE_ACTION_STOP ?
			    "stops" : "restarts");
			if (work_dry(w, (int)n)) {
				rsp->ok = true;
				break;
			}
			service_detached(name, verb);
			step_end(w, (int)n, true, "handed to a process of its "
			    "own: this daemon is stopped by it in a moment");
			rsp->ok = true;
			break;
		}
		if (svc_run(w, name, verb, &res) == 0)
			rsp->ok = true;
		else
			rsp->error = wtext(w, exec_error(w, &res, "service"));
		break;
	}
out:
	rsp->service_result = svc_current(w, sc);
	return (0);
}

/* What service name's script says of itself, and its extra commands. */
static void
svc_about(struct work *w, const char *name, struct service_config_rsp *rsp)
{
	struct execres	  res;
	const char	**cmds;
	char		 *copy, *it, *tok;
	size_t		  ncmd;

	if (svc_run(w, name, "describe", &res) == 0 && res.outlen > 0)
		rsp->description = wtext(w, wstrndup(w, res.out, res.outlen -
		    (res.out[res.outlen - 1] == '\n' ? 1 : 0)));
	cmds = NULL;
	ncmd = 0;
	if (svc_run(w, name, "extracommands", &res) == 0 && res.outlen > 0) {
		copy = wstrndup(w, res.out, res.outlen);
		for (it = copy; (tok = strsep(&it, " \t\n")) != NULL; ) {
			if (*tok == '\0')
				continue;
			if ((cmds = reallocarray(cmds, ncmd + 1,
			    sizeof(*cmds))) == NULL)
				err(1, "reallocarray");
			cmds[ncmd++] = wtext(w, tok);
		}
	}
	rsp->commands.v = wadopt(w, cmds);
	rsp->commands.n = ncmd;
}

/*
 * The variables of a service: those in rc.conf whose name starts with
 * the script's name or with its rcvar's stem, as "sysrc -a" lists them.
 * Variables in the request are set (sysrc key=value) or unset (sysrc -x
 * key) first; only such names are accepted.
 */
int
do_service_config(struct work *w, const struct service_config_req *rq,
    struct service_config_rsp *rsp)
{
	const struct script	*sc;
	struct script		*all;
	struct arc_variable	*vars;
	struct execres		 res;
	const char		*name, *rcvar, *stem, *e, *p, *nl, *sep;
	char			*argv[4];
	size_t			 n, i, nv, stemlen, namelen;

	name = rq->service;
	rsp->has_ok = true;
	rsp->ok = false;
	scan_scripts(w, &all, &n);
	sc = script_find(all, n, name);
	if (sc == NULL) {
		rsp->error = wfmt(w, "no rc.d script '%s' in %s", name,
		    opts.rc_dirs);
		return (0);
	}
	/* The rcvar tells the prefix: jail_enable -> jail_*. */
	rcvar = svc_rcvar(w, name, &e);
	stem = NULL;
	stemlen = 0;
	if (rcvar != NULL && (p = strstr(rcvar, "_enable")) != NULL &&
	    p[7] == '\0') {
		stem = rcvar;
		stemlen = (size_t)(p - rcvar) + 1;
	}
	namelen = strlen(name);

	/* All of them are looked at before the first is written. */
	for (i = 0; i < rq->variables.n; i++) {
		const struct arc_variable *var = &rq->variables.v[i];

		if (var->key == NULL || !valid_var(var->key) ||
		    !((strncmp(var->key, name, namelen) == 0 &&
		    var->key[namelen] == '_') || (stem != NULL &&
		    strncmp(var->key, stem, stemlen) == 0))) {
			rsp->error = wfmt(w, "'%s' is not a variable of %s",
			    var->key != NULL ? var->key : "", name);
			goto out;
		}
		if (!var->remove && !rc_value_ok(var->value)) {
			rsp->error = wfmt(w, "the value of %s has a quote, $, "
			    "` or \\: rc.conf would read it as more than a "
			    "value", var->key);
			goto out;
		}
	}
	for (i = 0; i < rq->variables.n; i++) {
		const struct arc_variable *var = &rq->variables.v[i];

		argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
		if (var->remove) {
			argv[1] = (char *)(uintptr_t)"-x";
			argv[2] = (char *)(uintptr_t)var->key;
			argv[3] = NULL;
		} else {
			argv[1] = wfmt(w, "%s=%s", var->key,
			    var->value != NULL ? var->value : "");
			argv[2] = NULL;
		}
		if (run_exec(w, argv, &res) != 0 && !(var->remove &&
		    res.status == 1)) {
			rsp->error = wtext(w, exec_error(w, &res, "sysrc"));
			goto out;
		}
	}

	/* What rc.conf holds now. */
	argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
	argv[1] = (char *)(uintptr_t)"-a";
	argv[2] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "sysrc -a"));
		goto out;
	}
	vars = NULL;
	nv = 0;
	for (p = res.out; *p != '\0'; p = nl != NULL ? nl + 1 :
	    p + strlen(p)) {
		nl = strchr(p, '\n');
		if ((sep = strstr(p, ": ")) == NULL || (nl != NULL && sep > nl))
			continue;
		if (!((strncmp(p, name, namelen) == 0 && p[namelen] == '_') ||
		    (stem != NULL && strncmp(p, stem, stemlen) == 0)))
			continue;
		if ((vars = reallocarray(vars, nv + 1, sizeof(*vars))) == NULL)
			err(1, "reallocarray");
		memset(&vars[nv], 0, sizeof(vars[nv]));
		vars[nv].key = wtext(w, wstrndup(w, p, (size_t)(sep - p)));
		vars[nv].value = wtext(w, wstrndup(w, sep + 2, nl != NULL ?
		    (size_t)(nl - sep - 2) : strlen(sep + 2)));
		nv++;
	}
	rsp->variables.v = wadopt(w, vars);
	rsp->variables.n = nv;
	svc_about(w, name, rsp);
	rsp->ok = true;
out:
	rsp->service_result = svc_current(w, sc);
	return (0);
}

/*
 * A service as it is now, without the others' status: enabled by
 * rc.subr's own answer (its rcvar, the defaults included), running or
 * not, what it says of itself and its extra commands.
 */
int
service_read(struct work *w, const char *name, struct service_config_rsp *rsp)
{
	const struct script	*sc;
	struct script		*all;
	struct arc_service	*s;
	struct execres		 res;
	const char		*e;
	size_t			 n;

	rsp->has_ok = true;
	rsp->ok = false;
	if (name == NULL || !valid_service(name)) {
		rsp->error = "invalid service name";
		return (0);
	}
	scan_scripts(w, &all, &n);
	if ((sc = script_find(all, n, name)) == NULL) {
		rsp->error = wfmt(w, "no rc.d script '%s' in %s", name,
		    opts.rc_dirs);
		return (0);
	}
	s = wcalloc(w, 1, sizeof(*s));
	s->name = wtext(w, sc->name);
	s->path = wtext(w, sc->path);
	s->rcvar = svc_rcvar(w, name, &e);
	s->has_enabled = true;
	s->enabled = svc_run(w, name, "enabled", &res) == 0;
	svc_status(w, s);
	rsp->service_result = s;
	svc_about(w, name, rsp);
	rsp->ok = true;
	return (0);
}

