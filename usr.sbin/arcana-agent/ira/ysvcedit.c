/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: arcana-services served (PLAN-SDN-YANG 3.1.2).  A GET is the
 * scripts read by service(8) (services.c, yservices.c), with each
 * script's rc.conf variables from the files rc(8) reads for it
 * (libvarconf): <name>_enable as enabled, the other <name>_* as its
 * variables, the last file that sets one winning as rc(8) has it.
 * Running is that alone: the scripts there are, enabled or not, with
 * their variables.
 *
 * A commit of the candidate writes what differs to Arcana's rc.conf
 * file by rcarcana.c's rules (rc-conf-files, rc-conf-conflict), one
 * service at a time: its rcvar YES or NO for enabled (service <name>
 * rcvar says which), a variable set or taken out (yservices_diff());
 * every file is put back where a later service's change fails.  A
 * variable is one of the service's, <name>_* or its rcvar's stem's, as
 * the service-config job takes them; the rcvar itself is enabled's
 * alone.  The service is left as it runs: the start, stop, restart and
 * reload actions change that, and read says how it is (yarcana.c).
 */

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <cblink.h>

#include "agent.h"
#include "collect.h"
#include "varconf.h"

typedef struct arcana_services_services_service yservice;
typedef struct arcana_services_services_service_variable yvar;

#define	RCA_MAX	64	/* services changed by one commit, at most */

static char *
astrdup(cbl_yarena *a, const char *s)
{
	size_t	len = strlen(s) + 1;
	char	*p;

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

/* Whether an rc.conf value says yes, as rc.subr's checkyesno does. */
static bool
yes(const char *v)
{

	return (v != NULL && (strcasecmp(v, "YES") == 0 || strcasecmp(v,
	    "TRUE") == 0 || strcasecmp(v, "ON") == 0 || strcmp(v, "1") == 0));
}

/*
 * Service s's configuration from the files rc(8) reads for it: enabled
 * by <name>_enable, its <name>_* variables.  The strings are a's.
 */
static int
from_rc(cbl_yarena *a, yservice *s)
{
	struct vc_file	 f;
	yvar		*v = NULL;
	const char	*en = NULL;
	char		**paths, err[256], prefix[80];
	size_t		 n, nv = 0, cap = 0, plen;
	int		 error = 0;

	if (vc_rc_files(opts.root != NULL ? opts.root : "", "/usr/local",
	    s->name, "arcana", &paths, &n, err, sizeof(err)) != 0) {
		logmsg(LOG_WARNING, "%s: %s", s->name, err);
		return (0);
	}
	plen = (size_t)snprintf(prefix, sizeof(prefix), "%s_", s->name);
	for (size_t i = 0; error == 0 && i < n; i++) {
		if (vc_read(&f, VC_SH, paths[i], err, sizeof(err)) == -1) {
			logmsg(LOG_WARNING, "%s: %s", paths[i], err);
			continue;
		}
		for (size_t k = 0; error == 0 && k < f.na; k++) {
			const struct vc_assign *as = &f.a[k];
			size_t j;

			if (as->value == NULL || strncmp(as->name, prefix,
			    plen) != 0)
				continue;
			if (strcmp(as->name + plen, "enable") == 0) {
				en = astrdup(a, as->value);
				continue;
			}
			for (j = 0; j < nv && strcmp(v[j].name, as->name) != 0;
			    j++)
				;
			if (j == nv) {
				if (nv == cap) {
					yvar *nvv;

					cap = cap > 0 ? cap * 2 : 8;
					if ((nvv = cbl_yarena_alloc(a, cap *
					    sizeof(*nvv))) == NULL) {
						error = ENOMEM;
						break;
					}
					if (nv > 0)
						memcpy(nvv, v, nv * sizeof(*v));
					v = nvv;
				}
				if ((v[nv].name = astrdup(a, as->name)) == NULL) {
					error = ENOMEM;
					break;
				}
				nv++;
			}
			if ((v[j].value = astrdup(a, as->value)) == NULL)
				error = ENOMEM;
		}
		vc_free(&f);
	}
	vc_rc_files_free(paths, n);
	if (error != 0)
		return (error);
	if (en != NULL) {
		s->has_enabled = true;
		s->enabled = yes(en);
	}
	s->variable.n = nv;
	s->variable.v = v;
	return (0);
}

int
arcana_services_services_get(cbl_req *req, struct arcana_services *data,
    cbl_yarena *a)
{
	struct services_rsp	 r;
	struct work		*w;
	yservice		*v;
	bool			 state;
	int			 error, root;

	/* Its steps told, as the operation's trace was. */
	state = cbl_req_ydatastore(req) == CBL_YDS_OPERATIONAL;
	if ((w = ywork_told(req, a, state ? "services" : "services "
	    "(configuration only)", &root)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	if (state) {
		(void)do_services(w, &r);
		step_end(w, root, r.ok, NULL);
		if (!r.ok) {
			logmsg(LOG_INFO, "a read of services for a model failed: "
			    "%s", r.error != NULL ? r.error : "no reason given");
			return (EIO);
		}
	} else {
		service_scripts(w, &r);
		step_end(w, root, true, NULL);
	}
	if ((error = yservices_from(&r, a, data)) != 0)
		return (error);
	/* Their rc.conf variables, from the files rc(8) reads. */
	v = (yservice *)(uintptr_t)data->services->service.v;
	for (size_t i = 0; i < data->services->service.n; i++) {
		bool has = v[i].has_enabled, on = v[i].enabled;

		if ((error = from_rc(a, &v[i])) != 0)
			return (error);
		/* What do_services() read, the defaults included. */
		if (has && !v[i].has_enabled) {
			v[i].has_enabled = true;
			v[i].enabled = on;
		}
	}
	return (0);
}

static const yservice *
service_named(const struct arcana_services *d, const char *name)
{

	if (d == NULL || d->services == NULL)
		return (NULL);
	for (size_t i = 0; i < d->services->service.n; i++)
		if (strcmp(d->services->service.v[i].name, name) == 0)
			return (&d->services->service.v[i]);
	return (NULL);
}

/* Whether var is one of service name's, its rcvar stem's included. */
static bool
var_of_service(const char *var, const char *name, const char *rcvar)
{
	const char	*p;
	size_t		 nl = strlen(name);

	if (strncmp(var, name, nl) == 0 && var[nl] == '_')
		return (true);
	if (rcvar != NULL && (p = strstr(rcvar, "_enable")) != NULL &&
	    p[7] == '\0')
		return (strncmp(var, rcvar, (size_t)(p - rcvar) + 1) == 0);
	return (false);
}

int
arcana_services_services_edit(cbl_req *req,
    const struct arcana_services *before, const struct arcana_services *after)
{
	struct rca	*x;
	struct work	 w;
	cbl_yarena	*a;
	const char	*rcvar, *e;
	char		 err[512];
	size_t		 nx = 0;
	int		 error = 0;

	if (after == NULL || after->services == NULL)
		return (0);
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((x = calloc(RCA_MAX, sizeof(*x))) == NULL) {
		cbl_yarena_free(a);
		return (ENOMEM);
	}
	work_init(&w);
	err[0] = '\0';
	for (size_t i = 0; error == 0 && i < after->services->service.n; i++) {
		const yservice *want = &after->services->service.v[i], *have;
		struct arc_variable *vars;
		size_t nvars;
		int enable;

		if (!valid_service(want->name)) {
			(void)snprintf(err, sizeof(err), "invalid service name");
			error = EINVAL;
			break;
		}
		have = service_named(before, want->name);
		if ((error = yservices_diff(have, want, a, &enable, &vars,
		    &nvars)) != 0) {
			(void)snprintf(err, sizeof(err), "%s: not its own "
			    "configuration", want->name);
			break;
		}
		if (enable == 0 && nvars == 0)
			continue;
		if (nx == RCA_MAX) {
			(void)snprintf(err, sizeof(err), "%d services at most "
			    "in one commit", RCA_MAX);
			error = E2BIG;
			break;
		}
		/* Its rcvar: what enabled sets, and no variable of its. */
		e = NULL;
		rcvar = service_rcvar(&w, want->name, &e);
		if (enable != 0 && rcvar == NULL) {
			(void)snprintf(err, sizeof(err), "%s", e != NULL ? e :
			    "no rcvar");
			error = EINVAL;
			break;
		}
		for (size_t k = 0; error == 0 && k < nvars; k++) {
			if (!valid_var_name(vars[k].key) || (rcvar != NULL &&
			    strcmp(vars[k].key, rcvar) == 0) ||
			    !var_of_service(vars[k].key, want->name, rcvar)) {
				(void)snprintf(err, sizeof(err), "'%s' is not a "
				    "variable of %s", vars[k].key, want->name);
				error = EINVAL;
			} else if (!vars[k].remove && !rc_value_ok(
			    vars[k].value)) {
				(void)snprintf(err, sizeof(err), "the value of "
				    "%s has a quote, $, ` or \\: rc.conf would "
				    "read it as more than a value", vars[k].key);
				error = EINVAL;
			}
		}
		if (error != 0)
			break;
		if ((error = rca_open(&x[nx], want->name, err, sizeof(err))) !=
		    0)
			break;
		nx++;
		if (enable != 0)
			error = rca_set(&x[nx - 1], rcvar, enable > 0 ? "YES" :
			    "NO", err, sizeof(err));
		for (size_t k = 0; error == 0 && k < nvars; k++)
			error = vars[k].remove ? rca_drop(&x[nx - 1],
			    vars[k].key) : rca_set(&x[nx - 1], vars[k].key,
			    vars[k].value, err, sizeof(err));
		if (error == 0)
			error = rca_write(&x[nx - 1], req, err, sizeof(err));
	}
	if (error != 0) {
		for (size_t i = nx; i-- > 0; )
			rca_undo(&x[i]);
		if (error != EEXIST) {
			(void)cbl_req_set_yerr(req, err[0] != '\0' ? err :
			    strerror(error), 0);
			if (nx > 0)
				logmsg(LOG_WARNING, "services: %s: rc.conf as "
				    "it was", err);
		}
	}
	for (size_t i = 0; i < nx; i++)
		rca_close(&x[i]);
	free(x);
	work_free(&w);
	cbl_yarena_free(a);
	return (error);
}

/*
 * A job's change of service sp->service's rc.conf configuration
 * (service-action's enable and disable, service-config), written as a
 * commit writes it: to Arcana's file by rcarcana.c's rules, what
 * sp->accept names accepted.  The variables are the service's own, its
 * rcvar among them, as sysrc(8) took them before.  xp given: the files
 * as they were, kept for a safe job's undo.  -1 and *errp: refused or
 * failed, every file as it was.
 */
int
service_job_rc(struct work *w, const struct arc_job_spec *sp,
    struct rca **xp, const char **errp)
{
	struct rca	*x;
	const char	*rcvar, *e = NULL, *name = sp->service;
	char		 err[1200];
	int		 enable = 0, error = 0, step;

	if (xp != NULL)
		*xp = NULL;
	if (sp->kind == ARC_JOB_KIND_SERVICE_ACTION)
		enable = sp->service_action == ARC_SERVICE_ACTION_ENABLE ? 1 :
		    -1;
	rcvar = service_rcvar(w, name, &e);
	if (enable != 0 && rcvar == NULL) {
		*errp = e != NULL ? e : "no rcvar";
		return (-1);
	}
	for (size_t k = 0; k < sp->variables.n; k++) {
		const struct arc_variable *v = &sp->variables.v[k];

		if (v->key == NULL || !valid_var_name(v->key) ||
		    !var_of_service(v->key, name, rcvar)) {
			*errp = wfmt(w, "'%s' is not a variable of %s",
			    v->key != NULL ? v->key : "", name);
			return (-1);
		}
		if (!v->remove && !rc_value_ok(v->value)) {
			*errp = wfmt(w, "the value of %s has a quote, $, ` or "
			    "\\: rc.conf would read it as more than a value",
			    v->key);
			return (-1);
		}
	}
	if ((x = calloc(1, sizeof(*x))) == NULL) {
		*errp = strerror(ENOMEM);
		return (-1);
	}
	step = step_begin(w, STEP_FILE, "write", "%s: %s, as a "
	    "commit writes it", name, RC_ARCANA);
	err[0] = '\0';
	if ((error = rca_open(x, name, err, sizeof(err))) != 0) {
		free(x);
		step_end(w, step, false, "%s", err);
		/* The text is err's, on this stack: the work's copy. */
		*errp = wtext(w, wstrdup(w, err[0] != '\0' ? err :
		    strerror(error)));
		return (-1);
	}
	x->accept = sp->accept.v;
	x->naccept = sp->accept.n;
	x->dry = w->dry;
	if (enable != 0)
		error = rca_set(x, rcvar, enable > 0 ? "YES" : "NO", err,
		    sizeof(err));
	for (size_t k = 0; error == 0 && k < sp->variables.n; k++)
		error = sp->variables.v[k].remove ? rca_drop(x,
		    sp->variables.v[k].key) : rca_set(x, sp->variables.v[k].key,
		    sp->variables.v[k].value != NULL ? sp->variables.v[k].value :
		    "", err, sizeof(err));
	/* rca_write() puts back what it wrote when it fails. */
	if (error == 0)
		error = rca_write(x, NULL, err, sizeof(err));
	if (error == 0 && w->dry) {
		/* What would be written, each variable, and what else. */
		const char	*said = "";

		if (enable != 0)
			said = wfmt(w, "%s=\"%s\"", rcvar, enable > 0 ? "YES" :
			    "NO");
		for (size_t k = 0; k < sp->variables.n; k++)
			said = wfmt(w, "%s%s%s%s%s%s", said, said[0] != '\0' ?
			    " " : "", sp->variables.v[k].remove ? "-x " : "",
			    sp->variables.v[k].key, sp->variables.v[k].remove ?
			    "" : "=", sp->variables.v[k].remove ? "" : wfmt(w,
			    "\"%s\"", sp->variables.v[k].value != NULL ?
			    sp->variables.v[k].value : ""));
		step_end(w, step, true, "%s: %s%s%s; not done: a dry run",
		    RC_ARCANA, said, err[0] != '\0' ? "; " : "", err);
		service_job_forget(x);
		return (0);
	}
	step_end(w, step, error == 0, error == 0 ? NULL : "%s", err[0] !=
	    '\0' ? err : strerror(error));
	if (error != 0) {
		*errp = wtext(w, wstrdup(w, err[0] != '\0' ? err :
		    strerror(error)));
		rca_close(x);
		free(x);
		return (-1);
	}
	if (xp != NULL)
		*xp = x;
	else
		service_job_forget(x);
	return (0);
}

/* A safe job's service change put back: every file as it was. */
int
service_job_undo(struct work *w, struct rca *x, const char **errp)
{
	int	step;

	(void)errp;
	step = step_begin(w, STEP_FILE, "write", "%s and your rc.conf "
	    "files, as they were", RC_ARCANA);
	if (w->dry) {
		const char	*said = "";

		for (size_t i = 0; i < x->nwas; i++)
			said = wfmt(w, "%s%s%s%s", said, i > 0 ? ", " : "",
			    x->was[i].path, x->was[i].there ? "" :
			    " (removed)");
		step_end(w, step, true, "put back as they were: %s; not done: "
		    "a dry run", said);
		return (0);
	}
	rca_undo(x);
	step_end(w, step, true, NULL);
	return (0);
}

void
service_job_forget(struct rca *x)
{

	if (x == NULL)
		return;
	rca_close(x);
	free(x);
}

typedef struct arcana_services_services_convert_output_service ysvc_taken;
typedef struct arcana_services_services_convert_output_service_variable
    yvar_taken;

/*
 * Service svc's <svc>_* variables in the user's files x reads, each
 * where it is (file, line, value), in the order rc(8) reads them; one
 * the files do not settle, or whose line sh(1) may not run, said left
 * in every entry of its name: it is not taken.  The entries are a's.
 */
static int
taken_of(cbl_yarena *a, struct rca *x, const char *svc, yvar_taken **vp,
    size_t *nvp)
{
	struct vc_file	 f;
	yvar_taken	*v = NULL;
	char		 err[256], prefix[80];
	size_t		 nv = 0, cap = 0, plen, rl;
	int		 error = 0;

	rl = opts.root != NULL ? strlen(opts.root) : 0;
	plen = (size_t)snprintf(prefix, sizeof(prefix), "%s_", svc);
	for (size_t i = 0; error == 0 && i < x->nuser; i++) {
		if (vc_read(&f, VC_SH, x->user[i], err, sizeof(err)) == -1) {
			logmsg(LOG_WARNING, "%s: %s", x->user[i], err);
			continue;
		}
		for (size_t k = 0; error == 0 && k < f.na; k++) {
			const struct vc_assign *as = &f.a[k];
			yvar_taken *t;

			if (strncmp(as->name, prefix, plen) != 0)
				continue;
			if (nv == cap) {
				cap = cap > 0 ? cap * 2 : 8;
				if ((t = cbl_yarena_alloc(a, cap * sizeof(*t))) ==
				    NULL) {
					error = ENOMEM;
					break;
				}
				if (nv > 0)
					memcpy(t, v, nv * sizeof(*v));
				v = t;
			}
			t = &v[nv];
			memset(t, 0, sizeof(*t));
			if ((t->name = astrdup(a, as->name)) == NULL ||
			    (t->file = astrdup(a, x->user[i] + rl)) == NULL ||
			    (as->value != NULL && (t->value = astrdup(a,
			    as->value)) == NULL)) {
				error = ENOMEM;
				break;
			}
			t->line = (uint32_t)as->line;
			if ((as->flags & VC_COND) != 0)
				t->left = "its line may or may not run (an if, "
				    "a loop, a function): move it by hand";
			else if ((as->flags & VC_OPAQUE) != 0)
				t->left = "set in a way not read here (a "
				    "command's environment, a subshell): move "
				    "it by hand";
			else if (as->value == NULL)
				t->left = "its value is not a literal (an "
				    "expansion): move it by hand";
			nv++;
		}
		vc_free(&f);
	}
	/* A name left anywhere is left everywhere. */
	for (size_t j = 0; error == 0 && j < nv; j++)
		for (size_t k = 0; v[j].left != NULL && k < nv; k++)
			if (v[k].left == NULL && strcmp(v[k].name, v[j].name) ==
			    0)
				v[k].left = v[j].left;
	*vp = v;
	*nvp = nv;
	return (error);
}

/*
 * The convert action (arcana-services): the n services named, none
 * every script the host has, their rc.conf configuration moved under
 * Arcana as running reads it: each <name>_* variable of the user's
 * files set in Arcana's file, by the last file that sets it, and
 * commented out where it is in theirs, by rca_write()'s rules (what is
 * not accepted refused, every file put back where a later service's
 * write fails); dry, the files as they are.  out lists what was taken
 * or would be, a service with such variables at a time; its strings
 * are a's.
 */
int
yservices_convert(cbl_req *req, const char *const *names, size_t n, bool dry,
    cbl_yarena *a, struct arcana_services_services_convert_output *out)
{
	struct services_rsp	 r;
	struct rca		*x;
	struct work		 w;
	ysvc_taken		*sv = NULL;
	const char		*const *all, **every;
	char			 err[512];
	size_t			 nall, nsv = 0, cap = 0, nx = 0;
	int			 error = 0;

	work_init(&w);
	memset(&r, 0, sizeof(r));
	service_scripts(&w, &r);
	if (n == 0) {
		if ((every = cbl_yarena_alloc(a, (r.services.n + 1) *
		    sizeof(*every))) == NULL) {
			work_free(&w);
			return (ENOMEM);
		}
		/* A script whose name is no variable's stem (ftp-proxy,
		 * its own name= another) has no <name>_ variables to take. */
		nall = 0;
		for (size_t i = 0; i < r.services.n; i++)
			if (vc_name_ok(VC_SH, r.services.v[i].name))
				every[nall++] = r.services.v[i].name;
		all = every;
	} else {
		all = names;
		nall = n;
		for (size_t i = 0; i < n; i++) {
			size_t k;

			for (k = 0; k < r.services.n && (!valid_service(
			    names[i]) || strcmp(r.services.v[k].name,
			    names[i]) != 0); k++)
				;
			if (k == r.services.n) {
				(void)snprintf(err, sizeof(err), "%s: no such "
				    "service", names[i]);
				(void)cbl_req_set_yerr(req, err, 0);
				work_free(&w);
				return (EINVAL);
			}
		}
	}
	if ((x = calloc(nall + 1, sizeof(*x))) == NULL) {
		work_free(&w);
		return (ENOMEM);
	}
	err[0] = '\0';
	for (size_t i = 0; error == 0 && i < nall; i++) {
		yvar_taken	*v;
		size_t		 nv, ntake = 0;

		if ((error = rca_open(&x[nx], all[i], err, sizeof(err))) != 0)
			break;
		if ((error = taken_of(a, &x[nx], all[i], &v, &nv)) != 0) {
			rca_close(&x[nx]);
			break;
		}
		if (nv == 0) {
			rca_close(&x[nx]);
			continue;
		}
		if (nsv == cap) {
			ysvc_taken *t;

			cap = cap > 0 ? cap * 2 : 8;
			if ((t = cbl_yarena_alloc(a, cap * sizeof(*t))) == NULL) {
				rca_close(&x[nx]);
				error = ENOMEM;
				break;
			}
			if (nsv > 0)
				memcpy(t, sv, nsv * sizeof(*sv));
			sv = t;
		}
		memset(&sv[nsv], 0, sizeof(sv[nsv]));
		if ((sv[nsv].name = astrdup(a, all[i])) == NULL) {
			rca_close(&x[nx]);
			error = ENOMEM;
			break;
		}
		sv[nsv].variable.v = v;
		sv[nsv].variable.n = nv;
		nsv++;
		/* Set in order: the last file's value wins, as rc(8) has
		 * it. */
		for (size_t k = 0; error == 0 && k < nv; k++)
			if (v[k].left == NULL) {
				ntake++;
				if (!dry)
					error = rca_set(&x[nx], v[k].name,
					    v[k].value, err, sizeof(err));
			}
		if (dry || ntake == 0) {
			rca_close(&x[nx]);
			continue;
		}
		nx++;
		if (error == 0)
			error = rca_write(&x[nx - 1], req, err, sizeof(err));
	}
	if (error != 0) {
		for (size_t i = nx; i-- > 0; )
			rca_undo(&x[i]);
		if (error != EEXIST) {
			(void)cbl_req_set_yerr(req, err[0] != '\0' ? err :
			    strerror(error), 0);
			if (nx > 0)
				logmsg(LOG_WARNING, "services convert: %s: "
				    "rc.conf as it was", err);
		}
	} else {
		out->service.v = sv;
		out->service.n = nsv;
		if (nx > 0)
			logmsg(LOG_NOTICE, "services convert: %zu service%s "
			    "under Arcana's rc.conf file", nx, nx == 1 ? "" :
			    "s");
	}
	for (size_t i = 0; i < nx; i++)
		rca_close(&x[i]);
	free(x);
	work_free(&w);
	return (error);
}

typedef struct arcana_services_services_release_output_service ysvc_given;
typedef struct arcana_services_services_release_output_service_variable
    yvar_given;
typedef struct
    arcana_services_services_release_output_service_variable_restored
    yline_given;

/* Room in p (a's) for one more of n elements of size sz, *cap of them. */
static void *
agrow(cbl_yarena *a, const void *p, size_t n, size_t *cap, size_t sz)
{
	void	*t;

	if (n < *cap)
		return ((void *)(uintptr_t)p);
	*cap = *cap > 0 ? *cap * 2 : 8;
	if ((t = cbl_yarena_alloc(a, *cap * sz)) != NULL && n > 0)
		memcpy(t, p, n * sz);
	return (t);
}

/* The entry of name (its len bytes) in *v, added if it has none. */
static yvar_given *
given(cbl_yarena *a, yvar_given **v, size_t *nv, size_t *cap,
    const char *name, size_t len)
{
	yvar_given	*t;
	char		*s;

	for (size_t i = 0; i < *nv; i++)
		if (strlen((*v)[i].name) == len && strncmp((*v)[i].name, name,
		    len) == 0)
			return (&(*v)[i]);
	if ((t = agrow(a, *v, *nv, cap, sizeof(**v))) == NULL ||
	    (s = cbl_yarena_alloc(a, len + 1)) == NULL)
		return (NULL);
	*v = t;
	memcpy(s, name, len);
	s[len] = '\0';
	t = &(*v)[(*nv)++];
	memset(t, 0, sizeof(*t));
	t->name = s;
	return (t);
}

/* The variables of prefix's whose lines in f rca_write() commented out
 * ("#var=...  # taken by Arcana"), each added to *v. */
static int
marked_of(cbl_yarena *a, const struct vc_file *f, const char *prefix,
    yvar_given **v, size_t *nv, size_t *cap)
{
	static const char mark[] = "  # " RCA_TAKEN;
	const char	*p, *q, *eol, *end = f->text + f->len;
	size_t		 plen = strlen(prefix), n;

	for (p = f->text; f->len > 0 && p < end; p = eol + 1) {
		if ((eol = memchr(p, '\n', (size_t)(end - p))) == NULL)
			eol = end;
		if (*p != '#' || (size_t)(eol - p) < sizeof(mark) ||
		    memcmp(eol - (sizeof(mark) - 1), mark, sizeof(mark) - 1) !=
		    0)
			continue;
		for (q = p + 1; *q == ' ' || *q == '\t'; q++)
			;
		for (n = 0; q + n < eol && (q[n] == '_' ||
		    isalnum((unsigned char)q[n])); n++)
			;
		if (q + n < eol && q[n] == '=' && n > plen &&
		    strncmp(q, prefix, plen) == 0 && given(a, v, nv, cap, q,
		    n) == NULL)
			return (ENOMEM);
	}
	return (0);
}

/*
 * One service given back (the release action), in memory: its <svc>_*
 * variables out of Arcana's file (*mine: there were some), and every
 * line of the user's that rca_write() commented out for one put back
 * (vc_uncomment()), uf[i] x->user[i] so changed, ufc[i] set where it
 * was.  *vp: each variable, what was put back where, what was only
 * dropped and what rc(8) reads now if not Arcana's value; a's.
 */
static int
give_back(cbl_yarena *a, struct rca *x, const char *svc, struct vc_file *uf,
    bool *ufc, bool *mine, yvar_given **vp, size_t *nvp, char *err,
    size_t errlen)
{
	yvar_given	*v = NULL;
	char		 prefix[80], why[400];
	size_t		 nv = 0, cap = 0, plen, rl;
	int		*was = NULL, error = 0;

	rl = opts.root != NULL ? strlen(opts.root) : 0;
	plen = (size_t)snprintf(prefix, sizeof(prefix), "%s_", svc);
	*mine = false;
	/* Arcana's, in its order; then those commented in theirs alone. */
	for (size_t k = 0; k < x->f->na; k++) {
		const struct vc_assign *as = &x->f->a[k];
		yvar_given *t;

		if (strncmp(as->name, prefix, plen) != 0)
			continue;
		if ((t = given(a, &v, &nv, &cap, as->name,
		    strlen(as->name))) == NULL)
			return (ENOMEM);
		t->arcana_value = NULL;
		if (as->value != NULL && (t->arcana_value = astrdup(a,
		    as->value)) == NULL)
			return (ENOMEM);
	}
	for (size_t i = 0; i < x->nuser; i++) {
		if (vc_read(&uf[i], VC_SH, x->user[i], why, sizeof(why)) ==
		    -1) {
			logmsg(LOG_WARNING, "%s: %s", x->user[i], why);
			memset(&uf[i], 0, sizeof(uf[i]));
		}
		if ((error = marked_of(a, &uf[i], prefix, &v, &nv, &cap)) != 0)
			return (error);
	}
	for (size_t j = 0; error == 0 && j < nv; j++) {
		yvar_given *t = &v[j];
		const struct vc_assign *now = NULL;
		size_t rcap = 0, nwas, at = 0;
		int r;

		for (size_t i = 0; error == 0 && i < x->nuser; i++) {
			/* Its lines before: what comes back is the rest. */
			free(was);
			if ((was = calloc(uf[i].na + 1, sizeof(*was))) == NULL) {
				error = ENOMEM;
				break;
			}
			nwas = 0;
			for (size_t k = 0; k < uf[i].na; k++)
				if (strcmp(uf[i].a[k].name, t->name) == 0)
					was[nwas++] = uf[i].a[k].line;
			errno = 0;
			if ((r = vc_uncomment(&uf[i], t->name, RCA_TAKEN, why,
			    sizeof(why))) == -1) {
				(void)snprintf(err, errlen, "%s: %s",
				    x->user[i] + rl, why);
				error = errno != 0 ? errno : EINVAL;
				break;
			}
			if (r == 0)
				continue;
			ufc[i] = true;
			for (size_t k = 0; error == 0 && k < uf[i].na; k++) {
				const struct vc_assign *as = &uf[i].a[k];
				yline_given *l;
				size_t m;

				if (strcmp(as->name, t->name) != 0)
					continue;
				for (m = 0; m < nwas && was[m] != as->line; m++)
					;
				if (m < nwas)
					continue;
				if ((l = agrow(a, t->restored.v, t->restored.n,
				    &rcap, sizeof(*l))) == NULL) {
					error = ENOMEM;
					break;
				}
				t->restored.v = l;
				l = &l[t->restored.n++];
				memset(l, 0, sizeof(*l));
				l->line = (uint32_t)as->line;
				if ((l->file = astrdup(a, x->user[i] + rl)) ==
				    NULL || (as->value != NULL && (l->value =
				    astrdup(a, as->value)) == NULL))
					error = ENOMEM;
			}
		}
		if (error != 0)
			break;
		if (vc_get(x->f, t->name) != NULL) {
			if ((error = rca_unset(x, t->name, err, errlen)) != 0)
				break;
			*mine = true;
		}
		/* What rc(8) reads now: the last of theirs. */
		for (size_t i = x->nuser; now == NULL && i-- > 0; )
			if ((now = vc_get(&uf[i], t->name)) != NULL)
				at = i;
		if (t->restored.n == 0) {
			if (now != NULL)
				(void)snprintf(why, sizeof(why), "no line of "
				    "yours to put back; %s line %d sets it",
				    x->user[at] + rl, now->line);
			else
				(void)snprintf(why, sizeof(why), "no line of "
				    "yours to put back; it falls back to the "
				    "defaults (/etc/defaults/rc.conf, the "
				    "script's own)");
			if ((t->dropped = astrdup(a, why)) == NULL)
				error = ENOMEM;
		}
		if (error == 0 && now != NULL && now->value != NULL &&
		    t->arcana_value != NULL && strcmp(now->value,
		    t->arcana_value) != 0) {
			(void)snprintf(why, sizeof(why), "\"%s\" now (%s line "
			    "%d), not Arcana's \"%s\"", now->value,
			    x->user[at] + rl, now->line, t->arcana_value);
			if ((t->differs = astrdup(a, why)) == NULL)
				error = ENOMEM;
		}
	}
	free(was);
	*vp = v;
	*nvp = nv;
	return (error);
}

/*
 * The release action (arcana-services), convert's inverse: the n
 * services named given back to the user's files, each <name>_* variable
 * out of Arcana's file and every line of theirs convert commented out
 * put back; all or nothing, every file put back where a later service's
 * write fails; dry, the files as they are.  out lists each service and
 * what was given back, or would be; its strings are a's.
 */
int
yservices_release(cbl_req *req, const char *const *names, size_t n,
    bool dry, cbl_yarena *a,
    struct arcana_services_services_release_output *out)
{
	struct rca	*x;
	ysvc_given	*sv;
	char		 err[512];
	size_t		 nx = 0;
	int		 error = 0;

	err[0] = '\0';
	if (n == 0)
		(void)snprintf(err, sizeof(err), "name the services to give "
		    "back");
	for (size_t i = 0; err[0] == '\0' && i < n; i++) {
		if (!valid_service(names[i]) || !vc_name_ok(VC_SH, names[i]) ||
		    strlen(names[i]) > 64)
			(void)snprintf(err, sizeof(err), "%s: not a service's "
			    "name", names[i]);
		for (size_t k = 0; err[0] == '\0' && k < i; k++)
			if (strcmp(names[k], names[i]) == 0)
				(void)snprintf(err, sizeof(err), "%s: named "
				    "twice", names[i]);
	}
	if (err[0] != '\0') {
		(void)cbl_req_set_yerr(req, err, 0);
		return (EINVAL);
	}
	if ((sv = cbl_yarena_alloc(a, n * sizeof(*sv))) == NULL ||
	    (x = calloc(n, sizeof(*x))) == NULL)
		return (ENOMEM);
	memset(sv, 0, n * sizeof(*sv));
	for (size_t i = 0; error == 0 && i < n; i++) {
		struct rca	*r = &x[nx];
		struct vc_file	*uf;
		yvar_given	*v = NULL;
		size_t		 nv = 0, nuser;
		bool		*ufc, mine = false, any = false;

		if ((sv[i].name = astrdup(a, names[i])) == NULL) {
			error = ENOMEM;
			break;
		}
		if ((error = rca_open(r, names[i], err, sizeof(err))) != 0)
			break;
		nuser = r->nuser;
		ufc = NULL;
		if ((uf = calloc(nuser + 1, sizeof(*uf))) == NULL ||
		    (ufc = calloc(nuser + 1, sizeof(*ufc))) == NULL) {
			free(uf);
			rca_close(r);
			error = ENOMEM;
			break;
		}
		error = give_back(a, r, names[i], uf, ufc, &mine, &v, &nv, err,
		    sizeof(err));
		sv[i].variable.v = v;
		sv[i].variable.n = nv;
		for (size_t k = 0; k < nuser; k++)
			any = any || ufc[k];
		if (error == 0 && !dry && (any || mine)) {
			/* Theirs first, then Arcana's without it. */
			nx++;
			for (size_t k = 0; error == 0 && k < nuser; k++)
				if (ufc[k])
					error = rca_put(r, &uf[k], r->user[k],
					    err, sizeof(err));
			if (error == 0 && mine)
				error = rca_put(r, r->f, r->path, err,
				    sizeof(err));
		} else
			rca_close(r);
		for (size_t k = 0; k < nuser; k++)
			vc_free(&uf[k]);
		free(ufc);
		free(uf);
	}
	if (error != 0) {
		for (size_t i = nx; i-- > 0; )
			rca_undo(&x[i]);
		(void)cbl_req_set_yerr(req, err[0] != '\0' ? err :
		    strerror(error), 0);
		if (nx > 0)
			logmsg(LOG_WARNING, "services release: %s: rc.conf as "
			    "it was", err);
	} else {
		out->service.v = sv;
		out->service.n = n;
		if (nx > 0)
			logmsg(LOG_NOTICE, "services release: %zu service%s "
			    "given back to your rc.conf files", nx, nx == 1 ?
			    "" : "s");
	}
	for (size_t i = 0; i < nx; i++)
		rca_close(&x[i]);
	free(x);
	return (error);
}
