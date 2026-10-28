/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: arcana-services served (PLAN-SDN-YANG 3.1.2).  A GET is the
 * services operation's read (services.c, yservices.c), with each
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
 * service-config takes them; the rcvar itself is enabled's alone.  The
 * service is left as it runs: the start, stop, restart and reload
 * actions change that (yarcana.c).
 */

#include <sys/param.h>

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
	struct arc_services_rsp	 r;
	struct work		*w;
	yservice		*v;
	int			 error;

	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	if (cbl_req_ydatastore(req) == CBL_YDS_OPERATIONAL) {
		(void)do_services(w, &r);
		if (!r.ok) {
			logmsg(LOG_INFO, "a read of services for a model failed: "
			    "%s", r.error != NULL ? r.error : "no reason given");
			return (EIO);
		}
	} else
		service_scripts(w, &r);
	if ((error = yservices_from(&r, NULL, 0, a, data)) != 0)
		return (error);
	/* Their rc.conf variables, from the files rc(8) reads. */
	v = (yservice *)(uintptr_t)data->services->service.v;
	for (size_t i = 0; i < data->services->service.n; i++) {
		bool has = v[i].has_enabled, on = v[i].enabled;

		if ((error = from_rc(a, &v[i])) != 0)
			return (error);
		/* What sysrc -A said, where it did: the defaults included. */
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
	struct arc_services_rsp	 r;
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
		for (size_t i = 0; i < r.services.n; i++)
			every[i] = r.services.v[i].name;
		all = every;
		nall = r.services.n;
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
