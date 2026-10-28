/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: arcana-sysctl and arcana-kernel served (PLAN-SDN-YANG
 * 3.1.6).  The kernel's values are read from the kernel (sysctl.c), a
 * GET's the first SYSCTL_GET of them, the read action's a part at a time
 * from where the one before ended; its modules and memory as do_kernel()
 * has them (kernel.c).  Running is what sysctl.conf(5) sets at boot and
 * what rc.conf(5)'s kld_list loads, read from the files rc(8) reads
 * (libvarconf).
 *
 * A commit of the candidate writes sysctl.conf in place, every other
 * line kept, and sets the kernel to each value changed, as sysctl(8)
 * does: a tunable the loader alone sets (CTLFLAG_TUN, not writable) is
 * refused first, for loader.conf(5); one the kernel refuses puts the file
 * back; one taken out of the file keeps its value until the next boot,
 * said with a warning (sysctl-unset).  kld_list is written to Arcana's
 * rc.conf file (rcarcana.c's rules, rc-conf-files and rc-conf-conflict):
 * what rc(8) loads at boot alone, the kernel as it is, said with a
 * warning (kld-list) where a module listed is not loaded or one taken out
 * is; a module is loaded and unloaded now by the module's load rpc and
 * unload action (yarcana.c).
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

#define	SYSCTL_GET	4000	/* values a GET gives, at most */

/* What an action or a commit failed of, said for the request. */
static int
said(cbl_req *req, const char *why)
{

	(void)cbl_req_set_yerr(req, why != NULL ? why : "it failed", 0);
	return (EIO);
}

static char *
astrdup(cbl_yarena *a, const char *s)
{
	size_t	len = strlen(s) + 1;
	char	*p;

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

/* The SID of top-level node mod:top's child name; 0 for none. */
static uint64_t
sid_of(const char *mod, const char *top, const char *name)
{
	const struct cbl_ynode	*n;

	if ((n = ynode_named(mod, top)) == NULL)
		return (0);
	for (uint32_t i = 0; i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]->sid);
	return (0);
}

/*
 * The values read, into the module's lists: the container's (a GET)
 * or the read action's output's, which have the same leaves.
 */
struct values {
	cbl_yarena				*a;
	struct arcana_sysctl_sysctl_value		*v;
	struct arcana_sysctl_sysctl_read_output_value	*rv;
	size_t					 n, cap;
	int					 error;
};

static void
value_in(void *arg, const struct sysctl_value *sv)
{
	struct values	*c = arg;
	const char	*name, *value, *type, *descr;

	if (c->error != 0 || c->n == c->cap)
		return;
	name = astrdup(c->a, sv->name);
	value = sv->value != NULL ? astrdup(c->a, sv->value) : NULL;
	type = sv->type != NULL ? astrdup(c->a, sv->type) : NULL;
	descr = sv->descr != NULL ? astrdup(c->a, sv->descr) : NULL;
	if (name == NULL || (sv->value != NULL && value == NULL) ||
	    (sv->type != NULL && type == NULL) || (sv->descr != NULL &&
	    descr == NULL)) {
		c->error = ENOMEM;
		return;
	}
	if (c->v != NULL) {
		struct arcana_sysctl_sysctl_value *v = &c->v[c->n];

		memset(v, 0, sizeof(*v));
		v->name = name;
		v->value = value;
		v->type = type;
		v->description = descr;
		/* A jail's, by sysctl(8): name and value alone. */
		v->has_writable = v->has_tunable = sv->type != NULL;
		v->writable = sv->rw;
		v->tunable = sv->tun;
	} else {
		struct arcana_sysctl_sysctl_read_output_value *v = &c->rv[c->n];

		memset(v, 0, sizeof(*v));
		v->name = name;
		v->value = value;
		v->type = type;
		v->description = descr;
		v->has_writable = v->has_tunable = sv->type != NULL;
		v->writable = sv->rw;
		v->tunable = sv->tun;
	}
	c->n++;
}

/*
 * What sysctl.conf sets at boot, as running has it: each line's name
 * and value, a name set twice its last value where it first is, as
 * sysctl(8) applies them.
 */
static int
sysctl_kept(cbl_yarena *a, struct arcana_sysctl_sysctl *o)
{
	struct arcana_sysctl_sysctl_kept	*k;
	struct vc_file				 f;
	char					 path[MAXPATHLEN], err[256];
	size_t					 n;

	sysctl_conf_lock();
	if (vc_read(&f, VC_SYSCTL, sysctl_conf_path(path, sizeof(path)), err,
	    sizeof(err)) == -1) {
		sysctl_conf_unlock();
		logmsg(LOG_WARNING, "sysctl.conf: %s", err);
		return (0);
	}
	sysctl_conf_unlock();
	if (f.na == 0) {
		vc_free(&f);
		return (0);
	}
	if ((k = cbl_yarena_alloc(a, f.na * sizeof(*k))) == NULL) {
		vc_free(&f);
		return (ENOMEM);
	}
	n = 0;
	for (size_t i = 0; i < f.na; i++) {
		const struct vc_assign *as = &f.a[i];
		size_t j;

		if (as->value == NULL || !sysctl_name_ok(as->name))
			continue;
		for (j = 0; j < n && strcmp(k[j].name, as->name) != 0; j++)
			;
		if (j == n) {
			if ((k[n].name = astrdup(a, as->name)) ==
			    NULL) {
				vc_free(&f);
				return (ENOMEM);
			}
			n++;
		}
		if ((k[j].value = astrdup(a, as->value)) == NULL) {
			vc_free(&f);
			return (ENOMEM);
		}
	}
	vc_free(&f);
	o->kept.n = n;
	o->kept.v = k;
	return (0);
}

int
arcana_sysctl_sysctl_get(cbl_req *req, struct arcana_sysctl *data,
    cbl_yarena *a)
{
	struct arcana_sysctl_sysctl	*o;
	struct values			 c;
	struct work			*w;
	const char			*e, *next;
	uint64_t			 total;
	int				 error;

	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	memset(o, 0, sizeof(*o));
	if ((error = sysctl_kept(a, o)) != 0)
		return (error);
	data->sysctl = o;
	/* Running, the candidate: the configuration alone. */
	if (cbl_req_ydatastore(req) != CBL_YDS_OPERATIONAL)
		return (0);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&c, 0, sizeof(c));
	c.a = a;
	c.cap = SYSCTL_GET;
	if ((c.v = cbl_yarena_alloc(a, c.cap * sizeof(*c.v))) == NULL)
		return (ENOMEM);
	e = NULL;
	if (sysctl_read(w, NULL, NULL, c.cap, value_in, &c, &total, &next,
	    &e) == -1)
		return (said(req, e));
	if (c.error != 0)
		return (c.error);
	o->value.n = c.n;
	o->value.v = c.v;
	if ((o->has_total = total > c.n))
		o->total = total;
	return (0);
}

int
arcana_sysctl_sysctl_read_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_sysctl_sysctl_read_input *in,
    struct arcana_sysctl_sysctl_read_output *out, cbl_yarena *a)
{
	struct values	 c;
	struct work	*w;
	const char	*e, *next, *prefix;
	uint64_t	 total;

	(void)target;
	prefix = in->prefix != NULL && in->prefix[0] != '\0' ? in->prefix :
	    NULL;
	if (prefix != NULL && !sysctl_name_ok(prefix))
		return (said(req, "a sysctl is named with letters, digits "
		    "and . _ - %"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&c, 0, sizeof(c));
	c.a = a;
	c.cap = in->has_count ? in->count : SYSCTL_GET;
	if ((c.rv = cbl_yarena_alloc(a, c.cap * sizeof(*c.rv))) == NULL)
		return (ENOMEM);
	e = NULL;
	total = 0;
	next = NULL;
	/* A vnet jail's network's, as its sysctl reads them: in one part. */
	if (in->jail != NULL && in->jail[0] != '\0') {
		if (!valid_jail(in->jail))
			return (said(req, "invalid jail name"));
		if (prefix == NULL || strncmp(prefix, "net.", 4) != 0)
			return (said(req, "a jail's sysctls are read under its "
			    "network's, net."));
		if (scope_enter(w, in->jail, &e) != 0 ||
		    sysctl_read_jail(w, prefix, value_in, &c, &e) == -1)
			return (said(req, e));
	} else if (sysctl_read(w, prefix, in->after != NULL &&
	    in->after[0] != '\0' ? in->after : NULL, c.cap, value_in, &c,
	    &total, &next, &e) == -1)
		return (said(req, e));
	if (c.error != 0)
		return (c.error);
	out->value.n = c.n;
	out->value.v = c.rv;
	if (next != NULL && (out->next = astrdup(a, next)) == NULL)
		return (ENOMEM);
	if ((out->has_total = total > c.n))
		out->total = total;
	return (0);
}

/* The kept value of name in s, NULL for none. */
static const char *
kept_value(const struct arcana_sysctl_sysctl *s, const char *name)
{

	for (size_t i = 0; i < s->kept.n; i++)
		if (strcmp(s->kept.v[i].name, name) == 0)
			return (s->kept.v[i].value);
	return (NULL);
}

int
arcana_sysctl_sysctl_edit(cbl_req *req, const struct arcana_sysctl *before,
    const struct arcana_sysctl *after)
{
	static const struct arcana_sysctl_sysctl none;
	const struct arcana_sysctl_sysctl *old, *new;
	struct vc_file	 f;
	struct rca	 x;
	struct work	 w;
	const char	*conf, *e, *was;
	char		 path[MAXPATHLEN], err[512], text[512];
	uint64_t	 sid;
	bool		 rw, tun, changed = false;
	int		 error = 0;

	old = before != NULL && before->sysctl != NULL ? before->sysctl : &none;
	new = after != NULL && after->sysctl != NULL ? after->sysctl : &none;
	for (size_t i = 0; i < new->kept.n; i++) {
		const struct arcana_sysctl_sysctl_kept *k = &new->kept.v[i];

		if (!sysctl_name_ok(k->name))
			return (said(req, "a sysctl is named with letters, "
			    "digits and . _ - %"));
		if (!sysctl_value_ok(k->value))
			return (said(req, "a sysctl's value is one line"));
		was = kept_value(old, k->name);
		if (was != NULL && strcmp(was, k->value) == 0)
			continue;
		changed = true;
		/* What the loader alone sets is for loader.conf. */
		if (sysctl_flags(k->name, &rw, &tun) && tun && !rw) {
			(void)snprintf(err, sizeof(err), "%s is a tunable the "
			    "loader sets, which sysctl.conf cannot: set it in "
			    "loader.conf(5)", k->name);
			return (said(req, err));
		}
	}
	for (size_t i = 0; !changed && i < old->kept.n; i++)
		changed = kept_value(new, old->kept.v[i].name) == NULL;
	if (!changed)
		return (0);
	sid = sid_of("arcana-sysctl", "sysctl", "kept");
	conf = sysctl_conf_path(path, sizeof(path));
	memset(&x, 0, sizeof(x));
	work_init(&w);
	sysctl_conf_lock();
	if ((error = rca_keep(&x, conf)) != 0) {
		sysctl_conf_unlock();
		rca_close(&x);
		work_free(&w);
		return (error);
	}
	if (vc_read(&f, VC_SYSCTL, conf, err, sizeof(err)) == -1) {
		sysctl_conf_unlock();
		rca_close(&x);
		work_free(&w);
		return (said(req, err));
	}
	if (ysysctl_conf_write(&f, new, err, sizeof(err)) == -1 ||
	    vc_write(&f, conf, 0644, err, sizeof(err)) == -1)
		error = errno != 0 ? errno : EIO;
	vc_free(&f);
	/* The kernel set to each value changed, as sysctl(8) does. */
	for (size_t i = 0; error == 0 && i < new->kept.n; i++) {
		const struct arcana_sysctl_sysctl_kept *k = &new->kept.v[i];

		was = kept_value(old, k->name);
		if (was != NULL && strcmp(was, k->value) == 0)
			continue;
		e = NULL;
		if (do_sysctl_set(&w, k->name, k->value, false, &e) != 0) {
			(void)snprintf(err, sizeof(err), "%s: %s", k->name, e !=
			    NULL ? e : "sysctl(8) refused it");
			error = EIO;
		}
	}
	if (error != 0) {
		rca_undo(&x);
		logmsg(LOG_WARNING, "sysctl.conf: %s: the file as it was", err);
	}
	sysctl_conf_unlock();
	/* Taken out: the kernel keeps the value until the next boot. */
	for (size_t i = 0; error == 0 && i < old->kept.n; i++) {
		if (kept_value(new, old->kept.v[i].name) != NULL)
			continue;
		(void)snprintf(text, sizeof(text), "%s is no longer set at "
		    "boot: the kernel keeps its value until then", old->kept.v[i].name);
		(void)cbl_req_ywarn(req, sid, "sysctl-unset", text);
	}
	rca_close(&x);
	work_free(&w);
	return (error != 0 ? said(req, err) : 0);
}

/*
 * What kld_list loads at boot, its words: as running has it, the last
 * of the files rc(8) reads for rc.d/kld that sets it (files); in the
 * operational state, as sysrc(8) resolves it now (rc_get(), what the
 * kmod job writes through too).
 */
static int
kld_kept(struct work *w, cbl_yarena *a, struct arcana_kernel_kernel *o,
    bool files)
{
	struct vc_file	 f;
	const char	*list = NULL, **v;
	char		**paths, *copy, *p, *word, err[256];
	size_t		 n, nv;

	if (!files) {
		if ((list = rc_get(w, "kld_list")) == NULL)
			return (0);
	} else {
		if (vc_rc_files(opts.root != NULL ? opts.root : "", "/usr/local",
		    "kld", "arcana", &paths, &n, err, sizeof(err)) != 0) {
			logmsg(LOG_WARNING, "kld_list: %s", err);
			return (0);
		}
		for (size_t i = 0; i < n; i++) {
			const struct vc_assign *as;

			if (vc_read(&f, VC_SH, paths[i], err, sizeof(err)) ==
			    -1) {
				logmsg(LOG_WARNING, "%s: %s", paths[i], err);
				continue;
			}
			if ((as = vc_get(&f, "kld_list")) != NULL &&
			    as->value != NULL)
				list = astrdup(a, as->value);
			vc_free(&f);
		}
		vc_rc_files_free(paths, n);
		if (list == NULL)
			return (0);
	}
	if ((copy = strdup(list)) == NULL)
		return (ENOMEM);
	nv = 0;
	for (p = copy; strsep(&p, " \t") != NULL;)
		nv++;
	free(copy);
	if ((v = cbl_yarena_alloc(a, (nv > 0 ? nv : 1) * sizeof(*v))) == NULL ||
	    (copy = strdup(list)) == NULL)
		return (ENOMEM);
	nv = 0;
	for (p = copy; (word = strsep(&p, " \t")) != NULL;) {
		if (word[0] == '\0')
			continue;
		if ((v[nv] = astrdup(a, word)) == NULL) {
			free(copy);
			return (ENOMEM);
		}
		nv++;
	}
	free(copy);
	o->kept.n = nv;
	o->kept.v = v;
	return (0);
}

int
arcana_kernel_kernel_get(cbl_req *req, struct arcana_kernel *data,
    cbl_yarena *a)
{
	struct arcana_kernel_kernel	*o;
	struct work			*w;
	const char			*json, *e;
	int				 error;

	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL ||
	    (w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(o, 0, sizeof(*o));
	if (cbl_req_ydatastore(req) == CBL_YDS_OPERATIONAL) {
		e = NULL;
		if ((json = do_kernel(w, &e)) == NULL) {
			logmsg(LOG_INFO, "a read of kernel for a model failed: "
			    "%s", e != NULL ? e : "no reason given");
			return (EIO);
		}
		if ((error = ykernel_from_json(json, a, o)) != 0)
			return (error);
	}
	if ((error = kld_kept(w, a, o, cbl_req_ydatastore(req) !=
	    CBL_YDS_OPERATIONAL)) != 0)
		return (error);
	data->kernel = o;
	return (0);
}

/* Whether list has name, with or without its .ko. */
static bool
listed(const struct arcana_kernel_kernel *k, const char *name)
{
	size_t	nl = strlen(name);

	if (nl > 3 && strcmp(name + nl - 3, ".ko") == 0)
		nl -= 3;
	for (size_t i = 0; i < k->kept.n; i++) {
		const char *m = k->kept.v[i];
		size_t ml = strlen(m);

		if (ml > 3 && strcmp(m + ml - 3, ".ko") == 0)
			ml -= 3;
		if (ml == nl && strncmp(m, name, nl) == 0)
			return (true);
	}
	return (false);
}

int
arcana_kernel_kernel_edit(cbl_req *req, const struct arcana_kernel *before,
    const struct arcana_kernel *after)
{
	static const struct arcana_kernel_kernel none;
	const struct arcana_kernel_kernel *old, *new;
	struct rca	 x;
	char		 err[512], text[512];
	uint64_t	 sid;
	bool		 changed;
	int		 error;

	old = before != NULL && before->kernel != NULL ? before->kernel : &none;
	new = after != NULL && after->kernel != NULL ? after->kernel : &none;
	for (size_t i = 0; i < new->kept.n; i++)
		if (!kmod_name_ok(new->kept.v[i]))
			return (said(req, "a module is named as kldload(8) "
			    "finds it, without a path"));
	changed = old->kept.n != new->kept.n;
	for (size_t i = 0; !changed && i < new->kept.n; i++)
		changed = strcmp(old->kept.v[i], new->kept.v[i]) != 0;
	if (!changed)
		return (0);
	if ((error = rca_open(&x, "kld", err, sizeof(err))) != 0)
		return (said(req, err));
	if (new->kept.n == 0)
		error = rca_drop(&x, "kld_list");
	else if (ykernel_kld_write(x.f, new, err, sizeof(err)) == -1)
		error = errno != 0 ? errno : EINVAL;
	if (error == 0)
		error = rca_write(&x, req, err, sizeof(err));
	if (error != 0) {
		rca_close(&x);
		return (error == EEXIST ? error : said(req, err));
	}
	rca_close(&x);
	/* The kernel as it is: said where the list and it differ. */
	sid = sid_of("arcana-kernel", "kernel", "kept");
	for (size_t i = 0; i < new->kept.n; i++) {
		if (listed(old, new->kept.v[i]) || kmod_loaded(new->kept.v[i]))
			continue;
		(void)snprintf(text, sizeof(text), "%s is not loaded: kld_list "
		    "loads it at the next boot; the load rpc loads it now",
		    new->kept.v[i]);
		(void)cbl_req_ywarn(req, sid, "kld-list", text);
	}
	for (size_t i = 0; i < old->kept.n; i++) {
		if (listed(new, old->kept.v[i]) || !kmod_loaded(old->kept.v[i]))
			continue;
		(void)snprintf(text, sizeof(text), "%s stays loaded until the "
		    "next boot, or its file's unload action", old->kept.v[i]);
		(void)cbl_req_ywarn(req, sid, "kld-list", text);
	}
	return (0);
}
