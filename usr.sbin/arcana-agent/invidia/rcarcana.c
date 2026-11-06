/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: Arcana's rc.conf variables, as a commit of the candidate
 * writes them (PLAN-SDN-YANG 2.3, decided 2026-10-28; the merge,
 * docs/notes/config-files.md).  Where, by arcana-agent's config-files
 * (cfgfiles.c):
 *
 *	arcana	one file of Arcana's own, /usr/local/etc/rc.conf.d/arcana,
 *		which /etc/rc.conf's rc_conf_files names so that every rc
 *		script reads it after the admin's files (rc-conf-files to
 *		accept, once)
 *	system	the admin's files: each variable in the last of the files
 *		rc(8) reads that sets it, else /etc/rc.conf; f is then
 *		Arcana's own values as the ledger has them, never a file
 *
 * A variable a commit changes that the admin's files set to something
 * else is a warning first, rc-conf-conflict.  Accepted, nothing of the
 * admin's is commented out: a word list (cf_list_var(), what sysrc(8)'s
 * += adds to) is merged, the admin's words in their order then
 * Arcana's not among them, a word the commit takes out (one Arcana
 * had, or the caller read) out of it; in Arcana's file (theirs left as
 * it is, Arcana's read last wins without hiding their words) or where
 * theirs is.  A value that no merge of words gives is refused again,
 * rc-conf-merge, its rows kept as pending for the page's merge editor:
 * resolve's value for it, or Arcana's with the warning accepted, is
 * written then.  The ledger keeps what Arcana changed of theirs (the
 * value before, after, Arcana's own) for release, and to know a value
 * already merged: not asked again.  Every file is kept as it was until
 * the change is through: rca_undo() puts them back, the ledger too.
 * Lines an older agent commented out ("# taken by Arcana") are read by
 * release and by the switch, never written.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"
#include "collect.h"
#include "varconf.h"

#define	RC_DEFAULTS	"/etc/defaults/rc.conf"
#define	RC_CONF		"/etc/rc.conf"

/* A path under the agent's root (a test's tree), in buf. */
static const char *
rooted(char *buf, size_t len, const char *path)
{

	(void)snprintf(buf, len, "%s%s", opts.root != NULL ? opts.root : "",
	    path);
	return (buf);
}

/* A file as it was, to put back. */
static int
keep(struct rca *x, const char *path)
{
	struct rca_was	*w;
	struct stat	 sb;
	FILE		*fp;

	for (size_t i = 0; i < x->nwas; i++)
		if (strcmp(x->was[i].path, path) == 0)
			return (0);
	if ((w = reallocarray(x->was, x->nwas + 1, sizeof(*w))) == NULL)
		return (ENOMEM);
	x->was = w;
	w = &x->was[x->nwas];
	memset(w, 0, sizeof(*w));
	if ((w->path = strdup(path)) == NULL)
		return (ENOMEM);
	if ((fp = fopen(path, "re")) != NULL) {
		w->there = true;
		if (fstat(fileno(fp), &sb) == 0 && sb.st_size > 0 &&
		    (w->text = malloc((size_t)sb.st_size)) != NULL)
			w->len = fread(w->text, 1, (size_t)sb.st_size, fp);
		w->mode = sb.st_mode & 07777;
		fclose(fp);
	}
	x->nwas++;
	return (0);
}

int
rca_keep(struct rca *x, const char *path)
{

	return (keep(x, path));
}

/* A copy of f, made with vc_parse(). */
static struct vc_file *
copy_of(const struct vc_file *f, char *err, size_t errlen)
{
	struct vc_file	*c;

	if ((c = calloc(1, sizeof(*c))) == NULL)
		return (NULL);
	if (vc_parse(c, VC_SH, f->text != NULL ? f->text : "", f->len, err,
	    errlen) == -1) {
		free(c);
		return (NULL);
	}
	return (c);
}

int
rca_open(struct rca *x, const char *svc, char *err, size_t errlen)
{
	struct cf_ledger led;
	char	**all;
	size_t	  n;
	char	  apath[MAXPATHLEN];

	memset(x, 0, sizeof(*x));
	x->sys = cf_system();
	rooted(apath, sizeof(apath), RC_ARCANA);
	if ((x->f = calloc(1, sizeof(*x->f))) == NULL)
		return (ENOMEM);
	if (!x->sys) {
		(void)snprintf(x->path, sizeof(x->path), "%s", apath);
		if (vc_read(x->f, VC_SH, x->path, err, errlen) == -1) {
			free(x->f);
			x->f = NULL;
			return (errno != 0 ? errno : EIO);
		}
	} else {
		/* Arcana's own values, as the ledger has them. */
		rooted(x->path, sizeof(x->path), RC_CONF);
		if (vc_parse(x->f, VC_SH, "", 0, err, errlen) == -1) {
			free(x->f);
			x->f = NULL;
			return (ENOMEM);
		}
		if (cf_ledger_read(&led) == 0) {
			for (size_t i = 0; i < led.n; i++)
				if (led.v[i].kind == CF_RC &&
				    led.v[i].arcana != NULL)
					(void)vc_set(x->f, led.v[i].var,
					    led.v[i].arcana, err, errlen);
			cf_ledger_free(&led);
		}
		err[0] = '\0';
	}
	if ((x->base = copy_of(x->f, err, errlen)) == NULL) {
		rca_close(x);
		return (ENOMEM);
	}
	/* The user's: what rc(8) reads for svc, but Arcana's file. */
	if (vc_rc_files(opts.root != NULL ? opts.root : "", "/usr/local", svc,
	    "arcana", &all, &n, err, errlen) == -1) {
		rca_close(x);
		return (errno != 0 ? errno : EIO);
	}
	if ((x->user = calloc(n + 1, sizeof(*x->user))) == NULL) {
		vc_rc_files_free(all, n);
		rca_close(x);
		return (ENOMEM);
	}
	for (size_t i = 0; i < n; i++) {
		if (strcmp(all[i], apath) == 0) {
			free(all[i]);
			continue;
		}
		x->user[x->nuser++] = all[i];
	}
	free(all);
	return (0);
}

const char *
rca_where(const struct rca *x)
{

	return (x->sys ? "your rc.conf files" : RC_ARCANA);
}

/* What rca_get() answered first for name; NULL if it was not asked. */
static const struct rca_seen *
seen_of(const struct rca *x, const char *name)
{

	for (size_t i = 0; i < x->nseen; i++)
		if (strcmp(x->seen[i].name, name) == 0)
			return (&x->seen[i]);
	return (NULL);
}

static void
saw(struct rca *x, const char *name, const char *value)
{
	struct rca_seen	*s;

	if (seen_of(x, name) != NULL || (s = reallocarray(x->seen,
	    x->nseen + 1, sizeof(*s))) == NULL)
		return;
	x->seen = s;
	s = &s[x->nseen];
	if ((s->name = strdup(name)) == NULL)
		return;
	s->value = value != NULL ? strdup(value) : NULL;
	x->nseen++;
}

const char *
rca_get(struct rca *x, const char *name)
{
	const struct vc_assign	*a;
	const char		*v = NULL;
	char			 err[128];

	if ((a = vc_get(x->f, name)) != NULL)
		v = a->value != NULL ? a->value : "";
	else {
		if (x->uf == NULL) {
			if ((x->uf = calloc(x->nuser + 1, sizeof(*x->uf))) ==
			    NULL)
				return (NULL);
			for (size_t i = 0; i < x->nuser; i++)
				if (vc_read(&x->uf[i], VC_SH, x->user[i], err,
				    sizeof(err)) == -1)
					memset(&x->uf[i], 0, sizeof(x->uf[i]));
		}
		for (size_t i = x->nuser; v == NULL && i-- > 0; )
			if ((a = vc_get(&x->uf[i], name)) != NULL)
				v = a->value != NULL ? a->value : "";
	}
	saw(x, name, v);
	return (v);
}

int
rca_set(struct rca *x, const char *name, const char *value, char *err,
    size_t errlen)
{

	if (vc_set(x->f, name, value, err, errlen) == -1)
		return (errno != 0 ? errno : EINVAL);
	return (0);
}

int
rca_drop(struct rca *x, const char *name)
{
	char	**v, err[64];

	(void)vc_unset(x->f, name, err, sizeof(err));
	for (size_t i = 0; i < x->ndrop; i++)
		if (strcmp(x->drop[i], name) == 0)
			return (0);
	if ((v = reallocarray(x->drop, x->ndrop + 1, sizeof(*v))) == NULL)
		return (ENOMEM);
	x->drop = v;
	if ((x->drop[x->ndrop] = strdup(name)) == NULL)
		return (ENOMEM);
	x->ndrop++;
	return (0);
}

int
rca_unset(struct rca *x, const char *name, char *err, size_t errlen)
{

	if (vc_unset(x->f, name, err, errlen) == -1)
		return (errno != 0 ? errno : EINVAL);
	return (0);
}

int
rca_put(struct rca *x, const struct vc_file *f, const char *path, char *err,
    size_t errlen)
{
	int	error;

	if ((error = keep(x, path)) != 0)
		return (error);
	if (vc_write(f, path, 0644, err, errlen) == -1)
		return (errno != 0 ? errno : EIO);
	return (0);
}

void
rca_close(struct rca *x)
{

	if (x->uf != NULL) {
		for (size_t i = 0; i < x->nuser; i++)
			vc_free(&x->uf[i]);
		free(x->uf);
	}
	if (x->f != NULL) {
		vc_free(x->f);
		free(x->f);
	}
	if (x->base != NULL) {
		vc_free(x->base);
		free(x->base);
	}
	vc_rc_files_free(x->user, x->nuser);
	for (size_t i = 0; i < x->ndrop; i++)
		free(x->drop[i]);
	free(x->drop);
	for (size_t i = 0; i < x->nseen; i++) {
		free(x->seen[i].name);
		free(x->seen[i].value);
	}
	free(x->seen);
	for (size_t i = 0; i < x->nwas; i++) {
		free(x->was[i].path);
		free(x->was[i].text);
	}
	free(x->was);
	memset(x, 0, sizeof(*x));
}

void
rca_undo(struct rca *x)
{
	FILE	*fp;

	for (size_t i = x->nwas; i-- > 0; ) {
		struct rca_was *w = &x->was[i];

		if (!w->there) {
			(void)unlink(w->path);
			continue;
		}
		if ((fp = fopen(w->path, "we")) == NULL)
			continue;
		if (w->len > 0)
			(void)fwrite(w->text, 1, w->len, fp);
		(void)fchmod(fileno(fp), w->mode != 0 ? w->mode : 0644);
		(void)fclose(fp);
	}
}

/* Whether list, rc_conf_files' words, names path. */
static bool
names(const char *list, const char *path)
{
	size_t	len = strlen(path);

	for (const char *p = list; (p = strstr(p, path)) != NULL; p += len)
		if ((p == list || p[-1] == ' ' || p[-1] == '\t') &&
		    (p[len] == '\0' || p[len] == ' ' || p[len] == '\t'))
			return (true);
	return (false);
}

/* Whether warning tag is accepted: by req, or without one by x's list. */
static bool
accepted(const struct rca *x, cbl_req *req, const char *tag)
{

	if (req != NULL)
		return (cbl_req_yaccepts(req, tag));
	for (size_t i = 0; i < x->naccept; i++)
		if (x->accept[i] != NULL && strcmp(x->accept[i], tag) == 0)
			return (true);
	return (false);
}

/* A refusal with its app-tag and words, for req; without one, in err. */
static int
refuse(cbl_req *req, const char *tag, const char *text, char *err,
    size_t errlen)
{

	if (req == NULL) {
		(void)snprintf(err, errlen, "%s", text);
		return (EEXIST);
	}
	(void)cbl_req_set_yapptag(req, tag);
	(void)cbl_req_set_yerr(req, text, 0);
	return (EEXIST);
}

/* What is said, a piece at a time, into buf. */
static void
say(char *buf, size_t len, const char *fmt, ...) __printflike(3, 4);

static void
say(char *buf, size_t len, const char *fmt, ...)
{
	va_list	ap;
	size_t	at = strlen(buf);

	if (at + 1 >= len)
		return;
	va_start(ap, fmt);
	(void)vsnprintf(buf + at, len - at, fmt, ap);
	va_end(ap);
}

/*
 * A variable a commit changes: Arcana's value p (NULL: taken out), the
 * admin's (u, the last of their files that sets it, ui), and what is
 * written (val, NULL: unset).
 */
struct op {
	char			*name;		/* a copy: f changes */
	char			*p;
	int			 ui;
	const struct vc_assign	*u;
	bool			 list;
	bool			 conflict;	/* rc-conf-conflict */
	bool			 merge;		/* rc-conf-merge: no value yet */
	bool			 resolved;	/* resolve's value */
	bool			 approved;	/* merged before, as it is */
	bool			 write;		/* val to write */
	char			*val;
	const struct cf_led	*led;		/* while the ops are made */
	bool			 hadled;
	char			*lbefore;	/* led's before, a copy */
};

static struct op *
op_of(struct op *v, size_t n, const char *name)
{

	for (size_t i = 0; i < n; i++)
		if (strcmp(v[i].name, name) == 0)
			return (&v[i]);
	return (NULL);
}

static int
op_add(struct op **v, size_t *n, const char *name, const char *p)
{
	struct op	*t;

	if (op_of(*v, *n, name) != NULL)
		return (0);
	if ((t = reallocarray(*v, *n + 1, sizeof(**v))) == NULL)
		return (ENOMEM);
	*v = t;
	t = &t[(*n)++];
	memset(t, 0, sizeof(*t));
	t->ui = -1;
	if ((t->name = strdup(name)) == NULL ||
	    (p != NULL && (t->p = strdup(p)) == NULL))
		return (ENOMEM);
	return (0);
}

static bool
eq(const char *a, const char *b)
{

	return (a != NULL && b != NULL && strcmp(a, b) == 0);
}

/* The words a commit takes out of name: those the caller saw, or
 * Arcana had, that p has not. */
static char *
removed(const struct rca *x, const struct op *o)
{
	const struct rca_seen	*s = seen_of(x, o->name);
	const struct vc_assign	*b;
	const char		*prev = NULL;

	if (s != NULL)
		prev = s->value;
	else if (o->led != NULL)
		prev = o->led->arcana;
	else if ((b = vc_get(x->base, o->name)) != NULL)
		prev = b->value;
	return (cf_minus(prev != NULL ? prev : "", o->p != NULL ? o->p :
	    ""));
}

int
rca_write(struct rca *x, cbl_req *req, char *err, size_t errlen)
{
	struct vc_file	 rc, dflt, *uf = NULL, rcnew;
	struct cf_ledger led;
	struct op	*ops = NULL;
	struct cf_pend	*pend = NULL;
	const struct vc_assign *a;
	char		 path[MAXPATHLEN], lpath[MAXPATHLEN], said[1536];
	char		*list = NULL;
	size_t		 nops = 0, npend = 0;
	bool		*ufc = NULL, rcf = false, conflict = false;
	bool		 merge = false, rcnew_used = false, ledc = false;
	int		 error = 0;

	memset(&rc, 0, sizeof(rc));
	memset(&rcnew, 0, sizeof(rcnew));
	memset(&led, 0, sizeof(led));
	said[0] = '\0';
	rooted(path, sizeof(path), RC_CONF);
	/* rc_conf_files: names Arcana's file, or will (Arcana's alone). */
	if (!x->sys) {
		if (vc_read(&rc, VC_SH, path, err, errlen) == -1)
			return (errno != 0 ? errno : EIO);
		if ((a = vc_get(&rc, "rc_conf_files")) != NULL &&
		    a->value != NULL)
			list = strdup(a->value);
		else if (vc_read(&dflt, VC_SH, rooted(lpath, sizeof(lpath),
		    RC_DEFAULTS), err, errlen) == 0) {
			a = vc_get(&dflt, "rc_conf_files");
			list = strdup(a != NULL && a->value != NULL ?
			    a->value : "/etc/rc.conf /etc/rc.conf.local");
			vc_free(&dflt);
		}
		if (list == NULL) {
			vc_free(&rc);
			return (ENOMEM);
		}
		if (!names(list, RC_ARCANA)) {
			if (!accepted(x, req, "rc-conf-files")) {
				(void)snprintf(said, sizeof(said), "Arcana keeps "
				    "what it writes of rc.conf in %s, which "
				    "rc(8) reads where rc_conf_files names it: "
				    "accept rc-conf-files to add it to %s, once",
				    RC_ARCANA, RC_CONF);
				free(list);
				vc_free(&rc);
				return (refuse(req, "rc-conf-files", said, err,
				    errlen));
			}
			rcf = true;
		}
	}
	if ((error = cf_ledger_read(&led)) != 0)
		goto out;
	/* What changed: set, or taken out. */
	for (size_t i = 0; error == 0 && i < x->f->na; i++) {
		const struct vc_assign *now = vc_get(x->f, x->f->a[i].name);
		const struct vc_assign *was = vc_get(x->base, now->name);

		if (now != &x->f->a[i] || now->value == NULL || (was != NULL &&
		    eq(was->value, now->value)))
			continue;
		error = op_add(&ops, &nops, now->name, now->value);
	}
	for (size_t i = 0; error == 0 && i < x->base->na; i++)
		if (vc_get(x->f, x->base->a[i].name) == NULL)
			error = op_add(&ops, &nops, x->base->a[i].name, NULL);
	for (size_t i = 0; error == 0 && i < x->ndrop; i++)
		if (vc_get(x->f, x->drop[i]) == NULL)
			error = op_add(&ops, &nops, x->drop[i], NULL);
	if (error != 0)
		goto out;
	/* The admin's files. */
	if (x->nuser > 0 && ((uf = calloc(x->nuser, sizeof(*uf))) == NULL ||
	    (ufc = calloc(x->nuser, sizeof(*ufc))) == NULL)) {
		error = ENOMEM;
		goto out;
	}
	for (size_t i = 0; error == 0 && i < x->nuser; i++)
		if (vc_read(&uf[i], VC_SH, x->user[i], err, errlen) == -1)
			error = errno != 0 ? errno : EIO;
	if (error != 0)
		goto out;
	/* Each: theirs, merged or asked for. */
	for (size_t j = 0; error == 0 && j < nops; j++) {
		struct op *o = &ops[j];
		const char *uv;
		char *r = NULL;

		for (size_t i = x->nuser; o->u == NULL && i-- > 0; )
			if ((o->u = vc_get(&uf[i], o->name)) != NULL)
				o->ui = (int)i;
		o->led = cf_ledger_get(&led, CF_RC, o->name);
		o->hadled = o->led != NULL;
		if (o->led != NULL && o->led->before != NULL &&
		    (o->lbefore = strdup(o->led->before)) == NULL) {
			error = ENOMEM;
			break;
		}
		o->list = cf_list_var(o->name);
		if (o->u == NULL) {
			/* Theirs set nothing: Arcana's as it is. */
			if (o->p != NULL && (o->val = strdup(o->p)) == NULL)
				error = ENOMEM;
			o->write = o->p != NULL;
			continue;
		}
		uv = o->u->value != NULL ? o->u->value : "";
		o->approved = o->led != NULL && eq(o->led->file,
		    cf_unrooted(x->user[o->ui])) && (x->sys ?
		    eq(o->led->after, uv) : eq(o->led->before, uv));
		if (o->p == NULL) {
			/* Taken out: Arcana's file alone, theirs as they
			 * are; in theirs, Arcana's words, or what Arcana
			 * wrote, back. */
			if (!x->sys) {
				/* A word list whose words of theirs the commit
				 * took out too: what is left, in Arcana's file
				 * (empty, an empty list), read after theirs. */
				if (!o->list || (r = removed(x, o)) == NULL ||
				    (o->val = cf_minus(uv, r)) == NULL) {
					error = o->list ? ENOMEM : 0;
					free(r);
					continue;
				}
				free(r);
				o->write = !cf_same_words(o->val, uv);
				continue;
			}
			o->write = true;
			if (o->list) {
				if ((r = removed(x, o)) == NULL ||
				    (o->val = cf_minus(uv, r)) == NULL)
					error = ENOMEM;
				free(r);
				if (error == 0 && o->val[0] == '\0') {
					free(o->val);
					o->val = NULL;
				}
			} else if (o->approved) {
				if (o->led->before != NULL &&
				    (o->val = strdup(o->led->before)) == NULL)
					error = ENOMEM;
			} else
				o->conflict = true;
			continue;
		}
		if (o->list) {
			if ((r = removed(x, o)) == NULL ||
			    (o->val = cf_merge(uv, o->p, r)) == NULL)
				error = ENOMEM;
			free(r);
			if (error != 0)
				break;
			o->conflict = !o->approved && !cf_same_words(o->val,
			    o->p);
			o->write = x->sys ? !eq(o->val, uv) : true;
			continue;
		}
		if (eq(uv, o->p) || o->approved) {
			o->val = strdup(o->p);
			o->write = x->sys ? !eq(o->p, uv) : true;
			if (o->val == NULL)
				error = ENOMEM;
			continue;
		}
		/* A value of theirs a merge of words does not give. */
		o->conflict = true;
		if ((o->val = cf_resolution(CF_RC, o->name)) != NULL)
			o->resolved = true;
		else if (accepted(x, req, "rc-conf-merge"))
			o->val = strdup(o->p);
		else
			o->merge = true;
		o->write = !o->merge;
	}
	if (error != 0)
		goto out;
	/* Warned of first: what of theirs a commit changes. */
	for (size_t j = 0; j < nops; j++) {
		const struct op *o = &ops[j];

		if (!o->conflict)
			continue;
		conflict = true;
		say(said, sizeof(said), "%s%s (%s line %d: \"%s\"; Arcana's %s%s%s"
		    "%s%s%s)", said[0] != '\0' ? ", " : "", o->name,
		    cf_unrooted(x->user[o->ui]), o->u->line, o->u->value != NULL ?
		    o->u->value : "", o->p != NULL ? "\"" : "", o->p != NULL ?
		    o->p : "none", o->p != NULL ? "\"" : "", o->list &&
		    o->val != NULL ? ", merged \"" : "", o->list && o->val !=
		    NULL ? o->val : "", o->list && o->val != NULL ? "\"" : "");
	}
	if (conflict && !accepted(x, req, "rc-conf-conflict")) {
		char	text[2048];

		(void)snprintf(text, sizeof(text), "your files set what Arcana "
		    "would change: %s; accept rc-conf-conflict: a word list "
		    "keeps your words and adds Arcana's (as sysrc += does), "
		    "%s; a value no merge gives is asked for next "
		    "(rc-conf-merge)", said, x->sys ? "written where yours is" :
		    "in Arcana's file, read after yours, your lines as they "
		    "are");
		error = refuse(req, "rc-conf-conflict", text, err, errlen);
		goto out;
	}
	/* Asked for: the values to merge by hand, kept for the page. */
	said[0] = '\0';
	for (size_t j = 0; j < nops; j++) {
		const struct op *o = &ops[j];
		struct cf_pend *t;

		if (!o->merge)
			continue;
		merge = true;
		if ((t = reallocarray(pend, npend + 1, sizeof(*pend))) == NULL) {
			error = ENOMEM;
			goto out;
		}
		pend = t;
		t = &t[npend++];
		t->kind = CF_RC;
		t->var = o->name;
		t->file = cf_unrooted(x->user[o->ui]);
		t->line = o->u->line;
		t->yours = o->u->value != NULL ? o->u->value : "";
		t->proposed = o->p;
		say(said, sizeof(said), "%s%s (%s line %d: yours \"%s\", "
		    "Arcana's \"%s\")", said[0] != '\0' ? ", " : "", o->name,
		    t->file, t->line, t->yours, t->proposed);
	}
	if (merge) {
		char	text[2048];

		cf_pending_set(pend, npend);
		(void)snprintf(text, sizeof(text), "no merge of words gives "
		    "these: %s; merge each by hand (arcana-agent's "
		    "config-files resolve, the page's merge) or accept "
		    "rc-conf-merge for Arcana's value, %s", said, x->sys ?
		    "written where yours is" : "in Arcana's file, yours left "
		    "as it is");
		error = refuse(req, "rc-conf-merge", text, err, errlen);
		goto out;
	}
	/* A dry run's: what would be written, said in err. */
	if (x->dry) {
		err[0] = '\0';
		for (size_t j = 0; j < nops; j++) {
			const struct op *o = &ops[j];

			if (!o->write || (!x->sys && o->u == NULL))
				continue;
			if (o->val != NULL)
				say(err, errlen, "%s%s=\"%s\" in %s", err[0] !=
				    '\0' ? "; " : "", o->name, o->val, x->sys &&
				    o->u != NULL ? cf_unrooted(x->user[o->ui]) :
				    x->sys ? RC_CONF : RC_ARCANA);
			else
				say(err, errlen, "%s%s taken out of your files",
				    err[0] != '\0' ? "; " : "", o->name);
		}
		if (rcf)
			say(err, errlen, "%s%s added to rc_conf_files in %s",
			    err[0] != '\0' ? "; " : "", RC_ARCANA, RC_CONF);
		goto out;
	}
	/* Written: Arcana's file, or theirs; the ledger with it. */
	for (size_t j = 0; error == 0 && j < nops; j++) {
		struct op *o = &ops[j];

		if (o->p == NULL || o->u == NULL) {
			if (cf_ledger_get(&led, CF_RC, o->name) != NULL &&
			    (o->p == NULL || !x->sys)) {
				cf_ledger_del(&led, CF_RC, o->name);
				ledc = true;
			}
		}
		if (!x->sys) {
			if (o->p == NULL && o->u != NULL && o->write &&
			    o->val != NULL) {
				if (vc_set(x->f, o->name, o->val, err, errlen) ==
				    -1) {
					error = errno != 0 ? errno : EIO;
					break;
				}
				error = cf_ledger_put(&led, CF_RC, o->name,
				    cf_unrooted(x->user[o->ui]), o->approved ?
				    o->lbefore : o->u->value, o->val, NULL);
				ledc = true;
				continue;
			}
			if (o->p != NULL && o->u != NULL && o->val != NULL) {
				if (vc_set(x->f, o->name, o->val, err, errlen) ==
				    -1) {
					error = errno != 0 ? errno : EIO;
					break;
				}
				if (!eq(o->val, o->u->value) || o->hadled) {
					error = cf_ledger_put(&led, CF_RC, o->name,
					    cf_unrooted(x->user[o->ui]),
					    o->approved ? o->lbefore :
					    o->u->value, o->val, o->p);
					ledc = true;
				}
			}
			continue;
		}
		if (o->p == NULL) {
			if (!o->write)
				continue;
			/* Out of every file of theirs, or what is left. */
			for (size_t i = 0; error == 0 && i < x->nuser; i++) {
				if (vc_get(&uf[i], o->name) == NULL)
					continue;
				if (o->val != NULL && (int)i != o->ui)
					continue;
				ufc[i] = true;
				if ((o->val != NULL ? vc_set(&uf[i], o->name,
				    o->val, err, errlen) : vc_unset(&uf[i],
				    o->name, err, errlen)) == -1)
					error = errno != 0 ? errno : EIO;
			}
			continue;
		}
		if (o->u == NULL) {
			/* /etc/rc.conf: the admin's if it is theirs. */
			struct vc_file *t = NULL;

			for (size_t i = 0; i < x->nuser && t == NULL; i++)
				if (strcmp(x->user[i], path) == 0) {
					t = &uf[i];
					ufc[i] = true;
				}
			if (t == NULL) {
				if (!rcnew_used && vc_read(&rcnew, VC_SH, path,
				    err, errlen) == -1) {
					error = errno != 0 ? errno : EIO;
					break;
				}
				rcnew_used = true;
				t = &rcnew;
			}
			if (vc_set(t, o->name, o->p, err, errlen) == -1) {
				error = errno != 0 ? errno : EIO;
				break;
			}
			error = cf_ledger_put(&led, CF_RC, o->name, RC_CONF,
			    NULL, o->p, o->p);
			ledc = true;
			continue;
		}
		if (o->write && o->val != NULL) {
			ufc[o->ui] = true;
			if (vc_set(&uf[o->ui], o->name, o->val, err, errlen) ==
			    -1) {
				error = errno != 0 ? errno : EIO;
				break;
			}
		}
		error = cf_ledger_put(&led, CF_RC, o->name,
		    cf_unrooted(x->user[o->ui]), o->approved ? o->lbefore :
		    o->u->value, o->val != NULL ? o->val : o->u->value, o->p);
		ledc = true;
	}
	if (error != 0)
		goto out;
	for (size_t j = 0; j < nops; j++)
		if (ops[j].conflict)
			cf_resolved(CF_RC, ops[j].name);
	/* Every file kept as it was first. */
	if (rcf) {
		char	*nl;

		if (asprintf(&nl, "%s %s", list, RC_ARCANA) == -1)
			error = ENOMEM;
		else {
			if ((error = keep(x, path)) == 0 && (vc_set(&rc,
			    "rc_conf_files", nl, err, errlen) == -1 ||
			    vc_write(&rc, path, 0644, err, errlen) == -1))
				error = errno != 0 ? errno : EIO;
			free(nl);
		}
	}
	for (size_t i = 0; error == 0 && i < x->nuser; i++)
		if (ufc[i] && ((error = keep(x, x->user[i])) != 0 ||
		    vc_write(&uf[i], x->user[i], 0644, err, errlen) == -1))
			error = error != 0 ? error : errno != 0 ? errno : EIO;
	if (error == 0 && rcnew_used && ((error = keep(x, path)) != 0 ||
	    vc_write(&rcnew, path, 0644, err, errlen) == -1))
		error = error != 0 ? error : errno != 0 ? errno : EIO;
	if (error == 0 && !x->sys) {
		char	dir[MAXPATHLEN], *slash;

		(void)snprintf(dir, sizeof(dir), "%s", x->path);
		if ((slash = strrchr(dir, '/')) != NULL) {
			*slash = '\0';
			(void)mkdir(dir, 0755);
		}
		if ((error = keep(x, x->path)) == 0 && vc_write(x->f, x->path,
		    0644, err, errlen) == -1)
			error = errno != 0 ? errno : EIO;
	}
	if (error == 0 && ledc && (error = keep(x, cf_ledger_path(lpath,
	    sizeof(lpath)))) == 0)
		error = cf_ledger_write(&led, err, errlen);
out:
	for (size_t j = 0; j < nops; j++) {
		free(ops[j].name);
		free(ops[j].p);
		free(ops[j].val);
		free(ops[j].lbefore);
	}
	free(ops);
	free(pend);
	for (size_t i = 0; uf != NULL && i < x->nuser; i++)
		vc_free(&uf[i]);
	free(uf);
	free(ufc);
	free(list);
	vc_free(&rc);
	if (rcnew_used)
		vc_free(&rcnew);
	cf_ledger_free(&led);
	if (error != 0 && error != EEXIST)
		rca_undo(x);
	return (error);
}

void
rca_rel_free(struct rca_rel *rel, size_t n)
{

	for (size_t i = 0; i < n; i++) {
		free(rel[i].name);
		free(rel[i].file);
		free(rel[i].value);
		free(rel[i].why);
	}
	free(rel);
}

/*
 * A service given back by the ledger: each entry of prefix's, what
 * Arcana added to the admin's taken back where it is as Arcana left
 * it; in the system's files (sys), or a merge in Arcana's file, which
 * the caller takes out (theirs are as they were).
 */
int
rca_release(struct rca *x, const char *prefix, bool dry,
    struct rca_rel **relp, size_t *nrelp, char *err, size_t errlen)
{
	struct cf_ledger led;
	struct vc_file	*uf = NULL;
	struct rca_rel	*rel = NULL, *t;
	char		 lpath[MAXPATHLEN], why[512];
	size_t		 plen = strlen(prefix), nrel = 0;
	bool		*ufc = NULL, ledc = false;
	int		 error;

	*relp = NULL;
	*nrelp = 0;
	if ((error = cf_ledger_read(&led)) != 0)
		return (error);
	if (x->nuser > 0 && ((uf = calloc(x->nuser, sizeof(*uf))) == NULL ||
	    (ufc = calloc(x->nuser, sizeof(*ufc))) == NULL)) {
		error = ENOMEM;
		goto out;
	}
	for (size_t i = 0; error == 0 && i < x->nuser; i++)
		if (vc_read(&uf[i], VC_SH, x->user[i], err, errlen) == -1)
			error = errno != 0 ? errno : EIO;
	for (size_t k = 0; error == 0 && k < led.n; ) {
		const struct cf_led *e = &led.v[k];
		const struct vc_assign *u = NULL;
		char *val = NULL;
		int ui = -1;

		if (e->kind != CF_RC || strncmp(e->var, prefix, plen) != 0) {
			k++;
			continue;
		}
		if ((t = reallocarray(rel, nrel + 1, sizeof(*rel))) == NULL) {
			error = ENOMEM;
			break;
		}
		rel = t;
		t = &rel[nrel++];
		memset(t, 0, sizeof(*t));
		if ((t->name = strdup(e->var)) == NULL) {
			error = ENOMEM;
			break;
		}
		why[0] = '\0';
		for (size_t i = x->nuser; u == NULL && i-- > 0; )
			if (eq(cf_unrooted(x->user[i]), e->file) &&
			    (u = vc_get(&uf[i], e->var)) != NULL)
				ui = (int)i;
		if (!x->sys) {
			/* Arcana's file's merge goes with it: theirs as
			 * they were. */
			(void)snprintf(why, sizeof(why), "%s's merge in "
			    "Arcana's file out; yours as it is", e->var);
		} else if (u == NULL || u->value == NULL)
			(void)snprintf(why, sizeof(why), "not in %s now: "
			    "nothing to give back", e->file);
		else if (cf_list_var(e->var)) {
			char *added = cf_minus(e->after, e->before != NULL ?
			    e->before : "");

			val = added != NULL ? cf_minus(u->value, added) : NULL;
			free(added);
			if (val == NULL) {
				error = ENOMEM;
				break;
			}
		} else if (eq(u->value, e->after)) {
			if (e->before != NULL && (val = strdup(e->before)) ==
			    NULL) {
				error = ENOMEM;
				break;
			}
		} else
			(void)snprintf(why, sizeof(why), "\"%s\" in %s now, not "
			    "what Arcana wrote (\"%s\"): left as it is",
			    u->value, e->file, e->after != NULL ? e->after :
			    "");
		if (why[0] != '\0') {
			if ((t->why = strdup(why)) == NULL)
				error = ENOMEM;
		} else {
			/* An emptied list, or a value that was not, out. */
			if (val != NULL && val[0] == '\0' && e->before == NULL) {
				free(val);
				val = NULL;
			}
			if ((val != NULL ? vc_set(&uf[ui], e->var, val, err,
			    errlen) : vc_unset(&uf[ui], e->var, err, errlen)) ==
			    -1)
				error = errno != 0 ? errno : EIO;
			ufc[ui] = true;
			t->file = strdup(e->file);
			t->line = u->line;
			t->value = val;
			val = NULL;
		}
		free(val);
		cf_ledger_del(&led, CF_RC, t->name);
		ledc = true;
	}
	if (error == 0 && !dry) {
		for (size_t i = 0; error == 0 && i < x->nuser; i++)
			if (ufc[i] && ((error = keep(x, x->user[i])) != 0 ||
			    vc_write(&uf[i], x->user[i], 0644, err, errlen) ==
			    -1))
				error = error != 0 ? error : errno != 0 ?
				    errno : EIO;
		if (error == 0 && ledc && (error = keep(x,
		    cf_ledger_path(lpath, sizeof(lpath)))) == 0)
			error = cf_ledger_write(&led, err, errlen);
	}
out:
	for (size_t i = 0; uf != NULL && i < x->nuser; i++)
		vc_free(&uf[i]);
	free(uf);
	free(ufc);
	cf_ledger_free(&led);
	if (error != 0) {
		rca_rel_free(rel, nrel);
		return (error);
	}
	*relp = rel;
	*nrelp = nrel;
	return (0);
}
