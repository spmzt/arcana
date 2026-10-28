/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: arcana-jails served (PLAN-SDN-YANG 3.1.1).  A GET is the jails
 * read (lifecycle.c, yjails.c): the operational state every jail
 * configured or running, with its processes; running the configured
 * alone, each with its parameters as jail(8) -e resolves them and
 * whether rc.d/jail starts it at boot, from the files rc(8) reads
 * (libvarconf).
 *
 * A commit of the candidate writes what differs, a jail at a time: a
 * parameter changed is set in the jail's own block of its file, in
 * place, every other line kept (libjailconf: one value jc_replace()'s
 * way, several taken out and added one by one, a boolean a bare
 * statement); one taken out goes with its statements, unless the block
 * has none and the value is inherited from the file's defaults, which
 * is refused; a jail not there before is a block of its own appended
 * to jail.conf.d/<name>.conf (or jail.conf, where scope says so); one
 * gone is its file taken away, when that file is its alone.  Each
 * file is read back by libjailconf after every edit and by jail(8) -e
 * once all are written, the jails' parameters then what was asked;
 * what fails puts every file back as it was.  What starts at boot is
 * written to Arcana's rc.conf file (rcarcana.c's rules, rc-conf-files
 * and rc-conf-conflict): jail_list the jails with boot, jail_enable
 * yes with any and no with none, never an empty list that starts every
 * jail.  The running jail is left as it is: the actions change that
 * (yarcana.c).
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <cblink.h>

#include "jailconf.h"
#include "agent.h"
#include "collect.h"

typedef struct arcana_jails_jails_jail yjail;
typedef struct arcana_jails_jails_jail_param yparam;

/* A configuration file a commit changes: as it was, to put back. */
struct jfile {
	char	*path;
	char	*was;
	size_t	 waslen;
	bool	 there;
};

struct jedit {
	struct jfile	*f;
	size_t		 n;
	struct work	*w;
	char		 err[512];
};

/* What a commit failed of, said for the request. */
static int
said(cbl_req *req, const char *why)
{

	(void)cbl_req_set_yerr(req, why != NULL ? why : "it failed", 0);
	return (EIO);
}

int
arcana_jails_jails_get(cbl_req *req, struct arcana_jails *data, cbl_yarena *a)
{
	struct jails_read	 r;
	struct work		*w;
	bool			 state;
	int			 root;

	state = cbl_req_ydatastore(req) == CBL_YDS_OPERATIONAL;
	if ((w = ywork_told(req, a, state ? "jails" : "jails (configuration "
	    "only)", &root)) == NULL)
		return (ENOMEM);
	(void)do_list(w, !state, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok) {
		logmsg(LOG_INFO, "a read of jails for a model failed: %s",
		    r.error != NULL ? r.error : "no reason given");
		return (EIO);
	}
	/* Running, the candidate: cblink keeps the configuration alone. */
	return (yjails_from_list(&r, a, data));
}

static const yjail *
yjail_named(const struct arcana_jails *d, const char *name)
{

	if (d == NULL || d->jails == NULL)
		return (NULL);
	for (size_t i = 0; i < d->jails->jail.n; i++)
		if (strcmp(d->jails->jail.v[i].name, name) == 0)
			return (&d->jails->jail.v[i]);
	return (NULL);
}

static const yparam *
param_named(const yjail *j, const char *name)
{

	for (size_t i = 0; j != NULL && i < j->param.n; i++)
		if (strcmp(j->param.v[i].name, name) == 0)
			return (&j->param.v[i]);
	return (NULL);
}

/* A parameter as jail(8) names one: letters, digits and . _ -. */
static bool
param_name_ok(const char *s)
{

	if (s == NULL || s[0] == '\0' || s[0] == '.' || strlen(s) > 64)
		return (false);
	for (; *s != '\0'; s++)
		if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
		    (*s >= '0' && *s <= '9') || *s == '.' || *s == '_' ||
		    *s == '-'))
			return (false);
	return (true);
}

/* One line, as a value in jail.conf is. */
static bool
param_value_ok(const char *s)
{

	return (s != NULL && strpbrk(s, "\n\r") == NULL);
}

static bool
same_values(const yparam *a, const yparam *b)
{

	if (a->value.n != b->value.n)
		return (false);
	for (size_t i = 0; i < a->value.n; i++)
		if (strcmp(a->value.v[i], b->value.v[i]) != 0)
			return (false);
	return (true);
}

/* path as it is now, kept for the undo; 0, or an errno. */
static int
keep_file(struct jedit *e, const char *path)
{
	struct jfile	*f;
	FILE		*fp;
	long		 len;

	for (size_t i = 0; i < e->n; i++)
		if (strcmp(e->f[i].path, path) == 0)
			return (0);
	if ((f = reallocarray(e->f, e->n + 1, sizeof(*f))) == NULL)
		return (ENOMEM);
	e->f = f;
	f = &e->f[e->n];
	memset(f, 0, sizeof(*f));
	if ((f->path = strdup(path)) == NULL)
		return (ENOMEM);
	if ((fp = fopen(path, "re")) != NULL) {
		f->there = true;
		if (fseek(fp, 0, SEEK_END) == 0 && (len = ftell(fp)) > 0 &&
		    fseek(fp, 0, SEEK_SET) == 0 && (f->was = malloc((size_t)
		    len)) != NULL)
			f->waslen = fread(f->was, 1, (size_t)len, fp);
		fclose(fp);
	}
	e->n++;
	return (0);
}

/* Every file as it was. */
static void
undo(struct jedit *e)
{
	char	err[256];

	for (size_t i = e->n; i-- > 0; ) {
		struct jfile *f = &e->f[i];

		if (!f->there)
			(void)unlink(f->path);
		else if (jc_write(f->path, f->was != NULL ? f->was : "",
		    f->waslen, err, sizeof(err)) == -1)
			logmsg(LOG_ERR, "%s: not put back: %s", f->path, err);
	}
}

static void
jedit_free(struct jedit *e)
{

	for (size_t i = 0; i < e->n; i++) {
		free(e->f[i].path);
		free(e->f[i].was);
	}
	free(e->f);
	e->f = NULL;
	e->n = 0;
}

/* A value as jail.conf takes it: bare where it can be, quoted else. */
static void
put_value(FILE *fp, const char *v)
{
	bool	bare = v[0] != '\0';

	for (const char *p = v; bare && *p != '\0'; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') || strchr("_.-+/:", *p) != NULL))
			bare = false;
	if (bare) {
		fputs(v, fp);
		return;
	}
	fputc('"', fp);
	for (const char *p = v; *p != '\0'; p++) {
		if (*p == '"' || *p == '\\')
			fputc('\\', fp);
		fputc(*p, fp);
	}
	fputc('"', fp);
}

/*
 * A jail not there before: its block, every parameter a statement,
 * appended to the file.  The file of jail.conf.d named after it, or
 * jail.conf where scope says so.
 */
static int
jail_new(struct jedit *e, const yjail *j)
{
	FILE		*fp;
	char		*text, path[MAXPATHLEN];
	size_t		 len;
	int		 error;

	(void)snprintf(path, sizeof(path), "%s/%s.conf", opts.jail_conf_d,
	    j->name);
	if (j->scope != NULL && j->scope[0] != '\0' && strcmp(j->scope, path)
	    != 0 && strcmp(j->scope, opts.jail_conf) != 0) {
		(void)snprintf(e->err, sizeof(e->err), "%s: a new jail is "
		    "written to %s, or to %s", j->name, path, opts.jail_conf);
		return (EINVAL);
	}
	if (j->scope != NULL && j->scope[0] != '\0')
		(void)strlcpy(path, j->scope, sizeof(path));
	if ((error = keep_file(e, path)) != 0)
		return (error);
	if ((fp = open_memstream(&text, &len)) == NULL)
		return (errno);
	fprintf(fp, "%s {\n", j->name);
	for (size_t i = 0; i < j->param.n; i++) {
		const yparam *p = &j->param.v[i];

		fprintf(fp, "\t%s", p->name);
		for (size_t k = 0; k < p->value.n; k++) {
			fputs(k == 0 ? " = " : ", ", fp);
			put_value(fp, p->value.v[k]);
		}
		fputs(";\n", fp);
	}
	fputs("}\n", fp);
	if (fclose(fp) != 0) {
		free(text);
		return (errno);
	}
	{
		struct jfile	*f = &e->f[e->n - 1];
		char		*buf;
		size_t		 blen;

		/* After what the file has, on a line of its own. */
		blen = f->waslen + len + 2;
		if ((buf = malloc(blen)) == NULL) {
			free(text);
			return (ENOMEM);
		}
		if (f->waslen > 0)
			memcpy(buf, f->was, f->waslen);
		blen = f->waslen;
		if (blen > 0 && buf[blen - 1] != '\n')
			buf[blen++] = '\n';
		if (blen > 0)
			buf[blen++] = '\n';
		memcpy(buf + blen, text, len);
		blen += len;
		free(text);
		(void)mkdir(opts.jail_conf_d, 0755);
		/* jc_write() keeps a file's mode and owner: one made first. */
		if (!f->there) {
			int fd;

			if ((fd = open(path, O_WRONLY | O_CREAT | O_EXCL |
			    O_CLOEXEC | O_NOFOLLOW, 0644)) == -1) {
				free(buf);
				(void)snprintf(e->err, sizeof(e->err), "%s: %s",
				    path, strerror(errno));
				return (EIO);
			}
			(void)close(fd);
		}
		if (jc_write(path, buf, blen, e->err, sizeof(e->err)) == -1) {
			free(buf);
			return (EIO);
		}
		free(buf);
	}
	return (0);
}

/*
 * The block of jail name in its file, parsed as the file is now: f and
 * b.  jc_free() of jc when done.
 */
static int
block_of(struct jedit *e, const char *scope, const char *name,
    struct jc_conf *jc, struct jc_file **f, struct jc_block **b)
{

	memset(jc, 0, sizeof(*jc));
	if (jc_load(jc, scope) == -1 || (*b = jc_find(jc, name, f)) == NULL) {
		(void)snprintf(e->err, sizeof(e->err), "%s: its block is not "
		    "found in %s%s%s", name, scope, jc->error != NULL ? ": " :
		    "", jc->error != NULL ? jc->error : "");
		jc_free(jc);
		return (ENOENT);
	}
	return (0);
}

/* out, the file's new text, read back and written in its place. */
static int
block_put(struct jedit *e, struct jc_file *f, char *out, size_t len)
{
	struct jc_conf	jc;
	int		error;

	memset(&jc, 0, sizeof(jc));
	if (jc_load_buf(&jc, f->path, out, len) == -1) {
		(void)snprintf(e->err, sizeof(e->err), "%s: the edit does not "
		    "read back%s%s", f->path, jc.error != NULL ? ": " : "",
		    jc.error != NULL ? jc.error : "");
		jc_free(&jc);
		free(out);
		return (EINVAL);
	}
	jc_free(&jc);
	if ((error = keep_file(e, f->path)) != 0) {
		free(out);
		return (error);
	}
	if (jc_write(f->path, out, len, e->err, sizeof(e->err)) == -1) {
		free(out);
		return (EIO);
	}
	free(out);
	return (0);
}

/*
 * Parameter name of jail j (in scope) set to the values, or taken out
 * with remove: the first value in place of what was (jc_replace), a
 * boolean a bare statement, the others added one by one after it
 * (jc_edit).  The file written after each step, the next parsing it
 * anew: a statement's offsets hold for one edit.
 */
static int
param_set(struct jedit *e, const char *scope, const char *name,
    const char *pname, const char *const *vals, size_t nvals, bool remove)
{
	struct jc_conf	 jc;
	struct jc_file	*f;
	struct jc_block	*b;
	char		*out;
	size_t		 len;
	int		 n, error;

	if ((error = block_of(e, scope, name, &jc, &f, &b)) != 0)
		return (error);
	n = jc_replace(f, b, pname, remove ? NULL : nvals == 0 ? "" : vals[0],
	    &out, &len);
	jc_free(&jc);
	if (n < 0)
		return (ENOMEM);
	if (remove && n == 0) {
		free(out);
		(void)snprintf(e->err, sizeof(e->err), "%s: %s is inherited "
		    "from the file's defaults, not the jail's own: not taken "
		    "out here", name, pname);
		return (EINVAL);
	}
	if ((error = block_put(e, f, out, len)) != 0)
		return (error);
	for (size_t i = 1; !remove && i < nvals; i++) {
		if ((error = block_of(e, scope, name, &jc, &f, &b)) != 0)
			return (error);
		if (jc_edit(f, b, pname, vals[i], true, vals, i, &out, &len,
		    e->err, sizeof(e->err)) == -1) {
			jc_free(&jc);
			return (EINVAL);
		}
		jc_free(&jc);
		if ((error = block_put(e, f, out, len)) != 0)
			return (error);
	}
	return (0);
}

/* The file of jail.conf.d a jail gone was alone in: taken away. */
static int
jail_gone(struct jedit *e, const yjail *j)
{
	struct jc_conf	 jc;
	char		 path[MAXPATHLEN];
	size_t		 nblocks;
	int		 error;

	(void)snprintf(path, sizeof(path), "%s/%s.conf", opts.jail_conf_d,
	    j->name);
	memset(&jc, 0, sizeof(jc));
	if (j->scope == NULL || strcmp(j->scope, path) != 0 || jc_load(&jc,
	    path) == -1) {
		jc_free(&jc);
		(void)snprintf(e->err, sizeof(e->err), "%s is defined in %s, "
		    "not in a file of its own: edit the file", j->name,
		    j->scope != NULL ? j->scope : "jail.conf");
		return (EINVAL);
	}
	nblocks = 0;
	for (size_t i = 0; i < jc.nfiles; i++)
		nblocks += jc.files[i]->nblocks;
	jc_free(&jc);
	if (nblocks != 1) {
		(void)snprintf(e->err, sizeof(e->err), "%s has other jails "
		    "than %s: edit the file", path, j->name);
		return (EINVAL);
	}
	if ((error = keep_file(e, path)) != 0)
		return (error);
	if (unlink(path) == -1) {
		(void)snprintf(e->err, sizeof(e->err), "%s: %s", path,
		    strerror(errno));
		return (EIO);
	}
	return (0);
}

/* The jails with boot, a word each; "" with none. */
static const char *
boot_list(struct work *w, const struct arcana_jails *d)
{
	const char	*s = "";

	for (size_t i = 0; d != NULL && d->jails != NULL && i <
	    d->jails->jail.n; i++) {
		const yjail *j = &d->jails->jail.v[i];

		if (j->has_boot && j->boot)
			s = wfmt(w, "%s%s%s", s, s[0] != '\0' ? " " : "",
			    j->name);
	}
	return (s);
}

/*
 * After every file is written: jail(8) reads each scope touched again,
 * and each jail changed has the parameters asked for, those taken out
 * gone.
 */
static int
verify(struct jedit *e, const struct arcana_jails *before,
    const struct arcana_jails *after, const char *const *changed,
    size_t nchanged)
{
	struct cconf	 conf;

	conf_read(e->w, &conf);
	for (size_t i = 0; i < conf.nerrors; i++)
		for (size_t k = 0; k < e->n; k++)
			if (strcmp(conf.errors[i].scope, e->f[k].path) == 0) {
				(void)snprintf(e->err, sizeof(e->err), "jail(8) "
				    "does not take %s: %s", e->f[k].path,
				    conf.errors[i].message);
				return (EINVAL);
			}
	for (size_t i = 0; i < nchanged; i++) {
		const struct cjail	*cj = conf_jail(&conf, changed[i]);
		const yjail		*j = yjail_named(after, changed[i]);
		const yjail		*old = yjail_named(before, changed[i]);

		if (cj == NULL) {
			(void)snprintf(e->err, sizeof(e->err), "%s: not defined "
			    "once written", changed[i]);
			return (EINVAL);
		}
		for (size_t k = 0; k < j->param.n; k++) {
			const yparam		*p = &j->param.v[k];
			const struct arc_param	*q = cjail_param(cj, p->name);
			bool			 same = q != NULL && q->values.n
						    == p->value.n;

			for (size_t m = 0; same && m < p->value.n; m++)
				same = jc_value_equal(p->name, q->values.v[m],
				    p->value.v[m]);
			if (!same) {
				(void)snprintf(e->err, sizeof(e->err), "%s: %s "
				    "is not what was asked once jail(8) reads "
				    "it: the file's defaults or variables "
				    "have a say", changed[i], p->name);
				return (EINVAL);
			}
		}
		for (size_t k = 0; old != NULL && k < old->param.n; k++)
			if (param_named(j, old->param.v[k].name) == NULL &&
			    cjail_param(cj, old->param.v[k].name) != NULL) {
				(void)snprintf(e->err, sizeof(e->err), "%s: %s "
				    "stays once jail(8) reads it: the file's "
				    "defaults have it", changed[i],
				    old->param.v[k].name);
				return (EINVAL);
			}
	}
	return (0);
}

int
arcana_jails_jails_edit(cbl_req *req, const struct arcana_jails *before,
    const struct arcana_jails *after)
{
	struct jedit	 e;
	struct rca	 x;
	struct work	 w;
	const yjail	*old, *new;
	const char	**changed = NULL, *was, *want;
	size_t		 nold = 0, nnew = 0, nchanged = 0;
	char		 err[512];
	int		 error = 0;

	if (before != NULL && before->jails != NULL)
		nold = before->jails->jail.n;
	if (after != NULL && after->jails != NULL)
		nnew = after->jails->jail.n;
	/* Checked whole before a file is touched. */
	for (size_t i = 0; i < nnew; i++) {
		new = &after->jails->jail.v[i];
		if (!valid_jail(new->name))
			return (said(req, "invalid jail name"));
		old = yjail_named(before, new->name);
		if (old != NULL && new->scope != NULL && new->scope[0] != '\0'
		    && (old->scope == NULL || strcmp(old->scope, new->scope) !=
		    0)) {
			(void)snprintf(err, sizeof(err), "%s is defined in %s: "
			    "a jail is not moved to %s", new->name, old->scope
			    != NULL ? old->scope : "a file", new->scope);
			return (said(req, err));
		}
		for (size_t k = 0; k < new->param.n; k++) {
			const yparam *p = &new->param.v[k];

			if (!param_name_ok(p->name)) {
				(void)snprintf(err, sizeof(err), "%s: '%s' is no "
				    "parameter's name", new->name, p->name);
				return (said(req, err));
			}
			for (size_t m = 0; m < p->value.n; m++)
				if (!param_value_ok(p->value.v[m])) {
					(void)snprintf(err, sizeof(err), "%s: a "
					    "value of %s is more than a line",
					    new->name, p->name);
					return (said(req, err));
				}
		}
	}
	memset(&e, 0, sizeof(e));
	work_init(&w);
	e.w = &w;
	if ((changed = calloc(nnew > 0 ? nnew : 1, sizeof(*changed))) == NULL) {
		work_free(&w);
		return (ENOMEM);
	}
	for (size_t i = 0; error == 0 && i < nnew; i++) {
		bool	touched = false;

		new = &after->jails->jail.v[i];
		if ((old = yjail_named(before, new->name)) == NULL) {
			if ((error = jail_new(&e, new)) == 0)
				changed[nchanged++] = new->name;
			continue;
		}
		for (size_t k = 0; error == 0 && k < new->param.n; k++) {
			const yparam *p = &new->param.v[k], *q;

			if ((q = param_named(old, p->name)) != NULL &&
			    same_values(p, q))
				continue;
			error = param_set(&e, old->scope, new->name, p->name,
			    p->value.v, p->value.n, false);
			touched = true;
		}
		for (size_t k = 0; error == 0 && k < old->param.n; k++) {
			const yparam *q = &old->param.v[k];

			if (param_named(new, q->name) != NULL)
				continue;
			error = param_set(&e, old->scope, new->name, q->name,
			    NULL, 0, true);
			touched = true;
		}
		if (error == 0 && touched)
			changed[nchanged++] = new->name;
	}
	for (size_t i = 0; error == 0 && i < nold; i++) {
		old = &before->jails->jail.v[i];
		if (yjail_named(after, old->name) == NULL)
			error = jail_gone(&e, old);
	}
	if (error == 0 && e.n > 0)
		error = verify(&e, before, after, changed, nchanged);
	if (error != 0) {
		undo(&e);
		if (e.n > 0)
			logmsg(LOG_WARNING, "jails: %s: the files as they were",
			    e.err);
		error = said(req, e.err[0] != '\0' ? e.err : strerror(error));
		goto out;
	}
	/* What starts at boot, where that changed: Arcana's rc.conf file. */
	was = boot_list(&w, before);
	want = boot_list(&w, after);
	if (strcmp(was, want) != 0) {
		memset(&x, 0, sizeof(x));
		if ((error = rca_open(&x, "jail", err, sizeof(err))) != 0) {
			undo(&e);
			error = said(req, err);
			goto out;
		}
		if (want[0] == '\0') {
			if ((error = rca_set(&x, "jail_enable", "NO", err,
			    sizeof(err))) == 0)
				error = rca_drop(&x, "jail_list");
		} else if ((error = rca_set(&x, "jail_list", want, err,
		    sizeof(err))) == 0)
			error = rca_set(&x, "jail_enable", "YES", err,
			    sizeof(err));
		if (error == 0)
			error = rca_write(&x, req, err, sizeof(err));
		if (error != 0) {
			rca_undo(&x);
			undo(&e);
			if (error != EEXIST)
				error = said(req, err);
		}
		rca_close(&x);
	}
out:
	free(changed);
	jedit_free(&e);
	work_free(&w);
	return (error);
}
