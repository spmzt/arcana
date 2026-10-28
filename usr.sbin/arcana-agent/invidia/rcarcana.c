/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: Arcana's rc.conf variables, as a commit of the candidate
 * writes them (PLAN-SDN-YANG 2.3, decided 2026-10-28): in one file of
 * Arcana's own, /usr/local/etc/rc.conf.d/arcana, which /etc/rc.conf's
 * rc_conf_files names so that every rc script reads it, after the
 * user's files.  The user's files are left as they are but for what
 * the user accepts:
 *
 *	rc-conf-files		rc_conf_files does not name Arcana's
 *				file: named, once, in /etc/rc.conf
 *	rc-conf-conflict	a variable Arcana writes (or takes out) the
 *				user's files set too: commented out where
 *				it is in theirs ("#var="value"  # taken by
 *				Arcana", the line kept), kept in Arcana's
 *
 * Unaccepted, the request is refused with that error-app-tag and says
 * what it would do.  Every file is kept as it was until the change is
 * through: rca_undo() puts them back, the commented line as it was.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
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

int
rca_open(struct rca *x, const char *svc, char *err, size_t errlen)
{
	char	**all;
	size_t	  n;

	memset(x, 0, sizeof(*x));
	rooted(x->path, sizeof(x->path), RC_ARCANA);
	if ((x->f = calloc(1, sizeof(*x->f))) == NULL)
		return (ENOMEM);
	if (vc_read(x->f, VC_SH, x->path, err, errlen) == -1) {
		free(x->f);
		x->f = NULL;
		return (errno != 0 ? errno : EIO);
	}
	/* The user's: what rc(8) reads for svc, but Arcana's file. */
	if (vc_rc_files(opts.root != NULL ? opts.root : "", "/usr/local", svc,
	    "arcana", &all, &n, err, errlen) == -1) {
		vc_free(x->f);
		free(x->f);
		x->f = NULL;
		return (errno != 0 ? errno : EIO);
	}
	if ((x->user = calloc(n + 1, sizeof(*x->user))) == NULL) {
		vc_rc_files_free(all, n);
		vc_free(x->f);
		free(x->f);
		x->f = NULL;
		return (ENOMEM);
	}
	for (size_t i = 0; i < n; i++) {
		if (strcmp(all[i], x->path) == 0) {
			free(all[i]);
			continue;
		}
		x->user[x->nuser++] = all[i];
	}
	free(all);
	return (0);
}

const char *
rca_get(struct rca *x, const char *name)
{
	const struct vc_assign	*a;
	char			 err[128];

	if ((a = vc_get(x->f, name)) != NULL)
		return (a->value != NULL ? a->value : "");
	if (x->uf == NULL) {
		if ((x->uf = calloc(x->nuser + 1, sizeof(*x->uf))) == NULL)
			return (NULL);
		for (size_t i = 0; i < x->nuser; i++)
			if (vc_read(&x->uf[i], VC_SH, x->user[i], err,
			    sizeof(err)) == -1)
				memset(&x->uf[i], 0, sizeof(x->uf[i]));
	}
	for (size_t i = x->nuser; i-- > 0; )
		if ((a = vc_get(&x->uf[i], name)) != NULL)
			return (a->value != NULL ? a->value : "");
	return (NULL);
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
	vc_rc_files_free(x->user, x->nuser);
	for (size_t i = 0; i < x->ndrop; i++)
		free(x->drop[i]);
	free(x->drop);
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

/* A refusal with its app-tag, err its words, for req. */
static int
refuse(cbl_req *req, const char *tag, const char *text)
{

	(void)cbl_req_set_yapptag(req, tag);
	(void)cbl_req_set_yerr(req, text, 0);
	return (EEXIST);
}

int
rca_write(struct rca *x, cbl_req *req, char *err, size_t errlen)
{
	struct vc_file	 rc, dflt, *uf = NULL;
	const struct vc_assign *a;
	char		 path[MAXPATHLEN], said[1024], *list = NULL;
	size_t		 off = 0;
	bool		 conflict = false, rcf = false;
	int		 error = 0;

	/* rc_conf_files: names Arcana's file, or will. */
	rooted(path, sizeof(path), RC_CONF);
	if (vc_read(&rc, VC_SH, path, err, errlen) == -1)
		return (errno != 0 ? errno : EIO);
	if ((a = vc_get(&rc, "rc_conf_files")) != NULL && a->value != NULL)
		list = strdup(a->value);
	else if (vc_read(&dflt, VC_SH, rooted(said, sizeof(said),
	    RC_DEFAULTS), err, errlen) == 0) {
		a = vc_get(&dflt, "rc_conf_files");
		list = strdup(a != NULL && a->value != NULL ? a->value :
		    "/etc/rc.conf /etc/rc.conf.local");
		vc_free(&dflt);
	}
	if (list == NULL) {
		vc_free(&rc);
		return (ENOMEM);
	}
	if (!names(list, RC_ARCANA)) {
		if (!cbl_req_yaccepts(req, "rc-conf-files")) {
			(void)snprintf(said, sizeof(said), "Arcana keeps what it "
			    "writes of rc.conf in %s, which rc(8) reads where "
			    "rc_conf_files names it: accept rc-conf-files to "
			    "add it to %s, once", RC_ARCANA, RC_CONF);
			free(list);
			vc_free(&rc);
			return (refuse(req, "rc-conf-files", said));
		}
		rcf = true;
	}
	/* The user's files: what Arcana's sets that one of them sets. */
	if (x->nuser > 0 && (uf = calloc(x->nuser, sizeof(*uf))) == NULL)
		error = ENOMEM;
	for (size_t i = 0; error == 0 && i < x->nuser; i++)
		if (vc_read(&uf[i], VC_SH, x->user[i], err, errlen) == -1)
			error = errno != 0 ? errno : EIO;
	said[0] = '\0';
	for (size_t j = 0; error == 0 && j < x->f->na + x->ndrop; j++)
		for (size_t i = 0; i < x->nuser; i++) {
			const struct vc_assign *u;
			const char *name = j < x->f->na ? x->f->a[j].name :
			    x->drop[j - x->f->na];

			if ((u = vc_get(&uf[i], name)) == NULL)
				continue;
			conflict = true;
			if (off < sizeof(said))
				off += (size_t)snprintf(said + off,
				    sizeof(said) - off, "%s%s (%s line %d)",
				    off == 0 ? "" : ", ", name, x->user[i],
				    u->line);
		}
	if (error == 0 && conflict && !cbl_req_yaccepts(req,
	    "rc-conf-conflict")) {
		char	text[1200];

		(void)snprintf(text, sizeof(text), "your files set what "
		    "Arcana would change: %s; accept rc-conf-conflict to have "
		    "them in Arcana's file alone, commented out in yours", said);
		error = refuse(req, "rc-conf-conflict", text);
	}
	/* Accepted: theirs commented out where they are, every file kept
	 * as it was first. */
	for (size_t i = 0; error == 0 && conflict && i < x->nuser; i++) {
		bool changed = false;

		for (size_t j = 0; error == 0 && j < x->f->na + x->ndrop; j++) {
			const char *name = j < x->f->na ? x->f->a[j].name :
			    x->drop[j - x->f->na];

			if (vc_get(&uf[i], name) != NULL) {
				if (!changed && (error = keep(x,
				    x->user[i])) != 0)
					break;
				changed = true;
				if (vc_comment(&uf[i], name, RCA_TAKEN, err,
				    errlen) == -1)
					error = errno != 0 ? errno : EIO;
			}
		}
		if (error == 0 && changed && vc_write(&uf[i], x->user[i], 0644,
		    err, errlen) == -1)
			error = errno != 0 ? errno : EIO;
	}
	if (error == 0 && rcf) {
		char	*nl;

		if (asprintf(&nl, "%s %s", list, RC_ARCANA) == -1)
			error = ENOMEM;
		else {
			/* The file as commenting the user's variables left it. */
			vc_free(&rc);
			memset(&rc, 0, sizeof(rc));
			if ((error = keep(x, path)) == 0 && (vc_read(&rc, VC_SH,
			    path, err, errlen) == -1 || vc_set(&rc,
			    "rc_conf_files", nl, err, errlen) == -1 ||
			    vc_write(&rc, path, 0644, err, errlen) == -1))
				error = errno != 0 ? errno : EIO;
			free(nl);
		}
	}
	if (error == 0) {
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
	for (size_t i = 0; uf != NULL && i < x->nuser; i++)
		vc_free(&uf[i]);
	free(uf);
	free(list);
	vc_free(&rc);
	if (error != 0 && error != EEXIST)
		rca_undo(x);
	return (error);
}
