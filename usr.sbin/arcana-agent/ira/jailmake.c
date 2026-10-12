/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: jails made and taken away from the console, the way one keeps
 * them by hand.  /etc/jail.conf holds the defaults every jail shares;
 * each jail is a file of its own in /etc/jail.conf.d, which includes
 * them and holds the jail's block, and the templates it includes are
 * kept beside it as <name>.inc, outside rc.d/jail's *.conf; each jail
 * has a ZFS dataset of its own, mounted at its path, made from a base
 * jail's snapshot by a clone or by a copy (zfs send | zfs recv).  What
 * is written is read back by jail(8) before it is put in place, and
 * what fails undoes what was done before it.
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"

#define	TEXT_MAX	65536

static bool
word_ok(const char *s, size_t max)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || s[0] == '-' || s[0] == '.' ||
	    strlen(s) > max)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' &&
		    s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9') || s[i] ==
		    '_' || s[i] == '-' || s[i] == '.'))
			return (false);
	return (true);
}

/* A dataset that is not a pool's own: pool/a/b, ZFS's characters. */
static bool
dataset_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || s[0] == '-' || s[0] == '/' ||
	    strchr(s, '/') == NULL || strlen(s) > 255 || strstr(s, "//") !=
	    NULL || s[strlen(s) - 1] == '/')
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' &&
		    s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9') || strchr(
		    "_-.:/", s[i]) != NULL))
			return (false);
	return (true);
}

static bool
snapshot_ok(const char *s)
{
	const char	*at;
	char		 ds[256];

	if (s == NULL || (at = strchr(s, '@')) == NULL || strchr(at + 1,
	    '@') != NULL || (size_t)(at - s) >= sizeof(ds) || !word_ok(at +
	    1, 255))
		return (false);
	snprintf(ds, sizeof(ds), "%.*s", (int)(at - s), s);
	/* A pool's own dataset may be a base: pool@snap. */
	return (dataset_ok(ds) || word_ok(ds, 255));
}

/* An absolute path of plain characters, no .. in it. */
static bool
path_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] != '/' || strlen(s) < 2 || strlen(s) > 1024 ||
	    strstr(s, "/../") != NULL || strcmp(s + strlen(s) - 3, "/..") ==
	    0)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' &&
		    s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9') || strchr(
		    "_-./+", s[i]) != NULL))
			return (false);
	return (true);
}

/* What a jail-conf job asks, checked before it is queued. */
const char *
jail_conf_check(const struct arc_job_spec *sp)
{
	const char	*v = sp->verb;

	if (sp->safe)
		return ("a jail made or taken away is not undone by a timer: "
		    "not in safe mode");
	if (sp->jail != NULL && sp->jail[0] != '\0' && v != NULL &&
	    strcmp(v, "make") != 0 && strcmp(v, "remove") != 0)
		return ("only make and remove name a jail");
	if (v == NULL)
		return ("a jail-conf job has a verb: make, remove, defaults, "
		    "template, untemplate");
	if (strcmp(v, "make") == 0 || strcmp(v, "remove") == 0) {
		if (!word_ok(sp->jail, 64))
			return ("a jail's name is letters, digits and _ - ., 64 "
			    "at most");
		if (sp->dataset != NULL && sp->dataset[0] != '\0' &&
		    !dataset_ok(sp->dataset))
			return ("a jail's dataset is under a pool, pool/jails/"
			    "name, ZFS's characters");
		if (strcmp(v, "remove") == 0)
			return (NULL);
		if (sp->text == NULL || sp->text[0] == '\0' || strlen(sp->text) >
		    TEXT_MAX)
			return ("make has the jail's file as text");
		if ((sp->snapshot != NULL && sp->snapshot[0] != '\0') !=
		    (sp->dataset != NULL && sp->dataset[0] != '\0'))
			return ("a dataset is made from a snapshot: both, or "
			    "neither");
		if (sp->snapshot != NULL && sp->snapshot[0] != '\0') {
			if (!snapshot_ok(sp->snapshot))
				return ("the base is a snapshot, dataset@name");
			if (sp->copy == NULL || (strcmp(sp->copy, "clone") != 0 &&
			    strcmp(sp->copy, "send") != 0))
				return ("the dataset is made by clone or send");
			if (!path_ok(sp->path))
				return ("the dataset is mounted at the jail's path, "
				    "an absolute one");
		}
		return (NULL);
	}
	if (strcmp(v, "defaults") == 0)
		return (sp->text == NULL || sp->text[0] == '\0' || strlen(
		    sp->text) > TEXT_MAX ? "defaults has the file as text" :
		    NULL);
	if (strcmp(v, "template") == 0 || strcmp(v, "untemplate") == 0) {
		if (sp->names.n != 1 || !word_ok(sp->names.v[0], 64))
			return ("a template has one name, letters, digits and "
			    "_ - .");
		if (strcmp(v, "template") == 0 && (sp->text == NULL ||
		    strlen(sp->text) > TEXT_MAX))
			return ("template has its lines as text");
		return (NULL);
	}
	return ("a jail-conf job's verb is make, remove, defaults, template "
	    "or untemplate");
}

/* text written as path, mode 0644, in place at once. */
static int
put_file(struct work *w, const char *path, const char *text,
    const char **errp)
{
	const char	*tmp;
	size_t		 off, len;
	ssize_t		 n;
	int		 fd, step;

	tmp = wfmt(w, "%s.arcana-new", path);
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", path);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)) ==
	    -1)
		goto fail;
	len = strlen(text);
	for (off = 0; off < len; off += (size_t)n)
		if ((n = write(fd, text + off, len - off)) <= 0) {
			close(fd);
			goto fail;
		}
	if (fsync(fd) == -1 || close(fd) == -1 || rename(tmp, path) == -1)
		goto fail;
	step_end(w, step, true, NULL);
	return (0);
fail:
	*errp = wfmt(w, "%s: %s", path, strerror(errno));
	(void)unlink(tmp);
	step_end(w, step, false, "%s", *errp);
	return (-1);
}

/* A file's whole content, or NULL. */
static char *
get_file(struct work *w, const char *path, size_t *lenp)
{
	struct stat	 st;
	char		*buf;
	ssize_t		 n;
	int		 fd;

	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
		return (NULL);
	if (fstat(fd, &st) == -1 || st.st_size > 4 * TEXT_MAX) {
		close(fd);
		return (NULL);
	}
	buf = wcalloc(w, 1, (size_t)st.st_size + 1);
	n = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (n != st.st_size)
		return (NULL);
	*lenp = (size_t)n;
	return (buf);
}

static int
zfs(struct work *w, const char **errp, const char *a0, const char *a1,
    const char *a2, const char *a3, const char *a4, const char *a5)
{
	struct execres	 res;
	char		*argv[8];
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.zfs_bin;
	argv[n++] = (char *)(uintptr_t)a0;
	if (a1 != NULL)
		argv[n++] = (char *)(uintptr_t)a1;
	if (a2 != NULL)
		argv[n++] = (char *)(uintptr_t)a2;
	if (a3 != NULL)
		argv[n++] = (char *)(uintptr_t)a3;
	if (a4 != NULL)
		argv[n++] = (char *)(uintptr_t)a4;
	if (a5 != NULL)
		argv[n++] = (char *)(uintptr_t)a5;
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		if (errp != NULL)
			*errp = wtext(w, exec_error(w, &res, "zfs"));
		return (-1);
	}
	return (0);
}

/*
 * zfs send of the snapshot into zfs recv of the dataset, mounted at
 * path: a copy of its own, as two processes joined by a pipe.  The
 * children only make system calls, as a child of a process with
 * threads must.
 */
static int
send_recv(struct work *w, const char *snap, const char *ds,
    const char *path, const char **errp)
{
	char		*sv[5], *rv[8], mp[1100];
	pid_t		 sp, rp;
	int		 fd[2], ss, rs, step, null;

	snprintf(mp, sizeof(mp), "mountpoint=%s", path);
	sv[0] = (char *)(uintptr_t)opts.zfs_bin;
	sv[1] = (char *)(uintptr_t)"send";
	sv[2] = (char *)(uintptr_t)snap;
	sv[3] = NULL;
	rv[0] = (char *)(uintptr_t)opts.zfs_bin;
	rv[1] = (char *)(uintptr_t)"recv";
	rv[2] = (char *)(uintptr_t)"-o";
	rv[3] = mp;
	rv[4] = (char *)(uintptr_t)ds;
	rv[5] = NULL;
	step = step_begin(w, ARC_STEP_KIND_EXEC, "zfs", "send %s | zfs recv -o "
	    "%s %s", snap, mp, ds);
	if (pipe2(fd, O_CLOEXEC) == -1) {
		*errp = wfmt(w, "pipe: %s", strerror(errno));
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	null = open("/dev/null", O_RDWR | O_CLOEXEC);
	if ((sp = fork()) == 0) {
		dup2(fd[1], STDOUT_FILENO);
		if (null != -1)
			dup2(null, STDIN_FILENO);
		execv(sv[0], sv);
		_exit(127);
	}
	if (sp != -1 && (rp = fork()) == 0) {
		dup2(fd[0], STDIN_FILENO);
		if (null != -1)
			dup2(null, STDOUT_FILENO);
		execv(rv[0], rv);
		_exit(127);
	}
	close(fd[0]);
	close(fd[1]);
	if (null != -1)
		close(null);
	ss = rs = -1;
	if (sp != -1)
		while (waitpid(sp, &ss, 0) == -1 && errno == EINTR)
			;
	if (sp != -1 && rp != -1)
		while (waitpid(rp, &rs, 0) == -1 && errno == EINTR)
			;
	if (sp == -1 || rp == -1 || !WIFEXITED(ss) || WEXITSTATUS(ss) != 0 ||
	    !WIFEXITED(rs) || WEXITSTATUS(rs) != 0) {
		*errp = wfmt(w, "zfs send %s | zfs recv %s failed (send %d, recv "
		    "%d)", snap, ds, WIFEXITED(ss) ? WEXITSTATUS(ss) : -1,
		    WIFEXITED(rs) ? WEXITSTATUS(rs) : -1);
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, NULL);
	return (0);
}

/* Does a dataset exist? */
static bool
ds_exists(struct work *w, const char *ds)
{

	return (zfs(w, NULL, "list", "-H", "-o", "name", ds, NULL) == 0);
}

/* The one value of zfs get, or NULL. */
static const char *
ds_get(struct work *w, const char *ds, const char *prop)
{
	struct execres	 res;
	char		*argv[8];

	argv[0] = (char *)(uintptr_t)opts.zfs_bin;
	argv[1] = (char *)(uintptr_t)"get";
	argv[2] = (char *)(uintptr_t)"-H";
	argv[3] = (char *)(uintptr_t)"-o";
	argv[4] = (char *)(uintptr_t)"value";
	argv[5] = (char *)(uintptr_t)prop;
	argv[6] = (char *)(uintptr_t)ds;
	argv[7] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return (NULL);
	return (wtext(w, wstrndup(w, res.out, res.outlen > 0 &&
	    res.out[res.outlen - 1] == '\n' ? res.outlen - 1 : res.outlen)));
}

/*
 * jail(8)'s reading of file: the one jail it defines, that it is the
 * one named, and its path the one asked; *errp otherwise.
 */
static int
reads_back(struct work *w, const char *file, const char *name,
    const char *path, const char **errp)
{
	struct cjail	*js;
	const char	*e, *p;
	size_t		 n;

	if (conf_scope_read(w, file, &js, &n, &e) == -1) {
		*errp = wfmt(w, "jail(8) does not take it: %s", e != NULL ? e :
		    "no reason given");
		return (-1);
	}
	if (n != 1 || strcmp(js[0].name, name) != 0) {
		*errp = wfmt(w, "the file defines %zu jail%s, not the one jail "
		    "%s", n, n == 1 ? "" : "s", name);
		return (-1);
	}
	if (path != NULL && path[0] != '\0' && ((p = cjail_param1(&js[0],
	    "path")) == NULL || strcmp(p, path) != 0)) {
		*errp = wfmt(w, "the jail's path is %s, not %s, where its "
		    "dataset is mounted", p != NULL ? p : "not set", path);
		return (-1);
	}
	return (0);
}

static int
jail_make(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct arc_action_rsp	 ar;
	const char		*file, *tmp, *e;
	bool			 made;

	file = wfmt(w, "%s/%s.conf", opts.jail_conf_d, sp->jail);
	if (access(file, F_OK) == 0) {
		*errp = wfmt(w, "%s is there already", file);
		return (-1);
	}
	if (jail_getid(sp->jail) >= 0) {
		*errp = wfmt(w, "a jail %s runs already", sp->jail);
		return (-1);
	}
	(void)mkdir(opts.jail_conf_d, 0755);
	made = false;
	if (sp->dataset != NULL && sp->dataset[0] != '\0') {
		if (ds_exists(w, sp->dataset)) {
			*errp = wfmt(w, "the dataset %s is there already",
			    sp->dataset);
			return (-1);
		}
		if (strcmp(sp->copy, "clone") == 0) {
			if (zfs(w, errp, "clone", "-o", wfmt(w, "mountpoint=%s",
			    sp->path), sp->snapshot, sp->dataset, NULL) != 0)
				return (-1);
		} else if (send_recv(w, sp->snapshot, sp->dataset, sp->path,
		    errp) != 0) {
			/* A recv cut short leaves nothing, or a part. */
			if (ds_exists(w, sp->dataset))
				(void)zfs(w, NULL, "destroy", "-r", sp->dataset,
				    NULL, NULL, NULL);
			return (-1);
		}
		made = true;
	}
	/* Read back by jail(8) first, beside where it goes. */
	tmp = wfmt(w, "%s/.%s.conf.arcana-check", opts.jail_conf_d, sp->jail);
	if (put_file(w, tmp, sp->text, errp) != 0)
		goto undo;
	if (reads_back(w, tmp, sp->jail, sp->path, errp) != 0) {
		(void)unlink(tmp);
		goto undo;
	}
	(void)unlink(tmp);
	if (put_file(w, file, sp->text, errp) != 0)
		goto undo;
	if (sp->start) {
		memset(&ar, 0, sizeof(ar));
		do_action(w, sp->jail, ARC_ACTION_START, &ar);
		if (!ar.ok) {
			e = ar.error != NULL ? ar.error : "it did not start";
			*errp = wfmt(w, "made, but %s did not start: %s; its file "
			    "and dataset taken away again", sp->jail, e);
			(void)unlink(file);
			goto undo;
		}
	}
	return (0);
undo:
	if (made)
		(void)zfs(w, NULL, "destroy", "-r", sp->dataset, NULL, NULL,
		    NULL);
	return (-1);
}

static int
jail_unmake(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct arc_action_rsp	 ar;
	struct cjail		*js;
	const char		*file, *path, *e, *mp;
	char			*buf;
	size_t			 n, len;

	file = wfmt(w, "%s/%s.conf", opts.jail_conf_d, sp->jail);
	if ((buf = get_file(w, file, &len)) == NULL) {
		*errp = wfmt(w, "no %s: a jail made elsewhere is not taken "
		    "away from here", file);
		return (-1);
	}
	path = NULL;
	if (conf_scope_read(w, file, &js, &n, &e) == 0 && n == 1)
		path = cjail_param1(&js[0], "path");
	if (jail_getid(sp->jail) >= 0) {
		memset(&ar, 0, sizeof(ar));
		do_action(w, sp->jail, ARC_ACTION_STOP, &ar);
		if (!ar.ok) {
			*errp = wfmt(w, "%s did not stop: %s", sp->jail, ar.error !=
			    NULL ? ar.error : "no reason given");
			return (-1);
		}
	}
	/* Its dataset, only where it is the jail's root. */
	if (sp->dataset != NULL && sp->dataset[0] != '\0') {
		mp = ds_get(w, sp->dataset, "mountpoint");
		if (path == NULL || mp == NULL || strcmp(mp, path) != 0) {
			*errp = wfmt(w, "%s is not mounted at the jail's path "
			    "(%s): it is not destroyed, nor is anything else",
			    sp->dataset, path != NULL ? path : "unknown");
			return (-1);
		}
	}
	if (write_backup(w, file, buf, len, errp) != 0)
		return (-1);
	if (unlink(file) == -1) {
		*errp = wfmt(w, "%s: %s", file, strerror(errno));
		return (-1);
	}
	if (sp->dataset != NULL && sp->dataset[0] != '\0' && zfs(w, errp,
	    "destroy", "-r", sp->dataset, NULL, NULL, NULL) != 0)
		return (-1);
	return (0);
}

/* /etc/jail.conf: written, read back, the one before kept and put back
 * when jail(8) does not take it. */
static int
jail_defaults(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct cjail	*js;
	const char	*e;
	char		*old;
	size_t		 n, len;

	old = get_file(w, opts.jail_conf, &len);
	if (old != NULL && write_backup(w, opts.jail_conf, old, len, errp) != 0)
		return (-1);
	if (put_file(w, opts.jail_conf, sp->text, errp) != 0)
		return (-1);
	if (conf_scope_read(w, opts.jail_conf, &js, &n, &e) == -1) {
		*errp = wfmt(w, "jail(8) does not take it: %s; the one before "
		    "put back", e != NULL ? e : "no reason given");
		if (old != NULL)
			(void)put_file(w, opts.jail_conf, old, &e);
		else
			(void)unlink(opts.jail_conf);
		return (-1);
	}
	return (0);
}

/* The jail files in jail.conf.d that include a template. */
static const char *
includers(struct work *w, const char *inc)
{
	struct dirent	*d;
	DIR		*dir;
	const char	*who, *f;
	char		*buf;
	size_t		 len;

	who = NULL;
	if ((dir = opendir(opts.jail_conf_d)) == NULL)
		return (NULL);
	while ((d = readdir(dir)) != NULL) {
		if (strlen(d->d_name) < 6 || strcmp(d->d_name + strlen(
		    d->d_name) - 5, ".conf") != 0 || d->d_name[0] == '.')
			continue;
		f = wfmt(w, "%s/%s", opts.jail_conf_d, d->d_name);
		if ((buf = get_file(w, f, &len)) != NULL && strstr(buf, inc) !=
		    NULL)
			who = who == NULL ? wstrdup(w, d->d_name) : wfmt(w, "%s, "
			    "%s", who, d->d_name);
	}
	closedir(dir);
	return (who);
}

static int
jail_template(struct work *w, const struct arc_job_spec *sp, bool rm,
    const char **errp)
{
	struct dirent	*d;
	DIR		*dir;
	struct cjail	*js;
	const char	*file, *who, *f, *e;
	char		*old;
	size_t		 len, n;

	file = wfmt(w, "%s/%s.inc", opts.jail_conf_d, sp->names.v[0]);
	if (rm) {
		if ((who = includers(w, file)) != NULL) {
			*errp = wfmt(w, "%s is included by %s: kept", file, who);
			return (-1);
		}
		if (unlink(file) == -1) {
			*errp = wfmt(w, "%s: %s", file, strerror(errno));
			return (-1);
		}
		return (0);
	}
	(void)mkdir(opts.jail_conf_d, 0755);
	old = get_file(w, file, &len);
	if (old != NULL && write_backup(w, file, old, len, errp) != 0)
		return (-1);
	if (put_file(w, file, sp->text, errp) != 0)
		return (-1);
	/* Each jail that includes it read back as it is now. */
	if ((dir = opendir(opts.jail_conf_d)) == NULL)
		return (0);
	while ((d = readdir(dir)) != NULL) {
		char	*buf;

		if (strlen(d->d_name) < 6 || strcmp(d->d_name + strlen(
		    d->d_name) - 5, ".conf") != 0 || d->d_name[0] == '.')
			continue;
		f = wfmt(w, "%s/%s", opts.jail_conf_d, d->d_name);
		if ((buf = get_file(w, f, &len)) == NULL || strstr(buf, file) ==
		    NULL)
			continue;
		if (conf_scope_read(w, f, &js, &n, &e) == -1) {
			closedir(dir);
			*errp = wfmt(w, "%s does not read with it: %s; the one "
			    "before put back", d->d_name, e != NULL ? e :
			    "no reason given");
			if (old != NULL)
				(void)put_file(w, file, old, &e);
			else
				(void)unlink(file);
			return (-1);
		}
	}
	closedir(dir);
	return (0);
}

int
do_jail_conf(struct work *w, const struct arc_job_spec *sp, const char **errp)
{

	if (strcmp(sp->verb, "make") == 0)
		return (jail_make(w, sp, errp));
	if (strcmp(sp->verb, "remove") == 0)
		return (jail_unmake(w, sp, errp));
	if (strcmp(sp->verb, "defaults") == 0)
		return (jail_defaults(w, sp, errp));
	return (jail_template(w, sp, strcmp(sp->verb, "untemplate") == 0,
	    errp));
}
