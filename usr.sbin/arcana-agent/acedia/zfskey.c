/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Acedia: the key of an encrypted dataset that is asked for at a
 * prompt, typed on the page: loaded, or changed.  zfs(8) reads it from
 * a file only root reads, in a directory of /tmp made for it, there
 * only while zfs reads it; then it is overwritten and taken away.  It
 * is in no job (a job is kept, and the page keeps what it sent to send
 * again), no argument list, no trace and no log.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"

static bool
ds_ok(const char *s)
{

	if (s == NULL || s[0] == '\0' || s[0] == '-' || s[0] == '/' ||
	    strlen(s) > 255 || strstr(s, "//") != NULL || s[strlen(s) - 1] ==
	    '/')
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.:/-", *s) == NULL)
			return (false);
	return (true);
}

/* A key of the format: a passphrase of 8 to 512, or 64 hex digits. */
static const char *
key_ok(const char *key, const char *format)
{
	size_t	n;

	n = strlen(key);
	if (strpbrk(key, "\r\n") != NULL)
		return ("a key is one line");
	if (strcmp(format, "hex") == 0)
		return (n == 64 && key[strspn(key, "0123456789abcdefABCDEF")] ==
		    '\0' ? NULL : "a hex key is 64 hex digits");
	if (strcmp(format, "passphrase") == 0)
		return (n >= 8 ? NULL : "a passphrase is 8 characters at least");
	return ("a raw key is not typed: its keylocation has it");
}

/* zfs get of the dataset's keylocation, keystatus and keyformat. */
static int
key_props(struct work *w, const char *ds, char *loc, char *status,
    char *format, size_t len, const char **errp)
{
	struct execres	 res;
	char		*argv[8], *p, *l;

	argv[0] = (char *)(uintptr_t)opts.zfs_bin;
	argv[1] = (char *)(uintptr_t)"get";
	argv[2] = (char *)(uintptr_t)"-H";
	argv[3] = (char *)(uintptr_t)"-o";
	argv[4] = (char *)(uintptr_t)"value";
	argv[5] = (char *)(uintptr_t)"keylocation,keystatus,keyformat";
	argv[6] = (char *)(uintptr_t)ds;
	argv[7] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL) {
		*errp = res.errlen > 0 ? wstrndup(w, res.err, strcspn(res.err,
		    "\n")) : "zfs get failed";
		return (-1);
	}
	p = wstrndup(w, res.out, res.outlen);
	l = strsep(&p, "\n");
	strlcpy(loc, l != NULL ? l : "", len);
	l = strsep(&p, "\n");
	strlcpy(status, l != NULL ? l : "", len);
	l = strsep(&p, "\n");
	strlcpy(format, l != NULL ? l : "", len);
	return (0);
}

/* The key in a file of its own; its path, or NULL.  dir to take away. */
static const char *
key_file(struct work *w, const char *key, char *dir, size_t dlen,
    const char **errp)
{
	const char	*path;
	size_t		 len;
	int		 fd;

	snprintf(dir, dlen, "%s/tmp/.arcana-key.XXXXXXXX", opts.tools_dir !=
	    NULL ? opts.tools_dir : "");
	if (mkdtemp(dir) == NULL) {
		*errp = wfmt(w, "%s: %s", dir, strerror(errno));
		return (NULL);
	}
	path = wfmt(w, "%s/key", dir);
	if ((fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, 0600)) == -1) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		(void)rmdir(dir);
		return (NULL);
	}
	len = strlen(key);
	if (write(fd, key, len) != (ssize_t)len) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		close(fd);
		(void)unlink(path);
		(void)rmdir(dir);
		return (NULL);
	}
	close(fd);
	return (path);
}

/* The file overwritten, and it and its directory taken away. */
static void
key_gone(const char *path, const char *dir)
{
	struct stat	sb;
	char		zero[512];
	int		fd;

	if (path != NULL) {
		if ((fd = open(path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)) != -1) {
			memset(zero, 0, sizeof(zero));
			if (fstat(fd, &sb) == 0 && sb.st_size <= (off_t)
			    sizeof(zero))
				(void)write(fd, zero, (size_t)sb.st_size);
			(void)fsync(fd);
			close(fd);
		}
		(void)unlink(path);
	}
	(void)rmdir(dir);
}

static int
zfs3(struct work *w, const char *a, const char *b, const char *c,
    const char *d, const char **errp)
{
	struct execres	 res;
	char		*argv[6];
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.zfs_bin;
	argv[n++] = (char *)(uintptr_t)a;
	argv[n++] = (char *)(uintptr_t)b;
	if (c != NULL)
		argv[n++] = (char *)(uintptr_t)c;
	if (d != NULL)
		argv[n++] = (char *)(uintptr_t)d;
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = res.errlen > 0 ? wstrndup(w, res.err, strcspn(res.err,
		    "\n")) : wtext(w, exec_error(w, &res, "zfs"));
		return (-1);
	}
	return (0);
}

/* Loaded from a file: zfs load-key -L file://path dataset. */
static int
load_with(struct work *w, const char *ds, const char *key, const char **errp)
{
	const char	*path;
	char		 dir[MAXPATHLEN];
	int		 rc;

	if ((path = key_file(w, key, dir, sizeof(dir), errp)) == NULL)
		return (-1);
	rc = zfs3(w, "load-key", "-L", wfmt(w, "file://%s", path), ds, errp);
	key_gone(path, dir);
	return (rc);
}

void
do_zfs_key(struct work *w, const struct arc_zfs_key_req *rq,
    struct arc_zfs_key_rsp *rsp)
{
	const char	*e, *path;
	char		 loc[MAXPATHLEN], status[64], format[64], dir[MAXPATHLEN];
	bool		 has_key, has_new;

	has_key = rq->zfs_key != NULL && rq->zfs_key[0] != '\0';
	has_new = rq->zfs_new_key != NULL && rq->zfs_new_key[0] != '\0';
	if (!ds_ok(rq->zfs_dataset)) {
		rsp->error = "a dataset is pool/name";
		return;
	}
	if (!has_key && !has_new) {
		rsp->error = "a key to load, or a new one";
		return;
	}
	if (key_props(w, rq->zfs_dataset, loc, status, format, sizeof(loc),
	    &rsp->error) != 0)
		return;
	if (strcmp(status, "-") == 0 || strcmp(status, "none") == 0) {
		rsp->error = wfmt(w, "%s is not encrypted, or not where its "
		    "key is (an encryption root)", rq->zfs_dataset);
		return;
	}
	if (strcmp(loc, "prompt") != 0) {
		rsp->error = wfmt(w, "%s's key is read from %s, not typed",
		    rq->zfs_dataset, loc);
		return;
	}
	if ((has_key && (e = key_ok(rq->zfs_key, format)) != NULL) ||
	    (has_new && (e = key_ok(rq->zfs_new_key, format)) != NULL)) {
		rsp->error = e;
		return;
	}
	/* Loaded first: by the key typed, when it is not. */
	if (strcmp(status, "unavailable") == 0) {
		if (!has_key) {
			rsp->error = "its key is not loaded: the key it has now "
			    "first";
			return;
		}
		if (load_with(w, rq->zfs_dataset, rq->zfs_key, &rsp->error) !=
		    0)
			return;
	} else if (!has_new) {
		rsp->error = wfmt(w, "%s's key is loaded already",
		    rq->zfs_dataset);
		return;
	}
	if (has_new) {
		if ((path = key_file(w, rq->zfs_new_key, dir, sizeof(dir),
		    &rsp->error)) == NULL)
			return;
		if (zfs3(w, "change-key", "-o", wfmt(w, "keylocation=file://%s",
		    path), rq->zfs_dataset, &rsp->error) != 0) {
			key_gone(path, dir);
			return;
		}
		key_gone(path, dir);
		/* Asked for at a prompt again, as it was. */
		if (zfs3(w, "set", "keylocation=prompt", rq->zfs_dataset, NULL,
		    &e) != 0) {
			rsp->error = wfmt(w, "the key is changed, but its "
			    "keylocation is left at a file that is gone: zfs "
			    "set keylocation=prompt %s: %s", rq->zfs_dataset, e);
			return;
		}
	}
	rsp->ok = true;
}
