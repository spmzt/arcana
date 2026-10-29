/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Acedia: the key of an encrypted dataset that is asked for at a
 * prompt, typed on the page: loaded, or changed.  zfs(8) reads it on
 * its standard input, through a pipe, as it does a key typed when that
 * is no terminal: it is on no disk, and in no job (a job is kept, and
 * the page keeps what it sent to send again), no argument list, no
 * trace and no log.
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

/*
 * zfs verb dataset, the key on its standard input: what a key asked for
 * at a prompt is read from when it is no terminal.
 */
static int
zfs_keyed(struct work *w, const char *verb, const char *ds, const char *key,
    const char **errp)
{

	exec_set_stdin(key, strlen(key));
	return (zfs3(w, verb, ds, NULL, NULL, errp));
}

void
do_zfs_key(struct work *w, const struct zfskey_req *rq,
    struct zfskey_rsp *rsp)
{
	const char	*e;
	char		 loc[MAXPATHLEN], status[64], format[64];
	bool		 has_key, has_new;

	has_key = rq->zfs_key != NULL && rq->zfs_key[0] != '\0';
	has_new = rq->zfs_new_key != NULL && rq->zfs_new_key[0] != '\0';
	if (!ds_ok(rq->zfs_dataset)) {
		rsp->error = "a dataset is pool/name";
		return;
	}
	/* Made encrypted, its passphrase the new key, read as zfs create
	 * asks for it: on its standard input. */
	if (rq->zfs_create != NULL && rq->zfs_create[0] != '\0') {
		static const char *const algos[] = { "on", "aes-128-ccm",
		    "aes-192-ccm", "aes-256-ccm", "aes-128-gcm", "aes-192-gcm",
		    "aes-256-gcm" };
		struct execres	 res;
		char		*argv[12];
		size_t		 i;

		for (i = 0; i < nitems(algos); i++)
			if (strcmp(rq->zfs_create, algos[i]) == 0)
				break;
		if (i == nitems(algos)) {
			rsp->error = "its encryption is on or aes-128-ccm, "
			    "aes-192-ccm, aes-256-ccm, aes-128-gcm, aes-192-gcm, "
			    "aes-256-gcm";
			return;
		}
		if (!has_new || has_key) {
			rsp->error = "a dataset made encrypted takes its "
			    "passphrase, as the new key";
			return;
		}
		if ((e = key_ok(rq->zfs_new_key, "passphrase")) != NULL) {
			rsp->error = e;
			return;
		}
		argv[0] = (char *)(uintptr_t)opts.zfs_bin;
		argv[1] = (char *)(uintptr_t)"create";
		argv[2] = (char *)(uintptr_t)"-o";
		argv[3] = wfmt(w, "encryption=%s", rq->zfs_create);
		argv[4] = (char *)(uintptr_t)"-o";
		argv[5] = (char *)(uintptr_t)"keyformat=passphrase";
		argv[6] = (char *)(uintptr_t)"-o";
		argv[7] = (char *)(uintptr_t)"keylocation=prompt";
		argv[8] = (char *)(uintptr_t)rq->zfs_dataset;
		argv[9] = NULL;
		exec_set_stdin(rq->zfs_new_key, strlen(rq->zfs_new_key));
		if (run_exec(w, argv, &res) != 0) {
			rsp->error = res.errlen > 0 ? wstrndup(w, res.err,
			    strcspn(res.err, "\n")) : wtext(w, exec_error(w,
			    &res, "zfs create"));
			return;
		}
		rsp->ok = true;
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
		if (zfs_keyed(w, "load-key", rq->zfs_dataset, rq->zfs_key,
		    &rsp->error) != 0)
			return;
	} else if (!has_new) {
		rsp->error = wfmt(w, "%s's key is loaded already",
		    rq->zfs_dataset);
		return;
	}
	/* Its keylocation stays prompt: the new key read as the old. */
	if (has_new && zfs_keyed(w, "change-key", rq->zfs_dataset,
	    rq->zfs_new_key, &rsp->error) != 0)
		return;
	rsp->ok = true;
}
