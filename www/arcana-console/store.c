/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Small JSON documents in the data directory, read and written with
 * libucl, replaced atomically.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "console.h"

/* The document, or NULL if there is none yet or it cannot be read. */
ucl_object_t *
store_load(const char *name)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	char			 path[MAXPATHLEN];

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, name);
	if (access(path, F_OK) == -1)
		return (NULL);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO);
	if (!ucl_parser_add_file(p, path)) {
		thread_log(LOG_ERR, "%s: %s", path, ucl_parser_get_error(p));
		ucl_parser_free(p);
		return (NULL);
	}
	o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

/* A document as it is to be, written here: to a temporary, renamed. */
int
store_write(const char *name, const void *body, size_t len)
{
	char		 path[MAXPATHLEN], tmp[MAXPATHLEN], *p;
	ssize_t		 w;
	int		 fd, e;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, name);
	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
	/* runs/7.json, sessions/<hash>.json: their directory first. */
	if ((p = strrchr(path, '/')) != NULL && strchr(name, '/') != NULL) {
		*p = '\0';
		(void)mkdir(path, 0700);
		*p = '/';
	}
	if ((fd = mkstemp(tmp)) == -1) {
		thread_log(LOG_ERR, "mkstemp %s: %s", tmp, strerror(errno));
		return (-1);
	}
	w = len > 0 ? write(fd, body, len) : 0;
	/* A short write sets no errno: a full disk, as a rule. */
	if (w >= 0 && w != (ssize_t)len)
		errno = ENOSPC;
	if (w != (ssize_t)len || fchmod(fd, 0600) == -1 || fsync(fd) == -1) {
		e = errno;
		(void)close(fd);
		thread_log(LOG_ERR, "writing %s: %s", path, strerror(e));
		unlink(tmp);
		return (-1);
	}
	if (close(fd) == -1 || rename(tmp, path) == -1) {
		thread_log(LOG_ERR, "writing %s: %s", path, strerror(errno));
		unlink(tmp);
		return (-1);
	}
	return (0);
}

/* A document taken away: here, or through the cluster from every node. */
int
store_remove(const char *name)
{
	char	path[MAXPATHLEN];

	if (cluster_on())
		return (cluster_save(name, NULL, 0, true));
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, name);
	return (unlink(path) == -1 && errno != ENOENT ? -1 : 0);
}

/* A document saved: here, or through the cluster to every node. */
int
store_save(const char *name, const ucl_object_t *o)
{
	unsigned char	*json;
	int		 rc;

	if ((json = ucl_object_emit(o, UCL_EMIT_JSON)) == NULL)
		return (-1);
	rc = cluster_on() ? cluster_save(name, json, strlen((char *)json),
	    false) : store_write(name, json, strlen((char *)json));
	free(json);
	return (rc);
}

/*
 * One of store_save's temporaries: <name>.json.XXXXXX, the six of
 * mkstemp(3) letters and digits, not all small letters (as an admin's
 * x.json.backup is), beside the store it was to replace.
 */
static bool
is_temp(const char *dir, const char *n)
{
	char	path[MAXPATHLEN];
	size_t	len, i;
	bool	mixed;

	len = strlen(n);
	if (len < 12 || n[len - 7] != '.' || strncmp(n + len - 12, ".json",
	    5) != 0)
		return (false);
	mixed = false;
	for (i = len - 6; i < len; i++) {
		if (!isalnum((unsigned char)n[i]))
			return (false);
		if (!islower((unsigned char)n[i]))
			mixed = true;
	}
	snprintf(path, sizeof(path), "%s/%.*s", dir, (int)(len - 7), n);
	return (mixed && access(path, F_OK) == 0);
}

static void
sweep_dir(const char *dir)
{
	DIR		*d;
	struct dirent	*e;
	char		 path[MAXPATHLEN];

	if ((d = opendir(dir)) == NULL)
		return;
	while ((e = readdir(d)) != NULL) {
		if (e->d_type != DT_REG || !is_temp(dir, e->d_name))
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		if (unlink(path) == 0)
			thread_log(LOG_NOTICE, "%s: a write cut short, taken away",
			    path);
	}
	closedir(d);
}

/*
 * The temporaries of writes a stop cut short, between the write and the
 * rename: at start, when nothing else writes.
 */
void
store_sweep(void)
{
	char	path[MAXPATHLEN];

	sweep_dir(cfg.datadir);
	snprintf(path, sizeof(path), "%s/runs", cfg.datadir);
	sweep_dir(path);
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, SESSIONS_DIR);
	sweep_dir(path);
}
