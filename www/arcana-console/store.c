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
		kore_log(LOG_ERR, "%s: %s", path, ucl_parser_get_error(p));
		ucl_parser_free(p);
		return (NULL);
	}
	o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

int
store_save(const char *name, const ucl_object_t *o)
{
	unsigned char	*json;
	char		 path[MAXPATHLEN], tmp[MAXPATHLEN];
	size_t		 len;
	ssize_t		 w;
	int		 fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, name);
	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
	if ((json = ucl_object_emit(o, UCL_EMIT_JSON)) == NULL)
		return (-1);
	len = strlen((char *)json);
	if ((fd = mkstemp(tmp)) == -1) {
		kore_log(LOG_ERR, "mkstemp %s: %s", tmp, strerror(errno));
		free(json);
		return (-1);
	}
	w = write(fd, json, len);
	free(json);
	if (w != (ssize_t)len || fchmod(fd, 0600) == -1 || fsync(fd) == -1 ||
	    close(fd) == -1 || rename(tmp, path) == -1) {
		kore_log(LOG_ERR, "writing %s: %s", path, strerror(errno));
		unlink(tmp);
		return (-1);
	}
	return (0);
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
			kore_log(LOG_NOTICE, "%s: a write cut short, taken away",
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
}
