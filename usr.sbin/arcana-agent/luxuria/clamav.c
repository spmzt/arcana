/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: ClamAV's freshclam, the program that fetches the signatures
 * c-icap's scanner and clamd read.  Its configuration, freshclam.conf
 * (--freshclam-conf), names the mirrors it fetches from, one
 * DatabaseMirror line each, tried in order.  The clamav job's verb
 * mirrors writes those lines, in place of the ones there were; a
 * freshclam.conf not there yet is made from the port's sample beside
 * it, without the Example line that keeps freshclam from running.
 * The read (sdproxy.c's clamav_json) says the mirrors there are.
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

#include <ucl.h>

#include "agent.h"

#define	MIRRORS_MAX	16
#define	MIRROR_MAX	255
#define	CONF_MAX	(256 * 1024)

/*
 * A mirror as freshclam takes one: a host name (database.clamav.net),
 * or an http or https URL to a mirror's directory; no white space, no
 * quote, nothing that would end the line.
 */
static bool
mirror_ok(const char *m)
{
	const char	*h;
	size_t		 i, n;

	n = strlen(m);
	if (n == 0 || n > MIRROR_MAX)
		return (false);
	for (i = 0; i < n; i++)
		if (!isgraph((unsigned char)m[i]) || m[i] == '"' || m[i] == '\''
		    || m[i] == '\\' || m[i] == '#')
			return (false);
	if (strncmp(m, "https://", 8) == 0)
		h = m + 8;
	else if (strncmp(m, "http://", 7) == 0)
		h = m + 7;
	else if (strchr(m, '/') == NULL && strchr(m, ':') == NULL)
		h = m;
	else
		return (false);
	/* A host there, of letters, digits, dots and dashes. */
	n = strcspn(h, "/:");
	if (n == 0)
		return (false);
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)h[i]) && h[i] != '.' && h[i] != '-')
			return (false);
	return (true);
}

const char *
clamav_check(const struct arc_job_spec *sp)
{
	size_t	i, n;

	if (sp->jail != NULL && sp->jail[0] != '\0')
		return ("freshclam is the host's");
	if (sp->safe)
		return ("freshclam's mirrors are not undone: not in safe mode");
	if (sp->verb == NULL || strcmp(sp->verb, "mirrors") != 0)
		return ("a clamav job's verb is mirrors");
	n = 0;
	for (i = 0; i < sp->names.n; i++) {
		if (strncmp(sp->names.v[i], "mirror=", 7) != 0)
			return ("the words of a clamav job are mirror=");
		if (!mirror_ok(sp->names.v[i] + 7))
			return ("a mirror is a host name, or an http or https "
			    "URL, 255 characters at most");
		n++;
	}
	if (n == 0)
		return ("freshclam needs a mirror at least");
	if (n > MIRRORS_MAX)
		return ("16 mirrors at most");
	return (NULL);
}

char *
clamav_title(const struct arc_job_spec *sp)
{
	char	*t, *o;
	size_t	 i;

	if ((t = strdup("freshclam mirrors")) == NULL)
		return (NULL);
	for (i = 0; i < sp->names.n && i < 3; i++) {
		if (asprintf(&o, "%s%s %s", t, i > 0 ? "," : "",
		    sp->names.v[i] + 7) == -1) {
			free(t);
			return (NULL);
		}
		free(t);
		t = o;
	}
	if (sp->names.n > 3) {
		if (asprintf(&o, "%s, and %zu more", t, sp->names.n - 3) == -1) {
			free(t);
			return (NULL);
		}
		free(t);
		t = o;
	}
	return (t);
}

/* The file, whole, as a string of the work's; NULL when it cannot be. */
static char *
read_text(struct work *w, const char *path)
{
	struct stat	 sb;
	char		*s;
	ssize_t		 n;
	int		 fd;

	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
		return (NULL);
	if (fstat(fd, &sb) == -1 || sb.st_size > CONF_MAX) {
		close(fd);
		return (NULL);
	}
	s = wcalloc(w, 1, (size_t)sb.st_size + 1);
	n = read(fd, s, (size_t)sb.st_size);
	close(fd);
	if (n != sb.st_size)
		return (NULL);
	return (s);
}

/* Is the line, its leading white space aside, the keyword? */
static bool
is_key(const char *line, size_t len, const char *key)
{
	size_t	k;

	while (len > 0 && (*line == ' ' || *line == '\t')) {
		line++;
		len--;
	}
	k = strlen(key);
	return (len >= k && strncmp(line, key, k) == 0 && (len == k ||
	    line[k] == ' ' || line[k] == '\t' || line[k] == '\r'));
}

int
do_clamav_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	const char	*conf, *text, *p, *nl;
	char		 sample[PATH_MAX], tmp[PATH_MAX];
	struct {
		char	*s;
		size_t	 len, cap;
	}		 out;
	size_t		 i, len;
	bool		 from_sample, placed, enabled, running;
	int		 fd, step;
	mode_t		 mode;
	struct stat	 sb;

	if ((*errp = clamav_check(sp)) != NULL)
		return (-1);
	conf = opts.freshclam_conf;
	snprintf(sample, sizeof(sample), "%s.sample", conf);
	from_sample = false;
	if ((text = read_text(w, conf)) == NULL) {
		if (errno != ENOENT || (text = read_text(w, sample)) == NULL) {
			*errp = wfmt(w, "neither %s nor its sample %s can be "
			    "read: ClamAV is a plugin, pkg install clamav",
			    conf, sample);
			return (-1);
		}
		from_sample = true;
	}
	step = step_begin(w, ARC_STEP_KIND_FILE, "freshclam.conf", "%s, its "
	    "mirrors written%s", conf, from_sample ? ", made from the port's "
	    "sample" : "");
	/* The lines as they were, less the Example line and the mirrors;
	 * the mirrors where the first of them was, or at the end. */
	memset(&out, 0, sizeof(out));
	out.cap = strlen(text) + (size_t)sp->names.n * (MIRROR_MAX + 32) + 64;
	out.s = wcalloc(w, 1, out.cap);
	placed = false;
	for (p = text; *p != '\0'; p = nl) {
		nl = strchr(p, '\n');
		nl = nl != NULL ? nl + 1 : p + strlen(p);
		len = (size_t)(nl - p);
		if (is_key(p, len - (p[len - 1] == '\n' ? 1 : 0), "Example"))
			continue;
		if (is_key(p, len - (p[len - 1] == '\n' ? 1 : 0),
		    "DatabaseMirror")) {
			if (!placed) {
				for (i = 0; i < sp->names.n; i++)
					out.len += (size_t)snprintf(out.s + out.len,
					    out.cap - out.len, "DatabaseMirror %s\n",
					    sp->names.v[i] + 7);
				placed = true;
			}
			continue;
		}
		memcpy(out.s + out.len, p, len);
		out.len += len;
	}
	if (!placed) {
		if (out.len > 0 && out.s[out.len - 1] != '\n')
			out.s[out.len++] = '\n';
		for (i = 0; i < sp->names.n; i++)
			out.len += (size_t)snprintf(out.s + out.len, out.cap -
			    out.len, "DatabaseMirror %s\n", sp->names.v[i] + 7);
	}
	/* Beside it, then over it: never half written. */
	snprintf(tmp, sizeof(tmp), "%s.arcana", conf);
	/* With the mode the file had (it may hold a proxy's password). */
	mode = stat(conf, &sb) == 0 ? sb.st_mode & 0777 : 0644;
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, mode)) == -1 || write(fd, out.s, out.len) !=
	    (ssize_t)out.len || fchmod(fd, mode) != 0 || fsync(fd) != 0) {
		*errp = wfmt(w, "%s: %s", conf, strerror(errno));
		if (fd != -1)
			(void)close(fd);
		(void)unlink(tmp);
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	if (close(fd) != 0 || rename(tmp, conf) != 0) {
		*errp = wfmt(w, "%s: %s", conf, strerror(errno));
		(void)unlink(tmp);
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, "%zu mirror%s", sp->names.n, sp->names.n == 1 ?
	    "" : "s");
	/* A running freshclam reads its mirrors as it starts again. */
	enabled = running = false;
	service_state(w, "clamav_freshclam", &running, &enabled);
	if (running) {
		struct service_action_rsp	r;

		memset(&r, 0, sizeof(r));
		(void)do_service_action(w, "clamav_freshclam",
		    ARC_SERVICE_ACTION_RESTART, &r);
	}
	return (0);
}

/* The mirrors freshclam.conf names, in order, into o as "mirrors". */
void
clamav_mirrors_json(ucl_object_t *o)
{
	ucl_object_t	*arr;
	FILE		*fp;
	char		 line[512], *v, *e;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if ((fp = fopen(opts.freshclam_conf, "re")) != NULL) {
		while (fgets(line, sizeof(line), fp) != NULL) {
			v = line + strspn(line, " \t");
			if (!is_key(v, strcspn(v, "\n"), "DatabaseMirror"))
				continue;
			v += strlen("DatabaseMirror");
			v += strspn(v, " \t");
			e = v + strcspn(v, " \t\r\n");
			*e = '\0';
			if (*v != '\0')
				ucl_array_append(arr, ucl_object_fromstring(v));
		}
		fclose(fp);
	}
	ucl_object_insert_key(o, arr, "mirrors", 0, false);
}
