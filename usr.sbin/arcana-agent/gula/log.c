/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: what the host wrote down, the logs of syslogd(8).  A log is a
 * file of the log directory, read from its end: its last lines, or what
 * came after where a look before ended, which is how one is followed.
 * A line of syslog's is taken apart into its time, host, tag, pid and
 * text, in either of the two forms syslogd writes; any other line is
 * its text.
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
#include <ucl.h>
#include <unistd.h>

#include "agent.h"

#define	LOG_LINES	200		/* when none are asked for */
#define	LOG_LINES_MAX	5000
#define	LOG_READ_MAX	(8 * 1024 * 1024)	/* of the end of a file */
#define	LOG_LINE_MAX	2048		/* of one line, and no more */
#define	LOG_FILES_MAX	256

/* A file's name in the log directory: no way out of it, nothing hidden. */
bool
log_name_ok(const char *name)
{
	size_t	i;

	if (name == NULL || name[0] == '\0' || name[0] == '.' ||
	    strlen(name) > 128)
		return (false);
	for (i = 0; name[i] != '\0'; i++)
		if (!isalnum((unsigned char)name[i]) && strchr("._-",
		    name[i]) == NULL)
			return (false);
	return (true);
}

/* What newsyslog(8) packed is not read from here. */
static bool
packed(const char *name)
{
	const char	*dot;

	if ((dot = strrchr(name, '.')) == NULL)
		return (false);
	return (strcmp(dot, ".bz2") == 0 || strcmp(dot, ".gz") == 0 ||
	    strcmp(dot, ".xz") == 0 || strcmp(dot, ".zst") == 0);
}

static void
str(ucl_object_t *o, const char *key, const char *v)
{

	ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0, false);
}

static int
name_cmp(const void *a, const void *b)
{

	return (strcmp(*(char *const *)a, *(char *const *)b));
}

/* The logs there are to read: [{"name","size","mtime"}]. */
static ucl_object_t *
files(struct work *w, int dfd)
{
	struct dirent	*de;
	struct stat	 sb;
	ucl_object_t	*arr, *o;
	char		*names[LOG_FILES_MAX];
	DIR		*d;
	size_t		 n, i;
	int		 fd;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if ((fd = openat(dfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1)
		return (arr);
	if ((d = fdopendir(fd)) == NULL) {
		close(fd);
		return (arr);
	}
	n = 0;
	while ((de = readdir(d)) != NULL && n < LOG_FILES_MAX)
		/* utx.log and its kin are getutxent(3)'s, and not text. */
		if (log_name_ok(de->d_name) && !packed(de->d_name) &&
		    strncmp(de->d_name, "utx.", 4) != 0)
			names[n++] = wstrdup(w, de->d_name);
	closedir(d);
	qsort(names, n, sizeof(names[0]), name_cmp);
	for (i = 0; i < n; i++) {
		if (fstatat(dfd, names[i], &sb, AT_SYMLINK_NOFOLLOW) == -1 ||
		    !S_ISREG(sb.st_mode))
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		str(o, "name", names[i]);
		ucl_object_insert_key(o, ucl_object_fromint(sb.st_size),
		    "size", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(sb.st_mtime),
		    "mtime", 0, false);
		ucl_array_append(arr, o);
	}
	return (arr);
}

/* The next word of *pp, ended in place; NULL when there is none. */
static char *
word(char **pp)
{
	char	*s, *e;

	s = *pp;
	if (s == NULL || *s == '\0')
		return (NULL);
	if ((e = strchr(s, ' ')) == NULL)
		*pp = NULL;
	else {
		*e = '\0';
		*pp = e + 1;
	}
	return (s);
}

/* "tag[pid]" or "tag" into the object. */
static void
tag(struct work *w, ucl_object_t *o, char *t)
{
	char	*b, *e;

	if ((b = strchr(t, '[')) != NULL && (e = strchr(b, ']')) != NULL &&
	    e > b + 1) {
		*b = *e = '\0';
		str(o, "pid", wtext(w, b + 1));
	}
	if (t[0] != '\0')
		str(o, "tag", wtext(w, t));
}

/*
 * One line as an object.  "Oct  5 12:00:00 host tag[pid]: text" is what
 * syslogd writes by itself; "2026-10-05T12:00:00.123+03:30 host tag pid
 * msgid data text" is what it writes with -O rfc5424.
 */
static ucl_object_t *
line_object(struct work *w, char *line)
{
	ucl_object_t	*o;
	char		*rest, *host, *t, *pid, *colon;
	size_t		 len;

	o = ucl_object_typed_new(UCL_OBJECT);
	len = strlen(line);
	if (len > 25 && isdigit((unsigned char)line[0]) && line[4] == '-' &&
	    line[10] == 'T') {
		rest = line;
		str(o, "time", wtext(w, word(&rest)));
		if ((host = word(&rest)) != NULL)
			str(o, "host", wtext(w, host));
		if ((t = word(&rest)) != NULL && strcmp(t, "-") != 0)
			str(o, "tag", wtext(w, t));
		if ((pid = word(&rest)) != NULL && strcmp(pid, "-") != 0)
			str(o, "pid", wtext(w, pid));
		(void)word(&rest);		/* the message's id */
		/* Structured data: "-", or what is in brackets. */
		if (rest != NULL && rest[0] == '[' && (colon = strstr(rest,
		    "] ")) != NULL)
			rest = colon + 2;
		else if (rest != NULL && rest[0] == '-')
			rest += rest[1] == ' ' ? 2 : 1;
		str(o, "text", wtext(w, rest != NULL ? rest : ""));
		return (o);
	}
	if (len > 16 && isalpha((unsigned char)line[0]) && line[3] == ' ' &&
	    line[6] == ' ' && line[9] == ':' && line[12] == ':' && line[15] ==
	    ' ') {
		line[15] = '\0';
		str(o, "time", wtext(w, line));
		rest = line + 16;
		if ((host = word(&rest)) != NULL)
			str(o, "host", wtext(w, host));
		if (rest == NULL)
			rest = host + strlen(host);
		/* A tag has no space in it and ends in a colon. */
		colon = strstr(rest, ": ");
		if (colon != NULL && memchr(rest, ' ', (size_t)(colon -
		    rest)) == NULL) {
			*colon = '\0';
			tag(w, o, rest);
			rest = colon + 2;
		}
		str(o, "text", wtext(w, rest));
		return (o);
	}
	str(o, "text", wtext(w, line));
	return (o);
}

int
do_log(struct work *w, const char *name, const char *filter, bool from,
    uint64_t position, uint32_t max, struct arc_log_rsp *rsp)
{
	struct stat	 sb;
	ucl_object_t	*top, *arr;
	unsigned char	*json;
	char		*buf, *p, *e, *end, **keep;
	off_t		 start;
	ssize_t		 n;
	size_t		 len, nkeep, i, first;
	int		 dfd, fd, step;
	bool		 rotated;

	rsp->has_ok = true;
	rsp->ok = false;
	if (name == NULL || name[0] == '\0')
		name = "messages";
	if (!log_name_ok(name) || packed(name)) {
		rsp->error = "a log is a file of the log directory, named "
		    "with letters, digits and . _ -, and not a packed one";
		return (0);
	}
	if (max == 0)
		max = LOG_LINES;
	if (max > LOG_LINES_MAX)
		max = LOG_LINES_MAX;
	step = step_begin(w, ARC_STEP_KIND_LIB, "read(2)", "%s/%s",
	    opts.log_dir, name);
	if ((dfd = open(opts.log_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) ==
	    -1) {
		rsp->error = wfmt(w, "%s: %s", opts.log_dir, strerror(errno));
		step_end(w, step, false, "%s", strerror(errno));
		return (0);
	}
	fd = openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd == -1 || fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode)) {
		rsp->error = fd == -1 ? wfmt(w, "%s: %s", name,
		    strerror(errno)) : wfmt(w, "%s is not a file", name);
		step_end(w, step, false, NULL);
		if (fd != -1)
			close(fd);
		close(dfd);
		return (0);
	}
	rotated = from && position > (uint64_t)sb.st_size;
	if (rotated)
		from = false;
	start = from ? (off_t)position : 0;
	if (sb.st_size - start > LOG_READ_MAX)
		start = sb.st_size - LOG_READ_MAX;
	len = (size_t)(sb.st_size - start);
	buf = wcalloc(w, len + 1, 1);
	n = len > 0 ? pread(fd, buf, len, start) : 0;
	close(fd);
	if (n < 0) {
		rsp->error = wfmt(w, "%s: %s", name, strerror(errno));
		step_end(w, step, false, "%s", strerror(errno));
		close(dfd);
		return (0);
	}
	len = (size_t)n;
	if (memchr(buf, '\0', len) != NULL) {
		rsp->error = wfmt(w, "%s is not a text", name);
		step_end(w, step, false, "not a text");
		close(dfd);
		return (0);
	}
	end = buf + len;
	p = buf;
	/* Not from where a line begins: the rest of that line is left. */
	if (start > 0 && !(from && start == (off_t)position)) {
		if ((p = memchr(buf, '\n', len)) == NULL)
			p = end;
		else
			p++;
	}
	/* A line still being written waits for the look after this one. */
	while (end > p && end[-1] != '\n')
		end--;
	keep = wcalloc(w, max, sizeof(*keep));
	nkeep = first = 0;
	for (; p < end; p = e + 1) {
		e = memchr(p, '\n', (size_t)(end - p));
		*e = '\0';
		if (e - p > LOG_LINE_MAX)
			p[LOG_LINE_MAX] = '\0';
		if (*p == '\0' || (filter != NULL && filter[0] != '\0' &&
		    strcasestr(p, filter) == NULL))
			continue;
		/* The last max of them: a ring, read from first. */
		if (nkeep < max)
			keep[nkeep++] = p;
		else {
			keep[first] = p;
			first = (first + 1) % max;
		}
	}
	step_end(w, step, true, "%zu lines of %zu bytes from %jd", nkeep, len,
	    (intmax_t)start);
	top = ucl_object_typed_new(UCL_OBJECT);
	str(top, "name", name);
	ucl_object_insert_key(top, files(w, dfd), "files", 0, false);
	close(dfd);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nkeep; i++)
		ucl_array_append(arr, line_object(w, keep[(first + i) %
		    (nkeep < max ? nkeep : max)]));
	ucl_object_insert_key(top, arr, "lines", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(sb.st_size), "size", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromint(start + (end - buf)),
	    "position", 0, false);
	if (rotated)
		ucl_object_insert_key(top, ucl_object_frombool(true),
		    "rotated", 0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "more lines than a reply carries: ask for fewer";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}
