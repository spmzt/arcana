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
 *
 * A position is the file's as well as the offset in it: above its low
 * POS_BITS, a tag of the file's inode.  A log newsyslog(8) turned over
 * since is followed on in the file it now is (name.0, while it is that
 * file and not packed), then the new one from its start, so that no
 * line is lost to the turn nor read from its middle.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

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
#define	POS_BITS	40		/* a position's offset; above, its file */
#define	POS_OFF(p)	((p) & ((UINT64_C(1) << POS_BITS) - 1))
#define	POS_TAG(p)	((p) >> POS_BITS)
/* 1 to 4096 (0 is a position of no file's), to stay a safe integer for
 * a page's JavaScript. */
#define	FILE_TAG(sb)	(((uint64_t)(sb).st_ino & 0xfff) + 1)

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

/* What newsyslog(8) packed: the program that unpacks it, or NULL. */
static const char *
packed(const char *name)
{
	const char	*dot;

	if ((dot = strrchr(name, '.')) == NULL)
		return (NULL);
	return (strcmp(dot, ".bz2") == 0 ? "bzcat" : strcmp(dot, ".gz") == 0 ?
	    "zcat" : strcmp(dot, ".xz") == 0 ? "xzcat" : strcmp(dot, ".zst") ==
	    0 ? "zstdcat" : NULL);
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
		if (log_name_ok(de->d_name) && strncmp(de->d_name, "utx.", 4)
		    != 0)
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
		if (packed(names[i]) != NULL)
			ucl_object_insert_key(o, ucl_object_frombool(true),
			    "packed", 0, false);
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
		/* "<auth.info>" before the host: syslogd -v. */
		if (rest[0] == '<' && (colon = strchr(rest, '>')) != NULL &&
		    colon[1] == ' ') {
			*colon = '\0';
			str(o, "level", wtext(w, rest + 1));
			rest = colon + 2;
		}
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

/* The lines of text as the reply, each taken apart; the last max. */
static int
lines_reply(struct work *w, const char *name, char *buf, size_t len,
    const char *filter, uint32_t max, struct json_rsp *rsp)
{
	ucl_object_t	*top, *arr;
	unsigned char	*json;
	char		*p, *e, **keep;
	size_t		 nkeep, first, i;

	keep = wcalloc(w, max, sizeof(*keep));
	nkeep = first = 0;
	for (p = buf; p < buf + len; p = e + 1) {
		if ((e = memchr(p, '\n', (size_t)(buf + len - p))) == NULL)
			e = buf + len;
		*e = '\0';
		if (e - p > LOG_LINE_MAX)
			p[LOG_LINE_MAX] = '\0';
		if (*p == '\0' || (filter != NULL && filter[0] != '\0' &&
		    strcasestr(p, filter) == NULL))
			continue;
		if (nkeep < max)
			keep[nkeep++] = p;
		else {
			keep[first] = p;
			first = (first + 1) % max;
		}
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	str(top, "name", name);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nkeep; i++)
		ucl_array_append(arr, line_object(w, keep[(first + i) %
		    (nkeep < max ? nkeep : max)]));
	ucl_object_insert_key(top, arr, "lines", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)len),
	    "position", 0, false);
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

/*
 * What is not a file of the log directory: @dmesg, the kernel's
 * message buffer, as dmesg(8) prints it; @audit, the audit trail of
 * now, as praudit(1) prints it.
 */
/*
 * @dmesg as the lines that kmsg.c has numbered, those after position
 * when following; each with its number and when it was seen.  false
 * when nothing follows the kernel's messages here.
 */
static bool
kmsg_reply(struct work *w, const char *filter, bool from, uint64_t position,
    uint32_t max, struct json_rsp *rsp)
{
	struct kmsg_line	*v;
	ucl_object_t		*top, *arr, *o;
	unsigned char		*json;
	uint64_t		 last;
	size_t			 n, i;
	int			 step;

	step = step_begin(w, STEP_LIB, "kmsg", "the kernel's "
	    "messages followed%s", from ? ", after a number" : "");
	if (!kmsg_lines(w, from ? position : 0, filter, max, &v, &n, &last)) {
		step_end(w, step, false, "not followed");
		return (false);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	str(top, "name", "@dmesg");
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < n; i++) {
		o = line_object(w, v[i].text);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)v[i].n),
		    "seq", 0, false);
		if (v[i].t != 0)
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)
			    v[i].t), "seen", 0, false);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, "lines", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)last),
	    "position", 0, false);
	/* A number from before the agent started: begun anew. */
	if (from && position > last)
		ucl_object_insert_key(top, ucl_object_frombool(true), "rotated",
		    0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	step_end(w, step, true, "%zu lines", n);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "more lines than a reply carries: ask for fewer";
		return (true);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (true);
}

static int
special(struct work *w, const char *name, const char *filter, bool from,
    uint64_t position, uint32_t max, struct json_rsp *rsp)
{
	struct execres	 res;
	const char	*bin;
	char		*argv[4], *buf, *p, *q;
	size_t		 len, k;
	int		 step;

	if (max == 0)
		max = LOG_LINES;
	if (max > LOG_LINES_MAX)
		max = LOG_LINES_MAX;
	if (strcmp(name, "@dmesg") == 0) {
		step = step_begin(w, STEP_LIB, "sysctl(3)",
		    "kern.msgbuf");
		if (w->jail != NULL) {
			rsp->error = "the kernel's messages are the host's";
			step_end(w, step, false, NULL);
			return (0);
		}
		step_end(w, step, true, "followed as they come");
		if (kmsg_reply(w, filter, from, position, max, rsp))
			return (0);
		step = step_begin(w, STEP_LIB, "sysctl(3)",
		    "kern.msgbuf");
		len = 0;
		if (sysctlbyname("kern.msgbuf", NULL, &len, NULL, 0) == -1) {
			/* Not root: the kernel says no, unless it is let. */
			rsp->error = errno == EPERM && geteuid() != 0 ?
			    "kern.msgbuf: the kernel's messages are root's: arcana-agent "
			    "runs as another, and is let read them by sysctl "
			    "security.bsd.unprivileged_read_msgbuf=1 (in "
			    "/etc/sysctl.conf to keep)" : wfmt(w,
			    "kern.msgbuf: %s", strerror(errno));
			step_end(w, step, false, "%s", strerror(errno));
			return (0);
		}
		buf = wcalloc(w, len + 1, 1);
		if (sysctlbyname("kern.msgbuf", buf, &len, NULL, 0) == -1) {
			rsp->error = wfmt(w, "kern.msgbuf: %s", strerror(
			    errno));
			step_end(w, step, false, "%s", strerror(errno));
			return (0);
		}
		/* "<6>text": the priority, which dmesg leaves out. */
		for (p = q = buf; p < buf + len; ) {
			/* "<6>", "<118>": one to three digits. */
			if ((p == buf || p[-1] == '\n') && p[0] == '<' &&
			    (k = strspn(p + 1, "0123456789")) >= 1 && k <= 3 &&
			    p[1 + k] == '>') {
				p += k + 2;
				continue;
			}
			*q++ = *p++;
		}
		len = (size_t)(q - buf);
		step_end(w, step, true, "%zu bytes", len);
		return (lines_reply(w, name, buf, len, filter, max, rsp));
	}
	if (strcmp(name, "@audit") == 0) {
		if ((bin = tool(w, "praudit")) == NULL) {
			rsp->error = "the host has no praudit";
			return (0);
		}
		argv[0] = (char *)(uintptr_t)bin;
		argv[1] = (char *)(uintptr_t)"-l";
		argv[2] = wfmt(w, "%s/var/audit/current", w->jail != NULL ?
		    w->jroot : "");
		argv[3] = NULL;
		if (run_exec_max(w, argv, &res, LOG_READ_MAX) != 0) {
			rsp->error = wtext(w, exec_error(w, &res, "praudit"));
			return (0);
		}
		buf = wcalloc(w, res.outlen + 1, 1);
		memcpy(buf, res.out, res.outlen);
		return (lines_reply(w, name, buf, res.outlen, filter, max,
		    rsp));
	}
	rsp->error = "a log is a file of the log directory, @dmesg or @audit";
	return (0);
}

int
do_log(struct work *w, const char *name, const char *filter, bool from,
    uint64_t position, uint32_t max, struct json_rsp *rsp)
{
	struct stat	 sb;
	ucl_object_t	*top, *arr;
	unsigned char	*json;
	char		*buf, *p, *e, *end, **keep;
	struct stat	 osb;
	off_t		 start;
	ssize_t		 n;
	size_t		 len, nkeep, i, first, plen;
	const char	*unpack;
	char		*prev;
	uint64_t	 tag;
	int		 dfd, fd, ofd, step;
	bool		 rotated;

	rsp->has_ok = true;
	rsp->ok = false;
	if (name == NULL || name[0] == '\0')
		name = "messages";
	if (name[0] == '@')
		return (special(w, name, filter, from, position, max, rsp));
	if (!log_name_ok(name)) {
		rsp->error = "a log is a file of the log directory, named "
		    "with letters, digits and . _ -";
		return (0);
	}
	if (max == 0)
		max = LOG_LINES;
	if (max > LOG_LINES_MAX)
		max = LOG_LINES_MAX;
	step = step_begin(w, STEP_LIB, "read(2)", "%s/%s",
	    opts.log_dir, name);
	if ((dfd = scope_dirfd(w, opts.log_dir)) == -1) {
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
	/* Turned over since the position: the rest of the file it was,
	 * name.0 now, then this one whole. */
	tag = from ? POS_TAG(position) : 0;
	position = POS_OFF(position);
	prev = NULL;
	plen = 0;
	rotated = false;
	if (tag != 0 && tag != FILE_TAG(sb)) {
		ofd = openat(dfd, wfmt(w, "%s.0", name), O_RDONLY | O_NOFOLLOW |
		    O_NONBLOCK | O_CLOEXEC);
		if (ofd != -1 && fstat(ofd, &osb) == 0 && S_ISREG(osb.st_mode) &&
		    FILE_TAG(osb) == tag && (uint64_t)osb.st_size >= position &&
		    osb.st_size - (off_t)position <= LOG_READ_MAX) {
			plen = (size_t)(osb.st_size - (off_t)position);
			prev = wcalloc(w, plen + 1, 1);
			if (pread(ofd, prev, plen, (off_t)position) !=
			    (ssize_t)plen)
				prev = NULL;
		}
		if (ofd != -1)
			close(ofd);
		if (prev == NULL)
			plen = 0;
		rotated = prev == NULL;
		position = 0;
	} else if (from && position > (uint64_t)sb.st_size) {
		rotated = true;
		from = false;
	}
	start = from ? (off_t)position : 0;
	if ((unpack = packed(name)) != NULL) {
		/* Unpacked by its program, whole; it is not followed. */
		struct execres	 res;
		const char	*bin;
		char		*argv[3];

		close(fd);
		if ((bin = tool(w, unpack)) == NULL) {
			rsp->error = wfmt(w, "the host has no %s to unpack %s",
			    unpack, name);
			step_end(w, step, false, NULL);
			close(dfd);
			return (0);
		}
		argv[0] = (char *)(uintptr_t)bin;
		argv[1] = wfmt(w, "%s/%s", w->jail != NULL ? wfmt(w, "%s%s",
		    w->jroot, opts.log_dir) : opts.log_dir, name);
		argv[2] = NULL;
		if (run_exec_max(w, argv, &res, LOG_READ_MAX) != 0) {
			rsp->error = wtext(w, exec_error(w, &res, unpack));
			step_end(w, step, false, NULL);
			close(dfd);
			return (0);
		}
		len = res.outlen;
		buf = wcalloc(w, len + 1, 1);
		memcpy(buf, res.out, len);
		n = (ssize_t)len;
		start = 0;
		from = false;
	} else {
		if (sb.st_size - start > LOG_READ_MAX)
			start = sb.st_size - LOG_READ_MAX;
		len = (size_t)(sb.st_size - start);
		buf = wcalloc(w, plen + len + 1, 1);
		if (plen > 0)
			memcpy(buf, prev, plen);
		n = len > 0 ? pread(fd, buf + plen, len, start) : 0;
		if (n >= 0)
			n += (ssize_t)plen;
		close(fd);
	}
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
	/* Of this file: what was read of the one before is not. */
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)(FILE_TAG(sb) <<
	    POS_BITS | (uint64_t)(start + (end - buf > (ptrdiff_t)plen ?
	    end - buf - (ptrdiff_t)plen : 0)))), "position", 0, false);
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
