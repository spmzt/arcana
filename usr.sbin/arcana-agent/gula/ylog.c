/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the logs as YANG.
 *
 * - arcana-log: the log operation's JSON (log.c) read back: the files
 *   of the log directory, and a read's lines, each line's facility and
 *   severity, where syslogd -v wrote them, as ietf-syslog's (RFC 9742);
 * - ietf-syslog itself: how syslogd(8) is set to write them, from
 *   syslog.conf(5) and the files it includes, each action's rotation
 *   from newsyslog.conf(5).  A selector "facility.level", one or more
 *   of them with ';' between, is a facility-list entry of its action's
 *   filter, the level and those above it (syslogd's default), or that
 *   level alone with '='; "*" is all, "none" none.  An action is the
 *   console (/dev/console), a file (/path, -/path without fsync), or
 *   a host over UDP (@host[:port]).  What the model cannot hold is
 *   said, not guessed: a pipe (|command), users or everyone (*) told,
 *   the comparisons '<', '>' and '!', a block of one program (!prog)
 *   or host (+host), a property filter (:...), facility mark; and of
 *   newsyslog, a rotation at a time of day (@, $).  newsyslog's count
 *   is the number of files, its size (KiB) the largest one in MiB,
 *   rounded up, its interval (hours) the rollover in minutes; of
 *   several lines of one file, the first, as newsyslog does.
 * - ietf-syslog committed: Arcana's lines in a file of its own,
 *   SYSLOG_ARCANA, which syslog.conf includes, and their rotation in
 *   NEWSYSLOG_ARCANA, which newsyslog.conf includes.  An action the
 *   commit leaves as it is stays where it is; one it changes is
 *   written in Arcana's file whole, one line, and a line of the user's
 *   that writes to it (or its newsyslog line, the rotation changed) is
 *   taken over: commented out where it is ("# taken by Arcana: ").
 *   What a commit asks that the files cannot hold is refused, said:
 *   TLS, a destination named otherwise than by its address, a facility
 *   override, block and stop, cron2, retention, a rollover of other
 *   than whole hours.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <glob.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

/* An identity's SID, by its module and name; 0: none. */
static uint64_t
ident(const char *mod, const char *name)
{

	for (uint32_t i = 0; i < ymodel_schema.nident; i++) {
		const struct cbl_yident *id = &ymodel_schema.ident[i];

		if (strcmp(id->name, name) == 0 &&
		    strcmp(id->module->name, mod) == 0)
			return (id->sid);
	}
	return (0);
}

static char *
astrdup(cbl_yarena *a, const char *s)
{
	size_t	 len = strlen(s) + 1;
	char	*p;

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

/* Seconds since the Epoch as yang:date-and-time, in UTC. */
static char *
datetime(cbl_yarena *a, int64_t t)
{
	char		buf[32];
	struct tm	tm;
	time_t		tt = (time_t)t;

	if (gmtime_r(&tt, &tm) == NULL ||
	    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		return (NULL);
	return (astrdup(a, buf));
}

/* syslog's facility names, as syslog.conf(5) and syslogd -v say them,
 * and RFC 5424's (ietf-syslog's identities). */
static const struct {
	const char	*bsd, *ietf;
} facilities[] = {
	{ "kern", "kern" }, { "user", "user" }, { "mail", "mail" },
	{ "daemon", "daemon" }, { "auth", "auth" }, { "syslog", "syslog" },
	{ "lpr", "lpr" }, { "news", "news" }, { "uucp", "uucp" },
	{ "cron", "cron" }, { "authpriv", "authpriv" }, { "ftp", "ftp" },
	{ "ntp", "ntp" }, { "security", "audit" }, { "console", "console" },
	{ "local0", "local0" }, { "local1", "local1" }, { "local2", "local2" },
	{ "local3", "local3" }, { "local4", "local4" }, { "local5", "local5" },
	{ "local6", "local6" }, { "local7", "local7" },
};

/* And the levels, from emerg; the index is ietf-syslog's enum's. */
static const struct {
	const char	*names[2];
} levels[] = {
	{ { "emerg", "panic" } }, { { "alert", NULL } }, { { "crit", NULL } },
	{ { "err", "error" } }, { { "warning", "warn" } },
	{ { "notice", NULL } }, { { "info", NULL } }, { { "debug", NULL } },
};

static uint64_t
facility_sid(const char *bsd, size_t n)
{
	char		 num[4];
	const char	*e;
	long long	 v;

	/* A number, syslog.h's: local0 is 16, after the one unnamed. */
	if (n > 0 && n < sizeof(num)) {
		memcpy(num, bsd, n);
		num[n] = '\0';
		v = strtonum(num, 0, 23, &e);
		if (e == NULL && v != 15)
			return (ident("ietf-syslog", facilities[v < 15 ? v : v -
			    1].ietf));
	}
	for (size_t i = 0; i < nitems(facilities); i++)
		if (strlen(facilities[i].bsd) == n && strncmp(bsd,
		    facilities[i].bsd, n) == 0)
			return (ident("ietf-syslog", facilities[i].ietf));
	return (0);
}

static int
level_of(const char *s)
{
	const char	*e;
	long long	 n;

	/* syslogd -v writes numbers, -vv names. */
	n = strtonum(s, 0, (long long)nitems(levels) - 1, &e);
	if (e == NULL)
		return ((int)n);
	for (size_t i = 0; i < nitems(levels); i++)
		for (size_t k = 0; k < 2; k++)
			if (levels[i].names[k] != NULL && strcmp(s,
			    levels[i].names[k]) == 0)
				return ((int)i);
	return (-1);
}

/* ---- The log operation's replies ----------------------------------- */

/* The files of the reply, *np of them; NULL: no memory.  The read's
 * output's list has the state's layout. */
static struct arcana_log_logs_file *
files_of(const ucl_object_t *top, cbl_yarena *a, size_t *np)
{
	struct arcana_log_logs_file	*v;
	const ucl_object_t		*e;
	ucl_object_iter_t		 it;
	int64_t				 n;
	size_t				 k = 0;

	if ((v = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "files")) + 1) * sizeof(*v))) == NULL)
		return (NULL);
	YJ_EACH(ucl_object_lookup(top, "files"), it, e) {
		memset(&v[k], 0, sizeof(v[k]));
		v[k].name = yj_str(a, e, "name");
		YJ_NUM(e, "size", &v[k], size);
		if (yj_num(e, "mtime", &n))
			v[k].modified = datetime(a, n);
		v[k].packed = yj_yes(e, "packed", &v[k].has_packed);
		if (v[k].name != NULL)
			k++;
	}
	*np = k;
	return (v);
}

int
ylog_files_from_json(const char *json, const char *dir, cbl_yarena *a,
    struct arcana_log_logs *out)
{
	ucl_object_t	*top;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->directory = dir != NULL ? astrdup(a, dir) : NULL;
	out->file.v = files_of(top, a, &out->file.n);
	ucl_object_unref(top);
	return (out->file.v == NULL ? ENOMEM : 0);
}

int
ylog_read_from_json(const char *json, cbl_yarena *a,
    struct arcana_log_logs_read_output *out)
{
	struct arcana_log_logs_read_output_line	*v;
	const ucl_object_t			*e;
	ucl_object_iter_t			 it;
	ucl_object_t				*top;
	const char				*lv, *dot;
	int64_t					 n;
	size_t					 k = 0;
	int					 l;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->name = yj_str(a, top, "name");
	YJ_NUM(top, "size", out, size);
	YJ_NUM(top, "position", out, position);
	out->rotated = yj_yes(top, "rotated", &out->has_rotated);
	if ((v = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "lines")) + 1) * sizeof(*v))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "lines"), it, e) {
		v[k].time = yj_str(a, e, "time");
		v[k].host = yj_str(a, e, "host");
		v[k].tag = yj_str(a, e, "tag");
		v[k].pid = yj_str(a, e, "pid");
		v[k].text = yj_str(a, e, "text");
		YJ_NUM(e, "seq", &v[k], sequence);
		if (yj_num(e, "seen", &n))
			v[k].seen = datetime(a, n);
		/* "auth.info", as syslogd -v writes it. */
		if ((lv = ucl_object_tostring(ucl_object_lookup(e, "level"))) !=
		    NULL && (dot = strchr(lv, '.')) != NULL) {
			if ((v[k].facility = facility_sid(lv, (size_t)(dot -
			    lv))) != 0)
				v[k].has_facility = true;
			if ((l = level_of(dot + 1)) >= 0) {
				v[k].has_severity = true;
				v[k].severity = l;
			}
		}
		k++;
	}
	out->line.n = k;
	out->line.v = v;
	out->file.v = (const void *)files_of(top, a, &out->file.n);
	ucl_object_unref(top);
	return (out->file.v == NULL ? ENOMEM : 0);
}

/* ---- syslog.conf and newsyslog.conf as ietf-syslog ------------------- */

typedef struct ietf_syslog_syslog_actions_file_log_file_filter_facility_list
    yfl;

/* An action as it is gathered, its selectors' entries. */
struct act {
	char		 kind;		/* 'c' console, 'f' file, 'r' remote */
	char		*name;		/* the file's path; the remote's host */
	char		*port;		/* the remote's */
	struct {
		uint64_t	 facility;	/* 0: all */
		int		 severity;	/* -1 all, -2 none */
		bool		 equals;
	}		 sel[64];
	size_t		 nsel;
	/* newsyslog's, -1 not said */
	long long	 count, size_kb, hours;
	bool		 nosync;	/* "-/path": not synced */
	char		*own;		/* its lines in Arcana's file */
};

/* A line of newsyslog.conf: a file's rotation. */
struct rot {
	char		*name;
	const char	*path;
	int		 line;
	bool		 own;		/* Arcana's file's */
	bool		 at;		/* at a time of day (@, $) */
	char		*text;
	long long	 count, size_kb, hours;
};

struct parse {
	cbl_yarena	*a;
	const char	*root;		/* the files under it; NULL: / */
	const char	*own, *ownrot;	/* Arcana's files, under root */
	struct act	 acts[64];
	size_t		 nacts;
	struct rot	 rots[256];
	size_t		 nrots;
	/* The user's lines of the actions, by the action's index. */
	struct {
		const char	*path;
		int		 line;
		size_t		 act;
	}		 lines[256];
	size_t		 nlines;
	char		*keep;		/* Arcana's lines no action holds */
	bool		 included;	/* syslog.conf includes Arcana's file */
	bool		 rot_included;	/* newsyslog.conf, Arcana's */
	bool		 full;		/* more than is kept */
	struct yunread	*u;
	size_t		 nu, maxu;
	int		 depth;
};

static void
unread(struct parse *p, const char *file, int line, const char *why)
{
	char	where[MAXPATHLEN + 16];

	if (p->nu == p->maxu)
		return;
	snprintf(where, sizeof(where), "%s:%d", file, line);
	p->u[p->nu].var = astrdup(p->a, where);
	p->u[p->nu].why = astrdup(p->a, why);
	p->nu++;
}

/* s, t and u, in a; s itself out of memory. */
static char *
cat(cbl_yarena *a, char *s, const char *t, const char *u)
{
	size_t	 n = s != NULL ? strlen(s) : 0, m = strlen(t), k = strlen(u);
	char	*r;

	if ((r = cbl_yarena_alloc(a, n + m + k + 1)) == NULL)
		return (s);
	if (n > 0)
		memcpy(r, s, n);
	memcpy(r + n, t, m);
	memcpy(r + n + m, u, k + 1);
	return (r);
}

/* path under p's root, in p's arena. */
static char *
rooted(struct parse *p, const char *path)
{
	char	buf[MAXPATHLEN];

	snprintf(buf, sizeof(buf), "%s%s", path[0] == '/' && p->root != NULL ?
	    p->root : "", path);
	return (astrdup(p->a, buf));
}

static struct act *
act_of(struct parse *p, char kind, const char *name, const char *port)
{
	struct act	*t;

	for (size_t i = 0; i < p->nacts; i++)
		if (p->acts[i].kind == kind && strcmp(p->acts[i].name, name) ==
		    0)
			return (&p->acts[i]);
	if (p->nacts == nitems(p->acts))
		return (NULL);
	t = &p->acts[p->nacts++];
	memset(t, 0, sizeof(*t));
	t->kind = kind;
	t->name = astrdup(p->a, name);
	t->port = port != NULL ? astrdup(p->a, port) : NULL;
	t->count = t->size_kb = t->hours = -1;
	return (t);
}

/* One selector's entry, once: the list's key is facility and severity. */
static void
sel_add(struct act *t, uint64_t facility, int severity, bool equals)
{

	for (size_t i = 0; i < t->nsel; i++)
		if (t->sel[i].facility == facility && t->sel[i].severity ==
		    severity)
			return;
	if (t->nsel == nitems(t->sel))
		return;
	t->sel[t->nsel].facility = facility;
	t->sel[t->nsel].severity = severity;
	t->sel[t->nsel].equals = equals;
	t->nsel++;
}

/*
 * One selector, "facility[,facility].[=]level", into its action;
 * false, with why, when it is one the model cannot hold.
 */
static bool
selector(struct act *t, char *s, const char **why)
{
	char		*dot, *f, *fs;
	int		 sev;
	bool		 equals = false;
	uint64_t	 sid;

	if ((dot = strrchr(s, '.')) == NULL) {
		*why = "a selector is facility.level";
		return (false);
	}
	*dot++ = '\0';
	if (*dot == '=') {
		equals = true;
		dot++;
	} else if (strncmp(dot, ">=", 2) == 0)
		dot += 2;
	else if (strchr("<>!", *dot) != NULL) {
		*why = "a level compared by '<', '>' or '!': ietf-syslog's "
		    "selectors compare equal, or that level and above";
		return (false);
	}
	sev = strcmp(dot, "*") == 0 ? -1 : strcmp(dot, "none") == 0 ? -2 :
	    level_of(dot);
	if (sev == -1 && strcmp(dot, "*") != 0) {
		*why = "a level syslog has no name for";
		return (false);
	}
	fs = s;
	while ((f = strsep(&fs, ",")) != NULL) {
		if (strcmp(f, "*") == 0)
			sid = 0;
		else if (strcmp(f, "mark") == 0) {
			*why = "facility mark, syslogd's own marks, is none of "
			    "RFC 5424's";
			return (false);
		} else if ((sid = facility_sid(f, strlen(f))) == 0) {
			*why = "a facility syslog has no name for";
			return (false);
		}
		sel_add(t, sid, sev, equals);
	}
	return (true);
}

static void conf_read(struct parse *, const char *);

/* "include dir": its files ending in .conf, in order, as syslogd does. */
static void
conf_include(struct parse *p, const char *dir)
{
	char	pat[MAXPATHLEN], *d;
	size_t	n;
	glob_t	g;

	if (p->depth > 4)
		return;
	d = rooted(p, dir);
	for (n = strlen(d); n > 1 && d[n - 1] == '/'; )
		d[--n] = '\0';
	/* syslogd reads the includes of syslog.conf itself alone. */
	if (p->depth == 0 && p->own != NULL && strncmp(p->own, d, n) == 0 &&
	    p->own[n] == '/' && strchr(p->own + n + 1, '/') == NULL)
		p->included = true;
	snprintf(pat, sizeof(pat), "%s/*.conf", d);
	if (glob(pat, 0, NULL, &g) != 0)
		return;
	p->depth++;
	for (size_t i = 0; i < g.gl_pathc; i++)
		conf_read(p, g.gl_pathv[i]);
	p->depth--;
	globfree(&g);
}

/* A line of Arcana's file no action holds: kept as it is. */
static void
held(struct parse *p, bool own, const char *raw)
{

	if (own)
		p->keep = cat(p->a, p->keep, raw, "\n");
}

static void
conf_read(struct parse *p, const char *path)
{
	char		 buf[2048], raw[2048], *s, *sels, *action, *sel, *port;
	char		*e, *where;
	const char	*why;
	struct act	*t, tmp;
	FILE		*fp;
	int		 line = 0;
	bool		 block = false, own;

	if ((fp = fopen(path, "r")) == NULL)
		return;
	own = p->own != NULL && strcmp(path, p->own) == 0;
	where = astrdup(p->a, path);
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		line++;
		buf[strcspn(buf, "\n")] = '\0';
		(void)strlcpy(raw, buf, sizeof(raw));
		s = buf + strspn(buf, " \t");
		/* A block of one program or host: "!prog", "#!prog",
		 * "+host", "-host"; "!*" and "+*" end it. */
		if (s[0] == '!' || s[0] == '+' || (s[0] == '-' && s[1] !=
		    '/') || (s[0] == '#' && (s[1] == '!' || s[1] == '+' ||
		    s[1] == '-'))) {
			const char *w = s[0] == '#' ? s + 2 : s + 1;

			block = strcmp(w, "*") != 0;
			held(p, own, raw);
			continue;
		}
		if (s[0] == '#' || s[0] == '\0')
			continue;
		if (strncmp(s, "include", 7) == 0 && isspace((unsigned char)
		    s[7])) {
			s += 7 + strspn(s + 7, " \t");
			s[strcspn(s, " \t")] = '\0';
			conf_include(p, s);
			held(p, own, raw);
			continue;
		}
		if (s[0] == ':') {
			unread(p, path, line, "a property filter: ietf-syslog "
			    "selects by facility and severity");
			held(p, own, raw);
			continue;
		}
		sels = s;
		action = s + strcspn(s, " \t");
		if (*action == '\0') {
			unread(p, path, line, "a selector with no action");
			held(p, own, raw);
			continue;
		}
		*action++ = '\0';
		action += strspn(action, " \t");
		e = action + strlen(action);
		while (e > action && isspace((unsigned char)e[-1]))
			*--e = '\0';
		if (block) {
			unread(p, path, line, "in a block of one program or "
			    "host: ietf-syslog has no such selector");
			held(p, own, raw);
			continue;
		}
		port = NULL;
		if (strcmp(action, "/dev/console") == 0)
			t = act_of(p, 'c', "console", NULL);
		else if (action[0] == '/' || (action[0] == '-' && action[1] ==
		    '/'))
			t = act_of(p, 'f', action + (action[0] == '-'), NULL);
		else if (action[0] == '@') {
			char *h = action + 1;

			if (h[0] == '[' && (e = strchr(h, ']')) != NULL) {
				*e = '\0';
				port = e[1] == ':' ? e + 2 : NULL;
				h++;
			} else if ((e = strrchr(h, ':')) != NULL &&
			    strchr(h, ':') == e) {
				*e = '\0';
				port = e + 1;
			}
			t = act_of(p, 'r', h, port);
		} else {
			unread(p, path, line, action[0] == '|' ? "a pipe to a "
			    "program: ietf-syslog has no such action" : "users "
			    "or everyone told: ietf-syslog has no such action");
			held(p, own, raw);
			continue;
		}
		if (t == NULL) {
			unread(p, path, line, "more actions than are read");
			held(p, own, raw);
			p->full = true;
			continue;
		}
		/* All its selectors, or none of them. */
		tmp = *t;
		why = NULL;
		while ((sel = strsep(&sels, ";")) != NULL)
			if (*sel != '\0' && !selector(&tmp, sel, &why))
				break;
		if (why != NULL) {
			unread(p, path, line, why);
			held(p, own, raw);
			continue;
		}
		*t = tmp;
		if (action[0] == '-')
			t->nosync = true;
		if (own)
			t->own = cat(p->a, t->own, raw, "\n");
		else if (p->nlines == nitems(p->lines))
			p->full = true;
		else {
			p->lines[p->nlines].path = where;
			p->lines[p->nlines].line = line;
			p->lines[p->nlines].act = (size_t)(t - p->acts);
			p->nlines++;
		}
	}
	fclose(fp);
}

/* newsyslog.conf(5): each file's count, size and interval. */
static void
newsyslog_read(struct parse *p, const char *path)
{
	char		 buf[2048], raw[2048], *s, *w[8], *where, *pat;
	FILE		*fp;
	int		 n, line = 0;
	bool		 own;
	glob_t		 g;

	if ((fp = fopen(path, "r")) == NULL)
		return;
	own = p->ownrot != NULL && strcmp(path, p->ownrot) == 0;
	where = astrdup(p->a, path);
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		struct rot *r;

		line++;
		buf[strcspn(buf, "\n")] = '\0';
		(void)strlcpy(raw, buf, sizeof(raw));
		s = buf + strspn(buf, " \t");
		if (s[0] == '#' || s[0] == '\0')
			continue;
		if (strncmp(s, "<include>", 9) == 0) {
			s += 9 + strspn(s + 9, " \t");
			pat = rooted(p, s);
			if (p->depth == 0 && p->ownrot != NULL && fnmatch(pat,
			    p->ownrot, FNM_PATHNAME | FNM_PERIOD) == 0)
				p->rot_included = true;
			if (p->depth < 4 && glob(pat, 0, NULL, &g) == 0) {
				p->depth++;
				for (size_t i = 0; i < g.gl_pathc; i++)
					newsyslog_read(p, g.gl_pathv[i]);
				p->depth--;
				globfree(&g);
			}
			continue;
		}
		for (n = 0; n < (int)nitems(w) && (w[n] = strsep(&s, " \t")) !=
		    NULL; )
			if (w[n][0] != '\0')
				n++;
		/* file [owner:group] mode count size when ... */
		if (n >= 2 && strchr(w[1], ':') != NULL) {
			memmove(&w[1], &w[2], (size_t)(n - 2) * sizeof(w[0]));
			n--;
		}
		if (n < 5)
			continue;
		if (p->nrots == nitems(p->rots)) {
			p->full = true;
			continue;
		}
		r = &p->rots[p->nrots++];
		memset(r, 0, sizeof(*r));
		r->name = astrdup(p->a, w[0]);
		r->path = where;
		r->line = line;
		r->own = own;
		r->text = astrdup(p->a, raw);
		r->count = strtoll(w[2], NULL, 10);
		r->size_kb = strcmp(w[3], "*") != 0 ? strtoll(w[3], NULL, 10) :
		    -1;
		r->hours = -1;
		if (strcmp(w[4], "*") == 0)
			;
		else if (isdigit((unsigned char)w[4][0]))
			r->hours = strtoll(w[4], NULL, 10);
		else
			r->at = true;
	}
	fclose(fp);
}

/* A file's rotation: newsyslog's first line of it, as newsyslog ignores
 * the others; NULL: none. */
static const struct rot *
rot_of(const struct parse *p, const char *name)
{

	for (size_t i = 0; i < p->nrots; i++)
		if (strcmp(p->rots[i].name, name) == 0)
			return (&p->rots[i]);
	return (NULL);
}

static void
files_read(struct parse *p, const char *conf, const char *newsyslog)
{
	const struct rot	*r;

	conf_read(p, conf);
	if (newsyslog != NULL)
		newsyslog_read(p, newsyslog);
	for (size_t i = 0; i < p->nacts; i++) {
		struct act *t = &p->acts[i];

		if (t->kind != 'f' || (r = rot_of(p, t->name)) == NULL)
			continue;
		t->count = r->count;
		t->size_kb = r->size_kb;
		t->hours = r->hours;
		if (r->at)
			unread(p, r->path, r->line, "turned over at a time of "
			    "day (@, $): ietf-syslog's rollover is an "
			    "interval");
	}
}

/* An action's selectors as a filter's facility-list. */
static int
filter_of(struct parse *p, const struct act *t, size_t *n, const yfl **out)
{
	yfl	*v;
	size_t	 k = 0;

	if ((v = cbl_yarena_alloc(p->a, (t->nsel + 1) * sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < t->nsel; i++) {
		if (t->sel[i].facility == 0) {
			v[k].facility.which = 1;
			v[k].facility.v.m1 =
			    IETF_SYSLOG_SYSLOG_ACTIONS_FILE_LOG_FILE_FILTER_FACILITY_LIST_FACILITY_M1_ALL;
		} else {
			v[k].facility.which = 0;
			v[k].facility.v.m0 = t->sel[i].facility;
		}
		if (t->sel[i].severity < 0) {
			v[k].severity.which = 1;
			v[k].severity.v.m1 = t->sel[i].severity == -1 ?
			    IETF_SYSLOG_SYSLOG_ACTIONS_FILE_LOG_FILE_FILTER_FACILITY_LIST_SEVERITY_M1_ALL :
			    IETF_SYSLOG_SYSLOG_ACTIONS_FILE_LOG_FILE_FILTER_FACILITY_LIST_SEVERITY_M1_NONE;
		} else {
			v[k].severity.which = 0;
			v[k].severity.v.m0 = t->sel[i].severity;
		}
		if (t->sel[i].equals) {
			struct ietf_syslog_syslog_actions_file_log_file_filter_facility_list_advanced_compare
			    *ac;

			if ((ac = cbl_yarena_alloc(p->a, sizeof(*ac))) == NULL)
				return (ENOMEM);
			ac->has_compare = true;
			ac->compare =
			    IETF_SYSLOG_SYSLOG_ACTIONS_FILE_LOG_FILE_FILTER_FACILITY_LIST_ADVANCED_COMPARE_COMPARE_EQUALS;
			v[k].advanced_compare = ac;
		}
		k++;
	}
	*n = k;
	*out = v;
	return (0);
}

/*
 * The console's, the files' and the remotes' structs share their shape
 * (one grouping): the file's are filled and the others cast to them.
 */
_Static_assert(sizeof(struct ietf_syslog_syslog_actions_file_log_file_filter_facility_list) ==
    sizeof(struct ietf_syslog_syslog_actions_console_filter_facility_list),
    "facility-list's shape");
_Static_assert(sizeof(struct ietf_syslog_syslog_actions_file_log_file_filter_facility_list) ==
    sizeof(struct ietf_syslog_syslog_actions_remote_destination_filter_facility_list),
    "facility-list's shape");

int
ysyslog_read(const char *root, const char *conf, const char *newsyslog,
    cbl_yarena *a, struct ietf_syslog *out, struct yunread **u, size_t *nu)
{
	struct ietf_syslog_syslog			*sl;
	struct ietf_syslog_syslog_actions		*ac;
	struct ietf_syslog_syslog_actions_file		*fa;
	struct ietf_syslog_syslog_actions_file_log_file	*lf;
	struct ietf_syslog_syslog_actions_remote	*ra;
	struct ietf_syslog_syslog_actions_remote_destination *rd;
	struct parse	*p;
	size_t		 nf = 0, nr = 0;
	int		 error = 0;

	memset(out, 0, sizeof(*out));
	*u = NULL;
	*nu = 0;
	if ((p = calloc(1, sizeof(*p))) == NULL)
		return (ENOMEM);
	p->a = a;
	p->root = root;
	p->maxu = 64;
	if ((p->u = cbl_yarena_alloc(a, p->maxu * sizeof(*p->u))) == NULL) {
		free(p);
		return (ENOMEM);
	}
	files_read(p, conf, newsyslog);
	if ((sl = cbl_yarena_alloc(a, sizeof(*sl))) == NULL ||
	    (ac = cbl_yarena_alloc(a, sizeof(*ac))) == NULL ||
	    (fa = cbl_yarena_alloc(a, sizeof(*fa))) == NULL ||
	    (ra = cbl_yarena_alloc(a, sizeof(*ra))) == NULL ||
	    (lf = cbl_yarena_alloc(a, (p->nacts + 1) * sizeof(*lf))) == NULL ||
	    (rd = cbl_yarena_alloc(a, (p->nacts + 1) * sizeof(*rd))) == NULL) {
		free(p);
		return (ENOMEM);
	}
	for (size_t i = 0; i < p->nacts && error == 0; i++) {
		struct act	*t = &p->acts[i];
		size_t		 n;
		const yfl	*fl;

		if (t->nsel == 0)
			continue;
		if ((error = filter_of(p, t, &n, &fl)) != 0)
			break;
		if (t->kind == 'c') {
			struct ietf_syslog_syslog_actions_console *c;
			struct ietf_syslog_syslog_actions_console_filter *cf;

			if ((c = cbl_yarena_alloc(a, sizeof(*c))) == NULL ||
			    (cf = cbl_yarena_alloc(a, sizeof(*cf))) == NULL) {
				error = ENOMEM;
				break;
			}
			cf->facility_list.n = n;
			cf->facility_list.v = (const void *)fl;
			c->filter = cf;
			ac->console = c;
		} else if (t->kind == 'f') {
			struct ietf_syslog_syslog_actions_file_log_file_filter *ff;
			struct ietf_syslog_syslog_actions_file_log_file_file_rotation
			    *fr;
			char uri[MAXPATHLEN + 8];

			if ((ff = cbl_yarena_alloc(a, sizeof(*ff))) == NULL ||
			    (fr = cbl_yarena_alloc(a, sizeof(*fr))) == NULL) {
				error = ENOMEM;
				break;
			}
			snprintf(uri, sizeof(uri), "file:%s", t->name);
			lf[nf].name = astrdup(a, uri);
			ff->facility_list.n = n;
			ff->facility_list.v = fl;
			lf[nf].filter = ff;
			if (t->count >= 0) {
				fr->has_number_of_files = true;
				fr->number_of_files = (uint32_t)t->count;
			}
			if (t->size_kb >= 0) {
				fr->has_max_file_size = true;
				fr->max_file_size = (uint32_t)((t->size_kb +
				    1023) / 1024);
			}
			if (t->hours >= 0) {
				fr->has_rollover = true;
				fr->rollover = (uint32_t)(t->hours * 60);
			}
			if (fr->has_number_of_files || fr->has_max_file_size ||
			    fr->has_rollover)
				lf[nf].file_rotation = fr;
			nf++;
		} else {
			struct ietf_syslog_syslog_actions_remote_destination_udp
			    *ud;
			struct ietf_syslog_syslog_actions_remote_destination_udp_udp
			    *uu;
			struct ietf_syslog_syslog_actions_remote_destination_filter
			    *rf;
			struct in_addr in;
			struct in6_addr in6;

			if ((ud = cbl_yarena_alloc(a, sizeof(*ud))) == NULL ||
			    (uu = cbl_yarena_alloc(a, sizeof(*uu))) == NULL ||
			    (rf = cbl_yarena_alloc(a, sizeof(*rf))) == NULL) {
				error = ENOMEM;
				break;
			}
			rd[nr].name = t->name;
			rd[nr].transport =
			    IETF_SYSLOG_SYSLOG_ACTIONS_REMOTE_DESTINATION_TRANSPORT_UDP;
			/* inet:host: an IPv4 or IPv6 address, or a name. */
			uu->address.which = inet_pton(AF_INET, t->name, &in) ==
			    1 ? 0 : inet_pton(AF_INET6, t->name, &in6) == 1 ? 1 : 2;
			uu->address.v.m0 = t->name;
			if (t->port != NULL) {
				uu->has_port = true;
				uu->port = (uint16_t)strtoul(t->port, NULL, 10);
			}
			ud->udp.n = 1;
			ud->udp.v = uu;
			rd[nr].udp = ud;
			rf->facility_list.n = n;
			rf->facility_list.v = (const void *)fl;
			rd[nr].filter = rf;
			nr++;
		}
	}
	if (error == 0) {
		fa->log_file.n = nf;
		fa->log_file.v = lf;
		ra->destination.n = nr;
		ra->destination.v = rd;
		if (nf > 0)
			ac->file = fa;
		if (nr > 0)
			ac->remote = ra;
		sl->actions = ac;
		out->syslog = sl;
		*u = p->u;
		*nu = p->nu;
	}
	free(p);
	return (error);
}

/* ---- ietf-syslog committed: Arcana's syslog.conf and newsyslog.conf -- */

#define	SYSLOG_HEAD	"# Arcana's: what a commit of ietf-syslog (RFC 9742) " \
	"wrote, written\n# again by the next one; syslogd(8) reads it by " \
	"syslog.conf's include.\n"
#define	NEWSYSLOG_HEAD	"# Arcana's: the rotation of the logs a commit of " \
	"ietf-syslog wrote,\n# written again by the next one.\n"
#define	TAKEN		"# taken by Arcana: "

/* syslog's name of facility sid; NULL: none (cron2). */
static const char *
facility_name(uint64_t sid)
{

	for (size_t i = 0; i < nitems(facilities); i++)
		if (ident("ietf-syslog", facilities[i].ietf) == sid)
			return (facilities[i].bsd);
	return (NULL);
}

/* An identity's name, by its SID. */
static const char *
ident_name(uint64_t sid)
{

	for (uint32_t i = 0; i < ymodel_schema.nident; i++)
		if (ymodel_schema.ident[i].sid == sid)
			return (ymodel_schema.ident[i].name);
	return ("?");
}

/* Whether s is a word syslog.conf holds as it is: no blank, no control
 * character, no '#' (a comment's start) or ';'. */
static bool
word_ok(const char *s)
{

	for (; *s != '\0'; s++)
		if (isspace((unsigned char)*s) || iscntrl((unsigned char)*s) ||
		    *s == '#' || *s == ';')
			return (false);
	return (true);
}

/* A filter's entries as t's selectors; err said, one syslogd has no
 * selector for. */
static int
want_sels(struct act *t, const char *what, size_t n, const yfl *v,
    char *err, size_t errlen)
{
	uint64_t	log = ident("ietf-syslog", "log");

	for (size_t i = 0; i < n; i++) {
		const struct ietf_syslog_syslog_actions_file_log_file_filter_facility_list_advanced_compare
		    *ac = v[i].advanced_compare;
		uint64_t	sid = v[i].facility.which == 0 ?
				    v[i].facility.v.m0 : 0;
		int		sev;

		if (sid != 0 && facility_name(sid) == NULL) {
			snprintf(err, errlen, "%s: facility %s: syslog has no "
			    "such facility", what, ident_name(sid));
			return (EOPNOTSUPP);
		}
		if (v[i].severity.which == 0)
			sev = (int)v[i].severity.v.m0;
		else
			sev = v[i].severity.v.m1 ==
			    IETF_SYSLOG_SYSLOG_ACTIONS_FILE_LOG_FILE_FILTER_FACILITY_LIST_SEVERITY_M1_ALL ?
			    -1 : -2;
		if (sev >= (int)nitems(levels)) {
			snprintf(err, errlen, "%s: a severity syslog has no "
			    "name for", what);
			return (EINVAL);
		}
		if (ac != NULL && ac->has_action && ac->action != log) {
			snprintf(err, errlen, "%s: %s: syslogd's selectors log "
			    "what they select, they neither block nor stop",
			    what, ident_name(ac->action));
			return (EOPNOTSUPP);
		}
		if (t->nsel == nitems(t->sel)) {
			snprintf(err, errlen, "%s: more selectors than are "
			    "written", what);
			return (E2BIG);
		}
		sel_add(t, sid, sev, sev >= 0 && ac != NULL &&
		    ac->has_compare && ac->compare ==
		    IETF_SYSLOG_SYSLOG_ACTIONS_FILE_LOG_FILE_FILTER_FACILITY_LIST_ADVANCED_COMPARE_COMPARE_EQUALS);
	}
	return (0);
}

/*
 * The actions after asks for, as the files' are gathered (a file's
 * rotation in newsyslog's units); err said, what syslogd or newsyslog
 * cannot have.
 */
static int
want_of(struct parse *q, const struct ietf_syslog *after, char *err,
    size_t errlen)
{
	const struct ietf_syslog_syslog_actions	*ac = NULL;
	struct act				*t;
	int					 error;

	if (after != NULL && after->syslog != NULL)
		ac = after->syslog->actions;
	if (ac == NULL)
		return (0);
	if (ac->console != NULL && ac->console->filter != NULL &&
	    (t = act_of(q, 'c', "console", NULL)) != NULL &&
	    (error = want_sels(t, "console",
	    ac->console->filter->facility_list.n, (const void *)
	    ac->console->filter->facility_list.v, err, errlen)) != 0)
		return (error);
	for (size_t i = 0; ac->file != NULL && i < ac->file->log_file.n; i++) {
		const struct ietf_syslog_syslog_actions_file_log_file *f =
		    &ac->file->log_file.v[i];
		const struct ietf_syslog_syslog_actions_file_log_file_file_rotation
		    *r = f->file_rotation;
		const char *path = f->name + 5;

		if (strncmp(f->name, "file:/", 6) != 0 || path[1] == '/' ||
		    !word_ok(path)) {
			snprintf(err, errlen, "%s: a log file is named "
			    "file:/path, a path syslog.conf holds (no blank, "
			    "'#' or ';')", f->name);
			return (EINVAL);
		}
		if (strcmp(path, "/dev/console") == 0) {
			snprintf(err, errlen, "%s: the console is an action of "
			    "its own", f->name);
			return (EINVAL);
		}
		if ((t = act_of(q, 'f', path, NULL)) == NULL) {
			snprintf(err, errlen, "more actions than are written");
			return (E2BIG);
		}
		if (f->filter != NULL && (error = want_sels(t, f->name,
		    f->filter->facility_list.n, f->filter->facility_list.v,
		    err, errlen)) != 0)
			return (error);
		if (r == NULL)
			continue;
		if (r->has_retention) {
			snprintf(err, errlen, "%s: retention: newsyslog keeps "
			    "a number of files, not an age", f->name);
			return (EOPNOTSUPP);
		}
		if (r->has_rollover && (r->rollover == 0 || r->rollover % 60 !=
		    0)) {
			snprintf(err, errlen, "%s: a rollover of %u minutes: "
			    "newsyslog turns a log over by the hour", f->name,
			    r->rollover);
			return (EOPNOTSUPP);
		}
		t->size_kb = r->has_max_file_size ?
		    (long long)r->max_file_size * 1024 : -1;
		t->hours = r->has_rollover ? (long long)r->rollover / 60 : -1;
		/* newsyslog's count is not left out: ietf-syslog's default. */
		t->count = r->has_number_of_files ?
		    (long long)r->number_of_files : t->size_kb >= 0 ||
		    t->hours >= 0 ? 1 : -1;
	}
	for (size_t i = 0; ac->remote != NULL && i < ac->remote->destination.n;
	    i++) {
		const struct ietf_syslog_syslog_actions_remote_destination *d =
		    &ac->remote->destination.v[i];
		const struct ietf_syslog_syslog_actions_remote_destination_udp_udp
		    *uu;
		struct in6_addr	in6;
		char		port[8];

		if (d->transport !=
		    IETF_SYSLOG_SYSLOG_ACTIONS_REMOTE_DESTINATION_TRANSPORT_UDP ||
		    d->udp == NULL || d->udp->udp.n != 1) {
			snprintf(err, errlen, "%s: syslogd sends to one "
			    "address over UDP alone", d->name);
			return (EOPNOTSUPP);
		}
		if (d->has_facility_override) {
			snprintf(err, errlen, "%s: facility-override: syslogd "
			    "forwards a message with its own facility",
			    d->name);
			return (EOPNOTSUPP);
		}
		uu = &d->udp->udp.v[0];
		if (uu->address.v.m0 == NULL || strcmp(uu->address.v.m0,
		    d->name) != 0) {
			snprintf(err, errlen, "%s: a destination is named by "
			    "its address, all syslog.conf has of it", d->name);
			return (EINVAL);
		}
		if (!word_ok(d->name) || d->name[strcspn(d->name, "[]@")] !=
		    '\0' || (strchr(d->name, ':') != NULL &&
		    inet_pton(AF_INET6, d->name, &in6) != 1)) {
			snprintf(err, errlen, "%s: an address syslog.conf "
			    "cannot hold", d->name);
			return (EINVAL);
		}
		if (uu->has_port)
			snprintf(port, sizeof(port), "%u", uu->port);
		if ((t = act_of(q, 'r', d->name, uu->has_port ? port :
		    NULL)) == NULL) {
			snprintf(err, errlen, "more actions than are written");
			return (E2BIG);
		}
		if (d->filter != NULL && (error = want_sels(t, d->name,
		    d->filter->facility_list.n, (const void *)
		    d->filter->facility_list.v, err, errlen)) != 0)
			return (error);
	}
	return (0);
}

/* t as a line of syslog.conf, its selectors and its action; NULL:
 * longer than syslogd reads (LINE_MAX). */
static char *
line_of(cbl_yarena *a, const struct act *t)
{
	char	buf[4096];
	size_t	off = 0;

	for (size_t i = 0; i < t->nsel && off < sizeof(buf); i++) {
		int sev = t->sel[i].severity;

		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
		    "%s%s.%s%s", i > 0 ? ";" : "", t->sel[i].facility == 0 ?
		    "*" : facility_name(t->sel[i].facility), t->sel[i].equals ?
		    "=" : "", sev == -1 ? "*" : sev == -2 ? "none" :
		    levels[sev].names[0]);
	}
	if (off < sizeof(buf)) {
		if (t->kind == 'c')
			off += (size_t)snprintf(buf + off, sizeof(buf) - off,
			    "\t/dev/console");
		else if (t->kind == 'f')
			off += (size_t)snprintf(buf + off, sizeof(buf) - off,
			    "\t%s%s", t->nosync ? "-" : "", t->name);
		else {
			bool v6 = strchr(t->name, ':') != NULL;

			off += (size_t)snprintf(buf + off, sizeof(buf) - off,
			    "\t@%s%s%s%s%s", v6 ? "[" : "", t->name, v6 ? "]" :
			    "", t->port != NULL ? ":" : "", t->port != NULL ?
			    t->port : "");
		}
	}
	if (off >= sizeof(buf) || off + 1 >= LINE_MAX)
		return (NULL);
	return (astrdup(a, buf));
}

/* t's rotation as a line of newsyslog.conf: the log's mode as it is,
 * syslogd -C's 0600 where it is not there yet; bzip2(1) the old ones,
 * the log made where it is gone (JC, as FreeBSD's own). */
static char *
rot_line(struct parse *p, const struct act *t)
{
	char		buf[MAXPATHLEN + 64], size[24], when[24];
	struct stat	sb;
	mode_t		mode = 0600;

	if (stat(rooted(p, t->name), &sb) == 0)
		mode = sb.st_mode & 0777;
	if (t->size_kb >= 0)
		snprintf(size, sizeof(size), "%lld", t->size_kb);
	else
		strlcpy(size, "*", sizeof(size));
	if (t->hours >= 0)
		snprintf(when, sizeof(when), "%lld", t->hours);
	else
		strlcpy(when, "*", sizeof(when));
	snprintf(buf, sizeof(buf), "%s\t%o  %lld\t%s\t%s\tJC", t->name,
	    (unsigned)mode, t->count, size, when);
	return (astrdup(p->a, buf));
}

/* Whether x and y select the same, in the same order. */
static bool
sels_same(const struct act *x, const struct act *y)
{

	if (x->nsel != y->nsel || (x->port == NULL) != (y->port == NULL) ||
	    (x->port != NULL && strcmp(x->port, y->port) != 0))
		return (false);
	for (size_t i = 0; i < x->nsel; i++)
		if (x->sel[i].facility != y->sel[i].facility ||
		    x->sel[i].severity != y->sel[i].severity ||
		    x->sel[i].equals != y->sel[i].equals)
			return (false);
	return (true);
}

/* Whether x's and y's rotations are one, as ietf-syslog has them. */
static bool
rot_same(const struct act *x, const struct act *y)
{
#define	MIB(kb)	((kb) < 0 ? -1 : ((kb) + 1023) / 1024)

	return (x->count == y->count && MIB(x->size_kb) == MIB(y->size_kb) &&
	    x->hours == y->hours);
#undef MIB
}

/* p's action of kind and name that selects anything; NULL: none. */
static struct act *
act_find(struct parse *p, char kind, const char *name)
{

	for (size_t i = 0; i < p->nacts; i++)
		if (p->acts[i].kind == kind && p->acts[i].nsel > 0 &&
		    strcmp(p->acts[i].name, name) == 0)
			return (&p->acts[i]);
	return (NULL);
}

/* The user's lines of h, to be taken over. */
static void
take(struct parse *p, const struct act *h, struct ysyslog_plan *out)
{

	for (size_t i = 0; i < p->nlines; i++)
		if (p->lines[i].act == (size_t)(h - p->acts)) {
			out->take[out->ntake].path = p->lines[i].path;
			out->take[out->ntake].line = p->lines[i].line;
			out->ntake++;
		}
}

int
ysyslog_plan(const char *root, const struct ietf_syslog *after,
    cbl_yarena *a, struct ysyslog_plan *out, char *err, size_t errlen)
{
	struct parse	*p, *q = NULL;
	struct stat	 sb;
	char		*conf, *rot, *line;
	bool		 lines = false, rlines = false;
	int		 error = 0;

	memset(out, 0, sizeof(*out));
	if ((p = calloc(1, sizeof(*p))) == NULL ||
	    (q = calloc(1, sizeof(*q))) == NULL) {
		free(p);
		return (ENOMEM);
	}
	p->a = q->a = a;
	p->root = q->root = root;
	p->own = rooted(p, SYSLOG_ARCANA);
	p->ownrot = rooted(p, NEWSYSLOG_ARCANA);
	files_read(p, rooted(p, SYSLOG_CONF), rooted(p, NEWSYSLOG_CONF));
	if (p->full) {
		snprintf(err, errlen, "syslog.conf and newsyslog.conf have "
		    "more than a commit reads");
		error = E2BIG;
	} else
		error = want_of(q, after, err, errlen);
	if (error == 0 && ((out->take = cbl_yarena_alloc(a, (p->nlines +
	    p->nrots + 1) * sizeof(*out->take))) == NULL || (out->create =
	    cbl_yarena_alloc(a, (q->nacts + 1) * sizeof(*out->create))) ==
	    NULL))
		error = ENOMEM;
	conf = astrdup(a, SYSLOG_HEAD);
	rot = astrdup(a, NEWSYSLOG_HEAD);
	for (size_t i = 0; error == 0 && i < q->nacts; i++) {
		struct act		*t = &q->acts[i], *h, was;
		const struct rot	*r;

		if (t->nsel == 0)
			continue;
		h = act_find(p, t->kind, t->name);
		if (h != NULL && sels_same(h, t)) {
			/* As it is: Arcana's lines of it, the user's left. */
			if (h->own != NULL) {
				conf = cat(a, conf, h->own, "");
				lines = true;
			}
		} else {
			out->changed = true;
			if (h != NULL) {
				t->nosync = h->nosync;
				take(p, h, out);
			} else if (t->kind == 'f' && stat(rooted(p, t->name),
			    &sb) == -1)
				out->create[out->ncreate++] = rooted(p,
				    t->name);
			if ((line = line_of(a, t)) == NULL) {
				snprintf(err, errlen, "%s: a line longer than "
				    "syslogd reads", t->name);
				error = E2BIG;
				break;
			}
			conf = cat(a, conf, line, "\n");
			lines = true;
		}
		if (t->kind != 'f')
			continue;
		/* Its rotation, newsyslog's first line of it. */
		memset(&was, 0, sizeof(was));
		was.count = was.size_kb = was.hours = -1;
		if ((r = rot_of(p, t->name)) != NULL) {
			was.count = r->count;
			was.size_kb = r->size_kb;
			was.hours = r->hours;
		}
		if (rot_same(&was, t)) {
			for (size_t k = 0; k < p->nrots; k++)
				if (p->rots[k].own && strcmp(p->rots[k].name,
				    t->name) == 0) {
					rot = cat(a, rot, p->rots[k].text,
					    "\n");
					rlines = true;
				}
			continue;
		}
		out->changed = true;
		for (size_t k = 0; k < p->nrots; k++)
			if (!p->rots[k].own && strcmp(p->rots[k].name,
			    t->name) == 0) {
				out->take[out->ntake].path = p->rots[k].path;
				out->take[out->ntake].line = p->rots[k].line;
				out->ntake++;
			}
		if (t->count >= 0) {
			rot = cat(a, rot, rot_line(p, t), "\n");
			rlines = true;
		}
	}
	/* What goes: the user's lines of it taken; Arcana's rotation of a
	 * file it writes no more. */
	for (size_t i = 0; error == 0 && i < p->nacts; i++)
		if (p->acts[i].nsel > 0 && act_find(q, p->acts[i].kind,
		    p->acts[i].name) == NULL) {
			out->changed = true;
			take(p, &p->acts[i], out);
		}
	for (size_t k = 0; error == 0 && k < p->nrots; k++)
		if (p->rots[k].own && act_find(q, 'f', p->rots[k].name) == NULL)
			out->changed = true;
	if (error == 0) {
		if (p->keep != NULL) {
			conf = cat(a, conf, p->keep, "");
			lines = true;
		}
		out->conf = lines || stat(p->own, &sb) == 0 ? conf : NULL;
		out->rot = rlines || stat(p->ownrot, &sb) == 0 ? rot : NULL;
		out->included = p->included;
		out->rot_included = p->rot_included;
	}
	free(p);
	free(q);
	return (error);
}

/* The lines of path the plan takes over, commented out. */
static int
take_in(const struct ysyslog_plan *pl, const char *path)
{
	char		 tmp[MAXPATHLEN], buf[4096];
	struct stat	 sb;
	FILE		*in, *out;
	int		 fd, line = 0, error = 0;
	bool		 bol = true;

	if ((in = fopen(path, "re")) == NULL)
		return (errno);
	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
	if (fstat(fileno(in), &sb) == -1 || (fd = mkstemp(tmp)) == -1) {
		error = errno;
		fclose(in);
		return (error);
	}
	(void)fchown(fd, sb.st_uid, sb.st_gid);
	(void)fchmod(fd, sb.st_mode & 07777);
	if ((out = fdopen(fd, "w")) == NULL) {
		error = errno;
		close(fd);
		unlink(tmp);
		fclose(in);
		return (error);
	}
	while (fgets(buf, sizeof(buf), in) != NULL) {
		if (bol) {
			line++;
			for (size_t i = 0; i < pl->ntake; i++)
				if (pl->take[i].line == line &&
				    strcmp(pl->take[i].path, path) == 0) {
					fputs(TAKEN, out);
					break;
				}
		}
		fputs(buf, out);
		bol = strchr(buf, '\n') != NULL;
	}
	if (ferror(in))
		error = errno != 0 ? errno : EIO;
	if (fclose(out) == EOF && error == 0)
		error = errno;
	fclose(in);
	if (error == 0 && rename(tmp, path) == -1)
		error = errno;
	if (error != 0)
		unlink(tmp);
	return (error);
}

int
ysyslog_take(const struct ysyslog_plan *pl)
{
	int	error;

	for (size_t i = 0; i < pl->ntake; i++) {
		bool done = false;

		for (size_t j = 0; j < i && !done; j++)
			done = strcmp(pl->take[j].path, pl->take[i].path) == 0;
		if (!done && (error = take_in(pl, pl->take[i].path)) != 0)
			return (error);
	}
	return (0);
}

int
ysyslog_check(const char *root, const struct ietf_syslog *after,
    char *err, size_t errlen)
{
	struct parse	*p, *q = NULL;
	cbl_yarena	*a;
	int		 error = 0;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((p = calloc(1, sizeof(*p))) == NULL ||
	    (q = calloc(1, sizeof(*q))) == NULL) {
		free(p);
		cbl_yarena_free(a);
		return (ENOMEM);
	}
	p->a = q->a = a;
	p->root = q->root = root;
	files_read(p, rooted(p, SYSLOG_CONF), rooted(p, NEWSYSLOG_CONF));
	error = want_of(q, after, err, errlen);
	for (size_t i = 0; error == 0 && i < q->nacts; i++) {
		const struct act	*t = &q->acts[i], *h;

		if (t->nsel == 0)
			continue;
		if ((h = act_find(p, t->kind, t->name)) == NULL ||
		    !sels_same(h, t) || (t->kind == 'f' && !rot_same(h, t))) {
			snprintf(err, errlen, "%s: the files read back "
			    "otherwise than it was asked", t->name);
			error = EIO;
		}
	}
	for (size_t i = 0; error == 0 && i < p->nacts; i++)
		if (p->acts[i].nsel > 0 && act_find(q, p->acts[i].kind,
		    p->acts[i].name) == NULL) {
			snprintf(err, errlen, "%s: in the files still",
			    p->acts[i].name);
			error = EIO;
		}
	free(p);
	free(q);
	cbl_yarena_free(a);
	return (error);
}
