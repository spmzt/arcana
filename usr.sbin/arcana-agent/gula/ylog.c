/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the logs as YANG (PLAN-SDN-YANG 3.1.7).
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
 *   rounded up, its interval (hours) the rollover in minutes.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

	for (size_t i = 0; i < nitems(facilities); i++)
		if (strlen(facilities[i].bsd) == n && strncmp(bsd,
		    facilities[i].bsd, n) == 0)
			return (ident("ietf-syslog", facilities[i].ietf));
	return (0);
}

static int
level_of(const char *s)
{

	for (size_t i = 0; i < nitems(levels); i++)
		for (size_t k = 0; k < 2; k++)
			if (levels[i].names[k] != NULL && strcmp(s,
			    levels[i].names[k]) == 0)
				return ((int)i);
	return (-1);
}

/* ---- The log operation's replies ----------------------------------- */

int
ylog_files_from_json(const char *json, const char *dir, cbl_yarena *a,
    struct arcana_log_logs *out)
{
	struct arcana_log_logs_file	*v;
	const ucl_object_t		*e;
	ucl_object_iter_t		 it;
	ucl_object_t			*top;
	int64_t				 n;
	size_t				 k = 0;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->directory = dir != NULL ? astrdup(a, dir) : NULL;
	if ((v = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "files")) + 1) * sizeof(*v))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "files"), it, e) {
		v[k].name = yj_str(a, e, "name");
		YJ_NUM(e, "size", &v[k], size);
		if (yj_num(e, "mtime", &n))
			v[k].modified = datetime(a, n);
		v[k].packed = yj_yes(e, "packed", &v[k].has_packed);
		if (v[k].name != NULL)
			k++;
	}
	out->file.n = k;
	out->file.v = v;
	ucl_object_unref(top);
	return (0);
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
	ucl_object_unref(top);
	return (0);
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
};

struct parse {
	cbl_yarena	*a;
	struct act	 acts[64];
	size_t		 nacts;
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
		if (t->nsel == nitems(t->sel))
			break;
		t->sel[t->nsel].facility = sid;
		t->sel[t->nsel].severity = sev;
		t->sel[t->nsel].equals = equals;
		t->nsel++;
	}
	return (true);
}

static void conf_read(struct parse *, const char *);

/* "include dir": its files ending in .conf, in order, as syslogd does. */
static void
conf_include(struct parse *p, const char *dir)
{
	char	pat[MAXPATHLEN];
	glob_t	g;

	if (p->depth > 4)
		return;
	snprintf(pat, sizeof(pat), "%s/*.conf", dir);
	if (glob(pat, 0, NULL, &g) != 0)
		return;
	p->depth++;
	for (size_t i = 0; i < g.gl_pathc; i++)
		conf_read(p, g.gl_pathv[i]);
	p->depth--;
	globfree(&g);
}

static void
conf_read(struct parse *p, const char *path)
{
	char		 buf[2048], *s, *sels, *action, *sel, *port, *e;
	const char	*why;
	struct act	*t, tmp;
	FILE		*fp;
	int		 line = 0;
	bool		 block = false;

	if ((fp = fopen(path, "r")) == NULL)
		return;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		line++;
		buf[strcspn(buf, "\n")] = '\0';
		s = buf + strspn(buf, " \t");
		/* A block of one program or host: "!prog", "#!prog",
		 * "+host", "-host"; "!*" and "+*" end it. */
		if (s[0] == '!' || s[0] == '+' || (s[0] == '-' && s[1] !=
		    '/') || (s[0] == '#' && (s[1] == '!' || s[1] == '+' ||
		    s[1] == '-'))) {
			const char *w = s[0] == '#' ? s + 2 : s + 1;

			block = strcmp(w, "*") != 0;
			continue;
		}
		if (s[0] == '#' || s[0] == '\0')
			continue;
		if (strncmp(s, "include", 7) == 0 && isspace((unsigned char)
		    s[7])) {
			s += 7 + strspn(s + 7, " \t");
			conf_include(p, s);
			continue;
		}
		if (s[0] == ':') {
			unread(p, path, line, "a property filter: ietf-syslog "
			    "selects by facility and severity");
			continue;
		}
		sels = s;
		action = s + strcspn(s, " \t");
		if (*action == '\0') {
			unread(p, path, line, "a selector with no action");
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
			continue;
		}
		if (t == NULL) {
			unread(p, path, line, "more actions than are read");
			continue;
		}
		/* All its selectors, or none of them. */
		tmp = *t;
		why = NULL;
		while ((sel = strsep(&sels, ";")) != NULL)
			if (*sel != '\0' && !selector(&tmp, sel, &why))
				break;
		if (why != NULL)
			unread(p, path, line, why);
		else
			*t = tmp;
	}
	fclose(fp);
}

/* newsyslog.conf(5): each file's count, size and interval. */
static void
newsyslog_read(struct parse *p, const char *path)
{
	char		 buf[2048], *s, *w[8];
	FILE		*fp;
	int		 n, line = 0;
	glob_t		 g;

	if ((fp = fopen(path, "r")) == NULL)
		return;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		line++;
		buf[strcspn(buf, "\n")] = '\0';
		s = buf + strspn(buf, " \t");
		if (s[0] == '#' || s[0] == '\0')
			continue;
		if (strncmp(s, "<include>", 9) == 0) {
			s += 9 + strspn(s + 9, " \t");
			if (p->depth < 4 && glob(s, 0, NULL, &g) == 0) {
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
		for (size_t i = 0; i < p->nacts; i++) {
			struct act *t = &p->acts[i];

			if (t->kind != 'f' || strcmp(t->name, w[0]) != 0)
				continue;
			t->count = strtoll(w[2], NULL, 10);
			if (strcmp(w[3], "*") != 0)
				t->size_kb = strtoll(w[3], NULL, 10);
			if (strcmp(w[4], "*") == 0)
				;
			else if (isdigit((unsigned char)w[4][0]))
				t->hours = strtoll(w[4], NULL, 10);
			else
				unread(p, path, line, "turned over at a time of "
				    "day (@, $): ietf-syslog's rollover is an "
				    "interval");
		}
	}
	fclose(fp);
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
		bool	dup = false;

		/* The key is facility and severity: once each. */
		for (size_t j = 0; j < i; j++)
			dup = dup || (t->sel[j].facility == t->sel[i].facility &&
			    t->sel[j].severity == t->sel[i].severity);
		if (dup)
			continue;
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
ysyslog_read(const char *conf, const char *newsyslog, cbl_yarena *a,
    struct ietf_syslog *out, struct yunread **u, size_t *nu)
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
	p->maxu = 64;
	if ((p->u = cbl_yarena_alloc(a, p->maxu * sizeof(*p->u))) == NULL) {
		free(p);
		return (ENOMEM);
	}
	conf_read(p, conf);
	if (newsyslog != NULL)
		newsyslog_read(p, newsyslog);
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
