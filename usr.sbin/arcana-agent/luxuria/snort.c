/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: Snort 3, an IDS/IPS, a plugin of the host's.  The snort3
 * package has no rc.d script: Arcana's own, arcana_snort, runs it, as
 * rc.conf's arcana_snort_* say: watching interfaces (ids) or inline,
 * taking what an ipfw divert rule hands its port (ips), its alerts in
 * alert_json.txt of the log directory.
 *
 * The admin's snort.lua stays the configuration; what Arcana adds is a
 * rules file of its own, arcana/arcana.rules, given by -R: an include
 * of each rules file an update took in, as turned on and off here, and
 * of local.rules.  An update fetches an archive (or a .rules file) by
 * libfetch, Snort's community rules unless another address is given,
 * and takes in every *.rules in it.  A rule turned on or off is kept
 * by gid:sid in arcana/rule-state and holds across updates: the
 * downloaded files are kept as they came, the active ones made from
 * them.  Whatever replaces what was there is checked by snort -T
 * first; a running Snort is then told to reload (SIGHUP, as rc.d's
 * reload does).
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <fetch.h>
#include <openssl/evp.h>
#include <ucl.h>

#include "agent.h"

#define	COMMUNITY_URL	"https://www.snort.org/downloads/community/" \
			    "snort3-community-rules.tar.gz"
#define	TEXT_MAX	(1024 * 1024)	/* snort.lua, local.rules */
#define	ARCHIVE_MAX	(256 * 1024 * 1024)
#define	ALERTS_TAIL	(512 * 1024)	/* of alert_json.txt, read */
#define	ALERTS_MAX	200
#define	FILES_MAX	512		/* rules files an archive gives */
#define	FETCH_WAIT_S	120

static pthread_mutex_t	sn_fetch_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *const actions[] = {
	"alert", "block", "drop", "log", "pass", "react", "reject",
	"rewrite",
};

/* A file whole, at most max bytes and no NUL in it; NULL else. */
static const char *
slurp_file(struct work *w, const char *path, size_t max)
{
	struct stat	 st;
	char		*buf;
	ssize_t		 got;
	int		 fd;

	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
		return (NULL);
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
	    (size_t)st.st_size > max) {
		close(fd);
		return (NULL);
	}
	buf = wcalloc(w, 1, (size_t)st.st_size + 1);
	got = st.st_size > 0 ? read(fd, buf, (size_t)st.st_size) : 0;
	close(fd);
	if (got != st.st_size || memchr(buf, '\0', (size_t)got) != NULL)
		return (NULL);
	return (buf);
}

/* JSON text as an object; the caller's to unref. */
static ucl_object_t *
json_parse_w(struct work *w __unused, const char *text)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, text, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	return (o);
}

/* ---- Where things are -------------------------------------------- */

static const char *
sn_lua(struct work *w)
{

	return (wfmt(w, "%s/snort.lua", opts.snort_etc));
}

static const char *
sn_local(struct work *w)
{

	return (wfmt(w, "%s/local.rules", opts.snort_etc));
}

static const char *
sn_dir(struct work *w, const char *name)
{

	return (wfmt(w, "%s/arcana%s%s", opts.snort_etc, name != NULL ? "/" :
	    "", name != NULL ? name : ""));
}

/* ---- Words ------------------------------------------------------- */

/* The value of key= among the job's words, or NULL; the n-th of it. */
static const char *
arg(const struct arc_job_spec *sp, const char *key, size_t nth)
{
	size_t	i, k;

	k = strlen(key);
	for (i = 0; i < sp->names.n; i++)
		if (strncmp(sp->names.v[i], key, k) == 0 &&
		    sp->names.v[i][k] == '=' && nth-- == 0)
			return (sp->names.v[i] + k + 1);
	return (NULL);
}

/* gid:sid, both numbers. */
static bool
gidsid_ok(const char *s)
{
	size_t	n;

	if (s == NULL || (n = strspn(s, "0123456789")) == 0 || n > 10 ||
	    s[n] != ':')
		return (false);
	s += n + 1;
	n = strspn(s, "0123456789");
	return (n > 0 && n <= 10 && s[n] == '\0');
}

/* HOME_NET as snort.lua takes it: any, or addresses and $VARS in [ ]. */
static bool
home_net_ok(const char *s)
{

	return (s != NULL && s[0] != '\0' && strlen(s) < 1024 &&
	    strspn(s, "0123456789abcdefABCDEF.:/,[]! $_GHIJKLMNOPQRSTUVWXYZ"
	    "ghijklmnopqrstuvwxyz") == strlen(s));
}

/* An address to fetch rules from: http, https or file, no space. */
static bool
url_ok(const char *s)
{

	if (s == NULL || strlen(s) > 1024 || strpbrk(s, " \t\r\n\"'`\\") !=
	    NULL)
		return (false);
	return (strncmp(s, "https://", 8) == 0 || strncmp(s, "http://",
	    7) == 0 || strncmp(s, "file:///", 8) == 0);
}

/*
 * A rules address with its oinkcode (the console's secret, put in the
 * query) hidden: what is written anywhere, the title, the trace,
 * source.json, has it as oinkcode=... and no more.
 */
static const char *
url_shown(struct work *w, const char *url)
{
	const char	*p, *e;

	if (url == NULL || (p = strstr(url, "oinkcode=")) == NULL)
		return (url);
	e = p + 9 + strcspn(p + 9, "&");
	return (wfmt(w, "%.*s...%s", (int)(p + 9 - url), url, e));
}

/* The same, into a buffer of the caller's. */
static const char *
url_shown_buf(const char *url, char *buf, size_t len)
{
	const char	*p, *e;

	if (url == NULL || (p = strstr(url, "oinkcode=")) == NULL)
		return (url);
	e = p + 9 + strcspn(p + 9, "&");
	snprintf(buf, len, "%.*s...%s", (int)(p + 9 - url), url, e);
	return (buf);
}

const char *
snort_check(const struct arc_job_spec *sp)
{
	const char	*v, *eq;
	size_t		 i;

	if (sp->jail != NULL && sp->jail[0] != '\0')
		return ("Snort is the host's: arcana_snort runs it there");
	if (sp->safe)
		return ("what Snort is given is checked by snort -T first: "
		    "not in safe mode");
	if (sp->verb == NULL)
		return ("a snort job has a verb: set, conf, update or rule");
	for (i = 0; i < sp->names.n; i++)
		if ((eq = strchr(sp->names.v[i], '=')) == NULL ||
		    eq == sp->names.v[i])
			return ("the words of a snort job are key=value");
	if (strcmp(sp->verb, "set") == 0) {
		for (i = 0; i < sp->names.n; i++) {
			v = sp->names.v[i];
			if (strncmp(v, "enable=", 7) == 0) {
				if (strcmp(v + 7, "yes") != 0 &&
				    strcmp(v + 7, "no") != 0)
					return ("enable is yes or no");
			} else if (strncmp(v, "mode=", 5) == 0) {
				if (strcmp(v + 5, "ids") != 0 &&
				    strcmp(v + 5, "ips") != 0)
					return ("mode is ids or ips");
			} else if (strncmp(v, "interface=", 10) == 0) {
				if (v[10] != '\0' && !valid_ifname(v + 10))
					return ("an interface= is an "
					    "interface's name");
			} else if (strncmp(v, "divert_port=", 12) == 0) {
				if (strspn(v + 12, "0123456789") !=
				    strlen(v + 12) || atoi(v + 12) < 1 ||
				    atoi(v + 12) > 65535)
					return ("divert_port is a port, 1 to "
					    "65535");
			} else if (strncmp(v, "home_net=", 9) == 0) {
				if (!home_net_ok(v + 9))
					return ("home_net is any, or "
					    "addresses and $VARIABLES, as in "
					    "[192.0.2.0/24,2001:db8::/32]");
			} else
				return ("set takes enable, mode, interface, "
				    "divert_port and home_net");
		}
		if (sp->names.n == 0)
			return ("set changes something: enable, mode, "
			    "interface, divert_port or home_net");
		return (NULL);
	}
	if (strcmp(sp->verb, "conf") == 0) {
		v = arg(sp, "file", 0);
		if (v == NULL || (strcmp(v, "snort.lua") != 0 &&
		    strcmp(v, "local.rules") != 0))
			return ("conf writes file=snort.lua or file=local.rules");
		if (sp->text == NULL || strlen(sp->text) > TEXT_MAX)
			return ("conf writes text, a megabyte at most");
		if (strcmp(v, "snort.lua") == 0 &&
		    sp->text[strspn(sp->text, " \t\r\n")] == '\0')
			return ("snort.lua is not left empty");
		return (NULL);
	}
	if (strcmp(sp->verb, "update") == 0) {
		v = arg(sp, "url", 0);
		if (v != NULL && v[0] != '\0' && !url_ok(v))
			return ("url is an http, https or file:/// address");
		for (i = 0; i < sp->names.n; i++)
			if (strncmp(sp->names.v[i], "url=", 4) != 0)
				return ("update takes url alone");
		return (NULL);
	}
	if (strcmp(sp->verb, "rule") == 0) {
		if (sp->names.n == 0)
			return ("rule turns rules on=, off= or default= "
			    "(gid:sid)");
		for (i = 0; i < sp->names.n; i++) {
			v = sp->names.v[i];
			eq = strchr(v, '=');
			if ((strncmp(v, "on=", 3) != 0 && strncmp(v, "off=",
			    4) != 0 && strncmp(v, "default=", 8) != 0) ||
			    !gidsid_ok(eq + 1))
				return ("rule turns rules on=, off= or "
				    "default=, each gid:sid (1:2000419)");
		}
		return (NULL);
	}
	return ("a snort job's verb is set, conf, update or rule");
}

char *
snort_title(const struct arc_job_spec *sp)
{
	char	*t, shown[1200];

	if (asprintf(&t, "snort %s%s%s", sp->verb != NULL ? sp->verb : "",
	    sp->names.n > 0 ? " " : "", sp->names.n > 0 ? url_shown_buf(
	    sp->names.v[0], shown, sizeof(shown)) : "") == -1)
		return (NULL);
	return (t);
}

/* ---- Rules ------------------------------------------------------- */

struct rule {
	const char	*action;	/* NULL: not a rule */
	size_t		 actlen;
	bool		 commented;	/* "# alert ...": off as it is */
	unsigned long	 gid, sid, rev;
	char		 msg[256];
	char		 class[64];
};

/*
 * A line as Snort reads a rule: an action, a header, and its options
 * in ( ), each key or key:value; a value in " " may hold a ;.  A rule
 * commented out with # is one too, off.
 */
static bool
rule_parse(const char *line, struct rule *r)
{
	const char	*p, *k, *v;
	size_t		 i, klen, vlen;
	char		 num[16];

	memset(r, 0, sizeof(*r));
	r->gid = 1;
	p = line + strspn(line, " \t");
	if (*p == '#') {
		r->commented = true;
		p += 1 + strspn(p + 1, " \t#");
	}
	for (i = 0; i < nitems(actions); i++)
		if (strncmp(p, actions[i], strlen(actions[i])) == 0 &&
		    (p[strlen(actions[i])] == ' ' ||
		    p[strlen(actions[i])] == '\t'))
			break;
	if (i == nitems(actions) || (p = strchr(p, '(')) == NULL)
		return (false);
	r->action = actions[i];
	p++;
	while (*p != '\0' && *p != ')') {
		p += strspn(p, " \t");
		k = p;
		klen = strcspn(p, ":;) \t");
		p += klen;
		p += strspn(p, " \t");
		v = NULL;
		vlen = 0;
		if (*p == ':') {
			p++;
			p += strspn(p, " \t");
			if (*p == '"') {
				v = ++p;
				while (*p != '\0' && *p != '"') {
					if (*p == '\\' && p[1] != '\0')
						p++;
					p++;
				}
				vlen = (size_t)(p - v);
				if (*p == '"')
					p++;
			} else {
				v = p;
				vlen = strcspn(p, ";)");
				while (vlen > 0 && (v[vlen - 1] == ' ' ||
				    v[vlen - 1] == '\t'))
					vlen--;
			}
			p += strcspn(p, ";)");
		}
		if (*p == ';')
			p++;
		if (v == NULL)
			continue;
		if (klen == 3 && (strncmp(k, "sid", 3) == 0 ||
		    strncmp(k, "gid", 3) == 0 || strncmp(k, "rev", 3) == 0)) {
			snprintf(num, sizeof(num), "%.*s", (int)MIN(vlen, 15),
			    v);
			if (k[0] == 's')
				r->sid = strtoul(num, NULL, 10);
			else if (k[0] == 'g')
				r->gid = strtoul(num, NULL, 10);
			else
				r->rev = strtoul(num, NULL, 10);
		} else if (klen == 3 && strncmp(k, "msg", 3) == 0)
			snprintf(r->msg, sizeof(r->msg), "%.*s", (int)vlen, v);
		else if (klen == 9 && strncmp(k, "classtype", 9) == 0)
			snprintf(r->class, sizeof(r->class), "%.*s",
			    (int)vlen, v);
	}
	return (r->sid != 0);
}

/* rule-state: "gid:sid on" or "gid:sid off", a line each. */
static ucl_object_t *
state_load(struct work *w)
{
	ucl_object_t	*o;
	const char	*text;
	char		*copy, *it, *line, *sp;

	o = ucl_object_typed_new(UCL_OBJECT);
	if ((text = slurp_file(w, sn_dir(w, "rule-state"), TEXT_MAX)) ==
	    NULL)
		return (o);
	copy = wstrdup(w, text);
	for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
		if ((sp = strchr(line, ' ')) == NULL)
			continue;
		*sp++ = '\0';
		if (gidsid_ok(line) && (strcmp(sp, "on") == 0 ||
		    strcmp(sp, "off") == 0))
			ucl_object_replace_key(o, ucl_object_frombool(
			    sp[1] == 'n'), line, 0, true);
	}
	return (o);
}

/* What the state says of a rule: 1 on, 0 off, -1 as shipped. */
static int
state_of(const ucl_object_t *st, const struct rule *r)
{
	const ucl_object_t	*e;
	char			 key[32];

	snprintf(key, sizeof(key), "%lu:%lu", r->gid, r->sid);
	if ((e = ucl_object_lookup(st, key)) == NULL)
		return (-1);
	return (ucl_object_toboolean(e) ? 1 : 0);
}

/* Write path from text, by a new file renamed over it. */
static int
put_file(struct work *w, const char *path, const char *text, size_t len,
    const char **errp)
{
	const char	*tmp;
	int		 fd;
	bool		 ok;

	tmp = wfmt(w, "%s.arcana-new", path);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
	    0644)) == -1) {
		*errp = wfmt(w, "%s: %s", tmp, strerror(errno));
		return (-1);
	}
	ok = (size_t)write(fd, text, len) == len;
	ok = close(fd) == 0 && ok;
	ok = ok && rename(tmp, path) == 0;
	if (!ok) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		(void)unlink(tmp);
		return (-1);
	}
	return (0);
}

static bool
is_rules_name(const char *name)
{
	size_t	n;

	n = strlen(name);
	return (n > 6 && n < 128 && strcmp(name + n - 6, ".rules") == 0 &&
	    name[0] != '.' && strchr(name, '/') == NULL);
}

/* The *.rules of dir, sorted. */
static size_t
rules_files(struct work *w, const char *dir, const char ***namesp)
{
	DIR		 *d;
	struct dirent	 *de;
	const char	**v;
	size_t		  n, i, j;

	v = wcalloc(w, FILES_MAX, sizeof(*v));
	n = 0;
	if ((d = opendir(dir)) != NULL) {
		while ((de = readdir(d)) != NULL && n < FILES_MAX)
			if (is_rules_name(de->d_name))
				v[n++] = wstrdup(w, de->d_name);
		closedir(d);
	}
	for (i = 1; i < n; i++)
		for (j = i; j > 0 && strcmp(v[j - 1], v[j]) > 0; j--) {
			const char *t = v[j];

			v[j] = v[j - 1];
			v[j - 1] = t;
		}
	*namesp = v;
	return (n);
}

/* Take dir and what is in it away: files, one level. */
static void
rm_dir(struct work *w, const char *dir)
{
	DIR		*d;
	struct dirent	*de;

	if ((d = opendir(dir)) != NULL) {
		while ((de = readdir(d)) != NULL)
			if (strcmp(de->d_name, ".") != 0 &&
			    strcmp(de->d_name, "..") != 0)
				(void)unlink(wfmt(w, "%s/%s", dir, de->d_name));
		closedir(d);
	}
	(void)rmdir(dir);
}

/*
 * The active files, made in out from the downloaded ones of in, each
 * rule on or off as the state says, else as it came; and the top file,
 * top, including them and local.rules.
 */
static int
make_active(struct work *w, const char *in, const char *out,
    const char *incdir, const char *top, const ucl_object_t *st,
    const char **errp)
{
	const char	**names, *text;
	struct rule	  r;
	char		 *copy, *it, *line, *buf;
	size_t		  n, i, len, cap, l;
	int		  want;

	rm_dir(w, out);
	if (mkdir(out, 0755) == -1) {
		*errp = wfmt(w, "%s: %s", out, strerror(errno));
		return (-1);
	}
	n = rules_files(w, in, &names);
	cap = 4096;
	buf = wcalloc(w, 1, cap);
	len = 0;
	for (i = 0; i < n; i++) {
		size_t	 fcap, flen;
		char	*fbuf;

		if ((text = slurp_file(w, wfmt(w, "%s/%s", in, names[i]),
		    ARCHIVE_MAX)) == NULL)
			continue;
		fcap = strlen(text) + 4096;
		fbuf = wcalloc(w, 1, fcap);
		flen = 0;
		copy = wstrdup(w, text);
		for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
			const char	*body = line;

			if (it == NULL && line[0] == '\0')
				break;
			if (rule_parse(line, &r) &&
			    (want = state_of(st, &r)) != -1) {
				if (want == 1 && r.commented)
					body = line + strspn(line, " \t#");
				else if (want == 0 && !r.commented)
					body = wfmt(w, "# %s", line);
			}
			l = strlen(body);
			if (flen + l + 2 > fcap) {
				char *nb;

				fcap = (flen + l + 2) * 2;
				nb = wcalloc(w, 1, fcap);
				memcpy(nb, fbuf, flen);
				fbuf = nb;
			}
			memcpy(fbuf + flen, body, l);
			flen += l;
			fbuf[flen++] = '\n';
		}
		if (put_file(w, wfmt(w, "%s/%s", out, names[i]), fbuf, flen,
		    errp) != 0)
			return (-1);
		line = wfmt(w, "include %s/%s\n", incdir, names[i]);
		l = strlen(line);
		if (len + l + 1 > cap) {
			char *nb;

			cap = (len + l + 1) * 2;
			nb = wcalloc(w, 1, cap);
			memcpy(nb, buf, len);
			buf = nb;
		}
		memcpy(buf + len, line, l);
		len += l;
	}
	if (access(sn_local(w), R_OK) == 0) {
		line = wfmt(w, "include %s\n", sn_local(w));
		buf = wfmt(w, "%.*s%s", (int)len, buf, line);
		len = strlen(buf);
	}
	return (put_file(w, top, wfmt(w, "# Made by Arcana: the rules it "
	    "takes in and local.rules.\n%.*s", (int)len, buf), strlen(
	    "# Made by Arcana: the rules it takes in and local.rules.\n") +
	    len, errp));
}

/* snort -T: what Snort makes of lua with the rules of top. */
static int
snort_test(struct work *w, const char *lua, const char *top,
    const char **errp)
{
	struct execres	 res;
	char		*argv[10], *e, *line, *it, *keep;
	int		 n, step;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.snort_bin;
	argv[n++] = (char *)(uintptr_t)"-c";
	argv[n++] = (char *)(uintptr_t)lua;
	if (top != NULL && access(top, R_OK) == 0) {
		argv[n++] = (char *)(uintptr_t)"-R";
		argv[n++] = (char *)(uintptr_t)top;
	}
	argv[n++] = (char *)(uintptr_t)"-T";
	argv[n++] = (char *)(uintptr_t)"-q";
	argv[n] = NULL;
	step = step_begin(w, ARC_STEP_KIND_EXEC, "snort -T",
	    "the configuration and rules checked");
	if (run_exec(w, argv, &res) == 0) {
		step_end(w, step, true, NULL);
		return (0);
	}
	/* Its ERROR lines say what; FATAL only that there were some. */
	keep = NULL;
	e = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
	e = wfmt(w, "%s\n%.*s", e, (int)res.errlen, res.err != NULL ?
	    res.err : "");
	for (it = e; (line = strsep(&it, "\n")) != NULL; )
		if (strncmp(line, "ERROR", 5) == 0)
			keep = keep == NULL ? wstrdup(w, line) : wfmt(w,
			    "%s; %s", keep, line);
	*errp = keep != NULL ? wfmt(w, "snort does not take it: %.900s",
	    keep) : wtext(w, exec_error(w, &res, "snort"));
	step_end(w, step, false, "%s", *errp);
	return (-1);
}

/* ---- Running ------------------------------------------------------ */

static long
snort_pid(struct work *w)
{
	const char	*t;
	long		 pid;

	t = slurp_file(w, wfmt(w, "%s/snort.pid", opts.snort_log), 64);
	if (t == NULL || (pid = strtol(t, NULL, 10)) <= 1)
		return (0);
	return (kill((pid_t)pid, 0) == 0 || errno == EPERM ? pid : 0);
}

/* A running Snort reads its configuration and rules again. */
static void
snort_reload(struct work *w)
{
	long	pid;
	int	step;

	if ((pid = snort_pid(w)) == 0)
		return;
	step = step_begin(w, ARC_STEP_KIND_SYSCALL, wfmt(w, "snort %ld", pid),
	    "SIGHUP: the rules and configuration read again");
	if (kill((pid_t)pid, SIGHUP) == 0)
		step_end(w, step, true, NULL);
	else
		step_end(w, step, false, "%s", strerror(errno));
}

/* ---- The job ------------------------------------------------------ */

/* The active files and the top file made again, checked, swapped in. */
static int
rebuild(struct work *w, const char *dl, const ucl_object_t *st,
    const char **errp)
{
	const char	*act, *anew, *aold, *top, *tnew;

	act = sn_dir(w, "active");
	anew = sn_dir(w, "active.new");
	aold = sn_dir(w, "active.old");
	top = sn_dir(w, "arcana.rules");
	tnew = sn_dir(w, "arcana.rules.check");
	if (make_active(w, dl, anew, anew, tnew, st, errp) != 0 ||
	    snort_test(w, sn_lua(w), tnew, errp) != 0) {
		rm_dir(w, anew);
		(void)unlink(tnew);
		return (-1);
	}
	(void)unlink(tnew);
	/* Made again pointing where they will be, then swapped in. */
	rm_dir(w, aold);
	if (make_active(w, dl, anew, act, tnew, st, errp) != 0)
		return (-1);
	(void)rename(act, aold);
	if (rename(anew, act) != 0 || rename(tnew, top) != 0) {
		*errp = wfmt(w, "%s: %s", act, strerror(errno));
		(void)rename(aold, act);
		return (-1);
	}
	rm_dir(w, aold);
	return (0);
}

static int
sn_set(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const char	*v, *text, *ifs, *p;
	char		*copy, *nl;
	size_t		 i;
	int		 step;

	if ((v = arg(sp, "home_net", 0)) != NULL) {
		/* snort.lua's HOME_NET = '...' line, checked as a whole. */
		if ((text = slurp_file(w, sn_lua(w), TEXT_MAX)) == NULL) {
			*errp = wfmt(w, "%s: %s", sn_lua(w), strerror(errno));
			return (-1);
		}
		for (p = text; p != NULL; p = (nl = strchr(p, '\n')) != NULL ?
		    nl + 1 : NULL)
			if (strncmp(p, "HOME_NET", 8) == 0 && (p[8] == ' ' ||
			    p[8] == '='))
				break;
		if (p == NULL) {
			*errp = wfmt(w, "%s has no HOME_NET = line at the start "
			    "of one", sn_lua(w));
			return (-1);
		}
		nl = strchr(p, '\n');
		copy = wfmt(w, "%.*sHOME_NET = '%s'%s", (int)(p - text), text,
		    v, nl != NULL ? nl : "\n");
		step = step_begin(w, ARC_STEP_KIND_FILE, sn_lua(w),
		    "HOME_NET = '%s'", v);
		if (put_file(w, wfmt(w, "%s.check.lua", sn_lua(w)), copy,
		    strlen(copy), errp) != 0 || snort_test(w, wfmt(w,
		    "%s.check.lua", sn_lua(w)), sn_dir(w, "arcana.rules"),
		    errp) != 0 || rename(wfmt(w, "%s.check.lua", sn_lua(w)),
		    sn_lua(w)) != 0) {
			(void)unlink(wfmt(w, "%s.check.lua", sn_lua(w)));
			if (*errp == NULL)
				*errp = wfmt(w, "%s: %s", sn_lua(w),
				    strerror(errno));
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
		step_end(w, step, true, NULL);
		snort_reload(w);
	}
	if ((v = arg(sp, "enable", 0)) != NULL && rc_set(w,
	    "arcana_snort_enable", "=", strcmp(v, "yes") == 0 ? "YES" : "NO",
	    errp) != 0)
		return (-1);
	if ((v = arg(sp, "mode", 0)) != NULL && rc_set(w, "arcana_snort_mode",
	    "=", v, errp) != 0)
		return (-1);
	if ((v = arg(sp, "divert_port", 0)) != NULL && rc_set(w,
	    "arcana_snort_divert_port", "=", v, errp) != 0)
		return (-1);
	/* The interfaces as a whole: those given, none when one is empty. */
	if (arg(sp, "interface", 0) != NULL) {
		ifs = "";
		for (i = 0; (v = arg(sp, "interface", i)) != NULL; i++)
			if (v[0] != '\0')
				ifs = ifs[0] == '\0' ? v : wfmt(w, "%s %s",
				    ifs, v);
		if (ifs[0] == '\0')
			rc_unset(w, "arcana_snort_interfaces");
		else if (rc_set(w, "arcana_snort_interfaces", "=", ifs,
		    errp) != 0)
			return (-1);
	}
	return (0);
}

static int
sn_conf(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const char	*file, *path, *check, *top;
	size_t		 len;
	int		 step;
	bool		 lua;

	file = arg(sp, "file", 0);
	lua = strcmp(file, "snort.lua") == 0;
	path = lua ? sn_lua(w) : sn_local(w);
	len = strlen(sp->text);
	step = step_begin(w, ARC_STEP_KIND_FILE, path, "written, %zu bytes",
	    len);
	(void)mkdir(sn_dir(w, NULL), 0755);
	if (lua) {
		check = wfmt(w, "%s.check.lua", path);
		top = sn_dir(w, "arcana.rules");
	} else {
		/* local.rules beside the rules taken in, as -R has them. */
		check = sn_dir(w, "local.rules.check");
		top = sn_dir(w, "arcana.rules.check");
	}
	if (put_file(w, check, sp->text, len, errp) != 0)
		goto fail;
	if (!lua) {
		const char	*cur, *mine;
		char		*t, *copy, *it, *line;

		/* The rules as they are, the new local.rules for the old. */
		cur = slurp_file(w, sn_dir(w, "arcana.rules"), TEXT_MAX);
		mine = wfmt(w, "include %s", path);
		t = wstrdup(w, "");
		copy = wstrdup(w, cur != NULL ? cur : "");
		for (it = copy; (line = strsep(&it, "\n")) != NULL; )
			if (line[0] != '\0' && strcmp(line, mine) != 0)
				t = wfmt(w, "%s%s\n", t, line);
		t = wfmt(w, "%sinclude %s\n", t, check);
		if (put_file(w, top, t, strlen(t), errp) != 0)
			goto fail;
	}
	if (snort_test(w, lua ? check : sn_lua(w), top, errp) != 0)
		goto fail;
	if (rename(check, path) != 0) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		goto fail;
	}
	step_end(w, step, true, NULL);
	if (!lua) {
		(void)unlink(top);
		/* The top file includes local.rules from now on. */
		if (rebuild(w, sn_dir(w, "rules"), state_load(w), errp) != 0)
			return (-1);
	}
	snort_reload(w);
	return (0);
fail:
	(void)unlink(check);
	if (!lua)
		(void)unlink(top);
	step_end(w, step, false, "%s", *errp);
	return (-1);
}

/* Each *.rules under dir, to depth levels, copied into out. */
static int
gather(struct work *w, const char *dir, const char *out, int depth,
    size_t *np, const char **errp)
{
	DIR		*d;
	struct dirent	*de;
	struct stat	 st;
	const char	*p, *text;

	if (depth < 0 || (d = opendir(dir)) == NULL)
		return (0);
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		p = wfmt(w, "%s/%s", dir, de->d_name);
		if (lstat(p, &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			if (gather(w, p, out, depth - 1, np, errp) != 0) {
				closedir(d);
				return (-1);
			}
		} else if (S_ISREG(st.st_mode) && is_rules_name(de->d_name) &&
		    *np < FILES_MAX) {
			if ((text = slurp_file(w, p, ARCHIVE_MAX)) == NULL ||
			    put_file(w, wfmt(w, "%s/%s", out, de->d_name),
			    text, strlen(text), errp) != 0) {
				closedir(d);
				if (*errp == NULL)
					*errp = wfmt(w, "%s: %s", p,
					    strerror(errno));
				return (-1);
			}
			(*np)++;
		}
	}
	closedir(d);
	return (0);
}

/* url fetched into path by libfetch, its sha256 in hex. */
static int
sn_fetch(struct work *w, const char *url, const char *path, char *hex,
    const char **errp)
{
	FILE		*f;
	EVP_MD_CTX	*ctx;
	unsigned char	 buf[65536], md[EVP_MAX_MD_SIZE];
	unsigned int	 mdlen, i;
	size_t		 n, total;
	int		 fd, step;
	bool		 ok;

	step = step_begin(w, ARC_STEP_KIND_LIB, "libfetch fetchGetURL()",
	    "%s", url_shown(w, url));
	pthread_mutex_lock(&sn_fetch_lock);
	fetchTimeout = FETCH_WAIT_S;
	f = fetchGetURL(url, "");
	if (f == NULL) {
		*errp = wfmt(w, "%s: %s", url_shown(w, url), fetchLastErrString);
		pthread_mutex_unlock(&sn_fetch_lock);
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	pthread_mutex_unlock(&sn_fetch_lock);
	if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
	    0600)) == -1) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		fclose(f);
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	ctx = EVP_MD_CTX_new();
	ok = ctx != NULL && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
	total = 0;
	while (ok && (n = fread(buf, 1, sizeof(buf), f)) > 0) {
		total += n;
		ok = total <= ARCHIVE_MAX && (size_t)write(fd, buf, n) == n &&
		    EVP_DigestUpdate(ctx, buf, n) == 1;
	}
	ok = ok && !ferror(f) && total > 0;
	ok = ok && EVP_DigestFinal_ex(ctx, md, &mdlen) == 1;
	EVP_MD_CTX_free(ctx);
	fclose(f);
	ok = close(fd) == 0 && ok;
	if (!ok) {
		*errp = total > ARCHIVE_MAX ? wfmt(w, "%s: more than %d MB",
		    url_shown(w, url), ARCHIVE_MAX >> 20) : total == 0 ? wfmt(w,
		    "%s: nothing came", url_shown(w, url)) : wfmt(w, "%s: %s",
		    url_shown(w, url), strerror(errno));
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	for (i = 0; i < mdlen && i < 32; i++)
		snprintf(hex + 2 * i, 3, "%02x", md[i]);
	step_end(w, step, true, NULL);
	return (0);
}

static int
sn_update(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct execres	 res;
	ucl_object_t	*src;
	const char	*url, *tmp, *got, *dl, *dnew, *dold, *t, *tar;
	char		*argv[8], hex[65], *json;
	size_t		 n;
	int		 rc;

	url = arg(sp, "url", 0);
	if (url == NULL || url[0] == '\0') {
		/* The last one, else Snort's community rules. */
		const ucl_object_t	*o;
		ucl_object_t		*old;

		url = COMMUNITY_URL;
		t = slurp_file(w, sn_dir(w, "source.json"), 65536);
		if (t != NULL && (old = json_parse_w(w, t)) != NULL) {
			if ((o = ucl_object_lookup(old, "url")) != NULL &&
			    url_ok(ucl_object_tostring(o)))
				url = wstrdup(w, ucl_object_tostring(o));
			ucl_object_unref(old);
		}
	}
	(void)mkdir(sn_dir(w, NULL), 0755);
	tmp = sn_dir(w, "fetch.tmp");
	rm_dir(w, wfmt(w, "%s/x", tmp));
	rm_dir(w, tmp);
	if (mkdir(tmp, 0700) == -1 || mkdir(wfmt(w, "%s/x", tmp), 0700) ==
	    -1) {
		*errp = wfmt(w, "%s: %s", tmp, strerror(errno));
		return (-1);
	}
	got = wfmt(w, "%s/x/%s", tmp, strlen(url) > 6 && strcmp(url +
	    strlen(url) - 6, ".rules") == 0 ? "fetched.rules" : "../archive");
	rc = -1;
	dl = sn_dir(w, "rules");
	dnew = sn_dir(w, "rules.new");
	dold = sn_dir(w, "rules.old");
	if (sn_fetch(w, url, got, hex, errp) != 0)
		goto out;
	if (strstr(got, "archive") != NULL) {
		/* tar(1) knows the compression by itself. */
		if ((tar = tool(w, "tar")) == NULL) {
			*errp = "the host has no tar";
			goto out;
		}
		argv[0] = (char *)(uintptr_t)tar;
		argv[1] = (char *)(uintptr_t)"-xf";
		argv[2] = (char *)(uintptr_t)got;
		argv[3] = (char *)(uintptr_t)"-C";
		argv[4] = wfmt(w, "%s/x", tmp);
		argv[5] = (char *)(uintptr_t)"--no-same-owner";
		argv[6] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			*errp = wfmt(w, "%s is not an archive tar takes: %s",
			    url_shown(w, url), exec_error(w, &res, "tar"));
			goto out;
		}
	}
	rm_dir(w, dnew);
	if (mkdir(dnew, 0755) == -1) {
		*errp = wfmt(w, "%s: %s", dnew, strerror(errno));
		goto out;
	}
	n = 0;
	*errp = NULL;
	if (gather(w, wfmt(w, "%s/x", tmp), dnew, 4, &n, errp) != 0)
		goto out;
	if (n == 0) {
		*errp = wfmt(w, "%s has no *.rules file", url_shown(w, url));
		goto out;
	}
	/* Checked with these, then they are the downloaded ones. */
	if (rebuild(w, dnew, state_load(w), errp) != 0)
		goto out;
	rm_dir(w, dold);
	(void)rename(dl, dold);
	if (rename(dnew, dl) != 0) {
		*errp = wfmt(w, "%s: %s", dl, strerror(errno));
		(void)rename(dold, dl);
		goto out;
	}
	rm_dir(w, dold);
	/* The active files were made from rules.new: again from rules. */
	if (rebuild(w, dl, state_load(w), errp) != 0)
		goto out;
	src = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(src, ucl_object_fromstring(url_shown(w, url)),
	    "url", 0, false);
	ucl_object_insert_key(src, ucl_object_fromint((int64_t)time(NULL)),
	    "updated", 0, false);
	ucl_object_insert_key(src, ucl_object_fromstring(hex), "sha256", 0,
	    false);
	json = (char *)ucl_object_emit(src, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(src);
	if (json != NULL) {
		(void)put_file(w, sn_dir(w, "source.json"), json, strlen(json),
		    errp);
		free(json);
	}
	*errp = NULL;
	snort_reload(w);
	rc = 0;
out:
	rm_dir(w, dnew);
	(void)unlink(wfmt(w, "%s/archive", tmp));
	{
		/* What tar made, to any depth: by rm -rf, it is ours. */
		const char	*rm = tool(w, "rm");

		if (rm != NULL) {
			argv[0] = (char *)(uintptr_t)rm;
			argv[1] = (char *)(uintptr_t)"-rf";
			argv[2] = (char *)(uintptr_t)tmp;
			argv[3] = NULL;
			(void)run_exec(w, argv, &res);
		}
	}
	return (rc);
}

static int
sn_rule(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	ucl_object_t		*st;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*v, *key, *text;
	size_t			 i;

	st = state_load(w);
	for (i = 0; i < sp->names.n; i++) {
		v = sp->names.v[i];
		key = strchr(v, '=') + 1;
		if (strncmp(v, "default=", 8) == 0)
			ucl_object_delete_key(st, key);
		else
			ucl_object_replace_key(st, ucl_object_frombool(v[1] ==
			    'n'), key, 0, true);
	}
	if (rebuild(w, sn_dir(w, "rules"), st, errp) != 0) {
		ucl_object_unref(st);
		return (-1);
	}
	text = "";
	it = NULL;
	while ((e = ucl_object_iterate(st, &it, true)) != NULL)
		text = wfmt(w, "%s%s %s\n", text, ucl_object_key(e),
		    ucl_object_toboolean(e) ? "on" : "off");
	ucl_object_unref(st);
	if (put_file(w, sn_dir(w, "rule-state"), text, strlen(text),
	    errp) != 0)
		return (-1);
	snort_reload(w);
	return (0);
}

/*
 * The rc.d script arcana_snort, as the agent's build has it (the
 * Makefile puts arcana_snort.sh into snort_rc.c): written into the
 * last of the rc directories when it is not there or differs, so that
 * a host whose agent came by agent-update, the binary alone, has it
 * too.  Quiet when it cannot be written: the service start then says
 * what is missing.
 */
void
snort_rc_install(struct work *w)
{
	const char	*dirs, *p;
	char		 dir[PATH_MAX], path[PATH_MAX], tmp[PATH_MAX];
	char		*have;
	struct stat	 sb;
	size_t		 n;
	ssize_t		 got;
	int		 fd;

	(void)w;
	dirs = opts.rc_dirs;
	p = strrchr(dirs, ':');
	snprintf(dir, sizeof(dir), "%s", p != NULL ? p + 1 : dirs);
	if (dir[0] == '\0')
		return;
	snprintf(path, sizeof(path), "%s/arcana_snort", dir);
	n = strlen(snort_rc_text);
	/* As it is, nothing to do. */
	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) != -1) {
		if (fstat(fd, &sb) == 0 && (size_t)sb.st_size == n && (have =
		    malloc(n + 1)) != NULL) {
			got = read(fd, have, n);
			have[got > 0 ? got : 0] = '\0';
			if (got == (ssize_t)n && memcmp(have, snort_rc_text, n) == 0) {
				free(have);
				close(fd);
				return;
			}
			free(have);
		}
		close(fd);
	}
	snprintf(tmp, sizeof(tmp), "%s.new", path);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0555)) ==
	    -1)
		return;
	if (write(fd, snort_rc_text, n) != (ssize_t)n || fchmod(fd, 0555) != 0 ||
	    close(fd) != 0 || rename(tmp, path) != 0) {
		(void)unlink(tmp);
		return;
	}
}

int
do_snort_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{

	if ((*errp = snort_check(sp)) != NULL)
		return (-1);
	if (access(opts.snort_bin, X_OK) != 0) {
		*errp = wfmt(w, "the host has no snort (%s): it is a plugin, "
		    "pkg install snort3", opts.snort_bin);
		return (-1);
	}
	snort_rc_install(w);
	if (strcmp(sp->verb, "set") == 0)
		return (sn_set(w, sp, errp));
	if (strcmp(sp->verb, "conf") == 0)
		return (sn_conf(w, sp, errp));
	if (strcmp(sp->verb, "update") == 0)
		return (sn_update(w, sp, errp));
	return (sn_rule(w, sp, errp));
}

/* ---- The read ----------------------------------------------------- */

/* Each rules file's rules, counted, and listed when list is given. */
static ucl_object_t *
files_read(struct work *w, const char *dir, const ucl_object_t *st,
    ucl_object_t *list, int64_t *totalp, int64_t *onp)
{
	ucl_object_t	*arr, *f, *r;
	const char	**names, *text;
	struct rule	  ru;
	char		 *copy, *it, *line;
	size_t		  n, i;
	int64_t		  rules, on;
	int		  want;
	bool		  is_on;

	arr = ucl_object_typed_new(UCL_ARRAY);
	n = rules_files(w, dir, &names);
	for (i = 0; i <= n; i++) {
		const char *name = i < n ? names[i] : "local.rules";

		/* local.rules last, as written: no state of its own. */
		text = slurp_file(w, i < n ? wfmt(w, "%s/%s", dir, names[i]) :
		    sn_local(w), ARCHIVE_MAX);
		if (text == NULL)
			continue;
		rules = on = 0;
		copy = wstrdup(w, text);
		for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
			if (!rule_parse(line, &ru))
				continue;
			want = i < n ? state_of(st, &ru) : -1;
			is_on = want == -1 ? !ru.commented : want == 1;
			rules++;
			on += is_on;
			if (list == NULL)
				continue;
			r = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(r, ucl_object_fromint(
			    (int64_t)ru.gid), "gid", 0, false);
			ucl_object_insert_key(r, ucl_object_fromint(
			    (int64_t)ru.sid), "sid", 0, false);
			ucl_object_insert_key(r, ucl_object_fromint(
			    (int64_t)ru.rev), "rev", 0, false);
			ucl_object_insert_key(r, ucl_object_fromstring(ru.msg),
			    "msg", 0, false);
			ucl_object_insert_key(r, ucl_object_fromstring(
			    ru.action), "action", 0, false);
			ucl_object_insert_key(r, ucl_object_fromstring(
			    ru.class), "class", 0, false);
			ucl_object_insert_key(r, ucl_object_fromstring(name),
			    "file", 0, true);
			ucl_object_insert_key(r, ucl_object_frombool(is_on),
			    "on", 0, false);
			ucl_object_insert_key(r, ucl_object_frombool(
			    !ru.commented), "default", 0, false);
			ucl_array_append(list, r);
		}
		if (i == n)
			break;
		f = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(f, ucl_object_fromstring(name), "name",
		    0, true);
		ucl_object_insert_key(f, ucl_object_fromint(rules), "rules", 0,
		    false);
		ucl_object_insert_key(f, ucl_object_fromint(on), "on", 0,
		    false);
		ucl_array_append(arr, f);
		*totalp += rules;
		*onp += on;
	}
	return (arr);
}

/* The newest alerts of alert_json.txt, newest first. */
static ucl_object_t *
alerts_read(struct work *w)
{
	ucl_object_t	*arr, *o;
	const char	*path;
	struct stat	 st;
	char		*buf, *line, *p;
	ssize_t		 got;
	off_t		 off;
	int		 fd, n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	path = wfmt(w, "%s/alert_json.txt", opts.snort_log);
	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
		return (arr);
	if (fstat(fd, &st) != 0) {
		close(fd);
		return (arr);
	}
	off = st.st_size > ALERTS_TAIL ? st.st_size - ALERTS_TAIL : 0;
	buf = wcalloc(w, 1, ALERTS_TAIL + 1);
	got = pread(fd, buf, ALERTS_TAIL, off);
	close(fd);
	if (got <= 0)
		return (arr);
	buf[got] = '\0';
	/* From the end back, a line at a time; a cut first line is not. */
	n = 0;
	while (n < ALERTS_MAX && (p = strrchr(buf, '\n')) != NULL) {
		*p = '\0';
		line = p[1] != '\0' ? p + 1 : NULL;
		if (line != NULL && line[0] == '{' && (o = json_parse_w(w,
		    line)) != NULL) {
			ucl_array_append(arr, o);
			n++;
		}
		if (p == buf)
			break;
	}
	if (n < ALERTS_MAX && off == 0 && buf[0] == '{' && (o = json_parse_w(w,
	    buf)) != NULL)
		ucl_array_append(arr, o);
	return (arr);
}

/* snort.lua's HOME_NET = '...', as written. */
static const char *
home_net(struct work *w, const char *lua)
{
	const char	*p, *q, *e;

	for (p = lua; p != NULL; p = (p = strchr(p, '\n')) != NULL ? p + 1 :
	    NULL)
		if (strncmp(p, "HOME_NET", 8) == 0 && (p[8] == ' ' ||
		    p[8] == '='))
			break;
	if (p == NULL || (q = strpbrk(p, "'\"\n")) == NULL || *q == '\n')
		return (NULL);
	if ((e = strchr(q + 1, *q)) == NULL)
		return (NULL);
	return (wstrndup(w, q + 1, (size_t)(e - q - 1)));
}

/* What keeps Snort from doing as rc.conf says. */
static void
warnings(struct work *w, ucl_object_t *top, const char *mode,
    const char *ifs, const char *port, bool enabled, bool running)
{
	struct execres	 res;
	ucl_object_t	*arr;
	char		*argv[3], *copy, *it, *ifn;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (enabled && !running)
		ucl_array_append(arr, ucl_object_fromstring("enabled, not "
		    "running: start it (service arcana_snort start)"));
	if (strcmp(mode, "ips") == 0) {
		argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
		argv[1] = (char *)(uintptr_t)"list";
		argv[2] = NULL;
		if (run_exec(w, argv, &res) == 0 && (res.out == NULL ||
		    strstr(wstrndup(w, res.out, res.outlen), wfmt(w,
		    " divert %s ", port)) == NULL))
			ucl_array_append(arr, ucl_object_fromstring(wfmt(w,
			    "inline, and no ipfw rule diverts to port %s: "
			    "nothing reaches Snort (add one in Firewall, "
			    "divert %s ip from any to any via <interface>)",
			    port, port)));
	} else {
		if (ifs[0] == '\0' && enabled)
			ucl_array_append(arr, ucl_object_fromstring("watching "
			    "no interface: pick one"));
		copy = wstrdup(w, ifs);
		for (it = copy; (ifn = strsep(&it, " ")) != NULL; )
			if (ifn[0] != '\0' && !if_exists(w, ifn))
				ucl_array_append(arr, ucl_object_fromstring(
				    wfmt(w, "no interface %s here", ifn)));
	}
	if (access(sn_dir(w, "arcana.rules"), R_OK) != 0)
		ucl_array_append(arr, ucl_object_fromstring("no rules taken "
		    "in yet: update them"));
	ucl_object_insert_key(top, arr, "warnings", 0, false);
}

void
do_snort(struct work *w, const char *const *names, size_t nnames,
    struct arc_snort_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *rc, *src, *list;
	const char	*t, *lua, *mode, *ifs, *port, *en, *hn;
	char		*argv[3], *json, *p;
	int64_t		 total, on;
	long		 pid;
	size_t		 i;
	bool		 with_rules, installed;

	with_rules = false;
	for (i = 0; i < nnames; i++)
		if (strcmp(names[i], "rules") == 0)
			with_rules = true;
	top = ucl_object_typed_new(UCL_OBJECT);
	installed = access(opts.snort_bin, X_OK) == 0;
	ucl_object_insert_key(top, ucl_object_frombool(installed),
	    "installed", 0, false);
	ucl_object_insert_key(top, ucl_object_fromstring(opts.snort_bin),
	    "program", 0, false);
	if (installed) {
		argv[0] = (char *)(uintptr_t)opts.snort_bin;
		argv[1] = (char *)(uintptr_t)"-V";
		argv[2] = NULL;
		if (run_exec(w, argv, &res) == 0 && res.out != NULL &&
		    (p = strstr(wstrndup(w, res.out, res.outlen),
		    "Version ")) != NULL)
			ucl_object_insert_key(top, ucl_object_fromlstring(p +
			    8, strcspn(p + 8, " \n")), "version", 0, false);
	}
	pid = snort_pid(w);
	ucl_object_insert_key(top, ucl_object_frombool(pid != 0), "running",
	    0, false);
	if (pid != 0)
		ucl_object_insert_key(top, ucl_object_fromint(pid), "pid", 0,
		    false);
	/* rc.conf's, as arcana_snort reads them, its defaults else. */
	en = rc_get(w, "arcana_snort_enable");
	mode = rc_get(w, "arcana_snort_mode");
	ifs = rc_get(w, "arcana_snort_interfaces");
	port = rc_get(w, "arcana_snort_divert_port");
	mode = mode != NULL && strcmp(mode, "ips") == 0 ? "ips" : "ids";
	ifs = ifs != NULL ? ifs : "";
	port = port != NULL ? port : "8000";
	rc = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(rc, ucl_object_frombool(en != NULL &&
	    (strcasecmp(en, "yes") == 0 || strcasecmp(en, "true") == 0 ||
	    strcasecmp(en, "on") == 0 || strcmp(en, "1") == 0)), "enable", 0,
	    false);
	ucl_object_insert_key(rc, ucl_object_fromstring(mode), "mode", 0,
	    false);
	ucl_object_insert_key(rc, ucl_object_fromstring(ifs), "interfaces", 0,
	    false);
	ucl_object_insert_key(rc, ucl_object_fromstring(port), "divert_port",
	    0, false);
	warnings(w, top, mode, ifs, port, ucl_object_toboolean(
	    ucl_object_lookup(rc, "enable")), pid != 0);
	ucl_object_insert_key(top, rc, "rc", 0, false);
	lua = slurp_file(w, sn_lua(w), TEXT_MAX);
	ucl_object_insert_key(top, ucl_object_fromstring(sn_lua(w)),
	    "conf_file", 0, false);
	ucl_object_insert_key(top, ucl_object_fromstring(lua != NULL ? lua :
	    ""), "snort_lua", 0, false);
	if (lua != NULL && (hn = home_net(w, lua)) != NULL)
		ucl_object_insert_key(top, ucl_object_fromstring(hn),
		    "home_net", 0, false);
	t = slurp_file(w, sn_local(w), TEXT_MAX);
	ucl_object_insert_key(top, ucl_object_fromstring(t != NULL ? t : ""),
	    "local_rules", 0, false);
	/* Where the rules came from, each file with its count. */
	t = slurp_file(w, sn_dir(w, "source.json"), 65536);
	src = t != NULL ? json_parse_w(w, t) : NULL;
	if (src == NULL)
		src = ucl_object_typed_new(UCL_OBJECT);
	if (ucl_object_lookup(src, "url") == NULL)
		ucl_object_insert_key(src, ucl_object_fromstring(
		    COMMUNITY_URL), "default_url", 0, false);
	total = on = 0;
	list = with_rules ? ucl_object_typed_new(UCL_ARRAY) : NULL;
	{
		ucl_object_t	*st = state_load(w);

		ucl_object_insert_key(src, files_read(w, sn_dir(w, "rules"), st,
		    list, &total, &on), "files", 0, false);
		ucl_object_unref(st);
	}
	ucl_object_insert_key(src, ucl_object_fromint(total), "rules", 0,
	    false);
	ucl_object_insert_key(src, ucl_object_fromint(on), "on", 0, false);
	ucl_object_insert_key(top, src, "source", 0, false);
	if (list != NULL)
		ucl_object_insert_key(top, list, "rules", 0, false);
	ucl_object_insert_key(top, alerts_read(w), "alerts", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen(json) > ARC_MAX_JSON) {
		free(json);
		rsp->ok = false;
		rsp->error = "more of Snort than a reply carries";
		return;
	}
	rsp->json = wstrdup(w, json);
	free(json);
	rsp->ok = true;
}
