/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Suricata's ruleset rule by rule.  What suricata-update wrote to
 * suricata.rules is read and searched, a page at a time (Emerging
 * Threats Open alone is some 70000 rules): a rule it disabled is a line
 * commented out.  The admin's choices of rules by sid, on, off or drop,
 * are kept in suricata-rule-state beside the agent's other files and
 * given to suricata-update as its own enable.conf, disable.conf and
 * drop.conf each time it runs, so that they hold across updates.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	STATE_FILE	"suricata-rule-state"
#define	STATES_MAX	20000
#define	SIDS_JOB	1000	/* sids a rule job sets, at most */
#define	LIMIT_DEFAULT	100
#define	LIMIT_MAX	500

static void	sources_json(struct work *, ucl_object_t *);
static bool	sc_read(struct work *, const char *const *, size_t,
		    struct arc_suricata_rules_rsp *);

/* A rule the admin set: 'e' on, 'd' off, 'p' drop. */
struct rstate {
	uint32_t	sid;
	char		st;
};

static int
state_cmp(const void *a, const void *b)
{
	uint32_t	x, y;

	x = ((const struct rstate *)a)->sid;
	y = ((const struct rstate *)b)->sid;
	return (x < y ? -1 : x > y);
}

static const char *
state_word(char st)
{

	return (st == 'e' ? "on" : st == 'd' ? "off" : st == 'p' ? "drop" :
	    NULL);
}

/* The admin's, sorted by sid, STATES_MAX of room; *np how many. */
static struct rstate *
state_load(struct work *w, size_t *np)
{
	struct rstate	*v;
	char		*text, *it, *line, *end;
	unsigned long	 sid;
	size_t		 n;

	v = wcalloc(w, STATES_MAX, sizeof(*v));
	n = 0;
	if ((text = sdwan_kept_read(STATE_FILE)) != NULL) {
		for (it = text; (line = strsep(&it, "\n")) != NULL &&
		    n < STATES_MAX;) {
			sid = strtoul(line, &end, 10);
			if (end == line || *end != ' ' || sid == 0 ||
			    sid > UINT32_MAX)
				continue;
			end++;
			if (strcmp(end, "on") == 0)
				v[n].st = 'e';
			else if (strcmp(end, "off") == 0)
				v[n].st = 'd';
			else if (strcmp(end, "drop") == 0)
				v[n].st = 'p';
			else
				continue;
			v[n++].sid = (uint32_t)sid;
		}
		free(text);
	}
	qsort(v, n, sizeof(*v), state_cmp);
	*np = n;
	return (v);
}

static char
state_of(const struct rstate *v, size_t n, uint32_t sid)
{
	struct rstate	 key;
	const struct rstate *r;

	key.sid = sid;
	r = bsearch(&key, v, n, sizeof(*v), state_cmp);
	return (r != NULL ? r->st : '\0');
}

/* suricata-update's file of the sids in state st (a drop is on too). */
static const char *
conf_text(struct work *w, const struct rstate *v, size_t n, char st,
    const char *what)
{
	char	*text;
	size_t	 i, len, off;

	len = 128 + n * 12;
	text = wcalloc(w, len, 1);
	off = (size_t)snprintf(text, len, "# Written by arcana-agent: the "
	    "rules the admin %s, by sid.\n", what);
	for (i = 0; i < n && off < len; i++)
		if (v[i].st == st || (st == 'e' && v[i].st == 'p'))
			off += (size_t)snprintf(text + off, len - off, "%u\n",
			    v[i].sid);
	return (text);
}

static int
state_save(struct work *w, const struct rstate *v, size_t n,
    const char **errp)
{
	char	*text;
	size_t	 i, len, off;

	len = 16 + n * 18;
	text = wcalloc(w, len, 1);
	off = 0;
	for (i = 0; i < n && off < len; i++)
		off += (size_t)snprintf(text + off, len - off, "%u %s\n",
		    v[i].sid, state_word(v[i].st));
	return (sdwan_conf_write(STATE_FILE, text, errp));
}

/*
 * suricata-update's arguments for the admin's rules, after argv[*np]:
 * its three files written from the state first.  -1 and why when one
 * cannot be.
 */
int
suricata_rule_args(struct work *w, char **argv, int *np, const char **errp)
{
	static const struct {
		const char	*opt, *file, *what;
		char		 st;
	} confs[] = {
		{ "--enable-conf", "suricata-enable.conf", "turned on", 'e' },
		{ "--disable-conf", "suricata-disable.conf", "turned off", 'd' },
		{ "--drop-conf", "suricata-drop.conf", "made drops", 'p' },
	};
	struct rstate	*v;
	char		 path[MAXPATHLEN];
	size_t		 n, i;

	v = state_load(w, &n);
	for (i = 0; i < nitems(confs); i++) {
		if (sdwan_conf_write(confs[i].file, conf_text(w, v, n,
		    confs[i].st, confs[i].what), errp) != 0)
			return (-1);
		argv[(*np)++] = (char *)(uintptr_t)confs[i].opt;
		argv[(*np)++] = wstrdup(w, sdwan_conf_path(confs[i].file, path,
		    sizeof(path)));
	}
	return (0);
}

/* A list of sids, joined by commas: their count, or -1. */
static int
sids_parse(const char *s, uint32_t *out, int room)
{
	unsigned long	 sid;
	char		*end;
	int		 n;

	n = 0;
	while (*s != '\0') {
		if (!isdigit((unsigned char)*s))
			return (-1);
		errno = 0;
		sid = strtoul(s, &end, 10);
		if (errno != 0 || sid == 0 || sid > UINT32_MAX || n == room ||
		    (*end != ',' && *end != '\0'))
			return (-1);
		if (out != NULL)
			out[n] = (uint32_t)sid;
		n++;
		s = *end == ',' ? end + 1 : end;
	}
	return (n);
}

static char
verb_state(const char *word, const char **sidsp)
{
	static const struct {
		const char	*key;
		char		 st;
	} keys[] = { { "on=", 'e' }, { "off=", 'd' }, { "drop=", 'p' },
	    { "default=", 'x' } };
	size_t	i;

	for (i = 0; i < nitems(keys); i++)
		if (strncmp(word, keys[i].key, strlen(keys[i].key)) == 0) {
			*sidsp = word + strlen(keys[i].key);
			return (keys[i].st);
		}
	return ('\0');
}

/* A rule job's words: on=, off=, drop= or default=, each of sids. */
const char *
suricata_rule_check(const struct arc_job_spec *sp)
{
	const char	*sids;
	size_t		 i;
	int		 k, total;

	if (sp->names.n == 0 || sp->names.n > 4)
		return ("rule sets rules on=, off=, drop= or default=, each "
		    "sids joined by commas");
	total = 0;
	for (i = 0; i < sp->names.n; i++) {
		if (sp->names.v[i] == NULL || verb_state(sp->names.v[i],
		    &sids) == '\0')
			return ("rule sets rules on=, off=, drop= or default=, "
			    "each sids joined by commas");
		if ((k = sids_parse(sids, NULL, SIDS_JOB)) <= 0 ||
		    (total += k) > SIDS_JOB)
			return ("a rule's sid is a number; 1000 of them a job, "
			    "at most");
	}
	return (NULL);
}

/* The rule job's words into the state, kept. */
int
suricata_rule_set(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct rstate	*v, key, *r;
	uint32_t	*sids;
	const char	*s;
	size_t		 n, i, k;
	char		 st;
	int		 ns, j;

	if ((*errp = suricata_rule_check(sp)) != NULL)
		return (-1);
	v = state_load(w, &n);
	sids = wcalloc(w, SIDS_JOB, sizeof(*sids));
	for (i = 0; i < sp->names.n; i++) {
		st = verb_state(sp->names.v[i], &s);
		ns = sids_parse(s, sids, SIDS_JOB);
		for (j = 0; j < ns; j++) {
			key.sid = sids[j];
			r = bsearch(&key, v, n, sizeof(*v), state_cmp);
			if (st == 'x') {
				if (r != NULL) {
					k = (size_t)(r - v);
					memmove(r, r + 1, (n - k - 1) *
					    sizeof(*v));
					n--;
				}
				continue;
			}
			if (r != NULL) {
				r->st = st;
				continue;
			}
			if (n == STATES_MAX) {
				*errp = "20000 rules set by sid, at most";
				return (-1);
			}
			v[n].sid = sids[j];
			v[n++].st = st;
			qsort(v, n, sizeof(*v), state_cmp);
		}
	}
	return (state_save(w, v, n, errp));
}

/*
 * An option's value in a rule: key: at an option's start (after "(",
 * ";" or a space), up to the ";" that ends it, or for one in quotes up
 * to its closing quote; *lenp its length.  NULL when the rule has none.
 */
static const char *
opt_span(const char *rule, const char *key, size_t *lenp)
{
	const char	*p, *e;
	size_t		 klen;

	klen = strlen(key);
	for (p = strchr(rule, '('); p != NULL && (p = strstr(p, key)) != NULL;
	    p += klen) {
		if (p[klen] != ':' || (p[-1] != '(' && p[-1] != ';' &&
		    p[-1] != ' '))
			continue;
		p += klen + 1;
		while (*p == ' ')
			p++;
		if (*p == '"') {
			p++;
			for (e = p; *e != '\0' && (*e != '"' || e[-1] == '\\');
			    e++)
				;
		} else
			e = p + strcspn(p, ";)");
		*lenp = (size_t)(e - p);
		return (p);
	}
	return (NULL);
}

/* An option's value, a quoted one as it reads: \" a ", \; a ;. */
static const char *
opt_value(struct work *w, const char *rule, const char *key)
{
	const char	*p;
	char		*out;
	size_t		 len, i, k;

	if ((p = opt_span(rule, key, &len)) == NULL)
		return (NULL);
	out = wcalloc(w, len + 1, 1);
	for (i = k = 0; i < len; i++) {
		if (p[i] == '\\' && i + 1 < len)
			i++;
		out[k++] = p[i];
	}
	return (out);
}

static bool
is_action(const char *s)
{
	static const char *const actions[] = { "alert ", "drop ", "pass ",
	    "reject ", "rejectsrc ", "rejectdst ", "rejectboth " };
	size_t	i;

	for (i = 0; i < nitems(actions); i++)
		if (strncmp(s, actions[i], strlen(actions[i])) == 0)
			return (true);
	return (false);
}

static const char *
word_value(const char *const *names, size_t n, const char *key)
{
	size_t	i, klen;

	klen = strlen(key);
	for (i = 0; i < n; i++)
		if (names[i] != NULL && strncmp(names[i], key, klen) == 0 &&
		    names[i][klen] == '=')
			return (names[i] + klen + 1);
	return (NULL);
}

static void
put_s(ucl_object_t *o, const char *k, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), k, 0, true);
}

void
do_suricata_rules(struct work *w, const char *const *names, size_t nn,
    struct arc_suricata_rules_rsp *rsp)
{
	static const char *const keys[] = { "q", "sid", "only", "classtype",
	    "offset", "limit", "sources", "instance", "command", "iface" };
	struct rstate	*v;
	struct stat	 sb;
	ucl_object_t	*top, *arr, *o;
	const char	*q, *only, *ct, *s, *path, *sev, *meta;
	char		*map, *line, *json, *end;
	const char	*p, *nl, *rule;
	unsigned long	 want, offset, limit, sid;
	size_t		 n, i, k, len, cap, total, enabled, matched;
	char		 st;
	bool		 on;
	int		 fd;

	rsp->has_ok = true;
	rsp->ok = false;
	for (i = 0; i < nn; i++) {
		for (k = 0; k < nitems(keys); k++)
			if (names[i] != NULL && strncmp(names[i], keys[k],
			    strlen(keys[k])) == 0 && names[i][strlen(keys[k])] ==
			    '=')
				break;
		if (k == nitems(keys)) {
			rsp->error = "the rules are searched by q=, sid=, only=, "
			    "classtype=, offset= and limit=; sources=1 says "
			    "the rule sources";
			return;
		}
	}
	/* instance= command=: Suricata's own answer. */
	if (sc_read(w, names, nn, rsp))
		return;
	/* sources=1: the rule sources, not the rules. */
	if (word_value(names, nn, "sources") != NULL) {
		top = ucl_object_typed_new(UCL_OBJECT);
		sources_json(w, top);
		json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
		ucl_object_unref(top);
		if (json == NULL) {
			rsp->error = "out of memory";
			return;
		}
		rsp->json = wstrdup(w, json);
		free(json);
		rsp->ok = true;
		return;
	}
	q = word_value(names, nn, "q");
	ct = word_value(names, nn, "classtype");
	only = word_value(names, nn, "only");
	if (only != NULL && strcmp(only, "enabled") != 0 && strcmp(only,
	    "disabled") != 0 && strcmp(only, "changed") != 0) {
		rsp->error = "only is enabled, disabled or changed";
		return;
	}
	want = offset = 0;
	limit = LIMIT_DEFAULT;
	if (((s = word_value(names, nn, "sid")) != NULL && ((want = strtoul(s,
	    &end, 10)) == 0 || *end != '\0')) || ((s = word_value(names, nn,
	    "offset")) != NULL && ((offset = strtoul(s, &end, 10)) > 1000000 ||
	    *end != '\0' || *s == '\0')) || ((s = word_value(names, nn,
	    "limit")) != NULL && ((limit = strtoul(s, &end, 10)) == 0 ||
	    limit > LIMIT_MAX || *end != '\0'))) {
		rsp->error = wfmt(w, "sid is a number, offset a number and "
		    "limit 1 to %d", LIMIT_MAX);
		return;
	}
	v = state_load(w, &n);
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)n), "changed",
	    0, false);
	total = enabled = matched = 0;
	path = suricata_ruleset();
	/* Read whole, not mapped: suricata-update truncates and rewrites
	 * the file in place, and a mapping of it would fault. */
	map = NULL;
	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) != -1 && fstat(fd, &sb) ==
	    0 && sb.st_size > 0 && sb.st_size < 1024L * 1024 * 1024 &&
	    (map = malloc((size_t)sb.st_size)) != NULL) {
		ssize_t	got = 0, rd;

		while (got < sb.st_size && (rd = read(fd, map + got,
		    (size_t)(sb.st_size - got))) > 0)
			got += rd;
		sb.st_size = got;
	}
	if (map != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put_s(o, "path", path);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)
		    sb.st_mtime), "at", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)
		    sb.st_size), "size", 0, false);
		ucl_object_insert_key(top, o, "ruleset", 0, false);
		cap = 4096;
		line = malloc(cap);
		for (p = map; line != NULL && p < map + sb.st_size; p = nl + 1) {
			if ((nl = memchr(p, '\n', (size_t)(map + sb.st_size -
			    p))) == NULL)
				nl = map + sb.st_size;
			len = (size_t)(nl - p);
			if (len + 1 > cap) {
				cap = len + 1;
				free(line);
				if ((line = malloc(cap)) == NULL)
					break;
			}
			memcpy(line, p, len);
			line[len] = '\0';
			rule = line + strspn(line, " \t");
			on = *rule != '#';
			if (!on)
				rule += 1 + strspn(rule + 1, " \t");
			if (!is_action(rule) || strchr(rule, '(') == NULL ||
			    (s = opt_span(rule, "sid", &k)) == NULL ||
			    (sid = strtoul(s, NULL, 10)) == 0 || sid >
			    UINT32_MAX)
				continue;
			total++;
			if (on)
				enabled++;
			st = state_of(v, n, (uint32_t)sid);
			if ((want != 0 && sid != want) || (only != NULL &&
			    ((strcmp(only, "enabled") == 0 && !on) ||
			    (strcmp(only, "disabled") == 0 && on) ||
			    (strcmp(only, "changed") == 0 && st == '\0'))) ||
			    (ct != NULL && ((s = opt_span(rule, "classtype",
			    &k)) == NULL || k != strlen(ct) || strncmp(s, ct,
			    k) != 0)) ||
			    (q != NULL && q[0] != '\0' && strcasestr(rule, q) == NULL))
				continue;
			if (matched++ < offset || ucl_array_size(arr) >= limit)
				continue;
			o = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(o, ucl_object_fromint((int64_t)sid),
			    "sid", 0, false);
			s = opt_value(w, rule, "gid");
			ucl_object_insert_key(o, ucl_object_fromint(s != NULL ?
			    strtoll(s, NULL, 10) : 1), "gid", 0, false);
			s = opt_value(w, rule, "rev");
			ucl_object_insert_key(o, ucl_object_fromint(s != NULL ?
			    strtoll(s, NULL, 10) : 0), "rev", 0, false);
			put_s(o, "action", wfmt(w, "%.*s", (int)strcspn(rule,
			    " "), rule));
			put_s(o, "msg", opt_value(w, rule, "msg"));
			put_s(o, "classtype", opt_value(w, rule, "classtype"));
			/* ET's metadata: signature_severity Major. */
			if ((meta = opt_value(w, rule, "metadata")) != NULL &&
			    (sev = strstr(meta, "signature_severity ")) != NULL)
				put_s(o, "severity", wfmt(w, "%.*s", (int)strcspn(
				    sev + 19, ","), sev + 19));
			ucl_object_insert_key(o, ucl_object_frombool(on),
			    "enabled", 0, false);
			put_s(o, "state", state_word(st));
			put_s(o, "rule", wtext(w, rule));
			ucl_array_append(arr, o);
		}
		free(line);
		free(map);
	}
	if (fd != -1)
		(void)close(fd);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)total),
	    "total", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)enabled),
	    "enabled", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)matched),
	    "matched", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)offset),
	    "offset", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)limit),
	    "limit", 0, false);
	ucl_object_insert_key(top, arr, "rules", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "out of memory";
		return;
	}
	rsp->json = wstrdup(w, json);
	free(json);
	rsp->ok = true;
}

/*
 * Rule sources: suricata-update's index of them (list-sources, once
 * update-sources fetched it), and those enabled, each a file of its
 * data directory's update/sources, NAME.yaml (with / made -), or
 * NAME.yaml.disabled.  The agent writes those files itself, so that a
 * source's secret code is never on a command line nor in a trace.
 */

/* suricata-update's data directory: the rules directory's parent,
 * /var/lib/suricata as it ships. */
const char *
suricata_data_dir(struct work *w)
{
	const char	*r = opts.suricata_rules, *slash;

	if ((slash = strrchr(r, '/')) == NULL || slash == r)
		return ("/");
	return (wfmt(w, "%.*s", (int)(slash - r), r));
}

static bool
source_name_ok(const char *s)
{
	size_t	n;

	n = strlen(s);
	return (n > 0 && n <= 64 && strspn(s, "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-") == n && s[0] != '/' &&
	    s[0] != '.' && strstr(s, "..") == NULL);
}

static const char *
source_file(struct work *w, const char *name, bool disabled)
{
	char	*safe, *p;

	safe = wstrdup(w, name);
	for (p = safe; *p != '\0'; p++)
		if (*p == '/')
			*p = '-';
	return (wfmt(w, "%s/update/sources/%s.yaml%s", suricata_data_dir(w),
	    safe, disabled ? ".disabled" : ""));
}

/* A word's value as YAML has it, in single quotes. */
static const char *
yaml_quoted(struct work *w, const char *v)
{
	char		*out, *q;
	const char	*p;

	out = wcalloc(w, strlen(v) * 2 + 3, 1);
	q = out;
	*q++ = '\'';
	for (p = v; *p != '\0'; p++) {
		if (*p == '\'')
			*q++ = '\'';
		*q++ = *p;
	}
	*q++ = '\'';
	return (out);
}

const char *
suricata_source_check(const struct arc_job_spec *sp)
{
	const char	*v;
	size_t		 i;
	bool		 name, url;

	if (strcmp(sp->verb, "sources") == 0)
		return (sp->names.n == 0 ? NULL : "sources takes no words");
	name = url = false;
	for (i = 0; i < sp->names.n; i++) {
		v = sp->names.v[i];
		if (v == NULL || strchr(v, '=') == NULL || strpbrk(v,
		    "\n\r") != NULL || strlen(v) > 512)
			return ("a source's words are key=value");
		if (strncmp(v, "name=", 5) == 0) {
			if (name || !source_name_ok(v + 5))
				return ("a source's name is letters, digits and "
				    ". _ / -, 64 at most");
			name = true;
		} else if (strncmp(v, "url=", 4) == 0) {
			if (strcmp(sp->verb, "source-add") != 0 || (strncmp(v +
			    4, "https://", 8) != 0 && strncmp(v + 4, "http://",
			    7) != 0 && strncmp(v + 4, "file:///", 8) != 0) ||
			    strpbrk(v, " \t") != NULL)
				return ("source-add's url is http, https or "
				    "file:///, without spaces");
			url = true;
		} else if (strcmp(sp->verb, "source-enable") != 0 ||
		    strspn(v, "abcdefghijklmnopqrstuvwxyz-") != (size_t)(
		    strchr(v, '=') - v) || strchr(v, '=') == v)
			return ("a source's parameters (secret-code=...) are "
			    "source-enable's");
	}
	if (!name)
		return ("a source is named: name=et/open");
	if (strcmp(sp->verb, "source-add") == 0 && !url)
		return ("source-add needs its url=");
	if (strcmp(sp->verb, "source-enable") != 0 && strcmp(sp->verb,
	    "source-disable") != 0 && strcmp(sp->verb, "source-remove") != 0 &&
	    strcmp(sp->verb, "source-add") != 0)
		return ("a suricata job's verb is update, rule, sources, "
		    "source-enable, source-disable, source-remove or source-add");
	return (NULL);
}

/* The title, without a secret: the verb and the source's name. */
char *
suricata_source_title(const struct arc_job_spec *sp)
{
	const char	*name;
	char		*t;
	size_t		 i;

	if (strcmp(sp->verb, "sources") == 0)
		return (strdup("suricata-update: the index of rule sources "
		    "fetched"));
	name = "";
	for (i = 0; i < sp->names.n; i++)
		if (strncmp(sp->names.v[i], "name=", 5) == 0)
			name = sp->names.v[i] + 5;
	if (asprintf(&t, "suricata %s %s", sp->verb + 7, name) == -1)
		return (NULL);
	return (t);
}

int
suricata_source_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct execres	 res;
	const char	*name, *bin, *on, *off, *text, *tmp;
	char		*argv[6];
	size_t		 i;
	int		 step, fd;
	bool		 k;

	if ((*errp = suricata_source_check(sp)) != NULL)
		return (-1);
	if (strcmp(sp->verb, "sources") == 0) {
		if ((bin = tool(w, "suricata-update")) == NULL)
			bin = "/usr/local/bin/suricata-update";
		argv[0] = (char *)(uintptr_t)bin;
		argv[1] = (char *)(uintptr_t)"-D";
		argv[2] = (char *)(uintptr_t)suricata_data_dir(w);
		argv[3] = (char *)(uintptr_t)"update-sources";
		argv[4] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			*errp = wtext(w, exec_error(w, &res, "suricata-update "
			    "update-sources"));
			return (-1);
		}
		return (0);
	}
	name = "";
	for (i = 0; i < sp->names.n; i++)
		if (strncmp(sp->names.v[i], "name=", 5) == 0)
			name = sp->names.v[i] + 5;
	on = source_file(w, name, false);
	off = source_file(w, name, true);
	step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
	    strcmp(sp->verb, "source-disable") == 0 ? wfmt(w, "%s disabled, "
	    "kept as %s", name, off) : strcmp(sp->verb, "source-remove") == 0 ?
	    wfmt(w, "%s taken away", name) : wfmt(w, "%s written", on));
	if (strcmp(sp->verb, "source-disable") == 0) {
		if (rename(on, off) != 0) {
			*errp = wfmt(w, "%s is not enabled", name);
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
	} else if (strcmp(sp->verb, "source-remove") == 0) {
		k = unlink(on) == 0;
		if (!(unlink(off) == 0 || k)) {
			*errp = wfmt(w, "%s is neither enabled nor disabled",
			    name);
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
	} else {
		/* Enabled again as it was, or with what is given. */
		if (strcmp(sp->verb, "source-enable") == 0 && sp->names.n == 1 &&
		    access(off, F_OK) == 0) {
			if (rename(off, on) != 0) {
				*errp = wfmt(w, "%s: %s", on, strerror(errno));
				step_end(w, step, false, "%s", *errp);
				return (-1);
			}
			step_end(w, step, true, NULL);
			return (0);
		}
		text = wfmt(w, "source: %s\n", yaml_quoted(w, name));
		if (strcmp(sp->verb, "source-add") == 0) {
			for (i = 0; i < sp->names.n; i++)
				if (strncmp(sp->names.v[i], "url=", 4) == 0)
					text = wfmt(w, "%surl: %s\n", text,
					    yaml_quoted(w, sp->names.v[i] + 4));
		} else if (sp->names.n > 1) {
			text = wfmt(w, "%sparams:\n", text);
			for (i = 0; i < sp->names.n; i++)
				if (strncmp(sp->names.v[i], "name=", 5) != 0)
					text = wfmt(w, "%s  %.*s: %s\n", text,
					    (int)(strchr(sp->names.v[i], '=') -
					    sp->names.v[i]), sp->names.v[i],
					    yaml_quoted(w, strchr(sp->names.v[i],
					    '=') + 1));
		}
		(void)mkdir(wfmt(w, "%s/update", suricata_data_dir(w)), 0755);
		(void)mkdir(wfmt(w, "%s/update/sources", suricata_data_dir(w)),
		    0755);
		(void)unlink(off);
		/* Its secret, root's alone: a new file, its mode set whatever
		 * an older one had, moved over the old. */
		tmp = wfmt(w, "%s.new", on);
		if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
		    O_NOFOLLOW, 0600)) == -1 || fchmod(fd, 0600) != 0 ||
		    write(fd, text, strlen(text)) != (ssize_t)strlen(text) ||
		    fsync(fd) != 0) {
			*errp = wfmt(w, "%s: %s", on, strerror(errno));
			if (fd != -1)
				(void)close(fd);
			(void)unlink(tmp);
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
		if (close(fd) != 0 || rename(tmp, on) != 0) {
			*errp = wfmt(w, "%s: %s", on, strerror(errno));
			(void)unlink(tmp);
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
	}
	step_end(w, step, true, NULL);
	return (0);
}

/* A small file of the agent's own, whole; NULL when it is not there. */
static char *
file_slurp(struct work *w, const char *path)
{
	FILE	*fp;
	char	*buf;
	size_t	 n;

	if ((fp = fopen(path, "re")) == NULL)
		return (NULL);
	buf = wcalloc(w, 64 * 1024 + 1, 1);
	n = fread(buf, 1, 64 * 1024, fp);
	fclose(fp);
	buf[n] = '\0';
	return (buf);
}

/* "\033[1;36mName\033[0m: ..." without its colours. */
static void
no_ansi(char *s)
{
	char	*r, *q;

	for (r = q = s; *r != '\0';) {
		if (*r == '\033' && r[1] == '[') {
			r += 2;
			r += strspn(r, "0123456789;");
			if (*r != '\0')
				r++;
			continue;
		}
		*q++ = *r++;
	}
	*q = '\0';
}

/* The sources: the index's, and each enabled or disabled here. */
static void
sources_json(struct work *w, ucl_object_t *top)
{
	struct execres		 res;
	ucl_object_t		*arr, *o;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*bin, *v, *st;
	char			*argv[5], *copy, *it2, *line, *key, *val;
	char			*text;
	bool			 any;

	arr = ucl_object_typed_new(UCL_ARRAY);
	o = NULL;
	if (access(wfmt(w, "%s/update/cache/index.yaml",
	    suricata_data_dir(w)), R_OK) == 0) {
		if ((bin = tool(w, "suricata-update")) == NULL)
			bin = "/usr/local/bin/suricata-update";
		argv[0] = (char *)(uintptr_t)bin;
		argv[1] = (char *)(uintptr_t)"-D";
		argv[2] = (char *)(uintptr_t)suricata_data_dir(w);
		argv[3] = (char *)(uintptr_t)"list-sources";
		argv[4] = NULL;
		if (run_exec(w, argv, &res) == 0) {
			copy = wstrdup(w, res.out);
			no_ansi(copy);
			for (it2 = copy; (line = strsep(&it2, "\n")) != NULL;) {
				key = line + strspn(line, " ");
				if ((val = strstr(key, ": ")) == NULL)
					continue;
				*val = '\0';
				val += 2;
				if (strcmp(key, "Name") == 0) {
					o = ucl_object_typed_new(UCL_OBJECT);
					ucl_array_append(arr, o);
					put_s(o, "name", val);
				} else if (o != NULL && (strcmp(key, "Vendor") ==
				    0 || strcmp(key, "Summary") == 0 ||
				    strcmp(key, "License") == 0 || strcmp(key,
				    "Parameters") == 0 || strcmp(key,
				    "Subscription") == 0 || strcmp(key,
				    "Replaces") == 0 || strcmp(key,
				    "Deprecated") == 0 || strcmp(key,
				    "Obsolete") == 0)) {
					key[0] = (char)tolower((unsigned char)
					    key[0]);
					put_s(o, key, val);
				}
			}
		}
		ucl_object_insert_key(top, ucl_object_frombool(true), "index", 0,
		    false);
	} else
		ucl_object_insert_key(top, ucl_object_frombool(false), "index",
		    0, false);
	/* Each one's state here: enabled, disabled, or neither. */
	any = false;
	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL) {
		v = ucl_object_tostring(ucl_object_lookup(e, "name"));
		st = access(source_file(w, v, false), F_OK) == 0 ? "enabled" :
		    access(source_file(w, v, true), F_OK) == 0 ? "disabled" :
		    NULL;
		if (st != NULL && strcmp(st, "enabled") == 0)
			any = true;
		if (st != NULL)
			put_s((ucl_object_t *)(uintptr_t)e, "state", st);
	}
	/* Those added by address, not in the index. */
	{
		DIR		*d;
		struct dirent	*de;
		size_t		 len;
		bool		 dis;

		if ((d = opendir(wfmt(w, "%s/update/sources",
		    suricata_data_dir(w)))) != NULL) {
			while ((de = readdir(d)) != NULL) {
				len = strlen(de->d_name);
				dis = len > 14 && strcmp(de->d_name + len - 14,
				    ".yaml.disabled") == 0;
				if (!dis && (len < 6 || strcmp(de->d_name + len -
				    5, ".yaml") != 0))
					continue;
				text = file_slurp(w, wfmt(w, "%s/update/sources/"
				    "%s", suricata_data_dir(w), de->d_name));
				if (text == NULL || strstr(text, "\nurl: ") ==
				    NULL || strncmp(text, "source: ", 8) != 0)
					continue;
				o = ucl_object_typed_new(UCL_OBJECT);
				/* Its url found before its name is cut. */
				val = strstr(text, "\nurl: ");
				line = text + 8;
				line[strcspn(line, "\n")] = '\0';
				if (line[0] == '\'') {
					line++;
					line[strcspn(line, "'")] = '\0';
				}
				put_s(o, "name", line);
				if (val != NULL) {
					val++;
					val += 5;
					val[strcspn(val, "\n")] = '\0';
					if (val[0] == '\'') {
						val++;
						val[strcspn(val, "'")] = '\0';
					}
					put_s(o, "url", val);
				}
				put_s(o, "state", dis ? "disabled" : "enabled");
				if (!dis)
					any = true;
				ucl_array_append(arr, o);
			}
			closedir(d);
		}
	}
	ucl_object_insert_key(top, arr, "sources", 0, false);
	/* None enabled: suricata-update fetches Emerging Threats Open. */
	ucl_object_insert_key(top, ucl_object_frombool(!any), "default_et_open",
	    0, false);
}

/*
 * Suricata's own answers, by its unix command socket (unix-command, the
 * instance's .sock): a version line, then a command, each JSON on a
 * line, each answered on one.  Those that read alone: what it runs,
 * its memcaps, its rules loaded and failed, its interfaces' counters,
 * its rules' profile where it is built with it.
 */
static const char *const sc_commands[] = { "uptime", "version",
    "running-mode", "capture-mode", "memcap-list", "ruleset-stats",
    "ruleset-failed-rules", "ruleset-profile", "iface-list", "iface-stat",
    "dump-counters" };

static char *
sc_line(struct work *w, int s)
{
	char	*buf;
	size_t	 len, cap;
	ssize_t	 n;

	cap = 4 * 1024 * 1024;
	buf = wcalloc(w, cap + 1, 1);
	len = 0;
	while (len < cap && (len == 0 || buf[len - 1] != '\n')) {
		if ((n = read(s, buf + len, cap - len)) <= 0)
			return (NULL);
		len += (size_t)n;
	}
	/* The line without its end. */
	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
		len--;
	buf[len] = '\0';
	return (buf);
}

static const char *
sc_ask(struct work *w, const char *path, const char *cmd, const char *iface,
    const char **errp)
{
	struct sockaddr_un	 sun;
	struct timeval		 tv = { 5, 0 };
	const char		*line;
	char			*r;
	int			 s;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		*errp = "its socket's path is too long";
		return (NULL);
	}
	if ((s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1 ||
	    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1 ||
	    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1 ||
	    connect(s, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		*errp = wfmt(w, "Suricata does not answer on %s: %s (is it "
		    "running?)", path, strerror(errno));
		if (s != -1)
			close(s);
		return (NULL);
	}
	line = "{\"version\":\"0.2\"}\n";
	if (write(s, line, strlen(line)) != (ssize_t)strlen(line) ||
	    (r = sc_line(w, s)) == NULL || strstr(r, "\"OK\"") == NULL) {
		*errp = "Suricata did not take the socket's version";
		close(s);
		return (NULL);
	}
	line = iface != NULL ? wfmt(w, "{\"command\":\"%s\",\"arguments\":"
	    "{\"iface\":\"%s\"}}\n", cmd, iface) : wfmt(w, "{\"command\":"
	    "\"%s\"}\n", cmd);
	if (write(s, line, strlen(line)) != (ssize_t)strlen(line) ||
	    (r = sc_line(w, s)) == NULL) {
		*errp = wfmt(w, "Suricata did not answer %s", cmd);
		close(s);
		return (NULL);
	}
	close(s);
	return (r);
}

/* instance=NAME command=CMD [iface=IF]: Suricata's answer, as it is. */
static bool
sc_read(struct work *w, const char *const *names, size_t nn,
    struct arc_suricata_rules_rsp *rsp)
{
	const char	*inst, *cmd, *ifn, *e, *r;
	size_t		 i;

	inst = word_value(names, nn, "instance");
	cmd = word_value(names, nn, "command");
	ifn = word_value(names, nn, "iface");
	if (inst == NULL && cmd == NULL)
		return (false);
	rsp->has_ok = true;
	rsp->ok = false;
	if (inst == NULL || cmd == NULL || !suricata_name_ok(inst)) {
		rsp->error = "Suricata is asked by instance= and command=";
		return (true);
	}
	for (i = 0; i < nitems(sc_commands); i++)
		if (strcmp(cmd, sc_commands[i]) == 0)
			break;
	if (i == nitems(sc_commands)) {
		rsp->error = "a command is one that reads: uptime, version, "
		    "running-mode, capture-mode, memcap-list, ruleset-stats, "
		    "ruleset-failed-rules, ruleset-profile, iface-list, "
		    "iface-stat or dump-counters";
		return (true);
	}
	if ((ifn != NULL) != (strcmp(cmd, "iface-stat") == 0) || (ifn !=
	    NULL && (strlen(ifn) >= 17 || strspn(ifn,
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._^")
	    != strlen(ifn)))) {
		rsp->error = "iface-stat, and it alone, names an iface=";
		return (true);
	}
	e = NULL;
	if ((r = sc_ask(w, suricata_socket(w, inst), cmd, ifn, &e)) == NULL) {
		rsp->error = e;
		return (true);
	}
	rsp->json = wtext(w, r);
	rsp->ok = true;
	return (true);
}

/* Has any source enabled here a secret code (params in its file)? */
bool
suricata_sources_secret(struct work *w)
{
	struct dirent	*de;
	DIR		*d;
	char		*text;
	bool		 any;

	any = false;
	if ((d = opendir(wfmt(w, "%s/update/sources", suricata_data_dir(w)))) ==
	    NULL)
		return (false);
	while (!any && (de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.' || strstr(de->d_name, ".yaml") == NULL)
			continue;
		text = file_slurp(w, wfmt(w, "%s/update/sources/%s",
		    suricata_data_dir(w), de->d_name));
		any = text != NULL && strstr(text, "params:") != NULL;
	}
	closedir(d);
	return (any);
}
