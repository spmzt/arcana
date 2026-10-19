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
#include <sys/stat.h>

#include <ctype.h>
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
	    "offset", "limit" };
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
			    "classtype=, offset= and limit=";
			return;
		}
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
	map = NULL;
	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) != -1 && fstat(fd, &sb) ==
	    0 && sb.st_size > 0 && (map = mmap(NULL, (size_t)sb.st_size,
	    PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED)
		map = NULL;
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
		(void)munmap(map, (size_t)sb.st_size);
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
