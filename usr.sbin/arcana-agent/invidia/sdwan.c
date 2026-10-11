/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * SD-WAN on this edge: the rules that classify what comes in at the
 * UNIs and steer each flow to a tunnel, and the steering itself.
 *
 * The console compiles the services into one ipfw(8) ruleset of a set
 * of its own, with the tables the rules look up (sdwan-rules): the
 * zone table, whose values are the rule numbers of each zone's block
 * (skipto tablearg), and a table for each zone's policy, whose values
 * are the far inner addresses of the tunnels (fwd tablearg).  The set
 * is emptied and filled while disabled, so that no packet meets half
 * of it, and kept in a file for the next start, when it is loaded
 * again.
 *
 * What goes into the policy tables is the steering (sdwan-steer): for
 * each far prefix the tunnels that may carry it, in the order the
 * console wants them, by its performance criteria; the first whose far
 * end the probes (gula/probe.c) do not say is down is the one, and
 * when a probe's state changes the choice is made again here, at
 * once, without the console: the local failover.  A table is filled
 * beside the one in use and swapped in.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	RULES_FILE	"sdwan-rules.json"
#define	STEER_FILE	"sdwan-steer.json"
#define	TABLES_MAX	512
#define	RULES_MAX	4096
#define	OBJECTS_MAX	512
#define	STEER_MAX	4096
#define	CANDS_MAX	16
#define	ADD_CHUNK	64	/* table entries in one ipfw atomic add */

struct table {
	char	name[64];
	char	valtype[16];
};

/* A dummynet pipe or queue, or a nat instance: its kind and number. */
struct object {
	char	kind[8];
	char	num[8];
};

struct cand {
	char	id[128];
	char	via[64];
};

struct steer {
	char		table[64];
	char		prefix[64];
	int		ncand;
	struct cand	cand[CANDS_MAX];
	int		chosen;		/* -1: none */
};

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
static int		set;		/* the set the rules are in, 0: none */
static struct table	tables[TABLES_MAX];
static int		ntables;
static struct object	objects[OBJECTS_MAX];
static int		nobjects;
static int		nrules;
static struct steer	*steers;
static int		nsteers;
static bool		steered;	/* the tables hold the choices */

const char *
sdwan_conf_path(const char *file, char *buf, size_t len)
{
	const char	*slash;

	if ((slash = strrchr(opts.history_conf, '/')) != NULL)
		snprintf(buf, len, "%.*s/%s", (int)(slash - opts.history_conf),
		    opts.history_conf, file);
	else
		snprintf(buf, len, "%s", file);
	return (buf);
}

int
sdwan_conf_write(const char *file, const char *text, const char **errp)
{
	char	path[MAXPATHLEN], tmp[MAXPATHLEN];
	FILE	*fp;

	sdwan_conf_path(file, path, sizeof(path));
	if (strrchr(path, '/') != NULL) {
		snprintf(tmp, sizeof(tmp), "%.*s", (int)(strrchr(path, '/') -
		    path), path);
		(void)mkdir(tmp, 0755);
	}
	snprintf(tmp, sizeof(tmp), "%s.new", path);
	if ((fp = fopen(tmp, "we")) == NULL || fputs(text, fp) == EOF ||
	    fclose(fp) != 0 || rename(tmp, path) == -1) {
		*errp = strerror(errno);
		if (fp != NULL)
			fclose(fp);
		unlink(tmp);
		return (-1);
	}
	return (0);
}

char *
sdwan_kept_read(const char *file)
{
	char	path[MAXPATHLEN], *text;
	FILE	*fp;
	long	len;

	sdwan_conf_path(file, path, sizeof(path));
	if ((fp = fopen(path, "re")) == NULL)
		return (NULL);
	text = NULL;
	if (fseek(fp, 0, SEEK_END) == 0 && (len = ftell(fp)) > 0 && len <
	    8 * 1024 * 1024 && (text = malloc((size_t)len + 1)) != NULL) {
		rewind(fp);
		text[fread(text, 1, (size_t)len, fp)] = '\0';
	}
	fclose(fp);
	return (text);
}

/* ipfw, run with its words; -1 and why when it failed. */
static int
ipfw_run(struct work *w, const char **errp, int quiet, const char **words,
    int n)
{
	struct execres	 res;
	char		**argv;
	int		 k, i;

	argv = wcalloc(w, (size_t)n + 3, sizeof(*argv));
	k = 0;
	argv[k++] = (char *)(uintptr_t)opts.ipfw_bin;
	if (quiet)
		argv[k++] = (char *)(uintptr_t)"-q";
	for (i = 0; i < n; i++)
		argv[k++] = (char *)(uintptr_t)words[i];
	argv[k] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		if (errp != NULL)
			*errp = wtext(w, exec_error(w, &res, "ipfw"));
		return (-1);
	}
	return (0);
}

static int
ipfw_words(struct work *w, const char **errp, int quiet, ...)
{
	const char	*words[16], *a;
	va_list		 ap;
	int		 n;

	n = 0;
	va_start(ap, quiet);
	while ((a = va_arg(ap, const char *)) != NULL && n < 16)
		words[n++] = a;
	va_end(ap);
	return (ipfw_run(w, errp, quiet, words, n));
}

static const char *sval(const ucl_object_t *, const char *);

/*
 * A table's entries put in by ipfw, ADD_CHUNK of them an atomic add
 * (one call each, all or nothing), into the table named; -1 and why.
 */
static int
table_fill(struct work *w, const char *name, const ucl_object_t *entries,
    const char **errp)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*words[ADD_CHUNK * 2 + 4];
	int			 n;

	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(entries, &it, true)) != NULL) {
		if (n == 0) {
			words[n++] = "table";
			words[n++] = name;
			words[n++] = "atomic";
			words[n++] = "add";
		}
		words[n++] = ucl_object_tostring_forced(ucl_array_find_index(e, 0));
		words[n++] = ucl_object_tostring_forced(ucl_array_find_index(e, 1));
		if (n >= ADD_CHUNK * 2 + 4 - 2) {
			if (ipfw_run(w, errp, 1, words, n) != 0)
				return (-1);
			n = 0;
		}
	}
	if (n > 0 && ipfw_run(w, errp, 1, words, n) != 0)
		return (-1);
	return (0);
}

/* Are two tables' entries the same, as JSON? */
static bool
entries_same(const ucl_object_t *a, const ucl_object_t *b)
{
	unsigned char	*ja, *jb;
	bool		 same;

	if ((a == NULL) != (b == NULL))
		return (a == NULL ? ucl_array_size(b) == 0 : ucl_array_size(a) ==
		    0);
	if (a == NULL)
		return (true);
	ja = ucl_object_emit(a, UCL_EMIT_JSON_COMPACT);
	jb = ucl_object_emit(b, UCL_EMIT_JSON_COMPACT);
	same = ja != NULL && jb != NULL && strcmp((char *)ja, (char *)jb) == 0;
	free(ja);
	free(jb);
	return (same);
}

/*
 * Only the tables' entries changed since the rules were applied: the
 * same set, objects, rules and tables (names and value types, in
 * order), as kept; then the tables can be swapped in place and the
 * rules left as they are.
 */
static bool
tables_only(const ucl_object_t *top, const ucl_object_t *kept)
{
	const ucl_object_t	*a, *b;
	ucl_object_iter_t	 ia, ib;
	unsigned char		*ja, *jb;
	bool			 same;

	if (kept == NULL || set == 0 || ucl_object_toint(ucl_object_lookup(top,
	    "set")) != set)
		return (false);
	ja = ucl_object_emit(ucl_object_lookup(top, "rules"),
	    UCL_EMIT_JSON_COMPACT);
	jb = ucl_object_emit(ucl_object_lookup(kept, "rules"),
	    UCL_EMIT_JSON_COMPACT);
	same = ja != NULL && jb != NULL && strcmp((char *)ja, (char *)jb) == 0;
	free(ja);
	free(jb);
	if (!same)
		return (false);
	a = ucl_object_lookup(top, "objects");
	b = ucl_object_lookup(kept, "objects");
	ja = a != NULL ? ucl_object_emit(a, UCL_EMIT_JSON_COMPACT) : NULL;
	jb = b != NULL ? ucl_object_emit(b, UCL_EMIT_JSON_COMPACT) : NULL;
	same = (ja == NULL && jb == NULL) || (ja != NULL && jb != NULL && strcmp(
	    (char *)ja, (char *)jb) == 0);
	free(ja);
	free(jb);
	if (!same)
		return (false);
	if (ucl_array_size(ucl_object_lookup(top, "tables")) != ucl_array_size(
	    ucl_object_lookup(kept, "tables")))
		return (false);
	ia = ib = NULL;
	while ((a = ucl_object_iterate(ucl_object_lookup(top, "tables"), &ia,
	    true)) != NULL) {
		b = ucl_object_iterate(ucl_object_lookup(kept, "tables"), &ib, true);
		if (b == NULL || sval(a, "name") == NULL || sval(b, "name") == NULL
		    || strcmp(sval(a, "name"), sval(b, "name")) != 0 || sval(a,
		    "valtype") == NULL || sval(b, "valtype") == NULL || strcmp(
		    sval(a, "valtype"), sval(b, "valtype")) != 0)
			return (false);
	}
	return (true);
}

static bool
name_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 58)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_')
			return (false);
	return (true);
}

static bool
prefix_ok(const char *s)
{
	char		buf[64], *slash;
	unsigned char	a[16];

	if (s == NULL || strlen(s) >= sizeof(buf))
		return (false);
	snprintf(buf, sizeof(buf), "%s", s);
	if ((slash = strchr(buf, '/')) != NULL) {
		*slash++ = '\0';
		if (slash[strspn(slash, "0123456789")] != '\0' || atoi(slash) >
		    128)
			return (false);
	}
	return (inet_pton(AF_INET, buf, a) == 1 || inet_pton(AF_INET6, buf,
	    a) == 1);
}

static bool
address_ok(const char *s)
{
	unsigned char	a[16];

	return (s != NULL && (inet_pton(AF_INET, s, a) == 1 || inet_pton(
	    AF_INET6, s, a) == 1));
}

static ucl_object_t *
parse(const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	return (o);
}

static const char *
sval(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	return ((v = ucl_object_lookup(o, key)) != NULL && ucl_object_type(v)
	    == UCL_STRING ? ucl_object_tostring(v) : NULL);
}

/* ---- The steering ---------------------------------------------------- */

static const struct table *
table_find(const char *name)
{
	int	i;

	for (i = 0; i < ntables; i++)
		if (strcmp(tables[i].name, name) == 0)
			return (&tables[i]);
	return (NULL);
}

/*
 * Each table's entries made the choices the probes allow, and swapped
 * in where they changed; all of them with force.  Under the lock.
 */
static int
steer_apply(struct work *w, bool force, const char **errp)
{
	const struct table	*t;
	const char		*words[ADD_CHUNK * 2 + 4];
	char			 alt[72];
	int			 i, k, c, n, changed, st;
	bool			 any;

	for (i = 0; i < nsteers; i++) {
		if (table_find(steers[i].table) == NULL) {
			*errp = wfmt(w, "table %s is not one of the rules'",
			    steers[i].table);
			return (-1);
		}
	}
	/* The choice of each: the first whose far end is not down. */
	changed = 0;
	for (i = 0; i < nsteers; i++) {
		c = -1;
		for (k = 0; k < steers[i].ncand && c == -1; k++) {
			/* BFD's word where there is a session, else the probe's. */
			st = sdwan_bfd_state(steers[i].cand[k].via);
			if (st == PROBE_NONE)
				st = probe_state_of(steers[i].cand[k].id);
			if (st != PROBE_DOWN)
				c = k;
		}
		if (c != steers[i].chosen)
			changed++;
		steers[i].chosen = c;
	}
	if (!force && changed == 0 && steered)
		return (0);
	/* Table by table: the other one filled, then swapped in. */
	for (i = 0; i < nsteers; i++) {
		if (i > 0 && strcmp(steers[i].table, steers[i - 1].table) == 0)
			continue;
		t = table_find(steers[i].table);
		snprintf(alt, sizeof(alt), "%s_alt", t->name);
		if (strcmp(t->valtype, "legacy") == 0)
			(void)ipfw_words(w, NULL, 1, "table", alt, "create", "type",
			    "addr", NULL);
		else
			(void)ipfw_words(w, NULL, 1, "table", alt, "create", "type",
			    "addr", "valtype", t->valtype, NULL);
		if (ipfw_words(w, errp, 1, "table", alt, "flush", NULL) != 0)
			return (-1);
		any = false;
		n = 0;
		for (k = i; k < nsteers; k++) {
			if (strcmp(steers[k].table, t->name) != 0 ||
			    steers[k].chosen < 0)
				continue;
			if (n == 0) {
				words[n++] = "table";
				words[n++] = alt;
				words[n++] = "atomic";
				words[n++] = "add";
			}
			words[n++] = steers[k].prefix;
			words[n++] = steers[k].cand[steers[k].chosen].via;
			any = true;
			if (n >= ADD_CHUNK * 2 + 4 - 2) {
				if (ipfw_run(w, errp, 1, words, n) != 0)
					return (-1);
				n = 0;
			}
		}
		if (n > 0 && ipfw_run(w, errp, 1, words, n) != 0)
			return (-1);
		if (ipfw_words(w, errp, 1, "table", t->name, "swap", alt,
		    NULL) != 0)
			return (-1);
		(void)ipfw_words(w, NULL, 1, "table", alt, "flush", NULL);
		(void)any;
	}
	steered = true;
	return (0);
}

/* A probe's state changed: the choices made again, here. */
void
sdwan_probe_changed(void)
{
	struct work	 w;
	const char	*e;

	work_init(&w);
	pthread_mutex_lock(&lock);
	e = NULL;
	if (nsteers > 0 && steer_apply(&w, false, &e) != 0)
		logmsg(LOG_WARNING, "sdwan: steering not changed: %s", e);
	pthread_mutex_unlock(&lock);
	work_free(&w);
}

static int
steers_parse(struct work *w, const char *json, struct steer **outp,
    const char **errp)
{
	ucl_object_t		*top;
	const ucl_object_t	*e, *c, *cands;
	ucl_object_iter_t	 it, cit;
	struct steer		*v, *s;
	int			 n;

	if ((top = parse(json)) == NULL || ucl_object_type(top) !=
	    UCL_OBJECT || ucl_object_type(ucl_object_lookup(top, "entries")) !=
	    UCL_ARRAY) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the steering is an object with entries, an array";
		return (-1);
	}
	if ((v = calloc(STEER_MAX, sizeof(*v))) == NULL) {
		ucl_object_unref(top);
		*errp = strerror(errno);
		return (-1);
	}
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(top, "entries"), &it,
	    true)) != NULL) {
		if (n == STEER_MAX) {
			*errp = wfmt(w, "%d entries at most", STEER_MAX);
			goto bad;
		}
		s = &v[n];
		if (!name_ok(sval(e, "table")) || !prefix_ok(sval(e,
		    "prefix"))) {
			*errp = "each entry has a table, named with letters, "
			    "digits and _, and a prefix";
			goto bad;
		}
		snprintf(s->table, sizeof(s->table), "%s", sval(e, "table"));
		snprintf(s->prefix, sizeof(s->prefix), "%s", sval(e, "prefix"));
		s->chosen = -1;
		cands = ucl_object_lookup(e, "candidates");
		cit = NULL;
		while ((c = ucl_object_iterate(cands, &cit, true)) != NULL) {
			if (s->ncand == CANDS_MAX) {
				*errp = wfmt(w, "%s: %d candidates at most",
				    s->prefix, CANDS_MAX);
				goto bad;
			}
			if (sval(c, "id") == NULL || strlen(sval(c, "id")) >=
			    sizeof(s->cand[0].id) || !address_ok(sval(c,
			    "via"))) {
				*errp = wfmt(w, "%s: a candidate is a tunnel's id "
				    "and the address it goes via", s->prefix);
				goto bad;
			}
			snprintf(s->cand[s->ncand].id, sizeof(s->cand[0].id),
			    "%s", sval(c, "id"));
			snprintf(s->cand[s->ncand].via, sizeof(s->cand[0].via),
			    "%s", sval(c, "via"));
			s->ncand++;
		}
		n++;
	}
	ucl_object_unref(top);
	*outp = v;
	return (n);
bad:
	ucl_object_unref(top);
	free(v);
	return (-1);
}

/* The steering set: checked, kept, and the tables filled by it. */
int
do_sdwan_steer(struct work *w, const char *json, const char **errp)
{
	struct steer	*v;
	int		 n, step, rc;
	const char	*e;

	if ((n = steers_parse(w, json, &v, errp)) < 0)
		return (-1);
	pthread_mutex_lock(&lock);
	if (set == 0 && n > 0) {
		pthread_mutex_unlock(&lock);
		free(v);
		*errp = "no rules are applied: the steering fills their tables";
		return (-1);
	}
	free(steers);
	steers = v;
	nsteers = n;
	steered = false;
	step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent", "steer: "
	    "%d prefix%s", n, n == 1 ? "" : "es");
	rc = n > 0 ? steer_apply(w, true, errp) : 0;
	step_end(w, step, rc == 0, rc == 0 ? NULL : "%s", *errp);
	pthread_mutex_unlock(&lock);
	if (rc != 0)
		return (-1);
	e = NULL;
	if (sdwan_conf_write(STEER_FILE, json, &e) != 0) {
		*errp = wfmt(w, "%s: %s", STEER_FILE, e);
		return (-1);
	}
	return (0);
}

/* ---- The rules ------------------------------------------------------- */

/* Every table of the set gone, and its rules: before new ones, and
 * when there are to be none. */
static void
rules_clear(struct work *w, int s)
{
	char	num[16], alt[72];
	int	i;

	snprintf(num, sizeof(num), "%d", s);
	(void)ipfw_words(w, NULL, 1, "set", "disable", num, NULL);
	(void)ipfw_words(w, NULL, 1, "-f", "delete", "set", num, NULL);
	for (i = 0; i < ntables; i++) {
		(void)ipfw_words(w, NULL, 1, "table", tables[i].name,
		    "destroy", NULL);
		snprintf(alt, sizeof(alt), "%s_alt", tables[i].name);
		(void)ipfw_words(w, NULL, 1, "table", alt, "destroy", NULL);
	}
	/* The queues before the pipes they are in. */
	for (i = nobjects - 1; i >= 0; i--)
		(void)ipfw_words(w, NULL, 1, objects[i].kind, objects[i].num,
		    "delete", NULL);
}

/*
 * An object of the rules: "pipe N config ...", "queue N config ...",
 * "nat N config ...", words ipfw takes, nothing a shell would read;
 * its kind and number into o.
 */
static bool
object_ok(const char *line, struct object *o)
{
	const char	*p;
	size_t		 i, n;

	if (line == NULL || strlen(line) > 400 || strpbrk(line, "\n\r;`$'\"\\")
	    != NULL)
		return (false);
	n = strcspn(line, " ");
	if (n >= sizeof(o->kind) || (strncmp(line, "pipe", n) != 0 && strncmp(
	    line, "queue", n) != 0 && strncmp(line, "sched", n) != 0 &&
	    strncmp(line, "nat", n) != 0))
		return (false);
	snprintf(o->kind, sizeof(o->kind), "%.*s", (int)n, line);
	p = line + n + strspn(line + n, " ");
	n = strspn(p, "0123456789");
	if (n == 0 || n >= sizeof(o->num) || p[n] != ' ' || strtol(p, NULL,
	    10) < 1 || strtol(p, NULL, 10) > 65535)
		return (false);
	snprintf(o->num, sizeof(o->num), "%.*s", (int)n, p);
	p += n + 1;
	if (strncmp(p, "config ", 7) != 0)
		return (false);
	for (i = 0; p[i] != '\0'; i++)
		if (!isalnum((unsigned char)p[i]) && strchr(" ._:/,-", p[i]) ==
		    NULL)
			return (false);
	return (true);
}

/* The module an object's kind needs, loaded if it is not. */
static void
object_module(struct work *w, const char *kind)
{
	struct execres	 res;
	char		*argv[4];

	argv[0] = (char *)(uintptr_t)opts.kldload_bin;
	argv[1] = (char *)(uintptr_t)"-n";
	argv[2] = (char *)(uintptr_t)(strcmp(kind, "nat") == 0 ? "ipfw_nat" :
	    "dummynet");
	argv[3] = NULL;
	(void)run_exec(w, argv, &res);
}

/*
 * The ruleset applied: {"set", "tables": [{"name", "valtype",
 * "entries": [[key, value], ...]}], "rules": ["number rest", ...]}.
 * With no rules, the set is emptied.
 */
int
do_sdwan_rules(struct work *w, const char *json, const char **errp)
{
	ucl_object_t		*top;
	const ucl_object_t	*t, *r, *e, *k;
	ucl_object_iter_t	 it, eit;
	ucl_object_t		*kept;
	struct table		*nt;
	struct object		*no;
	char			 path[MAXPATHLEN], tmp[MAXPATHLEN], num[16];
	char			*text, alt[72];
	FILE			*fp;
	int64_t			 s;
	int			 n, nr, step, fd, nob, kk;
	const char		*line, *err;
	bool			 ok, dn, natm;

	if ((top = parse(json)) == NULL || ucl_object_type(top) != UCL_OBJECT) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the rules are an object: set, tables, rules";
		return (-1);
	}
	s = ucl_object_toint(ucl_object_lookup(top, "set"));
	if (s < 2 || s > 31) {
		ucl_object_unref(top);
		*errp = "the set is 2 to 31: 0 and 1 are the kept rules'";
		return (-1);
	}
	if ((nt = calloc(TABLES_MAX, sizeof(*nt))) == NULL) {
		ucl_object_unref(top);
		*errp = strerror(errno);
		return (-1);
	}
	if ((no = calloc(OBJECTS_MAX, sizeof(*no))) == NULL) {
		free(nt);
		ucl_object_unref(top);
		*errp = strerror(errno);
		return (-1);
	}
	nob = 0;
	dn = natm = false;
	it = NULL;
	while ((r = ucl_object_iterate(ucl_object_lookup(top, "objects"), &it,
	    true)) != NULL) {
		if (nob == OBJECTS_MAX) {
			*errp = wfmt(w, "%d objects at most", OBJECTS_MAX);
			goto bad;
		}
		if (!object_ok(ucl_object_type(r) == UCL_STRING ?
		    ucl_object_tostring(r) : NULL, &no[nob])) {
			*errp = "an object is a pipe, queue, sched or nat, its "
			    "number, config and its words";
			goto bad;
		}
		if (strcmp(no[nob].kind, "nat") == 0)
			natm = true;
		else
			dn = true;
		nob++;
	}
	n = 0;
	it = NULL;
	while ((t = ucl_object_iterate(ucl_object_lookup(top, "tables"), &it,
	    true)) != NULL) {
		if (n == TABLES_MAX) {
			*errp = wfmt(w, "%d tables at most", TABLES_MAX);
			goto bad;
		}
		if (!name_ok(sval(t, "name")) || sval(t, "valtype") == NULL ||
		    (strcmp(sval(t, "valtype"), "skipto") != 0 && strcmp(sval(t,
		    "valtype"), "ipv4") != 0 && strcmp(sval(t, "valtype"),
		    "ipv6") != 0 && strcmp(sval(t, "valtype"), "legacy") != 0)) {
			*errp = "a table has a name of letters, digits and _, "
			    "and a valtype of skipto, ipv4, ipv6 or legacy";
			goto bad;
		}
		eit = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(t, "entries"),
		    &eit, true)) != NULL) {
			k = ucl_array_find_index(e, 0);
			if (ucl_object_type(e) != UCL_ARRAY || ucl_array_size(e)
			    != 2 || !prefix_ok(ucl_object_tostring_forced(k)) ||
			    strlen(ucl_object_tostring_forced(
			    ucl_array_find_index(e, 1))) > 63 || strpbrk(
			    ucl_object_tostring_forced(ucl_array_find_index(e,
			    1)), " \t\n\"'") != NULL) {
				*errp = wfmt(w, "table %s: an entry is a prefix "
				    "and a value", sval(t, "name"));
				goto bad;
			}
		}
		snprintf(nt[n].name, sizeof(nt[n].name), "%s", sval(t, "name"));
		snprintf(nt[n].valtype, sizeof(nt[n].valtype), "%s", sval(t,
		    "valtype"));
		n++;
	}
	nr = 0;
	it = NULL;
	while ((r = ucl_object_iterate(ucl_object_lookup(top, "rules"), &it,
	    true)) != NULL) {
		line = ucl_object_type(r) == UCL_STRING ? ucl_object_tostring(r) :
		    NULL;
		if (line == NULL || ++nr > RULES_MAX || !isdigit((unsigned char)
		    line[0]) || strlen(line) > 1000 || strpbrk(line, "\n\r;`$")
		    != NULL || strstr(line, "set ") != NULL) {
			*errp = "a rule is its number and its words, nothing "
			    "that is not a rule, no set of its own";
			goto bad;
		}
	}
	/* Only entries changed, the rules as they are (a list fetched
	 * anew): each table whose entries differ from the kept ones is
	 * filled afresh beside itself and swapped in, in one call; the
	 * rules are not reloaded and the steering stays. */
	text = sdwan_kept_read(RULES_FILE);
	kept = text != NULL ? parse(text) : NULL;
	free(text);
	pthread_mutex_lock(&lock);
	if (kept != NULL && tables_only(top, kept)) {
		step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent", "set %jd: "
		    "the tables' entries swapped in, the rules as they are",
		    (intmax_t)s);
		ok = true;
		err = NULL;
		it = NULL;
		eit = NULL;
		while (ok && (t = ucl_object_iterate(ucl_object_lookup(top,
		    "tables"), &it, true)) != NULL) {
			k = ucl_object_iterate(ucl_object_lookup(kept, "tables"),
			    &eit, true);
			if (entries_same(ucl_object_lookup(t, "entries"),
			    ucl_object_lookup(k, "entries")))
				continue;
			snprintf(alt, sizeof(alt), "%s_alt", sval(t, "name"));
			if (strcmp(sval(t, "valtype"), "legacy") == 0)
				(void)ipfw_words(w, NULL, 1, "table", alt, "create",
				    "type", "addr", NULL);
			else
				(void)ipfw_words(w, NULL, 1, "table", alt, "create",
				    "type", "addr", "valtype", sval(t, "valtype"),
				    NULL);
			if (ipfw_words(w, &err, 1, "table", alt, "flush", NULL) != 0 ||
			    table_fill(w, alt, ucl_object_lookup(t, "entries"), &err)
			    != 0 || ipfw_words(w, &err, 1, "table", sval(t, "name"),
			    "swap", alt, NULL) != 0)
				ok = false;
			(void)ipfw_words(w, NULL, 1, "table", alt, "flush", NULL);
		}
		step_end(w, step, ok, ok ? NULL : "%s", err);
		pthread_mutex_unlock(&lock);
		ucl_object_unref(kept);
		free(nt);
		free(no);
		ucl_object_unref(top);
		if (!ok) {
			*errp = err;
			return (-1);
		}
		if (sdwan_conf_write(RULES_FILE, json, &err) != 0) {
			*errp = wfmt(w, "%s: %s", RULES_FILE, err);
			return (-1);
		}
		return (0);
	}
	pthread_mutex_unlock(&lock);
	if (kept != NULL)
		ucl_object_unref(kept);
	/* Room for the tables: ipfw's limit raised when they would not fit. */
	{
		int	have = 0, want;
		size_t	len = sizeof(have);

		want = n * 2 > 128 ? (n * 2 > 4096 ? n * 2 : 4096) : 0;
		if (want > 0 && (sysctlbyname("net.inet.ip.fw.tables_max", &have,
		    &len, NULL, 0) != 0 || have < want))
			(void)sysctlbyname("net.inet.ip.fw.tables_max", NULL, NULL,
			    &want, sizeof(want));
	}
	/* What IPsec decrypted goes past the firewall on its way in unless
	 * net.inet.ipsec.filtertunnel says otherwise, and a tunnel's
	 * payload with it: the rules would never see what comes in by an
	 * IPsec-carried tunnel.  Both families' set, in this vnet. */
	{
		int	one = 1, have = 0;
		size_t	len = sizeof(have);

		if (sysctlbyname("net.inet.ipsec.filtertunnel", &have, &len, NULL,
		    0) == 0 && have == 0)
			(void)sysctlbyname("net.inet.ipsec.filtertunnel", NULL, NULL,
			    &one, sizeof(one));
		len = sizeof(have);
		if (sysctlbyname("net.inet6.ipsec6.filtertunnel", &have, &len,
		    NULL, 0) == 0 && have == 0)
			(void)sysctlbyname("net.inet6.ipsec6.filtertunnel", NULL,
			    NULL, &one, sizeof(one));
	}
	/* The file ipfw reads: the tables, their entries, the rules. */
	sdwan_conf_path(RULES_FILE, path, sizeof(path));
	if (strrchr(path, '/') != NULL) {
		snprintf(tmp, sizeof(tmp), "%.*s", (int)(strrchr(path, '/') -
		    path), path);
		(void)mkdir(tmp, 0755);
	}
	snprintf(tmp, sizeof(tmp), "%s.load", path);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1 || (fp = fdopen(fd, "w")) == NULL) {
		*errp = wfmt(w, "%s: %s", tmp, strerror(errno));
		if (fd != -1)
			close(fd);
		goto bad;
	}
	snprintf(num, sizeof(num), "%jd", (intmax_t)s);
	/* The objects first: the rules name them. */
	it = NULL;
	while ((r = ucl_object_iterate(ucl_object_lookup(top, "objects"), &it,
	    true)) != NULL)
		fprintf(fp, "%s\n", ucl_object_tostring(r));
	it = NULL;
	while ((t = ucl_object_iterate(ucl_object_lookup(top, "tables"), &it,
	    true)) != NULL) {
		/* legacy, a plain number, is ipfw's default and not a word it
		 * takes any more. */
		if (strcmp(sval(t, "valtype"), "legacy") == 0)
			fprintf(fp, "table %s create type addr\n", sval(t, "name"));
		else
			fprintf(fp, "table %s create type addr valtype %s\n", sval(t,
			    "name"), sval(t, "valtype"));
		/* Its entries, ADD_CHUNK an atomic add: a line each, not a call
		 * each (SASE-2, large lists). */
		eit = NULL;
		kk = 0;
		while ((e = ucl_object_iterate(ucl_object_lookup(t, "entries"),
		    &eit, true)) != NULL) {
			if (kk == 0)
				fprintf(fp, "table %s atomic add", sval(t, "name"));
			fprintf(fp, " %s %s", ucl_object_tostring_forced(
			    ucl_array_find_index(e, 0)), ucl_object_tostring_forced(
			    ucl_array_find_index(e, 1)));
			if (++kk == ADD_CHUNK) {
				fprintf(fp, "\n");
				kk = 0;
			}
		}
		if (kk > 0)
			fprintf(fp, "\n");
	}
	it = NULL;
	while ((r = ucl_object_iterate(ucl_object_lookup(top, "rules"), &it,
	    true)) != NULL) {
		line = ucl_object_tostring(r);
		fprintf(fp, "add %.*s set %s %s\n", (int)strspn(line,
		    "0123456789"), line, num, line + strspn(line, "0123456789 "));
	}
	if (fclose(fp) != 0) {
		*errp = wfmt(w, "%s: %s", tmp, strerror(errno));
		goto bad;
	}
	pthread_mutex_lock(&lock);
	/* The old set and tables go, the new ones come, while disabled. */
	step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent", "set %s: %d "
	    "table%s, %d rule%s, %d object%s", num, n, n == 1 ? "" : "s", nr,
	    nr == 1 ? "" : "s", nob, nob == 1 ? "" : "s");
	if (set != 0)
		rules_clear(w, set);
	rules_clear(w, (int)s);
	/* And the new tables' names, should an earlier agent have left
	 * them in the kernel: a table is made anew, never reused. */
	for (int ti = 0; ti < n; ti++) {
		(void)ipfw_words(w, NULL, 1, "table", nt[ti].name, "destroy",
		    NULL);
		snprintf(tmp, sizeof(tmp), "%s_alt", nt[ti].name);
		(void)ipfw_words(w, NULL, 1, "table", tmp, "destroy", NULL);
	}
	snprintf(tmp, sizeof(tmp), "%s.load", path);
	memcpy(tables, nt, sizeof(*nt) * (size_t)n);
	ntables = n;
	memcpy(objects, no, sizeof(*no) * (size_t)nob);
	nobjects = nob;
	nrules = nr;
	set = (int)s;
	ok = true;
	err = NULL;
	if (dn)
		object_module(w, "pipe");
	if (natm)
		object_module(w, "nat");
	if (nr > 0 && ipfw_words(w, &err, 1, tmp, NULL) != 0) {
		ok = false;
		rules_clear(w, (int)s);
		ntables = 0;
		nobjects = 0;
		nrules = 0;
		set = 0;
	} else if (nr > 0 && ipfw_words(w, &err, 1, "set", "enable", num,
	    NULL) != 0)
		ok = false;
	else if (nr == 0)
		set = 0;
	step_end(w, step, ok, ok ? NULL : "%s", err);
	(void)unlink(tmp);
	if (!ok) {
		pthread_mutex_unlock(&lock);
		*errp = err;
		goto bad;
	}
	/* The tables are new and empty: the steering fills them again. */
	steered = false;
	if (nsteers > 0 && set != 0 && steer_apply(w, true, &err) != 0)
		logmsg(LOG_WARNING, "sdwan: steering not applied: %s", err);
	pthread_mutex_unlock(&lock);
	free(nt);
	free(no);
	ucl_object_unref(top);
	text = NULL;
	if (sdwan_conf_write(RULES_FILE, json, &err) != 0) {
		*errp = wfmt(w, "%s: %s", RULES_FILE, err);
		return (-1);
	}
	(void)text;
	return (0);
bad:
	free(nt);
	free(no);
	ucl_object_unref(top);
	return (-1);
}

/* The tunnel a steering candidate goes by this address; NULL for none. */
const char *
sdwan_tunnel_by_via(const char *via)
{
	static _Thread_local char	id[128];
	int				i, k;

	pthread_mutex_lock(&lock);
	for (i = 0; via != NULL && i < nsteers; i++)
		for (k = 0; k < steers[i].ncand; k++)
			if (strcmp(steers[i].cand[k].via, via) == 0) {
				snprintf(id, sizeof(id), "%s", steers[i].cand[k].id);
				pthread_mutex_unlock(&lock);
				return (id);
			}
	pthread_mutex_unlock(&lock);
	return (NULL);
}

/* At the start: the rules and the steering kept, applied again. */
void
sdwan_start(void)
{
	struct work	 w;
	char		*json;
	const char	*e;

	work_init(&w);
	if ((json = sdwan_kept_read(RULES_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_rules(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "sdwan rules: %s", e);
		free(json);
	}
	if ((json = sdwan_kept_read(STEER_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_steer(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "sdwan steer: %s", e);
		free(json);
	}
	work_free(&w);
}

/*
 * The counters of the rules in the set, as ipfw -S show prints them
 * ("number packets bytes set N rest"): each its rule number, packets,
 * bytes and text, for the console to count what a policy denied (MEF
 * 88, SASE-1); none when no set is applied.
 */
static ucl_object_t *
counters_json(struct work *w, int inset)
{
	struct execres	 res;
	ucl_object_t	*arr, *c;
	const char	*p, *nl;
	char		*argv[4], *line, *rest;
	unsigned long long num, pkts, bytes;
	int		 rs, n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (inset <= 0)
		return (arr);
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-S";
	argv[2] = (char *)(uintptr_t)"show";
	argv[3] = NULL;
	if (run_exec_max(w, argv, &res, ARC_MAX_JSON) != 0 || res.out == NULL)
		return (arr);
	for (p = res.out; *p != '\0'; p = *nl != '\0' ? nl + 1 : nl) {
		nl = p + strcspn(p, "\n");
		line = wstrndup(w, p, (size_t)(nl - p));
		if (sscanf(line, "%llu %llu %llu set %d %n", &num, &pkts, &bytes,
		    &rs, &n) != 4 || rs != inset)
			continue;
		rest = line + n;
		c = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(c, ucl_object_fromint((int64_t)num), "rule",
		    0, false);
		ucl_object_insert_key(c, ucl_object_fromint((int64_t)pkts), "pkts",
		    0, false);
		ucl_object_insert_key(c, ucl_object_fromint((int64_t)bytes),
		    "bytes", 0, false);
		ucl_object_insert_key(c, ucl_object_fromstring(rest), "text", 0,
		    false);
		ucl_array_append(arr, c);
	}
	return (arr);
}

/* The rules and the steering, as they are, into the sdwan reply. */
void
sdwan_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*o, *arr, *e, *c, *cs;
	int		 i, k, st;

	pthread_mutex_lock(&lock);
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromint(set), "set", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(nrules), "rules", 0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < ntables; i++)
		ucl_array_append(arr, ucl_object_fromstring(tables[i].name));
	ucl_object_insert_key(o, arr, "tables", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(nobjects), "objects", 0,
	    false);
	ucl_object_insert_key(o, counters_json(w, set), "counters", 0, false);
	ucl_object_insert_key(top, o, "rules", 0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nsteers; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromstring(steers[i].table),
		    "table", 0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(steers[i].prefix),
		    "prefix", 0, false);
		ucl_object_insert_key(e, ucl_object_fromint(steers[i].chosen),
		    "chosen", 0, false);
		cs = ucl_object_typed_new(UCL_ARRAY);
		for (k = 0; k < steers[i].ncand; k++) {
			c = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(c, ucl_object_fromstring(
			    steers[i].cand[k].id), "id", 0, false);
			ucl_object_insert_key(c, ucl_object_fromstring(
			    steers[i].cand[k].via), "via", 0, false);
			st = probe_state_of(steers[i].cand[k].id);
			ucl_object_insert_key(c, ucl_object_fromstring(st ==
			    PROBE_DOWN ? "down" : st == PROBE_UP ? "up" : st ==
			    PROBE_NONE ? "not probed" : "unknown"), "state", 0,
			    false);
			st = sdwan_bfd_state(steers[i].cand[k].via);
			if (st != PROBE_NONE)
				ucl_object_insert_key(c, ucl_object_fromstring(st ==
				    PROBE_DOWN ? "down" : st == PROBE_UP ? "up" :
				    "unknown"), "bfd", 0, false);
			ucl_array_append(cs, c);
		}
		ucl_object_insert_key(e, cs, "candidates", 0, false);
		ucl_array_append(arr, e);
	}
	ucl_object_insert_key(top, arr, "steer", 0, false);
	ucl_object_insert_key(top, ucl_object_frombool(steered), "steered", 0,
	    false);
	pthread_mutex_unlock(&lock);
}
