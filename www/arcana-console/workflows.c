/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Workflows: a chain of steps the console keeps and runs on several
 * hosts at once.
 *
 * A step is a job of any kind (share/arcana/jobs.yaml says what each
 * needs and uses, and the steps are checked against it), or a read of
 * the host whose answer a later step looks at.  Before a step there may
 * be a condition: a read made then, or an earlier step's answer, a path
 * in it and a test of what is there; a step whose condition fails is
 * skipped.  A step that fails stops the host's run, or the run goes on,
 * or on at a later step.  A value may be ${param.NAME}, asked for when
 * the run begins, ${host.id} or ${host.name}, ${step.ID.PATH}, what an
 * earlier step answered, or ${event.PATH}, of the event that began it.
 *
 * A workflow runs by hand, every so many seconds, or on events: those
 * the console sees itself (a host that stopped answering, host-down;
 * that answers again, host-up) and those the host tells (a jail made
 * or removed, jail-state; threshold, kmsg, link and the rest), each
 * with what it must match, a value of which may be ${param.NAME}, that
 * parameter's default.  One that runs by itself may hold a step
 * that destroys (jobs.yaml's destroys) only when it says so.
 *
 *	GET    /api/workflows		the workflows
 *	POST   /api/workflows		one made or changed
 *	DELETE /api/workflows/<id>
 *	POST   /api/workflows/<id>/run	run now: {"params", "hosts"}
 *	GET    /api/runs		the last runs
 *	GET    /api/runs/<n>		one, each host and step with its trace
 *	DELETE /api/runs/<n>		one running stopped
 *
 * The workflows are kept in workflows.json and the last runs in
 * runs.json, written as they go, each run's traces in a file of its
 * own under runs/, so that the list stays small however much the
 * steps answered.  A run has a thread of its own and one
 * for each of its hosts.  What runs by itself is started by one worker,
 * the one holding workflows.lock: a thread of it looks every few
 * seconds at what is due, and keeps a subscription to the events of
 * each host a workflow waits on, in a thread of its own: an event runs
 * what it begins as soon as it is told.  What a host said while it was
 * not heard (a connection that dropped, a console that restarted) is
 * read once it answers again.  When each workflow last ran by its
 * interval is kept in every.json, so that the interval counts from
 * then after a restart.  Threads never look at the servers themselves:
 * a timer of the worker's copies where each is reached into a table
 * they read.
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/queue.h>
#include <sys/stat.h>


#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <unistd.h>

#include "console.h"
#include "jobs_table.h"

#define	WF_FILE		"workflows.json"
#define	RUNS_FILE	"runs.json"
#define	RUNS_DIR	"runs"
#define	WF_LOCK		"workflows.lock"
#define	WF_MAX		64
#define	WF_STEPS_MAX	64
#define	WF_PARAMS_MAX	16
#define	WF_ON_MAX	8
#define	RUNS_KEEP	30
#define	RUN_HOSTS_MAX	32
#define	TICK_S		5
#define	EVERY_FILE	"every.json"	/* when each ran by its interval */
#define	SUB_QUEUE	256		/* events heard, not yet looked at */
#define	SUB_RETRY_S	5		/* after a host stopped answering */
#define	SUB_WAKE_MS	250		/* how soon a stop is seen */
#define	JOB_POLL_US	500000
#define	JOB_WAIT_S	3600
#define	TRACE_MAX	(64 * 1024)	/* of a step's answer, kept */

/* Where each server is reached: copied by the worker, read by threads. */
static pthread_mutex_t	ref_lock = PTHREAD_MUTEX_INITIALIZER;
static struct hostref	refs[256];
static int		nrefs;

static pthread_mutex_t	wf_lock = PTHREAD_MUTEX_INITIALIZER;
static int		lockfd = -1;

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	(void)ucl_object_delete_key(o, key);
	ucl_object_insert_key(o, v, key, 0, true);
}

static bool
ref_get(const char *sid, struct hostref *out)
{
	int	i;

	pthread_mutex_lock(&ref_lock);
	for (i = 0; i < nrefs; i++)
		if (strcmp(refs[i].id, sid) == 0) {
			*out = refs[i];
			pthread_mutex_unlock(&ref_lock);
			return (true);
		}
	pthread_mutex_unlock(&ref_lock);
	return (false);
}

/* In the worker: the servers as they are, for the threads. */
static void
refs_copy(void)
{
	const struct server	*s;
	struct hostref		 v[256];
	int			 n;

	n = 0;
	for (int i = 0; (s = server_at(i)) != NULL && n < 256; i++) {
		memset(&v[n], 0, sizeof(v[n]));
		snprintf(v[n].id, sizeof(v[n].id), "%s", s->id);
		snprintf(v[n].name, sizeof(v[n].name), "%s", s->name);
		snprintf(v[n].uri, sizeof(v[n].uri), "%s", s->uri);
		snprintf(v[n].peer, sizeof(v[n].peer), "%s", s->peer_name !=
		    NULL ? s->peer_name : "");
		n++;
	}
	pthread_mutex_lock(&ref_lock);
	memcpy(refs, v, sizeof(v[0]) * (size_t)n);
	nrefs = n;
	pthread_mutex_unlock(&ref_lock);
}

/*
 * The servers as the worker last copied them (every 2 s), for a thread
 * that may not touch the table: up to max into out; how many.
 */
int
host_refs_get(struct hostref *out, int max)
{
	int	n;

	pthread_mutex_lock(&ref_lock);
	n = nrefs < max ? nrefs : max;
	memcpy(out, refs, sizeof(refs[0]) * (size_t)n);
	pthread_mutex_unlock(&ref_lock);
	return (n);
}

/* In the worker, before a thread of another part looks at the servers. */
void
host_refs(void)
{

	refs_copy();
}

/* Where a server is reached, for a thread of another part. */
bool
host_ref(const char *sid, char *uri, size_t ulen, char *peer, size_t plen,
    char *name, size_t nlen)
{
	struct hostref	h;

	if (!ref_get(sid, &h))
		return (false);
	snprintf(uri, ulen, "%s", h.uri);
	snprintf(peer, plen, "%s", h.peer);
	snprintf(name, nlen, "%s", h.name);
	return (true);
}

/* ---- What jobs.yaml says of a kind ---------------------------------- */

static const struct jobkind *
kind_of(const char *kind)
{
	size_t	i;

	for (i = 0; kind != NULL && i < nitems(jobkinds); i++)
		if (strcmp(jobkinds[i].kind, kind) == 0)
			return (&jobkinds[i]);
	return (NULL);
}

/* Is word one of the words of list, "a b c"? */
static bool
word_in(const char *list, const char *word, size_t len)
{
	const char	*p, *e;

	for (p = list; *p != '\0'; p = e) {
		p += strspn(p, " ");
		e = p + strcspn(p, " ");
		if ((size_t)(e - p) == len && strncmp(p, word, len) == 0)
			return (true);
	}
	return (false);
}

/* The values field takes, "a|b|c", from "f=a|b g=c"; NULL for any. */
static const char *
values_of(const char *values, const char *field, size_t *lenp)
{
	const char	*p, *e, *eq;
	size_t		 fl;

	fl = strlen(field);
	for (p = values; *p != '\0'; p = e) {
		p += strspn(p, " ");
		e = p + strcspn(p, " ");
		if ((eq = memchr(p, '=', (size_t)(e - p))) != NULL &&
		    (size_t)(eq - p) == fl && strncmp(p, field, fl) == 0) {
			*lenp = (size_t)(e - eq - 1);
			return (eq + 1);
		}
	}
	return (NULL);
}

/* Is a job of this kind, with this verb or action, one that destroys? */
static bool
destroys(const struct jobkind *k, const char *verb)
{
	size_t		 n;
	const char	*v, *p, *e;

	if (k->destroys[0] == '\0')
		return (false);
	if (strcmp(k->destroys, "always") == 0)
		return (true);
	if (verb == NULL)
		return (false);
	/* A verb from a value: what it may be is all it may be. */
	if (strstr(verb, "${") != NULL)
		return (true);
	if ((v = values_of(k->destroys, "verb", &n)) == NULL)
		return (false);
	for (p = v; p < v + n; p = e + 1) {
		e = memchr(p, '|', (size_t)(v + n - p));
		if (e == NULL)
			e = v + n;
		if ((size_t)(e - p) == strlen(verb) && strncmp(p, verb,
		    (size_t)(e - p)) == 0)
			return (true);
	}
	return (false);
}

/* What is wrong with a step's job, as jobs.yaml has its kind; or NULL. */
static const char *
job_check(const ucl_object_t *job, bool *destroysp)
{
	static char		 why[160];
	const struct jobkind	*k;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	const char		*key, *vals, *s, *p, *e;
	size_t			 n;
	bool			 ok;

	if (ucl_object_type(job) != UCL_OBJECT || (k = kind_of(ucl_str(job,
	    "kind"))) == NULL)
		return ("a job has a kind, one of jobs.yaml's");
	it = NULL;
	while ((v = ucl_object_iterate(job, &it, true)) != NULL) {
		key = ucl_object_key(v);
		if (strcmp(key, "kind") == 0)
			continue;
		if (!word_in(k->needs, key, strlen(key)) && !word_in(k->uses,
		    key, strlen(key))) {
			snprintf(why, sizeof(why), "a %s job has no %s",
			    k->kind, key);
			return (why);
		}
		/* A value of a few is one of them, unless it is made later. */
		if (ucl_object_type(v) == UCL_STRING && (vals = values_of(
		    k->values, key, &n)) != NULL && strstr((s =
		    ucl_object_tostring(v)), "${") == NULL) {
			ok = false;
			for (p = vals; p < vals + n && !ok; p = e + 1) {
				e = memchr(p, '|', (size_t)(vals + n - p));
				if (e == NULL)
					e = vals + n;
				ok = (size_t)(e - p) == strlen(s) &&
				    strncmp(p, s, (size_t)(e - p)) == 0;
			}
			if (!ok) {
				snprintf(why, sizeof(why), "%s of a %s job is "
				    "one of %.*s", key, k->kind, (int)n, vals);
				return (why);
			}
		}
	}
	for (p = k->needs; *p != '\0'; p = e) {
		p += strspn(p, " ");
		e = p + strcspn(p, " ");
		if (e > p && ucl_object_lookup_len(job, p, (size_t)(e - p)) ==
		    NULL) {
			snprintf(why, sizeof(why), "a %s job needs %.*s",
			    k->kind, (int)(e - p), p);
			return (why);
		}
	}
	*destroysp = destroys(k, ucl_str(job, "verb") != NULL ? ucl_str(job,
	    "verb") : ucl_str(job, "action"));
	return (NULL);
}

/* ---- Values in a step, ${...} --------------------------------------- */

/*
 * A path in an answer: words with dots, a number an array's place,
 * key[field=value] the element of an array whose field is value.
 */
static const ucl_object_t *
path_get(const ucl_object_t *o, const char *path)
{
	char			 buf[512], *p, *tok, *br, *eq, *end;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	long			 idx;

	if (path == NULL || path[0] == '\0')
		return (o);
	snprintf(buf, sizeof(buf), "%s", path);
	p = buf;
	while (o != NULL && (tok = strsep(&p, ".")) != NULL) {
		br = strchr(tok, '[');
		if (br != NULL)
			*br++ = '\0';
		if (tok[0] != '\0') {
			idx = strtol(tok, &end, 10);
			if (*end == '\0' && ucl_object_type(o) == UCL_ARRAY)
				o = ucl_array_find_index(o, (unsigned int)idx);
			else
				o = ucl_object_lookup(o, tok);
		}
		if (br == NULL || o == NULL)
			continue;
		/* [field=value] of an array. */
		if ((eq = strchr(br, '=')) == NULL || (end = strchr(eq,
		    ']')) == NULL)
			return (NULL);
		*eq++ = '\0';
		*end = '\0';
		it = NULL;
		while ((e = ucl_object_iterate(o, &it, true)) != NULL)
			if (ucl_object_lookup(e, br) != NULL && strcmp(
			    ucl_object_tostring_forced(ucl_object_lookup(e, br)),
			    eq) == 0)
				break;
		o = e;
	}
	return (o);
}

struct hostrun;

/* ${...} in s made what it says, for the host's run; malloc'ed. */
static char *
expand(const char *s, const ucl_object_t *params, const struct hostref *h,
    const ucl_object_t *answers, const ucl_object_t *event)
{
	const ucl_object_t	*v;
	char			*out, name[300], *dot;
	const char		*p, *e, *val;
	size_t			 len, cap, n;

	cap = strlen(s) + 64;
	out = malloc(cap);
	len = 0;
	for (p = s; *p != '\0'; ) {
		val = NULL;
		if (p[0] == '$' && p[1] == '{' && (e = strchr(p, '}')) != NULL &&
		    (size_t)(e - p - 2) < sizeof(name)) {
			memcpy(name, p + 2, (size_t)(e - p - 2));
			name[e - p - 2] = '\0';
			if (strncmp(name, "param.", 6) == 0)
				val = (v = ucl_object_lookup(params, name + 6)) !=
				    NULL ? ucl_object_tostring_forced(v) : "";
			else if (strcmp(name, "host.id") == 0)
				val = h->id;
			else if (strcmp(name, "host.name") == 0)
				val = h->name;
			else if (strncmp(name, "step.", 5) == 0 &&
			    (dot = strchr(name + 5, '.')) != NULL) {
				*dot = '\0';
				v = path_get(ucl_object_lookup(answers, name + 5),
				    dot + 1);
				val = v != NULL ? ucl_object_tostring_forced(v) :
				    "";
			} else if (strncmp(name, "event.", 6) == 0) {
				v = path_get(event, name + 6);
				val = v != NULL ? ucl_object_tostring_forced(v) :
				    "";
			}
		}
		if (val == NULL) {
			n = 1;
			val = p;
		} else {
			n = strlen(val);
			p = strchr(p, '}');
		}
		if (len + n + 1 > cap) {
			cap = (len + n + 1) * 2;
			out = realloc(out, cap);
		}
		memcpy(out + len, val, n);
		len += n;
		p++;
	}
	out[len] = '\0';
	return (out);
}

/* The type jobs.yaml gives a field of a job: number, bool, text... */
static const char *
field_type(const char *field)
{
	size_t	i;

	for (i = 0; field != NULL && i < nitems(jobfields); i++)
		if (strcmp(jobfields[i].field, field) == 0)
			return (jobfields[i].type);
	return ("text");
}

/*
 * One value of the job with every string expanded, field the job's
 * field it is (NULL for the job itself, "" within a list or a map): a
 * value made of ${...}
 * becomes what the field is, a number field's digits a number and a
 * bool field's true or false one; a text field's stays text, whatever
 * it looks like (a jail named 101, a ticket 4711, 007).
 */
static ucl_object_t *
expand_val(const ucl_object_t *o, const char *field,
    const ucl_object_t *params, const struct hostref *h,
    const ucl_object_t *answers, const ucl_object_t *event)
{
	ucl_object_t		*c, *x;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	const char		*type;
	char			*s;
	bool			 made;

	switch (ucl_object_type(o)) {
	case UCL_STRING:
		s = expand(ucl_object_tostring(o), params, h, answers, event);
		made = strstr(ucl_object_tostring(o), "${") != NULL;
		type = field_type(field);
		if (made && strcmp(type, "number") == 0 && s[0] != '\0' &&
		    strlen(s) <= 18 && s[strspn(s, "0123456789")] == '\0')
			c = ucl_object_fromint(strtoll(s, NULL, 10));
		else if (made && strcmp(type, "bool") == 0 && (strcmp(s,
		    "true") == 0 || strcmp(s, "false") == 0))
			c = ucl_object_frombool(strcmp(s, "true") == 0);
		else
			c = ucl_object_fromstring(s);
		free(s);
		return (c);
	case UCL_OBJECT:
		c = ucl_object_typed_new(UCL_OBJECT);
		it = NULL;
		while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
			/* A job's own fields are typed; within a map, text. */
			x = expand_val(v, field == NULL ? ucl_object_key(v) :
			    "", params, h, answers, event);
			ucl_object_insert_key(c, x, ucl_object_key(v), 0, true);
		}
		return (c);
	case UCL_ARRAY:
		c = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((v = ucl_object_iterate(o, &it, true)) != NULL)
			ucl_array_append(c, expand_val(v, "", params, h,
			    answers, event));
		return (c);
	default:
		return (ucl_object_copy(o));
	}
}

/* The job with every string expanded: a new object. */
static ucl_object_t *
expand_obj(const ucl_object_t *o, const ucl_object_t *params,
    const struct hostref *h, const ucl_object_t *answers,
    const ucl_object_t *event)
{

	return (expand_val(o, NULL, params, h, answers, event));
}

/* A condition's test of what is at its path. */
static bool
test(const ucl_object_t *v, const char *op, const char *want)
{
	const char	*have;
	double		 a, b;

	if (strcmp(op, "exists") == 0)
		return (v != NULL && ucl_object_type(v) != UCL_NULL);
	if (strcmp(op, "missing") == 0)
		return (v == NULL || ucl_object_type(v) == UCL_NULL);
	if (v == NULL)
		return (strcmp(op, "ne") == 0);
	have = ucl_object_tostring_forced(v);
	if (want == NULL)
		want = "";
	if (strcmp(op, "eq") == 0)
		return (strcmp(have, want) == 0);
	if (strcmp(op, "ne") == 0)
		return (strcmp(have, want) != 0);
	if (strcmp(op, "contains") == 0)
		return (strstr(have, want) != NULL);
	a = strtod(have, NULL);
	b = strtod(want, NULL);
	if (strcmp(op, "gt") == 0)
		return (a > b);
	if (strcmp(op, "lt") == 0)
		return (a < b);
	return (false);
}

/* ---- The workflows -------------------------------------------------- */

static bool
id_word(const char *s, size_t max)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > max)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '-')
			return (false);
	return (true);
}

static const char *const reads[] = { "hello", "jails", "services", "stats",
    "events", "history", "packages" };
static const char *const ops[] = { "eq", "ne", "contains", "gt", "lt",
    "exists", "missing" };
/* What a step does to Arcana itself (run_arcana). */
static const char *const arcana_steps[] = { "check", "build", "agents",
    "console" };

static bool
in_list(const char *s, const char *const *v, size_t n)
{
	size_t	i;

	for (i = 0; s != NULL && i < n; i++)
		if (strcmp(s, v[i]) == 0)
			return (true);
	return (false);
}

/*
 * A workflow as it was sent, checked and made the one kept: NULL and
 * why when it is not one.
 */
static ucl_object_t *
wf_check(const ucl_object_t *in, const char **whyp)
{
	static char		 why[200];
	ucl_object_t		*w, *steps, *s;
	const ucl_object_t	*v, *st, *job, *when, *e;
	ucl_object_iter_t	 it, sit;
	const char		*id, *of;
	char			 ids[WF_STEPS_MAX][17], newid[9];
	uint32_t		 r;
	int			 n, i, k;
	bool			 hurts, any_hurts, alone;

#define	REFUSE(...) do {						\
	snprintf(why, sizeof(why), __VA_ARGS__);			\
	*whyp = why;							\
	ucl_object_unref(w);						\
	return (NULL);							\
} while (0)

	w = ucl_object_typed_new(UCL_OBJECT);
	if (ucl_object_type(in) != UCL_OBJECT)
		REFUSE("a workflow is an object");
	if ((id = ucl_str(in, "id")) != NULL && id[0] != '\0') {
		if (strlen(id) != 8 || id[strspn(id, "0123456789abcdef")] !=
		    '\0')
			REFUSE("an id is eight hex digits");
		put(w, "id", ucl_object_fromstring(id));
	} else {
		arc4random_buf(&r, sizeof(r));
		snprintf(newid, sizeof(newid), "%08x", r);
		put(w, "id", ucl_object_fromstring(newid));
	}
	if (ucl_str(in, "name") == NULL || ucl_str(in, "name")[0] == '\0' ||
	    strlen(ucl_str(in, "name")) > 64)
		REFUSE("a workflow has a name, of 64 characters at most");
	put(w, "name", ucl_object_fromstring(ucl_str(in, "name")));
	/* The hosts it runs on by itself, and by hand unless told others. */
	put(w, "hosts", ucl_object_typed_new(UCL_ARRAY));
	it = NULL;
	n = 0;
	while ((v = ucl_object_iterate(ucl_object_lookup(in, "hosts"), &it,
	    true)) != NULL) {
		struct hostref	h;

		if (ucl_object_type(v) != UCL_STRING || !ref_get(
		    ucl_object_tostring(v), &h) || ++n > RUN_HOSTS_MAX)
			REFUSE("a host is a server's id, %d at most",
			    RUN_HOSTS_MAX);
		ucl_array_append((ucl_object_t *)(uintptr_t)ucl_object_lookup(w,
		    "hosts"), ucl_object_fromstring(ucl_object_tostring(v)));
	}
	put(w, "params", ucl_object_typed_new(UCL_ARRAY));
	it = NULL;
	n = 0;
	while ((v = ucl_object_iterate(ucl_object_lookup(in, "params"), &it,
	    true)) != NULL) {
		if (!id_word(ucl_str(v, "name"), 32) || ++n > WF_PARAMS_MAX ||
		    (ucl_str(v, "default") != NULL && strlen(ucl_str(v,
		    "default")) > 256))
			REFUSE("a parameter is named with letters, digits, - "
			    "and _; %d at most", WF_PARAMS_MAX);
		s = ucl_object_typed_new(UCL_OBJECT);
		put(s, "name", ucl_object_fromstring(ucl_str(v, "name")));
		put(s, "default", ucl_object_fromstring(ucl_str(v, "default") !=
		    NULL ? ucl_str(v, "default") : ""));
		ucl_array_append((ucl_object_t *)(uintptr_t)ucl_object_lookup(w,
		    "params"), s);
	}
	steps = ucl_object_typed_new(UCL_ARRAY);
	put(w, "steps", steps);
	any_hurts = false;
	n = 0;
	it = NULL;
	while ((st = ucl_object_iterate(ucl_object_lookup(in, "steps"), &it,
	    true)) != NULL) {
		if (n == WF_STEPS_MAX)
			REFUSE("%d steps at most", WF_STEPS_MAX);
		if (!id_word(ucl_str(st, "id"), 16))
			REFUSE("a step has an id: letters, digits, - and _");
		for (k = 0; k < n; k++)
			if (strcmp(ids[k], ucl_str(st, "id")) == 0)
				REFUSE("two steps are %s", ids[k]);
		snprintf(ids[n], sizeof(ids[n]), "%s", ucl_str(st, "id"));
		s = ucl_object_typed_new(UCL_OBJECT);
		put(s, "id", ucl_object_fromstring(ids[n]));
		put(s, "name", ucl_object_fromstring(ucl_str(st, "name") != NULL ?
		    ucl_str(st, "name") : ids[n]));
		job = ucl_object_lookup(st, "job");
		of = ucl_str(st, "read");
		if ((job != NULL) + (of != NULL) + (ucl_object_lookup(st,
		    "arcana") != NULL) + (ucl_object_lookup(st, "notify") !=
		    NULL) != 1) {
			ucl_object_unref(s);
			REFUSE("step %s is a job, a read, a notify or Arcana's "
			    "own", ids[n]);
		}
		if (ucl_object_lookup(st, "notify") != NULL) {
			const ucl_object_t	*nt = ucl_object_lookup(st,
			    "notify");
			const char		*via = ucl_str(nt, "via");
			const char		*text = ucl_str(nt, "text");

			if (via == NULL || (strcmp(via, "mail") != 0 &&
			    strcmp(via, "telegram") != 0 && strcmp(via, "all") !=
			    0) || text == NULL || text[0] == '\0' ||
			    strlen(text) > 2000) {
				ucl_object_unref(s);
				REFUSE("step %s: a notify says via (mail, telegram "
				    "or all) and its text, 2000 characters at "
				    "most", ids[n]);
			}
			put(s, "notify", ucl_object_copy(nt));
		} else if (ucl_object_lookup(st, "arcana") != NULL) {
			if (!in_list(ucl_str(st, "arcana"), arcana_steps,
			    nitems(arcana_steps))) {
				ucl_object_unref(s);
				REFUSE("step %s: Arcana's own steps are check, "
				    "build, agents and console", ids[n]);
			}
			put(s, "arcana", ucl_object_fromstring(ucl_str(st,
			    "arcana")));
		} else if (job != NULL) {
			hurts = false;
			if ((*whyp = job_check(job, &hurts)) != NULL) {
				ucl_object_unref(s);
				snprintf(why, sizeof(why), "step %s: %s", ids[n],
				    *whyp);
				*whyp = why;
				ucl_object_unref(w);
				return (NULL);
			}
			any_hurts = any_hurts || hurts;
			put(s, "job", ucl_object_copy(job));
			put(s, "destroys", ucl_object_frombool(hurts));
		} else {
			if (!in_list(of, reads, nitems(reads))) {
				ucl_object_unref(s);
				REFUSE("step %s reads hello, jails, services, "
				    "stats, events, history or packages", ids[n]);
			}
			put(s, "read", ucl_object_fromstring(of));
		}
		if ((when = ucl_object_lookup(st, "when")) != NULL) {
			ucl_object_t	*c;
			const char	*wr, *ws;

			wr = ucl_str(when, "read");
			ws = ucl_str(when, "step");
			if (!in_list(ucl_str(when, "op"), ops, nitems(ops)) ||
			    (wr == NULL) == (ws == NULL) || (wr != NULL &&
			    !in_list(wr, reads, nitems(reads))) ||
			    (ucl_str(when, "path") != NULL && strlen(ucl_str(
			    when, "path")) > 256)) {
				ucl_object_unref(s);
				REFUSE("step %s: a condition reads, or looks at "
				    "an earlier step, and tests what is at its "
				    "path: eq, ne, contains, gt, lt, exists or "
				    "missing", ids[n]);
			}
			for (k = 0; ws != NULL && k < n; k++)
				if (strcmp(ids[k], ws) == 0)
					break;
			if (ws != NULL && k == n) {
				ucl_object_unref(s);
				REFUSE("step %s: its condition looks at a step "
				    "before it", ids[n]);
			}
			c = ucl_object_copy(when);
			put(s, "when", c);
		}
		of = ucl_str(st, "on_fail") != NULL ? ucl_str(st, "on_fail") :
		    "stop";
		put(s, "on_fail", ucl_object_fromstring(of));
		ucl_array_append(steps, s);
		n++;
	}
	if (n == 0)
		REFUSE("a workflow has a step at least");
	/* Where a failure goes on: a step after it. */
	sit = NULL;
	i = 0;
	while ((st = ucl_object_iterate(steps, &sit, true)) != NULL) {
		of = ucl_str(st, "on_fail");
		if (strcmp(of, "stop") != 0 && strcmp(of, "continue") != 0) {
			for (k = i + 1; k < n; k++)
				if (strcmp(ids[k], of) == 0)
					break;
			if (k >= n)
				REFUSE("step %s: on a failure, stop, continue, or "
				    "a step after it", ids[i]);
		}
		i++;
	}
	/* By itself: at an interval, on events. */
	if ((v = ucl_object_lookup(in, "every")) != NULL &&
	    ucl_object_toint(v) != 0 && (ucl_object_toint(v) < 60 ||
	    ucl_object_toint(v) > 7 * 86400))
		REFUSE("every is 0, or 60 seconds to a week");
	put(w, "every", ucl_object_fromint(v != NULL ? ucl_object_toint(v) :
	    0));
	put(w, "on", ucl_object_typed_new(UCL_ARRAY));
	it = NULL;
	k = 0;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "on"), &it,
	    true)) != NULL) {
		if (!id_word(ucl_str(e, "event"), 32) || ++k > WF_ON_MAX ||
		    (ucl_object_lookup(e, "match") != NULL && ucl_object_type(
		    ucl_object_lookup(e, "match")) != UCL_OBJECT))
			REFUSE("an event is named, with what it must match; %d "
			    "at most", WF_ON_MAX);
		ucl_array_append((ucl_object_t *)(uintptr_t)ucl_object_lookup(w,
		    "on"), ucl_object_copy(e));
	}
	alone = ucl_object_toint(ucl_object_lookup(w, "every")) > 0 || k > 0;
	put(w, "destructive", ucl_object_frombool(ucl_flag(in, "destructive")));
	if (alone && any_hurts && !ucl_flag(in, "destructive"))
		REFUSE("it runs by itself and a step destroys: say so, "
		    "destructive");
	if (alone && ucl_array_size(ucl_object_lookup(w, "hosts")) == 0)
		REFUSE("what runs by itself names its hosts");
	put(w, "changed", ucl_object_fromint(time(NULL)));
#undef REFUSE
	return (w);
}

static ucl_object_t *
wf_load(void)
{
	ucl_object_t	*top;

	if ((top = store_load(WF_FILE)) == NULL)
		top = ucl_object_typed_new(UCL_OBJECT);
	if (ucl_object_lookup(top, "workflows") == NULL)
		put(top, "workflows", ucl_object_typed_new(UCL_ARRAY));
	return (top);
}

/* The workflow of that id, a copy; NULL when none. */
static ucl_object_t *
wf_find(const char *id)
{
	ucl_object_t		*top, *w;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	pthread_mutex_lock(&wf_lock);
	top = wf_load();
	pthread_mutex_unlock(&wf_lock);
	w = NULL;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(top, "workflows"),
	    &it, true)) != NULL)
		if (ucl_str(e, "id") != NULL && strcmp(ucl_str(e, "id"), id) ==
		    0)
			w = ucl_object_copy(e);
	ucl_object_unref(top);
	return (w);
}

/* ---- The runs -------------------------------------------------------- */

struct hoststep {
	char		 state[12];	/* pending, skipped, running, done,
					   failed, cancelled, not run */
	uint64_t	 job;
	char		 title[160];
	char		 error[300];
	char		*trace;		/* the job's, JSON */
	double		 started, ended;	/* s, to the millisecond */
};

struct hostrun {
	struct run	*run;
	struct hostref	 h;
	char		 state[12];
	struct hoststep	 steps[WF_STEPS_MAX];
	ucl_object_t	*answers;	/* step id: what it answered */
	pthread_t	 thread;
	bool		 started;
};

struct run {
	pthread_mutex_t	 lock;
	uint32_t	 id;
	ucl_object_t	*wf;
	ucl_object_t	*params;
	ucl_object_t	*event;		/* of what began it, or NULL */
	char		 trigger[64];
	char		 state[12];
	time_t		 started, ended;
	double		 began;		/* started, to the millisecond */
	int		 nhosts;
	struct hostrun	 hosts[RUN_HOSTS_MAX];
	int		 nsteps;
	bool		 cancel;
	time_t		 looked;	/* runs.json, for a stop */
};

/* The run as runs.json keeps it, with the traces or without. */
static ucl_object_t *
run_object(struct run *r, bool traces)
{
	ucl_object_t		*o, *hs, *h, *ss, *s, *t;
	const ucl_object_t	*st;
	ucl_object_iter_t	 it;
	struct ucl_parser	*p;
	int			 i, k;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "id", ucl_object_fromint(r->id));
	put(o, "workflow", ucl_object_fromstring(ucl_str(r->wf, "id")));
	put(o, "name", ucl_object_fromstring(ucl_str(r->wf, "name")));
	put(o, "trigger", ucl_object_fromstring(r->trigger));
	put(o, "state", ucl_object_fromstring(r->state));
	/* To the millisecond, as its steps' are, when it is known. */
	put(o, "started", r->began > 0 ? ucl_object_fromdouble(floor(r->began *
	    1000) / 1000) : ucl_object_fromint(r->started));
	if (r->ended != 0)
		put(o, "ended", ucl_object_fromint(r->ended));
	put(o, "params", ucl_object_copy(r->params));
	if (r->event != NULL)
		put(o, "event", ucl_object_copy(r->event));
	if (r->cancel)
		put(o, "cancel", ucl_object_frombool(true));
	hs = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < r->nhosts; i++) {
		h = ucl_object_typed_new(UCL_OBJECT);
		put(h, "id", ucl_object_fromstring(r->hosts[i].h.id));
		put(h, "name", ucl_object_fromstring(r->hosts[i].h.name));
		put(h, "state", ucl_object_fromstring(r->hosts[i].state));
		ss = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		k = 0;
		while ((st = ucl_object_iterate(ucl_object_lookup(r->wf,
		    "steps"), &it, true)) != NULL && k < r->nsteps) {
			struct hoststep	*x = &r->hosts[i].steps[k++];

			s = ucl_object_typed_new(UCL_OBJECT);
			put(s, "id", ucl_object_fromstring(ucl_str(st, "id")));
			put(s, "state", ucl_object_fromstring(x->state));
			if (x->job != 0)
				put(s, "job", ucl_object_fromint((int64_t)x->job));
			if (x->title[0] != '\0')
				put(s, "title", ucl_object_fromstring(x->title));
			if (x->error[0] != '\0')
				put(s, "error", ucl_object_fromstring(x->error));
			/* Seconds, to the millisecond: a step of a fraction
			 * of one is drawn as long as it was. */
			if (x->started != 0)
				put(s, "started", ucl_object_fromdouble(
				    floor(x->started * 1000) / 1000));
			if (x->ended != 0)
				put(s, "ended", ucl_object_fromdouble(
				    floor(x->ended * 1000) / 1000));
			if (traces && x->trace != NULL) {
				p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
				if (ucl_parser_add_string(p, x->trace, 0) &&
				    (t = ucl_parser_get_object(p)) != NULL)
					put(s, "trace", t);
				ucl_parser_free(p);
			}
			ucl_array_append(ss, s);
		}
		put(h, "steps", ss);
		ucl_array_append(hs, h);
	}
	put(o, "hosts", hs);
	return (o);
}

/* The file a run's traces are in: runs/<id>.json. */
static const char *
run_file(uint32_t id, char *buf, size_t len)
{

	snprintf(buf, len, "%s/%u.json", RUNS_DIR, id);
	return (buf);
}

/*
 * The run written into runs.json, in its place or as the newest, and
 * with its traces into its own file; a stop asked of another worker is
 * read back.  Called with r->lock held.
 */
static void
run_save(struct run *r)
{
	ucl_object_t		*top, *keep, *mine, *full;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	size_t			 n;
	char			 file[64], path[MAXPATHLEN];
	bool			 found;

	pthread_mutex_lock(&wf_lock);
	if ((top = store_load(RUNS_FILE)) == NULL)
		top = ucl_object_typed_new(UCL_OBJECT);
	keep = ucl_object_typed_new(UCL_ARRAY);
	full = run_object(r, true);
	(void)store_save(run_file(r->id, file, sizeof(file)), full);
	ucl_object_unref(full);
	mine = run_object(r, false);
	found = false;
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(top, "runs"), &it,
	    true)) != NULL) {
		if ((uint32_t)ucl_object_toint(ucl_object_lookup(e, "id")) ==
		    r->id) {
			if (ucl_object_toboolean(ucl_object_lookup(e, "cancel")))
				r->cancel = true;
			ucl_array_append(keep, ucl_object_ref(mine));
			found = true;
		} else
			ucl_array_append(keep, ucl_object_copy(e));
		n++;
	}
	if (!found) {
		ucl_array_append(keep, ucl_object_ref(mine));
		n++;
	}
	while (n > RUNS_KEEP) {
		ucl_object_t	*old = ucl_array_pop_first(keep);

		/* Its traces go with it. */
		snprintf(path, sizeof(path), "%s/%s", cfg.datadir, run_file(
		    (uint32_t)ucl_object_toint(ucl_object_lookup(old, "id")),
		    file, sizeof(file)));
		(void)unlink(path);
		ucl_object_unref(old);
		n--;
	}
	ucl_object_unref(mine);
	put(top, "runs", keep);
	(void)store_save(RUNS_FILE, top);
	ucl_object_unref(top);
	pthread_mutex_unlock(&wf_lock);
}

static void
step_set(struct hostrun *hr, int k, const char *state, const char *fmt, ...)
{
	struct hoststep	*x = &hr->steps[k];
	struct timespec	 ts;
	va_list		 ap;

	pthread_mutex_lock(&hr->run->lock);
	snprintf(x->state, sizeof(x->state), "%s", state);
	if (fmt != NULL) {
		va_start(ap, fmt);
		vsnprintf(x->error, sizeof(x->error), fmt, ap);
		va_end(ap);
	}
	clock_gettime(CLOCK_REALTIME, &ts);
	if (strcmp(state, "running") == 0)
		x->started = ts.tv_sec + ts.tv_nsec / 1e9;
	else if (strcmp(state, "pending") != 0)
		x->ended = ts.tv_sec + ts.tv_nsec / 1e9;
	run_save(hr->run);
	pthread_mutex_unlock(&hr->run->lock);
}

/*
 * Was a stop asked?  In runs.json, where any worker puts it: looked at
 * every two seconds, between what writes it anyway.
 */
static bool
cancelled(struct run *r)
{
	ucl_object_t		*top;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	bool			 c;

	pthread_mutex_lock(&r->lock);
	if (!r->cancel && time(NULL) - r->looked >= 2) {
		r->looked = time(NULL);
		pthread_mutex_lock(&wf_lock);
		top = store_load(RUNS_FILE);
		pthread_mutex_unlock(&wf_lock);
		it = NULL;
		while (top != NULL && (e = ucl_object_iterate(
		    ucl_object_lookup(top, "runs"), &it, true)) != NULL)
			if ((uint32_t)ucl_object_toint(ucl_object_lookup(e,
			    "id")) == r->id && ucl_object_toboolean(
			    ucl_object_lookup(e, "cancel")))
				r->cancel = true;
		if (top != NULL)
			ucl_object_unref(top);
	}
	c = r->cancel;
	pthread_mutex_unlock(&r->lock);
	return (c);
}

static ucl_object_t *
parse(const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	if (json == NULL)
		return (NULL);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	o = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	return (o);
}

/* A job of a step: queued, then followed until it ended. */
static bool
run_job(struct hostrun *hr, int k, const ucl_object_t *step)
{
	struct hoststep		*x = &hr->steps[k];
	ucl_object_t		*job, *ans, *jr;
	const char		*e, *st;
	char			*json;
	int			 status;
	time_t			 until;
	uint64_t		 id;
	bool			 ok;

	job = expand_obj(ucl_object_lookup(step, "job"), hr->run->params,
	    &hr->h, hr->answers, hr->run->event);
	json = hosts_submit(hr->h.uri, hr->h.peer, hr->h.name, job, &status,
	    &e);
	ucl_object_unref(job);
	if (json == NULL) {
		step_set(hr, k, "failed", "%s", e);
		return (false);
	}
	ans = parse(json);
	free(json);
	if (status != 200 || ans == NULL || ucl_object_lookup(ans,
	    "jobs") == NULL || (id = (uint64_t)ucl_object_toint(path_get(ans,
	    "jobs.0.id"))) == 0) {
		step_set(hr, k, "failed", "%s", ans != NULL && ucl_str(ans,
		    "error") != NULL ? ucl_str(ans, "error") : ans != NULL &&
		    ucl_object_lookup(ans, "error") != NULL ?
		    ucl_object_tostring_forced(path_get(ans, "error.message")) :
		    "the host did not take it");
		if (ans != NULL)
			ucl_object_unref(ans);
		return (false);
	}
	pthread_mutex_lock(&hr->run->lock);
	x->job = id;
	snprintf(x->title, sizeof(x->title), "%s", ucl_object_tostring_forced(
	    path_get(ans, "jobs.0.title")));
	run_save(hr->run);
	pthread_mutex_unlock(&hr->run->lock);
	ucl_object_unref(ans);
	until = time(NULL) + JOB_WAIT_S;
	for (;;) {
		usleep(JOB_POLL_US);
		if ((json = hosts_job(hr->h.uri, hr->h.peer, hr->h.name, id,
		    &status)) == NULL || (jr = parse(json)) == NULL) {
			free(json);
			if (time(NULL) > until) {
				step_set(hr, k, "failed", "the host did not "
				    "say how the job ended");
				return (false);
			}
			continue;
		}
		st = ucl_object_tostring_forced(path_get(jr, "job.state"));
		if (strcmp(st, "done") == 0 || strcmp(st, "cancelled") == 0) {
			/* Done is how it ended, ok whether it did it. */
			ok = strcmp(st, "done") == 0 && ucl_object_type(
			    path_get(jr, "job.ok")) == UCL_BOOLEAN &&
			    ucl_object_toboolean(path_get(jr, "job.ok"));
			pthread_mutex_lock(&hr->run->lock);
			free(x->trace);
			x->trace = strlen(json) < TRACE_MAX ? strdup(json) :
			    NULL;
			pthread_mutex_unlock(&hr->run->lock);
			/* What it answered, for the steps after. */
			ucl_object_insert_key(hr->answers, ucl_object_ref(jr),
			    ucl_object_tostring(ucl_object_lookup(step, "id")),
			    0, true);
			step_set(hr, k, ok ? "done" : "failed", ok ? NULL : "%s",
			    ok ? NULL : ucl_object_tostring_forced(path_get(jr,
			    "job.error")));
			ucl_object_unref(jr);
			free(json);
			return (ok);
		}
		ucl_object_unref(jr);
		free(json);
		if (cancelled(hr->run) || time(NULL) > until) {
			step_set(hr, k, "cancelled", cancelled(hr->run) ?
			    "stopped" : "it took more than an hour");
			return (false);
		}
	}
}

/* A read of a step, kept for the steps after. */
static bool
run_read(struct hostrun *hr, int k, const ucl_object_t *step)
{
	ucl_object_t	*ans;
	char		*json;
	int		 status;

	json = hosts_read(hr->h.uri, hr->h.peer, hr->h.name, ucl_str(step,
	    "read"), &status);
	ans = parse(json);
	if (status != 200 || ans == NULL) {
		step_set(hr, k, "failed", "the host did not answer");
		free(json);
		if (ans != NULL)
			ucl_object_unref(ans);
		return (false);
	}
	pthread_mutex_lock(&hr->run->lock);
	free(hr->steps[k].trace);
	hr->steps[k].trace = strlen(json) < TRACE_MAX ? strdup(json) : NULL;
	pthread_mutex_unlock(&hr->run->lock);
	free(json);
	ucl_object_insert_key(hr->answers, ans, ucl_str(step, "id"), 0, true);
	step_set(hr, k, "done", NULL);
	return (true);
}

/*
 * Arcana itself, from the repository agent_source names (web.conf):
 *
 *	check	the commit at its head, asked of the step's host, beside
 *		the one last built, the one the agents were last sent and
 *		the one the console last updated itself to: {"commit",
 *		"built", "agents", "updated", "new_agents", "new_console",
 *		"new"}, each new when the head is not that, and new when
 *		either is
 *	build	arcana-agent built on the step's host, kept to be sent
 *	agents	that agent sent to every host of the console, each
 *		restarted with it
 *	console	the console updated where it runs, through the step's
 *		host, which is the one it runs on (a server added by its
 *		local socket); it restarts once the step has ended
 *
 * What was built and updated to is kept in arcana-source.json.
 */
#define	SOURCE_FILE	"arcana-source.json"

static pthread_mutex_t	source_lock = PTHREAD_MUTEX_INITIALIZER;

static ucl_object_t *
source_state(void)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	char			 path[MAXPATHLEN];

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, SOURCE_FILE);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	o = ucl_parser_add_file(p, path) ? ucl_parser_get_object(p) : NULL;
	ucl_parser_free(p);
	return (o != NULL ? o : ucl_object_typed_new(UCL_OBJECT));
}

static void
source_note(const char *key, const char *commit)
{
	ucl_object_t	*o;
	unsigned char	*json;
	char		 path[MAXPATHLEN], tmp[MAXPATHLEN];
	FILE		*fp;

	if (commit == NULL || commit[0] == '\0')
		return;
	pthread_mutex_lock(&source_lock);
	o = source_state();
	put(o, key, ucl_object_fromstring(commit));
	json = ucl_object_emit(o, UCL_EMIT_JSON);
	ucl_object_unref(o);
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, SOURCE_FILE);
	snprintf(tmp, sizeof(tmp), "%s.new", path);
	if (json != NULL && (fp = fopen(tmp, "we")) != NULL) {
		fputs((char *)json, fp);
		if (fclose(fp) == 0)
			(void)rename(tmp, path);
	}
	free(json);
	pthread_mutex_unlock(&source_lock);
}

/* An answer of a call: kept as the step's trace and for the steps after. */
static void
step_answer(struct hostrun *hr, int k, const ucl_object_t *step,
    ucl_object_t *ans)
{
	unsigned char	*json;

	json = ucl_object_emit(ans, UCL_EMIT_JSON_COMPACT);
	pthread_mutex_lock(&hr->run->lock);
	free(hr->steps[k].trace);
	hr->steps[k].trace = json != NULL && strlen((char *)json) < TRACE_MAX ?
	    strdup((char *)json) : NULL;
	pthread_mutex_unlock(&hr->run->lock);
	free(json);
	ucl_object_insert_key(hr->answers, ans, ucl_str(step, "id"), 0, true);
}

/* One call of Arcana's to a host, as JSON; NULL and why when it failed. */
static ucl_object_t *
arcana_call(const struct hostref *h, const char *what, char *why,
    size_t len)
{
	ucl_object_t	*ans;
	char		*json;
	int		 status;

	json = hosts_arcana(h->uri, h->peer, h->name, what, &status);
	ans = parse(json);
	free(json);
	if (ans == NULL || status != 200 || !ucl_object_toboolean(
	    ucl_object_lookup(ans, "ok"))) {
		snprintf(why, len, "%s: %s", h->name, ans != NULL && ucl_str(ans,
		    "error") != NULL ? ucl_str(ans, "error") : ans != NULL &&
		    ucl_str(ans, "host_keys") != NULL ? "its SSH host key is "
		    "to be confirmed by hand first (Build agent here)" :
		    "the host did not answer");
		if (ans != NULL)
			ucl_object_unref(ans);
		return (NULL);
	}
	return (ans);
}

/*
 * A notify step: its text, ${...} made what it says for the host, sent
 * by mail, by Telegram or both (alert_send), as Settings have them set
 * up; said as the workflow's, on the host.
 */
static bool
run_notify(struct hostrun *hr, int k, const ucl_object_t *step)
{
	const ucl_object_t	*nt;
	ucl_object_t		*ans;
	char			*text, subject[300], err[600];
	int			 rc;

	nt = ucl_object_lookup(step, "notify");
	text = expand(ucl_str(nt, "text"), hr->run->params, &hr->h,
	    hr->answers, hr->run->event);
	snprintf(subject, sizeof(subject), "Arcana: workflow %s on %s",
	    ucl_str(hr->run->wf, "name") != NULL ? ucl_str(hr->run->wf,
	    "name") : "?", hr->h.name);
	/* Gone by one way of two: done, and what did not go said; sent
	 * again, it would go twice by the other. */
	if ((rc = alert_send(ucl_str(nt, "via"), subject, text, err,
	    sizeof(err))) < 0) {
		free(text);
		step_set(hr, k, "failed", "%s", err);
		return (false);
	}
	ans = ucl_object_typed_new(UCL_OBJECT);
	put(ans, "via", ucl_object_fromstring(ucl_str(nt, "via")));
	put(ans, "text", ucl_object_fromstring(text));
	if (rc > 0)
		put(ans, "not_sent", ucl_object_fromstring(err));
	free(text);
	step_answer(hr, k, step, ans);
	step_set(hr, k, "done", NULL);
	return (true);
}

static bool
run_arcana(struct hostrun *hr, int k, const ucl_object_t *step)
{
	struct hostref	 all[256];
	ucl_object_t	*ans, *st, *list, *one;
	const char	*what, *head, *updated, *agents;
	char		 why[400];
	char		 who[sizeof(((struct hoststep *)0)->error)];
	int		 i, n, failed;
	bool		 na, nc;

	what = ucl_str(step, "arcana");
	if (cfg.agent_source == NULL) {
		step_set(hr, k, "failed", "agent_source in web.conf names no "
		    "repository");
		return (false);
	}
	if (strcmp(what, "check") == 0) {
		if ((ans = arcana_call(&hr->h, "source-head", why,
		    sizeof(why))) == NULL) {
			step_set(hr, k, "failed", "%s", why);
			return (false);
		}
		pthread_mutex_lock(&source_lock);
		st = source_state();
		pthread_mutex_unlock(&source_lock);
		head = ucl_str(ans, "commit");
		updated = ucl_str(st, "updated");
		agents = ucl_str(st, "agents");
		put(ans, "built", ucl_object_fromstring(ucl_str(st, "built") !=
		    NULL ? ucl_str(st, "built") : ""));
		put(ans, "agents", ucl_object_fromstring(agents != NULL ?
		    agents : ""));
		put(ans, "updated", ucl_object_fromstring(updated != NULL ?
		    updated : ""));
		na = head != NULL && (agents == NULL || strcmp(head, agents) !=
		    0);
		nc = head != NULL && (updated == NULL || strcmp(head, updated) !=
		    0);
		put(ans, "new_agents", ucl_object_frombool(na));
		put(ans, "new_console", ucl_object_frombool(nc));
		put(ans, "new", ucl_object_frombool(na || nc));
		ucl_object_unref(st);
		step_answer(hr, k, step, ans);
		step_set(hr, k, "done", NULL);
		return (true);
	}
	if (strcmp(what, "build") == 0 || strcmp(what, "console") == 0) {
		if (strcmp(what, "console") == 0 && strncmp(hr->h.uri, "unix:",
		    5) != 0) {
			step_set(hr, k, "failed", "the console is updated "
			    "through the agent of the host it runs on: a "
			    "server added by its local socket");
			return (false);
		}
		if ((ans = arcana_call(&hr->h, strcmp(what, "build") == 0 ?
		    "agent-build" : "console-update", why, sizeof(why))) ==
		    NULL) {
			step_set(hr, k, "failed", "%s", why);
			return (false);
		}
		source_note(strcmp(what, "build") == 0 ? "built" : "updated",
		    ucl_str(ans, "commit"));
		step_answer(hr, k, step, ans);
		step_set(hr, k, "done", NULL);
		return (true);
	}
	/* agents: every host the console has, one after the other. */
	pthread_mutex_lock(&ref_lock);
	n = nrefs;
	memcpy(all, refs, sizeof(all[0]) * (size_t)n);
	pthread_mutex_unlock(&ref_lock);
	list = ucl_object_typed_new(UCL_ARRAY);
	failed = 0;
	who[0] = '\0';
	for (i = 0; i < n && !cancelled(hr->run); i++) {
		one = ucl_object_typed_new(UCL_OBJECT);
		put(one, "host", ucl_object_fromstring(all[i].name));
		if ((ans = arcana_call(&all[i], "agent-update", why,
		    sizeof(why))) == NULL) {
			failed++;
			put(one, "ok", ucl_object_frombool(false));
			put(one, "error", ucl_object_fromstring(why));
			/* Who did not, and why, said in the step's error. */
			snprintf(who + strlen(who), sizeof(who) - strlen(who),
			    "%s%s", who[0] != '\0' ? "; " : "", why);
		} else {
			put(one, "ok", ucl_object_frombool(true));
			if (ucl_str(ans, "version") != NULL)
				put(one, "version", ucl_object_fromstring(
				    ucl_str(ans, "version")));
			ucl_object_unref(ans);
		}
		ucl_array_append(list, one);
	}
	ans = ucl_object_typed_new(UCL_OBJECT);
	put(ans, "hosts", list);
	put(ans, "failed", ucl_object_fromint(failed));
	step_answer(hr, k, step, ans);
	if (failed > 0) {
		step_set(hr, k, "failed", "%d of %d hosts did not take it "
		    "(%s)", failed, n, who);
		return (false);
	}
	/* What they run now: what was built last. */
	pthread_mutex_lock(&source_lock);
	st = source_state();
	pthread_mutex_unlock(&source_lock);
	if (ucl_str(st, "built") != NULL)
		source_note("agents", ucl_str(st, "built"));
	ucl_object_unref(st);
	step_set(hr, k, "done", NULL);
	return (true);
}

/* Is a step's condition met?  Its read made now, when it has one. */
static bool
condition(struct hostrun *hr, const ucl_object_t *when)
{
	const ucl_object_t	*root;
	ucl_object_t		*ans;
	char			*json, *path;
	int			 status;
	bool			 met;

	ans = NULL;
	if (ucl_str(when, "read") != NULL) {
		json = hosts_read(hr->h.uri, hr->h.peer, hr->h.name,
		    ucl_str(when, "read"), &status);
		ans = parse(json);
		free(json);
		root = ans;
	} else
		root = ucl_object_lookup(hr->answers, ucl_str(when, "step"));
	path = expand(ucl_str(when, "path") != NULL ? ucl_str(when, "path") :
	    "", hr->run->params, &hr->h, hr->answers, hr->run->event);
	met = test(path_get(root, path), ucl_str(when, "op"), ucl_str(when,
	    "value"));
	free(path);
	if (ans != NULL)
		ucl_object_unref(ans);
	return (met);
}

static void *
host_run(void *arg)
{
	struct hostrun		*hr = arg;
	const ucl_object_t	*steps, *step, *when;
	const char		*of;
	int			 k, j, n;
	bool			 ok, stopped;

	steps = ucl_object_lookup(hr->run->wf, "steps");
	n = hr->run->nsteps;
	stopped = false;
	for (k = 0; k < n; k++) {
		step = ucl_array_find_index(steps, (unsigned int)k);
		if (stopped || cancelled(hr->run)) {
			step_set(hr, k, cancelled(hr->run) ? "cancelled" :
			    "not run", NULL);
			continue;
		}
		if ((when = ucl_object_lookup(step, "when")) != NULL &&
		    !condition(hr, when)) {
			step_set(hr, k, "skipped", NULL);
			continue;
		}
		step_set(hr, k, "running", NULL);
		ok = ucl_object_lookup(step, "job") != NULL ? run_job(hr, k,
		    step) : ucl_object_lookup(step, "arcana") != NULL ?
		    run_arcana(hr, k, step) : ucl_object_lookup(step,
		    "notify") != NULL ? run_notify(hr, k, step) : run_read(hr,
		    k, step);
		if (ok)
			continue;
		of = ucl_str(step, "on_fail");
		if (strcmp(of, "continue") == 0)
			continue;
		if (strcmp(of, "stop") == 0) {
			stopped = true;
			continue;
		}
		/* On at a later step: those between are not run. */
		for (j = k + 1; j < n; j++) {
			if (strcmp(ucl_str(ucl_array_find_index(steps,
			    (unsigned int)j), "id"), of) == 0)
				break;
			step_set(hr, j, "not run", NULL);
		}
		k = j - 1;
	}
	pthread_mutex_lock(&hr->run->lock);
	snprintf(hr->state, sizeof(hr->state), "%s", cancelled(hr->run) ?
	    "cancelled" : stopped ? "failed" : "done");
	for (k = 0; k < n && !stopped; k++)
		if (strcmp(hr->steps[k].state, "failed") == 0)
			snprintf(hr->state, sizeof(hr->state), "failed");
	run_save(hr->run);
	pthread_mutex_unlock(&hr->run->lock);
	return (NULL);
}

static int		 nrunning;
static pthread_mutex_t	 running_lock = PTHREAD_MUTEX_INITIALIZER;
static char		 running_wf[64][9];	/* those running now */

static void *
run_main(void *arg)
{
	struct run	*r = arg;
	int		 i, k;
	bool		 failed;

	for (i = 0; i < r->nhosts; i++)
		r->hosts[i].started = pthread_create(&r->hosts[i].thread,
		    NULL, host_run, &r->hosts[i]) == 0;
	for (i = 0; i < r->nhosts; i++)
		if (r->hosts[i].started)
			(void)pthread_join(r->hosts[i].thread, NULL);
		else
			snprintf(r->hosts[i].state, sizeof(r->hosts[i].state),
			    "failed");
	failed = false;
	for (i = 0; i < r->nhosts; i++)
		failed = failed || strcmp(r->hosts[i].state, "done") != 0;
	pthread_mutex_lock(&r->lock);
	snprintf(r->state, sizeof(r->state), "%s", r->cancel ? "cancelled" :
	    failed ? "failed" : "done");
	r->ended = time(NULL);
	run_save(r);
	pthread_mutex_unlock(&r->lock);
	thread_log(LOG_NOTICE, "workflow %s, run %u: %s",
	    ucl_str(r->wf, "name"), r->id, r->state);
	mail_run(ucl_str(r->wf, "name"), r->id, r->state);
	pthread_mutex_lock(&running_lock);
	for (k = 0; k < 64; k++)
		if (strcmp(running_wf[k], ucl_str(r->wf, "id")) == 0) {
			running_wf[k][0] = '\0';
			break;
		}
	nrunning--;
	pthread_mutex_unlock(&running_lock);
	for (i = 0; i < r->nhosts; i++) {
		for (k = 0; k < r->nsteps; k++)
			free(r->hosts[i].steps[k].trace);
		ucl_object_unref(r->hosts[i].answers);
	}
	ucl_object_unref(r->wf);
	ucl_object_unref(r->params);
	if (r->event != NULL)
		ucl_object_unref(r->event);
	pthread_mutex_destroy(&r->lock);
	free(r);
	return (NULL);
}

static bool
wf_running(const char *id)
{
	int	k;
	bool	yes;

	yes = false;
	pthread_mutex_lock(&running_lock);
	for (k = 0; k < 64 && !yes; k++)
		yes = strcmp(running_wf[k], id) == 0;
	pthread_mutex_unlock(&running_lock);
	return (yes);
}

/*
 * A run of wf begun on its hosts, or on hosts when given; params over
 * the defaults; event what began it.  Its number, or 0 and why.
 */
static uint32_t
run_start(const ucl_object_t *wf, const ucl_object_t *hosts,
    const ucl_object_t *params, const ucl_object_t *event,
    const char *trigger, const char **whyp)
{
	struct run		*r;
	const ucl_object_t	*v, *p;
	ucl_object_iter_t	 it;
	pthread_t		 tid;
	int			 k;

	if (hosts == NULL || ucl_array_size(hosts) == 0)
		hosts = ucl_object_lookup(wf, "hosts");
	if (ucl_array_size(hosts) == 0) {
		*whyp = "no host to run on";
		return (0);
	}
	if ((r = calloc(1, sizeof(*r))) == NULL) {
		*whyp = "out of memory";
		return (0);
	}
	pthread_mutex_init(&r->lock, NULL);
	r->wf = ucl_object_copy(wf);
	r->nsteps = (int)ucl_array_size(ucl_object_lookup(wf, "steps"));
	/* The parameters: what was given, else each one's default. */
	r->params = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while ((p = ucl_object_iterate(ucl_object_lookup(wf, "params"), &it,
	    true)) != NULL) {
		v = ucl_object_lookup(params, ucl_str(p, "name"));
		put(r->params, ucl_str(p, "name"), ucl_object_fromstring(v !=
		    NULL ? ucl_object_tostring_forced(v) : ucl_str(p,
		    "default")));
	}
	r->event = event != NULL ? ucl_object_copy(event) : NULL;
	snprintf(r->trigger, sizeof(r->trigger), "%s", trigger);
	snprintf(r->state, sizeof(r->state), "running");
	r->started = time(NULL);
	{
		struct timespec	ts;

		clock_gettime(CLOCK_REALTIME, &ts);
		r->began = ts.tv_sec + ts.tv_nsec / 1e9;
	}
	arc4random_buf(&r->id, sizeof(r->id));
	r->id &= 0x7fffffff;
	it = NULL;
	while ((v = ucl_object_iterate(hosts, &it, true)) != NULL &&
	    r->nhosts < RUN_HOSTS_MAX) {
		struct hostrun	*hr = &r->hosts[r->nhosts];

		if (!ref_get(ucl_object_tostring_forced(v), &hr->h))
			continue;
		hr->run = r;
		hr->answers = ucl_object_typed_new(UCL_OBJECT);
		snprintf(hr->state, sizeof(hr->state), "running");
		for (k = 0; k < r->nsteps; k++)
			snprintf(hr->steps[k].state, sizeof(hr->steps[k].state),
			    "pending");
		r->nhosts++;
	}
	if (r->nhosts == 0) {
		ucl_object_unref(r->wf);
		ucl_object_unref(r->params);
		if (r->event != NULL)
			ucl_object_unref(r->event);
		free(r);
		*whyp = "none of its hosts is a server now";
		return (0);
	}
	pthread_mutex_lock(&running_lock);
	if (nrunning >= 64) {
		pthread_mutex_unlock(&running_lock);
		*whyp = "64 runs at once at most";
		goto fail;
	}
	nrunning++;
	for (k = 0; k < 64; k++)
		if (running_wf[k][0] == '\0') {
			snprintf(running_wf[k], sizeof(running_wf[k]), "%s",
			    ucl_str(wf, "id"));
			break;
		}
	pthread_mutex_unlock(&running_lock);
	pthread_mutex_lock(&r->lock);
	run_save(r);
	pthread_mutex_unlock(&r->lock);
	if (pthread_create(&tid, NULL, run_main, r) != 0) {
		*whyp = "no thread for it";
		pthread_mutex_lock(&running_lock);
		nrunning--;
		pthread_mutex_unlock(&running_lock);
		goto fail;
	}
	(void)pthread_detach(tid);
	return (r->id);
fail:
	for (k = 0; k < r->nhosts; k++)
		ucl_object_unref(r->hosts[k].answers);
	ucl_object_unref(r->wf);
	ucl_object_unref(r->params);
	if (r->event != NULL)
		ucl_object_unref(r->event);
	free(r);
	return (0);
}

/* ---- By itself: at intervals, on events ---------------------------- */

struct watched {
	char		 sid[9];
	/* The subscription's, its thread's alone. */
	uint64_t	 last;		/* the newest event seen */
	bool		 known;		/* last is what it says */
	bool		 down;
	/* Between the two. */
	atomic_bool	 running;	/* its thread is there */
	atomic_bool	 stop;		/* no workflow waits on it now */
	/* What the subscription heard, for the thread to look at. */
	pthread_mutex_t	 qlock;
	char		*queue[SUB_QUEUE];
	int		 nqueue;
	bool		 lost;		/* the queue was full: read again */
};

static struct watched	watched[256];
static int		nwatched;

static struct watched *
watched_of(const char *sid)
{
	struct watched	*x;
	int		 i;

	for (i = 0; i < nwatched; i++)
		if (strcmp(watched[i].sid, sid) == 0)
			return (&watched[i]);
	if (nwatched == (int)nitems(watched))
		return (NULL);
	x = &watched[nwatched++];
	memset(x, 0, sizeof(*x));
	snprintf(x->sid, sizeof(x->sid), "%s", sid);
	pthread_mutex_init(&x->qlock, NULL);
	return (x);
}

/*
 * Does an event match a trigger: its name, and each of match's?  A
 * value ${param.NAME} is that parameter's default, the run's to be: an
 * empty one matches any.
 */
static bool
matches(const ucl_object_t *wf, const ucl_object_t *on, const char *kind,
    const ucl_object_t *data)
{
	const ucl_object_t	*m, *v, *p;
	ucl_object_iter_t	 it, pit;
	const char		*want;
	size_t			 len;

	if (strcmp(ucl_str(on, "event"), kind) != 0)
		return (false);
	it = NULL;
	while ((m = ucl_object_iterate(ucl_object_lookup(on, "match"), &it,
	    true)) != NULL) {
		want = ucl_object_tostring_forced(m);
		len = strlen(want);
		if (strncmp(want, "${param.", 8) == 0 && len > 9 &&
		    want[len - 1] == '}') {
			pit = NULL;
			while ((p = ucl_object_iterate(ucl_object_lookup(wf,
			    "params"), &pit, true)) != NULL)
				if (ucl_str(p, "name") != NULL && strlen(ucl_str(p,
				    "name")) == len - 9 && strncmp(ucl_str(p,
				    "name"), want + 8, len - 9) == 0)
					break;
			want = p != NULL && ucl_str(p, "default") != NULL ?
			    ucl_str(p, "default") : "";
			if (want[0] == '\0')
				continue;
		}
		v = ucl_object_lookup(data, ucl_object_key(m));
		if (v == NULL || strcmp(ucl_object_tostring_forced(v), want) !=
		    0)
			return (false);
	}
	return (true);
}

/* An event on a host: each workflow it begins runs there. */
static void
fire(const ucl_object_t *wfs, const char *sid, const char *kind,
    const ucl_object_t *data)
{
	const ucl_object_t	*w, *on, *h;
	ucl_object_iter_t	 it, oit, hit;
	ucl_object_t		*hosts, *ev;
	const char		*why;
	char			 trig[64];
	bool			 mine;

	it = NULL;
	while ((w = ucl_object_iterate(wfs, &it, true)) != NULL) {
		mine = false;
		hit = NULL;
		while ((h = ucl_object_iterate(ucl_object_lookup(w, "hosts"),
		    &hit, true)) != NULL)
			mine = mine || strcmp(ucl_object_tostring_forced(h),
			    sid) == 0;
		if (!mine || wf_running(ucl_str(w, "id")))
			continue;
		oit = NULL;
		while ((on = ucl_object_iterate(ucl_object_lookup(w, "on"),
		    &oit, true)) != NULL) {
			if (!matches(w, on, kind, data))
				continue;
			hosts = ucl_object_typed_new(UCL_ARRAY);
			ucl_array_append(hosts, ucl_object_fromstring(sid));
			/* host-down and host-up have nothing but what they are. */
			ev = data != NULL ? ucl_object_copy(data) :
			    ucl_object_typed_new(UCL_OBJECT);
			put(ev, "kind", ucl_object_fromstring(kind));
			put(ev, "host", ucl_object_fromstring(sid));
			snprintf(trig, sizeof(trig), "event %s", kind);
			(void)run_start(w, hosts, NULL, ev, trig, &why);
			ucl_object_unref(hosts);
			ucl_object_unref(ev);
			break;
		}
	}
}

/* In a subscription's thread: what it heard begins what it begins. */
static void
sub_fire(struct watched *x, const char *kind, const ucl_object_t *data)
{
	ucl_object_t	*top;

	pthread_mutex_lock(&wf_lock);
	top = wf_load();
	pthread_mutex_unlock(&wf_lock);
	fire(ucl_object_lookup(top, "workflows"), x->sid, kind, data);
	ucl_object_unref(top);
}

/* An event, heard or read: once each, and none from before the first. */
static void
sub_event(struct watched *x, const ucl_object_t *e)
{
	uint64_t	n;

	n = (uint64_t)ucl_object_toint(ucl_object_lookup(e, "n"));
	if (n <= x->last)
		return;
	if (x->known)
		sub_fire(x, ucl_object_tostring_forced(ucl_object_lookup(e,
		    "kind")), ucl_object_lookup(e, "data"));
	x->last = n;
}

/*
 * What the host said since it was last heard: read, as the events it
 * keeps.  The first look only says where the events are.  False when
 * it does not answer.
 */
static bool
sub_catch_up(struct watched *x, const struct hostref *h)
{
	ucl_object_t		*ans;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	char			*json;
	int			 status;

	json = hosts_events(h->uri, h->peer, h->name, x->known ? x->last : 0,
	    &status);
	ans = parse(json);
	free(json);
	if (status != 200 || ans == NULL) {
		if (ans != NULL)
			ucl_object_unref(ans);
		return (false);
	}
	it = NULL;
	while ((e = ucl_object_iterate(path_get(ans, "data.events"), &it,
	    true)) != NULL)
		sub_event(x, e);
	if (path_get(ans, "data.last") != NULL && (uint64_t)ucl_object_toint(
	    path_get(ans, "data.last")) > x->last)
		x->last = (uint64_t)ucl_object_toint(path_get(ans,
		    "data.last"));
	x->known = true;
	ucl_object_unref(ans);
	return (true);
}

/* Told by the host: kept for the thread, which looks after each read. */
static void
sub_heard(const struct arc_event_ntf *ntf, void *arg)
{
	struct watched	*x = arg;
	char		*text;

	if (ntf->json == NULL || ntf->json[0] != '{')
		return;
	pthread_mutex_lock(&x->qlock);
	if (x->nqueue == SUB_QUEUE || (text = strdup(ntf->json)) == NULL)
		x->lost = true;
	else
		x->queue[x->nqueue++] = text;
	pthread_mutex_unlock(&x->qlock);
}

/* What was heard, looked at in order; true when some were lost. */
static bool
sub_drain(struct watched *x)
{
	char		*q[SUB_QUEUE];
	ucl_object_t	*e;
	int		 i, n;
	bool		 lost;

	pthread_mutex_lock(&x->qlock);
	n = x->nqueue;
	memcpy(q, x->queue, (size_t)n * sizeof(q[0]));
	x->nqueue = 0;
	lost = x->lost;
	x->lost = false;
	pthread_mutex_unlock(&x->qlock);
	for (i = 0; i < n; i++) {
		if ((e = parse(q[i])) != NULL) {
			sub_event(x, e);
			ucl_object_unref(e);
		}
		free(q[i]);
	}
	return (lost);
}

/* A host that stopped answering, or answers again: once each way. */
static void
sub_state(struct watched *x, bool up)
{

	if (x->down == !up)
		return;
	x->down = !up;
	sub_fire(x, up ? "host-up" : "host-down", NULL);
}

/* Some seconds, or less when told to stop. */
static void
sub_pause(struct watched *x, int seconds)
{
	int	i;

	for (i = 0; i < seconds * 1000 / SUB_WAKE_MS &&
	    !atomic_load(&x->stop); i++)
		(void)poll(NULL, 0, SUB_WAKE_MS);
}

/*
 * A host's events as they come: subscribed to, on a connection of its
 * own, and subscribed to again when it drops.
 */
static void *
sub_run(void *arg)
{
	static const struct arc_events_handlers hd = { .event = sub_heard };
	struct watched		*x = arg;
	struct hostref		 h;
	struct arc_client	 cl;
	struct pollfd		 pfd;
	cbl_conn		*conn;
	cbl_tls			*tls;
	cbl_sub			*sub;
	int			 ev, ms;

	while (!atomic_load(&x->stop)) {
		if (!ref_get(x->sid, &h)) {
			sub_pause(x, SUB_RETRY_S);
			continue;
		}
		if (hosts_connect(h.uri, h.peer, &conn, &tls, &cl) != NULL) {
			sub_state(x, false);
			sub_pause(x, SUB_RETRY_S);
			continue;
		}
		if (arc_events_subscribe(&cl, &hd, x, &sub) != 0) {
			hosts_release(h.uri, h.peer, conn, tls, &cl, false);
			sub_state(x, false);
			sub_pause(x, SUB_RETRY_S);
			continue;
		}
		/* Subscribed first, read after: nothing falls between. */
		if (!sub_catch_up(x, &h)) {
			hosts_release(h.uri, h.peer, conn, tls, &cl, false);
			sub_state(x, false);
			sub_pause(x, SUB_RETRY_S);
			continue;
		}
		sub_state(x, true);
		while (!atomic_load(&x->stop)) {
			if (sub_drain(x) && !sub_catch_up(x, &h))
				break;
			ev = 0;
			ms = -1;
			(void)cbl_conn_interest(conn, &ev, &ms);
			pfd.fd = cbl_conn_fd(conn);
			pfd.events = ((ev & CBL_EV_READ) != 0 ? POLLIN : 0) |
			    ((ev & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
			pfd.revents = 0;
			if (poll(&pfd, 1, ms < 0 || ms > SUB_WAKE_MS ?
			    SUB_WAKE_MS : ms) == -1)
				continue;
			ev = ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) !=
			    0 ? CBL_EV_READ : 0) | ((pfd.revents & POLLOUT) !=
			    0 ? CBL_EV_WRITE : 0);
			if (cbl_conn_process(conn, ev) != 0)
				break;
		}
		(void)sub_drain(x);
		/* A connection with a subscription on it is no one else's. */
		hosts_release(h.uri, h.peer, conn, tls, &cl, false);
		if (!atomic_load(&x->stop)) {
			thread_log(LOG_NOTICE, "workflows: the events of %s "
			    "stopped coming", x->sid);
			sub_state(x, false);
			sub_pause(x, SUB_RETRY_S);
		}
	}
	atomic_store(&x->running, false);
	return (NULL);
}

/* A host a workflow waits on: its subscription, kept or begun. */
static void
sub_keep(struct watched *x)
{
	pthread_t	tid;

	atomic_store(&x->stop, false);
	if (atomic_load(&x->running))
		return;
	atomic_store(&x->running, true);
	if (pthread_create(&tid, NULL, sub_run, x) != 0) {
		atomic_store(&x->running, false);
		return;
	}
	pthread_detach(tid);
}

/* When the workflow last ran by its interval, as every.json keeps it. */
static time_t
every_last(const char *id)
{
	ucl_object_t	*top;
	time_t		 t;

	if ((top = store_load(EVERY_FILE)) == NULL)
		return (0);
	t = (time_t)ucl_object_toint(ucl_object_lookup(top, id));
	ucl_object_unref(top);
	return (t);
}

static void
every_ran(const char *id, time_t t)
{
	ucl_object_t	*top;

	if ((top = store_load(EVERY_FILE)) == NULL)
		top = ucl_object_typed_new(UCL_OBJECT);
	put(top, id, ucl_object_fromint(t));
	(void)store_save(EVERY_FILE, top);
	ucl_object_unref(top);
}

static void *
scheduler(void *arg __unused)
{
	ucl_object_t		*top;
	const ucl_object_t	*w, *h;
	ucl_object_iter_t	 it, hit;
	struct {
		char	id[9];
		time_t	last;
	}			 due[WF_MAX];
	struct watched		*x;
	int			 ndue, k;
	time_t			 now, t;
	const char		*why;
	char			 sids[256][9];
	int			 nsids, s, i;

	ndue = 0;
	for (;;) {
		sleep(TICK_S);
		/* Of a cluster, the leader's alone. */
		if (!cluster_leads())
			continue;
		pthread_mutex_lock(&wf_lock);
		top = wf_load();
		pthread_mutex_unlock(&wf_lock);
		now = time(NULL);
		nsids = 0;
		it = NULL;
		while ((w = ucl_object_iterate(ucl_object_lookup(top,
		    "workflows"), &it, true)) != NULL) {
			int64_t	every;

			every = ucl_object_toint(ucl_object_lookup(w, "every"));
			if (every > 0) {
				for (k = 0; k < ndue; k++)
					if (strcmp(due[k].id, ucl_str(w, "id")) ==
					    0)
						break;
				if (k == ndue && ndue < WF_MAX) {
					/*
					 * Counted from when it last ran by
					 * its interval, which a restart does
					 * not forget; else from now.
					 */
					snprintf(due[k].id, sizeof(due[k].id), "%s",
					    ucl_str(w, "id"));
					t = every_last(due[k].id);
					due[k].last = t > 0 && t <= now ? t : now;
					ndue++;
				}
				if (k < ndue && now - due[k].last >= every &&
				    !wf_running(ucl_str(w, "id"))) {
					due[k].last = now;
					every_ran(due[k].id, now);
					(void)run_start(w, NULL, NULL, NULL,
					    "every", &why);
				}
			}
			/* The hosts whose events it waits for. */
			if (ucl_array_size(ucl_object_lookup(w, "on")) == 0)
				continue;
			hit = NULL;
			while ((h = ucl_object_iterate(ucl_object_lookup(w,
			    "hosts"), &hit, true)) != NULL) {
				for (s = 0; s < nsids; s++)
					if (strcmp(sids[s],
					    ucl_object_tostring_forced(h)) == 0)
						break;
				if (s == nsids && nsids < 256)
					snprintf(sids[nsids++], sizeof(sids[0]),
					    "%s", ucl_object_tostring_forced(h));
			}
		}
		/* Each host waited on is subscribed to; the others not. */
		for (i = 0; i < nwatched; i++) {
			for (s = 0; s < nsids; s++)
				if (strcmp(sids[s], watched[i].sid) == 0)
					break;
			if (s == nsids)
				atomic_store(&watched[i].stop, true);
		}
		for (s = 0; s < nsids; s++) {
			if ((x = watched_of(sids[s])) == NULL)
				continue;
			sub_keep(x);
		}
		ucl_object_unref(top);
	}
	return (NULL);
}

static void
refs_tick(void *arg __unused, uint64_t now __unused)
{

	refs_copy();
}

/*
 * At the worker's start: the servers copied, and copied again every
 * few seconds; runs a restart cut said to be interrupted; and the one
 * worker that takes the lock watches for what runs by itself.
 */
/*
 * A run a restart cut: its hosts and steps that were running said to
 * be interrupted, why with them; those not yet begun not run.
 */
static void
run_cut(ucl_object_t *run)
{
	const ucl_object_t	*h, *st;
	ucl_object_iter_t	 hit, sit;

	hit = NULL;
	while ((h = ucl_object_iterate(ucl_object_lookup(run, "hosts"), &hit,
	    true)) != NULL) {
		if (ucl_str(h, "state") != NULL && strcmp(ucl_str(h, "state"),
		    "running") == 0)
			put((ucl_object_t *)(uintptr_t)h, "state",
			    ucl_object_fromstring("interrupted"));
		sit = NULL;
		while ((st = ucl_object_iterate(ucl_object_lookup(h, "steps"),
		    &sit, true)) != NULL) {
			if (ucl_str(st, "state") == NULL)
				continue;
			if (strcmp(ucl_str(st, "state"), "running") == 0) {
				put((ucl_object_t *)(uintptr_t)st, "state",
				    ucl_object_fromstring("interrupted"));
				put((ucl_object_t *)(uintptr_t)st, "detail",
				    ucl_object_fromstring("the console stopped "
				    "while it ran (restarted, or its worker "
				    "died): what it did on the hosts is not "
				    "known; look at them, or run it again"));
			} else if (strcmp(ucl_str(st, "state"), "pending") == 0)
				put((ucl_object_t *)(uintptr_t)st, "state",
				    ucl_object_fromstring("not run"));
		}
	}
}

/*
 * Every kind jobs.yaml has, one hosts.c can send: a kind added to the
 * one and not the other would be refused as unknown when it is used.
 */
int
workflows_kinds_check(void)
{
	size_t	i;
	int	rc = 0;

	for (i = 0; i < nitems(jobkinds); i++)
		if (!hosts_job_kind_known(jobkinds[i].kind)) {
			kore_log(LOG_ERR, "the job kind %s of jobs.yaml is not "
			    "in hosts.c's job_kind_names", jobkinds[i].kind);
			rc = -1;
		}
	return (rc);
}

void
workflows_init(void)
{
	ucl_object_t		*top;
	ucl_object_t		*o;
	ucl_object_iter_t	 it;
	pthread_t		 tid;
	char			 path[MAXPATHLEN];
	bool			 changed;

	refs_copy();
	(void)kore_timer_add(refs_tick, 2000, NULL, 0);
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, RUNS_DIR);
	(void)mkdir(path, 0700);
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, WF_LOCK);
	if ((lockfd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1 ||
	    flock(lockfd, LOCK_EX | LOCK_NB) == -1) {
		if (lockfd != -1)
			close(lockfd);
		lockfd = -1;
		return;
	}
	/* This worker is the one: what a restart cut was cut.  Not of a
	 * cluster's node, whose runs may be another node's, running. */
	if (!cluster_on() && (top = store_load(RUNS_FILE)) != NULL) {
		changed = false;
		it = NULL;
		while ((o = (ucl_object_t *)(uintptr_t)ucl_object_iterate(
		    ucl_object_lookup(top, "runs"), &it, true)) != NULL)
			if (ucl_str(o, "state") != NULL && strcmp(ucl_str(o,
			    "state"), "running") == 0) {
				put(o, "state", ucl_object_fromstring(
				    "interrupted"));
				run_cut(o);
				changed = true;
			}
		if (changed)
			(void)store_save(RUNS_FILE, top);
		ucl_object_unref(top);
	}
	if (pthread_create(&tid, NULL, scheduler, NULL) == 0)
		(void)pthread_detach(tid);
}

/* ---- The API --------------------------------------------------------- */

static int
reply_list(struct http_request *req, const char *file, const char *key,
    bool traces)
{
	ucl_object_t		*top, *out, *arr, *c;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	pthread_mutex_lock(&wf_lock);
	top = store_load(file);
	pthread_mutex_unlock(&wf_lock);
	out = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while (top != NULL && (e = ucl_object_iterate(ucl_object_lookup(top,
	    key), &it, true)) != NULL) {
		c = ucl_object_copy(e);
		/* The list without each step's trace: one run has them. */
		if (!traces) {
			const ucl_object_t	*h, *s;
			ucl_object_iter_t	 hit, sit;

			hit = NULL;
			while ((h = ucl_object_iterate(ucl_object_lookup(c,
			    "hosts"), &hit, true)) != NULL) {
				sit = NULL;
				while ((s = ucl_object_iterate(
				    ucl_object_lookup(h, "steps"), &sit,
				    true)) != NULL)
					(void)ucl_object_delete_key(
					    (ucl_object_t *)(uintptr_t)s,
					    "trace");
			}
		}
		ucl_array_append(arr, c);
	}
	if (top != NULL)
		ucl_object_unref(top);
	put(out, key, arr);
	return (reply_json(req, 200, out));
}

int
api_workflows(struct http_request *req)
{
	ucl_object_t		*body, *w, *top, *keep, *hosts, *params;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*why, *id, *p;
	char			 wid[9], buf[64];
	uint32_t		 n;
	bool			 found;

	refs_copy();
	if (req->method == HTTP_METHOD_GET) {
		if (!guard(req, false))
			return (KORE_RESULT_OK);
		return (reply_list(req, WF_FILE, "workflows", true));
	}
	if (!guard(req, true))
		return (KORE_RESULT_OK);
	/* /api/workflows/<id>[/run] */
	wid[0] = '\0';
	if (strncmp(req->path, "/api/workflows/", 15) == 0)
		snprintf(wid, sizeof(wid), "%.8s", req->path + 15);
	if (req->method == HTTP_METHOD_POST && (p = strstr(req->path,
	    "/run")) != NULL && p[4] == '\0') {
		if ((w = wf_find(wid)) == NULL)
			return (reply_error(req, 404, "not-found", "no such "
			    "workflow"));
		body = read_json(req);
		hosts = body != NULL ? (ucl_object_t *)(uintptr_t)
		    ucl_object_lookup(body, "hosts") : NULL;
		params = body != NULL ? (ucl_object_t *)(uintptr_t)
		    ucl_object_lookup(body, "params") : NULL;
		it = NULL;
		while ((e = ucl_object_iterate(hosts, &it, true)) != NULL) {
			struct hostref	h;

			if (!ref_get(ucl_object_tostring_forced(e), &h)) {
				ucl_object_unref(w);
				ucl_object_unref(body);
				return (reply_error(req, 404, "not_found",
				    "no such server"));
			}
			/* A change on each host: the user's role there, as a
			 * job on it would ask. */
			if (!host_allowed(req, ucl_object_tostring_forced(e),
			    true, false)) {
				ucl_object_unref(w);
				ucl_object_unref(body);
				return (KORE_RESULT_OK);
			}
		}
		n = run_start(w, hosts, params, NULL, "hand", &why);
		ucl_object_unref(w);
		if (body != NULL)
			ucl_object_unref(body);
		if (n == 0)
			return (reply_error(req, 409, "not-run", "%s", why));
		top = ucl_object_typed_new(UCL_OBJECT);
		put(top, "run", ucl_object_fromint(n));
		return (reply_json(req, 200, top));
	}
	pthread_mutex_lock(&wf_lock);
	top = wf_load();
	if (req->method == HTTP_METHOD_DELETE) {
		keep = ucl_object_typed_new(UCL_ARRAY);
		found = false;
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(top,
		    "workflows"), &it, true)) != NULL)
			if (strcmp(ucl_str(e, "id"), wid) == 0) {
				found = true;
				/* Said in the log, as a server removed is. */
				kore_log(LOG_NOTICE, "workflow %s deleted: %s", wid,
				    ucl_str(e, "name") != NULL ? ucl_str(e, "name") :
				    "");
			} else
				ucl_array_append(keep, ucl_object_copy(e));
		put(top, "workflows", keep);
		if (found)
			(void)store_save(WF_FILE, top);
		pthread_mutex_unlock(&wf_lock);
		ucl_object_unref(top);
		if (!found)
			return (reply_error(req, 404, "not-found", "no such "
			    "workflow"));
		top = ucl_object_typed_new(UCL_OBJECT);
		put(top, "ok", ucl_object_frombool(true));
		return (reply_json(req, 200, top));
	}
	pthread_mutex_unlock(&wf_lock);
	ucl_object_unref(top);
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "a workflow, as JSON"));
	w = wf_check(body, &why);
	ucl_object_unref(body);
	if (w == NULL)
		return (reply_error(req, 400, "invalid", "%s", why));
	/* In its place, or as the newest. */
	pthread_mutex_lock(&wf_lock);
	top = wf_load();
	keep = ucl_object_typed_new(UCL_ARRAY);
	found = false;
	id = ucl_str(w, "id");
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(top, "workflows"),
	    &it, true)) != NULL) {
		if (strcmp(ucl_str(e, "id"), id) == 0) {
			ucl_array_append(keep, ucl_object_ref(w));
			found = true;
		} else
			ucl_array_append(keep, ucl_object_copy(e));
	}
	if (!found && ucl_array_size(keep) >= WF_MAX) {
		pthread_mutex_unlock(&wf_lock);
		ucl_object_unref(keep);
		ucl_object_unref(top);
		ucl_object_unref(w);
		snprintf(buf, sizeof(buf), "%d workflows at most", WF_MAX);
		return (reply_error(req, 409, "full", "%s", buf));
	}
	if (!found)
		ucl_array_append(keep, ucl_object_ref(w));
	put(top, "workflows", keep);
	(void)store_save(WF_FILE, top);
	kore_log(LOG_NOTICE, "workflow %s %s: %s", ucl_str(w, "id") != NULL ?
	    ucl_str(w, "id") : "", found ? "changed" : "made", ucl_str(w,
	    "name") != NULL ? ucl_str(w, "name") : "");
	pthread_mutex_unlock(&wf_lock);
	ucl_object_unref(top);
	return (reply_json(req, 200, w));
}

int
api_runs(struct http_request *req)
{
	ucl_object_t		*top, *one;
	ucl_object_t		*e;
	ucl_object_iter_t	 it;
	uint32_t		 n;
	bool			 all;

	all = strcmp(req->path, "/api/runs") == 0;
	if (req->method == HTTP_METHOD_GET) {
		if (!guard(req, false))
			return (KORE_RESULT_OK);
		if (all)
			return (reply_list(req, RUNS_FILE, "runs", false));
	} else if (!guard(req, true))
		return (KORE_RESULT_OK);
	n = (uint32_t)strtoul(strrchr(req->path, '/') + 1, NULL, 10);
	pthread_mutex_lock(&wf_lock);
	top = store_load(RUNS_FILE);
	one = NULL;
	it = NULL;
	while (top != NULL && (e = (ucl_object_t *)(uintptr_t)
	    ucl_object_iterate(ucl_object_lookup(top, "runs"), &it, true)) !=
	    NULL)
		if ((uint32_t)ucl_object_toint(ucl_object_lookup(e, "id")) == n)
			one = e;
	if (one == NULL) {
		pthread_mutex_unlock(&wf_lock);
		if (top != NULL)
			ucl_object_unref(top);
		return (reply_error(req, 404, "not-found", "no such run"));
	}
	if (req->method == HTTP_METHOD_DELETE) {
		/* A stop: the run's threads see it when they write next. */
		if (strcmp(ucl_str(one, "state"), "running") != 0) {
			pthread_mutex_unlock(&wf_lock);
			ucl_object_unref(top);
			return (reply_error(req, 409, "ended", "it ended"));
		}
		put(one, "cancel", ucl_object_frombool(true));
		(void)store_save(RUNS_FILE, top);
		pthread_mutex_unlock(&wf_lock);
		ucl_object_unref(top);
		top = ucl_object_typed_new(UCL_OBJECT);
		put(top, "ok", ucl_object_frombool(true));
		return (reply_json(req, 200, top));
	}
	/* With its traces, from its own file; its state as the list has
	 * it, which a restart may have made interrupted. */
	{
		ucl_object_t	*full;
		char		 file[64];

		if ((full = store_load(run_file(n, file, sizeof(file)))) !=
		    NULL) {
			put(full, "state", ucl_object_copy(ucl_object_lookup(
			    one, "state")));
			if (strcmp(ucl_str(full, "state"), "interrupted") == 0)
				run_cut(full);
			one = full;
		} else
			one = ucl_object_ref(one);
	}
	pthread_mutex_unlock(&wf_lock);
	ucl_object_unref(top);
	return (reply_json(req, 200, one));
}
