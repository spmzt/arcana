/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Updates: the console asks the release feed, in a task thread, for the
 * newest version, remembers the answer for a while, and tells the UI
 * when a newer one exists.  It does not replace itself: the console runs
 * unprivileged, and how it is updated depends on how it was installed
 * (the package, or the container image); the UI says which.
 */

#include <sys/param.h>

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <fetch.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "console.h"

#define	UPDATE_CACHE	(6 * 60 * 60)
#define	UPDATE_MAX	(64 * 1024)
#define	NOTES_CACHE	(5 * 60)

struct check {
	struct kore_task	 task;		/* first: Kore frees the check */
	char			 latest[64];
	char			 url[512];
	char			 error[256];
	char			 feed[1024];	/* asked of: cfg may change */
};

static struct {
	char	latest[64];
	char	url[512];
	char	error[256];
	time_t	checked;
} cache;

static int	 newer(const char *, const char *);
static int	 check_run(struct kore_task *);
static int	 reply(struct http_request *);

/* Is version a newer than b?  "v1.2.3" and "1.2.3" compare as numbers. */
static int
newer(const char *a, const char *b)
{
	char	*ea, *eb;
	long	x, y;

	if (*a == 'v')
		a++;
	if (*b == 'v')
		b++;
	for (;;) {
		x = strtol(a, &ea, 10);
		y = strtol(b, &eb, 10);
		if (x != y)
			return (x > y);
		if (*ea != '.' || *eb != '.')
			return (0);
		a = ea + 1;
		b = eb + 1;
	}
}

/* In a task thread: the release feed's newest tag. */
static int
check_run(struct kore_task *t)
{
	struct check		*c;
	struct ucl_parser	*p;
	ucl_object_t		*o;
	const char		*tag, *url;
	FILE			*fp;
	char			*buf;
	size_t			 len, n;

	c = (struct check *)t;
	if ((fp = fetchGetURL(c->feed, "")) == NULL) {
		snprintf(c->error, sizeof(c->error), "%s", fetchLastErrString);
		return (KORE_RESULT_OK);
	}
	if ((buf = malloc(UPDATE_MAX)) == NULL) {
		fclose(fp);
		snprintf(c->error, sizeof(c->error), "out of memory");
		return (KORE_RESULT_OK);
	}
	for (len = 0; len < UPDATE_MAX - 1; len += n)
		if ((n = fread(buf + len, 1, UPDATE_MAX - 1 - len, fp)) == 0)
			break;
	buf[len] = '\0';
	fclose(fp);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_string(p, buf, len))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	free(buf);
	tag = o != NULL ? ucl_str(o, "tag_name") : NULL;
	url = o != NULL ? ucl_str(o, "html_url") : NULL;
	if (tag == NULL || !isdigit((unsigned char)tag[*tag == 'v']))
		snprintf(c->error, sizeof(c->error), "%s: no release tag in "
		    "the answer", c->feed);
	else {
		strlcpy(c->latest, tag, sizeof(c->latest));
		strlcpy(c->url, url != NULL ? url : "", sizeof(c->url));
	}
	if (o != NULL)
		ucl_object_unref(o);
	return (KORE_RESULT_OK);
}

static int
reply(struct http_request *req)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(ARCW_VERSION), "current",
	    0, false);
	ucl_object_insert_key(o, ucl_object_frombool(cfg.update_url != NULL),
	    "enabled", 0, false);
	if (cache.latest[0] != '\0') {
		ucl_object_insert_key(o, ucl_object_fromstring(cache.latest),
		    "latest", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(cache.url),
		    "url", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(newer(cache.latest,
		    ARCW_VERSION)), "newer", 0, false);
	}
	if (cache.error[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(cache.error),
		    "error", 0, false);
	if (cache.checked != 0)
		ucl_object_insert_key(o, ucl_object_fromint(cache.checked),
		    "checked", 0, false);
	return (reply_json(req, 200, o));
}

/* ---- What is new in the repository ---------------------------------- */

/* The repository's latest commits and tags, as a host last read them. */
static struct {
	ucl_object_t	*ans;
	time_t		 at;
	char		 host[128];
} notes;

/* A host's answer, as it came. */
static ucl_object_t *
parse(const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*top;

	if (json == NULL)
		return (NULL);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	return (top);
}

/* Is version b named in subject s, as "<component> <b>" and no more? */
static bool
names_version(const char *s, const char *component, const char *b)
{
	const char	*p;
	char		 key[96];
	size_t		 n;

	if (s == NULL || b == NULL || b[0] == '\0')
		return (false);
	snprintf(key, sizeof(key), "%s %s", component, b[0] == 'v' ? b + 1 : b);
	n = strlen(key);
	for (p = s; (p = strstr(p, key)) != NULL; p++)
		if ((p == s || !isalnum((unsigned char)p[-1])) && !isdigit(
		    (unsigned char)p[n]) && p[n] != '.')
			return (true);
	return (false);
}

/*
 * GET /api/update/notes?component=console|agent&from=VERSION[&to=VERSION]:
 * what is new in the repository since the version running, for the
 * update boxes and the What's new tab.  The host the console runs on
 * (reached by its local socket), else the first, reads the
 * repository's latest commits and tags (source-log); the tags with
 * messages are the release notes, when any is newer than the version;
 * else the commits are, each marked new when it came after the one
 * that brought the version (its subject names "<component> <version>",
 * as every commit that bumps one does), and that one marked here.
 * With to, only what is up to the version named.  The host's answer
 * is kept five minutes, unless fresh is asked.
 */
int
api_update_notes(struct http_request *req)
{
	const struct server	*s, *pick;
	ucl_object_t		*out, *list, *n, *ans, *tagl, *logl;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*comp, *from, *to;
	char			*json, *v;
	int			 status, i, ntags;
	bool			 usetags, before_from, after_to, fresh;

	if (!guard(req, false))
		return (KORE_RESULT_OK);
	http_populate_get(req);
	fresh = http_argument_get_string(req, "fresh", &v) && v[0] != '\0';
	comp = "console";
	if (http_argument_get_string(req, "component", &v) && strcmp(v,
	    "agent") == 0)
		comp = "agent";
	from = to = NULL;
	if (http_argument_get_string(req, "from", &v) && v[0] != '\0')
		from = v;
	if (http_argument_get_string(req, "to", &v) && v[0] != '\0')
		to = v;
	if (cfg.agent_source == NULL)
		return (reply_error(req, 409, "source", "agent_source in "
		    "web.conf names no repository"));
	pick = NULL;
	for (i = 0; (s = server_at(i)) != NULL; i++) {
		if (pick == NULL)
			pick = s;
		if (strncmp(s->uri, "unix:", 5) == 0) {
			pick = s;
			break;
		}
	}
	if (pick == NULL)
		return (reply_error(req, 409, "server", "no server to read the "
		    "repository through: add the host the console runs on"));
	if (notes.ans == NULL || fresh || time(NULL) - notes.at > NOTES_CACHE) {
		json = hosts_arcana(pick->uri, pick->peer_name, pick->name,
		    "source-log", &status);
		ans = parse(json);
		free(json);
		if (ans == NULL || status != 200 || !ucl_object_toboolean(
		    ucl_object_lookup(ans, "ok"))) {
			status = reply_error(req, 502, "source", "%s: %s", pick->name,
			    ans != NULL && ucl_str(ans, "error") != NULL ? ucl_str(
			    ans, "error") : ans != NULL && ucl_str(ans, "host_keys")
			    != NULL ? "its SSH host key is to be confirmed by hand "
			    "first (Build agent here)" : "the host did not answer");
			if (ans != NULL)
				ucl_object_unref(ans);
			return (status);
		}
		if (notes.ans != NULL)
			ucl_object_unref(notes.ans);
		notes.ans = ans;
		notes.at = time(NULL);
		snprintf(notes.host, sizeof(notes.host), "%s", pick->name);
	}
	list = ucl_object_typed_new(UCL_ARRAY);
	tagl = parse(ucl_str(notes.ans, "tags"));
	logl = parse(ucl_str(notes.ans, "log"));
	/* The tags with messages: the release notes, when any is newer. */
	ntags = 0;
	usetags = false;
	it = NULL;
	while ((e = ucl_object_iterate(tagl, &it, true)) != NULL) {
		if (ucl_str(e, "name") == NULL || ucl_str(e, "message") == NULL ||
		    ucl_str(e, "message")[0] == '\0')
			continue;
		ntags++;
		if (from == NULL || newer(ucl_str(e, "name"), from))
			usetags = true;
	}
	if (usetags) {
		it = NULL;
		while ((e = ucl_object_iterate(tagl, &it, true)) != NULL) {
			const char	*name = ucl_str(e, "name");

			if (name == NULL || ucl_str(e, "message") == NULL ||
			    ucl_str(e, "message")[0] == '\0')
				continue;
			n = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(n, ucl_object_fromstring(name), "id", 0,
			    false);
			ucl_object_insert_key(n, ucl_object_fromint(ucl_object_toint(
			    ucl_object_lookup(e, "time"))), "when", 0, false);
			ucl_object_insert_key(n, ucl_object_fromstring(name), "title",
			    0, false);
			ucl_object_insert_key(n, ucl_object_fromstring(ucl_str(e,
			    "message")), "body", 0, false);
			ucl_object_insert_key(n, ucl_object_frombool((from == NULL ||
			    newer(name, from)) && (to == NULL || !newer(name, to))),
			    "new", 0, false);
			ucl_object_insert_key(n, ucl_object_frombool(from != NULL &&
			    !newer(name, from) && !newer(from, name)), "here", 0,
			    false);
			ucl_array_append(list, n);
		}
	} else {
		/* The commits: new until the one that brought the version. */
		before_from = true;
		after_to = to == NULL;
		it = NULL;
		while ((e = ucl_object_iterate(logl, &it, true)) != NULL) {
			const char	*subj = ucl_str(e, "subject");
			bool		 here;

			if (ucl_str(e, "commit") == NULL || subj == NULL)
				continue;
			if (!after_to && names_version(subj, comp, to))
				after_to = true;
			here = before_from && from != NULL && names_version(subj,
			    comp, from);
			if (here)
				before_from = false;
			n = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(n, ucl_object_fromstring(ucl_str(e,
			    "commit")), "id", 0, false);
			ucl_object_insert_key(n, ucl_object_fromint(ucl_object_toint(
			    ucl_object_lookup(e, "time"))), "when", 0, false);
			ucl_object_insert_key(n, ucl_object_fromstring(subj), "title",
			    0, false);
			ucl_object_insert_key(n, ucl_object_fromstring(ucl_str(e,
			    "body") != NULL ? ucl_str(e, "body") : ""), "body", 0,
			    false);
			ucl_object_insert_key(n, ucl_object_frombool(before_from &&
			    after_to), "new", 0, false);
			ucl_object_insert_key(n, ucl_object_frombool(here), "here", 0,
			    false);
			ucl_array_append(list, n);
		}
	}
	if (tagl != NULL)
		ucl_object_unref(tagl);
	if (logl != NULL)
		ucl_object_unref(logl);
	out = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(out, ucl_object_fromstring(comp), "component", 0,
	    false);
	if (from != NULL)
		ucl_object_insert_key(out, ucl_object_fromstring(from), "from", 0,
		    false);
	if (to != NULL)
		ucl_object_insert_key(out, ucl_object_fromstring(to), "to", 0,
		    false);
	ucl_object_insert_key(out, ucl_object_fromstring(usetags ? "tags" :
	    "commits"), "kind", 0, false);
	ucl_object_insert_key(out, ucl_object_fromint(ntags), "tags", 0, false);
	if (ucl_str(notes.ans, "commit") != NULL)
		ucl_object_insert_key(out, ucl_object_fromstring(ucl_str(notes.ans,
		    "commit")), "head", 0, false);
	ucl_object_insert_key(out, ucl_object_fromstring(notes.host), "host", 0,
	    false);
	ucl_object_insert_key(out, ucl_object_fromint(notes.at), "read", 0,
	    false);
	ucl_object_insert_key(out, ucl_object_fromstring(cfg.agent_source),
	    "source", 0, false);
	ucl_object_insert_key(out, list, "notes", 0, false);
	return (reply_json(req, 200, out));
}

/* GET /api/update: the newest release against this one. */
int
api_update(struct http_request *req)
{
	struct check	*c;

	if (req->hdlr_extra != NULL) {
		c = req->hdlr_extra;
		if (kore_task_state(&c->task) != KORE_TASK_STATE_FINISHED) {
			http_request_sleep(req);
			return (KORE_RESULT_RETRY);
		}
		cache.checked = time(NULL);
		strlcpy(cache.error, c->error, sizeof(cache.error));
		if (c->latest[0] != '\0') {
			strlcpy(cache.latest, c->latest, sizeof(cache.latest));
			strlcpy(cache.url, c->url, sizeof(cache.url));
		}
		return (reply(req));
	}
	if (!guard(req, false))
		return (KORE_RESULT_OK);
	if (cfg.update_url == NULL ||
	    time(NULL) - cache.checked < UPDATE_CACHE)
		return (reply(req));
	c = kore_calloc(1, sizeof(*c));
	strlcpy(c->feed, cfg.update_url, sizeof(c->feed));
	/* A feed that takes the connection and says nothing is given up. */
	fetchTimeout = 30;
	req->hdlr_extra = c;
	kore_task_create(&c->task, check_run);
	kore_task_bind_request(&c->task, req);
	kore_task_run(&c->task);
	return (KORE_RESULT_RETRY);
}
