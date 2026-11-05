/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console's own configuration and state as the module arcana-console
 * (share/yang), served by RESTCONF beside the fleet:
 *
 *	/restconf/data/arcana-console:settings		owners
 *	/restconf/data/arcana-console:tokens		owners
 *	/restconf/data/arcana-console:users		owners
 *	/restconf/data/arcana-console:roles		owners
 *	/restconf/data/arcana-console:groups		owners
 *	/restconf/data/arcana-console:enrolment		owners
 *	/restconf/data/arcana-console:workflows		operators and owners
 *	/restconf/data/arcana-console:runs		operators and owners
 *
 * No second store: a request reads the files the stores keep, each
 * store's view of itself made into a tree (settings_yang() and the
 * others), runs on it as restconf.c makes a request of the console's own
 * datastore (restconf_run_own(): GET, POST, PUT, PATCH, YANG Patch,
 * DELETE, each change checked as RFC 7950 says), and what changed is
 * kept through the setters /api's handlers go through, with their
 * checks, their log lines and their refusals (settings_yang_set() and
 * the others).  Who may is /api's: users.c's and tokens.c's rules on
 * the path.  The actions (a token made, an invitation, an enrolment
 * token, a workflow run, a step approved, a run stopped, the runs
 * cleared) are POSTed to their node, their input and output RFC 8040
 * section 3.6's.  Each part's entity-tag changes when its store does,
 * by RESTCONF or by /api.
 */

#include <sys/param.h>

#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <cbl_data.h>
#include <ucl.h>

#include "console.h"
#include "restconf.h"
#include "yjsonin.h"
#include "ymodel.h"

#define	MODULE		"arcana-console"

/* The parts: the module's top-level containers, each a store's. */
static const struct part {
	const char	*name;
	bool		 trio;		/* users, roles, groups: one store */
	bool		 config;
} parts[] = {
	{ "settings", false, true },
	{ "tokens", false, true },
	{ "users", true, true },
	{ "roles", true, true },
	{ "groups", true, true },
	{ "enrolment", false, false },
	{ "workflows", false, true },
	{ "runs", false, false },
};

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

/* A time, seconds since the epoch, as yang:date-and-time (UTC), to the
 * millisecond where it has a fraction. */
ucl_object_t *
yang_time(double t)
{
	struct tm	tm;
	time_t		s;
	char		buf[48], frac[8];
	int		ms;

	s = (time_t)floor(t);
	ms = (int)lround((t - (double)s) * 1000);
	if (ms == 1000) {
		s++;
		ms = 0;
	}
	gmtime_r(&s, &tm);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
	if (ms != 0) {
		snprintf(frac, sizeof(frac), ".%03d", ms);
		strlcat(buf, frac, sizeof(buf));
	}
	strlcat(buf, "Z", sizeof(buf));
	return (ucl_object_fromstring(buf));
}

/* The part path names, below CYANG_DATA; NULL: none. */
static const struct part *
part_of(const char *path)
{
	size_t	n;

	if (strncmp(path, CYANG_DATA, sizeof(CYANG_DATA) - 1) != 0)
		return (NULL);
	path += sizeof(CYANG_DATA) - 1;
	for (size_t i = 0; i < nitems(parts); i++) {
		n = strlen(parts[i].name);
		if (strncmp(path, parts[i].name, n) == 0 && (path[n] == '\0' ||
		    path[n] == '/'))
			return (&parts[i]);
	}
	return (NULL);
}

bool
cyang_path(const char *path)
{

	return (strncmp(path, CYANG_DATA, sizeof(CYANG_DATA) - 1) == 0);
}

void
cyang_changed(const char *part)
{
	char	uri[64];

	snprintf(uri, sizeof(uri), "console:%s", part);
	restconf_own_changed(uri);
}

/* What guard() would let the request do at path, without a reply. */
static bool
may(struct http_request *req, const char *path, bool mutate)
{
	const char	*u;

	if (!session_valid(req)) {
		switch (token_kind(req)) {
		case TOKEN_WRITE:
			return (mutate ? token_writable(path) :
			    token_readable(path));
		case TOKEN_READ:
			return (!mutate && token_readable(path));
		default:
			return (false);
		}
	}
	if (session_by_token(req) && !(mutate ? token_writable(path) :
	    token_readable(path)))
		return (false);
	return ((u = session_user(req)) == NULL ||
	    user_path_ok(user_console(u), path, mutate));
}

/* Part p's value as its store has it; run one with its traces. */
static ucl_object_t *
value_of(const struct part *p, uint32_t one)
{
	ucl_object_t	*o;

	if (strcmp(p->name, "settings") == 0)
		return (settings_yang());
	if (strcmp(p->name, "tokens") == 0)
		return (tokens_yang());
	if (strcmp(p->name, "users") == 0)
		return (users_yang());
	if (strcmp(p->name, "roles") == 0)
		return (roles_yang());
	if (strcmp(p->name, "groups") == 0)
		return (groups_yang());
	if (strcmp(p->name, "workflows") == 0)
		return (workflows_yang());
	if (strcmp(p->name, "runs") == 0)
		return (runs_yang(one));
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "enabled", ucl_object_frombool(enrol_enabled()));
	return (o);
}

/* /restconf/data's: each part the request may read, into top. */
void
cyang_into(struct http_request *req, ucl_object_t *top)
{
	char	path[128], key[64];

	for (size_t i = 0; i < nitems(parts); i++) {
		snprintf(path, sizeof(path), CYANG_DATA "%s", parts[i].name);
		if (!may(req, path, false))
			continue;
		snprintf(key, sizeof(key), MODULE ":%s", parts[i].name);
		put(top, key, value_of(&parts[i], 0));
	}
}

static const struct cbl_ynode *
top_named(const char *name)
{
	const struct cbl_ymodule	*m;

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, MODULE) != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++)
			if (strcmp(m->top[k]->name, name) == 0)
				return (m->top[k]);
	}
	return (NULL);
}

/*
 * The tree a request of part p runs on (users, roles and groups
 * together: their leafrefs), its values into *doc as {name: value}.
 * NULL and why: a store's view not of the module.
 */
static cbl_dtree *
tree_of(const struct part *p, uint32_t one, ucl_object_t **doc,
    cbl_yarena *a, char *why, size_t len)
{
	const struct cbl_ynode	*n;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;
	cbl_dtree		*t;

	*doc = ucl_object_typed_new(UCL_OBJECT);
	for (size_t i = 0; i < nitems(parts); i++)
		if (&parts[i] == p || (p->trio && parts[i].trio))
			put(*doc, parts[i].name, value_of(&parts[i], one));
	if ((t = cbl_dtree_new(&ymodel_schema)) == NULL) {
		snprintf(why, len, "out of memory");
		return (NULL);
	}
	while ((v = ucl_object_iterate(*doc, &it, true)) != NULL) {
		if ((n = top_named(ucl_object_key(v))) == NULL) {
			snprintf(why, len, "no %s in the console's schema",
			    MODULE);
			cbl_dtree_free(t);
			return (NULL);
		}
		if (yjson_member(t, n, v, a, why, len) != 0) {
			cbl_dtree_free(t);
			return (NULL);
		}
	}
	return (t);
}

/* What is not configuration taken out from below n: a change is made
 * and checked of the configuration alone. */
static void
strip(cbl_dnode *n)
{
	cbl_dnode	*c, *next;

	for (c = cbl_dnode_first(n); c != NULL; c = next) {
		next = cbl_dnode_next(c);
		if ((cbl_dnode_schema(c)->flags & CBL_YNF_CONFIG) == 0)
			(void)cbl_dnode_remove(c);
		else
			strip(c);
	}
}

/* Tree t as {part: value}, each part of it RFC 7951's JSON has; NULL:
 * out of memory. */
static ucl_object_t *
values_in(const cbl_dtree *t)
{
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	struct ucl_parser	*p;
	ucl_object_t		*doc = NULL, *o;
	const ucl_object_t	*v;
	char			 key[64];

	if (cbl_dtree_json(t, &b) == 0) {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_chunk(p, b.p != NULL ? b.p :
		    (const unsigned char *)"{}", b.p != NULL ? b.len : 2))
			doc = ucl_parser_get_object(p);
		ucl_parser_free(p);
	}
	cbl_ybuf_free(&b);
	if (doc == NULL)
		return (NULL);
	o = ucl_object_typed_new(UCL_OBJECT);
	for (size_t i = 0; i < nitems(parts); i++) {
		snprintf(key, sizeof(key), MODULE ":%s", parts[i].name);
		put(o, parts[i].name, (v = ucl_object_lookup(doc, key)) !=
		    NULL ? ucl_object_copy(v) : ucl_object_typed_new(
		    UCL_OBJECT));
	}
	ucl_object_unref(doc);
	return (o);
}

/*
 * The change of part p from was to now kept through its store's
 * setters: 0, or the HTTP status and why.
 */
static int
keep(struct http_request *req, const struct part *p, const ucl_object_t *was,
    const ucl_object_t *now, char *why, size_t len)
{

	if (strcmp(p->name, "settings") == 0)
		return (settings_yang_set(ucl_object_lookup(was, "settings"),
		    ucl_object_lookup(now, "settings"), why, len));
	if (strcmp(p->name, "tokens") == 0)
		return (tokens_yang_set(ucl_object_lookup(was, "tokens"),
		    ucl_object_lookup(now, "tokens"), why, len));
	if (strcmp(p->name, "workflows") == 0)
		return (workflows_yang_set(ucl_object_lookup(was,
		    "workflows"), ucl_object_lookup(now, "workflows"), why,
		    len));
	if (p->trio)
		return (users_yang_set(was, now, session_who(req), why, len));
	snprintf(why, len, "%s is not configuration", p->name);
	return (405);
}

/* Whether path is CYANG_DATA part "/" list "=" key "/" action: the key
 * into key. */
static bool
action_at(const char *path, const char *part, const char *list,
    const char *action, char *key, size_t len)
{
	char	pre[128];
	size_t	n, k;

	snprintf(pre, sizeof(pre), CYANG_DATA "%s/%s=", part, list);
	n = strlen(pre);
	if (strncmp(path, pre, n) != 0)
		return (false);
	path += n;
	k = strcspn(path, "/");
	if (k == 0 || k >= len || path[k] != '/' || strcmp(path + k + 1,
	    action) != 0)
		return (false);
	memcpy(key, path, k);
	key[k] = '\0';
	return (true);
}

/* An action's reply: its output, or none. */
static int
output(struct http_request *req, ucl_object_t *out)
{
	ucl_object_t	*top;

	if (out == NULL) {
		http_response_header(req, "cache-control", "no-store");
		http_response(req, 204, NULL, 0);
		return (WEB_OK);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, MODULE ":output", out);
	return (restconf_reply(req, top));
}

/*
 * The actions, POSTed to their node: the input as section 3.6.1 has it,
 * {"arcana-console:input": {...}}, or no body.  -1: path names none.
 */
static int
action(struct http_request *req)
{
	ucl_object_t		*body, *out;
	const ucl_object_t	*in;
	char			 key[72], why[256], value[TOKEN_LEN], id[17];
	char			 token[80];
	time_t			 exp;
	uint32_t		 n;
	int			 rc;

	if (strcmp(req->path, CYANG_DATA "tokens/create") != 0 &&
	    strcmp(req->path, CYANG_DATA "enrolment/create-token") != 0 &&
	    strcmp(req->path, CYANG_DATA "runs/clear") != 0 &&
	    !action_at(req->path, "users", "user", "invite", key,
	    sizeof(key)) &&
	    !action_at(req->path, "workflows", "workflow", "run", key,
	    sizeof(key)) &&
	    !action_at(req->path, "runs", "run", "approve", key,
	    sizeof(key)) &&
	    !action_at(req->path, "runs", "run", "stop", key, sizeof(key)))
		return (-1);
	if (!guard(req, true))
		return (WEB_OK);
	body = read_json(req);
	if (req->http_body != NULL && req->http_body->length > 0 &&
	    body == NULL)
		return (restconf_error_tag(req, 400, "malformed-message",
		    "the body is not JSON"));
	in = ucl_object_lookup(body, MODULE ":input");
	if (body != NULL && body->len > 0 && in == NULL) {
		ucl_object_unref(body);
		return (restconf_error_tag(req, 400, "malformed-message",
		    "an action's body is {\"" MODULE ":input\": {...}}"));
	}
	out = NULL;
	rc = 0;
	why[0] = '\0';
	if (strcmp(req->path, CYANG_DATA "tokens/create") == 0) {
		if ((rc = token_new(ucl_str(in, "name"), ucl_str(in, "kind"),
		    id, value, why, sizeof(why))) == 0) {
			out = ucl_object_typed_new(UCL_OBJECT);
			put(out, "id", ucl_object_fromstring(id));
			put(out, "token", ucl_object_fromstring(value));
			explicit_bzero(value, sizeof(value));
		}
	} else if (strcmp(req->path, CYANG_DATA "enrolment/create-token") ==
	    0) {
		ucl_object_t	*o;

		if ((rc = enrol_token_new(ucl_str(in, "name"), ucl_str(in,
		    "host"), ucl_object_lookup(in, "port") != NULL ?
		    ucl_object_toint(ucl_object_lookup(in, "port")) : 4310, &o,
		    why, sizeof(why))) == 0) {
			out = ucl_object_typed_new(UCL_OBJECT);
			put(out, "token", ucl_object_fromstring(ucl_str(o,
			    "token")));
			put(out, "expires", yang_time((double)ucl_object_toint(
			    ucl_object_lookup(o, "expires"))));
			put(out, "command", ucl_object_fromstring(ucl_str(o,
			    "command")));
			ucl_object_unref(o);
		}
	} else if (strcmp(req->path, CYANG_DATA "runs/clear") == 0) {
		out = ucl_object_typed_new(UCL_OBJECT);
		put(out, "cleared", ucl_object_fromint(runs_yang_clear(
		    ucl_str(in, "workflow"), session_user(req))));
	} else if (action_at(req->path, "users", "user", "invite", key,
	    sizeof(key))) {
		if ((rc = users_yang_invite(key, session_who(req), token,
		    sizeof(token), &exp, why, sizeof(why))) == 0) {
			out = ucl_object_typed_new(UCL_OBJECT);
			put(out, "token", ucl_object_fromstring(token));
			put(out, "expires", yang_time((double)exp));
			explicit_bzero(token, sizeof(token));
		}
	} else if (action_at(req->path, "workflows", "workflow", "run", key,
	    sizeof(key))) {
		if ((rc = workflows_yang_run(req, key, in, &n, why,
		    sizeof(why))) == 0) {
			out = ucl_object_typed_new(UCL_OBJECT);
			put(out, "run", ucl_object_fromint(n));
		}
	} else {
		n = (uint32_t)strtoul(key, NULL, 10);
		if (strstr(req->path, "/approve") != NULL && ucl_str(in,
		    "step") == NULL) {
			rc = 400;
			snprintf(why, sizeof(why), "say the step");
		} else
			rc = runs_yang_mark(n, strstr(req->path, "/approve") !=
			    NULL ? ucl_str(in, "step") : NULL, session_user(req),
			    why, sizeof(why));
	}
	ucl_object_unref(body);
	if (rc != 0)
		return (restconf_error(req, rc, why));
	return (output(req, out));
}

static int
reply(struct http_request *req, struct rcreq *r, const char *uri,
    int status, char *json)
{

	http_response_header(req, "content-type", "application/yang-data+json");
	http_response_header(req, "cache-control", "no-store");
	http_response_header(req, "x-content-type-options", "nosniff");
	restconf_headers(req, r, uri, status);
	http_response(req, status, json, strlen(json));
	free(json);
	return (WEB_OK);
}

int
api_cyang(struct http_request *req)
{
	const struct part	*p;
	struct rcreq		*r;
	ucl_object_t		*body = NULL, *doc, *was, *now;
	cbl_dtree		*t;
	cbl_yarena		*a;
	const char		*why = NULL, *ctype = NULL, *e;
	char			 uri[64], err[256], *json = NULL;
	uint32_t		 one = 0;
	bool			 changed;
	int			 st, status;

	if ((p = part_of(req->path)) == NULL)
		return (restconf_error(req, 404, "no such resource: "
		    MODULE "'s are settings, tokens, users, roles, groups, "
		    "enrolment, workflows and runs"));
	if (req->method == HTTP_METHOD_POST && (st = action(req)) != -1)
		return (st);
	if (!guard(req, req->method != HTTP_METHOD_GET))
		return (WEB_OK);
	if (!p->config && req->method != HTTP_METHOD_GET) {
		http_response_header(req, "allow", "GET, OPTIONS");
		return (restconf_error(req, 405, "it is read, and changed by "
		    "its actions"));
	}
	if (req->method != HTTP_METHOD_GET && req->method !=
	    HTTP_METHOD_DELETE) {
		body = read_json(req);
		if (body == NULL && req->http_body != NULL &&
		    req->http_body->length > 0)
			return (restconf_error_tag(req, 400,
			    "malformed-message", "the body is not JSON"));
	}
	(void)http_request_header(req, "content-type", &ctype);
	if ((r = restconf_parse_own(req->path, req->query_string, &why)) ==
	    NULL) {
		ucl_object_unref(body);
		return (restconf_error(req, 400, why));
	}
	snprintf(uri, sizeof(uri), "console:%s", p->name);
	if ((st = restconf_prepare(r, req->method, ctype, body, &why)) == 0)
		st = restconf_precondition(req, r, uri);
	if (st != 0) {
		(void)restconf_refuse(req, r, uri, st, why);
		restconf_free(r);
		return (WEB_OK);
	}
	/* A run named: its traces. */
	if (strcmp(p->name, "runs") == 0 && strncmp(req->path, CYANG_DATA
	    "runs/run=", sizeof(CYANG_DATA) + 8) == 0) {
		e = req->path + sizeof(CYANG_DATA) + 8;
		one = (uint32_t)strtoul(e, NULL, 10);
	}
	if ((a = cbl_yarena_new()) == NULL) {
		restconf_free(r);
		return (restconf_error(req, 500, "out of memory"));
	}
	if ((t = tree_of(p, one, &doc, a, err, sizeof(err))) == NULL) {
		log_msg(LOG_ERR, "%s:%s: %s", MODULE, p->name, err);
		ucl_object_unref(doc);
		cbl_yarena_free(a);
		restconf_free(r);
		return (restconf_error(req, 500, err[0] != '\0' ? err :
		    "out of memory"));
	}
	ucl_object_unref(doc);
	was = NULL;
	if (req->method != HTTP_METHOD_GET) {
		strip(cbl_dtree_root(t));
		was = values_in(t);
	}
	restconf_run_own(r, t, a, &changed, &json, &status);
	if (changed) {
		now = values_in(t);
		if (was == NULL || now == NULL) {
			st = 500;
			snprintf(err, sizeof(err), "out of memory");
		} else
			st = keep(req, p, was, now, err, sizeof(err));
		ucl_object_unref(now);
		if (st != 0) {
			free(json);
			json = restconf_errors(st, err);
			status = st;
		}
	}
	ucl_object_unref(was);
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	if (json == NULL) {
		json = restconf_errors(500, "out of memory");
		status = 500;
	}
	st = reply(req, r, uri, status, json);
	restconf_free(r);
	return (st);
}
