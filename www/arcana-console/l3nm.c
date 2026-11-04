/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The services as the console stores them: RFC 9182's L3VPN network
 * model (L3NM, ietf-l3vpn-ntw, with RFC 9181's ietf-vpn-common), a
 * datastore of the console's own, served by RESTCONF beside the fleet:
 *
 *	/restconf/data/ietf-l3vpn-ntw:l3vpn-ntw[/<api-path>]
 *
 * GET, POST, PUT, PATCH (plain and YANG Patch) and DELETE, as restconf.c
 * makes them of a host's candidate, here of the tree kept, then checked
 * as RFC 7950 says and kept whole: l3nm.json in the data directory, RFC
 * 7951's JSON, saved through the cluster as every store is.  It is read
 * at each request, so a change another node of the cluster made is
 * what the next one sees.  Who may: the console's operators and owners,
 * as /api/sdwan (users.c).
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <cbl_data.h>
#include <ucl.h>

#include "console.h"
#include "restconf.h"
#include "ymodel.h"
#include "ytrans.h"

#define	L3NM_FILE	"l3nm.json"
#define	L3NM_PATH	"/restconf/data/ietf-l3vpn-ntw:l3vpn-ntw"
#define	L3NM_MEMBER	"ietf-l3vpn-ntw:l3vpn-ntw"
#define	L3NM_URI	"console:l3nm"	/* its entity-tags' */

static pthread_mutex_t	l3nm_lock = PTHREAD_MUTEX_INITIALIZER;

/* Whether path is below the L3NM's top-level node. */
bool
l3nm_path(const char *path)
{
	size_t	n = sizeof(L3NM_PATH) - 1;

	return (strncmp(path, L3NM_PATH, n) == 0 && (path[n] == '\0' ||
	    path[n] == '/'));
}

bool
l3nm_module(const struct cbl_ymodule *m)
{

	return (strcmp(m->name, "ietf-l3vpn-ntw") == 0 || strcmp(m->name,
	    "ietf-vpn-common") == 0 || strcmp(m->name, "arcana-l3nm") == 0);
}

static const struct cbl_ynode *
l3nm_top(void)
{
	const struct cbl_ymodule	*m;

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, "ietf-l3vpn-ntw") != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++)
			if (strcmp(m->top[k]->name, "l3vpn-ntw") == 0)
				return (m->top[k]);
	}
	return (NULL);
}

/* The tree kept, its strings in a; NULL and why: it cannot be read. */
static cbl_dtree *
l3nm_load(cbl_yarena *a, char *why, size_t len)
{
	const struct cbl_ynode	*n;
	const ucl_object_t	*v;
	ucl_object_t		*o;
	cbl_dtree		*t;

	if ((n = l3nm_top()) == NULL || (t = cbl_dtree_new(&ymodel_schema)) ==
	    NULL) {
		snprintf(why, len, "out of memory");
		return (NULL);
	}
	o = store_load(L3NM_FILE);
	if ((v = ucl_object_lookup(o, L3NM_MEMBER)) != NULL &&
	    yjson_member(t, n, v, a, why, len) != 0) {
		thread_log(LOG_ERR, "%s: %s", L3NM_FILE, why);
		cbl_dtree_free(t);
		t = NULL;
	}
	ucl_object_unref(o);
	return (t);
}

/* Tree t kept, as RFC 7951's JSON. */
static int
l3nm_save(const cbl_dtree *t)
{
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	struct ucl_parser	*p;
	ucl_object_t		*o = NULL;
	int			 rc;

	if (cbl_dtree_json(t, &b) == 0) {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_chunk(p, b.p != NULL ? b.p :
		    (const unsigned char *)"{}", b.p != NULL ? b.len : 2))
			o = ucl_parser_get_object(p);
		ucl_parser_free(p);
	}
	cbl_ybuf_free(&b);
	if (o == NULL)
		return (-1);
	rc = store_save(L3NM_FILE, o);
	ucl_object_unref(o);
	return (rc);
}

/* /restconf/data's: the L3NM kept, its top-level node into top, where
 * the user may read it. */
void
l3nm_into(struct http_request *req, ucl_object_t *top)
{
	ucl_object_t		*o;
	const ucl_object_t	*v;
	const char		*u;

	if ((u = session_user(req)) != NULL && !user_path_ok(user_console(u),
	    L3NM_PATH, false))
		return;
	pthread_mutex_lock(&l3nm_lock);
	o = store_load(L3NM_FILE);
	pthread_mutex_unlock(&l3nm_lock);
	if ((v = ucl_object_lookup(o, L3NM_MEMBER)) != NULL)
		ucl_object_insert_key(top, ucl_object_copy(v), L3NM_MEMBER, 0,
		    false);
	ucl_object_unref(o);
}

static int
reply(struct http_request *req, struct rcreq *r, int status, char *json)
{

	http_response_header(req, "content-type", "application/yang-data+json");
	http_response_header(req, "cache-control", "no-store");
	http_response_header(req, "x-content-type-options", "nosniff");
	restconf_headers(req, r, L3NM_URI, status);
	http_response(req, status, json, strlen(json));
	free(json);
	return (WEB_OK);
}

int
api_l3nm(struct http_request *req)
{
	struct rcreq	*r;
	ucl_object_t	*body = NULL;
	cbl_dtree	*t;
	cbl_yarena	*a;
	const char	*why = NULL, *ctype = NULL;
	char		 err[256], *json = NULL;
	bool		 changed;
	int		 st, status;

	if (!guard(req, req->method != HTTP_METHOD_GET))
		return (WEB_OK);
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
	if ((st = restconf_prepare(r, req->method, ctype, body, &why)) == 0)
		st = restconf_precondition(req, r, L3NM_URI);
	if (st != 0) {
		(void)restconf_refuse(req, r, L3NM_URI, st, why);
		restconf_free(r);
		return (WEB_OK);
	}
	if ((a = cbl_yarena_new()) == NULL) {
		restconf_free(r);
		return (restconf_error(req, 500, "out of memory"));
	}
	pthread_mutex_lock(&l3nm_lock);
	if ((t = l3nm_load(a, err, sizeof(err))) == NULL) {
		pthread_mutex_unlock(&l3nm_lock);
		cbl_yarena_free(a);
		restconf_free(r);
		return (restconf_error(req, 500, "the services kept could not "
		    "be read"));
	}
	restconf_run_own(r, t, a, &changed, &json, &status);
	if (changed && l3nm_save(t) != 0) {
		free(json);
		json = restconf_errors(500, "the services could not be kept");
		status = 500;
		changed = false;
	}
	if (changed)
		restconf_own_changed(L3NM_URI);
	pthread_mutex_unlock(&l3nm_lock);
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	if (changed)
		audit_add("policies-changed", "Administer", "the services as "
		    "L3NM", "a change of RFC 9182's model, checked first",
		    "the console (the Policy Administration Point)",
		    session_who(req), "%s %s", req->method == HTTP_METHOD_POST ?
		    "POST" : req->method == HTTP_METHOD_PUT ? "PUT" :
		    req->method == HTTP_METHOD_PATCH ? "PATCH" : "DELETE",
		    req->path);
	if (json == NULL)
		json = restconf_errors(500, "out of memory");
	st = reply(req, r, status, json);
	restconf_free(r);
	return (st);
}
