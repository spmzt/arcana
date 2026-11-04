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
 *
 * The SD-WAN document /api/sdwan serves (sdwan.c) is a view of it, one
 * source of truth: read, the L3NM exported (l3nm_mef.c); written, the
 * document imported into the L3NM kept and run as RESTCONF's PUT of it,
 * checked as one.  The document's version is the datastore's, kept
 * beside the L3NM in l3nm.json: one more at each change, made either
 * way, with its time.  A console that kept sdwan.json before has it
 * imported once, at start (in a cluster, which takes no write while it
 * starts, at its first use), and kept as sdwan-mef.json.
 */

#include <sys/param.h>
#include <sys/file.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
#define	MEF_FILE	"sdwan.json"	/* the document, before */
#define	MEF_BACKUP	"sdwan-mef.json"
#define	MEF_LOCK	"l3nm.lock"

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

/* Tree t kept, as RFC 7951's JSON, its version one more than the kept
 * one's and than floor. */
static int
l3nm_save(const cbl_dtree *t, int64_t floor)
{
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	struct ucl_parser	*p;
	ucl_object_t		*o = NULL, *kept;
	int64_t			 v;
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
	kept = store_load(L3NM_FILE);
	v = ucl_object_toint(ucl_object_lookup(kept, "version"));
	ucl_object_unref(kept);
	ucl_object_insert_key(o, ucl_object_fromint(MAX(v, floor) + 1),
	    "version", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(time(NULL)), "changed", 0,
	    false);
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
	if (changed && l3nm_save(t, 0) != 0) {
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

/* ---- The SD-WAN document, a view of it -------------------------------- */

/* The first error's message of restconf_errors()'s JSON, into why. */
static void
error_of(const char *json, char *why, size_t len)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	const ucl_object_t	*e;
	const char		*m, *at;

	snprintf(why, len, "the services as L3NM were refused");
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	if (json != NULL && ucl_parser_add_string(p, json, 0) &&
	    (o = ucl_parser_get_object(p)) != NULL) {
		e = ucl_array_find_index(ucl_object_lookup_path(o,
		    "ietf-restconf:errors.error"), 0);
		m = ucl_str(e, "error-message");
		at = ucl_str(e, "error-path");
		if (m != NULL)
			snprintf(why, len, "as L3NM: %s%s%s", at != NULL ? at :
			    "", at != NULL ? ": " : "", m);
		ucl_object_unref(o);
	}
	ucl_parser_free(p);
}

/*
 * Document doc imported into the L3NM kept, run as a PUT of it: 0, or
 * the HTTP status and why.  expect, unless -1, the version it was made
 * from; floor, the least the version kept is before it.  Under the
 * lock.
 */
static int
put_doc(const ucl_object_t *doc, int64_t expect, int64_t floor, char *why,
    size_t len)
{
	struct rcreq	*r;
	ucl_object_t	*o, *y, *body;
	cbl_dtree	*t;
	cbl_yarena	*a;
	const char	*w = NULL;
	char		 err[256], *json = NULL;
	int64_t		 have;
	bool		 changed;
	int		 status;

	o = store_load(L3NM_FILE);
	have = ucl_object_toint(ucl_object_lookup(o, "version"));
	if (expect != -1 && expect != have) {
		ucl_object_unref(o);
		snprintf(why, len, "it was changed since: version %jd, not %jd",
		    (intmax_t)have, (intmax_t)expect);
		return (409);
	}
	y = ucl_object_lookup(o, L3NM_MEMBER) != NULL ? ucl_object_copy(
	    ucl_object_lookup(o, L3NM_MEMBER)) : ucl_object_typed_new(
	    UCL_OBJECT);
	ucl_object_unref(o);
	mef_import(doc, y);
	body = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(body, y, L3NM_MEMBER, 0, false);
	if ((r = restconf_parse_own(L3NM_PATH, NULL, &w)) == NULL) {
		ucl_object_unref(body);
		snprintf(why, len, "%s", w != NULL ? w : "out of memory");
		return (500);
	}
	if ((status = restconf_prepare(r, HTTP_METHOD_PUT,
	    "application/yang-data+json", body, &w)) != 0) {
		snprintf(why, len, "as L3NM: %s", w != NULL ? w : "refused");
		restconf_free(r);
		return (status >= 500 ? 500 : 400);
	}
	t = NULL;
	if ((a = cbl_yarena_new()) == NULL || (t = l3nm_load(a, err,
	    sizeof(err))) == NULL) {
		if (a != NULL)
			cbl_yarena_free(a);
		restconf_free(r);
		snprintf(why, len, "the services kept could not be read");
		return (500);
	}
	restconf_run_own(r, t, a, &changed, &json, &status);
	if (status >= 300) {
		error_of(json, why, len);
		status = status >= 500 ? 500 : 400;
	} else if (l3nm_save(t, floor) != 0) {
		snprintf(why, len, "the services could not be kept");
		status = 500;
	} else {
		restconf_own_changed(L3NM_URI);
		status = 0;
	}
	free(json);
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	restconf_free(r);
	return (status);
}

/*
 * The document a console kept before, imported once, its version kept,
 * then kept as MEF_BACKUP and taken away.  When the L3NM has an SD-WAN
 * already (another node of the cluster imported it), kept and taken
 * away alone.
 */
void
l3nm_sdwan_migrate(void)
{
	ucl_object_t	*old, *o;
	char		 path[MAXPATHLEN], why[300];
	int		 fd, rc;
	bool		 done;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, MEF_FILE);
	if (access(path, F_OK) == -1)
		return;
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, MEF_LOCK);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return;
	(void)flock(fd, LOCK_EX);
	pthread_mutex_lock(&l3nm_lock);
	if ((old = store_load(MEF_FILE)) == NULL) {
		pthread_mutex_unlock(&l3nm_lock);
		close(fd);
		return;
	}
	o = store_load(L3NM_FILE);
	done = mef_has_sdwan(ucl_object_lookup(o, L3NM_MEMBER));
	ucl_object_unref(o);
	rc = done ? 0 : put_doc(old, -1, ucl_object_toint(ucl_object_lookup(
	    old, "version")) - 1, why, sizeof(why));
	if (rc == 0 && store_save(MEF_BACKUP, old) == 0 &&
	    store_remove(MEF_FILE) == 0)
		thread_log(LOG_NOTICE, "%s: %s as L3NM, kept as %s", MEF_FILE,
		    done ? "imported before" : "imported", MEF_BACKUP);
	else if (rc != 0 && !cluster_on())
		thread_log(LOG_ERR, "%s: not imported as L3NM: %s", MEF_FILE,
		    why);
	pthread_mutex_unlock(&l3nm_lock);
	ucl_object_unref(old);
	close(fd);
}

/* The SD-WAN document: the L3NM kept, exported, with its version. */
ucl_object_t *
l3nm_sdwan(void)
{
	ucl_object_t		*o, *doc;
	const ucl_object_t	*v;

	l3nm_sdwan_migrate();
	pthread_mutex_lock(&l3nm_lock);
	o = store_load(L3NM_FILE);
	pthread_mutex_unlock(&l3nm_lock);
	doc = mef_export(ucl_object_lookup(o, L3NM_MEMBER));
	ucl_object_insert_key(doc, ucl_object_fromint(ucl_object_toint(
	    ucl_object_lookup(o, "version"))), "version", 0, false);
	if ((v = ucl_object_lookup(o, "changed")) != NULL)
		ucl_object_insert_key(doc, ucl_object_copy(v), "changed", 0,
		    false);
	ucl_object_unref(o);
	return (doc);
}

/* Document doc kept, as L3NM: 0, or the HTTP status and why (409: not
 * made from version expect, unless that is -1). */
int
l3nm_sdwan_put(const ucl_object_t *doc, int64_t expect, char *why,
    size_t len)
{
	int	rc;

	l3nm_sdwan_migrate();
	pthread_mutex_lock(&l3nm_lock);
	rc = put_doc(doc, expect, 0, why, len);
	pthread_mutex_unlock(&l3nm_lock);
	return (rc);
}
