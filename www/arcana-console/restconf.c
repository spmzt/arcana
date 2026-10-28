/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * RESTCONF (RFC 8040): the console as the server of a datastore whose
 * hosts are mount points (arcana-fleet, RFC 8528), each host's data the
 * models its agent serves, read and changed through cblink's YANG
 * family.
 *
 *	/.well-known/host-meta		where the root is (section 3.1)
 *	/restconf			the root resource (3.3)
 *	/restconf/yang-library-version
 *	/restconf/data			the console's own: the fleet's hosts,
 *					restconf-state, yang-library and
 *					schema-mounts
 *	/restconf/data/arcana-fleet:fleet/host=<id>[/<api-path>]
 *					a host's entry, or a node of its
 *					agent's data by RFC 8040's api-path
 *
 * A host's path is made an XPath filter of the agent's GET, the node
 * then taken from the RFC 7951 JSON that comes back.  Of the query
 * parameters, content, depth, fields (4.8.3) and with-defaults (RFC
 * 8040 4.8.9, RFC 6243): the agent's data is as it has it (explicit),
 * report-all adds the defaults of leaves that are not there, trim leaves
 * out those at their default; of the operational datastore,
 * with-origin (RFC 8527 section 3.2.2), each configuration node's
 * origin as the agent tells it; insert and point a change's (4.8.5,
 * 4.8.6); every other is refused.  The errors are ietf-restconf's.
 *
 * The changes (section 4.4 to 4.7, RFC 8072's YANG Patch) are of a
 * host's candidate: the agents take a top-level node whole, so the
 * console reads the candidate's top-level nodes an edit goes through,
 * makes each edit of them in its own instance tree as RFC 6241 has the
 * operations (cbl_dtree_edit(): create, merge, replace, delete, remove,
 * and YANG Patch's insert and move, where said), and sends those nodes
 * back in one EDIT, all or nothing.  The candidate is every session's:
 * a change another makes between the read and the EDIT is lost to it;
 * If-Match with the candidate's entity-tag (section 3.4.1, kept here)
 * guards against one made before the request.
 */

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <cbl_data.h>
#include <ucl.h>

#include "console.h"
#include "restconf.h"
#include "ymodel.h"
#include "ytrans.h"

#define	FLEET		"/restconf/data/arcana-fleet:fleet"
#define	YLIB_VERSION	"2019-01-04"
#define	SEG_MAX		32
#define	KEY_MAX		8

enum { CONTENT_ALL, CONTENT_CONFIG, CONTENT_NONCONFIG };
enum { WD_EXPLICIT, WD_REPORT_ALL, WD_TRIM, WD_TAGGED };

/* fields' selection: each a node, with what is selected under it. */
struct fsel {
	char		*name;
	struct fsel	*sub;
	struct fsel	*next;
};

struct rcseg {
	const struct cbl_ynode	*n;
	char			*key[KEY_MAX];
	size_t			 nkey;
};

#define	ACCEPT_MAX	8
#define	EDIT_MAX	64

struct rcreq;

/* An edit of the candidate: a method's, or one of a YANG Patch's. */
struct rcedit {
	char		*id;		/* a YANG Patch's edit-id */
	int		 op;		/* CBL_DOP_* */
	int		 where;		/* CBL_DWHERE_*; 0: none said */
	struct rcreq	*t;		/* its target: the request's, or its own */
	struct rcreq	*pt;		/* before or after it */
	const ucl_object_t *value;	/* the target's value, of the body */
	bool		 whole;		/* a top-level node's value, merged */
};

struct rcreq {
	struct rcseg	 seg[SEG_MAX];
	size_t		 nseg;
	char		*xpath;
	int		 depth;		/* 0: unbounded */
	int		 content;
	int		 defaults;
	bool		 origin;	/* with-origin */
	struct fsel	*fields;
	/* Of the datastores (RFC 8527) and the changes: */
	int		 ds;		/* CBL_YDS_*; -1, /restconf/data */
	int		 method;	/* HTTP_METHOD_* */
	ucl_object_t	*body;		/* a change's, an rpc's input */
	const struct cbl_ynode *rpc;	/* POSTed: ietf-netconf's */
	char		*accept[ACCEPT_MAX];
	size_t		 naccept;
	char		*base;		/* the path to the host's entry */
	size_t		 nbase;		/* the nodes the path names */
	int		 insert;	/* CBL_DWHERE_*; 0: none said */
	char		*point;		/* insert's point, as the query has it */
	struct rcedit	*edit;
	size_t		 nedit;
	bool		 patch;		/* a YANG Patch (RFC 8072) */
	char		*patch_id;
	int		 cond;		/* If-Match: *, 1; If-None-Match: *, -1 */
	bool		 created;	/* a PUT's: it was not there */
	char		*location;	/* a POST's: what it made */
	const char	*tag;		/* refused: the error-tag; NULL, status's */
	char		*errjson;	/* refused with a body of its own */
	char		 why[256];
};

static char	*errors_of(int, const char *, const char *, const char *);

/* The error-tag and its status (RFC 8040 section 7) of the console's
 * own error codes. */
static const char *
tag_of(int status)
{

	switch (status) {
	case 400:
		return ("invalid-value");
	case 401:
	case 403:
		return ("access-denied");
	case 404:
		return ("invalid-value");
	case 405:
	case 501:
		return ("operation-not-supported");
	case 413:
		return ("too-big");
	default:
		return ("operation-failed");
	}
}

/* The status of an error-tag, RFC 8040 section 7's table. */
static int
status_of(const char *tag)
{
	static const struct {
		const char	*tag;
		int		 status;
	} st[] = {
		{ "in-use", 409 },
		{ "invalid-value", 400 },
		{ "too-big", 413 },
		{ "missing-attribute", 400 },
		{ "bad-attribute", 400 },
		{ "unknown-attribute", 400 },
		{ "bad-element", 400 },
		{ "unknown-element", 400 },
		{ "unknown-namespace", 400 },
		{ "missing-element", 400 },
		{ "access-denied", 403 },
		{ "lock-denied", 409 },
		{ "resource-denied", 409 },
		{ "rollback-failed", 500 },
		{ "data-exists", 409 },
		{ "data-missing", 409 },
		{ "operation-not-supported", 501 },
		{ "operation-failed", 500 },
		{ "partial-operation", 500 },
		{ "malformed-message", 400 },
	};

	for (size_t i = 0; tag != NULL && i < nitems(st); i++)
		if (strcmp(st[i].tag, tag) == 0)
			return (st[i].status);
	return (500);
}

char *
restconf_errors(int status, const char *msg)
{

	return (errors_of(status, NULL, NULL, msg));
}

/* An errors container of one error: of status, its error-tag tag (NULL:
 * status's), the node at fault path and its error-app-tag (NULL: none),
 * the message msg. */
static ucl_object_t *
error_list(int status, const char *tag, const char *path, const char *apptag,
    const char *msg)
{
	ucl_object_t	*errs, *arr, *e;

	if (tag == NULL)
		tag = tag_of(status);
	e = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(e, ucl_object_fromstring(status == 401 ||
	    status == 403 || strcmp(tag, "malformed-message") == 0 ?
	    "protocol" : "application"), "error-type", 0, false);
	ucl_object_insert_key(e, ucl_object_fromstring(tag), "error-tag", 0,
	    false);
	if (apptag != NULL && apptag[0] != '\0')
		ucl_object_insert_key(e, ucl_object_fromstring(apptag),
		    "error-app-tag", 0, false);
	if (path != NULL)
		ucl_object_insert_key(e, ucl_object_fromstring(path),
		    "error-path", 0, false);
	if (msg != NULL && msg[0] != '\0')
		ucl_object_insert_key(e, ucl_object_fromstring(msg),
		    "error-message", 0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(arr, e);
	errs = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(errs, arr, "error", 0, false);
	return (errs);
}

/* ietf-restconf:errors of status, its error-tag tag (NULL: status's),
 * the node at fault path and the error-app-tag (NULL: none), the
 * message msg. */
static char *
errors_of_app(int status, const char *tag, const char *path,
    const char *apptag, const char *msg)
{
	ucl_object_t	*top;
	char		*json;

	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, error_list(status, tag, path, apptag, msg),
	    "ietf-restconf:errors", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (json);
}

static char *
errors_of(int status, const char *tag, const char *path, const char *msg)
{

	return (errors_of_app(status, tag, path, NULL, msg));
}

/*
 * A YANG Patch's status (RFC 8072 section 2.3), of patch r: ok when tag
 * is NULL; else the errors of edit id, or with id NULL of the patch as a
 * whole (global-errors).
 */
static char *
patch_status(const struct rcreq *r, const char *id, int status,
    const char *tag, const char *path, const char *apptag, const char *msg)
{
	ucl_object_t	*top, *st, *es, *arr, *e, *ok;
	char		*json;

	st = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(st, ucl_object_fromstring(r->patch_id != NULL ?
	    r->patch_id : ""), "patch-id", 0, false);
	if (tag == NULL) {
		ok = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(ok, ucl_object_typed_new(UCL_NULL));
		ucl_object_insert_key(st, ok, "ok", 0, false);
	} else if (id == NULL)
		ucl_object_insert_key(st, error_list(status, tag, path, apptag,
		    msg), "errors", 0, false);
	else {
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromstring(id), "edit-id",
		    0, false);
		ucl_object_insert_key(e, error_list(status, tag, path, apptag,
		    msg), "errors", 0, false);
		arr = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(arr, e);
		es = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(es, arr, "edit", 0, false);
		ucl_object_insert_key(st, es, "edit-status", 0, false);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, st, "ietf-yang-patch:yang-patch-status", 0,
	    false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (json);
}

/* A body of RFC 8040's media type. */
static int
reply_yang(struct http_request *req, int status, char *json)
{

	if (json == NULL) {
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		return (WEB_OK);
	}
	http_response_header(req, "content-type", "application/yang-data+json");
	http_response_header(req, "cache-control", "no-store");
	http_response_header(req, "x-content-type-options", "nosniff");
	http_response(req, status, json, strlen(json));
	free(json);
	return (WEB_OK);
}

static int
reply_doc(struct http_request *req, ucl_object_t *top)
{
	char	*json;

	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (reply_yang(req, 200, json));
}

int
restconf_reply(struct http_request *req, ucl_object_t *top)
{

	return (reply_doc(req, top));
}

int
restconf_error(struct http_request *req, int status, const char *msg)
{

	return (reply_yang(req, status, restconf_errors(status, msg)));
}

int
restconf_error_tag(struct http_request *req, int status, const char *tag,
    const char *msg)
{

	return (reply_yang(req, status, errors_of(status, tag, NULL, msg)));
}

/* GET /.well-known/host-meta: the root, as RFC 6415's XRD. */
int
api_host_meta(struct http_request *req)
{
	static const char	xrd[] = "<XRD xmlns='http://docs.oasis-open."
				    "org/ns/xri/xrd-1.0'>\n  <Link rel='restconf' "
				    "href='/restconf'/>\n</XRD>\n";

	http_response_header(req, "content-type", "application/xrd+xml");
	http_response(req, 200, xrd, sizeof(xrd) - 1);
	return (WEB_OK);
}

/* GET /restconf */
int
api_restconf(struct http_request *req)
{
	ucl_object_t	*top, *r;

	if (!guard(req, false))
		return (WEB_OK);
	r = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(r, ucl_object_typed_new(UCL_OBJECT), "data", 0,
	    false);
	ucl_object_insert_key(r, ucl_object_typed_new(UCL_OBJECT),
	    "operations", 0, false);
	ucl_object_insert_key(r, ucl_object_fromstring(YLIB_VERSION),
	    "yang-library-version", 0, false);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, r, "ietf-restconf:restconf", 0, false);
	return (reply_doc(req, top));
}

/* GET /restconf/yang-library-version */
int
api_restconf_ylv(struct http_request *req)
{
	ucl_object_t	*top;

	if (!guard(req, false))
		return (WEB_OK);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_fromstring(YLIB_VERSION),
	    "ietf-restconf:yang-library-version", 0, false);
	return (reply_doc(req, top));
}

/* The hosts this user may read: id and name each. */
static ucl_object_t *
fleet_object(struct http_request *req)
{
	const struct server	*s;
	ucl_object_t		*fleet, *arr, *h;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (int i = 0; (s = server_at(i)) != NULL; i++) {
		if (!host_role_ok(req, s->id, false, false))
			continue;
		h = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(h, ucl_object_fromstring(s->id), "id", 0,
		    false);
		ucl_object_insert_key(h, ucl_object_fromstring(s->name), "name",
		    0, false);
		ucl_array_append(arr, h);
	}
	fleet = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(fleet, arr, "host", 0, false);
	return (fleet);
}

/* A stream's entry (section 9.1.2): its name, what it is, where its
 * events are read as Server-Sent Events. */
static ucl_object_t *
stream_entry(const char *name, const char *descr, const char *loc)
{
	ucl_object_t	*st1, *acc, *a1;

	st1 = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(st1, ucl_object_fromstring(name), "name", 0,
	    false);
	ucl_object_insert_key(st1, ucl_object_fromstring(descr),
	    "description", 0, false);
	a1 = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(a1, ucl_object_fromstring("json"), "encoding",
	    0, false);
	ucl_object_insert_key(a1, ucl_object_fromstring(loc), "location", 0,
	    false);
	acc = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(acc, a1);
	ucl_object_insert_key(st1, acc, "access", 0, false);
	return (st1);
}

/* restconf-state: what the server can (section 9.1.1), and each host's
 * stream this user may read (9.1.2), then the fleet's, all of theirs. */
static ucl_object_t *
state_object(struct http_request *req)
{
	const struct server	*s;
	ucl_object_t		*streams, *list;
	char			 loc[512];
	bool			 any = false;
	static const char *const caps[] = {
		("urn:ietf:params:restconf:capability:defaults:1.0"
		    "?basic-mode=explicit"),
		"urn:ietf:params:restconf:capability:depth:1.0",
		"urn:ietf:params:restconf:capability:fields:1.0",
		"urn:ietf:params:restconf:capability:with-defaults:1.0",
		"urn:ietf:params:restconf:capability:yang-patch:1.0",
	};
	ucl_object_t	*st, *c, *arr;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < nitems(caps); i++)
		ucl_array_append(arr, ucl_object_fromstring(caps[i]));
	c = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(c, arr, "capability", 0, false);
	st = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(st, c, "capabilities", 0, false);
	list = ucl_object_typed_new(UCL_ARRAY);
	for (int i = 0; (s = server_at(i)) != NULL; i++) {
		if (!host_role_ok(req, s->id, false, false))
			continue;
		snprintf(loc, sizeof(loc), "%s/restconf/streams/%s/json",
		    cfg.origin != NULL ? cfg.origin : "", s->id);
		ucl_array_append(list, stream_entry(s->id, s->name, loc));
		any = true;
	}
	if (any) {
		snprintf(loc, sizeof(loc), "%s/restconf/streams/fleet/json",
		    cfg.origin != NULL ? cfg.origin : "");
		ucl_array_append(list, stream_entry("fleet", "every host's "
		    "events, each in its host's entry of arcana-fleet", loc));
	}
	streams = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(streams, list, "stream", 0, false);
	ucl_object_insert_key(st, streams, "streams", 0, false);
	return (st);
}

/* The console's own modules (RFC 8525), one schema for its datastore. */
static ucl_object_t *
library_object(void)
{
	static const char *const mods[][3] = {
		{ "arcana-fleet", "2026-10-27", "urn:arcana:yang:arcana-fleet" },
		{ "ietf-restconf-monitoring", "2017-01-26",
		    "urn:ietf:params:xml:ns:yang:ietf-restconf-monitoring" },
		{ "ietf-yang-library", "2019-01-04",
		    "urn:ietf:params:xml:ns:yang:ietf-yang-library" },
		{ "ietf-yang-schema-mount", "2019-01-14",
		    "urn:ietf:params:xml:ns:yang:ietf-yang-schema-mount" },
	};
	ucl_object_t	*lib, *set, *sets, *arr, *m, *sch, *ds;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < nitems(mods); i++) {
		m = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(m, ucl_object_fromstring(mods[i][0]),
		    "name", 0, false);
		ucl_object_insert_key(m, ucl_object_fromstring(mods[i][1]),
		    "revision", 0, false);
		ucl_object_insert_key(m, ucl_object_fromstring(mods[i][2]),
		    "namespace", 0, false);
		ucl_array_append(arr, m);
	}
	set = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(set, ucl_object_fromstring("console"), "name",
	    0, false);
	ucl_object_insert_key(set, arr, "module", 0, false);
	sets = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(sets, set);
	lib = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(lib, sets, "module-set", 0, false);
	sch = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(sch, ucl_object_fromstring("console"), "name",
	    0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(arr, ucl_object_fromstring("console"));
	ucl_object_insert_key(sch, arr, "module-set", 0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(arr, sch);
	ucl_object_insert_key(lib, arr, "schema", 0, false);
	ds = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(ds, ucl_object_fromstring(
	    "ietf-datastores:operational"), "name", 0, false);
	ucl_object_insert_key(ds, ucl_object_fromstring("console"), "schema",
	    0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(arr, ds);
	ucl_object_insert_key(lib, arr, "datastore", 0, false);
	ucl_object_insert_key(lib, ucl_object_fromstring("2026-10-27"),
	    "content-id", 0, false);
	return (lib);
}

/*
 * RFC 8528's schema-mounts: each host's entry mounts its agent's
 * schema, inline (agents of other versions serve other modules), the
 * agent's YANG library inside it.
 */
static ucl_object_t *
mounts_object(void)
{
	ucl_object_t	*sm, *arr, *mp;

	mp = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(mp, ucl_object_fromstring("arcana-fleet"),
	    "module", 0, false);
	ucl_object_insert_key(mp, ucl_object_fromstring("agent"), "label", 0,
	    false);
	ucl_object_insert_key(mp, ucl_object_typed_new(UCL_OBJECT), "inline",
	    0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(arr, mp);
	sm = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(sm, arr, "mount-point", 0, false);
	return (sm);
}

/*
 * /restconf/ds/ietf-datastores:<datastore>/... (RFC 8527 section 3.1):
 * a host's running, candidate or operational state, below its entry.
 */
/* OPTIONS (section 4.1): the methods, and the patches taken (RFC 8072
 * section 2). */
static int
options(struct http_request *req)
{

	if (!guard(req, false))
		return (WEB_OK);
	http_response_header(req, "allow",
	    "GET, POST, PUT, PATCH, DELETE, OPTIONS");
	http_response_header(req, "accept-patch",
	    "application/yang-data+json, application/yang-patch+json");
	http_response(req, 200, NULL, 0);
	return (WEB_OK);
}

int
api_restconf_ds(struct http_request *req)
{
	char	sid[16];

	if (req->method == HTTP_METHOD_OPTIONS)
		return (options(req));
	if (req->hdlr_extra != NULL || restconf_host(req->path, sid,
	    sizeof(sid)))
		return (api_restconf_host(req));
	return (restconf_error(req, 404, "the datastores are each host's: "
	    "/restconf/ds/ietf-datastores:<running|candidate|operational>/"
	    "arcana-fleet:fleet/host=<id>"));
}

/*
 * GET /restconf/data[/...]: the console's own nodes here; a host's
 * (FLEET "/host=") read from its agent (hosts.c, restconf_run()).
 */
int
api_restconf_data(struct http_request *req)
{
	ucl_object_t	*top;
	const char	*p = req->path + strlen("/restconf/data");
	char		 sid[16];

	if (req->method == HTTP_METHOD_OPTIONS)
		return (options(req));
	/* establish-subscription POSTed under a host's entry; what else
	 * a host's is, hosts.c's (a change refused or run there). */
	if (req->method == HTTP_METHOD_POST && req->hdlr_extra == NULL) {
		const char	*e = strrchr(req->path, '/');

		if (restconf_host(req->path, sid, sizeof(sid)) && e != NULL &&
		    strcmp(e, "/ietf-subscribed-notifications:"
		    "establish-subscription") == 0)
			return (restconf_establish(req, sid));
	}
	if (restconf_host(req->path, sid, sizeof(sid)))
		return (api_restconf_host(req));
	if (req->method != HTTP_METHOD_GET)
		return (restconf_error(req, 405, "the console's own data is "
		    "read alone; a host's changes are below its entry"));
	if (!guard(req, false))
		return (WEB_OK);
	if (req->query_string != NULL && req->query_string[0] != '\0')
		return (restconf_error(req, 400, "no query parameter is taken "
		    "of the console's own data"));
	top = ucl_object_typed_new(UCL_OBJECT);
	if (*p == '\0' || strcmp(p, "/") == 0) {
		ucl_object_insert_key(top, fleet_object(req),
		    "arcana-fleet:fleet", 0, false);
		ucl_object_insert_key(top, state_object(req),
		    "ietf-restconf-monitoring:restconf-state", 0, false);
		ucl_object_insert_key(top, library_object(),
		    "ietf-yang-library:yang-library", 0, false);
		ucl_object_insert_key(top, mounts_object(),
		    "ietf-yang-schema-mount:schema-mounts", 0, false);
	} else if (strcmp(p, "/arcana-fleet:fleet") == 0)
		ucl_object_insert_key(top, fleet_object(req),
		    "arcana-fleet:fleet", 0, false);
	else if (strcmp(p, "/ietf-restconf-monitoring:restconf-state") == 0)
		ucl_object_insert_key(top, state_object(req),
		    "ietf-restconf-monitoring:restconf-state", 0, false);
	else if (strcmp(p, "/ietf-yang-library:yang-library") == 0)
		ucl_object_insert_key(top, library_object(),
		    "ietf-yang-library:yang-library", 0, false);
	else if (strcmp(p, "/ietf-yang-schema-mount:schema-mounts") == 0)
		ucl_object_insert_key(top, mounts_object(),
		    "ietf-yang-schema-mount:schema-mounts", 0, false);
	else {
		ucl_object_unref(top);
		return (restconf_error(req, 404, "no such resource"));
	}
	return (reply_doc(req, top));
}

#define	DS_PREFIX	"/restconf/ds/ietf-datastores:"
#define	FLEET_SEG	"arcana-fleet:fleet"
#define	HOST_SEG	"/" FLEET_SEG "/host="

/*
 * What path names below a datastore's root: /restconf/data's (the
 * agent's default, *ds -1), or an NMDA datastore's (RFC 8527 section
 * 3.1: /restconf/ds/ietf-datastores:running, candidate, operational).
 * NULL: neither.
 */
static const char *
below_root(const char *path, int *ds)
{
	static const struct {
		const char	*name;
		int		 ds;
	} dss[] = {
		{ "running", CBL_YDS_RUNNING },
		{ "candidate", CBL_YDS_CANDIDATE },
		{ "operational", CBL_YDS_OPERATIONAL },
	};
	const char	*p, *e;

	*ds = -1;
	if (strncmp(path, "/restconf/data", 14) == 0)
		return (path + 14);
	if (strncmp(path, DS_PREFIX, sizeof(DS_PREFIX) - 1) != 0)
		return (NULL);
	p = path + sizeof(DS_PREFIX) - 1;
	e = strchrnul(p, '/');
	for (size_t i = 0; i < nitems(dss); i++)
		if (strlen(dss[i].name) == (size_t)(e - p) &&
		    strncmp(p, dss[i].name, (size_t)(e - p)) == 0) {
			*ds = dss[i].ds;
			return (e);
		}
	return (NULL);
}

/* path's host, when it is a host's entry "/host=<id>"[/...] below a
 * datastore's root. */
bool
restconf_host(const char *path, char *sid, size_t len)
{
	const char	*p, *e;
	size_t		 n;
	int		 ds;

	if ((p = below_root(path, &ds)) == NULL || strncmp(p, HOST_SEG,
	    sizeof(HOST_SEG) - 1) != 0)
		return (false);
	p += sizeof(HOST_SEG) - 1;
	e = strchrnul(p, '/');
	n = (size_t)(e - p);
	if (n == 0 || n >= len || strspn(p, "0123456789abcdef") < n)
		return (false);
	memcpy(sid, p, n);
	sid[n] = '\0';
	return (true);
}

/* %XX decoded in place; false: a bad escape. */
static bool
pct_decode(char *s)
{
	char	*w = s;
	int	 hi, lo;

	for (; *s != '\0'; s++) {
		if (*s != '%') {
			*w++ = *s;
			continue;
		}
		if (!isxdigit((unsigned char)s[1]) ||
		    !isxdigit((unsigned char)s[2]))
			return (false);
		hi = isdigit((unsigned char)s[1]) ? s[1] - '0' :
		    tolower((unsigned char)s[1]) - 'a' + 10;
		lo = isdigit((unsigned char)s[2]) ? s[2] - '0' :
		    tolower((unsigned char)s[2]) - 'a' + 10;
		*w++ = (char)(hi * 16 + lo);
		s += 2;
	}
	*w = '\0';
	return (true);
}

static const struct cbl_ymodule *
module_named(const char *name)
{

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++)
		if (strcmp(ymodel_schema.mod[i]->name, name) == 0)
			return (ymodel_schema.mod[i]);
	return (NULL);
}

static bool
is_data(const struct cbl_ynode *n)
{

	return (n->kind == CBL_YN_CONTAINER || n->kind == CBL_YN_LIST ||
	    n->kind == CBL_YN_LEAF || n->kind == CBL_YN_LEAFLIST ||
	    n->kind == CBL_YN_ANYDATA || n->kind == CBL_YN_ANYXML);
}

/* The data node of that name (and module, when given) under parent, or
 * at the top when parent is NULL. */
static const struct cbl_ynode *
node_named(const struct cbl_ynode *parent, const char *mod, const char *name)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*c;

	/* At the top, or below a mount point (RFC 8528): a module's
	 * top-level node, named with its module. */
	if (parent == NULL || (parent->flags & CBL_YNF_MOUNT) != 0) {
		if (mod == NULL || (m = module_named(mod)) == NULL)
			return (NULL);
		for (uint32_t k = 0; k < m->ntop; k++)
			if (is_data(m->top[k]) && strcmp(m->top[k]->name,
			    name) == 0)
				return (m->top[k]);
		return (NULL);
	}
	for (uint32_t i = 0; i < parent->nchild; i++) {
		c = parent->child[i];
		if (!is_data(c) || strcmp(c->name, name) != 0)
			continue;
		if (mod != NULL ? strcmp(c->module->name, mod) == 0 :
		    c->module == parent->module)
			return (c);
	}
	return (NULL);
}

/* ietf-netconf's rpc of a datastore's, by name; NULL: no such one. */
static const struct cbl_ynode *
rpc_named(const char *mod, const char *name)
{
	const struct cbl_ymodule	*m;

	if (strcmp(mod, "ietf-netconf") != 0 || (strcmp(name, "commit") !=
	    0 && strcmp(name, "cancel-commit") != 0 && strcmp(name,
	    "discard-changes") != 0) || (m = module_named(mod)) == NULL)
		return (NULL);
	for (uint32_t k = 0; k < m->ntop; k++)
		if (m->top[k]->kind == CBL_YN_RPC && strcmp(m->top[k]->name,
		    name) == 0)
			return (m->top[k]);
	return (NULL);
}

/* v in an XPath literal; false when it has both kinds of quote. */
static bool
put_literal(FILE *fp, const char *v)
{
	char	q;

	q = strchr(v, '\'') == NULL ? '\'' : '"';
	if (q == '"' && strchr(v, '"') != NULL)
		return (false);
	fprintf(fp, "%c%s%c", q, v, q);
	return (true);
}

static void
fields_free(struct fsel *f)
{
	struct fsel	*next;

	for (; f != NULL; f = next) {
		next = f->next;
		fields_free(f->sub);
		free(f->name);
		free(f);
	}
}

/*
 * fields' expression (RFC 8040 4.8.3) from *pp on: paths by ";", a
 * path's nodes by "/", what is selected under its last in "( )".  NULL
 * where it is none; *pp past what was read.
 */
static struct fsel *
fields_parse(const char **pp, int level)
{
	struct fsel	*head = NULL, **tail = &head, *f, *last;
	const char	*p = *pp;
	size_t		 n;

	if (level > 16)
		return (NULL);
	for (;;) {
		/* A path: its nodes, each under the one before. */
		last = NULL;
		for (;;) {
			n = strcspn(p, "/;()");
			if (n == 0 || (f = calloc(1, sizeof(*f))) == NULL) {
				fields_free(head);
				return (NULL);
			}
			if ((f->name = strndup(p, n)) == NULL) {
				free(f);
				fields_free(head);
				return (NULL);
			}
			if (last == NULL) {
				*tail = f;
				tail = &f->next;
			} else
				last->sub = f;
			last = f;
			p += n;
			if (*p != '/')
				break;
			p++;
		}
		if (*p == '(') {
			p++;
			if ((last->sub = fields_parse(&p, level + 1)) == NULL ||
			    *p != ')') {
				fields_free(head);
				return (NULL);
			}
			p++;
		}
		if (*p != ';')
			break;
		p++;
	}
	*pp = p;
	return (head);
}

void
restconf_free(struct rcreq *r)
{

	if (r == NULL)
		return;
	fields_free(r->fields);
	ucl_object_unref(r->body);
	for (size_t i = 0; i < r->naccept; i++)
		free(r->accept[i]);
	/* The segment being read when it failed has keys too. */
	for (size_t i = 0; i < SEG_MAX && i <= r->nseg; i++)
		for (size_t k = 0; k < r->seg[i].nkey; k++)
			free(r->seg[i].key[k]);
	for (size_t i = 0; i < r->nedit; i++) {
		if (r->edit[i].t != r)
			restconf_free(r->edit[i].t);
		restconf_free(r->edit[i].pt);
		free(r->edit[i].id);
	}
	free(r->edit);
	free(r->xpath);
	free(r->base);
	free(r->point);
	free(r->patch_id);
	free(r->location);
	free(r->errjson);
	free(r);
}

/*
 * The nodes of rest (an api-path's segments below the host's entry, by
 * "/"), after those r has: each a data node of the one before, the
 * first named with its module; a list's entry by all its keys, a
 * leaf-list's by its value.  With encoded (a query's, a body's), each
 * name and key %-decoded once cut out; the path's own, libwebsockets
 * has decoded, and a key with "/" or "," in it cannot be named there.
 * 0, or *why.
 */
static int
parse_segs(struct rcreq *r, char *rest, bool encoded, const char **why)
{
	struct rcseg	*sg;
	char		*seg, *keys, *colon, *mod, *name, *k;

	while ((seg = strsep(&rest, "/")) != NULL) {
		if (r->nseg == SEG_MAX) {
			*why = "the path is too deep";
			return (EINVAL);
		}
		sg = &r->seg[r->nseg];
		if ((keys = strchr(seg, '=')) != NULL)
			*keys++ = '\0';
		if (encoded && !pct_decode(seg)) {
			*why = "a bad %-escape";
			return (EINVAL);
		}
		mod = NULL;
		name = seg;
		if ((colon = strchr(seg, ':')) != NULL) {
			*colon = '\0';
			mod = seg;
			name = colon + 1;
		}
		/* An rpc of the host's, the path's only node: invoked as
		 * an action of the mount (RFC 8528 section 3.3). */
		if (!encoded && r->nseg == 0 && rest == NULL && mod != NULL &&
		    (r->rpc = rpc_named(mod, name)) != NULL)
			break;
		if ((sg->n = node_named(r->nseg == 0 ? NULL :
		    r->seg[r->nseg - 1].n, mod, name)) == NULL) {
			*why = r->nseg == 0 && mod == NULL ? "the first node "
			    "of the path is named with its module" :
			    "no such node";
			return (EINVAL);
		}
		while (keys != NULL && (k = strsep(&keys, ",")) != NULL) {
			if (sg->nkey == KEY_MAX || (encoded && !pct_decode(k))) {
				*why = "a bad key";
				return (EINVAL);
			}
			if ((sg->key[sg->nkey++] = strdup(k)) == NULL) {
				*why = "out of memory";
				return (ENOMEM);
			}
		}
		if (sg->n->kind == CBL_YN_LIST) {
			if (sg->nkey != sg->n->nkeys || sg->nkey == 0) {
				*why = "a list's entry is named by all its keys";
				return (EINVAL);
			}
		} else if (sg->n->kind == CBL_YN_LEAFLIST) {
			if (sg->nkey != 1) {
				*why = "a leaf-list's entry is named by its "
				    "value";
				return (EINVAL);
			}
		} else if (sg->nkey != 0) {
			*why = "only a list's or a leaf-list's entry has keys";
			return (EINVAL);
		}
		r->nseg++;
		/* A leaf, a leaf-list's entry or anydata ends it. */
		if (sg->n->kind != CBL_YN_CONTAINER && sg->n->kind !=
		    CBL_YN_LIST && rest != NULL) {
			*why = "nothing is below a leaf";
			return (EINVAL);
		}
	}
	return (0);
}

/* Whether n's name is qualified below the one before it: at the top,
 * below a mount point, where the module changes (RFC 7951 section 4). */
static bool
qualified(const struct rcreq *r, size_t i)
{

	return (i == 0 || r->seg[i].n->module != r->seg[i - 1].n->module ||
	    (r->seg[i - 1].n->flags & CBL_YNF_MOUNT) != 0);
}

/*
 * r's first n nodes as an instance-identifier (RFC 7951 section 6.11),
 * an XPath the agent reads: each module's name where it changes, each
 * entry's keys.  malloc'd; NULL and *why: a key with both kinds of quote.
 */
static char *
path_of(const struct rcreq *r, size_t n, const char **why)
{
	const struct rcseg	*sg;
	FILE			*fp;
	char			*s = NULL;
	size_t			 len;
	bool			 ok = true;

	if ((fp = open_memstream(&s, &len)) == NULL) {
		*why = "out of memory";
		return (NULL);
	}
	for (size_t i = 0; ok && i < n; i++) {
		sg = &r->seg[i];
		fprintf(fp, "/%s%s%s", qualified(r, i) ? sg->n->module->name :
		    "", qualified(r, i) ? ":" : "", sg->n->name);
		if (sg->n->kind == CBL_YN_LIST)
			for (size_t k = 0; ok && k < sg->nkey; k++) {
				fprintf(fp, "[%s=", sg->n->child[sg->n->keys[k]]->
				    name);
				ok = put_literal(fp, sg->key[k]);
				fputc(']', fp);
			}
		else if (sg->n->kind == CBL_YN_LEAFLIST) {
			fputs("[.=", fp);
			ok = put_literal(fp, sg->key[0]);
			fputc(']', fp);
		}
	}
	if (fclose(fp) != 0 || !ok) {
		*why = ok ? "out of memory" : "a key with both kinds of quote";
		free(s);
		return (NULL);
	}
	return (s);
}

/* s %-encoded as a key in a path is (section 3.5.3): all but what RFC
 * 3986 leaves unreserved. */
static void
put_pct(FILE *fp, const char *s)
{

	for (; *s != '\0'; s++)
		if (isalnum((unsigned char)*s) || strchr("-._~", *s) != NULL)
			fputc(*s, fp);
		else
			fprintf(fp, "%%%02X", (unsigned char)*s);
}

/* r's nodes as an api-path (section 3.5.3) after its host's entry, its
 * whole URL: the console's origin first. */
static char *
url_of(const struct rcreq *r)
{
	const struct rcseg	*sg;
	FILE			*fp;
	char			*s = NULL;
	size_t			 len;

	if ((fp = open_memstream(&s, &len)) == NULL)
		return (NULL);
	fprintf(fp, "%s%s", cfg.origin != NULL ? cfg.origin : "", r->base);
	for (size_t i = 0; i < r->nseg; i++) {
		sg = &r->seg[i];
		fprintf(fp, "/%s%s%s", qualified(r, i) ? sg->n->module->name :
		    "", qualified(r, i) ? ":" : "", sg->n->name);
		for (size_t k = 0; k < sg->nkey; k++) {
			fputc(k == 0 ? '=' : ',', fp);
			put_pct(fp, sg->key[k]);
		}
	}
	if (fclose(fp) != 0) {
		free(s);
		return (NULL);
	}
	return (s);
}

/*
 * A path below r's first n nodes, of a YANG Patch's edit or a point (s,
 * "/" r's own; encoded as a body has it, or decoded), as a request of
 * its own.  NULL and *why: none.
 */
static struct rcreq *
parse_below(const struct rcreq *r, size_t n, const char *s, bool encoded,
    const char **why)
{
	struct rcreq	*t;
	char		*copy;

	*why = NULL;
	if (s == NULL || s[0] != '/') {
		*why = "a path begins with /";
		return (NULL);
	}
	if ((t = calloc(1, sizeof(*t))) == NULL || (copy = strdup(s + 1)) ==
	    NULL) {
		free(t);
		*why = "out of memory";
		return (NULL);
	}
	t->ds = r->ds;
	for (size_t i = 0; i < n; i++) {
		t->seg[i].n = r->seg[i].n;
		for (size_t k = 0; k < r->seg[i].nkey; k++)
			if ((t->seg[i].key[t->seg[i].nkey++] =
			    strdup(r->seg[i].key[k])) == NULL)
				goto bad;
		t->nseg++;
	}
	if (copy[0] != '\0' && parse_segs(t, copy, encoded, why) != 0)
		goto bad;
	free(copy);
	return (t);
bad:
	if (*why == NULL)
		*why = "out of memory";
	free(copy);
	restconf_free(t);
	return (NULL);
}

/*
 * The api-path below a host's entry (section 3.5.3), and the query, as
 * a request of the agent; NULL and *why when it is none.
 */
struct rcreq *
restconf_parse(const char *path, const char *query, const char **why)
{
	struct rcreq	*r;
	const char	*e;
	char		*copy, *rest;
	char		*q, *qcopy, *arg, *val;

	if ((r = calloc(1, sizeof(*r))) == NULL) {
		*why = "out of memory";
		return (NULL);
	}
	r->ds = -1;
	r->method = HTTP_METHOD_GET;
	/* The query.  libwebsockets cuts it at ";" as at "&": a piece with
	 * no "=" is the rest of the one before it (fields'). */
	qcopy = query != NULL ? strdup(query) : NULL;
	for (q = qcopy; q != NULL && (q = strchr(q, '&')) != NULL; q++)
		if (memchr(q + 1, '=', strcspn(q + 1, "&")) == NULL)
			*q = ';';
	for (q = qcopy; q != NULL && (arg = strsep(&q, "&")) != NULL;) {
		if (arg[0] == '\0')
			continue;
		/* with-origin has no value (RFC 8527 section 3.2.2). */
		if (strcmp(arg, "with-origin") == 0) {
			r->origin = true;
			continue;
		}
		if ((val = strchr(arg, '=')) == NULL) {
			*why = "a query parameter is name=value";
			goto bad;
		}
		*val++ = '\0';
		if (strcmp(arg, "content") == 0) {
			r->content = strcmp(val, "config") == 0 ? CONTENT_CONFIG :
			    strcmp(val, "nonconfig") == 0 ? CONTENT_NONCONFIG :
			    strcmp(val, "all") == 0 ? CONTENT_ALL : -1;
			if (r->content == -1) {
				*why = "content is config, nonconfig or all";
				goto bad;
			}
		} else if (strcmp(arg, "depth") == 0) {
			if (strcmp(val, "unbounded") == 0)
				r->depth = 0;
			else if ((r->depth = atoi(val)) < 1 || r->depth >
			    65535 || strspn(val, "0123456789") != strlen(val)) {
				*why = "depth is 1 to 65535, or unbounded";
				goto bad;
			}
		} else if (strcmp(arg, "with-defaults") == 0) {
			r->defaults = strcmp(val, "explicit") == 0 ?
			    WD_EXPLICIT : strcmp(val, "report-all") == 0 ?
			    WD_REPORT_ALL : strcmp(val, "trim") == 0 ?
			    WD_TRIM : strcmp(val, "report-all-tagged") == 0 ?
			    WD_TAGGED : -1;
			if (r->defaults == -1) {
				*why = "with-defaults is explicit, report-all, "
				    "trim or report-all-tagged";
				goto bad;
			}
		} else if (strcmp(arg, "fields") == 0) {
			const char	*f = val;

			if (r->fields != NULL || !pct_decode(val) ||
			    (r->fields = fields_parse(&f, 0)) == NULL ||
			    *f != '\0') {
				*why = "fields is node paths by ;, a node's own "
				    "in ( )";
				goto bad;
			}
		} else if (strcmp(arg, "arcana-accept") == 0) {
			/* Arcana's own: the warnings a change goes on
			 * despite, each its error-app-tag, by commas. */
			char	*t;

			while ((t = strsep(&val, ",")) != NULL)
				if (*t != '\0' && r->naccept < ACCEPT_MAX &&
				    (r->accept[r->naccept++] = strdup(t)) ==
				    NULL) {
					*why = "out of memory";
					goto bad;
				}
		} else if (strcmp(arg, "insert") == 0) {
			r->insert = strcmp(val, "first") == 0 ?
			    CBL_DWHERE_FIRST : strcmp(val, "last") == 0 ?
			    CBL_DWHERE_LAST : strcmp(val, "before") == 0 ?
			    CBL_DWHERE_BEFORE : strcmp(val, "after") == 0 ?
			    CBL_DWHERE_AFTER : -1;
			if (r->insert == -1) {
				*why = "insert is first, last, before or after";
				goto bad;
			}
		} else if (strcmp(arg, "point") == 0) {
			if (r->point != NULL || (r->point = strdup(val)) ==
			    NULL) {
				*why = "point is one path";
				goto bad;
			}
		} else {
			*why = "of the query parameters content, depth, "
			    "fields, with-defaults, with-origin, insert, point "
			    "and arcana-accept are taken";
			goto bad;
		}
	}
	free(qcopy);
	qcopy = NULL;
	/* The path below the host's entry, a segment a node. */
	if ((rest = (char *)(uintptr_t)below_root(path, &r->ds)) == NULL ||
	    strncmp(rest, HOST_SEG, sizeof(HOST_SEG) - 1) != 0) {
		*why = "no host's entry";
		goto bad;
	}
	if (r->origin && r->ds != CBL_YDS_OPERATIONAL) {
		*why = "with-origin is the operational datastore's";
		goto bad;
	}
	e = strchrnul(rest + sizeof(HOST_SEG) - 1, '/');
	if ((r->base = strndup(path, (size_t)(e - path))) == NULL) {
		*why = "out of memory";
		goto bad;
	}
	if (*e == '\0' || e[1] == '\0')
		return (r);
	if ((copy = strdup(e + 1)) == NULL) {
		*why = "out of memory";
		goto bad;
	}
	if (parse_segs(r, copy, false, why) != 0) {
		free(copy);
		goto bad;
	}
	free(copy);
	if (r->nseg > 0 && (r->xpath = path_of(r, r->nseg, why)) == NULL)
		goto bad;
	return (r);
bad:
	free(qcopy);
	restconf_free(r);
	return (NULL);
}

/* A JSON value's text, as a key is written in the path. */
static bool
value_is(const ucl_object_t *v, const char *want)
{
	const char	*s;

	if (v == NULL)
		return (false);
	s = ucl_object_tostring_forced(v);
	return (s != NULL && strcmp(s, want) == 0);
}

/* n's member name in its parent's object: qualified at the top or where
 * its module is not its parent's (RFC 7951 section 4). */
static const char *
member(const struct cbl_ynode *n, const struct cbl_ynode *parent, char *buf,
    size_t len)
{

	if (parent == NULL || n->module != parent->module) {
		snprintf(buf, len, "%s:%s", n->module->name, n->name);
		return (buf);
	}
	return (n->name);
}

static const struct cbl_ynode *
child_by_member(const struct cbl_ynode *n, const char *key)
{
	const char	*colon, *name;

	name = (colon = strchr(key, ':')) != NULL ? colon + 1 : key;
	for (uint32_t i = 0; n != NULL && i < n->nchild; i++)
		if (is_data(n->child[i]) && strcmp(n->child[i]->name, name) ==
		    0)
			return (n->child[i]);
	return (NULL);
}

static ucl_object_t	*shape(const struct cbl_ynode *, const ucl_object_t *,
			    int, int, bool);

/*
 * The annotations of object o (RFC 7952 section 5.2's "@" members) into
 * out, what was made of it: its own ("@"), and each member's ("@name")
 * where out has that member; one out has already gains these.
 */
static void
annotations(ucl_object_t *out, const ucl_object_t *o)
{
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it = NULL, jt;
	ucl_object_t		*have;
	const char		*k;

	while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
		k = ucl_object_key(v);
		if (k[0] != '@' || (k[1] != '\0' &&
		    ucl_object_lookup(out, k + 1) == NULL))
			continue;
		have = __DECONST(ucl_object_t *, ucl_object_lookup(out, k));
		if (have == NULL || ucl_object_type(have) != UCL_OBJECT ||
		    ucl_object_type(v) != UCL_OBJECT) {
			if (have == NULL)
				ucl_object_insert_key(out, ucl_object_copy(v),
				    k, 0, true);
			continue;
		}
		jt = NULL;
		while ((e = ucl_object_iterate(v, &jt, true)) != NULL)
			if (ucl_object_lookup(have, ucl_object_key(e)) == NULL)
				ucl_object_insert_key(have, ucl_object_copy(e),
				    ucl_object_key(e), 0, true);
	}
}

/*
 * The members of a container's or a list entry's object, as content and
 * depth leave them, a list entry's keys whatever content says; *any:
 * one but a key is left.
 */
static ucl_object_t *
shape_object(const struct cbl_ynode *n, const ucl_object_t *o, int depth,
    int content, bool *any)
{
	const struct cbl_ynode	*c;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*out, *s;
	bool			 key;

	*any = false;
	out = ucl_object_typed_new(UCL_OBJECT);
	if (depth == 1)
		return (out);
	while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
		if (ucl_object_key(v)[0] == '@')
			continue;
		c = child_by_member(n, ucl_object_key(v));
		key = c != NULL && (c->flags & CBL_YNF_KEY) != 0;
		if ((s = shape(c, v, depth > 0 ? depth - 1 : 0, content,
		    key)) == NULL)
			continue;
		if (!key)
			*any = true;
		ucl_object_insert_key(out, s, ucl_object_key(v), 0, true);
	}
	annotations(out, o);
	return (out);
}

/*
 * v, node n's value (NULL: a node these tables have not), as content and
 * depth leave it; NULL: left out, as a container or a list is where
 * content leaves nothing of it.  A key stays whatever content says.
 */
static ucl_object_t *
shape(const struct cbl_ynode *n, const ucl_object_t *v, int depth,
    int content, bool key)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*out, *s;
	bool			 config, any, kept;

	config = n == NULL || (n->flags & CBL_YNF_CONFIG) != 0;
	if (n == NULL || (n->kind != CBL_YN_CONTAINER && n->kind !=
	    CBL_YN_LIST)) {
		if (!key && ((content == CONTENT_CONFIG && !config) ||
		    (content == CONTENT_NONCONFIG && config)))
			return (NULL);
		return (ucl_object_copy(v));
	}
	/* Below config false all is state. */
	if (content == CONTENT_CONFIG && !config)
		return (NULL);
	if (n->kind == CBL_YN_CONTAINER) {
		out = shape_object(n, v, depth, content, &any);
		if (!any && depth != 1 && content != CONTENT_ALL) {
			ucl_object_unref(out);
			return (NULL);
		}
		return (out);
	}
	out = ucl_object_typed_new(UCL_ARRAY);
	kept = false;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
		s = shape_object(n, e, depth, content, &any);
		if (!any && depth != 1 && content != CONTENT_ALL) {
			ucl_object_unref(s);
			continue;
		}
		ucl_array_append(out, s);
		kept = true;
	}
	if (!kept && content != CONTENT_ALL) {
		ucl_object_unref(out);
		return (NULL);
	}
	return (out);
}

/* A default's text as RFC 7951 has the leaf's type. */
static ucl_object_t *
default_value(const struct cbl_ynode *n)
{
	const char	*d = n->dflt[0];

	switch (n->type->kind) {
	case CBL_YT_BOOLEAN:
		return (ucl_object_frombool(strcmp(d, "true") == 0));
	case CBL_YT_INT8:
	case CBL_YT_INT16:
	case CBL_YT_INT32:
	case CBL_YT_UINT8:
	case CBL_YT_UINT16:
	case CBL_YT_UINT32:
		return (ucl_object_fromint(strtoll(d, NULL, 10)));
	default:
		return (ucl_object_fromstring(d));
	}
}

/* A leaf that has a default and is there whenever its parent is: in no
 * choice, under no when. */
static bool
has_default(const struct cbl_ynode *n)
{

	return (n->kind == CBL_YN_LEAF && n->ndflt > 0 && n->nwhen == 0 &&
	    n->choice == NULL && n->type != NULL);
}

/*
 * v (node n's) with its leaves' defaults as mode says (with-defaults):
 * report-all those not there added, trim those at their default left
 * out, report-all-tagged added and each at its default tagged (RFC
 * 6243's annotation, RFC 7952's "@" member).  A new value.
 */
static ucl_object_t *
defaults(const struct cbl_ynode *n, const ucl_object_t *v, int mode)
{
	const struct cbl_ynode	*c;
	const ucl_object_t	*m, *e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*out, *tag, *mark;
	char			 at[128];
	bool			 dflt;

	if (n == NULL || mode == WD_EXPLICIT || (n->kind != CBL_YN_CONTAINER &&
	    n->kind != CBL_YN_LIST))
		return (ucl_object_copy(v));
	if (ucl_object_type(v) == UCL_ARRAY) {
		out = ucl_object_typed_new(UCL_ARRAY);
		while ((e = ucl_object_iterate(v, &it, true)) != NULL)
			ucl_array_append(out, defaults(n, e, mode));
		return (out);
	}
	out = ucl_object_typed_new(UCL_OBJECT);
	while ((m = ucl_object_iterate(v, &it, true)) != NULL) {
		if (ucl_object_key(m)[0] == '@')
			continue;
		c = child_by_member(n, ucl_object_key(m));
		dflt = c != NULL && has_default(c) && (c->flags &
		    CBL_YNF_KEY) == 0 && value_is(m, c->dflt[0]);
		if (dflt && mode == WD_TRIM)
			continue;
		ucl_object_insert_key(out, defaults(c, m, mode),
		    ucl_object_key(m), 0, true);
		if (dflt && mode == WD_TAGGED) {
			tag = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(tag, ucl_object_frombool(true),
			    "ietf-netconf-with-defaults:default", 0, false);
			snprintf(at, sizeof(at), "@%s", ucl_object_key(m));
			ucl_object_insert_key(out, tag, at, 0, true);
		}
	}
	annotations(out, v);
	if (mode != WD_REPORT_ALL && mode != WD_TAGGED)
		return (out);
	for (uint32_t i = 0; i < n->nchild; i++) {
		c = n->child[i];
		if (!has_default(c))
			continue;
		snprintf(at, sizeof(at), "%s%s%s", c->module != n->module ?
		    c->module->name : "", c->module != n->module ? ":" : "",
		    c->name);
		if (ucl_object_lookup(out, at) != NULL)
			continue;
		ucl_object_insert_key(out, default_value(c), at, 0, true);
		if (mode == WD_TAGGED) {
			mark = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(mark, ucl_object_frombool(true),
			    "ietf-netconf-with-defaults:default", 0, false);
			snprintf(at, sizeof(at), "@%s%s%s", c->module !=
			    n->module ? c->module->name : "", c->module !=
			    n->module ? ":" : "", c->name);
			ucl_object_insert_key(out, mark, at, 0, true);
		}
	}
	return (out);
}

/* A member's name and fields' node's the same, either qualified. */
static bool
same_name(const char *member, const char *sel)
{
	const char	*a, *b;

	a = (a = strchr(member, ':')) != NULL ? a + 1 : member;
	b = (b = strchr(sel, ':')) != NULL ? b + 1 : sel;
	return (strcmp(a, b) == 0);
}

/* sel's node of that member's name, or NULL. */
static const struct fsel *
selected(const struct fsel *sel, const char *member)
{

	for (; sel != NULL; sel = sel->next)
		if (same_name(member, sel->name))
			return (sel);
	return (NULL);
}

/*
 * What fields selects of v (node n's, a container's or a list's): the
 * members named, each with what is selected under it; a list entry's
 * keys always.  A new value.
 */
static ucl_object_t *
select_fields(const struct fsel *sel, const struct cbl_ynode *n,
    const ucl_object_t *v)
{
	const struct fsel	*f;
	const struct cbl_ynode	*c;
	const ucl_object_t	*m, *e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*out;

	if (ucl_object_type(v) == UCL_ARRAY) {
		out = ucl_object_typed_new(UCL_ARRAY);
		while ((e = ucl_object_iterate(v, &it, true)) != NULL)
			ucl_array_append(out, select_fields(sel, n, e));
		return (out);
	}
	if (ucl_object_type(v) != UCL_OBJECT)
		return (ucl_object_copy(v));
	out = ucl_object_typed_new(UCL_OBJECT);
	while ((m = ucl_object_iterate(v, &it, true)) != NULL) {
		if (ucl_object_key(m)[0] == '@')
			continue;
		c = child_by_member(n, ucl_object_key(m));
		if ((f = selected(sel, ucl_object_key(m))) != NULL)
			ucl_object_insert_key(out, f->sub != NULL ?
			    select_fields(f->sub, c, m) : ucl_object_copy(m),
			    ucl_object_key(m), 0, true);
		else if (c != NULL && (c->flags & CBL_YNF_KEY) != 0)
			ucl_object_insert_key(out, ucl_object_copy(m),
			    ucl_object_key(m), 0, true);
	}
	annotations(out, v);
	return (out);
}

/* v of node n as the query has it: with-defaults, content and depth,
 * then what sel selects of it (NULL: all); the target's own self kept
 * (top). */
static ucl_object_t *
query_shape(const struct rcreq *r, const struct fsel *sel,
    const struct cbl_ynode *n, const ucl_object_t *v, int depth, bool top)
{
	ucl_object_t	*d, *s, *f;
	bool		 any;

	d = defaults(n, v, r->defaults);
	if (top && n != NULL && (n->kind == CBL_YN_LIST || n->kind ==
	    CBL_YN_CONTAINER))
		s = shape_object(n, d, depth, r->content, &any);
	else
		s = shape(n, d, depth, r->content, false);
	ucl_object_unref(d);
	if (s == NULL || sel == NULL || n == NULL ||
	    (n->kind != CBL_YN_LIST && n->kind != CBL_YN_CONTAINER))
		return (s);
	f = select_fields(sel, n, s);
	ucl_object_unref(s);
	return (f);
}

/*
 * The node r names, of what the agent sent (doc, RFC 7951's JSON of all
 * the top-level nodes asked), as its own document; NULL and *status
 * when it is not there.
 */
static ucl_object_t *
select_node(const struct rcreq *r, const ucl_object_t *doc, int *status)
{
	const struct cbl_ynode	*n, *parent = NULL;
	const ucl_object_t	*cur = doc, *v, *e;
	ucl_object_iter_t	 it;
	ucl_object_t		*top, *s, *arr;
	char			 buf[256];
	size_t			 i, k;

	for (i = 0; i < r->nseg; i++) {
		n = r->seg[i].n;
		if ((v = ucl_object_lookup(cur, member(n, parent, buf,
		    sizeof(buf)))) == NULL) {
			*status = 404;
			return (NULL);
		}
		if (n->kind == CBL_YN_LIST) {
			it = NULL;
			while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
				for (k = 0; k < r->seg[i].nkey; k++)
					if (!value_is(ucl_object_lookup(e,
					    n->child[n->keys[k]]->name),
					    r->seg[i].key[k]))
						break;
				if (k == r->seg[i].nkey)
					break;
			}
			if ((v = e) == NULL) {
				*status = 404;
				return (NULL);
			}
		} else if (n->kind == CBL_YN_LEAFLIST) {
			it = NULL;
			while ((e = ucl_object_iterate(v, &it, true)) != NULL)
				if (value_is(e, r->seg[i].key[0]))
					break;
			if ((v = e) == NULL) {
				*status = 404;
				return (NULL);
			}
		}
		cur = v;
		parent = n;
	}
	/* The target itself is there whatever content leaves of it. */
	n = r->seg[r->nseg - 1].n;
	if ((s = query_shape(r, r->fields, n, cur, r->depth, true)) == NULL) {
		*status = 404;
		return (NULL);
	}
	if (n->kind == CBL_YN_LIST || n->kind == CBL_YN_LEAFLIST) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(arr, s);
		s = arr;
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	snprintf(buf, sizeof(buf), "%s:%s", n->module->name, n->name);
	ucl_object_insert_key(top, s, buf, 0, true);
	return (top);
}

/* The data node of that SID as an instance-identifier without keys,
 * /module:a/b, its module named where it changes; NULL: none. */
static const char *
node_path(uint64_t sid, char *buf, size_t len)
{
	const struct cbl_ynode	*v[32], *n;
	size_t			 nv = 0, off = 0;

	if (sid == 0 || (n = cbl_yschema_node(&ymodel_schema, sid)) == NULL)
		return (NULL);
	for (; n != NULL && nv < nitems(v); n = n->parent)
		v[nv++] = n;
	buf[0] = '\0';
	while (nv > 0 && off < len) {
		n = v[--nv];
		off += (size_t)snprintf(buf + off, len - off, "/%s%s%s",
		    n->parent == NULL || n->parent->module != n->module ?
		    n->module->name : "", n->parent == NULL || n->parent->module
		    != n->module ? ":" : "", n->name);
	}
	return (off < len ? buf : NULL);
}

/* A refusal of r's before the host is asked: its error-tag (NULL: the
 * status's) and why, in r. */
static int
refuse(struct rcreq *r, int status, const char *tag, const char **why,
    const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vsnprintf(r->why, sizeof(r->why), fmt, ap);
	va_end(ap);
	r->tag = tag;
	*why = r->why;
	return (status);
}

/*
 * The member of object v that names node n, qualified with its module
 * or not; v's only one.  NULL: none, or another beside it.
 */
static const ucl_object_t *
member_of(const ucl_object_t *v, const struct cbl_ynode *n)
{
	const ucl_object_t	*m;
	const char		*k, *colon;

	if (ucl_object_type(v) != UCL_OBJECT || v->len != 1 ||
	    (m = ucl_object_iterate(v, &(ucl_object_iter_t){ NULL }, true)) ==
	    NULL)
		return (NULL);
	k = ucl_object_key(m);
	if ((colon = strchr(k, ':')) != NULL && (strlen(n->module->name) !=
	    (size_t)(colon - k) || strncmp(k, n->module->name,
	    (size_t)(colon - k)) != 0))
		return (NULL);
	return (strcmp(colon != NULL ? colon + 1 : k, n->name) == 0 ? m :
	    NULL);
}

/*
 * The node body's only member names, a child of r's first n nodes' last
 * (n 0: a top-level node), and its value; the status of what is wrong
 * with it, else 0.
 */
static int
body_node(struct rcreq *r, size_t n, const ucl_object_t *body,
    const struct cbl_ynode **np, const ucl_object_t **vp, const char **why)
{
	const struct cbl_ynode	*parent = n > 0 ? r->seg[n - 1].n : NULL;
	const ucl_object_t	*m;
	const char		*k, *colon;
	char			 mod[128];

	if (ucl_object_type(body) != UCL_OBJECT || body->len != 1 ||
	    (m = ucl_object_iterate(body, &(ucl_object_iter_t){ NULL },
	    true)) == NULL)
		return (refuse(r, 400, NULL, why, "the body is one node: "
		    "{\"module:node\": ...}"));
	k = ucl_object_key(m);
	colon = strchr(k, ':');
	if (colon != NULL) {
		snprintf(mod, sizeof(mod), "%.*s", (int)(colon - k), k);
		if (module_named(mod) == NULL)
			return (refuse(r, 400, "unknown-namespace", why,
			    "%s: no such module", mod));
	}
	if (parent != NULL && parent->kind != CBL_YN_CONTAINER &&
	    parent->kind != CBL_YN_LIST)
		return (refuse(r, 400, NULL, why, "nothing is below a leaf"));
	if ((*np = node_named(parent, colon != NULL ? mod : NULL, colon !=
	    NULL ? colon + 1 : k)) == NULL)
		return (refuse(r, 400, "unknown-element", why, "%s: no such "
		    "node%s", k, parent == NULL && colon == NULL ? " (a "
		    "top-level node is named with its module)" : ""));
	*vp = m;
	return (0);
}

/* A list entry's or a leaf-list entry's value in a body: an array of
 * one; its object, or its value.  NULL: not so. */
static const ucl_object_t *
one_entry(const ucl_object_t *v)
{

	if (ucl_object_type(v) != UCL_ARRAY || ucl_array_size(v) != 1)
		return (NULL);
	return (ucl_array_find_index(v, 0));
}

static struct rcedit *
edit_add(struct rcreq *r, int op, struct rcreq *t, const ucl_object_t *v)
{
	struct rcedit	*e;

	if (r->nedit == EDIT_MAX || (e = reallocarray(r->edit, r->nedit + 1,
	    sizeof(*e))) == NULL)
		return (NULL);
	r->edit = e;
	e = &r->edit[r->nedit++];
	memset(e, 0, sizeof(*e));
	e->op = op;
	e->t = t;
	e->value = v;
	return (e);
}

/* The point of insert= (section 4.8.6): an entry of the target's list,
 * by its path from the host's entry or from the datastore's. */
static int
point_of(struct rcreq *r, struct rcedit *e, const char **why)
{
	const char	*p, *w = NULL;
	char		*dec;
	struct rcreq	*pt;

	if (r->insert == CBL_DWHERE_BEFORE || r->insert == CBL_DWHERE_AFTER) {
		if (r->point == NULL)
			return (refuse(r, 400, "missing-attribute", why,
			    "insert before or after needs a point"));
	} else if (r->point != NULL)
		return (refuse(r, 400, "bad-attribute", why, "a point is "
		    "insert's, before or after"));
	e->where = r->insert;
	if (r->point == NULL)
		return (0);
	/* The query as libwebsockets decoded it, a few escaped again
	 * (web.c): decoded whole, as the path is. */
	if ((dec = strdup(r->point)) == NULL || !pct_decode(dec)) {
		free(dec);
		return (refuse(r, 400, "bad-attribute", why, "a bad point"));
	}
	p = dec;
	if (strncmp(p, "/" FLEET_SEG "/host=", sizeof(FLEET_SEG) + 6) == 0)
		p = strchrnul(p + sizeof(FLEET_SEG) + 6, '/');
	pt = parse_below(r, 0, p, false, &w);
	free(dec);
	if (pt == NULL || pt->nseg == 0 || pt->seg[pt->nseg - 1].n !=
	    e->t->seg[e->t->nseg - 1].n) {
		restconf_free(pt);
		return (refuse(r, 400, "bad-attribute", why, "the point is "
		    "no entry of the target's list%s%s", w != NULL ? ": " : "",
		    w != NULL ? w : ""));
	}
	e->pt = pt;
	return (0);
}

/*
 * POST (section 4.4.1): the node the body has made a child of the
 * target, the path's own extended to it; its URL the Location.
 */
static int
prepare_create(struct rcreq *r, const char **why)
{
	const struct cbl_ynode	*n;
	const ucl_object_t	*v, *e, *k;
	struct rcseg		*sg;
	struct rcedit		*ed;
	int			 st;

	if ((st = body_node(r, r->nseg, r->body, &n, &v, why)) != 0)
		return (st);
	if (r->nseg == SEG_MAX)
		return (refuse(r, 400, NULL, why, "the path is too deep"));
	sg = &r->seg[r->nseg];
	sg->n = n;
	/* A list's entry, by the keys it has; a leaf-list's by its value. */
	if (n->kind == CBL_YN_LIST || n->kind == CBL_YN_LEAFLIST) {
		if ((e = one_entry(v)) == NULL)
			return (refuse(r, 400, NULL, why, "%s: one entry is "
			    "made, an array of it", n->name));
		for (uint16_t i = 0; n->kind == CBL_YN_LIST && i < n->nkeys;
		    i++) {
			if ((k = ucl_object_lookup(e, n->child[n->keys[i]]->
			    name)) == NULL)
				return (refuse(r, 400, NULL, why, "%s: an entry "
				    "without its key %s", n->name,
				    n->child[n->keys[i]]->name));
			if ((sg->key[sg->nkey++] = strdup(
			    ucl_object_tostring_forced(k))) == NULL)
				return (refuse(r, 500, NULL, why, "out of "
				    "memory"));
		}
		if (n->kind == CBL_YN_LEAFLIST && (sg->key[sg->nkey++] =
		    strdup(ucl_object_tostring_forced(e))) == NULL)
			return (refuse(r, 500, NULL, why, "out of memory"));
	}
	r->nseg++;
	if ((ed = edit_add(r, CBL_DOP_CREATE, r, v)) == NULL ||
	    (r->location = url_of(r)) == NULL)
		return (refuse(r, 500, NULL, why, "out of memory"));
	return (point_of(r, ed, why));
}

/* PUT (4.5) and plain PATCH (4.6.1): the body the target's node. */
static int
prepare_put(struct rcreq *r, int op, const char **why)
{
	const struct cbl_ynode	*n;
	const ucl_object_t	*v;
	struct rcedit		*ed;
	int			 st;

	if ((st = body_node(r, r->nseg - 1, r->body, &n, &v, why)) != 0)
		return (st);
	if (n != r->seg[r->nseg - 1].n)
		return (refuse(r, 400, NULL, why, "the body is the target's "
		    "node: %s", r->seg[r->nseg - 1].n->name));
	if ((n->kind == CBL_YN_LIST || n->kind == CBL_YN_LEAFLIST) &&
	    one_entry(v) == NULL)
		return (refuse(r, 400, NULL, why, "%s: the entry is an array "
		    "of it alone", n->name));
	if ((ed = edit_add(r, op, r, v)) == NULL)
		return (refuse(r, 500, NULL, why, "out of memory"));
	return (op == CBL_DOP_REPLACE ? point_of(r, ed, why) : 0);
}

/* A plain PATCH of the datastore: each top-level node the body has,
 * merged. */
static int
prepare_merge_all(struct rcreq *r, const char **why)
{
	const struct cbl_ynode	*n;
	const ucl_object_t	*m;
	ucl_object_iter_t	 it = NULL;
	struct rcedit		*ed;
	struct rcreq		*t;
	const char		*colon, *k;
	char			 mod[128];

	if (ucl_object_type(r->body) != UCL_OBJECT || r->body->len == 0)
		return (refuse(r, 400, NULL, why, "the body is top-level "
		    "nodes: {\"module:node\": ...}"));
	while ((m = ucl_object_iterate(r->body, &it, true)) != NULL) {
		k = ucl_object_key(m);
		if ((colon = strchr(k, ':')) == NULL)
			return (refuse(r, 400, NULL, why, "%s: a top-level "
			    "node is named with its module", k));
		snprintf(mod, sizeof(mod), "%.*s", (int)(colon - k), k);
		if (module_named(mod) == NULL)
			return (refuse(r, 400, "unknown-namespace", why,
			    "%s: no such module", mod));
		if ((n = node_named(NULL, mod, colon + 1)) == NULL)
			return (refuse(r, 400, "unknown-element", why,
			    "%s: no such node", k));
		if ((t = calloc(1, sizeof(*t))) == NULL)
			return (refuse(r, 500, NULL, why, "out of memory"));
		t->seg[0].n = n;
		t->nseg = 1;
		if ((ed = edit_add(r, CBL_DOP_MERGE, t, m)) == NULL) {
			free(t);
			return (refuse(r, 500, NULL, why, "out of memory"));
		}
		ed->whole = true;
	}
	return (0);
}

/*
 * A YANG Patch (RFC 8072): its edits, each with its target below the
 * request's; one that is not well made refused with the patch's status,
 * its edit-id said.
 */
static int
prepare_patch(struct rcreq *r, const char **why)
{
	static const struct {
		const char	*name;
		int		 op;
	} ops[] = {
		{ "create", CBL_DOP_CREATE }, { "delete", CBL_DOP_DELETE },
		{ "insert", CBL_DOP_INSERT }, { "merge", CBL_DOP_MERGE },
		{ "move", CBL_DOP_MOVE }, { "replace", CBL_DOP_REPLACE },
		{ "remove", CBL_DOP_REMOVE },
	};
	static const char *const wheres[] = { "", "first", "last", "before",
	    "after" };
	const ucl_object_t	*p, *edits, *x, *v;
	ucl_object_iter_t	 it = NULL;
	struct rcedit		*ed;
	struct rcreq		*t;
	const char		*id = NULL, *s, *w;
	size_t			 i;
	int			 st, op;

	r->patch = true;
	if ((p = ucl_object_lookup(r->body, "ietf-yang-patch:yang-patch")) ==
	    NULL || ucl_object_type(p) != UCL_OBJECT ||
	    ucl_object_type(ucl_object_lookup(p, "patch-id")) != UCL_STRING ||
	    ((edits = ucl_object_lookup(p, "edit")) != NULL &&
	    ucl_object_type(edits) != UCL_ARRAY))
		return (refuse(r, 400, NULL, why, "a YANG Patch is "
		    "{\"ietf-yang-patch:yang-patch\": {\"patch-id\": ..., "
		    "\"edit\": [...]}}"));
	if ((r->patch_id = strdup(ucl_object_tostring(ucl_object_lookup(p,
	    "patch-id")))) == NULL)
		return (refuse(r, 500, NULL, why, "out of memory"));
	while ((x = ucl_object_iterate(edits, &it, true)) != NULL) {
		id = ucl_object_tostring(ucl_object_lookup(x, "edit-id"));
		s = ucl_object_tostring(ucl_object_lookup(x, "operation"));
		for (i = 0, op = 0; s != NULL && i < nitems(ops); i++)
			if (strcmp(s, ops[i].name) == 0)
				op = ops[i].op;
		st = 0;
		t = NULL;
		w = NULL;
		if (id == NULL || op == 0)
			st = refuse(r, 400, NULL, why, "an edit has its edit-id "
			    "and its operation, one of create, delete, insert, "
			    "merge, move, replace and remove");
		/* "/": the request's target itself, never the datastore. */
		else if ((s = ucl_object_tostring(ucl_object_lookup(x,
		    "target"))) != NULL && strcmp(s, "/") == 0 && r->nseg > 0)
			t = r;
		else if ((t = parse_below(r, r->nseg, s, true, &w)) == NULL ||
		    t->nseg == r->nseg)
			st = refuse(r, 400, NULL, why, "the target is no data "
			    "node below the request's%s%s", w != NULL ? ": " :
			    "", w != NULL ? w : "");
		if (st == 0 && (ed = edit_add(r, op, t, NULL)) == NULL)
			st = refuse(r, 500, NULL, why, "out of memory");
		if (st != 0) {
			if (t != r)
				restconf_free(t);
			goto bad;
		}
		t = NULL;
		if ((ed->id = strdup(id)) == NULL) {
			st = refuse(r, 500, NULL, why, "out of memory");
			goto bad;
		}
		v = ucl_object_lookup(x, "value");
		if (op == CBL_DOP_CREATE || op == CBL_DOP_MERGE || op ==
		    CBL_DOP_REPLACE || op == CBL_DOP_INSERT) {
			if ((ed->value = member_of(v, ed->t->seg[ed->t->nseg -
			    1].n)) == NULL) {
				st = refuse(r, 400, NULL, why, "the value is "
				    "the target's node alone");
				goto bad;
			}
			if ((ed->t->seg[ed->t->nseg - 1].n->kind ==
			    CBL_YN_LIST || ed->t->seg[ed->t->nseg - 1].n->kind ==
			    CBL_YN_LEAFLIST) && one_entry(ed->value) == NULL) {
				st = refuse(r, 400, NULL, why, "the value is "
				    "the target's entry alone");
				goto bad;
			}
		}
		/* where, and point (before, after): insert's and move's. */
		s = ucl_object_tostring(ucl_object_lookup(x, "where"));
		for (i = 1; s != NULL && i < nitems(wheres); i++)
			if (strcmp(s, wheres[i]) == 0)
				ed->where = (int)i;
		if (s != NULL && ed->where == 0) {
			st = refuse(r, 400, "bad-attribute", why, "where is "
			    "first, last, before or after");
			goto bad;
		}
		if ((op == CBL_DOP_INSERT || op == CBL_DOP_MOVE) &&
		    ed->where == 0) {
			st = refuse(r, 400, "missing-attribute", why, "%s "
			    "says where", op == CBL_DOP_INSERT ? "insert" :
			    "move");
			goto bad;
		}
		s = ucl_object_tostring(ucl_object_lookup(x, "point"));
		if ((ed->where == CBL_DWHERE_BEFORE || ed->where ==
		    CBL_DWHERE_AFTER) != (s != NULL)) {
			st = refuse(r, 400, s == NULL ? "missing-attribute" :
			    "bad-attribute", why, "a point is before's or "
			    "after's, and theirs");
			goto bad;
		}
		if (s != NULL && ((ed->pt = parse_below(r, r->nseg, s, true,
		    &w)) == NULL || ed->pt->nseg == 0 ||
		    ed->pt->seg[ed->pt->nseg - 1].n !=
		    ed->t->seg[ed->t->nseg - 1].n)) {
			st = refuse(r, 400, "bad-attribute", why, "the point is "
			    "no entry of the target's list%s%s", w != NULL ?
			    ": " : "", w != NULL ? w : "");
			goto bad;
		}
	}
	return (0);
bad:
	/* Its status, that edit's errors in it. */
	r->errjson = patch_status(r, id, st, r->tag != NULL ? r->tag :
	    tag_of(st), NULL, NULL, r->why);
	return (st);
}

/*
 * A change asked of a host (RFC 8040 section 4.4 to 4.7, 3.6), checked
 * before the host is: a node POSTed (created), PUT (created or
 * replaced), PATCHed (merged; or a YANG Patch) or DELETEd in the
 * candidate, running changed by a commit of it alone (the agents take
 * no other); ietf-netconf's commit, cancel-commit and discard-changes
 * POSTed as the mount's actions.  Through the console a confirmed
 * commit carries persist: its connections are shared by every user,
 * whose closing must not undo it.  body is kept (NULL: none), ctype its
 * media type.  0, or the status and *why.
 */
int
restconf_prepare(struct rcreq *r, int method, const char *ctype,
    ucl_object_t *body, const char **why)
{
	const struct cbl_ynode	*n;
	const ucl_object_t	*in;

	r->method = method;
	r->body = body;
	r->nbase = r->nseg;
	if ((r->insert != 0 || r->point != NULL) && method !=
	    HTTP_METHOD_POST && method != HTTP_METHOD_PUT)
		return (refuse(r, 400, NULL, why, "insert and point are a "
		    "POST's or a PUT's"));
	if (method == HTTP_METHOD_GET)
		return (r->rpc != NULL ? refuse(r, 405, NULL, why, "an rpc is "
		    "POSTed") : 0);
	if (method == HTTP_METHOD_POST && r->rpc != NULL) {
		if (r->ds != -1) {
			*why = "of what is POSTed under a host's entry, "
			    "establish-subscription and ietf-netconf's commit, "
			    "cancel-commit and discard-changes";
			return (405);
		}
		in = ucl_object_lookup(body, "ietf-netconf:input");
		if (body != NULL && in == NULL && ucl_object_type(body) ==
		    UCL_OBJECT && body->len > 0) {
			*why = "an rpc's body is {\"ietf-netconf:input\": "
			    "{...}}";
			return (400);
		}
		if (strcmp(r->rpc->name, "commit") == 0 && in != NULL &&
		    ucl_object_lookup(in, "confirmed") != NULL &&
		    ucl_object_lookup(in, "persist") == NULL) {
			*why = "a confirmed commit through the console says "
			    "persist: the console's connection to the host is "
			    "every user's, and its session's end would undo it";
			return (400);
		}
		return (0);
	}
	if (method == HTTP_METHOD_POST && r->ds == -1)
		return (refuse(r, 405, NULL, why, "of what is POSTed under a "
		    "host's entry, establish-subscription and ietf-netconf's "
		    "commit, cancel-commit and discard-changes; a node is "
		    "made under /restconf/ds/ietf-datastores:candidate"));
	if (r->ds != CBL_YDS_CANDIDATE)
		return (refuse(r, 405, NULL, why, "running changes by a "
		    "confirmed commit of the candidate: the node changed "
		    "under /restconf/ds/ietf-datastores:candidate, then "
		    "ietf-netconf:commit POSTed under the host's entry"));
	if (r->rpc != NULL)
		return (refuse(r, 405, NULL, why, "an rpc is POSTed under "
		    "the host's entry of /restconf/data"));
	/* What is not configuration is not changed (RFC 8342 section
	 * 5.3): its own, or of what is below it. */
	n = r->nseg > 0 ? r->seg[r->nseg - 1].n : NULL;
	if (n != NULL && (n->flags & CBL_YNF_CONFIG) == 0)
		return (refuse(r, 405, NULL, why, "%s is not configuration",
		    n->name));
	if (body == NULL && method != HTTP_METHOD_DELETE)
		return (refuse(r, 400, NULL, why, "the body is the node, as "
		    "RFC 7951's JSON"));
	switch (method) {
	case HTTP_METHOD_POST:
		return (prepare_create(r, why));
	case HTTP_METHOD_PUT:
		if (r->nseg == 0)
			return (refuse(r, 501, NULL, why, "a host's datastore "
			    "is replaced a node at a time"));
		return (prepare_put(r, CBL_DOP_REPLACE, why));
	case HTTP_METHOD_PATCH:
		if (ctype != NULL && strncasecmp(ctype,
		    "application/yang-patch+json", 27) == 0)
			return (prepare_patch(r, why));
		if (ctype != NULL && strncasecmp(ctype,
		    "application/yang-patch", 22) == 0)
			return (refuse(r, 415, NULL, why, "a YANG Patch is "
			    "taken as JSON"));
		if (r->nseg == 0)
			return (prepare_merge_all(r, why));
		return (prepare_put(r, CBL_DOP_MERGE, why));
	case HTTP_METHOD_DELETE:
		if (r->nseg == 0)
			return (refuse(r, 405, NULL, why, "a host's datastore "
			    "is not deleted"));
		if (edit_add(r, CBL_DOP_DELETE, r, NULL) == NULL)
			return (refuse(r, 500, NULL, why, "out of memory"));
		return (0);
	default:
		return (refuse(r, 405, NULL, why, "GET, POST, PUT, PATCH, "
		    "DELETE and OPTIONS"));
	}
}

/* Whether r confirms a commit: its connection one of its own, a proof
 * that a new one reaches the host after the change. */
bool
restconf_confirms(const struct rcreq *r)
{
	const ucl_object_t	*in;

	if (r->rpc == NULL || strcmp(r->rpc->name, "commit") != 0)
		return (false);
	in = ucl_object_lookup(r->body, "ietf-netconf:input");
	return (ucl_object_lookup(in, "persist-id") != NULL &&
	    ucl_object_lookup(in, "confirmed") == NULL);
}

/* The status and error-tag of an agent's refusal, RFC 8040 section 7. */
static int
refusal(int error, const char **tag)
{

	switch (error) {
	case ENOENT:
		*tag = "invalid-value";
		return (404);
	case EACCES:
	case EPERM:
		*tag = "access-denied";
		return (403);
	case EINVAL:
	case ERANGE:
		*tag = "invalid-value";
		return (400);
	case EOPNOTSUPP:
		*tag = "operation-not-supported";
		return (501);
	case EBUSY:
		*tag = "in-use";
		return (409);
	case EEXIST:
		/* A change that needs consent: its error-app-tag says. */
		*tag = "operation-failed";
		return (409);
	case ENOMEM:
	case ENOSPC:
		*tag = "resource-denied";
		return (409);
	default:
		*tag = "operation-failed";
		return (502);
	}
}

/* An rpc of ietf-netconf's over conn, its input from r's body. */
static int
run_rpc(cbl_conn *conn, const struct rcreq *r, char *err, size_t errlen,
    char *apptag, size_t taglen, ucl_object_t **warnings)
{
	const struct cbl_ywarning	*w;
	const struct cbl_ynode		*inode = NULL;
	const ucl_object_t		*in, *v;
	struct ietf_netconf_commit_input cin;
	struct ietf_netconf_cancel_commit_input kin;
	struct ietf_netconf_discard_changes_input din;
	const void			*input;
	cbl_yarena			*a;
	cbl_msg				*m, *rep = NULL;
	size_t				 nw;
	int				 error;

	err[0] = apptag[0] = '\0';
	*warnings = NULL;
	for (uint32_t i = 0; i < r->rpc->nchild; i++)
		if (r->rpc->child[i]->kind == CBL_YN_INPUT)
			inode = r->rpc->child[i];
	in = ucl_object_lookup(r->body, "ietf-netconf:input");
	memset(&cin, 0, sizeof(cin));
	memset(&kin, 0, sizeof(kin));
	memset(&din, 0, sizeof(din));
	if (strcmp(r->rpc->name, "commit") == 0) {
		cin.confirmed = ucl_object_lookup(in, "confirmed") != NULL;
		if ((v = ucl_object_lookup(in, "confirm-timeout")) != NULL) {
			int64_t t = ucl_object_toint(v);

			if (t < 1 || t > UINT32_MAX) {
				snprintf(err, errlen, "confirm-timeout is 1 "
				    "or more seconds");
				return (EINVAL);
			}
			cin.has_confirm_timeout = true;
			cin.confirm_timeout = (uint32_t)t;
		}
		cin.persist = ucl_object_tostring(ucl_object_lookup(in,
		    "persist"));
		cin.persist_id = ucl_object_tostring(ucl_object_lookup(in,
		    "persist-id"));
		input = &cin;
	} else if (strcmp(r->rpc->name, "cancel-commit") == 0) {
		kin.persist_id = ucl_object_tostring(ucl_object_lookup(in,
		    "persist-id"));
		input = &kin;
	} else
		input = &din;
	if (inode == NULL)
		return (EOPNOTSUPP);
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_RPC, 0, &m)) != 0)
		return (error);
	if ((error = cbl_msg_put_ynode(m, inode, input)) != 0 ||
	    (r->naccept > 0 && (error = cbl_msg_set_accept(m,
	    (const char *const *)r->accept, r->naccept)) != 0)) {
		cbl_msg_free(m);
		return (error);
	}
	if ((error = cbl_request(conn, m, &rep, -1)) != 0) {
		snprintf(err, errlen, "%s", rep != NULL &&
		    cbl_msg_err_str(rep) != NULL ? cbl_msg_err_str(rep) :
		    strerror(error));
		if (rep != NULL && cbl_msg_err_apptag(rep) != NULL)
			snprintf(apptag, taglen, "%s",
			    cbl_msg_err_apptag(rep));
		cbl_msg_free(rep);
		return (error);
	}
	/* What the host says it did, which needs telling. */
	if ((a = cbl_yarena_new()) != NULL) {
		if (cbl_msg_ywarnings(rep, a, &w, &nw) == 0 && nw > 0) {
			*warnings = ucl_object_typed_new(UCL_ARRAY);
			for (size_t i = 0; i < nw; i++) {
				ucl_object_t *o = ucl_object_typed_new(
				    UCL_OBJECT);

				ucl_object_insert_key(o, ucl_object_fromstring(
				    w[i].tag), "tag", 0, false);
				ucl_object_insert_key(o, ucl_object_fromstring(
				    w[i].text), "text", 0, false);
				ucl_array_append(*warnings, o);
			}
		}
		cbl_yarena_free(a);
	}
	cbl_msg_free(rep);
	return (0);
}

/*
 * Each host's datastores' entity-tags and times of change (RFC 8040
 * section 3.4.1), by its agent's URI: running's and the candidate's.
 * The agents keep no count of their changes: the console counts those
 * it forwards (an EDIT, a commit, a cancel-commit, a discard-changes), a
 * confirmed commit's undo at its timeout, and the events that say a
 * host's configuration changed otherwise (a file of it, a job, an undo
 * that failed).  A change of running is the candidate's too, which is
 * running's until it is edited.  The count starts again with the
 * console, a number of its run in each tag; a change the console does
 * not hear of (another client's commit) changes no tag.
 */
#define	DS_RUNNING	0x1
#define	DS_CANDIDATE	0x2

struct dstag {
	char		*uri;
	uint64_t	 gen[2];	/* running, candidate */
	time_t		 at[2];
	time_t		 undo;		/* a confirmed commit's timeout */
};

static pthread_mutex_t	 tags_lock = PTHREAD_MUTEX_INITIALIZER;
static struct dstag	*tags;
static size_t		 ntags;
static time_t		 tags_start;
static uint32_t		 tags_run;

/* uri's, made at its first use; NULL: out of memory.  tags_lock held. */
static struct dstag *
tag_entry(const char *uri)
{
	struct dstag	*d;
	time_t		 now;

	now = time(NULL);
	if (tags_start == 0) {
		tags_start = now;
		tags_run = arc4random();
	}
	for (size_t i = 0; i < ntags; i++)
		if (strcmp(tags[i].uri, uri) == 0) {
			d = &tags[i];
			/* A confirmed commit not confirmed in time: undone
			 * by now. */
			if (d->undo != 0 && now >= d->undo) {
				d->gen[0]++;
				d->gen[1]++;
				d->at[0] = d->at[1] = d->undo;
				d->undo = 0;
			}
			return (d);
		}
	if ((d = reallocarray(tags, ntags + 1, sizeof(*tags))) == NULL)
		return (NULL);
	tags = d;
	d = &tags[ntags];
	memset(d, 0, sizeof(*d));
	if ((d->uri = strdup(uri)) == NULL)
		return (NULL);
	d->at[0] = d->at[1] = tags_start;
	ntags++;
	return (d);
}

/* uri's datastores in which changed (DS_*), when; undo, a confirmed
 * commit's timeout from now (0: none waits; -1, as it was). */
static void
tags_changed(const char *uri, int which, time_t when, time_t undo)
{
	struct dstag	*d;

	if (uri == NULL)
		return;
	pthread_mutex_lock(&tags_lock);
	if ((d = tag_entry(uri)) != NULL) {
		for (int i = 0; i < 2; i++)
			if ((which & (1 << i)) != 0) {
				d->gen[i]++;
				d->at[i] = MAX(d->at[i], when);
			}
		if (undo >= 0)
			d->undo = undo > 0 ? when + undo : 0;
	}
	pthread_mutex_unlock(&tags_lock);
}

/* r's datastore's index in the tags: running's (and /restconf/data's),
 * the candidate's; -1, operational's, which has none. */
static int
tag_ds(const struct rcreq *r)
{

	return (r->ds == CBL_YDS_CANDIDATE ? 1 : r->ds ==
	    CBL_YDS_OPERATIONAL ? -1 : 0);
}

/* The entity-tag and the time of change of uri's datastore i. */
static bool
tag_now(const char *uri, int i, char *etag, size_t len, time_t *at)
{
	struct dstag	*d;

	pthread_mutex_lock(&tags_lock);
	if ((d = tag_entry(uri)) != NULL) {
		snprintf(etag, len, "\"%08x-%jx\"", tags_run,
		    (uintmax_t)d->gen[i]);
		*at = d->at[i];
	}
	pthread_mutex_unlock(&tags_lock);
	return (d != NULL);
}

void
restconf_events(const char *uri, const char *json)
{
	struct ucl_parser	*p;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*top;
	const char		*kind;
	time_t			 t, last = 0;

	/* Most have none of these: not read then. */
	if (uri == NULL || json == NULL || (strstr(json, "\"conf\"") == NULL &&
	    strstr(json, "\"job\"") == NULL && strstr(json,
	    "\"undo-failed\"") == NULL))
		return;
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	while ((e = ucl_object_iterate(ucl_object_lookup(top, "events"), &it,
	    true)) != NULL) {
		kind = ucl_object_tostring(ucl_object_lookup(e, "kind"));
		t = (time_t)ucl_object_toint(ucl_object_lookup(e, "t"));
		if (kind != NULL && (strcmp(kind, "conf") == 0 || strcmp(kind,
		    "job") == 0 || strcmp(kind, "undo-failed") == 0))
			last = MAX(last, t);
	}
	ucl_object_unref(top);
	if (last == 0)
		return;
	/* An event read again (a page's, a workflow's, the mail's) is
	 * none newer than the last change: it changes nothing. */
	pthread_mutex_lock(&tags_lock);
	{
		struct dstag	*d;

		if ((d = tag_entry(uri)) != NULL && last > d->at[0]) {
			d->gen[0]++;
			d->gen[1]++;
			d->at[0] = d->at[1] = last;
		}
	}
	pthread_mutex_unlock(&tags_lock);
}

/* An HTTP-date (RFC 9110 section 5.6.7), as IMF-fixdate has it. */
static bool
http_date(const char *s, time_t *t)
{
	struct tm	 tm;
	const char	*e;

	memset(&tm, 0, sizeof(tm));
	if ((e = strptime(s, "%a, %d %b %Y %H:%M:%S GMT", &tm)) == NULL ||
	    *e != '\0')
		return (false);
	*t = timegm(&tm);
	return (true);
}

/* Whether list (If-Match's, If-None-Match's) has etag; weak, a W/ tag
 * as good as its strong one. */
static bool
tag_listed(const char *list, const char *etag, bool weak)
{
	const char	*p = list, *e;
	size_t		 n;

	while (*p != '\0') {
		p += strspn(p, " \t,");
		e = p + strcspn(p, ",");
		n = (size_t)(e - p);
		while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t'))
			n--;
		if (weak && strncmp(p, "W/", 2) == 0 && n >= 2) {
			p += 2;
			n -= 2;
		}
		if (n == strlen(etag) && strncmp(p, etag, n) == 0)
			return (true);
		p = e;
	}
	return (false);
}

int
restconf_precondition(struct http_request *req, struct rcreq *r,
    const char *uri)
{
	const char	*im, *inm, *ims, *ius;
	char		 etag[48];
	time_t		 at, since;
	bool		 edit;
	int		 i;

	if ((i = tag_ds(r)) < 0)
		return (0);
	edit = r->method != HTTP_METHOD_GET;
	if (!http_request_header(req, "if-match", &im))
		im = NULL;
	if (!http_request_header(req, "if-none-match", &inm))
		inm = NULL;
	if (!http_request_header(req, "if-modified-since", &ims))
		ims = NULL;
	if (!http_request_header(req, "if-unmodified-since", &ius))
		ius = NULL;
	if ((im == NULL && inm == NULL && ims == NULL && ius == NULL) ||
	    !tag_now(uri, i, etag, sizeof(etag), &at))
		return (0);
	/* RFC 9110 section 13.2.2's order: If-Match, else
	 * If-Unmodified-Since; If-None-Match, else If-Modified-Since. */
	r->tag = "operation-failed";
	snprintf(r->why, sizeof(r->why), "the datastore is not as the "
	    "condition says: changed since");
	if (im != NULL) {
		if (strcmp(im, "*") == 0)
			r->cond = 1;
		else if (!tag_listed(im, etag, false))
			return (412);
	} else if (ius != NULL && http_date(ius, &since) && at > since)
		return (412);
	if (inm != NULL) {
		if (strcmp(inm, "*") == 0) {
			if (edit)
				r->cond = -1;
		} else if (tag_listed(inm, etag, true))
			return (edit ? 412 : 304);
	} else if (!edit && ims != NULL && http_date(ims, &since) &&
	    at <= since)
		return (304);
	r->tag = NULL;
	r->why[0] = '\0';
	return (0);
}

void
restconf_headers(struct http_request *req, const struct rcreq *r,
    const char *uri, int status)
{
	char		 etag[48], date[64];
	struct tm	 tm;
	time_t		 at;
	int		 i;

	if (r == NULL)
		return;
	if (status == 201 && r->location != NULL)
		http_response_header(req, "location", r->location);
	/* A read's, or the datastore's after a change. */
	if ((i = tag_ds(r)) < 0 || r->rpc != NULL || (status != 304 &&
	    (status < 200 || status > 299)) || uri == NULL ||
	    !tag_now(uri, i, etag, sizeof(etag), &at))
		return;
	gmtime_r(&at, &tm);
	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", &tm);
	http_response_header(req, "etag", etag);
	http_response_header(req, "last-modified", date);
}

int
restconf_refuse(struct http_request *req, struct rcreq *r, const char *uri,
    int status, const char *why)
{
	char	*json;

	if (status == 304) {
		restconf_headers(req, r, uri, status);
		http_response(req, 304, NULL, 0);
		return (WEB_OK);
	}
	if (r != NULL && r->errjson != NULL) {
		json = r->errjson;
		r->errjson = NULL;
	} else
		json = errors_of(status, r != NULL ? r->tag : NULL, NULL, why);
	return (reply_yang(req, status, json));
}

/* The value of key text of list or leaf-list n's k-th, in a. */
static int
key_value(const struct cbl_ynode *n, size_t k, const char *text,
    cbl_yarena *a, const void **v, char *msg, size_t len)
{
	void	*p;
	int	 error;

	if ((error = yjson_text(n->kind == CBL_YN_LIST ?
	    n->child[n->keys[k]] : n, text, a, &p, msg, len)) != 0)
		return (error);
	*v = p;
	return (0);
}

/* The keys of segment sg, its list's or its leaf-list's value, in a. */
static int
seg_keys(const struct rcseg *sg, cbl_yarena *a, const void **keys,
    char *msg, size_t len)
{
	int	error;

	for (size_t k = 0; k < sg->nkey; k++)
		if ((error = key_value(sg->n, k, sg->key[k], a, &keys[k], msg,
		    len)) != 0)
			return (error);
	return (0);
}

/*
 * What t's first n nodes name in tree w: *x, or NULL where it is not.
 * 0, or EINVAL and msg: a key that is no value of its leaf.
 */
static int
locate(const cbl_dtree *w, const struct rcreq *t, size_t n, cbl_yarena *a,
    cbl_dnode **x, char *msg, size_t len)
{
	const void	*keys[KEY_MAX];
	cbl_dnode	*cur = cbl_dtree_root(w);
	int		 error;

	for (size_t i = 0; cur != NULL && i < n; i++) {
		const struct rcseg *sg = &t->seg[i];

		if ((error = seg_keys(sg, a, keys, msg, len)) != 0)
			return (error);
		cur = sg->n->kind == CBL_YN_LIST ? cbl_dnode_entry(cur, sg->n,
		    keys) : sg->n->kind == CBL_YN_LEAFLIST ?
		    cbl_dnode_llentry(cur, sg->n, keys[0]) :
		    cbl_dnode_child(cur, sg->n);
	}
	*x = cur;
	return (0);
}

/* The node segment sg names made a child of parent, *out, with its keys:
 * a node above an edit's. */
static int
path_node(cbl_dnode *parent, const struct rcseg *sg, cbl_yarena *a,
    cbl_dnode **out, char *msg, size_t len)
{
	const void	*keys[KEY_MAX];
	int		 error;

	if ((error = seg_keys(sg, a, keys, msg, len)) != 0)
		return (error);
	if (sg->n->kind == CBL_YN_LIST)
		error = cbl_dnode_add_entry(parent, sg->n, keys, out);
	else
		error = cbl_dnode_add(parent, sg->n, sg->n->kind ==
		    CBL_YN_LEAFLIST ? keys[0] : NULL, out);
	if (error != 0)
		snprintf(msg, len, "%s: %s", sg->n->name, strerror(error));
	return (error);
}

/*
 * Edit e made in w, the candidate's top-level nodes as the console read
 * them: delete and remove take the node away, the others are an edit
 * tree of the nodes above the target as the path names them, the
 * target's with its operation (its value the body's, which must be the
 * one the path names), applied (cbl_dtree_edit()).  0, or an errno with
 * *tag and msg.
 */
static int
edit_apply(cbl_dtree *w, const struct rcedit *e, cbl_yarena *a,
    const char **tag, char *msg, size_t len)
{
	const struct rcreq	*t = e->t;
	const struct rcseg	*sg = &t->seg[t->nseg - 1];
	const void		*keys[KEY_MAX], *pkeys[KEY_MAX];
	struct cbl_dederr	 derr;
	cbl_dtree		*ed;
	cbl_dnode		*x = NULL, *parent, *made = NULL, *c;
	size_t			 n;
	int			 error;

	*tag = "invalid-value";
	if (!e->whole && (error = locate(w, t, t->nseg, a, &x, msg, len)) != 0)
		return (error);
	if (e->op == CBL_DOP_DELETE || e->op == CBL_DOP_REMOVE) {
		if (x == NULL && e->op == CBL_DOP_REMOVE)
			return (0);
		if (x == NULL) {
			*tag = "data-missing";
			snprintf(msg, len, "%s: not there", sg->n->name);
			return (ENOENT);
		}
		if ((error = cbl_dnode_remove(x)) != 0)
			snprintf(msg, len, "%s: a key goes with its entry",
			    sg->n->name);
		return (error);
	}
	if (e->op == CBL_DOP_MOVE && x == NULL) {
		*tag = "data-missing";
		snprintf(msg, len, "%s: not there to move", sg->n->name);
		return (ENOENT);
	}
	if ((ed = cbl_dtree_new(&ymodel_schema)) == NULL)
		return (ENOMEM);
	parent = cbl_dtree_root(ed);
	for (size_t i = 0; i + 1 < t->nseg; i++)
		if ((error = path_node(parent, &t->seg[i], a, &parent, msg,
		    len)) != 0)
			goto out;
	if (e->op == CBL_DOP_MOVE)
		error = path_node(parent, sg, a, &made, msg, len);
	else if ((error = yjson_node(parent, sg->n, e->value, a, &made, msg,
	    len)) != 0) {
		*tag = error == ENOENT ? "unknown-element" : "bad-element";
		goto out;
	}
	if (error != 0)
		goto out;
	/* The body's entry the path's: its keys, alone. */
	if (!e->whole && (sg->n->kind == CBL_YN_LIST || sg->n->kind ==
	    CBL_YN_LEAFLIST)) {
		if ((error = seg_keys(sg, a, keys, msg, len)) != 0)
			goto out;
		for (n = 0, c = cbl_dnode_first(parent); c != NULL;
		    c = cbl_dnode_next(c))
			n += cbl_dnode_schema(c) == sg->n;
		if (n != 1 || made != (sg->n->kind == CBL_YN_LIST ?
		    cbl_dnode_entry(parent, sg->n, keys) :
		    cbl_dnode_llentry(parent, sg->n, keys[0]))) {
			snprintf(msg, len, "%s: the body's entry is not the "
			    "one the path names", sg->n->name);
			error = EINVAL;
			goto out;
		}
	}
	if (!e->whole && (error = cbl_dnode_set_op(made, e->op)) != 0)
		goto out;
	if (e->where != 0) {
		if (e->pt != NULL && (error = seg_keys(&e->pt->seg[e->pt->nseg -
		    1], a, pkeys, msg, len)) != 0)
			goto out;
		if ((error = cbl_dnode_set_where(made, e->where, e->pt != NULL ?
		    pkeys : NULL)) != 0) {
			*tag = "bad-attribute";
			snprintf(msg, len, "%s: no list or leaf-list's entry to "
			    "put where said", sg->n->name);
			goto out;
		}
	}
	if ((error = cbl_dtree_edit(w, ed, CBL_DOP_MERGE, &derr)) != 0) {
		*tag = derr.tag != NULL ? derr.tag : "operation-failed";
		snprintf(msg, len, "%s", derr.msg);
	}
out:
	cbl_dtree_free(ed);
	return (error);
}

/* An agent's refusal of r's, error over conn: its body, of the status
 * and tag the errno says, the node at fault and the app-tag it gives. */
static char *
refused(const struct rcreq *r, int error, const char *err, uint64_t errsid,
    const char *apptag, int *status)
{
	const char	*tag;
	char		 path[512];

	*status = refusal(error, &tag);
	if (r->patch)
		return (patch_status(r, NULL, *status, tag, errsid != 0 ?
		    node_path(errsid, path, sizeof(path)) : NULL, apptag, err));
	return (errors_of_app(*status, tag, errsid != 0 ? node_path(errsid,
	    path, sizeof(path)) : NULL, apptag, err));
}

/*
 * The edits of r over conn: the candidate's top-level nodes they go
 * through read, each edit made of them in order, then all sent back in
 * one EDIT.  A POST's 201, a PUT's 201 or 204, a plain PATCH's and a
 * DELETE's 204, a YANG Patch's 200 and its status.
 */
static void
edits_run(cbl_conn *conn, struct rcreq *r, const char *uri, char **json,
    int *status)
{
	const struct cbl_ynode	*tops[32];
	cbl_dtree		*w = NULL;
	cbl_dnode		*x;
	cbl_yarena		*a;
	const char		*tag;
	uint64_t		 errsid = 0;
	size_t			 ntop = 0, i, k;
	char			 err[512], apptag[80], *path;
	int			 error;

	/* The top-level nodes: of the target, of each edit. */
	for (i = 0; i <= r->nedit; i++) {
		const struct rcreq *t = i < r->nedit ? r->edit[i].t : r;

		if (t->nseg == 0)
			continue;
		for (k = 0; k < ntop && tops[k] != t->seg[0].n; k++)
			;
		if (k == ntop && ntop < nitems(tops))
			tops[ntop++] = t->seg[0].n;
	}
	if ((a = cbl_yarena_new()) == NULL) {
		*status = 500;
		*json = restconf_errors(500, "out of memory");
		return;
	}
	if (ntop > 0 && (error = ytrans_get_tree(conn, tops, ntop,
	    CBL_YDS_CANDIDATE, &w, err, sizeof(err), &errsid)) != 0) {
		*json = refused(r, error, err, errsid, NULL, status);
		goto done;
	}
	/* The request's target there (but what a PUT or POST makes), and as
	 * If-Match: * and If-None-Match: * say. */
	x = NULL;
	if (r->nseg > 0 && (error = locate(w, r, r->nseg, a, &x, err,
	    sizeof(err))) != 0) {
		*status = 400;
		*json = errors_of(400, "invalid-value", NULL, err);
		goto done;
	}
	if (r->nbase > 0 && r->method != HTTP_METHOD_PUT &&
	    r->method != HTTP_METHOD_DELETE) {
		cbl_dnode *b;

		if (locate(w, r, r->nbase, a, &b, err, sizeof(err)) != 0 ||
		    b == NULL) {
			*status = 404;
			*json = r->patch ? patch_status(r, NULL, 404,
			    "invalid-value", NULL, NULL, "no such resource") :
			    restconf_errors(404, "no such resource");
			goto done;
		}
	}
	if ((r->cond == 1 && r->nseg > 0 && x == NULL) || (r->cond == -1 &&
	    (r->nseg == 0 || x != NULL))) {
		*status = 412;
		*json = errors_of(412, "operation-failed", NULL, r->cond == 1 ?
		    "If-Match: *, and it is not there" : "If-None-Match: *, "
		    "and it is there");
		goto done;
	}
	r->created = x == NULL;
	for (i = 0; i < r->nedit; i++) {
		if ((error = edit_apply(w, &r->edit[i], a, &tag, err,
		    sizeof(err))) == 0)
			continue;
		*status = status_of(tag);
		path = path_of(r->edit[i].t, r->edit[i].t->nseg, &(const char *){
		    NULL });
		*json = r->patch ? patch_status(r, r->edit[i].id, *status, tag,
		    path, NULL, err) : errors_of(*status, tag, path, err);
		free(path);
		goto done;
	}
	if (ntop > 0 && (error = yjson_edit_tree(conn, w, tops, ntop,
	    CBL_YDS_CANDIDATE, (const char *const *)r->accept, r->naccept,
	    err, sizeof(err), &errsid, apptag, sizeof(apptag))) != 0) {
		*json = refused(r, error, err, errsid, apptag, status);
		goto done;
	}
	tags_changed(uri, DS_CANDIDATE, time(NULL), -1);
	if (r->patch) {
		*status = 200;
		*json = patch_status(r, NULL, 200, NULL, NULL, NULL, NULL);
	} else {
		*status = r->method == HTTP_METHOD_POST || (r->method ==
		    HTTP_METHOD_PUT && r->created) ? 201 : 204;
		*json = strdup("");
	}
done:
	cbl_dtree_free(w);
	cbl_yarena_free(a);
}

/* A change of a host's (restconf_prepare()) over conn: an rpc's 204, or
 * the warnings it gives with 200; the edits' as edits_run() says;
 * refused, ietf-restconf's errors. */
static void
change_run(cbl_conn *conn, struct rcreq *r, const char *uri, char **json,
    int *status)
{
	const ucl_object_t	*in, *v;
	ucl_object_t		*warnings = NULL, *top;
	uint64_t		 errsid = 0;
	char			 err[512], apptag[80];
	int			 error;

	if (r->rpc == NULL) {
		edits_run(conn, r, uri, json, status);
		return;
	}
	apptag[0] = '\0';
	if ((error = run_rpc(conn, r, err, sizeof(err), apptag,
	    sizeof(apptag), &warnings)) != 0) {
		*json = refused(r, error, err, errsid, apptag, status);
		return;
	}
	/* What it changed, for the entity-tags: a commit running (a
	 * confirmed one undone at its timeout unless confirmed),
	 * cancel-commit running back, discard-changes the candidate. */
	in = ucl_object_lookup(r->body, "ietf-netconf:input");
	if (strcmp(r->rpc->name, "commit") == 0)
		tags_changed(uri, DS_RUNNING | DS_CANDIDATE, time(NULL),
		    ucl_object_lookup(in, "confirmed") == NULL ? 0 :
		    (v = ucl_object_lookup(in, "confirm-timeout")) != NULL ?
		    (time_t)ucl_object_toint(v) : 600);
	else if (strcmp(r->rpc->name, "cancel-commit") == 0)
		tags_changed(uri, DS_RUNNING | DS_CANDIDATE, time(NULL), 0);
	else
		tags_changed(uri, DS_CANDIDATE, time(NULL), -1);
	if (warnings == NULL) {
		*status = 204;
		*json = strdup("");
		return;
	}
	*status = 200;
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, warnings, "arcana-fleet:warnings", 0,
	    false);
	*json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
}

/*
 * A host's part of the datastore, read from its agent over conn: its
 * entry (id, name and what is mounted under it) or the node r names.
 * The reply's body in *json, malloc'd, and its status.
 */
void
restconf_run(cbl_conn *conn, struct rcreq *r, const char *id,
    const char *name, const char *uri, char **json, int *status)
{
	const struct cbl_ynode	*n;
	const struct fsel	*f;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*doc, *top, *h, *arr, *s;
	uint64_t		 sid, errsid;
	char			 err[256], path[512];
	int			 error;

	if (r->method != HTTP_METHOD_GET) {
		change_run(conn, r, uri, json, status);
		return;
	}
	*status = 200;
	sid = r->nseg > 0 ? r->seg[0].n->sid : 0;
	if ((error = ytrans_get_origin(conn, r->nseg > 0 ? &sid : NULL,
	    r->nseg > 0 ? 1 : 0, r->xpath, r->ds, r->origin, &doc, err,
	    sizeof(err), &errsid)) != 0) {
		/* The agent's refusal as RFC 8040 section 7 has it. */
		const char	*tag;

		*status = refusal(error, &tag);
		*json = errors_of(*status, tag, node_path(errsid, path,
		    sizeof(path)), err);
		return;
	}
	if (r->nseg > 0) {
		top = select_node(r, doc, status);
		ucl_object_unref(doc);
		if (top == NULL) {
			*json = restconf_errors(*status, "no such resource");
			return;
		}
	} else {
		/* The entry: its leaves, then what is mounted, each
		 * top-level node shaped as the query says. */
		h = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(h, ucl_object_fromstring(id), "id", 0,
		    false);
		if (r->content != CONTENT_CONFIG && (r->fields == NULL ||
		    selected(r->fields, "name") != NULL))
			ucl_object_insert_key(h, ucl_object_fromstring(name),
			    "name", 0, false);
		while (r->depth != 1 && (v = ucl_object_iterate(doc, &it,
		    true)) != NULL) {
			n = NULL;
			for (uint32_t i = 0; n == NULL && i < ymodel_schema.nmod;
			    i++)
				for (uint32_t k = 0; k <
				    ymodel_schema.mod[i]->ntop; k++) {
					const struct cbl_ynode *t =
					    ymodel_schema.mod[i]->top[k];
					char b[256];

					snprintf(b, sizeof(b), "%s:%s",
					    t->module->name, t->name);
					if (strcmp(b, ucl_object_key(v)) == 0) {
						n = t;
						break;
					}
				}
			f = NULL;
			if (r->fields != NULL && (f = selected(r->fields,
			    ucl_object_key(v))) == NULL)
				continue;
			if ((s = query_shape(r, f != NULL ? f->sub : NULL, n, v,
			    r->depth > 0 ? r->depth - 1 : 0, false)) != NULL)
				ucl_object_insert_key(h, s, ucl_object_key(v), 0,
				    true);
		}
		ucl_object_unref(doc);
		arr = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(arr, h);
		top = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(top, arr, "arcana-fleet:host", 0, false);
	}
	*json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (*json == NULL) {
		*status = 500;
		*json = restconf_errors(500, "out of memory");
	}
}
