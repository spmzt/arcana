/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * RESTCONF (RFC 8040), its reads: the console as the server of a
 * datastore whose hosts are mount points (arcana-fleet, RFC 8528), each
 * host's data the models its agent serves, read through cblink's YANG
 * family.
 *
 *	/.well-known/host-meta		where the root is (section 3.1)
 *	/restconf			the root resource (3.3)
 *	/restconf/yang-library-version
 *	/restconf/data			the console's own: the fleet's hosts,
 *					restconf-state and yang-library
 *	/restconf/data/arcana-fleet:fleet/host=<id>[/<api-path>]
 *					a host's entry, or a node of its
 *					agent's data by RFC 8040's api-path
 *
 * A host's path is made an XPath filter of the agent's GET, the node
 * then taken from the RFC 7951 JSON that comes back.  Of the query
 * parameters, content and depth (section 4.8); every other is refused.
 * Of the query parameters, content, depth, fields (4.8.3) and
 * with-defaults (RFC 8040 4.8.9, RFC 6243): the agent's data is as it
 * has it (explicit), report-all adds the defaults of leaves that are
 * not there, trim leaves out those at their default.  The errors are
 * ietf-restconf's.
 */

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
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

struct rcreq {
	struct rcseg	 seg[SEG_MAX];
	size_t		 nseg;
	char		*xpath;
	int		 depth;		/* 0: unbounded */
	int		 content;
	int		 defaults;
	struct fsel	*fields;
	/* Of the datastores (RFC 8527) and the changes: */
	int		 ds;		/* CBL_YDS_*; -1, /restconf/data */
	int		 method;	/* HTTP_METHOD_* */
	ucl_object_t	*body;		/* a PUT's, an rpc's input */
	const struct cbl_ynode *rpc;	/* POSTed: ietf-netconf's */
	char		*accept[ACCEPT_MAX];
	size_t		 naccept;
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
		return ("operation-not-supported");
	default:
		return ("operation-failed");
	}
}

char *
restconf_errors(int status, const char *msg)
{

	return (errors_of(status, NULL, NULL, msg));
}

/* ietf-restconf:errors of status, its error-tag tag (NULL: status's),
 * the node at fault path (NULL: none), the message msg. */
static char *
errors_of(int status, const char *tag, const char *path, const char *msg)
{
	ucl_object_t	*top, *errs, *arr, *e;
	char		*json;

	e = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(e, ucl_object_fromstring(status == 401 ||
	    status == 403 ? "protocol" : "application"), "error-type", 0,
	    false);
	ucl_object_insert_key(e, ucl_object_fromstring(tag != NULL ? tag :
	    tag_of(status)), "error-tag", 0, false);
	if (path != NULL)
		ucl_object_insert_key(e, ucl_object_fromstring(path),
		    "error-path", 0, false);
	if (msg != NULL)
		ucl_object_insert_key(e, ucl_object_fromstring(msg),
		    "error-message", 0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(arr, e);
	errs = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(errs, arr, "error", 0, false);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, errs, "ietf-restconf:errors", 0, false);
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
 * /restconf/ds/ietf-datastores:<datastore>/... (RFC 8527 section 3.1):
 * a host's running, candidate or operational state, below its entry.
 */
int
api_restconf_ds(struct http_request *req)
{
	char	sid[16];

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
	} else if (strcmp(p, "/arcana-fleet:fleet") == 0)
		ucl_object_insert_key(top, fleet_object(req),
		    "arcana-fleet:fleet", 0, false);
	else if (strcmp(p, "/ietf-restconf-monitoring:restconf-state") == 0)
		ucl_object_insert_key(top, state_object(req),
		    "ietf-restconf-monitoring:restconf-state", 0, false);
	else if (strcmp(p, "/ietf-yang-library:yang-library") == 0)
		ucl_object_insert_key(top, library_object(),
		    "ietf-yang-library:yang-library", 0, false);
	else {
		ucl_object_unref(top);
		return (restconf_error(req, 404, "no such resource"));
	}
	return (reply_doc(req, top));
}

#define	DS_PREFIX	"/restconf/ds/ietf-datastores:"
#define	HOST_SEG	"/arcana-fleet:fleet/host="

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

	if (parent == NULL) {
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
	free(r->xpath);
	free(r);
}

/*
 * The api-path below a host's entry (section 3.5.3), and the query, as
 * a request of the agent; NULL and *why when it is none.
 */
struct rcreq *
restconf_parse(const char *path, const char *query, const char **why)
{
	struct rcreq	*r;
	struct rcseg	*sg;
	FILE		*fp;
	size_t		 xlen;
	char		*copy, *rest, *seg, *keys, *colon, *mod, *name, *k;
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
		} else {
			*why = "of the query parameters content, depth, "
			    "fields, with-defaults and arcana-accept are "
			    "taken";
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
	rest = strchr(rest + sizeof(HOST_SEG) - 1, '/');
	if (rest == NULL || rest[1] == '\0')
		return (r);
	if ((copy = strdup(rest + 1)) == NULL) {
		*why = "out of memory";
		goto bad;
	}
	fp = open_memstream(&r->xpath, &xlen);
	rest = copy;
	while ((seg = strsep(&rest, "/")) != NULL) {
		if (r->nseg == SEG_MAX || fp == NULL) {
			*why = "the path is too deep";
			goto bad2;
		}
		sg = &r->seg[r->nseg];
		/* libwebsockets has decoded the path's %-escapes already: a
		 * key with "/" or "," in it cannot be named. */
		if ((keys = strchr(seg, '=')) != NULL)
			*keys++ = '\0';
		mod = NULL;
		name = seg;
		if ((colon = strchr(seg, ':')) != NULL) {
			*colon = '\0';
			mod = seg;
			name = colon + 1;
		}
		/* An rpc of the host's, the path's only node: invoked as
		 * an action of the mount (RFC 8528 section 3.3). */
		if (r->nseg == 0 && rest == NULL && mod != NULL &&
		    (r->rpc = rpc_named(mod, name)) != NULL)
			break;
		if ((sg->n = node_named(r->nseg == 0 ? NULL :
		    r->seg[r->nseg - 1].n, mod, name)) == NULL) {
			*why = r->nseg == 0 && mod == NULL ? "the first node "
			    "of the path is named with its module" :
			    "no such node";
			goto bad2;
		}
		fprintf(fp, "/%s%s%s", r->nseg == 0 || sg->n->module !=
		    r->seg[r->nseg - 1].n->module ? sg->n->module->name : "",
		    r->nseg == 0 || sg->n->module != r->seg[r->nseg - 1].n->module
		    ? ":" : "", sg->n->name);
		if (keys != NULL) {
			while ((k = strsep(&keys, ",")) != NULL) {
				if (sg->nkey == KEY_MAX) {
					*why = "a bad key";
					goto bad2;
				}
				if ((sg->key[sg->nkey++] = strdup(k)) == NULL) {
					*why = "out of memory";
					goto bad2;
				}
			}
		}
		if (sg->n->kind == CBL_YN_LIST) {
			if (sg->nkey != sg->n->nkeys || sg->nkey == 0) {
				*why = "a list's entry is named by all its keys";
				goto bad2;
			}
			for (size_t i = 0; i < sg->nkey; i++) {
				fprintf(fp, "[%s=", sg->n->child[sg->n->keys[i]]->
				    name);
				if (!put_literal(fp, sg->key[i])) {
					*why = "a key with both kinds of quote";
					goto bad2;
				}
				fputc(']', fp);
			}
		} else if (sg->n->kind == CBL_YN_LEAFLIST) {
			if (sg->nkey != 1) {
				*why = "a leaf-list's entry is named by its "
				    "value";
				goto bad2;
			}
			fputs("[.=", fp);
			if (!put_literal(fp, sg->key[0])) {
				*why = "a value with both kinds of quote";
				goto bad2;
			}
			fputc(']', fp);
		} else if (sg->nkey != 0) {
			*why = "only a list's or a leaf-list's entry has keys";
			goto bad2;
		}
		r->nseg++;
		/* A leaf, a leaf-list's entry or anydata ends it. */
		if (sg->n->kind != CBL_YN_CONTAINER && sg->n->kind !=
		    CBL_YN_LIST && rest != NULL) {
			*why = "nothing is below a leaf";
			goto bad2;
		}
	}
	if (fclose(fp) != 0) {
		fp = NULL;
		*why = "out of memory";
		goto bad2;
	}
	free(copy);
	return (r);
bad2:
	if (fp != NULL)
		(void)fclose(fp);
	free(copy);
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
		c = child_by_member(n, ucl_object_key(v));
		key = c != NULL && (c->flags & CBL_YNF_KEY) != 0;
		if ((s = shape(c, v, depth > 0 ? depth - 1 : 0, content,
		    key)) == NULL)
			continue;
		if (!key)
			*any = true;
		ucl_object_insert_key(out, s, ucl_object_key(v), 0, true);
	}
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
		c = child_by_member(n, ucl_object_key(m));
		if ((f = selected(sel, ucl_object_key(m))) != NULL)
			ucl_object_insert_key(out, f->sub != NULL ?
			    select_fields(f->sub, c, m) : ucl_object_copy(m),
			    ucl_object_key(m), 0, true);
		else if (c != NULL && (c->flags & CBL_YNF_KEY) != 0)
			ucl_object_insert_key(out, ucl_object_copy(m),
			    ucl_object_key(m), 0, true);
	}
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

/*
 * A change asked of a host (RFC 8040 section 4.5, 4.7, 3.6), checked
 * before the host is: a top-level node PUT or DELETEd in the candidate,
 * running changed by a commit of it alone (the agents take no other);
 * ietf-netconf's commit, cancel-commit and discard-changes POSTed as
 * the mount's actions.  Through the console a confirmed commit carries
 * persist: its connections are shared by every user, whose closing must
 * not undo it.  body is kept (NULL: none).  0, or the status and *why.
 */
int
restconf_prepare(struct rcreq *r, int method, ucl_object_t *body,
    const char **why)
{
	const struct cbl_ynode	*n = r->nseg > 0 ? r->seg[0].n : NULL;
	const ucl_object_t	*in, *v;
	char			 key[256];

	r->method = method;
	r->body = body;
	if (method == HTTP_METHOD_GET)
		return (r->rpc != NULL ? (*why = "an rpc is POSTed", 405) : 0);
	if (method == HTTP_METHOD_POST) {
		if (r->rpc == NULL || r->ds != -1) {
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
	if (r->ds != CBL_YDS_CANDIDATE) {
		*why = "running changes by a confirmed commit of the "
		    "candidate: the node put or deleted under "
		    "/restconf/ds/ietf-datastores:candidate, then "
		    "ietf-netconf:commit POSTed under the host's entry";
		return (405);
	}
	if (r->nseg != 1 || n == NULL || r->seg[0].nkey > 0 ||
	    (n->flags & CBL_YNF_CONFIG) == 0) {
		*why = "of the candidate, a host's top-level configuration "
		    "node is put or deleted whole, so far";
		return (501);
	}
	if (method == HTTP_METHOD_PUT) {
		snprintf(key, sizeof(key), "%s:%s", n->module->name, n->name);
		if ((v = ucl_object_lookup(body, key)) == NULL) {
			*why = "a PUT's body is the node: {\"module:node\": "
			    "...}";
			return (400);
		}
		(void)v;
	} else if (method != HTTP_METHOD_DELETE) {
		*why = "GET, PUT, DELETE and POST";
		return (405);
	}
	return (0);
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
		return (500);
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

/* A change of a host's (restconf_prepare()) over conn: 204, or the
 * warnings it gives with 200; refused, ietf-restconf's errors. */
static void
change_run(cbl_conn *conn, const struct rcreq *r, char **json, int *status)
{
	const struct cbl_ynode	*n = r->nseg > 0 ? r->seg[0].n : NULL;
	ucl_object_t		*warnings = NULL, *top, *e;
	const char		*tag;
	uint64_t		 errsid = 0;
	char			 err[512], apptag[80], key[256], path[512];
	int			 error;

	apptag[0] = '\0';
	if (r->rpc != NULL)
		error = run_rpc(conn, r, err, sizeof(err), apptag,
		    sizeof(apptag), &warnings);
	else {
		snprintf(key, sizeof(key), "%s:%s", n->module->name, n->name);
		error = yjson_edit(conn, n, r->method == HTTP_METHOD_DELETE ?
		    NULL : ucl_object_lookup(r->body, key), CBL_YDS_CANDIDATE,
		    (const char *const *)r->accept, r->naccept, err,
		    sizeof(err), &errsid, apptag, sizeof(apptag));
	}
	if (error != 0) {
		*status = refusal(error, &tag);
		top = NULL;
		*json = errors_of(*status, tag, errsid != 0 ? node_path(errsid,
		    path, sizeof(path)) : NULL, err);
		/* The consent it waits for, as RFC 8040 section 7.1 has
		 * an error-app-tag. */
		if (apptag[0] != '\0' && *json != NULL) {
			struct ucl_parser *p = ucl_parser_new(0);

			if (ucl_parser_add_string(p, *json, 0) &&
			    (top = ucl_parser_get_object(p)) != NULL &&
			    (e = (ucl_object_t *)(uintptr_t)ucl_array_head(
			    ucl_object_lookup_path(top,
			    "ietf-restconf:errors.error"))) != NULL) {
				ucl_object_insert_key(e, ucl_object_fromstring(
				    apptag), "error-app-tag", 0, false);
				free(*json);
				*json = (char *)ucl_object_emit(top,
				    UCL_EMIT_JSON_COMPACT);
			}
			ucl_object_unref(top);
			ucl_parser_free(p);
		}
		return;
	}
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
restconf_run(cbl_conn *conn, const struct rcreq *r, const char *id,
    const char *name, char **json, int *status)
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
		change_run(conn, r, json, status);
		return;
	}
	*status = 200;
	sid = r->nseg > 0 ? r->seg[0].n->sid : 0;
	if ((error = ytrans_get_ds(conn, r->nseg > 0 ? &sid : NULL, r->nseg >
	    0 ? 1 : 0, r->xpath, r->ds, &doc, err, sizeof(err),
	    &errsid)) != 0) {
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
