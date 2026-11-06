/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The page's requests to the console's RESTCONF (RFC 8040, PLAN-SDN-YANG
 * 4.8.1), JSON both ways (application/yang-data+json): the console makes
 * a host's YANG-CBOR JSON by the host's own names, and the page has no
 * host's .sid files to read the pass-through by (ycbor.c waits for
 * them).  A read hands its callback the node, unwrapped; a change sends
 * If-Match with the entity-tag last read at the node or above it, and
 * keeps the tag it gets back; an action's input goes wrapped in its
 * module's "input", its output comes back unwrapped.  An error is
 * ietf-restconf's, said in the words api.c's callbacks have always had.
 * The CSRF header is api.c's, as on every request.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"

#define	TAGS		32

/* The entity-tags read, by the path read (no query). */
static struct {
	char	path[256];
	char	tag[64];
} tags[TAGS];
static int	tagnext;

struct rcreq {
	api_cb	*cb;
	void	*arg;
	char	 path[256];	/* read: where; change: the tag's entry */
	bool	 entry;		/* read of a list's entry */
	int	 kind;		/* RK_* */
};

enum { RK_GET, RK_EDIT, RK_ACTION, RK_VERB };

static void
tag_keep(const char *path, const char *tag)
{
	int	i;

	if (tag == NULL || strlen(path) >= sizeof(tags[0].path) ||
	    strlen(tag) >= sizeof(tags[0].tag))
		return;
	for (i = 0; i < TAGS; i++)
		if (strcmp(tags[i].path, path) == 0)
			break;
	if (i == TAGS) {
		i = tagnext;
		tagnext = (tagnext + 1) % TAGS;
	}
	snprintf(tags[i].path, sizeof(tags[i].path), "%s", path);
	snprintf(tags[i].tag, sizeof(tags[i].tag), "%s", tag);
}

/* The tag read at path or the nearest node above it; -1: none. */
static int
tag_find(const char *path)
{
	size_t	n, best;
	int	i, at;

	at = -1;
	best = 0;
	for (i = 0; i < TAGS; i++) {
		n = strlen(tags[i].path);
		if (n == 0 || n < best || strncmp(path, tags[i].path, n) != 0 ||
		    (path[n] != '\0' && path[n] != '/' && path[n] != '='))
			continue;
		at = i;
		best = n;
	}
	return (at);
}

/* After a change of the page's: the others' tags no longer known. */
static void
tag_forget(void)
{

	memset(tags, 0, sizeof(tags));
	tagnext = 0;
}

char *
rc_c(char *buf, size_t len, const char *fmt, ...)
{
	va_list	ap;
	int	n;

	n = snprintf(buf, len, RC_C);
	va_start(ap, fmt);
	if (n >= 0 && (size_t)n < len)
		vsnprintf(buf + n, len - (size_t)n, fmt, ap);
	va_end(ap);
	return (buf);
}

char *
rc_h(char *buf, size_t len, const char *sid, const char *fmt, ...)
{
	va_list	ap;
	int	n;

	n = snprintf(buf, len, "/restconf/data/arcana-fleet:fleet/host=%s%s",
	    rc_key(sid), fmt[0] != '\0' ? "/" : "");
	va_start(ap, fmt);
	if (n >= 0 && (size_t)n < len)
		vsnprintf(buf + n, len - (size_t)n, fmt, ap);
	va_end(ap);
	return (buf);
}

/*
 * A key as a path has it (RFC 8040 section 3.5.3), percent-encoded but
 * the unreserved; one of four buffers, for one path's several keys.
 */
const char *
rc_key(const char *key)
{
	static char		 buf[4][256];
	static int		 next;
	static const char	 hex[] = "0123456789ABCDEF";
	char			*b, *p;

	b = buf[next];
	next = (next + 1) % 4;
	for (p = b; key != NULL && *key != '\0' && p < b + sizeof(buf[0]) -
	    4; key++) {
		if ((*key >= 'a' && *key <= 'z') || (*key >= 'A' && *key <=
		    'Z') || (*key >= '0' && *key <= '9') || strchr("-._~",
		    *key) != NULL)
			*p++ = *key;
		else {
			*p++ = '%';
			*p++ = hex[(unsigned char)*key >> 4];
			*p++ = hex[(unsigned char)*key & 15];
		}
	}
	*p = '\0';
	return (b);
}

/* The first error of a reply: ietf-restconf's, or a YANG Patch's
 * (RFC 8072), the patch's or an edit's. */
static const ucl_object_t *
first_error(const ucl_object_t *o)
{
	const ucl_object_t	*e;

	if ((e = jget(o, "ietf-restconf:errors.error.0")) != NULL ||
	    (e = jget(o, "ietf-yang-patch:yang-patch-status.errors.error.0")) !=
	    NULL)
		return (e);
	return (jget(o, "ietf-yang-patch:yang-patch-status.edit-status.edit.0."
	    "errors.error.0"));
}

/* error's words: its message, and where it is (error-path) if said. */
const char *
rc_error(const ucl_object_t *o, char *buf, size_t len)
{
	const ucl_object_t	*e;
	const char		*m, *at;

	if ((e = first_error(o)) == NULL || ((m = jstr(e, "error-message")) ==
	    NULL && (m = jstr(e, "error-tag")) == NULL))
		return (NULL);
	at = jstr(e, "error-path");
	snprintf(buf, len, "%s%s%s%s", m, at != NULL ? " (at " : "", at !=
	    NULL ? at : "", at != NULL ? ")" : "");
	return (buf);
}

const char *
rc_tag(const ucl_object_t *o)
{

	return (jstr(first_error(o), "error-app-tag"));
}

/* A yang:date-and-time as seconds since the epoch; 0: none or not one. */
int64_t
rc_time(const char *s)
{
	struct tm	 tm;
	const char	*p;
	int		 oh, om;
	int64_t		 t;

	memset(&tm, 0, sizeof(tm));
	if (s == NULL || sscanf(s, "%d-%d-%dT%d:%d:%d", &tm.tm_year,
	    &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6)
		return (0);
	tm.tm_year -= 1900;
	tm.tm_mon--;
	t = (int64_t)timegm(&tm);
	p = s + strcspn(s, "T") + 9;
	if (*p == '.')
		p += 1 + strspn(p + 1, "0123456789");
	if ((*p == '+' || *p == '-') && sscanf(p + 1, "%d:%d", &oh, &om) ==
	    2)
		t -= (*p == '+' ? 1 : -1) * (oh * 3600 + om * 60);
	return (t);
}

/* The value of o's one member: what a read's or an action's reply has. */
static const ucl_object_t *
inner(const ucl_object_t *o, bool entry)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;

	if (ucl_object_type(o) != UCL_OBJECT || o->len != 1 ||
	    (v = ucl_object_iterate(o, &it, true)) == NULL)
		return (o);
	if (entry && ucl_object_type(v) == UCL_ARRAY)
		return (ucl_array_head(v));
	return (v);
}

static void
done_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct rcreq	 r = *(struct rcreq *)arg;

	free(arg);
	switch (r.kind) {
	case RK_GET:
		if (status == 200) {
			tag_keep(r.path, api_etag());
			o = inner(o, r.entry);
		}
		break;
	case RK_EDIT:
		/* The tag after the change is the one at the node read. */
		if (status >= 200 && status < 300 && api_etag() != NULL &&
		    r.path[0] != '\0') {
			tag_forget();
			tag_keep(r.path, api_etag());
		} else if (status != 0)
			tag_forget();
		break;
	default:
		if (status == 200) {
			o = inner(o, false);
			if (r.kind == RK_VERB)
				o = jget(o, "result");
		} else if (status == 204)
			o = NULL;
		break;
	}
	r.cb(status, o, err, r.arg);
}

static struct rcreq *
req_new(int kind, api_cb *cb, void *arg)
{
	struct rcreq	*r;

	if ((r = calloc(1, sizeof(*r))) == NULL)
		abort();
	r->kind = kind;
	r->cb = cb;
	r->arg = arg;
	return (r);
}

/* A GET of path, with query ("fields=...&depth=2") when not NULL. */
int
rc_get(const char *path, const char *query, api_cb *cb, void *arg)
{
	struct rcreq	*r;
	const char	*last;
	char		 url[1024];

	r = req_new(RK_GET, cb, arg);
	snprintf(r->path, sizeof(r->path), "%s", path);
	last = strrchr(path, '/');
	r->entry = last != NULL && strchr(last, '=') != NULL;
	snprintf(url, sizeof(url), "%s%s%s", path, query != NULL &&
	    query[0] != '\0' ? "?" : "", query != NULL ? query : "");
	return (api("GET", url, NULL, done_cb, r));
}

/* A change of path's: PUT, PATCH, POST (a child made) or DELETE. */
int
rc_edit(const char *method, const char *path, const char *json,
    api_cb *cb, void *arg)
{
	struct rcreq	*r;
	char		 hdr[96];
	int		 t;

	r = req_new(RK_EDIT, cb, arg);
	hdr[0] = '\0';
	if ((t = tag_find(path)) >= 0) {
		snprintf(r->path, sizeof(r->path), "%s", tags[t].path);
		snprintf(hdr, sizeof(hdr), "If-Match: %s", tags[t].tag);
	}
	return (api_hdr(method, path, json, hdr[0] != '\0' ? hdr : NULL,
	    done_cb, r));
}

/* The module an action's or an rpc's input is named by: path's last. */
static void
module_of(const char *path, char *buf, size_t len)
{
	const char	*p, *c, *e;

	buf[0] = '\0';
	for (p = path; (p = strchr(p, '/')) != NULL; p++) {
		e = p + 1 + strcspn(p + 1, "/=");
		if ((c = memchr(p + 1, ':', (size_t)(e - p - 1))) != NULL)
			snprintf(buf, len, "%.*s", (int)(c - p - 1), p + 1);
	}
}

static int
invoke(int kind, const char *path, const char *input, const char *query,
    api_cb *cb, void *arg)
{
	struct rcreq	*r;
	char		 mod[64], *body, url[1024];
	int		 id;

	r = req_new(kind, cb, arg);
	module_of(path, mod, sizeof(mod));
	if (asprintf(&body, "{\"%s:input\":%s}", mod, input != NULL ? input :
	    "{}") == -1)
		abort();
	snprintf(url, sizeof(url), "%s%s%s", path, query != NULL &&
	    query[0] != '\0' ? "?" : "", query != NULL ? query : "");
	id = api("POST", url, body, done_cb, r);
	free(body);
	return (id);
}

/*
 * Action or rpc path invoked, input a JSON object or NULL, query
 * ("arcana-accept=rc-conf-files") when not NULL.
 */
int
rc_action(const char *path, const char *input, const char *query,
    api_cb *cb, void *arg)
{

	return (invoke(RK_ACTION, path, input, query, cb, arg));
}

/* The same of an action that only reads: a read's task, not a change's. */
int
rc_read(const char *path, const char *input, const char *query,
    api_cb *cb, void *arg)
{

	api_reads();
	return (invoke(RK_ACTION, path, input, query, cb, arg));
}

/*
 * The same of a verb the console answers with /api's handler
 * (arcana-console's, cyang.c's bridges): the callback gets its output's
 * result, the handler's document.
 */
int
rc_verb(const char *path, const char *input, const char *query,
    api_cb *cb, void *arg)
{

	return (invoke(RK_VERB, path, input, query, cb, arg));
}
