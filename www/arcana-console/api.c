/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * HTTP plumbing: JSON in and out with libucl, errors in one shape, and
 * the one guard every protected route goes through.
 */

#include <sys/types.h>
#include <sys/queue.h>

#include <locale.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "console.h"
#include "restconf.h"

#define	BODY_MAX	(8 * 1024 * 1024)	/* as http_body_max */

int
reply_json(struct http_request *req, int status, ucl_object_t *o)
{
	unsigned char	*json;

	json = ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	if (json == NULL) {
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		return (WEB_OK);
	}
	http_response_header(req, "content-type",
	    "application/json; charset=utf-8");
	http_response_header(req, "cache-control", "no-store");
	http_response_header(req, "x-content-type-options", "nosniff");
	http_response(req, status, json, strlen((char *)json));
	free(json);
	return (WEB_OK);
}

/*
 * An /api/ path the console does not have (routes.c's last route): a
 * JSON 404 like every other error, not the server's plain one.
 */
int
api_not_found(struct http_request *req)
{

	return (reply_error(req, 404, "not-found", "no such route: %s",
	    req->path));
}

/* {"error": {"code": "...", "message": "..."}} */
int
reply_error(struct http_request *req, int status, const char *code,
    const char *fmt, ...)
{
	ucl_object_t	*top, *e;
	va_list		 ap;
	char		 msg[1024];

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	/* RESTCONF's own shape on its paths (RFC 8040 section 7). */
	if (strcmp(req->path, "/restconf") == 0 || strncmp(req->path,
	    "/restconf/", 10) == 0)
		return (restconf_error(req, status, msg));
	top = ucl_object_typed_new(UCL_OBJECT);
	e = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(e, ucl_object_fromstring(code), "code", 0,
	    false);
	ucl_object_insert_key(e, ucl_object_fromstring(msg), "message", 0,
	    false);
	ucl_object_insert_key(top, e, "error", 0, false);
	return (reply_json(req, status, top));
}

/* The request body as a JSON object, or NULL. */
ucl_object_t *
read_json(struct http_request *req)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	char			*buf;
	size_t			 len;
	ssize_t			 r;

	if ((buf = malloc(BODY_MAX)) == NULL)
		return (NULL);
	for (len = 0; len < BODY_MAX; len += (size_t)r) {
		if ((r = http_body_read(req, buf + len, BODY_MAX - len)) <= 0)
			break;
	}
	if (len == 0 || len == BODY_MAX) {
		free(buf);
		return (NULL);
	}
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_chunk(p, (unsigned char *)buf, len))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	/* A body may carry a key (a CA's, a preshared one): not left in
	 * memory given back. */
	explicit_bzero(buf, len);
	free(buf);
	/* And the server's own copy. */
	if (req->http_body != NULL && req->http_body->data != NULL)
		explicit_bzero(req->http_body->data, req->http_body->length);
	if (o != NULL && ucl_object_type(o) != UCL_OBJECT) {
		ucl_object_unref(o);
		o = NULL;
	}
	return (o);
}

/*
 * Every protected route starts here.  It needs a valid session; a request
 * that changes something also needs our page's Origin, or, from a client
 * that sends no Origin, the X-Arcana header.  On failure the reply has
 * been sent.
 */
bool
guard(struct http_request *req, bool mutate)
{
	const char	*v, *u;

	config_refresh();
	if (!session_valid(req)) {
		/*
		 * An API token (tokens.c): a read one to read, a write one
		 * to change things too; neither to the console's own
		 * settings, sign-in, push or the keys that let a host join,
		 * nor, for a change, to the tokens or the CA.  A bearer
		 * token is not sent by a browser by itself: no CSRF checks.
		 */
		switch (token_kind(req)) {
		case TOKEN_WRITE:
			if (mutate ? token_writable(req->path) :
			    token_readable(req->path))
				return (true);
			reply_error(req, 403, "token", "an API token may not "
			    "%s this", mutate ? "change" : "read");
			return (false);
		case TOKEN_READ:
			if (!mutate && token_readable(req->path))
				return (true);
			reply_error(req, 401, "unauthenticated", mutate ?
			    "an API token reads only" : "log in first");
			return (false);
		default:
			reply_error(req, 401, "unauthenticated", "log in first");
			return (false);
		}
	}
	/* Opened with a write token: what the token may, no more. */
	if (session_by_token(req) && !(mutate ? token_writable(req->path) :
	    token_readable(req->path))) {
		reply_error(req, 403, "token", "a session opened with an API "
		    "token may not %s this: sign in with a security key",
		    mutate ? "change" : "read");
		return (false);
	}
	/* A console user: what their role on the console allows
	 * (users.c); the hosts' routes look at their role on the host. */
	if ((u = session_user(req)) != NULL && !user_path_ok(user_console(u),
	    req->path, mutate)) {
		reply_error(req, 403, "role", "%s of this console may not %s "
		    "this", user_console(u) == CROLE_OPERATOR ? "an operator" :
		    user_console(u) == CROLE_MEMBER ? "a member" : "a user no "
		    "longer", mutate ? "change" : "read");
		return (false);
	}
	if (!mutate)
		return (true);
	/*
	 * That our page asked: its Origin, which a browser sends with every
	 * change and no page can make another's; from a client that sends
	 * none (a script with the cookie, an app), X-Arcana: 1, which
	 * another origin cannot send without a CORS preflight we never
	 * answer.  Over HTTP/2 a browser's X-Arcana does not reach the
	 * console from its second use on a connection on (web.c): the
	 * Origin is what a browser is judged by.
	 */
	if (http_request_header(req, "origin", &v)) {
		if (strcmp(v, cfg.origin) == 0 || cluster_origin(v))
			return (true);
		reply_error(req, 403, "csrf", "origin %s not allowed", v);
		return (false);
	}
	if (!http_request_header(req, "x-arcana", &v) ||
	    strcmp(v, "1") != 0) {
		reply_error(req, 403, "csrf", "missing X-Arcana header (or "
		    "the Origin of the console's page)");
		return (false);
	}
	return (true);
}

/*
 * Path segment idx, counting from 1: in /api/servers/<id>/jails/<name>,
 * the server is 3 and the jail 5.  The routes are compiled with
 * REG_NOSUB, so their capture groups are not available; the route's
 * regular expression has already checked the characters.
 */
bool
capture(struct http_request *req, int idx, char *buf, size_t len)
{

	return (capture_path(req->path, idx, buf, len));
}

/* Path segment idx of path, as capture() takes it of a request's. */
bool
capture_path(const char *path, int idx, char *buf, size_t len)
{
	const char	*p, *e;
	size_t		 n;

	for (p = path; idx > 0; idx--) {
		if (*p != '/')
			return (false);
		e = strchrnul(p + 1, '/');
		if (idx == 1) {
			n = (size_t)(e - (p + 1));
			if (n == 0 || n >= len)
				return (false);
			memcpy(buf, p + 1, n);
			buf[n] = '\0';
			return (true);
		}
		p = e;
	}
	return (false);
}

const char *
ucl_str(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(o, key)) == NULL ||
	    ucl_object_type(v) != UCL_STRING)
		return (NULL);
	return (ucl_object_tostring(v));
}

bool
ucl_flag(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	return ((v = ucl_object_lookup(o, key)) != NULL &&
	    ucl_object_type(v) == UCL_BOOLEAN && ucl_object_toboolean(v));
}

int
api_health(struct http_request *req)
{
	ucl_object_t	*o;
	const char	*build;
	bool		 known;

	config_refresh();
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_frombool(true), "ok", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(ARCW_VERSION),
	    "version", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(time(NULL)), "time", 0,
	    false);
	/* The build of the arcana-agent this console hands to hosts. */
	if ((build = agent_build()) != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(build),
		    "agent_build", 0, false);
	if ((build = agent_version()) != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(build),
		    "agent_version", 0, false);
	/*
	 * Where a host can be asked to build it from: for those who are
	 * logged in or hold an API token, as a repository's address may
	 * say more than its name.
	 */
	known = session_valid(req) || token_kind(req) != TOKEN_NONE;
	if (cfg.agent_source != NULL && known)
		ucl_object_insert_key(o, ucl_object_fromstring(
		    cfg.agent_source), "agent_source", 0, false);
	if (cfg.agent_ref != NULL && known)
		ucl_object_insert_key(o, ucl_object_fromstring(cfg.agent_ref),
		    "agent_ref", 0, false);
	return (reply_json(req, 200, o));
}

/*
 * /.well-known/assetlinks.json: the Android app of web.conf's android
 * block, which Android asks for before it lets the app use the keys
 * registered for rp_id, and before it opens the console's links in the
 * app.  Without the block, there is none.
 */
int
api_assetlinks(struct http_request *req)
{
	ucl_object_t	*top, *e, *rel, *tgt, *fps;
	char		 fp[32 * 3];
	int		 i, n;

	if (cfg.android_package == NULL)
		return (reply_error(req, 404, "not_found", "no Android app is "
		    "configured"));
	fps = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < cfg.nandroid_keys; i++) {
		/* "AB:CD:...", as apksigner prints it: 32 bytes, 95 chars. */
		for (n = 0; n < 32; n++)
			snprintf(fp + (n == 0 ? 0 : n * 3 - 1), sizeof(fp) -
			    (n == 0 ? 0 : n * 3 - 1), "%s%02X", n > 0 ? ":" : "",
			    cfg.android_keys[i][n]);
		ucl_array_append(fps, ucl_object_fromstring(fp));
	}
	rel = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(rel, ucl_object_fromstring(
	    "delegate_permission/common.handle_all_urls"));
	ucl_array_append(rel, ucl_object_fromstring(
	    "delegate_permission/common.get_login_creds"));
	tgt = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(tgt, ucl_object_fromstring("android_app"),
	    "namespace", 0, false);
	ucl_object_insert_key(tgt, ucl_object_fromstring(cfg.android_package),
	    "package_name", 0, false);
	ucl_object_insert_key(tgt, fps, "sha256_cert_fingerprints", 0, false);
	e = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(e, rel, "relation", 0, false);
	ucl_object_insert_key(e, tgt, "target", 0, false);
	top = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(top, e);
	return (reply_json(req, 200, top));
}

/* A line of the log from any thread: log_msg() is safe from all. */
void
thread_log(int prio, const char *fmt, ...)
{
	va_list	 ap;
	char	*msg;

	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		msg = NULL;
	va_end(ap);
	if (msg == NULL)
		return;
	log_msg(prio, "%s", msg);
	free(msg);
}

/* A store another node of the cluster wrote, read again by what keeps
 * it; NULL: every one. */
static void
reload_one(const char *name)
{

	if (name == NULL || strcmp(name, "credentials.json") == 0 ||
	    strncmp(name, SESSIONS_DIR "/", sizeof(SESSIONS_DIR)) == 0)
		auth_reload(name);
	if (name == NULL || strcmp(name, "users.json") == 0)
		users_reload();
	if (name == NULL || strcmp(name, "servers.json") == 0)
		servers_reload();
	if (name == NULL || strcmp(name, "push.json") == 0)
		push_reload();
}

/* On the worker, which those stores are of. */
static void
cluster_tick(void *arg __unused, uint64_t now __unused)
{

	cluster_changes(reload_one);
}

/* Called by the server in its worker, once it listens as its user. */
int
arcw_init(void)
{

	/* vis(3) treats UTF-8 in program output as printable. */
	(void)setlocale(LC_CTYPE, "C.UTF-8");
	if (config_load(web_conf_path) == -1 || pki_init() == -1 ||
	    config_check_certs() == -1 || hosts_init() == -1 ||
	    workflows_kinds_check() == -1 || cluster_init() == -1 ||
	    push_init() == -1)
		fatalx("arcana: not starting, see above");
	store_sweep();
	/* The hosts' certificates, on the TLS listeners (notif.c). */
	web_client_ca(cfg.tls_ca);
	auth_init();
	users_init();
	if (cluster_on())
		(void)timer_add(cluster_tick, 500, NULL, 0);
	servers_init();
	transfers_init();
	workflows_init();
	sdwan_init();
	mail_init();
	cluster_started();
	return (WEB_OK);
}
