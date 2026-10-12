/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * HTTP plumbing: JSON in and out with libucl (Kore's own JSON writer does
 * not escape strings), errors in one shape, and the one guard every
 * protected route goes through.
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

#define	BODY_MAX	(1024 * 1024)	/* as http_body_max */

int
reply_json(struct http_request *req, int status, ucl_object_t *o)
{
	unsigned char	*json;

	json = ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	if (json == NULL) {
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		return (KORE_RESULT_OK);
	}
	http_response_header(req, "content-type",
	    "application/json; charset=utf-8");
	http_response_header(req, "cache-control", "no-store");
	http_response_header(req, "x-content-type-options", "nosniff");
	http_response(req, status, json, strlen((char *)json));
	free(json);
	return (KORE_RESULT_OK);
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
	free(buf);
	if (o != NULL && ucl_object_type(o) != UCL_OBJECT) {
		ucl_object_unref(o);
		o = NULL;
	}
	return (o);
}

/*
 * Every protected route starts here.  It needs a valid session; a request
 * that changes something also needs the X-Arcana header, which other
 * origins cannot send without a CORS preflight we never answer, and an
 * Origin, when the browser sends one, that is ours.  On failure the
 * reply has been sent.
 */
bool
guard(struct http_request *req, bool mutate)
{
	const char	*v;

	config_refresh();
	if (!session_valid(req)) {
		/*
		 * A read-only API token (tokens.c): to read, never to
		 * change anything, nor to read the console's own settings,
		 * sign-in, push or the keys that let a host join.
		 */
		if (!mutate && token_readable(req->path) && token_valid(req))
			return (true);
		reply_error(req, 401, "unauthenticated", mutate &&
		    token_valid(req) ? "an API token reads only" :
		    "log in first");
		return (false);
	}
	if (!mutate)
		return (true);
	if (!http_request_header(req, "x-arcana", &v) ||
	    strcmp(v, "1") != 0) {
		reply_error(req, 403, "csrf", "missing X-Arcana header");
		return (false);
	}
	if (http_request_header(req, "origin", &v) &&
	    strcmp(v, cfg.origin) != 0) {
		reply_error(req, 403, "csrf", "origin %s not allowed", v);
		return (false);
	}
	return (true);
}

/*
 * Path segment idx, counting from 1: in /api/servers/<id>/jails/<name>,
 * the server is 3 and the jail 5.  Kore compiles the routes of C modules
 * with REG_NOSUB, so their capture groups are not available; the route's
 * regular expression has already checked the characters.
 */
bool
capture(struct http_request *req, int idx, char *buf, size_t len)
{
	const char	*p, *e;
	size_t		 n;

	for (p = req->path; idx > 0; idx--) {
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
	 * logged in, as a repository's address may say more than its name.
	 */
	if (cfg.agent_source != NULL && session_valid(req))
		ucl_object_insert_key(o, ucl_object_fromstring(
		    cfg.agent_source), "agent_source", 0, false);
	if (cfg.agent_ref != NULL && session_valid(req))
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

/*
 * kore_log() is the worker's: it writes on the worker's channel to the
 * parent, which a thread of the console's own (a workflow's run, a
 * transfer, a host's events followed) must not touch while the worker
 * does.  Such a thread's line waits here, and the worker logs it at its
 * next tick.
 */
struct tlog {
	STAILQ_ENTRY(tlog)	 next;
	int			 prio;
	char			*msg;
};
static STAILQ_HEAD(, tlog) tlogs = STAILQ_HEAD_INITIALIZER(tlogs);
static pthread_mutex_t	tlog_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t	worker_thread;

void
thread_log(int prio, const char *fmt, ...)
{
	struct tlog	*t;
	va_list		 ap;
	char		*msg;

	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		msg = NULL;
	va_end(ap);
	if (msg == NULL)
		return;
	if (pthread_equal(pthread_self(), worker_thread)) {
		kore_log(prio, "%s", msg);
		free(msg);
		return;
	}
	if ((t = malloc(sizeof(*t))) == NULL) {
		free(msg);
		return;
	}
	t->prio = prio;
	t->msg = msg;
	pthread_mutex_lock(&tlog_lock);
	STAILQ_INSERT_TAIL(&tlogs, t, next);
	pthread_mutex_unlock(&tlog_lock);
}

static void
tlog_tick(void *arg, u_int64_t now)
{
	STAILQ_HEAD(, tlog)	 q;
	struct tlog		*t;

	(void)arg;
	(void)now;
	STAILQ_INIT(&q);
	pthread_mutex_lock(&tlog_lock);
	STAILQ_CONCAT(&q, &tlogs);
	pthread_mutex_unlock(&tlog_lock);
	while ((t = STAILQ_FIRST(&q)) != NULL) {
		STAILQ_REMOVE_HEAD(&q, next);
		kore_log(t->prio, "%s", t->msg);
		free(t->msg);
		free(t);
	}
}

/* Called by Kore in every worker when the module is loaded. */
int
arcw_onload(int action)
{
	const char	*path;

	if (action != KORE_MODULE_LOAD)
		return (KORE_RESULT_OK);
	worker_thread = pthread_self();
	(void)kore_timer_add(tlog_tick, 500, NULL, 0);
	/* vis(3) treats UTF-8 in program output as printable. */
	(void)setlocale(LC_CTYPE, "C.UTF-8");
	if ((path = getenv("ARCANA_WEB_CONF")) == NULL)
		path = ARCW_CONF;
	/* Kore goes on serving after a failed onload: stop it here. */
	if (config_load(path) == -1 || pki_init() == -1 ||
	    config_check_certs() == -1 || hosts_init() == -1 ||
	    push_init() == -1)
		fatalx("arcana: not starting, see above");
	auth_init();
	servers_init();
	transfers_init();
	workflows_init();
	sdwan_init();
	return (KORE_RESULT_OK);
}
