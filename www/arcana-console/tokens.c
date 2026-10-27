/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * API tokens: for a program to use the console without a passkey.  A
 * token is made in a session, shown once, and kept only as its SHA-256
 * with a name, its kind, when it was made and when it was last used
 * (tokens.json in the data directory).  Sent as
 *
 *	Authorization: Bearer arcr_<64 hex digits>	(reads)
 *	Authorization: Bearer arcw_<64 hex digits>	(reads and writes)
 *
 * a read token opens what a GET opens and nothing else.  A write token
 * also changes things: queues jobs, updates hosts and the console; the
 * session's CSRF checks are not needed, since a browser never sends a
 * bearer token by itself.  Neither opens the console's own settings,
 * sign-in, push, the enrolment tokens that let a host join, or, for a
 * change, the tokens and the CA: a token cannot make another, add a
 * passkey or change what repository is built as root.  What a write
 * token does is audited under its name.  Deleted, a token opens
 * nothing at once, in every worker: the file is read again whenever it
 * changed.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

#include "console.h"

#define	TOKENS_FILE	"tokens.json"
#define	TOKENS_MAX	32
#define	TOKEN_PREFIX	"arcr_"		/* a read token */
#define	TOKEN_WPREFIX	"arcw_"		/* a write token */
#define	TOKEN_SAVE	60	/* s between two writes of when one was used */

struct token {
	char		id[17];		/* the hash's first 8 bytes, in hex */
	uint8_t		hash[32];
	char		name[65];
	time_t		created;
	time_t		last;
	bool		write;
};

static struct token	tokens[TOKENS_MAX];
static int		ntokens;
static struct timespec	tokens_mtime;
static time_t		tokens_saved;

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

/*
 * What a token may read: anything the API tells, but the console's
 * own settings, sign-in, push and the enrolment tokens that let a host
 * join.  A read is what guard() is told is not a change.
 */
bool
token_readable(const char *path)
{

	if (strcmp(path, "/restconf") == 0 || strncmp(path, "/restconf/",
	    10) == 0)
		return (true);
	return (strncmp(path, "/api/", 5) == 0 && strncmp(path,
	    "/api/settings", 13) != 0 && strncmp(path, "/api/auth", 9) != 0 &&
	    strncmp(path, "/api/push", 9) != 0 && strncmp(path, "/api/enrol",
	    10) != 0);
}

/* What a write token may change: what it may read, but the tokens and
 * the CA. */
bool
token_writable(const char *path)
{

	/* Nor who is who: a token must not make itself an owner. */
	return (token_readable(path) && strncmp(path, "/api/tokens", 11) !=
	    0 && strncmp(path, "/api/ca", 7) != 0 && strncmp(path,
	    "/api/users", 10) != 0 && strncmp(path, "/api/roles", 10) != 0 &&
	    strncmp(path, "/api/groups", 11) != 0);
}

static void
digest(const char *s, uint8_t *md)
{
	unsigned int	len;

	EVP_Digest(s, strlen(s), md, &len, EVP_sha256(), NULL);
}

static void
hex(const uint8_t *b, size_t n, char *out)
{
	size_t	i;

	for (i = 0; i < n; i++)
		snprintf(out + 2 * i, 3, "%02x", b[i]);
}

/* The file, read again when it changed (another worker made one). */
static void
tokens_load(void)
{
	struct stat		 sb;
	ucl_object_t		*o;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*h, *n;
	char			 path[MAXPATHLEN];
	unsigned int		 b;
	int			 k;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, TOKENS_FILE);
	if (stat(path, &sb) == -1) {
		ntokens = 0;
		memset(&tokens_mtime, 0, sizeof(tokens_mtime));
		return;
	}
	if (sb.st_mtim.tv_sec == tokens_mtime.tv_sec &&
	    sb.st_mtim.tv_nsec == tokens_mtime.tv_nsec)
		return;
	tokens_mtime = sb.st_mtim;
	ntokens = 0;
	if ((o = store_load(TOKENS_FILE)) == NULL)
		return;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(o, "tokens"), &it,
	    true)) != NULL && ntokens < TOKENS_MAX) {
		if ((h = ucl_object_tostring(ucl_object_lookup(e, "hash"))) ==
		    NULL || strlen(h) != 64)
			continue;
		for (k = 0; k < 32; k++) {
			if (sscanf(h + 2 * k, "%2x", &b) != 1)
				break;
			tokens[ntokens].hash[k] = (uint8_t)b;
		}
		if (k < 32)
			continue;
		hex(tokens[ntokens].hash, 8, tokens[ntokens].id);
		n = ucl_object_tostring(ucl_object_lookup(e, "name"));
		snprintf(tokens[ntokens].name, sizeof(tokens[ntokens].name),
		    "%s", n != NULL ? n : "");
		tokens[ntokens].created = ucl_object_toint(ucl_object_lookup(e,
		    "created"));
		tokens[ntokens].last = ucl_object_toint(ucl_object_lookup(e,
		    "last"));
		tokens[ntokens].write = ucl_object_toboolean(ucl_object_lookup(
		    e, "write"));
		ntokens++;
	}
	ucl_object_unref(o);
}

static int
tokens_save(void)
{
	struct stat	 sb;
	ucl_object_t	*o, *a, *e;
	char		 h[65], path[MAXPATHLEN];
	int		 i, rc;

	o = ucl_object_typed_new(UCL_OBJECT);
	a = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < ntokens; i++) {
		hex(tokens[i].hash, 32, h);
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "hash", ucl_object_fromstring(h));
		put(e, "name", ucl_object_fromstring(tokens[i].name));
		put(e, "created", ucl_object_fromint(tokens[i].created));
		put(e, "last", ucl_object_fromint(tokens[i].last));
		put(e, "write", ucl_object_frombool(tokens[i].write));
		ucl_array_append(a, e);
	}
	put(o, "tokens", a);
	rc = store_save(TOKENS_FILE, o);
	ucl_object_unref(o);
	/* What was written is what is held: not read again for it. */
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, TOKENS_FILE);
	if (rc == 0 && stat(path, &sb) == 0)
		tokens_mtime = sb.st_mtim;
	tokens_saved = time(NULL);
	return (rc);
}

/* The request's bearer token, if one of ours; NULL else. */
static struct token *
token_of(struct http_request *req)
{
	const char	*v;
	uint8_t		 h[32];
	int		 i;

	if (!http_request_header(req, "authorization", &v) ||
	    strncmp(v, "Bearer ", 7) != 0)
		return (NULL);
	v += 7;
	if ((strncmp(v, TOKEN_PREFIX, strlen(TOKEN_PREFIX)) != 0 &&
	    strncmp(v, TOKEN_WPREFIX, strlen(TOKEN_WPREFIX)) != 0) ||
	    strlen(v) != strlen(TOKEN_PREFIX) + 64)
		return (NULL);
	tokens_load();
	digest(v, h);
	for (i = 0; i < ntokens; i++)
		if (memcmp(tokens[i].hash, h, sizeof(h)) == 0)
			return (&tokens[i]);
	return (NULL);
}

/*
 * What the request's bearer token may do: TOKEN_NONE (no token of
 * ours), TOKEN_READ or TOKEN_WRITE.  Its use is noted.
 */
int
token_kind(struct http_request *req)
{
	struct token	*t;
	time_t		 now;

	if ((t = token_of(req)) == NULL)
		return (TOKEN_NONE);
	now = time(NULL);
	t->last = now;
	if (now - tokens_saved >= TOKEN_SAVE)
		(void)tokens_save();
	return (t->write ? TOKEN_WRITE : TOKEN_READ);
}

/*
 * A write token typed to sign in with (auth.c): its name, and its id
 * into id; NULL when it is not one of ours, or reads only.
 */
const char *
token_login(const char *v, char *id, size_t idlen)
{
	uint8_t	 h[32];
	int	 i;

	if (strncmp(v, TOKEN_WPREFIX, strlen(TOKEN_WPREFIX)) != 0 ||
	    strlen(v) != strlen(TOKEN_WPREFIX) + 64)
		return (NULL);
	tokens_load();
	digest(v, h);
	for (i = 0; i < ntokens; i++)
		if (tokens[i].write && memcmp(tokens[i].hash, h, sizeof(h)) ==
		    0) {
			snprintf(id, idlen, "%s", tokens[i].id);
			tokens[i].last = time(NULL);
			(void)tokens_save();
			return (tokens[i].name);
		}
	return (NULL);
}

/* Whether the write token of id is still there. */
bool
token_alive(const char *id)
{
	int	i;

	tokens_load();
	for (i = 0; i < ntokens; i++)
		if (tokens[i].write && strcmp(tokens[i].id, id) == 0)
			return (true);
	return (false);
}

/* Who a write token's request is, for the audit trail; NULL else. */
const char *
token_who(struct http_request *req)
{
	static char	 who[sizeof(((struct token *)0)->name) + 16];
	struct token	*t;

	if ((t = token_of(req)) == NULL || !t->write)
		return (NULL);
	snprintf(who, sizeof(who), "API token %s", t->name);
	return (who);
}

/*
 * GET /api/tokens: the tokens, without what opens them.
 * POST /api/tokens {"name", "kind": "read"|"write"}: a new one, a read
 * one unless said, its value in the reply only.
 * DELETE /api/tokens/<id>: one gone.
 */
int
api_tokens(struct http_request *req)
{
	ucl_object_t	*top, *a, *e, *body;
	const char	*name, *id, *kind;
	uint8_t		 raw[32];
	bool		 write;
	char		 value[sizeof(TOKEN_PREFIX) + 64];
	int		 i;

	if (req->method == HTTP_METHOD_GET) {
		if (!guard(req, false))
			return (WEB_OK);
		tokens_load();
		top = ucl_object_typed_new(UCL_OBJECT);
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < ntokens; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put(e, "id", ucl_object_fromstring(tokens[i].id));
			put(e, "name", ucl_object_fromstring(tokens[i].name));
			put(e, "created", ucl_object_fromint(tokens[i].created));
			put(e, "last", ucl_object_fromint(tokens[i].last));
			put(e, "kind", ucl_object_fromstring(tokens[i].write ?
			    "write" : "read"));
			ucl_array_append(a, e);
		}
		put(top, "tokens", a);
		return (reply_json(req, 200, top));
	}
	/* Made and deleted in a session only: guard() lets no token
	 * through where something changes. */
	if (!guard(req, true))
		return (WEB_OK);
	tokens_load();
	if (req->method == HTTP_METHOD_DELETE) {
		id = strrchr(req->path, '/') != NULL ? strrchr(req->path, '/') +
		    1 : "";
		for (i = 0; i < ntokens; i++)
			if (strcmp(tokens[i].id, id) == 0)
				break;
		if (i == ntokens)
			return (reply_error(req, 404, "not-found", "no such "
			    "token"));
		tokens[i] = tokens[--ntokens];
		if (tokens_save() != 0)
			return (reply_error(req, 500, "store", "the tokens "
			    "could not be written"));
		top = ucl_object_typed_new(UCL_OBJECT);
		put(top, "ok", ucl_object_frombool(true));
		return (reply_json(req, 200, top));
	}
	body = read_json(req);
	name = body != NULL ? ucl_str(body, "name") : NULL;
	if (name == NULL || name[0] == '\0' || strlen(name) > 64) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "a token has a name "
		    "of 1 to 64 characters"));
	}
	kind = ucl_str(body, "kind");
	if (kind != NULL && strcmp(kind, "read") != 0 && strcmp(kind,
	    "write") != 0) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "a token's kind is "
		    "read or write"));
	}
	write = kind != NULL && strcmp(kind, "write") == 0;
	if (ntokens == TOKENS_MAX) {
		ucl_object_unref(body);
		return (reply_error(req, 409, "full", "%d tokens at most: "
		    "delete one first", TOKENS_MAX));
	}
	arc4random_buf(raw, sizeof(raw));
	memcpy(value, write ? TOKEN_WPREFIX : TOKEN_PREFIX,
	    strlen(TOKEN_PREFIX));
	hex(raw, sizeof(raw), value + strlen(TOKEN_PREFIX));
	memset(&tokens[ntokens], 0, sizeof(tokens[ntokens]));
	digest(value, tokens[ntokens].hash);
	hex(tokens[ntokens].hash, 8, tokens[ntokens].id);
	snprintf(tokens[ntokens].name, sizeof(tokens[ntokens].name), "%s",
	    name);
	tokens[ntokens].created = time(NULL);
	tokens[ntokens].write = write;
	ntokens++;
	ucl_object_unref(body);
	if (tokens_save() != 0) {
		ntokens--;
		return (reply_error(req, 500, "store", "the token could not "
		    "be written"));
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "id", ucl_object_fromstring(tokens[ntokens - 1].id));
	put(top, "name", ucl_object_fromstring(tokens[ntokens - 1].name));
	put(top, "kind", ucl_object_fromstring(write ? "write" : "read"));
	put(top, "token", ucl_object_fromstring(value));
	explicit_bzero(value, sizeof(value));
	explicit_bzero(raw, sizeof(raw));
	return (reply_json(req, 200, top));
}
