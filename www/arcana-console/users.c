/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console's users and what each may do (RBAC): a user has a role
 * on the console (owner: everything, the settings, keys, tokens, CA
 * and users among it; operator: the fleet's tools too, SD-WAN,
 * workflows, templates, transfers; member: the hosts alone), a role
 * on each host (viewer reads; operator changes; admin also updates,
 * moves and removes it), by host id or "*" for all, and may belong to
 * a tenant, a fleet of its own: it then sees the hosts of that tenant
 * alone (servers carry the tenant's name).  Sign-in keys belong to a
 * user; a key with none is the built-in admin's, the owner, so a
 * console with keys from before has its owner.  A user is invited: a
 * one-time token with which they register their first key.
 * users.json in the data directory, {"users": [...], "invites":
 * [...]}; GET and POST /api/users, PUT and DELETE /api/users/<name>,
 * POST /api/users/<name>/invite.
 */

#include <sys/param.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <openssl/evp.h>

#include "console.h"

#define	USERS_FILE	"users.json"
#define	USERS_MAX	256
#define	INVITE_LIFE	(24 * 3600)
#define	INVITE_BYTES	24

static ucl_object_t	*udoc;

/* Base64url of bytes, without padding. */
static void
b64url_of(const uint8_t *d, size_t n, char *out, size_t len)
{
	static const char	alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789-_";
	size_t			i, o;
	uint32_t		v;
	int			bits;

	o = 0;
	v = 0;
	bits = 0;
	for (i = 0; i < n && o + 1 < len; i++) {
		v = (v << 8) | d[i];
		bits += 8;
		while (bits >= 6 && o + 1 < len) {
			bits -= 6;
			out[o++] = alphabet[(v >> bits) & 0x3f];
		}
	}
	if (bits > 0 && o + 1 < len)
		out[o++] = alphabet[(v << (6 - bits)) & 0x3f];
	out[o] = '\0';
}

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_replace_key(o, v, key, 0, true);
}

static ucl_object_t *
users_list(void)
{

	return ((ucl_object_t *)(uintptr_t)ucl_object_lookup(udoc, "users"));
}

static ucl_object_t *
invites_list(void)
{

	return ((ucl_object_t *)(uintptr_t)ucl_object_lookup(udoc, "invites"));
}

/* A user's or a tenant's name: letters, digits, _ . @ -, 64 at most. */
bool
user_name_ok(const char *s)
{
	size_t	n;

	if (s == NULL)
		return (false);
	n = strlen(s);
	return (n > 0 && n <= 64 && strspn(s, "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.@-") == n);
}

static const ucl_object_t *
user_find(const char *name)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;

	it = NULL;
	while (name != NULL && (u = ucl_object_iterate(users_list(), &it, true))
	    != NULL)
		if (ucl_str(u, "name") != NULL && strcmp(ucl_str(u, "name"), name)
		    == 0)
			return (u);
	return (NULL);
}

bool
user_exists(const char *name)
{

	return (user_find(name) != NULL);
}

static enum crole
crole_of(const char *s)
{

	if (s == NULL)
		return (CROLE_MEMBER);
	if (strcmp(s, "owner") == 0)
		return (CROLE_OWNER);
	if (strcmp(s, "operator") == 0)
		return (CROLE_OPERATOR);
	return (CROLE_MEMBER);
}

static enum role
role_of(const char *s)
{

	if (s == NULL)
		return (ROLE_NONE);
	if (strcmp(s, "admin") == 0)
		return (ROLE_ADMIN);
	if (strcmp(s, "operator") == 0)
		return (ROLE_OPERATOR);
	if (strcmp(s, "viewer") == 0)
		return (ROLE_VIEWER);
	return (ROLE_NONE);
}

const char *
role_name(enum role r)
{

	return (r == ROLE_ADMIN ? "admin" : r == ROLE_OPERATOR ? "operator" :
	    r == ROLE_VIEWER ? "viewer" : "none");
}

const char *
crole_name(enum crole r)
{

	return (r == CROLE_OWNER ? "owner" : r == CROLE_OPERATOR ? "operator" :
	    r == CROLE_MEMBER ? "member" : "none");
}

/*
 * A user's role on the console.  NULL, a session that carries no
 * user (an API token's, a directory's user the console has no record
 * of), is an operator's: what a write token may.
 */
enum crole
user_console(const char *name)
{
	const ucl_object_t	*u;

	if (name == NULL || name[0] == '\0')
		return (CROLE_OPERATOR);
	if ((u = user_find(name)) == NULL)
		return (CROLE_NONE);
	return (crole_of(ucl_str(u, "console")));
}

/* The user's tenant, "" for none. */
const char *
user_tenant(const char *name)
{
	const ucl_object_t	*u;

	if ((u = user_find(name)) == NULL || ucl_str(u, "tenant") == NULL)
		return ("");
	return (ucl_str(u, "tenant"));
}

/*
 * A user's role on a host: the one named for it, else the one for
 * "*"; none on a host of another tenant.  A session with no user has
 * every host as an admin, as before there were users.
 */
enum role
user_host(const char *name, const char *sid)
{
	const ucl_object_t	*u, *h;
	const struct server	*s;
	const char		*t;

	if (name == NULL || name[0] == '\0')
		return (ROLE_ADMIN);
	if ((u = user_find(name)) == NULL)
		return (ROLE_NONE);
	t = ucl_str(u, "tenant");
	if (t != NULL && t[0] != '\0') {
		if ((s = server_find(sid)) == NULL || s->tenant == NULL ||
		    strcmp(s->tenant, t) != 0)
			return (ROLE_NONE);
	}
	h = ucl_object_lookup(u, "hosts");
	if (ucl_object_lookup(h, sid) != NULL)
		return (role_of(ucl_object_tostring(ucl_object_lookup(h, sid))));
	return (role_of(ucl_object_tostring(ucl_object_lookup(h, "*"))));
}

/*
 * May a user of this console role take the path: the console's own
 * (settings, tokens, CA, users, enrolment, update, push) for the owner
 * alone; the fleet's tools (SD-WAN, workflows, templates, transfers,
 * the path finder, adding a host, keeping prefix lists) for an
 * operator too; the rest for everyone, the hosts' routes checked by
 * host besides.
 */
bool
user_path_ok(enum crole r, const char *path, bool mutate)
{
	static const char	*owner_only[] = { "/api/settings", "/api/tokens",
				    "/api/ca", "/api/users", "/api/enrol",
				    "/api/update", "/api/push/send" };
	static const char	*operator_up[] = { "/api/sdwan", "/api/workflows",
				    "/api/runs", "/api/templates",
				    "/api/transfers", "/api/troubleshoot",
				    "/api/wg" };
	size_t			 i, n;

	if (r == CROLE_NONE)
		return (false);
	if (r == CROLE_OWNER)
		return (true);
	for (i = 0; i < nitems(owner_only); i++) {
		n = strlen(owner_only[i]);
		if (strncmp(path, owner_only[i], n) == 0 && (path[n] == '\0' ||
		    path[n] == '/' || path[n] == '?'))
			return (false);
	}
	if (r == CROLE_OPERATOR)
		return (true);
	for (i = 0; i < nitems(operator_up); i++) {
		n = strlen(operator_up[i]);
		if (strncmp(path, operator_up[i], n) == 0 && (path[n] == '\0' ||
		    path[n] == '/' || path[n] == '?'))
			return (false);
	}
	if (mutate && (strcmp(path, "/api/servers") == 0 || strncmp(path,
	    "/api/prefix-lists", 17) == 0))
		return (false);
	return (true);
}

/* The WebAuthn user handle of a user: 16 bytes of the hash of the name. */
void
user_handle(const char *name, char *buf, size_t len)
{
	uint8_t		 h[32];
	unsigned int	 n;

	EVP_Digest(name, strlen(name), h, &n, EVP_sha256(), NULL);
	b64url_of(h, 16, buf, len);
}

static void
hex_of(const uint8_t *b, size_t n, char *out)
{
	size_t	i;

	for (i = 0; i < n; i++)
		snprintf(out + 2 * i, 3, "%02x", b[i]);
}

/*
 * An invitation given out: the token's hash kept with the user and
 * when it runs out; the token itself goes to the caller once.
 */
static bool
invite_make(const char *user, char *token, size_t len)
{
	ucl_object_t	*inv;
	uint8_t		 raw[INVITE_BYTES], h[32];
	char		 hex[65], s[48];
	unsigned int	 n;

	arc4random_buf(raw, sizeof(raw));
	b64url_of(raw, sizeof(raw), s, sizeof(s));
	snprintf(token, len, "inv_%s", s);
	EVP_Digest(token, strlen(token), h, &n, EVP_sha256(), NULL);
	hex_of(h, sizeof(h), hex);
	inv = ucl_object_typed_new(UCL_OBJECT);
	put(inv, "hash", ucl_object_fromstring(hex));
	put(inv, "user", ucl_object_fromstring(user));
	put(inv, "expires", ucl_object_fromint(time(NULL) + INVITE_LIFE));
	ucl_array_append(invites_list(), inv);
	return (store_save(USERS_FILE, udoc) == 0);
}

/* An invitation used: its user, and it is gone. */
bool
invite_take(const char *token, char *user, size_t len)
{
	const ucl_object_t	*inv;
	ucl_object_iter_t	 it;
	uint8_t			 h[32];
	char			 hex[65];
	unsigned int		 n;
	time_t			 now;

	if (token == NULL || strncmp(token, "inv_", 4) != 0)
		return (false);
	EVP_Digest(token, strlen(token), h, &n, EVP_sha256(), NULL);
	hex_of(h, sizeof(h), hex);
	now = time(NULL);
	it = NULL;
	while ((inv = ucl_object_iterate(invites_list(), &it, true)) != NULL) {
		if (ucl_str(inv, "hash") == NULL || strlen(ucl_str(inv, "hash"))
		    != 64 || timingsafe_bcmp(ucl_str(inv, "hash"), hex, 64) != 0)
			continue;
		if (ucl_object_toint(ucl_object_lookup(inv, "expires")) < now ||
		    !user_exists(ucl_str(inv, "user")))
			break;
		snprintf(user, len, "%s", ucl_str(inv, "user"));
		ucl_object_unref(ucl_array_delete(invites_list(),
		    (ucl_object_t *)(uintptr_t)inv));
		(void)store_save(USERS_FILE, udoc);
		return (true);
	}
	return (false);
}

/* Invitations that ran out, forgotten. */
static void
invites_sweep(void)
{
	const ucl_object_t	*inv;
	ucl_object_iter_t	 it;
	time_t			 now;
	bool			 again;

	now = time(NULL);
	do {
		again = false;
		it = NULL;
		while ((inv = ucl_object_iterate(invites_list(), &it, true)) !=
		    NULL)
			if (ucl_object_toint(ucl_object_lookup(inv, "expires")) <
			    now) {
				ucl_object_unref(ucl_array_delete(invites_list(),
				    (ucl_object_t *)(uintptr_t)inv));
				again = true;
				break;
			}
	} while (again);
}

void
users_init(void)
{
	ucl_object_t	*u, *h;

	if ((udoc = store_load(USERS_FILE)) == NULL || ucl_object_type(udoc) !=
	    UCL_OBJECT) {
		if (udoc != NULL)
			ucl_object_unref(udoc);
		udoc = ucl_object_typed_new(UCL_OBJECT);
	}
	if (ucl_object_lookup(udoc, "users") == NULL)
		put(udoc, "users", ucl_object_typed_new(UCL_ARRAY));
	if (ucl_object_lookup(udoc, "invites") == NULL)
		put(udoc, "invites", ucl_object_typed_new(UCL_ARRAY));
	/* The built-in owner: the keys from before users belong to it. */
	if (user_find(ADMIN_USER) == NULL) {
		u = ucl_object_typed_new(UCL_OBJECT);
		put(u, "name", ucl_object_fromstring(ADMIN_USER));
		put(u, "console", ucl_object_fromstring("owner"));
		h = ucl_object_typed_new(UCL_OBJECT);
		put(h, "*", ucl_object_fromstring("admin"));
		put(u, "hosts", h);
		put(u, "created", ucl_object_fromint(time(NULL)));
		ucl_array_append(users_list(), u);
		(void)store_save(USERS_FILE, udoc);
	}
}

/* What is said of a user: without the invitations' hashes. */
static ucl_object_t *
user_object(const ucl_object_t *u)
{
	ucl_object_t		*o;
	const ucl_object_t	*inv;
	ucl_object_iter_t	 it;
	int			 n;

	o = ucl_object_copy(u);
	n = 0;
	it = NULL;
	while ((inv = ucl_object_iterate(invites_list(), &it, true)) != NULL)
		if (ucl_str(inv, "user") != NULL && strcmp(ucl_str(inv, "user"),
		    ucl_str(u, "name")) == 0)
			n++;
	put(o, "invites", ucl_object_fromint(n));
	put(o, "keys", ucl_object_fromint(cred_count_of(ucl_str(u, "name"))));
	return (o);
}

static int
reply_users(struct http_request *req)
{
	ucl_object_t		*o, *a;
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;

	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((u = ucl_object_iterate(users_list(), &it, true)) != NULL)
		ucl_array_append(a, user_object(u));
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "users", a);
	return (reply_json(req, 200, o));
}

/* Is body a user that may be kept?  NULL, or what is wrong with it. */
static const char *
user_check(const ucl_object_t *body)
{
	const ucl_object_t	*h, *v;
	ucl_object_iter_t	 it;
	const char		*s;

	if ((s = ucl_str(body, "console")) != NULL && strcmp(s, "owner") != 0 &&
	    strcmp(s, "operator") != 0 && strcmp(s, "member") != 0)
		return ("console is owner, operator or member");
	if ((s = ucl_str(body, "tenant")) != NULL && s[0] != '\0' &&
	    !user_name_ok(s))
		return ("a tenant is named by letters, digits, _ . @ and -, 64 "
		    "at most");
	if ((h = ucl_object_lookup(body, "hosts")) != NULL) {
		if (ucl_object_type(h) != UCL_OBJECT)
			return ("hosts is an object: a role by host id, or \"*\"");
		it = NULL;
		while ((v = ucl_object_iterate(h, &it, true)) != NULL) {
			if (ucl_object_type(v) != UCL_STRING || role_of(
			    ucl_object_tostring(v)) == ROLE_NONE)
				return ("a host's role is viewer, operator or admin");
			if (strcmp(ucl_object_key(v), "*") != 0 && (strlen(
			    ucl_object_key(v)) != 8 || strspn(ucl_object_key(v),
			    "0123456789abcdef") != 8))
				return ("a host is named by its id, or \"*\" for all");
		}
	}
	return (NULL);
}

static int
owners(void)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((u = ucl_object_iterate(users_list(), &it, true)) != NULL)
		if (crole_of(ucl_str(u, "console")) == CROLE_OWNER)
			n++;
	return (n);
}

/* A user kept, added or in place of the one of the name; body is taken. */
static int
user_keep(struct http_request *req, ucl_object_t *body)
{
	ucl_object_t		*u, *h;
	const ucl_object_t	*old;
	const char		*e, *name;

	name = ucl_str(body, "name");
	if (!user_name_ok(name)) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "a user is named by "
		    "letters, digits, _ . @ and -, 64 at most"));
	}
	if ((e = user_check(body)) != NULL) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "%s", e));
	}
	old = user_find(name);
	if (old == NULL && ucl_array_size(users_list()) >= USERS_MAX) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "%d users at most",
		    USERS_MAX));
	}
	/* The last owner stays one. */
	if (old != NULL && crole_of(ucl_str(old, "console")) == CROLE_OWNER &&
	    crole_of(ucl_str(body, "console")) != CROLE_OWNER && owners() == 1) {
		ucl_object_unref(body);
		return (reply_error(req, 409, "last_owner", "the console keeps "
		    "an owner: make another one first"));
	}
	u = ucl_object_typed_new(UCL_OBJECT);
	put(u, "name", ucl_object_fromstring(name));
	put(u, "console", ucl_object_fromstring(ucl_str(body, "console") != NULL
	    ? ucl_str(body, "console") : "member"));
	if (ucl_str(body, "tenant") != NULL && ucl_str(body, "tenant")[0] != '\0')
		put(u, "tenant", ucl_object_fromstring(ucl_str(body, "tenant")));
	h = ucl_object_lookup(body, "hosts") != NULL ? ucl_object_copy(
	    ucl_object_lookup(body, "hosts")) : ucl_object_typed_new(UCL_OBJECT);
	put(u, "hosts", h);
	put(u, "created", ucl_object_fromint(old != NULL && ucl_object_lookup(
	    old, "created") != NULL ? ucl_object_toint(ucl_object_lookup(old,
	    "created")) : time(NULL)));
	if (old != NULL)
		ucl_object_unref(ucl_array_delete(users_list(), (ucl_object_t *)
		    (uintptr_t)old));
	ucl_array_append(users_list(), u);
	ucl_object_unref(body);
	if (store_save(USERS_FILE, udoc) != 0)
		return (reply_error(req, 500, "store", "the users could not be "
		    "written"));
	kore_log(LOG_NOTICE, "user %s %s by %s", name, old != NULL ? "changed" :
	    "added", session_who(req) != NULL ? session_who(req) : "?");
	return (reply_users(req));
}

/* GET /api/users: them all.  POST: one added or replaced, by its name. */
int
api_users(struct http_request *req)
{
	ucl_object_t	*body;

	if (!guard(req, req->method != HTTP_METHOD_GET))
		return (KORE_RESULT_OK);
	if (req->method == HTTP_METHOD_GET)
		return (reply_users(req));
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "a user: {\"name\", "
		    "\"console\", \"tenant\", \"hosts\": {\"*\": \"viewer\"}}"));
	return (user_keep(req, body));
}

/* PUT /api/users/<name>: as POST with the name; DELETE: gone, with
 * its keys and invitations. */
int
api_user(struct http_request *req)
{
	ucl_object_t		*body;
	const ucl_object_t	*u, *inv;
	ucl_object_iter_t	 it;
	char			 name[72];
	bool			 again;

	if (!capture(req, 3, name, sizeof(name)) || !user_name_ok(name))
		return (reply_error(req, 400, "invalid", "a user's name"));
	if (req->method == HTTP_METHOD_PUT) {
		if (!guard(req, true))
			return (KORE_RESULT_OK);
		if ((body = read_json(req)) == NULL)
			return (reply_error(req, 400, "invalid", "a user"));
		put(body, "name", ucl_object_fromstring(name));
		return (user_keep(req, body));
	}
	if (req->method != HTTP_METHOD_DELETE)
		return (reply_error(req, 405, "method", "PUT or DELETE"));
	if (!guard(req, true))
		return (KORE_RESULT_OK);
	if ((u = user_find(name)) == NULL)
		return (reply_error(req, 404, "not_found", "no user %s", name));
	if (crole_of(ucl_str(u, "console")) == CROLE_OWNER && owners() == 1)
		return (reply_error(req, 409, "last_owner", "the console keeps "
		    "an owner: make another one first"));
	ucl_object_unref(ucl_array_delete(users_list(), (ucl_object_t *)
	    (uintptr_t)u));
	do {
		again = false;
		it = NULL;
		while ((inv = ucl_object_iterate(invites_list(), &it, true)) !=
		    NULL)
			if (ucl_str(inv, "user") != NULL && strcmp(ucl_str(inv,
			    "user"), name) == 0) {
				ucl_object_unref(ucl_array_delete(invites_list(),
				    (ucl_object_t *)(uintptr_t)inv));
				again = true;
				break;
			}
	} while (again);
	if (store_save(USERS_FILE, udoc) != 0)
		return (reply_error(req, 500, "store", "the users could not be "
		    "written"));
	creds_forget_user(name);
	sessions_end_user(name);
	kore_log(LOG_NOTICE, "user %s removed by %s", name, session_who(req) !=
	    NULL ? session_who(req) : "?");
	return (reply_users(req));
}

/* POST /api/users/<name>/invite: a token for their first key, said once. */
int
api_user_invite(struct http_request *req)
{
	ucl_object_t	*o;
	char		 name[72], token[80];

	if (req->method != HTTP_METHOD_POST)
		return (reply_error(req, 405, "method", "POST"));
	if (!guard(req, true))
		return (KORE_RESULT_OK);
	if (!capture(req, 3, name, sizeof(name)) || !user_exists(name))
		return (reply_error(req, 404, "not_found", "no such user"));
	invites_sweep();
	if (!invite_make(name, token, sizeof(token)))
		return (reply_error(req, 500, "store", "the invitation could not "
		    "be written"));
	kore_log(LOG_NOTICE, "user %s invited by %s", name, session_who(req) !=
	    NULL ? session_who(req) : "?");
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "user", ucl_object_fromstring(name));
	put(o, "token", ucl_object_fromstring(token));
	put(o, "expires", ucl_object_fromint(time(NULL) + INVITE_LIFE));
	return (reply_json(req, 200, o));
}
