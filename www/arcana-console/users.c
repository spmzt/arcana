/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console's users, roles and what each may do (RBAC).  A role
 * names what may be done: on the console (owner: everything, the
 * settings, keys, tokens, CA, users and roles among it; operator: the
 * fleet's tools too, SD-WAN, workflows, templates, transfers; member:
 * the hosts alone) and on the hosts, by host id or "*" for all (viewer
 * reads; operator changes; admin also updates, moves and removes).  A
 * user has roles, one or more, and what they allow together; and may
 * belong to a tenant, a fleet of its own: it then sees the hosts of
 * that tenant alone (servers carry the tenant's name).  Three roles
 * come built in, owner, operator and viewer, and may be changed like
 * any.  Sign-in keys belong to a user; a key with none is the built-in
 * admin's, an owner, so a console with keys from before has its owner.
 * A user is invited: a one-time token with which they register their
 * first key.  A group is users given roles together: a user may do
 * what its own roles allow and what its groups' do.  users.json in the
 * data directory, {"users": [...], "roles": [...], "groups": [...],
 * "invites": [...]}; GET and POST /api/users, PUT and DELETE
 * /api/users/<name>, POST /api/users/<name>/invite; POST /api/roles,
 * PUT and DELETE /api/roles/<name>; POST /api/groups, PUT and DELETE
 * /api/groups/<name>.
 *
 * A user the console keeps may also have a password of the console's
 * own, beside their keys: kept as crypt(3)'s bcrypt ("$2b$"), never
 * said back, set from a session that may change the sign-in (auth.c),
 * or at the console's setup by password; a session it opens has the
 * user's roles, or, with password_full = false in web.conf, is limited
 * as a directory user's is.  A user the directory keeps (source ldap)
 * signs in with the directory's.
 */

#include <sys/param.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "console.h"

#define	USERS_FILE	"users.json"
#define	USERS_MAX	256
#define	ROLES_MAX	64
#define	GROUPS_MAX	64
#define	INVITE_LIFE	(24 * 3600)
#define	INVITE_BYTES	24

static ucl_object_t	*udoc;

static const char	*pw_of(const char *);

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
list_of(const char *key)
{

	return ((ucl_object_t *)(uintptr_t)ucl_object_lookup(udoc, key));
}

static const ucl_object_t *
by_name(const char *list, const char *name)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;

	it = NULL;
	while (name != NULL && (u = ucl_object_iterate(list_of(list), &it,
	    true)) != NULL)
		if (ucl_str(u, "name") != NULL && strcmp(ucl_str(u, "name"), name)
		    == 0)
			return (u);
	return (NULL);
}

/* A user's, a role's or a tenant's name: letters, digits, _ . @ -, 64. */
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

bool
user_exists(const char *name)
{

	return (by_name("users", name) != NULL);
}

/*
 * The users' names in v, max of them, copies the caller frees: every
 * one, or the owners of the console alone; how many.
 */
size_t
users_names(char **v, size_t max, bool owners_only)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	size_t			 n;

	n = 0;
	it = NULL;
	while (n < max && (u = ucl_object_iterate(list_of("users"), &it,
	    true)) != NULL)
		if (ucl_str(u, "name") != NULL && (!owners_only ||
		    user_console(ucl_str(u, "name")) == CROLE_OWNER))
			v[n++] = xstrdup(ucl_str(u, "name"));
	return (n);
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

/* A role's say on a host: the host's own entry, else "*"'s. */
static enum role
role_host(const ucl_object_t *role, const char *sid)
{
	const ucl_object_t	*h;

	h = ucl_object_lookup(role, "hosts");
	if (sid != NULL && ucl_object_lookup(h, sid) != NULL)
		return (role_of(ucl_object_tostring(ucl_object_lookup(h, sid))));
	return (role_of(ucl_object_tostring(ucl_object_lookup(h, "*"))));
}

/*
 * A user's roles: its own, and its groups'; into v, max at most, each
 * once.  How many.
 */
static int
roles_of(const ucl_object_t *u, const ucl_object_t **v, int max)
{
	const ucl_object_t	*e, *g, *r;
	ucl_object_iter_t	 it, git;
	int			 n, i;

	n = 0;
	it = NULL;
	while (n < max && (e = ucl_object_iterate(ucl_object_lookup(u,
	    "roles"), &it, true)) != NULL)
		if ((r = by_name("roles", ucl_object_tostring(e))) != NULL)
			v[n++] = r;
	it = NULL;
	while ((g = ucl_object_iterate(ucl_object_lookup(u, "groups"), &it,
	    true)) != NULL) {
		if ((g = by_name("groups", ucl_object_tostring(g))) == NULL)
			continue;
		git = NULL;
		while (n < max && (e = ucl_object_iterate(ucl_object_lookup(g,
		    "roles"), &git, true)) != NULL) {
			if ((r = by_name("roles", ucl_object_tostring(e))) ==
			    NULL)
				continue;
			for (i = 0; i < n && v[i] != r; i++)
				;
			if (i == n)
				v[n++] = r;
		}
	}
	return (n);
}

/*
 * A user's role on the console: the most its roles allow.  NULL, a
 * session that carries no user (an API token's, a directory's user
 * the console has no record of), is an operator's: what a write token
 * may.
 */
enum crole
user_console(const char *name)
{
	const ucl_object_t	*u, *v[ROLES_MAX];
	enum crole		 best, c;
	int			 i, n;

	if (name == NULL || name[0] == '\0')
		return (CROLE_OPERATOR);
	if ((u = by_name("users", name)) == NULL)
		return (CROLE_NONE);
	best = CROLE_NONE;
	n = roles_of(u, v, ROLES_MAX);
	for (i = 0; i < n; i++) {
		c = crole_of(ucl_str(v[i], "console"));
		if (c > best)
			best = c;
	}
	return (best);
}

/* The user's tenant, "" for none. */
const char *
user_tenant(const char *name)
{
	const ucl_object_t	*u;

	if ((u = by_name("users", name)) == NULL || ucl_str(u, "tenant") == NULL)
		return ("");
	return (ucl_str(u, "tenant"));
}

/*
 * A user's role on a host: the most its roles allow there; none on a
 * host of another tenant.  A session with no user has every host as
 * an admin.
 */
enum role
user_host(const char *name, const char *sid)
{
	const ucl_object_t	*u, *v[ROLES_MAX];
	const struct server	*s;
	const char		*t;
	enum role		 best, h;
	int			 i, n;

	if (name == NULL || name[0] == '\0')
		return (ROLE_ADMIN);
	if ((u = by_name("users", name)) == NULL)
		return (ROLE_NONE);
	t = ucl_str(u, "tenant");
	if (t != NULL && t[0] != '\0') {
		if ((s = server_find(sid)) == NULL || s->tenant == NULL ||
		    strcmp(s->tenant, t) != 0)
			return (ROLE_NONE);
	}
	best = ROLE_NONE;
	n = roles_of(u, v, ROLES_MAX);
	for (i = 0; i < n; i++) {
		h = role_host(v[i], sid);
		if (h > best)
			best = h;
	}
	return (best);
}

/*
 * May a user of this console role take the path: the console's own
 * (settings, tokens, CA, users, roles, enrolment, update, push) for
 * the owner alone; the fleet's tools (SD-WAN, workflows, templates,
 * transfers, the path finder, adding a host, keeping prefix lists) for
 * an operator too; the rest for everyone, the hosts' routes checked
 * by host besides.
 */
bool
user_path_ok(enum crole r, const char *path, bool mutate)
{
	static const char	*owner_only[] = { "/api/settings", "/api/tokens",
				    "/api/ca", "/api/users", "/api/roles",
				    "/api/groups",
				    "/api/enrol", "/api/update", "/api/push/send",
				    CYANG_DATA "settings", CYANG_DATA "tokens",
				    CYANG_DATA "users", CYANG_DATA "roles",
				    CYANG_DATA "groups", CYANG_DATA "enrolment" };
	static const char	*operator_up[] = { "/api/sdwan", "/api/feeds",
				    CYANG_DATA "workflows", CYANG_DATA "runs",
				    "/restconf/data/ietf-l3vpn-ntw:l3vpn-ntw",
				    "/restconf/data/ietf-vn:access-point",
				    "/restconf/data/ietf-vn:virtual-network",
				    "/restconf/operations/ietf-vn:vn-compute",
				    "/api/workflows",
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
	ucl_array_append(list_of("invites"), inv);
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
	while ((inv = ucl_object_iterate(list_of("invites"), &it, true)) !=
	    NULL) {
		if (ucl_str(inv, "hash") == NULL || strlen(ucl_str(inv, "hash"))
		    != 64 || timingsafe_bcmp(ucl_str(inv, "hash"), hex, 64) != 0)
			continue;
		if (ucl_object_toint(ucl_object_lookup(inv, "expires")) < now ||
		    !user_exists(ucl_str(inv, "user")))
			break;
		snprintf(user, len, "%s", ucl_str(inv, "user"));
		ucl_object_unref(ucl_array_delete(list_of("invites"),
		    (ucl_object_t *)(uintptr_t)inv));
		(void)store_save(USERS_FILE, udoc);
		return (true);
	}
	return (false);
}

/* Entries of a list taken away where match says: invitations run
 * out, or a user's, a role's name in users' lists. */
static void
invites_drop(const char *user)
{
	const ucl_object_t	*inv;
	ucl_object_iter_t	 it;
	time_t			 now;
	bool			 again;

	now = time(NULL);
	do {
		again = false;
		it = NULL;
		while ((inv = ucl_object_iterate(list_of("invites"), &it, true)) !=
		    NULL)
			if (ucl_object_toint(ucl_object_lookup(inv, "expires")) <
			    now || (user != NULL && ucl_str(inv, "user") != NULL &&
			    strcmp(ucl_str(inv, "user"), user) == 0)) {
				ucl_object_unref(ucl_array_delete(list_of("invites"),
				    (ucl_object_t *)(uintptr_t)inv));
				again = true;
				break;
			}
	} while (again);
}

static ucl_object_t *
role_new(const char *name, const char *console, const char *all)
{
	ucl_object_t	*r, *h;

	r = ucl_object_typed_new(UCL_OBJECT);
	put(r, "name", ucl_object_fromstring(name));
	put(r, "console", ucl_object_fromstring(console));
	h = ucl_object_typed_new(UCL_OBJECT);
	if (all != NULL)
		put(h, "*", ucl_object_fromstring(all));
	put(r, "hosts", h);
	put(r, "created", ucl_object_fromint(time(NULL)));
	return (r);
}

/* users.json, written by another node of the cluster: read again. */
void
users_reload(void)
{

	ucl_object_unref(udoc);
	udoc = NULL;
	users_init();
}

void
users_init(void)
{
	ucl_object_t		*u, *roles;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	bool			 changed;

	if ((udoc = store_load(USERS_FILE)) == NULL || ucl_object_type(udoc) !=
	    UCL_OBJECT) {
		if (udoc != NULL)
			ucl_object_unref(udoc);
		udoc = ucl_object_typed_new(UCL_OBJECT);
	}
	changed = false;
	if (ucl_object_lookup(udoc, "users") == NULL)
		put(udoc, "users", ucl_object_typed_new(UCL_ARRAY));
	if (ucl_object_lookup(udoc, "invites") == NULL)
		put(udoc, "invites", ucl_object_typed_new(UCL_ARRAY));
	if (ucl_object_lookup(udoc, "groups") == NULL)
		put(udoc, "groups", ucl_object_typed_new(UCL_ARRAY));
	if (ucl_object_lookup(udoc, "roles") == NULL) {
		put(udoc, "roles", ucl_object_typed_new(UCL_ARRAY));
		changed = true;
	}
	/* The roles that come built in, when none of the name is there. */
	if (by_name("roles", "owner") == NULL) {
		ucl_array_append(list_of("roles"), role_new("owner", "owner",
		    "admin"));
		changed = true;
	}
	if (by_name("roles", "operator") == NULL) {
		ucl_array_append(list_of("roles"), role_new("operator", "operator",
		    "operator"));
		changed = true;
	}
	if (by_name("roles", "viewer") == NULL) {
		ucl_array_append(list_of("roles"), role_new("viewer", "member",
		    "viewer"));
		changed = true;
	}
	/* A user written before roles: what it said becomes a role of its
	 * name, the built-in owner's the owner role. */
	it = NULL;
	while ((e = ucl_object_iterate(list_of("users"), &it, true)) != NULL) {
		if (ucl_object_lookup(e, "roles") != NULL)
			continue;
		u = (ucl_object_t *)(uintptr_t)e;
		roles = ucl_object_typed_new(UCL_ARRAY);
		if (strcmp(ucl_str(u, "name"), ADMIN_USER) == 0 || (ucl_str(u,
		    "console") == NULL && ucl_object_lookup(u, "hosts") == NULL))
			ucl_array_append(roles, ucl_object_fromstring(strcmp(
			    ucl_str(u, "name"), ADMIN_USER) == 0 ? "owner" :
			    "viewer"));
		else {
			ucl_object_t	*r = role_new(ucl_str(u, "name"), ucl_str(u,
			    "console") != NULL ? ucl_str(u, "console") : "member",
			    NULL);

			if (ucl_object_lookup(u, "hosts") != NULL)
				put(r, "hosts", ucl_object_copy(ucl_object_lookup(u,
				    "hosts")));
			if (by_name("roles", ucl_str(u, "name")) == NULL)
				ucl_array_append(list_of("roles"), r);
			else
				ucl_object_unref(r);
			ucl_array_append(roles, ucl_object_fromstring(ucl_str(u,
			    "name")));
		}
		put(u, "roles", roles);
		(void)ucl_object_delete_key(u, "console");
		(void)ucl_object_delete_key(u, "hosts");
		changed = true;
	}
	/* The built-in owner: the keys from before users belong to it. */
	if (by_name("users", ADMIN_USER) == NULL) {
		u = ucl_object_typed_new(UCL_OBJECT);
		put(u, "name", ucl_object_fromstring(ADMIN_USER));
		roles = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(roles, ucl_object_fromstring("owner"));
		put(u, "roles", roles);
		put(u, "created", ucl_object_fromint(time(NULL)));
		ucl_array_append(list_of("users"), u);
		changed = true;
	}
	if (changed)
		(void)store_save(USERS_FILE, udoc);
}

/* How many users have the role. */
static int
role_users(const char *role)
{
	const ucl_object_t	*u, *e;
	ucl_object_iter_t	 it, rit;
	int			 n;

	n = 0;
	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL) {
		rit = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(u, "roles"), &rit,
		    true)) != NULL)
			if (strcmp(ucl_object_tostring_forced(e), role) == 0) {
				n++;
				break;
			}
	}
	return (n);
}

/* How many groups give the role. */
static int
role_groups(const char *role)
{
	const ucl_object_t	*g, *e;
	ucl_object_iter_t	 it, rit;
	int			 n;

	n = 0;
	it = NULL;
	while ((g = ucl_object_iterate(list_of("groups"), &it, true)) != NULL) {
		rit = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(g, "roles"), &rit,
		    true)) != NULL)
			if (strcmp(ucl_object_tostring_forced(e), role) == 0) {
				n++;
				break;
			}
	}
	return (n);
}

static bool
in_group(const ucl_object_t *u, const char *group)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(u, "groups"), &it,
	    true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(e), group) == 0)
			return (true);
	return (false);
}

/* Its members' names, as a list. */
static ucl_object_t *
group_members(const char *group)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	ucl_object_t		*a;

	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL)
		if (in_group(u, group))
			ucl_array_append(a, ucl_object_fromstring(ucl_str(u,
			    "name")));
	return (a);
}

/* How many users are owners, as their roles stand. */
static int
owners(void)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL)
		if (user_console(ucl_str(u, "name")) == CROLE_OWNER)
			n++;
	return (n);
}

/* What is said of them all: the users with what their roles come to,
 * the roles with how many have each; the invitations' hashes not. */
static int
reply_all(struct http_request *req)
{
	ucl_object_t		*o, *a, *e, *rs, *gs;
	const ucl_object_t	*u, *inv, *r;
	ucl_object_iter_t	 it, iit;
	int			 n;

	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL) {
		e = ucl_object_copy(u);
		n = 0;
		iit = NULL;
		while ((inv = ucl_object_iterate(list_of("invites"), &iit, true))
		    != NULL)
			if (ucl_str(inv, "user") != NULL && strcmp(ucl_str(inv,
			    "user"), ucl_str(u, "name")) == 0)
				n++;
		put(e, "invites", ucl_object_fromint(n));
		put(e, "keys", ucl_object_fromint(cred_count_of(ucl_str(u,
		    "name"))));
		/* Whether they have a password; the hash is never said. */
		put(e, "password", ucl_object_frombool(pw_of(ucl_str(u,
		    "name")) != NULL));
		put(e, "console", ucl_object_fromstring(crole_name(user_console(
		    ucl_str(u, "name")))));
		ucl_array_append(a, e);
	}
	rs = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((r = ucl_object_iterate(list_of("roles"), &it, true)) != NULL) {
		e = ucl_object_copy(r);
		put(e, "users", ucl_object_fromint(role_users(ucl_str(r,
		    "name"))));
		put(e, "groups", ucl_object_fromint(role_groups(ucl_str(r,
		    "name"))));
		ucl_array_append(rs, e);
	}
	gs = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((r = ucl_object_iterate(list_of("groups"), &it, true)) != NULL) {
		e = ucl_object_copy(r);
		put(e, "members", group_members(ucl_str(r, "name")));
		ucl_array_append(gs, e);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "users", a);
	put(o, "roles", rs);
	put(o, "groups", gs);
	return (reply_json(req, 200, o));
}

/*
 * The roles given by a directory group, and the groups: into names and
 * groups, max at most; how many.  Good while the users are not changed.
 */
int
roles_ldap_groups(const char **names, const char **groups, int max)
{
	const ucl_object_t	*r;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while (n < max && (r = ucl_object_iterate(list_of("roles"), &it, true))
	    != NULL)
		if (ucl_str(r, "ldap_group") != NULL && ucl_str(r,
		    "ldap_group")[0] != '\0') {
			names[n] = ucl_str(r, "name");
			groups[n++] = ucl_str(r, "ldap_group");
		}
	return (n);
}

/*
 * A directory's user signed in, with the roles its groups gave: a user
 * of the console the directory keeps (source ldap) is made, or its
 * roles brought up to date, or, given none, taken away, so that the
 * sign-in is limited as before; one the owner made is left as it is.
 */
void
users_ldap_sync(const char *name, const char **roles, int nroles)
{
	const ucl_object_t	*old;
	ucl_object_t		*u, *ra;
	int			 i;

	if (!user_name_ok(name))
		return;
	old = by_name("users", name);
	if (old != NULL && (ucl_str(old, "source") == NULL || strcmp(ucl_str(
	    old, "source"), "ldap") != 0))
		return;
	if (old != NULL)
		ucl_object_unref(ucl_array_delete(list_of("users"), (ucl_object_t *)
		    (uintptr_t)old));
	if (nroles > 0) {
		u = ucl_object_typed_new(UCL_OBJECT);
		put(u, "name", ucl_object_fromstring(name));
		put(u, "source", ucl_object_fromstring("ldap"));
		ra = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < nroles; i++)
			ucl_array_append(ra, ucl_object_fromstring(roles[i]));
		put(u, "roles", ra);
		put(u, "created", ucl_object_fromint(time(NULL)));
		ucl_array_append(list_of("users"), u);
	}
	if (old != NULL || nroles > 0)
		(void)store_save(USERS_FILE, udoc);
}

/* ---- Passwords ---------------------------------------------------- */

#define	BCRYPT_COST	"12"		/* 2^12 rounds: a quarter second */

/* A bcrypt hash of pw, in out ("$2b$12$" and 53 more), or false. */
static bool
pw_hash(const char *pw, char *out, size_t len)
{
	static const char	alphabet[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789";
	struct crypt_data	cd;
	uint8_t			r[22];
	char			salt[40];
	const char		*h;
	size_t			i;
	bool			ok;

	arc4random_buf(r, sizeof(r));
	snprintf(salt, sizeof(salt), "$2b$%s$", BCRYPT_COST);
	for (i = 0; i < sizeof(r); i++)
		salt[7 + i] = alphabet[r[i] & 0x3f];
	salt[7 + sizeof(r)] = '\0';
	memset(&cd, 0, sizeof(cd));
	/* The hash is in cd: copied out before cd is wiped. */
	h = crypt_r(pw, salt, &cd);
	ok = h != NULL && strncmp(h, "$2b$", 4) == 0 && strlen(h) < len;
	if (ok)
		snprintf(out, len, "%s", h);
	explicit_bzero(&cd, sizeof(cd));
	return (ok);
}

/* A user's hash, or NULL: none, or one the directory keeps. */
static const char *
pw_of(const char *name)
{
	const ucl_object_t	*u;
	const char		*h;

	if ((u = by_name("users", name)) == NULL || ((h = ucl_str(u,
	    "password")) == NULL) || strncmp(h, "$2b$", 4) != 0)
		return (NULL);
	return (h);
}

bool
user_has_password(const char *name)
{

	return (name != NULL && pw_of(name) != NULL);
}

/*
 * Is pw the user's password?  One with none is compared all the same,
 * with a hash of nothing, so the time taken says not which users have
 * one.
 */
bool
user_password_ok(const char *name, const char *pw)
{
	static const char	 none[] = "$2b$" BCRYPT_COST "$"
	    "......................" "...............................";
	struct crypt_data	 cd;
	const char		*want, *got;
	bool			 ok;

	want = name != NULL ? pw_of(name) : NULL;
	if (pw == NULL || strlen(pw) > PASSWORD_MAX)
		pw = "";
	memset(&cd, 0, sizeof(cd));
	got = crypt_r(pw, want != NULL ? want : none, &cd);
	ok = want != NULL && got != NULL && strlen(got) == strlen(want) &&
	    timingsafe_bcmp(got, want, strlen(want)) == 0;
	explicit_bzero(&cd, sizeof(cd));
	return (ok);
}

/* Does any user have one?  The sign-in page then asks for it. */
bool
users_any_password(void)
{
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL)
		if (pw_of(ucl_str(u, "name")) != NULL)
			return (true);
	return (false);
}

/* Is pw a password that may be kept?  NULL, or what is wrong. */
const char *
user_password_check(const char *pw)
{
	size_t	i, n;

	if (pw == NULL || pw[0] == '\0')
		return ("a password, please");
	n = strlen(pw);
	if (n > PASSWORD_MAX)
		return ("a password is " __XSTRING(PASSWORD_MAX)
		    " bytes at most (bcrypt reads no more)");
	for (i = 0; i < n; i++)
		if ((unsigned char)pw[i] < 0x20 || pw[i] == 0x7f)
			return ("a password has no control characters");
	/* Characters, not bytes: a UTF-8 one counts once. */
	for (i = n = 0; pw[i] != '\0'; i++)
		if (((unsigned char)pw[i] & 0xc0) != 0x80)
			n++;
	if (n < PASSWORD_MIN)
		return ("a password is " __XSTRING(PASSWORD_MIN)
		    " characters at least");
	return (NULL);
}

/*
 * The user's password set to pw, or taken away when pw is NULL or "".
 * NULL when kept, or what is wrong.
 */
const char *
user_password_set(const char *name, const char *pw)
{
	const ucl_object_t	*old;
	ucl_object_t		*u;
	const char		*e;
	char			 h[128];

	if ((old = by_name("users", name)) == NULL)
		return ("no such user");
	if (ucl_str(old, "source") != NULL && strcmp(ucl_str(old, "source"),
	    "ldap") == 0)
		return ("a user the directory keeps signs in with the "
		    "directory's password");
	h[0] = '\0';
	if (pw != NULL && pw[0] != '\0') {
		if ((e = user_password_check(pw)) != NULL)
			return (e);
		if (!pw_hash(pw, h, sizeof(h)))
			return ("crypt(3) made no bcrypt hash");
	}
	u = ucl_object_copy(old);
	if (h[0] != '\0')
		put(u, "password", ucl_object_fromstring(h));
	else
		ucl_object_delete_key(u, "password");
	explicit_bzero(h, sizeof(h));
	ucl_object_unref(ucl_array_delete(list_of("users"), (ucl_object_t *)
	    (uintptr_t)old));
	ucl_array_append(list_of("users"), u);
	if (store_save(USERS_FILE, udoc) != 0)
		return ("the users could not be written");
	return (NULL);
}

/*
 * An owner of the console named name, made at its setup by password
 * (auth.c) when it is not the built-in admin: NULL when there is one,
 * or what is wrong.
 */
const char *
user_owner_add(const char *name)
{
	ucl_object_t	*u, *roles;

	if (!user_name_ok(name))
		return ("a user name is 1 to 64 letters, digits and _ . @ -");
	if (by_name("users", name) != NULL)
		return (user_console(name) == CROLE_OWNER ? NULL : "that user "
		    "is no owner of the console");
	if (ucl_array_size(list_of("users")) >= USERS_MAX)
		return ("too many users");
	u = ucl_object_typed_new(UCL_OBJECT);
	put(u, "name", ucl_object_fromstring(name));
	roles = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(roles, ucl_object_fromstring("owner"));
	put(u, "roles", roles);
	put(u, "created", ucl_object_fromint(time(NULL)));
	ucl_array_append(list_of("users"), u);
	if (store_save(USERS_FILE, udoc) != 0) {
		ucl_object_unref(ucl_array_delete(list_of("users"), u));
		return ("the users could not be written");
	}
	return (NULL);
}

/* The owner user_owner_add() made, gone again: its password was not
 * kept.  It has no keys, sessions or invitations yet. */
void
user_owner_undo(const char *name)
{
	const ucl_object_t	*u;

	if ((u = by_name("users", name)) == NULL)
		return;
	ucl_object_unref(ucl_array_delete(list_of("users"), (ucl_object_t *)
	    (uintptr_t)u));
	(void)store_save(USERS_FILE, udoc);
}

/* Is body a role that may be kept?  NULL, or what is wrong with it. */
static const char *
role_check(const ucl_object_t *body)
{
	const ucl_object_t	*h, *v;
	ucl_object_iter_t	 it;
	const char		*s;
	size_t			 i;

	/* A directory group's DN: printable, an attribute=value in it. */
	if ((s = ucl_str(body, "ldap_group")) != NULL && s[0] != '\0') {
		if (strlen(s) > 500 || strchr(s, '=') == NULL)
			return ("ldap_group is a group's DN, cn=noc,ou=groups,"
			    "dc=example,dc=org");
		for (i = 0; s[i] != '\0'; i++)
			if ((unsigned char)s[i] < 0x20 || s[i] == 0x7f)
				return ("ldap_group has no control characters");
	}

	if ((s = ucl_str(body, "console")) != NULL && strcmp(s, "owner") != 0 &&
	    strcmp(s, "operator") != 0 && strcmp(s, "member") != 0)
		return ("console is owner, operator or member");
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

/* Is body a user that may be kept?  NULL, or what is wrong with it. */
static const char *
user_check(const ucl_object_t *body)
{
	const ucl_object_t	*v, *g, *e;
	ucl_object_iter_t	 it;
	const char		*s;

	if ((s = ucl_str(body, "tenant")) != NULL && s[0] != '\0' &&
	    !user_name_ok(s))
		return ("a tenant is named by letters, digits, _ . @ and -, 64 "
		    "at most");
	if ((v = ucl_object_lookup(body, "roles")) != NULL && ucl_object_type(v)
	    != UCL_ARRAY)
		return ("roles is a list of the roles");
	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		if (ucl_object_type(e) != UCL_STRING || by_name("roles",
		    ucl_object_tostring(e)) == NULL)
			return ("a role named is one there is");
	if ((g = ucl_object_lookup(body, "groups")) != NULL && ucl_object_type(g)
	    != UCL_ARRAY)
		return ("groups is a list of the groups");
	it = NULL;
	while ((e = ucl_object_iterate(g, &it, true)) != NULL)
		if (ucl_object_type(e) != UCL_STRING || by_name("groups",
		    ucl_object_tostring(e)) == NULL)
			return ("a group named is one there is");
	if ((v == NULL || ucl_array_size(v) == 0) && (g == NULL ||
	    ucl_array_size(g) == 0))
		return ("a user has a role, or is in a group, one at least");
	return (NULL);
}

/* Why a change is refused: its HTTP status, /api's error code, words. */
struct uerr {
	int		 status;
	const char	*code;
	char		 why[160];
};

static int
refuse(struct uerr *e, int status, const char *code, const char *fmt, ...)
{
	va_list	ap;

	e->status = status;
	e->code = code;
	va_start(ap, fmt);
	vsnprintf(e->why, sizeof(e->why), fmt, ap);
	va_end(ap);
	return (status);
}

/* users.json as it is kept, again: what was changed in udoc undone. */
static void
undo(void)
{

	ucl_object_unref(udoc);
	udoc = NULL;
	users_init();
}

/* users.json written: 0, or 500 and why.  arcana-console's users, roles
 * and groups (each says the others') changed. */
static int
keep(struct uerr *e, const char *what)
{

	if (store_save(USERS_FILE, udoc) != 0)
		return (refuse(e, 500, "store", "the %s could not be written",
		    what));
	cyang_changed("users");
	cyang_changed("roles");
	cyang_changed("groups");
	return (0);
}

/* A role kept, added or in place of the one of the name; body is taken.
 * 0, or the status and why. */
static int
role_keep(ucl_object_t *body, const char *who, struct uerr *err)
{
	ucl_object_t		*r;
	const ucl_object_t	*old;
	const char		*e, *name;
	char			 kept[65];	/* name, the body's, kept */
	bool			 was_owner;

	name = ucl_str(body, "name");
	if (!user_name_ok(name)) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "a role is named by "
		    "letters, digits, _ . @ and -, 64 at most"));
	}
	if ((e = role_check(body)) != NULL) {
		refuse(err, 400, "invalid", "%s", e);
		ucl_object_unref(body);
		return (400);
	}
	strlcpy(kept, name, sizeof(kept));
	old = by_name("roles", name);
	if (old == NULL && ucl_array_size(list_of("roles")) >= ROLES_MAX) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "%d roles at most",
		    ROLES_MAX));
	}
	r = role_new(name, ucl_str(body, "console") != NULL ? ucl_str(body,
	    "console") : "member", NULL);
	if (ucl_object_lookup(body, "hosts") != NULL)
		put(r, "hosts", ucl_object_copy(ucl_object_lookup(body, "hosts")));
	if (ucl_str(body, "ldap_group") != NULL && ucl_str(body,
	    "ldap_group")[0] != '\0')
		put(r, "ldap_group", ucl_object_fromstring(ucl_str(body,
		    "ldap_group")));
	if (old != NULL && ucl_object_lookup(old, "created") != NULL)
		put(r, "created", ucl_object_fromint(ucl_object_toint(
		    ucl_object_lookup(old, "created"))));
	ucl_object_unref(body);
	/* Changed so that no owner is left: refused. */
	was_owner = old != NULL && crole_of(ucl_str(old, "console")) ==
	    CROLE_OWNER;
	if (old != NULL)
		ucl_object_unref(ucl_array_delete(list_of("roles"),
		    (ucl_object_t *)(uintptr_t)old));
	ucl_array_append(list_of("roles"), r);
	if (was_owner && owners() == 0) {
		undo();
		return (refuse(err, 409, "last_owner", "the console keeps an "
		    "owner: this role is what makes the last one"));
	}
	if (keep(err, "roles") != 0)
		return (500);
	log_msg(LOG_NOTICE, "role %s %s by %s", kept, old != NULL ? "changed" :
	    "added", who != NULL ? who : "?");
	return (0);
}

/* A user kept, added or in place of the one of the name; body is taken.
 * 0, or the status and why. */
static int
user_keep(ucl_object_t *body, const char *who, struct uerr *err)
{
	ucl_object_t		*u;
	const ucl_object_t	*old;
	const char		*e, *name;
	char			 kept[65];	/* name, the body's, kept */
	bool			 was_owner;

	name = ucl_str(body, "name");
	if (!user_name_ok(name)) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "a user is named by "
		    "letters, digits, _ . @ and -, 64 at most"));
	}
	if ((e = user_check(body)) != NULL) {
		refuse(err, 400, "invalid", "%s", e);
		ucl_object_unref(body);
		return (400);
	}
	strlcpy(kept, name, sizeof(kept));
	old = by_name("users", name);
	if (old == NULL && ucl_array_size(list_of("users")) >= USERS_MAX) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "%d users at most",
		    USERS_MAX));
	}
	was_owner = old != NULL && user_console(name) == CROLE_OWNER;
	u = ucl_object_typed_new(UCL_OBJECT);
	put(u, "name", ucl_object_fromstring(name));
	if (ucl_str(body, "tenant") != NULL && ucl_str(body, "tenant")[0] != '\0')
		put(u, "tenant", ucl_object_fromstring(ucl_str(body, "tenant")));
	put(u, "roles", ucl_object_lookup(body, "roles") != NULL ?
	    ucl_object_copy(ucl_object_lookup(body, "roles")) :
	    ucl_object_typed_new(UCL_ARRAY));
	if (ucl_object_lookup(body, "groups") != NULL &&
	    ucl_array_size(ucl_object_lookup(body, "groups")) > 0)
		put(u, "groups", ucl_object_copy(ucl_object_lookup(body,
		    "groups")));
	put(u, "created", ucl_object_fromint(old != NULL && ucl_object_lookup(
	    old, "created") != NULL ? ucl_object_toint(ucl_object_lookup(old,
	    "created")) : time(NULL)));
	/* Its password is set apart (auth.c), and kept through an edit. */
	if (old != NULL && pw_of(name) != NULL)
		put(u, "password", ucl_object_fromstring(pw_of(name)));
	ucl_object_unref(body);
	if (old != NULL)
		ucl_object_unref(ucl_array_delete(list_of("users"), (ucl_object_t *)
		    (uintptr_t)old));
	ucl_array_append(list_of("users"), u);
	/* The last owner stays one. */
	if (was_owner && owners() == 0) {
		undo();
		return (refuse(err, 409, "last_owner", "the console keeps an "
		    "owner: make another one first"));
	}
	if (keep(err, "users") != 0)
		return (500);
	log_msg(LOG_NOTICE, "user %s %s by %s", kept, old != NULL ? "changed" :
	    "added", who != NULL ? who : "?");
	return (0);
}

/* User name gone, with its keys, invitations, sessions and console
 * plugins' stores: 0, or the status and why. */
static int
user_remove(const char *name, const char *who, struct uerr *err)
{
	const ucl_object_t	*u;

	if ((u = by_name("users", name)) == NULL)
		return (refuse(err, 404, "not_found", "no user %s", name));
	if (user_console(name) == CROLE_OWNER && owners() == 1)
		return (refuse(err, 409, "last_owner", "the console keeps an "
		    "owner: make another one first"));
	ucl_object_unref(ucl_array_delete(list_of("users"), (ucl_object_t *)
	    (uintptr_t)u));
	invites_drop(name);
	if (keep(err, "users") != 0)
		return (500);
	creds_forget_user(name);
	sessions_end_user(name);
	cplug_store_forget(name);
	log_msg(LOG_NOTICE, "user %s removed by %s", name, who != NULL ? who :
	    "?");
	return (0);
}

/* Role name gone, when no user has it and no group gives it. */
static int
role_remove(const char *name, const char *who, struct uerr *err)
{
	const ucl_object_t	*r;

	if ((r = by_name("roles", name)) == NULL)
		return (refuse(err, 404, "not_found", "no role %s", name));
	if (role_users(name) > 0)
		return (refuse(err, 409, "in_use", "%d user%s ha%s the role: "
		    "give them another first", role_users(name), role_users(name)
		    == 1 ? "" : "s", role_users(name) == 1 ? "s" : "ve"));
	if (role_groups(name) > 0)
		return (refuse(err, 409, "in_use", "%d group%s give%s the "
		    "role: take it from them first", role_groups(name),
		    role_groups(name) == 1 ? "" : "s", role_groups(name) == 1 ?
		    "s" : ""));
	ucl_object_unref(ucl_array_delete(list_of("roles"), (ucl_object_t *)
	    (uintptr_t)r));
	if (keep(err, "roles") != 0)
		return (500);
	log_msg(LOG_NOTICE, "role %s removed by %s", name, who != NULL ? who :
	    "?");
	return (0);
}

/* GET /api/users: the users and the roles.  POST: a user added or
 * replaced, by its name. */
int
api_users(struct http_request *req)
{
	ucl_object_t	*body;
	struct uerr	 e;

	if (!guard(req, req->method != HTTP_METHOD_GET))
		return (WEB_OK);
	if (req->method == HTTP_METHOD_GET)
		return (reply_all(req));
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "a user: {\"name\", "
		    "\"tenant\", \"roles\": [...]}"));
	if (user_keep(body, session_who(req), &e) != 0)
		return (reply_error(req, e.status, e.code, "%s", e.why));
	return (reply_all(req));
}

/* PUT /api/users/<name>: as POST with the name; DELETE: gone, with
 * its keys, invitations, sessions and console plugins' stores. */
int
api_user(struct http_request *req)
{
	ucl_object_t		*body;
	struct uerr		 e;
	char			 name[72];

	if (!capture(req, 3, name, sizeof(name)) || !user_name_ok(name))
		return (reply_error(req, 400, "invalid", "a user's name"));
	if (req->method == HTTP_METHOD_PUT) {
		if (!guard(req, true))
			return (WEB_OK);
		if ((body = read_json(req)) == NULL)
			return (reply_error(req, 400, "invalid", "a user"));
		put(body, "name", ucl_object_fromstring(name));
		if (user_keep(body, session_who(req), &e) != 0)
			return (reply_error(req, e.status, e.code, "%s", e.why));
		return (reply_all(req));
	}
	if (req->method != HTTP_METHOD_DELETE)
		return (reply_error(req, 405, "method", "PUT or DELETE"));
	if (!guard(req, true))
		return (WEB_OK);
	if (user_remove(name, session_who(req), &e) != 0)
		return (reply_error(req, e.status, e.code, "%s", e.why));
	return (reply_all(req));
}

/* An invitation for user name, said once into token, with when it runs
 * out: 0, or the status and why. */
static int
user_invite(const char *name, const char *who, char *token, size_t len,
    time_t *expires, struct uerr *err)
{

	if (!user_exists(name))
		return (refuse(err, 404, "not_found", "no such user"));
	invites_drop(NULL);
	if (!invite_make(name, token, len))
		return (refuse(err, 500, "store", "the invitation could not be "
		    "written"));
	*expires = time(NULL) + INVITE_LIFE;
	cyang_changed("users");
	log_msg(LOG_NOTICE, "user %s invited by %s", name, who != NULL ? who :
	    "?");
	return (0);
}

/* POST /api/users/<name>/invite: a token for their first key, said once. */
int
api_user_invite(struct http_request *req)
{
	ucl_object_t	*o;
	struct uerr	 e;
	time_t		 expires;
	char		 name[72], token[80];

	if (req->method != HTTP_METHOD_POST)
		return (reply_error(req, 405, "method", "POST"));
	if (!guard(req, true))
		return (WEB_OK);
	if (!capture(req, 3, name, sizeof(name)))
		return (reply_error(req, 404, "not_found", "no such user"));
	if (user_invite(name, session_who(req), token, sizeof(token), &expires,
	    &e) != 0)
		return (reply_error(req, e.status, e.code, "%s", e.why));
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "user", ucl_object_fromstring(name));
	put(o, "token", ucl_object_fromstring(token));
	put(o, "expires", ucl_object_fromint(expires));
	explicit_bzero(token, sizeof(token));
	return (reply_json(req, 200, o));
}

/* POST /api/roles: a role added or replaced, by its name. */
int
api_roles(struct http_request *req)
{
	ucl_object_t	*body;
	struct uerr	 e;

	if (req->method != HTTP_METHOD_POST)
		return (reply_error(req, 405, "method", "POST; the roles come "
		    "with GET /api/users"));
	if (!guard(req, true))
		return (WEB_OK);
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "a role: {\"name\", "
		    "\"console\", \"hosts\": {\"*\": \"viewer\"}}"));
	if (role_keep(body, session_who(req), &e) != 0)
		return (reply_error(req, e.status, e.code, "%s", e.why));
	return (reply_all(req));
}

/* PUT /api/roles/<name>: as POST with the name; DELETE: gone, when no
 * user has it. */
int
api_role(struct http_request *req)
{
	ucl_object_t	*body;
	struct uerr	 e;
	char		 name[72];

	if (!capture(req, 3, name, sizeof(name)) || !user_name_ok(name))
		return (reply_error(req, 400, "invalid", "a role's name"));
	if (req->method == HTTP_METHOD_PUT) {
		if (!guard(req, true))
			return (WEB_OK);
		if ((body = read_json(req)) == NULL)
			return (reply_error(req, 400, "invalid", "a role"));
		put(body, "name", ucl_object_fromstring(name));
		if (role_keep(body, session_who(req), &e) != 0)
			return (reply_error(req, e.status, e.code, "%s", e.why));
		return (reply_all(req));
	}
	if (req->method != HTTP_METHOD_DELETE)
		return (reply_error(req, 405, "method", "PUT or DELETE"));
	if (!guard(req, true))
		return (WEB_OK);
	if (role_remove(name, session_who(req), &e) != 0)
		return (reply_error(req, e.status, e.code, "%s", e.why));
	return (reply_all(req));
}

/* Is body a group that may be kept?  NULL, or what is wrong with it. */
static const char *
group_check(const ucl_object_t *body)
{
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;

	if ((v = ucl_object_lookup(body, "roles")) == NULL || ucl_object_type(v)
	    != UCL_ARRAY)
		return ("roles is a list of the roles the group gives");
	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		if (ucl_object_type(e) != UCL_STRING || by_name("roles",
		    ucl_object_tostring(e)) == NULL)
			return ("a role named is one there is");
	if ((v = ucl_object_lookup(body, "members")) != NULL) {
		if (ucl_object_type(v) != UCL_ARRAY)
			return ("members is a list of the users in it");
		it = NULL;
		while ((e = ucl_object_iterate(v, &it, true)) != NULL)
			if (ucl_object_type(e) != UCL_STRING || by_name("users",
			    ucl_object_tostring(e)) == NULL)
				return ("a member named is a user there is");
	}
	if ((e = ucl_object_lookup(body, "description")) != NULL &&
	    (ucl_object_type(e) != UCL_STRING || strlen(ucl_object_tostring(e))
	    > 200))
		return ("a description is 200 characters at most");
	return (NULL);
}

/* The user in the group, or not. */
static void
membership(const char *user, const char *group, bool in)
{
	ucl_object_t		*u, *gs, *e;
	ucl_object_iter_t	 it;

	if ((u = (ucl_object_t *)(uintptr_t)by_name("users", user)) == NULL)
		return;
	if ((gs = (ucl_object_t *)(uintptr_t)ucl_object_lookup(u, "groups")) ==
	    NULL) {
		if (!in)
			return;
		gs = ucl_object_typed_new(UCL_ARRAY);
		put(u, "groups", gs);
	}
	it = NULL;
	while ((e = (ucl_object_t *)(uintptr_t)ucl_object_iterate(gs, &it,
	    true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(e), group) == 0) {
			if (in)
				return;
			ucl_object_unref(ucl_array_delete(gs, e));
			break;
		}
	if (in)
		ucl_array_append(gs, ucl_object_fromstring(group));
}

/* Undone, as users.json still has it, with why: the last owner stays. */
static int
undo_owner(struct uerr *err)
{

	undo();
	return (refuse(err, 409, "last_owner", "the console keeps an owner: "
	    "make another one first"));
}

/*
 * A group kept, added or in place of the one of the name; its members,
 * when they are named, made those; body is taken.  0, or the status and
 * why.
 */
static int
group_keep(ucl_object_t *body, const char *who, struct uerr *err)
{
	ucl_object_t		*g;
	const ucl_object_t	*old, *m, *u, *e;
	ucl_object_iter_t	 it, mit;
	const char		*bad, *name;
	char			 kept[65];	/* name, the body's, kept */
	bool			 named;

	name = ucl_str(body, "name");
	if (!user_name_ok(name)) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "a group is named by "
		    "letters, digits, _ . @ and -, 64 at most"));
	}
	if ((bad = group_check(body)) != NULL) {
		refuse(err, 400, "invalid", "%s", bad);
		ucl_object_unref(body);
		return (400);
	}
	strlcpy(kept, name, sizeof(kept));
	old = by_name("groups", name);
	if (old == NULL && ucl_array_size(list_of("groups")) >= GROUPS_MAX) {
		ucl_object_unref(body);
		return (refuse(err, 400, "invalid", "%d groups at most",
		    GROUPS_MAX));
	}
	g = ucl_object_typed_new(UCL_OBJECT);
	put(g, "name", ucl_object_fromstring(name));
	put(g, "roles", ucl_object_copy(ucl_object_lookup(body, "roles")));
	if (ucl_str(body, "description") != NULL && ucl_str(body,
	    "description")[0] != '\0')
		put(g, "description", ucl_object_fromstring(ucl_str(body,
		    "description")));
	if (old != NULL)
		ucl_object_unref(ucl_array_delete(list_of("groups"),
		    (ucl_object_t *)(uintptr_t)old));
	ucl_array_append(list_of("groups"), g);
	if ((m = ucl_object_lookup(body, "members")) != NULL) {
		it = NULL;
		while ((u = ucl_object_iterate(list_of("users"), &it, true)) !=
		    NULL) {
			named = false;
			mit = NULL;
			while ((e = ucl_object_iterate(m, &mit, true)) != NULL)
				if (strcmp(ucl_object_tostring(e), ucl_str(u,
				    "name")) == 0)
					named = true;
			membership(ucl_str(u, "name"), name, named);
		}
	}
	ucl_object_unref(body);
	/* The last owner stays one, whatever a group's roles became. */
	if (owners() == 0)
		return (undo_owner(err));
	if (keep(err, "groups") != 0)
		return (500);
	log_msg(LOG_NOTICE, "group %s %s by %s", kept, old != NULL ? "changed" :
	    "added", who != NULL ? who : "?");
	return (0);
}

/* Group name gone, its users out of it. */
static int
group_remove(const char *name, const char *who, struct uerr *err)
{
	const ucl_object_t	*g, *u;
	ucl_object_iter_t	 it;

	if ((g = by_name("groups", name)) == NULL)
		return (refuse(err, 404, "not_found", "no group %s", name));
	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL)
		membership(ucl_str(u, "name"), name, false);
	ucl_object_unref(ucl_array_delete(list_of("groups"), (ucl_object_t *)
	    (uintptr_t)g));
	if (owners() == 0)
		return (undo_owner(err));
	if (keep(err, "groups") != 0)
		return (500);
	log_msg(LOG_NOTICE, "group %s removed by %s", name, who != NULL ? who :
	    "?");
	return (0);
}

/* POST /api/groups: a group added or replaced, by its name. */
int
api_groups(struct http_request *req)
{
	ucl_object_t	*body;
	struct uerr	 e;

	if (req->method != HTTP_METHOD_POST)
		return (reply_error(req, 405, "method", "POST; the groups come "
		    "with GET /api/users"));
	if (!guard(req, true))
		return (WEB_OK);
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "a group: {\"name\", "
		    "\"roles\": [...], \"members\": [...]}"));
	if (group_keep(body, session_who(req), &e) != 0)
		return (reply_error(req, e.status, e.code, "%s", e.why));
	return (reply_all(req));
}

/* PUT /api/groups/<name>: as POST with the name; DELETE: gone, its users
 * out of it. */
int
api_group(struct http_request *req)
{
	ucl_object_t	*body;
	struct uerr	 e;
	char		 name[72];

	if (!capture(req, 3, name, sizeof(name)) || !user_name_ok(name))
		return (reply_error(req, 400, "invalid", "a group's name"));
	if (req->method == HTTP_METHOD_PUT) {
		if (!guard(req, true))
			return (WEB_OK);
		if ((body = read_json(req)) == NULL)
			return (reply_error(req, 400, "invalid", "a group"));
		put(body, "name", ucl_object_fromstring(name));
		if (group_keep(body, session_who(req), &e) != 0)
			return (reply_error(req, e.status, e.code, "%s", e.why));
		return (reply_all(req));
	}
	if (req->method != HTTP_METHOD_DELETE)
		return (reply_error(req, 405, "method", "PUT or DELETE"));
	if (!guard(req, true))
		return (WEB_OK);
	if (group_remove(name, session_who(req), &e) != 0)
		return (reply_error(req, e.status, e.code, "%s", e.why));
	return (reply_all(req));
}

/* ---- arcana-console's users, roles and groups (cyang.c) -------------- */

static void
strings_into(ucl_object_t *o, const char *key, const ucl_object_t *a)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*l;

	l = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(a, &it, true)) != NULL)
		ucl_array_append(l, ucl_object_fromstring(
		    ucl_object_tostring_forced(e)));
	if (ucl_array_size(l) > 0)
		put(o, key, l);
	else
		ucl_object_unref(l);
}

/* arcana-console:users's value. */
ucl_object_t *
users_yang(void)
{
	ucl_object_t		*o, *a, *e;
	const ucl_object_t	*u, *inv, *v;
	ucl_object_iter_t	 it, iit;
	const char		*name;
	int			 n;

	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((u = ucl_object_iterate(list_of("users"), &it, true)) != NULL) {
		if ((name = ucl_str(u, "name")) == NULL)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "name", ucl_object_fromstring(name));
		if (ucl_str(u, "tenant") != NULL && ucl_str(u, "tenant")[0] !=
		    '\0')
			put(e, "tenant", ucl_object_fromstring(ucl_str(u,
			    "tenant")));
		strings_into(e, "role", ucl_object_lookup(u, "roles"));
		strings_into(e, "group", ucl_object_lookup(u, "groups"));
		if ((v = ucl_object_lookup(u, "created")) != NULL)
			put(e, "created", yang_time((double)ucl_object_toint(v)));
		put(e, "console-role", ucl_object_fromstring(crole_name(
		    user_console(name))));
		put(e, "keys", ucl_object_fromint(cred_count_of(name)));
		n = 0;
		iit = NULL;
		while ((inv = ucl_object_iterate(list_of("invites"), &iit,
		    true)) != NULL)
			if (ucl_str(inv, "user") != NULL && strcmp(ucl_str(inv,
			    "user"), name) == 0)
				n++;
		put(e, "invitations", ucl_object_fromint(n));
		put(e, "has-password", ucl_object_frombool(pw_of(name) !=
		    NULL));
		ucl_array_append(a, e);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "user", a);
	return (o);
}

/* arcana-console:roles's value. */
ucl_object_t *
roles_yang(void)
{
	ucl_object_t		*o, *a, *e, *hs, *h;
	const ucl_object_t	*r, *v;
	ucl_object_iter_t	 it, hit;
	const char		*name;

	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((r = ucl_object_iterate(list_of("roles"), &it, true)) != NULL) {
		if ((name = ucl_str(r, "name")) == NULL)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "name", ucl_object_fromstring(name));
		put(e, "console", ucl_object_fromstring(ucl_str(r, "console") !=
		    NULL ? ucl_str(r, "console") : "member"));
		hs = ucl_object_typed_new(UCL_ARRAY);
		hit = NULL;
		while ((v = ucl_object_iterate(ucl_object_lookup(r, "hosts"),
		    &hit, true)) != NULL) {
			h = ucl_object_typed_new(UCL_OBJECT);
			put(h, "id", ucl_object_fromstring(ucl_object_key(v)));
			put(h, "role", ucl_object_fromstring(
			    ucl_object_tostring_forced(v)));
			ucl_array_append(hs, h);
		}
		if (ucl_array_size(hs) > 0)
			put(e, "host", hs);
		else
			ucl_object_unref(hs);
		if (ucl_str(r, "ldap_group") != NULL && ucl_str(r,
		    "ldap_group")[0] != '\0')
			put(e, "ldap-group", ucl_object_fromstring(ucl_str(r,
			    "ldap_group")));
		if ((v = ucl_object_lookup(r, "created")) != NULL)
			put(e, "created", yang_time((double)ucl_object_toint(v)));
		put(e, "users", ucl_object_fromint(role_users(name)));
		put(e, "groups", ucl_object_fromint(role_groups(name)));
		ucl_array_append(a, e);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "role", a);
	return (o);
}

/* arcana-console:groups's value. */
ucl_object_t *
groups_yang(void)
{
	ucl_object_t		*o, *a, *e, *m;
	const ucl_object_t	*g;
	ucl_object_iter_t	 it;
	const char		*name;

	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((g = ucl_object_iterate(list_of("groups"), &it, true)) != NULL) {
		if ((name = ucl_str(g, "name")) == NULL)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "name", ucl_object_fromstring(name));
		strings_into(e, "role", ucl_object_lookup(g, "roles"));
		if (ucl_str(g, "description") != NULL && ucl_str(g,
		    "description")[0] != '\0')
			put(e, "description", ucl_object_fromstring(ucl_str(g,
			    "description")));
		m = group_members(name);
		strings_into(e, "member", m);
		ucl_object_unref(m);
		ucl_array_append(a, e);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "group", a);
	return (o);
}

/* list's entry named name; NULL: none. */
static const ucl_object_t *
entry_of(const ucl_object_t *list, const char *name)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;

	while ((e = ucl_object_iterate(list, &it, true)) != NULL)
		if (ucl_str(e, "name") != NULL && strcmp(ucl_str(e, "name"),
		    name) == 0)
			return (e);
	return (NULL);
}

/* Whether a and b have the same at each of keys. */
static bool
same_at(const ucl_object_t *a, const ucl_object_t *b,
    const char *const *keys)
{
	const ucl_object_t	*x, *y;

	for (; *keys != NULL; keys++) {
		x = ucl_object_lookup(a, *keys);
		y = ucl_object_lookup(b, *keys);
		if ((x == NULL) != (y == NULL) || (x != NULL &&
		    ucl_object_compare(x, y) != 0))
			return (false);
	}
	return (true);
}

/* A string list of o's key, or an empty one. */
static ucl_object_t *
strings_of(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, key);
	return (v != NULL ? ucl_object_copy(v) : ucl_object_typed_new(
	    UCL_ARRAY));
}

/*
 * arcana-console's users, roles and groups changed from was to now
 * (each the value of the three, as {"users": ..., "roles": ...,
 * "groups": ...}): each entry made or changed kept, each left out
 * removed, through the setters /api's go through.  All or nothing: what
 * was kept before a refusal undone (but a user's keys and sessions, a
 * user removed being last).  0, or the status and why.
 */
int
users_yang_set(const ucl_object_t *was, const ucl_object_t *now,
    const char *who, char *why, size_t len)
{
	static const char *const ukeys[] = { "tenant", "role", "group", NULL };
	static const char *const rkeys[] = { "console", "host", "ldap-group",
	    NULL };
	static const char *const gkeys[] = { "role", "description", NULL };
	const ucl_object_t	*e, *o, *h;
	ucl_object_iter_t	 it, hit;
	ucl_object_t		*body, *hs, *saved;
	struct uerr		 err;
	int			 rc = 0;

	saved = ucl_object_copy(udoc);
	/* The roles, the groups, then the users made or changed. */
	it = NULL;
	while (rc == 0 && (e = ucl_object_iterate(ucl_object_lookup_path(now,
	    "roles.role"), &it, true)) != NULL) {
		o = entry_of(ucl_object_lookup_path(was, "roles.role"),
		    ucl_str(e, "name"));
		if (o != NULL && same_at(o, e, rkeys))
			continue;
		body = ucl_object_typed_new(UCL_OBJECT);
		put(body, "name", ucl_object_fromstring(ucl_str(e, "name")));
		put(body, "console", ucl_object_fromstring(ucl_str(e,
		    "console") != NULL ? ucl_str(e, "console") : "member"));
		hs = ucl_object_typed_new(UCL_OBJECT);
		hit = NULL;
		while ((h = ucl_object_iterate(ucl_object_lookup(e, "host"),
		    &hit, true)) != NULL)
			put(hs, ucl_str(h, "id"), ucl_object_fromstring(
			    ucl_str(h, "role")));
		put(body, "hosts", hs);
		if (ucl_str(e, "ldap-group") != NULL)
			put(body, "ldap_group", ucl_object_fromstring(ucl_str(e,
			    "ldap-group")));
		rc = role_keep(body, who, &err);
	}
	it = NULL;
	while (rc == 0 && (e = ucl_object_iterate(ucl_object_lookup_path(now,
	    "groups.group"), &it, true)) != NULL) {
		o = entry_of(ucl_object_lookup_path(was, "groups.group"),
		    ucl_str(e, "name"));
		if (o != NULL && same_at(o, e, gkeys))
			continue;
		body = ucl_object_typed_new(UCL_OBJECT);
		put(body, "name", ucl_object_fromstring(ucl_str(e, "name")));
		put(body, "roles", strings_of(e, "role"));
		if (ucl_str(e, "description") != NULL)
			put(body, "description", ucl_object_fromstring(ucl_str(e,
			    "description")));
		rc = group_keep(body, who, &err);
	}
	it = NULL;
	while (rc == 0 && (e = ucl_object_iterate(ucl_object_lookup_path(now,
	    "users.user"), &it, true)) != NULL) {
		o = entry_of(ucl_object_lookup_path(was, "users.user"),
		    ucl_str(e, "name"));
		if (o != NULL && same_at(o, e, ukeys))
			continue;
		body = ucl_object_typed_new(UCL_OBJECT);
		put(body, "name", ucl_object_fromstring(ucl_str(e, "name")));
		if (ucl_str(e, "tenant") != NULL)
			put(body, "tenant", ucl_object_fromstring(ucl_str(e,
			    "tenant")));
		put(body, "roles", strings_of(e, "role"));
		put(body, "groups", strings_of(e, "group"));
		rc = user_keep(body, who, &err);
	}
	/* Then those left out: the users, the groups, the roles. */
	it = NULL;
	while (rc == 0 && (o = ucl_object_iterate(ucl_object_lookup_path(was,
	    "users.user"), &it, true)) != NULL)
		if (entry_of(ucl_object_lookup_path(now, "users.user"),
		    ucl_str(o, "name")) == NULL)
			rc = user_remove(ucl_str(o, "name"), who, &err);
	it = NULL;
	while (rc == 0 && (o = ucl_object_iterate(ucl_object_lookup_path(was,
	    "groups.group"), &it, true)) != NULL)
		if (entry_of(ucl_object_lookup_path(now, "groups.group"),
		    ucl_str(o, "name")) == NULL)
			rc = group_remove(ucl_str(o, "name"), who, &err);
	it = NULL;
	while (rc == 0 && (o = ucl_object_iterate(ucl_object_lookup_path(was,
	    "roles.role"), &it, true)) != NULL)
		if (entry_of(ucl_object_lookup_path(now, "roles.role"),
		    ucl_str(o, "name")) == NULL)
			rc = role_remove(ucl_str(o, "name"), who, &err);
	if (rc != 0) {
		snprintf(why, len, "%s", err.why);
		ucl_object_unref(udoc);
		udoc = saved;
		(void)store_save(USERS_FILE, udoc);
		return (err.status);
	}
	ucl_object_unref(saved);
	return (0);
}

/* The invite action: an invitation for user name, said once.  0, or the
 * status and why. */
int
users_yang_invite(const char *name, const char *who, char *token,
    size_t tlen, time_t *expires, char *why, size_t len)
{
	struct uerr	err;

	if (user_invite(name, who, token, tlen, expires, &err) != 0) {
		snprintf(why, len, "%s", err.why);
		return (err.status);
	}
	return (0);
}
