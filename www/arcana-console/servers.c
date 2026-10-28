/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The arcana-agent instances the console knows: a name and a cblink URI,
 * "unix:/var/run/arcana-agent.sock" for this host or "tcp://host:4310" for
 * others, with the certificate name to expect when it differs from the
 * host.  Kept in servers.json in the data directory.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <openssl/evp.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "console.h"

#define	SERVERS		"servers.json"
#define	MAX_SERVERS	64

static struct server	servers[MAX_SERVERS];
static int		nservers;

/*
 * The table is the worker's, but threads ask it the rollback timer of a
 * URI: what changes a URI, a server or a timer holds this lock.
 */
static pthread_mutex_t	table_lock = PTHREAD_MUTEX_INITIALIZER;

static bool	valid_name(const char *);
static bool	valid_uri(const char *);
static int	save(void);
static ucl_object_t *server_object(const struct server *, bool);
static void	 add(const char *, const char *, const char *, const char *,
		    const char *);
static void	new_id(char *, size_t);
static void	local_enrol(void);
static const char *socket_path(const char *);
static bool	same_socket(const char *, const char *);

/*
 * The agent beside the console.  Arcana installs both, so the host the
 * console runs on is the first to manage: once its agent answers on
 * its local socket, it is added by itself, under the host's name.  It
 * is added once: taken off the list by somebody, it stays off.
 */
static bool		local_done;	/* added once, or found there */
static const char	*local_state = "off";

static bool
valid_name(const char *s)
{
	size_t	len;

	len = strlen(s);
	if (len == 0 || len > 64)
		return (false);
	for (; *s != '\0'; s++)
		if (iscntrl((unsigned char)*s))
			return (false);
	return (true);
}

/* unix:/absolute/path, or tcp://host:port with a non-empty host. */
static bool
valid_uri(const char *s)
{
	const char	*p;

	if (strlen(s) > 255)
		return (false);
	for (p = s; *p != '\0'; p++)
		if (isspace((unsigned char)*p) || iscntrl((unsigned char)*p))
			return (false);
	if (strncmp(s, "unix:/", 6) == 0)
		return (s[6] != '\0');
	if (strncmp(s, "tcp://", 6) == 0 || strncmp(s, "sctp://", 7) == 0)
		return ((p = strrchr(s, ':')) != NULL && p[1] != '\0' &&
		    p > strchr(s, ':') + 3);
	return (false);
}

static void
add(const char *id, const char *name, const char *uri, const char *peer,
    const char *tenant)
{
	struct server	*s;

	pthread_mutex_lock(&table_lock);
	s = &servers[nservers++];
	strlcpy(s->id, id, sizeof(s->id));
	s->name = xstrdup(name);
	s->uri = xstrdup(uri);
	s->peer_name = peer != NULL && *peer != '\0' ? xstrdup(peer) :
	    NULL;
	s->tenant = tenant != NULL && *tenant != '\0' ? xstrdup(tenant) :
	    NULL;
	s->safe_wait = 0;
	s->pkg_repos = NULL;
	s->notif_token = NULL;
	pthread_mutex_unlock(&table_lock);
}

/* servers.json, written by another node of the cluster: read again. */
void
servers_reload(void)
{
	int	i;

	pthread_mutex_lock(&table_lock);
	for (i = 0; i < nservers; i++) {
		free(servers[i].name);
		free(servers[i].uri);
		free(servers[i].peer_name);
		free(servers[i].tenant);
		free(servers[i].notif_token);
	}
	nservers = 0;
	pthread_mutex_unlock(&table_lock);
	servers_init();
}

void
servers_init(void)
{
	const ucl_object_t	*a, *o;
	ucl_object_t		*doc;
	ucl_object_iter_t	 it;
	const char		*id, *name, *uri;
	int64_t			 k;

	if ((doc = store_load(SERVERS)) == NULL)
		return;
	a = ucl_object_lookup(doc, "servers");
	it = NULL;
	while ((o = ucl_object_iterate(a, &it, true)) != NULL &&
	    nservers < MAX_SERVERS) {
		id = ucl_str(o, "id");
		name = ucl_str(o, "name");
		uri = ucl_str(o, "uri");
		if (id == NULL || strlen(id) != 8 || name == NULL ||
		    uri == NULL || !valid_uri(uri))
			continue;
		add(id, name, uri, ucl_str(o, "peer_name"), ucl_str(o, "tenant"));
		k = ucl_object_toint(ucl_object_lookup(o, "safe_wait"));
		servers[nservers - 1].safe_wait = k >= SAFE_WAIT_MIN &&
		    k <= SAFE_WAIT_MAX ? (int)k : 0;
		if (ucl_object_type(ucl_object_lookup(o, "pkg_repos")) ==
		    UCL_OBJECT)
			servers[nservers - 1].pkg_repos = ucl_object_ref(
			    ucl_object_lookup(o, "pkg_repos"));
		if ((name = ucl_str(o, "notif_token")) != NULL && strlen(name) ==
		    64 && strspn(name, "0123456789abcdef") == 64)
			servers[nservers - 1].notif_token = xstrdup(name);
	}
	local_done = ucl_flag(doc, "local_done");
	ucl_object_unref(doc);
}

/* The path of a unix: URI, however many slashes it was written with. */
static const char *
socket_path(const char *uri)
{

	if (strncmp(uri, "unix:", 5) != 0)
		return (NULL);
	uri += 5;
	while (uri[0] == '/' && uri[1] == '/')
		uri++;
	return (uri);
}

/* Do two URIs name one local socket?  unix:/x and unix:///x do. */
static bool
same_socket(const char *a, const char *b)
{
	const char	*pa, *pb;

	return ((pa = socket_path(a)) != NULL && (pb = socket_path(b)) !=
	    NULL && strcmp(pa, pb) == 0);
}

/*
 * Look for the agent beside the console, until it was added once.  Its
 * socket is tried, not only looked at: one the console's user may not
 * connect to is no agent to add, and why is told to who asks.
 */
static void
local_enrol(void)
{
	struct sockaddr_un	 sun;
	char			 host[MAXHOSTNAMELEN], id[9];
	const char		*path;
	int			 i, s, error;

	if (cfg.local_agent == NULL || strncmp(cfg.local_agent, "unix:/",
	    6) != 0) {
		local_state = "off";
		return;
	}
	for (i = 0; i < nservers; i++)
		if (same_socket(servers[i].uri, cfg.local_agent)) {
			local_state = "added";
			if (!local_done) {
				local_done = true;
				(void)save();
			}
			return;
		}
	if (local_done) {
		local_state = "removed";
		return;
	}
	path = socket_path(cfg.local_agent);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path) || nservers == MAX_SERVERS) {
		local_state = "off";
		return;
	}
	if ((s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
		return;
	error = connect(s, (struct sockaddr *)&sun, sizeof(sun)) == -1 ?
	    errno : 0;
	close(s);
	if (error != 0) {
		/* Not running, or not for the console's user to reach. */
		local_state = error == EACCES || error == EPERM ? "denied" :
		    "absent";
		return;
	}
	if (gethostname(host, sizeof(host)) == -1 || host[0] == '\0')
		strlcpy(host, "this host", sizeof(host));
	host[sizeof(host) - 1] = '\0';
	host[strcspn(host, ".")] = '\0';
	if (!valid_name(host))
		strlcpy(host, "this host", sizeof(host));
	new_id(id, sizeof(id));
	add(id, host, cfg.local_agent, NULL, NULL);
	local_done = true;
	local_state = "added";
	if (save() == -1)
		log_msg(LOG_ERR, "cannot save the list of servers");
	log_msg(LOG_NOTICE, "server %s added by itself: the agent beside "
	    "the console, %s", id, cfg.local_agent);
}

static void
new_id(char *id, size_t len)
{
	uint8_t	raw[4];

	do {
		arc4random_buf(raw, sizeof(raw));
		snprintf(id, len, "%02x%02x%02x%02x", raw[0], raw[1], raw[2],
		    raw[3]);
	} while (server_find(id) != NULL);
}

/*
 * Add a server and save the list.  -1 when the arguments do not pass,
 * the list is full or the URI is already there, or saving fails.
 */
int
servers_add(const char *name, const char *uri, const char *peer)
{
	char	id[9];
	int	i;

	if (!valid_name(name) || !valid_uri(uri) || (peer != NULL &&
	    (!valid_name(peer) || strchr(peer, ' ') != NULL)) ||
	    nservers == MAX_SERVERS)
		return (-1);
	for (i = 0; i < nservers; i++)
		if (strcmp(servers[i].uri, uri) == 0)
			return (-1);
	new_id(id, sizeof(id));
	add(id, name, uri, peer, NULL);
	if (save() == -1)
		return (-1);
	log_msg(LOG_NOTICE, "server %s added: %s", id, uri);
	return (0);
}

/*
 * A server is reached at another URI from now on.  -1 when it is not a
 * URI, another server has it, or saving fails; the connections kept to
 * where it was are closed.
 */
int
servers_move(const char *id, const char *uri)
{
	char	*old;
	int	 i, k;

	if (!valid_uri(uri))
		return (-1);
	for (i = 0; i < nservers; i++)
		if (strcmp(servers[i].id, id) == 0)
			break;
	if (i == nservers)
		return (-1);
	for (k = 0; k < nservers; k++)
		if (k != i && strcmp(servers[k].uri, uri) == 0)
			return (-1);
	old = servers[i].uri;
	pthread_mutex_lock(&table_lock);
	servers[i].uri = xstrdup(uri);
	pthread_mutex_unlock(&table_lock);
	if (save() == -1) {
		pthread_mutex_lock(&table_lock);
		free(servers[i].uri);
		servers[i].uri = old;
		pthread_mutex_unlock(&table_lock);
		return (-1);
	}
	log_msg(LOG_NOTICE, "server %s moved: %s to %s", id, old, uri);
	hosts_forget(old);
	free(old);
	return (0);
}

/*
 * The rollback timer of the server reached at uri: the seconds a change
 * made in safe mode waits to be confirmed there: the server's own, else
 * Settings' for every host, else 0 for the agent's own.
 */
int
servers_safe_wait(const char *uri)
{
	char	*all;
	int	 i, k;

	k = 0;
	pthread_mutex_lock(&table_lock);
	for (i = 0; uri != NULL && i < nservers; i++)
		if (strcmp(servers[i].uri, uri) == 0) {
			k = servers[i].safe_wait;
			break;
		}
	pthread_mutex_unlock(&table_lock);
	if (k == 0 && (all = settings_peek("safe_wait")) != NULL) {
		k = atoi(all);
		if (k < SAFE_WAIT_MIN || k > SAFE_WAIT_MAX)
			k = 0;
		free(all);
	}
	return (k);
}

/* SHA-256 of a token, hex, in out (65 bytes). */
static void
token_hash(const char *token, char *out)
{
	uint8_t		md[32];
	unsigned int	len;

	EVP_Digest(token, strlen(token), md, &len, EVP_sha256(), NULL);
	for (size_t k = 0; k < sizeof(md); k++)
		snprintf(out + 2 * k, 3, "%02x", md[k]);
}

/*
 * A new receiver token for the server id, in token (65 bytes): 32
 * random bytes in hex, its hash alone kept in place of the one before.
 * ENOENT: no such server; an errno of the store otherwise.
 */
int
servers_notif_token_new(const char *id, char *token, size_t len)
{
	uint8_t	raw[32];
	char	hash[65];
	int	i, error;

	if (len < 65)
		return (EINVAL);
	arc4random_buf(raw, sizeof(raw));
	for (size_t k = 0; k < sizeof(raw); k++)
		snprintf(token + 2 * k, 3, "%02x", raw[k]);
	explicit_bzero(raw, sizeof(raw));
	token_hash(token, hash);
	pthread_mutex_lock(&table_lock);
	for (i = 0; i < nservers && strcmp(servers[i].id, id) != 0; i++)
		;
	if (i == nservers) {
		pthread_mutex_unlock(&table_lock);
		explicit_bzero(token, len);
		return (ENOENT);
	}
	free(servers[i].notif_token);
	servers[i].notif_token = xstrdup(hash);
	error = save() == 0 ? 0 : EIO;
	pthread_mutex_unlock(&table_lock);
	return (error);
}

/* Whether token is the server id's: its hash, compared whole. */
bool
servers_notif_token_check(const char *id, const char *token)
{
	char	hash[65];
	int	i;
	bool	ok = false;

	if (token == NULL || strlen(token) != 64)
		return (false);
	token_hash(token, hash);
	pthread_mutex_lock(&table_lock);
	for (i = 0; i < nservers; i++)
		if (strcmp(servers[i].id, id) == 0) {
			ok = servers[i].notif_token != NULL &&
			    timingsafe_bcmp(servers[i].notif_token, hash, 64) ==
			    0;
			break;
		}
	pthread_mutex_unlock(&table_lock);
	return (ok);
}

const struct server *
server_find(const char *id)
{
	int	i;

	for (i = 0; i < nservers; i++)
		if (strcmp(servers[i].id, id) == 0)
			return (&servers[i]);
	return (NULL);
}

/* The i-th server, or NULL past the last: to go through them. */
const struct server *
server_at(int i)
{

	return (i >= 0 && i < nservers ? &servers[i] : NULL);
}

static ucl_object_t *
server_object(const struct server *s, bool kept)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(s->id), "id", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(s->name), "name", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(s->uri), "uri", 0,
	    false);
	if (s->peer_name != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(s->peer_name),
		    "peer_name", 0, false);
	if (s->tenant != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(s->tenant),
		    "tenant", 0, false);
	ucl_object_insert_key(o, ucl_object_frombool(strncmp(s->uri,
	    "unix:", 5) == 0), "local", 0, false);
	if (s->safe_wait > 0)
		ucl_object_insert_key(o, ucl_object_fromint(s->safe_wait),
		    "safe_wait", 0, false);
	if (s->pkg_repos != NULL)
		ucl_object_insert_key(o, ucl_object_ref(s->pkg_repos),
		    "pkg_repos", 0, false);
	/* The token's hash is the file's; the API says there is one. */
	if (kept && s->notif_token != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(s->notif_token),
		    "notif_token", 0, false);
	else if (!kept)
		ucl_object_insert_key(o, ucl_object_frombool(s->notif_token !=
		    NULL), "notif_token", 0, false);
	return (o);
}

static int
save(void)
{
	ucl_object_t	*doc, *a;
	int		 i, rc;

	doc = ucl_object_typed_new(UCL_OBJECT);
	a = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nservers; i++)
		ucl_array_append(a, server_object(&servers[i], true));
	ucl_object_insert_key(doc, a, "servers", 0, false);
	ucl_object_insert_key(doc, ucl_object_frombool(local_done),
	    "local_done", 0, false);
	rc = store_save(SERVERS, doc);
	ucl_object_unref(doc);
	return (rc);
}

/* GET: the list, the hosts the user has a role on, with it.  POST
 * {name, uri, peer_name?, tenant?}: add one. */
int
api_servers(struct http_request *req)
{
	ucl_object_t	*o, *a, *body, *so;
	const char	*name, *uri, *peer, *tenant, *u;
	char		 id[9];
	int		 i;

	if (!guard(req, req->method != HTTP_METHOD_GET))
		return (WEB_OK);
	if (req->method == HTTP_METHOD_POST) {
		if ((body = read_json(req)) == NULL)
			return (reply_error(req, 400, "bad_request",
			    "expected a JSON object"));
		name = ucl_str(body, "name");
		uri = ucl_str(body, "uri");
		peer = ucl_str(body, "peer_name");
		tenant = ucl_str(body, "tenant");
		if (name == NULL || !valid_name(name) || uri == NULL ||
		    !valid_uri(uri) || (peer != NULL && (!valid_name(peer) ||
		    strchr(peer, ' ') != NULL))) {
			ucl_object_unref(body);
			return (reply_error(req, 400, "invalid", "a name and a "
			    "URI such as tcp://host:4310 or "
			    "unix:/var/run/arcana-agent.sock are needed"));
		}
		if (tenant != NULL && tenant[0] != '\0' && !user_name_ok(tenant)) {
			ucl_object_unref(body);
			return (reply_error(req, 400, "invalid", "a tenant is "
			    "named by letters, digits, _ . @ and -, 64 at most"));
		}
		if (nservers == MAX_SERVERS) {
			ucl_object_unref(body);
			return (reply_error(req, 409, "full",
			    "at most %d servers", MAX_SERVERS));
		}
		for (i = 0; i < nservers; i++) {
			if (strcmp(servers[i].uri, uri) == 0) {
				/* uri is the body's: the reply first. */
				reply_error(req, 409, "duplicate", "%s is already "
				    "%s", uri, servers[i].name);
				ucl_object_unref(body);
				return (WEB_OK);
			}
		}
		new_id(id, sizeof(id));
		add(id, name, uri, peer, tenant);
		ucl_object_unref(body);
		if (save() == -1)
			return (reply_error(req, 500, "store", "cannot save"));
		log_msg(LOG_NOTICE, "server %s added: %s", id,
		    servers[nservers - 1].uri);
	}
	/* The agent beside the console may have come up since. */
	local_enrol();
	u = session_user(req);
	a = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nservers; i++) {
		if (u != NULL && user_host(u, servers[i].id) == ROLE_NONE)
			continue;
		so = server_object(&servers[i], false);
		if (u != NULL)
			ucl_object_insert_key(so, ucl_object_fromstring(role_name(
			    user_host(u, servers[i].id))), "role", 0, false);
		ucl_array_append(a, so);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, a, "servers", 0, false);
	/* added, removed, absent (not running), denied (not reachable). */
	ucl_object_insert_key(o, ucl_object_fromstring(local_state), "local",
	    0, false);
	if (cfg.local_agent != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(
		    cfg.local_agent), "local_agent", 0, false);
	return (reply_json(req, 200, o));
}

/*
 * DELETE /api/servers/<id>; POST {safe_wait}: its rollback timer, the
 * seconds a change made in safe mode there waits to be confirmed before
 * the agent undoes it, 0 for the agent's own (-w); {tenant}; {pkg_repos}.
 */
int
api_server(struct http_request *req)
{
	ucl_object_t	*body;
	const ucl_object_t *v;
	char		 id[16];
	int		 i, was;
	int64_t		 k;

	if (!guard(req, true))
		return (WEB_OK);
	if (!capture(req, 3, id, sizeof(id)))
		return (reply_error(req, 400, "bad_request", "bad server id"));
	for (i = 0; i < nservers; i++)
		if (strcmp(servers[i].id, id) == 0)
			break;
	if (i == nservers)
		return (reply_error(req, 404, "not_found", "no such server"));
	if (!host_allowed(req, id, true, true))
		return (WEB_OK);
	if (req->method == HTTP_METHOD_POST) {
		if ((body = read_json(req)) == NULL)
			return (reply_error(req, 400, "bad_request",
			    "expected a JSON object"));
		/* {tenant}: the fleet it is in, "" for none. */
		if ((v = ucl_object_lookup(body, "tenant")) != NULL) {
			const char	*t = ucl_object_tostring(v);

			if (t == NULL || (t[0] != '\0' && !user_name_ok(t))) {
				ucl_object_unref(body);
				return (reply_error(req, 400, "invalid", "a tenant "
				    "is named by letters, digits, _ . @ and -, 64 "
				    "at most"));
			}
			pthread_mutex_lock(&table_lock);
			free(servers[i].tenant);
			servers[i].tenant = t[0] != '\0' ? xstrdup(t) : NULL;
			pthread_mutex_unlock(&table_lock);
			if (ucl_object_lookup(body, "safe_wait") == NULL) {
				char	tenant[80];

				/* t is the body's. */
				strlcpy(tenant, t[0] != '\0' ? t : "none",
				    sizeof(tenant));
				ucl_object_unref(body);
				if (save() == -1)
					return (reply_error(req, 500, "store",
					    "cannot save"));
				log_msg(LOG_NOTICE, "server %s: tenant %s", id,
				    tenant);
				req->method = HTTP_METHOD_GET;
				return (api_servers(req));
			}
		}
		/*
		 * {pkg_repos: {"<jail>" or ".": {upgrade, install, base}}}:
		 * which of pkg's repositories each action takes packages
		 * from there, per jail ("." the host), "" or absent for
		 * any; kept whole, as given.
		 */
		if ((v = ucl_object_lookup(body, "pkg_repos")) != NULL) {
			const ucl_object_t	*jo, *ao;
			ucl_object_iter_t	 jit, ait;
			ucl_object_t		*keep;

			if (ucl_object_type(v) != UCL_OBJECT) {
				ucl_object_unref(body);
				return (reply_error(req, 400, "invalid",
				    "pkg_repos is an object: a jail's name, or "
				    ". for the host, to {upgrade, install, "
				    "base}"));
			}
			jit = NULL;
			while ((jo = ucl_object_iterate(v, &jit, true)) != NULL) {
				const char	*jn = ucl_object_key(jo);

				if (jn == NULL || strlen(jn) > 64 ||
				    ucl_object_type(jo) != UCL_OBJECT) {
					ucl_object_unref(body);
					return (reply_error(req, 400, "invalid",
					    "pkg_repos: a jail's name, 64 at "
					    "most, to an object"));
				}
				ait = NULL;
				while ((ao = ucl_object_iterate(jo, &ait, true)) !=
				    NULL) {
					const char	*an = ucl_object_key(ao);

					if (an == NULL || (strcmp(an, "upgrade") !=
					    0 && strcmp(an, "install") != 0 &&
					    strcmp(an, "base") != 0) ||
					    ucl_object_type(ao) != UCL_STRING ||
					    strlen(ucl_object_tostring(ao)) > 64) {
						ucl_object_unref(body);
						return (reply_error(req, 400,
						    "invalid", "pkg_repos: upgrade, "
						    "install or base, each a "
						    "repository's name, 64 at most"));
					}
				}
			}
			keep = ucl_object_ref(v);
			pthread_mutex_lock(&table_lock);
			if (servers[i].pkg_repos != NULL)
				ucl_object_unref(servers[i].pkg_repos);
			servers[i].pkg_repos = keep;
			pthread_mutex_unlock(&table_lock);
			if (ucl_object_lookup(body, "safe_wait") == NULL) {
				ucl_object_unref(body);
				if (save() == -1)
					return (reply_error(req, 500, "store",
					    "cannot save"));
				log_msg(LOG_NOTICE, "server %s: pkg repositories "
				    "chosen", id);
				req->method = HTTP_METHOD_GET;
				return (api_servers(req));
			}
		}
		v = ucl_object_lookup(body, "safe_wait");
		k = v != NULL && ucl_object_type(v) == UCL_INT ?
		    ucl_object_toint(v) : -1;
		ucl_object_unref(body);
		if (k != 0 && (k < SAFE_WAIT_MIN || k > SAFE_WAIT_MAX))
			return (reply_error(req, 400, "invalid", "safe_wait is "
			    "0, the agent's own, or %d to %d seconds",
			    SAFE_WAIT_MIN, SAFE_WAIT_MAX));
		pthread_mutex_lock(&table_lock);
		was = servers[i].safe_wait;
		servers[i].safe_wait = (int)k;
		pthread_mutex_unlock(&table_lock);
		if (save() == -1) {
			pthread_mutex_lock(&table_lock);
			servers[i].safe_wait = was;
			pthread_mutex_unlock(&table_lock);
			return (reply_error(req, 500, "store", "cannot save"));
		}
		log_msg(LOG_NOTICE, "server %s: rollback timer %d s", id,
		    (int)k);
		req->method = HTTP_METHOD_GET;
		return (api_servers(req));
	}
	log_msg(LOG_NOTICE, "server %s removed: %s", id, servers[i].uri);
	hosts_forget(servers[i].uri);
	pthread_mutex_lock(&table_lock);
	free(servers[i].name);
	free(servers[i].uri);
	free(servers[i].peer_name);
	free(servers[i].tenant);
	free(servers[i].notif_token);
	if (servers[i].pkg_repos != NULL)
		ucl_object_unref(servers[i].pkg_repos);
	memmove(&servers[i], &servers[i + 1],
	    (size_t)(nservers - i - 1) * sizeof(servers[0]));
	nservers--;
	pthread_mutex_unlock(&table_lock);
	if (save() == -1)
		return (reply_error(req, 500, "store", "cannot save"));
	req->method = HTTP_METHOD_GET;
	return (api_servers(req));
}

/*
 * POST /api/servers/<id>/move {"uri": "tcp://address:port"}: the host
 * reached at another address.  The agent is asked, where it is reached
 * now, to listen on the new one too; the new one is tried on a
 * connection of its own; only when it answers is the server moved, and
 * then the old listener closed, by the new way, and the change kept in
 * the host's rc.conf.  When the new one does not answer, or the move
 * cannot be saved, the agent closes the new listener again: the host is
 * reached as before.
 */
struct mv {
	struct task task;		/* first */
	int		 stage;		/* MV_* */
	char		 sid[16];
	char		 from[256];
	char		 to[256];
	char		 peer[256];
	char		 name[128];
	bool		 ok;
	char		 error[600];
	char		 note[400];
};

enum { MV_TRY, MV_DROP, MV_BACK };

/* What an agent's answer said went wrong, or NULL when it went right. */
static const char *
mv_why(const char *json, int status, char *buf, size_t len)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	const ucl_object_t	*e;

	o = NULL;
	if (json != NULL) {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_string(p, json, 0))
			o = ucl_parser_get_object(p);
		ucl_parser_free(p);
	}
	if (status == 200 && o != NULL && ((e = ucl_object_lookup(o, "ok")) ==
	    NULL || ucl_object_toboolean(e)) && ((e = ucl_object_lookup(o,
	    "error")) == NULL || ucl_object_type(e) == UCL_NULL)) {
		ucl_object_unref(o);
		return (NULL);
	}
	e = o != NULL ? ucl_object_lookup(o, "error") : NULL;
	if (e != NULL && ucl_object_type(e) == UCL_OBJECT)
		e = ucl_object_lookup(e, "message");
	snprintf(buf, len, "%s", e != NULL && ucl_object_type(e) ==
	    UCL_STRING ? ucl_object_tostring(e) : status == 0 ? "no answer" :
	    "it did not say why");
	if (o != NULL)
		ucl_object_unref(o);
	return (buf);
}

static int
mv_run(struct task *t)
{
	struct mv	*m = (struct mv *)t;
	char		*json, why[400];
	const char	*e;
	int		 status;

	switch (m->stage) {
	case MV_TRY:
		json = hosts_listen(m->from, m->peer, m->name, m->to, NULL,
		    false, &status);
		e = mv_why(json, status, why, sizeof(why));
		free(json);
		if (e != NULL) {
			snprintf(m->error, sizeof(m->error), "The agent did not "
			    "listen on %s: %s. Nothing changed.", m->to, e);
			break;
		}
		json = hosts_read(m->to, m->peer, m->name, "hello", &status);
		e = mv_why(json, status, why, sizeof(why));
		free(json);
		if (e == NULL) {
			m->ok = true;
			break;
		}
		snprintf(m->error, sizeof(m->error), "It does not answer at "
		    "%s (%s): the host is reached as before", m->to, e);
		json = hosts_listen(m->from, m->peer, m->name, NULL, m->to,
		    false, &status);
		if ((e = mv_why(json, status, why, sizeof(why))) != NULL)
			snprintf(m->note, sizeof(m->note), "The agent still "
			    "listens on %s as well: %s", m->to, e);
		free(json);
		break;
	case MV_DROP:
		/* By the new way: the old listener closed, the new kept. */
		json = hosts_listen(m->to, m->peer, m->name, m->to, m->from,
		    true, &status);
		if ((e = mv_why(json, status, why, sizeof(why))) != NULL)
			snprintf(m->note, sizeof(m->note), "Moved; but the "
			    "agent still listens on %s, or did not keep %s in "
			    "rc.conf: %s", m->from, m->to, e);
		free(json);
		break;
	case MV_BACK:
		json = hosts_listen(m->from, m->peer, m->name, NULL, m->to,
		    false, &status);
		if ((e = mv_why(json, status, why, sizeof(why))) != NULL)
			snprintf(m->note, sizeof(m->note), "The agent still "
			    "listens on %s as well: %s", m->to, e);
		free(json);
		break;
	}
	return (WEB_OK);
}

static void
mv_start(struct http_request *req, struct mv *m, int stage)
{

	m->stage = stage;
	task_create(&m->task, mv_run);
	task_bind_request(&m->task, req);
	task_run(&m->task);
}

int
api_server_move(struct http_request *req)
{
	const struct server	*s;
	struct mv		*m;
	ucl_object_t		*body, *top;
	const char		*to;
	char			 id[16];

	if ((m = req->hdlr_extra) != NULL) {
		if (task_state(&m->task) != TASK_STATE_FINISHED) {
			http_request_sleep(req);
			return (WEB_RETRY);
		}
		if (m->stage == MV_TRY && m->ok) {
			task_destroy(&m->task);
			if (servers_move(m->sid, m->to) == -1) {
				m->ok = false;
				snprintf(m->error, sizeof(m->error), "It answers "
				    "at %s, but the console could not keep the "
				    "change: the host is reached as before",
				    m->to);
				mv_start(req, m, MV_BACK);
			} else
				mv_start(req, m, MV_DROP);
			return (WEB_RETRY);
		}
		top = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(top, ucl_object_frombool(m->ok), "ok", 0,
		    false);
		ucl_object_insert_key(top, ucl_object_fromstring(m->ok ? m->to :
		    m->from), "uri", 0, false);
		if (!m->ok)
			ucl_object_insert_key(top, ucl_object_fromstring(m->error),
			    "error", 0, false);
		if (m->note[0] != '\0')
			ucl_object_insert_key(top, ucl_object_fromstring(m->note),
			    "note", 0, false);
		log_msg(LOG_NOTICE, "server %s: move to %s: %s", m->sid, m->to,
		    m->ok ? "done" : m->error);
		return (reply_json(req, 200, top));
	}
	if (!guard(req, true))
		return (WEB_OK);
	if (!capture(req, 3, id, sizeof(id)) || (s = server_find(id)) == NULL)
		return (reply_error(req, 404, "not_found", "no such server"));
	if (!host_allowed(req, id, true, true))
		return (WEB_OK);
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "a JSON object: uri"));
	to = ucl_str(body, "uri");
	if (to == NULL || (strncmp(to, "tcp://", 6) != 0 && strncmp(to,
	    "sctp://", 7) != 0) || !valid_uri(to) || strlen(to) >= 256) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "uri is tcp:// or "
		    "sctp://, an address and a port"));
	}
	if ((strncmp(s->uri, "tcp://", 6) != 0 && strncmp(s->uri, "sctp://",
	    7) != 0) || strcmp(s->uri, to) == 0) {
		/* to is the body's: the reply first. */
		reply_error(req, 400, "invalid", strcmp(s->uri, to) == 0 ?
		    "it is reached there already" : "a host reached by its "
		    "local socket is not moved");
		ucl_object_unref(body);
		return (WEB_OK);
	}
	m = xcalloc(1, sizeof(*m));
	snprintf(m->sid, sizeof(m->sid), "%s", s->id);
	snprintf(m->from, sizeof(m->from), "%s", s->uri);
	snprintf(m->to, sizeof(m->to), "%s", to);
	snprintf(m->peer, sizeof(m->peer), "%s", s->peer_name != NULL ?
	    s->peer_name : "");
	snprintf(m->name, sizeof(m->name), "%s", s->name);
	ucl_object_unref(body);
	req->hdlr_extra = m;
	mv_start(req, m, MV_TRY);
	return (WEB_RETRY);
}

void
api_server_move_free(struct http_request *req)
{
	struct mv	*m = req->hdlr_extra;

	/* Asked while the task runs too: only once it is done. */
	if (m == NULL || !task_finished(&m->task))
		return;
	task_destroy(&m->task);
	free(m);
	req->hdlr_extra = NULL;
}
