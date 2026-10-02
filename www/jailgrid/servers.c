/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The jailgridd instances the console knows: a name and a cblink URI,
 * "unix:/var/run/jailgridd.sock" for this host or "tcp://host:4310" for
 * others, with the certificate name to expect when it differs from the
 * host.  Kept in servers.json in the data directory.
 */

#include <sys/types.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jgweb.h"

#define	SERVERS		"servers.json"
#define	MAX_SERVERS	64

static struct server	servers[MAX_SERVERS];
static int		nservers;

static bool	valid_name(const char *);
static bool	valid_uri(const char *);
static int	save(void);
static ucl_object_t *server_object(const struct server *);
static void	add(const char *, const char *, const char *, const char *);
static void	new_id(char *, size_t);

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
add(const char *id, const char *name, const char *uri, const char *peer)
{
	struct server	*s;

	s = &servers[nservers++];
	strlcpy(s->id, id, sizeof(s->id));
	s->name = kore_strdup(name);
	s->uri = kore_strdup(uri);
	s->peer_name = peer != NULL && *peer != '\0' ? kore_strdup(peer) :
	    NULL;
}

void
servers_init(void)
{
	const ucl_object_t	*a, *o;
	ucl_object_t		*doc;
	ucl_object_iter_t	 it;
	const char		*id, *name, *uri;

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
		add(id, name, uri, ucl_str(o, "peer_name"));
	}
	ucl_object_unref(doc);
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
	add(id, name, uri, peer);
	if (save() == -1)
		return (-1);
	kore_log(LOG_NOTICE, "server %s added: %s", id, uri);
	return (0);
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

static ucl_object_t *
server_object(const struct server *s)
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
	ucl_object_insert_key(o, ucl_object_frombool(strncmp(s->uri,
	    "unix:", 5) == 0), "local", 0, false);
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
		ucl_array_append(a, server_object(&servers[i]));
	ucl_object_insert_key(doc, a, "servers", 0, false);
	rc = store_save(SERVERS, doc);
	ucl_object_unref(doc);
	return (rc);
}

/* GET: the list.  POST {name, uri, peer_name?}: add one. */
int
api_servers(struct http_request *req)
{
	ucl_object_t	*o, *a, *body;
	const char	*name, *uri, *peer;
	char		 id[9];
	int		 i;

	if (!guard(req, req->method != HTTP_METHOD_GET))
		return (KORE_RESULT_OK);
	if (req->method == HTTP_METHOD_POST) {
		if ((body = read_json(req)) == NULL)
			return (reply_error(req, 400, "bad_request",
			    "expected a JSON object"));
		name = ucl_str(body, "name");
		uri = ucl_str(body, "uri");
		peer = ucl_str(body, "peer_name");
		if (name == NULL || !valid_name(name) || uri == NULL ||
		    !valid_uri(uri) || (peer != NULL && (!valid_name(peer) ||
		    strchr(peer, ' ') != NULL))) {
			ucl_object_unref(body);
			return (reply_error(req, 400, "invalid", "a name and a "
			    "URI such as tcp://host:4310 or "
			    "unix:/var/run/jailgridd.sock are needed"));
		}
		if (nservers == MAX_SERVERS) {
			ucl_object_unref(body);
			return (reply_error(req, 409, "full",
			    "at most %d servers", MAX_SERVERS));
		}
		for (i = 0; i < nservers; i++) {
			if (strcmp(servers[i].uri, uri) == 0) {
				ucl_object_unref(body);
				return (reply_error(req, 409, "duplicate",
				    "%s is already %s", uri, servers[i].name));
			}
		}
		new_id(id, sizeof(id));
		add(id, name, uri, peer);
		ucl_object_unref(body);
		if (save() == -1)
			return (reply_error(req, 500, "store", "cannot save"));
		kore_log(LOG_NOTICE, "server %s added: %s", id,
		    servers[nservers - 1].uri);
	}
	a = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nservers; i++)
		ucl_array_append(a, server_object(&servers[i]));
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, a, "servers", 0, false);
	return (reply_json(req, 200, o));
}

/* DELETE /api/servers/<id> */
int
api_server(struct http_request *req)
{
	char	id[16];
	int	i;

	if (!guard(req, true))
		return (KORE_RESULT_OK);
	if (!capture(req, 3, id, sizeof(id)))
		return (reply_error(req, 400, "bad_request", "bad server id"));
	for (i = 0; i < nservers; i++)
		if (strcmp(servers[i].id, id) == 0)
			break;
	if (i == nservers)
		return (reply_error(req, 404, "not_found", "no such server"));
	kore_log(LOG_NOTICE, "server %s removed: %s", id, servers[i].uri);
	kore_free(servers[i].name);
	kore_free(servers[i].uri);
	kore_free(servers[i].peer_name);
	memmove(&servers[i], &servers[i + 1],
	    (size_t)(nservers - i - 1) * sizeof(servers[0]));
	nservers--;
	if (save() == -1)
		return (reply_error(req, 500, "store", "cannot save"));
	req->method = HTTP_METHOD_GET;
	return (api_servers(req));
}
