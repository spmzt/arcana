/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console as the receiver of a host's configured subscription (RFC
 * 8639 section 2.5) over HTTPS-notif (draft-ietf-netconf-https-notif):
 * an agent GETs /api/notif/<host>/capabilities once and POSTs each
 * record, RFC 8040's notification JSON, to
 * /api/notif/<host>/relay-notification.  The agent shows its own
 * certificate from the console's CA: a request is taken when the
 * certificate verifies, names the host's role and the host (its
 * peer_name, or the host of its URI), on a TLS listener (server { }
 * with certfile); it is refused on a plain one.  The records are kept
 * as the host's, in notif/<host>.jsonl of the data directory, a record
 * a line, so that they outlive a restart of the console: one received
 * again after a replay (the same record, the same event time) is kept
 * once.  /api/servers/<host>/notifications reads them;
 * /api/servers/<host>/subscription says what to put in the host's
 * candidate for the console to be its receiver (the endpoints under
 * notif_base of web.conf, the origin by default), which RESTCONF's PUT
 * of /ietf-subscribed-notifications:subscriptions and
 * ietf-netconf:commit send it.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "console.h"

#define	NOTIF_DIR	"notif"
#define	NOTIF_MAX	(2 * 1024 * 1024)	/* a host's file; then halved */
#define	NOTIF_LINE_MAX	(256 * 1024)
#define	NOTIF_READ	500			/* records read at most */
#define	ROLE_AGENT	"urn:arcana:role:agent"
#define	CAPS	"{\"ietf-https-notif-transport:receiver-capabilities\":" \
		"{\"receiver-capability\":[\"urn:ietf:capability:" \
		"https-notif-receiver:encoding:json\"]}}"

static pthread_mutex_t	notif_lock = PTHREAD_MUTEX_INITIALIZER;

/* The host's id from /api/notif/<id>/..., or /api/servers/<id>/...;
 * false: none there. */
static bool
host_of(const char *path, const char *prefix, char *id, size_t len)
{
	const char	*p;
	size_t		 n;

	if (strncmp(path, prefix, strlen(prefix)) != 0)
		return (false);
	p = path + strlen(prefix);
	n = strcspn(p, "/");
	if (n == 0 || n >= len || n != strspn(p, "0123456789abcdef"))
		return (false);
	memcpy(id, p, n);
	id[n] = '\0';
	return (true);
}

/* Whether the certificate says the host's role, among its SAN URIs. */
static bool
cert_is_agent(X509 *x)
{
	GENERAL_NAMES	*v;
	GENERAL_NAME	*g;
	const char	*s;
	bool		 ok = false;

	if ((v = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL)) == NULL)
		return (false);
	for (int i = 0; !ok && i < sk_GENERAL_NAME_num(v); i++) {
		g = sk_GENERAL_NAME_value(v, i);
		if (g->type != GEN_URI)
			continue;
		s = (const char *)ASN1_STRING_get0_data(g->d.uniformResourceIdentifier);
		ok = s != NULL && (size_t)ASN1_STRING_length(
		    g->d.uniformResourceIdentifier) == strlen(ROLE_AGENT) &&
		    strncmp(s, ROLE_AGENT, strlen(ROLE_AGENT)) == 0;
	}
	GENERAL_NAMES_free(v);
	return (ok);
}

/*
 * The agent of host id, by its certificate: verified by the console's
 * CA (web.c), of the host's role, and named as the host is known: its
 * peer_name, else the host of its URI.  On failure the reply has been
 * sent.
 */
static bool
agent_of(struct http_request *req, const char *id)
{
	const struct server	*s;
	X509			*x;
	char			 host[256];
	bool			 ok;

	if ((s = server_find(id)) == NULL) {
		reply_error(req, 404, "not_found", "no such host");
		return (false);
	}
	if ((x = web_peer_cert(req)) == NULL) {
		reply_error(req, 401, "certificate", "a receiver is reached "
		    "over TLS with the host's certificate from the console's CA");
		return (false);
	}
	host[0] = '\0';
	if (s->peer_name != NULL)
		snprintf(host, sizeof(host), "%s", s->peer_name);
	else if (strncmp(s->uri, "tcp://", 6) == 0 || strncmp(s->uri,
	    "sctp://", 7) == 0) {
		const char	*h = strstr(s->uri, "://") + 3, *e;

		if (*h == '[' && (e = strchr(h, ']')) != NULL)
			snprintf(host, sizeof(host), "%.*s", (int)(e - h - 1),
			    h + 1);
		else
			snprintf(host, sizeof(host), "%.*s", (int)strcspn(h,
			    ":/"), h);
	}
	ok = cert_is_agent(x) && host[0] != '\0' && (X509_check_host(x, host,
	    0, 0, NULL) == 1 || X509_check_ip_asc(x, host, 0) == 1);
	X509_free(x);
	if (!ok) {
		log_msg(LOG_WARNING, "notif: a record for %s from a certificate "
		    "not the host's%s", s->name, host[0] == '\0' ? " (the host "
		    "has no peer_name, and its URI no host)" : "");
		reply_error(req, 403, "certificate", "the certificate is not "
		    "this host's");
		return (false);
	}
	return (true);
}

static void
notif_path(char *buf, size_t len, const char *id)
{

	snprintf(buf, len, "%s/" NOTIF_DIR "/%s.jsonl", cfg.datadir, id);
}

/* GET /api/notif/<host>/capabilities: JSON is what the console takes. */
int
api_notif_capabilities(struct http_request *req)
{
	char	id[17];

	if (!host_of(req->path, "/api/notif/", id, sizeof(id)) ||
	    !agent_of(req, id))
		return (WEB_OK);
	http_response_header(req, "content-type",
	    "application/yang-data+json");
	http_response_header(req, "cache-control", "no-store");
	http_response(req, 200, CAPS, strlen(CAPS));
	return (WEB_OK);
}

/*
 * The record appended to the host's file, a line; the file halved at
 * its oldest when it is NOTIF_MAX; the same record as the last one
 * (a replay's) kept once.  0, or an errno.
 */
static int
record_keep(const char *id, const char *json, size_t len)
{
	struct stat	 sb;
	char		 path[MAXPATHLEN], dir[MAXPATHLEN], *buf, *nl;
	ssize_t		 n;
	int		 fd, error = 0;

	snprintf(dir, sizeof(dir), "%s/" NOTIF_DIR, cfg.datadir);
	notif_path(path, sizeof(path), id);
	pthread_mutex_lock(&notif_lock);
	(void)mkdir(dir, 0700);
	if ((fd = open(path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0600)) ==
	    -1) {
		pthread_mutex_unlock(&notif_lock);
		return (errno);
	}
	if (fstat(fd, &sb) == 0 && sb.st_size > 0 && sb.st_size <= NOTIF_MAX &&
	    (buf = malloc((size_t)sb.st_size + 1)) != NULL) {
		if ((n = pread(fd, buf, (size_t)sb.st_size, 0)) == sb.st_size) {
			buf[n] = '\0';
			/* The last line against the record. */
			if (n > 1 && buf[n - 1] == '\n') {
				buf[n - 1] = '\0';
				nl = strrchr(buf, '\n');
				nl = nl != NULL ? nl + 1 : buf;
				if (strlen(nl) == len && memcmp(nl, json, len) ==
				    0) {
					free(buf);
					close(fd);
					pthread_mutex_unlock(&notif_lock);
					return (0);
				}
			}
			/* Full: the newer half kept, whole lines. */
			if ((size_t)n + len + 1 > NOTIF_MAX && (nl = strchr(buf +
			    n / 2, '\n')) != NULL) {
				nl++;
				if (pwrite(fd, nl, (size_t)(buf + n - nl), 0) ==
				    buf + n - nl)
					(void)ftruncate(fd, buf + n - nl);
			}
		}
		free(buf);
	}
	if (write(fd, json, len) != (ssize_t)len || write(fd, "\n", 1) != 1)
		error = errno != 0 ? errno : EIO;
	close(fd);
	pthread_mutex_unlock(&notif_lock);
	return (error);
}

/* POST /api/notif/<host>/relay-notification: a record kept. */
int
api_notif_relay(struct http_request *req)
{
	ucl_object_t	*body;
	unsigned char	*json;
	char		 id[17];
	int		 error;

	if (!host_of(req->path, "/api/notif/", id, sizeof(id)) ||
	    !agent_of(req, id))
		return (WEB_OK);
	if ((body = read_json(req)) == NULL || ucl_object_lookup(body,
	    "ietf-restconf:notification") == NULL) {
		if (body != NULL)
			ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "a record is "
		    "{\"ietf-restconf:notification\": {\"eventTime\": ..., "
		    "...}}"));
	}
	/* As the console writes it: one line, the same each time. */
	json = ucl_object_emit(body, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(body);
	if (json == NULL || strlen((char *)json) > NOTIF_LINE_MAX) {
		free(json);
		return (reply_error(req, 413, "invalid", "too long a record"));
	}
	error = record_keep(id, (char *)json, strlen((char *)json));
	free(json);
	if (error != 0) {
		log_msg(LOG_ERR, "notif/%s.jsonl: %s", id, strerror(error));
		return (reply_error(req, 500, "store", "the record could not "
		    "be kept"));
	}
	http_response(req, 204, NULL, 0);
	return (WEB_OK);
}

/*
 * GET /api/servers/<id>/notifications[?after=n]: the records kept, the
 * newest NOTIF_READ at most, each with its number (its line's, from 1
 * since the file began), those after n alone: {"records": [{"n":, ...
 * the record}], "last": n}.
 */
int
api_notifications(struct http_request *req)
{
	struct ucl_parser	*p;
	ucl_object_t		*top, *arr, *o;
	const ucl_object_t	*rec;
	char			 id[17], path[MAXPATHLEN], *line = NULL;
	const char		*v;
	size_t			 cap = 0, n = 0, skip = 0;
	ssize_t			 len;
	uint64_t		 after = 0, total = 0;
	FILE			*fp;

	if (!host_of(req->path, "/api/servers/", id, sizeof(id)))
		return (reply_error(req, 404, "not_found", "no such host"));
	if (!guard(req, false) || !host_allowed(req, id, false, false))
		return (WEB_OK);
	if (http_argument_get_string(req, "after", &v) == WEB_OK)
		after = strtoull(v, NULL, 10);
	notif_path(path, sizeof(path), id);
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	pthread_mutex_lock(&notif_lock);
	if ((fp = fopen(path, "r")) != NULL) {
		/* The count first: the newest NOTIF_READ are given. */
		while ((len = getline(&line, &cap, fp)) > 0)
			total++;
		if (total > after + NOTIF_READ)
			skip = total - NOTIF_READ;
		if (skip < after)
			skip = after;
		rewind(fp);
		while ((len = getline(&line, &cap, fp)) > 0) {
			if (++n <= skip)
				continue;
			if (line[len - 1] == '\n')
				line[len - 1] = '\0';
			p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
			    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
			o = ucl_parser_add_string(p, line, 0) ?
			    ucl_parser_get_object(p) : NULL;
			ucl_parser_free(p);
			if (o == NULL)
				continue;
			rec = ucl_object_lookup(o, "ietf-restconf:notification");
			if (rec != NULL) {
				ucl_object_t *e = ucl_object_ref(rec);

				ucl_object_insert_key(e, ucl_object_fromint(
				    (int64_t)n), "n", 0, false);
				ucl_array_append(arr, e);
			}
			ucl_object_unref(o);
		}
		fclose(fp);
		free(line);
	}
	pthread_mutex_unlock(&notif_lock);
	ucl_object_insert_key(top, arr, "records", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)total), "last",
	    0, false);
	return (reply_json(req, 200, top));
}

/*
 * GET /api/servers/<id>/subscription: the subscriptions container to
 * put in the host's candidate for the console to be its receiver, as
 * RESTCONF's PUT takes it: the NETCONF stream, every event, replayed to
 * the console when it was away; the receiver instance the console's
 * endpoints for the host.
 */
int
api_subscription(struct http_request *req)
{
	ucl_object_t	*top, *subs, *sub, *rcvs, *rcv, *insts, *inst, *https,
			*ep, *list, *doc;
	const char	*base;
	char		 id[17], uri[512];

	if (!host_of(req->path, "/api/servers/", id, sizeof(id)))
		return (reply_error(req, 404, "not_found", "no such host"));
	if (!guard(req, false) || !host_allowed(req, id, false, false))
		return (WEB_OK);
	if ((base = cfg.notif_base != NULL ? cfg.notif_base : cfg.origin) ==
	    NULL || strncmp(base, "https://", 8) != 0)
		return (reply_error(req, 409, "config", "web.conf names no "
		    "https origin (or notif_base) the hosts reach the console "
		    "by"));
	sub = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(sub, ucl_object_fromint(1), "id", 0, false);
	ucl_object_insert_key(sub, ucl_object_fromstring("NETCONF"), "stream",
	    0, false);
	list = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(list, ucl_object_typed_new(UCL_NULL));
	ucl_object_insert_key(sub, list, "configured-replay", 0, false);
	rcv = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(rcv, ucl_object_fromstring("console"), "name", 0,
	    false);
	ucl_object_insert_key(rcv, ucl_object_fromstring("console"),
	    "ietf-subscribed-notif-receivers:receiver-instance-ref", 0, false);
	list = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(list, rcv);
	rcvs = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(rcvs, list, "receiver", 0, false);
	ucl_object_insert_key(sub, rcvs, "receivers", 0, false);
	list = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(list, sub);
	subs = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(subs, list, "subscription", 0, false);
	https = ucl_object_typed_new(UCL_OBJECT);
	snprintf(uri, sizeof(uri), "%s/api/notif/%s/capabilities", base, id);
	ep = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(ep, ucl_object_fromstring(uri), "uri", 0, false);
	ucl_object_insert_key(https, ep, "capabilities-endpoint", 0, false);
	snprintf(uri, sizeof(uri), "%s/api/notif/%s/relay-notification", base,
	    id);
	ep = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(ep, ucl_object_fromstring(uri), "uri", 0, false);
	ucl_object_insert_key(https, ep, "relay-notification-endpoint", 0,
	    false);
	inst = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(inst, ucl_object_fromstring("console"), "name", 0,
	    false);
	ucl_object_insert_key(inst, https,
	    "ietf-https-notif-transport:https-receiver", 0, false);
	list = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(list, inst);
	insts = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(insts, list, "receiver-instance", 0, false);
	ucl_object_insert_key(subs, insts,
	    "ietf-subscribed-notif-receivers:receiver-instances", 0, false);
	doc = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(doc, subs,
	    "ietf-subscribed-notifications:subscriptions", 0, false);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, doc, "candidate", 0, false);
	snprintf(uri, sizeof(uri), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s/ietf-subscribed-notifications:"
	    "subscriptions", id);
	ucl_object_insert_key(top, ucl_object_fromstring(uri), "put", 0, false);
	snprintf(uri, sizeof(uri), "/restconf/data/arcana-fleet:fleet/host=%s/"
	    "ietf-netconf:commit", id);
	ucl_object_insert_key(top, ucl_object_fromstring(uri), "commit", 0,
	    false);
	return (reply_json(req, 200, top));
}
