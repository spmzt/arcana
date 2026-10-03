/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Notifications to the devices that asked for them, by Web Push: a
 * task that ends in one browser is told to the others, a phone say,
 * whether or not the console is open there.
 *
 * A browser subscribes with its push service and gives the console the
 * address to post to and its keys.  The console keeps those in
 * push.json, and its own key, which the push services know it by
 * (VAPID), in vapid.pem, both in the data directory.  A message is
 * encrypted for each subscription (webpush.c) and posted to its
 * address over HTTPS, from a task thread.  A push service that says a
 * subscription is gone has it dropped.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "console.h"
#include "webpush.h"

#define	PUSH_FILE	"push.json"
#define	VAPID_FILE	"vapid.pem"
#define	PUSH_MAX	16		/* devices */
#define	PUSH_TIMEOUT	15		/* s, for a push service to answer */

struct target {
	char	*endpoint;
	uint8_t	*p256dh;
	uint8_t	*auth;
	int	 status;		/* what the push service said; 0 none */
	char	 said[201];		/* and in words, when it refused */
};

struct send {
	struct kore_task	 task;		/* first: Kore frees the send */
	struct target		 targets[PUSH_MAX];
	size_t			 ntargets;
	char			*payload;
};

static EVP_PKEY		*vapid;
static char		*vapid_pub;	/* base64url, for the browsers */
static ucl_object_t	*subs;		/* {"subscriptions": [...]} */

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, false);
}

static ucl_object_t *
sub_list(void)
{

	return ((ucl_object_t *)(uintptr_t)ucl_object_lookup(subs,
	    "subscriptions"));
}

/* The key the push services know this console by; made once. */
int
push_init(void)
{
	unsigned char	*pub;
	char		 path[1024];
	FILE		*fp;
	size_t		 publen;
	int		 fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, VAPID_FILE);
	if ((fp = fopen(path, "r")) != NULL) {
		vapid = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
		fclose(fp);
	}
	if (vapid == NULL) {
		if ((vapid = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")) ==
		    NULL)
			return (-1);
		(void)unlink(path);
		if ((fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600)) == -1 ||
		    (fp = fdopen(fd, "w")) == NULL) {
			kore_log(LOG_ERR, "%s: %s", path, strerror(errno));
			return (-1);
		}
		PEM_write_PrivateKey(fp, vapid, NULL, NULL, 0, NULL, NULL);
		fclose(fp);
	}
	if ((publen = EVP_PKEY_get1_encoded_public_key(vapid, &pub)) != 65)
		return (-1);
	vapid_pub = wp_b64url(pub, publen);
	OPENSSL_free(pub);
	if ((subs = store_load(PUSH_FILE)) == NULL || sub_list() == NULL) {
		subs = ucl_object_typed_new(UCL_OBJECT);
		put(subs, "subscriptions", ucl_object_typed_new(UCL_ARRAY));
	}
	return (vapid_pub != NULL ? 0 : -1);
}

/* The host of an "https://host[:443]/path" address, and its path. */
static bool
endpoint_parse(const char *url, char *host, size_t hostlen, const char **path)
{
	const char	*p, *e;
	size_t		 n;

	if (strncmp(url, "https://", 8) != 0)
		return (false);
	/* It goes into a request line: no space, nothing that ends one. */
	for (p = url; *p != '\0'; p++)
		if ((unsigned char)*p <= 0x20 || *p == 0x7f)
			return (false);
	p = url + 8;
	e = p + strcspn(p, "/:");
	n = (size_t)(e - p);
	if (n == 0 || n >= hostlen)
		return (false);
	memcpy(host, p, n);
	host[n] = '\0';
	for (p = host; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-')
			return (false);
	if (*e == ':') {
		if (strncmp(e, ":443/", 5) != 0)
			return (false);
		e += 4;
	}
	if (*e != '/')
		return (false);
	*path = e;
	return (true);
}

/* A connection to host's port 443, made within the time allowed. */
static int
connect_to(const char *host)
{
	struct addrinfo	 hints, *res, *ai;
	struct timeval	 tv = { PUSH_TIMEOUT, 0 };
	struct pollfd	 pfd;
	socklen_t	 len;
	int		 fd, flags, error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, "443", &hints, &res) != 0)
		return (-1);
	fd = -1;
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		if ((fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
		    ai->ai_protocol)) == -1)
			continue;
		flags = fcntl(fd, F_GETFL);
		(void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
		error = 0;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
			pfd.fd = fd;
			pfd.events = POLLOUT;
			len = sizeof(error);
			if (errno != EINPROGRESS || poll(&pfd, 1, PUSH_TIMEOUT *
			    1000) != 1 || getsockopt(fd, SOL_SOCKET, SO_ERROR,
			    &error, &len) == -1)
				error = -1;
		}
		if (error == 0) {
			/* From here on it waits, but never for long. */
			(void)fcntl(fd, F_SETFL, flags);
			(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv,
			    sizeof(tv));
			(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv,
			    sizeof(tv));
			break;
		}
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return (fd);
}

/*
 * POST body to an HTTPS address with the headers given; the status the
 * server answers with, or -1.  The certificate is checked against the
 * system's and the name asked for.  In a task thread: it waits, for
 * the connection, the handshake and the answer, each for a time.
 */
static int
https_post(const char *url, const char *headers, const uint8_t *body,
    size_t len, char *said, size_t saidlen)
{
	SSL_CTX		*ctx;
	SSL		*ssl;
	const char	*path;
	char		 host[256], *req, line[1024], *b;
	int		 n, status, fd, reqlen;

	status = -1;
	said[0] = '\0';
	ssl = NULL;
	fd = -1;
	if (!endpoint_parse(url, host, sizeof(host), &path) ||
	    (ctx = SSL_CTX_new(TLS_client_method())) == NULL)
		return (-1);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	if (SSL_CTX_set_default_verify_paths(ctx) != 1 ||
	    (fd = connect_to(host)) == -1 || (ssl = SSL_new(ctx)) == NULL ||
	    SSL_set_tlsext_host_name(ssl, host) != 1 ||
	    SSL_set1_host(ssl, host) != 1 || SSL_set_fd(ssl, fd) != 1 ||
	    SSL_connect(ssl) != 1)
		goto out;
	if ((reqlen = asprintf(&req, "POST %s HTTP/1.1\r\nHost: %s\r\n%s"
	    "Content-Length: %zu\r\nConnection: close\r\n\r\n", path, host,
	    headers, len)) == -1)
		goto out;
	if (SSL_write(ssl, req, reqlen) == reqlen && (len == 0 ||
	    SSL_write(ssl, body, (int)len) == (int)len) &&
	    (n = SSL_read(ssl, line, sizeof(line) - 1)) > 12) {
		line[n] = '\0';
		if (strncmp(line, "HTTP/1.", 7) == 0)
			status = atoi(line + 9);
		/* What it says besides, when it refuses: its reason. */
		if (status >= 300 && (b = strstr(line, "\r\n\r\n")) != NULL)
			snprintf(said, saidlen, "%.200s", b + 4);
	}
	free(req);
out:
	ERR_clear_error();
	if (ssl != NULL) {
		(void)SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (fd != -1)
		close(fd);
	SSL_CTX_free(ctx);
	return (status);
}

/* In a task thread: the message, to each device in turn. */
static int
send_run(struct kore_task *t)
{
	struct send	*s;
	struct target	*tg;
	const char	*path;
	char		 host[256], aud[280], contact[300], *auth, *headers;
	uint8_t		*body;
	size_t		 i, len;

	s = (struct send *)t;
	for (i = 0; i < s->ntargets; i++) {
		tg = &s->targets[i];
		if (!endpoint_parse(tg->endpoint, host, sizeof(host), &path))
			continue;
		snprintf(aud, sizeof(aud), "https://%s", host);
		/*
		 * Whom the push service may write to about this sender: an
		 * https address or a mailbox, nothing else is taken.
		 */
		if (strncmp(cfg.origin, "https://", 8) == 0)
			snprintf(contact, sizeof(contact), "%s", cfg.origin);
		else
			snprintf(contact, sizeof(contact), "mailto:arcana@%s",
			    strcmp(cfg.rp_id, "localhost") == 0 ?
			    "localhost.localdomain" : cfg.rp_id);
		auth = wp_vapid(vapid, aud, contact, time(NULL));
		if (auth == NULL || wp_encrypt(tg->p256dh, tg->auth, NULL, NULL,
		    (const uint8_t *)s->payload, strlen(s->payload), &body,
		    &len) != 0) {
			free(auth);
			continue;
		}
		if (asprintf(&headers, "TTL: 86400\r\nUrgency: normal\r\n"
		    "Content-Encoding: aes128gcm\r\nContent-Type: "
		    "application/octet-stream\r\nAuthorization: %s\r\n",
		    auth) != -1) {
			tg->status = https_post(tg->endpoint, headers, body,
			    len, tg->said, sizeof(tg->said));
			free(headers);
		}
		free(auth);
		free(body);
	}
	return (KORE_RESULT_OK);
}

static void
send_free(struct send *s)
{
	size_t	i;

	for (i = 0; i < s->ntargets; i++) {
		free(s->targets[i].endpoint);
		free(s->targets[i].p256dh);
		free(s->targets[i].auth);
	}
	s->ntargets = 0;
	free(s->payload);
	s->payload = NULL;
}

/*
 * The request is going away, answered or given up by its browser: what
 * the send held is released, once its task has ended.
 */
void
api_push_free(struct http_request *req)
{
	struct send	*s;

	if ((s = req->hdlr_extra) != NULL && kore_task_finished(&s->task))
		send_free(s);
}

/* Remove the subscription with this address; true if there was one. */
static bool
sub_remove(const char *endpoint)
{
	const ucl_object_t	*e;
	const char		*s;
	ucl_object_t		*list, *keep;
	ucl_object_iter_t	 it;
	bool			 found;

	keep = ucl_object_typed_new(UCL_ARRAY);
	found = false;
	it = NULL;
	while ((e = ucl_object_iterate(sub_list(), &it, true)) != NULL) {
		s = ucl_str(e, "endpoint");
		if (s != NULL && strcmp(s, endpoint) == 0)
			found = true;
		else
			ucl_array_append(keep, ucl_object_ref(
			    (ucl_object_t *)(uintptr_t)e));
	}
	list = ucl_object_typed_new(UCL_OBJECT);
	put(list, "subscriptions", keep);
	ucl_object_unref(subs);
	subs = list;
	return (found);
}

/*
 * GET /api/push: the key browsers subscribe with, and the devices that
 * have, by the name they gave and the push service they are at.
 */
int
api_push(struct http_request *req)
{
	const ucl_object_t	*e, *v;
	ucl_object_t		*o, *a, *d;
	ucl_object_iter_t	 it;
	const char		*path;
	char			 host[256];

	if (!guard(req, false))
		return (KORE_RESULT_OK);
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "public_key", ucl_object_fromstring(vapid_pub));
	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(sub_list(), &it, true)) != NULL) {
		d = ucl_object_typed_new(UCL_OBJECT);
		if ((v = ucl_object_lookup(e, "name")) != NULL)
			put(d, "name", ucl_object_fromstring(
			    ucl_object_tostring(v)));
		if ((v = ucl_object_lookup(e, "added")) != NULL)
			put(d, "added", ucl_object_fromint(ucl_object_toint(v)));
		if ((v = ucl_object_lookup(e, "endpoint")) != NULL) {
			put(d, "endpoint", ucl_object_fromstring(
			    ucl_object_tostring(v)));
			if (endpoint_parse(ucl_object_tostring(v), host,
			    sizeof(host), &path))
				put(d, "service", ucl_object_fromstring(host));
		}
		ucl_array_append(a, d);
	}
	put(o, "devices", a);
	return (reply_json(req, 200, o));
}

/*
 * POST /api/push/subscribe {"endpoint", "p256dh", "auth", "name"}: this
 * browser is to be told.  POST /api/push/unsubscribe {"endpoint"}: no
 * longer.
 */
int
api_push_subscribe(struct http_request *req)
{
	ucl_object_t		*body, *e;
	const char		*endpoint, *p256dh, *auth, *name, *path;
	char			 host[256];
	uint8_t			*raw;
	size_t			 len;
	bool			 remove;

	if (!guard(req, true))
		return (KORE_RESULT_OK);
	remove = strstr(req->path, "unsubscribe") != NULL;
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "a JSON body is "
		    "needed"));
	endpoint = ucl_str(body, "endpoint");
	if (endpoint == NULL || strlen(endpoint) > 1024 ||
	    !endpoint_parse(endpoint, host, sizeof(host), &path)) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "the address of a "
		    "push service is https://host/path"));
	}
	if (remove) {
		(void)sub_remove(endpoint);
		(void)store_save(PUSH_FILE, subs);
		ucl_object_unref(body);
		return (api_push_list(req));
	}
	p256dh = ucl_str(body, "p256dh");
	auth = ucl_str(body, "auth");
	if ((name = ucl_str(body, "name")) == NULL)
		name = "a browser";
	/* The keys have to be what they are said to be. */
	if (p256dh == NULL || (raw = wp_unb64url(p256dh, &len)) == NULL ||
	    len != 65 || raw[0] != 0x04) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "p256dh is not a "
		    "P-256 public key"));
	}
	free(raw);
	if (auth == NULL || (raw = wp_unb64url(auth, &len)) == NULL ||
	    len != 16) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "auth is not 16 "
		    "bytes"));
	}
	free(raw);
	/* The same browser again replaces what it had. */
	(void)sub_remove(endpoint);
	if (ucl_array_size(sub_list()) >= PUSH_MAX) {
		ucl_object_unref(body);
		return (reply_error(req, 409, "full", "%d devices are "
		    "subscribed already; remove one in Settings", PUSH_MAX));
	}
	e = ucl_object_typed_new(UCL_OBJECT);
	put(e, "endpoint", ucl_object_fromstring(endpoint));
	put(e, "p256dh", ucl_object_fromstring(p256dh));
	put(e, "auth", ucl_object_fromstring(auth));
	put(e, "name", ucl_object_fromlstring(name, strnlen(name, 80)));
	put(e, "added", ucl_object_fromint(time(NULL)));
	ucl_array_append(sub_list(), e);
	ucl_object_unref(body);
	if (store_save(PUSH_FILE, subs) == -1)
		return (reply_error(req, 500, "io", "cannot write %s",
		    PUSH_FILE));
	return (api_push_list(req));
}

/* The devices as they are now, for those who changed them. */
int
api_push_list(struct http_request *req)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "ok", ucl_object_frombool(true));
	put(o, "devices", ucl_object_fromint((int64_t)ucl_array_size(
	    sub_list())));
	return (reply_json(req, 200, o));
}

/*
 * POST /api/push/send {"title", "body", "except"}: tell every device
 * but the one at the address "except", which is the one that asks.
 */
int
api_push_send(struct http_request *req)
{
	ucl_object_t		*body, *o, *msg, *res, *one;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct send		*s;
	struct target		*tg;
	const char		*title, *text, *except, *ep, *k, *a, *path;
	char			 host[256];
	size_t			 i, len;
	int			 sent, gone;
	bool			 changed;

	if (req->hdlr_extra != NULL) {
		s = req->hdlr_extra;
		if (kore_task_state(&s->task) != KORE_TASK_STATE_FINISHED) {
			http_request_sleep(req);
			return (KORE_RESULT_RETRY);
		}
		/* 404 and 410: the browser has left; forget it. */
		sent = gone = 0;
		changed = false;
		for (i = 0; i < s->ntargets; i++) {
			if (s->targets[i].status >= 200 &&
			    s->targets[i].status < 300)
				sent++;
			else if (s->targets[i].status == 404 ||
			    s->targets[i].status == 410) {
				gone++;
				changed |= sub_remove(s->targets[i].endpoint);
			}
		}
		if (changed)
			(void)store_save(PUSH_FILE, subs);
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "ok", ucl_object_frombool(true));
		put(o, "sent", ucl_object_fromint(sent));
		put(o, "gone", ucl_object_fromint(gone));
		put(o, "failed", ucl_object_fromint((int64_t)s->ntargets -
		    sent - gone));
		/* What each push service said: 201 is taken, -1 no answer. */
		res = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < s->ntargets; i++) {
			one = ucl_object_typed_new(UCL_OBJECT);
			if (endpoint_parse(s->targets[i].endpoint, host,
			    sizeof(host), &path))
				put(one, "service", ucl_object_fromstring(host));
			put(one, "status", ucl_object_fromint(
			    s->targets[i].status));
			if (s->targets[i].said[0] != '\0')
				put(one, "said", ucl_object_fromstring(
				    s->targets[i].said));
			ucl_array_append(res, one);
		}
		put(o, "results", res);
		send_free(s);
		return (reply_json(req, 200, o));
	}
	if (!guard(req, true))
		return (KORE_RESULT_OK);
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "a JSON body is "
		    "needed"));
	if ((title = ucl_str(body, "title")) == NULL)
		title = "Arcana";
	if ((text = ucl_str(body, "body")) == NULL)
		text = "";
	if ((except = ucl_str(body, "except")) == NULL)
		except = "";
	s = kore_calloc(1, sizeof(*s));
	msg = ucl_object_typed_new(UCL_OBJECT);
	put(msg, "title", ucl_object_fromlstring(title, strnlen(title, 120)));
	put(msg, "body", ucl_object_fromlstring(text, strnlen(text, 600)));
	s->payload = (char *)ucl_object_emit(msg, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(msg);
	it = NULL;
	while ((e = ucl_object_iterate(sub_list(), &it, true)) != NULL &&
	    s->ntargets < PUSH_MAX) {
		ep = ucl_str(e, "endpoint");
		k = ucl_str(e, "p256dh");
		a = ucl_str(e, "auth");
		if (ep == NULL || k == NULL || a == NULL || strcmp(ep,
		    except) == 0)
			continue;
		tg = &s->targets[s->ntargets];
		tg->endpoint = strdup(ep);
		tg->p256dh = wp_unb64url(k, &len);
		tg->auth = wp_unb64url(a, &len);
		if (tg->endpoint == NULL || tg->p256dh == NULL ||
		    tg->auth == NULL) {
			free(tg->endpoint);
			free(tg->p256dh);
			free(tg->auth);
			continue;
		}
		s->ntargets++;
	}
	ucl_object_unref(body);
	if (s->ntargets == 0 || s->payload == NULL) {
		send_free(s);
		kore_free(s);
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "ok", ucl_object_frombool(true));
		put(o, "sent", ucl_object_fromint(0));
		return (reply_json(req, 200, o));
	}
	req->hdlr_extra = s;
	kore_task_create(&s->task, send_run);
	kore_task_bind_request(&s->task, req);
	kore_task_run(&s->task);
	return (KORE_RESULT_RETRY);
}
