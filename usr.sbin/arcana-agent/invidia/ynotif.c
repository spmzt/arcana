/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: ietf-subscribed-notifications' subscriptions container: the
 * dynamic subscriptions cblink keeps (cbl_ysub.c) listed, and the
 * configured ones (RFC 8639 section 2.5) kept.  Those are running's:
 * the container whole in a file of its own (--subscriptions) as
 * YANG-CBOR, written by a commit (or an EDIT of running) and told to
 * cblink, which makes, changes and ends them, and told again at the
 * start.  Their receivers are HTTPS-notif's
 * (draft-ietf-netconf-https-notif, ietf-subscribed-notif-receivers and
 * ietf-https-notif-transport): a receiver names a receiver instance,
 * an https-receiver with its capabilities-endpoint and its
 * relay-notification-endpoint.  A receiver is connected by a GET of
 * the capabilities, which must say the receiver takes JSON; each record
 * is then a POST to the relay endpoint of RFC 8040's notification JSON
 * ({"ietf-restconf:notification": {"eventTime": ..., "module:name":
 * {...}}}), HTTP/1.1 on one TLS connection kept open, the agent's own
 * certificate and key shown (-C, -K), the CA of -A and the system's
 * trusted, and the instance's token (arcana-notif), where it has one,
 * sent as Authorization: Bearer.  A reply other than 2xx, or the
 * connection gone, is the receiver down: cblink connects it again
 * later and replays what it missed.  The console is the receiver
 * meant: it authenticates the agent by its certificate, or by the
 * token it handed the host, and keeps the records as the host's.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <cblink.h>
#include <cbl_data.h>
#include <cbl_schema.h>

#include "agent.h"
#include "ymodel.h"

#define	SUBS_FILE_MAX	(1024 * 1024)
#define	HTTP_TIMEOUT_S	15
#define	HTTP_BODY_MAX	(64 * 1024)	/* a reply's, at most */
#define	CAP_JSON	"urn:ietf:capability:https-notif-receiver:encoding:json"

typedef struct ietf_subscribed_notifications ysn;
typedef struct ietf_subscribed_notifications_subscriptions ysubs;
typedef struct ietf_subscribed_notifications_subscriptions_subscription
    ysubscription;
typedef struct ietf_subscribed_notifications_subscriptions_subscription_receivers
    yreceivers;
typedef struct ietf_subscribed_notifications_subscriptions_subscription_receivers_receiver
    yreceiver;
typedef struct ietf_subscribed_notifications_subscriptions_snr_receiver_instances_receiver_instance
    yinstance;
#define	YSUB(x)	IETF_SUBSCRIBED_NOTIFICATIONS_SUBSCRIPTIONS_SUBSCRIPTION_##x
#define	YINST(x) \
    IETF_SUBSCRIBED_NOTIFICATIONS_SUBSCRIPTIONS_SNR_RECEIVER_INSTANCES_RECEIVER_INSTANCE_##x

/* The configuration kept: the container's bytes, as the file has them;
 * cblink's context, told of them. */
static pthread_mutex_t	subs_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t		*kept;
static size_t		 keptlen;
static cbl_ctx		*subs_ctx;

static const struct cbl_ynode *
subs_node(void)
{

	return (ynode_named("ietf-subscribed-notifications", "subscriptions"));
}

/* The file's bytes, malloc'd; NULL and ENOENT where there is none. */
static uint8_t *
subs_read(size_t *lenp)
{
	struct stat	 sb;
	uint8_t		*p;
	ssize_t		 n;
	int		 fd;

	if ((fd = open(opts.subs_file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) ==
	    -1)
		return (NULL);
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size <= 0 ||
	    sb.st_size > SUBS_FILE_MAX || (p = malloc((size_t)sb.st_size)) ==
	    NULL) {
		(void)close(fd);
		errno = EIO;
		return (NULL);
	}
	if ((n = read(fd, p, (size_t)sb.st_size)) != sb.st_size) {
		free(p);
		(void)close(fd);
		errno = EIO;
		return (NULL);
	}
	(void)close(fd);
	*lenp = (size_t)n;
	return (p);
}

/* The bytes written whole in place of the file; none: the file gone. */
static int
subs_write(const uint8_t *p, size_t len)
{
	char	tmp[PATH_MAX];
	int	error, fd;

	if (p == NULL)
		return (unlink(opts.subs_file) == 0 || errno == ENOENT ? 0 :
		    errno);
	(void)snprintf(tmp, sizeof(tmp), "%s.arcana-new", opts.subs_file);
	error = 0;
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1)
		return (errno);
	if (write(fd, p, len) != (ssize_t)len || fsync(fd) != 0)
		error = errno != 0 ? errno : EIO;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && rename(tmp, opts.subs_file) != 0)
		error = errno;
	if (error != 0)
		(void)unlink(tmp);
	return (error);
}

/* The kept container decoded into a; NULL: none kept. */
static const ysubs *
kept_decode(cbl_yarena *a)
{
	ysn	 data;
	char	 why[160];
	int	 error;

	memset(&data, 0, sizeof(data));
	pthread_mutex_lock(&subs_lock);
	error = kept != NULL ? cbl_ydecode_member(subs_node(), kept, keptlen,
	    &data, a, 0, why, sizeof(why)) : ENOENT;
	pthread_mutex_unlock(&subs_lock);
	if (error != 0 && error != ENOENT)
		logmsg(LOG_ERR, "%s: %s", opts.subs_file, why);
	return (error == 0 ? data.subscriptions : NULL);
}

/*
 * An HTTPS URI: its host, port and path.  The scheme is https alone: a
 * receiver authenticates the agent by its certificate.
 */
struct uri {
	char	host[256];
	char	port[8];
	char	path[512];
};

static bool
uri_parse(const char *s, struct uri *u)
{
	const char	*h, *e, *p;
	size_t		 n;

	memset(u, 0, sizeof(*u));
	if (strncasecmp(s, "https://", 8) != 0)
		return (false);
	h = s + 8;
	if (*h == '[') {
		if ((e = strchr(h, ']')) == NULL)
			return (false);
		n = (size_t)(e - h - 1);
		if (n == 0 || n >= sizeof(u->host))
			return (false);
		memcpy(u->host, h + 1, n);
		e++;
	} else {
		n = strcspn(h, ":/?#");
		if (n == 0 || n >= sizeof(u->host))
			return (false);
		memcpy(u->host, h, n);
		e = h + n;
	}
	if (*e == ':') {
		n = strcspn(e + 1, "/?#");
		if (n == 0 || n >= sizeof(u->port) || strspn(e + 1,
		    "0123456789") < n)
			return (false);
		memcpy(u->port, e + 1, n);
		e += 1 + n;
	} else
		strlcpy(u->port, "443", sizeof(u->port));
	p = *e == '/' ? e : "/";
	n = strcspn(p, "#");
	if (n >= sizeof(u->path))
		return (false);
	memcpy(u->path, p, n);
	if (n > 1 && u->path[n - 1] == '/')
		u->path[n - 1] = '\0';
	return (true);
}

/* A TLS connection to a receiver's endpoint, HTTP/1.1 over it. */
struct hconn {
	int		 fd;
	SSL_CTX		*ctx;
	SSL		*ssl;
	struct uri	 u;
};

static void
hconn_close(struct hconn *c)
{

	if (c->ssl != NULL) {
		(void)SSL_shutdown(c->ssl);
		SSL_free(c->ssl);
	}
	if (c->ctx != NULL)
		SSL_CTX_free(c->ctx);
	if (c->fd != -1)
		(void)close(c->fd);
	c->ssl = NULL;
	c->ctx = NULL;
	c->fd = -1;
}

static const char *
ssl_err(void)
{
	const char	*s;

	s = ERR_reason_error_string(ERR_get_error());
	ERR_clear_error();
	return (s != NULL ? s : "TLS failed");
}

/*
 * Connected to u: the agent's certificate and key shown, the CA of -A
 * and the system's trusted, the host's name (or address) checked.  The
 * files are read anew each time: they are renewed while the agent runs.
 */
static int
hconn_open(struct hconn *c, const struct uri *u, char *err, size_t errlen)
{
	struct addrinfo	 hints, *res, *ai;
	struct timeval	 tv = { HTTP_TIMEOUT_S, 0 };
	unsigned char	 a[16];
	int		 error, on = 1;

	memset(c, 0, sizeof(*c));
	c->fd = -1;
	c->u = *u;
	if (tls_files_cert() == NULL || tls_files_key() == NULL ||
	    tls_files_ca() == NULL) {
		snprintf(err, errlen, "no certificate to show: the agent "
		    "runs without -A, -C and -K");
		return (ENOENT);
	}
	if ((c->ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
		snprintf(err, errlen, "%s", ssl_err());
		return (ENOMEM);
	}
	if (SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION) != 1 ||
	    SSL_CTX_use_certificate_chain_file(c->ctx, tls_files_cert()) != 1 ||
	    SSL_CTX_use_PrivateKey_file(c->ctx, tls_files_key(),
	    SSL_FILETYPE_PEM) != 1 || SSL_CTX_load_verify_locations(c->ctx,
	    tls_files_ca(), NULL) != 1) {
		snprintf(err, errlen, "the agent's TLS files: %s", ssl_err());
		hconn_close(c);
		return (EINVAL);
	}
	(void)SSL_CTX_set_default_verify_paths(c->ctx);
	SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((error = getaddrinfo(u->host, u->port, &hints, &res)) != 0) {
		snprintf(err, errlen, "%s: %s", u->host, gai_strerror(error));
		hconn_close(c);
		return (EHOSTUNREACH);
	}
	error = EHOSTUNREACH;
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		if ((c->fd = socket(ai->ai_family, ai->ai_socktype |
		    SOCK_CLOEXEC, ai->ai_protocol)) == -1)
			continue;
		(void)setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		(void)setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		(void)setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &on,
		    sizeof(on));
		if (connect(c->fd, ai->ai_addr, ai->ai_addrlen) == 0) {
			error = 0;
			break;
		}
		error = errno;
		(void)close(c->fd);
		c->fd = -1;
	}
	freeaddrinfo(res);
	if (error != 0) {
		snprintf(err, errlen, "%s port %s: %s", u->host, u->port,
		    strerror(error));
		hconn_close(c);
		return (error);
	}
	if ((c->ssl = SSL_new(c->ctx)) == NULL || SSL_set_fd(c->ssl, c->fd) !=
	    1) {
		snprintf(err, errlen, "%s", ssl_err());
		hconn_close(c);
		return (ENOMEM);
	}
	/* The name the certificate must have: the host's, an address as
	 * one of its addresses. */
	if (inet_pton(AF_INET, u->host, a) == 1 || inet_pton(AF_INET6, u->host,
	    a) == 1)
		(void)X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(c->ssl),
		    u->host);
	else {
		(void)SSL_set1_host(c->ssl, u->host);
		(void)SSL_set_tlsext_host_name(c->ssl,
		    (char *)(uintptr_t)u->host);
	}
	(void)SSL_set_alpn_protos(c->ssl, (const unsigned char *)"\x08http/1.1",
	    9);
	if (SSL_connect(c->ssl) != 1) {
		long	v = SSL_get_verify_result(c->ssl);

		snprintf(err, errlen, "%s port %s: %s", u->host, u->port,
		    v != X509_V_OK ? X509_verify_cert_error_string(v) :
		    ssl_err());
		hconn_close(c);
		return (ECONNREFUSED);
	}
	return (0);
}

static int
hconn_write(struct hconn *c, const void *p, size_t n)
{
	const char	*s = p;
	int		 w;

	while (n > 0) {
		if ((w = SSL_write(c->ssl, s, n > INT_MAX ? INT_MAX : (int)n)) <=
		    0)
			return (EPIPE);
		s += w;
		n -= (size_t)w;
	}
	return (0);
}

/*
 * One request, its reply: the status; its body (Content-Length's, up to
 * HTTP_BODY_MAX) in rbody when it is wanted; the token, where there is
 * one, as Authorization: Bearer.  The connection is for the next
 * request unless the reply says it closes.  EPIPE: the connection is
 * gone, or the reply was none.
 */
static int
http_do(struct hconn *c, const char *method, const char *path,
    const char *token, const char *ctype, const char *body, size_t blen,
    int *status, char *rbody, size_t rlen, bool *closes)
{
	char		 hdr[1024], *buf, *e, *l, *v;
	size_t		 cap = 4096, len = 0, hlen, clen = 0;
	int		 n, rc;
	bool		 chunked = false;

	n = snprintf(hdr, sizeof(hdr), "%s %s HTTP/1.1\r\nHost: %s\r\n"
	    "User-Agent: arcana-agent/%s\r\nAccept: application/yang-data+json"
	    "\r\n%s%s%s%s%s%s", method, path, c->u.host, ARCANA_AGENT_VERSION,
	    token != NULL ? "Authorization: Bearer " : "", token != NULL ?
	    token : "", token != NULL ? "\r\n" : "",
	    ctype != NULL ? "Content-Type: " : "", ctype != NULL ? ctype : "",
	    ctype != NULL ? "\r\n" : "");
	if (n < 0 || (size_t)n >= sizeof(hdr))
		return (ENAMETOOLONG);
	if (body != NULL)
		n += snprintf(hdr + n, sizeof(hdr) - (size_t)n,
		    "Content-Length: %zu\r\n", blen);
	if ((size_t)n + 2 >= sizeof(hdr))
		return (ENAMETOOLONG);
	memcpy(hdr + n, "\r\n", 3);
	n += 2;
	if ((rc = hconn_write(c, hdr, (size_t)n)) != 0 || (body != NULL &&
	    (rc = hconn_write(c, body, blen)) != 0))
		return (rc);
	/* The head, then as much of the body as is wanted. */
	if ((buf = malloc(cap)) == NULL)
		return (ENOMEM);
	*closes = false;
	for (;;) {
		buf[len] = '\0';
		if ((e = strstr(buf, "\r\n\r\n")) != NULL)
			break;
		if (len + 1 >= cap) {
			char	*nb;

			if (cap >= HTTP_BODY_MAX || (nb = realloc(buf, cap *
			    2)) == NULL) {
				free(buf);
				return (E2BIG);
			}
			buf = nb;
			cap *= 2;
		}
		if ((n = SSL_read(c->ssl, buf + len, (int)(cap - len - 1))) <=
		    0) {
			free(buf);
			return (EPIPE);
		}
		len += (size_t)n;
	}
	hlen = (size_t)(e + 4 - buf);
	if (sscanf(buf, "HTTP/1.%*d %d", status) != 1) {
		free(buf);
		return (EPIPE);
	}
	for (l = strchr(buf, '\n'); l != NULL && l < e; l = strchr(l + 1,
	    '\n')) {
		l++;
		if (strncasecmp(l, "content-length:", 15) == 0)
			clen = strtoul(l + 15, NULL, 10);
		else if (strncasecmp(l, "connection:", 11) == 0) {
			for (v = l + 11; *v == ' ' || *v == '\t'; v++)
				;
			if (strncasecmp(v, "close", 5) == 0)
				*closes = true;
		} else if (strncasecmp(l, "transfer-encoding:", 18) == 0 &&
		    strcasestr(l, "chunked") != NULL && strcasestr(l,
		    "chunked") < e)
			chunked = true;
	}
	/* A chunked body is not read: the connection is let go after. */
	if (chunked || clen > HTTP_BODY_MAX) {
		*closes = true;
		clen = 0;
	}
	while (len - hlen < clen) {
		if (len + 1 >= cap) {
			char	*nb;

			if ((nb = realloc(buf, hlen + clen + 1)) == NULL) {
				free(buf);
				return (ENOMEM);
			}
			buf = nb;
			cap = hlen + clen + 1;
		}
		if ((n = SSL_read(c->ssl, buf + len, (int)(cap - len - 1))) <=
		    0) {
			free(buf);
			return (EPIPE);
		}
		len += (size_t)n;
	}
	if (rbody != NULL)
		snprintf(rbody, rlen, "%.*s", (int)clen, buf + hlen);
	free(buf);
	return (0);
}

/* A receiver as the transport keeps it: its relay connection, and the
 * instance's token; none: "". */
struct rcv {
	struct hconn	 c;
	bool		 open;
	struct uri	 relay;
	char		 token[257];
};

/* The https-receiver of the instance named, from the kept
 * configuration decoded into a; NULL and why. */
static const yinstance *
instance_named(const ysubs *s, const char *name)
{
	const yinstance	*v;

	if (s == NULL || s->snr_receiver_instances == NULL || name == NULL)
		return (NULL);
	v = s->snr_receiver_instances->receiver_instance.v;
	for (size_t i = 0; i < s->snr_receiver_instances->receiver_instance.n;
	    i++)
		if (strcmp(v[i].name, name) == 0)
			return (&v[i]);
	return (NULL);
}

/*
 * cblink's connect: the capabilities read from the instance's endpoint,
 * JSON among them; the connection kept for the relay endpoint where it
 * is the same host's, else one opened to it.
 */
static int
rcv_connect(struct cbl_ysub_rcv *r, void *arg)
{
	const yinstance	*in;
	const ysubs	*s;
	struct rcv	*rc;
	struct uri	 cap;
	cbl_yarena	*a;
	char		 err[256], body[HTTP_BODY_MAX];
	int		 error, status;
	bool		 closes;

	(void)arg;
	if ((rc = r->arg) == NULL) {
		if ((rc = calloc(1, sizeof(*rc))) == NULL)
			return (ENOMEM);
		rc->c.fd = -1;
		r->arg = rc;
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	s = kept_decode(a);
	if ((in = instance_named(s, r->instance)) == NULL ||
	    in->hnt_https_receiver == NULL ||
	    in->hnt_https_receiver->capabilities_endpoint == NULL ||
	    in->hnt_https_receiver->relay_notification_endpoint == NULL ||
	    !uri_parse(in->hnt_https_receiver->capabilities_endpoint->uri,
	    &cap) || !uri_parse(
	    in->hnt_https_receiver->relay_notification_endpoint->uri,
	    &rc->relay)) {
		cbl_yarena_free(a);
		logmsg(LOG_WARNING, "subscription %u: receiver %s: no https "
		    "receiver instance %s", r->id, r->name, r->instance !=
		    NULL ? r->instance : "(none)");
		return (ENOENT);
	}
	strlcpy(rc->token, in->hnt_https_receiver->arcnf_token != NULL ?
	    in->hnt_https_receiver->arcnf_token : "", sizeof(rc->token));
	cbl_yarena_free(a);
	if ((error = hconn_open(&rc->c, &cap, err, sizeof(err))) != 0) {
		logmsg(LOG_WARNING, "subscription %u: receiver %s: %s", r->id,
		    r->name, err);
		return (error);
	}
	if ((error = http_do(&rc->c, "GET", cap.path[0] != '\0' ? cap.path :
	    "/", rc->token[0] != '\0' ? rc->token : NULL, NULL, NULL, 0,
	    &status, body, sizeof(body), &closes)) != 0) {
		hconn_close(&rc->c);
		logmsg(LOG_WARNING, "subscription %u: receiver %s: no "
		    "capabilities from %s: %s", r->id, r->name, cap.host,
		    strerror(error));
		return (error);
	}
	if (status != 200 || strstr(body, CAP_JSON) == NULL) {
		hconn_close(&rc->c);
		logmsg(LOG_WARNING, "subscription %u: receiver %s: %s "
		    "answered %d to the capabilities%s", r->id, r->name,
		    cap.host, status, status == 200 ? ", without JSON among "
		    "them" : "");
		return (EPROTONOSUPPORT);
	}
	if (closes || strcmp(cap.host, rc->relay.host) != 0 ||
	    strcmp(cap.port, rc->relay.port) != 0) {
		hconn_close(&rc->c);
		if ((error = hconn_open(&rc->c, &rc->relay, err, sizeof(err))) !=
		    0) {
			logmsg(LOG_WARNING, "subscription %u: receiver %s: %s",
			    r->id, r->name, err);
			return (error);
		}
	}
	rc->open = true;
	logmsg(LOG_INFO, "subscription %u: receiver %s connected, %s port %s",
	    r->id, r->name, rc->relay.host, rc->relay.port);
	return (0);
}

/* yang:date-and-time of ts, in buf. */
static const char *
timestr(const struct timespec *ts, char *buf, size_t len)
{
	struct tm	tm;

	(void)gmtime_r(&ts->tv_sec, &tm);
	(void)strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm);
	return (buf);
}

/*
 * cblink's send: the record as RFC 8040's notification JSON, POSTed to
 * the relay endpoint; 2xx takes it.  Anything else is the receiver
 * down, the connection let go.
 */
static int
rcv_send(struct cbl_ysub_rcv *r, uint64_t sid, const uint8_t *content,
    size_t len, const struct timespec *when, void *arg)
{
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	const struct cbl_ynode	*n;
	struct rcv		*rc = r->arg;
	cbl_yarena		*a;
	void			*p;
	char			*json = NULL, tbuf[32], why[160];
	int			 error, status;
	bool			 closes;

	(void)arg;
	if (rc == NULL || !rc->open)
		return (EPIPE);
	if ((n = cbl_yschema_node(&ymodel_schema, sid)) == NULL)
		return (0);
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((p = cbl_yarena_alloc(a, n->size)) == NULL ||
	    (error = cbl_ydecode(n, content, len, p, a, 0, why, sizeof(why))) !=
	    0 || (error = cbl_yjson(n, p, &b)) != 0) {
		cbl_yarena_free(a);
		cbl_ybuf_free(&b);
		logmsg(LOG_ERR, "subscription %u: %s: not told: %s", r->id,
		    n->name, p == NULL ? "out of memory" : why);
		return (0);	/* not the receiver's fault */
	}
	cbl_yarena_free(a);
	if (asprintf(&json, "{\"ietf-restconf:notification\":{\"eventTime\":"
	    "\"%s\",\"%s:%s\":%.*s}}", timestr(when, tbuf, sizeof(tbuf)),
	    n->module->name, n->name, (int)b.len, (const char *)b.p) == -1)
		json = NULL;
	cbl_ybuf_free(&b);
	if (json == NULL)
		return (ENOMEM);
	error = http_do(&rc->c, "POST", rc->relay.path[0] != '\0' ?
	    rc->relay.path : "/", rc->token[0] != '\0' ? rc->token : NULL,
	    "application/yang-data+json", json, strlen(json), &status, NULL, 0,
	    &closes);
	free(json);
	if (error == 0 && (status < 200 || status > 299)) {
		logmsg(LOG_WARNING, "subscription %u: receiver %s answered %d "
		    "to a record", r->id, r->name, status);
		error = EPROTO;
	} else if (error != 0)
		logmsg(LOG_WARNING, "subscription %u: receiver %s: %s", r->id,
		    r->name, strerror(error));
	if (error != 0 || closes) {
		hconn_close(&rc->c);
		rc->open = false;
		/* The reply closes it: the next record opens it again. */
		if (error == 0 && hconn_open(&rc->c, &rc->relay, why,
		    sizeof(why)) == 0)
			rc->open = true;
	}
	return (error);
}

static void
rcv_disconnect(struct cbl_ysub_rcv *r, void *arg)
{
	struct rcv	*rc = r->arg;

	(void)arg;
	if (rc == NULL)
		return;
	hconn_close(&rc->c);
	rc->open = false;
	logmsg(LOG_INFO, "subscription %u: receiver %s disconnected", r->id,
	    r->name);
}

static const struct cbl_ysub_transport transport = {
	.connect = rcv_connect,
	.send = rcv_send,
	.disconnect = rcv_disconnect,
};

/* The configuration told to cblink; said for req where it refuses. */
static int
subs_tell(cbl_req *req, const ysn *data, char *why, size_t whylen)
{
	int	error;

	if ((error = cbl_ysub_configure(subs_ctx, subs_node(), data, why,
	    whylen)) != 0 && req != NULL)
		(void)cbl_req_set_yerr(req, why, subs_node()->sid);
	return (error);
}

int
ysubs_init(cbl_ctx *ctx)
{
	ysn		 data;
	cbl_yarena	*a;
	char		 why[160];
	int		 error;

	subs_ctx = ctx;
	(void)cbl_ysub_set_transport(ctx, &transport, NULL);
	pthread_mutex_lock(&subs_lock);
	kept = subs_read(&keptlen);
	pthread_mutex_unlock(&subs_lock);
	if (kept == NULL) {
		if (errno != ENOENT)
			logmsg(LOG_ERR, "%s: cannot be read: no configured "
			    "subscriptions", opts.subs_file);
		return (0);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&data, 0, sizeof(data));
	if ((error = cbl_ydecode_member(subs_node(), kept, keptlen, &data, a,
	    CBL_YD_STRICT, why, sizeof(why))) != 0 ||
	    (error = subs_tell(NULL, &data, why, sizeof(why))) != 0) {
		/* What is kept is kept: fixed by the next commit. */
		logmsg(LOG_ERR, "%s: %s: the configured subscriptions are "
		    "not made", opts.subs_file, why);
		error = 0;
	} else if (data.subscriptions != NULL)
		logmsg(LOG_INFO, "%zu configured subscription%s",
		    data.subscriptions->subscription.n,
		    data.subscriptions->subscription.n == 1 ? "" : "s");
	cbl_yarena_free(a);
	return (error);
}

static const char *
ystr(cbl_yarena *a, const char *s)
{
	char	*p;

	if (s == NULL || (p = cbl_yarena_alloc(a, strlen(s) + 1)) == NULL)
		return (NULL);
	memcpy(p, s, strlen(s) + 1);
	return (p);
}

/*
 * A subtree filter, as the subscriptions list's anydata name holds it
 * (its keys are deltas from that node's SID), into *out in a.
 */
static int
ysubtree(cbl_yarena *a, const struct cbl_dfilter *f, const char *name,
    struct cbl_bytes *out)
{
	const struct cbl_ynode	*e = NULL, *n = NULL;
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	void			*p;
	int			 error;

	for (uint32_t i = 0; subs_node() != NULL && i < subs_node()->nchild;
	    i++)
		if (strcmp(subs_node()->child[i]->name, "subscription") == 0)
			e = subs_node()->child[i];
	for (uint32_t i = 0; e != NULL && i < e->nchild; i++)
		if (strcmp(e->child[i]->name, name) == 0)
			n = e->child[i];
	if (n == NULL)
		return (0);
	if ((error = cbl_dfilter_encode(f, n->sid, &b)) == 0) {
		if ((p = cbl_yarena_alloc(a, b.len)) == NULL)
			error = ENOMEM;
		else {
			memcpy(p, b.p, b.len);
			out->p = p;
			out->len = b.len;
		}
	}
	cbl_ybuf_free(&b);
	return (error);
}

struct ylist {
	cbl_yarena	*a;
	const ysubs	*cfg;		/* what is kept, or NULL */
	ysubscription	*v;
	size_t		 n, cap;
};

/*
 * One of cblink's subscriptions, into the arena: a dynamic one from
 * what cblink says of it; a configured one its kept entry, the
 * receivers' state and counts cblink's.
 */
static int
ysub_one(const struct cbl_ysub_info *in, void *arg)
{
	struct ietf_subscribed_notifications_subscriptions_subscription_yp_periodic
	    *per;
	struct ietf_subscribed_notifications_subscriptions_subscription_yp_on_change
	    *oc;
	struct ylist		*ys = arg;
	const ysubscription	*k = NULL;
	ysubscription		*v, *s;
	yreceivers		*rs;
	yreceiver		*r;
	size_t			 nr;
	int			 error;

	if (ys->n == ys->cap) {
		if ((v = cbl_yarena_alloc(ys->a, (ys->cap + 8) *
		    sizeof(*v))) == NULL)
			return (ENOMEM);
		if (ys->n > 0)
			memcpy(v, ys->v, ys->n * sizeof(*v));
		ys->v = v;
		ys->cap += 8;
	}
	s = &ys->v[ys->n];
	memset(s, 0, sizeof(*s));
	for (size_t i = 0; in->configured && ys->cfg != NULL &&
	    i < ys->cfg->subscription.n; i++)
		if (ys->cfg->subscription.v[i].id == in->id)
			k = &ys->cfg->subscription.v[i];
	if (k != NULL) {
		*s = *k;
		s->has_configured_subscription_state = true;
		s->configured_subscription_state = in->concluded ?
		    YSUB(CONFIGURED_SUBSCRIPTION_STATE_CONCLUDED) :
		    YSUB(CONFIGURED_SUBSCRIPTION_STATE_VALID);
	}
	nr = k != NULL ? in->nrcvs : 1;
	if ((rs = cbl_yarena_alloc(ys->a, sizeof(*rs))) == NULL ||
	    (r = cbl_yarena_alloc(ys->a, (nr > 0 ? nr : 1) * sizeof(*r))) ==
	    NULL)
		return (ENOMEM);
	memset(r, 0, (nr > 0 ? nr : 1) * sizeof(*r));
	if (k != NULL) {
		for (size_t i = 0; i < nr; i++) {
			const yreceiver	*kr = NULL;

			for (size_t j = 0; k->receivers != NULL && j <
			    k->receivers->receiver.n; j++)
				if (strcmp(k->receivers->receiver.v[j].name,
				    in->rcvs[i].name) == 0)
					kr = &k->receivers->receiver.v[j];
			if (kr != NULL)
				r[i] = *kr;
			else
				r[i].name = ystr(ys->a, in->rcvs[i].name);
			r[i].has_sent_event_records = true;
			r[i].sent_event_records = in->rcvs[i].sent;
			r[i].has_excluded_event_records = true;
			r[i].excluded_event_records = in->rcvs[i].excluded;
			r[i].has_state = true;
			r[i].state = in->rcvs[i].state == CBL_YSUB_RCV_ACTIVE ?
			    YSUB(RECEIVERS_RECEIVER_STATE_ACTIVE) :
			    in->rcvs[i].state == CBL_YSUB_RCV_SUSPENDED ?
			    YSUB(RECEIVERS_RECEIVER_STATE_SUSPENDED) :
			    YSUB(RECEIVERS_RECEIVER_STATE_CONNECTING);
		}
		rs->receiver.n = nr;
		rs->receiver.v = r;
		s->receivers = rs;
		ys->n++;
		return (0);
	}
	s->id = in->id;
	if (in->stream != NULL) {
		s->target = YSUB(TARGET_STREAM);
		s->stream = ystr(ys->a, in->stream);
		if (in->xpath != NULL) {
			s->stream_filter =
			    YSUB(STREAM_FILTER_WITHIN_SUBSCRIPTION);
			s->filter_spec = YSUB(FILTER_SPEC_STREAM_XPATH_FILTER);
			s->stream_xpath_filter = ystr(ys->a, in->xpath);
		} else if (in->subtree != NULL) {
			s->stream_filter =
			    YSUB(STREAM_FILTER_WITHIN_SUBSCRIPTION);
			s->filter_spec =
			    YSUB(FILTER_SPEC_STREAM_SUBTREE_FILTER);
			if ((error = ysubtree(ys->a, in->subtree,
			    "stream-subtree-filter",
			    &s->stream_subtree_filter)) != 0)
				return (error);
		}
	} else {
		s->target = YSUB(TARGET_DATASTORE);
		s->has_yp_datastore = true;
		s->yp_datastore = in->datastore;
		if (in->xpath != NULL) {
			s->yp_selection_filter =
			    YSUB(YP_SELECTION_FILTER_WITHIN_SUBSCRIPTION);
			s->yp_filter_spec =
			    YSUB(YP_FILTER_SPEC_DATASTORE_XPATH_FILTER);
			s->yp_datastore_xpath_filter = ystr(ys->a, in->xpath);
		} else if (in->subtree != NULL) {
			s->yp_selection_filter =
			    YSUB(YP_SELECTION_FILTER_WITHIN_SUBSCRIPTION);
			s->yp_filter_spec =
			    YSUB(YP_FILTER_SPEC_DATASTORE_SUBTREE_FILTER);
			if ((error = ysubtree(ys->a, in->subtree,
			    "datastore-subtree-filter",
			    &s->yp_datastore_subtree_filter)) != 0)
				return (error);
		}
		if (in->on_change) {
			if ((oc = cbl_yarena_alloc(ys->a, sizeof(*oc))) ==
			    NULL)
				return (ENOMEM);
			memset(oc, 0, sizeof(*oc));
			oc->has_dampening_period = true;
			oc->dampening_period = in->dampening;
			s->yp_update_trigger = YSUB(YP_UPDATE_TRIGGER_ON_CHANGE);
			s->yp_on_change = oc;
		} else {
			if ((per = cbl_yarena_alloc(ys->a, sizeof(*per))) ==
			    NULL)
				return (ENOMEM);
			per->has_period = true;
			per->period = in->period;
			per->anchor_time = ystr(ys->a, in->anchor_time);
			s->yp_update_trigger = YSUB(YP_UPDATE_TRIGGER_PERIODIC);
			s->yp_periodic = per;
		}
	}
	s->stop_time = ystr(ys->a, in->stop_time);
	r->name = in->receiver != NULL ? ystr(ys->a, in->receiver) :
	    "the subscriber";
	r->has_sent_event_records = true;
	r->sent_event_records = in->sent;
	r->has_excluded_event_records = true;
	r->excluded_event_records = in->excluded;
	r->has_state = true;
	r->state = in->suspended ? YSUB(RECEIVERS_RECEIVER_STATE_SUSPENDED) :
	    YSUB(RECEIVERS_RECEIVER_STATE_ACTIVE);
	rs->receiver.n = 1;
	rs->receiver.v = r;
	s->receivers = rs;
	ys->n++;
	return (0);
}

/* The subscriptions: cblink's, dynamic and configured, with the kept
 * receiver instances. */
int
ietf_subscribed_notifications_subscriptions_get(cbl_req *req,
    struct ietf_subscribed_notifications *data, cbl_yarena *a)
{
	struct ylist	 ys;
	ysubs		*ss;
	int		 error;

	(void)req;
	memset(&ys, 0, sizeof(ys));
	ys.a = a;
	ys.cfg = kept_decode(a);
	if (subs_ctx != NULL && (error = cbl_ysub_each(subs_ctx, ysub_one,
	    &ys)) != 0)
		return (error);
	if (ys.n == 0 && (ys.cfg == NULL || ys.cfg->snr_receiver_instances ==
	    NULL))
		return (0);
	if ((ss = cbl_yarena_alloc(a, sizeof(*ss))) == NULL)
		return (ENOMEM);
	memset(ss, 0, sizeof(*ss));
	ss->subscription.n = ys.n;
	ss->subscription.v = ys.v;
	if (ys.cfg != NULL)
		ss->snr_receiver_instances = ys.cfg->snr_receiver_instances;
	data->subscriptions = ss;
	return (0);
}

/* What is wrong with the container as it is to be; NULL: nothing. */
static const char *
subs_check(const ysubs *s, uint64_t *sidp)
{
	const yinstance	*in;
	struct uri	 u;

	*sidp = 0;
	if (s == NULL)
		return (NULL);
	if (s->snr_receiver_instances != NULL)
		for (size_t i = 0; i <
		    s->snr_receiver_instances->receiver_instance.n; i++) {
			in = &s->snr_receiver_instances->receiver_instance.v[i];
			if (in->transport_type != YINST(TRANSPORT_TYPE_HTTPS) ||
			    in->hnt_https_receiver == NULL)
				return ("a receiver instance is an https-receiver "
				    "(ietf-https-notif-transport)");
			if (in->hnt_https_receiver->capabilities_endpoint ==
			    NULL || in->hnt_https_receiver->
			    relay_notification_endpoint == NULL)
				return ("an https-receiver has its "
				    "capabilities-endpoint and its "
				    "relay-notification-endpoint");
			if (!uri_parse(in->hnt_https_receiver->
			    capabilities_endpoint->uri, &u) || !uri_parse(
			    in->hnt_https_receiver->relay_notification_endpoint->
			    uri, &u))
				return ("an endpoint's uri is https://host"
				    "[:port]/path");
		}
	for (size_t i = 0; i < s->subscription.n; i++) {
		const ysubscription	*e = &s->subscription.v[i];

		if (e->receivers == NULL || e->receivers->receiver.n == 0)
			return ("a configured subscription has a receiver");
		for (size_t j = 0; j < e->receivers->receiver.n; j++) {
			const yreceiver	*r = &e->receivers->receiver.v[j];

			if (r->snr_receiver_instance_ref == NULL ||
			    instance_named(s, r->snr_receiver_instance_ref) ==
			    NULL)
				return ("a receiver names a receiver instance "
				    "(receiver-instance-ref)");
		}
	}
	return (NULL);
}

/*
 * The container written whole, in place of the file, and told to
 * cblink; refused as cblink or the check says.  None: the file gone,
 * the subscriptions ended.
 */
int
ietf_subscribed_notifications_subscriptions_edit(cbl_req *req,
    const struct ietf_subscribed_notifications *before,
    const struct ietf_subscribed_notifications *after)
{
	struct cbl_ybuf	 b = { NULL, 0, 0 };
	const char	*what;
	uint8_t		*old;
	size_t		 oldlen;
	uint64_t	 sid;
	char		 why[160];
	int		 error;

	(void)before;
	if (subs_ctx == NULL)
		return (EOPNOTSUPP);
	if ((what = subs_check(after->subscriptions, &sid)) != NULL) {
		(void)cbl_req_set_yerr(req, what, sid);
		return (EINVAL);
	}
	if (after->subscriptions != NULL && (error = cbl_yencode_member(
	    subs_node(), after, &b)) != 0)
		return (error);
	/* Kept first: the transport reads the instances from it. */
	pthread_mutex_lock(&subs_lock);
	old = kept;
	oldlen = keptlen;
	kept = b.p;
	keptlen = b.len;
	pthread_mutex_unlock(&subs_lock);
	if ((error = subs_tell(req, after, why, sizeof(why))) == 0 &&
	    (error = subs_write(b.p, b.len)) != 0) {
		(void)cbl_req_set_yerr(req, strerror(error), 0);
		logmsg(LOG_ERR, "%s: %s", opts.subs_file, strerror(error));
	}
	if (error != 0) {
		pthread_mutex_lock(&subs_lock);
		kept = old;
		keptlen = oldlen;
		pthread_mutex_unlock(&subs_lock);
		cbl_ybuf_free(&b);
		return (error);
	}
	free(old);
	logmsg(LOG_NOTICE, "%s: the configured subscriptions written",
	    opts.subs_file);
	return (0);
}

/* A receiver's reset: connected anew. */
int
ietf_subscribed_notifications_subscriptions_subscription_receivers_receiver_reset_action(
    cbl_req *req, const struct cbl_bytes *target,
    const struct ietf_subscribed_notifications_subscriptions_subscription_receivers_receiver_reset_input
    *in,
    struct ietf_subscribed_notifications_subscriptions_subscription_receivers_receiver_reset_output
    *out, cbl_yarena *a)
{
	const struct cbl_ynode	*n;
	const void		**vals;
	struct timespec		 now;
	size_t			 nvals;
	char			*t;

	(void)in;
	if (subs_ctx == NULL || cbl_yiid_read(&ymodel_schema, target, &n,
	    &vals, &nvals, a) != 0 || nvals != 2) {
		(void)cbl_req_set_yerr(req, "a receiver of a subscription", 0);
		return (EINVAL);
	}
	if (cbl_ysub_reset(subs_ctx, *(const uint32_t *)vals[0],
	    *(const char *const *)vals[1]) != 0) {
		(void)cbl_req_set_yerr(req, "no such receiver of a configured "
		    "subscription", 0);
		return (ENOENT);
	}
	(void)clock_gettime(CLOCK_REALTIME, &now);
	if ((t = cbl_yarena_alloc(a, 32)) == NULL)
		return (ENOMEM);
	out->time = timestr(&now, t, 32);
	return (0);
}
