/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A mail handed to a relay by SMTP (RFC 5321) itself, when Settings
 * name one: over TLS from the first byte (port 465, RFC 8314), after
 * STARTTLS (587, RFC 3207), or in the clear (25, a relay of one's own
 * network); the relay's certificate checked against the system's CAs
 * and its name; AUTH PLAIN (RFC 4954) with a user and password, only
 * over TLS.  Every read and write waits SMTP_WAIT_S at most, so that a
 * relay that does not answer holds the mail's thread that long and no
 * more.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "console.h"

#define	SMTP_WAIT_S	15
#define	SMTP_LINE	1024

struct conv {
	int	 fd;
	SSL_CTX	*ctx;
	SSL	*ssl;
	char	 buf[4096];
	size_t	 have;
	char	*err;
	size_t	 errlen;
};

static int
conv_write(struct conv *c, const char *s, size_t len)
{
	ssize_t	n;

	while (len > 0) {
		n = c->ssl != NULL ? SSL_write(c->ssl, s, (int)len) :
		    write(c->fd, s, len);
		if (n <= 0)
			return (-1);
		s += n;
		len -= (size_t)n;
	}
	return (0);
}

static int
say(struct conv *c, const char *fmt, ...)
{
	va_list	 ap;
	char	*line;
	int	 n, rc;

	va_start(ap, fmt);
	n = vasprintf(&line, fmt, ap);
	va_end(ap);
	if (n < 0)
		return (-1);
	rc = conv_write(c, line, (size_t)n);
	explicit_bzero(line, (size_t)n);
	free(line);
	return (rc);
}

/* One line of the relay's, without its CRLF: false at its end. */
static bool
line_in(struct conv *c, char *out, size_t len)
{
	char	*nl;
	ssize_t	 n;
	size_t	 k;

	for (;;) {
		if ((nl = memchr(c->buf, '\n', c->have)) != NULL) {
			k = (size_t)(nl - c->buf);
			snprintf(out, len, "%.*s", (int)(k > 0 && c->buf[k -
			    1] == '\r' ? k - 1 : k), c->buf);
			memmove(c->buf, nl + 1, c->have - k - 1);
			c->have -= k + 1;
			return (true);
		}
		if (c->have == sizeof(c->buf))
			return (false);
		n = c->ssl != NULL ? SSL_read(c->ssl, c->buf + c->have,
		    (int)(sizeof(c->buf) - c->have)) : read(c->fd, c->buf +
		    c->have, sizeof(c->buf) - c->have);
		if (n <= 0)
			return (false);
		c->have += (size_t)n;
	}
}

/*
 * The relay's reply, all its lines (250-…, then 250 …): its code, or -1;
 * the last line's words kept for the error.  ext: EHLO's lines, joined.
 */
static int
reply(struct conv *c, char *ext, size_t extlen)
{
	char	line[SMTP_LINE];
	int	code;

	if (ext != NULL && extlen > 0)
		ext[0] = '\0';
	for (;;) {
		if (!line_in(c, line, sizeof(line)) || strlen(line) < 3) {
			snprintf(c->err, c->errlen, "the relay closed or did "
			    "not answer in %d s", SMTP_WAIT_S);
			return (-1);
		}
		code = atoi(line);
		if (ext != NULL)
			snprintf(ext + strlen(ext), extlen - strlen(ext), "%s\n",
			    line + 4 <= line + strlen(line) ? line + 4 : "");
		if (line[3] != '-') {
			snprintf(c->err, c->errlen, "the relay said: %s", line);
			return (code);
		}
	}
}

/* A command and its reply; -1 unless the reply is want's (2, 3: its
 * first digit). */
static int
cmd(struct conv *c, int want, const char *fmt, ...)
{
	va_list	 ap;
	char	*line;
	int	 n, code;

	va_start(ap, fmt);
	n = vasprintf(&line, fmt, ap);
	va_end(ap);
	if (n < 0)
		return (-1);
	code = conv_write(c, line, (size_t)n) == 0 ? reply(c, NULL, 0) : -1;
	explicit_bzero(line, (size_t)n);
	free(line);
	return (code / 100 == want ? 0 : -1);
}

static int
tls_start(struct conv *c, const char *host)
{
	X509_VERIFY_PARAM	*vp;
	unsigned char		 ip[16];
	char			 why[256];

	if ((c->ctx = SSL_CTX_new(TLS_client_method())) == NULL)
		return (-1);
	SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
	SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
	if (SSL_CTX_set_default_verify_paths(c->ctx) != 1 || (c->ssl =
	    SSL_new(c->ctx)) == NULL)
		return (-1);
	vp = SSL_get0_param(c->ssl);
	/*
	 * An address is checked against the certificate's IP addresses,
	 * and named in no SNI (RFC 6066); a name against its DNS names,
	 * and sent as SNI (SSL_set_tlsext_host_name()'s macro casts the
	 * const away).
	 */
	if (inet_pton(AF_INET, host, ip) == 1 || inet_pton(AF_INET6, host,
	    ip) == 1) {
		if (X509_VERIFY_PARAM_set1_ip_asc(vp, host) != 1)
			return (-1);
	} else {
		(void)SSL_ctrl(c->ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME,
		    TLSEXT_NAMETYPE_host_name, (void *)(uintptr_t)host);
		X509_VERIFY_PARAM_set_hostflags(vp,
		    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		if (X509_VERIFY_PARAM_set1_host(vp, host, 0) != 1)
			return (-1);
	}
	if (SSL_set_fd(c->ssl, c->fd) != 1)
		return (-1);
	if (SSL_connect(c->ssl) != 1) {
		ERR_error_string_n(ERR_get_error(), why, sizeof(why));
		snprintf(c->err, c->errlen, "TLS with %s: %s", host,
		    SSL_get_verify_result(c->ssl) != X509_V_OK ?
		    X509_verify_cert_error_string(SSL_get_verify_result(
		    c->ssl)) : why);
		SSL_free(c->ssl);
		c->ssl = NULL;
		return (-1);
	}
	return (0);
}

static int
dial(const char *host, int port, char *err, size_t errlen)
{
	struct addrinfo	 hints, *res, *ai;
	struct timeval	 tv;
	char		 serv[8];
	int		 fd, e;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	snprintf(serv, sizeof(serv), "%d", port);
	if ((e = getaddrinfo(host, serv, &hints, &res)) != 0) {
		snprintf(err, errlen, "%s: %s", host, gai_strerror(e));
		return (-1);
	}
	fd = -1;
	tv.tv_sec = SMTP_WAIT_S;
	tv.tv_usec = 0;
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		if ((fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
		    ai->ai_protocol)) == -1)
			continue;
		(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		snprintf(err, errlen, "%s port %d: %s", host, port,
		    strerror(errno));
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return (fd);
}

/*
 * The message (its headers, a blank line, its body; lines ended by \n)
 * from from to each of rcpt, by the relay host:port: security "tls",
 * "starttls" or "none".  0, or -1 with why in err.
 */
int
smtp_send(const char *host, int port, const char *security,
    const char *user, const char *pass, const char *from,
    const char *const *rcpt, size_t nrcpt, const char *msg, char *err,
    size_t errlen)
{
	struct conv	 c;
	char		 me[256], ext[2048], *auth, *b64;
	const char	*p, *e;
	size_t		 i, ulen, plen;
	int		 rc;

	memset(&c, 0, sizeof(c));
	c.err = err;
	c.errlen = errlen;
	c.fd = -1;
	rc = -1;
	if (gethostname(me, sizeof(me)) != 0)
		strlcpy(me, "localhost", sizeof(me));
	if ((c.fd = dial(host, port, err, errlen)) == -1)
		return (-1);
	if (strcmp(security, "tls") == 0 && tls_start(&c, host) != 0)
		goto out;
	if (reply(&c, NULL, 0) / 100 != 2)
		goto out;
	if (say(&c, "EHLO %s\r\n", me) != 0 || reply(&c, ext, sizeof(ext)) /
	    100 != 2)
		goto out;
	if (strcmp(security, "starttls") == 0) {
		if (strstr(ext, "STARTTLS") == NULL) {
			snprintf(err, errlen, "%s does not offer STARTTLS", host);
			goto out;
		}
		if (cmd(&c, 2, "STARTTLS\r\n") != 0)
			goto out;
		/* Nothing said in the clear is read after it. */
		c.have = 0;
		if (tls_start(&c, host) != 0)
			goto out;
		if (say(&c, "EHLO %s\r\n", me) != 0 || reply(&c, ext,
		    sizeof(ext)) / 100 != 2)
			goto out;
	}
	if (user != NULL && user[0] != '\0') {
		/* A password is never sent in the clear. */
		if (c.ssl == NULL) {
			snprintf(err, errlen, "a password is sent over TLS "
			    "only: choose STARTTLS or TLS");
			goto out;
		}
		ulen = strlen(user);
		plen = pass != NULL ? strlen(pass) : 0;
		if ((auth = malloc(ulen + plen + 3)) == NULL || (b64 =
		    malloc(4 * ((ulen + plen + 4) / 3) + 1)) == NULL) {
			free(auth);
			goto out;
		}
		auth[0] = '\0';
		memcpy(auth + 1, user, ulen);
		auth[ulen + 1] = '\0';
		if (plen > 0)
			memcpy(auth + ulen + 2, pass, plen);
		EVP_EncodeBlock((unsigned char *)b64, (unsigned char *)auth,
		    (int)(ulen + plen + 2));
		explicit_bzero(auth, ulen + plen + 2);
		free(auth);
		i = (size_t)cmd(&c, 2, "AUTH PLAIN %s\r\n", b64);
		explicit_bzero(b64, strlen(b64));
		free(b64);
		if (i != 0)
			goto out;
	}
	if (cmd(&c, 2, "MAIL FROM:<%s>\r\n", from) != 0)
		goto out;
	for (i = 0; i < nrcpt; i++)
		if (cmd(&c, 2, "RCPT TO:<%s>\r\n", rcpt[i]) != 0)
			goto out;
	if (cmd(&c, 3, "DATA\r\n") != 0)
		goto out;
	/* Each line ended by CRLF, one that starts with a dot doubled. */
	for (p = msg; *p != '\0'; p = *e != '\0' ? e + 1 : e) {
		e = p + strcspn(p, "\n");
		if ((*p == '.' && conv_write(&c, ".", 1) != 0) ||
		    conv_write(&c, p, (size_t)(e - p - (e > p && e[-1] == '\r' ?
		    1 : 0))) != 0 || conv_write(&c, "\r\n", 2) != 0)
			goto out;
	}
	if (cmd(&c, 2, ".\r\n") != 0)
		goto out;
	(void)say(&c, "QUIT\r\n");
	rc = 0;
out:
	if (c.ssl != NULL) {
		SSL_shutdown(c.ssl);
		SSL_free(c.ssl);
	}
	if (c.ctx != NULL)
		SSL_CTX_free(c.ctx);
	if (c.fd != -1)
		close(c.fd);
	return (rc);
}
