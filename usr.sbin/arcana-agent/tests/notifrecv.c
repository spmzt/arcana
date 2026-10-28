/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A stand-in HTTPS-notif receiver (draft-ietf-netconf-https-notif) for
 * agent_tls_test.sh: notifrecv cert key ca port log.  It listens on
 * 127.0.0.1 and takes one connection at a time, a client certificate
 * from ca required; each request is logged as "METHOD path" and its
 * body on the lines after, then a blank line.  A GET whose path ends in
 * /capabilities is answered with the receiver's capabilities, JSON
 * among them; a POST whose path ends in /relay-notification with 204;
 * anything else 404.  While the file "down" exists beside the log, a
 * connection is closed at once: the receiver is away.
 */

#include <sys/socket.h>

#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	CAPS	"{\"ietf-https-notif-transport:receiver-capabilities\":" \
		"{\"receiver-capability\":[\"urn:ietf:capability:" \
		"https-notif-receiver:encoding:json\"]}}"

static int
reply(SSL *ssl, int status, const char *text, const char *body)
{
	char	hdr[256];
	int	n;

	n = snprintf(hdr, sizeof(hdr), "HTTP/1.1 %d %s\r\nContent-Type: "
	    "application/yang-data+json\r\nContent-Length: %zu\r\n\r\n", status,
	    text, body != NULL ? strlen(body) : 0);
	if (SSL_write(ssl, hdr, n) <= 0)
		return (-1);
	if (body != NULL && SSL_write(ssl, body, (int)strlen(body)) <= 0)
		return (-1);
	return (0);
}

/* The requests of one connection, until it ends. */
static void
serve(SSL *ssl, FILE *log)
{
	char	buf[65536], method[16], path[512], *e, *l;
	size_t	len = 0, hlen, clen;
	int	n;

	for (;;) {
		for (;;) {
			buf[len] = '\0';
			if ((e = strstr(buf, "\r\n\r\n")) != NULL)
				break;
			if (len + 1 >= sizeof(buf) || (n = SSL_read(ssl, buf +
			    len, (int)(sizeof(buf) - len - 1))) <= 0)
				return;
			len += (size_t)n;
		}
		hlen = (size_t)(e + 4 - buf);
		if (sscanf(buf, "%15s %511s", method, path) != 2)
			return;
		clen = 0;
		for (l = strchr(buf, '\n'); l != NULL && l < e; l = strchr(l +
		    1, '\n'))
			if (strncasecmp(l + 1, "content-length:", 15) == 0)
				clen = strtoul(l + 16, NULL, 10);
		while (len - hlen < clen) {
			if (len + 1 >= sizeof(buf) || (n = SSL_read(ssl, buf +
			    len, (int)(sizeof(buf) - len - 1))) <= 0)
				return;
			len += (size_t)n;
		}
		fprintf(log, "%s %s\n%.*s\n\n", method, path, (int)clen, buf +
		    hlen);
		fflush(log);
		if (strcmp(method, "GET") == 0 && strlen(path) >= 13 &&
		    strcmp(path + strlen(path) - 13, "/capabilities") == 0)
			n = reply(ssl, 200, "OK", CAPS);
		else if (strcmp(method, "POST") == 0 && strlen(path) >= 19 &&
		    strcmp(path + strlen(path) - 19, "/relay-notification") ==
		    0)
			n = reply(ssl, 204, "No Content", NULL);
		else
			n = reply(ssl, 404, "Not Found", "{}");
		if (n != 0)
			return;
		memmove(buf, buf + hlen + clen, len - hlen - clen);
		len -= hlen + clen;
	}
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in	 sin;
	SSL_CTX			*ctx;
	SSL			*ssl;
	FILE			*log;
	char			 down[1024], *slash;
	int			 ls, fd, on = 1;

	if (argc != 6)
		errx(2, "usage: notifrecv cert key ca port log");
	signal(SIGPIPE, SIG_IGN);
	if ((ctx = SSL_CTX_new(TLS_server_method())) == NULL ||
	    SSL_CTX_use_certificate_chain_file(ctx, argv[1]) != 1 ||
	    SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) != 1 ||
	    SSL_CTX_load_verify_locations(ctx, argv[3], NULL) != 1)
		errx(1, "TLS: %s", ERR_reason_error_string(ERR_get_error()));
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
	    NULL);
	SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(argv[3]));
	if ((log = fopen(argv[5], "a")) == NULL)
		err(1, "%s", argv[5]);
	snprintf(down, sizeof(down), "%s", argv[5]);
	if ((slash = strrchr(down, '/')) != NULL)
		snprintf(slash + 1, sizeof(down) - (size_t)(slash + 1 - down),
		    "down");
	else
		snprintf(down, sizeof(down), "down");
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_port = htons((uint16_t)atoi(argv[4]));
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if ((ls = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
	    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1 ||
	    bind(ls, (struct sockaddr *)&sin, sizeof(sin)) == -1 ||
	    listen(ls, 4) == -1)
		err(1, "listen on %s", argv[4]);
	printf("ready\n");
	fflush(stdout);
	for (;;) {
		if ((fd = accept(ls, NULL, NULL)) == -1)
			continue;
		if (access(down, F_OK) == 0) {
			close(fd);
			continue;
		}
		if ((ssl = SSL_new(ctx)) == NULL) {
			close(fd);
			continue;
		}
		SSL_set_fd(ssl, fd);
		if (SSL_accept(ssl) == 1)
			serve(ssl, log);
		SSL_free(ssl);
		close(fd);
	}
}
