/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Sign-in by LDAP (RFC 4511), when Settings name a directory: the
 * user is looked up under the base by an attribute (uid, sAMAccountName)
 * as the console's own reader, or anonymously; then the console binds
 * as the entry found with the password given, which is what checks it;
 * and when a group is named, the entry must be a member of it (member,
 * uniqueMember or memberUid).  LDAP is ASN.1 in BER, and the little of
 * it this needs (a bind, a search with an equality filter, StartTLS, an
 * unbind) is written here, so that the console depends on no LDAP
 * library.  Always over TLS: ldaps://, or StartTLS on ldap://, the
 * server's certificate checked against the system's CAs (or the file
 * Settings name) and its name, as the SMTP relay's is.  Every read and
 * write waits LDAP_WAIT_S at most.  An empty password is refused
 * first: a directory takes it as an anonymous bind and says yes.
 * Failures are counted, and after LDAP_TRIES in a minute every sign-in
 * waits for the minute to pass.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "console.h"

#define	LDAP_WAIT_S	10
#define	LDAP_TRIES	5		/* failures a minute before a wait */
#define	LDAP_MSG_MAX	65536		/* a message of the server's, at most */

/* Tags (RFC 4511 §4.1): universal, and the application ones. */
#define	T_BOOL		0x01
#define	T_INT		0x02
#define	T_OCTETS	0x04
#define	T_ENUM		0x0a
#define	T_SEQ		0x30
#define	T_SET		0x31
#define	T_BIND_REQ	0x60
#define	T_BIND_RSP	0x61
#define	T_UNBIND	0x42
#define	T_SEARCH_REQ	0x63
#define	T_SEARCH_ENTRY	0x64
#define	T_SEARCH_DONE	0x65
#define	T_EXT_REQ	0x77
#define	T_EXT_RSP	0x78
#define	T_CTX(n)	(0x80 | (n))	/* a context-specific primitive */
#define	T_CTXC(n)	(0xa0 | (n))	/* ... constructed */

#define	STARTTLS_OID	"1.3.6.1.4.1.1466.20037"

struct ber {
	unsigned char	*p;
	size_t		 len, cap;
};

struct lconn {
	int	 fd;
	SSL_CTX	*ctx;
	SSL	*ssl;
	int	 id;		/* the next message's id */
	char	*err;
	size_t	 errlen;
};

/* ---- BER out ------------------------------------------------------ */

static void
ber_room(struct ber *b, size_t n)
{

	while (b->len + n > b->cap) {
		b->cap = b->cap == 0 ? 256 : b->cap * 2;
		b->p = kore_realloc(b->p, b->cap);
	}
}

static void
ber_byte(struct ber *b, unsigned char c)
{

	ber_room(b, 1);
	b->p[b->len++] = c;
}

/* A length, in the short or the long form. */
static void
ber_len(struct ber *b, size_t n)
{
	int	k;

	if (n < 0x80) {
		ber_byte(b, (unsigned char)n);
		return;
	}
	for (k = 1; k < 4 && (n >> (8 * k)) != 0; k++)
		;
	ber_byte(b, (unsigned char)(0x80 | k));
	while (k-- > 0)
		ber_byte(b, (unsigned char)(n >> (8 * k)));
}

static void
ber_raw(struct ber *b, unsigned char tag, const void *v, size_t n)
{

	ber_byte(b, tag);
	ber_len(b, n);
	ber_room(b, n);
	memcpy(b->p + b->len, v, n);
	b->len += n;
}

static void
ber_str(struct ber *b, unsigned char tag, const char *s)
{

	ber_raw(b, tag, s, strlen(s));
}

static void
ber_int(struct ber *b, unsigned char tag, long v)
{
	unsigned char	buf[8];
	int		k, n;

	/* Two's complement, the fewest bytes that keep the sign. */
	for (n = 1; n < 8; n++) {
		long	top = v >> (8 * n);

		if (top == 0 && !(v & (1L << (8 * n - 1))))
			break;
		if (top == -1 && (v & (1L << (8 * n - 1))))
			break;
	}
	for (k = 0; k < n; k++)
		buf[k] = (unsigned char)(v >> (8 * (n - 1 - k)));
	ber_raw(b, tag, buf, (size_t)n);
}

/* A constructed value: what was written since mark, wrapped in tag. */
static void
ber_wrap(struct ber *b, unsigned char tag, size_t mark)
{
	struct ber	h;
	size_t		n;

	n = b->len - mark;
	memset(&h, 0, sizeof(h));
	ber_byte(&h, tag);
	ber_len(&h, n);
	ber_room(b, h.len);
	memmove(b->p + mark + h.len, b->p + mark, n);
	memcpy(b->p + mark, h.p, h.len);
	b->len += h.len;
	kore_free(h.p);
}

/* ---- BER in ------------------------------------------------------- */

struct tlv {
	unsigned char		 tag;
	const unsigned char	*v;
	size_t			 len;
};

/* The next element at *pp, before end; false when there is none. */
static bool
ber_next(const unsigned char **pp, const unsigned char *end, struct tlv *t)
{
	const unsigned char	*p = *pp;
	size_t			 n;
	int			 k;

	if (end - p < 2)
		return (false);
	t->tag = *p++;
	n = *p++;
	if (n & 0x80) {
		k = n & 0x7f;
		if (k == 0 || k > 4 || end - p < k)
			return (false);
		n = 0;
		while (k-- > 0)
			n = (n << 8) | *p++;
	}
	if ((size_t)(end - p) < n)
		return (false);
	t->v = p;
	t->len = n;
	*pp = p + n;
	return (true);
}

static long
ber_toint(const struct tlv *t)
{
	long	v;
	size_t	i;

	if (t->len == 0 || t->len > 8)
		return (-1);
	v = (t->v[0] & 0x80) ? -1 : 0;
	for (i = 0; i < t->len; i++)
		v = (v << 8) | t->v[i];
	return (v);
}

/* ---- The connection ---------------------------------------------- */

static int
lconn_write(struct lconn *c, const unsigned char *s, size_t len)
{
	ssize_t	n;

	while (len > 0) {
		n = c->ssl != NULL ? SSL_write(c->ssl, s, (int)len) : write(c->fd,
		    s, len);
		if (n <= 0) {
			snprintf(c->err, c->errlen, "the directory closed, or "
			    "took nothing in %d s", LDAP_WAIT_S);
			return (-1);
		}
		s += n;
		len -= (size_t)n;
	}
	return (0);
}

static int
lconn_read(struct lconn *c, unsigned char *buf, size_t len)
{
	ssize_t	n;

	while (len > 0) {
		n = c->ssl != NULL ? SSL_read(c->ssl, buf, (int)len) : read(c->fd,
		    buf, len);
		if (n <= 0) {
			snprintf(c->err, c->errlen, "the directory closed, or "
			    "said nothing in %d s", LDAP_WAIT_S);
			return (-1);
		}
		buf += n;
		len -= (size_t)n;
	}
	return (0);
}

/*
 * One LDAPMessage of the server's: its id checked, the protocol op
 * (tag, value) in *op; the message's bytes in *bufp, the caller's to
 * free.
 */
static int
lconn_message(struct lconn *c, int id, struct tlv *op, unsigned char **bufp)
{
	unsigned char		 head[6], *buf;
	const unsigned char	*p, *end;
	struct tlv		 msg, mid;
	size_t			 len, hlen, k;

	*bufp = NULL;
	/* The SEQUENCE's tag and length first, then the rest. */
	if (lconn_read(c, head, 2) != 0)
		return (-1);
	if (head[0] != T_SEQ) {
		snprintf(c->err, c->errlen, "the directory did not answer in "
		    "LDAP");
		return (-1);
	}
	hlen = 2;
	if (head[1] & 0x80) {
		k = head[1] & 0x7f;
		if (k == 0 || k > 4 || lconn_read(c, head + 2, k) != 0) {
			snprintf(c->err, c->errlen, "the directory's answer is "
			    "not BER");
			return (-1);
		}
		len = 0;
		while (k > 0) {
			len = (len << 8) | head[hlen++];
			k--;
		}
	} else
		len = head[1];
	if (len > LDAP_MSG_MAX) {
		snprintf(c->err, c->errlen, "the directory's answer is too "
		    "large (%zu bytes)", len);
		return (-1);
	}
	buf = kore_malloc(hlen + len);
	memcpy(buf, head, hlen);
	if (lconn_read(c, buf + hlen, len) != 0) {
		kore_free(buf);
		return (-1);
	}
	p = buf;
	end = buf + hlen + len;
	if (!ber_next(&p, end, &msg) || msg.tag != T_SEQ) {
		kore_free(buf);
		snprintf(c->err, c->errlen, "the directory's answer is not BER");
		return (-1);
	}
	p = msg.v;
	end = msg.v + msg.len;
	if (!ber_next(&p, end, &mid) || mid.tag != T_INT || ber_toint(&mid) !=
	    id || !ber_next(&p, end, op)) {
		kore_free(buf);
		snprintf(c->err, c->errlen, "the directory answered another "
		    "message");
		return (-1);
	}
	*bufp = buf;
	return (0);
}

/* An LDAPMessage of ours, op already written in b, sent; its id. */
static int
lconn_send(struct lconn *c, struct ber *b)
{
	struct ber	m;
	int		id, rc;

	id = c->id++;
	memset(&m, 0, sizeof(m));
	ber_int(&m, T_INT, id);
	ber_room(&m, b->len);
	memcpy(m.p + m.len, b->p, b->len);
	m.len += b->len;
	ber_wrap(&m, T_SEQ, 0);
	rc = lconn_write(c, m.p, m.len);
	explicit_bzero(m.p, m.len);
	kore_free(m.p);
	explicit_bzero(b->p, b->len);
	kore_free(b->p);
	memset(b, 0, sizeof(*b));
	return (rc != 0 ? -1 : id);
}

/*
 * An LDAPResult (RFC 4511 §4.1.9) in op: its code, with the diagnostic
 * message in diag.
 */
static long
result_of(const struct tlv *op, char *diag, size_t dlen)
{
	const unsigned char	*p, *end;
	struct tlv		 code, matched, msg;

	p = op->v;
	end = op->v + op->len;
	diag[0] = '\0';
	if (!ber_next(&p, end, &code) || code.tag != T_ENUM)
		return (-1);
	if (ber_next(&p, end, &matched) && ber_next(&p, end, &msg) && msg.tag ==
	    T_OCTETS)
		snprintf(diag, dlen, "%.*s", (int)MIN(msg.len, dlen - 1),
		    (const char *)msg.v);
	return (ber_toint(&code));
}

static const char *
code_words(long code)
{

	switch (code) {
	case 0: return ("success");
	case 1: return ("operations error");
	case 2: return ("protocol error");
	case 7: return ("authentication method not supported");
	case 8: return ("a stronger authentication is required");
	case 32: return ("no such object");
	case 34: return ("invalid DN syntax");
	case 48: return ("inappropriate authentication");
	case 49: return ("invalid credentials");
	case 50: return ("insufficient access rights");
	case 51: return ("busy");
	case 52: return ("unavailable");
	case 53: return ("unwilling to perform");
	default: return ("refused");
	}
}

/* ---- TLS, as the SMTP relay's ----------------------------------- */

static int
tls_start(struct lconn *c, const char *host, const char *cafile)
{
	X509_VERIFY_PARAM	*vp;
	unsigned char		 ip[16];
	char			 why[256];

	snprintf(c->err, c->errlen, "TLS could not be set up");
	if ((c->ctx = SSL_CTX_new(TLS_client_method())) == NULL)
		return (-1);
	SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
	SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
	if (cafile != NULL && cafile[0] != '\0') {
		if (SSL_CTX_load_verify_locations(c->ctx, cafile, NULL) != 1) {
			snprintf(c->err, c->errlen, "TLS: the CA file %s could "
			    "not be read", cafile);
			return (-1);
		}
	} else if (SSL_CTX_set_default_verify_paths(c->ctx) != 1) {
		snprintf(c->err, c->errlen, "TLS: the system's CAs could not "
		    "be read");
		return (-1);
	}
	if ((c->ssl = SSL_new(c->ctx)) == NULL)
		return (-1);
	vp = SSL_get0_param(c->ssl);
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
	tv.tv_sec = LDAP_WAIT_S;
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

static void
lconn_close(struct lconn *c)
{
	struct ber	b;

	if (c->fd != -1) {
		/* UnbindRequest: the server closes; nothing comes back. */
		memset(&b, 0, sizeof(b));
		ber_raw(&b, T_UNBIND, "", 0);
		(void)lconn_send(c, &b);
	}
	if (c->ssl != NULL) {
		SSL_shutdown(c->ssl);
		SSL_free(c->ssl);
	}
	if (c->ctx != NULL)
		SSL_CTX_free(c->ctx);
	if (c->fd != -1)
		close(c->fd);
	c->fd = -1;
	c->ssl = NULL;
	c->ctx = NULL;
}

/* ---- The operations ---------------------------------------------- */

/* StartTLS (RFC 4511 §4.14): the extended operation, then TLS. */
static int
starttls(struct lconn *c, const char *host, const char *cafile)
{
	struct ber	b;
	struct tlv	op;
	unsigned char	*buf;
	char		diag[200];
	long		code;
	int		id;

	memset(&b, 0, sizeof(b));
	ber_str(&b, T_CTX(0), STARTTLS_OID);
	ber_wrap(&b, T_EXT_REQ, 0);
	if ((id = lconn_send(c, &b)) < 0)
		return (-1);
	if (lconn_message(c, id, &op, &buf) != 0)
		return (-1);
	code = op.tag == T_EXT_RSP ? result_of(&op, diag, sizeof(diag)) : -1;
	kore_free(buf);
	if (code != 0) {
		snprintf(c->err, c->errlen, "StartTLS refused: %s%s%s",
		    code_words(code), diag[0] != '\0' ? ", " : "", diag);
		return (-1);
	}
	return (tls_start(c, host, cafile));
}

/* A simple bind as dn with password; "" and "" is anonymous. */
static int
bind_as(struct lconn *c, const char *dn, const char *password, long *codep)
{
	struct ber	b;
	struct tlv	op;
	unsigned char	*buf;
	char		diag[200];
	long		code;
	int		id;

	memset(&b, 0, sizeof(b));
	ber_int(&b, T_INT, 3);
	ber_str(&b, T_OCTETS, dn);
	ber_str(&b, T_CTX(0), password);
	ber_wrap(&b, T_BIND_REQ, 0);
	if ((id = lconn_send(c, &b)) < 0)
		return (-1);
	if (lconn_message(c, id, &op, &buf) != 0)
		return (-1);
	code = op.tag == T_BIND_RSP ? result_of(&op, diag, sizeof(diag)) : -1;
	kore_free(buf);
	*codep = code;
	if (code != 0) {
		snprintf(c->err, c->errlen, "bind as %s: %s%s%s", dn[0] != '\0' ?
		    dn : "anonymous", code_words(code), diag[0] != '\0' ? ", " :
		    "", diag);
		return (-1);
	}
	return (0);
}

/* A value in a filter, escaped as RFC 4515 says. */
static void
filter_value(struct ber *b, const char *v)
{
	char	esc[4];

	for (; *v != '\0'; v++) {
		if (*v == '*' || *v == '(' || *v == ')' || *v == '\\' || *v ==
		    '\0' || (unsigned char)*v < 0x20) {
			snprintf(esc, sizeof(esc), "\\%02x", (unsigned char)*v);
			ber_room(b, 3);
			memcpy(b->p + b->len, esc, 3);
			b->len += 3;
		} else
			ber_byte(b, (unsigned char)*v);
	}
}

/* An equalityMatch [3] { attr, value } filter. */
static void
filter_eq(struct ber *b, const char *attr, const char *value)
{
	size_t	mark, vmark;

	mark = b->len;
	ber_str(b, T_OCTETS, attr);
	vmark = b->len;
	filter_value(b, value);
	ber_wrap(b, T_OCTETS, vmark);
	ber_wrap(b, T_CTXC(3), mark);
}

/*
 * A search under base, of scope (0 base, 2 subtree), with the filter
 * already in f, for no attributes: the first entry's DN into dn, and
 * how many entries came in *np.
 */
static int
search(struct lconn *c, const char *base, int scope, struct ber *f, char *dn,
    size_t dnlen, int *np)
{
	struct ber	b;
	struct tlv	op, name;
	unsigned char	*buf;
	const unsigned char *p, *end;
	char		diag[200];
	long		code;
	int		id;

	*np = 0;
	dn[0] = '\0';
	memset(&b, 0, sizeof(b));
	ber_str(&b, T_OCTETS, base);
	ber_int(&b, T_ENUM, scope);
	ber_int(&b, T_ENUM, 0);		/* neverDerefAliases */
	ber_int(&b, T_INT, 2);		/* sizeLimit: one, and a second to tell */
	ber_int(&b, T_INT, LDAP_WAIT_S);
	ber_int(&b, T_BOOL, 1);		/* typesOnly: no values wanted */
	ber_room(&b, f->len);
	memcpy(b.p + b.len, f->p, f->len);
	b.len += f->len;
	kore_free(f->p);
	memset(f, 0, sizeof(*f));
	{
		size_t	mark = b.len;

		ber_str(&b, T_OCTETS, "1.1");	/* no attributes */
		ber_wrap(&b, T_SEQ, mark);
	}
	ber_wrap(&b, T_SEARCH_REQ, 0);
	if ((id = lconn_send(c, &b)) < 0)
		return (-1);
	for (;;) {
		if (lconn_message(c, id, &op, &buf) != 0)
			return (-1);
		if (op.tag == T_SEARCH_ENTRY) {
			p = op.v;
			end = op.v + op.len;
			if (ber_next(&p, end, &name) && name.tag == T_OCTETS &&
			    *np == 0)
				snprintf(dn, dnlen, "%.*s", (int)MIN(name.len,
				    dnlen - 1), (const char *)name.v);
			(*np)++;
			kore_free(buf);
			continue;
		}
		if (op.tag == T_SEARCH_DONE) {
			code = result_of(&op, diag, sizeof(diag));
			kore_free(buf);
			/* sizeLimitExceeded (4) with entries is an answer. */
			if (code == 0 || (code == 4 && *np > 0))
				return (0);
			snprintf(c->err, c->errlen, "search under %s: %s%s%s",
			    base, code_words(code), diag[0] != '\0' ? ", " : "",
			    diag);
			return (-1);
		}
		/* A referral or an intermediate response: passed over. */
		kore_free(buf);
	}
}

/* ---- Sign-in ------------------------------------------------------ */

static time_t	fail_minute;		/* the minute the failures are of */
static int	fails;

static bool
throttled(void)
{
	time_t	now;

	now = time(NULL) / 60;
	if (now != fail_minute) {
		fail_minute = now;
		fails = 0;
	}
	return (fails >= LDAP_TRIES);
}

static void
failed(void)
{

	(void)throttled();
	fails++;
}

/* The directory's URL into its parts: ldap or ldaps, a host, a port. */
static bool
url_parts(const char *url, bool *tlsp, char *host, size_t hlen, int *portp)
{
	const char	*p, *e;
	char		*end;
	long		 port;

	if (strncmp(url, "ldaps://", 8) == 0) {
		*tlsp = true;
		p = url + 8;
	} else if (strncmp(url, "ldap://", 7) == 0) {
		*tlsp = false;
		p = url + 7;
	} else
		return (false);
	if (*p == '[') {
		if ((e = strchr(p, ']')) == NULL)
			return (false);
		snprintf(host, hlen, "%.*s", (int)(e - p - 1), p + 1);
		p = e + 1;
	} else {
		e = p + strcspn(p, ":/");
		snprintf(host, hlen, "%.*s", (int)(e - p), p);
		p = e;
	}
	if (host[0] == '\0')
		return (false);
	*portp = *tlsp ? 636 : 389;
	if (*p == ':') {
		port = strtol(p + 1, &end, 10);
		if (end == p + 1 || port < 1 || port > 65535 || (*end != '\0' &&
		    *end != '/'))
			return (false);
		*portp = (int)port;
		p = end;
	}
	return (*p == '\0' || strcmp(p, "/") == 0);
}

bool
ldap_enabled(void)
{
	const char	*url;

	url = settings_peek("ldap_url");
	return (url != NULL && url[0] != '\0');
}

/*
 * user and password tried against the directory Settings name: true,
 * and who the session is (the entry's DN), or false and why in err.
 * The why is for the log and the page alike: it names no entry that
 * is not the user's own.
 */
bool
ldap_login(const char *user, const char *password, char *who, size_t wholen,
    char *err, size_t errlen, const char **roles, int *nroles, int maxroles)
{
	const char	*rnames[ROLES_LDAP_MAX], *rgroups[ROLES_LDAP_MAX];
	int		 nr, ri;
	struct lconn	 c;
	struct ber	 f;
	const char	*url, *base, *attr, *group, *bind_dn, *bind_pw, *cafile;
	char		 host[256], dn[512], gdn[512];
	long		 code;
	size_t		 i;
	int		 port, n, fmark;
	bool		 tls, ok;

	err[0] = '\0';
	who[0] = '\0';
	if (!ldap_enabled()) {
		snprintf(err, errlen, "sign-in by LDAP is not set up");
		return (false);
	}
	if (user == NULL || user[0] == '\0' || strlen(user) > 64) {
		snprintf(err, errlen, "a user name is 1 to 64 characters");
		return (false);
	}
	for (i = 0; user[i] != '\0'; i++)
		if ((unsigned char)user[i] < 0x20 || user[i] == 0x7f) {
			snprintf(err, errlen, "a user name has no control "
			    "characters");
			return (false);
		}
	if (password == NULL || password[0] == '\0' || strlen(password) > 256) {
		snprintf(err, errlen, "a password is 1 to 256 characters: an "
		    "empty one would be an anonymous bind");
		return (false);
	}
	if (throttled()) {
		snprintf(err, errlen, "too many failed sign-ins: try again in "
		    "a minute");
		return (false);
	}
	url = settings_peek("ldap_url");
	base = settings_peek("ldap_base");
	attr = settings_peek("ldap_user_attr");
	group = settings_peek("ldap_group");
	bind_dn = settings_peek("ldap_bind_dn");
	bind_pw = settings_peek("ldap_bind_password");
	cafile = settings_peek("ldap_ca");
	if (attr == NULL || attr[0] == '\0')
		attr = "uid";
	if (base == NULL || base[0] == '\0') {
		snprintf(err, errlen, "LDAP: the search base is not set");
		return (false);
	}
	if (!url_parts(url, &tls, host, sizeof(host), &port)) {
		snprintf(err, errlen, "LDAP: the URL is not ldap://host[:port] "
		    "or ldaps://host[:port]");
		return (false);
	}
	memset(&c, 0, sizeof(c));
	c.err = err;
	c.errlen = errlen;
	c.id = 1;
	ok = false;
	if ((c.fd = dial(host, port, err, errlen)) == -1)
		goto out;
	if (tls ? tls_start(&c, host, cafile) : starttls(&c, host, cafile))
		goto out;
	/* The console's own reader, or anonymous, finds the entry. */
	if (bind_as(&c, bind_dn != NULL ? bind_dn : "", bind_dn != NULL &&
	    bind_dn[0] != '\0' && bind_pw != NULL ? bind_pw : "", &code) != 0)
		goto out;
	memset(&f, 0, sizeof(f));
	filter_eq(&f, attr, user);
	if (search(&c, base, 2, &f, dn, sizeof(dn), &n) != 0)
		goto out;
	if (n == 0) {
		snprintf(err, errlen, "no such user, or a wrong password");
		kore_log(LOG_NOTICE, "LDAP sign-in of %s refused: no entry with "
		    "%s=%s under %s", user, attr, user, base);
		failed();
		goto out;
	}
	if (n > 1) {
		snprintf(err, errlen, "more than one entry has %s=%s: the "
		    "directory is ambiguous", attr, user);
		failed();
		goto out;
	}
	/* The user's own bind is what checks the password. */
	if (bind_as(&c, dn, password, &code) != 0) {
		if (code == 49) {
			snprintf(err, errlen, "no such user, or a wrong "
			    "password");
			kore_log(LOG_NOTICE, "LDAP sign-in of %s refused: "
			    "invalid credentials for %s", user, dn);
		} else
			kore_log(LOG_NOTICE, "LDAP sign-in of %s failed: %s",
			    user, err);
		failed();
		goto out;
	}
	if (group != NULL && group[0] != '\0') {
		/* Of the group, by any of the ways a group names a member. */
		memset(&f, 0, sizeof(f));
		fmark = 0;
		filter_eq(&f, "member", dn);
		filter_eq(&f, "uniqueMember", dn);
		filter_eq(&f, "memberUid", user);
		ber_wrap(&f, T_CTXC(1), (size_t)fmark);	/* or */
		if (search(&c, group, 0, &f, gdn, sizeof(gdn), &n) != 0) {
			kore_log(LOG_NOTICE, "LDAP sign-in of %s failed: %s",
			    user, err);
			failed();
			goto out;
		}
		if (n == 0) {
			snprintf(err, errlen, "not a member of the group the "
			    "console admits");
			kore_log(LOG_NOTICE, "LDAP sign-in of %s refused: %s is "
			    "not in %s", user, dn, group);
			failed();
			goto out;
		}
	}
	/* The roles whose directory group has the user (users.c), by the
	 * same ways a group names a member. */
	*nroles = 0;
	nr = roles_ldap_groups(rnames, rgroups, ROLES_LDAP_MAX);
	for (ri = 0; ri < nr && *nroles < maxroles; ri++) {
		memset(&f, 0, sizeof(f));
		fmark = 0;
		filter_eq(&f, "member", dn);
		filter_eq(&f, "uniqueMember", dn);
		filter_eq(&f, "memberUid", user);
		ber_wrap(&f, T_CTXC(1), (size_t)fmark);	/* or */
		if (search(&c, rgroups[ri], 0, &f, gdn, sizeof(gdn), &n) == 0 &&
		    n > 0)
			roles[(*nroles)++] = rnames[ri];
	}
	snprintf(who, wholen, "LDAP user %s", user);
	kore_log(LOG_NOTICE, "LDAP sign-in of %s (%s), %d role%s by its groups",
	    user, dn, *nroles, *nroles == 1 ? "" : "s");
	ok = true;
out:
	if (!ok && err[0] == '\0')
		snprintf(err, errlen, "the directory did not answer");
	if (!ok && c.fd != -1 && !(n == 0 && err[0] != '\0'))
		kore_log(LOG_NOTICE, "LDAP sign-in of %s failed: %s", user, err);
	lconn_close(&c);
	return (ok);
}
