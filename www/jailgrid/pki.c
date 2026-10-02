/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console's own certificate authority, and enrolment of jail hosts.
 *
 * Without a tls { } block in web.conf the console makes a CA and its
 * client certificate in the data directory at first start.  A host joins
 * with a one-time token made here by the logged-in user: jailgrid-enrol(8)
 * on the host sends a certificate request with the token, gets back a
 * certificate for its name signed by the CA, and the host is added to
 * the server list.  All EC P-256, signed with SHA-256.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "jgweb.h"

#define	CA_DAYS		3650
#define	CERT_DAYS	825
#define	TOKEN_TTL	3600
#define	MAX_TOKENS	16
#define	DEFAULT_PORT	4310

struct etoken {
	char		value[65];	/* 32 random bytes in hex */
	char		name[65];	/* the server's name in the console */
	char		host[256];	/* its host name or address */
	int		port;
	time_t		expires;
};

static struct etoken	tokens[MAX_TOKENS];

static const char *ssl_err(void);
static EVP_PKEY	*key_new(void);
static X509	*cert_new(EVP_PKEY *, const char *, X509 *, EVP_PKEY *,
		    const char *, int);
static int	 add_ext(X509 *, X509 *, int, const char *);
static int	 write_pem(const char *, X509 *, EVP_PKEY *, mode_t);
static X509	*read_cert(const char *);
static EVP_PKEY	*read_key(const char *);
static char	*pem_string(X509 *);
static bool	 valid_host(const char *);
static struct etoken *token_find(const char *);

static const char *
ssl_err(void)
{
	const char	*s;

	s = ERR_reason_error_string(ERR_get_error());
	ERR_clear_error();
	return (s != NULL ? s : "libcrypto error");
}

static EVP_PKEY *
key_new(void)
{

	return (EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"));
}

static int
add_ext(X509 *x, X509 *issuer, int nid, const char *value)
{
	X509V3_CTX	 ctx;
	X509_EXTENSION	*ex;
	int		 rc;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, issuer != NULL ? issuer : x, x, NULL, NULL, 0);
	if ((ex = X509V3_EXT_conf_nid(NULL, &ctx, nid,
	    (char *)(uintptr_t)value)) == NULL)
		return (-1);
	rc = X509_add_ext(x, ex, -1) == 1 ? 0 : -1;
	X509_EXTENSION_free(ex);
	return (rc);
}

/*
 * A certificate for key, named cn.  With issuer NULL it is a CA signing
 * itself; else it is signed by issuer's key, and san names the host.
 */
static X509 *
cert_new(EVP_PKEY *key, const char *cn, X509 *issuer, EVP_PKEY *ikey,
    const char *san, int days)
{
	X509		*x;
	X509_NAME	*name;
	BIGNUM		*bn;
	ASN1_INTEGER	*serial;
	int		 ok;

	if ((x = X509_new()) == NULL)
		return (NULL);
	ok = X509_set_version(x, X509_VERSION_3) == 1;
	if ((bn = BN_new()) != NULL && BN_rand(bn, 127, BN_RAND_TOP_ANY,
	    BN_RAND_BOTTOM_ANY) == 1 && (serial = BN_to_ASN1_INTEGER(bn,
	    NULL)) != NULL) {
		ok = ok && X509_set_serialNumber(x, serial) == 1;
		ASN1_INTEGER_free(serial);
	} else
		ok = 0;
	BN_free(bn);
	ok = ok && X509_gmtime_adj(X509_getm_notBefore(x), -300) != NULL &&
	    X509_gmtime_adj(X509_getm_notAfter(x), (long)days * 86400) != NULL;
	name = X509_get_subject_name(x);
	ok = ok && X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
	    (const unsigned char *)cn, -1, -1, 0) == 1;
	ok = ok && X509_set_issuer_name(x, issuer != NULL ?
	    X509_get_subject_name(issuer) : name) == 1;
	ok = ok && X509_set_pubkey(x, key) == 1;
	if (issuer == NULL) {
		ok = ok && add_ext(x, NULL, NID_basic_constraints,
		    "critical,CA:TRUE") == 0 &&
		    add_ext(x, NULL, NID_key_usage,
		    "critical,keyCertSign,cRLSign") == 0;
	} else {
		ok = ok && add_ext(x, issuer, NID_basic_constraints,
		    "critical,CA:FALSE") == 0 &&
		    add_ext(x, issuer, NID_key_usage,
		    "critical,digitalSignature") == 0 &&
		    add_ext(x, issuer, NID_ext_key_usage, san != NULL ?
		    "serverAuth" : "clientAuth") == 0 &&
		    add_ext(x, issuer, NID_authority_key_identifier,
		    "keyid:always") == 0;
		if (san != NULL)
			ok = ok && add_ext(x, issuer, NID_subject_alt_name,
			    san) == 0;
	}
	ok = ok && add_ext(x, issuer, NID_subject_key_identifier, "hash") == 0;
	ok = ok && X509_sign(x, issuer != NULL ? ikey : key, EVP_sha256()) > 0;
	if (!ok) {
		X509_free(x);
		return (NULL);
	}
	return (x);
}

/* A certificate or a key as PEM, written through a temporary file. */
static int
write_pem(const char *path, X509 *x, EVP_PKEY *key, mode_t mode)
{
	FILE	*fp;
	char	 tmp[MAXPATHLEN];
	int	 fd, ok;

	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
	if ((fd = mkstemp(tmp)) == -1 || fchmod(fd, mode) == -1 ||
	    (fp = fdopen(fd, "w")) == NULL) {
		kore_log(LOG_ERR, "%s: %s", tmp, strerror(errno));
		if (fd != -1) {
			close(fd);
			unlink(tmp);
		}
		return (-1);
	}
	ok = x != NULL ? PEM_write_X509(fp, x) :
	    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
	if (!ok || fflush(fp) != 0 || fsync(fd) == -1 || fclose(fp) != 0 ||
	    rename(tmp, path) == -1) {
		kore_log(LOG_ERR, "writing %s: %s", path, ok ? strerror(errno) :
		    ssl_err());
		unlink(tmp);
		return (-1);
	}
	return (0);
}

static X509 *
read_cert(const char *path)
{
	FILE	*fp;
	X509	*x;

	if ((fp = fopen(path, "r")) == NULL)
		return (NULL);
	x = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	return (x);
}

static EVP_PKEY *
read_key(const char *path)
{
	FILE		*fp;
	EVP_PKEY	*k;

	if ((fp = fopen(path, "r")) == NULL)
		return (NULL);
	k = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	return (k);
}

/* The certificate as PEM text; the caller frees it. */
static char *
pem_string(X509 *x)
{
	BIO	*b;
	char	*s, *out;
	long	 len;

	if ((b = BIO_new(BIO_s_mem())) == NULL)
		return (NULL);
	out = NULL;
	if (PEM_write_bio_X509(b, x) == 1 && (len = BIO_get_mem_data(b,
	    &s)) > 0 && (out = malloc((size_t)len + 1)) != NULL) {
		memcpy(out, s, (size_t)len);
		out[len] = '\0';
	}
	BIO_free(b);
	return (out);
}

/*
 * Without a tls { } block: the CA and the console's client certificate
 * live in the data directory, made at first start.
 */
int
pki_init(void)
{
	EVP_PKEY	*cakey, *key;
	X509		*ca, *cert;
	char		 path[4][MAXPATHLEN];
	int		 rc;

	if (!cfg.tls_own)
		return (0);
	snprintf(path[0], MAXPATHLEN, "%s/ca.pem", cfg.datadir);
	snprintf(path[1], MAXPATHLEN, "%s/ca.key", cfg.datadir);
	snprintf(path[2], MAXPATHLEN, "%s/console.pem", cfg.datadir);
	snprintf(path[3], MAXPATHLEN, "%s/console.key", cfg.datadir);
	cfg.tls_ca = kore_strdup(path[0]);
	cfg.tls_ca_key = kore_strdup(path[1]);
	cfg.tls_cert = kore_strdup(path[2]);
	cfg.tls_key = kore_strdup(path[3]);
	if (access(path[0], F_OK) == 0 && access(path[1], F_OK) == 0 &&
	    access(path[2], F_OK) == 0 && access(path[3], F_OK) == 0)
		return (0);

	rc = -1;
	cakey = key = NULL;
	ca = cert = NULL;
	if ((cakey = key_new()) == NULL || (key = key_new()) == NULL ||
	    (ca = cert_new(cakey, "jailgrid CA", NULL, NULL, NULL,
	    CA_DAYS)) == NULL || (cert = cert_new(key, "jailgrid console", ca,
	    cakey, NULL, CA_DAYS)) == NULL) {
		kore_log(LOG_ERR, "making the CA: %s", ssl_err());
		goto out;
	}
	if (write_pem(path[1], NULL, cakey, 0600) == -1 ||
	    write_pem(path[0], ca, NULL, 0644) == -1 ||
	    write_pem(path[3], NULL, key, 0600) == -1 ||
	    write_pem(path[2], cert, NULL, 0644) == -1)
		goto out;
	kore_log(LOG_NOTICE, "made the jailgrid CA and the console's "
	    "certificate in %s", cfg.datadir);
	rc = 0;
out:
	X509_free(ca);
	X509_free(cert);
	EVP_PKEY_free(cakey);
	EVP_PKEY_free(key);
	return (rc);
}

/* A host name (letters, digits, '.', '-') or an IP address. */
static bool
valid_host(const char *s)
{
	unsigned char	a[16];
	size_t		len;

	len = strlen(s);
	if (len == 0 || len > 253)
		return (false);
	if (inet_pton(AF_INET, s, a) == 1 || inet_pton(AF_INET6, s, a) == 1)
		return (true);
	if (s[0] == '-' || s[0] == '.' || s[len - 1] == '.')
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && *s != '.' && *s != '-')
			return (false);
	return (true);
}

static struct etoken *
token_find(const char *value)
{
	time_t	now;
	int	i;

	now = time(NULL);
	for (i = 0; i < MAX_TOKENS; i++) {
		if (tokens[i].value[0] == '\0')
			continue;
		if (tokens[i].expires < now) {
			memset(&tokens[i], 0, sizeof(tokens[i]));
			continue;
		}
		if (strlen(value) == 64 && timingsafe_bcmp(tokens[i].value,
		    value, 64) == 0)
			return (&tokens[i]);
	}
	return (NULL);
}

/*
 * POST /api/enrol/tokens {name, host, port?}: a one-time token for a host
 * to join with, and the command to run there.
 */
int
api_enrol_tokens(struct http_request *req)
{
	struct etoken		*t;
	ucl_object_t		*body, *o;
	const ucl_object_t	*v;
	const char		*name, *host;
	uint8_t			 raw[32];
	char			 cmd[512];
	int64_t			 port;
	int			 i;

	if (!guard(req, true))
		return (KORE_RESULT_OK);
	if (cfg.tls_ca_key == NULL)
		return (reply_error(req, 409, "no_ca", "the console has no "
		    "CA key (tls.ca_key in web.conf); enrolment is off"));
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "bad_request",
		    "expected a JSON object"));
	name = ucl_str(body, "name");
	host = ucl_str(body, "host");
	port = (v = ucl_object_lookup(body, "port")) != NULL ?
	    ucl_object_toint(v) : DEFAULT_PORT;
	if (name == NULL || *name == '\0' || strlen(name) > 64 ||
	    host == NULL || !valid_host(host) || port < 1 || port > 65535) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "a name, the host's "
		    "name or address, and a port (default %d) are needed",
		    DEFAULT_PORT));
	}
	/* A free slot, else the one that expires first. */
	t = &tokens[0];
	for (i = 0; i < MAX_TOKENS; i++) {
		if (tokens[i].value[0] == '\0' || tokens[i].expires <
		    time(NULL)) {
			t = &tokens[i];
			break;
		}
		if (tokens[i].expires < t->expires)
			t = &tokens[i];
	}
	memset(t, 0, sizeof(*t));
	arc4random_buf(raw, sizeof(raw));
	for (i = 0; i < 32; i++)
		snprintf(t->value + i * 2, 3, "%02x", raw[i]);
	strlcpy(t->name, name, sizeof(t->name));
	strlcpy(t->host, host, sizeof(t->host));
	t->port = (int)port;
	t->expires = time(NULL) + TOKEN_TTL;
	ucl_object_unref(body);
	kore_log(LOG_NOTICE, "enrolment token for %s (%s) made", t->host,
	    t->name);

	/* Options first: getopt(3) stops at the first argument. */
	snprintf(cmd, sizeof(cmd), "jailgrid-enrol -s%s%s %s %s",
	    port != DEFAULT_PORT ? " -p " : "", port != DEFAULT_PORT ?
	    ucl_object_tostring_forced(v) : "", cfg.origin, t->value);
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(t->value), "token", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->host), "host", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->name), "name", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->port), "port", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(t->expires), "expires", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(cmd), "command", 0,
	    false);
	return (reply_json(req, 200, o));
}

/*
 * POST /api/enrol {token, csr}: no session; the token is the credential.
 * The certificate is for the host the token was made for, whatever the
 * request's subject says.  The host joins the server list.
 */
int
api_enrol(struct http_request *req)
{
	struct etoken		*t;
	ucl_object_t		*body, *o;
	X509_REQ		*csr;
	X509			*ca, *cert;
	EVP_PKEY		*cakey, *key;
	BIO			*b;
	const char		*token, *pem, *err;
	char			 san[300], uri[300], *s, *capem;
	unsigned char		 a[16];
	int			 status;

	csr = NULL;
	ca = cert = NULL;
	cakey = key = NULL;
	s = capem = NULL;
	o = NULL;
	status = 400;
	err = NULL;
	if (cfg.tls_ca_key == NULL)
		return (reply_error(req, 409, "no_ca", "enrolment is off"));
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "bad_request",
		    "expected a JSON object"));
	token = ucl_str(body, "token");
	pem = ucl_str(body, "csr");
	if (token == NULL || (t = token_find(token)) == NULL) {
		status = 403;
		err = "unknown or expired token";
		kore_log(LOG_NOTICE, "enrolment refused: %s", err);
		goto out;
	}
	if (pem == NULL || (b = BIO_new_mem_buf(pem, -1)) == NULL) {
		err = "a certificate request (csr) is needed";
		goto out;
	}
	csr = PEM_read_bio_X509_REQ(b, NULL, NULL, NULL);
	BIO_free(b);
	if (csr == NULL || (key = X509_REQ_get_pubkey(csr)) == NULL ||
	    X509_REQ_verify(csr, key) != 1) {
		err = "the certificate request does not check out";
		goto out;
	}
	if (EVP_PKEY_get_base_id(key) != EVP_PKEY_EC &&
	    EVP_PKEY_get_base_id(key) != EVP_PKEY_ED25519) {
		err = "the key must be EC or Ed25519";
		goto out;
	}
	if ((ca = read_cert(cfg.tls_ca)) == NULL ||
	    (cakey = read_key(cfg.tls_ca_key)) == NULL) {
		status = 500;
		err = "cannot read the CA";
		kore_log(LOG_ERR, "enrolment: cannot read %s or %s", cfg.tls_ca,
		    cfg.tls_ca_key);
		goto out;
	}
	snprintf(san, sizeof(san), "%s:%s", inet_pton(AF_INET, t->host, a) == 1
	    || inet_pton(AF_INET6, t->host, a) == 1 ? "IP" : "DNS", t->host);
	if ((cert = cert_new(key, t->host, ca, cakey, san, CERT_DAYS)) == NULL ||
	    (s = pem_string(cert)) == NULL || (capem = pem_string(ca)) == NULL) {
		status = 500;
		err = "cannot sign the certificate";
		kore_log(LOG_ERR, "enrolment: signing for %s: %s", t->host,
		    ssl_err());
		goto out;
	}
	/* The token is used up; the host is now a server. */
	snprintf(uri, sizeof(uri), strchr(t->host, ':') != NULL ?
	    "tcp://[%s]:%d" : "tcp://%s:%d", t->host, t->port);
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(s), "certificate", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(capem), "ca", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->host), "host", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(t->name), "name", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_frombool(servers_add(t->name, uri,
	    NULL) == 0), "added", 0, false);
	kore_log(LOG_NOTICE, "enrolled %s (%s) as %s", t->host, t->name, uri);
	memset(t, 0, sizeof(*t));
	status = 200;
out:
	free(s);
	free(capem);
	X509_REQ_free(csr);
	X509_free(ca);
	X509_free(cert);
	EVP_PKEY_free(cakey);
	EVP_PKEY_free(key);
	ucl_object_unref(body);
	if (status != 200)
		return (reply_error(req, status, "enrol", "%s", err));
	return (reply_json(req, 200, o));
}
