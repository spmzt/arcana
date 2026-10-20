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
 * with a one-time token made here by the logged-in user: arcana-enrol(8)
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
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "console.h"

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
static X509	*cert_make(EVP_PKEY *, const char *, X509 *, EVP_PKEY *,
		    const char *, const char *, int);
static int	 add_ext(X509 *, X509 *, int, const char *);
static int	 write_pem(const char *, X509 *, EVP_PKEY *, mode_t);
static EVP_PKEY	*read_key(const char *);
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

	return (cert_make(key, cn, issuer, ikey, san, san != NULL ? "agent" :
	    "console", days));
}

/*
 * A certificate: the CA's own when there is no issuer; else a leaf of
 * role (agent, or console), for a server too when it names a host (san).
 */
static X509 *
cert_make(EVP_PKEY *key, const char *cn, X509 *issuer, EVP_PKEY *ikey,
    const char *san, const char *role, int days)
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
		    "serverAuth,clientAuth" : "clientAuth") == 0 &&
		    add_ext(x, issuer, NID_authority_key_identifier,
		    "keyid:always") == 0;
		/*
		 * Its role: a host's may reach other hosts (the mesh) but
		 * not ask them as the console does; they tell it by this.
		 */
		if (san != NULL) {
			char	sanr[400];

			snprintf(sanr, sizeof(sanr), "%s,URI:urn:arcana:role:%s",
			    san, role);
			ok = ok && add_ext(x, issuer, NID_subject_alt_name,
			    sanr) == 0;
		} else
			ok = ok && add_ext(x, issuer, NID_subject_alt_name,
			    "URI:urn:arcana:role:console") == 0;
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

/*
 * data signed by the CA key (SHA-256, or Ed25519's own), for a host to
 * check against the CA it trusts: malloc(3)ed into *sigp, or NULL and
 * why not.  What the console sends to replace a host's program.
 */
const char *
pki_sign_data(const uint8_t *data, size_t len, uint8_t **sigp,
    size_t *siglenp)
{
	EVP_PKEY	*key;
	EVP_MD_CTX	*ctx;
	const char	*e;

	*sigp = NULL;
	*siglenp = 0;
	if (cfg.tls_ca_key == NULL || (key = read_key(cfg.tls_ca_key)) == NULL)
		return ("the console has no CA key (tls.ca_key) to sign with");
	e = NULL;
	if ((ctx = EVP_MD_CTX_new()) == NULL || EVP_DigestSignInit(ctx, NULL,
	    EVP_PKEY_id(key) == EVP_PKEY_ED25519 ? NULL : EVP_sha256(), NULL,
	    key) != 1 || EVP_DigestSign(ctx, NULL, siglenp, data, len) != 1 ||
	    (*sigp = malloc(*siglenp)) == NULL || EVP_DigestSign(ctx, *sigp,
	    siglenp, data, len) != 1) {
		free(*sigp);
		*sigp = NULL;
		e = "the console cannot sign with its CA key";
	}
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(key);
	return (e);
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
	    (ca = cert_new(cakey, "arcana CA", NULL, NULL, NULL,
	    CA_DAYS)) == NULL || (cert = cert_new(key, "arcana console", ca,
	    cakey, NULL, CA_DAYS)) == NULL) {
		kore_log(LOG_ERR, "making the CA: %s", ssl_err());
		goto out;
	}
	if (write_pem(path[1], NULL, cakey, 0600) == -1 ||
	    write_pem(path[0], ca, NULL, 0644) == -1 ||
	    write_pem(path[3], NULL, key, 0600) == -1 ||
	    write_pem(path[2], cert, NULL, 0644) == -1)
		goto out;
	kore_log(LOG_NOTICE, "made the arcana CA and the console's "
	    "certificate in %s", cfg.datadir);
	rc = 0;
out:
	X509_free(ca);
	X509_free(cert);
	EVP_PKEY_free(cakey);
	EVP_PKEY_free(key);
	return (rc);
}

/* Every certificate of a PEM file, or of PEM text, up to max. */
static int
certs_bio(BIO *b, X509 **v, int max)
{
	X509	*x;
	int	 n;

	n = 0;
	while (n < max && (x = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL)
		v[n++] = x;
	ERR_clear_error();
	return (n);
}

static int
certs_read(const char *path, X509 **v, int max)
{
	BIO	*b;
	int	 n;

	if ((b = BIO_new_file(path, "r")) == NULL) {
		ERR_clear_error();
		return (0);
	}
	n = certs_bio(b, v, max);
	BIO_free(b);
	return (n);
}

static int
certs_parse(const char *pem, X509 **v, int max)
{
	BIO	*b;
	int	 n;

	if (pem == NULL || (b = BIO_new_mem_buf(pem, -1)) == NULL)
		return (0);
	n = certs_bio(b, v, max);
	BIO_free(b);
	return (n);
}

static void
certs_free(X509 **v, int n)
{
	int	i;

	for (i = 0; i < n; i++)
		X509_free(v[i]);
}

static bool
self_signed(X509 *x)
{

	return (X509_check_issued(x, x) == X509_V_OK);
}

/*
 * ca, then the CA that issued it among all, and so on up to a root
 * (self-signed), which ends it.  Not taken: they are all's.
 */
static int
chain_up(X509 *ca, X509 **all, int n, X509 **out, int max)
{
	X509	*cur;
	int	 k, i;

	k = 0;
	out[k++] = ca;
	for (cur = ca; k < max && !self_signed(cur); ) {
		for (i = 0; i < n; i++)
			if (all[i] != cur && X509_check_issued(all[i], cur) ==
			    X509_V_OK)
				break;
		if (i == n)
			break;
		cur = out[k++] = all[i];
	}
	return (k);
}

/* The PEM of v, one after the other; the caller frees it. */
static char *
certs_pem(X509 **v, int n)
{
	BIO	*b;
	char	*s, *out;
	long	 len;
	int	 i;

	if ((b = BIO_new(BIO_s_mem())) == NULL)
		return (NULL);
	for (i = 0; i < n; i++)
		(void)PEM_write_bio_X509(b, v[i]);
	out = NULL;
	if ((len = BIO_get_mem_data(b, &s)) > 0 && (out = malloc((size_t)len +
	    1)) != NULL) {
		memcpy(out, s, (size_t)len);
		out[len] = '\0';
	}
	BIO_free(b);
	return (out);
}

#define	CERTS_MAX	32

/*
 * A certificate for a host's request, from the CA of cafile (its first
 * certificate) with keyfile: for host, whatever the request's subject
 * says, the CAs between it and the root after it.  PEM, to free; NULL
 * with why in err.  Any thread.
 */
static char *
sign_with(const char *cafile, const char *keyfile, const char *csrpem,
    const char *host, char *err, size_t errlen)
{
	X509_REQ	*csr;
	X509		*all[CERTS_MAX], *ch[CERTS_MAX], *cert;
	EVP_PKEY	*cakey, *key;
	BIO		*b;
	char		 san[300], *s;
	unsigned char	 a[16];
	int		 n, k;

	s = NULL;
	csr = NULL;
	cert = NULL;
	cakey = key = NULL;
	n = 0;
	if (keyfile == NULL) {
		snprintf(err, errlen, "the console has no CA key to sign with "
		    "(web.conf's tls block names none)");
		return (NULL);
	}
	if (csrpem == NULL || (b = BIO_new_mem_buf(csrpem, -1)) == NULL) {
		snprintf(err, errlen, "no certificate request");
		return (NULL);
	}
	csr = PEM_read_bio_X509_REQ(b, NULL, NULL, NULL);
	BIO_free(b);
	if (csr == NULL || (key = X509_REQ_get_pubkey(csr)) == NULL ||
	    X509_REQ_verify(csr, key) != 1 || (EVP_PKEY_get_base_id(key) !=
	    EVP_PKEY_EC && EVP_PKEY_get_base_id(key) != EVP_PKEY_ED25519)) {
		snprintf(err, errlen, "the host's request does not check out");
		goto out;
	}
	if ((n = certs_read(cafile, all, CERTS_MAX)) == 0 || (cakey =
	    read_key(keyfile)) == NULL) {
		snprintf(err, errlen, "cannot read the CA");
		goto out;
	}
	snprintf(san, sizeof(san), "%s:%s", inet_pton(AF_INET, host, a) == 1 ||
	    inet_pton(AF_INET6, host, a) == 1 ? "IP" : "DNS", host);
	if ((cert = cert_new(key, host, all[0], cakey, san, CERT_DAYS)) ==
	    NULL) {
		snprintf(err, errlen, "cannot sign: %s", ssl_err());
		goto out;
	}
	/* The leaf, then its CAs short of the root the host trusts. */
	ch[0] = cert;
	k = chain_up(all[0], all, n, ch + 1, CERTS_MAX - 1) + 1;
	if (k > 1 && self_signed(ch[k - 1]))
		k--;
	s = certs_pem(ch, k);
out:
	X509_REQ_free(csr);
	X509_free(cert);
	certs_free(all, n);
	EVP_PKEY_free(cakey);
	EVP_PKEY_free(key);
	return (s);
}

/* The same from the console's own CA. */
char *
pki_sign_host(const char *csrpem, const char *host, char *err, size_t errlen)
{

	return (sign_with(cfg.tls_ca, cfg.tls_ca_key, csrpem, host, err,
	    errlen));
}

/* The roots of a CA file: what a host is to trust; PEM, to free. */
static char *
anchors_pem(const char *path)
{
	X509	*all[CERTS_MAX], *r[CERTS_MAX];
	char	*s;
	int	 n, i, k;

	n = certs_read(path, all, CERTS_MAX);
	for (i = k = 0; i < n; i++)
		if (self_signed(all[i]))
			r[k++] = all[i];
	s = k > 0 ? certs_pem(r, k) : NULL;
	certs_free(all, n);
	return (s);
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
	char			 cmd[512], portstr[16];
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
	snprintf(portstr, sizeof(portstr), "%d", t->port);
	ucl_object_unref(body);
	kore_log(LOG_NOTICE, "enrolment token for %s (%s) made", t->host,
	    t->name);

	/* Options first: getopt(3) stops at the first argument. */
	snprintf(cmd, sizeof(cmd), "arcana-enrol -s%s%s %s %s",
	    port != DEFAULT_PORT ? " -p " : "", port != DEFAULT_PORT ?
	    portstr : "", cfg.origin, t->value);
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
	char			 why[300], uri[300], *s, *capem;
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
	/* Its certificate with the CAs short of the root; the roots for
	 * the host to trust (more than one while the CA is changed). */
	if ((s = sign_with(cfg.tls_ca, cfg.tls_ca_key, pem, t->host, why,
	    sizeof(why))) == NULL || (capem = anchors_pem(cfg.tls_ca)) ==
	    NULL) {
		status = 500;
		err = "cannot sign the certificate";
		kore_log(LOG_ERR, "enrolment: signing for %s: %s", t->host,
		    s == NULL ? why : "no root in the CA file");
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

/*
 * --- The CA changed ---------------------------------------------------
 *
 * The console's own CA (no tls block in web.conf) is changed for
 * another without a host left behind: the next one made here, imported
 * with its chain (the console as an intermediate CA under another), or
 * its request made here for another CA to sign; then rolled out: the
 * console trusts both, each host is given both to trust and a new
 * certificate from the next one, the console takes the next one's
 * certificate and key for its own; and finished: each host trusts the
 * next one alone, and so does the console.  The next one waits in
 * datadir/ca-next; what is done is in datadir/ca-state.json, read by
 * every request, written by the one thread that does it.
 */

#define	NEXT_DIR	"ca-next"
#define	CA_STATE	"ca-state.json"

static void		rm_next(void);
static pthread_mutex_t	ca_lock = PTHREAD_MUTEX_INITIALIZER;
static bool		ca_running;

static void
dpath(char *buf, size_t len, const char *name)
{

	snprintf(buf, len, "%s/%s", cfg.datadir, name);
}

static int
write_text(const char *path, const char *text, mode_t mode)
{
	char	tmp[MAXPATHLEN];
	size_t	len, off;
	ssize_t	n;
	int	fd;

	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
	if ((fd = mkstemp(tmp)) == -1)
		return (-1);
	len = strlen(text);
	for (off = 0; off < len; off += (size_t)n)
		if ((n = write(fd, text + off, len - off)) <= 0)
			break;
	if (off < len || fchmod(fd, mode) == -1 || fsync(fd) == -1 ||
	    close(fd) == -1 || rename(tmp, path) == -1) {
		unlink(tmp);
		return (-1);
	}
	return (0);
}

static char *
text_of(const char *path)
{
	FILE	*fp;
	char	*buf;
	size_t	 n;

	if ((fp = fopen(path, "r")) == NULL)
		return (NULL);
	if ((buf = calloc(1, 262145)) == NULL) {
		fclose(fp);
		return (NULL);
	}
	n = fread(buf, 1, 262144, fp);
	fclose(fp);
	if (n == 0 || n == 262144) {
		free(buf);
		return (NULL);
	}
	return (buf);
}

static int64_t
epoch_of(const ASN1_TIME *t)
{
	struct tm	tm;

	if (t == NULL || ASN1_TIME_to_tm(t, &tm) != 1)
		return (0);
	return ((int64_t)timegm(&tm));
}

static char *
name_text(const X509_NAME *n)
{
	BIO	*b;
	char	*p, *s;
	long	 len;

	if ((b = BIO_new(BIO_s_mem())) == NULL)
		return (strdup(""));
	X509_NAME_print_ex(b, n, 0, XN_FLAG_RFC2253);
	len = BIO_get_mem_data(b, &p);
	s = strndup(p, (size_t)len);
	BIO_free(b);
	return (s != NULL ? s : strdup(""));
}

static ucl_object_t *
cert_info(X509 *x)
{
	ucl_object_t	*o;
	unsigned char	 md[EVP_MAX_MD_SIZE];
	unsigned int	 n, i;
	char		 hex[EVP_MAX_MD_SIZE * 3 + 1], *t;

	o = ucl_object_typed_new(UCL_OBJECT);
	t = name_text(X509_get_subject_name(x));
	ucl_object_insert_key(o, ucl_object_fromstring(t), "subject", 0, false);
	free(t);
	t = name_text(X509_get_issuer_name(x));
	ucl_object_insert_key(o, ucl_object_fromstring(t), "issuer", 0, false);
	free(t);
	ucl_object_insert_key(o, ucl_object_fromint(epoch_of(
	    X509_get0_notAfter(x))), "not_after", 0, false);
	hex[0] = '\0';
	if (X509_digest(x, EVP_sha256(), md, &n) == 1)
		for (i = 0; i < n; i++)
			snprintf(hex + 3 * i, 4, "%02X%s", md[i], i + 1 < n ? ":" :
			    "");
	ucl_object_insert_key(o, ucl_object_fromstring(hex), "sha256", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_frombool(self_signed(x)),
	    "root", 0, false);
	return (o);
}

static ucl_object_t *
state_read(void)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	char			 path[MAXPATHLEN];

	dpath(path, sizeof(path), CA_STATE);
	o = NULL;
	if (access(path, F_OK) == 0) {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_file(p, path))
			o = ucl_parser_get_object(p);
		ucl_parser_free(p);
	}
	return (o != NULL ? o : ucl_object_typed_new(UCL_OBJECT));
}

static void
state_write(const ucl_object_t *o)
{
	char	path[MAXPATHLEN], *json;

	dpath(path, sizeof(path), CA_STATE);
	if ((json = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT)) != NULL)
		(void)write_text(path, json, 0600);
	free(json);
}

static void
state_set(ucl_object_t *st, const char *k, const char *v)
{

	ucl_object_replace_key(st, ucl_object_fromstring(v), k, 0, true);
}

/* One host's step, and what went wrong there; written at once. */
static void
host_state(ucl_object_t *st, const char *id, const char *name,
    const char *step, const char *why)
{
	ucl_object_t	*hs, *h;

	if ((hs = (ucl_object_t *)(uintptr_t)ucl_object_lookup(st, "hosts")) ==
	    NULL) {
		hs = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(st, hs, "hosts", 0, false);
	}
	h = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(h, ucl_object_fromstring(name), "name", 0, false);
	ucl_object_insert_key(h, ucl_object_fromstring(step), "step", 0, false);
	if (why != NULL)
		ucl_object_insert_key(h, ucl_object_fromstring(why), "error", 0,
		    false);
	ucl_object_replace_key(hs, h, id, 0, true);
	state_write(st);
}

/*
 * The next CA ready: its certificate and chain (ca.pem, up to its
 * root), its key, and the console's certificate from it with the CAs
 * short of the root after it (console.pem, console.key).
 */
static const char *
next_write(X509 *ca, X509 **chain, int nchain, EVP_PKEY *cakey)
{
	EVP_PKEY	*key;
	X509		*cert, *v[CERTS_MAX];
	char		 dir[MAXPATHLEN], path[MAXPATHLEN], *pem;
	int		 n, i;

	dpath(dir, sizeof(dir), NEXT_DIR);
	(void)mkdir(dir, 0700);
	if ((key = key_new()) == NULL || (cert = cert_new(key, "arcana console",
	    ca, cakey, NULL, CERT_DAYS)) == NULL) {
		EVP_PKEY_free(key);
		return ("cannot make the console's certificate");
	}
	v[0] = ca;
	for (i = 0, n = 1; i < nchain && n < CERTS_MAX; i++)
		v[n++] = chain[i];
	pem = certs_pem(v, n);
	snprintf(path, sizeof(path), "%s/ca.pem", dir);
	if (pem == NULL || write_text(path, pem, 0644) != 0)
		goto fail;
	free(pem);
	snprintf(path, sizeof(path), "%s/ca.key", dir);
	if (write_pem(path, NULL, cakey, 0600) != 0)
		goto fail2;
	snprintf(path, sizeof(path), "%s/console.key", dir);
	if (write_pem(path, NULL, key, 0600) != 0)
		goto fail2;
	/* Sent with the console's: the CAs short of the root. */
	v[0] = cert;
	v[1] = ca;
	for (i = 0, n = 2; i < nchain && n < CERTS_MAX; i++)
		v[n++] = chain[i];
	if (self_signed(v[n - 1]))
		n--;
	pem = certs_pem(v, n);
	snprintf(path, sizeof(path), "%s/console.pem", dir);
	if (pem == NULL || write_text(path, pem, 0644) != 0)
		goto fail;
	free(pem);
	X509_free(cert);
	EVP_PKEY_free(key);
	return (NULL);
fail:
	free(pem);
fail2:
	X509_free(cert);
	EVP_PKEY_free(key);
	return ("cannot write the next CA's files");
}

/* {"action":"make"}: a new CA of the console's own, self-signed. */
static const char *
ca_make(const char *cn)
{
	EVP_PKEY	*key;
	X509		*ca;
	const char	*e;

	if ((key = key_new()) == NULL || (ca = cert_new(key, cn, NULL, NULL,
	    NULL, CA_DAYS)) == NULL) {
		EVP_PKEY_free(key);
		return ("cannot make a CA");
	}
	e = next_write(ca, NULL, 0, key);
	X509_free(ca);
	EVP_PKEY_free(key);
	return (e);
}

/*
 * {"action":"request","cn"}: a key here and a request for another CA to
 * sign as an intermediate CA; imported with "import" once it is.
 */
static const char *
ca_request(const char *cn, char **csrp)
{
	EVP_PKEY	*key;
	X509_REQ	*rq;
	X509_NAME	*nm;
	X509V3_CTX	 ctx;
	STACK_OF(X509_EXTENSION) *exts;
	X509_EXTENSION	*ex;
	BIO		*b;
	char		 dir[MAXPATHLEN], path[MAXPATHLEN], *p;
	long		 len;
	int		 ok;

	*csrp = NULL;
	dpath(dir, sizeof(dir), NEXT_DIR);
	(void)mkdir(dir, 0700);
	if ((key = key_new()) == NULL || (rq = X509_REQ_new()) == NULL) {
		EVP_PKEY_free(key);
		return ("cannot make a key");
	}
	nm = X509_REQ_get_subject_name(rq);
	ok = X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_UTF8,
	    (const unsigned char *)cn, -1, -1, 0) == 1 &&
	    X509_REQ_set_pubkey(rq, key) == 1;
	/* Asked for as a CA: the signer may keep it or not. */
	exts = sk_X509_EXTENSION_new_null();
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, NULL, NULL, rq, NULL, 0);
	if (ok && exts != NULL && (ex = X509V3_EXT_conf_nid(NULL, &ctx,
	    NID_basic_constraints, "critical,CA:TRUE,pathlen:0")) != NULL)
		sk_X509_EXTENSION_push(exts, ex);
	if (ok && exts != NULL && (ex = X509V3_EXT_conf_nid(NULL, &ctx,
	    NID_key_usage, "critical,keyCertSign,cRLSign")) != NULL)
		sk_X509_EXTENSION_push(exts, ex);
	ok = ok && X509_REQ_add_extensions(rq, exts) == 1 &&
	    X509_REQ_sign(rq, key, EVP_sha256()) > 0;
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	snprintf(path, sizeof(path), "%s/request.key", dir);
	if (!ok || write_pem(path, NULL, key, 0600) != 0 || (b =
	    BIO_new(BIO_s_mem())) == NULL) {
		X509_REQ_free(rq);
		EVP_PKEY_free(key);
		return ("cannot make the request");
	}
	EVP_PKEY_free(key);
	(void)PEM_write_bio_X509_REQ(b, rq);
	X509_REQ_free(rq);
	len = BIO_get_mem_data(b, &p);
	*csrp = strndup(p, (size_t)len);
	BIO_free(b);
	snprintf(path, sizeof(path), "%s/request.csr", dir);
	if (*csrp == NULL || write_text(path, *csrp, 0644) != 0)
		return ("cannot keep the request");
	return (NULL);
}

/*
 * {"action":"import","cert","key"}: a CA to be the next one, its chain
 * after it up to its root; its key given, or the one of the request
 * made here.
 */
static const char *
ca_import(const char *certpem, const char *keypem)
{
	X509		*v[CERTS_MAX], *ch[CERTS_MAX];
	EVP_PKEY	*key;
	BIO		*b;
	char		 path[MAXPATHLEN];
	const char	*e;
	int		 n, k, i;

	if ((n = certs_parse(certpem, v, CERTS_MAX)) == 0)
		return ("no certificate");
	e = NULL;
	key = NULL;
	if (keypem != NULL && keypem[0] != '\0') {
		if ((b = BIO_new_mem_buf(keypem, -1)) != NULL) {
			key = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
			BIO_free(b);
		}
	} else {
		dpath(path, sizeof(path), NEXT_DIR "/request.key");
		key = read_key(path);
	}
	if (key == NULL)
		e = "no key: give the CA's, or make a request here first";
	else if (X509_check_ca(v[0]) < 1)
		e = "the first certificate is not a CA's";
	else if (X509_check_private_key(v[0], key) != 1)
		e = "the key is not the CA's";
	if (e == NULL) {
		k = chain_up(v[0], v, n, ch, CERTS_MAX);
		if (!self_signed(ch[k - 1]))
			e = "the chain does not reach a root: give the CAs "
			    "above it after it, up to the root";
		for (i = 1; e == NULL && i < k; i++)
			if (X509_check_ca(ch[i]) < 1)
				e = "a certificate of the chain is not a CA's";
		if (e == NULL)
			e = next_write(v[0], ch + 1, k - 1, key);
	}
	ERR_clear_error();
	EVP_PKEY_free(key);
	certs_free(v, n);
	if (e == NULL) {
		dpath(path, sizeof(path), NEXT_DIR "/request.key");
		(void)unlink(path);
		dpath(path, sizeof(path), NEXT_DIR "/request.csr");
		(void)unlink(path);
	}
	return (e);
}

/* An agent's tls call; its JSON, or NULL with why. */
static char *
host_tls(const char *uri, const char *peer, const char *verb,
    const char *cert, const char *ca, const char *mine, char *why,
    size_t wlen)
{
	struct arc_client	 cl;
	struct arc_tls_req	 rq;
	struct arc_tls_rsp	*rs;
	cbl_conn		*conn;
	cbl_tls			*tls;
	const char		*e;
	char			*out;
	int			 error;

	if ((e = hosts_connect(uri, peer, &conn, &tls, &cl)) != NULL) {
		snprintf(why, wlen, "%s", e);
		return (NULL);
	}
	memset(&rq, 0, sizeof(rq));
	rq.tls_verb = verb;
	rq.tls_cert = cert;
	rq.tls_ca = ca;
	rq.tls_peer = mine;
	out = NULL;
	if ((error = arc_tls(&cl, &rq, &rs)) != 0) {
		snprintf(why, wlen, "%s", strerror(error));
		hosts_release(uri, peer, conn, tls, &cl, false);
		return (NULL);
	}
	if (rs->ok && rs->json != NULL)
		out = strdup(rs->json);
	else
		snprintf(why, wlen, "%s", rs->error != NULL ? rs->error :
		    "refused");
	arc_tls_rsp_free(rs);
	hosts_release(uri, peer, conn, tls, &cl, true);
	return (out);
}

struct tlshost {
	char	 id[9];
	char	*name, *uri, *peer;
};

/* The hosts reached over TLS, copied: the list may change meanwhile. */
static int
tls_hosts(struct tlshost **vp)
{
	const struct server	*s;
	struct tlshost		*v;
	int			 i, n;

	for (n = 0; server_at(n) != NULL; n++)
		;
	if ((v = calloc((size_t)n + 1, sizeof(*v))) == NULL)
		abort();
	for (i = n = 0; (s = server_at(i)) != NULL; i++) {
		if (strncmp(s->uri, "unix:", 5) == 0)
			continue;
		strlcpy(v[n].id, s->id, sizeof(v[n].id));
		if ((v[n].name = strdup(s->name)) == NULL || (v[n].uri =
		    strdup(s->uri)) == NULL || (s->peer_name != NULL &&
		    (v[n].peer = strdup(s->peer_name)) == NULL))
			abort();
		n++;
	}
	*vp = v;
	return (n);
}

static void
hosts_free(struct tlshost *v, int n)
{
	int	i;

	for (i = 0; i < n; i++) {
		free(v[i].name);
		free(v[i].uri);
		free(v[i].peer);
	}
	free(v);
}

/* The host's part of its URI, as uri_host() in hosts.c reads it. */
static const char *
host_of(const char *uri, char *buf, size_t len)
{
	const char	*h, *e;

	h = strstr(uri, "://");
	h = h != NULL ? h + 3 : uri;
	if (*h == '[') {
		h++;
		e = strchr(h, ']');
	} else
		e = strrchr(h, ':');
	if (e == NULL)
		e = h + strlen(h);
	snprintf(buf, len, "%.*s", (int)(e - h), h);
	return (buf);
}

/* Two bundles' certificates as one, each once. */
static char *
bundle(const char *a, const char *b)
{
	X509		*v[CERTS_MAX * 2];
	unsigned char	 m1[EVP_MAX_MD_SIZE], m2[EVP_MAX_MD_SIZE];
	unsigned int	 l1, l2;
	char		*s;
	int		 n, k, i, j;

	n = certs_parse(a, v, CERTS_MAX);
	n += certs_parse(b, v + n, CERTS_MAX);
	for (i = k = 0; i < n; i++) {
		for (j = 0; j < k; j++)
			if (X509_digest(v[i], EVP_sha256(), m1, &l1) == 1 &&
			    X509_digest(v[j], EVP_sha256(), m2, &l2) == 1 &&
			    l1 == l2 && memcmp(m1, m2, l1) == 0)
				break;
		if (j < k)
			X509_free(v[i]);
		else
			v[k++] = v[i];
	}
	s = certs_pem(v, k);
	certs_free(v, k);
	return (s);
}

/*
 * The rollout: the console trusts both; each host trusts both and gets
 * its certificate from the next one; the console then is the next
 * one's.  Hosts that could not be reached are said so, and the
 * rollout may be run again for them.
 */
static void *
rollout_run(void *arg)
{
	struct tlshost	*hv;
	ucl_object_t	*st;
	char		 nca[MAXPATHLEN], nkey[MAXPATHLEN], ncon[MAXPATHLEN],
			 nconkey[MAXPATHLEN], why[400], hb[300], bak[MAXPATHLEN];
	char		*old_roots, *new_roots, *both, *mine, *j, *csr, *pem,
			*cur, *merged, *t;
	ucl_object_t	*o;
	int		 n, i, fails;

	st = state_read();
	dpath(nca, sizeof(nca), NEXT_DIR "/ca.pem");
	dpath(nkey, sizeof(nkey), NEXT_DIR "/ca.key");
	dpath(ncon, sizeof(ncon), NEXT_DIR "/console.pem");
	dpath(nconkey, sizeof(nconkey), NEXT_DIR "/console.key");
	old_roots = ucl_object_lookup(st, "old_roots") != NULL ?
	    strdup(ucl_object_tostring(ucl_object_lookup(st, "old_roots"))) :
	    anchors_pem(cfg.tls_ca);
	new_roots = anchors_pem(nca);
	if (old_roots == NULL || new_roots == NULL) {
		state_set(st, "error", "a CA without its root");
		goto out;
	}
	state_set(st, "old_roots", old_roots);
	state_set(st, "phase", "rolling");
	state_write(st);
	both = bundle(old_roots, new_roots);
	/* 1. The console trusts the next one too, hosts it signs. */
	if ((cur = text_of(cfg.tls_ca)) != NULL && (t = text_of(nca)) !=
	    NULL) {
		merged = bundle(cur, t);
		if (merged != NULL)
			(void)write_text(cfg.tls_ca, merged, 0644);
		free(merged);
		free(t);
	}
	free(cur);
	/* 2. Each host: both to trust, then its certificate. */
	mine = text_of(cfg.tls_cert);
	n = tls_hosts(&hv);
	fails = 0;
	for (i = 0; i < n; i++) {
		const ucl_object_t *h;

		/* Done in a run before: not again. */
		h = ucl_object_lookup(ucl_object_lookup(st, "hosts"), hv[i].id);
		if (h != NULL && strcmp(ucl_object_tostring(ucl_object_lookup(h,
		    "step")), "renewed") == 0)
			continue;
		j = host_tls(hv[i].uri, hv[i].peer, "install", NULL, both, mine,
		    why, sizeof(why));
		if (j == NULL) {
			host_state(st, hv[i].id, hv[i].name, "failed", why);
			fails++;
			continue;
		}
		free(j);
		csr = NULL;
		pem = NULL;
		if ((j = host_tls(hv[i].uri, hv[i].peer, "csr", NULL, NULL, NULL,
		    why, sizeof(why))) != NULL) {
			struct ucl_parser *p;

			p = ucl_parser_new(0);
			o = ucl_parser_add_string(p, j, 0) ?
			    ucl_parser_get_object(p) : NULL;
			ucl_parser_free(p);
			if (o != NULL && ucl_object_lookup(o, "csr") != NULL)
				csr = strdup(ucl_object_tostring(
				    ucl_object_lookup(o, "csr")));
			if (o != NULL)
				ucl_object_unref(o);
			free(j);
		}
		if (csr != NULL)
			pem = sign_with(nca, nkey, csr, host_of(hv[i].uri, hb,
			    sizeof(hb)), why, sizeof(why));
		free(csr);
		j = pem != NULL ? host_tls(hv[i].uri, hv[i].peer, "install", pem,
		    NULL, mine, why, sizeof(why)) : NULL;
		free(pem);
		if (j == NULL) {
			host_state(st, hv[i].id, hv[i].name, "failed", why);
			fails++;
			continue;
		}
		free(j);
		host_state(st, hv[i].id, hv[i].name, "renewed", NULL);
	}
	free(mine);
	/*
	 * 3. The console the next one's, the one before trusted still; not
	 * while a host would not trust it, unless forced: that host would
	 * be lost to the console.
	 */
	if (fails > 0 && arg == NULL) {
		snprintf(why, sizeof(why), "%d host%s not renewed: run it again "
		    "when they answer, or with force", fails, fails == 1 ? "" :
		    "s");
		state_set(st, "error", why);
	} else if ((cur = text_of(nca)) != NULL) {
		merged = bundle(cur, old_roots);
		snprintf(bak, sizeof(bak), "%s.before", cfg.tls_cert);
		(void)unlink(bak);
		(void)link(cfg.tls_cert, bak);
		snprintf(bak, sizeof(bak), "%s.before", cfg.tls_key);
		(void)unlink(bak);
		(void)link(cfg.tls_key, bak);
		snprintf(bak, sizeof(bak), "%s.before", cfg.tls_ca_key);
		(void)unlink(bak);
		(void)link(cfg.tls_ca_key, bak);
		if (merged == NULL || write_text(cfg.tls_ca, merged, 0644) != 0 ||
		    rename(nkey, cfg.tls_ca_key) != 0 || rename(nconkey,
		    cfg.tls_key) != 0 || rename(ncon, cfg.tls_cert) != 0)
			state_set(st, "error", "the console's files were not "
			    "all put in place");
		else
			state_set(st, "phase", "switched");
		free(merged);
		free(cur);
	} else {
		snprintf(why, sizeof(why), "%s: %s", nca, strerror(errno));
		state_set(st, "error", why);
	}
	/* New connections, with the console's new certificate. */
	for (i = 0; i < n; i++)
		hosts_forget(hv[i].uri);
	hosts_free(hv, n);
	free(both);
	thread_log(fails > 0 ? LOG_WARNING : LOG_NOTICE, "the CA rolled out, "
	    "%d hosts not reached", fails);
out:
	free(old_roots);
	free(new_roots);
	ucl_object_replace_key(st, ucl_object_frombool(false), "running", 0,
	    true);
	state_write(st);
	ucl_object_unref(st);
	pthread_mutex_lock(&ca_lock);
	ca_running = false;
	pthread_mutex_unlock(&ca_lock);
	return (NULL);
}

/*
 * The finish: each host trusts the new one alone, then the console;
 * a host not renewed is left as it is, unless forced.
 */
static void *
finish_run(void *arg)
{
	struct tlshost	*hv;
	ucl_object_t	*st;
	const ucl_object_t *h;
	char		 why[400], *roots, *mine, *j, *t;
	int		 n, i, fails;
	bool		 force;

	force = arg != NULL;
	st = state_read();
	roots = NULL;
	if ((t = text_of(cfg.tls_ca)) != NULL) {
		X509	*v[CERTS_MAX], *ch[CERTS_MAX];
		int	 k, m;

		/* The console's CA and its chain: the rest go. */
		m = certs_parse(t, v, CERTS_MAX);
		k = m > 0 ? chain_up(v[0], v, m, ch, CERTS_MAX) : 0;
		if (k > 0 && self_signed(ch[k - 1]))
			roots = certs_pem(ch + k - 1, 1);
		if (k > 0 && (j = certs_pem(ch, k)) != NULL) {
			free(t);
			t = j;
		}
		certs_free(v, m);
	}
	mine = text_of(cfg.tls_cert);
	n = tls_hosts(&hv);
	fails = 0;
	for (i = 0; roots != NULL && mine != NULL && i < n; i++) {
		h = ucl_object_lookup(ucl_object_lookup(st, "hosts"), hv[i].id);
		if (!force && (h == NULL || strcmp(ucl_object_tostring(
		    ucl_object_lookup(h, "step")), "renewed") != 0)) {
			fails++;
			continue;
		}
		if ((j = host_tls(hv[i].uri, hv[i].peer, "install", NULL, roots,
		    mine, why, sizeof(why))) == NULL) {
			host_state(st, hv[i].id, hv[i].name, "failed", why);
			fails++;
			continue;
		}
		free(j);
		host_state(st, hv[i].id, hv[i].name, "finished", NULL);
	}
	if (roots != NULL && t != NULL && (fails == 0 || force)) {
		(void)write_text(cfg.tls_ca, t, 0644);
		rm_next();
		state_set(st, "phase", "finished");
		thread_log(LOG_NOTICE, "the CA changed: the one before is "
		    "trusted no more");
	} else
		state_set(st, "error", "hosts not renewed: roll out again, or "
		    "finish with force");
	hosts_free(hv, n);
	free(roots);
	free(mine);
	free(t);
	ucl_object_replace_key(st, ucl_object_frombool(false), "running", 0,
	    true);
	state_write(st);
	ucl_object_unref(st);
	pthread_mutex_lock(&ca_lock);
	ca_running = false;
	pthread_mutex_unlock(&ca_lock);
	return (NULL);
}

/*
 * What there is: the CA now, the next one, the rollout's state.  Whether
 * a change runs is asked first: its thread writes all it changed before
 * it says it no longer runs, so once that is said, what is read after
 * is the end, never what was there before it.
 */
static ucl_object_t *
ca_view(void)
{
	ucl_object_t	*o, *arr, *st, *nx;
	X509		*v[CERTS_MAX];
	char		 path[MAXPATHLEN], *csr;
	int		 n, i;
	bool		 running;

	pthread_mutex_lock(&ca_lock);
	running = ca_running;
	pthread_mutex_unlock(&ca_lock);
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_frombool(cfg.tls_own), "own", 0,
	    false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	n = cfg.tls_ca != NULL ? certs_read(cfg.tls_ca, v, CERTS_MAX) : 0;
	for (i = 0; i < n; i++)
		ucl_array_append(arr, cert_info(v[i]));
	certs_free(v, n);
	ucl_object_insert_key(o, arr, "trusted", 0, false);
	if (cfg.tls_cert != NULL && (n = certs_read(cfg.tls_cert, v,
	    CERTS_MAX)) > 0) {
		ucl_object_insert_key(o, cert_info(v[0]), "console", 0, false);
		certs_free(v, n);
	}
	dpath(path, sizeof(path), NEXT_DIR "/ca.pem");
	if ((n = certs_read(path, v, CERTS_MAX)) > 0) {
		nx = ucl_object_typed_new(UCL_OBJECT);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < n; i++)
			ucl_array_append(arr, cert_info(v[i]));
		ucl_object_insert_key(nx, arr, "chain", 0, false);
		ucl_object_insert_key(o, nx, "next", 0, false);
		certs_free(v, n);
	}
	dpath(path, sizeof(path), NEXT_DIR "/request.csr");
	if ((csr = text_of(path)) != NULL) {
		ucl_object_insert_key(o, ucl_object_fromstring(csr), "request",
		    0, false);
		free(csr);
	}
	st = state_read();
	ucl_object_replace_key(st, ucl_object_frombool(running), "running", 0,
	    true);
	ucl_object_delete_key(st, "old_roots");
	ucl_object_insert_key(o, st, "state", 0, false);
	return (o);
}

static void
rm_next(void)
{
	static const char *const files[] = { "ca.pem", "ca.key", "console.pem",
	    "console.key", "request.key", "request.csr" };
	char	path[MAXPATHLEN];
	size_t	i;

	for (i = 0; i < nitems(files); i++) {
		snprintf(path, sizeof(path), "%s/%s/%s", cfg.datadir, NEXT_DIR,
		    files[i]);
		(void)unlink(path);
	}
	dpath(path, sizeof(path), NEXT_DIR);
	(void)rmdir(path);
}

/*
 * GET /api/ca: the CA now, the next one, the change's state.  POST
 * {"action": make | request | import | discard | rollout | finish}.
 */
int
api_ca(struct http_request *req)
{
	ucl_object_t	*body, *o, *st;
	pthread_t	 tid;
	const char	*act, *e, *cn, *phase;
	char		 path[MAXPATHLEN], *csr;
	bool		 busy, staged;

	if (!guard(req, req->method == HTTP_METHOD_POST))
		return (KORE_RESULT_OK);
	if (req->method == HTTP_METHOD_GET)
		return (reply_json(req, 200, ca_view()));
	if (!cfg.tls_own)
		return (reply_error(req, 409, "not_own", "web.conf's tls block "
		    "names the CA: it is changed there, not here"));
	if ((body = read_json(req)) == NULL || (act = ucl_str(body, "action")) ==
	    NULL) {
		if (body != NULL)
			ucl_object_unref(body);
		return (reply_error(req, 400, "bad_request", "an action"));
	}
	pthread_mutex_lock(&ca_lock);
	busy = ca_running;
	pthread_mutex_unlock(&ca_lock);
	st = state_read();
	phase = ucl_object_lookup(st, "phase") != NULL ? ucl_object_tostring(
	    ucl_object_lookup(st, "phase")) : "";
	dpath(path, sizeof(path), NEXT_DIR "/ca.pem");
	staged = access(path, F_OK) == 0;
	e = NULL;
	csr = NULL;
	cn = ucl_str(body, "cn") != NULL && ucl_str(body, "cn")[0] != '\0' ?
	    ucl_str(body, "cn") : "arcana CA";
	if (busy)
		e = "the CA is being changed: wait for it";
	else if (strlen(cn) > 64)
		e = "a name of 64 characters at most";
	else if (strcmp(act, "make") == 0 || strcmp(act, "request") == 0 ||
	    strcmp(act, "import") == 0) {
		if (strcmp(phase, "rolling") == 0 || strcmp(phase, "switched") ==
		    0)
			e = "a change is under way: finish it first";
		else if (strcmp(act, "make") == 0) {
			rm_next();
			e = ca_make(cn);
		} else if (strcmp(act, "request") == 0) {
			rm_next();
			e = ca_request(cn, &csr);
		} else
			e = ca_import(ucl_str(body, "cert"), ucl_str(body, "key"));
		if (e == NULL) {
			ucl_object_unref(st);
			st = ucl_object_typed_new(UCL_OBJECT);
			if (strcmp(act, "request") != 0)
				state_set(st, "phase", "staged");
			state_write(st);
		}
	} else if (strcmp(act, "discard") == 0) {
		if (strcmp(phase, "rolling") == 0 || strcmp(phase, "switched") ==
		    0)
			e = "a change is under way: finish it";
		else {
			rm_next();
			dpath(path, sizeof(path), CA_STATE);
			(void)unlink(path);
		}
	} else if (strcmp(act, "rollout") == 0 || strcmp(act, "finish") == 0) {
		if (strcmp(act, "rollout") == 0 && (!staged || strcmp(phase,
		    "switched") == 0))
			e = staged ? "rolled out already: finish it" : "no next "
			    "CA: make or import one first";
		else if (strcmp(act, "finish") == 0 && strcmp(phase,
		    "switched") != 0)
			e = "nothing rolled out to finish";
		else {
			pthread_mutex_lock(&ca_lock);
			ca_running = true;
			pthread_mutex_unlock(&ca_lock);
			state_set(st, "error", "");
			ucl_object_replace_key(st, ucl_object_frombool(true),
			    "running", 0, true);
			state_write(st);
			if (pthread_create(&tid, NULL, act[0] == 'r' ?
			    rollout_run : finish_run, ucl_object_toboolean(
			    ucl_object_lookup(body, "force")) ? (void *)1 :
			    NULL) != 0) {
				pthread_mutex_lock(&ca_lock);
				ca_running = false;
				pthread_mutex_unlock(&ca_lock);
				e = "cannot start it";
			} else
				(void)pthread_detach(tid);
		}
	} else
		e = "the action is make, request, import, discard, rollout or "
		    "finish";
	ucl_object_unref(st);
	ucl_object_unref(body);
	if (e != NULL) {
		free(csr);
		return (reply_error(req, 409, "ca", "%s", e));
	}
	o = ca_view();
	free(csr);
	return (reply_json(req, 200, o));
}

/*
 * A node of a cluster's certificate (cluster.c), signed by the CA: the
 * console's role, as a client of the agents and of the other nodes and
 * as their server, under the node's host name.  Made once, kept in
 * certpath and keypath.
 */
int
pki_node_cert(const char *host, const char *certpath, const char *keypath,
    char *err, size_t errlen)
{
	X509		*all[CERTS_MAX], *cert;
	EVP_PKEY	*key, *cakey;
	unsigned char	 a[16];
	char		 san[300], cn[300];
	int		 n, rc;

	if (access(certpath, F_OK) == 0 && access(keypath, F_OK) == 0)
		return (0);
	rc = -1;
	key = cakey = NULL;
	cert = NULL;
	n = 0;
	if (cfg.tls_ca_key == NULL) {
		snprintf(err, errlen, "no CA key to sign the node's certificate "
		    "with: copy the first node's ca.pem and ca.key here");
		return (-1);
	}
	if ((n = certs_read(cfg.tls_ca, all, CERTS_MAX)) == 0 || (cakey =
	    read_key(cfg.tls_ca_key)) == NULL) {
		snprintf(err, errlen, "cannot read the CA");
		goto out;
	}
	snprintf(san, sizeof(san), "%s:%s", inet_pton(AF_INET, host, a) == 1 ||
	    inet_pton(AF_INET6, host, a) == 1 ? "IP" : "DNS", host);
	snprintf(cn, sizeof(cn), "arcana console %s", host);
	if ((key = key_new()) == NULL || (cert = cert_make(key, cn, all[0],
	    cakey, san, "console", CERT_DAYS)) == NULL) {
		snprintf(err, errlen, "cannot sign: %s", ssl_err());
		goto out;
	}
	if (write_pem(keypath, NULL, key, 0600) == -1 || write_pem(certpath,
	    cert, NULL, 0644) == -1) {
		snprintf(err, errlen, "cannot write %s", certpath);
		goto out;
	}
	rc = 0;
out:
	X509_free(cert);
	certs_free(all, n);
	EVP_PKEY_free(cakey);
	EVP_PKEY_free(key);
	return (rc);
}
