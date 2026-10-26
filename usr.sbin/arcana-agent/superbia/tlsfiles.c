/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: the agent's own TLS files, those of -A, -C and -K, renewed
 * while it runs.  A new key is made here and never leaves the host; the
 * console signs a request for it and sends the certificate back, and
 * the CAs to trust when they change; the files are written whole, the
 * ones before kept beside, and cblink reads them again for the
 * connections made from then on.  The console that asks shows its own
 * certificate, and nothing is taken that would no longer trust it.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	TLS_CHAIN_MAX	8
#define	TLS_CA_MAX	64

static cbl_tls	*t_tls;
static char	 f_ca[MAXPATHLEN], f_cert[MAXPATHLEN], f_key[MAXPATHLEN];

/* The CA file the agent trusts, when it has one. */
const char *
tls_files_ca(void)
{

	return (f_ca[0] != '\0' ? f_ca : NULL);
}

/* The agent's own certificate and key, when it has them. */
const char *
tls_files_cert(void)
{

	return (f_cert[0] != '\0' ? f_cert : NULL);
}

const char *
tls_files_key(void)
{

	return (f_key[0] != '\0' ? f_key : NULL);
}

/* At the start: which files, and the context to read them again. */
void
tls_files_init(cbl_tls *tls, const char *ca, const char *cert,
    const char *key)
{

	t_tls = tls;
	if (realpath(ca, f_ca) == NULL)
		snprintf(f_ca, sizeof(f_ca), "%s", ca);
	if (realpath(cert, f_cert) == NULL)
		snprintf(f_cert, sizeof(f_cert), "%s", cert);
	if (realpath(key, f_key) == NULL)
		snprintf(f_key, sizeof(f_key), "%s", key);
}

/* Is path one of the agent's own TLS files, or one made beside it? */
bool
tls_file_is(const char *path)
{
	const char *const	 f[] = { f_ca, f_cert, f_key };
	char			 real[MAXPATHLEN];
	size_t			 i, n;

	if (realpath(path, real) == NULL)
		snprintf(real, sizeof(real), "%s", path);
	for (i = 0; i < nitems(f); i++) {
		n = strlen(f[i]);
		if (n > 0 && strncmp(real, f[i], n) == 0 && (real[n] == '\0' ||
		    strcmp(real + n, ".next") == 0 || strcmp(real + n,
		    ".before") == 0))
			return (true);
	}
	return (false);
}

static const char *
ssl_err(struct work *w)
{
	unsigned long	e;
	char		buf[256];

	if ((e = ERR_get_error()) == 0)
		return ("no reason given");
	ERR_error_string_n(e, buf, sizeof(buf));
	ERR_clear_error();
	return (wstrdup(w, buf));
}

/* Every certificate of PEM text, up to max; how many. */
static int
certs_of(const char *pem, size_t len, X509 **v, int max)
{
	BIO	*b;
	X509	*x;
	int	 n;

	if (pem == NULL || (b = BIO_new_mem_buf(pem, (int)len)) == NULL)
		return (0);
	n = 0;
	while (n < max && (x = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL)
		v[n++] = x;
	BIO_free(b);
	ERR_clear_error();
	return (n);
}

static void
certs_free(X509 **v, int n)
{
	int	i;

	for (i = 0; i < n; i++)
		X509_free(v[i]);
}

static char *
file_text(struct work *w, const char *path, size_t *lenp)
{
	struct stat	 st;
	char		*buf;
	ssize_t		 r;
	int		 fd;

	if ((fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK)) == -1)
		return (NULL);
	if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || st.st_size >
	    256 * 1024) {
		close(fd);
		return (NULL);
	}
	buf = wcalloc(w, 1, (size_t)st.st_size + 1);
	r = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (r != st.st_size)
		return (NULL);
	*lenp = (size_t)r;
	return (buf);
}

static int64_t
epoch(const ASN1_TIME *t)
{
	struct tm	tm;

	if (t == NULL || ASN1_TIME_to_tm(t, &tm) != 1)
		return (0);
	return ((int64_t)timegm(&tm));
}

static const char *
name_of(struct work *w, const X509_NAME *n)
{
	BIO	*b;
	char	*p;
	long	 len;
	const char *s;

	if ((b = BIO_new(BIO_s_mem())) == NULL)
		return ("");
	X509_NAME_print_ex(b, n, 0, XN_FLAG_RFC2253);
	len = BIO_get_mem_data(b, &p);
	s = wstrndup(w, p, (size_t)len);
	BIO_free(b);
	return (s);
}

static const char *
sha256_of(struct work *w, X509 *x)
{
	unsigned char	md[EVP_MAX_MD_SIZE];
	unsigned int	n, i;
	char		hex[EVP_MAX_MD_SIZE * 3];

	if (X509_digest(x, EVP_sha256(), md, &n) != 1)
		return ("");
	for (i = 0; i < n; i++)
		snprintf(hex + 3 * i, 4, "%02X%s", md[i], i + 1 < n ? ":" : "");
	return (wstrdup(w, hex));
}

static ucl_object_t *
cert_obj(struct work *w, X509 *x)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(name_of(w,
	    X509_get_subject_name(x))), "subject", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(name_of(w,
	    X509_get_issuer_name(x))), "issuer", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(epoch(
	    X509_get0_notBefore(x))), "not_before", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(epoch(
	    X509_get0_notAfter(x))), "not_after", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(sha256_of(w, x)),
	    "sha256", 0, false);
	return (o);
}

static const char *
pending_path(struct work *w)
{

	return (wfmt(w, "%s.next", f_key));
}

static ucl_object_t *
status(struct work *w)
{
	ucl_object_t	*top, *c, *arr;
	X509		*v[TLS_CA_MAX];
	const char	*t;
	size_t		 len;
	int		 n, i;

	top = ucl_object_typed_new(UCL_OBJECT);
	t = file_text(w, f_cert, &len);
	n = certs_of(t, t != NULL ? len : 0, v, TLS_CHAIN_MAX);
	if (n > 0) {
		c = cert_obj(w, v[0]);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (i = 1; i < n; i++)
			ucl_array_append(arr, cert_obj(w, v[i]));
		ucl_object_insert_key(c, arr, "chain", 0, false);
		ucl_object_insert_key(top, c, "cert", 0, false);
	}
	certs_free(v, n);
	t = file_text(w, f_ca, &len);
	n = certs_of(t, t != NULL ? len : 0, v, TLS_CA_MAX);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < n; i++)
		ucl_array_append(arr, cert_obj(w, v[i]));
	certs_free(v, n);
	ucl_object_insert_key(top, arr, "ca", 0, false);
	ucl_object_insert_key(top, ucl_object_frombool(access(pending_path(w),
	    F_OK) == 0), "pending", 0, false);
	return (top);
}

/* text as path, whole or not at all; the one before as path.before. */
static int
put_file(struct work *w, const char *path, const char *text, size_t len,
    mode_t mode, const char **errp)
{
	const char	*tmp, *before;
	size_t		 off;
	ssize_t		 n;
	int		 fd;

	tmp = wfmt(w, "%s.arcana-new", path);
	(void)unlink(tmp);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode)) ==
	    -1)
		goto fail;
	for (off = 0; off < len; off += (size_t)n)
		if ((n = write(fd, text + off, len - off)) <= 0) {
			close(fd);
			goto fail;
		}
	if (fsync(fd) == -1 || close(fd) == -1)
		goto fail;
	/* The one before kept, if there is one (none: ENOENT). */
	before = wfmt(w, "%s.before", path);
	(void)unlink(before);
	if (link(path, before) == -1 && errno != ENOENT)
		goto fail;
	if (rename(tmp, path) == -1)
		goto fail;
	return (0);
fail:
	*errp = wfmt(w, "%s: %s", path, strerror(errno));
	(void)unlink(tmp);
	return (-1);
}

static void
put_back(struct work *w, const char *path)
{
	const char	*before;

	/* None kept (ENOENT): what is there stays. */
	before = wfmt(w, "%s.before", path);
	(void)rename(before, path);
}

/* A new key beside the host's, and a request for it named as the host. */
static int
csr(struct work *w, ucl_object_t **outp, const char **errp)
{
	EVP_PKEY	*key;
	X509_REQ	*rq;
	X509		*v[1];
	X509_NAME	*nm;
	BIO		*b;
	const char	*t, *cn;
	char		*p, cnbuf[256];
	long		 len;
	size_t		 flen;
	int		 fd, ok;
	FILE		*fp;

	cn = "arcana-agent";
	t = file_text(w, f_cert, &flen);
	if (certs_of(t, t != NULL ? flen : 0, v, 1) == 1) {
		if (X509_NAME_get_text_by_NID(X509_get_subject_name(v[0]),
		    NID_commonName, cnbuf, sizeof(cnbuf)) > 0)
			cn = wstrdup(w, cnbuf);
		X509_free(v[0]);
	}
	if ((key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")) == NULL) {
		*errp = wfmt(w, "a key: %s", ssl_err(w));
		return (-1);
	}
	(void)unlink(pending_path(w));
	if ((fd = open(pending_path(w), O_WRONLY | O_CREAT | O_EXCL |
	    O_CLOEXEC, 0600)) == -1 || (fp = fdopen(fd, "w")) == NULL) {
		*errp = wfmt(w, "%s: %s", pending_path(w), strerror(errno));
		if (fd != -1)
			close(fd);
		EVP_PKEY_free(key);
		return (-1);
	}
	ok = PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL) == 1;
	if (fclose(fp) != 0 || !ok) {
		*errp = wfmt(w, "%s: not written", pending_path(w));
		(void)unlink(pending_path(w));
		EVP_PKEY_free(key);
		return (-1);
	}
	rq = X509_REQ_new();
	nm = X509_REQ_get_subject_name(rq);
	ok = rq != NULL && X509_REQ_set_version(rq, 0) == 1 &&
	    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_UTF8,
	    (const unsigned char *)cn, -1, -1, 0) == 1 &&
	    X509_REQ_set_pubkey(rq, key) == 1 &&
	    X509_REQ_sign(rq, key, EVP_sha256()) > 0;
	EVP_PKEY_free(key);
	if (!ok || (b = BIO_new(BIO_s_mem())) == NULL ||
	    PEM_write_bio_X509_REQ(b, rq) != 1) {
		*errp = wfmt(w, "the request: %s", ssl_err(w));
		X509_REQ_free(rq);
		return (-1);
	}
	X509_REQ_free(rq);
	len = BIO_get_mem_data(b, &p);
	*outp = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(*outp, ucl_object_fromlstring(p, (size_t)len),
	    "csr", 0, false);
	ucl_object_insert_key(*outp, ucl_object_fromstring(cn), "cn", 0,
	    false);
	BIO_free(b);
	return (0);
}

/* Does chain[0] verify with the CAs ca, as purpose says? */
static const char *
verify(struct work *w, X509 **chain, int nchain, X509 **ca, int nca,
    int purpose)
{
	X509_STORE	*st;
	X509_STORE_CTX	*cx;
	STACK_OF(X509)	*un;
	const char	*why;
	int		 i;

	why = NULL;
	st = X509_STORE_new();
	cx = X509_STORE_CTX_new();
	un = sk_X509_new_null();
	for (i = 0; i < nca; i++)
		X509_STORE_add_cert(st, ca[i]);
	for (i = 1; i < nchain; i++)
		sk_X509_push(un, chain[i]);
	if (st == NULL || cx == NULL || un == NULL ||
	    X509_STORE_CTX_init(cx, st, chain[0], un) != 1)
		why = "cannot verify";
	else {
		X509_STORE_CTX_set_purpose(cx, purpose);
		if (X509_verify_cert(cx) != 1)
			why = wstrdup(w, X509_verify_cert_error_string(
			    X509_STORE_CTX_get_error(cx)));
	}
	sk_X509_free(un);
	X509_STORE_CTX_free(cx);
	X509_STORE_free(st);
	ERR_clear_error();
	return (why);
}

static int
install(struct work *w, const char *certpem, const char *capem,
    const char *peerpem, const uint8_t *peerfp, const char **errp)
{
	X509		*leaf[TLS_CHAIN_MAX], *ca[TLS_CA_MAX], *peer[TLS_CHAIN_MAX];
	EVP_PKEY	*key;
	FILE		*fp;
	const char	*t, *why, *keytext;
	unsigned char	 md[EVP_MAX_MD_SIZE];
	unsigned int	 mdlen;
	size_t		 len, klen;
	int		 nleaf, nca, npeer, i, rc;
	bool		 wrote_cert, wrote_ca;

	nleaf = nca = npeer = 0;
	rc = -1;
	keytext = NULL;
	klen = 0;
	if ((certpem == NULL || certpem[0] == '\0') && (capem == NULL ||
	    capem[0] == '\0')) {
		*errp = "install has a certificate, CAs or both";
		return (-1);
	}
	/* The CAs to trust: given, or those trusted now. */
	if (capem != NULL && capem[0] != '\0')
		nca = certs_of(capem, strlen(capem), ca, TLS_CA_MAX);
	else if ((t = file_text(w, f_ca, &len)) != NULL)
		nca = certs_of(t, len, ca, TLS_CA_MAX);
	if (nca == 0) {
		*errp = "no CA certificate among them";
		goto out;
	}
	for (i = 0; i < nca; i++)
		if (X509_check_ca(ca[i]) < 1) {
			*errp = wfmt(w, "%s is not a CA", name_of(w,
			    X509_get_subject_name(ca[i])));
			goto out;
		}
	/* The console that asks: its own, and trusted afterwards still. */
	npeer = peerpem != NULL ? certs_of(peerpem, strlen(peerpem), peer,
	    TLS_CHAIN_MAX) : 0;
	if (peerfp != NULL) {
		if (npeer == 0 || X509_digest(peer[0], EVP_sha256(), md,
		    &mdlen) != 1 || mdlen != 32 || memcmp(md, peerfp, 32) !=
		    0) {
			*errp = "tls-peer is not the certificate of the console "
			    "that asks";
			goto out;
		}
	}
	if (npeer > 0 && (why = verify(w, peer, npeer, ca, nca,
	    X509_PURPOSE_SSL_CLIENT)) != NULL) {
		*errp = wfmt(w, "the console's own certificate would not be "
		    "trusted any more (%s): nothing changed", why);
		goto out;
	}
	if (certpem != NULL && certpem[0] != '\0') {
		if ((nleaf = certs_of(certpem, strlen(certpem), leaf,
		    TLS_CHAIN_MAX)) == 0) {
			*errp = "tls-cert has no certificate";
			goto out;
		}
		if ((keytext = file_text(w, pending_path(w), &klen)) == NULL) {
			*errp = "no key waits for a certificate: csr first";
			goto out;
		}
		if ((fp = fopen(pending_path(w), "r")) == NULL ||
		    (key = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
			if (fp != NULL)
				fclose(fp);
			*errp = wfmt(w, "%s: not a key", pending_path(w));
			goto out;
		}
		fclose(fp);
		i = X509_check_private_key(leaf[0], key);
		EVP_PKEY_free(key);
		if (i != 1) {
			ERR_clear_error();
			*errp = "the certificate is not for the key that waits";
			goto out;
		}
		if ((why = verify(w, leaf, nleaf, ca, nca,
		    X509_PURPOSE_SSL_SERVER)) != NULL) {
			*errp = wfmt(w, "the certificate does not verify with "
			    "the CAs: %s", why);
			goto out;
		}
	}
	/* Written: the CAs, the certificate, its key; then read again. */
	wrote_cert = wrote_ca = false;
	if (capem != NULL && capem[0] != '\0') {
		if (put_file(w, f_ca, capem, strlen(capem), 0644, errp) != 0)
			goto out;
		wrote_ca = true;
	}
	if (nleaf > 0) {
		if (put_file(w, f_cert, certpem, strlen(certpem), 0644,
		    errp) != 0 || put_file(w, f_key, keytext, klen, 0600,
		    errp) != 0) {
			put_back(w, f_cert);
			if (wrote_ca)
				put_back(w, f_ca);
			goto out;
		}
		wrote_cert = true;
	}
	if (t_tls != NULL && cbl_tls_reload(t_tls) != 0) {
		*errp = wfmt(w, "read again, refused: %s; the files before put "
		    "back", cbl_tls_errstr(t_tls));
		if (wrote_cert) {
			put_back(w, f_cert);
			put_back(w, f_key);
		}
		if (wrote_ca)
			put_back(w, f_ca);
		(void)cbl_tls_reload(t_tls);
		goto out;
	}
	if (wrote_cert)
		(void)unlink(pending_path(w));
	rc = 0;
out:
	if (keytext != NULL)
		explicit_bzero((char *)(uintptr_t)keytext, klen);
	certs_free(leaf, nleaf);
	certs_free(ca, nca);
	certs_free(peer, npeer);
	return (rc);
}

void
do_tls(struct work *w, const char *verb, const char *certpem,
    const char *capem, const char *peerpem, const uint8_t *peerfp,
    struct arc_tls_rsp *rsp)
{
	ucl_object_t	*o;
	const char	*e;
	char		*json;
	int		 step;

	rsp->has_ok = true;
	rsp->ok = false;
	e = NULL;
	o = NULL;
	if (f_cert[0] == '\0') {
		rsp->error = "this agent has no TLS files: it listens on a "
		    "local socket only";
		return;
	}
	step = step_begin(w, ARC_STEP_KIND_LIB, "OpenSSL", "tls %s", verb);
	if (strcmp(verb, "status") == 0)
		o = status(w);
	else if (strcmp(verb, "csr") == 0) {
		if (csr(w, &o, &e) != 0)
			o = NULL;
	} else if (strcmp(verb, "install") == 0) {
		if (install(w, certpem, capem, peerpem, peerfp, &e) == 0)
			o = status(w);
	} else
		e = "tls: status, csr or install";
	step_end(w, step, o != NULL, "%s", e != NULL ? e : "done");
	if (o == NULL) {
		rsp->error = e;
		return;
	}
	json = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	rsp->json = json != NULL ? wtext(w, wstrdup(w, json)) : NULL;
	free(json);
	rsp->ok = rsp->json != NULL;
}
