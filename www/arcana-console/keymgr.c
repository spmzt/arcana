/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The HTTPS key kept out of the worker.  A process of its own, the key
 * manager, is forked by the worker while it is still root and before it
 * has read anything of the key: it reads the key, becomes the console's
 * user, enters capability mode (capsicum(4)) and from then on only
 * signs the digests the worker sends it on a socket pair.  The worker
 * gives libwebsockets a key of an OpenSSL provider of its own whose
 * keys are public halves: hashing what TLS signs is done there, the
 * digest's signature asked of the key manager.  A flaw that discloses
 * the worker's memory discloses no key.
 *
 * RSA (PKCS #1 v1.5 and PSS) and EC keys; TLS 1.2's key exchange is
 * ECDHE alone, as a static RSA one would ask for decryption.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/socket.h>

#include <errno.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "web.h"
#include "keymgr.h"

#define	KM_PROV		"arcana-keymgr"
#define	KM_DGST_MAX	64		/* SHA-512 */
#define	KM_SIG_MAX	1024		/* RSA 8192 */

/* What the worker asks, and what it is told. */
struct kreq {
	char		md[32];
	char		mgf1[32];
	int32_t		pad;
	int32_t		saltlen;
	uint32_t	dlen;
	uint8_t		dgst[KM_DGST_MAX];
};

struct krsp {
	int32_t		ok;
	uint32_t	siglen;
	uint8_t		sig[KM_SIG_MAX];
};

static int		kfd = -1;	/* the worker's end */
static pthread_mutex_t	klock = PTHREAD_MUTEX_INITIALIZER;
static OSSL_LIB_CTX	*kctx;		/* the provider's alone */

/* ---------------------------------------------------------------- */
/* The key manager. */

static const char *
ssl_error(void)
{
	static char	buf[256];
	unsigned long	e;

	if ((e = ERR_get_error()) == 0)
		return ("no reason given");
	ERR_error_string_n(e, buf, sizeof(buf));
	return (buf);
}

/* One signature, of the digest in r, with key. */
static void
km_sign(EVP_PKEY *key, const struct kreq *r, struct krsp *o)
{
	EVP_PKEY_CTX	*c;
	EVP_MD		*md, *mgf1;
	size_t		 len;

	memset(o, 0, sizeof(*o));
	md = mgf1 = NULL;
	if ((c = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)) == NULL)
		return;
	if (r->dlen == 0 || r->dlen > KM_DGST_MAX ||
	    memchr(r->md, '\0', sizeof(r->md)) == NULL ||
	    memchr(r->mgf1, '\0', sizeof(r->mgf1)) == NULL ||
	    (md = EVP_MD_fetch(NULL, r->md, NULL)) == NULL ||
	    (size_t)EVP_MD_get_size(md) != r->dlen ||
	    EVP_PKEY_sign_init(c) <= 0 ||
	    EVP_PKEY_CTX_set_signature_md(c, md) <= 0)
		goto out;
	if (EVP_PKEY_is_a(key, "RSA")) {
		if (r->pad != RSA_PKCS1_PADDING && r->pad !=
		    RSA_PKCS1_PSS_PADDING)
			goto out;
		if (EVP_PKEY_CTX_set_rsa_padding(c, r->pad) <= 0)
			goto out;
		if (r->pad == RSA_PKCS1_PSS_PADDING) {
			if ((mgf1 = EVP_MD_fetch(NULL, r->mgf1[0] != '\0' ?
			    r->mgf1 : r->md, NULL)) == NULL ||
			    EVP_PKEY_CTX_set_rsa_pss_saltlen(c, r->saltlen) <=
			    0 || EVP_PKEY_CTX_set_rsa_mgf1_md(c, mgf1) <= 0)
				goto out;
		}
	}
	len = sizeof(o->sig);
	if (EVP_PKEY_sign(c, o->sig, &len, r->dgst, r->dlen) > 0) {
		o->ok = 1;
		o->siglen = (uint32_t)len;
	}
out:
	EVP_MD_free(md);
	EVP_MD_free(mgf1);
	EVP_PKEY_CTX_free(c);
}

/* The key manager's life: the key read and checked against the
 * certificate, the rest sealed off, then signatures until the worker
 * goes.  Its first message is "" or what is wrong. */
static void __dead2
km_main(int fd, const char *certfile, const char *keyfile, const char *user)
{
	struct passwd	*pw;
	struct kreq	 r;
	struct krsp	 o;
	cap_rights_t	 rights;
	EVP_PKEY	*key;
	X509		*cert;
	FILE		*fp;
	char		 why[512];
	ssize_t		 n;

	setproctitle("keymgr");
	/* Not the worker's handlers: a TERM ends it. */
	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	why[0] = '\0';
	key = NULL;
	cert = NULL;
	if ((fp = fopen(keyfile, "r")) == NULL)
		snprintf(why, sizeof(why), "certkey %s: %s", keyfile,
		    strerror(errno));
	else {
		key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
		fclose(fp);
		if (key == NULL)
			snprintf(why, sizeof(why), "certkey %s: not a key: %s",
			    keyfile, ssl_error());
	}
	if (why[0] == '\0' && !EVP_PKEY_is_a(key, "RSA") &&
	    !EVP_PKEY_is_a(key, "EC"))
		snprintf(why, sizeof(why), "certkey %s: neither RSA nor EC",
		    keyfile);
	if (why[0] == '\0') {
		if ((fp = fopen(certfile, "r")) == NULL ||
		    (cert = PEM_read_X509(fp, NULL, NULL, NULL)) == NULL)
			snprintf(why, sizeof(why), "certfile %s: not read",
			    certfile);
		else if (EVP_PKEY_eq(X509_get0_pubkey(cert), key) != 1)
			snprintf(why, sizeof(why), "certkey %s is not the key "
			    "of certfile %s", keyfile, certfile);
		if (fp != NULL)
			fclose(fp);
		X509_free(cert);
	}
	/* The worker's user, by the setuid of root: same uid, but it may
	 * not debug a process that changed its credentials. */
	if (why[0] == '\0' && geteuid() == 0 && user[0] != '\0') {
		if ((pw = getpwnam(user)) == NULL || initgroups(pw->pw_name,
		    pw->pw_gid) == -1 || setgid(pw->pw_gid) == -1 ||
		    setuid(pw->pw_uid) == -1)
			snprintf(why, sizeof(why), "keymgr: cannot become %s",
			    user);
	}
	/* Everything is loaded before the seal: one signature first. */
	if (why[0] == '\0') {
		memset(&r, 0, sizeof(r));
		strlcpy(r.md, "SHA256", sizeof(r.md));
		r.pad = RSA_PKCS1_PADDING;
		r.dlen = 32;
		km_sign(key, &r, &o);
		if (!o.ok)
			snprintf(why, sizeof(why), "certkey %s does not sign: "
			    "%s", keyfile, ssl_error());
	}
	cap_rights_init(&rights, CAP_READ, CAP_WRITE);
	if (why[0] == '\0' && (cap_rights_limit(fd, &rights) == -1 ||
	    cap_enter() == -1))
		snprintf(why, sizeof(why), "keymgr: capability mode: %s",
		    strerror(errno));
	(void)write(fd, why, strlen(why) + 1);
	if (why[0] != '\0')
		_exit(1);
	for (;;) {
		if ((n = read(fd, &r, sizeof(r))) != (ssize_t)sizeof(r))
			_exit(n == 0 ? 0 : 1);
		km_sign(key, &r, &o);
		explicit_bzero(&r, sizeof(r));
		if (write(fd, &o, sizeof(o)) != (ssize_t)sizeof(o))
			_exit(1);
	}
}

int
keymgr_start(const char *certfile, const char *keyfile, const char *user,
    const int *keep_closed, int nclosed)
{
	char	why[512];
	pid_t	pid;
	ssize_t	n;
	int	sp[2], i;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sp) == -1) {
		log_msg(LOG_ERR, "keymgr: socketpair: %s", strerror(errno));
		return (-1);
	}
	if ((pid = fork()) == -1) {
		log_msg(LOG_ERR, "keymgr: fork: %s", strerror(errno));
		close(sp[0]);
		close(sp[1]);
		return (-1);
	}
	if (pid == 0) {
		close(sp[0]);
		for (i = 0; i < nclosed; i++)
			close(keep_closed[i]);
		km_main(sp[1], certfile, keyfile, user);
	}
	close(sp[1]);
	kfd = sp[0];
	if ((n = read(kfd, why, sizeof(why) - 1)) <= 0) {
		log_msg(LOG_ERR, "keymgr: ended at once");
		return (-1);
	}
	why[n] = '\0';
	if (why[0] != '\0') {
		log_msg(LOG_ERR, "%s", why);
		return (-1);
	}
	return (0);
}

/* The digest's signature, from the key manager; false for none. */
static bool
keymgr_ask(const char *md, const char *mgf1, int pad, int saltlen,
    const unsigned char *dgst, size_t dlen, unsigned char *sig,
    size_t *siglen, size_t sigsize)
{
	struct kreq	r;
	struct krsp	o;
	bool		ok;

	if (dlen > KM_DGST_MAX)
		return (false);
	memset(&r, 0, sizeof(r));
	strlcpy(r.md, md, sizeof(r.md));
	strlcpy(r.mgf1, mgf1 != NULL ? mgf1 : "", sizeof(r.mgf1));
	r.pad = pad;
	r.saltlen = saltlen;
	r.dlen = (uint32_t)dlen;
	memcpy(r.dgst, dgst, dlen);
	pthread_mutex_lock(&klock);
	ok = write(kfd, &r, sizeof(r)) == (ssize_t)sizeof(r) &&
	    read(kfd, &o, sizeof(o)) == (ssize_t)sizeof(o);
	pthread_mutex_unlock(&klock);
	if (!ok) {
		/* Without it no handshake ends: the supervisor starts both
		 * again. */
		log_msg(LOG_ERR, "keymgr: gone: starting again");
		_exit(1);
	}
	if (!o.ok || o.siglen > sigsize)
		return (false);
	memcpy(sig, o.sig, o.siglen);
	*siglen = o.siglen;
	return (true);
}

/* ---------------------------------------------------------------- */
/* The worker's provider: keys that are public halves, signatures that
 * are the key manager's. */

struct kkey {
	int		 rsa;		/* else EC */
	EVP_PKEY	*pub;		/* the default provider's */
};

struct ksig {
	struct kkey	*key;
	EVP_MD_CTX	*mdctx;
	char		 md[32];
	char		 mgf1[32];
	int		 pad;
	int		 saltlen;
};

static EVP_KEYMGMT	*def_rsa, *def_ec;

static void *
kk_new(int rsa)
{
	struct kkey	*k;

	if ((k = calloc(1, sizeof(*k))) != NULL)
		k->rsa = rsa;
	return (k);
}

static void *kk_new_rsa(void *p) { (void)p; return (kk_new(1)); }
static void *kk_new_ec(void *p) { (void)p; return (kk_new(0)); }

static void
kk_free(void *v)
{
	struct kkey	*k = v;

	if (k == NULL)
		return;
	EVP_PKEY_free(k->pub);
	free(k);
}

static void *
kk_dup(const void *v, int selection)
{
	const struct kkey	*k = v;
	struct kkey		*d;

	(void)selection;
	if ((d = kk_new(k->rsa)) != NULL && k->pub != NULL &&
	    EVP_PKEY_up_ref(k->pub))
		d->pub = k->pub;
	return (d);
}

/* It has what the public half has, and says it has the private one. */
static int
kk_has(const void *v, int selection)
{
	const struct kkey	*k = v;

	(void)selection;
	return (k != NULL && k->pub != NULL);
}

static int
kk_import(void *v, int selection, const OSSL_PARAM params[])
{
	struct kkey	*k = v;
	EVP_PKEY_CTX	*c;
	int		 ok;

	(void)selection;
	if ((c = EVP_PKEY_CTX_new_from_name(NULL, k->rsa ? "RSA" : "EC",
	    "provider=default")) == NULL)
		return (0);
	EVP_PKEY_free(k->pub);
	k->pub = NULL;
	ok = EVP_PKEY_fromdata_init(c) > 0 && EVP_PKEY_fromdata(c, &k->pub,
	    EVP_PKEY_PUBLIC_KEY, (OSSL_PARAM *)(uintptr_t)params) > 0;
	EVP_PKEY_CTX_free(c);
	return (ok);
}

/*
 * Not exported: OpenSSL looks for a signature in the SSL_CTX's library
 * context first, and would sign there with an export of this key,
 * which has no private half.  Refused, it signs with this provider's.
 * (A comparison with the certificate's key imports that one here.)
 */
static int
kk_export(void *v, int selection, OSSL_CALLBACK *cb, void *arg)
{

	(void)v;
	(void)selection;
	(void)cb;
	(void)arg;
	return (0);
}

static const OSSL_PARAM kk_rsa_types[] = {
	OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
	OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
	OSSL_PARAM_END
};
static const OSSL_PARAM kk_ec_types[] = {
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
	OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
	    NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *
kk_types_rsa(int selection)
{
	(void)selection;
	return (kk_rsa_types);
}

static const OSSL_PARAM *
kk_types_ec(int selection)
{
	(void)selection;
	return (kk_ec_types);
}

static int
kk_get_params(void *v, OSSL_PARAM params[])
{
	struct kkey	*k = v;

	return (k->pub != NULL && EVP_PKEY_get_params(k->pub, params));
}

static const OSSL_PARAM *
kk_gettable_rsa(void *p)
{
	(void)p;
	return (EVP_KEYMGMT_gettable_params(def_rsa));
}

static const OSSL_PARAM *
kk_gettable_ec(void *p)
{
	(void)p;
	return (EVP_KEYMGMT_gettable_params(def_ec));
}

static int
kk_match(const void *a, const void *b, int selection)
{
	const struct kkey	*x = a, *y = b;

	(void)selection;
	return (x->pub != NULL && y->pub != NULL && EVP_PKEY_eq(x->pub,
	    y->pub) == 1);
}

static const char *
kk_opname_rsa(int op)
{
	return (op == OSSL_OP_SIGNATURE ? "RSA" : NULL);
}

static const char *
kk_opname_ec(int op)
{
	return (op == OSSL_OP_SIGNATURE ? "ECDSA" : NULL);
}

#define	F(f)	((void (*)(void))(f))
static const OSSL_DISPATCH kk_rsa[] = {
	{ OSSL_FUNC_KEYMGMT_NEW, F(kk_new_rsa) },
	{ OSSL_FUNC_KEYMGMT_FREE, F(kk_free) },
	{ OSSL_FUNC_KEYMGMT_DUP, F(kk_dup) },
	{ OSSL_FUNC_KEYMGMT_HAS, F(kk_has) },
	{ OSSL_FUNC_KEYMGMT_IMPORT, F(kk_import) },
	{ OSSL_FUNC_KEYMGMT_IMPORT_TYPES, F(kk_types_rsa) },
	{ OSSL_FUNC_KEYMGMT_EXPORT, F(kk_export) },
	{ OSSL_FUNC_KEYMGMT_EXPORT_TYPES, F(kk_types_rsa) },
	{ OSSL_FUNC_KEYMGMT_GET_PARAMS, F(kk_get_params) },
	{ OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, F(kk_gettable_rsa) },
	{ OSSL_FUNC_KEYMGMT_MATCH, F(kk_match) },
	{ OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, F(kk_opname_rsa) },
	OSSL_DISPATCH_END
};
static const OSSL_DISPATCH kk_ec[] = {
	{ OSSL_FUNC_KEYMGMT_NEW, F(kk_new_ec) },
	{ OSSL_FUNC_KEYMGMT_FREE, F(kk_free) },
	{ OSSL_FUNC_KEYMGMT_DUP, F(kk_dup) },
	{ OSSL_FUNC_KEYMGMT_HAS, F(kk_has) },
	{ OSSL_FUNC_KEYMGMT_IMPORT, F(kk_import) },
	{ OSSL_FUNC_KEYMGMT_IMPORT_TYPES, F(kk_types_ec) },
	{ OSSL_FUNC_KEYMGMT_EXPORT, F(kk_export) },
	{ OSSL_FUNC_KEYMGMT_EXPORT_TYPES, F(kk_types_ec) },
	{ OSSL_FUNC_KEYMGMT_GET_PARAMS, F(kk_get_params) },
	{ OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, F(kk_gettable_ec) },
	{ OSSL_FUNC_KEYMGMT_MATCH, F(kk_match) },
	{ OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, F(kk_opname_ec) },
	OSSL_DISPATCH_END
};

static void *
ks_newctx(void *p, const char *propq)
{
	struct ksig	*s;

	(void)p;
	(void)propq;
	if ((s = calloc(1, sizeof(*s))) == NULL)
		return (NULL);
	s->pad = RSA_PKCS1_PADDING;
	s->saltlen = RSA_PSS_SALTLEN_AUTO;
	return (s);
}

static void
ks_freectx(void *v)
{
	struct ksig	*s = v;

	if (s == NULL)
		return;
	EVP_MD_CTX_free(s->mdctx);
	free(s);
}

static void *
ks_dupctx(void *v)
{
	struct ksig	*s = v, *d;

	if ((d = malloc(sizeof(*d))) == NULL)
		return (NULL);
	*d = *s;
	d->mdctx = NULL;
	if (s->mdctx != NULL && (d->mdctx = EVP_MD_CTX_dup(s->mdctx)) ==
	    NULL) {
		free(d);
		return (NULL);
	}
	return (d);
}

static int
ks_set_ctx_params(void *v, const OSSL_PARAM params[])
{
	struct ksig		*s = v;
	const OSSL_PARAM	*p;
	const char		*str;
	int			 i;

	if (params == NULL)
		return (1);
	if ((p = OSSL_PARAM_locate_const(params,
	    OSSL_SIGNATURE_PARAM_DIGEST)) != NULL) {
		if (!OSSL_PARAM_get_utf8_string_ptr(p, &str))
			return (0);
		strlcpy(s->md, str, sizeof(s->md));
	}
	if ((p = OSSL_PARAM_locate_const(params,
	    OSSL_SIGNATURE_PARAM_MGF1_DIGEST)) != NULL) {
		if (!OSSL_PARAM_get_utf8_string_ptr(p, &str))
			return (0);
		strlcpy(s->mgf1, str, sizeof(s->mgf1));
	}
	if ((p = OSSL_PARAM_locate_const(params,
	    OSSL_SIGNATURE_PARAM_PAD_MODE)) != NULL) {
		if (p->data_type == OSSL_PARAM_UTF8_STRING) {
			if (!OSSL_PARAM_get_utf8_string_ptr(p, &str))
				return (0);
			if (strcmp(str, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0)
				s->pad = RSA_PKCS1_PSS_PADDING;
			else if (strcmp(str, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) ==
			    0)
				s->pad = RSA_PKCS1_PADDING;
			else
				return (0);
		} else if (OSSL_PARAM_get_int(p, &i))
			s->pad = i;
		else
			return (0);
	}
	if ((p = OSSL_PARAM_locate_const(params,
	    OSSL_SIGNATURE_PARAM_PSS_SALTLEN)) != NULL) {
		if (p->data_type == OSSL_PARAM_UTF8_STRING) {
			if (!OSSL_PARAM_get_utf8_string_ptr(p, &str))
				return (0);
			s->saltlen = strcmp(str, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST)
			    == 0 ? RSA_PSS_SALTLEN_DIGEST : strcmp(str,
			    OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0 ?
			    RSA_PSS_SALTLEN_MAX : strcmp(str,
			    OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0 ?
			    RSA_PSS_SALTLEN_AUTO : atoi(str);
		} else if (OSSL_PARAM_get_int(p, &i))
			s->saltlen = i;
		else
			return (0);
	}
	return (1);
}

static const OSSL_PARAM ks_settable[] = {
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
	OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL),
	OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM *
ks_settable_ctx_params(void *v, void *p)
{
	(void)v;
	(void)p;
	return (ks_settable);
}

static int
ks_get_ctx_params(void *v, OSSL_PARAM params[])
{
	struct ksig	*s = v;
	OSSL_PARAM	*p;

	if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST)) !=
	    NULL && !OSSL_PARAM_set_utf8_string(p, s->md))
		return (0);
	return (1);
}

static const OSSL_PARAM ks_gettable[] = {
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *
ks_gettable_ctx_params(void *v, void *p)
{
	(void)v;
	(void)p;
	return (ks_gettable);
}

static int
ks_sign_init(void *v, void *key, const OSSL_PARAM params[])
{
	struct ksig	*s = v;

	s->key = key;
	return (ks_set_ctx_params(s, params));
}

static int
ks_sign(void *v, unsigned char *sig, size_t *siglen, size_t sigsize,
    const unsigned char *tbs, size_t tbslen)
{
	struct ksig	*s = v;

	if (sig == NULL) {
		*siglen = (size_t)EVP_PKEY_get_size(s->key->pub);
		return (1);
	}
	return (keymgr_ask(s->md[0] != '\0' ? s->md : "SHA256", s->mgf1,
	    s->pad, s->saltlen, tbs, tbslen, sig, siglen, sigsize));
}

static int
ks_digest_sign_init(void *v, const char *mdname, void *key,
    const OSSL_PARAM params[])
{
	struct ksig	*s = v;
	EVP_MD		*md;
	int		 ok;

	s->key = key;
	strlcpy(s->md, mdname != NULL ? mdname : "SHA256", sizeof(s->md));
	if (!ks_set_ctx_params(s, params) || (md = EVP_MD_fetch(NULL, s->md,
	    NULL)) == NULL)
		return (0);
	EVP_MD_CTX_free(s->mdctx);
	ok = (s->mdctx = EVP_MD_CTX_new()) != NULL && EVP_DigestInit_ex2(
	    s->mdctx, md, NULL);
	/* Its own name, as the key manager fetches it. */
	strlcpy(s->md, EVP_MD_get0_name(md), sizeof(s->md));
	EVP_MD_free(md);
	return (ok);
}

static int
ks_digest_sign_update(void *v, const unsigned char *data, size_t len)
{
	struct ksig	*s = v;

	return (s->mdctx != NULL && EVP_DigestUpdate(s->mdctx, data, len));
}

static int
ks_digest_sign_final(void *v, unsigned char *sig, size_t *siglen,
    size_t sigsize)
{
	struct ksig	*s = v;
	unsigned char	 d[EVP_MAX_MD_SIZE];
	unsigned int	 dl;

	if (sig == NULL) {
		*siglen = (size_t)EVP_PKEY_get_size(s->key->pub);
		return (1);
	}
	if (s->mdctx == NULL || !EVP_DigestFinal_ex(s->mdctx, d, &dl))
		return (0);
	return (keymgr_ask(s->md, s->mgf1, s->pad, s->saltlen, d, dl, sig,
	    siglen, sigsize));
}

static const OSSL_DISPATCH ks_fns[] = {
	{ OSSL_FUNC_SIGNATURE_NEWCTX, F(ks_newctx) },
	{ OSSL_FUNC_SIGNATURE_FREECTX, F(ks_freectx) },
	{ OSSL_FUNC_SIGNATURE_DUPCTX, F(ks_dupctx) },
	{ OSSL_FUNC_SIGNATURE_SIGN_INIT, F(ks_sign_init) },
	{ OSSL_FUNC_SIGNATURE_SIGN, F(ks_sign) },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, F(ks_digest_sign_init) },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, F(ks_digest_sign_update) },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, F(ks_digest_sign_final) },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, F(ks_set_ctx_params) },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, F(ks_settable_ctx_params) },
	{ OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, F(ks_get_ctx_params) },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, F(ks_gettable_ctx_params) },
	OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM km_keymgmt[] = {
	{ "RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=" KM_PROV,
	    kk_rsa, "an RSA key whose private half is the key manager's" },
	{ "EC:id-ecPublicKey:1.2.840.10045.2.1", "provider=" KM_PROV, kk_ec,
	    "an EC key whose private half is the key manager's" },
	{ NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM km_signature[] = {
	{ "RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=" KM_PROV,
	    ks_fns, "RSA signatures by the key manager" },
	{ "ECDSA", "provider=" KM_PROV, ks_fns,
	    "ECDSA signatures by the key manager" },
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *
km_query(void *p, int op, int *no_cache)
{
	(void)p;
	*no_cache = 0;
	return (op == OSSL_OP_KEYMGMT ? km_keymgmt : op == OSSL_OP_SIGNATURE ?
	    km_signature : NULL);
}

static const OSSL_DISPATCH km_prov[] = {
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, F(km_query) },
	OSSL_DISPATCH_END
};

static int
km_init(const OSSL_CORE_HANDLE *h, const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out, void **provctx)
{
	(void)in;
	*out = km_prov;
	*provctx = (void *)(uintptr_t)h;
	return (1);
}

/*
 * The certificate and the key manager's key on the vhost's SSL_CTX:
 * the key is the provider's, in a library context of its own, so that
 * nothing else of the console's (WebAuthn, its CA) ever fetches it.
 */
int
keymgr_tls(SSL_CTX *ctx, const char *certfile)
{
	EVP_PKEY_CTX	*c;
	EVP_PKEY	*cpub, *pk;
	OSSL_PARAM	*p;
	X509		*x;
	int		 rsa, ok;

	if (kfd == -1) {
		log_msg(LOG_ERR, "keymgr: not running");
		return (-1);
	}
	if (kctx == NULL) {
		if ((kctx = OSSL_LIB_CTX_new()) == NULL ||
		    !OSSL_PROVIDER_add_builtin(kctx, KM_PROV, km_init) ||
		    OSSL_PROVIDER_load(kctx, KM_PROV) == NULL ||
		    (def_rsa = EVP_KEYMGMT_fetch(NULL, "RSA",
		    "provider=default")) == NULL || (def_ec =
		    EVP_KEYMGMT_fetch(NULL, "EC", "provider=default")) ==
		    NULL) {
			log_msg(LOG_ERR, "keymgr: its OpenSSL provider: %s",
			    ssl_error());
			return (-1);
		}
	}
	if (SSL_CTX_use_certificate_chain_file(ctx, certfile) != 1 ||
	    (x = SSL_CTX_get0_certificate(ctx)) == NULL ||
	    (cpub = X509_get0_pubkey(x)) == NULL) {
		log_msg(LOG_ERR, "certfile %s: %s", certfile, ssl_error());
		return (-1);
	}
	rsa = EVP_PKEY_is_a(cpub, "RSA");
	if (!rsa && !EVP_PKEY_is_a(cpub, "EC")) {
		log_msg(LOG_ERR, "certfile %s: neither RSA nor EC", certfile);
		return (-1);
	}
	p = NULL;
	pk = NULL;
	ok = EVP_PKEY_todata(cpub, EVP_PKEY_PUBLIC_KEY, &p) > 0 &&
	    (c = EVP_PKEY_CTX_new_from_name(kctx, rsa ? "RSA" : "EC", NULL)) !=
	    NULL;
	if (ok) {
		ok = EVP_PKEY_fromdata_init(c) > 0 && EVP_PKEY_fromdata(c, &pk,
		    EVP_PKEY_PUBLIC_KEY, p) > 0;
		EVP_PKEY_CTX_free(c);
	}
	OSSL_PARAM_free(p);
	if (!ok || SSL_CTX_use_PrivateKey(ctx, pk) != 1) {
		log_msg(LOG_ERR, "keymgr: the key for %s: %s", certfile,
		    ssl_error());
		EVP_PKEY_free(pk);
		return (-1);
	}
	EVP_PKEY_free(pk);
	return (0);
}
