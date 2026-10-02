/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * WebAuthn for one user, and sessions.
 *
 * Browsers hand over the credential's public key as SubjectPublicKeyInfo
 * (getPublicKey()) and the authenticator data as bytes
 * (getAuthenticatorData()), so nothing here decodes CBOR: libcrypto
 * parses the key and checks signatures.  With attestation "none" there is
 * no attestation statement to verify; the one-time setup token is what
 * makes the first registration trustworthy.
 *
 * Kore runs this module in one worker, so challenges and sessions live
 * in that process; restarting the console logs you out.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "jgweb.h"

#define	CREDENTIALS	"credentials.json"
#define	SETUP_TOKEN	"setup-token"

/* Authenticator data flags. */
#define	AD_UP		0x01	/* user present */
#define	AD_UV		0x04	/* user verified */
#define	AD_AT		0x40	/* attested credential data included */

#define	COSE_ES256	-7
#define	COSE_EDDSA	-8
#define	COSE_RS256	-257

struct challenge {
	char		value[48];	/* base64url of 32 random bytes */
	time_t		expires;
};

struct session {
	uint8_t		hash[32];	/* SHA-256 of the cookie value */
	time_t		created;
	time_t		last;
	bool		used;
};

static ucl_object_t	*creds;		/* the credentials document */
static char		 setup_token[65];
static struct challenge	 reg_chal, login_chal;
static struct session	 sessions[SESSIONS];

static char	*b64url(const void *, size_t);
static uint8_t	*unb64url(const char *, size_t *);
static void	 sha256(const void *, size_t, uint8_t *);
static void	 challenge_new(struct challenge *);
static bool	 challenge_take(struct challenge *, const char *);
static const char *check_client_data(const uint8_t *, size_t, const char *,
		    struct challenge *);
static const char *check_auth_data(const uint8_t *, size_t, uint8_t *,
		    uint32_t *);
static bool	 verify_sig(int, const uint8_t *, size_t, const uint8_t *,
		    size_t, const uint8_t *, size_t);
static bool	 key_matches(int, const uint8_t *, size_t);
static ucl_object_t *cred_list(void);
static const ucl_object_t *cred_find(const char *);
static void	 session_start(struct http_request *);
static void	 setup_token_init(void);
static void	 put(ucl_object_t *, const char *, ucl_object_t *);
static int	 status_reply(struct http_request *, bool);

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

/* base64url without padding; the caller frees with kore_free(). */
static char *
b64url(const void *data, size_t len)
{
	char	*out;

	if (!kore_base64url_encode(data, len, &out, KORE_BASE64_RAW))
		return (NULL);
	return (out);
}

/*
 * Kore's decoder refuses KORE_BASE64_RAW input whose length is already a
 * multiple of 4 (nothing to pad), so ask for padding only when needed.
 */
static uint8_t *
unb64url(const char *s, size_t *lenp)
{
	uint8_t	*out;

	if (s == NULL || *s == '\0' || !kore_base64url_decode(s, &out, lenp,
	    strlen(s) % 4 == 0 ? 0 : KORE_BASE64_RAW))
		return (NULL);
	return (out);
}

static void
sha256(const void *data, size_t len, uint8_t *md)
{
	unsigned int	mdlen;

	EVP_Digest(data, len, md, &mdlen, EVP_sha256(), NULL);
}

static void
challenge_new(struct challenge *c)
{
	uint8_t	 raw[32];
	char	*s;

	arc4random_buf(raw, sizeof(raw));
	s = b64url(raw, sizeof(raw));
	strlcpy(c->value, s, sizeof(c->value));
	kore_free(s);
	c->expires = time(NULL) + CHALLENGE_TTL;
}

/* Use the challenge up: it matches at most once. */
static bool
challenge_take(struct challenge *c, const char *value)
{
	bool	ok;

	ok = c->value[0] != '\0' && time(NULL) <= c->expires &&
	    strcmp(c->value, value) == 0;
	memset(c, 0, sizeof(*c));
	return (ok);
}

/*
 * clientDataJSON must be of the expected type, for the challenge we
 * issued, from our origin.  Returns NULL or what is wrong.
 */
static const char *
check_client_data(const uint8_t *cd, size_t len, const char *type,
    struct challenge *chal)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	const char		*s, *err;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_chunk(p, cd, len))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	if (o == NULL)
		return ("clientDataJSON is not JSON");
	err = NULL;
	if ((s = ucl_str(o, "type")) == NULL || strcmp(s, type) != 0)
		err = "wrong clientData type";
	else if ((s = ucl_str(o, "challenge")) == NULL ||
	    !challenge_take(chal, s))
		err = "unknown or expired challenge";
	else if ((s = ucl_str(o, "origin")) == NULL ||
	    strcmp(s, cfg.origin) != 0)
		err = "wrong origin";
	else if (ucl_flag(o, "crossOrigin"))
		err = "cross-origin request";
	ucl_object_unref(o);
	return (err);
}

/*
 * Authenticator data: the RP ID hash must be ours and the user present.
 * Returns NULL or what is wrong; *flags and *count are filled in.
 */
static const char *
check_auth_data(const uint8_t *ad, size_t len, uint8_t *flags,
    uint32_t *count)
{
	uint8_t	rpid[32];

	if (len < 37)
		return ("authenticator data too short");
	sha256(cfg.rp_id, strlen(cfg.rp_id), rpid);
	if (memcmp(ad, rpid, sizeof(rpid)) != 0)
		return ("authenticator data for another relying party");
	*flags = ad[32];
	*count = (uint32_t)ad[33] << 24 | (uint32_t)ad[34] << 16 |
	    (uint32_t)ad[35] << 8 | ad[36];
	if ((*flags & AD_UP) == 0)
		return ("user not present");
	return (NULL);
}

/* Is the SubjectPublicKeyInfo a key of the COSE algorithm's type? */
static bool
key_matches(int alg, const uint8_t *spki, size_t len)
{
	const uint8_t	*p;
	EVP_PKEY	*pk;
	char		 group[64];
	size_t		 glen;
	bool		 ok;

	p = spki;
	if ((pk = d2i_PUBKEY(NULL, &p, (long)len)) == NULL)
		return (false);
	switch (alg) {
	case COSE_ES256:
		ok = EVP_PKEY_get_base_id(pk) == EVP_PKEY_EC &&
		    EVP_PKEY_get_group_name(pk, group, sizeof(group),
		    &glen) == 1 && strcmp(group, "prime256v1") == 0;
		break;
	case COSE_EDDSA:
		ok = EVP_PKEY_get_base_id(pk) == EVP_PKEY_ED25519;
		break;
	case COSE_RS256:
		ok = EVP_PKEY_get_base_id(pk) == EVP_PKEY_RSA &&
		    EVP_PKEY_get_bits(pk) >= 2048;
		break;
	default:
		ok = false;
		break;
	}
	EVP_PKEY_free(pk);
	return (ok);
}

/* Verify sig over msg with the stored key. */
static bool
verify_sig(int alg, const uint8_t *spki, size_t spkilen, const uint8_t *msg,
    size_t msglen, const uint8_t *sig, size_t siglen)
{
	const uint8_t	*p;
	EVP_PKEY	*pk;
	EVP_MD_CTX	*ctx;
	bool		 ok;

	if (!key_matches(alg, spki, spkilen))
		return (false);
	p = spki;
	if ((pk = d2i_PUBKEY(NULL, &p, (long)spkilen)) == NULL)
		return (false);
	ctx = EVP_MD_CTX_new();
	ok = ctx != NULL && EVP_DigestVerifyInit(ctx, NULL,
	    alg == COSE_EDDSA ? NULL : EVP_sha256(), NULL, pk) == 1 &&
	    EVP_DigestVerify(ctx, sig, siglen, msg, msglen) == 1;
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pk);
	return (ok);
}

static ucl_object_t *
cred_list(void)
{
	const ucl_object_t	*a;

	a = ucl_object_lookup(creds, "credentials");
	return ((ucl_object_t *)(uintptr_t)a);
}

static const ucl_object_t *
cred_find(const char *id)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	const char		*s;

	it = NULL;
	while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL)
		if ((s = ucl_str(c, "id")) != NULL && strcmp(s, id) == 0)
			return (c);
	return (NULL);
}

/*
 * With no credential registered, the first registration needs a setup
 * token, written where only the console's user can read it.
 */
static void
setup_token_init(void)
{
	uint8_t	 raw[32];
	char	 path[MAXPATHLEN];
	FILE	*fp;
	int	 fd, i;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, SETUP_TOKEN);
	if (ucl_array_size(cred_list()) > 0) {
		setup_token[0] = '\0';
		(void)unlink(path);
		return;
	}
	if ((fp = fopen(path, "r")) != NULL) {
		if (fgets(setup_token, sizeof(setup_token), fp) == NULL)
			setup_token[0] = '\0';
		fclose(fp);
		setup_token[strcspn(setup_token, "\n")] = '\0';
		if (strlen(setup_token) == 64)
			return;
	}
	arc4random_buf(raw, sizeof(raw));
	for (i = 0; i < 32; i++)
		snprintf(setup_token + i * 2, 3, "%02x", raw[i]);
	if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600)) == -1 ||
	    dprintf(fd, "%s\n", setup_token) < 0 || close(fd) == -1) {
		kore_log(LOG_ERR, "%s: %s", path, strerror(errno));
		return;
	}
	kore_log(LOG_NOTICE, "no security key registered yet: the setup "
	    "token is in %s", path);
}

void
auth_init(void)
{
	uint8_t	 uid[16];
	char	*s;

	if ((creds = store_load(CREDENTIALS)) == NULL)
		creds = ucl_object_typed_new(UCL_OBJECT);
	if (ucl_object_lookup(creds, "user_id") == NULL) {
		arc4random_buf(uid, sizeof(uid));
		s = b64url(uid, sizeof(uid));
		put(creds, "user_id", ucl_object_fromstring(s));
		kore_free(s);
	}
	if (cred_list() == NULL)
		put(creds, "credentials", ucl_object_typed_new(UCL_ARRAY));
	setup_token_init();
}

bool
session_valid(struct http_request *req)
{
	struct session	*s;
	uint8_t		 h[32];
	char		*cookie;
	time_t		 now;
	int		 i;

	http_populate_cookies(req);
	if (!http_request_cookie(req, SESSION_COOKIE, &cookie) ||
	    strlen(cookie) != 64)
		return (false);
	sha256(cookie, strlen(cookie), h);
	now = time(NULL);
	for (i = 0; i < SESSIONS; i++) {
		s = &sessions[i];
		if (!s->used || memcmp(s->hash, h, sizeof(h)) != 0)
			continue;
		if (now - s->last > SESSION_IDLE ||
		    now - s->created > SESSION_MAX) {
			memset(s, 0, sizeof(*s));
			return (false);
		}
		s->last = now;
		return (true);
	}
	return (false);
}

/* A new session in a cookie only the console can read. */
static void
session_start(struct http_request *req)
{
	struct session	*s, *old;
	uint8_t		 raw[32];
	char		 token[65], cookie[256];
	int		 i;

	arc4random_buf(raw, sizeof(raw));
	for (i = 0; i < 32; i++)
		snprintf(token + i * 2, 3, "%02x", raw[i]);
	/* Reuse a free slot, else the least recently used. */
	old = &sessions[0];
	for (i = 0; i < SESSIONS; i++) {
		if (!sessions[i].used) {
			old = &sessions[i];
			break;
		}
		if (sessions[i].last < old->last)
			old = &sessions[i];
	}
	s = old;
	sha256(token, 64, s->hash);
	s->created = s->last = time(NULL);
	s->used = true;
	snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; HttpOnly; "
	    "SameSite=Strict; Max-Age=%d%s", SESSION_COOKIE, token,
	    SESSION_MAX, cfg.cookie_secure ? "; Secure" : "");
	http_response_header(req, "set-cookie", cookie);
	explicit_bzero(token, sizeof(token));
}

static int
status_reply(struct http_request *req, bool authenticated)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "authenticated", ucl_object_frombool(authenticated));
	put(o, "setup_required", ucl_object_frombool(
	    ucl_array_size(cred_list()) == 0));
	put(o, "rp_id", ucl_object_fromstring(cfg.rp_id));
	return (reply_json(req, 200, o));
}

int
api_auth_status(struct http_request *req)
{

	return (status_reply(req, session_valid(req)));
}

/*
 * Options for navigator.credentials.create().  The first registration
 * needs the setup token; later ones, to add a spare key, a session.
 */
int
api_register_begin(struct http_request *req)
{
	const ucl_object_t	*c;
	ucl_object_t		*body, *o, *pk, *rp, *user, *params, *p, *excl;
	ucl_object_t		*sel, *e;
	ucl_object_iter_t	 it;
	const char		*token;
	static const int	 algs[] = { COSE_EDDSA, COSE_ES256,
				    COSE_RS256 };
	size_t			 i;

	body = read_json(req);
	if (ucl_array_size(cred_list()) == 0) {
		token = body != NULL ? ucl_str(body, "setup_token") : NULL;
		if (token == NULL || setup_token[0] == '\0' ||
		    strlen(token) != strlen(setup_token) ||
		    timingsafe_bcmp(token, setup_token,
		    strlen(setup_token)) != 0) {
			ucl_object_unref(body);
			return (reply_error(req, 403, "setup_token",
			    "the first key needs the setup token from %s/%s",
			    cfg.datadir, SETUP_TOKEN));
		}
	} else if (!guard(req, true)) {
		ucl_object_unref(body);
		return (KORE_RESULT_OK);
	}
	ucl_object_unref(body);

	challenge_new(&reg_chal);
	pk = ucl_object_typed_new(UCL_OBJECT);
	put(pk, "challenge", ucl_object_fromstring(reg_chal.value));
	rp = ucl_object_typed_new(UCL_OBJECT);
	put(rp, "id", ucl_object_fromstring(cfg.rp_id));
	put(rp, "name", ucl_object_fromstring(cfg.rp_name));
	put(pk, "rp", rp);
	user = ucl_object_typed_new(UCL_OBJECT);
	put(user, "id", ucl_object_fromstring(ucl_str(creds, "user_id")));
	put(user, "name", ucl_object_fromstring("admin"));
	put(user, "displayName", ucl_object_fromstring("Jailgrid admin"));
	put(pk, "user", user);
	params = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nitems(algs); i++) {
		p = ucl_object_typed_new(UCL_OBJECT);
		put(p, "type", ucl_object_fromstring("public-key"));
		put(p, "alg", ucl_object_fromint(algs[i]));
		ucl_array_append(params, p);
	}
	put(pk, "pubKeyCredParams", params);
	excl = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "type", ucl_object_fromstring("public-key"));
		put(e, "id", ucl_object_fromstring(ucl_str(c, "id")));
		ucl_array_append(excl, e);
	}
	put(pk, "excludeCredentials", excl);
	/* A discoverable credential where the authenticator offers one: a
	 * phone's passkey logs in without the credential list. */
	sel = ucl_object_typed_new(UCL_OBJECT);
	put(sel, "residentKey", ucl_object_fromstring("preferred"));
	put(sel, "userVerification", ucl_object_fromstring("preferred"));
	put(pk, "authenticatorSelection", sel);
	put(pk, "attestation", ucl_object_fromstring("none"));
	put(pk, "timeout", ucl_object_fromint(CHALLENGE_TTL * 1000));
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "publicKey", pk);
	return (reply_json(req, 200, o));
}

/*
 * {id, clientDataJSON, authenticatorData, publicKey, publicKeyAlgorithm,
 *  transports, name}, all binary fields base64url.
 */
int
api_register_finish(struct http_request *req)
{
	ucl_object_t		*body, *c, *tr;
	const ucl_object_t	*v, *t;
	ucl_object_iter_t	 it;
	uint8_t			*cd, *ad, *spki, *credid, flags;
	const char		*id, *err, *name;
	size_t			 cdlen, adlen, spkilen, idlen, l;
	uint32_t		 count;
	int64_t			 alg;
	int			 status;

	cd = ad = spki = credid = NULL;
	status = 400;
	err = NULL;
	if (ucl_array_size(cred_list()) > 0 && !guard(req, true))
		return (KORE_RESULT_OK);
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "bad_request",
		    "expected a JSON object"));
	id = ucl_str(body, "id");
	v = ucl_object_lookup(body, "publicKeyAlgorithm");
	alg = v != NULL ? ucl_object_toint(v) : 0;
	if (id == NULL || (credid = unb64url(id, &idlen)) == NULL ||
	    (cd = unb64url(ucl_str(body, "clientDataJSON"), &cdlen)) ==
	    NULL ||
	    (ad = unb64url(ucl_str(body, "authenticatorData"), &adlen)) ==
	    NULL ||
	    (spki = unb64url(ucl_str(body, "publicKey"), &spkilen)) == NULL) {
		err = "missing or malformed fields";
		goto out;
	}
	if ((err = check_client_data(cd, cdlen, "webauthn.create",
	    &reg_chal)) != NULL ||
	    (err = check_auth_data(ad, adlen, &flags, &count)) != NULL)
		goto out;
	/* Attested credential data: aaguid(16) idlen(2) id. */
	if ((flags & AD_AT) == 0 || adlen < 55) {
		err = "no attested credential data";
		goto out;
	}
	l = (size_t)ad[53] << 8 | ad[54];
	if (l != idlen || adlen < 55 + l || memcmp(ad + 55, credid, l) != 0) {
		err = "credential id does not match the authenticator data";
		goto out;
	}
	if (!key_matches((int)alg, spki, spkilen)) {
		err = "unsupported key or algorithm";
		goto out;
	}
	if (cred_find(id) != NULL) {
		err = "credential already registered";
		goto out;
	}
	name = ucl_str(body, "name");
	if (name != NULL && strlen(name) > 64) {
		err = "the key's name is at most 64 characters";
		goto out;
	}

	c = ucl_object_typed_new(UCL_OBJECT);
	put(c, "id", ucl_object_fromstring(id));
	put(c, "public_key", ucl_object_fromstring(ucl_str(body,
	    "publicKey")));
	put(c, "alg", ucl_object_fromint(alg));
	put(c, "sign_count", ucl_object_fromint(count));
	put(c, "name", ucl_object_fromstring(name != NULL && *name != '\0' ?
	    name : "Security key"));
	put(c, "created", ucl_object_fromint(time(NULL)));
	put(c, "user_verified", ucl_object_frombool((flags & AD_UV) != 0));
	tr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	if ((v = ucl_object_lookup(body, "transports")) != NULL)
		while ((t = ucl_object_iterate(v, &it, true)) != NULL &&
		    ucl_array_size(tr) < 8)
			if (ucl_object_type(t) == UCL_STRING)
				ucl_array_append(tr, ucl_object_copy(t));
	put(c, "transports", tr);
	ucl_array_append(cred_list(), c);
	if (store_save(CREDENTIALS, creds) == -1) {
		/* A key that would be gone after a restart is not one. */
		ucl_object_unref(ucl_array_delete(cred_list(), c));
		status = 500;
		err = "cannot save the credential";
		goto out;
	}
	kore_log(LOG_NOTICE, "registered security key \"%s\"",
	    ucl_str(c, "name"));
	setup_token_init();
	session_start(req);
	status = 200;
out:
	kore_free(cd);
	kore_free(ad);
	kore_free(spki);
	kore_free(credid);
	ucl_object_unref(body);
	if (status != 200)
		return (reply_error(req, status, "registration", "%s", err));
	return (status_reply(req, true));
}

/*
 * Options for navigator.credentials.get().  {"discoverable": true} asks
 * for a passkey: no credential list, the authenticator picks one of
 * its own for this RP; the id it answers with is looked up as usual.
 */
int
api_login_begin(struct http_request *req)
{
	const ucl_object_t	*c, *t;
	ucl_object_t		*o, *pk, *allow, *e, *body;
	ucl_object_iter_t	 it;
	bool			 discoverable;

	if (ucl_array_size(cred_list()) == 0)
		return (reply_error(req, 409, "setup_required",
		    "no security key registered yet"));
	body = read_json(req);
	discoverable = body != NULL && ucl_flag(body, "discoverable");
	ucl_object_unref(body);
	challenge_new(&login_chal);
	pk = ucl_object_typed_new(UCL_OBJECT);
	put(pk, "challenge", ucl_object_fromstring(login_chal.value));
	put(pk, "rpId", ucl_object_fromstring(cfg.rp_id));
	allow = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while (!discoverable &&
	    (c = ucl_object_iterate(cred_list(), &it, true)) != NULL) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "type", ucl_object_fromstring("public-key"));
		put(e, "id", ucl_object_fromstring(ucl_str(c, "id")));
		if ((t = ucl_object_lookup(c, "transports")) != NULL &&
		    ucl_array_size(t) > 0)
			put(e, "transports", ucl_object_copy(t));
		ucl_array_append(allow, e);
	}
	put(pk, "allowCredentials", allow);
	put(pk, "userVerification", ucl_object_fromstring("preferred"));
	put(pk, "timeout", ucl_object_fromint(CHALLENGE_TTL * 1000));
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "publicKey", pk);
	return (reply_json(req, 200, o));
}

/* {id, clientDataJSON, authenticatorData, signature}, base64url. */
int
api_login_finish(struct http_request *req)
{
	const ucl_object_t	*c;
	ucl_object_t		*body;
	uint8_t			*cd, *ad, *sig, *spki, *msg, flags;
	uint8_t			 cdhash[32];
	const char		*id, *err;
	size_t			 cdlen, adlen, siglen, spkilen;
	uint32_t		 count, stored;

	cd = ad = sig = spki = msg = NULL;
	err = NULL;
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "bad_request",
		    "expected a JSON object"));
	if ((id = ucl_str(body, "id")) == NULL ||
	    (c = cred_find(id)) == NULL) {
		err = "unknown credential";
		goto out;
	}
	if ((cd = unb64url(ucl_str(body, "clientDataJSON"), &cdlen)) ==
	    NULL ||
	    (ad = unb64url(ucl_str(body, "authenticatorData"), &adlen)) ==
	    NULL ||
	    (sig = unb64url(ucl_str(body, "signature"), &siglen)) == NULL ||
	    (spki = unb64url(ucl_str(c, "public_key"), &spkilen)) == NULL) {
		err = "missing or malformed fields";
		goto out;
	}
	if ((err = check_client_data(cd, cdlen, "webauthn.get",
	    &login_chal)) != NULL ||
	    (err = check_auth_data(ad, adlen, &flags, &count)) != NULL)
		goto out;
	/* The signature covers authenticatorData || SHA-256(clientData). */
	sha256(cd, cdlen, cdhash);
	if ((msg = malloc(adlen + sizeof(cdhash))) == NULL) {
		err = "out of memory";
		goto out;
	}
	memcpy(msg, ad, adlen);
	memcpy(msg + adlen, cdhash, sizeof(cdhash));
	if (!verify_sig((int)ucl_object_toint(ucl_object_lookup(c, "alg")),
	    spki, spkilen, msg, adlen + sizeof(cdhash), sig, siglen)) {
		err = "bad signature";
		goto out;
	}
	/* A counter that does not move forward means a cloned key. */
	stored = (uint32_t)ucl_object_toint(ucl_object_lookup(c,
	    "sign_count"));
	if ((count != 0 || stored != 0) && count <= stored) {
		err = "signature counter went backwards";
		kore_log(LOG_WARNING, "security key \"%s\": counter %u after "
		    "%u: possibly cloned", ucl_str(c, "name"), count, stored);
		goto out;
	}
	ucl_object_replace_key((ucl_object_t *)(uintptr_t)c,
	    ucl_object_fromint(count), "sign_count", 0, true);
	ucl_object_replace_key((ucl_object_t *)(uintptr_t)c,
	    ucl_object_fromint(time(NULL)), "last_used", 0, true);
	(void)store_save(CREDENTIALS, creds);
	session_start(req);
	kore_log(LOG_NOTICE, "login with \"%s\"", ucl_str(c, "name"));
out:
	kore_free(cd);
	kore_free(ad);
	kore_free(sig);
	kore_free(spki);
	free(msg);
	ucl_object_unref(body);
	if (err != NULL) {
		kore_log(LOG_NOTICE, "login refused: %s", err);
		return (reply_error(req, 401, "login", "%s", err));
	}
	return (status_reply(req, true));
}

int
api_logout(struct http_request *req)
{
	uint8_t	 h[32];
	char	*cookie, clear[128];
	int	 i;

	http_populate_cookies(req);
	if (http_request_cookie(req, SESSION_COOKIE, &cookie)) {
		sha256(cookie, strlen(cookie), h);
		for (i = 0; i < SESSIONS; i++)
			if (memcmp(sessions[i].hash, h, sizeof(h)) == 0)
				memset(&sessions[i], 0, sizeof(sessions[i]));
	}
	snprintf(clear, sizeof(clear), "%s=; Path=/; HttpOnly; "
	    "SameSite=Strict; Max-Age=0", SESSION_COOKIE);
	http_response_header(req, "set-cookie", clear);
	return (status_reply(req, false));
}

/* GET: the registered keys, without their public keys. */
int
api_credentials(struct http_request *req)
{
	const ucl_object_t	*c, *v;
	ucl_object_t		*a, *e;
	ucl_object_iter_t	 it;
	static const char	*keys[] = { "id", "name", "alg", "created",
				    "last_used", "sign_count", "transports" };
	size_t			 i;

	if (!guard(req, false))
		return (KORE_RESULT_OK);
	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL) {
		e = ucl_object_typed_new(UCL_OBJECT);
		for (i = 0; i < nitems(keys); i++)
			if ((v = ucl_object_lookup(c, keys[i])) != NULL)
				put(e, keys[i], ucl_object_copy(v));
		ucl_array_append(a, e);
	}
	e = ucl_object_typed_new(UCL_OBJECT);
	put(e, "credentials", a);
	return (reply_json(req, 200, e));
}

/* DELETE /api/auth/credentials/<id>: never the last one. */
int
api_credential(struct http_request *req)
{
	const ucl_object_t	*c;
	ucl_object_t		*gone;
	char			 id[512];

	if (!guard(req, true))
		return (KORE_RESULT_OK);
	if (req->method != HTTP_METHOD_DELETE || !capture(req, 4, id,
	    sizeof(id)))
		return (reply_error(req, 400, "bad_request", "bad request"));
	if ((c = cred_find(id)) == NULL)
		return (reply_error(req, 404, "not_found", "no such key"));
	if (ucl_array_size(cred_list()) == 1)
		return (reply_error(req, 409, "last_key",
		    "register another key before removing the last one"));
	gone = ucl_array_delete(cred_list(), (ucl_object_t *)(uintptr_t)c);
	ucl_object_unref(gone);
	if (store_save(CREDENTIALS, creds) == -1)
		return (reply_error(req, 500, "store", "cannot save"));
	return (api_credentials(req));
}
