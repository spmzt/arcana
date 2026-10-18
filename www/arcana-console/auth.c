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
#include <sys/endian.h>
#include <sys/stat.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "console.h"

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
	char		who[64];	/* the key it was opened with */
	char		tok[17];	/* the API token it was, its id; "" a key */
	bool		ldap;		/* opened by a directory's user */
	char		user[64];	/* the console user (users.c); "" none */
};

static ucl_object_t	*creds;		/* the credentials document */
static char		 setup_token[65];
static struct challenge	 reg_chal;
static char		 reg_user[64];	/* whose key is being registered */
static bool		 reg_invited;	/* ... by an invitation: no session */
static char		 last_user[64];	/* of the session just started: its
					 * cookie is not on the request yet */

/*
 * Login challenges are not kept.  Anyone may ask for one, and one kept
 * for each asker would let whoever asks most push the others' out.  A
 * challenge says when it ends and carries a MAC of the console's over
 * that; it is noted only once used, to be used once.
 */
#define	USED_CHALS	64
static uint8_t		 chal_key[32];
static bool		 chal_keyed;
static struct challenge	 used_chals[USED_CHALS];
static struct session	 sessions[SESSIONS];
static time_t		 sessions_saved;	/* when the file was last written */

static char	*b64url(const void *, size_t);
static bool	 origin_ours(const char *);
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
static void	 session_start(struct http_request *, const char *,
		    const char *, const char *);
static void	 sessions_save(void);
static void	 sessions_load(void);
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

/* A login challenge: 12 random bytes, when it ends, and the MAC. */
static void
login_challenge(char *out, size_t len)
{
	uint8_t		 raw[32], mac[32];
	unsigned int	 n;
	char		*s;

	if (!chal_keyed) {
		arc4random_buf(chal_key, sizeof(chal_key));
		chal_keyed = true;
	}
	arc4random_buf(raw, 12);
	be32enc(raw + 12, (uint32_t)(time(NULL) + CHALLENGE_TTL));
	HMAC(EVP_sha256(), chal_key, sizeof(chal_key), raw, 16, mac, &n);
	memcpy(raw + 16, mac, 16);
	s = b64url(raw, sizeof(raw));
	strlcpy(out, s, len);
	kore_free(s);
}

/* Is value a login challenge of ours, in time, and not used before? */
static bool
login_challenge_take(const char *value)
{
	struct challenge	*slot;
	uint8_t			*raw, mac[32];
	size_t			 len;
	unsigned int		 n;
	time_t			 now, expires;
	int			 i;
	bool			 ok;

	if (!chal_keyed || strlen(value) >= sizeof(slot->value) ||
	    (raw = unb64url(value, &len)) == NULL)
		return (false);
	ok = len == 32;
	if (ok) {
		HMAC(EVP_sha256(), chal_key, sizeof(chal_key), raw, 16, mac,
		    &n);
		ok = CRYPTO_memcmp(mac, raw + 16, 16) == 0;
	}
	now = time(NULL);
	expires = ok ? (time_t)be32dec(raw + 12) : 0;
	kore_free(raw);
	if (!ok || now > expires)
		return (false);
	/* Used once: noted until it would have ended anyway. */
	slot = &used_chals[0];
	for (i = 0; i < USED_CHALS; i++) {
		if (used_chals[i].expires >= now && strcmp(used_chals[i].value,
		    value) == 0)
			return (false);
		if (used_chals[i].expires < slot->expires)
			slot = &used_chals[i];
	}
	strlcpy(slot->value, value, sizeof(slot->value));
	slot->expires = expires;
	return (true);
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
 * The console's origin, or the Android app's named in web.conf: a
 * credential made or used in the app comes with the origin
 * android:apk-key-hash:<base64url of its signing certificate's SHA-256>.
 */
static bool
origin_ours(const char *origin)
{
	static const char	 pfx[] = "android:apk-key-hash:";
	char			*h;
	bool			 ok;
	int			 i;

	if (strcmp(origin, cfg.origin) == 0)
		return (true);
	if (strncmp(origin, pfx, sizeof(pfx) - 1) != 0)
		return (false);
	ok = false;
	for (i = 0; !ok && i < cfg.nandroid_keys; i++) {
		h = b64url(cfg.android_keys[i], sizeof(cfg.android_keys[i]));
		ok = h != NULL && strcmp(origin + sizeof(pfx) - 1, h) == 0;
		kore_free(h);
	}
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
	    !(chal != NULL ? challenge_take(chal, s) :
	    login_challenge_take(s)))
		err = "unknown or expired challenge";
	else if ((s = ucl_str(o, "origin")) == NULL || !origin_ours(s))
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
	char	 path[MAXPATHLEN], tmp[MAXPATHLEN];
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
	/* Whole or not at all: whoever reads it never finds it empty. */
	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
	if ((fd = mkstemp(tmp)) == -1 || fchmod(fd, 0600) == -1 ||
	    dprintf(fd, "%s\n", setup_token) < 0 || close(fd) == -1 ||
	    rename(tmp, path) == -1) {
		kore_log(LOG_ERR, "%s: %s", path, strerror(errno));
		if (fd != -1)
			(void)unlink(tmp);
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
	sessions_load();
	setup_token_init();
}

/*
 * The sessions outlive the console's process: it can be restarted from
 * its own page, and that should not log everyone out.  They are kept
 * in the data directory, readable by the console's user alone, as the
 * hash of each cookie with its times: what is on disk does not log
 * anyone in.
 */
static void
sessions_save(void)
{
	ucl_object_t	*o, *a, *e;
	char		 hex[65];
	int		 i, k;

	o = ucl_object_typed_new(UCL_OBJECT);
	a = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < SESSIONS; i++) {
		if (!sessions[i].used)
			continue;
		for (k = 0; k < 32; k++)
			snprintf(hex + 2 * k, 3, "%02x", sessions[i].hash[k]);
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "hash", ucl_object_fromstring(hex));
		put(e, "created", ucl_object_fromint(sessions[i].created));
		put(e, "last", ucl_object_fromint(sessions[i].last));
		put(e, "who", ucl_object_fromstring(sessions[i].who));
		if (sessions[i].tok[0] != '\0')
			put(e, "token", ucl_object_fromstring(sessions[i].tok));
		if (sessions[i].ldap)
			put(e, "ldap", ucl_object_frombool(true));
		if (sessions[i].user[0] != '\0')
			put(e, "user", ucl_object_fromstring(sessions[i].user));
		ucl_array_append(a, e);
	}
	put(o, "sessions", a);
	(void)store_save(SESSIONS_FILE, o);
	ucl_object_unref(o);
	sessions_saved = time(NULL);
}

/* Those of the file that have not run out. */
static void
sessions_load(void)
{
	ucl_object_t		*o;
	const ucl_object_t	*e, *h;
	ucl_object_iter_t	 it;
	const char		*hex;
	struct session		*s;
	unsigned int		 b;
	time_t			 now;
	int			 n, k;

	memset(sessions, 0, sizeof(sessions));
	if ((o = store_load(SESSIONS_FILE)) == NULL)
		return;
	now = time(NULL);
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(o, "sessions"), &it,
	    true)) != NULL && n < SESSIONS) {
		if ((h = ucl_object_lookup(e, "hash")) == NULL ||
		    (hex = ucl_object_tostring(h)) == NULL || strlen(hex) != 64)
			continue;
		s = &sessions[n];
		for (k = 0; k < 32; k++) {
			if (sscanf(hex + 2 * k, "%2x", &b) != 1)
				break;
			s->hash[k] = (uint8_t)b;
		}
		s->created = ucl_object_toint(ucl_object_lookup(e, "created"));
		s->last = ucl_object_toint(ucl_object_lookup(e, "last"));
		snprintf(s->who, sizeof(s->who), "%s", ucl_object_lookup(e, "who")
		    != NULL ? ucl_object_tostring_forced(ucl_object_lookup(e,
		    "who")) : "");
		snprintf(s->tok, sizeof(s->tok), "%s", ucl_object_lookup(e,
		    "token") != NULL ? ucl_object_tostring_forced(
		    ucl_object_lookup(e, "token")) : "");
		s->ldap = ucl_object_toboolean(ucl_object_lookup(e, "ldap"));
		snprintf(s->user, sizeof(s->user), "%s", ucl_object_lookup(e,
		    "user") != NULL ? ucl_object_tostring_forced(
		    ucl_object_lookup(e, "user")) : "");
		if (k < 32 || s->created > now || now - s->last > cfg.session_idle ||
		    now - s->created > cfg.session_max) {
			memset(s, 0, sizeof(*s));
			continue;
		}
		s->used = true;
		n++;
	}
	ucl_object_unref(o);
}

/* The request's session, valid or not; NULL: none. */
static struct session *
session_of(struct http_request *req)
{
	uint8_t		 h[32];
	char		*cookie;
	int		 i;

	http_populate_cookies(req);
	if (!http_request_cookie(req, SESSION_COOKIE, &cookie) ||
	    strlen(cookie) != 64)
		return (NULL);
	sha256(cookie, strlen(cookie), h);
	for (i = 0; i < SESSIONS; i++)
		if (sessions[i].used && memcmp(sessions[i].hash, h,
		    sizeof(h)) == 0)
			return (&sessions[i]);
	return (NULL);
}

/*
 * Whether the request's session was opened with an API token: it may
 * then do what the token may, no more (guard()).
 */
bool
session_by_token(struct http_request *req)
{
	struct session	*s;

	/* A directory's user is limited as a token is: what changes the
	 * console's own sign-in, tokens, CA and settings takes a key. */
	return ((s = session_of(req)) != NULL && (s->tok[0] != '\0' ||
	    s->ldap));
}

/* Was the session opened by a directory's user? */
static bool
session_by_ldap(struct http_request *req)
{
	struct session	*s;

	return ((s = session_of(req)) != NULL && s->ldap);
}

bool
session_valid(struct http_request *req)
{
	struct session	*s;
	time_t		 now;

	now = time(NULL);
	if ((s = session_of(req)) != NULL) {
		/* Its token deleted, the session it opened ends with it. */
		if (now - s->last > cfg.session_idle ||
		    now - s->created > cfg.session_max || (s->tok[0] != '\0' &&
		    !token_alive(s->tok))) {
			memset(s, 0, sizeof(*s));
			sessions_save();
			return (false);
		}
		s->last = now;
		/* The time of use, written now and then, not at every
		 * request. */
		if (now - sessions_saved >= SESSION_SAVE)
			sessions_save();
		return (true);
	}
	return (false);
}

/*
 * Who a request comes from: the name of the security key its session
 * was opened with, or "API token <name>" for a write token; NULL else.
 * For the audit trail (MEF 118.1's who of a Policy Action).
 */
const char *
session_who(struct http_request *req)
{
	uint8_t	 h[32];
	char	*cookie;
	int	 i;

	http_populate_cookies(req);
	if (!http_request_cookie(req, SESSION_COOKIE, &cookie) ||
	    strlen(cookie) != 64)
		return (token_who(req));
	sha256(cookie, strlen(cookie), h);
	for (i = 0; i < SESSIONS; i++)
		if (sessions[i].used && memcmp(sessions[i].hash, h, sizeof(h))
		    == 0)
			return (sessions[i].who[0] != '\0' ? sessions[i].who :
			    "a security key");
	return (token_who(req));
}

/*
 * The console user a request's session is of (users.c): NULL for one
 * that carries none, an API token's or a directory's user the console
 * has no record of, which may what a write token may, on every host.
 */
const char *
session_user(struct http_request *req)
{
	struct session	*s;

	if ((s = session_of(req)) == NULL || s->user[0] == '\0')
		return (NULL);
	return (s->user);
}

/*
 * May the request's user do this on the host: a viewer reads, an
 * operator changes, an admin also what admin says (updating, moving,
 * removing it).  Without a reply; host_allowed() sends one.
 */
bool
host_role_ok(struct http_request *req, const char *sid, bool mutate,
    bool admin)
{
	enum role	r;

	r = user_host(session_user(req), sid);
	if (r == ROLE_NONE)
		return (false);
	if (mutate && r == ROLE_VIEWER)
		return (false);
	if (admin && r != ROLE_ADMIN)
		return (false);
	return (true);
}

bool
host_allowed(struct http_request *req, const char *sid, bool mutate,
    bool admin)
{
	enum role	r;

	if (host_role_ok(req, sid, mutate, admin))
		return (true);
	r = user_host(session_user(req), sid);
	if (r == ROLE_NONE)
		reply_error(req, 404, "not_found", "no such server");
	else
		reply_error(req, 403, "role", "a %s of this host may not %s "
		    "it", role_name(r), admin ? "administer" : "change");
	return (false);
}

/* The sessions of a user, ended: when the user is removed. */
void
sessions_end_user(const char *user)
{
	int	i;

	for (i = 0; i < SESSIONS; i++)
		if (sessions[i].used && strcmp(sessions[i].user, user) == 0)
			memset(&sessions[i], 0, sizeof(sessions[i]));
	sessions_save();
}

/* The user a key belongs to: the built-in owner's when it says none. */
static const char *
cred_user(const ucl_object_t *c)
{

	return (ucl_str(c, "user") != NULL ? ucl_str(c, "user") : ADMIN_USER);
}

/* How many keys a user has. */
int
cred_count_of(const char *user)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL)
		if (strcmp(cred_user(c), user) == 0)
			n++;
	return (n);
}

/* A user's keys, gone with the user. */
void
creds_forget_user(const char *user)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	bool			 again;

	do {
		again = false;
		it = NULL;
		while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL)
			if (strcmp(cred_user(c), user) == 0) {
				ucl_object_unref(ucl_array_delete(cred_list(),
				    (ucl_object_t *)(uintptr_t)c));
				again = true;
				break;
			}
	} while (again);
	(void)store_save(CREDENTIALS, creds);
}

/* A new session in a cookie only the console can read, opened by the
 * key named who, or by the API token of id tok, for the console user
 * (NULL or "": none). */
static void
session_start(struct http_request *req, const char *who, const char *tok,
    const char *user)
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
	snprintf(s->who, sizeof(s->who), "%s", who != NULL ? who : "");
	snprintf(s->tok, sizeof(s->tok), "%s", tok != NULL ? tok : "");
	s->ldap = false;
	snprintf(s->user, sizeof(s->user), "%s", user != NULL ? user : "");
	snprintf(last_user, sizeof(last_user), "%s", s->user);
	snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; HttpOnly; "
	    "SameSite=Strict; Max-Age=%d%s", SESSION_COOKIE, token,
	    cfg.session_max, cfg.cookie_secure ? "; Secure" : "");
	http_response_header(req, "set-cookie", cookie);
	explicit_bzero(token, sizeof(token));
	sessions_save();
}

static int
status_reply_as(struct http_request *req, bool authenticated, bool by_token,
    bool by_ldap)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "authenticated", ucl_object_frombool(authenticated));
	/* Opened with an API token, or by a directory's user: the page
	 * does not offer what it may not do. */
	if (authenticated && by_token)
		put(o, "by_token", ucl_object_frombool(true));
	if (authenticated && by_ldap)
		put(o, "by_ldap", ucl_object_frombool(true));
	/* Who, and what they may (users.c): the page offers no more. */
	if (authenticated) {
		const char	*u = session_user(req);
		char		 just[64];

		/* Just signed in: the session's cookie is on its way. */
		if (u == NULL && session_of(req) == NULL && last_user[0] != '\0') {
			snprintf(just, sizeof(just), "%s", last_user);
			u = just;
		}
		last_user[0] = '\0';
		if (u != NULL) {
			put(o, "user", ucl_object_fromstring(u));
			put(o, "console", ucl_object_fromstring(crole_name(
			    user_console(u))));
			if (user_tenant(u)[0] != '\0')
				put(o, "tenant", ucl_object_fromstring(
				    user_tenant(u)));
		} else
			put(o, "console", ucl_object_fromstring("operator"));
	}
	/* The page offers a user and password when a directory is set. */
	put(o, "ldap", ucl_object_frombool(ldap_enabled()));
	put(o, "setup_required", ucl_object_frombool(
	    ucl_array_size(cred_list()) == 0));
	put(o, "rp_id", ucl_object_fromstring(cfg.rp_id));
	/* The browser checks both against its address before any key is
	 * asked: the page says so when they do not match. */
	put(o, "origin", ucl_object_fromstring(cfg.origin));
	return (reply_json(req, 200, o));
}

static int
status_reply(struct http_request *req, bool authenticated)
{

	return (status_reply_as(req, authenticated, authenticated &&
	    session_by_token(req), authenticated && session_by_ldap(req)));
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
	/* Whose key: an invited user's, by their invitation (users.c);
	 * the first key the built-in owner's, by the setup token; else
	 * the signed-in user's own, or, for the owner, the one named. */
	reg_invited = false;
	if (body != NULL && ucl_str(body, "invite") != NULL) {
		if (!invite_take(ucl_str(body, "invite"), reg_user,
		    sizeof(reg_user))) {
			ucl_object_unref(body);
			return (reply_error(req, 403, "invite", "not an "
			    "invitation of this console's, or one that ran out"));
		}
		reg_invited = true;
	} else if (ucl_array_size(cred_list()) == 0) {
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
		snprintf(reg_user, sizeof(reg_user), "%s", ADMIN_USER);
	} else {
		const char	*u, *forname;

		if (!guard(req, true)) {
			ucl_object_unref(body);
			return (KORE_RESULT_OK);
		}
		u = session_user(req);
		forname = body != NULL ? ucl_str(body, "user") : NULL;
		if (forname != NULL && forname[0] != '\0' && (u == NULL ||
		    strcmp(forname, u) != 0)) {
			if (user_console(u) != CROLE_OWNER || !user_exists(
			    forname)) {
				ucl_object_unref(body);
				return (reply_error(req, 403, "role", "a key for "
				    "another user is registered by the owner, for "
				    "a user there is"));
			}
			snprintf(reg_user, sizeof(reg_user), "%s", forname);
		} else
			snprintf(reg_user, sizeof(reg_user), "%s", u != NULL ? u :
			    ADMIN_USER);
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
	if (strcmp(reg_user, ADMIN_USER) == 0)
		put(user, "id", ucl_object_fromstring(ucl_str(creds, "user_id")));
	else {
		char	handle[40];

		user_handle(reg_user, handle, sizeof(handle));
		put(user, "id", ucl_object_fromstring(handle));
	}
	put(user, "name", ucl_object_fromstring(reg_user));
	put(user, "displayName", ucl_object_fromstring(reg_user));
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
	/* An invited user's first key needs no session: the invitation,
	 * taken at the start, was it; the challenge ties the two. */
	if (ucl_array_size(cred_list()) > 0 && !reg_invited && !guard(req,
	    true))
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
	if (reg_user[0] != '\0' && strcmp(reg_user, ADMIN_USER) != 0)
		put(c, "user", ucl_object_fromstring(reg_user));
	ucl_array_append(cred_list(), c);
	if (store_save(CREDENTIALS, creds) == -1) {
		/* A key that would be gone after a restart is not one. */
		ucl_object_unref(ucl_array_delete(cred_list(), c));
		status = 500;
		err = "cannot save the credential";
		goto out;
	}
	kore_log(LOG_NOTICE, "registered security key \"%s\" of %s",
	    ucl_str(c, "name"), cred_user(c));
	setup_token_init();
	session_start(req, ucl_str(c, "name"), NULL, cred_user(c));
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
	char			 chal[48];
	bool			 discoverable;

	if (ucl_array_size(cred_list()) == 0)
		return (reply_error(req, 409, "setup_required",
		    "no security key registered yet"));
	body = read_json(req);
	discoverable = body != NULL && ucl_flag(body, "discoverable");
	ucl_object_unref(body);
	login_challenge(chal, sizeof(chal));
	pk = ucl_object_typed_new(UCL_OBJECT);
	put(pk, "challenge", ucl_object_fromstring(chal));
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
	if ((err = check_client_data(cd, cdlen, "webauthn.get", NULL)) !=
	    NULL ||
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
	session_start(req, ucl_str(c, "name"), NULL, cred_user(c));
	kore_log(LOG_NOTICE, "login with \"%s\" of %s", ucl_str(c, "name"),
	    cred_user(c));
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

/*
 * POST /api/auth/login/token {"token": "arcw_..."}: signed in with a
 * write token, for one with no security key at hand.  The session may
 * do what the token may and no more: not the console's settings,
 * sign-in, push, enrolment, tokens or CA; it ends when the token is
 * deleted.  A read token does not sign in.
 */
int
api_login_token(struct http_request *req)
{
	ucl_object_t	*body;
	const char	*v, *name;
	char		 id[17], who[96];

	if (req->method != HTTP_METHOD_POST)
		return (reply_error(req, 405, "method", "POST"));
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "bad_request", "expected a JSON "
		    "object"));
	v = ucl_str(body, "token");
	name = v != NULL ? token_login(v, id, sizeof(id)) : NULL;
	if (name == NULL) {
		ucl_object_unref(body);
		kore_log(LOG_NOTICE, "login with a token refused");
		return (reply_error(req, 401, "login", "not a write token of "
		    "this console's: a read token does not sign in, and a "
		    "deleted one opens nothing"));
	}
	snprintf(who, sizeof(who), "API token %s", name);
	session_start(req, who, id, NULL);
	kore_log(LOG_NOTICE, "login with %s", who);
	ucl_object_unref(body);
	/* Its cookie is only on its way: said so here. */
	return (status_reply_as(req, true, true, false));
}

/*
 * POST {"user", "password"}: a sign-in by the directory Settings name,
 * limited as a token's is.  The password is kept nowhere: it goes to
 * the directory and is wiped.
 */
int
api_login_ldap(struct http_request *req)
{
	ucl_object_t	*body;
	const char	*user, *password;
	char		 who[96], err[300];
	bool		 ok;

	if (req->method != HTTP_METHOD_POST)
		return (reply_error(req, 405, "method", "POST"));
	config_refresh();
	if (!ldap_enabled())
		return (reply_error(req, 404, "ldap", "sign-in by LDAP is not "
		    "set up on this console"));
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "bad_request", "expected a JSON "
		    "object"));
	user = ucl_str(body, "user");
	password = ucl_str(body, "password");
	ok = ldap_login(user, password, who, sizeof(who), err, sizeof(err));
	if (password != NULL)
		explicit_bzero((char *)(uintptr_t)password, strlen(password));
	ucl_object_unref(body);
	if (!ok)
		return (reply_error(req, strstr(err, "too many") != NULL ? 429 :
		    strstr(err, "not set") != NULL || strstr(err, "characters")
		    != NULL ? 400 : 401, "login", "%s", err));
	/* A user the console knows by that name has its roles; one it
	 * does not is limited as a write token is. */
	session_start(req, who, "", user_exists(user) ? user : NULL);
	{
		struct session	*s = session_of(req);

		/* The cookie is only on its way: the slot just made is the
		 * newest; marked by its who, which session_start set. */
		if (s == NULL) {
			int	i, best = -1;

			for (i = 0; i < SESSIONS; i++)
				if (sessions[i].used && strcmp(sessions[i].who,
				    who) == 0 && (best < 0 || sessions[i].created
				    >= sessions[best].created))
					best = i;
			if (best >= 0)
				sessions[best].ldap = true;
		} else
			s->ldap = true;
		sessions_save();
	}
	return (status_reply_as(req, true, true, true));
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
		sessions_save();
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
	const char		*u;
	size_t			 i;

	if (!guard(req, false))
		return (KORE_RESULT_OK);
	/* The owner sees them all, with whose each is; others their own. */
	u = session_user(req);
	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((c = ucl_object_iterate(cred_list(), &it, true)) != NULL) {
		if (u != NULL && user_console(u) != CROLE_OWNER && strcmp(
		    cred_user(c), u) != 0)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		for (i = 0; i < nitems(keys); i++)
			if ((v = ucl_object_lookup(c, keys[i])) != NULL)
				put(e, keys[i], ucl_object_copy(v));
		put(e, "user", ucl_object_fromstring(cred_user(c)));
		ucl_array_append(a, e);
	}
	e = ucl_object_typed_new(UCL_OBJECT);
	put(e, "credentials", a);
	return (reply_json(req, 200, e));
}

/* Is there a sign-in key of this name: a console user (SASE-3)? */
bool
cred_named(const char *name)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;

	it = NULL;
	while (name != NULL && (c = ucl_object_iterate(cred_list(), &it, true))
	    != NULL)
		if (ucl_str(c, "name") != NULL && strcmp(ucl_str(c, "name"), name)
		    == 0)
			return (true);
	return (false);
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
	if (session_user(req) != NULL && user_console(session_user(req)) !=
	    CROLE_OWNER && strcmp(cred_user(c), session_user(req)) != 0)
		return (reply_error(req, 403, "role", "another user's key is "
		    "removed by the owner"));
	if (ucl_array_size(cred_list()) == 1)
		return (reply_error(req, 409, "last_key",
		    "register another key before removing the last one"));
	gone = ucl_array_delete(cred_list(), (ucl_object_t *)(uintptr_t)c);
	ucl_object_unref(gone);
	if (store_save(CREDENTIALS, creds) == -1)
		return (reply_error(req, 500, "store", "cannot save"));
	return (api_credentials(req));
}
