/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Web Push, the parts that are arithmetic: the encryption of a message
 * for one subscription (RFC 8291, the aes128gcm content coding of
 * RFC 8188) and the token that says who sends it (VAPID, RFC 8292).
 * Nothing of the server in here: the tests link this file by itself.
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "webpush.h"

#define	KEYLEN	65		/* an uncompressed P-256 point */
#define	RS	4096		/* record size: one record holds it all */

/* base64url without padding; the caller frees. */
char *
wp_b64url(const void *data, size_t len)
{
	char	*out, *p;

	if ((out = malloc(4 * ((len + 2) / 3) + 1)) == NULL)
		return (NULL);
	EVP_EncodeBlock((unsigned char *)out, data, (int)len);
	for (p = out; *p != '\0'; p++) {
		if (*p == '+')
			*p = '-';
		else if (*p == '/')
			*p = '_';
		else if (*p == '=') {
			*p = '\0';
			break;
		}
	}
	return (out);
}

/* The bytes of base64url s, padded or not; NULL when it is not that. */
uint8_t *
wp_unb64url(const char *s, size_t *lenp)
{
	char	*tmp;
	uint8_t	*out;
	size_t	 n, i, pad;
	int	 len;

	n = strlen(s);
	while (n > 0 && s[n - 1] == '=')
		n--;
	if (n % 4 == 1)
		return (NULL);
	pad = (4 - n % 4) % 4;
	if ((tmp = malloc(n + pad + 1)) == NULL ||
	    (out = malloc(3 * (n + pad) / 4 + 1)) == NULL) {
		free(tmp);
		return (NULL);
	}
	for (i = 0; i < n; i++)
		tmp[i] = s[i] == '-' ? '+' : s[i] == '_' ? '/' : s[i];
	for (i = 0; i < pad; i++)
		tmp[n + i] = '=';
	tmp[n + pad] = '\0';
	len = EVP_DecodeBlock(out, (unsigned char *)tmp, (int)(n + pad));
	free(tmp);
	if (len < 0) {
		free(out);
		return (NULL);
	}
	*lenp = (size_t)len - pad;
	return (out);
}

/* HKDF with SHA-256 for outputs of one block: extract, then expand. */
static void
hkdf(const uint8_t *salt, size_t saltlen, const uint8_t *ikm, size_t ikmlen,
    const uint8_t *info, size_t infolen, uint8_t *out, size_t outlen)
{
	uint8_t		prk[32], t[32], buf[256];
	unsigned int	n;

	HMAC(EVP_sha256(), salt, (int)saltlen, ikm, ikmlen, prk, &n);
	memcpy(buf, info, infolen);
	buf[infolen] = 0x01;
	HMAC(EVP_sha256(), prk, sizeof(prk), buf, infolen + 1, t, &n);
	memcpy(out, t, outlen);
}

/*
 * plain, encrypted for the subscription whose public key is ua_pub (65
 * bytes) and whose secret is auth (16 bytes).  as_key is the sender's
 * key for this one message and salt its 16 random bytes; NULL for
 * either has them made here, as they should be but in a test.  The
 * result is the body to send, with Content-Encoding: aes128gcm.
 */
int
wp_encrypt(const uint8_t *ua_pub, const uint8_t *auth, EVP_PKEY *as_key,
    const uint8_t *salt, const uint8_t *plain, size_t plen, uint8_t **outp,
    size_t *outlenp)
{
	EVP_PKEY	*peer, *mine;
	EVP_PKEY_CTX	*dctx;
	EVP_CIPHER_CTX	*cctx;
	unsigned char	*as_pub;
	uint8_t		 secret[32], ikm[32], cek[16], nonce[12], rsalt[16];
	uint8_t		 info[160], *out, *rec;
	size_t		 slen, publen, n;
	int		 len, rc;

	rc = -1;
	peer = NULL;
	dctx = NULL;
	cctx = NULL;
	as_pub = NULL;
	out = rec = NULL;
	if (plen > RS - 16 - 1 - 86)
		return (-1);
	mine = as_key != NULL ? as_key : EVP_PKEY_Q_keygen(NULL, NULL, "EC",
	    "P-256");
	if (mine == NULL)
		return (-1);
	if (salt == NULL) {
		if (RAND_bytes(rsalt, sizeof(rsalt)) != 1)
			goto out;
		salt = rsalt;
	}

	/* What both ends can work out: ECDH of our key and theirs. */
	if ((peer = EVP_PKEY_new()) == NULL ||
	    EVP_PKEY_copy_parameters(peer, mine) != 1 ||
	    EVP_PKEY_set1_encoded_public_key(peer, ua_pub, KEYLEN) != 1 ||
	    (dctx = EVP_PKEY_CTX_new(mine, NULL)) == NULL ||
	    EVP_PKEY_derive_init(dctx) != 1 ||
	    EVP_PKEY_derive_set_peer(dctx, peer) != 1)
		goto out;
	slen = sizeof(secret);
	if (EVP_PKEY_derive(dctx, secret, &slen) != 1 || slen != 32 ||
	    (publen = EVP_PKEY_get1_encoded_public_key(mine, &as_pub)) !=
	    KEYLEN)
		goto out;

	/* RFC 8291, 3.4: the key for this message, bound to both keys. */
	n = sizeof("WebPush: info");
	memcpy(info, "WebPush: info", n);
	memcpy(info + n, ua_pub, KEYLEN);
	memcpy(info + n + KEYLEN, as_pub, KEYLEN);
	hkdf(auth, 16, secret, 32, info, n + 2 * KEYLEN, ikm, 32);
	/* RFC 8188, 2.2 and 2.3: the content key and the nonce. */
	n = sizeof("Content-Encoding: aes128gcm");
	hkdf(salt, 16, ikm, 32, (const uint8_t *)"Content-Encoding: aes128gcm",
	    n, cek, 16);
	n = sizeof("Content-Encoding: nonce");
	hkdf(salt, 16, ikm, 32, (const uint8_t *)"Content-Encoding: nonce", n,
	    nonce, 12);

	/* One record: the text, the delimiter of a last record, the tag. */
	if ((rec = malloc(plen + 1)) == NULL ||
	    (out = malloc(16 + 4 + 1 + KEYLEN + plen + 1 + 16)) == NULL)
		goto out;
	memcpy(rec, plain, plen);
	rec[plen] = 0x02;
	memcpy(out, salt, 16);
	out[16] = (RS >> 24) & 0xff;
	out[17] = (RS >> 16) & 0xff;
	out[18] = (RS >> 8) & 0xff;
	out[19] = RS & 0xff;
	out[20] = KEYLEN;
	memcpy(out + 21, as_pub, KEYLEN);
	n = 21 + KEYLEN;
	if ((cctx = EVP_CIPHER_CTX_new()) == NULL ||
	    EVP_EncryptInit_ex(cctx, EVP_aes_128_gcm(), NULL, cek, nonce) !=
	    1 || EVP_EncryptUpdate(cctx, out + n, &len, rec, (int)plen + 1) !=
	    1)
		goto out;
	n += (size_t)len;
	if (EVP_EncryptFinal_ex(cctx, out + n, &len) != 1)
		goto out;
	n += (size_t)len;
	if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, 16, out + n) != 1)
		goto out;
	n += 16;
	*outp = out;
	*outlenp = n;
	out = NULL;
	rc = 0;
out:
	free(out);
	free(rec);
	OPENSSL_free(as_pub);
	EVP_CIPHER_CTX_free(cctx);
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_free(peer);
	if (as_key == NULL)
		EVP_PKEY_free(mine);
	return (rc);
}

/*
 * The Authorization header for a push to audience ("https://host"), as
 * VAPID has it: a JWT signed with the server's key, and that key.  sub
 * says whom the push service may write to.  The caller frees.
 */
char *
wp_vapid(EVP_PKEY *key, const char *audience, const char *sub, time_t now)
{
	EVP_MD_CTX	*md;
	ECDSA_SIG	*sig;
	const BIGNUM	*r, *s;
	const unsigned char *dp;
	unsigned char	*der, *pub, raw[64];
	char		 claims[512], *h, *c, *signing, *b64sig, *b64pub, *out;
	size_t		 derlen, publen;

	out = NULL;
	md = NULL;
	sig = NULL;
	der = pub = NULL;
	h = c = signing = b64sig = b64pub = NULL;
	snprintf(claims, sizeof(claims), "{\"aud\":\"%s\",\"exp\":%lld,"
	    "\"sub\":\"%s\"}", audience, (long long)now + 12 * 3600, sub);
	h = wp_b64url("{\"typ\":\"JWT\",\"alg\":\"ES256\"}", 27);
	c = wp_b64url(claims, strlen(claims));
	if (h == NULL || c == NULL || asprintf(&signing, "%s.%s", h, c) == -1)
		goto out;
	if ((md = EVP_MD_CTX_new()) == NULL ||
	    EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, key) != 1 ||
	    EVP_DigestSign(md, NULL, &derlen, (unsigned char *)signing,
	    strlen(signing)) != 1 || (der = malloc(derlen)) == NULL ||
	    EVP_DigestSign(md, der, &derlen, (unsigned char *)signing,
	    strlen(signing)) != 1)
		goto out;
	/* JOSE wants r and s as they are, 32 bytes each; not DER. */
	dp = der;
	if ((sig = d2i_ECDSA_SIG(NULL, &dp, (long)derlen)) == NULL)
		goto out;
	ECDSA_SIG_get0(sig, &r, &s);
	if (BN_bn2binpad(r, raw, 32) != 32 || BN_bn2binpad(s, raw + 32, 32) !=
	    32 || (publen = EVP_PKEY_get1_encoded_public_key(key, &pub)) !=
	    KEYLEN)
		goto out;
	b64sig = wp_b64url(raw, sizeof(raw));
	b64pub = wp_b64url(pub, publen);
	if (b64sig == NULL || b64pub == NULL || asprintf(&out,
	    "vapid t=%s.%s, k=%s", signing, b64sig, b64pub) == -1)
		out = NULL;
out:
	free(h);
	free(c);
	free(signing);
	free(b64sig);
	free(b64pub);
	free(der);
	OPENSSL_free(pub);
	ECDSA_SIG_free(sig);
	EVP_MD_CTX_free(md);
	return (out);
}
