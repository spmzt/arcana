/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Web Push arithmetic against what the standards print: the worked
 * example of RFC 8291, section 5 and appendix A, and a VAPID token that
 * verifies under its own key.
 */

#define	OPENSSL_SUPPRESS_DEPRECATED

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <atf-c.h>

#include "../webpush.h"

/* A P-256 key from its private scalar, as the RFC gives the sender's. */
static EVP_PKEY *
key_of(const char *b64priv)
{
	EC_KEY		*ec;
	EC_POINT	*pub;
	EVP_PKEY	*pk;
	BIGNUM		*d;
	uint8_t		*raw;
	size_t		 len;

	ATF_REQUIRE((raw = wp_unb64url(b64priv, &len)) != NULL);
	ATF_REQUIRE_EQ(32, len);
	ATF_REQUIRE((ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) !=
	    NULL);
	ATF_REQUIRE((d = BN_bin2bn(raw, 32, NULL)) != NULL);
	ATF_REQUIRE((pub = EC_POINT_new(EC_KEY_get0_group(ec))) != NULL);
	ATF_REQUIRE(EC_POINT_mul(EC_KEY_get0_group(ec), pub, d, NULL, NULL,
	    NULL) == 1);
	ATF_REQUIRE(EC_KEY_set_private_key(ec, d) == 1);
	ATF_REQUIRE(EC_KEY_set_public_key(ec, pub) == 1);
	ATF_REQUIRE((pk = EVP_PKEY_new()) != NULL);
	ATF_REQUIRE(EVP_PKEY_assign_EC_KEY(pk, ec) == 1);
	EC_POINT_free(pub);
	BN_free(d);
	free(raw);
	return (pk);
}

ATF_TC_WITHOUT_HEAD(rfc8291);
ATF_TC_BODY(rfc8291, tc)
{
	static const char plain[] =
	    "When I grow up, I want to be a watermelon";
	static const char want[] =
	    "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml"
	    "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT"
	    "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";
	EVP_PKEY	*as;
	uint8_t		*ua, *auth, *salt, *out;
	char		*got, *aspub;
	unsigned char	*enc;
	size_t		 len, outlen;

	as = key_of("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw");
	/* The key made from the scalar is the one the RFC names. */
	ATF_REQUIRE_EQ(65, EVP_PKEY_get1_encoded_public_key(as, &enc));
	aspub = wp_b64url(enc, 65);
	ATF_CHECK_STREQ("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vC"
	    "YLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8", aspub);
	ATF_REQUIRE((ua = wp_unb64url("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhq"
	    "UzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4", &len)) != NULL);
	ATF_REQUIRE_EQ(65, len);
	ATF_REQUIRE((auth = wp_unb64url("BTBZMqHH6r4Tts7J_aSIgg", &len)) !=
	    NULL);
	ATF_REQUIRE_EQ(16, len);
	ATF_REQUIRE((salt = wp_unb64url("DGv6ra1nlYgDCS1FRnbzlw", &len)) !=
	    NULL);
	ATF_REQUIRE_EQ(16, len);

	ATF_REQUIRE(wp_encrypt(ua, auth, as, salt, (const uint8_t *)plain,
	    strlen(plain), &out, &outlen) == 0);
	got = wp_b64url(out, outlen);
	ATF_CHECK_STREQ(want, got);

	/* Made by itself, with a key and a salt of its own: not the same
	 * twice, and of the same length. */
	free(out);
	ATF_REQUIRE(wp_encrypt(ua, auth, NULL, NULL, (const uint8_t *)plain,
	    strlen(plain), &out, &len) == 0);
	ATF_CHECK_EQ(outlen, len);
	free(got);
	got = wp_b64url(out, len);
	ATF_CHECK(strcmp(want, got) != 0);
}

ATF_TC_WITHOUT_HEAD(vapid);
ATF_TC_BODY(vapid, tc)
{
	EVP_PKEY	*key;
	EVP_MD_CTX	*md;
	ECDSA_SIG	*sig;
	uint8_t		*raw, *claims;
	unsigned char	*der, *dp;
	char		*hdr, *t, *k, *dot1, *dot2;
	size_t		 len;
	int		 derlen;

	ATF_REQUIRE((key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")) !=
	    NULL);
	ATF_REQUIRE((hdr = wp_vapid(key, "https://push.example",
	    "https://console.example", 1700000000)) != NULL);
	ATF_REQUIRE(strncmp(hdr, "vapid t=", 8) == 0);
	t = hdr + 8;
	ATF_REQUIRE((k = strstr(t, ", k=")) != NULL);
	*k = '\0';
	k += 4;
	ATF_REQUIRE((raw = wp_unb64url(k, &len)) != NULL);
	ATF_CHECK_EQ(65, len);
	free(raw);

	/* header.claims.signature; the claims say whom, until when, who. */
	ATF_REQUIRE((dot1 = strchr(t, '.')) != NULL);
	ATF_REQUIRE((dot2 = strchr(dot1 + 1, '.')) != NULL);
	*dot2 = '\0';
	ATF_REQUIRE((claims = wp_unb64url(dot1 + 1, &len)) != NULL);
	claims[len] = '\0';
	ATF_CHECK_STREQ("{\"aud\":\"https://push.example\",\"exp\":1700043200,"
	    "\"sub\":\"https://console.example\"}", (char *)claims);

	/* The signature, r and s as they are, verifies under the key. */
	ATF_REQUIRE((raw = wp_unb64url(dot2 + 1, &len)) != NULL);
	ATF_REQUIRE_EQ(64, len);
	ATF_REQUIRE((sig = ECDSA_SIG_new()) != NULL);
	ATF_REQUIRE(ECDSA_SIG_set0(sig, BN_bin2bn(raw, 32, NULL),
	    BN_bin2bn(raw + 32, 32, NULL)) == 1);
	der = NULL;
	ATF_REQUIRE((derlen = i2d_ECDSA_SIG(sig, &der)) > 0);
	dp = der;
	ATF_REQUIRE((md = EVP_MD_CTX_new()) != NULL);
	ATF_REQUIRE(EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, key) ==
	    1);
	ATF_CHECK_EQ(1, EVP_DigestVerify(md, dp, (size_t)derlen,
	    (unsigned char *)t, strlen(t)));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, rfc8291);
	ATF_TP_ADD_TC(tp, vapid);
	return (atf_no_error());
}
