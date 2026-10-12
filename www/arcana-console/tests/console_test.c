/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console end to end: kore(1) with arcana-console.so and a arcana-agent(8)
 * with a stand-in for jail(8), both on sockets in the work directory,
 * driven over HTTP.  The test is its own WebAuthn authenticator: it makes
 * ES256 and Ed25519 keys with libcrypto and builds authenticator data and
 * clientDataJSON byte by byte, the way a security key and a browser do.
 *
 * Configuration variables: kore (the kore binary), dhparam (Kore's DH
 * parameters), arcana-agent.
 */

#include <sys/param.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ucl.h>
#include <unistd.h>

#include "harness.h"


struct authn {
	EVP_PKEY	*key;
	int		 alg;
	uint8_t		 id[16];
};



/* base64url without padding. */
static char *
b64url(const void *data, size_t len)
{
	char	*out, *p;

	ATF_REQUIRE((out = malloc(4 * ((len + 2) / 3) + 1)) != NULL);
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

static void
authn_new(struct authn *a, int alg)
{

	a->alg = alg;
	a->key = alg == -7 ? EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256") :
	    EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
	ATF_REQUIRE(a->key != NULL);
	arc4random_buf(a->id, sizeof(a->id));
}

/* rpIdHash | flags | counter [| aaguid | idlen | id | key] */
static size_t
auth_data(uint8_t *ad, const char *rpid, uint8_t flags, uint32_t count,
    const struct authn *a)
{
	unsigned int	mdlen;
	size_t		len;

	EVP_Digest(rpid, strlen(rpid), ad, &mdlen, EVP_sha256(), NULL);
	ad[32] = flags;
	ad[33] = (uint8_t)(count >> 24);
	ad[34] = (uint8_t)(count >> 16);
	ad[35] = (uint8_t)(count >> 8);
	ad[36] = (uint8_t)count;
	len = 37;
	if (a != NULL) {
		memset(ad + len, 0, 16);
		len += 16;
		ad[len++] = 0;
		ad[len++] = sizeof(a->id);
		memcpy(ad + len, a->id, sizeof(a->id));
		len += sizeof(a->id);
		ad[len++] = 0xa0;	/* the COSE key; the server uses SPKI */
	}
	return (len);
}

static char *
client_data(const char *type, const char *challenge, const char *origin)
{
	char	cd[512];

	snprintf(cd, sizeof(cd), "{\"type\":\"%s\",\"challenge\":\"%s\","
	    "\"origin\":\"%s\",\"crossOrigin\":false}", type, challenge,
	    origin);
	return (strdup(cd));
}

/* navigator.credentials.create(), as a browser and a key would do it. */
static void
do_register(struct authn *a, const char *token, struct resp *r)
{
	struct resp	 b;
	uint8_t		 ad[256], *spki;
	char		 body[4096], *cd, *id64, *cd64, *ad64, *pk64, *p;
	size_t		 adlen;
	int		 spkilen;

	snprintf(body, sizeof(body), "{\"setup_token\":\"%s\"}",
	    token != NULL ? token : "");
	http("POST", "/api/auth/register/begin", body, &b);
	EXPECT(&b, 200);
	cd = client_data("webauthn.create", jstr(&b, "publicKey.challenge"),
	    harness_origin);
	adlen = auth_data(ad, RP_ID, 0x41, 0, a);
	spki = NULL;
	ATF_REQUIRE((spkilen = i2d_PUBKEY(a->key, &spki)) > 0);
	id64 = b64url(a->id, sizeof(a->id));
	cd64 = b64url(cd, strlen(cd));
	ad64 = b64url(ad, adlen);
	pk64 = b64url(spki, (size_t)spkilen);
	snprintf(body, sizeof(body), "{\"id\":\"%s\",\"clientDataJSON\":\"%s\","
	    "\"authenticatorData\":\"%s\",\"publicKey\":\"%s\","
	    "\"publicKeyAlgorithm\":%d,\"transports\":[\"usb\"],"
	    "\"name\":\"key %d\"}", id64, cd64, ad64, pk64, a->alg, a->alg);
	http("POST", "/api/auth/register/finish", body, r);
	resp_free(&b);
	p = (char *)spki;
	OPENSSL_free(p);
	free(cd);
	free(id64);
	free(cd64);
	free(ad64);
	free(pk64);
}

/*
 * navigator.credentials.get(): sign authenticatorData || SHA-256 of
 * clientDataJSON.  origin, rpid and the challenge can be wrong on purpose;
 * flip corrupts the signature.
 */
static void
do_login(struct authn *a, uint32_t count, const char *origin,
    const char *rpid, const char *challenge, bool flip, struct resp *r)
{
	struct resp	 b;
	EVP_MD_CTX	*ctx;
	uint8_t		 ad[64], msg[128], sig[256];
	char		 body[4096], *cd, *id64, *cd64, *ad64, *sig64;
	size_t		 adlen, siglen;
	unsigned int	 mdlen;

	http("POST", "/api/auth/login/begin", "{}", &b);
	EXPECT(&b, 200);
	cd = client_data("webauthn.get", challenge != NULL ? challenge :
	    jstr(&b, "publicKey.challenge"), origin);
	adlen = auth_data(ad, rpid, 0x05, count, NULL);
	memcpy(msg, ad, adlen);
	EVP_Digest(cd, strlen(cd), msg + adlen, &mdlen, EVP_sha256(), NULL);
	ATF_REQUIRE((ctx = EVP_MD_CTX_new()) != NULL);
	siglen = sizeof(sig);
	ATF_REQUIRE(EVP_DigestSignInit(ctx, NULL, a->alg == -7 ?
	    EVP_sha256() : NULL, NULL, a->key) == 1);
	ATF_REQUIRE(EVP_DigestSign(ctx, sig, &siglen, msg, adlen + 32) == 1);
	EVP_MD_CTX_free(ctx);
	if (flip)
		sig[siglen - 1] ^= 1;
	id64 = b64url(a->id, sizeof(a->id));
	cd64 = b64url(cd, strlen(cd));
	ad64 = b64url(ad, adlen);
	sig64 = b64url(sig, siglen);
	snprintf(body, sizeof(body), "{\"id\":\"%s\",\"clientDataJSON\":\"%s\","
	    "\"authenticatorData\":\"%s\",\"signature\":\"%s\"}", id64, cd64,
	    ad64, sig64);
	http("POST", "/api/auth/login/finish", body, r);
	resp_free(&b);
	free(cd);
	free(id64);
	free(cd64);
	free(ad64);
	free(sig64);
}

static char *
setup_token(void)
{
	FILE	*fp;
	char	 buf[128];

	ATF_REQUIRE((fp = fopen("data/setup-token", "r")) != NULL);
	ATF_REQUIRE(fgets(buf, sizeof(buf), fp) != NULL);
	fclose(fp);
	buf[strcspn(buf, "\n")] = '\0';
	return (strdup(buf));
}

/* Register an ES256 key with the setup token: logged in after. */
static void
enrol(struct authn *a)
{
	struct resp	 r;
	char		*tok;

	authn_new(a, -7);
	tok = setup_token();
	do_register(a, tok, &r);
	EXPECT(&r, 200);
	free(tok);
	resp_free(&r);
}

#define	CONSOLE_TC(name, descr)						\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	atf_tc_set_md_var(tc, "timeout", "60");				\
}									\
ATF_TC_CLEANUP(name, tc)						\
{									\
	stop();								\
}

CONSOLE_TC(unauthenticated, "Without a session only health and status work")
ATF_TC_BODY(unauthenticated, tc)
{
	struct resp	r;

	start(tc, 0, NULL);
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "setup_required"));
	ATF_CHECK_STREQ(harness_origin, jstr(&r, "origin"));
	ATF_CHECK_STREQ("false", jstr(&r, "authenticated"));
	resp_free(&r);
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 401);
	ATF_CHECK_STREQ("unauthenticated", jstr(&r, "error.code"));
	resp_free(&r);
	http("GET", "/api/auth/credentials", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http("POST", "/api/auth/login/begin", "{}", &r);
	EXPECT(&r, 409);
	resp_free(&r);
	http("GET", "/", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK_EQ(0, access("data/setup-token", R_OK));
}

CONSOLE_TC(setup_token, "The first key needs the setup token")
ATF_TC_BODY(setup_token, tc)
{
	struct resp	r;
	struct stat	sb;

	start(tc, 0, NULL);
	ATF_REQUIRE(stat("data/setup-token", &sb) == 0);
	ATF_CHECK_EQ(0600, sb.st_mode & 0777);
	http("POST", "/api/auth/register/begin", "{}", &r);
	EXPECT(&r, 403);
	ATF_CHECK_STREQ("setup_token", jstr(&r, "error.code"));
	resp_free(&r);
	http("POST", "/api/auth/register/begin",
	    "{\"setup_token\":\"0000000000000000000000000000000000000000000000"
	    "000000000000000000\"}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
}

CONSOLE_TC(register_login, "Register an ES256 key, log out, log in")
ATF_TC_BODY(register_login, tc)
{
	struct authn	a;
	struct resp	r;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_CHECK_MSG(cookie[0] != '\0', "no session cookie after enrolment");
	ATF_CHECK_MSG(access("data/setup-token", F_OK) == -1,
	    "setup token left behind");
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "authenticated"));
	ATF_CHECK_STREQ("false", jstr(&r, "setup_required"));
	resp_free(&r);
	http("GET", "/api/auth/credentials", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("key -7", jstr(&r, "credentials.0.name"));
	ATF_CHECK_EQ(NULL, jstr(&r, "credentials.0.public_key"));
	resp_free(&r);

	/* Once a key exists, the setup token is no longer a way in. */
	send_xjg = false;
	http("POST", "/api/auth/register/begin", "{}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	send_xjg = true;

	http("POST", "/api/auth/logout", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK_STREQ("", cookie);
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);

	do_login(&a, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "authenticated"));
	resp_free(&r);
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);

	/* The counter has to move forward. */
	cookie[0] = '\0';
	do_login(&a, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "counter") != NULL, "%s", r.body);
	resp_free(&r);
	do_login(&a, 2, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
}

CONSOLE_TC(login_refused, "Wrong origin, RP, challenge or signature")
ATF_TC_BODY(login_refused, tc)
{
	struct authn	a, other;
	struct resp	r, b;
	char		old[64];

	start(tc, 0, NULL);
	enrol(&a);
	cookie[0] = '\0';

	do_login(&a, 5, "https://evil.example", RP_ID, NULL, false, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "origin") != NULL, "%s", r.body);
	resp_free(&r);
	do_login(&a, 6, ORIGIN, "evil.example", NULL, false, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "relying party") != NULL, "%s", r.body);
	resp_free(&r);
	do_login(&a, 7, ORIGIN, RP_ID, NULL, true, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "signature") != NULL, "%s", r.body);
	resp_free(&r);

	/* A challenge the console did not make, or made too long ago. */
	do_login(&a, 8, ORIGIN, RP_ID, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	    "AAA", false, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "challenge") != NULL, "%s", r.body);
	resp_free(&r);

	authn_new(&other, -7);
	do_login(&other, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	ATF_CHECK_STREQ("", cookie);

	/*
	 * Others asking to log in meanwhile do not take one's challenge
	 * away: nobody can keep the rest out by asking often.  And a
	 * challenge works once.
	 */
	http("POST", "/api/auth/login/begin", "{}", &b);
	strlcpy(old, jstr(&b, "publicKey.challenge"), sizeof(old));
	resp_free(&b);
	for (int i = 0; i < 100; i++) {
		http("POST", "/api/auth/login/begin", "{}", &b);
		EXPECT(&b, 200);
		resp_free(&b);
	}
	do_login(&a, 9, ORIGIN, RP_ID, old, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	do_login(&a, 10, ORIGIN, RP_ID, old, false, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "challenge") != NULL, "%s", r.body);
	resp_free(&r);
}

/* The SHA-256 of a signing certificate, as apksigner prints it. */
#define	APP_FP	"00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:"	\
		"10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F"

CONSOLE_TC(android, "The Android app of web.conf: its assetlinks.json, and "
    "logins made in it, whose origin is its signing key's hash")
ATF_TC_BODY(android, tc)
{
	struct authn	 a;
	struct resp	 r;
	uint8_t		 h[32];
	char		 origin[128], *h64;
	int		 i;

	for (i = 0; i < 32; i++)
		h[i] = (uint8_t)i;
	h64 = b64url(h, sizeof(h));
	snprintf(origin, sizeof(origin), "android:apk-key-hash:%s", h64);
	free(h64);
	snprintf(harness_webconf, sizeof(harness_webconf), "android {\n"
	    "\tpackage = \"org.example.arcana\";\n"
	    "\tfingerprints = [ \"%s\", \"%s\" ];\n}\n", APP_FP,
	    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
	start(tc, 0, NULL);

	/* Before any login: Android asks for it as anyone would. */
	http("GET", "/.well-known/assetlinks.json", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("android_app", jstr(&r, "0.target.namespace"));
	ATF_CHECK_STREQ("org.example.arcana", jstr(&r,
	    "0.target.package_name"));
	ATF_CHECK_STREQ(APP_FP, jstr(&r, "0.target.sha256_cert_fingerprints.0"));
	ATF_CHECK_STREQ("1F:1E:1D:1C:1B:1A:19:18:17:16:15:14:13:12:11:10:"
	    "0F:0E:0D:0C:0B:0A:09:08:07:06:05:04:03:02:01:00", jstr(&r,
	    "0.target.sha256_cert_fingerprints.1"));
	ATF_CHECK_STREQ("delegate_permission/common.get_login_creds",
	    jstr(&r, "0.relation.1"));
	resp_free(&r);

	enrol(&a);
	cookie[0] = '\0';
	do_login(&a, 1, origin, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "authenticated"));
	resp_free(&r);

	/* Another app, or the right hash under another scheme: no. */
	cookie[0] = '\0';
	do_login(&a, 2, "android:apk-key-hash:"
	    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", RP_ID, NULL, false,
	    &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "origin") != NULL, "%s", r.body);
	resp_free(&r);
	do_login(&a, 3, origin + strlen("android:"), RP_ID, NULL, false, &r);
	EXPECT(&r, 401);
	resp_free(&r);
}

CONSOLE_TC(android_none, "Without an Android app, no assetlinks.json and no "
    "logins from an app")
ATF_TC_BODY(android_none, tc)
{
	struct authn	 a;
	struct resp	 r;

	start(tc, 0, NULL);
	http("GET", "/.well-known/assetlinks.json", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	enrol(&a);
	cookie[0] = '\0';
	do_login(&a, 1, "android:apk-key-hash:"
	    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", RP_ID, NULL, false,
	    &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "origin") != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(second_key, "A spare Ed25519 key, added from a session")
ATF_TC_BODY(second_key, tc)
{
	struct authn	a, b;
	struct resp	r, pk;
	char		path[256];

	start(tc, 0, NULL);
	enrol(&a);
	authn_new(&b, -8);
	do_register(&b, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	cookie[0] = '\0';
	/* A passkey login names no credentials: the authenticator picks. */
	http("POST", "/api/auth/login/begin", "{\"discoverable\":true}", &pk);
	EXPECT(&pk, 200);
	ATF_CHECK(jstr(&pk, "publicKey.allowCredentials.0.id") == NULL);
	ATF_CHECK(jstr(&pk, "publicKey.rpId") != NULL);
	resp_free(&pk);
	do_login(&b, 0, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/auth/credentials", NULL, &r);
	ATF_CHECK_STREQ("key -8", jstr(&r, "credentials.1.name"));
	snprintf(path, sizeof(path), "/api/auth/credentials/%s",
	    jstr(&r, "credentials.0.id"));
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/auth/credentials", NULL, &r);
	snprintf(path, sizeof(path), "/api/auth/credentials/%s",
	    jstr(&r, "credentials.0.id"));
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 409);
	resp_free(&r);
}

CONSOLE_TC(csrf, "Changes need X-Arcana and our Origin")
ATF_TC_BODY(csrf, tc)
{
	struct authn	a;
	struct resp	r;
	const char	*add = "{\"name\":\"x\",\"uri\":\"unix:/x.sock\"}";

	start(tc, 0, NULL);
	enrol(&a);
	send_xjg = false;
	http("POST", "/api/servers", add, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	send_xjg = true;
	origin_hdr = "https://evil.example";
	http("POST", "/api/servers", add, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	origin_hdr = ORIGIN;
	http("POST", "/api/servers", add, &r);
	EXPECT(&r, 200);
	resp_free(&r);
}

CONSOLE_TC(jails, "Servers, jails, actions and addresses through arcana-agent")
ATF_TC_BODY(jails, tc)
{
	struct authn		 a;
	struct resp		 r;
	const ucl_object_t	*t, *s;
	ucl_object_iter_t	 it;
	char			 cwd[MAXPATHLEN], body[MAXPATHLEN + 64];
	char			 base[64], path[128];
	bool			 api, auth, lib, daemon, exec;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(base, sizeof(base), "/api/servers/%s",
	    jstr(&r, "servers.0.id"));
	ATF_CHECK_STREQ("true", jstr(&r, "servers.0.local"));
	resp_free(&r);
	http("POST", "/api/servers", "{\"name\":\"x\",\"uri\":\"http://x\"}",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);

	snprintf(path, sizeof(path), "%s/hello", base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("FreeBSD", jstr(&r, "host.sysname"));
	resp_free(&r);

	snprintf(path, sizeof(path), "%s/jails", base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	/* JSON that a strict parser takes: each step's status once, never
	 * a key twice (",," and an array where a word goes). */
	ATF_CHECK_MSG(strstr(r.body, ",,") == NULL && strstr(r.body,
	    "\"status\":[") == NULL, "%s", r.body);
	{
		FILE	*fp;

		ATF_REQUIRE((fp = fopen("jails.json", "w")) != NULL);
		fputs(r.body, fp);
		fclose(fp);
		ATF_CHECK_MSG(system("python3 -c 'import json; json.load(open("
		    "\"jails.json\"))'") == 0, "not strict JSON: %s", r.body);
	}
	ATF_CHECK(jail_named(&r, "db") != NULL);
	ATF_CHECK_STREQ("stopped", jail_str(&r, "web", "state"));
	ATF_CHECK_STREQ("10.0.0.10", jail_str(&r, "web", "ip4.0"));
	ATF_CHECK_STREQ("/jails/web", jail_str(&r, "web", "path"));
	ATF_CHECK_STREQ("true", jail_str(&r, "web", "configured"));
	/* One trace: the console's steps over the daemon's. */
	api = auth = lib = daemon = exec = false;
	t = ucl_object_lookup(r.json, "trace");
	it = NULL;
	while ((s = ucl_object_iterate(t, &it, true)) != NULL) {
		const char *k = ucl_object_tostring(ucl_object_lookup(s,
		    "kind"));

		api |= strcmp(k, "api") == 0;
		auth |= strcmp(k, "auth") == 0;
		lib |= strcmp(k, "lib") == 0;
		daemon |= strcmp(k, "daemon") == 0 &&
		    ucl_object_toint(ucl_object_lookup(s, "parent")) == 2;
		if (strcmp(k, "exec") == 0 && strstr(ucl_object_tostring(
		    ucl_object_lookup(s, "output")), "name=web") != NULL)
			exec = true;
	}
	ATF_CHECK(api && auth && lib && daemon && exec);
	resp_free(&r);

	snprintf(path, sizeof(path), "%s/jails/web/action", base);
	http("POST", path, "{\"action\":\"start\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(r.body, "fake-jail: -f etc/jail.conf -c web") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("POST", path, "{\"action\":\"reboot\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/jails/web/action", base);
	http("POST", path, "{\"action\":\"stop\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_STREQ("jail 'web' is not running", jstr(&r, "error"));
	resp_free(&r);

	snprintf(path, sizeof(path), "%s/jails/web/address", base);
	http("POST", path, "{\"address\":\"10.0.0.11\",\"persist\":true,"
	    "\"dry_run\":true}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(jstr(&r, "diff"),
	    "+\tip4.addr = 10.0.0.10, \"10.0.0.11\";") != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(agent_update, "The console sends its arcana-agent to a host, "
    "which puts it in place and restarts on request")
ATF_TC_BODY(agent_update, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[160], jails[160], cwd[MAXPATHLEN], body[MAXPATHLEN];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/servers/%s/agent-update", jstr(&r,
	    "servers.0.id"));
	resp_free(&r);

	/* The console says which build it sends; the host runs that one
	 * here, so the page has nothing to offer. */
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "agent_build") != NULL);
	strlcpy(body, jstr(&r, "agent_build"), sizeof(body));
	ATF_CHECK_EQ(64, strlen(body));
	resp_free(&r);
	snprintf(jails, sizeof(jails), "%.*s/jails", (int)(strrchr(path, '/') -
	    path), path);
	http("GET", jails, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(body, jstr(&r, "host.build"));
	resp_free(&r);

	/* With no repository named, there is nothing to build from. */
	snprintf(jails, sizeof(jails), "%.*s/agent-build", (int)(strrchr(path,
	    '/') - path), path);
	http("POST", jails, "{}", &r);
	EXPECT(&r, 409);
	resp_free(&r);

	ATF_REQUIRE(access("installed-agent", F_OK) == -1);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("false", jstr(&r, "restarting"));
	ATF_CHECK(jstr(&r, "version") != NULL);
	ATF_CHECK(access("installed-agent", X_OK) == 0);
	resp_free(&r);

	http("POST", path, "{\"restart\":true}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("true", jstr(&r, "restarting"));
	ATF_CHECK(access("installed-agent.old", F_OK) == 0);
	resp_free(&r);
}

CONSOLE_TC(update_notes, "What is new in the repository since the version "
    "running: the commit messages, new until the version's own commit, or "
    "the tags' messages where there are any")
ATF_TC_BODY(update_notes, tc)
{
	struct authn	a;
	struct resp	r;
	FILE		*fp;
	char		cwd[MAXPATHLEN], body[MAXPATHLEN];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	harness_other_agent = true;
	snprintf(harness_webconf, sizeof(harness_webconf), "agent_source = "
	    "\"https://example.org/arcana.git\";\nagent_ref = \"main\";\n");
	start(tc, 0, NULL);
	enrol(&a);
	/* No server yet: nothing to read the repository through. */
	http("GET", "/api/update/notes?component=console&from=0.2.0", NULL, &r);
	EXPECT(&r, 409);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* Three commits, the middle one the version running: the newest
	 * is new, the running one marked, the oldest neither. */
	ATF_REQUIRE((fp = fopen("commits", "w")) != NULL);
	fprintf(fp, "cccc\037300\037console 0.3.0: three\037the third's body\036"
	    "bbbb\037200\037agent 0.9.0, console 0.2.0: two\037\036"
	    "aaaa\037100\037console 0.1.0: one\037\036");
	fclose(fp);
	http("GET", "/api/update/notes?component=console&from=0.2.0", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "kind") != NULL && jstr(&r, "host") != NULL &&
	    jstr(&r, "notes.0.title") != NULL, "%d %s", r.status, r.body);
	ATF_CHECK_STREQ("commits", jstr(&r, "kind"));
	ATF_CHECK_STREQ("here", jstr(&r, "host"));
	ATF_CHECK_STREQ("console 0.3.0: three", jstr(&r, "notes.0.title"));
	ATF_CHECK_STREQ("true", jstr(&r, "notes.0.new"));
	ATF_CHECK_STREQ("the third's body", jstr(&r, "notes.0.body"));
	ATF_CHECK_STREQ("false", jstr(&r, "notes.1.new"));
	ATF_CHECK_STREQ("true", jstr(&r, "notes.1.here"));
	ATF_CHECK_STREQ("false", jstr(&r, "notes.2.new"));
	ATF_CHECK_STREQ("false", jstr(&r, "notes.2.here"));
	resp_free(&r);
	/* The agents: what is up to the console's version, from a version
	 * no commit names: everything up to it. */
	http("GET", "/api/update/notes?component=agent&from=0.8.0&to=0.9.0",
	    NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "notes.0.new"));
	ATF_CHECK_STREQ("true", jstr(&r, "notes.1.new"));
	ATF_CHECK_STREQ("true", jstr(&r, "notes.2.new"));
	resp_free(&r);
	/* Tags with messages, one newer: the release notes instead, read
	 * again when asked fresh. */
	ATF_REQUIRE((fp = fopen("tags", "w")) != NULL);
	fprintf(fp, "v0.3.0\037300\037Release three\n\nWith the record.\036"
	    "v0.2.0\037200\037Release two\036");
	fclose(fp);
	http("GET", "/api/update/notes?component=console&from=0.2.0", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("commits", jstr(&r, "kind"));
	resp_free(&r);
	http("GET", "/api/update/notes?component=console&from=0.2.0&fresh=1",
	    NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("tags", jstr(&r, "kind"));
	ATF_CHECK_STREQ("v0.3.0", jstr(&r, "notes.0.title"));
	ATF_CHECK_STREQ("true", jstr(&r, "notes.0.new"));
	ATF_CHECK_MSG(strncmp(jstr(&r, "notes.0.body"), "Release three", 13) == 0,
	    "%s", r.body);
	ATF_CHECK_STREQ("true", jstr(&r, "notes.1.here"));
	ATF_CHECK_STREQ("false", jstr(&r, "notes.1.new"));
	resp_free(&r);
}

CONSOLE_TC(agent_build, "A host builds arcana-agent from the repository "
    "the console names, and the console keeps it to send")
ATF_TC_BODY(agent_build, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[160], cwd[MAXPATHLEN], body[MAXPATHLEN], sha[65];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	harness_other_agent = true;
	snprintf(harness_webconf, sizeof(harness_webconf), "agent_source = "
	    "\"https://example.org/arcana.git\";\nagent_ref = \"main\";\n");
	start(tc, 0, NULL);
	/* Where the agent is built from is not told to who is not in. */
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "agent_source") == NULL);
	ATF_CHECK(jstr(&r, "agent_ref") == NULL);
	resp_free(&r);
	enrol(&a);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/servers/%s/agent-build", jstr(&r,
	    "servers.0.id"));
	resp_free(&r);

	/* Before: the one installed with the console, another build. */
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("https://example.org/arcana.git", jstr(&r,
	    "agent_source"));
	ATF_CHECK_STREQ("main", jstr(&r, "agent_ref"));
	ATF_CHECK(jstr(&r, "agent_version") != NULL);
	strlcpy(sha, jstr(&r, "agent_build"), sizeof(sha));
	resp_free(&r);

	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK(jstr(&r, "version") != NULL);
	ATF_REQUIRE(jstr(&r, "sha256") != NULL);
	ATF_CHECK(strcmp(sha, jstr(&r, "sha256")) != 0);
	strlcpy(sha, jstr(&r, "sha256"), sizeof(sha));
	resp_free(&r);
	ATF_CHECK(access("data/agent/arcana-agent", X_OK) == 0);

	/* After: what the host built is what the console sends. */
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(sha, jstr(&r, "agent_build"));
	ATF_CHECK(jstr(&r, "agent_version") != NULL);
	resp_free(&r);

	/*
	 * Unless the one installed beside the console is newer, as after
	 * the console itself was updated: that one is of its version, and
	 * the built one of the version before.
	 */
	ATF_REQUIRE(system("touch -t 203001010000 other-agent") == 0);
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strcmp(sha, jstr(&r, "agent_build")) != 0);
	resp_free(&r);
	ATF_REQUIRE(system("touch -t 200001010000 other-agent") == 0);
	http("GET", "/api/health", NULL, &r);
	ATF_CHECK_STREQ(sha, jstr(&r, "agent_build"));
	resp_free(&r);

	/*
	 * Over SSH: the host hands back the server's host keys for the
	 * user to confirm, and builds once they come back confirmed.
	 */
	ATF_REQUIRE(system("ssh-keygen -q -t ed25519 -N '' -f hostkey") == 0);
	http("POST", "/api/settings", "{\"set\":{\"agent_source\":"
	    "\"git@git.example.org:me/arcana.git\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_REQUIRE(jstr(&r, "host_keys") != NULL);
	ATF_CHECK(strncmp(jstr(&r, "host_keys"), "git.example.org ssh-ed25519 ",
	    28) == 0);
	ATF_CHECK(jstr(&r, "fingerprints.0") != NULL && strstr(jstr(&r,
	    "fingerprints.0"), "SHA256:") != NULL);
	ATF_CHECK(jstr(&r, "deploy_key") != NULL);
	snprintf(body, sizeof(body), "{\"host_keys\":\"%.*s\"}",
	    (int)strcspn(jstr(&r, "host_keys"), "\n"), jstr(&r, "host_keys"));
	resp_free(&r);
	http("POST", path, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);
	ATF_CHECK(access("build/known_hosts", R_OK) == 0);
	/* Without a key named, the host shows its own. */
	ATF_CHECK(system("grep -q 'ssh -i .*/build/id_ed25519 ' git.log") == 0);

	/* The key named in Settings is the one git is told to show. */
	snprintf(body, sizeof(body), "{\"set\":{\"agent_ssh_key\":"
	    "\"%s/hostkey\"}}", cwd);
	http("POST", "/api/settings", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);
	snprintf(body, sizeof(body), "grep -q 'ssh -i %s/hostkey ' git.log",
	    cwd);
	ATF_CHECK(system(body) == 0);

	/*
	 * The console's own update, through the agent of its host: the
	 * tree is built and installed, and the console's service asked
	 * to restart.
	 */
	snprintf(body, sizeof(body), "%.*s/console-update", (int)(strrchr(path,
	    '/') - path), path);
	http("POST", body, "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("true", jstr(&r, "restarting"));
	resp_free(&r);
}

CONSOLE_TC(session_restart, "A login outlives a restart of the console; a "
    "logout does not")
ATF_TC_BODY(session_restart, tc)
{
	struct authn	a;
	struct resp	r;
	FILE		*fp;
	char		 buf[512];

	start(tc, 0, NULL);
	enrol(&a);
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* What is kept is the cookie's hash, for its user alone. */
	ATF_REQUIRE((fp = fopen("data/sessions.json", "r")) != NULL);
	ATF_REQUIRE(fread(buf, 1, sizeof(buf) - 1, fp) > 0);
	fclose(fp);
	ATF_CHECK(strstr(buf, "\"hash\"") != NULL);
	ATF_CHECK(strstr(buf, cookie + 12) == NULL);
	ATF_CHECK(system("test \"$(stat -f %Lp data/sessions.json)\" = 600")
	    == 0);

	restart_console();
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);

	/* Logged out, the session is gone from the file too, and stays
	 * gone over a restart. */
	strlcpy(buf, cookie, sizeof(buf));
	http("POST", "/api/auth/logout", "{}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	strlcpy(cookie, buf, sizeof(cookie));
	restart_console();
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
}

CONSOLE_TC(load, "The console keeps answering under many requests at once, "
    "some of them abandoned")
ATF_TC_BODY(load, tc)
{
	static const char *what[] = { "jails", "stats", "services",
	    "net/interfaces", "net/routes", "packages", "jobs" };
	struct authn	a;
	struct resp	r;
	char		base[96], path[160], cwd[MAXPATHLEN], body[MAXPATHLEN];
	pid_t		pids[8];
	int		i, k, status, bad;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(base, sizeof(base), "/api/servers/%s", jstr(&r,
	    "servers.0.id"));
	resp_free(&r);

	/* Eight clients at once, each asking for everything in turn and
	 * walking away from every third request. */
	for (k = 0; k < 8; k++) {
		if ((pids[k] = fork()) == 0) {
			bad = 0;
			for (i = 0; i < 42; i++) {
				snprintf(path, sizeof(path), "%s/%s", base,
				    what[(i + k) % 7]);
				if (i % 3 == 2) {
					http_abandon(path);
					continue;
				}
				http("GET", path, NULL, &r);
				if (r.status != 200)
					bad++;
				resp_free(&r);
				http("GET", "/api/health", NULL, &r);
				if (r.status != 200)
					bad++;
				resp_free(&r);
			}
			_exit(bad > 250 ? 250 : bad);
		}
		ATF_REQUIRE(pids[k] > 0);
	}
	for (k = 0; k < 8; k++) {
		ATF_REQUIRE(waitpid(pids[k], &status, 0) == pids[k]);
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "client %d: %d requests failed", k, WIFEXITED(status) ?
		    WEXITSTATUS(status) : -1);
	}
	/* It is the same process still, and it answers. */
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("! grep -Ei 'exited|signal|crash|fatal' kore.out") ==
	    0);
}

/* Wait for a run to end; its JSON in r. */
static void
run_wait(const char *n, struct resp *r)
{
	char	path[64];
	int	i;

	snprintf(path, sizeof(path), "/api/runs/%s", n);
	for (i = 0; i < 300; i++) {
		http("GET", path, NULL, r);
		if (r->status == 200 && jstr(r, "state") != NULL && strcmp(jstr(r,
		    "state"), "running") != 0)
			return;
		resp_free(r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(0, "run %s did not end", n);
}

CONSOLE_TC(workflows, "A workflow's steps checked against jobs.yaml, run on "
    "a host with its values, conditions and what follows a failure, and "
    "begun by the host's events")
ATF_TC_BODY(workflows, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[4096], sid[16], run[32], wid[16];
	char		path[128], every[16];
	FILE		*fp;
	int		i;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sid, sizeof(sid), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);

	/* What is not one, as jobs.yaml has the kinds. */
	static const char *const bad[][2] = {
		{ "{\"kind\":\"explode\"}", "one of jobs.yaml's" },
		{ "{\"kind\":\"service-action\",\"service\":\"sshd\","
		    "\"action\":\"start\",\"bogus\":1}", "has no bogus" },
		{ "{\"kind\":\"service-action\",\"service\":\"sshd\"}",
		    "needs action" },
		{ "{\"kind\":\"service-action\",\"service\":\"sshd\","
		    "\"action\":\"explode\"}", "one of start|stop" },
	};
	for (i = 0; i < 4; i++) {
		snprintf(body, sizeof(body), "{\"name\":\"bad\",\"hosts\":[\"%s\"],"
		    "\"steps\":[{\"id\":\"a\",\"job\":%s}]}", sid, bad[i][0]);
		http("POST", "/api/workflows", body, &r);
		EXPECT(&r, 400);
		ATF_CHECK_MSG(strstr(r.body, bad[i][1]) != NULL, "%s", r.body);
		resp_free(&r);
	}
	/* What runs by itself and destroys says so. */
	snprintf(body, sizeof(body), "{\"name\":\"bad\",\"hosts\":[\"%s\"],"
	    "\"every\":3600,\"steps\":[{\"id\":\"a\",\"job\":{\"kind\":"
	    "\"if-destroy\",\"interface\":\"gif9\"}}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "destructive") != NULL);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"bad\",\"steps\":[{\"id\":"
	    "\"a\",\"read\":\"hello\",\"on_fail\":\"a\"}]}");
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "a step after it") != NULL);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"bad\",\"hosts\":[\"%s\"],"
	    "\"every\":30,\"steps\":[{\"id\":\"a\",\"read\":\"hello\"}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/*
	 * A read, a job with a parameter when the read says so, one that
	 * fails and goes on further, one jumped over, a condition of a
	 * read made then, and one whose condition is not met.
	 */
	snprintf(body, sizeof(body), "{\"name\":\"restart\",\"hosts\":[\"%s\"],"
	    "\"params\":[{\"name\":\"svc\",\"default\":\"ntpd\"}],\"steps\":["
	    "{\"id\":\"r\",\"read\":\"hello\"},"
	    "{\"id\":\"a\",\"name\":\"Restart it\",\"job\":{\"kind\":"
	    "\"service-action\",\"service\":\"${param.svc}\",\"action\":"
	    "\"restart\"},\"when\":{\"step\":\"r\",\"path\":\"host.hostname\","
	    "\"op\":\"exists\"}},"
	    "{\"id\":\"b\",\"job\":{\"kind\":\"kmod\",\"verb\":\"load\","
	    "\"args\":[\"../evil\"]},\"on_fail\":\"d\"},"
	    "{\"id\":\"c\",\"job\":{\"kind\":\"service-action\",\"service\":"
	    "\"ntpd\",\"action\":\"stop\"}},"
	    "{\"id\":\"d\",\"read\":\"services\",\"when\":{\"read\":\"jails\","
	    "\"path\":\"jails[name=web].state\",\"op\":\"eq\",\"value\":"
	    "\"stopped\"}},"
	    "{\"id\":\"e\",\"job\":{\"kind\":\"service-action\",\"service\":"
	    "\"${param.svc}\",\"action\":\"stop\"},\"when\":{\"step\":\"r\","
	    "\"path\":\"host.hostname\",\"op\":\"eq\",\"value\":\"nope\"}}]}",
	    sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	snprintf(wid, sizeof(wid), "%s", jstr(&r, "id"));
	ATF_CHECK_EQ(8, strlen(wid));
	ATF_CHECK_STREQ("false", jstr(&r, "steps.1.destroys"));
	resp_free(&r);
	http("GET", "/api/workflows", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("restart", jstr(&r, "workflows.0.name"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/workflows/%s/run", wid);
	http("POST", path, "{\"params\":{\"svc\":\"sshd\"}}", &r);
	EXPECT(&r, 200);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("hand", jstr(&r, "trigger"));
	ATF_CHECK_STREQ("sshd", jstr(&r, "params.svc"));
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.0.state"));
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.1.state"));
	ATF_CHECK_STREQ("service sshd restart", jstr(&r,
	    "hosts.0.steps.1.title"));
	ATF_CHECK(jstr(&r, "hosts.0.steps.1.trace.job.trace.0.label") !=
	    NULL);
	/* Its traces are in the run's own file, not in the list. */
	snprintf(body, sizeof(body), "test -s data/runs/%s.json", run);
	ATF_CHECK(system(body) == 0);
	resp_free(&r);
	http("GET", "/api/runs", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "\"trace\"") == NULL);
	ATF_CHECK(strstr(r.body, "\"state\":\"done\"") != NULL);
	snprintf(path, sizeof(path), "/api/runs/%s", run);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("failed", jstr(&r, "hosts.0.steps.2.state"));
	ATF_CHECK_STREQ("not run", jstr(&r, "hosts.0.steps.3.state"));
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.4.state"));
	ATF_CHECK_STREQ("skipped", jstr(&r, "hosts.0.steps.5.state"));
	ATF_CHECK_STREQ("failed", jstr(&r, "state"));
	resp_free(&r);
	ATF_CHECK(system("grep -q 'sshd restart' service.log 2>/dev/null || "
	    "test -f running.sshd") == 0);
	/* The list has the runs, not their traces. */
	http("GET", "/api/runs", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(run, jstr(&r, "runs.0.id"));
	ATF_CHECK(strstr(r.body, "\"trace\"") == NULL);
	resp_free(&r);

	/*
	 * Arcana kept up to date from its repository: its head asked of
	 * the host, the agent built and sent to every host only when the
	 * head is newer, and the console updated through its host (by
	 * its local socket, as this one is: make install and the service
	 * restarted are stand-ins); a second run finds nothing new and
	 * builds nothing.
	 */
	http("POST", "/api/settings", "{\"set\":{\"agent_source\":"
	    "\"https://example.org/arcana.git\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_REQUIRE(system("echo 4444444444444444444444444444444444444444 > "
	    "head") == 0);
	snprintf(body, sizeof(body), "{\"name\":\"arcana\",\"hosts\":[\"%s\"],"
	    "\"every\":3600,\"steps\":["
	    "{\"id\":\"check\",\"arcana\":\"check\"},"
	    "{\"id\":\"build\",\"arcana\":\"build\",\"when\":{\"step\":"
	    "\"check\",\"path\":\"new\",\"op\":\"eq\",\"value\":\"true\"}},"
	    "{\"id\":\"agents\",\"arcana\":\"agents\",\"when\":{\"step\":"
	    "\"check\",\"path\":\"new_agents\",\"op\":\"eq\",\"value\":"
	    "\"true\"}},"
	    "{\"id\":\"console\",\"arcana\":\"console\",\"on_fail\":"
	    "\"continue\",\"when\":{\"step\":\"check\",\"path\":"
	    "\"new_console\",\"op\":\"eq\",\"value\":\"true\"}}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/workflows/%s/run", jstr(&r, "id"));
	resp_free(&r);
	http("POST", "/api/workflows", "{\"name\":\"bad\",\"steps\":[{\"id\":"
	    "\"a\",\"arcana\":\"explode\"}]}", &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "check, build, agents and console") != NULL);
	resp_free(&r);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.0.state"));
	ATF_CHECK_STREQ("4444444444444444444444444444444444444444", jstr(&r,
	    "hosts.0.steps.0.trace.commit"));
	ATF_CHECK_STREQ("true", jstr(&r, "hosts.0.steps.0.trace.new"));
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.1.state"));
	ATF_CHECK_STREQ("4444444444444444444444444444444444444444", jstr(&r,
	    "hosts.0.steps.1.trace.commit"));
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.2.state"));
	ATF_CHECK_STREQ("lab", jstr(&r, "hosts.0.steps.2.trace.hosts.0.host"));
	ATF_CHECK_STREQ("true", jstr(&r, "hosts.0.steps.2.trace.hosts.0.ok"));
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.3.state"));
	ATF_CHECK_STREQ("true", jstr(&r, "hosts.0.steps.3.trace.restarting"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '\"built\": *\"4444' data/arcana-source.json "
	    "&& grep -q '\"agents\": *\"4444' data/arcana-source.json && "
	    "grep -q '\"updated\": *\"4444' data/arcana-source.json") == 0);
	/* Nothing newer: nothing built, nothing sent. */
	ATF_REQUIRE(system(": > git.log") == 0);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("false", jstr(&r, "hosts.0.steps.0.trace.new_agents"));
	ATF_CHECK_STREQ("skipped", jstr(&r, "hosts.0.steps.1.state"));
	ATF_CHECK_STREQ("skipped", jstr(&r, "hosts.0.steps.2.state"));
	ATF_CHECK_STREQ("skipped", jstr(&r, "hosts.0.steps.3.state"));
	resp_free(&r);
	ATF_CHECK(system("! grep -q clone git.log") == 0);

	/*
	 * At an interval, counted from when it last ran by it, which a
	 * restart of the console does not forget: kept as having run 58 s
	 * before, a workflow of every minute runs within a tick or two of
	 * the console's start, not a minute after.
	 */
	snprintf(body, sizeof(body), "{\"name\":\"each minute\",\"hosts\":"
	    "[\"%s\"],\"every\":60,\"steps\":[{\"id\":\"s\",\"read\":"
	    "\"hello\"}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "id") != NULL);
	snprintf(every, sizeof(every), "%s", jstr(&r, "id"));
	resp_free(&r);
	ATF_REQUIRE((fp = fopen("data/every.json", "w")) != NULL);
	fprintf(fp, "{\"%s\": %lld}\n", every, (long long)time(NULL) - 58);
	fclose(fp);
	restart_console();
	for (i = 0; i < 150; i++) {
		http("GET", "/api/runs", NULL, &r);
		if (strstr(r.body, "\"each minute\"") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 150, "the interval was counted from the restart");
	ATF_CHECK(i == 150 || strstr(r.body, "\"trigger\":\"every\"") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/workflows/%s", every);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);

	/* Begun by the host's events: a threshold crossed, then the host
	 * that stops answering. */
	snprintf(body, sizeof(body), "{\"name\":\"on mem\",\"hosts\":[\"%s\"],"
	    "\"on\":[{\"event\":\"threshold\",\"match\":{\"what\":\"mem\","
	    "\"over\":\"true\"}}],\"steps\":[{\"id\":\"s\",\"read\":\"stats\"}]}",
	    sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"on down\",\"hosts\":[\"%s\"],"
	    "\"on\":[{\"event\":\"host-down\"}],\"steps\":[{\"id\":\"s\","
	    "\"read\":\"hello\"}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* A tick to learn where the events are; then the threshold. */
	sleep(7);
	snprintf(path, sizeof(path), "/api/servers/%s/history", sid);
	http("POST", path, "{\"step\":1,\"keep\":10,\"cpu\":90,\"mem\":1,"
	    "\"swap\":90}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 200; i++) {
		http("GET", "/api/runs", NULL, &r);
		if (strstr(r.body, "\"event threshold\"") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 200, "no run begun by the threshold");
	ATF_CHECK(strstr(r.body, "\"what\":\"mem\"") != NULL);
	resp_free(&r);
	ATF_REQUIRE(system("kill $(cat arcana-agent.pid)") == 0);
	for (i = 0; i < 200; i++) {
		http("GET", "/api/runs", NULL, &r);
		if (strstr(r.body, "\"event host-down\"") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	if (i == 200)
		(void)system("tail -20 kore.out >&2");
	ATF_CHECK_MSG(i < 200, "no run begun by the host going away");
	/* Subscribed to, not asked every few seconds: a host that goes is
	 * known at once. */
	ATF_CHECK_MSG(i < 30, "host-down came after %d ms", i * 100);
	resp_free(&r);

	ATF_CHECK(system("! grep -q 'exited with status' kore.out") == 0);
	/* Gone. */
	snprintf(path, sizeof(path), "/api/workflows/%s", wid);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
}

CONSOLE_TC(transfers, "A snapshot sent from one host to another, the "
    "console carrying it at the pace the receiver takes it")
ATF_TC_BODY(transfers, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[1200], sa[16], sb[16], id[32];
	int		i;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	/* Two names for the one agent here: two hosts to the console. */
	snprintf(body, sizeof(body), "{\"name\":\"a\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sa, sizeof(sa), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"b\",\"uri\":\"unix:%s/./"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sb, sizeof(sb), "%s", strcmp(jstr(&r, "servers.0.id"), sa) ==
	    0 ? jstr(&r, "servers.1.id") : jstr(&r, "servers.0.id"));
	resp_free(&r);
	/* More than the window: the relay waits on the receiver. */
	ATF_REQUIRE(system("dd if=/dev/random of=zsend.data bs=1m count=10 "
	    "2>/dev/null") == 0);
	snprintf(body, sizeof(body), "{\"from\":\"%s\",\"snapshot\":"
	    "\"tank/data@b\",\"to\":\"%s\",\"dataset\":\"tank/copy\"}", sa, sb);
	http("POST", "/api/transfers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "id"));
	resp_free(&r);
	for (i = 0; i < 300; i++) {
		http("GET", "/api/transfers", NULL, &r);
		if (jstr(&r, "transfers.0.state") != NULL && strcmp(jstr(&r,
		    "transfers.0.state"), "running") != 0)
			break;
		resp_free(&r);
		usleep(100000);
	}
	if (i == 300)
		(void)system("cat data/transfers.json; tail -5 storage.log; "
		    "ls -l zrecv.data; tail -20 kore.out; tail -20 "
		    "arcana-agent.out");
	ATF_REQUIRE(i < 300);
	ATF_CHECK_STREQ("done", jstr(&r, "transfers.0.state"));
	ATF_CHECK_STREQ("10485760", jstr(&r, "transfers.0.bytes"));
	ATF_CHECK_STREQ(id, jstr(&r, "transfers.0.id"));
	resp_free(&r);
	ATF_CHECK(system("cmp -s zsend.data zrecv.data") == 0);
	ATF_CHECK(system("grep -q '^zfs send tank/data@b$' storage.log && "
	    "grep -q '^zfs receive -u tank/copy$' storage.log") == 0);
	ATF_CHECK(system("test \"$(stat -f %Lp data/transfers.json)\" = 600")
	    == 0);

	/* Only what changed since a snapshot both have; a receive that
	 * refuses: said as zfs says it. */
	snprintf(body, sizeof(body), "{\"from\":\"%s\",\"snapshot\":"
	    "\"tank/data@b\",\"since\":\"tank/data@a\",\"to\":\"%s\","
	    "\"dataset\":\"tank/fail\"}", sa, sb);
	http("POST", "/api/transfers", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 300; i++) {
		http("GET", "/api/transfers", NULL, &r);
		if (jstr(&r, "transfers.1.state") != NULL && strcmp(jstr(&r,
		    "transfers.1.state"), "running") != 0)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE(i < 300);
	ATF_CHECK_STREQ("failed", jstr(&r, "transfers.1.state"));
	ATF_CHECK_MSG(jstr(&r, "transfers.1.error") != NULL && strstr(jstr(&r,
	    "transfers.1.error"), "destination 'tank/fail' exists") != NULL,
	    "%s", jstr(&r, "transfers.1.error"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^zfs send -i tank/data@a tank/data@b$' "
	    "storage.log") == 0);

	/* What is not one is refused before anything begins. */
	snprintf(body, sizeof(body), "{\"from\":\"%s\",\"snapshot\":"
	    "\"tank/data@b\",\"to\":\"%s\",\"dataset\":\"tank/x\"}", sa, sa);
	http("POST", "/api/transfers", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"from\":\"%s\",\"snapshot\":"
	    "\"tank/data@b\",\"to\":\"%s\",\"dataset\":\"tank\"}", sa, sb);
	http("POST", "/api/transfers", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"from\":\"%s\",\"snapshot\":"
	    "\"tank/data\",\"to\":\"%s\",\"dataset\":\"tank/x\"}", sa, sb);
	http("POST", "/api/transfers", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* Ended: nothing to stop. */
	snprintf(body, sizeof(body), "/api/transfers/%s", id);
	http("DELETE", body, NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
}

CONSOLE_TC(tokens, "A read-only API token, made in a session, reads what is "
    "said of the hosts and changes nothing; deleted, it opens nothing")
ATF_TC_BODY(tokens, tc)
{
	struct authn	a;
	struct resp	r;
	char		token[80], id[20], cwd[1024], body[1200], path[256];
	char		server[256];

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(server, sizeof(server), "/api/servers/%s/hello",
	    jstr(&r, "servers.0.id"));
	resp_free(&r);

	/* Made in a session, its value said once; kept as its hash only. */
	http("POST", "/api/tokens", "{\"name\":\"overlay planner\"}", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "token") != NULL);
	ATF_CHECK(strncmp(jstr(&r, "token"), "arcr_", 5) == 0);
	ATF_CHECK_EQ(69, strlen(jstr(&r, "token")));
	snprintf(token, sizeof(token), "%s", jstr(&r, "token"));
	snprintf(id, sizeof(id), "%s", jstr(&r, "id"));
	resp_free(&r);
	snprintf(path, sizeof(path), "grep -q '%s' data/tokens.json", token + 5);
	ATF_CHECK(system(path) != 0);
	ATF_CHECK(system("test \"$(stat -f %Lp data/tokens.json)\" = 600") ==
	    0);
	http("GET", "/api/tokens", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("overlay planner", jstr(&r, "tokens.0.name"));
	ATF_CHECK(jstr(&r, "tokens.0.token") == NULL);
	resp_free(&r);

	/* It reads what is said of the hosts... */
	http_bearer("GET", "/api/servers", token, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lab", jstr(&r, "servers.0.name"));
	resp_free(&r);
	http_bearer("GET", server, token, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* ... and changes nothing, nor reads the console's own. */
	http_bearer("POST", "/api/servers", token, "{\"name\":\"x\",\"uri\":"
	    "\"unix:/nonexistent\"}", &r);
	EXPECT(&r, 401);
	ATF_CHECK(strstr(r.body, "reads only") != NULL);
	resp_free(&r);
	http_bearer("POST", "/api/tokens", token, "{\"name\":\"another\"}", &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http_bearer("GET", "/api/settings", token, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http_bearer("GET", "/api/push", token, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	/* Every other read is its: the workflows and their runs too. */
	http_bearer("GET", "/api/workflows", token, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http_bearer("GET", "/api/runs", token, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http_bearer("GET", "/api/sdwan", token, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http_bearer("POST", "/api/sdwan/check", token, "{}", &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http_bearer("GET", "/api/servers", "arcr_0000000000000000000000000000"
	    "000000000000000000000000000000000000", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	/* Its use noted. */
	http("GET", "/api/tokens", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "tokens.0.last") != NULL && strcmp(jstr(&r,
	    "tokens.0.last"), "0") != 0);
	resp_free(&r);

	/* Deleted: it opens nothing at once. */
	snprintf(path, sizeof(path), "/api/tokens/%s", id);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http_bearer("GET", "/api/servers", token, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
}

CONSOLE_TC(push, "Devices subscribe to be told of tasks, and a message goes "
    "to all but the one that sends it")
ATF_TC_BODY(push, tc)
{
	/* A P-256 point and 16 bytes, as a browser gives them. */
	static const char key[] = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx"
	    "aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
	static const char auth[] = "BTBZMqHH6r4Tts7J_aSIgg";
	struct authn	a;
	struct resp	r;
	char		body[1024];

	start(tc, 0, NULL);
	http("GET", "/api/push", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	enrol(&a);

	/* The console's key, for browsers to subscribe with; kept. */
	http("GET", "/api/push", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "public_key") != NULL);
	ATF_CHECK_EQ(87, strlen(jstr(&r, "public_key")));
	ATF_CHECK(jstr(&r, "devices.0.name") == NULL);
	resp_free(&r);
	ATF_CHECK(system("test \"$(stat -f %Lp data/vapid.pem)\" = 600") == 0);

	/* What is not a push service's address, or not keys, is refused. */
	snprintf(body, sizeof(body), "{\"endpoint\":\"http://plain.example/x\","
	    "\"p256dh\":\"%s\",\"auth\":\"%s\"}", key, auth);
	http("POST", "/api/push/subscribe", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"endpoint\":\"https://localhost/a\","
	    "\"p256dh\":\"AAAA\",\"auth\":\"%s\"}", auth);
	http("POST", "/api/push/subscribe", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* Two devices; one of them twice is still one. */
	snprintf(body, sizeof(body), "{\"endpoint\":\"https://localhost/a\","
	    "\"p256dh\":\"%s\",\"auth\":\"%s\",\"name\":\"Chrome on "
	    "Android\"}", key, auth);
	http("POST", "/api/push/subscribe", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/push/subscribe", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("1", jstr(&r, "devices"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"endpoint\":\"https://localhost/b\","
	    "\"p256dh\":\"%s\",\"auth\":\"%s\",\"name\":\"Firefox on "
	    "FreeBSD\"}", key, auth);
	http("POST", "/api/push/subscribe", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("2", jstr(&r, "devices"));
	resp_free(&r);
	http("GET", "/api/push", NULL, &r);
	ATF_CHECK_STREQ("Chrome on Android", jstr(&r, "devices.0.name"));
	ATF_CHECK_STREQ("localhost", jstr(&r, "devices.0.service"));
	resp_free(&r);

	/*
	 * A message goes to the one that did not send it.  Nothing
	 * listens there, so it fails, and says so without failing the
	 * request; with no other device there is nothing to send.
	 */
	http("POST", "/api/push/send", "{\"title\":\"Arcana: done\","
	    "\"body\":\"start web on lab: done\",\"except\":"
	    "\"https://localhost/a\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("0", jstr(&r, "sent"));
	ATF_CHECK_STREQ("1", jstr(&r, "failed"));
	resp_free(&r);

	http("POST", "/api/push/unsubscribe", "{\"endpoint\":"
	    "\"https://localhost/b\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("1", jstr(&r, "devices"));
	resp_free(&r);
	http("POST", "/api/push/send", "{\"title\":\"t\",\"body\":\"b\","
	    "\"except\":\"https://localhost/a\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("0", jstr(&r, "sent"));
	resp_free(&r);

	/*
	 * What is not a text where one is meant is not taken for one, and
	 * an address that would add to the request sent to it is refused.
	 */
	http("POST", "/api/push/send", "{\"title\":1,\"body\":2,\"except\":3}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"endpoint\":\"https://localhost/c\","
	    "\"p256dh\":\"%s\",\"auth\":\"%s\",\"name\":7}", key, auth);
	http("POST", "/api/push/subscribe", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/push/unsubscribe", "{\"endpoint\":"
	    "\"https://localhost/c\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"endpoint\":\"https://localhost/x "
	    "HTTP/1.1\\r\\nHost: other\",\"p256dh\":\"%s\",\"auth\":\"%s\"}",
	    key, auth);
	http("POST", "/api/push/subscribe", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* The devices outlive a restart. */
	restart_console();
	http("GET", "/api/push", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("Chrome on Android", jstr(&r, "devices.0.name"));
	resp_free(&r);
}

CONSOLE_TC(local_agent, "The agent beside the console is added by itself, "
    "once, when its socket answers")
ATF_TC_BODY(local_agent, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], path[MAXPATHLEN], host[MAXHOSTNAMELEN];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(gethostname(host, sizeof(host)) == 0);
	host[strcspn(host, ".")] = '\0';
	harness_local_agent = true;
	start(tc, 0, NULL);
	enrol(&a);

	/* It runs, and the console may reach it: there it is, by the
	 * host's name, and it answers. */
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("added", jstr(&r, "local"));
	ATF_CHECK_STREQ(host, jstr(&r, "servers.0.name"));
	ATF_CHECK_STREQ("true", jstr(&r, "servers.0.local"));
	ATF_CHECK(strstr(jstr(&r, "servers.0.uri"), "/jgd.sock") != NULL);
	ATF_CHECK(jstr(&r, "servers.1.id") == NULL);
	snprintf(path, sizeof(path), "/api/servers/%s", jstr(&r,
	    "servers.0.id"));
	resp_free(&r);
	snprintf(cwd, sizeof(cwd), "%s/jails", path);
	http("GET", cwd, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* Asked again, it is not added twice. */
	http("GET", "/api/servers", NULL, &r);
	ATF_CHECK(jstr(&r, "servers.1.id") == NULL);
	resp_free(&r);

	/* Taken off the list, it stays off: over a restart too. */
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "servers.0.id") == NULL);
	ATF_CHECK_STREQ("removed", jstr(&r, "local"));
	resp_free(&r);
	restart_console();
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "servers.0.id") == NULL);
	ATF_CHECK_STREQ("removed", jstr(&r, "local"));
	resp_free(&r);
}

CONSOLE_TC(local_same, "The agent beside the console is not added again "
    "when it is on the list under another spelling of its socket")
ATF_TC_BODY(local_same, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], buf[MAXPATHLEN + 128];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(mkdir("data", 0700) == 0);
	snprintf(buf, sizeof(buf), "{\"servers\":[{\"id\":\"933e5390\",\"name\":"
	    "\"here\",\"uri\":\"unix://%s/jgd.sock\"}]}\n", cwd);
	put("data/servers.json", buf);
	harness_local_agent = true;
	start(tc, 0, NULL);
	enrol(&a);
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("added", jstr(&r, "local"));
	ATF_CHECK_STREQ("here", jstr(&r, "servers.0.name"));
	ATF_CHECK(jstr(&r, "servers.1.id") == NULL);
	resp_free(&r);
}

CONSOLE_TC(local_absent, "Without an agent beside the console, it says "
    "what it waits for")
ATF_TC_BODY(local_absent, tc)
{
	struct authn	a;
	struct resp	r;

	snprintf(harness_webconf, sizeof(harness_webconf), "local_agent = "
	    "\"unix:/nonexistent/arcana-agent.sock\";\n");
	harness_webconf_only_local = true;
	start(tc, 0, NULL);
	enrol(&a);
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("absent", jstr(&r, "local"));
	ATF_CHECK_STREQ("unix:/nonexistent/arcana-agent.sock", jstr(&r,
	    "local_agent"));
	ATF_CHECK(jstr(&r, "servers.0.id") == NULL);
	resp_free(&r);
}

CONSOLE_TC(settings, "Settings are changed from the console, kept in the "
    "data directory, and override web.conf")
ATF_TC_BODY(settings, tc)
{
	struct authn	a;
	struct resp	r;

	start(tc, 0, NULL);
	http("GET", "/api/settings", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	enrol(&a);

	http("GET", "/api/settings", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("rp_name", jstr(&r, "settings.0.key"));
	ATF_CHECK_STREQ("Arcana", jstr(&r, "settings.0.value"));
	ATF_CHECK_STREQ("true", jstr(&r, "settings.0.editable"));
	ATF_CHECK_STREQ("false", jstr(&r, "settings.0.overridden"));
	resp_free(&r);
	http("GET", "/api/health", NULL, &r);
	ATF_CHECK(jstr(&r, "agent_source") == NULL);
	resp_free(&r);

	/* The program sent to hosts is never one of the console's own
	 * files: its keys are in the data directory. */
	{
		char cwd[MAXPATHLEN], body[MAXPATHLEN + 64];

		ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
		snprintf(body, sizeof(body), "{\"set\":{\"agent_binary\":"
		    "\"%s/data/ca.key\"}}", cwd);
		http("POST", "/api/settings", body, &r);
		EXPECT(&r, 400);
		resp_free(&r);
		snprintf(body, sizeof(body), "{\"set\":{\"agent_binary\":"
		    "\"%s/data/../data/agent/arcana-agent\"}}", cwd);
		http("POST", "/api/settings", body, &r);
		EXPECT(&r, 400);
		resp_free(&r);
	}

	/* What is not a value for a setting, or not a setting to change
	 * here, changes nothing. */
	http("POST", "/api/settings", "{\"set\":{\"agent_source\":"
	    "\"--upload-pack=x\"}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"rp_id\":\"evil.example\"}}",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"rp_name\":\"Lab\","
	    "\"update_url\":\"http://plain.example/\"}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	ATF_CHECK(access("data/settings.json", F_OK) == -1);

	http("POST", "/api/settings", "{\"set\":{\"rp_name\":\"Lab\","
	    "\"agent_source\":\"https://example.org/arcana.git\","
	    "\"agent_ref\":\"main\",\"update_check\":false}}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("Lab", jstr(&r, "settings.0.value"));
	ATF_CHECK_STREQ("Arcana", jstr(&r, "settings.0.base"));
	ATF_CHECK_STREQ("true", jstr(&r, "settings.0.overridden"));
	ATF_CHECK_STREQ("false", jstr(&r, "settings.1.value"));
	resp_free(&r);
	ATF_CHECK(access("data/settings.json", R_OK) == 0);
	http("GET", "/api/health", NULL, &r);
	ATF_CHECK_STREQ("https://example.org/arcana.git", jstr(&r,
	    "agent_source"));
	ATF_CHECK_STREQ("main", jstr(&r, "agent_ref"));
	resp_free(&r);

	/* Back at web.conf's value, or null: the override goes. */
	http("POST", "/api/settings", "{\"set\":{\"rp_name\":\"Arcana\","
	    "\"agent_source\":null,\"agent_ref\":\"\"}}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "settings.0.overridden"));
	resp_free(&r);
	http("GET", "/api/health", NULL, &r);
	ATF_CHECK(jstr(&r, "agent_source") == NULL);
	resp_free(&r);
}

CONSOLE_TC(services, "Services listed, acted on and configured through "
    "service(8) and sysrc(8)")
ATF_TC_BODY(services, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[160], base[128], cwd[MAXPATHLEN], body[MAXPATHLEN];
	char		old[65];
	int		i;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(base, sizeof(base), "/api/servers/%s/services", jstr(&r,
	    "servers.0.id"));
	resp_free(&r);

	http("GET", base, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("ntpd", jstr(&r, "services.0.name"));
	ATF_CHECK_STREQ("false", jstr(&r, "services.0.enabled"));
	ATF_CHECK_STREQ("sshd", jstr(&r, "services.1.name"));
	ATF_CHECK_STREQ("true", jstr(&r, "services.1.enabled"));
	ATF_CHECK_STREQ("false", jstr(&r, "services.1.running"));
	ATF_CHECK(jstr(&r, "trace.3.label") != NULL);
	resp_free(&r);

	snprintf(path, sizeof(path), "%s/sshd/action", base);
	http("POST", path, "{\"action\":\"start\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("true", jstr(&r, "service.running"));
	ATF_CHECK_STREQ("7", jstr(&r, "service.pid"));
	resp_free(&r);
	http("POST", path, "{\"action\":\"dance\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ntpd/action", base);
	http("POST", path, "{\"action\":\"enable\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "service.enabled"));
	resp_free(&r);

	snprintf(path, sizeof(path), "%s/sshd/config", base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("-4", jstr(&r, "variables.sshd_flags"));
	ATF_CHECK_STREQ("The sshd daemon.", jstr(&r, "description"));
	ATF_CHECK_STREQ("reload", jstr(&r, "commands.0"));
	resp_free(&r);
	http("POST", path, "{\"set\":{\"sshd_flags\":\"-6\"},\"unset\":"
	    "[\"sshd_nothing\"]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("-6", jstr(&r, "variables.sshd_flags"));
	resp_free(&r);
	http("POST", path, "{\"set\":{\"ntpd_flags\":\"x\"}}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(jstr(&r, "error"), "not a variable") != NULL,
	    "%s", jstr(&r, "error"));
	resp_free(&r);

	/* Usage figures: real sysctls, a zpool(8) that may not be there. */
	snprintf(path, sizeof(path), "%.*s/stats",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK(jstr(&r, "stats.cpu_pct") != NULL);
	ATF_CHECK(atoll(jstr(&r, "stats.mem_total")) > 0);
	resp_free(&r);

	/* Jobs: a batch is queued, runs in order, and can be read back. */
	snprintf(path, sizeof(path), "%.*s/jobs",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"jobs\":[{\"kind\":\"service-action\","
	    "\"service\":\"sshd\",\"action\":\"stop\"},{\"kind\":"
	    "\"jail-action\",\"jail\":\"web\",\"action\":\"start\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("service sshd stop", jstr(&r, "jobs.0.title"));
	ATF_CHECK_STREQ("start web", jstr(&r, "jobs.1.title"));
	ATF_REQUIRE(jstr(&r, "jobs.1.id") != NULL);
	snprintf(body, sizeof(body), "%s/%s", path, jstr(&r, "jobs.1.id"));
	resp_free(&r);
	for (i = 0; i < 100; i++) {
		http("GET", body, NULL, &r);
		EXPECT(&r, 200);
		if (strcmp(jstr(&r, "job.state"), "done") == 0)
			break;
		resp_free(&r);
		usleep(50000);
	}
	ATF_REQUIRE_MSG(i < 100, "the job did not finish");
	ATF_CHECK_STREQ("true", jstr(&r, "job.ok"));
	ATF_CHECK_STREQ("api", jstr(&r, "job.trace.0.kind"));
	ATF_CHECK_MSG(strstr(jstr(&r, "job.trace.3.detail"), "start web") !=
	    NULL, "%s", jstr(&r, "job.trace.3.detail"));
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("done", jstr(&r, "jobs.0.state"));
	ATF_CHECK_STREQ("done", jstr(&r, "jobs.1.state"));
	resp_free(&r);
	http("DELETE", body, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	resp_free(&r);
	http("POST", path, "{\"jobs\":[{\"kind\":\"dance\"}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", path, "{\"jobs\":[{\"kind\":\"jail-action\","
	    "\"jail\":\"../x\",\"action\":\"start\"}]}", &r);
	EXPECT(&r, 502);
	resp_free(&r);

	/* Packages: pending upgrades, a dry run, an upgrade of one. */
	snprintf(path, sizeof(path), "%.*s/packages?refresh=1",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("aria2", jstr(&r, "packages.0.name"));
	ATF_CHECK_STREQ("1.37.0_2", jstr(&r, "packages.0.available"));
	ATF_CHECK_STREQ("pimd", jstr(&r, "packages.1.name"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/packages?jail=web",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(jstr(&r, "error"), "not running") != NULL, "%s",
	    jstr(&r, "error"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/packages/upgrade",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"packages\":[\"pimd\"],\"dry_run\":true}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("pimd", jstr(&r, "packages.1.name"));
	resp_free(&r);
	http("POST", path, "{\"packages\":[\"pimd\"]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("1", jstr(&r, "upgraded"));
	ATF_CHECK(jstr(&r, "packages.1.name") == NULL);
	ATF_CHECK_STREQ("aria2", jstr(&r, "packages.0.name"));
	resp_free(&r);
	http("POST", path, "{\"jail\":\"../x\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* The network tables: the kernel's routes, inside ours. */
	snprintf(path, sizeof(path), "%.*s/net/routes?family=inet",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("default", jstr(&r, "data.statistics.route-information."
	    "route-table.rt-family.0.rt-entry.0.destination"));
	ATF_CHECK_MSG(strstr(jstr(&r, "trace.4.label"), "routes 4 0") != NULL,
	    "%s", jstr(&r, "trace.4.label"));
	resp_free(&r);

	/* The routes searched on the host: the text goes through, and
	 * what is not a text to search for is refused. */
	snprintf(path, sizeof(path), "%.*s/net/routes?family=inet&filter="
	    "10.0.0.", (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK(jstr(&r, "total") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/net/routes?filter=a%%20b",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* The interfaces, read by the agent itself; and a change to one,
	 * which is a job that runs ifconfig(8). */
	snprintf(path, sizeof(path), "%.*s/net/interfaces",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK(jstr(&r, "data.interfaces.0.name") != NULL);
	ATF_CHECK(jstr(&r, "data.interfaces.0.up") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/jobs",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"jobs\":[{\"kind\":\"if-address\","
	    "\"interface\":\"lo0\",\"address\":\"10.9.0.5/24\"},"
	    "{\"kind\":\"if-state\",\"interface\":\"lo0\",\"up\":true}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lo0: add 10.9.0.5/24", jstr(&r, "jobs.0.title"));
	ATF_CHECK_STREQ("lo0: up", jstr(&r, "jobs.1.title"));
	resp_free(&r);
	for (i = 0; i < 100 && access("ifconfig.log", F_OK) == -1; i++)
		usleep(50000);
	usleep(300000);
	ATF_CHECK(system("grep -q '^lo0 inet 10.9.0.5/24 alias$' ifconfig.log "
	    "&& grep -q '^lo0 up$' ifconfig.log") == 0);
	http("POST", path, "{\"jobs\":[{\"kind\":\"if-state\","
	    "\"interface\":\"lo0\"}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/*
	 * The host's rollback timer: kept with the server, refused out
	 * of its range, and sent with each safe change.
	 */
	snprintf(body, sizeof(body), "%.*s", (int)(strlen(base) -
	    strlen("/services")), base);
	http("POST", body, "{\"safe_wait\":5}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", body, "{\"safe_wait\":15}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("15", jstr(&r, "servers.0.safe_wait"));
	resp_free(&r);

	/*
	 * A safe change waits to hear from the console again; reading
	 * the job is that, so the change stays.
	 */
	http("POST", path, "{\"jobs\":[{\"kind\":\"if-address\","
	    "\"interface\":\"lo0\",\"address\":\"10.9.0.6/24\","
	    "\"safe\":true}]}", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "jobs.0.id") != NULL);
	snprintf(body, sizeof(body), "%s/%s", path, jstr(&r, "jobs.0.id"));
	resp_free(&r);
	for (i = 0; i < 200; i++) {
		http("GET", body, NULL, &r);
		EXPECT(&r, 200);
		if (strcmp(jstr(&r, "job.state"), "done") == 0)
			break;
		resp_free(&r);
		usleep(50000);
	}
	ATF_REQUIRE_MSG(i < 200, "the safe job did not finish");
	ATF_CHECK_STREQ("true", jstr(&r, "job.ok"));
	ATF_CHECK_MSG(strstr(r.body, "the timer was 15 s") != NULL, "%s", r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "%.*s", (int)(strlen(base) -
	    strlen("/services")), base);
	http("POST", body, "{\"safe_wait\":0}", &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "servers.0.safe_wait") == NULL);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^lo0 inet 10.9.0.6/24 alias$' ifconfig.log "
	    "&& ! grep -q '10.9.0.6 -alias' ifconfig.log") == 0);

	/* A static route, added and deleted with route(8). */
	http("POST", path, "{\"jobs\":[{\"kind\":\"route\",\"destination\":"
	    "\"10.77.0.0/16\",\"gateway\":\"10.0.0.1\"},{\"kind\":\"route\","
	    "\"destination\":\"10.77.0.0/16\",\"remove\":true}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("route add 10.77.0.0/16 via 10.0.0.1", jstr(&r,
	    "jobs.0.title"));
	ATF_CHECK_STREQ("route delete 10.77.0.0/16", jstr(&r, "jobs.1.title"));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q route-del route.log 2>/dev/null") !=
	    0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^0 route-add 10.77.0.0/16 10.0.0.1 - 0 0 0 "
	    "-$' route.log && grep -q '^0 route-del 10.77.0.0/16 - - 0 0$' "
	    "route.log")
	    == 0);
	http("POST", path, "{\"jobs\":[{\"kind\":\"route\",\"destination\":"
	    "\"10.77.0.0/16\"}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/*
	 * A tunnel made, an MTU set, a route in a routing table of its
	 * own, a netgraph hook: each a job with what it needs.
	 */
	http("POST", path, "{\"jobs\":[{\"kind\":\"if-create\",\"interface\":"
	    "\"gif3\",\"tunnel_local\":\"192.0.2.1\",\"tunnel_remote\":"
	    "\"192.0.2.2\",\"address\":\"10.255.0.1/30\",\"destination\":"
	    "\"10.255.0.2\",\"mtu\":1400,\"description\":\"to lab\"},"
	    "{\"kind\":\"if-set\",\"interface\":\"lo0\",\"mtu\":9000},"
	    "{\"kind\":\"route\",\"destination\":\"10.88.0.0/16\",\"gateway\":"
	    "\"10.0.0.1\",\"fib\":2},{\"kind\":\"netgraph\",\"verb\":"
	    "\"mkpeer\",\"args\":[\"em0:\",\"bridge\",\"lower\",\"link0\"]},"
	    "{\"kind\":\"if-destroy\",\"interface\":\"gif3\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("create gif3 to 192.0.2.2 with 10.255.0.1/30", jstr(&r,
	    "jobs.0.title"));
	ATF_CHECK_STREQ("if-create", jstr(&r, "jobs.0.kind"));
	ATF_CHECK_STREQ("netgraph", jstr(&r, "jobs.3.kind"));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'gif3 destroy' ifconfig.log "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^gif3 tunnel 192.0.2.1 192.0.2.2$' "
	    "ifconfig.log && grep -q '^gif3 inet 10.255.0.1/30 10.255.0.2$' "
	    "ifconfig.log && grep -q '^gif3 description to lab$' ifconfig.log "
	    "&& grep -q '^lo0 mtu 9000$' ifconfig.log && grep -q "
	    "'^0 route-add 10.88.0.0/16 10.0.0.1 - 2 0 0 -$' route.log && "
	    "grep -q '^mkpeer em0: bridge lower link0$' ngctl.log") == 0);
	/* What ngctl is not to be given the agent refuses to queue. */
	http("POST", path, "{\"jobs\":[{\"kind\":\"netgraph\",\"verb\":"
	    "\"msg\",\"args\":[\"em0:\",\"x\"]}]}", &r);
	EXPECT(&r, 502);
	resp_free(&r);
	ATF_CHECK(system("grep -q msg ngctl.log") != 0);

	/* The route to an address, and the netgraph nodes. */
	snprintf(path, sizeof(path), "%.*s/net/lookup?to=10.77.5.5&fib=1",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("10.0.0.1", jstr(&r, "data.best.gateway"));
	ATF_CHECK_STREQ("em0", jstr(&r, "data.best.interface"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^-Q 0 route-get 10.77.5.5 1$' helper.log")
	    == 0);
	snprintf(path, sizeof(path), "%.*s/net/lookup?to=10.0.0.1;id",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/net/netgraph",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("em0", jstr(&r, "data.nodes.0.name"));
	ATF_CHECK_STREQ("bridge0", jstr(&r, "data.nodes.0.hooks.0.peer"));
	resp_free(&r);

	/*
	 * A jail with a network of its own: read and changed through its
	 * host, by naming the jail.
	 */
	snprintf(path, sizeof(path), "%.*s/net/interfaces?jail=gw",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("epair1b", jstr(&r, "data.interfaces.0.name"));
	ATF_CHECK_STREQ("10.99.0.2", jstr(&r,
	    "data.interfaces.0.addresses.0.address"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/net/lookup?to=192.0.2.9&jail=gw",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^-Q 4 route-get 192.0.2.9 0$' helper.log")
	    == 0);
	snprintf(path, sizeof(path), "%.*s/net/interfaces?jail=a;b",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* A jail without one has none to show. */
	snprintf(path, sizeof(path), "%.*s/net/interfaces?jail=web",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/jobs",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"jobs\":[{\"kind\":\"if-address\",\"jail\":\"gw\","
	    "\"interface\":\"epair1b\",\"address\":\"10.99.0.5/24\",\"persist\":"
	    "true}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("gw: epair1b: add 10.99.0.5/24", jstr(&r,
	    "jobs.0.title"));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'alias0' jroot/etc/rc.conf "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^-j 4 epair1b inet 10.99.0.5/24 alias$' "
	    "ifconfig.log && grep -q '^ifconfig_epair1b_alias0=\"inet "
	    "10.99.0.5/24\"$' jroot/etc/rc.conf && ! grep -q 10.99.0.5 "
	    "rc.conf") == 0);

	/*
	 * WireGuard: the host makes the key, and the console is told the
	 * public one; a peer is given to it.  BIRD: its protocols, and
	 * one of them restarted.
	 */
	snprintf(path, sizeof(path), "%.*s/jobs",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"jobs\":[{\"kind\":\"wireguard\",\"interface\":"
	    "\"wg0\",\"verb\":\"init\",\"listen_port\":51820},{\"kind\":"
	    "\"wireguard\",\"interface\":\"wg0\",\"verb\":\"peer\",\"peer\":"
	    "\"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\",\"endpoint\":"
	    "\"192.0.2.9:51820\",\"allowed_ips\":\"10.9.9.2/32\",\"keepalive\":"
	    "25},{\"kind\":\"bird\",\"verb\":\"restart\",\"args\":"
	    "[\"bgp_core\"]},{\"kind\":\"bird\",\"verb\":\"configure\"}]}",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("wg0: wireguard init", jstr(&r, "jobs.0.title"));
	ATF_CHECK_STREQ("bird restart bgp_core", jstr(&r, "jobs.2.title"));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q '^configure$' birdc.log "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^set wg0 listen-port 51820$' wg.log && "
	    "grep -q '^set wg0 peer xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg= "
	    "endpoint 192.0.2.9:51820 allowed-ips 10.9.9.2/32 "
	    "persistent-keepalive 25$' wg.log && grep -q '^restart bgp_core$' "
	    "birdc.log") == 0);
	http("POST", path, "{\"jobs\":[{\"kind\":\"wireguard\",\"interface\":"
	    "\"wg0\",\"verb\":\"peer\",\"peer\":\"short\"}]}", &r);
	EXPECT(&r, 502);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/net/wireguard",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "data.interfaces.0.private-key"));
	ATF_CHECK_STREQ("HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=",
	    jstr(&r, "data.interfaces.0.public-key"));
	ATF_CHECK_STREQ("192.0.2.9:51820", jstr(&r,
	    "data.interfaces.0.peers.0.endpoint"));
	/* The key the host made is nowhere in what the console says. */
	ATF_CHECK(system("test -s wg.key") == 0);
	{
		char key[64];
		FILE *fp;

		ATF_REQUIRE((fp = fopen("wg.key", "r")) != NULL);
		ATF_REQUIRE(fgets(key, sizeof(key), fp) != NULL);
		fclose(fp);
		key[strcspn(key, "\n")] = '\0';
		ATF_CHECK(strstr(r.body, key) == NULL);
	}
	resp_free(&r);

	/*
	 * IPsec: the host makes its key and tells its public half; a
	 * connection is written for it, IKEv2, and read back.
	 */
	snprintf(path, sizeof(path), "%.*s/jobs",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"jobs\":[{\"kind\":\"ipsec\",\"verb\":\"init\"}]}",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("ipsec init", jstr(&r, "jobs.0.title"));
	resp_free(&r);
	for (i = 0; i < 100 && system("test -s swanctl/pubkey/arcana.pub") !=
	    0; i++)
		usleep(50000);
	snprintf(path, sizeof(path), "%.*s/net/ipsec",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "data.public-key") != NULL);
	ATF_CHECK(strlen(jstr(&r, "data.public-key")) > 80);
	ATF_CHECK(strstr(r.body, "PRIVATE") == NULL);
	snprintf(body, sizeof(body), "{\"jobs\":[{\"kind\":\"ipsec\",\"verb\":"
	    "\"conn\",\"conn\":\"to-lab2\",\"tunnel_local\":\"192.0.2.1\","
	    "\"tunnel_remote\":\"192.0.2.2\",\"ipsec_mode\":\"transport\","
	    "\"pubkey\":\"%s\",\"local_ts\":\"192.0.2.1[gre]\","
	    "\"remote_ts\":\"192.0.2.2[gre]\",\"start_action\":\"start\"}]}",
	    jstr(&r, "data.public-key"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/jobs",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("ipsec conn to-lab2 (transport)", jstr(&r,
	    "jobs.0.title"));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'version = 2' "
	    "swanctl/conf.d/arcana-to-lab2.conf 2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q 'mode = transport' "
	    "swanctl/conf.d/arcana-to-lab2.conf") == 0);
	snprintf(path, sizeof(path), "%.*s/net/ipsec",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("to-lab2", jstr(&r, "data.connections.0.name"));
	ATF_CHECK_STREQ("true", jstr(&r, "data.connections.0.arcana"));
	ATF_CHECK_STREQ("INSTALLED", jstr(&r, "data.sas.0.children.0.state"));
	resp_free(&r);
	/* A connection is named, but for init and start. */
	snprintf(path, sizeof(path), "%.*s/jobs",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"jobs\":[{\"kind\":\"ipsec\",\"verb\":\"up\"}]}",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/net/bird",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("Router ID is 192.0.2.1", jstr(&r, "data.status.1"));
	ATF_CHECK_STREQ("bgp_core", jstr(&r, "data.protocols.1.name"));
	ATF_CHECK_STREQ("Established", jstr(&r, "data.protocols.1.info"));
	ATF_CHECK_STREQ("192.0.2.1", jstr(&r, "data.protocols.1.neighbor"));
	ATF_CHECK_STREQ("65001", jstr(&r, "data.protocols.1.neighbor-as"));
	ATF_CHECK_STREQ("bgp_in", jstr(&r,
	    "data.protocols.1.channels.0.input-filter"));
	ATF_CHECK_STREQ("845233", jstr(&r,
	    "data.protocols.1.channels.0.imported"));
	ATF_CHECK_STREQ("10.0.0.2", jstr(&r, "data.ospf.0.router-id"));
	ATF_CHECK_STREQ("r4", jstr(&r, "data.tables.1.name"));
	resp_free(&r);

	/*
	 * BIRD's configuration: read with its checksum, put back changed
	 * once bird(8) has parsed it; what it refuses does not stay, and
	 * a change made from an older text is not taken.
	 */
	snprintf(path, sizeof(path), "%.*s/bird/config",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "sha256") != NULL && jstr(&r, "text") != NULL);
	ATF_CHECK(strstr(jstr(&r, "text"), "filter bgp_in") != NULL);
	ATF_CHECK(strstr(jstr(&r, "files.0"), "/bird/bird.conf") != NULL);
	snprintf(body, sizeof(body), "{\"text\":\"router id 192.0.2.9;\\n\","
	    "\"sha256\":\"%s\"}", jstr(&r, "sha256"));
	resp_free(&r);
	(void)old;
	http("POST", path, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^router id 192.0.2.9;$' bird/bird.conf && "
	    "grep -q 'filter bgp_in' bird/bird.conf.arcana-old && "
	    "grep -q '^configure$' birdc.log") == 0);
	http("POST", path, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK(strstr(jstr(&r, "error"), "changed it meanwhile") != NULL);
	resp_free(&r);
	http("GET", path, NULL, &r);
	snprintf(body, sizeof(body), "{\"text\":\"BROKEN\\n\",\"sha256\":"
	    "\"%s\"}", jstr(&r, "sha256"));
	resp_free(&r);
	http("POST", path, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK(strstr(jstr(&r, "error"), "syntax error") != NULL);
	resp_free(&r);
	ATF_CHECK(system("grep -q BROKEN bird/bird.conf") != 0);
	snprintf(body, sizeof(body), "%s?path=/etc/../etc/passwd", path);
	http("GET", body, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "%s?path=/etc/passwd", path);
	http("GET", body, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	resp_free(&r);

	/*
	 * In safe mode BIRD is told to take the change back by itself;
	 * the reply says by when, and a confirmation makes it stay.
	 */
	http("GET", path, NULL, &r);
	snprintf(body, sizeof(body), "{\"text\":\"router id 192.0.2.10;\\n\","
	    "\"safe\":true,\"sha256\":\"%s\"}", jstr(&r, "sha256"));
	resp_free(&r);
	http("POST", path, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK(jstr(&r, "confirm_by") != NULL);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^configure timeout 60$' birdc.log") == 0);
	http("POST", path, "{\"confirm\":true}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^configure confirm$' birdc.log && grep -q "
	    "'^router id 192.0.2.10;$' bird/bird.conf") == 0);
	http("POST", path, "{\"confirm\":true}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	resp_free(&r);

	/*
	 * The kernel: what is linked into it, read from the kernel, and
	 * what its memory went to; a module loaded by a job.
	 */
	snprintf(path, sizeof(path), "%.*s/kernel",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("kernel", jstr(&r, "data.files.0.name"));
	ATF_CHECK(jstr(&r, "data.files.0.size") != NULL);
	ATF_CHECK(jstr(&r, "data.files.0.modules.0") != NULL);
	ATF_CHECK(jstr(&r, "data.memory.malloc.0.name") != NULL);
	ATF_CHECK(jstr(&r, "data.memory.zones.0.size") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/jobs",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"jobs\":[{\"kind\":\"kmod\",\"verb\":\"load\","
	    "\"args\":[\"sctp\"],\"persist\":true}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("kldload sctp (kept)", jstr(&r, "jobs.0.title"));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'kld_list' rc.conf "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^kldload -n sctp$' kld.log && grep -q "
	    "'^kld_list=\"sctp\"$' rc.conf") == 0);
	/* A name is a name, and a verb one of the two. */
	http("POST", path, "{\"jobs\":[{\"kind\":\"kmod\",\"verb\":\"load\","
	    "\"args\":[\"/tmp/evil.ko\"]}]}", &r);
	ATF_CHECK(r.status != 200 || strcmp(jstr(&r, "ok") != NULL ? jstr(&r,
	    "ok") : "", "true") != 0);
	resp_free(&r);
	http("POST", path, "{\"jobs\":[{\"kind\":\"kmod\",\"verb\":\"load\"}]}",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/*
	 * The kernel's state: from a name on, with what is kept for the
	 * next boot; one set by a job, and kept.
	 */
	snprintf(path, sizeof(path), "%.*s/sysctl?filter=kern.ostype",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("kern.ostype", jstr(&r, "data.values.0.name"));
	ATF_CHECK_STREQ("FreeBSD", jstr(&r, "data.values.0.value"));
	ATF_CHECK_STREQ("false", jstr(&r, "data.values.0.rw"));
	ATF_CHECK_STREQ("kern.ipc.somaxconn", jstr(&r, "data.kept.0.name"));
	ATF_CHECK_STREQ("1024", jstr(&r, "data.kept.0.value"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/sysctl?filter=kern,x",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/jobs",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"jobs\":[{\"kind\":\"sysctl\",\"args\":["
	    "\"kern.ipc.somaxconn\",\"4096\"],\"persist\":true}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("sysctl kern.ipc.somaxconn=4096 (kept)", jstr(&r,
	    "jobs.0.title"));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q '^kern.ipc.somaxconn=4096$' "
	    "sysctl.conf 2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^sysctl kern.ipc.somaxconn=4096$' kld.log "
	    "&& grep -q '^kern.ipc.somaxconn=4096$' sysctl.conf && grep -q "
	    "'^# kept$' sysctl.conf && ! grep -q 1024 sysctl.conf") == 0);
	http("POST", path, "{\"jobs\":[{\"kind\":\"sysctl\",\"args\":["
	    "\"kern.hostname\"]}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/*
	 * What runs, a log and the history: read as the host says them;
	 * a process sent a signal by a job.
	 */
	snprintf(path, sizeof(path), "%.*s/processes",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK(jstr(&r, "data.processes.0.pid") != NULL);
	ATF_CHECK(jstr(&r, "data.processes.0.wcpu") != NULL);
	ATF_CHECK(jstr(&r, "data.processes.0.rss") != NULL);
	ATF_CHECK(jstr(&r, "data.ncpu") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/processes?jail=nosuchjail",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/log",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("messages", jstr(&r, "data.name"));
	ATF_CHECK_STREQ("auth.log", jstr(&r, "data.files.0.name"));
	ATF_CHECK_STREQ("kernel", jstr(&r, "data.lines.0.tag"));
	ATF_CHECK_STREQ("sshd", jstr(&r, "data.lines.1.tag"));
	ATF_CHECK_STREQ("812", jstr(&r, "data.lines.1.pid"));
	ATF_CHECK_STREQ("cron", jstr(&r, "data.lines.2.tag"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/log?name=auth.log&filter=bad%%20su"
	    "&lines=5", (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("su", jstr(&r, "data.lines.0.tag"));
	i = atoi(jstr(&r, "data.position"));
	ATF_CHECK(i > 0);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/log?name=auth.log&position=%d",
	    (int)(strlen(base) - strlen("/services")), base, i);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "data.lines.0.text") == NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/log?jail=gw",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "data.lines.0.text") != NULL && strcmp(jstr(&r,
	    "data.lines.0.text"), "the jail's own line") == 0);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/processes?pid=%d",
	    (int)(strlen(base) - strlen("/services")), base, (int)getpid());
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "data.threads.0.tid") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/log?name=..%%2Frc.conf",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	ATF_CHECK(r.status != 200 || strcmp(jstr(&r, "ok"), "false") == 0);
	resp_free(&r);
	sleep(2);
	snprintf(path, sizeof(path), "%.*s/history",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("5", jstr(&r, "data.step"));
	ATF_CHECK_STREQ("cpu", jstr(&r, "data.fields.1"));
	ATF_CHECK(jstr(&r, "data.samples.0.0") != NULL);
	ATF_CHECK_STREQ("720", jstr(&r, "data.keep"));
	ATF_CHECK(jstr(&r, "data.bytes") != NULL);
	resp_free(&r);
	/* How it is sampled is set, and said back; not anyhow. */
	http("POST", path, "{\"step\":3,\"keep\":100,\"cpu\":95,\"mem\":80,"
	    "\"swap\":10}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("3", jstr(&r, "data.step"));
	ATF_CHECK_STREQ("100", jstr(&r, "data.keep"));
	ATF_CHECK_STREQ("80", jstr(&r, "data.limits.mem"));
	ATF_CHECK(system("grep -q '^step=3$' history.conf && grep -q "
	    "'^keep=100$' history.conf") == 0);
	resp_free(&r);
	http("POST", path, "{\"step\":0,\"keep\":100}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", path, "{\"step\":5}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", path, "{\"step\":5,\"keep\":720}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/history?after=99999999999",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "data.samples.0.0") == NULL);
	resp_free(&r);
	/* What happened there: numbered, to be asked for from a number. */
	snprintf(path, sizeof(path), "%.*s/events",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK(jstr(&r, "data.last") != NULL);
	ATF_CHECK_STREQ("512", jstr(&r, "data.kept"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/events?after=99999999",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "data.events.0.n") == NULL);
	resp_free(&r);
	/* Packets followed through the firewall by the kernel. */
	snprintf(path, sizeof(path), "%.*s/ipfw/trace?address=10.0.0.2&"
	    "seconds=2&packets=5", (int)(strlen(base) - strlen("/services")),
	    base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("pass", jstr(&r, "data.packets.0.verdict"));
	ATF_CHECK_STREQ("100", jstr(&r, "data.packets.0.rule"));
	ATF_CHECK_STREQ("in", jstr(&r, "data.packets.0.direction"));
	ATF_CHECK_STREQ("5", jstr(&r, "data.limit"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^tick-2s$' trace.d") == 0);
	snprintf(path, sizeof(path), "%.*s/ipfw/trace?address=10.0.0.2;x",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	ATF_REQUIRE(system("sleep 300 & echo $! > sleep.pid") == 0);
	{
		char	what[256], pid[16];
		FILE	*fp;

		ATF_REQUIRE((fp = fopen("sleep.pid", "r")) != NULL);
		ATF_REQUIRE(fgets(pid, sizeof(pid), fp) != NULL);
		fclose(fp);
		pid[strcspn(pid, "\n")] = '\0';
		snprintf(path, sizeof(path), "%.*s/jobs",
		    (int)(strlen(base) - strlen("/services")), base);
		snprintf(what, sizeof(what), "{\"jobs\":[{\"kind\":"
		    "\"process\",\"verb\":\"signal\",\"args\":[\"%s\","
		    "\"TERM\"]}]}", pid);
		http("POST", path, what, &r);
		EXPECT(&r, 200);
		snprintf(what, sizeof(what), "kill -TERM %s", pid);
		ATF_CHECK_STREQ(what, jstr(&r, "jobs.0.title"));
		resp_free(&r);
		snprintf(what, sizeof(what), "kill -0 %s 2>/dev/null", pid);
		for (i = 0; i < 100 && system(what) == 0; i++)
			usleep(50000);
		ATF_CHECK(system(what) != 0);
		http("POST", path, "{\"jobs\":[{\"kind\":\"process\","
		    "\"verb\":\"signal\",\"args\":[\"1\",\"TERM\"]}]}",
		    &r);
		ATF_CHECK(r.status != 200 || jstr(&r, "jobs.0.title") == NULL);
		resp_free(&r);
	}

	/*
	 * The firewall: its rules with their sets and counters, and the
	 * kept ones; a rule kept by a job; the kept rules read, checked
	 * and replaced, and applied through set 1.
	 */
	snprintf(path, sizeof(path), "%.*s/net/ipfw",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "data.loaded"));
	ATF_CHECK_STREQ("5", jstr(&r, "data.rules.0.num"));
	ATF_CHECK_STREQ("skipto 500 ip from any to any out", jstr(&r,
	    "data.rules.0.text"));
	ATF_CHECK_STREQ("900", jstr(&r, "data.rules.0.bytes"));
	ATF_CHECK_STREQ("T46", jstr(&r, "data.tables.0.name"));
	ATF_CHECK_STREQ("1002", jstr(&r, "data.kept.3.num"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/jobs",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"jobs\":[{\"kind\":\"ipfw\",\"verb\":\"add\","
	    "\"args\":[\"1003\",\"allow\",\"tcp\",\"from\",\"any\",\"to\","
	    "\"me6\",\"443\",\"in\"],\"persist\":true,\"live\":true},"
	    "{\"kind\":\"ipfw\",\"verb\":\"apply\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("ipfw add 1003 allow tcp from any to me6 443 in "
	    "(now, and kept)", jstr(&r, "jobs.0.title"));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'set swap 0 1' ipfw.log "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^ipfw -q add 1003 allow tcp from any to "
	    "me6 443 in$' ipfw.log && grep -q '^add 01003 allow tcp from any "
	    "to me6 443 in$' ipfw.rules && grep -q '^add 01003 set 1 allow' "
	    "loaded.rules && grep -q '^ipfw -q set disable 1$' ipfw.log") ==
	    0);
	http("POST", path, "{\"jobs\":[{\"kind\":\"ipfw\",\"verb\":\"add\","
	    "\"args\":[\"10\",\"allow\",\"ip;reboot\"],\"live\":true}]}", &r);
	ATF_CHECK(r.status != 200 || strcmp(jstr(&r, "ok") != NULL ? jstr(&r,
	    "ok") : "", "true") != 0);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/ipfw/rules",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(jstr(&r, "text"), "add 01003 allow") != NULL);
	snprintf(body, sizeof(body), "{\"text\":\"add 00010 allow ip from "
	    "any to any\\nbogus\\n\",\"sha256\":\"%s\"}", jstr(&r,
	    "sha256"));
	resp_free(&r);
	http("POST", path, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK(strstr(jstr(&r, "error"), "bogus") != NULL);
	resp_free(&r);

	/*
	 * Bridges and geneve tunnels: what they are; a port made an
	 * access port by a job.
	 */
	snprintf(path, sizeof(path), "%.*s/net/bridges",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bridge0", jstr(&r, "data.bridges.0.name"));
	ATF_CHECK_STREQ("true", jstr(&r, "data.bridges.0.vlanfilter"));
	ATF_CHECK_STREQ("root", jstr(&r, "data.bridges.0.members.0.role"));
	ATF_CHECK_STREQ("forwarding", jstr(&r,
	    "data.bridges.0.members.0.state"));
	ATF_CHECK_STREQ("trunk", jstr(&r, "data.bridges.0.members.1.mode"));
	ATF_CHECK_STREQ("192.0.2.7", jstr(&r,
	    "data.bridges.0.members.1.addresses.0"));
	ATF_CHECK_STREQ("discarding", jstr(&r,
	    "data.bridges.0.members.2.state"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/net/geneve",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("l2", jstr(&r, "data.geneves.0.mode"));
	ATF_CHECK_STREQ("100", jstr(&r, "data.geneves.0.id"));
	ATF_CHECK_STREQ("l3", jstr(&r, "data.geneves.1.mode"));
	ATF_CHECK_STREQ("inherit", jstr(&r, "data.geneves.1.ttl"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/jobs",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"jobs\":[{\"kind\":\"bridge\",\"interface\":"
	    "\"bridge0\",\"verb\":\"access\",\"args\":[\"epair5a\",\"20\"]},"
	    "{\"kind\":\"geneve\",\"interface\":\"geneve7\",\"verb\":"
	    "\"create\",\"args\":[\"mode\",\"l3\",\"id\",\"7\",\"local\","
	    "\"192.0.2.1\",\"remote\",\"192.0.2.2\"]}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bridge0 access epair5a 20", jstr(&r, "jobs.0.title"));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'geneve7 create' ifconfig.log "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^bridge0 ifuntagged epair5a 20 iftagged "
	    "epair5a none$' ifconfig.log && grep -q '^geneve7 create "
	    "genevemode l3 geneveid 7 genevelocal 192.0.2.1 geneveremote "
	    "192.0.2.2$' ifconfig.log") == 0);

	/*
	 * How the agent is reached: its listeners and who is connected.
	 * The console keeps its connection open: what it asks next goes
	 * over the same one, and the agent has seen no new connection.
	 */
	snprintf(path, sizeof(path), "%.*s/transport",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("unix", jstr(&r, "data.listeners.0.transport"));
	ATF_CHECK_STREQ("true", jstr(&r, "data.listeners.0.up"));
	ATF_CHECK_STREQ("unix", jstr(&r, "data.sessions.0.transport"));
	ATF_CHECK(jstr(&r, "uri") != NULL && strncmp(jstr(&r, "uri"), "unix:",
	    5) == 0);
	{
		long	seen, after;

		seen = atol(jstr(&r, "data.seen"));
		resp_free(&r);
		for (i = 0; i < 6; i++) {
			http("GET", base, NULL, &r);
			EXPECT(&r, 200);
			resp_free(&r);
		}
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		after = atol(jstr(&r, "data.seen"));
		ATF_CHECK_MSG(after == seen, "the agent saw %ld connections, "
		    "then %ld after six more requests", seen, after);
		resp_free(&r);
	}
	/* A local socket has no other way to be reached. */
	snprintf(path, sizeof(path), "%.*s/transport/switch",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"transport\":\"sctp\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/*
	 * Storage: the pools with their devices, datasets, snapshots of
	 * one, the disks from the kernel, what is mounted; a snapshot
	 * taken by a job; fstab read and put back.
	 */
	snprintf(path, sizeof(path), "%.*s/storage/pools",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("tank", jstr(&r, "data.pools.0.name"));
	ATF_CHECK_STREQ("DEGRADED", jstr(&r, "data.pools.0.health"));
	ATF_CHECK_STREQ("mirror-0", jstr(&r, "data.pools.0.vdevs.1.name"));
	ATF_CHECK_STREQ("OFFLINE", jstr(&r, "data.pools.0.vdevs.3.state"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/storage/importable",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("spare", jstr(&r, "data.importable.0.name"));
	ATF_CHECK_STREQ("1234567890", jstr(&r, "data.importable.0.id"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/storage/datasets",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("tank/data", jstr(&r, "data.datasets.1.name"));
	ATF_CHECK_STREQ("8000000", jstr(&r, "data.datasets.1.quota"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/storage/snapshots?filter=tank/data",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("tank/data@b", jstr(&r, "data.snapshots.0.name"));
	resp_free(&r);
	ATF_CHECK(system("grep -q -- '-S creation -r tank/data$' storage.log")
	    == 0);
	snprintf(path, sizeof(path), "%.*s/storage/snapshots?filter=-r",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/storage/disks",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/storage/mounts",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("/", jstr(&r, "data.mounts.0.on"));
	ATF_CHECK_STREQ("/mnt/data", jstr(&r, "data.fstab.1.file"));
	ATF_CHECK_STREQ("false", jstr(&r, "data.fstab.1.mounted"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/jobs",
	    (int)(strlen(base) - strlen("/services")), base);
	http("POST", path, "{\"jobs\":[{\"kind\":\"zfs\",\"verb\":\"snapshot\","
	    "\"args\":[\"tank/data@now\"],\"recursive\":true},{\"kind\":"
	    "\"gpart\",\"verb\":\"add\",\"args\":[\"ada9\",\"freebsd-zfs\","
	    "\"10G\",\"tank0\"]}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("zfs snapshot -r tank/data@now", jstr(&r,
	    "jobs.0.title"));
	ATF_CHECK_STREQ("gpart add -t freebsd-zfs -a 1m -s 10G -l tank0 ada9",
	    jstr(&r, "jobs.1.title"));
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q '^gpart add' storage.log "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^zfs snapshot -r tank/data@now$' "
	    "storage.log") == 0);
	/* A word that is an option, or a pool to destroy, is no job. */
	http("POST", path, "{\"jobs\":[{\"kind\":\"zfs\",\"verb\":\"destroy\","
	    "\"args\":[\"tank\"]}]}", &r);
	ATF_CHECK(r.status != 200 || strcmp(jstr(&r, "ok") != NULL ? jstr(&r,
	    "ok") : "", "true") != 0);
	resp_free(&r);
	http("POST", path, "{\"jobs\":[{\"kind\":\"gpart\",\"verb\":\"destroy\","
	    "\"args\":[\"-F\",\"ada9\"]}]}", &r);
	ATF_CHECK(r.status != 200 || strcmp(jstr(&r, "ok") != NULL ? jstr(&r,
	    "ok") : "", "true") != 0);
	resp_free(&r);
	ATF_CHECK(system("grep -q 'destroy' storage.log") != 0);
	snprintf(path, sizeof(path), "%.*s/fstab",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "sha256") != NULL);
	ATF_CHECK(strstr(jstr(&r, "text"), "/mnt/data") != NULL);
	snprintf(body, sizeof(body), "{\"text\":\"/dev/ada0p2\\t/\\tufs\\trw"
	    "\\t1\\t1\\n/dev/ada0p4 /mnt/more ufs rw 2 2\\n\",\"sha256\":"
	    "\"%s\"}", jstr(&r, "sha256"));
	resp_free(&r);
	http("POST", path, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '/mnt/more' fstab && grep -q '/mnt/data' "
	    "fstab.arcana-old") == 0);
	http("POST", path, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK(strstr(jstr(&r, "error"), "changed it meanwhile") != NULL);
	resp_free(&r);

	/* The host says which plugins it has: the programs are there. */
	snprintf(path, sizeof(path), "%.*s/jails",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bird", jstr(&r, "host.plugins.0"));
	ATF_CHECK_STREQ("wireguard", jstr(&r, "host.plugins.1"));
	ATF_CHECK_STREQ("strongswan", jstr(&r, "host.plugins.2"));
	resp_free(&r);

	/* BIRD's routes, asked for in birdc's words with , between. */
	snprintf(path, sizeof(path), "%.*s/net/bird-routes?filter=10.1.2.3,all",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("10.1.0.0/16", jstr(&r, "data.routes.0.prefix"));
	ATF_CHECK_STREQ("bgp_core", jstr(&r, "data.routes.0.protocol"));
	ATF_CHECK_STREQ("192.0.2.1", jstr(&r, "data.routes.0.nexthops.0.via"));
	ATF_CHECK_STREQ("BGP.as_path: 65001 65010", jstr(&r,
	    "data.routes.0.attrs.0"));
	ATF_CHECK_STREQ("bgp_edge", jstr(&r, "data.routes.1.protocol"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^-r show route for 10.1.2.3 all$' birdc.log")
	    == 0);
	/* A neighbour's whole table is counted, not sent. */
	snprintf(path, sizeof(path), "%.*s/net/bird-routes?filter=protocol,"
	    "bgp_core", (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK(strstr(jstr(&r, "error"), "845233 routes") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/net/bird-routes?filter=where,x",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	resp_free(&r);
}

CONSOLE_TC(unreachable, "A server that does not answer is reported")
ATF_TC_BODY(unreachable, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[128];

	start(tc, 0, NULL);
	enrol(&a);
	http("POST", "/api/servers", "{\"name\":\"gone\","
	    "\"uri\":\"unix:/nonexistent/jgd.sock\"}", &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/servers/%s/jails",
	    jstr(&r, "servers.0.id"));
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 502);
	ATF_CHECK_STREQ("unreachable", jstr(&r, "error.code"));
	ATF_CHECK_STREQ("failed", jstr(&r, "trace.2.status"));
	resp_free(&r);
	http("GET", "/api/servers/00000000/jails", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	path[strlen("/api/servers/12345678")] = '\0';
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_EQ(0, ucl_array_size(ucl_object_lookup(r.json, "servers")));
	resp_free(&r);
}

/* openssl(1): a CA, or a certificate it signs with the given SAN. */
static void
pki(const char *name, const char *ca, const char *san)
{
	char	 key[64], pem[64], csr[64], ext[64], subj[80], *argv[24];
	char	 cakey[64], capem[64];
	FILE	*fp;
	int	 i;

	snprintf(key, sizeof(key), "pki/%s.key", name);
	snprintf(pem, sizeof(pem), "pki/%s.pem", name);
	snprintf(csr, sizeof(csr), "pki/%s.csr", name);
	snprintf(ext, sizeof(ext), "pki/%s.ext", name);
	snprintf(subj, sizeof(subj), "/CN=%s", name);
	i = 0;
	argv[i++] = (char *)(uintptr_t)"/usr/bin/openssl";
	argv[i++] = (char *)(uintptr_t)"req";
	if (ca == NULL) {
		argv[i++] = (char *)(uintptr_t)"-x509";
		argv[i++] = (char *)(uintptr_t)"-days";
		argv[i++] = (char *)(uintptr_t)"2";
		argv[i++] = (char *)(uintptr_t)"-addext";
		argv[i++] =
		    (char *)(uintptr_t)"basicConstraints=critical,CA:TRUE";
	}
	argv[i++] = (char *)(uintptr_t)"-newkey";
	argv[i++] = (char *)(uintptr_t)"ec";
	argv[i++] = (char *)(uintptr_t)"-pkeyopt";
	argv[i++] = (char *)(uintptr_t)"ec_paramgen_curve:P-256";
	argv[i++] = (char *)(uintptr_t)"-nodes";
	argv[i++] = (char *)(uintptr_t)"-subj";
	argv[i++] = subj;
	argv[i++] = (char *)(uintptr_t)"-keyout";
	argv[i++] = key;
	argv[i++] = (char *)(uintptr_t)"-out";
	argv[i++] = ca == NULL ? pem : csr;
	argv[i] = NULL;
	ATF_REQUIRE_MSG(run_prog(argv), "openssl req %s failed", name);
	if (ca == NULL)
		return;
	ATF_REQUIRE((fp = fopen(ext, "w")) != NULL);
	fprintf(fp, "subjectAltName=%s\n", san);
	fclose(fp);
	snprintf(cakey, sizeof(cakey), "pki/%s.key", ca);
	snprintf(capem, sizeof(capem), "pki/%s.pem", ca);
	i = 0;
	argv[i++] = (char *)(uintptr_t)"/usr/bin/openssl";
	argv[i++] = (char *)(uintptr_t)"x509";
	argv[i++] = (char *)(uintptr_t)"-req";
	argv[i++] = (char *)(uintptr_t)"-in";
	argv[i++] = csr;
	argv[i++] = (char *)(uintptr_t)"-CA";
	argv[i++] = capem;
	argv[i++] = (char *)(uintptr_t)"-CAkey";
	argv[i++] = cakey;
	argv[i++] = (char *)(uintptr_t)"-CAcreateserial";
	argv[i++] = (char *)(uintptr_t)"-days";
	argv[i++] = (char *)(uintptr_t)"2";
	argv[i++] = (char *)(uintptr_t)"-extfile";
	argv[i++] = ext;
	argv[i++] = (char *)(uintptr_t)"-out";
	argv[i++] = pem;
	argv[i] = NULL;
	ATF_REQUIRE_MSG(run_prog(argv), "openssl x509 %s failed", name);
}

CONSOLE_TC(mtls, "A host over TCP with mutual TLS")
ATF_TC_BODY(mtls, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], uri[64], body[256], path[128];
	char		 jgd[MAXPATHLEN], listen[64], *argv[16];
	char		 sid[16], sw[128];
	FILE		*fp;
	pid_t		 pid;
	int		 port, i;
	long		 seen_pre;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(mkdir("pki", 0700) == 0);
	pki("ca", NULL, NULL);
	pki("server", "ca", "IP:127.0.0.1,DNS:localhost");
	pki("console", "ca", "DNS:console");
	snprintf(harness_webconf, sizeof(harness_webconf), "tls {\n"
	    "\tca = \"%s/pki/ca.pem\";\n\tcert = \"%s/pki/console.pem\";\n"
	    "\tkey = \"%s/pki/console.key\";\n}\n", cwd, cwd, cwd);
	start(tc, 0, NULL);

	/* A second arcana-agent, on TCP. */
	port = 20000 + (int)(getpid() % 20000);
	snprintf(listen, sizeof(listen), "tcp://127.0.0.1:%d", port);
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	i = 0;
	argv[i++] = jgd;
	argv[i++] = (char *)(uintptr_t)"-F";
	argv[i++] = (char *)(uintptr_t)"-l";
	argv[i++] = listen;
	argv[i++] = (char *)(uintptr_t)"-A";
	argv[i++] = (char *)(uintptr_t)"pki/ca.pem";
	argv[i++] = (char *)(uintptr_t)"-C";
	argv[i++] = (char *)(uintptr_t)"pki/server.pem";
	argv[i++] = (char *)(uintptr_t)"-K";
	argv[i++] = (char *)(uintptr_t)"pki/server.key";
	argv[i++] = (char *)(uintptr_t)"-f";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf";
	argv[i++] = (char *)(uintptr_t)"-D";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf.d";
	argv[i] = NULL;
	pid = spawn_server(argv, "arcana-agent2.out");
	ATF_REQUIRE((fp = fopen("arcana-agent2.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);
	usleep(300000);

	enrol(&a);
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%d", port);
	snprintf(body, sizeof(body), "{\"name\":\"remote\",\"uri\":\"%s\"}",
	    uri);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/servers/%s/jails",
	    jstr(&r, "servers.0.id"));
	ATF_CHECK_STREQ("false", jstr(&r, "servers.0.local"));
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("10.0.0.10", jail_str(&r, "web", "ip4.0"));
	ATF_CHECK_MSG(strstr(jstr(&r, "trace.2.detail"), "mutual TLS") != NULL,
	    "%s", jstr(&r, "trace.2.detail"));
	resp_free(&r);

	/* The certificate has to name the host the console expects. */
	snprintf(body, sizeof(body), "{\"name\":\"wrong\",\"uri\":"
	    "\"tcp://localhost:%d\",\"peer_name\":\"elsewhere.example\"}",
	    port);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/servers/%s/jails",
	    jstr(&r, "servers.1.id"));
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 502);
	ATF_CHECK_STREQ("unreachable", jstr(&r, "error.code"));
	resp_free(&r);

	/*
	 * Beside its TCP listener the agent has an SCTP one, at the same
	 * address and port, where the kernel has SCTP.  The console is
	 * switched to it only when the agent answers there, and back.
	 */
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	snprintf(sid, sizeof(sid), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/transport", sid);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("tcp", jstr(&r, "data.listeners.0.transport"));
	ATF_CHECK_STREQ("sctp", jstr(&r, "data.listeners.1.transport"));
	ATF_CHECK_STREQ("tcp", jstr(&r, "data.sessions.0.transport"));
	seen_pre = atol(jstr(&r, "data.seen"));
	ATF_CHECK(jstr(&r, "data.sessions.0.subject") != NULL && strstr(jstr(
	    &r, "data.sessions.0.subject"), "console") != NULL);
	resp_free(&r);
	snprintf(sw, sizeof(sw), "/api/servers/%s/transport/switch", sid);
	if (modfind("sctp") != -1) {
		http("POST", sw, "{\"transport\":\"sctp\"}", &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("true", jstr(&r, "ok"));
		resp_free(&r);
		http("GET", "/api/servers", NULL, &r);
		ATF_CHECK(strncmp(jstr(&r, "servers.0.uri"), "sctp://", 7) ==
		    0);
		resp_free(&r);
		/*
		 * A burst of first requests makes one association: the
		 * first makes it, the others wait for it and share it.
		 * The agent counts what connected.
		 */
		{
			pid_t	kids[6];
			long	seen1;
			int	k, st, bad;

			snprintf(path, sizeof(path), "/api/servers/%s/jails",
			    sid);
			for (k = 0; k < 6; k++)
				if ((kids[k] = fork()) == 0) {
					struct resp	kr;

					http("GET", path, NULL, &kr);
					_exit(kr.status == 200 ? 0 : 1);
				}
			bad = 0;
			for (k = 0; k < 6; k++)
				if (waitpid(kids[k], &st, 0) == -1 ||
				    !WIFEXITED(st) || WEXITSTATUS(st) != 0)
					bad++;
			ATF_CHECK_EQ(0, bad);
			/*
			 * What comes in parts, as a stream over that same
			 * association: the kernel's state, all of it, and no
			 * connection more for it.
			 */
			{
				char	 ask[160], *m;
				int	 ws, parts, done;

				ws = ws_open("/api/stream");
				snprintf(ask, sizeof(ask), "{\"id\":3,\"server\":"
				    "\"%s\",\"what\":\"sysctl\",\"filter\":"
				    "\"kern.\"}", sid);
				ws_send(ws, ask);
				parts = done = 0;
				while (!done && (m = ws_recv(ws)) != NULL) {
					if (strstr(m, "\"rows\":[") != NULL)
						parts++;
					if (strstr(m, "\"done\":true") != NULL)
						done = 1;
					ATF_CHECK_MSG(strstr(m, "\"error\"") ==
					    NULL, "%.200s", m);
					if (strstr(m, "\"error\"") != NULL)
						done = 1;
					free(m);
				}
				close(ws);
				ATF_CHECK_MSG(done && parts > 0, "%d parts, "
				    "done %d", parts, done);
			}
			snprintf(path, sizeof(path), "/api/servers/%s/transport",
			    sid);
			http("GET", path, NULL, &r);
			EXPECT(&r, 200);
			seen1 = atol(jstr(&r, "data.seen"));
			resp_free(&r);
			/* The switch's own, and the burst's one. */
			ATF_CHECK_MSG(seen1 - seen_pre <= 2, "the switch and a "
			    "burst of six first requests made %ld connections",
			    seen1 - seen_pre);
		}
		snprintf(path, sizeof(path), "/api/servers/%s/jails", sid);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("10.0.0.10", jail_str(&r, "web", "ip4.0"));
		ATF_CHECK_MSG(strstr(jstr(&r, "trace.2.detail"), "mutual DTLS")
		    != NULL, "%s", jstr(&r, "trace.2.detail"));
		resp_free(&r);
		/* And kept open: the next one goes over the same. */
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_MSG(strstr(jstr(&r, "trace.2.detail"), "kept open")
		    != NULL && strstr(jstr(&r, "trace.2.detail"), "shared") !=
		    NULL, "%s", jstr(&r, "trace.2.detail"));
		resp_free(&r);
		/*
		 * Requests at once go over that one association, each
		 * waiting for its own answer: the agent sees one SCTP
		 * session, however many there were.
		 */
		{
			pid_t	kids[6];
			int	k, st, bad;

			for (k = 0; k < 6; k++)
				if ((kids[k] = fork()) == 0) {
					struct resp	kr;

					http("GET", path, NULL, &kr);
					_exit(kr.status == 200 ? 0 : 1);
				}
			bad = 0;
			for (k = 0; k < 6; k++)
				if (waitpid(kids[k], &st, 0) == -1 ||
				    !WIFEXITED(st) || WEXITSTATUS(st) != 0)
					bad++;
			ATF_CHECK_EQ(0, bad);
		}
		snprintf(path, sizeof(path), "/api/servers/%s/transport", sid);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		{
			const char	*t;
			char		 key[64];
			int		 k, nsctp;

			nsctp = 0;
			for (k = 0; k < 32; k++) {
				snprintf(key, sizeof(key),
				    "data.sessions.%d.transport", k);
				if ((t = jstr(&r, key)) == NULL)
					break;
				if (strcmp(t, "sctp") == 0)
					nsctp++;
			}
			ATF_CHECK_EQ_MSG(1, nsctp, "%d SCTP sessions", nsctp);
		}
		resp_free(&r);
		snprintf(path, sizeof(path), "/api/servers/%s/jails", sid);
		snprintf(path, sizeof(path), "/api/servers/%s/transport", sid);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("true", jstr(&r, "data.listeners.1.up"));
		ATF_CHECK_STREQ("sctp", jstr(&r, "data.sessions.0.transport"));
		ATF_CHECK(strncmp(jstr(&r, "uri"), "sctp://", 7) == 0);
		resp_free(&r);
		http("POST", sw, "{\"transport\":\"tcp\"}", &r);
		EXPECT(&r, 200);
		resp_free(&r);
		http("GET", "/api/servers", NULL, &r);
		ATF_CHECK(strncmp(jstr(&r, "servers.0.uri"), "tcp://", 6) == 0);
		resp_free(&r);
	} else {
		/* No SCTP here: said by the agent, and nothing is changed. */
		http("GET", path, NULL, &r);
		ATF_CHECK_STREQ("false", jstr(&r, "data.listeners.1.up"));
		ATF_CHECK_STREQ("false", jstr(&r, "data.sctp"));
		resp_free(&r);
		http("POST", path, "{\"retry\":true}", &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("false", jstr(&r, "ok"));
		ATF_CHECK(strstr(jstr(&r, "error"), "sctp module") != NULL);
		resp_free(&r);
		http("POST", sw, "{\"transport\":\"sctp\"}", &r);
		EXPECT(&r, 502);
		resp_free(&r);
		http("GET", "/api/servers", NULL, &r);
		ATF_CHECK(strncmp(jstr(&r, "servers.0.uri"), "tcp://", 6) == 0);
		resp_free(&r);
	}
	snprintf(path, sizeof(path), "/api/servers/%s/jails", sid);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", sw, "{\"transport\":\"udp\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
}

CONSOLE_TC(enrol, "The console's own CA, and a host joining with "
    "arcana-enrol(8)")
ATF_TC_BODY(enrol, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 url[64], body[512], tok[80], listen[64], path[128];
	char		 tool[MAXPATHLEN], jgd[MAXPATHLEN], *argv[20];
	FILE		*fp;
	pid_t		 pid;
	int		 port, jport, i;

	port = 20000 + (int)(getpid() % 20000);
	snprintf(tool, sizeof(tool), "%s", locate(tc,
	    "../../../usr.sbin/arcana-enrol/arcana-enrol", "enrol",
	    "/usr/local/sbin/arcana-enrol"));
	ATF_REQUIRE_MSG(access(tool, X_OK) == 0, "no arcana-enrol at %s",
	    tool);
	start(tc, port, NULL);

	/* No tls block in web.conf: the console made a CA of its own. */
	ATF_CHECK(access("data/ca.pem", F_OK) == 0);
	ATF_CHECK(access("data/ca.key", F_OK) == 0);
	ATF_CHECK(access("data/console.pem", F_OK) == 0);
	ATF_CHECK(access("data/console.key", F_OK) == 0);

	/* Enrolment is for the logged-in user; the joining host needs
	 * only its token. */
	http("POST", "/api/enrol/tokens", "{\"name\":\"lab\",\"host\":"
	    "\"127.0.0.1\"}", &r);
	EXPECT(&r, 401);
	resp_free(&r);
	enrol(&a);
	http("POST", "/api/enrol/tokens", "{\"name\":\"lab\",\"host\":"
	    "\"not a host\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/enrol/tokens", "{\"name\":\"lab\",\"host\":"
	    "\"127.0.0.1\"}", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "token") != NULL);
	snprintf(tok, sizeof(tok), "%s", jstr(&r, "token"));
	ATF_CHECK_MSG(strstr(jstr(&r, "command"), "arcana-enrol -s http://"
	    "localhost:") != NULL, "%s", jstr(&r, "command"));
	resp_free(&r);
	/* Another port than the usual is in the command for the host. */
	http("POST", "/api/enrol/tokens", "{\"name\":\"lab\",\"host\":"
	    "\"127.0.0.1\",\"port\":4311}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(jstr(&r, "command"), "arcana-enrol -s -p 4311 "
	    "http://") != NULL, "%s", jstr(&r, "command"));
	resp_free(&r);
	http("POST", "/api/enrol", "{\"token\":\"nope\",\"csr\":\"\"}", &r);
	EXPECT(&r, 403);
	resp_free(&r);

	/* The host joins. */
	snprintf(url, sizeof(url), "%s", harness_origin);
	i = 0;
	argv[i++] = tool;
	argv[i++] = (char *)(uintptr_t)"-d";
	argv[i++] = (char *)(uintptr_t)"host";
	argv[i++] = url;
	argv[i++] = tok;
	argv[i] = NULL;
	ATF_REQUIRE_MSG(run_prog(argv), "arcana-enrol failed");
	ATF_CHECK(access("host/host.key", F_OK) == 0);
	ATF_CHECK(access("host/host.pem", F_OK) == 0);
	ATF_CHECK(access("host/ca.pem", F_OK) == 0);
	i = 0;
	argv[i++] = (char *)(uintptr_t)"/usr/bin/openssl";
	argv[i++] = (char *)(uintptr_t)"verify";
	argv[i++] = (char *)(uintptr_t)"-CAfile";
	argv[i++] = (char *)(uintptr_t)"data/ca.pem";
	argv[i++] = (char *)(uintptr_t)"host/host.pem";
	argv[i] = NULL;
	ATF_CHECK_MSG(run_prog(argv), "the certificate does not verify");
	/* The token is used up. */
	i = 0;
	argv[i++] = tool;
	argv[i++] = (char *)(uintptr_t)"-d";
	argv[i++] = (char *)(uintptr_t)"again";
	argv[i++] = url;
	argv[i++] = tok;
	argv[i] = NULL;
	ATF_CHECK(!run_prog(argv));

	/* It is a server now, and a arcana-agent with the certificate
	 * answers the console over mutual TLS. */
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lab", jstr(&r, "servers.0.name"));
	ATF_CHECK_STREQ("tcp://127.0.0.1:4310", jstr(&r, "servers.0.uri"));
	snprintf(path, sizeof(path), "/api/servers/%s", jstr(&r,
	    "servers.0.id"));
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	jport = port + 1;
	snprintf(listen, sizeof(listen), "tcp://127.0.0.1:%d", jport);
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	i = 0;
	argv[i++] = jgd;
	argv[i++] = (char *)(uintptr_t)"-F";
	argv[i++] = (char *)(uintptr_t)"-l";
	argv[i++] = listen;
	argv[i++] = (char *)(uintptr_t)"-A";
	argv[i++] = (char *)(uintptr_t)"host/ca.pem";
	argv[i++] = (char *)(uintptr_t)"-C";
	argv[i++] = (char *)(uintptr_t)"host/host.pem";
	argv[i++] = (char *)(uintptr_t)"-K";
	argv[i++] = (char *)(uintptr_t)"host/host.key";
	argv[i++] = (char *)(uintptr_t)"-f";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf";
	argv[i++] = (char *)(uintptr_t)"-D";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf.d";
	argv[i++] = (char *)(uintptr_t)"-j";
	argv[i++] = (char *)(uintptr_t)"./fake-jail";
	argv[i] = NULL;
	pid = spawn_server(argv, "arcana-agent2.out");
	ATF_REQUIRE((fp = fopen("arcana-agent2.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);
	usleep(300000);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"tcp://"
	    "127.0.0.1:%d\"}", jport);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/servers/%s/jails",
	    jstr(&r, "servers.0.id"));
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("10.0.0.10", jail_str(&r, "web", "ip4.0"));
	ATF_CHECK_MSG(strstr(jstr(&r, "trace.2.detail"), "mutual TLS") != NULL,
	    "%s", jstr(&r, "trace.2.detail"));
	resp_free(&r);
}

/* A service as MEF 70.2 says one, with two edges: @A and @B are them. */
static const char sdwan_good[] =
    "{\"version\":0,"
    "\"ucs\":[{\"id\":\"inet\",\"type\":\"public\",\"billing\":\"flat-rate\","
    "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}},{\"id\":\"mpls\","
    "\"type\":\"private\",\"billing\":\"flat-rate\",\"tunnel\":{\"kind\":"
    "\"geneve\"}}],"
    "\"edges\":[{\"server\":\"@A\",\"ntp\":[\"ntp.example.org\",\"10.99.0.9\"],"
    "\"ucs_end_points\":[{\"id\":\"a-inet\","
    "\"ucs\":\"inet\",\"interface\":\"vtnet0\",\"breakout\":true},{\"id\":"
    "\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"}]},{\"server\":"
    "\"@B\",\"ucs_end_points\":[{\"id\":\"b-inet\",\"ucs\":\"inet\","
    "\"interface\":\"vtnet0\"},{\"id\":\"b-mpls\",\"ucs\":\"mpls\","
    "\"interface\":\"vtnet1\",\"backup\":true}]}],"
    "\"swvcs\":[{\"id\":\"acme\",\"fib\":1,\"as\":64600,\"md5\":\"edges-secret\","
    "\"ucs\":[\"inet\",\"mpls\"],"
    "\"reserved_prefixes\":[\"100.64.0.0/24\"],"
    "\"domains\":{\"service\":{\"prefix\":\"100.64.0.0/24\",\"rd\":\"64600:1\","
    "\"rt\":[\"64600:1\"],\"label\":1001},\"breakout\":{\"fib\":2,\"rd\":"
    "\"64600:2\",\"label\":1002},\"subscriber\":{\"rd\":\"64600:3\",\"label\":"
    "1003}},"
    "\"zones\":[{\"name\":\"office\",\"prefixes\":[\"10.1.0.0/16\"],"
    "\"policies\":[{\"app\":\"web\",\"policy\":\"fast\"}]},{\"name\":"
    "\"rest\",\"prefixes\":\"Default\"}],"
    "\"topologies\":[{\"name\":\"hub\",\"type\":\"rooted-multipoint\","
    "\"roots\":[\"hq\"],\"leaves\":[\"branch\"]}],"
    "\"intervals\":{\"eval\":1000,\"arrival\":100,\"ir\":500},"
    "\"bfd\":{\"interval\":200,\"multiplier\":3},"
    "\"tca\":{\"delay\":30,\"loss\":0.05,\"damping\":2},"
    "\"rate_limiters\":[{\"name\":\"shared\",\"commit\":1000000,\"limit\":"
    "5000000}],"
    "\"security_policies\":[{\"name\":\"guard\",\"criteria\":{\"ip-block\":{"
    "\"allow\":[\"10.1.0.0/16\"],\"deny\":[\"192.0.2.0/24\"]},"
    "\"dns-domain-filter\":{\"deny\":[\"ads.example\"]},"
    "\"dns-protocol-filter\":true,\"rate-limit\":2000000,\"log\":true,"
    "\"url-filter\":{\"mode\":\"sni\",\"deny\":[\"bad.example\"]},"
    "\"malware\":true,\"ids\":{\"mode\":\"detect\",\"ruleset\":true,"
    "\"rules\":[\"alert http any any -> $HOME_NET any (msg:\\\"x\\\"; "
    "sid:1000001; rev:1;)\"]}}}],"
    "\"importance\":{\"levels\":[\"high\",\"low\"],\"default\":\"low\"},"
    "\"groups\":[\"bulk\"],"
    "\"flows\":[{\"name\":\"web\",\"criteria\":{\"dport\":[80,\"https\"],"
    "\"protv4\":[\"tcp\"]}},{\"name\":\"voice\",\"criteria\":{\"appid\":"
    "[\"sip\"],\"dscp\":[46]},\"group\":\"bulk\"},{\"name\":\"all\","
    "\"criteria\":{\"any\":true}}],"
    "\"policies\":[{\"name\":\"fast\",\"direction\":\"ingress\",\"criteria\":"
    "{\"encryption\":\"required-public-only\",\"performance\":{\"primary\":"
    "{\"metric\":\"delay\",\"threshold\":10,\"ceiling\":12,\"remediation\":"
    "9},\"secondary\":[{\"metric\":\"loss\",\"threshold\":0.05}]},"
    "\"bandwidth\":\"shared\",\"business-importance\":\"high\","
    "\"internet-breakout\":\"enabled\",\"af-security-ingress\":\"guard\"}},"
    "{\"name\":"
    "\"hubonly\",\"direction\":\"ingress\",\"criteria\":{"
    "\"virtual-topology\":\"hub\"}},{\"name\":\"quiet\",\"direction\":"
    "\"egress\",\"criteria\":{\"egress-block\":\"discard\"}}],"
    "\"end_points\":[{\"id\":\"hq\",\"edge\":\"@A\",\"uni\":{\"id\":"
    "\"uni-hq\",\"interface\":\"vtnet2\",\"ipv4\":{\"mode\":\"dhcp\","
    "\"prefix\":\"10.1.0.0/24\",\"provider\":[\"10.1.0.1\"],\"reserved\":"
    "[\"10.1.0.0/26\",\"10.1.0.200/30\"],\"dns\":[\"10.1.0.1\"],\"lease\":"
    "\"1h\"},\"routes\":"
    "[{\"prefix\":\"10.1.8.0/22\",\"next_hop\":\"10.1.0.2\",\"distance\":"
    "10}],\"bgp\":{\"family\":\"ipv4\",\"as\":65010,\"neighbors\":"
    "[\"10.1.0.2\"],\"password\":\"s3cret\",\"hold_time\":90,\"distance\":"
    "150,\"communities\":[[64600,100]]}},\"policy_map\":[{\"zone\":\"office\",\"app\":\"all\",\"ingress\":"
    "\"hubonly\",\"egress\":\"quiet\"}],\"nat\":{\"ip_version\":\"ipv4\","
    "\"public_prefix\":\"198.51.100.0/30\"}},{\"id\":\"branch\",\"edge\":"
    "\"@B\",\"uni\":{\"id\":\"uni-br\",\"interface\":\"vtnet2\",\"vlan\":20,"
    "\"ipv6\":{\"mode\":\"slaac\",\"prefix\":\"2001:db8:1::/64\","
    "\"provider\":[\"2001:db8:1::1\"],\"dns\":[\"2001:db8:1::1\"]}}},"
    "{\"id\":\"road\",\"edge\":\"@A\",\"remote\":{\"interface\":\"wg5\","
    "\"prefix\":\"10.30.0.0/24\",\"port\":51820,\"identities\":[{\"name\":"
    "\"alice\",\"zone\":\"office\",\"public_key\":"
    "\"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\"}]}}]}]}";

/* s with its first from made to, into out; false when from is not there. */
/* An interface of this host with an IPv4 address that is not the
 * loopback's, and the address: the first up, by ifconfig(8). */
static bool
host_iface(char *ifn, size_t ilen, char *addr, size_t alen)
{
	FILE	*fp;
	char	 line[200], *p, *q;

	ifn[0] = addr[0] = '\0';
	if ((fp = popen("ifconfig -l -u", "r")) == NULL)
		return (false);
	if (fgets(line, sizeof(line), fp) == NULL)
		line[0] = '\0';
	pclose(fp);
	for (p = line; (q = strsep(&p, " \n")) != NULL; ) {
		char	cmd[200];

		if (q[0] == '\0' || strncmp(q, "lo", 2) == 0 || strncmp(q, "cni",
		    3) == 0 || strncmp(q, "pflog", 5) == 0)
			continue;
		snprintf(cmd, sizeof(cmd), "ifconfig %s inet 2>/dev/null | awk "
		    "'/inet /{print $2; exit}'", q);
		if ((fp = popen(cmd, "r")) == NULL)
			continue;
		if (fgets(addr, (int)alen, fp) != NULL && addr[0] != '\0' &&
		    addr[0] != '\n') {
			addr[strcspn(addr, "\n")] = '\0';
			pclose(fp);
			snprintf(ifn, ilen, "%s", q);
			return (true);
		}
		pclose(fp);
		addr[0] = '\0';
	}
	return (false);
}

static bool
swap_in(const char *s, const char *from, const char *to, char *out,
    size_t len)
{
	const char	*p;

	if ((p = strstr(s, from)) == NULL)
		return (false);
	snprintf(out, len, "%.*s%s%s", (int)(p - s), s, to, p + strlen(from));
	return (true);
}

CONSOLE_TC(sdwan, "SD-WAN services are checked as MEF 70.2 says, and kept")
ATF_TC_BODY(sdwan, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[8192], t1[8192], bad[8192];
	size_t		i;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"a\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sa, sizeof(sa), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"b\",\"uri\":\"unix:%s/./"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sb, sizeof(sb), "%s", strcmp(jstr(&r, "servers.0.id"), sa) ==
	    0 ? jstr(&r, "servers.1.id") : jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);

	/* Nothing yet: version 0. */
	http("GET", "/api/sdwan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("0", jstr(&r, "version"));
	resp_free(&r);
	http("POST", "/api/sdwan/check", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);

	/* Each change that breaks a requirement, and what it is told. */
	static const char *const breaks[][3] = {
		{ "\"type\":\"public\"", "\"type\":\"cloud\"", "R170" },
		{ "\"fib\":1", "\"fib\":0", "FIB 0" },
		{ "\"10.1.0.0/16\"", "\"10.1.0.0/16\",\"10.1.4.0/24\"",
		    "(R20)" },
		{ "\"prefixes\":\"Default\"", "\"prefixes\":\"Default\"},"
		    "{\"name\":\"more\",\"prefixes\":\"Default\"", "(R21)" },
		{ "\"name\":\"rest\"", "\"name\":\"Internet\"", "(§9.5)" },
		{ "\"ceiling\":12", "\"ceiling\":8", "(R72)" },
		{ "\"remediation\":9", "\"remediation\":12", "(R75)" },
		{ "{\"any\":true}", "{\"any\":true,\"dscp\":[1]}", "(R99)" },
		{ "\"limit\":5000000", "\"limit\":10", "(R7)" },
		{ "\"ingress\":\"hubonly\"", "\"ingress\":\"quiet\"", "(R106)" },
		{ "\"zone\":\"office\"", "\"zone\":\"Internet\"", "(R107)" },
		{ "\"provider\":[\"10.1.0.1\"]", "\"provider\":[\"10.2.0.1\"]",
		    "(R131)" },
		{ "\"leaves\":[\"branch\"]", "\"leaves\":[\"hq\"]", "(R31)" },
		{ "\"neighbors\":[\"10.1.0.2\"]", "\"neighbors\":[\"10.9.0.2\"]",
		    "(§11.6.2)" },
		{ "\"hold_time\":90", "\"hold_time\":90,\"as_override\":true",
		    "as_override" },
		{ "\"as\":65010", "\"as\":0", "subscriber's AS" },
		{ "\"deny\":[\"192.0.2.0/24\"]", "\"deny\":[\"192.0.2.0/33\"]",
		    "is not a prefix" },
		{ "\"deny\":[\"ads.example\"]", "\"deny\":[\"ads..example\"]",
		    "not a domain name" },
		{ "\"rate-limit\":2000000", "\"rate-limit\":10", "1000 or more" },
		{ "\"log\":true,", "\"log\":true,\"nope\":true,", "not a criterion" },
		/* The URL filter (SASE-4): a mode, sni or inspect; domains. */
		{ "\"mode\":\"sni\"", "\"mode\":\"spy\"", "sni or inspect" },
		/* Intrusion detection (SASE-4): detect, rules with a sid. */
		{ "\"mode\":\"detect\"", "\"mode\":\"prevent\"", "a mode, detect" },
		{ "sid:1000001; rev:1;)", "rev:1;)", "is not a Suricata rule" },
		{ "\"alert http any", "\"shout http any", "is not a Suricata rule" },
		{ "\"ruleset\":true", "\"ruleset\":\"yes\"", "ids.ruleset is true" },
		{ "\"deny\":[\"bad.example\"]", "\"deny\":[\"bad example\"]",
		    "not a domain name" },
		{ "\"deny\":[\"192.0.2.0/24\"]", "\"deny\":[\"192.0.2.0/24\"],"
		    "\"lists\":[\"nowhere\"]", "no list nowhere" },
		{ "\"dns-protocol-filter\":true", "\"dns-protocol-filter\":\"yes\"",
		    "true or false" },
		{ "\"md5\":\"edges-secret\",", "\"md5\":\"edges-secret\","
		    "\"control_plane\":{\"host\":\"nobody\"},", "control_plane.host" },
		{ "\"md5\":\"edges-secret\",", "\"md5\":\"edges-secret\","
		    "\"control_plane\":{\"host\":\"@A\",\"cluster_id\":\"x\"},",
		    "cluster_id" },
		{ "\"md5\":\"edges-secret\",", "\"md5\":\"edges-secret\","
		    "\"control_plane\":{\"host\":\"@A\",\"ctvc\":\"dsl\"},",
		    "control_plane.ctvc" },
		{ "\"multiplier\":3", "\"multiplier\":1", "(R159)" },
		{ "\"10.99.0.9\"]", "\"not a host!\"]", "ntp:" },
		{ "\"damping\":2", "\"damping\":0", "(CR2)" },
		{ "\"vlan\":20", "\"vlan\":5000", "(§11.2)" },
		{ "\"virtual-topology\":\"hub\"", "\"virtual-topology\":\"nope\"",
		    "(R47)" },
		{ "\"metric\":\"loss\"", "\"metric\":\"delay\"", "(R68)" },
		{ "\"kind\":\"geneve\"", "\"kind\":\"wg\",\"ipsec\":true",
		    "wg encrypts" },
		{ "\"interface\":\"vtnet1\"}", "\"interface\":\"vtnet1\","
		    "\"breakout\":true}", "(§12.3)" },
		{ "\"business-importance\":\"high\"",
		    "\"business-importance\":\"mid\"", "importance levels" },
		{ "\"next_hop\":\"10.1.0.2\"", "\"next_hop\":\"10.9.0.2\"",
		    "(§11.6.1)" },
		{ "\"dport\":[80,\"https\"]", "\"dport\":[80,\"nosuchport\"]",
		    "nosuchport is not one" },
		{ "\"groups\":[\"bulk\"]", "\"groups\":[\"bulk\",\"web\"]",
		    "(R92)" },
		{ "\"egress-block\":\"discard\"", "\"encryption\":\"optional\"",
		    "egress policy" },
		{ "\"ipv6\":{", "\"ipv6\":{\"mode\":\"none\"},\"x\":{", "(R128)" },
		/* A remote end point (SASE-3): its port, an identity's zone
		 * and key, and not a UNI besides. */
		{ "\"port\":51820", "\"port\":70000", "port is 1 to 65535" },
		{ "\"zone\":\"office\",\"public_key\"", "\"zone\":\"nowhere\","
		    "\"public_key\"", "its zone is one of the zones" },
		{ "\"public_key\":\"xTIB", "\"public_key\":\"short", "a WireGuard "
		    "one" },
		{ "\"remote\":{", "\"uni\":{\"id\":\"x\"},\"remote\":{", "not "
		    "both" },
		/* The UCS end points' addressing and routing (Mplify 119). */
		{ "\"interface\":\"vtnet1\",\"backup\":true", "\"interface\":"
		    "\"vtnet1\",\"backup\":true,\"addressing\":\"ppp\"",
		    "(Mplify 119 §12.2.3.2)" },
		{ "\"interface\":\"vtnet1\",\"backup\":true", "\"interface\":"
		    "\"vtnet1\",\"backup\":true,\"vrf\":0", "(§12.2.3.4)" },
		{ "\"interface\":\"vtnet1\",\"backup\":true", "\"interface\":"
		    "\"vtnet1\",\"backup\":true,\"routing\":{\"bgp\":{\"family\":"
		    "\"ipv4\",\"neighbors\":[\"10.99.0.9\"]}}", "AS number" },
		/* The routing domains (Mplify 119). */
		{ "\"breakout\":{\"fib\":2", "\"breakout\":{\"fib\":1", "(R20)" },
		{ "\"label\":1001", "\"label\":7", "(R19)" },
		{ "\"label\":1002", "\"label\":1001", "(R19)" },
		{ "\"rd\":\"64600:1\"", "\"rd\":\"x:1\"", "(R16)" },
		/* Another service with a UNI on the same interface and VLAN
		 * of the same edge. */
		{ "\"swvcs\":[", "\"swvcs\":[{\"id\":\"other\",\"fib\":2,\"ucs\":"
		    "[\"inet\"],\"zones\":[{\"name\":\"z\",\"prefixes\":\"Default\"}],"
		    "\"flows\":[{\"name\":\"all\",\"criteria\":{\"any\":true}}],"
		    "\"policies\":[{\"name\":\"p\",\"direction\":\"ingress\"}],"
		    "\"end_points\":[{\"id\":\"o1\",\"edge\":\"@A\",\"uni\":{\"id\":"
		    "\"uni-o1\",\"interface\":\"vtnet2\",\"ipv4\":{\"mode\":\"static\","
		    "\"prefix\":\"10.5.0.0/24\",\"provider\":[\"10.5.0.1\"]}}}]},",
		    "(R3)" },
	};
	for (i = 0; i < nitems(breaks); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, breaks[i][0], breaks[i][1], bad,
		    sizeof(bad)), "%s is not in the document", breaks[i][0]);
		while (swap_in(bad, "@A", sa, t1, sizeof(t1)))
			snprintf(bad, sizeof(bad), "%s", t1);
		http("POST", "/api/sdwan/check", bad, &r);
		ATF_CHECK_MSG(r.status == 400 && strstr(r.body, breaks[i][2]) !=
		    NULL, "%s: HTTP %d, %s", breaks[i][1], r.status, r.body);
		resp_free(&r);
	}

	/* Kept, as version 1; one from version 0 again is too old. */
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("1", jstr(&r, "version"));
	resp_free(&r);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 409);
	resp_free(&r);
	http("GET", "/api/sdwan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("1", jstr(&r, "version"));
	ATF_CHECK_STREQ("acme", jstr(&r, "swvcs.0.id"));
	ATF_CHECK_STREQ("10", jstr(&r,
	    "swvcs.0.policies.0.criteria.performance.primary.threshold"));
	resp_free(&r);
	/* Without a session, nothing. */
	cookie[0] = '\0';
	http("GET", "/api/sdwan", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
}

/* The apply's end: done or failed; its state, into r. */
static void
sdwan_wait(struct resp *r)
{
	int	i;

	for (i = 0; i < 300; i++) {
		http("GET", "/api/sdwan/apply", NULL, r);
		if (r->status == 200 && jstr(r, "applying") != NULL &&
		    strcmp(jstr(r, "applying"), "false") == 0 && jstr(r,
		    "apply.state") != NULL && strcmp(jstr(r, "apply.state"),
		    "running") != 0)
			return;
		resp_free(r);
		usleep(200000);
	}
	ATF_REQUIRE_MSG(false, "the apply did not end");
}

/* How many of the plan's changes are of that kind. */
static int
changes_of(const struct resp *r, const char *change)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((c = ucl_object_iterate(ucl_object_lookup(r->json, "changes"),
	    &it, true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(ucl_object_lookup(c,
		    "change")), change) == 0)
			n++;
	return (n);
}

/*
 * A USWE tunnel (Mplify 119 §10): the public underlay's tunnels made
 * ipsec(4) interfaces keyed by the agents: a pair each, the SAs derived
 * from the far end's public half, which the apply reads from that end.
 */
CONSOLE_TC(sdwan_uswe, "SD-WAN with a uswe tunnel: keys made, SAs derived")
ATF_TC_BODY(sdwan_uswe, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[8192], t1[8192], t2[400];
	size_t		i;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"a\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sa, sizeof(sa), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"b\",\"uri\":\"unix:%s/./"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sb, sizeof(sb), "%s", strcmp(jstr(&r, "servers.0.id"), sa) ==
	    0 ? jstr(&r, "servers.1.id") : jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	static const char *const edits[][2] = {
		{ "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}",
		    "\"tunnel\":{\"kind\":\"uswe\",\"algorithms\":\"aes-gcm-16\"}" },
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"gateway\":\"192.0.2.254\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
		{ "\"kind\":\"geneve\"", "\"kind\":\"gif\"" },
	};
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)));
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* IPsec IKEv2 under a uswe tunnel is refused. */
	ATF_REQUIRE(swap_in(doc, "\"kind\":\"uswe\",", "\"kind\":\"uswe\","
	    "\"ipsec\":true,", t1, sizeof(t1)));
	http("PUT", "/api/sdwan", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "encrypts by itself")
	    != NULL, "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* The plan: ipsec100 and ipsec101 with their reqid, a key pair each
	 * before, the SAs derived after from the far end's public half,
	 * GCM without a separate authentication, ESN and UDP by default. */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"if-create\",\"interface\":"
	    "\"ipsec100\",\"fib\":1,\"description\":\"sdwan\",\"persist\":true,"
	    "\"tunnel_local\":\"192.0.2.1\",\"tunnel_remote\":\"192.0.2.2\","
	    "\"reqid\":100") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"key\":\"uswekey:ipsec100\",\"phase\":2") !=
	    NULL);
	ATF_CHECK(strstr(r.body, "\"kind\":\"ipsec-sa\",\"verb\":\"key\","
	    "\"interface\":\"ipsec101\"") != NULL);
	snprintf(t2, sizeof(t2), "\"kind\":\"ipsec-sa\",\"verb\":\"derive\","
	    "\"interface\":\"ipsec100\",\"reqid\":100,\"tunnel_local\":"
	    "\"192.0.2.1\",\"tunnel_remote\":\"192.0.2.2\",\"args\":[\"peer\","
	    "\"${uswe:%s:ipsec101}\",\"enc\",\"aes-gcm-16\",\"encap\",\"esn\","
	    "\"epoch\",\"0\",\"lifetime\",\"86400\"]", sb);
	ATF_CHECK_MSG(strstr(r.body, t2) != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"verb\":\"clear\",\"interface\":\"ipsec100\"")
	    != NULL);
	ATF_CHECK(strstr(r.body, "\"kind\":\"ipsec\",\"verb\":\"conn\"") == NULL);
	resp_free(&r);
	/* Applied: the pairs made (one agent stands for both ends, so two
	 * files), the far halves read from the sdwan read, the two SAs each
	 * way set by setkey, mirrored. */
	http("POST", "/api/sdwan/apply", "{}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	resp_free(&r);
	ATF_CHECK(system("test -f sdwan-key-ipsec100.pem -a -f "
	    "sdwan-key-ipsec101.pem") == 0);
	ATF_CHECK(system("grep -q '^ipsec100 create reqid 100' ifconfig.log && "
	    "grep -q '^ipsec101 create reqid 101' ifconfig.log") == 0);
	ATF_CHECK(system("grep -c '^add 192.0.2.1 192.0.2.2 esp 0x[0-9a-f]* -m "
	    "tunnel -u 10[01] -r 128 -esn -natt 192.0.2.1\\[4500\\] 192.0.2.2"
	    "\\[4500\\] -E aes-gcm-16 0x[0-9a-f]*' setkey.conf | grep -q '^2$'")
	    == 0);
	ATF_CHECK(system("grep '^add 192.0.2.1 192.0.2.2 ' setkey.conf | sed "
	    "'s/-u 10[01]/-u N/' | sort -u | wc -l | grep -q '^ *1$'") == 0);
	/* Its SPIs are the same both ways: what a derive on each end set. */
	ATF_CHECK(system("grep '^add 192.0.2.2 192.0.2.1 ' setkey.conf | sed "
	    "'s/-u 10[01]/-u N/' | sort -u | wc -l | grep -q '^ *1$'") == 0);
	/* The keys turned by hand (Mplify 119 R110, R112): a next pair on
	 * each end, the new SAs from them put in inbound on both, then
	 * outbound, then the old taken out and the next pair made the pair;
	 * the apply refused meanwhile; the rotation's state kept. */
	ATF_CHECK(system("cp sdwan-key-ipsec100.pem k100.was && cp "
	    "sdwan-key-ipsec101.pem k101.was") == 0);
	http("POST", "/api/sdwan/rekey", "{\"tunnel\":\"acme/none\"}", &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("POST", "/api/sdwan/rekey", "{\"tunnel\":\"acme/a-inet-b-inet\"}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/sdwan/apply", "{}", &r);
	ATF_CHECK_MSG(r.status == 409 && strstr(r.body, "key rotation") != NULL,
	    "%d %s", r.status, r.body);
	resp_free(&r);
	for (i = 0; i < 300; i++) {
		http("GET", "/api/sdwan/rekey", NULL, &r);
		if (r.status == 200 && jstr(&r, "rekeys.acme/a-inet-b-inet.state")
		    != NULL && strcmp(jstr(&r, "rekeys.acme/a-inet-b-inet.state"),
		    "running") != 0)
			break;
		resp_free(&r);
		usleep(200000);
	}
	ATF_CHECK_MSG(jstr(&r, "rekeys.acme/a-inet-b-inet.state") != NULL &&
	    strcmp(jstr(&r, "rekeys.acme/a-inet-b-inet.state"), "done") == 0,
	    "%s", r.body);
	ATF_CHECK(jstr(&r, "rekeying") != NULL && strcmp(jstr(&r, "rekeying"),
	    "false") == 0);
	resp_free(&r);
	/* Eight SAs added in all (four, then the new four: the two inbound
	 * ones, then the two outbound, each with the old outbound taken
	 * out after it), then the two old inbound taken out: in that
	 * order; the new SPIs not the old; the next pairs made the pairs. */
	ATF_CHECK(system("grep -c '^add ' setkey.conf | grep -q '^8$'") == 0);
	ATF_CHECK(system("grep -c '^delete ' setkey.conf | grep -q '^4$'") == 0);
	ATF_CHECK(system("grep '^add \\|^delete ' setkey.conf | sed -n '5,12p' | "
	    "cut -c1-3 | tr -d '\\n' | grep -q '^addaddadddeladddeldeldel$'") ==
	    0);
	ATF_CHECK(system("grep '^add \\|^delete ' setkey.conf | sed -n '5,6p' | "
	    "grep -c '^add 192.0.2.2 192.0.2.1 .* -u 100 \\|^add 192.0.2.1 "
	    "192.0.2.2 .* -u 101 ' | grep -q '^2$'") == 0);
	ATF_CHECK(system("grep '^add \\|^delete ' setkey.conf | sed -n '8p;10p' | "
	    "grep -c '^delete 192.0.2.1 192.0.2.2 \\|^delete 192.0.2.2 192.0.2.1 "
	    "' | grep -q '^2$'") == 0);
	ATF_CHECK(system("grep '^add ' setkey.conf | sed 's/-u 10[01]//' | awk "
	    "'{print $5}' | sort -u | wc -l | grep -q '^ *4$'") == 0);
	ATF_CHECK(system("test ! -e sdwan-key-ipsec100-next.pem && ! cmp -s "
	    "k100.was sdwan-key-ipsec100.pem && ! cmp -s k101.was "
	    "sdwan-key-ipsec101.pem") == 0);
}

CONSOLE_TC(sdwan_apply, "SD-WAN made on the edges: planned, applied, kept")
ATF_TC_BODY(sdwan_apply, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[8192], t1[8192], t2[300], lifn[32], laddr[64];
	size_t		i;
	FILE		*fp;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"a\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sa, sizeof(sa), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"b\",\"uri\":\"unix:%s/./"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sb, sizeof(sb), "%s", strcmp(jstr(&r, "servers.0.id"), sa) ==
	    0 ? jstr(&r, "servers.1.id") : jstr(&r, "servers.0.id"));
	resp_free(&r);
	/* The lists the security policy names (SASE-2): one pasted, one a
	 * feed from a file the console's host reads with libfetch; each
	 * kept with a version, a failed feed with its error. */
	snprintf(t2, sizeof(t2), "%s/feed.txt", cwd);
	ATF_REQUIRE((fp = fopen(t2, "w")) != NULL);
	fprintf(fp, "# a feed\n203.0.113.0/24 ; evil\n\nbad-feed.example\n");
	fclose(fp);
	snprintf(body, sizeof(body), "{\"interval\":2,\"feeds\":[{\"name\":"
	    "\"blocked\",\"text\":\"198.51.100.0/24\\nbad.example\\n\"},{\"name\":"
	    "\"feedlist\",\"url\":\"file://%s\"},{\"name\":\"dead\",\"url\":"
	    "\"file://%s/none.txt\"}]}", t2, cwd);
	http("PUT", "/api/sdwan/lists", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/sdwan/lists/fetch", "{}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/lists", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "lists.blocked.version") != NULL && strcmp(jstr(
	    &r, "lists.blocked.version"), "1") == 0 && strcmp(jstr(&r,
	    "lists.blocked.count"), "2") == 0 && strcmp(jstr(&r,
	    "lists.feedlist.version"), "1") == 0 && strcmp(jstr(&r,
	    "lists.feedlist.count"), "2") == 0 && jstr(&r, "lists.dead.error")
	    != NULL && strcmp(jstr(&r, "lists.dead.count"), "0") == 0, "%s",
	    r.body);
	ATF_CHECK_STREQ("2", jstr(&r, "interval"));
	resp_free(&r);
	/* Fetched again unchanged: the version stays. */
	http("POST", "/api/sdwan/lists/fetch", "{\"name\":\"feedlist\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/lists", NULL, &r);
	ATF_CHECK_STREQ("1", jstr(&r, "lists.feedlist.version"));
	resp_free(&r);
	http("PUT", "/api/sdwan/lists", "{\"feeds\":[{\"name\":\"x\",\"text\":"
	    "\"not a prefix!\"}]}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "not a prefix nor a "
	    "domain") != NULL, "%s", r.body);
	resp_free(&r);
	/* The good one, its underlays with addresses, its UNIs on lo0. */
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	static const char *const edits[][2] = {
		{ "\"ip-block\":{\"allow\":[\"10.1.0.0/16\"],\"deny\":[\"192.0.2.0/24\"]}",
		    "\"ip-block\":{\"allow\":[\"10.1.0.0/16\"],\"deny\":[\"192.0.2.0/24\"],"
		    "\"lists\":[\"blocked\",\"feedlist\"]}" },
		{ "\"dns-domain-filter\":{\"deny\":[\"ads.example\"]}",
		    "\"dns-domain-filter\":{\"deny\":[\"ads.example\"],\"lists\":["
		    "\"feedlist\",\"blocked\"]}" },
		{ "\"md5\":\"edges-secret\",", "\"md5\":\"edges-secret\","
		    "\"control_plane\":{\"host\":\"@A\",\"cluster_id\":\"192.0.2.1\","
		    "\"ctvc\":\"inet\"}," },
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"gateway\":\"192.0.2.254\","
		    "\"vrf\":3,\"routing\":{\"bgp\":{\"family\":\"ipv4\",\"as\":"
		    "65000,\"neighbors\":[\"192.0.2.254\"],\"password\":\"up\"}}" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
		/* gif: geneve's address needs an interface the kernel has. */
		{ "\"kind\":\"geneve\"", "\"kind\":\"gif\"" },
	};
	/* b-mpls addressed by DHCP (Mplify 119 §12.2.3.2): its address is
	 * not in the document but learned from the host, so it is an
	 * interface of this host with an IPv4 address, whichever that is;
	 * a host without one keeps the address in the document. */
	if (host_iface(lifn, sizeof(lifn), laddr, sizeof(laddr)))
		snprintf(t2, sizeof(t2), "\"id\":\"b-mpls\",\"ucs\":\"mpls\","
		    "\"interface\":\"%s\",\"addressing\":\"dhcp\"", lifn);
	else {
		snprintf(laddr, sizeof(laddr), "10.99.0.2");
		snprintf(t2, sizeof(t2), "\"id\":\"b-mpls\",\"ucs\":\"mpls\","
		    "\"interface\":\"vtnet1\",\"address\":\"10.99.0.2\"");
	}
	ATF_REQUIRE(swap_in(doc, "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":"
	    "\"vtnet1\"", t2, t1, sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)));
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);

	/*
	 * The plan: two tunnels, over the Internet (gre under IPsec) and
	 * over the MPLS (geneve), each a unit of its own and a /31 of the
	 * reserved prefix; nothing made yet.
	 */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_EQ_MSG(3, (int)ucl_array_size(ucl_object_lookup(r.json,
	    "tunnels")), "%s", r.body);
	/* The third is the control plane's own, over inet, after the data
	 * tunnels: gre again, marked control, addresses after theirs. */
	ATF_CHECK_STREQ("acme/a-inet-b-inet/ctvc", jstr(&r, "tunnels.2.id"));
	ATF_CHECK_STREQ("true", jstr(&r, "tunnels.2.control"));
	ATF_CHECK_STREQ("gre104", jstr(&r, "tunnels.2.ends.0.ifname"));
	ATF_CHECK_STREQ("100.64.0.4", jstr(&r, "tunnels.2.ends.0.inner4"));
	ATF_CHECK_STREQ("100.64.0.5", jstr(&r, "tunnels.2.ends.1.inner4"));
	ATF_CHECK_STREQ("gre", jstr(&r, "tunnels.0.kind"));
	ATF_CHECK_STREQ("true", jstr(&r, "tunnels.0.ipsec"));
	ATF_CHECK_STREQ("gre100", jstr(&r, "tunnels.0.ends.0.ifname"));
	ATF_CHECK_STREQ("gre101", jstr(&r, "tunnels.0.ends.1.ifname"));
	ATF_CHECK_STREQ("100.64.0.0", jstr(&r, "tunnels.0.ends.0.inner4"));
	ATF_CHECK_STREQ("100.64.0.1", jstr(&r, "tunnels.0.ends.1.inner4"));
	ATF_CHECK_STREQ("gif", jstr(&r, "tunnels.1.kind"));
	ATF_CHECK_STREQ("false", jstr(&r, "tunnels.1.ipsec"));
	ATF_CHECK_STREQ("true", jstr(&r, "tunnels.1.backup"));
	ATF_CHECK_STREQ("100.64.0.2", jstr(&r, "tunnels.1.ends.0.inner4"));
	ATF_CHECK_EQ(0, changes_of(&r, "keep"));
	ATF_CHECK(changes_of(&r, "make") > 10);
	ATF_CHECK(strstr(r.body, "\"key\":\"uni:branch\"") != NULL);
	/* Each edge measures its tunnels: the far inner address, through
	 * the service's table, as the service's probe settings say. */
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"sdwan-probes\",\"targets\":[{"
	    "\"id\":\"acme/a-inet-b-inet\",\"address\":\"100.64.0.1\",\"fib\":1,"
	    "\"eval\":1000,\"tca\":{\"delay\":30,\"loss\":0.050000,\"damping\":2}}")
	    != NULL, "%s", r.body);
	/* The rules: the UNI's packets to their zone's block, each flow
	 * with its policy's table, the rest dropped; and the steering. */
	ATF_CHECK_MSG(strstr(r.body, "\"10 skipto tablearg ip from table("
	    "sw1_zone) to any in recv lo0\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"10 deny ip from any to any ipoptions "
	    "lsrr,ssrr,rr in recv lo0\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"11 skipto 99 ip from any to any\"") != NULL);
	/* The office zone (block 12): web, tcp to 80 and https, by policy
	 * fast (the first policy, 0) in IPv4 and IPv6 tables; voice, sip,
	 * dropped (no policy); all, by hubonly (policy 1). */
	ATF_CHECK_MSG(strstr(r.body, "\"12 fwd tablearg tcp from any to table("
	    "sw1_z0p0_4) dst-port 80,https\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"12 fwd tablearg tcp from any to table("
	    "sw1_z0p0_6) dst-port 80,https\"") != NULL);
	/* Then what the flow may do beyond the tunnels: the hosts of the
	 * edge's own UNI (queued, as fast has bandwidth), the Internet by
	 * breakout (fast enables it; not known is the Internet), and
	 * nothing else; a flow with no bandwidth is let through. */
	/* Two end points on the edge, the UNI and the remote: each rule
	 * of the block names the interface it is for. */
	ATF_CHECK_MSG(strstr(r.body, "\"12 queue 3001 tcp from any to "
	    "10.1.0.0/24,10.1.8.0/22 dst-port 80,https in recv lo0\"") != NULL,
	    "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"12 queue 3001 tcp from any to not table("
	    "sw1_known) dst-port 80,https\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"12 deny tcp from any to any dst-port "
	    "80,https\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"12 allow ip4 from any to 10.1.0.0/24,"
	    "10.1.8.0/22 in recv lo0\"") != NULL);
	ATF_CHECK(strstr(r.body, "[\"10.1.8.0/22\",\"0\"],[\"2001:db8:1::/64\","
	    "\"0\"]") != NULL);
	/* Its bandwidth: the shared limiter a pipe of its limit, the flow
	 * a queue in it, weighted by its commit and importance (high),
	 * on the way out by the tunnels. */
	ATF_CHECK(strstr(r.body, "\"pipe 3000 config bw 5000000bit/s\"") !=
	    NULL);
	ATF_CHECK(strstr(r.body, "\"queue 3001 config pipe 3000 weight 100\"")
	    != NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"11 queue 3001 tcp from any to any "
	    "dst-port 80,https src-ip table(sw1_zp0) out { xmit gre100 or xmit "
	    "gif102 }\"") != NULL, "%s", r.body);
	/* Egress: quiet discards all of the office zone leaving by hq's
	 * UNI. */
	ATF_CHECK(strstr(r.body, "\"11 deny ip from any to any src-ip table("
	    "sw1_zp0) out xmit lo0\"") != NULL);
	/* The security policy guard, named by fast (MEF 88): before the
	 * forward, web to or from a denied prefix dropped and logged, the
	 * allowed prefixes excepted, by tables of the policy's own; its
	 * rate limit a pipe of its own on the way out by the tunnels. */
	ATF_CHECK_MSG(strstr(r.body, "\"12 deny log logdst rtsock logamount 1000 "
	    "tcp from any to table(sw1_s0d4) dst-port 80,https not dst-ip table("
	    "sw1_s0a4) // security acme guard dst\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"12 deny log logdst rtsock logamount 1000 tcp "
	    "from any to any dst-port 80,https src-ip table(sw1_s0d4) not src-ip "
	    "table(sw1_s0a4) // security acme guard src\"") != NULL);
	/* With the lists' prefixes after the policy's own, the domains of
	 * both in the DNS filter. */
	ATF_CHECK_MSG(strstr(r.body, "\"name\":\"sw1_s0d4\",\"valtype\":\"legacy\","
	    "\"entries\":[[\"192.0.2.0/24\",\"0\"],[\"198.51.100.0/24\",\"0\"],"
	    "[\"203.0.113.0/24\",\"0\"]]") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\\tlocal-zone: \\\"bad-feed.example.\\\" "
	    "always_nxdomain\\n\\tlocal-zone: \\\"bad.example.\\\" always_nxdomain"
	    "\\n") != NULL);
	ATF_CHECK(strstr(r.body, "\"name\":\"sw1_s0a4\",\"valtype\":\"legacy\","
	    "\"entries\":[[\"10.1.0.0/16\",\"0\"]]") != NULL);
	ATF_CHECK(strstr(r.body, "sw1_s0d6") == NULL);
	ATF_CHECK(strstr(r.body, "\"pipe 3002 config bw 2000000bit/s\"") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"11 pipe 3002 tcp from any to any "
	    "dst-port 80,https src-ip table(sw1_zp0) out { xmit gre100 or xmit "
	    "gif102 }\"") != NULL, "%s", r.body);
	/* Its DNS: an unbound instance of the service at a, on hq's
	 * provider address, the denied domain a local zone; every query
	 * from the UNI forwarded to it (dns-protocol-filter). */
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"dns\",\"phase\":10,\"title\":"
	    "\"DNS filters: unbound, 1 instance in the services' tables, the "
	    "domains the security policies deny\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"kind\":\"sdwan-dns\",\"instances\":[{\"name\":"
	    "\"sw1\",\"fib\":1,\"conf\":\"# Written by the Arcana console: SD-WAN "
	    "service acme at a, in routing table 1.") != NULL);
	ATF_CHECK(strstr(r.body, "\\tinterface: 10.1.0.1\\n\\taccess-control: "
	    "10.1.0.0/24 allow\\n") != NULL);
	ATF_CHECK(strstr(r.body, "\\tlocal-zone: \\\"ads.example.\\\" "
	    "always_nxdomain\\n") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"10 fwd 10.1.0.1,53 udp from any to any "
	    "dst-port 53 in recv lo0\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"10 fwd 10.1.0.1,53 tcp from any to any "
	    "dst-port 53 in recv lo0\"") != NULL);
	/* Breakout at a, by a-inet: the NAT of hq's public prefix, out by
	 * vtnet0 and back in to the service's table; the default route
	 * by the gateway, reached by the interface.  At b, by a tunnel to
	 * a. */
	ATF_CHECK(strstr(r.body, "\"nat 3001 config ip 198.51.100.1\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"11 nat 3001 ip4 from table(sw1_known) to "
	    "not table(sw1_known) out xmit vtnet0\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"11 setfib 2 ip from any to 198.51.100.1 in "
	    "recv vtnet0\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"11 nat 3001 ip4 from any to 198.51.100.1 in "
	    "recv vtnet0\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"11 setfib 2 ip from any to table(sw1_known) "
	    "in recv vtnet0\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"key\":\"route:acme:2:192.0.2.254/32\"") !=
	    NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"title\":\"0.0.0.0/0 via 192.0.2.254, "
	    "fib 2 (the Internet, by local breakout)\"") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"title\":\"0.0.0.0/0 via 100.64.0.0, fib "
	    "2 (the Internet, by breakout at a)\"") != NULL, "%s", r.body);
	/* The breakout domain (Mplify 119 R20-R26): the UNIs' routes in
	 * its table, the flows that break out sent to it, the way back in
	 * by it; the service's own table without a default route. */
	ATF_CHECK_MSG(strstr(r.body, "/24 via lo0, fib 2 (the UNI's hosts, in the "
	    "breakout domain (R25))\"") != NULL || strstr(r.body, "/24 via vtnet2, "
	    "fib 2 (the UNI's hosts, in the breakout domain (R25))\"") != NULL,
	    "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"10.1.8.0/22 via 10.1.0.2, fib 2 (behind the "
	    "UNI, in the breakout domain (R26))\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"12 setfib 2 tcp from any to not table("
	    "sw1_known) dst-port 80,https\"") != NULL);
	ATF_CHECK(strstr(r.body, "setfib 2 ip from any to table(sw1_known) in "
	    "recv vtnet0") != NULL);
	ATF_CHECK(strstr(r.body, "\"100.64.0.0/32 via gre101, fib 2 (the tunnel's "
	    "far end, in the breakout domain)\"") != NULL);
	ATF_CHECK(strstr(r.body, "0.0.0.0/0 via 192.0.2.254, fib 1 (") == NULL);
	/* The UCS end points (Mplify 119 §12.2.3): b-mpls addressed by
	 * DHCP, its address learned from the host (the helper says
	 * epair1b has 10.99.0.2), so the geneve tunnel still has its far
	 * end; a-inet in its own table, the gre tunnel's outer packets by
	 * it, BGP with the underlay by a BIRD instance of its own. */
	if (lifn[0] != '\0') {
		snprintf(t2, sizeof(t2), "\"kind\":\"if-set\",\"interface\":\"%s\","
		    "\"persist\":true,\"addressing\":\"dhcp\"", lifn);
		ATF_CHECK_MSG(strstr(r.body, "\"key\":\"ucs:b-mpls\"") != NULL &&
		    strstr(r.body, t2) != NULL, "%s", r.body);
	}
	snprintf(t2, sizeof(t2), "\"tunnel_remote\":\"%s\"", laddr);
	ATF_CHECK_MSG(strstr(r.body, t2) != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"if-set\",\"interface\":\"vtnet0\","
	    "\"persist\":true,\"fib\":3") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"tunnel_remote\":\"192.0.2.2\",\"tunnelfib\":3")
	    != NULL);
	ATF_CHECK_MSG(strstr(r.body, "{\"name\":\"ucs3\",\"fib\":3,\"conf\":\"# "
	    "Written by the Arcana console: UCS end point a-inet at a, routing "
	    "with the underlay in table 3.") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "protocol bgp ucs_a_inet_0 {\\n\\tlocal as 64512;"
	    "\\n\\tneighbor 192.0.2.254 as 65000;\\n\\tinterface \\\"vtnet0\\\";")
	    != NULL);
	/* Routing: a BIRD instance of the service on each edge, in its
	 * table, iBGP between them by each tunnel, and at hq's UNI BGP
	 * with the subscriber as the entry says. */
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"sdwan-bird\",\"instances\":[{"
	    "\"name\":\"sw1\",\"fib\":1,\"conf\":\"# Written by the Arcana "
	    "console: SD-WAN service acme at a, in routing table 1.") != NULL,
	    "%s", r.body);
	ATF_CHECK(strstr(r.body, "router id 100.64.0.0;") != NULL);
	ATF_CHECK(strstr(r.body, "kernel table 1;\\n\\tlearn;\\n\\tpersist;") !=
	    NULL);
	ATF_CHECK_MSG(strstr(r.body, "protocol direct {\\n\\tipv4;\\n\\tipv6;\\n"
	    "\\tinterface \\\"lo0\\\", \\\"gre100\\\", \\\"gif102\\\", \\\"gre104\\\";"
	    "\\n}") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "&& dest = RTD_UNICAST;") != NULL);
	ATF_CHECK(strstr(r.body, "import filter { preference = 200; accept; };") !=
	    NULL);
	ATF_CHECK_MSG(strstr(r.body, "filter to_edges {\\n\\tif source = RTS_INHERIT "
	    "then reject;\\n\\tif net ~ [ 100.64.0.0/24+, 100.64.0.0/24+ ] then reject;"
	    "\\n\\taccept;"
	    "\\n}") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "export filter to_edges;") != NULL);
	/* The hosts' addresses: hq's IPv4 by DHCP, dnsmasq (a plugin,
	 * installed before and never by the apply) in the service's table,
	 * its ranges the subnet less the reserved prefixes and the
	 * provider's address, the router and DNS told; branch's IPv6 by
	 * SLAAC, rtadvd on the VLAN with RDNSS; the kernel forwarding on
	 * both edges.  What the edges need is listed, each there or not. */
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"pkg-install\"") == NULL,
	    "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"plugin\":\"dnsmasq\",\"package\":"
	    "\"dnsmasq\"") != NULL && strstr(r.body, "\"plugin\":\"squid\"")
	    != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"sdwan-dhcp\",\"instances\":[{"
	    "\"name\":\"sw1\",\"fib\":1,\"conf\":\"# Written by the Arcana "
	    "console: SD-WAN service acme at a, in routing table 1.") != NULL,
	    "%s", r.body);
	/* The UNI is lo0 here (swapped in for the apply). */
	ATF_CHECK_MSG(strstr(r.body, "interface=lo0\\ndhcp-range=set:lo0,"
	    "10.1.0.64,10.1.0.199,255.255.255.0,1h\\ndhcp-range=set:lo0,"
	    "10.1.0.204,10.1.0.254,255.255.255.0,1h\\ndhcp-option=tag:lo0,"
	    "option:router,10.1.0.1\\ndhcp-option=tag:lo0,option:dns-server,"
	    "10.1.0.1\\n") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"rtadvd\",\"interface\":\"vlan")
	    != NULL && strstr(r.body, "\"args\":[\"2001:db8:1::/64\",\"2001:db8:1::1"
	    "\"],\"persist\":true") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"kind\":\"sysctl\",\"args\":[\"net.inet6.ip6."
	    "forwarding\",\"1\"]") != NULL);
	/* The iBGP by the control tunnel alone: the host a reflector, b its
	 * client and nothing else; no session by the data tunnels. */
	ATF_CHECK_MSG(strstr(r.body, "# acme/a-inet-b-inet/ctvc, to b, a client of "
	    "this reflector\\nprotocol bgp edge0 from edge {\\n\\tlocal 100.64.0.4 "
	    "as 64600;\\n\\tneighbor 100.64.0.5 as 64600;\\n\\trr client;\\n\\trr "
	    "cluster id 192.0.2.1;\\n}") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "# acme/a-inet-b-inet/ctvc, to a, the control "
	    "plane\\nprotocol bgp edge0 from edge {\\n\\tlocal 100.64.0.5 as "
	    "64600;\\n\\tneighbor 100.64.0.4 as 64600;\\n}") != NULL, "%s",
	    r.body);
	ATF_CHECK(strstr(r.body, "# acme/a-inet-b-inet, to") == NULL);
	ATF_CHECK(strstr(r.body, "protocol bgp edge1 from edge") == NULL);
	/* BFD on the edge's tunnel interfaces, the iBGP sessions by it. */
	ATF_CHECK_MSG(strstr(r.body, "protocol bfd {\\n\\tinterface \\\"gre100\\\", "
	    "\\\"gif102\\\", \\\"gre104\\\" {\\n\\t\\tinterval 200 ms;\\n\\t\\tmultiplier "
	    "3;\\n\\t};\\n}") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "hold time 30;\\n\\terror wait time 10, 60;\\n\\tbfd "
	    "on;\\n\\tpassword \\\"edges-secret\\\";\\n") != NULL);
	/* NTP at a, with the FIBs, by the ntp job; taken away by it too. */
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"ntp\",\"phase\":1,\"title\":\"NTP: "
	    "ntpd by 2 servers, for the time faults and keys go by\",\"make\":[{"
	    "\"kind\":\"ntp\",\"args\":[\"ntp.example.org\",\"10.99.0.9\"],"
	    "\"persist\":true}]") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "protocol bgp uni_hq_0 {\\n\\tlocal as "
	    "64600;\\n\\tneighbor 10.1.0.2 as 65010;\\n\\tinterface \\\"lo0\\\";"
	    "\\n\\tpreference 106;\\n\\tpassword \\\"s3cret\\\";\\n\\thold time "
	    "90;\\n\\tipv4 {\\n\\t\\timport all;\\n\\t\\texport filter {\\n\\t\\t"
	    "\\tbgp_community.add((64600, 100));\\n\\t\\t\\taccept;\\n\\t\\t};"
	    "\\n\\t};\\n}") != NULL, "%s", r.body);
	/* b has no routing at its UNI, but the service's instance all the
	 * same: what hq learns reaches it. */
	ATF_CHECK(strstr(r.body, "SD-WAN service acme at b, in routing table 1.")
	    != NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"12 deny ip from any to any { src-port "
	    "5060,5061 or dst-port 5060,5061 } dscp 46\"") != NULL, "%s",
	    r.body);
	ATF_CHECK(strstr(r.body, "\"12 fwd tablearg ip4 from any to table("
	    "sw1_z0p1_4) in recv lo0\"") != NULL);
	/* The remote's identities get the zone's own policies, having no
	 * map of their own: the block's rules for wg5. */
	ATF_CHECK(strstr(r.body, "\"12 fwd tablearg tcp from any to table("
	    "sw1_z0p0_4) dst-port 80,https in recv wg5\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"11 deny ip from any to any in recv wg5\"")
	    != NULL);
	ATF_CHECK(strstr(r.body, "\"12 deny ip from any to any\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"99 count ip from any to any\"") != NULL);
	ATF_CHECK(strstr(r.body, "[\"10.1.0.0/16\",\"12\"]") != NULL);
	ATF_CHECK(strstr(r.body, "[\"0.0.0.0/0\",\"13\"]") != NULL);
	/* hq's branch is a leaf of the hub topology: hubonly reaches it,
	 * over the private tunnel first, the public one after. */
	ATF_CHECK_MSG(strstr(r.body, "\"table\":\"sw1_z1p1_6\",\"prefix\":"
	    "\"2001:db8:1::/64\"") == NULL, "%s", r.body);
	/* A remote end point (SASE-3): wg5 in the service's table with the
	 * prefix's first host, listening; the identity a peer allowed its
	 * address, the second host, which the zone table sends to its
	 * zone's block, and its packets in by wg5 as a UNI's. */
	ATF_CHECK_MSG(strstr(r.body, "{\"kind\":\"if-create\",\"interface\":"
	    "\"wg5\",\"fib\":1,\"description\":\"sdwan\",\"address\":"
	    "\"10.30.0.1/24\",\"persist\":true}") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "{\"kind\":\"wireguard\",\"verb\":\"init\","
	    "\"interface\":\"wg5\",\"listen_port\":51820,\"persist\":true}") !=
	    NULL);
	ATF_CHECK(strstr(r.body, "{\"kind\":\"wireguard\",\"verb\":\"peer\","
	    "\"interface\":\"wg5\",\"peer\":"
	    "\"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\",\"allowed_ips\":"
	    "\"10.30.0.2/32\",\"persist\":true}") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "[\"10.30.0.2/32\",\"12\"]") != NULL, "%s",
	    r.body);
	ATF_CHECK(strstr(r.body, "\"10 skipto tablearg ip from table(sw1_zone) "
	    "to any in recv wg5\"") != NULL);
	/* The URL filter (SASE-4): HTTP and TLS from the end points forwarded
	 * to Squid on the edge's own addresses, its instance in the plan
	 * with the TLS names looked at and the domain denied. */
	ATF_CHECK(strstr(r.body, "\"10 fwd 10.1.0.1,3128 tcp from any to any "
	    "dst-port 80 in recv lo0\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"10 fwd 10.30.0.1,3129 tcp from any to any "
	    "dst-port 443 in recv wg5\"") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "{\"kind\":\"sdwan-proxy\",\"instances\":[{"
	    "\"name\":\"sw1\",\"fib\":1,\"mode\":\"sni\",\"conf\":\"# Written by "
	    "the Arcana console") != NULL && strstr(r.body, "https_port "
	    "10.1.0.1:3129 intercept ssl-bump tls-cert=@CA@") != NULL && strstr(
	    r.body, "ssl_bump terminate denied_site\\nssl_bump splice all") !=
	    NULL && strstr(r.body, "\"deny\":\".bad.example\\n\"") != NULL, "%s",
	    r.body);
	/* Malware (MEF 88): what comes back goes to c-icap by ICAP, on the
	 * edge's own address in the service at the service's port, which
	 * takes Squid's address alone; c-icap scans with ClamAV. */
	ATF_CHECK_MSG(strstr(r.body, "icap_service sdwan_av respmod_precache "
	    "bypass=off icap://10.1.0.1:1354/avscan") != NULL && strstr(r.body,
	    "\"icap\":\"# Written by the Arcana console") != NULL && strstr(
	    r.body, "Service avscan virus_scan.so") != NULL && strstr(r.body,
	    "Port 10.1.0.1:1354\\nacl squid src 10.1.0.1/255.255.255.255") !=
	    NULL && strstr(r.body, "client_access deny all") != NULL && strstr(
	    r.body, "\"plugin\":"
	    "\"c-icap\",\"package\":\"c-icap c-icap-modules clamav\"") !=
	    NULL, "%s", r.body);
	/* Intrusion detection (MEF 88): Suricata on the service's UNIs at
	 * each edge, its home the UNIs' subnets, the policy's rules and the
	 * ruleset suricata-update keeps; Suricata a need. */
	ATF_CHECK_MSG(strstr(r.body, "{\"kind\":\"sdwan-ids\",\"instances\":[{"
	    "\"name\":\"sw1\",\"interfaces\":[\"") != NULL && strstr(r.body,
	    "default-log-dir: @LOGDIR@") != NULL && strstr(r.body,
	    "HOME_NET: \\\"[10.1.0.0/24") != NULL && strstr(r.body,
	    "  - @RULES@\\n  - /var/lib/suricata/rules/suricata.rules") != NULL &&
	    strstr(r.body, "\"rules\":\"alert http any any -> $HOME_NET any "
	    "(msg:\\\"x\\\"; sid:1000001; rev:1;)\\n\"") != NULL && strstr(
	    r.body, "\"plugin\":\"suricata\",\"package\":\"suricata\"") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/* The record: the edges' logged packets read now; none yet. */
	http("GET", "/api/sdwan/record?swvc=acme&policy=guard", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"record\":[]") != NULL, "%s", r.body);
	resp_free(&r);
	http("GET", "/api/sdwan/record.csv", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strncmp(r.body, "time,edge,rule,action,source,destination,"
	    "interface,comment\n", 60) == 0, "%s", r.body);
	resp_free(&r);

	/* Applied: each made, in the order, IPsec with the far key. */
	/* An edge without what a service needs there: nothing is
	 * installed by the apply, which refuses and says what to install
	 * where.  Squid back, it goes on. */
	ATF_REQUIRE(rename("tools/squid", "tools/squid.off") == 0);
	http("POST", "/api/sdwan/apply", "{}", &r);
	EXPECT(&r, 409);
	ATF_CHECK_MSG(strstr(r.body, "pkg install squid") != NULL &&
	    strstr(r.body, "nothing is installed by the apply") != NULL, "%s",
	    r.body);
	resp_free(&r);
	ATF_REQUIRE(rename("tools/squid.off", "tools/squid") == 0);
	http("POST", "/api/sdwan/apply", "{}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	/* Into the history: this one, done, with what it made. */
	ATF_CHECK_MSG(jstr(&r, "history.0.state") != NULL && strcmp(jstr(&r,
	    "history.0.state"), "done") == 0 && jstr(&r, "history.0.made") !=
	    NULL && atoi(jstr(&r, "history.0.made")) > 10 && jstr(&r,
	    "history.1.state") == NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^gre100 create' ifconfig.log") == 0);
	ATF_CHECK(system("grep -q '^gre100 fib 1' ifconfig.log") == 0);
	ATF_CHECK(system("grep -q '^gre100 tunnel 192.0.2.1 192.0.2.2' "
	    "ifconfig.log") == 0);
	ATF_CHECK(system("grep -q '^gre101 tunnel 192.0.2.2 192.0.2.1' "
	    "ifconfig.log") == 0);
	ATF_CHECK(system("grep -q '^gre100 inet 100.64.0.0/31 100.64.0.1' "
	    "ifconfig.log") == 0);
	snprintf(t2, sizeof(t2), "grep -q '^gif102 tunnel 10.99.0.1 %s' "
	    "ifconfig.log", laddr);
	ATF_CHECK_MSG(system(t2) == 0, "%s", t2);
	ATF_CHECK(system("grep -q '^lo0 fib 1' ifconfig.log") == 0);
	ATF_CHECK(system("grep -q 'vlan106 create vlan 20 vlandev lo0' "
	    "ifconfig.log") == 0);
	/* The proxy, by the stand-ins: parsed, started in the table. */
	ATF_CHECK(system("grep -q '^squid -k parse -f .*sdwan-proxy-sw1.conf' "
	    "squid.log && grep -q '^setfib -F 1 .*tools/squid -f .*sdwan-proxy-"
	    "sw1.conf' setfib.log") == 0);
	/* Its scanner, c-icap, started in the table before it. */
	ATF_CHECK(system("grep -q '^setfib -F 1 .*tools/c-icap -f .*sdwan-icap-"
	    "sw1.conf' setfib.log") == 0);
	/* Identities (SASE-3): one issued for a name, its key pair made
	 * here, the configuration answered once with its address, the
	 * second host after alice's, and the edges applied; listed with
	 * both; revoked, gone and the peer removed; alice past the
	 * remote's re-authorisation has no peer. */
	http("POST", "/api/sdwan/identities", "{\"swvc\":\"acme\",\"end_point\":"
	    "\"road\",\"name\":\"bob\",\"zone\":\"office\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "name"));
	ATF_CHECK_MSG(jstr(&r, "config") != NULL && strstr(jstr(&r, "config"),
	    "[Interface]\nPrivateKey = ") != NULL && strstr(jstr(&r, "config"),
	    "\nAddress = 10.30.0.3/24\n") != NULL && strstr(jstr(&r, "config"),
	    "\n[Peer]\nPublicKey = ") != NULL && strstr(jstr(&r, "config"),
	    "\nEndpoint = 192.0.2.1:51820\n") != NULL && strstr(jstr(&r,
	    "config"), "AllowedIPs = 10.1.0.0/24, 10.1.8.0/22, 2001:db8:1::/64, "
	    "10.30.0.0/24\n") != NULL, "%s", r.body);
	ATF_CHECK_STREQ("true", jstr(&r, "applied"));
	ATF_CHECK(strlen(jstr(&r, "public_key")) == 44);
	resp_free(&r);
	sdwan_wait(&r);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^set wg5 peer .* allowed-ips 10.30.0.3/32' "
	    "wg.log") == 0);
	http("GET", "/api/sdwan/identities", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("alice", jstr(&r, "identities.0.name"));
	ATF_CHECK_STREQ("10.30.0.2", jstr(&r, "identities.0.address"));
	ATF_CHECK_STREQ("true", jstr(&r, "identities.0.live"));
	ATF_CHECK_STREQ("bob", jstr(&r, "identities.1.name"));
	ATF_CHECK_STREQ("10.30.0.3", jstr(&r, "identities.1.address"));
	ATF_CHECK_STREQ("false", jstr(&r, "identities.1.user"));
	/* Its session, as the edge's wg tells its peer (S3.4): the stand-in
	 * keeps the last peer set on an interface. */
	ATF_CHECK_MSG(jstr(&r, "identities.1.session.endpoint") != NULL &&
	    strcmp(jstr(&r, "identities.1.session.endpoint"), "192.0.2.9:51820")
	    == 0 && jstr(&r, "identities.1.session.rx") != NULL, "%s", r.body);
	resp_free(&r);
	/* A console user: a sign-in key of the name, or none. */
	http("POST", "/api/sdwan/identities", "{\"swvc\":\"acme\",\"end_point\":"
	    "\"road\",\"name\":\"nobody\",\"zone\":\"office\",\"user\":true}",
	    &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("DELETE", "/api/sdwan/identities?swvc=acme&end_point=road&name=bob",
	    NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "revoked"));
	resp_free(&r);
	sdwan_wait(&r);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^set wg5 peer .* remove' wg.log") == 0);
	http("GET", "/api/sdwan/identities", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "identities.1.name") == NULL);
	resp_free(&r);
	http("DELETE", "/api/sdwan/identities?swvc=acme&end_point=road&name=bob",
	    NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* The remote end point's wg, by the stand-in: listening, the
	 * identity its peer. */
	ATF_CHECK(system("grep -q '^set wg5 listen-port 51820' wg.log && grep "
	    "-q '^set wg5 peer xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg= "
	    "allowed-ips 10.30.0.2/32' wg.log") == 0);
	/* One IPsec connection for the pair of outer addresses and kind. */
	ATF_CHECK(system("ls swanctl/conf.d/arcana-sdw*.conf | wc -l | grep -q "
	    "'^ *2$'") == 0);
	ATF_CHECK(system("grep -q 'mode = transport' "
	    "swanctl/conf.d/arcana-sdw*.conf") == 0);
	ATF_CHECK(system("grep -q 'dynamic\\[gre\\]' "
	    "swanctl/conf.d/arcana-sdw*.conf") == 0);
	/* The agent probes them from now on (without root, it says so),
	 * and holds the rules in set 30 and their tables. */
	snprintf(body, sizeof(body), "/api/servers/%s/sdwan", sa);
	http("GET", body, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"id\":\"acme/a-inet-b-inet\"") != NULL &&
	    strstr(r.body, "\"id\":\"acme/a-mpls-b-mpls\"") != NULL, "%s",
	    r.body);
	ATF_CHECK(jstr(&r, "data.targets.0.state") != NULL);
	ATF_CHECK_MSG(jstr(&r, "data.rules.set") != NULL && strcmp(jstr(&r,
	    "data.rules.set"), "30") == 0, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^setfib -F 1 ./fake-local-unbound -c .*sdwan-dns-"
	    "sw1.conf' setfib.log && grep -q '^checkconf .*sdwan-dns-sw1.conf' "
	    "unbound.log") == 0);
	ATF_CHECK(system("grep -q '^setfib -F 1 ./fake-dnsmasq -C .*sdwan-dhcp-sw1"
	    ".conf -x ' setfib.log") == 0);
	ATF_CHECK(system("grep -q 'addr=\"2001:db8:1::\":prefixlen#64:rdnss=\""
	    "2001:db8:1::1\":' rtadvd.conf && grep -q '^vlan[0-9]*:' rtadvd.conf "
	    "&& grep -q '^rtadvd_enable=\"YES\"' rc.conf") == 0);
	ATF_CHECK(system("grep -q '^setfib -F 1 .*fake-bird -c .*sdwan-bird-sw1"
	    ".conf -s ' setfib.log") == 0);
	ATF_CHECK(system("grep -q '^server ntp.example.org iburst$' ntp.conf && "
	    "grep -q '^server 10.99.0.9 iburst$' ntp.conf && grep -q "
	    "'^ntpd_enable=\"YES\"' rc.conf") == 0);
	ATF_CHECK(system("grep -q 'add 12 set 30 fwd tablearg tcp from any to "
	    "table(sw1_z0p0_4) dst-port 80,https' ipfw.log") == 0);
	ATF_CHECK(system("grep -q 'ipfw -q set enable 30' ipfw.log") == 0);
	/* The manager: on its first tick it sends each edge its steering,
	 * and says what it sent; branch's web flows reach hq's prefixes by
	 * the encrypted public tunnel (the private one is a backup). */
	for (i = 0; i < 60; i++) {
		http("GET", "/api/sdwan/steer", NULL, &r);
		EXPECT(&r, 200);
		snprintf(body, sizeof(body), "sent.%s.entries.0.prefix", sb);
		if (jstr(&r, body) != NULL)
			break;
		resp_free(&r);
		usleep(300000);
	}
	ATF_REQUIRE_MSG(i < 60, "the manager sent nothing");
	ATF_CHECK_STREQ("10.1.0.0/24", jstr(&r, body));
	snprintf(body, sizeof(body), "sent.%s.entries.0.candidates.0.id", sb);
	ATF_CHECK_STREQ("acme/a-inet-b-inet", jstr(&r, body));
	snprintf(body, sizeof(body), "sent.%s.entries.0.policy", sb);
	ATF_CHECK_STREQ("fast", jstr(&r, body));
	resp_free(&r);
	/* Again: nothing to do. */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_EQ(0, changes_of(&r, "make") + changes_of(&r, "remake") +
	    changes_of(&r, "unmake"));
	resp_free(&r);

	/* The MPLS no longer the service's: its tunnel taken away. */
	ATF_REQUIRE(swap_in(doc, "\"ucs\":[\"inet\",\"mpls\"]",
	    "\"ucs\":[\"inet\"]", t1, sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	ATF_REQUIRE(swap_in(doc, "\"version\":0", "\"version\":3", t1,
	    sizeof(t1)));
	http("PUT", "/api/sdwan", t1, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_EQ(2, changes_of(&r, "unmake"));
	ATF_CHECK_EQ(2, (int)ucl_array_size(ucl_object_lookup(r.json,
	    "tunnels")));
	resp_free(&r);
	http("POST", "/api/sdwan/apply", "{}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^gif102 destroy' ifconfig.log") == 0);
	ATF_CHECK(system("grep -q '^gif103 destroy' ifconfig.log") == 0);
	ATF_CHECK(system("! grep -q '\"units\":\\[102' data/sdwan-state.json") ==
	    0);

	/* A policy that requires encryption always: the private tunnel
	 * is under IPsec too; a UCS that says no IPsec cannot be. */
	ATF_REQUIRE(swap_in(doc, "\"encryption\":\"required-public-only\"",
	    "\"encryption\":\"required-always\"", t1, sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	ATF_REQUIRE(swap_in(doc, "\"version\":0", "\"version\":4", t1,
	    sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"ucs\":[\"inet\"]",
	    "\"ucs\":[\"inet\",\"mpls\"]", doc, sizeof(doc)));
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "tunnels.1.ipsec"));
	ATF_CHECK_STREQ("gif", jstr(&r, "tunnels.1.kind"));
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"kind\":\"gif\"",
	    "\"kind\":\"gif\",\"ipsec\":false", t1, sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":4", "\"version\":5", doc,
	    sizeof(doc)));
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/plan", NULL, &r);
	ATF_CHECK_MSG(r.status == 409 && strstr(r.body, "(R39)") != NULL, "%s",
	    r.body);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"kind\":\"gif\",\"ipsec\":false",
	    "\"kind\":\"gif\"", t1, sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"encryption\":\"required-always\"",
	    "\"encryption\":\"required-public-only\"", doc, sizeof(doc)));
	ATF_REQUIRE(swap_in(doc, "\"version\":5", "\"version\":6", t1,
	    sizeof(t1)));
	http("PUT", "/api/sdwan", t1, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* An IPv6 UNI with no IPv6 inner addresses: the plan says so. */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"notes\":[\"swvc acme: no tunnel from a "
	    "to b carries 2001:db8:1::/64") != NULL, "%s", r.body);
	resp_free(&r);
	/* A geneve tunnel: one VNI at both ends, its table after it. */
	ATF_REQUIRE(swap_in(doc, "\"kind\":\"gif\"", "\"kind\":\"geneve\"",
	    t1, sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	ATF_REQUIRE(swap_in(doc, "\"version\":5", "\"version\":7", t1,
	    sizeof(t1)));
	http("PUT", "/api/sdwan", t1, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	snprintf(t2, sizeof(t2), "\"args\":[\"mode\",\"l3\",\"id\",\"102\","
	    "\"local\",\"10.99.0.1\",\"remote\",\"%s\"]", laddr);
	ATF_CHECK_MSG(strstr(r.body, t2) != NULL, "%s", r.body);
	snprintf(t2, sizeof(t2), "\"args\":[\"mode\",\"l3\",\"id\",\"102\","
	    "\"local\",\"%s\",\"remote\",\"10.99.0.1\"]", laddr);
	ATF_CHECK_MSG(strstr(r.body, t2) != NULL, "%s", r.body);
	resp_free(&r);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, unauthenticated);
	ATF_TP_ADD_TC(tp, setup_token);
	ATF_TP_ADD_TC(tp, register_login);
	ATF_TP_ADD_TC(tp, login_refused);
	ATF_TP_ADD_TC(tp, android);
	ATF_TP_ADD_TC(tp, android_none);
	ATF_TP_ADD_TC(tp, second_key);
	ATF_TP_ADD_TC(tp, csrf);
	ATF_TP_ADD_TC(tp, jails);
	ATF_TP_ADD_TC(tp, services);
	ATF_TP_ADD_TC(tp, agent_update);
	ATF_TP_ADD_TC(tp, agent_build);
	ATF_TP_ADD_TC(tp, update_notes);
	ATF_TP_ADD_TC(tp, settings);
	ATF_TP_ADD_TC(tp, local_agent);
	ATF_TP_ADD_TC(tp, local_same);
	ATF_TP_ADD_TC(tp, local_absent);
	ATF_TP_ADD_TC(tp, push);
	ATF_TP_ADD_TC(tp, tokens);
	ATF_TP_ADD_TC(tp, transfers);
	ATF_TP_ADD_TC(tp, workflows);
	ATF_TP_ADD_TC(tp, sdwan);
	ATF_TP_ADD_TC(tp, sdwan_apply);
	ATF_TP_ADD_TC(tp, sdwan_uswe);
	ATF_TP_ADD_TC(tp, load);
	ATF_TP_ADD_TC(tp, session_restart);
	ATF_TP_ADD_TC(tp, unreachable);
	ATF_TP_ADD_TC(tp, mtls);
	ATF_TP_ADD_TC(tp, enrol);
	return (atf_no_error());
}
