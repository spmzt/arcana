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
		    != NULL, "%s", jstr(&r, "trace.2.detail"));
		resp_free(&r);
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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, unauthenticated);
	ATF_TP_ADD_TC(tp, setup_token);
	ATF_TP_ADD_TC(tp, register_login);
	ATF_TP_ADD_TC(tp, login_refused);
	ATF_TP_ADD_TC(tp, second_key);
	ATF_TP_ADD_TC(tp, csrf);
	ATF_TP_ADD_TC(tp, jails);
	ATF_TP_ADD_TC(tp, services);
	ATF_TP_ADD_TC(tp, agent_update);
	ATF_TP_ADD_TC(tp, agent_build);
	ATF_TP_ADD_TC(tp, settings);
	ATF_TP_ADD_TC(tp, local_agent);
	ATF_TP_ADD_TC(tp, local_same);
	ATF_TP_ADD_TC(tp, local_absent);
	ATF_TP_ADD_TC(tp, push);
	ATF_TP_ADD_TC(tp, load);
	ATF_TP_ADD_TC(tp, session_restart);
	ATF_TP_ADD_TC(tp, unreachable);
	ATF_TP_ADD_TC(tp, mtls);
	ATF_TP_ADD_TC(tp, enrol);
	return (atf_no_error());
}
