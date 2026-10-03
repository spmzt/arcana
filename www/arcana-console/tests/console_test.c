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

	/* A challenge works once. */
	http("POST", "/api/auth/login/begin", "{}", &b);
	strlcpy(old, jstr(&b, "publicKey.challenge"), sizeof(old));
	resp_free(&b);
	do_login(&a, 8, ORIGIN, RP_ID, old, false, &r);
	EXPECT(&r, 401);
	ATF_CHECK_MSG(strstr(r.body, "challenge") != NULL, "%s", r.body);
	resp_free(&r);

	authn_new(&other, -7);
	do_login(&other, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	ATF_CHECK_STREQ("", cookie);
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
	char		path[160], cwd[MAXPATHLEN], body[MAXPATHLEN];

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

CONSOLE_TC(services, "Services listed, acted on and configured through "
    "service(8) and sysrc(8)")
ATF_TC_BODY(services, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[160], base[128], cwd[MAXPATHLEN], body[MAXPATHLEN];
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

	/* The network tables: netstat's JSON, inside ours. */
	snprintf(path, sizeof(path), "%.*s/net/routes?family=inet",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("default", jstr(&r, "data.statistics.route-information."
	    "route-table.rt-family.0.rt-entry.0.destination"));
	ATF_CHECK_MSG(strstr(jstr(&r, "trace.4.label"), "-f inet") != NULL,
	    "%s", jstr(&r, "trace.4.label"));
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
	ATF_TP_ADD_TC(tp, unreachable);
	ATF_TP_ADD_TC(tp, mtls);
	ATF_TP_ADD_TC(tp, enrol);
	return (atf_no_error());
}
