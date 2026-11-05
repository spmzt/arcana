/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console end to end: arcana-console(8) and an arcana-agent(8) with a
 * stand-in for jail(8), both on sockets in the work directory,
 * driven over HTTP.  The test is its own WebAuthn authenticator: it makes
 * ES256 and Ed25519 keys with libcrypto and builds authenticator data and
 * clientDataJSON byte by byte, the way a security key and a browser do.
 *
 * Configuration variables: arcana-console, arcana-agent (the programs,
 * when not the ones built beside the tests).
 */

#include <sys/param.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/in.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ucl.h>
#include <unistd.h>

#include "harness.h"

/* The page's YANG-CBOR reader (www/arcana-ui/src/ycbor.c). */
ucl_object_t	*ycbor_json(const void *, size_t, const ucl_object_t *,
		    char *, size_t);

/* Does the kernel have SCTP: compiled in, or the module loaded. */
static bool
has_sctp(void)
{
	size_t	len;
	int	have;

	len = sizeof(have);
	if (sysctlbyname("kern.features.sctp", &have, &len, NULL, 0) == 0 &&
	    have != 0)
		return (true);
	return (modfind("sctp") != -1);
}


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

/* navigator.credentials.create(), as a browser and a key would do it;
 * token the setup token, or an invitation (inv_...) of a user's. */
static void
do_register(struct authn *a, const char *token, struct resp *r)
{
	struct resp	 b;
	uint8_t		 ad[256], *spki;
	char		 body[4096], *cd, *id64, *cd64, *ad64, *pk64, *p;
	size_t		 adlen;
	int		 spkilen;

	snprintf(body, sizeof(body), "{\"%s\":\"%s\"}", token != NULL &&
	    strncmp(token, "inv_", 4) == 0 ? "invite" : "setup_token", token !=
	    NULL ? token : "");
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

/* The same with three minutes: an apply made twice over. */
#define	CONSOLE_TC_LONG(name, descr)					\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	atf_tc_set_md_var(tc, "timeout", "180");				\
}									\
ATF_TC_CLEANUP(name, tc)						\
{									\
	stop();								\
}

CONSOLE_TC(unauthenticated, "Without a session only health and status work")
ATF_TC_BODY(unauthenticated, tc)
{
	struct resp	r;

	/* A write cut short by a stop, its temporary left: taken away at
	 * start, and what only looks like one kept. */
	ATF_REQUIRE(mkdir("data", 0700) == 0);
	put("data/sdwan-state.json", "{}");
	put("data/sdwan-state.json.AbC123", "{}");
	put("data/sdwan-state.json.backup", "{}");
	put("data/gone.json.Xy12zz", "{}");
	start(tc, 0, NULL);
	ATF_CHECK(access("data/sdwan-state.json.AbC123", F_OK) == -1);
	ATF_CHECK(access("data/sdwan-state.json.backup", F_OK) == 0);
	ATF_CHECK(access("data/gone.json.Xy12zz", F_OK) == 0);
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
	/* An /api/ path the console does not have: a JSON 404. */
	http("GET", "/api/servers/0123abcd/tls-old", NULL, &r);
	EXPECT(&r, 404);
	ATF_CHECK_STREQ("not-found", jstr(&r, "error.code"));
	resp_free(&r);
	http("POST", "/api/nowhere", "{}", &r);
	EXPECT(&r, 404);
	ATF_CHECK_STREQ("not-found", jstr(&r, "error.code"));
	resp_free(&r);
	ATF_CHECK_EQ(0, access("data/setup-token", R_OK));
}

CONSOLE_TC(restconf, "RESTCONF's reads: discovery, the root, the fleet "
    "and a host's data by api-path, content, depth, fields and "
    "with-defaults; its errors")
/*
 * NACM (RFC 8341) on the host: the console says whose each request is.
 * An operator of the console's is in no group of the host's rules, so
 * what changes the host is refused to him there; the admin's goes.
 */
ATF_TC_WITHOUT_HEAD(nacm_user);
ATF_TC_BODY(nacm_user, tc)
{
	static const char job[] = "{\"jobs\":[{\"kind\":\"monitor\","
	    "\"verb\":\"set\",\"args\":[\"name=gre8\",\"interface=gre8\","
	    "\"address=192.0.2.8\",\"interval=500\",\"eval=10000\"]}]}";
	struct authn	 a, b;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64], id[16];
	char		 path[256], invite[80];

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	http("PUT", "/api/roles/ops", "{\"console\":\"member\",\"hosts\":"
	    "{\"*\":\"operator\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("PUT", "/api/users/bob", "{\"roles\":[\"ops\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/users/bob/invite", NULL, &r);
	EXPECT(&r, 200);
	snprintf(invite, sizeof(invite), "%s", jstr(&r, "token"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", id);
	/* bob: the console lets an operator change; the host does not. */
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "user"));
	resp_free(&r);
	http("POST", path, job, &r);
	ATF_CHECK_MSG(strstr(r.body, "access denied") !=
	    NULL, "%d %s", r.status, r.body);
	resp_free(&r);
	/* The admin. */
	cookie[0] = '\0';
	do_login(&a, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", path, job, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "access denied") == NULL);
	resp_free(&r);
}

/*
 * The console's roles synchronized to a host's access rules, by an
 * owner, when asked and not before: bob, an owner, is anyone else to
 * the host until then; synchronized, he is of its group admin and
 * changes the host as himself; once more, nothing to do; an operator
 * again, he may not ask, and the admin's synchronizing takes him out.
 * Rules of the host's own with no group admin are left as they are.
 */
ATF_TC_WITHOUT_HEAD(nacm_sync);
ATF_TC_BODY(nacm_sync, tc)
{
	static const char job[] = "{\"jobs\":[{\"kind\":\"monitor\","
	    "\"verb\":\"set\",\"args\":[\"name=gre8\",\"interface=gre8\","
	    "\"address=192.0.2.8\",\"interval=500\",\"eval=10000\"]}]}";
	static const char rules[] = "{\"groups\":{\"group\":[{\"name\":"
	    "\"ops\",\"user-name\":[\"admin\"%s]}]},\"rule-list\":[{\"name\":"
	    "\"ops\",\"group\":[\"ops\"],\"rule\":[{\"name\":\"all\","
	    "\"module-name\":\"*\",\"access-operations\":\"*\",\"action\":"
	    "\"permit\"}]}]}";
	struct authn	 a, b;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64], id[16];
	char		 path[256], sync[256], invite[80], admin[160], bob[160];
	char		 cmd[3 * MAXPATHLEN];
	const char	*ctl;
	FILE		*fp;

	start(tc, 0, NULL);
	enrol(&a);
	snprintf(admin, sizeof(admin), "%s", cookie);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", id);
	snprintf(sync, sizeof(sync), "/api/servers/%s/nacm-sync", id);
	http("PUT", "/api/roles/ops", "{\"console\":\"member\",\"hosts\":"
	    "{\"*\":\"operator\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("PUT", "/api/users/bob", "{\"roles\":[\"owner\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/users/bob/invite", NULL, &r);
	EXPECT(&r, 200);
	snprintf(invite, sizeof(invite), "%s", jstr(&r, "token"));
	resp_free(&r);
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(bob, sizeof(bob), "%s", cookie);
	/* Not before it is asked for. */
	http("POST", path, job, &r);
	ATF_CHECK_MSG(strstr(r.body, "access denied") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	/* Synchronized: bob of the host's group admin, and let. */
	http("POST", sync, "{}", &r);
	ATF_CHECK_MSG(r.status == 200, "%d %s", r.status, r.body);
	ATF_CHECK_STREQ("changed", jstr(&r, "data.result"));
	ATF_CHECK_MSG(strstr(r.body, "\"bob\"") != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", path, job, &r);
	ATF_CHECK_MSG(r.status == 200 && strstr(r.body, "access denied") ==
	    NULL, "%d %s", r.status, r.body);
	resp_free(&r);
	http("POST", sync, "{}", &r);
	ATF_CHECK_STREQ("unchanged", jstr(&r, "data.result"));
	resp_free(&r);
	/* An operator again: he may not ask; the admin's takes him out. */
	snprintf(cookie, sizeof(cookie), "%s", admin);
	http("PUT", "/api/users/bob", "{\"roles\":[\"ops\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", bob);
	http("POST", sync, "{}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", admin);
	http("POST", sync, "{}", &r);
	ATF_CHECK_STREQ("changed", jstr(&r, "data.result"));
	ATF_CHECK_MSG(strstr(r.body, "\"bob\"") == NULL, "%s", r.body);
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", bob);
	http("POST", path, job, &r);
	ATF_CHECK_MSG(strstr(r.body, "access denied") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	/*
	 * The host's own rules decide: rules that do not let the console
	 * read them refuse it, and rules that do but have no group admin
	 * are left as they are.
	 */
	ctl = locate(tc, "../../../usr.sbin/arcanactl/arcanactl", "arcanactl",
	    "/usr/local/sbin/arcanactl");
	snprintf(cookie, sizeof(cookie), "%s", admin);
	for (int k = 0; k < 2; k++) {
		ATF_REQUIRE((fp = fopen("rules.json", "w")) != NULL);
		fprintf(fp, rules, k == 0 ? "" : ",\"console\"");
		fprintf(fp, "\n");
		fclose(fp);
		snprintf(cmd, sizeof(cmd), "%s -c unix:%s/jgd.sock edit nacm "
		    "@rules.json && %s -c unix:%s/jgd.sock commit", ctl, cwd,
		    ctl, cwd);
		ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
		http("POST", sync, "{}", &r);
		if (k == 0)
			ATF_CHECK_MSG(jstr(&r, "data.result") == NULL &&
			    strstr(r.body, "do not let the console") != NULL,
			    "%d %s", r.status, r.body);
		else
			ATF_CHECK_STREQ("no-admin-group", jstr(&r,
			    "data.result"));
		resp_free(&r);
	}
}

/*
 * Where the console reaches a host, its own record alone: a server
 * added at a wrong address is unreachable, and told the right one it is
 * reached, the host asked nothing.  Moved, the name its certificate is
 * checked for stays the old address's host unless one is given ("" the
 * new address's own); no URI, or another server's, is refused.
 */
ATF_TC_WITHOUT_HEAD(server_readdress);
ATF_TC_BODY(server_readdress, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 128], id[16];
	char		 tid[16], path[256], jails[256];

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "nowhere.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s", id);
	snprintf(jails, sizeof(jails), "/api/servers/%s/jails", id);
	http("GET", jails, NULL, &r);
	ATF_CHECK_MSG(r.status != 200 || jstr(&r, "error") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	/* The right address: reached, nothing asked of the host before. */
	snprintf(body, sizeof(body), "{\"uri\":\"unix:%s/jgd.sock\","
	    "\"peer_name\":\"\"}", cwd);
	http("POST", path, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "jgd.sock") != NULL, "%s", r.body);
	resp_free(&r);
	http("GET", jails, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("10.0.0.10", jail_str(&r, "web", "ip4.0"));
	resp_free(&r);
	/* Over TCP: the old host's name still checked, or the one given. */
	http("POST", "/api/servers", "{\"name\":\"far\",\"uri\":"
	    "\"tcp://192.0.2.7:4310\"}", &r);
	EXPECT(&r, 200);
	snprintf(tid, sizeof(tid), "%s", jstr(&r, "servers.1.id"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s", tid);
	http("POST", path, "{\"uri\":\"tcp://192.0.2.8:4310\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("tcp://192.0.2.8:4310", jstr(&r, "servers.1.uri"));
	ATF_CHECK_STREQ("192.0.2.7", jstr(&r, "servers.1.peer_name"));
	resp_free(&r);
	http("POST", path, "{\"uri\":\"tcp://192.0.2.9:4310\","
	    "\"peer_name\":\"far.example\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("far.example", jstr(&r, "servers.1.peer_name"));
	resp_free(&r);
	http("POST", path, "{\"uri\":\"tcp://192.0.2.9:4310\","
	    "\"peer_name\":\"\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "servers.1.peer_name") == NULL);
	resp_free(&r);
	/* No URI; another server's. */
	http("POST", path, "{\"uri\":\"192.0.2.9\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"uri\":\"unix:%s/jgd.sock\"}", cwd);
	http("POST", path, body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("GET", "/api/servers", NULL, &r);
	ATF_CHECK_STREQ("tcp://192.0.2.9:4310", jstr(&r, "servers.1.uri"));
	resp_free(&r);
}

/*
 * What the console does for no one (a workflow at its interval) it asks
 * as NACM's user "console", never as the agent's recovery session, even
 * over the local socket as the agent's own user: with "console" out of
 * the agent's group admin, the run's change is refused.
 */
ATF_TC_WITHOUT_HEAD(nacm_console);
ATF_TC_BODY(nacm_console, tc)
{
	static const char rules[] = "{\"groups\":{\"group\":[{\"name\":"
	    "\"admin\",\"user-name\":[\"admin\"]}]},\"rule-list\":[{\"name\":"
	    "\"admin\",\"group\":[\"admin\"],\"rule\":[{\"name\":\"all\","
	    "\"module-name\":\"*\",\"access-operations\":\"*\",\"action\":"
	    "\"permit\"}]}]}";
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 512], id[16];
	char		 wid[16], cmd[3 * MAXPATHLEN];
	const char	*ctl;
	FILE		*fp;
	int		 i;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ctl = locate(tc, "../../../usr.sbin/arcanactl/arcanactl", "arcanactl",
	    "/usr/local/sbin/arcanactl");
	/* The agent's rules, by its recovery session (this test's uid). */
	ATF_REQUIRE((fp = fopen("rules.json", "w")) != NULL);
	fprintf(fp, "%s\n", rules);
	fclose(fp);
	snprintf(cmd, sizeof(cmd), "%s -c unix:%s/jgd.sock edit nacm "
	    "@rules.json && %s -c unix:%s/jgd.sock commit", ctl, cwd, ctl, cwd);
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"each minute\",\"hosts\":"
	    "[\"%s\"],\"every\":60,\"steps\":[{\"id\":\"s\",\"job\":{\"kind\":"
	    "\"monitor\",\"verb\":\"set\",\"args\":[\"name=gre8\","
	    "\"interface=gre8\",\"address=192.0.2.8\",\"interval=500\","
	    "\"eval=10000\"]}}]}", id);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "id") != NULL);
	snprintf(wid, sizeof(wid), "%s", jstr(&r, "id"));
	resp_free(&r);
	ATF_REQUIRE((fp = fopen("data/every.json", "w")) != NULL);
	fprintf(fp, "{\"%s\": %lld}\n", wid, (long long)time(NULL) - 58);
	fclose(fp);
	restart_console();
	for (i = 0; i < 300; i++) {
		http("GET", "/api/runs", NULL, &r);
		if (strstr(r.body, "\"each minute\"") != NULL &&
		    strstr(r.body, "\"running\"") == NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(i < 300, "the workflow did not run");
	ATF_CHECK_MSG(strstr(r.body, "access denied") !=
	    NULL, "%s", r.body);
	resp_free(&r);
}

/*
 * Who asked for a job: the console's user, as the host's NACM has it,
 * in the list, the job read and the event of its end; a run by hand,
 * who started it.  arcanactl as the host's recovery session names none.
 */
static void	run_wait(const char *, struct resp *);

CONSOLE_TC(job_user, "A job records the console user who asked for it; "
    "a run who started it")
ATF_TC_BODY(job_user, tc)
{
	static const char rules[] = "{\"groups\":{\"group\":[{\"name\":"
	    "\"admin\",\"user-name\":[\"admin\",\"console\",\"alice\"]}]},"
	    "\"rule-list\":[{\"name\":\"admin\",\"group\":[\"admin\"],\"rule\":"
	    "[{\"name\":\"all\",\"module-name\":\"*\",\"access-operations\":"
	    "\"*\",\"action\":\"permit\"}]}]}";
	struct authn	 a, b;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 512], id[16];
	char		 path[256], jpath[300], invite[80], wid[16], run[16];
	char		 cmd[3 * MAXPATHLEN], jid[24], key[64];
	const char	*ctl, *v;
	FILE		*fp;
	int		 i;
	bool		 seen;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ctl = locate(tc, "../../../usr.sbin/arcanactl/arcanactl", "arcanactl",
	    "/usr/local/sbin/arcanactl");
	ATF_REQUIRE((fp = fopen("rules.json", "w")) != NULL);
	fprintf(fp, "%s\n", rules);
	fclose(fp);
	snprintf(cmd, sizeof(cmd), "%s -c unix:%s/jgd.sock edit nacm "
	    "@rules.json && %s -c unix:%s/jgd.sock commit", ctl, cwd, ctl, cwd);
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"again\",\"hosts\":[\"%s\"],"
	    "\"steps\":[{\"id\":\"s\",\"job\":{\"kind\":\"service-action\","
	    "\"service\":\"sshd\",\"action\":\"restart\"}}]}", id);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	snprintf(wid, sizeof(wid), "%s", jstr(&r, "id"));
	resp_free(&r);
	http("PUT", "/api/users/alice", "{\"roles\":[\"operator\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/users/alice/invite", NULL, &r);
	EXPECT(&r, 200);
	snprintf(invite, sizeof(invite), "%s", jstr(&r, "token"));
	resp_free(&r);
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("alice", jstr(&r, "user"));
	resp_free(&r);

	/* alice's job: hers in the list, the read and the event. */
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", id);
	http("POST", path, "{\"jobs\":[{\"kind\":\"service-action\","
	    "\"service\":\"sshd\",\"action\":\"stop\"}]}", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "jobs.0.id") != NULL, "%s", r.body);
	snprintf(jid, sizeof(jid), "%s", jstr(&r, "jobs.0.id"));
	ATF_CHECK_STREQ("alice", jstr(&r, "jobs.0.user"));
	resp_free(&r);
	snprintf(jpath, sizeof(jpath), "%s/%s", path, jid);
	for (i = 0; i < 100; i++) {
		http("GET", jpath, NULL, &r);
		EXPECT(&r, 200);
		if (strcmp(jstr(&r, "job.state"), "done") == 0)
			break;
		resp_free(&r);
		usleep(50000);
	}
	ATF_REQUIRE_MSG(i < 100, "the job did not finish");
	ATF_CHECK_STREQ("alice", jstr(&r, "job.user"));
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(jid, jstr(&r, "jobs.0.id"));
	ATF_CHECK_STREQ("alice", jstr(&r, "jobs.0.user"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/events", id);
	seen = false;
	for (i = 0; i < 50 && !seen; i++) {
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		for (int k = 0; k < 64 && !seen; k++) {
			snprintf(key, sizeof(key), "data.events.%d.kind", k);
			if ((v = jstr(&r, key)) == NULL)
				break;
			snprintf(key, sizeof(key), "data.events.%d.data.id", k);
			if (strcmp(v, "job") != 0 || jstr(&r, key) == NULL ||
			    strcmp(jstr(&r, key), jid) != 0)
				continue;
			snprintf(key, sizeof(key), "data.events.%d.data.user",
			    k);
			ATF_CHECK_STREQ("alice", jstr(&r, key));
			seen = true;
		}
		resp_free(&r);
		if (!seen)
			usleep(100000);
	}
	ATF_CHECK_MSG(seen, "no event of job %s", jid);

	/* A run by hand: who started it, and its job hers too. */
	snprintf(path, sizeof(path), "/api/workflows/%s/run", wid);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("alice", jstr(&r, "started_by"));
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.0.state"));
	ATF_CHECK_STREQ("alice", jstr(&r, "hosts.0.steps.0.trace.job.user"));
	resp_free(&r);
	http("GET", "/api/runs", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("alice", jstr(&r, "runs.0.started_by"));
	resp_free(&r);

	/* arcanactl over the unix socket, saying no user: none. */
	snprintf(cmd, sizeof(cmd), "%s -q -c unix:%s/jgd.sock service sshd "
	    "start > /dev/null && %s --libxo json -c unix:%s/jgd.sock jobs > "
	    "ctl.json", ctl, cwd, ctl, cwd);
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
	ATF_CHECK(system("grep -q '\"user\":\"alice\"' ctl.json") == 0);
	ATF_CHECK(system("grep -q '\"title\":\"service sshd start\",[^}]*"
	    "\"user\"' ctl.json") != 0);
	ATF_CHECK(system("grep -q '\"title\":\"service sshd start\"' "
	    "ctl.json") == 0);
}

/*
 * RESTCONF's changes (RFC 8040, RFC 8527): running is not written; the
 * candidate's node PUT, read back from the candidate's datastore; a
 * confirmed commit refused without persist; with it, then confirmed by
 * its persist-id; running has it.  NACM's rules, the agent's own file.
 */
ATF_TC_WITHOUT_HEAD(restconf_write);
ATF_TC_BODY(restconf_write, tc)
{
	static const char rules[] = "{\"ietf-netconf-acm:nacm\":{"
	    "\"groups\":{\"group\":[{\"name\":\"admin\",\"user-name\":"
	    "[\"admin\",\"console\"]},{\"name\":\"ops\",\"user-name\":"
	    "[\"bob\"]}]},\"rule-list\":[{\"name\":\"admin\",\"group\":"
	    "[\"admin\"],\"rule\":[{\"name\":\"all\",\"module-name\":\"*\","
	    "\"access-operations\":\"*\",\"action\":\"permit\"}]}]}}";
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64], id[16];
	char		 data[256], cand[256], run[256], path[320];

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(data, sizeof(data), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s", id);
	snprintf(cand, sizeof(cand), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s", id);
	snprintf(run, sizeof(run), "/restconf/ds/ietf-datastores:running/"
	    "arcana-fleet:fleet/host=%s", id);
	/* with-origin (RFC 8527 section 3.2.2), the operational
	 * datastore's alone: nacm is running's, intended. */
	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:"
	    "operational/arcana-fleet:fleet/host=%s/ietf-netconf-acm:nacm"
	    "?with-origin", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ_MSG("ietf-origin:intended", jstr(&r,
	    "ietf-netconf-acm:nacm.@.ietf-origin:origin"), "%s", r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf-acm:nacm?with-origin",
	    run);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* Running is changed by a commit alone. */
	snprintf(path, sizeof(path), "%s/ietf-netconf-acm:nacm", data);
	http("PUT", path, rules, &r);
	EXPECT(&r, 405);
	ATF_CHECK_MSG(strstr(r.body, "confirmed commit of the candidate") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf-acm:nacm", cand);
	http("PUT", path, rules, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"ops\"") != NULL, "%s", r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf-acm:nacm", run);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"ops\"") == NULL, "%s", r.body);
	resp_free(&r);
	/* Confirmed: its persist token, then confirmed by it. */
	snprintf(path, sizeof(path), "%s/ietf-netconf:commit", data);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60}}", &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "persist") != NULL);
	resp_free(&r);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"t1\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("POST", path, "{\"ietf-netconf:input\":{\"persist-id\":\"t1\"}}",
	    &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-netconf-acm:nacm", run);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"ops\"") != NULL, "%s", r.body);
	resp_free(&r);
	/* What is not taken. */
	snprintf(path, sizeof(path), "%s/ietf-netconf:lock", data);
	http("POST", path, "{}", &r);
	ATF_CHECK(r.status == 404 || r.status == 405 || r.status == 400);
	resp_free(&r);
}

/*
 * An interface's router advertisements (RFC 8349's submodule with
 * arcana-ra) put in the candidate at their path below the interface,
 * committed confirmed: the first commit stops at rc-conf-files, the
 * warning accepted it goes through; running has the node, the host's
 * rtadvd.conf the record, rtadvd started.
 */
ATF_TC_WITHOUT_HEAD(restconf_ra);
ATF_TC_BODY(restconf_ra, tc)
{
	static const char node[] = "{\"ietf-ipv6-unicast-routing:"
	    "ipv6-router-advertisements\":{\"send-advertisements\":true,"
	    "\"max-rtr-adv-interval\":300,\"arcana-ra:router-preference\":"
	    "\"high\",\"arcana-ra:rdnss\":[{\"address\":\"2001:db8::53\"}],"
	    "\"prefix-list\":{\"prefix\":[{\"prefix-spec\":\"2001:db8:57::/64\","
	    "\"valid-lifetime\":3600,\"preferred-lifetime\":1800}]}}}";
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64], id[16];
	char		 path[400], conf[MAXPATHLEN + 32];
	FILE		*fp;
	size_t		 n;
	int		 ss;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	/* Arcana's rc.conf file goes where a host has the directory. */
	(void)mkdir("root/usr", 0755);
	(void)mkdir("root/usr/local", 0755);
	(void)mkdir("root/usr/local/etc", 0755);
	ATF_REQUIRE(mkdir("root/usr/local/etc/rc.conf.d", 0755) == 0);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	/* A dynamic subscription as the candidate is made, gone before its
	 * commit: no change of running's, which has the configured alone. */
	snprintf(conf, sizeof(conf), "GET /restconf/streams/%s/json HTTP/1.1"
	    "\r\nHost: localhost:8443\r\nCookie: %s\r\n\r\n", id, cookie);
	ss = console_socket();
	ATF_REQUIRE(write(ss, conf, strlen(conf)) == (ssize_t)strlen(conf));
	usleep(1500000);
	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s/ietf-interfaces:interfaces/"
	    "interface=lo0/ietf-ip:ipv6/ietf-ipv6-unicast-routing:"
	    "ipv6-router-advertisements", id);
	http("PUT", path, node, &r);
	ATF_CHECK_MSG(r.status == 204 || r.status == 201, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"arcana-ra:router-preference\":\"high\"")
	    != NULL, "%s", r.body);
	resp_free(&r);
	close(ss);
	usleep(1500000);
	/* The commit stops at the warning: rc_conf_files does not name
	 * Arcana's file; accepted, it goes on. */
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s/ietf-netconf:commit", id);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"ra1\"}}", &r);
	ATF_CHECK_MSG(r.status >= 400, "%d %s", r.status, r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"error-app-tag\":\"rc-conf-files\"") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s/ietf-netconf:commit?arcana-accept=rc-conf-files", id);
	http("POST", path, "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"ra1\"}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s/ietf-netconf:commit", id);
	http("POST", path, "{\"ietf-netconf:input\":{\"persist-id\":\"ra1\"}}",
	    &r);
	EXPECT(&r, 204);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:running/"
	    "arcana-fleet:fleet/host=%s/ietf-interfaces:interfaces/"
	    "interface=lo0/ietf-ip:ipv6/ietf-ipv6-unicast-routing:"
	    "ipv6-router-advertisements", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"max-rtr-adv-interval\":300") != NULL &&
	    strstr(r.body, "\"send-advertisements\":true") != NULL &&
	    strstr(r.body, "\"arcana-ra:rdnss\":[{\"address\":\"2001:db8::53\"}]")
	    != NULL, "%s", r.body);
	resp_free(&r);
	/* The host's file, as rtadvd.conf(5) wants it; rtadvd run. */
	ATF_REQUIRE((fp = fopen("rtadvd.conf", "r")) != NULL);
	n = fread(conf, 1, sizeof(conf) - 1, fp);
	conf[n] = '\0';
	fclose(fp);
	ATF_CHECK_MSG(strstr(conf, "lo0:\\\n\t:maxinterval#300:raflags=\"h\":"
	    "addr=\"2001:db8:57::\":prefixlen#64:\\\n\t:vltime#3600:pltime#1800:"
	    "rdnss=\"2001:db8::53\":\n") != NULL, "%s", conf);
	ATF_CHECK(access("running.rtadvd", F_OK) == 0);
}

/* A path through a mount point (RFC 8528): a FIB's routing below its
 * network instance's vrf-root. */
ATF_TC_WITHOUT_HEAD(restconf_mount);
ATF_TC_BODY(restconf_mount, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64], id[16];
	char		 path[320];
	int		 fibs = 0;
	size_t		 len = sizeof(fibs);

	if (sysctlbyname("net.fibs", &fibs, &len, NULL, 0) == -1 || fibs < 2)
		atf_tc_skip("one FIB alone here");
	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-network-instance:network-instances/network-instance=fib1/"
	    "vrf-root/ietf-routing:routing", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"ietf-routing:routing\"") != NULL &&
	    strstr(r.body, "\"ribs\"") != NULL, "%s", r.body);
	resp_free(&r);
}

#define	NACM		"/ietf-netconf-acm:nacm"
#define	YANG_PATCH	"Content-Type: application/yang-patch+json\r\n"
#define	ERROR_TAG	"ietf-restconf:errors.error.0.error-tag"

/* The console with the lab host, the admin's session: its entry in
 * /restconf/data (data) and in the candidate (cand), each len bytes. */
static void
rc_lab(const atf_tc_t *tc, char *data, char *cand, size_t len)
{
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64], id[16];

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	if (data != NULL)
		snprintf(data, len, "/restconf/data/arcana-fleet:fleet/host=%s",
		    id);
	snprintf(cand, len, "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s", id);
}

/* method of what is below base, with headers extra (NULL: none), its
 * status and error-tag what is said. */
static void
rc_expect(const char *method, const char *base, const char *below,
    const char *extra, const char *body, int status, const char *tag)
{
	struct resp	 r;
	char		 path[512];

	snprintf(path, sizeof(path), "%s%s", base, below);
	http_with(method, path, extra != NULL ? extra : "", body, &r);
	ATF_CHECK_MSG(r.status == status, "%s %s: %d, not %d: %s", method,
	    below, r.status, status, r.body);
	if (tag != NULL)
		ATF_CHECK_STREQ(tag, jstr(&r, ERROR_TAG));
	resp_free(&r);
}

/* Whether a, b and c are in s in that order. */
static bool
in_order(const char *s, const char *a, const char *b, const char *c)
{
	const char	*pa, *pb, *pc;

	return ((pa = strstr(s, a)) != NULL && (pb = strstr(s, b)) != NULL &&
	    (pc = strstr(s, c)) != NULL && pa < pb && pb < pc);
}

/*
 * One request with a body of len bytes and headers extra (each ending in
 * CRLF), the session's: its status, its content-type in ctype, its body
 * malloc'd in *out (*outlen bytes), as they came.
 */
static int
http_bin(const char *method, const char *path, const char *extra,
    const void *body, size_t blen, char *ctype, size_t ctlen, uint8_t **out,
    size_t *outlen)
{
	char	*req, *buf, *b, *c;
	size_t	 len = 0, cap = 65536, need = 0;
	ssize_t	 n;
	int	 s, status = 0;

	ATF_REQUIRE(asprintf(&req, "%s %s HTTP/1.1\r\nHost: localhost:8443\r\n"
	    "Connection: close\r\n%s%s%s%s%s%s%s%sContent-Length: %zu\r\n\r\n",
	    method, path, send_xjg ? "X-Arcana: 1\r\n" : "",
	    origin_hdr != NULL ? "Origin: " : "",
	    origin_hdr != NULL ? origin_hdr : "",
	    origin_hdr != NULL ? "\r\n" : "",
	    cookie[0] != '\0' ? "Cookie: " : "", cookie,
	    cookie[0] != '\0' ? "\r\n" : "", extra, blen) != -1);
	s = console_socket();
	ATF_REQUIRE(write(s, req, strlen(req)) == (ssize_t)strlen(req));
	if (blen > 0)
		ATF_REQUIRE(write(s, body, blen) == (ssize_t)blen);
	free(req);
	ATF_REQUIRE((buf = malloc(cap + 1)) != NULL);
	for (;;) {
		if (len == cap)
			ATF_REQUIRE((buf = realloc(buf, (cap *= 2) + 1)) != NULL);
		if ((n = read(s, buf + len, cap - len)) <= 0)
			break;
		len += (size_t)n;
		buf[len] = '\0';
		if (need == 0 && (b = strstr(buf, "\r\n\r\n")) != NULL &&
		    (c = strcasestr(buf, "content-length:")) != NULL && c < b)
			need = (size_t)(b + 4 - buf) + strtoul(c + 15, NULL,
			    10);
		if (need != 0 && len >= need)
			break;
	}
	close(s);
	buf[len] = '\0';
	ATF_REQUIRE(sscanf(buf, "HTTP/1.1 %d", &status) == 1);
	ATF_REQUIRE((b = strstr(buf, "\r\n\r\n")) != NULL);
	ctype[0] = '\0';
	if ((c = strcasestr(buf, "\r\ncontent-type: ")) != NULL && c < b)
		snprintf(ctype, ctlen, "%.*s", (int)strcspn(c + 16, "\r"),
		    c + 16);
	*outlen = len - (size_t)(b + 4 - buf);
	ATF_REQUIRE((*out = malloc(*outlen + 1)) != NULL);
	memcpy(*out, b + 4, *outlen);
	(*out)[*outlen] = '\0';
	free(buf);
	return (status);
}

/* Every .sid file of share/yang, the agent's own: an array of them. */
static ucl_object_t *
sid_files(void)
{
	struct ucl_parser	*p;
	struct dirent		*d;
	ucl_object_t		*arr;
	DIR			*dir;
	char			 path[MAXPATHLEN];

	arr = ucl_object_typed_new(UCL_ARRAY);
	ATF_REQUIRE((dir = opendir(TESTSRC "/../../../share/yang")) != NULL);
	while ((d = readdir(dir)) != NULL) {
		if (strlen(d->d_name) < 5 || strcmp(d->d_name +
		    strlen(d->d_name) - 4, ".sid") != 0)
			continue;
		snprintf(path, sizeof(path), "%s/../../../share/yang/%s",
		    TESTSRC, d->d_name);
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
		ATF_REQUIRE_MSG(ucl_parser_add_file(p, path), "%s", path);
		ucl_array_append(arr, ucl_parser_get_object(p));
		ucl_parser_free(p);
	}
	closedir(dir);
	return (arr);
}

/*
 * application/yang-data+cbor (PLAN-SDN-YANG 4.1.10): a host's YANG-CBOR
 * passed through, as the agent has it, its keys SIDs; the page's decoder
 * (www/arcana-ui/src/ycbor.c) reads it by the agent's .sid files to what
 * the JSON says; a PUT's body of it; what the console makes of JSON
 * refused with it.
 */
CONSOLE_TC(restconf_cbor, "application/yang-data+cbor: a host's YANG-CBOR "
    "passed through and read by the page's decoder; a PUT of it")
ATF_TC_BODY(restconf_cbor, tc)
{
	static const char cbor[] = "Accept: application/yang-data+cbor\r\n";
	/* {group: [{name: "gc", user-name: ["uc"]}]}, 1259 its SID. */
	static const uint8_t group[] = { 0xa1, 0x19, 0x04, 0xeb, 0x81, 0xa2,
	    0x01, 0x62, 'g', 'c', 0x02, 0x81, 0x62, 'u', 'c' };
	struct resp	 r;
	ucl_object_t	*sids, *o;
	const ucl_object_t *a, *b;
	uint8_t		*out;
	size_t		 len;
	char		 data[256], cand[256], path[512], ctype[128], why[160];
	int		 st;

	rc_lab(tc, data, cand, sizeof(cand));
	sids = sid_files();
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces", data);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	st = http_bin("GET", path, cbor, NULL, 0, ctype, sizeof(ctype), &out,
	    &len);
	ATF_REQUIRE_MSG(st == 200, "%d %s", st, out);
	ATF_CHECK_MSG(strncmp(ctype, "application/yang-data+cbor", 26) == 0,
	    "%s", ctype);
	o = ycbor_json(out, len, sids, why, sizeof(why));
	ATF_REQUIRE_MSG(o != NULL, "%s", why);
	/* Each interface the JSON has, named the same. */
	a = ucl_object_lookup_path(r.json, "ietf-interfaces:interfaces.interface");
	b = ucl_object_lookup_path(o, "ietf-interfaces:interfaces.interface");
	ATF_REQUIRE(a != NULL && b != NULL);
	ATF_CHECK_EQ(ucl_array_size(a), ucl_array_size(b));
	for (unsigned i = 0; i < ucl_array_size(a); i++)
		ATF_CHECK_STREQ(ucl_object_tostring(ucl_object_lookup(
		    ucl_array_find_index(a, i), "name")), ucl_object_tostring(
		    ucl_object_lookup(ucl_array_find_index(b, i), "name")));
	ucl_object_unref(o);
	free(out);
	resp_free(&r);
	/* The host's entry: each top-level node the agent has. */
	st = http_bin("GET", data, cbor, NULL, 0, ctype, sizeof(ctype), &out,
	    &len);
	ATF_REQUIRE_MSG(st == 200, "%d %s", st, out);
	o = ycbor_json(out, len, sids, why, sizeof(why));
	ATF_REQUIRE_MSG(o != NULL, "%s", why);
	ATF_CHECK(ucl_object_lookup(o, "ietf-interfaces:interfaces") != NULL);
	ATF_CHECK(ucl_object_lookup(o, "ietf-yang-library:yang-library") !=
	    NULL);
	ucl_object_unref(o);
	free(out);
	/* What the console makes of JSON is not asked of YANG-CBOR. */
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces?depth=2",
	    data);
	st = http_bin("GET", path, cbor, NULL, 0, ctype, sizeof(ctype), &out,
	    &len);
	ATF_CHECK_MSG(st == 400, "%d %s", st, out);
	free(out);
	st = http_bin("GET", data, "Accept: application/yang-data+cbor; "
	    "id=name\r\n", NULL, 0, ctype, sizeof(ctype), &out, &len);
	ATF_CHECK_MSG(st == 406, "%d %s", st, out);
	free(out);
	/* JSON first in Accept: JSON. */
	st = http_bin("GET", data, "Accept: application/yang-data+json, "
	    "application/yang-data+cbor\r\n", NULL, 0, ctype, sizeof(ctype),
	    &out, &len);
	ATF_CHECK_MSG(st == 200 && strstr(ctype, "json") != NULL, "%d %s", st,
	    ctype);
	free(out);
	/* A PUT of YANG-CBOR: the group made, as JSON reads it back. */
	snprintf(path, sizeof(path), "%s" NACM "/groups/group=gc", cand);
	st = http_bin("PUT", path, "Content-Type: application/yang-data+cbor"
	    "\r\n", group, sizeof(group), ctype, sizeof(ctype), &out, &len);
	ATF_CHECK_MSG(st == 201, "%d %s", st, out);
	free(out);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("uc", jstr(&r, "ietf-netconf-acm:group.0.user-name.0"));
	resp_free(&r);
	st = http_bin("PUT", path, "Content-Type: application/yang-data+cbor"
	    "\r\n", "\xa1\x19\x04", 3, ctype, sizeof(ctype), &out, &len);
	ATF_CHECK_MSG(st == 400 && strstr((char *)out, "malformed-message") !=
	    NULL, "%d %s", st, out);
	free(out);
	ucl_object_unref(sids);
}

/*
 * RFC 8040 section 4's changes, of the candidate's NACM rules: POST
 * makes a node under its target (201, its Location), data-exists the
 * second time; PUT makes (201) or replaces (204); a plain PATCH merges,
 * and makes nothing where its target is not; DELETE takes an entry and
 * a leaf-list's value away, data-missing the second time; insert and
 * point place an entry of an ordered-by user list; a plain PATCH of the
 * datastore merges its top-level nodes.
 */
CONSOLE_TC(restconf_edit, "RESTCONF's POST, PUT, PATCH and DELETE of the "
    "candidate, their status codes, Location, insert and point")
ATF_TC_BODY(restconf_edit, tc)
{
	struct resp	 r;
	char		 cand[256], path[512], loc[512];

	rc_lab(tc, NULL, cand, sizeof(cand));
	/* POST: a group made, where Location says. */
	snprintf(path, sizeof(path), "%s" NACM "/groups", cand);
	http("POST", path, "{\"ietf-netconf-acm:group\":[{\"name\":\"g1\","
	    "\"user-name\":[\"u1\"]}]}", &r);
	EXPECT(&r, 201);
	ATF_REQUIRE_MSG(resp_header(&r, "location", loc, sizeof(loc)) != NULL,
	    "%s", r.head);
	ATF_CHECK_MSG(strstr(loc, cand) != NULL && strstr(loc, NACM
	    "/groups/group=g1") != NULL, "%s", loc);
	resp_free(&r);
	rc_expect("POST", cand, NACM "/groups", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"g1\"}]}", 409,
	    "data-exists");
	/* Of the datastore, a top-level node (section 4.4.1's jukebox). */
	rc_expect("POST", cand, "", NULL, "{\"ietf-netconf-acm:nacm\":{}}",
	    409, "data-exists");
	http("GET", strstr(loc, "/restconf/"), NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("u1", jstr(&r, "ietf-netconf-acm:group.0.user-name.0"));
	resp_free(&r);
	/* PUT: made, then replaced; the body's key must be the path's. */
	rc_expect("PUT", cand, NACM "/groups/group=g2", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"g2\"}]}", 201, NULL);
	rc_expect("PUT", cand, NACM "/groups/group=g2", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"g2\",\"user-name\":"
	    "[\"u2\"]}]}", 204, NULL);
	rc_expect("PUT", cand, NACM "/groups/group=g2", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"g3\"}]}", 400,
	    "invalid-value");
	/* Plain PATCH: merged; where nothing is, nothing made. */
	rc_expect("PATCH", cand, NACM "/groups/group=g2", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"g2\",\"user-name\":"
	    "[\"u3\"]}]}", 204, NULL);
	snprintf(path, sizeof(path), "%s" NACM "/groups/group=g2", cand);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"u2\"") != NULL && strstr(r.body,
	    "\"u3\"") != NULL, "%s", r.body);
	resp_free(&r);
	rc_expect("PATCH", cand, NACM "/groups/group=nosuch", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"nosuch\"}]}", 404,
	    "invalid-value");
	/* DELETE: a leaf-list's value, an entry; then data-missing. */
	rc_expect("DELETE", cand, NACM "/groups/group=g2/user-name=u2", NULL,
	    NULL, 204, NULL);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"u2\"") == NULL && strstr(r.body,
	    "\"u3\"") != NULL, "%s", r.body);
	resp_free(&r);
	rc_expect("DELETE", cand, NACM "/groups/group=g2", NULL, NULL, 204,
	    NULL);
	rc_expect("DELETE", cand, NACM "/groups/group=g2", NULL, NULL, 409,
	    "data-missing");
	rc_expect("GET", cand, NACM "/groups/group=g2", NULL, NULL, 404,
	    NULL);
	/* insert and point (4.8.5, 4.8.6): rule-lists are ordered by the
	 * user; PUT places one too. */
	rc_expect("POST", cand, NACM, NULL, "{\"ietf-netconf-acm:rule-list\":"
	    "[{\"name\":\"rl-b\"}]}", 201, NULL);
	rc_expect("POST", cand, NACM "?insert=first", NULL,
	    "{\"ietf-netconf-acm:rule-list\":[{\"name\":\"rl-a\"}]}", 201,
	    NULL);
	rc_expect("POST", cand, NACM "?insert=after&point=" NACM
	    "/rule-list=rl-a", NULL, "{\"ietf-netconf-acm:rule-list\":"
	    "[{\"name\":\"rl-m\"}]}", 201, NULL);
	rc_expect("PUT", cand, NACM "/rule-list=rl-z?insert=before&point=%2F"
	    "ietf-netconf-acm%3Anacm%2Frule-list%3Drl-a", NULL,
	    "{\"ietf-netconf-acm:rule-list\":[{\"name\":\"rl-z\"}]}", 201,
	    NULL);
	snprintf(path, sizeof(path), "%s" NACM, cand);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(in_order(r.body, "\"rl-z\"", "\"rl-a\"", "\"rl-m\"") &&
	    in_order(r.body, "\"rl-a\"", "\"rl-m\"", "\"rl-b\""), "%s",
	    r.body);
	resp_free(&r);
	/* A plain PATCH of the datastore: its top-level nodes merged. */
	rc_expect("PATCH", cand, "", NULL, "{\"ietf-netconf-acm:nacm\":"
	    "{\"groups\":{\"group\":[{\"name\":\"g9\"}]}}}", 204, NULL);
	rc_expect("GET", cand, NACM "/groups/group=g9", NULL, NULL, 200, NULL);
	rc_expect("GET", cand, NACM "/groups/group=g1", NULL, NULL, 200, NULL);
}

/*
 * RFC 8072's YANG Patch, its examples' kinds on the candidate's rule
 * lists: two made (A.1.2); one that is there already and another, the
 * whole refused and nothing made (A.1.1); an entry inserted after one
 * (A.1.3), one moved (A.1.4); merge, replace, delete and remove at
 * once; a datastore's edits by their whole paths (A.1.5); an edit not
 * well made, its edit-id in the status.
 */
CONSOLE_TC(restconf_yang_patch, "RFC 8072's YANG Patch of the candidate, "
    "all or nothing, its status")
ATF_TC_BODY(restconf_yang_patch, tc)
{
	struct resp	 r;
	char		 cand[256], path[512];

	rc_lab(tc, NULL, cand, sizeof(cand));
	snprintf(path, sizeof(path), "%s" NACM, cand);
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"add-lists\",\"edit\":[{\"edit-id\":\"edit1\","
	    "\"operation\":\"create\",\"target\":\"/rule-list=p1\","
	    "\"value\":{\"ietf-netconf-acm:rule-list\":[{\"name\":\"p1\"}]}},"
	    "{\"edit-id\":\"edit2\",\"operation\":\"create\",\"target\":"
	    "\"/rule-list=p3\",\"value\":{\"rule-list\":[{\"name\":\"p3\"}]}}"
	    "]}}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("add-lists", jstr(&r,
	    "ietf-yang-patch:yang-patch-status.patch-id"));
	ATF_CHECK_MSG(strstr(r.body, "\"ok\":[null]") != NULL, "%s", r.body);
	resp_free(&r);
	/* One there already: refused whole, its edit said. */
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"again\",\"edit\":[{\"edit-id\":\"edit1\","
	    "\"operation\":\"create\",\"target\":\"/rule-list=p4\","
	    "\"value\":{\"rule-list\":[{\"name\":\"p4\"}]}},"
	    "{\"edit-id\":\"edit2\",\"operation\":\"create\",\"target\":"
	    "\"/rule-list=p1\",\"value\":{\"rule-list\":[{\"name\":\"p1\"}]}}"
	    "]}}", &r);
	EXPECT(&r, 409);
	ATF_CHECK_STREQ("edit2", jstr(&r, "ietf-yang-patch:yang-patch-status."
	    "edit-status.edit.0.edit-id"));
	ATF_CHECK_STREQ("data-exists", jstr(&r, "ietf-yang-patch:"
	    "yang-patch-status.edit-status.edit.0.errors.error.0.error-tag"));
	ATF_CHECK_MSG(strstr(r.body, "rule-list[name='p1']") != NULL, "%s",
	    r.body);
	resp_free(&r);
	rc_expect("GET", cand, NACM "/rule-list=p4", NULL, NULL, 404, NULL);
	/* insert after, then move after. */
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"insert\",\"edit\":[{\"edit-id\":\"edit1\","
	    "\"operation\":\"insert\",\"target\":\"/rule-list=p2\","
	    "\"point\":\"/rule-list=p1\",\"where\":\"after\",\"value\":"
	    "{\"ietf-netconf-acm:rule-list\":[{\"name\":\"p2\"}]}}]}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK_MSG(in_order(r.body, "\"p1\"", "\"p2\"", "\"p3\""), "%s",
	    r.body);
	resp_free(&r);
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"move\",\"edit\":[{\"edit-id\":\"edit1\","
	    "\"operation\":\"move\",\"target\":\"/rule-list=p1\","
	    "\"point\":\"/rule-list=p3\",\"where\":\"after\"}]}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK_MSG(in_order(r.body, "\"p2\"", "\"p3\"", "\"p1\""), "%s",
	    r.body);
	resp_free(&r);
	/* merge, replace, delete, remove (of what is not there) at once. */
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"four\",\"edit\":["
	    "{\"edit-id\":\"m\",\"operation\":\"merge\",\"target\":"
	    "\"/rule-list=p2\",\"value\":{\"rule-list\":[{\"name\":\"p2\","
	    "\"group\":[\"gm\"]}]}},"
	    "{\"edit-id\":\"r\",\"operation\":\"replace\",\"target\":"
	    "\"/rule-list=p3\",\"value\":{\"rule-list\":[{\"name\":\"p3\","
	    "\"group\":[\"gr\"]}]}},"
	    "{\"edit-id\":\"d\",\"operation\":\"delete\",\"target\":"
	    "\"/rule-list=p1\"},"
	    "{\"edit-id\":\"x\",\"operation\":\"remove\",\"target\":"
	    "\"/rule-list=nosuch\"}]}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", path, NULL, &r);
	ATF_CHECK_MSG(strstr(r.body, "\"gm\"") != NULL && strstr(r.body,
	    "\"gr\"") != NULL && strstr(r.body, "\"p1\"") == NULL, "%s",
	    r.body);
	resp_free(&r);
	/* The datastore's: edits by their whole paths. */
	http_with("PATCH", cand, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"datastore\",\"edit\":[{\"edit-id\":\"edit1\","
	    "\"operation\":\"create\",\"target\":\"" NACM "/groups/group=pg\","
	    "\"value\":{\"ietf-netconf-acm:group\":[{\"name\":\"pg\"}]}}]}}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	rc_expect("GET", cand, NACM "/groups/group=pg", NULL, NULL, 200, NULL);
	/* Not well made: insert without where; a move of what is not
	 * there. */
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"bad\",\"edit\":[{\"edit-id\":\"e9\","
	    "\"operation\":\"insert\",\"target\":\"/rule-list=p9\","
	    "\"value\":{\"rule-list\":[{\"name\":\"p9\"}]}}]}}", &r);
	EXPECT(&r, 400);
	ATF_CHECK_STREQ("e9", jstr(&r, "ietf-yang-patch:yang-patch-status."
	    "edit-status.edit.0.edit-id"));
	ATF_CHECK_STREQ("missing-attribute", jstr(&r, "ietf-yang-patch:"
	    "yang-patch-status.edit-status.edit.0.errors.error.0.error-tag"));
	resp_free(&r);
	http_with("PATCH", path, YANG_PATCH, "{\"ietf-yang-patch:yang-patch\":"
	    "{\"patch-id\":\"gone\",\"edit\":[{\"edit-id\":\"e8\","
	    "\"operation\":\"move\",\"target\":\"/rule-list=p9\","
	    "\"where\":\"first\"}]}}", &r);
	EXPECT(&r, 409);
	ATF_CHECK_STREQ("data-missing", jstr(&r, "ietf-yang-patch:"
	    "yang-patch-status.edit-status.edit.0.errors.error.0.error-tag"));
	resp_free(&r);
	/* The capability, and OPTIONS's Accept-Patch. */
	http("GET", "/restconf/data/ietf-restconf-monitoring:restconf-state",
	    NULL, &r);
	ATF_CHECK(strstr(r.body, "capability:yang-patch:1.0") != NULL);
	resp_free(&r);
	http("OPTIONS", path, NULL, &r);
	EXPECT(&r, 200);
	{
		char	v[256];

		ATF_CHECK_MSG(resp_header(&r, "accept-patch", v, sizeof(v)) !=
		    NULL && strstr(v, "application/yang-patch+json") != NULL,
		    "%s", r.head);
	}
	resp_free(&r);
}

/*
 * ETag and Last-Modified (RFC 8040 section 3.4.1): a GET of the
 * candidate has them, a conditional GET of the same is 304; an edit on
 * a stale tag or date is 412, on the right one goes and changes the tag;
 * If-Match: * and If-None-Match: * by what is there; running's tag
 * changes with a commit.
 */
CONSOLE_TC(restconf_etag, "RESTCONF's entity-tags and times of change, "
    "conditional reads and edits")
ATF_TC_BODY(restconf_etag, tc)
{
	static const char rules[] = "{\"ietf-netconf-acm:nacm\":{"
	    "\"groups\":{\"group\":[{\"name\":\"admin\",\"user-name\":"
	    "[\"admin\",\"console\"]}]},\"rule-list\":[{\"name\":\"admin\","
	    "\"group\":[\"admin\"],\"rule\":[{\"name\":\"all\",\"module-name\":"
	    "\"*\",\"access-operations\":\"*\",\"action\":\"permit\"}]}]}}";
	struct resp	 r;
	char		 data[256], cand[256], path[512], hdr[256];
	char		 e1[64], e2[64], lm[64], r1[64];

	rc_lab(tc, data, cand, sizeof(cand));
	snprintf(path, sizeof(path), "%s" NACM, cand);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(resp_header(&r, "etag", e1, sizeof(e1)) != NULL &&
	    resp_header(&r, "last-modified", lm, sizeof(lm)) != NULL, "%s",
	    r.head);
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-None-Match: %s\r\n", e1);
	rc_expect("GET", path, "", hdr, NULL, 304, NULL);
	snprintf(hdr, sizeof(hdr), "If-Modified-Since: %s\r\n", lm);
	rc_expect("GET", path, "", hdr, NULL, 304, NULL);
	rc_expect("GET", path, "", "If-Modified-Since: Sat, 01 Jan 2000 "
	    "00:00:00 GMT\r\n", NULL, 200, NULL);
	/* Stale: refused. */
	rc_expect("PUT", path, "/groups/group=e1", "If-Match: \"0-0\"\r\n",
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"e1\"}]}", 412,
	    "operation-failed");
	rc_expect("PUT", path, "/groups/group=e1", "If-Unmodified-Since: Sat, "
	    "01 Jan 2000 00:00:00 GMT\r\n", "{\"ietf-netconf-acm:group\":"
	    "[{\"name\":\"e1\"}]}", 412, "operation-failed");
	/* As it is: made, the tag a new one. */
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", e1);
	snprintf(path, sizeof(path), "%s" NACM "/groups/group=e1", cand);
	http_with("PUT", path, hdr, "{\"ietf-netconf-acm:group\":[{\"name\":"
	    "\"e1\"}]}", &r);
	EXPECT(&r, 201);
	ATF_REQUIRE(resp_header(&r, "etag", e2, sizeof(e2)) != NULL);
	ATF_CHECK_MSG(strcmp(e1, e2) != 0, "%s %s", e1, e2);
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-None-Match: %s\r\n", e1);
	rc_expect("GET", path, "", hdr, NULL, 200, NULL);
	/* * : there, or not. */
	rc_expect("PUT", cand, NACM "/groups/group=e9", "If-Match: *\r\n",
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"e9\"}]}", 412,
	    "operation-failed");
	rc_expect("PUT", cand, NACM "/groups/group=e1", "If-None-Match: *\r\n",
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"e1\"}]}", 412,
	    "operation-failed");
	rc_expect("PUT", cand, NACM "/groups/group=e1", "If-Match: *\r\n",
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"e1\"}]}", 204, NULL);
	/* Running's: a commit changes it. */
	snprintf(path, sizeof(path), "%s" NACM, data);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(resp_header(&r, "etag", r1, sizeof(r1)) != NULL);
	resp_free(&r);
	rc_expect("PUT", cand, NACM, NULL, rules, 204, NULL);
	rc_expect("POST", data, "/ietf-netconf:commit", NULL, "{}", 204, NULL);
	snprintf(hdr, sizeof(hdr), "If-None-Match: %s\r\n", r1);
	rc_expect("GET", path, "", hdr, NULL, 200, NULL);
}

/*
 * RFC 8040 section 7: each error-tag the console says, a case each, of
 * its status.  The rest it does not say: lock-denied (the agents lock
 * nothing), rollback-failed and partial-operation (a change is all or
 * nothing), resource-denied (the agent's lack of memory), too-big (a
 * body too big is the server's 413 before RESTCONF's) and
 * unknown-attribute (an annotation in a body is a member like another).
 */
CONSOLE_TC(restconf_tag_access_denied, "access-denied: 403, a viewer's "
    "change")
ATF_TC_BODY(restconf_tag_access_denied, tc)
{
	struct authn	 b;
	struct resp	 r;
	char		 cand[256], invite[80];

	rc_lab(tc, NULL, cand, sizeof(cand));
	http("PUT", "/api/roles/look", "{\"console\":\"member\",\"hosts\":"
	    "{\"*\":\"viewer\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("PUT", "/api/users/vic", "{\"roles\":[\"look\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/users/vic/invite", NULL, &r);
	EXPECT(&r, 200);
	snprintf(invite, sizeof(invite), "%s", jstr(&r, "token"));
	resp_free(&r);
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	rc_expect("PUT", cand, NACM "/groups/group=v", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"v\"}]}", 403,
	    "access-denied");
}

CONSOLE_TC(restconf_tag_invalid_value, "invalid-value: 400, a body's key "
    "not the path's; 404, nothing there")
ATF_TC_BODY(restconf_tag_invalid_value, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("PUT", cand, NACM "/groups/group=a", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"b\"}]}", 400,
	    "invalid-value");
	rc_expect("GET", cand, NACM "/groups/group=nosuch", NULL, NULL, 404,
	    "invalid-value");
}

CONSOLE_TC(restconf_tag_operation_not_supported, "operation-not-supported: "
    "405, running PUT")
ATF_TC_BODY(restconf_tag_operation_not_supported, tc)
{
	char	data[256], cand[256];

	rc_lab(tc, data, cand, sizeof(cand));
	rc_expect("PUT", data, NACM "/groups/group=a", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"a\"}]}", 405,
	    "operation-not-supported");
}

CONSOLE_TC(restconf_tag_operation_failed, "operation-failed: 412, an "
    "If-Match not met")
ATF_TC_BODY(restconf_tag_operation_failed, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("PUT", cand, NACM "/groups/group=a", "If-Match: \"x\"\r\n",
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"a\"}]}", 412,
	    "operation-failed");
}

CONSOLE_TC(restconf_tag_in_use, "in-use: 409, a commit while another's "
    "confirmed commit waits")
ATF_TC_BODY(restconf_tag_in_use, tc)
{
	static const char rules[] = "{\"ietf-netconf-acm:nacm\":{"
	    "\"groups\":{\"group\":[{\"name\":\"admin\",\"user-name\":"
	    "[\"admin\",\"console\"]}]},\"rule-list\":[{\"name\":\"admin\","
	    "\"group\":[\"admin\"],\"rule\":[{\"name\":\"all\",\"module-name\":"
	    "\"*\",\"access-operations\":\"*\",\"action\":\"permit\"}]}]}}";
	char	data[256], cand[256];

	rc_lab(tc, data, cand, sizeof(cand));
	rc_expect("PUT", cand, NACM, NULL, rules, 204, NULL);
	rc_expect("POST", data, "/ietf-netconf:commit", NULL,
	    "{\"ietf-netconf:input\":{\"confirmed\":[null],"
	    "\"confirm-timeout\":60,\"persist\":\"p1\"}}", 204, NULL);
	rc_expect("POST", data, "/ietf-netconf:commit", NULL, "{}", 409,
	    "in-use");
	rc_expect("POST", data, "/ietf-netconf:cancel-commit", NULL,
	    "{\"ietf-netconf:input\":{\"persist-id\":\"p1\"}}", 204, NULL);
}

CONSOLE_TC(restconf_tag_data_exists, "data-exists: 409, a POST of what "
    "is there")
ATF_TC_BODY(restconf_tag_data_exists, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("POST", cand, NACM "/groups", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"a\"}]}", 201, NULL);
	rc_expect("POST", cand, NACM "/groups", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"a\"}]}", 409,
	    "data-exists");
}

CONSOLE_TC(restconf_tag_data_missing, "data-missing: 409, a DELETE of "
    "what is not there")
ATF_TC_BODY(restconf_tag_data_missing, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("DELETE", cand, NACM "/groups/group=nosuch", NULL, NULL,
	    409, "data-missing");
}

CONSOLE_TC(restconf_tag_missing_attribute, "missing-attribute: 400, "
    "insert=before without its point")
ATF_TC_BODY(restconf_tag_missing_attribute, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("POST", cand, NACM "?insert=before", NULL,
	    "{\"ietf-netconf-acm:rule-list\":[{\"name\":\"a\"}]}", 400,
	    "missing-attribute");
}

CONSOLE_TC(restconf_tag_bad_attribute, "bad-attribute: 400, insert in a "
    "list the system orders")
ATF_TC_BODY(restconf_tag_bad_attribute, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("POST", cand, NACM "/groups?insert=first", NULL,
	    "{\"ietf-netconf-acm:group\":[{\"name\":\"a\"}]}", 400,
	    "bad-attribute");
}

CONSOLE_TC(restconf_tag_unknown_element, "unknown-element: 400, a member "
    "that is no node")
ATF_TC_BODY(restconf_tag_unknown_element, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("PUT", cand, NACM, NULL, "{\"ietf-netconf-acm:nacm\":"
	    "{\"nosuch\":1}}", 400, "unknown-element");
}

CONSOLE_TC(restconf_tag_unknown_namespace, "unknown-namespace: 400, a "
    "module there is not")
ATF_TC_BODY(restconf_tag_unknown_namespace, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("PATCH", cand, "", NULL, "{\"example-nosuch:x\":{}}", 400,
	    "unknown-namespace");
}

CONSOLE_TC(restconf_tag_bad_element, "bad-element: 400, a value not of "
    "its leaf's type")
ATF_TC_BODY(restconf_tag_bad_element, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("PUT", cand, NACM, NULL, "{\"ietf-netconf-acm:nacm\":"
	    "{\"enable-nacm\":\"maybe\"}}", 400, "bad-element");
}

CONSOLE_TC(restconf_tag_malformed_message, "malformed-message: 400, a "
    "body that is not JSON")
ATF_TC_BODY(restconf_tag_malformed_message, tc)
{
	char	cand[256];

	rc_lab(tc, NULL, cand, sizeof(cand));
	rc_expect("PUT", cand, NACM, NULL, "{\"ietf-netconf-acm:nacm\": {",
	    400, "malformed-message");
}

#define	L3NM	"/restconf/data/ietf-l3vpn-ntw:l3vpn-ntw"

/*
 * RFC 9182 Appendix A.1, Figures 32 to 34, as published, but for three
 * errors of the figures against the module: Figure 32's route
 * distinguisher and target, "0:65550:1", which ietf-routing-types'
 * patterns refuse (a type 0's AS is 2 bytes), are "2:65550:1" here, the
 * type of a 4-byte AS (RFC 4364 section 4.2); Figure 34's IPv4
 * "static-addresses" is a case of a choice, no node, its members the
 * ipv4 container's own (as the figure has IPv6's); and its routing
 * protocol "ietf-vpn-common:direct", an identity RFC 9181 names
 * direct-routing.
 */
static const char l3nm_fig32[] =
    "{\"ietf-l3vpn-ntw:vpn-services\":{\"vpn-service\":[{\"vpn-id\":\"4G\","
    "\"vpn-description\":\"VPN to deploy 4G services\",\"customer-name\":"
    "\"mycustomer\",\"vpn-service-topology\":\"custom\","
    "\"vpn-instance-profiles\":{\"vpn-instance-profile\":[{\"profile-id\":"
    "\"simple-profile\",\"local-as\":65550,\"rd\":\"2:65550:1\","
    "\"address-family\":[{\"address-family\":\"ietf-vpn-common:dual-stack\","
    "\"vpn-targets\":{\"vpn-target\":[{\"id\":1,\"route-targets\":"
    "[{\"route-target\":\"2:65550:1\"}],\"route-target-type\":\"both\"}]}}]}]}}"
    "]}}";
static const char l3nm_fig33[] =
    "{\"ietf-l3vpn-ntw:vpn-nodes\":{\"vpn-node\":[{\"vpn-node-id\":\"44\","
    "\"ne-id\":\"198.51.100.1\",\"active-vpn-instance-profiles\":"
    "{\"vpn-instance-profile\":[{\"profile-id\":\"simple-profile\"}]}}]}}";
#define	L3NM_ACCESS(id, vlan, what)					\
    "{\"id\":\"" id "\",\"interface-id\":\"1/1/1\",\"description\":"	\
    "\"Interface " what " to eNODE-B\",\"vpn-network-access-type\":"	\
    "\"ietf-vpn-common:point-to-point\",\"vpn-instance-profile\":"	\
    "\"simple-profile\",\"status\":{\"admin-status\":{\"status\":"	\
    "\"ietf-vpn-common:admin-up\"}},\"connection\":{\"encapsulation\":"	\
    "{\"type\":\"ietf-vpn-common:dot1q\",\"dot1q\":{\"cvlan-id\":" vlan	\
    "}}},\"ip-connection\":{\"ipv4\":{\"local-address\":\"192.0.2.1\","	\
    "\"prefix-length\":30,\"address-allocation-type\":\"static-address\","	\
    "\"primary-address\":\"1\",\"address\":"				\
    "[{\"address-id\":\"1\",\"customer-address\":\"192.0.2.2\"}]},"	\
    "\"ipv6\":{\"local-address\":\"2001:db8::1\",\"prefix-length\":64,"	\
    "\"address-allocation-type\":\"static-address\",\"primary-address\":"	\
    "\"1\",\"address\":[{\"address-id\":\"1\",\"customer-address\":"	\
    "\"2001:db8::2\"}]}},\"routing-protocols\":{\"routing-protocol\":"	\
    "[{\"id\":\"1\",\"type\":\"ietf-vpn-common:direct-routing\"}]}}"
static const char l3nm_fig34[] =
    "{\"ietf-l3vpn-ntw:vpn-network-accesses\":{\"vpn-network-access\":["
    L3NM_ACCESS("1/1/1.1", "1", "SYNC") ","
    L3NM_ACCESS("1/1/1.2", "2", "DATA") "]}}";

/* A module of the console's own datastore, which no host has; not
 * ietf-vpn-common, which the agents implement too for RFC 9408's SAPs
 * (no data nodes of its own). */
static bool
own_name(const char *m, size_t n)
{
	static const char *const own[] = { "ietf-l3vpn-ntw", "arcana-l3nm" };

	for (size_t i = 0; i < nitems(own); i++)
		if (strlen(own[i]) == n && strncmp(m, own[i], n) == 0)
			return (true);
	return (false);
}

/* A host entry's member (RFC 7951's module:node) of the console's own
 * modules, into where; NULL: none. */
static const char *
own_top(const ucl_object_t *top, char *where, size_t len)
{
	const ucl_object_t	*h, *m;
	ucl_object_iter_t	 it = NULL;
	const char		*k, *c;

	h = ucl_array_find_index(ucl_object_lookup(top, "arcana-fleet:host"),
	    0);
	while ((m = ucl_object_iterate(h, &it, true)) != NULL) {
		k = ucl_object_key(m);
		if ((c = strchr(k, ':')) != NULL && own_name(k, (size_t)(c -
		    k))) {
			snprintf(where, len, "%s", k);
			return (where);
		}
	}
	return (NULL);
}

/* A module of a yang-library's module sets, implemented or imported,
 * of the console's own, into where; NULL: none. */
static const char *
own_module(const ucl_object_t *top, char *where, size_t len)
{
	static const char *const lists[] = { "module", "import-only-module" };
	const ucl_object_t	*set, *m;
	ucl_object_iter_t	 it = NULL, mit;
	const char		*n;

	while ((set = ucl_object_iterate(ucl_object_lookup_path(top,
	    "ietf-yang-library:yang-library.module-set"), &it, true)) != NULL)
		for (size_t i = 0; i < nitems(lists); i++) {
			mit = NULL;
			while ((m = ucl_object_iterate(ucl_object_lookup(set,
			    lists[i]), &mit, true)) != NULL)
				if ((n = ucl_object_tostring(ucl_object_lookup(m,
				    "name"))) != NULL && own_name(n, strlen(n))) {
					snprintf(where, len, "%s", n);
					return (where);
				}
		}
	return (NULL);
}

CONSOLE_TC(l3nm, "the services as L3NM, the console's own datastore: RFC "
    "9182 Appendix A.1 made by its three POSTs, read back, changed, "
    "checked and kept")
ATF_TC_BODY(l3nm, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 etag[64];

	start(tc, 0, NULL);
	http("GET", L3NM, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	enrol(&a);
	/* Nothing kept yet. */
	http("GET", L3NM "/vpn-services", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* Figure 32 as published: its route target refused, the node at
	 * fault said. */
	{
		char	pub[sizeof(l3nm_fig32)], *p;

		memcpy(pub, l3nm_fig32, sizeof(pub));
		while ((p = strstr(pub, "2:65550:1")) != NULL)
			*p = '0';
		http("POST", L3NM, pub, &r);
		EXPECT(&r, 400);
		ATF_CHECK(strstr(r.body, "route-targets/route-target\"") !=
		    NULL || strstr(r.body, "/rd\"") != NULL);
		resp_free(&r);
	}
	/* Figure 32: the service, below a container not yet there. */
	http("POST", L3NM, l3nm_fig32, &r);
	EXPECT(&r, 201);
	ATF_CHECK_MSG(resp_header(&r, "location", etag, sizeof(etag)) !=
	    NULL, "%s", r.head);
	resp_free(&r);
	http("POST", L3NM "/vpn-services/vpn-service=4G", l3nm_fig33, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("POST", L3NM "/vpn-services/vpn-service=4G/vpn-nodes/vpn-node=44",
	    l3nm_fig34, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	/* Read back, whole and a node. */
	http("GET", L3NM, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("4G", jstr(&r, "ietf-l3vpn-ntw:l3vpn-ntw.vpn-services."
	    "vpn-service.0.vpn-id"));
	ATF_CHECK_STREQ("ietf-vpn-common:custom", jstr(&r, "ietf-l3vpn-ntw:"
	    "l3vpn-ntw.vpn-services.vpn-service.0.vpn-service-topology"));
	ATF_CHECK_STREQ("2:65550:1", jstr(&r, "ietf-l3vpn-ntw:l3vpn-ntw."
	    "vpn-services.vpn-service.0.vpn-instance-profiles."
	    "vpn-instance-profile.0.rd"));
	ATF_CHECK_MSG(resp_header(&r, "etag", etag, sizeof(etag)) != NULL,
	    "%s", r.head);
	resp_free(&r);
	/* (A key with "/" in it is not named in a path the server has
	 * decoded: the accesses read and changed by their container.) */
	http("GET", L3NM "/vpn-services/vpn-service=4G/vpn-nodes/vpn-node=44/"
	    "vpn-network-accesses", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("2", jstr(&r, "ietf-l3vpn-ntw:vpn-network-accesses."
	    "vpn-network-access.1.connection.encapsulation.dot1q.cvlan-id"));
	resp_free(&r);
	/* Changed: merged; a value not of its type refused; a leafref to
	 * no profile of the node refused, nothing kept of either. */
	http("PATCH", L3NM "/vpn-services/vpn-service=4G", "{\"ietf-l3vpn-ntw:"
	    "vpn-service\":[{\"vpn-id\":\"4G\",\"vpn-name\":\"mobile\"}]}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("PATCH", L3NM "/vpn-services/vpn-service=4G/vpn-nodes/"
	    "vpn-node=44/vpn-network-accesses", "{\"ietf-l3vpn-ntw:"
	    "vpn-network-accesses\":{\"vpn-network-access\":[{\"id\":"
	    "\"1/1/1.1\",\"connection\":{\"encapsulation\":{\"dot1q\":"
	    "{\"cvlan-id\":5000}}}}]}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PATCH", L3NM "/vpn-services/vpn-service=4G/vpn-nodes/"
	    "vpn-node=44/vpn-network-accesses", "{\"ietf-l3vpn-ntw:"
	    "vpn-network-accesses\":{\"vpn-network-access\":[{\"id\":"
	    "\"1/1/1.1\",\"vpn-instance-profile\":\"nosuch\"}]}}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d %s", r.status,
	    r.body);
	ATF_CHECK(strstr(r.body, "error-tag") != NULL);
	resp_free(&r);
	/* Kept: across a restart, in /restconf/data, the library naming
	 * its modules. */
	restart_console();
	http("GET", L3NM "/vpn-services/vpn-service=4G/vpn-name", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("mobile", jstr(&r, "ietf-l3vpn-ntw:vpn-name"));
	resp_free(&r);
	http("GET", L3NM "/vpn-services/vpn-service=4G/vpn-nodes/vpn-node=44/"
	    "vpn-network-accesses", NULL, &r);
	ATF_CHECK_STREQ("simple-profile", jstr(&r, "ietf-l3vpn-ntw:"
	    "vpn-network-accesses.vpn-network-access.0.vpn-instance-profile"));
	ATF_CHECK_STREQ("1", jstr(&r, "ietf-l3vpn-ntw:vpn-network-accesses."
	    "vpn-network-access.0.connection.encapsulation.dot1q.cvlan-id"));
	resp_free(&r);
	http("GET", "/restconf/data", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("4G", jstr(&r, "ietf-l3vpn-ntw:l3vpn-ntw.vpn-services."
	    "vpn-service.0.vpn-id"));
	ATF_CHECK(strstr(r.body, "\"name\":\"ietf-l3vpn-ntw\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"name\":\"ietf-vpn-common\"") != NULL);
	resp_free(&r);
	/* A host's are as they were: its drift, its entry and what is
	 * mounted there, none of the console's own modules. */
	{
		char	cwd[MAXPATHLEN], body[MAXPATHLEN + 64], id[16];
		char	path[256], where[128];

		ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
		snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":"
		    "\"unix:%s/jgd.sock\"}", cwd);
		http("POST", "/api/servers", body, &r);
		EXPECT(&r, 200);
		snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
		resp_free(&r);
		snprintf(path, sizeof(path), "/api/servers/%s/drift", id);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("true", jstr(&r, "ok"));
		resp_free(&r);
		snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:"
		    "fleet/host=%s", id);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		/* By key: the host's processes' arguments are free text
		 * (arcana-processes), a test's anywhere on the VM. */
		ATF_CHECK(jstr(&r, "arcana-fleet:host.0.id") != NULL);
		ATF_CHECK_MSG(own_top(r.json, where, sizeof(where)) == NULL,
		    "the host's data has %s", where);
		resp_free(&r);
		snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:"
		    "fleet/host=%s/ietf-yang-library:yang-library", id);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK(strstr(r.body, "\"ietf-interfaces\"") != NULL);
		ATF_CHECK_MSG(own_module(r.json, where, sizeof(where)) == NULL,
		    "the host's library names %s", where);
		resp_free(&r);
		snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:"
		    "fleet/host=%s/ietf-l3vpn-ntw:l3vpn-ntw", id);
		http("GET", path, NULL, &r);
		EXPECT(&r, 400);
		resp_free(&r);
	}
	/* Taken away. */
	http("DELETE", L3NM "/vpn-services/vpn-service=4G", NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", L3NM "/vpn-services/vpn-service=4G", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
}

/*
 * The SD-WAN document's example (sdwan_good, @A and @B as edges a and
 * b) as L3NM and arcana-l3nm, by the mapping arcana-l3nm says: an SWVC
 * a vpn-service, its domains its VPN instance profiles (RD, RTs), each
 * edge with end points a vpn-node, each end point a vpn-network-access
 * (the UNI's interface, VLAN, first provider address and subnet length,
 * static routes and BGP L3NM's), the rest the augments.
 */
static const char l3nm_good[] =
    "{\"ietf-l3vpn-ntw:l3vpn-ntw\":{\"arcana-l3nm:sdwan\":{\"ucs\":[{\"id\""
    ":\"inet\",\"type\":\"public\",\"billing\":\"flat-rate\",\"tunnel\":{\""
    "kind\":\"gre\",\"ipsec\":true}},{\"id\":\"mpls\",\"type\":\"private\","
    "\"billing\":\"flat-rate\",\"tunnel\":{\"kind\":\"geneve\"}}],\"edge\":"
    "[{\"server\":\"a\",\"ntp\":[\"ntp.example.org\",\"10.99.0.9\"],\"ucs-e"
    "nd-point\":[{\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0"
    "\",\"breakout\":true},{\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface"
    "\":\"vtnet1\"}]},{\"server\":\"b\",\"ucs-end-point\":[{\"id\":\"b-inet"
    "\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"},{\"id\":\"b-mpls\",\"ucs"
    "\":\"mpls\",\"interface\":\"vtnet1\",\"backup\":true}]}]},\"vpn-servic"
    "es\":{\"vpn-service\":[{\"vpn-id\":\"acme\",\"vpn-instance-profiles\":"
    "{\"vpn-instance-profile\":[{\"profile-id\":\"subscriber\",\"local-as\""
    ":64600,\"rd\":\"0:64600:3\",\"arcana-l3nm:domain\":\"subscriber\",\"ar"
    "cana-l3nm:fib\":1,\"arcana-l3nm:label\":1003},{\"profile-id\":\"servic"
    "e\",\"local-as\":64600,\"rd\":\"0:64600:1\",\"address-family\":[{\"add"
    "ress-family\":\"ietf-vpn-common:dual-stack\",\"vpn-targets\":{\"vpn-ta"
    "rget\":[{\"id\":1,\"route-targets\":[{\"route-target\":\"0:64600:1\"}]"
    ",\"route-target-type\":\"both\"}]}}],\"arcana-l3nm:domain\":\"service"
    "\",\"arcana-l3nm:label\":1001,\"arcana-l3nm:prefix\":\"100.64.0.0/24\""
    "},{\"profile-id\":\"breakout\",\"local-as\":64600,\"rd\":\"0:64600:2\""
    ",\"arcana-l3nm:domain\":\"breakout\",\"arcana-l3nm:fib\":2,\"arcana-l3"
    "nm:label\":1002}]},\"vpn-nodes\":{\"vpn-node\":[{\"vpn-node-id\":\"a\""
    ",\"ne-id\":\"a\",\"active-vpn-instance-profiles\":{\"vpn-instance-prof"
    "ile\":[{\"profile-id\":\"subscriber\"}]},\"vpn-network-accesses\":{\"v"
    "pn-network-access\":[{\"id\":\"hq\",\"interface-id\":\"vtnet2\",\"vpn-"
    "network-access-type\":\"ietf-vpn-common:multipoint\",\"vpn-instance-pr"
    "ofile\":\"subscriber\",\"ip-connection\":{\"ipv4\":{\"local-address\":"
    "\"10.1.0.1\",\"prefix-length\":24,\"address-allocation-type\":\"ietf-l"
    "3vpn-ntw:provider-dhcp\",\"arcana-l3nm:mode\":\"dhcp\",\"arcana-l3nm:p"
    "rovider\":[\"10.1.0.1\"],\"arcana-l3nm:reserved\":[\"10.1.0.0/26\",\"1"
    "0.1.0.200/30\"],\"arcana-l3nm:dns\":[\"10.1.0.1\"],\"arcana-l3nm:lease"
    "\":\"1h\"}},\"routing-protocols\":{\"routing-protocol\":[{\"id\":\"sta"
    "tic\",\"type\":\"ietf-vpn-common:static-routing\",\"static\":{\"cascad"
    "ed-lan-prefixes\":{\"ipv4-lan-prefixes\":[{\"lan\":\"10.1.8.0/22\",\"n"
    "ext-hop\":\"10.1.0.2\",\"arcana-l3nm:distance\":10}]}}},{\"id\":\"bgp-"
    "1\",\"type\":\"ietf-vpn-common:bgp-routing\",\"bgp\":{\"peer-as\":6501"
    "0,\"address-family\":\"ietf-vpn-common:ipv4\",\"neighbor\":[\"10.1.0.2"
    "\"],\"bgp-timers\":{\"hold-time\":90},\"authentication\":{\"enable\":t"
    "rue,\"keying-material\":{\"key\":\"s3cret\",\"crypto-algorithm\":\"iet"
    "f-key-chain:md5\"}},\"arcana-l3nm:distance\":150,\"arcana-l3nm:communi"
    "ty\":[{\"as\":64600,\"value\":100}]}}]},\"arcana-l3nm:sdwan\":{\"uni-i"
    "d\":\"uni-hq\",\"policy-map\":[{\"zone\":\"office\",\"app\":\"all\",\""
    "ingress\":\"hubonly\",\"egress\":\"quiet\"}],\"nat\":{\"ip-version\":"
    "\"ipv4\",\"public-prefix\":\"198.51.100.0/30\"}}},{\"id\":\"road\",\"i"
    "nterface-id\":\"wg5\",\"vpn-network-access-type\":\"ietf-vpn-common:mu"
    "ltipoint\",\"vpn-instance-profile\":\"subscriber\",\"arcana-l3nm:sdwan"
    "\":{\"remote\":{\"prefix\":\"10.30.0.0/24\",\"port\":51820,\"group\":["
    "{\"name\":\"staff\",\"zone\":\"office\",\"pool\":\"10.30.0.64/26\"},{"
    "\"name\":\"guests\",\"zone\":\"office\"}],\"identity\":[{\"name\":\"al"
    "ice\",\"zone\":\"office\",\"public-key\":\"xTIBA5rboUvnH4htodjb6e697Qj"
    "LERt1NAB4mZqp8Dg=\"},{\"name\":\"carol\",\"group\":\"staff\",\"public-"
    "key\":\"HIgo9xNzJMWLKASShiTqIYNW7HVnKq0pjaZxmvZ6rKA=\"}]}}}]}},{\"vpn-"
    "node-id\":\"b\",\"ne-id\":\"b\",\"active-vpn-instance-profiles\":{\"vp"
    "n-instance-profile\":[{\"profile-id\":\"subscriber\"}]},\"vpn-network-"
    "accesses\":{\"vpn-network-access\":[{\"id\":\"branch\",\"interface-id"
    "\":\"vtnet2\",\"vpn-network-access-type\":\"ietf-vpn-common:multipoint"
    "\",\"vpn-instance-profile\":\"subscriber\",\"connection\":{\"encapsula"
    "tion\":{\"type\":\"ietf-vpn-common:dot1q\",\"dot1q\":{\"cvlan-id\":20}"
    "}},\"ip-connection\":{\"ipv6\":{\"local-address\":\"2001:db8:1::1\",\""
    "prefix-length\":64,\"address-allocation-type\":\"ietf-l3vpn-ntw:slaac"
    "\",\"arcana-l3nm:mode\":\"slaac\",\"arcana-l3nm:provider\":[\"2001:db8"
    ":1::1\"],\"arcana-l3nm:dns\":[\"2001:db8:1::1\"]}},\"arcana-l3nm:sdwan"
    "\":{\"uni-id\":\"uni-br\"}}]}}]},\"arcana-l3nm:sdwan\":{\"fib\":1,\"md"
    "5\":\"edges-secret\",\"ucs\":[\"inet\",\"mpls\"],\"reserved-prefix\":["
    "\"100.64.0.0/24\"],\"zone\":[{\"name\":\"office\",\"prefix\":[\"10.1.0"
    ".0/16\"],\"policy\":[{\"app\":\"web\",\"policy\":\"fast\"}]},{\"name\""
    ":\"rest\",\"default\":[null]}],\"virtual-topology\":[{\"name\":\"hub\""
    ",\"type\":\"rooted-multipoint\",\"root\":[\"hq\"],\"leaf\":[\"branch\""
    "]}],\"intervals\":{\"eval\":1000,\"arrival\":100,\"ir\":500},\"bfd\":{"
    "\"interval\":200,\"multiplier\":3},\"tca\":{\"delay\":\"30\",\"loss\":"
    "\"0.05\",\"damping\":2},\"rate-limiter\":[{\"name\":\"shared\",\"commi"
    "t\":\"1000000\",\"limit\":\"5000000\"}],\"security-function-policy\":["
    "{\"id\":\"g-ippf\",\"function\":\"ippf\",\"allow\":{\"tuple\":[{\"id\""
    ":1,\"dav4\":[\"192.0.2.8/29\"]}]},\"block\":{\"tuple\":[{\"id\":1,\"da"
    "v4\":[\"192.0.2.0/24\"]}]},\"no-match\":\"allow\",\"duration\":6},{\"i"
    "d\":\"g-dnf\",\"function\":\"dnf\",\"block\":{\"value\":[\"ads.example"
    "\"]},\"allow\":{\"value\":[\"ok.ads.example\"]},\"no-match\":\"allow\""
    ",\"duration\":6},{\"id\":\"g-dpf\",\"function\":\"dpf\",\"block\":{\"t"
    "uple\":[{\"id\":1,\"sav4\":[\"192.0.2.53/32\"],\"message-type\":\"resp"
    "onse\"},{\"id\":2,\"dav4\":[\"192.0.2.54/32\"],\"message-type\":\"quer"
    "y\"}]},\"no-match\":\"block\",\"redirect\":true,\"duration\":6},{\"id"
    "\":\"g-urlf\",\"function\":\"urlf\",\"block\":{\"value\":[\"bad.exampl"
    "e\"]},\"no-match\":\"allow\",\"duration\":6},{\"id\":\"g-mdr\",\"funct"
    "ion\":\"mdr\",\"detection-type\":\"signature\",\"removal\":\"block-sub"
    "set\",\"block\":{\"value\":[\"44D88612FEA8A8F36DE82E1278ABB02F:68\",\""
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\"]},"
    "\"allow\":{\"value\":[\"3395856ce81f2b7382dee72602f798b642f14140\"]},"
    "\"no-match\":\"allow\",\"duration\":24}],\"security-policy\":[{\"name"
    "\":\"guard\",\"function-policy\":[\"g-ippf\",\"g-dnf\",\"g-dpf\",\"g-u"
    "rlf\",\"g-mdr\"],\"rate-limit\":\"2000000\",\"ids\":{\"mode\":\"preven"
    "t\",\"ruleset\":true,\"rule\":[\"alert http any any -> $HOME_NET any ("
    "msg:\\\"x\\\"; sid:1000001; rev:1;)\"]}}],\"importance\":{\"level\":["
    "\"high\",\"low\"],\"default\":\"low\"},\"application-flow-group\":[\"b"
    "ulk\"],\"application-flow\":[{\"name\":\"web\",\"criteria\":{\"dport\""
    ":[80,\"https\"],\"protv4\":[\"tcp\"]}},{\"name\":\"voice\",\"group\":"
    "\"bulk\",\"criteria\":{\"appid\":[\"sip\"],\"dscp\":[46]}},{\"name\":"
    "\"all\",\"criteria\":{\"any\":true}}],\"policy\":[{\"name\":\"fast\","
    "\"direction\":\"ingress\",\"criteria\":{\"encryption\":\"required-publ"
    "ic-only\",\"performance\":{\"primary\":{\"metric\":\"delay\",\"thresho"
    "ld\":\"10\",\"ceiling\":\"12\",\"remediation\":\"9\"},\"secondary\":[{"
    "\"metric\":\"loss\",\"threshold\":\"0.05\"}]},\"rate-limiter\":\"share"
    "d\",\"business-importance\":\"high\",\"internet-breakout\":\"enabled\""
    ",\"af-security-ingress\":\"guard\"}},{\"name\":\"hubonly\",\"direction"
    "\":\"ingress\",\"criteria\":{\"virtual-topology\":\"hub\"}},{\"name\":"
    "\"quiet\",\"direction\":\"egress\",\"criteria\":{\"egress-block\":\"di"
    "scard\"}}]}}]}}}";

static const char l3nm_full[] =
    "{\"ietf-l3vpn-ntw:l3vpn-ntw\":{\"arcana-l3nm:sdwan\":{\"ucs\":[{\"id\""
    ":\"wgu\",\"type\":\"public\",\"billing\":\"usage-based\",\"tunnel\":{"
    "\"kind\":\"wg\",\"mss\":\"auto\",\"mtu\":1420}},{\"id\":\"usw\",\"type"
    "\":\"public\",\"billing\":\"other\",\"tunnel\":{\"kind\":\"uswe\",\"ms"
    "s\":1360,\"mtu\":\"auto\",\"algorithms\":\"aes-gcm-16\",\"esn\":true,"
    "\"encap\":true,\"lifetime\":3600}}],\"edge\":[{\"server\":\"c/edge1\","
    "\"own-table\":true,\"host-bird\":false,\"transit\":true,\"bgp-import\""
    ":\"sets\",\"breakout-set\":[{\"set\":\"cdn\",\"via\":\"c-wg\"}],\"ucs-"
    "end-point\":[{\"id\":\"c-wg\",\"ucs\":\"wgu\",\"interface\":\"igb0\","
    "\"address\":\"192.0.2.10\",\"gateway\":\"192.0.2.1\",\"beacon\":\"198."
    "51.100.53\",\"breakout\":true,\"bandwidth\":\"100000000\",\"preference"
    "\":200,\"nat\":true,\"relay\":[{\"to\":\"a\",\"endpoint\":\"127.0.0.1:"
    "4096\",\"port\":4097,\"plugin\":\"speederv2\",\"fec\":\"20:10\",\"mode"
    "\":0}],\"addressing\":\"dhcp\",\"vrf\":3,\"routing\":{\"bgp\":[{\"id\""
    ":1,\"family\":\"both\",\"as\":65001,\"neighbor\":[\"192.0.2.1\",\"2001"
    ":db8::1\"],\"password\":\"pw\",\"hold-time\":30,\"source\":\"192.0.2.1"
    "0\",\"multihop\":true,\"distance\":20,\"bfd\":true,\"community\":[{\"a"
    "s\":65001,\"value\":7}]}],\"ospf\":[{\"id\":1,\"family\":\"ipv4\",\"ar"
    "ea\":0,\"cost\":10,\"password\":\"k\",\"hello\":10,\"dead\":40,\"dista"
    "nce\":110,\"bfd\":false}]}}]}],\"named-list\":[{\"name\":\"branches\","
    "\"kind\":\"prefixes\",\"item\":[\"10.2.0.0/16\"]},{\"name\":\"web\",\""
    "kind\":\"services\",\"protocol\":[\"tcp\"],\"port\":[80,\"443\",\"8000"
    "-8080\"]},{\"name\":\"links\",\"kind\":\"ucs-end-points\",\"item\":[\""
    "c-wg\"],\"end-point\":[{\"id\":\"c-wg\",\"preference\":5}]}]},\"vpn-se"
    "rvices\":{\"vpn-service\":[{\"vpn-id\":\"full\",\"vpn-instance-profile"
    "s\":{\"vpn-instance-profile\":[{\"profile-id\":\"subscriber\",\"local-"
    "as\":64700,\"arcana-l3nm:fib\":9}]},\"vpn-nodes\":{\"vpn-node\":[{\"vp"
    "n-node-id\":\"c/edge1\",\"ne-id\":\"c\",\"active-vpn-instance-profiles"
    "\":{\"vpn-instance-profile\":[{\"profile-id\":\"subscriber\"}]},\"vpn-"
    "network-accesses\":{\"vpn-network-access\":[{\"id\":\"lan\",\"interfac"
    "e-id\":\"igb1\",\"vpn-instance-profile\":\"subscriber\",\"connection\""
    ":{\"encapsulation\":{\"type\":\"ietf-vpn-common:untagged-int\"}},\"ip-"
    "connection\":{\"ipv4\":{\"local-address\":\"10.2.0.1\",\"prefix-length"
    "\":24,\"address-allocation-type\":\"ietf-l3vpn-ntw:static-address\",\""
    "arcana-l3nm:mode\":\"static\",\"arcana-l3nm:provider\":[\"10.2.0.1\","
    "\"10.2.0.2\"],\"arcana-l3nm:secondary\":[{\"prefix\":\"10.2.9.0/24\","
    "\"provider\":[\"10.2.9.1\"]}]},\"ipv6\":{\"arcana-l3nm:mode\":\"ll-onl"
    "y\"}},\"routing-protocols\":{\"routing-protocol\":[{\"id\":\"static\","
    "\"type\":\"ietf-vpn-common:static-routing\",\"static\":{\"cascaded-lan"
    "-prefixes\":{\"ipv6-lan-prefixes\":[{\"lan\":\"2001:db8:9::/48\",\"nex"
    "t-hop\":\"fe80::1\",\"arcana-l3nm:distance\":5}]}}},{\"id\":\"ospf-1\""
    ",\"type\":\"ietf-vpn-common:ospf-routing\",\"ospf\":{\"address-family"
    "\":\"ietf-vpn-common:ipv4\",\"area-id\":\"0.0.0.1\",\"metric\":10,\"au"
    "thentication\":{\"enable\":true,\"keying-material\":{\"key\":\"k2\"}},"
    "\"arcana-l3nm:hello\":5,\"arcana-l3nm:dead\":20,\"arcana-l3nm:bfd\":tr"
    "ue,\"arcana-l3nm:distance\":100}}]},\"arcana-l3nm:sdwan\":{\"uni-id\":"
    "\"uni-lan\",\"host-addressed\":true,\"max-frame\":9000,\"clat\":{\"pre"
    "fix\":\"2001:db8:46::/96\"},\"policy-map\":[{\"zone\":\"Internet\",\"a"
    "pp\":\"all\",\"egress\":\"out\"}],\"nat\":{\"disabled\":[null]},\"avai"
    "lability\":\"99.9\"}}]}}]},\"arcana-l3nm:sdwan\":{\"fib\":9,\"ucs\":["
    "\"wgu\",\"usw\"],\"bgp-set\":[{\"name\":\"cdn\",\"as-path\":[13335],\""
    "community\":[{\"as\":65001,\"value\":1}]}],\"nat64\":{\"prefix\":\"64:"
    "ff9b::/96\",\"pool\":\"192.0.2.64/28\",\"edge\":\"c/edge1\"},\"ibgp\":"
    "\"tunnel\",\"control-plane\":{\"host\":\"c/edge1\",\"cluster-id\":\"10"
    ".255.0.1\",\"ctvc\":\"wgu\"},\"zone\":[{\"name\":\"lan\",\"prefix-list"
    "\":\"branches\"}],\"virtual-topology\":[{\"name\":\"mesh\",\"type\":\""
    "multipoint-to-multipoint\",\"end-point\":[\"lan\",\"lan2\"]}],\"probe"
    "\":{\"interval\":500,\"size\":128,\"count\":0,\"dscp\":46,\"down\":3,"
    "\"up\":2,\"timeout\":1000,\"history\":100,\"report\":10},\"tca\":{\"ip"
    "dv\":\"5.5\"},\"security-function-policy\":[{\"id\":\"m\",\"function\""
    ":\"mbsf\",\"allow\":{\"value\":[\"tls1.2\",\"tls1.3\"]},\"no-match\":"
    "\"block\",\"invalid-server-certificate\":\"block\",\"invalid-client-ce"
    "rtificate\":\"allow\",\"unencrypted\":\"allow\",\"trusted-cas\":\"syst"
    "em\",\"pass-through\":[\"*.bank.example\"]},{\"id\":\"p\",\"function\""
    ":\"pdns\",\"block\":{\"pdns\":[{\"id\":1,\"type\":\"A\",\"value\":\"20"
    "3.0.113.0/24\",\"encryption\":[\"any\"]},{\"id\":2,\"type\":\"NS\",\"v"
    "alue\":\"ns.bad.example\"}]},\"lists\":{\"block\":[\"feed1\"]},\"no-ma"
    "tch\":\"allow\",\"duration\":12,\"notify\":[\"block\",\"quarantine\"],"
    "\"southbound\":[\"unencrypted\",\"dot\"],\"northbound\":\"dot\",\"upst"
    "ream\":[\"192.0.2.53@853#dns.example\"]},{\"id\":\"q\",\"function\":\""
    "ippf\",\"quarantine\":{\"tuple\":[{\"id\":1,\"sav6\":[\"2001:db8::/32"
    "\"],\"nextheadv6\":[\"udp\"],\"sport\":[53],\"dport\":[\"1000-2000\"]}"
    "]},\"no-match\":\"allow\",\"duration\":1}],\"security-policy\":[{\"nam"
    "e\":\"edge\",\"function-policy\":[\"m\",\"p\"]}],\"application-flow\":"
    "[{\"name\":\"svc\",\"group\":\"None\",\"criteria\":{\"service-list\":"
    "\"web\",\"src-list\":\"branches\",\"sdav4\":[\"10.0.0.0/8\"],\"dav6\":"
    "[\"2001:db8::/32\"],\"sdav6\":[\"2001:db8:1::/48\"],\"sav6\":[\"2001:d"
    "b8:2::/48\"],\"sdport\":[22],\"sport\":[1024],\"ethertype\":[2048],\"n"
    "extheadv6\":[6],\"sav4\":[\"10.9.0.0/16\"],\"dav4\":[\"10.8.0.0/16\"]}"
    "},{\"name\":\"tun\",\"criteria\":{\"dst-list\":\"branches\",\"sdst-lis"
    "t\":\"branches\"}}],\"policy\":[{\"name\":\"p1\",\"direction\":\"ingre"
    "ss\",\"criteria\":{\"ucs-list\":\"u\",\"edge-list\":\"e\",\"ucs-end-po"
    "int-list\":\"links\",\"public-private\":\"either\",\"backup\":\"disabl"
    "ed\",\"billing-method\":\"either\",\"virtual-topology\":\"Swvc\",\"all"
    "owed-destination-zones\":{\"zone\":[\"lan\",\"Self\"]},\"bandwidth\":{"
    "\"commit\":\"1000\",\"limit\":\"2000\"},\"performance\":{\"primary\":{"
    "\"metric\":\"loss\"}}}},{\"name\":\"p2\",\"direction\":\"ingress\",\"c"
    "riteria\":{\"allowed-destination-zones\":{\"all\":[null]}}},{\"name\":"
    "\"p3\",\"direction\":\"ingress\",\"criteria\":{\"allowed-destination-z"
    "ones\":{},\"internet-breakout\":\"enabled\"}},{\"name\":\"out\",\"dire"
    "ction\":\"egress\",\"criteria\":{\"egress-block\":\"allow\",\"af-secur"
    "ity-egress\":\"edge\"}}]}}]}}}";
/* a and b the same JSON: objects with the same members, arrays in the
 * same order, values with the same text.  false, where says where. */
static bool
same_json(const ucl_object_t *a, const ucl_object_t *b, char *where,
    size_t len)
{
	const ucl_object_t	*x, *y;
	ucl_object_iter_t	 it = NULL;
	const char		*sa, *sb;
	size_t			 n, i;
	double			 da, db;
	char			 sub[256], *ea, *eb;

	if (a == NULL || b == NULL || ucl_object_type(a) != ucl_object_type(b))
		return (false);
	switch (ucl_object_type(a)) {
	case UCL_OBJECT:
		if (a->len != b->len) {
			snprintf(where, len, "%s: %u members, not %u", where,
			    a->len, b->len);
			return (false);
		}
		while ((x = ucl_object_iterate(a, &it, true)) != NULL) {
			snprintf(sub, sizeof(sub), "%s.%s", where,
			    ucl_object_key(x));
			if (!same_json(x, ucl_object_lookup(b, ucl_object_key(x)),
			    sub, sizeof(sub))) {
				snprintf(where, len, "%s", sub);
				return (false);
			}
		}
		return (true);
	case UCL_ARRAY:
		if ((n = ucl_array_size(a)) != ucl_array_size(b))
			return (false);
		for (i = 0; i < n; i++) {
			x = ucl_array_find_index(a, i);
			y = ucl_array_find_index(b, i);
			snprintf(sub, sizeof(sub), "%s.%zu", where, i);
			if (!same_json(x, y, sub, sizeof(sub))) {
				snprintf(where, len, "%s", sub);
				return (false);
			}
		}
		return (true);
	case UCL_NULL:
		return (true);
	default:
		/* A decimal64 is written with all its fraction digits. */
		sa = ucl_object_tostring_forced(a);
		sb = ucl_object_tostring_forced(b);
		if (strcmp(sa, sb) == 0)
			return (true);
		da = strtod(sa, &ea);
		db = strtod(sb, &eb);
		return (ea != sa && *ea == '\0' && eb != sb && *eb == '\0' &&
		    da == db);
	}
}

static ucl_object_t *
json_of(const char *s)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	ATF_REQUIRE(ucl_parser_add_string(p, s, 0));
	o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

CONSOLE_TC(l3nm_sdwan, "the SD-WAN document's example as L3NM and "
    "arcana-l3nm, every field the document has in a node, kept and read "
    "back the same")
ATF_TC_BODY(l3nm_sdwan, tc)
{
	struct authn		 a;
	struct resp		 r;
	ucl_object_t		*want, *full;
	const ucl_object_t	*w, *g;
	char			 where[256];

	start(tc, 0, NULL);
	enrol(&a);
	http("PUT", L3NM, l3nm_good, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", L3NM, NULL, &r);
	EXPECT(&r, 200);
	want = json_of(l3nm_good);
	snprintf(where, sizeof(where), "l3vpn-ntw");
	ATF_CHECK_MSG(same_json(want, r.json, where, sizeof(where)),
	    "not as put at %s: %s", where, r.body);
	resp_free(&r);
	/* The fields the example has not: merged, read back the same. */
	http("PATCH", L3NM, l3nm_full, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", L3NM, NULL, &r);
	EXPECT(&r, 200);
	full = json_of(l3nm_full);
	w = ucl_array_find_index(ucl_object_lookup_path(full,
	    "ietf-l3vpn-ntw:l3vpn-ntw.vpn-services.vpn-service"), 0);
	g = ucl_array_find_index(ucl_object_lookup_path(r.json,
	    "ietf-l3vpn-ntw:l3vpn-ntw.vpn-services.vpn-service"), 1);
	snprintf(where, sizeof(where), "vpn-service");
	ATF_CHECK_MSG(same_json(w, g, where, sizeof(where)),
	    "not as merged at %s: %s", where, r.body);
	w = ucl_array_find_index(ucl_object_lookup_path(full,
	    "ietf-l3vpn-ntw:l3vpn-ntw.arcana-l3nm:sdwan.edge"), 0);
	g = ucl_array_find_index(ucl_object_lookup_path(r.json,
	    "ietf-l3vpn-ntw:l3vpn-ntw.arcana-l3nm:sdwan.edge"), 2);
	snprintf(where, sizeof(where), "edge");
	ATF_CHECK_MSG(same_json(w, g, where, sizeof(where)),
	    "not as merged at %s: %s", where, r.body);
	ATF_CHECK_STREQ("speederv2", jstr(&r, "ietf-l3vpn-ntw:l3vpn-ntw."
	    "arcana-l3nm:sdwan.edge.2.ucs-end-point.0.relay.0.plugin"));
	ATF_CHECK_STREQ("8000-8080", jstr(&r, "ietf-l3vpn-ntw:l3vpn-ntw."
	    "arcana-l3nm:sdwan.named-list.1.port.2"));
	resp_free(&r);
	/* The augments are checked as L3NM is: a security policy naming
	 * no function policy, a UCS End Point of no UCS. */
	http("PATCH", L3NM "/vpn-services/vpn-service=acme",
	    "{\"ietf-l3vpn-ntw:vpn-service\":[{\"vpn-id\":\"acme\","
	    "\"arcana-l3nm:sdwan\":{\"security-policy\":[{\"name\":\"x\","
	    "\"function-policy\":[\"nosuch\"]}]}}]}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	http("PATCH", L3NM, "{\"ietf-l3vpn-ntw:l3vpn-ntw\":{\"arcana-l3nm:"
	    "sdwan\":{\"edge\":[{\"server\":\"a\",\"ucs-end-point\":[{\"id\":"
	    "\"a-x\",\"ucs\":\"nosuch\"}]}]}}}", &r);
	ATF_CHECK_MSG(r.status == 400 || r.status == 409, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	/* A metric's value of no type refused. */
	http("PATCH", L3NM "/vpn-services/vpn-service=acme",
	    "{\"ietf-l3vpn-ntw:vpn-service\":[{\"vpn-id\":\"acme\","
	    "\"arcana-l3nm:sdwan\":{\"tca\":{\"loss\":\"2\"}}}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	ucl_object_unref(want);
	ucl_object_unref(full);
}

ATF_TC_BODY(restconf, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64];
	char		 host[128], path[256], id[16];

	start(tc, 0, NULL);
	http("GET", "/.well-known/host-meta", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "<Link rel='restconf' href='/restconf'/>") !=
	    NULL);
	resp_free(&r);
	/* Without a session: refused, as ietf-restconf's errors say it. */
	http("GET", "/restconf", NULL, &r);
	EXPECT(&r, 401);
	ATF_CHECK_STREQ("access-denied",
	    jstr(&r, "ietf-restconf:errors.error.0.error-tag"));
	resp_free(&r);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
	snprintf(host, sizeof(host), "/restconf/data/arcana-fleet:fleet/"
	    "host=%s", id);
	resp_free(&r);
	http("GET", "/restconf", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("2019-01-04",
	    jstr(&r, "ietf-restconf:restconf.yang-library-version"));
	resp_free(&r);
	http("GET", "/restconf/data/arcana-fleet:fleet", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lab", jstr(&r, "arcana-fleet:fleet.host.0.name"));
	resp_free(&r);
	/* Each host's agent mounted inline (RFC 8528). */
	http("GET", "/restconf/data/ietf-yang-schema-mount:schema-mounts",
	    NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("agent", jstr(&r, "ietf-yang-schema-mount:"
	    "schema-mounts.mount-point.0.label"));
	ATF_CHECK(strstr(r.body, "\"inline\":{}") != NULL);
	resp_free(&r);
	http("GET", "/restconf/data/ietf-restconf-monitoring:restconf-state",
	    NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("urn:ietf:params:restconf:capability:depth:1.0",
	    jstr(&r, "ietf-restconf-monitoring:restconf-state.capabilities."
	    "capability.1"));
	ATF_CHECK_STREQ(id, jstr(&r, "ietf-restconf-monitoring:restconf-state."
	    "streams.stream.0.name"));
	ATF_CHECK(strstr(r.body, "/restconf/streams/") != NULL);
	ATF_CHECK(strstr(r.body, "\"name\":\"fleet\"") != NULL &&
	    strstr(r.body, "/restconf/streams/fleet/json") != NULL);
	resp_free(&r);
	/* The host's events as Server-Sent Events: a job's comes. */
	{
		struct timeval	 tv = { 10, 0 };
		char		 rq[512], buf[16384];
		size_t		 len = 0;
		ssize_t		 n;
		int		 s, i;

		s = console_socket();
		ATF_REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) == 0);
		snprintf(rq, sizeof(rq), "GET /restconf/streams/%s/json "
		    "HTTP/1.1\r\nHost: localhost:8443\r\nCookie: %s\r\n\r\n",
		    id, cookie);
		ATF_REQUIRE(write(s, rq, strlen(rq)) == (ssize_t)strlen(rq));
		buf[0] = '\0';
		for (i = 0; i < 50 && strstr(buf, "NETCONF stream") == NULL;
		    i++) {
			if ((n = read(s, buf + len, sizeof(buf) - 1 - len)) <= 0)
				break;
			len += (size_t)n;
			buf[len] = '\0';
		}
		ATF_CHECK_MSG(strstr(buf, "200") != NULL && strstr(buf,
		    "text/event-stream") != NULL, "%s", buf);
		/* Subscribed once the thread has the host: then a job. */
		usleep(1500000);
		snprintf(path, sizeof(path), "/api/servers/%s/jobs", id);
		http("POST", path, "{\"jobs\":[{\"kind\":\"monitor\","
		    "\"verb\":\"set\",\"args\":[\"name=gre9\",\"interface="
		    "gre9\",\"address=192.0.2.9\",\"interval=500\",\"eval="
		    "10000\"]}]}", &r);
		resp_free(&r);
		for (i = 0; i < 50 && strstr(buf, "arcana-events:event") ==
		    NULL; i++) {
			if ((n = read(s, buf + len, sizeof(buf) - 1 - len)) <= 0)
				break;
			len += (size_t)n;
			buf[len] = '\0';
		}
		ATF_CHECK_MSG(strstr(buf, "\nid: 20") != NULL && strstr(buf,
		    "\ndata: {\"ietf-restconf:notification\":{\"eventTime\":")
		    != NULL && strstr(buf, "\"arcana-events:event\":") != NULL,
		    "%s", buf);
		close(s);
		/* Back with the id of one before: the agent's kept events
		 * since then first, the job's among them, then its replay
		 * said done. */
		s = console_socket();
		ATF_REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) == 0);
		snprintf(rq, sizeof(rq), "GET /restconf/streams/%s/json "
		    "HTTP/1.1\r\nHost: localhost:8443\r\nCookie: %s\r\n"
		    "Last-Event-ID: 2001-01-01T00:00:00Z\r\n\r\n", id, cookie);
		ATF_REQUIRE(write(s, rq, strlen(rq)) == (ssize_t)strlen(rq));
		len = 0;
		buf[0] = '\0';
		for (i = 0; i < 50 && strstr(buf, "replay-completed") == NULL;
		    i++) {
			if ((n = read(s, buf + len, sizeof(buf) - 1 - len)) <= 0)
				break;
			len += (size_t)n;
			buf[len] = '\0';
		}
		ATF_CHECK_MSG(strstr(buf, "\"arcana-events:event\":") != NULL &&
		    strstr(buf, "replay-completed") != NULL, "%s", buf);
		close(s);
		/* The fleet's: the same, each record in its host's entry. */
		s = console_socket();
		ATF_REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) == 0);
		snprintf(rq, sizeof(rq), "GET /restconf/streams/fleet/json "
		    "HTTP/1.1\r\nHost: localhost:8443\r\nCookie: %s\r\n"
		    "Last-Event-ID: 2001-01-01T00:00:00Z\r\n\r\n", cookie);
		ATF_REQUIRE(write(s, rq, strlen(rq)) == (ssize_t)strlen(rq));
		len = 0;
		buf[0] = '\0';
		for (i = 0; i < 50 && strstr(buf, "replay-completed") == NULL;
		    i++) {
			if ((n = read(s, buf + len, sizeof(buf) - 1 - len)) <= 0)
				break;
			len += (size_t)n;
			buf[len] = '\0';
		}
		snprintf(rq, sizeof(rq), "\"arcana-fleet:fleet\":{\"host\":"
		    "[{\"id\":\"%s\",\"arcana-events:event\":", id);
		ATF_CHECK_MSG(strstr(buf, "fleet's stream") != NULL &&
		    strstr(buf, rq) != NULL && strstr(buf,
		    "replay-completed") != NULL, "%s", buf);
		close(s);
	}
	/* A subscription of one's own (RFC 8650): POSTed, its id and URI
	 * answered; that URI's GET its stream, the operational datastore
	 * every half second; taken once. */
	snprintf(path, sizeof(path), "%s/ietf-subscribed-notifications:"
	    "establish-subscription", host);
	http("POST", path, "{\"ietf-subscribed-notifications:input\":{"
	    "\"ietf-yang-push:datastore\":\"ietf-datastores:operational\","
	    "\"ietf-yang-push:datastore-xpath-filter\":\"/ietf-interfaces:"
	    "interfaces/interface[name='lo0']/oper-status\","
	    "\"ietf-yang-push:periodic\":{\"period\":50}}}", &r);
	EXPECT(&r, 200);
	{
		struct timeval	 tv = { 10, 0 };
		char		 rq[512], buf[16384], sub[64];
		const char	*uri;
		size_t		 len = 0;
		ssize_t		 n;
		int		 s, i;

		uri = jstr(&r, "ietf-subscribed-notifications:output."
		    "ietf-restconf-subscribed-notifications:uri");
		ATF_REQUIRE_MSG(uri != NULL && strstr(uri, "/restconf/"
		    "subscriptions/") != NULL, "%s", r.body);
		snprintf(sub, sizeof(sub), "%s", strstr(uri, "/restconf/"));
		resp_free(&r);
		s = console_socket();
		ATF_REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) == 0);
		snprintf(rq, sizeof(rq), "GET %s HTTP/1.1\r\nHost: "
		    "localhost:8443\r\nCookie: %s\r\n\r\n", sub, cookie);
		ATF_REQUIRE(write(s, rq, strlen(rq)) == (ssize_t)strlen(rq));
		buf[0] = '\0';
		for (i = 0; i < 50 && strstr(buf, "push-update") == NULL;
		    i++) {
			if ((n = read(s, buf + len, sizeof(buf) - 1 - len)) <= 0)
				break;
			len += (size_t)n;
			buf[len] = '\0';
		}
		ATF_CHECK_MSG(strstr(buf, "\"ietf-yang-push:push-update\":") !=
		    NULL && strstr(buf, "\"oper-status\":\"up\"") != NULL,
		    "%s", buf);
		close(s);
		http("GET", sub, NULL, &r);
		EXPECT(&r, 404);
		resp_free(&r);
	}
	http("POST", path, "{\"ietf-subscribed-notifications:input\":{"
	    "\"stream\":\"OTHER\"}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/restconf/data/arcana-fleet:fleet", "{}", &r);
	EXPECT(&r, 405);
	resp_free(&r);
	/* A leaf of the agent's, by its path. */
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0/name", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lo0", jstr(&r, "ietf-interfaces:name"));
	resp_free(&r);
	/* An entry: depth 1 is the entry alone; content=config keeps
	 * its key and leaves out its state. */
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0?depth=1", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ_MSG("{\"ietf-interfaces:interface\":[{}]}", r.body,
	    "%s", r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0?content=config", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lo0", jstr(&r, "ietf-interfaces:interface.0.name"));
	ATF_CHECK(jstr(&r, "ietf-interfaces:interface.0.oper-status") == NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0?content=nonconfig", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("up", jstr(&r,
	    "ietf-interfaces:interface.0.oper-status"));
	resp_free(&r);
	/* fields: the members named, the key always; with-defaults: an
	 * enabled interface's enabled is its default, true. */
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0?fields=type;statistics(in-octets)", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("lo0", jstr(&r, "ietf-interfaces:interface.0.name"));
	ATF_CHECK(jstr(&r, "ietf-interfaces:interface.0.type") != NULL);
	ATF_CHECK(jstr(&r, "ietf-interfaces:interface.0.statistics.in-octets")
	    != NULL);
	ATF_CHECK(jstr(&r, "ietf-interfaces:interface.0.statistics."
	    "out-octets") == NULL);
	ATF_CHECK(jstr(&r, "ietf-interfaces:interface.0.oper-status") == NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0?with-defaults=trim", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "ietf-interfaces:interface.0.enabled") == NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=lo0?with-defaults=report-all-tagged", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ietf-interfaces:interface.0.enabled"));
	ATF_CHECK_STREQ("true", jstr(&r, "ietf-interfaces:interface.0."
	    "@enabled.ietf-netconf-with-defaults:default"));
	resp_free(&r);
	/* What is not there, a query not taken, a path that is none. */
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces/"
	    "interface=nosuch9", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 404);
	ATF_CHECK_STREQ("invalid-value",
	    jstr(&r, "ietf-restconf:errors.error.0.error-tag"));
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces?point=x",
	    host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* fields with an empty node, first or after one: refused. */
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces?fields="
	    "interface//name", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/ietf-interfaces:interfaces?fields="
	    "(name)", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), "%s/interfaces", host);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	ATF_CHECK(strstr(r.body, "named with its module") != NULL);
	resp_free(&r);
	http("GET", "/restconf/data/arcana-fleet:fleet/host=ffffffff", NULL,
	    &r);
	EXPECT(&r, 404);
	resp_free(&r);
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

CONSOLE_TC(setup_password, "The console set up by a password: the setup "
    "token, an owner's name and password; then set up, no token, no "
    "second setup; the session the user's roles, settings and keys among "
    "them; no key to sign in with until one is added; signed in again by "
    "the password")
ATF_TC_BODY(setup_password, tc)
{
	struct resp	 r;
	struct stat	 sb;
	char		*tok, body[300];

	start(tc, 0, NULL);
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "setup_required"));
	ATF_CHECK_STREQ("false", jstr(&r, "keys"));
	ATF_CHECK_STREQ("true", jstr(&r, "password_full"));
	resp_free(&r);
	tok = setup_token();
	/* Not without the token; nor a short password, nor a bad name. */
	http("POST", "/api/auth/setup/password", "{\"setup_token\":\"0000\","
	    "\"user\":\"ops\",\"password\":\"correct horse battery\"}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"setup_token\":\"%s\",\"user\":"
	    "\"ops\",\"password\":\"too short\"}", tok);
	http("POST", "/api/auth/setup/password", body, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "12 characters") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"setup_token\":\"%s\",\"user\":"
	    "\"no such name!\",\"password\":\"correct horse battery\"}", tok);
	http("POST", "/api/auth/setup/password", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	ATF_CHECK(cookie[0] == '\0');
	/* Set up: ops an owner, signed in, the session not limited. */
	snprintf(body, sizeof(body), "{\"setup_token\":\"%s\",\"user\":"
	    "\"ops\",\"password\":\"correct horse battery\"}", tok);
	http("POST", "/api/auth/setup/password", body, &r);
	ATF_CHECK_MSG(r.status == 200, "%s", r.body);
	ATF_CHECK_STREQ("ops", jstr(&r, "user"));
	ATF_CHECK_STREQ("owner", jstr(&r, "console"));
	ATF_CHECK_STREQ("true", jstr(&r, "by_password"));
	ATF_CHECK(jstr(&r, "by_token") == NULL);
	ATF_CHECK_STREQ("false", jstr(&r, "setup_required"));
	resp_free(&r);
	ATF_CHECK(cookie[0] != '\0');
	ATF_CHECK(stat("data/setup-token", &sb) == -1 && errno == ENOENT);
	http("POST", "/api/auth/setup/password", body, &r);
	EXPECT(&r, 409);
	resp_free(&r);
	free(tok);
	/* What a key's session may: the settings, the keys, a key added. */
	http("GET", "/api/settings", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/auth/credentials", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/auth/register/begin", "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("ops", jstr(&r, "publicKey.user.name"));
	resp_free(&r);
	/* Signed out: no key to sign in with, the password again. */
	http("POST", "/api/auth/logout", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "keys"));
	ATF_CHECK_STREQ("true", jstr(&r, "password"));
	resp_free(&r);
	cookie[0] = '\0';
	http("POST", "/api/auth/login/begin", "{}", &r);
	EXPECT(&r, 404);
	ATF_CHECK_STREQ("no_key", jstr(&r, "error.code"));
	resp_free(&r);
	http("POST", "/api/auth/login/password", "{\"user\":\"ops\","
	    "\"password\":\"correct horse battery\"}", &r);
	ATF_CHECK_MSG(r.status == 200, "%s", r.body);
	ATF_CHECK(jstr(&r, "by_token") == NULL);
	resp_free(&r);
	http("GET", "/api/settings", NULL, &r);
	EXPECT(&r, 200);
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

	/* Once a key exists, the setup token is no longer a way in: a
	 * request neither from our page nor marked X-Arcana is refused. */
	send_xjg = false;
	origin_hdr = NULL;
	http("POST", "/api/auth/register/begin", "{}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	send_xjg = true;
	origin_hdr = ORIGIN;

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

CONSOLE_TC(users, "Users with roles: a member sees the hosts they have a "
    "role on, a viewer reads them, an admin alone updates one; a tenant is "
    "a fleet of its own; the owner keeps the console")
ATF_TC_BODY(users, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		ha[12], hb[12], path[256], body[600], invite[80];

	start(tc, 0, NULL);
	enrol(&a);
	/* The keys from before users are the built-in owner's. */
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("admin", jstr(&r, "user"));
	ATF_CHECK_STREQ("owner", jstr(&r, "console"));
	resp_free(&r);
	http("GET", "/api/users", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("admin", jstr(&r, "users.0.name"));
	ATF_CHECK_STREQ("owner", jstr(&r, "users.0.roles.0"));
	ATF_CHECK_STREQ("owner", jstr(&r, "users.0.console"));
	ATF_CHECK_STREQ("1", jstr(&r, "users.0.keys"));
	/* The roles that come built in. */
	ATF_CHECK_STREQ("owner", jstr(&r, "roles.0.name"));
	ATF_CHECK_STREQ("admin", jstr(&r, "roles.0.hosts.*"));
	ATF_CHECK_STREQ("operator", jstr(&r, "roles.1.name"));
	ATF_CHECK_STREQ("viewer", jstr(&r, "roles.2.name"));
	ATF_CHECK_STREQ("member", jstr(&r, "roles.2.console"));
	resp_free(&r);
	http("POST", "/api/servers", "{\"name\":\"a\",\"uri\":\"tcp://"
	    "192.0.2.1:4310\"}", &r);
	EXPECT(&r, 200);
	snprintf(ha, sizeof(ha), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	http("POST", "/api/servers", "{\"name\":\"b\",\"uri\":\"tcp://"
	    "192.0.2.2:4310\",\"tenant\":\"acme\"}", &r);
	EXPECT(&r, 200);
	snprintf(hb, sizeof(hb), "%s", jstr(&r, "servers.1.id"));
	ATF_CHECK_STREQ("acme", jstr(&r, "servers.1.tenant"));
	resp_free(&r);
	/* A role, a-viewer: a member of the console, a viewer of a; bob
	 * with it.  What is refused: a console role that is not one, a
	 * host that is not an id, a user without a role, the last owner
	 * made less. */
	snprintf(body, sizeof(body), "{\"console\":\"member\",\"hosts\":{\"%s\":"
	    "\"viewer\"}}", ha);
	http("PUT", "/api/roles/a-viewer", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("a-viewer", jstr(&r, "roles.3.name"));
	ATF_CHECK_STREQ("0", jstr(&r, "roles.3.users"));
	resp_free(&r);
	http("PUT", "/api/roles/bad", "{\"console\":\"king\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", "/api/roles/bad", "{\"hosts\":{\"zz\":\"viewer\"}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", "/api/users/bob", "{\"roles\":[\"a-viewer\"]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "users.1.name"));
	ATF_CHECK_STREQ("member", jstr(&r, "users.1.console"));
	ATF_CHECK_STREQ("1", jstr(&r, "roles.3.users"));
	resp_free(&r);
	http("PUT", "/api/users/bad", "{\"tenant\":\"x\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", "/api/users/bad", "{\"roles\":[\"nosuch\"]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", "/api/users/admin", "{\"roles\":[\"viewer\"]}", &r);
	EXPECT(&r, 409);
	resp_free(&r);
	http("PUT", "/api/roles/owner", "{\"console\":\"member\",\"hosts\":{\"*\":"
	    "\"admin\"}}", &r);
	EXPECT(&r, 409);
	resp_free(&r);
	http("DELETE", "/api/roles/a-viewer", NULL, &r);
	EXPECT(&r, 409);
	resp_free(&r);
	/* Invited: a token said once, with which bob registers a key and
	 * is signed in as bob. */
	http("POST", "/api/users/bob/invite", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "token") != NULL);
	snprintf(invite, sizeof(invite), "%s", jstr(&r, "token"));
	resp_free(&r);
	http("GET", "/api/users", NULL, &r);
	ATF_CHECK_STREQ("1", jstr(&r, "users.1.invites"));
	resp_free(&r);
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "user"));
	ATF_CHECK_STREQ("member", jstr(&r, "console"));
	resp_free(&r);
	/* Used once. */
	cookie[0] = '\0';
	snprintf(body, sizeof(body), "{\"invite\":\"%s\"}", invite);
	http("POST", "/api/auth/register/begin", body, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	do_login(&b, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "user"));
	resp_free(&r);
	/* The hosts: a alone, as a viewer; b not there, and not reached. */
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(ha, jstr(&r, "servers.0.id"));
	ATF_CHECK_STREQ("viewer", jstr(&r, "servers.0.role"));
	ATF_CHECK(jstr(&r, "servers.1.id") == NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", hb);
	http("GET", path, NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", ha);
	http("POST", path, "{\"kind\":\"sysctl\",\"args\":[\"kern.hostname\"]}",
	    &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* A dry run, and a job's undo previewed, are submit's and cancel's:
	 * a viewer's neither. */
	snprintf(path, sizeof(path), "/api/servers/%s/jobs/dry-run", ha);
	http("POST", path, "{\"jobs\":[{\"kind\":\"service-action\","
	    "\"service\":\"sshd\",\"action\":\"restart\"}]}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("POST", path, "{\"undo\":1}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s", ha);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* What changes a host or the console by POST is a change, whatever
	 * the route reads: refused to a viewer. */
	snprintf(path, sizeof(path), "/api/servers/%s/transport/switch", ha);
	http("POST", path, "{\"to\":\"sctp\"}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/bird/config", ha);
	http("POST", path, "{\"text\":\"router id 10.0.0.1;\"}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* The console's own, and the fleet's tools, not a member's; the
	 * prefix lists read. */
	http("GET", "/api/settings", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", "/api/users", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", "/api/sdwan", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", "/api/workflows", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", "/api/prefix-lists", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("PUT", "/api/prefix-lists/x", "{\"prefixes\":[]}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* Their own keys alone. */
	http("GET", "/api/auth/credentials", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "credentials.0.user"));
	ATF_CHECK(jstr(&r, "credentials.1.id") == NULL);
	resp_free(&r);
	/* The owner again: bob an operator of every host of tenant acme;
	 * a is not in it, b is. */
	cookie[0] = '\0';
	do_login(&a, 1, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/auth/credentials", NULL, &r);
	ATF_CHECK(jstr(&r, "credentials.1.user") != NULL);
	resp_free(&r);
	http("PUT", "/api/roles/acme-ops", "{\"console\":\"member\",\"hosts\":"
	    "{\"*\":\"operator\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("PUT", "/api/users/bob", "{\"tenant\":\"acme\",\"roles\":"
	    "[\"acme-ops\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* a-viewer has no user now: it may go. */
	http("DELETE", "/api/roles/a-viewer", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "roles.4.name") == NULL);
	resp_free(&r);
	cookie[0] = '\0';
	do_login(&b, 2, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("acme", jstr(&r, "tenant"));
	resp_free(&r);
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(hb, jstr(&r, "servers.0.id"));
	ATF_CHECK_STREQ("operator", jstr(&r, "servers.0.role"));
	ATF_CHECK(jstr(&r, "servers.1.id") == NULL);
	resp_free(&r);
	/* An operator changes (the host is not reached here: not 403), an
	 * admin alone updates or removes. */
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", hb);
	http("POST", path, "{\"kind\":\"sysctl\",\"args\":[\"kern.hostname\"]}",
	    &r);
	ATF_CHECK_MSG(r.status != 403 && r.status != 404, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/jobs/dry-run", hb);
	http("POST", path, "{\"undo\":1}", &r);
	ATF_CHECK_MSG(r.status != 403 && r.status != 404, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/agent-update", hb);
	http("POST", path, "{}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/labels/%s/vtnet0", hb);
	http("PUT", path, "{\"label\":\"uplink\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/labels/%s/vtnet0", ha);
	http("PUT", path, "{\"label\":\"uplink\"}", &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* Removed by the owner: bob's keys and session go with him. */
	cookie[0] = '\0';
	do_login(&a, 2, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("DELETE", "/api/users/admin", NULL, &r);
	EXPECT(&r, 409);
	resp_free(&r);
	/* Groups: users given roles together; a user may do what its own
	 * roles and its groups' allow. */
	http("PUT", "/api/groups/ops", "{\"roles\":[\"operator\"],"
	    "\"members\":[\"bob\"]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("ops", jstr(&r, "groups.0.name"));
	ATF_CHECK_STREQ("bob", jstr(&r, "groups.0.members.0"));
	ATF_CHECK_STREQ("operator", jstr(&r, "users.1.console"));
	ATF_CHECK_STREQ("ops", jstr(&r, "users.1.groups.0"));
	resp_free(&r);
	http("PUT", "/api/groups/bad", "{\"roles\":[\"nosuch\"]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", "/api/groups/bad", "{\"roles\":[],\"members\":"
	    "[\"nobody\"]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* A role a group gives stays while it does. */
	http("DELETE", "/api/roles/operator", NULL, &r);
	EXPECT(&r, 409);
	ATF_CHECK(strstr(r.body, "group") != NULL);
	resp_free(&r);
	/* A user of a group alone; a user of neither is not one. */
	http("PUT", "/api/users/carl", "{\"groups\":[\"ops\"]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("operator", jstr(&r, "users.2.console"));
	resp_free(&r);
	http("PUT", "/api/users/dave", "{}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", "/api/users/dave", "{\"groups\":[\"nosuch\"]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* Gone, its members out of it: what they may do is their own
	 * roles' again. */
	http("DELETE", "/api/groups/ops", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "groups.0.name") == NULL);
	ATF_CHECK_STREQ("member", jstr(&r, "users.1.console"));
	ATF_CHECK(jstr(&r, "users.1.groups.0") == NULL);
	ATF_CHECK_STREQ("none", jstr(&r, "users.2.console"));
	resp_free(&r);
	http("DELETE", "/api/users/carl", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("DELETE", "/api/users/bob", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "users.1.name") == NULL);
	resp_free(&r);
	http("GET", "/api/auth/credentials", NULL, &r);
	ATF_CHECK(jstr(&r, "credentials.1.id") == NULL);
	resp_free(&r);
	cookie[0] = '\0';
	do_login(&b, 3, ORIGIN, RP_ID, NULL, false, &r);
	EXPECT(&r, 401);
	resp_free(&r);
}

CONSOLE_TC(csrf, "Changes need our Origin, or X-Arcana from a client "
    "without one")
ATF_TC_BODY(csrf, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[128];

	start(tc, 0, NULL);
	enrol(&a);
	/* Neither: refused. */
	send_xjg = false;
	origin_hdr = NULL;
	http("POST", "/api/servers", "{\"name\":\"x\",\"uri\":\"unix:/x.sock\"}",
	    &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* A browser's: our page's Origin is enough (over HTTP/2 its
	 * X-Arcana is lost from the second use on); another's, or none
	 * ("null"), is refused, X-Arcana or not. */
	origin_hdr = ORIGIN;
	http("POST", "/api/servers", "{\"name\":\"x\",\"uri\":\"unix:/x.sock\"}",
	    &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/servers/%s/system", jstr(&r, "id"));
	resp_free(&r);
	/* A read counted as a change for the roles (a host's system
	 * files) is still a GET: neither header is asked for, as a
	 * browser sends no Origin with one.  No agent answers there. */
	origin_hdr = NULL;
	http("GET", path, NULL, &r);
	ATF_CHECK_MSG(r.status != 403, "HTTP %d: %s", r.status, r.body);
	/* Nor can another site's page take the reply into its own, or
	 * frame it, and so on (web.c's sec_headers). */
	ATF_CHECK(strcasestr(r.head, "cross-origin-resource-policy: "
	    "same-origin") != NULL);
	ATF_CHECK(strcasestr(r.head, "x-content-type-options: nosniff") !=
	    NULL);
	ATF_CHECK(strcasestr(r.head, "frame-ancestors 'none'") != NULL);
	ATF_CHECK(strcasestr(r.head, "x-frame-options: DENY") != NULL);
	ATF_CHECK(strcasestr(r.head, "cross-origin-opener-policy: "
	    "same-origin") != NULL);
	ATF_CHECK(strcasestr(r.head, "referrer-policy: no-referrer") !=
	    NULL);
	ATF_CHECK(strcasestr(r.head, "camera=()") != NULL);
	resp_free(&r);
	/* The page itself, the same. */
	http("GET", "/", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strcasestr(r.head, "content-security-policy: default-src "
	    "'self'") != NULL);
	resp_free(&r);
	send_xjg = true;
	origin_hdr = "https://evil.example";
	http("POST", "/api/servers", "{\"name\":\"y\",\"uri\":\"unix:/y.sock\"}",
	    &r);
	EXPECT(&r, 403);
	resp_free(&r);
	origin_hdr = "null";
	http("POST", "/api/servers", "{\"name\":\"y\",\"uri\":\"unix:/y.sock\"}",
	    &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* A client without an Origin: X-Arcana. */
	origin_hdr = NULL;
	http("POST", "/api/servers", "{\"name\":\"y\",\"uri\":\"unix:/y.sock\"}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	origin_hdr = ORIGIN;
}

/* "sha384-" and the base64 of the SHA-384 of s, as the page's
 * integrity says it. */
static void
sri_of(const char *s, char *out, size_t len)
{
	unsigned char	md[EVP_MAX_MD_SIZE], b64[96];
	unsigned int	mdlen;

	EVP_Digest(s, strlen(s), md, &mdlen, EVP_sha384(), NULL);
	EVP_EncodeBlock(b64, md, (int)mdlen);
	snprintf(out, len, "sha384-%s", b64);
}

/* What the reply says of the console plugin id, at path in it. */
static const char *
cplug_str(const struct resp *r, const char *id, const char *path)
{
	const ucl_object_t	*p, *v;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((p = ucl_object_iterate(ucl_object_lookup(r->json, "plugins"),
	    &it, true)) != NULL)
		if (strcmp(ucl_object_tostring(ucl_object_lookup(p, "id")), id)
		    == 0)
			break;
	if (p == NULL || (v = ucl_object_lookup_path(p, path)) == NULL)
		return (NULL);
	return (ucl_object_tostring_forced(v));
}

static bool
has(const char *s, const char *want)
{

	return (s != NULL && strstr(s, want) != NULL);
}

CONSOLE_TC(console_plugins, "Console plugins: scanned and hashed, served "
    "only as listed, from inside their directory, once a console owner "
    "enabled them; rescanned without a restart")
ATF_TC_BODY(console_plugins, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		cwd[MAXPATHLEN], sri[128], hdr[256], owner[160];
	char		other[160], invite[80], tag[40], stag[40], tok[80];
	const char	*js = "window.x = 1;\n";

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(mkdir("plugins", 0755) == 0);
	/* A good one, with files it does not list. */
	ATF_REQUIRE(mkdir("plugins/good", 0755) == 0);
	ATF_REQUIRE(mkdir("plugins/good/img", 0755) == 0);
	put("plugins/good/plugin.json", "{\"id\":\"good\",\"name\":\"Good\","
	    "\"version\":\"1.2.0\",\"arcana\":\"0.1.0\",\"description\":"
	    "\"A test\",\"author\":\"Tests\",\"entry\":[\"main.js\"],"
	    "\"styles\":[\"look.css\"],\"assets\":[\"img/*.png\"],"
	    "\"provides\":[\"theme\"]}");
	put("plugins/good/main.js", js);
	put("plugins/good/look.css", "body { color: red; }\n");
	put("plugins/good/img/a.png", "PNG a");
	put("plugins/good/img/b.png", "PNG b");
	put("plugins/good/img/.hidden.png", "hidden");
	put("plugins/good/extra.js", "window.y = 2;\n");
	/* Its id not its directory's. */
	ATF_REQUIRE(mkdir("plugins/bad", 0755) == 0);
	put("plugins/bad/plugin.json", "{\"id\":\"other\",\"name\":\"Bad\","
	    "\"version\":\"1\",\"arcana\":\"0.1.0\"}");
	/* A file that is a link out of its directory. */
	put("outside.js", "window.secret = 1;\n");
	ATF_REQUIRE(mkdir("plugins/leak", 0755) == 0);
	put("plugins/leak/plugin.json", "{\"id\":\"leak\",\"name\":\"Leak\","
	    "\"version\":\"1\",\"arcana\":\"0.1.0\",\"entry\":[\"s.js\"]}");
	ATF_REQUIRE(symlink("../../outside.js", "plugins/leak/s.js") == 0);
	/* Of a console to come. */
	ATF_REQUIRE(mkdir("plugins/newer", 0755) == 0);
	put("plugins/newer/plugin.json", "{\"id\":\"newer\",\"name\":\"Newer\","
	    "\"version\":\"1\",\"arcana\":\"99.0.0\"}");
	/* A path out of its directory; a key not of the format. */
	ATF_REQUIRE(mkdir("plugins/up", 0755) == 0);
	put("plugins/up/plugin.json", "{\"id\":\"up\",\"name\":\"Up\","
	    "\"version\":\"1\",\"arcana\":\"0.1.0\",\"entry\":"
	    "[\"../outside.js\"]}");
	ATF_REQUIRE(mkdir("plugins/odd", 0755) == 0);
	put("plugins/odd/plugin.json", "{\"id\":\"odd\",\"name\":\"Odd\","
	    "\"version\":\"1\",\"arcana\":\"0.1.0\",\"colour\":\"red\"}");
	snprintf(harness_webconf, sizeof(harness_webconf), "plugins_dir = "
	    "\"%s/plugins\";\n", cwd);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(owner, sizeof(owner), "%s", cookie);

	/* Listed, each with why it is not served, the good one's files
	 * with their integrity. */
	http("GET", "/api/plugins", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "dir") != NULL);
	ATF_CHECK_STREQ("bad", jstr(&r, "plugins.0.id"));
	ATF_CHECK(has(cplug_str(&r, "bad", "error"), "directory"));
	ATF_CHECK(cplug_str(&r, "good", "error") == NULL);
	ATF_CHECK_STREQ("Good", cplug_str(&r, "good", "name"));
	ATF_CHECK_STREQ("1.2.0", cplug_str(&r, "good", "version"));
	ATF_CHECK_STREQ("Tests", cplug_str(&r, "good", "author"));
	ATF_CHECK_STREQ("theme", cplug_str(&r, "good", "provides.0"));
	ATF_CHECK_STREQ("false", cplug_str(&r, "good", "enabled"));
	ATF_CHECK_STREQ("main.js", cplug_str(&r, "good", "files.0.path"));
	ATF_CHECK_STREQ("script", cplug_str(&r, "good", "files.0.kind"));
	sri_of(js, sri, sizeof(sri));
	ATF_CHECK_STREQ(sri, cplug_str(&r, "good", "files.0.integrity"));
	ATF_CHECK_STREQ("style", cplug_str(&r, "good", "files.1.kind"));
	ATF_CHECK_STREQ("img/a.png", cplug_str(&r, "good", "files.2.path"));
	ATF_CHECK_STREQ("asset", cplug_str(&r, "good", "files.2.kind"));
	ATF_CHECK_STREQ("img/b.png", cplug_str(&r, "good", "files.3.path"));
	ATF_CHECK(cplug_str(&r, "good", "files.4.path") == NULL);
	ATF_CHECK(has(cplug_str(&r, "leak", "error"), "outside"));
	ATF_CHECK(cplug_str(&r, "leak", "files") == NULL);
	ATF_CHECK(has(cplug_str(&r, "newer", "error"), "needs console "
	    "99.0.0"));
	ATF_CHECK(has(cplug_str(&r, "up", "error"), "not a path"));
	ATF_CHECK(has(cplug_str(&r, "odd", "error"), "colour"));
	resp_free(&r);

	/* Not served until enabled. */
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("POST", "/api/plugins/good", "{\"enabled\":true}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", cplug_str(&r, "good", "enabled"));
	resp_free(&r);
	ATF_CHECK(access("data/console-plugins.json", F_OK) == 0);
	/* One with something wrong is not enabled; one not there neither. */
	http("POST", "/api/plugins/leak", "{\"enabled\":true}", &r);
	EXPECT(&r, 409);
	resp_free(&r);
	http("POST", "/api/plugins/nosuch", "{\"enabled\":true}", &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("POST", "/api/plugins/good", "{\"enabled\":\"yes\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* Served: its bytes, its type, its hash its tag, the console's
	 * headers. */
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ(js, r.body);
	ATF_CHECK(resp_header(&r, "content-type", hdr, sizeof(hdr)) != NULL &&
	    strncmp(hdr, "text/javascript", 15) == 0);
	ATF_CHECK(resp_header(&r, "cache-control", hdr, sizeof(hdr)) != NULL &&
	    strcmp(hdr, "no-cache") == 0);
	ATF_CHECK(resp_header(&r, "etag", hdr, sizeof(hdr)) != NULL &&
	    strncmp(hdr + 1, sri, strlen(sri)) == 0);
	ATF_CHECK(strcasestr(r.head, "x-content-type-options: nosniff") !=
	    NULL);
	ATF_CHECK(strcasestr(r.head, "content-security-policy: default-src "
	    "'self'") != NULL);
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-None-Match: \"%s\"\r\n", sri);
	http_with("GET", "/plugins/good/main.js", hdr, NULL, &r);
	EXPECT(&r, 304);
	resp_free(&r);
	http("GET", "/plugins/good/img/b.png", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(resp_header(&r, "content-type", hdr, sizeof(hdr)) != NULL &&
	    strcmp(hdr, "image/png") == 0);
	resp_free(&r);
	/* What it does not list, a hidden file, a way out: not found. */
	http("GET", "/plugins/good/extra.js", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("GET", "/plugins/good/plugin.json", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("GET", "/plugins/good/img/.hidden.png", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	http("GET", "/plugins/good/%2e%2e/%2e%2e/outside.js", NULL, &r);
	ATF_CHECK_MSG(r.status == 404, "HTTP %d", r.status);
	resp_free(&r);
	http("GET", "/plugins/good/img/..%2f..%2f..%2foutside.js", NULL, &r);
	ATF_CHECK_MSG(r.status == 404, "HTTP %d", r.status);
	resp_free(&r);
	http("GET", "/plugins/leak/s.js", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* Without a session, nothing. */
	cookie[0] = '\0';
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http("GET", "/api/plugins", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);

	/* An operator of the console, then a member: they read the list
	 * and load what is enabled, and enable or disable nothing. */
	snprintf(cookie, sizeof(cookie), "%s", owner);
	http("PUT", "/api/users/bob", "{\"roles\":[\"operator\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/users/bob/invite", NULL, &r);
	EXPECT(&r, 200);
	snprintf(invite, sizeof(invite), "%s", jstr(&r, "token"));
	resp_free(&r);
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("operator", jstr(&r, "console"));
	resp_free(&r);
	snprintf(other, sizeof(other), "%s", cookie);
	http("POST", "/api/plugins/good", "{\"enabled\":false}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", "/api/plugins", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "dir") == NULL);
	ATF_CHECK_STREQ("true", cplug_str(&r, "good", "enabled"));
	resp_free(&r);
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", owner);
	http("PUT", "/api/users/bob", "{\"roles\":[\"viewer\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", other);
	http("POST", "/api/plugins/good", "{\"enabled\":false}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("GET", "/plugins/good/look.css", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);

	/* Changed while the console runs: a plugin added, a file
	 * rewritten, a file made a link out; seen without a restart. */
	ATF_REQUIRE(mkdir("plugins/fresh", 0755) == 0);
	put("plugins/fresh/plugin.json", "{\"id\":\"fresh\",\"name\":\"Fresh\","
	    "\"version\":\"1\",\"arcana\":\"0.1.0\",\"entry\":[\"f.js\"]}");
	put("plugins/fresh/f.js", "window.f = 1;\n");
	put("plugins/good/main.js", "window.x = 2;\n");
	usleep(1200 * 1000);
	http("GET", "/api/plugins", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(cplug_str(&r, "fresh", "name") != NULL);
	ATF_CHECK(cplug_str(&r, "fresh", "error") == NULL);
	ATF_CHECK_STREQ("false", cplug_str(&r, "fresh", "enabled"));
	sri_of("window.x = 2;\n", sri, sizeof(sri));
	ATF_CHECK_STREQ(sri, cplug_str(&r, "good", "files.0.integrity"));
	resp_free(&r);
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("window.x = 2;\n", r.body);
	resp_free(&r);
	ATF_REQUIRE(unlink("plugins/good/img/b.png") == 0);
	ATF_REQUIRE(symlink("../../../outside.js", "plugins/good/img/b.png") ==
	    0);
	http("GET", "/plugins/good/img/b.png", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	usleep(1200 * 1000);
	http("GET", "/api/plugins", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(has(cplug_str(&r, "good", "error"), "outside"));
	resp_free(&r);
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	ATF_REQUIRE(unlink("plugins/good/img/b.png") == 0);
	put("plugins/good/img/b.png", "PNG b");
	usleep(1200 * 1000);
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);

	/* Its store: the owner's own, written first with no tag, then
	 * only in place of the tag read. */
	snprintf(cookie, sizeof(cookie), "%s", owner);
	http("GET", "/api/plugins/good/store", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("null", jstr(&r, "data"));
	ATF_CHECK_STREQ("null", jstr(&r, "etag"));
	resp_free(&r);
	http("PUT", "/api/plugins/good/store", "{\"level\":3}", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "etag") != NULL);
	snprintf(tag, sizeof(tag), "%s", jstr(&r, "etag"));
	resp_free(&r);
	ATF_CHECK(access("data/plugin-store/good.user.admin.json", F_OK) == 0);
	http("PUT", "/api/plugins/good/store", "{\"level\":9}", &r);
	EXPECT(&r, 412);
	resp_free(&r);
	http_with("PUT", "/api/plugins/good/store", "If-Match: \"0\"\r\n",
	    "{\"level\":9}", &r);
	EXPECT(&r, 412);
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", tag);
	http_with("PUT", "/api/plugins/good/store", hdr, "{\"level\":4,"
	    "\"seen\":[\"a\"]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "etag") != NULL && strcmp(jstr(&r, "etag"), tag) !=
	    0);
	snprintf(tag, sizeof(tag), "%s", jstr(&r, "etag"));
	resp_free(&r);
	/* The old tag is stale now. */
	http_with("PUT", "/api/plugins/good/store", hdr, "{\"level\":5}", &r);
	EXPECT(&r, 412);
	resp_free(&r);
	http("GET", "/api/plugins/good/store", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("4", jstr(&r, "data.level"));
	ATF_CHECK_STREQ("a", jstr(&r, "data.seen.0"));
	ATF_CHECK_STREQ(tag, jstr(&r, "etag"));
	ATF_CHECK(resp_header(&r, "etag", hdr, sizeof(hdr)) != NULL &&
	    strcmp(hdr, tag) == 0);
	resp_free(&r);
	/* A JSON object alone, of 16 KB at most. */
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", tag);
	http_with("PUT", "/api/plugins/good/store", hdr, "[1]", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http_with("PUT", "/api/plugins/good/store", hdr, "level = 1;", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	{
		char	*big;

		big = malloc(17 * 1024 + 16);
		ATF_REQUIRE(big != NULL);
		memcpy(big, "{\"x\":\"", 6);
		memset(big + 6, 'a', 17 * 1024);
		memcpy(big + 6 + 17 * 1024, "\"}", 3);
		http_with("PUT", "/api/plugins/good/store", hdr, big, &r);
		EXPECT(&r, 413);
		resp_free(&r);
		free(big);
	}
	/* The shared one, by the owner; not for an API token. */
	http("PUT", "/api/plugins/good/store/shared", "{\"motd\":\"hi\"}", &r);
	EXPECT(&r, 200);
	snprintf(stag, sizeof(stag), "%s", jstr(&r, "etag"));
	resp_free(&r);
	http("POST", "/api/tokens", "{\"name\":\"w\",\"kind\":\"write\"}", &r);
	EXPECT(&r, 200);
	snprintf(tok, sizeof(tok), "%s", jstr(&r, "token"));
	resp_free(&r);
	http_bearer("GET", "/api/plugins/good/store/shared", tok, NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http_bearer("PUT", "/api/plugins/good/store", tok, "{\"t\":1}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* bob, a member now: his own, empty, not the owner's; the shared
	 * one read and not written. */
	snprintf(cookie, sizeof(cookie), "%s", other);
	http("GET", "/api/plugins/good/store", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("null", jstr(&r, "data"));
	resp_free(&r);
	http("PUT", "/api/plugins/good/store", "{\"mine\":true}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/plugins/good/store", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "data.mine"));
	ATF_CHECK(jstr(&r, "data.level") == NULL);
	resp_free(&r);
	ATF_CHECK(access("data/plugin-store/good.user.bob.json", F_OK) == 0);
	http("GET", "/api/plugins/good/store/shared", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("hi", jstr(&r, "data.motd"));
	ATF_CHECK_STREQ(stag, jstr(&r, "etag"));
	resp_free(&r);
	snprintf(hdr, sizeof(hdr), "If-Match: %s\r\n", stag);
	http_with("PUT", "/api/plugins/good/store/shared", hdr,
	    "{\"motd\":\"bob\"}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* An operator writes it. */
	snprintf(cookie, sizeof(cookie), "%s", owner);
	http("PUT", "/api/users/bob", "{\"roles\":[\"operator\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", other);
	http_with("PUT", "/api/plugins/good/store/shared", hdr,
	    "{\"motd\":\"bob\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/plugins/good/store/shared", NULL, &r);
	ATF_CHECK_STREQ("bob", jstr(&r, "data.motd"));
	resp_free(&r);
	/* A plugin not there: not found. */
	http("GET", "/api/plugins/nosuch/store", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	cookie[0] = '\0';
	http("GET", "/api/plugins/good/store", NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);

	/* Disabled by the owner: not served again, its store neither,
	 * which is kept; both in the audit trail. */
	snprintf(cookie, sizeof(cookie), "%s", owner);
	http("POST", "/api/plugins/good", "{\"enabled\":false}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", cplug_str(&r, "good", "enabled"));
	resp_free(&r);
	http("GET", "/api/plugins/good/store", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	ATF_CHECK(access("data/plugin-store/good.user.admin.json", F_OK) == 0);
	snprintf(cookie, sizeof(cookie), "%s", other);
	http("GET", "/plugins/good/main.js", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* A user removed: their store with them, no one else's. */
	snprintf(cookie, sizeof(cookie), "%s", owner);
	http("DELETE", "/api/users/bob", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(access("data/plugin-store/good.user.bob.json", F_OK) == -1);
	ATF_CHECK(access("data/plugin-store/good.user.admin.json", F_OK) == 0);
	ATF_CHECK(access("data/plugin-store/good.shared.json", F_OK) == 0);
	snprintf(cookie, sizeof(cookie), "%s", owner);
	http("GET", "/api/sdwan/audit", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(has(r.body, "plugin-enabled"));
	ATF_CHECK(has(r.body, "plugin-disabled"));
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
	/* Started at boot: arcana-jails' boot committed, refused for what
	 * it has not accepted, the warning named; accepted, jail_list in
	 * Arcana's rc.conf file. */
	http("POST", path, "{\"action\":\"enable\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_STREQ("rc-conf-files", jstr(&r, "error_tag"));
	resp_free(&r);
	http("POST", path, "{\"action\":\"enable\",\"accept\":"
	    "[\"rc-conf-files\"]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("true", jstr(&r, "jail.boot"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^jail_list=\"web\"$' "
	    "root/usr/local/etc/rc.conf.d/arcana") == 0);
	http("POST", path, "{\"action\":\"disable\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("false", jstr(&r, "jail.boot"));
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
    "which puts it in place and restarts on request; compressed to an agent "
    "that takes it so, as it is to one before")
ATF_TC_BODY(agent_update, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[160], jails[160], cwd[MAXPATHLEN], body[MAXPATHLEN];
	char		old[160], jgd[MAXPATHLEN], listen[MAXPATHLEN], *argv[16];
	struct stat	sb, sbig;
	FILE		*fp;
	pid_t		pid;
	int		i;

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
	/* Sent compressed: the agent says it takes it so. */
	ATF_CHECK_MSG(strstr(r.body, "inflate(3)") != NULL, "%s", r.body);
	resp_free(&r);

	/*
	 * An agent before compressed updates, as one with no features in
	 * arcana-host: the program as it is, within a frame.
	 */
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	snprintf(listen, sizeof(listen), "unix:%s/old.sock", cwd);
	i = 0;
	argv[i++] = jgd;
	argv[i++] = (char *)(uintptr_t)"-F";
	argv[i++] = (char *)(uintptr_t)"-l";
	argv[i++] = listen;
	argv[i++] = (char *)(uintptr_t)"-f";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf";
	argv[i++] = (char *)(uintptr_t)"-D";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf.d";
	argv[i++] = (char *)(uintptr_t)"-y";
	argv[i++] = (char *)(uintptr_t)"./fake-sysrc";
	argv[i++] = (char *)(uintptr_t)"-U";
	argv[i++] = (char *)(uintptr_t)"installed-agent3";
	argv[i++] = (char *)(uintptr_t)"--features";
	argv[i++] = (char *)(uintptr_t)"none";
	argv[i] = NULL;
	pid = spawn_server(argv, "arcana-agent2.out");
	ATF_REQUIRE((fp = fopen("arcana-agent2.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);
	wait_for("old.sock");
	snprintf(body, sizeof(body), "{\"name\":\"old\",\"uri\":\"%s\"}",
	    listen);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(old, sizeof(old), "/api/servers/%s/agent-update", jstr(&r,
	    "servers.1.id"));
	resp_free(&r);
	http("POST", old, "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strcmp(jstr(&r, "ok"), "true") == 0, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "inflate") == NULL, "%s", r.body);
	ATF_CHECK(stat("installed-agent3", &sb) == 0 && stat(jgd, &sbig) == 0 &&
	    sb.st_size == sbig.st_size);
	resp_free(&r);

	/*
	 * Past a frame, the agent with 7 MiB of zeros after it: carried
	 * compressed to the one that takes it so, refused for the one
	 * before.
	 */
	snprintf(body, sizeof(body), "cat '%s' > big-agent && dd if=/dev/zero "
	    "bs=1m count=7 >> big-agent 2>/dev/null && chmod 755 big-agent",
	    jgd);
	ATF_REQUIRE(system(body) == 0);
	snprintf(body, sizeof(body), "{\"set\":{\"agent_binary\":"
	    "\"%s/big-agent\"}}", cwd);
	http("POST", "/api/settings", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strcmp(jstr(&r, "ok"), "true") == 0, "%s", r.body);
	ATF_CHECK(stat("installed-agent", &sb) == 0 && stat("big-agent",
	    &sbig) == 0 && sb.st_size == sbig.st_size);
	resp_free(&r);
	http("POST", old, "{}", &r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "ok"), "false") == 0, "%s", r.body);
	ATF_CHECK_MSG(jstr(&r, "error") != NULL && strstr(jstr(&r, "error"),
	    "takes no compressed update") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(stat("installed-agent3", &sb) == 0 && sb.st_size !=
	    sbig.st_size);
	snprintf(body, sizeof(body), "{\"set\":{\"agent_binary\":"
	    "\"%s\"}}", jgd);
	http("POST", "/api/settings", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);

	http("POST", path, "{\"restart\":true}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("true", jstr(&r, "restarting"));
	ATF_CHECK(access("installed-agent.old", F_OK) == 0);
	resp_free(&r);
}

CONSOLE_TC(monitors, "Tunnel monitors through the console: set by a job as "
    "the page sends it, read back with their settings, a refusal said, "
    "removed")
ATF_TC_BODY(monitors, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[160], jobs[160], body[512], cwd[MAXPATHLEN];
	int		i;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/servers/%s/monitors", jstr(&r,
	    "servers.0.id"));
	snprintf(jobs, sizeof(jobs), "/api/servers/%s/jobs", jstr(&r,
	    "servers.0.id"));
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"monitors\":[]") != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", jobs, "{\"jobs\":[{\"kind\":\"monitor\",\"verb\":\"set\","
	    "\"args\":[\"name=gre9\",\"interface=gre9\",\"address=192.0.2.9\","
	    "\"interval=500\",\"eval=10000\",\"delay-max=40\",\"loss-max=2\"]}]}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 100; i++) {
		http("GET", path, NULL, &r);
		if (jstr(&r, "data.monitors.0.id") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_STREQ("gre9", jstr(&r, "data.monitors.0.id"));
	ATF_CHECK_STREQ("192.0.2.9", jstr(&r, "data.monitors.0.address"));
	ATF_CHECK_STREQ("gre9", jstr(&r, "data.monitors.0.interface"));
	ATF_CHECK_STREQ("500", jstr(&r, "data.monitors.0.interval"));
	ATF_CHECK_STREQ("0.020000", jstr(&r, "data.monitors.0.tca.loss"));
	resp_free(&r);
	/* What the host refuses comes back as the job's failure. */
	http("POST", jobs, "{\"jobs\":[{\"kind\":\"monitor\",\"verb\":\"set\","
	    "\"args\":[\"name=x\",\"address=192.0.2.1\",\"loss-max=150\"]}]}",
	    &r);
	EXPECT(&r, 502);
	ATF_CHECK_MSG(strstr(r.body, "loss-max a per cent") != NULL, "%s",
	    r.body);
	resp_free(&r);
	http("POST", jobs, "{\"jobs\":[{\"kind\":\"monitor\",\"verb\":"
	    "\"remove\",\"args\":[\"name=gre9\"]}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 100; i++) {
		http("GET", path, NULL, &r);
		if (r.body != NULL && strstr(r.body, "\"monitors\":[]") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 100, "the monitor is not removed");
	resp_free(&r);

	/*
	 * As the Quality dialog sets them: arcana-probe's monitors, a YANG
	 * Patch of the host's candidate, then a confirmed commit confirmed;
	 * and taken away the same way.
	 */
	{
		char	cand[256], rpc[256], id[16];

		snprintf(id, sizeof(id), "%.*s", (int)(strlen(path) -
		    strlen("/api/servers/") - strlen("/monitors")), path +
		    strlen("/api/servers/"));
		snprintf(cand, sizeof(cand), "/restconf/ds/ietf-datastores:"
		    "candidate/arcana-fleet:fleet/host=%s/arcana-probe:probes",
		    id);
		snprintf(rpc, sizeof(rpc), "/restconf/data/arcana-fleet:fleet/"
		    "host=%s/ietf-netconf:commit", id);
		http_with("PATCH", cand, "Content-Type: application/"
		    "yang-patch+json\r\n", "{\"ietf-yang-patch:yang-patch\":{"
		    "\"patch-id\":\"quality\",\"edit\":[{\"edit-id\":\"ov-gre9\","
		    "\"operation\":\"merge\",\"target\":\"/monitor=ov-gre9\","
		    "\"value\":{\"arcana-probe:monitor\":[{\"name\":\"ov-gre9\","
		    "\"interface\":\"gre9\",\"address\":\"192.0.2.9\",\"fib\":1,"
		    "\"interval\":100,\"eval\":1000}]}}]}}", &r);
		EXPECT(&r, 200);
		resp_free(&r);
		http("POST", rpc, "{\"ietf-netconf:input\":{\"confirmed\":"
		    "[null],\"confirm-timeout\":60,\"persist\":\"q1\"}}", &r);
		EXPECT(&r, 204);
		resp_free(&r);
		http("POST", rpc, "{\"ietf-netconf:input\":{\"persist-id\":"
		    "\"q1\"}}", &r);
		EXPECT(&r, 204);
		resp_free(&r);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("ov-gre9", jstr(&r, "data.monitors.0.id"));
		ATF_CHECK_STREQ("1", jstr(&r, "data.monitors.0.fib"));
		ATF_CHECK_STREQ("100", jstr(&r, "data.monitors.0.interval"));
		resp_free(&r);
		ATF_CHECK(system("grep -q ov-gre9 monitors.json") == 0);
		http_with("PATCH", cand, "Content-Type: application/"
		    "yang-patch+json\r\n", "{\"ietf-yang-patch:yang-patch\":{"
		    "\"patch-id\":\"quality\",\"edit\":[{\"edit-id\":\"ov-gre9\","
		    "\"operation\":\"remove\",\"target\":\"/monitor=ov-gre9\"}]}}",
		    &r);
		EXPECT(&r, 200);
		resp_free(&r);
		http("POST", rpc, "{\"ietf-netconf:input\":{}}", &r);
		EXPECT(&r, 204);
		resp_free(&r);
		http("GET", path, NULL, &r);
		ATF_CHECK_MSG(r.body != NULL && strstr(r.body, "\"monitors\":[]") !=
		    NULL, "%s", r.body);
		resp_free(&r);
	}
}

CONSOLE_TC(speeder, "UDPspeeder's relay read through the console, its "
    "overhead from its log; its flags written by a safe job as the page "
    "sends it, confirmed by the console; the key in no reply")
ATF_TC_BODY(speeder, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[160], jobs[160], body[1024], cwd[MAXPATHLEN];
	int		i;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/servers/%s/speeder", jstr(&r,
	    "servers.0.id"));
	snprintf(jobs, sizeof(jobs), "/api/servers/%s/jobs", jstr(&r,
	    "servers.0.id"));
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "data.installed"));
	ATF_CHECK_STREQ("50.0", jstr(&r,
	    "data.report.client_to_server.overhead"));
	ATF_CHECK_STREQ("2", jstr(&r, "data.fec_groups.1.0"));
	resp_free(&r);
	/* The flags, by a safe job as the tab sends it. */
	http("POST", jobs, "{\"jobs\":[{\"kind\":\"speeder\",\"verb\":\"conf\","
	    "\"args\":[\"role=client\",\"listen=127.0.0.1:51821\",\"remote="
	    "192.0.2.1:14350\",\"fec=20:10\",\"report=10\",\"key=t0psecret\"],"
	    "\"safe\":true}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "t0psecret") == NULL, "%s", r.body);
	resp_free(&r);
	for (i = 0; i < 300 && system("grep -q '^arcana_relay_flags=\"-c "
	    "-l127.0.0.1:51821 -r192.0.2.1:14350 -k t0psecret -f20:10 --report "
	    "10\"$' rc.conf") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 300, "the flags are not written");
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "data.key"));
	ATF_CHECK_MSG(strstr(r.body, "t0psecret") == NULL, "%s", r.body);
	resp_free(&r);
	/* Confirmed by the console's next look: not undone after. */
	sleep(3);
	ATF_CHECK(system("grep -q '^arcana_relay_flags=\"-c ' rc.conf") == 0);
	http("GET", jobs, NULL, &r);
	ATF_CHECK_MSG(strstr(r.body, "t0psecret") == NULL && strstr(r.body,
	    "undone") == NULL, "%.800s", r.body);
	resp_free(&r);
	/* What the host refuses comes back as the job's failure. */
	http("POST", jobs, "{\"jobs\":[{\"kind\":\"speeder\",\"verb\":\"fec\","
	    "\"args\":[\"0:9\"]}]}", &r);
	EXPECT(&r, 502);
	ATF_CHECK_MSG(strstr(r.body, "fec takes the ratios") != NULL, "%s",
	    r.body);
	resp_free(&r);
}

CONSOLE_TC(smtpd, "OpenSMTPD read through the console; smtpd.conf rendered on "
    "the host from the form; a table's passwords hashed there, never read back")
ATF_TC_BODY(smtpd, tc)
{
	struct authn	a;
	struct resp	r;
	char		path[160], jobs[160], body[2048], cwd[MAXPATHLEN];
	int		i;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/servers/%s/smtpd", jstr(&r,
	    "servers.0.id"));
	snprintf(jobs, sizeof(jobs), "/api/servers/%s/jobs", jstr(&r,
	    "servers.0.id"));
	resp_free(&r);
	/* Installed (the fake), not running: no status asked. */
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "data.installed"));
	ATF_CHECK_STREQ("false", jstr(&r, "data.running"));
	ATF_CHECK(jstr(&r, "data.status") == NULL);
	resp_free(&r);
	/* A jail's (the one that runs here): read in its root, where
	 * nothing is installed. */
	snprintf(body, sizeof(body), "%s?jail=gw", path);
	http("GET", body, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "data.installed") != NULL && strcmp(jstr(&r,
	    "data.installed"), "false") == 0, "%.400s", r.body);
	ATF_CHECK_STREQ("gw", jstr(&r, "data.jail"));
	resp_free(&r);
	/* The form, as the page sends it: rendered on the host, checked by
	 * smtpd -n, written; the form kept and read back. */
	snprintf(body, sizeof(body), "{\"jobs\":[{\"kind\":\"smtpd\",\"verb\":\"conf\","
	    "\"text\":\"{\\\"listeners\\\":[{\\\"on\\\":\\\"localhost\\\"},"
	    "{\\\"on\\\":\\\"em0\\\",\\\"port\\\":587,\\\"tls\\\":\\\"tls\\\","
	    "\\\"pki\\\":\\\"mail\\\",\\\"auth\\\":true}],\\\"domains\\\":"
	    "[\\\"example.org\\\"],\\\"delivery\\\":{\\\"kind\\\":\\\"maildir\\\","
	    "\\\"aliases\\\":true}}\"}]}");
	http("POST", jobs, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "smtpd conf") != NULL, "%s", r.body);
	resp_free(&r);
	for (i = 0; i < 300 && system("grep -q '^listen on em0 port 587 tls pki "
	    "mail auth <credentials>$' smtpd.conf") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 300, "smtpd.conf is not rendered");
	ATF_CHECK(system("grep -q '^smtpd -n -f ' smtpd.log") == 0);
	ATF_CHECK(system("grep -q '^match from any for domain <domains> action "
	    "\"local\"$' smtpd.conf") == 0);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("em0", jstr(&r, "data.spec.listeners.1.on"));
	ATF_CHECK_MSG(strstr(r.body, "listen on localhost") != NULL, "%.600s",
	    r.body);
	resp_free(&r);
	/* What the host refuses comes back as the job's failure. */
	http("POST", jobs, "{\"jobs\":[{\"kind\":\"smtpd\",\"verb\":\"conf\","
	    "\"text\":\"{\\\"listeners\\\":[]}\"}]}", &r);
	EXPECT(&r, 502);
	ATF_CHECK_MSG(strstr(r.body, "a listener at least") != NULL, "%s",
	    r.body);
	resp_free(&r);
	/* Credentials: hashed on the host, the clear password nowhere. */
	http("POST", jobs, "{\"jobs\":[{\"kind\":\"smtpd\",\"verb\":\"table\","
	    "\"args\":[\"credentials\"],\"text\":\"alice hunter2\\n\"}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 300 && access("smtpd.d/credentials", F_OK) != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 300, "the table is not written");
	ATF_CHECK(system("grep -q '^alice	$6$fake$hashOf$1$' smtpd.d/credentials")
	    == 0);
	ATF_CHECK(system("grep -q '^encrypt <hunter2$' smtpd.log") == 0);
	/* The same in the jail that runs: its table under its root, its
	 * encrypt run in it (jexec), nothing of the host's touched. */
	ATF_REQUIRE(system("mkdir -p jroot/smtpd.d && rm -f smtpd.d/aliases") ==
	    0);
	http("POST", jobs, "{\"jobs\":[{\"kind\":\"smtpd\",\"verb\":\"table\","
	    "\"jail\":\"gw\",\"args\":[\"credentials\"],\"text\":\"bob pw2\\n\"}]}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 300 && system("grep -q '^bob	' jroot/smtpd.d/credentials "
	    "2>/dev/null") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 300, "the jail's table is not written under its root");
	ATF_CHECK(system("grep -q '^jexec 4 .*encrypt' jexec.log") == 0);
	ATF_CHECK(system("grep -q '^bob' smtpd.d/credentials") != 0);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("alice", jstr(&r, "data.tables.credentials.0"));
	ATF_CHECK(strstr(r.body, "hunter2") == NULL && strstr(r.body, "hashOf")
	    == NULL);
	resp_free(&r);
	/* Started (its rc.d script there, as the port installs it): its
	 * status and queue, as smtpctl says. */
	ATF_REQUIRE(mkdir("rc.d", 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(system("printf '#!/bin/sh\\n' > rc.d/smtpd && chmod +x "
	    "rc.d/smtpd") == 0);
	http("POST", jobs, "{\"jobs\":[{\"kind\":\"smtpd\",\"verb\":\"enable\","
	    "\"args\":[\"enable=yes\"]}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 300 && access("running.smtpd", F_OK) != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 300, "smtpd was not started");
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "data.running"));
	ATF_CHECK_STREQ("running", jstr(&r, "data.status.mta"));
	ATF_CHECK_STREQ("6022923fc9341b9d", jstr(&r, "data.queue.0.evpid"));
	ATF_CHECK_STREQ("(TempFail) no route", jstr(&r, "data.queue.0.error"));
	resp_free(&r);
	http("POST", jobs, "{\"jobs\":[{\"kind\":\"smtpd\",\"verb\":\"remove\","
	    "\"args\":[\"6022923fc9341b9d\"]}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 300 && system("grep -q '^smtpctl remove 6022923fc9341b9d$'"
	    " smtpd.log") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 300, "the envelope was not removed");
	http("POST", jobs, "{\"jobs\":[{\"kind\":\"smtpd\",\"verb\":\"remove\","
	    "\"args\":[\"../x\"]}]}", &r);
	EXPECT(&r, 502);
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
	/* The repository cannot be fetched: the host's reason, said. */
	ATF_REQUIRE((fp = fopen("fetch-fails", "w")) != NULL);
	fclose(fp);
	http("GET", "/api/update/notes?component=console&from=0.2.0&fresh=1",
	    NULL, &r);
	ATF_CHECK_EQ_MSG(502, r.status, "%d %s", r.status, r.body);
	ATF_CHECK_MSG(jstr(&r, "error.message") != NULL && strstr(jstr(&r,
	    "error.message"), "host key is known") != NULL, "%d %s", r.status,
	    r.body);
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
	/* Sent back compressed, kept inflated: its SHA-256 the program's. */
	ATF_CHECK_MSG(strstr(r.body, "deflate(3)") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(access("data/agent/arcana-agent", X_OK) == 0);
	snprintf(body, sizeof(body), "test \"$(sha256 -q "
	    "data/agent/arcana-agent)\" = %s", sha);
	ATF_CHECK(system(body) == 0);

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
	/* What is kept is the cookie's hash, for its user alone: a
	 * document a session. */
	ATF_CHECK(system("test \"$(ls data/sessions | wc -l)\" -eq 1") == 0);
	ATF_REQUIRE((fp = popen("cat data/sessions/*.json", "r")) != NULL);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(fread(buf, 1, sizeof(buf) - 1, fp) > 0);
	pclose(fp);
	ATF_CHECK(strstr(buf, "\"hash\"") != NULL);
	ATF_CHECK(strstr(buf, cookie + 12) == NULL);
	ATF_CHECK(system("test \"$(stat -f %Lp data/sessions/*.json)\" = 600")
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
	ATF_CHECK(system("test -z \"$(ls data/sessions)\"") == 0);
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
	ATF_CHECK(system("! grep -Ei 'exited|signal|crash|fatal' console.out") ==
	    0);
}

/*
 * A stand-in for an agent that is never whole: on ./flaky.sock it takes
 * each connection and lets it go at once, after the request, a while
 * later, or after bytes that are no frame.
 */
static pid_t
flaky_agent(void)
{
	struct sockaddr_un	sun;
	char			buf[512];
	pid_t			pid;
	int			s, c, n;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, "flaky.sock", sizeof(sun.sun_path));
	ATF_REQUIRE((s = socket(AF_UNIX, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE(bind(s, (struct sockaddr *)&sun, sizeof(sun)) == 0);
	ATF_REQUIRE(listen(s, 64) == 0);
	ATF_REQUIRE((pid = fork()) != -1);
	if (pid != 0) {
		close(s);
		return (pid);
	}
	for (n = 0;; n++) {
		if ((c = accept(s, NULL, NULL)) == -1)
			continue;
		switch (n % 4) {
		case 1:
			(void)read(c, buf, sizeof(buf));
			break;
		case 2:
			usleep(200000);
			break;
		case 3:
			(void)write(c, "\377\377\377\377 no frame", 13);
			break;
		}
		close(c);
	}
}

CONSOLE_TC(churn, "No descriptor is closed twice while the store is "
    "written, hosts fail and pages come and go")
ATF_TC_BODY(churn, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], body[1024], here[16], flaky[16];
	char		wid[16], path[160], ask[160];
	pid_t		pids[8], fake;
	int		i, k, ws, status;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	fake = flaky_agent();
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(here, sizeof(here), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"flaky\",\"uri\":\"unix:%s/"
	    "flaky.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(flaky, sizeof(flaky), "%s", jstr(&r, "servers.1.id"));
	resp_free(&r);
	/* Runs: threads that write the store as they go. */
	snprintf(body, sizeof(body), "{\"name\":\"churn\",\"hosts\":[\"%s\","
	    "\"%s\"],\"steps\":[{\"id\":\"a\",\"read\":\"hello\"},{\"id\":"
	    "\"b\",\"read\":\"jails\"},{\"id\":\"c\",\"read\":\"services\"}]}",
	    here, flaky);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	snprintf(wid, sizeof(wid), "%s", jstr(&r, "id"));
	resp_free(&r);

	for (k = 0; k < 8; k++) {
		if ((pids[k] = fork()) != 0)
			continue;
		for (i = 0; i < 30; i++) {
			switch ((i + k) % 5) {
			case 0:
				snprintf(path, sizeof(path), "/api/workflows/"
				    "%s/run", wid);
				http("POST", path, "{}", &r);
				break;
			case 1:
				snprintf(path, sizeof(path), "/api/labels/%s/"
				    "e%d", here, k);
				snprintf(body, sizeof(body), "{\"label\":\"%d\"}",
				    i);
				http("PUT", path, body, &r);
				break;
			case 2:
				snprintf(path, sizeof(path), "/api/servers/%s/"
				    "jails", here);
				http_abandon(path);
				continue;
			case 3:
				snprintf(path, sizeof(path), "/api/servers/%s/"
				    "jails", flaky);
				http("GET", path, NULL, &r);
				break;
			default:
				/* A page following both, gone at once. */
				ws = ws_open("/api/stream");
				snprintf(ask, sizeof(ask), "{\"id\":1,\"server\":"
				    "\"%s\",\"what\":\"events\"}", here);
				ws_send(ws, ask);
				snprintf(ask, sizeof(ask), "{\"id\":2,\"server\":"
				    "\"%s\",\"what\":\"events\"}", flaky);
				ws_send(ws, ask);
				snprintf(ask, sizeof(ask), "{\"id\":3,\"server\":"
				    "\"%s\",\"what\":\"sysctl\",\"filter\":"
				    "\"kern.\"}", here);
				ws_send(ws, ask);
				usleep(1000 * (useconds_t)(i % 4) * 30);
				close(ws);
				continue;
			}
			resp_free(&r);
		}
		_exit(0);
	}
	for (k = 0; k < 8; k++)
		ATF_REQUIRE(waitpid(pids[k], &status, 0) == pids[k]);
	/* The runs ended, the last of each label written. */
	for (i = 0; i < 300; i++) {
		http("GET", "/api/runs", NULL, &r);
		k = strstr(r.body, "\"running\"") != NULL;
		resp_free(&r);
		if (!k)
			break;
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 300, "runs still running");
	(void)kill(fake, SIGKILL);
	(void)waitpid(fake, NULL, 0);
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	if (system("grep -q 'Bad file descriptor' console.out") == 0)
		(void)system("grep -B2 -A2 'Bad file descriptor' console.out "
		    ">&2");
	ATF_CHECK(system("! grep -q 'Bad file descriptor' console.out") == 0);
	ATF_CHECK(system("! grep -Ei 'exited|signal|crash|fatal' "
	    "console.out") == 0);
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
		/* A commit's warnings are a service's rc.conf change's. */
		{ "{\"kind\":\"jail-action\",\"jail\":\"web\","
		    "\"action\":\"start\",\"accept\":[\"rc-conf-files\"]}",
		    "has no accept" },
	};
	for (i = 0; i < (int)nitems(bad); i++) {
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
	/* A job the console runs is in safe mode where the host can undo
	 * it; a restart it cannot, so that one was sent again without,
	 * and the step says so. */
	ATF_CHECK_STREQ("not in safe mode: the host cannot undo this one",
	    jstr(&r, "hosts.0.steps.1.error"));
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
	/* A host that cannot take the agent is named, and why, in the
	 * step's error: a run's row says it. */
	http("POST", "/api/servers", "{\"name\":\"gone\",\"uri\":"
	    "\"unix:/nonexistent/arcana.sock\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_REQUIRE(system("echo 5555555555555555555555555555555555555555 > "
	    "head") == 0);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("failed", jstr(&r, "hosts.0.steps.2.state"));
	ATF_CHECK_MSG(jstr(&r, "hosts.0.steps.2.error") != NULL && strstr(jstr(
	    &r, "hosts.0.steps.2.error"), "hosts did not take it (") != NULL &&
	    strstr(jstr(&r, "hosts.0.steps.2.error"), "gone: the host did not "
	    "answer") != NULL && strstr(jstr(&r, "hosts.0.steps.2.error"),
	    "gone: gone") == NULL, "%s", jstr(&r, "hosts.0.steps.2.error"));
	resp_free(&r);
	/*
	 * A run whose worker dies under it: once one is there again, the
	 * run, its host and the step that was running are said to be
	 * interrupted, and why; the steps after it were not run.
	 */
	ATF_REQUIRE(system("touch slow") == 0);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	sleep(2);
	ATF_REQUIRE(system("kill -9 $(sed -n 's/.*worker started (pid "
	    "\\([0-9]*\\)).*/\\1/p' console.out | tail -1)") == 0);
	(void)unlink("slow");
	for (i = 0; i < 100; i++) {
		snprintf(body, sizeof(body), "/api/runs/%s", run);
		r.status = 0;
		http("GET", body, NULL, &r);
		if (r.status == 200 && jstr(&r, "state") != NULL &&
		    strcmp(jstr(&r, "state"), "interrupted") == 0)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(i < 100, "the run was not said to be interrupted");
	ATF_CHECK_STREQ("interrupted", jstr(&r, "hosts.0.state"));
	ATF_CHECK_STREQ("interrupted", jstr(&r, "hosts.0.steps.0.state"));
	ATF_CHECK(jstr(&r, "hosts.0.steps.0.detail") != NULL && strstr(jstr(
	    &r, "hosts.0.steps.0.detail"), "the console stopped") != NULL);
	ATF_CHECK_STREQ("not run", jstr(&r, "hosts.0.steps.1.state"));
	resp_free(&r);
	/* What a run whose worker died is not, the console's end. */
	ATF_REQUIRE(system("sed -i '' '/exited with status/d' console.out") == 0);

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
	/* The next tick's, which a busy host makes late. */
	for (i = 0; i < 400; i++) {
		http("GET", "/api/runs", NULL, &r);
		if (r.body != NULL && strstr(r.body, "\"event threshold\"") !=
		    NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 400, "no run begun by the threshold");
	ATF_CHECK(r.body != NULL && strstr(r.body, "\"what\":\"mem\"") !=
	    NULL);
	resp_free(&r);
	/*
	 * A program that crashes (the kernel's line, kern.logsigexit):
	 * matched by a parameter's default, as the service-crash template
	 * does; the workflow waiting on another program is not begun.
	 */
	snprintf(body, sizeof(body), "{\"name\":\"on crash\",\"hosts\":"
	    "[\"%s\"],\"params\":[{\"name\":\"process\",\"default\":"
	    "\"arccrash\"}],\"on\":[{\"event\":\"crash\",\"match\":{"
	    "\"process\":\"${param.process}\",\"jid\":\"0\"}}],\"steps\":"
	    "[{\"id\":\"s\",\"read\":\"hello\"}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"on another crash\","
	    "\"hosts\":[\"%s\"],\"params\":[{\"name\":\"process\","
	    "\"default\":\"nginx\"}],\"on\":[{\"event\":\"crash\","
	    "\"match\":{\"process\":\"${param.process}\"}}],\"steps\":"
	    "[{\"id\":\"s\",\"read\":\"hello\"}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	if (system("[ \"$(sysctl -n kern.logsigexit)\" = 1 ] && "
	    "[ \"$(sysctl -n security.bsd.unprivileged_read_msgbuf)\" = 1 ]")
	    == 0) {
		ATF_REQUIRE(system("cp /bin/sh arccrash && ./arccrash -c "
		    "'ulimit -c 0; kill -SEGV $$'; true") == 0);
		for (i = 0; i < 200; i++) {
			http("GET", "/api/runs", NULL, &r);
			if (strstr(r.body, "\"event crash\"") != NULL)
				break;
			resp_free(&r);
			usleep(100000);
		}
		ATF_CHECK_MSG(i < 200, "no run begun by the crash");
		ATF_CHECK(strstr(r.body, "\"process\":\"arccrash\"") !=
		    NULL);
		ATF_CHECK(strstr(r.body, "\"name\":\"on crash\"") != NULL);
		ATF_CHECK(strstr(r.body, "\"name\":\"on another crash\"") ==
		    NULL);
		resp_free(&r);
	}
	/*
	 * A page following the host's events when the agent goes, as an
	 * update restarts it: told, and the worker lives on (a timer was
	 * taken out in its own callback, and the worker died of it).
	 */
	{
		char	ask[200], *m;
		int	ws, k;

		ws = ws_open("/api/stream");
		snprintf(ask, sizeof(ask), "{\"id\":5,\"server\":\"%s\","
		    "\"what\":\"events\"}", sid);
		ws_send(ws, ask);
		sleep(1);
		ATF_REQUIRE(system("kill $(cat arcana-agent.pid)") == 0);
		/* Events it told before it went, then why it is over. */
		for (k = 0; k < 50 && (m = ws_recv(ws)) != NULL; k++) {
			bool	over = strstr(m, "\"id\":5,\"error\":") != NULL;

			free(m);
			if (over)
				break;
		}
		ATF_CHECK_MSG(k < 50 && m != NULL, "no error after %d", k);
		close(ws);
		/* Its follow gone: the ticker runs on, with none. */
		sleep(1);
		ATF_CHECK(system("! grep -q 'exited with status' console.out") ==
		    0);
	}
	for (i = 0; i < 200; i++) {
		http("GET", "/api/runs", NULL, &r);
		if (strstr(r.body, "\"event host-down\"") != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	if (i == 200)
		(void)system("tail -20 console.out >&2");
	ATF_CHECK_MSG(i < 200, "no run begun by the host going away");
	/* Subscribed to, not asked every few seconds: a host that goes is
	 * known at once. */
	ATF_CHECK_MSG(i < 30, "host-down came after %d ms", i * 100);
	resp_free(&r);

	ATF_CHECK(system("! grep -q 'exited with status' console.out") == 0);
	/* The history cleared: another workflow's alone is none of
	 * these; all of it, every run that has ended, its traces too, the
	 * one going on left. */
	http("DELETE", "/api/runs?workflow=ffffffff", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("0", jstr(&r, "cleared"));
	resp_free(&r);
	http("DELETE", "/api/runs", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "cleared") != NULL && atoi(jstr(&r, "cleared"))
	    >= 1, "%s", r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "test ! -e data/runs/%s.json", run);
	ATF_CHECK(system(body) == 0);
	http("GET", "/api/runs", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"state\":\"done\"") == NULL &&
	    strstr(r.body, "\"state\":\"failed\"") == NULL, "%s", r.body);
	resp_free(&r);
	/* Gone. */
	snprintf(path, sizeof(path), "/api/workflows/%s", wid);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
}

/* Wait for a step of a run's first host to reach a state; the run in r. */
static void
step_wait(const char *n, int k, const char *state, struct resp *r)
{
	char	path[64], key[64];
	int	i;

	snprintf(path, sizeof(path), "/api/runs/%s", n);
	snprintf(key, sizeof(key), "hosts.0.steps.%d.state", k);
	for (i = 0; i < 300; i++) {
		http("GET", path, NULL, r);
		if (r->status == 200 && jstr(r, key) != NULL && strcmp(jstr(r,
		    key), state) == 0)
			return;
		resp_free(r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(0, "run %s: step %d not %s", n, k, state);
}

CONSOLE_TC(workflow_approval, "A workflow waits at an approval step until "
    "someone approves it, the run is stopped or its time is out; serial, "
    "its hosts run one after the other and a failure leaves the rest not run")
ATF_TC_BODY(workflow_approval, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[2048], sid[16], gone[16], run[32];
	char		wid[16], path[128];

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sid, sizeof(sid), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	http("POST", "/api/servers", "{\"name\":\"gone\",\"uri\":"
	    "\"unix:/nonexistent/arcana.sock\"}", &r);
	EXPECT(&r, 200);
	snprintf(gone, sizeof(gone), "%s", strcmp(jstr(&r, "servers.0.name"),
	    "gone") == 0 ? jstr(&r, "servers.0.id") : jstr(&r, "servers.1.id"));
	resp_free(&r);

	/* What an approval must say. */
	snprintf(body, sizeof(body), "{\"name\":\"bad\",\"hosts\":[\"%s\"],"
	    "\"steps\":[{\"id\":\"a\",\"approval\":{\"via\":\"all\"}}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 400);
	ATF_CHECK_MSG(strstr(r.body, "an approval says") != NULL, "%s", r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"bad\",\"hosts\":[\"%s\"],"
	    "\"steps\":[{\"id\":\"a\",\"approval\":{\"text\":\"go?\","
	    "\"timeout\":99999999}}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"bad\",\"hosts\":[\"%s\"],"
	    "\"steps\":[{\"id\":\"a\",\"approval\":{\"text\":\"go?\"},"
	    "\"read\":\"hello\"}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 400);
	ATF_CHECK_MSG(strstr(r.body, "an approval or") != NULL, "%s", r.body);
	resp_free(&r);

	/*
	 * A read, an approval, a read: the run waits at the approval with
	 * its text expanded, an approval of a step that does not wait is
	 * refused, the step approved says by whom and the run goes on.
	 */
	snprintf(body, sizeof(body), "{\"name\":\"gated\",\"hosts\":[\"%s\"],"
	    "\"steps\":[{\"id\":\"r\",\"read\":\"hello\"},"
	    "{\"id\":\"ok\",\"name\":\"Go on?\",\"approval\":{\"text\":\"Go on "
	    "with ${host.name}?\"}},{\"id\":\"s\",\"read\":\"services\"}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	snprintf(wid, sizeof(wid), "%s", jstr(&r, "id"));
	ATF_CHECK_STREQ("false", jstr(&r, "serial"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/workflows/%s/run", wid);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	step_wait(run, 1, "waiting", &r);
	ATF_CHECK_STREQ("running", jstr(&r, "state"));
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.0.state"));
	ATF_CHECK_STREQ("Go on with lab?", jstr(&r, "hosts.0.steps.1.title"));
	ATF_CHECK_STREQ("pending", jstr(&r, "hosts.0.steps.2.state"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/runs/%s/approve", run);
	http("POST", path, "{\"step\":\"s\"}", &r);
	EXPECT(&r, 409);
	ATF_CHECK(strstr(r.body, "no step s waits") != NULL);
	resp_free(&r);
	http("POST", path, "{}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", path, "{\"step\":\"ok\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("done", jstr(&r, "state"));
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.1.state"));
	ATF_CHECK_STREQ("approved by admin", jstr(&r, "hosts.0.steps.1.title"));
	ATF_CHECK_STREQ("admin", jstr(&r, "hosts.0.steps.1.trace.approved_by"));
	ATF_CHECK_STREQ("ok", jstr(&r, "approved.0.step"));
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.2.state"));
	resp_free(&r);
	/* Ended, it takes no more approvals. */
	http("POST", path, "{\"step\":\"ok\"}", &r);
	EXPECT(&r, 409);
	resp_free(&r);

	/* Stopped while it waits: the step is cancelled, and the run. */
	snprintf(path, sizeof(path), "/api/workflows/%s/run", wid);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	step_wait(run, 1, "waiting", &r);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/runs/%s", run);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("cancelled", jstr(&r, "state"));
	ATF_CHECK_STREQ("cancelled", jstr(&r, "hosts.0.steps.1.state"));
	ATF_CHECK_STREQ("stopped while it waited", jstr(&r,
	    "hosts.0.steps.1.error"));
	ATF_CHECK_STREQ("cancelled", jstr(&r, "hosts.0.steps.2.state"));
	resp_free(&r);

	/* Its time out: the step fails, and what follows a failure follows
	 * (here, on at the last step). */
	snprintf(body, sizeof(body), "{\"name\":\"timed\",\"hosts\":[\"%s\"],"
	    "\"steps\":[{\"id\":\"ok\",\"approval\":{\"text\":\"go?\","
	    "\"timeout\":1},\"on_fail\":\"s\"},{\"id\":\"x\",\"read\":\"hello\"},"
	    "{\"id\":\"s\",\"read\":\"hello\"}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	snprintf(wid, sizeof(wid), "%s", jstr(&r, "id"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/workflows/%s/run", wid);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("failed", jstr(&r, "state"));
	ATF_CHECK_STREQ("failed", jstr(&r, "hosts.0.steps.0.state"));
	ATF_CHECK_STREQ("not approved within 1 s", jstr(&r,
	    "hosts.0.steps.0.error"));
	ATF_CHECK_STREQ("not run", jstr(&r, "hosts.0.steps.1.state"));
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.2.state"));
	resp_free(&r);

	/*
	 * Serial: the hosts one after the other, in the workflow's order;
	 * the first fails (it is not there), so the second is not run.
	 * The same at once: both run, the second done.
	 */
	snprintf(body, sizeof(body), "{\"name\":\"serial\",\"serial\":true,"
	    "\"hosts\":[\"%s\",\"%s\"],\"steps\":[{\"id\":\"r\",\"read\":"
	    "\"hello\"}]}", gone, sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	snprintf(wid, sizeof(wid), "%s", jstr(&r, "id"));
	ATF_CHECK_STREQ("true", jstr(&r, "serial"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/workflows/%s/run", wid);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("failed", jstr(&r, "state"));
	ATF_CHECK_STREQ("gone", jstr(&r, "hosts.0.name"));
	ATF_CHECK_STREQ("failed", jstr(&r, "hosts.0.state"));
	ATF_CHECK_STREQ("not run", jstr(&r, "hosts.1.state"));
	ATF_CHECK_STREQ("not run", jstr(&r, "hosts.1.steps.0.state"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"id\":\"%s\",\"name\":\"serial\","
	    "\"hosts\":[\"%s\",\"%s\"],\"steps\":[{\"id\":\"r\",\"read\":"
	    "\"hello\"}]}", wid, gone, sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "serial"));
	resp_free(&r);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("failed", jstr(&r, "hosts.0.state"));
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.1.state"));
	resp_free(&r);
}

/*
 * A directory for the LDAP case: the slapd of a tree the configuration
 * names (slapd, slapd_lib for its libraries, slapd_etc for its schema),
 * on two ports of this test's own, with a CA and a certificate for
 * 127.0.0.1 made here; two users, one in the group.  Skipped without
 * it.  Its pid in slapd.pid, for the end of the case.
 */
static bool
slapd_start(const atf_tc_t *tc, int *portp, int *tlsportp)
{
	const char	*slapd, *lib, *etc;
	char		 cwd[MAXPATHLEN], cmd[8192];
	FILE		*fp;
	int		 port;

	if (!atf_tc_has_config_var(tc, "slapd"))
		return (false);
	slapd = atf_tc_get_config_var(tc, "slapd");
	lib = atf_tc_has_config_var(tc, "slapd_lib") ? atf_tc_get_config_var(tc,
	    "slapd_lib") : "/usr/local/lib";
	etc = atf_tc_has_config_var(tc, "slapd_etc") ? atf_tc_get_config_var(tc,
	    "slapd_etc") : "/usr/local/etc/openldap";
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	port = 20000 + (int)(getpid() % 20000);
	*portp = port;
	*tlsportp = port + 1;
	ATF_REQUIRE(system("openssl req -x509 -newkey ec -pkeyopt "
	    "ec_paramgen_curve:P-256 -nodes -keyout lca.key -out lca.pem -subj "
	    "'/CN=Arcana test LDAP CA' -days 2 >/dev/null 2>&1 && openssl req "
	    "-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout lsrv.key "
	    "-out lsrv.csr -subj '/CN=ldap.test' >/dev/null 2>&1 && printf "
	    "'subjectAltName=DNS:ldap.test,IP:127.0.0.1\\n' > lext && openssl "
	    "x509 -req -in lsrv.csr -CA lca.pem -CAkey lca.key -CAcreateserial "
	    "-out lsrv.pem -days 2 -extfile lext >/dev/null 2>&1") == 0);
	ATF_REQUIRE(mkdir("ldb", 0700) == 0);
	ATF_REQUIRE((fp = fopen("slapd.conf", "w")) != NULL);
	fprintf(fp, "include %s/schema/core.schema.sample\n"
	    "include %s/schema/cosine.schema.sample\n"
	    "include %s/schema/inetorgperson.schema.sample\n"
	    "include %s/schema/nis.schema.sample\n"
	    "pidfile %s/slapd.pid\nargsfile %s/slapd.args\n"
	    "modulepath %s/../libexec/openldap\nmoduleload back_mdb\n"
	    "TLSCACertificateFile %s/lca.pem\nTLSCertificateFile %s/lsrv.pem\n"
	    "TLSCertificateKeyFile %s/lsrv.key\n"
	    "database mdb\nmaxsize 67108864\nsuffix \"dc=lab,dc=test\"\n"
	    "rootdn \"cn=admin,dc=lab,dc=test\"\nrootpw labadmin\n"
	    "directory %s/ldb\nindex objectClass eq\n"
	    "access to attrs=userPassword by self write by anonymous auth by * "
	    "none\naccess to * by dn.exact=\"cn=reader,dc=lab,dc=test\" read by "
	    "users read by anonymous read\n", etc, etc, etc, etc, cwd, cwd, lib,
	    cwd, cwd, cwd, cwd);
	fclose(fp);
	ATF_REQUIRE((fp = fopen("base.ldif", "w")) != NULL);
	fputs("dn: dc=lab,dc=test\nobjectClass: dcObject\nobjectClass: "
	    "organization\ndc: lab\no: Lab\n\n"
	    "dn: cn=reader,dc=lab,dc=test\nobjectClass: organizationalRole\n"
	    "objectClass: simpleSecurityObject\ncn: reader\nuserPassword: "
	    "readerpw\n\n"
	    "dn: ou=people,dc=lab,dc=test\nobjectClass: organizationalUnit\n"
	    "ou: people\n\n"
	    "dn: uid=alice,ou=people,dc=lab,dc=test\nobjectClass: "
	    "inetOrgPerson\nuid: alice\ncn: Alice Lab\nsn: Lab\nuserPassword: "
	    "alicepw\n\n"
	    "dn: uid=bob,ou=people,dc=lab,dc=test\nobjectClass: inetOrgPerson\n"
	    "uid: bob\ncn: Bob Lab\nsn: Lab\nuserPassword: bobpw\n\n"
	    "dn: ou=groups,dc=lab,dc=test\nobjectClass: organizationalUnit\n"
	    "ou: groups\n\n"
	    "dn: cn=arcana,ou=groups,dc=lab,dc=test\nobjectClass: groupOfNames\n"
	    "cn: arcana\nmember: uid=alice,ou=people,dc=lab,dc=test\n\n"
	    "dn: cn=noc,ou=groups,dc=lab,dc=test\nobjectClass: groupOfNames\n"
	    "cn: noc\nmember: uid=alice,ou=people,dc=lab,dc=test\n", fp);
	fclose(fp);
	snprintf(cmd, sizeof(cmd), "LD_LIBRARY_PATH=%s %s/../sbin/slapadd -f "
	    "slapd.conf -l base.ldif >slapadd.out 2>&1 && LD_LIBRARY_PATH=%s %s "
	    "-f slapd.conf -h 'ldap://127.0.0.1:%d/ ldaps://127.0.0.1:%d/' "
	    ">slapd.out 2>&1", lib, lib, lib, slapd, port, port + 1);
	ATF_REQUIRE_MSG(system(cmd) == 0, "slapd did not start: %s", cmd);
	usleep(500000);
	return (true);
}

static void
slapd_stop(void)
{

	(void)system("[ -f slapd.pid ] && kill $(cat slapd.pid) 2>/dev/null; "
	    "true");
}

CONSOLE_TC(password, "A password of the console's own: set from a key's "
    "session, said as set but never its hash, kept through an edit; a "
    "sign-in with it limited as a token's under password_full = false; a "
    "wrong one, an unknown user, a short one refused; another's the "
    "owner's alone to set; taken away, the sessions it opened end; too "
    "many failures throttled")
ATF_TC_BODY(password, tc)
{
	struct authn	a, b;
	struct resp	r;
	char		keycookie[160], pwcookie[160], invite[80];
	int		i, k;

	/* The limits of a password's session, which web.conf asks for. */
	snprintf(harness_webconf, sizeof(harness_webconf), "password_full = "
	    "false;\n");
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(keycookie, sizeof(keycookie), "%s", cookie);
	/* None yet: the page offers none, and none signs in. */
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("false", jstr(&r, "password"));
	resp_free(&r);
	cookie[0] = '\0';
	http("POST", "/api/auth/login/password", "{\"user\":\"admin\","
	    "\"password\":\"correct horse battery\"}", &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* Not without a session. */
	http("POST", "/api/auth/password", "{\"password\":\"correct horse "
	    "battery\"}", &r);
	EXPECT(&r, 401);
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", keycookie);
	/* Too short, a control character; then the session's own. */
	http("POST", "/api/auth/password", "{\"password\":\"short one\"}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "12 characters") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("POST", "/api/auth/password", "{\"password\":\"correct\\thorse "
	    "battery\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/auth/password", "{\"password\":\"correct horse "
	    "battery\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("admin", jstr(&r, "user"));
	ATF_CHECK_STREQ("true", jstr(&r, "password"));
	resp_free(&r);
	/* Said as set; its hash never, nor kept anywhere but users.json. */
	http("GET", "/api/users", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "users.0.password"));
	ATF_CHECK_MSG(strstr(r.body, "$2b$") == NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '\"password\": *\"\\$2b\\$12\\$' "
	    "data/users.json") == 0);
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "password"));
	resp_free(&r);
	/* Bob, a viewer: the owner sets his, and an edit keeps it. */
	http("PUT", "/api/users/bob", "{\"roles\":[\"viewer\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/auth/password", "{\"user\":\"bob\",\"password\":"
	    "\"bob's own long password\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("PUT", "/api/users/bob", "{\"roles\":[\"viewer\",\"operator\"]}",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "users.1.password"));
	resp_free(&r);
	http("POST", "/api/auth/password", "{\"user\":\"nosuch\",\"password\":"
	    "\"a long enough one\"}", &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* Signed in by it: a wrong one and an unknown user alike refused,
	 * then bob, limited as a token's session is. */
	cookie[0] = '\0';
	http("POST", "/api/auth/login/password", "{\"user\":\"bob\","
	    "\"password\":\"not his password\"}", &r);
	ATF_CHECK_MSG(r.status == 401 && strstr(r.body, "not right") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("POST", "/api/auth/login/password", "{\"user\":\"nobody\","
	    "\"password\":\"bob's own long password\"}", &r);
	ATF_CHECK_MSG(r.status == 401 && strstr(r.body, "not right") != NULL,
	    "%s", r.body);
	resp_free(&r);
	ATF_CHECK(cookie[0] == '\0');
	http("POST", "/api/auth/login/password", "{\"user\":\"bob\","
	    "\"password\":\"bob's own long password\"}", &r);
	ATF_CHECK_MSG(r.status == 200, "%s", r.body);
	ATF_CHECK_STREQ("bob", jstr(&r, "user"));
	ATF_CHECK_STREQ("true", jstr(&r, "by_password"));
	ATF_CHECK_STREQ("true", jstr(&r, "by_token"));
	resp_free(&r);
	ATF_CHECK(cookie[0] != '\0');
	snprintf(pwcookie, sizeof(pwcookie), "%s", cookie);
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "by_password"));
	resp_free(&r);
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* Nor its own password, nor the keys, users or settings. */
	http("POST", "/api/auth/password", "{\"password\":\"a new long "
	    "password\"}", &r);
	ATF_CHECK_MSG(r.status == 403, "%s", r.body);
	resp_free(&r);
	http("GET", "/api/auth/credentials", NULL, &r);
	ATF_CHECK_MSG(r.status == 403, "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/users/bob", "{\"roles\":[\"owner\"]}", &r);
	ATF_CHECK_MSG(r.status == 403, "%s", r.body);
	resp_free(&r);
	/* Bob with a key of his own sets his, not the owner's. */
	snprintf(cookie, sizeof(cookie), "%s", keycookie);
	http("POST", "/api/users/bob/invite", NULL, &r);
	EXPECT(&r, 200);
	snprintf(invite, sizeof(invite), "%s", jstr(&r, "token"));
	resp_free(&r);
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/auth/password", "{\"user\":\"admin\",\"password\":"
	    "\"taken over now\"}", &r);
	ATF_CHECK_MSG(r.status == 403, "%s", r.body);
	resp_free(&r);
	/* Taken away by the owner: the session it opened ends. */
	snprintf(cookie, sizeof(cookie), "%s", keycookie);
	http("POST", "/api/auth/password", "{\"user\":\"bob\",\"password\":"
	    "\"\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "password"));
	resp_free(&r);
	snprintf(cookie, sizeof(cookie), "%s", pwcookie);
	for (i = 0; i < 50; i++) {
		http("GET", "/api/servers", NULL, &r);
		if (r.status == 401)
			break;
		resp_free(&r);
		usleep(100000);
	}
	EXPECT(&r, 401);
	resp_free(&r);
	/* Throttled: five failures in a minute (counted again should one
	 * begin on the way), then a wait, even for the right password. */
	cookie[0] = '\0';
	for (i = 0; i < 12; i++) {
		http("POST", "/api/auth/login/password", "{\"user\":\"admin\","
		    "\"password\":\"not the password\"}", &r);
		k = r.status;
		resp_free(&r);
		if (k == 429)
			break;
	}
	http("POST", "/api/auth/login/password", "{\"user\":\"admin\","
	    "\"password\":\"correct horse battery\"}", &r);
	ATF_CHECK_MSG(r.status == 429, "%d %s", r.status, r.body);
	resp_free(&r);
}

CONSOLE_TC(ldap, "Sign-in by LDAP over TLS: the user looked up and bound "
    "as, a group's members alone, a role by a directory group, a session "
    "limited as a token's without one; a wrong "
    "password, an unknown user, an empty password and an outsider refused; "
    "too many failures throttled; StartTLS on ldap://, ldaps:// too")
ATF_TC_BODY(ldap, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], body[2048], keycookie[160];
	int		port, tlsport, i;

	start(tc, 0, NULL);
	if (!slapd_start(tc, &port, &tlsport))
		atf_tc_skip("no slapd: give slapd, slapd_lib and slapd_etc");
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	/* Not set up: said so, and the status offers no directory. */
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("false", jstr(&r, "ldap"));
	resp_free(&r);
	http("POST", "/api/auth/login/password", "{\"user\":\"alice\",\"password\":"
	    "\"alicepw\"}", &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* A URL that is not one, refused; then the directory, by StartTLS,
	 * its CA from the file here, the reader and the group. */
	http("POST", "/api/settings", "{\"set\":{\"ldap_url\":\"http://x\"}}", &r);
	ATF_CHECK_MSG(r.status == 400, "%s", r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"set\":{\"ldap_url\":\"ldap://127.0.0.1:"
	    "%d\",\"ldap_ca\":\"%s/lca.pem\",\"ldap_base\":\"ou=people,dc=lab,"
	    "dc=test\",\"ldap_user_attr\":\"uid\",\"ldap_group\":\"cn=arcana,"
	    "ou=groups,dc=lab,dc=test\",\"ldap_bind_dn\":\"cn=reader,dc=lab,"
	    "dc=test\",\"ldap_bind_password\":\"readerpw\"}}", port, cwd);
	http("POST", "/api/settings", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "ldap"));
	resp_free(&r);
	/* A role given by a directory group: noc, alice's. */
	http("PUT", "/api/roles/noc", "{\"console\":\"member\",\"hosts\":"
	    "{\"*\":\"viewer\"},\"ldap_group\":\"cn=noc,ou=groups,dc=lab,dc=test\"}",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("cn=noc,ou=groups,dc=lab,dc=test", jstr(&r,
	    "roles.3.ldap_group"));
	resp_free(&r);
	http("PUT", "/api/roles/bad", "{\"ldap_group\":\"no dn here\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* The key's session kept aside: the sign-ins open their own. */
	snprintf(keycookie, sizeof(keycookie), "%s", cookie);
	cookie[0] = '\0';
	http("POST", "/api/auth/login/password", "{\"user\":\"alice\",\"password\":"
	    "\"\"}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "anonymous") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("POST", "/api/auth/login/password", "{\"user\":\"alice\",\"password\":"
	    "\"wrong\"}", &r);
	ATF_CHECK_MSG(r.status == 401 && strstr(r.body, "wrong password") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("POST", "/api/auth/login/password", "{\"user\":\"nobody\",\"password\":"
	    "\"x\"}", &r);
	ATF_CHECK_MSG(r.status == 401 && strstr(r.body, "no such user") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/* Bob is a user, but not of the group. */
	http("POST", "/api/auth/login/password", "{\"user\":\"bob\",\"password\":"
	    "\"bobpw\"}", &r);
	ATF_CHECK_MSG(r.status == 401 && strstr(r.body, "not a member") != NULL,
	    "%s", r.body);
	resp_free(&r);
	ATF_CHECK(cookie[0] == '\0');
	/* Alice: in, said to be by LDAP, and the user alice the console
	 * made for her, with the role of her group noc: a member of the
	 * console, a viewer of the hosts. */
	http("POST", "/api/auth/login/password", "{\"user\":\"alice\",\"password\":"
	    "\"alicepw\"}", &r);
	ATF_CHECK_MSG(r.status == 200, "%s", r.body);
	ATF_CHECK_STREQ("true", jstr(&r, "authenticated"));
	ATF_CHECK_STREQ("true", jstr(&r, "by_ldap"));
	ATF_CHECK_STREQ("alice", jstr(&r, "user"));
	ATF_CHECK_STREQ("member", jstr(&r, "console"));
	resp_free(&r);
	ATF_CHECK(cookie[0] != '\0');
	http("GET", "/api/auth/status", NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "authenticated"));
	ATF_CHECK_STREQ("true", jstr(&r, "by_ldap"));
	resp_free(&r);
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/settings", NULL, &r);
	ATF_CHECK_MSG(r.status == 403, "%s", r.body);
	resp_free(&r);
	http("GET", "/api/auth/credentials", NULL, &r);
	ATF_CHECK_MSG(r.status == 403, "%s", r.body);
	resp_free(&r);
	http("POST", "/api/auth/logout", "{}", &r);
	resp_free(&r);
	cookie[0] = '\0';
	/* Throttled: after the failures above and two more, a minute's
	 * wait, even for the right password. */
	for (i = 0; i < 3; i++) {
		http("POST", "/api/auth/login/password", "{\"user\":\"alice\","
		    "\"password\":\"wrong\"}", &r);
		resp_free(&r);
	}
	http("POST", "/api/auth/login/password", "{\"user\":\"alice\",\"password\":"
	    "\"alicepw\"}", &r);
	ATF_CHECK_MSG(r.status == 429, "%d %s", r.status, r.body);
	resp_free(&r);
	/* ldaps://, no group, anonymous lookup: bob is in. The throttle
	 * is the worker's minute: the console restarted for it. */
	snprintf(cookie, sizeof(cookie), "%s", keycookie);
	snprintf(body, sizeof(body), "{\"set\":{\"ldap_url\":\"ldaps://127.0.0.1:"
	    "%d\",\"ldap_group\":\"\",\"ldap_bind_dn\":\"\",\"ldap_bind_password\":"
	    "\"\"}}", tlsport);
	http("POST", "/api/settings", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	restart_console();
	cookie[0] = '\0';
	http("POST", "/api/auth/login/password", "{\"user\":\"bob\",\"password\":"
	    "\"bobpw\"}", &r);
	ATF_CHECK_MSG(r.status == 200, "%d %s", r.status, r.body);
	/* No group of his gives a role: no user is made for him, and the
	 * session is limited as before. */
	ATF_CHECK(jstr(&r, "user") == NULL);
	resp_free(&r);
	/* Alice's user is the directory's; bob has none. */
	snprintf(cookie, sizeof(cookie), "%s", keycookie);
	http("GET", "/api/users", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"name\":\"alice\",\"source\":\"ldap\","
	    "\"roles\":[\"noc\"]") != NULL && strstr(r.body, "\"bob\"") == NULL,
	    "%s", r.body);
	resp_free(&r);
	cookie[0] = '\0';
	/* A directory whose certificate is not trusted: refused. */
	snprintf(cookie, sizeof(cookie), "%s", keycookie);
	http("POST", "/api/settings", "{\"set\":{\"ldap_ca\":\"\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	cookie[0] = '\0';
	http("POST", "/api/auth/login/password", "{\"user\":\"bob\",\"password\":"
	    "\"bobpw\"}", &r);
	ATF_CHECK_MSG(r.status == 401 && strstr(r.body, "TLS") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	slapd_stop();
}

CONSOLE_TC(labels, "Labels on interfaces: the console's own tags, kept by "
    "server and interface; set, changed, taken away; a bad one refused; "
    "read by a token, not written by a read one")
ATF_TC_BODY(labels, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], body[400], sid[16], url[96];

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"a\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sid, sizeof(sid), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	http("GET", "/api/labels", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strcmp(r.body, "{\"labels\":{}}") == 0);
	resp_free(&r);
	snprintf(url, sizeof(url), "/api/labels/%s/vtnet0", sid);
	http("PUT", url, "{\"label\":\"uplink A, to the IXP\"}", &r);
	EXPECT(&r, 200);
	snprintf(body, sizeof(body), "labels.%s/vtnet0", sid);
	ATF_CHECK_STREQ("uplink A, to the IXP", jstr(&r, body));
	resp_free(&r);
	http("PUT", url, "{\"label\":\"a\\tb\"}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no control") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/labels/zz/../x", "{\"label\":\"x\"}", &r);
	ATF_CHECK(r.status == 400 || r.status == 404);
	resp_free(&r);
	http("PUT", url, "{\"label\":\"uplink B\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("uplink B", jstr(&r, body));
	resp_free(&r);
	http("PUT", url, "{\"label\":\"\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, body) == NULL);
	resp_free(&r);
}

CONSOLE_TC(pfxlists, "The console's prefix lists: kept by name, each a "
    "description and prefixes checked as such; changed, taken away; a bad "
    "prefix or name refused")
ATF_TC_BODY(pfxlists, tc)
{
	struct authn	a;
	struct resp	r;

	start(tc, 0, NULL);
	enrol(&a);
	http("GET", "/api/prefix-lists", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strcmp(r.body, "{\"lists\":{}}") == 0);
	resp_free(&r);
	http("PUT", "/api/prefix-lists/branches", "{\"description\":\"the "
	    "branches' networks\",\"prefixes\":[\"10.1.8.0/22\",\"2001:db8:9::/48\"]}",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("the branches' networks", jstr(&r,
	    "lists.branches.description"));
	ATF_CHECK_STREQ("2001:db8:9::/48", jstr(&r, "lists.branches.prefixes.1"));
	resp_free(&r);
	http("PUT", "/api/prefix-lists/branches", "{\"prefixes\":[\"10.1.8.1/22\"]}",
	    &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no host bits") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/prefix-lists/bad%20name", "{\"prefixes\":[]}", &r);
	ATF_CHECK(r.status == 400 || r.status == 404);
	resp_free(&r);
	http("PUT", "/api/prefix-lists/branches", "{\"prefixes\":[\"10.1.8.0/22\"]}",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "lists.branches.prefixes.1") == NULL);
	ATF_CHECK(jstr(&r, "lists.branches.description") == NULL);
	resp_free(&r);
	http("DELETE", "/api/prefix-lists/branches", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strcmp(r.body, "{\"lists\":{}}") == 0);
	resp_free(&r);
}

CONSOLE_TC(templates, "Configuration templates: a host's setup kept by "
    "name, its values {{placeholders}}, checked; applied to a host with its "
    "own values, checked first, then written; one without a value refused")
ATF_TC_BODY(templates, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], body[MAXPATHLEN], base[128], sid[16];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sid, sizeof(sid), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(base, sizeof(base), "/api/servers/%s/config", sid);

	http("GET", "/api/templates", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strcmp(r.body, "{\"templates\":[]}") == 0);
	resp_free(&r);
	/* Not kept: a secret, a path that climbs, no mode. */
	http("PUT", "/api/templates/edge", "{\"files\":[{\"path\":"
	    "\"/usr/local/etc/wireguard/wg0.conf\",\"mode\":\"0600\",\"owner\":"
	    "\"root\",\"group\":\"wheel\",\"secret\":true}]}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "carries no secrets")
	    != NULL, "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/templates/edge", "{\"files\":[{\"path\":\"/etc/../"
	    "root/x\",\"mode\":\"0644\",\"owner\":\"root\",\"group\":\"wheel\","
	    "\"text\":\"\"}]}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "without ..") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/templates/bad%20name", "{}", &r);
	ATF_CHECK(r.status == 400 || r.status == 404);
	resp_free(&r);
	/* Kept: rc.conf with the host's name and address its values, the
	 * address with a default. */
	http("PUT", "/api/templates/edge", "{\"description\":\"an edge\","
	    "\"files\":[{\"path\":\"/etc/rc.conf\",\"mode\":\"0644\",\"owner\":"
	    "\"root\",\"group\":\"wheel\",\"text\":\"hostname=\\\"{{hostname}}"
	    "\\\"\\nifconfig_lo1=\\\"inet {{address}}/32\\\"\\n# a ${shell} "
	    "word, as it is\\n\"}],\"packages\":[{\"name\":\"bird3\"}],\"variables\":{"
	    "\"address\":{\"description\":\"its loopback\",\"default\":"
	    "\"192.0.2.10\"}}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/templates", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("edge", jstr(&r, "templates.0.name"));
	ATF_CHECK_STREQ("an edge", jstr(&r, "templates.0.description"));
	ATF_CHECK_STREQ("1", jstr(&r, "templates.0.files"));
	ATF_CHECK_STREQ("hostname", jstr(&r, "templates.0.placeholders.0"));
	ATF_CHECK_STREQ("address", jstr(&r, "templates.0.placeholders.1"));
	resp_free(&r);
	/* Applied without a hostname: refused, nothing asked of the host. */
	http("POST", base, "{\"template\":\"edge\",\"dry_run\":true}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "{{hostname}} has no "
	    "value") != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", base, "{\"template\":\"nosuch\",\"dry_run\":true}", &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no template nosuch")
	    != NULL, "%s", r.body);
	resp_free(&r);
	/* Checked: what rc.conf would become, the default address in it,
	 * the shell's own ${} left alone, the package told. */
	http("POST", base, "{\"template\":\"edge\",\"values\":{\"hostname\":"
	    "\"edge7\"},\"dry_run\":true}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(r.body, "\"path\":\"/etc/rc.conf\",\"state\":"
	    "\"changed\"") != NULL && strstr(r.body, "+hostname=\\\"edge7\\\"")
	    != NULL && strstr(r.body, "+ifconfig_lo1=\\\"inet 192.0.2.10/32"
	    "\\\"") != NULL && strstr(r.body, "${shell}") != NULL, "%.600s",
	    r.body);
	ATF_CHECK(strstr(r.body, "bird3") != NULL);
	resp_free(&r);
	ATF_CHECK(system("! grep -q edge7 root/etc/rc.conf") == 0);
	/* Applied: written, the file before kept. */
	http("POST", base, "{\"template\":\"edge\",\"values\":{\"hostname\":"
	    "\"edge7\",\"address\":\"192.0.2.77\"}}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "data.applied"));
	resp_free(&r);
	ATF_CHECK(system("grep -q 'hostname=\"edge7\"' root/etc/rc.conf && "
	    "grep -q 'inet 192.0.2.77/32' root/etc/rc.conf") == 0);
	/* Forgotten. */
	http("DELETE", "/api/templates/edge", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/templates/edge", NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
}

CONSOLE_TC(config_bundle, "A host as a bundle, its secrets only when "
    "asked; another host's bundle applied here by the console, checked "
    "first, the files before kept")
ATF_TC_BODY(config_bundle, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], body[MAXPATHLEN], base[128], sid[16];
	char		*bundle, *at;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sid, sizeof(sid), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(base, sizeof(base), "/api/servers/%s/config", sid);

	/* Read: the bundle, the test's tree its files (--root). */
	http("GET", base, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("host", jstr(&r, "data.arcana"));
	ATF_CHECK(strstr(r.body, "\"path\":\"/etc/hosts\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"trace\":[") != NULL);
	resp_free(&r);
	snprintf(body, sizeof(body), "%s/export", base);
	http("POST", body, "{\"secrets\":true}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	/* The bundle as it is sent back, to be given again changed. */
	{
		struct ucl_parser	*p;
		ucl_object_t		*o;

		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
		ATF_REQUIRE(ucl_parser_add_string(p, r.body, 0));
		o = ucl_parser_get_object(p);
		ucl_parser_free(p);
		bundle = (char *)ucl_object_emit(ucl_object_lookup(o, "data"),
		    UCL_EMIT_JSON_COMPACT);
		ucl_object_unref(o);
	}
	resp_free(&r);
	ATF_REQUIRE((at = strstr(bundle, "127.0.0.1 localhost\\n")) != NULL);

	/* Another host's, read by the console itself: here it is this
	 * one, and nothing would change. */
	snprintf(body, sizeof(body), "{\"from\":\"%s\",\"dry_run\":true}", sid);
	http("POST", base, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK(strstr(r.body, "\"state\":\"changed\"") == NULL);
	ATF_CHECK(strstr(r.body, "\"state\":\"same\"") != NULL);
	resp_free(&r);
	http("POST", base, "{\"from\":\"ffffffff\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", base, "{\"dry_run\":true}", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* A bundle given: checked, then applied; the file before kept. */
	{
		char	*mod, *req;
		size_t	 n = strlen(bundle) + 64;

		mod = malloc(n);
		snprintf(mod, n, "%.*s127.0.0.1 localhost\\n192.0.2.7 db\\n%s",
		    (int)(at - bundle), bundle, at + strlen(
		    "127.0.0.1 localhost\\n"));
		ATF_REQUIRE(asprintf(&req, "{\"bundle\":%s,\"dry_run\":true}",
		    mod) != -1);
		http("POST", base, req, &r);
		EXPECT(&r, 200);
		ATF_CHECK_MSG(strstr(r.body, "\"path\":\"/etc/hosts\",\"state\":"
		    "\"changed\"") != NULL, "%.400s", r.body);
		ATF_CHECK(strstr(r.body, "+192.0.2.7 db") != NULL);
		resp_free(&r);
		ATF_CHECK(system("! grep -q 192.0.2.7 root/etc/hosts") == 0);
		free(req);
		ATF_REQUIRE(asprintf(&req, "{\"bundle\":%s}", mod) != -1);
		http("POST", base, req, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("true", jstr(&r, "data.applied"));
		resp_free(&r);
		ATF_CHECK(system("grep -q 192.0.2.7 root/etc/hosts && ! grep "
		    "-q 192.0.2.7 root/var/backups/arcana/config-*/etc/hosts")
		    == 0);
		free(req);
		free(mod);
	}
	free(bundle);
}

CONSOLE_TC(troubleshoot, "A packet followed across the hosts' jails: the "
    "way it goes, where it is stopped and why, the reply's way, and an "
    "asymmetric return a stateful firewall drops")
ATF_TC_BODY(troubleshoot, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], body[1024], sid[16];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sid, sizeof(sid), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	ts_net(cwd, "10.1.0.0/24 10.12.0.1 em0\n",
	    "65535 allow ip from any to any\n");
#define	ASK(proto, port)						\
	snprintf(body, sizeof(body), "{\"src\":\"10.1.0.2\",\"dst\":"	\
	    "\"10.3.0.2\",\"proto\":\"" proto "\",\"port\":" #port ","	\
	    "\"places\":[{\"server\":\"%s\",\"jail\":\"r1\"},{\"server\":"	\
	    "\"%s\",\"jail\":\"r2\"},{\"server\":\"%s\",\"jail\":\"r3\"}]}",	\
	    sid, sid, sid);						\
	http("POST", "/api/troubleshoot/path", body, &r);		\
	EXPECT(&r, 200)

	/* Through: in on r1 from the client's network, on to r2 by r1's
	 * default route, onto the server's network; back the same way. */
	ASK("tcp", 22);
	ATF_CHECK_STREQ("here, jail r1", jstr(&r, "hops.0.place"));
	ATF_CHECK_STREQ("em0", jstr(&r, "hops.0.ingress"));
	ATF_CHECK_STREQ("10.12.0.2", jstr(&r, "hops.0.next_hop"));
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "hops.1.place"));
	ATF_CHECK_STREQ("em0", jstr(&r, "hops.1.ingress"));
	ATF_CHECK_STREQ("em1", jstr(&r, "hops.1.egress"));
	ATF_CHECK_STREQ("delivered", jstr(&r, "end.how"));
	ATF_CHECK(jstr(&r, "hops.2.place") == NULL);
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "return.0.place"));
	ATF_CHECK_STREQ("here, jail r1", jstr(&r, "return.1.place"));
	ATF_CHECK_STREQ("delivered", jstr(&r, "return_end.how"));
	ATF_CHECK_MSG(strstr(r.body, "\"severity\":\"bad\"") == NULL &&
	    strstr(r.body, "Asymmetric") == NULL, "%.600s", r.body);
	resp_free(&r);

	/* r2's firewall: stopped there, by its rule. */
	ts_net(cwd, "10.1.0.0/24 10.12.0.1 em0\n",
	    "01000 deny tcp from any to 10.3.0.0/24 22 in\n"
	    "65535 allow ip from any to any\n");
	ASK("tcp", 22);
	ATF_CHECK_STREQ("blocked", jstr(&r, "end.how"));
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "end.place"));
	ATF_CHECK_STREQ("bad", jstr(&r, "findings.0.severity"));
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "findings.0.place"));
	/* The finding names the place to the page. */
	ATF_CHECK_STREQ(sid, jstr(&r, "findings.0.server"));
	ATF_CHECK_STREQ("r2", jstr(&r, "findings.0.jail"));
	resp_free(&r);

	/* From the Internet: no place has 203.0.113.9 nor its network; r2
	 * is the edge, its default route leaving the places asked, so the
	 * packet comes in there, on em2, and is delivered. */
	ts_net(cwd, "10.1.0.0/24 10.12.0.1 em0\n0.0.0.0/0 10.23.0.9 em2\n",
	    "65535 allow ip from any to any\n");
	snprintf(body, sizeof(body), "{\"src\":\"203.0.113.9\",\"dst\":"
	    "\"10.3.0.2\",\"proto\":\"tcp\",\"port\":443,\"places\":[{"
	    "\"server\":\"%s\",\"jail\":\"r1\"},{\"server\":\"%s\",\"jail"
	    "\":\"r2\"},{\"server\":\"%s\",\"jail\":\"r3\"}]}", sid, sid,
	    sid);
	http("POST", "/api/troubleshoot/path", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "hops.0.place"));
	ATF_CHECK_STREQ("em2", jstr(&r, "hops.0.ingress"));
	ATF_CHECK_STREQ("delivered", jstr(&r, "end.how"));
	ATF_CHECK_MSG(strstr(r.body, "comes from beyond the hosts asked") !=
	    NULL, "%.500s", r.body);
	resp_free(&r);
	ts_net(cwd, "10.1.0.0/24 10.12.0.1 em0\n",
	    "01000 deny tcp from any to 10.3.0.0/24 22 in\n"
	    "65535 allow ip from any to any\n");

	/* r3's agent call hangs: the survey waits for it no longer than
	 * its deadline, and the way is still followed by r1 and r2. */
	ATF_REQUIRE(system("touch hang-13") == 0);
	{
		time_t	t0 = time(NULL);

		ASK("tcp", 22);
		ATF_CHECK_MSG(time(NULL) - t0 < 40, "%lld s", (long long)(
		    time(NULL) - t0));
		ATF_CHECK_STREQ("here, jail r2", jstr(&r, "end.place"));
		ATF_CHECK_MSG(strstr(r.body, "no answer in 20 seconds") != NULL,
		    "%.400s", r.body);
		resp_free(&r);
	}
	ATF_REQUIRE(unlink("hang-13") == 0);

	/* One host asked alone, for its firewall tab: the walk, rule by
	 * rule, as the kernel would make it. */
	snprintf(body, sizeof(body), "/api/servers/%s/ipfw/path?src=10.1.0.2&"
	    "dst=10.3.0.2&proto=tcp&port=22&jail=r2", sid);
	http("GET", body, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("deny", jstr(&r, "data.firewall.in.verdict"));
	ATF_CHECK_STREQ("1000", jstr(&r, "data.firewall.in.walk.0.rule"));
	ATF_CHECK_STREQ("decides", jstr(&r, "data.firewall.in.walk.0.how"));
	ATF_CHECK_STREQ("em0", jstr(&r, "data.ingress.interface"));
	resp_free(&r);
	snprintf(body, sizeof(body), "/api/servers/%s/ipfw/path?src=10.1.0.2&"
	    "dst=nowhere", sid);
	http("GET", body, NULL, &r);
	EXPECT(&r, 400);
	ASK("tcp", 22);
	ATF_CHECK_MSG(strstr(jstr(&r, "findings.0.what"), "The firewall drops "
	    "it coming in on em0: rule 1000") != NULL, "%s", jstr(&r,
	    "findings.0.what"));
	ATF_CHECK(jstr(&r, "return.0.place") == NULL);
	resp_free(&r);

	/* r2 sends the reply back by r3, which saw no request: its
	 * stateful firewall drops the reply.  An ICMP echo it lets by. */
	ts_net(cwd, "10.1.0.0/24 10.23.0.3 em2\n",
	    "65535 allow ip from any to any\n");
	ASK("tcp", 22);
	ATF_CHECK_STREQ("delivered", jstr(&r, "end.how"));
	ATF_CHECK_STREQ("here, jail r2", jstr(&r, "return.0.place"));
	ATF_CHECK_STREQ("here, jail r3", jstr(&r, "return.1.place"));
	ATF_CHECK_STREQ("blocked", jstr(&r, "return_end.how"));
	ATF_CHECK_STREQ("here, jail r3", jstr(&r, "return_end.place"));
	ATF_CHECK_MSG(strstr(r.body, "The reply: The firewall drops it coming "
	    "in on em1: rule 65535") != NULL, "%.1500s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "Asymmetric across the places: the request "
	    "goes here, jail r1 → here, jail r2, the reply comes back "
	    "here, jail r3 → here, jail r2") != NULL, "%.2000s", r.body);
	resp_free(&r);
	ASK("icmp", 0);
	ATF_CHECK_STREQ("delivered", jstr(&r, "return_end.how"));
	ATF_CHECK(strstr(r.body, "\"severity\":\"bad\"") == NULL);
	ATF_CHECK(strstr(r.body, "Asymmetric across the places") != NULL);
	resp_free(&r);

	/* Who is on no place's network comes in where the route back to
	 * it leaves the places asked: r1 alone asked, by its default route,
	 * on em1. */
	snprintf(body, sizeof(body), "{\"src\":\"198.51.100.1\",\"dst\":"
	    "\"10.3.0.2\",\"places\":[{\"server\":\"%s\",\"jail\":\"r1\"}]}",
	    sid);
	http("POST", "/api/troubleshoot/path", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("em1", jstr(&r, "hops.0.ingress"));
	resp_free(&r);
	/* And with no route back to it out of them at all: not known. */
	snprintf(body, sizeof(body), "{\"src\":\"198.51.100.1\",\"dst\":"
	    "\"10.3.0.2\",\"places\":[{\"server\":\"%s\",\"jail\":\"r3\"}]}",
	    sid);
	http("POST", "/api/troubleshoot/path", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("unknown", jstr(&r, "end.how"));
	resp_free(&r);
	/* SCTP, with its port: asked as TCP and UDP are. */
	snprintf(body, sizeof(body), "{\"src\":\"198.51.100.1\",\"dst\":"
	    "\"10.3.0.2\",\"proto\":\"sctp\",\"port\":4310,\"places\":"
	    "[{\"server\":\"%s\",\"jail\":\"r1\"}]}", sid);
	http("POST", "/api/troubleshoot/path", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("sctp", jstr(&r, "proto"));
	ATF_CHECK_STREQ("em1", jstr(&r, "hops.0.ingress"));
	resp_free(&r);
	http("POST", "/api/troubleshoot/path", "{\"src\":\"10.1.0.2\","
	    "\"dst\":\"10.1.0.3\",\"proto\":\"gre\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/troubleshoot/path", "{\"src\":\"10.1.0.2\","
	    "\"dst\":\"2001:db8::1\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
#undef	ASK
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
		    "ls -l zrecv.data; tail -20 console.out; tail -20 "
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

	/*
	 * A write token changes things too, with no session's headers:
	 * but never the tokens, the console's settings, push or the CA.
	 */
	http("POST", "/api/tokens", "{\"name\":\"claude\",\"kind\":\"write\"}",
	    &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("write", jstr(&r, "kind"));
	ATF_REQUIRE(jstr(&r, "token") != NULL &&
	    strncmp(jstr(&r, "token"), "arcw_", 5) == 0);
	{
		char wtok[80];

		snprintf(wtok, sizeof(wtok), "%s", jstr(&r, "token"));
		resp_free(&r);
		http("GET", "/api/tokens", NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("read", jstr(&r, "tokens.0.kind"));
		ATF_CHECK_STREQ("write", jstr(&r, "tokens.1.kind"));
		resp_free(&r);
		http_bearer("GET", "/api/servers", wtok, NULL, &r);
		EXPECT(&r, 200);
		resp_free(&r);
		http_bearer("POST", "/api/sdwan/check", wtok, "{}", &r);
		ATF_CHECK_MSG(r.status != 401 && r.status != 403, "%d %s",
		    r.status, r.body);
		resp_free(&r);
		http_bearer("POST", "/api/tokens", wtok, "{\"name\":\"more\"}",
		    &r);
		EXPECT(&r, 403);
		ATF_CHECK(strstr(r.body, "may not change") != NULL);
		resp_free(&r);
		/* Nor who is who: a token does not make itself an owner. */
		http_bearer("PUT", "/api/users/intruder", wtok, "{\"role\":"
		    "\"owner\"}", &r);
		EXPECT(&r, 403);
		resp_free(&r);
		http_bearer("POST", "/api/groups", wtok, "{\"name\":\"g\"}",
		    &r);
		EXPECT(&r, 403);
		resp_free(&r);
		http_bearer("GET", "/api/settings", wtok, NULL, &r);
		EXPECT(&r, 403);
		resp_free(&r);
		http_bearer("POST", "/api/settings", wtok, "{}", &r);
		EXPECT(&r, 403);
		resp_free(&r);
		http_bearer("GET", "/api/push", wtok, NULL, &r);
		EXPECT(&r, 403);
		resp_free(&r);
		http_bearer("POST", "/api/ca", wtok, "{\"action\":\"make\"}", &r);
		EXPECT(&r, 403);
		resp_free(&r);
		/*
		 * Signed in on the web with it: a session that may do what
		 * the token may, no more; a read token does not sign in;
		 * deleted, the token ends the session it opened.
		 */
		{
			char	saved[sizeof(cookie)], tbody[128];

			strlcpy(saved, cookie, sizeof(saved));
			cookie[0] = '\0';
			http("POST", "/api/auth/login/token", "{\"token\":\""
			    "arcw_0000000000000000000000000000000000000000000000"
			    "000000000000000000\"}", &r);
			EXPECT(&r, 401);
			resp_free(&r);
			snprintf(tbody, sizeof(tbody), "{\"token\":\"%s\"}", token);
			http("POST", "/api/auth/login/token", tbody, &r);
			EXPECT(&r, 401);
			resp_free(&r);
			snprintf(tbody, sizeof(tbody), "{\"token\":\"%s\"}", wtok);
			http("POST", "/api/auth/login/token", tbody, &r);
			EXPECT(&r, 200);
			ATF_CHECK(strstr(r.body, "\"by_token\":true") != NULL);
			resp_free(&r);
			ATF_REQUIRE(cookie[0] != '\0');
			http("GET", "/api/auth/status", NULL, &r);
			ATF_CHECK(strstr(r.body, "\"authenticated\":true") !=
			    NULL && strstr(r.body, "\"by_token\":true") != NULL);
			resp_free(&r);
			http("GET", "/api/servers", NULL, &r);
			EXPECT(&r, 200);
			resp_free(&r);
			http("POST", "/api/sdwan/check", "{}", &r);
			ATF_CHECK_MSG(r.status != 401 && r.status != 403,
			    "%d %s", r.status, r.body);
			resp_free(&r);
			http("POST", "/api/tokens", "{\"name\":\"more\"}", &r);
			EXPECT(&r, 403);
			ATF_CHECK(strstr(r.body, "security key") != NULL);
			resp_free(&r);
			http("GET", "/api/settings", NULL, &r);
			EXPECT(&r, 403);
			resp_free(&r);
			/* The token deleted, by a key's session. */
			{
				char	tsess[sizeof(cookie)], tid[24];

				strlcpy(tsess, cookie, sizeof(tsess));
				strlcpy(cookie, saved, sizeof(cookie));
				http("GET", "/api/tokens", NULL, &r);
				EXPECT(&r, 200);
				ATF_REQUIRE(jstr(&r, "tokens.1.id") != NULL);
				snprintf(tid, sizeof(tid), "%s", jstr(&r,
				    "tokens.1.id"));
				resp_free(&r);
				snprintf(tbody, sizeof(tbody), "/api/tokens/%s", tid);
				http("DELETE", tbody, NULL, &r);
				EXPECT(&r, 200);
				resp_free(&r);
				strlcpy(cookie, tsess, sizeof(cookie));
				http("GET", "/api/servers", NULL, &r);
				EXPECT(&r, 401);
				resp_free(&r);
			}
			strlcpy(cookie, saved, sizeof(cookie));
		}
	}
	http("POST", "/api/tokens", "{\"name\":\"x\",\"kind\":\"root\"}",
	    &r);
	EXPECT(&r, 400);
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
	/* HSTS's days: 0 (none sent) to 730. */
	http("POST", "/api/settings", "{\"set\":{\"hsts_days\":\"731\"}}",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"hsts_days\":\"0\"}}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"hsts_days\":\"730\"}}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);

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

	/* How long a sign-in lasts: in its bounds, and in force. */
	http("POST", "/api/settings", "{\"set\":{\"session_idle\":\"3\"}}",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"session_max\":\"0\"}}",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"session_idle\":\"45\","
	    "\"session_max\":\"48\"}}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"session_idle\"") != NULL &&
	    strstr(r.body, "\"value\":\"45\"") != NULL && strstr(r.body,
	    "\"value\":\"48\"") != NULL, "%s", r.body);
	resp_free(&r);
	http("GET", "/api/health", NULL, &r);
	EXPECT(&r, 200);
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

/*
 * Telegram's Bot API, a sink of the test's: each request's first line
 * and body written to tg.out, answered as sent.  Its port is returned;
 * it runs in a child.
 */
static int
tg_sink(pid_t *pidp)
{
	struct sockaddr_in	 sin;
	socklen_t		 sl;
	char			 line[1024], *body;
	FILE			*io, *out;
	long			 len;
	int			 ls, fd;

	ATF_REQUIRE((ls = socket(AF_INET, SOCK_STREAM, 0)) != -1);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE(bind(ls, (struct sockaddr *)&sin, sizeof(sin)) == 0);
	ATF_REQUIRE(listen(ls, 8) == 0);
	sl = sizeof(sin);
	ATF_REQUIRE(getsockname(ls, (struct sockaddr *)&sin, &sl) == 0);
	if ((*pidp = fork()) != 0) {
		close(ls);
		return (ntohs(sin.sin_port));
	}
	for (;;) {
		if ((fd = accept(ls, NULL, NULL)) == -1)
			_exit(1);
		io = fdopen(fd, "r+");
		out = fopen("tg.out", "a");
		len = 0;
		if (fgets(line, sizeof(line), io) != NULL)
			fprintf(out, "REQ %s", line);
		while (fgets(line, sizeof(line), io) != NULL && strcmp(line,
		    "\r\n") != 0)
			if (strncasecmp(line, "Content-Length:", 15) == 0)
				len = strtol(line + 15, NULL, 10);
		if (len > 0 && len < 65536 && (body = calloc(1, (size_t)len +
		    1)) != NULL) {
			if (fread(body, 1, (size_t)len, io) == (size_t)len)
				fprintf(out, "%s\n", body);
			free(body);
		}
		fclose(out);
		fputs("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
		    "Content-Length: 11\r\nConnection: close\r\n\r\n"
		    "{\"ok\":true}", io);
		fclose(io);
	}
}

CONSOLE_TC(telegram, "Alerts and a workflow's message to Telegram chats, "
    "by a bot, sent by an agent; its token never read back")
ATF_TC_BODY(telegram, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], body[MAXPATHLEN], path[160], sid[16];
	char		run[32];
	pid_t		sink;
	int		port, i;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	port = tg_sink(&sink);
	snprintf(harness_telegram_api, sizeof(harness_telegram_api),
	    "http://127.0.0.1:%d", port);
	snprintf(harness_webconf, sizeof(harness_webconf), "mail_tick = 1;\n");
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sid, sizeof(sid), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	/* Not a token, not a chat: refused. */
	http("POST", "/api/settings", "{\"set\":{\"telegram_token\":"
	    "\"x y\"}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"telegram_chats\":"
	    "\"-100 x;y\"}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"telegram_token\":"
	    "\"123:abc_DEF\",\"telegram_chats\":\"-100 42\","
	    "\"telegram_via\":\"here\",\"telegram_jobs\":\"failed\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/settings", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "abc_DEF") == NULL);
	resp_free(&r);
	/* The test: to each chat, by the host's agent. */
	http("POST", "/api/settings/telegram-test", "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("-100 42", jstr(&r, "to"));
	resp_free(&r);
	ATF_CHECK(system("grep -c '^REQ POST /bot123:abc_DEF/sendMessage' "
	    "tg.out | grep -qx 2 && grep -q '\"chat_id\":-100,' tg.out && "
	    "grep -q '\"chat_id\":42,' tg.out && grep -q '\"text\":\"🛰️ Arcana: "
	    "a test.' tg.out") == 0);
	/* How many jobs of pkg in jails run at once: set, said by the
	 * jobs list, and refused outside 1 to 32. */
	snprintf(path, sizeof(path), "/api/servers/%s/jobs/config", sid);
	http("POST", path, "{\"lanes\":3}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("3", jstr(&r, "lanes"));
	resp_free(&r);
	http("POST", path, "{\"lanes\":0}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", sid);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("3", jstr(&r, "lanes"));
	resp_free(&r);
	/* A job that failed, told within a tick or two. */
	sleep(2);
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", sid);
	http("POST", path, "{\"jobs\":[{\"kind\":\"cert\",\"verb\":"
	    "\"trust\",\"path\":\"nosuch.0\"}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 150 && system("grep -q 'failed: certificate trust "
	    "nosuch.0' tg.out") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(system("grep -q '❌ here · job [0-9]* failed.ncertificate "
	    "trust nosuch.0.n⚠️ [^\"]*.n🕒 [0-9:]*\"' tg.out") == 0,
	    "no message of the job");
	/* A workflow's notify step: its text made for the host. */
	http("POST", "/api/workflows", "{\"name\":\"bad\",\"steps\":[{\"id\":"
	    "\"t\",\"notify\":{\"via\":\"pigeon\",\"text\":\"x\"}}]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"tell\",\"hosts\":[\"%s\"],"
	    "\"steps\":[{\"id\":\"t\",\"notify\":{\"via\":\"telegram\","
	    "\"text\":\"${host.name} said hi\"}},{\"id\":\"m\",\"notify\":{"
	    "\"via\":\"mail\",\"text\":\"x\"}}]}", sid);
	http("POST", "/api/workflows", body, &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/workflows/%s/run", jstr(&r, "id"));
	resp_free(&r);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	snprintf(run, sizeof(run), "%s", jstr(&r, "run"));
	resp_free(&r);
	run_wait(run, &r);
	ATF_CHECK_STREQ("done", jstr(&r, "hosts.0.steps.0.state"));
	ATF_CHECK_STREQ("here said hi", jstr(&r, "hosts.0.steps.0.trace.text"));
	/* Mail is not set up: the step says so. */
	ATF_CHECK_STREQ("failed", jstr(&r, "hosts.0.steps.1.state"));
	ATF_CHECK_MSG(jstr(&r, "hosts.0.steps.1.error") != NULL && strstr(
	    jstr(&r, "hosts.0.steps.1.error"), "mail is not set up") != NULL,
	    "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q 'workflow tell on here.n.nhere said hi' "
	    "tg.out") == 0);
	ATF_CHECK(system("! grep -q abc_DEF arcana-agent.out") == 0);
	(void)kill(sink, SIGTERM);
	(void)waitpid(sink, NULL, 0);
}

static void	pki(const char *, const char *, const char *);

CONSOLE_TC(mail, "Faults, jobs and runs mailed by sendmail(8), as the "
    "settings say")
ATF_TC_BODY(mail, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], body[MAXPATHLEN], path[160];
	int		i;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	/* The hosts' events read each second, not each fifteen. */
	snprintf(harness_webconf, sizeof(harness_webconf), "mail_tick = 1;\n");
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(body, sizeof(body), "{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", jstr(&r,
	    "servers.0.id"));
	resp_free(&r);
	/* No one to mail to: said so. */
	http("POST", "/api/settings/mail-test", "{}", &r);
	EXPECT(&r, 502);
	ATF_CHECK_STREQ("no address to mail to", jstr(&r, "error.message"));
	resp_free(&r);
	/* Addresses only, nothing a header could be made of. */
	http("POST", "/api/settings", "{\"set\":{\"mail_to\":\"ops\"}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"mail_to\":\"ops@example.org"
	    "\\nBcc: x@example.org\"}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"mail_jobs\":\"some\"}}",
	    &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"mail_to\":\"ops@example.org,"
	    " noc@example.org\",\"mail_jobs\":\"failed\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/settings/mail-test", "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("ops@example.org, noc@example.org", jstr(&r, "to"));
	resp_free(&r);
	ATF_CHECK(system("grep -qx 'ARGS -t -i' mail.out && grep -qx 'To: "
	    "ops@example.org, noc@example.org' mail.out && grep -qx 'Subject: "
	    "Arcana: a test' mail.out && grep -q '^From: Arcana <arcana@' "
	    "mail.out && grep -qx 'Auto-Submitted: auto-generated' mail.out")
	    == 0);
	/* The host's events read from here on: a job failed is mailed,
	 * one done is not. */
	sleep(3);
	http("POST", path, "{\"jobs\":[{\"kind\":\"cert\",\"verb\":"
	    "\"rehash\"},{\"kind\":\"cert\",\"verb\":\"trust\",\"path\":"
	    "\"nosuch.0\"}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 150 && system("grep -q 'failed: certificate trust "
	    "nosuch.0' mail.out") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(system("grep -q '^Subject: Arcana: [0-9:]* here: job "
	    "[0-9]* failed: certificate trust nosuch.0' mail.out") == 0,
	    "no mail of the job");
	ATF_CHECK(system("grep -q 'certificate rehash' mail.out") != 0);
	/* None: nothing more. */
	http("POST", "/api/settings", "{\"set\":{\"mail_to\":\"\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
}

CONSOLE_TC(services, "Services listed, acted on and configured through "
    "arcana-services: a GET, its actions, its configuration committed with "
    "the warnings accepted")
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
	/* Enabled: a commit, refused for what it has not accepted, the
	 * warning named; with it accepted, Arcana's rc.conf file has it. */
	snprintf(path, sizeof(path), "%s/ntpd/action", base);
	http("POST", path, "{\"action\":\"enable\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_STREQ("rc-conf-files", jstr(&r, "error_tag"));
	ATF_CHECK_STREQ("false", jstr(&r, "service.enabled"));
	resp_free(&r);
	http("POST", path, "{\"action\":\"enable\",\"accept\":"
	    "[\"rc-conf-files\"]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("true", jstr(&r, "service.enabled"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^ntpd_enable=\"YES\"$' "
	    "root/usr/local/etc/rc.conf.d/arcana") == 0);

	snprintf(path, sizeof(path), "%s/sshd/config", base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("-4", jstr(&r, "variables.sshd_flags"));
	ATF_CHECK_STREQ("The sshd daemon.", jstr(&r, "description"));
	ATF_CHECK_STREQ("reload", jstr(&r, "commands.0"));
	ATF_CHECK_STREQ("true", jstr(&r, "service.enabled"));
	resp_free(&r);
	/* Yours sets it: taken by Arcana once accepted. */
	http("POST", path, "{\"set\":{\"sshd_flags\":\"-6\"},\"unset\":"
	    "[\"sshd_nothing\"]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_STREQ("rc-conf-conflict", jstr(&r, "error_tag"));
	ATF_CHECK_STREQ("-4", jstr(&r, "variables.sshd_flags"));
	resp_free(&r);
	http("POST", path, "{\"set\":{\"sshd_flags\":\"-6\"},\"unset\":"
	    "[\"sshd_nothing\"],\"accept\":[\"rc-conf-conflict\"]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("-6", jstr(&r, "variables.sshd_flags"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^sshd_flags=\"-6\"$' "
	    "root/usr/local/etc/rc.conf.d/arcana && grep -q "
	    "'^#sshd_flags=\"-4\"  # taken by Arcana$' root/etc/rc.conf") ==
	    0);
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

	/* A dry run: the steps the job would take, said by the agent,
	 * service(8)'s start not run; a job's undo with none waiting, or
	 * a body that is neither, refused. */
	snprintf(path, sizeof(path), "%.*s/jobs/dry-run",
	    (int)(strlen(base) - strlen("/services")), base);
	(void)unlink("running.ntpd");
	http("POST", path, "{\"jobs\":[{\"kind\":\"service-action\","
	    "\"service\":\"ntpd\",\"action\":\"start\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("daemon", jstr(&r, "steps.0.kind"));
	ATF_CHECK_STREQ("arcana-agent", jstr(&r, "steps.0.label"));
	ATF_CHECK_STREQ("-1", jstr(&r, "steps.0.parent"));
	ATF_CHECK_MSG(strstr(r.body, "fake-service ntpd start\",\"detail\":"
	    "\"not run: a dry run\"") != NULL, "%s", r.body);
	ATF_CHECK(jstr(&r, "notes") != NULL);
	resp_free(&r);
	ATF_CHECK(access("running.ntpd", F_OK) == -1);
	http("POST", path, "{\"undo\":424242}", &r);
	EXPECT(&r, 502);
	ATF_CHECK_STREQ("no such job", jstr(&r, "error.message"));
	resp_free(&r);
	http("POST", path, "{\"undo\":\"x\"}", &r);
	EXPECT(&r, 400);
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
	/* From one of pkg's repositories (pkg upgrade -r); one it has not,
	 * refused by the agent. */
	http("POST", path, "{\"packages\":[\"pimd\"],\"dry_run\":true,"
	    "\"pkg_repo\":\"builder\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^upgrade -r builder -n pimd$' pkg.log") ==
	    0);
	http("POST", path, "{\"dry_run\":true,\"pkg_repo\":\"nosuch\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_MSG(jstr(&r, "error") != NULL && strstr(jstr(&r, "error"),
	    "pkg has no repository nosuch") != NULL, "%s", r.body);
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
	/* The same rows by the standard models (ytrans.c), as the Network
	 * tab asks: a GET of cblink's YANG family, translated. */
	{
		static const char *const same[] = { "name", "up", "mtu",
		    "ether" };
		char	*was[nitems(same)], *addrs[32];
		char	 p2[512], key[64];
		size_t	 k, na, nb;
		bool	 found;

		for (k = 0; k < nitems(same); k++) {
			snprintf(key, sizeof(key), "data.interfaces.0.%s",
			    same[k]);
			was[k] = jstr(&r, key) != NULL ? strdup(jstr(&r, key)) :
			    NULL;
		}
		/* Its addresses, "address/prefixlen", in whatever order. */
		for (na = 0; na < nitems(addrs); na++) {
			snprintf(key, sizeof(key), "data.interfaces.0."
			    "addresses.%zu.address", na);
			if (jstr(&r, key) == NULL)
				break;
			snprintf(p2, sizeof(p2), "%s/%s", jstr(&r, key), (
			    snprintf(key, sizeof(key), "data.interfaces.0."
			    "addresses.%zu.prefixlen", na), jstr(&r, key) !=
			    NULL ? jstr(&r, key) : "-"));
			addrs[na] = strdup(p2);
		}
		resp_free(&r);
		snprintf(p2, sizeof(p2), "%s?source=yang", path);
		http("GET", p2, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("true", jstr(&r, "ok"));
		ATF_CHECK_STREQ("yang", jstr(&r, "data.source"));
		for (k = 0; k < nitems(same); k++) {
			snprintf(key, sizeof(key), "data.interfaces.0.%s",
			    same[k]);
			ATF_CHECK_MSG((was[k] == NULL) == (jstr(&r, key) ==
			    NULL) && (was[k] == NULL || strcmp(was[k],
			    jstr(&r, key)) == 0), "%s: %s by the table, %s by "
			    "the models", same[k], was[k] != NULL ? was[k] :
			    "none", jstr(&r, key) != NULL ? jstr(&r, key) :
			    "none");
			free(was[k]);
		}
		for (nb = 0; nb < nitems(addrs); nb++) {
			snprintf(key, sizeof(key), "data.interfaces.0."
			    "addresses.%zu.address", nb);
			if (jstr(&r, key) == NULL)
				break;
			snprintf(p2, sizeof(p2), "%s/%s", jstr(&r, key), (
			    snprintf(key, sizeof(key), "data.interfaces.0."
			    "addresses.%zu.prefixlen", nb), jstr(&r, key) !=
			    NULL ? jstr(&r, key) : "-"));
			for (k = 0, found = false; k < na && !found; k++)
				found = strcmp(addrs[k], p2) == 0;
			ATF_CHECK_MSG(found, "%s by the models, not by the "
			    "table", p2);
		}
		ATF_CHECK_EQ(na, nb);
		for (k = 0; k < na; k++)
			free(addrs[k]);
	}
	resp_free(&r);
	/* The agent's YANG data, the nodes named, as RFC 7951's JSON. */
	snprintf(path, sizeof(path), "%.*s/data?node=interfaces,sysctl",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_MSG(jstr(&r, "data.ietf-interfaces:interfaces.interface.0."
	    "name") != NULL, "%.600s", r.body);
	ATF_CHECK(jstr(&r, "data.arcana-sysctl:sysctl.value.0.name") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/data?node=interfaces&filter=x",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/data?node=nowhere",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK(jstr(&r, "error") != NULL && strstr(jstr(&r, "error"),
	    "nowhere is no node") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/data?node=a;b",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* The drift: the operational configuration against running, each
	 * row a node with its api-path; what the host has beyond running
	 * says where it came from (the agent's rc.conf is a fake's:
	 * every address of the host is beyond it). */
	snprintf(path, sizeof(path), "%.*s/drift",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_MSG(jstr(&r, "drift.0.path") != NULL &&
	    jstr(&r, "drift.0.path")[0] == '/' &&
	    jstr(&r, "drift.0.kind") != NULL, "%.600s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"extra\"") != NULL &&
	    strstr(r.body, "\"origin\":\"") != NULL, "%.600s", r.body);
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
	/* Which repository each pkg action takes from, per jail: kept
	 * with the server, as given; the shape is checked. */
	http("POST", body, "{\"pkg_repos\":{\".\":{\"upgrade\":\"mine\"},"
	    "\"web\":{\"install\":\"\",\"base\":\"FreeBSD-base\"}}}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("FreeBSD-base", jstr(&r, "servers.0.pkg_repos.web.base"));
	ATF_CHECK_STREQ("FreeBSD-base", jstr(&r,
	    "servers.0.pkg_repos.web.base"));
	ATF_CHECK_STREQ("15", jstr(&r, "servers.0.safe_wait"));
	resp_free(&r);
	http("POST", body, "{\"pkg_repos\":{\"web\":{\"remove\":\"x\"}}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", body, "{\"pkg_repos\":[]}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("GET", "/api/servers", NULL, &r);
	ATF_CHECK_STREQ("FreeBSD-base", jstr(&r, "servers.0.pkg_repos.web.base"));
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
	/* None of its own: Settings' for every host goes with the change. */
	http("POST", "/api/settings", "{\"set\":{\"safe_wait\":\"5\"}}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"safe_wait\":\"25\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", path, "{\"jobs\":[{\"kind\":\"if-address\","
	    "\"interface\":\"lo0\",\"address\":\"10.9.0.7/24\","
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
	ATF_CHECK_MSG(strstr(r.body, "the timer was 25 s") != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"safe_wait\":\"\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);

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
	ATF_CHECK(system("grep -q '^--scope-helper 0 route-get 10.77.5.5 1$' helper.log")
	    == 0);
	/* Not an address (a ; is an argument's end, as forms had it). */
	snprintf(path, sizeof(path), "%.*s/net/lookup?to=10.0.0.1%%3Bid",
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
	ATF_CHECK(system("grep -q '^--scope-helper 4 route-get 192.0.2.9 0$' helper.log")
	    == 0);
	snprintf(path, sizeof(path), "%.*s/net/interfaces?jail=a%%3Bb",
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
	snprintf(body, sizeof(body), "{\"text\":\"router id 192.0.2.9;\\n"
	    "protocol device {\\n}\\n\","
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
	snprintf(body, sizeof(body), "{\"text\":\"router id 192.0.2.10;\\n"
	    "protocol device {\\n}\\n\","
	    "\"safe\":true,\"sha256\":\"%s\"}", jstr(&r, "sha256"));
	resp_free(&r);
	http("POST", path, body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK(jstr(&r, "confirm_by") != NULL);
	resp_free(&r);
	/* A confirmed commit of a minute, BIRD's timer a little longer. */
	ATF_CHECK(system("grep -q '^configure timeout 65$' birdc.log") == 0);
	http("POST", path, "{\"confirm\":true}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	resp_free(&r);
	/* The commit confirmed, BIRD is told so in a moment. */
	ATF_CHECK(system("for i in $(seq 1 40); do grep -q '^configure "
	    "confirm$' birdc.log && break; sleep 0.1; done; grep -q "
	    "'^configure confirm$' birdc.log && grep -q "
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
	/* A file system's limit too, when said; without it, as it was. */
	http("POST", path, "{\"step\":3,\"keep\":100,\"cpu\":95,\"mem\":80,"
	    "\"swap\":10,\"storage\":85}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("85", jstr(&r, "data.limits.storage"));
	resp_free(&r);
	http("POST", path, "{\"step\":3,\"keep\":100,\"cpu\":95,\"mem\":80,"
	    "\"swap\":10}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("85", jstr(&r, "data.limits.storage"));
	resp_free(&r);
	http("POST", path, "{\"step\":3,\"keep\":100,\"cpu\":95,\"mem\":80,"
	    "\"swap\":10,\"storage\":101}", &r);
	EXPECT(&r, 400);
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
	snprintf(path, sizeof(path), "%.*s/ipfw/trace?address=10.0.0.2%%3Bx",
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
		/* Alive: there, and not a zombie (one no reaper waits for,
		 * as in a container, stays one). */
		snprintf(what, sizeof(what), "kill -0 %s 2>/dev/null && ! ps "
		    "-o state= -p %s | grep -q Z", pid, pid);
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
	    "192.0.2.2 up$' ifconfig.log") == 0);

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
	/* A jail's: what its own zfs sees, by jexec; one that does not
	 * run has none; and of a jail, datasets and snapshots only. */
	snprintf(path, sizeof(path), "%.*s/storage/datasets?jail=gw",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("tank/data", jstr(&r, "data.datasets.1.name"));
	resp_free(&r);
	ATF_CHECK(system("grep -q '^jexec 4 .*zfs list -j -p -t filesystem,"
	    "volume' jexec.log") == 0);
	snprintf(path, sizeof(path), "%.*s/storage/datasets?jail=web",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK(jstr(&r, "error") != NULL && strstr(jstr(&r, "error"),
	    "not running") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "%.*s/storage/pools?jail=gw",
	    (int)(strlen(base) - strlen("/services")), base);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("of a jail, its datasets and snapshots only", jstr(&r,
	    "error"));
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
	ATF_CHECK_STREQ("strongswan", jstr(&r, "host.plugins.1"));
	/* WireGuard is no plugin: wg(8) is the base system's. */
	ATF_CHECK(strstr(r.body, "\"wireguard\"") == NULL);
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
	char		 cwd[MAXPATHLEN], uri[64], body[256], path[128], upd[128];
	char		 jgd[MAXPATHLEN], listen[64], *argv[20];
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
	    "\tkey = \"%s/pki/console.key\";\n\tca_key = \"%s/pki/ca.key\";\n"
	    "}\n", cwd, cwd, cwd, cwd);
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
	/* rc.conf: the test's own, never the host's. */
	argv[i++] = (char *)(uintptr_t)"-y";
	argv[i++] = (char *)(uintptr_t)"./fake-sysrc";
	/* The program an update replaces: not the one under test. */
	argv[i++] = (char *)(uintptr_t)"-U";
	argv[i++] = (char *)(uintptr_t)"installed-agent2";
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
	snprintf(upd, sizeof(upd), "/api/servers/%s/agent-update",
	    jstr(&r, "servers.0.id"));
	ATF_CHECK_STREQ("false", jstr(&r, "servers.0.local"));
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("10.0.0.10", jail_str(&r, "web", "ip4.0"));
	ATF_CHECK_MSG(strstr(jstr(&r, "trace.2.detail"), "mutual TLS") != NULL,
	    "%s", jstr(&r, "trace.2.detail"));
	resp_free(&r);
	/* Over TLS the program sent is signed by the console's CA key, and
	 * the host checks it against the CA it trusts before anything
	 * else: here the console's own CA, so it is taken. */
	ATF_REQUIRE(access("installed-agent2", F_OK) == -1);
	http("POST", upd, "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strcmp(jstr(&r, "ok"), "true") == 0, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "verified") != NULL, "%s", r.body);
	/* Compressed, and the signature the program's, inflated. */
	ATF_CHECK_MSG(strstr(r.body, "inflate(3)") != NULL, "%s", r.body);
	ATF_CHECK(access("installed-agent2", X_OK) == 0);
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
	if (has_sctp()) {
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

			/* A read the subscriptions hold none of. */
			snprintf(path, sizeof(path), "/api/servers/%s/services",
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
		snprintf(path, sizeof(path), "/api/servers/%s/services", sid);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
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
		/* The jails: their subscription's association made beside
		 * the requests'. */
		snprintf(path, sizeof(path), "/api/servers/%s/jails", sid);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("10.0.0.10", jail_str(&r, "web", "ip4.0"));
		resp_free(&r);
		/* The association's paths, as the agent's kernel sees
		 * them: to the console's address, active, the primary. */
		snprintf(path, sizeof(path), "/api/servers/%s/transport", sid);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_MSG(strstr(r.body, "\"paths\":[{\"address\":"
		    "\"127.0.0.1\",\"state\":\"active\"") != NULL && strstr(
		    r.body, "\"primary\":true") != NULL && strstr(r.body,
		    "\"local\":[\"127.0.0.1\"]") != NULL, "%s", r.body);
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
			/* The requests' and the subscriptions'. */
			ATF_CHECK_EQ_MSG(2, nsctp, "%d SCTP sessions", nsctp);
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

	/*
	 * SCTP over several paths: the agent's other addresses, checked,
	 * bound where they can be (192.0.2.99 is no address of this host:
	 * said with the listener), kept in rc.conf, and let go.
	 */
	snprintf(path, sizeof(path), "/api/servers/%s/transport", sid);
	http("POST", path, "{\"sctp_also\":\"no-such\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "no-such is not an address") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("POST", path, "{\"sctp_also\":\"192.0.2.99\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	ATF_CHECK_STREQ("192.0.2.99", jstr(&r, "data.sctp_also"));
	if (has_sctp())
		ATF_CHECK_MSG(strstr(r.body, "\"also_error\":\"192.0.2.99: ")
		    != NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^arcana_agent_sctp_also=\"192.0.2.99\"$' "
	    "rc.conf") == 0);
	http("POST", path, "{\"sctp_also\":\"\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "also_error") == NULL);
	resp_free(&r);
	ATF_CHECK(system("! grep -q 'arcana_agent_sctp_also' rc.conf") == 0);

	/*
	 * Moved to another address: listened on there too, tried, and
	 * only then the old listener closed and the new kept in rc.conf;
	 * where the agent cannot listen, nothing changes.
	 */
	snprintf(path, sizeof(path), "/api/servers/%s/move", sid);
	http("POST", path, "{\"uri\":\"udp://127.0.0.1:1\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("POST", path, "{\"uri\":\"tcp://192.0.2.77:4430\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strcmp(jstr(&r, "ok"), "false") == 0 && strstr(jstr(&r,
	    "error"), "did not listen on tcp://192.0.2.77:4430") != NULL,
	    "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(system("echo 'arcana_agent_listen=\"tcp://127.0.0.1:1 "
	    "keep\"' >> rc.conf") == 0);
	{
		char	moved[64], b2[160], was[64];

		snprintf(was, sizeof(was), "tcp://127.0.0.1:%d", port);
		snprintf(moved, sizeof(moved), "tcp://127.0.0.1:%d", port + 1);
		snprintf(b2, sizeof(b2), "{\"uri\":\"%s\"}", moved);
		http("POST", path, b2, &r);
		EXPECT(&r, 200);
		ATF_CHECK_MSG(strcmp(jstr(&r, "ok"), "true") == 0 && strcmp(jstr(
		    &r, "uri"), moved) == 0 && jstr(&r, "note") == NULL, "%s",
		    r.body);
		resp_free(&r);
		http("GET", "/api/servers", NULL, &r);
		ATF_CHECK_STREQ(moved, jstr(&r, "servers.0.uri"));
		resp_free(&r);
		snprintf(b2, sizeof(b2), "/api/servers/%s/transport", sid);
		http("GET", b2, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_MSG(strstr(r.body, moved) != NULL && strstr(r.body,
		    was) == NULL, "%s", r.body);
		resp_free(&r);
		/* Not in arcana_agent_listen: added to it. */
		snprintf(b2, sizeof(b2), "grep -q '^arcana_agent_listen=\"tcp://"
		    "127.0.0.1:1 keep %s\"$' rc.conf", moved);
		ATF_CHECK_MSG(system(b2) == 0, "%s", b2);
		/* And back, its word put in place of the other. */
		snprintf(b2, sizeof(b2), "{\"uri\":\"%s\"}", was);
		http("POST", path, b2, &r);
		EXPECT(&r, 200);
		ATF_CHECK_MSG(strcmp(jstr(&r, "ok"), "true") == 0, "%s", r.body);
		resp_free(&r);
		snprintf(b2, sizeof(b2), "grep -q '^arcana_agent_listen=\"tcp://"
		    "127.0.0.1:1 keep %s\"$' rc.conf", was);
		ATF_CHECK_MSG(system(b2) == 0, "%s", b2);
		/*
		 * Moved to SCTP at the same address: the SCTP listener the
		 * agent opened beside the TCP one is the one moved to, and is
		 * not closed with it; the host is reached there afterwards.
		 */
		if (has_sctp()) {
			char	sctp[64];

			snprintf(sctp, sizeof(sctp), "sctp://127.0.0.1:%d", port);
			snprintf(b2, sizeof(b2), "{\"uri\":\"%s\"}", sctp);
			http("POST", path, b2, &r);
			EXPECT(&r, 200);
			ATF_CHECK_MSG(strcmp(jstr(&r, "ok"), "true") == 0 && strcmp(
			    jstr(&r, "uri"), sctp) == 0, "%s", r.body);
			resp_free(&r);
			snprintf(b2, sizeof(b2), "/api/servers/%s/transport", sid);
			http("GET", b2, NULL, &r);
			EXPECT(&r, 200);
			ATF_CHECK_MSG(strstr(r.body, "\"uri\":\"sctp://127.0.0.1:")
			    != NULL && strstr(r.body, was) == NULL && strstr(r.body,
			    "\"up\":true,\"addresses\"") != NULL, "%s", r.body);
			resp_free(&r);
			snprintf(b2, sizeof(b2), "grep -q '^arcana_agent_listen=\""
			    "tcp://127.0.0.1:1 keep %s\"$' rc.conf", sctp);
			ATF_CHECK_MSG(system(b2) == 0, "%s", b2);
		}
	}
	snprintf(path, sizeof(path), "/api/servers/%s/jails", sid);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
}

/* A file's text, malloc(3)ed. */
static char *
slurp_file(const char *path)
{
	FILE	*fp;
	char	*buf;
	size_t	 n;

	ATF_REQUIRE((fp = fopen(path, "r")) != NULL);
	ATF_REQUIRE((buf = calloc(1, 65537)) != NULL);
	n = fread(buf, 1, 65536, fp);
	fclose(fp);
	buf[n] = '\0';
	return (buf);
}

/* s as a JSON string, its quotes and newlines escaped. */
static char *
json_quote_test(const char *s)
{
	char	*out, *o;

	ATF_REQUIRE((out = malloc(strlen(s) * 2 + 3)) != NULL);
	o = out;
	*o++ = '"';
	for (; *s != '\0'; s++) {
		if (*s == '\n') {
			*o++ = '\\';
			*o++ = 'n';
		} else if (*s == '"' || *s == '\\') {
			*o++ = '\\';
			*o++ = *s;
		} else
			*o++ = *s;
	}
	*o++ = '"';
	*o = '\0';
	return (out);
}

/* The CA's state once the thread is done with it. */
static void
ca_wait(struct resp *r)
{
	int	i;

	for (i = 0; i < 200; i++) {
		http("GET", "/api/ca", NULL, r);
		if (r->status == 200 && jstr(r, "state.running") != NULL &&
		    strcmp(jstr(r, "state.running"), "false") == 0)
			return;
		resp_free(r);
		usleep(100000);
	}
	atf_tc_fail("the CA's change did not end");
}

/*
 * The next CA staged by body, rolled out and finished, the host of
 * jails path reached at each step.
 */
static void
ca_change(const char *path, const char *body)
{
	struct resp	r;

	http("POST", "/api/ca", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("staged", jstr(&r, "state.phase"));
	ATF_CHECK(jstr(&r, "next.chain.0.subject") != NULL);
	resp_free(&r);
	http("POST", "/api/ca", "{\"action\":\"rollout\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ca_wait(&r);
	if (jstr(&r, "state.phase") == NULL || strcmp(jstr(&r, "state.phase"),
	    "switched") != 0)
		(void)system("tail -30 console.out >&2");
	ATF_CHECK_MSG(jstr(&r, "state.phase") != NULL && strcmp(jstr(&r,
	    "state.phase"), "switched") == 0, "%s", r.body);
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("10.0.0.10", jail_str(&r, "web", "ip4.0"));
	resp_free(&r);
	http("POST", "/api/ca", "{\"action\":\"finish\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ca_wait(&r);
	ATF_CHECK_MSG(jstr(&r, "state.phase") != NULL && strcmp(jstr(&r,
	    "state.phase"), "finished") == 0, "%s", r.body);
	ATF_CHECK_MSG(jstr(&r, "next") == NULL, "%s", r.body);
	resp_free(&r);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("10.0.0.10", jail_str(&r, "web", "ip4.0"));
	resp_free(&r);
}

/*
 * An agent of a release before, its program named by the environment's
 * ARCANA_OLD_AGENT or the config variable old_agent; NULL without.
 */
static const char *
old_agent(const atf_tc_t *tc)
{
	const char	*p;

	if ((p = getenv("ARCANA_OLD_AGENT")) != NULL && p[0] != '\0')
		return (p);
	if (atf_tc_has_config_var(tc, "old_agent"))
		return (atf_tc_get_config_var(tc, "old_agent"));
	return (NULL);
}

/*
 * prog listening on listen, and on tcp (not NULL) with mutual TLS, the
 * pki's server certificate; the program an update replaces, installed.
 */
static pid_t
agent_spawn(const char *prog, const char *listen, const char *tcp,
    const char *installed)
{
	char	*argv[24];
	FILE	*fp;
	pid_t	 pid;
	int	 i;

	i = 0;
	argv[i++] = (char *)(uintptr_t)prog;
	argv[i++] = (char *)(uintptr_t)"-F";
	argv[i++] = (char *)(uintptr_t)"-l";
	argv[i++] = (char *)(uintptr_t)listen;
	if (tcp != NULL) {
		argv[i++] = (char *)(uintptr_t)"-l";
		argv[i++] = (char *)(uintptr_t)tcp;
		argv[i++] = (char *)(uintptr_t)"-A";
		argv[i++] = (char *)(uintptr_t)"pki/ca.pem";
		argv[i++] = (char *)(uintptr_t)"-C";
		argv[i++] = (char *)(uintptr_t)"pki/server.pem";
		argv[i++] = (char *)(uintptr_t)"-K";
		argv[i++] = (char *)(uintptr_t)"pki/server.key";
	}
	argv[i++] = (char *)(uintptr_t)"-f";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf";
	argv[i++] = (char *)(uintptr_t)"-D";
	argv[i++] = (char *)(uintptr_t)"etc/jail.conf.d";
	argv[i++] = (char *)(uintptr_t)"-y";
	argv[i++] = (char *)(uintptr_t)"./fake-sysrc";
	argv[i++] = (char *)(uintptr_t)"-U";
	argv[i++] = (char *)(uintptr_t)installed;
	argv[i] = NULL;
	pid = spawn_server(argv, "arcana-agent2.out");
	ATF_REQUIRE((fp = fopen("arcana-agent2.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);
	return (pid);
}

/* A host named name at uri, the n-th added: its id, in buf. */
static void
host_add(const char *name, const char *uri, int n, char *buf, size_t len)
{
	struct resp	r;
	char		body[MAXPATHLEN + 64];

	snprintf(body, sizeof(body), "{\"name\":\"%s\",\"uri\":\"%s\"}", name,
	    uri);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(body, sizeof(body), "servers.%d.id", n);
	ATF_REQUIRE_MSG(jstr(&r, body) != NULL, "%s", r.body);
	strlcpy(buf, jstr(&r, body), len);
	resp_free(&r);
}

/* id's agent-update, its answer in r, checked: as it is, or compressed. */
static void
bridge_update(const char *id, bool gz, struct resp *r)
{
	char	path[160];

	snprintf(path, sizeof(path), "/api/servers/%s/agent-update", id);
	http("POST", path, "{}", r);
	EXPECT(r, 200);
	ATF_CHECK_MSG(strcmp(jstr(r, "ok"), "true") == 0, "%s", r->body);
	if (gz)
		ATF_CHECK_MSG(strstr(r->body, "inflate(3)") != NULL, "%s",
		    r->body);
	else
		ATF_CHECK_MSG(strstr(r->body, "inflate") == NULL, "%s",
		    r->body);
}

/* id's host as hello said it, in r. */
static void
bridge_hello(const char *id, struct resp *r)
{
	char	path[160];

	snprintf(path, sizeof(path), "/api/servers/%s/jails", id);
	http("GET", path, NULL, r);
	EXPECT(r, 200);
}

CONSOLE_TC(agent_update_bridge, "An agent of the release before the "
    "interim protocol went, a real build of it (ARCANA_OLD_AGENT), is read "
    "and updated through YANG alone, over a unix socket and over TCP with "
    "mutual TLS, sent its program as it is; the agent it becomes takes the "
    "next one compressed")
ATF_TC_BODY(agent_update_bridge, tc)
{
	struct authn	a;
	struct resp	r;
	struct stat	sb, snew;
	char		cwd[MAXPATHLEN], jgd[MAXPATHLEN], unix[MAXPATHLEN];
	char		tcp[64], id[16], became[MAXPATHLEN];
	const char	*old;
	pid_t		pid;
	int		port, i;

	if ((old = old_agent(tc)) == NULL)
		atf_tc_skip("no agent of a release before: set ARCANA_OLD_AGENT "
		    "or old_agent");
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(mkdir("pki", 0700) == 0);
	pki("ca", NULL, NULL);
	pki("server", "ca", "IP:127.0.0.1,DNS:localhost");
	pki("console", "ca", "DNS:console");
	snprintf(harness_webconf, sizeof(harness_webconf), "tls {\n"
	    "\tca = \"%s/pki/ca.pem\";\n\tcert = \"%s/pki/console.pem\";\n"
	    "\tkey = \"%s/pki/console.key\";\n\tca_key = \"%s/pki/ca.key\";\n"
	    "}\n", cwd, cwd, cwd, cwd);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	ATF_REQUIRE(stat(jgd, &snew) == 0);

	port = 20000 + (int)(getpid() % 20000);
	snprintf(unix, sizeof(unix), "unix:%s/old.sock", cwd);
	snprintf(tcp, sizeof(tcp), "tcp://127.0.0.1:%d", port);
	pid = agent_spawn(old, unix, tcp, "installed-old");
	wait_for("old.sock");

	/* Its hello: its version, and no features. */
	host_add("old-unix", unix, 0, id, sizeof(id));
	bridge_hello(id, &r);
	ATF_CHECK_MSG(jstr(&r, "host.version") != NULL, "%s", r.body);
	ATF_CHECK_MSG(jstr(&r, "host.features.0") == NULL, "%s", r.body);
	printf("old agent %s, its features none\n", jstr(&r,
	    "host.version"));
	resp_free(&r);

	/* Over the unix socket: as it is, taken unsigned. */
	bridge_update(id, false, &r);
	printf("unix: %s\n", r.body);
	resp_free(&r);
	ATF_CHECK(stat("installed-old", &sb) == 0 && sb.st_size ==
	    snew.st_size);
	ATF_REQUIRE(unlink("installed-old") == 0);

	/* Over TCP with mutual TLS: as it is, signed by the CA key. */
	host_add("old-tcp", tcp, 1, id, sizeof(id));
	bridge_update(id, false, &r);
	printf("tcp: %s\n", r.body);
	resp_free(&r);
	ATF_CHECK(stat("installed-old", &sb) == 0 && sb.st_size ==
	    snew.st_size);

	/* What it became runs, and takes the next one compressed. */
	(void)kill(pid, SIGTERM);
	for (i = 0; i < 100 && kill(pid, 0) == 0; i++)
		usleep(50000);
	ATF_REQUIRE(system("cp installed-old became && chmod 755 became") ==
	    0);
	snprintf(became, sizeof(became), "%s/became", cwd);
	snprintf(unix, sizeof(unix), "unix:%s/new.sock", cwd);
	(void)agent_spawn(became, unix, NULL, "installed-new");
	wait_for("new.sock");
	host_add("became", unix, 2, id, sizeof(id));
	bridge_hello(id, &r);
	ATF_CHECK_MSG(strstr(r.body, "gzip-update") != NULL, "%s", r.body);
	resp_free(&r);
	bridge_update(id, true, &r);
	resp_free(&r);
	ATF_CHECK(stat("installed-new", &sb) == 0 && sb.st_size ==
	    snew.st_size);
}

/* path's GET, again while the host is not reached: its answer in r. */
static void
rc_get(const char *path, struct resp *r)
{

	for (int i = 0; i < 50; i++) {
		http("GET", path, NULL, r);
		if (r->status != 502 && r->status != 503)
			return;
		resp_free(r);
		usleep(100000);
	}
	http("GET", path, NULL, r);
}

/*
 * The fleet mount by each host's own schema (PLAN-SDN-YANG 4.3.1,
 * 4.3.2): an agent of the release the console is and one of a release
 * before (ARCANA_OLD_AGENT), each read by its own YANG library and .sid
 * files: what both have read from both, a module only the newer has
 * refused of the older as its modules', each one's library its own.
 * The older updated under the console (the newer program at its
 * address), its schema is read again and the module is there.
 */
CONSOLE_TC(restconf_revisions, "The fleet mount by each host's own schema: "
    "two agents of different releases, the older updated under the "
    "console and read again")
ATF_TC_BODY(restconf_revisions, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], jgd[MAXPATHLEN], uri[MAXPATHLEN + 8];
	char		 idn[16], ido[16], path[512];
	const char	*old;
	pid_t		 pid;
	int		 i;

	if ((old = old_agent(tc)) == NULL)
		atf_tc_skip("no agent of a release before: set ARCANA_OLD_AGENT "
		    "or old_agent");
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	start(tc, 0, NULL);
	enrol(&a);
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	snprintf(uri, sizeof(uri), "unix:%s/jgd.sock", cwd);
	host_add("new", uri, 0, idn, sizeof(idn));
	snprintf(uri, sizeof(uri), "unix:%s/old.sock", cwd);
	pid = agent_spawn(old, uri, NULL, "installed-old");
	wait_for("old.sock");
	host_add("old", uri, 1, ido, sizeof(ido));

	/* What both have, read from both by their own SIDs. */
	for (i = 0; i < 2; i++) {
		snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/"
		    "host=%s/ietf-interfaces:interfaces", i == 0 ? idn : ido);
		rc_get(path, &r);
		ATF_CHECK_MSG(r.status == 200 && strstr(r.body,
		    "\"name\":\"lo0\"") != NULL, "%s: %d %s", i == 0 ? "new" :
		    "old", r.status, r.body);
		resp_free(&r);
	}
	/* Each one's library its own: arcana-steer the newer's alone. */
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-yang-library:yang-library", idn);
	rc_get(path, &r);
	ATF_CHECK_MSG(strstr(r.body, "\"arcana-steer\"") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-yang-library:yang-library", ido);
	rc_get(path, &r);
	ATF_CHECK_MSG(r.status == 200 && strstr(r.body, "\"arcana-steer\"") ==
	    NULL, "%d %s", r.status, r.body);
	resp_free(&r);
	/* A module only the newer has: the older's modules have it not. */
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/arcana-steer:steering", ido);
	rc_get(path, &r);
	ATF_CHECK_MSG(r.status == 404 && strstr(r.body, "the host's modules "
	    "have no arcana-steer:steering") != NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/arcana-steer:steering", idn);
	rc_get(path, &r);
	ATF_CHECK_MSG(strstr(r.body, "have no") == NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);

	/* The older updated under the console: the newer at its address. */
	(void)kill(pid, SIGTERM);
	for (i = 0; i < 100 && kill(pid, 0) == 0; i++)
		usleep(50000);
	(void)unlink("old.sock");
	(void)agent_spawn(jgd, uri, NULL, "installed-new");
	wait_for("old.sock");
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/arcana-steer:steering", ido);
	for (i = 0;; i++) {
		rc_get(path, &r);
		if (strstr(r.body, "have no") == NULL || i == 50)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_MSG(strstr(r.body, "have no") == NULL, "%d %s", r.status,
	    r.body);
	resp_free(&r);
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-yang-library:yang-library", ido);
	rc_get(path, &r);
	ATF_CHECK_MSG(strstr(r.body, "\"arcana-steer\"") != NULL, "%d %s",
	    r.status, r.body);
	resp_free(&r);
}

CONSOLE_TC(enrol, "The console's own CA, a host's certificate renewed, the CA changed for another and for an intermediate across the hosts, and a host joining with "
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

	/* The host joins, by the address the console listens on: localhost
	 * may be ::1 first, and where that is dropped rather than refused,
	 * fetch(3) waits out its connect before it tries 127.0.0.1. */
	snprintf(url, sizeof(url), "http://127.0.0.1%s", strrchr(
	    harness_origin, ':'));
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

	/* A host's certificate may reach hosts, but asks nothing of them
	 * as the console does: refused by the agent. */
	ATF_CHECK(system("openssl x509 -in host/host.pem -noout -ext "
	    "extendedKeyUsage,subjectAltName | grep -q 'TLS Web Client "
	    "Authentication' && openssl x509 -in host/host.pem -noout -ext "
	    "subjectAltName | grep -q 'URI:urn:arcana:role:agent' && openssl "
	    "x509 -in data/console.pem -noout -ext subjectAltName | grep -q "
	    "'URI:urn:arcana:role:console'") == 0);
	snprintf(body, sizeof(body), "%s -c tcp://127.0.0.1:%d -A data/ca.pem "
	    "-C host/host.pem -K host/host.key hello 2>&1 | grep -q "
	    "'not let in'", locate(tc, "../../../usr.sbin/arcanactl/"
	    "arcanactl", "arcanactl", "/usr/local/sbin/arcanactl"), jport);
	ATF_CHECK(system(body) == 0);
	/* Its certificate renewed from here: a key made there, signed
	 * here, taken there, and the host reached with it. */
	{
		char	tpath[96], first[128];

		snprintf(tpath, sizeof(tpath), "%.*s/tls", (int)(strlen(path) -
		    6), path);
		http("GET", tpath, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("CN=arcana CA", jstr(&r, "data.cert.issuer"));
		snprintf(first, sizeof(first), "%s", jstr(&r,
		    "data.cert.sha256") != NULL ? jstr(&r, "data.cert.sha256") :
		    "");
		resp_free(&r);
		http("POST", tpath, "{}", &r);
		EXPECT(&r, 200);
		ATF_CHECK_MSG(jstr(&r, "ok") != NULL && strcmp(jstr(&r, "ok"),
		    "true") == 0, "%s", r.body);
		ATF_CHECK(jstr(&r, "data.cert.sha256") != NULL && strcmp(jstr(&r,
		    "data.cert.sha256"), first) != 0);
		ATF_CHECK_STREQ("CN=127.0.0.1", jstr(&r, "data.cert.subject"));
		resp_free(&r);
		ATF_CHECK(access("host/host.pem.before", F_OK) == 0);
		ATF_CHECK(access("host/host.key.next", F_OK) != 0);
		i = 0;
		argv[i++] = (char *)(uintptr_t)"/usr/bin/openssl";
		argv[i++] = (char *)(uintptr_t)"verify";
		argv[i++] = (char *)(uintptr_t)"-CAfile";
		argv[i++] = (char *)(uintptr_t)"data/ca.pem";
		argv[i++] = (char *)(uintptr_t)"host/host.pem";
		argv[i] = NULL;
		ATF_CHECK_MSG(run_prog(argv), "the renewed one does not verify");
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("10.0.0.10", jail_str(&r, "web", "ip4.0"));
		resp_free(&r);
	}

	/*
	 * The CA changed for another: made here, rolled out (the host
	 * trusts both and is given a certificate from the new one, the
	 * console takes the new one's), finished (the old one trusted no
	 * more); then the console as an intermediate CA under a root of
	 * its own, from a request made here.
	 */
	/* A host that does not answer: the console does not switch, for
	 * that host would be lost to it; once it is gone, it does. */
	http("POST", "/api/servers", "{\"name\":\"gone\",\"uri\":"
	    "\"tcp://127.0.0.1:1\"}", &r);
	EXPECT(&r, 200);
	snprintf(tok, sizeof(tok), "/api/servers/%s", jstr(&r,
	    "servers.1.name") != NULL && strcmp(jstr(&r, "servers.1.name"),
	    "gone") == 0 ? jstr(&r, "servers.1.id") : jstr(&r, "servers.0.id"));
	resp_free(&r);
	http("POST", "/api/ca", "{\"action\":\"make\",\"cn\":\"arcana CA "
	    "2\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/ca", "{\"action\":\"rollout\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ca_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "state.phase"), "rolling") == 0 &&
	    strstr(jstr(&r, "state.error"), "1 host not renewed") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("POST", "/api/ca", "{\"action\":\"finish\"}", &r);
	EXPECT(&r, 409);
	resp_free(&r);
	http("DELETE", tok, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/ca", "{\"action\":\"rollout\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ca_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "state.phase"), "switched") == 0, "%s",
	    r.body);
	resp_free(&r);
	http("POST", "/api/ca", "{\"action\":\"finish\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ca_wait(&r);
	ATF_CHECK_STREQ("finished", jstr(&r, "state.phase"));
	resp_free(&r);
	ATF_CHECK(system("openssl x509 -in host/ca.pem -noout -subject | grep "
	    "-q 'CN *= *arcana CA 2' && [ $(grep -c 'BEGIN CERT' host/ca.pem) "
	    "= 1 ]") == 0);
	/* The console's certificate from before is trusted no more. */
	snprintf(body, sizeof(body), "%s -c tcp://127.0.0.1:%d -A data/ca.pem "
	    "-C data/console.pem.before -K data/console.key.before hello "
	    ">/dev/null 2>&1", locate(tc, "../../../usr.sbin/arcanactl/"
	    "arcanactl", "arcanactl", "/usr/local/sbin/arcanactl"), jport);
	ATF_CHECK(system(body) != 0);
	snprintf(body, sizeof(body), "%s -c tcp://127.0.0.1:%d -A data/ca.pem "
	    "-C data/console.pem -K data/console.key hello >/dev/null 2>&1",
	    locate(tc, "../../../usr.sbin/arcanactl/arcanactl", "arcanactl",
	    "/usr/local/sbin/arcanactl"), jport);
	ATF_CHECK(system(body) == 0);
	/* An intermediate: the request made here, signed by a root. */
	http("POST", "/api/ca", "{\"action\":\"request\",\"cn\":\"arcana "
	    "sub\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK(jstr(&r, "request") != NULL && strstr(jstr(&r, "request"),
	    "CERTIFICATE REQUEST") != NULL);
	resp_free(&r);
	ATF_REQUIRE(system("openssl req -x509 -newkey ec -pkeyopt "
	    "ec_paramgen_curve:P-256 -nodes -keyout root.key -out root.pem "
	    "-days 2 -subj /CN=lab-root -addext basicConstraints=critical,"
	    "CA:TRUE -addext keyUsage=critical,keyCertSign >/dev/null 2>&1 && "
	    "printf 'basicConstraints=critical,CA:TRUE,pathlen:0\\nkeyUsage="
	    "critical,keyCertSign,cRLSign\\n' > sub.ext && openssl x509 -req "
	    "-in data/ca-next/request.csr -CA root.pem -CAkey root.key "
	    "-CAcreateserial -days 2 -extfile sub.ext -out sub.pem >/dev/null "
	    "2>&1 && cat sub.pem root.pem > subchain.pem") == 0);
	/* Without its root it is refused. */
	{
		char	*sub, *chain, *q, *bodyb;

		sub = slurp_file("sub.pem");
		chain = slurp_file("subchain.pem");
		q = json_quote_test(sub);
		ATF_REQUIRE(asprintf(&bodyb, "{\"action\":\"import\",\"cert\":"
		    "%s}", q) != -1);
		http("POST", "/api/ca", bodyb, &r);
		EXPECT(&r, 409);
		ATF_CHECK(strstr(r.body, "does not reach a root") != NULL);
		resp_free(&r);
		free(q);
		free(bodyb);
		q = json_quote_test(chain);
		ATF_REQUIRE(asprintf(&bodyb, "{\"action\":\"import\",\"cert\":"
		    "%s}", q) != -1);
		ca_change(path, bodyb);
		free(q);
		free(bodyb);
		free(sub);
		free(chain);
	}
	ATF_CHECK(system("openssl x509 -in host/ca.pem -noout -subject | grep "
	    "-q 'CN *= *lab-root' && openssl verify -CAfile root.pem "
	    "-untrusted host/host.pem host/host.pem >/dev/null 2>&1") == 0);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("10.0.0.10", jail_str(&r, "web", "ip4.0"));
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
    "\"security_function_policies\":[{\"id\":\"g-ippf\",\"function\":"
    "\"ippf\",\"allow\":[{\"dav4\":[\"192.0.2.8/29\"]}],\"block\":[{\"dav4\":"
    "[\"192.0.2.0/24\"]}],\"no-match\":\"allow\",\"duration\":6},"
    "{\"id\":\"g-dnf\",\"function\":\"dnf\",\"block\":[\"ads.example\"],"
    "\"allow\":[\"ok.ads.example\"],\"no-match\":\"allow\",\"duration\":6},"
    "{\"id\":\"g-dpf\",\"function\":\"dpf\",\"block\":[{\"sav4\":"
    "[\"192.0.2.53/32\"],\"message-type\":\"response\"},{\"dav4\":"
    "[\"192.0.2.54/32\"],\"message-type\":\"query\"}],\"no-match\":\"block\","
    "\"redirect\":true,\"duration\":6},"
    "{\"id\":\"g-urlf\",\"function\":\"urlf\",\"block\":[\"bad.example\"],"
    "\"no-match\":\"allow\",\"duration\":6},"
    "{\"id\":\"g-mdr\",\"function\":\"mdr\",\"detection-type\":"
    "\"signature\",\"removal\":\"block-subset\",\"block\":["
    "\"44D88612FEA8A8F36DE82E1278ABB02F:68\",\"275a021bbfb6489e54d4718"
    "99f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\"],\"allow\":["
    "\"3395856ce81f2b7382dee72602f798b642f14140\"],\"no-match\":\"allow\","
    "\"duration\":24}],"
    "\"security_policies\":[{\"name\":\"guard\",\"function-policies\":["
    "\"g-ippf\",\"g-dnf\",\"g-dpf\",\"g-urlf\",\"g-mdr\"],\"rate-limit\":"
    "2000000,\"ids\":{\"mode\":\"prevent\",\"ruleset\":true,"
    "\"rules\":[\"alert http any any -> $HOME_NET any (msg:\\\"x\\\"; "
    "sid:1000001; rev:1;)\"]}}],"
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
    "\"prefix\":\"10.30.0.0/24\",\"port\":51820,\"groups\":[{\"name\":"
    "\"staff\",\"zone\":\"office\",\"pool\":\"10.30.0.64/26\"},{\"name\":"
    "\"guests\",\"zone\":\"office\"}],\"identities\":[{\"name\":"
    "\"alice\",\"zone\":\"office\",\"public_key\":"
    "\"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\"},{\"name\":\"carol\","
    "\"group\":\"staff\",\"public_key\":"
    "\"HIgo9xNzJMWLKASShiTqIYNW7HVnKq0pjaZxmvZ6rKA=\"}]}}]}]}";

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

/* sdwan_good with its edges @A and @B named. */
static void
sdwan_good_at(const char *a, const char *b, char *doc, size_t len)
{
	char	t[8192];

	snprintf(doc, len, "%s", sdwan_good);
	while (swap_in(doc, "@A", a, t, sizeof(t)))
		snprintf(doc, len, "%s", t);
	while (swap_in(doc, "@B", b, t, sizeof(t)))
		snprintf(doc, len, "%s", t);
}

/*
 * The document a view of the L3NM kept (PLAN-SDN-YANG 4.5.3): the L3NM
 * form of the example exported as the example; a console's document of
 * before imported at its start, its version kept, the file kept aside.
 * (Every document kept by the tests comes back the same: http().)
 */
CONSOLE_TC(l3nm_mef, "the SD-WAN document a view of the L3NM: l3nm_good "
    "exported is sdwan_good; sdwan.json imported once at start")
ATF_TC_BODY(l3nm_mef, tc)
{
	struct authn	 a;
	struct resp	 r;
	FILE		*fp;
	char		 doc[8192], where[512];

	start(tc, 0, NULL);
	enrol(&a);
	http("PUT", L3NM, l3nm_good, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	http("GET", "/api/sdwan", NULL, &r);
	EXPECT(&r, 200);
	sdwan_good_at("a", "b", doc, sizeof(doc));
	ATF_CHECK_MSG(sdwan_round_trip(doc, r.json, where, sizeof(where)),
	    "l3nm_good is not sdwan_good: %s: %s", where, r.body);
	ATF_CHECK_STREQ("acme", jstr(&r, "swvcs.0.id"));
	ATF_CHECK_STREQ("64600:1", jstr(&r, "swvcs.0.domains.service.rd"));
	resp_free(&r);
	/* A change by RESTCONF is a version of the document too. */
	http("GET", "/api/sdwan", NULL, &r);
	ATF_CHECK_STREQ("1", jstr(&r, "version"));
	resp_free(&r);
	http("DELETE", L3NM, NULL, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("GET", "/api/sdwan", NULL, &r);
	ATF_CHECK_STREQ("2", jstr(&r, "version"));
	/* None: the document's lists empty, as the page has them. */
	ATF_CHECK_MSG(ucl_object_type(ucl_object_lookup(r.json, "swvcs")) ==
	    UCL_ARRAY && ucl_array_size(ucl_object_lookup(r.json, "swvcs")) ==
	    0 && ucl_array_size(ucl_object_lookup(r.json, "edges")) == 0 &&
	    ucl_object_type(ucl_object_lookup(r.json, "ucs")) == UCL_ARRAY,
	    "%s", r.body);
	resp_free(&r);

	/* A console of before: its sdwan.json, version 7. */
	console_stop();
	sdwan_good_at("a", "b", doc, sizeof(doc));
	ATF_REQUIRE(strncmp(doc, "{\"version\":0,", 13) == 0);
	ATF_REQUIRE((fp = fopen("data/sdwan.json", "w")) != NULL);
	fprintf(fp, "{\"version\":7,%s", doc + 13);
	fclose(fp);
	console_start();
	http("GET", "/api/sdwan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(access("data/sdwan.json", F_OK) == -1);
	ATF_CHECK(access("data/sdwan-mef.json", F_OK) == 0);
	ATF_CHECK_STREQ("7", jstr(&r, "version"));
	ATF_CHECK_MSG(sdwan_round_trip(doc, r.json, where, sizeof(where)),
	    "sdwan.json not imported the same: %s: %s", where, r.body);
	resp_free(&r);
	http("GET", L3NM "/vpn-services/vpn-service=acme/vpn-nodes/"
	    "vpn-node=a/vpn-network-accesses/vpn-network-access=hq/"
	    "interface-id", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("vtnet2", jstr(&r, "ietf-l3vpn-ntw:interface-id"));
	resp_free(&r);
	/* Once: started again, nothing more of it. */
	restart_console();
	http("GET", "/api/sdwan", NULL, &r);
	ATF_CHECK_STREQ("7", jstr(&r, "version"));
	resp_free(&r);
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
		/* The security function policies (MEF 138) and the security
		 * policies made of them. */
		{ "\"dav4\":[\"192.0.2.0/24\"]", "\"dav4\":[\"192.0.2.0/33\"]",
		    "dav4" },
		{ "\"block\":[\"ads.example\"]", "\"block\":[\"ads..example\"]",
		    "not a domain name" },
		{ "\"rate-limit\":2000000", "\"rate-limit\":10", "1000 or more" },
		{ "\"rate-limit\":2000000", "\"rate-limit\":2000000,\"nope\":true",
		    "is not of a security policy" },
		{ "\"function\":\"ippf\"", "\"function\":\"fw\"",
		    "one of MEF 138's" },
		{ "\"function\":\"ippf\"", "\"function\":\"dlp\"",
		    "no engine for data loss" },
		{ "\"no-match\":\"block\",\"redirect\"",
		    "\"no-match\":\"drop\",\"redirect\"", "allow or block" },
		{ "\"duration\":24}", "\"duration\":0}", "duration is hours" },
		{ "\"allow\":[\"ok.ads.example\"]", "\"allow\":[\"ads.example\"]",
		    "one list at most (R14)" },
		{ "\"removal\":\"block-subset\"", "\"removal\":\"remove\"",
		    "removal block-subset" },
		{ "\"g-mdr\"],", "\"g-mdr\",\"g-ippf\"],", "one of a function" },
		{ "\"g-mdr\"],", "\"g-none\"],", "no function policy g-none" },
		{ "\"allow\":[\"ok.ads.example\"],", "\"allow\":[\"ok.ads.example\"],"
		    "\"lists\":{\"block\":[\"nowhere\"]},", "no list nowhere" },
		{ "\"block\":[\"bad.example\"]", "\"block\":[\"bad.example/x\"]",
		    "seen over HTTPS where the zone's mbsf" },
		{ "\"block\":[\"bad.example\"]", "\"block\":[\"bad example\"]",
		    "is not a host" },
		{ "\"egress-block\":\"discard\"", "\"egress-block\":\"discard\","
		    "\"af-security-egress\":\"guard\"", "serves a zone's clients" },
		{ "\"redirect\":true", "\"redirect\":true,\"pass-through\":[\"x.example\"]",
		    "are mbsf's" },
		/* DPF: a message type ipfw tells by the port. */
		{ "\"message-type\":\"query\"", "\"message-type\":\"update\"",
		    "inside the message" },
		/* MD+R: hashes, one list at an edge. */
		{ "\"3395856ce81f2b7382dee72602f798b642f14140\"",
		    "\"3395856ce81f2b7382dee72602f798b642f1414\"", "is not a hash" },
		{ "\"3395856ce81f2b7382dee72602f798b642f14140\"",
		    "\"3395856ce81f2b7382dee72602f798b642f14140:0\"", "is not a hash" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-mdr2\",\"function\":\"mdr\","
		    "\"detection-type\":\"signature\",\"removal\":\"block-subset\","
		    "\"quarantine\":[\"3395856CE81F2B7382DEE72602F798B642F14140:5\"],"
		    "\"no-match\":\"allow\",\"duration\":24},{\"id\":\"g-mdr\"",
		    "whose ClamAV is one for them all" },
		/* DNF: a * for a whole label, a Block's or a Quarantine's. */
		{ "\"allow\":[\"ok.ads.example\"]", "\"allow\":[\"ok.*.example\"]",
		    "a * inside a name is a Block's" },
		{ "\"block\":[\"ads.example\"]", "\"block\":[\"a*s.example\"]",
		    "a * for a whole label" },
		{ "\"block\":[\"ads.example\"]", "\"block\":[\"*.*\"]",
		    "a * for a whole label" },
		/* PDNS: what unbound takes of R104, D21 and D22. */
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"block\":[{\"type\":\"MX\",\"value\":\"mx.example\"}],"
		    "\"no-match\":\"allow\",\"duration\":6},{\"id\":\"g-mdr\"",
		    "MX is not taken" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"block\":[{\"type\":\"NS\",\"value\":\"not a name\"}],"
		    "\"no-match\":\"allow\",\"duration\":6},{\"id\":\"g-mdr\"",
		    "an NS entry's value" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"no-match\":\"allow\",\"duration\":6,\"southbound\":["
		    "\"unencrypted\",\"doh\"]},{\"id\":\"g-mdr\"",
		    "without DNS over HTTPS" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"block\":[{\"type\":\"A\",\"value\":\"192.0.2.1\","
		    "\"encryption\":\"unencrypted\"}],\"no-match\":\"allow\","
		    "\"duration\":6,\"southbound\":[\"unencrypted\",\"dot\"]},"
		    "{\"id\":\"g-mdr\"", "however they ask" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"no-match\":\"allow\",\"duration\":6,\"southbound\":[\"dot\"]},"
		    "{\"id\":\"g-mdr\"", "southbound has unencrypted" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"no-match\":\"allow\",\"duration\":6,\"northbound\":\"dot\","
		    "\"upstream\":[\"192.0.2.53\"]},{\"id\":\"g-mdr\"",
		    "the name its certificate has" },
		{ "{\"id\":\"g-mdr\"", "{\"id\":\"g-p\",\"function\":\"pdns\","
		    "\"no-match\":\"allow\",\"duration\":6,\"northbound\":\"dot\","
		    "\"upstream\":[\"192.0.2.53#dns.example\"]},{\"id\":\"g-q\","
		    "\"function\":\"pdns\",\"no-match\":\"allow\",\"duration\":6},"
		    "{\"id\":\"g-mdr\"", "the service has one resolver" },
		/* Intrusion detection: detect, rules with a sid. */
		{ "\"mode\":\"prevent\"", "\"mode\":\"block\"",
		    "a mode, detect or prevent" },
		{ "sid:1000001; rev:1;)", "rev:1;)", "is not a Suricata rule" },
		{ "\"alert http any", "\"shout http any", "is not a Suricata rule" },
		{ "\"ruleset\":true", "\"ruleset\":\"yes\"", "ids.ruleset is true" },
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
		/* A remote end point: its port, an identity's zone
		 * and key, and not a UNI besides. */
		{ "\"port\":51820", "\"port\":70000", "port is 1 to 65535" },
		{ "\"zone\":\"office\",\"public_key\"", "\"zone\":\"nowhere\","
		    "\"public_key\"", "its zone is one of the zones" },
		{ "\"public_key\":\"xTIB", "\"public_key\":\"short", "a WireGuard "
		    "one" },
		{ "\"remote\":{", "\"uni\":{\"id\":\"x\"},\"remote\":{", "not "
		    "both" },
		/* Its groups: a zone of the service, a pool inside the prefix
		 * and not the edge's own address, reaching groups of its own,
		 * and an identity's group one of them. */
		{ "\"name\":\"guests\",\"zone\":\"office\"", "\"name\":\"guests\","
		    "\"zone\":\"nowhere\"", "group guests: its zone" },
		{ "\"pool\":\"10.30.0.64/26\"", "\"pool\":\"10.31.0.64/26\"",
		    "inside the remote's" },
		{ "\"pool\":\"10.30.0.64/26\"", "\"pool\":\"10.30.0.0/25\"",
		    "the edge's own address" },
		{ "\"name\":\"guests\",\"zone\":\"office\"", "\"name\":\"guests\","
		    "\"zone\":\"office\",\"pool\":\"10.30.0.96/27\"", "pools "
		    "overlap" },
		{ "\"name\":\"guests\",\"zone\":\"office\"", "\"name\":\"guests\","
		    "\"zone\":\"office\",\"reach\":[\"nobody\"]", "it reaches groups "
		    "of this remote" },
		{ "\"name\":\"guests\",\"zone\":\"office\"", "\"name\":\"guests\","
		    "\"zone\":\"office\",\"reach\":[\"guests\"]", "reach each other "
		    "already" },
		{ "\"group\":\"staff\"", "\"group\":\"board\"", "its group is one "
		    "of the remote's" },
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

/*
 * MEF 138's Security Admin Notifications (§6.3): a document kept with a
 * function policy's values changed issues a SAN of that policy (R31),
 * with the values that changed alone, a Block's names neutralised
 * (R34), who did it and from where; kept (R32), as CSV too, and mailed
 * to the SAN recipients (R36).  No SEN without events.
 */
CONSOLE_TC(sdwan_notices, "SD-WAN security admin notifications: a function "
    "policy changed is told")
ATF_TC_BODY(sdwan_notices, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[12288], t1[12288];
	int		i;

	/* The hosts' events read each second: the notices go out a tick. */
	snprintf(harness_webconf, sizeof(harness_webconf), "mail_tick = 1;\n");
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
	http("POST", "/api/settings", "{\"set\":{\"mail_san\":\"soc@example.org"
	    "\",\"mail_sen\":\"soc@example.org\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(doc, sizeof(doc), "%s", sdwan_good);
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* The first document: every function policy added, a SAN each. */
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/san", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(ucl_object_toint(ucl_object_lookup(r.json, "count")) == 5
	    && strcmp(jstr(&r, "notices.0.service"), "acme") == 0 && strlen(
	    jstr(&r, "notices.0.id")) == 36 && strcmp(jstr(&r, "notices.0.who"),
	    "key -7") == 0 && strstr(jstr(&r, "notices.0.when"), "T") != NULL &&
	    jstr(&r, "notices.0.when")[strlen(jstr(&r, "notices.0.when")) - 1] ==
	    'Z', "%s", r.body);
	resp_free(&r);
	/* The DNF's Block changed and its No-match: one SAN, of it, the
	 * entries added and taken away neutralised, the No-match's values. */
	ATF_REQUIRE(swap_in(doc, "\"version\":0", "\"version\":1", t1,
	    sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	ATF_REQUIRE(swap_in(doc, "\"block\":[\"ads.example\"],\"allow\":"
	    "[\"ok.ads.example\"],\"no-match\":\"allow\"", "\"block\":"
	    "[\"bad.example\",\"*.worse.example\"],\"allow\":[\"ok.ads.example\"]"
	    ",\"no-match\":\"block\"", t1, sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/san?q=g-dnf", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(ucl_object_toint(ucl_object_lookup(r.json, "count")) == 6
	    && strcmp(jstr(&r, "notices.0.policy"), "g-dnf") == 0 && strcmp(
	    jstr(&r, "notices.1.policy"), "g-dnf") == 0 && jstr(&r,
	    "notices.2.policy") == NULL && strstr(jstr(&r, "notices.0.details"),
	    "block: added \"bad[.]example\", \"*[.]worse[.]example\", taken away "
	    "\"ads[.]example\"") != NULL && strstr(jstr(&r, "notices.0.details"),
	    "no-match: \"allow\" was now \"block\"") != NULL && strstr(jstr(&r,
	    "notices.0.details"), "ok") == NULL, "%s", r.body);
	resp_free(&r);
	/* The same again: nothing changed, no SAN. */
	ATF_REQUIRE(swap_in(doc, "\"version\":1", "\"version\":2", t1,
	    sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/san", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(ucl_object_toint(ucl_object_lookup(r.json, "count")) == 6,
	    "%s", r.body);
	resp_free(&r);
	http("GET", "/api/sdwan/san.csv", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strncmp(r.body, "id,when,issuer,source,who,service,policy,"
	    "details\n", 48) == 0 && strstr(r.body, ",\"key -7\",\"acme\","
	    "\"g-dnf\",\"block: added \"\"bad[.]example\"\"") != NULL, "%s",
	    r.body);
	resp_free(&r);
	/* None without a session; nothing of SENs yet. */
	http("GET", "/api/sdwan/sen", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(ucl_object_toint(ucl_object_lookup(r.json, "count")) == 0);
	resp_free(&r);
	/* Mailed to the SAN recipients, the names neutralised, within the
	 * tick; the alerts' address has none to go to. */
	for (i = 0; i < 100 && system("grep -q 'Security Admin Notification' "
	    "mail.out") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(system("grep -qx 'To: soc@example.org' mail.out && grep "
	    "-q '^Subject: Arcana: [0-9]* Security Admin Notifications' mail.out "
	    "&& grep -q 'Security Function Policy: g-dnf of service acme' "
	    "mail.out && grep -q 'bad\\[\\.\\]example' mail.out && grep -q "
	    "'Changed by key -7' mail.out") == 0, "no mail of the SANs");
	cookie[0] = '\0';
	http("GET", "/api/sdwan/san", NULL, &r);
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
	/* What the console and the lab's agents (sdwan_lab) said. */
	show("console.out");
	show("ea/agent.out");
	show("eb/agent.out");
	http("GET", "/api/sdwan/apply", NULL, r);
	ATF_REQUIRE_MSG(false, "the apply did not end: %s", r->body);
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

/* The plan's change of a key at the first edge that has it, and the
 * form of its first instance, as JSON; NULL for none. */
static const char *
plan_spec(struct resp *r, const char *key)
{
	static char		*last;
	const ucl_object_t	*o;
	char			 path[96];
	int			 i;

	for (i = 0; i < 200; i++) {
		snprintf(path, sizeof(path), "changes.%d.key", i);
		if (jstr(r, path) == NULL)
			return (NULL);
		if (strcmp(jstr(r, path), key) != 0)
			continue;
		snprintf(path, sizeof(path), "changes.%d.make.0.instances.0.spec",
		    i);
		if ((o = ucl_object_lookup_path(r->json, path)) == NULL)
			return (NULL);
		free(last);
		last = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
		return (last);
	}
	return (NULL);
}

/*
 * The security function policies (MEF 138) the edges serve a zone with:
 * an MBSF (TLS opened, old versions refused, a host never opened, plain
 * HTTP blocked), a URLF with paths and No-match block, a PDNS by the
 * answers' addresses, the Default zone with the same: the forms the
 * agent renders, Squid's and unbound's (agent_test's sdwan_forms has
 * their text, taken by the real local-unbound-checkconf).
 */
CONSOLE_TC(sdwan_sfp, "SD-WAN security function policies: Squid and unbound "
    "by zone")
ATF_TC_BODY(sdwan_sfp, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[12288], t1[12288];
	const char	*c;
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
		{ "{\"id\":\"g-urlf\",\"function\":\"urlf\",\"block\":["
		    "\"bad.example\"],\"no-match\":\"allow\"",
		    "{\"id\":\"g-mbsf\",\"function\":\"mbsf\",\"block\":[\"tls1.0\","
		    "\"tls1.1\"],\"allow\":[\"tls1.2\",\"tls1.3\"],\"no-match\":"
		    "\"block\",\"invalid-server-certificate\":\"block\","
		    "\"unencrypted\":\"block\",\"pass-through\":[\"bank.example\"]},"
		    "{\"id\":\"g-pdns\",\"function\":\"pdns\",\"block\":[{\"type\":"
		    "\"A\",\"value\":\"192.0.2.66\"},{\"type\":\"CNAME\",\"value\":"
		    "\"*.tracker.example\"},{\"type\":\"NS\",\"value\":"
		    "\"ns.evil.example\",\"encryption\":\"any\"},{\"type\":\"NS\","
		    "\"value\":\"198.51.100.53\"},{\"type\":\"NS\",\"value\":"
		    "\"2001:db8::53/128\"}],\"allow\":[{\"type\":\"AAAA\","
		    "\"value\":\"any\"},{\"type\":\"CNAME\",\"value\":"
		    "\"ok.tracker.example\",\"encryption\":[\"unencrypted\","
		    "\"dot\"]}],\"no-match\":\"allow\",\"duration\":6,"
		    "\"southbound\":[\"unencrypted\",\"dot\"],\"northbound\":\"dot\","
		    "\"upstream\":[\"192.0.2.53#dns.example\","
		    "\"2001:db8::53@8853#dns.example\"]},"
		    "{\"id\":\"g-urlf\",\"function\":\"urlf\",\"block\":["
		    "\"bad.example\",\"*.worse.example/ads/*\"],\"allow\":["
		    "\"bad.example/ok\"],\"no-match\":\"block\"" },
		{ "\"g-urlf\",\"g-mdr\"]", "\"g-urlf\",\"g-mdr\",\"g-mbsf\","
		    "\"g-pdns\"]" },
		{ "\"block\":[\"ads.example\"]", "\"block\":[\"ads.example\","
		    "\"cdn.*.example\"],\"quarantine\":[\"*.track.*\"]" },
		{ "{\"name\":\"rest\",\"prefixes\":\"Default\"}",
		    "{\"name\":\"rest\",\"prefixes\":\"Default\",\"policies\":[{"
		    "\"app\":\"web\",\"policy\":\"fast\"}]}" },
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
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s is not in the document", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	/* Squid at a: TLS opened (inspect); the office zone by its prefixes
	 * here (its remote end point's identities' too) first, Default after
	 * it; each with its URLF, MBSF and MD+R as the service has them;
	 * where it is reached, the resolver and c-icap here. */
	ATF_REQUIRE_MSG((c = plan_spec(&r, "proxy")) != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"mode\":\"inspect\",\"host\":\"a\"") !=
	    NULL && strstr(c, "\"flavor\":\"sdwan\",\"service\":\"acme\","
	    "\"fib\":1,\"listen\":[{\"end_point\":\"hq\",\"address\":"
	    "\"10.1.0.1\"},{\"end_point\":\"road\",\"address\":\"10.30.0.1\"}],"
	    "\"resolver\":true,\"icap\":true,") != NULL, "%s", c);
	/* The DNF's names with a * inside (R71) are the zone's Squid's. */
	ATF_CHECK_MSG(strstr(c, "{\"name\":\"z0\",\"dnf\":[\"cdn.*.example\","
	    "\"*.track.*\"],\"prefixes\":") != NULL, "%s", c);
	ATF_CHECK_MSG(strstr(c, "\"zones\":[{\"name\":\"z0\",\"dnf\":[\"cdn.*."
	    "example\",\"*.track.*\"],\"prefixes\":"
	    "[\"10.1.0.0/16\",\"10.30.0.2/32\",\"10.30.0.64/32\"],") != NULL &&
	    strstr(c, "{\"name\":\"z1\",\"dnf\":[\"cdn.*.example\",\"*.track.*\"],"
	    "\"default\":true,\"urlf\"") != NULL &&
	    strstr(c, "\"name\":\"z0\"") < strstr(c, "\"name\":\"z1\""), "%s",
	    c);
	ATF_CHECK_MSG(strstr(c, "\"urlf\":{\"no-match\":\"block\",\"block\":["
	    "\"bad.example\",\"*.worse.example/ads/*\"],\"allow\":["
	    "\"bad.example/ok\"]},\"mbsf\":{\"no-match\":\"block\",\"block\":["
	    "\"tls1.0\",\"tls1.1\"],\"allow\":[\"tls1.2\",\"tls1.3\"],"
	    "\"pass-through\":[\"bank.example\"],\"invalid-server-certificate\":"
	    "\"block\",\"unencrypted\":\"block\"},\"mdr\":{\"no-match\":\"allow\","
	    "\"block\":[\"44D88612FEA8A8F36DE82E1278ABB02F:68\",\"275a021bbfb6489e"
	    "54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\"],\"allow\":["
	    "\"3395856ce81f2b7382dee72602f798b642f14140\"],\"id\":\"g-mdr\"}}") !=
	    NULL, "%s",
	    c);
	/* unbound at a: the zones' views, the Default zone's by all its
	 * prefixes; the DNF's names and the PDNS's answers. */
	ATF_REQUIRE_MSG((c = plan_spec(&r, "dns")) != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(c, "\"unis\":[{\"id\":\"uni-hq\",\"address\":"
	    "\"10.1.0.1\",\"prefix\":\"10.1.0.0/24\"}]") != NULL && strstr(c,
	    "{\"name\":\"z1\",\"prefixes\":[\"0.0.0.0/0\",\"::/0\"],") != NULL &&
	    strstr(c, "\"pdns\":{\"no-match\":\"allow\",\"block\":[{\"type\":"
	    "\"A\",\"value\":\"192.0.2.66\"},{\"type\":\"CNAME\",\"value\":"
	    "\"*.tracker.example\"},{\"type\":\"NS\",\"value\":\"ns.evil.example\""
	    ",\"encryption\":\"any\"},{\"type\":\"NS\",\"value\":\"198.51.100.53\"}"
	    ",{\"type\":\"NS\",\"value\":\"2001:db8::53/128\"}],\"allow\":[{"
	    "\"type\":\"AAAA\",\"value\":\"any\"},{\"type\":\"CNAME\",\"value\":"
	    "\"ok.tracker.example\",\"encryption\":[\"unencrypted\",\"dot\"]}]}")
	    != NULL && strstr(c, "\"dnf\":{\"no-match\":"
	    "\"allow\",\"block\":[\"ads.example\",\"cdn.*.example\"],"
	    "\"quarantine\":[\"*.track.*\"],\"allow\":[\"ok.ads.example\"]}") !=
	    NULL, "%s", c);
	/* How the PDNS has DNS carried (D21, D22), the resolver's: DNS over
	 * TLS to the clients too, its questions over TLS to the servers
	 * named. */
	ATF_CHECK_MSG(strstr(c, "\"fib\":1,\"dot\":true,\"upstream\":["
	    "\"192.0.2.53#dns.example\",\"2001:db8::53@8853#dns.example\"],"
	    "\"upstream_tls\":true,") != NULL, "%s", c);
	resp_free(&r);
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

/* Two edges on one agent: the host, and its vnet jail gw (@A/gw). */
static const char sdwan_jail_doc[] =
    "{\"version\":0,"
    "\"ucs\":[{\"id\":\"inet\",\"type\":\"public\",\"billing\":\"flat-rate\","
    "\"tunnel\":{\"kind\":\"gre\"}}],"
    "\"edges\":[{\"server\":\"@A\",\"ucs_end_points\":[{\"id\":\"a-inet\","
    "\"ucs\":\"inet\",\"interface\":\"vtnet0\",\"address\":\"192.0.2.1\"}]},"
    "{\"server\":\"@J\",\"ucs_end_points\":[{\"id\":\"g-inet\",\"ucs\":"
    "\"inet\",\"interface\":\"vtnet0\",\"address\":\"192.0.2.2\"}]}],"
    "\"swvcs\":[{\"id\":\"acme\",\"fib\":1,\"ucs\":[\"inet\"],"
    "\"reserved_prefixes\":[\"100.64.0.0/24\"],"
    "\"bfd\":{\"interval\":200,\"multiplier\":3},"
    "\"zones\":[{\"name\":\"rest\",\"prefixes\":\"Default\"}],"
    "\"intervals\":{\"eval\":1000,\"arrival\":100,\"ir\":500},"
    "\"flows\":[{\"name\":\"all\",\"criteria\":{\"any\":true}}],"
    "\"policies\":[{\"name\":\"open\",\"direction\":\"ingress\","
    "\"criteria\":{}}],"
    "\"end_points\":[{\"id\":\"hq\",\"edge\":\"@A\",\"uni\":{\"id\":"
    "\"uni-hq\",\"interface\":\"lo0\",\"ipv4\":{\"mode\":\"static\","
    "\"prefix\":\"10.1.0.0/24\",\"provider\":[\"10.1.0.1\"]}},\"policy_map\":[{\"zone\":\"rest\","
    "\"app\":\"all\",\"ingress\":\"open\"}]},{\"id\":\"branch\",\"edge\":"
    "\"@J\",\"uni\":{\"id\":\"uni-br\",\"interface\":\"epair1b\",\"ipv4\":{"
    "\"mode\":\"static\",\"prefix\":\"10.2.0.0/24\",\"provider\":["
    "\"10.2.0.1\"]}},"
    "\"policy_map\":[{\"zone\":\"rest\",\"app\":\"all\",\"ingress\":"
    "\"open\"}]}]}]}";

CONSOLE_TC(sdwan_jail, "SD-WAN at an edge that is a vnet jail: checked, "
    "planned and applied there, its probes and steering its own")
ATF_TC_BODY(sdwan_jail, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sj[40];
	char		doc[4096], t1[4096];

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"a\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sa, sizeof(sa), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(sj, sizeof(sj), "%s/gw", sa);
	snprintf(doc, sizeof(doc), "%s", sdwan_jail_doc);
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* Not a jail's name, or no server: refused. */
	{
		char	bad[4096], bad2[4096];

		snprintf(bad, sizeof(bad), "%s", doc);
		while (swap_in(bad, "@J", "nosuch/gw", bad2, sizeof(bad2)))
			snprintf(bad, sizeof(bad), "%s", bad2);
		http("PUT", "/api/sdwan", bad, &r);
		ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no such server "
		    "(an edge is a server, or server/jail") != NULL, "%s", r.body);
		resp_free(&r);
		snprintf(bad, sizeof(bad), "%s", doc);
		snprintf(t1, sizeof(t1), "%s/a b", sa);
		while (swap_in(bad, "@J", t1, bad2, sizeof(bad2)))
			snprintf(bad, sizeof(bad), "%s", bad2);
		http("PUT", "/api/sdwan", bad, &r);
		ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no such server")
		    != NULL, "%s", r.body);
		resp_free(&r);
	}
	while (swap_in(doc, "@J", sj, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* The plan: a tunnel between the host and its jail, each end its
	 * own edge, the jail's named a/gw. */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_EQ_MSG(1, (int)ucl_array_size(ucl_object_lookup(r.json,
	    "tunnels")), "%s", r.body);
	ATF_CHECK_STREQ(sa, jstr(&r, "tunnels.0.ends.0.edge"));
	ATF_CHECK_STREQ(sj, jstr(&r, "tunnels.0.ends.1.edge"));
	/* Each edge watches its links: its UCS end points' and UNIs'. */
	ATF_CHECK_MSG(strstr(r.body, "\"links\":[{\"interface\":\"vtnet0\","
	    "\"id\":\"a-inet\",\"role\":\"ucs\"},{\"interface\":\"lo0\","
	    "\"id\":\"uni-hq\",\"role\":\"uni\"}]") != NULL && strstr(r.body,
	    "\"links\":[{\"interface\":\"vtnet0\",\"id\":\"g-inet\",\"role\":"
	    "\"ucs\"},{\"interface\":\"epair1b\",\"id\":\"uni-br\",\"role\":"
	    "\"uni\"}]") != NULL, "%s", r.body);
	/* The jail's BIRD, with BFD: an instance named by the jail too,
	 * run in it by the host's agent. */
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"sdwan-bird\",\"instances\":[{"
	    "\"name\":\"sw1-gw\",\"fib\":1,") != NULL, "%s", r.body);
	resp_free(&r);
	/* The jail runs no BIRD here (jls lists none in a test): the
	 * service without BFD from here on. */
	ATF_REQUIRE(swap_in(doc, "\"bfd\":{\"interval\":200,\"multiplier\":3},", "",
	    t1, sizeof(t1)));
	snprintf(doc, sizeof(doc), "%s", t1);
	/* Applied: the jail's jobs run in it, its probes, rules and
	 * steering are the jail's on the agent, the host's its own. */
	/* What the jail's edge needs is looked for in the jail, as it
	 * sees its files: strongSwan, for the public UCS's IPsec, is not
	 * there, though the host has it. */
	http("POST", "/api/sdwan/apply", "{}", &r);
	EXPECT(&r, 409);
	ATF_CHECK_MSG(strstr(r.body, "a/gw: pkg install strongswan") != NULL &&
	    strstr(r.body, "a: pkg install") == NULL, "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"tunnel\":{\"kind\":\"gre\"}",
	    "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":false}", t1, sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":0", "\"version\":1", doc,
	    sizeof(doc)));
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	(void)unlink("jexec.log");
	http("POST", "/api/sdwan/apply", "{}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	resp_free(&r);
	/* Its tunnel made in it (ifconfig -j), the host's on the host. */
	ATF_CHECK_MSG(system("grep -q '^-j 4 gre101 create' ifconfig.log && "
	    "grep -q '^gre100 create' ifconfig.log && ! grep -q '^-j 4 gre100' "
	    "ifconfig.log") == 0, "the jail's tunnel was not made in it");
	ATF_CHECK_MSG(system("grep -q '^jexec 4 .*ipfw -q /var/run/arcana-sdwan-"
	    "rules.load' jexec.log") == 0, "the jail's rules were not loaded "
	    "by its ipfw");
	ATF_CHECK_MSG(system("test -f sdwan-probes@gw.json && test -f "
	    "sdwan-rules@gw.json && test -f sdwan-probes.json") == 0,
	    "the jail's probes and rules are not its own");
	snprintf(t1, sizeof(t1), "/api/servers/%s/sdwan", sa);
	http("GET", t1, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"edges\":[{\"jail\":\"gw\",\"rules\":{"
	    "\"set\":") != NULL && strstr(r.body, "\"jail\":\"gw\",\"fib\":1")
	    != NULL, "%s", r.body);
	resp_free(&r);
	/* What only the host's own edge has yet (its NTP, say) is refused
	 * at the jail's, said so. */
	ATF_REQUIRE(swap_in(doc, "\"ucs_end_points\":[{\"id\":\"g-inet\"",
	    "\"ntp\":[\"10.0.0.1\"],\"ucs_end_points\":[{\"id\":\"g-inet\"",
	    t1, sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":1", "\"version\":2", doc,
	    sizeof(doc)));
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/sdwan/apply", "{}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "failed") == 0 &&
	    strstr(r.body, "an edge that is a vnet jail has no ntp yet") != NULL,
	    "%s", r.body);
	resp_free(&r);
}

/*
 * The root lab (sdwan_lab): two vnet jails, each an agent's host, an
 * epair between them for the Internet and another whose ends are their
 * UNIs.  What a service makes there, snapshot by lab.sh: each jail's
 * addresses, FIBs and tunnels, and its routes to the lab's prefixes in
 * every table.
 */
#define	LAB_A	"arcw_la"
#define	LAB_B	"arcw_lb"

static const char lab_sh[] =
    "#!/bin/sh\n"
    "# up: the jails and epairs; snap: what is made; down: all gone.\n"
    "case $1 in\n"
    "up)\n"
    "\tfor j in " LAB_A " " LAB_B "; do jail -c name=$j vnet persist "
    "path=/ host.hostname=$j >/dev/null || exit 1; jexec $j ifconfig lo0 "
    "inet 127.0.0.1/8 up; done\n"
    "\tu=$(ifconfig epair create) && n=$(ifconfig epair create) || exit 1\n"
    "\techo \"${u%a} ${n%a}\" > lab.epairs\n"
    "\tifconfig ${u} vnet " LAB_A " && ifconfig ${u%a}b vnet " LAB_B " && "
    "ifconfig ${n} vnet " LAB_A " && ifconfig ${n%a}b vnet " LAB_B " || "
    "exit 1\n"
    "\tjexec " LAB_A " ifconfig ${u} inet 10.203.0.1/24 up && jexec " LAB_B
    " ifconfig ${u%a}b inet 10.203.0.2/24 up && jexec " LAB_A " ifconfig "
    "${n} up && jexec " LAB_B " ifconfig ${n%a}b up\n"
    "\techo \"${u} ${u%a}b ${n} ${n%a}b\" ;;\n"
    "snap)\n"
    "\tfor j in " LAB_A " " LAB_B "; do echo \"== $j\"\n"
    "\t\tjexec $j ifconfig -a | awk '/^[a-z]/ { i = $1 } /^\\t(inet |fib:|"
    "tunnelfib:|tunnel )/ && !/fe80:/ { print i, $1, $2, $3, $4 }'\n"
    "\t\tf=0; while [ $f -lt $(jexec $j sysctl -n net.fibs) ]; do jexec $j "
    "netstat -rn4 -F $f | awk -v f=$f '$1 ~ /^(10\\.|100\\.64\\.)/ { print "
    "f, $1, $2, $4 }'; f=$((f + 1)); done\n"
    "\tdone ;;\n"
    "down)\n"
    "\tfor j in " LAB_A " " LAB_B "; do jls -j $j >/dev/null 2>&1 || "
    "continue\n"
    "\t\tfor i in $(jexec $j ifconfig -l); do case $i in gre*|gif*|vlan*) "
    "jexec $j ifconfig $i destroy ;; esac; done; done\n"
    "\t[ -f lab.epairs ] && for e in $(cat lab.epairs); do for j in "
    LAB_A " " LAB_B "; do ifconfig -j $j ${e}a destroy 2>/dev/null; "
    "ifconfig -j $j ${e}b destroy 2>/dev/null; done; ifconfig ${e}a "
    "destroy 2>/dev/null; done\n"
    "\tfor j in " LAB_A " " LAB_B "; do jls -j $j >/dev/null 2>&1 && "
    "jail -r $j >/dev/null; done; true ;;\n"
    "esac\n";

/* The lab's service: hq on a, branch on b (its UNI on unib), a gre
 * tunnel between them; hq's UNI routes 10.1.8.0/22 by 10.1.0.2. */
static void
lab_doc(char *buf, size_t len, const char *version, const char *sa,
    const char *sb, char ifs[4][IFNAMSIZ], const char *unib)
{

	snprintf(buf, len, "{\"version\":%s,"
	    "\"ucs\":[{\"id\":\"inet\",\"type\":\"public\",\"billing\":"
	    "\"flat-rate\",\"tunnel\":{\"kind\":\"gre\",\"ipsec\":false}}],"
	    "\"edges\":[{\"server\":\"%s\",\"ucs_end_points\":[{\"id\":"
	    "\"a-inet\",\"ucs\":\"inet\",\"interface\":\"%s\",\"address\":"
	    "\"10.203.0.1\"}]},{\"server\":\"%s\",\"ucs_end_points\":[{\"id\":"
	    "\"b-inet\",\"ucs\":\"inet\",\"interface\":\"%s\",\"address\":"
	    "\"10.203.0.2\"}]}],"
	    "\"swvcs\":[{\"id\":\"acme\",\"fib\":1,\"ucs\":[\"inet\"],"
	    "\"reserved_prefixes\":[\"100.64.0.0/24\"],"
	    "\"zones\":[{\"name\":\"rest\",\"prefixes\":\"Default\"}],"
	    "\"intervals\":{\"eval\":1000,\"arrival\":100,\"ir\":500},"
	    "\"flows\":[{\"name\":\"all\",\"criteria\":{\"any\":true}}],"
	    "\"policies\":[{\"name\":\"open\",\"direction\":\"ingress\","
	    "\"criteria\":{}}],"
	    "\"end_points\":[{\"id\":\"hq\",\"edge\":\"%s\",\"uni\":{\"id\":"
	    "\"uni-hq\",\"interface\":\"%s\",\"ipv4\":{\"mode\":\"static\","
	    "\"prefix\":\"10.1.0.0/24\",\"provider\":[\"10.1.0.1\"]},"
	    "\"routes\":[{\"prefix\":\"10.1.8.0/22\",\"next_hop\":"
	    "\"10.1.0.2\"}]},"
	    "\"policy_map\":[{\"zone\":\"rest\",\"app\":\"all\",\"ingress\":"
	    "\"open\"}]},{\"id\":\"branch\",\"edge\":\"%s\",\"uni\":{\"id\":"
	    "\"uni-br\",\"interface\":\"%s\",\"ipv4\":{\"mode\":\"static\","
	    "\"prefix\":\"10.2.0.0/24\",\"provider\":[\"10.2.0.1\"]}},"
	    "\"policy_map\":[{\"zone\":\"rest\",\"app\":\"all\",\"ingress\":"
	    "\"open\"}]}]}]}", version, sa, ifs[0], sb, ifs[1], sa, ifs[2],
	    sb, unib);
}

/* The document's version now, for the next PUT. */
static void
lab_version(char *buf, size_t len)
{
	struct resp	r;

	http("GET", "/api/sdwan", NULL, &r);
	EXPECT(&r, 200);
	snprintf(buf, len, "%s", jstr(&r, "version") != NULL ? jstr(&r,
	    "version") : "0");
	resp_free(&r);
}

/* What lab.sh's snap says, malloc'd. */
static char *
lab_snap(void)
{
	FILE	*fp;
	char	*s;
	size_t	 n;

	ATF_REQUIRE(system("./lab.sh snap > snap.out 2>&1") == 0);
	ATF_REQUIRE((fp = fopen("snap.out", "r")) != NULL);
	s = calloc(1, 65536);
	n = fread(s, 1, 65535, fp);
	s[n] = '\0';
	fclose(fp);
	return (s);
}

/* A sysctl of a lab jail, its value. */
static long
lab_sysctl(const char *jail, const char *oid)
{
	char	 cmd[200], line[64];
	FILE	*fp;
	long	 v = -1;

	snprintf(cmd, sizeof(cmd), "jexec %s sysctl -n %s", jail, oid);
	if ((fp = popen(cmd, "r")) == NULL)
		return (-1);
	if (fgets(line, sizeof(line), fp) != NULL)
		v = strtol(line, NULL, 10);
	pclose(fp);
	return (v);
}

ATF_TC_WITH_CLEANUP(sdwan_lab);
ATF_TC_HEAD(sdwan_lab, tc)
{
	atf_tc_set_md_var(tc, "descr", "The console's SD-WAN apply on a lab "
	    "for real, as root: two vnet jails, each an agent's host; a "
	    "failing apply rolled back leaves their addresses, FIBs and "
	    "routes as they were, a good one makes them, the service taken "
	    "away takes them away again");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_CLEANUP(sdwan_lab, tc)
{

	stop();
	/* Interfaces out of the jails before they go: a vnet torn down
	 * with them panics a debug kernel. */
	if (access("lab.sh", X_OK) == 0)
		(void)system("./lab.sh down");
}
ATF_TC_BODY(sdwan_lab, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], body[MAXPATHLEN + 64], sa[16], sb[16];
	char		doc[4096], ver[16], line[128], ifs[4][IFNAMSIZ];
	char		*before, *after;
	FILE		*fp;

	if (system("jls -j " LAB_A " >/dev/null 2>&1 || jls -j " LAB_B
	    " >/dev/null 2>&1") == 0)
		atf_tc_skip("a jail of the lab's names is there already");
	if (system("ifconfig -C | grep -qw gre && ifconfig -C | grep -qw "
	    "epair") != 0)
		atf_tc_skip("no gre(4) or epair(4)");
	put("lab.sh", lab_sh);
	ATF_REQUIRE(chmod("lab.sh", 0755) == 0);
	ATF_REQUIRE((fp = popen("./lab.sh up", "r")) != NULL);
	ATF_REQUIRE(fgets(line, sizeof(line), fp) != NULL);
	ATF_REQUIRE(pclose(fp) == 0);
	ATF_REQUIRE(sscanf(line, "%15s %15s %15s %15s", ifs[0], ifs[1],
	    ifs[2], ifs[3]) == 4);
	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	agent_jailed(LAB_A, "ea");
	agent_jailed(LAB_B, "eb");
	snprintf(body, sizeof(body), "{\"name\":\"a\",\"uri\":\"unix:%s/ea/"
	    "agent.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sa, sizeof(sa), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"b\",\"uri\":\"unix:%s/eb/"
	    "agent.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sb, sizeof(sb), "%s", strcmp(jstr(&r, "servers.0.id"), sa) ==
	    0 ? jstr(&r, "servers.1.id") : jstr(&r, "servers.0.id"));
	resp_free(&r);
	before = lab_snap();
	ATF_REQUIRE_EQ(1, lab_sysctl(LAB_A, "net.fibs"));

	/*
	 * b's UNI on an interface b has not: its step fails after the
	 * tunnel's and a's UNI's were made, and the apply rolled back
	 * leaves the jails as they were, but net.fibs, which only goes up.
	 */
	lab_doc(doc, sizeof(doc), "0", sa, sb, ifs, "lab9");
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/sdwan/apply", "{\"fresh\":true}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "rolled back") == 0 &&
	    strstr(r.body, "\"state\":\"undone\"") != NULL, "%s", r.body);
	resp_free(&r);
	after = lab_snap();
	ATF_CHECK_STREQ(before, after);
	free(after);

	/* The good one: made for real. */
	lab_version(ver, sizeof(ver));
	lab_doc(doc, sizeof(doc), ver, sa, sb, ifs, ifs[3]);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/sdwan/apply", "{\"fresh\":true}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_REQUIRE_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	resp_free(&r);
	after = lab_snap();
	/* Each end of the tunnel in the service's table, its inner /31
	 * and its outer ends the underlay's; the UNI's address in it too,
	 * and hq's static route; b's routes to hq by the tunnel. */
	snprintf(line, sizeof(line), "%s: inet 10.1.0.1 netmask 0xffffff00\n"
	    "%s: fib: 1", ifs[2], ifs[2]);
	ATF_CHECK_MSG(strstr(after, "gre100: tunnel inet 10.203.0.1 -->\n"
	    "gre100: inet 100.64.0.0 --> 100.64.0.1\ngre100: fib: 1") != NULL &&
	    strstr(after, "gre101: inet 100.64.0.1 --> 100.64.0.0\n"
	    "gre101: fib: 1") != NULL && strstr(after, line) != NULL, "%s",
	    after);
	ATF_CHECK_MSG(strstr(after, "1 10.1.0.0/24 link#") != NULL &&
	    strstr(after, "1 10.1.8.0/22 10.1.0.2 ") != NULL && strstr(after,
	    "1 10.1.8.0/22 100.64.0.0 gre101") != NULL && strstr(after,
	    "1 10.2.0.0/24 link#") != NULL, "%s", after);
	free(after);
	ATF_CHECK_EQ(2, lab_sysctl(LAB_A, "net.fibs"));
	ATF_CHECK_EQ(2, lab_sysctl(LAB_B, "net.fibs"));
	ATF_CHECK_EQ(1, lab_sysctl(LAB_A, "net.inet.ip.forwarding"));
	ATF_CHECK_EQ(1, lab_sysctl(LAB_B, "net.inet6.ip6.forwarding"));
	/* The tunnel carries: b's inner end answers a's ping, in the
	 * service's table. */
	ATF_CHECK_MSG(system("jexec " LAB_A " setfib 1 ping -c 1 -t 5 "
	    "100.64.0.1 >/dev/null") == 0, "no answer through the tunnel");

	/* The service taken away: what it made goes, the rest stays. */
	lab_version(ver, sizeof(ver));
	snprintf(doc, sizeof(doc), "{\"version\":%s,\"ucs\":[],\"edges\":[],"
	    "\"swvcs\":[]}", ver);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/sdwan/apply", "{}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "done") == 0, "%s",
	    r.body);
	resp_free(&r);
	after = lab_snap();
	ATF_CHECK_STREQ(before, after);
	free(after);
	free(before);
}

CONSOLE_TC(sdwan_mesh, "Several transports on a pair of edges: two Internet "
    "Accesses join only when their tunnels are of one kind, IPsec alike, so "
    "K transports give K tunnels; a UCS End Point's preference orders the "
    "steering where a policy names none")
ATF_TC_BODY(sdwan_mesh, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		/* A second Internet Access, WireGuard, beside the gre one. */
		{ "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}}",
		    "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}},{\"id\":\"wgnet\","
		    "\"type\":\"public\",\"billing\":\"flat-rate\",\"tunnel\":{"
		    "\"kind\":\"wg\"}}" },
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-wg\",\"ucs\":\"wgnet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"breakout\":true,\"preference\":1},"
		    "{\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"preference\":10" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		/* b's wg end goes through a relay of its own toward a, in a
		 * table of its own; a's is behind NAT. */
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-wg\",\"ucs\":\"wgnet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\",\"preference\":1,\"vrf\":2,\"relay\":"
		    "[{\"to\":\"@A\",\"endpoint\":\"127.0.0.1:51821\",\"port\":14350}]},"
		    "{\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\",\"preference\":10" },
		{ "\"address\":\"192.0.2.1\",\"breakout\":true,\"preference\":1}",
		    "\"address\":\"192.0.2.1\",\"breakout\":true,\"preference\":1,"
		    "\"nat\":true}" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"ucs\":[\"inet\",\"mpls\"]", "\"ucs\":[\"inet\",\"wgnet\","
		    "\"mpls\"]" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
	};

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
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* A preference out of range is refused. */
	ATF_REQUIRE(swap_in(doc, "\"preference\":10", "\"preference\":70000", t1,
	    sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "its preference is 0 "
	    "to 65535") != NULL, "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* Three tunnels, one a transport: gre over inet, wg over wgnet,
	 * geneve over mpls; none across inet and wgnet. */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"id\":\"acme/a-inet-b-inet\"") != NULL &&
	    strstr(r.body, "\"id\":\"acme/a-wg-b-wg\"") != NULL &&
	    strstr(r.body, "\"id\":\"acme/a-mpls-b-mpls\"") != NULL &&
	    strstr(r.body, "a-inet-b-wg") == NULL && strstr(r.body,
	    "a-wg-b-inet") == NULL && jstr(&r, "tunnels.3.id") == NULL, "%s",
	    r.body);
	/* The steering's order where no policy names end points: the gre
	 * tunnel, its end preferred 10, before the wg one, preferred 1. */
	ATF_CHECK_MSG(strstr(r.body, "\"preference\":10") != NULL, "%s",
	    r.body);
	/*
	 * b's wg peer toward a points at b's relay, its interface made
	 * without a tunnelfib (the relay is on the host, in the first
	 * table) and the relay's own flow sent by b's underlay table;
	 * a's peer toward b has b's address and port; a's wg end is
	 * behind NAT, so nobody is given an endpoint for it but through
	 * a relay.
	 */
	ATF_CHECK_MSG(strstr(r.body, "\"endpoint\":\"127.0.0.1:51821\"") != NULL
	    && strstr(r.body, "\"endpoint\":\"192.0.2.2:51101\"") != NULL &&
	    strstr(r.body, "setfib 2 udp from me to 192.0.2.1 dst-port 14350 "
	    "out") != NULL, "%s", r.body);
	resp_free(&r);
	/*
	 * Two tunnels to the same edge: a far prefix's route goes over
	 * both at once, one multipath route (ECMP) the kernel shares the
	 * flows over, not kept in rc.conf; and BIRD merges the paths iBGP
	 * brings.
	 */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG((strstr(r.body, "\"gateway\":\"100.64.0.0,100.64.0.2\"")
	    != NULL || strstr(r.body, "\"gateway\":\"100.64.0.2,100.64.0.0\"")
	    != NULL || strstr(r.body, "\"gateway\":\"100.64.0.1,100.64.0.3\"")
	    != NULL || strstr(r.body, "\"gateway\":\"100.64.0.3,100.64.0.1\"")
	    != NULL) && strstr(r.body, "\"to\":\"b\",\"local\":\"100.64.0.0\"")
	    != NULL && strstr(r.body, "\"to\":\"b\",\"local\":\"100.64.0.2\"")
	    != NULL, "%s", r.body);
	resp_free(&r);
	/* A relay toward no edge, or on an underlay that is not WireGuard,
	 * is refused. */
	ATF_REQUIRE(swap_in(doc, "\"to\":\"", "\"to\":\"x", t1, sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "to is one of the "
	    "edges") != NULL, "%s", r.body);
	resp_free(&r);
	/*
	 * A relay the apply makes, speederv2's: b's client listening where
	 * its wg peer points and sending to a's underlay at the relay's
	 * port; a's server there, handing it to a's wg port; each a
	 * profile of arcana_relay, started, taken away with the tunnel;
	 * the plugin is what the edges need.
	 */
	ATF_REQUIRE(swap_in(doc, "\"port\":14350}", "\"port\":14350,"
	    "\"plugin\":\"speederv2\",\"fec\":\"10:5\",\"mode\":0}", t1,
	    sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":0", "\"version\":1", doc,
	    sizeof(doc)));
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"relay:c_") != NULL &&
	    strstr(r.body, "\"key\":\"relay:s_") != NULL && strstr(r.body,
	    "\"role=client\",\"listen=127.0.0.1:51821\",\"remote=192.0.2.1:"
	    "14350\",\"fec=10:5\",\"mode=0\",\"report=10\",\"fifo=/var/run/"
	    "arcana_relay/c_") != NULL && strstr(r.body, "\"role=server\",\""
	    "listen=192.0.2.1:14350\",\"remote=127.0.0.1:51") != NULL &&
	    strstr(r.body, ".fifo\",\"svcj=yes\",\"svcj_ipaddrs=192.0.2.2,"
	    "127.0.0.1\"]") != NULL && strstr(r.body, ".fifo\",\"svcj=yes\","
	    "\"svcj_ipaddrs=192.0.2.1,127.0.0.1\"]") != NULL &&
	    strstr(r.body, "\"kind\":\"speeder\",\"verb\":\"remove\"") != NULL &&
	    strstr(r.body, "UDPspeeder, for the FEC relays") != NULL, "%s",
	    r.body);
	resp_free(&r);
	/* Another plugin, or ratios for a relay of the admin's own, are
	 * refused. */
	ATF_REQUIRE(swap_in(doc, "\"plugin\":\"speederv2\"", "\"plugin\":"
	    "\"udp2raw\"", t1, sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "plugin is speederv2")
	    != NULL, "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"plugin\":\"speederv2\",", "", t1,
	    sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "fec is its plugin's")
	    != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_host, "A host-as-subscriber edge (own_table): the service's "
    "overlay in the host's own table, its uplinks in tables of their own, "
    "its UNI left where it is; a host running its own BIRD takes no "
    "service's")
ATF_TC_BODY(sdwan_host, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		/* b is the host-as-subscriber: its uplink in table 2. */
		{ "{\"server\":\"@B\",\"ucs_end_points\":[{\"id\":\"b-inet\","
		    "\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "{\"server\":\"@B\",\"own_table\":true,\"ucs_end_points\":[{"
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\",\"vrf\":2" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\",\"host_addressed\":true" },
	};

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
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* A host that runs its own BIRD cannot carry the service's (bfd). */
	ATF_REQUIRE(swap_in(doc, "\"own_table\":true", "\"own_table\":true,"
	    "\"host_bird\":true", t1, sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "runs its own BIRD") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/*
	 * On b: its tunnel end, its routes and its BIRD in the host's own
	 * table (0, no kernel table statement), its UNI not moved nor
	 * addressed (host_addressed), the uplinks' connected routes kept
	 * in the host's table too (allfibs); on a, as ever, table 1.
	 */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"interface\":\"gre100\",\"fib\":1,") !=
	    NULL && strstr(r.body, "\"interface\":\"gre101\",\"fib\":0,") != NULL,
	    "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"if-set\",\"interface\":\"lo0\","
	    "\"fib\":1,") != NULL && strstr(r.body, "\"key\":\"uni:branch\","
	    "\"phase\":") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"allfibs\":true") != NULL && strstr(
	    r.body, "\"allfibs\":false") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"name\":\"sw1\",\"fib\":0,") != NULL &&
	    strstr(r.body, "\"name\":\"sw1\",\"fib\":1,") != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_loop, "iBGP between the edges' loopbacks: a lo(4) per edge, "
    "a static to each far loopback over every tunnel with BFD on each path, "
    "one multihop session per edge, reflection on the edges carrying "
    "transit, the UNIs' prefixes as the edge's own statics, no far-prefix "
    "kernel statics")
ATF_TC_BODY(sdwan_loop, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[12288], t1[12288];
	const char	*p;
	size_t		i;
	int		n;
	static const char *const edits[][2] = {
		{ "\"bfd\":{\"interval\":200,\"multiplier\":3},",
		    "\"bfd\":{\"interval\":200,\"multiplier\":3},\"ibgp\":"
		    "\"loopback\"," },
		/* b carries no transit: it reflects nothing, breaks out for
		 * nobody. */
		{ "{\"server\":\"@B\",\"ucs_end_points\"",
		    "{\"server\":\"@B\",\"transit\":false,\"ucs_end_points\"" },
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\"" },
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
	};

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
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* Without BFD the loopbacks' routes go unwatched: refused. */
	ATF_REQUIRE(swap_in(doc, "\"bfd\":{\"interval\":200,\"multiplier\":3},",
	    "\"bfd\":null,", t1, sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "ibgp loopback needs "
	    "bfd") != NULL, "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/*
	 * The plan: a loopback per edge after the tunnels' pairs (.0/31,
	 * .2/31), so a's is 100.64.0.4 and b's 100.64.0.6; a's BIRD has
	 * a static to b's loopback by the gre tunnel (b's inner .1), the
	 * backup geneve one (.3) in a lower static, a multihop session
	 * from loopback to loopback with rr client (a carries transit,
	 * b does not), the hq UNI's subnet and static route and the
	 * remote end point's prefix as its own statics kept out of the
	 * kernel; no kernel static for the far prefixes on b.
	 */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"loop:acme\"") != NULL &&
	    strstr(r.body, "\"address\":\"100.64.0.4/32\"") != NULL && strstr(
	    r.body, "\"address\":\"100.64.0.6/32\"") != NULL, "%s", r.body);
	/* BIRD's forms (agent_test's sdwan_forms has their text). */
	ATF_CHECK_MSG(strstr(r.body, "\"loopback\":true,") != NULL && strstr(
	    r.body, "\"loop\":{\"local4\":\"100.64.0.4\",\"transit\":true,"
	    "\"edges\":[{\"name\":\"b\",\"ipv4\":\"100.64.0.6\",\"paths4\":"
	    "[\"100.64.0.1\"],\"backup4\":[\"100.64.0.3\"]}]") != NULL, "%s",
	    r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"loop\":{\"local4\":\"100.64.0.6\","
	    "\"edges\":[{\"name\":\"a\",\"ipv4\":\"100.64.0.4\",") != NULL,
	    "%s", r.body);
	for (n = 0, p = r.body; (p = strstr(p, "\"transit\":true")) != NULL; p++)
		n++;
	ATF_CHECK_MSG(n == 1, "transit %d times", n);
	ATF_CHECK_MSG(strstr(r.body, "\"multihop\":true,\"sessions\":true}") !=
	    NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"origins\":[{\"id\":\"hq\",\"interface\":"
	    "\"lo0\",\"ipv4\":[{\"prefix\":\"10.1.0.0/24\"},{\"prefix\":"
	    "\"10.1.8.0/22\",\"next_hop\":\"10.1.0.2\"}]},{\"id\":\"road\","
	    "\"interface\":\"wg5\",\"ipv4\":[{\"prefix\":\"10.30.0.0/24\"}]}]")
	    != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"route:acme:10.1.0.0/24\"") == NULL &&
	    strstr(r.body, "\"key\":\"route:acme:10.30.0.0/24\"") == NULL, "%s",
	    r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"direct\":[\"lo0\",\"gre100\","
	    "\"geneve102\",\"lo1") != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(l3nm_plan, "The planner reads the L3NM (PLAN-SDN-YANG 4.5.4): "
    "a node's active profile over the service's (its AS, router id and "
    "an RD it asks to be allocated), a service naming no table given "
    "one from the ledger, the same plan after plan")
ATF_TC_BODY(l3nm_plan, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[1024], sa[16], sb[16], want[200];
	char		doc[12288], t1[12288], fib[16], *first;
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\"" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
	};

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
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* The service's table on each node, its tables named by it. */
	http("GET", "/api/sdwan/ledger", NULL, &r);
	EXPECT(&r, 200);
	snprintf(want, sizeof(want), "\"acme/%s\":1", sa);
	ATF_CHECK_MSG(strstr(r.body, want) != NULL && strstr(r.body,
	    "\"tables\":{\"acme\":\"sw1\"}") != NULL, "%s", r.body);
	resp_free(&r);
	/* Node a's active profile: its own AS and router id, an RD
	 * allocated; node b keeps the service's. */
	snprintf(t1, sizeof(t1), L3NM "/vpn-services/vpn-service=acme/"
	    "vpn-nodes/vpn-node=%s", sa);
	snprintf(body, sizeof(body), "{\"ietf-l3vpn-ntw:vpn-node\":[{"
	    "\"vpn-node-id\":\"%s\",\"active-vpn-instance-profiles\":{"
	    "\"vpn-instance-profile\":[{\"profile-id\":\"subscriber\","
	    "\"local-as\":65010,\"router-id\":[{\"address-family\":"
	    "\"ietf-vpn-common:ipv4\",\"router-id\":\"10.255.0.1\"}],"
	    "\"rd-auto\":{\"auto\":[null]}}]}}]}", sa);
	http("PATCH", t1, body, &r);
	ATF_REQUIRE_MSG(r.status == 204, "%d %s", r.status, r.body);
	resp_free(&r);
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"as\":65010,\"router_id\":\"10.255.0.1\"")
	    != NULL && strstr(r.body, "\"as\":64600,\"router_id\":") != NULL,
	    "%s", r.body);
	first = strdup(r.body);
	resp_free(&r);
	http("GET", "/api/sdwan/ledger", NULL, &r);
	EXPECT(&r, 200);
	snprintf(want, sizeof(want), "\"rds\":{\"acme/%s\":\"0:65010:1\"}", sa);
	ATF_CHECK_MSG(strstr(r.body, want) != NULL, "%s", r.body);
	resp_free(&r);
	/* The same again: nothing moves between plans. */
	http("GET", "/api/sdwan/plan", NULL, &r);
	ATF_CHECK_STREQ(first, r.body);
	resp_free(&r);
	free(first);
	/* A service naming no table: the lowest no other has. */
	http("DELETE", L3NM "/vpn-services/vpn-service=acme/"
	    "arcana-l3nm:sdwan/fib", NULL, &r);
	resp_free(&r);
	http("DELETE", L3NM "/vpn-services/vpn-service=acme/"
	    "vpn-instance-profiles/vpn-instance-profile=subscriber/"
	    "arcana-l3nm:fib", NULL, &r);
	resp_free(&r);
	http("GET", "/api/sdwan/ledger", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE_MSG(jstr(&r, "fibs.acme") != NULL, "%s", r.body);
	snprintf(fib, sizeof(fib), "%s", jstr(&r, "fibs.acme"));
	snprintf(want, sizeof(want), "\"tables\":{\"acme\":\"sw%s\"}", fib);
	ATF_CHECK_MSG(strcmp(fib, "1") == 0 && strstr(r.body, want) != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	snprintf(want, sizeof(want), "\"swvc\":\"acme\",\"fib\":%s,", fib);
	ATF_CHECK_MSG(strstr(r.body, want) != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_infeasible, "The infeasible refused (PLAN-SDN-YANG 4.5.6): "
    "an edge whose policies commit more bandwidth than its uplinks carry "
    "is not planned, the reason and the commit that would fit said; one "
    "with room is")
ATF_TC_BODY(sdwan_infeasible, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"bandwidth\":400000" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\",\"bandwidth\":300000" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
	};

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
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* a carries 700 kbit/s, its policies commit 1 Mbit/s (shared):
	 * refused, with the commit that fits; nothing to apply. */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 409);
	ATF_CHECK_MSG(strstr(r.body, "infeasible: edge a's policies commit "
	    "1000000 bit/s, more than its uplinks carry, 700000 bit/s: it "
	    "fits with the commit of rate limiter shared of service acme at "
	    "700000 bit/s or less") != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", "/api/sdwan/apply", "{}", &r);
	ATF_CHECK_MSG(r.status == 409 && strstr(r.body, "infeasible") != NULL,
	    "%d %s", r.status, r.body);
	resp_free(&r);
	/* An uplink with room: planned. */
	ATF_REQUIRE(swap_in(doc, "\"bandwidth\":400000", "\"bandwidth\":"
	    "10000000", t1, sizeof(t1)));
	ATF_REQUIRE(swap_in(t1, "\"version\":0", "\"version\":1", doc,
	    sizeof(doc)));
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
}

CONSOLE_TC(sdwan_breakout, "Breakout failover: an edge with several breakout "
    "uplinks has a route to each one's gateway, the default by the most "
    "preferred, a probe to each one's beacon, and the agent told to put "
    "the first that answers in the default's place")
ATF_TC_BODY(sdwan_breakout, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		/* A second Internet Access, WireGuard, breaking out too, less
		 * preferred, with a beacon of its own. */
		{ "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}}",
		    "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}},{\"id\":\"wgnet\","
		    "\"type\":\"public\",\"billing\":\"flat-rate\",\"tunnel\":{"
		    "\"kind\":\"wg\"}}" },
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"breakout\":true",
		    "\"id\":\"a-wg\",\"ucs\":\"wgnet\",\"interface\":\"vtnet3\","
		    "\"address\":\"203.0.113.1\",\"gateway\":\"203.0.113.254\","
		    "\"beacon\":\"198.51.100.1\",\"breakout\":true,\"preference\":5},"
		    "{\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\",\"gateway\":\"192.0.2.254\","
		    "\"breakout\":true,\"preference\":10" },
		{ "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"a-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.1\"" },
		{ "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"b-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.2\"" },
		{ "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\"",
		    "\"id\":\"b-mpls\",\"ucs\":\"mpls\",\"interface\":\"vtnet1\","
		    "\"address\":\"10.99.0.2\"" },
		{ "\"ucs\":[\"inet\",\"mpls\"]", "\"ucs\":[\"inet\",\"wgnet\","
		    "\"mpls\"]" },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
	};

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
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* A beacon that is no address is refused. */
	ATF_REQUIRE(swap_in(doc, "\"beacon\":\"198.51.100.1\"",
	    "\"beacon\":\"nowhere\"", t1, sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "its beacon is an "
	    "address") != NULL, "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/*
	 * In the breakout table (2): each gateway by its interface, the
	 * default by the preferred (inet, 10, over wg, 5), the wg one's
	 * beacon by its gateway; a probe to each beacon; the steering's
	 * route with both candidates in that order.
	 */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"route:acme:2:192.0.2.254/32\"") !=
	    NULL && strstr(r.body, "\"key\":\"route:acme:2:203.0.113.254/32\"") !=
	    NULL && strstr(r.body, "\"key\":\"route:acme:2:198.51.100.1/32\"") != NULL,
	    "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"destination\":\"0.0.0.0/0\",\"gateway\":"
	    "\"192.0.2.254\"") != NULL && strstr(r.body, "\"destination\":"
	    "\"0.0.0.0/0\",\"gateway\":\"203.0.113.254\"") == NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"id\":\"bo:a-inet\",\"address\":"
	    "\"192.0.2.254\",\"fib\":2") != NULL && strstr(r.body, "\"id\":"
	    "\"bo:a-wg\",\"address\":\"198.51.100.1\",\"fib\":2") != NULL, "%s",
	    r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"routes\":[{\"fib\":2,\"destination\":"
	    "\"0.0.0.0/0\",\"candidates\":[{\"id\":\"bo:a-inet\",\"via\":"
	    "\"192.0.2.254\"},{\"id\":\"bo:a-wg\",\"via\":\"203.0.113.254\"}]}]")
	    != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_nat64, "NAT64 at one edge (nat64lsn, its pool among the "
    "known prefixes, the way in before the zones, the way back after the "
    "NAT) and CLAT at a UNI (nat64clat), ipfw_nat64 kept; checked")
ATF_TC_BODY(sdwan_nat64, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
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
		{ "\"reserved_prefixes\":[\"100.64.0.0/24\"],",
		    "\"reserved_prefixes\":[\"100.64.0.0/24\"],\"nat64\":{\"prefix\":"
		    "\"64:ff9b::/96\",\"pool\":\"192.0.2.64/26\",\"edge\":\"@A\"}," },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\",\"clat\":{\"prefix\":"
		    "\"2001:db8:c::/96\"}" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
	};

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
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* A prefix that is no /96, an edge that is none, a CLAT without
	 * the service's NAT64: refused. */
	ATF_REQUIRE(swap_in(doc, "\"prefix\":\"64:ff9b::/96\"", "\"prefix\":"
	    "\"64:ff9b::/64\"", t1, sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "nat64 is an object") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"edge\":\"", "\"edge\":\"nosuch", t1,
	    sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && (strstr(r.body, "nat64: edge is one of "
	    "the edges") != NULL || strstr(r.body, "no such") != NULL), "%s",
	    r.body);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"nat64\":{\"prefix\":\"64:ff9b::/96\",\"pool\":"
	    "\"192.0.2.64/26\",\"edge\":\"", "\"nat64x\":{\"prefix\":\"64:ff9b::/96\","
	    "\"pool\":\"192.0.2.64/26\",\"edge\":\"", t1, sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "clat needs the "
	    "service's nat64") != NULL, "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/*
	 * On a: the nat64lsn instance, the pool in the known table, the
	 * IPv6 way in before the zones (rule 100), the pool's way back
	 * after the NAT (11), the CLAT of hq with the NAT64 prefix as
	 * its PLAT, and ipfw_nat64 kept.
	 */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"nat64lsn sw1_64 create prefix4 "
	    "192.0.2.64/26 prefix6 64:ff9b::/96 allow_private\"") != NULL,
	    "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "[\"192.0.2.64/26\",\"0\"]") != NULL, "%s",
	    r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"10 nat64lsn sw1_64 ip6 from "
	    "table(sw1_known) to 64:ff9b::/96 in\"") != NULL && strstr(r.body,
	    "\"11 nat64lsn sw1_64 ip4 from any to 192.0.2.64/26 in recv "
	    "vtnet0\"") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"nat64clat sw1_chq create clat_prefix "
	    "2001:db8:c::/96 plat_prefix 64:ff9b::/96\"") != NULL && strstr(
	    r.body, "\"10 nat64clat sw1_chq ip4 from any to not table(sw1_known) "
	    "in recv lo0\"") != NULL && strstr(r.body, "\"10 nat64clat sw1_chq "
	    "ip6 from any to 2001:db8:c::/96 in\"") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"nat64\"") != NULL && strstr(
	    r.body, "\"args\":[\"ipfw_nat64\"]") != NULL, "%s", r.body);
	/* The CLAT prefix is hq's, routed to a from b like its subnet. */
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"route:acme:2001:db8:c::/96\"") !=
	    NULL || strstr(r.body, "carries 2001:db8:c::/96") != NULL, "%s",
	    r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_sets, "Destination sets by BGP attribute: a service's sets "
    "(AS path, communities), an edge's breakout for each by one of its "
    "uplinks, written as BIRD's filter to the kernel with that gateway, the "
    "gateway routed by its interface in the service's table; bgp_import "
    "sets keeps every other BGP route out of the kernel; checked")
ATF_TC_BODY(sdwan_sets, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
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
		/* The country's routes, by their AS path or a community, go
		 * out by a-inet on a; nothing else of BGP's reaches its
		 * kernel. */
		{ "{\"server\":\"@A\",\"ntp\"",
		    "{\"server\":\"@A\",\"breakout_sets\":[{\"set\":\"country\","
		    "\"via\":\"a-inet\"}],\"bgp_import\":\"sets\",\"ntp\"" },
		{ "\"reserved_prefixes\":[\"100.64.0.0/24\"],",
		    "\"reserved_prefixes\":[\"100.64.0.0/24\"],\"bgp_sets\":[{"
		    "\"name\":\"country\",\"as_path\":[64600,64601],\"communities\":"
		    "[[64600,100]]}]," },
		{ "\"id\":\"uni-hq\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-hq\",\"interface\":\"lo0\"" },
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
	};

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
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* A set that is none, an uplink that is no breakout of the edge:
	 * refused. */
	ATF_REQUIRE(swap_in(doc, "\"set\":\"country\"", "\"set\":\"nowhere\"", t1,
	    sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "nowhere is no bgp_sets "
	    "name") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"via\":\"a-inet\"", "\"via\":\"a-mpls\"", t1,
	    sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "no breakout UCS end "
	    "point of this edge") != NULL, "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* a's BIRD: the filters, the gateway rewritten, the rest of BGP
	 * kept out; the gateway's route in the service's table; b's
	 * BIRD as ever. */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"sets\":{\"only\":true,\"sets\":[{"
	    "\"name\":\"country\",\"via\":\"a-inet\",\"gateway\":"
	    "\"192.0.2.254\",\"as_path\":[64600,64601],\"communities\":[[64600,"
	    "100]]}]}") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"host\":\"b\",\"spec\":{\"service\":"
	    "\"acme\",\"fib\":1,\"table\":1,\"as\":64600,\"router_id\":"
	    "\"100.64.0.1\",\"direct\":[\"vlan104\",\"gre101\",\"geneve103\"],"
	    "\"bfd\"") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"destination\":\"192.0.2.254/32\","
	    "\"gateway\":\"vtnet0\",\"fib\":1") != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_neigh, "Routing neighbours at a UNI: several BGP entries, "
    "one of the service's own AS from a source address, multihop, with BFD "
    "(iBGP, next hop self); OSPF an area per family with BFD; BFD on the "
    "UNI's interface too, and multihop; checked")
ATF_TC_BODY(sdwan_neigh, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[12288], t1[12288];
	size_t		i;
	static const char *const edits[][2] = {
		{ "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\"",
		    "\"id\":\"a-inet\",\"ucs\":\"inet\",\"interface\":\"vtnet0\","
		    "\"address\":\"192.0.2.1\"" },
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
		/* hq: the subscriber's eBGP neighbour watched by BFD, and an
		 * iBGP one of the service's AS from the provider address,
		 * multihop. */
		{ "\"bgp\":{\"family\":\"ipv4\",\"as\":65010,\"neighbors\":"
		    "[\"10.1.0.2\"],\"password\":\"s3cret\",\"hold_time\":90,"
		    "\"distance\":150,\"communities\":[[64600,100]]}",
		    "\"bgp\":[{\"family\":\"ipv4\",\"as\":65010,\"neighbors\":"
		    "[\"10.1.0.2\"],\"password\":\"s3cret\",\"hold_time\":90,"
		    "\"distance\":150,\"communities\":[[64600,100]],\"bfd\":true},"
		    "{\"family\":\"ipv4\",\"as\":64600,\"neighbors\":[\"10.1.0.3\"],"
		    "\"source\":\"10.1.0.1\",\"multihop\":true,\"bfd\":true}]" },
		/* branch: OSPFv3 in the backbone with BFD, OSPFv2 in area 1. */
		{ "\"id\":\"uni-br\",\"interface\":\"vtnet2\"",
		    "\"id\":\"uni-br\",\"interface\":\"lo0\"" },
		{ "\"dns\":[\"2001:db8:1::1\"]}}}",
		    "\"dns\":[\"2001:db8:1::1\"]},\"ospf\":[{\"family\":\"ipv6\","
		    "\"area\":0,\"cost\":50,\"bfd\":true},{\"family\":\"ipv4\","
		    "\"area\":1}]}}" },
	};

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
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	/* A source that is no address is refused. */
	ATF_REQUIRE(swap_in(doc, "\"source\":\"10.1.0.1\"", "\"source\":"
	    "\"nowhere\"", t1, sizeof(t1)));
	http("POST", "/api/sdwan/check", t1, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "bgp: source is an "
	    "address") != NULL, "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"unis\":[{\"id\":\"uni-hq\",\"end_point\":"
	    "\"hq\",\"interface\":\"lo0\",\"bgp\":[{\"family\":\"ipv4\",\"as\":"
	    "65010,\"neighbors\":[\"10.1.0.2\"],") != NULL && strstr(r.body,
	    "{\"family\":\"ipv4\",\"as\":64600,\"neighbors\":[\"10.1.0.3\"],"
	    "\"source\":\"10.1.0.1\",\"multihop\":true,\"bfd\":true}") != NULL,
	    "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"bfd\":{\"interfaces\":[\"gre100\","
	    "\"geneve102\",\"lo0\"],\"interval\":200,\"multiplier\":3,"
	    "\"multihop\":true,") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "{\"id\":\"uni-br\",\"end_point\":"
	    "\"branch\",\"interface\":\"vlan104\",\"ospf\":[{\"family\":"
	    "\"ipv6\",\"area\":0,\"cost\":50,\"bfd\":true},{\"family\":"
	    "\"ipv4\",\"area\":1}]}") != NULL, "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC(sdwan_lists, "SD-WAN's named lists: prefixes, services, UCS, "
    "edges and UCS End Points kept once, each named where a value would "
    "be, checked; a prefix list an ipfw table, a service list the AFS's "
    "protocols and ports, a zone's its prefixes, a policy's the ways it "
    "takes in order of preference")
ATF_TC_BODY(sdwan_lists, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[12288], t1[12288], bad[12288];
	size_t		i;
	static const char *const edits[][2] = {
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
		/* TCP's MSS clamped on the Internet's tunnels: auto. */
		{ "\"tunnel\":{\"kind\":\"gre\",\"ipsec\":true}", "\"tunnel\":{"
		    "\"kind\":\"gre\",\"ipsec\":true,\"mss\":\"auto\"}" },
		/* The lists, and where each is named. */
		{ "\"swvcs\":[", "\"lists\":[{\"name\":\"branches\",\"kind\":"
		    "\"prefixes\",\"items\":[\"10.1.8.0/22\",\"2001:db8:9::/48\"]},"
		    "{\"name\":\"webports\",\"kind\":\"services\",\"protocols\":"
		    "[\"tcp\"],\"ports\":[8443,\"https\"]},{\"name\":\"dc\","
		    "\"kind\":\"prefixes\",\"items\":[\"10.7.0.0/16\"]},{\"name\":"
		    "\"prefer-mpls\",\"kind\":\"ucs-end-points\",\"items\":[{\"id\":"
		    "\"b-inet\",\"preference\":200},\"a-inet\",\"a-mpls\","
		    "\"b-mpls\"]},{\"name\":\"wan\",\"kind\":\"ucs\",\"items\":"
		    "[\"inet\",\"mpls\"]},{\"name\":\"sites\",\"kind\":\"edges\","
		    "\"items\":[\"@A\",\"@B\"]}],\"swvcs\":[" },
		{ "\"flows\":[", "\"flows\":[{\"name\":\"branchweb\",\"criteria\":"
		    "{\"src-list\":\"branches\",\"service-list\":\"webports\"}}," },
		{ "\"prefixes\":[\"10.1.0.0/16\"]", "\"prefixes\":[\"10.1.0.0/16\"],"
		    "\"prefix-list\":\"dc\"" },
		{ "\"af-security-ingress\":\"guard\"", "\"af-security-ingress\":"
		    "\"guard\",\"ucs-list\":\"wan\",\"edge-list\":\"sites\","
		    "\"ucs-end-point-list\":\"prefer-mpls\"" },
		{ "{\"app\":\"web\",\"policy\":\"fast\"}", "{\"app\":\"web\","
		    "\"policy\":\"fast\"},{\"app\":\"branchweb\",\"policy\":"
		    "\"fast\"}" },
	};
	/* Each wrong reference, and what it is told. */
	static const char *const breaks[][3] = {
		{ "\"src-list\":\"branches\"", "\"src-list\":\"nolist\"",
		    "there is no list nolist of prefixes" },
		{ "\"src-list\":\"branches\"", "\"src-list\":\"webports\"",
		    "there is no list webports of prefixes" },
		{ "\"src-list\":\"branches\"", "\"src-list\":\"branches\","
		    "\"sav4\":[\"10.1.0.0/16\"]", "the sav4 and sav6 of a list" },
		{ "\"service-list\":\"webports\"", "\"service-list\":\"webports\","
		    "\"dport\":[80]", "not with protv4, nextheadv6, dport" },
		{ "\"10.7.0.0/16\"", "\"10.7.0.1/16\"", "is not a prefix" },
		{ "\"b-mpls\"]}", "\"x-mpls\"]}", "there is no UCS End Point "
		    "x-mpls" },
		{ "\"preference\":200", "\"preference\":70000", "a preference is "
		    "0 to 65535" },
		{ "\"kind\":\"ucs\"", "\"kind\":\"vrfs\"", "a list is of "
		    "prefixes" },
		{ "\"ucs-list\":\"wan\"", "\"ucs-list\":\"sites\"", "there is no "
		    "list sites of ucs" },
		{ "\"prefixes\":\"Default\"", "\"prefixes\":\"Default\","
		    "\"prefix-list\":\"dc\"", "a Default zone has no prefix list" },
		{ "\"name\":\"dc\"", "\"name\":\"d c\"", "letters, digits" },
	};

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
	for (i = 0; i < nitems(edits); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, edits[i][0], edits[i][1], t1,
		    sizeof(t1)), "%s", edits[i][0]);
		snprintf(doc, sizeof(doc), "%s", t1);
	}
	while (swap_in(doc, "@A", sa, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	while (swap_in(doc, "@B", sb, t1, sizeof(t1)))
		snprintf(doc, sizeof(doc), "%s", t1);
	for (i = 0; i < nitems(breaks); i++) {
		ATF_REQUIRE_MSG(swap_in(doc, breaks[i][0], breaks[i][1], bad,
		    sizeof(bad)), "%s is not in the document", breaks[i][0]);
		http("POST", "/api/sdwan/check", bad, &r);
		ATF_CHECK_MSG(r.status == 400 && strstr(r.body, breaks[i][2]) !=
		    NULL, "%s: HTTP %d, %s", breaks[i][1], r.status, r.body);
		resp_free(&r);
	}
	/* Kept as written: the lists named, not what they stand for. */
	http("PUT", "/api/sdwan", doc, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan", NULL, &r);
	ATF_CHECK(strstr(r.body, "\"prefix-list\":\"dc\"") != NULL &&
	    strstr(r.body, "\"service-list\":\"webports\"") != NULL);
	resp_free(&r);
	/* The plan: branches an ipfw table of both families; webports the
	 * flow's protocol and ports; dc among office's prefixes; fast's
	 * ways from b-inet with its preference. */
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"name\":\"arcl_branches\",\"valtype\":"
	    "\"legacy\",\"entries\":[[\"10.1.8.0/22\",\"0\"],"
	    "[\"2001:db8:9::/48\",\"0\"]]") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "from table(arcl_branches)") != NULL &&
	    strstr(r.body, "tcp from table(arcl_branches) to") != NULL &&
	    strstr(r.body, "dst-port 8443,https") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "[\"10.7.0.0/16\",") != NULL, "%s",
	    r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"preference\":200") != NULL, "%s",
	    r.body);
	/* The MSS clamped on gre100 and gre101 (gre 24 and IPsec 64 under
	 * 1500: 1412, less 40 or 60), ipfw_pmod loaded and kept first. */
	ATF_CHECK_MSG(strstr(r.body, "tcp-setmss 1372 tcp from any to any via "
	    "gre100 tcpflags syn ip4") != NULL && strstr(r.body, "tcp-setmss "
	    "1352 tcp from any to any via gre100 tcpflags syn ip6") != NULL &&
	    strstr(r.body, "\"kind\":\"kmod\",\"verb\":\"load\",\"args\":["
	    "\"ipfw_pmod\"]") != NULL && strstr(r.body, "\"verb\":\"keep\","
	    "\"args\":[\"ipfw_pmod\"]") != NULL, "%s", r.body);
	resp_free(&r);
	/* Not auto nor bytes: refused. */
	ATF_REQUIRE(swap_in(doc, "\"mss\":\"auto\"", "\"mss\":\"big\"", bad,
	    sizeof(bad)));
	http("POST", "/api/sdwan/check", bad, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "mss is auto") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/* The tunnels' MTU likewise: auto, 1500 less the overhead, on the
	 * interface made; or bytes, 1280 to 9000; else refused. */
	ATF_REQUIRE(swap_in(doc, "\"mss\":\"auto\"", "\"mtu\":\"auto\",\"mss\":"
	    "\"auto\"", bad, sizeof(bad)));
	http("POST", "/api/sdwan/check", bad, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_REQUIRE(swap_in(doc, "\"mss\":\"auto\"", "\"mtu\":100,\"mss\":"
	    "\"auto\"", bad, sizeof(bad)));
	http("POST", "/api/sdwan/check", bad, &r);
	ATF_CHECK_MSG(r.status == 400 && strstr(r.body, "mtu is auto") != NULL,
	    "%s", r.body);
	resp_free(&r);
}

CONSOLE_TC_LONG(sdwan_apply, "SD-WAN made on the edges: planned, applied, kept")
ATF_TC_BODY(sdwan_apply, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[1024], body[400], sa[16], sb[16];
	char		doc[8192], t1[8192], t2[300], lifn[32], laddr[64];
	size_t		i;
	FILE		*fp;

	/* The hosts' events read each second: the SENs come by them. */
	snprintf(harness_webconf, sizeof(harness_webconf), "mail_tick = 1;\n");
	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"a\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sa, sizeof(sa), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	http("POST", "/api/settings", "{\"set\":{\"mail_sen\":\"soc@example.org"
	    "\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"name\":\"b\",\"uri\":\"unix:%s/./"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sb, sizeof(sb), "%s", strcmp(jstr(&r, "servers.0.id"), sa) ==
	    0 ? jstr(&r, "servers.1.id") : jstr(&r, "servers.0.id"));
	resp_free(&r);
	/* The lists the security policy names: one pasted, one a
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
		{ "\"block\":[{\"dav4\":[\"192.0.2.0/24\"]}],",
		    "\"block\":[{\"dav4\":[\"192.0.2.0/24\"]}],\"lists\":{\"block\":"
		    "[\"blocked\",\"feedlist\"]}," },
		{ "\"allow\":[\"ok.ads.example\"],", "\"allow\":[\"ok.ads.example\"],"
		    "\"lists\":{\"block\":[\"feedlist\",\"blocked\"]}," },
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
	/* (The end points by edge, as the L3NM keeps them: road, at a,
	 * before branch.) */
	ATF_CHECK(strstr(r.body, "[\"10.1.8.0/22\",\"0\"],[\"10.30.0.0/24\","
	    "\"0\"],[\"2001:db8:1::/64\",\"0\"]") != NULL);
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
	/*
	 * The security policy guard, named by fast, its function policies
	 * (MEF 138).  IPPF before the forward: its entries most specific
	 * first, the Allow tagging, the Block dropping the untagged and
	 * logged; its lists' prefixes in a table of its own, the list the
	 * value.  Its rate limit a pipe of its own on the way out by the
	 * tunnels.
	 */
	ATF_CHECK_MSG(strstr(r.body, "\"12 count tag 1 tcp from any to any "
	    "dst-port 80,https dst-ip 192.0.2.8/29\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"12 deny log logdst rtsock logamount 1000 tcp "
	    "from any to any dst-port 80,https dst-ip 192.0.2.0/24 not tagged 1 "
	    "// security acme g-ippf block\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"12 count tag 1 tcp from any to any dst-port "
	    "80,https dst-ip 192.0.2.8/29\",\"12 deny") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"name\":\"sw1_f0v4\",\"valtype\":\"legacy\","
	    "\"entries\":[[\"198.51.100.0/24\",\"1\"],[\"203.0.113.0/24\",\"1\"]]")
	    != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"12 deny log logdst rtsock logamount 1000 tcp "
	    "from any to any dst-port 80,https dst-ip table(sw1_f0v4,1) not "
	    "tagged 1 // security acme g-ippf block\"") != NULL);
	ATF_CHECK(strstr(r.body, "\"12 deny log logdst rtsock logamount 1000 tcp "
	    "from any to any dst-port 80,https src-ip table(sw1_f0v4,1) not "
	    "tagged 1 // security acme g-ippf block\"") != NULL);
	ATF_CHECK(strstr(r.body, "sw1_f0v6") == NULL);
	ATF_CHECK(strstr(r.body, "\"pipe 3002 config bw 2000000bit/s\"") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"11 pipe 3002 tcp from any to any "
	    "dst-port 80,https src-ip table(sw1_zp0) out { xmit gre100 or xmit "
	    "gif102 }\"") != NULL, "%s", r.body);
	/* DPF, No-match block with redirect: the flow's DNS not to the
	 * edge sent to the service's resolver on hq's address; DNS over
	 * TLS answered at once, port unreachable (R100). */
	ATF_CHECK_MSG(strstr(r.body, "\"12 fwd 10.1.0.1,53 tcp from any to any "
	    "dst-port 80,https ipversion 4 proto udp dst-port 53 not dst-ip me "
	    "not tagged 3 in recv lo0\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"12 unreach port log logdst rtsock logamount 1000 "
	    "tcp from any to any dst-port 80,https proto tcp dst-port 853 not "
	    "dst-ip me not tagged 3 // security acme g-dpf no-match\"") != NULL);
	/* Its entries by message type (Table 6): a response from a server
	 * by its source port, a query to one by its destination port; the
	 * No-match blocks both ways. */
	ATF_CHECK_MSG(strstr(r.body, "\"12 unreach port log logdst rtsock "
	    "logamount 1000 tcp from any to any dst-port 80,https src-ip "
	    "192.0.2.53/32 proto udp src-port 53 not src-ip me not tagged 3 in recv "
	    "lo0 // security acme g-dpf block\"") != NULL && strstr(r.body,
	    "\"12 unreach port log logdst rtsock logamount 1000 tcp from any to "
	    "any dst-port 80,https dst-ip 192.0.2.54/32 proto udp dst-port 53 not "
	    "dst-ip me not tagged 3 in recv lo0 // security acme g-dpf block\"")
	    != NULL && strstr(r.body, "src-ip 192.0.2.53/32 proto udp dst-port 53")
	    == NULL && strstr(r.body, "\"12 unreach port log logdst rtsock "
	    "logamount 1000 tcp from any to any dst-port 80,https proto udp "
	    "src-port 53 not src-ip me not tagged 3 in recv lo0 // security acme "
	    "g-dpf no-match\"") != NULL, "%s", r.body);
	/* The DNF of the office zone: an unbound instance of the service at
	 * a, on hq's provider address, a view of the zone's own by its
	 * prefixes, the Block's names nxdomain, the Allow's transparent, the
	 * lists' domains too. */
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"dns\",\"phase\":10,\"title\":"
	    "\"DNS filtering and protective DNS (MEF 138): unbound, 1 instance "
	    "in the services' tables, a view a zone\"") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"sdwan-dns\",\"instances\":[{"
	    "\"name\":\"sw1\",\"fib\":1,\"host\":\"a\",\"spec\":{\"service\":"
	    "\"acme\",\"fib\":1,\"unis\":[{\"id\":\"uni-hq\",\"address\":"
	    "\"10.1.0.1\",\"prefix\":\"10.1.0.0/24\"}],\"zones\":[{\"name\":"
	    "\"z0\",\"prefixes\":[\"10.1.0.0/16\",") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"dnf\":{\"no-match\":\"allow\",\"block\":"
	    "[\"ads.example\"],\"allow\":[\"ok.ads.example\"],\"listed\":{"
	    "\"block\":[\"bad-feed.example\",\"bad.example\"]}}") != NULL, "%s",
	    r.body);
	ATF_CHECK(strstr(r.body, "\"10 fwd 10.1.0.1,53") == NULL);
	/* HTTP and TLS of the office zone to its proxy, by its table. */
	ATF_CHECK_MSG(strstr(r.body, "\"10 fwd 10.1.0.1,3128 tcp from table("
	    "sw1_zp0) to any dst-port 80 in recv lo0\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"10 fwd 10.1.0.1,3129 tcp from table("
	    "sw1_zp0) to any dst-port 443 in recv lo0\"") != NULL);
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
		/* Undone, addressed as before, not static. */
		snprintf(t2, sizeof(t2), "\"kind\":\"if-set\",\"interface\":"
		    "\"%s\",\"persist\":true,\"addressing\":\"was\"", lifn);
		ATF_CHECK_MSG(strstr(r.body, t2) != NULL, "%s", r.body);
	}
	snprintf(t2, sizeof(t2), "\"tunnel_remote\":\"%s\"", laddr);
	ATF_CHECK_MSG(strstr(r.body, t2) != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"if-set\",\"interface\":\"vtnet0\","
	    "\"persist\":true,\"fib\":3") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"tunnel_remote\":\"192.0.2.2\",\"tunnelfib\":3")
	    != NULL);
	ATF_CHECK_MSG(strstr(r.body, "{\"name\":\"ucs3\",\"fib\":3,\"host\":"
	    "\"a\",\"spec\":{\"flavor\":\"ucs\",\"end_point\":\"a-inet\","
	    "\"table\":3,\"router_id\":\"192.0.2.1\",\"interface\":\"vtnet0\","
	    "\"as\":64512,\"bgp\":{\"family\":\"ipv4\",\"as\":65000,"
	    "\"neighbors\":[\"192.0.2.254\"]") != NULL, "%s", r.body);
	/* Routing: a BIRD instance of the service on each edge, in its
	 * table, iBGP between them by each tunnel, and at hq's UNI BGP
	 * with the subscriber as the entry says. */
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"sdwan-bird\",\"instances\":[{"
	    "\"name\":\"sw1\",\"fib\":1,\"host\":\"a\",\"spec\":{\"service\":"
	    "\"acme\",\"fib\":1,\"table\":1,\"as\":64600,\"router_id\":"
	    "\"100.64.0.0\",\"direct\":[\"lo0\",\"gre100\",\"gif102\","
	    "\"gre104\"],") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"reject\":[\"100.64.0.0/24\","
	    "\"100.64.0.0/24\"]") != NULL, "%s", r.body);
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
	/* The UNI is lo0 here (swapped in for the apply). */
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"sdwan-dhcp\",\"instances\":[{"
	    "\"name\":\"sw1\",\"fib\":1,\"host\":\"a\",\"spec\":{\"service\":"
	    "\"acme\",\"fib\":1,\"unis\":[{\"id\":\"uni-hq\",\"interface\":"
	    "\"lo0\",\"ipv4\":{\"mode\":\"dhcp\",\"prefix\":\"10.1.0.0/24\","
	    "\"provider\":[\"10.1.0.1\"],\"reserved\":[\"10.1.0.0/26\","
	    "\"10.1.0.200/30\"],\"lease\":\"1h\",\"dns\":[\"10.1.0.1\"]}}]}}") !=
	    NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"kind\":\"rtadvd\",\"interface\":\"vlan")
	    != NULL && strstr(r.body, "\"args\":[\"2001:db8:1::/64\",\"2001:db8:1::1"
	    "\"],\"persist\":true") != NULL, "%s", r.body);
	/* Forwarding and the FIBs by arcana-sysctl, device edits of the
	 * hosts' candidates (4.5.5), no longer sysctl jobs. */
	ATF_CHECK_MSG(strstr(r.body, "{\"kind\":\"edit\",\"method\":\"PATCH\","
	    "\"path\":\"arcana-sysctl:sysctl\",\"body\":{\"arcana-sysctl:sysctl\""
	    ":{\"kept\":[{\"name\":\"net.inet.ip.forwarding\",\"value\":\"1\"},"
	    "{\"name\":\"net.inet6.ip6.forwarding\",\"value\":\"1\"}]}}}") !=
	    NULL && strstr(r.body, "{\"name\":\"net.fibs\",\"value\":\"4\"}") !=
	    NULL && strstr(r.body, "\"kind\":\"sysctl\"") == NULL, "%s",
	    r.body);
	/* The iBGP by the control tunnel alone: the host a reflector, b its
	 * client and nothing else; no session by the data tunnels. */
	ATF_CHECK_MSG(strstr(r.body, "\"peers\":[{\"tunnel\":"
	    "\"acme/a-inet-b-inet/ctvc\",\"to\":\"b\",\"local\":\"100.64.0.4\","
	    "\"neighbor\":\"100.64.0.5\",\"role\":\"client\",\"cluster_id\":"
	    "\"192.0.2.1\"}]") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"peers\":[{\"tunnel\":"
	    "\"acme/a-inet-b-inet/ctvc\",\"to\":\"a\",\"local\":\"100.64.0.5\","
	    "\"neighbor\":\"100.64.0.4\",\"role\":\"control\"}]") != NULL, "%s",
	    r.body);
	ATF_CHECK(strstr(r.body, "\"tunnel\":\"acme/a-inet-b-inet\",") == NULL);
	/* BFD on the edge's tunnel interfaces, the iBGP sessions by it. */
	ATF_CHECK_MSG(strstr(r.body, "\"bfd\":{\"interfaces\":[\"gre100\","
	    "\"gif102\",\"gre104\"],\"interval\":200,\"multiplier\":3,"
	    "\"sessions\":true},") != NULL && strstr(r.body, "\"md5\":"
	    "\"edges-secret\"") != NULL, "%s", r.body);
	/* NTP at a, with the FIBs, by the ntp job; taken away by it too. */
	ATF_CHECK_MSG(strstr(r.body, "\"key\":\"ntp\",\"phase\":1,\"title\":\"NTP: "
	    "ntpd by 2 servers, for the time faults and keys go by\",\"make\":[{"
	    "\"kind\":\"ntp\",\"args\":[\"ntp.example.org\",\"10.99.0.9\"],"
	    "\"persist\":true}]") != NULL, "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"unis\":[{\"id\":\"uni-hq\",\"end_point\":"
	    "\"hq\",\"interface\":\"lo0\",\"bgp\":{\"family\":\"ipv4\",\"as\":"
	    "65010,\"neighbors\":[\"10.1.0.2\"],\"password\":\"s3cret\","
	    "\"hold_time\":90,\"distance\":150,\"communities\":[[64600,100]]}}]")
	    != NULL, "%s", r.body);
	/* b has no routing at its UNI, but the service's instance all the
	 * same: what hq learns reaches it. */
	ATF_CHECK(strstr(r.body, "\"host\":\"b\",\"spec\":{\"service\":"
	    "\"acme\",\"fib\":1,\"table\":1,") != NULL);
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
	/* A remote end point: wg5 in the service's table with the
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
	/* Its groups: carol of staff takes the first address of the
	 * group's pool and her group's zone; a table each of the members;
	 * staff and guests, neither reaching the other, kept apart both
	 * ways before the zone table. */
	ATF_CHECK_MSG(strstr(r.body, "\"peer\":"
	    "\"HIgo9xNzJMWLKASShiTqIYNW7HVnKq0pjaZxmvZ6rKA=\",\"allowed_ips\":"
	    "\"10.30.0.64/32\"") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "[\"10.30.0.64/32\",\"12\"]") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "\"name\":\"sw1_g0\",\"valtype\":\"legacy\","
	    "\"entries\":[[\"10.30.0.64/32\",\"0\"]]") != NULL, "%s", r.body);
	ATF_CHECK(strstr(r.body, "\"name\":\"sw1_g1\",\"valtype\":\"legacy\","
	    "\"entries\":[]") != NULL);
	ATF_CHECK(strstr(r.body, "\"10 deny ip from table(sw1_g0) to "
	    "table(sw1_g1) in recv wg5\",\"10 deny ip from table(sw1_g1) to "
	    "table(sw1_g0) in recv wg5\",\"10 skipto tablearg ip from "
	    "table(sw1_zone) to any in recv wg5\"") != NULL);
	/*
	 * URLF (MEF 138): HTTP and TLS of the office zone forwarded to Squid
	 * on the edge's own addresses, the remote end point's too, where
	 * the zone's identities come from; its instance in the plan with
	 * the zone by its prefixes, the TLS name of the Block's host ended,
	 * the rest let through unopened (no MBSF), the zone's malware
	 * scanned.
	 */
	ATF_CHECK(strstr(r.body, "\"10 fwd 10.30.0.1,3129 tcp from table("
	    "sw1_zp0) to any dst-port 443 in recv wg5\"") != NULL);
	ATF_CHECK_MSG(strstr(r.body, "{\"kind\":\"sdwan-proxy\",\"instances\":[{"
	    "\"name\":\"sw1\",\"fib\":1,\"mode\":\"sni\",\"host\":\"a\","
	    "\"spec\":{\"flavor\":\"sdwan\",\"service\":\"acme\",\"fib\":1,"
	    "\"listen\":[{\"end_point\":\"hq\",\"address\":\"10.1.0.1\"},{"
	    "\"end_point\":\"road\",\"address\":\"10.30.0.1\"}],\"resolver\":"
	    "true,") != NULL && strstr(r.body, "\"zones\":[{\"name\":\"z0\","
	    "\"prefixes\":[\"10.1.0.0/16\",\"10.30.0.2/32\",\"10.30.0.64/32\"],"
	    "\"urlf\":{\"no-match\":\"allow\",\"block\":[\"bad.example\"]},"
	    "\"mdr\":{\"no-match\":\"allow\",\"block\":[\"44D88612FEA8A8F36DE82E1278"
	    "ABB02F:68\",\"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aa"
	    "bf651fd0f\"],\"allow\":[\"3395856ce81f2b7382dee72602f798b642f14140\"],"
	    "\"id\":\"g-mdr\"}}]},\"lists\":{}") != NULL, "%s", r.body);
	/* MD+R (MEF 138): what comes back goes to c-icap by ICAP, beside
	 * Squid on the edge's own address (the agent renders its file of
	 * the same form); c-icap scans with ClamAV, a need. */
	ATF_CHECK_MSG(strstr(r.body, "\"resolver\":true,\"icap\":true,") != NULL
	    && strstr(r.body, "\"plugin\":\"c-icap\",\"package\":\"c-icap "
	    "c-icap-modules clamav\"") != NULL, "%s", r.body);
	/* Intrusion detection (Arcana's own): Suricata on the service's UNIs at
	 * each edge, its home the UNIs' subnets, the policy's rules and the
	 * ruleset suricata-update keeps; Suricata a need.  It prevents: the
	 * UNI's traffic both ways diverted to it as it comes in, on the
	 * service's port, one rule before the way in, and given back to
	 * the service's table there. */
	ATF_CHECK_MSG(strstr(r.body, "\"divert\":8001") != NULL && strstr(
	    r.body, "\"9 divert 8001 ip4 from any to any in recv ") != NULL &&
	    strstr(r.body, "\"9 divert 8001 ip4 from any to 10.1.0.0/24 in not "
	    "recv ") != NULL && strstr(r.body, " not dst-ip me\",") != NULL &&
	    strstr(r.body, "\"10 setfib 1 ip4 from any to 10.1.0.0/24 in "
	    "diverted-loopback not dst-ip me\"") != NULL && strstr(r.body,
	    "\"oneside\":true") != NULL, "%s", r.body);
	/* The instance's settings, which the agent renders into Suricata's
	 * YAML: the UNIs' prefixes its home, the ruleset, one side. */
	ATF_CHECK_MSG(strstr(r.body, "{\"kind\":\"sdwan-ids\",\"instances\":[{"
	    "\"name\":\"sw1\",\"host\":\"") != NULL && strstr(r.body,
	    "\"spec\":{\"flavor\":\"sdwan\",\"service\":\"acme\",\"home\":"
	    "[\"10.1.0.0/24\"") != NULL && strstr(r.body,
	    "\"ruleset\":true,\"oneside\":true}") != NULL &&
	    strstr(r.body, "\"rules\":\"alert http any any -> $HOME_NET any "
	    "(msg:\\\"x\\\"; sid:1000001; rev:1;)\\n\"") != NULL && strstr(
	    r.body, "\"plugin\":\"suricata\",\"package\":\"suricata\"") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/* The record: the edges' logged packets read now; none yet. */
	http("GET", "/api/sdwan/record?swvc=acme&policy=g-ippf", NULL, &r);
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
	/* The edits committed: sysctl.conf has them, sysctl(8) set them. */
	ATF_CHECK(system("grep -qx 'net.inet6.ip6.forwarding=1' sysctl.conf && "
	    "grep -qx 'net.fibs=4' sysctl.conf && grep -q "
	    "'^sysctl net.inet.ip.forwarding=1' kld.log") == 0);
	/* Suricata's alert (the stand-in writes one as it starts) is an
	 * event, and the event a Security Event Notification (MEF 138
	 * R24, Table 3): Arcana's own function, the service, the source,
	 * the action, its ID; mailed to the SEN recipients. */
	for (i = 0; i < 300; i++) {
		http("GET", "/api/sdwan/sen", NULL, &r);
		if (r.status == 200 && ucl_object_toint(ucl_object_lookup(r.json,
		    "count")) > 0)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_CHECK_MSG(r.status == 200 && jstr(&r, "notices.0.id") != NULL &&
	    strlen(jstr(&r, "notices.0.id")) == 36 && strncmp(jstr(&r,
	    "notices.0.function"), "Intrusion detection", 19) == 0 && strcmp(
	    jstr(&r, "notices.0.policy"), "ids") == 0 && strcmp(jstr(&r,
	    "notices.0.service"), "acme") == 0 && strcmp(jstr(&r,
	    "notices.0.source"), "10.0.0.9") == 0 && strcmp(jstr(&r,
	    "notices.0.type"), "OTHER") == 0 && strncmp(jstr(&r,
	    "notices.0.action"), "Alerted", 7) == 0 && strcmp(jstr(&r,
	    "notices.0.uni"), strcmp(jstr(&r, "notices.0.edge"), "a") == 0 ?
	    "uni-hq" : "uni-br") == 0 && strstr(jstr(&r, "notices.0.details"),
	    "LOCAL telnet (severity 2): 10.0.0.9:4444 to 10.0.0.1:23 TCP on "
	    "lo0 at ") != NULL, "%s", r.body);
	resp_free(&r);
	for (i = 0; i < 100 && system("grep -q 'Security Event Notification' "
	    "mail.out") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(system("grep -q 'Security Function: Intrusion detection' "
	    "mail.out && grep -q '^Subject: Arcana: .*Security Event "
	    "Notification' mail.out && grep -qx 'To: soc@example.org' mail.out")
	    == 0, "no mail of the SEN");
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
	/* Identities: one issued for a name, its key pair made
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
	    "config"), "AllowedIPs = 10.1.0.0/24, 10.1.8.0/22, 10.30.0.0/24, "
	    "2001:db8:1::/64\n") != NULL, "%s", r.body);
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
	ATF_CHECK_STREQ("carol", jstr(&r, "identities.1.name"));
	ATF_CHECK_STREQ("staff", jstr(&r, "identities.1.group"));
	ATF_CHECK_STREQ("office", jstr(&r, "identities.1.zone"));
	ATF_CHECK_STREQ("10.30.0.64", jstr(&r, "identities.1.address"));
	ATF_CHECK_STREQ("bob", jstr(&r, "identities.2.name"));
	ATF_CHECK_STREQ("10.30.0.3", jstr(&r, "identities.2.address"));
	ATF_CHECK_STREQ("false", jstr(&r, "identities.2.user"));
	/* Its session, as the edge's wg tells its peer (S3.4): the stand-in
	 * keeps the last peer set on an interface. */
	ATF_CHECK_MSG(jstr(&r, "identities.2.session.endpoint") != NULL &&
	    strcmp(jstr(&r, "identities.2.session.endpoint"), "192.0.2.9:51820")
	    == 0 && jstr(&r, "identities.2.session.rx") != NULL, "%s", r.body);
	resp_free(&r);
	/* One issued into a group: the group's zone, an address outside
	 * every pool; a group the remote has not, refused. */
	http("POST", "/api/sdwan/identities", "{\"swvc\":\"acme\",\"end_point\":"
	    "\"road\",\"name\":\"dave\",\"group\":\"guests\"}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "config") != NULL && strstr(jstr(&r, "config"),
	    "\nAddress = 10.30.0.4/24\n") != NULL, "%s", r.body);
	resp_free(&r);
	sdwan_wait(&r);
	resp_free(&r);
	http("GET", "/api/sdwan/identities", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("dave", jstr(&r, "identities.3.name"));
	ATF_CHECK_STREQ("guests", jstr(&r, "identities.3.group"));
	ATF_CHECK_STREQ("office", jstr(&r, "identities.3.zone"));
	resp_free(&r);
	http("DELETE", "/api/sdwan/identities?swvc=acme&end_point=road&name=dave",
	    NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	resp_free(&r);
	http("POST", "/api/sdwan/identities", "{\"swvc\":\"acme\",\"end_point\":"
	    "\"road\",\"name\":\"erin\",\"group\":\"board\"}", &r);
	EXPECT(&r, 400);
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
	ATF_CHECK_STREQ("carol", jstr(&r, "identities.1.name"));
	ATF_CHECK(jstr(&r, "identities.2.name") == NULL);
	resp_free(&r);
	http("DELETE", "/api/sdwan/identities?swvc=acme&end_point=road&name=bob",
	    NULL, &r);
	EXPECT(&r, 404);
	resp_free(&r);
	/* The audit trail (MEF 118.1 §13.1): the issue an Allow, the revoke a
	 * Block, the document kept and the apply by the System
	 * Administrator, each with who did it, newest first; the chain
	 * whole.  A line altered on disk, the read says where it broke. */
	http("GET", "/api/sdwan/audit", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(ucl_object_toboolean(ucl_object_lookup(r.json, "intact"))
	    && strcmp(jstr(&r, "events.0.event"), "identity-revoked") == 0 &&
	    strcmp(jstr(&r, "events.0.action"), "Block") == 0 &&
	    strcmp(jstr(&r, "events.0.who"), "key -7") == 0 && strcmp(jstr(&r,
	    "events.0.policy"), "office") == 0 && strstr(jstr(&r,
	    "events.0.where"), "end point road of acme") != NULL && strstr(
	    r.body, "\"event\":\"identity-issued\",\"action\":\"Allow\"") !=
	    NULL && strstr(r.body, "\"event\":\"policies-changed\",\"action\":"
	    "\"Administer\"") != NULL && strstr(r.body, "\"event\":\""
	    "policies-applied\"") != NULL && strstr(r.body, "\"prev\"") == NULL,
	    "%s", r.body);
	resp_free(&r);
	http("GET", "/api/sdwan/audit.csv", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strncmp(r.body, "seq,when,event,action,policy,how,where,"
	    "who,why\n", 45) == 0 && strstr(r.body, ",\"identity-revoked\","
	    "\"Block\",\"office\",") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_REQUIRE(system("sed -i '' '2s/\"Allow\"/\"Block\"/; "
	    "2s/\"Administer\"/\"Allow\"/' data/sdwan-audit.jsonl") == 0);
	http("GET", "/api/sdwan/audit", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(!ucl_object_toboolean(ucl_object_lookup(r.json,
	    "intact")) && ucl_object_toint(ucl_object_lookup(r.json,
	    "broken_at")) == 2, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("stat -f %Lp data/sdwan-audit.key | grep -qx 600 && "
	    "stat -f %Lp data/sdwan-audit.jsonl | grep -qx 600") == 0);
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
	/*
	 * arcana-steer: the edge says why each choice is what it is, in
	 * its read and as the manager last read it; the console's pin is
	 * in the edge's read at once, one of no candidate refused, and
	 * cleared, the policy's order is again.
	 */
	{
		char	tbl[64], pfx[64], c1[96], pin[400];

		snprintf(body, sizeof(body), "/api/servers/%s/sdwan", sb);
		http("GET", body, NULL, &r);
		EXPECT(&r, 200);
		ATF_REQUIRE_MSG(jstr(&r, "data.steer.0.table") != NULL, "%s",
		    r.body);
		snprintf(tbl, sizeof(tbl), "%s", jstr(&r, "data.steer.0.table"));
		snprintf(pfx, sizeof(pfx), "%s", jstr(&r, "data.steer.0.prefix"));
		ATF_REQUIRE_MSG(jstr(&r, "data.steer.0.candidates.0.id") != NULL,
		    "%s", r.body);
		snprintf(c1, sizeof(c1), "%s", jstr(&r,
		    "data.steer.0.candidates.0.id"));
		ATF_CHECK_STREQ("preference", jstr(&r, "data.steer.0.reason"));
		ATF_CHECK(jstr(&r, "data.steer.0.since") != NULL);
		resp_free(&r);
		for (i = 0; i < 60; i++) {
			http("GET", "/api/sdwan/steer", NULL, &r);
			EXPECT(&r, 200);
			snprintf(body, sizeof(body), "live.%s.steer.0.reason", sb);
			if (jstr(&r, body) != NULL)
				break;
			resp_free(&r);
			usleep(300000);
		}
		ATF_REQUIRE_MSG(i < 60, "the manager read no steering");
		ATF_CHECK_STREQ("preference", jstr(&r, body));
		resp_free(&r);
		snprintf(pin, sizeof(pin), "{\"edge\":\"%s\",\"table\":\"%s\","
		    "\"prefix\":\"%s\",\"candidate\":\"%s\"}", sb, tbl, pfx,
		    c1);
		http("POST", "/api/sdwan/steer", pin, &r);
		EXPECT(&r, 200);
		resp_free(&r);
		snprintf(body, sizeof(body), "/api/servers/%s/sdwan", sb);
		http("GET", body, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("override", jstr(&r, "data.steer.0.reason"));
		ATF_CHECK_STREQ(c1, jstr(&r, "data.steer.0.pinned"));
		ATF_CHECK_STREQ("0", jstr(&r, "data.steer.0.chosen"));
		resp_free(&r);
		snprintf(pin, sizeof(pin), "{\"edge\":\"%s\",\"table\":\"%s\","
		    "\"prefix\":\"%s\",\"candidate\":\"acme/nowhere\"}", sb, tbl,
		    pfx);
		http("POST", "/api/sdwan/steer", pin, &r);
		ATF_CHECK_MSG(r.status == 409 && strstr(r.body,
		    "acme/nowhere is no candidate") != NULL, "%s", r.body);
		resp_free(&r);
		snprintf(pin, sizeof(pin), "{\"edge\":\"%s\",\"table\":\"%s\","
		    "\"prefix\":\"%s\"}", sb, tbl, pfx);
		http("POST", "/api/sdwan/steer", pin, &r);
		EXPECT(&r, 200);
		resp_free(&r);
		snprintf(body, sizeof(body), "/api/servers/%s/sdwan", sb);
		http("GET", body, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("preference", jstr(&r, "data.steer.0.reason"));
		ATF_CHECK(jstr(&r, "data.steer.0.pinned") == NULL);
		ATF_CHECK_STREQ("0", jstr(&r, "data.steer.0.chosen"));
		resp_free(&r);
		ATF_CHECK(system("grep -q 'steering-pinned' data/audit.log") ==
		    0 || system("grep -rq 'steering-pinned' data") == 0);
	}
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
	ATF_REQUIRE(swap_in(doc, "\"version\":0", "\"version\":5", t1,
	    sizeof(t1)));
	http("PUT", "/api/sdwan", t1, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", "/api/sdwan/plan", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_EQ_MSG(2, changes_of(&r, "unmake"), "%s", r.body);
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
	ATF_REQUIRE(swap_in(doc, "\"version\":0", "\"version\":6", t1,
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
	ATF_REQUIRE(swap_in(t1, "\"version\":6", "\"version\":7", doc,
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
	ATF_REQUIRE(swap_in(doc, "\"version\":7", "\"version\":8", t1,
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
	ATF_REQUIRE(swap_in(doc, "\"version\":7", "\"version\":9", t1,
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

	/* The Security page's own: a form not right refused; one made into
	 * Squid's and c-icap's files beside SD-WAN's, its form told back;
	 * Suricata's the same; [] stops them. */
	snprintf(t2, sizeof(t2), "/api/servers/%s/security", sa);
	http("POST", t2, "{\"what\":\"proxy\",\"instances\":[{\"name\":"
	    "\"web\",\"listen\":[\"10.1.0.1\"],\"allow\":[\"10.1.0.0/24\"]}]}",
	    &r);
	EXPECT(&r, 400);
	ATF_CHECK_MSG(strstr(r.body, "sec-") != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", t2, "{\"what\":\"proxy\",\"instances\":[{\"name\":"
	    "\"sec-web\",\"listen\":[\"10.1.0.1\"],\"allow\":[\"10.1.0.0/x\"]}]}",
	    &r);
	EXPECT(&r, 400);
	ATF_CHECK_MSG(strstr(r.body, "allow") != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", t2, "{\"what\":\"proxy\",\"instances\":[{\"name\":"
	    "\"sec-web\",\"listen\":[\"10.1.0.1\",\"2001:db8::1\"],\"allow\":"
	    "[\"10.1.0.0/24\"],\"deny\":[\".bad.example\",\"worse.example\"],"
	    "\"malware\":true}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"ok\":true") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^http_port 10.1.0.1:3128 ssl-bump tls-cert=' "
	    "sdwan-proxy-sec-web.conf && grep -q '^http_port \\[2001:db8::1\\]:"
	    "3128 ' sdwan-proxy-sec-web.conf && grep -q '^acl localnet src "
	    "10.1.0.0/24$' sdwan-proxy-sec-web.conf && grep -q 'icap://"
	    "127.0.0.1:1345/avscan' sdwan-proxy-sec-web.conf && grep -q "
	    "'^ssl_bump splice all$' sdwan-proxy-sec-web.conf") == 0);
	ATF_CHECK(system("grep -qx '.bad.example' sdwan-proxy-sec-web.deny && "
	    "grep -qx '.worse.example' sdwan-proxy-sec-web.deny") == 0);
	ATF_CHECK(system("grep -q '^Port 127.0.0.1:1345$' "
	    "sdwan-icap-sec-web.conf") == 0);
	snprintf(t1, sizeof(t1), "/api/servers/%s/sdwan", sa);
	http("GET", t1, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(jstr(&r, "data.security_proxy.0.name") != NULL && strcmp(jstr(
	    &r, "data.security_proxy.0.name"), "sec-web") == 0 && strstr(r.body,
	    "\"name\":\"sw1\"") != NULL && strstr(r.body, "\"group\":"
	    "\"security\"") != NULL && strstr(r.body, "acl localnet") == NULL,
	    "%s", r.body);
	resp_free(&r);
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"]}]}", &r);
	EXPECT(&r, 400);
	ATF_CHECK_MSG(strstr(r.body, "ruleset") != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"rules\":\"alert tcp any any "
	    "-> any 23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"ok\":true") != NULL, "%s", r.body);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^  - interface: lo0$' sdwan-ids-sec-lan.yaml "
	    "&& grep -q 'HOME_NET: \"\\[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'"
	    " sdwan-ids-sec-lan.yaml && grep -q 'sid:1000009' "
	    "sdwan-ids-sec-lan.rules") == 0);
	/* Every address its home: any, alone, and so outside too. */
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\",\"10.0.0.0/8\"],"
	    "\"rules\":\"alert tcp any any -> any 23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(r.body, "any stands alone") != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"nonsense\"],"
	    "\"rules\":\"alert tcp any any -> any 23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(r.body, "nonsense is not one") != NULL && strstr(
	    r.body, "or any") != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"rules\":\"alert tcp any any -> any 23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("grep -q 'HOME_NET: \"any\"$' sdwan-ids-sec-lan.yaml && "
	    "grep -q 'EXTERNAL_NET: \"any\"$' sdwan-ids-sec-lan.yaml") == 0);
	/* Its thresholds: threshold.config's lines, checked; written to a
	 * file of its own, which its configuration names. */
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"thresholds\":\"suppress sig_id 5; rm -rf /\",\"rules\":"
	    "\"alert tcp any any -> any 23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 400);
	ATF_CHECK_MSG(strstr(r.body, "threshold line 1 is suppress") != NULL,
	    "%s", r.body);
	resp_free(&r);
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"thresholds\":\"# quiet\\nsuppress gen_id 1, sig_id 1000009, "
	    "track by_src, ip 10.0.0.9\\n\",\"rules\":\"alert tcp any any -> "
	    "any 23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("grep -q '^threshold-file: .*sdwan-ids-sec-lan."
	    "threshold$' sdwan-ids-sec-lan.yaml && grep -qx 'suppress gen_id "
	    "1, sig_id 1000009, track by_src, ip 10.0.0.9' "
	    "sdwan-ids-sec-lan.threshold") == 0);
	/* A capture up from the page, in two parts: on the host, beside its
	 * replay; a part that does not follow, refused. */
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap?instance=sec-lan&"
	    "file=up.pcap", sa);
	http("POST", t1, "PCAP", &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"ok\":true") != NULL && strstr(r.body,
	    "/sdwan-ids-sec-lan.replay.d/captures/up.pcap\"") != NULL &&
	    strstr(r.body, "\"size\":4") != NULL, "%s", r.body);
	resp_free(&r);
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap?instance=sec-lan&"
	    "file=up.pcap&offset=9&last=1", sa);
	http("POST", t1, "DATA", &r);
	EXPECT(&r, 502);
	ATF_CHECK_MSG(strstr(r.body, "the part before ended at 4, not 9") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap?instance=sec-lan&"
	    "file=up.pcap&offset=4&last=1", sa);
	http("POST", t1, "DATA", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("[ \"$(cat sdwan-ids-sec-lan.replay.d/captures/"
	    "up.pcap)\" = PCAPDATA ] && [ ! -e sdwan-ids-sec-lan.replay.d/"
	    "captures/up.pcap.part ]") == 0);
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap?instance=sec-lan&"
	    "file=../up.pcap", sa);
	http("POST", t1, "PCAP", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* A file of its pcap-log down, as an alert's row links it; one it
	 * has not, said. */
	ATF_CHECK(system("mkdir -p sdwan-ids-sec-lan.d && printf PCAPLOG > "
	    "sdwan-ids-sec-lan.d/log.pcap.1792400000") == 0);
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap-log?instance="
	    "sec-lan&file=log.pcap.1792400000", sa);
	http("GET", t1, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "PCAPLOG") != NULL, "%s", r.body);
	resp_free(&r);
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap-log?instance="
	    "sec-lan&file=log.pcap.1", sa);
	http("GET", t1, NULL, &r);
	EXPECT(&r, 404);
	ATF_CHECK_MSG(strstr(r.body, "has no such file") != NULL, "%s", r.body);
	resp_free(&r);
	snprintf(t1, sizeof(t1), "/api/servers/%s/ids/pcap-log?instance="
	    "sec-lan&file=eve.json", sa);
	http("GET", t1, NULL, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	/* What its profiling wrote, read through the console. */
	snprintf(t1, sizeof(t1), "/api/servers/%s/suricata/rules?instance="
	    "sec-lan&profiling=1", sa);
	http("GET", t1, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"build\":{") != NULL, "%s", r.body);
	resp_free(&r);
	/* Its settings: each into Suricata's YAML, checked first; where the
	 * host has Suricata itself, what it makes of the whole. */
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"runmode\":\"fast\",\"rules\":\"alert tcp any any -> any 23 "
	    "(sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(r.body, "runmode is autofp, workers or single") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"flow_memcap\":\"lots\",\"rules\":\"alert tcp any any -> any "
	    "23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	resp_free(&r);
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"eve\":[\"http\",\"dns\",\"tls\",\"flow\"],\"payload\":true,"
	    "\"stats_interval\":30,\"runmode\":\"workers\",\"mpm\":\"ac-ks\","
	    "\"profile\":\"high\",\"management_cpus\":\"0\",\"worker_cpus\":"
	    "\"0-1\",\"max_pending\":2048,\"flow_memcap\":\"128mb\","
	    "\"stream_memcap\":\"64mb\",\"reassembly_memcap\":\"256mb\","
	    "\"defrag_memcap\":\"32mb\",\"host_memcap\":\"32mb\","
	    "\"http_memcap\":\"64mb\",\"stream_inline\":\"auto\","
	    "\"reassembly_depth\":\"1mb\",\"http_request_body\":\"200kb\","
	    "\"http_response_body\":\"2mb\",\"midstream\":true,"
	    "\"exception_policy\":\"drop-flow\",\"yaml\":\"vlan:\\n  "
	    "use-for-tracking: false\\n\",\"rules\":\"alert tcp any any -> "
	    "any 23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("f=sdwan-ids-sec-lan.yaml; grep -q '^        - alert:$' "
	    "$f && grep -q '^            payload-printable: yes$' $f && "
	    "grep -q '^        - tls$' $f && grep -q '^  interval: 30$' $f && "
	    "grep -q '^runmode: workers$' $f && grep -q '^mpm-algo: ac-ks$' $f "
	    "&& grep -q '^  profile: high$' $f && grep -q '^      cpu: \\[ 0-1 "
	    "\\]$' $f && grep -q '^max-pending-packets: 2048$' $f && grep -q "
	    "'^    depth: 1mb$' $f && grep -q '^          response-body-limit: "
	    "2mb$' $f && grep -q '^exception-policy: drop-flow$' $f && grep -q "
	    "'^  use-for-tracking: false$' $f") == 0);
	if (access("/usr/local/bin/suricata", X_OK) == 0)
		ATF_CHECK_MSG(system("/usr/local/bin/suricata -T -c "
		    "sdwan-ids-sec-lan.yaml > suricata-T.out 2>&1") == 0,
		    "Suricata refuses the settings: see suricata-T.out");
	/* By netmap(4): a pair at L2, copy-mode ips both ways, a worker's
	 * to the end; pairs are netmap's; not with divert.  A preset's
	 * values where a field says none. */
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"pairs\":[\"em0:em1\"],"
	    "\"rules\":\"alert tcp any any -> any 23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(r.body, "pairs of interfaces are netmap's") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"capture\":\"netmap\",\"divert\":8600,"
	    "\"pairs\":[\"em0:em1\"],\"rules\":\"alert tcp any any -> any "
	    "23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(r.body, "not both") != NULL, "%s", r.body);
	resp_free(&r);
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"capture\":\"netmap\",\"pairs\":[\"lo0:lo0^\"],"
	    "\"home\":[\"any\"],\"preset\":\"large\",\"flow_memcap\":"
	    "\"64mb\",\"offload_off\":true,\"rules\":\"alert tcp any any -> "
	    "any 23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("f=sdwan-ids-sec-lan.yaml; grep -q '^netmap:$' $f && "
	    "grep -A3 -x '  - interface: lo0' $f | grep -qx '    copy-iface: "
	    "lo0^' && grep -A3 -x '  - interface: lo0^' $f | grep -qx '    "
	    "copy-iface: lo0' && grep -q '^runmode: workers$' $f && ! grep -q "
	    "'^pcap:' $f && grep -A1 -x 'flow:' $f | grep -qx '  memcap: 64mb' "
	    "&& grep -A3 -x 'stream:' $f | grep -qx '    memcap: 2gb' && "
	    "grep -q '^  profile: high$' $f") == 0);
	ATF_CHECK(system("grep -q '\"capture\":\"netmap\"' security-ids.json "
	    "&& grep -q '\"interfaces\":\\[\"lo0\",\"lo0^\"\\]' "
	    "security-ids.json && grep -q '\"offload\":false' security-ids.json")
	    == 0);
	if (access("/usr/local/bin/suricata", X_OK) == 0)
		ATF_CHECK_MSG(system("/usr/local/bin/suricata -T -c "
		    "sdwan-ids-sec-lan.yaml > suricata-T.out 2>&1") == 0,
		    "Suricata refuses netmap's: see suricata-T.out");
	/* Lua: its scripts to the agent, allowed for rules, one an
	 * output; the packets of its alerts kept; its plugins.  Suricata
	 * itself checks the first two where the host has it. */
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"lua_outputs\":[\"nosuch.lua\"],\"rules\":\"alert tcp any any "
	    "-> any 23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(r.body, "a Lua output is one of its scripts") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"lua\":{\"pkts.lua\":\"function init (args)\\n  local needs = "
	    "{}\\n  needs[\\\"type\\\"] = \\\"packet\\\"\\n  return needs\\n"
	    "end\\nfunction setup (args)\\nend\\nfunction log (args)\\nend\\n"
	    "function deinit (args)\\nend\\n\"},\"lua_outputs\":[\"pkts.lua\"],"
	    "\"pcap_log\":true,\"pcap_log_limit\":\"10mb\",\"pcap_log_files\":"
	    "3,\"rules\":\"alert tcp any any -> any 23 (sid:1000009;)\"}]}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("f=sdwan-ids-sec-lan.yaml; grep -q '^  - lua:$' $f && "
	    "grep -q '^      scripts-dir: .*sdwan-ids-sec-lan.lua$' $f && "
	    "grep -q '^        - pkts.lua$' $f && grep -q '^    allow-rules: "
	    "yes$' $f && grep -q '^  - pcap-log:$' $f && grep -q '^      "
	    "max-files: 3$' $f && grep -q '^      conditional: alerts$' $f && "
	    "grep -q 'needs' sdwan-ids-sec-lan.lua/pkts.lua") == 0);
	if (access("/usr/local/bin/suricata", X_OK) == 0)
		ATF_CHECK_MSG(system("/usr/local/bin/suricata -T -c "
		    "sdwan-ids-sec-lan.yaml > suricata-T.out 2>&1") == 0,
		    "Suricata refuses Lua or pcap-log: see suricata-T.out");
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"plugins\":[\"/tmp/x.so\"],"
	    "\"rules\":\"alert tcp any any -> any 23 (sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "ok"));
	ATF_CHECK_MSG(strstr(r.body, "a .so under /usr/local/lib") != NULL,
	    "%s", r.body);
	resp_free(&r);
	/* Stopped by the admin: kept in the list, told to the agent. */
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[{\"name\":"
	    "\"sec-lan\",\"interfaces\":[\"lo0\"],\"home\":[\"any\"],"
	    "\"stopped\":true,\"rules\":\"alert tcp any any -> any 23 "
	    "(sid:1000009;)\"}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(system("grep -q '\"name\":\"sec-lan\",\"host\":\"a\","
	    "\"interfaces\":\\[\"lo0\"\\],\"stopped\":true' security-ids.json")
	    == 0);
	/* A job's words, its args, carried to the host for ClamAV and
	 * Suricata alike. */
	snprintf(t2, sizeof(t2), "/api/servers/%s/jobs", sa);
	http("POST", t2, "{\"jobs\":[{\"kind\":\"clamav\",\"verb\":"
	    "\"mirrors\",\"args\":[\"mirror=db.example.net\"]},{\"kind\":"
	    "\"suricata\",\"verb\":\"rule\",\"args\":[\"off=2000001\"]}]}",
	    &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("GET", t2, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "freshclam mirrors db.example.net") !=
	    NULL && strstr(r.body, "suricata rules set: off=2000001") != NULL,
	    "%s", r.body);
	resp_free(&r);
	snprintf(t2, sizeof(t2), "/api/servers/%s/security", sa);
	http("POST", t2, "{\"what\":\"ids\",\"instances\":[]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", t2, "{\"what\":\"proxy\",\"instances\":[]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_CHECK(access("sdwan-proxy-sec-web.conf", F_OK) != 0);
	ATF_CHECK(access("sdwan-proxy-sw1.conf", F_OK) == 0);
	/*
	 * A step that fails after others were made rolls the apply back:
	 * what it made before is taken away again, the last first, and
	 * the apply says which step failed.  A route the host refuses
	 * (10.66.0.0/16, the stand-in's, as a UNI's static route the far
	 * edge gets a route to) comes after the tunnels; made all again,
	 * the tunnels are destroyed once at the start and once more by
	 * the rollback.
	 */
	http("GET", "/api/sdwan", NULL, &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(swap_in(r.body, "\"prefix\":\"10.1.8.0/22\",\"next_hop\"",
	    "\"prefix\":\"10.66.0.0/16\",\"next_hop\"", t1, sizeof(t1)));
	resp_free(&r);
	http("PUT", "/api/sdwan", t1, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_REQUIRE(system(": > ifconfig.log") == 0);
	http("POST", "/api/sdwan/apply", "{\"fresh\":true}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	sdwan_wait(&r);
	ATF_CHECK_MSG(strcmp(jstr(&r, "apply.state"), "rolled back") == 0 &&
	    jstr(&r, "apply.failed_step") != NULL && strstr(r.body,
	    "\"state\":\"undone\"") != NULL && strstr(r.body, "taken away "
	    "again: a step after it failed") != NULL, "%s", r.body);
	ATF_CHECK_MSG(system("test \"$(grep -c '^gre100 destroy' ifconfig.log)\" "
	    "-ge 2 && grep -q '^gre100 create' ifconfig.log") == 0,
	    "the tunnel was not made and taken away again");
	resp_free(&r);
}

/*
 * Three consoles of a cluster, each in its own directory, joined by unix
 * sockets: the seed leads, a change made on any is every one's, a
 * sign-in too, and one stopped catches up when it starts again.
 */
static const char *const cl_nodes[] = { "na", "nb", "nc" };

ATF_TC_WITH_CLEANUP(cluster);
ATF_TC_HEAD(cluster, tc)
{
	atf_tc_set_md_var(tc, "descr", "Three consoles of a cluster: the seed "
	    "leads, a change on any is every one's, a sign-in too, and one "
	    "stopped catches up");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_CLEANUP(cluster, tc)
{
	char	cwd[MAXPATHLEN];
	int	i;

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return;
	for (i = 0; i < 3; i++)
		if (chdir(cl_nodes[i]) == 0) {
			stop();
			(void)chdir(cwd);
		}
}

/* GET path of node i until its answer says want: 15 s at most. */
static bool
cl_until(const char *cwd, int i, const char *path, const char *want)
{
	struct resp	r;
	int		k;
	bool		ok;

	ATF_REQUIRE(chdir(cl_nodes[i]) == 0);
	ok = false;
	for (k = 0; k < 150 && !ok; k++) {
		http("GET", path, NULL, &r);
		ok = r.status == 200 && r.body != NULL && strstr(r.body,
		    want) != NULL;
		resp_free(&r);
		if (!ok)
			usleep(100000);
	}
	ATF_REQUIRE(chdir(cwd) == 0);
	return (ok);
}

ATF_TC_BODY(cluster, tc)
{
	struct authn	a;
	struct resp	r;
	char		cwd[MAXPATHLEN], nodes[1024], key[64], far[16] = "";
	char		path[128], body[128];
	pid_t		pid;
	int		i, n, k, st;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	n = snprintf(nodes, sizeof(nodes), "nodes {");
	for (i = 0; i < 3; i++)
		n += snprintf(nodes + n, sizeof(nodes) - (size_t)n, " %s { uri "
		    "= \"unix:%s/%s/cl.sock\"; }", cl_nodes[i], cwd,
		    cl_nodes[i]);
	snprintf(nodes + n, sizeof(nodes) - (size_t)n, " }");
	for (i = 0; i < 3; i++) {
		ATF_REQUIRE(mkdir(cl_nodes[i], 0755) == 0);
		ATF_REQUIRE(chdir(cl_nodes[i]) == 0);
		snprintf(harness_webconf, sizeof(harness_webconf), "cluster { "
		    "self = \"%s\"; listen = \"unix:%s/%s/cl.sock\"; %s }\n",
		    cl_nodes[i], cwd, cl_nodes[i], nodes);
		start(tc, 0, NULL);
		ATF_REQUIRE(chdir(cwd) == 0);
	}
	harness_webconf[0] = '\0';
	/* The seed's first key, once it leads; the others follow it. */
	ATF_REQUIRE(chdir(cl_nodes[0]) == 0);
	enrol(&a);
	ATF_REQUIRE(chdir(cwd) == 0);
	ATF_CHECK(cl_until(cwd, 0, "/api/cluster", "\"role\":\"leader\""));
	ATF_CHECK(cl_until(cwd, 1, "/api/cluster", "\"leader\":\"na\""));
	ATF_CHECK(cl_until(cwd, 2, "/api/cluster", "\"leader\":\"na\""));
	/* Signed in on one, signed in on every one. */
	ATF_CHECK(cl_until(cwd, 2, "/api/servers", "\"servers\""));
	/* A host added on a follower: written by the leader, every one's. */
	ATF_REQUIRE(chdir(cl_nodes[1]) == 0);
	http("POST", "/api/servers", "{\"name\":\"far\",\"uri\":\"tcp://"
	    "192.0.2.9:4310\"}", &r);
	EXPECT(&r, 200);
	for (i = 0; jstr(&r, (snprintf(key, sizeof(key), "servers.%d.name",
	    i), key)) != NULL; i++)
		if (strcmp(jstr(&r, key), "far") == 0) {
			snprintf(key, sizeof(key), "servers.%d.id", i);
			snprintf(far, sizeof(far), "%s", jstr(&r, key));
			break;
		}
	ATF_REQUIRE(far[0] != '\0');
	resp_free(&r);
	ATF_REQUIRE(chdir(cwd) == 0);
	for (i = 0; i < 3; i++)
		ATF_CHECK_MSG(cl_until(cwd, i, "/api/servers", "\"far\""),
		    "%s", cl_nodes[i]);
	/* A store read, changed and written again on two nodes at the same
	 * time, ten times over: each reads what the other wrote before it
	 * (the cluster's lock, and the writes committed before it waited
	 * for), so no label is written over. */
	for (k = 0; k < 10; k++) {
		if ((pid = fork()) == 0) {
			ATF_REQUIRE(chdir(cl_nodes[2]) == 0);
			snprintf(path, sizeof(path), "/api/labels/%s/em%d", far,
			    10 + k);
			http("PUT", path, "{\"label\":\"by nc\"}", &r);
			_exit(r.status == 200 ? 0 : 1);
		}
		ATF_REQUIRE(pid > 0);
		ATF_REQUIRE(chdir(cl_nodes[1]) == 0);
		snprintf(path, sizeof(path), "/api/labels/%s/em%d", far, k);
		http("PUT", path, "{\"label\":\"by nb\"}", &r);
		EXPECT(&r, 200);
		resp_free(&r);
		ATF_REQUIRE(chdir(cwd) == 0);
		ATF_REQUIRE(waitpid(pid, &st, 0) == pid);
		ATF_CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	}
	snprintf(body, sizeof(body), "%s/em19", far);
	ATF_CHECK(cl_until(cwd, 0, "/api/labels", body));
	ATF_REQUIRE(chdir(cl_nodes[0]) == 0);
	http("GET", "/api/labels", NULL, &r);
	for (k = 0; k < 20; k++) {
		snprintf(key, sizeof(key), "labels.%s/em%d", far, k);
		ATF_CHECK_MSG(jstr(&r, key) != NULL, "em%d's label written "
		    "over: %.400s", k, r.body);
	}
	resp_free(&r);
	ATF_REQUIRE(chdir(cwd) == 0);
	/* One stopped misses a change two make; started, it has it. */
	ATF_REQUIRE(chdir(cl_nodes[2]) == 0);
	console_stop();
	ATF_REQUIRE(chdir(cwd) == 0);
	ATF_REQUIRE(chdir(cl_nodes[0]) == 0);
	http("POST", "/api/servers", "{\"name\":\"later\",\"uri\":\"tcp://"
	    "192.0.2.10:4310\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_REQUIRE(chdir(cwd) == 0);
	ATF_REQUIRE(chdir(cl_nodes[2]) == 0);
	console_start();
	ATF_REQUIRE(chdir(cwd) == 0);
	ATF_CHECK(cl_until(cwd, 2, "/api/servers", "\"later\""));
	/* Signed out on one, signed out on every one: the session's own
	 * document taken away. */
	strlcpy(body, cookie, sizeof(body));
	ATF_REQUIRE(chdir(cl_nodes[1]) == 0);
	http("POST", "/api/auth/logout", "{}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_REQUIRE(chdir(cwd) == 0);
	strlcpy(cookie, body, sizeof(cookie));
	ATF_REQUIRE(chdir(cl_nodes[2]) == 0);
	for (k = 0; k < 300; k++) {
		http("GET", "/api/servers", NULL, &r);
		n = r.status;
		resp_free(&r);
		if (n == 401)
			break;
		usleep(100000);
	}
	ATF_CHECK_EQ(401, n);
	ATF_REQUIRE(chdir(cwd) == 0);
}

/*
 * HTTPS with an EC certificate (P-256), which the console serves as it
 * does an RSA one, on TLS 1.3: HTTP/2 to a client that offers it (by
 * ALPN), HTTP/1.1 to one that does not.
 */
ATF_TC_WITH_CLEANUP(tls_ec);
ATF_TC_HEAD(tls_ec, tc)
{
	atf_tc_set_md_var(tc, "descr", "the console serves HTTPS with an EC "
	    "certificate, over HTTP/2 and HTTP/1.1");
	atf_tc_set_md_var(tc, "require.progs", "curl openssl");
}
ATF_TC_BODY(tls_ec, tc)
{
	char	cwd[MAXPATHLEN], cmd[MAXPATHLEN * 2];
	int	port, i;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(system("openssl req -x509 -newkey ec -pkeyopt "
	    "ec_paramgen_curve:P-256 -nodes -keyout ec.key -out ec.pem -days 1 "
	    "-subj /CN=localhost 2>/dev/null") == 0);
	snprintf(harness_server, sizeof(harness_server), "\tcertfile = "
	    "\"%s/ec.pem\";\n\tcertkey = \"%s/ec.key\";\n", cwd, cwd);
	port = 20000 + (int)(getpid() % 20000);
	start(tc, port, NULL);
	for (i = 0; i < 50; i++) {
		snprintf(cmd, sizeof(cmd), "curl -sk https://127.0.0.1:%d/api/"
		    "health | grep -q '\"ok\":true'", port);
		if (system(cmd) == 0)
			break;
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 50, "no answer over HTTPS");
	snprintf(cmd, sizeof(cmd), "echo | openssl s_client -connect "
	    "127.0.0.1:%d 2>/dev/null | grep -q 'Peer signature type: "
	    "ecdsa_secp256r1_sha256'", port);
	ATF_CHECK_MSG(system(cmd) == 0, "not signed with the EC key");
	snprintf(cmd, sizeof(cmd), "curl -sk --http2 -o /dev/null -w "
	    "'%%{http_version} %%{http_code}' https://127.0.0.1:%d/api/health "
	    "| grep -qx '2 200'", port);
	ATF_CHECK_MSG(system(cmd) == 0, "no HTTP/2");
	/* A request with a body, and a reply without one (over the
	 * largest body), each to the end of its stream. */
	snprintf(cmd, sizeof(cmd), "curl -sk --http2 -m 5 -o /dev/null -w "
	    "'%%{http_version} %%{http_code}' -H 'content-type: application/"
	    "json' -d '{}' https://127.0.0.1:%d/api/auth/status | grep -qx "
	    "'2 [0-9][0-9][0-9]'", port);
	ATF_CHECK_MSG(system(cmd) == 0, "no answer to a body over HTTP/2");
	snprintf(cmd, sizeof(cmd), "curl -sk --http1.1 -o /dev/null -w "
	    "'%%{http_version} %%{http_code}' https://127.0.0.1:%d/api/health "
	    "| grep -qx '1.1 200'", port);
	ATF_CHECK_MSG(system(cmd) == 0, "no HTTP/1.1");
	/* Over HTTPS, browsers are kept to it for the settings' days
	 * (a year unless set). */
	snprintf(cmd, sizeof(cmd), "curl -skI https://127.0.0.1:%d/api/health "
	    "| grep -qi '^strict-transport-security: max-age=31536000'", port);
	ATF_CHECK_MSG(system(cmd) == 0, "no Strict-Transport-Security");
	/*
	 * A reply of a handler's larger than an HTTP/2 frame (16 KB): a
	 * host's sysctl, read with a session opened by an API token, its
	 * host added with the console's Origin.  Written whole, it ended
	 * the connection (curl: exit 16).
	 */
	snprintf(cmd, sizeof(cmd), "T=arcw_$(printf 'b%%.0s' $(seq 1 64)); "
	    "printf '{\"tokens\":[{\"hash\":\"%%s\",\"name\":\"t\","
	    "\"created\":1,\"last\":0,\"write\":true}]}' $(printf %%s $T "
	    "| sha256 -q) > data/tokens.json && "
	    "curl -sk --http2 -c jar -H 'content-type: application/json' -d "
	    "\"{\\\"token\\\":\\\"$T\\\"}\" https://127.0.0.1:%d/api/auth/"
	    "login/token -o /dev/null && "
	    "curl -sk --http2 -b jar -H 'origin: %s' -H 'content-type: "
	    "application/json' -d '{\"name\":\"here\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}' https://127.0.0.1:%d/api/servers > servers.out && "
	    "S=$(sed 's/.*\"id\":\"\\([0-9a-f]*\\)\".*/\\1/' servers.out) && "
	    "curl -sk --http2 -b jar -o sysctl.out -w '%%{http_version} "
	    "%%{http_code}' https://127.0.0.1:%d/api/servers/$S/sysctl | grep "
	    "-qx '2 200' && [ $(wc -c < sysctl.out) -gt 65536 ]", port,
	    harness_origin, cwd, port, port);
	if (system(cmd) != 0) {
		(void)system("echo servers:; head -c 300 servers.out; echo; "
		    "echo sysctl:; head -c 300 sysctl.out; echo; wc -c sysctl.out; "
		    "tail -5 console.out; tail -5 arcana-agent.out");
		atf_tc_fail("a large reply did not come whole over HTTP/2");
	}
	/*
	 * Forty large replies on one connection, to a client with
	 * HTTP/2's own window (64 KB, nghttp's; curl's is far larger)
	 * that keeps to the 24 streams the console allows.  Written past
	 * the window, the client ended the connection with
	 * FLOW_CONTROL_ERROR; a stream ended while output waited stayed
	 * open to libwebsockets after the client had its end, and the
	 * client's next one, past the limit, ended the connection.
	 */
	snprintf(cmd, sizeof(cmd), "command -v nghttp >/dev/null || exit 0; "
	    "S=$(sed 's/.*\"id\":\"\\([0-9a-f]*\\)\".*/\\1/' "
	    "servers.out) && C=$(awk '/arc_session/ { print $7 }' jar) && "
	    "nghttp -nv -M 24 -H \"cookie: arc_session=$C\" $(for i in "
	    "$(seq 1 40); do echo https://127.0.0.1:%d/api/servers/$S/"
	    "sysctl?n=$i; done) > nghttp.out 2>&1; "
	    "[ $(grep -c ':status: 200' nghttp.out) -eq 40 ] && "
	    "! grep -q 'recv GOAWAY\\|FLOW_CONTROL' nghttp.out", port);
	if (system(cmd) != 0) {
		(void)system("grep -i 'goaway\\|status\\|processed' -A1 "
		    "nghttp.out | head -20");
		atf_tc_fail("not every large reply on one HTTP/2 connection came");
	}
	/*
	 * The key is the key manager's, the worker's child: killed, the
	 * worker goes with it and the supervisor starts both again.
	 */
	ATF_REQUIRE(system("W=$(sed -n 's/.*worker started (pid "
	    "\\([0-9]*\\)).*/\\1/p' console.out | tail -1) && "
	    "ps -o command= -p $(pgrep -P $W) | grep -q 'arcana-console: "
	    "keymgr' && pkill -TERM -P $W -f 'arcana-console: keymgr'") == 0);
	for (i = 0; i < 50; i++) {
		snprintf(cmd, sizeof(cmd), "curl -sk https://127.0.0.1:%d/api/"
		    "health | grep -q '\"ok\":true'", port);
		/* The next handshake finds it gone; one after, both are
		 * back. */
		if (system(cmd) == 0 && system("grep -q 'keymgr: gone' "
		    "console.out") == 0)
			break;
		usleep(200000);
	}
	ATF_CHECK_MSG(i < 50, "no HTTPS after the key manager was killed");
	ATF_CHECK(system("[ $(grep -c 'worker started' console.out) -ge 2 ]")
	    == 0);
	/* Plain HTTP on that port is not served. */
	snprintf(cmd, sizeof(cmd), "! curl -s http://127.0.0.1:%d/api/health "
	    "| grep -q ok", port);
	ATF_CHECK(system(cmd) == 0);
}
ATF_TC_CLEANUP(tls_ec, tc)
{

	(void)tc;
	stop();
}

/* The host's records kept by the console, those after n: how many have
 * what, within secs. */
static int
notif_count(const char *id, const char *what, int want, int secs)
{
	struct resp	 r;
	char		 path[128];
	int		 n = 0, i;

	snprintf(path, sizeof(path), "/api/servers/%s/notifications", id);
	for (i = 0; i < secs * 10; i++) {
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		n = 0;
		for (const char *p = r.body; (p = strstr(p, what)) != NULL;
		    p += strlen(what))
			n++;
		resp_free(&r);
		if (n >= want)
			break;
		usleep(100000);
	}
	return (n);
}

/* The token in the document /subscription/token gives; a record. */
#define	NOTIF_TOKEN_PATH \
	"candidate.ietf-subscribed-notifications:subscriptions." \
	"ietf-subscribed-notif-receivers:receiver-instances." \
	"receiver-instance.0.ietf-https-notif-transport:https-receiver." \
	"arcana-notif:token"
#define	NOTIF_RECORD \
	"{\"ietf-restconf:notification\":{\"eventTime\":" \
	"\"2026-10-28T10:00:00Z\",\"arcana-events:event\":{\"id\":1}}}"

/*
 * The console as a host's receiver (RFC 8639 section 2.5 over
 * HTTPS-notif): the host's candidate given what /subscription says and
 * committed, the agent connects to the TLS listener with its
 * certificate, the records come and are kept; the console restarted,
 * they are still there, the agent connects again and what it missed
 * meanwhile is replayed after them.
 */
CONSOLE_TC(notif_receiver, "A host's configured subscription to the "
    "console over HTTPS-notif: records kept, resumed over a restart")
ATF_TC_BODY(notif_receiver, tc)
{
	struct authn	 a;
	struct resp	 r;
	ucl_object_t	*cand;
	unsigned char	*json;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64], id[16];
	char		 path[256], path2[256], token[80];
	int		 n, after;

	harness_tls_port = 20000 + (int)(getpid() % 20000);
	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	/* The host, known by the name its certificate has. */
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\",\"peer_name\":\"localhost\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	/* Not the agent: no certificate, refused. */
	snprintf(path, sizeof(path), "/api/notif/%s/capabilities", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	/* Nothing yet. */
	snprintf(path, sizeof(path), "/api/servers/%s/notifications", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("0", jstr(&r, "last"));
	resp_free(&r);
	/* What to put: the console's endpoints for the host. */
	snprintf(path, sizeof(path), "/api/servers/%s/subscription", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	snprintf(body, sizeof(body), "https://127.0.0.1:%d/api/notif/%s/"
	    "capabilities", harness_tls_port, id);
	ATF_CHECK_STREQ(body, jstr(&r, "candidate.ietf-subscribed-notifications:"
	    "subscriptions.ietf-subscribed-notif-receivers:receiver-instances."
	    "receiver-instance.0.ietf-https-notif-transport:https-receiver."
	    "capabilities-endpoint.uri"));
	ATF_CHECK_STREQ("certificate", jstr(&r, "notif_auth"));
	ATF_CHECK_STREQ("false", jstr(&r, "token"));
	cand = ucl_object_ref(ucl_object_lookup(r.json, "candidate"));
	snprintf(path, sizeof(path), "%s", jstr(&r, "put"));
	snprintf(body, sizeof(body), "%s", jstr(&r, "commit"));
	resp_free(&r);
	/* A token made for the host is shown once, in the document; the
	 * receiver, by the certificate alone (notif_auth's default),
	 * refuses a record with the token and no certificate. */
	snprintf(path2, sizeof(path2), "/api/servers/%s/subscription/token",
	    id);
	http("POST", path2, "{}", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, NOTIF_TOKEN_PATH) != NULL);
	snprintf(token, sizeof(token), "%s", jstr(&r, NOTIF_TOKEN_PATH));
	ATF_CHECK_EQ(64, strlen(token));
	resp_free(&r);
	snprintf(path2, sizeof(path2), "/api/notif/%s/relay-notification", id);
	http_bearer("POST", path2, token, NOTIF_RECORD, &r);
	EXPECT(&r, 401);
	ATF_CHECK_STREQ("certificate", jstr(&r, "error.code"));
	resp_free(&r);
	json = ucl_object_emit(cand, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(cand);
	http("PUT", path, (const char *)json, &r);
	/* Made in the candidate, which had none (RFC 8040 section 4.5). */
	EXPECT(&r, 201);
	resp_free(&r);
	free(json);
	http("POST", body, "{\"ietf-netconf:input\":{}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* The agent connected: told subscription-started, kept. */
	ATF_REQUIRE_EQ(1, notif_count(id, "subscription-started", 1, 15));
	ATF_REQUIRE_EQ(1, notif_count(id, "replay-completed", 1, 5));
	/* An event of the host's: a record. */
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", id);
	http("POST", path, "{\"jobs\":[{\"kind\":\"sysctl\",\"verb\":\"set\","
	    "\"args\":[\"kern.hostname\",\"lab\"]}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_REQUIRE(notif_count(id, "\"arcana-events:event\"", 1, 15) >= 1);
	snprintf(path, sizeof(path), "/api/servers/%s/notifications", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	after = atoi(jstr(&r, "last"));
	ATF_CHECK(after >= 3);
	ATF_CHECK(strstr(r.body, "\"eventTime\":\"") != NULL);
	resp_free(&r);
	/* The subscription seen on the host, its receiver active. */
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-subscribed-notifications:subscriptions", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"state\":\"active\"") != NULL, "%s",
	    r.body);
	resp_free(&r);
	/* The console restarted: the records kept are there; the agent,
	 * whose POST failed meanwhile, connects again and replays what it
	 * missed after them. */
	restart_console();
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", id);
	http("POST", path, "{\"jobs\":[{\"kind\":\"sysctl\",\"verb\":\"set\","
	    "\"args\":[\"kern.hostname\",\"lab2\"]}]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	ATF_REQUIRE_EQ(2, notif_count(id, "subscription-started", 2, 30));
	snprintf(path, sizeof(path), "/api/servers/%s/notifications?after=%d",
	    id, after);
	n = 0;
	for (int i = 0; i < 100 && n == 0; i++) {
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		if (strstr(r.body, "replay-previous-event-time") != NULL &&
		    strstr(r.body, "lab2") != NULL)
			n = atoi(jstr(&r, "last"));
		resp_free(&r);
		if (n == 0)
			usleep(100000);
	}
	ATF_CHECK_MSG(n > after, "no replay after the restart");
	/* All of them, from the first: nothing lost over the restart. */
	snprintf(path, sizeof(path), "/api/servers/%s/notifications", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("1", jstr(&r, "records.0.n"));
	ATF_CHECK(strstr(r.body, "\"kern.hostname=lab\"") != NULL ||
	    strstr(r.body, "lab") != NULL);
	resp_free(&r);
}

/*
 * The host's token beside its certificate (notif_auth = token): made
 * and shown once in the subscription document, kept hashed; on the
 * plain listener (TLS ended before it) it names the host, none or
 * another is refused; the agent, handed it in its candidate, sends it;
 * made anew, the one before is refused; with either, a bearer decides
 * where there is one, the certificate else.
 */
CONSOLE_TC(notif_token, "A host's token for the console's receiver, "
    "beside its certificate (notif_auth): records taken on a plain "
    "listener, the agent sends it, a new one retires the old")
ATF_TC_BODY(notif_token, tc)
{
	struct authn	 a;
	struct resp	 r;
	ucl_object_t	*cand;
	unsigned char	*json;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64], id[16];
	char		 put[256], commit[256], relay[256], caps[256];
	char		 path[256], token[80], token2[80];

	harness_tls_port = 20000 + (int)(getpid() % 20000);
	snprintf(harness_webconf, sizeof(harness_webconf),
	    "notif_auth = \"token\";\n");
	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\",\"peer_name\":\"localhost\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, sizeof(id), "%s", jstr(&r, "servers.0.id"));
	ATF_CHECK_STREQ("false", jstr(&r, "servers.0.notif_token"));
	resp_free(&r);
	snprintf(relay, sizeof(relay), "/api/notif/%s/relay-notification", id);
	snprintf(caps, sizeof(caps), "/api/notif/%s/capabilities", id);
	/* Made and shown once, in the document; the listing says the host
	 * has one, the GET of the document shows none. */
	snprintf(path, sizeof(path), "/api/servers/%s/subscription/token", id);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("token", jstr(&r, "notif_auth"));
	ATF_REQUIRE(jstr(&r, NOTIF_TOKEN_PATH) != NULL);
	snprintf(token, sizeof(token), "%s", jstr(&r, NOTIF_TOKEN_PATH));
	ATF_CHECK_EQ(64, strlen(token));
	cand = ucl_object_ref(ucl_object_lookup(r.json, "candidate"));
	snprintf(put, sizeof(put), "%s", jstr(&r, "put"));
	snprintf(commit, sizeof(commit), "%s", jstr(&r, "commit"));
	resp_free(&r);
	http("GET", "/api/servers", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "servers.0.notif_token"));
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/subscription", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "token"));
	ATF_CHECK(strstr(r.body, "arcana-notif:token") == NULL);
	ATF_CHECK(strstr(r.body, token) == NULL);
	resp_free(&r);
	/* On the plain listener: the token names the host; none, or
	 * another, is refused. */
	http_bearer("GET", caps, token, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, "encoding:json") != NULL);
	resp_free(&r);
	http_bearer("POST", relay, token, NOTIF_RECORD, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http("POST", relay, NOTIF_RECORD, &r);
	EXPECT(&r, 401);
	ATF_CHECK_STREQ("token", jstr(&r, "error.code"));
	resp_free(&r);
	snprintf(token2, sizeof(token2), "%064d", 0);
	http_bearer("POST", relay, token2, NOTIF_RECORD, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/notifications", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("1", jstr(&r, "last"));
	resp_free(&r);
	/* The agent, handed the token in its candidate, sends it with
	 * each request: its records come over the TLS listener, the token
	 * judged. */
	json = ucl_object_emit(cand, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(cand);
	http("PUT", put, (const char *)json, &r);
	EXPECT(&r, 201);
	resp_free(&r);
	free(json);
	http("POST", commit, "{\"ietf-netconf:input\":{}}", &r);
	EXPECT(&r, 204);
	resp_free(&r);
	ATF_REQUIRE_EQ(1, notif_count(id, "subscription-started", 1, 15));
	ATF_REQUIRE_EQ(1, notif_count(id, "replay-completed", 1, 5));
	/* The token is not read back from the host but by a rule that
	 * permits it: the admin's does. */
	snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:fleet/host=%s"
	    "/ietf-subscribed-notifications:subscriptions", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "\"state\":\"active\"") != NULL, "%s",
	    r.body);
	resp_free(&r);
	/* A new token: the one before is refused. */
	snprintf(path, sizeof(path), "/api/servers/%s/subscription/token", id);
	http("POST", path, "{}", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, NOTIF_TOKEN_PATH) != NULL);
	snprintf(token2, sizeof(token2), "%s", jstr(&r, NOTIF_TOKEN_PATH));
	resp_free(&r);
	ATF_CHECK(strcmp(token, token2) != 0);
	http_bearer("POST", relay, token, NOTIF_RECORD, &r);
	EXPECT(&r, 401);
	resp_free(&r);
	http_bearer("POST", relay, token2, NOTIF_RECORD, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	/* either: a bearer decides where there is one; without one, the
	 * certificate, which the plain listener has none of. */
	ATF_REQUIRE_EQ(0, system("sed -i '' 's/notif_auth = \"token\"/"
	    "notif_auth = \"either\"/' web.conf"));
	restart_console();
	http_bearer("POST", relay, token2, NOTIF_RECORD, &r);
	EXPECT(&r, 204);
	resp_free(&r);
	http_bearer("POST", relay, token, NOTIF_RECORD, &r);
	EXPECT(&r, 401);
	ATF_CHECK_STREQ("token", jstr(&r, "error.code"));
	resp_free(&r);
	http("POST", relay, NOTIF_RECORD, &r);
	EXPECT(&r, 401);
	ATF_CHECK_STREQ("certificate", jstr(&r, "error.code"));
	resp_free(&r);
}

#define	HELD	"held: the host's subscription pushed it"

/* A host on the test's agent, its id in id. */
static void
watch_host(char *id, size_t len)
{
	struct resp	 r;
	char		 cwd[MAXPATHLEN], body[MAXPATHLEN + 64];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"lab\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(id, len, "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
}

/*
 * The console's subscription of topic at host id, as /watch says it:
 * its state and pushes, within secs of it being open with a push since
 * pushed (time(3)); asked for by read meanwhile, a GET of it.
 */
static bool
watch_open(const char *id, const char *topic, const char *read,
    time_t pushed, int secs)
{
	const ucl_object_t	*t;
	ucl_object_iter_t	 it;
	struct resp		 r;
	char			 path[128];
	bool			 open;

	for (int i = 0; i < secs * 10; i++) {
		if (read != NULL) {
			snprintf(path, sizeof(path), "/api/servers/%s/%s", id,
			    read);
			http("GET", path, NULL, &r);
			resp_free(&r);
		}
		snprintf(path, sizeof(path), "/api/servers/%s/watch", id);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		open = false;
		it = NULL;
		while ((t = ucl_object_iterate(ucl_object_lookup(r.json,
		    "topics"), &it, true)) != NULL)
			if (strcmp(ucl_object_tostring(ucl_object_lookup(t,
			    "topic")), topic) == 0 && strcmp(ucl_object_tostring(
			    ucl_object_lookup(t, "state")), "open") == 0 &&
			    (pushed == 0 || ucl_object_toint(ucl_object_lookup(
			    t, "pushed")) >= pushed) && (strcmp(topic,
			    "events") == 0 || ucl_object_lookup(t, "pushed") !=
			    NULL))
				open = true;
		resp_free(&r);
		if (open)
			return (true);
		usleep(100000);
	}
	return (false);
}

/* /watch's count of what was asked of the agents, or answered held. */
static long
watch_count(const char *id, const char *which)
{
	struct resp	 r;
	char		 path[128];
	long		 n;

	snprintf(path, sizeof(path), "/api/servers/%s/watch", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	snprintf(path, sizeof(path), "requests.%s", which);
	n = jstr(&r, path) != NULL ? atol(jstr(&r, path)) : -1;
	resp_free(&r);
	return (n);
}

/*
 * PLAN-SDN-YANG 3.4.1: one connection per agent for its subscriptions,
 * made again when the agent comes back.  The first read of the jails
 * goes to the host and has them subscribed; once pushed, the reads are
 * answered from what is held.  The agent restarted, the connection is
 * made again a while on, the subscription with it, and the reads are
 * answered from it again.
 */
CONSOLE_TC(watch_reconnect, "The subscriptions' connection to an agent: "
    "the reads answered from it, an agent restarted, it comes back")
ATF_TC_BODY(watch_reconnect, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 id[16], path[128], name[64];
	unsigned char	*host, *held;
	time_t		 t;
	int		 i;

	start(tc, 0, NULL);
	enrol(&a);
	watch_host(id, sizeof(id));
	snprintf(path, sizeof(path), "/api/servers/%s/jails", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, HELD) == NULL);
	ATF_REQUIRE(jstr(&r, "jails.0.name") != NULL);
	snprintf(name, sizeof(name), "%s", jstr(&r, "jails.0.name"));
	host = ucl_object_emit(ucl_object_lookup(r.json, "jails"),
	    UCL_EMIT_JSON_COMPACT);
	resp_free(&r);
	ATF_REQUIRE_MSG(watch_open(id, "jails", "jails", 0, 15),
	    "the jails not subscribed");
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, HELD) != NULL, "%s", r.body);
	/* As the host gives it: the host by hello, the jails, each as
	 * the host's own answer has it. */
	ATF_CHECK_STREQ(name, jstr(&r, "jails.0.name"));
	ATF_CHECK(jstr(&r, "host.version") != NULL);
	ATF_CHECK_STREQ("true", jstr(&r, "ok"));
	held = ucl_object_emit(ucl_object_lookup(r.json, "jails"),
	    UCL_EMIT_JSON_COMPACT);
	ATF_CHECK_MSG(host != NULL && held != NULL && strcmp((char *)host,
	    (char *)held) == 0, "the host's:\n%s\nheld:\n%s", host, held);
	free(host);
	free(held);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/watch", id);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "connected"));
	ATF_CHECK_STREQ("0", jstr(&r, "reconnects"));
	resp_free(&r);

	t = time(NULL);
	agent_restart();
	/* Gone: the reads go to the host again; back, they are held. */
	ATF_REQUIRE_MSG(watch_open(id, "jails", "jails", t, 30),
	    "the subscription did not come back");
	snprintf(path, sizeof(path), "/api/servers/%s/watch", id);
	http("GET", path, NULL, &r);
	ATF_CHECK_STREQ("true", jstr(&r, "connected"));
	ATF_CHECK(jstr(&r, "reconnects") != NULL && atoi(jstr(&r,
	    "reconnects")) >= 1);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/jails", id);
	for (i = 0; i < 50; i++) {
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		if (strstr(r.body, HELD) != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(i < 50, "not held after the agent came back");
	ATF_CHECK_STREQ(name, jstr(&r, "jails.0.name"));
	resp_free(&r);
}

/* What the fleet's stream s says until want is in buf, for secs at most. */
static bool
sse_until(int s, char *buf, size_t *len, size_t cap, const char *want,
    int secs)
{
	time_t	t0 = time(NULL);
	ssize_t	n;

	while (strstr(buf, want) == NULL && time(NULL) - t0 < secs &&
	    *len < cap - 1) {
		if ((n = read(s, buf + *len, cap - 1 - *len)) <= 0) {
			if (n == 0)
				break;
			continue;
		}
		*len += (size_t)n;
		buf[*len] = '\0';
	}
	return (strstr(buf, want) != NULL);
}

/* How many arcana-events records buf has from p on. */
static int
events_count(const char *p)
{
	int	n = 0;

	while ((p = strstr(p, "\"arcana-events:event\":")) != NULL) {
		p++;
		n++;
	}
	return (n);
}

/*
 * The numbers of the arcana-events records in buf from p on, to end
 * (NULL: to its end), each one more than the one before; how many.
 * Every data line once.
 */
static int
events_continuous(const char *p, const char *end, const char *what)
{
	const char	*k = "\"arcana-events:event\":", *num, *nl;
	unsigned long	 v, prev = 0;
	int		 n = 0;

	while ((p = strstr(p, k)) != NULL && (end == NULL || p < end)) {
		p += strlen(k);
		nl = strchr(p, '\n');
		if ((num = strstr(p, "\"number\":\"")) == NULL || (nl != NULL &&
		    num > nl))
			continue;
		v = strtoul(num + 10, NULL, 10);
		ATF_CHECK_MSG(n == 0 || v == prev + 1, "%s: %lu after %lu",
		    what, v, prev);
		prev = v;
		n++;
	}
	return (n);
}

/*
 * The fleet's stream outlives a host's agent restarting: its stream
 * ended is said, the host subscribed again by the console, from its
 * last record on, said heard again; what came after on the same reply,
 * numbered on without a gap or a record twice.  A host removed is not
 * asked again: said so, the reply ends.
 */
CONSOLE_TC(fleet_stream_rejoin, "The fleet's event stream subscribes "
    "again to a host whose agent restarted, and lets go of one removed")
ATF_TC_BODY(fleet_stream_rejoin, tc)
{
	struct authn	 a;
	struct resp	 r;
	struct timeval	 tv = { 2, 0 };
	char		 id[16], path[128], rq[512], want[128];
	char		*buf, *info, *line, *nl;
	size_t		 len = 0, cap = 1 << 20;
	ssize_t		 n;
	int		 s, before, after;

	start(tc, 0, NULL);
	enrol(&a);
	watch_host(id, sizeof(id));
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", id);
	ATF_REQUIRE((buf = calloc(1, cap)) != NULL);
	s = console_socket();
	ATF_REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv,
	    sizeof(tv)) == 0);
	snprintf(rq, sizeof(rq), "GET /restconf/streams/fleet/json "
	    "HTTP/1.1\r\nHost: localhost:8443\r\nCookie: %s\r\n\r\n", cookie);
	ATF_REQUIRE(write(s, rq, strlen(rq)) == (ssize_t)strlen(rq));
	ATF_REQUIRE_MSG(sse_until(s, buf, &len, cap, "fleet's stream", 10),
	    "%s", buf);
	/* Subscribed once the thread has the host: then a job. */
	usleep(1500000);
	http("POST", path, "{\"jobs\":[{\"kind\":\"monitor\",\"verb\":\"set\","
	    "\"args\":[\"name=gre9\",\"interface=gre9\",\"address=192.0.2.9\","
	    "\"interval=500\",\"eval=10000\"]}]}", &r);
	resp_free(&r);
	ATF_REQUIRE_MSG(sse_until(s, buf, &len, cap, "arcana-events:event",
	    15), "%s", buf);

	/* The agent restarted: said lost, then heard again. */
	agent_restart();
	snprintf(want, sizeof(want), "host %s: ", id);
	ATF_CHECK_MSG(sse_until(s, buf, &len, cap, "event: error", 15) &&
	    strstr(strstr(buf, "event: error"), want) != NULL, "%s", buf);
	snprintf(want, sizeof(want), "event: info\ndata: {\"host\":\"%s\"", id);
	ATF_REQUIRE_MSG(sse_until(s, buf, &len, cap, want, 30), "%s", buf);
	/* A job's event after it, on the same reply. */
	after = events_count(strstr(buf, want));
	http("POST", path, "{\"jobs\":[{\"kind\":\"monitor\",\"verb\":\"set\","
	    "\"args\":[\"name=gre8\",\"interface=gre8\",\"address=192.0.2.8\","
	    "\"interval=500\",\"eval=10000\"]}]}", &r);
	resp_free(&r);
	for (n = 0; n < 15 && events_count(strstr(buf, want)) <= after; n++)
		(void)sse_until(s, buf, &len, cap, "\a", 1);
	ATF_CHECK_MSG(events_count(strstr(buf, want)) > after, "%s", buf);
	info = strstr(buf, want);
	before = events_continuous(buf, info, "before the restart");
	after = events_continuous(info, NULL, "after the restart");
	ATF_CHECK_MSG(before > 0 && after > 0, "%d before, %d after:\n%s",
	    before, after, buf);
	/* No record twice. */
	for (line = buf; (line = strstr(line, "\ndata: {\"ietf-restconf:"
	    "notification\"")) != NULL; line = nl) {
		line++;
		if ((nl = strchr(line, '\n')) == NULL)
			break;
		*nl = '\0';
		ATF_CHECK_MSG(strstr(nl + 1, line) == NULL, "twice: %s", line);
		*nl = '\n';
	}

	/* Removed: its stream ended, it is not asked again; the reply
	 * ends, it was the only one. */
	snprintf(path, sizeof(path), "/api/servers/%s", id);
	http("DELETE", path, NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	agent_restart();
	snprintf(want, sizeof(want), "host %s: removed", id);
	ATF_CHECK_MSG(sse_until(s, buf, &len, cap, want, 15), "%s", buf);
	ATF_CHECK_MSG(sse_until(s, buf, &len, cap, "every host was removed",
	    10), "%s", buf);
	n = strstr(buf, want) != NULL ? (ssize_t)(strstr(buf, want) - buf) :
	    0;
	ATF_CHECK_MSG(strstr(buf + n, "event: info") == NULL, "%s", buf);
	close(s);
	free(buf);
}

/*
 * PLAN-SDN-YANG 3.4.2: the reads the pages poll answered from the
 * subscriptions, in the shapes the host's answers have: the stats
 * (periodic), the jails (periodic), the jobs (on-change, the agent
 * telling each job's change); nothing asked of the agent meanwhile.
 * A job queued is in the jobs held within a second or two of its
 * change; a job's read, kept, is not asked twice in a second.
 */
CONSOLE_TC(watch_held, "The stats, jails and jobs the pages poll "
    "answered from subscriptions, nothing asked of the agent")
ATF_TC_BODY(watch_held, tc)
{
	struct authn	 a;
	struct resp	 r;
	char		 id[16], path[128], job[24];
	long		 asked, held;
	int		 i;

	start(tc, 0, NULL);
	enrol(&a);
	watch_host(id, sizeof(id));
	/* The host's own answers, before. */
	snprintf(path, sizeof(path), "/api/servers/%s/stats", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, HELD) == NULL);
	ATF_CHECK(jstr(&r, "stats.mem_total") != NULL);
	resp_free(&r);
	ATF_REQUIRE(watch_open(id, "stats", "stats", 0, 15));
	ATF_REQUIRE(watch_open(id, "jails", "jails", 0, 15));
	ATF_REQUIRE(watch_open(id, "jobs", "jobs", 0, 15));
	asked = watch_count(id, "asked");
	held = watch_count(id, "held");
	for (i = 0; i < 20; i++) {
		snprintf(path, sizeof(path), "/api/servers/%s/stats", id);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK(strstr(r.body, HELD) != NULL);
		ATF_CHECK(jstr(&r, "stats.mem_total") != NULL);
		ATF_CHECK(jstr(&r, "stats.cpu_pct") != NULL);
		ATF_CHECK_STREQ(id, jstr(&r, "server.id"));
		resp_free(&r);
		snprintf(path, sizeof(path), "/api/servers/%s/jails", id);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK(strstr(r.body, HELD) != NULL);
		ATF_CHECK(jstr(&r, "jails.0.name") != NULL);
		ATF_CHECK(ucl_object_lookup(r.json, "scopes") != NULL);
		resp_free(&r);
		snprintf(path, sizeof(path), "/api/servers/%s/jobs", id);
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK(strstr(r.body, HELD) != NULL);
		ATF_CHECK(ucl_object_lookup(r.json, "jobs") != NULL);
		ATF_CHECK(jstr(&r, "stopping") != NULL);
		resp_free(&r);
	}
	/* The jails' host by its hello alone, each time: what tools it
	 * has can change unannounced. */
	ATF_CHECK_MSG(watch_count(id, "asked") == asked + 20, "the agent was "
	    "asked %ld times", watch_count(id, "asked") - asked);
	ATF_CHECK(watch_count(id, "held") >= held + 60);

	/* The SD-WAN read: the page's first the host's, all the samples;
	 * those after a time it has, held. */
	snprintf(path, sizeof(path), "/api/servers/%s/sdwan", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, HELD) == NULL);
	ATF_CHECK(ucl_object_lookup_path(r.json, "data.targets") != NULL);
	resp_free(&r);
	ATF_REQUIRE(watch_open(id, "sdwan", "sdwan?after=1", 0, 15));
	snprintf(path, sizeof(path), "/api/servers/%s/sdwan?after=%ld", id,
	    (long)time(NULL) - 30);
	for (i = 0; i < 50; i++) {
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		if (strstr(r.body, HELD) != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(i < 50, "the SD-WAN read not held");
	ATF_CHECK(ucl_object_lookup_path(r.json, "data.targets") != NULL);
	ATF_CHECK(ucl_object_lookup_path(r.json, "data.edges") != NULL);
	ATF_CHECK(ucl_object_lookup_path(r.json, "data.time") != NULL);
	ATF_CHECK(ucl_object_lookup_path(r.json, "data.faults") != NULL);
	resp_free(&r);
	/* Long before what is held: the host's. */
	snprintf(path, sizeof(path), "/api/servers/%s/sdwan?after=1", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(strstr(r.body, HELD) == NULL);
	resp_free(&r);

	/* A job: in the jobs held as the agent tells its changes. */
	snprintf(path, sizeof(path), "/api/servers/%s/jobs", id);
	http("POST", path, "{\"jobs\":[{\"kind\":\"sysctl\",\"verb\":\"set\","
	    "\"args\":[\"kern.hostname\",\"lab\"]}]}", &r);
	EXPECT(&r, 200);
	ATF_REQUIRE(jstr(&r, "jobs.0.id") != NULL);
	snprintf(job, sizeof(job), "%s", jstr(&r, "jobs.0.id"));
	resp_free(&r);
	for (i = 0; i < 100; i++) {
		const ucl_object_t	*j;
		ucl_object_iter_t	 it = NULL;
		bool			 done = false;

		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		while ((j = ucl_object_iterate(ucl_object_lookup(r.json,
		    "jobs"), &it, true)) != NULL)
			if (ucl_object_toint(ucl_object_lookup(j, "id")) ==
			    atoll(job) && strcmp(ucl_object_tostring(
			    ucl_object_lookup(j, "state")), "done") == 0)
				done = true;
		done = done && strstr(r.body, HELD) != NULL;
		resp_free(&r);
		if (done)
			break;
		usleep(100000);
	}
	ATF_CHECK_MSG(i < 100, "the job's end not in the jobs held");
	/* Its read with its trace: the host's once, then kept. */
	snprintf(path, sizeof(path), "/api/servers/%s/jobs/%s", id, job);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("done", jstr(&r, "job.state"));
	ATF_CHECK(ucl_object_lookup_path(r.json, "job.trace") != NULL);
	resp_free(&r);
	asked = watch_count(id, "asked");
	for (i = 0; i < 5; i++) {
		http("GET", path, NULL, &r);
		EXPECT(&r, 200);
		ATF_CHECK_STREQ("done", jstr(&r, "job.state"));
		ATF_CHECK(ucl_object_lookup_path(r.json, "job.trace") != NULL);
		resp_free(&r);
	}
	ATF_CHECK_EQ(asked, watch_count(id, "asked"));
}

/*
 * PLAN-SDN-YANG 3.4.3: the host's events subscribed once for the pages
 * that follow them, each relayed to every one of them within a second
 * of the agent telling it: sysctl.conf changed by somebody else, the
 * agent told by the kernel (EVFILT_VNODE).
 */
CONSOLE_TC(watch_events, "A host's events subscribed once, relayed to "
    "each page that follows them within a second")
ATF_TC_BODY(watch_events, tc)
{
	struct authn	 a;
	struct resp	 r;
	struct timespec	 t0, t1;
	struct pollfd	 pfd;
	char		 id[16], ask[128], path[128], *m;
	double		 secs;
	long		 last;
	bool		 one, two, told;
	int		 ws, n;

	start(tc, 0, NULL);
	enrol(&a);
	watch_host(id, sizeof(id));
	ws = ws_open("/api/stream");
	snprintf(ask, sizeof(ask), "{\"id\":1,\"server\":\"%s\",\"what\":"
	    "\"events\"}", id);
	ws_send(ws, ask);
	snprintf(ask, sizeof(ask), "{\"id\":2,\"server\":\"%s\",\"what\":"
	    "\"events\"}", id);
	ws_send(ws, ask);
	ATF_REQUIRE_MSG(watch_open(id, "events", NULL, 0, 15),
	    "the events not subscribed");
	/* One subscription for both. */
	snprintf(path, sizeof(path), "/api/servers/%s/watch", id);
	http("GET", path, NULL, &r);
	ATF_CHECK_EQ(1, ucl_array_size(ucl_object_lookup(r.json, "topics")));
	resp_free(&r);
	/* The last the agent has, read from it. */
	snprintf(path, sizeof(path), "/api/servers/%s/events", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	last = jstr(&r, "data.last") != NULL ? atol(jstr(&r, "data.last")) :
	    0;
	resp_free(&r);
	/*
	 * The agent says what it saw once a second: when it has the event
	 * is when its read has it, asked meanwhile; the page has it within
	 * a second of that.
	 */
	ATF_REQUIRE(system("echo 'kern.maxfiles=4321' >> sysctl.conf") == 0);
	one = two = false;
	told = false;
	secs = 0;
	memset(&t0, 0, sizeof(t0));
	snprintf(path, sizeof(path), "/api/servers/%s/events?after=%ld", id,
	    last);
	for (n = 0; n < 2000 && !(one && two); n++) {
		if (!told) {
			http("GET", path, NULL, &r);
			if (jstr(&r, "data.events.0.n") != NULL) {
				clock_gettime(CLOCK_MONOTONIC, &t0);
				told = true;
			}
			resp_free(&r);
		}
		pfd.fd = ws;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 20) != 1)
			continue;
		if ((m = ws_recv(ws)) == NULL)
			break;
		if (strstr(m, "\"event\":") != NULL) {
			clock_gettime(CLOCK_MONOTONIC, &t1);
			if (!told) {
				t0 = t1;
				told = true;
			}
			secs = (double)(t1.tv_sec - t0.tv_sec) +
			    (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
			if (strstr(m, "\"id\":1,") != NULL)
				one = true;
			if (strstr(m, "\"id\":2,") != NULL)
				two = true;
		}
		free(m);
	}
	ATF_REQUIRE_MSG(one && two, "the event not told to both");
	printf("the event in the page %.3f s after the agent had it\n", secs);
	ATF_CHECK_MSG(secs < 1.0, "the event came %.3f s after", secs);
	close(ws);
}

/*
 * What is held is held for one user, read as that user: the host's
 * access rules (NACM) let the admin read arcana-probe and arcana-host
 * and deny them bob; once the admin's reads are held, bob's are never
 * answered with them, his own subscription read as him.
 */
CONSOLE_TC(watch_nacm, "What the subscriptions hold is one user's, read "
    "as that user: another whose rules deny it never sees it")
ATF_TC_BODY(watch_nacm, tc)
{
	static const char rules[] = "{\"groups\":{\"group\":[{\"name\":"
	    "\"admin\",\"user-name\":[\"admin\",\"console\"]},{\"name\":"
	    "\"ops\",\"user-name\":[\"bob\"]}]},\"rule-list\":[{\"name\":"
	    "\"admin\",\"group\":[\"admin\"],\"rule\":[{\"name\":\"all\","
	    "\"module-name\":\"*\",\"access-operations\":\"*\",\"action\":"
	    "\"permit\"}]},{\"name\":\"ops\",\"group\":[\"ops\"],\"rule\":["
	    "{\"name\":\"no-probe\",\"module-name\":\"arcana-probe\","
	    "\"access-operations\":\"*\",\"action\":\"deny\"},{\"name\":"
	    "\"no-host\",\"module-name\":\"arcana-host\",\"access-operations\":"
	    "\"*\",\"action\":\"deny\"}]}]}";
	struct authn	 a, b;
	struct resp	 r;
	char		 cwd[MAXPATHLEN], cmd[3 * MAXPATHLEN], id[16];
	char		 path[128], sdwan[128], invite[80];
	const char	*ctl;
	FILE		*fp;
	int		 i;

	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ctl = locate(tc, "../../../usr.sbin/arcanactl/arcanactl", "arcanactl",
	    "/usr/local/sbin/arcanactl");
	ATF_REQUIRE((fp = fopen("rules.json", "w")) != NULL);
	fprintf(fp, "%s\n", rules);
	fclose(fp);
	snprintf(cmd, sizeof(cmd), "%s -c unix:%s/jgd.sock edit nacm "
	    "@rules.json && %s -c unix:%s/jgd.sock commit", ctl, cwd, ctl, cwd);
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);
	watch_host(id, sizeof(id));
	http("PUT", "/api/roles/ops", "{\"console\":\"member\",\"hosts\":"
	    "{\"*\":\"operator\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("PUT", "/api/users/bob", "{\"roles\":[\"ops\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/users/bob/invite", NULL, &r);
	EXPECT(&r, 200);
	snprintf(invite, sizeof(invite), "%s", jstr(&r, "token"));
	resp_free(&r);

	/* The admin's, held. */
	snprintf(path, sizeof(path), "/api/servers/%s/sdwan", id);
	http("GET", path, NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK(ucl_object_lookup_path(r.json, "data.targets") != NULL);
	resp_free(&r);
	ATF_REQUIRE(watch_open(id, "sdwan", "sdwan?after=1", 0, 15));
	ATF_REQUIRE(watch_open(id, "stats", "stats", 0, 15));
	snprintf(sdwan, sizeof(sdwan), "/api/servers/%s/sdwan?after=%ld", id,
	    (long)time(NULL) - 30);
	for (i = 0; i < 50; i++) {
		http("GET", sdwan, NULL, &r);
		if (strstr(r.body, HELD) != NULL)
			break;
		resp_free(&r);
		usleep(100000);
	}
	ATF_REQUIRE_MSG(i < 50, "the admin's SD-WAN read not held");
	ATF_CHECK(ucl_object_lookup_path(r.json, "data.targets") != NULL);
	resp_free(&r);
	snprintf(path, sizeof(path), "/api/servers/%s/stats", id);
	http("GET", path, NULL, &r);
	ATF_CHECK(strstr(r.body, HELD) != NULL);
	ATF_CHECK(jstr(&r, "stats.mem_total") != NULL);
	resp_free(&r);

	/* bob, while the admin's stay held: never the admin's. */
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("bob", jstr(&r, "user"));
	resp_free(&r);
	for (i = 0; i < 40; i++) {
		http("GET", sdwan, NULL, &r);
		ATF_CHECK_MSG(strstr(r.body, HELD) == NULL &&
		    ucl_object_lookup_path(r.json, "data.targets") == NULL,
		    "bob was given the probes: %.300s", r.body);
		resp_free(&r);
		http("GET", path, NULL, &r);
		ATF_CHECK_MSG(jstr(&r, "stats.mem_total") == NULL,
		    "bob was given the stats: %.300s", r.body);
		resp_free(&r);
		usleep(100000);
	}
	/* His own subscriptions, as him. */
	snprintf(cmd, sizeof(cmd), "/api/servers/%s/watch", id);
	http("GET", cmd, NULL, &r);
	ATF_CHECK(strstr(r.body, "\"user\":\"bob\"") != NULL);
	resp_free(&r);
}

/* GET /api/feeds/<id> until what is told: a key that is there. */
static void
feed_wait(const char *id, const char *key, const char *want,
    struct resp *r)
{
	char	path[96];
	int	i;

	snprintf(path, sizeof(path), "/api/feeds/%s", id);
	for (i = 0; i < 300; i++) {
		http("GET", path, NULL, r);
		if (r->status == 200 && jstr(r, key) != NULL && (want == NULL ||
		    strcmp(jstr(r, key), want) == 0))
			return;
		resp_free(r);
		usleep(100000);
	}
	http("GET", path, NULL, r);
	atf_tc_fail("feed %s: no %s%s%s: %s", id, key, want != NULL ? " = " :
	    "", want != NULL ? want : "", r->body);
}

/* The feed's dropped entries: is entry there with a reason that has why? */
static bool
feed_dropped(const struct resp *r, const char *entry, const char *why)
{
	char	k[32];
	int	i;

	for (i = 0; i < 50; i++) {
		snprintf(k, sizeof(k), "dropped.%d.entry", i);
		if (jstr(r, k) == NULL)
			return (false);
		if (strcmp(jstr(r, k), entry) != 0)
			continue;
		snprintf(k, sizeof(k), "dropped.%d.reason", i);
		if (strstr(jstr(r, k), why) != NULL)
			return (true);
		snprintf(k, sizeof(k), "dropped.%d.detail", i);
		return (jstr(r, k) != NULL && strstr(jstr(r, k), why) != NULL);
	}
	return (false);
}

CONSOLE_TC_LONG(feeds, "Threat feeds: the presets' formats parsed from "
    "fixtures, fetched by the console with If-Modified-Since, the "
    "console's, a host's and a sign-in's addresses dropped, private space "
    "kept only where the feed lists it on purpose; delivered as an ipfw "
    "table swapped in; a preview; an alarm after three failures; a feed "
    "disabled gives up its table alone; members may not")
ATF_TC_BODY(feeds, tc)
{
	struct authn	a, b, c;
	struct resp	r;
	char		cwd[1024], body[1024], sa[16], k[96], invite[80];
	char		invite2[80], sn[16], sg[16];
	int		port, i;

	port = feeds_server(tc);
	start(tc, 0, NULL);
	enrol(&a);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(body, sizeof(body), "{\"name\":\"a\",\"uri\":\"unix:%s/"
	    "jgd.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	snprintf(sa, sizeof(sa), "%s", jstr(&r, "servers.0.id"));
	resp_free(&r);
	/* A host the console reaches at 192.0.2.77, and a user who last
	 * signed in from 203.0.113.9: no feed is to cut either off. */
	http("POST", "/api/servers", "{\"name\":\"far\",\"uri\":\"tcp://"
	    "192.0.2.77:4310\"}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	/* And one at 100.64.0.5, which the operator below may read. */
	http("POST", "/api/servers", "{\"name\":\"near\",\"uri\":\"tcp://"
	    "100.64.0.5:4310\"}", &r);
	EXPECT(&r, 200);
	sn[0] = '\0';
	for (i = 0; i < 3; i++) {
		snprintf(k, sizeof(k), "servers.%d.name", i);
		if (jstr(&r, k) != NULL && strcmp(jstr(&r, k), "near") == 0) {
			snprintf(k, sizeof(k), "servers.%d.id", i);
			snprintf(sn, sizeof(sn), "%s", jstr(&r, k));
		}
	}
	ATF_REQUIRE(sn[0] != '\0');
	resp_free(&r);
	/* And one no agent answers for, which the operator may not read. */
	snprintf(body, sizeof(body), "{\"name\":\"gone\",\"uri\":\"unix:%s/"
	    "none.sock\"}", cwd);
	http("POST", "/api/servers", body, &r);
	EXPECT(&r, 200);
	sg[0] = '\0';
	for (i = 0; i < 4; i++) {
		snprintf(k, sizeof(k), "servers.%d.name", i);
		if (jstr(&r, k) != NULL && strcmp(jstr(&r, k), "gone") == 0) {
			snprintf(k, sizeof(k), "servers.%d.id", i);
			snprintf(sg, sizeof(sg), "%s", jstr(&r, k));
		}
	}
	ATF_REQUIRE(sg[0] != '\0');
	resp_free(&r);
	put("data/signins.json", "{\"alice\":{\"addr\":\"203.0.113.9\","
	    "\"at\":1}}");

	/* A feed comes from the internet: what resolves to loopback,
	 * private space or a cloud's metadata is refused, unless Settings
	 * let its prefix through; the stand-in's 127.0.0.1 so. */
	{
		static const char *const priv[] = { "127.0.0.1", "10.0.0.1",
		    "169.254.169.254", "[::1]" };

		for (i = 0; i < 4; i++) {
			snprintf(body, sizeof(body), "{\"url\":\"http://%s:%d/"
			    "drop_v4.json\"}", priv[i], port);
			http("PUT", "/api/feeds/x", body, &r);
			ATF_CHECK_MSG(r.status == 400 && strstr(r.body,
			    "is a private or reserved address") != NULL, "%s: %s",
			    priv[i], r.body);
			resp_free(&r);
		}
	}
	http("POST", "/api/settings", "{\"set\":{\"feeds_allow_private\":"
	    "\"127.0.0.1/32\"}}", &r);
	EXPECT(&r, 200);
	resp_free(&r);

	/* The presets, off, each with its source and its terms. */
	http("GET", "/api/feeds", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("spamhaus-drop-v4", jstr(&r, "presets.0.id"));
	ATF_CHECK_STREQ("https://www.spamhaus.org/drop/terms/", jstr(&r,
	    "presets.0.terms_url"));
	ATF_CHECK_STREQ("true", jstr(&r, "presets.2.bogons"));
	ATF_CHECK(jstr(&r, "feeds.0.id") == NULL);
	resp_free(&r);
	/* What is no feed: refused. */
	http("PUT", "/api/feeds/x", "{\"url\":\"ftp://example.org/x\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", "/api/feeds/x", "{\"url\":\"https://example.org/x\","
	    "\"interval\":0}", &r);
	EXPECT(&r, 400);
	resp_free(&r);
	http("PUT", "/api/feeds/x", "{\"url\":\"https://example.org/x\","
	    "\"table\":\"bad table\"}", &r);
	EXPECT(&r, 400);
	resp_free(&r);

	/* Spamhaus DROP, its JSON lines: fetched, kept, sent to host a as
	 * a table filled by a scratch one and swapped in. */
	snprintf(body, sizeof(body), "{\"preset\":\"spamhaus-drop-v4\","
	    "\"url\":\"http://127.0.0.1:%d/drop_v4.json\",\"enabled\":true,"
	    "\"hosts\":[\"%s\"]}", port, sa);
	http("PUT", "/api/feeds/spamhaus-drop-v4", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("feed_spamhaus_drop_v4", jstr(&r, "feed.table"));
	ATF_CHECK_STREQ("12", jstr(&r, "feed.interval"));
	resp_free(&r);
	snprintf(k, sizeof(k), "delivered.%s.at", sa);
	feed_wait("spamhaus-drop-v4", k, NULL, &r);
	ATF_CHECK_STREQ("4", jstr(&r, "count"));
	ATF_CHECK_STREQ("1.10.16.0/20", jstr(&r, "sample.0"));
	snprintf(k, sizeof(k), "delivered.%s.count", sa);
	ATF_CHECK_STREQ("4", jstr(&r, k));
	ATF_CHECK_STREQ("4", jstr(&r, "events.0.count"));
	resp_free(&r);
	ATF_CHECK(system("grep -q 'table feed_spamhaus_drop_v4 swap "
	    "feed_spamhaus_drop_v4_load' ipfw.log") == 0);
	ATF_CHECK(system("grep -q 'table feed_spamhaus_drop_v4_load add "
	    "1.10.16.0/20 0 1.19.0.0/16 0' ipfw.log") == 0);
	ATF_CHECK(system("grep -q '^# arcana feed spamhaus-drop-v4$' "
	    "feeds/feed_spamhaus_drop_v4") == 0);
	/* Fetched again: If-Modified-Since, a 304, nothing sent again. */
	ATF_REQUIRE(system(": > ipfw.log") == 0);
	http("POST", "/api/feeds/spamhaus-drop-v4/fetch", NULL, &r);
	EXPECT(&r, 202);
	resp_free(&r);
	for (i = 0; i < 300 && system("grep -q 'drop_v4.json 304' "
	    "feedsrv.log") != 0; i++)
		usleep(100000);
	ATF_CHECK(system("grep -q 'drop_v4.json 304' feedsrv.log") == 0);
	usleep(500000);
	ATF_CHECK(system("grep -q 'swap' ipfw.log") != 0);

	/* FireHOL level 1 lists the bogons on purpose: kept, but for what
	 * covers the console's own 127.0.0.1. */
	snprintf(body, sizeof(body), "{\"preset\":\"firehol-level1\",\"url\":"
	    "\"http://127.0.0.1:%d/firehol_level1.netset\",\"enabled\":true,"
	    "\"hosts\":[\"%s\"]}", port, sa);
	http("PUT", "/api/feeds/firehol-level1", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	feed_wait("firehol-level1", "fetched_at", NULL, &r);
	ATF_CHECK_MSG(feed_dropped(&r, "127.0.0.0/8", "covers 127.0.0.1, the "
	    "console's"), "%s", r.body);
	ATF_CHECK_MSG(strstr(r.body, "\"198.18.0.0/15\"") != NULL, "%s",
	    r.body);
	ATF_CHECK_STREQ("13", jstr(&r, "count"));
	resp_free(&r);

	/* A list of one's own, of every kind of entry: what is no prefix,
	 * the whole space, a host's and a sign-in's address, private space
	 * it does not list on purpose; one within another left out. */
	snprintf(body, sizeof(body), "{\"name\":\"Local\",\"url\":\"http://"
	    "127.0.0.1:%d/local.txt\",\"format\":\"plain\",\"interval\":1,"
	    "\"enabled\":true,\"hosts\":[\"%s\"]}", port, sa);
	http("PUT", "/api/feeds/local", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("feed_local", jstr(&r, "feed.table"));
	resp_free(&r);
	feed_wait("local", "fetched_at", NULL, &r);
	ATF_CHECK_STREQ("2", jstr(&r, "count"));
	ATF_CHECK_STREQ("1", jstr(&r, "covered"));
	ATF_CHECK_STREQ("5", jstr(&r, "dropped_count"));
	ATF_CHECK_MSG(feed_dropped(&r, "192.0.2.0/24", "covers a protected "
	    "address"), "%s", r.body);
	ATF_CHECK_MSG(feed_dropped(&r, "192.0.2.0/24", "covers 192.0.2.77, "
	    "host far's"), "%s", r.body);
	ATF_CHECK_MSG(feed_dropped(&r, "203.0.113.0/24", "alice's last "
	    "sign-in"), "%s", r.body);
	ATF_CHECK_MSG(feed_dropped(&r, "198.51.100.0/24", "private or "
	    "reserved"), "%s", r.body);
	ATF_CHECK_MSG(feed_dropped(&r, "0.0.0.0/0", "the whole address space"),
	    "%s", r.body);
	ATF_CHECK_MSG(feed_dropped(&r, "line 2", "not an address"), "%s",
	    r.body);
	ATF_CHECK_MSG(strstr(r.body, "nonsense") == NULL, "%s", r.body);
	ATF_CHECK_STREQ("8.8.8.0/24", jstr(&r, "sample.0"));
	ATF_CHECK_STREQ("2001:4860::/32", jstr(&r, "sample.1"));
	resp_free(&r);
	/* The preview: each host's dry run; nothing changes. */
	ATF_REQUIRE(system(": > ipfw.log") == 0);
	http("POST", "/api/feeds/local/preview", NULL, &r);
	EXPECT(&r, 202);
	resp_free(&r);
	snprintf(k, sizeof(k), "preview.hosts.%s.count", sa);
	feed_wait("local", k, "2", &r);
	snprintf(k, sizeof(k), "preview.hosts.%s.added", sa);
	ATF_CHECK_STREQ("0", jstr(&r, k));
	resp_free(&r);
	ATF_CHECK(system("grep -q 'swap' ipfw.log") != 0);

	/* A source gone: an alarm after three failures in a row, the
	 * hosts' table as it was; back, the alarm cleared. */
	snprintf(body, sizeof(body), "{\"preset\":\"spamhaus-drop-v4\","
	    "\"url\":\"http://127.0.0.1:%d/missing\",\"enabled\":true,"
	    "\"hosts\":[\"%s\"]}", port, sa);
	http("PUT", "/api/feeds/spamhaus-drop-v4", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	feed_wait("spamhaus-drop-v4", "failures", "1", &r);
	resp_free(&r);
	for (i = 2; i <= 3; i++) {
		http("POST", "/api/feeds/spamhaus-drop-v4/fetch", NULL, &r);
		resp_free(&r);
		snprintf(k, sizeof(k), "%d", i);
		feed_wait("spamhaus-drop-v4", "failures", k, &r);
		resp_free(&r);
	}
	feed_wait("spamhaus-drop-v4", "alarm.since", NULL, &r);
	ATF_CHECK_STREQ("4", jstr(&r, "count"));
	resp_free(&r);
	ATF_CHECK(access("feeds/feed_spamhaus_drop_v4", F_OK) == 0);
	snprintf(body, sizeof(body), "{\"preset\":\"spamhaus-drop-v4\","
	    "\"url\":\"http://127.0.0.1:%d/drop_v4.json\",\"enabled\":true,"
	    "\"hosts\":[\"%s\"]}", port, sa);
	http("PUT", "/api/feeds/spamhaus-drop-v4", body, &r);
	resp_free(&r);
	feed_wait("spamhaus-drop-v4", "failures", "0", &r);
	ATF_CHECK(jstr(&r, "alarm.since") == NULL);
	resp_free(&r);

	/* Disabled: its own table given up, the others' left. */
	snprintf(body, sizeof(body), "{\"name\":\"Local\",\"url\":\"http://"
	    "127.0.0.1:%d/local.txt\",\"enabled\":false,\"hosts\":[\"%s\"]}",
	    port, sa);
	http("PUT", "/api/feeds/local", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 300 && access("feeds/feed_local", F_OK) == 0; i++)
		usleep(100000);
	ATF_CHECK(access("feeds/feed_local", F_OK) != 0);
	ATF_CHECK(access("feeds/feed_spamhaus_drop_v4", F_OK) == 0);
	ATF_CHECK(access("feeds/feed_firehol_level1", F_OK) == 0);
	/* Removed: the same. */
	http("DELETE", "/api/feeds/firehol-level1", NULL, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	for (i = 0; i < 300 && access("feeds/feed_firehol_level1", F_OK) ==
	    0; i++)
		usleep(100000);
	ATF_CHECK(access("feeds/feed_firehol_level1", F_OK) != 0);
	ATF_CHECK(access("feeds/feed_spamhaus_drop_v4", F_OK) == 0);

	/* Redirected: followed on the stand-in; to a cloud's metadata,
	 * refused though the stand-in itself is let through. */
	snprintf(body, sizeof(body), "{\"url\":\"http://127.0.0.1:%d/"
	    "redirect\",\"format\":\"spamhaus-json\",\"enabled\":true,"
	    "\"hosts\":[]}", port);
	http("PUT", "/api/feeds/hop", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	feed_wait("hop", "count", "4", &r);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"url\":\"http://127.0.0.1:%d/"
	    "redirect-private\",\"enabled\":true,\"hosts\":[]}", port);
	http("PUT", "/api/feeds/meta", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	feed_wait("meta", "failures", "1", &r);
	ATF_CHECK_MSG(strstr(r.body, "169.254.169.254 is a private or "
	    "reserved address") != NULL, "%s", r.body);
	resp_free(&r);

	/* A feed of chosen addresses: a sign-in's, an unreadable host's, a
	 * readable host's.  The owner sees each entry dropped, and why. */
	snprintf(body, sizeof(body), "{\"url\":\"http://127.0.0.1:%d/"
	    "oracle.txt\",\"enabled\":true,\"hosts\":[]}", port);
	http("PUT", "/api/feeds/oracle", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	feed_wait("oracle", "fetched_at", NULL, &r);
	ATF_CHECK_MSG(feed_dropped(&r, "203.0.113.9/32", "alice's last "
	    "sign-in") && feed_dropped(&r, "192.0.2.77/32", "host far's") &&
	    feed_dropped(&r, "100.64.0.5/32", "host near's"), "%s", r.body);
	ATF_CHECK(jstr(&r, "protected_hidden") == NULL);
	ATF_CHECK_STREQ("1", jstr(&r, "count"));
	resp_free(&r);

	/* A feed on host gone, which fails there: the owner sees it, by
	 * its name and error, in what was sent and in a preview. */
	snprintf(body, sizeof(body), "{\"url\":\"http://127.0.0.1:%d/"
	    "drop_v4.json\",\"format\":\"spamhaus-json\",\"enabled\":true,"
	    "\"hosts\":[\"%s\"]}", port, sg);
	http("PUT", "/api/feeds/seen", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	snprintf(k, sizeof(k), "delivered.%s.error", sg);
	feed_wait("seen", k, NULL, &r);
	snprintf(k, sizeof(k), "delivered.%s.name", sg);
	ATF_CHECK_STREQ("gone", jstr(&r, k));
	resp_free(&r);
	http("POST", "/api/feeds/seen/preview", NULL, &r);
	EXPECT(&r, 202);
	resp_free(&r);
	snprintf(k, sizeof(k), "preview.hosts.%s.error", sg);
	feed_wait("seen", k, NULL, &r);
	resp_free(&r);

	/* An operator who only views hosts a and near may not take away
	 * the feed that is on a, nor change it: refused, its table left.
	 * A member reads none and changes none. */
	snprintf(body, sizeof(body), "{\"console\":\"operator\",\"hosts\":"
	    "{\"%s\":\"viewer\",\"%s\":\"viewer\"}}", sa, sn);
	http("PUT", "/api/roles/a-viewer-op", body, &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("PUT", "/api/users/carol", "{\"roles\":[\"a-viewer-op\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/users/carol/invite", NULL, &r);
	EXPECT(&r, 200);
	snprintf(invite2, sizeof(invite2), "%s", jstr(&r, "token"));
	resp_free(&r);
	http("PUT", "/api/users/bob", "{\"roles\":[\"viewer\"]}", &r);
	EXPECT(&r, 200);
	resp_free(&r);
	http("POST", "/api/users/bob/invite", NULL, &r);
	EXPECT(&r, 200);
	snprintf(invite, sizeof(invite), "%s", jstr(&r, "token"));
	resp_free(&r);
	cookie[0] = '\0';
	authn_new(&c, -7);
	do_register(&c, invite2, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("operator", jstr(&r, "console"));
	resp_free(&r);
	http("DELETE", "/api/feeds/spamhaus-drop-v4", NULL, &r);
	ATF_CHECK_MSG(r.status == 403 && strstr(r.body, "host a is not one") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"preset\":\"spamhaus-drop-v4\","
	    "\"url\":\"http://127.0.0.1:%d/drop_v4.json\",\"enabled\":false,"
	    "\"hosts\":[]}", port);
	http("PUT", "/api/feeds/spamhaus-drop-v4", body, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"url\":\"http://127.0.0.1:%d/"
	    "drop_v4.json\",\"enabled\":true,\"hosts\":[\"%s\"]}", port, sa);
	http("PUT", "/api/feeds/carols", body, &r);
	EXPECT(&r, 400);
	resp_free(&r);
	usleep(3000000);
	ATF_CHECK(access("feeds/feed_spamhaus_drop_v4", F_OK) == 0);
	http("GET", "/api/feeds/spamhaus-drop-v4", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("true", jstr(&r, "enabled"));
	resp_free(&r);
	/* What a feed dropped read by one who is no owner: what covers
	 * a host's address it may not read, or a sign-in's, only counted. */
	http("GET", "/api/feeds/local", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(!feed_dropped(&r, "192.0.2.0/24", "covers") &&
	    !feed_dropped(&r, "203.0.113.0/24", "covers"), "%s", r.body);
	ATF_CHECK_STREQ("2", jstr(&r, "protected_hidden"));
	ATF_CHECK_MSG(strstr(r.body, "192.0.2.77") == NULL && strstr(r.body,
	    "203.0.113.9") == NULL && strstr(r.body, "alice") == NULL &&
	    strstr(r.body, "far") == NULL && strstr(r.body, "127.0.0.1,") ==
	    NULL, "%s", r.body);
	resp_free(&r);
	/* A feed from a URL of one's own is an owner's: an operator uses
	 * a preset, enables or disables such a feed, and previews none. */
	snprintf(body, sizeof(body), "{\"url\":\"http://127.0.0.1:%d/"
	    "drop_v4.json\",\"enabled\":true,\"hosts\":[]}", port);
	http("PUT", "/api/feeds/carol2", body, &r);
	ATF_CHECK_MSG(r.status == 403 && strstr(r.body, "console owner") !=
	    NULL, "%s", r.body);
	resp_free(&r);
	http("PUT", "/api/feeds/dshield", "{\"preset\":\"dshield\","
	    "\"enabled\":false,\"hosts\":[]}", &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("https://feeds.dshield.org/block.txt", jstr(&r,
	    "feed.url"));
	resp_free(&r);
	http("POST", "/api/feeds/oracle/preview", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"url\":\"http://127.0.0.1:%d/"
	    "oracle.txt\",\"enabled\":false,\"hosts\":[]}", port);
	http("PUT", "/api/feeds/oracle", body, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("false", jstr(&r, "feed.enabled"));
	resp_free(&r);
	snprintf(body, sizeof(body), "{\"url\":\"http://127.0.0.1:%d/"
	    "local.txt\",\"enabled\":true,\"hosts\":[]}", port);
	http("PUT", "/api/feeds/oracle", body, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	/* Host gone is not the operator's to read: neither its id nor its
	 * name nor its error anywhere, only counted. */
	http("GET", "/api/feeds", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, sg) == NULL && strstr(r.body, "gone") ==
	    NULL && strstr(r.body, "none.sock") == NULL, "%s", r.body);
	resp_free(&r);
	http("GET", "/api/feeds/seen", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, sg) == NULL && strstr(r.body, "gone") ==
	    NULL && strstr(r.body, "none.sock") == NULL, "%s", r.body);
	ATF_CHECK_STREQ("1", jstr(&r, "hosts_hidden"));
	ATF_CHECK_STREQ("1", jstr(&r, "delivered_hidden"));
	ATF_CHECK_STREQ("1", jstr(&r, "preview.hosts_hidden"));
	resp_free(&r);
	/* Not even listed by entry, which a feed of chosen addresses
	 * would tell: counted; the host it may read, listed. */
	http("GET", "/api/feeds/oracle", NULL, &r);
	EXPECT(&r, 200);
	ATF_CHECK_MSG(strstr(r.body, "203.0.113.9") == NULL && strstr(r.body,
	    "192.0.2.77") == NULL && strstr(r.body, "alice") == NULL,
	    "%s", r.body);
	ATF_CHECK_STREQ("2", jstr(&r, "protected_hidden"));
	ATF_CHECK_MSG(feed_dropped(&r, "100.64.0.5/32", "host near's"), "%s",
	    r.body);
	resp_free(&r);
	cookie[0] = '\0';
	authn_new(&b, -8);
	do_register(&b, invite, &r);
	EXPECT(&r, 200);
	ATF_CHECK_STREQ("member", jstr(&r, "console"));
	resp_free(&r);
	http("GET", "/api/feeds", NULL, &r);
	EXPECT(&r, 403);
	resp_free(&r);
	http("PUT", "/api/feeds/x", "{\"url\":\"https://example.org/x\"}", &r);
	EXPECT(&r, 403);
	resp_free(&r);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, feeds);
	ATF_TP_ADD_TC(tp, watch_nacm);
	ATF_TP_ADD_TC(tp, cluster);
	ATF_TP_ADD_TC(tp, notif_receiver);
	ATF_TP_ADD_TC(tp, notif_token);
	ATF_TP_ADD_TC(tp, watch_reconnect);
	ATF_TP_ADD_TC(tp, fleet_stream_rejoin);
	ATF_TP_ADD_TC(tp, watch_held);
	ATF_TP_ADD_TC(tp, watch_events);

	ATF_TP_ADD_TC(tp, unauthenticated);
	ATF_TP_ADD_TC(tp, setup_token);
	ATF_TP_ADD_TC(tp, setup_password);
	ATF_TP_ADD_TC(tp, register_login);
	ATF_TP_ADD_TC(tp, login_refused);
	ATF_TP_ADD_TC(tp, android);
	ATF_TP_ADD_TC(tp, android_none);
	ATF_TP_ADD_TC(tp, second_key);
	ATF_TP_ADD_TC(tp, users);
	ATF_TP_ADD_TC(tp, csrf);
	ATF_TP_ADD_TC(tp, console_plugins);
	ATF_TP_ADD_TC(tp, jails);
	ATF_TP_ADD_TC(tp, restconf);
	ATF_TP_ADD_TC(tp, restconf_write);
	ATF_TP_ADD_TC(tp, restconf_ra);
	ATF_TP_ADD_TC(tp, restconf_mount);
	ATF_TP_ADD_TC(tp, restconf_cbor);
	ATF_TP_ADD_TC(tp, restconf_edit);
	ATF_TP_ADD_TC(tp, restconf_yang_patch);
	ATF_TP_ADD_TC(tp, restconf_etag);
	ATF_TP_ADD_TC(tp, restconf_tag_access_denied);
	ATF_TP_ADD_TC(tp, restconf_tag_invalid_value);
	ATF_TP_ADD_TC(tp, restconf_tag_operation_not_supported);
	ATF_TP_ADD_TC(tp, restconf_tag_operation_failed);
	ATF_TP_ADD_TC(tp, restconf_tag_in_use);
	ATF_TP_ADD_TC(tp, restconf_tag_data_exists);
	ATF_TP_ADD_TC(tp, restconf_tag_data_missing);
	ATF_TP_ADD_TC(tp, restconf_tag_missing_attribute);
	ATF_TP_ADD_TC(tp, restconf_tag_bad_attribute);
	ATF_TP_ADD_TC(tp, restconf_tag_unknown_element);
	ATF_TP_ADD_TC(tp, restconf_tag_unknown_namespace);
	ATF_TP_ADD_TC(tp, restconf_tag_bad_element);
	ATF_TP_ADD_TC(tp, restconf_tag_malformed_message);
	ATF_TP_ADD_TC(tp, l3nm);
	ATF_TP_ADD_TC(tp, l3nm_sdwan);
	ATF_TP_ADD_TC(tp, l3nm_mef);
	ATF_TP_ADD_TC(tp, nacm_user);
	ATF_TP_ADD_TC(tp, nacm_sync);
	ATF_TP_ADD_TC(tp, server_readdress);
	ATF_TP_ADD_TC(tp, nacm_console);
	ATF_TP_ADD_TC(tp, job_user);
	ATF_TP_ADD_TC(tp, services);
	ATF_TP_ADD_TC(tp, agent_update);
	ATF_TP_ADD_TC(tp, agent_build);
	ATF_TP_ADD_TC(tp, update_notes);
	ATF_TP_ADD_TC(tp, smtpd);
	ATF_TP_ADD_TC(tp, speeder);
	ATF_TP_ADD_TC(tp, monitors);
	ATF_TP_ADD_TC(tp, settings);
	ATF_TP_ADD_TC(tp, mail);
	ATF_TP_ADD_TC(tp, telegram);
	ATF_TP_ADD_TC(tp, local_agent);
	ATF_TP_ADD_TC(tp, local_same);
	ATF_TP_ADD_TC(tp, local_absent);
	ATF_TP_ADD_TC(tp, push);
	ATF_TP_ADD_TC(tp, tokens);
	ATF_TP_ADD_TC(tp, transfers);
	ATF_TP_ADD_TC(tp, config_bundle);
	ATF_TP_ADD_TC(tp, templates);
	ATF_TP_ADD_TC(tp, pfxlists);
	ATF_TP_ADD_TC(tp, labels);
	ATF_TP_ADD_TC(tp, password);
	ATF_TP_ADD_TC(tp, ldap);
	ATF_TP_ADD_TC(tp, troubleshoot);
	ATF_TP_ADD_TC(tp, workflows);
	ATF_TP_ADD_TC(tp, workflow_approval);
	ATF_TP_ADD_TC(tp, sdwan);
	ATF_TP_ADD_TC(tp, sdwan_apply);
	ATF_TP_ADD_TC(tp, sdwan_mesh);
	ATF_TP_ADD_TC(tp, sdwan_host);
	ATF_TP_ADD_TC(tp, sdwan_loop);
	ATF_TP_ADD_TC(tp, l3nm_plan);
	ATF_TP_ADD_TC(tp, sdwan_infeasible);
	ATF_TP_ADD_TC(tp, sdwan_breakout);
	ATF_TP_ADD_TC(tp, sdwan_nat64);
	ATF_TP_ADD_TC(tp, sdwan_sets);
	ATF_TP_ADD_TC(tp, sdwan_neigh);
	ATF_TP_ADD_TC(tp, sdwan_lists);
	ATF_TP_ADD_TC(tp, sdwan_notices);
	ATF_TP_ADD_TC(tp, sdwan_uswe);
	ATF_TP_ADD_TC(tp, sdwan_sfp);
	ATF_TP_ADD_TC(tp, sdwan_jail);
	ATF_TP_ADD_TC(tp, sdwan_lab);
	ATF_TP_ADD_TC(tp, load);
	ATF_TP_ADD_TC(tp, churn);
	ATF_TP_ADD_TC(tp, session_restart);
	ATF_TP_ADD_TC(tp, unreachable);
	ATF_TP_ADD_TC(tp, mtls);
	ATF_TP_ADD_TC(tp, agent_update_bridge);
	ATF_TP_ADD_TC(tp, restconf_revisions);
	ATF_TP_ADD_TC(tp, enrol);
	ATF_TP_ADD_TC(tp, tls_ec);
	return (atf_no_error());
}
