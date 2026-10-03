/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The PWA in a real browser: Chromium, driven through chromedriver's
 * WebDriver interface, with a virtual CTAP2 authenticator, against kore
 * and arcana-agent in the work directory.  Skipped when Chromium or
 * chromedriver are not installed.
 *
 * Configuration variables: kore, dhparam, arcana-agent (as for console_test),
 * chrome, chromedriver, webroot (the built PWA).
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <openssl/evp.h>

#include <atf-c.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "harness.h"

static int	wd_port;
static char	wd_sid[128];

static int
free_port(void)
{
	struct sockaddr_in	sin;
	socklen_t		len;
	int			s, port;

	ATF_REQUIRE((s = socket(AF_INET, SOCK_STREAM, 0)) != -1);
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE(bind(s, (struct sockaddr *)&sin, sizeof(sin)) == 0);
	len = sizeof(sin);
	ATF_REQUIRE(getsockname(s, (struct sockaddr *)&sin, &len) == 0);
	port = ntohs(sin.sin_port);
	close(s);
	return (port);
}

/* One WebDriver command; returns its "value", which the caller unrefs. */
static ucl_object_t *
wd(const char *method, const char *path, const char *body)
{
	struct resp		 r;
	const ucl_object_t	*v;
	ucl_object_t		*out;
	char			 host[32], full[512];
	char			 saved[sizeof(cookie)];

	snprintf(host, sizeof(host), "127.0.0.1:%d", wd_port);
	if (wd_sid[0] != '\0' && strncmp(path, "/session/", 9) == 0)
		snprintf(full, sizeof(full), "/session/%s%s", wd_sid, path + 8);
	else
		snprintf(full, sizeof(full), "%s", path);
	/* Keep the console's cookie: chromedriver sets none, but be sure. */
	memcpy(saved, cookie, sizeof(saved));
	http_on(tcp_socket(wd_port), host, "", method, full, body, &r);
	memcpy(cookie, saved, sizeof(saved));
	ATF_REQUIRE_MSG(r.status == 200, "WebDriver %s %s: %d %.400s", method,
	    full, r.status, r.body);
	v = r.json != NULL ? ucl_object_lookup(r.json, "value") : NULL;
	out = v != NULL ? ucl_object_ref((ucl_object_t *)(uintptr_t)v) : NULL;
	resp_free(&r);
	return (out);
}

/*
 * With the configuration variable "shots" naming a directory, keep a
 * picture of the page there as <name>.png: for looking at a change of
 * layout, which no assertion sees.
 */
static const char	*shots;

static void
shot(const char *name)
{
	ucl_object_t	*v;
	const char	*b64;
	unsigned char	*png;
	char		 path[MAXPATHLEN];
	size_t		 len;
	FILE		*fp;
	int		 n;

	if (shots == NULL)
		return;
	usleep(400000);		/* let transitions end */
	if ((v = wd("GET", "/session/screenshot", NULL)) == NULL)
		return;
	b64 = ucl_object_tostring(v);
	len = strlen(b64);
	if ((png = malloc(len)) != NULL && (n = EVP_DecodeBlock(png,
	    (const unsigned char *)b64, (int)len)) > 0) {
		while (len > 0 && b64[--len] == '=')
			n--;
		snprintf(path, sizeof(path), "%s/%s.png", shots, name);
		if ((fp = fopen(path, "w")) != NULL) {
			fwrite(png, 1, (size_t)n, fp);
			fclose(fp);
		}
	}
	free(png);
	ucl_object_unref(v);
}

/* Run script in the page; returns its result. */
static ucl_object_t *
js(const char *script)
{
	ucl_object_t	*b, *res;
	char		*body;

	b = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(b, ucl_object_fromstring(script), "script", 0,
	    false);
	ucl_object_insert_key(b, ucl_object_typed_new(UCL_ARRAY), "args", 0,
	    false);
	body = (char *)ucl_object_emit(b, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(b);
	res = wd("POST", "/session/execute/sync", body);
	free(body);
	return (res);
}

static bool
js_true(const char *expr)
{
	ucl_object_t	*v;
	char		 script[2048];
	bool		 t;

	snprintf(script, sizeof(script), "return !!(%s);", expr);
	v = js(script);
	t = v != NULL && ucl_object_toboolean(v);
	if (v != NULL)
		ucl_object_unref(v);
	return (t);
}

static void
wait_js(const char *expr, int seconds)
{
	int	i;

	for (i = 0; i < seconds * 10; i++) {
		if (js_true(expr))
			return;
		usleep(100000);
	}
	atf_tc_fail("timed out waiting for %s", expr);
}

static void
run(const char *script)
{
	ucl_object_t	*v;

	if ((v = js(script)) != NULL)
		ucl_object_unref(v);
}

static void
browser_start(const atf_tc_t *tc)
{
	const char	*chrome, *driver;
	ucl_object_t	*v;
	char		 port[32], body[2048], cwd[MAXPATHLEN];
	char		*argv[4];
	FILE		*fp;
	pid_t		 pid;
	int		 i;

	chrome = atf_tc_get_config_var_wd(tc, "chrome",
	    "/usr/local/bin/chrome");
	driver = atf_tc_get_config_var_wd(tc, "chromedriver",
	    "/usr/local/bin/chromedriver");
	if (access(chrome, X_OK) == -1 || access(driver, X_OK) == -1)
		atf_tc_skip("needs %s and %s", chrome, driver);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	wd_port = free_port();
	snprintf(port, sizeof(port), "--port=%d", wd_port);
	argv[0] = (char *)(uintptr_t)driver;
	argv[1] = port;
	argv[2] = NULL;
	pid = spawn(argv, "chromedriver.out");
	ATF_REQUIRE((fp = fopen("chromedriver.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);
	for (i = 0; i < 100; i++) {
		int s = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in sin;

		memset(&sin, 0, sizeof(sin));
		sin.sin_len = sizeof(sin);
		sin.sin_family = AF_INET;
		sin.sin_port = htons((uint16_t)wd_port);
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == 0) {
			close(s);
			break;
		}
		close(s);
		usleep(50000);
	}
	snprintf(body, sizeof(body), "{\"capabilities\":{\"alwaysMatch\":{"
	    "\"browserName\":\"chrome\","
	    "\"webauthn:virtualAuthenticators\":true,"
	    "\"goog:chromeOptions\":{\"binary\":\"%s\",\"args\":["
	    "\"--headless=new\",\"--no-sandbox\",\"--user-data-dir=%s/chrome\","
	    "\"--window-size=1280,800\"]}}}}", chrome, cwd);
	wd_sid[0] = '\0';
	v = wd("POST", "/session", body);
	ATF_REQUIRE(v != NULL && ucl_object_lookup(v, "sessionId") != NULL);
	snprintf(wd_sid, sizeof(wd_sid), "%s", ucl_object_tostring(
	    ucl_object_lookup(v, "sessionId")));
	ucl_object_unref(v);
	v = wd("POST", "/session/webauthn/authenticator", "{\"protocol\":"
	    "\"ctap2\",\"transport\":\"usb\",\"hasResidentKey\":false,"
	    "\"hasUserVerification\":true,\"isUserConsenting\":true,"
	    "\"isUserVerified\":true}");
	if (v != NULL)
		ucl_object_unref(v);
}

static void
browser_stop(void)
{
	FILE	*fp;
	int	 pid;

	if ((fp = fopen("chromedriver.pid", "r")) != NULL) {
		if (fscanf(fp, "%d", &pid) == 1)
			kill(pid, SIGTERM);
		fclose(fp);
	}
	stop();
}

static void
go(const char *path)
{
	ucl_object_t	*v;
	char		 body[256];

	snprintf(body, sizeof(body), "{\"url\":\"%s%s\"}", harness_origin,
	    path);
	if ((v = wd("POST", "/session/url", body)) != NULL)
		ucl_object_unref(v);
}

static void
offline(bool off)
{
	ucl_object_t	*v;
	char		 body[256];

	v = wd("POST", "/session/goog/cdp/execute",
	    "{\"cmd\":\"Network.enable\",\"params\":{}}");
	if (v != NULL)
		ucl_object_unref(v);
	snprintf(body, sizeof(body), "{\"cmd\":"
	    "\"Network.emulateNetworkConditions\",\"params\":{\"offline\":%s,"
	    "\"latency\":0,\"downloadThroughput\":-1,"
	    "\"uploadThroughput\":-1}}", off ? "true" : "false");
	if ((v = wd("POST", "/session/goog/cdp/execute", body)) != NULL)
		ucl_object_unref(v);
}

ATF_TC_WITH_CLEANUP(pwa);
ATF_TC_HEAD(pwa, tc)
{

	atf_tc_set_md_var(tc, "descr", "Enrol, manage jails, see the workflow, "
	    "log in again and go offline, in Chromium");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(pwa, tc)
{
	char		 web[MAXPATHLEN], cwd[MAXPATHLEN], script[2048];
	char		*token;
	FILE		*fp;

	snprintf(web, sizeof(web), "%s", locate(tc, "../../arcana-ui/dist",
	    "webroot", "/usr/local/www/arcana-console"));
	if (access(web, R_OK) == -1)
		atf_tc_skip("no built PWA at %s", web);
	shots = atf_tc_has_config_var(tc, "shots") ?
	    atf_tc_get_config_var(tc, "shots") : NULL;
	start(tc, free_port(), web);
	browser_start(tc);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);

	/* Opened at an address it is not set up for, the console says so
	 * before the browser can only say "SecurityError". */
	snprintf(script, sizeof(script), "{\"url\":\"http://127.0.0.1:%d/\"}",
	    harness_port);
	ucl_object_unref(wd("POST", "/session/url", script));
	wait_js("document.querySelector('.err.origin') && document."
	    "querySelector('.err.origin').textContent.includes('rp_id "
	    "localhost')", 20);

	/* Enrol: the setup token and the (virtual) security key. */
	go("/");
	wait_js("document.querySelector('form[data-form=enrol]')", 20);
	ATF_CHECK(!js_true("document.querySelector('.err.origin')"));
	ATF_REQUIRE((fp = fopen("data/setup-token", "r")) != NULL);
	ATF_REQUIRE((token = calloc(1, 128)) != NULL);
	ATF_REQUIRE(fgets(token, 128, fp) != NULL);
	fclose(fp);
	token[strcspn(token, "\n")] = '\0';
	snprintf(script, sizeof(script), "const f = document.querySelector("
	    "'form[data-form=enrol]'); f.token.value = '%s'; f.name.value = "
	    "'virtual key'; f.requestSubmit();", token);
	free(token);
	run(script);
	wait_js("document.querySelector('.shell')", 20);
	/* The effects class comes from a script in the head: the page's
	 * Content-Security-Policy must let it run. */
	ATF_CHECK(js_true("document.documentElement.classList.contains('fx')"));
	ATF_CHECK_MSG(access("data/setup-token", F_OK) == -1,
	    "setup token not consumed");

	/* A server, its jails, and starting one. */
	run("document.querySelector('button[data-act=add-server]').click()");
	wait_js("document.querySelector('form[data-form=add-server]')", 5);
	snprintf(script, sizeof(script), "const f = document.querySelector("
	    "'form[data-form=add-server]'); f.name.value = 'lab'; f.uri.value "
	    "= 'unix:%s/jgd.sock'; f.requestSubmit();", cwd);
	run(script);
	/* The new host is selected: its summary, with usage and a graph
	 * of its jails; the tree has the host and the jails under it. */
	wait_js("document.querySelector('.tree .titem.server.selected')", 20);
	wait_js("document.querySelector('.topo .tnode.s-stopped')", 20);
	ATF_CHECK(js_true("document.querySelector('.tree .titem.leaf')"));
	ATF_CHECK(js_true("document.querySelector('.tiles .tile')"));
	shot("1-host-summary");
	/* The fleet page lists it, and leads back to it. */
	run("document.querySelector('.tree .titem.fleet').click()");
	wait_js("document.querySelector('.hosts .hostcard')", 5);
	shot("2-fleet");
	run("document.querySelector('.hosts .hostcard').click()");
	wait_js("document.querySelector('.tree .titem.server.selected')", 5);
	run("document.querySelector('button.tab[data-arg=jails]').click()");
	wait_js("document.querySelector('#j-web.s-stopped')", 20);
	ATF_CHECK(js_true("document.querySelector('#j-db')"));
	run("document.querySelector('#j-web button[data-act=start]').click()");
	wait_js("document.querySelector('.dock .last.o-ok')", 20);

	/* The workflow and the raw output of jail(8). */
	run("document.querySelector('.dock > header').click()");
	wait_js("document.querySelector('.graph .node.k-exec')", 5);
	shot("3-jails-and-workflow");
	ATF_CHECK(js_true("document.querySelector('.graph .node.k-daemon')"));
	ATF_CHECK(js_true("document.querySelector('.graph .node.k-auth')"));
	run("document.querySelector('.trace button[data-act=raw]').click()");
	wait_js("document.querySelector('.terminal')", 5);
	ATF_CHECK(js_true("document.querySelector('.terminal').textContent."
	    "includes('fake-jail: -f etc/jail.conf -c web')"));
	run("document.querySelector('.modal button[data-act=close]').click()");
	run("document.querySelector('.dock > header').click()");

	/* Previewing a persistent address change shows the diff. */
	run("document.querySelector('#j-db').click()");
	wait_js("document.querySelector('.jail-page')", 5);
	shot("4-jail-page");
	ATF_CHECK(js_true("document.querySelector('.tree .titem.leaf.selected')"));
	run("document.querySelector('.jail-page button[data-act=address-add]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=address]')", 5);
	run("const f = document.querySelector('form[data-form=address]'); "
	    "f.address.value = '10.0.0.21'; f.live.checked = false; "
	    "f.persist.checked = true; "
	    "f.querySelector('button[value=preview]').click();");
	wait_js("document.querySelector('pre.diff') && document.querySelector("
	    "'pre.diff').textContent.includes('\"10.0.0.21\"')", 10);
	run("document.querySelector('.modal button[data-act=close]').click()");
	/* The host's own record of jobs has the start that was done. */
	run("document.querySelector('.jail-page button[data-act=close-drawer]')"
	    ".click()");
	run("document.querySelector('button.tab[data-arg=jobs]').click()");
	wait_js("document.querySelector('table.jobs tr.j-done')", 10);
	shot("5-jobs");

	/* Log out, and in again with the key. */
	run("document.querySelector('button[data-act=logout]').click()");
	wait_js("document.querySelector('button[data-act=login]')", 10);
	run("document.querySelector('button[data-act=login]').click()");
	wait_js("document.querySelector('.shell')", 20);

	/* The shell works offline and says the data needs the network. */
	run("return navigator.serviceWorker.ready.then(() => true)");
	if (!js_true("navigator.serviceWorker.controller")) {
		go("/");
		wait_js("document.querySelector('.shell')", 20);
	}
	ATF_REQUIRE(js_true("navigator.serviceWorker.controller"));
	offline(true);
	go("/");
	wait_js("document.querySelector('.auth .offline')", 20);
	offline(false);
	wait_js("document.querySelector('.shell')", 30);
}
ATF_TC_CLEANUP(pwa, tc)
{

	browser_stop();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, pwa);
	return (atf_no_error());
}
