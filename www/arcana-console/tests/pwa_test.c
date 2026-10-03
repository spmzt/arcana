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

/* The viewport of a phone, or the window's own again. */
static void
phone(bool on)
{
	ucl_object_t	*v;

	v = wd("POST", "/session/goog/cdp/execute", on ?
	    "{\"cmd\":\"Emulation.setDeviceMetricsOverride\",\"params\":{"
	    "\"width\":390,\"height\":844,\"deviceScaleFactor\":2,"
	    "\"mobile\":true}}" :
	    "{\"cmd\":\"Emulation.clearDeviceMetricsOverride\",\"params\":{}}");
	if (v != NULL)
		ucl_object_unref(v);
	usleep(300000);
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
	harness_other_agent = true;
	/* A copy of the shell, for the test of its update to change. */
	snprintf(script, sizeof(script), "cp -R '%s' www-copy", web);
	ATF_REQUIRE(system(script) == 0);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(web, sizeof(web), "%s/www-copy", cwd);
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

	/* Settings: a repository to build the agent from is set from the
	 * page, kept by the console, and what web.conf fixes is shown. */
	run("document.querySelector('button[data-act=settings]').click()");
	wait_js("document.querySelector('form[data-form=settings] "
	    "input[name=agent_source]')", 10);
	ATF_CHECK(js_true("document.querySelector('form.settings dl.kv')."
	    "textContent.includes('localhost')"));
	shot("0a-settings");
	run("const f = document.querySelector('form[data-form=settings]'); "
	    "f.agent_source.value = 'git@git.example.org:me/arcana.git'; "
	    "f.requestSubmit();");
	wait_js("!document.querySelector('form[data-form=settings]') && "
	    "[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('Settings saved'))", 10);

	/* A desktop browser is not asked to install the console; a phone
	 * is, with the browser's own prompt, and can say not now. */
	ATF_CHECK(!js_true("document.querySelector('.banner.install')"));
	run("Object.defineProperty(navigator, 'userAgent', { get: () => "
	    "'Mozilla/5.0 (Linux; Android 14) Chrome/126 Mobile' }); "
	    "const e = new Event('beforeinstallprompt'); "
	    "e.prompt = () => { window.prompted = true; }; "
	    "e.userChoice = Promise.resolve({ outcome: 'dismissed' }); "
	    "window.dispatchEvent(e);");
	wait_js("document.querySelector('.banner.install button"
	    "[data-act=install]')", 5);
	shot("0-install-offer");
	run("document.querySelector('button[data-act=install]').click()");
	wait_js("window.prompted === true && "
	    "!document.querySelector('.banner.install')", 5);
	run("const e = new Event('beforeinstallprompt'); e.prompt = () => {}; "
	    "e.userChoice = Promise.resolve({ outcome: 'dismissed' }); "
	    "window.dispatchEvent(e);");
	wait_js("document.querySelector('.banner.install')", 5);
	run("document.querySelector('button[data-act=install-dismiss]')"
	    ".click()");
	wait_js("!document.querySelector('.banner.install') && "
	    "localStorage.getItem('arc_install') === '0'", 5);
	ATF_CHECK_MSG(access("data/setup-token", F_OK) == -1,
	    "setup token not consumed");

	/* A server, its jails, and starting one. */
	/* A third jail, so the tree has something to leave out. */
	ATF_REQUIRE((fp = fopen("etc/jail.conf.d/cache.conf", "w")) != NULL);
	fprintf(fp, "cache {\n\tpath = \"/jails/cache\";\n\tip4.addr = "
	    "10.0.0.30;\n}\n");
	fclose(fp);
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
	/* Its jails are folded away until asked for; the choice is kept. */
	ATF_CHECK(!js_true("document.querySelector('.tree .titem.leaf')"));
	run("document.querySelector('.tree button[data-act=fold]').click()");
	wait_js("document.querySelectorAll('.tree .titem.leaf').length === 3 "
	    "&& localStorage.getItem('arc_open').includes('\"')", 5);
	run("document.querySelector('.tree button[data-act=fold]').click()");
	wait_js("!document.querySelector('.tree .titem.leaf') && "
	    "localStorage.getItem('arc_open') === '[]'", 5);
	run("document.querySelector('.tree button[data-act=fold]').click()");
	wait_js("document.querySelectorAll('.tree .titem.leaf').length === 3",
	    5);
	ATF_CHECK(!js_true("document.querySelector('.tree .titem.more')"));
	/* With no room under the hosts, a row stands for the rest and
	 * shows them when asked. */
	ucl_object_unref(wd("POST", "/session/window/rect",
	    "{\"width\":1280,\"height\":330}"));
	wait_js("document.querySelector('.tree .titem.more') && "
	    "document.querySelectorAll('.tree .titem.leaf:not(.more)').length "
	    "=== 1", 5);
	shot("1a-tree-more");
	run("document.querySelector('.tree .titem.more').click()");
	wait_js("document.querySelectorAll('.tree .titem.leaf:not(.more)')."
	    "length === 3 && document.querySelector('.tree .titem.more')."
	    "textContent.includes('fewer')", 5);
	run("document.querySelector('.tree .titem.more').click()");
	ucl_object_unref(wd("POST", "/session/window/rect",
	    "{\"width\":1280,\"height\":800}"));
	wait_js("!document.querySelector('.tree .titem.more') && "
	    "document.querySelectorAll('.tree .titem.leaf').length === 3", 5);
	ATF_CHECK(js_true("document.querySelector('.tiles .tile')"));
	shot("1-host-summary");
	/* The host runs another build of arcana-agent than the console
	 * has: the page offers to send its own, here without a restart. */
	wait_js("document.querySelector('.hostbar button[data-act="
	    "agent-update]')", 10);
	run("document.querySelector('.hostbar button[data-act=agent-update]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=agent-update]')", 5);
	shot("1b-agent-update");
	run("const f = document.querySelector('form[data-form=agent-update]'); "
	    "f.restart.checked = false; f.requestSubmit();");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('in place'))", 20);
	ATF_CHECK(access("installed-agent", X_OK) == 0);

	/*
	 * With the repository set, the host can be asked to build.  It is
	 * reached over SSH and the host does not know its server: the
	 * page shows the server's key for the user to confirm, and the
	 * build goes on once it is.
	 */
	ATF_REQUIRE(system("ssh-keygen -q -t ed25519 -N '' -f hostkey") == 0);
	run("document.querySelector('.hostbar button[data-act=agent-build]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=confirm]')", 5);
	run("document.querySelector('form[data-form=confirm]')"
	    ".requestSubmit()");
	wait_js("document.querySelector('form[data-form=host-key] "
	    ".fingerprints code') && document.querySelector('form[data-form="
	    "host-key] .fingerprints code').textContent.includes('SHA256:') "
	    "&& document.querySelector('pre.deploy-key').textContent."
	    "startsWith('ssh-ed25519 ')", 20);
	shot("1c-host-key");
	run("document.querySelector('form[data-form=host-key]')"
	    ".requestSubmit()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('built arcana-agent'))", 30);
	/* The console's own update is offered on the host it runs on. */
	ATF_CHECK(js_true("document.querySelector('.hostbar button[data-act="
	    "console-update]')"));
	/* What was built is the host's own build here: nothing to send. */
	wait_js("!document.querySelector('.hostbar button[data-act="
	    "agent-update]')", 10);

	/* A jail picked in the summary's graph opens in a box over it,
	 * and the page under it stays the summary. */
	run("document.querySelector('.topo .tnode[data-act=peek-jail]')"
	    ".click()");
	wait_js("document.querySelector('.peek-box .jail-page')", 5);
	ATF_CHECK(js_true("document.querySelector('.tiles .tile') && "
	    "document.querySelector('button.tab.on, button.tab.active, "
	    "button.tab[aria-selected=true]') !== undefined"));
	ATF_CHECK(js_true("document.querySelector('.peek-box button[data-act="
	    "address-add]')"));
	shot("1d-jail-overlay");
	run("document.querySelector('.peek-box .close').click()");
	wait_js("!document.querySelector('.peek-box')", 5);

	/*
	 * The page keeps itself current without being asked: a host is
	 * read again every few seconds while the page is in view.
	 */
	run("window.listed = 0; const of2 = window.fetch; window.fetch = "
	    "function (u, o) { if (String(u).endsWith('/jails')) "
	    "window.listed++; return of2.call(this, u, o); };");
	wait_js("window.listed >= 1", 15);

	/* The fleet page lists it, and leads back to it. */
	run("document.querySelector('.tree .titem.fleet').click()");
	wait_js("document.querySelector('.hosts .hostcard')", 5);
	/* In the fleet's graph too, a jail opens over the page. */
	run("document.querySelector('.topo .tnode[data-act=peek-jail]')"
	    ".click()");
	wait_js("document.querySelector('.peek-box .jail-page') && "
	    "document.querySelector('.hosts .hostcard')", 5);
	run("document.querySelector('.peek-box .close').click()");
	wait_js("!document.querySelector('.peek-box') && "
	    "document.querySelector('.hosts .hostcard')", 5);
	shot("2-fleet");
	run("document.querySelector('.hosts .hostcard').click()");
	wait_js("document.querySelector('.tree .titem.server.selected')", 5);
	run("document.querySelector('button.tab[data-arg=jails]').click()");
	wait_js("document.querySelector('#j-web.s-stopped')", 20);
	ATF_CHECK(js_true("document.querySelector('#j-db')"));
	/* Jails: those running first, by name within; by name when asked,
	 * and the other way round when asked again. */
	ATF_CHECK(js_true("document.querySelector('.sorts button.on')."
	    "dataset.arg === 'running'"));
	ATF_CHECK(js_true("document.querySelector('.grid > *').id === "
	    "'j-cache'"));
	run("document.querySelector('.sorts button[data-arg=name]').click()");
	run("document.querySelector('.sorts button[data-arg=name]').click()");
	wait_js("document.querySelector('.grid > *').id === 'j-web'", 5);
	run("document.querySelector('.sorts button[data-arg=running]')"
	    ".click()");
	wait_js("document.querySelector('.grid > *').id === 'j-cache'", 5);
	/* A change waits in the queue until it is sent. */
	ATF_CHECK(js_true("document.querySelector('button[data-act=queue].on')"));
	run("document.querySelector('#j-web button[data-act=start]').click()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	ATF_CHECK(js_true("document.querySelector('#j-web.s-stopped')"));
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("document.querySelector('.dock .last.o-ok') && "
	    "!document.querySelector('button[data-act=queue-run]')", 20);

	/* The tree and the dock are resized by dragging their edges; the
	 * browser keeps the sizes, and a double click drops them. */
	run("const drag = (sel, x, y) => { const h = document.querySelector("
	    "sel); h.dispatchEvent(new PointerEvent('pointerdown', { bubbles: "
	    "true, button: 0 })); window.dispatchEvent(new PointerEvent("
	    "'pointermove', { clientX: x, clientY: y })); window.dispatchEvent("
	    "new PointerEvent('pointerup', {})); }; "
	    "drag('.rail > .resizer', 400, 300); "
	    "drag('.dock > .resizer', 600, 200);");
	wait_js("Math.round(document.querySelector('.rail')."
	    "getBoundingClientRect().width) === 400 && Math.abs(document."
	    "querySelector('.dock-body').getBoundingClientRect().top - 200) < 3"
	    " && JSON.parse(localStorage.getItem('arc_sizes')).rail === 400", 5);
	shot("3a-resized");
	run("document.querySelector('.rail > .resizer').dispatchEvent("
	    "new MouseEvent('dblclick', { bubbles: true }));"
	    "document.querySelector('.dock > .resizer').dispatchEvent("
	    "new MouseEvent('dblclick', { bubbles: true }));");
	wait_js("Math.round(document.querySelector('.rail')."
	    "getBoundingClientRect().width) === 250 && "
	    "localStorage.getItem('arc_sizes') === '{}'", 5);

	/* The workflow and the raw output of jail(8): sending the queue
	 * opened the dock, and the graph fills in as the job runs. */
	wait_js("document.querySelector('.graph .node.k-exec')", 20);
	shot("3-jails-and-workflow");
	ATF_CHECK(js_true("document.querySelector('.graph .node.k-daemon')"));
	/* A step picked shows beside the graph, in view whatever the
	 * graph's length, and goes when closed. */
	run("document.querySelector('.graph .node.k-exec').click()");
	wait_js("document.querySelector('.trace-main.has-step .step-pane "
	    ".step-detail')", 5);
	ATF_CHECK(js_true("(() => { const p = document.querySelector("
	    "'.step-pane').getBoundingClientRect(), d = document.querySelector("
	    "'.dock').getBoundingClientRect(); return p.top >= d.top && "
	    "p.top < d.bottom - 40; })()"));
	shot("3b-step");
	run("document.querySelector('.step-pane .close').click()");
	wait_js("!document.querySelector('.step-pane .step-detail')", 5);
	/* Beside the operation, what it is on the wire: its request and
	 * reply as CBOR maps, and the sets they nest. */
	wait_js("document.querySelector('.schema pre.cddl')", 10);
	ATF_CHECK(js_true("(() => { const t = document.querySelector("
	    "'.schema').textContent; return t.includes('arcana') && "
	    "t.includes('command') && t.includes('request = {') && "
	    "t.includes('reply = {') && t.includes('=> uint') && "
	    "t.includes('; id'); })()"));
	shot("3c-schema");
	run("document.querySelector('.trace button[data-act=schema]').click()");
	wait_js("!document.querySelector('.step-pane')", 5);
	run("document.querySelector('.trace button[data-act=schema]').click()");
	wait_js("document.querySelector('.schema pre.cddl')", 5);
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
	/* Services: those running first, then those enabled; by name when
	 * asked, and the other way round when asked again. */
	run("document.querySelector('.jail-page button[data-act=close-drawer]')"
	    ".click()");
	run("document.querySelector('button.tab[data-arg=services]').click()");
	wait_js("document.querySelectorAll('.services .svc').length === 2", 20);
	ATF_CHECK(js_true("document.querySelector('.sorts button.on')."
	    "dataset.arg === 'running'"));
	ATF_CHECK(js_true("document.querySelector('.services .svc')."
	    "dataset.arg === 'sshd'"));
	run("document.querySelector('.sorts button[data-arg=name]').click()");
	wait_js("document.querySelector('.services .svc').dataset.arg === "
	    "'ntpd'", 5);
	run("document.querySelector('.sorts button[data-arg=name]').click()");
	wait_js("document.querySelector('.services .svc').dataset.arg === "
	    "'sshd'", 5);
	shot("6-services");

	/*
	 * A reading that takes its time is waited for once: leaving its
	 * tab and coming back does not ask again.  And it can be given
	 * up from the activity list.
	 */
	ATF_REQUIRE((fp = fopen("fake-pkg", "r")) != NULL);
	fclose(fp);
	ATF_REQUIRE(system("cp fake-pkg fake-pkg.fast && "
	    "{ echo '#!/bin/sh'; echo 'sleep 3'; echo 'exec ./fake-pkg.fast "
	    "\"$@\"'; } > fake-pkg.slow && chmod +x fake-pkg.slow && "
	    "mv fake-pkg.slow fake-pkg") == 0);
	run("window.pkgAsked = 0; const of = window.fetch; window.fetch = "
	    "function (u, o) { if (String(u).includes('/packages')) "
	    "window.pkgAsked++; return of.call(this, u, o); };");
	run("document.querySelector('button.tab[data-arg=packages]').click()");
	wait_js("window.pkgAsked === 1", 5);
	run("document.querySelector('button.tab[data-arg=jails]').click()");
	run("document.querySelector('button.tab[data-arg=packages]').click()");
	run("document.querySelector('button.tab[data-arg=summary]').click()");
	run("document.querySelector('button.tab[data-arg=packages]').click()");
	ATF_CHECK(js_true("window.pkgAsked === 1"));
	/* Given up: the entry ends as cancelled, and the tab says so. */
	run("document.querySelector('.dock > header').click()");
	wait_js("document.querySelector('.ops button[data-act=op-cancel]')", 5);
	shot("6a-cancel");
	run("document.querySelector('.ops button[data-act=op-cancel]').click()");
	wait_js("!document.querySelector('.ops button[data-act=op-cancel]') && "
	    "document.querySelector('.ops .op.o-failed')", 5);
	run("document.querySelector('.dock > header').click()");
	ATF_REQUIRE(system("mv fake-pkg.fast fake-pkg") == 0);

	/* The interfaces, in the network tab: an address is added to one
	 * through the queue, as any change is. */
	run("document.querySelector('button.tab[data-arg=network]').click()");
	wait_js("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=interfaces]')", 10);
	run("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=interfaces]').click()");
	wait_js("document.querySelector('table.ifaces tr[data-if=lo0] .chip')",
	    20);
	shot("7-interfaces");
	run("document.querySelector('tr[data-if=lo0] button[data-act="
	    "if-addr-add]').click()");
	wait_js("document.querySelector('form[data-form=if-address]')", 5);
	run("const f = document.querySelector('form[data-form=if-address]'); "
	    "f.address.value = '10.9.0.7/24'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('lo0: add 10.9.0.7/24: done'))", 20);
	ATF_CHECK(system("grep -q '^lo0 inet 10.9.0.7/24 alias$' ifconfig.log")
	    == 0);
	run("document.querySelector('.dock > header').click()");

	/* A static route, from the routes table: asked for in a dialog,
	 * queued, and run with route(8). */
	run("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=routes]').click()");
	wait_js("document.querySelector('button[data-act=route-add]')", 10);
	run("document.querySelector('button[data-act=route-add]').click()");
	wait_js("document.querySelector('form[data-form=route]')", 5);
	run("const f = document.querySelector('form[data-form=route]'); "
	    "f.destination.value = '10.88.0.0/16'; f.gateway.value = "
	    "'10.0.0.1'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('route add 10.88.0.0/16 via 10.0.0.1: "
	    "done'))", 20);
	ATF_CHECK(system("grep -q '^-n add -inet 10.88.0.0/16 10.0.0.1$' "
	    "route.log") == 0);
	run("document.querySelector('.dock > header').click()");

	/* The host's own record of jobs has the start that was done. */
	run("document.querySelector('button.tab[data-arg=jails]').click()");
	run("document.querySelector('#j-db').click()");
	wait_js("document.querySelector('.jail-page')", 5);
	run("document.querySelector('.jail-page button[data-act=close-drawer]')"
	    ".click()");
	run("document.querySelector('button.tab[data-arg=jobs]').click()");
	wait_js("document.querySelector('table.jobs tr.j-done')", 10);
	shot("5-jobs");

	/*
	 * On a phone: nothing is wider than the screen, on any of the
	 * pages, and what is pressed is large enough to press.
	 */
	phone(true);
	{
		static const char *tabs[] = { "summary", "jails", "services",
		    "network", "packages", "jobs" };
		char name[32];
		size_t t;

		for (t = 0; t < 6; t++) {
			snprintf(script, sizeof(script), "document.querySelector("
			    "'button.tab[data-arg=%s]').click()", tabs[t]);
			run(script);
			usleep(700000);
			snprintf(name, sizeof(name), "m%zu-%s", t, tabs[t]);
			shot(name);
			ATF_CHECK_MSG(js_true("document.documentElement."
			    "scrollWidth <= window.innerWidth + 1"),
			    "the %s tab is wider than a phone", tabs[t]);
		}
	}
	/* The tree is one line until unfolded, and folds again when
	 * something in it is picked. */
	ATF_CHECK(js_true("getComputedStyle(document.querySelector('.tree'))"
	    ".display === 'none'"));
	run("document.querySelector('button[data-act=rail-toggle]').click()");
	wait_js("getComputedStyle(document.querySelector('.tree')).display "
	    "!== 'none'", 5);
	shot("m5a-tree");
	run("document.querySelector('.tree .titem.fleet').click()");
	wait_js("getComputedStyle(document.querySelector('.tree')).display "
	    "=== 'none' && document.querySelector('.hosts .hostcard')", 5);
	usleep(500000);
	shot("m6-fleet");
	/* Every control of the top bar can be reached. */
	ATF_CHECK(js_true("(() => { const b = document.querySelector("
	    "'button[data-act=logout]'); b.scrollIntoView(); const r = "
	    "b.getBoundingClientRect(); return r.left >= 0 && r.right <= "
	    "innerWidth + 1; })()"));
	ATF_CHECK(js_true("document.documentElement.scrollWidth <= "
	    "window.innerWidth + 1"));
	run("document.querySelector('.dock > header').click()");
	usleep(500000);
	shot("m7-activity");
	run("document.querySelector('.dock > header').click()");
	run("document.querySelector('button[data-act=settings]').click()");
	wait_js("document.querySelector('form[data-form=settings] input')", 10);
	shot("m8-settings");
	/* A theme is picked there, takes at once, and is kept. */
	run("document.querySelector('button.theme[data-arg=amber]').click()");
	wait_js("document.documentElement.dataset.theme === 'amber' && "
	    "localStorage.getItem('arc_theme') === 'amber' && "
	    "getComputedStyle(document.documentElement).getPropertyValue("
	    "'--cyan').trim() === '#ffb547'", 5);
	shot("m9-amber");
	run("document.querySelector('button.theme[data-arg=paper]').click()");
	wait_js("document.documentElement.dataset.theme === 'paper'", 5);
	shot("m10-paper");
	run("document.querySelector('button.theme[data-arg=\"\"]').click()");
	wait_js("!document.documentElement.dataset.theme && "
	    "localStorage.getItem('arc_theme') === null", 5);
	run("document.querySelector('.modal button[data-act=close]').click()");
	run("document.querySelector('.hosts .hostcard').click()");
	phone(false);

	/*
	 * Two hosts with a service of the same name: an action on the one
	 * leaves the other's alone.  The second host here is the same
	 * agent, reached by another name of its socket.
	 */
	ATF_REQUIRE(symlink("jgd.sock", "jgd2.sock") == 0);
	run("document.querySelector('button[data-act=add-server]').click()");
	wait_js("document.querySelector('form[data-form=add-server]')", 5);
	snprintf(script, sizeof(script), "const f = document.querySelector("
	    "'form[data-form=add-server]'); f.name.value = 'lab2'; f.uri.value "
	    "= 'unix:%s/jgd2.sock'; f.requestSubmit();", cwd);
	run(script);
	wait_js("document.querySelector('.tree .titem.server.selected .name') "
	    "&& document.querySelector('.tree .titem.server.selected .name')"
	    ".textContent === 'lab2'", 20);
	ATF_REQUIRE((fp = fopen("slow", "w")) != NULL);
	fclose(fp);
	run("document.querySelector('button.tab[data-arg=services]').click()");
	wait_js("document.querySelector('.svc[data-arg=sshd] button"
	    "[data-value=restart]')", 20);
	run("document.querySelector('.svc[data-arg=sshd] button"
	    "[data-value=restart]').click()");
	wait_js("document.querySelector('form[data-form=confirm]')", 5);
	run("document.querySelector('form[data-form=confirm]')"
	    ".requestSubmit()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("document.querySelector('.svc[data-arg=sshd] button"
	    "[disabled]')", 10);
	run("document.querySelectorAll('.tree .titem.server')[0].click()");
	wait_js("document.querySelector('.tree .titem.server.selected .name')"
	    ".textContent === 'lab' && document.querySelector("
	    "'.svc[data-arg=sshd] button[data-value=restart]')", 20);
	ATF_CHECK_MSG(!js_true("document.querySelector('.svc[data-arg=sshd] "
	    "button[disabled]')"), "sshd on lab is held by lab2's action");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('service sshd restart: done'))", 20);
	(void)unlink("slow");
	run("document.querySelector('.dock > header').click()");

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

	/*
	 * A newer shell on the console: the page finds it when it comes
	 * back into view, takes it and loads itself again, still logged
	 * in, and what it shows is the new files, not copies it kept.
	 */
	ATF_REQUIRE((fp = fopen("www-copy/style.css", "a")) != NULL);
	fprintf(fp, "\n/* v2 */\n");
	fclose(fp);
	ATF_REQUIRE(system("sed -i '' 's/const CACHE = \"arcana-/const CACHE "
	    "= \"arcana-2-/' www-copy/sw.js") == 0);
	run("window.before = true; "
	    "document.dispatchEvent(new Event('visibilitychange'));");
	wait_js("window.before === undefined && "
	    "document.querySelector('.shell')", 40);
	run("fetch('style.css').then(r => r.text()).then(t => { "
	    "window.v2 = t.includes('/* v2 */'); });");
	wait_js("window.v2 === true", 10);
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
