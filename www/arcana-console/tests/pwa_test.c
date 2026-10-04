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
	int		 i;

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
	run("window.subbed = false; fetch('/api/push/subscribe', { method: "
	    "'POST', headers: { 'Content-Type': 'application/json', "
	    "'X-Arcana': '1' }, body: JSON.stringify({ endpoint: "
	    "'https://push.example.org/x', p256dh: 'BCVxsr7N_eNgVRqvHtD0zTZsEc"
	    "6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4', "
	    "auth: 'BTBZMqHH6r4Tts7J_aSIgg', name: 'Chrome on Android' }) })"
	    ".then(r => { window.subbed = r.ok; });");
	wait_js("window.subbed", 10);
	run("document.querySelector('button[data-act=settings]').click()");
	wait_js("document.querySelector('form[data-form=settings] "
	    "input[name=agent_source]')", 10);
	ATF_CHECK(js_true("document.querySelector('form.settings dl.kv')."
	    "textContent.includes('localhost')"));
	/* A device that subscribed to be told of tasks is listed, and
	 * taken off with its cross. */
	wait_js("document.querySelector('ul.devices li .name') && document."
	    "querySelector('ul.devices').textContent.includes('Chrome on "
	    "Android')", 10);
	ATF_CHECK(js_true("document.querySelector('ul.devices').textContent"
	    ".includes('push.example.org')"));
	/*
	 * What is typed in a field stays there when the box is drawn
	 * again under it, as it is when the list of devices changes or
	 * their age does: the key's path typed first is still there when
	 * the form is sent, and is what the console keeps.
	 */
	run("const f = document.querySelector('form[data-form=settings]'); "
	    "f.agent_ssh_key.value = '/usr/local/etc/arcana/id_ed25519'; "
	    "f.update_check.checked = !f.update_check.checked; "
	    "window.wasChecked = f.update_check.checked;");
	run("document.querySelector('ul.devices button[data-act=push-remove]')"
	    ".click()");
	wait_js("document.querySelector('ul.devices').textContent.includes("
	    "'No device yet')", 10);
	ATF_CHECK_MSG(js_true("document.querySelector('form[data-form="
	    "settings]').agent_ssh_key.value === "
	    "'/usr/local/etc/arcana/id_ed25519'"), "what was typed was lost "
	    "when the box was drawn again");
	ATF_CHECK(js_true("document.querySelector('form[data-form=settings]')"
	    ".update_check.checked === window.wasChecked"));
	shot("0a-settings");
	run("const f = document.querySelector('form[data-form=settings]'); "
	    "f.update_check.checked = !f.update_check.checked; "
	    "f.agent_source.value = 'git@git.example.org:me/arcana.git'; "
	    "f.requestSubmit();");
	wait_js("!document.querySelector('form[data-form=settings]') && "
	    "[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('Settings saved'))", 10);
	ATF_CHECK(system("grep -q '/usr/local/etc/arcana/id_ed25519' "
	    "data/settings.json") == 0);
	/* There is no such key here: the builds below use the host's own. */
	run("window.unset = false; fetch('/api/settings', { method: 'POST', "
	    "headers: { 'Content-Type': 'application/json', 'X-Arcana': '1' }, "
	    "body: JSON.stringify({ set: { agent_ssh_key: '' } }) }).then(r => "
	    "{ window.unset = r.ok; });");
	wait_js("window.unset", 10);

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
	wait_js("document.querySelectorAll('.tree .titem.leaf').length === 4 "
	    "&& localStorage.getItem('arc_open').includes('\"')", 5);
	run("document.querySelector('.tree button[data-act=fold]').click()");
	wait_js("!document.querySelector('.tree .titem.leaf') && "
	    "localStorage.getItem('arc_open') === '[]'", 5);
	run("document.querySelector('.tree button[data-act=fold]').click()");
	wait_js("document.querySelectorAll('.tree .titem.leaf').length === 4",
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
	    "length === 4 && document.querySelector('.tree .titem.more')."
	    "textContent.includes('fewer')", 5);
	run("document.querySelector('.tree .titem.more').click()");
	ucl_object_unref(wd("POST", "/session/window/rect",
	    "{\"width\":1280,\"height\":800}"));
	wait_js("!document.querySelector('.tree .titem.more') && "
	    "document.querySelectorAll('.tree .titem.leaf').length === 4", 5);
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

	/*
	 * The route to an address, looked up on the host: what it takes,
	 * in a box over the table.  And an interface's traffic and its
	 * MTU, in the interfaces.
	 */
	run("const i = document.querySelector('#filter'); i.value = "
	    "'10.77.5.5'; i.dispatchEvent(new Event('input', { bubbles: true "
	    "}));");
	run("document.querySelector('button[data-act=net-lookup]').click()");
	wait_js("document.querySelector('.notice.lookup') && document."
	    "querySelector('.notice.lookup').textContent.includes('10.0.0.1')",
	    10);
	shot("7a-lookup");
	run("document.querySelector('button[data-act=net-lookup-clear]')"
	    ".click()");
	run("const i = document.querySelector('#filter'); i.value = ''; "
	    "i.dispatchEvent(new Event('input', { bubbles: true }));");
	run("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=interfaces]').click()");
	wait_js("document.querySelector('tr[data-if=lo0] button[data-act="
	    "if-edit]')", 20);
	run("document.querySelector('tr[data-if=lo0] button[data-act=if-edit]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=if-set]')", 5);
	run("const f = document.querySelector('form[data-form=if-set]'); "
	    "f.mtu.value = '9000'; f.persist.checked = false; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('lo0: set: done'))", 20);
	ATF_CHECK(system("grep -q '^lo0 mtu 9000$' ifconfig.log") == 0);
	run("document.querySelector('.dock > header').click()");

	/* Netgraph: the nodes as a graph, with the hooks that join them. */
	run("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=netgraph]').click()");
	wait_js("document.querySelectorAll('.ngmap .tnode').length === 2 && "
	    "document.querySelector('.ngmap .tlink .lbl')", 20);
	ATF_CHECK(js_true("document.querySelector('.ngmap .tlink .lbl')."
	    "textContent.includes('lower')"));
	run("window.ptr = (el, type, x, y) => { const r = el."
	    "getBoundingClientRect(); (type === 'pointerdown' ? el : document)"
	    ".dispatchEvent(new PointerEvent(type, { bubbles: true, button: "
	    "0, clientX: x === undefined ? r.x + r.width / 2 : x, clientY: "
	    "y === undefined ? r.y + r.height / 2 : y })); };");
	run("const n = document.querySelector('.ngmap .tnode .box'); "
	    "ptr(n, 'pointerdown'); ptr(n, 'pointerup');");
	wait_js("document.querySelector('.ngmap .tnode.sel') && document."
	    "querySelector('.ngmap button[data-act=ng-rmhook]')", 5);
	shot("7b-netgraph");

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
	run("document.querySelector('button.theme[data-arg=onyx]').click()");
	wait_js("document.documentElement.dataset.theme === 'onyx' && "
	    "getComputedStyle(document.documentElement).getPropertyValue("
	    "'--cyan').trim() === '#e5484d' && !getComputedStyle(document.body)"
	    ".fontFamily.startsWith('\"JetBrains')", 5);
	shot("m9a-onyx");
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

	/*
	 * A jail with a network of its own: its page shows that network,
	 * read through the host, and a change made there is made in the
	 * jail, and kept in the jail's own rc.conf.
	 */
	run("const m = document.querySelector('.tree .titem.more'); if (m && "
	    "!m.textContent.includes('fewer')) m.click();");
	wait_js("[...document.querySelectorAll('.tree .titem.leaf')].some(l => "
	    "l.dataset.arg === 'gw')", 10);
	run("[...document.querySelectorAll('.tree .titem.leaf')].find(l => "
	    "l.dataset.arg === 'gw').click()");
	wait_js("document.querySelector('.jail-page .jail-net table.ifaces "
	    "tr[data-if=epair1b] .chip')", 20);
	ATF_CHECK(js_true("document.querySelector('.jail-net').textContent"
	    ".includes('10.99.0.2/24') && !document.querySelector('.jail-net "
	    "tr[data-if=lo0]')"));
	shot("7g-vnet-jail");
	run("document.querySelector('.jail-net tr[data-if=epair1b] button"
	    "[data-act=if-addr-add]').click()");
	wait_js("document.querySelector('form[data-form=if-address]')", 5);
	run("const f = document.querySelector('form[data-form=if-address]'); "
	    "f.address.value = '10.99.0.7/24'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('gw: epair1b: add 10.99.0.7/24: done'))",
	    20);
	ATF_CHECK(system("grep -q '^-j 4 epair1b inet 10.99.0.7/24 alias$' "
	    "ifconfig.log && grep -q '10.99.0.7/24' jroot/etc/rc.conf && "
	    "! grep -q 10.99.0.7 rc.conf") == 0);
	run("document.querySelector('.dock > header').click()");
	/*
	 * An interface from the host: a new epair, made there, whose b
	 * end the jail gets; the host does it, not told to work in the
	 * jail.  And one the jail has, taken back to the host.
	 */
	run("document.querySelector('.jail-net button[data-act=if-vnet-give]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=if-vnet] input[name="
	    "persist]')", 5);
	shot("7h-vnet-give");
	run("document.querySelector('form[data-form=if-vnet]')."
	    "requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('give epair to gw'))", 20);
	for (i = 0; i < 100 && system("grep -q '^epair create$' ifconfig.log")
	    != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^epair create$' ifconfig.log && ! grep -q "
	    "'^-j 4 epair create' ifconfig.log") == 0);
	wait_js("document.querySelector('.jail-net tr[data-if=epair1b] button"
	    "[data-act=if-vnet-back]')", 20);
	run("document.querySelector('.jail-net tr[data-if=epair1b] button"
	    "[data-act=if-vnet-back]').click()");
	wait_js("document.querySelector('form[data-form=confirm]')", 5);
	run("document.querySelector('form[data-form=confirm]')"
	    ".requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('take epair1b back from gw: done'))", 20);
	ATF_CHECK(system("grep -q '^epair1b -vnet 4$' ifconfig.log") == 0);
	wait_js("document.querySelector('.jail-net button[data-act=net-kind]"
	    "[data-arg=routes]')", 20);
	/* Its routes, by the host's netstat told which jail. */
	run("document.querySelector('.jail-net button[data-act=net-kind]"
	    "[data-arg=routes]').click()");
	wait_js("document.querySelector('.jail-net button[data-act=route-add]')",
	    10);
	run("document.querySelector('li[data-act=select-server]').click()");
	wait_js("document.querySelector('button.tab[data-arg=network]')", 10);

	/*
	 * WireGuard, in a host's network tab: an interface without a key
	 * is given one, made on the host, and then a peer.  And BIRD: its
	 * protocols, one of them reloaded.
	 */
	/* They are plugins, installed on the host: each a tab of its own,
	 * not among what the Network tab has of the base system. */
	run("document.querySelector('button.tab[data-arg=network]').click()");
	wait_js("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=interfaces]')", 10);
	ATF_CHECK(js_true("!document.querySelector('button[data-act=net-kind]"
	    "[data-arg=wireguard]') && !document.querySelector('button"
	    "[data-act=net-kind][data-arg=bird]') && document.querySelector("
	    "'button.tab.plugin[data-arg=bird]')"));
	run("document.querySelector('button.tab.plugin[data-arg=wireguard]')"
	    ".click()");
	wait_js("document.querySelector('button.tab.plugin[data-arg=wireguard]"
	    ".on') && !document.querySelector('button.tab[data-arg=network]"
	    ".on') && !document.querySelector('button[data-act=net-kind]')",
	    10);
	wait_js("document.querySelector('.pane.wg button[data-act=wg-init]')",
	    20);
	ATF_CHECK(js_true("document.querySelector('.pane.wg').textContent."
	    "includes('no key yet')"));
	run("document.querySelector('.pane.wg button[data-act=wg-init]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=wg-init]')", 5);
	run("const f = document.querySelector('form[data-form=wg-init]'); "
	    "f.port.value = '51820'; f.persist.checked = false; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("document.querySelector('.pane.wg code.key') && document."
	    "querySelector('.pane.wg code.key').textContent.startsWith('HIgo')",
	    20);
	run("document.querySelector('.pane.wg button[data-act=wg-peer-add]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=wg-peer]')", 5);
	run("const f = document.querySelector('form[data-form=wg-peer]'); "
	    "f.peer.value = 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg='; "
	    "f.endpoint.value = '192.0.2.9:51820'; f.allowed.value = "
	    "'10.9.9.2/32, fd00::2/128'; f.persist.checked = false; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("document.querySelector('.pane.wg button[data-act=wg-unpeer]')",
	    20);
	ATF_CHECK(system("grep -q '^set wg0 peer xTIBA5rboUvnH4htodjb6e697QjLER"
	    "t1NAB4mZqp8Dg= endpoint 192.0.2.9:51820 allowed-ips 10.9.9.2/32,"
	    "fd00::2/128$' wg.log") == 0);
	run("document.querySelector('.dock > header').click()");
	shot("7c-wireguard");
	run("document.querySelector('button.tab.plugin[data-arg=bird]')"
	    ".click()");
	wait_js("document.querySelectorAll('table.bird tbody tr').length === 4",
	    20);
	ATF_CHECK(js_true("document.querySelector('.pane.bird').textContent."
	    "includes('Router ID is 192.0.2.1')"));
	run("[...document.querySelectorAll('table.bird button[data-act="
	    "bird-verb][data-arg=reload]')].find(b => b.dataset.value === "
	    "'bgp_core').click()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('bird reload bgp_core: done'))", 20);
	ATF_CHECK(system("grep -q '^reload bgp_core$' birdc.log") == 0);
	run("document.querySelector('.dock > header').click()");
	/*
	 * Its neighbours drawn around it: two BGP ones, an OSPF one, an
	 * RPKI cache.  And the parts of its configuration, once read.
	 */
	wait_js("document.querySelectorAll('.birdmap .tnode.peer').length === 4 "
	    "&& document.querySelector('.birdmap .tnode.peer.ospf') && "
	    "document.querySelector('.birdmap .tnode.peer.rpki')", 10);
	wait_js("[...document.querySelectorAll('.conf-grid ul.blocks li b')]"
	    ".some(b => b.textContent === 'bgp_in') && [...document."
	    "querySelectorAll('.conf-grid ul.blocks li')].some(l => "
	    "l.textContent.includes('CUSTOMERS') && l.textContent.includes("
	    "'communities')) && [...document.querySelectorAll('.conf-grid "
	    "ul.blocks li')].some(l => l.textContent.includes('BLACKHOLE_LC') "
	    "&& l.textContent.includes('large communities'))", 20);
	shot("7d-bird");
	/*
	 * BIRD's routes: asked for by an address, with what they carry;
	 * the one in use marked, the other shown beside it.
	 */
	run("const f = document.querySelector('form[data-form=bird-routes]'); "
	    "f.q.value = '10.1.2.3'; f.all.checked = true; f.requestSubmit();");
	wait_js("document.querySelectorAll('table.broutes tbody tr.best')."
	    "length === 1 && document.querySelectorAll('table.broutes tbody "
	    "tr.other').length === 1", 20);
	ATF_CHECK(js_true("document.querySelector('table.broutes').textContent"
	    ".includes('10.1.0.0/16') && document.querySelector('table.broutes "
	    "tr.attrs').textContent.includes('BGP.large_community: (65001, 1, "
	    "100)') && document.querySelector('table.broutes').textContent"
	    ".includes('198.51.100.7')"));
	ATF_CHECK(system("grep -q '^-r show route for 10.1.2.3 all$' birdc.log")
	    == 0);
	shot("7d-bird-routes");
	/* A table that is the whole Internet is counted, not carried. */
	run("const f = document.querySelector('form[data-form=bird-routes]'); "
	    "f.q.value = ''; f.all.checked = false; f.proto.value = 'bgp_core'; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('form.bird-routes + .notice.bad') && "
	    "document.querySelector('form.bird-routes + .notice.bad')."
	    "textContent.includes('845233 routes')", 20);
	/*
	 * A change to the configuration is made in safe mode unless that
	 * is turned off: the steps here follow each other faster than a
	 * change is confirmed, so it is off until its own step below.
	 */
	run("document.querySelector('button[data-act=bird-safe]').click()");
	wait_js("document.querySelector('button[data-act=bird-safe]')."
	    "textContent.includes('off')", 5);
	/* A neighbour picked opens in a box: what the daemon says of it,
	 * and the part of the configuration that makes it. */
	run("document.querySelector('.birdmap .tnode.peer.bgp').dispatchEvent("
	    "new MouseEvent('click', { bubbles: true }))");
	wait_js("document.querySelector('form[data-form=bird-block] textarea') "
	    "&& document.querySelector('form[data-form=bird-block] textarea')"
	    ".value.includes('neighbor 192.0.2.1 as 65001')", 5);
	ATF_CHECK(js_true("document.querySelector('.modal dl.kv').textContent"
	    ".includes('65001') && document.querySelector('.modal table.net')"
	    ".textContent.includes('bgp_out')"));
	shot("7e-bird-neighbour");
	run("const t = document.querySelector('form[data-form=bird-block] "
	    "textarea'); t.value = t.value.replace('Core uplink', 'Core uplink, "
	    "east'); t.form.requestSubmit();");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('BIRD has its new configuration')) && "
	    "!document.querySelector('.modal')", 20);
	ATF_CHECK(system("grep -q 'description \"Core uplink, east\";' "
	    "bird/bird.conf && grep -q '^configure$' birdc.log && grep -q "
	    "'filter bgp_in' bird/bird.conf") == 0);
	/* What bird refuses does not stay, and what was typed is kept. */
	run("[...document.querySelectorAll('.conf-grid ul.blocks li')].find("
	    "l => l.querySelector('b').textContent === 'bgp_in').click()");
	wait_js("document.querySelector('form[data-form=bird-block] textarea')",
	    5);
	run("const t = document.querySelector('form[data-form=bird-block] "
	    "textarea'); t.value = 'filter bgp_in {\\n\\tBROKEN\\n}'; "
	    "t.form.requestSubmit();");
	wait_js("document.querySelector('.modal .err') && document."
	    "querySelector('.modal .err').textContent.includes('syntax error')",
	    20);
	ATF_CHECK(js_true("document.querySelector('form[data-form=bird-block] "
	    "textarea').value.includes('BROKEN')"));
	ATF_CHECK(system("grep -q BROKEN bird/bird.conf") != 0);
	run("document.querySelector('.modal button[data-act=close]').click()");
	/* A community set, as a list: an entry more. */
	run("[...document.querySelectorAll('.conf-grid ul.blocks li')].find("
	    "l => l.querySelector('b').textContent === 'CUSTOMERS').click()");
	wait_js("document.querySelector('form[data-form=bird-set] textarea') "
	    "&& document.querySelector('form[data-form=bird-set] textarea')"
	    ".value === '(65000,100)\\n(65000,200)'", 5);
	shot("7f-bird-communities");
	run("const t = document.querySelector('form[data-form=bird-set] "
	    "textarea'); t.value += '\\n(65000, 300..399)'; "
	    "t.form.requestSubmit();");
	wait_js("!document.querySelector('.modal') && [...document."
	    "querySelectorAll('.conf-grid ul.blocks li')].some(l => "
	    "l.textContent.includes('300..399'))", 20);
	ATF_CHECK(system("grep -q '(65000, 300..399)' bird/bird.conf && "
	    "grep -q '^define CUSTOMERS = \\[$' bird/bird.conf") == 0);
	/* A set of large communities, new. */
	run("document.querySelector('button[data-act=bird-new][data-arg=lset]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=bird-set]')", 5);
	run("const f = document.querySelector('form[data-form=bird-set]'); "
	    "f.name.value = 'PEERS_LC'; f.text.value = '(65000, 1, *)'; "
	    "f.requestSubmit();");
	wait_js("!document.querySelector('.modal') && [...document."
	    "querySelectorAll('.conf-grid ul.blocks li')].some(l => "
	    "l.textContent.includes('PEERS_LC'))", 20);
	/* An RPKI cache: its tables, its protocol, and the function that
	 * filters ask. */
	run("document.querySelector('button[data-act=bird-new][data-arg=rpki]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=bird-rpki]')", 5);
	run("const f = document.querySelector('form[data-form=bird-rpki]'); "
	    "f.host.value = 'rtr.example.org'; f.requestSubmit();");
	wait_js("!document.querySelector('.modal') && [...document."
	    "querySelectorAll('.conf-grid ul.blocks li b')].some(b => "
	    "b.textContent === 'rpki_invalid')", 20);
	ATF_CHECK(system("grep -q 'remote \"rtr.example.org\" port 3323;' "
	    "bird/bird.conf && grep -q '^roa6 table r6;$' bird/bird.conf && "
	    "test \"$(grep -c '^roa4 table r4;$' bird/bird.conf)\" = 1 && "
	    "grep -q 'protocol rpki rpki2' bird/bird.conf && grep -q "
	    "'define PEERS_LC' bird/bird.conf") == 0);
	/*
	 * A neighbour's filter is chosen from the filters there are, and
	 * written into its part of the configuration.  In safe mode BIRD
	 * is told to take the change back by itself, and the page, still
	 * reaching the host a while after, says that it stays.
	 */
	run("document.querySelector('button[data-act=bird-safe]').click()");
	wait_js("document.querySelector('button[data-act=bird-safe]')."
	    "textContent.includes('on')", 5);
	run("document.querySelector('.birdmap .tnode.peer.bgp').dispatchEvent("
	    "new MouseEvent('click', { bubbles: true }))");
	wait_js("document.querySelector('form[data-form=bird-block] select"
	    "[name=export_ipv4]')", 10);
	ATF_CHECK(js_true("[...document.querySelector('select[name=import_ipv4]"
	    "').options].map(o => o.value).join('|') === '|all|none|filter "
	    "bgp_out'"));
	shot("7f-bird-filter-list");
	run("const f = document.querySelector('form[data-form=bird-block]'); "
	    "f.export_ipv4.value = 'none'; f.import_ipv4.value = 'filter "
	    "bgp_out'; f.requestSubmit();");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('takes it back unless the host is still "
	    "reached'))", 20);
	ATF_CHECK(system("grep -q '^\t\timport filter bgp_out;$' bird/bird.conf "
	    "&& grep -q '^\t\texport none;$' bird/bird.conf && ! grep -q "
	    "'export filter bgp_out' bird/bird.conf && grep -q '^configure "
	    "timeout 60$' birdc.log") == 0);
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('BIRD keeps its new configuration'))", 30);
	ATF_CHECK(system("grep -q '^configure confirm$' birdc.log") == 0);
	/* Routes a neighbour sent, from its box. */
	run("[...document.querySelectorAll('table.bird tbody tr')].find(r => "
	    "r.textContent.includes('bgp_edge')).click()");
	wait_js("document.querySelector('.modal button[data-act=bird-routes-of]"
	    "')", 10);
	run("document.querySelector('.modal button[data-act=bird-routes-of]"
	    "[data-arg=protocol]').click()");
	wait_js("!document.querySelector('.modal') && document.querySelector("
	    "'table.broutes tbody tr.best')", 20);
	ATF_CHECK(system("grep -q '^-r show route protocol bgp_edge$' birdc.log")
	    == 0);

	/*
	 * The kernel: the files linked into it with the modules each
	 * holds, what its memory went to, a module loaded and one
	 * unloaded, kept in rc.conf's kld_list or taken out of it.
	 */
	run("document.querySelector('button.tab[data-arg=kernel]').click()");
	wait_js("document.querySelector('table.kmods tr[data-kld=kernel]') && "
	    "document.querySelectorAll('table.kmem tbody tr').length > 3", 20);
	ATF_CHECK(js_true("!document.querySelector('table.kmods tr[data-kld="
	    "kernel] button[data-act=kmod-unload]') && document.querySelector("
	    "'.facts.kmem').textContent.includes('kernel memory in use') && "
	    "document.querySelectorAll('#kmods option').length > 0"));
	shot("7i-kernel");
	run("document.querySelector('button[data-act=kmem][data-arg=zones]')"
	    ".click()");
	wait_js("document.querySelector('table.kmem thead').textContent."
	    "includes('Item size')", 5);
	run("const f = document.querySelector('form[data-form=kmod-load]'); "
	    "f.name.value = 'sctp'; f.persist.checked = true; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('kldload sctp: done'))", 20);
	ATF_CHECK(system("grep -q '^kldload -n sctp$' kld.log && grep -q "
	    "'^kld_list=\"sctp\"$' rc.conf") == 0);
	/* Kept, and not in this kernel: said. */
	wait_js("document.querySelector('.notice.info') && document."
	    "querySelector('.notice.info').textContent.includes('sctp')", 20);
	run("document.querySelector('.dock > header').click()");
	/* One that is in is unloaded once its name is typed. */
	run("window.kld = [...document.querySelectorAll('table.kmods button"
	    "[data-act=kmod-unload]')][0].dataset.arg; document.querySelector("
	    "'table.kmods button[data-act=kmod-unload]').click()");
	wait_js("document.querySelector('form[data-form=confirm] input')", 5);
	run("const f = document.querySelector('form[data-form=confirm]'); "
	    "const i = f.querySelector('input'); i.value = window.kld; "
	    "i.dispatchEvent(new Event('input', { bubbles: true })); "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('kldunload ' + window.kld))", 20);
	ATF_CHECK(system("grep -q '^kldunload ' kld.log") == 0);
	run("document.querySelector('.dock > header').click()");

	/*
	 * The network: every host a node of a map, joined to the others
	 * as its interfaces join it.  Both agents here read the same
	 * machine, so they share its networks.
	 */
	run("window.ptr = (el, type, x, y) => { const r = el."
	    "getBoundingClientRect(); (type === 'pointerdown' ? el : document)"
	    ".dispatchEvent(new PointerEvent(type, { bubbles: true, button: "
	    "0, clientX: x === undefined ? r.x + r.width / 2 : x, clientY: "
	    "y === undefined ? r.y + r.height / 2 : y })); };");
	run("document.querySelector('li[data-act=select-network]').click()");
	wait_js("document.querySelectorAll('svg.topo .tnode.up').length === 2",
	    30);
	wait_js("document.querySelector('.map-panel .facts')", 10);
	shot("8-network");
	/* A host is picked: its interfaces, with their addresses. */
	run("const n = document.querySelector('svg.topo .tnode .box'); "
	    "ptr(n, 'pointerdown'); ptr(n, 'pointerup');");
	wait_js("document.querySelector('svg.topo .tnode.sel') && document."
	    "querySelector('.map-panel .iflist li')", 5);
	ATF_CHECK(js_true("document.querySelector('.map-panel .iflist')."
	    "textContent.includes('lo0')"));
	/* And dragged: it is where it was put, and stays there. */
	run("window.was = document.querySelector('svg.topo .tnode')."
	    "getAttribute('transform'); const n = document.querySelector("
	    "'svg.topo .tnode .box'), r = n.getBoundingClientRect(); "
	    "ptr(n, 'pointerdown'); ptr(n, 'pointermove', r.x + 150, r.y + "
	    "90);");
	wait_js("document.querySelector('svg.topo .tnode').getAttribute("
	    "'transform') !== window.was", 5);
	run("const r = document.querySelector('svg.topo .tnode .box')."
	    "getBoundingClientRect(); ptr(document.body, 'pointerup', r.x + "
	    "10, r.y + 10);");
	wait_js("(localStorage.getItem('arc_topo') || '').split('\\n')."
	    "length >= 2", 5);
	/* The traffic of an interface, once it was read twice. */
	wait_js("document.querySelector('.map-panel svg.bw path.in')", 30);
	shot("8a-host-panel");
	/* Nothing picked: the fleet's traffic; and the jails, when asked. */
	run("document.querySelector('button[data-act=topo-unselect]').click()");
	run("document.querySelector('button[data-act=topo-jails]').click()");
	wait_js("document.querySelector('button[data-act=topo-jails].on') && "
	    "document.querySelector('.map-panel .io-now')", 30);
	/*
	 * Routing on the map: the BGP and OSPF neighbours that are not
	 * hosts of this console, beside the host that speaks to them; and
	 * every WireGuard peer, with when it last shook hands.
	 */
	wait_js("document.querySelectorAll('svg.topo g.tpeer.bgp').length >= 2 "
	    "&& document.querySelector('svg.topo g.tpeer.ospf') && "
	    "[...document.querySelectorAll('.map-panel h4')].some(h => "
	    "h.textContent === 'WireGuard sessions') && [...document."
	    "querySelectorAll('.map-panel h4')].some(h => h.textContent === "
	    "'Routing')", 60);
	ATF_CHECK(js_true("document.querySelector('svg.topo g.tpeer.bgp')."
	    "textContent.includes('AS65001') && document.querySelector("
	    "'.iflist.wgs').textContent.includes('192.0.2.9:51820')"));
	shot("8a-overview");
	run("document.documentElement.dataset.theme = 'onyx'");
	shot("8a-onyx");
	run("delete document.documentElement.dataset.theme");

	/*
	 * A tunnel is drawn: from one host's port onto the other.  That
	 * asks for its details, with addresses offered, and makes its two
	 * ends, one on each host.
	 */
	run("const ns = document.querySelectorAll('svg.topo .tnode'), p = "
	    "ns[0].querySelector('.port'), b = ns[1].querySelector('.box')."
	    "getBoundingClientRect(); window.bx = b.x + b.width / 2; "
	    "window.by = b.y + b.height / 2; ptr(p, 'pointerdown'); "
	    "ptr(p, 'pointermove', window.bx, window.by);");
	wait_js("document.querySelector('svg.topo .tdraft')", 5);
	run("ptr(document.body, 'pointerup', window.bx, window.by);");
	wait_js("document.querySelector('form[data-form=tunnel]')", 5);
	ATF_CHECK(js_true("document.querySelector('form[data-form=tunnel]')."
	    "inner_a.value === '10.255.0.1/30'"));
	shot("8b-tunnel");
	/* Not kept: the two hosts here are one, with one rc.conf, which
	 * would have the second end's name already. */
	run("const f = document.querySelector('form[data-form=tunnel]'); "
	    "f.persist.checked = false; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].filter(t => "
	    "t.textContent.includes('create gif0')).length >= 1", 20);
	for (int k = 0; k < 100 && system("test \"$(grep -c '^gif0 inet "
	    "10.255.0' ifconfig.log)\" = 2") != 0; k++)
		usleep(100000);
	ATF_CHECK(system("grep -q '^gif0 inet 10.255.0.1/30 10.255.0.2$' "
	    "ifconfig.log && grep -q '^gif0 inet 10.255.0.2/30 10.255.0.1$' "
	    "ifconfig.log && test \"$(grep -c '^gif0 tunnel ' ifconfig.log)\" "
	    "= 2") == 0);
	run("document.querySelector('.dock > header').click()");

	/*
	 * The same, as WireGuard: each host makes its interface and its
	 * key, and when both public keys are known each is given the
	 * other as its peer, by that key, at its outer address.
	 */
	run("const ns = document.querySelectorAll('svg.topo .tnode'), p = "
	    "ns[0].querySelector('.port'), b = ns[1].querySelector('.box')."
	    "getBoundingClientRect(); window.bx = b.x + b.width / 2; "
	    "window.by = b.y + b.height / 2; ptr(p, 'pointerdown'); "
	    "ptr(p, 'pointermove', window.bx, window.by);");
	wait_js("document.querySelector('svg.topo .tdraft')", 5);
	run("ptr(document.body, 'pointerup', window.bx, window.by);");
	wait_js("document.querySelector('form[data-form=tunnel]')", 5);
	run("const f = document.querySelector('form[data-form=tunnel]'); "
	    "f.type.value = 'wg'; f.inner_a.value = '10.254.0.1/30'; "
	    "f.inner_b.value = '10.254.0.2/30'; f.persist.checked = false; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	/* The peers are queued once the keys are read: run them too. */
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('Queued: wg0: wireguard peer'))", 40);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (int k = 0; k < 150 && system("grep -q 'allowed-ips 10.254.0.2/32$'"
	    " wg.log 2>/dev/null && grep -q 'allowed-ips 10.254.0.1/32$' "
	    "wg.log") != 0; k++)
		usleep(100000);
	ATF_CHECK(system("grep -q '^wg0 create$' ifconfig.log && grep -q "
	    "'^wg0 inet 10.254.0.1/30$' ifconfig.log && grep -Eq '^set wg0 "
	    "peer HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw= endpoint "
	    "[^ ]+:51820 allowed-ips 10.254.0.2/32$' wg.log && grep -q "
	    "'allowed-ips 10.254.0.1/32$' wg.log") == 0);
	run("document.querySelector('.dock > header').click()");

	/* The route from a host to an address: asked of the host, drawn
	 * over the map, and told hop by hop. */
	run("const i = document.querySelector('#topo-addr'); i.value = "
	    "'10.77.5.5'; i.dispatchEvent(new Event('input', { bubbles: true "
	    "}));");
	run("document.querySelector('button[data-act=topo-trace]').click()");
	wait_js("document.querySelector('.hops li') && document.querySelector("
	    "'svg.topo .tpath.best')", 15);
	ATF_CHECK(js_true("document.querySelector('.hops').textContent."
	    "includes('10.0.0.1') && document.querySelector('.hops')."
	    "textContent.includes('leaves the fleet')"));
	shot("8c-path");
	run("document.querySelector('button[data-act=topo-path-clear]')."
	    "click()");
	/*
	 * A running jail with a network of its own is a node of the map,
	 * tied to its host, read through it.  No jail runs here, so the
	 * page is told that gw does.
	 */
	run("window.fetch0 = window.fetch; window.fetch = (u, o) => "
	    "window.fetch0(u, o).then(r => String(u).endsWith('/jails') ? "
	    "r.text().then(t => { const j = JSON.parse(t), walk = v => { if "
	    "(v && typeof v === 'object') { if (v.name === 'gw' && 'vnet' in "
	    "v) v.state = 'running'; Object.values(v).forEach(walk); } }; "
	    "walk(j); return new Response(JSON.stringify(j), { status: "
	    "r.status, headers: r.headers }); }) : r);");
	run("document.querySelector('li[data-act=select-server]').click()");
	wait_js("document.querySelector('button[data-act=refresh]')", 10);
	run("document.querySelector('button[data-act=refresh]').click()");
	wait_js("[...document.querySelectorAll('.tree .titem.leaf')].some(l => "
	    "l.dataset.arg === 'gw' && l.classList.contains('s-running'))", 15);
	run("document.querySelector('li[data-act=select-network]').click()");
	wait_js("document.querySelector('svg.topo .tnode.jail.up') && "
	    "document.querySelector('svg.topo .tlink.vnet')", 30);
	ATF_CHECK(js_true("[...document.querySelectorAll('svg.topo .tnode.jail "
	    ".name')].some(n => n.textContent === 'gw')"));
	run("const n = document.querySelector('svg.topo .tnode.jail .box'); "
	    "ptr(n, 'pointerdown'); ptr(n, 'pointerup');");
	wait_js("document.querySelector('svg.topo .tnode.jail.sel') && "
	    "document.querySelector('.map-panel .iflist').textContent."
	    "includes('epair1b')", 10);
	shot("8d-vnet-jail-node");
	/* Its network is the jail's page. */
	run("document.querySelector('.map-panel button[data-act="
	    "topo-open-host]').click()");
	wait_js("document.querySelector('.jail-page .jail-net tr[data-if="
	    "epair1b]')", 20);
	run("window.fetch = window.fetch0;");
	run("document.querySelector('li[data-act=select-network]').click()");
	wait_js("document.querySelector('svg.topo .tnode')", 10);
	/* On a phone the map is above its panel, each as wide as the screen. */
	phone(true);
	wait_js("document.querySelector('.map-wrap').getBoundingClientRect()"
	    ".width <= window.innerWidth && document.documentElement."
	    "scrollWidth <= window.innerWidth + 1", 10);
	shot("m11-network");
	phone(false);
	run("document.querySelector('li[data-act=select-server]').click()");
	wait_js("document.querySelector('button.tab[data-arg=jails]')", 10);

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
