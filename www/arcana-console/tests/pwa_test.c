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
#include <math.h>
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
		ATF_REQUIRE_MSG(r.status == 200, "WebDriver %s %s: %d %.400s; sent: "
	    "%.300s", method, path, r.status, r.body != NULL ? r.body : "",
	    body != NULL ? body : "");
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

static void	run(const char *);

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
	/* The pictures go into the book: the toasts are not of the page. */
	run("var t = document.querySelector('.toasts'); if (t) "
	    "t.style.visibility = 'hidden';");
	v = wd("GET", "/session/screenshot", NULL);
	run("var t = document.querySelector('.toasts'); if (t) "
	    "t.style.visibility = '';");
	if (v == NULL)
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
	ucl_object_t	*v;
	int		 i;

	for (i = 0; i < seconds * 10; i++) {
		if (js_true(expr))
			return;
		usleep(100000);
	}
	shot("failed");
	/* With what the page last said, which is most often why. */
	v = js("return ([...document.querySelectorAll('.toast, .err, .notice')].map("
	    "t => t.textContent.slice(0, 120)).join(' | ').slice(-700) + ' / "
	    "the textarea: ' + JSON.stringify((document.querySelector('.modal "
	    "textarea') || {}).value || ''));");
	atf_tc_fail("timed out waiting for %s; the page says: %s", expr,
	    v != NULL && ucl_object_tostring(v) != NULL ?
	    ucl_object_tostring(v) : "nothing");
}

static void
run(const char *script)
{
	ucl_object_t	*v;

	if ((v = js(script)) != NULL)
		ucl_object_unref(v);
}

static double
js_num(const char *expr)
{
	ucl_object_t	*v;
	char		 script[2048];
	double		 d;

	snprintf(script, sizeof(script), "return (%s);", expr);
	v = js(script);
	d = v != NULL ? ucl_object_todouble(v) : 0;
	if (v != NULL)
		ucl_object_unref(v);
	return (d);
}

/*
 * A mouse, as a hand moves one: the browser decides what is under it,
 * which a click() from a script does not ask.  what is pointerMove,
 * pointerDown or pointerUp.
 */
static void
mouse(const char *what, double x, double y)
{
	char	body[512];

	if (strcmp(what, "pointerMove") == 0)
		snprintf(body, sizeof(body), "{\"actions\":[{\"type\":\"pointer\","
		    "\"id\":\"mouse\",\"parameters\":{\"pointerType\":\"mouse\"},"
		    "\"actions\":[{\"type\":\"pointerMove\",\"duration\":60,"
		    "\"x\":%d,\"y\":%d}]}]}", (int)x, (int)y);
	else
		snprintf(body, sizeof(body), "{\"actions\":[{\"type\":\"pointer\","
		    "\"id\":\"mouse\",\"parameters\":{\"pointerType\":\"mouse\"},"
		    "\"actions\":[{\"type\":\"%s\",\"button\":0}]}]}", what);
	ucl_object_unref(wd("POST", "/session/actions", body));
}

/* A click where the thing is, if the browser lets it be reached. */
static void
click_at(const char *selector)
{
	char	expr[600];
	double	x, y;

	snprintf(expr, sizeof(expr), "(r => r.x + r.width / 2)(document."
	    "querySelector('%s').getBoundingClientRect())", selector);
	x = js_num(expr);
	snprintf(expr, sizeof(expr), "(r => r.y + r.height / 2)(document."
	    "querySelector('%s').getBoundingClientRect())", selector);
	y = js_num(expr);
	mouse("pointerMove", x, y);
	mouse("pointerDown", 0, 0);
	mouse("pointerUp", 0, 0);
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

/*
 * Each case of the browser: the console started with a copy of the shell
 * and Chromium with a virtual security key, enrolled; with servers, the
 * one agent here added as lab (with a third jail, so the tree has one to
 * leave out) and, by another name of its socket, as lab2, lab selected
 * again after.  The cases run side by side, each its own console.
 */
static char	cwd[MAXPATHLEN];	/* the case's directory, for the parts */

static void
prologue(const atf_tc_t *tc, int nservers)
{
	char		 web[MAXPATHLEN], script[2048];
	char		*token;
	FILE		*fp;
	int		 i;

	(void)web;
	(void)script;
	(void)token;
	(void)fp;
	(void)i;

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
	/* A repository to build the agent from, so the hosts offer the
	 * build; no key for it here: the builds use the host's own. */
	run("window.unset = false; fetch('/api/settings', { method: 'POST', "
	    "headers: { 'Content-Type': 'application/json', 'X-Arcana': '1' }, "
	    "body: JSON.stringify({ set: { agent_ssh_key: '', agent_source: "
	    "'git@git.example.org:me/arcana.git' } }) }).then(r => "
	    "{ window.unset = r.ok; });");
	wait_js("window.unset", 10);
	/* The page learns of the repository from the console's health,
	 * read as it opens: opened again. */
	go("/");
	wait_js("document.querySelector('.shell')", 20);
	if (nservers == 0)
		return;
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
	wait_js("document.querySelector('.tree .titem.server.selected') && "
	    "document.querySelector('.tiles .tile')", 20);
	/* Its jails unfolded in the tree, as the cases find them. */
	wait_js("document.querySelector('.tree button[data-act=fold]')", 20);
	run("document.querySelector('.tree button[data-act=fold]').click()");
	wait_js("document.querySelectorAll('.tree .titem.leaf').length === 4",
	    5);
	if (nservers == 1)
		return;
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
	run("document.querySelector('li[data-act=select-server]').click()");
	wait_js("document.querySelector('.tree .titem.server.selected .name')"
	    ".textContent === 'lab' && document.querySelector('.tiles .tile')",
	    10);
}

static void
part_shell(void)
{
	char		 web[MAXPATHLEN], script[2048];
	char		*token;
	FILE		*fp;
	int		 i;

	(void)web;
	(void)script;
	(void)token;
	(void)fp;
	(void)i;

	/* Notify: allowed once by the browser (a stand-in here), then
	 * turned off and on again by the button, and kept so. */
	run("Object.defineProperty(Notification, 'permission', { get: () => "
	    "window.perm || 'default' }); Notification.requestPermission = "
	    "() => { window.perm = 'granted'; return (Promise.resolve("
	    "'granted')); };");
	run("document.querySelector('button[data-act=notify]').click()");
	wait_js("document.querySelector('button.on[data-act=notify]')", 5);
	run("document.querySelector('button[data-act=notify]').click()");
	wait_js("!document.querySelector('button.on[data-act=notify]') && "
	    "localStorage.getItem('arc_notify') === 'off' && document."
	    "querySelector('button[data-act=notify]').title.includes("
	    "'press to turn on')", 5);
	run("document.querySelector('button[data-act=notify]').click()");
	wait_js("document.querySelector('button.on[data-act=notify]') && "
	    "localStorage.getItem('arc_notify') === ''", 5);

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
	/*
	 * Settings, a section at the foot of the side bar, a tab for each
	 * part; the top bar has no Settings or Keys any more.
	 */
	ATF_CHECK(!js_true("document.querySelector('header button[data-act="
	    "settings]') || document.querySelector('header button[data-act="
	    "keys]')"));
	run("document.querySelector('.rail-foot li[data-act=settings]')"
	    ".click()");
	wait_js("document.querySelector('section.setsect button.tab.on"
	    "[data-arg=look]') && document.querySelector('.crumb.place')"
	    ".textContent === 'Settings'", 10);
	run("document.querySelector('button[data-act=set-tab][data-arg="
	    "webconf]').click()");
	wait_js("document.querySelector('section.setsect dl.kv') && document."
	    "querySelector('section.setsect dl.kv').textContent.includes("
	    "'localhost')", 10);
	/* A device that subscribed to be told of tasks is listed, and
	 * taken off with its cross. */
	run("document.querySelector('button[data-act=set-tab][data-arg="
	    "notify]').click()");
	wait_js("document.querySelector('ul.devices li .name') && document."
	    "querySelector('ul.devices').textContent.includes('Chrome on "
	    "Android')", 10);
	ATF_CHECK(js_true("document.querySelector('ul.devices').textContent"
	    ".includes('push.example.org')"));
	run("document.querySelector('ul.devices button[data-act=push-remove]')"
	    ".click()");
	wait_js("document.querySelector('ul.devices').textContent.includes("
	    "'No device yet')", 10);
	/* By mail: its settings here, and none of them under Console. */
	wait_js("document.querySelector('form[data-form=settings-mail] "
	    "input[name=mail_to]')", 10);
	run("const f = document.querySelector('form[data-form=settings-mail]');"
	    " f.mail_to.value = 'ops@example.org'; f.mail_faults.value = "
	    "'Critical'; f.requestSubmit();");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('Settings saved'))", 10);
	ATF_CHECK(system("grep -q 'ops@example.org' data/settings.json && "
	    "grep -q '\"mail_faults\": *\"Critical\"' data/settings.json") ==
	    0);
	run("document.querySelector('button[data-act=mail-test]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('A test mail went to ops@example.org'))",
	    10);
	ATF_CHECK(system("grep -qx 'To: ops@example.org' mail.out") == 0);
	shot("0b-mail");
	/*
	 * What is typed in a field stays there when the page is drawn
	 * again under it: the key's path typed first is still there when
	 * the form is sent, and is what the console keeps.
	 */
	run("document.querySelector('button[data-act=set-tab][data-arg="
	    "console]').click()");
	wait_js("document.querySelector('form[data-form=settings] "
	    "input[name=agent_source]')", 10);
	ATF_CHECK(js_true("!document.querySelector('form[data-form=settings] "
	    "input[name=mail_to]')"));
	run("const f = document.querySelector('form[data-form=settings]'); "
	    "f.agent_ssh_key.value = '/usr/local/etc/arcana/id_ed25519'; "
	    "f.update_check.checked = !f.update_check.checked; "
	    "window.wasChecked = f.update_check.checked; "
	    "window.dispatchEvent(new Event('resize'));");
	usleep(300000);
	ATF_CHECK_MSG(js_true("document.querySelector('form[data-form="
	    "settings]').agent_ssh_key.value === "
	    "'/usr/local/etc/arcana/id_ed25519'"), "what was typed was lost "
	    "when the page was drawn again");
	ATF_CHECK(js_true("document.querySelector('form[data-form=settings]')"
	    ".update_check.checked === window.wasChecked"));
	shot("0a-settings");
	run("const f = document.querySelector('form[data-form=settings]'); "
	    "f.update_check.checked = !f.update_check.checked; "
	    "f.agent_source.value = 'git@git.example.org:me/arcana.git'; "
	    "f.requestSubmit();");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('Settings saved'))", 10);
	ATF_CHECK(system("grep -q '/usr/local/etc/arcana/id_ed25519' "
	    "data/settings.json") == 0);
	/* The keys that sign in, a tab of their own. */
	run("document.querySelector('button[data-act=set-tab][data-arg=keys]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=add-key] ul.keys li "
	    ".name')", 10);
	/* A read-only API token: made with a name in the settings, its
	 * value shown once, listed, and deleted once confirmed. */
	run("document.querySelector('button[data-act=set-tab][data-arg="
	    "tokens]').click()");
	wait_js("document.querySelector('input[data-input=token-name]')", 10);
	run("const i = document.querySelector('input[data-input=token-name]'); "
	    "i.value = 'overlay planner'; i.dispatchEvent(new Event('input', "
	    "{ bubbles: true })); document.querySelector('button[data-act="
	    "token-new]').click();");
	wait_js("document.querySelector('pre.out.token') && document."
	    "querySelector('pre.out.token').textContent.startsWith('arcr_') "
	    "&& [...document.querySelectorAll('ul.tokens li')].some(l => "
	    "l.textContent.includes('overlay planner') && l.textContent."
	    "includes('never used'))", 10);
	/* Beside it, the code the Arcana app scans: the console's address
	 * and the token, drawn while the value is shown. */
	ATF_CHECK(js_true("document.querySelector('.token-qr svg path') && "
	    "document.querySelector('.token-qr svg path').getAttribute('d')."
	    "length > 2000 && document.querySelector('.token-qr').closest("
	    "'.notice').querySelector('pre.out.token')"));
	shot("0b-token");
	run("document.querySelector('ul.tokens button[data-act=token-del]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=confirm]')", 5);
	run("document.querySelector('form[data-form=confirm]')."
	    "requestSubmit();");
	wait_js("!document.querySelector('form[data-form=confirm]')", 5);
	for (i = 0; i < 100 && system("grep -q 'overlay planner' "
	    "data/tokens.json") == 0; i++)
		usleep(50000);
	ATF_CHECK(system("! grep -q 'overlay planner' data/tokens.json") == 0);
	run("document.querySelector('li[data-act=select-fleet]').click()");
	wait_js("!document.querySelector('section.setsect')", 10);
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

static void
part_hosts(void)
{
	char		 web[MAXPATHLEN], script[2048];
	char		*token;
	FILE		*fp;
	int		 i;

	(void)web;
	(void)script;
	(void)token;
	(void)fp;
	(void)i;

	/* A server, its jails, and starting one. */
	/* A third jail, so the tree has something to leave out. */
	ATF_REQUIRE((fp = fopen("etc/jail.conf.d/cache.conf", "w")) != NULL);
	fprintf(fp, "cache {\n\tpath = \"/jails/cache\";\n\tip4.addr = "
	    "10.0.0.30;\n}\n");
	fclose(fp);
	wait_js("document.querySelector('button[data-act=add-server]')", 10);
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
	/* The fleet's graph is of what runs: no jail here does, so the
	 * host stands alone in it. */
	ATF_CHECK(js_true("document.querySelector('.topo .tnode.host') && "
	    "!document.querySelector('.topo .tnode[data-act=peek-jail]')"));
	shot("2-fleet");
	/* Devices: the hosts as a table, filtered; a row opens its host. */
	run("document.querySelector('.tree .titem.devnode').click()");
	wait_js("document.querySelectorAll('table.devices tbody tr.pick')"
	    ".length >= 1 && location.hash === '#/devices'", 10);
	ATF_CHECK(js_true("[...document.querySelectorAll('table.devices thead "
	    "th')].map(t => t.textContent).join(',').startsWith('Host,Address,"
	    "State,Agent,FreeBSD,Jails running')"));
	run("const i = document.querySelector('#filter'); i.value = "
	    "'nothing-matches-this'; i.dispatchEvent(new Event('input', { "
	    "bubbles: true }));");
	wait_js("document.querySelectorAll('table.devices tbody tr.pick')"
	    ".length === 0", 5);
	run("const i = document.querySelector('#filter'); i.value = ''; "
	    "i.dispatchEvent(new Event('input', { bubbles: true }));");
	wait_js("document.querySelectorAll('table.devices tbody tr.pick')"
	    ".length >= 1", 5);
	shot("2b-devices");
	run("document.querySelector('table.devices tbody tr.pick').click()");
	wait_js("document.querySelector('.tree .titem.server.selected') && "
	    "location.hash.startsWith('#/hosts/')", 10);
	run("document.querySelector('.tree .titem.fleet[data-act=select-fleet]')"
	    ".click()");
	wait_js("document.querySelector('.hosts .hostcard')", 10);
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
	/* The dock opened with the queue, so the task is in its list, not
	 * the strip along the header (that one shows while it is closed). */
	wait_js("document.querySelector('.dock.open ol.ops .op.o-ok') && "
	    "!document.querySelector('.dock .recent .last') && "
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
	wait_js("document.querySelector('.terminal') && document."
	    "querySelector('.terminal').textContent.includes('fake-jail: -f "
	    "etc/jail.conf -c web')", 5);
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
	/*
	 * A repository for a newer FreeBSD: pkg refuses, and the page asks
	 * whether to go past OSVERSION; approved, the same upgrade again
	 * with IGNORE_OSVERSION.
	 */
	ATF_REQUIRE(system("touch newer-os && cp pending pending.keep") == 0);
	run("document.querySelector('button.tab[data-arg=packages]').click()");
	/* At first the installed, from the host's own database: by hand
	 * or automatic; the repository is asked under Upgrades. */
	wait_js("[...document.querySelectorAll('table.pkg-installed tbody "
	    "tr')].some(r => r.textContent.includes('pimd') && r.textContent."
	    "includes('automatic')) && [...document.querySelectorAll('table."
	    "pkg-installed tbody tr')].some(r => r.textContent.includes("
	    "'aria2') && r.textContent.includes('by hand'))", 20);
	ATF_CHECK(system("grep -q '^query ' pkg.log") == 0);
	shot("6b-installed");
	/* The cache cleaned, all of it: asked first, then a job. */
	run("document.querySelector('button[data-act=pkg-clean][data-arg=all]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=confirm]') && document."
	    "querySelector('.modal').textContent.includes('every downloaded "
	    "package')", 5);
	run("document.querySelector('form[data-form=confirm]')."
	    "requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 200 && system("grep -q '^clean -ay$' pkg.log "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^clean -ay$' pkg.log") == 0);
	run("document.querySelector('.dock > header').click()");
	/* Packages installed: named in a box, checked, then a job. */
	run("document.querySelector('button[data-act=pkg-install]').click()");
	wait_js("document.querySelector('form[data-form=pkg-install]')", 5);
	run("const f = document.querySelector('form[data-form=pkg-install]'); "
	    "f.names.value = 'strongswan;rm'; f.requestSubmit();");
	wait_js("document.querySelector('.modal').textContent.includes("
	    "'letters, digits')", 5);
	run("const f = document.querySelector('form[data-form=pkg-install]'); "
	    "f.names.value = 'strongswan  wireguard-tools'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 200 && system("grep -q 'install -y strongswan "
	    "wireguard-tools$' pkg.log 2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q 'install -y strongswan wireguard-tools$' "
	    "pkg.log") == 0);
	run("document.querySelector('.dock > header').click()");
	/* Of every running jail at once: none runs here, which is said,
	 * and nothing is asked. */
	run("document.querySelector('button[data-act=pkg-clean-jails]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('has no running jail'))", 5);
	ATF_CHECK(js_true("!document.querySelector('form[data-form=confirm]')"));
	/* Over IPv6 only: pkg -6, kept in the browser. */
	run("document.querySelector('button[data-act=pkg-ip][data-arg=\"6\"]')"
	    ".click()");
	run("document.querySelector('button[data-act=pkg-mode][data-arg=\"1\"]')"
	    ".click()");
	wait_js("document.querySelector('button[value=go]:not([disabled])')",
	    20);
	ATF_CHECK(system("grep -q '^-6 version -vRl <$' pkg.log") == 0);
	run("document.querySelector('button[value=go]').click()");
	wait_js("document.querySelector('form[data-form=confirm]')", 5);
	run("document.querySelector('form[data-form=confirm]')."
	    "requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("document.querySelector('form[data-form=confirm]') && "
	    "document.querySelector('.modal').textContent.includes("
	    "'Packages for a newer FreeBSD') && document.querySelector("
	    "'.modal').textContent.includes('IGNORE_OSVERSION')", 20);
	shot("6b-osversion");
	run("document.querySelector('form[data-form=confirm]')."
	    "requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 200 && system("grep -q '^-6 -o IGNORE_OSVERSION=yes "
	    "upgrade -y$' pkg.log 2>/dev/null && ! [ -s pending ]") != 0; i++)
		usleep(100000);
	ATF_CHECK(system("grep -q '^-6 -o IGNORE_OSVERSION=yes upgrade -y$' "
	    "pkg.log && ! [ -s pending ]") == 0);
	wait_js("[...document.querySelectorAll('.ops .op')].some(o => "
	    "o.textContent.includes('ignoring OSVERSION'))", 10);
	run("document.querySelector('.dock > header').click()");
	ATF_REQUIRE(system("rm newer-os && mv pending.keep pending") == 0);
	run("document.querySelector('button[data-act=pkg-ip][data-arg=\"0\"]')"
	    ".click()");

	/* The page opened again: what ended is still along the bottom. */
	go("/");
	wait_js("document.querySelector('.shell')", 20);
	/*
	 * The page was loaded again: the tasks that ended before are
	 * still along the bottom, with their hosts and how they ended;
	 * one picked opens the list at it.
	 */
	wait_js("document.querySelectorAll('.dock .recent .last').length >= 4 "
	    "&& [...document.querySelectorAll('.dock .recent .last small')]."
	    "some(e => /done|failed/.test(e.textContent))", 20);
	/* Kept as the page keeps them, which may come a moment after. */
	wait_js("(localStorage.getItem('arc_tasks') || '').split('\\n')"
	    ".length > 5", 5);
	shot("9a-recent-tasks");
	run("[...document.querySelectorAll('.dock .recent .last')].pop()."
	    "click()");
	wait_js("document.querySelector('.dock.open ol.ops li.op.selected .w')",
	    5);
	run("document.querySelector('.dock > header').click()");
	wait_js("!document.querySelector('.dock.open')", 5);
	/*
	 * Jails made from the page: a template; a jail of its own file that
	 * includes the defaults and the template, read back by jail(8),
	 * then taken away; the defaults written, the file before kept.
	 */
	run("document.querySelector('.tree .titem.server').click()");
	wait_js("document.querySelector('button.tab[data-arg=jails]')", 10);
	run("document.querySelector('button.tab[data-arg=jails]').click()");
	wait_js("document.querySelector('button[data-act=jm-new]')", 10);
	run("document.querySelector('button[data-act=jm-files]').click()");
	wait_js("document.querySelector('form[data-form=jm-files] button"
	    "[data-act=jm-tpl-new]')", 5);
	run("document.querySelector('button[data-act=jm-tpl-new]').click()");
	wait_js("document.querySelector('form[data-form=jm-template]')", 5);
	run("const f = document.querySelector('form[data-form=jm-template]'); "
	    "f.name.value = 'certbot'; f.text.value = 'allow.raw_sockets;\\n'; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 100 && access("etc/jail.conf.d/certbot.inc", F_OK) !=
	    0; i++)
		usleep(100000);
	ATF_CHECK(system("grep -qx 'allow.raw_sockets;' "
	    "etc/jail.conf.d/certbot.inc") == 0);
	run("document.querySelector('button[data-act=jm-new]').click()");
	wait_js("document.querySelector('form[data-form=jm-new] "
	    "input[name=tpl_certbot]')", 10);
	shot("4j-jail-new");
	run("const f = document.querySelector('form[data-form=jm-new]'); "
	    "f.name.value = 'www'; f.ip4.value = 'lo0|127.0.0.9'; "
	    "f.ruleset.value = '4'; f.sysvsem.checked = true; "
	    "f.tpl_certbot.checked = true; f.start.checked = false; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 100 && access("etc/jail.conf.d/www.conf", F_OK) != 0;
	    i++)
		usleep(100000);
	ATF_CHECK(system("grep -Eqx '\\.include \"/.*/etc/jail\\.conf\";' "
	    "etc/jail.conf.d/www.conf && grep -qx 'www {' etc/jail.conf.d/www.conf "
	    "&& grep -q 'devfs_ruleset = 4;' etc/jail.conf.d/www.conf && grep -q "
	    "'sysvsem = new;' etc/jail.conf.d/www.conf && grep -q 'ip4.addr = "
	    "\"lo0|127.0.0.9\";' etc/jail.conf.d/www.conf && grep -Eq '\\.include "
	    "\"/.*/etc/jail\\.conf\\.d/certbot\\.inc\";' etc/jail.conf.d/www.conf") ==
	    0);
	/* Taken away again, its file kept beside. */
	run("document.querySelector('button[data-act=jm-files]').click()");
	wait_js("document.querySelector('button[data-act=jm-rm][data-arg=www]')",
	    10);
	run("document.querySelector('button[data-act=jm-rm][data-arg=www]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=jm-remove]')", 5);
	run("document.querySelector('form[data-form=jm-remove]')"
	    ".requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 100 && access("etc/jail.conf.d/www.conf", F_OK) == 0;
	    i++)
		usleep(100000);
	ATF_CHECK(access("etc/jail.conf.d/www.conf", F_OK) != 0 &&
	    access("etc/jail.conf.d/www.conf.arcana.bak", F_OK) == 0);
	/* The defaults: the path there now offered, the domain asked. */
	run("document.querySelector('button[data-act=jm-defaults]').click()");
	wait_js("document.querySelector('form[data-form=jm-defaults]') && "
	    "document.querySelector('form[data-form=jm-defaults] details')", 10);
	ATF_CHECK(js_true("document.querySelector('form[data-form=jm-defaults]')"
	    ".path.value === '/jails/$name'"));
	run("const f = document.querySelector('form[data-form=jm-defaults]'); "
	    "f.domain.value = 'example.org'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 100 && system("grep -q 'host.domainname = "
	    "\"example.org\";' etc/jail.conf") != 0; i++)
		usleep(100000);
	ATF_CHECK(system("grep -q 'host.hostname = \"${name}.example.org\";' "
	    "etc/jail.conf && grep -qx 'exec.clean;' etc/jail.conf && grep -q "
	    "'^web {' etc/jail.conf.arcana.bak") == 0);
}

static void
part_nettab(void)
{
	char		 web[MAXPATHLEN], script[2048];
	char		*token;
	FILE		*fp;
	int		 i;

	(void)web;
	(void)script;
	(void)token;
	(void)fp;
	(void)i;

	/* The interfaces, in the network tab: an address is added to one
	 * through the queue, as any change is. */
	run("document.querySelector('button.tab[data-arg=network]').click()");
	wait_js("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=interfaces]')", 10);
	/*
	 * The routes and the sockets come in parts over the stream, and
	 * are whole: no word of a table cut short.
	 */
	run("window.netw = []; window.ws1 = WebSocket.prototype.send; "
	    "WebSocket.prototype.send = function (t) { window.netw.push(t); "
	    "return window.ws1.call(this, t); };");
	run("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=routes]').click()");
	wait_js("[...document.querySelectorAll('.stage table.net td')].some("
	    "t => t.textContent === 'default') && !document.querySelector("
	    "'.routes-cut') && window.netw.some(t => t.includes("
	    "'\"what\":\"routes\"'))", 20);
	run("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=sockets]').click()");
	wait_js("document.querySelectorAll('.stage table.net tbody tr')."
	    "length > 0 && window.netw.some(t => t.includes('\"what\":"
	    "\"sockets\"'))", 20);
	run("WebSocket.prototype.send = window.ws1;");
	/* The neighbours, ARP's and NDP's, asked of the kernel. */
	run("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=neighbours]').click()");
	wait_js("[...document.querySelectorAll('.stage table.net tbody tr')]"
	    ".some(r => r.textContent.includes('58:9c:fc:00:00:02') && "
	    "r.textContent.includes('reachable'))", 20);
	/* One set by hand, aging out; and one taken away. */
	run("document.querySelector('button[data-act=neigh-add]').click()");
	wait_js("document.querySelector('form[data-form=neigh]')", 5);
	run("const f = document.querySelector('form[data-form=neigh]'); "
	    "f.address.value = '10.0.0.9'; f.lladdr.value = "
	    "'02:00:00:00:00:09'; f.temp.checked = true; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 100 && system("grep -qx 'arp -s 10.0.0.9 "
	    "02:00:00:00:00:09 temp' neigh.log") != 0; i++)
		usleep(100000);
	ATF_CHECK(system("grep -qx 'arp -s 10.0.0.9 02:00:00:00:00:09 temp' "
	    "neigh.log") == 0);
	run("document.querySelector('.dock > header').click()");
	run("document.querySelector('button[data-act=neigh-delete][data-arg="
	    "\"10.0.0.2\"]').click()");
	wait_js("document.querySelector('.modal button.danger')", 5);
	run("document.querySelector('.modal button.danger').click()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 100 && system("grep -qx 'arp -d 10.0.0.2' neigh.log") !=
	    0; i++)
		usleep(100000);
	ATF_CHECK(system("grep -qx 'arp -d 10.0.0.2' neigh.log") == 0);
	run("document.querySelector('.dock > header').click()");
	/* The nexthop groups, as netstat -O has them, under Nexthops:
	 * each next hop a line of its own, with its share. */
	ATF_CHECK(js_true("!document.querySelector('nav.sub button[data-act="
	    "net-kind][data-arg=nhgroups]')"));
	run("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=nexthops]').click()");
	wait_js("document.querySelector('nav.sub button[data-act=net-kind]"
	    "[data-arg=nhgroups]')", 10);
	/*
	 * What each next hop carried, from the agent's samples: told here
	 * that em0 sent 3000 bytes a second and em1 1000, for ten minutes,
	 * so the group sent 75% and 25% where its weights say 67% and 33%.
	 */
	run("window.fetchH = window.fetch; window.hist = () => { const now = "
	    "Date.now() / 1000, s = []; for (let t = now - 600; t <= now; t "
	    "+= 5) s.push([t, 1, 0.1, 1e9, 0, 4000, 4000, 0, 0, 500, 3000, "
	    "700, 1000]); return { ok: true, data: { step: 5, keep: 720, "
	    "ncpu: 1, mem_total: 2e9, swap_total: 0, bytes: 1, nets: ['em0', "
	    "'em1'], disks: [], jails: [], samples: s } }; }; window.fetch = "
	    "(u, o) => String(u).includes('/history') ? Promise.resolve(new "
	    "Response(JSON.stringify(window.hist()), { status: 200, headers: "
	    "{ 'Content-Type': 'application/json' } })) : window.fetchH(u, "
	    "o);");
	run("document.querySelector('nav.sub button[data-act=net-kind]"
	    "[data-arg=nhgroups]').click()");
	wait_js("document.querySelectorAll('.stage table.nhgroups .nhg-hop')"
	    ".length >= 2 && document.querySelector('button[data-act="
	    "net-kind][data-arg=nexthops].on')", 20);
	ATF_CHECK(js_true("(() => { const h = [...document.querySelectorAll("
	    "'.nhg-hop')].map(e => e.textContent); return h[0].includes("
	    "'10.0.0.1') && h[0].includes('67%') && h[1].includes('em1') && "
	    "h[1].includes('33%'); })()"));
	wait_js("(() => { const k = [...document.querySelectorAll('table."
	    "nhgroups .ecmp-side')[0].querySelectorAll('.ecmp-key li')].map("
	    "l => l.textContent); return k.length === 2 && k[0].includes("
	    "'10.0.0.1') && k[0].includes('75%of weight 67%') && k[1]."
	    "includes('25%of weight 33%'); })()", 20);
	/* Ten minutes of fifteen: two thirds of the columns. */
	ATF_CHECK(js_true("(() => { const e = document.querySelectorAll("
	    "'table.nhgroups .ecmp-side'); return e[0].querySelectorAll("
	    "'rect.hit').length >= 35 && e[0].querySelectorAll('line.ecmp-"
	    "weight').length === 1 && e[1].textContent.includes('Received'); "
	    "})()"));
	ATF_CHECK(js_true("document.querySelector('.stage').scrollWidth <= "
	    "document.querySelector('.stage').clientWidth + 1"));
	shot("7n-nhgroups");
	/* The same in the network section, a tab beside the map. */
	run("document.querySelector('li[data-act=select-network]').click()");
	wait_js("document.querySelector('.netsect button.tab.on[data-arg=map]"
	    "') && document.querySelector('.netsect svg.topo')", 20);
	run("document.querySelector('.netsect button.tab[data-arg=groups]')"
	    ".click()");
	wait_js("[...document.querySelectorAll('.ecmp-page .ecmp-group')]"
	    ".some(g => g.querySelector('h4').textContent.includes('group 7') "
	    "&& g.textContent.includes('75%of weight 67%'))", 30);
	ATF_CHECK(js_true("!document.querySelector('.netsect svg.topo')"));
	shot("7n-network-nhgroups");
	phone(true);
	wait_js("document.documentElement.scrollWidth <= window.innerWidth + 1 "
	    "&& document.querySelector('.ecmp-page .ecmp')", 10);
	shot("m7n-network-nhgroups");
	phone(false);
	run("document.querySelector('.netsect button.tab[data-arg=map]')"
	    ".click()");
	wait_js("document.querySelector('.netsect svg.topo')", 20);
	run("window.fetch = window.fetchH;");
	run("document.querySelector('li[data-act=select-server]').click()");
	wait_js("document.querySelector('button.tab[data-arg=network]')", 10);
	run("document.querySelector('button.tab[data-arg=network]').click()");
	wait_js("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=interfaces]')", 10);
	run("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=interfaces]').click()");
	wait_js("document.querySelector('table.ifaces tr[data-if=lo0] .chip')",
	    20);
	shot("7-interfaces");
	/*
	 * A box closes when a hand clicks beside it, as with Escape:
	 * a real mouse, which goes to what the browser has there.
	 */
	run("document.querySelector('tr[data-if=lo0] button[data-act="
	    "if-addr-add]').click()");
	wait_js("document.querySelector('form[data-form=if-address]')", 5);
	run("window.under = document.elementFromPoint(12, window.innerHeight - "
	    "60); window.underName = window.under ? window.under.className + "
	    "' ' + window.under.tagName : 'none';");
	mouse("pointerMove", 12, js_num("window.innerHeight - 60"));
	mouse("pointerDown", 0, 0);
	mouse("pointerUp", 0, 0);
	for (i = 0; i < 50 && js_true("document.querySelector('form[data-form="
	    "if-address]')"); i++)
		usleep(100000);
	{
		ucl_object_t *u = js("return window.underName;");

		ATF_CHECK_MSG(i < 50, "a click beside the box left it open; "
		    "under the hand: %s", u != NULL && ucl_object_tostring(u)
		    != NULL ? ucl_object_tostring(u) : "?");
		if (u != NULL)
			ucl_object_unref(u);
	}
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
	/* Every table can be had as CSV: its columns by their names, its
	 * rows as shown, without the buttons. */
	run("document.querySelector('tr[data-if=lo0]').closest('table')"
	    ".querySelector('thead button.csv-btn').click()");
	wait_js("typeof window.arcCsvLast === 'string'", 5);
	ATF_CHECK(js_true("(() => { const l = window.arcCsvLast.split('\\n');"
	    " return l.length > 2 && !l[0].startsWith(',') && l.some(x => "
	    "x.startsWith('lo0,')) && !window.arcCsvLast.includes('+ "
	    "address'); })()"));
	/* An address changed: the form with what it is now; the new one
	 * added, then the old one taken off. */
	run("document.querySelector('tr[data-if=lo0] button[data-act="
	    "if-addr-edit][data-value=\"127.0.0.1/8\"]').click()");
	wait_js("document.querySelector('form[data-form=if-address]')", 5);
	ATF_CHECK(js_true("document.querySelector('form[data-form=if-address]')"
	    ".address.value === '127.0.0.1/8' && document.querySelector('.modal "
	    "button.primary').textContent === 'Change'"));
	run("const f = document.querySelector('form[data-form=if-address]'); "
	    "f.address.value = '127.0.0.2/8'; f.persist.checked = false; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('lo0: remove 127.0.0.1: done'))", 20);
	ATF_CHECK(system("grep -n 'lo0 inet 127.0.0.2/8 alias\\|lo0 inet "
	    "127.0.0.1 -alias' ifconfig.log | sed 's/:.*inet / /' | tr '\\n' "
	    "' ' | grep -q '127.0.0.2/8 alias .*127.0.0.1 -alias'") == 0);
	run("document.querySelector('.dock > header').click()");

	/* A static route, from the routes table: asked for in a dialog,
	 * queued, and run with route(8). */
	run("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=routes]').click()");
	wait_js("document.querySelector('button[data-act=route-add]')", 10);
	run("document.querySelector('button[data-act=route-add]').click()");
	wait_js("document.querySelector('form[data-form=route]')", 5);
	/* On a phone a dialog is a sheet from the bottom, its fields one
	 * under the other and as wide as it; a tap above it closes it. */
	phone(true);
	wait_js("document.querySelector('.modal').getBoundingClientRect()."
	    "bottom >= window.innerHeight - 2", 10);
	shot("m3a-route-form");
	run("document.querySelector('.modal > form').scrollTop = 1e6;");
	shot("m3b-route-form-end");
	mouse("pointerMove", 30, 30);
	mouse("pointerDown", 0, 0);
	mouse("pointerUp", 0, 0);
	wait_js("!document.querySelector('form[data-form=route]')", 5);
	phone(false);
	run("document.querySelector('button[data-act=route-add]').click()");
	wait_js("document.querySelector('form[data-form=route]')", 5);
	/* With its cost, its share, the address sent from and the table. */
	run("const f = document.querySelector('form[data-form=route]'); "
	    "f.destination.value = '10.88.0.0/16'; f.gateway.value = "
	    "'10.0.0.1'; f.metric.value = '5'; f.weight.value = '20'; "
	    "f.source.value = '10.0.0.9'; f.fib.value = '2'; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('route add 10.88.0.0/16 via 10.0.0.1: "
	    "done'))", 20);
	ATF_CHECK(system("grep -q '^0 route-add 10.88.0.0/16 10.0.0.1 - 2 5 "
	    "20 10.0.0.9$' route.log") == 0);
	run("document.querySelector('.dock > header').click()");

	/* A route's nexthop opens in a box, read from the host. */
	wait_js("document.querySelector('table.net button.cell-link[data-act="
	    "net-nhop]')", 10);
	run("window.nh = document.querySelector('table.net button.cell-link"
	    "[data-act=net-nhop][data-value=nexthop]').textContent; document."
	    "querySelector('table.net button.cell-link[data-act=net-nhop]"
	    "[data-value=nexthop]').click();");
	wait_js("document.querySelector('form[data-form=nhop] h2').textContent "
	    "=== 'Nexthop ' + window.nh && document.querySelector('form"
	    "[data-form=nhop] dl.kv') && document.querySelector('form[data-form="
	    "nhop] dl.kv').textContent.includes('MTU1500')", 15);
	shot("7a-nhop");
	run("document.querySelector('button[data-act=net-nhop-all]').click()");
	wait_js("!document.querySelector('.modal') && document.querySelector("
	    "'button[data-act=net-kind][data-arg=nexthops].on')", 10);
	run("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=routes]').click()");
	wait_js("document.querySelector('button[data-act=net-lookup]')", 10);

	/*
	 * The route to an address, looked up on the host: what it takes,
	 * in a box over the table.  And an interface's traffic and its
	 * MTU, in the interfaces.
	 */
	run("document.querySelector('button[data-act=net-lookup]').click()");
	wait_js("document.querySelector('form[data-form=lookup] input[name="
	    "address]')", 5);
	run("const f = document.querySelector('form[data-form=lookup]'); "
	    "f.address.value = '10.77.5.5'; f.requestSubmit();");
	wait_js("document.querySelector('.modal .notice.lookup') && document."
	    "querySelector('.modal .notice.lookup').textContent.includes("
	    "'10.0.0.1')", 10);
	shot("7a-lookup");
	run("document.querySelector('.modal button[data-act=close]').click()");
	wait_js("!document.querySelector('.modal')", 5);
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
		    "network", "packages", "sysctl", "processes", "log",
		    "jobs" };
		char name[32];
		size_t t;

		for (t = 0; t < 9; t++) {
			snprintf(script, sizeof(script), "document.querySelector("
			    "'button.tab[data-arg=%s]').click()", tabs[t]);
			run(script);
			usleep(700000);
			snprintf(name, sizeof(name), "m%zu-%s", t, tabs[t]);
			shot(name);
			ATF_CHECK_MSG(js_true("document.documentElement."
			    "scrollWidth <= window.innerWidth + 1"),
			    "the %s tab is wider than a phone", tabs[t]);
			/* A table is a card for each row, each value with
			 * its column's name; none scrolls sideways. */
			ATF_CHECK_MSG(js_true("[...document.querySelectorAll("
			    "'.stage table.net')].every(t => t.classList."
			    "contains('cards') && t.scrollWidth <= t."
			    "clientWidth + 1)"), "a table of the %s tab is not "
			    "cards", tabs[t]);
		}
		run("document.querySelector('button.tab[data-arg=processes]')"
		    ".click()");
		wait_js("document.querySelector('table.procs.cards tbody tr td"
		    "[data-label=PID]')", 10);
		/* A card is titled by the command, not by its number. */
		ATF_CHECK(js_true("(() => { const tr = document.querySelector("
		    "'table.procs.cards tbody tr'), t = tr.querySelector("
		    "'td.ctitle'); return t && t.dataset.label === 'Command' && "
		    "t.getBoundingClientRect().top <= tr.querySelector("
		    "'td[data-label=PID]').getBoundingClientRect().top; })()"));
		shot("m9-processes-cards");
		/* The firewall's parts as a strip above its rules. */
		run("document.querySelector('button.tab[data-arg=firewall]')"
		    ".click()");
		wait_js("document.querySelector('.fw-strip') && getComputedStyle("
		    "document.querySelector('.fw-strip')).display === 'flex' && "
		    "document.querySelectorAll('.fw-strip button').length >= 4",
		    20);
		ATF_CHECK(js_true("document.documentElement.scrollWidth <= "
		    "window.innerWidth + 1"));
		shot("m9b-firewall");
		run("[...document.querySelectorAll('.fw-strip button')].find(b "
		    "=> b.textContent.includes('As text')).click()");
		wait_js("document.querySelector('.fw-strip button.on') && document"
		    ".querySelector('.fw-strip button.on').textContent.includes("
		    "'As text')", 10);
		run("document.querySelector('.fw-strip button').click()");
		wait_js("document.querySelector('.fw-strip button.on') && document"
		    ".querySelector('.fw-strip button.on').textContent === "
		    "'Overview'", 10);
		run("document.querySelector('button.tab[data-arg=processes]')"
		    ".click()");
		wait_js("document.querySelector('table.procs.cards')", 10);
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
	/* Every control of the top bar can be reached: what does not fit
	 * the one row is behind its menu, which the next thing done
	 * closes. */
	ATF_CHECK(js_true("getComputedStyle(document.querySelector('.who'))"
	    ".display === 'none'"));
	run("document.querySelector('button[data-act=who-toggle]').click()");
	wait_js("getComputedStyle(document.querySelector('.who')).display "
	    "!== 'none'", 5);
	ATF_CHECK(js_true("(() => { const r = document.querySelector("
	    "'button[data-act=logout]').getBoundingClientRect(); return "
	    "r.width > 0 && r.left >= 0 && r.right <= innerWidth + 1 && "
	    "r.top >= 0 && r.bottom <= innerHeight; })()"));
	shot("m6a-menu");
	run("document.querySelector('button[data-act=who-toggle]').click()");
	wait_js("getComputedStyle(document.querySelector('.who')).display "
	    "=== 'none'", 5);
	ATF_CHECK(js_true("document.documentElement.scrollWidth <= "
	    "window.innerWidth + 1"));
	run("document.querySelector('.dock > header').click()");
	usleep(500000);
	shot("m7-activity");
	run("document.querySelector('.dock > header').click()");
	run("document.querySelector('.rail-foot li[data-act=settings]')"
	    ".click()");
	wait_js("document.querySelector('section.setsect .themes') && "
	    "document.documentElement.scrollWidth <= window.innerWidth + 1",
	    10);
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
	/* The other light ones: each a light ground and its own colour. */
	{
		static const char *const light[] = { "sand", "mist", "mint" };
		char	name[32];
		size_t	k;

		for (k = 0; k < 3; k++) {
			snprintf(script, sizeof(script), "document.querySelector("
			    "'button.theme[data-arg=%s]').click()", light[k]);
			run(script);
			snprintf(script, sizeof(script), "document."
			    "documentElement.dataset.theme === '%s' && "
			    "getComputedStyle(document.documentElement)."
			    "colorScheme === 'light' && /^#[ef]/.test("
			    "getComputedStyle(document.documentElement)."
			    "getPropertyValue('--bg').trim())", light[k]);
			wait_js(script, 5);
			snprintf(name, sizeof(name), "m10-%s", light[k]);
			shot(name);
		}
	}
	/* Tron, the neon one: its glow and capitals. */
	run("document.querySelector('button.theme[data-arg=tron]').click()");
	wait_js("document.documentElement.dataset.theme === 'tron' && "
	    "localStorage.getItem('arc_theme') === 'tron' && document."
	    "documentElement.classList.contains('neon') && getComputedStyle("
	    "document.documentElement).getPropertyValue('--cyan').trim() === "
	    "'#3be8ff'", 5);
	shot("m10b-tron");
	/* Graphite, the default, everywhere: none kept, no neon. */
	run("document.querySelector('button.theme[data-arg=\"\"]').click()");
	wait_js("!document.documentElement.dataset.theme && localStorage."
	    "getItem('arc_theme') === null && !document.documentElement."
	    "classList.contains('neon') && document.querySelector('button."
	    "theme[data-arg=\"\"]').classList.contains('on') && !getComputedStyle("
	    "document.body).fontFamily.startsWith('\"JetBrains')", 5);
	run("const s = document.createElement('script'); s.src = '/fx.js?again';"
	    " document.head.appendChild(s);");
	usleep(500000);
	ATF_CHECK(js_true("!document.documentElement.dataset.theme"));
	shot("m10a-phone-default");
	/* A theme kept from before Graphite was the default: moved to it
	 * once; one picked after that stays. */
	run("localStorage.setItem('arc_theme', 'tron'); localStorage."
	    "removeItem('arc_theme_v'); const s = document.createElement("
	    "'script'); s.src = '/fx.js?once'; document.head.appendChild(s);");
	usleep(500000);
	ATF_CHECK(js_true("!document.documentElement.dataset.theme && "
	    "localStorage.getItem('arc_theme') === null && localStorage."
	    "getItem('arc_theme_v') === '2'"));
	run("localStorage.setItem('arc_theme', 'paper'); const s = document."
	    "createElement('script'); s.src = '/fx.js?kept'; document.head."
	    "appendChild(s);");
	usleep(500000);
	ATF_CHECK(js_true("document.documentElement.dataset.theme === "
	    "'paper'"));
	run("localStorage.removeItem('arc_theme')");
	run("delete document.documentElement.dataset.theme");
	run("document.querySelector('li[data-act=select-fleet]').click()");
	wait_js("document.querySelector('.hosts .hostcard')", 10);
	run("document.querySelector('.hosts .hostcard').click()");
	phone(false);

}

static void
part_plugins(void)
{
	char		 web[MAXPATHLEN], script[2048];
	char		*token;
	FILE		*fp;
	int		 i;

	(void)web;
	(void)script;
	(void)token;
	(void)fp;
	(void)i;

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
	 * A jail with a network of its own: its page sends to the host's
	 * Network tab with the jail picked there, which shows that network,
	 * read through the host; a change made there is made in the jail,
	 * and kept in the jail's own rc.conf.
	 */
	run("const m = document.querySelector('.tree .titem.more'); if (m && "
	    "!m.textContent.includes('fewer')) m.click();");
	wait_js("[...document.querySelectorAll('.tree .titem.leaf')].some(l => "
	    "l.dataset.arg === 'gw')", 10);
	run("[...document.querySelectorAll('.tree .titem.leaf')].find(l => "
	    "l.dataset.arg === 'gw').click()");
	wait_js("document.querySelector('.jail-page .jail-net button[data-act="
	    "jail-net]')", 20);
	ATF_CHECK(js_true("!document.querySelector('.jail-page table.ifaces')"));
	run("document.querySelector('.jail-net button[data-act=jail-net]')"
	    ".click()");
	wait_js("document.querySelector('button.tab[data-arg=network].on') && "
	    "document.querySelector('select[data-input=net-jail]')?.value === "
	    "'gw' && document.querySelector('table.ifaces tr[data-if=epair1b] "
	    ".chip')", 20);
	ATF_CHECK(js_true("document.querySelector('table.ifaces').textContent"
	    ".includes('10.99.0.2/24') && !document.querySelector('table.ifaces "
	    "tr[data-if=lo0]')"));
	shot("7g-vnet-jail");
	run("document.querySelector('table.ifaces tr[data-if=epair1b] button"
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
	run("document.querySelector('button[data-act=if-vnet-give]').click()");
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
	wait_js("document.querySelector('table.ifaces tr[data-if=epair1b] "
	    "button[data-act=if-vnet-back]')", 20);
	run("document.querySelector('table.ifaces tr[data-if=epair1b] button"
	    "[data-act=if-vnet-back]').click()");
	wait_js("document.querySelector('form[data-form=confirm]')", 5);
	run("document.querySelector('form[data-form=confirm]')"
	    ".requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('take epair1b back from gw: done'))", 20);
	ATF_CHECK(system("grep -q '^epair1b -vnet 4$' ifconfig.log") == 0);
	wait_js("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=routes]')", 20);
	/* Its routes, by the host's netstat told which jail. */
	run("document.querySelector('button[data-act=net-kind]"
	    "[data-arg=routes]').click()");
	wait_js("document.querySelector('button[data-act=route-add]') && "
	    "document.querySelector('select[data-input=net-jail]')?.value === "
	    "'gw'", 10);
	/* And the host's again, picked there; gw does not run, so the
	 * host's own network is offered no picker then. */
	run("const p = document.querySelector('select[data-input=net-jail]'); "
	    "p.value = ''; p.dispatchEvent(new Event('input', {bubbles: "
	    "true}));");
	wait_js("!document.querySelector('select[data-input=net-jail]') && "
	    "document.querySelector('button[data-act=route-add]')", 10);
	run("document.querySelector('li[data-act=select-server]').click()");
	wait_js("document.querySelector('button.tab[data-arg=network]')", 10);

	/*
	 * WireGuard, in a host's network tab: an interface without a key
	 * is given one, made on the host, and then a peer.  And BIRD: its
	 * protocols, one of them reloaded.
	 */
	/*
	 * A plugin not installed: its tab is there still, and says what
	 * to install, with a button that installs it by pkg(8).  Put back,
	 * the tab comes alive once the job is done.
	 */
	ATF_REQUIRE(rename("fake-swanctl", "fake-swanctl.off") == 0);
	run("document.querySelector('button[data-act=refresh]').click()");
	wait_js("document.querySelector('button.tab.plugin.missing[data-arg="
	    "ipsec]')", 20);
	run("document.querySelector('button.tab.plugin[data-arg=ipsec]')"
	    ".click()");
	wait_js("document.querySelector('.plugin-missing button[data-act="
	    "plugin-install][data-arg=strongswan]')", 10);
	ATF_CHECK(js_true("document.querySelector('.plugin-missing')."
	    "textContent.includes('Click the button to install it') && "
	    "document.querySelector('.plugin-missing').textContent.includes("
	    "'swanctl(8)')"));
	shot("4p-plugin-missing");
	ATF_REQUIRE(rename("fake-swanctl.off", "fake-swanctl") == 0);
	run("document.querySelector('.plugin-missing button[data-act="
	    "plugin-install]').click()");
	run("const q = document.querySelector('button[data-act=queue-run]'); "
	    "if (q) q.click();");
	for (i = 0; i < 100 && system("grep -q 'install.*strongswan' pkg.log "
	    "2>/dev/null") != 0; i++)
		usleep(100000);
	ATF_CHECK_MSG(i < 100, "no pkg install strongswan");
	wait_js("!document.querySelector('button.tab.plugin.missing') && "
	    "!document.querySelector('.plugin-missing')", 20);

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
	/* The peer's whole key, to read and copy; and the peer changed: its
	 * form filled with what it has, the key that names it fixed. */
	ATF_CHECK(js_true("[...document.querySelectorAll('table.wgpeers "
	    "code.key')].some(c => c.textContent === 'xTIBA5rboUvnH4htodjb6e697"
	    "QjLERt1NAB4mZqp8Dg=') && document.querySelector('table.wgpeers "
	    "button.copy[data-copy]')"));
	run("document.querySelector('.pane.wg button[data-act=wg-peer-edit]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=wg-peer]')", 5);
	run("window.wf = document.querySelector('form[data-form=wg-peer]');");
	ATF_CHECK(js_true("wf.peer.readOnly && wf.peer.value === "
	    "'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=' && wf.endpoint."
	    "value === '192.0.2.9:51820' && wf.allowed.value === "
	    "'10.9.9.2/32'"));
	run("const f = document.querySelector('form[data-form=wg-peer]'); "
	    "f.keepalive.value = '25'; f.persist.checked = false; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 100 && system("grep -q 'persistent-keepalive 25$' "
	    "wg.log") != 0; i++)
		usleep(100000);
	/* What it has now (the stand-in keeps 10.9.9.2/32), with the
	 * keepalive. */
	ATF_CHECK(system("grep -q '^set wg0 peer xTIBA5rboUvnH4htodjb6e697QjLER"
	    "t1NAB4mZqp8Dg= endpoint 192.0.2.9:51820 allowed-ips 10.9.9.2/32 "
	    "persistent-keepalive 25$' wg.log") == 0);
	/* A client: the form offers the next address after the peers', the
	 * host and the port, everything through the tunnel; made, its
	 * configuration is shown once with its QR code, the private key in
	 * it, the host's peer its public half. */
	run("document.querySelector('.pane.wg button[data-act=wg-client-add]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=wg-client]')", 5);
	run("window.wf = document.querySelector('form[data-form=wg-client]');");
	ATF_CHECK(js_true("wf.address.value === '10.9.9.3/32' && wf.endpoint"
	    ".value.endsWith(':51820') && wf.allowed.value === '0.0.0.0/0, ::/0' "
	    "&& wf.keepalive.value === '25'"));
	run("wf.name.value = 'phone'; wf.dns.value = '10.9.9.1'; "
	    "wf.persist.checked = false; wf.requestSubmit();");
	wait_js("document.querySelector('form[data-form=wg-conf] pre.wg-conf') "
	    "&& document.querySelector('form[data-form=wg-conf] svg')", 10);
	run("window.wc = document.querySelector('pre.wg-conf').textContent;");
	ATF_CHECK(js_true("/^\\[Interface\\]\\nPrivateKey = [A-Za-z0-9+\\/]{43}"
	    "=\\nAddress = 10\\.9\\.9\\.3\\/32\\nDNS = 10\\.9\\.9\\.1\\n\\n"
	    "\\[Peer\\]\\nPublicKey = HIgo/.test(wc) && wc.includes('AllowedIPs = "
	    "0.0.0.0/0, ::/0') && wc.includes('PersistentKeepalive = 25') && "
	    "document.querySelector('form[data-form=wg-conf] a[download="
	    "\"phone.conf\"]') !== null"));
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 100 && system("grep -q 'allowed-ips 10.9.9.3/32$' "
	    "wg.log") != 0; i++)
		usleep(100000);
	ATF_CHECK(system("grep -Eq '^set wg0 peer [A-Za-z0-9+/]{43}= "
	    "allowed-ips 10.9.9.3/32 preshared-key .*/\\.wg0\\.psk\\.[0-9a-f]{8}$' "
	    "wg.log") == 0);
	ATF_CHECK(js_true("/\\nPresharedKey = [A-Za-z0-9+\\/]{43}=\\nEndpoint = "
	    "/.test(wc)"));
	shot("7c-wireguard-client");
	run("document.querySelector('.modal button[data-act=close]').click()");
	/* A new key for a client: its address kept, the new peer in and
	 * then the old one out. */
	run("window.rk = document.querySelector('table.wgpeers button"
	    "[data-act=wg-rekey]').dataset.value; document.querySelector("
	    "'table.wgpeers button[data-act=wg-rekey]').click()");
	wait_js("document.querySelector('form[data-form=wg-client]')", 5);
	ATF_CHECK(js_true("document.querySelector('form[data-form=wg-client] "
	    "h2').textContent.startsWith('A new key for a client') && "
	    "document.querySelector('form[data-form=wg-client]').address.value "
	    "=== '10.9.9.2/32'"));
	run("const f = document.querySelector('form[data-form=wg-client]'); "
	    "f.name.value = 'laptop'; f.persist.checked = false; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('form[data-form=wg-conf] pre.wg-conf')",
	    10);
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	{
		ucl_object_t	*rk = js("return window.rk;");
		char		 cmd[300];

		ATF_REQUIRE(rk != NULL && ucl_object_tostring(rk) != NULL);
		snprintf(cmd, sizeof(cmd), "grep -n '' wg.log | grep -A3 "
		    "'allowed-ips 10.9.9.2/32 preshared-key' | grep -qF 'peer %s "
		    "remove'", ucl_object_tostring(rk));
		for (i = 0; i < 100 && system(cmd) != 0; i++)
			usleep(100000);
		ATF_CHECK_MSG(system(cmd) == 0, "the old peer %s was not taken "
		    "away after the new one came", ucl_object_tostring(rk));
		ucl_object_unref(rk);
	}
	/* The stand-in keeps one peer, which went with the old key: the
	 * peer of before, back, for what follows. */
	ATF_REQUIRE(system("printf 'wg0\\txTIBA5rboUvnH4htodjb6e697QjLERt1NAB4"
	    "mZqp8Dg=\\t(none)\\t192.0.2.9:51820\\t10.9.9.2/32\\t0\\t0\\t0\\t0"
	    "\\n' > wg.peers.wg0") == 0);
	run("document.querySelector('.modal button[data-act=close]').click()");
	run("document.querySelector('.dock > header').click()");
	shot("7c-wireguard");
	/*
	 * IPsec, strongSwan: the host makes its key, whose public half is
	 * shown; a connection is made with the form, IKEv2, and its SA is
	 * there.
	 */
	run("document.querySelector('button.tab.plugin[data-arg=ipsec]')"
	    ".click()");
	wait_js("document.querySelector('.pane.ipsec button[data-act="
	    "ipsec-init]')", 20);
	ATF_CHECK(js_true("document.querySelector('.pane.ipsec').textContent."
	    "includes('no key yet')"));
	run("document.querySelector('.pane.ipsec button[data-act=ipsec-init]')"
	    ".click()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("document.querySelector('.pane.ipsec code.key.pub')", 20);
	run("window.pub = document.querySelector('.pane.ipsec code.key.pub')"
	    ".textContent; document.querySelector('.pane.ipsec button"
	    "[data-act=ipsec-conn-add]').click()");
	wait_js("document.querySelector('form[data-form=ipsec-conn]')", 5);
	/* A reqid is an interface's: tunnel mode only. */
	run("const f = document.querySelector('form[data-form=ipsec-conn]'); "
	    "f.conn.value = 'to-lab2'; f.local.value = '192.0.2.1'; "
	    "f.remote.value = '192.0.2.2'; f.mode.value = 'transport'; "
	    "f.pubkey.value = '-----BEGIN PUBLIC KEY-----\\n' + window.pub + "
	    "'\\n-----END PUBLIC KEY-----'; f.local_ts.value = "
	    "'192.0.2.1[gre]'; f.remote_ts.value = '192.0.2.2[gre]'; "
	    "f.reqid.value = '7'; f.start.value = 'start'; f.requestSubmit();");
	wait_js("document.querySelector('form[data-form=ipsec-conn]') && "
	    "document.querySelector('.modal').textContent.includes('tunnel "
	    "mode')", 5);
	shot("7d-ipsec-form");
	phone(true);
	usleep(500000);
	shot("m7d-ipsec-form");
	run("document.querySelector('.modal > form').scrollTop = 1e6;");
	shot("m7d-ipsec-form-end");
	phone(false);
	run("const f = document.querySelector('form[data-form=ipsec-conn]'); "
	    "f.reqid.value = ''; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("document.querySelector('table.ipsec tbody tr.up') && "
	    "document.querySelector('table.ipsec').textContent.includes("
	    "'TRANSPORT')", 20);
	ATF_CHECK(system("grep -q 'version = 2' "
	    "swanctl/conf.d/arcana-to-lab2.conf && grep -q "
	    "'local_ts = 192.0.2.1\\[gre\\]' swanctl/conf.d/arcana-to-lab2.conf "
	    "&& grep -q 'start_action = start' "
	    "swanctl/conf.d/arcana-to-lab2.conf") == 0);
	run("document.querySelector('.dock > header').click()");
	shot("7e-ipsec");
	/* The certificates in swanctl's x509 and x509ca are listed, and a
	 * peer may be known by one; a child of the connection's own,
	 * added and taken away. */
	ATF_CHECK(js_true("[...document.querySelectorAll('table.ipsec-certs "
	    "tbody tr')].some(r => r.textContent.includes('edge-b.pem') && "
	    "r.textContent.includes('CN=edge-b.example')) && [...document."
	    "querySelectorAll('table.ipsec-certs tbody tr')].some(r => r."
	    "textContent.includes('lab-ca.pem') && r.textContent.includes("
	    "'CA'))"));
	/* Until when: a date, and the days left when few. */
	ATF_CHECK(js_true("[...document.querySelectorAll('table.ipsec-certs "
	    "tbody tr')].every(r => /\\d{4}-\\d{2}-\\d{2}/.test(r.lastElementChild"
	    ".textContent) && r.lastElementChild.textContent.includes('in ') "
	    "&& r.lastElementChild.querySelector('.warn'))"));
	shot("7e-ipsec-certs");
	run("document.querySelector('table.ipsec button[data-act="
	    "ipsec-child-add]').click()");
	wait_js("document.querySelector('form[data-form=ipsec-child] "
	    "input[name=child]')", 5);
	run("const f = document.querySelector('form[data-form=ipsec-child]'); "
	    "f.child.value = 'lan'; f.local_ts.value = '10.1.0.0/24'; "
	    "f.remote_ts.value = '10.2.0.0/24'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 200 && system("grep -q 'local_ts = 10.1.0.0/24' "
	    "swanctl/conf.d/arcana-to-lab2.conf 2>/dev/null") != 0; i++)
		usleep(50000);
	if (i == 200) {
		show("arcana-agent.out");
		atf_tc_fail("the child lan was not written");
	}
	wait_js("[...document.querySelectorAll('table.ipsec td .child')].some("
	    "c => c.textContent.includes('lan') && c.textContent.includes("
	    "'TUNNEL'))", 20);
	shot("7e-ipsec-child");
	run("[...document.querySelectorAll('table.ipsec td .child')].find(c => "
	    "c.textContent.includes('lan')).querySelector('button[data-act="
	    "ipsec-unchild]').click()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("![...document.querySelectorAll('table.ipsec td .child')]."
	    "some(c => c.textContent.includes('lan'))", 20);
	/* The form offers the certificate and the CA as ways to know the
	 * peer. */
	run("document.querySelector('button[data-act=ipsec-conn-add]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=ipsec-conn] "
	    "select[name=auth] option[value=cert]') && document.querySelector("
	    "'form[data-form=ipsec-conn] select[name=auth] option[value=ca]')",
	    5);
	run("const s = document.querySelector('form[data-form=ipsec-conn] "
	    "select[name=auth]'); s.value = 'cert'; s.dispatchEvent(new "
	    "Event('input', { bubbles: true }));");
	wait_js("document.querySelector('form[data-form=ipsec-conn] "
	    "select[name=remote_cert] option[value=\"edge-b.pem\"]')", 5);
	shot("7e-ipsec-by-certificate");
	run("document.querySelector('.modal button[data-act=close]').click()");
	wait_js("!document.querySelector('.modal')", 5);
	run("document.querySelector('table.ipsec button[data-act="
	    "ipsec-unconn]').click()");
	wait_js("document.querySelector('form[data-form=confirm]')", 5);
	run("document.querySelector('form[data-form=confirm]')."
	    "requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("!document.querySelector('table.ipsec')", 20);
	run("document.querySelector('button.tab.plugin[data-arg=bird]')"
	    ".click()");
	wait_js("document.querySelectorAll('table.bird tbody tr').length === 4",
	    20);
	ATF_CHECK(js_true("document.querySelector('.pane.bird').textContent."
	    "includes('Router ID is 192.0.2.1')"));
	/* BFD: each session, up or not. */
	ATF_CHECK(js_true("document.querySelector('table.bfd tbody tr.up') && "
	    "document.querySelector('table.bfd').textContent.includes("
	    "'fe80::2')"));
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
	/* A set with comments in it is communities all the same, each
	 * comment kept on its entry's line and written back after the
	 * entry's comma. */
	ATF_CHECK(js_true("[...document.querySelectorAll('.conf-grid ul.blocks "
	    "li')].some(l => l.querySelector('b').textContent === 'PEERS' && "
	    "l.querySelector('.dim').textContent === 'communities')"));
	run("[...document.querySelectorAll('.conf-grid ul.blocks li')].find("
	    "l => l.querySelector('b').textContent === 'PEERS').click()");
	wait_js("document.querySelector('form[data-form=bird-set] textarea') "
	    "&& document.querySelector('form[data-form=bird-set] textarea')"
	    ".value === '# the exchange\\n(65000,300) # ix-a\\n(65000,301) "
	    "/* ix-b */'", 5);
	run("const t = document.querySelector('form[data-form=bird-set] "
	    "textarea'); t.value += '\\n(65000,302)'; t.form.requestSubmit();");
	wait_js("!document.querySelector('.modal') && [...document."
	    "querySelectorAll('.conf-grid ul.blocks li')].some(l => "
	    "l.textContent.includes('(65000,302)'))", 20);
	ATF_CHECK(system("grep -q '^\t# the exchange$' bird/bird.conf && "
	    "grep -q '^\t(65000,300), # ix-a$' bird/bird.conf && grep -q "
	    "'^\t(65000,301), /\\* ix-b \\*/$' bird/bird.conf && grep -q "
	    "'^\t(65000,302)$' bird/bird.conf") == 0);
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

}

/*
 * The certificates OpenSSL trusts: read with OpenSSL, one ending soon
 * said; one given to the host, one distrusted and trusted again.
 */
static void
part_certs(void)
{
	char	 js[8192], pem[4096], *p, *q;
	FILE	*f;
	size_t	 n;
	int	 i;

	ATF_REQUIRE(system("R=tools/certroot; mkdir -p $R/usr/share/certs/"
	    "trusted && for n in root:400 soon:10 mine:400; do openssl req "
	    "-x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "
	    "${n%:*}.key -out ${n%:*}.pem -days ${n#*:} -subj \"/O=Arcana/"
	    "CN=Arcana ${n%:*} CA\" 2>/dev/null || exit 1; done; cp root.pem "
	    "soon.pem $R/usr/share/certs/trusted/ && tools/certctl -D $R "
	    "rehash") == 0);
	run("document.querySelector('button.tab[data-arg=certificates]')"
	    ".click()");
	wait_js("location.hash.endsWith('/certificates') && [...document."
	    "querySelectorAll('table.certs tbody tr')].some(r => r.textContent"
	    ".includes('Arcana root CA') && r.textContent.includes('EC "
	    "prime256v1'))", 20);
	ATF_CHECK(js_true("document.querySelector('.chip.warn').textContent"
	    ".includes('1 ends within 30 days') && [...document."
	    "querySelectorAll('table.certs td.warn')].length === 1"));
	/* One given: its PEM pasted, a key never. */
	ATF_REQUIRE((f = fopen("mine.pem", "r")) != NULL);
	n = fread(pem, 1, sizeof(pem) - 1, f);
	fclose(f);
	pem[n] = '\0';
	q = js + snprintf(js, sizeof(js), "const f = document.querySelector("
	    "'form[data-form=cert-add]'); f.name.value = 'mine'; f.pem.value "
	    "= '");
	for (p = pem; *p != '\0'; p++) {
		if (*p == '\n') {
			*q++ = '\\';
			*q++ = 'n';
		} else
			*q++ = *p;
	}
	snprintf(q, sizeof(js) - (size_t)(q - js), "'; f.requestSubmit();");
	run("document.querySelector('button[data-act=cert-add]').click()");
	wait_js("document.querySelector('form[data-form=cert-add]')", 5);
	run(js);
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('table.certs tbody tr')].some("
	    "r => r.textContent.includes('Arcana mine CA') && r.textContent"
	    ".includes('/usr/local/share/certs/trusted/mine.pem'))", 20);
	run("document.querySelector('.dock > header').click()");
	shot("9-certificates");
	/* Distrusted, and trusted again. */
	run("document.querySelector('button[data-act=cert-untrust][data-arg="
	    "\"root.0\"]').click()");
	wait_js("document.querySelector('.modal button.danger')", 5);
	run("document.querySelector('.modal button.danger').click()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 100 && access("tools/certroot/usr/local/share/certs/"
	    "untrusted/root.0.pem", F_OK) != 0; i++)
		usleep(100000);
	run("document.querySelector('.dock > header').click()");
	run("document.querySelector('button[data-act=certs-show][data-arg="
	    "untrusted]').click()");
	wait_js("[...document.querySelectorAll('table.certs tbody tr')].some("
	    "r => r.textContent.includes('Arcana root CA') && r.querySelector("
	    "'button[data-act=cert-trust]'))", 20);
	run("document.querySelector('button[data-act=cert-trust]').click()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 100 && access("tools/certroot/usr/local/share/certs/"
	    "untrusted/root.0.pem", F_OK) == 0; i++)
		usleep(100000);
	ATF_CHECK(access("tools/certroot/usr/local/share/certs/untrusted/"
	    "root.0.pem", F_OK) != 0);
	run("document.querySelector('.dock > header').click()");
	wait_js("document.querySelectorAll('table.certs tbody tr td.dim')"
	    ".length === 1", 20);
}

/* A file's text as a JavaScript string's, between single quotes. */
static void
js_text(char *out, size_t len, const char *path)
{
	FILE	*f;
	size_t	 o;
	int	 c;

	ATF_REQUIRE((f = fopen(path, "r")) != NULL);
	for (o = 0; o + 3 < len && (c = fgetc(f)) != EOF; ) {
		if (c == '\n') {
			out[o++] = '\\';
			out[o++] = 'n';
		} else if (c == '\'' || c == '\\') {
			out[o++] = '\\';
			out[o++] = (char)c;
		} else
			out[o++] = (char)c;
	}
	out[o] = '\0';
	fclose(f);
}

/*
 * The base system's sshd: a setting changed, the banner, a user's key
 * added and taken away, the host key signed by a CA's.
 */
static void
part_ssh(void)
{
	char	 key[4096], js[8192];
	int	 i;

	ATF_REQUIRE(system("R=tools/sshroot; mkdir -p $R/etc/ssh $R/root "
	    "$R/home/alice && printf 'PermitRootLogin no\\nPasswordAuthentication"
	    " yes\\n' > $R/etc/ssh/sshd_config && printf 'root:*:0:0::/root:"
	    "/bin/sh\\nalice:*:%d:%d:Alice:/home/alice:/bin/sh\\n' $(id -u) "
	    "$(id -g) > $R/etc/passwd && ssh-keygen -q -t ed25519 -N '' -C host "
	    "-f $R/etc/ssh/ssh_host_ed25519_key && ssh-keygen -q -t ed25519 -N "
	    "'' -C alice@lab -f alice_key && ssh-keygen -q -t ed25519 -N '' -C "
	    "lab-ca -f lab_ca") == 0);
	run("document.querySelector('button.tab[data-arg=ssh]').click()");
	wait_js("location.hash.endsWith('/ssh') && [...document."
	    "querySelectorAll('table.ssh-set tbody tr')].some(r => r."
	    "textContent.includes('PermitRootLogin') && r.textContent."
	    "includes('no'))", 20);
	ATF_CHECK(js_true("[...document.querySelectorAll('table.ssh-hk tbody "
	    "tr')].some(r => r.textContent.includes('ssh-ed25519') && r."
	    "textContent.includes('SHA256:'))"));
	/* A setting, from what it takes. */
	run("document.querySelector('button[data-act=ssh-set][data-arg="
	    "PermitRootLogin]').click()");
	wait_js("document.querySelector('form[data-form=ssh-set] select')", 5);
	run("const f = document.querySelector('form[data-form=ssh-set]'); "
	    "f.value.value = 'prohibit-password'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('table.ssh-set tbody tr')]"
	    ".some(r => r.textContent.includes('prohibit-password'))", 20);
	ATF_CHECK(system("grep -qx 'PermitRootLogin prohibit-password' "
	    "tools/sshroot/etc/ssh/sshd_config") == 0);
	run("document.querySelector('.dock > header').click()");
	/* The banner. */
	run("const f = document.querySelector('form[data-form=ssh-banner]'); "
	    "f.text.value = 'Authorised use only.'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	/* The file first, then sshd_config naming it. */
	for (i = 0; i < 100 && system("grep -qx 'Banner /etc/ssh/banner' "
	    "tools/sshroot/etc/ssh/sshd_config") != 0; i++)
		usleep(100000);
	ATF_CHECK(system("grep -qx 'Authorised use only.' "
	    "tools/sshroot/etc/ssh/banner") == 0);
	run("document.querySelector('.dock > header').click()");
	/* alice's key, added and taken away. */
	js_text(key, sizeof(key), "alice_key.pub");
	run("document.querySelector('button[data-act=ssh-key-add][data-arg="
	    "alice]').click()");
	wait_js("document.querySelector('form[data-form=ssh-key]')", 5);
	snprintf(js, sizeof(js), "const f = document.querySelector('form"
	    "[data-form=ssh-key]'); f.key.value = '%s'; f.requestSubmit();",
	    key);
	run(js);
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('table.ssh-keys tbody tr')]"
	    ".some(r => r.textContent.includes('alice@lab'))", 20);
	run("document.querySelector('.dock > header').click()");
	run("document.querySelector('button[data-act=ssh-key-del]').click()");
	wait_js("document.querySelector('.modal button.danger')", 5);
	run("document.querySelector('.modal button.danger').click()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("![...document.querySelectorAll('table.ssh-keys tbody tr')]"
	    ".some(r => r.textContent.includes('alice@lab'))", 20);
	ATF_CHECK(system("test ! -s tools/sshroot/home/alice/.ssh/"
	    "authorized_keys") == 0);
	run("document.querySelector('.dock > header').click()");
	/* The host key signed: the CA's key given once. */
	js_text(key, sizeof(key), "lab_ca");
	run("document.querySelector('button[data-act=ssh-sign]').click()");
	wait_js("document.querySelector('form[data-form=ssh-sign]')", 5);
	snprintf(js, sizeof(js), "const f = document.querySelector('form"
	    "[data-form=ssh-sign]'); f.key.value = '%s'; f.principals.value = "
	    "'lab.example lab'; f.requestSubmit();", key);
	run(js);
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('table.ssh-hk tbody tr')]"
	    ".some(r => r.textContent.includes('for lab.example lab'))", 20);
	ATF_CHECK(system("grep -qx 'HostCertificate /etc/ssh/"
	    "ssh_host_ed25519_key-cert.pub' tools/sshroot/etc/ssh/sshd_config")
	    == 0);
	ATF_CHECK(system("ls -a tools/sshroot/etc/ssh | grep -q arcana-ca") !=
	    0);
	run("document.querySelector('.dock > header').click()");
	/* Nothing wider than the page. */
	ATF_CHECK(js_true("document.querySelector('.stage').scrollWidth <= "
	    "document.querySelector('.stage').clientWidth + 1"));
	shot("9b-ssh");
	run("document.querySelector('table.ssh-hk').scrollIntoView()");
	shot("9c-ssh-keys");
}

static void
part_storage(void)
{
	char		 web[MAXPATHLEN], script[2048];
	char		*token;
	FILE		*fp;
	int		 i;

	(void)web;
	(void)script;
	(void)token;
	(void)fp;
	(void)i;

	/*
	 * Storage: the pools with their devices, the datasets, a snapshot
	 * taken and one destroyed once its name is typed, the disks as
	 * the kernel has them, what is mounted, and fstab edited.
	 */
	run("document.querySelector('button.tab[data-arg=storage]').click()");
	wait_js("document.querySelector('section.pool[data-pool=tank] table."
	    "vdevs tr.bad')", 20);
	ATF_CHECK(js_true("document.querySelector('section.pool').textContent"
	    ".includes('DEGRADED') && document.querySelectorAll('table.vdevs "
	    "tbody tr').length === 4 && document.querySelector('table.vdevs "
	    "button[data-arg=online]')"));
	shot("7j-storage-pools");
	run("[...document.querySelectorAll('section.pool button[data-act="
	    "st-zpool]')].find(b => b.dataset.arg === 'scrub').click()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('zpool scrub tank: done'))", 20);
	ATF_CHECK(system("grep -q '^zpool scrub tank$' storage.log") == 0);
	run("document.querySelector('.dock > header').click()");
	/* A pool made of two devices that mirror each other; one found
	 * on the host's devices imported. */
	run("document.querySelector('button[data-act=st-pool-new]').click()");
	wait_js("document.querySelector('form[data-form=st-pool-new] select"
	    "[name=layout]')", 5);
	run("const f = document.querySelector('form[data-form=st-pool-new]'); "
	    "f.name.value = 'lab'; f.layout.value = 'mirror'; f.devices.value "
	    "= 'ada8p1 ada9p1'; f.mountpoint.value = '/srv/lab'; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('zpool create lab mirror ada8p1 ada9p1 "
	    "mountpoint=/srv/lab: done'))", 20);
	ATF_CHECK(system("grep -q '^zpool create -m /srv/lab lab mirror ada8p1 "
	    "ada9p1$' storage.log") == 0);
	run("document.querySelector('.dock > header').click()");
	wait_js("document.querySelector('button[data-act=st-pool-import]')", 20);
	run("document.querySelector('button[data-act=st-pool-import]')."
	    "click()");
	wait_js("document.querySelector('.modal li[data-act=st-import]"
	    "[data-arg=spare]')", 10);
	shot("7j-storage-import");
	run("document.querySelector('.modal li[data-act=st-import]').click()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('zpool import spare: done'))", 20);
	run("document.querySelector('.dock > header').click()");
	/* A device replaced, by the one named. */
	wait_js("document.querySelector('table.vdevs button[data-act=st-vdev]"
	    "[data-arg=replace]')", 20);
	run("[...document.querySelectorAll('table.vdevs button[data-act="
	    "st-vdev][data-arg=replace]')].find(b => b.dataset.value === "
	    "'tank ada2p1').click()");
	wait_js("document.querySelector('form[data-form=st-vdev-replace] input"
	    "[name=device]')", 5);
	run("const f = document.querySelector('form[data-form=st-vdev-replace]"
	    "'); f.device.value = 'ada6p1'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('zpool replace tank ada2p1 ada6p1: done'))",
	    20);
	ATF_CHECK(system("grep -q '^zpool replace tank ada2p1 ada6p1$' "
	    "storage.log") == 0);
	run("document.querySelector('.dock > header').click()");
	wait_js("document.querySelector('button[data-act=st-kind][data-arg="
	    "datasets]')", 20);
	run("document.querySelector('button[data-act=st-kind][data-arg="
	    "datasets]').click()");
	wait_js("document.querySelector('table.datasets tr[data-ds=\"tank/data"
	    "\"]')", 20);
	ATF_CHECK(js_true("document.querySelector('table.datasets').textContent"
	    ".includes('volume') && !document.querySelector('table.datasets tr"
	    "[data-ds=tank] button[data-act=st-destroy]')"));
	shot("7k-storage-datasets");
	/* Every table sorts by a column picked, and back; the filter
	 * leaves the rows that have the text. */
	run("[...document.querySelectorAll('table.datasets th.sortable')]"
	    ".find(t => t.textContent === 'Used').click()");
	wait_js("document.querySelector('table.datasets th.asc') && document."
	    "querySelector('table.datasets tbody tr').dataset.ds === "
	    "'tank/vol'", 5);
	run("document.querySelector('table.datasets th.asc').click()");
	wait_js("document.querySelector('table.datasets th.desc') && document."
	    "querySelector('table.datasets tbody tr').dataset.ds === 'tank'",
	    5);
	run("document.querySelector('table.datasets th.desc').click()");
	wait_js("!document.querySelector('table.datasets th.asc, table.datasets "
	    "th.desc')", 5);
	run("const i = document.getElementById('filter'); i.value = 'vol'; "
	    "i.dispatchEvent(new Event('input', { bubbles: true }));");
	wait_js("document.querySelectorAll('table.datasets tbody tr').length "
	    "=== 1", 5);
	run("const i = document.getElementById('filter'); i.value = ''; "
	    "i.dispatchEvent(new Event('input', { bubbles: true }));");
	wait_js("document.querySelectorAll('table.datasets tbody tr').length "
	    "=== 3", 5);
	run("document.querySelector('table.datasets tr[data-ds=\"tank/data\"] "
	    "button[data-act=st-snapshot]').click()");
	wait_js("document.querySelector('form[data-form=st-snapshot] input"
	    "[name=name]')", 5);
	run("const f = document.querySelector('form[data-form=st-snapshot]'); "
	    "f.name.value = 'before'; f.recursive.checked = true; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('zfs snapshot tank/data@before: done'))",
	    20);
	ATF_CHECK(system("grep -q '^zfs snapshot -r tank/data@before$' "
	    "storage.log") == 0);
	run("document.querySelector('.dock > header').click()");
	/* Its snapshots; one destroyed, once it is confirmed: nothing is
	 * typed for a snapshot. */
	wait_js("document.querySelector('table.datasets tr[data-ds=\"tank/data"
	    "\"] button[data-act=st-snaps-of]')", 20);
	run("document.querySelector('table.datasets tr[data-ds=\"tank/data\"] "
	    "button[data-act=st-snaps-of]').click()");
	wait_js("document.querySelectorAll('table.snapshots tbody tr').length "
	    "=== 2", 20);
	run("document.querySelector('table.snapshots tr[data-snap=\"tank/data@a"
	    "\"] button[data-act=st-destroy]').click()");
	wait_js("document.querySelector('form[data-form=confirm]')", 5);
	ATF_CHECK(js_true("!document.querySelector('form[data-form=confirm] "
	    "input')"));
	run("document.querySelector('form[data-form=confirm]')."
	    "requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('zfs destroy tank/data@a: done'))", 20);
	ATF_CHECK(system("grep -q '^zfs destroy tank/data@a$' storage.log") ==
	    0);
	run("document.querySelector('.dock > header').click()");
	/*
	 * Several picked, here all of them, and destroyed at once: one
	 * question, one batch of a job each.
	 */
	run("document.querySelector('input[data-act=st-sel-all]').click()");
	wait_js("document.querySelectorAll('table.snapshots tr.picked')."
	    "length === 2 && document.querySelector('button[data-act="
	    "st-destroy-sel]').textContent === 'Destroy 2'", 5);
	shot("7l-snapshots-picked");
	run("document.querySelector('button[data-act=st-destroy-sel]')."
	    "click()");
	wait_js("document.querySelector('form[data-form=confirm]') && "
	    "!document.querySelector('form[data-form=confirm] input')", 5);
	run("document.querySelector('form[data-form=confirm]')."
	    "requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 200 && system("[ $(grep -c '^zfs destroy tank/data@' "
	    "storage.log) -ge 3 ]") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^zfs destroy tank/data@b$' storage.log && "
	    "[ $(grep -c '^zfs destroy tank/data@a$' storage.log) -eq 2 ]") ==
	    0);
	ATF_CHECK(js_true("!document.querySelector('button[data-act="
	    "st-destroy-sel]')"));
	run("document.querySelector('.dock > header').click()");
	/* The newest of a dataset's snapshots, and only it, taken again
	 * under its name: the new one first, then the old one goes. */
	ATF_CHECK(js_true("document.querySelector('table.snapshots tr[data-"
	    "snap=\"tank/data@b\"] button[data-act=st-resnap]') && !document."
	    "querySelector('table.snapshots tr[data-snap=\"tank/data@a\"] "
	    "button[data-act=st-resnap]')"));
	run("document.querySelector('table.snapshots tr[data-snap=\"tank/data@b"
	    "\"] button[data-act=st-resnap]').click()");
	wait_js("document.querySelector('form[data-form=confirm]') && "
	    "!document.querySelector('form[data-form=confirm] input')", 5);
	run("document.querySelector('form[data-form=confirm]')."
	    "requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('zfs resnapshot tank/data@b: done'))", 20);
	ATF_CHECK(system("grep -A2 '^zfs snapshot tank/data@b.resnap$' "
	    "storage.log | tr '\\n' '|' | grep -q '^zfs snapshot "
	    "tank/data@b.resnap|zfs destroy tank/data@b|zfs rename "
	    "tank/data@b.resnap tank/data@b|'") == 0);
	run("document.querySelector('.dock > header').click()");
	/*
	 * A snapshot sent to another host: chosen in Replicate's box, the
	 * console carrying it, and listed with what it carried.
	 */
	ATF_REQUIRE(system("dd if=/dev/random of=zsend.data bs=1m count=6 "
	    "2>/dev/null") == 0);
	run("document.querySelector('table.snapshots tr[data-snap=\"tank/data@b"
	    "\"] button[data-act=st-ask][data-arg=replicate]').click()");
	wait_js("document.querySelector('form select[name=to]') && "
	    "document.querySelector('form select[name=to]').options.length "
	    "=== 2", 5);
	run("const f = document.querySelector('form select[name=to]').form; "
	    "f.to.selectedIndex = 1; f.name.value = 'tank/copy'; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('ul.xfers li.done') && document."
	    "querySelector('ul.xfers li.done').textContent.includes("
	    "'tank/data@b') && document.querySelector('ul.xfers li.done')."
	    "textContent.includes('6.00M')", 30);
	ATF_CHECK(system("cmp -s zsend.data zrecv.data") == 0);
	shot("7l-transfer");
	/* Several at once: the newest of each dataset picked, and taken
	 * again in one batch; one picked that is not the newest left. */
	run("document.querySelector('button[data-act=st-sel-newest]').click()");
	wait_js("document.querySelectorAll('table.snapshots tr.picked')."
	    "length === 1 && document.querySelector('table.snapshots tr."
	    "picked').dataset.snap === 'tank/data@b' && document."
	    "querySelector('button[data-act=st-resnap-sel]').textContent "
	    "=== 'Resnapshot 1'", 5);
	run("document.querySelector('table.snapshots tr[data-snap=\"tank/data@a"
	    "\"] input[data-act=st-sel]').click()");
	wait_js("document.querySelectorAll('table.snapshots tr.picked')."
	    "length === 2 && document.querySelector('button[data-act="
	    "st-resnap-sel]').textContent === 'Resnapshot 1'", 5);
	shot("7l-snapshots-resnap");
	run("document.querySelector('button[data-act=st-resnap-sel]').click()");
	wait_js("document.querySelector('form[data-form=confirm]') && "
	    "document.querySelector('form[data-form=confirm]').textContent."
	    "includes('not the newest of their dataset are left')", 5);
	run("document.querySelector('form[data-form=confirm]')."
	    "requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 200 && system("[ $(grep -c '^zfs rename "
	    "tank/data@b.resnap tank/data@b$' storage.log) -ge 2 ]") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("[ $(grep -c '^zfs rename tank/data@b.resnap "
	    "tank/data@b$' storage.log) -eq 2 ] && ! grep -q 'tank/data@a."
	    "resnap' storage.log") == 0);
	ATF_CHECK(js_true("!document.querySelector('table.snapshots tr."
	    "picked')"));
	run("document.querySelector('.dock > header').click()");
	/* The disks are this machine's own. */
	run("document.querySelector('button[data-act=st-kind][data-arg=disks]')"
	    ".click()");
	wait_js("document.querySelector('section.disk, .empty')", 20);
	shot("7l-storage-disks");
	/*
	 * How the disks say they are; a dataset that is encrypted, its
	 * key loaded where it is kept; a snapshot sent into a new one.
	 */
	run("document.querySelector('button[data-act=st-kind][data-arg=health]"
	    "').click()");
	wait_js("document.querySelectorAll('table.health tbody tr').length "
	    "=== 3 && document.querySelector('table.health .chip.ok') && "
	    "document.querySelector('table.health .chip.bad').textContent "
	    "=== 'failing' && document.querySelector('table.health')."
	    "textContent.includes('88 reallocated sectors')", 20);
	shot("7m-storage-health");
	run("document.querySelector('button[data-act=st-kind][data-arg="
	    "datasets]').click()");
	wait_js("document.querySelector('tr[data-ds=\"tank/data\"] .chip.warn')"
	    " && document.querySelector('tr[data-ds=\"tank/data\"] button"
	    "[data-act=st-key][data-arg=load-key]')", 20);
	run("document.querySelector('tr[data-ds=\"tank/data\"] button"
	    "[data-act=st-key]').click()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 200 && system("grep -q '^zfs load-key tank/data$' "
	    "storage.log 2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^zfs load-key tank/data$' storage.log") ==
	    0);
	run("document.querySelector('tr[data-ds=\"tank/data\"] button"
	    "[data-act=st-ask][data-arg=jail]').click()");
	wait_js("document.querySelector('form[data-form=st-ask] input[name="
	    "name]')", 5);
	run("const f = document.querySelector('form[data-form=st-ask]'); "
	    "f.name.value = 'web'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 200 && system("grep -q '^zfs jail web tank/data$' "
	    "storage.log 2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^zfs jail web tank/data$' storage.log") ==
	    0);
	run("document.querySelector('.dock > header').click()");
	/* fstab, with a line more. */
	run("document.querySelector('button[data-act=st-kind][data-arg=mounts]"
	    "').click()");
	wait_js("document.querySelector('table.fstab tr[data-fs=\"/mnt/data\"] "
	    "button[data-act=st-mount]')", 20);
	ATF_CHECK(js_true("document.querySelector('table.swap') && document."
	    "querySelector('button[data-act=st-ask][data-arg=swapon]')"));
	shot("7m-storage-mounts");
	run("document.querySelector('button[data-act=st-fstab]').click()");
	wait_js("document.querySelector('form[data-form=st-fstab] textarea') "
	    "&& document.querySelector('form[data-form=st-fstab] textarea')"
	    ".value.includes('/mnt/data')", 10);
	run("const t = document.querySelector('form[data-form=st-fstab] "
	    "textarea'); t.value += 'not an entry\\n'; t.form.requestSubmit();");
	wait_js("document.querySelector('.modal .err') && document."
	    "querySelector('.modal .err').textContent.includes('an entry is "
	    "a device')", 10);
	run("const t = document.querySelector('form[data-form=st-fstab] "
	    "textarea'); t.value = t.value.replace('not an entry\\n', "
	    "'/dev/ada0p5\\t/mnt/web\\tufs\\trw\\t2\\t2\\n'); "
	    "t.form.requestSubmit();");
	wait_js("!document.querySelector('.modal') && document.querySelector("
	    "'table.fstab tr[data-fs=\"/mnt/web\"]')", 20);
	ATF_CHECK(system("grep -q '/mnt/web' fstab && ! grep -q '/mnt/web' "
	    "fstab.arcana-old") == 0);
	run("document.querySelector('table.fstab tr[data-fs=\"/mnt/web\"] "
	    "button[data-act=st-mount]').click()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('mount /mnt/web: done'))", 20);
	ATF_CHECK(system("grep -q '^mount -F .*/fstab /mnt/web$' storage.log")
	    == 0);
	run("document.querySelector('.dock > header').click()");

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
	    "f.name.value = 'if_disc'; f.persist.checked = true; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('kldload if_disc: done'))", 20);
	ATF_CHECK(system("grep -q '^kldload -n if_disc$' kld.log && grep -q "
	    "'^kld_list=\"if_disc\"$' rc.conf") == 0);
	/* Kept, and not in this kernel: said.  A module hardly ever
	 * loaded, so that the kernel the test runs on has not. */
	wait_js("document.querySelector('.notice.info') && document."
	    "querySelector('.notice.info').textContent.includes('if_disc')", 20);
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
	    "t.textContent.includes('kldunload ' + window.kld + ': done'))",
	    20);
	ATF_CHECK(system("grep -q '^kldunload ' kld.log") == 0);
	run("document.querySelector('.dock > header').click()");

	/*
	 * The kernel's state: a part of the tree, read from the kernel;
	 * another part named; one value set in its row, and kept.
	 */
	run("document.querySelector('button.tab[data-arg=sysctl]').click()");
	wait_js("document.querySelectorAll('table.sysctl tbody tr').length > "
	    "20 && [...document.querySelectorAll('table.sysctl tbody tr b')]."
	    "some(b => b.textContent === 'kern.ostype')", 20);
	ATF_CHECK(js_true("document.querySelector('.sy-kept').textContent."
	    "includes('kern.ipc.somaxconn=')"));
	/* Sorted by a column, as every table is. */
	run("document.querySelector('table.sysctl th[data-act=t-sort]')."
	    "click()");
	wait_js("document.querySelector('table.sysctl th.sortable.up, "
	    "table.sysctl th.sortable.down, table.sysctl th.sortable.asc, "
	    "table.sysctl th.sortable.desc')", 5);
	run("document.querySelector('table.sysctl th[data-act=t-sort]')."
	    "click(); document.querySelector('table.sysctl th[data-act=t-sort]')"
	    ".click();");
	shot("7n-sysctl");
	/*
	 * A column is as wide as its border is dragged, and stays so when
	 * the table is drawn again; a double click on the border lets it
	 * be as wide as what is in it.
	 */
	{
		double	x, y, w0, w1;

		x = js_num("document.querySelector('table.sysctl th')."
		    "getBoundingClientRect().right");
		y = js_num("(r => r.y + r.height / 2)(document.querySelector("
		    "'table.sysctl th').getBoundingClientRect())");
		w0 = js_num("document.querySelector('table.sysctl th')."
		    "getBoundingClientRect().width");
		mouse("pointerMove", x - 2, y);
		mouse("pointerDown", 0, 0);
		mouse("pointerMove", x + 70, y);
		mouse("pointerUp", 0, 0);
		usleep(1300000);
		w1 = js_num("document.querySelector('table.sysctl th')."
		    "getBoundingClientRect().width");
		ATF_CHECK_MSG(w1 > w0 + 50, "the column was %.0f wide and is "
		    "%.0f after its border was dragged by 72", w0, w1);
		ATF_CHECK(js_true("document.querySelector('table.sysctl th')."
		    "style.width !== ''"));
		run("const th = document.querySelector('table.sysctl th'), r = "
		    "th.getBoundingClientRect(); th.dispatchEvent(new MouseEvent("
		    "'dblclick', { bubbles: true, cancelable: true, clientX: "
		    "r.right - 2, clientY: r.y + 4 }));");
		wait_js("document.querySelector('table.sysctl th').style.width "
		    "=== ''", 5);
	}
	/*
	 * The whole tree comes in parts, over the console's socket, and
	 * the table fills as they arrive: more of it than one reply was
	 * ever allowed to carry.
	 */
	run("document.querySelector('button[data-act=sy-tree][data-arg=\"\"]')"
	    ".click()");
	wait_js("document.querySelector('.toolbar .age').textContent."
	    "includes('so far') || /[0-9]+ more/.test(document.querySelector("
	    "'.stage').textContent)", 20);
	wait_js("!document.querySelector('.toolbar .age').textContent."
	    "includes('reading') && (m => m && parseInt(m[1], 10) > 3600)("
	    "/([0-9]+) more/.exec(document.querySelector('.stage')."
	    "textContent))", 60);
	ATF_CHECK(js_true("[...document.querySelectorAll('table.sysctl tbody "
	    "tr b')].some(b => b.textContent === 'kern.ostype')"));
	run("const f = document.querySelector('form[data-form=sy-from]'); "
	    "f.name.value = 'kern.ipc.somaxconn'; f.requestSubmit();");
	wait_js("document.querySelectorAll('table.sysctl tbody tr').length "
	    "=== 1 && document.querySelector('table.sysctl button[data-act="
	    "sy-edit]')", 20);
	run("document.querySelector('table.sysctl button[data-act=sy-edit]')."
	    "click()");
	wait_js("document.querySelector('form[data-form=sy-set] input[name="
	    "value]')", 5);
	/* It is kept already: so says the box, ticked. */
	wait_js("document.querySelector('form[data-form=sy-set] "
	    "input[name=persist]').checked", 5);
	run("const f = document.querySelector('form[data-form=sy-set]'); "
	    "f.value.value = '8192'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('sysctl kern.ipc.somaxconn=8192: done'))",
	    20);
	ATF_CHECK(system("grep -q '^sysctl kern.ipc.somaxconn=8192$' kld.log "
	    "&& grep -q '^kern.ipc.somaxconn=8192$' sysctl.conf") == 0);
	run("document.querySelector('.dock > header').click()");

	/*
	 * What runs: in the order of what each uses; one picked is given
	 * a nice value, and sent a signal once that is confirmed.
	 */
	ATF_REQUIRE(system("sleep 300 & echo $! > sleep.pid") == 0);
	{
		char	pid[16], cmd[96];

		ATF_REQUIRE((fp = fopen("sleep.pid", "r")) != NULL);
		ATF_REQUIRE(fgets(pid, sizeof(pid), fp) != NULL);
		fclose(fp);
		pid[strcspn(pid, "\n")] = '\0';
		run("document.querySelector('button.tab[data-arg=processes]')"
		    ".click()");
		snprintf(script, sizeof(script), "document.querySelectorAll("
		    "'table.procs tbody tr').length > 3 && document."
		    "querySelector('table.procs tr[data-arg=\"%s\"]')", pid);
		wait_js(script, 20);
		ATF_CHECK(js_true("document.querySelector('.ps-sum')."
		    "textContent.includes('processes') && document."
		    "querySelector('button[data-act=ps-live].on')"));
		/* By memory: the most first, and so the table says. */
		run("document.querySelector('button[data-act=ps-sort]"
		    "[data-arg=\"6\"]').click()");
		wait_js("document.querySelector('table.procs th.sortable.desc') "
		    "&& document.querySelector('table.procs th.sortable.desc')"
		    ".textContent === 'Res' && document.querySelector("
		    "'button[data-act=ps-sort][data-arg=\"6\"].on')", 5);
		for (i = 0; i < 4; i++) {
			static const char *const by[] = { "8", "9", "10", "6" };

			snprintf(script, sizeof(script), "document."
			    "querySelector('button[data-act=ps-sort][data-arg="
			    "\"%s\"]').click()", by[i]);
			run(script);
			snprintf(script, sizeof(script), "document."
			    "querySelector('button[data-act=ps-sort][data-arg="
			    "\"%s\"].on')", by[i]);
			wait_js(script, 5);
		}
		shot("7r-processes");
		snprintf(script, sizeof(script), "const r = document."
		    "querySelector('table.procs tr[data-arg=\"%s\"]'); "
		    "r.scrollIntoView({ block: 'center' }); r.click()", pid);
		run(script);
		wait_js("document.querySelector('form[data-form=ps-renice]') "
		    "&& document.querySelector('.ps-what code').textContent."
		    "includes('sleep 300') && document.querySelector("
		    "'table.ps-threads tbody tr')", 10);
		shot("7r-process-picked");
		run("const f = document.querySelector('form[data-form="
		    "ps-renice]'); f.nice.value = '7'; f.requestSubmit();");
		wait_js("document.querySelector('button[data-act=queue-run]')",
		    5);
		run("document.querySelector('button[data-act=queue-run]')."
		    "click()");
		snprintf(cmd, sizeof(cmd), "[ \"$(ps -o nice= -p %s | tr -d "
		    "' ')\" = 7 ]", pid);
		for (i = 0; i < 200 && system(cmd) != 0; i++)
			usleep(50000);
		ATF_CHECK(system(cmd) == 0);
		run("const f = document.querySelector('form[data-form="
		    "ps-signal]'); f.signal.value = 'KILL'; f.requestSubmit();");
		wait_js("document.querySelector('form[data-form=confirm]') && "
		    "document.querySelector('.modal').textContent.includes("
		    "'SIGKILL')", 5);
		run("document.querySelector('form[data-form=confirm]')."
		    "requestSubmit()");
		wait_js("document.querySelector('button[data-act=queue-run]')",
		    5);
		run("document.querySelector('button[data-act=queue-run]')."
		    "click()");
		snprintf(cmd, sizeof(cmd), "! kill -0 %s 2>/dev/null", pid);
		for (i = 0; i < 200 && system(cmd) != 0; i++)
			usleep(50000);
		ATF_CHECK(system(cmd) == 0);
		run("document.querySelector('.dock > header').click()");
	}

	/*
	 * A log: its lines taken apart, the newest first; a text searched
	 * for on the host; and what is written while it is shown.
	 */
	run("document.querySelector('button.tab[data-arg=log]').click()");
	wait_js("document.querySelectorAll('table.logs tbody tr').length === "
	    "3 && document.querySelector('table.logs tbody tr b').textContent "
	    "=== 'cron' && document.querySelectorAll('label.lg-file option')"
	    ".length === 5", 20);
	run("const f = document.querySelector('form[data-form=lg-find]'); "
	    "f.text.value = 'publickey for'; f.requestSubmit();");
	wait_js("document.querySelectorAll('table.logs tbody tr').length === "
	    "1 && document.querySelector('table.logs tbody tr b').textContent "
	    "=== 'sshd'", 10);
	run("const f = document.querySelector('form[data-form=lg-find]'); "
	    "f.text.value = ''; f.requestSubmit();");
	wait_js("document.querySelectorAll('table.logs tbody tr').length === "
	    "3", 10);
	ATF_REQUIRE(system("printf 'Oct  5 12:00:09 web1 ntpd[5]: time set"
	    "\\nOct  5 12:00:10 web1 kernel: em0: link state changed to DOWN"
	    "\\n' >> log/messages") == 0);
	wait_js("document.querySelectorAll('table.logs tbody tr').length === "
	    "5 && document.querySelector('table.logs tbody tr.l-warn td.msg')"
	    ".textContent.includes('changed to DOWN')", 15);
	shot("7s-log");
	run("const s = document.querySelector('label.lg-file select'); "
	    "s.value = 'auth.log'; s.dispatchEvent(new Event('input', "
	    "{ bubbles: true }));");
	wait_js("document.querySelectorAll('table.logs tbody tr').length === "
	    "1 && document.querySelector('table.logs tbody tr b').textContent "
	    "=== 'su'", 10);

	/* A jail's own logs; the kernel's messages, or why not. */
	if (js_true("document.querySelector('button[data-act=lg-jail]"
	    "[data-arg=gw]')")) {
		run("document.querySelector('button[data-act=lg-jail]"
		    "[data-arg=gw]').click()");
		wait_js("document.querySelector('table.logs tbody tr td.msg') "
		    "&& document.querySelector('table.logs tbody tr td.msg')."
		    "textContent === \"the jail's own line\"", 10);
		run("document.querySelector('button[data-act=lg-jail]"
		    "[data-arg=\"\"]').click()");
		wait_js("document.querySelectorAll('table.logs tbody tr')."
		    "length === 5", 10);
	}
	run("const s = document.querySelector('label.lg-file select'); "
	    "s.value = '@dmesg'; s.dispatchEvent(new Event('input', "
	    "{ bubbles: true }));");
	wait_js("document.querySelector('table.logs tbody tr') || document."
	    "querySelector('.notice.bad')", 10);
	/* What the kernel told the agent, in the same place. */
	run("const s = document.querySelector('label.lg-file select'); "
	    "s.value = '@events'; s.dispatchEvent(new Event('input', "
	    "{ bubbles: true }));");
	wait_js("document.querySelector('.stage').textContent.includes("
	    "'events, the newest first') && document.querySelector("
	    "'label.lg-file select').value === '@events'", 10);
	/* Told as it happens, not asked for: a limit of the memory's
	 * crossed is shown as the agent tells it, over the stream. */
	wait_js("document.querySelector('.stage').textContent.includes("
	    "'the moment the agent tells it')", 10);
	run("window.evt0 = performance.now(); window.lim = (cpu, mem) => fetch('/api/servers').then(r => "
	    "r.json()).then(j => Promise.all(j.servers.map(s => fetch("
	    "'/api/servers/' + s.id + '/history', { method: 'POST', headers: "
	    "{ 'Content-Type': 'application/json', 'X-Arcana': '1' }, body: "
	    "JSON.stringify({ step: 5, keep: 720, cpu: cpu, mem: mem, swap: "
	    "50 }) }))));");
	/* The agent samples every five seconds and the console asks for
	 * events every five: two clocks in a row, and the page's draw. */
	run("window.lim(90, 1);");
	wait_js("[...document.querySelectorAll('table.logs tbody tr')].some("
	    "r => r.textContent.includes('threshold') && r.textContent."
	    "includes('mem at'))", 40);
	/* Nothing was asked again for it: it came by itself. */
	ATF_CHECK(js_true("!performance.getEntriesByType('resource').some("
	    "e => e.name.includes('/events?after=') && e.startTime > "
	    "window.evt0)"));
	/* And the way back under, as well, while it stays followed. */
	run("window.lim(90, 90);");
	wait_js("[...document.querySelectorAll('table.logs tbody tr')].some("
	    "r => r.textContent.includes('back under its limit of 90%')) && "
	    "document.querySelector('.stage').textContent.includes("
	    "'the moment the agent tells it')", 40);
	shot("7r-events-live");
	run("const s = document.querySelector('label.lg-file select'); "
	    "s.value = 'auth.log'; s.dispatchEvent(new Event('input', "
	    "{ bubbles: true }));");
	wait_js("document.querySelectorAll('table.logs tbody tr').length === "
	    "1", 10);

	/*
	 * How busy the hosts have been: the agent kept it by itself, and
	 * it is drawn as lines.
	 */
	run("document.querySelector('li[data-act=select-usage]').click()");
	wait_js("document.querySelectorAll('section.ucard').length === 2 && "
	    "document.querySelectorAll('section.ucard figure.uplot').length "
	    "=== 10 && document.querySelectorAll('section.ucard figure.uplot "
	    "svg path.line').length >= 10 && document.querySelectorAll("
	    "'.uplots.compare figure.uplot').length === 3 && document."
	    "querySelectorAll('.uplots.compare .ukey').length === 6", 30);
	ATF_CHECK(js_true("document.querySelector('.crumb.place').textContent "
	    "=== 'Utilization' && document.querySelector('section.ucard h4')"
	    ".textContent.includes('CPUs')"));
	run("document.querySelector('button[data-act=usage-window][data-arg="
	    "\"300\"]').click()");
	wait_js("document.querySelector('button[data-act=usage-window]"
	    "[data-arg=\"300\"].on')", 5);
	/*
	 * The network is all the interfaces or the one picked, by name;
	 * how the agent samples is said with what it takes, and set.
	 */
	ATF_CHECK(js_true("[...document.querySelectorAll('section.ucard "
	    "figure.uplot figcaption b')].some(b => /^Network · all [0-9]+ "
	    "interfaces$/.test(b.textContent)) && document.querySelector("
	    "'section.ucard h4 small').textContent.includes('every 5 s, 720 "
	    "kept (1 h)')"));
	if (js_true("document.querySelector('button[data-act=usage-net]"
	    ":not([data-value=\"\"])')")) {
		run("window.ifn = document.querySelector('button[data-act="
		    "usage-net]:not([data-value=\"\"])'); window.ifn = "
		    "window.ifn.dataset.value; document.querySelector("
		    "'button[data-act=usage-net]:not([data-value=\"\"])')."
		    "click()");
		wait_js("[...document.querySelectorAll('section.ucard "
		    "figure.uplot figcaption b')].some(b => b.textContent "
		    "=== 'Network · ' + window.ifn) && document.querySelector("
		    "'button[data-act=usage-net].on').dataset.value === "
		    "window.ifn", 5);
	}
	run("document.querySelectorAll('main, .stage').forEach(e => { "
	    "e.scrollTop = 0; })");
	usleep(300000);
	shot("7t-usage");
	run("document.querySelector('button[data-act=usage-cfg]').click()");
	wait_js("document.querySelector('form[data-form=usage-set]') && "
	    "document.querySelector('form[data-form=usage-set] small.dim')."
	    "textContent.includes('interfaces') && document.querySelector("
	    "'form[data-form=usage-set] input[name=cpu]').value === '90'", 5);
	shot("7t-usage-sampling");
	/* The limits of devices and jails, a line each. */
	run("const f = document.querySelector('form[data-form=usage-set]'); "
	    "f.step.value = '2'; f.keep.value = '50'; f.rules.value = "
	    "'net:lo0=1000000\\n jail-mem:web=1073741824\\n'; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('section.ucard h4 small').textContent"
	    ".includes('every 2 s, 50 kept') && !document.querySelector("
	    "'form[data-form=usage-set]') && document.querySelectorAll("
	    "'section.ucard figure.uplot svg path.line').length >= 10", 30);
	ATF_CHECK(system("grep -q '^step=2$' history.conf && grep -q "
	    "'^keep=50$' history.conf") == 0);
	ATF_CHECK(system("grep -q '^rule=net:lo0=1000000$' history.conf && "
	    "grep -q '^rule=jail-mem:web=1073741824$' history.conf") == 0);
	/* Without the kernel's accounting, what turns it on is said. */
	ATF_CHECK(js_true("document.querySelector('section.ucard p.ujails') "
	    "? document.querySelector('section.ucard p.ujails').textContent."
	    "includes('kern.racct.enable') : document.querySelector("
	    "'section.ucard .ujails')"));
	run("document.querySelector('section.ucard .uname').click()");
	wait_js("document.querySelector('button.tab[data-arg=log].on')", 5);
	part_certs();
	part_ssh();
}

static void
part_firewall(void)
{
	char		 web[MAXPATHLEN], script[2048];
	char		*token;
	FILE		*fp;
	int		 i;

	(void)web;
	(void)script;
	(void)token;
	(void)fp;
	(void)i;

	/*
	 * The firewall: the layout with a tab for each of its parts; a
	 * part's rules, those of now and those only kept; a rule added
	 * now and kept; the kept rules as a text; and applied through
	 * set 1, which stays once the console is heard from again.
	 */
	run("document.querySelector('button.tab[data-arg=firewall]').click()");
	/* The layout is in the side bar, a line for each part, in place of
	 * the hosts; the light that says it is on is the switch. */
	wait_js("document.querySelectorAll('.fwrail .titem.fw').length >= 34 "
	    "&& document.querySelector('table.fw-layout tr.pick')", 20);
	ATF_CHECK(js_true("document.querySelector('button.switch.on[data-act="
	    "fw-onoff]') && document.querySelector('.fw-count').textContent."
	    "includes('7 rules now') && !document.querySelector('.tree "
	    ".titem.server')"));
	shot("7o-firewall-layout");
	run("document.querySelector('.fwrail .titem.fw[data-arg=\"10\"]')."
	    "click()");
	wait_js("document.querySelector('table.fw-rules tr[data-rule=\"1001\"]"
	    "') && document.querySelector('table.fw-rules tr[data-rule="
	    "\"1002\"].off')", 10);
	ATF_CHECK(js_true("document.querySelector('table.fw-rules tr[data-rule="
	    "\"1001\"]').textContent.includes('now, kept') && document."
	    "querySelector('table.fw-rules tr[data-rule=\"1002\"]')."
	    "textContent.includes('kept, not loaded') && document."
	    "querySelector('form[data-form=fw-add]').num.value === '1003'"));
	/* Read again while the part is shown: what a rule takes, drawn. */
	wait_js("document.querySelector('table.fw-rules tr[data-rule=\"1001\"]"
	    " svg.hits polyline') && document.querySelector('button.live.on"
	    "[data-act=fw-live]')", 30);
	shot("7o-firewall-hits");
	/* A rule dragged above another: its row opened with the number
	 * between, for Save to move it there. */
	run("const a = document.querySelector('table.fw-rules tr[data-rule="
	    "\"1999\"]'), b = document.querySelector('table.fw-rules "
	    "tr[data-rule=\"1001\"]'), d = new DataTransfer(), r = b."
	    "getBoundingClientRect(), y = r.top + 2; "
	    "a.dispatchEvent(new DragEvent('dragstart', { bubbles: true, "
	    "dataTransfer: d })); b.dispatchEvent(new DragEvent('dragover', "
	    "{ bubbles: true, cancelable: true, dataTransfer: d, clientY: y "
	    "})); b.dispatchEvent(new DragEvent('drop', { bubbles: true, "
	    "cancelable: true, dataTransfer: d, clientY: y })); "
	    "a.dispatchEvent(new DragEvent('dragend', { bubbles: true, "
	    "dataTransfer: d }));");
	wait_js("document.querySelector('table.fw-rules tr.editing[data-rule="
	    "\"1999\"] input[name=num]') && document.querySelector('table."
	    "fw-rules tr.editing[data-rule=\"1999\"] input[name=num]')."
	    "value === '1000'", 5);
	/* Not saved: the row closed again as it was. */
	run("document.querySelector('table.fw-rules tr.editing button"
	    "[data-act=fw-edit][data-arg=\"0\"]').click()");
	wait_js("!document.querySelector('table.fw-rules tr.editing')", 5);
	/* A rule's words offered as it is typed, by ipfw's order: after
	 * from, the addresses and the host's tables; then to. */
	run("const i = document.querySelector('form[data-form=fw-add] "
	    "input[name=rule]'); i.value = 'allow tcp from '; "
	    "i.dispatchEvent(new Event('input', { bubbles: true }));");
	wait_js("(() => { const o = [...document.querySelectorAll("
	    "'#fw-words option')].map(e => e.value); return o.includes("
	    "'allow tcp from any') && o.includes('allow tcp from me6') && "
	    "o.includes('allow tcp from table(T46)'); })()", 5);
	run("const i = document.querySelector('form[data-form=fw-add] "
	    "input[name=rule]'); i.value = 'allow tcp from any '; "
	    "i.dispatchEvent(new Event('input', { bubbles: true }));");
	wait_js("[...document.querySelectorAll('#fw-words option')].some(e => "
	    "e.value === 'allow tcp from any to')", 5);
	run("const i = document.querySelector('form[data-form=fw-add] "
	    "input[name=rule]'); i.value = 'sk'; "
	    "i.dispatchEvent(new Event('input', { bubbles: true }));");
	wait_js("[...document.querySelectorAll('#fw-words option')].some(e => "
	    "e.value === 'skipto')", 5);
	run("const i = document.querySelector('form[data-form=fw-add] "
	    "input[name=rule]'); i.value = ''; "
	    "i.dispatchEvent(new Event('input', { bubbles: true }));");
	run("const f = document.querySelector('form[data-form=fw-add]'); "
	    "f.num.value = '1500'; f.rule.value = 'allow tcp from any to me6 "
	    "8443 in'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('ipfw add 1500') && t.textContent."
	    "includes('done'))", 20);
	ATF_CHECK(system("grep -q '^ipfw -q add 1500 allow tcp from any to me6 "
	    "8443 in$' ipfw.log && grep -q '^add 01500 allow tcp from any to "
	    "me6 8443 in$' ipfw.rules") == 0);
	run("document.querySelector('.dock > header').click()");
	/* A rule's number is one of its part's. */
	run("const f = document.querySelector('form[data-form=fw-add]'); "
	    "f.num.value = '5'; f.rule.value = 'allow ip from any to any'; "
	    "f.requestSubmit();");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('from 1000 to 1999'))", 5);
	/* A rule is pressed, and changed in its own row: the words it is
	 * kept with are the ones in the field; saved, the old one goes
	 * and the new one comes, now and kept. */
	wait_js("document.querySelector('table.fw-rules tr.pick[data-rule="
	    "\"1001\"]')", 20);
	run("document.querySelector('table.fw-rules tr.pick[data-rule=\"1001\"]"
	    "').click()");
	wait_js("document.querySelector('form[data-form=fw-edit] input[name="
	    "rule]')", 5);
	ATF_CHECK(js_true("document.querySelector('form[data-form=fw-edit]')."
	    "rule.value === 'allow tcp from any to me6 22 in' && document."
	    "querySelector('form[data-form=fw-edit]').live.checked && document"
	    ".querySelector('form[data-form=fw-edit]').persist.checked"));
	shot("7o-firewall-part");
	/* One job: the new rule read by ipfw first, then the old one out
	 * and the new one in; an interface's pattern, quoted the shell's
	 * way, given to ipfw without its quotes. */
	run("const f = document.querySelector('form[data-form=fw-edit]'); "
	    "f.rule.value = 'allow tcp from any to me6 2222 in via \"wg[0-1]\"'; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('ipfw 1001 changed: 1001 allow tcp from any "
	    "to me6 2222') && t.textContent.includes('done'))", 20);
	ATF_CHECK(system("grep -n '' ipfw.log | grep -A9 'ipfw -q -n add 1001 "
	    "allow tcp from any to me6 2222 in via wg\\[0-1\\]$' | grep -q "
	    "'ipfw -q delete 1001$' && grep -q '^ipfw -q add 1001 allow tcp from "
	    "any to me6 2222 in via wg\\[0-1\\]$' ipfw.log && grep -q '^add "
	    "01001 allow tcp from any to me6 2222 in via wg\\[0-1\\]$' "
	    "ipfw.rules && ! grep -q 'me6 22 in' ipfw.rules") == 0);
	run("document.querySelector('.dock > header').click()");
	/* The kept rules as a text, and the connections let through now,
	 * read again by themselves. */
	run("document.querySelector('.fwrail .titem.fw[data-arg=\"-3\"]')."
	    "click()");
	wait_js("document.querySelector('form[data-form=fw-text] textarea') && "
	    "document.querySelector('form[data-form=fw-text] textarea').value."
	    "includes('add 01500 allow')", 10);
	run("document.querySelector('.fwrail .titem.fw[data-arg=\"-2\"]')."
	    "click()");
	wait_js("document.querySelectorAll('table.fw-dyn tbody tr').length === "
	    "2 && document.querySelector('table.fw-dyn').textContent.includes("
	    "'2001:db8::9 51234 <-> 2001:db8::1 22') && document.querySelector("
	    "'button.live.on[data-act=fw-live]')", 20);
	shot("7o-firewall-dynamic");
	/* A file of the host's own that the firewall loads now, as
	 * rc.conf names it: read again with the rules. */
	ATF_REQUIRE(system("printf -- '-f flush\\nadd 100 allow ip from any "
	    "to any via lo0\\n' > host.rules && printf 'firewall_type=\"%s/"
	    "host.rules\"\\n' \"$(pwd)\" >> rc.conf") == 0);
	run("window.fwn = 0; window.fetch1 = window.fetch; window.fetch = "
	    "function (u, o) { if (String(u).includes('/net/ipfw')) window.fwn"
	    "++; return window.fetch1(u, o); };");
	wait_js("window.fwn >= 2", 15);
	run("window.fetch = window.fetch1;");
	/* A state pressed leads to the rule that made it. */
	run("document.querySelector('table.fw-dyn tbody tr').click()");
	wait_js("document.querySelector('table.fw-rules tr[data-rule=\"1001\"]"
	    "')", 10);
	/* That file loaded as the kept rules' text, not kept until Keep. */
	run("document.querySelector('.fwrail .titem.fw[data-arg=\"-3\"]')."
	    "click()");
	wait_js("document.querySelector('button[data-act=fw-load-rc]')", 10);
	run("document.querySelector('button[data-act=fw-load-rc]').click()");
	wait_js("document.querySelector('form[data-form=fw-text] textarea')"
	    ".value === '# left out, applying does it: -f flush\\nadd 100 "
	    "allow ip from any to any via lo0\\n' && document.querySelector("
	    "'.notice.info').textContent.includes('host.rules, not kept yet')",
	    10);
	shot("7p-firewall-load-rc");
	ATF_CHECK(system("grep -q 'add 01500 allow' ipfw.rules && ! grep -q "
	    "'via lo0' ipfw.rules") == 0);
	/* A script of the host's own, as firewall_script names it, read
	 * first: its ipfw commands taken out, its own lines as comments. */
	ATF_REQUIRE(system("printf '#!/bin/sh\\nfwcmd=\"/sbin/ipfw -q\"\\n"
	    "${fwcmd} add 200 allow ip from any to any via lo0\\n' > fw.sh && "
	    "printf 'firewall_script=\"%s/fw.sh\"\\n' \"$(pwd)\" >> rc.conf")
	    == 0);
	run("window.fwn = 0; window.fetch = function (u, o) { if (String(u)"
	    ".includes('/net/ipfw')) window.fwn++; return window.fetch1(u, o); "
	    "};");
	run("document.querySelector('button.tab[data-arg=summary]').click()");
	run("document.querySelector('button.tab[data-arg=firewall]').click()");
	wait_js("window.fwn >= 1", 15);
	run("window.fetch = window.fetch1;");
	run("document.querySelector('.fwrail .titem.fw[data-arg=\"-3\"]')."
	    "click()");
	wait_js("document.querySelector('button[data-act=fw-load-rc]') && "
	    "document.querySelector('button[data-act=fw-load-rc]').title"
	    ".includes('fw.sh')", 10);
	run("document.querySelector('button[data-act=fw-load-rc]').click()");
	wait_js("document.querySelector('form[data-form=fw-text] textarea')"
	    ".value === '# left out, the script\\'s own: fwcmd=\"/sbin/ipfw -q\""
	    "\\nadd 200 allow ip from any to any via lo0\\n'", 10);
	ATF_REQUIRE(system("sed -i '' -e '/^firewall_type=/d' -e "
	    "'/^firewall_script=/d' rc.conf") == 0);
	/*
	 * A table and what is in it, an entry more; what Apply would
	 * change; a packet followed through the rules; the firewall of
	 * a jail with a network of its own.
	 */
	run("document.querySelector('.fwrail li[data-act=fw-sect][data-arg="
	    "\"-4\"]').click()");
	wait_js("document.querySelectorAll('table.fwentries tbody tr').length "
	    "=== 2 && document.querySelector('section.fwtable h4').textContent"
	    ".includes('T46')", 10);
	run("const f = document.querySelector('form[data-form=fw-entry]'); "
	    "f.key.value = '198.51.100.0/24'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 200 && system("grep -q '^ipfw -q table T46 add "
	    "198.51.100.0/24$' ipfw.log 2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^ipfw -q table T46 add 198.51.100.0/24$' "
	    "ipfw.log") == 0);
	run("document.querySelector('.dock > header').click()");
	shot("7o-firewall-tables");
	run("document.querySelector('.fwrail li[data-act=fw-sect][data-arg="
	    "\"-6\"]').click()");
	wait_js("document.querySelector('table.fw-diff tr.d-add') && document."
	    "querySelector('table.fw-diff tr.d-del') && document."
	    "querySelector('.stage').textContent.includes('added ·')", 10);
	shot("7o-firewall-diff");
	run("document.querySelector('.fwrail li[data-act=fw-sect][data-arg="
	    "\"-7\"]').click()");
	wait_js("document.querySelector('form[data-form=fw-trace]')", 10);
	run("const f = document.querySelector('form[data-form=fw-trace]'); "
	    "f.src.value = '2001:db8::9'; f.dst.value = '2001:db8::1'; "
	    "f.port.value = '22'; f.requestSubmit();");
	wait_js("document.querySelectorAll('ol.fw-steps li').length === 2 && "
	    "document.querySelector('ol.fw-steps li').textContent.includes("
	    "'into 9100') && document.querySelector('.stage .notice.bad')."
	    "textContent.includes('dropped')", 10);
	shot("7o-firewall-trace");
	/* And the kernel's own answer, for an address: the packets it
	 * decided, each with the rule that did, a press away. */
	ATF_CHECK(js_true("document.querySelector('form[data-form=fw-ktrace]')"
	    ".address.value === '2001:db8::1'"));
	run("const f = document.querySelector('form[data-form=fw-ktrace]'); "
	    "f.address.value = '10.0.0.2'; f.seconds.value = '3'; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('table.ktrace tbody tr') && document."
	    "querySelector('table.ktrace tbody tr').textContent.includes("
	    "'pass') && document.querySelector('table.ktrace button[data-act="
	    "fw-goto][data-arg=\"100\"]')", 20);
	ATF_CHECK(system("grep -q '^tick-3s$' trace.d") == 0);
	shot("7o-firewall-ktrace");
	run("document.querySelector('.fwrail li[data-act=fw-sect][data-arg="
	    "\"-5\"]').click()");
	wait_js("document.querySelector('form[data-form=fw-object] select')",
	    10);
	/* A NAT instance and a pipe, by what they are: ipfw's words made
	 * of the forms, and kept. */
	run("const f = document.querySelector('form[data-form=fw-nat]'); "
	    "f.num.value = '7'; f.what.value = 'em0'; f.deny_in.checked = "
	    "true; f.redirects.value = 'tcp 10.0.0.5:80 8080\\nudp "
	    "10.0.0.6:53 53'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 200 && system("grep -q '^nat 7 config' ipfw.rules "
	    "2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^ipfw -q nat 7 config if em0 same_ports "
	    "deny_in redirect_port tcp 10.0.0.5:80 8080 redirect_port udp "
	    "10.0.0.6:53 53$' ipfw.log && grep -q '^nat 7 config if em0 "
	    "same_ports deny_in' ipfw.rules") == 0);
	run("document.querySelector('.dock > header').click()");
	run("const f = document.querySelector('form[data-form=fw-pipe]'); "
	    "f.num.value = '3'; f.bw.value = '20'; f.delay.value = '15'; "
	    "f.plr.value = '1'; f.mask.value = 'src'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	for (i = 0; i < 200 && system("grep -q '^ipfw -q pipe 3 config' "
	    "ipfw.log 2>/dev/null") != 0; i++)
		usleep(50000);
	ATF_CHECK(system("grep -q '^ipfw -q pipe 3 config bw 20Mbit/s delay "
	    "15 plr 0.01 mask src-ip 0xffffffff$' ipfw.log") == 0);
	run("document.querySelector('.dock > header').click()");
	/* What is not a number is said, and nothing is done. */
	run("const f = document.querySelector('form[data-form=fw-pipe]'); "
	    "f.num.value = '3'; f.bw.value = 'fast'; f.requestSubmit();");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('are numbers'))", 5);
	shot("7o-firewall-objects");
	run("document.querySelector('.fwrail li[data-act=fw-sect][data-arg="
	    "\"-8\"]').click()");
	wait_js("document.querySelector('.stage').textContent.includes("
	    "'Logged packets')", 10);
	run("document.querySelector('.fwrail li[data-act=fw-jail]:not("
	    "[data-arg=\"\"])') && document.querySelector('.fwrail "
	    "li[data-act=fw-jail]:not([data-arg=\"\"])').click()");
	usleep(700000);
	run("document.querySelector('.fwrail li[data-act=fw-jail][data-arg="
	    "\"\"]').click()");
	wait_js("document.querySelector('table.fw-layout')", 20);
	/* Back to the hosts, and to the layout again. */
	run("document.querySelector('.fwrail button[data-act=fw-rail]')."
	    "click()");
	wait_js("document.querySelector('.tree .titem.server') && document."
	    "querySelector('.fwbar button[data-act=fw-rail]')", 5);
	run("document.querySelector('.fwbar button[data-act=fw-rail]').click()");
	wait_js("document.querySelector('.fwrail .titem.fw')", 5);
	run("document.querySelector('button[data-act=fw-apply]').click()");
	wait_js("document.querySelector('form[data-form=confirm]')", 5);
	run("document.querySelector('form[data-form=confirm]').requestSubmit()");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('ipfw apply') && t.textContent.includes("
	    "'done'))", 40);
	ATF_CHECK(system("grep -q '^ipfw -q set disable 1$' ipfw.log && [ "
	    "\"$(grep -c 'set swap 0 1' ipfw.log)\" = 1 ] && grep -q '^ipfw "
	    "-q -f delete set 1$' ipfw.log && grep -q '^add 01500 set 1 allow' "
	    "loaded.rules") == 0);
	run("document.querySelector('.dock > header').click()");

	/*
	 * A bridge, drawn as a switch: each port by what the spanning tree
	 * made of it; a member that has an address is marked; a port made
	 * an access port.
	 */
	run("document.querySelector('button.tab[data-arg=network]').click()");
	wait_js("document.querySelector('button[data-act=net-kind][data-arg="
	    "bridges]')", 10);
	run("document.querySelector('button[data-act=net-kind][data-arg="
	    "bridges]').click()");
	wait_js("document.querySelectorAll('.pane.bridge .ports .port').length "
	    "=== 3", 20);
	ATF_CHECK(js_true("document.querySelector('.ports .port.st-forwarding')"
	    ".textContent.includes('epair5a') && document.querySelector("
	    "'.ports .port.st-discarding').textContent.includes('tap3') && "
	    "document.querySelector('.ports .port.st-nostp').textContent."
	    "includes('trunk 10-20,30') && document.querySelector('.ports "
	    ".port.st-nostp .warn') && document.querySelector('.pane.bridge')."
	    "textContent.includes('filters VLANs')"));
	/* What it has learned, and its own options, unfolded and set. */
	ATF_CHECK(js_true("document.querySelector('table.brmac') && document."
	    "querySelector('table.brmac').textContent.includes("
	    "'02:00:00:00:00:01') && document.querySelector('form[data-form="
	    "br-set] input[name=priority]')"));
	shot("7p-bridge");
	/* A bridge's box folds at its head, and unfolds. */
	run("document.querySelector('.pane.bridge .boxhead .chev').click()");
	wait_js("!document.querySelector('.pane.bridge .ports') && document."
	    "querySelector('.pane.bridge .boxhead.shut')", 5);
	run("document.querySelector('.pane.bridge .boxhead .chev').click()");
	wait_js("document.querySelector('.pane.bridge .ports')", 5);
	run("document.querySelector('.ports .port.st-nostp').click()");
	wait_js("document.querySelector('form[data-form=br-port]')", 5);
	ATF_CHECK(js_true("document.querySelector('.pane.bridge .notice.warn')"
	    ".textContent.includes('192.0.2.7')"));
	run("const f = document.querySelector('form[data-form=br-port]'); "
	    "f.mode.value = 'access'; f.untagged.value = '30'; "
	    "f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('bridge0 access') && t.textContent."
	    "includes('done'))", 20);
	ATF_CHECK(system("grep -q '^bridge0 ifuntagged em1 30 iftagged em1 "
	    "none$' ifconfig.log") == 0);
	run("document.querySelector('.dock > header').click()");

	/* Geneve tunnels: both modes; one made, to a group. */
	wait_js("document.querySelector('button[data-act=net-kind][data-arg="
	    "geneve]')", 20);
	run("document.querySelector('button[data-act=net-kind][data-arg="
	    "geneve]').click()");
	wait_js("document.querySelectorAll('table.geneve tbody tr.pick')."
	    "length === 2", 20);
	ATF_CHECK(js_true("document.querySelector('table.geneve').textContent."
	    "includes('l3') && document.querySelector('table.geneve')."
	    "textContent.includes('[ff08::db8:1]:6081')"));
	run("document.querySelector('button[data-act=gn-pick][data-arg=\"+\"]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=gn-set] select[name="
	    "mode]')", 5);
	shot("7q-geneve");
	run("const f = document.querySelector('form[data-form=gn-set]'); "
	    "f.name.value = 'geneve9'; f.mode.value = 'l3'; f.id.value = '9'; "
	    "f.local.value = '192.0.2.1'; f.group.value = '239.0.0.9'; "
	    "f.dev.value = 'em0'; f.ttl.value = 'inherit'; f.requestSubmit();");
	wait_js("document.querySelector('button[data-act=queue-run]')", 5);
	run("document.querySelector('button[data-act=queue-run]').click()");
	wait_js("[...document.querySelectorAll('.toast')].some(t => "
	    "t.textContent.includes('geneve9 create') && t.textContent."
	    "includes('done'))", 20);
	ATF_CHECK(system("grep -q '^geneve9 create genevemode l3 geneveid 9 "
	    "genevelocal 192.0.2.1 genevegroup 239.0.0.9 genevedev em0 "
	    "genevettl inherit genevelearn -genevedscpinherit "
	    "-geneveexternal$' ifconfig.log") == 0);
	run("document.querySelector('.dock > header').click()");

	/*
	 * How the host is reached, on its summary: the agent's listener,
	 * the console's own connection among those open now.  A local
	 * socket is not switched to anything.
	 */
	run("document.querySelector('button.tab[data-arg=summary]').click()");
	wait_js("document.querySelector('.transport ul.listeners li.up') && "
	    "document.querySelector('table.sessions tbody tr')", 20);
	ATF_CHECK(js_true("document.querySelector('.transport ul.listeners')."
	    "textContent.includes('the console\\'s way in') && !document."
	    "querySelector('button[data-act=tr-switch]') && document."
	    "querySelector('table.sessions tbody').textContent.includes("
	    "'unix')"));
	/* A line is the address, and what it means is said when hovered. */
	ATF_CHECK(js_true("!document.querySelector('.transport ul.listeners')"
	    ".textContent.includes('title=') && document.querySelector("
	    "'.transport ul.listeners li').title.length > 10"));
	/* Green is before the console's own way in, and before no other. */
	ATF_CHECK(js_true("document.querySelectorAll('.transport ul.listeners "
	    "li.up').length === 1 && document.querySelector('.transport "
	    "ul.listeners li.up .chip')"));
	shot("1e-transport");

	/*
	 * The host's rollback timer, beside it: saved, said, and the
	 * agent's own again when emptied.
	 */
	ATF_CHECK(js_true("document.querySelector('form[data-form=tr-safe]') "
	    "!== null && document.body.textContent.includes('Rollback "
	    "timer')"));
	run("var f = document.querySelector('form[data-form=tr-safe]'); "
	    "f.querySelector('input[name=wait]').value = '30'; "
	    "f.requestSubmit();");
	wait_js("document.body.textContent.includes('This host waits 30 s')",
	    10);
	run("var f = document.querySelector('form[data-form=tr-safe]'); "
	    "f.querySelector('input[name=wait]').value = ''; "
	    "f.requestSubmit();");
	wait_js("document.body.textContent.includes('its agent\\'s own')",
	    10);

	/*
	 * Connections are read again by themselves while they are shown,
	 * until paused.
	 */
	run("document.querySelector('button.tab[data-arg=network]').click()");
	wait_js("document.querySelector('button[data-act=net-kind][data-arg="
	    "connections]')", 10);
	run("document.querySelector('button[data-act=net-kind][data-arg="
	    "connections]').click()");
	wait_js("document.querySelector('button.live.on')", 10);
	/* They come over the stream: what is sent on it is counted. */
	run("window.nets = 0; window.ws0 = WebSocket.prototype.send; "
	    "WebSocket.prototype.send = function (t) { if (String(t)."
	    "includes('\"what\":\"connections\"')) window.nets++; return "
	    "window.ws0.call(this, t); };");
	wait_js("window.nets >= 2", 15);
	run("document.querySelector('button[data-act=net-live]').click()");
	wait_js("!document.querySelector('button.live.on')", 5);
	usleep(2500000);
	run("window.nets = 0;");
	usleep(4500000);
	ATF_CHECK_MSG(js_true("window.nets === 0"), "paused, the connections "
	    "were still read again");
	run("WebSocket.prototype.send = window.ws0; document.querySelector("
	    "'button[data-act=net-live]').click()");

}

static void
part_flows(void)
{
	char		 web[MAXPATHLEN], script[2048];
	char		*token;
	FILE		*fp;
	int		 i;

	(void)web;
	(void)script;
	(void)token;
	(void)fp;
	(void)i;

	/*
	 * Workflows: one made in the editor, its steps' forms from
	 * jobs.json, a parameter, a condition; run, its chain drawn as it
	 * went, a step's trace; and the queue kept as one.
	 */
	run("document.querySelector('li.titem.wfnode').click()");
	wait_js("document.querySelector('button[data-act=wf-new]')", 10);
	/* A template: Arcana kept up to date, its four steps Arcana's own,
	 * each after the check only when its head is newer. */
	run("const t = document.querySelector('select[data-input=wf-template]'"
	    "); t.value = 'arcana-update'; t.dispatchEvent(new Event('input', "
	    "{ bubbles: true }));");
	wait_js("document.querySelectorAll('li.wfedstep').length === 4 && "
	    "[...document.querySelectorAll('select[data-input=wf-type]')].map("
	    "s => s.value).join() === 'arcana:check,arcana:build,arcana:agents,"
	    "arcana:console' && document.querySelectorAll('li.wfedstep "
	    ".wfwhen').length === 3", 10);
	shot("9-workflow-template");
	run("document.querySelector('button[data-act=wf-back]').click()");
	wait_js("document.querySelector('button[data-act=wf-new]')", 10);
	/* And one that installs a plugin's package, by a parameter. */
	run("const t = document.querySelector('select[data-input=wf-template]'"
	    "); t.value = 'plugin-install'; t.dispatchEvent(new Event('input', "
	    "{ bubbles: true }));");
	wait_js("document.querySelectorAll('li.wfedstep').length === 1 && "
	    "document.querySelector('select[data-input=wf-kind]').value === "
	    "'pkg-install' && document.querySelector('input[data-arg=\"text:"
	    "params.0.default\"]').value === 'bird3'", 10);
	run("document.querySelector('button[data-act=wf-back]').click()");
	wait_js("document.querySelector('button[data-act=wf-new]')", 10);
	run("document.querySelector('button[data-act=wf-new]').click()");
	wait_js("document.querySelector('select[data-input=wf-kind]') && "
	    "document.querySelector('select[data-input=wf-kind]').options."
	    "length > 25", 10);
	{
		/* What a page's input does: its value, then the event. */
		static const char set[] = "window.setf = (sel, v) => { const e = "
		    "document.querySelector(sel); if (e.type === 'checkbox') "
		    "e.checked = v; else e.value = v; e.dispatchEvent(new Event("
		    "'input', { bubbles: true })); };";

		run(set);
	}
	run("setf('input[data-arg=\"text:name\"]', 'restart a service')");
	run("document.querySelector('button[data-act=wf-param-add]').click()");
	wait_js("document.querySelector('input[data-arg=\"text:params.0.name\"]')",
	    5);
	run("setf('input[data-arg=\"text:params.0.name\"]', 'svc'); "
	    "setf('input[data-arg=\"text:params.0.default\"]', 'ntpd')");
	/* The first step's kind: its fields, those it needs marked. */
	run("setf('select[data-input=wf-kind]', 'service-action')");
	wait_js("document.querySelector('input[data-arg=\"text:steps.0.job."
	    "service\"]') && document.querySelector('select[data-arg=\"text:"
	    "steps.0.job.action\"]')", 5);
	run("setf('input[data-arg=\"text:steps.0.job.service\"]', "
	    "'${param.svc}'); setf('select[data-arg=\"text:steps.0.job."
	    "action\"]', 'restart')");
	/* Only when the jail web is stopped, as a read of the jails says. */
	run("document.querySelector('input[data-act=wf-when]').click()");
	wait_js("document.querySelector('select[data-input=wf-when-of]')", 5);
	run("setf('select[data-input=wf-when-of]', 'read:jails'); "
	    "setf('input[data-arg=\"text:steps.0.when.path\"]', "
	    "'jails[name=web].state'); setf('select[data-arg=\"text:steps.0."
	    "when.op\"]', 'eq'); setf('input[data-arg=\"text:steps.0.when."
	    "value\"]', 'stopped')");
	/* A second step: a read of the host. */
	run("document.querySelector('button[data-act=wf-step-add]').click()");
	wait_js("document.querySelectorAll('li.wfedstep').length === 2", 5);
	run("setf('select[data-input=wf-type][data-arg=\"1\"]', 'read:hello')");
	/*
	 * Steps dragged by their number to another place: the read put
	 * first, and back again.
	 */
	run("window.dragto = (from, to, where) => { const g = document."
	    "querySelector('li.wfedstep[data-arg=\"' + from + '\"] .grip'), "
	    "t = document.querySelector('li.wfedstep[data-arg=\"' + to + "
	    "'\"]'), b = t.getBoundingClientRect(), dt = new DataTransfer(), "
	    "y = where === 'before' ? b.top + 2 : b.bottom - 2; g.dispatchEvent("
	    "new DragEvent('dragstart', { bubbles: true, dataTransfer: dt })); "
	    "t.dispatchEvent(new DragEvent('dragover', { bubbles: true, "
	    "cancelable: true, dataTransfer: dt, clientY: y })); t.dispatchEvent("
	    "new DragEvent('drop', { bubbles: true, cancelable: true, "
	    "dataTransfer: dt, clientY: y })); g.dispatchEvent(new DragEvent("
	    "'dragend', { bubbles: true, dataTransfer: dt })); };");
	run("dragto(1, 0, 'before')");
	wait_js("document.querySelector('select[data-input=wf-type][data-arg="
	    "\"0\"]').value === 'read:hello'", 5);
	run("dragto(1, 0, 'before')");
	wait_js("document.querySelector('select[data-input=wf-type][data-arg="
	    "\"1\"]').value === 'read:hello' && document.querySelector("
	    "'input[data-arg=\"text:steps.0.job.service\"]').value === "
	    "'${param.svc}'", 5);
	/* On a failure of the first, on at the second: drawn as a jump. */
	run("setf('select[data-arg=\"text:steps.0.on_fail\"]', document."
	    "querySelector('input[data-arg=\"text:steps.1.id\"]').value)");
	shot("9a-workflow-edit");
	run("document.querySelector('button[data-act=wf-save]').click()");
	wait_js("document.querySelector('ul.wflist button[data-act=wf-run]') "
	    "&& document.querySelector('ul.wflist').textContent.includes("
	    "'restart a service')", 10);
	run("document.querySelector('ul.wflist button[data-act=wf-run]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=wf-run] input"
	    "[name=p_svc]')", 5);
	run("const f = document.querySelector('form[data-form=wf-run]'); "
	    "f.p_svc.value = 'sshd'; f.requestSubmit();");
	wait_js("document.querySelectorAll('.wfgraph button.wfstep.done')."
	    "length === 2", 30);
	/* The jump drawn under the row, not taken: the first did not fail. */
	ATF_CHECK(js_true("document.querySelector('.wfgraph .wfjump') && "
	    "!document.querySelector('.wfgraph .wfjump.taken') && document."
	    "querySelector('.wfgraph .wfjump').textContent.includes("
	    "'on a failure')"));
	/* The run is a task of the activity bar too, and ended there. */
	wait_js("document.querySelector('.dock').textContent.includes("
	    "'workflow restart a service') && document.querySelector('.dock')"
	    ".textContent.includes('done')", 15);
	run("document.querySelector('.wfgraph button.wfstep').click()");
	wait_js("document.querySelector('section.wftrace') && document."
	    "querySelector('section.wftrace').textContent.includes('sshd')",
	    10);
	shot("9b-workflow-run");
	/* What waits in the queue, kept as one. */
	run("document.querySelector('button[data-act=wf-back]').click()");
	ATF_CHECK(js_true("document.querySelector('ul.wfruns li.done')"));
	run("document.querySelector('li.titem.server').click()");
	wait_js("document.querySelector('button.tab[data-arg=services]')", 10);
	run("document.querySelector('button.tab[data-arg=services]').click()");
	wait_js("document.querySelector('button[data-act=svc][data-value="
	    "restart]')", 10);
	run("document.querySelector('button[data-act=svc][data-value=restart]')"
	    ".click()");
	wait_js("document.querySelector('form[data-form=confirm]')", 5);
	run("document.querySelector('form[data-form=confirm]').requestSubmit()");
	wait_js("document.querySelector('button[data-act=queue-to-wf]')", 5);
	run("document.querySelector('button[data-act=queue-to-wf]').click()");
	wait_js("document.querySelector('li.wfedstep select[data-input="
	    "wf-kind]') && document.querySelector('li.wfedstep select[data-"
	    "input=wf-kind]').value === 'service-action' && document."
	    "querySelector('input[data-arg=\"text:name\"]').value === 'From "
	    "the queue'", 10);
	shot("9c-workflow-queue");
	run("document.querySelector('button[data-act=wf-back]').click()");
	run("document.querySelector('button[data-act=queue-clear]').click()");
	/*
	 * The API's own page, from the menu: every route of the document,
	 * by group, searched, one unfolded.
	 */
	/* From the top bar: the API's light is the way to it. */
	run("document.querySelector('.topbar .link[data-act=select-api]')"
	    ".click()");
	wait_js("document.querySelectorAll('ul.apiops li.apiop').length > 40",
	    20);
	run("document.querySelector('button[data-act=api-tag][data-arg=auth]')"
	    ".click()");
	wait_js("document.querySelectorAll('ul.apiops li.apiop').length === 12",
	    5);
	run("document.querySelector('button[data-act=api-tag][data-arg=\"\"]')"
	    ".click()");
	run("const i = document.querySelector('#filter'); i.value = "
	    "'transport/switch'; i.dispatchEvent(new Event('input', { bubbles: "
	    "true }));");
	wait_js("document.querySelectorAll('ul.apiops li.apiop').length === 1",
	    5);
	run("document.querySelector('ul.apiops li.apiop').click()");
	wait_js("document.querySelector('ul.apiops li.apiop.open .more') && "
	    "document.querySelector('ul.apiops li.apiop.open .more')."
	    "textContent.includes('X-Arcana')", 5);
	shot("9-api");
	ATF_CHECK(js_true("document.querySelector('.apidoc header a')."
	    "getAttribute('href') === '/openapi.yaml'"));
	run("const i = document.querySelector('#filter'); i.value = ''; "
	    "i.dispatchEvent(new Event('input', { bubbles: true }));");
	run("document.querySelector('.tree .titem.server').click()");
	wait_js("document.querySelector('button.tab[data-arg=summary]')", 10);

	/*
	 * SD-WAN, a section of its own: nothing kept yet; the example, as
	 * the document, checked; one that breaks a requirement told which;
	 * kept, and then in the overview and the service's own tables.
	 */
	/* The agent on the console's own host, by its socket, is told
	 * apart in the tree and on its page. */
	ATF_CHECK(js_true("[...document.querySelectorAll('.tree .titem.server "
	    ".chip.here')].length === 2"));
	run("document.querySelector('li[data-act=select-sdwan]').click()");
	wait_js("document.querySelector('section.sdwan .sd-block') && "
	    "document.querySelector('section.sdwan').textContent.includes("
	    "'None yet')", 20);
	ATF_CHECK(js_true("document.querySelector('.crumb.place').textContent "
	    "=== 'SD-WAN'"));
	run("document.querySelector('button[data-act=sd-tab][data-arg="
	    "document]').click()");
	wait_js("document.querySelector('form[data-form=sd-doc] textarea')", 10);
	run("document.querySelector('button[data-act=sd-example]').click()");
	wait_js("document.querySelector('form[data-form=sd-doc] textarea')"
	    ".value.includes('\"office\"')", 10);
	run("window.sdText = document.querySelector('form[data-form=sd-doc] "
	    "textarea').value;");
	run("document.querySelector('form[data-form=sd-doc] button[value="
	    "check]').click()");
	wait_js("(document.querySelector('section.sdwan .notice') || {})."
	    "textContent?.includes('MEF 70.2 allows')", 20);
	run("const t = document.querySelector('form[data-form=sd-doc] "
	    "textarea'); t.value = window.sdText.replace('\"ceiling\": 50', "
	    "'\"ceiling\": 20');");
	run("document.querySelector('form[data-form=sd-doc] button[value="
	    "check]').click()");
	wait_js("(document.querySelector('section.sdwan .notice.bad') || {})."
	    "textContent?.includes('(R72)')", 20);
	shot("9-sdwan-refused");
	/* Its UNIs on lo0 and gif for geneve: what the stand-ins can make. */
	run("const t = document.querySelector('form[data-form=sd-doc] "
	    "textarea'); t.value = window.sdText.replaceAll('\"vtnet2\"', "
	    "'\"lo0\"').replace('\"geneve\"', '\"gif\"').replace(', "
	    "\"fd00:64::/64\"', '').replace('\"log\": true}}', '\"log\": "
	    "true, \"ids\": {\"mode\": \"detect\", \"ruleset\": true, "
	    "\"rules\": [\"alert tcp any any -> any 80 (sid:1000001; rev:1;)\"]}}}');");
	run("document.querySelector('form[data-form=sd-doc] button[value="
	    "keep]').click()");
	wait_js("(document.querySelector('section.sdwan .notice') || {})."
	    "textContent?.includes('version 1')", 20);
	run("document.querySelector('button[data-act=sd-tab][data-arg="
	    "overview]').click()");
	wait_js("[...document.querySelectorAll('section.sdwan table.sd')]"
	    ".length === 3 && document.querySelector('section.sdwan "
	    "button[data-act=sd-swvc]')?.textContent === 'office'", 10);
	/* Four WAN links, and each edge's own line below its links. */
	ATF_CHECK(js_true("document.querySelectorAll('section.sdwan table.sd')"
	    "[1].querySelectorAll('tbody tr').length === 6 && document."
	    "querySelectorAll('section.sdwan table.sd')[1].querySelectorAll("
	    "'tbody tr.sd-edge-row').length === 2"));
	/* The dashboard: the tiles, and the topology with the two edges
	 * and the plan's two tunnels between them. */
	wait_js("document.querySelectorAll('svg.sd-topo g.node').length === 2 "
	    "&& document.querySelectorAll('svg.sd-topo g.tun').length === 2 && "
	    "document.querySelector('.sd-tiles .tile b').textContent === '2'",
	    20);
	shot("9-sdwan-overview");
	/* What SD-WAN needs on the edges, and that the apply installs none. */
	wait_js("document.querySelector('section.sd-needs') && document."
	    "querySelector('section.sd-needs').textContent.includes("
	    "'Before using SD-WAN') && document.querySelector('section.sd-needs')"
	    ".textContent.includes('dnsmasq')", 15);
	/*
	 * The forms: an underlay added, changed and taken away; a WAN link
	 * on an edge, its interface picked from the host's own list, with
	 * the address the interface has; the document kept each time.
	 */
	run("document.querySelector('button[data-act=sd-ucs-add]').click()");
	wait_js("document.querySelector('form[data-form=sd-ucs] input[name=id]')",
	    5);
	shot("9-sdwan-form-underlay");
	run("const f = document.querySelector('form[data-form=sd-ucs]'); "
	    "f.id.value = 'lte'; f.type.value = 'public'; f.kind.value = 'wg'; "
	    "f.requestSubmit();");
	wait_js("!document.querySelector('form[data-form=sd-ucs]') && [..."
	    "document.querySelectorAll('section.sdwan table.sd')][0]"
	    ".textContent.includes('lte') && [...document.querySelectorAll("
	    "'section.sdwan table.sd')][0].textContent.includes('wg')", 20);
	run("[...document.querySelectorAll('button[data-act=sd-ucs-edit]')]"
	    ".find(b => b.dataset.arg === 'lte').click()");
	wait_js("document.querySelector('form[data-form=sd-ucs] input[name=id]')"
	    "?.value === 'lte'", 5);
	run("const f = document.querySelector('form[data-form=sd-ucs]'); "
	    "f.billing.value = 'usage-based'; f.requestSubmit();");
	wait_js("!document.querySelector('form[data-form=sd-ucs]') && [..."
	    "document.querySelectorAll('section.sdwan table.sd tbody tr')]"
	    ".some(r => r.textContent.includes('lte') && r.textContent."
	    "includes('usage-based'))", 20);
	run("document.querySelector('button[data-act=sd-link-add]').click()");
	wait_js("document.querySelector('form[data-form=sd-link] "
	    "select[name=interface] option')", 15);
	ATF_CHECK(js_true("document.querySelector('form[data-form=sd-link] "
	    "input[name=address]').value.length > 0"));
	shot("9-sdwan-form-link");
	run("const f = document.querySelector('form[data-form=sd-link]'); "
	    "f.ucs.value = 'lte'; f.breakout.checked = true; f.requestSubmit();");
	wait_js("!document.querySelector('form[data-form=sd-link]') && [..."
	    "document.querySelectorAll('section.sdwan table.sd tbody tr')]"
	    ".some(r => r.textContent.includes('lab-lte') && r.textContent."
	    "includes('breakout'))", 20);
	run("[...document.querySelectorAll('button[data-act=sd-link-del]')]"
	    ".find(b => b.dataset.value === 'lab-lte').click()");
	wait_js("document.querySelector('form[data-form=confirm]')", 5);
	run("document.querySelector('form[data-form=confirm]').requestSubmit();");
	wait_js("!document.querySelector('form[data-form=confirm]') && ![..."
	    "document.querySelectorAll('section.sdwan table.sd tbody tr')]"
	    ".some(r => r.textContent.includes('lab-lte'))", 20);
	run("[...document.querySelectorAll('button[data-act=sd-ucs-del]')]"
	    ".find(b => b.dataset.arg === 'lte').click()");
	wait_js("document.querySelector('form[data-form=confirm]')", 5);
	run("document.querySelector('form[data-form=confirm]').requestSubmit();");
	wait_js("!document.querySelector('form[data-form=confirm]') && ![..."
	    "document.querySelectorAll('section.sdwan table.sd')][0]"
	    ".textContent.includes('lte')", 20);
	run("document.querySelector('button[data-act=sd-swvc]').click()");
	wait_js("[...document.querySelectorAll('section.sdwan h3')].some(h => "
	    "h.textContent.startsWith('End points')) && document."
	    "querySelector('select[data-input=sd-swvc]')", 10);
	ATF_CHECK(js_true("document.querySelector('section.sdwan').textContent"
	    ".includes('10.10.0.0/24')"));
	shot("9-sdwan-service");
	/*
	 * The service's parts by forms: a zone, a flow matching an
	 * application, a policy with a performance threshold, and a rule
	 * at an end point tying them; each kept and checked.
	 */
	run("document.querySelector('button[data-act=sd-zone-add]').click()");
	wait_js("document.querySelector('form[data-form=sd-zone] input[name="
	    "name]')", 5);
	run("const f = document.querySelector('form[data-form=sd-zone]'); "
	    "f.name.value = 'guests'; f.prefixes.value = '10.10.9.0/24'; "
	    "f.requestSubmit();");
	wait_js("!document.querySelector('form[data-form=sd-zone]') && "
	    "document.querySelector('section.sdwan').textContent.includes("
	    "'guests')", 20);
	run("document.querySelector('button[data-act=sd-flow-add]').click()");
	wait_js("document.querySelector('form[data-form=sd-flow] input[name="
	    "name]')", 5);
	shot("9-sdwan-form-flow");
	run("const f = document.querySelector('form[data-form=sd-flow]'); "
	    "f.name.value = 'web'; f.app_https.checked = true; f.app_http."
	    "checked = true; f.proto.value = 'tcp'; f.requestSubmit();");
	wait_js("!document.querySelector('form[data-form=sd-flow]') && [..."
	    "document.querySelectorAll('section.sdwan table.sd tbody tr')]"
	    ".some(r => r.textContent.includes('web') && r.textContent."
	    "includes('http'))", 20);
	run("document.querySelector('button[data-act=sd-policy-add]').click()");
	wait_js("document.querySelector('form[data-form=sd-policy] select[name="
	    "metric]')", 5);
	shot("9-sdwan-form-policy");
	run("const f = document.querySelector('form[data-form=sd-policy]'); "
	    "f.name.value = 'cheap'; f['internet-breakout'].value = 'enabled'; "
	    "f.metric.value = 'loss'; f.threshold.value = '0.02'; f.commit.value"
	    " = '2000000'; f.requestSubmit();");
	wait_js("!document.querySelector('form[data-form=sd-policy]') && [..."
	    "document.querySelectorAll('section.sdwan table.sd tbody tr')]"
	    ".some(r => r.textContent.includes('cheap') && r.textContent."
	    "includes('loss'))", 20);
	run("document.querySelector('button[data-act=sd-map-add]').click()");
	wait_js("document.querySelector('form[data-form=sd-map] select[name="
	    "zone] option[value=guests]')", 5);
	run("const f = document.querySelector('form[data-form=sd-map]'); "
	    "f.zone.value = 'guests'; f.app.value = 'web'; f.ingress.value = "
	    "'cheap'; f.requestSubmit();");
	wait_js("!document.querySelector('form[data-form=sd-map]') && [..."
	    "document.querySelectorAll('section.sdwan .pmap')].some(p => p."
	    "textContent.includes('guests') && p.textContent.includes('web') "
	    "&& p.textContent.includes('cheap'))", 20);
	ATF_CHECK(system("grep -q guests data/sdwan.json && grep -q https "
	    "data/sdwan.json && grep -q internet-breakout data/sdwan.json") ==
	    0);
	/* The end point form, with the edge's interfaces. */
	run("[...document.querySelectorAll('button[data-act=sd-ep-edit]')]"
	    ".find(b => b.dataset.arg === 'hq').click()");
	wait_js("document.querySelector('form[data-form=sd-ep] select[name="
	    "interface] option') && document.querySelector('form[data-form="
	    "sd-ep] input[name=p4]').value === '10.10.0.0/24'", 15);
	shot("9-sdwan-form-endpoint");
	/* The hosts' IPv4 addresses given by the edge (DHCP by dnsmasq),
	 * with a reserved prefix, the DNS server told and a lease; the
	 * service's table says DHCP, the document holds it. */
	run("const f = document.querySelector('form[data-form=sd-ep]'); "
	    "f.m4.value = 'dhcp'; f.r4.value = '10.10.0.0/28'; f.d4.value = "
	    "'10.10.0.1'; f.l4.value = '2h'; f.requestSubmit();");
	wait_js("!document.querySelector('form[data-form=sd-ep]') && [..."
	    "document.querySelectorAll('section.sdwan table.sd tbody tr')]"
	    ".some(r => r.textContent.includes('hq') && r.textContent."
	    "includes('DHCP'))", 20);
	ATF_CHECK(system("grep -q dhcp data/sdwan.json && grep -q 10.10.0.0/28 "
	    "data/sdwan.json && grep -q '\"2h\"' data/sdwan.json") == 0);
	/*
	 * Edges: the tunnels and what each edge is to have; applied, each
	 * step done, and then nothing left to do.
	 */
	run("document.querySelector('button[data-act=sd-tab][data-arg=edges]')"
	    ".click()");
	wait_js("document.querySelectorAll('table.sd-plan tbody tr').length > 8 "
	    "&& document.querySelector('button[data-act=sd-apply-ask]') && "
	    "!document.querySelector('button[data-act=sd-apply-ask]').disabled",
	    20);
	ATF_CHECK(js_true("[...document.querySelectorAll('section.sdwan h3')]"
	    ".find(h => h.textContent.startsWith('Tunnels')).closest('.sd-block')"
	    ".querySelectorAll('tbody tr').length === 2"));
	shot("9-sdwan-edges-plan");
	/* Deploy asks first, saying what changes; then it runs. */
	run("document.querySelector('button[data-act=sd-apply-ask]').click()");
	wait_js("document.querySelector('form[data-form=confirm]') && document."
	    "querySelector('form[data-form=confirm]').textContent.includes("
	    "'to make')", 5);
	shot("9-sdwan-deploy-ask");
	run("document.querySelector('form[data-form=confirm]').requestSubmit();");
	wait_js("(document.querySelector('.sd-applied h3') || {}).textContent"
	    "?.startsWith('Last apply') && document.querySelector("
	    "'button[data-act=sd-apply-ask]').disabled", 60);
	ATF_CHECK(js_true("document.querySelector('table.sd-history tbody tr') "
	    "&& document.querySelectorAll('table.sd-plan tr.sd-edge-head')"
	    ".length === 2"));
	ATF_CHECK(js_true("document.querySelector('.sd-applied h3')"
	    ".textContent.startsWith('Last apply: done')"));
	shot("9-sdwan-edges-applied");
	/* Paths: each tunnel's two ends, as their probes see them; the
	 * agent here runs without root, so each end says so. */
	run("document.querySelector('button[data-act=sd-tab][data-arg=paths]')"
	    ".click()");
	wait_js("document.querySelectorAll('.sd-path').length === 2 && "
	    "[...document.querySelectorAll('.sd-path .chip')].length === 4 && "
	    "document.querySelector('.sd-path').textContent.includes('needs "
	    "root')", 30);
	ATF_CHECK(js_true("[...document.querySelectorAll('section.sdwan h3')]"
	    ".some(h => h.textContent.startsWith('Steering'))"));
	/* The monitor of each tunnel: nothing to draw without root, and
	 * a span to choose. */
	ATF_CHECK(js_true("document.querySelectorAll('.sd-path .sd-mon').length"
	    " === 2 && document.querySelector('.sd-path .sd-mon p').textContent"
	    ".includes('No sample in the last 15 min')"));
	run("document.querySelector('button[data-act=sd-span][data-arg=\"3600\"]')"
	    ".click()");
	wait_js("document.querySelector('button[data-act=sd-span][data-arg="
	    "\"3600\"].on') && document.querySelector('.sd-path .sd-mon p')"
	    ".textContent.includes('last 60 min')", 5);
	shot("9-sdwan-paths");
	/* Security: the policies, and the record of what their deny rules
	 * logged, nothing yet; its filter and the CSV link. */
	run("document.querySelector('button[data-act=sd-tab][data-arg="
	    "security]').click()");
	wait_js("[...document.querySelectorAll('section.sdwan h3')].some(h => "
	    "h.textContent.startsWith('Record')) && document.querySelector("
	    "'section.sdwan').textContent.includes('Nothing logged yet')", 20);
	ATF_CHECK(js_true("document.querySelector('input[data-input="
	    "sd-record-filter]') !== null && document.querySelector('a[href="
	    "\"/api/sdwan/record.csv\"]') !== null"));
	/* Zero trust (MEF 118.1): the Access Control Policies, Subject Actor
	 * to Target Actor, the staff zone Allowed to every zone and the
	 * Internet, anything else Blocked; the Policy End Points; the audit
	 * trail, intact, the document kept and applied by this key. */
	wait_js("[...document.querySelectorAll('section.sdwan h4')].some(h => "
	    "h.textContent.startsWith('Audit Events')) && document.querySelector("
	    "'section.sdwan').textContent.includes('policies-applied')", 20);
	ATF_CHECK(js_true("[...document.querySelectorAll('section.sdwan table.sd "
	    "tbody tr')].some(tr => tr.textContent.startsWith('staff') && tr"
	    ".textContent.includes('every zone, the Internet') && tr.textContent"
	    ".includes('Allow')) && [...document.querySelectorAll('section.sdwan "
	    "table.sd tbody tr')].some(tr => tr.textContent.startsWith('any "
	    "other') && tr.textContent.includes('Block')) && [...document"
	    ".querySelectorAll('section.sdwan .chip')].some(c => c.textContent "
	    "=== 'intact') && document.querySelector('a[href=\"/api/sdwan/audit"
	    ".csv\"]') !== null && [...document.querySelectorAll('section.sdwan "
	    "h4')].some(h => h.textContent.startsWith('Policy End Points'))"));
	/* Intrusion detection: the policy's IDS in its column, the block of
	 * the edges' Suricata, and the form's mode, rules and ruleset. */
	ATF_CHECK(js_true("[...document.querySelectorAll('section.sdwan h3')]"
	    ".some(h => h.textContent.startsWith('Intrusion detection')) && "
	    "[...document.querySelectorAll('section.sdwan table.sd tbody tr')]"
	    ".some(tr => tr.textContent.includes('detect, 1 rule and the "
	    "ruleset'))"));
	run("document.querySelector('button[data-act=sd-secpol-edit]').click()");
	wait_js("document.querySelector('.modal select[name=idsmode]') !== null",
	    5);
	ATF_CHECK(js_true("document.querySelector('.modal select[name=idsmode]')"
	    ".value === 'detect' && document.querySelector('.modal textarea[name="
	    "idsrules]').value.includes('sid:1000001') && document.querySelector("
	    "'.modal input[name=idsruleset]').checked"));
	run("document.querySelector('.modal button[data-act=close]').click()");
	shot("9-sdwan-security");
	/* Identities: the example's alice, at the remote end point, with
	 * the address the plan gave her. */
	run("document.querySelector('button[data-act=sd-tab][data-arg="
	    "identities]').click()");
	wait_js("[...document.querySelectorAll('section.sdwan table.sd tbody "
	    "tr')].some(tr => tr.textContent.includes('alice') && tr.textContent"
	    ".includes('10.30.0.2'))", 20);
	ATF_CHECK(js_true("document.querySelector('button[data-act="
	    "sd-ident-add]') !== null && document.querySelector('button[data-act="
	    "sd-ident-revoke]') !== null"));
	shot("9-sdwan-identities");
	phone(true);
	wait_js("document.documentElement.scrollWidth <= window.innerWidth + 1",
	    10);
	shot("m12-sdwan");
	phone(false);

}

static void
part_netsect(void)
{
	char		 web[MAXPATHLEN], script[2048];
	char		*token;
	FILE		*fp;
	int		 i;

	(void)web;
	(void)script;
	(void)token;
	(void)fp;
	(void)i;

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
	/* A host's bridge is drawn above it: a dot for each member, in
	 * the colour the spanning tree gave it. */
	wait_js("document.querySelectorAll('svg.topo g.tbridge').length >= 1 "
	    "&& document.querySelector('svg.topo g.tbridge circle.p-fwd') && "
	    "document.querySelector('svg.topo g.tbridge circle.p-block') && "
	    "document.querySelector('svg.topo g.tbridge circle.p-off')", 30);
	shot("8-network");
	/* The legend takes a kind of line out of the map, and puts it back. */
	/* Picked with the mouse itself: it has to be reached by one. */
	ATF_REQUIRE(js_true("document.querySelector('svg.topo .tlink.lan')"));
	click_at(".map-legend li[data-arg=lan]");
	wait_js("!document.querySelector('svg.topo .tlink.lan') && "
	    "!document.querySelector('svg.topo .tseg') && "
	    "document.querySelector('.map-legend li.off[data-arg=lan]')", 5);
	click_at(".map-legend li[data-arg=lan]");
	wait_js("document.querySelector('svg.topo .tlink.lan') && "
	    "!document.querySelector('.map-legend li.off')", 5);
	/* Labels, kind by kind: the shared networks' left out, the others
	 * as they were. */
	click_at(".map-tools button[data-act=topo-labels]");
	wait_js("document.querySelectorAll('.map-labels button').length === 8",
	    5);
	run("window.otherQuiet = [...document.querySelectorAll('svg.topo "
	    ".tlink:not(.lan)')].map(g => g.classList.contains('quiet'))"
	    ".join()");
	click_at(".map-labels button[data-arg=lan].on");
	wait_js("document.querySelector('.map-labels button[data-arg=lan]:not(.on)')"
	    " && [...document.querySelectorAll('svg.topo .tlink.lan')].every(g "
	    "=> g.classList.contains('quiet')) && [...document.querySelectorAll("
	    "'svg.topo .tlink:not(.lan)')].map(g => g.classList.contains("
	    "'quiet')).join() === window.otherQuiet", 5);
	shot("8a-labels");
	click_at(".map-labels button[data-arg=lan]");
	wait_js("document.querySelector('.map-labels button[data-arg=lan].on') "
	    "&& ![...document.querySelectorAll('svg.topo .tlink.lan')].some(g "
	    "=> g.classList.contains('quiet'))", 5);
	click_at(".map-tools button[data-act=topo-labels]");
	wait_js("!document.querySelector('.map-labels')", 5);
	/* On no line is its name written over its rate. */
	ATF_CHECK(js_true("[...document.querySelectorAll('svg.topo g.tlink')]"
	    ".every(g => { const r = g.querySelector('.rate'); if (!r) "
	    "return true; const b = r.getBBox(); return [...g.querySelectorAll("
	    "'.lbl')].every(l => { const a = l.getBBox(); return a.x + a.width "
	    "<= b.x || b.x + b.width <= a.x || a.y + a.height <= b.y || b.y + "
	    "b.height <= a.y; }); })"));
	/* A line dragged aside bends to the pointer, and stays so. */
	{
		double	x0, y0;
		int	step;

		run("window.d0 = document.querySelector('svg.topo g.tlink.lan "
		    ".wire').getAttribute('d')");
		x0 = js_num("(p => { const l = p.getTotalLength(), m = p."
		    "getPointAtLength(l / 2), c = p.getScreenCTM(); return m.x "
		    "* c.a + c.e; })(document.querySelector('svg.topo g.tlink."
		    "lan .hit'))");
		y0 = js_num("(p => { const l = p.getTotalLength(), m = p."
		    "getPointAtLength(l / 2), c = p.getScreenCTM(); return m.y "
		    "* c.d + c.f; })(document.querySelector('svg.topo g.tlink."
		    "lan .hit'))");
		mouse("pointerMove", x0, y0);
		mouse("pointerDown", 0, 0);
		for (step = 1; step <= 6; step++) {
			mouse("pointerMove", x0 + step, y0 + 12 * step);
			usleep(150000);
		}
		mouse("pointerUp", 0, 0);
		wait_js("document.querySelector('svg.topo g.tlink.lan .wire')"
		    ".getAttribute('d') !== window.d0 && (localStorage."
		    "getItem('arc_topo_bends') || '').length > 0", 5);
		shot("8b-bent");
		/* A neighbour outside, dragged elsewhere, stays there. */
		x0 = js_num("(r => r.x + r.width / 2)(document.querySelector("
		    "'svg.topo g.tpeer rect').getBoundingClientRect())");
		y0 = js_num("(r => r.y + r.height / 2)(document.querySelector("
		    "'svg.topo g.tpeer rect').getBoundingClientRect())");
		run("window.p0 = document.querySelector('svg.topo g.tpeer rect')"
		    ".getAttribute('x')");
		mouse("pointerMove", x0, y0);
		mouse("pointerDown", 0, 0);
		for (step = 1; step <= 6; step++) {
			mouse("pointerMove", x0 - 10 * step, y0 + 4 * step);
			usleep(150000);
		}
		mouse("pointerUp", 0, 0);
		wait_js("document.querySelector('svg.topo g.tpeer rect')."
		    "getAttribute('x') !== window.p0 && (localStorage.getItem("
		    "'arc_topo_peers') || '').length > 0", 5);
		/* Taken by where it was held: it does not jump to the
		 * pointer, it moves with it. */
		{
			double	cx, cy;

			cx = js_num("(r => r.x + r.width / 2)(document."
			    "querySelector('svg.topo g.tpeer rect')."
			    "getBoundingClientRect())");
			cy = js_num("(r => r.y + r.height / 2)(document."
			    "querySelector('svg.topo g.tpeer rect')."
			    "getBoundingClientRect())");
			ATF_CHECK_MSG(fabs(cx - (x0 - 60)) < 6 && fabs(cy -
			    (y0 + 24)) < 6, "the neighbour is at %.0f,%.0f and "
			    "the pointer at %.0f,%.0f", cx, cy, x0 - 60, y0 + 24);
		}
		shot("8c-peer");
		run("document.querySelector('button[data-act=topo-arrange]')"
		    ".click()");
		wait_js("!(localStorage.getItem('arc_topo_bends') || '') && "
		    "!(localStorage.getItem('arc_topo_peers') || '')", 5);
	}
	/*
	 * A host dragged by the mouse stays under it, all the way, and
	 * while the map reads the hosts again: taken by its middle, its
	 * middle is where the pointer is after every move.
	 */
	{
		double	x0, y0, x, y, cx, cy;
		int	step;

		x0 = js_num("(r => r.x + r.width / 2)(document.querySelector("
		    "'svg.topo .tnode .box').getBoundingClientRect())");
		y0 = js_num("(r => r.y + r.height / 2)(document.querySelector("
		    "'svg.topo .tnode .box').getBoundingClientRect())");
		mouse("pointerMove", x0, y0);
		mouse("pointerDown", 0, 0);
		for (step = 1; step <= 16; step++) {
			x = x0 + 9 * step * (step % 4 < 2 ? 1 : 0.6);
			y = y0 + 6 * step;
			mouse("pointerMove", x, y);
			usleep(450000);
			cx = js_num("(r => r.x + r.width / 2)(document."
			    "querySelector('svg.topo .tnode .box')."
			    "getBoundingClientRect())");
			cy = js_num("(r => r.y + r.height / 2)(document."
			    "querySelector('svg.topo .tnode .box')."
			    "getBoundingClientRect())");
			ATF_CHECK_MSG(fabs(cx - x) < 6 && fabs(cy - y) < 6,
			    "step %d: the host is at %.0f,%.0f and the "
			    "pointer at %.0f,%.0f", step, cx, cy, x, y);
		}
		mouse("pointerUp", 0, 0);
	}
	/* Two fingers parting on the map bring it closer. */
	run("window.vb = document.querySelector('svg.topo').getAttribute("
	    "'viewBox'); const s = document.querySelector('svg.topo'), r = "
	    "s.getBoundingClientRect(), ev = (t, id, x, y) => (t === "
	    "'pointerdown' ? s : document).dispatchEvent(new PointerEvent(t, "
	    "{ bubbles: true, cancelable: true, pointerId: id, pointerType: "
	    "'touch', clientX: x, clientY: y })); const cx = r.x + r.width / "
	    "2, cy = r.y + r.height / 2; ev('pointerdown', 11, cx - 40, cy); "
	    "ev('pointerdown', 12, cx + 40, cy); ev('pointermove', 12, cx + "
	    "120, cy); ev('pointerup', 11, cx - 40, cy); ev('pointerup', 12, "
	    "cx + 120, cy);");
	wait_js("parseFloat(document.querySelector('svg.topo').getAttribute("
	    "'viewBox').split(' ')[2]) < parseFloat(window.vb.split(' ')[2])",
	    5);
	run("document.querySelector('button[data-act=topo-fit]').click()");
	/* A host is picked: its interfaces, with their addresses.  The
	 * drawing keeps its size whatever the panel beside it shows: it
	 * would grow or shrink under the pointer otherwise. */
	{
		double	w0, h0, w1, h1;

		w0 = js_num("document.querySelector('svg.topo')."
		    "getBoundingClientRect().width");
		h0 = js_num("document.querySelector('svg.topo')."
		    "getBoundingClientRect().height");
		run("const n = document.querySelector('svg.topo .tnode .box'); "
		    "ptr(n, 'pointerdown'); ptr(n, 'pointerup');");
		wait_js("document.querySelector('svg.topo .tnode.sel') && "
		    "document.querySelector('.map-panel .iflist li')", 5);
		w1 = js_num("document.querySelector('svg.topo')."
		    "getBoundingClientRect().width");
		h1 = js_num("document.querySelector('svg.topo')."
		    "getBoundingClientRect().height");
		ATF_CHECK_MSG(fabs(w1 - w0) < 1 && fabs(h1 - h0) < 1,
		    "the map was %.0fx%.0f and is %.0fx%.0f with a host "
		    "picked", w0, h0, w1, h1);
	}
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
	/* In the fleet's graph the one that runs is there, and none of
	 * the stopped; it opens over the page. */
	run("document.querySelector('.tree .titem.fleet').click()");
	wait_js("document.querySelector('.topo .tnode.s-running[data-arg=gw]')",
	    10);
	ATF_CHECK(js_true("!document.querySelector('.topo .tnode.s-stopped')"));
	run("document.querySelector('.topo .tnode[data-act=peek-jail]')"
	    ".click()");
	wait_js("document.querySelector('.peek-box .jail-page') && "
	    "document.querySelector('.hosts .hostcard')", 5);
	run("document.querySelector('.peek-box .close').click()");
	wait_js("!document.querySelector('.peek-box') && "
	    "document.querySelector('.hosts .hostcard')", 5);
	shot("2a-fleet-running");
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
	/* Its network is its host's Network tab, the jail picked there. */
	run("document.querySelector('.map-panel button[data-act="
	    "topo-open-host]').click()");
	wait_js("document.querySelector('select[data-input=net-jail]')?.value "
	    "=== 'gw' && document.querySelector('table.ifaces tr[data-if="
	    "epair1b]')", 20);
	run("window.fetch = window.fetch0;");
	run("document.querySelector('li[data-act=select-network]').click()");
	wait_js("document.querySelector('svg.topo .tnode')", 10);
	/*
	 * A nexthop group's far ends found by their link-local addresses:
	 * told here that lab sends by em1 to fe80::2, which lab2 has on
	 * two links, em6 and em5, of which only em5 shares a network with
	 * lab's em1; and by em0 to fe80::1, which lab2 has on its loopback
	 * alone, as every host does: no host of the fleet is that one.
	 */
	run("window.fetchL = window.fetch; const ids = {}; document."
	    "querySelectorAll('li.titem.server').forEach(l => ids[l."
	    "querySelector('.name').textContent.trim()] = l.dataset.arg); "
	    "window.labIds = ids; const A = (f, a, p) => ({ family: f, "
	    "address: a, prefixlen: p }), I = (n, ad) => ({ name: n, up: "
	    "true, mtu: 1500, addresses: ad, ibytes: 0, obytes: 0 }); "
	    "const ifs = { lab: [I('lo0', [A('inet6', 'fe80::1%lo0', 64)]), "
	    "I('em0', [A('inet', '10.0.0.1', 24), A('inet6', 'fe80::a%em0', "
	    "64)]), I('em1', [A('inet', '10.0.1.1', 24), A('inet6', "
	    "'fe80::1%em1', 64)])], lab2: [I('lo0', [A('inet6', 'fe80::1%lo0'"
	    ", 64)]), I('em6', [A('inet', '10.9.9.2', 24), A('inet6', "
	    "'fe80::2%em6', 64)]), I('em5', [A('inet', '10.0.1.2', 24), A("
	    "'inet6', 'fe80::2%em5', 64)])] }; const nets = { lab: ['em0', "
	    "'em1'], lab2: ['em6', 'em5'] }, rate = { lab: [0, 1000, 0, "
	    "1000], lab2: [0, 0, 2000, 0] }; const who = u => Object.keys("
	    "ids).find(k => String(u).includes('/servers/' + ids[k] + '/')); "
	    "const R = o => Promise.resolve(new Response(JSON.stringify(o), { "
	    "status: 200, headers: { 'Content-Type': 'application/json' } })); "
	    "window.fetch = (u, o) => { const k = who(u); if (!k) return "
	    "window.fetchL(u, o); if (String(u).includes('/net/interfaces')) "
	    "return R({ ok: true, data: { interfaces: ifs[k], time: Date.now()"
	    " } }); if (String(u).includes('/net/nhgroups')) return R({ ok: "
	    "true, data: { statistics: { 'route-nhgrp-information': { "
	    "'nhgrp-table': { 'rt-family': k !== 'lab' ? [] : [{ "
	    "'address-family': 'Internet6', 'nhgrp-entry': [{ 'nhgrp-index': "
	    "9, 'nhg-refcnt': 1, 'nhop-weights': [{ 'nh-index': 1, "
	    "'nh-weight': 1, 'nh-gw': 'fe80::2%em1', 'nh-interface': 'em1' }, "
	    "{ 'nh-index': 2, 'nh-weight': 1, 'nh-gw': 'fe80::1%em0', "
	    "'nh-interface': 'em0' }] }] }] } } } } }); if (String(u).includes("
	    "'/history')) { const now = Date.now() / 1000, s = []; for (let t "
	    "= now - 600; t <= now; t += 5) s.push([t, 1, 0.1, 1e9, 0, 0, 0, "
	    "0, 0].concat(rate[k])); return R({ ok: true, data: { step: 5, "
	    "keep: 720, ncpu: 1, mem_total: 2e9, swap_total: 0, bytes: 1, "
	    "nets: nets[k], disks: [], jails: [], samples: s } }); } return "
	    "window.fetchL(u, o); };");
	run("document.querySelector('.netsect button.tab[data-arg=groups]')"
	    ".click()");
	wait_js("(() => { const g = [...document.querySelectorAll('.ecmp-page "
	    ".ecmp-group')].find(g => g.querySelector('h4').textContent."
	    "includes('group 9')); if (!g) return false; const r = g."
	    "querySelectorAll('.ecmp-side')[1].textContent; return r.includes("
	    "'lab2 · em5') && !r.includes('em6') && r.includes('no host of "
	    "this console has it on that link'); })()", 40);
	shot("8-network-nhgroups-linklocal");
	/*
	 * Traceroute, as mtr: rounds one after the other, each hop with
	 * its loss and times; the host itself named where it is a hop.
	 */
	run("window.fetch = window.fetchL;");
	run("document.querySelector('.netsect button.tab[data-arg=traceroute]')"
	    ".click()");
	wait_js("document.querySelector('input[data-input=mtr-to]')", 10);
	run("const i = document.querySelector('input[data-input=mtr-to]'); "
	    "i.value = '192.0.2.77'; i.dispatchEvent(new Event('input', { "
	    "bubbles: true }));");
	run("document.querySelector('button[data-act=mtr-start]').click()");
	wait_js("(() => { const r = [...document.querySelectorAll('table."
	    "mtr-table tbody tr')].map(t => t.textContent); return r.length "
	    "=== 4 && r[1].includes('127.0.0.1') && r[1].includes('in lo0') "
	    "&& r[2].includes('198.51.100.1') && document.querySelectorAll("
	    "'table.mtr-table tbody tr')[2].children[5].textContent === '50%' "
	    "&& r[3]"
	    ".includes('192.0.2.77'); })()", 40);
	shot("8-network-traceroute");
	run("document.querySelector('button[data-act=mtr-stop]').click()");
	wait_js("document.querySelector('button[data-act=mtr-start]')", 5);
	run("window.fetch = window.fetchL;");
	run("document.querySelector('.netsect button.tab[data-arg=map]')"
	    ".click()");
	wait_js("document.querySelectorAll('svg.topo .tnode.up').length === 2 "
	    "&& document.querySelector('svg.topo .tlink.lan')", 40);
	/* On a phone the map is above its panel, each as wide as the screen;
	 * its tools in a line of their own, its legend under it. */
	phone(true);
	wait_js("document.querySelector('.map-wrap').getBoundingClientRect()"
	    ".width <= window.innerWidth && document.documentElement."
	    "scrollWidth <= window.innerWidth + 1", 10);
	ATF_CHECK(js_true("(() => { const t = document.querySelector("
	    "'.map-tools').getBoundingClientRect(), w = document."
	    "querySelector('.map-wrap').getBoundingClientRect(); return "
	    "t.right <= w.right + 1 && document.querySelector('.map-legend')"
	    ".getBoundingClientRect().right <= w.right + 1 && document."
	    "querySelector('.map-legend').getBoundingClientRect().top > "
	    "t.bottom; })()"));
	run("document.querySelector('button[data-act=topo-arrange]').click()");
	usleep(500000);
	shot("m11-network");
	phone(false);
	run("document.querySelector('li[data-act=select-server]').click()");
	wait_js("document.querySelector('button.tab[data-arg=jails]')", 10);

}

/*
 * The page's address names what it shows: written as it changes, gone
 * back through with the browser's history, and followed when the page
 * is opened at it.
 */
static void
part_routes(void)
{
	ucl_object_t	*v;
	char		 id[16], expr[512], path[128];

	wait_js("location.hash.startsWith('#/hosts/')", 10);
	v = js("return location.hash.split('/')[2];");
	ATF_REQUIRE(v != NULL && ucl_object_type(v) == UCL_STRING);
	snprintf(id, sizeof(id), "%s", ucl_object_tostring(v));
	ucl_object_unref(v);
	ATF_REQUIRE_MSG(strlen(id) > 0, "no host in the address");
	snprintf(expr, sizeof(expr), "location.hash === '#/hosts/%s'", id);
	wait_js(expr, 5);

	/* A tab, and back. */
	run("document.querySelector('button[data-act=tab][data-arg=jails]')"
	    ".click()");
	snprintf(expr, sizeof(expr), "location.hash === '#/hosts/%s/jails'",
	    id);
	wait_js(expr, 5);
	run("history.back()");
	snprintf(expr, sizeof(expr), "location.hash === '#/hosts/%s' && "
	    "document.querySelector('button[data-act=tab][data-arg=summary]"
	    ".on')", id);
	wait_js(expr, 5);
	run("history.forward()");
	snprintf(expr, sizeof(expr), "location.hash === '#/hosts/%s/jails' && "
	    "document.querySelector('button[data-act=tab][data-arg=jails].on')",
	    id);
	wait_js(expr, 5);

	/* A jail from the tree. */
	run("document.querySelector('.tree li[data-act=open-jail]"
	    "[data-arg=cache]').click()");
	snprintf(expr, sizeof(expr), "location.hash === "
	    "'#/hosts/%s/jails/cache'", id);
	wait_js(expr, 5);
	run("document.querySelector('.tree [data-act=select-fleet]').click()");
	wait_js("location.hash === '#/'", 5);

	/* An address given, as a link in the page would: followed. */
	snprintf(path, sizeof(path), "/#/hosts/%s/processes", id);
	go(path);
	snprintf(expr, sizeof(expr), "location.hash === '#/hosts/%s/processes' "
	    "&& document.querySelector('button[data-act=tab]"
	    "[data-arg=processes].on')", id);
	wait_js(expr, 20);
	go("/#/settings/tokens");
	wait_js("location.hash === '#/settings/tokens' && document."
	    "querySelector('button[data-act=set-tab][data-arg=tokens].on')", 20);
	/* A host that is not there: the fleet, and the address says so. */
	go("/#/hosts/ffffffff/log");
	wait_js("location.hash === '#/' && document.querySelector("
	    "'.tree [data-act=select-fleet].selected')", 20);

	/* Opened at an address: there once the hosts are known. */
	snprintf(path, sizeof(path), "/#/hosts/%s/jails/cache", id);
	go(path);
	run("window.before = 1; location.reload();");
	wait_js("window.before === undefined && document.querySelector("
	    "'.tree .titem.leaf.selected') && document.querySelector("
	    "'.tree .titem.leaf.selected').dataset.arg === 'cache'", 30);
	go("/#/usage");
	run("window.before = 1; location.reload();");
	wait_js("window.before === undefined && location.hash === '#/usage' && "
	    "document.querySelector('.tree [data-act=select-usage].selected')", 30);
	go("/#/hosts/ffffffff/log");
	run("window.before = 1; location.reload();");
	wait_js("window.before === undefined && location.hash === '#/' && "
	    "document.querySelector('.tree [data-act=select-fleet].selected')", 30);
}

ATF_TC_WITH_CLEANUP(pwa_routes);
ATF_TC_HEAD(pwa_routes, tc)
{

	atf_tc_set_md_var(tc, "descr", "The page's address follows what is shown, the history goes back through it, and opening an address shows what it names");
	atf_tc_set_md_var(tc, "timeout", "240");
}
ATF_TC_BODY(pwa_routes, tc)
{

	prologue(tc, 1);
	part_routes();
}
ATF_TC_CLEANUP(pwa_routes, tc)
{

	browser_stop();
}

ATF_TC_WITH_CLEANUP(pwa_shell);
ATF_TC_HEAD(pwa_shell, tc)
{

	atf_tc_set_md_var(tc, "descr", "Enrol, the settings, the install offer, log in again, offline, and a newer shell, in Chromium");
	atf_tc_set_md_var(tc, "timeout", "240");
}
ATF_TC_BODY(pwa_shell, tc)
{

	prologue(tc, 0);
	part_shell();
}
ATF_TC_CLEANUP(pwa_shell, tc)
{

	browser_stop();
}

ATF_TC_WITH_CLEANUP(pwa_hosts);
ATF_TC_HEAD(pwa_hosts, tc)
{

	atf_tc_set_md_var(tc, "descr", "A host added, its summary, agent and jails, services and packages, the queue, and the tasks kept");
	atf_tc_set_md_var(tc, "timeout", "240");
}
ATF_TC_BODY(pwa_hosts, tc)
{

	prologue(tc, 0);
	part_hosts();
}
ATF_TC_CLEANUP(pwa_hosts, tc)
{

	browser_stop();
}

ATF_TC_WITH_CLEANUP(pwa_nettab);
ATF_TC_HEAD(pwa_nettab, tc)
{

	atf_tc_set_md_var(tc, "descr", "The network tab, jobs, and every page on a phone with its themes");
	atf_tc_set_md_var(tc, "timeout", "240");
}
ATF_TC_BODY(pwa_nettab, tc)
{

	prologue(tc, 1);
	part_nettab();
}
ATF_TC_CLEANUP(pwa_nettab, tc)
{

	browser_stop();
}

ATF_TC_WITH_CLEANUP(pwa_plugins);
ATF_TC_HEAD(pwa_plugins, tc)
{

	atf_tc_set_md_var(tc, "descr", "Two hosts, vnet jails, WireGuard, IPsec and BIRD, and the network map");
	atf_tc_set_md_var(tc, "timeout", "400");
}
ATF_TC_BODY(pwa_plugins, tc)
{

	prologue(tc, 1);
	part_plugins();
	part_netsect();
}
ATF_TC_CLEANUP(pwa_plugins, tc)
{

	browser_stop();
}

ATF_TC_WITH_CLEANUP(pwa_storage);
ATF_TC_HEAD(pwa_storage, tc)
{

	atf_tc_set_md_var(tc, "descr", "Storage, the kernel, sysctl, processes, logs, events and utilization");
	atf_tc_set_md_var(tc, "timeout", "240");
}
ATF_TC_BODY(pwa_storage, tc)
{

	prologue(tc, 2);
	part_storage();
}
ATF_TC_CLEANUP(pwa_storage, tc)
{

	browser_stop();
}

ATF_TC_WITH_CLEANUP(pwa_firewall);
ATF_TC_HEAD(pwa_firewall, tc)
{

	atf_tc_set_md_var(tc, "descr", "The firewall, a bridge, geneve tunnels and the transport");
	atf_tc_set_md_var(tc, "timeout", "240");
}
ATF_TC_BODY(pwa_firewall, tc)
{

	prologue(tc, 1);
	part_firewall();
}
ATF_TC_CLEANUP(pwa_firewall, tc)
{

	browser_stop();
}

ATF_TC_WITH_CLEANUP(pwa_flows);
ATF_TC_HEAD(pwa_flows, tc)
{

	atf_tc_set_md_var(tc, "descr", "Workflows, the API, and SD-WAN");
	atf_tc_set_md_var(tc, "timeout", "240");
}
ATF_TC_BODY(pwa_flows, tc)
{

	prologue(tc, 2);
	part_flows();
}
ATF_TC_CLEANUP(pwa_flows, tc)
{

	browser_stop();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, pwa_shell);
	ATF_TP_ADD_TC(tp, pwa_routes);
	ATF_TP_ADD_TC(tp, pwa_hosts);
	ATF_TP_ADD_TC(tp, pwa_nettab);
	ATF_TP_ADD_TC(tp, pwa_plugins);
	ATF_TP_ADD_TC(tp, pwa_storage);
	ATF_TP_ADD_TC(tp, pwa_firewall);
	ATF_TP_ADD_TC(tp, pwa_flows);
	return (atf_no_error());
}
