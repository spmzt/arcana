/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Security page's Snort tab: Snort 3 on the host the page shows, a
 * plugin run by Arcana's rc.d script arcana_snort.  Its alerts and its
 * rules, each turned on or off; the rules updated from where they came
 * (Snort's community rules unless told); rc.conf's settings and
 * HOME_NET; local.rules and snort.lua written.  Each change is a snort
 * job, checked by snort -T on the host before it replaces anything.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	RULES_SHOWN	300

enum snview { SN_ALERTS, SN_RULES, SN_SETTINGS, SN_LOCAL, SN_LUA };

static struct {
	char		 sid[16];
	ucl_object_t	*st;		/* the host's snort read */
	bool		 with_rules;	/* st has every rule */
	bool		 loading;
	char		 error[256];
	enum snview	 view;
	char		*text;		/* local.rules or snort.lua, edited */
	enum snview	 text_of;
	char		 url[1100];
} sn;

static const char *const views[] = { "alerts", "rules", "settings",
    "local", "lua" };

static struct server *
sn_server(void)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sn.sid) == 0)
			return (&app.servers[i]);
	return (NULL);
}

static void
sn_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid = arg;
	bool	 rules;

	rules = sid[0] == 'R';
	/* Another host's, asked before this one was chosen: not its. */
	if (strcmp(sid + 1, sn.sid) != 0) {
		free(sid);
		return;
	}
	free(sid);
	sn.loading = false;
	if (status != 200) {
		snprintf(sn.error, sizeof(sn.error), "%s", err != NULL ? err :
		    jstr(o, "error") != NULL ? jstr(o, "error") :
		    "the host did not answer");
		render();
		return;
	}
	sn.error[0] = '\0';
	if (sn.st != NULL)
		ucl_object_unref(sn.st);
	sn.st = jget(o, "data") != NULL ? ucl_object_copy(jget(o, "data")) :
	    ucl_object_typed_new(UCL_OBJECT);
	sn.with_rules = rules;
	render();
}

static void
sn_load(void)
{
	char	url[96], *sid;
	bool	rules;

	if (sn.sid[0] == '\0')
		return;
	rules = sn.view == SN_RULES;
	if (asprintf(&sid, "%c%s", rules ? 'R' : '-', sn.sid) == -1)
		abort();
	snprintf(url, sizeof(url), "/api/servers/%s/snort%s", sn.sid, rules ?
	    "?rules=1" : "");
	sn.loading = true;
	api("GET", url, NULL, sn_cb, sid);
}

/* After a job of the tab's: read again. */
void
snort_refresh(void)
{

	sn_load();
}

/* A snort job: its verb, its words, and text for conf. */
static void
sn_job(const char *verb, const char *const *args, int nargs, const char *text,
    const char *title)
{
	struct server	*s;
	char		*json, *q, *t;
	size_t		 len;
	int		 i;

	if ((s = sn_server()) == NULL)
		return;
	if (asprintf(&json, "{\"kind\":\"snort\",\"verb\":\"%s\",\"args\":[",
	    verb) == -1)
		abort();
	for (i = 0; i < nargs; i++) {
		q = json_quote(args[i]);
		len = strlen(json);
		if (asprintf(&t, "%.*s%s%s", (int)len, json, i > 0 ? "," : "",
		    q) == -1)
			abort();
		free(json);
		free(q);
		json = t;
	}
	q = text != NULL ? json_quote(text) : NULL;
	if (asprintf(&t, "%s]%s%s}", json, q != NULL ? ",\"text\":" : "",
	    q != NULL ? q : "") == -1)
		abort();
	free(json);
	free(q);
	job_send_host(s, t, title, JOB_SNORT, "");
}

/* service arcana_snort start, stop, restart. */
static void
sn_service(const char *what)
{
	struct server	*s;
	char		*json, title[64];

	if ((s = sn_server()) == NULL)
		return;
	if (asprintf(&json, "{\"kind\":\"service-action\",\"service\":"
	    "\"arcana_snort\",\"action\":\"%s\"}", what) == -1)
		abort();
	snprintf(title, sizeof(title), "service arcana_snort %s", what);
	job_send_host(s, json, title, JOB_SNORT, "");
}

/* ---- Views ---------------------------------------------------------- */

static const struct tcol acols[] = {
	{ "Time", "timestamp", false }, { "Rule", "sid", true },
	{ "Message", "msg", false }, { "Class", "class", false },
	{ "Priority", "priority", true }, { "Proto", "proto", false },
	{ "Source", "src_addr", false }, { "Destination", "dst_addr", false },
	{ "Action", "action", false },
};

static void
addr_port(struct html *h, const ucl_object_t *a, const char *addr,
    const char *port)
{

	h_txt(h, jstr(a, addr) != NULL ? jstr(a, addr) : "—");
	if (jget(a, port) != NULL)
		h_fmt(h, "<span class=\"dim\">:%lld</span>", (long long)jint(a,
		    port, 0));
}

static void
view_alerts(struct html *h)
{
	static const char *const key2[] = { NULL, "gid", NULL, NULL, NULL,
	    NULL, "src_port", "dst_port", NULL };
	const ucl_object_t	**rows, *a;
	int			  r;

	if (ucl_array_size(jget(sn.st, "alerts")) == 0) {
		h_raw(h, "<div class=\"empty\"><p>No alerts.</p><p class=\""
		    "dim\">What a rule that is on matches is written to "
		    "alert_json.txt and shows here, the newest first.</p>"
		    "</div>");
		return;
	}
	h_raw(h, "<table class=\"net snort-alerts\">");
	tbl_head(h, "snort-alerts", acols, 9, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows2("snort-alerts", jget(sn.st, "alerts"), acols, key2, 9,
	    app.filter);
	for (r = 0; (a = rows[r]) != NULL; r++) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(a, "timestamp"));
		h_fmt(h, "</td><td class=\"mono\">%lld:%lld</td><td><b>",
		    (long long)jint(a, "gid", 1), (long long)jint(a, "sid", 0));
		h_txt(h, jstr(a, "msg"));
		h_raw(h, "</b></td><td>");
		h_txt(h, jstr(a, "class"));
		h_fmt(h, "</td><td>%lld</td><td>", (long long)jint(a,
		    "priority", 0));
		h_txt(h, jstr(a, "proto"));
		h_raw(h, "</td><td class=\"mono\">");
		addr_port(h, a, "src_addr", "src_port");
		h_raw(h, "</td><td class=\"mono\">");
		addr_port(h, a, "dst_addr", "dst_port");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(a, "action"));
		h_fmt(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
		    "data-act=\"sn-rule\" data-arg=\"%lld:%lld\" data-value=\""
		    "off\" title=\"The rule off, across updates: no more "
		    "alerts of it\">Turn off</button></td></tr>", (long long)
		    jint(a, "gid", 1), (long long)jint(a, "sid", 0));
	}
	free(rows);
	h_raw(h, "</tbody></table>");
}

static const struct tcol rcols[] = {
	{ "On", "on", false }, { "Rule", "sid", true },
	{ "Message", "msg", false }, { "Class", "class", false },
	{ "Action", "action", false }, { "File", "file", false },
};

static void
view_rules(struct html *h)
{
	const ucl_object_t	**rows, *r, *src;
	const char		 *url;
	char			  gs[48];
	int			  i, n;
	bool			  local;

	src = jget(sn.st, "source");
	url = jstr(src, "url");
	h_raw(h, "<form data-form=\"sn-update\" class=\"toolbar sn-update\">"
	    "<label class=\"grow\" title=\"An archive of rules files (or one "
	    ".rules file), by http, https or file:///\">Rules from<input "
	    "name=\"url\" spellcheck=\"false\" autocomplete=\"off\"");
	h_attr(h, "placeholder", url != NULL ? url : jstr(src, "default_url"));
	h_attr(h, "value", sn.url);
	h_raw(h, "></label><label class=\"toggle\" title=\"Snort's registered "
	    "rules, fetched with the oinkcode kept in Settings, Console: the "
	    "code never reaches the host's records\"><input type=\"checkbox\" "
	    "name=\"registered\"><span>registered rules</span></label><button "
	    "class=\"primary\">Update</button></form>");
	if (url != NULL) {
		char	age[32];

		fmt_age(age, sizeof(age), (double)jint(src, "updated", 0) *
		    1000.0);
		h_fmt(h, "<p class=\"dim sn-src\">%lld rules, %lld on. Taken in "
		    "", (long long)jint(src, "rules", 0), (long long)jint(src,
		    "on", 0));
		h_txt(h, age);
		h_raw(h, " from <span class=\"mono\">");
		h_txt(h, url);
		h_raw(h, "</span>, sha256 <span class=\"mono\">");
		h_fmt(h, "%.16s…", jstr(src, "sha256") != NULL ? jstr(src,
		    "sha256") : "");
		h_raw(h, "</span></p>");
	}
	if (!sn.with_rules) {
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	if (ucl_array_size(jget(sn.st, "rules")) == 0) {
		h_raw(h, "<div class=\"empty\"><p>No rules yet.</p><p class=\""
		    "dim\">Update takes in Snort's community rules, or those "
		    "of the address given; local.rules is your own.</p>"
		    "</div>");
		return;
	}
	h_raw(h, "<table class=\"net snort-rules\">");
	tbl_head(h, "snort-rules", rcols, 6, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("snort-rules", jget(sn.st, "rules"), rcols, 6,
	    app.filter);
	for (n = 0; rows[n] != NULL; n++)
		;
	for (i = 0; i < n && i < RULES_SHOWN; i++) {
		r = rows[i];
		local = jstr(r, "file") != NULL && strcmp(jstr(r, "file"),
		    "local.rules") == 0;
		snprintf(gs, sizeof(gs), "%lld:%lld", (long long)jint(r, "gid",
		    1), (long long)jint(r, "sid", 0));
		h_raw(h, "<tr><td>");
		if (local)
			h_fmt(h, "<span class=\"chip %s\" title=\"As local.rules "
			    "has it\">%s</span>", jbool(r, "on") ? "st-up" :
			    "st-down", jbool(r, "on") ? "on" : "off");
		else
			h_fmt(h, "<button class=\"chip %s\" data-act=\"sn-rule\" "
			    "data-arg=\"%s\" data-value=\"%s\" title=\"Turn it "
			    "%s\">%s</button>", jbool(r, "on") ? "st-up" :
			    "st-down", gs, jbool(r, "on") ? "off" : "on",
			    jbool(r, "on") ? "off" : "on", jbool(r, "on") ? "on" :
			    "off");
		h_fmt(h, "</td><td class=\"mono\">%s</td><td>", gs);
		h_txt(h, jstr(r, "msg"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "class"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "action"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "file"));
		h_raw(h, "</td><td class=\"acts\">");
		if (!local && jbool(r, "on") != jbool(r, "default"))
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "sn-rule\" data-arg=\"%s\" data-value=\"default\" "
			    "title=\"As it is shipped: %s\">As shipped</button>",
			    gs, jbool(r, "default") ? "on" : "off");
		h_raw(h, "</td></tr>");
	}
	if (n > RULES_SHOWN)
		h_fmt(h, "<tr class=\"empty-row\"><td colspan=\"7\">%d more: "
		    "narrow them with the filter.</td></tr>", n - RULES_SHOWN);
	free(rows);
	h_raw(h, "</tbody></table>");
}

static void
view_settings(struct html *h)
{
	const ucl_object_t	*rc;
	bool			 ips;

	rc = jget(sn.st, "rc");
	ips = jstr(rc, "mode") != NULL && strcmp(jstr(rc, "mode"), "ips") == 0;
	h_raw(h, "<form data-form=\"sn-set\" class=\"secform sn-set\">"
	    "<label class=\"check\" title=\"arcana_snort_enable: started at "
	    "boot\"><input type=\"checkbox\" name=\"enable\"");
	if (jbool(rc, "enable"))
		h_raw(h, " checked");
	h_raw(h, "><span>Started at boot</span></label><label>Mode<select "
	    "name=\"mode\">");
	h_fmt(h, "<option value=\"ids\"%s>Detects (ids): watches "
	    "interfaces</option><option value=\"ips\"%s>Prevents (ips): "
	    "inline, by ipfw divert</option>", ips ? "" : " selected", ips ?
	    " selected" : "");
	h_raw(h, "</select></label><label title=\"Detects: each watched, a "
	    "packet thread each\">Interfaces<input name=\"interfaces\" "
	    "placeholder=\"em0 em1\" spellcheck=\"false\" autocomplete=\"off\"");
	h_attr(h, "value", jstr(rc, "interfaces"));
	h_raw(h, "></label><label title=\"Prevents: the divert(4) port an ipfw "
	    "rule sends packets to\">Divert port<input name=\"divert_port\" "
	    "inputmode=\"numeric\"");
	h_attr(h, "value", jstr(rc, "divert_port"));
	h_raw(h, "></label><label title=\"snort.lua's HOME_NET: the networks "
	    "the rules call home\">HOME_NET<input name=\"home_net\" "
	    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\""
	    "[192.0.2.0/24,2001:db8::/32]\"");
	h_attr(h, "value", jstr(sn.st, "home_net"));
	h_raw(h, "></label><p class=\"dim wide\">Snort takes rc.conf's settings when "
	    "it starts: restart it after a change. HOME_NET is read again at "
	    "once. In prevent mode, an ipfw rule sends it packets: divert "
	    "<i>port</i> ip from any to any via <i>interface</i>, in "
	    "Firewall.</p><div class=\"actions\"><button class=\"primary\">"
	    "Save</button></div></form>");
}

static void
view_text(struct html *h, enum snview v)
{
	const char	*file;

	file = v == SN_LOCAL ? "local.rules" : "snort.lua";
	if (sn.text == NULL || sn.text_of != v) {
		free(sn.text);
		sn.text = strdup(jstr(sn.st, v == SN_LOCAL ? "local_rules" :
		    "snort_lua") != NULL ? jstr(sn.st, v == SN_LOCAL ?
		    "local_rules" : "snort_lua") : "");
		if (sn.text == NULL)
			abort();
		sn.text_of = v;
	}
	h_fmt(h, "<form data-form=\"sn-conf\" class=\"sn-conf\"><input "
	    "type=\"hidden\" name=\"file\" value=\"%s\"><textarea class=\""
	    "mono\" data-input=\"sn-text\" name=\"text\" rows=\"22\" "
	    "spellcheck=\"false\"", file);
	if (v == SN_LOCAL)
		h_raw(h, " placeholder=\"alert icmp any any -&gt; $HOME_NET "
		    "any (msg:&quot;ping&quot;; itype:8; sid:1000001; rev:1;)\"");
	h_raw(h, ">");
	h_txt(h, sn.text);
	h_fmt(h, "</textarea><p class=\"dim\">Checked by snort -T on the host "
	    "first: what it refuses is not written. %s</p><div class=\""
	    "buttons\"><button class=\"ghost\" type=\"button\" data-act=\""
	    "sn-revert\">As the host has it</button><button class=\"primary\">"
	    "Save %s</button></div></form>", v == SN_LOCAL ? "Your own rules, "
	    "included after those taken in." : "Snort's configuration: Arcana "
	    "gives it the rules by -R.", file);
}

/* The Snort tab of the Security page, for the host sid. */
void
view_snort(struct html *h, const char *sid)
{
	static const char *const names[] = { "Alerts", "Rules", "Settings",
	    "local.rules", "snort.lua" };
	const ucl_object_t	*rc, *w, *src;
	ucl_object_iter_t	 it;
	size_t			 i;
	bool			 running;

	if (strcmp(sid, sn.sid) != 0) {
		snprintf(sn.sid, sizeof(sn.sid), "%s", sid);
		if (sn.st != NULL)
			ucl_object_unref(sn.st);
		sn.st = NULL;
		free(sn.text);
		sn.text = NULL;
		sn.error[0] = '\0';
		sn_load();
	}
	if (sn.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, sn.error);
		h_raw(h, "</div>");
	}
	if (sn.st == NULL) {
		if (sn.error[0] == '\0')
			h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	if (!jbool(sn.st, "installed")) {
		h_raw(h, "<div class=\"empty\"><p>Snort is not installed here."
		    "</p><p class=\"dim\">Snort 3 watches interfaces for what "
		    "its rules match, or, inline behind an ipfw divert rule, "
		    "drops it. It is a plugin; Arcana runs it by its own rc.d "
		    "script, arcana_snort, as the package has none.</p><button "
		    "class=\"primary\" data-act=\"sn-install\">Install snort3"
		    "</button></div>");
		return;
	}
	rc = jget(sn.st, "rc");
	running = jbool(sn.st, "running");
	h_raw(h, "<div class=\"toolbar sn-head\">");
	h_fmt(h, "<span class=\"chip %s\">%s</span>", running ? "st-up" :
	    "st-down", running ? "running" : "stopped");
	h_raw(h, "<span class=\"dim\">Snort ");
	h_txt(h, jstr(sn.st, "version"));
	h_raw(h, " · ");
	if (jstr(rc, "mode") != NULL && strcmp(jstr(rc, "mode"), "ips") == 0) {
		h_raw(h, "prevents, divert ");
		h_txt(h, jstr(rc, "divert_port"));
	} else {
		h_raw(h, "detects on ");
		h_txt(h, jstr(rc, "interfaces") != NULL && jstr(rc,
		    "interfaces")[0] != '\0' ? jstr(rc, "interfaces") :
		    "no interface");
	}
	h_fmt(h, "%s</span><span class=\"grow\"></span>", jbool(rc, "enable") ?
	    " · at boot" : "");
	if (running)
		h_raw(h, "<button class=\"ghost small\" data-act=\"sn-service\" "
		    "data-arg=\"restart\">Restart</button><button class=\""
		    "ghost small danger\" data-act=\"sn-service\" data-arg=\""
		    "stop\">Stop</button>");
	else
		h_raw(h, "<button class=\"small\" data-act=\"sn-service\" "
		    "data-arg=\"start\">Start</button>");
	h_raw(h, "</div>");
	it = NULL;
	while ((w = ucl_object_iterate(jget(sn.st, "warnings"), &it, true)) !=
	    NULL) {
		h_raw(h, "<div class=\"notice warn\">");
		h_txt(h, ucl_object_tostring(w));
		h_raw(h, "</div>");
	}
	src = jget(sn.st, "source");
	h_raw(h, "<nav class=\"sub\">");
	for (i = 0; i < nitems(names); i++) {
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"sn-view\" "
		    "data-arg=\"%s\">%s", (size_t)sn.view == i ? " on" : "",
		    views[i], names[i]);
		if (i == SN_ALERTS)
			h_fmt(h, " <small>%u</small>", ucl_array_size(jget(sn.st,
			    "alerts")));
		else if (i == SN_RULES)
			h_fmt(h, " <small>%lld/%lld</small>", (long long)jint(src,
			    "on", 0), (long long)jint(src, "rules", 0));
		h_raw(h, "</button>");
	}
	h_raw(h, "</nav>");
	if (sn.view == SN_ALERTS || sn.view == SN_RULES) {
		h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\""
		    "filter\" data-input=\"filter\" placeholder=\"Filter\" "
		    "autocomplete=\"off\" spellcheck=\"false\"");
		h_attr(h, "value", app.filter);
		h_raw(h, "></div>");
	}
	switch (sn.view) {
	case SN_ALERTS:
		view_alerts(h);
		break;
	case SN_RULES:
		view_rules(h);
		break;
	case SN_SETTINGS:
		view_settings(h);
		break;
	case SN_LOCAL:
	case SN_LUA:
		view_text(h, sn.view);
		break;
	}
}

/* ---- Doing ---------------------------------------------------------- */

bool
snort_form(const char *form, const ucl_object_t *f)
{
	const char	*args[40], *v, *rules, *mode, *ifs, *port, *hn;
	char		*copy, *it, *w, buf[1200];
	int		 n;

	if (strcmp(form, "sn-update") == 0) {
		v = jstr(f, "url") != NULL ? jstr(f, "url") : "";
		snprintf(sn.url, sizeof(sn.url), "%s", v);
		/* The registered rules: the console adds the oinkcode. */
		if (jbool(f, "registered")) {
			args[0] = "registered=yes";
			sn_job("update", args, 1, NULL, "snort update: the "
			    "registered rules fetched and checked");
			return (true);
		}
		snprintf(buf, sizeof(buf), "url=%s", v);
		args[0] = buf;
		sn_job("update", args, v[0] != '\0' ? 1 : 0, NULL,
		    "snort update: the rules fetched and checked");
		return (true);
	}
	if (strcmp(form, "sn-conf") == 0) {
		v = jstr(f, "file") != NULL ? jstr(f, "file") : "";
		if (strcmp(v, "snort.lua") != 0 && strcmp(v, "local.rules") != 0)
			return (true);
		snprintf(buf, sizeof(buf), "file=%s", v);
		args[0] = buf;
		rules = sn.text != NULL ? sn.text : jstr(f, "text") != NULL ?
		    jstr(f, "text") : "";
		snprintf(buf + 600, sizeof(buf) - 600, "snort %s written", v);
		sn_job("conf", args, 1, rules, buf + 600);
		return (true);
	}
	if (strcmp(form, "sn-set") != 0)
		return (false);
	mode = jstr(f, "mode") != NULL ? jstr(f, "mode") : "ids";
	ifs = jstr(f, "interfaces") != NULL ? jstr(f, "interfaces") : "";
	port = jstr(f, "divert_port") != NULL ? jstr(f, "divert_port") : "";
	hn = jstr(f, "home_net") != NULL ? jstr(f, "home_net") : "";
	n = 0;
	args[n++] = jbool(f, "enable") ? "enable=yes" : "enable=no";
	args[n++] = strcmp(mode, "ips") == 0 ? "mode=ips" : "mode=ids";
	/* The interfaces as a whole, each a word; none, an empty one. */
	copy = strdup(ifs);
	if (copy == NULL)
		abort();
	for (it = copy; (w = strsep(&it, " ,\t")) != NULL && n < 32; ) {
		if (w[0] == '\0')
			continue;
		if (asprintf((char **)(uintptr_t)&args[n++], "interface=%s", w) ==
		    -1)
			abort();
	}
	if (n == 2)
		args[n++] = "interface=";
	if (port[0] != '\0') {
		snprintf(buf, sizeof(buf), "divert_port=%s", port);
		args[n++] = buf;
	}
	/* HOME_NET when it changes: snort.lua is written for it. */
	if (hn[0] != '\0' && (jstr(sn.st, "home_net") == NULL ||
	    strcmp(hn, jstr(sn.st, "home_net")) != 0)) {
		if (asprintf((char **)(uintptr_t)&args[n++], "home_net=%s", hn) ==
		    -1)
			abort();
	}
	sn_job("set", args, n, NULL, "snort set: rc.conf's settings");
	free(copy);
	return (true);
}

bool
snort_action(const char *act, const char *arg, const char *value)
{
	const char	*args[1];
	char		 w[64], title[96];
	size_t		 i;

	if (strcmp(act, "input:sn-text") == 0) {
		free(sn.text);
		if ((sn.text = strdup(value != NULL ? value : "")) == NULL)
			abort();
		return (true);
	}
	if (strncmp(act, "sn-", 3) != 0)
		return (false);
	if (strcmp(act, "sn-view") == 0) {
		for (i = 0; i < nitems(views); i++)
			if (strcmp(arg, views[i]) == 0)
				sn.view = (enum snview)i;
		app.filter[0] = '\0';
		if (sn.view == SN_RULES && !sn.with_rules)
			sn_load();
		return (true);
	}
	if (strcmp(act, "sn-revert") == 0) {
		free(sn.text);
		sn.text = NULL;
		return (true);
	}
	if (strcmp(act, "sn-rule") == 0) {
		if (value == NULL || (strcmp(value, "on") != 0 && strcmp(value,
		    "off") != 0 && strcmp(value, "default") != 0) ||
		    strspn(arg, "0123456789:") != strlen(arg))
			return (true);
		snprintf(w, sizeof(w), "%s=%s", value, arg);
		args[0] = w;
		snprintf(title, sizeof(title), "snort rule %s", w);
		sn_job("rule", args, 1, NULL, title);
		return (true);
	}
	if (strcmp(act, "sn-service") == 0) {
		if (strcmp(arg, "start") == 0 || strcmp(arg, "stop") == 0 ||
		    strcmp(arg, "restart") == 0)
			sn_service(arg);
		return (true);
	}
	if (strcmp(act, "sn-install") == 0) {
		struct server	*s;
		char		*json;

		if ((s = sn_server()) == NULL)
			return (true);
		if ((json = strdup("{\"kind\":\"pkg-install\",\"packages\":"
		    "[\"snort3\"]}")) == NULL)
			abort();
		job_send_host(s, json, "pkg install snort3", JOB_SNORT, "");
		return (true);
	}
	return (false);
}

/* While the tab is shown: read again every 10 s, but not under a hand
 * that is writing. */
void
snort_tick(double now)
{
	static double	last;

	if (!app.visible || sn.loading || sn.sid[0] == '\0' || sn.view ==
	    SN_LOCAL || sn.view == SN_LUA || sn.view == SN_SETTINGS ||
	    now - last < 10000)
		return;
	last = now;
	sn_load();
}

void
snort_loc(char *buf, size_t len)
{

	snprintf(buf, len, "%s", views[sn.view]);
}
