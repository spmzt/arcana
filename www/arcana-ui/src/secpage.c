/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Security page: the luxuria plugins that guard a host by
 * themselves, apart from SD-WAN, a tab each.  URL filter: Squid as a
 * proxy the clients are told of.  Malware: c-icap with ClamAV's module
 * scanning what a URL filter fetches.  Signatures: ClamAV's databases as
 * freshclam keeps them.  IDS/IPS: Suricata, watching interfaces or
 * taking what an ipfw divert rule hands it.  Snort: Snort 3, the same
 * by Arcana's rc.d script, its rules kept (snort.c).  A host at a time: its
 * sdwan read tells what runs and the forms it was given; a save sends
 * the kind's whole list (POST /api/servers/<id>/security).
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

enum sectab { SEC_URL, SEC_MALWARE, SEC_SIGS, SEC_IDS, SEC_SNORT };

static struct {
	enum sectab	 tab;
	char		 sid[16];
	ucl_object_t	*state;		/* the host's sdwan read */
	bool		 loading;
	char		 error[256];
	int		 edit;		/* the form open: an index, n for a new
					 * one, -1 none */
	bool		 busy;
} sec = { .edit = -1 };

static const char *const tabs[] = { "url", "malware", "signatures", "ids",
    "snort" };

static void
sec_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid = arg;

	/* Another host's, asked before this one was chosen: not its. */
	if (strcmp(sid, sec.sid) != 0) {
		free(sid);
		return;
	}
	free(sid);
	sec.loading = false;
	if (status != 200) {
		snprintf(sec.error, sizeof(sec.error), "%s", err != NULL ? err :
		    jstr(o, "error") != NULL ? jstr(o, "error") :
		    "the host did not answer");
		render();
		return;
	}
	sec.error[0] = '\0';
	if (sec.state != NULL)
		ucl_object_unref(sec.state);
	/* The read is under data, beside the server and when it was. */
	sec.state = jget(o, "data") != NULL ? ucl_object_copy(jget(o,
	    "data")) : ucl_object_typed_new(UCL_OBJECT);
	render();
}

static void
sec_load(void)
{
	char	url[96], *sid;

	if (sec.sid[0] == '\0')
		return;
	if ((sid = strdup(sec.sid)) == NULL)
		abort();
	snprintf(url, sizeof(url), "/api/servers/%s/sdwan", sec.sid);
	sec.loading = true;
	api("GET", url, NULL, sec_cb, sid);
}

/* The kind's forms on the host: what the page last saved. */
static const ucl_object_t *
specs(bool ids)
{

	return (jget(sec.state, ids ? "security_ids" : "security_proxy"));
}

/* What runs of a form's instance: its entry in the host's read. */
static const ucl_object_t *
live(bool ids, const char *name)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(jget(sec.state, ids ? "ids" : "proxy"),
	    &it, true)) != NULL)
		if (jstr(e, "name") != NULL && name != NULL && strcmp(jstr(e,
		    "name"), name) == 0)
			return (e);
	return (NULL);
}

/* A list's strings joined by sep. */
static void
joined(struct html *h, const ucl_object_t *arr, const char *sep)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	bool			 first;

	first = true;
	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (!first)
			h_raw(h, sep);
		h_txt(h, ucl_object_tostring_forced(e));
		first = false;
	}
}

static void
joined_attr(struct html *h, const char *attr, const ucl_object_t *arr,
    const char *sep)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	char			*buf;
	size_t			 len;

	len = 1;
	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL)
		len += strlen(ucl_object_tostring_forced(e)) + strlen(sep);
	if ((buf = calloc(1, len)) == NULL)
		abort();
	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (buf[0] != '\0')
			strlcat(buf, sep, len);
		strlcat(buf, ucl_object_tostring_forced(e), len);
	}
	h_attr(h, attr, buf);
	free(buf);
}

static void
chip_run(struct html *h, const ucl_object_t *l, const char *key)
{

	if (l == NULL)
		h_raw(h, "<span class=\"chip warn\" title=\"Not applied: the "
		    "host has not taken it, see the last error\">not "
		    "running</span>");
	else if (jbool(l, key))
		h_raw(h, "<span class=\"chip st-up\">running</span>");
	else
		h_raw(h, "<span class=\"chip st-down\">stopped</span>");
}

static void
host_pick(struct html *h)
{
	int	i;

	h_raw(h, "<label class=\"secpick\">Host <select data-input=\"sec-host\">");
	if (sec.sid[0] == '\0')
		h_raw(h, "<option value=\"\" selected>choose…</option>");
	for (i = 0; i < app.nservers; i++) {
		h_raw(h, "<option");
		h_attr(h, "value", app.servers[i].id);
		if (strcmp(app.servers[i].id, sec.sid) == 0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, app.servers[i].name);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label>");
}

/* The server the page shows. */
static struct server *
sec_server(void)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sec.sid) == 0)
			return (&app.servers[i]);
	return (NULL);
}

/*
 * What a tab needs and the host has not: said, with a button that
 * installs it (pkg install), pressed by whoever reads it; Arcana
 * installs nothing by itself.  pkgs: the packages, a space between.
 */
static void
missing(struct html *h, const char *what, const char *pkgs)
{

	h_raw(h, "<div class=\"notice warn sec-missing\"><span>");
	h_txt(h, what);
	h_raw(h, "</span><button class=\"primary small\" data-act=\""
	    "sec-install\"");
	h_attr(h, "data-arg", pkgs);
	h_raw(h, ">Install ");
	h_txt(h, pkgs);
	h_raw(h, "</button></div>");
}

/* Has the host the plugin? Unknown, while its list is not read, is yes. */
static bool
sec_has(const char *plugin)
{
	struct server	*s;

	if ((s = sec_server()) == NULL || s->list == NULL)
		return (true);
	return (has_plugin(s, plugin));
}

/* ---- URL filter ------------------------------------------------------- */

static void
proxy_form(struct html *h, const ucl_object_t *f)
{
	const char	*mode;

	mode = jstr(f, "mode") != NULL ? jstr(f, "mode") : "sni";
	h_raw(h, "<form class=\"secform\" data-form=\"sec-proxy\" "
	    "id=\"sec-proxy\"><h4>");
	h_raw(h, f != NULL ? "Change the URL filter" : "A URL filter");
	h_raw(h, "</h4><input type=\"hidden\" name=\"orig\"");
	h_attr(h, "value", jstr(f, "name") != NULL ? jstr(f, "name") : "");
	h_raw(h, "><label>Name <input name=\"name\" required "
	    "pattern=\"sec-[A-Za-z0-9_-]{1,28}\" spellcheck=\"false\"");
	h_attr(h, "value", jstr(f, "name") != NULL ? jstr(f, "name") :
	    "sec-web");
	h_raw(h, "><small class=\"help\">sec- and letters, digits, _ or -: "
	    "its files and logs are named by it</small></label>"
	    "<label>Listens on <input name=\"listen\" required "
	    "spellcheck=\"false\" placeholder=\"192.0.2.1, 2001:db8::1\"");
	joined_attr(h, "value", jget(f, "listen"), ", ");
	h_raw(h, "><small class=\"help\">the host's addresses the clients "
	    "are told of: their browsers' proxy, or WPAD</small></label>"
	    "<label>Port <input name=\"port\" type=\"number\" min=\"1\" "
	    "max=\"65535\"");
	h_fmt(h, " value=\"%lld\"", (long long)jint(f, "port", 3128));
	h_raw(h, "></label><label>Who may use it <input name=\"allow\" "
	    "spellcheck=\"false\" placeholder=\"10.0.0.0/8, "
	    "192.168.0.0/16\"");
	joined_attr(h, "value", jget(f, "allow"), ", ");
	h_raw(h, "><small class=\"help\">networks, the rest refused</small>"
	    "</label>");
	pfxlist_select(h, "And the networks of a list", "allow_pfx", "A prefix "
	    "list of the console's, added to the networks when kept.");
	h_raw(h, "<label>TLS <select name=\"mode\">");
	h_fmt(h, "<option value=\"sni\"%s>its name looked at (sni): denied "
	    "ones ended, the rest left unopened</option><option value=\""
	    "inspect\"%s>opened (inspect): the clients trust this filter's "
	    "own CA</option>", strcmp(mode, "sni") == 0 ? " selected" : "",
	    strcmp(mode, "inspect") == 0 ? " selected" : "");
	h_raw(h, "</select></label><label>Denied <textarea name=\"deny\" "
	    "rows=\"5\" spellcheck=\"false\" placeholder=\"example.com\">");
	joined(h, jget(f, "deny"), "\n");
	h_raw(h, "</textarea><small class=\"help\">a domain a line: the names "
	    "beneath it too</small></label><label class=\"check\">"
	    "<input type=\"checkbox\" name=\"malware\"");
	if (jbool(f, "malware"))
		h_raw(h, " checked");
	h_raw(h, "> Scan what it fetches for malware <small class=\"help\">"
	    "c-icap with ClamAV, on the loopback (the Malware tab)</small>"
	    "</label><details class=\"wfmore\"><summary>More options</summary>"
	    "<label>Routing table <input name=\"fib\" type=\"number\" min=\"0\" "
	    "max=\"65535\"");
	h_fmt(h, " value=\"%lld\"", (long long)jint(f, "fib", 0));
	h_raw(h, "><small class=\"help\">setfib(1): the table it reaches the "
	    "web by</small></label></details><div class=\"actions\">"
	    "<button type=\"button\" class=\"ghost\" data-act=\"sec-cancel\">"
	    "Cancel</button><button type=\"submit\" class=\"primary\"");
	if (sec.busy)
		h_raw(h, " disabled");
	h_raw(h, ">Save</button></div></form>");
}

static const struct tcol pcols[] = {
	{ "Name", "name", false }, { "Listens on", NULL, false },
	{ "TLS", "mode", false }, { "Denied", NULL, true },
	{ "Malware", "malware", false }, { "State", NULL, false },
};

static void
view_url(struct html *h, bool malware_only)
{
	const ucl_object_t	**rows, *f, *l;
	int			  r, n;

	if (!malware_only && !sec_has("squid"))
		missing(h, "Squid is not installed on this host: a URL filter "
		    "is Squid.", "squid");
	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\"filter\" "
	    "data-input=\"filter\" placeholder=\"Filter\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, ">");
	if (!malware_only)
		h_raw(h, "<button class=\"primary\" data-act=\"sec-new\">New URL "
		    "filter</button>");
	h_raw(h, "</div>");
	n = (int)ucl_array_size(specs(false));
	if (sec.edit >= 0 && !malware_only)
		proxy_form(h, sec.edit < n ? ucl_array_find_index(specs(false),
		    (unsigned)sec.edit) : NULL);
	if (n == 0) {
		h_raw(h, "<div class=\"empty\"><p>No URL filter on this host.</p>"
		    "<p class=\"dim\">Squid as a proxy the clients are told of: "
		    "what they ask for by a denied name is refused, its TLS "
		    "ended at the name.</p></div>");
		return;
	}
	h_raw(h, "<table class=\"net secproxy\">");
	tbl_head(h, "secproxy", pcols, 6, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("secproxy", specs(false), pcols, 6, app.filter);
	for (r = 0; (f = rows[r]) != NULL; r++) {
		if (malware_only && !jbool(f, "malware"))
			continue;
		l = live(false, jstr(f, "name"));
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(f, "name"));
		h_raw(h, "</b></td><td class=\"mono\">");
		joined(h, jget(f, "listen"), ", ");
		h_fmt(h, " <small class=\"dim\">port %lld</small></td><td>%s"
		    "</td><td>%u</td><td>", (long long)jint(f, "port", 3128),
		    jstr(f, "mode") != NULL && strcmp(jstr(f, "mode"),
		    "inspect") == 0 ? "inspected" : "names looked at",
		    ucl_array_size(jget(f, "deny")));
		if (!jbool(f, "malware"))
			h_raw(h, "<span class=\"dim\">not scanned</span>");
		else if (l != NULL && jget(l, "icap") != NULL)
			h_raw(h, jbool(l, "icap") ? "<span class=\"chip st-up\">"
			    "c-icap running</span>" : "<span class=\"chip "
			    "st-down\">c-icap stopped</span>");
		else
			h_raw(h, "<span class=\"chip warn\">not applied</span>");
		h_raw(h, "</td><td>");
		chip_run(h, l, "running");
		h_raw(h, "</td><td class=\"acts\">");
		h_fmt(h, "<button class=\"ghost small\" data-act=\"%s\"",
		    malware_only ? "sec-unscan" : "sec-edit");
		h_attr(h, "data-arg", jstr(f, "name"));
		h_fmt(h, ">%s</button>", malware_only ? "Stop scanning" :
		    "Change");
		if (!malware_only) {
			h_raw(h, "<button class=\"ghost small danger\" "
			    "data-act=\"sec-remove\" data-value=\"proxy\"");
			h_attr(h, "data-arg", jstr(f, "name"));
			h_raw(h, ">Remove</button>");
		}
		h_raw(h, "</td></tr>");
		/* The CA the clients are to trust, where TLS is opened. */
		if (!malware_only && l != NULL && jstr(l, "ca") != NULL &&
		    jstr(f, "mode") != NULL && strcmp(jstr(f, "mode"),
		    "inspect") == 0) {
			h_raw(h, "<tr class=\"sub\"><td colspan=\"7\"><details>"
			    "<summary>Its CA, for the clients to trust</summary>"
			    "<pre class=\"cert\">");
			h_txt(h, jstr(l, "ca"));
			h_raw(h, "</pre></details></td></tr>");
		}
	}
	free(rows);
	h_raw(h, "</tbody></table>");
}

/* ---- Malware and signatures ------------------------------------------- */

static void
view_malware(struct html *h)
{
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;
	int			 n;

	if (!sec_has("c-icap") || jget(sec.state, "clamav") == NULL)
		missing(h, "Scanning needs c-icap, its modules and ClamAV, not "
		    "all installed on this host.", "c-icap c-icap-modules "
		    "clamav");
	h_raw(h, "<p class=\"lead\">c-icap with ClamAV's module scans what a "
	    "URL filter fetches, before the client has it: one that holds "
	    "malware is refused. Each URL filter that scans has its own "
	    "c-icap on the loopback; turn it on in the filter's form. "
	    "ClamAV's signatures are freshclam's (the Signatures tab).</p>");
	n = 0;
	it = NULL;
	while ((f = ucl_object_iterate(specs(false), &it, true)) != NULL)
		if (jbool(f, "malware"))
			n++;
	if (n == 0) {
		h_raw(h, "<div class=\"empty\"><p>No URL filter here scans for "
		    "malware.</p><p class=\"dim\">Change a filter on the URL "
		    "filter tab and tick “Scan what it fetches for malware”. "
		    "It needs the plugins c-icap, c-icap-modules and clamav "
		    "installed.</p><button class=\"ghost\" data-act=\"sec-tab\" "
		    "data-arg=\"url\">URL filters</button></div>");
		return;
	}
	view_url(h, true);
}

static const struct tcol dcols[] = {
	{ "Database", "name", false }, { "Version", "version", true },
	{ "Signatures", "signatures", true }, { "Built", "built", false },
	{ "File", "file", false },
};

static void
view_sigs(struct html *h)
{
	const ucl_object_t	**rows, *cl, *d;
	int			  r;

	cl = jget(sec.state, "clamav");
	h_raw(h, "<p class=\"lead\">ClamAV's signatures, as freshclam fetches "
	    "them from ClamAV's mirrors into /var/db/clamav: the malware "
	    "scanning knows what they know. freshclam runs as the service "
	    "clamav_freshclam.</p>");
	if (cl == NULL) {
		missing(h, "ClamAV is not installed on this host.", "clamav");
		h_raw(h, "<div class=\"empty\"><p>No ClamAV here.</p><p class=\""
		    "dim\">Once it is installed, start freshclam here, and "
		    "enable clamav_freshclam on the Services tab to have it at "
		    "boot.</p></div>");
		return;
	}
	h_fmt(h, "<div class=\"toolbar\">%s<button class=\"ghost\" "
	    "data-act=\"sec-freshclam\" data-arg=\"%s\" title=\"freshclam looks "
	    "for new signatures as it starts\">%s</button></div>",
	    jbool(cl, "freshclam") ? "<span class=\"chip st-up\">freshclam "
	    "running</span>" : "<span class=\"chip st-down\">freshclam not "
	    "running: the signatures age</span>", jbool(cl, "freshclam") ?
	    "restart" : "start", jbool(cl, "freshclam") ? "Look now (restart)" :
	    "Start freshclam");
	/* Why signatures may not come: no freshclam.conf but the port's
	 * sample, which freshclam refuses; and its log's last lines. */
	if (jget(cl, "conf") != NULL && !jbool(cl, "conf"))
		h_raw(h, "<div class=\"notice warn\">freshclam has no "
		    "configuration: <code>/usr/local/etc/freshclam.conf</code> is "
		    "missing, or still the port's sample with its <code>Example"
		    "</code> line, which freshclam refuses to run with. Copy "
		    "<code>freshclam.conf.sample</code> to it and take that line "
		    "out (Files, or the shell), then start freshclam here.</div>");
	if (ucl_array_size(jget(cl, "log")) > 0) {
		const ucl_object_t	*ln;
		ucl_object_iter_t	 lit = NULL;

		h_raw(h, "<pre class=\"out dim seclog\" title=\"/var/log/clamav/"
		    "freshclam.log, its last lines\">");
		while ((ln = ucl_object_iterate(jget(cl, "log"), &lit, true)) !=
		    NULL) {
			h_txt(h, ucl_object_tostring_forced(ln));
			h_raw(h, "\n");
		}
		h_raw(h, "</pre>");
	}
	if (ucl_array_size(jget(cl, "databases")) == 0) {
		h_raw(h, "<div class=\"empty\"><p>No signatures yet.</p><p class="
		    "\"dim\">freshclam has not fetched them: start it; the first "
		    "fetch takes minutes, the page looks again by itself.</p>"
		    "</div>");
		return;
	}
	h_raw(h, "<table class=\"net secsigs\">");
	tbl_head(h, "secsigs", dcols, 5, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("secsigs", jget(cl, "databases"), dcols, 5,
	    app.filter);
	for (r = 0; (d = rows[r]) != NULL; r++) {
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(d, "name"));
		h_fmt(h, "</b></td><td>%lld</td><td>%lld</td><td>", (long long)
		    jint(d, "version", 0), (long long)jint(d, "signatures", 0));
		h_txt(h, jstr(d, "built"));
		h_raw(h, "</td><td class=\"mono dim\">");
		h_txt(h, jstr(d, "file"));
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
}

/* ---- IDS/IPS ---------------------------------------------------------- */

static void
ids_form(struct html *h, const ucl_object_t *f)
{

	h_raw(h, "<form class=\"secform\" data-form=\"sec-ids\" id=\"sec-ids\">"
	    "<h4>");
	h_raw(h, f != NULL ? "Change the intrusion detection" :
	    "An intrusion detection");
	h_raw(h, "</h4><input type=\"hidden\" name=\"orig\"");
	h_attr(h, "value", jstr(f, "name") != NULL ? jstr(f, "name") : "");
	h_raw(h, "><label>Name <input name=\"name\" required "
	    "pattern=\"sec-[A-Za-z0-9_-]{1,28}\" spellcheck=\"false\"");
	h_attr(h, "value", jstr(f, "name") != NULL ? jstr(f, "name") :
	    "sec-lan");
	h_raw(h, "></label><label>Interfaces <input name=\"interfaces\" "
	    "required spellcheck=\"false\" placeholder=\"em0, vtnet1\"");
	joined_attr(h, "value", jget(f, "interfaces"), ", ");
	h_raw(h, "><small class=\"help\">what it watches, by pcap(3)</small>"
	    "</label><label>The networks it guards <input name=\"home\" "
	    "spellcheck=\"false\" placeholder=\"10.0.0.0/8, 172.16.0.0/12, "
	    "192.168.0.0/16\"");
	joined_attr(h, "value", jget(f, "home"), ", ");
	h_raw(h, "><small class=\"help\">HOME_NET of the rules; empty: the "
	    "private ranges</small></label>");
	pfxlist_select(h, "And the networks of a list", "home_pfx", "A prefix "
	    "list of the console's, added to HOME_NET when kept.");
	h_raw(h, "<label class=\"check\"><input type=\"checkbox\" name=\""
	    "ruleset\"");
	if (f == NULL || jbool(f, "ruleset"))
		h_raw(h, " checked");
	h_raw(h, "> The ruleset suricata-update keeps <small class=\"help\">"
	    "/var/lib/suricata/rules/suricata.rules: run suricata-update to "
	    "fetch it</small></label><label>Rules of its own <textarea "
	    "name=\"rules\" rows=\"4\" spellcheck=\"false\" placeholder=\""
	    "alert tcp any any -> $HOME_NET 23 (msg:&quot;telnet&quot;; "
	    "sid:1000001;)\">");
	h_txt(h, jstr(f, "rules"));
	h_raw(h, "</textarea><small class=\"help\">a rule a line, as "
	    "Suricata writes them</small></label><details class=\"wfmore\"");
	if (jint(f, "divert", 0) > 0)
		h_raw(h, " open");
	h_raw(h, "><summary>Prevent, not only detect</summary><label>Divert "
	    "port <input name=\"divert\" type=\"number\" min=\"1\" "
	    "max=\"65535\" placeholder=\"8600\"");
	if (jint(f, "divert", 0) > 0)
		h_fmt(h, " value=\"%lld\"", (long long)jint(f, "divert", 0));
	h_raw(h, "><small class=\"help\">Suricata takes the packets an ipfw "
	    "divert rule sends to this port, and drops what its rules say "
	    "drop. Add the rule on the Firewall tab, e.g. <code>divert 8600 "
	    "ip from any to any via em0</code>. While it is stopped, what "
	    "is diverted is dropped: empty, it only detects.</small>"
	    "</label></details><div class=\"actions\"><button type=\"button\" "
	    "class=\"ghost\" data-act=\"sec-cancel\">Cancel</button><button "
	    "type=\"submit\" class=\"primary\"");
	if (sec.busy)
		h_raw(h, " disabled");
	h_raw(h, ">Save</button></div></form>");
}

static const struct tcol icols[] = {
	{ "Name", "name", false }, { "Interfaces", NULL, false },
	{ "Does", NULL, false }, { "Alerts", NULL, true },
	{ "State", NULL, false },
};

static void
view_ids(struct html *h)
{
	const ucl_object_t	**rows, *f, *l, *a;
	ucl_object_iter_t	  it;
	int			  r, n;

	if (!sec_has("suricata"))
		missing(h, "Suricata is not installed on this host: intrusion "
		    "detection here is Suricata.", "suricata");
	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\"filter\" "
	    "data-input=\"filter\" placeholder=\"Filter\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "><button class=\"primary\" data-act=\"sec-new\">New "
	    "intrusion detection</button></div>");
	n = (int)ucl_array_size(specs(true));
	if (sec.edit >= 0)
		ids_form(h, sec.edit < n ? ucl_array_find_index(specs(true),
		    (unsigned)sec.edit) : NULL);
	if (n == 0) {
		h_raw(h, "<div class=\"empty\"><p>No intrusion detection on this "
		    "host.</p><p class=\"dim\">Suricata watching interfaces, "
		    "its alerts here; or, where it prevents, dropping what its "
		    "rules say.</p></div>");
		return;
	}
	h_raw(h, "<table class=\"net secids\">");
	tbl_head(h, "secids", icols, 5, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("secids", specs(true), icols, 5, app.filter);
	for (r = 0; (f = rows[r]) != NULL; r++) {
		l = live(true, jstr(f, "name"));
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(f, "name"));
		h_raw(h, "</b></td><td class=\"mono\">");
		joined(h, jget(f, "interfaces"), ", ");
		if (jint(f, "divert", 0) > 0)
			h_fmt(h, "</td><td>prevents <small class=\"dim\">divert "
			    "%lld</small></td>", (long long)jint(f, "divert", 0));
		else
			h_raw(h, "</td><td>detects</td>");
		h_fmt(h, "<td>%lld</td><td>", (long long)jint(l, "alerts_seen",
		    0));
		chip_run(h, l, "running");
		h_raw(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
		    "data-act=\"sec-edit\"");
		h_attr(h, "data-arg", jstr(f, "name"));
		h_raw(h, ">Change</button><button class=\"ghost small danger\" "
		    "data-act=\"sec-remove\" data-value=\"ids\"");
		h_attr(h, "data-arg", jstr(f, "name"));
		h_raw(h, ">Remove</button></td></tr>");
		if (ucl_array_size(jget(l, "alerts")) == 0)
			continue;
		h_raw(h, "<tr class=\"sub\"><td colspan=\"6\"><ul class=\""
		    "secalerts\">");
		it = NULL;
		while ((a = ucl_object_iterate(jget(l, "alerts"), &it, true)) !=
		    NULL) {
			h_raw(h, "<li><span class=\"dim mono\">");
			h_txt(h, jstr(a, "timestamp"));
			h_raw(h, "</span> <b>");
			h_txt(h, jstr(a, "signature") != NULL ? jstr(a,
			    "signature") : jstr(a, "alert.signature"));
			h_raw(h, "</b> <span class=\"mono\">");
			h_txt(h, jstr(a, "src_ip"));
			h_raw(h, " → ");
			h_txt(h, jstr(a, "dest_ip"));
			h_raw(h, "</span></li>");
		}
		h_raw(h, "</ul></td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
}

void
view_secpage(struct html *h)
{
	static const char *const names[] = { "URL filter", "Malware",
	    "Signatures", "IDS/IPS", "Snort" };
	static const char *const titles[] = {
	    "Squid: what the clients ask for, by name",
	    "c-icap with ClamAV: what a URL filter fetches, scanned",
	    "freshclam: ClamAV's signatures",
	    "Suricata: intrusion detection, and prevention",
	    "Snort 3: intrusion detection and prevention, its rules here" };
	size_t	i;

	h_raw(h, "<section class=\"secpage\"><div class=\"sechead\">");
	host_pick(h);
	h_raw(h, "</div><nav class=\"tabs\">");
	for (i = 0; i < nitems(names); i++) {
		h_fmt(h, "<button class=\"tab%s\" data-act=\"sec-tab\" "
		    "data-arg=\"%s\" title=\"%s\">%s</button>", (size_t)sec.tab ==
		    i ? " on" : "", tabs[i], titles[i], names[i]);
	}
	h_raw(h, "</nav>");
	if (sec.sid[0] == '\0') {
		h_raw(h, "<div class=\"empty\"><p>Choose a host.</p><p class=\""
		    "dim\">Each guards itself: its own URL filters, malware "
		    "scanning and intrusion detection, by plugins it has "
		    "installed (Arcana installs nothing).</p></div></section>");
		return;
	}
	/* Snort's tab reads its own, not the host's sdwan read. */
	if (sec.tab == SEC_SNORT) {
		view_snort(h, sec.sid);
		h_raw(h, "</section>");
		return;
	}
	if (sec.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, sec.error);
		h_raw(h, "</div>");
	}
	if (sec.state == NULL) {
		if (sec.error[0] == '\0')
			h_raw(h, "<div class=\"loader\"></div>");
		h_raw(h, "</section>");
		return;
	}
	switch (sec.tab) {
	case SEC_URL:
		view_url(h, false);
		break;
	case SEC_MALWARE:
		view_malware(h);
		break;
	case SEC_SIGS:
		view_sigs(h);
		break;
	case SEC_IDS:
		view_ids(h);
		break;
	case SEC_SNORT:
		break;
	}
	h_raw(h, "</section>");
}

/* ---- Saving ------------------------------------------------------------ */

static void
save_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	sec.busy = false;
	if (status == 200 && jbool(o, "ok")) {
		toast(false, "Applied");
		sec.edit = -1;
	} else
		toast(true, "%s", err != NULL ? err : jstr(o, "error") != NULL ?
		    jstr(o, "error") : "not applied");
	sec_load();
	render();
}

/* The kind's whole list sent: the forms as they are now. */
static void
save(bool ids, ucl_object_t *list)
{
	ucl_object_t	*body;
	char		 url[96], *json;

	body = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(body, ucl_object_fromstring(ids ? "ids" :
	    "proxy"), "what", 0, false);
	ucl_object_insert_key(body, list, "instances", 0, false);
	json = (char *)ucl_object_emit(body, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(body);
	snprintf(url, sizeof(url), "/api/servers/%s/security", sec.sid);
	sec.busy = true;
	api("POST", url, json, save_cb, NULL);
	free(json);
}

/* A copy of the kind's forms, but the one named skip. */
static ucl_object_t *
specs_but(bool ids, const char *skip)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*out;

	out = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(specs(ids), &it, true)) != NULL)
		if (skip == NULL || jstr(e, "name") == NULL || strcmp(jstr(e,
		    "name"), skip) != 0)
			ucl_array_append(out, ucl_object_copy(e));
	return (out);
}

/* A field's words, split at commas, spaces and lines, as a list. */
static ucl_object_t *
words(const char *s)
{
	ucl_object_t	*arr;
	char		*copy, *p, *w;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (s == NULL)
		return (arr);
	if ((copy = strdup(s)) == NULL)
		abort();
	p = copy;
	while ((w = strsep(&p, ", \t\r\n")) != NULL)
		if (w[0] != '\0')
			ucl_array_append(arr, ucl_object_fromstring(w));
	free(copy);
	return (arr);
}

static void
put_num(ucl_object_t *o, const char *k, const char *v)
{

	if (v != NULL && v[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromint(strtoll(v, NULL,
		    10)), k, 0, true);
}

/* The text typed, and the prefixes of a console list after it. */
char *
with_list(const char *text, const char *list)
{
	char	*more, *out;

	more = list != NULL && list[0] != '\0' ? pfxlist_joined(list, ", ") :
	    NULL;
	if (asprintf(&out, "%s%s%s", text != NULL ? text : "", more != NULL &&
	    text != NULL && text[0] != '\0' ? ", " : "", more != NULL ? more :
	    "") == -1)
		abort();
	free(more);
	return (out);
}

bool
secpage_form(const char *form, const ucl_object_t *f)
{
	ucl_object_t	*list, *o;
	bool		 ids;

	if (strncmp(form, "sn-", 3) == 0)
		return (snort_form(form, f));
	if (strcmp(form, "sec-proxy") != 0 && strcmp(form, "sec-ids") != 0)
		return (false);
	if (strcmp(form, "sec-proxy") == 0 && (jstr(f, "allow") == NULL || jstr(
	    f, "allow")[0] == '\0') && (jstr(f, "allow_pfx") == NULL || jstr(f,
	    "allow_pfx")[0] == '\0')) {
		toast(true, "Who may use it: networks, or a prefix list");
		return (true);
	}
	ids = strcmp(form, "sec-ids") == 0;
	list = specs_but(ids, jstr(f, "orig") != NULL && jstr(f,
	    "orig")[0] != '\0' ? jstr(f, "orig") : NULL);
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(jstr(f, "name") !=
	    NULL ? jstr(f, "name") : ""), "name", 0, false);
	if (!ids) {
		ucl_object_insert_key(o, words(jstr(f, "listen")), "listen", 0,
		    false);
		put_num(o, "port", jstr(f, "port"));
		{
			char	*all = with_list(jstr(f, "allow"), jstr(f,
			    "allow_pfx"));

			ucl_object_insert_key(o, words(all), "allow", 0, false);
			free(all);
		}
		ucl_object_insert_key(o, ucl_object_fromstring(jstr(f, "mode") !=
		    NULL ? jstr(f, "mode") : "sni"), "mode", 0, false);
		ucl_object_insert_key(o, words(jstr(f, "deny")), "deny", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_frombool(jbool(f,
		    "malware")), "malware", 0, false);
		put_num(o, "fib", jstr(f, "fib"));
	} else {
		ucl_object_insert_key(o, words(jstr(f, "interfaces")),
		    "interfaces", 0, false);
		{
			char	*hm = with_list(jstr(f, "home"), jstr(f, "home_pfx"));

			ucl_object_insert_key(o, words(hm), "home", 0, false);
			free(hm);
		}
		ucl_object_insert_key(o, ucl_object_frombool(jbool(f,
		    "ruleset")), "ruleset", 0, false);
		if (jstr(f, "rules") != NULL && jstr(f, "rules")[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromstring(jstr(f,
			    "rules")), "rules", 0, false);
		put_num(o, "divert", jstr(f, "divert"));
	}
	ucl_array_append(list, o);
	save(ids, list);
	return (true);
}

/* "#/security[/tab[/host]]" */
void
secpage_loc(char *buf, size_t len)
{

	snprintf(buf, len, "#/security/%s%s%s", tabs[sec.tab], sec.sid[0] !=
	    '\0' ? "/" : "", sec.sid);
}

void
secpage_open(const char *rest)
{
	char	tab[32];
	size_t	i;

	snprintf(tab, sizeof(tab), "%.*s", (int)strcspn(rest, "/"), rest);
	for (i = 0; i < nitems(tabs); i++)
		if (strcmp(tab, tabs[i]) == 0)
			sec.tab = (enum sectab)i;
	rest += strcspn(rest, "/");
	if (*rest == '/' && strcmp(rest + 1, sec.sid) != 0) {
		snprintf(sec.sid, sizeof(sec.sid), "%.15s", rest + 1);
		if (sec.state != NULL)
			ucl_object_unref(sec.state);
		sec.state = NULL;
		sec_load();
	}
}

bool
secpage_action(const char *act, const char *arg, const char *value)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	size_t			 i;
	int			 n;
	bool			 ids;

	if (strcmp(act, "select-security") == 0) {
		app.node = NODE_SECURITY;
		app.jail[0] = '\0';
		app.rail_open = false;
		/* One host alone: it, without asking. */
		if (sec.sid[0] == '\0' && app.nservers == 1)
			snprintf(sec.sid, sizeof(sec.sid), "%s",
			    app.servers[0].id);
		sec_load();
		return (true);
	}
	if (strncmp(act, "sn-", 3) == 0 || strcmp(act, "input:sn-text") == 0)
		return (snort_action(act, arg, value));
	if (strncmp(act, "sec-", 4) != 0 && strcmp(act, "input:sec-host") != 0)
		return (false);
	ids = sec.tab == SEC_IDS;
	if (strcmp(act, "sec-tab") == 0) {
		for (i = 0; i < nitems(tabs); i++)
			if (strcmp(arg, tabs[i]) == 0)
				sec.tab = (enum sectab)i;
		sec.edit = -1;
		app.filter[0] = '\0';
		return (true);
	}
	if (strcmp(act, "input:sec-host") == 0) {
		if (value == NULL || strcmp(value, sec.sid) == 0)
			return (true);
		snprintf(sec.sid, sizeof(sec.sid), "%s", value);
		if (sec.state != NULL)
			ucl_object_unref(sec.state);
		sec.state = NULL;
		sec.edit = -1;
		sec_load();
		return (true);
	}
	if (strcmp(act, "sec-new") == 0) {
		sec.edit = (int)ucl_array_size(specs(ids));
		return (true);
	}
	if (strcmp(act, "sec-cancel") == 0) {
		sec.edit = -1;
		return (true);
	}
	if (strcmp(act, "sec-edit") == 0) {
		n = 0;
		it = NULL;
		while ((e = ucl_object_iterate(specs(ids), &it, true)) != NULL) {
			if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"),
			    arg) == 0)
				sec.edit = n;
			n++;
		}
		return (true);
	}
	if (strcmp(act, "sec-remove") == 0) {
		char	body[256];

		snprintf(body, sizeof(body), "%s is stopped on the host and its "
		    "files taken away.", arg);
		confirm("Remove it?", body, "Remove", true, NULL,
		    "sec-remove-yes", arg, value != NULL ? value : "proxy");
		return (true);
	}
	if (strcmp(act, "sec-remove-yes") == 0) {
		ids = value != NULL && strcmp(value, "ids") == 0;
		save(ids, specs_but(ids, arg));
		return (true);
	}
	if (strcmp(act, "sec-unscan") == 0) {
		ucl_object_t	*list;

		list = specs_but(false, NULL);
		it = NULL;
		while ((e = ucl_object_iterate(list, &it, true)) != NULL)
			if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"),
			    arg) == 0)
				ucl_object_replace_key((ucl_object_t *)(uintptr_t)
				    e, ucl_object_frombool(false), "malware", 0,
				    false);
		save(false, list);
		return (true);
	}
	if (strcmp(act, "sec-install") == 0) {
		struct server	*s;
		char		*json, *it2, *w, *copy, *q, *t;
		bool		 first;

		/* Only the packages the tabs name: nothing else is sent. */
		if ((s = sec_server()) == NULL || (strcmp(arg, "squid") != 0 &&
		    strcmp(arg, "clamav") != 0 && strcmp(arg, "suricata") != 0 &&
		    strcmp(arg, "c-icap c-icap-modules clamav") != 0))
			return (true);
		if ((json = strdup("{\"kind\":\"pkg-install\",\"packages\":["))
		    == NULL || (copy = strdup(arg)) == NULL)
			abort();
		first = true;
		for (it2 = copy; (w = strsep(&it2, " ")) != NULL; ) {
			q = json_quote(w);
			if (asprintf(&t, "%s%s%s", json, first ? "" : ",", q) ==
			    -1)
				abort();
			free(json);
			free(q);
			json = t;
			first = false;
		}
		free(copy);
		if (asprintf(&t, "%s]}", json) == -1)
			abort();
		free(json);
		{
			char	title[96];

			snprintf(title, sizeof(title), "pkg install %s", arg);
			job_send_host(s, t, title, JOB_SECURITY, "");
		}
		return (true);
	}
	if (strcmp(act, "sec-freshclam") == 0) {
		struct server	*s;
		char		*json, title[64];

		for (i = 0; i < (size_t)app.nservers; i++)
			if (strcmp(app.servers[i].id, sec.sid) == 0)
				break;
		if (i == (size_t)app.nservers)
			return (true);
		s = &app.servers[i];
		/* Enabled first, so that rc starts it, then (re)started:
		 * two jobs the host runs in order; the page looks again
		 * when they end. */
		{
			struct queued	q[2];

			memset(q, 0, sizeof(q));
			if (asprintf(&q[0].json, "{\"kind\":\"service-action\","
			    "\"service\":\"clamav_freshclam\",\"action\":\"enable\"}")
			    == -1 || asprintf(&q[1].json, "{\"kind\":\"service-action"
			    "\",\"service\":\"clamav_freshclam\",\"action\":\"restart"
			    "\"}") == -1)
				abort();
			snprintf(q[0].title, sizeof(q[0].title), "clamav_freshclam "
			    "enabled at boot");
			snprintf(q[1].title, sizeof(q[1].title), "service "
			    "clamav_freshclam restart");
			for (i = 0; i < 2; i++) {
				snprintf(q[i].sid, sizeof(q[i].sid), "%s", s->id);
				snprintf(q[i].host, sizeof(q[i].host), "%s", s->name);
				q[i].what = JOB_SECURITY;
			}
			job_send_many(s, q, 2, JOB_SECURITY);
		}
		(void)json;
		(void)title;
		return (true);
	}
	return (false);
}

/* After a plugin was installed: the host read again. */
void
secpage_refresh(void)
{

	sec_load();
}

/* Each tick: the page's host read again, every 10 s while it is shown
 * and no form is open. */
void
secpage_tick(double now)
{
	static double	last;

	if (app.node == NODE_SECURITY && sec.tab == SEC_SNORT) {
		snort_tick(now);
		return;
	}
	if (app.node != NODE_SECURITY || !app.visible || sec.loading ||
	    sec.busy || sec.edit >= 0 || now - last < 10000)
		return;
	last = now;
	sec_load();
}
