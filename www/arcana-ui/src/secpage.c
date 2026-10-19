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
 * taking what an ipfw divert rule hands it.  A host at a time: its
 * sdwan read tells what runs and the forms it was given; a save sends
 * the kind's whole list (POST /api/servers/<id>/security).
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

enum sectab { SEC_URL, SEC_AV, SEC_IDS };

static void	ids_settings_form(struct html *, const ucl_object_t *);

static struct {
	enum sectab	 tab;
	char		 sid[16];
	ucl_object_t	*state;		/* the host's sdwan read */
	bool		 loading;
	char		 error[256];
	int		 edit;		/* the form open: an index, n for a new
					 * one, -1 none */
	bool		 busy;
	bool		 rules;		/* IDS/IPS: the ruleset's rules shown */
	bool		 sources;	/* IDS/IPS: the rule sources shown */
} sec = { .edit = -1 };

static const char *const tabs[] = { "url", "antivirus", "ids" };

static void
sec_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid = arg;

	/* Read again, a save is done with. */
	sec.busy = false;
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

/* Start, for one that is not running or not applied: the list applied
 * again, which starts what is not running and leaves the rest be. */
static void
start_button(struct html *h, const ucl_object_t *l, bool ids)
{

	if (l != NULL && jbool(l, "running"))
		return;
	h_fmt(h, "<button class=\"ghost small\" data-act=\"sec-start\" "
	    "data-value=\"%s\" title=\"Apply the list again: the host starts "
	    "what is not running, and says why when it cannot\">Start</button>",
	    ids ? "ids" : "proxy");
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
	    "c-icap with ClamAV, on the loopback (the Antivirus tab)</small>"
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
		start_button(h, l, false);
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
	    "ClamAV's signatures are freshclam's, below.</p>");
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

/* The mirrors a freshclam.conf Arcana writes names: ClamAV's own, and
 * Microsoft's, which carries the same databases. */
static const char *const default_mirrors[] = { "database.clamav.net",
    "https://packages.microsoft.com/clam" };

/* A clamav job of mirrors, n of them, as the API takes it. */
static char *
mirrors_job(const char *const *m, size_t n)
{
	char	*json, *q, *t;
	size_t	 i;

	if ((json = strdup("{\"kind\":\"clamav\",\"verb\":\"mirrors\","
	    "\"args\":[")) == NULL)
		abort();
	for (i = 0; i < n; i++) {
		char	*w;

		if (asprintf(&w, "mirror=%s", m[i]) == -1)
			abort();
		q = json_quote(w);
		free(w);
		if (asprintf(&t, "%s%s%s", json, i > 0 ? "," : "", q) == -1)
			abort();
		free(json);
		free(q);
		json = t;
	}
	if (asprintf(&t, "%s]}", json) == -1)
		abort();
	free(json);
	return (t);
}

/* Jobs one after the other on the page's host, and the page read again
 * when they end. */
static void
sec_jobs(char **json, const char **title, int n)
{
	struct server	*s;
	struct queued	 q[4];
	int		 i;

	if ((s = sec_server()) == NULL || n > 4) {
		for (i = 0; i < n; i++)
			free(json[i]);
		return;
	}
	memset(q, 0, sizeof(q));
	for (i = 0; i < n; i++) {
		q[i].json = json[i];
		snprintf(q[i].title, sizeof(q[i].title), "%s", title[i]);
		snprintf(q[i].sid, sizeof(q[i].sid), "%s", s->id);
		snprintf(q[i].host, sizeof(q[i].host), "%s", s->name);
		q[i].what = JOB_SECURITY;
	}
	job_send_many(s, q, n, JOB_SECURITY);
}

/*
 * freshclam's mirrors, as freshclam.conf says them, a line each, with
 * Microsoft's offered after them when it is not there.
 */
static void
mirrors_form(struct html *h, const ucl_object_t *cl)
{
	const ucl_object_t	*m;
	ucl_object_iter_t	 it;
	bool			 ms;

	h_raw(h, "<form data-form=\"sec-mirrors\" class=\"secform\"><label>"
	    "Mirrors <small class=\"dim\">freshclam.conf's DatabaseMirror "
	    "lines, a line each, tried in order: a host name, or an http or "
	    "https URL</small><textarea name=\"mirrors\" rows=\"4\" class=\""
	    "mono\" spellcheck=\"false\" autocomplete=\"off\">");
	ms = false;
	it = NULL;
	while ((m = ucl_object_iterate(jget(cl, "mirrors"), &it, true)) !=
	    NULL) {
		h_txt(h, ucl_object_tostring_forced(m));
		h_raw(h, "\n");
		if (strcmp(ucl_object_tostring_forced(m), default_mirrors[1]) == 0)
			ms = true;
	}
	if (ucl_array_size(jget(cl, "mirrors")) == 0) {
		h_txt(h, default_mirrors[0]);
		h_raw(h, "\n");
	}
	if (!ms) {
		h_txt(h, default_mirrors[1]);
		h_raw(h, "\n");
	}
	h_fmt(h, "</textarea></label><div class=\"actions\"><button class=\""
	    "primary\">Save the mirrors%s</button></div></form>", jbool(cl,
	    "freshclam") ? " and restart freshclam" : "");
}

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
		    "</code> line, which freshclam refuses to run with. Saving "
		    "the mirrors below writes it, from the port's sample, and "
		    "Start freshclam does too.</div>");
	mirrors_form(h, cl);
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
	h_raw(h, "><small class=\"help\">HOME_NET of the rules; any for every address; empty: the "
	    "private ranges</small></label>");
	pfxlist_select(h, "And the networks of a list", "home_pfx", "A prefix "
	    "list of the console's, added to HOME_NET when kept.");
	h_raw(h, "<label class=\"check\"><input type=\"checkbox\" name=\""
	    "ruleset\"");
	if (f == NULL || jbool(f, "ruleset"))
		h_raw(h, " checked");
	h_raw(h, "> The ruleset suricata-update keeps <small class=\"help\">"
	    "Emerging Threats Open, fetched by Fetch the ruleset above; left "
	    "out until it is</small></label><label>Rules of its own <textarea "
	    "name=\"rules\" rows=\"4\" spellcheck=\"false\" placeholder=\""
	    "alert tcp any any -> $HOME_NET 23 (msg:&quot;telnet&quot;; "
	    "sid:1000001;)\">");
	h_txt(h, jstr(f, "rules"));
	h_raw(h, "</textarea><small class=\"help\">a rule a line, as "
	    "Suricata writes them</small></label>");
	ids_settings_form(h, f);
	h_raw(h, "<details class=\"wfmore\"");
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

/* Suricata's settings, as ids_settings in the console writes them. */
static const char *const evtypes[] = { "anomaly", "http", "dns", "tls",
    "ssh", "flow", "netflow", "fileinfo", "drop", "smtp", "quic", "http2",
    "dhcp", "smb" };

static void
set_select(struct html *h, const char *label, const char *name,
    const char *cur, const char *const *opts, size_t n, const char *help)
{
	size_t	i;

	h_fmt(h, "<label>%s <select name=\"%s\"><option value=\"\">"
	    "Suricata's default</option>", label, name);
	for (i = 0; i < n; i++) {
		h_raw(h, "<option");
		if (cur != NULL && strcmp(cur, opts[i]) == 0)
			h_raw(h, " selected");
		h_fmt(h, ">%s</option>", opts[i]);
	}
	h_raw(h, "</select>");
	if (help != NULL)
		h_fmt(h, "<small class=\"help\">%s</small>", help);
	h_raw(h, "</label>");
}

static void
set_input(struct html *h, const char *label, const char *name,
    const char *cur, const char *ph, const char *help)
{

	h_fmt(h, "<label>%s <input name=\"%s\" spellcheck=\"false\" "
	    "autocomplete=\"off\"", label, name);
	h_attr(h, "value", cur != NULL ? cur : "");
	h_attr(h, "placeholder", ph);
	h_raw(h, ">");
	if (help != NULL)
		h_fmt(h, "<small class=\"help\">%s</small>", help);
	h_raw(h, "</label>");
}

static bool
has_word(const ucl_object_t *arr, const char *w)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL)
		if (ucl_object_type(e) == UCL_STRING && strcmp(
		    ucl_object_tostring(e), w) == 0)
			return (true);
	return (false);
}

static void
ids_settings_form(struct html *h, const ucl_object_t *f)
{
	static const char *const runmodes[] = { "autofp", "workers",
	    "single" };
	static const char *const mpms[] = { "ac", "ac-ks", "hs" };
	static const char *const profiles[] = { "low", "medium", "high" };
	static const char *const inlines[] = { "auto", "yes", "no" };
	static const char *const policies[] = { "auto", "drop-packet",
	    "drop-flow", "pass-packet", "pass-flow", "bypass", "reject",
	    "ignore" };
	char	num[24];
	size_t	i;

	h_raw(h, "<details class=\"wfmore\"><summary>Logging</summary>"
	    "<p class=\"help\">What eve.json has besides alerts, each a "
	    "record of its own; the statistics feed the graphs.</p><div "
	    "class=\"checks\">");
	for (i = 0; i < nitems(evtypes); i++) {
		h_fmt(h, "<label class=\"check\"><input type=\"checkbox\" "
		    "name=\"eve_%s\"%s> %s</label>", evtypes[i], has_word(jget(f,
		    "eve"), evtypes[i]) ? " checked" : "", evtypes[i]);
	}
	h_raw(h, "</div><label class=\"check\"><input type=\"checkbox\" "
	    "name=\"payload\"");
	if (jbool(f, "payload"))
		h_raw(h, " checked");
	h_raw(h, "> An alert's packet and payload <small class=\"help\">"
	    "larger records; what matched, readable</small></label>");
	snprintf(num, sizeof(num), "%lld", (long long)(jget(f,
	    "stats_interval") != NULL ? jint(f, "stats_interval", 10) : 10));
	h_raw(h, "<label>Statistics every <input name=\"stats_interval\" "
	    "type=\"number\" min=\"0\" max=\"3600\"");
	h_attr(h, "value", num);
	h_raw(h, "><small class=\"help\">seconds; 0 none</small></label>");
	h_raw(h, "</details><details class=\"wfmore\"><summary>Capture"
	    "</summary><div class=\"rowform\"><label>By <select name=\""
	    "capture\"><option value=\"pcap\">pcap(3): it watches</option>"
	    "<option value=\"netmap\"");
	if (jstr(f, "capture") != NULL && strcmp(jstr(f, "capture"),
	    "netmap") == 0)
		h_raw(h, " selected");
	h_raw(h, ">netmap(4): it takes the NIC's rings</option></select>"
	    "<small class=\"help\">netmap is faster, a thread a ring the "
	    "NIC's RSS fills, and prevents at L2</small></label>");
	h_raw(h, "<label>L2 pairs <input name=\"pairs\" spellcheck=\"false\" "
	    "placeholder=\"em0:em1, em2:em2^\"");
	joined_attr(h, "value", jget(f, "pairs"), ", ");
	h_raw(h, "><small class=\"help\">netmap: what one gets Suricata "
	    "passes to the other, dropping what its rules say (a bump in "
	    "the wire); em0^ is em0's host stack</small></label></div>"
	    "<label class=\"check\"><input type=\"checkbox\" name=\""
	    "offload_off\"");
	if (jbool(f, "offload_off"))
		h_raw(h, " checked");
	h_raw(h, "> Its interfaces' offloading off <small class=\"help\">"
	    "checksums, TSO and LRO, by ifconfig(8) as it starts: Suricata "
	    "sees packets as they are on the wire</small></label></details>"
	    "<details class=\"wfmore\"><summary>Performance</summary>");
	{
		const ucl_object_t	*hc = jget(sec.state, "ids_host");
		static const char *const presets[] = { "small", "medium",
		    "large" };

		if (hc != NULL && jint(hc, "ncpu", 0) > 0)
			h_fmt(h, "<p class=\"help\">This host has %lld CPUs (0 "
			    "to %lld), in %lld memory domain%s.</p>",
			    (long long)jint(hc, "ncpu", 0), (long long)jint(hc,
			    "ncpu", 0) - 1, (long long)jint(hc, "ndomains", 1),
			    jint(hc, "ndomains", 1) == 1 ? "" : "s");
		h_raw(h, "<div class=\"rowform\">");
		set_select(h, "Preset", "preset", jstr(f, "preset"), presets,
		    nitems(presets), "for a host of its size: what the fields "
		    "below do not say");
		h_raw(h, "</div>");
	}
	h_raw(h, "<div class=\"rowform\">");
	set_select(h, "Runmode", "runmode", jstr(f, "runmode"), runmodes,
	    nitems(runmodes), "workers: a thread does all of a packet");
	set_select(h, "Pattern matcher", "mpm", jstr(f, "mpm"), mpms,
	    nitems(mpms), "hs: Hyperscan, where it is built in");
	set_select(h, "Detect profile", "profile", jstr(f, "profile"),
	    profiles, nitems(profiles), "memory for speed");
	h_raw(h, "</div><div class=\"rowform\">");
	set_input(h, "Management CPUs", "management_cpus", jstr(f,
	    "management_cpus"), "0", NULL);
	set_input(h, "Worker CPUs", "worker_cpus", jstr(f, "worker_cpus"),
	    "1-3", "its threads on these alone (cpu-affinity)");
	snprintf(num, sizeof(num), "%lld", (long long)jint(f, "max_pending",
	    0));
	h_raw(h, "<label>Pending packets <input name=\"max_pending\" "
	    "type=\"number\" min=\"0\" max=\"65535\" placeholder=\"1024\"");
	if (jint(f, "max_pending", 0) > 0)
		h_attr(h, "value", num);
	h_raw(h, "></label></div></details><details class=\"wfmore\">"
	    "<summary>Memory</summary><div class=\"rowform\">");
	set_input(h, "Flows", "flow_memcap", jstr(f, "flow_memcap"), "128mb",
	    NULL);
	set_input(h, "Stream", "stream_memcap", jstr(f, "stream_memcap"),
	    "64mb", NULL);
	set_input(h, "Reassembly", "reassembly_memcap", jstr(f,
	    "reassembly_memcap"), "256mb", NULL);
	h_raw(h, "</div><div class=\"rowform\">");
	set_input(h, "Fragments", "defrag_memcap", jstr(f, "defrag_memcap"),
	    "32mb", NULL);
	set_input(h, "Hosts", "host_memcap", jstr(f, "host_memcap"), "32mb",
	    NULL);
	set_input(h, "HTTP", "http_memcap", jstr(f, "http_memcap"), "64mb",
	    NULL);
	h_raw(h, "</div></details><details class=\"wfmore\"><summary>Stream "
	    "and HTTP</summary><div class=\"rowform\">");
	set_select(h, "Inline stream", "stream_inline", jstr(f,
	    "stream_inline"), inlines, nitems(inlines), "where it prevents: "
	    "the stream inspected before it passes");
	set_input(h, "Reassembly depth", "reassembly_depth", jstr(f,
	    "reassembly_depth"), "1mb", "of each stream, inspected");
	h_raw(h, "</div><div class=\"rowform\">");
	set_input(h, "HTTP request body", "http_request_body", jstr(f,
	    "http_request_body"), "100kb", "inspected of each");
	set_input(h, "HTTP response body", "http_response_body", jstr(f,
	    "http_response_body"), "100kb", NULL);
	h_raw(h, "</div><label class=\"check\"><input type=\"checkbox\" "
	    "name=\"midstream\"");
	if (jbool(f, "midstream"))
		h_raw(h, " checked");
	h_raw(h, "> Streams picked up midway <small class=\"help\">those "
	    "begun before it started</small></label>");
	set_select(h, "Past a limit", "exception_policy", jstr(f,
	    "exception_policy"), policies, nitems(policies), "what is done "
	    "with traffic when a memcap or the like is reached");
	h_raw(h, "</details><details class=\"wfmore\"><summary>Its own YAML"
	    "</summary><label>Besides the above <textarea name=\"yaml\" "
	    "rows=\"5\" spellcheck=\"false\" placeholder=\"vlan:\n"
	    "  use-for-tracking: false\">");
	h_txt(h, jstr(f, "yaml"));
	h_raw(h, "</textarea><small class=\"help\">Suricata's YAML, keys the "
	    "form does not set; checked by suricata -T with the rest</small>"
	    "</label></details>");
}

static const struct tcol icols[] = {
	{ "Name", "name", false }, { "Interfaces", NULL, false },
	{ "Does", NULL, false }, { "Alerts", NULL, true },
	{ "State", NULL, false },
};

/* The ruleset suricata-update keeps on the host: when it was fetched,
 * or that it was not. */
static void
ruleset_line(struct html *h)
{
	const ucl_object_t	*rs = jget(sec.state, "ids_ruleset");
	char			 age[32], size[32];

	if (rs == NULL) {
		h_raw(h, "<p class=\"dim\">The ruleset is not fetched on this "
		    "host yet: an instance that adds it runs on its own rules "
		    "until it is.</p>");
		return;
	}
	fmt_age(age, sizeof(age), (double)jint(rs, "at", 0) * 1000);
	fmt_bytes(size, sizeof(size), jint(rs, "size", 0));
	h_raw(h, "<p class=\"dim\">The ruleset, ");
	h_txt(h, jstr(rs, "path"));
	h_fmt(h, ", fetched %s (%s).</p>", age, size);
}

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
	h_raw(h, "><button class=\"ghost\" data-act=\"sec-ruleset\" title=\""
	    "suricata-update fetches Emerging Threats Open; each instance that "
	    "adds the ruleset takes it\">");
	h_raw(h, jget(sec.state, "ids_ruleset") != NULL ? "Fetch the ruleset "
	    "again" : "Fetch the ruleset");
	h_raw(h, "</button><button class=\"primary\" data-act=\"sec-new\">New "
	    "intrusion detection</button></div>");
	ruleset_line(h);
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
	h_fmt(h, "<table class=\"net secids%s\">", sec.busy ? " applying" :
	    "");
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
			    "%lld</small>", (long long)jint(f, "divert", 0));
		else if (ucl_array_size(jget(f, "pairs")) > 0) {
			h_raw(h, "</td><td>prevents <small class=\"dim\">at L2, ");
			joined(h, jget(f, "pairs"), ", ");
			h_raw(h, "</small>");
		} else
			h_raw(h, "</td><td>detects");
		if (jstr(f, "capture") != NULL && strcmp(jstr(f, "capture"),
		    "netmap") == 0)
			h_raw(h, " <small class=\"chip\">netmap</small>");
		/* Offloading its interfaces still have on. */
		if (!jbool(f, "offload_off") && l != NULL) {
			const ucl_object_t	*oe;
			ucl_object_iter_t	 oit;
			bool			 any = false;

			oit = NULL;
			while ((oe = ucl_object_iterate(jget(l, "offload"), &oit,
			    true)) != NULL)
				if (ucl_array_size(oe) > 0)
					any = true;
			if (any) {
				h_raw(h, " <span class=\"chip warn\" title=\""
				    "Offloading on: ");
				oit = NULL;
				while ((oe = ucl_object_iterate(jget(l,
				    "offload"), &oit, true)) != NULL) {
					h_txt(h, ucl_object_key(oe));
					h_raw(h, " ");
					joined(h, oe, ",");
					h_raw(h, "; ");
				}
				h_raw(h, "Suricata may see packets merged or "
				    "with checksums not yet made: Capture, "
				    "offloading off\">offload</span>");
			}
		}
		h_raw(h, "</td>");
		h_fmt(h, "<td>%lld</td><td>", (long long)jint(l, "alerts_seen",
		    0));
		if (jbool(f, "stopped"))
			h_raw(h, "<span class=\"chip st-down\" title=\"Stopped "
			    "here: kept, not run until it is started\">stopped"
			    "</span>");
		else
			chip_run(h, l, "running");
		h_raw(h, "</td><td class=\"acts\">");
		/* Stopped by the admin, or not running: Start; else Stop.
		 * Either keeps its form. */
		if (jbool(f, "stopped") || l == NULL || !jbool(l, "running")) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "sec-ids-run\" data-value=\"start\" title=\"Started "
			    "on the host, its configuration as it is\"");
			h_attr(h, "data-arg", jstr(f, "name"));
			h_raw(h, ">Start</button>");
		} else {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "sec-ids-stop\" title=\"Stopped on the host, its "
			    "configuration kept for Start\"");
			h_attr(h, "data-arg", jstr(f, "name"));
			h_raw(h, ">Stop</button>");
		}
		h_raw(h, "<button class=\"ghost small\" data-act=\"ist-open\" "
		    "title=\"Packets, drops, alerts, memory and flows over "
		    "time\"");
		h_attr(h, "data-arg", jstr(f, "name"));
		h_raw(h, ">Statistics</button>");
		h_raw(h, "<button class=\"ghost small\" data-act=\"own-open\" "
		    "title=\"Its rules besides the ruleset's\"");
		h_attr(h, "data-arg", jstr(f, "name"));
		h_fmt(h, ">Own rules (%d)</button>", idsown_count(jstr(f,
		    "rules")));
		h_raw(h, "<button class=\"ghost small\" data-act=\"sec-edit\"");
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
			/* As the agent tells it: time, src, dst, sid. */
			h_raw(h, "<li><span class=\"dim mono\">");
			h_txt(h, jstr(a, "time"));
			h_raw(h, "</span> <b>");
			h_txt(h, jstr(a, "signature"));
			h_fmt(h, "</b> <small class=\"dim\">sid %lld",
			    (long long)jint(a, "sid", 0));
			if (jstr(a, "action") != NULL && strcmp(jstr(a,
			    "action"), "blocked") == 0)
				h_raw(h, ", dropped");
			h_raw(h, "</small> <span class=\"mono\">");
			h_txt(h, jstr(a, "src"));
			if (jint(a, "sport", 0) > 0)
				h_fmt(h, ":%lld", (long long)jint(a, "sport", 0));
			h_raw(h, " → ");
			h_txt(h, jstr(a, "dst"));
			if (jint(a, "dport", 0) > 0)
				h_fmt(h, ":%lld", (long long)jint(a, "dport", 0));
			h_raw(h, "</span>");
			if (jint(a, "sid", 0) > 0 && jstr(a, "src") != NULL) {
				char	arg[96];

				snprintf(arg, sizeof(arg), "%lld|%s",
				    (long long)jint(a, "sid", 0), jstr(a, "src"));
				h_raw(h, " <button class=\"ghost small\" "
				    "data-act=\"own-suppress\" title=\"Not told "
				    "again from this address (suppress, track "
				    "by_src)\"");
				h_attr(h, "data-arg", arg);
				h_attr(h, "data-value", jstr(f, "name"));
				h_raw(h, ">Suppress</button>");
			}
			h_raw(h, "</li>");
		}
		h_raw(h, "</ul></td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
}

void
view_secpage(struct html *h)
{
	static const char *const names[] = { "URL filter", "Antivirus",
	    "IDS/IPS" };
	static const char *const titles[] = {
	    "Squid: what the clients ask for, by name",
	    ("ClamAV: what a URL filter fetches, scanned by c-icap; its "
	    "signatures, by freshclam"),
	    "Suricata: intrusion detection, and prevention" };
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
	case SEC_AV:
		/* ClamAV: what it scans, then what it knows. */
		view_malware(h);
		h_raw(h, "<h3 class=\"secsub\">Signatures</h3>");
		view_sigs(h);
		break;
	case SEC_IDS:
		/* Its instances, or the ruleset's rules. */
		h_fmt(h, "<nav class=\"tabs sub\"><button class=\"tab%s\" "
		    "data-act=\"sec-idsview\" data-arg=\"instances\">Instances"
		    "</button><button class=\"tab%s\" data-act=\"sec-idsview\" "
		    "data-arg=\"rules\" title=\"The ruleset suricata-update "
		    "keeps, each rule on, off or a drop\">Rules</button><button "
		    "class=\"tab%s\" data-act=\"sec-idsview\" data-arg=\""
		    "sources\" title=\"Where suricata-update fetches the "
		    "ruleset from\">Sources</button></nav>", sec.rules ||
		    sec.sources ? "" : " on", sec.rules ? " on" : "",
		    sec.sources ? " on" : "");
		if (sec.sources)
			view_susources(h, sec.sid);
		else if (sec.rules)
			view_surules(h, sec.sid);
		else if (idsown_active())
			view_idsown(h);
		else if (idsstats_active())
			view_idsstats(h);
		else
			view_ids(h);
		break;
	}
	h_raw(h, "</section>");
}

/* ---- Saving ------------------------------------------------------------ */

static void
save_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	/* Applied, busy until the host is read again (sec_cb ends it);
	 * refused, nothing changed there and nothing to wait for. */
	if (status == 200 && jbool(o, "ok")) {
		toast(false, "Applied");
		sec.edit = -1;
	} else {
		sec.busy = false;
		toast(true, "%s", err != NULL ? err : jstr(o, "error") != NULL ?
		    jstr(o, "error") : "not applied");
	}
	sec_load();
	render();
}

/* The kind's whole list sent: the forms as they are now. */
static void
save(bool ids, ucl_object_t *list)
{
	ucl_object_t	*body;
	char		 url[96], *json;

	/* One change at a time, each on the host's list as it was read
	 * after the last: what is made meanwhile would undo that one. */
	if (sec.busy) {
		ucl_object_unref(list);
		toast(true, "The last change is being applied: again in a "
		    "moment");
		return;
	}
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

/* For idsown.c: an intrusion detection's form, by name. */
const ucl_object_t *
sec_ids_spec(const char *name)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(specs(true), &it, true)) != NULL)
		if (jstr(e, "name") != NULL && name != NULL && strcmp(jstr(e,
		    "name"), name) == 0)
			return (e);
	return (NULL);
}

/* One key of a form set to text, and the whole list applied again. */
void
sec_ids_set(const char *name, const char *key, const char *text)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*list;

	list = specs_but(true, NULL);
	it = NULL;
	while ((e = ucl_object_iterate(list, &it, true)) != NULL)
		if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"), name) ==
		    0)
			ucl_object_replace_key((ucl_object_t *)(uintptr_t)e,
			    ucl_object_fromstring(text), key, 0, true);
	save(true, list);
}

/* For idsstats.c: what runs of an intrusion detection, by name. */
const ucl_object_t *
sec_ids_live(const char *name)
{

	return (live(true, name));
}

bool
sec_ids_busy(void)
{

	return (sec.busy);
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

	if (surules_form(form, f) || idsown_form(form, f))
		return (true);
	{
		char		*json[1], title[96];
		const char	*t[1];

		if (susources_form(form, f, &json[0], title, sizeof(title))) {
			if (json[0] != NULL) {
				t[0] = title;
				sec_jobs(json, t, 1);
			}
			return (true);
		}
	}
	if (strcmp(form, "sec-mirrors") == 0) {
		const ucl_object_t	*cl = jget(sec.state, "clamav");
		char			*copy, *it, *line, *json[2];
		const char		*m[16], *title[2];
		size_t			 n;
		int			 nj;

		copy = strdup(jstr(f, "mirrors") != NULL ? jstr(f, "mirrors") :
		    "");
		if (copy == NULL)
			abort();
		n = 0;
		for (it = copy; (line = strsep(&it, "\n")) != NULL && n < 16; ) {
			line += strspn(line, " \t\r");
			line[strcspn(line, " \t\r")] = '\0';
			if (line[0] != '\0')
				m[n++] = line;
		}
		if (n == 0) {
			toast(true, "freshclam needs a mirror at least");
			free(copy);
			return (true);
		}
		nj = 0;
		json[nj] = mirrors_job(m, n);
		title[nj++] = "freshclam's mirrors written";
		/* A running freshclam reads them as it starts again. */
		if (jbool(cl, "freshclam")) {
			if (asprintf(&json[nj], "{\"kind\":\"service-action\","
			    "\"service\":\"clamav_freshclam\",\"action\":"
			    "\"restart\"}") == -1)
				abort();
			title[nj++] = "service clamav_freshclam restart";
		}
		sec_jobs(json, title, nj);
		free(copy);
		return (true);
	}
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
		/* Its settings: each only when given. */
		{
			static const char *const strs[] = { "capture",
			    "preset", "runmode", "mpm",
			    "profile", "management_cpus", "worker_cpus",
			    "flow_memcap", "stream_memcap", "reassembly_memcap",
			    "defrag_memcap", "host_memcap", "http_memcap",
			    "stream_inline", "reassembly_depth",
			    "http_request_body", "http_response_body",
			    "exception_policy", "yaml" };
			ucl_object_t	*ev;
			char		 k[32];
			size_t		 i;

			for (i = 0; i < nitems(strs); i++)
				if (jstr(f, strs[i]) != NULL && jstr(f,
				    strs[i])[0] != '\0')
					ucl_object_insert_key(o,
					    ucl_object_fromstring(jstr(f,
					    strs[i])), strs[i], 0, true);
			ev = ucl_object_typed_new(UCL_ARRAY);
			for (i = 0; i < nitems(evtypes); i++) {
				snprintf(k, sizeof(k), "eve_%s", evtypes[i]);
				if (jbool(f, k))
					ucl_array_append(ev,
					    ucl_object_fromstring(evtypes[i]));
			}
			ucl_object_insert_key(o, ev, "eve", 0, false);
			put_num(o, "stats_interval", jstr(f, "stats_interval"));
			put_num(o, "max_pending", jstr(f, "max_pending"));
			if (jbool(f, "payload"))
				ucl_object_insert_key(o, ucl_object_frombool(true),
				    "payload", 0, false);
			if (jbool(f, "midstream"))
				ucl_object_insert_key(o, ucl_object_frombool(true),
				    "midstream", 0, false);
			if (jbool(f, "offload_off"))
				ucl_object_insert_key(o, ucl_object_frombool(true),
				    "offload_off", 0, false);
			if (jstr(f, "pairs") != NULL && jstr(f, "pairs")[0] !=
			    '\0')
				ucl_object_insert_key(o, words(jstr(f, "pairs")),
				    "pairs", 0, false);
		}
		/* One stopped stays stopped, changed; its thresholds,
		 * not in this form, stay. */
		{
			const ucl_object_t	*e;
			ucl_object_iter_t	 it;

			it = NULL;
			while ((e = ucl_object_iterate(specs(true), &it, true)) !=
			    NULL) {
				if (jstr(f, "orig") == NULL || jstr(e, "name") ==
				    NULL || strcmp(jstr(e, "name"), jstr(f,
				    "orig")) != 0)
					continue;
				if (jbool(e, "stopped"))
					ucl_object_insert_key(o,
					    ucl_object_frombool(true), "stopped",
					    0, false);
				if (jstr(e, "thresholds") != NULL)
					ucl_object_insert_key(o,
					    ucl_object_fromstring(jstr(e,
					    "thresholds")), "thresholds", 0,
					    false);
			}
		}
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
	/* The two tabs Antivirus was before; Snort's, gone. */
	if (strcmp(tab, "malware") == 0 || strcmp(tab, "signatures") == 0)
		sec.tab = SEC_AV;
	else if (strcmp(tab, "snort") == 0)
		sec.tab = SEC_IDS;
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
	if (idsown_action(act, arg, value) || idsstats_action(act, arg))
		return (true);
	if (strncmp(act, "sur-", 4) == 0 || strncmp(act, "sus-", 4) == 0) {
		char	*json[1], title[96];
		const char *t[1];

		if (strncmp(act, "sus-", 4) == 0 ? !susources_action(act, arg,
		    &json[0], title, sizeof(title)) : !surules_action(act, arg,
		    value, &json[0], title, sizeof(title)))
			return (false);
		if (json[0] != NULL) {
			t[0] = title;
			sec_jobs(json, t, 1);
		}
		return (true);
	}
	if (strncmp(act, "sec-", 4) != 0 && strcmp(act, "input:sec-host") != 0)
		return (false);
	ids = sec.tab == SEC_IDS;
	if (strcmp(act, "sec-idsview") == 0) {
		sec.rules = strcmp(arg, "rules") == 0;
		sec.sources = strcmp(arg, "sources") == 0;
		if (sec.rules)
			surules_load(sec.sid);
		if (sec.sources)
			susources_load(sec.sid);
		render();
		return (true);
	}
	if (strcmp(act, "sec-tab") == 0) {
		for (i = 0; i < nitems(tabs); i++)
			if (strcmp(arg, tabs[i]) == 0)
				sec.tab = (enum sectab)i;
		if (strcmp(arg, "malware") == 0 || strcmp(arg, "signatures") ==
		    0)
			sec.tab = SEC_AV;
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
	if (strcmp(act, "sec-ids-stop") == 0) {
		char	body[300];
		int64_t	divert;

		divert = 0;
		it = NULL;
		while ((e = ucl_object_iterate(specs(true), &it, true)) != NULL)
			if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"),
			    arg) == 0)
				divert = jint(e, "divert", 0);
		snprintf(body, sizeof(body), "Suricata %s is stopped on the host; "
		    "its configuration is kept, to start it again.%s", arg,
		    divert > 0 ? " It prevents: while it is stopped, what ipfw "
		    "diverts to it passes nothing." : "");
		confirm("Stop it?", body, "Stop", divert > 0, NULL,
		    "sec-ids-run", arg, "stop");
		return (true);
	}
	/* One's stopped set or cleared, the whole list applied again. */
	if (strcmp(act, "sec-ids-run") == 0) {
		ucl_object_t	*list;

		list = specs_but(true, NULL);
		it = NULL;
		while ((e = ucl_object_iterate(list, &it, true)) != NULL)
			if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"),
			    arg) == 0)
				ucl_object_replace_key((ucl_object_t *)(uintptr_t)
				    e, ucl_object_frombool(value != NULL &&
				    strcmp(value, "stop") == 0), "stopped", 0,
				    false);
		save(true, list);
		return (true);
	}
	if (strcmp(act, "sec-start") == 0) {
		ids = value != NULL && strcmp(value, "ids") == 0;
		save(ids, specs_but(ids, NULL));
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
		const ucl_object_t	*cl = jget(sec.state, "clamav");
		char			*json[3];
		const char		*title[3];
		int			 n = 0;

		/* A configuration it can run with first, the default
		 * mirrors in it; then enabled, so that rc starts it, and
		 * (re)started: jobs the host runs in order. */
		if (jget(cl, "conf") != NULL && !jbool(cl, "conf")) {
			json[n] = mirrors_job(default_mirrors,
			    nitems(default_mirrors));
			title[n++] = "freshclam.conf written, its mirrors the "
			    "defaults";
		}
		if (asprintf(&json[n], "{\"kind\":\"service-action\",\"service"
		    "\":\"clamav_freshclam\",\"action\":\"enable\"}") == -1)
			abort();
		title[n++] = "clamav_freshclam enabled at boot";
		if (asprintf(&json[n], "{\"kind\":\"service-action\",\"service"
		    "\":\"clamav_freshclam\",\"action\":\"restart\"}") == -1)
			abort();
		title[n++] = "service clamav_freshclam restart";
		sec_jobs(json, title, n);
		(void)arg;
		return (true);
	}
	if (strcmp(act, "sec-ruleset") == 0) {
		char		*json[1];
		const char	*title[1];

		if ((json[0] = strdup("{\"kind\":\"suricata\",\"verb\":"
		    "\"update\"}")) == NULL)
			abort();
		title[0] = "suricata-update: the ruleset fetched";
		sec_jobs(json, title, 1);
		(void)arg;
		return (true);
	}
	return (false);
}

/* After a plugin was installed: the host read again. */
void
secpage_refresh(void)
{

	sec_load();
	if (sec.tab == SEC_IDS && sec.rules)
		surules_load(sec.sid);
	if (sec.tab == SEC_IDS && sec.sources)
		susources_load(sec.sid);
}

/* Each tick: the page's host read again, every 10 s while it is shown
 * and no form is open. */
void
secpage_tick(double now)
{
	static double	last;

	if (app.node != NODE_SECURITY || !app.visible || sec.loading ||
	    sec.busy || sec.edit >= 0 || now - last < 10000)
		return;
	last = now;
	sec_load();
}
