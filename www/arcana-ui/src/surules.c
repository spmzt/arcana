/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Security, IDS/IPS, Rules: the ruleset suricata-update keeps, rule by
 * rule.  The host searches it and sends a page at a time (GET
 * /api/servers/<id>/suricata/rules): Emerging Threats Open alone is some
 * 70000 rules.  Each is turned on, off, made a drop or put back as it
 * ships by sid, a suricata job (verb rule) whose choice the agent keeps
 * and gives suricata-update every time it runs, so that it holds across
 * updates.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	SR_PAGE	50

static struct {
	char		 sid[16];	/* the host read */
	char		 q[128];
	char		 only[16];
	char		 classtype[64];
	long		 offset;
	ucl_object_t	*o;
	bool		 loading;
	char		 error[256];
	unsigned	 gen;		/* a reply not the latest is dropped */
	long long	 open;		/* the sid whose text is shown */
} sr;

static const struct tcol cols[] = {
	{ "Sid", "sid", true }, { "Message", "msg", false },
	{ "Class", "classtype", false }, { "Severity", "severity", false },
	{ "Action", "action", false }, { "State", NULL, false },
};

static void
sr_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	if ((unsigned)(uintptr_t)arg != sr.gen)
		return;
	sr.loading = false;
	if (status != 200 || !jbool(o, "ok")) {
		snprintf(sr.error, sizeof(sr.error), "%s", jstr(o, "error") !=
		    NULL ? jstr(o, "error") : err != NULL ? err :
		    "the host did not answer");
		render();
		return;
	}
	sr.error[0] = '\0';
	if (sr.o != NULL)
		ucl_object_unref(sr.o);
	sr.o = jget(o, "data") != NULL ? ucl_object_copy(jget(o, "data")) :
	    ucl_object_typed_new(UCL_OBJECT);
	render();
}

/* A query's value, escaped as a URL has it. */
static void
put_param(char *url, size_t len, const char *key, const char *v)
{
	size_t	off;

	if (v == NULL || v[0] == '\0')
		return;
	off = strlen(url);
	off += (size_t)snprintf(url + off, len - off, "%c%s=", strchr(url,
	    '?') != NULL ? '&' : '?', key);
	for (; *v != '\0' && off + 4 < len; v++)
		off += (size_t)snprintf(url + off, len - off,
		    (*v >= 'a' && *v <= 'z') || (*v >= 'A' && *v <= 'Z') ||
		    (*v >= '0' && *v <= '9') || *v == '-' || *v == '_' ||
		    *v == '.' ? "%c" : "%%%02X", (unsigned char)*v);
}

/* The page of rules asked again, of host sid. */
void
surules_load(const char *sid)
{
	char	url[512], num[24];

	if (sid == NULL || sid[0] == '\0')
		return;
	if (strcmp(sid, sr.sid) != 0) {
		snprintf(sr.sid, sizeof(sr.sid), "%s", sid);
		if (sr.o != NULL)
			ucl_object_unref(sr.o);
		sr.o = NULL;
		sr.offset = 0;
	}
	snprintf(url, sizeof(url), "/api/servers/%s/suricata/rules", sid);
	put_param(url, sizeof(url), "q", sr.q);
	put_param(url, sizeof(url), "only", sr.only);
	put_param(url, sizeof(url), "classtype", sr.classtype);
	snprintf(num, sizeof(num), "%ld", sr.offset);
	put_param(url, sizeof(url), "offset", sr.offset > 0 ? num : NULL);
	snprintf(num, sizeof(num), "%d", SR_PAGE);
	put_param(url, sizeof(url), "limit", num);
	sr.loading = true;
	api("GET", url, NULL, sr_cb, (void *)(uintptr_t)++sr.gen);
}

static void
state_chip(struct html *h, const ucl_object_t *r)
{
	const char	*st = jstr(r, "state");

	if (jbool(r, "enabled"))
		h_raw(h, "<span class=\"chip st-up\">on</span>");
	else
		h_raw(h, "<span class=\"chip st-down\">off</span>");
	if (st != NULL)
		h_fmt(h, " <small class=\"dim\" title=\"Set here by sid: it "
		    "holds across updates\">set %s</small>", st);
	else
		h_raw(h, " <small class=\"dim\">as it ships</small>");
}

static void
rule_button(struct html *h, long long sid, const char *to, const char *label,
    const char *title)
{

	h_fmt(h, "<button class=\"ghost small\" data-act=\"sur-set\" "
	    "data-arg=\"%lld\" data-value=\"%s\" title=\"%s\">%s</button>", sid,
	    to, title, label);
}

void
view_surules(struct html *h, const char *sid)
{
	static const char *const onlies[] = { "", "enabled", "disabled",
	    "changed" };
	static const char *const only_names[] = { "Every rule", "Enabled",
	    "Disabled", "Set here" };
	const ucl_object_t	**rows, *r;
	long long		  matched, s;
	size_t			  i;
	int			  k;

	if (sr.o == NULL || strcmp(sid, sr.sid) != 0) {
		if (!sr.loading || strcmp(sid, sr.sid) != 0)
			surules_load(sid);
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	h_raw(h, "<form class=\"toolbar surq\" data-form=\"sur-search\"><input "
	    "class=\"filter\" name=\"q\" placeholder=\"Search the rules: "
	    "text, ET SCAN, a CVE\" autocomplete=\"off\" spellcheck=\"false\"");
	h_attr(h, "value", sr.q);
	h_raw(h, "><input name=\"classtype\" placeholder=\"Class\" "
	    "autocomplete=\"off\" spellcheck=\"false\" size=\"14\"");
	h_attr(h, "value", sr.classtype);
	h_raw(h, "><select name=\"only\">");
	for (i = 0; i < nitems(onlies); i++) {
		h_raw(h, "<option");
		h_attr(h, "value", onlies[i]);
		if (strcmp(sr.only, onlies[i]) == 0)
			h_raw(h, " selected");
		h_fmt(h, ">%s</option>", only_names[i]);
	}
	h_raw(h, "</select><button class=\"primary\">Search</button></form>");
	if (sr.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, sr.error);
		h_raw(h, "</div>");
	}
	if (jget(sr.o, "ruleset") == NULL) {
		h_raw(h, "<div class=\"empty\"><p>The ruleset is not fetched "
		    "on this host yet.</p><p class=\"dim\">Fetch the ruleset "
		    "(Instances) runs suricata-update; its rules are set here "
		    "once it has.</p></div>");
		return;
	}
	matched = jint(sr.o, "matched", 0);
	h_fmt(h, "<p class=\"dim\">%lld rules, %lld enabled; %lld set here "
	    "(enable.conf, disable.conf and drop.conf, given to "
	    "suricata-update each time it runs). ", (long long)jint(sr.o,
	    "total", 0), (long long)jint(sr.o, "enabled", 0),
	    (long long)jint(sr.o, "changed", 0));
	if (matched == 0) {
		h_raw(h, "None matches.</p>");
		return;
	}
	h_fmt(h, "%lld match: %ld to %ld.</p>", matched, sr.offset + 1,
	    sr.offset + (long)ucl_array_size(jget(sr.o, "rules")));
	h_raw(h, "<table class=\"net surules\">");
	tbl_head(h, "surules", cols, 6, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("surules", jget(sr.o, "rules"), cols, 6, "");
	for (k = 0; (r = rows[k]) != NULL; k++) {
		s = jint(r, "sid", 0);
		h_fmt(h, "<tr><td class=\"mono\"><button class=\"link\" "
		    "data-act=\"sur-open\" data-arg=\"%lld\" title=\"The rule's "
		    "text\">%lld</button></td><td>", s, s);
		h_txt(h, jstr(r, "msg"));
		/* Its text, under its message, once its sid is clicked. */
		if (s == sr.open) {
			h_raw(h, "<pre class=\"mono surule\">");
			h_txt(h, jstr(r, "rule"));
			h_raw(h, "</pre>");
		}
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "classtype"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "severity"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "action"));
		h_raw(h, "</td><td>");
		state_chip(h, r);
		h_raw(h, "</td><td class=\"acts\">");
		if (!jbool(r, "enabled"))
			rule_button(h, s, "on", "Enable", "On, across updates");
		else
			rule_button(h, s, "off", "Disable", "Off, across updates");
		if (jstr(r, "state") == NULL || strcmp(jstr(r, "state"),
		    "drop") != 0)
			rule_button(h, s, "drop", "Drop", "On, and a drop where "
			    "an instance prevents (ipfw divert): what it "
			    "matches does not pass");
		if (jstr(r, "state") != NULL)
			rule_button(h, s, "default", "As it ships", "Back to "
			    "the ruleset's own choice");
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table><div class=\"toolbar\">");
	if (sr.offset > 0)
		h_raw(h, "<button class=\"ghost\" data-act=\"sur-page\" "
		    "data-arg=\"prev\">Previous</button>");
	if (sr.offset + SR_PAGE < matched)
		h_raw(h, "<button class=\"ghost\" data-act=\"sur-page\" "
		    "data-arg=\"next\">Next</button>");
	h_raw(h, "</div>");
}

bool
surules_form(const char *form, const ucl_object_t *f)
{

	if (strcmp(form, "sur-search") != 0)
		return (false);
	snprintf(sr.q, sizeof(sr.q), "%s", jstr(f, "q") != NULL ? jstr(f,
	    "q") : "");
	snprintf(sr.classtype, sizeof(sr.classtype), "%s", jstr(f,
	    "classtype") != NULL ? jstr(f, "classtype") : "");
	snprintf(sr.only, sizeof(sr.only), "%s", jstr(f, "only") != NULL ?
	    jstr(f, "only") : "");
	sr.offset = 0;
	surules_load(sr.sid);
	return (true);
}

/* sur-page, sur-open and sur-set; *jsonp a rule job to send, or NULL. */
bool
surules_action(const char *act, const char *arg, const char *value,
    char **jsonp, char *title, size_t tlen)
{
	char	*w, *q;

	*jsonp = NULL;
	if (strcmp(act, "sur-page") == 0) {
		sr.offset += strcmp(arg, "next") == 0 ? SR_PAGE : -SR_PAGE;
		if (sr.offset < 0)
			sr.offset = 0;
		surules_load(sr.sid);
		return (true);
	}
	if (strcmp(act, "sur-open") == 0) {
		sr.open = sr.open == strtoll(arg, NULL, 10) ? 0 :
		    strtoll(arg, NULL, 10);
		render();
		return (true);
	}
	if (strcmp(act, "sur-set") != 0)
		return (false);
	if (value == NULL || (strcmp(value, "on") != 0 && strcmp(value,
	    "off") != 0 && strcmp(value, "drop") != 0 && strcmp(value,
	    "default") != 0) || strspn(arg, "0123456789") != strlen(arg) ||
	    arg[0] == '\0')
		return (true);
	if (asprintf(&w, "%s=%s", value, arg) == -1)
		abort();
	q = json_quote(w);
	if (asprintf(jsonp, "{\"kind\":\"suricata\",\"verb\":\"rule\","
	    "\"args\":[%s]}", q) == -1)
		abort();
	snprintf(title, tlen, "suricata rules set: %s", w);
	free(q);
	free(w);
	return (true);
}

/*
 * IDS/IPS, Sources: the rule sources suricata-update knows (its index,
 * fetched by a job) and those enabled here, each enabled, disabled,
 * removed or added by address, a job each.  None enabled, it fetches
 * Emerging Threats Open.  A source that needs a parameter (a commercial
 * one's secret code) asks for it as it is enabled; the host writes it
 * to a file of its own and nowhere else.
 */

static struct {
	char		 sid[16];
	ucl_object_t	*o;
	bool		 loading;
	char		 error[256];
	unsigned	 gen;
	char		 asking[72];	/* the source whose parameters are
					 * asked for */
	bool		 adding;
} so;

static void
so_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	if ((unsigned)(uintptr_t)arg != so.gen)
		return;
	so.loading = false;
	if (status != 200 || !jbool(o, "ok")) {
		snprintf(so.error, sizeof(so.error), "%s", jstr(o, "error") !=
		    NULL ? jstr(o, "error") : err != NULL ? err :
		    "the host did not answer");
		render();
		return;
	}
	so.error[0] = '\0';
	if (so.o != NULL)
		ucl_object_unref(so.o);
	so.o = jget(o, "data") != NULL ? ucl_object_copy(jget(o, "data")) :
	    ucl_object_typed_new(UCL_OBJECT);
	render();
}

void
susources_load(const char *sid)
{
	char	url[96];

	if (sid == NULL || sid[0] == '\0')
		return;
	if (strcmp(sid, so.sid) != 0) {
		snprintf(so.sid, sizeof(so.sid), "%s", sid);
		if (so.o != NULL)
			ucl_object_unref(so.o);
		so.o = NULL;
	}
	snprintf(url, sizeof(url), "/api/servers/%s/suricata/rules?sources=1",
	    sid);
	so.loading = true;
	api("GET", url, NULL, so_cb, (void *)(uintptr_t)++so.gen);
}

static void
source_button(struct html *h, const char *act, const char *name,
    const char *label, bool danger)
{

	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"%s\"", danger ?
	    " danger" : "", act);
	h_attr(h, "data-arg", name);
	h_fmt(h, ">%s</button>", label);
}

void
view_susources(struct html *h, const char *sid)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*st, *params;
	char			*copy, *p, *w;

	if (so.o == NULL || strcmp(sid, so.sid) != 0) {
		if (!so.loading || strcmp(sid, so.sid) != 0)
			susources_load(sid);
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	h_raw(h, "<div class=\"toolbar\"><button class=\"ghost\" data-act=\""
	    "sus-index\" title=\"suricata-update update-sources: the list of "
	    "sources it knows\">");
	h_raw(h, jbool(so.o, "index") ? "Fetch the list again" :
	    "Fetch the list of sources");
	h_raw(h, "</button><span class=\"grow\"></span><button class=\"ghost\" "
	    "data-act=\"sus-adding\">Add by address</button></div>");
	if (so.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, so.error);
		h_raw(h, "</div>");
	}
	h_raw(h, "<p class=\"dim\">Where suricata-update fetches the ruleset "
	    "from. ");
	h_raw(h, jbool(so.o, "default_et_open") ? "None is enabled here: it "
	    "fetches Emerging Threats Open." : "It fetches those enabled.");
	h_raw(h, " A change takes effect when the ruleset is fetched again "
	    "(Instances, Fetch the ruleset).</p>");
	if (so.adding) {
		h_raw(h, "<form class=\"secform\" data-form=\"sus-add\"><h4>A "
		    "source by its address</h4><div class=\"rowform\"><label>"
		    "Name <input name=\"name\" required spellcheck=\"false\" "
		    "placeholder=\"lab/local\" pattern=\"[A-Za-z0-9._/-]{1,64}\">"
		    "</label><label>Address <input name=\"url\" required "
		    "spellcheck=\"false\" placeholder=\"https://rules.example.org/"
		    "local.rules\" pattern=\"(https?://|file:///)\\S+\"><small "
		    "class=\"help\">a .rules file or an archive of them, by "
		    "http, https or file:///</small></label></div><div class=\""
		    "actions\"><button type=\"button\" class=\"ghost\" data-act="
		    "\"sus-cancel\">Cancel</button><button type=\"submit\" "
		    "class=\"primary\">Add</button></div></form>");
	}
	if (ucl_array_size(jget(so.o, "sources")) == 0) {
		h_raw(h, "<div class=\"empty\"><p>The list of sources is not "
		    "fetched on this host.</p><p class=\"dim\">Fetch the list "
		    "of sources: Emerging Threats Open and Pro, OISF's, "
		    "Abuse.ch's and others suricata-update knows.</p></div>");
		return;
	}
	h_raw(h, "<table class=\"net susources\"><thead><tr><th>Source</th>"
	    "<th>Vendor</th><th>What</th><th>License</th><th>State</th><th>"
	    "</th></tr></thead><tbody>");
	it = NULL;
	while ((e = ucl_object_iterate(jget(so.o, "sources"), &it, true)) !=
	    NULL) {
		st = jstr(e, "state");
		params = jstr(e, "parameters");
		h_raw(h, "<tr><td class=\"mono\"><b>");
		h_txt(h, jstr(e, "name"));
		h_raw(h, "</b>");
		if (jstr(e, "url") != NULL) {
			h_raw(h, "<br><small class=\"dim\">");
			h_txt(h, jstr(e, "url"));
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td>");
		h_txt(h, jstr(e, "vendor"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(e, "summary"));
		if (jstr(e, "subscription") != NULL) {
			h_raw(h, " <a target=\"_blank\" rel=\"noopener\"");
			h_attr(h, "href", jstr(e, "subscription"));
			h_raw(h, ">subscription</a>");
		}
		h_raw(h, "</td><td>");
		h_txt(h, jstr(e, "license"));
		h_raw(h, "</td><td>");
		if (st != NULL && strcmp(st, "enabled") == 0)
			h_raw(h, "<span class=\"chip st-up\">enabled</span>");
		else if (st != NULL)
			h_raw(h, "<span class=\"chip st-down\">disabled</span>");
		else if (jbool(so.o, "default_et_open") && strcmp(jstr(e,
		    "name"), "et/open") == 0)
			h_raw(h, "<span class=\"chip\">the default</span>");
		h_raw(h, "</td><td class=\"acts\">");
		if (st != NULL && strcmp(st, "enabled") == 0)
			source_button(h, "sus-disable", jstr(e, "name"),
			    "Disable", false);
		else
			source_button(h, params != NULL && st == NULL ?
			    "sus-ask" : "sus-enable", jstr(e, "name"), "Enable",
			    false);
		if (st != NULL)
			source_button(h, "sus-remove", jstr(e, "name"), "Remove",
			    true);
		h_raw(h, "</td></tr>");
		/* Its parameters asked for, one input each. */
		if (params != NULL && strcmp(so.asking, jstr(e, "name")) == 0) {
			h_raw(h, "<tr class=\"sub\"><td colspan=\"6\"><form "
			    "class=\"secform\" data-form=\"sus-enable\"><input "
			    "type=\"hidden\" name=\"name\"");
			h_attr(h, "value", jstr(e, "name"));
			h_raw(h, "><div class=\"rowform\">");
			if ((copy = strdup(params)) == NULL)
				abort();
			for (p = copy; (w = strsep(&p, ", ")) != NULL;) {
				if (w[0] == '\0')
					continue;
				h_raw(h, "<label>");
				h_txt(h, w);
				h_raw(h, " <input type=\"password\" required "
				    "autocomplete=\"off\"");
				h_attr(h, "name", w);
				h_raw(h, "></label>");
			}
			free(copy);
			h_raw(h, "</div><small class=\"help\">Kept on the host "
			    "alone, in suricata-update's file of the source, "
			    "root's.</small><div class=\"actions\"><button type="
			    "\"button\" class=\"ghost\" data-act=\"sus-cancel\">"
			    "Cancel</button><button type=\"submit\" class=\""
			    "primary\">Enable</button></div></form></td></tr>");
		}
	}
	h_raw(h, "</tbody></table>");
}

/* A source job: verb and its words, the title without a secret. */
static void
source_job(char **jsonp, char *title, size_t tlen, const char *verb,
    const char *const *words, size_t n, const char *name)
{
	char	*t, *q;
	size_t	 i;

	if (asprintf(jsonp, "{\"kind\":\"suricata\",\"verb\":\"%s\","
	    "\"args\":[", verb) == -1)
		abort();
	for (i = 0; i < n; i++) {
		q = json_quote(words[i]);
		if (asprintf(&t, "%s%s%s", *jsonp, i > 0 ? "," : "", q) == -1)
			abort();
		free(*jsonp);
		free(q);
		*jsonp = t;
	}
	if (asprintf(&t, "%s]}", *jsonp) == -1)
		abort();
	free(*jsonp);
	*jsonp = t;
	snprintf(title, tlen, "suricata %s %s", verb + 7, name);
}

/* sus-add and sus-enable: *jsonp the job to send, or NULL. */
bool
susources_form(const char *form, const ucl_object_t *f, char **jsonp,
    char *title, size_t tlen)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	const char		*words[8];
	char			*w[8];
	size_t			 n, i;

	*jsonp = NULL;
	if (strcmp(form, "sus-add") == 0) {
		if (jstr(f, "name") == NULL || jstr(f, "url") == NULL)
			return (true);
		if (asprintf(&w[0], "name=%s", jstr(f, "name")) == -1 ||
		    asprintf(&w[1], "url=%s", jstr(f, "url")) == -1)
			abort();
		words[0] = w[0];
		words[1] = w[1];
		source_job(jsonp, title, tlen, "source-add", words, 2, jstr(f,
		    "name"));
		free(w[0]);
		free(w[1]);
		so.adding = false;
		return (true);
	}
	if (strcmp(form, "sus-enable") != 0 || jstr(f, "name") == NULL)
		return (false);
	n = 0;
	if (asprintf(&w[n], "name=%s", jstr(f, "name")) == -1)
		abort();
	words[n] = w[n];
	n++;
	it = NULL;
	while ((v = ucl_object_iterate(f, &it, true)) != NULL && n < 8) {
		/* Its parameters alone: not the page's own (__submit). */
		if (strcmp(ucl_object_key(v), "name") == 0 ||
		    strncmp(ucl_object_key(v), "__", 2) == 0 ||
		    ucl_object_type(v) != UCL_STRING)
			continue;
		if (asprintf(&w[n], "%s=%s", ucl_object_key(v),
		    ucl_object_tostring(v)) == -1)
			abort();
		words[n] = w[n];
		n++;
	}
	source_job(jsonp, title, tlen, "source-enable", words, n, jstr(f,
	    "name"));
	for (i = 0; i < n; i++)
		free(w[i]);
	so.asking[0] = '\0';
	return (true);
}

/* sus-*: *jsonp a job to send, or NULL. */
bool
susources_action(const char *act, const char *arg, char **jsonp,
    char *title, size_t tlen)
{
	const char	*words[1];
	char		*w;

	*jsonp = NULL;
	if (strncmp(act, "sus-", 4) != 0)
		return (false);
	if (strcmp(act, "sus-index") == 0) {
		if ((*jsonp = strdup("{\"kind\":\"suricata\",\"verb\":"
		    "\"sources\"}")) == NULL)
			abort();
		snprintf(title, tlen, "suricata-update: the index of rule "
		    "sources fetched");
	} else if (strcmp(act, "sus-adding") == 0) {
		so.adding = true;
		render();
	} else if (strcmp(act, "sus-cancel") == 0) {
		so.adding = false;
		so.asking[0] = '\0';
		render();
	} else if (strcmp(act, "sus-ask") == 0) {
		snprintf(so.asking, sizeof(so.asking), "%s", arg);
		render();
	} else if (strcmp(act, "sus-enable") == 0 || strcmp(act,
	    "sus-disable") == 0 || strcmp(act, "sus-remove") == 0) {
		if (asprintf(&w, "name=%s", arg) == -1)
			abort();
		words[0] = w;
		source_job(jsonp, title, tlen, strcmp(act, "sus-enable") == 0 ?
		    "source-enable" : strcmp(act, "sus-disable") == 0 ?
		    "source-disable" : "source-remove", words, 1, arg);
		free(w);
	}
	return (true);
}
