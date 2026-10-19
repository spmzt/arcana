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
