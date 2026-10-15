/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The host's configuration as a whole, on its Summary: saved as a
 * bundle (config-export: the files Arcana manages, the packages put
 * there by hand, the hardware), and a host made the same as this one,
 * or this one made as a bundle file says (config-apply).
 *
 * Nothing is written before it was looked at: Check asks the host that
 * is to change what it would do (the hardware against the bundle's,
 * each file same, changed with its diff, new, or a secret it keeps,
 * the packages it lacks), and only then Apply does it.  From another
 * host, the console reads that host's bundle with its secrets itself:
 * they do not pass through the page.  The packages are installed only
 * when Install is pressed; the files take hold at the next boot.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	char		 sid[9];	/* the host the box is open on */
	bool		 secrets;	/* the export: with them */
	char		 target[9];	/* made this one; "" none picked */
	char		 hostname[256];	/* its name after, or "" the bundle's */
	ucl_object_t	*bundle;	/* a file's, for this host */
	char		 file[128];	/* its name */
	bool		 anyway;
	bool		 busy;
	/* The last report: of which host, a dry run or done. */
	ucl_object_t	*report;
	char		 rsid[9];
	bool		 rdry;
	char		 error[512];
} hc;

static void
reset(const char *sid)
{

	if (strcmp(hc.sid, sid) == 0)
		return;
	if (hc.bundle != NULL)
		ucl_object_unref(hc.bundle);
	if (hc.report != NULL)
		ucl_object_unref(hc.report);
	memset(&hc, 0, sizeof(hc));
	snprintf(hc.sid, sizeof(hc.sid), "%s", sid);
}

static struct server *
server_of(const char *sid)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sid) == 0)
			return (&app.servers[i]);
	return (NULL);
}

static const char *
why(int status, const ucl_object_t *o, const char *err)
{

	return (jstr(o, "error") != NULL ? jstr(o, "error") :
	    jstr(o, "error.message") != NULL ? jstr(o, "error.message") :
	    err != NULL ? err : status == 0 ? "no answer" : "it failed");
}

static void
export_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct server	*s;
	char		 base[300];
	bool		 yaml = arg != NULL;

	hc.busy = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(hc.error, sizeof(hc.error), "The bundle was not made: "
		    "%s", why(status, o, err));
		return;
	}
	hc.error[0] = '\0';
	s = server_of(hc.sid);
	export_base(base, sizeof(base), s != NULL ? s->name : "host",
	    "config");
	export_save(base, jget(o, "data"), yaml);
	toast(false, "The host's bundle saved%s", hc.secrets ? ", its secrets "
	    "in it: keep it as one keeps a key" : "");
}

static void
apply_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	hc.busy = false;
	if (hc.report != NULL)
		ucl_object_unref(hc.report);
	hc.report = jget(o, "data") != NULL ? ucl_object_copy(jget(o,
	    "data")) : NULL;
	if (status != 200 || !jbool(o, "ok"))
		snprintf(hc.error, sizeof(hc.error), "%s", why(status, o, err));
	else
		hc.error[0] = '\0';
}

/* Check (dry) or Apply: to the target, from this host; or this host's,
 * from the file. */
static void
send(bool dry)
{
	ucl_object_t	*b;
	char		 url[96], *json;
	const char	*to;

	to = hc.target[0] != '\0' ? hc.target : hc.sid;
	b = ucl_object_typed_new(UCL_OBJECT);
	if (hc.target[0] != '\0')
		ucl_object_insert_key(b, ucl_object_fromstring(hc.sid), "from",
		    0, true);
	else if (hc.bundle != NULL)
		ucl_object_insert_key(b, ucl_object_ref(hc.bundle), "bundle", 0,
		    true);
	else {
		ucl_object_unref(b);
		return;
	}
	ucl_object_insert_key(b, ucl_object_frombool(dry), "dry_run", 0, true);
	ucl_object_insert_key(b, ucl_object_frombool(hc.anyway), "anyway", 0,
	    true);
	if (hc.hostname[0] != '\0')
		ucl_object_insert_key(b, ucl_object_fromstring(hc.hostname),
		    "hostname", 0, true);
	json = (char *)ucl_object_emit(b, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(b);
	snprintf(url, sizeof(url), "/api/servers/%s/config", to);
	snprintf(hc.rsid, sizeof(hc.rsid), "%s", to);
	hc.rdry = dry;
	hc.busy = true;
	hc.error[0] = '\0';
	api("POST", url, json, apply_cb, NULL);
	free(json);
}

static void
report(struct html *h)
{
	const ucl_object_t	*r = hc.report, *e;
	ucl_object_iter_t	 it;
	struct server		*t = server_of(hc.rsid);
	const char		*st;
	int			 nch = 0;
	bool			 done = jbool(r, "applied");

	if (r == NULL)
		return;
	h_raw(h, "<div class=\"hcreport\"><h4>");
	h_txt(h, t != NULL ? t->name : "the host");
	h_raw(h, done ? ": done" : hc.rdry ? ": what it would do" :
	    ": nothing done");
	h_raw(h, "</h4>");
	if (ucl_array_size(jget(r, "mismatches")) > 0) {
		h_raw(h, "<div class=\"notice bad\">Not the bundle's hardware:"
		    "<ul>");
		it = NULL;
		while ((e = ucl_object_iterate(jget(r, "mismatches"), &it,
		    true)) != NULL) {
			h_raw(h, "<li>");
			h_txt(h, ucl_object_tostring_forced(e));
			h_raw(h, "</li>");
		}
		h_raw(h, "</ul>Interfaces and disks the files name may not be "
		    "there; apply anyway only when that is meant.</div>");
	}
	if (done) {
		h_raw(h, "<div class=\"notice\">Written. The files before are "
		    "kept in <code>");
		h_txt(h, jstr(r, "backup"));
		h_raw(h, "</code>. They take hold at the next boot: reboot the "
		    "host when it suits.</div>");
	}
	h_raw(h, "<table class=\"hcfiles\"><thead><tr><th>File</th><th>"
	    "</th></tr></thead><tbody>");
	it = NULL;
	while ((e = ucl_object_iterate(jget(r, "files"), &it, true)) != NULL) {
		st = jstr(e, "state") != NULL ? jstr(e, "state") : "";
		if (strcmp(st, "same") == 0)
			continue;
		nch++;
		h_fmt(h, "<tr class=\"%s\"><td><code>", st);
		h_txt(h, jstr(e, "path"));
		h_raw(h, "</code>");
		if (jstr(e, "diff") != NULL) {
			h_raw(h, "<details><summary>the diff</summary><pre "
			    "class=\"diff\">");
			h_txt(h, jstr(e, "diff"));
			h_raw(h, "</pre></details>");
		}
		h_raw(h, "</td><td>");
		h_raw(h, strcmp(st, "changed") == 0 ? "changed" : strcmp(st,
		    "new") == 0 ? "new here" : strcmp(st, "withheld") == 0 ?
		    "a secret the bundle does not carry: kept as it is" : st);
		h_raw(h, "</td></tr>");
	}
	if (nch == 0)
		h_raw(h, "<tr><td colspan=\"2\" class=\"dim\">Every file is the "
		    "bundle's already.</td></tr>");
	h_raw(h, "</tbody></table>");
	if (ucl_array_size(jget(r, "packages")) > 0) {
		h_raw(h, "<p>Packages the bundle has and this host has not: ");
		it = NULL;
		nch = 0;
		while ((e = ucl_object_iterate(jget(r, "packages"), &it,
		    true)) != NULL) {
			h_raw(h, nch++ > 0 ? ", <code>" : "<code>");
			h_txt(h, jstr(e, "name"));
			h_raw(h, "</code>");
		}
		h_raw(h, ". Arcana installs none by itself.</p>"
		    "<button class=\"ghost small\" data-act=\"hc-pkgs\">Install "
		    "them</button>");
	}
	if (hc.rdry && !done)
		h_fmt(h, "<div class=\"actions\">%s<button class=\"primary\" "
		    "data-act=\"hc-apply\"%s>Apply</button></div>",
		    ucl_array_size(jget(r, "mismatches")) > 0 ? "<label "
		    "class=\"toggle\"><input type=\"checkbox\" data-input=\""
		    "hc-anyway\"> Though the hardware differs</label>" : "",
		    hc.busy || (ucl_array_size(jget(r, "mismatches")) > 0 &&
		    !hc.anyway) ? " disabled" : "");
	h_raw(h, "</div>");
}

void
view_hostconf(struct html *h, struct server *s)
{
	int	i;

	reset(s->id);
	h_raw(h, "<section class=\"transport hostconf\">");
	box_head(h, "hostconf", "h3");
	h_raw(h, "Configuration, as a whole</h3>");
	if (box_shut("hostconf")) {
		h_raw(h, "</section>");
		return;
	}
	h_raw(h, "<p class=\"dim\">The files Arcana manages (rc.conf, "
	    "loader.conf, sysctl.conf, jail.conf, fstab, ipfw's rules, "
	    "BIRD's, strongSwan's, WireGuard's, the SD-WAN's), the packages "
	    "put here by hand, and what the hardware is: saved, or another "
	    "host made the same. The agent's own keys never, and data (jails, "
	    "datasets) not: that is a ZFS send.</p>");
	if (hc.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, hc.error);
		h_raw(h, "</div>");
	}
	/* Saved. */
	h_fmt(h, "<div class=\"toolbar\"><span>Save it</span><button class=\""
	    "ghost small\" data-act=\"hc-export\" data-arg=\"json\"%s>JSON"
	    "</button><button class=\"ghost small\" data-act=\"hc-export\" "
	    "data-arg=\"yaml\"%s>YAML</button><label class=\"toggle\"><input "
	    "type=\"checkbox\" data-input=\"hc-secrets\"%s> With its secrets "
	    "(WireGuard's and strongSwan's keys)</label></div>", hc.busy ?
	    " disabled" : "", hc.busy ? " disabled" : "", hc.secrets ?
	    " checked" : "");
	/* Another host made this one. */
	h_raw(h, "<div class=\"toolbar\"><label>Make <select data-input=\""
	    "hc-target\"><option value=\"\">another host…</option>");
	for (i = 0; i < app.nservers; i++) {
		if (strcmp(app.servers[i].id, s->id) == 0)
			continue;
		h_raw(h, "<option");
		h_attr(h, "value", app.servers[i].id);
		if (strcmp(hc.target, app.servers[i].id) == 0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, app.servers[i].name);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select> the same as this one</label><label>named "
	    "<input data-input=\"hc-hostname\" placeholder=\"its own name\" "
	    "maxlength=\"255\"");
	h_attr(h, "value", hc.hostname);
	h_fmt(h, "></label><button class=\"small\" data-act=\"hc-check\""
	    "%s>Check</button></div>", hc.target[0] == '\0' || hc.busy ?
	    " disabled" : "");
	/* This host made as a file says. */
	h_raw(h, "<div class=\"toolbar\"><span>Or this host made as a "
	    "bundle says</span><label class=\"button ghost small\" title=\"A "
	    "bundle saved before, JSON or YAML: checked first\">From a file"
	    "<input type=\"file\" accept=\"application/json,.json,"
	    "application/yaml,.yaml,.yml\" data-file=\"hc-bundle\" hidden>"
	    "</label>");
	if (hc.bundle != NULL) {
		h_raw(h, "<span class=\"dim\">");
		h_txt(h, hc.file);
		h_raw(h, ", of ");
		h_txt(h, jstr(hc.bundle, "host"));
		h_raw(h, "</span>");
	}
	h_raw(h, "</div>");
	if (hc.busy)
		h_raw(h, "<div class=\"loader\"></div>");
	report(h);
	h_raw(h, "</section>");
}

bool
hostconf_action(const char *act, const char *arg, const char *value)
{
	struct server	*s, *t;
	char		 url[96], why2[300];

	if (strncmp(act, "hc-", 3) != 0 && strncmp(act, "input:hc-", 9) != 0 &&
	    strcmp(act, "file:hc-bundle") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	reset(s->id);
	if (strcmp(act, "input:hc-secrets") == 0)
		hc.secrets = strcmp(value, "true") == 0;
	else if (strcmp(act, "input:hc-anyway") == 0)
		hc.anyway = strcmp(value, "true") == 0;
	else if (strcmp(act, "input:hc-hostname") == 0)
		snprintf(hc.hostname, sizeof(hc.hostname), "%s", value);
	else if (strcmp(act, "input:hc-target") == 0) {
		snprintf(hc.target, sizeof(hc.target), "%s", value);
		if (hc.bundle != NULL)
			ucl_object_unref(hc.bundle);
		hc.bundle = NULL;
	} else if (strcmp(act, "hc-export") == 0) {
		snprintf(url, sizeof(url), "/api/servers/%s/config/export",
		    s->id);
		hc.busy = true;
		api("POST", url, hc.secrets ? "{\"secrets\":true}" : "{}",
		    export_cb, strcmp(arg, "yaml") == 0 ? (void *)1 : NULL);
	} else if (strcmp(act, "hc-check") == 0) {
		hc.anyway = false;
		send(true);
	} else if (strcmp(act, "hc-apply") == 0)
		send(false);
	else if (strcmp(act, "file:hc-bundle") == 0) {
		ucl_object_t	*o;

		o = value[0] != '\0' ? data_parse(value, why2, sizeof(why2)) :
		    NULL;
		if (o == NULL || jstr(o, "arcana") == NULL || strcmp(jstr(o,
		    "arcana"), "host") != 0) {
			snprintf(hc.error, sizeof(hc.error), "%s: not a host's "
			    "bundle%s%s", arg, why2[0] != '\0' && o == NULL ?
			    ": " : "", o == NULL ? why2 : "");
			if (o != NULL)
				ucl_object_unref(o);
			return (true);
		}
		if (hc.bundle != NULL)
			ucl_object_unref(hc.bundle);
		hc.bundle = o;
		hc.target[0] = '\0';
		snprintf(hc.file, sizeof(hc.file), "%s", arg);
		hc.anyway = false;
		send(true);
	} else if (strcmp(act, "hc-pkgs") == 0 && hc.report != NULL &&
	    (t = server_of(hc.rsid)) != NULL) {
		const ucl_object_t	*e;
		ucl_object_iter_t	 it = NULL;
		char			*json, *q, *list;
		size_t			 len = 0;

		list = calloc(1, 65536);
		while ((e = ucl_object_iterate(jget(hc.report, "packages"),
		    &it, true)) != NULL && len < 65000) {
			q = json_quote(jstr(e, "name"));
			len += (size_t)snprintf(list + len, 65536 - len, "%s%s",
			    len > 0 ? "," : "", q);
			free(q);
		}
		if (asprintf(&json, "{\"kind\":\"pkg-install\",\"packages\":"
		    "[%s]}", list) == -1)
			abort();
		free(list);
		snprintf(why2, sizeof(why2), "pkg install on %s: the bundle's "
		    "packages", t->name);
		job_send(t, json, why2, JOB_PACKAGES, "");
	}
	return (true);
}
