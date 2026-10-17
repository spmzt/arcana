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
	char		 tname[65];	/* Save as a template: its name */
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

/* Is c of a host's name (letters, digits, - _), as one written beside
 * it would make it another word? */
static bool
name_char(char c)
{

	return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0'
	    && c <= '9') || c == '-' || c == '_');
}

/*
 * The host's bundle, without secrets, kept as a template: its secret
 * files left out (a host's keys are its own), its hostname everywhere
 * {{hostname}}, which each host it is applied to gives.
 */
static void
template_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*b, *f;
	ucl_object_iter_t	 it;
	ucl_object_t		*t, *files, *nf, *vars, *v;
	struct server		*s;
	const char		*text, *p, *q;
	char			 hn[256];
	char			*name = arg;

	hc.busy = false;
	if (status != 200 || !jbool(o, "ok") || (b = jget(o, "data")) ==
	    NULL) {
		snprintf(hc.error, sizeof(hc.error), "No template made: %s",
		    why(status, o, err));
		free(name);
		return;
	}
	/* Its hostname, as rc.conf says it. */
	hn[0] = '\0';
	it = NULL;
	while ((f = ucl_object_iterate(jget(b, "files"), &it, true)) != NULL)
		if (jstr(f, "path") != NULL && strcmp(jstr(f, "path"),
		    "/etc/rc.conf") == 0 && (text = jstr(f, "text")) != NULL &&
		    (p = strstr(text, "hostname=\"")) != NULL &&
		    (p == text || p[-1] == '\n') && (q = strchr(p + 10, '"')) !=
		    NULL && q - (p + 10) < (long)sizeof(hn))
			snprintf(hn, sizeof(hn), "%.*s", (int)(q - (p + 10)),
			    p + 10);
	t = ucl_object_typed_new(UCL_OBJECT);
	s = server_of(hc.sid);
	ucl_object_insert_key(t, ucl_object_fromstring(s != NULL ? s->name :
	    "a host"), "from", 0, true);
	files = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((f = ucl_object_iterate(jget(b, "files"), &it, true)) != NULL) {
		struct html	 out;

		if (jbool(f, "secret") || (text = jstr(f, "text")) == NULL)
			continue;
		nf = ucl_object_copy(f);
		/* The hostname, wherever it is written as a name of its own
		 * (not inside a longer word: lab in label), a value. */
		memset(&out, 0, sizeof(out));
		p = text;
		for (q = text; hn[0] != '\0' && (q = strstr(q, hn)) != NULL; ) {
			const char	*e = q + strlen(hn);

			if ((q > text && name_char(q[-1])) || name_char(*e)) {
				q = e;
				continue;
			}
			h_fmt(&out, "%.*s{{hostname}}", (int)(q - p), p);
			p = q = e;
		}
		h_raw(&out, p);
		ucl_object_replace_key(nf, ucl_object_fromstring(out.s != NULL ?
		    out.s : ""), "text", 0, true);
		free(out.s);
		ucl_array_append(files, nf);
	}
	ucl_object_insert_key(t, files, "files", 0, true);
	if (jget(b, "packages") != NULL)
		ucl_object_insert_key(t, ucl_object_copy(jget(b, "packages")),
		    "packages", 0, true);
	if (jget(b, "facts") != NULL)
		ucl_object_insert_key(t, ucl_object_copy(jget(b, "facts")),
		    "facts", 0, true);
	if (hn[0] != '\0') {
		vars = ucl_object_typed_new(UCL_OBJECT);
		v = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(v, ucl_object_fromstring("the host's "
		    "name"), "description", 0, true);
		ucl_object_insert_key(vars, v, "hostname", 0, true);
		ucl_object_insert_key(t, vars, "variables", 0, true);
	}
	/* Opened there once kept (template_put's). */
	template_put(name, t);
	ucl_object_unref(t);
	app.node = NODE_DEVICES;
	app.devtab = 1;
	free(name);
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

/*
 * What a host would do with a bundle, or did (config-apply's report):
 * the hardware it lacks, each file changed or new with its diff, the
 * packages it lacks; Apply after a check.  pfx names the actions
 * (<pfx>-apply, <pfx>-pkgs, input <pfx>-anyway): the host's box's, or
 * a template's.
 */
void
config_report(struct html *h, const ucl_object_t *r, const char *host,
    bool dry, bool busy, bool anyway, const char *pfx)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*st;
	int			 nch = 0;
	bool			 done = jbool(r, "applied");

	if (r == NULL)
		return;
	h_raw(h, "<div class=\"hcreport\"><h4>");
	h_txt(h, host != NULL ? host : "the host");
	h_raw(h, done ? ": done" : dry ? ": what it would do" :
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
		h_fmt(h, ". Arcana installs none by itself.</p>"
		    "<button class=\"ghost small\" data-act=\"%s-pkgs\">Install "
		    "them</button>", pfx);
	}
	if (dry && !done) {
		h_raw(h, "<div class=\"actions\">");
		if (ucl_array_size(jget(r, "mismatches")) > 0)
			h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox"
			    "\" data-input=\"%s-anyway\"> Though the hardware "
			    "differs</label>", pfx);
		h_fmt(h, "<button class=\"primary\" data-act=\"%s-apply\"%s>"
		    "Apply</button></div>", pfx, busy || (ucl_array_size(jget(r,
		    "mismatches")) > 0 && !anyway) ? " disabled" : "");
	}
	h_raw(h, "</div>");
}

/* The packages a report says the host lacks, installed: a job. */
void
config_pkgs(struct server *t, const ucl_object_t *r, const char *why)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	char			*json, *q, *list, title[300];
	size_t			 len = 0;

	list = calloc(1, 65536);
	while ((e = ucl_object_iterate(jget(r, "packages"), &it, true)) !=
	    NULL && len < 65000) {
		q = json_quote(jstr(e, "name"));
		len += (size_t)snprintf(list + len, 65536 - len, "%s%s", len > 0 ?
		    "," : "", q);
		free(q);
	}
	if (asprintf(&json, "{\"kind\":\"pkg-install\",\"packages\":[%s]}",
	    list) == -1)
		abort();
	free(list);
	snprintf(title, sizeof(title), "pkg install on %s: %s", t->name, why);
	job_send(t, json, title, JOB_PACKAGES, "");
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
	/* Kept by the console as a template, for other hosts. */
	h_raw(h, "<div class=\"toolbar\"><label title=\"Its files without "
	    "secrets, its hostname {{hostname}}: the Devices page's Templates "
	    "apply it to other hosts\">Save as a template named <input "
	    "data-input=\"hc-tname\" maxlength=\"64\" placeholder=\""
	    "edge-router\"");
	h_attr(h, "value", hc.tname);
	h_fmt(h, "></label><button class=\"ghost small\" data-act=\""
	    "hc-template\"%s>Save</button></div>", hc.busy || hc.tname[0] ==
	    '\0' ? " disabled" : "");
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
	if (hc.report != NULL)
		config_report(h, hc.report, server_of(hc.rsid) != NULL ?
		    server_of(hc.rsid)->name : NULL, hc.rdry, hc.busy, hc.anyway,
		    "hc");
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
	else if (strcmp(act, "input:hc-tname") == 0)
		snprintf(hc.tname, sizeof(hc.tname), "%s", value);
	else if (strcmp(act, "hc-template") == 0 && hc.tname[0] != '\0') {
		if (strspn(hc.tname, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
		    "OPQRSTUVWXYZ0123456789._-") != strlen(hc.tname) ||
		    hc.tname[0] == '.' || hc.tname[0] == '-') {
			snprintf(hc.error, sizeof(hc.error), "A template is "
			    "named with letters, digits, . _ and -");
			return (true);
		}
		snprintf(url, sizeof(url), "/api/servers/%s/config/export",
		    s->id);
		hc.busy = true;
		api("POST", url, "{}", template_cb, strdup(hc.tname));
	} else if (strcmp(act, "input:hc-hostname") == 0)
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
	    (t = server_of(hc.rsid)) != NULL)
		config_pkgs(t, hc.report, "the bundle's packages");
	return (true);
}
