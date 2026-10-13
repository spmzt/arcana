/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's jails made from the page, the way they are kept by hand:
 * the defaults every jail includes (/etc/jail.conf), templates kept
 * beside the jails (<name>.inc in jail.conf.d), and each jail a file of
 * its own that includes them, its dataset made from a base jail's
 * snapshot by a clone or a copy.  The page writes the files' text from
 * its forms; the host checks them with jail(8) and does the rest, a
 * jail-conf job each.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	char		 server[16];
	ucl_object_t	*files;		/* jail-files: defaults, templates, jails */
	ucl_object_t	*snaps;		/* the host's snapshots */
	ucl_object_t	*ifs;		/* its interfaces */
	char		 edit[72];	/* the template edited, "" a new one */
	char		 rm[72];	/* the jail taken away */
	char		 file[72];	/* the jail whose file is changed */
} jm;

static void
jm_reset(struct server *s)
{

	if (strcmp(jm.server, s->id) == 0)
		return;
	snprintf(jm.server, sizeof(jm.server), "%s", s->id);
	if (jm.files != NULL)
		ucl_object_unref(jm.files);
	if (jm.snaps != NULL)
		ucl_object_unref(jm.snaps);
	if (jm.ifs != NULL)
		ucl_object_unref(jm.ifs);
	jm.files = jm.snaps = jm.ifs = NULL;
}

static void
got_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	ucl_object_t	**where = arg;

	(void)err;
	if (status != 200 || jget(o, "data") == NULL)
		return;
	if (*where != NULL)
		ucl_object_unref(*where);
	*where = ucl_object_copy(jget(o, "data"));
	if (app.modal == MODAL_JAIL_NEW || app.modal == MODAL_JAIL_DEFAULTS ||
	    app.modal == MODAL_JAIL_FILES || app.modal == MODAL_JAIL_TEMPLATE)
		render();
}

/* What the forms need, asked of the host again. */
static void
jm_load(struct server *s)
{
	char	url[128];

	jm_reset(s);
	snprintf(url, sizeof(url), "/api/servers/%s/jails/files", s->id);
	api("GET", url, NULL, got_cb, &jm.files);
	snprintf(url, sizeof(url), "/api/servers/%s/storage/snapshots", s->id);
	api("GET", url, NULL, got_cb, &jm.snaps);
	snprintf(url, sizeof(url), "/api/servers/%s/net/interfaces", s->id);
	api("GET", url, NULL, got_cb, &jm.ifs);
}

/* The jails list's buttons. */
void
jailmk_buttons(struct html *h)
{

	h_raw(h, "<span class=\"pane-actions\"><button class=\"ghost small\" "
	    "data-act=\"jm-new\" title=\"A jail of its own file, its dataset "
	    "from a base jail's snapshot\">+ jail</button><button class=\""
	    "ghost small\" data-act=\"jm-defaults\" title=\"/etc/jail.conf, "
	    "what every jail includes\">Defaults</button><button class=\""
	    "ghost small\" data-act=\"jm-files\" title=\"The templates, and "
	    "the jails made from here\">Templates</button></span>");
}

static const char *
dir_of(void)
{

	return (jstr(jm.files, "dir") != NULL ? jstr(jm.files, "dir") :
	    "/etc/jail.conf.d");
}

static const char *
defaults_path(void)
{
	const char	*p = jstr(jget(jm.files, "defaults"), "path");

	return (p != NULL ? p : "/etc/jail.conf");
}

/* A value of the defaults' text, key = "value";, or NULL. */
static bool
defaults_value(const char *key, char *out, size_t len)
{
	const char	*t, *p, *q;
	size_t		 n;

	if ((t = jstr(jget(jm.files, "defaults"), "text")) == NULL)
		return (false);
	n = strlen(key);
	for (p = t; (p = strstr(p, key)) != NULL; p += n) {
		if (p != t && p[-1] != '\n' && p[-1] != '\t' && p[-1] != ' ')
			continue;
		q = p + n;
		while (*q == ' ' || *q == '\t')
			q++;
		if (*q != '=')
			continue;
		q++;
		while (*q == ' ' || *q == '\t')
			q++;
		if (*q == '"')
			q++;
		snprintf(out, len, "%.*s", (int)strcspn(q, "\";\n"), q);
		return (true);
	}
	return (false);
}

static void
datalist_ifs(struct html *h)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it = NULL;

	h_raw(h, "<datalist id=\"jm-ifs\">");
	while ((o = ucl_object_iterate(jget(jm.ifs, "interfaces"), &it, true)) !=
	    NULL) {
		h_raw(h, "<option");
		h_attr(h, "value", jstr(o, "name"));
		h_raw(h, ">");
	}
	h_raw(h, "</datalist>");
}

bool
jailmk_modal(struct html *h)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	char			 v[256], dom[128];
	int			 n;

	switch (app.modal) {
	case MODAL_JAIL_DEFAULTS:
		h_raw(h, "<form data-form=\"jm-defaults\"><h2>The jails' "
		    "defaults</h2><p>Written as <code>");
		h_txt(h, defaults_path());
		h_raw(h, "</code>, which every jail made here includes first; "
		    "<code>${name}</code> is each jail's name. The file there now "
		    "is kept beside it as <code>.arcana.bak</code>, and put back "
		    "if jail(8) does not take the new one.</p>");
		dom[0] = '\0';
		if (defaults_value("host.domainname", v, sizeof(v)))
			snprintf(dom, sizeof(dom), "%s", v);
		h_raw(h, "<label>Domain<input name=\"domain\" spellcheck=\"false\" "
		    "placeholder=\"example.org\" autofocus");
		h_attr(h, "value", dom);
		h_raw(h, "><small>host.hostname is the jail's name in it, "
		    "host.domainname it.</small></label><label>Path<input name=\""
		    "path\" spellcheck=\"false\"");
		h_attr(h, "value", defaults_value("path", v, sizeof(v)) ? v :
		    "/usr/jails/${name}");
		h_raw(h, "></label><label>exec.start<input name=\"start\"");
		h_attr(h, "value", defaults_value("exec.start", v, sizeof(v)) ? v :
		    "/bin/sh /etc/rc");
		h_raw(h, "></label><label>exec.stop<input name=\"stop\"");
		h_attr(h, "value", defaults_value("exec.stop", v, sizeof(v)) ? v :
		    "/bin/sh /etc/rc.shutdown jail");
		h_raw(h, "></label><label>exec.consolelog<input name=\"log\"");
		h_attr(h, "value", defaults_value("exec.consolelog", v, sizeof(v)) ?
		    v : "/var/log/${name}_console.log");
		h_raw(h, "></label><label class=\"toggle\"><input type=\"checkbox\" "
		    "name=\"clean\" checked> exec.clean <small>the jail's commands "
		    "in a clean environment</small></label><label class=\"toggle\">"
		    "<input type=\"checkbox\" name=\"devfs\" checked> mount.devfs"
		    "</label><label>More lines<textarea name=\"more\" rows=\"3\" "
		    "spellcheck=\"false\" placeholder=\"allow.set_hostname = 0;"
		    "\"></textarea></label>");
		if (jstr(jget(jm.files, "defaults"), "text") != NULL) {
			h_raw(h, "<details><summary>The file there now</summary>"
			    "<pre class=\"wg-conf\">");
			h_txt(h, jstr(jget(jm.files, "defaults"), "text"));
			h_raw(h, "</pre></details>");
		}
		return (true);
	case MODAL_JAIL_NEW:
		h_raw(h, "<form data-form=\"jm-new\"><h2>A new jail</h2><p>Its "
		    "own file in <code>");
		h_txt(h, dir_of());
		h_raw(h, "</code>, which includes <code>");
		h_txt(h, defaults_path());
		h_raw(h, "</code>; its dataset made from a base jail's snapshot "
		    "and mounted at its path. The host reads the file back with "
		    "jail(8) before it is kept; what fails is undone.</p>");
		if (jstr(jget(jm.files, "defaults"), "text") == NULL)
			h_raw(h, "<p class=\"notice warn\">The host has no "
			    "defaults yet: <b>Defaults</b> writes them first.</p>");
		datalist_ifs(h);
		h_raw(h, "<label>Name<input name=\"name\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"www\" autofocus></label>"
		    "<label>Base snapshot<select name=\"snapshot\"><option value="
		    "\"\">none: no dataset made</option>");
		it = NULL;
		while ((o = ucl_object_iterate(jget(jm.snaps, "snapshots"), &it,
		    true)) != NULL) {
			h_raw(h, "<option");
			h_attr(h, "value", jstr(o, "name"));
			h_raw(h, ">");
			h_txt(h, jstr(o, "name"));
			h_raw(h, "</option>");
		}
		h_raw(h, "</select><small>Its dataset is the base's sibling, "
		    "<code>&lt;pool&gt;/jails/&lt;name&gt;</code>, unless named "
		    "below.</small></label><fieldset class=\"toggles\"><label "
		    "class=\"toggle\"><input type=\"radio\" name=\"copy\" value=\""
		    "clone\" checked> zfs clone <small>quick, tied to the "
		    "snapshot</small></label><label class=\"toggle\"><input type="
		    "\"radio\" name=\"copy\" value=\"send\"> zfs send | zfs recv "
		    "<small>a copy of its own</small></label></fieldset><label>"
		    "Dataset<input name=\"ds\" spellcheck=\"false\" "
		    "placeholder=\"from the base's\"></label><label>Path<input "
		    "name=\"path\" spellcheck=\"false\" placeholder=\"as the "
		    "defaults say\"><small>Empty: the defaults' path; another "
		    "is written in the jail's block.</small></label>"
		    "<label>IPv4 addresses<textarea name=\"ip4\" rows=\"2\" "
		    "spellcheck=\"false\" placeholder=\"bridge0|172.23.1.43\">"
		    "</textarea><small>An interface and an address a line.</small>"
		    "</label><label>IPv6 addresses<textarea name=\"ip6\" rows=\"2\" "
		    "spellcheck=\"false\" placeholder=\"bridge0.20|2001:db8::443\">"
		    "</textarea></label><label>devfs_ruleset<input name=\"ruleset\" "
		    "inputmode=\"numeric\" placeholder=\"4\"></label><fieldset "
		    "class=\"toggles\"><label class=\"toggle\"><input type=\""
		    "checkbox\" name=\"sysvsem\"> sysvsem = new</label><label "
		    "class=\"toggle\"><input type=\"checkbox\" name=\"sysvshm\"> "
		    "sysvshm = new</label><label class=\"toggle\"><input type=\""
		    "checkbox\" name=\"sysvmsg\"> sysvmsg = new</label><label "
		    "class=\"toggle\"><input type=\"checkbox\" name=\"raw\"> "
		    "allow.raw_sockets</label></fieldset>");
		n = 0;
		it = NULL;
		while ((o = ucl_object_iterate(jget(jm.files, "templates"), &it,
		    true)) != NULL) {
			if (n++ == 0)
				h_raw(h, "<fieldset class=\"toggles\"><legend>"
				    "Templates it includes</legend>");
			h_raw(h, "<label class=\"toggle\"><input type=\"checkbox\" "
			    "name=\"tpl_");
			h_txt(h, jstr(o, "name"));
			h_raw(h, "\"> ");
			h_txt(h, jstr(o, "name"));
			h_raw(h, "</label>");
		}
		if (n > 0)
			h_raw(h, "</fieldset>");
		h_raw(h, "<label>More lines<textarea name=\"more\" rows=\"2\" "
		    "spellcheck=\"false\" placeholder=\"enforce_statfs = 1;\">"
		    "</textarea></label><label class=\"toggle\"><input type=\""
		    "checkbox\" name=\"start\" checked> Start it once made</label>");
		return (true);
	case MODAL_JAIL_FILES:
		h_raw(h, "<form data-form=\"jm-files\"><h2>Templates and jails"
		    "</h2><p>Templates are kept in <code>");
		h_txt(h, dir_of());
		h_raw(h, "</code> as <code>&lt;name&gt;.inc</code>, outside "
		    "rc.d/jail's <code>*.conf</code>; a jail includes those it "
		    "is made with.</p><p class=\"pane-actions\"><button type=\""
		    "button\" class=\"ghost small\" data-act=\"jm-tpl-new\">+ "
		    "template</button></p><table class=\"net\"><thead><tr><th>"
		    "Template</th><th>First line</th><th></th></tr></thead><tbody>");
		n = 0;
		it = NULL;
		while ((o = ucl_object_iterate(jget(jm.files, "templates"), &it,
		    true)) != NULL) {
			const char	*t = jstr(o, "text") != NULL ? jstr(o, "text") :
			    "";

			n++;
			h_raw(h, "<tr><td><b>");
			h_txt(h, jstr(o, "name"));
			h_fmt(h, "</b></td><td class=\"mono\">%.*s</td><td class=\""
			    "acts\"><button type=\"button\" class=\"icon\" data-act="
			    "\"jm-tpl-edit\" title=\"Change it\"", (int)strcspn(t,
			    "\n") > 60 ? 60 : (int)strcspn(t, "\n"), "");
			h_attr(h, "data-arg", jstr(o, "name"));
			h_raw(h, ">&#9998;</button><button type=\"button\" class=\""
			    "icon\" data-act=\"jm-tpl-del\" title=\"Take it away; not "
			    "while a jail includes it\"");
			h_attr(h, "data-arg", jstr(o, "name"));
			h_raw(h, ">×</button></td></tr>");
		}
		if (n == 0)
			h_raw(h, "<tr><td colspan=\"3\" class=\"dim\">None yet."
			    "</td></tr>");
		h_raw(h, "</tbody></table><table class=\"net\"><thead><tr><th>"
		    "Jail file</th><th></th></tr></thead><tbody>");
		n = 0;
		it = NULL;
		while ((o = ucl_object_iterate(jget(jm.files, "jails"), &it,
		    true)) != NULL) {
			n++;
			h_raw(h, "<tr><td><b>");
			h_txt(h, jstr(o, "name"));
			h_raw(h, "</b><small class=\"dim\">.conf</small></td><td "
			    "class=\"acts\"><button type=\"button\" class=\"icon\" "
			    "data-act=\"jm-file-edit\" title=\"Change its file\"");
			h_attr(h, "data-arg", jstr(o, "name"));
			h_raw(h, ">&#9998;</button><button type=\"button\" "
			    "class=\"icon\" data-act=\"jm-rm\" title=\"Stop it and "
			    "take its file "
			    "away, its dataset with it when asked\"");
			h_attr(h, "data-arg", jstr(o, "name"));
			h_raw(h, ">×</button></td></tr>");
		}
		if (n == 0)
			h_raw(h, "<tr><td colspan=\"2\" class=\"dim\">None.</td>"
			    "</tr>");
		h_raw(h, "</tbody></table>");
		return (true);
	case MODAL_JAIL_TEMPLATE: {
		const ucl_object_t	*t = NULL;

		it = NULL;
		while (jm.edit[0] != '\0' && (o = ucl_object_iterate(jget(jm.files,
		    "templates"), &it, true)) != NULL)
			if (jstr(o, "name") != NULL && strcmp(jstr(o, "name"),
			    jm.edit) == 0)
				t = o;
		h_raw(h, "<form data-form=\"jm-template\"><h2>");
		h_raw(h, t != NULL ? "A template, changed" : "A new template");
		h_raw(h, "</h2><p>Lines a jail's block takes, such as a certbot "
		    "one's <code>exec.created +=</code> and <code>exec.poststop "
		    "+=</code>; every jail that includes it is read back with it "
		    "before it is kept.</p><label>Name<input name=\"name\" "
		    "spellcheck=\"false\" placeholder=\"certbot\"");
		h_attr(h, "value", jm.edit);
		h_raw(h, t != NULL ? " readonly" : " autofocus");
		h_raw(h, "></label><label>Lines<textarea name=\"text\" rows=\"8\" "
		    "spellcheck=\"false\">");
		h_txt(h, t != NULL && jstr(t, "text") != NULL ? jstr(t, "text") :
		    "");
		h_raw(h, "</textarea></label>");
		return (true);
	}
	case MODAL_JAIL_FILE: {
		const ucl_object_t	*t = NULL;

		it = NULL;
		while ((o = ucl_object_iterate(jget(jm.files, "jails"), &it,
		    true)) != NULL)
			if (jstr(o, "name") != NULL && strcmp(jstr(o, "name"),
			    jm.file) == 0)
				t = o;
		h_raw(h, "<form data-form=\"jm-file\"><h2>");
		h_txt(h, jm.file);
		h_raw(h, "<small class=\"dim\">.conf</small></h2><p>Read back "
		    "by <code>jail -e</code> as this one jail before it is kept, "
		    "the file before kept beside as <code>.arcana.bak</code>. A "
		    "running jail keeps its path, and takes the rest when it is "
		    "restarted.</p><label>The file<textarea name=\"text\" rows="
		    "\"14\" class=\"mono\" spellcheck=\"false\">");
		h_txt(h, t != NULL && jstr(t, "text") != NULL ? jstr(t, "text") :
		    "");
		h_raw(h, "</textarea></label>");
		return (true);
	}
	case MODAL_JAIL_REMOVE:
		h_raw(h, "<form data-form=\"jm-remove\"><h2>Take away ");
		h_txt(h, jm.rm);
		h_raw(h, "</h2><p>The jail is stopped and its file taken away, "
		    "kept beside as <code>.arcana.bak</code>. Its dataset is "
		    "destroyed only when named here, and only when it is mounted "
		    "at the jail's path.</p><label>Its dataset, to destroy<input "
		    "name=\"ds\" spellcheck=\"false\" placeholder=\"none: "
		    "kept\"></label>");
		return (true);
	default:
		return (false);
	}
}

/* A list as typed, one a line, as jail.conf's lines of key = and +=. */
static void
addrs(struct html *b, const char *key, const char *typed)
{
	const char	*p, *e;
	int		 n;

	n = 0;
	for (p = typed; p != NULL && *p != '\0'; p = *e != '\0' ? e + 1 : e) {
		e = p + strcspn(p, "\n");
		while (p < e && (*p == ' ' || *p == '\r'))
			p++;
		if (e == p)
			continue;
		h_fmt(b, "\t%s %s \"%.*s\";\n", key, n++ == 0 ? "=" : "+=",
		    (int)(e - p - (e[-1] == '\r' ? 1 : 0)), p);
	}
}

static void
lines(struct html *b, const char *typed, const char *indent)
{
	const char	*p, *e;

	for (p = typed; p != NULL && *p != '\0'; p = *e != '\0' ? e + 1 : e) {
		e = p + strcspn(p, "\n");
		if (e > p)
			h_fmt(b, "%s%.*s\n", indent, (int)(e - p - (e[-1] == '\r' ?
			    1 : 0)), p);
	}
}

static bool
name_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || s[0] == '-' || s[0] == '.' ||
	    strlen(s) > 64)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z')
		    || (s[i] >= '0' && s[i] <= '9') || s[i] == '_' || s[i] == '-' ||
		    s[i] == '.'))
			return (false);
	return (true);
}

/* A jail-conf job: the JSON's fields after kind and verb. */
static void
send(struct server *s, const char *title, const char *fmt, ...)
{
	va_list	 ap;
	char	*rest, *json;

	va_start(ap, fmt);
	if (vasprintf(&rest, fmt, ap) == -1)
		abort();
	va_end(ap);
	if (asprintf(&json, "{\"kind\":\"jail-conf\",%s}", rest) == -1)
		abort();
	free(rest);
	job_send_host(s, json, title, JOB_JAIL, "jails");
}

bool
jailmk_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	struct html	 b;
	char		 path[512], ds[300], title[160], *q1, *q2, *q3, *q4, *q5;
	const char	*v, *snap;

	if (strncmp(form, "jm-", 3) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	memset(&b, 0, sizeof(b));
	if (strcmp(form, "jm-files") == 0) {
		app.modal = MODAL_NONE;
		return (true);
	}
	if (strcmp(form, "jm-defaults") == 0) {
		if ((v = jstr(f, "domain")) == NULL || v[0] == '\0' || strchr(v,
		    '"') != NULL) {
			snprintf(app.modal_error, sizeof(app.modal_error), "A "
			    "domain, for the jails' host names");
			return (true);
		}
		h_fmt(&b, "# Written by the Arcana console: what every jail "
		    "includes.\npath = \"%s\";\nhost.hostname = \"${name}.%s\";\n"
		    "host.domainname = \"%s\";\nexec.start = \"%s\";\nexec.stop = "
		    "\"%s\";\nexec.consolelog = \"%s\";\n", jstr(f, "path"), v, v,
		    jstr(f, "start"), jstr(f, "stop"), jstr(f, "log"));
		if (jbool(f, "clean"))
			h_raw(&b, "exec.clean;\n");
		if (jbool(f, "devfs"))
			h_raw(&b, "mount.devfs;\n");
		lines(&b, jstr(f, "more"), "");
		q1 = json_quote(b.s);
		send(s, "jail defaults", "\"verb\":\"defaults\",\"text\":%s", q1);
		free(q1);
		free(b.s);
		app.modal = MODAL_NONE;
		return (true);
	}
	if (strcmp(form, "jm-template") == 0) {
		if (!name_ok(jstr(f, "name"))) {
			snprintf(app.modal_error, sizeof(app.modal_error), "A "
			    "template's name is letters, digits and _ - .");
			return (true);
		}
		q1 = json_quote(jstr(f, "name"));
		q2 = json_quote(jstr(f, "text") != NULL ? jstr(f, "text") : "");
		snprintf(title, sizeof(title), "jail template %s", jstr(f,
		    "name"));
		send(s, title, "\"verb\":\"template\",\"args\":[%s],\"text\":%s",
		    q1, q2);
		free(q1);
		free(q2);
		app.modal = MODAL_NONE;
		return (true);
	}
	if (strcmp(form, "jm-file") == 0) {
		v = jstr(f, "text") != NULL ? jstr(f, "text") : "";
		if (v[strspn(v, " \t\r\n")] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "The "
			    "jail's file: to take it away, use ×");
			return (true);
		}
		q1 = json_quote(jm.file);
		q2 = json_quote(v);
		snprintf(title, sizeof(title), "jail edit %s", jm.file);
		send(s, title, "\"verb\":\"edit\",\"jail\":%s,\"text\":%s", q1,
		    q2);
		free(q1);
		free(q2);
		app.modal = MODAL_NONE;
		return (true);
	}
	if (strcmp(form, "jm-remove") == 0) {
		v = jstr(f, "ds") != NULL ? jstr(f, "ds") : "";
		q1 = json_quote(jm.rm);
		q2 = json_quote(v);
		snprintf(title, sizeof(title), "jail remove %s", jm.rm);
		send(s, title, "\"verb\":\"remove\",\"jail\":%s%s%s", q1, v[0] !=
		    '\0' ? ",\"dataset\":" : "", v[0] != '\0' ? q2 : "");
		free(q1);
		free(q2);
		app.modal = MODAL_NONE;
		return (true);
	}
	/* jm-new: the jail's file, from the form. */
	v = jstr(f, "name");
	if (!name_ok(v)) {
		snprintf(app.modal_error, sizeof(app.modal_error), "A jail's name "
		    "is letters, digits and _ - .");
		return (true);
	}
	snap = jstr(f, "snapshot") != NULL ? jstr(f, "snapshot") : "";
	/* Its path: the form's, else the defaults' with its name. */
	path[0] = '\0';
	if (jstr(f, "path") != NULL && jstr(f, "path")[0] != '\0')
		snprintf(path, sizeof(path), "%s", jstr(f, "path"));
	else if (defaults_value("path", path, sizeof(path))) {
		char	*n;

		if ((n = strstr(path, "${name}")) != NULL) {
			char	tail[512];

			snprintf(tail, sizeof(tail), "%s", n + 7);
			snprintf(n, sizeof(path) - (size_t)(n - path), "%s%s", v,
			    tail);
		}
	} else
		snprintf(path, sizeof(path), "/usr/jails/%s", v);
	/* Its dataset: the form's, else the base's sibling. */
	ds[0] = '\0';
	if (jstr(f, "ds") != NULL && jstr(f, "ds")[0] != '\0')
		snprintf(ds, sizeof(ds), "%s", jstr(f, "ds"));
	else if (snap[0] != '\0') {
		const char	*at = strchr(snap, '@'), *sl;

		sl = NULL;
		for (const char *c = snap; at != NULL && c < at; c++)
			if (*c == '/')
				sl = c;
		if (sl != NULL)
			snprintf(ds, sizeof(ds), "%.*s/%s", (int)(sl - snap), snap,
			    v);
		else if (at != NULL)
			snprintf(ds, sizeof(ds), "%.*s/jails/%s", (int)(at - snap),
			    snap, v);
	}
	h_fmt(&b, "# Written by the Arcana console.\n.include \"%s\";\n\n%s {\n",
	    defaults_path(), v);
	if (jstr(f, "path") != NULL && jstr(f, "path")[0] != '\0')
		h_fmt(&b, "\tpath = \"%s\";\n", path);
	if (jstr(f, "ruleset") != NULL && jstr(f, "ruleset")[0] != '\0')
		h_fmt(&b, "\tdevfs_ruleset = %d;\n", atoi(jstr(f, "ruleset")));
	if (jbool(f, "sysvsem"))
		h_raw(&b, "\tsysvsem = new;\n");
	if (jbool(f, "sysvshm"))
		h_raw(&b, "\tsysvshm = new;\n");
	if (jbool(f, "sysvmsg"))
		h_raw(&b, "\tsysvmsg = new;\n");
	if (jbool(f, "raw"))
		h_raw(&b, "\tallow.raw_sockets;\n");
	addrs(&b, "ip4.addr", jstr(f, "ip4"));
	addrs(&b, "ip6.addr", jstr(f, "ip6"));
	{
		const ucl_object_t	*o;
		ucl_object_iter_t	 it = NULL;
		char			 k[96];

		while ((o = ucl_object_iterate(jget(jm.files, "templates"), &it,
		    true)) != NULL) {
			snprintf(k, sizeof(k), "tpl_%s", jstr(o, "name"));
			if (jbool(f, k))
				h_fmt(&b, "\t.include \"%s/%s.inc\";\n", dir_of(),
				    jstr(o, "name"));
		}
	}
	lines(&b, jstr(f, "more"), "\t");
	h_raw(&b, "}\n");
	q1 = json_quote(v);
	q2 = json_quote(b.s);
	q3 = json_quote(ds);
	q4 = json_quote(snap);
	q5 = json_quote(path);
	snprintf(title, sizeof(title), "jail make %s", v);
	if (snap[0] != '\0')
		send(s, title, "\"verb\":\"make\",\"jail\":%s,\"text\":%s,"
		    "\"dataset\":%s,\"snapshot\":%s,\"copy\":\"%s\",\"path\":%s,"
		    "\"start\":%s", q1, q2, q3, q4, jstr(f, "copy") != NULL &&
		    strcmp(jstr(f, "copy"), "send") == 0 ? "send" : "clone", q5,
		    jbool(f, "start") ? "true" : "false");
	else
		send(s, title, "\"verb\":\"make\",\"jail\":%s,\"text\":%s,"
		    "\"start\":%s", q1, q2, jbool(f, "start") ? "true" : "false");
	free(q1);
	free(q2);
	free(q3);
	free(q4);
	free(q5);
	free(b.s);
	app.modal = MODAL_NONE;
	return (true);
}

bool
jailmk_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 title[160], *q;

	(void)value;
	if (strncmp(act, "jm-", 3) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	app.modal_error[0] = '\0';
	if (strcmp(act, "jm-new") == 0 || strcmp(act, "jm-defaults") == 0 ||
	    strcmp(act, "jm-files") == 0) {
		jm_load(s);
		app.modal = act[3] == 'n' ? MODAL_JAIL_NEW : act[3] == 'd' ?
		    MODAL_JAIL_DEFAULTS : MODAL_JAIL_FILES;
	} else if (strcmp(act, "jm-tpl-new") == 0 || strcmp(act,
	    "jm-tpl-edit") == 0) {
		snprintf(jm.edit, sizeof(jm.edit), "%s", act[7] == 'e' ? arg : "");
		app.modal = MODAL_JAIL_TEMPLATE;
	} else if (strcmp(act, "jm-tpl-del") == 0) {
		q = json_quote(arg);
		snprintf(title, sizeof(title), "jail untemplate %s", arg);
		send(s, title, "\"verb\":\"untemplate\",\"args\":[%s]", q);
		free(q);
		app.modal = MODAL_NONE;
	} else if (strcmp(act, "jm-file-edit") == 0) {
		snprintf(jm.file, sizeof(jm.file), "%s", arg);
		app.modal = MODAL_JAIL_FILE;
	} else if (strcmp(act, "jm-rm") == 0) {
		snprintf(jm.rm, sizeof(jm.rm), "%s", arg);
		app.modal = MODAL_JAIL_REMOVE;
	}
	return (true);
}
