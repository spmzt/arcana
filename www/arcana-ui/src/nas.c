/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Storage page: a host's network storage services, the base
 * system's, a tab each.  NFS, v4 alone: nfsd(8) and mountd(8),
 * exports(5) with its V4: root on ZFS, the datasets that share
 * themselves (sharenfs), NFSv4 up to 4.2 and pNFS (pnfsserver(4)).  iSCSI: the target, ctld(8) and
 * ctl.conf(5), its LUNs and sessions by ctladm(8).  HAST: hastd(8) and
 * hast.conf(5), its resources' roles by hastctl(8).  A host at a time
 * (GET /api/servers/<id>/netstore); each change a job of the nfs, iscsi
 * or hast kind.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "app.h"

enum nastab { NAS_NFS, NAS_ISCSI, NAS_HAST };

static const char *const tabs[] = { "nfs", "iscsi", "hast" };

static struct {
	enum nastab	 tab;
	struct res	 r;		/* the netstore read */
	bool		 target;	/* the iSCSI target form open */
} nas;

static void
nas_load_of(const char *sid)
{
	char	url[96];

	snprintf(url, sizeof(url), "/api/servers/%s/netstore", sid);
	res_load(&nas.r, sid, url);
}

static void
nas_load(void)
{

	nas_load_of(nas.r.sid);
}

static struct server *
nas_server(void)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, nas.r.sid) == 0)
			return (&app.servers[i]);
	return (NULL);
}

/* A job on the page's host, its words and text, the page read again
 * when it ends. */
static void
nas_job(const char *kind, const char *verb, const char *const *words,
    size_t n, const char *text, const char *title)
{
	struct server	*s;
	struct queued	 q;
	char		*json, *t, *qw;
	size_t		 i;

	if ((s = nas_server()) == NULL)
		return;
	if (asprintf(&json, "{\"kind\":\"%s\",\"verb\":\"%s\",\"args\":[",
	    kind, verb) == -1)
		abort();
	for (i = 0; i < n; i++) {
		qw = json_quote(words[i]);
		if (asprintf(&t, "%s%s%s", json, i > 0 ? "," : "", qw) == -1)
			abort();
		free(json);
		free(qw);
		json = t;
	}
	if (text != NULL) {
		qw = json_quote(text);
		if (asprintf(&t, "%s],\"text\":%s}", json, qw) == -1)
			abort();
		free(qw);
	} else if (asprintf(&t, "%s]}", json) == -1)
		abort();
	free(json);
	memset(&q, 0, sizeof(q));
	q.json = t;
	snprintf(q.title, sizeof(q.title), "%s", title);
	snprintf(q.sid, sizeof(q.sid), "%s", s->id);
	snprintf(q.host, sizeof(q.host), "%s", s->name);
	q.what = JOB_NETSTORE;
	job_send_many(s, &q, 1, JOB_NETSTORE);
}

static void
state_chips(struct html *h, const ucl_object_t *o, const char *svc,
    const char *name)
{
	char	run[40], en[40];

	snprintf(run, sizeof(run), "%s_running", svc);
	snprintf(en, sizeof(en), "%s_enabled", svc);
	h_fmt(h, "<span class=\"chip %s\">%s %s</span> ", jbool(o, run) ?
	    "st-up" : "st-down", name, jbool(o, run) ? "running" : "stopped");
	if (!jbool(o, en))
		h_raw(h, "<small class=\"dim\">not enabled at boot</small> ");
}

static void
pre(struct html *h, const char *title, const char *text)
{

	if (text == NULL || text[0] == '\0')
		return;
	h_raw(h, "<h4>");
	h_txt(h, title);
	h_raw(h, "</h4><pre class=\"mono naspre\">");
	h_txt(h, text);
	h_raw(h, "</pre>");
}

static bool
yes(const char *v)
{

	return (v != NULL && (strcasecmp(v, "YES") == 0 || strcasecmp(v,
	    "TRUE") == 0 || strcasecmp(v, "ON") == 0 || strcmp(v, "1") == 0));
}

static void
view_nfs(struct html *h, const ucl_object_t *o)
{
	static const struct tcol cols[] = {
		{ "Dataset", "dataset", false },
		{ "Mounted at", "mountpoint", false },
		{ "sharenfs", "sharenfs", false },
	};
	const ucl_object_t	**rows, *r;
	const char		*minor;
	int			 i, k;

	h_raw(h, "<p>");
	state_chips(h, o, "nfsd", "nfsd");
	state_chips(h, o, "mountd", "mountd");
	h_raw(h, "</p><form class=\"secform\" data-form=\"nas-nfs\"><h4>The "
	    "server</h4><div class=\"rowform\"><label class=\"check\"><input "
	    "type=\"checkbox\" name=\"enable\"");
	if (yes(jstr(o, "nfs_server_enable")) || jbool(o, "nfsd_enabled"))
		h_raw(h, " checked");
	h_raw(h, "> Serves NFS <small class=\"help\">nfsd, NFSv4 alone "
	    "(nfsv4_server_only: no NFSv3, no rpcbind), mountd for the "
	    "exports</small></label></div><div class=\""
	    "rowform\"><label>NFSv4 up to <select name=\"minor\">");
	minor = jget(o, "max_minorversion") != NULL ? NULL : "2";
	for (i = 0; i <= 2; i++)
		h_fmt(h, "<option value=\"%d\"%s>4.%d%s</option>", i,
		    (minor != NULL && i == 2) || (minor == NULL && jint(o,
		    "max_minorversion", 2) == i) ? " selected" : "", i, i == 2 ?
		    " (copy_file_range, sparse files, server-side copy)" : "");
	h_raw(h, "</select><small class=\"help\">vfs.nfsd.server_max_"
	    "minorversion</small></label><label>Threads <input name=\""
	    "threads\" type=\"number\" min=\"1\" max=\"256\"");
	h_attr(h, "value", jstr(o, "threads") != NULL ? jstr(o, "threads") :
	    "");
	h_raw(h, " placeholder=\"4\"></label></div><div class=\"rowform\">"
	    "<label>pNFS data servers <input name=\"pnfs\" spellcheck=\"false\" "
	    "placeholder=\"ds1:/DSstore0,ds2:/DSstore1\"");
	h_attr(h, "value", jstr(o, "pnfs") != NULL ? jstr(o, "pnfs") : "");
	h_raw(h, "><small class=\"help\">this host the metadata server "
	    "(pnfsserver(4)): each data server an NFSv4.1+ server exporting "
	    "its directory to it; the clients read and write files there "
	    "directly</small></label><label>Mirrors <input name=\"mirror\" "
	    "type=\"number\" min=\"2\" max=\"8\"");
	h_attr(h, "value", jstr(o, "mirror") != NULL ? jstr(o, "mirror") : "");
	h_raw(h, " placeholder=\"none\"><small class=\"help\">each file on so "
	    "many data servers</small></label></div><div class=\"actions\">"
	    "<button type=\"submit\" class=\"primary\">Save</button></div>"
	    "</form><form class=\"secform\" data-form=\"nas-exports\"><h4>");
	h_txt(h, jstr(o, "exports_path") != NULL ? jstr(o, "exports_path") :
	    "exports");
	h_raw(h, "</h4>");
	/* NFSv4's root, a directory on ZFS: the agent checks it. */
	if (jstr(o, "v4root") != NULL) {
		h_raw(h, "<p class=\"help\">NFSv4 root <code>");
		h_txt(h, jstr(o, "v4root"));
		h_raw(h, "</code>: ");
		h_txt(h, jbool(o, "v4root_zfs") ? "on ZFS" : jstr(o,
		    "v4root_error") != NULL ? jstr(o, "v4root_error") :
		    "not on ZFS");
		h_raw(h, "</p>");
	} else
		h_raw(h, "<p class=\"help\">No V4: line yet: NFSv4 alone serves "
		    "nothing until its root, a directory on ZFS, is named.</p>");
	h_raw(h, "<label class=\"wide\">What it exports <textarea name=\"text\" rows=\"8\" "
	    "spellcheck=\"false\" placeholder=\"V4: /export -sec=sys\n"
	    "/export/home -maproot=root -network 10.0.0.0/24\">");
	h_txt(h, jstr(o, "exports"));
	h_raw(h, "</textarea><small class=\"help\">exports(5): first the "
	    "V4: line, NFSv4's root, a directory on ZFS (the agent refuses "
	    "any other); then a line a directory and who may mount it. "
	    "Datasets share themselves below instead.</small>"
	    "</label><div class=\"actions\"><button type=\"submit\" class=\""
	    "primary\">Save and tell mountd</button></div></form>");
	/* The datasets that share themselves: sharenfs, which zfs writes
	 * to /etc/zfs/exports for mountd. */
	h_raw(h, "<h4>ZFS shares</h4>");
	if (jget(o, "shares") != NULL && ucl_array_size(jget(o, "shares")) >
	    0) {
		tbl_head(h, "nfsshares", cols, 3, 1);
		h_raw(h, "<tbody>");
		rows = tbl_rows("nfsshares", jget(o, "shares"), cols, 3, "");
		for (k = 0; (r = rows[k]) != NULL; k++) {
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(r, "dataset"));
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(r, "mountpoint"));
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(r, "sharenfs"));
			h_raw(h, "</td><td><button class=\"ghost small danger\" "
			    "data-act=\"nas-unshare\"");
			h_attr(h, "data-arg", jstr(r, "dataset"));
			h_raw(h, ">Stop sharing</button></td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table>");
	} else
		h_raw(h, "<p class=\"help\">No dataset shares itself. A "
		    "dataset's sharenfs (zfsprops(7)) exports its mountpoint: "
		    "zfs writes /etc/zfs/exports, which mountd reads beside "
		    "exports(5), and tells mountd itself.</p>");
	h_raw(h, "<form class=\"secform\" data-form=\"nas-share\"><div class=\""
	    "rowform\"><label>Dataset <input name=\"dataset\" spellcheck=\""
	    "false\" placeholder=\"zroot/export/home\" required></label>"
	    "<label>sharenfs <input name=\"sharenfs\" spellcheck=\"false\" "
	    "placeholder=\"on, or -maproot=root -network 10.0.0.0/24\">"
	    "</label></div><small class=\"help\">zfs set sharenfs=...: on "
	    "for everyone, or exports(5) options</small><div class=\"actions\">"
	    "<button type=\"submit\" class=\"primary\">Share</button></div>"
	    "</form>");
	pre(h, "Exported now (showmount -e)", jstr(o, "exported"));
}

static void
view_iscsi(struct html *h, const ucl_object_t *o)
{

	h_raw(h, "<p>");
	state_chips(h, o, "ctld", "ctld");
	h_fmt(h, "<button class=\"ghost small\" data-act=\"nas-ctld\" "
	    "data-arg=\"%s\">%s</button></p>", jbool(o, "ctld_running") ? "no" :
	    "yes", jbool(o, "ctld_running") ? "Stop the target" : "Enable and "
	    "start the target");
	h_raw(h, "<div class=\"toolbar\"><span class=\"grow\"></span><button "
	    "class=\"ghost\" data-act=\"nas-target\">A target</button></div>");
	if (nas.target)
		h_raw(h, "<form class=\"secform\" data-form=\"nas-target\"><h4>A "
		    "target, added to ctl.conf</h4><div class=\"rowform\"><label>"
		    "Name <input name=\"iqn\" required spellcheck=\"false\" "
		    "placeholder=\"iqn.2026-10.org.example:vol0\"></label><label>"
		    "Its LUN 0 <input name=\"path\" required spellcheck=\"false\" "
		    "placeholder=\"/dev/zvol/tank/vol0\"><small class=\"help\">a "
		    "ZFS volume, a disk or a file</small></label></div><div "
		    "class=\"rowform\"><label>Listens on <input name=\"listen\" "
		    "spellcheck=\"false\" value=\"0.0.0.0\"></label><label>CHAP "
		    "user <input name=\"user\" spellcheck=\"false\" placeholder="
		    "\"none: no authentication\"></label><label>CHAP secret <input "
		    "name=\"secret\" type=\"password\" autocomplete=\"off\" "
		    "minlength=\"12\" maxlength=\"16\"><small class=\"help\">12 to "
		    "16 characters</small></label></div><div class=\"actions\">"
		    "<button type=\"button\" class=\"ghost\" data-act=\"nas-cancel\">"
		    "Cancel</button><button type=\"submit\" class=\"primary\">Add"
		    "</button></div></form>");
	h_raw(h, "<form class=\"secform\" data-form=\"nas-ctl\"><h4>");
	h_txt(h, jstr(o, "conf_path") != NULL ? jstr(o, "conf_path") :
	    "ctl.conf");
	h_raw(h, "</h4><label class=\"wide\">Portal groups, auth groups, "
	    "targets and their "
	    "LUNs <textarea name=\"text\" rows=\"12\" spellcheck=\"false\">");
	h_txt(h, jstr(o, "conf"));
	h_raw(h, "</textarea><small class=\"help\">ctl.conf(5), root's alone "
	    "(CHAP secrets); ctld reads it again on saving</small></label><div "
	    "class=\"actions\"><button type=\"submit\" class=\"primary\">Save"
	    "</button></div></form>");
	pre(h, "LUNs (ctladm devlist)", jstr(o, "luns"));
	pre(h, "Sessions (ctladm islist)", jstr(o, "sessions"));
	pre(h, "Ports (ctladm portlist)", jstr(o, "ports"));
}

/* Its resources, as hast.conf names them. */
static int
resources(const char *conf, char names[16][65])
{
	const char	*p;
	int		 n;
	size_t		 k;

	n = 0;
	for (p = conf; p != NULL && (p = strstr(p, "resource ")) != NULL &&
	    n < 16; p += 9) {
		if (p != conf && p[-1] != '\n' && p[-1] != ' ' && p[-1] != '\t')
			continue;
		k = strspn(p + 9, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS"
		    "TUVWXYZ0123456789_-.");
		if (k == 0 || k > 64)
			continue;
		snprintf(names[n++], 65, "%.*s", (int)k, p + 9);
	}
	return (n);
}

static void
view_hast(struct html *h, const ucl_object_t *o)
{
	char	names[16][65];
	int	n, i;

	h_raw(h, "<p>");
	state_chips(h, o, "hastd", "hastd");
	h_fmt(h, "<button class=\"ghost small\" data-act=\"nas-hastd\" "
	    "data-arg=\"%s\">%s</button></p>", jbool(o, "hastd_running") ?
	    "no" : "yes", jbool(o, "hastd_running") ? "Stop hastd" : "Enable "
	    "and start hastd");
	n = resources(jstr(o, "conf"), names);
	if (n > 0) {
		h_raw(h, "<table class=\"net hastres\"><thead><tr><th>Resource"
		    "</th><th></th></tr></thead><tbody>");
		for (i = 0; i < n; i++) {
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, names[i]);
			h_raw(h, "</td><td class=\"acts\">");
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "nas-role\" data-arg=\"%s\" data-value=\"primary\">"
			    "Primary</button><button class=\"ghost small\" "
			    "data-act=\"nas-role\" data-arg=\"%s\" data-value=\""
			    "secondary\">Secondary</button><button class=\"ghost "
			    "small\" data-act=\"nas-role\" data-arg=\"%s\" "
			    "data-value=\"init\">Init</button><button class=\""
			    "ghost small danger\" data-act=\"nas-create\" "
			    "data-arg=\"%s\">Create</button></td></tr>", names[i],
			    names[i], names[i], names[i]);
		}
		h_raw(h, "</tbody></table>");
	}
	h_raw(h, "<form class=\"secform\" data-form=\"nas-hast\"><h4>");
	h_txt(h, jstr(o, "conf_path") != NULL ? jstr(o, "conf_path") :
	    "hast.conf");
	h_raw(h, "</h4><label class=\"wide\">Its resources <textarea name=\"text\" rows=\"10\" "
	    "spellcheck=\"false\" placeholder=\"resource shared {\n\ton a {\n"
	    "\t\tlocal /dev/ada1\n\t\tremote 10.0.0.2\n\t}\n\ton b {\n\t\t"
	    "local /dev/ada1\n\t\tremote 10.0.0.1\n\t}\n}\">");
	h_txt(h, jstr(o, "conf"));
	h_raw(h, "</textarea><small class=\"help\">hast.conf(5), the same on "
	    "both nodes: each resource a provider replicated to the other "
	    "node; /dev/hast/NAME on the primary</small></label><div class=\""
	    "actions\"><button type=\"submit\" class=\"primary\">Save</button>"
	    "</div></form>");
	pre(h, "Status (hastctl status)", jstr(o, "status"));
	pre(h, "Resources (hastctl list)", jstr(o, "list"));
}

void
view_naspage(struct html *h)
{
	static const char *const names[] = { "NFS", "iSCSI", "HAST" };
	static const char *const titles[] = {
	    "nfsd(8): exports, NFSv4.2 and pNFS",
	    "ctld(8): an iSCSI target and its LUNs",
	    "hastd(8): a disk replicated to another host" };
	size_t	i;
	int	k;

	h_raw(h, "<section class=\"secpage naspage\"><div class=\"sechead\">"
	    "<label class=\"secpick\">Host <select data-input=\"nas-host\">");
	if (nas.r.sid[0] == '\0')
		h_raw(h, "<option value=\"\" selected>choose…</option>");
	for (k = 0; k < app.nservers; k++) {
		h_raw(h, "<option");
		h_attr(h, "value", app.servers[k].id);
		if (strcmp(app.servers[k].id, nas.r.sid) == 0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, app.servers[k].name);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label></div><nav class=\"tabs\">");
	for (i = 0; i < nitems(names); i++)
		h_fmt(h, "<button class=\"tab%s\" data-act=\"nas-tab\" data-arg="
		    "\"%s\" title=\"%s\">%s</button>", (size_t)nas.tab == i ?
		    " on" : "", tabs[i], titles[i], names[i]);
	h_raw(h, "</nav>");
	if (nas.r.sid[0] == '\0') {
		h_raw(h, "<div class=\"empty\"><p>Choose a host.</p><p class=\""
		    "dim\">Its NFS server, iSCSI target and HAST: FreeBSD's "
		    "own, nothing to install.</p></div></section>");
		return;
	}
	if (nas.r.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, nas.r.error);
		h_raw(h, " <button class=\"ghost small\" data-act=\"nas-retry\">"
		    "Try again</button></div>");
	}
	if (nas.r.o == NULL) {
		if (!nas.r.loading)
			nas_load();
		h_raw(h, "<div class=\"loader\"></div></section>");
		return;
	}
	switch (nas.tab) {
	case NAS_NFS:
		view_nfs(h, jget(nas.r.o, "nfs"));
		break;
	case NAS_ISCSI:
		view_iscsi(h, jget(nas.r.o, "iscsi"));
		break;
	case NAS_HAST:
		view_hast(h, jget(nas.r.o, "hast"));
		break;
	}
	h_raw(h, "</section>");
}

static bool
cfg_word(const char *v)
{

	return (v != NULL && v[0] != '\0' && strspn(v,
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	    "._:/-") == strlen(v));
}

bool
naspage_form(const char *form, const ucl_object_t *f)
{
	const char	*words[8];
	char		*w[8], *text;
	size_t		 n, i;

	if (strcmp(form, "nas-exports") == 0) {
		nas_job("nfs", "exports", NULL, 0, jstr(f, "text") != NULL ?
		    jstr(f, "text") : "", "nfs exports");
		return (true);
	}
	if (strcmp(form, "nas-ctl") == 0) {
		nas_job("iscsi", "conf", NULL, 0, jstr(f, "text") != NULL ?
		    jstr(f, "text") : "", "iscsi conf");
		return (true);
	}
	if (strcmp(form, "nas-hast") == 0) {
		nas_job("hast", "conf", NULL, 0, jstr(f, "text") != NULL ?
		    jstr(f, "text") : "", "hast conf");
		return (true);
	}
	if (strcmp(form, "nas-share") == 0) {
		if (jstr(f, "dataset") == NULL || jstr(f, "dataset")[0] == '\0')
			return (true);
		if (asprintf(&w[0], "dataset=%s", jstr(f, "dataset")) == -1 ||
		    asprintf(&w[1], "sharenfs=%s", jstr(f, "sharenfs") != NULL &&
		    jstr(f, "sharenfs")[0] != '\0' ? jstr(f, "sharenfs") : "on")
		    == -1)
			abort();
		words[0] = w[0];
		words[1] = w[1];
		nas_job("nfs", "share", words, 2, NULL, "nfs share");
		free(w[0]);
		free(w[1]);
		return (true);
	}
	if (strcmp(form, "nas-nfs") == 0) {
		n = 0;
		if (asprintf(&w[n++], "enable=%s", jbool(f, "enable") ? "yes" :
		    "no") == -1 || asprintf(&w[n++],
		    "minor=%s", jstr(f, "minor") != NULL ? jstr(f, "minor") :
		    "2") == -1)
			abort();
		if (jstr(f, "threads") != NULL && jstr(f, "threads")[0] != '\0' &&
		    asprintf(&w[n++], "threads=%s", jstr(f, "threads")) == -1)
			abort();
		if (jstr(f, "pnfs") != NULL && asprintf(&w[n++], "pnfs=%s",
		    jstr(f, "pnfs")) == -1)
			abort();
		if (jstr(f, "mirror") != NULL && jstr(f, "mirror")[0] != '\0' &&
		    asprintf(&w[n++], "mirror=%s", jstr(f, "mirror")) == -1)
			abort();
		for (i = 0; i < n; i++)
			words[i] = w[i];
		nas_job("nfs", "server", words, n, NULL, "nfs server");
		for (i = 0; i < n; i++)
			free(w[i]);
		return (true);
	}
	if (strcmp(form, "nas-target") == 0) {
		const ucl_object_t	*o = jget(nas.r.o, "iscsi");
		const char		*conf = jstr(o, "conf");
		const char		*user = jstr(f, "user");
		bool			 chap;

		chap = user != NULL && user[0] != '\0';
		if (!cfg_word(jstr(f, "iqn")) || !cfg_word(jstr(f, "path")) ||
		    !cfg_word(jstr(f, "listen")) || (chap && (!cfg_word(user) ||
		    jstr(f, "secret") == NULL || strlen(jstr(f, "secret")) < 12 ||
		    strlen(jstr(f, "secret")) > 16 || strpbrk(jstr(f, "secret"),
		    "\"\\\n") != NULL))) {
			toast(true, "A target needs its name, its LUN's path and "
			    "where it listens; CHAP a user and a secret of 12 to "
			    "16 characters");
			return (true);
		}
		/* Its portal group and auth group, named after it (two
		 * targets on one address would else name one group twice),
		 * then the target. */
		if (asprintf(&text, "%s%s%sportal-group pg-%s {\n\tdiscovery-auth-"
		    "group no-authentication\n\tlisten %s\n}\n\n%sauth-group "
		    "ag-%s {\n%s%s%s%s%s}\n\ntarget %s {\n\tauth-group ag-%s\n"
		    "\tportal-group pg-%s\n\tlun 0 {\n\t\tpath %s\n\t}\n}\n",
		    conf != NULL ? conf : "", conf != NULL && conf[0] != '\0' &&
		    conf[strlen(conf) - 1] != '\n' ? "\n" : "", conf != NULL &&
		    conf[0] != '\0' ? "\n" : "", jstr(f, "iqn"), jstr(f,
		    "listen"), "", jstr(f, "iqn"), chap ? "\tchap " : "\tauth-type "
		    "none", chap ? user : "", chap ? " \"" : "", chap ? jstr(f,
		    "secret") : "", chap ? "\"\n" : "\n", jstr(f, "iqn"), jstr(f,
		    "iqn"), jstr(f, "iqn"), jstr(f, "path")) == -1)
			abort();
		nas_job("iscsi", "conf", NULL, 0, text, "iscsi conf");
		free(text);
		nas.target = false;
		return (true);
	}
	return (false);
}

bool
naspage_action(const char *act, const char *arg, const char *value)
{
	const char	*words[2];
	char		*w[2], title[160];
	size_t		 i;

	if (strcmp(act, "select-storage") == 0) {
		app.node = NODE_STORAGE;
		app.jail[0] = '\0';
		app.rail_open = false;
		if (nas.r.sid[0] == '\0' && app.nservers == 1)
			snprintf(nas.r.sid, sizeof(nas.r.sid), "%s",
			    app.servers[0].id);
		nas_load();
		render();
		return (true);
	}
	if (strcmp(act, "input:nas-host") == 0) {
		snprintf(nas.r.sid, sizeof(nas.r.sid), "%s", value != NULL ? value :
		    "");
		if (nas.r.o != NULL)
			ucl_object_unref(nas.r.o);
		nas.r.o = NULL;
		nas.r.error[0] = '\0';
		nas.target = false;
		nas_load();
		render();
		return (true);
	}
	if (strncmp(act, "nas-", 4) != 0)
		return (false);
	if (strcmp(act, "nas-tab") == 0) {
		for (i = 0; i < nitems(tabs); i++)
			if (strcmp(arg, tabs[i]) == 0)
				nas.tab = (enum nastab)i;
	} else if (strcmp(act, "nas-retry") == 0) {
		if (nas.r.o != NULL)
			ucl_object_unref(nas.r.o);
		nas.r.o = NULL;
		nas_load();
	} else if (strcmp(act, "nas-unshare") == 0) {
		char	body[200];

		snprintf(body, sizeof(body), "sharenfs is set off on %s: "
		    "zfs takes it out of /etc/zfs/exports and tells mountd; "
		    "whoever has it mounted loses it.", arg);
		confirm("Stop sharing?", body, "Stop sharing", true, NULL,
		    "nas-unshare-yes", arg, "");
		return (true);
	} else if (strcmp(act, "nas-unshare-yes") == 0) {
		if (asprintf(&w[0], "dataset=%s", arg) == -1)
			abort();
		words[0] = w[0];
		words[1] = "sharenfs=off";
		nas_job("nfs", "share", words, 2, NULL, "nfs share");
		free(w[0]);
	} else if (strcmp(act, "nas-target") == 0)
		nas.target = true;
	else if (strcmp(act, "nas-cancel") == 0)
		nas.target = false;
	else if ((strcmp(act, "nas-ctld") == 0 || strcmp(act, "nas-hastd") ==
	    0) && strcmp(arg, "no") == 0) {
		/* Stopping drops every session: asked first. */
		confirm(strcmp(act, "nas-ctld") == 0 ? "Stop the target?" :
		    "Stop hastd?", strcmp(act, "nas-ctld") == 0 ? "ctld is "
		    "stopped and disabled: every initiator's session ends, and "
		    "its LUNs are gone until it is started." : "hastd is stopped "
		    "and disabled: the resources stop replicating, and the "
		    "primary's /dev/hast/* go away.", "Stop", true, NULL,
		    strcmp(act, "nas-ctld") == 0 ? "nas-ctld-yes" : "nas-hastd-yes",
		    "no", "");
		return (true);
	} else if (strcmp(act, "nas-ctld") == 0 || strcmp(act, "nas-hastd") ==
	    0 || strcmp(act, "nas-ctld-yes") == 0 || strcmp(act,
	    "nas-hastd-yes") == 0) {
		if (asprintf(&w[0], "enable=%s", arg) == -1)
			abort();
		words[0] = w[0];
		nas_job(strncmp(act, "nas-ctld", 8) == 0 ? "iscsi" : "hast",
		    "enable", words, 1, NULL, strncmp(act, "nas-ctld", 8) == 0 ?
		    "iscsi enable" : "hast enable");
		free(w[0]);
	} else if (strcmp(act, "nas-role") == 0) {
		char	body[300];

		/* A role is the pair's: two primaries split the data. */
		snprintf(body, sizeof(body), "%s becomes %s on this host. The "
		    "other host must be the other role: two primaries write "
		    "apart, and init forgets what was replicated.", arg,
		    value != NULL ? value : "");
		confirm("Change the role?", body, "Change", true,
		    value != NULL && strcmp(value, "secondary") != 0 ? arg :
		    NULL, "nas-role-yes", arg, value != NULL ? value : "");
		return (true);
	} else if (strcmp(act, "nas-role-yes") == 0) {
		if (asprintf(&w[0], "resource=%s", arg) == -1 || asprintf(&w[1],
		    "role=%s", value != NULL ? value : "") == -1)
			abort();
		words[0] = w[0];
		words[1] = w[1];
		snprintf(title, sizeof(title), "hast role %s", arg);
		nas_job("hast", "role", words, 2, NULL, title);
		free(w[0]);
		free(w[1]);
	} else if (strcmp(act, "nas-create") == 0) {
		char	body[300];

		snprintf(body, sizeof(body), "hastctl create %s writes its "
		    "metadata on its provider: what the provider holds is "
		    "lost.", arg);
		confirm("Create the resource?", body, "Create", true, arg,
		    "nas-create-yes", arg, nas.r.sid);
		return (true);
	} else if (strcmp(act, "nas-create-yes") == 0) {
		/* On the host it was asked of, not one picked meanwhile. */
		if (value == NULL || strcmp(value, nas.r.sid) != 0) {
			toast(true, "The host changed: ask again");
			render();
			return (true);
		}
		if (asprintf(&w[0], "resource=%s", arg) == -1)
			abort();
		words[0] = w[0];
		snprintf(title, sizeof(title), "hast create %s", arg);
		nas_job("hast", "create", words, 1, NULL, title);
		free(w[0]);
	}
	render();
	return (true);
}

/* "#/storage[/tab[/host]]" */
void
naspage_loc(char *buf, size_t len)
{

	snprintf(buf, len, "#/storage/%s%s%s", tabs[nas.tab], nas.r.sid[0] !=
	    '\0' ? "/" : "", nas.r.sid);
}

void
naspage_open(const char *rest)
{
	char	tab[16];
	size_t	i;

	snprintf(tab, sizeof(tab), "%.*s", (int)strcspn(rest, "/"), rest);
	for (i = 0; i < nitems(tabs); i++)
		if (strcmp(tab, tabs[i]) == 0)
			nas.tab = (enum nastab)i;
	rest += strcspn(rest, "/");
	if (*rest == '/' && strcmp(rest + 1, nas.r.sid) != 0) {
		snprintf(nas.r.sid, sizeof(nas.r.sid), "%.15s", rest + 1);
		if (nas.r.o != NULL)
			ucl_object_unref(nas.r.o);
		nas.r.o = NULL;
		nas_load();
	}
}

/* After a job of its own: the host read again. */
void
naspage_refresh(void)
{

	nas_load();
}
