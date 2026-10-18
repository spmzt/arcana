/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Builder page: poudriere(8), a host's package builder, a plugin.
 * Jails: the build jails, made, updated and deleted, and poudriere.conf.
 * Ports: the ports trees.  Bulk: a build of some ports in a jail with a
 * tree and a set, each make.conf, the latest builds, the repositories
 * they fill.  A host at a time, as GET /api/servers/<id>/builder reads
 * it; a change is a poudriere job.  What takes long (a jail or a tree
 * made or updated, a build) is a run the job starts and leaves: its
 * output is read with the rest, every few seconds while one runs.
 *
 * Debug symbols are a set's make.conf: WITH_DEBUG_PORTS lists the ports
 * built unstripped, with -g (bsd.port.mk), into the set's own
 * repository, apart from the others'.  The build form writes it before
 * the build, the two jobs one batch.
 */

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"

enum bldtab { BLD_JAILS, BLD_PORTS, BLD_BULK };
enum bldform { BF_NONE, BF_JAIL, BF_PORTS, BF_CONF, BF_MAKECONF };

static struct {
	enum bldtab	 tab;
	char		 sid[16];
	ucl_object_t	*state;		/* the host's builder read */
	bool		 loading;
	char		 error[256];
	enum bldform	 form;
	char		 makeconf[80];	/* the make.conf the editor has */
	bool		 newmc;		/* a new one, named in the form */
	bool		 busy;
	/* A port's options, as builder/options read them. */
	ucl_object_t	*opts;
	char		 optq[512];	/* their query, to read them again */
	bool		 optloading;
	char		 opterr[256];
} bld;

static const char *const tabs[] = { "jails", "ports", "bulk" };

static void
bld_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid = arg;

	if (strcmp(sid, bld.sid) != 0) {
		free(sid);
		return;
	}
	free(sid);
	bld.loading = false;
	if (status != 200) {
		snprintf(bld.error, sizeof(bld.error), "%s", err != NULL ? err :
		    jstr(o, "error") != NULL ? jstr(o, "error") :
		    "the host did not answer");
		render();
		return;
	}
	bld.error[0] = '\0';
	if (jstr(o, "error") != NULL && jget(o, "data") == NULL)
		snprintf(bld.error, sizeof(bld.error), "%s", jstr(o, "error"));
	if (bld.state != NULL)
		ucl_object_unref(bld.state);
	bld.state = jget(o, "data") != NULL ? ucl_object_copy(jget(o,
	    "data")) : ucl_object_typed_new(UCL_OBJECT);
	render();
}

static void
bld_load(void)
{
	char	url[96], *sid;

	if (bld.sid[0] == '\0' || bld.loading)
		return;
	if ((sid = strdup(bld.sid)) == NULL)
		abort();
	snprintf(url, sizeof(url), "/api/servers/%s/builder", bld.sid);
	bld.loading = true;
	api("GET", url, NULL, bld_cb, sid);
}

static void
opts_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	bld.optloading = false;
	if (bld.opts != NULL)
		ucl_object_unref(bld.opts);
	bld.opts = NULL;
	if (status != 200 || jget(o, "data") == NULL)
		snprintf(bld.opterr, sizeof(bld.opterr), "%s", err != NULL ? err :
		    jstr(o, "error") != NULL ? jstr(o, "error") :
		    "the host did not answer");
	else {
		bld.opterr[0] = '\0';
		bld.opts = ucl_object_copy(jget(o, "data"));
	}
	render();
}

static void
opts_load(void)
{
	char	url[640];

	if (bld.sid[0] == '\0' || bld.optq[0] == '\0')
		return;
	snprintf(url, sizeof(url), "/api/servers/%s/builder/options?%s",
	    bld.sid, bld.optq);
	bld.optloading = true;
	api("GET", url, NULL, opts_cb, NULL);
}

/* After a job of the page's: read again, a port's options too. */
void
builder_refresh(void)
{

	bld.busy = false;
	bld_load();
	if (bld.opts != NULL)
		opts_load();
}

static struct server *
bld_server(void)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, bld.sid) == 0)
			return (&app.servers[i]);
	return (NULL);
}

/* A poudriere job: its verb, its key=value words, a make.conf's text. */
static char *
pd_job(const char *verb, ucl_object_t *args, const char *text)
{
	ucl_object_t	*o;
	char		*json;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring("poudriere"), "kind",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(verb), "verb", 0,
	    false);
	ucl_object_insert_key(o, args != NULL ? args :
	    ucl_object_typed_new(UCL_ARRAY), "args", 0, false);
	if (text != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(text), "text", 0,
		    false);
	json = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	return (json);
}

static void
kv(ucl_object_t *args, const char *k, const char *v)
{
	char	*w;

	if (v == NULL || v[0] == '\0')
		return;
	if (asprintf(&w, "%s=%s", k, v) == -1)
		abort();
	ucl_array_append(args, ucl_object_fromstring(w));
	free(w);
}

static void
bld_send(const char *verb, ucl_object_t *args, const char *text,
    const char *title)
{
	struct server	*s;

	if ((s = bld_server()) == NULL) {
		if (args != NULL)
			ucl_object_unref(args);
		return;
	}
	/* Held in the queue, it is not under way yet. */
	bld.busy = !app.queue_on;
	job_send_host(s, pd_job(verb, args, text), title, JOB_BUILDER, "");
}

/* ---- Pieces -------------------------------------------------------- */

static void
host_pick(struct html *h)
{
	int	i;

	h_raw(h, "<label class=\"secpick\">Host <select data-input=\"bld-host\">");
	if (bld.sid[0] == '\0')
		h_raw(h, "<option value=\"\" selected>choose…</option>");
	for (i = 0; i < app.nservers; i++) {
		h_raw(h, "<option");
		h_attr(h, "value", app.servers[i].id);
		if (strcmp(app.servers[i].id, bld.sid) == 0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, app.servers[i].name);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label>");
}

/* Seconds since the epoch as a day and a time, the browser's zone. */
static void
when(struct html *h, int64_t t)
{
	struct tm	tm;
	time_t		tt;
	char		buf[32];

	if (t <= 0) {
		h_raw(h, "<span class=\"dim\">—</span>");
		return;
	}
	tt = (time_t)t;
	localtime_r(&tt, &tm);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tm);
	h_txt(h, buf);
}

/* A run's command, the program's path left out. */
static void
argv_words(struct html *h, const ucl_object_t *argv)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	bool			 first;

	h_raw(h, "poudriere");
	first = true;
	it = NULL;
	while ((e = ucl_object_iterate(argv, &it, true)) != NULL) {
		if (first) {
			first = false;
			continue;
		}
		h_raw(h, " ");
		h_txt(h, ucl_object_tostring_forced(e));
	}
}

/* The second word of a run's command: jail, ports or bulk. */
static const char *
run_kind(const ucl_object_t *r)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int			 i;

	it = NULL;
	for (i = 0; (e = ucl_object_iterate(jget(r, "argv"), &it, true)) !=
	    NULL; i++)
		if (i == 1)
			return (ucl_object_tostring(e));
	return ("");
}

static void
state_chip(struct html *h, const char *st)
{

	h_fmt(h, "<span class=\"chip %s\">%s</span>", strcmp(st, "running") ==
	    0 ? "st-up live" : strcmp(st, "done") == 0 ? "st-up" :
	    strcmp(st, "failed") == 0 ? "st-down" : "warn", st);
}

/* The runs of a kind, newest first, each with its output's end. */
static void
runs(struct html *h, const char *kind, const char *what)
{
	const ucl_object_t	*r;
	ucl_object_iter_t	 it;
	const char		*st;
	int			 n;

	n = 0;
	it = NULL;
	while ((r = ucl_object_iterate(jget(bld.state, "runs"), &it, true)) !=
	    NULL)
		if (strcmp(run_kind(r), kind) == 0)
			n++;
	h_fmt(h, "<h3 class=\"bldh\">Runs <small class=\"dim\">%s: poudriere "
	    "goes on by itself, its output kept</small></h3>", what);
	if (n == 0) {
		h_raw(h, "<p class=\"dim\">None yet.</p>");
		return;
	}
	h_raw(h, "<ul class=\"bldruns\">");
	it = NULL;
	while ((r = ucl_object_iterate(jget(bld.state, "runs"), &it, true)) !=
	    NULL) {
		if (strcmp(run_kind(r), kind) != 0)
			continue;
		st = jstr(r, "state") != NULL ? jstr(r, "state") : "lost";
		h_fmt(h, "<li class=\"bldrun\" data-run=\"%lld\"><details%s>"
		    "<summary><b>#%lld</b> ", (long long)jint(r, "id", 0),
		    strcmp(st, "running") == 0 ? " open" : "",
		    (long long)jint(r, "id", 0));
		state_chip(h, st);
		h_raw(h, " <span class=\"mono\">");
		argv_words(h, jget(r, "argv"));
		h_raw(h, "</span> <span class=\"dim\">");
		when(h, jint(r, "started", 0));
		if (jget(r, "exit") != NULL)
			h_fmt(h, ", exit %lld", (long long)jint(r, "exit", 0));
		h_raw(h, "</span>");
		if (strcmp(st, "running") == 0)
			h_fmt(h, " <button class=\"ghost small danger\" data-act="
			    "\"bld-stop\" data-arg=\"%lld\" title=\"SIGINT to its "
			    "process group, as Ctrl-C: poudriere tears its jails "
			    "down\">Stop</button>", (long long)jint(r, "id", 0));
		h_raw(h, "</summary><pre class=\"bldlog\">");
		h_txt(h, jstr(r, "log") != NULL ? jstr(r, "log") :
		    "(its output is in ");
		if (jstr(r, "log") == NULL) {
			h_txt(h, jstr(r, "log_file"));
			h_raw(h, ")");
		}
		h_raw(h, "</pre></details></li>");
	}
	h_raw(h, "</ul>");
}

/* A select of the jails' or trees' names. */
static void
name_select(struct html *h, const char *field, const char *list,
    bool optional)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	h_fmt(h, "<select name=\"%s\"%s>", field, optional ? "" : " required");
	if (optional)
		h_raw(h, "<option value=\"\">default</option>");
	it = NULL;
	while ((e = ucl_object_iterate(jget(bld.state, list), &it, true)) !=
	    NULL) {
		h_raw(h, "<option");
		h_attr(h, "value", jstr(e, "name"));
		h_raw(h, ">");
		h_txt(h, jstr(e, "name"));
		h_raw(h, "</option>");
	}
	h_raw(h, "</select>");
}

/* ---- Jails --------------------------------------------------------- */

static const struct tcol jcols[] = {
	{ "Name", "name", false }, { "Version", "version", false },
	{ "Arch", "arch", false }, { "Method", "method", false },
	{ "Path", "mnt", false }, { "Updated", "timestamp", true },
};

static void
jail_form(struct html *h)
{

	h_raw(h, "<form class=\"secform\" data-form=\"bld-jail\"><h4>A build "
	    "jail</h4><label>Name <input name=\"name\" required "
	    "pattern=\"[A-Za-z0-9_:+][A-Za-z0-9_:+-]{0,63}\" "
	    "spellcheck=\"false\" placeholder=\"150amd64\"><small "
	    "class=\"help\">letters, digits and _ : + -, no dot; an ABI's "
	    "name (FreeBSD:15:amd64) is taken</small></label><label>FreeBSD "
	    "version <input name=\"version\" required spellcheck=\"false\" "
	    "placeholder=\"15.0-RELEASE\"><small class=\"help\">as the method "
	    "names them: 15.0-RELEASE, 14.3-RELEASE, 16.0-CURRENT with "
	    "pkgbase</small></label><label>Arch <input name=\"arch\" "
	    "spellcheck=\"false\" placeholder=\"amd64\"><small class=\"help\">"
	    "TARGET_ARCH, arm64.aarch64; the host's when empty</small>"
	    "</label><label>Method <select name=\"method\"><option value=\"\">"
	    "the default (http: the release's sets)</option><option>http"
	    "</option><option>ftp</option><option>pkgbase</option><option>"
	    "git+https</option><option>freebsdci</option></select><small "
	    "class=\"help\">how poudriere gets the base system</small></label>"
	    "<div class=\"actions\"><button type=\"button\" class=\"ghost\" "
	    "data-act=\"bld-cancel\">Cancel</button><button type=\"submit\" "
	    "class=\"primary\"");
	if (bld.busy)
		h_raw(h, " disabled");
	h_raw(h, ">Create</button></div></form>");
}

/* poudriere.conf: what it says, and the variables a first set-up
 * needs. */
static void
conf_view(struct html *h)
{
	const ucl_object_t	*conf, *e;
	ucl_object_iter_t	 it;
	const char		*z;

	conf = jget(bld.state, "conf");
	z = jstr(conf, "ZPOOL");
	h_raw(h, "<details class=\"bldconf\"");
	if (!jbool(bld.state, "configured") || (z == NULL &&
	    jstr(conf, "NO_ZFS") == NULL) || bld.form == BF_CONF)
		h_raw(h, " open");
	h_raw(h, "><summary>poudriere.conf <span class=\"dim mono\">");
	h_txt(h, jstr(bld.state, "conf_file"));
	h_raw(h, "</span></summary>");
	if (z == NULL && jstr(conf, "NO_ZFS") == NULL)
		h_raw(h, "<div class=\"notice\">Neither ZPOOL nor NO_ZFS is set: "
		    "poudriere refuses to make a jail until one is. ZFS gives "
		    "each jail a dataset it clones for every builder.</div>");
	h_raw(h, "<table class=\"net bldconfkv\"><tbody>");
	it = NULL;
	while ((e = ucl_object_iterate(conf, &it, true)) != NULL) {
		h_raw(h, "<tr><th class=\"mono\">");
		h_txt(h, ucl_object_key(e));
		h_raw(h, "</th><td class=\"mono\">");
		h_txt(h, ucl_object_tostring_forced(e));
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table><form class=\"secform\" data-form=\""
	    "bld-conf\"><h4>Set</h4>");
#define	CONF_IN(k, ph, help) do {					\
	h_raw(h, "<label>" k " <input name=\"" k "\" spellcheck=\"false\" "	\
	    "placeholder=\"" ph "\"");						\
	h_attr(h, "value", jstr(conf, k) != NULL ? jstr(conf, k) : "");		\
	h_raw(h, "><small class=\"help\">" help "</small></label>");		\
} while (0)
	CONF_IN("ZPOOL", "zroot", "the pool its datasets are made in");
	CONF_IN("BASEFS", "/usr/local/poudriere", "where its jails, trees and "
	    "data are");
	CONF_IN("DISTFILES_CACHE", "/usr/ports/distfiles", "the sources "
	    "fetched, kept between builds");
	CONF_IN("PARALLEL_JOBS", "the CPUs", "how many ports at once");
	CONF_IN("USE_TMPFS", "yes", "wrkdir, data, all or no: builds in "
	    "memory");
	CONF_IN("CCACHE_DIR", "/var/cache/ccache", "a compiler cache, kept");
	CONF_IN("ALLOW_MAKE_JOBS", "yes", "make -j inside each build");
#undef	CONF_IN
	h_raw(h, "<div class=\"actions\"><small class=\"help\">An empty field "
	    "unsets it (sysrc -x); the rest are left as they are.</small>"
	    "<button type=\"submit\" class=\"primary\"");
	if (bld.busy)
		h_raw(h, " disabled");
	h_raw(h, ">Save</button></div></form></details>");
}

static void
view_jails(struct html *h)
{
	const ucl_object_t	**rows, *e;
	int			  r;

	h_raw(h, "<p class=\"lead\">The FreeBSD each package is built in: a "
	    "jail of poudriere's own, cloned for every builder, as old as the "
	    "oldest host the packages are for.</p>");
	conf_view(h);
	h_raw(h, "<div class=\"toolbar\"><button class=\"primary\" "
	    "data-act=\"bld-new\" data-arg=\"jail\">New jail</button></div>");
	if (bld.form == BF_JAIL)
		jail_form(h);
	if (ucl_array_size(jget(bld.state, "jails")) == 0)
		h_raw(h, "<div class=\"empty\"><p>No build jail yet.</p><p "
		    "class=\"dim\">Make one of the oldest FreeBSD the packages "
		    "are for: 15.0-RELEASE builds packages 15.x runs.</p>"
		    "</div>");
	else {
		h_raw(h, "<table class=\"net bldjails\">");
		tbl_head(h, "bldjails", jcols, 6, 1);
		h_raw(h, "<tbody>");
		rows = tbl_rows("bldjails", jget(bld.state, "jails"), jcols, 6,
		    app.filter);
		for (r = 0; (e = rows[r]) != NULL; r++) {
			h_raw(h, "<tr");
			h_attr(h, "data-jail", jstr(e, "name"));
			h_raw(h, "><td><b>");
			h_txt(h, jstr(e, "name"));
			h_raw(h, "</b></td><td>");
			h_txt(h, jstr(e, "version"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(e, "arch"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(e, "method"));
			h_raw(h, "</td><td class=\"mono dim\">");
			h_txt(h, jstr(e, "mnt"));
			h_raw(h, "</td><td>");
			when(h, jint(e, "timestamp", 0));
			h_raw(h, "</td><td class=\"acts\"><button class=\"ghost "
			    "small\" data-act=\"bld-jail-update\"");
			h_attr(h, "data-arg", jstr(e, "name"));
			h_raw(h, " title=\"poudriere jail -u: its base system "
			    "brought up to date\">Update</button><button "
			    "class=\"ghost small danger\" data-act=\"bld-delete\" "
			    "data-value=\"jail\"");
			h_attr(h, "data-arg", jstr(e, "name"));
			h_raw(h, ">Delete</button></td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table>");
	}
	runs(h, "jail", "a jail made or updated");
}

/* ---- Ports --------------------------------------------------------- */

static const struct tcol pcols[] = {
	{ "Name", "name", false }, { "Method", "method", false },
	{ "Path", "mnt", false }, { "Updated", "timestamp", true },
};

static void
ports_form(struct html *h)
{

	h_raw(h, "<form class=\"secform\" data-form=\"bld-ports\"><h4>A ports "
	    "tree</h4><label>Name <input name=\"name\" required "
	    "pattern=\"[A-Za-z0-9_:+][A-Za-z0-9_:+-]{0,63}\" "
	    "spellcheck=\"false\" placeholder=\"default\"></label><label>"
	    "Method <select name=\"method\"><option value=\"\">the default "
	    "(git+https)</option><option>git+https</option><option>git+ssh"
	    "</option><option>null</option></select><small class=\"help\">"
	    "null: a tree already there, at Path</small></label><label>"
	    "Branch <input name=\"branch\" spellcheck=\"false\" "
	    "placeholder=\"main\"><small class=\"help\">main, or a quarterly "
	    "one: 2026Q4</small></label><details class=\"wfmore\"><summary>"
	    "More options</summary><label>Repository <input name=\"url\" "
	    "spellcheck=\"false\" placeholder=\"https://git.FreeBSD.org/"
	    "ports.git\"><small class=\"help\">a fork of the tree, with git"
	    "</small></label><label>Path <input name=\"path\" "
	    "spellcheck=\"false\" placeholder=\"/usr/ports\"><small "
	    "class=\"help\">with null: the tree used where it is</small>"
	    "</label></details><div class=\"actions\"><button type=\"button\" "
	    "class=\"ghost\" data-act=\"bld-cancel\">Cancel</button><button "
	    "type=\"submit\" class=\"primary\"");
	if (bld.busy)
		h_raw(h, " disabled");
	h_raw(h, ">Create</button></div></form>");
}

static void
view_ports(struct html *h)
{
	const ucl_object_t	**rows, *e;
	int			  r;

	h_raw(h, "<p class=\"lead\">The ports trees packages are built from, "
	    "each its own git clone (or a tree already on the host).</p>"
	    "<div class=\"toolbar\"><button class=\"primary\" "
	    "data-act=\"bld-new\" data-arg=\"ports\">New ports tree</button>"
	    "</div>");
	if (bld.form == BF_PORTS)
		ports_form(h);
	if (ucl_array_size(jget(bld.state, "ports")) == 0)
		h_raw(h, "<div class=\"empty\"><p>No ports tree yet.</p><p "
		    "class=\"dim\">Name one default: a build without a tree "
		    "named uses it.</p></div>");
	else {
		h_raw(h, "<table class=\"net bldports\">");
		tbl_head(h, "bldports", pcols, 4, 1);
		h_raw(h, "<tbody>");
		rows = tbl_rows("bldports", jget(bld.state, "ports"), pcols, 4,
		    app.filter);
		for (r = 0; (e = rows[r]) != NULL; r++) {
			h_raw(h, "<tr");
			h_attr(h, "data-ports", jstr(e, "name"));
			h_raw(h, "><td><b>");
			h_txt(h, jstr(e, "name"));
			h_raw(h, "</b></td><td>");
			h_txt(h, jstr(e, "method"));
			h_raw(h, "</td><td class=\"mono dim\">");
			h_txt(h, jstr(e, "mnt"));
			h_raw(h, "</td><td>");
			when(h, jint(e, "timestamp", 0));
			h_raw(h, "</td><td class=\"acts\"><button class=\"ghost "
			    "small\" data-act=\"bld-ports-update\"");
			h_attr(h, "data-arg", jstr(e, "name"));
			h_raw(h, " title=\"poudriere ports -u: pulled\">Update"
			    "</button><button class=\"ghost small danger\" "
			    "data-act=\"bld-delete\" data-value=\"ports\"");
			h_attr(h, "data-arg", jstr(e, "name"));
			h_raw(h, ">Delete</button></td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table>");
	}
	runs(h, "ports", "a tree made or updated");
}

/* ---- Bulk ---------------------------------------------------------- */

static const struct tcol bcols[] = {
	{ "Jail", "jail", false }, { "Ports", "ports", false },
	{ "Set", "set", false }, { "Build", "build", false },
	{ "Status", "status", false }, { "Built", "built", true },
	{ "Failed", "failed", true }, { "Skipped", "skipped", true },
	{ "Left", "remaining", true }, { "Time", "time", false },
};

static const struct tcol rcols[] = {
	{ "Repository", "name", false }, { "Packages", "packages", true },
	{ "Path", "path", false },
};

static void
bulk_form(struct html *h)
{

	if (ucl_array_size(jget(bld.state, "jails")) == 0) {
		h_raw(h, "<div class=\"empty\"><p>A build needs a jail.</p>"
		    "<button class=\"ghost\" data-act=\"bld-tab\" "
		    "data-arg=\"jails\">Make one</button></div>");
		return;
	}
	h_raw(h, "<form class=\"secform\" data-form=\"bld-bulk\"><h4>Build "
	    "packages</h4><label>Jail ");
	name_select(h, "jail", "jails", false);
	h_raw(h, "</label><label>Ports tree ");
	name_select(h, "ports", "ports", true);
	h_raw(h, "</label><label>Set <input name=\"set\" spellcheck=\"false\" "
	    "pattern=\"[A-Za-z0-9_:+]{0,64}\" placeholder=\"none\"><small "
	    "class=\"help\">its own make.conf and repository: "
	    "jail-tree-set</small></label><label>Ports <textarea name="
	    "\"origins\" rows=\"3\" required spellcheck=\"false\" "
	    "placeholder=\"net/bird3\"></textarea><small class=\"help\">"
	    "category/name, a line each; @flavor where there are "
	    "flavors</small></label><label class=\"check\"><input "
	    "type=\"checkbox\" name=\"debug\"> Debug symbols (WITH_DEBUG) "
	    "<small class=\"help\">built unstripped, with -g: the set's "
	    "make.conf gets WITH_DEBUG_PORTS for them first (the set is debug "
	    "if none is named), so that a core has their names</small>"
	    "</label><details class=\"wfmore\"><summary>More options"
	    "</summary><label>Builders <input name=\"jobs\" type=\"number\" "
	    "min=\"1\" max=\"1024\" placeholder=\"PARALLEL_JOBS\"></label>"
	    "<label class=\"check\"><input type=\"checkbox\" name=\"clean\"> "
	    "Built again from scratch (-C) <small class=\"help\">these "
	    "ports' packages deleted first</small></label><label "
	    "class=\"check\"><input type=\"checkbox\" name=\"test\"> Tested "
	    "(-t) <small class=\"help\">for leftovers after deinstall, and "
	    "the plist</small></label></details><div class=\"actions\">"
	    "<button type=\"submit\" class=\"primary\"");
	if (bld.busy)
		h_raw(h, " disabled");
	h_raw(h, ">Build</button></div></form>");
}

static void
makeconf_view(struct html *h)
{
	const ucl_object_t	*e, *cur;
	ucl_object_iter_t	 it;
	const char		*name;

	h_raw(h, "<h3 class=\"bldh\">make.conf <small class=\"dim\">poudriere."
	    "d: make.conf for every build, then the jail's, the tree's, the "
	    "set's and their pairs' (jail-tree-make.conf…)</small></h3>"
	    "<div class=\"toolbar\"><button class=\"ghost small\" "
	    "data-act=\"bld-mc-new\">New make.conf</button></div>");
	cur = NULL;
	if (ucl_array_size(jget(bld.state, "makeconf")) == 0 && !bld.newmc)
		h_raw(h, "<p class=\"dim\">None: the ports' defaults.</p>");
	h_raw(h, "<ul class=\"bldmc\">");
	it = NULL;
	while ((e = ucl_object_iterate(jget(bld.state, "makeconf"), &it,
	    true)) != NULL) {
		name = jstr(e, "name") != NULL ? jstr(e, "name") : "";
		if (bld.form == BF_MAKECONF && !bld.newmc &&
		    strcmp(name, bld.makeconf) == 0)
			cur = e;
		h_raw(h, "<li><button class=\"ghost small\" data-act=\"bld-mc\"");
		h_attr(h, "data-arg", name);
		h_raw(h, "><span class=\"mono\">");
		h_txt(h, name[0] != '\0' ? name : "make.conf");
		h_raw(h, name[0] != '\0' ? "-make.conf" : "");
		h_raw(h, "</span></button></li>");
	}
	h_raw(h, "</ul>");
	if (bld.form != BF_MAKECONF)
		return;
	h_raw(h, "<form class=\"secform\" data-form=\"bld-makeconf\"><h4>");
	if (bld.newmc)
		h_raw(h, "A make.conf</h4><label>For <input name=\"name\" "
		    "spellcheck=\"false\" pattern=\"[A-Za-z0-9_:+-]{0,64}\" "
		    "placeholder=\"empty: make.conf itself\"><small "
		    "class=\"help\">a jail, a tree, a set, or those joined by "
		    "-</small></label>");
	else {
		h_txt(h, jstr(cur, "file"));
		h_raw(h, "</h4><input type=\"hidden\" name=\"name\"");
		h_attr(h, "value", bld.makeconf);
		h_raw(h, ">");
	}
	h_raw(h, "<label class=\"wide\">Text <textarea name=\"text\" rows=\"10\" "
	    "spellcheck=\"false\" placeholder=\"WITH_DEBUG_PORTS+= net/bird3"
	    "\">");
	h_txt(h, jstr(cur, "text") != NULL ? jstr(cur, "text") : "");
	h_raw(h, "</textarea><small class=\"help\">make(1)'s: OPTIONS_SET, "
	    "DEFAULT_VERSIONS, WITH_DEBUG_PORTS…; empty takes the file away"
	    "</small></label><div class=\"actions\"><button type=\"button\" "
	    "class=\"ghost\" data-act=\"bld-cancel\">Cancel</button><button "
	    "type=\"submit\" class=\"primary\"");
	if (bld.busy)
		h_raw(h, " disabled");
	h_raw(h, ">Save</button></div></form>");
}

/* Beneath a build with ports that failed or were skipped: each, and
 * the end of each failed one's log. */
static void
build_failures(struct html *h, const ucl_object_t *b)
{
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;
	size_t			 nf, ns;

	nf = ucl_array_size(jget(b, "failed_ports"));
	ns = ucl_array_size(jget(b, "skipped_ports"));
	if (nf == 0 && ns == 0)
		return;
	h_fmt(h, "<tr class=\"bldfail\"><td colspan=\"10\"><details><summary>"
	    "%zu failed%s", nf, ns > 0 ? ", " : "");
	if (ns > 0)
		h_fmt(h, "%zu skipped for them", ns);
	h_raw(h, "</summary><ul class=\"bldfailed\">");
	it = NULL;
	while ((f = ucl_object_iterate(jget(b, "failed_ports"), &it, true)) !=
	    NULL) {
		h_raw(h, "<li><details><summary><b class=\"mono\">");
		h_txt(h, jstr(f, "origin"));
		h_raw(h, "</b> <span class=\"mono dim\">");
		h_txt(h, jstr(f, "package"));
		h_raw(h, "</span> <span class=\"chip st-down\">");
		h_txt(h, jstr(f, "phase"));
		h_raw(h, "</span>");
		if (jstr(f, "reason") != NULL) {
			h_raw(h, " <span class=\"chip warn\">");
			h_txt(h, jstr(f, "reason"));
			h_raw(h, "</span>");
		}
		if (jget(f, "elapsed") != NULL)
			h_fmt(h, " <span class=\"dim\">after %llds</span>",
			    (long long)jint(f, "elapsed", 0));
		h_raw(h, "</summary><pre class=\"bldlog\"");
		h_attr(h, "title", jstr(f, "log_file"));
		h_raw(h, ">");
		h_txt(h, jstr(f, "log") != NULL ? jstr(f, "log") :
		    "(no log: it failed before it was built)");
		h_raw(h, "</pre></details></li>");
	}
	it = NULL;
	while ((f = ucl_object_iterate(jget(b, "skipped_ports"), &it, true)) !=
	    NULL) {
		h_raw(h, "<li class=\"dim\"><span class=\"mono\">");
		h_txt(h, jstr(f, "origin"));
		h_raw(h, "</span> skipped");
		if (jstr(f, "because") != NULL) {
			h_raw(h, ": it needs <span class=\"mono\">");
			h_txt(h, jstr(f, "because"));
			h_raw(h, "</span>");
		}
		h_raw(h, "</li>");
	}
	h_raw(h, "</ul></details></td></tr>");
}

/* A port's options: which, then each, as the build takes them; and
 * what each options directory sets. */
static void
options_view(struct html *h)
{
	const ucl_object_t	*sec, *o, *d, *p, *v;
	ucl_object_iter_t	 it, it2, it3;

	h_raw(h, "<h3 class=\"bldh\">Port options <small class=\"dim\">each "
	    "port's OPTIONS, as make config sets them; a build copies the "
	    "first options directory there is of its jail, tree and set"
	    "</small></h3><form class=\"secform\" data-form=\"bld-optshow\">"
	    "<label>Jail ");
	name_select(h, "jail", "jails", false);
	h_raw(h, "</label><label>Ports tree ");
	name_select(h, "ports", "ports", true);
	h_raw(h, "</label><label>Set <input name=\"set\" spellcheck=\"false\" "
	    "pattern=\"[A-Za-z0-9_:+]{0,64}\" placeholder=\"none\"></label>"
	    "<label>Port <input name=\"origin\" required spellcheck=\"false\" "
	    "placeholder=\"net/bird3\"></label><div class=\"actions\"><button "
	    "type=\"submit\" class=\"ghost\">Show its options</button></div>"
	    "</form>");
	if (bld.optloading)
		h_raw(h, "<div class=\"loader\"></div>");
	if (bld.opterr[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, bld.opterr);
		h_raw(h, "</div>");
	}
	if (bld.opts != NULL) {
		h_raw(h, "<form class=\"secform bldopts\" data-form=\"bld-options\">"
		    "<h4>");
		h_txt(h, jstr(bld.opts, "pkgname"));
		h_raw(h, jbool(bld.opts, "configured") ? " <span class=\"chip "
		    "st-up\">set</span>" : " <span class=\"chip\">the port's "
		    "defaults</span>");
		h_raw(h, "</h4><p class=\"help wide\">In <span class=\"mono\">");
		h_txt(h, jstr(bld.opts, "options_dir"));
		h_raw(h, "</span>");
		if (!jbool(bld.opts, "options_dir_exists"))
			h_raw(h, ": made when saved, and from then the "
			    "directory this jail, tree and set's builds copy, "
			    "instead of a wider one");
		h_raw(h, ".</p>");
		it = NULL;
		while ((sec = ucl_object_iterate(jget(bld.opts, "sections"), &it,
		    true)) != NULL) {
			h_raw(h, "<fieldset class=\"wide\"><legend>");
			h_txt(h, jstr(sec, "title") != NULL && jstr(sec,
			    "title")[0] != '\0' ? jstr(sec, "title") : "Options");
			h_raw(h, "</legend>");
			it2 = NULL;
			while ((o = ucl_object_iterate(jget(sec, "options"), &it2,
			    true)) != NULL) {
				h_raw(h, "<label class=\"check\"><input "
				    "type=\"checkbox\"");
				h_attr(h, "name", jstr(o, "name"));
				if (jbool(o, "on"))
					h_raw(h, " checked");
				h_raw(h, "> <b class=\"mono\">");
				h_txt(h, jstr(o, "name"));
				h_raw(h, "</b> <small class=\"help\">");
				h_txt(h, jstr(o, "description"));
				h_raw(h, "</small></label>");
			}
			h_raw(h, "</fieldset>");
		}
		h_raw(h, "<div class=\"actions\">");
		if (jbool(bld.opts, "configured"))
			h_raw(h, "<button type=\"button\" class=\"ghost\" "
			    "data-act=\"bld-opt-reset\">The port's defaults"
			    "</button>");
		h_raw(h, "<button type=\"button\" class=\"ghost\" "
		    "data-act=\"bld-opt-close\">Close</button><button "
		    "type=\"submit\" class=\"primary\"");
		if (bld.busy)
			h_raw(h, " disabled");
		h_raw(h, ">Save</button></div></form>");
	}
	/* What the options directories set already. */
	it = NULL;
	while ((d = ucl_object_iterate(jget(bld.state, "options"), &it,
	    true)) != NULL) {
		h_raw(h, "<div class=\"bldoptdir\"><span class=\"mono dim\">");
		h_txt(h, jstr(d, "dir"));
		h_raw(h, "</span><ul>");
		it2 = NULL;
		while ((p = ucl_object_iterate(jget(d, "ports"), &it2, true)) !=
		    NULL) {
			h_raw(h, "<li><b class=\"mono\">");
			h_txt(h, jstr(p, "pkgname") != NULL ? jstr(p, "pkgname") :
			    jstr(p, "name"));
			h_raw(h, "</b>");
			it3 = NULL;
			while ((v = ucl_object_iterate(jget(p, "set"), &it3,
			    true)) != NULL) {
				h_raw(h, " <span class=\"chip st-up\">+");
				h_txt(h, ucl_object_tostring(v));
				h_raw(h, "</span>");
			}
			it3 = NULL;
			while ((v = ucl_object_iterate(jget(p, "unset"), &it3,
			    true)) != NULL) {
				h_raw(h, " <span class=\"chip\">−");
				h_txt(h, ucl_object_tostring(v));
				h_raw(h, "</span>");
			}
			h_raw(h, "</li>");
		}
		h_raw(h, "</ul></div>");
	}
}

static void
view_bulk(struct html *h)
{
	const ucl_object_t	**rows, *e;
	int			  r;

	h_raw(h, "<p class=\"lead\">Ports built into packages in a jail, with "
	    "a tree and a set, into a repository of their own that pkg(8) "
	    "installs from.</p>");
	/* A build under way: said first, with the way to stop it. */
	{
		const ucl_object_t	*r;
		ucl_object_iter_t	 it;

		it = NULL;
		while ((r = ucl_object_iterate(jget(bld.state, "runs"), &it,
		    true)) != NULL)
			if (strcmp(run_kind(r), "bulk") == 0 && jstr(r, "state") !=
			    NULL && strcmp(jstr(r, "state"), "running") == 0) {
				h_fmt(h, "<div class=\"notice info bld-running\">"
				    "Build <b>#%lld</b> is running: <span class=\"mono"
				    "\">", (long long)jint(r, "id", 0));
				argv_words(h, jget(r, "argv"));
				h_fmt(h, "</span> <button class=\"ghost small danger\" "
				    "data-act=\"bld-stop\" data-arg=\"%lld\" title=\""
				    "SIGINT to its process group, as Ctrl-C: poudriere "
				    "tears its jails down\">Cancel the build</button>"
				    "</div>", (long long)jint(r, "id", 0));
			}
	}
	bulk_form(h);
	runs(h, "bulk", "a build");
	makeconf_view(h);
	options_view(h);
	h_raw(h, "<h3 class=\"bldh\">Builds <small class=\"dim\">the latest of "
	    "each jail, tree and set, as poudriere status says</small></h3>");
	if (jstr(bld.state, "builds_error") != NULL) {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, jstr(bld.state, "builds_error"));
		h_raw(h, "</div>");
	}
	if (ucl_array_size(jget(bld.state, "builds")) == 0)
		h_raw(h, "<p class=\"dim\">None yet.</p>");
	else {
		h_raw(h, "<table class=\"net bldbuilds\">");
		tbl_head(h, "bldbuilds", bcols, 10, 0);
		h_raw(h, "<tbody>");
		rows = tbl_rows("bldbuilds", jget(bld.state, "builds"), bcols,
		    10, app.filter);
		for (r = 0; (e = rows[r]) != NULL; r++) {
			h_raw(h, "<tr><td>");
			h_txt(h, jstr(e, "jail"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(e, "ports"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(e, "set"));
			h_raw(h, "</td><td class=\"mono\"");
			h_attr(h, "title", jstr(e, "logs"));
			h_raw(h, ">");
			h_txt(h, jstr(e, "build"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(e, "status"));
			h_fmt(h, "</td><td>%lld</td><td%s>%lld</td><td>%lld</td>"
			    "<td>%lld</td><td>", (long long)jint(e, "built", 0),
			    jint(e, "failed", 0) > 0 ? " class=\"bad\"" : "",
			    (long long)jint(e, "failed", 0), (long long)jint(e,
			    "skipped", 0), (long long)jint(e, "remaining", 0));
			h_txt(h, jstr(e, "time"));
			h_raw(h, "</td></tr>");
			build_failures(h, e);
		}
		free(rows);
		h_raw(h, "</tbody></table>");
	}
	h_raw(h, "<h3 class=\"bldh\">Repositories <small class=\"dim\">what "
	    "the builds filled: a host's pkg(8) takes one as a repository "
	    "whose url is file:// it, or it served by a web server</small>"
	    "</h3>");
	if (ucl_array_size(jget(bld.state, "repos")) == 0) {
		h_raw(h, "<p class=\"dim\">None yet.</p>");
		return;
	}
	h_raw(h, "<table class=\"net bldrepos\">");
	tbl_head(h, "bldrepos", rcols, 3, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("bldrepos", jget(bld.state, "repos"), rcols, 3,
	    app.filter);
	for (r = 0; (e = rows[r]) != NULL; r++) {
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(e, "name"));
		h_fmt(h, "</b></td><td>%lld</td><td class=\"mono dim\">",
		    (long long)jint(e, "packages", 0));
		h_txt(h, jstr(e, "path"));
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
}

/* ---- The page ------------------------------------------------------ */

void
view_builder(struct html *h)
{
	static const char *const names[] = { "Jails", "Ports", "Bulk" };
	static const char *const titles[] = {
	    "poudriere jail: the FreeBSD packages are built in",
	    "poudriere ports: the trees they are built from",
	    "poudriere bulk: packages built, with their make.conf" };
	size_t	i;

	h_raw(h, "<section class=\"secpage bldpage\"><div class=\"sechead\">");
	host_pick(h);
	if (bld.state != NULL && jbool(bld.state, "installed"))
		h_raw(h, "<span class=\"chip st-up\" title=\"poudriere(8), a "
		    "plugin\">poudriere</span>");
	h_raw(h, "</div><nav class=\"tabs\">");
	for (i = 0; i < nitems(names); i++)
		h_fmt(h, "<button class=\"tab%s\" data-act=\"bld-tab\" "
		    "data-arg=\"%s\" title=\"%s\">%s</button>", (size_t)bld.tab ==
		    i ? " on" : "", tabs[i], titles[i], names[i]);
	h_raw(h, "</nav>");
	if (bld.sid[0] == '\0') {
		h_raw(h, "<div class=\"empty\"><p>Choose a host.</p><p class=\""
		    "dim\">The one that builds the packages: poudriere on it, "
		    "with room for its jails and the ports' sources.</p></div>"
		    "</section>");
		return;
	}
	if (bld.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, bld.error);
		h_raw(h, "</div>");
	}
	if (bld.state == NULL) {
		if (bld.error[0] == '\0')
			h_raw(h, "<div class=\"loader\"></div>");
		h_raw(h, "</section>");
		return;
	}
	if (!jbool(bld.state, "installed")) {
		h_raw(h, "<div class=\"empty\"><p>poudriere is not installed "
		    "here.</p><p class=\"dim\">It is a plugin: Arcana installs "
		    "nothing by itself. This installs the package poudriere "
		    "(pkg install -y poudriere); poudriere-devel is the newer "
		    "one.</p><button class=\"primary\" data-act=\"bld-install\" "
		    "data-arg=\"poudriere\">Install poudriere</button> <button "
		    "class=\"ghost\" data-act=\"bld-install\" "
		    "data-arg=\"poudriere-devel\">Install poudriere-devel</button>"
		    "</div></section>");
		return;
	}
	switch (bld.tab) {
	case BLD_JAILS:
		view_jails(h);
		break;
	case BLD_PORTS:
		view_ports(h);
		break;
	case BLD_BULK:
		view_bulk(h);
		break;
	}
	h_raw(h, "</section>");
}

/* ---- Forms and actions --------------------------------------------- */

/* Whether text has origin among its WITH_DEBUG_PORTS. */
static bool
debug_listed(const char *text, const char *origin)
{
	const char	*p, *e;
	size_t		 n;

	n = strlen(origin);
	for (p = text; p != NULL && *p != '\0'; p = e != NULL ? e + 1 : NULL) {
		e = strchr(p, '\n');
		p += strspn(p, " \t");
		if (strncmp(p, "WITH_DEBUG_PORTS", 16) != 0)
			continue;
		for (p += 16; *p != '\0' && *p != '\n'; p++)
			if (strncmp(p, origin, n) == 0 && (p[-1] == ' ' ||
			    p[-1] == '\t' || p[-1] == '=') && (p[n] == '\0' ||
			    p[n] == ' ' || p[n] == '\t' || p[n] == '\n'))
				return (true);
	}
	return (false);
}

static const char *
makeconf_text(const char *name)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(jget(bld.state, "makeconf"), &it,
	    true)) != NULL)
		if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"), name) ==
		    0)
			return (jstr(e, "text"));
	return (NULL);
}

static void
bulk_submit(const ucl_object_t *f)
{
	struct queued	 q[2];
	struct server	*s;
	ucl_object_t	*args;
	const char	*set, *old;
	char		*origins, *p, *w, *text, *add, title[160];
	size_t		 len;
	int		 n, nq;

	if ((s = bld_server()) == NULL)
		return;
	set = jstr(f, "set") != NULL ? jstr(f, "set") : "";
	if (jbool(f, "debug") && set[0] == '\0')
		set = "debug";
	if ((origins = strdup(jstr(f, "origins") != NULL ? jstr(f, "origins") :
	    "")) == NULL)
		abort();
	args = ucl_object_typed_new(UCL_ARRAY);
	kv(args, "jail", jstr(f, "jail"));
	kv(args, "ports", jstr(f, "ports"));
	kv(args, "set", set);
	kv(args, "jobs", jstr(f, "jobs"));
	if (jbool(f, "clean"))
		kv(args, "clean", "yes");
	if (jbool(f, "test"))
		kv(args, "test", "yes");
	/* The debug line: the ports not listed yet. */
	old = makeconf_text(set);
	len = 32 + strlen(origins) + 1;
	if ((add = calloc(1, len)) == NULL)
		abort();
	n = 0;
	p = origins;
	while ((w = strsep(&p, " ,\t\r\n")) != NULL) {
		if (w[0] == '\0')
			continue;
		kv(args, "origin", w);
		n++;
		if (jbool(f, "debug") && !debug_listed(old != NULL ? old : "",
		    w)) {
			if (add[0] == '\0')
				strlcpy(add, "WITH_DEBUG_PORTS+=", len);
			strlcat(add, " ", len);
			strlcat(add, w, len);
		}
	}
	free(origins);
	if (n == 0) {
		ucl_object_unref(args);
		free(add);
		toast(true, "Name the ports to build: net/bird3");
		return;
	}
	nq = 0;
	memset(q, 0, sizeof(q));
	if (add[0] != '\0') {
		if (asprintf(&text, "%s%s%s\n", old != NULL ? old : "", old !=
		    NULL && old[0] != '\0' && old[strlen(old) - 1] != '\n' ? "\n" :
		    "", add) == -1)
			abort();
		{
			ucl_object_t	*ma;

			ma = ucl_object_typed_new(UCL_ARRAY);
			kv(ma, "name", set);
			q[nq].json = pd_job("make-conf", ma, text);
		}
		free(text);
		snprintf(q[nq].title, sizeof(q[nq].title), "poudriere %s-make.conf: "
		    "debug symbols for %s", set, add + 19);
		nq++;
	}
	free(add);
	snprintf(title, sizeof(title), "poudriere bulk in %s%s%s",
	    jstr(f, "jail") != NULL ? jstr(f, "jail") : "", set[0] != '\0' ?
	    ", set " : "", set);
	q[nq].json = pd_job("bulk", args, NULL);
	snprintf(q[nq].title, sizeof(q[nq].title), "%s", title);
	nq++;
	bld.busy = !app.queue_on;
	job_send_many(s, q, nq, JOB_BUILDER);
}

bool
builder_form(const char *form, const ucl_object_t *f)
{
	ucl_object_t	*args;
	char		 title[160];
	static const char *const keys[] = { "ZPOOL", "BASEFS",
	    "DISTFILES_CACHE", "PARALLEL_JOBS", "USE_TMPFS", "CCACHE_DIR",
	    "ALLOW_MAKE_JOBS" };
	const ucl_object_t	*conf;
	const char		*v, *was;
	size_t			 i;
	char			*w;

	if (strncmp(form, "bld-", 4) != 0)
		return (false);
	if (strcmp(form, "bld-jail") == 0) {
		args = ucl_object_typed_new(UCL_ARRAY);
		kv(args, "name", jstr(f, "name"));
		kv(args, "version", jstr(f, "version"));
		kv(args, "arch", jstr(f, "arch"));
		kv(args, "method", jstr(f, "method"));
		snprintf(title, sizeof(title), "poudriere jail-create %s",
		    jstr(f, "name") != NULL ? jstr(f, "name") : "");
		bld_send("jail-create", args, NULL, title);
		bld.form = BF_NONE;
		return (true);
	}
	if (strcmp(form, "bld-ports") == 0) {
		args = ucl_object_typed_new(UCL_ARRAY);
		kv(args, "name", jstr(f, "name"));
		kv(args, "method", jstr(f, "method"));
		kv(args, "branch", jstr(f, "branch"));
		kv(args, "url", jstr(f, "url"));
		kv(args, "path", jstr(f, "path"));
		snprintf(title, sizeof(title), "poudriere ports-create %s",
		    jstr(f, "name") != NULL ? jstr(f, "name") : "");
		bld_send("ports-create", args, NULL, title);
		bld.form = BF_NONE;
		return (true);
	}
	if (strcmp(form, "bld-conf") == 0) {
		/* Only what changed: an emptied field unsets. */
		conf = jget(bld.state, "conf");
		args = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < nitems(keys); i++) {
			v = jstr(f, keys[i]) != NULL ? jstr(f, keys[i]) : "";
			was = jstr(conf, keys[i]) != NULL ? jstr(conf, keys[i]) :
			    "";
			if (strcmp(v, was) == 0)
				continue;
			if (asprintf(&w, "%s=%s", keys[i], v) == -1)
				abort();
			ucl_array_append(args, ucl_object_fromstring(w));
			free(w);
		}
		if (ucl_array_size(args) == 0) {
			ucl_object_unref(args);
			toast(false, "Nothing changed");
			return (true);
		}
		bld_send("conf", args, NULL, "poudriere.conf");
		return (true);
	}
	if (strcmp(form, "bld-makeconf") == 0) {
		v = jstr(f, "name") != NULL ? jstr(f, "name") : "";
		args = ucl_object_typed_new(UCL_ARRAY);
		if (asprintf(&w, "name=%s", v) == -1)
			abort();
		ucl_array_append(args, ucl_object_fromstring(w));
		free(w);
		snprintf(title, sizeof(title), "poudriere %s%smake.conf", v,
		    v[0] != '\0' ? "-" : "");
		bld_send("make-conf", args, jstr(f, "text") != NULL ? jstr(f,
		    "text") : "", title);
		bld.form = BF_NONE;
		bld.newmc = false;
		return (true);
	}
	if (strcmp(form, "bld-bulk") == 0) {
		bulk_submit(f);
		return (true);
	}
	if (strcmp(form, "bld-optshow") == 0) {
		static const char *const k[] = { "jail", "ports", "set",
		    "origin" };
		size_t	 len;

		len = 0;
		bld.optq[0] = '\0';
		for (i = 0; i < nitems(k); i++) {
			v = jstr(f, k[i]);
			if (v == NULL || v[0] == '\0')
				continue;
			len += (size_t)snprintf(bld.optq + len,
			    sizeof(bld.optq) - len, "%s%s=", len > 0 ? "&" : "",
			    k[i]);
			for (; *v != '\0' && len + 4 < sizeof(bld.optq); v++)
				len += (size_t)snprintf(bld.optq + len,
				    sizeof(bld.optq) - len, isalnum((unsigned
				    char)*v) || strchr("-_.:+", *v) != NULL ?
				    "%c" : "%%%02X", (unsigned char)*v);
		}
		bld.opterr[0] = '\0';
		opts_load();
		return (true);
	}
	if (strcmp(form, "bld-options") == 0) {
		const ucl_object_t	*sec, *o;
		ucl_object_iter_t	 it, it2;

		if (bld.opts == NULL)
			return (true);
		args = ucl_object_typed_new(UCL_ARRAY);
		kv(args, "jail", jstr(bld.opts, "jail"));
		kv(args, "ports", jstr(bld.opts, "ports"));
		kv(args, "set", jstr(bld.opts, "set"));
		kv(args, "origin", jstr(bld.opts, "origin"));
		it = NULL;
		while ((sec = ucl_object_iterate(jget(bld.opts, "sections"),
		    &it, true)) != NULL) {
			it2 = NULL;
			while ((o = ucl_object_iterate(jget(sec, "options"),
			    &it2, true)) != NULL)
				kv(args, jbool(f, jstr(o, "name")) ? "on" : "off",
				    jstr(o, "name"));
		}
		snprintf(title, sizeof(title), "poudriere options of %s",
		    jstr(bld.opts, "origin"));
		bld_send("options", args, NULL, title);
		return (true);
	}
	return (false);
}

/* "#/builder[/tab[/host]]" */
void
builder_loc(char *buf, size_t len)
{

	snprintf(buf, len, "#/builder/%s%s%s", tabs[bld.tab], bld.sid[0] !=
	    '\0' ? "/" : "", bld.sid);
}

void
builder_open(const char *rest)
{
	char	tab[32];
	size_t	i;

	snprintf(tab, sizeof(tab), "%.*s", (int)strcspn(rest, "/"), rest);
	for (i = 0; i < nitems(tabs); i++)
		if (strcmp(tab, tabs[i]) == 0)
			bld.tab = (enum bldtab)i;
	rest += strcspn(rest, "/");
	if (*rest == '/' && strcmp(rest + 1, bld.sid) != 0) {
		snprintf(bld.sid, sizeof(bld.sid), "%.15s", rest + 1);
		if (bld.state != NULL)
			ucl_object_unref(bld.state);
		bld.state = NULL;
		bld.loading = false;
		bld_load();
	}
}

bool
builder_action(const char *act, const char *arg, const char *value)
{
	ucl_object_t	*args;
	struct server	*s;
	char		*json, title[160], body[256];
	size_t		 i;

	if (strcmp(act, "select-builder") == 0) {
		app.node = NODE_BUILDER;
		app.jail[0] = '\0';
		app.rail_open = false;
		if (bld.sid[0] == '\0' && app.nservers == 1)
			snprintf(bld.sid, sizeof(bld.sid), "%s",
			    app.servers[0].id);
		bld_load();
		return (true);
	}
	if (strncmp(act, "bld-", 4) != 0 && strcmp(act, "input:bld-host") != 0)
		return (false);
	if (strcmp(act, "bld-tab") == 0) {
		for (i = 0; i < nitems(tabs); i++)
			if (strcmp(arg, tabs[i]) == 0)
				bld.tab = (enum bldtab)i;
		bld.form = BF_NONE;
		app.filter[0] = '\0';
		return (true);
	}
	if (strcmp(act, "input:bld-host") == 0) {
		if (value == NULL || strcmp(value, bld.sid) == 0)
			return (true);
		snprintf(bld.sid, sizeof(bld.sid), "%s", value);
		if (bld.state != NULL)
			ucl_object_unref(bld.state);
		bld.state = NULL;
		if (bld.opts != NULL)
			ucl_object_unref(bld.opts);
		bld.opts = NULL;
		bld.optq[0] = '\0';
		bld.loading = false;
		bld.form = BF_NONE;
		bld_load();
		return (true);
	}
	if (strcmp(act, "bld-new") == 0) {
		bld.form = strcmp(arg, "ports") == 0 ? BF_PORTS : BF_JAIL;
		return (true);
	}
	if (strcmp(act, "bld-cancel") == 0) {
		bld.form = BF_NONE;
		bld.newmc = false;
		return (true);
	}
	if (strcmp(act, "bld-mc") == 0) {
		bld.form = BF_MAKECONF;
		bld.newmc = false;
		snprintf(bld.makeconf, sizeof(bld.makeconf), "%s", arg);
		return (true);
	}
	if (strcmp(act, "bld-mc-new") == 0) {
		bld.form = BF_MAKECONF;
		bld.newmc = true;
		bld.makeconf[0] = '\0';
		return (true);
	}
	if (strcmp(act, "bld-jail-update") == 0 || strcmp(act,
	    "bld-ports-update") == 0) {
		args = ucl_object_typed_new(UCL_ARRAY);
		kv(args, "name", arg);
		snprintf(title, sizeof(title), "poudriere %s-update %s", act[4] ==
		    'j' ? "jail" : "ports", arg);
		bld_send(act[4] == 'j' ? "jail-update" : "ports-update", args, NULL,
		    title);
		return (true);
	}
	if (strcmp(act, "bld-delete") == 0) {
		snprintf(body, sizeof(body), "poudriere deletes the %s %s and "
		    "its files.%s", strcmp(value, "jail") == 0 ? "jail" :
		    "ports tree", arg, strcmp(value, "jail") == 0 ? " Its "
		    "packages stay." : "");
		confirm(strcmp(value, "jail") == 0 ? "Delete the jail?" :
		    "Delete the ports tree?", body, "Delete", true, arg,
		    "bld-delete-yes", arg, value);
		return (true);
	}
	if (strcmp(act, "bld-delete-yes") == 0) {
		args = ucl_object_typed_new(UCL_ARRAY);
		kv(args, "name", arg);
		snprintf(title, sizeof(title), "poudriere %s-delete %s",
		    strcmp(value, "jail") == 0 ? "jail" : "ports", arg);
		bld_send(strcmp(value, "jail") == 0 ? "jail-delete" : "ports-delete",
		    args, NULL, title);
		return (true);
	}
	if (strcmp(act, "bld-stop") == 0) {
		snprintf(body, sizeof(body), "Run %s gets SIGINT, as Ctrl-C would "
		    "give it: poudriere stops its builders and tears its jails "
		    "down. What was built stays.", arg);
		confirm("Stop the run?", body, "Stop", true, NULL,
		    "bld-stop-yes", arg, "");
		return (true);
	}
	if (strcmp(act, "bld-stop-yes") == 0) {
		args = ucl_object_typed_new(UCL_ARRAY);
		kv(args, "run", arg);
		snprintf(title, sizeof(title), "poudriere run %s stopped", arg);
		bld_send("stop", args, NULL, title);
		return (true);
	}
	if (strcmp(act, "bld-opt-close") == 0) {
		if (bld.opts != NULL)
			ucl_object_unref(bld.opts);
		bld.opts = NULL;
		bld.optq[0] = '\0';
		return (true);
	}
	if (strcmp(act, "bld-opt-reset") == 0 && bld.opts != NULL) {
		args = ucl_object_typed_new(UCL_ARRAY);
		kv(args, "jail", jstr(bld.opts, "jail"));
		kv(args, "ports", jstr(bld.opts, "ports"));
		kv(args, "set", jstr(bld.opts, "set"));
		kv(args, "origin", jstr(bld.opts, "origin"));
		kv(args, "reset", "yes");
		snprintf(title, sizeof(title), "poudriere options of %s: the "
		    "port's defaults", jstr(bld.opts, "origin"));
		bld_send("options", args, NULL, title);
		return (true);
	}
	if (strcmp(act, "bld-install") == 0) {
		if ((s = bld_server()) == NULL)
			return (true);
		if (asprintf(&json, "{\"kind\":\"pkg-install\",\"packages\":"
		    "[\"%s\"]}", strcmp(arg, "poudriere-devel") == 0 ?
		    "poudriere-devel" : "poudriere") == -1)
			abort();
		snprintf(title, sizeof(title), "pkg install %s", arg);
		bld.busy = !app.queue_on;
		job_send_host(s, json, title, JOB_BUILDER, "");
		return (true);
	}
	return (false);
}

/* Each tick: read again, every 4 s while a run runs, else every 15 s,
 * while the page is shown and no form is open. */
void
builder_tick(double now)
{
	static double		 last;
	const ucl_object_t	*r;
	ucl_object_iter_t	 it;
	bool			 running;

	if (app.node != NODE_BUILDER || !app.visible || bld.loading ||
	    bld.form != BF_NONE || bld.sid[0] == '\0')
		return;
	running = false;
	it = NULL;
	while ((r = ucl_object_iterate(jget(bld.state, "runs"), &it, true)) !=
	    NULL)
		if (jstr(r, "state") != NULL && strcmp(jstr(r, "state"),
		    "running") == 0)
			running = true;
	if (now - last < (running ? 4000 : 15000))
		return;
	last = now;
	bld_load();
}
