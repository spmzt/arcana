/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What the console does: talk to its API and keep the state in step.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "app.h"

#define	RESTART_WATCH_MS	45000	/* an agent to be back, updated */
#define	RESTART_ASK_MS		3000
#define	HEALTH_RETRY_MS		2000	/* a missed health check is asked again */

struct ctx {
	char	sid[9];
	char	jail[256];
	char	name[128];
	int	op;
	bool	user;
	bool	dry_run;
	bool	read;		/* packages: the pending read, not an upgrade */
	enum pending pend;
	int	net_kind;	/* the network table asked for */
	bool	more;		/* rows to add to those there are */
	int	op_family;	/* and its family */
	ucl_object_t *held;	/* a first read's, while a second is asked */
};

static void	osversion_ask(const char *, bool, bool);
static void	 who_set(const ucl_object_t *);
static void	 kput(ucl_object_t *, const char *, ucl_object_t *);
static struct ctx *ctx_new(void);
static struct op *op_new(const char *, const char *);
static struct server *server_by_id(const char *);
static void	merge_jail(struct server *, const ucl_object_t *);
static char	*emit(const ucl_object_t *);
static api_cb	 key_added_cb;

/*
 * A name a host gave, to go into the path of a request: only what
 * leaves the path the one that was meant.
 */
bool
url_word(const char *s)
{

	if (s == NULL || s[0] == '\0' || s[0] == '.')
		return (false);
	for (; *s != '\0'; s++)
		if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
		    (*s >= '0' && *s <= '9') || *s == '_' || *s == '-' ||
		    *s == '.'))
			return (false);
	return (true);
}

/*
 * A jail whose network the Network tab can show: one of its own.  One
 * that does not run has none now, which the host says when asked.
 */
bool
net_jail_ok(const ucl_object_t *j)
{

	return (j != NULL && jstr(j, "name") != NULL && url_word(jstr(j,
	    "name")) && jbool(j, "vnet"));
}

/* And offered there: one that runs. */
static bool
net_jail_runs(const ucl_object_t *j)
{

	return (net_jail_ok(j) && jstr(j, "state") != NULL && strcmp(jstr(j,
	    "state"), "running") == 0);
}

/*
 * The vnet jail whose network the page shows and changes: the one picked
 * in the host's Network tab, while it runs; "" for the host's.
 */
const char *
net_scope(void)
{
	const struct server	*s;

	if (app.node != NODE_HOST || app.tab != TAB_NETWORK ||
	    app.net_jail[0] == '\0' || (s = cur_server()) == NULL ||
	    !net_jail_ok(find_jail(s, app.net_jail)))
		return ("");
	return (app.net_jail);
}

/*
 * What each plugin with a tab needs installed: its program, and the
 * package that has it.  WireGuard's wg(8) is the base system's.
 */
static const struct plugin_pkg plugin_pkgs[] = {
	{ "bird", "BIRD", "birdc(8)", "bird3" },
	{ "strongswan", "strongSwan", "swanctl(8)", "strongswan" },
};

const struct plugin_pkg *
plugin_pkg(const char *plugin)
{
	size_t	i;

	for (i = 0; plugin != NULL && i < sizeof(plugin_pkgs) /
	    sizeof(plugin_pkgs[0]); i++)
		if (strcmp(plugin_pkgs[i].plugin, plugin) == 0)
			return (&plugin_pkgs[i]);
	return (NULL);
}

/* A plugin's packages being installed on s, on the host or in jail. */
bool
plugin_installing(const struct server *s, const char *jail)
{
	const struct op	*o;
	int		 i;

	for (i = 0; i < app.nops; i++) {
		o = &app.ops[i];
		if (o->state == OP_RUNNING && o->what == JOB_PACKAGES &&
		    strcmp(o->sid, s->id) == 0 && strcmp(o->target, jail) ==
		    0 && strncmp(o->title, "pkg install ", 12) == 0)
			return (true);
	}
	return (false);
}

/* The plugin's packages installed where the tab looks: a job. */
void
plugin_install(struct server *s, const char *plugin)
{
	const struct plugin_pkg	*pp;
	const char		*jail;
	char			*json, *qj, title[300];

	if ((pp = plugin_pkg(plugin)) == NULL)
		return;
	jail = net_scope();
	qj = json_quote(jail);
	if (asprintf(&json, "{\"kind\":\"pkg-install\",\"packages\":"
	    "[\"%s\"]%s%s}", pp->package, jail[0] != '\0' ? ",\"jail\":" :
	    "", jail[0] != '\0' ? qj : "") == -1)
		abort();
	free(qj);
	snprintf(title, sizeof(title), "pkg install %s%s%s", pp->package,
	    jail[0] != '\0' ? " in " : "", jail);
	job_send(s, json, title, JOB_PACKAGES, jail);
}

/* The plugin a view of the network is of, or NULL: of the base system. */
const char *
kind_plugin(int kind)
{

	return (kind == NET_BIRD ? "bird" : kind == NET_IPSEC ? "strongswan" :
	    NULL);
}

/*
 * Where on the host a plugin is: "" the host itself, else the first vnet
 * jail that runs with it; NULL nowhere.
 */
const char *
plugin_where(const struct server *s, const char *name)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;

	if (plugin_at(s, "", name))
		return ("");
	it = NULL;
	while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL)
		if (net_jail_runs(j) && plugin_at(s, jstr(j, "name"), name))
			return (jstr(j, "name"));
	return (NULL);
}

/*
 * The same, of any jail that runs, a network of its own or not: for a
 * plugin that serves with the host's network (OpenSMTPD).
 */
const char *
plugin_anywhere(const struct server *s, const char *name)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;

	if (plugin_at(s, "", name))
		return ("");
	it = NULL;
	while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL)
		if (jstr(j, "state") != NULL && strcmp(jstr(j, "state"),
		    "running") == 0 && plugin_at(s, jstr(j, "name"), name))
			return (jstr(j, "name"));
	return (NULL);
}

/*
 * Has the host, or its jail named, the plugin?  A plugin works through
 * a program that is installed, not the base system's: BIRD, WireGuard's
 * wg(8).  The host says which it has, and which a vnet jail of it has.
 */
bool
plugin_at(const struct server *s, const char *jail, const char *name)
{
	const ucl_object_t	*list, *o;
	ucl_object_iter_t	 it;

	if (s == NULL || s->list == NULL)
		return (false);
	list = jail != NULL && jail[0] != '\0' ? jget(find_jail(s, jail),
	    "plugins") : jget(s->list, "host.plugins");
	it = NULL;
	while ((o = ucl_object_iterate(list, &it, true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(o), name) == 0)
			return (true);
	return (false);
}

/* The same of what the page shows: the host, or the vnet jail open. */
bool
has_plugin(const struct server *s, const char *name)
{

	return (plugin_at(s, s == cur_server() ? net_scope() : "", name));
}

static struct ctx *
ctx_new(void)
{
	struct ctx	*c;

	if ((c = calloc(1, sizeof(*c))) == NULL)
		abort();
	return (c);
}

static char *
emit(const ucl_object_t *o)
{

	return ((char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT));
}

static struct server *
server_by_id(const char *id)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, id) == 0)
			return (&app.servers[i]);
	return (NULL);
}

/* A new entry at the top of the activity log. */
/* A task of the console's own, begun and ended by another part. */
struct op *
op_begin(const char *title, const char *server)
{
	struct op	*o;

	/* Not one request: the part that begins it says what it does. */
	o = op_new(title, server);
	o->await = false;
	return (o);
}

void
op_end(struct op *o, bool ok, const char *err)
{

	op_done(o, ok, NULL, err);
}

static struct op *
op_new(const char *title, const char *server)
{
	struct op	*o;

	if (app.nops == MAX_OPS) {
		o = &app.ops[MAX_OPS - 1];
		if (o->trace != NULL)
			ucl_object_unref(o->trace);
		free(o->diff);
		free(o->again);
		app.nops--;
	}
	memmove(&app.ops[1], &app.ops[0],
	    (size_t)app.nops * sizeof(app.ops[0]));
	app.nops++;
	o = &app.ops[0];
	memset(o, 0, sizeof(*o));
	o->id = ++app.nextop;
	snprintf(o->title, sizeof(o->title), "%s", title);
	snprintf(o->server, sizeof(o->server), "%s", server);
	o->state = OP_RUNNING;
	o->started = arc_now();
	o->await = true;
	return (o);
}

/*
 * A poll of the page's own (app.quiet), as a task shown apart: its
 * title the host's read, its server by the id in the path.
 */
int
op_quiet_begin(const char *method, const char *url)
{
	struct op	*o;
	const char	*p, *q;
	char		 title[160], sid[16], server[64];
	int		 i;

	server[0] = '\0';
	snprintf(title, sizeof(title), "%s", url);
	if ((p = strstr(url, "/api/servers/")) != NULL ||
	    (p = strstr(url, "/host=")) != NULL) {
		p += p[1] == 'h' ? strlen("/host=") : strlen("/api/servers/");
		q = strchr(p, '/');
		snprintf(sid, sizeof(sid), "%.*s", (int)(q != NULL ? q - p :
		    (ptrdiff_t)strlen(p)), p);
		for (i = 0; i < app.nservers; i++)
			if (strcmp(app.servers[i].id, sid) == 0)
				snprintf(server, sizeof(server), "%s",
				    app.servers[i].name);
		snprintf(title, sizeof(title), "poll %s", q != NULL ? q + 1 :
		    "the host");
	} else if (strncmp(url, "/api/", 5) == 0)
		snprintf(title, sizeof(title), "poll %s", url + 5);
	title[strcspn(title, "?")] = '\0';
	o = op_new(title, server);
	o->quiet = true;
	o->await = false;
	snprintf(o->method, sizeof(o->method), "%s", method);
	snprintf(o->url, sizeof(o->url), "%s", url);
	return (o->id);
}

/*
 * A change no part made a task for: one made of its request, so that
 * every change done is seen in the task list, ended by its answer.
 * Its title is what it changes (/api/servers/<id>/<what>, or RESTCONF's
 * node), its server by the id in the path.
 */
int
op_auto(const char *method, const char *url, int req)
{
	struct op	*o;
	const char	*p, *q, *verb;
	char		 title[160], sid[16], server[64], what[120];
	int		 i;

	server[0] = sid[0] = '\0';
	verb = strcmp(method, "DELETE") == 0 ? "remove" :
	    strcmp(method, "PATCH") == 0 ? "change" : "set";
	snprintf(what, sizeof(what), "%s", url);
	if ((p = strstr(url, "/api/servers/")) != NULL)
		p += strlen("/api/servers/");
	else if ((p = strstr(url, "/host=")) != NULL)
		p += strlen("/host=");
	if (p != NULL) {
		q = strchr(p, '/');
		snprintf(sid, sizeof(sid), "%.*s", (int)(q != NULL ? q - p :
		    (ptrdiff_t)strlen(p)), p);
		snprintf(what, sizeof(what), "%s", q != NULL ? q + 1 : "the host");
	} else if ((p = strstr(url, "/restconf/data/")) != NULL)
		snprintf(what, sizeof(what), "%s", p + strlen("/restconf/data/"));
	else if (strncmp(url, "/api/", 5) == 0)
		snprintf(what, sizeof(what), "%s", url + 5);
	what[strcspn(what, "?")] = '\0';
	for (i = 0; sid[0] != '\0' && i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sid) == 0)
			snprintf(server, sizeof(server), "%s",
			    app.servers[i].name);
	snprintf(title, sizeof(title), "%s %s", verb, what);
	o = op_new(title, server);
	o->await = false;
	o->req = req;
	snprintf(o->method, sizeof(o->method), "%s", method);
	snprintf(o->url, sizeof(o->url), "%s", url);
	return (o->id);
}

void
op_quiet_end(int id, int status)
{
	struct op	*o;

	if ((o = op_find(id)) == NULL)
		return;
	o->state = status >= 200 && status < 300 ? OP_OK : OP_FAILED;
	o->finished = arc_now();
	if (o->state == OP_FAILED)
		snprintf(o->error, sizeof(o->error), "HTTP %d", status);
}

/*
 * The finished tasks kept in the browser, so that a reload has them with
 * what was seen of them: each its title, host, times and outcome, its
 * job on the host (whose trace is read from there again when it is
 * opened), its request, its error, and its trace and diff when they are
 * small enough to keep.
 */
#define	OPS_KEPT	24
#define	OPS_KEPT_TRACE	(16 * 1024)

void
ops_save(void)
{
	static unsigned long	 last;
	ucl_object_t		*arr, *e;
	unsigned long		 sig;
	char			*json, *t;
	int			 i, n;

	sig = 5381;
	for (i = 0; i < app.nops; i++)
		sig = sig * 33 + (unsigned long)app.ops[i].id * 8 +
		    (unsigned long)app.ops[i].state * 2 + (app.ops[i].trace !=
		    NULL ? 1 : 0);
	if (sig == last)
		return;
	last = sig;
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0, n = 0; i < app.nops && n < OPS_KEPT; i++) {
		if (app.ops[i].quiet)
			continue;
		struct op	*o = &app.ops[i];

		if (o->state == OP_RUNNING)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_frombool(o->state == OP_OK),
		    "ok", 0, false);
		ucl_object_insert_key(e, ucl_object_fromdouble(o->started),
		    "started", 0, false);
		ucl_object_insert_key(e, ucl_object_fromdouble(o->finished),
		    "finished", 0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(o->server),
		    "server", 0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(o->title),
		    "title", 0, false);
		if (o->sid[0] != '\0')
			ucl_object_insert_key(e, ucl_object_fromstring(o->sid),
			    "sid", 0, false);
		if (o->watched > 0)
			ucl_object_insert_key(e, ucl_object_fromint(o->watched),
			    "job", 0, false);
		if (o->method[0] != '\0')
			ucl_object_insert_key(e, ucl_object_fromstring(o->method),
			    "method", 0, false);
		if (o->url[0] != '\0')
			ucl_object_insert_key(e, ucl_object_fromstring(o->url),
			    "url", 0, false);
		if (o->error[0] != '\0')
			ucl_object_insert_key(e, ucl_object_fromstring(o->error),
			    "error", 0, false);
		if (o->diff != NULL && strlen(o->diff) < OPS_KEPT_TRACE)
			ucl_object_insert_key(e, ucl_object_fromstring(o->diff),
			    "diff", 0, false);
		/* A job's trace is its host's to give again. */
		if (o->trace != NULL && o->watched == 0 && (t = (char *)
		    ucl_object_emit(o->trace, UCL_EMIT_JSON_COMPACT)) != NULL) {
			if (strlen(t) < OPS_KEPT_TRACE)
				ucl_object_insert_key(e, ucl_object_ref(o->trace),
				    "trace", 0, false);
			free(t);
		}
		ucl_array_append(arr, e);
		n++;
	}
	json = (char *)ucl_object_emit(arr, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(arr);
	arc_store_set("arc_tasks", json != NULL ? json : "[]");
	free(json);
}

void
ops_load(void)
{
	struct op		*o;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr;
	char			*text;

	static bool	 loaded;

	/* Once: after what this page has done already, being older. */
	if (loaded)
		return;
	loaded = true;
	if ((text = arc_store_get("arc_tasks")) == NULL)
		return;
	arr = json_parse(text);
	free(text);
	if (arr == NULL)
		return;
	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL &&
	    app.nops < MAX_OPS) {
		if (jstr(e, "title") == NULL)
			continue;
		/* In the order they were kept: the oldest comes last. */
		o = &app.ops[app.nops++];
		memset(o, 0, sizeof(*o));
		o->id = ++app.nextop;
		snprintf(o->title, sizeof(o->title), "%s", jstr(e, "title"));
		snprintf(o->server, sizeof(o->server), "%s", jstr(e, "server") !=
		    NULL ? jstr(e, "server") : "");
		snprintf(o->sid, sizeof(o->sid), "%s", jstr(e, "sid") != NULL ?
		    jstr(e, "sid") : "");
		snprintf(o->method, sizeof(o->method), "%s", jstr(e, "method") !=
		    NULL ? jstr(e, "method") : "");
		snprintf(o->url, sizeof(o->url), "%s", jstr(e, "url") != NULL ?
		    jstr(e, "url") : "");
		snprintf(o->error, sizeof(o->error), "%s", jstr(e, "error") !=
		    NULL ? jstr(e, "error") : "");
		o->state = jbool(e, "ok") ? OP_OK : OP_FAILED;
		o->started = jnum(e, "started", 0);
		o->finished = jnum(e, "finished", 0);
		o->watched = jint(e, "job", 0);
		if (jstr(e, "diff") != NULL && (o->diff = strdup(jstr(e,
		    "diff"))) == NULL)
			abort();
		if (jget(e, "trace") != NULL)
			o->trace = ucl_object_copy(jget(e, "trace"));
	}
	ucl_object_unref(arr);
}

static ucl_object_t	*steps_trace(const ucl_object_t *);
static char		*job_path(char *, size_t, const char *, long long,
			    const char *);

static void
trace_fetch_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx	*c;
	struct op	*op;

	(void)err;
	c = arg;
	op = op_find(c->op);
	free(c);
	if (op == NULL || op->trace != NULL)
		return;
	if (status == 200 && jget(o, "step") != NULL)
		op->trace = steps_trace(jget(o, "step"));
	else
		snprintf(op->stage, sizeof(op->stage), "%s", status == 404 ?
		    "gone from its host" : "its host did not answer");
}

/*
 * A task opened whose trace is not here (a job kept over a reload of
 * the page): read from its host, which keeps its jobs.
 */
void
op_trace_fetch(struct op *op)
{
	struct ctx	*c;
	char		 url[300];

	if (op == NULL || op->trace != NULL || op->watched <= 0 ||
	    op->sid[0] == '\0' || op->state == OP_RUNNING)
		return;
	c = ctx_new();
	c->op = op->id;
	job_path(url, sizeof(url), op->sid, op->watched, "read");
	rc_read(url, NULL, NULL, trace_fetch_cb, c);
}

/*
 * A job of pkg's in a jail refused for allow.chflags (pkg sets the
 * base's files' flags: a conversion to pkgbase, or an upgrade or an
 * install of base packages in a jail on it): asked whether to allow it
 * on the running jail alone, not in its file and not in safe mode, then
 * the same job again once that is done.
 */
static struct {
	char	*again;		/* the job to send again */
	char	 sid[16];
	char	 jail[64];
	int	 allow_op;	/* the jail-allow's task, 0 none */
} chf;

static void
chflags_after(struct op *o, bool ok, const char *err)
{
	struct server	*s;
	ucl_object_t	*j;
	char		 body[512], title[160];
	char		*again;

	if (chf.allow_op != 0 && o->id == chf.allow_op) {
		chf.allow_op = 0;
		again = chf.again;
		chf.again = NULL;
		if (!ok || (s = server_by_id(chf.sid)) == NULL) {
			free(again);
			return;
		}
		snprintf(title, sizeof(title), "jail %s: pkg again "
		    "(allow.chflags now)", chf.jail);
		job_send(s, again, title, JOB_PACKAGES, chf.jail);
		return;
	}
	if (ok || err == NULL || strstr(err, "allow.chflags") == NULL ||
	    o->again == NULL || (strstr(o->again, "\"kind\":\"jail-base\"") ==
	    NULL && strstr(o->again, "\"kind\":\"pkg-upgrade\"") == NULL &&
	    strstr(o->again, "\"kind\":\"pkg-install\"") == NULL) ||
	    (j = json_parse(o->again)) == NULL)
		return;
	/* A jail's alone: the host's own pkg is not refused so. */
	if (jstr(j, "jail") == NULL || jstr(j, "jail")[0] == '\0') {
		ucl_object_unref(j);
		return;
	}
	free(chf.again);
	chf.again = strdup(o->again);
	snprintf(chf.sid, sizeof(chf.sid), "%s", o->sid);
	snprintf(chf.jail, sizeof(chf.jail), "%s", jstr(j, "jail") != NULL ?
	    jstr(j, "jail") : "");
	ucl_object_unref(j);
	snprintf(body, sizeof(body), "pkg needs to set flags on the base "
	    "system's files (chflags(2)), and jail %s may not "
	    "(allow.chflags=0). Allow it on the running jail now and run the "
	    "same again? Only for now: not kept in its file, so it is gone "
	    "at the jail's next start, and not in safe mode.", chf.jail);
	confirm("The jail may not set files' flags", body, "Allow now and "
	    "retry", false, "", "do-chflags-retry", chf.jail, "");
}

/* Approved: allow.chflags on the running jail alone, then the job. */
void
chflags_retry(struct server *s)
{
	char	*json, *qn, title[160];
	bool	 queued = app.queue_on;

	if (s == NULL || chf.again == NULL || strcmp(s->id, chf.sid) != 0)
		return;
	qn = json_quote(chf.jail);
	if (asprintf(&json, "{\"kind\":\"jail-allow\",\"jail\":%s,\"args\":"
	    "[\"allow.chflags=1\"],\"live\":true,\"persist\":false,"
	    "\"safe\":false}", qn) == -1)
		abort();
	free(qn);
	snprintf(title, sizeof(title), "jail %s allow.chflags (now, not kept)",
	    chf.jail);
	/* Approved as it is: sent now, the queue or not, so that the job
	 * follows it. */
	app.queue_on = false;
	job_send_host(s, json, title, JOB_JAIL, "jails");
	app.queue_on = queued;
	chf.allow_op = app.nops > 0 ? app.ops[0].id : 0;
}

void
op_done(struct op *o, bool ok, const ucl_object_t *reply, const char *err)
{
	const ucl_object_t	*t;

	if (o == NULL)
		return;
	o->state = ok ? OP_OK : OP_FAILED;
	o->finished = arc_now();
	/* A task that took a while is worth announcing. */
	if (o->finished - o->started >= NOTIFY_MS) {
		char body[256];

		snprintf(body, sizeof(body), "%s on %s: %s", o->title,
		    o->server, ok ? "done" : err != NULL ? err : "failed");
		arc_notify(ok ? "Arcana: done" : "Arcana: failed", body);
		/* And to the other devices that asked to be told. */
		arc_push_send(ok ? "Arcana: done" : "Arcana: failed", body);
	}
	if (reply != NULL && (t = jget(reply, "trace")) != NULL) {
		/* The whole trace, in place of the steps told live. */
		if (o->trace != NULL)
			ucl_object_unref(o->trace);
		o->trace = ucl_object_ref((ucl_object_t *)(uintptr_t)t);
	}
	if (err != NULL)
		snprintf(o->error, sizeof(o->error), "%s", err);
	chflags_after(o, ok, err);
}

/* Replace the jail of the same name in the server's list. */
static void
merge_jail(struct server *s, const ucl_object_t *j)
{
	ucl_object_t		*arr, *old;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*name;
	unsigned int		 i;

	if (s->list == NULL || j == NULL || (name = jstr(j, "name")) == NULL)
		return;
	arr = (ucl_object_t *)(uintptr_t)jget(s->list, "jails");
	if (arr == NULL)
		return;
	it = NULL;
	i = 0;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"),
		    name) == 0) {
			old = ucl_array_replace_index(arr,
			    ucl_object_ref((ucl_object_t *)(uintptr_t)j), i);
			if (old != NULL)
				ucl_object_unref(old);
			return;
		}
		i++;
	}
}

static void	job_finished(struct op *, bool, const char *);
static void	op_wait(int, int);

/* The job is over: what showed it as pending is cleared and re-read. */
static void
job_finished(struct op *op, bool ok, const char *err)
{
	struct server	*s;
	struct jailui	*ju;

	op->job = 0;
	if ((s = server_by_id(op->sid)) == NULL)
		return;
	if (s->jobs != NULL)
		refresh_jobs(s);
	if (op->what == JOB_WATCH)
		return;
	/* What a job changed is read again by the page: no tasks. */
	app.quiet = true;
	switch (op->what) {
	case JOB_JAIL:
	case JOB_ADDRESS:
		ju = jailui(s, op->target);
		ju->pending = PEND_NONE;
		ju->error[0] = '\0';
		if (!ok)
			snprintf(ju->error, sizeof(ju->error), "%s", err != NULL ?
			    err : "failed");
		s->loading = false;
		refresh_jails(s, false);
		break;
	case JOB_SERVICE:
		s->services_loading = false;
		if (s->services != NULL)
			refresh_services(s, false);
		if (strcmp(app.service, op->target) == 0)
			service_config(op->target);
		break;
	case JOB_SVC_OFF:
		/* Stopped: now not started at boot. */
		refresh_system(s, true);
		if (ok)
			sysview_svc_off(s, op->target);
		break;
	case JOB_KERNEL:
		refresh_kernel(s, true);
		break;
	case JOB_CERTS:
		refresh_certs(s, true);
		break;
	case JOB_SSH:
		refresh_ssh(s, true);
		break;
	case JOB_BUILDER:
		builder_refresh();
		break;
	case JOB_SECURITY:
		/* The host's plugins, and the page's read of them. */
		refresh_jails(s, false);
		secpage_refresh();
		break;
	case JOB_NETSTORE:
		naspage_refresh();
		break;
	case JOB_SYSTEM:
		refresh_system(s, true);
		refresh_ssh(s, false);
		break;
	case JOB_MAIL:
		/* Installed, the host's plugins say so too. */
		refresh_jails(s, false);
		mail_refresh();
		break;
	case JOB_RELAY:
		refresh_jails(s, false);
		relay_refresh();
		break;
	case JOB_MONITOR:
		monitors_refresh();
		tq_refresh();
		break;
	case JOB_PROCESS:
		refresh_procs(s, true);
		break;
	case JOB_SYSCTL:
		refresh_sysctl(s, true);
		break;
	case JOB_FIREWALL:
		firewall_job_done(op->title, ok, err);
		refresh_firewall(s, true);
		break;
	case JOB_STORAGE:
		refresh_storage(s, true);
		break;
	case JOB_IFACE:
		/* The interfaces as they are now, if they are on show. */
		if ((app.net.kind == NET_INTERFACES || app.net.kind ==
		    NET_ROUTES || app.net.kind >= NET_NETGRAPH) &&
		    strcmp(app.net.sid, s->id) == 0 && (app.node == NODE_HOST ||
		    net_scope()[0] != '\0'))
			refresh_network(s, false);
		/* And for the map, which draws its links from them. */
		topo_poll(s);
		break;
	default:
		/*
		 * A plugin's packages: the host says again what it has, and
		 * the plugin's tab reads once it does.
		 */
		if (ok && strncmp(op->title, "pkg install ", 12) == 0) {
			s->loading = false;
			refresh_jails(s, false);
		}
		app.pkg.busy = false;
		if (strcmp(app.pkg.sid, s->id) == 0 &&
		    strcmp(app.pkg.jail, op->target) == 0) {
			snprintf(app.pkg.result, sizeof(app.pkg.result),
			    "%s: pkg upgrade %s", op->target[0] != '\0' ?
			    op->target : "host", ok ? "finished" : "failed");
			refresh_packages(s, false);
		}
		if (!ok)
			osversion_ask(err, false, false);
		break;
	}
	app.quiet = false;
	toast(!ok, "%s: %s", op->title, ok ? "done" : err != NULL ? err :
	    "failed");
}

/*
 * A program's output as the trace shows it: binary's base64 decoded,
 * a byte not to be shown as vis(3)'s \ooo.
 */
static ucl_object_t *
step_output(const char *b64)
{
	static const char	 al[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
	    "opqrstuvwxyz0123456789+/";
	struct html		 h;
	const char		*p;
	unsigned int		 acc = 0;
	int			 bits = 0;
	unsigned char		 c;
	ucl_object_t		*o;

	memset(&h, 0, sizeof(h));
	h_raw(&h, "");
	for (; b64 != NULL && *b64 != '\0' && *b64 != '='; b64++) {
		if ((p = strchr(al, *b64)) == NULL)
			continue;
		acc = acc << 6 | (unsigned int)(p - al);
		if ((bits += 6) < 8)
			continue;
		bits -= 8;
		c = (unsigned char)(acc >> bits);
		if ((c < 0x20 && c != '\n' && c != '\t') || c == 0x7f)
			h_fmt(&h, "\\%03o", c);
		else if (c == '\\')
			h_raw(&h, "\\\\");
		else
			h_fmt(&h, "%c", c);
	}
	o = ucl_object_fromstring(h.s != NULL ? h.s : "");
	free(h.s);
	return (o);
}

/* arcana-jobs' steps as the trace has them. */
static ucl_object_t *
steps_trace(const ucl_object_t *steps)
{
	static const char *const map[] = { "id", "id", "parent", "parent",
	    "kind", "kind", "label", "label", "detail", "detail", "status",
	    "status", "duration", "duration_us", "argv", "argv", "exit",
	    "exit", NULL };
	const ucl_object_t	*e;
	ucl_object_t		*t, *r;
	ucl_object_iter_t	 it = NULL;

	/* Under the console's three, as a live read's (live.c): the
	 * request, the session checked, the call through the mount. */
	t = ucl_object_typed_new(UCL_ARRAY);
	for (int i = 0; i < 3; i++) {
		r = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(r, ucl_object_fromint(i), "id", 0, false);
		ucl_object_insert_key(r, ucl_object_fromint(i - 1 > 0 ? 0 :
		    i - 1), "parent", 0, false);
		ucl_object_insert_key(r, ucl_object_fromstring(i == 0 ? "api" :
		    i == 1 ? "auth" : "lib"), "kind", 0, false);
		ucl_object_insert_key(r, ucl_object_fromstring(i == 0 ?
		    "through the fleet mount" : i == 1 ? "session check" :
		    "RESTCONF arcana-jobs:jobs"), "label", 0, false);
		ucl_object_insert_key(r, ucl_object_fromstring("ok"), "status",
		    0, false);
		ucl_array_append(t, r);
	}
	while ((e = ucl_object_iterate(steps, &it, true)) != NULL) {
		r = jmap(e, map);
		ucl_object_replace_key(r, ucl_object_fromint(jint(e, "id", 0) +
		    3), "id", 0, false);
		ucl_object_replace_key(r, ucl_object_fromint(jint(e, "parent",
		    -1) < 0 ? 2 : jint(e, "parent", 0) + 3), "parent", 0, false);
		if (jget(e, "output") != NULL)
			ucl_object_insert_key(r, step_output(jstr(e, "output")),
			    "output", 0, false);
		if (jget(e, "error-output") != NULL)
			ucl_object_insert_key(r, step_output(jstr(e,
			    "error-output")), "error_output", 0, false);
		ucl_array_append(t, r);
	}
	return (t);
}

/* A job as the lists have it. */
static const char *const job_map[] = { "id", "id", "kind", "kind", "title",
    "title", "state", "state", "ok", "ok", "error", "error", "confirm-by",
    "confirm_by", "peer", "peer", "user", "user", "created", "created",
    "started", "started", "finished", "finished", NULL };

/* Where job id of host sid is, or its action act. */
static char *
job_path(char *buf, size_t len, const char *sid, long long id,
    const char *act)
{

	return (rc_h(buf, len, sid, "arcana-jobs:jobs/job=%lld%s%s", id,
	    act != NULL ? "/" : "", act != NULL ? act : ""));
}

/* A confirm's answer: the next read says where the job is. */
static void
job_confirm_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{

	(void)status;
	(void)o;
	(void)err;
	(void)arg;
}

static void
job_poll_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx		*c;
	struct op		*op;
	const ucl_object_t	*t;
	const char		*st;
	char			 url[300];
	bool			 ok;

	c = arg;
	op = op_find(c->op);
	free(c);
	if (op == NULL || op->job == 0)
		return;
	op->polling = false;
	op->next_poll = arc_now() + JOB_POLL_MS;
	if (status != 200 || o == NULL) {
		/* Gone from its host; else the console or the host is away,
		 * the job is not. */
		if (status == 404) {
			op_done(op, false, NULL, err);
			job_finished(op, false, err);
			return;
		}
		op->waiting = true;
		op->next_poll = arc_now() + 2 * JOB_POLL_MS;
		return;
	}
	op->waiting = false;
	if (jstr(o, "state") != NULL)
		snprintf(op->stage, sizeof(op->stage), "%s", jstr(o, "state"));
	/*
	 * A safe change the host waits to hear about: shown with the time
	 * it has, and confirmed (the console dials the host anew for it,
	 * the proof that it is still reached).
	 */
	op->confirm_by = jstr(o, "state") != NULL && strcmp(jstr(o, "state"),
	    "unconfirmed") == 0 ? jint(o, "confirm-by", 0) : 0;
	/*
	 * arcana-jobs' on-change subscription tells when it changes
	 * (sse.c): read then, and now and then; one waiting to be
	 * confirmed each second, as the host's timer runs.
	 */
	if (op->poll_again)
		op->next_poll = arc_now();
	else if (sse_jobs_up() && op->confirm_by == 0)
		op->next_poll = arc_now() + JOB_SAFE_MS;
	op->poll_again = false;
	if (op->confirm_by != 0) {
		job_path(url, sizeof(url), op->sid, op->job, "confirm");
		rc_read(url, NULL, NULL, job_confirm_cb, NULL);
	}
	if ((t = jget(o, "step")) != NULL) {
		if (op->trace != NULL)
			ucl_object_unref(op->trace);
		op->trace = steps_trace(t);
	}
	st = jstr(o, "state");
	if (st == NULL || (strcmp(st, "done") != 0 &&
	    strcmp(st, "cancelled") != 0))
		return;
	ok = strcmp(st, "done") == 0 && jbool(o, "ok");
	err = strcmp(st, "cancelled") == 0 ? "cancelled" : jstr(o, "error");
	op->state = ok ? OP_OK : OP_FAILED;
	op->finished = arc_now();
	if (!ok)
		snprintf(op->error, sizeof(op->error), "%s", err != NULL ? err :
		    "failed");
	{
		char	body[256];
		bool	not_undone;

		/* A safe change that was not confirmed and could not be
		 * taken back leaves the host changed: an alert, not a mere
		 * failure, here and on every device that is told. */
		not_undone = !ok && strstr(op->error, "could not be undone") !=
		    NULL;
		snprintf(body, sizeof(body), "%s on %s: %s", op->title,
		    op->server, ok ? "done" : op->error);
		if (not_undone)
			toast(true, "Not undone: %s on %s was not confirmed, "
			    "and the host could not take it back. Look at the "
			    "host: %s", op->title, op->server, op->error);
		/* Here, when it took a while; and every change that this
		 * browser asked for, to the other devices that are told. */
		if (not_undone || op->finished - op->started >= NOTIFY_MS)
			arc_notify(not_undone ? "Arcana: NOT UNDONE" : ok ?
			    "Arcana: done" : "Arcana: failed", body);
		if (op->what != JOB_WATCH || not_undone)
			arc_push_send(not_undone ? "Arcana: NOT UNDONE" : ok ?
			    "Arcana: done" : "Arcana: failed", body);
	}
	/* A job is over here, not in op_done: what follows from it. */
	chflags_after(op, ok, err);
	job_finished(op, ok, err);
}

/* Host sid's jobs changed (sse.c): its running ones read now, its Jobs
 * tab soon. */
void
jobs_changed(const char *sid)
{
	struct server	*s;
	struct op	*op;
	int		 i;

	for (i = 0; i < app.nops; i++) {
		op = &app.ops[i];
		if (op->job <= 0 || strcmp(op->sid, sid) != 0)
			continue;
		if (op->polling)
			op->poll_again = true;
		else
			op->next_poll = arc_now();
	}
	if ((s = server_by_id(sid)) != NULL && s == cur_server() &&
	    app.node == NODE_HOST && app.tab == TAB_JOBS)
		refresh_jobs(s);
	jobs_poll();
}

/* Read every running job that is due; called from the clock. */
void
jobs_poll(void)
{
	struct ctx	*c;
	struct op	*op;
	char		 url[300];
	double		 now;
	int		 i;

	if (!app.online)
		return;
	now = arc_now();
	for (i = 0; i < app.nops; i++) {
		op = &app.ops[i];
		if (op->job == 0 || op->polling || now < op->next_poll)
			continue;
		op->polling = true;
		c = ctx_new();
		c->op = op->id;
		job_path(url, sizeof(url), op->sid, op->job, "read");
		rc_read(url, NULL, NULL, job_poll_cb, c);
	}
}

struct submit {
	int	nops;
	int	ops[MAX_BATCH];
};

static void
job_submit_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct submit	*sub;
	struct op	*op;
	char		 path[32];
	int		 i;

	sub = arg;
	for (i = 0; i < sub->nops; i++) {
		if ((op = op_find(sub->ops[i])) == NULL)
			continue;
		snprintf(path, sizeof(path), "id.%d", i);
		if (status == 200 && jint(o, path, 0) > 0) {
			op->job = op->watched = jint(o, path, 0);
			op->next_poll = arc_now();
			snprintf(op->stage, sizeof(op->stage), "accepted");
			continue;
		}
		if (status == 200)
			err = "the host gave it no job number";
		op_done(op, false, NULL, err);
		op->job = -1;
		job_finished(op, false, err);
	}
	free(sub);
	jobs_poll();
}

/*
 * A job as the page makes it ({"kind": k, its fields, "safe"}) as
 * arcana-jobs' change: its fields in its kind's container, their _ as
 * -, safe beside it and, when the host's timer is not its agent's,
 * safe-wait.
 */
static void
job_change(struct html *b, const char *json, const struct server *s)
{
	const ucl_object_t	*v;
	ucl_object_t		*o, *f;
	ucl_object_iter_t	 it = NULL;
	char			 key[64], *p, *t;
	bool			 safe = false;

	if ((o = json_parse(json)) == NULL || jstr(o, "kind") == NULL) {
		h_raw(b, "{}");
		if (o != NULL)
			ucl_object_unref(o);
		return;
	}
	f = ucl_object_typed_new(UCL_OBJECT);
	while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
		if (strcmp(ucl_object_key(v), "kind") == 0)
			continue;
		if (strcmp(ucl_object_key(v), "safe") == 0) {
			safe = ucl_object_toboolean(v);
			continue;
		}
		snprintf(key, sizeof(key), "%s", ucl_object_key(v));
		for (p = key; (p = strchr(p, '_')) != NULL; p++)
			*p = '-';
		ucl_object_insert_key(f, ucl_object_copy(v), key, 0, true);
	}
	t = (char *)ucl_object_emit(f, UCL_EMIT_JSON_COMPACT);
	h_fmt(b, "{\"%s\":%s", jstr(o, "kind"), t != NULL ? t : "{}");
	free(t);
	if (safe) {
		h_raw(b, ",\"safe\":true");
		if (s->safe_wait > 0)
			h_fmt(b, ",\"safe-wait\":%d", s->safe_wait);
	}
	h_raw(b, "}");
	ucl_object_unref(f);
	ucl_object_unref(o);
}

/* Send the batch (n jobs, with an op each) to the server. */
static void
jobs_submit(struct server *s, struct queued *q, int n)
{
	struct submit	*sub;
	struct op	*op;
	struct html	 b;
	char		*body, url[300];
	int		 i, req;

	if ((sub = calloc(1, sizeof(*sub))) == NULL)
		abort();
	/* arcana-jobs' submit: a change each, in order. */
	memset(&b, 0, sizeof(b));
	h_raw(&b, "{\"change\":[");
	for (i = 0; i < n; i++) {
		if (i > 0)
			h_raw(&b, ",");
		job_change(&b, q[i].json, s);
	}
	h_raw(&b, "]}");
	body = h_take(&b);
	for (i = 0; i < n; i++) {
		op = op_new(q[i].title, s->name);
		snprintf(op->sid, sizeof(op->sid), "%s", s->id);
		op->what = q[i].what;
		snprintf(op->target, sizeof(op->target), "%s", q[i].target);
		/* Kept as it was sent, for when it fails and is tried again:
		 * but not one with a key in it, which is kept nowhere. */
		op->again = q[i].json != NULL && strstr(q[i].json,
		    "PRIVATE KEY") == NULL && strstr(q[i].json,
		    "\"preshared_key\"") == NULL ? strdup(q[i].json) : NULL;
		sub->ops[sub->nops++] = op->id;
		if (i == 0) {
			app.trace_op = op->id;
			app.trace_step = -1;
		}
	}
	rc_h(url, sizeof(url), s->id, "arcana-jobs:submit");
	/* One request for them all: each says it. */
	for (i = 0; i < sub->nops; i++)
		if ((op = op_find(sub->ops[i])) != NULL) {
			snprintf(op->method, sizeof(op->method), "POST");
			snprintf(op->url, sizeof(op->url), "%s", url);
			op->await = false;
		}
	req = rc_action(url, body, NULL, job_submit_cb, sub);
	for (i = 0; i < sub->nops; i++)
		op_wait(sub->ops[i], req);
	free(body);
}

/*
 * A change for the server, as the jobs API takes it: sent as a job now,
 * or held in the queue when queueing is on.  json is taken over.
 */
/* A change to the host's own network, though a jail's page asks it. */
static bool	on_host;

void
job_send_host(struct server *s, char *json, const char *title, int what,
    const char *target)
{

	on_host = true;
	job_send(s, json, title, what, target);
	on_host = false;
}

void
job_send(struct server *s, char *json, const char *title, int what,
    const char *target)
{
	struct queued	 q;
	const char	*scope;
	char		*in, *qj;

	/*
	 * A change to a network asked for on a jail's page is one to that
	 * jail's network: the job says so, and the host does it there.
	 */
	scope = on_host ? "" : net_scope();
	if (what == JOB_IFACE && scope[0] != '\0' && s == cur_server() &&
	    json[0] == '{') {
		qj = json_quote(scope);
		if (asprintf(&in, "{\"jail\":%s,%s", qj, json + 1) == -1)
			abort();
		free(qj);
		free(json);
		json = in;
	}
	memset(&q, 0, sizeof(q));
	q.json = json;
	if (what == JOB_IFACE && scope[0] != '\0' && s == cur_server())
		snprintf(q.title, sizeof(q.title), "%s: %s", scope, title);
	else
		snprintf(q.title, sizeof(q.title), "%s", title);
	q.what = what;
	snprintf(q.target, sizeof(q.target), "%s", target);
	snprintf(q.sid, sizeof(q.sid), "%s", s->id);
	snprintf(q.host, sizeof(q.host), "%s", s->name);
	if (app.queue_on) {
		if (app.nbatch == MAX_BATCH) {
			toast(true, "The queue holds %d changes at most",
			    MAX_BATCH);
			free(json);
			return;
		}
		app.batch[app.nbatch++] = q;
		toast(false, "Queued: %s", title);
		return;
	}
	jobs_submit(s, &q, 1);
	free(json);
}

/*
 * Several jobs for one host, chosen together: one batch, or as many
 * as the host takes at once, in the order given; into the queue when
 * the queue is on.  Takes the jobs' text.
 */
void
job_send_many(struct server *s, struct queued *q, int n, int what)
{
	int	i, k;

	for (i = 0; i < n; i++) {
		q[i].what = what;
		snprintf(q[i].sid, sizeof(q[i].sid), "%s", s->id);
		snprintf(q[i].host, sizeof(q[i].host), "%s", s->name);
	}
	if (app.queue_on) {
		for (i = 0; i < n; i++) {
			if (app.nbatch == MAX_BATCH) {
				toast(true, "The queue holds %d changes at "
				    "most: %d were not queued", MAX_BATCH,
				    n - i);
				for (; i < n; i++)
					free(q[i].json);
				return;
			}
			app.batch[app.nbatch++] = q[i];
		}
		toast(false, "Queued: %d changes", n);
		return;
	}
	for (i = 0; i < n; i += k) {
		k = n - i > MAX_BATCH ? MAX_BATCH : n - i;
		jobs_submit(s, q + i, k);
	}
	for (i = 0; i < n; i++)
		free(q[i].json);
	app.dock_open = true;
}

/*
 * A job that failed, sent again as it was: to the same host, with the
 * same words.  It goes into the queue when the queue is on.
 */
void
op_retry(int id)
{
	struct queued	 q;
	struct op	*o;
	int		 i;

	if ((o = op_find(id)) == NULL || o->again == NULL || o->state !=
	    OP_FAILED)
		return;
	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, o->sid) == 0)
			break;
	if (i == app.nservers) {
		toast(true, "The host it was for is no longer here");
		return;
	}
	memset(&q, 0, sizeof(q));
	q.json = strdup(o->again);
	snprintf(q.title, sizeof(q.title), "%s", o->title);
	q.what = o->what;
	snprintf(q.target, sizeof(q.target), "%s", o->target);
	snprintf(q.sid, sizeof(q.sid), "%s", app.servers[i].id);
	snprintf(q.host, sizeof(q.host), "%s", app.servers[i].name);
	if (app.queue_on) {
		if (app.nbatch == MAX_BATCH) {
			toast(true, "The queue holds %d changes at most",
			    MAX_BATCH);
			free(q.json);
			return;
		}
		app.batch[app.nbatch++] = q;
		toast(false, "Queued again: %s", q.title);
		return;
	}
	jobs_submit(&app.servers[i], &q, 1);
	free(q.json);
}

/* Send everything held, in the order it was added. */
void
queue_run(void)
{
	struct queued	 part[MAX_BATCH];
	struct server	*s;
	bool		 sent[MAX_BATCH];
	int		 i, k, n;

	/*
	 * Each host gets what was queued for it, as one batch, in the
	 * order it was added: whichever host is selected now.
	 */
	memset(sent, 0, sizeof(sent));
	for (i = 0; i < app.nbatch; i++) {
		if (sent[i])
			continue;
		n = 0;
		for (k = i; k < app.nbatch; k++)
			if (!sent[k] && strcmp(app.batch[k].sid,
			    app.batch[i].sid) == 0) {
				part[n++] = app.batch[k];
				sent[k] = true;
			}
		if ((s = server_by_id(app.batch[i].sid)) != NULL)
			jobs_submit(s, part, n);
		else
			toast(true, "%s is no longer a server: %d queued "
			    "change%s dropped", app.batch[i].host, n, n == 1 ?
			    "" : "s");
	}
	for (i = 0; i < app.nbatch; i++)
		free(app.batch[i].json);
	app.nbatch = 0;
	app.dock_open = true;
}

void
queue_clear(void)
{
	int	i;

	for (i = 0; i < app.nbatch; i++)
		free(app.batch[i].json);
	app.nbatch = 0;
}

static int	health_misses;

static void
health_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	/*
	 * One check without an answer is a hiccup: a busy moment, a
	 * connection the server closed.  It is asked again at once, and
	 * only a second miss says the console is away.
	 */
	if (status == 200) {
		health_misses = 0;
		app.api = LINK_UP;
	} else if (status != 429 && ++health_misses >= 2)
		app.api = LINK_DOWN;
	else if (status != 429)
		app.health_retry = arc_now() + HEALTH_RETRY_MS;
	/*
	 * Another version than the page was loaded from: the console was
	 * updated and has restarted.  The page loads itself again, to be
	 * the one that goes with it.
	 */
	if (status == 200 && jstr(o, "version") != NULL && app.version[0] !=
	    '\0' && strcmp(app.version, jstr(o, "version")) != 0) {
		arc_reload();
		return;
	}
	if (status == 200 && jstr(o, "version") != NULL)
		snprintf(app.version, sizeof(app.version), "%s",
		    jstr(o, "version"));
	if (status == 200)
		snprintf(app.agent_build, sizeof(app.agent_build), "%s",
		    jstr(o, "agent_build") != NULL ? jstr(o, "agent_build") :
		    "");
	if (status == 200) {
		snprintf(app.agent_version, sizeof(app.agent_version), "%s",
		    jstr(o, "agent_version") != NULL ? jstr(o,
		    "agent_version") : "");
		snprintf(app.agent_source, sizeof(app.agent_source), "%s%s%s",
		    jstr(o, "agent_source") != NULL ? jstr(o, "agent_source") :
		    "", jstr(o, "agent_ref") != NULL ? " at " : "",
		    jstr(o, "agent_ref") != NULL ? jstr(o, "agent_ref") : "");
	}
}

static void
update_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	app.update_latest[0] = '\0';
	if (status == 200 && jbool(o, "newer") && jstr(o, "latest") != NULL) {
		snprintf(app.update_latest, sizeof(app.update_latest), "%s",
		    jstr(o, "latest"));
		snprintf(app.update_url, sizeof(app.update_url), "%s",
		    jstr(o, "url") != NULL ? jstr(o, "url") : "");
	}
}

/* Is there a newer release?  The console asks the feed and remembers. */
void
check_update(void)
{

	rc_get(RC_C "update", NULL, update_cb, NULL);
}

void
check_health(void)
{

	if (!app.online) {
		app.api = LINK_UNKNOWN;
		return;
	}
	api("GET", "/api/health", NULL, health_cb, NULL);
}

void
servers_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	static struct server	 old[MAX_SERVERS];	/* big for a stack */
	struct server		*s, *p;
	const ucl_object_t	*a, *e;
	ucl_object_iter_t	 it;
	char			 selid[9];
	int			 nold, i;

	if (status != 200) {
		if (status == 0)
			check_health();
		if (status != 401)
			toast(true, "Servers: %s", err != NULL ? err :
			    "no answer");
		return;
	}
	/* Keep what is known about servers that are still there. */
	selid[0] = '\0';
	if (app.sel >= 0)
		snprintf(selid, sizeof(selid), "%s", app.servers[app.sel].id);
	memcpy(old, app.servers, sizeof(old));
	nold = app.nservers;
	memset(app.servers, 0, sizeof(app.servers));
	app.nservers = 0;
	/* arcana-console:hosts. */
	snprintf(app.local, sizeof(app.local), "%s", jstr(o, "local") != NULL ?
	    jstr(o, "local") : "");
	snprintf(app.local_agent, sizeof(app.local_agent), "%s", jstr(o,
	    "local-agent") != NULL ? jstr(o, "local-agent") : "");
	a = jget(o, "host");
	it = NULL;
	while ((e = ucl_object_iterate(a, &it, true)) != NULL &&
	    app.nservers < MAX_SERVERS) {
		s = &app.servers[app.nservers++];
		snprintf(s->id, sizeof(s->id), "%s", jstr(e, "id"));
		for (i = 0; i < nold; i++) {
			p = &old[i];
			if (p->id[0] != '\0' && strcmp(p->id, s->id) == 0) {
				*s = *p;
				p->id[0] = '\0';
				break;
			}
		}
		snprintf(s->name, sizeof(s->name), "%s", jstr(e, "name"));
		snprintf(s->uri, sizeof(s->uri), "%s", jstr(e, "uri"));
		snprintf(s->peer, sizeof(s->peer), "%s", jstr(e, "peer-name") !=
		    NULL ? jstr(e, "peer-name") : "");
		s->local = jbool(e, "local");
		s->safe_wait = (int)jint(e, "safe-wait", 0);
		s->sampling_off = jget(e, "sampled") != NULL && !jbool(e,
		    "sampled");
		s->mute = 0;
		{
			const ucl_object_t	*m;
			ucl_object_iter_t	 mit = NULL;
			const char		*mv;

			while ((m = ucl_object_iterate(jget(e, "notify-mute"),
			    &mit, true)) != NULL) {
				mv = ucl_object_tostring(m);
				s->mute |= mv == NULL ? 0 : strcmp(mv,
				    "utilization") == 0 ? MUTE_UTIL : strcmp(mv,
				    "sessions") == 0 ? MUTE_SESSIONS : strcmp(mv,
				    "all") == 0 ? MUTE_ALL : 0;
			}
		}
	}
	for (i = 0; i < nold; i++) {
		if (old[i].id[0] == '\0')
			continue;
		if (old[i].list != NULL)
			ucl_object_unref(old[i].list);
		if (old[i].services != NULL)
			ucl_object_unref(old[i].services);
		if (old[i].stats != NULL)
			ucl_object_unref(old[i].stats);
		if (old[i].jobs != NULL)
			ucl_object_unref(old[i].jobs);
		free(old[i].jui);
	}
	app.servers_loaded = true;
	app.sel = -1;
	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, selid) == 0)
			app.sel = i;
	if (app.sel < 0 && app.nservers > 0)
		app.sel = 0;
	/* Every host read once the page has them: in the background, as
	 * nobody asked for it, whatever page is shown. */
	for (i = 0; i < app.nservers; i++) {
		if (app.servers[i].list == NULL)
			refresh_jails(&app.servers[i], false);
		/* The fleet's cards and Devices show each host's use: read
		 * now, not at the next tick, ten seconds on. */
		if ((app.node == NODE_FLEET || app.node == NODE_DEVICES) &&
		    app.servers[i].stats == NULL)
			refresh_stats(&app.servers[i]);
	}
	/* What the page's address named, now that its host can be found. */
	loc_pending();
	plugins_servers();
}

/* arcana-console:hosts as last read: each host's entry, to change. */
static ucl_object_t	*hosts_rc;

static void
hosts_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	if (status == 200) {
		if (hosts_rc != NULL)
			ucl_object_unref(hosts_rc);
		hosts_rc = ucl_object_copy(o);
	}
	servers_cb(status, o, err, arg);
}

/* Host sid's entry as read; NULL: none. */
static const ucl_object_t *
host_rc(const char *sid)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;

	while ((e = ucl_object_iterate(jget(hosts_rc, "host"), &it, true)) !=
	    NULL)
		if (jstr(e, "id") != NULL && strcmp(jstr(e, "id"), sid) == 0)
			return (e);
	return (NULL);
}

/* A copy of host sid's configuration, to be changed and put; NULL:
 * not read. */
ucl_object_t *
host_conf(const char *sid)
{
	static const char *const state[] = { "local",
	    "notification-token-set", "sampled", "role" };
	const ucl_object_t	*e;
	ucl_object_t		*c;
	size_t			 i;

	if ((e = host_rc(sid)) == NULL)
		return (NULL);
	c = ucl_object_copy(e);
	for (i = 0; i < sizeof(state) / sizeof(state[0]); i++)
		ucl_object_delete_key(c, state[i]);
	return (c);
}

/* Host entry e (host_conf()'s, changed) put whole, e consumed. */
void
host_put(const char *sid, ucl_object_t *e, api_cb *cb, void *arg)
{
	ucl_object_t	*top, *a;
	unsigned char	*json;
	char		 url[200];

	a = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(a, e);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, a, "arcana-console:host", 0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	rc_edit("PUT", rc_c(url, sizeof(url), "hosts/host=%s", rc_key(sid)),
	    (const char *)json, cb, arg);
	free(json);
}

void
refresh_servers(void)
{
	char	url[200];

	rc_get(rc_c(url, sizeof(url), "hosts"), NULL, hosts_cb, NULL);
	/* Settings' rollback timer is told on each host's System tab. */
	if (app.settings == NULL)
		load_settings();
}

/* A jail of arcana-jails' as the pages have it. */
static ucl_object_t *
jail_row(const ucl_object_t *j)
{
	static const char *const map[] = { "name", "name", "state", "state",
	    "jid", "jid", "configured", "configured", "scope", "scope",
	    "hostname", "hostname", "path", "path", "ip4", "ip4", "ip6", "ip6",
	    "vnet", "vnet", "plugin", "plugins", "osrelease", "osrelease",
	    "persist", "persist", "boot", "boot", "allow", "allow",
	    "interface", "interface", "nproc", "nproc", "rss", "rss_kb", "cpu",
	    "cpu_pct", "securelevel", "securelevel", "children", "children",
	    NULL };
	static const char *const pmap[] = { "name", "key", "value", "values",
	    NULL };
	const ucl_object_t	*p;
	ucl_object_t		*r, *ps, *e;
	ucl_object_iter_t	 it = NULL;

	r = jmap(j, map);
	if (jstr(r, "state") == NULL)
		kput(r, "state", ucl_object_fromstring("unknown"));
	if (jget(r, "jid") == NULL)
		kput(r, "jid", ucl_object_typed_new(UCL_NULL));
	if (jget(r, "ip4") == NULL)
		kput(r, "ip4", ucl_object_typed_new(UCL_ARRAY));
	if (jget(r, "ip6") == NULL)
		kput(r, "ip6", ucl_object_typed_new(UCL_ARRAY));
	ps = ucl_object_typed_new(UCL_ARRAY);
	while ((p = ucl_object_iterate(jget(j, "param"), &it, true)) != NULL) {
		e = jmap(p, pmap);
		if (jget(e, "values") == NULL)
			kput(e, "values", ucl_object_typed_new(UCL_ARRAY));
		ucl_array_append(ps, e);
	}
	kput(r, "params", ps);
	/* Earlier jails of its name, dying: their jids and roots. */
	if (jget(j, "dying") != NULL)
		kput(r, "dying", ucl_object_copy(jget(j, "dying")));
	return (r);
}

/*
 * The host as its list has it, of arcana-host's host: its agent's
 * version, build, timer and features beside the host's own.
 */
static ucl_object_t *
host_row(const ucl_object_t *h)
{
	static const char *const map[] = { "hostname", "hostname", "sysname",
	    "sysname", "release", "release", "machine", "machine", "ncpu",
	    "ncpu", "physmem", "physmem", "securelevel", "securelevel",
	    "privileged", "privileged", "reboot-required", "reboot_required",
	    "agent.version", "version", "agent.build", "build",
	    "agent.safe-wait", "safe_wait", "agent.feature", "features", NULL };
	const ucl_object_t	*p;
	ucl_object_t		*r, *pl;
	ucl_object_iter_t	 it = NULL;
	const char		*n;

	r = jmap(h, map);
	kput(r, "boottime", ucl_object_fromint(rc_time(jstr(h, "boot-time"))));
	kput(r, "time", ucl_object_fromint(rc_time(jstr(h, "time"))));
	if (jget(r, "features") == NULL)
		kput(r, "features", ucl_object_typed_new(UCL_ARRAY));
	/* Its plugins by their names, without their identities' module. */
	pl = ucl_object_typed_new(UCL_ARRAY);
	while ((p = ucl_object_iterate(jget(h, "plugin"), &it, true)) !=
	    NULL) {
		n = ucl_object_tostring_forced(p);
		ucl_array_append(pl, ucl_object_fromstring(strchr(n, ':') !=
		    NULL ? strchr(n, ':') + 1 : n));
	}
	kput(r, "plugins", pl);
	return (r);
}

static void	jails_host_cb(int, const ucl_object_t *, const char *, void *);

/* arcana-jails' jails read: the host's own asked next. */
static void
jails_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx		*c = arg;
	struct server		*s;
	const ucl_object_t	*e;
	ucl_object_t		*l, *rows, *errs;
	ucl_object_iter_t	 it = NULL;

	if (status != 200 || (s = server_by_id(c->sid)) == NULL) {
		jails_host_cb(status, NULL, err, c);
		return;
	}
	l = ucl_object_typed_new(UCL_OBJECT);
	rows = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(jget(o, "jail"), &it, true)) != NULL)
		ucl_array_append(rows, jail_row(e));
	kput(l, "jails", rows);
	kput(l, "scopes", jget(o, "scope") != NULL ? ucl_object_copy(jget(o,
	    "scope")) : ucl_object_typed_new(UCL_ARRAY));
	errs = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(jget(o, "conf-error"), &it, true)) !=
	    NULL)
		ucl_array_append(errs, ucl_object_copy(e));
	kput(l, "conf_errors", errs);
	c->held = l;
	host_yread(s, "arcana-host:host", NULL, NULL, false, jails_host_cb, c);
}

static void
jails_host_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx	*c;
	struct server	*s;
	struct op	*op;

	c = arg;
	op = c->op != 0 ? op_find(c->op) : NULL;
	if ((s = server_by_id(c->sid)) == NULL) {
		if (c->held != NULL)
			ucl_object_unref(c->held);
		free(c);
		return;
	}
	s->loading = false;
	/* Given up here: that says nothing about the host. */
	if (status == 0 && err != NULL && strcmp(err, "cancelled") == 0) {
		op_done(op, false, NULL, err);
		if (c->held != NULL)
			ucl_object_unref(c->held);
		free(c);
		return;
	}
	if (status == 200 && c->held != NULL) {
		if (s->list != NULL)
			ucl_object_unref(s->list);
		kput(c->held, "host", host_row(o));
		s->list = c->held;
		c->held = NULL;
		s->fetched = arc_now();
		s->failed = false;
		s->error[0] = '\0';
		op_done(op, true, NULL, NULL);
	} else {
		if (c->held != NULL)
			ucl_object_unref(c->held);
		/* Whether the console is away is the health check's to say. */
		if (status == 0)
			check_health();
		s->failed = true;
		snprintf(s->error, sizeof(s->error), "%s", err != NULL ? err :
		    "no answer from the console");
		op_done(op, false, o, s->error);
		if (c->user)
			toast(true, "%s: %s", s->name, s->error);
	}
	free(c);
}

/*
 * Fetch the jails of a server.  A read the user asked for (opening the
 * host or its Jails tab, Refresh) is a task with its trace, even with a
 * periodic one on its way; the periodic ones are not.
 */
void
refresh_jails(struct server *s, bool user)
{
	struct ctx	*c;
	struct op	*op;

	if (!app.online || (s->loading && !user))
		return;
	if (!s->loading)
		s->loading_since = arc_now();
	s->loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	c->user = user = user && !app.quiet;
	/* Asked for: a task, its steps drawn as the host takes them. */
	if (user) {
		op = op_new("list jails", s->name);
		c->op = op->id;
	}
	host_yread(s, "arcana-jails:jails", NULL, NULL, user, jails_cb, c);
}

struct hrc {
	api_cb	*cb;
	void	*arg;
	char	 sid[9];
	int	 op;		/* the task it made, read live */
};

/* A module the host's agent lacks (its own schema's 404), said so. */
static void
hrc_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct hrc		 h = *(struct hrc *)arg;
	const struct server	*s;
	const char		*m, *v;
	char			 why[400];
	int			 i;

	free(arg);
	if (status == 404 && err != NULL && (m = strstr(err, "modules have no "))
	    != NULL) {
		m += strlen("modules have no ");
		for (i = 0, v = NULL; i < app.nservers && v == NULL; i++) {
			s = &app.servers[i];
			if (strcmp(s->id, h.sid) == 0)
				v = jstr(s->list, "host.version");
		}
		snprintf(why, sizeof(why), "%.*s needs a newer arcana-agent "
		    "than this host's%s%s", (int)strcspn(m, " (\""), m, v !=
		    NULL ? " " : "", v != NULL ? v : "");
		err = why;
	}
	h.cb(status, o, err, h.arg);
	/* Its task, over the socket: ended here. */
	if (h.op != 0)
		op_done(op_find(h.op), status >= 200 && status < 300, NULL,
		    err);
}

/*
 * A read of host s's through the fleet mount: path below its entry
 * ("arcana-kernel:kernel", a query after ?), or, with input, the read
 * action there.  The callback gets the node or the action's output.  One
 * the user asked for is a task called title (NULL: the one just made),
 * read over the console's socket, its steps drawn as the host takes
 * them; the others a plain read.
 */
void
host_yread(const struct server *s, const char *path, const char *input,
    const char *title, bool user, api_cb *cb, void *arg)
{
	struct hrc	*h;
	struct op	*op;
	char		 url[512], q[400];
	size_t		 n;

	if ((h = calloc(1, sizeof(*h))) == NULL)
		abort();
	h->cb = cb;
	h->arg = arg;
	snprintf(h->sid, sizeof(h->sid), "%s", s->id);
	n = strcspn(path, "?");
	snprintf(q, sizeof(q), "%s", path[n] == '?' ? path + n + 1 : "");
	rc_h(url, sizeof(url), s->id, "%.*s", (int)n, path);
	if (user && !app.quiet) {
		op = title != NULL ? op_new(title, s->name) : app.nops > 0 &&
		    app.ops[0].await ? &app.ops[0] : NULL;
		if (op != NULL) {
			h->op = title != NULL ? op->id : 0;
			rc_live(s->id, path, input, op->id, hrc_cb, h);
			return;
		}
	}
	if (input != NULL)
		rc_read(url, input, q[0] != '\0' ? q : NULL, hrc_cb, h);
	else
		rc_get(url, q[0] != '\0' ? q : NULL, hrc_cb, h);
}

/*
 * A jail started at boot or not: arcana-jails' boot in the host's
 * candidate (RFC 8527), committed confirmed (ycommit.c); a warning the
 * host stops at, offered to be accepted on the jail's card.  The jails
 * read again once it is saved or undone.
 */
static struct ycommit jail_yc = {
	.act = "jail-yc",
	.saved = "Saved: Arcana's rc.conf file has it (jail_list).",
	.undone = "Undone: started at boot as it was.",
};
static char jail_yc_name[256];

static void
jail_saved(struct ycommit *yc, int how)
{
	struct server	*s;

	if (how == YC_REFUSED || (s = server_by_id(yc->sid)) == NULL)
		return;
	s->loading = false;
	refresh_jails(s, false);
}

static void
jail_boot(struct server *s, const char *jail, bool on)
{
	char	url[600], *qj, *body;

	if (!url_word(jail)) {
		toast(true, "%s: not a jail's name", jail);
		return;
	}
	snprintf(url, sizeof(url), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s/arcana-jails:jails/jail=%s", s->id,
	    jail);
	qj = json_quote(jail);
	if (asprintf(&body, "{\"arcana-jails:jail\":[{\"name\":%s,"
	    "\"boot\":%s}]}", qj, on ? "true" : "false") == -1)
		abort();
	free(qj);
	jail_yc.done = jail_saved;
	if (ycommit_save(&jail_yc, s->id, "PATCH", url, body))
		snprintf(jail_yc_name, sizeof(jail_yc_name), "%s", jail);
	else
		toast(true, "A change of the configuration is on its way");
	free(body);
}

/* How the commit of jail's boot went, on its card and its page. */
void
jail_commit_note(struct html *h, const struct server *s, const char *jail)
{

	if (strcmp(jail_yc.sid, s->id) == 0 && strcmp(jail_yc_name,
	    jail) == 0)
		ycommit_note(h, &jail_yc);
}

bool
jail_commit_action(const char *act)
{

	return (ycommit_action(&jail_yc, act));
}

void
jail_commit_tick(double now)
{

	ycommit_tick(&jail_yc, now);
}

/*
 * start, stop, restart or kill a jail of the selected server: a job;
 * enable or disable, its boot committed.
 */
void
jail_action(const char *jail, const char *action)
{
	struct server	*s;
	char		 title[160], *qj, *json;

	if ((s = cur_server()) == NULL)
		return;
	if (strcmp(action, "enable") == 0 || strcmp(action, "disable") == 0) {
		jail_boot(s, jail, strcmp(action, "enable") == 0);
		return;
	}
	snprintf(title, sizeof(title), "%s %s", action, jail);
	qj = json_quote(jail);
	if (asprintf(&json, "{\"kind\":\"jail-action\",\"jail\":%s,"
	    "\"action\":\"%s\"}", qj, action) == -1)
		abort();
	free(qj);
	if (!app.queue_on) {
		jailui(s, jail)->pending = strcmp(action, "start") == 0 ?
		    PEND_START : strcmp(action, "stop") == 0 ? PEND_STOP :
		    strcmp(action, "restart") == 0 ? PEND_RESTART : PEND_KILL;
		jailui(s, jail)->error[0] = '\0';
	}
	job_send(s, json, title, JOB_JAIL, jail);
}

static const char *const svc_map[] = { "name", "name", "path", "path",
    "rcvar", "rcvar", "enabled", "enabled", "running", "running", "pid",
    "pid", "status", "status", NULL };

static void
services_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx	*c;
	struct server	*s;
	struct op	*op;

	c = arg;
	op = c->op != 0 ? op_find(c->op) : NULL;
	if ((s = server_by_id(c->sid)) == NULL) {
		free(c);
		return;
	}
	s->services_loading = false;
	if (status == 200) {
		if (s->services != NULL)
			ucl_object_unref(s->services);
		/* arcana-services' list as the tab draws it. */
		s->services = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(s->services, jmap_each(jget(o, "service"),
		    svc_map), "services", 0, false);
		s->services_fetched = arc_now();
		s->services_error[0] = '\0';
		op_done(op, true, NULL, NULL);
	} else {
		snprintf(s->services_error, sizeof(s->services_error), "%s",
		    err != NULL ? err : "no answer from the console");
		op_done(op, false, o, s->services_error);
		if (c->user)
			toast(true, "%s: %s", s->name, s->services_error);
	}
	free(c);
}

/* The rc.d services of a server; a manual refresh goes into the log. */
void
refresh_services(struct server *s, bool user)
{
	struct ctx	*c;
	struct op	*op;

	if (!app.online || s->services_loading)
		return;
	s->services_loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	c->user = user = user && !app.quiet;
	if (user) {
		op = op_new("list services", s->name);
		c->op = op->id;
		app.trace_op = op->id;
	}
	host_yread(s, "arcana-services:services", NULL, NULL, user,
	    services_cb, c);
}

/* Replace the service of the same name in the server's list. */
static void
merge_service(struct server *s, const ucl_object_t *j)
{
	ucl_object_t		*arr, *old;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*name;
	unsigned int		 i;

	if (s->services == NULL || j == NULL || (name = jstr(j, "name")) ==
	    NULL)
		return;
	arr = (ucl_object_t *)(uintptr_t)jget(s->services, "services");
	it = NULL;
	i = 0;
	while (arr != NULL && (e = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"),
		    name) == 0) {
			old = ucl_array_replace_index(arr,
			    ucl_object_ref((ucl_object_t *)(uintptr_t)j), i);
			if (old != NULL)
				ucl_object_unref(old);
			return;
		}
		i++;
	}
}

/* start, stop, restart or reload a service: a job. */
void
service_action(const char *name, const char *action)
{
	struct server	*s;
	char		 title[160], *qn, *json;

	if ((s = cur_server()) == NULL)
		return;
	/* Started at boot or not: its configuration, committed. */
	if (strcmp(action, "enable") == 0 || strcmp(action, "disable") == 0) {
		service_enable(s, name, strcmp(action, "enable") == 0);
		return;
	}
	snprintf(title, sizeof(title), "service %s %s", name, action);
	qn = json_quote(name);
	if (asprintf(&json, "{\"kind\":\"service-action\",\"service\":%s,"
	    "\"action\":\"%s\"}", qn, action) == -1)
		abort();
	free(qn);
	job_send(s, json, title, JOB_SERVICE, name);
}

/* A service's variables, as running has them: into the drawer's. */
static void
svc_vars_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*v;
	ucl_object_t		*vars;
	ucl_object_iter_t	 it = NULL;
	char			*name = arg;

	(void)err;
	if (status == 200 && app.svc_config != NULL && strcmp(app.service,
	    name) == 0 && (vars = (ucl_object_t *)(uintptr_t)jget(
	    app.svc_config, "variables")) != NULL)
		while ((v = ucl_object_iterate(jget(o, "variable"), &it,
		    true)) != NULL)
			if (jstr(v, "name") != NULL)
				ucl_object_insert_key(vars, ucl_object_fromstring(
				    jstr(v, "value") != NULL ? jstr(v, "value") :
				    ""), jstr(v, "name"), 0, true);
	free(name);
}

static void
service_config_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{
	struct ctx	*c;
	struct server	*s;
	struct op	*op;
	ucl_object_t	*sv;
	char		 url[512], path[300];
	bool		 ok;

	c = arg;
	op = c->op != 0 ? op_find(c->op) : NULL;
	app.svc_loading = false;
	ok = status == 200 && o != NULL;
	op_done(op, ok, NULL, err);
	if (ok && strcmp(app.service, c->jail) == 0) {
		/* Its read's output as the drawer draws it; its variables
		 * as running has them, read next. */
		if (app.svc_config != NULL)
			ucl_object_unref(app.svc_config);
		app.svc_config = ucl_object_typed_new(UCL_OBJECT);
		sv = jmap(o, svc_map);
		ucl_object_insert_key(sv, ucl_object_fromstring(c->jail),
		    "name", 0, true);
		ucl_object_insert_key(app.svc_config, sv, "service", 0, false);
		if (jstr(o, "description") != NULL)
			ucl_object_insert_key(app.svc_config,
			    ucl_object_fromstring(jstr(o, "description")),
			    "description", 0, false);
		ucl_object_insert_key(app.svc_config, jget(o, "command") !=
		    NULL ? ucl_object_copy(jget(o, "command")) :
		    ucl_object_typed_new(UCL_ARRAY), "commands", 0, false);
		ucl_object_insert_key(app.svc_config, ucl_object_typed_new(
		    UCL_OBJECT), "variables", 0, false);
		snprintf(path, sizeof(path), "arcana-services:services/"
		    "service=%s", rc_key(c->jail));
		rc_get(rc_ds(url, sizeof(url), "running", c->sid, path), NULL,
		    svc_vars_cb, strdup(c->jail));
		if ((s = server_by_id(c->sid)) != NULL)
			merge_service(s, sv);
	}
	snprintf(app.svc_error, sizeof(app.svc_error), "%s", ok ? "" :
	    err != NULL ? err : "failed");
	free(c);
}

/* A service's rc.conf variables, read. */
void
service_config(const char *name)
{
	struct server	*s;
	struct ctx	*c;
	struct op	*op;
	char		 url[512], title[160];

	if ((s = cur_server()) == NULL)
		return;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->jail, sizeof(c->jail), "%s", name);
	snprintf(title, sizeof(title), "service %s config", name);
	op = op_new(title, s->name);
	c->op = op->id;
	app.trace_op = op->id;
	app.svc_loading = true;
	app.svc_error[0] = '\0';
	/* A name goes into the address as it is: none that changes it. */
	if (!url_word(name)) {
		op_done(op, false, NULL, "not a service's name");
		free(c);
		return;
	}
	snprintf(url, sizeof(url), "arcana-services:services/service=%s/read",
	    rc_key(name));
	host_yread(s, url, "{}", NULL, false, service_config_cb, c);
}

/*
 * A service's configuration changed (arcana-services): its entry in the
 * host's candidate edited (RFC 8527), committed confirmed (ycommit.c);
 * a warning the host stops at, offered to be accepted in the drawer.
 * The services read again once it is saved or undone.
 */
static struct ycommit svc_yc = {
	.act = "svc-yc",
	.saved = "Saved: Arcana's rc.conf file has it.",
	.undone = "Undone: the service's configuration is as it was.",
};
static char svc_yc_name[64];

static void
svc_saved(struct ycommit *yc, int how)
{
	struct server	*s;

	if (how == YC_REFUSED || (s = server_by_id(yc->sid)) == NULL)
		return;
	if (s->services != NULL)
		refresh_services(s, false);
	if (s == cur_server() && strcmp(app.service, svc_yc_name) == 0)
		service_config(svc_yc_name);
}

/*
 * Service name's entry of host sid's candidate (tail below it), method
 * with body: the edit, then the commit.  Its own commit, done its way
 * (NULL: the drawer's).
 */
bool
service_commit(const char *sid, const char *name, const char *method,
    const char *tail, const char *body, struct ycommit *yc)
{
	char	url[400];

	if (!url_word(name)) {
		toast(true, "%s: not a service's name", name);
		return (false);
	}
	snprintf(url, sizeof(url), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s/arcana-services:services/service=%s%s",
	    sid, name, tail != NULL ? tail : "");
	if (yc == NULL) {
		yc = &svc_yc;
		yc->done = svc_saved;
		snprintf(svc_yc_name, sizeof(svc_yc_name), "%s", name);
	}
	if (!ycommit_save(yc, sid, method, url, body)) {
		toast(true, "A change of the configuration is on its way");
		return (false);
	}
	return (true);
}

/* Started at boot or not: its rcvar, arcana-services' enabled. */
void
service_enable(struct server *s, const char *name, bool on)
{
	char	*qn, *body;

	qn = json_quote(name);
	if (asprintf(&body, "{\"arcana-services:service\":[{\"name\":%s,"
	    "\"enabled\":%s}]}", qn, on ? "true" : "false") == -1)
		abort();
	free(qn);
	(void)service_commit(s->id, name, "PATCH", NULL, body, NULL);
	free(body);
}

/* Its variables set: {"key": "value", ...}, merged into its own. */
void
service_set_vars(struct server *s, const char *name, const ucl_object_t *set)
{
	ucl_object_t		*top, *e, *vars, *v;
	const ucl_object_t	*x;
	ucl_object_iter_t	 it = NULL;
	char			*body;

	vars = ucl_object_typed_new(UCL_ARRAY);
	while ((x = ucl_object_iterate(set, &it, true)) != NULL) {
		v = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(v, ucl_object_fromstring(
		    ucl_object_key(x)), "name", 0, true);
		ucl_object_insert_key(v, ucl_object_fromstring(
		    ucl_object_tostring_forced(x)), "value", 0, true);
		ucl_array_append(vars, v);
	}
	e = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(e, ucl_object_fromstring(name), "name", 0, true);
	ucl_object_insert_key(e, vars, "variable", 0, true);
	top = ucl_object_typed_new(UCL_OBJECT);
	v = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(v, e);
	ucl_object_insert_key(top, v, "arcana-services:service", 0, true);
	body = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	(void)service_commit(s->id, name, "PATCH", NULL, body, NULL);
	free(body);
}

/* One variable unset: taken out of its entry. */
void
service_unset_var(struct server *s, const char *name, const char *key)
{
	char	tail[160];

	if (!url_word(key)) {
		toast(true, "%s: not a variable's name", key);
		return;
	}
	snprintf(tail, sizeof(tail), "/variable=%s", key);
	(void)service_commit(s->id, name, "DELETE", tail, NULL, NULL);
}

/* The drawer's commit: how it went, its buttons and its countdown. */
void
service_commit_note(struct html *h)
{
	const struct server	*s = cur_server();

	if (s != NULL && strcmp(svc_yc.sid, s->id) == 0 &&
	    strcmp(svc_yc_name, app.service) == 0)
		ycommit_note(h, &svc_yc);
}

bool
service_commit_action(const char *act)
{

	return (ycommit_action(&svc_yc, act));
}

void
service_commit_tick(double now)
{

	ycommit_tick(&svc_yc, now);
}

static const char *const stats_map[] = { "cpu", "cpu_pct", "load1",
    "load1", "load5", "load5", "load15", "load15", "memory-total",
    "mem_total", "memory-used", "mem_used", "memory-inactive",
    "mem_inactive", "memory-free", "mem_free", "swap-total", "swap_total",
    "swap-used", "swap_used", NULL };
static const char *const pool_map[] = { "name", "name", "size", "size",
    "allocated", "alloc", "free", "free", "health", "health", NULL };

static void
stats_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx		*c;
	struct server		*s;

	c = arg;
	if ((s = server_by_id(c->sid)) != NULL) {
		s->stats_loading = false;
		if (status == 200 && o != NULL)
			stats_take(s, o);
	}
	free(c);
}

/* arcana-host's stats of host s, read or pushed (sse.c): its sample. */
void
stats_take(struct server *s, const ucl_object_t *o)
{
	const ucl_object_t	*st, *p;
	ucl_object_t		*sm;
	ucl_object_iter_t	 it;
	double			 total, alloc, size, used;
	int			 i;

	if (s->stats != NULL)
		ucl_object_unref(s->stats);
	/* arcana-host's stats as the cards draw them. */
	s->stats = ucl_object_typed_new(UCL_OBJECT);
	sm = jmap(o, stats_map);
	ucl_object_insert_key(sm, jmap_each(jget(o, "pool"), pool_map),
	    "pools", 0, false);
	ucl_object_insert_key(s->stats, sm, "stats", 0, false);
	st = sm;
	s->stats_fetched = arc_now();
	/* One sample each: CPU %, memory in use %, ZFS allocated %. */
	if (s->nhist == HISTORY) {
		for (i = 0; i < 3; i++)
			memmove(&s->hist[i][0], &s->hist[i][1],
			    (HISTORY - 1) * sizeof(float));
		s->nhist--;
	}
	total = jnum(st, "mem_total", 0);
	used = jnum(st, "mem_used", 0);
	alloc = size = 0;
	it = NULL;
	while ((p = ucl_object_iterate(jget(st, "pools"), &it, true)) != NULL) {
		alloc += jnum(p, "alloc", 0);
		size += jnum(p, "size", 0);
	}
	s->hist[0][s->nhist] = (float)jnum(st, "cpu_pct", 0);
	s->hist[1][s->nhist] = total > 0 ? (float)(100 * used / total) : 0;
	s->hist[2][s->nhist] = size > 0 ? (float)(100 * alloc / size) : 0;
	s->nhist++;
}

static const char *const jobs_map[] = { "lanes", "lanes", "stopping",
    "stopping", NULL };
static void	lanes_saved(struct ycommit *, int);
static struct ycommit lanes_yc = { .act = "lanes-yc", .saved = "Saved: the "
    "host runs so many at once.", .undone = "Undone: the lanes are as "
    "they were.", .done = lanes_saved };
static int lanes_n;

static void
jobs_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx	*c;
	struct server	*s;

	c = arg;
	if ((s = server_by_id(c->sid)) != NULL) {
		s->jobs_loading = false;
		if (status == 200 && o != NULL) {
			/* arcana-jobs' list as the tab draws it. */
			if (s->jobs != NULL)
				ucl_object_unref(s->jobs);
			s->jobs = jmap(o, jobs_map);
			ucl_object_insert_key(s->jobs, jmap_each(jget(o, "job"),
			    job_map), "jobs", 0, false);
		}
	}
	free(c);
}

/* The lanes saved, or not: said, and the record read again. */
static void
lanes_saved(struct ycommit *yc, int how)
{
	struct server	*s;

	if ((s = server_by_id(yc->sid)) == NULL)
		return;
	if (how == YC_SAVED)
		toast(false, "%s: pkg in jails, %d at once", s->name, lanes_n);
	else if (how == YC_REFUSED)
		toast(true, "%s: lanes not set: %s", s->name, yc->note);
	s->jobs_loading = false;
	refresh_jobs(s);
}

/* How many jobs of pkg in jails the host runs at once: 1 to 32;
 * arcana-jobs' lanes, committed. */
void
set_job_lanes(struct server *s, int lanes)
{
	char	url[300], body[64];

	if (lanes < 1 || lanes > 32) {
		toast(true, "%s: lanes is 1 to 32", s->name);
		return;
	}
	lanes_n = lanes;
	rc_ds(url, sizeof(url), "candidate", s->id, "arcana-jobs:jobs");
	snprintf(body, sizeof(body), "{\"arcana-jobs:jobs\":{\"lanes\":%d}}",
	    lanes);
	if (!ycommit_save(&lanes_yc, s->id, "PATCH", url, body))
		toast(true, "%s: a change of the lanes is on its way already",
		    s->name);
}

/* The host's own record of jobs, whoever queued them; quiet. */
void
refresh_jobs(struct server *s)
{
	struct ctx	*c;

	if (!app.online || s->jobs_loading)
		return;
	s->jobs_loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	host_yread(s, "arcana-jobs:jobs", NULL, NULL, false, jobs_cb, c);
}

/* Show a job of the host in the activity dock, and follow it. */
void
open_job(struct server *s, long long id, const char *title)
{
	struct op	*op;
	int		 i;

	for (i = 0; i < app.nops; i++)
		if (strcmp(app.ops[i].sid, s->id) == 0 &&
		    app.ops[i].watched == id)
			break;
	if (i < app.nops)
		op = &app.ops[i];
	else {
		op = op_new(title, s->name);
		snprintf(op->sid, sizeof(op->sid), "%s", s->id);
		op->what = JOB_WATCH;
		op->job = op->watched = id;
		op->next_poll = arc_now();
	}
	app.trace_op = op->id;
	app.trace_step = -1;
	app.dock_open = true;
	jobs_poll();
}

/* A usage sample from the server; quiet, no log entry. */
void
refresh_stats(struct server *s)
{
	struct ctx	*c;

	if (!app.online || s->stats_loading)
		return;
	s->stats_loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	host_yread(s, "arcana-host:host/stats", NULL, NULL, false, stats_cb,
	    c);
}

/*
 * pkg refused packages built for a newer FreeBSD than the host's: the
 * same asked again past OSVERSION, once it is approved.  A read (the
 * pending upgrades) asks once a session for the host or jail, then
 * reads past it; an upgrade or a dry run asks each time.
 */
static void
osversion_ask(const char *err, bool dry_run, bool read)
{
	char	body[700];

	if (err == NULL || strstr(err, "OSVERSION") == NULL)
		return;
	if (read) {
		if (app.pkg.asked)
			return;
		app.pkg.asked = true;
		snprintf(body, sizeof(body), "pkg refused: the repository's "
		    "packages are built for a newer FreeBSD than %s runs (its "
		    "OSVERSION is lower than theirs), so what is pending cannot "
		    "be read. Read past it with IGNORE_OSVERSION=yes? Upgrading "
		    "asks again.", app.pkg.jail[0] != '\0' ? app.pkg.jail :
		    "this host");
		confirm("Packages for a newer FreeBSD", body, "Read anyway", true,
		    "", "do-pkg-read-anyos", "", "");
		return;
	}
	snprintf(body, sizeof(body), "pkg refused: the repository's packages "
	    "are built for a newer FreeBSD than %s runs (its OSVERSION is "
	    "lower than theirs). Installed anyway, a package may need what "
	    "this kernel and base system do not have yet, and fail to run; "
	    "upgrading the system first is the safe way. %s with "
	    "IGNORE_OSVERSION=yes?", app.pkg.jail[0] != '\0' ? app.pkg.jail :
	    "this host", dry_run ? "Show what pkg would do" : "Upgrade the "
	    "packages anyway");
	confirm("Packages for a newer FreeBSD", body, dry_run ? "Dry run "
	    "anyway" : "Upgrade anyway", true, "", dry_run ? "do-pkg-dry-anyos" :
	    "do-pkg-anyos", app.pkg.names != NULL ? "some" : "", "");
	app.confirm.pkgnet = true;
}

static const char *const pkg_top_map[] = { "pkgbase", "pkgbase",
    "upgraded", "upgraded", NULL };
static const char *const pkg_map[] = { "name", "name", "installed",
    "installed", "available", "available", "origin", "origin", "comment",
    "comment", "automatic", "automatic", "size", "size", NULL };

/* How the repository is reached, as input's member, or "". */
static const char *
pkg_ipv(void)
{

	return (app.pkg.ip == 4 ? ",\"ip-version\":\"ipv4\"" : app.pkg.ip ==
	    6 ? ",\"ip-version\":\"ipv6\"" : "");
}

/* Where a jail's packages are: arcana-packages below its entry. */
static void
pkg_path(char *buf, size_t len, const char *jail, const char *act)
{

	if (jail[0] == '\0' || strcmp(jail, "*") == 0)
		snprintf(buf, len, "arcana-packages:packages/%s", act);
	else
		snprintf(buf, len, "arcana-jails:jails/jail=%s/arcana-packages:"
		    "packages/%s", rc_key(jail), act);
}

static void
packages_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx	*c;
	struct op	*op;
	bool		 ok;

	c = arg;
	op = c->op != 0 ? op_find(c->op) : NULL;
	ok = status == 200 && o != NULL;
	op_done(op, ok, NULL, err);
	if (strcmp(app.pkg.sid, c->sid) == 0 &&
	    strcmp(app.pkg.jail, c->jail) == 0 && (c->dry_run || c->net_kind ==
	    app.pkg.mode)) {
		app.pkg.loading = false;
		app.pkg.busy = false;
		if (ok) {
			ucl_object_t	*nd;

			/* arcana-packages' as the tab draws it.  An upgrade's
			 * reply says no repositories: those the read before
			 * said are kept, the choice with them. */
			nd = jmap(o, pkg_top_map);
			ucl_object_insert_key(nd, jmap_each(jget(o, "package"),
			    pkg_map), "packages", 0, false);
			if (jget(o, "repository") != NULL || !c->dry_run)
				ucl_object_insert_key(nd, jget(o, "repository") !=
				    NULL ? ucl_object_copy(jget(o, "repository")) :
				    ucl_object_typed_new(UCL_ARRAY), "repos", 0,
				    false);
			o = nd;
			if (jget(nd, "repos") == NULL && app.pkg.data != NULL &&
			    jget(app.pkg.data, "repos") != NULL)
				ucl_object_insert_key(nd, ucl_object_copy(jget(
				    app.pkg.data, "repos")), "repos", 0, false);
			if (app.pkg.data != NULL)
				ucl_object_unref(app.pkg.data);
			app.pkg.data = nd;
			app.pkg.fetched = arc_now();
			app.pkg.error[0] = '\0';
			if (jget(o, "upgraded") != NULL && c->user)
				snprintf(app.pkg.result, sizeof(app.pkg.result),
				    "%s: %lld package%s%s", c->jail[0] != '\0' ?
				    c->jail : "host", (long long)jint(o,
				    "upgraded", 0), jint(o, "upgraded", 0) == 1 ?
				    "" : "s", c->dry_run ? " would be upgraded" :
				    " upgraded");
		} else
			snprintf(app.pkg.error, sizeof(app.pkg.error), "%s",
			    err != NULL ? err : "no answer from the console");
	}
	if (!ok && (c->user || c->read))
		osversion_ask(err, c->dry_run, c->read);
	if (c->user)
		toast(ok ? false : true, "%s: %s", c->jail[0] != '\0' ? c->jail :
		    "host", ok ? (op != NULL ? op->title : "done") : err != NULL ?
		    err : "failed");
	free(c);
}

/* Pending upgrades of app.pkg.jail on the server; refresh: pkg update. */
void
refresh_packages(struct server *s, bool refresh)
{
	struct ctx	*c;
	struct op	*op;
	char		 url[512], title[160], in[128];

	if (!app.online)
		return;
	if (strcmp(app.pkg.sid, s->id) != 0) {
		if (app.pkg.data != NULL)
			ucl_object_unref(app.pkg.data);
		app.pkg.data = NULL;
		app.pkg.error[0] = '\0';
		app.pkg.result[0] = '\0';
		/* Another host: its own packages, not a jail of the last. */
		app.pkg.jail[0] = '\0';
		snprintf(app.pkg.repo, sizeof(app.pkg.repo), "%s",
		    pkg_repo_kept(s, "", "upgrade"));
		app.pkg.anyos = app.pkg.asked = false;
	}
	snprintf(app.pkg.sid, sizeof(app.pkg.sid), "%s", s->id);
	app.pkg.loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->jail, sizeof(c->jail), "%s", app.pkg.jail);
	c->read = app.pkg.mode == 1;
	/* Which view asked: an answer for the other is not shown. */
	c->net_kind = app.pkg.mode;
	snprintf(title, sizeof(title), "%s%s%s", refresh && app.pkg.mode ==
	    1 ? "pkg update, " : "", app.pkg.mode == 0 ? "installed packages" :
	    "pending packages", app.pkg.jail[0] != '\0' ? " of jail " : "");
	strlcat(title, app.pkg.jail, sizeof(title));
	/* The installed are the host's own: the repository is not asked. */
	pkg_path(url, sizeof(url), app.pkg.jail, app.pkg.mode == 0 ? "read" :
	    "refresh");
	if (app.pkg.mode == 0)
		snprintf(in, sizeof(in), "{}");
	else
		snprintf(in, sizeof(in), "{\"update\":%s%s%s}", refresh ? "true" :
		    "false", pkg_ipv(), app.pkg.anyos ?
		    ",\"ignore-osversion\":true" : "");
	/* Read again by the page itself (after an upgrade): no task. */
	if (!app.quiet) {
		op = op_new(title, s->name);
		c->op = op->id;
		app.trace_op = op->id;
	}
	host_yread(s, url, in, NULL, c->op != 0, packages_cb, c);
}

/* pkg upgrade of the named packages (JSON array text), or of all. */
void
pkg_upgrade(struct server *s, const char *names, bool dry_run, bool anyos)
{
	struct ctx	*c;
	struct op	*op;
	char		 url[512], title[200], *qj, *qr, *body;

	if (!app.online || app.pkg.busy)
		return;
	/* What it is asked of, to ask it again past OSVERSION; asked again,
	 * names is that already. */
	if (names != app.pkg.names) {
		free(app.pkg.names);
		app.pkg.names = names != NULL ? strdup(names) : NULL;
	}
	if (!dry_run) {
		char *json;

		qj = json_quote(app.pkg.jail);
		qr = json_quote(app.pkg.repo);
		snprintf(title, sizeof(title), "pkg upgrade%s%s%s%s%s%s",
		    app.pkg.jail[0] != '\0' ? " in " : "", app.pkg.jail,
		    names != NULL ? " of some" : "", app.pkg.repo[0] != '\0' ?
		    " from " : "", app.pkg.repo, anyos ? ", ignoring "
		    "OSVERSION" : "");
		if (asprintf(&json, "{\"kind\":\"pkg-upgrade\"%s%s,"
		    "\"packages\":%s%s%s%s%s}", app.pkg.jail[0] != '\0' ?
		    ",\"jail\":" : "", app.pkg.jail[0] != '\0' ? qj : "",
		    names != NULL ? names : "[]", anyos ? ",\"force\":true" :
		    "", app.pkg.ip == 4 ? ",\"pkg_ip\":4" : app.pkg.ip == 6 ?
		    ",\"pkg_ip\":6" : "", app.pkg.repo[0] != '\0' ?
		    ",\"pkg_repo\":" : "", app.pkg.repo[0] != '\0' ? qr : "") ==
		    -1)
			abort();
		free(qj);
		free(qr);
		if (!app.queue_on) {
			app.pkg.busy = true;
			app.pkg.result[0] = '\0';
		}
		job_send(s, json, title, JOB_PACKAGES, app.pkg.jail);
		return;
	}
	app.pkg.busy = true;
	app.pkg.result[0] = '\0';
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->jail, sizeof(c->jail), "%s", app.pkg.jail);
	c->user = true;
	c->dry_run = dry_run;
	snprintf(title, sizeof(title), "pkg upgrade%s%s%s%s", dry_run ?
	    " (dry run)" : "", app.pkg.jail[0] != '\0' ? " in " : "",
	    app.pkg.jail, names != NULL ? " of some" : "");
	op = op_new(title, s->name);
	c->op = op->id;
	app.trace_op = op->id;
	app.trace_step = -1;
	qr = json_quote(app.pkg.repo);
	if (asprintf(&body, "{\"name\":%s,\"dry-run\":%s,\"ignore-osversion\":"
	    "%s%s%s%s%s}", names != NULL ? names : "[]", dry_run ? "true" :
	    "false", anyos ? "true" : "false", pkg_ipv(), app.pkg.repo[0] !=
	    '\0' ? ",\"repository\":" : "", app.pkg.repo[0] != '\0' ? qr : "",
	    strcmp(app.pkg.jail, "*") == 0 ?
	    ",\"every-jail\":true" : "") == -1)
		abort();
	free(qr);
	rc_h(url, sizeof(url), s->id, "%s", "");
	pkg_path(url + strlen(url), sizeof(url) - strlen(url), app.pkg.jail,
	    "upgrade");
	rc_read(url, body, NULL, packages_cb, c);
	free(body);
}

#define	RTFAM	"data.statistics.route-information.route-table.rt-family"

static api_cb	 network_cb;

/* How many routes the table shown holds. */
int
routes_held(void)
{
	const ucl_object_t	*fam;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((fam = ucl_object_iterate(jget(app.net.data, RTFAM), &it,
	    true)) != NULL)
		n += (int)ucl_array_size(jget(fam, "rt-entry"));
	return (n);
}

/*
 * More routes of a table too large for one reply: each family's are
 * put after those of the same family that are there, and what the
 * reply says of the whole takes the place of what was said before.
 */
static void
routes_more(const ucl_object_t *o)
{
	const ucl_object_t	*nf, *of, *e;
	ucl_object_iter_t	 it, oit, eit;
	const char		*name;

	it = NULL;
	while ((nf = ucl_object_iterate(jget(o, RTFAM), &it, true)) != NULL) {
		name = jstr(nf, "address-family");
		oit = NULL;
		while ((of = ucl_object_iterate(jget(app.net.data, RTFAM),
		    &oit, true)) != NULL)
			if (name != NULL && jstr(of, "address-family") != NULL &&
			    strcmp(jstr(of, "address-family"), name) == 0)
				break;
		if (of == NULL) {
			ucl_array_append((ucl_object_t *)(uintptr_t)jget(
			    app.net.data, RTFAM), ucl_object_ref(nf));
			continue;
		}
		eit = NULL;
		while ((e = ucl_object_iterate(jget(nf, "rt-entry"), &eit,
		    true)) != NULL)
			ucl_array_append((ucl_object_t *)(uintptr_t)jget(of,
			    "rt-entry"), ucl_object_ref(e));
	}
	ucl_object_replace_key(app.net.data, ucl_object_frombool(jbool(o,
	    "truncated")), "truncated", 0, false);
}

/* Ask for the routes after those that are here. */
void
network_more(struct server *s)
{
	struct ctx	*c;
	struct netq	 q;

	if (!app.online || app.net.loading || app.net.data == NULL ||
	    app.net.kind != NET_ROUTES)
		return;
	app.net.loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	c->net_kind = (int)app.net.kind;
	c->op_family = app.net.family;
	snprintf(c->jail, sizeof(c->jail), "%s", app.net.jail);
	c->more = true;
	memset(&q, 0, sizeof(q));
	q.kind = "routes";
	q.family = app.net.family;
	q.fib = app.net.fib;
	q.offset = routes_held();
	q.jail = app.net.jail;
	q.filter = app.net.host_filter;
	net_yread(s->id, &q, false, network_cb, c);
}

static void
network_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx	*c;
	struct op	*op;
	bool		 ok;

	c = arg;
	op = c->op != 0 ? op_find(c->op) : NULL;
	ok = status == 200 && jbool(o, "ok");
	if (status == 200 && !ok)
		err = jstr(o, "error");
	op_done(op, ok, o, err);
	/* Still the table that was asked for? */
	if (strcmp(app.net.sid, c->sid) == 0 && (int)app.net.kind == c->net_kind &&
	    app.net.family == c->op_family && strcmp(app.net.jail, c->jail) ==
	    0) {
		app.net.loading = false;
		if (ok && c->more && app.net.data != NULL) {
			routes_more(o);
			app.net.fetched = arc_now();
			app.net.error[0] = '\0';
		} else if (ok) {
			if (app.net.data != NULL)
				ucl_object_unref(app.net.data);
			app.net.data = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
			app.net.data_kind = c->net_kind;
			app.net.fetched = arc_now();
			app.net.error[0] = '\0';
			if ((size_t)c->net_kind < nitems(app.net.cache)) {
				if (app.net.cache[c->net_kind].data != NULL)
					ucl_object_unref(
					    app.net.cache[c->net_kind].data);
				app.net.cache[c->net_kind].data =
				    ucl_object_ref(app.net.data);
				app.net.cache[c->net_kind].family =
				    c->op_family;
				app.net.cache[c->net_kind].fetched =
				    app.net.fetched;
			}
		} else
			snprintf(app.net.error, sizeof(app.net.error), "%s",
			    err != NULL ? err : "no answer from the console");
	}
	free(c);
}

/*
 * The routes, connections and sockets come in parts over the console's
 * stream, as the host reads them, and nothing is left out for size.
 * The first time, the table fills as they come; read again, the table
 * shown stays until the new one is whole.  Without a stream, they are
 * asked for whole as the others are.
 */
#define	NS_BASE		1000000		/* ids apart from sysctl's */

static struct {
	int		 id;
	bool		 on;
	bool		 nostream;
	bool		 swap;		/* to be shown once it is whole */
	ucl_object_t	*target;	/* the reply being made */
	ucl_object_t	*arr;		/* where a row goes: not routes' */
	char		 sid[9];
	int		 kind;
	int		 family;
	char		 jail[256];
} ns = { .id = NS_BASE };

static void
ns_stop(void)
{
	char	msg[64];

	if (ns.on) {
		snprintf(msg, sizeof(msg), "{\"id\":%d,\"stop\":true}", ns.id);
		arc_stream_send(msg);
	}
	ns.on = false;
	if (ns.target != NULL)
		ucl_object_unref(ns.target);
	ns.target = NULL;
	ns.arr = NULL;
}

/* An empty reply of the shape the table is drawn from. */
static ucl_object_t *
ns_shape(int kind, ucl_object_t **arrp)
{
	ucl_object_t	*top, *data, *a, *b, *c;

	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_frombool(true), "ok", 0, false);
	data = ucl_object_typed_new(UCL_OBJECT);
	*arrp = ucl_object_typed_new(UCL_ARRAY);
	if (kind == NET_ROUTES) {
		c = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(c, *arrp, "rt-family", 0, false);
		b = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(b, c, "route-table", 0, false);
		a = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(a, b, "route-information", 0, false);
		ucl_object_insert_key(data, a, "statistics", 0, false);
	} else {
		a = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(a, *arrp, "socket", 0, false);
		ucl_object_insert_key(data, a, kind == NET_SOCKETS ?
		    "sockstat" : "statistics", 0, false);
	}
	ucl_object_insert_key(top, data, "data", 0, false);
	return (top);
}

/* The rt-entry array of a family, made when it is not there yet. */
static ucl_object_t *
ns_family(ucl_object_t *fams, const char *name)
{
	ucl_object_t		*f, *e;
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(fams, &it, true)) != NULL)
		if (jstr(o, "address-family") != NULL && strcmp(jstr(o,
		    "address-family"), name) == 0)
			return ((ucl_object_t *)(uintptr_t)jget(o, "rt-entry"));
	f = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(f, ucl_object_fromstring(name),
	    "address-family", 0, false);
	e = ucl_object_typed_new(UCL_ARRAY);
	ucl_object_insert_key(f, e, "rt-entry", 0, false);
	ucl_array_append(fams, f);
	return (e);
}

/* Read the table in parts; false when there is no stream for it. */
static bool
ns_start(struct server *s)
{
	char	msg[400];

	if (ns.nostream || (app.net.kind != NET_ROUTES && app.net.kind !=
	    NET_CONNECTIONS && app.net.kind != NET_SOCKETS))
		return (false);
	ns_stop();
	ns.id++;
	ns.on = true;
	ns.kind = (int)app.net.kind;
	ns.family = app.net.family;
	snprintf(ns.sid, sizeof(ns.sid), "%s", s->id);
	snprintf(ns.jail, sizeof(ns.jail), "%s", app.net.jail);
	ns.target = ns_shape(ns.kind, &ns.arr);
	/* Shown as it fills when there is nothing of its own to show yet. */
	ns.swap = app.net.data != NULL && app.net.data_kind == ns.kind;
	if (!ns.swap) {
		if (app.net.data != NULL)
			ucl_object_unref(app.net.data);
		app.net.data = ucl_object_ref(ns.target);
		app.net.data_kind = ns.kind;
	}
	snprintf(msg, sizeof(msg), "{\"id\":%d,\"server\":\"%s\",\"what\":"
	    "\"%s\",\"family\":\"%s\",\"fib\":%d,\"jail\":\"%s\","
	    "\"filter\":\"%s\"}", ns.id, s->id, ns.kind == NET_ROUTES ?
	    "routes" : ns.kind == NET_SOCKETS ? "sockets" : "connections",
	    app.net.family == 4 ? "inet" : app.net.family == 6 ? "inet6" :
	    "all", ns.kind == NET_ROUTES ? app.net.fib : 0, app.net.jail,
	    ns.kind == NET_ROUTES ? app.net.host_filter : "");
	arc_stream_send(msg);
	return (true);
}

void
network_stream(const ucl_object_t *o)
{
	const ucl_object_t	*r;
	ucl_object_iter_t	 it;
	struct server		*s;
	bool			 mine;

	if (jbool(o, "closed")) {
		if (ns.on) {
			ns_stop();
			ns.nostream = true;
			app.net.loading = false;
			if ((s = cur_server()) != NULL)
				refresh_network(s, false);
		}
		return;
	}
	if (!ns.on || jint(o, "id", -1) != ns.id || ns.target == NULL)
		return;
	it = NULL;
	while ((r = ucl_object_iterate(jget(o, "rows"), &it, true)) != NULL)
		ucl_array_append(ns.kind == NET_ROUTES ? ns_family(ns.arr,
		    jstr(r, "family") != NULL ? jstr(r, "family") :
		    "Internet") : ns.arr, ucl_object_ref(r));
	mine = strcmp(app.net.sid, ns.sid) == 0 && (int)app.net.kind ==
	    ns.kind && app.net.family == ns.family && strcmp(app.net.jail,
	    ns.jail) == 0;
	if (mine && !ns.swap)
		app.net.fetched = arc_now();
	if (!jbool(o, "done") && jstr(o, "error") == NULL)
		return;
	if (mine) {
		app.net.loading = false;
		if (jstr(o, "error") != NULL)
			snprintf(app.net.error, sizeof(app.net.error), "%s",
			    jstr(o, "error"));
		else {
			app.net.error[0] = '\0';
			app.net.fetched = arc_now();
			if (ns.swap) {
				if (app.net.data != NULL)
					ucl_object_unref(app.net.data);
				app.net.data = ucl_object_ref(ns.target);
				app.net.data_kind = ns.kind;
			}
		}
	}
	ns.on = false;
	ucl_object_unref(ns.target);
	ns.target = NULL;
	ns.arr = NULL;
}

/* The network table the tab shows, from the server; user: log it. */
void
refresh_network(struct server *s, bool user)
{
	static const char *kinds[] = { "routes", "nexthops", "connections",
	    "sockets", "interfaces", "netgraph", "wireguard", "bird",
	    "bridges", "geneve", "nhgroups", "neighbours", "ipsec",
	    "bridges", "interfaces", "multicast", "kept-routes",
	    "interfaces" };
	struct ctx	*c;
	struct op	*op;
	struct netq	 q;
	char		 title[160];

	if (!app.online)
		return;
	/*
	 * A plugin's view, of a host or jail known not to have the plugin:
	 * nothing to ask, and the tab says how to install it.
	 */
	if (s->list != NULL && kind_plugin(app.net.kind) != NULL &&
	    !has_plugin(s, kind_plugin(app.net.kind))) {
		app.net.loading = false;
		return;
	}
	/*
	 * Another host's or jail's: what is shown goes.  The same one read
	 * again while a read is on its way keeps it: a form drawn from it
	 * (a bridge, an interface to choose) would lose its choices.
	 */
	if (strcmp(app.net.sid, s->id) != 0 || strcmp(app.net.jail,
	    net_scope()) != 0) {
		if (app.net.data != NULL)
			ucl_object_unref(app.net.data);
		app.net.data = NULL;
		app.net.error[0] = '\0';
		for (size_t k = 0; k < nitems(app.net.cache); k++) {
			if (app.net.cache[k].data != NULL)
				ucl_object_unref(app.net.cache[k].data);
			app.net.cache[k].data = NULL;
		}
	} else if (app.net.data_kind != (int)app.net.kind &&
	    app.net.kind < nitems(app.net.cache) &&
	    app.net.cache[app.net.kind].data != NULL &&
	    app.net.cache[app.net.kind].family == app.net.family) {
		/* Another kind again: the last of it, while it is read. */
		if (app.net.data != NULL)
			ucl_object_unref(app.net.data);
		app.net.data = ucl_object_ref(app.net.cache[app.net.kind].data);
		app.net.data_kind = (int)app.net.kind;
		app.net.fetched = app.net.cache[app.net.kind].fetched;
		app.net.error[0] = '\0';
	}
	snprintf(app.net.sid, sizeof(app.net.sid), "%s", s->id);
	snprintf(app.net.jail, sizeof(app.net.jail), "%s", net_scope());
	app.net.loading = true;
	/* Span is the bridges, and the firewall's taps and the sources. */
	if (app.net.kind == NET_SPAN)
		span_refresh(s);
	if (ns_start(s))
		return;
	ns_stop();
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	c->net_kind = (int)app.net.kind;
	c->op_family = app.net.family;
	snprintf(c->jail, sizeof(c->jail), "%s", app.net.jail);
	c->user = user = user && !app.quiet;
	if (user) {
		snprintf(title, sizeof(title), "net %s%s", kinds[app.net.kind],
		    app.net.family == 4 ? " inet" : app.net.family == 6 ?
		    " inet6" : "");
		op = op_new(title, s->name);
		c->op = op->id;
		app.trace_op = op->id;
	}
	memset(&q, 0, sizeof(q));
	q.kind = kinds[app.net.kind];
	q.family = app.net.family;
	if (app.net.kind == NET_ROUTES || app.net.kind == NET_NEXTHOPS)
		q.fib = app.net.fib;
	q.jail = app.net.jail;
	if (app.net.kind == NET_ROUTES)
		q.filter = app.net.host_filter;
	/* The Interfaces table by the standard models; the other tabs of
	 * the same table by arcana-network's. */
	q.yang = app.net.kind == NET_INTERFACES;
	/* Asked for: its steps drawn as the host takes them. */
	net_yread(s->id, &q, user, network_cb, c);
}

static void
address_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx	*c;
	struct server	*s;
	struct op	*op;
	const char	*diff;
	bool		 ok;

	c = arg;
	op = op_find(c->op);
	ok = status == 200 || status == 204;
	op_done(op, ok, NULL, err);
	diff = jstr(o, "diff");
	if (op != NULL && diff != NULL)
		op->diff = strdup(diff);
	app.modal_busy = false;
	if (c->dry_run) {
		free(app.preview);
		app.preview = NULL;
		if (ok)
			app.preview = strdup(diff != NULL ? diff :
			    "(no configuration change)");
		else
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "%s", err != NULL ? err : "failed");
	} else if (ok) {
		if (app.modal == MODAL_ADDRESS)
			app.modal = MODAL_NONE;
		toast(false, "%s: %s", c->jail, op != NULL ? op->title :
		    "done");
	} else
		snprintf(app.modal_error, sizeof(app.modal_error), "%s",
		    err != NULL ? err : "failed");
	if ((s = server_by_id(c->sid)) != NULL) {
		jailui(s, c->jail)->pending = PEND_NONE;
		if (!c->dry_run) {
			merge_jail(s, jget(o, "jail"));
			s->loading = false;
			refresh_jails(s, false);
		}
	}
	free(c);
}

/* Add or remove an address, live and/or persistent, or preview it. */
void
address_change(const char *jail, const char *address, bool remove, bool live,
    bool persist, bool dry_run)
{
	struct server	*s;
	struct ctx	*c;
	struct op	*op;
	char		 url[512], title[160], *body, *qa;

	if ((s = cur_server()) == NULL)
		return;
	if (!dry_run) {
		char *json, *qjail;

		snprintf(title, sizeof(title), "%s %s %s %s%s",
		    remove ? "remove" : "add", address, remove ? "from" : "to",
		    jail, persist && !live ? " (config)" : live && persist ?
		    " (live + config)" : "");
		qa = json_quote(address);
		qjail = json_quote(jail);
		if (asprintf(&json, "{\"kind\":\"address\",\"jail\":%s,"
		    "\"address\":%s,\"remove\":%s,\"live\":%s,\"persist\":%s}",
		    qjail, qa, remove ? "true" : "false", live ? "true" :
		    "false", persist ? "true" : "false") == -1)
			abort();
		free(qa);
		free(qjail);
		if (!app.queue_on)
			jailui(s, jail)->pending = PEND_ADDRESS;
		if (app.modal == MODAL_ADDRESS)
			app.modal = MODAL_NONE;
		job_send(s, json, title, JOB_ADDRESS, jail);
		return;
	}
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->jail, sizeof(c->jail), "%s", jail);
	c->dry_run = dry_run;
	snprintf(title, sizeof(title), "%s%s %s %s%s%s", dry_run ?
	    "preview: " : "", remove ? "remove" : "add", address,
	    remove ? "from " : "to ", jail, persist && !live ?
	    " (config)" : live && persist ? " (live + config)" : "");
	op = op_new(title, s->name);
	c->op = op->id;
	app.trace_op = op->id;
	if (!dry_run)
		jailui(s, jail)->pending = PEND_ADDRESS;
	app.modal_busy = true;
	app.modal_error[0] = '\0';
	/* The preview: arcana-network's address on the jail, a dry run. */
	rc_h(url, sizeof(url), s->id, "arcana-jails:jails/jail=%s/"
	    "arcana-network:address", rc_key(jail));
	qa = json_quote(address);
	if (asprintf(&body, "{\"address\":%s,\"remove\":%s,\"live\":%s,"
	    "\"persist\":%s,\"dry-run\":true}", qa, remove ? "true" : "false",
	    live ? "true" : "false", persist ? "true" : "false") == -1)
		abort();
	free(qa);
	rc_action(url, body, NULL, address_cb, c);
	free(body);
}

/*
 * WebAuthn works only at the origin the console is configured for: its
 * rp_id must be this page's host or a parent domain of it, and the page
 * must be the configured origin.  The browser says only "SecurityError"
 * (Firefox: "The operation is insecure"), so say what is wrong here.
 */
static void
origin_check(const char *origin, const char *rp_id)
{
	char	*here, *host;
	size_t	 hl, rl;
	bool	 suffix;

	app.origin_error[0] = '\0';
	if (origin == NULL || rp_id == NULL)
		return;
	snprintf(app.console_origin, sizeof(app.console_origin), "%s", origin);
	here = arc_origin();
	host = arc_hostname();
	/* The host without its port, against rp_id as a domain suffix. */
	hl = strcspn(host, ":");
	if (host[0] == '[')
		hl = strcspn(host, "]") + 1;
	rl = strlen(rp_id);
	suffix = hl >= rl && strncmp(host + hl - rl, rp_id, rl) == 0 &&
	    (hl == rl || host[hl - rl - 1] == '.');
	if (strcmp(here, origin) != 0 || !suffix)
		snprintf(app.origin_error, sizeof(app.origin_error),
		    "This console is set up for %s (rp_id %s), but it is open "
		    "at %s. Security keys work only there: open it at that "
		    "address, or set rp_id and origin in web.conf "
		    "(ARCANA_RP_ID and ARCANA_ORIGIN in the container) to this "
		    "one. Keys are bound to the rp_id they were registered "
		    "under.", origin, rp_id, here);
	else if (strncmp(here, "https://", 8) != 0 &&
	    strncmp(host, "localhost", 9) != 0)
		snprintf(app.origin_error, sizeof(app.origin_error),
		    "Security keys need HTTPS (or localhost); this page is "
		    "open at %s.", here);
	free(here);
	free(host);
}

static void
status_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	if (status == 0) {
		/* The shell came from the cache; the console is away. */
		app.api = LINK_DOWN;
		if (app.screen != SCREEN_CONSOLE)
			app.screen = SCREEN_OFFLINE;
		return;
	}
	if (status != 200) {
		if (app.screen == SCREEN_BOOT || app.screen == SCREEN_OFFLINE)
			app.screen = SCREEN_LOGIN;
		snprintf(app.auth_error, sizeof(app.auth_error),
		    "The console answered %d: %s", status, err != NULL ? err :
		    "error");
		return;
	}
	app.setup_required = jbool(o, "setup_required");
	app.by_ldap = jbool(o, "by_ldap");
	app.by_password = jbool(o, "by_password");
	/* Limited as the console says: a password's session is not when
	 * web.conf's password_full is on. */
	app.by_token = jbool(o, "by_token");
	app.ldap_on = jbool(o, "ldap");
	app.password_on = jbool(o, "password");
	app.password_full = jbool(o, "password_full");
	app.no_keys = ucl_object_lookup(o, "keys") != NULL && !jbool(o, "keys");
	who_set(o);
	origin_check(jstr(o, "origin"), jstr(o, "rp_id"));
	if (jbool(o, "authenticated")) {
		app.screen = SCREEN_CONSOLE;
		app.auth_error[0] = '\0';
		app.invite_token[0] = '\0';
		refresh_servers();
		/* Where notifications are allowed, this browser is told. */
		arc_push_sync();
	} else
		app.screen = app.setup_required || app.invite_token[0] != '\0' ?
		    SCREEN_ENROL : SCREEN_LOGIN;
}

void
auth_status(void)
{

	api("GET", "/api/auth/status", NULL, status_cb, NULL);
}

static void
auth_done_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	app.auth_busy = false;
	if (status == 200 && jbool(o, "authenticated")) {
		app.by_ldap = jbool(o, "by_ldap");
		app.by_password = jbool(o, "by_password");
		app.by_token = jbool(o, "by_token");
		app.password_full = jbool(o, "password_full");
		app.no_keys = ucl_object_lookup(o, "keys") != NULL &&
		    !jbool(o, "keys");
		who_set(o);
		app.invite_token[0] = '\0';
		app.screen = SCREEN_CONSOLE;
		app.auth_error[0] = '\0';
		app.setup_required = false;
		refresh_servers();
		arc_push_sync();
		return;
	}
	snprintf(app.auth_error, sizeof(app.auth_error), "%s",
	    err != NULL ? err : "not accepted");
}

static void
login_assert_cb(bool ok, const char *result, void *arg)
{

	if (!ok) {
		app.auth_busy = false;
		snprintf(app.auth_error, sizeof(app.auth_error),
		    "Security key: %s", result);
		return;
	}
	api("POST", "/api/auth/login/finish", result, auth_done_cb, NULL);
}

static void
login_begin_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*opts;

	if (status != 200) {
		app.auth_busy = false;
		snprintf(app.auth_error, sizeof(app.auth_error), "%s",
		    err != NULL ? err : "cannot start");
		if (status == 409)
			app.screen = SCREEN_ENROL;
		return;
	}
	opts = emit(o);
	webauthn(false, opts, login_assert_cb, NULL);
	free(opts);
}

/*
 * Signed in with a write token, for one with no security key at hand:
 * the console opens a session that may do what the token may.
 */
void
login_token(const char *token)
{
	char	*q, *body;

	if (app.auth_busy)
		return;
	app.auth_busy = true;
	app.auth_error[0] = '\0';
	q = json_quote(token);
	if (asprintf(&body, "{\"token\":%s}", q) == -1)
		abort();
	free(q);
	api("POST", "/api/auth/login/token", body, auth_done_cb, NULL);
	explicit_bzero(body, strlen(body));
	free(body);
}

/* How a limited session was opened, for what the page says of it. */
const char *
signed_in_how(void)
{

	return (app.by_ldap ? "by a directory's user" : app.by_password ?
	    "with a password" : "with an API token");
}

/* A user and password: the console's own, or the directory's. */
void
login_password(const char *user, const char *password)
{
	char	*qu, *qp, *body;

	if (app.auth_busy)
		return;
	app.auth_busy = true;
	app.auth_error[0] = '\0';
	qu = json_quote(user);
	qp = json_quote(password);
	if (asprintf(&body, "{\"user\":%s,\"password\":%s}", qu, qp) == -1)
		abort();
	explicit_bzero(qp, strlen(qp));
	free(qu);
	free(qp);
	api("POST", "/api/auth/login/password", body, auth_done_cb, NULL);
	explicit_bzero(body, strlen(body));
	free(body);
}

/* With passkey, the authenticator picks the credential itself. */
void
login(bool passkey)
{

	if (app.auth_busy)
		return;
	app.auth_busy = true;
	app.auth_error[0] = '\0';
	api("POST", "/api/auth/login/begin", passkey ?
	    "{\"discoverable\":true}" : "{}", login_begin_cb, NULL);
}

/* After create(): add the key's name and finish the registration. */
static void
create_cb(bool ok, const char *result, void *arg)
{
	struct ctx	*c;
	ucl_object_t	*o;
	char		*body;

	c = arg;
	if (!ok) {
		app.auth_busy = app.modal_busy = false;
		snprintf(c->user ? app.modal_error : app.auth_error,
		    sizeof(app.auth_error), "Security key: %s", result);
		free(c);
		return;
	}
	if ((o = json_parse(result)) == NULL) {
		app.auth_busy = app.modal_busy = false;
		snprintf(c->user ? app.modal_error : app.auth_error,
		    sizeof(app.auth_error), "Security key: no answer");
		free(c);
		return;
	}
	ucl_object_insert_key(o, ucl_object_fromstring(c->name), "name", 0,
	    true);
	body = emit(o);
	ucl_object_unref(o);
	api("POST", "/api/auth/register/finish", body, c->user ?
	    key_added_cb : auth_done_cb, NULL);
	free(body);
	free(c);
}

static void
register_begin_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{
	struct ctx	*c;
	char		*opts;

	c = arg;
	if (status != 200) {
		app.auth_busy = app.modal_busy = false;
		snprintf(c->user ? app.modal_error : app.auth_error,
		    sizeof(app.auth_error), "%s", err != NULL ? err :
		    "cannot start");
		free(c);
		return;
	}
	opts = emit(o);
	webauthn(true, opts, create_cb, c);
	free(opts);
}

/* Who is signed in, and what they may, from a status reply. */
static void
who_set(const ucl_object_t *o)
{

	snprintf(app.user, sizeof(app.user), "%s", jstr(o, "user") != NULL ?
	    jstr(o, "user") : "");
	snprintf(app.console_role, sizeof(app.console_role), "%s", jstr(o,
	    "console") != NULL ? jstr(o, "console") : "");
	snprintf(app.tenant, sizeof(app.tenant), "%s", jstr(o, "tenant") != NULL
	    ? jstr(o, "tenant") : "");
}

/* The first key, with the setup token from the console's data dir, or
 * a user's first with their invitation (inv_...). */
void
enrol(const char *token, const char *name)
{
	struct ctx	*c;
	char		*qt, *body;

	if (app.auth_busy)
		return;
	app.auth_busy = true;
	app.auth_error[0] = '\0';
	c = ctx_new();
	snprintf(c->name, sizeof(c->name), "%s", *name != '\0' ? name :
	    "Security key");
	qt = json_quote(token);
	if (asprintf(&body, "{\"%s\":%s}", strncmp(token, "inv_", 4) == 0 ?
	    "invite" : "setup_token", qt) == -1)
		abort();
	api("POST", "/api/auth/register/begin", body, register_begin_cb, c);
	free(qt);
	free(body);
}

/* The console set up by a password instead of a key: the setup token,
 * the owner's name ("" the built-in admin) and their password, twice. */
void
setup_password(const char *token, const char *user, const char *password)
{
	char	*qt, *qu, *qp, *body;

	if (app.auth_busy)
		return;
	app.auth_busy = true;
	app.auth_error[0] = '\0';
	qt = json_quote(token);
	qu = json_quote(user);
	qp = json_quote(password);
	if (asprintf(&body, "{\"setup_token\":%s,\"user\":%s,\"password\":"
	    "%s}", qt, qu, qp) == -1)
		abort();
	explicit_bzero(qp, strlen(qp));
	free(qt);
	free(qu);
	free(qp);
	api("POST", "/api/auth/setup/password", body, auth_done_cb, NULL);
	explicit_bzero(body, strlen(body));
	free(body);
}

static void
key_added_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	app.modal_busy = false;
	if (status != 200) {
		snprintf(app.modal_error, sizeof(app.modal_error), "%s",
		    err != NULL ? err : "not accepted");
		return;
	}
	toast(false, "Key added");
	load_keys();
}

/* A spare key, from a logged-in session. */
void
add_key(const char *name)
{
	struct ctx	*c;

	app.modal_busy = true;
	app.modal_error[0] = '\0';
	c = ctx_new();
	c->user = true;
	snprintf(c->name, sizeof(c->name), "%s", *name != '\0' ? name :
	    "Spare key");
	api("POST", "/api/auth/register/begin", "{}", register_begin_cb, c);
}

static void
logout_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	app.screen = SCREEN_LOGIN;
	app.auth_error[0] = '\0';
	plugins_signed_out();
	/* The reply is the status: which ways in the sign-in page offers. */
	if (status == 200) {
		app.ldap_on = jbool(o, "ldap");
		app.password_on = jbool(o, "password");
		app.password_full = jbool(o, "password_full");
		app.no_keys = ucl_object_lookup(o, "keys") != NULL &&
		    !jbool(o, "keys");
	}
	app.by_token = app.by_ldap = app.by_password = false;
}

void
logout(void)
{

	api("POST", "/api/auth/logout", NULL, logout_cb, NULL);
}

static void
keys_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*k;

	if (app.keys != NULL)
		ucl_object_unref(app.keys);
	app.keys = NULL;
	if (status != 200) {
		if (status != 401)
			snprintf(app.modal_error, sizeof(app.modal_error), "%s",
			    err != NULL ? err : "cannot load keys");
		return;
	}
	/* arcana-console's credentials: {id, name, user, alg, last_used}. */
	app.keys = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(jget(o, "credential"), &it, true)) !=
	    NULL) {
		k = ucl_object_copy(e);
		ucl_object_delete_key(k, "last-used");
		if (jstr(e, "last-used") != NULL)
			kput(k, "last_used", ucl_object_fromint(rc_time(jstr(e,
			    "last-used"))));
		ucl_array_append(app.keys, k);
	}
}

void
load_keys(void)
{

	rc_get(RC_C "credentials", NULL, keys_cb, NULL);
}

static void
key_gone_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	if (status < 200 || status > 299) {
		keys_cb(status, o, err, arg);
		return;
	}
	load_keys();
}

void
delete_key(const char *id)
{
	char	url[600];

	rc_edit("DELETE", rc_c(url, sizeof(url), "credentials/credential=%s",
	    rc_key(id)), NULL, key_gone_cb, NULL);
}

static void
server_added_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{

	char	*id = arg;
	int	 i;

	app.modal_busy = false;
	hosts_cb(status, o, err, NULL);
	/* The one added shown. */
	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, id) == 0) {
			app.sel = i;
			app.node = NODE_HOST;
			app.tab = TAB_SUMMARY;
			refresh_stats(&app.servers[i]);
		}
	free(id);
}

static void
server_made_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{
	char	url[200];

	if (status < 200 || status > 299) {
		app.modal_busy = false;
		free(arg);
		snprintf(app.modal_error, sizeof(app.modal_error), "%s",
		    err != NULL ? err : "not added");
		return;
	}
	app.modal = MODAL_NONE;
	toast(false, "Server added");
	rc_get(rc_c(url, sizeof(url), "hosts"), NULL, server_added_cb, arg);
}

/* A host added, an id of 32 bits the page draws for it. */
void
add_server(const char *name, const char *uri, const char *peer)
{
	unsigned char	 r[4];
	ucl_object_t	*e;
	char		 id[9], url[200];
	unsigned char	*json;
	ucl_object_t	*top, *a;

	app.modal_busy = true;
	app.modal_error[0] = '\0';
	if (getentropy(r, sizeof(r)) != 0) {
		app.modal_busy = false;
		snprintf(app.modal_error, sizeof(app.modal_error), "no random "
		    "bytes for its id");
		return;
	}
	snprintf(id, sizeof(id), "%02x%02x%02x%02x", r[0], r[1], r[2], r[3]);
	e = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(e, ucl_object_fromstring(id), "id", 0, true);
	ucl_object_insert_key(e, ucl_object_fromstring(name), "name", 0,
	    true);
	ucl_object_insert_key(e, ucl_object_fromstring(uri), "uri", 0, true);
	if (*peer != '\0')
		ucl_object_insert_key(e, ucl_object_fromstring(peer),
		    "peer-name", 0, true);
	a = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(a, e);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, a, "arcana-console:host", 0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	rc_edit("POST", rc_c(url, sizeof(url), "hosts"), (const char *)json,
	    server_made_cb, strdup(id));
	free(json);
}

static void
enrol_token_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{

	app.modal_busy = false;
	if (status != 200 || jstr(o, "command") == NULL) {
		snprintf(app.modal_error, sizeof(app.modal_error), "%s",
		    err != NULL ? err : "no token");
		return;
	}
	snprintf(app.enrol_cmd, sizeof(app.enrol_cmd), "%s",
	    jstr(o, "command"));
}

/* A one-time token for a host to join with arcana-enrol(8). */
void
enrol_host(const char *name, const char *host)
{
	char	*qn, *qh, *body, url[200];

	app.modal_busy = true;
	app.modal_error[0] = '\0';
	app.enrol_cmd[0] = '\0';
	qn = json_quote(name);
	qh = json_quote(host);
	if (asprintf(&body, "{\"name\":%s,\"host\":%s}", qn, qh) == -1)
		abort();
	rc_action(rc_c(url, sizeof(url), "enrolment/create-token"), body, NULL,
	    enrol_token_cb, NULL);
	free(qn);
	free(qh);
	free(body);
}

static void
readdressed_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{

	if (status < 200 || status > 299) {
		toast(true, "Not changed: %s", err != NULL ? err : "no answer");
		return;
	}
	toast(false, "The console reaches it at the new address");
	/* Tried there at once: the host's page reads it again. */
	refresh_servers();
}

/*
 * Where the console reaches a host, the console's alone: the host is
 * asked nothing, so one unreachable where it was can be told anew.
 */
void
server_readdress(struct server *s, const char *uri, const char *peer)
{
	ucl_object_t	*e;

	if ((e = host_conf(s->id)) == NULL)
		return;
	ucl_object_replace_key(e, ucl_object_fromstring(uri), "uri", 0, true);
	ucl_object_delete_key(e, "peer-name");
	if (peer[0] != '\0')
		ucl_object_insert_key(e, ucl_object_fromstring(peer),
		    "peer-name", 0, true);
	host_put(s->id, e, readdressed_cb, NULL);
}

static void
server_gone_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{

	if (status < 200 || status > 299) {
		servers_cb(status, o, err, arg);
		return;
	}
	refresh_servers();
}

void
delete_server(const char *id)
{
	char	url[200];

	rc_edit("DELETE", rc_c(url, sizeof(url), "hosts/host=%s", rc_key(id)),
	    NULL, server_gone_cb, NULL);
}

/* op waits for request req, which can be given up. */
static void
op_wait(int opid, int req)
{
	struct op	*op;

	if (opid != 0 && (op = op_find(opid)) != NULL)
		op->req = req;
}

static void
job_cancel_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx	*c;

	struct server	*s;

	c = arg;
	/* Taken back, the next reading of the job ends its entry. */
	if (status != 200 && status != 204)
		toast(true, "%s: not cancelled: %s", c->name, err != NULL ?
		    err : "failed");
	else if (c->sid[0] != '\0')
		toast(false, "%s: %s", c->name, jstr(o, "state") != NULL ?
		    jstr(o, "state") : "cancelled");
	/* Asked from the Jobs tab: its record read again. */
	if (c->sid[0] != '\0' && (s = server_by_id(c->sid)) != NULL) {
		s->jobs_loading = false;
		refresh_jobs(s);
	}
	free(c);
}

/*
 * Job id of the server's record taken back, from the Jobs tab: out of
 * the queue if it has not started, undone if it waits to be confirmed;
 * the agent says when it can be neither.
 */
void
cancel_job(struct server *s, long long id, const char *title)
{
	struct ctx	*c;
	char		 url[300];

	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->name, sizeof(c->name), "%s", title != NULL && title[0] !=
	    '\0' ? title : "the job");
	rc_action(job_path(url, sizeof(url), s->id, id, "cancel"), NULL, NULL,
	    job_cancel_cb, c);
}

/* Every job still queued on the server taken back, one by one. */
void
cancel_queued_jobs(struct server *s)
{
	const ucl_object_t	*j, *arr;
	ucl_object_iter_t	 it;
	int			 n;

	if (s->jobs == NULL || (arr = jget(s->jobs, "jobs")) == NULL)
		return;
	it = NULL;
	n = 0;
	while ((j = ucl_object_iterate(arr, &it, true)) != NULL)
		if (jstr(j, "state") != NULL && strcmp(jstr(j, "state"),
		    "queued") == 0) {
			cancel_job(s, (long long)jint(j, "id", 0), jstr(j,
			    "title"));
			n++;
		}
	if (n == 0)
		toast(false, "%s: nothing is queued", s->name);
}

/*
 * Give up what an entry of the activity list waits for, where that is
 * safe.  A job that has not started is taken out of the host's queue;
 * a safe change waiting to be confirmed is undone at once; pkg at work
 * in a jail is stopped by the agent; any other at work is left to
 * finish, as stopping a change half way is what would not be safe.  A
 * reading still on its way is no longer
 * waited for: the host may finish it, and nothing was to change.
 */
void
op_cancel(struct op *op)
{
	struct ctx	*c;
	char		 url[300];

	if (op->state != OP_RUNNING)
		return;
	if (op->job > 0) {
		c = ctx_new();
		snprintf(c->name, sizeof(c->name), "%s", op->title);
		rc_action(job_path(url, sizeof(url), op->sid, op->job,
		    "cancel"), NULL, NULL, job_cancel_cb, c);
		return;
	}
	if (op->live)
		live_cancel(op->id);
	else if (op->req != 0)
		arc_http_abort(op->req);
	else
		/* Nothing is on its way for it: it waits for an answer that
		 * cannot come, so it is given up here and now. */
		op_done(op, false, NULL, "given up");
}

/*
 * Request req, which task opid awaited, has been answered and its
 * callback has run.  A task the callback did not end — did not make a
 * job of, a live read, or hand on to another request — would wait for
 * ever: it is ended here by what the answer was.
 */
void
op_answered(int opid, int req, int status, const ucl_object_t *o,
    const char *err)
{
	struct op	*op;
	bool		 ok;

	if ((op = op_find(opid)) == NULL || op->req != req)
		return;
	op->req = 0;
	if (op->state != OP_RUNNING || op->job != 0 || op->live || op->await)
		return;
	ok = status >= 200 && status < 300 && (jget(o, "ok") == NULL ||
	    jbool(o, "ok"));
	if (!ok && err == NULL)
		err = status == 200 ? jstr(o, "error") : "no answer";
	op_done(op, ok, o, err);
}

/* Dotted versions compared number by number: <0, 0, >0. */
static int
version_cmp(const char *a, const char *b)
{
	char	*ea, *eb;

	for (;;) {
		unsigned long x = strtoul(a, &ea, 10);
		unsigned long y = strtoul(b, &eb, 10);

		if (x != y)
			return (x < y ? -1 : 1);
		if (*ea != '.' || *eb != '.')
			return ((*ea == '.') - (*eb == '.'));
		a = ea + 1;
		b = eb + 1;
	}
}

/*
 * The host runs an older arcana-agent than the one the console would
 * send.  By version: every change of the agent has its own, so a
 * version is a program, whoever built it, and an agent built on the
 * host by hand is not out of date for being another build; a newer one
 * is not offered the console's older.  By build, its SHA-256, only where
 * the console or the host has no version to tell.  A console with no
 * arcana-agent to send has nothing to offer.
 */
bool
agent_outdated(const struct server *s)
{
	const char	*b, *v;

	if (app.agent_build[0] == '\0' || s->list == NULL || s->failed)
		return (false);
	if (app.agent_version[0] != '\0' &&
	    (v = jstr(s->list, "host.version")) != NULL)
		return (version_cmp(v, app.agent_version) < 0);
	return ((b = jstr(s->list, "host.build")) == NULL ||
	    strcmp(b, app.agent_build) != 0);
}

/* The host runs the very build the console sends: an update took. */
static bool
agent_sent_runs(const struct server *s)
{
	const char	*b;

	return (s->list != NULL && !s->failed && (b = jstr(s->list,
	    "host.build")) != NULL && strcmp(b, app.agent_build) == 0);
}

static void
agent_update_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx	*c;
	struct server	*s;
	bool		 ok;

	c = arg;
	ok = status == 200 && jbool(o, "ok");
	if (status == 200 && !ok)
		err = jstr(o, "error");
	op_done(op_find(c->op), ok, o, err);
	if (!ok && status != 200 && (s = server_by_id(c->sid)) != NULL) {
		/* No answer about it, which an agent that restarted as it
		 * answered can leave: whether it runs the new build is
		 * asked of the host, and said either way. */
		toast(true, "%s: no answer about the agent update (%s); "
		    "asking the host which agent it runs", c->name, err !=
		    NULL ? err : "no answer");
		s->restart_until = arc_now() + RESTART_WATCH_MS;
		s->restart_asked = arc_now();
	} else if (!ok)
		toast(true, "%s: agent not updated: %s", c->name, err != NULL ?
		    err : "failed");
	else if (jbool(o, "restarting")) {
		toast(false, "%s: arcana-agent %s in place, restarting", c->name,
		    jstr(o, "version") != NULL ? jstr(o, "version") : "");
		/* Watched until it answers as the new build, or does not. */
		if ((s = server_by_id(c->sid)) != NULL) {
			s->restart_until = arc_now() + RESTART_WATCH_MS;
			s->restart_asked = arc_now();
		}
	}
	else
		toast(false, "%s: arcana-agent %s in place; it runs from the "
		    "next start of the service", c->name, jstr(o, "version") !=
		    NULL ? jstr(o, "version") : "");
	/* A restarted agent shows its version at the next refresh. */
	if (ok && !jbool(o, "restarting") && (s = server_by_id(c->sid)) != NULL)
		refresh_jails(s, false);
	free(c);
}

/*
 * The hosts whose agent was told to restart after an update: ask each
 * how it is every few seconds, and say when it answers as the build the
 * console sent, or when it has not after a while.  "In place" is not
 * "running": a service that is not enabled does not restart.
 */
void
agent_restarts(double now)
{
	struct server	*s;
	int		 i;

	for (i = 0; i < app.nservers; i++) {
		s = &app.servers[i];
		if (s->restart_until == 0)
			continue;
		if (agent_sent_runs(s) && now - s->restart_asked > 500) {
			s->restart_until = 0;
			toast(false, "%s now runs arcana-agent %s", s->name,
			    jstr(s->list, "host.version") != NULL ? jstr(s->list,
			    "host.version") : "");
			continue;
		}
		if (now > s->restart_until) {
			s->restart_until = 0;
			toast(true, "%s still runs the agent from before the "
			    "update: its service did not restart. The new "
			    "program is in place; on the host, see the log, "
			    "check arcana_agent_enable, and run \"service "
			    "arcana_agent restart\".", s->name);
			continue;
		}
		if (now - s->restart_asked >= RESTART_ASK_MS) {
			s->restart_asked = now;
			refresh_jails(s, false);
		}
	}
}

/* Send s the console's arcana-agent; restart its service with restart. */
void
agent_update(struct server *s, bool restart)
{
	struct ctx	*c;
	struct op	*op;
	char		 url[200];

	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->name, sizeof(c->name), "%s", s->name);
	op = op_new(restart ? "update agent and restart" : "update agent",
	    s->name);
	c->op = op->id;
	app.trace_op = op->id;
	rc_c(url, sizeof(url), "hosts/host=%s/agent-update", rc_key(s->id));
	rc_verb(url, restart ? "{\"restart\":true}" : NULL, NULL,
	    agent_update_cb, c);
}

static void
agent_build_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx	*c;
	bool		 ok;

	c = arg;
	ok = status == 200 && jbool(o, "ok");
	if (status == 200 && !ok)
		err = jstr(o, "error");
	op_done(op_find(c->op), ok, o, err);
	if (ok && c->dry_run)
		toast(false, "%s installed the console from the repository; "
		    "it restarts, and this page reconnects", c->name);
	else if (ok)
		toast(false, "%s built arcana-agent %s: the console sends it "
		    "from now on", c->name, jstr(o, "version") != NULL ?
		    jstr(o, "version") : "");
	else if (status == 200 && (jstr(o, "host_keys") != NULL ||
	    jstr(o, "deploy_key") != NULL)) {
		/*
		 * Over SSH, and the host needs a person: to confirm the
		 * server's host key, or to allow the host's key there.
		 */
		if (app.build_reply != NULL)
			ucl_object_unref(app.build_reply);
		app.build_reply = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
		snprintf(app.build_sid, sizeof(app.build_sid), "%s", c->sid);
		app.build_console = c->dry_run;
		app.modal = MODAL_HOST_KEY;
		app.modal_error[0] = '\0';
	} else
		toast(true, "%s: %s: %s", c->name, c->dry_run ? "console not "
		    "updated" : "agent not built", err != NULL ? err :
		    "failed");
	/* Which build the console has decides who is offered an update. */
	check_health();
	free(c);
}

/*
 * Have s build arcana-agent from the console's repository; host_keys,
 * if not NULL, are the SSH host keys of its server the user confirmed.
 * With console, it is the whole tree, installed there, and the console
 * restarted: its own update, on the host it runs on.
 */
static void
notes_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	app.notes_busy = false;
	if (status != 200 || jget(o, "notes") == NULL) {
		snprintf(app.notes_error, sizeof(app.notes_error), "%s", err !=
		    NULL ? err : "cannot read what is new");
		return;
	}
	if (app.notes != NULL)
		ucl_object_unref(app.notes);
	app.notes = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	app.notes_error[0] = '\0';
}

/*
 * What is new in the repository since a version (and up to another),
 * for the update boxes and the What's new tab: the release notes, or
 * the commits.
 */
void
notes_load(const char *component, const char *from, const char *to,
    bool fresh)
{
	char	url[256];

	snprintf(url, sizeof(url), "component=%s&from=%s%s%s%s", component,
	    from != NULL ? from : "", to != NULL && to[0] != '\0' ? "&to=" :
	    "", to != NULL ? to : "", fresh ? "&fresh=1" : "");
	snprintf(app.notes_for, sizeof(app.notes_for), "%s", component);
	app.notes_busy = true;
	app.notes_error[0] = '\0';
	if (app.notes != NULL) {
		ucl_object_unref(app.notes);
		app.notes = NULL;
	}
	rc_get(RC_C "update-notes", url, notes_cb, NULL);
}

void
agent_build(struct server *s, const char *host_keys, bool console)
{
	struct ctx	*c;
	struct op	*op;
	char		 url[200], *q, *body;

	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->name, sizeof(c->name), "%s", s->name);
	c->dry_run = console;		/* which of the two this is */
	op = op_new(console ? "update console" : "build agent", s->name);
	c->op = op->id;
	app.trace_op = op->id;
	app.dock_open = true;
	rc_c(url, sizeof(url), "hosts/host=%s/%s", rc_key(s->id), console ?
	    "console-update" : "agent-build");
	if (host_keys == NULL) {
		rc_verb(url, NULL, NULL, agent_build_cb, c);
		return;
	}
	q = json_quote(host_keys);
	if (asprintf(&body, "{\"host-keys\":%s}", q) == -1)
		abort();
	free(q);
	rc_verb(url, body, NULL, agent_build_cb, c);
	free(body);
}

static void
kput(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

static ucl_object_t *
fixed_setting(const char *key, const char *label, const char *v)
{
	ucl_object_t	*e;

	e = ucl_object_typed_new(UCL_OBJECT);
	kput(e, "key", ucl_object_fromstring(key));
	kput(e, "label", ucl_object_fromstring(label));
	kput(e, "value", ucl_object_fromstring(v != NULL ? v : ""));
	kput(e, "editable", ucl_object_frombool(false));
	return (e);
}

/*
 * arcana-console:settings as the forms read them: each setting of
 * source's, in its order, {key, label, help, type, value, set, base,
 * overridden, editable} (key and value as the console's file has
 * them: _ for -, a text), then those web.conf alone sets.
 */
static ucl_object_t *
settings_model(const ucl_object_t *rc)
{
	const ucl_object_t	*e, *v;
	ucl_object_iter_t	 it;
	ucl_object_t		*o, *a, *s;
	const char		*name;
	char			 key[64], set[80], path[400];
	char			*p;

	a = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(jget(rc, "source"), &it, true)) !=
	    NULL) {
		if ((name = jstr(e, "name")) == NULL)
			continue;
		snprintf(key, sizeof(key), "%s", name);
		for (p = key; *p != '\0'; p++)
			if (*p == '-')
				*p = '_';
		snprintf(set, sizeof(set), "%s-set", name);
		s = ucl_object_typed_new(UCL_OBJECT);
		kput(s, "key", ucl_object_fromstring(key));
		kput(s, "label", ucl_object_fromstring(jstr(e, "label") != NULL ?
		    jstr(e, "label") : key));
		kput(s, "help", ucl_object_fromstring(jstr(e, "help") != NULL ?
		    jstr(e, "help") : ""));
		v = ucl_object_lookup(rc, name);
		if (ucl_object_lookup(rc, set) != NULL) {
			kput(s, "type", ucl_object_fromstring("secret"));
			kput(s, "value", ucl_object_fromstring(""));
			kput(s, "set", ucl_object_frombool(jbool(rc, set)));
		} else {
			kput(s, "type", ucl_object_fromstring(
			    ucl_object_type(v) == UCL_BOOLEAN ? "bool" : "text"));
			kput(s, "value", ucl_object_fromstring(v != NULL ?
			    ucl_object_tostring_forced(v) : ""));
			/* A number's leaf takes a number back. */
			if (ucl_object_type(v) == UCL_INT)
				kput(s, "number", ucl_object_frombool(true));
		}
		kput(s, "base", ucl_object_fromstring(jstr(e, "web-conf") !=
		    NULL ? jstr(e, "web-conf") : ""));
		kput(s, "overridden", ucl_object_frombool(jbool(e,
		    "overridden")));
		kput(s, "editable", ucl_object_frombool(true));
		ucl_array_append(a, s);
	}
	ucl_array_append(a, fixed_setting("rp_id", "Relying party", jstr(rc,
	    "fixed.relying-party")));
	ucl_array_append(a, fixed_setting("origin", "Origin", jstr(rc,
	    "fixed.origin")));
	ucl_array_append(a, fixed_setting("datadir", "Data directory",
	    jstr(rc, "fixed.data-directory")));
	ucl_array_append(a, fixed_setting("cookie_secure", "Session cookie "
	    "over HTTPS only", jbool(rc, "fixed.cookie-secure") ? "true" :
	    "false"));
	ucl_array_append(a, fixed_setting("tls", "Certificates for the agents",
	    jstr(rc, "fixed.agent-certificates")));
	o = ucl_object_typed_new(UCL_OBJECT);
	kput(o, "settings", a);
	snprintf(path, sizeof(path), "%s/settings.json", jstr(rc,
	    "fixed.data-directory") != NULL ? jstr(rc,
	    "fixed.data-directory") : "");
	kput(o, "file", ucl_object_fromstring(path));
	return (o);
}

static void
settings_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	bool	saved;

	saved = arg != NULL;
	app.modal_busy = false;
	if (status != 200 || jget(o, "source") == NULL) {
		/* Refused to a session an API token opened: the page says
		 * so already, as soon as it knows the session is one. */
		if (status != 401 && !(status == 403 && app.by_token))
			snprintf(app.modal_error, sizeof(app.modal_error), "%s",
			    err != NULL ? err : "cannot load the settings");
		return;
	}
	if (app.settings != NULL)
		ucl_object_unref(app.settings);
	app.settings = settings_model(o);
	app.modal_error[0] = '\0';
	load_push();
	if (saved) {
		app.modal = MODAL_NONE;
		toast(false, "Settings saved");
		/* What the console sends and checks may have changed. */
		check_health();
		check_update();
	}
}

static void
mail_test_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	app.modal_busy = false;
	if (status == 200)
		toast(false, "A test mail went to %s", jstr(o, "to") != NULL ?
		    jstr(o, "to") : "them");
	else
		toast(true, "No mail sent: %s", err != NULL ? err : "failed");
}

void
mail_test(void)
{
	char	url[200];

	app.modal_busy = true;
	rc_action(rc_c(url, sizeof(url), "settings/mail-test"), NULL, NULL,
	    mail_test_cb, NULL);
}

static void
telegram_test_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{

	(void)arg;
	app.modal_busy = false;
	if (status == 200)
		toast(false, "A test message went to %s", jstr(o, "to") != NULL ?
		    jstr(o, "to") : "the chats");
	else
		toast(true, "No message sent: %s", err != NULL ? err : "failed");
}

void
telegram_test(void)
{
	char	url[200];

	app.modal_busy = true;
	rc_action(rc_c(url, sizeof(url), "settings/telegram-test"), NULL, NULL,
	    telegram_test_cb, NULL);
}

/* Which form a setting is in: the console's, mail's or Telegram's. */
int
setting_group(const char *key)
{

	return (strncmp(key, "mail_", 5) == 0 ?
	    SETG_MAIL : strncmp(key, "telegram_", 9) == 0 ? SETG_TELEGRAM :
	    strncmp(key, "ldap_", 5) == 0 ? SETG_LDAP : strncmp(key,
	    "notify_", 7) == 0 ? SETG_ALERTS : SETG_CONSOLE);
}

void
load_settings(void)
{

	/* Not to a session an API token opened: refused, and the page
	 * says so already. */
	char	url[200];

	if (app.by_token)
		return;
	rc_get(rc_c(url, sizeof(url), "settings"), NULL, settings_cb, NULL);
}

/* The settings merged: read again, said saved. */
static void
settings_put_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{
	char	url[200];

	(void)arg;
	if (status < 200 || status > 299) {
		app.modal_busy = false;
		snprintf(app.modal_error, sizeof(app.modal_error), "%s", err !=
		    NULL ? err : "not kept");
		return;
	}
	rc_get(rc_c(url, sizeof(url), "settings"), NULL, settings_cb,
	    &app.settings);
}

/*
 * Every setting of the form sent, one YANG Patch (RFC 8072): each leaf
 * merged; the console keeps what differs.  The mail's are a form of
 * their own, on the Notifications tab: each form sends its own.  A
 * secret left empty, or a leaf empty that was, is left out: as it is; a
 * number emptied is removed, web.conf's again.
 */
void
save_settings(const ucl_object_t *f, int group)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct html		 b;
	const char		*key, *type, *v;
	char			*q, name[64], *p, url[200];
	int			 n;

	memset(&b, 0, sizeof(b));
	h_raw(&b, "{\"ietf-yang-patch:yang-patch\":{\"patch-id\":\"settings\","
	    "\"edit\":[");
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(jget(app.settings, "settings"), &it,
	    true)) != NULL) {
		if (!jbool(e, "editable") || (key = jstr(e, "key")) == NULL ||
		    setting_group(key) != group)
			continue;
		type = jstr(e, "type") != NULL ? jstr(e, "type") : "text";
		v = jstr(f, key) != NULL ? jstr(f, key) : "";
		if (strcmp(type, "bool") != 0 && v[0] == '\0' &&
		    (strcmp(type, "secret") == 0 || jstr(e, "value") == NULL ||
		    jstr(e, "value")[0] == '\0'))
			continue;
		snprintf(name, sizeof(name), "%s", key);
		for (p = name; *p != '\0'; p++)
			if (*p == '_')
				*p = '-';
		n++;
		if (jbool(e, "number") && v[0] == '\0') {
			h_fmt(&b, "%s{\"edit-id\":\"%d\",\"operation\":\"remove\","
			    "\"target\":\"/%s\"}", n > 1 ? "," : "", n, name);
			continue;
		}
		h_fmt(&b, "%s{\"edit-id\":\"%d\",\"operation\":\"merge\","
		    "\"target\":\"/%s\",\"value\":{\"arcana-console:%s\":",
		    n > 1 ? "," : "", n, name, name);
		if (strcmp(type, "bool") == 0)
			h_raw(&b, jbool(f, key) ? "true" : "false");
		else if (jbool(e, "number") && strspn(v, "0123456789") ==
		    strlen(v))
			h_raw(&b, v);
		else {
			q = json_quote(v);
			h_raw(&b, q);
			free(q);
		}
		h_raw(&b, "}}");
	}
	h_raw(&b, "]}}");
	app.modal_busy = true;
	app.modal_error[0] = '\0';
	if (n == 0) {
		settings_put_cb(204, NULL, NULL, NULL);
		free(b.s);
		return;
	}
	rc_edit("PATCH", rc_c(url, sizeof(url), "settings"), b.s,
	    settings_put_cb, NULL);
	free(b.s);
}

/* Add address to interface ifname of s as an alias, or take it off. */
void
if_address(struct server *s, const char *ifname, const char *address,
    bool remove, bool persist)
{
	char	*qi, *qa, *json, title[160];

	qi = json_quote(ifname);
	qa = json_quote(address);
	if (asprintf(&json, "{\"kind\":\"if-address\",\"interface\":%s,"
	    "\"address\":%s,\"remove\":%s,\"persist\":%s,\"safe\":true}", qi,
	    qa, remove ? "true" : "false", persist ? "true" : "false") == -1)
		abort();
	free(qi);
	free(qa);
	snprintf(title, sizeof(title), "%s: %s %s", ifname, remove ? "remove" :
	    "add", address);
	job_send(s, json, title, JOB_IFACE, ifname);
}

/* Bring interface ifname of s up or down. */
void
if_state(struct server *s, const char *ifname, bool up)
{
	char	*qi, *json, title[160];

	qi = json_quote(ifname);
	if (asprintf(&json, "{\"kind\":\"if-state\",\"interface\":%s,"
	    "\"up\":%s,\"safe\":true}", qi, up ? "true" : "false") == -1)
		abort();
	free(qi);
	snprintf(title, sizeof(title), "%s: %s", ifname, up ? "up" : "down");
	job_send(s, json, title, JOB_IFACE, ifname);
}

/*
 * Add a static route on s, or delete the one to destination; kept in
 * rc.conf by name when one is given.  keep: rc.conf alone, the kernel's
 * table as it is (a route BIRD puts there, say); with a name and no
 * gateway, the one rc.conf keeps renamed.
 */
void
route_change(struct server *s, const char *destination, const char *gateway,
    bool remove, bool persist, int fib, int metric, int weight,
    const char *source, const char *name, bool keep)
{
	char	*qd, *qg, *qs, *qn, *json, title[200], more[300];
	bool	 named;

	named = name != NULL && name[0] != '\0';
	qd = json_quote(destination);
	qg = json_quote(gateway);
	qs = json_quote(source != NULL ? source : "");
	qn = json_quote(named ? name : "");
	/* Its cost, its share, where it is sent from, its name: when
	 * given. */
	snprintf(more, sizeof(more), "%s%.0d%s%.0d%s%s%s%s%s%s", metric > 0 ?
	    ",\"metric\":" : "", metric > 0 ? metric : 0, weight > 0 ?
	    ",\"weight\":" : "", weight > 0 ? weight : 0, source != NULL &&
	    source[0] != '\0' ? ",\"source\":" : "", source != NULL &&
	    source[0] != '\0' ? qs : "", named ? ",\"route_name\":[" : "",
	    named ? qn : "", named ? "]" : "", keep ? ",\"verb\":\"keep\"" :
	    "");
	/* Safe, unless it is a delete that could not be put back, or
	 * rc.conf's alone. */
	if (asprintf(&json, "{\"kind\":\"route\",\"destination\":%s%s%s,"
	    "\"remove\":%s,\"persist\":%s,\"fib\":%d%s,\"safe\":%s}", qd,
	    gateway[0] != '\0' ? ",\"gateway\":" : "", gateway[0] != '\0' ?
	    qg : "", remove ? "true" : "false", persist || keep ? "true" :
	    "false", fib, more, !keep && (!remove || gateway[0] != '\0') ?
	    "true" : "false") == -1)
		abort();
	free(qd);
	free(qg);
	free(qs);
	free(qn);
	if (keep && !remove && gateway[0] == '\0')
		snprintf(title, sizeof(title), "route %s kept as %s",
		    destination, named ? name : "");
	else
		snprintf(title, sizeof(title), "route %s%s %s%s%s%s%s",
		    keep ? "keep " : "", remove ? "delete" : "add",
		    destination, gateway[0] != '\0' ? " via " : "", gateway,
		    named ? " as " : "", named ? name : "");
	job_send(s, json, title, JOB_IFACE, destination);
}

/*
 * An action on service name of host s is under way.  Asked of the
 * entries of the activity list, which know their host: a service of
 * the same name on another host is another service.
 */
bool
service_busy(const struct server *s, const char *name)
{
	const struct op	*o;
	int		 i;

	for (i = 0; i < app.nops; i++) {
		o = &app.ops[i];
		if (o->state == OP_RUNNING && o->what == JOB_SERVICE &&
		    strcmp(o->sid, s->id) == 0 && strcmp(o->target, name) == 0)
			return (true);
	}
	/* Its configuration's commit on its way. */
	return (svc_yc.busy && strcmp(svc_yc.sid, s->id) == 0 &&
	    strcmp(svc_yc_name, name) == 0);
}

/* An upgrade of the packages shown, of this host or jail, is under way. */
bool
packages_busy(const struct server *s)
{
	const struct op	*o;
	int		 i;

	for (i = 0; i < app.nops; i++) {
		o = &app.ops[i];
		if (o->state == OP_RUNNING && o->what == JOB_PACKAGES &&
		    strcmp(o->sid, s->id) == 0 && strcmp(o->target,
		    app.pkg.jail) == 0)
			return (true);
	}
	return (false);
}

static void
push_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*a, *d;

	if (status != 200)
		return;
	if (app.push != NULL)
		ucl_object_unref(app.push);
	/* arcana-console's push: the user's own subscriptions, devices. */
	a = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(jget(o, "subscription"), &it, true)) !=
	    NULL) {
		d = ucl_object_copy(e);
		ucl_object_delete_key(d, "added");
		if (jstr(e, "added") != NULL)
			kput(d, "added", ucl_object_fromint(rc_time(jstr(e,
			    "added"))));
		ucl_array_append(a, d);
	}
	app.push = ucl_object_typed_new(UCL_OBJECT);
	kput(app.push, "devices", a);
}

/*
 * The API tokens, for the settings to show: arcana-console's, each
 * {id, name, kind, created, last} with its times in seconds.
 */
static void
tokens_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*m, *a, *t;

	(void)err;
	(void)arg;
	if (status != 200)
		return;
	a = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(jget(o, "token"), &it, true)) != NULL) {
		t = ucl_object_typed_new(UCL_OBJECT);
		kput(t, "id", ucl_object_fromstring(jstr(e, "id")));
		kput(t, "name", ucl_object_fromstring(jstr(e, "name")));
		kput(t, "kind", ucl_object_fromstring(jstr(e, "kind") != NULL ?
		    jstr(e, "kind") : "read"));
		kput(t, "created", ucl_object_fromint(rc_time(jstr(e,
		    "created"))));
		kput(t, "last", ucl_object_fromint(rc_time(jstr(e,
		    "last-used"))));
		ucl_array_append(a, t);
	}
	m = ucl_object_typed_new(UCL_OBJECT);
	kput(m, "tokens", a);
	if (app.tokens != NULL)
		ucl_object_unref(app.tokens);
	app.tokens = m;
}

void
load_tokens(void)
{
	char	url[200];

	rc_get(rc_c(url, sizeof(url), "tokens"), NULL, tokens_cb, NULL);
}

/* A new one made: its value is in this reply only, shown once. */
static void
token_made_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200 || jstr(o, "token") == NULL) {
		toast(true, "The token was not made: %s", err != NULL ? err :
		    "no answer");
		return;
	}
	snprintf(app.token_value, sizeof(app.token_value), "%s", jstr(o,
	    "token"));
	app.token_name[0] = '\0';
	load_tokens();
}

void
token_new(void)
{
	char	*q, *body, url[200];

	if (app.token_name[0] == '\0') {
		toast(true, "A token is made with a name: what will use it");
		return;
	}
	q = json_quote(app.token_name);
	if (asprintf(&body, "{\"name\":%s,\"kind\":\"%s\"}", q,
	    app.token_write ? "write" : "read") == -1)
		abort();
	free(q);
	rc_action(rc_c(url, sizeof(url), "tokens/create"), body, NULL,
	    token_made_cb, NULL);
	free(body);
}

static void
token_gone_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status < 200 || status > 299)
		toast(true, "The token was not deleted: %s", err != NULL ? err :
		    "no answer");
	load_tokens();
}

void
token_del(const char *id)
{
	char	url[200];

	if (strlen(id) != 16 || id[strspn(id, "0123456789abcdef")] != '\0')
		return;
	rc_edit("DELETE", rc_c(url, sizeof(url), "tokens/token=%s", id), NULL,
	    token_gone_cb, NULL);
}

/* The devices that are told of tasks, for the settings to show. */
void
load_push(void)
{

	rc_get(RC_C "push", NULL, push_cb, NULL);
}


/*
 * Which of pkg's repositories an action (upgrade, install, base) takes
 * from on s, in a jail or on the host ("" or NULL): what was chosen
 * there last time, kept with the server by the console; "" for any.
 */
const char *
pkg_repo_kept(const struct server *s, const char *jail, const char *action)
{
	const ucl_object_t	*h, *e;
	ucl_object_iter_t	 it = NULL;
	const char		*key, *v;

	if (s == NULL || (h = host_rc(s->id)) == NULL)
		return ("");
	key = jail != NULL && jail[0] != '\0' ? jail : ".";
	while ((e = ucl_object_iterate(jget(h, "pkg-repos"), &it, true)) !=
	    NULL)
		if (jstr(e, "jail") != NULL && strcmp(jstr(e, "jail"), key) ==
		    0)
			return ((v = jstr(e, action)) != NULL ? v : "");
	return ("");
}

static void
repo_kept_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)o;
	(void)arg;
	if (status < 200 || status > 299)
		toast(true, "The repository chosen was not kept by the "
		    "console: %s", err != NULL ? err : "no answer");
	else
		refresh_servers();
}

/* The choice made now, kept with the server for the next time. */
void
pkg_repo_keep(struct server *s, const char *jail, const char *action,
    const char *repo)
{
	ucl_object_t		*e, *all, *jo;
	const ucl_object_t	*j;
	ucl_object_iter_t	 it = NULL;
	const char		*key;

	if (s == NULL)
		return;
	repo = repo != NULL ? repo : "";
	if (strcmp(pkg_repo_kept(s, jail, action), repo) == 0 ||
	    (e = host_conf(s->id)) == NULL)
		return;
	key = jail != NULL && jail[0] != '\0' ? jail : ".";
	if ((all = (ucl_object_t *)(uintptr_t)jget(e, "pkg-repos")) == NULL) {
		all = ucl_object_typed_new(UCL_ARRAY);
		ucl_object_insert_key(e, all, "pkg-repos", 0, false);
	}
	jo = NULL;
	while ((j = ucl_object_iterate(all, &it, true)) != NULL)
		if (jstr(j, "jail") != NULL && strcmp(jstr(j, "jail"), key) ==
		    0)
			jo = (ucl_object_t *)(uintptr_t)j;
	if (jo == NULL) {
		jo = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(jo, ucl_object_fromstring(key), "jail", 0,
		    true);
		ucl_array_append(all, jo);
	}
	ucl_object_replace_key(jo, ucl_object_fromstring(repo), action, 0,
	    true);
	host_put(s->id, e, repo_kept_cb, NULL);
}
