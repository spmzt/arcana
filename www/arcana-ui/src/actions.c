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
	enum pending pend;
	int	net_kind;	/* the network table asked for */
	bool	more;		/* rows to add to those there are */
	int	op_family;	/* and its family */
};

static void	osversion_ask(const char *, bool);
static void	 who_set(const ucl_object_t *);
static struct ctx *ctx_new(void);
static struct op *op_new(const char *, const char *);
static void	op_done(struct op *, bool, const ucl_object_t *, const char *);
static struct server *server_by_id(const char *);
static void	merge_jail(struct server *, const ucl_object_t *);
static char	*emit(const ucl_object_t *);
static api_cb	 key_added_cb;

/*
 * A name a host gave, to go into the path of a request: only what
 * leaves the path the one that was meant.
 */
static bool
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

	return (kind == NET_WIREGUARD ? "wireguard" : kind == NET_BIRD ?
	    "bird" : kind == NET_IPSEC ? "strongswan" : NULL);
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
	if ((p = strstr(url, "/api/servers/")) != NULL) {
		p += strlen("/api/servers/");
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
	if (status == 200 && jget(o, "job.trace") != NULL)
		op->trace = ucl_object_copy(jget(o, "job.trace"));
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
	char		 url[128];

	if (op == NULL || op->trace != NULL || op->watched <= 0 ||
	    op->sid[0] == '\0' || op->state == OP_RUNNING)
		return;
	c = ctx_new();
	c->op = op->id;
	snprintf(url, sizeof(url), "/api/servers/%s/jobs/%lld", op->sid,
	    op->watched);
	api("GET", url, NULL, trace_fetch_cb, c);
}

static void
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
	case JOB_SERVICE_CONFIG:
		s->services_loading = false;
		if (s->services != NULL)
			refresh_services(s, false);
		if (op->what == JOB_SERVICE_CONFIG &&
		    strcmp(app.service, op->target) == 0) {
			app.svc_loading = false;
			snprintf(app.svc_error, sizeof(app.svc_error), "%s",
			    ok ? "" : err != NULL ? err : "failed");
			service_config(op->target, NULL);
		}
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
	case JOB_SNORT:
		snort_refresh();
		break;
	case JOB_SECURITY:
		/* The host's plugins, and the page's read of them. */
		refresh_jails(s, false);
		secpage_refresh();
		break;
	case JOB_PROCESS:
		refresh_procs(s, true);
		break;
	case JOB_SYSCTL:
		refresh_sysctl(s, true);
		break;
	case JOB_FIREWALL:
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
			osversion_ask(err, false);
		break;
	}
	app.quiet = false;
	toast(!ok, "%s: %s", op->title, ok ? "done" : err != NULL ? err :
	    "failed");
}

static void
job_poll_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx		*c;
	struct op		*op;
	const ucl_object_t	*t;
	const char		*st;
	bool			 ok;

	c = arg;
	op = op_find(c->op);
	free(c);
	if (op == NULL || op->job == 0)
		return;
	op->polling = false;
	op->next_poll = arc_now() + JOB_POLL_MS;
	if (status != 200 || jget(o, "job") == NULL) {
		/* The console or the host is away; the job is not. */
		if (status == 200 && !jbool(o, "ok")) {
			op_done(op, false, o, jstr(o, "error"));
			job_finished(op, false, jstr(o, "error"));
			return;
		}
		op->waiting = true;
		op->next_poll = arc_now() + 2 * JOB_POLL_MS;
		return;
	}
	op->waiting = false;
	if (jstr(o, "job.state") != NULL)
		snprintf(op->stage, sizeof(op->stage), "%s", jstr(o,
		    "job.state"));
	if ((t = jget(o, "job.trace")) != NULL) {
		if (op->trace != NULL)
			ucl_object_unref(op->trace);
		op->trace = ucl_object_ref((ucl_object_t *)(uintptr_t)t);
	}
	st = jstr(o, "job.state");
	if (st == NULL || (strcmp(st, "done") != 0 &&
	    strcmp(st, "cancelled") != 0))
		return;
	ok = strcmp(st, "done") == 0 && jbool(o, "job.ok");
	err = strcmp(st, "cancelled") == 0 ? "cancelled" :
	    jstr(o, "job.error");
	op->state = ok ? OP_OK : OP_FAILED;
	op->finished = arc_now();
	if (!ok)
		snprintf(op->error, sizeof(op->error), "%s", err != NULL ? err :
		    "failed");
	{
		char body[256];

		snprintf(body, sizeof(body), "%s on %s: %s", op->title,
		    op->server, ok ? "done" : op->error);
		/* Here, when it took a while; and every change that this
		 * browser asked for, to the other devices that are told. */
		if (op->finished - op->started >= NOTIFY_MS)
			arc_notify(ok ? "Arcana: done" : "Arcana: failed", body);
		if (op->what != JOB_WATCH)
			arc_push_send(ok ? "Arcana: done" : "Arcana: failed",
			    body);
	}
	job_finished(op, ok, err);
}

/* Read every running job that is due; called from the clock. */
void
jobs_poll(void)
{
	struct ctx	*c;
	struct op	*op;
	char		 url[128];
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
		snprintf(url, sizeof(url), "/api/servers/%s/jobs/%lld", op->sid,
		    op->job);
		api("GET", url, NULL, job_poll_cb, c);
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
		snprintf(path, sizeof(path), "jobs.%d.id", i);
		if (status == 200 && jbool(o, "ok") && jget(o, path) != NULL) {
			op->job = op->watched = jint(o, path, 0);
			op->next_poll = arc_now();
			snprintf(op->stage, sizeof(op->stage), "accepted");
			continue;
		}
		if (status == 200)
			err = jstr(o, "error");
		op_done(op, false, o, err);
		op->job = -1;
		job_finished(op, false, err);
	}
	free(sub);
	jobs_poll();
}

/* Send the batch (n jobs, with an op each) to the server. */
static void
jobs_submit(struct server *s, struct queued *q, int n)
{
	struct submit	*sub;
	struct op	*op;
	char		*body, *p, url[128];
	size_t		 len;
	int		 i;

	if ((sub = calloc(1, sizeof(*sub))) == NULL)
		abort();
	len = 16;
	for (i = 0; i < n; i++)
		len += strlen(q[i].json) + 1;
	if ((body = malloc(len)) == NULL)
		abort();
	p = body + sprintf(body, "{\"jobs\":[");
	/* Ops are newest first: make them in reverse, the first job last. */
	for (i = 0; i < n; i++)
		p += sprintf(p, "%s%s", i > 0 ? "," : "", q[i].json);
	sprintf(p, "]}");
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
	snprintf(url, sizeof(url), "/api/servers/%s/jobs", s->id);
	/* One request for them all: each says it. */
	for (i = 0; i < sub->nops; i++)
		if ((op = op_find(sub->ops[i])) != NULL) {
			snprintf(op->method, sizeof(op->method), "POST");
			snprintf(op->url, sizeof(op->url), "%s", url);
			op->await = false;
		}
	api("POST", url, body, job_submit_cb, sub);
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

	api("GET", "/api/update", NULL, update_cb, NULL);
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
	snprintf(app.local, sizeof(app.local), "%s", jstr(o, "local") != NULL ?
	    jstr(o, "local") : "");
	snprintf(app.local_agent, sizeof(app.local_agent), "%s", jstr(o,
	    "local_agent") != NULL ? jstr(o, "local_agent") : "");
	a = jget(o, "servers");
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
		s->local = jbool(e, "local");
		s->safe_wait = (int)jint(e, "safe_wait", 0);
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
}

void
refresh_servers(void)
{

	api("GET", "/api/servers", NULL, servers_cb, NULL);
	/* Settings' rollback timer is told on each host's System tab. */
	if (app.settings == NULL)
		load_settings();
}

static void
jails_cb(int status, const ucl_object_t *o, const char *err, void *arg)
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
	s->loading = false;
	/* Given up here: that says nothing about the host. */
	if (status == 0 && err != NULL && strcmp(err, "cancelled") == 0) {
		op_done(op, false, o, err);
		free(c);
		return;
	}
	if (status == 200) {
		if (s->list != NULL)
			ucl_object_unref(s->list);
		s->list = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
		s->fetched = arc_now();
		s->failed = false;
		s->error[0] = '\0';
		op_done(op, jbool(o, "ok"), o, jstr(o, "error"));
	} else {
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
	char		 url[128], title[160];

	if (!app.online || (s->loading && !user))
		return;
	if (!s->loading)
		s->loading_since = arc_now();
	s->loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	c->user = user = user && !app.quiet;
	snprintf(url, sizeof(url), "/api/servers/%s/jails", s->id);
	/* Asked for: a task, its steps drawn as the host takes them. */
	if (user) {
		snprintf(title, sizeof(title), "list jails");
		op = op_new(title, s->name);
		c->op = op->id;
		live_read(s->id, "jails", url, c->op, jails_cb, c);
		return;
	}
	op_wait(c->op, api("GET", url, NULL, jails_cb, c));
}

/* A tab's read asked for: its task, then what the tab does with it. */
struct hread {
	int	 op;
	api_cb	*cb;
	void	*arg;
};

static void
hread_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct hread	 h = *(struct hread *)arg;
	const char	*e;
	bool		 ok;

	free(arg);
	e = err != NULL ? err : jstr(o, "error.message") != NULL ?
	    jstr(o, "error.message") : jstr(o, "error");
	ok = status == 200 && e == NULL && (jget(o, "ok") == NULL ||
	    jbool(o, "ok"));
	op_done(op_find(h.op), ok, o, ok ? NULL : e != NULL ? e :
	    "no answer from the console");
	h.cb(status, o, err, h.arg);
}

/*
 * A read of host s's for a tab: read is the path after
 * /api/servers/<id>/, with its query.  One the user asked for (opening
 * the tab, Refresh) is a task called title, its steps drawn as the host
 * takes them over the console's socket; the others, as a tab reads on
 * by itself, are a plain GET and no task.
 */
void
host_read(const struct server *s, const char *read, const char *title,
    bool user, api_cb *cb, void *arg)
{
	struct hread	*h;
	struct op	*op;
	char		 url[400];

	snprintf(url, sizeof(url), "/api/servers/%s/%s", s->id, read);
	if (!user || app.quiet) {
		api("GET", url, NULL, cb, arg);
		return;
	}
	if ((h = calloc(1, sizeof(*h))) == NULL)
		abort();
	op = op_new(title, s->name);
	h->op = op->id;
	h->cb = cb;
	h->arg = arg;
	live_read(s->id, read, url, op->id, hread_cb, h);
}

/* start, stop, restart or kill a jail of the selected server: a job. */
void
jail_action(const char *jail, const char *action)
{
	struct server	*s;
	char		 title[160], *qj, *json;

	if ((s = cur_server()) == NULL)
		return;
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
		s->services = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
		s->services_fetched = arc_now();
		s->services_error[0] = '\0';
		op_done(op, jbool(o, "ok"), o, jstr(o, "error"));
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
	char		 url[128];

	if (!app.online || s->services_loading)
		return;
	s->services_loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	c->user = user = user && !app.quiet;
	snprintf(url, sizeof(url), "/api/servers/%s/services", s->id);
	if (user) {
		op = op_new("list services", s->name);
		c->op = op->id;
		app.trace_op = op->id;
		live_read(s->id, "services", url, c->op, services_cb, c);
		return;
	}
	op_wait(c->op, api("GET", url, NULL, services_cb, c));
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

/* start, stop, restart, reload, enable or disable a service: a job. */
void
service_action(const char *name, const char *action)
{
	struct server	*s;
	char		 title[160], *qn, *json;

	if ((s = cur_server()) == NULL)
		return;
	snprintf(title, sizeof(title), "service %s %s", name, action);
	qn = json_quote(name);
	if (asprintf(&json, "{\"kind\":\"service-action\",\"service\":%s,"
	    "\"action\":\"%s\"}", qn, action) == -1)
		abort();
	free(qn);
	job_send(s, json, title, JOB_SERVICE, name);
}

static void
service_config_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{
	struct ctx	*c;
	struct server	*s;
	struct op	*op;
	bool		 ok;

	c = arg;
	op = c->op != 0 ? op_find(c->op) : NULL;
	app.svc_loading = false;
	ok = status == 200 && jbool(o, "ok");
	if (status == 200 && !ok)
		err = jstr(o, "error");
	op_done(op, ok, o, err);
	if (status == 200 && strcmp(app.service, c->jail) == 0) {
		if (app.svc_config != NULL)
			ucl_object_unref(app.svc_config);
		app.svc_config = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	}
	snprintf(app.svc_error, sizeof(app.svc_error), "%s", ok ? "" :
	    err != NULL ? err : "failed");
	if ((s = server_by_id(c->sid)) != NULL)
		merge_service(s, jget(o, "service"));
	if (c->user)
		toast(ok ? false : true, "%s: %s", c->jail, ok ? "configured" :
		    err != NULL ? err : "failed");
	free(c);
}

/*
 * A service's rc.conf variables: read them (body NULL), or change them
 * with {"set": {...}, "unset": [...]} and read them back.
 */
void
service_config(const char *name, const char *body)
{
	struct server	*s;
	struct ctx	*c;
	struct op	*op;
	char		 url[512], title[160];

	if ((s = cur_server()) == NULL)
		return;
	if (body != NULL) {
		/* {"set": ..} becomes {"kind": .., "service": .., "set": ..}. */
		char *qn = json_quote(name), *json;

		snprintf(title, sizeof(title), "service %s configure", name);
		if (asprintf(&json, "{\"kind\":\"service-config\","
		    "\"service\":%s,%s", qn, body + 1) == -1)
			abort();
		free(qn);
		if (!app.queue_on)
			app.svc_loading = true;
		job_send(s, json, title, JOB_SERVICE_CONFIG, name);
		return;
	}
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->jail, sizeof(c->jail), "%s", name);
	c->user = body != NULL;
	snprintf(title, sizeof(title), "service %s %s", name, body != NULL ?
	    "configure" : "config");
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
	snprintf(url, sizeof(url), "/api/servers/%s/services/%s/config",
	    s->id, name);
	api(body != NULL ? "POST" : "GET", url, body, service_config_cb, c);
}

static void
stats_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx		*c;
	struct server		*s;
	const ucl_object_t	*st, *p;
	ucl_object_iter_t	 it;
	double			 total, alloc, size, used;
	int			 i;

	c = arg;
	if ((s = server_by_id(c->sid)) == NULL) {
		free(c);
		return;
	}
	s->stats_loading = false;
	if (status != 200 || !jbool(o, "ok")) {
		free(c);
		return;
	}
	if (s->stats != NULL)
		ucl_object_unref(s->stats);
	s->stats = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	s->stats_fetched = arc_now();
	st = jget(o, "stats");
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
	free(c);
}

static void
jobs_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx	*c;
	struct server	*s;

	c = arg;
	if ((s = server_by_id(c->sid)) != NULL) {
		s->jobs_loading = false;
		if (status == 200 && jget(o, "jobs") != NULL) {
			if (s->jobs != NULL)
				ucl_object_unref(s->jobs);
			s->jobs = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
		}
	}
	free(c);
}

/* The host's own record of jobs, whoever queued them; quiet. */
void
refresh_jobs(struct server *s)
{
	struct ctx	*c;
	char		 url[128];

	if (!app.online || s->jobs_loading)
		return;
	s->jobs_loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(url, sizeof(url), "/api/servers/%s/jobs", s->id);
	api("GET", url, NULL, jobs_cb, c);
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
	char		 url[128];

	if (!app.online || s->stats_loading)
		return;
	s->stats_loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(url, sizeof(url), "/api/servers/%s/stats", s->id);
	api("GET", url, NULL, stats_cb, c);
}

/*
 * pkg refused packages built for a newer FreeBSD than the host's: the
 * same asked again past OSVERSION, once it is approved.
 */
static void
osversion_ask(const char *err, bool dry_run)
{
	char	body[700];

	if (err == NULL || strstr(err, "OSVERSION") == NULL)
		return;
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
	    "do-pkg-anyos", "", app.pkg.names != NULL ? app.pkg.names : "");
}

static void
packages_cb(int status, const ucl_object_t *o, const char *err, void *arg)
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
	if (strcmp(app.pkg.sid, c->sid) == 0 &&
	    strcmp(app.pkg.jail, c->jail) == 0 && (c->dry_run || jget(o,
	    "upgraded") != NULL || c->net_kind == app.pkg.mode)) {
		app.pkg.loading = false;
		app.pkg.busy = false;
		if (ok) {
			ucl_object_t	*nd;

			/* An upgrade's reply says no repositories: those the
			 * read before said are kept, the choice with them. */
			nd = ucl_object_copy(o);
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
	if (!ok && c->user)
		osversion_ask(err, c->dry_run);
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
	char		 url[512], title[160];

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
	}
	snprintf(app.pkg.sid, sizeof(app.pkg.sid), "%s", s->id);
	app.pkg.loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->jail, sizeof(c->jail), "%s", app.pkg.jail);
	/* Which view asked: an answer for the other is not shown. */
	c->net_kind = app.pkg.mode;
	snprintf(title, sizeof(title), "%s%s%s", refresh && app.pkg.mode ==
	    1 ? "pkg update, " : "", app.pkg.mode == 0 ? "installed packages" :
	    "pending packages", app.pkg.jail[0] != '\0' ? " of jail " : "");
	strlcat(title, app.pkg.jail, sizeof(title));
	/* The installed are the host's own: the repository is not asked. */
	snprintf(url, sizeof(url), "/api/servers/%s/packages?jail=%s%s%s%s",
	    s->id, url_word(app.pkg.jail) ? app.pkg.jail : "",
	    app.pkg.mode == 0 ? "&installed=1" : refresh ? "&refresh=1" : "",
	    app.pkg.ip == 4 ? "&ip=4" : app.pkg.ip == 6 ? "&ip=6" : "", "");
	/* Read again by the page itself (after an upgrade): no task. */
	if (app.quiet) {
		api("GET", url, NULL, packages_cb, c);
		return;
	}
	op = op_new(title, s->name);
	c->op = op->id;
	app.trace_op = op->id;
	live_read(s->id, url + strlen("/api/servers/") + strlen(s->id) + 1,
	    url, c->op, packages_cb, c);
}

/* pkg upgrade of the named packages (JSON array text), or of all. */
void
pkg_upgrade(struct server *s, const char *names, bool dry_run, bool anyos)
{
	struct ctx	*c;
	struct op	*op;
	char		 url[160], title[200], *qj, *qr, *body;

	if (!app.online || app.pkg.busy)
		return;
	/* What it is asked of, to ask it again past OSVERSION. */
	free(app.pkg.names);
	app.pkg.names = names != NULL ? strdup(names) : NULL;
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
	qj = json_quote(app.pkg.jail);
	qr = json_quote(app.pkg.repo);
	if (asprintf(&body, "{\"jail\":%s,\"packages\":%s,\"dry_run\":%s,"
	    "\"ignore_osversion\":%s,\"pkg_ip\":%d,\"pkg_repo\":%s}", qj,
	    names != NULL ? names : "[]", dry_run ? "true" : "false", anyos ?
	    "true" : "false", app.pkg.ip, qr) == -1)
		abort();
	free(qr);
	snprintf(url, sizeof(url), "/api/servers/%s/packages/upgrade", s->id);
	api("POST", url, body, packages_cb, c);
	free(qj);
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
	char		 url[640], fib[24], jail[270];

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
	fib[0] = '\0';
	if (app.net.fib > 0)
		snprintf(fib, sizeof(fib), "&fib=%d", app.net.fib);
	snprintf(jail, sizeof(jail), "%s%s", app.net.jail[0] != '\0' ?
	    "&jail=" : "", app.net.jail);
	snprintf(url, sizeof(url), "/api/servers/%s/net/routes?family=%s%s%s"
	    "&offset=%d%s%s", s->id, app.net.family == 4 ? "inet" :
	    app.net.family == 6 ? "inet6" : "all", app.net.host_filter[0] !=
	    '\0' ? "&filter=" : "", app.net.host_filter, routes_held(), fib,
	    jail);
	api("GET", url, NULL, network_cb, c);
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
	    "bridges", "interfaces", "multicast" };
	struct ctx	*c;
	struct op	*op;
	char		 url[640], title[160], fib[24], c0jail[270];

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
	snprintf(c0jail, sizeof(c0jail), "%s%s", app.net.jail[0] != '\0' ?
	    "&jail=" : "", app.net.jail);
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
	fib[0] = '\0';
	if (app.net.fib > 0 && (app.net.kind == NET_ROUTES || app.net.kind ==
	    NET_NEXTHOPS))
		snprintf(fib, sizeof(fib), "&fib=%d", app.net.fib);
	snprintf(url, sizeof(url), "/api/servers/%s/net/%s?family=%s%s%s%s%s",
	    s->id, kinds[app.net.kind], app.net.family == 4 ? "inet" :
	    app.net.family == 6 ? "inet6" : "all", app.net.kind ==
	    NET_ROUTES && app.net.host_filter[0] != '\0' ? "&filter=" : "",
	    app.net.kind == NET_ROUTES ? app.net.host_filter : "", fib,
	    c0jail);
	if (user) {
		/* Asked for: its steps drawn as the host takes them. */
		live_read(s->id, url + strlen("/api/servers/") +
		    strlen(s->id) + 1, url, c->op, network_cb, c);
		return;
	}
	api("GET", url, NULL, network_cb, c);
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
	ok = status == 200 && jbool(o, "ok");
	if (status == 200 && !ok)
		err = jstr(o, "error");
	op_done(op, ok, o, err);
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
	snprintf(url, sizeof(url), "/api/servers/%s/jails/%s/address", s->id,
	    url_word(jail) ? jail : "-");
	qa = json_quote(address);
	if (asprintf(&body, "{\"address\":%s,\"remove\":%s,\"live\":%s,"
	    "\"persist\":%s,\"dry_run\":%s}", qa, remove ? "true" : "false",
	    live ? "true" : "false", persist ? "true" : "false",
	    dry_run ? "true" : "false") == -1)
		abort();
	free(qa);
	api("POST", url, body, address_cb, c);
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
	app.by_token = jbool(o, "by_token") || app.by_ldap;
	app.ldap_on = jbool(o, "ldap");
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
		app.by_token = jbool(o, "by_token") || app.by_ldap;
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

/* A directory's user and password: the console asks the directory. */
void
login_ldap(const char *user, const char *password)
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
	api("POST", "/api/auth/login/ldap", body, auth_done_cb, NULL);
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
}

void
logout(void)
{

	api("POST", "/api/auth/logout", NULL, logout_cb, NULL);
}

static void
keys_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	if (app.keys != NULL)
		ucl_object_unref(app.keys);
	app.keys = NULL;
	if (status == 200 && jget(o, "credentials") != NULL)
		app.keys = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o,
		    "credentials"));
	else if (status != 401)
		snprintf(app.modal_error, sizeof(app.modal_error), "%s",
		    err != NULL ? err : "cannot load keys");
}

void
load_keys(void)
{

	api("GET", "/api/auth/credentials", NULL, keys_cb, NULL);
}

void
delete_key(const char *id)
{
	char	url[600];

	snprintf(url, sizeof(url), "/api/auth/credentials/%s", id);
	api("DELETE", url, NULL, keys_cb, NULL);
}

static void
server_added_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{

	app.modal_busy = false;
	if (status != 200) {
		snprintf(app.modal_error, sizeof(app.modal_error), "%s",
		    err != NULL ? err : "not added");
		return;
	}
	app.modal = MODAL_NONE;
	toast(false, "Server added");
	servers_cb(status, o, err, arg);
	if (app.nservers > 0) {
		app.sel = app.nservers - 1;
		app.node = NODE_HOST;
		app.tab = TAB_SUMMARY;
		refresh_stats(&app.servers[app.sel]);
	}
}

void
add_server(const char *name, const char *uri, const char *peer)
{
	char	*qn, *qu, *qp, *body;

	app.modal_busy = true;
	app.modal_error[0] = '\0';
	qn = json_quote(name);
	qu = json_quote(uri);
	qp = json_quote(peer);
	if (asprintf(&body, "{\"name\":%s,\"uri\":%s%s%s}", qn, qu,
	    *peer != '\0' ? ",\"peer_name\":" : "", *peer != '\0' ? qp :
	    "") == -1)
		abort();
	api("POST", "/api/servers", body, server_added_cb, NULL);
	free(qn);
	free(qu);
	free(qp);
	free(body);
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
	char	*qn, *qh, *body;

	app.modal_busy = true;
	app.modal_error[0] = '\0';
	app.enrol_cmd[0] = '\0';
	qn = json_quote(name);
	qh = json_quote(host);
	if (asprintf(&body, "{\"name\":%s,\"host\":%s}", qn, qh) == -1)
		abort();
	api("POST", "/api/enrol/tokens", body, enrol_token_cb, NULL);
	free(qn);
	free(qh);
	free(body);
}

void
delete_server(const char *id)
{
	char	url[64];

	snprintf(url, sizeof(url), "/api/servers/%s", id);
	api("DELETE", url, NULL, servers_cb, NULL);
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

	c = arg;
	/* Taken back, the next reading of the job ends its entry. */
	if (status != 200 || !jbool(o, "ok"))
		toast(true, "%s: not cancelled: %s", c->name, status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "failed");
	free(c);
}

/*
 * Give up what an entry of the activity list waits for, where that is
 * safe.  A job that has not started is taken out of the host's queue;
 * a safe change waiting to be confirmed is undone at once; one at work
 * is left to finish, as stopping a change half way is what would not
 * be safe.  A reading still on its way is no longer
 * waited for: the host may finish it, and nothing was to change.
 */
void
op_cancel(struct op *op)
{
	struct ctx	*c;
	char		 url[128];

	if (op->state != OP_RUNNING)
		return;
	if (op->job > 0) {
		c = ctx_new();
		snprintf(c->name, sizeof(c->name), "%s", op->title);
		snprintf(url, sizeof(url), "/api/servers/%s/jobs/%lld", op->sid,
		    op->job);
		api("DELETE", url, NULL, job_cancel_cb, c);
		return;
	}
	if (op->live)
		live_cancel(op->id);
	else if (op->req != 0)
		arc_http_abort(op->req);
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
	if (!ok)
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
	char		 url[128];

	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->name, sizeof(c->name), "%s", s->name);
	op = op_new(restart ? "update agent and restart" : "update agent",
	    s->name);
	c->op = op->id;
	app.trace_op = op->id;
	snprintf(url, sizeof(url), "/api/servers/%s/agent-update", s->id);
	api("POST", url, restart ? "{\"restart\":true}" : "{}",
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

	snprintf(url, sizeof(url), "/api/update/notes?component=%s&from=%s%s%s"
	    "%s", component, from != NULL ? from : "", to != NULL && to[0] !=
	    '\0' ? "&to=" : "", to != NULL ? to : "", fresh ? "&fresh=1" : "");
	snprintf(app.notes_for, sizeof(app.notes_for), "%s", component);
	app.notes_busy = true;
	app.notes_error[0] = '\0';
	if (app.notes != NULL) {
		ucl_object_unref(app.notes);
		app.notes = NULL;
	}
	api("GET", url, NULL, notes_cb, NULL);
}

void
agent_build(struct server *s, const char *host_keys, bool console)
{
	struct ctx	*c;
	struct op	*op;
	char		 url[128], *q, *body;

	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->name, sizeof(c->name), "%s", s->name);
	c->dry_run = console;		/* which of the two this is */
	op = op_new(console ? "update console" : "build agent", s->name);
	c->op = op->id;
	app.trace_op = op->id;
	app.dock_open = true;
	snprintf(url, sizeof(url), "/api/servers/%s/%s", s->id, console ?
	    "console-update" : "agent-build");
	if (host_keys == NULL) {
		api("POST", url, "{}", agent_build_cb, c);
		return;
	}
	q = json_quote(host_keys);
	if (asprintf(&body, "{\"host_keys\":%s}", q) == -1)
		abort();
	free(q);
	api("POST", url, body, agent_build_cb, c);
	free(body);
}

static void
settings_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	bool	saved;

	saved = arg != NULL;
	app.modal_busy = false;
	if (status != 200 || jget(o, "settings") == NULL) {
		/* Refused to a session an API token opened: the page says
		 * so already, as soon as it knows the session is one. */
		if (status != 401 && !(status == 403 && jstr(o, "error.code") !=
		    NULL && strcmp(jstr(o, "error.code"), "token") == 0))
			snprintf(app.modal_error, sizeof(app.modal_error), "%s",
			    err != NULL ? err : "cannot load the settings");
		return;
	}
	if (app.settings != NULL)
		ucl_object_unref(app.settings);
	app.settings = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
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
	if (status == 200 && jbool(o, "ok"))
		toast(false, "A test mail went to %s", jstr(o, "to") != NULL ?
		    jstr(o, "to") : "them");
	else
		toast(true, "No mail sent: %s", jstr(o, "error.message") != NULL ?
		    jstr(o, "error.message") : err != NULL ? err : "failed");
}

void
mail_test(void)
{

	app.modal_busy = true;
	api("POST", "/api/settings/mail-test", "{}", mail_test_cb, NULL);
}

static void
telegram_test_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{

	(void)arg;
	app.modal_busy = false;
	if (status == 200 && jbool(o, "ok"))
		toast(false, "A test message went to %s", jstr(o, "to") != NULL ?
		    jstr(o, "to") : "the chats");
	else
		toast(true, "No message sent: %s", err != NULL ? err : "failed");
}

void
telegram_test(void)
{

	app.modal_busy = true;
	api("POST", "/api/settings/telegram-test", "{}", telegram_test_cb,
	    NULL);
}

/* Which form a setting is in: the console's, mail's or Telegram's. */
int
setting_group(const char *key)
{

	return (strncmp(key, "mail_", 5) == 0 || strncmp(key, "smtp_", 5) == 0 ?
	    SETG_MAIL : strncmp(key, "telegram_", 9) == 0 ? SETG_TELEGRAM :
	    strncmp(key, "ldap_", 5) == 0 ? SETG_LDAP : SETG_CONSOLE);
}

void
load_settings(void)
{

	/* Not to a session an API token opened: refused, and the page
	 * says so already. */
	if (app.by_token)
		return;
	api("GET", "/api/settings", NULL, settings_cb, NULL);
}

/*
 * Send every setting of the form; the console keeps what differs.  The
 * mail's are a form of their own, on the Notifications tab: each form
 * sends its own.
 */
void
save_settings(const ucl_object_t *f, int group)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct html		 b;
	const char		*key;
	char			*q;
	bool			 first;

	memset(&b, 0, sizeof(b));
	h_raw(&b, "{\"set\":{");
	first = true;
	it = NULL;
	while ((e = ucl_object_iterate(jget(app.settings, "settings"), &it,
	    true)) != NULL) {
		if (!jbool(e, "editable") || (key = jstr(e, "key")) == NULL ||
		    setting_group(key) != group)
			continue;
		q = json_quote(key);
		h_raw(&b, first ? "" : ",");
		h_raw(&b, q);
		free(q);
		h_raw(&b, ":");
		if (jstr(e, "type") != NULL && strcmp(jstr(e, "type"),
		    "bool") == 0)
			h_raw(&b, jbool(f, key) ? "true" : "false");
		else {
			q = json_quote(jstr(f, key) != NULL ? jstr(f, key) : "");
			h_raw(&b, q);
			free(q);
		}
		first = false;
	}
	h_raw(&b, "}}");
	app.modal_busy = true;
	app.modal_error[0] = '\0';
	api("POST", "/api/settings", b.s, settings_cb, &app.settings);
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

/* Add a static route on s, or delete the one to destination. */
void
route_change(struct server *s, const char *destination, const char *gateway,
    bool remove, bool persist, int fib, int metric, int weight,
    const char *source)
{
	char	*qd, *qg, *qs, *json, title[200], more[160];

	qd = json_quote(destination);
	qg = json_quote(gateway);
	qs = json_quote(source != NULL ? source : "");
	/* Its cost, its share, where it is sent from: when given. */
	snprintf(more, sizeof(more), "%s%.0d%s%.0d%s%s", metric > 0 ?
	    ",\"metric\":" : "", metric > 0 ? metric : 0, weight > 0 ?
	    ",\"weight\":" : "", weight > 0 ? weight : 0, source != NULL &&
	    source[0] != '\0' ? ",\"source\":" : "", source != NULL &&
	    source[0] != '\0' ? qs : "");
	/* Safe, unless it is a delete that could not be put back. */
	if (asprintf(&json, "{\"kind\":\"route\",\"destination\":%s%s%s,"
	    "\"remove\":%s,\"persist\":%s,\"fib\":%d%s,\"safe\":%s}", qd,
	    gateway[0] != '\0' ? ",\"gateway\":" : "", gateway[0] != '\0' ?
	    qg : "", remove ? "true" : "false", persist ? "true" : "false",
	    fib, more, !remove || gateway[0] != '\0' ? "true" : "false") == -1)
		abort();
	free(qd);
	free(qg);
	free(qs);
	snprintf(title, sizeof(title), "route %s %s%s%s", remove ? "delete" :
	    "add", destination, gateway[0] != '\0' ? " via " : "", gateway);
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
		if (o->state == OP_RUNNING && (o->what == JOB_SERVICE ||
		    o->what == JOB_SERVICE_CONFIG) && strcmp(o->sid, s->id) ==
		    0 && strcmp(o->target, name) == 0)
			return (true);
	}
	return (false);
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

	if (status != 200)
		return;
	if (app.push != NULL)
		ucl_object_unref(app.push);
	app.push = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
}

/* The read-only API tokens, for the settings to show. */
static void
tokens_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	if (status != 200)
		return;
	if (app.tokens != NULL)
		ucl_object_unref(app.tokens);
	app.tokens = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
}

void
load_tokens(void)
{

	api("GET", "/api/tokens", NULL, tokens_cb, NULL);
}

/* A new one made: its value is in this reply only, shown once. */
static void
token_made_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200 || jstr(o, "token") == NULL) {
		toast(true, "The token was not made: %s", jstr(o, "error.message")
		    != NULL ? jstr(o, "error.message") : err != NULL ? err :
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
	char	*q, *body;

	if (app.token_name[0] == '\0') {
		toast(true, "A token is made with a name: what will use it");
		return;
	}
	q = json_quote(app.token_name);
	if (asprintf(&body, "{\"name\":%s,\"kind\":\"%s\"}", q,
	    app.token_write ? "write" : "read") == -1)
		abort();
	free(q);
	api("POST", "/api/tokens", body, token_made_cb, NULL);
	free(body);
}

static void
token_gone_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200)
		toast(true, "The token was not deleted: %s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
	load_tokens();
}

void
token_del(const char *id)
{
	char	url[64];

	if (strlen(id) != 16 || id[strspn(id, "0123456789abcdef")] != '\0')
		return;
	snprintf(url, sizeof(url), "/api/tokens/%s", id);
	api("DELETE", url, NULL, token_gone_cb, NULL);
}

/* The devices that are told of tasks, for the settings to show. */
void
load_push(void)
{

	api("GET", "/api/push", NULL, push_cb, NULL);
}

