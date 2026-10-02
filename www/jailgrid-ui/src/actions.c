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

struct ctx {
	char	sid[9];
	char	jail[256];
	char	name[128];
	int	op;
	bool	user;
	bool	dry_run;
	enum pending pend;
	int	net_kind;	/* the network table asked for */
	int	op_family;	/* and its family */
};

static struct ctx *ctx_new(void);
static struct op *op_new(const char *, const char *);
static void	op_done(struct op *, bool, const ucl_object_t *, const char *);
static struct server *server_by_id(const char *);
static void	merge_jail(struct server *, const ucl_object_t *);
static char	*emit(const ucl_object_t *);
static api_cb	 key_added_cb;

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
static struct op *
op_new(const char *title, const char *server)
{
	struct op	*o;

	if (app.nops == MAX_OPS) {
		o = &app.ops[MAX_OPS - 1];
		if (o->trace != NULL)
			ucl_object_unref(o->trace);
		free(o->diff);
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
	o->started = jg_now();
	return (o);
}

static void
op_done(struct op *o, bool ok, const ucl_object_t *reply, const char *err)
{
	const ucl_object_t	*t;

	if (o == NULL)
		return;
	o->state = ok ? OP_OK : OP_FAILED;
	o->finished = jg_now();
	if (reply != NULL && (t = jget(reply, "trace")) != NULL)
		o->trace = ucl_object_ref((ucl_object_t *)(uintptr_t)t);
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

static void
health_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	app.api = status == 200 ? LINK_UP : LINK_DOWN;
	if (status == 200 && jstr(o, "version") != NULL)
		snprintf(app.version, sizeof(app.version), "%s",
		    jstr(o, "version"));
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

static void
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
			app.api = LINK_DOWN;
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
	}
	for (i = 0; i < nold; i++) {
		if (old[i].id[0] == '\0')
			continue;
		if (old[i].list != NULL)
			ucl_object_unref(old[i].list);
		if (old[i].services != NULL)
			ucl_object_unref(old[i].services);
		free(old[i].jui);
	}
	app.servers_loaded = true;
	app.sel = -1;
	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, selid) == 0)
			app.sel = i;
	if (app.sel < 0 && app.nservers > 0)
		app.sel = 0;
	for (i = 0; i < app.nservers; i++)
		if (app.servers[i].list == NULL)
			refresh_jails(&app.servers[i], i == app.sel);
}

void
refresh_servers(void)
{

	api("GET", "/api/servers", NULL, servers_cb, NULL);
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
	if (status == 200) {
		if (s->list != NULL)
			ucl_object_unref(s->list);
		s->list = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
		s->fetched = jg_now();
		s->failed = false;
		s->error[0] = '\0';
		op_done(op, jbool(o, "ok"), o, jstr(o, "error"));
	} else {
		if (status == 0)
			app.api = LINK_DOWN;
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
 * Fetch the jails of a server.  A refresh the user asked for goes into
 * the activity log with its trace; the periodic ones do not.
 */
void
refresh_jails(struct server *s, bool user)
{
	struct ctx	*c;
	struct op	*op;
	char		 url[128], title[160];

	if (!app.online || s->loading)
		return;
	s->loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	c->user = user;
	if (user) {
		snprintf(title, sizeof(title), "list jails");
		op = op_new(title, s->name);
		c->op = op->id;
	}
	snprintf(url, sizeof(url), "/api/servers/%s/jails", s->id);
	api("GET", url, NULL, jails_cb, c);
}

static void
action_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ctx	*c;
	struct server	*s;
	struct jailui	*ju;
	struct op	*op;
	bool		 ok;

	c = arg;
	op = op_find(c->op);
	ok = status == 200 && jbool(o, "ok");
	if (status == 200 && !ok)
		err = jstr(o, "error");
	op_done(op, ok, o, err);
	if ((s = server_by_id(c->sid)) != NULL) {
		ju = jailui(s, c->jail);
		ju->pending = PEND_NONE;
		ju->error[0] = '\0';
		if (!ok)
			snprintf(ju->error, sizeof(ju->error), "%s",
			    err != NULL ? err : "failed");
		merge_jail(s, jget(o, "jail"));
		if (ok)
			toast(false, "%s: %s", c->jail, op != NULL ?
			    op->title : "done");
		else
			toast(true, "%s: %s", c->jail, err != NULL ? err :
			    "failed");
		s->loading = false;
		refresh_jails(s, false);
	}
	free(c);
}

/* start, stop, restart or kill a jail of the selected server. */
void
jail_action(const char *jail, const char *action)
{
	struct server	*s;
	struct ctx	*c;
	struct op	*op;
	char		 url[512], title[160], body[64];

	if ((s = cur_server()) == NULL)
		return;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->jail, sizeof(c->jail), "%s", jail);
	snprintf(title, sizeof(title), "%s %s", action, jail);
	op = op_new(title, s->name);
	c->op = op->id;
	app.trace_op = op->id;
	app.trace_step = -1;
	jailui(s, jail)->pending = strcmp(action, "start") == 0 ? PEND_START :
	    strcmp(action, "stop") == 0 ? PEND_STOP :
	    strcmp(action, "restart") == 0 ? PEND_RESTART : PEND_KILL;
	jailui(s, jail)->error[0] = '\0';
	snprintf(url, sizeof(url), "/api/servers/%s/jails/%s/action", s->id,
	    jail);
	snprintf(body, sizeof(body), "{\"action\":\"%s\"}", action);
	api("POST", url, body, action_cb, c);
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
		s->services_fetched = jg_now();
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
	c->user = user;
	if (user) {
		op = op_new("list services", s->name);
		c->op = op->id;
		app.trace_op = op->id;
	}
	snprintf(url, sizeof(url), "/api/servers/%s/services", s->id);
	api("GET", url, NULL, services_cb, c);
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

static void
service_action_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{
	struct ctx	*c;
	struct server	*s;
	struct op	*op;
	bool		 ok;

	c = arg;
	op = op_find(c->op);
	ok = status == 200 && jbool(o, "ok");
	if (status == 200 && !ok)
		err = jstr(o, "error");
	op_done(op, ok, o, err);
	app.service_busy[0] = '\0';
	if ((s = server_by_id(c->sid)) != NULL) {
		merge_service(s, jget(o, "service"));
		if (ok)
			toast(false, "%s: %s", c->jail, op != NULL ? op->title :
			    "done");
		else
			toast(true, "%s: %s", c->jail, err != NULL ? err :
			    "failed");
	}
	free(c);
}

/* start, stop, restart, reload, enable or disable a service. */
void
service_action(const char *name, const char *action)
{
	struct server	*s;
	struct ctx	*c;
	struct op	*op;
	char		 url[512], title[160], body[64];

	if ((s = cur_server()) == NULL)
		return;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->jail, sizeof(c->jail), "%s", name);
	snprintf(title, sizeof(title), "service %s %s", name, action);
	op = op_new(title, s->name);
	c->op = op->id;
	app.trace_op = op->id;
	app.trace_step = -1;
	snprintf(app.service_busy, sizeof(app.service_busy), "%s", name);
	snprintf(url, sizeof(url), "/api/servers/%s/services/%s/action",
	    s->id, name);
	snprintf(body, sizeof(body), "{\"action\":\"%s\"}", action);
	api("POST", url, body, service_action_cb, c);
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
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	snprintf(c->jail, sizeof(c->jail), "%s", name);
	c->user = body != NULL;
	if (body != NULL) {
		snprintf(title, sizeof(title), "service %s configure", name);
		op = op_new(title, s->name);
		c->op = op->id;
		app.trace_op = op->id;
	}
	app.svc_loading = true;
	app.svc_error[0] = '\0';
	snprintf(url, sizeof(url), "/api/servers/%s/services/%s/config",
	    s->id, name);
	api(body != NULL ? "POST" : "GET", url, body, service_config_cb, c);
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
	    app.net.family == c->op_family) {
		app.net.loading = false;
		if (ok) {
			if (app.net.data != NULL)
				ucl_object_unref(app.net.data);
			app.net.data = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
			app.net.fetched = jg_now();
			app.net.error[0] = '\0';
		} else
			snprintf(app.net.error, sizeof(app.net.error), "%s",
			    err != NULL ? err : "no answer from the console");
	}
	free(c);
}

/* The network table the tab shows, from the server; user: log it. */
void
refresh_network(struct server *s, bool user)
{
	static const char *kinds[] = { "routes", "nexthops", "connections",
	    "sockets" };
	struct ctx	*c;
	struct op	*op;
	char		 url[160], title[160];

	if (!app.online)
		return;
	if (strcmp(app.net.sid, s->id) != 0 || app.net.loading) {
		if (app.net.data != NULL)
			ucl_object_unref(app.net.data);
		app.net.data = NULL;
		app.net.error[0] = '\0';
	}
	snprintf(app.net.sid, sizeof(app.net.sid), "%s", s->id);
	app.net.loading = true;
	c = ctx_new();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	c->net_kind = (int)app.net.kind;
	c->op_family = app.net.family;
	c->user = user;
	if (user) {
		snprintf(title, sizeof(title), "net %s%s", kinds[app.net.kind],
		    app.net.family == 4 ? " inet" : app.net.family == 6 ?
		    " inet6" : "");
		op = op_new(title, s->name);
		c->op = op->id;
		app.trace_op = op->id;
	}
	snprintf(url, sizeof(url), "/api/servers/%s/net/%s%s", s->id,
	    kinds[app.net.kind], app.net.family == 4 ? "?family=inet" :
	    app.net.family == 6 ? "?family=inet6" : "");
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
	    jail);
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
	if (jbool(o, "authenticated")) {
		app.screen = SCREEN_CONSOLE;
		app.auth_error[0] = '\0';
		refresh_servers();
	} else
		app.screen = app.setup_required ? SCREEN_ENROL : SCREEN_LOGIN;
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
		app.screen = SCREEN_CONSOLE;
		app.auth_error[0] = '\0';
		app.setup_required = false;
		refresh_servers();
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

/* The first key, with the setup token from the console's data dir. */
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
	if (asprintf(&body, "{\"setup_token\":%s}", qt) == -1)
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
	if (app.nservers > 0)
		app.sel = app.nservers - 1;
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

/* A one-time token for a host to join with jailgrid-enrol(8). */
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
