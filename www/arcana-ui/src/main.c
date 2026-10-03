/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console's entry point, its clock, and what each control does.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <emscripten/emscripten.h>
#include <emscripten/eventloop.h>

#include "app.h"

struct app app = {
	.screen = SCREEN_BOOT,
	.online = true,
	.visible = true,
	.sel = -1,
	.trace_op = -1,
	.trace_step = -1,
	.raw_op = -1,
	.net = { .sort = -1 },
};

static double	last_health, last_refresh, last_tick_render, last_update;

static void	tick(void *);
static void	confirm(const char *, const char *, const char *, bool,
		    const char *, const char *, const char *, const char *);
static void	dispatch(const char *, const char *, const char *);
static void	close_service(void);
static void	submit(const char *, const ucl_object_t *);

/*
 * Rebuild the page.  On the console, each region is rebuilt in C (cheap)
 * and handed to the browser only when its markup differs from what it
 * got last time: patching the DOM is what costs, in Firefox most of all.
 */
void
render(void)
{
	static struct html	h;
	static char		*last[VIEW_REGIONS];
	static bool		 shell;
	struct server		*s;
	char			 title[128];
	int			 r;

	if (app.screen != SCREEN_CONSOLE) {
		h_reset(&h);
		view(&h);
		arc_patch("app", h.s);
		shell = false;
	} else {
		if (!shell) {
			h_reset(&h);
			view_shell(&h);
			arc_patch("app", h.s);
			shell = true;
			for (r = 0; r < VIEW_REGIONS; r++) {
				free(last[r]);
				last[r] = NULL;
			}
		}
		for (r = 0; r < VIEW_REGIONS; r++) {
			h_reset(&h);
			view_region(&h, r);
			if (last[r] != NULL && strcmp(last[r], h.s) == 0)
				continue;
			arc_patch(view_regions[r], h.s);
			free(last[r]);
			last[r] = strdup(h.s);
		}
		arc_set_class("body", "with-drawer", view_with_drawer());
	}
	s = cur_server();
	snprintf(title, sizeof(title), "%s%s%s", s != NULL &&
	    app.screen == SCREEN_CONSOLE ? s->name : "",
	    s != NULL && app.screen == SCREEN_CONSOLE ? " · " : "", APP_NAME);
	arc_title(title);
}

void
toast(bool error, const char *fmt, ...)
{
	struct toast	*t;
	va_list		 ap;

	if (app.ntoasts == MAX_TOASTS) {
		memmove(&app.toasts[0], &app.toasts[1],
		    (MAX_TOASTS - 1) * sizeof(app.toasts[0]));
		app.ntoasts--;
	}
	t = &app.toasts[app.ntoasts++];
	va_start(ap, fmt);
	vsnprintf(t->text, sizeof(t->text), fmt, ap);
	va_end(ap);
	t->error = error;
	t->until = arc_now() + (error ? 8000 : 4000);
}

struct server *
cur_server(void)
{

	if (app.sel < 0 || app.sel >= app.nservers)
		return (NULL);
	return (&app.servers[app.sel]);
}

/* UI state of a jail, made on first use. */
struct jailui *
jailui(struct server *s, const char *name)
{
	struct jailui	*j;
	size_t		 i;

	for (i = 0; i < s->njui; i++)
		if (strcmp(s->jui[i].name, name) == 0)
			return (&s->jui[i]);
	if ((s->jui = reallocarray(s->jui, s->njui + 1,
	    sizeof(*s->jui))) == NULL)
		abort();
	j = &s->jui[s->njui++];
	memset(j, 0, sizeof(*j));
	snprintf(j->name, sizeof(j->name), "%s", name);
	return (j);
}

const ucl_object_t *
find_jail(const struct server *s, const char *name)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;

	if (s == NULL || s->list == NULL)
		return (NULL);
	it = NULL;
	while ((j = ucl_object_iterate(jget(s->list, "jails"), &it,
	    true)) != NULL)
		if (jstr(j, "name") != NULL && strcmp(jstr(j, "name"),
		    name) == 0)
			return (j);
	return (NULL);
}

struct op *
op_find(int id)
{
	int	i;

	for (i = 0; i < app.nops; i++)
		if (app.ops[i].id == id)
			return (&app.ops[i]);
	return (NULL);
}

/*
 * Once a second: toasts expire, data is kept fresh.  The page is only
 * rebuilt when something it shows changed: a toast went, or enough time
 * passed for an age or a stale mark to read differently.  Replies and
 * actions render on their own.
 */
static void
tick(void *arg)
{
	struct server	*s;
	double		 now;
	bool		 changed;
	int		 i;

	now = arc_now();
	changed = false;
	for (i = 0; i < app.ntoasts; ) {
		if (app.toasts[i].until < now) {
			memmove(&app.toasts[i], &app.toasts[i + 1],
			    (size_t)(app.ntoasts - i - 1) *
			    sizeof(app.toasts[0]));
			app.ntoasts--;
			changed = true;
		} else
			i++;
	}
	if (now - last_health > HEALTH_MS) {
		last_health = now;
		check_health();
		/* Offline at start: try to reach the console again. */
		if (app.screen == SCREEN_OFFLINE && app.online)
			auth_status();
	}
	/* Running jobs: read them, and redraw when their trace grew. */
	if (app.screen == SCREEN_CONSOLE)
		jobs_poll();
	if (app.screen == SCREEN_CONSOLE && app.online &&
	    now - last_update > UPDATE_MS) {
		last_update = now;
		check_update();
	}
	if (app.screen == SCREEN_CONSOLE && app.visible && app.online &&
	    now - last_refresh > REFRESH_MS) {
		last_refresh = now;
		/* The fleet page watches every host, a host page its own. */
		for (i = 0; app.node == NODE_FLEET && i < app.nservers; i++) {
			refresh_jails(&app.servers[i], false);
			refresh_stats(&app.servers[i]);
		}
		if (app.node != NODE_FLEET && (s = cur_server()) != NULL) {
			refresh_jails(s, false);
			refresh_stats(s);
			if (app.tab == TAB_JOBS)
				refresh_jobs(s);
		}
	}
	if (changed || now - last_tick_render >= AGE_STEP_MS) {
		last_tick_render = now;
		render();
	}
}

static void
confirm(const char *title, const char *body, const char *button,
    bool danger, const char *typed, const char *act, const char *arg,
    const char *value)
{
	struct confirm	*c;

	c = &app.confirm;
	memset(c, 0, sizeof(*c));
	snprintf(c->title, sizeof(c->title), "%s", title);
	snprintf(c->body, sizeof(c->body), "%s", body);
	snprintf(c->button, sizeof(c->button), "%s", button);
	c->danger = danger;
	snprintf(c->typed, sizeof(c->typed), "%s", typed);
	snprintf(c->act, sizeof(c->act), "%s", act);
	snprintf(c->arg, sizeof(c->arg), "%s", arg);
	snprintf(c->value, sizeof(c->value), "%s", value);
	app.modal = MODAL_CONFIRM;
	app.modal_error[0] = '\0';
}

/* The service drawer closes: its configuration goes. */
static void
close_service(void)
{

	app.service[0] = '\0';
	app.svc_error[0] = '\0';
	if (app.svc_config != NULL)
		ucl_object_unref(app.svc_config);
	app.svc_config = NULL;
}

static void
close_modal(void)
{

	/* A host enrolled meanwhile is a server now. */
	if (app.modal == MODAL_ENROL && app.enrol_cmd[0] != '\0')
		refresh_servers();
	app.modal = MODAL_NONE;
	app.modal_busy = false;
	app.modal_error[0] = '\0';
	app.enrol_cmd[0] = '\0';
	free(app.preview);
	app.preview = NULL;
}

/* Forms: their fields arrive as one JSON object. */
static void
submit(const char *form, const ucl_object_t *f)
{
	struct server	*s2;
	const char	*s;
	bool		 dry;
	int		 i;

	if (strcmp(form, "enrol") == 0) {
		enrol(jstr(f, "token") != NULL ? jstr(f, "token") : "",
		    jstr(f, "name") != NULL ? jstr(f, "name") : "");
	} else if (strcmp(form, "add-server") == 0) {
		add_server(jstr(f, "name") != NULL ? jstr(f, "name") : "",
		    jstr(f, "uri") != NULL ? jstr(f, "uri") : "",
		    jstr(f, "peer") != NULL ? jstr(f, "peer") : "");
	} else if (strcmp(form, "enrol-host") == 0) {
		enrol_host(jstr(f, "name") != NULL ? jstr(f, "name") : "",
		    jstr(f, "host") != NULL ? jstr(f, "host") : "");
	} else if (strcmp(form, "svc-config") == 0 && app.service[0] != '\0') {
		/* Fields v:<key> are the variables; key/value add one. */
		const ucl_object_t *f2;
		ucl_object_iter_t it;
		ucl_object_t *set, *top;
		char *b;

		set = ucl_object_typed_new(UCL_OBJECT);
		it = NULL;
		while ((f2 = ucl_object_iterate(f, &it, true)) != NULL) {
			const char *k = ucl_object_key(f2);

			if (k != NULL && strncmp(k, "v:", 2) == 0 &&
			    ucl_object_type(f2) == UCL_STRING)
				ucl_object_insert_key(set, ucl_object_copy(f2),
				    k + 2, 0, true);
		}
		if ((s = jstr(f, "key")) != NULL && *s != '\0')
			ucl_object_insert_key(set, ucl_object_fromstring(
			    jstr(f, "value") != NULL ? jstr(f, "value") : ""),
			    s, 0, true);
		top = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(top, set, "set", 0, false);
		b = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
		ucl_object_unref(top);
		service_config(app.service, b);
		free(b);
	} else if (strcmp(form, "packages") == 0) {
		/* Checked boxes p:<name>; the button says dry run or not. */
		const ucl_object_t *f2;
		ucl_object_iter_t it;
		ucl_object_t *arr;
		char *names;
		bool any;

		if ((s2 = cur_server()) == NULL)
			return;
		arr = ucl_object_typed_new(UCL_ARRAY);
		any = false;
		it = NULL;
		while ((f2 = ucl_object_iterate(f, &it, true)) != NULL) {
			const char *k = ucl_object_key(f2);

			if (k != NULL && strncmp(k, "p:", 2) == 0 &&
			    ucl_object_type(f2) == UCL_BOOLEAN &&
			    ucl_object_toboolean(f2)) {
				ucl_array_append(arr,
				    ucl_object_fromstring(k + 2));
				any = true;
			}
		}
		names = (char *)ucl_object_emit(arr, UCL_EMIT_JSON_COMPACT);
		ucl_object_unref(arr);
		dry = jstr(f, "__submit") != NULL &&
		    strcmp(jstr(f, "__submit"), "dry") == 0;
		if (dry)
			pkg_upgrade(s2, any ? names : NULL, true);
		else if (any)
			confirm("Upgrade packages", "pkg upgrade -y of the "
			    "selected packages; services may restart.",
			    "Upgrade", true, "", "do-pkg-upgrade", "", names);
		else
			dispatch("pkg-upgrade-all", "", "");
		free(names);
	} else if (strcmp(form, "add-key") == 0) {
		add_key(jstr(f, "name") != NULL ? jstr(f, "name") : "");
	} else if (strcmp(form, "address") == 0) {
		s = jstr(f, "address");
		if (s == NULL || *s == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "Give an address, such as 10.0.0.5 or 10.0.0.5/24");
			return;
		}
		dry = jstr(f, "__submit") != NULL &&
		    strcmp(jstr(f, "__submit"), "preview") == 0;
		if (!jbool(f, "live") && !jbool(f, "persist")) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "Choose live, persistent or both");
			return;
		}
		address_change(app.jail, s, jstr(f, "mode") != NULL &&
		    strcmp(jstr(f, "mode"), "remove") == 0, jbool(f, "live"),
		    jbool(f, "persist"), dry);
	} else if (strcmp(form, "agent-update") == 0) {
		app.modal = MODAL_NONE;
		for (i = 0; i < app.nservers; i++) {
			s2 = &app.servers[i];
			if (app.confirm.arg[0] != '\0' ? strcmp(s2->id,
			    app.confirm.arg) == 0 : agent_outdated(s2))
				agent_update(s2, jbool(f, "restart"));
		}
	} else if (strcmp(form, "confirm") == 0) {
		if (app.confirm.typed[0] != '\0' && (jstr(f, "typed") == NULL ||
		    strcmp(jstr(f, "typed"), app.confirm.typed) != 0)) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "Type %s to confirm", app.confirm.typed);
			return;
		}
		app.modal = MODAL_NONE;
		dispatch(app.confirm.act, app.confirm.arg, app.confirm.value);
	}
}

/* What a control with data-act does. */
static void
dispatch(const char *act, const char *arg, const char *value)
{
	struct server		*s;
	char			 body[512];
	int			 i;

	s = cur_server();
	if (strcmp(act, "fold") == 0) {
		arc_open_set(arg, !arc_open_get(arg));
	} else if (strcmp(act, "tree-more") == 0) {
		for (i = 0; i < app.nservers; i++)
			if (strcmp(app.servers[i].id, arg) == 0)
				app.servers[i].tree_all =
				    !app.servers[i].tree_all;
	} else if (strcmp(act, "resize") == 0) {
		/* Only drawn again: the tree fits itself to its room. */
	} else if (strcmp(act, "select-server") == 0) {
		for (i = 0; i < app.nservers; i++)
			if (strcmp(app.servers[i].id, arg) == 0)
				app.sel = i;
		app.node = NODE_HOST;
		app.jail[0] = '\0';
		close_service();
		if ((s = cur_server()) != NULL) {
			refresh_jails(s, false);
			refresh_stats(s);
			if (app.tab == TAB_SERVICES && s->services == NULL)
				refresh_services(s, true);
			if (app.tab == TAB_NETWORK)
				refresh_network(s, true);
			if (app.tab == TAB_PACKAGES)
				refresh_packages(s, false);
		}
	} else if (strcmp(act, "tab") == 0 && s != NULL) {
		app.tab = strcmp(arg, "services") == 0 ? TAB_SERVICES :
		    strcmp(arg, "network") == 0 ? TAB_NETWORK :
		    strcmp(arg, "packages") == 0 ? TAB_PACKAGES :
		    strcmp(arg, "jails") == 0 ? TAB_JAILS :
		    strcmp(arg, "jobs") == 0 ? TAB_JOBS : TAB_SUMMARY;
		app.node = NODE_HOST;
		app.jail[0] = '\0';
		if (app.tab == TAB_JOBS)
			refresh_jobs(s);
		close_service();
		if (app.tab == TAB_SERVICES && s->services == NULL)
			refresh_services(s, true);
		if (app.tab == TAB_NETWORK && (app.net.data == NULL ||
		    strcmp(app.net.sid, s->id) != 0))
			refresh_network(s, true);
		if (app.tab == TAB_PACKAGES && (app.pkg.data == NULL ||
		    strcmp(app.pkg.sid, s->id) != 0))
			refresh_packages(s, false);
	} else if (strcmp(act, "pkg-target") == 0 && s != NULL) {
		snprintf(app.pkg.jail, sizeof(app.pkg.jail), "%s", arg);
		if (app.pkg.data != NULL)
			ucl_object_unref(app.pkg.data);
		app.pkg.data = NULL;
		app.pkg.result[0] = '\0';
		refresh_packages(s, false);
	} else if (strcmp(act, "pkg-check") == 0 && s != NULL) {
		refresh_packages(s, true);
	} else if (strcmp(act, "pkg-upgrade-all") == 0 && s != NULL) {
		snprintf(body, sizeof(body), "pkg upgrade -y %s%s: every "
		    "package with a newer version in the repository is "
		    "replaced; services may restart.", app.pkg.jail[0] != '\0' ?
		    "in jail " : "on the host", app.pkg.jail);
		confirm("Upgrade all packages", body, "Upgrade", true, "",
		    "do-pkg-upgrade", "", "");
	} else if (strcmp(act, "do-pkg-upgrade") == 0 && s != NULL) {
		pkg_upgrade(s, value[0] != '\0' ? value : NULL, false);
	} else if (strcmp(act, "queue") == 0) {
		app.queue_on = !app.queue_on;
		arc_queue_set(app.queue_on ? 1 : 0);
		app.dock_open = true;
	} else if (strcmp(act, "queue-run") == 0) {
		queue_run();
	} else if (strcmp(act, "queue-clear") == 0) {
		queue_clear();
	} else if (strcmp(act, "svc-sort") == 0) {
		/* The same key again turns the order round. */
		i = strcmp(arg, "name") == 0 ? SVC_SORT_NAME :
		    strcmp(arg, "enabled") == 0 ? SVC_SORT_ENABLED :
		    SVC_SORT_RUNNING;
		app.svc_sort_desc = app.svc_sort == i && !app.svc_sort_desc;
		app.svc_sort = i;
	} else if (strcmp(act, "net-sort") == 0) {
		/* The same column again turns the order round. */
		if (app.net.sort == atoi(arg))
			app.net.sort_desc = !app.net.sort_desc;
		else {
			app.net.sort = atoi(arg);
			app.net.sort_desc = false;
		}
	} else if (strcmp(act, "notify") == 0) {
		arc_notify_ask();
	} else if (strcmp(act, "notify-changed") == 0) {
		app.notify = arc_notify_state();
	} else if (strcmp(act, "net-kind") == 0 && s != NULL) {
		app.net.sort = -1;
		app.net.kind = strcmp(arg, "nexthops") == 0 ? NET_NEXTHOPS :
		    strcmp(arg, "connections") == 0 ? NET_CONNECTIONS :
		    strcmp(arg, "sockets") == 0 ? NET_SOCKETS : NET_ROUTES;
		app.net.loading = false;
		refresh_network(s, true);
	} else if (strcmp(act, "net-family") == 0 && s != NULL) {
		app.net.family = atoi(arg);
		app.net.loading = false;
		refresh_network(s, true);
	} else if (strcmp(act, "select-fleet") == 0) {
		app.node = NODE_FLEET;
		app.jail[0] = '\0';
		close_service();
		for (i = 0; i < app.nservers; i++) {
			refresh_jails(&app.servers[i], false);
			refresh_stats(&app.servers[i]);
		}
	} else if (strcmp(act, "open-jail") == 0) {
		/* value: the server, when the jail is picked in the tree. */
		for (i = 0; value[0] != '\0' && i < app.nservers; i++)
			if (strcmp(app.servers[i].id, value) == 0)
				app.sel = i;
		app.node = NODE_JAIL;
		snprintf(app.jail, sizeof(app.jail), "%s", arg);
		close_service();
	} else if (strcmp(act, "close-drawer") == 0) {
		if (app.node == NODE_JAIL)
			app.node = NODE_HOST;
		app.jail[0] = '\0';
		close_service();
	} else if (strcmp(act, "jail-packages") == 0 && s != NULL) {
		/* The jail's packages: the host's tab, aimed at the jail. */
		snprintf(app.pkg.jail, sizeof(app.pkg.jail), "%s", arg);
		if (app.pkg.data != NULL)
			ucl_object_unref(app.pkg.data);
		app.pkg.data = NULL;
		app.pkg.result[0] = '\0';
		app.node = NODE_HOST;
		app.tab = TAB_PACKAGES;
		app.jail[0] = '\0';
		refresh_packages(s, false);
	} else if (strcmp(act, "open-job") == 0 && s != NULL) {
		open_job(s, atoll(arg), value);
	} else if (strcmp(act, "refresh") == 0 && s != NULL) {
		if (app.tab == TAB_SERVICES) {
			s->services_loading = false;
			refresh_services(s, true);
		} else if (app.tab == TAB_NETWORK) {
			app.net.loading = false;
			refresh_network(s, true);
		} else if (app.tab == TAB_PACKAGES) {
			app.pkg.loading = false;
			refresh_packages(s, true);
		} else {
			s->loading = false;
			refresh_jails(s, true);
		}
		app.trace_op = app.nops > 0 ? app.ops[0].id : -1;
	} else if (strcmp(act, "open-svc") == 0) {
		close_service();
		snprintf(app.service, sizeof(app.service), "%s", arg);
		service_config(arg, NULL);
	} else if (strcmp(act, "svc") == 0) {
		/* value: the verb; stop and restart ask first. */
		if (strcmp(value, "stop") == 0 || strcmp(value, "restart") == 0) {
			snprintf(body, sizeof(body), "service %s %s: the "
			    "service's own rc.d script does it, as from the "
			    "shell.", arg, value);
			confirm(strcmp(value, "stop") == 0 ? "Stop service" :
			    "Restart service", body, strcmp(value, "stop") == 0 ?
			    "Stop" : "Restart", false, "", "do-svc", arg, value);
		} else
			service_action(arg, value);
	} else if (strcmp(act, "do-svc") == 0) {
		service_action(arg, value);
	} else if (strcmp(act, "svc-unset") == 0 && app.service[0] != '\0') {
		char *q = json_quote(arg), *b;

		if (asprintf(&b, "{\"unset\":[%s]}", q) == -1)
			abort();
		service_config(app.service, b);
		free(q);
		free(b);
	} else if (strcmp(act, "start") == 0) {
		jail_action(arg, "start");
	} else if (strcmp(act, "stop") == 0) {
		snprintf(body, sizeof(body), "jail(8) runs the jail's stop "
		    "scripts (exec.stop) and removes it. Everything running "
		    "in %s stops.", arg);
		confirm("Stop jail", body, "Stop", false, "", "do-stop", arg,
		    "");
	} else if (strcmp(act, "restart") == 0) {
		snprintf(body, sizeof(body), "jail(8) stops %s and starts it "
		    "again (-rc). Its services are down meanwhile.", arg);
		confirm("Restart jail", body, "Restart", false, "",
		    "do-restart", arg, "");
	} else if (strcmp(act, "kill") == 0) {
		snprintf(body, sizeof(body), "jail_remove(2) kills every "
		    "process in %s at once, without its stop scripts. Use it "
		    "for jails that will not stop or that no configuration "
		    "describes.", arg);
		confirm("Kill jail", body, "Kill", true, arg, "do-kill", arg,
		    "");
	} else if (strcmp(act, "do-stop") == 0) {
		jail_action(arg, "stop");
	} else if (strcmp(act, "do-restart") == 0) {
		jail_action(arg, "restart");
	} else if (strcmp(act, "do-kill") == 0) {
		jail_action(arg, "kill");
	} else if (strcmp(act, "address-add") == 0 ||
	    strcmp(act, "address-remove") == 0) {
		snprintf(app.jail, sizeof(app.jail), "%s", arg);
		app.modal = MODAL_ADDRESS;
		app.modal_error[0] = '\0';
		app.modal_busy = false;
		free(app.preview);
		app.preview = NULL;
		snprintf(app.confirm.value, sizeof(app.confirm.value), "%s",
		    value);
		snprintf(app.confirm.act, sizeof(app.confirm.act), "%s",
		    strcmp(act, "address-add") == 0 ? "add" : "remove");
	} else if (strcmp(act, "trace") == 0) {
		app.trace_op = atoi(arg);
		app.trace_step = -1;
		app.dock_open = true;
	} else if (strcmp(act, "step") == 0) {
		app.trace_step = app.trace_step == atoi(arg) ? -1 : atoi(arg);
	} else if (strcmp(act, "dock") == 0) {
		app.dock_open = !app.dock_open;
	} else if (strcmp(act, "raw") == 0) {
		app.raw_op = atoi(arg);
		app.modal = MODAL_RAW;
	} else if (strcmp(act, "add-server") == 0) {
		app.modal = MODAL_ADD_SERVER;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "enrol") == 0) {
		app.modal = MODAL_ENROL;
		app.modal_busy = false;
		app.modal_error[0] = '\0';
		app.enrol_cmd[0] = '\0';
	} else if (strcmp(act, "delete-server") == 0) {
		for (i = 0; i < app.nservers; i++)
			if (strcmp(app.servers[i].id, arg) == 0)
				break;
		snprintf(body, sizeof(body), "The console forgets %s. Its "
		    "jails are not touched, and it can be added again.",
		    i < app.nservers ? app.servers[i].name : arg);
		confirm("Remove server", body, "Remove", true, "",
		    "do-delete-server", arg, "");
	} else if (strcmp(act, "do-delete-server") == 0) {
		delete_server(arg);
	} else if (strcmp(act, "agent-build") == 0 && s != NULL) {
		char body[512];

		snprintf(body, sizeof(body), "%s clones %s and builds "
		    "arcana-agent there, without installing it. The console "
		    "keeps the program and offers it to the hosts that run "
		    "another build. This can take a few minutes.", s->name,
		    app.agent_source);
		confirm("Build arcana-agent", body, "Build", false, "",
		    "do-agent-build", s->id, "");
	} else if (strcmp(act, "do-agent-build") == 0) {
		for (i = 0; i < app.nservers; i++)
			if (strcmp(app.servers[i].id, arg) == 0)
				agent_build(&app.servers[i]);
	} else if (strcmp(act, "jail-sort") == 0) {
		i = strcmp(arg, "name") == 0 ? JAIL_SORT_NAME :
		    JAIL_SORT_RUNNING;
		app.jail_sort_desc = app.jail_sort == i && !app.jail_sort_desc;
		app.jail_sort = i;
	} else if (strcmp(act, "agent-update") == 0) {
		/* arg: a host, or none for every host that is behind. */
		snprintf(app.confirm.arg, sizeof(app.confirm.arg), "%s", arg);
		app.modal = MODAL_AGENT_UPDATE;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "keys") == 0) {
		app.modal = MODAL_KEYS;
		app.modal_error[0] = '\0';
		load_keys();
	} else if (strcmp(act, "delete-key") == 0) {
		confirm("Remove security key", "This key will no longer log "
		    "in. The last key cannot be removed.", "Remove", true, "",
		    "do-delete-key", arg, "");
	} else if (strcmp(act, "do-delete-key") == 0) {
		app.modal = MODAL_KEYS;
		delete_key(arg);
	} else if (strcmp(act, "retry") == 0) {
		auth_status();
	} else if (strcmp(act, "login") == 0) {
		login(false);
	} else if (strcmp(act, "login-passkey") == 0) {
		login(true);
	} else if (strcmp(act, "logout") == 0) {
		logout();
	} else if (strcmp(act, "install") == 0) {
		arc_install_prompt();
		app.install = arc_install_state();
	} else if (strcmp(act, "install-dismiss") == 0) {
		arc_install_dismiss();
		app.install = 0;
	} else if (strcmp(act, "install-changed") == 0) {
		app.install = arc_install_state();
	} else if (strcmp(act, "fx") == 0) {
		app.fx = !app.fx;
		arc_fx_set(app.fx ? 1 : 0);
	} else if (strcmp(act, "close") == 0 || strcmp(act, "escape") == 0) {
		if (app.modal != MODAL_NONE)
			close_modal();
		else if (app.node == NODE_JAIL) {
			app.node = NODE_HOST;
			app.jail[0] = '\0';
		} else if (app.service[0] != '\0')
			close_service();
	} else if (strcmp(act, "toast") == 0) {
		i = atoi(arg);
		if (i >= 0 && i < app.ntoasts) {
			memmove(&app.toasts[i], &app.toasts[i + 1],
			    (size_t)(app.ntoasts - i - 1) *
			    sizeof(app.toasts[0]));
			app.ntoasts--;
		}
	} else if (strcmp(act, "input:filter") == 0) {
		snprintf(app.filter, sizeof(app.filter), "%s", value);
	} else if (strncmp(act, "submit:", 7) == 0) {
		ucl_object_t *f = json_parse(value);

		submit(act + 7, f);
		if (f != NULL)
			ucl_object_unref(f);
	}
}

EMSCRIPTEN_KEEPALIVE void
arc_on_action(char *act, char *arg, char *value)
{

	dispatch(act, arg, value);
	free(act);
	free(arg);
	free(value);
	render();
}

EMSCRIPTEN_KEEPALIVE void
arc_on_net(int online)
{

	app.online = online != 0;
	if (app.online) {
		last_health = last_refresh = 0;
		check_health();
		if (app.screen == SCREEN_OFFLINE)
			auth_status();
	} else
		app.api = LINK_UNKNOWN;
	render();
}

EMSCRIPTEN_KEEPALIVE void
arc_on_visible(int visible)
{

	app.visible = visible != 0;
	if (app.visible)
		last_refresh = 0;
}

int
main(void)
{

	arc_events_init();
	arc_sw_register();
	app.fx = arc_fx_get() != 0;
	app.notify = arc_notify_state();
	app.install = arc_install_state();
	app.queue_on = arc_queue_get() != 0;
	render();
	check_health();
	last_health = last_refresh = arc_now();
	auth_status();
	emscripten_set_interval(tick, 1000, NULL);
	return (0);
}
