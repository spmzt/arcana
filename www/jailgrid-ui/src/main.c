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
};

static double	last_health, last_refresh, last_tick_render, last_update;

static void	tick(void *);
static void	confirm(const char *, const char *, const char *, bool,
		    const char *, const char *, const char *, const char *);
static void	dispatch(const char *, const char *, const char *);
static void	close_service(void);
static void	submit(const char *, const ucl_object_t *);

void
render(void)
{
	static struct html	h;
	struct server		*s;
	char			 title[128];

	h_reset(&h);
	view(&h);
	jg_patch("app", h.s);
	s = cur_server();
	snprintf(title, sizeof(title), "%s%s%s", s != NULL &&
	    app.screen == SCREEN_CONSOLE ? s->name : "",
	    s != NULL && app.screen == SCREEN_CONSOLE ? " · " : "", APP_NAME);
	jg_title(title);
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
	t->until = jg_now() + (error ? 8000 : 4000);
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

	now = jg_now();
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
	if (app.screen == SCREEN_CONSOLE && app.online &&
	    now - last_update > UPDATE_MS) {
		last_update = now;
		check_update();
	}
	if (app.screen == SCREEN_CONSOLE && app.visible && app.online &&
	    now - last_refresh > REFRESH_MS) {
		last_refresh = now;
		if ((s = cur_server()) != NULL)
			refresh_jails(s, false);
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
	const char	*s;
	bool		 dry;

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
	if (strcmp(act, "select-server") == 0) {
		for (i = 0; i < app.nservers; i++)
			if (strcmp(app.servers[i].id, arg) == 0)
				app.sel = i;
		app.jail[0] = '\0';
		close_service();
		if ((s = cur_server()) != NULL) {
			refresh_jails(s, false);
			if (app.tab == TAB_SERVICES && s->services == NULL)
				refresh_services(s, false);
		}
	} else if (strcmp(act, "tab") == 0 && s != NULL) {
		app.tab = strcmp(arg, "services") == 0 ? TAB_SERVICES :
		    TAB_JAILS;
		app.jail[0] = '\0';
		close_service();
		if (app.tab == TAB_SERVICES && s->services == NULL)
			refresh_services(s, false);
	} else if (strcmp(act, "open-jail") == 0) {
		snprintf(app.jail, sizeof(app.jail), "%s", arg);
	} else if (strcmp(act, "close-drawer") == 0) {
		app.jail[0] = '\0';
		close_service();
	} else if (strcmp(act, "refresh") == 0 && s != NULL) {
		if (app.tab == TAB_SERVICES) {
			s->services_loading = false;
			refresh_services(s, true);
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
	} else if (strcmp(act, "fx") == 0) {
		app.fx = !app.fx;
		jg_fx_set(app.fx ? 1 : 0);
	} else if (strcmp(act, "close") == 0 || strcmp(act, "escape") == 0) {
		if (app.modal != MODAL_NONE)
			close_modal();
		else if (app.jail[0] != '\0')
			app.jail[0] = '\0';
		else if (app.service[0] != '\0')
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
jg_on_action(char *act, char *arg, char *value)
{

	dispatch(act, arg, value);
	free(act);
	free(arg);
	free(value);
	render();
}

EMSCRIPTEN_KEEPALIVE void
jg_on_net(int online)
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
jg_on_visible(int visible)
{

	app.visible = visible != 0;
	if (app.visible)
		last_refresh = 0;
}

int
main(void)
{

	jg_events_init();
	jg_sw_register();
	app.fx = jg_fx_get() != 0;
	render();
	check_health();
	last_health = last_refresh = jg_now();
	auth_status();
	emscripten_set_interval(tick, 1000, NULL);
	return (0);
}
