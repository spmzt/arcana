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
static char	loc_shown[600];	/* the page's address names this */
static char	loc_wanted[600];	/* to go to once the hosts are known */
static int	others_turn;	/* refreshes since the other hosts were read */

#define	OTHERS_EVERY	3	/* the hosts not selected: every third refresh */

static void	tick(void *);
static void	dispatch(const char *, const char *, const char *);
static void	close_service(void);
static void	submit(const char *, const ucl_object_t *);
static void	submit_form(const char *, const ucl_object_t *);
static void	loc_of(char *, size_t);
static void	loc_go(const char *);
static void	loc_show(void);

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
	loc_show();
}

/*
 * The page's address names what it shows: #/ the fleet, #/network,
 * #/usage, #/workflows, #/sdwan, #/api, #/settings/<tab>, a host as
 * #/hosts/<id> or #/hosts/<id>/<tab>, and a jail as
 * #/hosts/<id>/jails/<name>.  A link, a reload, the browser's back and
 * forward, and the Android app land where it says.
 */
static const char *const tabnames[] = {
	[TAB_SUMMARY] = "summary", [TAB_JAILS] = "jails",
	[TAB_SERVICES] = "services", [TAB_NETWORK] = "network",
	[TAB_FIREWALL] = "firewall", [TAB_PACKAGES] = "packages",
	[TAB_STORAGE] = "storage", [TAB_KERNEL] = "kernel",
	[TAB_SYSCTL] = "sysctl", [TAB_PROCESSES] = "processes",
	[TAB_LOG] = "log", [TAB_JOBS] = "jobs",
};

/* A jail's name in the address: what is not a letter, a digit or ._- in
 * %XX. */
static void
loc_enc(char *buf, size_t len, const char *s)
{
	static const char	hex[] = "0123456789ABCDEF";
	size_t			n;

	for (n = 0; *s != '\0' && n + 4 < len; s++) {
		if ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
		    (*s >= '0' && *s <= '9') || *s == '.' || *s == '_' ||
		    *s == '-')
			buf[n++] = *s;
		else {
			buf[n++] = '%';
			buf[n++] = hex[(unsigned char)*s >> 4];
			buf[n++] = hex[(unsigned char)*s & 15];
		}
	}
	buf[n] = '\0';
}

static int
loc_hex(int c)
{

	return (c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ?
	    c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1);
}

/* A field of the address, its %XX decoded. */
static void
loc_dec(char *buf, size_t len, const char *s)
{
	size_t	n;
	int	hi, lo;

	for (n = 0; *s != '\0' && n + 1 < len; s++) {
		if (s[0] == '%' && (hi = loc_hex((unsigned char)s[1])) != -1 &&
		    (lo = loc_hex((unsigned char)s[2])) != -1) {
			buf[n++] = (char)(hi << 4 | lo);
			s += 2;
		} else
			buf[n++] = *s;
	}
	buf[n] = '\0';
}

static void
loc_of(char *buf, size_t len)
{
	struct server	*s;
	char		 jail[sizeof(app.jail) * 3];

	s = cur_server();
	switch (app.node) {
	case NODE_NETWORK:
		snprintf(buf, len, "#/network");
		break;
	case NODE_API:
		snprintf(buf, len, "#/api");
		break;
	case NODE_USAGE:
		snprintf(buf, len, "#/usage");
		break;
	case NODE_WORKFLOWS:
		snprintf(buf, len, "#/workflows");
		break;
	case NODE_SDWAN:
		snprintf(buf, len, "#/sdwan");
		break;
	case NODE_SETTINGS:
		snprintf(buf, len, "#/settings/%s", settab_arg(app.settab));
		break;
	case NODE_JAIL:
		if (s != NULL && app.jail[0] != '\0') {
			loc_enc(jail, sizeof(jail), app.jail);
			snprintf(buf, len, "#/hosts/%s/jails/%s", s->id, jail);
			break;
		}
		/* FALLTHROUGH */
	case NODE_HOST:
		if (s != NULL) {
			snprintf(buf, len, "#/hosts/%s%s%s", s->id,
			    app.tab != TAB_SUMMARY ? "/" : "",
			    app.tab != TAB_SUMMARY ? tabnames[app.tab] : "");
			break;
		}
		/* FALLTHROUGH */
	default:
		snprintf(buf, len, "#/");
		break;
	}
}

/*
 * After every change, the address follows what is shown: a new entry in
 * the browser's history, so back goes to what was shown before, but
 * not for the first address, which only says where the page is.
 */
static void
loc_show(void)
{
	char	r[sizeof(loc_shown)];

	if (app.screen != SCREEN_CONSOLE || !app.servers_loaded ||
	    loc_wanted[0] != '\0')
		return;
	loc_of(r, sizeof(r));
	if (strcmp(r, loc_shown) == 0)
		return;
	arc_loc_set(r, loc_shown[0] != '\0');
	snprintf(loc_shown, sizeof(loc_shown), "%s", r);
}

/* Show what an address names, by the actions the page's controls use. */
static void
loc_go(const char *r)
{
	char	 buf[sizeof(loc_wanted)], *f[4], *q;
	char	 id[sizeof(app.servers[0].id)], arg[sizeof(app.jail)];
	int	 i, np;

	snprintf(buf, sizeof(buf), "%s", r);
	buf[strcspn(buf, "?")] = '\0';
	for (q = buf; *q == '#' || *q == '/'; q++)
		;
	for (np = 0; np < 4 && *q != '\0'; ) {
		f[np++] = q;
		q += strcspn(q, "/");
		if (*q == '/')
			*q++ = '\0';
	}
#define	IS(i, s)	(np > (i) && strcmp(f[i], (s)) == 0)
	if (IS(0, "network"))
		dispatch("select-network", "", "");
	else if (IS(0, "api"))
		dispatch("select-api", "", "");
	else if (IS(0, "usage"))
		dispatch("select-usage", "", "");
	else if (IS(0, "workflows"))
		dispatch("select-workflows", "", "");
	else if (IS(0, "sdwan"))
		dispatch("select-sdwan", "", "");
	else if (IS(0, "settings")) {
		loc_dec(arg, sizeof(arg), np > 1 ? f[1] : "");
		dispatch("set-tab", arg, "");
	} else if (IS(0, "hosts") && np > 1) {
		loc_dec(id, sizeof(id), f[1]);
		for (i = 0; i < app.nservers; i++)
			if (strcmp(app.servers[i].id, id) == 0)
				break;
		if (i == app.nservers) {
			/* A host no longer there: the fleet. */
			dispatch("select-fleet", "", "");
			return;
		}
		dispatch("select-server", id, "");
		if (IS(2, "jails") && np > 3) {
			loc_dec(arg, sizeof(arg), f[3]);
			dispatch("open-jail", arg, id);
		} else {
			loc_dec(arg, sizeof(arg), np > 2 ? f[2] : "summary");
			dispatch("tab", arg, "");
		}
	} else
		dispatch("select-fleet", "", "");
#undef IS
}

/*
 * The hosts are known: go where the address named when the page was
 * opened, or before the login it waited for.
 */
void
loc_pending(void)
{
	char	r[sizeof(loc_wanted)];

	if (loc_wanted[0] == '\0' || app.screen != SCREEN_CONSOLE)
		return;
	snprintf(r, sizeof(r), "%s", loc_wanted);
	loc_wanted[0] = '\0';
	loc_go(r);
	loc_of(loc_shown, sizeof(loc_shown));
	arc_loc_set(loc_shown, 0);
}

/* The browser went back or forward, or the address was typed. */
EMSCRIPTEN_KEEPALIVE void
arc_on_loc(char *r)
{

	if (app.screen == SCREEN_CONSOLE && app.servers_loaded) {
		loc_go(r);
		/* What it named, as it is said: a host gone is the fleet. */
		loc_of(loc_shown, sizeof(loc_shown));
		arc_loc_set(loc_shown, 0);
		render();
	} else
		snprintf(loc_wanted, sizeof(loc_wanted), "%s", r);
	free(r);
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
	if (now - last_health > HEALTH_MS || (app.health_retry != 0 &&
	    now > app.health_retry)) {
		app.health_retry = 0;
		last_health = now;
		check_health();
		/* Offline at start: try to reach the console again. */
		if (app.screen == SCREEN_OFFLINE && app.online)
			auth_status();
	}
	/* Running jobs: read them, and redraw when their trace grew. */
	if (app.screen == SCREEN_CONSOLE) {
		ops_load();
		ops_save();
		jobs_poll();
		agent_restarts(now);
		if (app.visible && app.online)
			topo_tick(now);
		if (app.online)
			bird_tick(now);
		if (app.online) {
			transport_tick(now);
			net_live_tick(now);
			firewall_tick(now);
			procs_tick(now);
			logs_tick(now);
			usage_tick(now);
			ecmp_tick(now);
			mtr_tick(now);
			storage_tick(now);
			workflows_tick(now);
			sdwan_tick(now);
		}
	}
	if (app.screen == SCREEN_CONSOLE && app.online &&
	    now - last_update > UPDATE_MS) {
		last_update = now;
		check_update();
	}
	if (app.screen == SCREEN_CONSOLE && app.visible && app.online &&
	    now - last_refresh > REFRESH_MS) {
		last_refresh = now;
		/* The fleet page watches every host, a host page its own. */
		for (i = 0; (app.node == NODE_FLEET || app.node ==
		    NODE_NETWORK || app.node == NODE_USAGE) && i <
		    app.nservers; i++) {
			refresh_jails(&app.servers[i], false);
			if (app.node == NODE_FLEET)
				refresh_stats(&app.servers[i]);
		}
		if (app.node != NODE_FLEET && app.node != NODE_NETWORK &&
		    app.node != NODE_USAGE && (s = cur_server()) != NULL) {
			refresh_jails(s, false);
			refresh_stats(s);
			if (app.tab == TAB_JOBS)
				refresh_jobs(s);
		}
		/*
		 * The tree shows every host: its state, its jails, its
		 * agent's version.  The others are read too, less often,
		 * or an agent updated or restarted elsewhere would show
		 * its old self until the page is loaded again.
		 */
		if (app.node != NODE_FLEET && app.node != NODE_NETWORK &&
		    app.node != NODE_USAGE && ++others_turn >= OTHERS_EVERY) {
			others_turn = 0;
			for (i = 0; i < app.nservers; i++)
				if (i != app.sel)
					refresh_jails(&app.servers[i], false);
		}
	}
	if (changed || now - last_tick_render >= AGE_STEP_MS) {
		last_tick_render = now;
		render();
	}
}

/* Is version a older than b?  "1.2.3" against "1.10.0", as numbers. */
bool
version_older(const char *a, const char *b)
{
	long	x, y;
	char	*ea, *eb;

	if (*a == 'v')
		a++;
	if (*b == 'v')
		b++;
	for (;;) {
		x = strtol(a, &ea, 10);
		y = strtol(b, &eb, 10);
		if (x != y)
			return (x < y);
		if (*ea != '.' || *eb != '.')
			return (false);
		a = ea + 1;
		b = eb + 1;
	}
}

void
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
	/* Nothing to type is no word, not the word "(null)". */
	snprintf(c->typed, sizeof(c->typed), "%s", typed != NULL ? typed : "");
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
	if (topo_form(form, f) || bird_form(form, f) || vpn_form(form, f) ||
	    jailmk_form(form, f) ||
	    ipsec_form(form, f) || workflows_form(form, f) || sdwan_form(form, f) ||
	    kernel_form(form, f) || storage_form(form, f) ||
	    sysctl_form(form, f) || procs_form(form, f) || logs_form(form, f) || usage_form(form, f) ||
	    firewall_form(form, f) || l2_form(form, f))
		return;
	submit_form(form, f);
}

static void
submit_form(const char *form, const ucl_object_t *f)
{
	struct server	*s2;
	const char	*s;
	bool		 dry;
	int		 i;

	if (strcmp(form, "pkg-install") == 0 && cur_server() != NULL) {
		struct html	 b;
		const char	*p;
		char		 word[128], title[300], *q, *qj;
		size_t		 n, nw;

		/* The names typed, each checked, as a JSON array. */
		memset(&b, 0, sizeof(b));
		nw = 0;
		for (p = jstr(f, "names") != NULL ? jstr(f, "names") : "";
		    *p != '\0'; ) {
			p += strspn(p, " ,\t");
			n = strcspn(p, " ,\t");
			if (n == 0)
				break;
			if (n >= sizeof(word) || strspn(p,
			    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
			    "0123456789-_.+@/") < n) {
				snprintf(app.modal_error, sizeof(app.modal_error),
				    "A package is named with letters, digits and "
				    "- _ . + @ /");
				free(b.s);
				return;
			}
			snprintf(word, sizeof(word), "%.*s", (int)n, p);
			q = json_quote(word);
			h_fmt(&b, "%s%s", nw++ > 0 ? "," : "", q);
			free(q);
			p += n;
		}
		if (nw == 0) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "Name the packages to install");
			free(b.s);
			return;
		}
		qj = json_quote(app.pkg.jail);
		if (asprintf(&q, "{\"kind\":\"pkg-install\",\"packages\":[%s]"
		    "%s%s%s%s%s}", b.s, app.pkg.jail[0] != '\0' ? ",\"jail\":" :
		    "", app.pkg.jail[0] != '\0' ? qj : "", app.pkg.ip != 0 ?
		    (app.pkg.ip == 4 ? ",\"pkg_ip\":4" : ",\"pkg_ip\":6") : "",
		    jbool(f, "anyos") ? ",\"force\":true" : "", "") == -1)
			abort();
		free(qj);
		snprintf(title, sizeof(title), "pkg install %.200s%s%s",
		    jstr(f, "names"), app.pkg.jail[0] != '\0' ? " in " : "",
		    app.pkg.jail);
		free(b.s);
		app.modal = MODAL_NONE;
		job_send(cur_server(), q, title, JOB_PACKAGES, app.pkg.jail);
	} else if (strcmp(form, "enrol") == 0) {
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
			pkg_upgrade(s2, any ? names : NULL, true, false);
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
	} else if (strcmp(form, "route") == 0) {
		s = jstr(f, "destination") != NULL ? jstr(f, "destination") :
		    "";
		if (s[0] == '\0' || jstr(f, "gateway") == NULL ||
		    jstr(f, "gateway")[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "Give a destination and a gateway");
			return;
		}
		/* A number, or nothing: not half of one. */
		for (i = 0; i < 3; i++) {
			static const char *const nf[] = { "metric", "weight",
			    "fib" };
			const char *t = jstr(f, nf[i]) != NULL ? jstr(f,
			    nf[i]) : "";

			if (t[strspn(t, "0123456789")] != '\0' || strlen(t) >
			    9) {
				snprintf(app.modal_error,
				    sizeof(app.modal_error), "The %s is a "
				    "number", nf[i]);
				return;
			}
		}
		app.modal = MODAL_NONE;
		if ((s2 = cur_server()) != NULL)
			route_change(s2, s, jstr(f, "gateway"), false, jbool(f,
			    "persist"), jstr(f, "fib") != NULL && jstr(f,
			    "fib")[0] != '\0' ? atoi(jstr(f, "fib")) :
			    app.net.fib, jstr(f, "metric") != NULL ? atoi(jstr(
			    f, "metric")) : 0, jstr(f, "weight") != NULL ?
			    atoi(jstr(f, "weight")) : 0, jstr(f, "source"));
	} else if (strcmp(form, "lookup") == 0) {
		/* The box stays: what the host answers is shown in it. */
		s = jstr(f, "address") != NULL ? jstr(f, "address") : "";
		if ((s2 = cur_server()) != NULL)
			topo_lookup(s2, s, jstr(f, "fib") != NULL && jstr(f,
			    "fib")[0] != '\0' ? atoi(jstr(f, "fib")) :
			    app.net.fib);
	} else if (strcmp(form, "if-address") == 0) {
		s = jstr(f, "address") != NULL ? jstr(f, "address") : "";
		if (strlen(s) < 2 || strchr(s, ' ') != NULL) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "Give an address, such as 10.0.0.5/24 or "
			    "2001:db8::5/64");
			return;
		}
		app.modal = MODAL_NONE;
		if ((s2 = cur_server()) == NULL)
			return;
		if (app.confirm.value[0] != '\0') {
			char	old[160];

			/* Unchanged: nothing to do. */
			if (strcmp(app.confirm.value, s) == 0)
				return;
			/* The new one first, then the old one off. */
			snprintf(old, sizeof(old), "%.*s", (int)strcspn(
			    app.confirm.value, "/"), app.confirm.value);
			if_address(s2, app.confirm.arg, s, false, jbool(f,
			    "persist"));
			if_address(s2, app.confirm.arg, old, true, true);
			return;
		}
		if_address(s2, app.confirm.arg, s, false, jbool(f,
		    "persist"));
	} else if (strcmp(form, "host-key") == 0) {
		/* Confirmed: build again, with the keys shown as trusted;
		 * or just again, once the deploy key is allowed. */
		app.modal = MODAL_NONE;
		for (i = 0; i < app.nservers; i++)
			if (strcmp(app.servers[i].id, app.build_sid) == 0)
				agent_build(&app.servers[i], jstr(app.build_reply,
				    "host_keys"), app.build_console);
	} else if (strcmp(form, "settings") == 0) {
		save_settings(f);
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
	if (topo_action(act, arg, value) || ng_action(act, arg, value) ||
	    bird_action(act, arg, value) || vpn_action(act, arg, value) ||
	    jailmk_action(act, arg, value) ||
	    ipsec_action(act, arg, value) || workflows_action(act, arg, value) ||
	    sdwan_action(act, arg, value) ||
	    kernel_action(act, arg, value) || storage_action(act, arg, value) ||
	    sysctl_action(act, arg, value) || apidoc_action(act, arg, value) ||
	    procs_action(act, arg, value) || logs_action(act, arg, value) ||
	    usage_action(act, arg, value) || ecmp_action(act, arg, value) ||
	    nhop_action(act, arg, value) || mtr_action(act, arg, value) ||
	    firewall_action(act, arg, value) || l2_action(act, arg, value) ||
	    tbl_action(act, arg, value))
		return;
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
		app.rail_open = false;
		for (i = 0; i < app.nservers; i++)
			if (strcmp(app.servers[i].id, arg) == 0)
				app.sel = i;
		app.node = NODE_HOST;
		app.jail[0] = '\0';
		/* A host opened from the tree shows its own network first. */
		app.net_jail[0] = '\0';
		close_service();
		if ((s = cur_server()) != NULL) {
			refresh_jails(s, false);
			refresh_stats(s);
			if (app.tab == TAB_SERVICES && s->services == NULL)
				refresh_services(s, true);
			if (app.tab == TAB_KERNEL)
				refresh_kernel(s, false);
			if (app.tab == TAB_SYSCTL)
				refresh_sysctl(s, false);
			if (app.tab == TAB_PROCESSES)
				refresh_procs(s, false);
			if (app.tab == TAB_LOG)
				refresh_logs(s, false);
			if (app.tab == TAB_FIREWALL)
				refresh_firewall(s, false);
			if (app.tab == TAB_STORAGE)
				refresh_storage(s, false);
			if (app.tab == TAB_NETWORK && (strcmp(app.net.sid,
			    s->id) != 0 || (app.net.data == NULL &&
			    !app.net.loading)))
				refresh_network(s, true);
			if (app.tab == TAB_PACKAGES && (strcmp(app.pkg.sid,
			    s->id) != 0 || (app.pkg.data == NULL &&
			    !app.pkg.loading)))
				refresh_packages(s, false);
		}
	} else if (strcmp(act, "tab") == 0 && s != NULL) {
		/* A plugin's tab is its view of the host's network. */
		if (strcmp(arg, "wireguard") == 0 || strcmp(arg, "bird") == 0 ||
		    strcmp(arg, "ipsec") == 0 ||
		    (strcmp(arg, "network") == 0 && app.net.kind >=
		    NET_WIREGUARD)) {
			app.net.kind = arg[0] == 'w' ? NET_WIREGUARD : arg[0] ==
			    'b' ? NET_BIRD : arg[0] == 'i' ? NET_IPSEC :
			    NET_INTERFACES;
			/* Opened where the plugin is, when not here. */
			if (kind_plugin(app.net.kind) != NULL && s->list !=
			    NULL && !has_plugin(s, kind_plugin(app.net.kind))) {
				const char *w = plugin_where(s,
				    kind_plugin(app.net.kind));

				if (w != NULL)
					snprintf(app.net_jail,
					    sizeof(app.net_jail), "%s", w);
			}
			app.net.sort = -1;
			app.net.loading = false;
			app.net.sid[0] = '\0';
		}
		app.tab = strcmp(arg, "services") == 0 ? TAB_SERVICES :
		    strcmp(arg, "network") == 0 || strcmp(arg, "wireguard") ==
		    0 || strcmp(arg, "bird") == 0 || strcmp(arg, "ipsec") == 0 ?
		    TAB_NETWORK :
		    strcmp(arg, "packages") == 0 ? TAB_PACKAGES :
		    strcmp(arg, "kernel") == 0 ? TAB_KERNEL :
		    strcmp(arg, "sysctl") == 0 ? TAB_SYSCTL :
		    strcmp(arg, "processes") == 0 ? TAB_PROCESSES :
		    strcmp(arg, "log") == 0 ? TAB_LOG :
		    strcmp(arg, "firewall") == 0 ? TAB_FIREWALL :
		    strcmp(arg, "storage") == 0 ? TAB_STORAGE :
		    strcmp(arg, "jails") == 0 ? TAB_JAILS :
		    strcmp(arg, "jobs") == 0 ? TAB_JOBS : TAB_SUMMARY;
		app.node = NODE_HOST;
		app.jail[0] = '\0';
		if (app.tab == TAB_JOBS)
			refresh_jobs(s);
		if (app.tab == TAB_KERNEL)
			refresh_kernel(s, true);
		if (app.tab == TAB_SYSCTL)
			refresh_sysctl(s, false);
		if (app.tab == TAB_PROCESSES)
			refresh_procs(s, true);
		if (app.tab == TAB_LOG)
			refresh_logs(s, false);
		if (app.tab == TAB_FIREWALL)
			refresh_firewall(s, true);
		if (app.tab == TAB_STORAGE)
			refresh_storage(s, true);
		close_service();
		if (app.tab == TAB_SERVICES && s->services == NULL)
			refresh_services(s, true);
		/* What is on its way for this host is waited for, not asked
		 * for again; what is here is shown. */
		if (app.tab == TAB_NETWORK && strcmp(app.net.sid, s->id) != 0)
			refresh_network(s, true);
		else if (app.tab == TAB_NETWORK && app.net.data == NULL &&
		    !app.net.loading)
			refresh_network(s, true);
		if (app.tab == TAB_PACKAGES && strcmp(app.pkg.sid, s->id) != 0)
			refresh_packages(s, false);
		else if (app.tab == TAB_PACKAGES && app.pkg.data == NULL &&
		    !app.pkg.loading)
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
	} else if (strcmp(act, "pkg-install") == 0 && s != NULL) {
		app.modal = MODAL_PKG_INSTALL;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "pkg-clean") == 0 && s != NULL) {
		snprintf(body, sizeof(body), "pkg clean%s on %s%s%s: %s",
		    arg[0] != '\0' ? " -a" : "", s->name, app.pkg.jail[0] !=
		    '\0' ? ", in jail " : "", app.pkg.jail, arg[0] != '\0' ?
		    "every downloaded package in the cache is deleted; what is "
		    "installed stays, and what is upgraded later is downloaded "
		    "again." : "the downloaded packages that are no longer "
		    "needed, or that the repository no longer has, are "
		    "deleted; what is installed stays.");
		confirm(arg[0] != '\0' ? "Clean all the package cache" :
		    "Clean the package cache", body, "Clean", arg[0] != '\0',
		    "", "do-pkg-clean", arg, "");
	} else if (strcmp(act, "do-pkg-clean") == 0 && s != NULL) {
		char	*json, *qj, title[300];

		qj = json_quote(app.pkg.jail);
		if (asprintf(&json, "{\"kind\":\"pkg-clean\"%s%s%s}",
		    app.pkg.jail[0] != '\0' ? ",\"jail\":" : "",
		    app.pkg.jail[0] != '\0' ? qj : "", arg[0] != '\0' ?
		    ",\"force\":true" : "") == -1)
			abort();
		free(qj);
		snprintf(title, sizeof(title), "pkg clean%s%s%s", arg[0] != '\0' ?
		    " -a" : "", app.pkg.jail[0] != '\0' ? " in " : "",
		    app.pkg.jail);
		/* The text is the queue's now. */
		job_send(s, json, title, JOB_PACKAGES, app.pkg.jail);
	} else if (strcmp(act, "pkg-clean-jails") == 0 && s != NULL) {
		const ucl_object_t	*j;
		ucl_object_iter_t	 it;
		int			 n;

		n = 0;
		it = NULL;
		while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
		    "jails"), &it, true)) != NULL)
			if (jstr(j, "state") != NULL && strcmp(jstr(j, "state"),
			    "running") == 0)
				n++;
		if (n == 0) {
			toast(true, "%s has no running jail", s->name);
			return;
		}
		snprintf(body, sizeof(body), "pkg clean%s in each of the %d "
		    "running jails of %s, each a job of its own in one batch: "
		    "%s A jail without pkg, or whose pkg refuses, fails alone; "
		    "the others are cleaned all the same. The host's own cache "
		    "is not touched.", arg[0] != '\0' ? " -a" : "", n, s->name,
		    arg[0] != '\0' ? "every downloaded package in their caches "
		    "is deleted." : "the downloaded packages no longer needed, "
		    "or no longer in the repository, are deleted.");
		confirm(arg[0] != '\0' ? "Clean all the caches of the jails" :
		    "Clean the caches of the jails", body, "Clean", arg[0] !=
		    '\0', "", "do-pkg-clean-jails", arg, "");
	} else if (strcmp(act, "do-pkg-clean-jails") == 0 && s != NULL) {
		const ucl_object_t	*j;
		ucl_object_iter_t	 it;
		struct queued		*q;
		char			*qj;
		int			 n;

		n = (int)ucl_array_size(jget(s->list, "jails"));
		if (n == 0 || (q = calloc((size_t)n, sizeof(*q))) == NULL)
			return;
		n = 0;
		it = NULL;
		while ((j = ucl_object_iterate(jget(s->list, "jails"), &it,
		    true)) != NULL) {
			if (jstr(j, "name") == NULL || jstr(j, "state") ==
			    NULL || strcmp(jstr(j, "state"), "running") != 0)
				continue;
			qj = json_quote(jstr(j, "name"));
			if (asprintf(&q[n].json, "{\"kind\":\"pkg-clean\","
			    "\"jail\":%s%s}", qj, arg[0] != '\0' ?
			    ",\"force\":true" : "") == -1)
				abort();
			free(qj);
			snprintf(q[n].title, sizeof(q[n].title), "pkg clean%s "
			    "in %s", arg[0] != '\0' ? " -a" : "", jstr(j,
			    "name"));
			snprintf(q[n].target, sizeof(q[n].target), "%s",
			    jstr(j, "name"));
			n++;
		}
		if (n > 0)
			job_send_many(s, q, n, JOB_PACKAGES);
		free(q);
	} else if (strcmp(act, "pkg-mode") == 0 && s != NULL) {
		/* The installed, or what the repository has newer: the
		 * repository is asked only for the second. */
		app.pkg.mode = atoi(arg) == 1 ? 1 : 0;
		if (app.pkg.data != NULL)
			ucl_object_unref(app.pkg.data);
		app.pkg.data = NULL;
		app.pkg.error[0] = '\0';
		app.pkg.loading = false;
		refresh_packages(s, false);
	} else if (strcmp(act, "pkg-ip") == 0) {
		app.pkg.ip = atoi(arg) == 4 ? 4 : atoi(arg) == 6 ? 6 : 0;
		arc_store_set("arc_pkg_ip", app.pkg.ip == 4 ? "4" : app.pkg.ip ==
		    6 ? "6" : "");
	} else if (strcmp(act, "pkg-upgrade-all") == 0 && s != NULL) {
		snprintf(body, sizeof(body), "pkg upgrade -y %s%s: every "
		    "package with a newer version in the repository is "
		    "replaced; services may restart.", app.pkg.jail[0] != '\0' ?
		    "in jail " : "on the host", app.pkg.jail);
		confirm("Upgrade all packages", body, "Upgrade", true, "",
		    "do-pkg-upgrade", "", "");
	} else if (strcmp(act, "do-pkg-upgrade") == 0 && s != NULL) {
		pkg_upgrade(s, value[0] != '\0' ? value : NULL, false, false);
	} else if ((strcmp(act, "do-pkg-anyos") == 0 || strcmp(act,
	    "do-pkg-dry-anyos") == 0) && s != NULL) {
		/* Approved: the same again, OSVERSION ignored. */
		pkg_upgrade(s, value[0] != '\0' ? value : NULL, act[7] == 'd',
		    true);
	} else if (strcmp(act, "queue") == 0) {
		app.queue_on = !app.queue_on;
		arc_queue_set(app.queue_on ? 1 : 0);
		app.dock_open = true;
	} else if (strcmp(act, "queue-run") == 0) {
		queue_run();
	} else if (strcmp(act, "queue-clear") == 0) {
		queue_clear();
	} else if (strcmp(act, "queue-drop") == 0) {
		i = atoi(arg);
		if (i >= 0 && i < app.nbatch) {
			free(app.batch[i].json);
			memmove(&app.batch[i], &app.batch[i + 1],
			    (size_t)(app.nbatch - i - 1) * sizeof(app.batch[0]));
			app.nbatch--;
		}
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
		/*
		 * The browser's leave is asked once; after, the button turns
		 * them off and on here, which the browser alone cannot.
		 */
		if (app.notify == 0)
			arc_notify_ask();
		else if (app.notify == 2)
			toast(true, "Notifications are blocked in this browser's "
			    "settings for this site: allow them there");
		else if (!app.notify_off) {
			app.notify_off = true;
			arc_store_set("arc_notify", "off");
			arc_push_off();
		} else {
			app.notify_off = false;
			arc_store_set("arc_notify", "");
			arc_push_sync();
		}
	} else if (strcmp(act, "notify-changed") == 0) {
		app.notify = arc_notify_state();
		/* Just allowed: on. */
		if (app.notify == 1) {
			app.notify_off = false;
			arc_store_set("arc_notify", "");
		}
		/* Allowed: this browser is told of tasks from now on. */
		arc_push_sync();
	} else if (strcmp(act, "push-changed") == 0) {
		load_push();
	} else if (strcmp(act, "push-remove") == 0) {
		arc_push_remove(arg);
	} else if (strcmp(act, "net-more") == 0 && s != NULL) {
		network_more(s);
	} else if (strcmp(act, "net-live") == 0) {
		app.net.paused = !app.net.paused;
	} else if (strcmp(act, "net-kind") == 0 && s != NULL) {
		app.net.sort = -1;
		app.net.kind = strcmp(arg, "nexthops") == 0 ? NET_NEXTHOPS :
		    strcmp(arg, "connections") == 0 ? NET_CONNECTIONS :
		    strcmp(arg, "sockets") == 0 ? NET_SOCKETS :
		    strcmp(arg, "interfaces") == 0 ? NET_INTERFACES :
		    strcmp(arg, "netgraph") == 0 ? NET_NETGRAPH :
		    strcmp(arg, "bridges") == 0 ? NET_BRIDGES :
		    strcmp(arg, "geneve") == 0 ? NET_GENEVE :
		    strcmp(arg, "nhgroups") == 0 ? NET_NHGROUPS :
		    strcmp(arg, "neighbours") == 0 ? NET_NEIGHBOURS :
		    strcmp(arg, "wireguard") == 0 ? NET_WIREGUARD :
		    strcmp(arg, "bird") == 0 ? NET_BIRD :
		    strcmp(arg, "ipsec") == 0 ? NET_IPSEC : NET_ROUTES;
		if (app.net.kind == NET_INTERFACES)
			topo_poll(s);
		app.net.loading = false;
		refresh_network(s, true);
	} else if (strcmp(act, "net-search") == 0 && s != NULL) {
		/* The text in the filter, searched for on the host. */
		const char *p;

		for (p = app.filter; *p != '\0'; p++)
			if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <=
			    'z') || (*p >= 'A' && *p <= 'Z') || strchr(".:/_-",
			    *p) != NULL))
				break;
		if (*p != '\0' || strlen(app.filter) > 128) {
			toast(true, "The host is searched for letters, digits "
			    "and . : / _ - only");
		} else {
			snprintf(app.net.host_filter,
			    sizeof(app.net.host_filter), "%s", app.filter);
			app.filter[0] = '\0';
			app.net.loading = false;
			refresh_network(s, true);
		}
	} else if (strcmp(act, "net-search-clear") == 0 && s != NULL) {
		app.net.host_filter[0] = '\0';
		app.net.loading = false;
		refresh_network(s, true);
	} else if (strcmp(act, "route-add") == 0 && s != NULL) {
		app.modal = MODAL_ROUTE;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "route-delete") == 0 && s != NULL) {
		char body[400];

		snprintf(body, sizeof(body), "route delete %s%s%s, on %s. %s "
		    "If rc.conf keeps the route, it is forgotten there too.", arg,
		    value[0] != '\0' ? " " : "", value, s->name, value[0] !=
		    '\0' ? "If that cuts the host off from the console, the "
		    "host puts the route back by itself after a minute." :
		    "This route has no gateway to put it back by: if the "
		    "console reaches the host through it, the host is cut "
		    "off.");
		confirm("Delete the route", body, "Delete", true, "",
		    "do-route-delete", arg, value);
	} else if (strcmp(act, "do-route-delete") == 0 && s != NULL) {
		route_change(s, arg, value, true, true, app.net.fib, 0, 0, NULL);
	} else if ((strcmp(act, "if-addr-add") == 0 || strcmp(act,
	    "if-addr-edit") == 0) && s != NULL) {
		/* One changed: the form with what it is now, which goes
		 * once the new one is there. */
		snprintf(app.confirm.arg, sizeof(app.confirm.arg), "%s", arg);
		snprintf(app.confirm.value, sizeof(app.confirm.value), "%s",
		    strcmp(act, "if-addr-edit") == 0 ? value : "");
		app.modal = MODAL_IF_ADDRESS;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "if-addr-remove") == 0 && s != NULL) {
		char body[400];

		snprintf(body, sizeof(body), "ifconfig %s %s -alias, on %s. "
		    "If that cuts the host off from the console, the host "
		    "puts the address back by itself after a minute. If "
		    "rc.conf keeps the address, it is forgotten there too.",
		    arg, value, s->name);
		confirm("Remove the address", body, "Remove", true, "",
		    "do-if-addr-remove", arg, value);
	} else if (strcmp(act, "do-if-addr-remove") == 0 && s != NULL) {
		if_address(s, arg, value, true, true);
	} else if (strcmp(act, "if-up") == 0 && s != NULL) {
		if_state(s, arg, true);
	} else if (strcmp(act, "if-down") == 0 && s != NULL) {
		char body[400];

		snprintf(body, sizeof(body), "ifconfig %s down, on %s. If "
		    "that cuts the host off from the console, the host "
		    "brings the interface back up by itself after a minute.",
		    arg, s->name);
		confirm("Bring the interface down", body, "Bring down", true,
		    arg, "do-if-down", arg, "");
	} else if (strcmp(act, "do-if-down") == 0 && s != NULL) {
		if_state(s, arg, false);
	} else if (strcmp(act, "if-edit") == 0 && s != NULL) {
		/* value: "mtu description", as the row has them now. */
		snprintf(app.confirm.arg, sizeof(app.confirm.arg), "%s", arg);
		snprintf(app.confirm.value, sizeof(app.confirm.value), "%d",
		    atoi(value));
		snprintf(app.confirm.body, sizeof(app.confirm.body), "%s",
		    strchr(value, ' ') != NULL ? strchr(value, ' ') + 1 : "");
		app.modal = MODAL_IF_SET;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "if-vnet-give") == 0 && s != NULL &&
	    net_scope()[0] != '\0') {
		app.modal = MODAL_IF_VNET;
		app.modal_error[0] = '\0';
		/* What the host has to give, and its bridges. */
		topo_poll_host(s);
	} else if (strcmp(act, "if-vnet-back") == 0 && s != NULL &&
	    net_scope()[0] != '\0') {
		snprintf(body, sizeof(body), "ifconfig %s -vnet %s, on %s: "
		    "the interface leaves the jail with what it carries "
		    "there, and is the host's again. It is taken out of the "
		    "jail's vnet.interface in jail.conf too.", arg, net_scope(),
		    s->name);
		confirm("Take the interface back", body, "Take back", true,
		    "", "do-if-vnet-back", arg, "");
	} else if (strcmp(act, "do-if-vnet-back") == 0 && s != NULL &&
	    net_scope()[0] != '\0') {
		const ucl_object_t *jl = find_jail(s, net_scope());
		char *q = json_quote(arg), *qj = json_quote(net_scope()), *json;

		/* Kept where the jail is defined, when it is. */
		if (asprintf(&json, "{\"kind\":\"if-vnet\",\"interface\":%s,"
		    "\"jail\":%s,\"remove\":true,\"persist\":%s}", q, qj,
		    jl != NULL && jstr(jl, "scope") != NULL ? "true" :
		    "false") == -1)
			abort();
		free(q);
		free(qj);
		snprintf(body, sizeof(body), "take %s back from %s", arg,
		    net_scope());
		job_send_host(s, json, body, JOB_IFACE, arg);
	} else if (strcmp(act, "if-destroy") == 0 && s != NULL) {
		snprintf(body, sizeof(body), "ifconfig %s destroy, on %s, and "
		    "it is forgotten in rc.conf. This cannot be undone; the "
		    "host refuses when the console reaches it through this "
		    "interface.", arg, s->name);
		confirm("Destroy the interface", body, "Destroy", true, arg,
		    "do-if-destroy", arg, "");
	} else if (strcmp(act, "do-if-destroy") == 0 && s != NULL) {
		char *q = json_quote(arg), *json;

		if (asprintf(&json, "{\"kind\":\"if-destroy\",\"interface\":"
		    "%s,\"persist\":true}", q) == -1)
			abort();
		free(q);
		snprintf(body, sizeof(body), "destroy %s", arg);
		job_send(s, json, body, JOB_IFACE, arg);
	} else if (strcmp(act, "net-lookup") == 0 && s != NULL) {
		topo_lookup_clear();
		app.modal = MODAL_LOOKUP;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "net-lookup-clear") == 0) {
		topo_lookup_clear();
	} else if (strcmp(act, "jail-net") == 0 && s != NULL) {
		/* A jail's own network: the host's tab, the jail picked. */
		app.node = NODE_HOST;
		app.peek = false;
		app.tab = TAB_NETWORK;
		app.jail[0] = '\0';
		snprintf(app.net_jail, sizeof(app.net_jail), "%s", arg);
		/* Its interfaces first. */
		app.net.kind = NET_INTERFACES;
		app.net.sort = -1;
		app.net.loading = false;
		topo_lookup_clear();
		topo_poll(s);
		refresh_network(s, true);
	} else if (strcmp(act, "plugin-install") == 0 && s != NULL) {
		plugin_install(s, arg);
	} else if (strcmp(act, "net-jail-set") == 0 && s != NULL) {
		snprintf(app.net_jail, sizeof(app.net_jail), "%s", arg);
		app.net.sort = -1;
		app.net.loading = false;
		refresh_network(s, true);
	} else if (strcmp(act, "input:net-jail") == 0 && s != NULL) {
		snprintf(app.net_jail, sizeof(app.net_jail), "%s", value);
		app.net.sort = -1;
		app.net.loading = false;
		app.net.host_filter[0] = '\0';
		topo_lookup_clear();
		if (app.net.kind == NET_INTERFACES)
			topo_poll(s);
		refresh_network(s, true);
	} else if (strcmp(act, "input:net-fib") == 0 && s != NULL) {
		app.net.fib = atoi(value) > 0 && atoi(value) < 65536 ?
		    atoi(value) : 0;
		app.net.loading = false;
		refresh_network(s, false);
	} else if (strcmp(act, "net-family") == 0 && s != NULL) {
		app.net.family = atoi(arg);
		app.net.loading = false;
		refresh_network(s, true);
	} else if (strcmp(act, "select-fleet") == 0) {
		app.rail_open = false;
		app.node = NODE_FLEET;
		app.jail[0] = '\0';
		close_service();
		for (i = 0; i < app.nservers; i++) {
			refresh_jails(&app.servers[i], false);
			refresh_stats(&app.servers[i]);
		}
	} else if (strcmp(act, "open-jail") == 0) {
		app.rail_open = false;
		/* value: the server, when the jail is picked in the tree. */
		for (i = 0; value[0] != '\0' && i < app.nservers; i++)
			if (strcmp(app.servers[i].id, value) == 0)
				app.sel = i;
		app.node = NODE_JAIL;
		app.peek = false;
		snprintf(app.jail, sizeof(app.jail), "%s", arg);
		close_service();
		topo_lookup_clear();
	} else if (strcmp(act, "peek-jail") == 0) {
		/* From a graph, the fleet's or a host's: the jail in a box
		 * over the page, which stays the page it is. */
		for (i = 0; value[0] != '\0' && i < app.nservers; i++)
			if (strcmp(app.servers[i].id, value) == 0)
				app.sel = i;
		app.peek = true;
		snprintf(app.jail, sizeof(app.jail), "%s", arg);
	} else if (strcmp(act, "close-drawer") == 0) {
		if (app.node == NODE_JAIL)
			app.node = NODE_HOST;
		app.peek = false;
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
		} else if (app.tab == TAB_KERNEL) {
			refresh_kernel(s, true);
		} else if (app.tab == TAB_SYSCTL) {
			refresh_sysctl(s, true);
		} else if (app.tab == TAB_PROCESSES) {
			refresh_procs(s, true);
		} else if (app.tab == TAB_LOG) {
			refresh_logs(s, true);
		} else if (app.tab == TAB_FIREWALL) {
			refresh_firewall(s, true);
		} else if (app.tab == TAB_STORAGE) {
			refresh_storage(s, true);
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
	} else if (strcmp(act, "schema") == 0) {
		app.trace_schema = !app.trace_schema;
	} else if (strcmp(act, "op-retry") == 0) {
		op_retry(atoi(arg));
	} else if (strcmp(act, "op-cancel") == 0) {
		struct op *o;

		if ((o = op_find(atoi(arg))) != NULL)
			op_cancel(o);
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
	} else if (strcmp(act, "console-update") == 0 && s != NULL) {
		char body[640];

		snprintf(body, sizeof(body), "%s clones %s, builds all of "
		    "Arcana there and installs it over what is installed: the "
		    "console, the page and the agent. The console's service "
		    "is then restarted and this page reconnects. This can "
		    "take several minutes.", s->name, app.agent_source);
		confirm("Update the console", body, "Update", true, "",
		    "do-agent-build", s->id, "console");
		/* What the update brings: the box reads it. */
		notes_load("console", app.version, NULL, false);
	} else if (strcmp(act, "do-agent-build") == 0) {
		for (i = 0; i < app.nservers; i++)
			if (strcmp(app.servers[i].id, arg) == 0)
				agent_build(&app.servers[i], NULL, value[0] !=
				    '\0');
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
		/* What the hosts get: from the oldest of theirs to the
		 * console's. */
		{
			const char	*from, *hv;

			from = NULL;
			for (i = 0; i < app.nservers; i++) {
				if (arg[0] != '\0' ? strcmp(app.servers[i].id, arg)
				    != 0 : !agent_outdated(&app.servers[i]))
					continue;
				hv = jstr(app.servers[i].list, "host.version");
				if (hv != NULL && (from == NULL || version_older(hv,
				    from)))
					from = hv;
			}
			notes_load("agent", from != NULL ? from : "0",
			    app.agent_version, false);
		}
	} else if (strcmp(act, "theme") == 0) {
		snprintf(app.theme, sizeof(app.theme), "%s", arg);
		arc_theme_set(app.theme);
	} else if (strcmp(act, "rail-toggle") == 0) {
		app.rail_open = !app.rail_open;
	} else if (strcmp(act, "who-toggle") == 0) {
		app.who_open = !app.who_open;
	} else if (strcmp(act, "settings") == 0 || strcmp(act, "keys") == 0 ||
	    strcmp(act, "set-tab") == 0) {
		/* Settings, a section: opened at its first tab, or one named. */
		if (app.node != NODE_SETTINGS) {
			app.node = NODE_SETTINGS;
			app.jail[0] = '\0';
			app.rail_open = false;
			app.who_open = false;
			app.settab = SET_LOOK;
			load_settings();
			load_tokens();
			load_keys();
		}
		if (strcmp(act, "keys") == 0)
			app.settab = SET_KEYS;
		else if (strcmp(act, "set-tab") == 0)
			app.settab = settab_of(arg);
		if (app.settab == SET_NEWS && !app.notes_busy && (app.notes ==
		    NULL || strcmp(app.notes_for, "console") != 0))
			notes_load("console", app.version, NULL, false);
	} else if (strcmp(act, "notes-reload") == 0) {
		notes_load("console", app.version, NULL, true);
		app.modal_error[0] = '\0';
		/* A token's value is shown once: not again on another tab. */
		app.token_value[0] = '\0';
	} else if (strcmp(act, "input:token-name") == 0) {
		snprintf(app.token_name, sizeof(app.token_name), "%s", value);
	} else if (strcmp(act, "token-new") == 0) {
		token_new();
	} else if (strcmp(act, "token-del") == 0) {
		confirm("Delete the API token", "A program that uses it can no "
		    "longer read anything from the console, from now on.",
		    "Delete", true, "", "do-token-del", arg, "");
	} else if (strcmp(act, "do-token-del") == 0) {
		token_del(arg);
	} else if (strcmp(act, "delete-key") == 0) {
		confirm("Remove security key", "This key will no longer log "
		    "in. The last key cannot be removed.", "Remove", true, "",
		    "do-delete-key", arg, "");
	} else if (strcmp(act, "do-delete-key") == 0) {
		delete_key(arg);
	} else if (strcmp(act, "servers-again") == 0) {
		refresh_servers();
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
	} else if (strcmp(act, "copied") == 0) {
		toast(value[0] != '\0', value[0] != '\0' ? "The browser would "
		    "not copy it: select it and copy it by hand" : "Copied");
	} else if (strcmp(act, "close") == 0 || strcmp(act, "escape") == 0) {
		if (app.modal != MODAL_NONE)
			close_modal();
		else if (app.peek) {
			app.peek = false;
			app.jail[0] = '\0';
		} else if (app.node == NODE_JAIL) {
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

	/* The top bar's menu closes at whatever is done next. */
	if (app.who_open && strcmp(act, "who-toggle") != 0 && strcmp(act,
	    "resize") != 0)
		app.who_open = false;
	dispatch(act, arg, value);
	free(act);
	free(arg);
	free(value);
	render();
}

/* A part of something that comes in parts, or word that none will. */
EMSCRIPTEN_KEEPALIVE void
arc_on_stream(char *text)
{
	ucl_object_t	*o;

	o = json_parse(text);
	free(text);
	if (o == NULL)
		return;
	sysctl_stream(o);
	network_stream(o);
	logs_stream(o);
	ucl_object_unref(o);
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
	{
		char *v = arc_store_get("arc_notify");

		app.notify_off = v != NULL && strcmp(v, "off") == 0;
		free(v);
	}
	app.install = arc_install_state();
	{
		char *v = arc_store_get("arc_pkg_ip");

		app.pkg.ip = v != NULL ? atoi(v) : 0;
		free(v);
	}
	app.queue_on = arc_queue_get() != 0;
	{
		char *t = arc_theme_get();

		snprintf(app.theme, sizeof(app.theme), "%s", t);
		free(t);
	}
	app.trace_schema = true;
	{
		char *r = arc_loc_get();

		/* An address that names more than the fleet. */
		if (strcmp(r, "") != 0 && strcmp(r, "#") != 0 &&
		    strcmp(r, "#/") != 0)
			snprintf(loc_wanted, sizeof(loc_wanted), "%s", r);
		free(r);
	}
	render();
	check_health();
	last_health = last_refresh = arc_now();
	auth_status();
	emscripten_set_interval(tick, 1000, NULL);
	return (0);
}
