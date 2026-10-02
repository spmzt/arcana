/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console's markup, rebuilt from the state on every change; bridge.js
 * patches the page so only what differs is touched.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static const char *icon_grid =
    "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M3 3h7v7H3z"
    "M14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z\"/></svg>";
static const char *icon_key =
    "<svg viewBox=\"0 0 64 64\" aria-hidden=\"true\"><rect x=\"18\" y=\"6\" "
    "width=\"28\" height=\"40\" rx=\"6\"/><circle cx=\"32\" cy=\"22\" "
    "r=\"7\"/><path d=\"M26 46v8h12v-8\"/><path d=\"M24 36h16\"/></svg>";
static const char *icon_refresh =
    "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M20 12a8 8 "
    "0 1 1-2.3-5.7M20 4v4h-4\"/></svg>";

static void	topbar(struct html *);
static void	banner(struct html *);
static void	rail(struct html *);
static void	stage(struct html *);
static void	hostbar(struct html *, struct server *);
static void	card(struct html *, struct server *, const ucl_object_t *);
static void	drawer(struct html *);
static void	actions(struct html *, struct server *, const ucl_object_t *,
		    const struct jailui *, bool);
static void	dock(struct html *);
static void	modal(struct html *);
static void	toasts(struct html *);
static void	auth_screen(struct html *);
static void	fmt_kb(char *, size_t, int64_t);
static int	count_state(const struct server *, const char *);
static bool	stale(const struct server *);

void
fmt_age(char *buf, size_t len, double ms)
{
	double	s;

	s = (jg_now() - ms) / 1000;
	if (s < 15)
		snprintf(buf, len, "just now");
	else if (s < 60)
		snprintf(buf, len, "%.0fs ago", s - (double)((int)s % 10));
	else if (s < 3600)
		snprintf(buf, len, "%.0fm ago", s / 60);
	else
		snprintf(buf, len, "%.1fh ago", s / 3600);
}

void
fmt_dur(char *buf, size_t len, int64_t us)
{

	if (us < 1000)
		snprintf(buf, len, "%lld µs", (long long)us);
	else if (us < 1000000)
		snprintf(buf, len, "%.1f ms", us / 1000.0);
	else
		snprintf(buf, len, "%.2f s", us / 1000000.0);
}

static void
fmt_kb(char *buf, size_t len, int64_t kb)
{

	if (kb < 1024)
		snprintf(buf, len, "%lld KiB", (long long)kb);
	else if (kb < 1024 * 1024)
		snprintf(buf, len, "%.0f MiB", kb / 1024.0);
	else
		snprintf(buf, len, "%.1f GiB", kb / (1024.0 * 1024));
}

/* Data is stale when the last refresh failed or it is simply old. */
static bool
stale(const struct server *s)
{

	return (s->list != NULL && (s->failed || !app.online ||
	    jg_now() - s->fetched > STALE_MS));
}

/*
 * The state to show: an action in flight wins, then a failed action,
 * then "unknown" when the host is unreachable, then what the host said.
 */
const char *
state_class(const struct server *s, const ucl_object_t *j,
    const struct jailui *u)
{
	const char	*st;

	if (u != NULL) {
		switch (u->pending) {
		case PEND_START:
			return ("starting");
		case PEND_STOP:
		case PEND_KILL:
			return ("stopping");
		case PEND_RESTART:
			return ("restarting");
		default:
			break;
		}
		if (u->error[0] != '\0')
			return ("error");
	}
	if (s->failed || !app.online)
		return ("unknown");
	st = jstr(j, "state");
	return (h_word(st, "unknown"));
}

static int
count_state(const struct server *s, const char *state)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	if (s->list == NULL)
		return (0);
	while ((j = ucl_object_iterate(jget(s->list, "jails"), &it,
	    true)) != NULL)
		if (state == NULL || (jstr(j, "state") != NULL &&
		    strcmp(jstr(j, "state"), state) == 0))
			n++;
	return (n);
}

static void
link_led(struct html *h, const char *name, enum link l, const char *title)
{

	h_fmt(h, "<span class=\"link %s\"", l == LINK_UP ? "up" :
	    l == LINK_DOWN ? "down" : "unknown");
	h_attr(h, "title", title);
	h_raw(h, "><i class=\"led\"></i>");
	h_txt(h, name);
	h_raw(h, "</span>");
}

static void
topbar(struct html *h)
{
	struct server	*s;
	enum link	 host;

	s = cur_server();
	h_raw(h, "<header class=\"topbar\"><div class=\"brand\">"
	    "<span class=\"logo\">");
	h_raw(h, icon_grid);
	h_raw(h, "</span><span class=\"wordmark\">JAILGRID</span></div>"
	    "<nav class=\"crumbs\">");
	if (s != NULL) {
		h_raw(h, "<span class=\"crumb\">");
		h_txt(h, s->name);
		h_raw(h, "</span>");
		if (app.jail[0] != '\0') {
			h_raw(h, "<span class=\"sep\">/</span>"
			    "<span class=\"crumb\">");
			h_txt(h, app.jail);
			h_raw(h, "</span>");
		}
	}
	h_raw(h, "</nav><div class=\"links\">");
	link_led(h, "NET", app.online ? LINK_UP : LINK_DOWN, app.online ?
	    "This device is online" : "This device is offline");
	link_led(h, "API", app.api, app.api == LINK_UP ?
	    "The console answers" : app.api == LINK_DOWN ?
	    "The console does not answer" : "Not checked yet");
	host = s == NULL || (s->list == NULL && !s->failed) ? LINK_UNKNOWN :
	    s->failed ? LINK_DOWN : LINK_UP;
	link_led(h, "HOST", host, s == NULL ? "No server selected" :
	    s->failed ? s->error : "jailgridd answers");
	h_raw(h, "</div><div class=\"who\">");
	h_fmt(h, "<button class=\"ghost%s\" data-act=\"fx\" title=\"Blur and "
	    "idle animations: %s. Off is lighter on slow browsers; the "
	    "choice stays in this browser.\">FX</button>", app.fx ? " on" :
	    "", app.fx ? "on" : "off");
	h_raw(h, "<button class=\"ghost\" data-act=\"keys\">Keys</button>"
	    "<button class=\"ghost\" data-act=\"logout\">Log out</button>"
	    "</div></header>");
}

static void
banner(struct html *h)
{

	if (!app.online)
		h_raw(h, "<div class=\"banner warn\"><b>Offline.</b> The "
		    "console itself is cached on this device; jail data is "
		    "not, and what is shown is the last known state.</div>");
	else if (app.api == LINK_DOWN)
		h_raw(h, "<div class=\"banner bad\"><b>The console does not "
		    "answer.</b> Showing the last known state; it will "
		    "reconnect by itself.</div>");
	else if (app.update_latest[0] != '\0') {
		h_raw(h, "<div class=\"banner info\"><b>Jailgrid ");
		h_txt(h, app.update_latest);
		h_raw(h, " is out</b> (this console is ");
		h_txt(h, app.version[0] != '\0' ? app.version : "older");
		h_raw(h, "). In the container: <code>podman auto-update</code>; "
		    "from the package: <code>pkg upgrade jailgrid</code>; then "
		    "<code>jailgrid-enrol</code> hosts again only if told so in "
		    "the ");
		if (app.update_url[0] != '\0') {
			h_raw(h, "<a target=\"_blank\" rel=\"noopener\"");
			h_attr(h, "href", app.update_url);
			h_raw(h, ">release notes</a>");
		} else
			h_raw(h, "release notes");
		h_raw(h, ".</div>");
	}
}

static void
rail(struct html *h)
{
	struct server	*s;
	const char	*cls;
	char		 buf[64];
	int		 i, run, all;

	h_raw(h, "<aside class=\"rail\"><div class=\"rail-head\">"
	    "<span class=\"label\">Servers</span>"
	    "<button class=\"icon\" data-act=\"add-server\" title=\"Add a "
	    "server\">+</button></div><ul class=\"servers\">");
	for (i = 0; i < app.nservers; i++) {
		s = &app.servers[i];
		run = count_state(s, "running");
		all = count_state(s, NULL);
		cls = s->failed ? "down" : s->list != NULL ? "up" : "unknown";
		h_fmt(h, "<li class=\"server %s%s\"", cls, i == app.sel ?
		    " selected" : "");
		h_raw(h, " data-act=\"select-server\"");
		h_attr(h, "data-arg", s->id);
		h_raw(h, "><i class=\"led\"></i><div class=\"meta\">"
		    "<span class=\"name\">");
		h_txt(h, s->name);
		h_raw(h, "</span><span class=\"uri\">");
		h_txt(h, s->uri);
		h_raw(h, "</span></div>");
		if (s->list != NULL) {
			snprintf(buf, sizeof(buf), "%d/%d", run, all);
			h_raw(h, "<span class=\"count\" title=\"running/"
			    "known\">");
			h_txt(h, buf);
			h_raw(h, "</span>");
		}
		h_raw(h, "<button class=\"icon del\" data-act=\"delete-server"
		    "\" title=\"Remove\"");
		h_attr(h, "data-arg", s->id);
		h_raw(h, ">×</button></li>");
	}
	h_raw(h, "</ul></aside>");
}

static void
hostbar(struct html *h, struct server *s)
{
	const ucl_object_t	*host;
	char			 buf[96], age[32];
	int64_t			 up;

	host = jget(s->list, "host");
	h_raw(h, "<section class=\"hostbar\"><div class=\"host-id\">"
	    "<h1>");
	h_txt(h, jstr(host, "hostname") != NULL ? jstr(host, "hostname") :
	    s->name);
	h_raw(h, "</h1><div class=\"facts\">");
	if (host != NULL) {
		snprintf(buf, sizeof(buf), "%s %s %s", jstr(host, "sysname"),
		    jstr(host, "release"), jstr(host, "machine"));
		h_raw(h, "<span>");
		h_txt(h, buf);
		h_raw(h, "</span>");
		snprintf(buf, sizeof(buf), "%lld CPU",
		    (long long)jint(host, "ncpu", 0));
		h_raw(h, "<span>");
		h_txt(h, buf);
		h_raw(h, "</span>");
		fmt_kb(buf, sizeof(buf), jint(host, "physmem", 0) / 1024);
		h_raw(h, "<span>");
		h_txt(h, buf);
		h_raw(h, "</span>");
		up = jint(host, "time", 0) - jint(host, "boottime", 0);
		snprintf(buf, sizeof(buf), "up %lldd %lldh",
		    (long long)(up / 86400), (long long)(up % 86400 / 3600));
		h_raw(h, "<span>");
		h_txt(h, buf);
		h_raw(h, "</span>");
		if (!jbool(host, "privileged"))
			h_raw(h, "<span class=\"warn\" title=\"jailgridd is "
			    "not running as root: changes will fail\">"
			    "unprivileged</span>");
		if (jstr(host, "version") != NULL) {
			h_raw(h, app.version[0] != '\0' && strcmp(jstr(host,
			    "version"), app.version) != 0 ? "<span class=\"warn\" "
			    "title=\"Not the console's version: update jailgridd "
			    "on this host\">jailgridd " : "<span>jailgridd ");
			h_txt(h, jstr(host, "version"));
			h_raw(h, "</span>");
		}
	} else {
		h_raw(h, "<span>");
		h_txt(h, s->uri);
		h_raw(h, "</span>");
	}
	h_raw(h, "</div></div><div class=\"freshness\">");
	if (s->list != NULL) {
		fmt_age(age, sizeof(age), s->fetched);
		h_fmt(h, "<span class=\"age%s\">", stale(s) ? " stale" : "");
		h_raw(h, stale(s) ? "STALE · " : "");
		h_txt(h, age);
		h_raw(h, "</span>");
	}
	h_fmt(h, "<button class=\"icon%s\" data-act=\"refresh\" "
	    "title=\"Refresh (shows its trace)\">", s->loading ? " spin" : "");
	h_raw(h, icon_refresh);
	h_raw(h, "</button></div></section>");
	if (s->failed) {
		h_raw(h, "<div class=\"notice bad\"><b>");
		h_txt(h, s->name);
		h_raw(h, " is unreachable:</b> ");
		h_txt(h, s->error);
		h_raw(h, "</div>");
	}
}

static void
actions(struct html *h, struct server *s, const ucl_object_t *j,
    const struct jailui *u, bool big)
{
	const char	*st, *name;
	bool		 busy, configured, running;

	name = jstr(j, "name");
	st = jstr(j, "state");
	busy = (u != NULL && u->pending != PEND_NONE) || s->failed ||
	    !app.online;
	configured = jbool(j, "configured");
	running = st != NULL && (strcmp(st, "running") == 0 ||
	    strcmp(st, "dying") == 0);
	h_fmt(h, "<div class=\"actions%s\">", big ? " big" : "");
	if (!running) {
		h_fmt(h, "<button class=\"act go\" data-act=\"start\"%s",
		    busy || !configured ? " disabled" : "");
		h_attr(h, "data-arg", name);
		h_raw(h, configured ? ">Start</button>" : " title=\"Not in "
		    "any jail.conf\">Start</button>");
	} else {
		h_fmt(h, "<button class=\"act\" data-act=\"stop\"%s",
		    busy || !configured ? " disabled" : "");
		h_attr(h, "data-arg", name);
		h_raw(h, configured ? ">Stop</button>" : " title=\"Not in any "
		    "jail.conf: use kill\">Stop</button>");
		h_fmt(h, "<button class=\"act\" data-act=\"restart\"%s",
		    busy || !configured ? " disabled" : "");
		h_attr(h, "data-arg", name);
		h_raw(h, ">Restart</button>");
		h_fmt(h, "<button class=\"act danger\" data-act=\"kill\"%s",
		    busy ? " disabled" : "");
		h_attr(h, "data-arg", name);
		h_raw(h, " title=\"jail_remove(2): no stop scripts\">"
		    "Kill</button>");
	}
	h_raw(h, "</div>");
}

static void
card(struct html *h, struct server *s, const ucl_object_t *j)
{
	const ucl_object_t	*ips;
	const struct jailui	*u;
	const char		*name, *cls;
	char			 buf[96];
	unsigned int		 n;

	name = jstr(j, "name");
	u = jailui(s, name);
	cls = state_class(s, j, u);
	h_fmt(h, "<article class=\"jail s-%s%s\"", cls,
	    strcmp(app.jail, name) == 0 ? " open" : "");
	snprintf(buf, sizeof(buf), "j-%s", name);
	h_attr(h, "id", buf);
	h_raw(h, " data-act=\"open-jail\"");
	h_attr(h, "data-arg", name);
	h_raw(h, "><div class=\"scan\"></div><header><i class=\"led\"></i>"
	    "<h3>");
	h_txt(h, name);
	h_raw(h, "</h3><span class=\"state\">");
	h_txt(h, cls);
	h_raw(h, "</span>");
	if (jget(j, "jid") != NULL && ucl_object_type(jget(j, "jid")) ==
	    UCL_INT) {
		snprintf(buf, sizeof(buf), "JID %lld",
		    (long long)jint(j, "jid", 0));
		h_raw(h, "<span class=\"jid\">");
		h_txt(h, buf);
		h_raw(h, "</span>");
	}
	h_raw(h, "</header><dl>");
	ips = jget(j, "ip4");
	if (ucl_array_size(ips) == 0)
		ips = jget(j, "ip6");
	if ((n = ucl_array_size(ips)) > 0) {
		h_raw(h, "<dt>IP</dt><dd class=\"mono\">");
		h_txt(h, ucl_object_tostring(ucl_array_find_index(ips, 0)));
		if (n > 1)
			h_fmt(h, " <span class=\"more\">+%u</span>", n - 1);
		h_raw(h, "</dd>");
	} else if (jbool(j, "vnet"))
		h_raw(h, "<dt>NET</dt><dd>vnet</dd>");
	if (jstr(j, "hostname") != NULL) {
		h_raw(h, "<dt>HOST</dt><dd>");
		h_txt(h, jstr(j, "hostname"));
		h_raw(h, "</dd>");
	}
	if (jstr(j, "path") != NULL) {
		h_raw(h, "<dt>PATH</dt><dd class=\"mono\">");
		h_txt(h, jstr(j, "path"));
		h_raw(h, "</dd>");
	}
	h_raw(h, "</dl>");
	if (jget(j, "nproc") != NULL) {
		char rss[32];

		fmt_kb(rss, sizeof(rss), jint(j, "rss_kb", 0));
		h_raw(h, "<div class=\"meters\">");
		h_fmt(h, "<span><b>%lld</b> proc</span>",
		    (long long)jint(j, "nproc", 0));
		h_raw(h, "<span><b>");
		h_txt(h, rss);
		h_raw(h, "</b></span>");
		h_fmt(h, "<span><b>%.1f%%</b> cpu</span>",
		    jnum(j, "cpu_pct", 0));
		h_fmt(h, "<i class=\"bar\" style=\"--v:%.3f\"></i>",
		    jnum(j, "cpu_pct", 0) / 100.0 > 1 ? 1.0 :
		    jnum(j, "cpu_pct", 0) / 100.0);
		h_raw(h, "</div>");
	} else if (!jbool(j, "configured"))
		h_raw(h, "<div class=\"meters dim\">not in any "
		    "jail.conf</div>");
	else
		h_raw(h, "<div class=\"meters dim\">configured, not "
		    "running</div>");
	if (u->error[0] != '\0') {
		h_raw(h, "<p class=\"err\">");
		h_txt(h, u->error);
		h_raw(h, "</p>");
	}
	actions(h, s, j, u, false);
	h_raw(h, "</article>");
}

static void
stage(struct html *h)
{
	const ucl_object_t	*j, *e;
	ucl_object_iter_t	 it;
	struct server		*s;
	int			 shown;

	h_raw(h, "<main class=\"stage\">");
	if (!app.servers_loaded) {
		h_raw(h, "<div class=\"empty\"><div class=\"loader\"></div>"
		    "</div></main>");
		return;
	}
	if ((s = cur_server()) == NULL) {
		h_raw(h, "<div class=\"empty\"><h2>No servers yet</h2><p>Add "
		    "a host running <code>jailgridd(8)</code>: "
		    "<code>unix:/var/run/jailgridd.sock</code> for this "
		    "machine, <code>tcp://host:4310</code> for others.</p>"
		    "<button class=\"primary\" data-act=\"add-server\">Add a "
		    "server</button> <button class=\"ghost\" data-act=\"enrol\">"
		    "Enrol a host</button></div></main>");
		return;
	}
	hostbar(h, s);
	h_fmt(h, "<nav class=\"tabs\"><button class=\"tab%s\" data-act=\"tab\" "
	    "data-arg=\"jails\">Jails</button><button class=\"tab%s\" "
	    "data-act=\"tab\" data-arg=\"services\">Services</button></nav>",
	    app.tab == TAB_JAILS ? " on" : "", app.tab == TAB_SERVICES ?
	    " on" : "");
	if (app.tab == TAB_SERVICES) {
		view_services(h, s);
		h_raw(h, "</main>");
		return;
	}
	if (s->list != NULL && ucl_array_size(jget(s->list,
	    "conf_errors")) > 0) {
		h_raw(h, "<div class=\"notice warn\"><b>Configuration "
		    "problems</b> (from jail(8) -e)<ul>");
		it = NULL;
		while ((e = ucl_object_iterate(jget(s->list, "conf_errors"),
		    &it, true)) != NULL) {
			h_raw(h, "<li><code>");
			h_txt(h, jstr(e, "scope"));
			h_raw(h, "</code><pre>");
			h_txt(h, jstr(e, "message"));
			h_raw(h, "</pre></li>");
		}
		h_raw(h, "</ul></div>");
	}
	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" "
	    "id=\"filter\" data-input=\"filter\" placeholder=\"Filter jails\" "
	    "autocomplete=\"off\" spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_fmt(h, "><span class=\"tally\"><b class=\"c-run\">%d</b> running · "
	    "<b>%d</b> stopped · <b>%d</b> total</span></div>",
	    count_state(s, "running"), count_state(s, "stopped"),
	    count_state(s, NULL));
	if (s->list == NULL) {
		h_raw(h, s->failed ? "<div class=\"empty\"><h2>No data</h2>"
		    "<p>The host has not answered yet.</p></div>" :
		    "<div class=\"empty\"><div class=\"loader\"></div></div>");
		h_raw(h, "</main>");
		return;
	}
	h_fmt(h, "<div class=\"grid%s\">", stale(s) ? " is-stale" : "");
	shown = 0;
	it = NULL;
	while ((j = ucl_object_iterate(jget(s->list, "jails"), &it,
	    true)) != NULL) {
		/* A jail is known by its name. */
		if (jstr(j, "name") == NULL || (app.filter[0] != '\0' &&
		    strstr(jstr(j, "name"), app.filter) == NULL))
			continue;
		card(h, s, j);
		shown++;
	}
	h_raw(h, "</div>");
	if (shown == 0)
		h_raw(h, app.filter[0] != '\0' ? "<div class=\"empty\"><p>"
		    "Nothing matches the filter.</p></div>" :
		    "<div class=\"empty\"><h2>No jails</h2><p>Nothing is "
		    "running and nothing is configured in jail.conf or "
		    "jail.conf.d.</p></div>");
	h_raw(h, "</main>");
}

static void
drawer(struct html *h)
{
	const ucl_object_t	*j, *p, *v;
	ucl_object_iter_t	 it, vit;
	struct server		*s;
	struct jailui		*u;
	const char		*cls, *keys[] = { "ip4", "ip6" };
	char			 buf[64], *jv;
	int			 i, k;

	s = cur_server();
	if (app.jail[0] == '\0' || s == NULL ||
	    (j = find_jail(s, app.jail)) == NULL) {
		h_raw(h, "<aside class=\"drawer\"></aside>");
		return;
	}
	u = jailui(s, app.jail);
	cls = state_class(s, j, u);
	h_fmt(h, "<aside class=\"drawer open s-%s\"><header>"
	    "<i class=\"led\"></i><h2>", cls);
	h_txt(h, app.jail);
	h_raw(h, "</h2><span class=\"state\">");
	h_txt(h, cls);
	h_raw(h, "</span><button class=\"icon\" data-act=\"close-drawer\" "
	    "title=\"Close\">×</button></header><div class=\"drawer-body\">");
	actions(h, s, j, u, true);
	if (u->error[0] != '\0') {
		h_raw(h, "<p class=\"err\">");
		h_txt(h, u->error);
		h_raw(h, "</p>");
	}

	h_raw(h, "<h4>Addresses</h4><ul class=\"chips\">");
	for (k = 0; k < 2; k++) {
		it = NULL;
		while ((v = ucl_object_iterate(jget(j, keys[k]), &it,
		    true)) != NULL) {
			h_raw(h, "<li class=\"chip\"><span>");
			h_txt(h, ucl_object_tostring(v));
			h_raw(h, "</span><button class=\"icon\" "
			    "data-act=\"address-remove\" title=\"Remove\"");
			h_attr(h, "data-arg", app.jail);
			h_attr(h, "data-value", ucl_object_tostring(v));
			h_raw(h, ">×</button></li>");
		}
	}
	h_raw(h, "<li><button class=\"ghost small\" data-act=\"address-add\"");
	h_attr(h, "data-arg", app.jail);
	h_raw(h, ">+ address</button></li></ul>");

	h_raw(h, "<h4>Jail</h4><dl class=\"kv\">");
	if (jget(j, "jid") != NULL && ucl_object_type(jget(j, "jid")) ==
	    UCL_INT) {
		snprintf(buf, sizeof(buf), "%lld", (long long)jint(j, "jid",
		    0));
		h_raw(h, "<dt>jid</dt><dd>");
		h_txt(h, buf);
		h_raw(h, "</dd>");
	}
	{
		static const char *fields[] = { "hostname", "path",
		    "osrelease", "interface", "scope" };

		for (i = 0; i < 5; i++) {
			if (jstr(j, fields[i]) == NULL)
				continue;
			h_raw(h, "<dt>");
			h_txt(h, fields[i]);
			h_raw(h, "</dt><dd class=\"mono\">");
			h_txt(h, jstr(j, fields[i]));
			h_raw(h, "</dd>");
		}
	}
	h_fmt(h, "<dt>vnet</dt><dd>%s</dd><dt>persist</dt><dd>%s</dd>",
	    jbool(j, "vnet") ? "yes" : "no", jbool(j, "persist") ? "yes" :
	    "no");
	h_raw(h, "</dl>");

	if (ucl_array_size(jget(j, "params")) > 0) {
		h_raw(h, "<h4>Configuration <span class=\"dim\">as jail(8) "
		    "reads it</span></h4><table class=\"params\">");
		it = NULL;
		while ((p = ucl_object_iterate(jget(j, "params"), &it,
		    true)) != NULL) {
			h_raw(h, "<tr><th>");
			h_txt(h, jstr(p, "key"));
			h_raw(h, "</th><td>");
			vit = NULL;
			while ((v = ucl_object_iterate(jget(p, "values"), &vit,
			    true)) != NULL) {
				jv = (char *)(uintptr_t)ucl_object_tostring(v);
				h_raw(h, "<code>");
				h_txt(h, jv);
				h_raw(h, "</code>");
			}
			h_raw(h, "</td></tr>");
		}
		h_raw(h, "</table>");
	}

	h_raw(h, "<h4>History</h4><ul class=\"history\">");
	k = 0;
	for (i = 0; i < app.nops; i++) {
		const char *t = app.ops[i].title;
		size_t tl = strlen(t), jl = strlen(app.jail);

		if (tl < jl || strstr(t, app.jail) == NULL)
			continue;
		h_fmt(h, "<li class=\"op o-%s\" data-act=\"trace\" "
		    "data-arg=\"%d\">", app.ops[i].state == OP_RUNNING ?
		    "running" : app.ops[i].state == OP_OK ? "ok" : "failed",
		    app.ops[i].id);
		h_raw(h, "<i class=\"led\"></i>");
		h_txt(h, t);
		h_raw(h, "</li>");
		k++;
	}
	if (k == 0)
		h_raw(h, "<li class=\"dim\">Nothing done from here yet.</li>");
	h_raw(h, "</ul></div></aside>");
}

static void
dock(struct html *h)
{
	const struct op	*o;
	char		 dur[32];
	int		 i;

	h_fmt(h, "<section class=\"dock%s\"><header data-act=\"dock\">"
	    "<span class=\"label\">Activity</span>", app.dock_open ?
	    " open" : "");
	if (app.nops > 0) {
		o = &app.ops[0];
		h_fmt(h, "<span class=\"last o-%s\"><i class=\"led\"></i>",
		    o->state == OP_RUNNING ? "running" : o->state == OP_OK ?
		    "ok" : "failed");
		h_txt(h, o->title);
		h_raw(h, "</span>");
	}
	h_fmt(h, "<span class=\"chev\">%s</span></header>",
	    app.dock_open ? "▾" : "▴");
	if (app.dock_open) {
		h_raw(h, "<div class=\"dock-body\"><ol class=\"ops\">");
		for (i = 0; i < app.nops; i++) {
			o = &app.ops[i];
			h_fmt(h, "<li class=\"op o-%s%s\" data-act=\"trace\" "
			    "data-arg=\"%d\"><i class=\"led\"></i>",
			    o->state == OP_RUNNING ? "running" :
			    o->state == OP_OK ? "ok" : "failed",
			    o->id == app.trace_op ? " selected" : "", o->id);
			h_raw(h, "<span class=\"t\">");
			h_txt(h, o->title);
			h_raw(h, "</span><span class=\"s\">");
			h_txt(h, o->server);
			h_raw(h, "</span>");
			if (o->state != OP_RUNNING) {
				fmt_dur(dur, sizeof(dur), (int64_t)
				    ((o->finished - o->started) * 1000));
				h_raw(h, "<span class=\"d\">");
				h_txt(h, dur);
				h_raw(h, "</span>");
			}
			h_raw(h, "</li>");
		}
		if (app.nops == 0)
			h_raw(h, "<li class=\"dim\">Actions and manual "
			    "refreshes show up here with what they ran.</li>");
		h_raw(h, "</ol><div class=\"trace-pane\">");
		if ((o = op_find(app.trace_op)) != NULL)
			view_trace(h, o);
		else
			h_raw(h, "<div class=\"empty small\"><p>Pick an entry "
			    "to see its workflow: every library call, system "
			    "call and program behind it.</p></div>");
		h_raw(h, "</div></div>");
	}
	h_raw(h, "</section>");
}

static void
modal(struct html *h)
{
	struct confirm	*c;
	const ucl_object_t *k;
	ucl_object_iter_t it;
	bool		 add;

	if (app.modal == MODAL_NONE)
		return;
	h_raw(h, "<div class=\"scrim\" data-act=\"close\"></div>"
	    "<div class=\"modal\" role=\"dialog\" aria-modal=\"true\">");
	switch (app.modal) {
	case MODAL_CONFIRM:
		c = &app.confirm;
		h_fmt(h, "<form data-form=\"confirm\" class=\"%s\"><h2>",
		    c->danger ? "danger" : "");
		h_txt(h, c->title);
		h_raw(h, "</h2><p>");
		h_txt(h, c->body);
		h_raw(h, "</p>");
		if (c->typed[0] != '\0') {
			h_raw(h, "<label>Type <code>");
			h_txt(h, c->typed);
			h_raw(h, "</code> to confirm<input name=\"typed\" "
			    "autocomplete=\"off\" spellcheck=\"false\" "
			    "autofocus></label>");
		}
		break;
	case MODAL_ADD_SERVER:
		h_raw(h, "<form data-form=\"add-server\"><h2>Add a server</h2>"
		    "<p>A host running <code>jailgridd(8)</code>. Over TCP the "
		    "console uses the client certificate from its "
		    "<code>web.conf</code>.</p>"
		    "<label>Name<input name=\"name\" required maxlength=\"64\" "
		    "placeholder=\"lab\" autofocus></label>"
		    "<label>Address<input name=\"uri\" required "
		    "placeholder=\"tcp://host.example:4310\" "
		    "spellcheck=\"false\"></label>"
		    "<label>Certificate name <span class=\"dim\">if not the "
		    "host above</span><input name=\"peer\" "
		    "spellcheck=\"false\"></label>"
		    "<p class=\"dim\">No certificate yet? <a href=\"#\" "
		    "data-act=\"enrol\">Enrol the host</a> and the console "
		    "issues one.</p>");
		break;
	case MODAL_ENROL:
		h_raw(h, "<form data-form=\"enrol-host\"><h2>Enrol a host</h2>"
		    "<p>The console makes a one-time token; "
		    "<code>jailgrid-enrol(8)</code> on the host turns it into a "
		    "certificate from the console's CA, starts "
		    "<code>jailgridd(8)</code> with <code>-s</code>, and the host "
		    "appears here.</p>"
		    "<label>Name<input name=\"name\" required maxlength=\"64\" "
		    "placeholder=\"lab\" autofocus></label>"
		    "<label>Host name or address <span class=\"dim\">as the "
		    "console reaches it</span><input name=\"host\" required "
		    "placeholder=\"host1.example\" spellcheck=\"false\">"
		    "</label>");
		if (app.enrol_cmd[0] != '\0') {
			h_raw(h, "<p>Run as root on the host, within an hour:"
			    "</p><pre class=\"diff\">");
			h_txt(h, app.enrol_cmd);
			h_raw(h, " -s</pre>");
		}
		break;
	case MODAL_ADDRESS:
		add = strcmp(app.confirm.act, "add") == 0;
		h_raw(h, "<form data-form=\"address\"><h2>");
		h_raw(h, add ? "Add an address to " :
		    "Remove an address from ");
		h_txt(h, app.jail);
		h_raw(h, "</h2>");
		h_fmt(h, "<input type=\"hidden\" name=\"mode\" value=\"%s\">",
		    add ? "add" : "remove");
		h_raw(h, "<label>Address<input name=\"address\" "
		    "spellcheck=\"false\" placeholder=\"10.0.0.5/24\"");
		h_attr(h, "value", app.confirm.value);
		h_raw(h, add ? " autofocus" : " readonly");
		h_raw(h, "></label><fieldset class=\"toggles\">"
		    "<label class=\"toggle\"><input type=\"checkbox\" "
		    "name=\"live\" checked><span>Live <em>jail_setv(3) and "
		    "the interface alias, now</em></span></label>"
		    "<label class=\"toggle\"><input type=\"checkbox\" "
		    "name=\"persist\"><span>Persistent <em>edit the jail's "
		    "block in its jail.conf, in place</em></span></label>"
		    "</fieldset>");
		if (app.preview != NULL) {
			h_raw(h, "<pre class=\"diff\">");
			h_txt(h, app.preview);
			h_raw(h, "</pre>");
		}
		break;
	case MODAL_KEYS:
		h_raw(h, "<form data-form=\"add-key\"><h2>Security keys</h2>"
		    "<ul class=\"keys\">");
		it = NULL;
		while ((k = ucl_object_iterate(app.keys, &it, true)) != NULL) {
			char when[32];

			h_raw(h, "<li><span class=\"name\">");
			h_txt(h, jstr(k, "name"));
			h_raw(h, "</span><span class=\"dim\">");
			h_txt(h, jint(k, "alg", 0) == -8 ? "Ed25519" :
			    jint(k, "alg", 0) == -7 ? "ES256" : "RS256");
			if (jget(k, "last_used") != NULL) {
				fmt_age(when, sizeof(when),
				    jint(k, "last_used", 0) * 1000.0);
				h_raw(h, " · used ");
				h_txt(h, when);
			}
			h_raw(h, "</span><button type=\"button\" "
			    "class=\"icon\" data-act=\"delete-key\" "
			    "title=\"Remove\"");
			h_attr(h, "data-arg", jstr(k, "id"));
			h_raw(h, ">×</button></li>");
		}
		h_raw(h, "</ul><p class=\"dim\">A spare security key, or a "
		    "passkey: open the console on the phone, log in here once, "
		    "and register from there.</p><label>Add a spare key<input "
		    "name=\"name\" placeholder=\"Spare YubiKey, or Pixel\" "
		    "maxlength=\"64\"></label>");
		break;
	case MODAL_RAW:
		view_trace(h, NULL);
		break;
	default:
		break;
	}
	if (app.modal != MODAL_RAW) {
		if (app.modal_error[0] != '\0') {
			h_raw(h, "<p class=\"err\">");
			h_txt(h, app.modal_error);
			h_raw(h, "</p>");
		}
		h_raw(h, "<div class=\"buttons\"><button type=\"button\" "
		    "class=\"ghost\" data-act=\"close\">Cancel</button>");
		switch (app.modal) {
		case MODAL_CONFIRM:
			h_fmt(h, "<button class=\"%s\">",
			    app.confirm.danger ? "danger" : "primary");
			h_txt(h, app.confirm.button);
			h_raw(h, "</button>");
			break;
		case MODAL_ADD_SERVER:
			h_fmt(h, "<button class=\"primary\"%s>Add</button>",
			    app.modal_busy ? " disabled" : "");
			break;
		case MODAL_ENROL:
			h_fmt(h, "<button class=\"primary\"%s>%s</button>",
			    app.modal_busy ? " disabled" : "",
			    app.enrol_cmd[0] != '\0' ? "New token" :
			    "Make a token");
			break;
		case MODAL_ADDRESS:
			h_fmt(h, "<button class=\"ghost\" value=\"preview\"%s>"
			    "Preview</button><button class=\"primary\" "
			    "value=\"apply\"%s>Apply</button>",
			    app.modal_busy ? " disabled" : "",
			    app.modal_busy ? " disabled" : "");
			break;
		case MODAL_KEYS:
			h_fmt(h, "<button class=\"primary\"%s>Register "
			    "key</button>", app.modal_busy ? " disabled" : "");
			break;
		default:
			break;
		}
		h_raw(h, "</div></form>");
	}
	h_raw(h, "</div>");
}

static void
toasts(struct html *h)
{
	int	i;

	h_raw(h, "<div class=\"toasts\" aria-live=\"polite\">");
	for (i = 0; i < app.ntoasts; i++) {
		h_fmt(h, "<div class=\"toast%s\" data-act=\"toast\" "
		    "data-arg=\"%d\">", app.toasts[i].error ? " bad" : "", i);
		h_txt(h, app.toasts[i].text);
		h_raw(h, "</div>");
	}
	h_raw(h, "</div>");
}

static void
auth_screen(struct html *h)
{

	h_raw(h, "<div class=\"auth\"><div class=\"panel\">"
	    "<div class=\"brand big\"><span class=\"logo\">");
	h_raw(h, icon_grid);
	h_raw(h, "</span><span class=\"wordmark\">JAILGRID</span></div>"
	    "<p class=\"sub\">FreeBSD jail console</p>");
	if (app.screen == SCREEN_BOOT) {
		h_raw(h, "<div class=\"loader\"></div>");
	} else if (app.screen == SCREEN_OFFLINE) {
		h_raw(h, "<div class=\"offline\"><h2>");
		h_raw(h, app.online ? "The console does not answer" :
		    "Offline");
		h_raw(h, "</h2><p>The console app is on this device and "
		    "works without a network, but jail data comes only from "
		    "the console, live. It reconnects by itself.</p>"
		    "<button class=\"ghost\" data-act=\"retry\">Try "
		    "again</button></div>");
	} else if (app.screen == SCREEN_ENROL) {
		h_raw(h, "<form data-form=\"enrol\" class=\"enrol\">"
		    "<p>No security key is registered yet. The console wrote a "
		    "one-time setup token to <code>setup-token</code> in its "
		    "data directory; paste it here, then touch your key.</p>"
		    "<label>Setup token<input name=\"token\" required "
		    "autocomplete=\"off\" spellcheck=\"false\" autofocus>"
		    "</label><label>Key name<input name=\"name\" "
		    "placeholder=\"YubiKey 5C\" maxlength=\"64\"></label>");
		h_fmt(h, "<button class=\"primary\"%s>%s</button></form>",
		    app.auth_busy ? " disabled" : "", app.auth_busy ?
		    "Touch your key…" : "Register security key");
	} else {
		h_fmt(h, "<div class=\"key%s\">", app.auth_busy ? " pulse" :
		    "");
		h_raw(h, icon_key);
		h_fmt(h, "</div><button class=\"primary\" data-act=\"login\""
		    "%s>%s</button>", app.auth_busy ? " disabled" : "",
		    app.auth_busy ? "Touch your key…" : "Log in with your "
		    "security key");
		h_fmt(h, "<button class=\"ghost\" data-act=\"login-passkey\"%s "
		    "title=\"A passkey on this device, or on a phone nearby\">"
		    "Use a passkey</button>", app.auth_busy ? " disabled" : "");
	}
	if (app.auth_error[0] != '\0') {
		h_raw(h, "<p class=\"err\">");
		h_txt(h, app.auth_error);
		h_raw(h, "</p>");
	}
	h_raw(h, "</div></div>");
}

void
view(struct html *h)
{

	if (app.screen != SCREEN_CONSOLE) {
		auth_screen(h);
		toasts(h);
		return;
	}
	h_raw(h, "<div class=\"shell\">");
	topbar(h);
	banner(h);
	h_fmt(h, "<div class=\"body%s\">", (app.tab == TAB_JAILS ?
	    app.jail[0] : app.service[0]) != '\0' ? " with-drawer" : "");
	rail(h);
	stage(h);
	if (app.tab == TAB_SERVICES)
		view_service_drawer(h, cur_server());
	else
		drawer(h);
	h_raw(h, "</div>");
	dock(h);
	h_raw(h, "</div>");
	modal(h);
	toasts(h);
}

/* One rc.d service as a row. */
static void
service_row(struct html *h, const ucl_object_t *sv)
{
	const ucl_object_t	*en, *run;
	const char		*name, *state;
	bool			 enabled, running, known, busy;

	name = jstr(sv, "name");
	en = jget(sv, "enabled");
	run = jget(sv, "running");
	enabled = en != NULL && ucl_object_type(en) == UCL_BOOLEAN &&
	    ucl_object_toboolean(en);
	known = run != NULL && ucl_object_type(run) == UCL_BOOLEAN;
	running = known && ucl_object_toboolean(run);
	state = !known ? "unknown" : running ? "running" : "stopped";
	busy = strcmp(app.service_busy, name) == 0;
	h_fmt(h, "<li class=\"svc s-%s%s%s\"", state, enabled ? " enabled" : "",
	    strcmp(app.service, name) == 0 ? " open" : "");
	h_raw(h, " data-act=\"open-svc\"");
	h_attr(h, "data-arg", name);
	h_raw(h, "><i class=\"led\"></i><span class=\"name\">");
	h_txt(h, name);
	h_raw(h, "</span><span class=\"flags\">");
	h_raw(h, enabled ? "<b class=\"on\">enabled</b>" : "<b>disabled</b>");
	if (known) {
		h_raw(h, running ? " <b class=\"on\">running" : " <b>stopped");
		if (jget(sv, "pid") != NULL && ucl_object_type(jget(sv,
		    "pid")) == UCL_INT)
			h_fmt(h, " · pid %lld", (long long)jint(sv, "pid", 0));
		h_raw(h, "</b>");
	}
	h_raw(h, "</span><span class=\"acts\">");
	if (known && !running)
		h_fmt(h, "<button class=\"act go\" data-act=\"svc\" "
		    "data-value=\"start\"%s", busy ? " disabled" : "");
	else
		h_fmt(h, "<button class=\"act\" data-act=\"svc\" "
		    "data-value=\"stop\"%s", busy ? " disabled" : "");
	h_attr(h, "data-arg", name);
	h_raw(h, known && !running ? ">Start</button>" : ">Stop</button>");
	h_fmt(h, "<button class=\"act\" data-act=\"svc\" data-value=\"restart\""
	    "%s", busy ? " disabled" : "");
	h_attr(h, "data-arg", name);
	h_raw(h, ">Restart</button>");
	h_fmt(h, "<button class=\"act\" data-act=\"svc\" data-value=\"%s\"%s",
	    enabled ? "disable" : "enable", busy ? " disabled" : "");
	h_attr(h, "data-arg", name);
	h_raw(h, enabled ? ">Disable</button>" : ">Enable</button>");
	h_raw(h, "</span></li>");
}

/* The services tab: the rc.d scripts of the server. */
void
view_services(struct html *h, struct server *s)
{
	const ucl_object_t	*sv;
	ucl_object_iter_t	 it;
	char			 age[32];
	int			 shown, n, en, run;

	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\"filter\" "
	    "data-input=\"filter\" placeholder=\"Filter services\" "
	    "autocomplete=\"off\" spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, ">");
	if (s->services != NULL) {
		n = en = run = 0;
		it = NULL;
		while ((sv = ucl_object_iterate(jget(s->services, "services"),
		    &it, true)) != NULL) {
			n++;
			if (jbool(sv, "enabled"))
				en++;
			if (jbool(sv, "running"))
				run++;
		}
		fmt_age(age, sizeof(age), s->services_fetched);
		h_fmt(h, "<span class=\"tally\"><b class=\"c-run\">%d</b> running "
		    "· <b>%d</b> enabled · <b>%d</b> scripts · ", run, en, n);
		h_txt(h, age);
		h_raw(h, "</span>");
	}
	h_raw(h, "</div>");
	if (s->services_error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, s->services_error);
		h_raw(h, "</div>");
	}
	if (s->services == NULL) {
		h_raw(h, s->services_loading ? "<div class=\"empty\"><div "
		    "class=\"loader\"></div><p class=\"dim\">service(8) is "
		    "asking every enabled script for its status…</p></div>" :
		    "<div class=\"empty\"><h2>No data</h2><p>The host has not "
		    "answered yet.</p></div>");
		return;
	}
	h_raw(h, "<ul class=\"services\">");
	shown = 0;
	it = NULL;
	while ((sv = ucl_object_iterate(jget(s->services, "services"), &it,
	    true)) != NULL) {
		if (jstr(sv, "name") == NULL || (app.filter[0] != '\0' &&
		    strstr(jstr(sv, "name"), app.filter) == NULL))
			continue;
		service_row(h, sv);
		shown++;
	}
	h_raw(h, "</ul>");
	if (shown == 0)
		h_raw(h, "<div class=\"empty\"><p>Nothing matches.</p></div>");
}

/* The drawer of the open service: its rc.conf variables, editable. */
void
view_service_drawer(struct html *h, struct server *s)
{
	const ucl_object_t	*sv, *vars, *v, *c;
	ucl_object_iter_t	 it;
	const char		*name;
	char			 fname[160];

	name = app.service;
	if (name[0] == '\0' || s == NULL) {
		h_raw(h, "<aside class=\"drawer\"></aside>");
		return;
	}
	sv = app.svc_config != NULL ? jget(app.svc_config, "service") : NULL;
	h_fmt(h, "<aside class=\"drawer open s-%s\"><header><i class=\"led\">"
	    "</i><h2>", sv == NULL ? "unknown" : jbool(sv, "running") ?
	    "running" : "stopped");
	h_txt(h, name);
	h_raw(h, "</h2><span class=\"state\">");
	h_txt(h, sv == NULL ? "" : jbool(sv, "enabled") ? "enabled" :
	    "disabled");
	h_raw(h, "</span><button class=\"icon\" data-act=\"close-drawer\" "
	    "title=\"Close\">×</button></header><div class=\"drawer-body\">");
	if (app.svc_config == NULL) {
		h_raw(h, app.svc_loading ? "<div class=\"loader\"></div>" : "");
		if (app.svc_error[0] != '\0') {
			h_raw(h, "<p class=\"err\">");
			h_txt(h, app.svc_error);
			h_raw(h, "</p>");
		}
		h_raw(h, "</div></aside>");
		return;
	}
	if (jstr(app.svc_config, "description") != NULL) {
		h_raw(h, "<p class=\"dim\">");
		h_txt(h, jstr(app.svc_config, "description"));
		h_raw(h, "</p>");
	}
	if (sv != NULL) {
		h_raw(h, "<dl class=\"kv\"><dt>script</dt><dd class=\"mono\">");
		h_txt(h, jstr(sv, "path"));
		h_raw(h, "</dd>");
		if (jstr(sv, "status") != NULL) {
			h_raw(h, "<dt>status</dt><dd>");
			h_txt(h, jstr(sv, "status"));
			h_raw(h, "</dd>");
		}
		h_raw(h, "</dl>");
	}
	h_raw(h, "<div class=\"actions big\">");
	{
		static const char *verbs[] = { "start", "stop", "restart",
		    "reload", "enable", "disable" };
		size_t i;

		for (i = 0; i < 6; i++) {
			h_fmt(h, "<button class=\"act%s\" data-act=\"svc\" "
			    "data-value=\"%s\"%s", i == 0 ? " go" : "", verbs[i],
			    strcmp(app.service_busy, name) == 0 ? " disabled" :
			    "");
			h_attr(h, "data-arg", name);
			h_raw(h, ">");
			h_txt(h, verbs[i]);
			h_raw(h, "</button>");
		}
	}
	c = jget(app.svc_config, "commands");
	if (ucl_array_size(c) > 0) {
		h_raw(h, "<span class=\"dim\">also: ");
		it = NULL;
		while ((v = ucl_object_iterate(c, &it, true)) != NULL) {
			h_raw(h, "<code>");
			h_txt(h, ucl_object_tostring(v));
			h_raw(h, "</code> ");
		}
		h_raw(h, "</span>");
	}
	h_raw(h, "</div>");
	if (app.svc_error[0] != '\0') {
		h_raw(h, "<p class=\"err\">");
		h_txt(h, app.svc_error);
		h_raw(h, "</p>");
	}

	h_raw(h, "<h4>rc.conf <span class=\"dim\">through sysrc(8)</span></h4>"
	    "<form data-form=\"svc-config\" class=\"vars\">");
	vars = jget(app.svc_config, "variables");
	it = NULL;
	while ((v = ucl_object_iterate(vars, &it, true)) != NULL) {
		snprintf(fname, sizeof(fname), "v:%s", ucl_object_key(v));
		h_raw(h, "<label class=\"var\"><span class=\"mono\">");
		h_txt(h, ucl_object_key(v));
		h_raw(h, "</span><input spellcheck=\"false\"");
		h_attr(h, "name", fname);
		h_attr(h, "value", ucl_object_tostring_forced(v));
		h_raw(h, "><button type=\"button\" class=\"icon\" "
		    "data-act=\"svc-unset\" title=\"Remove from rc.conf\"");
		h_attr(h, "data-arg", ucl_object_key(v));
		h_raw(h, ">×</button></label>");
	}
	h_raw(h, "<label class=\"var new\"><input name=\"key\" "
	    "spellcheck=\"false\"");
	snprintf(fname, sizeof(fname), "%s_…", name);
	h_attr(h, "placeholder", fname);
	h_raw(h, "><input name=\"value\" placeholder=\"value\" "
	    "spellcheck=\"false\"></label>");
	h_fmt(h, "<div class=\"buttons\"><button class=\"primary\"%s>Apply"
	    "</button></div></form></div></aside>", app.svc_loading ?
	    " disabled" : "");
}
