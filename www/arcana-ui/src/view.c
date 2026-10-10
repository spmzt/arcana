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
#include <time.h>

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
/* The tree's own nodes, and its head's buttons: drawn, not glyphs a
 * face may lack. */
#define	TREE_ICON(d)	"<svg class=\"ti\" viewBox=\"0 0 24 24\" " \
    "aria-hidden=\"true\"><path d=\"" d "\"/></svg>"
static const char *icon_hosts = TREE_ICON("M4 5h16v5H4zM4 14h16v5H4zM7 "
    "7.5h.01M7 16.5h.01");
static const char *icon_network = TREE_ICON("M12 4v6M12 10l-6 7M12 10l6 "
    "7M10 2h4v4h-4zM4 17h4v4H4zM16 17h4v4h-4z");
static const char *icon_usage = TREE_ICON("M3 12h4l3-7 4 14 3-7h4");
static const char *icon_flows = TREE_ICON("M6 3v12M18 9a3 3 0 1 0 0-6 3 3 "
    "0 0 0 0 6zM6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM18 9a9 9 0 0 1-9 9");
static const char *icon_sdwan = TREE_ICON("M5 7a2 2 0 1 0 0-.01M19 7a2 2 0 "
    "1 0 0-.01M12 19a2 2 0 1 0 0-.01M7 7h10M6 9l5 8M18 9l-5 8");
static const char *icon_gear = TREE_ICON("M12 15a3 3 0 1 0 0-6 3 3 0 0 0 "
    "0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 "
    "1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 "
    "0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 "
    "0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 "
    "1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 "
    "0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 "
    "1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 "
    "0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 "
    "1z");
static const char *icon_enrol = TREE_ICON("M9 15l6-6M11 6l1-1a4 4 0 0 1 6 "
    "6l-1 1M13 18l-1 1a4 4 0 0 1-6-6l1-1");
static const char *icon_plus = TREE_ICON("M12 5v14M5 12h14");

static void	topbar(struct html *);
static void	view_settings(struct html *);
static void	banner(struct html *);
static void	install_offer(struct html *);
static void	rail(struct html *);
static void	stage(struct html *);
static void	hostbar(struct html *, struct server *);
static void	card(struct html *, struct server *, const ucl_object_t *);
static void	jail_page(struct html *);
static void	peek_box(struct html *);
static void	actions(struct html *, struct server *, const ucl_object_t *,
		    const struct jailui *, bool);
static void	dock(struct html *);
static void	modal(struct html *);
static void	toasts(struct html *);
static void	auth_screen(struct html *);
static void	fmt_kb(char *, size_t, int64_t);
static int	count_state(const struct server *, const char *);
static void	tree_caps(int *);
static bool	stale(const struct server *);

void
fmt_age(char *buf, size_t len, double ms)
{
	double	s;

	s = (arc_now() - ms) / 1000;
	if (s < 15)
		snprintf(buf, len, "just now");
	else if (s < 60)
		snprintf(buf, len, "%.0fs ago", s - (double)((int)s % 10));
	else if (s < 3600)
		snprintf(buf, len, "%.0fm ago", s / 60);
	else if (s < 172800)
		snprintf(buf, len, "%.1fh ago", s / 3600);
	else
		snprintf(buf, len, "%.0fd ago", s / 86400);
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
	    arc_now() - s->fetched > STALE_MS));
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

	/* The API's light is also the way to the API's own page. */
	h_fmt(h, "<span class=\"link %s%s\"%s", l == LINK_UP ? "up" :
	    l == LINK_DOWN ? "down" : "unknown", strcmp(name, "API") == 0 ?
	    app.node == NODE_API ? " go on" : " go" : "", strcmp(name,
	    "API") == 0 ? " data-act=\"select-api\" role=\"button\"" : "");
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
	h_raw(h, "<header class=\"topbar\"><button class=\"ghost burger\" "
	    "data-act=\"rail-toggle\" title=\"Hosts and jails\" aria-label=\""
	    "Hosts and jails\">☰</button><div class=\"brand\">"
	    "<span class=\"logo\">");
	h_raw(h, icon_grid);
	h_raw(h, "</span><span class=\"wordmark\">ARCANA</span>");
	if (app.version[0] != '\0') {
		h_raw(h, "<span class=\"version\" title=\"The console's "
		    "version\">");
		h_txt(h, app.version);
		h_raw(h, "</span>");
	}
	h_raw(h, "</div><nav class=\"crumbs\">");
	if (app.node == NODE_NETWORK || app.node == NODE_FLEET || app.node ==
	    NODE_API || app.node == NODE_USAGE || app.node == NODE_WORKFLOWS ||
	    app.node == NODE_SDWAN || app.node == NODE_SETTINGS)
		h_fmt(h, "<span class=\"crumb place\">%s</span>", app.node ==
		    NODE_NETWORK ? "Network" : app.node == NODE_API ? "API" :
		    app.node == NODE_USAGE ? "Utilization" : app.node ==
		    NODE_WORKFLOWS ? "Workflows" : app.node == NODE_SDWAN ?
		    "SD-WAN" : app.node == NODE_SETTINGS ? "Settings" :
		    "All hosts");
	else if (s != NULL) {
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
	    "The console answers. Its API, as it is documented: press" :
	    app.api == LINK_DOWN ? "The console does not answer. Its API, as "
	    "it is documented: press" : "Not checked yet. The console's API, "
	    "as it is documented: press");
	host = s == NULL || (s->list == NULL && !s->failed) ? LINK_UNKNOWN :
	    s->failed ? LINK_DOWN : LINK_UP;
	link_led(h, "HOST", host, s == NULL ? "No server selected" :
	    s->failed ? s->error : "arcana-agent answers");
	h_fmt(h, "</div><button class=\"ghost more%s\" data-act=\"who-toggle\" "
	    "title=\"Notifications, log out\" aria-label=\"Menu\"><svg class=\"ti\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M12 5h.01M12 12h.01M12 19h.01\"/></svg></button>"
	    "<div class=\"who%s\">", app.who_open ? " on" : "", app.who_open ?
	    " open" : "");
	if (app.notify != 3)
		h_fmt(h, "<button class=\"ghost%s\" data-act=\"notify\" title=\""
		    "Notify when a task that took more than ten seconds "
		    "ends: %s\">Notify</button>", app.notify == 1 &&
		    !app.notify_off ? " on" : "", app.notify == 1 ?
		    app.notify_off ? "off, press to turn on" : "on, press to "
		    "turn off" : app.notify == 2 ? "blocked in the browser's "
		    "settings" : "off, press to allow");
	h_raw(h, "<button class=\"ghost\" data-act=\"logout\">Log out</button>"
	    "</div></header>");
}

/*
 * On a phone or tablet with the console open in the browser: offer to
 * install it as an app, with the browser's prompt where it has one and
 * the way through its menus where it does not.
 */
static void
install_offer(struct html *h)
{

	if (app.install == 0)
		return;
	h_raw(h, "<div class=\"banner info install\"><span><b>Install "
	    "Arcana on this device.</b> ");
	if (app.install == 1)
		h_raw(h, "It opens full screen from the home screen, like an "
		    "app.");
	else if (app.install == 2)
		h_raw(h, "In Safari, tap Share, then <q>Add to Home Screen"
		    "</q>.");
	else
		h_raw(h, "In the browser's menu, tap <q>Add app to Home screen"
		    "</q>.");
	h_raw(h, "</span>");
	if (app.install == 1)
		h_raw(h, "<button class=\"primary\" data-act=\"install\">"
		    "Install</button>");
	h_raw(h, "<button class=\"ghost\" data-act=\"install-dismiss\" "
	    "title=\"Do not offer again in this browser\">Not now</button>"
	    "</div>");
}

static void
banner(struct html *h)
{

	install_offer(h);

	if (!app.online)
		h_raw(h, "<div class=\"banner warn\"><b>Offline.</b> The "
		    "console itself is cached on this device; jail data is "
		    "not, and what is shown is the last known state.</div>");
	else if (app.api == LINK_DOWN)
		h_raw(h, "<div class=\"banner bad\"><b>The console does not "
		    "answer.</b> Showing the last known state; it will "
		    "reconnect by itself.</div>");
	else if (app.update_latest[0] != '\0') {
		h_raw(h, "<div class=\"banner info\"><b>Arcana ");
		h_txt(h, app.update_latest);
		h_raw(h, " is out</b> (this console is ");
		h_txt(h, app.version[0] != '\0' ? app.version : "older");
		h_raw(h, "). In the container: <code>podman auto-update</code>; "
		    "from the package: <code>pkg upgrade arcana</code>; then "
		    "<code>arcana-enrol</code> hosts again only if told so in "
		    "the ");
		if (strncmp(app.update_url, "https://", 8) == 0) {
			h_raw(h, "<a target=\"_blank\" rel=\"noopener\"");
			h_attr(h, "href", app.update_url);
			h_raw(h, ">release notes</a>");
		} else
			h_raw(h, "release notes");
		h_raw(h, ".</div>");
	}
}

/*
 * The resource tree: the fleet, its hosts, and under each host its
 * jails.  What is selected here decides what the stage shows.
 */
/* A handle that drags the edge of a part of the page; bridge.js. */
#define	RESIZER(axis, what)						\
	"<div class=\"resizer " axis "\" data-resize=\"" what "\" "	\
	"title=\"Drag to resize; double-click for the usual size\"></div>"

#define	TREE_MIN	2	/* rows a host with more jails than room gets */

/*
 * How many rows each host's jails get in the tree: all of them while
 * they fit in the room under the hosts, a fair share of it otherwise,
 * what a small host leaves going to the larger ones.  A host shown in
 * full takes its rows first; a folded one takes none.
 */
static void
tree_caps(int *cap)
{
	struct server	*s;
	int		 n[MAX_SERVERS];
	int		 i, room, open, share;
	bool		 again;

	room = arc_tree_room();
	open = 0;
	for (i = 0; i < app.nservers; i++) {
		s = &app.servers[i];
		n[i] = count_state(s, NULL);
		cap[i] = n[i];
		if (n[i] == 0 || arc_open_get(s->id) == 0)
			n[i] = 0;
		else if (s->tree_all) {
			room -= n[i] + 1;
			n[i] = 0;
		} else
			open++;
	}
	if (room < 0 && arc_tree_room() < 0)
		return;			/* not drawn yet: no limit */
	/* Hosts that fit in a share take what they need. */
	do {
		again = false;
		share = open > 0 ? (room > 0 ? room : 0) / open : 0;
		for (i = 0; i < app.nservers; i++)
			if (n[i] > 0 && n[i] <= share) {
				room -= n[i];
				n[i] = 0;
				open--;
				again = true;
			}
	} while (again && open > 0);
	/* The rest get a share each: at least a jail and the "more" row. */
	for (i = 0; i < app.nservers; i++)
		if (n[i] > 0)
			cap[i] = share < TREE_MIN ? TREE_MIN : share;
}

static void
rail(struct html *h)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;
	struct server		*s;
	const char		*cls, *name, *st;
	char			 buf[64];
	int			 cap[MAX_SERVERS];
	int			 i, run, all, idx, sidx, lim;
	bool			 folded, selhere;

	/* The firewall's parts are in the side bar while its tab is shown. */
	if (firewall_rail(h))
		return;
	tree_caps(cap);
	/* On a narrow screen the tree is one line until it is unfolded. */
	s = cur_server();
	if (app.rail_open)
		h_raw(h, "<div class=\"scrim rail-scrim\" data-act=\"rail-toggle\"></div>");
	h_fmt(h, "<aside class=\"rail%s\"><div class=\"rail-head\">"
	    "<button class=\"ghost small rail-toggle\" data-act=\""
	    "rail-toggle\" title=\"Hosts and jails\">%s ", app.rail_open ?
	    " open" : "", app.rail_open ? "▴" : "▾");
	h_txt(h, app.node == NODE_NETWORK ? "Network" : app.node == NODE_API ?
	    "API" : app.node == NODE_USAGE ? "Utilization" : app.node ==
	    NODE_WORKFLOWS ? "Workflows" : app.node == NODE_SDWAN ? "SD-WAN" :
	    app.node == NODE_SETTINGS ? "Settings" : app.node ==
	    NODE_FLEET || s == NULL ? "All hosts" :
	    s->name);
	if (app.node == NODE_JAIL && app.jail[0] != '\0') {
		h_raw(h, " / ");
		h_txt(h, app.jail);
	}
	h_raw(h, "</button>"
	    "<span class=\"label\">Fleet</span>"
	    "<button class=\"icon\" data-act=\"enrol\" title=\"Enrol a host\">");
	h_raw(h, icon_enrol);
	h_raw(h, "</button><button class=\"icon\" data-act=\"add-server\" "
	    "title=\"Add a server\">");
	h_raw(h, icon_plus);
	h_raw(h, "</button></div><ul class=\"tree\">");
	h_fmt(h, "<li class=\"titem fleet%s\" data-act=\"select-fleet\">"
	    "<span class=\"twig\">%s</span><span class=\"name\">All hosts</span>"
	    "<span class=\"count\">%d</span></li>"
	    "<li class=\"titem fleet netnode%s\" data-act=\"select-network\">"
	    "<span class=\"twig\">%s</span><span class=\"name\">Network</span>"
	    "</li><li class=\"titem fleet usagenode%s\" data-act=\""
	    "select-usage\"><span class=\"twig\">%s</span><span class=\"name\">"
	    "Utilization</span></li><li class=\"titem fleet wfnode%s\" "
	    "data-act=\"select-workflows\"><span class=\"twig\">%s</span>"
	    "<span class=\"name\">Workflows</span></li><li class=\"titem fleet "
	    "sdnode%s\" data-act=\"select-sdwan\"><span class=\"twig\">%s"
	    "</span><span class=\"name\">SD-WAN</span></li>", app.node ==
	    NODE_FLEET ? " selected" : "", icon_hosts, app.nservers,
	    app.node == NODE_NETWORK ? " selected" : "", icon_network,
	    app.node == NODE_USAGE ? " selected" : "", icon_usage,
	    app.node == NODE_WORKFLOWS ? " selected" : "", icon_flows,
	    app.node == NODE_SDWAN ? " selected" : "", icon_sdwan);
	for (i = 0; i < app.nservers; i++) {
		s = &app.servers[i];
		run = count_state(s, "running");
		all = count_state(s, NULL);
		cls = s->failed ? "down" : s->list != NULL ? "up" : "unknown";
		h_fmt(h, "<li class=\"titem server %s%s\"", cls, i == app.sel &&
		    app.node == NODE_HOST ? " selected" : "");
		h_raw(h, " data-act=\"select-server\"");
		h_attr(h, "data-arg", s->id);
		h_raw(h, ">");
		folded = arc_open_get(s->id) == 0;
		if (all > 0) {
			h_fmt(h, "<button class=\"icon fold\" data-act=\"fold\" "
			    "title=\"%s its jails\"", folded ? "Show" : "Hide");
			h_attr(h, "data-arg", s->id);
			h_fmt(h, ">%s</button>", folded ? "▸" : "▾");
		}
		h_raw(h, "<i class=\"led\"></i><div class=\"meta\">"
		    "<span class=\"name\">");
		h_txt(h, s->name);
		h_raw(h, "</span>");
		/* The agent beside the console: it builds the agent sent to
		 * the others, and updates the console itself. */
		if (s->local)
			h_raw(h, "<span class=\"chip here\" title=\"The agent on "
			    "the console's own host, by its socket: it builds "
			    "arcana-agent for the others and updates the console "
			    "itself\">console's host</span>");
		h_raw(h, "<span class=\"uri\">");
		h_txt(h, s->uri);
		h_raw(h, "</span>");
		if (s->list != NULL && jstr(s->list, "host.version") != NULL) {
			const char *ver = jstr(s->list, "host.version");

			h_raw(h, agent_outdated(s) ? "<span class=\"ver warn\" "
			    "title=\"Not the console's arcana-agent\">" :
			    "<span class=\"ver\">");
			h_txt(h, ver);
			h_raw(h, "</span>");
		}
		h_raw(h, "</div>");
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
		if (folded)
			continue;
		/*
		 * Its jails, as leaves: as many as there is room for, the
		 * selected one among them, and a row that shows the rest.
		 */
		selhere = i == app.sel && app.node == NODE_JAIL;
		sidx = -1;
		idx = 0;
		it = NULL;
		while (selhere && s->list != NULL && (j = ucl_object_iterate(
		    jget(s->list, "jails"), &it, true)) != NULL) {
			if ((name = jstr(j, "name")) == NULL)
				continue;
			if (strcmp(app.jail, name) == 0)
				sidx = idx;
			idx++;
		}
		lim = all;
		if (!s->tree_all && cap[i] < all) {
			lim = cap[i] - 1;	/* a row is the "more" one */
			if (sidx >= lim)
				lim--;
		}
		idx = 0;
		it = NULL;
		while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
		    "jails"), &it, true)) != NULL) {
			if ((name = jstr(j, "name")) == NULL)
				continue;
			if (idx++ >= lim && idx - 1 != sidx)
				continue;
			st = s->failed ? "unknown" : h_word(jstr(j, "state"),
			    "unknown");
			h_fmt(h, "<li class=\"titem leaf s-%s%s\" "
			    "data-act=\"open-jail\"", st, selhere &&
			    strcmp(app.jail, name) == 0 ? " selected" : "");
			h_attr(h, "data-arg", name);
			h_attr(h, "data-value", s->id);
			h_raw(h, "><i class=\"led\"></i><span class=\"name\">");
			h_txt(h, name);
			h_raw(h, "</span></li>");
		}
		if (s->tree_all || cap[i] < all) {
			h_raw(h, "<li class=\"titem leaf more\" "
			    "data-act=\"tree-more\"");
			h_attr(h, "data-arg", s->id);
			if (s->tree_all)
				h_raw(h, "><span class=\"name\">show fewer"
				    "</span></li>");
			else
				h_fmt(h, "><span class=\"name\">+%d more…"
				    "</span></li>", all - lim - (sidx >= lim ?
				    1 : 0));
		}
	}
	/* At the foot of the side bar: the console's own settings. */
	h_fmt(h, "</ul><ul class=\"tree rail-foot\"><li class=\"titem fleet "
	    "setnode%s\" data-act=\"settings\"><span class=\"twig\">%s"
	    "</span><span class=\"name\">Settings</span>",
	    app.node == NODE_SETTINGS ? " selected" : "", icon_gear);
	/* The console's version, where a phone shows it: the top bar
	 * has no room for it there. */
	if (app.version[0] != '\0') {
		h_raw(h, "<span class=\"ver\" title=\"The console's version\">");
		h_txt(h, app.version);
		h_raw(h, "</span>");
	}
	h_raw(h, "</li></ul>");
	h_raw(h, RESIZER("x", "rail") "</aside>");
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
	h_raw(h, "</h1>");
	if (s->local)
		h_raw(h, "<span class=\"chip here\" title=\"The agent on the "
		    "console's own host, reached by its socket. Besides what "
		    "every agent does, it builds arcana-agent from the "
		    "repository for every host, and Update console builds and "
		    "installs the console itself here\">console's host: builds "
		    "the agent, updates the console</span>");
	h_raw(h, "<div class=\"facts\">");
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
			h_raw(h, "<span class=\"warn\" title=\"arcana-agent is "
			    "not running as root: changes will fail\">"
			    "unprivileged</span>");
		if (jstr(host, "version") != NULL) {
			h_raw(h, agent_outdated(s) ? "<span class=\"warn\" "
			    "title=\"Not the arcana-agent this console has: "
			    "another build, or another version\">arcana-agent " :
			    "<span>arcana-agent ");
			h_txt(h, jstr(host, "version"));
			h_raw(h, "</span>");
		}
	} else {
		h_raw(h, "<span>");
		h_txt(h, s->uri);
		h_raw(h, "</span>");
	}
	h_raw(h, "</div></div>");
	/* What is done to Arcana itself on this host: apart, at the right. */
	h_raw(h, "<div class=\"host-actions\">");
	if (host != NULL && agent_outdated(s)) {
		h_raw(h, "<button class=\"small primary\" "
		    "data-act=\"agent-update\"");
		h_attr(h, "data-arg", s->id);
		h_raw(h, " title=\"Send this host the console's "
		    "arcana-agent\">Update agent</button>");
	}
	if (host != NULL && app.agent_source[0] != '\0') {
		h_raw(h, "<button class=\"ghost small\" "
		    "data-act=\"agent-build\"");
		h_attr(h, "title", app.agent_source);
		h_raw(h, ">Build agent here</button>");
		/* The console's own update: on the host it runs on, which
		 * is the one reached by a local socket. */
		if (strncmp(s->uri, "unix:", 5) == 0) {
			h_raw(h, "<button class=\"ghost small\" "
			    "data-act=\"console-update\"");
			h_attr(h, "title", app.agent_source);
			h_raw(h, ">Update console</button>");
		}
	}
	h_raw(h, "</div><div class=\"freshness\">");
	if (s->list != NULL) {
		fmt_age(age, sizeof(age), s->fetched);
		h_fmt(h, "<span class=\"age%s\">", stale(s) ? " stale" : "");
		h_raw(h, stale(s) ? "stale · " : "");
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

static const char *jail_sorts[] = {
	[JAIL_SORT_RUNNING] = "running",
	[JAIL_SORT_NAME] = "name",
};

/* Jails with those running first, or by name; within a state by name. */
static int
jail_cmp(const void *ap, const void *bp)
{
	const ucl_object_t	*a, *b;
	const char		*sa, *sb;
	int			 run, r;

	a = *(const ucl_object_t *const *)ap;
	b = *(const ucl_object_t *const *)bp;
	sa = jstr(a, "state");
	sb = jstr(b, "state");
	run = (int)(sb != NULL && strcmp(sb, "running") == 0) -
	    (int)(sa != NULL && strcmp(sa, "running") == 0);
	r = strcmp(jstr(a, "name"), jstr(b, "name"));
	if (app.jail_sort == JAIL_SORT_NAME)
		return (app.jail_sort_desc ? -r : r);
	if (app.jail_sort_desc)
		run = -run;
	return (run != 0 ? run : r);
}

/* A jail picked in a graph: in a box over the page it was picked on. */
static void
peek_box(struct html *h)
{

	if (!app.peek || app.jail[0] == '\0')
		return;
	h_raw(h, "<div class=\"scrim peek\" data-act=\"close-drawer\"></div>"
	    "<div class=\"peek-box\" role=\"dialog\" aria-modal=\"true\">");
	jail_page(h);
	h_raw(h, "</div>");
}

static void
stage(struct html *h)
{
	const ucl_object_t	*j, *e;
	ucl_object_iter_t	 it;
	const ucl_object_t	**rows;
	struct server		*s;
	int			 shown, n;

	h_raw(h, "<main class=\"stage\">");
	if (!app.servers_loaded) {
		h_raw(h, "<div class=\"empty\"><div class=\"loader\"></div>"
		    "</div></main>");
		return;
	}
	/* Settings are the console's own: there with no host as well. */
	if (app.node == NODE_SETTINGS) {
		view_settings(h);
		h_raw(h, "</main>");
		return;
	}
	if ((s = cur_server()) == NULL) {
		h_raw(h, "<div class=\"empty\"><h2>No hosts yet</h2>");
		/*
		 * The machine the console runs on is the first host: its
		 * agent is added by itself once it answers, and until then
		 * this says what it waits for.
		 */
		if (strcmp(app.local, "absent") == 0) {
			h_raw(h, "<div class=\"notice info local\"><b>This "
			    "machine</b> is added by itself once its agent "
			    "runs. On it:<pre>service arcana_agent enable\n"
			    "service arcana_agent start</pre>Nothing answers "
			    "on <code>");
			h_txt(h, app.local_agent);
			h_raw(h, "</code> yet. <button class=\"ghost small\" "
			    "data-act=\"servers-again\">Look again</button>"
			    "</div>");
		} else if (strcmp(app.local, "denied") == 0) {
			h_raw(h, "<div class=\"notice warn local\"><b>This "
			    "machine's</b> agent runs, but the console may not "
			    "use its socket <code>");
			h_txt(h, app.local_agent);
			h_raw(h, "</code>. Put the console's user in the "
			    "socket's group, then restart both:<pre>sysrc "
			    "arcana_agent_group=arcana\npw groupmod arcana -m "
			    "arcana\nservice arcana_agent restart\nservice "
			    "arcana_console restart</pre><button class=\"ghost "
			    "small\" data-act=\"servers-again\">Look again"
			    "</button></div>");
		}
		h_raw(h, "<p>Enrol a host running <code>arcana-agent(8)</code>, "
		    "or add one that already has its certificates: "
		    "<code>tcp://host:4310</code>.</p>"
		    "<button class=\"primary\" data-act=\"enrol\">Enrol a host"
		    "</button> <button class=\"ghost\" data-act=\"add-server\">"
		    "Add a server</button></div></main>");
		return;
	}
	if (app.node == NODE_FLEET) {
		view_fleet(h);
		peek_box(h);
		h_raw(h, "</main>");
		return;
	}
	if (app.node == NODE_NETWORK) {
		/* The map first; beside it, what the nexthop groups carry. */
		h_fmt(h, "<div class=\"netsect\"><nav class=\"tabs\"><button "
		    "class=\"tab%s\" data-act=\"netsect-tab\" data-arg=\"map\">"
		    "Map</button><button class=\"tab%s\" data-act=\"netsect-tab\" "
		    "data-arg=\"groups\" title=\"How each route of several next "
		    "hops shares what it sends, as the agents sampled it, at "
		    "both ends\">Nexthop groups</button><button class=\"tab%s\" "
		    "data-act=\"netsect-tab\" data-arg=\"traceroute\" title=\"The "
		    "way from a host to an address, hop by hop, again and again "
		    "as mtr does\">Traceroute</button></nav>",
		    app.netsect == NETSECT_MAP ? " on" : "", app.netsect ==
		    NETSECT_GROUPS ? " on" : "", app.netsect == NETSECT_TRACE ?
		    " on" : "");
		if (app.netsect == NETSECT_GROUPS)
			view_ecmp(h);
		else if (app.netsect == NETSECT_TRACE)
			view_traceroute(h);
		else
			view_netmap(h);
		h_raw(h, "</div></main>");
		return;
	}
	if (app.node == NODE_API) {
		view_apidoc(h);
		h_raw(h, "</main>");
		return;
	}
	if (app.node == NODE_USAGE) {
		view_usage(h);
		h_raw(h, "</main>");
		return;
	}
	if (app.node == NODE_WORKFLOWS) {
		view_workflows(h);
		h_raw(h, "</main>");
		return;
	}
	if (app.node == NODE_SDWAN) {
		view_sdwan(h);
		h_raw(h, "</main>");
		return;
	}
	if (app.node == NODE_JAIL) {
		jail_page(h);
		h_raw(h, "</main>");
		return;
	}
	hostbar(h, s);
	{
		static const struct {
			const char	*arg, *title;
		} tabs[] = {
			{ "summary", "Summary" }, { "jails", "Jails" },
			{ "services", "Services" }, { "network", "Network" },
			{ "firewall", "Firewall" },
			{ "packages", "Packages" }, { "storage", "Storage" },
			{ "kernel", "Kernel" }, { "sysctl", "Sysctl" },
			{ "processes", "Processes" }, { "log", "Log" },
			{ "jobs", "Jobs" },
		};
		/*
		 * A plugin has a tab of its own, on a host that has it or
		 * one of whose vnet jails does: it is what was installed
		 * there, not the base system's.
		 */
		static const struct {
			const char	*arg, *title;
			int		 kind;
		} plugins[] = {
			{ "wireguard", "WireGuard", NET_WIREGUARD },
			{ "bird", "BIRD", NET_BIRD },
			{ "ipsec", "IPsec", NET_IPSEC },
		};
		bool	plug;
		int	t;

		plug = app.tab == TAB_NETWORK && NET_PLUGIN(app.net.kind);
		h_raw(h, "<nav class=\"tabs\">");
		for (t = 0; t < (int)(sizeof(tabs) / sizeof(tabs[0])); t++)
			h_fmt(h, "<button class=\"tab%s\" data-act=\"tab\" "
			    "data-arg=\"%s\">%s</button>", (int)app.tab == t &&
			    !(plug && t == TAB_NETWORK) ? " on" : "", tabs[t].arg,
			    tabs[t].title);
		for (t = 0; t < 3; t++)
			if (plugin_where(s, kind_plugin(plugins[t].kind)) !=
			    NULL)
				h_fmt(h, "<button class=\"tab plugin%s\" "
				    "data-act=\"tab\" data-arg=\"%s\" title=\""
				    "A plugin: installed on this host or a jail "
				    "of it, not the base system's\">%s</button>",
				    plug &&
				    (int)app.net.kind == plugins[t].kind ? " on" :
				    "", plugins[t].arg, plugins[t].title);
		h_raw(h, "</nav>");
	}
	if (app.tab == TAB_SUMMARY) {
		view_summary(h, s);
		view_transport(h, s);
		peek_box(h);
		h_raw(h, "</main>");
		return;
	}
	if (app.tab == TAB_JOBS) {
		view_jobs(h, s);
		h_raw(h, "</main>");
		return;
	}
	if (app.tab == TAB_SERVICES) {
		view_services(h, s);
		h_raw(h, "</main>");
		return;
	}
	if (app.tab == TAB_NETWORK) {
		view_network(h, s);
		h_raw(h, "</main>");
		return;
	}
	if (app.tab == TAB_STORAGE) {
		view_storage(h, s);
		h_raw(h, "</main>");
		return;
	}
	if (app.tab == TAB_KERNEL) {
		view_kernel(h, s);
		h_raw(h, "</main>");
		return;
	}
	if (app.tab == TAB_SYSCTL) {
		view_sysctl(h, s);
		h_raw(h, "</main>");
		return;
	}
	if (app.tab == TAB_PROCESSES) {
		view_procs(h, s);
		h_raw(h, "</main>");
		return;
	}
	if (app.tab == TAB_LOG) {
		view_logs(h, s);
		h_raw(h, "</main>");
		return;
	}
	if (app.tab == TAB_FIREWALL) {
		view_firewall(h, s);
		h_raw(h, "</main>");
		return;
	}
	if (app.tab == TAB_PACKAGES) {
		view_packages(h, s);
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
	    "<b>%d</b> stopped · <b>%d</b> total</span>"
	    "<span class=\"sorts\">Sort", count_state(s, "running"),
	    count_state(s, "stopped"), count_state(s, NULL));
	for (n = 0; n <= JAIL_SORT_NAME; n++)
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"jail-sort\" "
		    "data-arg=\"%s\">%s%s</button>", app.jail_sort == n ?
		    " on" : "", jail_sorts[n], jail_sorts[n],
		    app.jail_sort != n ? "" : app.jail_sort_desc ? " ▴" : " ▾");
	h_raw(h, "</span></div>");
	if (s->list == NULL) {
		h_raw(h, s->failed ? "<div class=\"empty\"><h2>No data</h2>"
		    "<p>The host has not answered yet.</p></div>" :
		    "<div class=\"empty\"><div class=\"loader\"></div></div>");
		h_raw(h, "</main>");
		return;
	}
	/* Those that match, in the order asked for. */
	n = (int)ucl_array_size(jget(s->list, "jails"));
	if ((rows = calloc(n > 0 ? n : 1, sizeof(*rows))) == NULL)
		abort();
	shown = 0;
	it = NULL;
	while ((j = ucl_object_iterate(jget(s->list, "jails"), &it,
	    true)) != NULL) {
		/* A jail is known by its name. */
		if (jstr(j, "name") == NULL || (app.filter[0] != '\0' &&
		    strstr(jstr(j, "name"), app.filter) == NULL))
			continue;
		rows[shown++] = j;
	}
	qsort(rows, shown, sizeof(*rows), jail_cmp);
	h_fmt(h, "<div class=\"grid%s\">", stale(s) ? " is-stale" : "");
	for (n = 0; n < shown; n++)
		card(h, s, rows[n]);
	h_raw(h, "</div>");
	free(rows);
	if (shown == 0)
		h_raw(h, app.filter[0] != '\0' ? "<div class=\"empty\"><p>"
		    "Nothing matches the filter.</p></div>" :
		    "<div class=\"empty\"><h2>No jails</h2><p>Nothing is "
		    "running and nothing is configured in jail.conf or "
		    "jail.conf.d.</p></div>");
	h_raw(h, "</main>");
}

/* The page of the jail selected in the tree. */
static void
jail_page(struct html *h)
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
		h_raw(h, "<div class=\"empty\"><h2>No such jail</h2><p>It is "
		    "neither running nor configured on this host any more."
		    "</p></div>");
		return;
	}
	u = jailui(s, app.jail);
	cls = state_class(s, j, u);
	h_fmt(h, "<section class=\"jail-page s-%s\"><header>"
	    "<i class=\"led\"></i><h1>", cls);
	h_txt(h, app.jail);
	h_raw(h, "</h1><span class=\"state\">");
	h_txt(h, cls);
	h_raw(h, "</span><span class=\"dim\">on ");
	h_txt(h, s->name);
	h_fmt(h, "</span><button class=\"%s\" data-act=\"close-drawer\" "
	    "title=\"%s\">%s</button></header><div class=\"jail-body\">",
	    app.peek ? "icon close" : "ghost small", app.peek ? "Close" :
	    "Back to the host", app.peek ? "×" : "← host");
	actions(h, s, j, u, true);
	if (jstr(j, "state") != NULL && strcmp(jstr(j, "state"),
	    "running") == 0) {
		h_raw(h, "<button class=\"ghost small\" "
		    "data-act=\"jail-packages\"");
		h_attr(h, "data-arg", app.jail);
		h_raw(h, ">Packages of this jail</button>");
	}
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

	/*
	 * A jail with a network of its own: that network is in the host's
	 * Network tab, with the jail picked there, as are its plugins.
	 */
	if (net_jail_ok(j)) {
		h_raw(h, "<p class=\"jail-net\">Its network is its own (vnet), "
		    "read and changed from the host: <button class=\"ghost "
		    "small\" data-act=\"jail-net\"");
		h_attr(h, "data-arg", jstr(j, "name"));
		h_raw(h, ">Open it in the Network tab</button></p>");
	}

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
	h_raw(h, "</ul></div></section>");
}

static void
dock(struct html *h)
{
	const struct op	*o;
	char		 dur[32];
	int		 i;

	h_fmt(h, "<section class=\"dock%s\">%s<header data-act=\"dock\">"
	    "<span class=\"label\">Recent tasks</span><div class=\"recent\">",
	    app.dock_open ? " open" : "", app.dock_open ? RESIZER("y",
	    "dock") : "");
	/*
	 * The last few, always in sight: what each was, on which host,
	 * how it ended and how long it took.  One picked opens below.
	 */
	for (i = 0; i < app.nops && i < 6; i++) {
		o = &app.ops[i];
		h_fmt(h, "<span class=\"last o-%s%s\" data-act=\"trace\" "
		    "data-arg=\"%d\"", o->state == OP_RUNNING ? "running" :
		    o->state == OP_OK ? "ok" : "failed", app.dock_open &&
		    o->id == app.trace_op ? " selected" : "", o->id);
		h_attr(h, "title", o->state == OP_FAILED && o->error[0] !=
		    '\0' ? o->error : o->title);
		h_raw(h, "><i class=\"led\"></i><b>");
		h_txt(h, o->title);
		h_raw(h, "</b><small>");
		h_txt(h, o->server);
		if (o->state == OP_RUNNING)
			h_raw(h, " · running");
		else {
			fmt_dur(dur, sizeof(dur), (int64_t)((o->finished -
			    o->started) * 1000));
			h_fmt(h, " · %s · ", o->state == OP_OK ? "done" :
			    "failed");
			h_txt(h, dur);
		}
		h_raw(h, "</small></span>");
	}
	h_raw(h, "</div>");
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"queue\" title=\""
	    "Changes are held in a queue until you press Run, and sent "
	    "together: the host runs them in order, also when it loses the "
	    "console. Off, a change is sent at once.\">Queue%s</button>",
	    app.queue_on ? " on" : "", app.queue_on ? " on" : " off");
	if (app.nbatch > 0)
		h_fmt(h, "<button class=\"primary small\" data-act=\"queue-run\">"
		    "Run %d</button><button class=\"ghost small\" "
		    "data-act=\"queue-clear\">Clear</button><button class=\""
		    "ghost small\" data-act=\"queue-to-wf\" title=\"What waits "
		    "here, kept as a workflow\">As a workflow</button>",
		    app.nbatch);
	h_fmt(h, "<span class=\"chev\">%s</span></header>",
	    app.dock_open ? "▾" : "▴");
	if (app.dock_open) {
		h_raw(h, "<div class=\"dock-body\">" RESIZER("x", "ops")
		    "<ol class=\"ops\">");
		/* What waits in the queue, in the order it will run. */
		for (i = 0; i < app.nbatch; i++) {
			h_fmt(h, "<li class=\"op o-queued\"><i class=\"led\"></i>"
			    "<span class=\"t\">%d. ", i + 1);
			h_txt(h, app.batch[i].title);
			h_raw(h, "</span><span class=\"s\">");
			h_txt(h, app.batch[i].host);
			h_fmt(h, " · queued here</span><button class=\"icon\" "
			    "data-act=\"queue-drop\" data-arg=\"%d\" title=\""
			    "Take it out of the queue\">×</button></li>", i);
		}
		for (i = 0; i < app.nops; i++) {
			o = &app.ops[i];
			h_fmt(h, "<li class=\"op o-%s%s\" data-act=\"trace\" "
			    "data-arg=\"%d\"><i class=\"led\"></i>",
			    o->state == OP_RUNNING ? "running" :
			    o->state == OP_OK ? "ok" : "failed",
			    o->id == app.trace_op ? " selected" : "", o->id);
			{
				time_t		when = (time_t)(o->started / 1000);
				struct tm	tm;
				char		clock[16];

				localtime_r(&when, &tm);
				strftime(clock, sizeof(clock), "%H:%M:%S", &tm);
				h_fmt(h, "<span class=\"w\" title=\"When it "
				    "began\">%s</span>", clock);
			}
			h_raw(h, "<span class=\"t\">");
			h_txt(h, o->title);
			h_raw(h, "</span><span class=\"s\">");
			h_txt(h, o->server);
			if (o->job > 0)
				h_fmt(h, " · job %lld%s", o->job, o->waiting ?
				    ", host away, it runs on there" : "");
			h_raw(h, "</span>");
			if (o->state != OP_RUNNING) {
				fmt_dur(dur, sizeof(dur), (int64_t)
				    ((o->finished - o->started) * 1000));
				h_raw(h, "<span class=\"d\">");
				h_txt(h, dur);
				h_raw(h, "</span>");
			}
			if (o->state == OP_FAILED && o->again != NULL)
				h_fmt(h, "<button class=\"ghost small retry\" "
				    "data-act=\"op-retry\" data-arg=\"%d\" "
				    "title=\"Send it again, as it was\">Retry"
				    "</button>", o->id);
			if (o->state != OP_RUNNING)
				;
			else if (o->job > 0 || o->req != 0)
				h_fmt(h, "<button class=\"icon\" "
				    "data-act=\"op-cancel\" data-arg=\"%d\" "
				    "title=\"%s\">×</button>", o->id, o->job > 0 ?
				    "Take the job out of the host's queue, if it "
				    "has not started" : "Stop waiting for this; "
				    "the host may still finish it");
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

/* The themes of the stylesheet: html[data-theme], "" the default. */
static const struct {
	const char	*name, *title;
} themes[] = {
	{ "", "Graphite" }, { "tron", "Tron" }, { "amber", "Amber" },
	{ "matrix", "Matrix" },
	{ "synth", "Synth" }, { "slate", "Slate" }, { "onyx", "Onyx" },
	{ "paper", "Paper" }, { "sand", "Sand" }, { "mist", "Mist" },
	{ "mint", "Mint" },
};

/*
 * Settings, a section of its own: a tab for each part.  What is kept in
 * this browser (the look), who is told when a task ends, the read-only
 * API tokens, the keys that sign in, the console's own settings, and
 * what web.conf alone sets.
 */
static const struct {
	int		 tab;
	const char	*arg, *title;
} settabs[] = {
	{ SET_LOOK, "look", "Look" },
	{ SET_NOTIFY, "notify", "Notifications" },
	{ SET_TOKENS, "tokens", "API tokens" },
	{ SET_KEYS, "keys", "Sign-in keys" },
	{ SET_CONSOLE, "console", "Console" },
	{ SET_WEBCONF, "webconf", "web.conf" },
};

int
settab_of(const char *arg)
{
	size_t	i;

	for (i = 0; i < sizeof(settabs) / sizeof(settabs[0]); i++)
		if (strcmp(settabs[i].arg, arg) == 0)
			return (settabs[i].tab);
	return (SET_LOOK);
}

static void
set_look(struct html *h)
{
	int	i;

	h_raw(h, "<h3>Theme</h3><div class=\"themes\">");
	for (i = 0; i < (int)(sizeof(themes) / sizeof(themes[0])); i++)
		h_fmt(h, "<button type=\"button\" class=\"theme t-%s%s\" "
		    "data-act=\"theme\" data-arg=\"%s\"><i></i>%s</button>",
		    themes[i].name[0] != '\0' ? themes[i].name : "graphite",
		    strcmp(app.theme, themes[i].name) == 0 ? " on" : "",
		    themes[i].name, themes[i].title);
	h_fmt(h, "</div><p class=\"dim\">Kept in this browser. Graphite is "
	    "the default; Tron, Amber, Matrix and Synth are the neon ones, "
	    "with glow and capitals.</p><h3>Motion</h3><label class=\""
	    "toggle\"><input type=\"checkbox\" data-act=\"fx\"%s><span>Blur "
	    "and idle animations <em>off is lighter on slow browsers; kept "
	    "in this browser</em></span></label>", app.fx ? " checked" : "");
}

static void
set_notify(struct html *h)
{
	const ucl_object_t	*k;
	ucl_object_iter_t	 it;
	char			*here;
	int			 n;

	h_raw(h, "<p class=\"dim\">A change that ends in one browser is told "
	    "to the others listed here, open or not. A browser joins when "
	    "notifications are allowed in it, with <b>Notify</b> in the top "
	    "bar.</p>");
	here = arc_push_here();
	n = 0;
	it = NULL;
	h_raw(h, "<ul class=\"keys devices\">");
	while ((k = ucl_object_iterate(jget(app.push, "devices"), &it,
	    true)) != NULL) {
		char when[32];

		n++;
		h_raw(h, "<li><span class=\"name\">");
		h_txt(h, jstr(k, "name"));
		if (jstr(k, "endpoint") != NULL && strcmp(jstr(k, "endpoint"),
		    here) == 0)
			h_raw(h, " <em>this one</em>");
		h_raw(h, "</span><span class=\"dim\">");
		h_txt(h, jstr(k, "service"));
		fmt_age(when, sizeof(when), (double)jint(k, "added", 0) * 1000);
		h_raw(h, " · since ");
		h_txt(h, when);
		h_raw(h, "</span><button type=\"button\" class=\"icon\" "
		    "data-act=\"push-remove\" title=\"Stop telling this "
		    "device\"");
		h_attr(h, "data-arg", jstr(k, "endpoint"));
		h_raw(h, ">×</button></li>");
	}
	if (n == 0)
		h_raw(h, "<li class=\"dim\">No device yet.</li>");
	h_raw(h, "</ul>");
	free(here);
}

static void
set_tokens(struct html *h)
{
	const ucl_object_t	*k;
	ucl_object_iter_t	 it;
	int			 n;

	h_raw(h, "<p class=\"dim\">For a program to read what the console "
	    "says of the hosts, with <code>Authorization: Bearer</code>: "
	    "their jails, network, storage, logs and the rest, and nothing "
	    "that changes them, nor this console's settings or sign-in. Its "
	    "value is shown once, when it is made.</p>");
	if (app.token_value[0] != '\0') {
		h_raw(h, "<div class=\"notice info\"><b>Copy it now: it is not "
		    "shown again.</b><pre class=\"out token\">");
		h_txt(h, app.token_value);
		h_raw(h, "</pre></div>");
	}
	n = 0;
	it = NULL;
	h_raw(h, "<ul class=\"keys tokens\">");
	while ((k = ucl_object_iterate(jget(app.tokens, "tokens"), &it,
	    true)) != NULL) {
		char made[32], used[32];

		n++;
		fmt_age(made, sizeof(made), (double)jint(k, "created", 0) *
		    1000);
		fmt_age(used, sizeof(used), (double)jint(k, "last", 0) * 1000);
		h_raw(h, "<li><span class=\"name\">");
		h_txt(h, jstr(k, "name"));
		h_raw(h, "</span><span class=\"dim\">made ");
		h_txt(h, made);
		h_raw(h, " · ");
		if (jint(k, "last", 0) > 0) {
			h_raw(h, "used ");
			h_txt(h, used);
		} else
			h_raw(h, "never used");
		h_raw(h, "</span><button type=\"button\" class=\"icon\" "
		    "data-act=\"token-del\" title=\"Delete it\"");
		h_attr(h, "data-arg", jstr(k, "id"));
		h_raw(h, ">×</button></li>");
	}
	if (n == 0)
		h_raw(h, "<li class=\"dim\">No token.</li>");
	h_raw(h, "</ul><div class=\"token-new\"><input data-input=\""
	    "token-name\" spellcheck=\"false\" autocomplete=\"off\" "
	    "maxlength=\"64\" placeholder=\"what will use it\"");
	h_attr(h, "value", app.token_name);
	h_raw(h, "><button type=\"button\" class=\"small\" data-act=\""
	    "token-new\">Make a token</button></div>");
}

static void
set_keys(struct html *h)
{
	const ucl_object_t	*k;
	ucl_object_iter_t	 it;

	h_raw(h, "<form data-form=\"add-key\" class=\"set-form\"><ul class=\""
	    "keys\">");
	it = NULL;
	while ((k = ucl_object_iterate(app.keys, &it, true)) != NULL) {
		char when[32];

		h_raw(h, "<li><span class=\"name\">");
		h_txt(h, jstr(k, "name"));
		h_raw(h, "</span><span class=\"dim\">");
		h_txt(h, jint(k, "alg", 0) == -8 ? "Ed25519" : jint(k, "alg",
		    0) == -7 ? "ES256" : "RS256");
		if (jget(k, "last_used") != NULL) {
			fmt_age(when, sizeof(when), jint(k, "last_used", 0) *
			    1000.0);
			h_raw(h, " · used ");
			h_txt(h, when);
		}
		h_raw(h, "</span><button type=\"button\" class=\"icon\" "
		    "data-act=\"delete-key\" title=\"Remove\"");
		h_attr(h, "data-arg", jstr(k, "id"));
		h_raw(h, ">×</button></li>");
	}
	h_fmt(h, "</ul><p class=\"dim\">A spare security key, or a passkey: "
	    "open the console on the phone, log in here once, and register "
	    "from there.</p><label>Add a spare key<input name=\"name\" "
	    "placeholder=\"Spare YubiKey, or Pixel\" maxlength=\"64\"></label>"
	    "<div class=\"actions\"><button class=\"primary\"%s>Register key"
	    "</button></div></form>", app.modal_busy ? " disabled" : "");
}

static void
set_console(struct html *h)
{
	const ucl_object_t	*k;
	ucl_object_iter_t	 it;

	if (app.settings == NULL) {
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	h_raw(h, "<form data-form=\"settings\" class=\"settings set-form\">"
	    "<p class=\"dim\">What is set here is kept in <code>");
	h_txt(h, jstr(app.settings, "file"));
	h_raw(h, "</code> and takes the place of <code>web.conf</code>'s "
	    "value; a field put back to that value follows <code>web.conf"
	    "</code> again.</p>");
	it = NULL;
	while ((k = ucl_object_iterate(jget(app.settings, "settings"), &it,
	    true)) != NULL) {
		if (!jbool(k, "editable"))
			continue;
		if (jstr(k, "type") != NULL && strcmp(jstr(k, "type"),
		    "bool") == 0) {
			h_raw(h, "<fieldset class=\"toggles\"><label class=\""
			    "toggle\"><input type=\"checkbox\"");
			h_attr(h, "name", jstr(k, "key"));
			h_raw(h, jstr(k, "value") != NULL && strcmp(jstr(k,
			    "value"), "true") == 0 ? " checked" : "");
			h_raw(h, "><span>");
			h_txt(h, jstr(k, "label"));
			h_raw(h, " <em>");
			h_txt(h, jstr(k, "help"));
			h_raw(h, "</em></span></label></fieldset>");
			continue;
		}
		h_raw(h, "<label>");
		h_txt(h, jstr(k, "label"));
		h_raw(h, "<input spellcheck=\"false\" autocomplete=\"off\"");
		h_attr(h, "name", jstr(k, "key"));
		h_attr(h, "value", jstr(k, "value"));
		h_attr(h, "placeholder", jstr(k, "base"));
		h_raw(h, "><small>");
		h_txt(h, jstr(k, "help"));
		if (jbool(k, "overridden")) {
			h_raw(h, " web.conf says: ");
			h_txt(h, jstr(k, "base") != NULL && jstr(k, "base")[0] !=
			    '\0' ? jstr(k, "base") : "nothing");
			h_raw(h, ".");
		}
		h_raw(h, "</small></label>");
	}
	h_fmt(h, "<div class=\"actions\"><button class=\"primary\"%s>Save"
	    "</button></div></form>", app.modal_busy ? " disabled" : "");
}

static void
set_webconf(struct html *h)
{
	const ucl_object_t	*k;
	ucl_object_iter_t	 it;

	if (app.settings == NULL) {
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	h_raw(h, "<p class=\"dim\">Every registered key is bound to the "
	    "relying party and the origin, and these are read once, when the "
	    "console starts: a wrong value locks everyone out. They are "
	    "changed in <code>web.conf</code> only.</p><dl class=\"kv\">");
	it = NULL;
	while ((k = ucl_object_iterate(jget(app.settings, "settings"), &it,
	    true)) != NULL) {
		if (jbool(k, "editable"))
			continue;
		h_raw(h, "<dt>");
		h_txt(h, jstr(k, "label"));
		h_raw(h, "</dt><dd class=\"mono\">");
		h_txt(h, jstr(k, "value"));
		h_raw(h, "</dd>");
	}
	h_raw(h, "</dl>");
}

static void
view_settings(struct html *h)
{
	size_t	i;

	h_raw(h, "<section class=\"setsect\"><div class=\"set-head\"><h2>"
	    "Settings</h2><span class=\"versions dim\">Arcana console ");
	h_txt(h, app.version[0] != '\0' ? app.version : "?");
	if (app.agent_version[0] != '\0') {
		h_raw(h, " · sends arcana-agent ");
		h_txt(h, app.agent_version);
	}
	h_raw(h, "</span></div><nav class=\"tabs\">");
	for (i = 0; i < sizeof(settabs) / sizeof(settabs[0]); i++)
		h_fmt(h, "<button class=\"tab%s\" data-act=\"set-tab\" "
		    "data-arg=\"%s\">%s</button>", app.settab ==
		    settabs[i].tab ? " on" : "", settabs[i].arg,
		    settabs[i].title);
	h_raw(h, "</nav><div class=\"set-body\">");
	if (app.modal_error[0] != '\0' && app.modal == MODAL_NONE) {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, app.modal_error);
		h_raw(h, "</div>");
	}
	switch (app.settab) {
	case SET_NOTIFY:
		set_notify(h);
		break;
	case SET_TOKENS:
		set_tokens(h);
		break;
	case SET_KEYS:
		set_keys(h);
		break;
	case SET_CONSOLE:
		set_console(h);
		break;
	case SET_WEBCONF:
		set_webconf(h);
		break;
	default:
		set_look(h);
		break;
	}
	h_raw(h, "</div></section>");
}

static void
modal(struct html *h)
{
	struct confirm	*c;
	const ucl_object_t *k;
	ucl_object_iter_t it;
	bool		 add, changed;
	int		 i, n;

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
		    "<p>A host running <code>arcana-agent(8)</code>. Over TCP the "
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
		    "<code>arcana-enrol(8)</code> on the host turns it into a "
		    "certificate from the console's CA, starts "
		    "<code>arcana-agent(8)</code> with <code>-s</code>, and the host "
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
			h_raw(h, "</pre><p class=\"dim\">-s enables and starts "
			    "arcana-agent there; leave it out to only write the "
			    "certificate.</p>");
		}
		break;
	case MODAL_TUNNEL:
	case MODAL_IF_CREATE:
	case MODAL_IF_SET:
	case MODAL_IF_VNET:
	case MODAL_NG_CONNECT:
	case MODAL_NG_MKPEER:
		if (!topo_modal(h))
			return;
		break;
	case MODAL_STORAGE:
		if (!storage_modal(h))
			return;
		break;
	case MODAL_WG_INIT:
	case MODAL_WG_PEER:
		if (!vpn_modal(h))
			return;
		break;
	case MODAL_IPSEC_CONN:
	case MODAL_IPSEC_CHILD:
		if (!ipsec_modal(h))
			return;
		break;
	case MODAL_BIRD_PROTO:
	case MODAL_BIRD_BLOCK:
	case MODAL_BIRD_RPKI:
	case MODAL_BIRD_FILE:
		if (!bird_modal(h))
			return;
		break;
	case MODAL_ROUTE:
		h_fmt(h, "<form data-form=\"route\"><h2>Add a static route%s"
		    "</h2>", app.net.fib > 0 ? " to this routing table" : "");
		h_raw(h, "<p>With <code>route add</code>, now, in safe mode: "
		    "unless the host is reached again afterwards, it takes "
		    "the route back.</p><label class=\"toggle\"><input type="
		    "\"checkbox\" name=\"persist\" checked><span>Keep it in "
		    "<code>rc.conf</code>, to be there after a boot</span>"
		    "</label>"
		    "<label>Destination<input name=\"destination\" "
		    "spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"10.20.0.0/16\" autofocus><small>A network "
		    "with its prefix length, a host address, or default "
		    "(::/0 for IPv6's).</small></label>"
		    "<label>Gateway<input name=\"gateway\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"10.0.0.1\"><small>An "
		    "address, or the name of an interface. Several addresses "
		    "with commas make one route of as many next hops (ECMP), "
		    "each with its share after an @: 10.0.0.1@2,10.0.0.2."
		    "</small></label>"
		    "<div class=\"two\"><label>Metric<input name=\"metric\" "
		    "inputmode=\"numeric\" autocomplete=\"off\" placeholder="
		    "\"the system's, 1\"><small>Its cost: of several routes "
		    "to one destination the lowest is used, the others "
		    "when it is gone.</small></label><label>Weight<input name="
		    "\"weight\" inputmode=\"numeric\" autocomplete=\"off\" "
		    "placeholder=\"the system's\"><small>Its share among "
		    "routes of one metric.</small></label></div>"
		    "<div class=\"two\"><label>Source address<input name=\""
		    "source\" spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"the interface's own\"><small>The address "
		    "of this host that what takes the route is sent from."
		    "</small></label><label>Routing table (FIB)<input name=\""
		    "fib\" inputmode=\"numeric\" autocomplete=\"off\"");
		if (app.net.fib > 0)
			h_fmt(h, " value=\"%d\"", app.net.fib);
		h_raw(h, " placeholder=\"0\"><small>The table the route goes "
		    "into; 0 is the first.</small></label></div>");
		break;
	case MODAL_WF_RUN:
		if (!workflows_modal(h))
			return;
		break;
	case MODAL_PKG_INSTALL:
		if (cur_server() == NULL)
			return;
		h_raw(h, "<form data-form=\"pkg-install\"><h2>Install packages"
		    "</h2><p><code>pkg install -y</code> ");
		if (app.pkg.jail[0] != '\0') {
			h_raw(h, "in the jail <b>");
			h_txt(h, app.pkg.jail);
			h_raw(h, "</b>");
		} else {
			h_raw(h, "on <b>");
			h_txt(h, cur_server()->name);
			h_raw(h, "</b>");
		}
		h_fmt(h, ", from its repository%s, with what they need.</p>"
		    "<label>Packages<input name=\"names\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"strongswan "
		    "wireguard-tools\" autofocus><small>Their names, with spaces "
		    "between them.</small></label><label class=\"toggle\"><input "
		    "type=\"checkbox\" name=\"anyos\"><span>Also packages built "
		    "for a newer FreeBSD <em>IGNORE_OSVERSION</em></span></label>",
		    app.pkg.ip == 4 ? ", over IPv4" : app.pkg.ip == 6 ?
		    ", over IPv6" : "");
		break;
	case MODAL_LOOKUP:
		if (cur_server() == NULL)
			return;
		/*
		 * Asked in a box of its own: which route the host takes to
		 * an address, and the others that cover it.
		 */
		h_raw(h, "<form data-form=\"lookup\" class=\"wide\"><h2>Look "
		    "up a route</h2><p>The route this host takes to an "
		    "address, as <code>route get</code> tells it, and the "
		    "other routes of the table that cover the address.</p>"
		    "<div class=\"two\"><label>Address<input name=\"address\" "
		    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\""
		    "192.0.2.10 or 2001:db8::10\" autofocus></label><label>"
		    "Routing table (FIB)<input name=\"fib\" inputmode=\""
		    "numeric\" autocomplete=\"off\"");
		if (app.net.fib > 0)
			h_fmt(h, " value=\"%d\"", app.net.fib);
		h_raw(h, " placeholder=\"0\"></label></div>");
		view_lookup(h, cur_server());
		break;
	case MODAL_NHOP:
		nhop_modal(h);
		break;
	case MODAL_IF_ADDRESS:
		h_raw(h, "<form data-form=\"if-address\"><h2>Add an address to ");
		h_txt(h, app.confirm.arg);
		h_raw(h, "</h2><p>As an alias, with <code>ifconfig</code>, now, "
		    "in safe mode: unless the host is reached again "
		    "afterwards, it takes the address off.</p><label class=\""
		    "toggle\"><input type=\"checkbox\" name=\"persist\" checked>"
		    "<span>Keep it in <code>rc.conf</code>, to be there after "
		    "a boot</span></label>"
		    "<label>Address<input name=\"address\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"10.0.0.5/24\" autofocus>"
		    "<small>IPv4 or IPv6, with its prefix length; without one "
		    "it is /32 or /128.</small></label>");
		break;
	case MODAL_HOST_KEY:
		k = app.build_reply;
		add = jstr(k, "host_keys") != NULL;	/* a key to confirm */
		changed = add && jstr(k, "error") != NULL && strstr(jstr(k,
		    "error"), "CHANGED") != NULL;
		/*
		 * Three different things to say, each under its own name:
		 * a host key to confirm, one that changed, and a server
		 * that knows the host but refuses its key.
		 */
		h_fmt(h, "<form data-form=\"host-key\" class=\"hostkey%s\">"
		    "<h2>%s</h2><p>", changed ? " danger" : "", changed ?
		    "The server's SSH host key changed" : add ?
		    "Confirm the SSH host key" :
		    "The git server refused the host's key");
		h_txt(h, jstr(k, "error"));
		h_raw(h, "</p>");
		if (!add)
			h_raw(h, "<p>The server's host key is confirmed and "
			    "kept; this is about who the build host is to "
			    "the server. Pressing <b>Build again</b> before "
			    "the key is allowed there asks the same and gets "
			    "the same answer.</p>");
		if (add) {
			h_raw(h, "<p>The repository's server showed these keys "
			    "to the host that builds. Compare a fingerprint "
			    "with what the server's administrator gives; once "
			    "confirmed, the host keeps the keys and refuses the "
			    "server if it ever shows another.</p>"
			    "<ul class=\"fingerprints\">");
			it = NULL;
			while ((k = ucl_object_iterate(jget(app.build_reply,
			    "fingerprints"), &it, true)) != NULL) {
				h_raw(h, "<li><code>");
				h_txt(h, ucl_object_tostring(k));
				h_raw(h, "</code></li>");
			}
			h_raw(h, "</ul>");
		}
		if (jstr(app.build_reply, "deploy_key") != NULL) {
			h_raw(h, add ? "<p>The host shows the server this key "
			    "of its own; allow it there, read-only, if it is "
			    "not yet:</p>" : "<p>This is the public half of "
			    "the key the host showed. Add it to the "
			    "repository on the server as a read-only deploy "
			    "key (or to a user who may read it), then build "
			    "again. To use another key, name its path in "
			    "Settings, <q>SSH key for git</q>.</p>");
			h_raw(h, "<pre class=\"out deploy-key\">");
			h_txt(h, jstr(app.build_reply, "deploy_key"));
			h_raw(h, "</pre>");
		}
		break;
	case MODAL_AGENT_UPDATE:
		h_raw(h, "<form data-form=\"agent-update\"><h2>Update "
		    "arcana-agent</h2><p>The console sends its arcana-agent");
		if (app.agent_version[0] != '\0') {
			h_raw(h, " (");
			h_txt(h, app.agent_version);
			h_raw(h, ")");
		}
		h_raw(h, " to ");
		if (app.confirm.arg[0] != '\0') {
			for (i = 0; i < app.nservers; i++)
				if (strcmp(app.servers[i].id, app.confirm.arg) ==
				    0)
					h_txt(h, app.servers[i].name);
		} else {
			n = 0;
			for (i = 0; i < app.nservers; i++)
				if (agent_outdated(&app.servers[i])) {
					h_raw(h, n++ > 0 ? ", " : "");
					h_txt(h, app.servers[i].name);
				}
		}
		h_raw(h, ". Each host checks that the program runs there "
		    "before it replaces the one installed, which it keeps "
		    "beside it as <code>arcana-agent.old</code>.</p>"
		    "<fieldset class=\"toggles\"><label class=\"toggle\">"
		    "<input type=\"checkbox\" name=\"restart\" checked>"
		    "<span>Restart the agent now <em>otherwise the new "
		    "program runs from the next start of the service; a "
		    "restart drops the jobs still queued on the host</em>"
		    "</span></label></fieldset>");
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
		/* A box that only shows is closed, not cancelled. */
		h_fmt(h, "<div class=\"buttons\"><button type=\"button\" "
		    "class=\"ghost\" data-act=\"close\">%s</button>",
		    app.modal == MODAL_NHOP ? "Close" : "Cancel");
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
		case MODAL_AGENT_UPDATE:
			h_raw(h, "<button class=\"primary\">Update</button>");
			break;
		case MODAL_IF_ADDRESS:
		case MODAL_ROUTE:
			h_raw(h, "<button class=\"primary\">Add</button>");
			break;
		case MODAL_TUNNEL:
		case MODAL_IF_CREATE:
		case MODAL_NG_MKPEER:
			h_raw(h, "<button class=\"primary\">Create</button>");
			break;
		case MODAL_IF_VNET:
			h_raw(h, "<button class=\"primary\">Give</button>");
			break;
		case MODAL_IF_SET:
		case MODAL_WG_INIT:
			h_raw(h, "<button class=\"primary\">Set</button>");
			break;
		case MODAL_WG_PEER:
		case MODAL_IPSEC_CONN:
			h_raw(h, "<button class=\"primary\">Add</button>");
			break;
		case MODAL_IPSEC_CHILD:
			h_raw(h, "<button class=\"primary\">Add</button>");
			break;
		case MODAL_STORAGE:
			storage_modal_buttons(h);
			break;
		case MODAL_LOOKUP:
			h_raw(h, "<button class=\"primary\">Look up</button>");
			break;
		case MODAL_PKG_INSTALL:
			h_raw(h, "<button class=\"primary\">Install</button>");
			break;
		case MODAL_WF_RUN:
			h_raw(h, "<button class=\"primary\">Run</button>");
			break;
		case MODAL_BIRD_PROTO:
		case MODAL_BIRD_BLOCK:
		case MODAL_BIRD_RPKI:
		case MODAL_BIRD_FILE:
			bird_modal_buttons(h);
			break;
		case MODAL_NG_CONNECT:
			h_raw(h, "<button class=\"primary\">Connect</button>");
			break;
		case MODAL_HOST_KEY:
			h_fmt(h, "<button class=\"%s\">%s</button>",
			    jstr(app.build_reply, "host_keys") == NULL ?
			    "primary" : "danger", jstr(app.build_reply,
			    "host_keys") == NULL ? "Build again" :
			    "Trust these keys and build");
			break;
		case MODAL_ADDRESS:
			h_fmt(h, "<button class=\"ghost\" value=\"preview\"%s>"
			    "Preview</button><button class=\"primary\" "
			    "value=\"apply\"%s>Apply</button>",
			    app.modal_busy ? " disabled" : "",
			    app.modal_busy ? " disabled" : "");
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
	h_raw(h, "</span><span class=\"wordmark\">ARCANA</span></div>"
	    "<p class=\"sub\">The Seven Archives of FreeBSD</p>");
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
	install_offer(h);
	if (app.origin_error[0] != '\0') {
		h_raw(h, "<p class=\"err origin\">");
		h_txt(h, app.origin_error);
		h_raw(h, "</p>");
	}
	if (app.auth_error[0] != '\0') {
		h_raw(h, "<p class=\"err\">");
		h_txt(h, app.auth_error);
		h_raw(h, "</p>");
	}
	h_raw(h, "</div></div>");
}

/*
 * The console is a fixed skeleton of regions (view_shell), each filled
 * by view_region(); render() patches only the regions whose markup
 * changed, so a reply that touches the dock does not re-diff the grid.
 */
const char *const view_regions[VIEW_REGIONS] = {
	"r-topbar", "r-banner", "r-rail", "r-stage", "r-drawer", "r-dock",
	"r-modal", "r-toasts",
};

void
view_shell(struct html *h)
{

	h_raw(h, "<div class=\"shell\"><div id=\"r-topbar\" class=\"region\">"
	    "</div><div id=\"r-banner\" class=\"region\"></div>"
	    "<div class=\"body\" id=\"body\"><div id=\"r-rail\" class=\"region\">"
	    "</div><div id=\"r-stage\" class=\"region\"></div>"
	    "<div id=\"r-drawer\" class=\"region\"></div></div>"
	    "<div id=\"r-dock\" class=\"region\"></div></div>"
	    "<div id=\"r-modal\" class=\"region\"></div>"
	    "<div id=\"r-toasts\" class=\"region\"></div>");
}

/*
 * A box that folds: its head is pressed to shut it and to open it
 * again, and how it was left is kept in the browser.  box_head() is
 * the head's attributes and its mark; box_shut() says not to draw what
 * is under it.
 */
bool
box_shut(const char *key)
{
	char	k[96];

	snprintf(k, sizeof(k), "shut:%s", key);
	return (arc_open_get(k) != 0);
}

void
box_head(struct html *h, const char *key, const char *tag)
{
	char	k[96];

	snprintf(k, sizeof(k), "shut:%s", key);
	h_fmt(h, "<%s class=\"boxhead%s\" data-act=\"fold\"", tag,
	    arc_open_get(k) != 0 ? " shut" : "");
	h_attr(h, "data-arg", k);
	h_fmt(h, " title=\"Fold, or unfold\"><i class=\"chev\">%s</i>",
	    arc_open_get(k) != 0 ? "▸" : "▾");
}

/* Is the service drawer open?  The body lays out differently. */
bool
view_with_drawer(void)
{

	return (app.node == NODE_HOST && app.tab == TAB_SERVICES &&
	    app.service[0] != '\0');
}

void
view_region(struct html *h, int r)
{

	switch (r) {
	case 0:
		topbar(h);
		break;
	case 1:
		banner(h);
		break;
	case 2:
		rail(h);
		break;
	case 3:
		stage(h);
		break;
	case 4:
		if (app.node == NODE_HOST && app.tab == TAB_SERVICES)
			view_service_drawer(h, cur_server());
		else
			h_raw(h, "<aside class=\"drawer\"></aside>");
		break;
	case 5:
		dock(h);
		break;
	case 6:
		modal(h);
		break;
	default:
		toasts(h);
		break;
	}
}

/* The login screens: one piece, small. */
void
view(struct html *h)
{

	auth_screen(h);
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
	busy = cur_server() != NULL && service_busy(cur_server(), name);
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
static const char *svc_sorts[] = {
	[SVC_SORT_RUNNING] = "running",
	[SVC_SORT_ENABLED] = "enabled",
	[SVC_SORT_NAME] = "name",
};

/*
 * Services in the order asked for: those running first, or those
 * enabled first, or by name.  The key alone is turned round when the
 * order is; within it the other state decides, then the name.
 */
static int
svc_cmp(const void *ap, const void *bp)
{
	const ucl_object_t	*a, *b;
	int			 run, en, r;

	a = *(const ucl_object_t *const *)ap;
	b = *(const ucl_object_t *const *)bp;
	run = (int)jbool(b, "running") - (int)jbool(a, "running");
	en = (int)jbool(b, "enabled") - (int)jbool(a, "enabled");
	r = strcmp(jstr(a, "name"), jstr(b, "name"));
	if (app.svc_sort_desc) {
		if (app.svc_sort == SVC_SORT_RUNNING)
			run = -run;
		else if (app.svc_sort == SVC_SORT_ENABLED)
			en = -en;
		else
			r = -r;
	}
	if (app.svc_sort == SVC_SORT_NAME)
		return (r);
	if (app.svc_sort == SVC_SORT_ENABLED)
		return (en != 0 ? en : run != 0 ? run : r);
	return (run != 0 ? run : en != 0 ? en : r);
}

void
view_services(struct html *h, struct server *s)
{
	const ucl_object_t	*sv, **rows;
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
		h_raw(h, "</span><span class=\"sorts\">Sort");
		for (n = 0; n <= SVC_SORT_NAME; n++)
			h_fmt(h, "<button class=\"ghost small%s\" "
			    "data-act=\"svc-sort\" data-arg=\"%s\">%s%s</button>",
			    app.svc_sort == n ? " on" : "", svc_sorts[n],
			    svc_sorts[n], app.svc_sort != n ? "" :
			    app.svc_sort_desc ? " ▴" : " ▾");
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
	/* Those that match, in the order asked for. */
	n = (int)ucl_array_size(jget(s->services, "services"));
	if ((rows = calloc(n > 0 ? n : 1, sizeof(*rows))) == NULL)
		abort();
	shown = 0;
	it = NULL;
	while ((sv = ucl_object_iterate(jget(s->services, "services"), &it,
	    true)) != NULL) {
		if (jstr(sv, "name") == NULL || (app.filter[0] != '\0' &&
		    strstr(jstr(sv, "name"), app.filter) == NULL))
			continue;
		rows[shown++] = sv;
	}
	qsort(rows, shown, sizeof(*rows), svc_cmp);
	h_raw(h, "<ul class=\"services\">");
	for (n = 0; n < shown; n++)
		service_row(h, rows[n]);
	h_raw(h, "</ul>");
	free(rows);
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
	h_fmt(h, "<aside class=\"drawer open s-%s\">" RESIZER("x", "drawer")
	    "<header><i class=\"led\">"
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
			    cur_server() != NULL && service_busy(cur_server(),
			    name) ? " disabled" : "");
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

/*
 * A gauge: the figure, and the recent samples as a line with the area
 * under it, drawn as inline SVG in a 120x36 box.
 */
static void
gauge(struct html *h, const char *label, const char *cls, const float *v,
    int n, double value, const char *unit, const char *detail)
{
	char	buf[32];
	int	i;
	double	x, y;

	h_fmt(h, "<div class=\"gauge g-%s\"", cls);
	h_attr(h, "title", detail);
	h_raw(h, "><div class=\"gl\">");
	h_txt(h, label);
	h_raw(h, "</div><div class=\"gv\">");
	snprintf(buf, sizeof(buf), "%.0f", value);
	h_txt(h, buf);
	h_raw(h, "<small>");
	h_txt(h, unit);
	h_raw(h, "</small></div><svg class=\"spark\" viewBox=\"0 0 120 36\" "
	    "preserveAspectRatio=\"none\" aria-hidden=\"true\">");
	if (n > 1) {
		h_raw(h, "<path class=\"area\" d=\"M0 36 ");
		for (i = 0; i < n; i++) {
			x = 120.0 * i / (n - 1);
			y = 36 - 34 * (v[i] > 100 ? 100 : v[i] < 0 ? 0 : v[i]) /
			    100;
			h_fmt(h, "L%.1f %.1f ", x, y);
		}
		h_raw(h, "L120 36 Z\"/><path class=\"line\" d=\"");
		for (i = 0; i < n; i++) {
			x = 120.0 * i / (n - 1);
			y = 36 - 34 * (v[i] > 100 ? 100 : v[i] < 0 ? 0 : v[i]) /
			    100;
			h_fmt(h, "%s%.1f %.1f ", i == 0 ? "M" : "L", x, y);
		}
		h_raw(h, "\"/>");
	}
	h_raw(h, "</svg><i class=\"bar\"");
	snprintf(buf, sizeof(buf), "--v:%.3f", (value > 100 ? 100 : value) /
	    100);
	h_attr(h, "style", buf);
	h_raw(h, "></i></div>");
}

/* CPU, memory and ZFS of the server, each with its recent history. */
void
view_gauges(struct html *h, struct server *s)
{
	const ucl_object_t	*st, *p;
	ucl_object_iter_t	 it;
	char			 d1[160], d2[200], d3[400], tmp[96];
	double			 total, used, inact, size;
	float			 cpu, mem, zfs;
	int			 n;

	if (s->stats == NULL || s->nhist == 0)
		return;
	st = jget(s->stats, "stats");
	n = s->nhist;
	cpu = s->hist[0][n - 1];
	mem = s->hist[1][n - 1];
	zfs = s->hist[2][n - 1];
	snprintf(d1, sizeof(d1), "load %.2f %.2f %.2f, over the last %d "
	    "samples", jnum(st, "load1", 0), jnum(st, "load5", 0),
	    jnum(st, "load15", 0), n);
	total = jnum(st, "mem_total", 0) / 1048576;
	used = jnum(st, "mem_used", 0) / 1048576;
	inact = jnum(st, "mem_inactive", 0) / 1048576;
	snprintf(d2, sizeof(d2), "%.0f of %.0f MiB in use (active, wired, "
	    "laundry); %.0f inactive; swap %.0f of %.0f MiB", used, total,
	    inact, jnum(st, "swap_used", 0) / 1048576,
	    jnum(st, "swap_total", 0) / 1048576);
	d3[0] = '\0';
	size = 0;
	it = NULL;
	while ((p = ucl_object_iterate(jget(st, "pools"), &it, true)) != NULL) {
		snprintf(tmp, sizeof(tmp), "%s%s: %.0f of %.0f GiB, %s",
		    d3[0] != '\0' ? "; " : "", jstr(p, "name") != NULL ?
		    jstr(p, "name") : "?", jnum(p, "alloc", 0) / 1073741824,
		    jnum(p, "size", 0) / 1073741824, jstr(p, "health") != NULL ?
		    jstr(p, "health") : "");
		strlcat(d3, tmp, sizeof(d3));
		size += jnum(p, "size", 0);
	}
	h_raw(h, "<section class=\"gauges\">");
	gauge(h, "CPU", "cpu", s->hist[0], n, cpu, "%", d1);
	gauge(h, "RAM", "mem", s->hist[1], n, mem, "%", d2);
	if (size > 0)
		gauge(h, "ZFS", "zfs", s->hist[2], n, zfs, "%", d3);
	h_raw(h, "</section>");
}

/* A size in bytes, short. */
static void
pkg_size(char *buf, size_t len, int64_t n)
{
	if (n >= 1073741824)
		snprintf(buf, len, "%.1f GiB", (double)n / 1073741824.0);
	else if (n >= 1048576)
		snprintf(buf, len, "%.1f MiB", (double)n / 1048576.0);
	else
		snprintf(buf, len, "%lld KiB", (long long)(n + 1023) / 1024);
}

/*
 * The packages installed: each with its version, whether it was asked
 * for by name or came as what another needs, its size, its port and
 * what it is.
 */
static void
installed_packages(struct html *h)
{
	static const struct tcol cols[] = {
		{ "Package", "name", false }, { "Version", "installed", false },
		{ "Installed", "automatic", false }, { "Size", "size", true },
		{ "Origin", "origin", false }, { "What it is", "comment", false },
	};
	const ucl_object_t	**rows, *p;
	ucl_object_iter_t	 it;
	char			 sz[32];
	int			 r, all, autos;

	all = autos = 0;
	it = NULL;
	while ((p = ucl_object_iterate(jget(app.pkg.data, "packages"), &it,
	    true)) != NULL) {
		all++;
		if (jbool(p, "automatic"))
			autos++;
	}
	h_fmt(h, "<p class=\"dim\"><b>%d</b> installed: <b>%d</b> asked for "
	    "by name, <b>%d</b> automatically, as what another needs. "
	    "<b>Upgrades</b> asks the repository what is newer.</p>", all,
	    all - autos, autos);
	h_raw(h, "<table class=\"net pkg-installed\">");
	tbl_head(h, "pkginst", cols, 6, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("pkginst", jget(app.pkg.data, "packages"), cols, 6,
	    app.filter);
	for (r = 0; (p = rows[r]) != NULL; r++) {
		h_raw(h, "<tr><td>");
		h_txt(h, jstr(p, "name"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(p, "installed"));
		h_fmt(h, "</td><td><span class=\"chip%s\" title=\"%s\">%s"
		    "</span></td><td>", jbool(p, "automatic") ? " dim" : "",
		    jbool(p, "automatic") ? "Came as what another package "
		    "needs: pkg autoremove takes it once none does" : "Asked "
		    "for by name", jbool(p, "automatic") ? "automatic" :
		    "by hand");
		pkg_size(sz, sizeof(sz), jint(p, "size", 0));
		h_txt(h, sz);
		h_raw(h, "</td><td class=\"dim\">");
		h_txt(h, jstr(p, "origin"));
		h_raw(h, "</td><td class=\"msg\">");
		h_txt(h, jstr(p, "comment"));
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (r == 0)
		h_raw(h, "<div class=\"empty\"><p>No package, or none with that "
		    "in it.</p></div>");
}

/* The packages tab: the host or a running jail, and what pkg can upgrade. */
void
view_packages(struct html *h, struct server *s)
{
	const ucl_object_t	*j, *p, **prows;
	ucl_object_iter_t	 it;
	char			 age[32], fname[300];
	int			 n, pr;
	bool			 mine;

	mine = app.pkg.data != NULL && strcmp(app.pkg.sid, s->id) == 0;
	h_raw(h, "<div class=\"toolbar\"><nav class=\"sub\">");
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"pkg-target\" "
	    "data-arg=\"\">host</button>", app.pkg.jail[0] == '\0' ? " on" : "");
	it = NULL;
	while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		if (jstr(j, "name") == NULL || jstr(j, "state") == NULL ||
		    strcmp(jstr(j, "state"), "running") != 0)
			continue;
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"pkg-target\"",
		    strcmp(app.pkg.jail, jstr(j, "name")) == 0 ? " on" : "");
		h_attr(h, "data-arg", jstr(j, "name"));
		h_raw(h, ">");
		h_txt(h, jstr(j, "name"));
		h_raw(h, "</button>");
	}
	h_raw(h, "</nav>");
	h_fmt(h, "<nav class=\"sub\"><button class=\"ghost small%s\" data-act="
	    "\"pkg-mode\" data-arg=\"0\" title=\"What is installed, from the "
	    "host's own database: the repository is not asked\">Installed"
	    "</button><button class=\"ghost small%s\" data-act=\"pkg-mode\" "
	    "data-arg=\"1\" title=\"What the repository has newer versions "
	    "of: it is asked\">Upgrades</button></nav>", app.pkg.mode == 0 ?
	    " on" : "", app.pkg.mode == 1 ? " on" : "");
	/* How the repository is reached: pkg -4, -6, or either. */
	h_fmt(h, "<nav class=\"sub\" title=\"How pkg reaches the repository: "
	    "over IPv4 only (pkg -4), IPv6 only (pkg -6), or either\">"
	    "<button class=\"ghost small%s\" data-act=\"pkg-ip\" data-arg=\"0"
	    "\">either</button><button class=\"ghost small%s\" data-act=\""
	    "pkg-ip\" data-arg=\"4\">IPv4</button><button class=\"ghost "
	    "small%s\" data-act=\"pkg-ip\" data-arg=\"6\">IPv6</button></nav>",
	    app.pkg.ip == 0 ? " on" : "", app.pkg.ip == 4 ? " on" : "",
	    app.pkg.ip == 6 ? " on" : "");
	h_raw(h, "<button class=\"ghost small\" data-act=\"pkg-install\" "
	    "title=\"pkg install: packages added\">Install…</button>");
	/* The cache of downloaded packages, cleaned. */
	h_raw(h, "<button class=\"ghost small\" data-act=\"pkg-clean\" "
	    "data-arg=\"\" title=\"pkg clean: the downloaded packages no "
	    "longer needed deleted\">Clean</button><button class=\"ghost "
	    "small\" data-act=\"pkg-clean\" data-arg=\"all\" title=\"pkg "
	    "clean -a: all the downloaded packages deleted\">Clean all"
	    "</button>");
	/* Of every running jail at once, from the host's page. */
	if (app.pkg.jail[0] == '\0')
		h_raw(h, "<button class=\"ghost small\" data-act=\""
		    "pkg-clean-jails\" data-arg=\"\" title=\"pkg clean in "
		    "every running jail, one batch of a job each\">Clean the "
		    "jails</button>");
	if (app.pkg.mode == 1)
		h_fmt(h, "<button class=\"ghost small\" data-act=\"pkg-check\""
		    "%s title=\"pkg update, then list what has a newer version"
		    "\">Check</button>", app.pkg.loading || packages_busy(s) ?
		    " disabled" : "");
	if (mine) {
		fmt_age(age, sizeof(age), app.pkg.fetched);
		h_raw(h, "<span class=\"tally\">");
		h_txt(h, age);
		h_raw(h, "</span>");
	}
	h_raw(h, "</div>");
	if (app.pkg.error[0] != '\0' && strcmp(app.pkg.sid, s->id) == 0) {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, app.pkg.error);
		h_raw(h, "</div>");
	}
	if (app.pkg.result[0] != '\0' && mine) {
		h_raw(h, "<div class=\"notice\">");
		h_txt(h, app.pkg.result);
		h_raw(h, "</div>");
	}
	if (!mine) {
		h_raw(h, !app.pkg.loading ? "<div class=\"empty\"><h2>No data"
		    "</h2><p>The host has not answered yet.</p></div>" :
		    app.pkg.mode == 0 ? "<div class=\"empty\"><div class="
		    "\"loader\"></div><p class=\"dim\">pkg query, the "
		    "installed packages…</p></div>" : "<div class=\"empty\"><div "
		    "class=\"loader\"></div><p class=\"dim\">pkg version "
		    "against the repository…</p></div>");
		return;
	}
	if (app.pkg.mode == 0) {
		installed_packages(h);
		return;
	}
	n = 0;
	h_raw(h, "<form data-form=\"packages\" class=\"pkgs\">"
	    "<table class=\"net\">");
	{
		static const struct tcol pcols[] = {
			{ "", NULL, false }, { "Package", "name", false },
			{ "Installed", "installed", false },
			{ "Available", "available", false },
		};

		tbl_head(h, "pkgs", pcols, 4, 0);
		h_raw(h, "<tbody>");
		prows = tbl_rows("pkgs", jget(app.pkg.data, "packages"),
		    pcols, 4, app.filter);
	}
	for (pr = 0; (p = prows[pr]) != NULL; pr++) {
		if (jstr(p, "name") == NULL)
			continue;
		snprintf(fname, sizeof(fname), "p:%s", jstr(p, "name"));
		h_raw(h, "<tr><td><input type=\"checkbox\"");
		h_attr(h, "name", fname);
		h_raw(h, "></td><td>");
		h_txt(h, jstr(p, "name"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(p, "installed"));
		h_raw(h, "</td><td class=\"c-run\">");
		h_txt(h, jstr(p, "available"));
		h_raw(h, "</td></tr>");
		n++;
	}
	free(prows);
	h_raw(h, "</tbody></table>");
	if (n == 0)
		h_raw(h, "<div class=\"empty\"><p>Everything is up to date."
		    "</p></div>");
	else
		h_fmt(h, "<div class=\"buttons\"><span class=\"dim\">%d pending; "
		    "none selected means all</span><button class=\"ghost\" "
		    "value=\"dry\"%s>Dry run</button><button class=\"danger\" "
		    "value=\"go\"%s>Upgrade</button></div>", n,
		    packages_busy(s) ? " disabled" : "", packages_busy(s) ?
		    " disabled" : "");
	h_raw(h, "</form>");
	if (packages_busy(s))
		h_raw(h, "<div class=\"notice\"><div class=\"loader\"></div>"
		    "pkg upgrade is running; its output lands in the activity "
		    "trace.</div>");
}
