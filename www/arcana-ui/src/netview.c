/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The network tab: routes, nexthops, connections and sockets, as tables
 * built from the JSON netstat(1) and sockstat(1) printed on the host.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

struct column {
	const char	*title;
	const char	*path;		/* in the entry */
	const char	*path2;		/* appended after ':', or NULL */
};

static const struct column routes_cols[] = {
	{ "Destination", "destination", NULL },
	{ "Gateway", "gateway", NULL },
	{ "Flags", "flags", NULL },
	{ "Nhop", "nhop", NULL },
	{ "MTU", "mtu", NULL },
	{ "Interface", "interface-name", NULL },
	{ "Metric", "metric", NULL },
	{ "Weight", "weight", NULL },
	{ "Path", "path", "paths" },
	{ "Source", "source", NULL },
	{ "Expire", "expire-time", NULL },
};

static const struct column nexthops_cols[] = {
	{ "Idx", "index", NULL },
	{ "Type", "type_str", NULL },
	{ "IFA", "ifa", NULL },
	{ "Gateway", "gateway", NULL },
	{ "Flags", "flags", NULL },
	{ "Use", "use", NULL },
	{ "MTU", "mtu", NULL },
	{ "Netif", "interface-name", NULL },
	{ "Addrif", "address-interface-name", NULL },
	{ "Refcnt", "refcount", NULL },
};

static const struct column conn_cols[] = {
	{ "Proto", "protocol", NULL },
	{ "Recv-Q", "receive-bytes-waiting", NULL },
	{ "Send-Q", "send-bytes-waiting", NULL },
	{ "Local", "local.address", "local.port" },
	{ "Remote", "remote.address", "remote.port" },
	{ "State", "tcp-state", NULL },
};

static const struct column sock_cols[] = {
	{ "User", "user", NULL },
	{ "Command", "command", NULL },
	{ "PID", "pid", NULL },
	{ "FD", "fd", NULL },
	{ "Proto", "proto", NULL },
	{ "Local", "local.address", "local.port" },
	{ "Foreign", "foreign.address", "foreign.port" },
};

static const struct column neigh_cols[] = {
	{ "Address", "address", NULL },
	{ "Link address", "lladdr", NULL },
	{ "Interface", "interface-name", NULL },
	{ "State", "state", NULL },
	{ "Family", "family", NULL },
	{ "Router", "router", NULL },
};

static void	cell(struct html *, const ucl_object_t *, const struct column *);
static int	table(struct html *, const ucl_object_t *, const struct column *,
		    size_t, const char *);
static void	route_delete(struct html *, const ucl_object_t *, const char *);
static int	interfaces(struct html *, const struct server *,
		    const ucl_object_t *);



/* One cell: the value at path, or "a:b" with path2, as text. */
static void
cell(struct html *h, const ucl_object_t *e, const struct column *c)
{
	const ucl_object_t	*v;

	/*
	 * A route's nexthop opens it: the group its ways share when it
	 * has several, else the one next hop.
	 */
	if (strcmp(c->path, "nhop") == 0 && jint(e, "nhop", 0) > 0) {
		h_fmt(h, "<td><button class=\"cell-link mono\" data-act=\"net-nhop\" "
		    "data-arg=\"%lld\" data-value=\"%s\" title=\"%s\">%lld"
		    "</button></td>", (long long)jint(e, "nhop", 0), jint(e,
		    "paths", 0) > 1 ? "group" : "nexthop", jint(e, "paths", 0) >
		    1 ? "The nexthop group its ways share" : "Its next hop",
		    (long long)jint(e, "nhop", 0));
		return;
	}
	h_raw(h, "<td>");
	if ((v = jget(e, c->path)) != NULL && ucl_object_type(v) != UCL_NULL)
		h_txt(h, ucl_object_tostring_forced(v));
	if (c->path2 != NULL && (v = jget(e, c->path2)) != NULL &&
	    ucl_object_type(v) != UCL_NULL) {
		h_raw(h, "<span class=\"dim\">:</span>");
		h_txt(h, ucl_object_tostring_forced(v));
	}
	h_raw(h, "</td>");
}

/*
 * A table of the entries in the array, sorted and filtered as every
 * table is (tbl.c); the rows shown.  id names it, for the order kept.
 */
static int
table(struct html *h, const ucl_object_t *arr, const struct column *cols,
    size_t ncols, const char *family)
{
	struct tcol		 tc[16];
	const ucl_object_t	**rows;
	char			 id[48];
	size_t			 i, c;

	for (c = 0; c < ncols && c < 16; c++) {
		tc[c].title = cols[c].title;
		tc[c].key = cols[c].path;
		tc[c].num = false;
	}
	snprintf(id, sizeof(id), "net-%d-%s", (int)app.net.kind, family !=
	    NULL ? family : "");
	h_raw(h, "<table class=\"net\">");
	tbl_head(h, id, tc, (int)c, family != NULL ? 1 : 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows(id, arr, tc, (int)c, app.filter);
	for (i = 0; rows[i] != NULL; i++) {
		h_raw(h, "<tr>");
		for (c = 0; c < ncols; c++)
			cell(h, rows[i], &cols[c]);
		if (family != NULL)
			route_delete(h, rows[i], family);
		h_raw(h, "</tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	return ((int)i);
}

/*
 * The last cell of a route's row: a way to delete it, for the static
 * ones (flag S), which are those somebody added.  The default route of
 * IPv6 is named ::/0, as "default" alone is IPv4's.
 */
static void
route_delete(struct html *h, const ucl_object_t *e, const char *family)
{
	const char	*dest, *flags;

	h_raw(h, "<td>");
	dest = jstr(e, "destination");
	flags = jstr(e, "flags");
	if (dest != NULL && flags != NULL && strchr(flags, 'S') != NULL) {
		if (strcmp(dest, "default") == 0 && strstr(family, "6") != NULL)
			dest = "::/0";
		h_raw(h, "<button class=\"icon\" data-act=\"route-delete\" "
		    "title=\"Delete this static route\"");
		h_attr(h, "data-arg", dest);
		h_attr(h, "data-value", jstr(e, "gateway") != NULL &&
		    strncmp(jstr(e, "gateway"), "link#", 5) != 0 ? jstr(e,
		    "gateway") : "");
		h_raw(h, ">×</button>");
	}
	h_raw(h, "</td>");
}

/*
 * The nexthop groups, what a route of several next hops points to:
 * each a row of its own, its next hops one under the other, each with
 * its gateway and interface and a bar of its share of the group.
 */
static int
nhgroups(struct html *h, const struct server *s, const ucl_object_t *fams)
{
	static const struct tcol	cols[] = {
		{ "Group", "nhgrp-index", true },
		{ "Routes", "nhg-refcnt", true },
		{ "Next hops, and the share of each", NULL, false },
	};
	const ucl_object_t		**rows, *fam, *g, *n;
	ucl_object_iter_t		  it, nit;
	long long			  sum, wt;
	int				  r, shown, hops;

	shown = 0;
	/* What each carried, from the samples: a jail's are not taken. */
	if (net_scope()[0] == '\0' && ucl_array_size(fams) > 0)
		ecmp_head(h);
	else if (ucl_array_size(fams) > 0)
		h_raw(h, "<p class=\"dim ecmp-note\">What each next hop "
		    "carried is drawn for the host's groups only: its agent "
		    "samples the host's interfaces, not a jail's.</p>");
	it = NULL;
	while ((fam = ucl_object_iterate(fams, &it, true)) != NULL) {
		h_raw(h, "<h4 class=\"family\">");
		h_txt(h, jstr(fam, "address-family"));
		h_raw(h, "</h4><table class=\"net nhgroups\">");
		tbl_head(h, "nhgroups", cols, 3, 0);
		h_raw(h, "<tbody>");
		rows = tbl_rows("nhgroups", jget(fam, "nhgrp-entry"), cols, 3,
		    app.filter);
		for (r = 0; (g = rows[r]) != NULL; r++) {
			shown++;
			sum = 0;
			hops = 0;
			nit = NULL;
			while ((n = ucl_object_iterate(jget(g, "nhop-weights"),
			    &nit, true)) != NULL) {
				sum += jint(n, "nh-weight", 0);
				hops++;
			}
			h_fmt(h, "<tr><td class=\"nhg-id\"><b>%lld</b><small>%d "
			    "next hop%s</small></td><td class=\"num\">%lld</td>"
			    "<td><div class=\"nhg-hops\">",
			    (long long)jint(g, "nhgrp-index", 0), hops, hops ==
			    1 ? "" : "s", (long long)jint(g, "nhg-refcnt", 0));
			nit = NULL;
			while ((n = ucl_object_iterate(jget(g, "nhop-weights"),
			    &nit, true)) != NULL) {
				wt = jint(n, "nh-weight", 0);
				h_raw(h, "<div class=\"nhg-hop\"><span class=\""
				    "mono nhg-gw\">");
				h_txt(h, jstr(n, "nh-gw") != NULL ? jstr(n,
				    "nh-gw") : "?");
				h_raw(h, "</span><span class=\"nhg-if\">");
				h_txt(h, jstr(n, "nh-interface") != NULL ?
				    jstr(n, "nh-interface") : "");
				h_fmt(h, "</span><span class=\"nhg-bar\" title=\""
				    "weight %lld of %lld\"><i style=\"width:"
				    "%lld%%\"></i></span><span class=\"nhg-pct\">"
				    "%lld%%</span><span class=\"dim nhg-meta\">"
				    "weight %lld · nexthop %lld</span></div>",
				    wt, sum, sum > 0 ? wt * 100 / sum : 0, sum >
				    0 ? (wt * 100 + sum / 2) / sum : 0, wt,
				    (long long)jint(n, "nh-index", 0));
			}
			h_raw(h, "</div></td></tr>");
			/* What each carried: a row of its own, the table's width. */
			if (net_scope()[0] == '\0') {
				h_raw(h, "<tr class=\"nhg-carried\"><td colspan=\"3\">");
				ecmp_group(h, s, g);
				h_raw(h, "</td></tr>");
			}
		}
		free(rows);
		h_raw(h, "</tbody></table>");
	}
	if (shown == 0)
		h_raw(h, "<div class=\"empty\"><p>No route of this host has "
		    "several next hops. One is made by a route with several "
		    "gateways, <code>10.0.0.1@2,10.0.0.2@1</code>, each with "
		    "its share after the @, or by a second route to a "
		    "destination that has one.</p></div>");
	return (shown);
}

/* A count of bytes, in the unit that keeps it short. */
void
fmt_bytes(char *buf, size_t len, int64_t n)
{
	static const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
	double	v;
	int	u;

	v = (double)n;
	for (u = 0; v >= 1024 && u < 4; u++)
		v /= 1024;
	snprintf(buf, len, u == 0 ? "%.0f %s" : "%.1f %s", v, units[u]);
}

/* Is name an interface that was made, and so can be destroyed? */
static bool
cloned(const char *name)
{
	static const char *const types[] = { "epair", "gif", "gre", "ipsec",
	    "me", "vxlan", "vlan", "bridge", "lagg", "tap", "tun", "wg",
	    "ovpn" };
	size_t	i, len;

	for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		len = strlen(types[i]);
		if (strncmp(name, types[i], len) == 0 && name[len] >= '0' &&
		    name[len] <= '9')
			return (true);
	}
	return (strncmp(name, "lo", 2) == 0 && name[2] > '0' && name[2] <= '9');
}

/*
 * The interfaces: one row each, with its addresses as chips that can be
 * taken off, a way to add one, and to bring it up or down.  The filter
 * matches the name, the description and the addresses.
 */
static int
interfaces(struct html *h, const struct server *s, const ucl_object_t *arr)
{
	static const struct tcol cols[] = {
		{ "Interface", "name", false }, { "State", "up", false },
		{ "Addresses", NULL, false }, { "MTU", "mtu", true },
		{ "Ether", "ether", false }, { "In / out", "ibytes", true },
		{ "Now", NULL, false },
	};
	const ucl_object_t	*o, *a, **rows;
	ucl_object_iter_t	 ait;
	const char		*name;
	char			 buf[96], in[24], out[24];
	bool			 up, match;
	int			 n, r;

	h_raw(h, "<table class=\"net ifaces\">");
	tbl_head(h, "ifaces", cols, 7, 1);
	h_raw(h, "<tbody>");
	n = 0;
	/* In the order asked for; the filter is this table's own, which
	 * looks at the addresses too. */
	rows = tbl_rows("ifaces", arr, cols, 7, NULL);
	for (r = 0; (o = rows[r]) != NULL; r++) {
		if ((name = jstr(o, "name")) == NULL)
			continue;
		match = app.filter[0] == '\0' || strstr(name, app.filter) !=
		    NULL || (jstr(o, "description") != NULL && strstr(jstr(o,
		    "description"), app.filter) != NULL);
		ait = NULL;
		while (!match && (a = ucl_object_iterate(jget(o, "addresses"),
		    &ait, true)) != NULL)
			match = jstr(a, "address") != NULL && strstr(jstr(a,
			    "address"), app.filter) != NULL;
		if (!match)
			continue;
		n++;
		up = jbool(o, "up");
		h_fmt(h, "<tr class=\"iface %s\"", up ? "up" : "down");
		h_attr(h, "data-if", name);
		h_raw(h, "><td><i class=\"led\"></i><b>");
		h_txt(h, name);
		h_raw(h, "</b>");
		if (jstr(o, "description") != NULL) {
			h_raw(h, "<small>");
			h_txt(h, jstr(o, "description"));
			h_raw(h, "</small>");
		}
		if (jstr(o, "tunnel.local") != NULL) {
			h_raw(h, "<small>tunnel ");
			h_txt(h, jstr(o, "tunnel.local"));
			h_raw(h, " → ");
			h_txt(h, jstr(o, "tunnel.remote") != NULL ? jstr(o,
			    "tunnel.remote") : "?");
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td>");
		h_txt(h, up ? "up" : "down");
		if (jstr(o, "link") != NULL && strcmp(jstr(o, "link"),
		    "unknown") != 0) {
			h_raw(h, "<small>link ");
			h_txt(h, jstr(o, "link"));
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td><ul class=\"chips\">");
		ait = NULL;
		while ((a = ucl_object_iterate(jget(o, "addresses"), &ait,
		    true)) != NULL) {
			if (jstr(a, "address") == NULL)
				continue;
			if (jget(a, "prefixlen") != NULL)
				snprintf(buf, sizeof(buf), "%s/%lld", jstr(a,
				    "address"), (long long)jint(a, "prefixlen",
				    0));
			else
				snprintf(buf, sizeof(buf), "%s", jstr(a,
				    "address"));
			/* ifconfig takes a scoped address without its zone. */
			h_raw(h, "<li class=\"chip\"><span>");
			h_txt(h, buf);
			if (jstr(a, "destination") != NULL) {
				h_raw(h, " → ");
				h_txt(h, jstr(a, "destination"));
			}
			h_raw(h, "</span><button class=\"icon\" "
			    "data-act=\"if-addr-remove\" title=\"Remove\"");
			h_attr(h, "data-arg", name);
			snprintf(buf, sizeof(buf), "%.*s", (int)strcspn(jstr(a,
			    "address"), "%"), jstr(a, "address"));
			h_attr(h, "data-value", buf);
			h_raw(h, ">×</button></li>");
		}
		h_raw(h, "<li><button class=\"ghost small\" "
		    "data-act=\"if-addr-add\"");
		h_attr(h, "data-arg", name);
		h_raw(h, ">+ address</button></li></ul></td><td>");
		if (jget(o, "mtu") != NULL) {
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(o,
			    "mtu", 0));
			h_txt(h, buf);
		}
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(o, "ether"));
		h_raw(h, "</td><td>");
		fmt_bytes(in, sizeof(in), jint(o, "ibytes", 0));
		fmt_bytes(out, sizeof(out), jint(o, "obytes", 0));
		snprintf(buf, sizeof(buf), "%s / %s", in, out);
		h_txt(h, buf);
		if (jint(o, "ierrors", 0) + jint(o, "oerrors", 0) > 0) {
			snprintf(buf, sizeof(buf), "%lld errors",
			    (long long)(jint(o, "ierrors", 0) + jint(o,
			    "oerrors", 0)));
			h_raw(h, "<small class=\"err\">");
			h_txt(h, buf);
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td>");
		topo_spark(h, s, name);
		h_fmt(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
		    "data-act=\"%s\"", up ? "if-down" : "if-up");
		h_attr(h, "data-arg", name);
		h_fmt(h, ">%s</button><button class=\"ghost small\" "
		    "data-act=\"if-edit\" title=\"MTU and description\"", up ?
		    "Down" : "Up");
		h_attr(h, "data-arg", name);
		snprintf(buf, sizeof(buf), "%lld %s", (long long)jint(o, "mtu",
		    0), jstr(o, "description") != NULL ? jstr(o,
		    "description") : "");
		h_attr(h, "data-value", buf);
		h_raw(h, ">Edit</button>");
		if (net_scope()[0] != '\0' && strncmp(name, "lo", 2) != 0) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "if-vnet-back\" title=\"Take this interface out "
			    "of the jail, back to its host\"");
			h_attr(h, "data-arg", name);
			h_raw(h, ">To host</button>");
		}
		if (cloned(name)) {
			h_raw(h, "<button class=\"icon\" data-act=\""
			    "if-destroy\" title=\"Destroy this interface\"");
			h_attr(h, "data-arg", name);
			h_raw(h, ">×</button>");
		}
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	return (n);
}

/*
 * Whose network this is: the host's, or a vnet jail's of it that runs.
 * A plugin's tab offers only where the plugin is.
 */
static void
net_jail_pick(struct html *h, const struct server *s)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;
	const char		*plugin, *name;
	int			 n;

	plugin = kind_plugin(app.net.kind);
	n = 0;
	it = NULL;
	while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL)
		if (net_jail_ok(j) && (plugin == NULL || plugin_at(s, jstr(j,
		    "name"), plugin)) && (strcmp(jstr(j, "name"), net_scope())
		    == 0 || (jstr(j, "state") != NULL && strcmp(jstr(j, "state"),
		    "running") == 0)))
			n++;
	if (n == 0 && net_scope()[0] == '\0')
		return;
	h_raw(h, "<label class=\"net-jail\" title=\"Whose network: the "
	    "host's, or a jail's own (vnet), read and changed from the host"
	    "\"><select data-input=\"net-jail\">");
	if (plugin == NULL || plugin_at(s, "", plugin)) {
		h_fmt(h, "<option value=\"\"%s>", net_scope()[0] == '\0' ?
		    " selected" : "");
		h_txt(h, s->name);
		h_raw(h, "</option>");
	}
	it = NULL;
	while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		/* Those that run, and the one picked even if it stopped. */
		if (!net_jail_ok(j) || (plugin != NULL && !plugin_at(s, jstr(j,
		    "name"), plugin)) || (strcmp(jstr(j, "name"), net_scope())
		    != 0 && (jstr(j, "state") == NULL || strcmp(jstr(j, "state"),
		    "running") != 0)))
			continue;
		name = jstr(j, "name");
		h_raw(h, "<option");
		h_attr(h, "value", name);
		if (strcmp(name, net_scope()) == 0)
			h_raw(h, " selected");
		h_raw(h, ">jail ");
		h_txt(h, name);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label>");
}

void
view_network(struct html *h, struct server *s)
{
	static const struct {
		const char	*arg, *title;
	} kinds[] = {
		{ "routes", "Routes" }, { "nexthops", "Nexthops" },
		{ "connections", "Connections" }, { "sockets", "Sockets" },
		{ "interfaces", "Interfaces" }, { "netgraph", "Netgraph" },
		{ "wireguard", "WireGuard" }, { "bird", "BIRD" },
		{ "bridges", "Bridges" }, { "geneve", "Geneve" },
		{ "nhgroups", "Nexthop groups" }, { "neighbours", "Neighbours" },
		{ "ipsec", "IPsec" },
	};
	const ucl_object_t	*fam, *arr;
	ucl_object_iter_t	 it;
	char			 age[32];
	int			 i, n, shown;
	bool			 mine, plug, nh;

	mine = app.net.data != NULL && strcmp(app.net.sid, s->id) == 0 &&
	    strcmp(app.net.jail, net_scope()) == 0;
	/*
	 * A plugin's view stands by itself: it is a tab of its own, and
	 * what the base system has is not offered beside it.
	 */
	plug = NET_PLUGIN(app.net.kind);
	h_raw(h, "<div class=\"toolbar\">");
	net_jail_pick(h, s);
	h_raw(h, "<nav class=\"sub\">");
	/* The nexthop groups are of the Nexthops, not a tab of their own. */
	nh = app.net.kind == NET_NEXTHOPS || app.net.kind == NET_NHGROUPS;
	for (i = 0; i < 6 && !plug; i++)
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"net-kind\" "
		    "data-arg=\"%s\">%s</button>", (int)app.net.kind == i ||
		    (i == NET_NEXTHOPS && nh) ? " on" : "", kinds[i].arg,
		    kinds[i].title);
	/* What is of the base system too, and came later. */
	for (i = 8; i < (int)(sizeof(kinds) / sizeof(kinds[0])) && !plug;
	    i++)
		if (i != NET_NHGROUPS && !NET_PLUGIN(i))
			h_fmt(h, "<button class=\"ghost small%s\" data-act=\""
			    "net-kind\" data-arg=\"%s\">%s</button>",
			    (int)app.net.kind == i ? " on" : "", kinds[i].arg,
			    kinds[i].title);
	h_raw(h, "</nav>");
	if (nh)
		h_fmt(h, "<nav class=\"sub\" title=\"A nexthop is where a "
		    "route sends; a group is what a route of several next "
		    "hops (ECMP) sends through, each with its share\"><button "
		    "class=\"ghost small%s\" data-act=\"net-kind\" data-arg="
		    "\"nexthops\">Each nexthop</button><button class=\"ghost "
		    "small%s\" data-act=\"net-kind\" data-arg=\"nhgroups\">"
		    "Groups</button></nav>", app.net.kind ==
		    NET_NEXTHOPS ? " on" : "", app.net.kind == NET_NHGROUPS ?
		    " on" : "");
	h_raw(h, "<nav class=\"sub\">");
	for (i = 0; i < 3 && !plug; i++) {
		static const int fams[] = { 0, 4, 6 };

		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"net-family\" "
		    "data-arg=\"%d\">%s</button>", app.net.family == fams[i] ?
		    " on" : "", fams[i], fams[i] == 0 ? "all" : fams[i] == 4 ?
		    "inet" : "inet6");
	}
	h_raw(h, "</nav>");
	if (app.net.kind == NET_INTERFACES)
		h_raw(h, "<button class=\"ghost small\" data-act=\""
		    "topo-if-create\" data-arg=\"\" title=\"Create an epair, a "
		    "tunnel, a bridge, a VLAN…\">+ interface</button>");
	if (app.net.kind == NET_INTERFACES && net_scope()[0] != '\0')
		h_raw(h, "<button class=\"ghost small\" data-act=\""
		    "if-vnet-give\" title=\"Give the jail an interface of "
		    "its host, or one end of a new epair\">+ from host"
		    "</button>");
	if (app.net.kind == NET_ROUTES || app.net.kind == NET_NEXTHOPS) {
		h_raw(h, "<label class=\"fib\" title=\"The routing table "
		    "(FIB) shown and changed\">fib<input data-input=\""
		    "net-fib\" inputmode=\"numeric\" size=\"2\"");
		if (app.net.fib > 0)
			h_fmt(h, " value=\"%d\"", app.net.fib);
		h_raw(h, " placeholder=\"0\"></label>");
	}
	if (app.net.kind == NET_ROUTES)
		h_raw(h, "<button class=\"ghost small\" data-act=\"net-lookup\" "
		    "title=\"Which route this host takes to an address, and "
		    "the others that cover it\">Look up a route</button>"
		    "<button class=\"ghost small\" data-act=\"route-add\" "
		    "title=\"Add a static route\">+ route</button>"
		    "<button class=\"ghost small\" data-act=\"net-search\" "
		    "title=\"Search the whole table on the host for the text "
		    "in the filter: for tables too large to send\">Search "
		    "host</button>");
	/* What changes by itself is read again by itself, unless paused. */
	if (app.net.kind == NET_CONNECTIONS || app.net.kind == NET_SOCKETS)
		h_fmt(h, "<button class=\"ghost small live%s\" data-act=\""
		    "net-live\" title=\"Read again every two seconds while "
		    "this is shown\"><span class=\"led\"></span>Live</button>",
		    app.net.paused ? "" : " on");
	h_raw(h, "<input class=\"filter\" id=\"filter\" data-input="
	    "\"filter\" placeholder=\"Filter rows\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, ">");
	if (mine) {
		fmt_age(age, sizeof(age), app.net.fetched);
		h_raw(h, "<span class=\"tally\">");
		h_txt(h, age);
		h_raw(h, "</span>");
	}
	h_raw(h, "</div>");
	if (app.net.error[0] != '\0' && strcmp(app.net.sid, s->id) == 0) {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, app.net.error);
		h_raw(h, "</div>");
	}
	if (!mine) {
		h_raw(h, app.net.loading ? "<div class=\"empty\"><div class="
		    "\"loader\"></div></div>" : "<div class=\"empty\"><h2>No "
		    "data</h2><p>The host has not answered yet.</p></div>");
		return;
	}
	/*
	 * A routing table too large to send: say how large, and that the
	 * host can be searched; and say what it was searched for.
	 */
	if (app.net.kind == NET_ROUTES && (jget(app.net.data, "total") !=
	    NULL || app.net.host_filter[0] != '\0')) {
		h_raw(h, "<div class=\"notice info routes-cut\">");
		if (jget(app.net.data, "total") != NULL)
			h_fmt(h, "The table has <b>%lld</b> routes, too many to "
			    "send. ", (long long)jint(app.net.data, "total", 0));
		if (app.net.host_filter[0] != '\0') {
			h_raw(h, "These are the rows containing <code>");
			h_txt(h, app.net.host_filter);
			h_raw(h, "</code>");
			if (jbool(app.net.data, "truncated"))
				h_fmt(h, ", the first %d of them", routes_held());
			h_raw(h, ". <button class=\"ghost small\" data-act=\""
			    "net-search-clear\">Clear</button>");
		} else
			h_fmt(h, "These are its first %d. <b>More</b>, below "
			    "them, reads on; or type what to look for in the "
			    "filter, a prefix or an interface, and press <b>"
			    "Search host</b>.", routes_held());
		h_raw(h, "</div>");
	}
	shown = 0;
	switch (app.net.kind) {
	case NET_ROUTES:
	case NET_NEXTHOPS:
		arr = jget(app.net.data, app.net.kind == NET_ROUTES ?
		    "data.statistics.route-information.route-table.rt-family" :
		    "data.statistics.route-nhop-information.nhop-table."
		    "rt-family");
		it = NULL;
		while ((fam = ucl_object_iterate(arr, &it, true)) != NULL) {
			h_raw(h, "<h4 class=\"family\">");
			h_txt(h, jstr(fam, "address-family"));
			h_raw(h, "</h4>");
			n = app.net.kind == NET_ROUTES ? table(h, jget(fam,
			    "rt-entry"), routes_cols, 11, jstr(fam,
			    "address-family") != NULL ? jstr(fam,
			    "address-family") : "") : table(h, jget(fam,
			    "nh-entry"), nexthops_cols, 10, NULL);
			shown += n;
		}
		/* The table goes on: the next of it, after these. */
		if (app.net.kind == NET_ROUTES && jbool(app.net.data,
		    "truncated"))
			h_fmt(h, "<div class=\"more\"><button class=\"ghost\" "
			    "data-act=\"net-more\"%s>%s</button><span class=\""
			    "dim\">%d of %lld here</span></div>",
			    app.net.loading ? " disabled" : "", app.net.loading ?
			    "Reading…" : "More", routes_held(), (long long)jint(
			    app.net.data, "total", 0));
		break;
	case NET_CONNECTIONS:
		shown = table(h, jget(app.net.data, "data.statistics.socket"),
		    conn_cols, 6, NULL);
		break;
	case NET_INTERFACES:
		shown = interfaces(h, s, jget(app.net.data, "data.interfaces"));
		break;
	case NET_NETGRAPH:
		view_netgraph(h, s, jget(app.net.data, "data.nodes"));
		return;
	case NET_WIREGUARD:
		view_wireguard(h, s, jget(app.net.data, "data"));
		return;
	case NET_BIRD:
		view_bird(h, s, jget(app.net.data, "data"));
		return;
	case NET_IPSEC:
		view_ipsec(h, s, jget(app.net.data, "data"));
		return;
	case NET_BRIDGES:
		view_bridges(h, s, jget(app.net.data, "data.bridges"));
		return;
	case NET_NHGROUPS:
		shown = nhgroups(h, s, jget(app.net.data, "data.statistics."
		    "route-nhgrp-information.nhgrp-table.rt-family"));
		break;
	case NET_GENEVE:
		view_geneve(h, s, jget(app.net.data, "data.geneves"));
		return;
	case NET_NEIGHBOURS:
		shown = table(h, jget(app.net.data, "data.neighbours"),
		    neigh_cols, 6, NULL);
		break;
	default:
		shown = table(h, jget(app.net.data, "data.sockstat.socket"),
		    sock_cols, 7, NULL);
		break;
	}
	if (shown == 0)
		h_raw(h, "<div class=\"empty\"><p>Nothing to show.</p></div>");
}

/*
 * Connections, sockets and neighbours change by themselves: while one
 * of them is shown, and nobody paused it, it is read again every two
 * seconds, without a task of its own in the activity.
 */
void
net_live_tick(double now)
{
	struct server	*s;

	if (!app.visible || app.net.paused || app.net.loading ||
	    app.node != NODE_HOST || app.tab != TAB_NETWORK ||
	    (app.net.kind != NET_CONNECTIONS && app.net.kind != NET_SOCKETS &&
	    app.net.kind != NET_NEIGHBOURS))
		return;
	if ((s = cur_server()) == NULL || strcmp(app.net.sid, s->id) != 0 ||
	    app.net.data == NULL || now - app.net.fetched < 2000)
		return;
	refresh_network(s, false);
}


/*
 * A route's nexthop, or the group of its ways, in a box over the routes:
 * read from the host when asked, as the Nexthops tab has it.
 */
static struct {
	char		 sid[9];
	long long	 id;
	bool		 group;
	ucl_object_t	*data;
	bool		 loading;
	char		 error[200];
} nb;

static void
nhop_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	nb.loading = false;
	if (status != 200 || !jbool(o, "ok")) {
		snprintf(nb.error, sizeof(nb.error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	if (nb.data != NULL)
		ucl_object_unref(nb.data);
	nb.data = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
}

bool
nhop_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 url[400];

	if (strcmp(act, "net-nhop-all") == 0) {
		app.modal = MODAL_NONE;
		if ((s = cur_server()) != NULL) {
			app.net.kind = nb.group ? NET_NHGROUPS : NET_NEXTHOPS;
			app.net.sort = -1;
			app.net.loading = false;
			refresh_network(s, true);
		}
		return (true);
	}
	if (strcmp(act, "net-nhop") != 0 || (s = cur_server()) == NULL)
		return (strcmp(act, "net-nhop") == 0);
	snprintf(nb.sid, sizeof(nb.sid), "%s", s->id);
	nb.id = atoll(arg);
	nb.group = strcmp(value, "group") == 0;
	if (nb.data != NULL)
		ucl_object_unref(nb.data);
	nb.data = NULL;
	nb.error[0] = '\0';
	nb.loading = true;
	app.modal = MODAL_NHOP;
	app.modal_error[0] = '\0';
	snprintf(url, sizeof(url), "/api/servers/%s/net/%s?family=all%s%s",
	    s->id, nb.group ? "nhgroups" : "nexthops", net_scope()[0] != '\0' ?
	    "&jail=" : "", net_scope());
	api("GET", url, NULL, nhop_cb, NULL);
	return (true);
}

/* A field of the box: a name, and what it is. */
static void
nhop_field(struct html *h, const char *name, const char *v)
{

	if (v == NULL || v[0] == '\0')
		return;
	h_raw(h, "<dt>");
	h_txt(h, name);
	h_raw(h, "</dt><dd class=\"mono\">");
	h_txt(h, v);
	h_raw(h, "</dd>");
}

void
nhop_modal(struct html *h)
{
	static const struct {
		const char	*key, *name;
	} fields[] = {
		{ "type_str", "Type" }, { "gateway", "Gateway" },
		{ "interface-name", "Interface" },
		{ "address-interface-name", "Address of" }, { "ifa", "Address" },
		{ "mtu", "MTU" }, { "flags", "Flags" }, { "refcount", "Routes" },
		{ "use", "Used" },
	};
	const ucl_object_t	*fams, *fam, *e, *found;
	ucl_object_iter_t	 it, eit;
	struct server		*s;
	size_t			 i;

	h_fmt(h, "<form data-form=\"nhop\" class=\"wide\"><h2>%s %lld</h2>",
	    nb.group ? "Nexthop group" : "Nexthop", nb.id);
	if (nb.loading) {
		h_raw(h, "<div class=\"empty\"><div class=\"loader\"></div>"
		    "</div>");
		return;
	}
	if (nb.error[0] != '\0') {
		h_raw(h, "<p class=\"err\">");
		h_txt(h, nb.error);
		h_raw(h, "</p>");
		return;
	}
	fams = jget(nb.data, nb.group ? "statistics.route-nhgrp-information."
	    "nhgrp-table.rt-family" : "statistics.route-nhop-information."
	    "nhop-table.rt-family");
	found = NULL;
	it = NULL;
	while (found == NULL && (fam = ucl_object_iterate(fams, &it, true)) !=
	    NULL) {
		eit = NULL;
		while ((e = ucl_object_iterate(jget(fam, nb.group ?
		    "nhgrp-entry" : "nh-entry"), &eit, true)) != NULL)
			if (jint(e, nb.group ? "nhgrp-index" : "index", -1) ==
			    nb.id) {
				found = e;
				break;
			}
	}
	if (found == NULL) {
		h_raw(h, "<p class=\"dim\">The host has it no longer: the route "
		    "changed since the table was read.</p>");
	} else if (nb.group) {
		h_fmt(h, "<p class=\"dim\">Shared by %lld route%s; each of its "
		    "next hops with its weight, and what each carried as the "
		    "agents sampled it.</p><div class=\"nhg-hops\">",
		    (long long)jint(found, "nhg-refcnt", 0), jint(found,
		    "nhg-refcnt", 0) == 1 ? "" : "s");
		eit = NULL;
		while ((e = ucl_object_iterate(jget(found, "nhop-weights"),
		    &eit, true)) != NULL) {
			h_raw(h, "<div class=\"nhg-hop\"><span class=\"mono "
			    "nhg-gw\">");
			h_txt(h, jstr(e, "nh-gw") != NULL ? jstr(e, "nh-gw") :
			    "?");
			h_raw(h, "</span><span class=\"nhg-if\">");
			h_txt(h, jstr(e, "nh-interface") != NULL ? jstr(e,
			    "nh-interface") : "");
			h_fmt(h, "</span><span class=\"dim nhg-meta\">weight "
			    "%lld · nexthop %lld</span></div>", (long long)jint(e,
			    "nh-weight", 0), (long long)jint(e, "nh-index", 0));
		}
		h_raw(h, "</div>");
		if ((s = cur_server()) != NULL && net_scope()[0] == '\0')
			ecmp_group(h, s, found);
	} else {
		h_raw(h, "<dl class=\"kv\">");
		for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
			e = jget(found, fields[i].key);
			nhop_field(h, fields[i].name, e != NULL &&
			    ucl_object_type(e) != UCL_NULL ?
			    ucl_object_tostring_forced(e) : NULL);
		}
		h_raw(h, "</dl>");
	}
	h_fmt(h, "<p><button type=\"button\" class=\"ghost small\" "
	    "data-act=\"net-nhop-all\">Every %s of the host</button></p>",
	    nb.group ? "group" : "nexthop");
}
