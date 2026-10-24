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

static void	view_multicast(struct html *, const ucl_object_t *);
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
	const char		*k2[16];
	const ucl_object_t	**rows;
	char			 id[48];
	size_t			 i, c;

	for (c = 0; c < ncols && c < 16; c++) {
		tc[c].title = cols[c].title;
		tc[c].key = cols[c].path;
		tc[c].num = false;
		k2[c] = cols[c].path2;
	}
	snprintf(id, sizeof(id), "net-%d-%s", (int)app.net.kind, family !=
	    NULL ? family : "");
	h_raw(h, "<table class=\"net\">");
	tbl_head(h, id, tc, (int)c, family != NULL ? 1 : 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows2(id, arr, tc, k2, (int)c, app.filter);
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
 * The neighbours, each with a way to take it away: one set by hand
 * (permanent) for good, one learnt to be learnt again.
 */
static int
neigh_table(struct html *h, const ucl_object_t *arr)
{
	struct tcol		 tc[6];
	const ucl_object_t	**rows;
	const char		*a;
	size_t			 i, c;

	for (c = 0; c < 6; c++) {
		tc[c].title = neigh_cols[c].title;
		tc[c].key = neigh_cols[c].path;
		tc[c].num = false;
	}
	h_raw(h, "<table class=\"net\">");
	tbl_head(h, "net-neigh", tc, 6, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("net-neigh", arr, tc, 6, app.filter);
	for (i = 0; rows[i] != NULL; i++) {
		h_raw(h, "<tr>");
		for (c = 0; c < 6; c++)
			cell(h, rows[i], &neigh_cols[c]);
		h_raw(h, "<td>");
		a = jstr(rows[i], "address");
		if (a != NULL && strcmp(jstr(rows[i], "lladdr") != NULL ?
		    jstr(rows[i], "lladdr") : "", "(incomplete)") != 0) {
			h_raw(h, "<button class=\"icon\" data-act=\""
			    "neigh-delete\" title=\"Take it away (arp -d, ndp "
			    "-d); kept in rc.conf, forgotten there too\"");
			h_attr(h, "data-arg", a);
			h_raw(h, ">×</button>");
		}
		h_raw(h, "</td></tr>");
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
 * The static routes rc.conf keeps (static_routes, ipv6_static_routes),
 * each by its name: a new name for it, or forgotten there, the kernel's
 * table left as it is.  A variable no list names, which rc.d/routing
 * leaves, and a name without its variable are said so; the default
 * routers, of each table, under them.
 */
static const struct column kept_cols[] = {
	{ "Name", "name", NULL },
	{ "Destination", "destination", NULL },
	{ "Gateway", "gateway", NULL },
	{ "Kind", "kind", NULL },
	{ "FIB", "fib", NULL },
	{ "Family", "family", NULL },
};

static int
kept_table(struct html *h, const ucl_object_t *data)
{
	struct tcol		 tc[7];
	const ucl_object_t	**rows, *r, *d;
	ucl_object_iter_t	 it;
	char			 v[96];
	const char		*dest;
	size_t			 i, c, n;

	for (c = 0; c < 6; c++) {
		tc[c].title = kept_cols[c].title;
		tc[c].key = kept_cols[c].path;
		tc[c].num = c == 4;
	}
	tc[6].title = "Value";
	tc[6].key = "value";
	tc[6].num = false;
	h_raw(h, "<table class=\"net kept\">");
	tbl_head(h, "net-kept", tc, 7, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("net-kept", jget(data, "routes"), tc, 7, app.filter);
	for (i = 0; rows[i] != NULL; i++) {
		r = rows[i];
		h_raw(h, "<tr>");
		for (c = 0; c < 6; c++)
			cell(h, r, &kept_cols[c]);
		h_raw(h, "<td class=\"mono dim\">");
		if (jstr(r, "value") != NULL)
			h_txt(h, jstr(r, "value"));
		if (jbool(r, "missing"))
			h_raw(h, "<span class=\"kept-note\" title=\"The list "
			    "names it, rc.conf has no variable for it: rc(8) "
			    "skips it\">no variable</span>");
		else if (!jbool(r, "listed"))
			h_raw(h, " <span class=\"kept-note\" title=\"No list "
			    "names it: rc.d/routing does not add it at "
			    "boot\">not listed</span>");
		h_raw(h, "</td><td>");
		dest = jstr(r, "destination");
		if (dest != NULL && jbool(r, "listed")) {
			snprintf(v, sizeof(v), "%lld %s", (long long)jint(r,
			    "fib", 0), jstr(r, "name") != NULL ? jstr(r,
			    "name") : "");
			h_raw(h, "<button class=\"icon\" data-act=\"kept-rename\" "
			    "title=\"Keep it by another name, its words as they "
			    "are\"");
			h_attr(h, "data-arg", dest);
			h_attr(h, "data-value", v);
			h_raw(h, ">✎</button>");
			snprintf(v, sizeof(v), "%lld", (long long)jint(r, "fib",
			    0));
			h_raw(h, "<button class=\"icon\" data-act=\"kept-forget\" "
			    "title=\"Forget it in rc.conf: not added at the next "
			    "boot; the kernel's table as it is\"");
			h_attr(h, "data-arg", dest);
			h_attr(h, "data-value", v);
			h_raw(h, ">×</button>");
		}
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	n = i;
	/* The default routers: rc.conf's own variables, not by a name. */
	d = jget(data, "defaults");
	if (d != NULL && ucl_array_size(d) > 0) {
		h_raw(h, "<h3 class=\"kept-h\">Default routers</h3><table class="
		    "\"net\"><thead><tr><th>Variable</th><th>Gateway</th><th>"
		    "FIB</th><th>Family</th></tr></thead><tbody>");
		it = NULL;
		while ((r = ucl_object_iterate(d, &it, true)) != NULL) {
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(r, "variable") != NULL ? jstr(r,
			    "variable") : "");
			h_raw(h, "</td><td>");
			h_txt(h, jstr(r, "gateway") != NULL ? jstr(r,
			    "gateway") : "");
			h_fmt(h, "</td><td>%lld</td><td>", (long long)jint(r,
			    "fib", 0));
			h_txt(h, jstr(r, "family") != NULL ? jstr(r, "family") :
			    "");
			h_raw(h, "</td></tr>");
		}
		h_raw(h, "</tbody></table>");
		n++;
	}
	return ((int)n);
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
		    "description"), app.filter) != NULL) || (label_of(s->id,
		    name) != NULL && strstr(label_of(s->id, name), app.filter) !=
		    NULL);
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
		/* The console's own label, beside the host's description. */
		label_cell(h, s->id, name);
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
			    "data-act=\"if-addr-edit\" title=\"Change it\"");
			h_attr(h, "data-arg", name);
			{
				char	full[160];
				size_t	z = strcspn(jstr(a, "address"), "%");

				if (jget(a, "prefixlen") != NULL)
					snprintf(full, sizeof(full), "%.*s/%lld",
					    (int)z, jstr(a, "address"), (long long)
					    jint(a, "prefixlen", 0));
				else
					snprintf(full, sizeof(full), "%.*s", (int)z,
					    jstr(a, "address"));
				h_attr(h, "data-value", full);
			}
			h_raw(h, ">&#9998;</button><button class=\"icon\" "
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
		/* Its tables, when not the first: FIB, and a tunnel's outer. */
		if (jint(o, "fib", 0) > 0 || jint(o, "tunnelfib", 0) > 0) {
			snprintf(buf, sizeof(buf), "%s%lld%s%s%lld", jint(o,
			    "fib", 0) > 0 ? "fib " : "", (long long)jint(o, "fib",
			    0), jint(o, "fib", 0) > 0 && jint(o, "tunnelfib", 0) >
			    0 ? ", " : "", jint(o, "tunnelfib", 0) > 0 ?
			    "tunnelfib " : "", (long long)jint(o, "tunnelfib",
			    0));
			h_raw(h, "<small>");
			h_txt(h, buf);
			h_raw(h, "</small>");
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
		    "data-act=\"if-edit\" title=\"MTU, description and tables\"",
		    up ? "Down" : "Up");
		h_attr(h, "data-arg", name);
		snprintf(buf, sizeof(buf), "%lld %lld %lld %s", (long long)jint(o,
		    "mtu", 0), (long long)jint(o, "fib", 0), (long long)jint(o,
		    "tunnelfib", 0), jstr(o, "description") != NULL ? jstr(o,
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
 * A plugin's tab offers each, saying where the plugin is not installed:
 * there it can be.
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
		if (net_jail_ok(j) && (strcmp(jstr(j, "name"), net_scope())
		    == 0 || (jstr(j, "state") != NULL && strcmp(jstr(j, "state"),
		    "running") == 0)))
			n++;
	if (n == 0 && net_scope()[0] == '\0')
		return;
	h_raw(h, "<label class=\"net-jail\" title=\"Whose network: the "
	    "host's, or a jail's own (vnet), read and changed from the host"
	    "\"><select data-input=\"net-jail\">");
	h_fmt(h, "<option value=\"\"%s>", net_scope()[0] == '\0' ?
	    " selected" : "");
	h_txt(h, s->name);
	if (plugin != NULL && !plugin_at(s, "", plugin))
		h_raw(h, " (not installed)");
	h_raw(h, "</option>");
	it = NULL;
	while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		/* Those that run, and the one picked even if it stopped. */
		if (!net_jail_ok(j) || (strcmp(jstr(j, "name"), net_scope())
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
		if (plugin != NULL && !plugin_at(s, name, plugin))
			h_raw(h, " (not installed)");
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label>");
}

/*
 * A plugin's tab where its program is not installed: what it needs,
 * and a button that installs it with pkg(8), on the host or in the
 * jail picked.  Nothing is installed but when that is pressed.
 */
static void
plugin_missing(struct html *h, const struct server *s)
{
	const struct plugin_pkg	*pp;
	const char		*where;

	if ((pp = plugin_pkg(kind_plugin(app.net.kind))) == NULL)
		return;
	h_raw(h, "<div class=\"empty plugin-missing\"><h2>");
	h_txt(h, pp->title);
	h_raw(h, " is not installed ");
	if (net_scope()[0] != '\0') {
		h_raw(h, "in the jail ");
		h_txt(h, net_scope());
	} else {
		h_raw(h, "on ");
		h_txt(h, s->name);
	}
	h_fmt(h, "</h2><p>This tab works through %s, which comes with the "
	    "package <code>%s</code>. Click the button to install it%s with "
	    "<code>pkg install</code>, for this plugin to work: it is a job "
	    "in the activity bar, and the tab comes alive once it is done."
	    "</p>", pp->program, pp->package, net_scope()[0] != '\0' ?
	    " in the jail" : "");
	if (plugin_installing(s, net_scope()))
		h_fmt(h, "<button class=\"primary\" disabled>Installing "
		    "%s…</button>", pp->package);
	else
		h_fmt(h, "<button class=\"primary\" data-act=\"plugin-install"
		    "\" data-arg=\"%s\">Install %s</button>", pp->plugin,
		    pp->package);
	/* Where it is already: there to look, rather than here. */
	if ((where = plugin_where(s, pp->plugin)) != NULL && strcmp(where,
	    net_scope()) != 0) {
		h_raw(h, "<p class=\"dim\">");
		if (where[0] == '\0') {
			h_raw(h, "The host has it: <button class=\"ghost small\" "
			    "data-act=\"net-jail-set\" data-arg=\"\">Show the "
			    "host's</button>");
		} else {
			h_raw(h, "The jail ");
			h_txt(h, where);
			h_raw(h, " has it: <button class=\"ghost small\" "
			    "data-act=\"net-jail-set\"");
			h_attr(h, "data-arg", where);
			h_raw(h, ">Show the jail's</button>");
		}
		h_raw(h, "</p>");
	}
	h_raw(h, "</div>");
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
		{ "nhgroups", "Load balance" }, { "neighbours", "Neighbours" },
		{ "ipsec", "IPsec" }, { "span", "Span" }, { "carp", "CARP" },
		{ "multicast", "Multicast" }, { "kept-routes", "Kept routes" },
		{ "monitors", "Tunnel quality" },
	};
	const ucl_object_t	*fam, *arr;
	ucl_object_iter_t	 it;
	char			 age[32];
	int			 i, n, shown;
	bool			 mine, plug, nh, rt;

	/* What was read for this view: another's is not drawn as it. */
	mine = app.net.data != NULL && strcmp(app.net.sid, s->id) == 0 &&
	    strcmp(app.net.jail, net_scope()) == 0 && app.net.data_kind ==
	    (int)app.net.kind;
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
	/* What rc.conf keeps is of the Routes, not a tab of its own. */
	rt = app.net.kind == NET_ROUTES || app.net.kind == NET_KEPT;
	/* Routes to WireGuard, the base system's. */
	for (i = 0; i <= NET_WIREGUARD && !plug; i++)
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"net-kind\" "
		    "data-arg=\"%s\">%s</button>", (int)app.net.kind == i ||
		    (i == NET_NEXTHOPS && nh) || (i == NET_ROUTES && rt) ?
		    " on" : "", kinds[i].arg, kinds[i].title);
	/* What is of the base system too, and came later. */
	for (i = 8; i < (int)(sizeof(kinds) / sizeof(kinds[0])) && !plug;
	    i++)
		if (i != NET_NHGROUPS && i != NET_KEPT && !NET_PLUGIN(i))
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
	if (rt)
		h_fmt(h, "<nav class=\"sub\" title=\"The kernel's table now, "
		    "or the static routes rc.conf adds at boot, each by its "
		    "name\"><button class=\"ghost small%s\" data-act=\"net-kind\" "
		    "data-arg=\"routes\">In the table</button><button class="
		    "\"ghost small%s\" data-act=\"net-kind\" data-arg=\""
		    "kept-routes\">Kept in rc.conf</button></nav>",
		    app.net.kind == NET_ROUTES ? " on" : "", app.net.kind ==
		    NET_KEPT ? " on" : "");
	/* rc.conf's routes are of both families, read at once; so are
	 * the tunnels measured. */
	if (app.net.kind != NET_KEPT && app.net.kind != NET_MONITORS) {
		h_raw(h, "<nav class=\"sub\">");
		for (i = 0; i < 3 && !plug && app.net.kind != NET_SPAN; i++) {
			static const int fams[] = { 0, 4, 6 };

			h_fmt(h, "<button class=\"ghost small%s\" data-act="
			    "\"net-family\" data-arg=\"%d\">%s</button>",
			    app.net.family == fams[i] ? " on" : "", fams[i],
			    fams[i] == 0 ? "all" : fams[i] == 4 ? "inet" :
			    "inet6");
		}
		h_raw(h, "</nav>");
	}
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
	if (app.net.kind == NET_CARP)
		h_raw(h, "<button class=\"ghost small\" data-act=\"carp-add\" "
		    "title=\"An address shared with other hosts by carp(4)\">+ "
		    "CARP address</button>");
	if (app.net.kind == NET_NEIGHBOURS)
		h_raw(h, "<button class=\"ghost small\" data-act=\"neigh-add\" "
		    "title=\"An ARP or NDP entry set by hand\">+ neighbour"
		    "</button>");
	if (app.net.kind == NET_KEPT)
		h_raw(h, "<button class=\"ghost small\" data-act=\"route-add\" "
		    "title=\"Add a static route, kept by a name\">+ route"
		    "</button>");
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
	if (app.net.kind != NET_SPAN) {
		h_raw(h, "<input class=\"filter\" id=\"filter\" data-input="
		    "\"filter\" placeholder=\"Filter rows\" autocomplete=\"off\" "
		    "spellcheck=\"false\"");
		h_attr(h, "value", app.filter);
		h_raw(h, ">");
	}
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
	if (plug && s->list != NULL && !has_plugin(s, kind_plugin(
	    app.net.kind))) {
		plugin_missing(h, s);
		/* setkey(8) is the base system's, strongSwan or none. */
		if (app.net.kind == NET_IPSEC)
			view_setkey(h, s);
		return;
	}
	if (!mine) {
		h_raw(h, app.net.loading ? "<div class=\"empty\"><div class="
		    "\"loader\"></div></div>" : "<div class=\"empty\"><h2>No "
		    "data</h2><p>The host has not answered yet.</p></div>");
		return;
	}
	if (app.net.kind == NET_SPAN) {
		view_span(h, s);
		return;
	}
	if (app.net.kind == NET_CARP) {
		view_carp(h, s, jget(app.net.data, "data"));
		return;
	}
	if (app.net.kind == NET_MONITORS) {
		view_monitors(h, s, jget(app.net.data, "data.interfaces"));
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
		view_setkey(h, s);
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
		shown = neigh_table(h, jget(app.net.data, "data.neighbours"));
		break;
	case NET_MULTICAST:
		view_multicast(h, jget(app.net.data, "data"));
		return;
	case NET_KEPT:
		shown = kept_table(h, jget(app.net.data, "data"));
		break;
	default:
		shown = table(h, jget(app.net.data, "data.sockstat.socket"),
		    sock_cols, 7, NULL);
		break;
	}
	if (shown == 0)
		h_raw(h, "<div class=\"empty\"><p>Nothing to show.</p></div>");
}

/* A setting of the kernel's IGMP or MLD, as the read says it. */
static const char *
mcast_setting(const ucl_object_t *d, const char *name)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;

	while ((e = ucl_object_iterate(jget(d, "settings"), &it, true)) !=
	    NULL)
		if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"), name) == 0)
			return (jstr(e, "value"));
	return (NULL);
}

/*
 * An interface's IGMP or MLD as the kernel keeps it, "IGMPv3 · rv 2 ·
 * qi 125 · qri 10 · uri 3": not turned into seconds, for qri is in
 * seconds until a router queries, then that query's Max Response Code.
 */
static void
mcast_proto(struct html *h, const ucl_object_t *p, const char *what)
{

	if (p == NULL) {
		h_raw(h, "—");
		return;
	}
	h_fmt(h, "<span title=\"Robustness variable; query interval (s); query "
	    "response interval: seconds, or after a router's query its Max "
	    "Response Code (%s); unsolicited report interval (s)\">%sv%lld "
	    "<span class=\"dim\">· rv %lld · qi %lld · qri %lld · uri %lld%s%s"
	    "</span></span>", strcmp(what, "IGMP") == 0 ? "tenths of a second" :
	    "milliseconds", what, (long long)jint(p, "version", 0),
	    (long long)jint(p, "rv", 0), (long long)jint(p, "qi", 0),
	    (long long)jint(p, "qri", 0), (long long)jint(p, "uri", 0),
	    jstr(p, "flags") != NULL ? " · " : "", jstr(p, "flags") != NULL ?
	    jstr(p, "flags") : "");
}

/*
 * IGMP and MLD, the Multicast view: the kernel's settings (a form, a
 * sysctl job each, kept at boot when asked); each interface's version
 * and timers; the groups joined, sorted and filtered.
 */
static void
view_multicast(struct html *h, const ucl_object_t *d)
{
	static const struct tcol	cols[] = {
		{ "Interface", "if", false }, { "Family", "family", false },
		{ "Group", "group", false }, { "Mode", "mode", false },
		{ "Sources", "src", false }, { "Link address", "lladdr", false },
	};
	static const struct {
		const char	*name, *label, *title;
	} toggles[] = {
		{ "net.inet.igmp.v1enable", "IGMPv1 heard", "Reports and "
		    "queries of IGMP version 1 are taken" },
		{ "net.inet.igmp.v2enable", "IGMPv2 heard", "Reports and "
		    "queries of IGMP version 2 are taken" },
		{ "net.inet.igmp.legacysupp", "Old routers' way", "An interface "
		    "falls back to the version an older router queries in" },
		{ "net.inet.igmp.sendlocal", "Local groups reported", "Groups "
		    "of 224.0.0.0/24 are reported too" },
		{ "net.inet.igmp.sendra", "Router Alert", "Reports carry the "
		    "IP Router Alert option" },
		{ "net.inet6.mld.v1enable", "MLDv1 heard", "Reports and queries "
		    "of MLD version 1 are taken" },
		{ "net.inet6.mld.v2enable", "MLDv2 heard", "Reports and queries "
		    "of MLD version 2 are taken" },
		{ "net.inet6.mld.use_allow", "MLDv2 ALLOW records", "Joins are "
		    "reported as ALLOW records, not changes of mode" },
	};
	const ucl_object_t	*ifo, *g, *src, **rows, *r;
	ucl_object_iter_t	 it, git, sit;
	ucl_object_t		*arr, *o;
	const char		*v;
	char			 sources[400];
	size_t			 i;
	int			 k;

	/* The kernel's settings, the jail's own in a vnet jail. */
	v = mcast_setting(d, "net.inet.igmp.default_version");
	h_raw(h, "<form data-form=\"mcast-set\" class=\"mcast-set\"><div "
	    "class=\"toolbar\"><label title=\"The IGMP version an interface "
	    "starts with (net.inet.igmp.default_version)\">IGMP version "
	    "<select name=\"net.inet.igmp.default_version\">");
	for (k = 1; k <= 3; k++)
		h_fmt(h, "<option value=\"%d\"%s>%d</option>", k, v != NULL &&
		    atoi(v) == k ? " selected" : "", k);
	h_raw(h, "</select></label>");
	for (i = 0; i < nitems(toggles); i++) {
		v = mcast_setting(d, toggles[i].name);
		if (v == NULL)
			continue;
		h_raw(h, "<label class=\"toggle\"");
		h_attr(h, "title", toggles[i].title);
		h_raw(h, "><input type=\"checkbox\"");
		h_attr(h, "name", toggles[i].name);
		h_fmt(h, "%s><span>", atoi(v) != 0 ? " checked" : "");
		h_txt(h, toggles[i].label);
		h_raw(h, "</span></label>");
	}
	h_raw(h, "<label class=\"toggle\" title=\"Written in sysctl.conf too, "
	    "for the next boot\"><input type=\"checkbox\" name=\"keep\" "
	    "checked><span>Kept at boot</span></label><button class=\"small\">"
	    "Set</button></div></form>");
	/* Each interface's version and timers. */
	h_raw(h, "<table class=\"net mcast-ifs\"><thead><tr><th>Interface</th>"
	    "<th>IGMP</th><th>MLD</th><th>Groups</th></tr></thead><tbody>");
	it = NULL;
	while ((ifo = ucl_object_iterate(jget(d, "interfaces"), &it, true)) !=
	    NULL) {
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(ifo, "name"));
		h_raw(h, "</b></td><td>");
		mcast_proto(h, jget(ifo, "igmp"), "IGMP");
		h_raw(h, "</td><td>");
		mcast_proto(h, jget(ifo, "mld"), "MLD");
		h_fmt(h, "</td><td>%u</td></tr>", ucl_array_size(jget(ifo,
		    "groups")));
	}
	h_raw(h, "</tbody></table>");
	/* The groups joined, a row each. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((ifo = ucl_object_iterate(jget(d, "interfaces"), &it, true)) !=
	    NULL) {
		git = NULL;
		while ((g = ucl_object_iterate(jget(ifo, "groups"), &git,
		    true)) != NULL) {
			/* inet or inet6 alone, as the family picked says. */
			if (app.net.family != 0 && jstr(g, "family") != NULL &&
			    strcmp(jstr(g, "family"), app.net.family == 4 ?
			    "inet" : "inet6") != 0)
				continue;
			o = ucl_object_copy(g);
			ucl_object_insert_key(o, ucl_object_fromstring(jstr(ifo,
			    "name")), "if", 0, true);
			sources[0] = '\0';
			sit = NULL;
			while ((src = ucl_object_iterate(jget(g, "sources"), &sit,
			    true)) != NULL)
				snprintf(sources + strlen(sources), sizeof(sources) -
				    strlen(sources), "%s%s", sources[0] != '\0' ?
				    ", " : "", ucl_object_tostring_forced(src));
			ucl_object_insert_key(o, ucl_object_fromstring(sources),
			    "src", 0, true);
			ucl_array_append(arr, o);
		}
	}
	h_raw(h, "<table class=\"net mcast\">");
	tbl_head(h, "net-mcast", cols, 6, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("net-mcast", arr, cols, 6, app.filter);
	for (k = 0; (r = rows[k]) != NULL; k++) {
		h_raw(h, "<tr><td>");
		h_txt(h, jstr(r, "if"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "family"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "group"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "mode"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "src")[0] != '\0' ? jstr(r, "src") : "any");
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "lladdr") != NULL ? jstr(r, "lladdr") : "—");
		h_raw(h, "</td></tr>");
	}
	if (k == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"6\">No group "
		    "is joined.</td></tr>");
	free(rows);
	h_raw(h, "</tbody></table>");
	ucl_object_unref(arr);
}

/*
 * The Multicast view's settings set: a sysctl job each that differs
 * from what the host said, in the network shown.
 */
bool
mcast_form(const ucl_object_t *f)
{
	static const char *const names[] = {
		"net.inet.igmp.default_version", "net.inet.igmp.v1enable",
		"net.inet.igmp.v2enable", "net.inet.igmp.legacysupp",
		"net.inet.igmp.sendlocal", "net.inet.igmp.sendra",
		"net.inet6.mld.v1enable", "net.inet6.mld.v2enable",
		"net.inet6.mld.use_allow",
	};
	struct server	*s;
	const ucl_object_t *d = jget(app.net.data, "data");
	const ucl_object_t *fv;
	const char	*was;
	char		 want[8], *json, title[200];
	size_t		 i;
	int		 n = 0;
	bool		 keep = jbool(f, "keep");

	if ((s = cur_server()) == NULL || d == NULL)
		return (true);
	for (i = 0; i < nitems(names); i++) {
		if ((was = mcast_setting(d, names[i])) == NULL)
			continue;
		/* The fields by their own names: dots are no path here. */
		fv = ucl_object_lookup(f, names[i]);
		if (i == 0)
			snprintf(want, sizeof(want), "%s", fv != NULL &&
			    ucl_object_type(fv) == UCL_STRING ?
			    ucl_object_tostring(fv) : was);
		else
			snprintf(want, sizeof(want), "%d", fv != NULL &&
			    ucl_object_toboolean(fv) ? 1 : 0);
		if (strcmp(want, was) == 0)
			continue;
		if (asprintf(&json, "{\"kind\":\"sysctl\",\"args\":[\"%s\","
		    "\"%s\"],\"persist\":%s}", names[i], want, keep ? "true" :
		    "false") == -1)
			abort();
		snprintf(title, sizeof(title), "sysctl %s=%s", names[i], want);
		/* Taken over by job_send(); in a jail's network, the jail's. */
		job_send(s, json, title, JOB_IFACE, "multicast");
		n++;
	}
	if (n == 0)
		toast(false, "Nothing to change: the host has these already");
	return (true);
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

/* A neighbour set by hand, or taken away: a job, in the network shown. */
static void
neigh_job(struct server *s, const char *verb, const char *addr,
    const char *ll, bool temp, bool keep)
{
	char	*qa, *ql, *json, title[160];

	qa = json_quote(addr);
	ql = json_quote(ll != NULL ? ll : "");
	if (asprintf(&json, "{\"kind\":\"neighbour\",\"verb\":\"%s\","
	    "\"address\":%s%s%s,\"temporary\":%s,\"live\":true,\"persist\""
	    ":%s}", verb, qa, ll != NULL ? ",\"lladdr\":" : "", ll != NULL ?
	    ql : "", temp ? "true" : "false", keep ? "true" : "false") == -1)
		abort();
	free(qa);
	free(ql);
	snprintf(title, sizeof(title), "neighbour %s %s%s%s", verb, addr, ll !=
	    NULL ? " " : "", ll != NULL ? ll : "");
	job_send(s, json, title, JOB_IFACE, "neighbours");
}

bool
neigh_modal(struct html *h)
{

	if (app.modal != MODAL_NEIGH)
		return (false);
	h_raw(h, "<form data-form=\"neigh\"><h2>A neighbour set by hand</h2>"
	    "<p>An entry of ARP (IPv4) or NDP (IPv6), with <code>arp -s</code> "
	    "or <code>ndp -s</code>: the address on one of the networks here, "
	    "and the link address it is at.</p><label>Address<input name=\""
	    "address\" spellcheck=\"false\" autocomplete=\"off\" "
	    "placeholder=\"192.0.2.5 or 2001:db8::5\" autofocus></label>"
	    "<label>Link address<input name=\"lladdr\" spellcheck=\"false\" "
	    "autocomplete=\"off\" placeholder=\"00:11:22:33:44:55\"></label>"
	    "<label class=\"toggle\"><input type=\"checkbox\" name=\"temp\"> "
	    "It ages out <small>as a learnt one does (temp); without it, it "
	    "stays (permanent)</small></label><label class=\"toggle\"><input "
	    "type=\"checkbox\" name=\"persist\"> Keep it for a boot <small>"
	    "a pair of rc.conf's static_arp_pairs or static_ndp_pairs"
	    "</small></label>");
	return (true);
}

bool
neigh_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*a, *l;

	if (strcmp(form, "neigh") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	a = jstr(f, "address") != NULL ? jstr(f, "address") : "";
	l = jstr(f, "lladdr") != NULL ? jstr(f, "lladdr") : "";
	if (a[0] == '\0' || strchr(a, ' ') != NULL || strlen(l) != 17) {
		snprintf(app.modal_error, sizeof(app.modal_error), "An address, "
		    "and its link address as 00:11:22:33:44:55");
		return (true);
	}
	if (jbool(f, "temp") && jbool(f, "persist")) {
		snprintf(app.modal_error, sizeof(app.modal_error), "One that "
		    "ages out is not kept for a boot");
		return (true);
	}
	neigh_job(s, "add", a, l, jbool(f, "temp"), jbool(f, "persist"));
	app.modal = MODAL_NONE;
	return (true);
}

bool
neigh_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 body[400];

	(void)value;
	if (strncmp(act, "neigh-", 6) != 0 && strcmp(act, "do-neigh-delete") !=
	    0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "neigh-add") == 0) {
		app.modal = MODAL_NEIGH;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "neigh-delete") == 0) {
		snprintf(body, sizeof(body), "%s taken out of the neighbours of "
		    "%s, and out of rc.conf where it is kept there. One learnt "
		    "is learnt again when it is next spoken to.", arg, s->name);
		confirm("Take the neighbour away", body, "Take away", true, "",
		    "do-neigh-delete", arg, "");
	} else if (strcmp(act, "do-neigh-delete") == 0)
		neigh_job(s, "delete", arg, NULL, false, true);
	return (true);
}
