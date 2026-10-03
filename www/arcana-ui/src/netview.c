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

static void	cell(struct html *, const ucl_object_t *, const struct column *);
static int	table(struct html *, const ucl_object_t *, const struct column *,
		    size_t, const char *);
static void	route_delete(struct html *, const ucl_object_t *, const char *);
static int	cmp_rows(const void *, const void *);
static int	interfaces(struct html *, const ucl_object_t *);
static void	fmt_bytes(char *, size_t, int64_t);

/* What qsort(3) compares by: the sorted column of the table drawn. */
static const struct column	*sort_col;
static bool			 sort_desc;

/* Numbers as numbers, everything else as text. */
static int
cmp_rows(const void *a, const void *b)
{
	const ucl_object_t	*x, *y;
	const char		*sx, *sy;
	char			*ex, *ey;
	double			 dx, dy;
	int			 r;

	x = jget(*(const ucl_object_t *const *)a, sort_col->path);
	y = jget(*(const ucl_object_t *const *)b, sort_col->path);
	sx = x != NULL ? ucl_object_tostring_forced(x) : "";
	sy = y != NULL ? ucl_object_tostring_forced(y) : "";
	dx = strtod(sx, &ex);
	dy = strtod(sy, &ey);
	if (*sx != '\0' && *sy != '\0' && *ex == '\0' && *ey == '\0')
		r = dx < dy ? -1 : dx > dy ? 1 : 0;
	else
		r = strcmp(sx, sy);
	return (sort_desc ? -r : r);
}

/* One cell: the value at path, or "a:b" with path2, as text. */
static void
cell(struct html *h, const ucl_object_t *e, const struct column *c)
{
	const ucl_object_t	*v;

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

/* A table of the entries in the array; the rows shown. */
static int
table(struct html *h, const ucl_object_t *arr, const struct column *cols,
    size_t ncols, const char *family)
{
	const ucl_object_t	*e, **rows;
	ucl_object_iter_t	 it;
	size_t			 i, c, n, cap;
	bool			 sorted;

	sorted = app.net.sort >= 0 && (size_t)app.net.sort < ncols;
	h_raw(h, "<table class=\"net\"><thead><tr>");
	for (i = 0; i < ncols; i++) {
		h_fmt(h, "<th class=\"sortable%s\" data-act=\"net-sort\" "
		    "data-arg=\"%zu\" title=\"Sort by this column\">",
		    sorted && (size_t)app.net.sort == i ? app.net.sort_desc ?
		    " desc" : " asc" : "", i);
		h_txt(h, cols[i].title);
		h_raw(h, "</th>");
	}
	if (family != NULL)
		h_raw(h, "<th></th>");
	h_raw(h, "</tr></thead><tbody>");
	/* The rows that pass the filter, then in the order asked for. */
	rows = NULL;
	n = cap = 0;
	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (app.filter[0] != '\0') {
			char *line = (char *)ucl_object_emit(e,
			    UCL_EMIT_JSON_COMPACT);
			bool hit = line != NULL && strstr(line, app.filter) !=
			    NULL;

			free(line);
			if (!hit)
				continue;
		}
		if (n == cap) {
			cap = cap == 0 ? 256 : cap * 2;
			if ((rows = reallocarray(rows, cap, sizeof(*rows))) ==
			    NULL)
				abort();
		}
		rows[n++] = e;
	}
	if (sorted && n > 1) {
		sort_col = &cols[app.net.sort];
		sort_desc = app.net.sort_desc;
		qsort(rows, n, sizeof(*rows), cmp_rows);
	}
	for (i = 0; i < n; i++) {
		h_raw(h, "<tr>");
		for (c = 0; c < ncols; c++)
			cell(h, rows[i], &cols[c]);
		if (family != NULL)
			route_delete(h, rows[i], family);
		h_raw(h, "</tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	return ((int)n);
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

/* A count of bytes, in the unit that keeps it short. */
static void
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

/*
 * The interfaces: one row each, with its addresses as chips that can be
 * taken off, a way to add one, and to bring it up or down.  The filter
 * matches the name, the description and the addresses.
 */
static int
interfaces(struct html *h, const ucl_object_t *arr)
{
	const ucl_object_t	*o, *a;
	ucl_object_iter_t	 it, ait;
	const char		*name;
	char			 buf[96], in[24], out[24];
	bool			 up, match;
	int			 n;

	h_raw(h, "<table class=\"net ifaces\"><thead><tr><th>Interface</th>"
	    "<th>State</th><th>Addresses</th><th>MTU</th><th>Ether</th>"
	    "<th>In / out</th><th></th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while ((o = ucl_object_iterate(arr, &it, true)) != NULL) {
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
		h_fmt(h, "</td><td><button class=\"ghost small\" "
		    "data-act=\"%s\"", up ? "if-down" : "if-up");
		h_attr(h, "data-arg", name);
		h_fmt(h, ">%s</button></td></tr>", up ? "Down" : "Up");
	}
	h_raw(h, "</tbody></table>");
	return (n);
}

void
view_network(struct html *h, struct server *s)
{
	static const struct {
		const char	*arg, *title;
	} kinds[] = {
		{ "routes", "Routes" }, { "nexthops", "Nexthops" },
		{ "connections", "Connections" }, { "sockets", "Sockets" },
		{ "interfaces", "Interfaces" },
	};
	const ucl_object_t	*fam, *arr;
	ucl_object_iter_t	 it;
	char			 age[32];
	int			 i, n, shown;
	bool			 mine;

	mine = app.net.data != NULL && strcmp(app.net.sid, s->id) == 0;
	h_raw(h, "<div class=\"toolbar\"><nav class=\"sub\">");
	for (i = 0; i < 5; i++)
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"net-kind\" "
		    "data-arg=\"%s\">%s</button>", (int)app.net.kind == i ?
		    " on" : "", kinds[i].arg, kinds[i].title);
	h_raw(h, "</nav><nav class=\"sub\">");
	for (i = 0; i < 3; i++) {
		static const int fams[] = { 0, 4, 6 };

		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"net-family\" "
		    "data-arg=\"%d\">%s</button>", app.net.family == fams[i] ?
		    " on" : "", fams[i], fams[i] == 0 ? "all" : fams[i] == 4 ?
		    "inet" : "inet6");
	}
	h_raw(h, "</nav>");
	if (app.net.kind == NET_ROUTES)
		h_raw(h, "<button class=\"ghost small\" data-act=\"route-add\" "
		    "title=\"Add a static route\">+ route</button>"
		    "<button class=\"ghost small\" data-act=\"net-search\" "
		    "title=\"Search the whole table on the host for the text "
		    "in the filter: for tables too large to send\">Search "
		    "host</button>");
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
			h_fmt(h, "</code>%s. <button class=\"ghost small\" "
			    "data-act=\"net-search-clear\">Clear</button>",
			    jbool(app.net.data, "truncated") ? ", the first "
			    "2000 of them" : "");
		} else
			h_raw(h, "These are its first 2000. Type what to look "
			    "for in the filter, a prefix or an interface, and "
			    "press <b>Search host</b>.");
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
			    "rt-entry"), routes_cols, 7, jstr(fam,
			    "address-family") != NULL ? jstr(fam,
			    "address-family") : "") : table(h, jget(fam,
			    "nh-entry"), nexthops_cols, 10, NULL);
			shown += n;
		}
		break;
	case NET_CONNECTIONS:
		shown = table(h, jget(app.net.data, "data.statistics.socket"),
		    conn_cols, 6, NULL);
		break;
	case NET_INTERFACES:
		shown = interfaces(h, jget(app.net.data, "data.interfaces"));
		break;
	default:
		shown = table(h, jget(app.net.data, "data.sockstat.socket"),
		    sock_cols, 7, NULL);
		break;
	}
	if (shown == 0)
		h_raw(h, "<div class=\"empty\"><p>Nothing to show.</p></div>");
}
