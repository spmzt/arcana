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
		    size_t);
static int	cmp_rows(const void *, const void *);

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
    size_t ncols)
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
		h_raw(h, "</tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	return ((int)n);
}

void
view_network(struct html *h, struct server *s)
{
	static const struct {
		const char	*arg, *title;
	} kinds[] = {
		{ "routes", "Routes" }, { "nexthops", "Nexthops" },
		{ "connections", "Connections" }, { "sockets", "Sockets" },
	};
	const ucl_object_t	*fam, *arr;
	ucl_object_iter_t	 it;
	char			 age[32];
	int			 i, n, shown;
	bool			 mine;

	mine = app.net.data != NULL && strcmp(app.net.sid, s->id) == 0;
	h_raw(h, "<div class=\"toolbar\"><nav class=\"sub\">");
	for (i = 0; i < 4; i++)
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
	h_raw(h, "</nav><input class=\"filter\" id=\"filter\" data-input="
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
			    "rt-entry"), routes_cols, 7) : table(h, jget(fam,
			    "nh-entry"), nexthops_cols, 10);
			shown += n;
		}
		break;
	case NET_CONNECTIONS:
		shown = table(h, jget(app.net.data, "data.statistics.socket"),
		    conn_cols, 6);
		break;
	default:
		shown = table(h, jget(app.net.data, "data.sockstat.socket"),
		    sock_cols, 7);
		break;
	}
	if (shown == 0)
		h_raw(h, "<div class=\"empty\"><p>Nothing to show.</p></div>");
}
