/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Network section's BGP, OSPF and BFD tabs: every session of every
 * BIRD in the fleet, hosts and vnet jails, in one table and one graph.
 * What each BIRD says is what the map reads of it (topo.c), read every
 * poll while one of these tabs is shown.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	RT_SIDE		40	/* routers, or peers, drawn at most */
#define	RT_EDGES	160

enum { RT_BGP, RT_OSPF, RT_BFD };

static const struct tcol	bgp_cols[] = {
	{ "Router", "where", false },
	{ "Protocol", "proto", false },
	{ "Neighbour", "peer", false },
	{ "AS", "as", true },
	{ "Local AS", "las", true },
	{ "State", "state", false },
	{ "Since", "since", false },
	{ "Imported", "imp", true },
	{ "Exported", "exp", true },
	{ "Last error", "err", false },
};
static const struct tcol	ospf_cols[] = {
	{ "Router", "where", false },
	{ "Protocol", "proto", false },
	{ "Neighbour ID", "rid", false },
	{ "Priority", "pri", true },
	{ "State", "state", false },
	{ "Dead in", "dtime", false },
	{ "Interface", "if", false },
	{ "Address", "peer", false },
};
static const struct tcol	bfd_cols[] = {
	{ "Router", "where", false },
	{ "Protocol", "proto", false },
	{ "Address", "peer", false },
	{ "Interface", "if", false },
	{ "State", "state", false },
	{ "Since", "since", false },
	{ "Interval (s)", "intv", true },
	{ "Timeout (s)", "tmo", true },
};

/* A field as text, whether BIRD's reading made it text or a number. */
static const char *
val(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	if ((v = jget(o, key)) == NULL || ucl_object_type(v) == UCL_NULL)
		return ("");
	return (ucl_object_tostring_forced(v));
}

static void
put(ucl_object_t *row, const char *key, const char *s)
{

	ucl_object_insert_key(row, ucl_object_fromstring(s != NULL ? s : ""),
	    key, 0, true);
}

/* up, warn or down: how a session's state reads, as BIRD words it. */
static const char *
bgp_class(const ucl_object_t *o)
{
	const char	*st;

	st = val(o, "state");
	return (strcmp(st, "up") == 0 ? "up" : strcmp(st, "down") == 0 ?
	    "down" : "warn");
}

static const char *
ospf_class(const char *st)
{

	/* Two routers neither of which is the DR stop at 2-Way: as it
	 * should be. */
	return (strncmp(st, "Full", 4) == 0 || strncmp(st, "2-Way", 5) == 0 ?
	    "up" : strncmp(st, "Down", 4) == 0 ? "down" : "warn");
}

static const char *
bfd_class(const char *st)
{

	return (strcmp(st, "Up") == 0 ? "up" : strcmp(st, "Down") == 0 ||
	    strcmp(st, "AdminDown") == 0 ? "down" : "warn");
}

/* A BGP protocol's routes, over its channels. */
static void
bgp_routes(const ucl_object_t *o, long long *imp, long long *exp)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;

	*imp = *exp = 0;
	it = NULL;
	while ((c = ucl_object_iterate(jget(o, "channels"), &it, true)) !=
	    NULL) {
		*imp += strtoll(val(c, "imported"), NULL, 10);
		*exp += strtoll(val(c, "exported"), NULL, 10);
	}
}

/* Every session of one kind across the fleet, a row each. */
static ucl_object_t *
rows_build(int kind)
{
	const ucl_object_t	*bird, *o;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr, *r;
	const char		*key, *label, *st;
	char			 n[32];
	long long		 imp, exp;
	int			 i;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; (i = topo_bird_next(i, &key, &label, &bird)) != -1; i++) {
		it = NULL;
		while ((o = ucl_object_iterate(jget(bird, kind == RT_BGP ?
		    "protocols" : kind == RT_OSPF ? "ospf" : "bfd"), &it,
		    true)) != NULL) {
			if (kind == RT_BGP && strcmp(val(o, "proto"), "BGP") != 0)
				continue;
			r = ucl_object_typed_new(UCL_OBJECT);
			put(r, "where", label);
			put(r, "key", key);
			put(r, "proto", val(o, kind == RT_BGP ? "name" :
			    "proto"));
			switch (kind) {
			case RT_BGP:
				put(r, "peer", val(o, "neighbor"));
				put(r, "as", val(o, "neighbor-as"));
				put(r, "las", val(o, "local-as"));
				st = val(o, "bgp-state");
				put(r, "state", st[0] != '\0' ? st : val(o,
				    "info")[0] != '\0' ? val(o, "info") :
				    val(o, "state"));
				put(r, "cls", bgp_class(o));
				put(r, "since", val(o, "since"));
				put(r, "desc", val(o, "description"));
				bgp_routes(o, &imp, &exp);
				snprintf(n, sizeof(n), "%lld", imp);
				put(r, "imp", n);
				snprintf(n, sizeof(n), "%lld", exp);
				put(r, "exp", n);
				put(r, "err", val(o, "last-error"));
				break;
			case RT_OSPF:
				put(r, "rid", val(o, "router-id"));
				put(r, "pri", val(o, "pri"));
				put(r, "state", val(o, "state"));
				put(r, "cls", ospf_class(val(o, "state")));
				put(r, "dtime", val(o, "dtime"));
				put(r, "if", val(o, "interface"));
				put(r, "peer", val(o, "address"));
				break;
			default:
				put(r, "peer", val(o, "address"));
				put(r, "if", val(o, "interface"));
				put(r, "state", val(o, "state"));
				put(r, "cls", bfd_class(val(o, "state")));
				put(r, "since", val(o, "since"));
				put(r, "intv", val(o, "interval"));
				put(r, "tmo", val(o, "timeout"));
				break;
			}
			put(r, "peerhost", topo_addr_node(val(r, "peer")));
			ucl_array_append(arr, r);
		}
	}
	return (arr);
}

/* A figure with its caption: how many are as they should be, of all. */
static void
tile(struct html *h, int up, int all, const char *what, const char *ok)
{

	h_fmt(h, "<div class=\"tile %s\"><b>", all == 0 ? "" : up == all ?
	    "ok" : "warn");
	if (all == 0)
		h_raw(h, "—</b><span>");
	else
		h_fmt(h, "%d<small> of %d</small></b><span>", up, all);
	h_txt(h, what);
	if (all > 0) {
		h_raw(h, " · ");
		h_txt(h, up == all ? ok : "not all");
	}
	h_raw(h, "</span></div>");
}

/* What the fleet's BIRDs say, in figures. */
static void
tiles(struct html *h)
{
	const ucl_object_t	*arr, *o;
	ucl_object_iter_t	 it;
	ucl_object_t		*rows;
	long long		 routes;
	char			 buf[32];
	int			 k, up[3], all[3], i, routers;
	const char		*key, *label;
	const ucl_object_t	*bird;

	for (k = RT_BGP; k <= RT_BFD; k++) {
		rows = rows_build(k);
		up[k] = all[k] = 0;
		it = NULL;
		while ((o = ucl_object_iterate(rows, &it, true)) != NULL) {
			all[k]++;
			if (strcmp(val(o, "cls"), "up") == 0)
				up[k]++;
		}
		ucl_object_unref(rows);
	}
	routes = routers = 0;
	for (i = 0; (i = topo_bird_next(i, &key, &label, &bird)) != -1; i++) {
		routers++;
		arr = jget(bird, "tables");
		it = NULL;
		while ((o = ucl_object_iterate(arr, &it, true)) != NULL)
			routes += strtoll(val(o, "routes"), NULL, 10);
	}
	h_raw(h, "<div class=\"tiles rt-tiles\">");
	h_fmt(h, "<div class=\"tile\"><b>%d</b><span>router%s with BIRD"
	    "</span></div>", routers, routers == 1 ? "" : "s");
	tile(h, up[RT_BGP], all[RT_BGP], "BGP sessions", "all established");
	tile(h, up[RT_OSPF], all[RT_OSPF], "OSPF neighbours", "all full");
	tile(h, up[RT_BFD], all[RT_BFD], "BFD sessions", "all up");
	if (routes >= 1000000)
		snprintf(buf, sizeof(buf), "%.1fM", routes / 1e6);
	else if (routes >= 10000)
		snprintf(buf, sizeof(buf), "%.1fk", routes / 1e3);
	else
		snprintf(buf, sizeof(buf), "%lld", routes);
	h_fmt(h, "<div class=\"tile\"><b>%s</b><span>routes in their tables"
	    "</span></div></div>", buf);
}

/* The index of s in v[0..n), added at the end if not there; -1: full. */
static int
slot(char v[][96], int *n, const char *s)
{
	int	i;

	for (i = 0; i < *n; i++)
		if (strcmp(v[i], s) == 0)
			return (i);
	if (*n == RT_SIDE)
		return (-1);
	snprintf(v[*n], sizeof(v[0]), "%s", s);
	return ((*n)++);
}

/* A line from a router to what it speaks to: its sessions, together. */
struct redge {
	int	a, b;
	int	n, worst;		/* 0 up, 1 warn, 2 down */
	char	title[600];
};

/* What a peer is drawn as: a host of the fleet, an AS, a router ID. */
struct rpeer {
	char	key[96];
	char	label[96];
	char	names[160];		/* its sessions' protocols */
	char	one[96];		/* the sub of a single session */
	int	n;
	bool	fleet;
};

static int
worst_of(const char *cls)
{

	return (strcmp(cls, "down") == 0 ? 2 : strcmp(cls, "warn") == 0 ? 1 :
	    0);
}

/*
 * The routers on the left, what they speak to on the right: a host of
 * the fleet, else BGP's neighbour AS, OSPF's router ID, BFD's address.
 * A line a router and a peer, in the colour of the worst of its
 * sessions, their number on it when more than one; OSPF dashed, BFD
 * dotted.  Each session is in the table under it.
 */
static void
graph(struct html *h, int kind, const ucl_object_t **rows)
{
	static const char *const wcls[] = { "up", "warn", "down" };
	static char		 left[RT_SIDE][96];
	static struct rpeer	 pr[RT_SIDE];
	static struct redge	 ed[RT_EDGES];
	const ucl_object_t	*r, *lr[RT_SIDE];
	struct rpeer		*p;
	struct redge		*e;
	char			 key[96], sub[160], line[160];
	int			 nl, nr, ne, a, b, i, j, rows_n, more;
	double			 yl, yr, height;
	size_t			 len;

	nl = nr = ne = more = 0;
	for (i = 0; (r = rows[i]) != NULL; i++) {
		a = slot(left, &nl, val(r, "key"));
		if (a != -1)
			lr[a] = r;
		if (val(r, "peerhost")[0] != '\0')
			snprintf(key, sizeof(key), "h:%s", val(r, "peerhost"));
		else if (kind == RT_BGP && val(r, "as")[0] != '\0')
			snprintf(key, sizeof(key), "as:%s", val(r, "as"));
		else if (kind == RT_OSPF && val(r, "rid")[0] != '\0')
			snprintf(key, sizeof(key), "id:%s", val(r, "rid"));
		else
			snprintf(key, sizeof(key), "ad:%s", val(r, "peer"));
		for (b = 0; b < nr && strcmp(pr[b].key, key) != 0; b++)
			;
		if (b == nr && nr < RT_SIDE) {
			p = &pr[nr++];
			memset(p, 0, sizeof(*p));
			snprintf(p->key, sizeof(p->key), "%s", key);
			p->fleet = key[0] == 'h';
			if (p->fleet)
				snprintf(p->label, sizeof(p->label), "%s", val(r,
				    "peerhost"));
			else if (key[0] == 'a' && key[1] == 's')
				snprintf(p->label, sizeof(p->label), "AS%s%s",
				    val(r, "as"), strcmp(val(r, "as"), val(r,
				    "las")) == 0 ? " · iBGP" : "");
			else
				snprintf(p->label, sizeof(p->label), "%s",
				    key + 3);
			snprintf(p->one, sizeof(p->one), "%s · %s", val(r,
			    "proto"), kind == RT_OSPF ? val(r, "if") : val(r,
			    "peer"));
		}
		if (a == -1 || b == nr) {
			more++;
			continue;
		}
		p = &pr[b];
		p->n++;
		len = strlen(p->names);
		if (strstr(p->names, val(r, "proto")) == NULL && len + 2 <
		    sizeof(p->names))
			snprintf(p->names + len, sizeof(p->names) - len, "%s%s",
			    len > 0 ? ", " : "", val(r, "proto"));
		for (j = 0; j < ne && (ed[j].a != a || ed[j].b != b); j++)
			;
		if (j == ne) {
			if (ne == RT_EDGES) {
				more++;
				continue;
			}
			e = &ed[ne++];
			memset(e, 0, sizeof(*e));
			e->a = a;
			e->b = b;
		}
		e = &ed[j];
		e->n++;
		if (worst_of(val(r, "cls")) > e->worst)
			e->worst = worst_of(val(r, "cls"));
		snprintf(line, sizeof(line), "%s%s %s: %s", e->n > 1 ? "\n" :
		    "", val(r, "proto"), val(r, "peer"), val(r, "state"));
		len = strlen(e->title);
		if (len + strlen(line) + 1 < sizeof(e->title))
			snprintf(e->title + len, sizeof(e->title) - len, "%s",
			    line);
	}
	if (ne == 0)
		return;
	rows_n = nl > nr ? nl : nr;
	height = 24 + rows_n * 52;
	h_fmt(h, "<div class=\"map-wrap rtgraph\"><svg class=\"rtg %s\" "
	    "viewBox=\"0 0 1000 %.0f\" role=\"img\" aria-label=\"Sessions "
	    "between the fleet's routers and their neighbours\">",
	    kind == RT_BGP ? "bgp" : kind == RT_OSPF ? "ospf" : "bfd", height);
	/* The lines first, under the boxes. */
	for (i = 0; i < ne; i++) {
		e = &ed[i];
		yl = 12 + (e->a + 0.5) * (height - 24) / nl;
		yr = 12 + (e->b + 0.5) * (height - 24) / nr;
		h_fmt(h, "<g class=\"edge %s\"><path d=\"M250 %.1f C500 %.1f "
		    "500 %.1f 750 %.1f\"/>", wcls[e->worst], yl, yl, yr, yr);
		if (e->n > 1)
			h_fmt(h, "<text class=\"cnt\" x=\"720\" y=\"%.1f\">%d"
			    "</text>", yr - 5, e->n);
		h_raw(h, "<title>");
		h_txt(h, val(lr[e->a], "where"));
		h_raw(h, " → ");
		h_txt(h, pr[e->b].label);
		h_raw(h, "\n");
		h_txt(h, e->title);
		h_raw(h, "</title></g>");
	}
	for (a = 0; a < nl; a++) {
		r = lr[a];
		yl = 12 + (a + 0.5) * (height - 24) / nl;
		h_fmt(h, "<g class=\"rnode mine\" transform=\"translate(20,%.1f)"
		    "\" data-act=\"rt-open\"", yl);
		h_attr(h, "data-arg", val(r, "key"));
		h_raw(h, "><rect x=\"0\" y=\"-20\" width=\"230\" height=\"40\" "
		    "rx=\"8\"/><text class=\"name\" x=\"12\" y=\"5\">");
		h_fit(h, val(r, "where"), 28);
		h_raw(h, "</text><title>");
		h_txt(h, val(r, "where"));
		h_raw(h, ": its BIRD</title></g>");
	}
	for (b = 0; b < nr; b++) {
		p = &pr[b];
		yr = 12 + (b + 0.5) * (height - 24) / nr;
		if (p->n > 1)
			snprintf(sub, sizeof(sub), "%d sessions: %s", p->n,
			    p->names);
		else
			snprintf(sub, sizeof(sub), "%s", p->one);
		h_fmt(h, "<g class=\"rnode %s\" transform=\"translate(750,%.1f)"
		    "\"><rect x=\"0\" y=\"-20\" width=\"230\" height=\"40\" "
		    "rx=\"8\"/><text class=\"name\" x=\"12\" y=\"-2\">",
		    p->fleet ? "fleet" : "outside", yr);
		h_fit(h, p->label, 28);
		h_raw(h, "</text><text class=\"sub\" x=\"12\" y=\"13\">");
		h_fit(h, sub, 34);
		h_raw(h, "</text><title>");
		h_txt(h, p->label);
		h_raw(h, p->fleet ? " · a host of the fleet\n" : " · outside "
		    "the fleet\n");
		h_txt(h, sub);
		h_raw(h, "</title></g>");
	}
	h_fmt(h, "</svg><ul class=\"map-legend rt-legend\"><li class=\"up\">"
	    "%s</li><li class=\"warn\">%s</li><li class=\"down\">%s</li>"
	    "<li class=\"fleet\">a host of the fleet</li><li class=\"cnt\">"
	    "<b>3</b> sessions on a line: its colour the worst</li></ul>",
	    kind == RT_BGP ? "Established" : kind == RT_OSPF ?
	    "Full, or 2-Way" : "Up", kind == RT_BGP ? "Connecting (Active, "
	    "Connect, OpenSent…)" : kind == RT_OSPF ? "Forming (Init, "
	    "ExStart, Loading…)" : "Init", kind == RT_BGP ? "Down, or turned off" :
	    "Down");
	if (more > 0)
		h_fmt(h, "<p class=\"dim\">And %d more, in the table.</p>", more);
	h_raw(h, "</div>");
}

/* A cell: text, or a dash when BIRD did not say. */
static void
cell(struct html *h, const ucl_object_t *r, const char *key, const char *cls)
{

	h_fmt(h, "<td%s%s%s>", cls != NULL ? " class=\"" : "", cls != NULL ?
	    cls : "", cls != NULL ? "\"" : "");
	h_txt(h, val(r, key)[0] != '\0' ? val(r, key) : "—");
	h_raw(h, "</td>");
}

static void
table(struct html *h, int kind, const char *id, const struct tcol *cols,
    int ncols, const ucl_object_t **rows)
{
	const ucl_object_t	*r;
	int			 i;

	h_fmt(h, "<table class=\"net rt %s\">", id);
	tbl_head(h, id, cols, ncols, 0);
	h_raw(h, "<tbody>");
	for (i = 0; (r = rows[i]) != NULL; i++) {
		h_fmt(h, "<tr class=\"pick\" data-act=\"rt-open\"");
		h_attr(h, "data-arg", val(r, "key"));
		h_attr(h, "data-value", val(r, "proto"));
		h_raw(h, " title=\"Open it in its host's BIRD\"><td><b>");
		h_txt(h, val(r, "where"));
		h_raw(h, "</b></td>");
		cell(h, r, "proto", "mono");
		if (kind == RT_OSPF)
			cell(h, r, "rid", "mono");
		else {
			h_raw(h, "<td class=\"mono\">");
			h_txt(h, val(r, "peer"));
			if (val(r, "peerhost")[0] != '\0') {
				h_raw(h, "<small>");
				h_txt(h, val(r, "peerhost"));
				h_raw(h, "</small>");
			}
			h_raw(h, "</td>");
		}
		switch (kind) {
		case RT_BGP:
			cell(h, r, "as", "num");
			cell(h, r, "las", "num");
			break;
		case RT_OSPF:
			cell(h, r, "pri", "num");
			break;
		default:
			cell(h, r, "if", "mono");
			break;
		}
		h_fmt(h, "<td><span class=\"chip %s\">", strcmp(val(r, "cls"),
		    "up") == 0 ? "ok" : strcmp(val(r, "cls"), "down") == 0 ?
		    "bad" : "warn");
		h_txt(h, val(r, "state")[0] != '\0' ? val(r, "state") : "?");
		h_raw(h, "</span></td>");
		switch (kind) {
		case RT_BGP:
			cell(h, r, "since", NULL);
			cell(h, r, "imp", "num");
			cell(h, r, "exp", "num");
			cell(h, r, "err", val(r, "err")[0] != '\0' ? "err" :
			    NULL);
			break;
		case RT_OSPF:
			cell(h, r, "dtime", "num");
			cell(h, r, "if", "mono");
			h_raw(h, "<td class=\"mono\">");
			h_txt(h, val(r, "peer"));
			if (val(r, "peerhost")[0] != '\0') {
				h_raw(h, "<small>");
				h_txt(h, val(r, "peerhost"));
				h_raw(h, "</small>");
			}
			h_raw(h, "</td>");
			break;
		default:
			cell(h, r, "since", NULL);
			cell(h, r, "intv", "num");
			cell(h, r, "tmo", "num");
			break;
		}
		h_raw(h, "</tr>");
	}
	h_raw(h, "</tbody></table>");
}

void
view_routing(struct html *h)
{
	static const char *const names[] = { "BGP", "OSPF", "BFD" };
	static const char *const what[] = { "session", "neighbour",
	    "session" };
	const ucl_object_t	**rows;
	const struct tcol	 *cols;
	ucl_object_t		 *all;
	const char		 *id;
	int			  kind, routers, asking, ncols, n, total;

	kind = app.netsect == NETSECT_OSPF ? RT_OSPF : app.netsect ==
	    NETSECT_BFD ? RT_BFD : RT_BGP;
	routers = topo_bird_hosts(&asking);
	if (routers == 0) {
		h_raw(h, "<div class=\"empty\"><p>No host of the fleet runs "
		    "BIRD.</p><p class=\"dim\">BGP, OSPF and BFD are read from "
		    "BIRD (net/bird2) on each host or vnet jail where its "
		    "plugin is on, with <code>birdc</code> over its control "
		    "socket.</p></div>");
		return;
	}
	h_fmt(h, "<p class=\"dim rt-note\">%s across the fleet: what each BIRD "
	    "says, read every few seconds with <code>birdc</code>. A row "
	    "opens the protocol in its host's BIRD.</p>", names[kind]);
	tiles(h);
	if (asking == routers) {
		h_fmt(h, "<div class=\"empty\"><p>Asking %d BIRD%s…</p></div>",
		    routers, routers == 1 ? "" : "s");
		return;
	}
	cols = kind == RT_BGP ? bgp_cols : kind == RT_OSPF ? ospf_cols :
	    bfd_cols;
	ncols = kind == RT_BGP ? 10 : 8;
	id = kind == RT_BGP ? "rt-bgp" : kind == RT_OSPF ? "rt-ospf" :
	    "rt-bfd";
	all = rows_build(kind);
	total = (int)ucl_array_size(all);
	if (total == 0) {
		h_fmt(h, "<div class=\"empty\"><p>No %s %s in any BIRD of the "
		    "fleet.</p><p class=\"dim\">A %s protocol is added in a "
		    "host's Network tab, under BIRD.</p></div>", names[kind],
		    what[kind], names[kind]);
		ucl_object_unref(all);
		return;
	}
	rows = tbl_rows(id, all, cols, ncols, app.filter);
	for (n = 0; rows[n] != NULL; n++)
		;
	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\"filter\" "
	    "data-input=\"filter\" placeholder=\"Filter by router, neighbour, "
	    "state…\" autocomplete=\"off\" spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_fmt(h, "><span class=\"tally\"><b>%d</b> of %d %s%s</span></div>", n,
	    total, what[kind], total == 1 ? "" : "s");
	if (n == 0) {
		h_raw(h, "<div class=\"empty\"><p>None has “");
		h_txt(h, app.filter);
		h_raw(h, "”.</p></div>");
	} else {
		graph(h, kind, rows);
		table(h, kind, id, cols, ncols, rows);
	}
	free(rows);
	ucl_object_unref(all);
}

bool
routing_action(const char *act, const char *arg, const char *value)
{

	if (strcmp(act, "rt-open") != 0)
		return (false);
	if (topo_bird_open(arg) && value != NULL && value[0] != '\0')
		bird_show(value);
	return (true);
}
