/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The network of the fleet: every host as a node of a map, joined to
 * the others as its interfaces join it.  A link is drawn only between
 * hosts of this console: a tunnel whose far end is an address of
 * another host, a point-to-point address whose peer is one, or two
 * hosts with addresses in the same network.  Nothing is configured for
 * it: it is worked out from what each agent reads with getifaddrs(3).
 *
 * The interfaces are read again every few seconds, and two readings of
 * the counters make a rate: the links carry it, and the panel draws it
 * over time.  The route from one host to another is asked of each host
 * on the way (route-lookup) and drawn over the map, with the routes
 * that would be taken in its place.  A link is made by drawing one:
 * from one node's port to another node, which asks for a tunnel's
 * details and creates its two ends.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	TOPO_POLL_MS	5000
#define	MAX_NODES	(MAX_SERVERS + 32)
#define	TOPO_IFS	64
#define	TOPO_HIST	48
#define	TOPO_LINKS	1024
#define	TOPO_SEGS	48
#define	TOPO_HOPS	16
#define	TOPO_ALTS	3
#define	NODE_W		150
#define	NODE_H		58
/*
 * What of the drawing is seen at a zoom of one: as much as the map has
 * room for on the page, so that a host and what is written on it are
 * as large on a phone as on a wide screen.  Before the map is drawn
 * its room is not known, and is guessed.
 */
#define	VIEW_W		(tp.vw > 0 ? tp.vw : arc_narrow() ? 360.0 : 900.0)
#define	VIEW_H		(tp.vh > 0 ? tp.vh : arc_narrow() ? 450.0 : 560.0)
#define	LEGEND_H	64.0		/* the legend, over the drawing's foot */
#define	TOOLS_H		52.0		/* the buttons, over its head */

struct ifrate {
	char	name[16];
	double	ib, ob;			/* the counters last read */
	float	in[TOPO_HIST];		/* bytes a second, newest last */
	float	out[TOPO_HIST];
	int	n;
};

/* What is known of one host's network. */
struct thost {
	char		 sid[80];	/* the node: a server, or server/jail */
	ucl_object_t	*ifs;		/* its interfaces, as last read */
	double		 fetched;
	double		 time;		/* the host's clock at that reading */
	bool		 loading;
	bool		 failed;
	struct ifrate	 r[TOPO_IFS];
	int		 nr;
	double		 x, y;
	bool		 placed;
	double		 out_a;		/* where its outside neighbours stand */
	bool		 out_set;
	ucl_object_t	*bridges;	/* its bridges, as last read */
	double		 br_fetched;
	bool		 br_loading;
	ucl_object_t	*wg;		/* its WireGuard interfaces */
	bool		 wg_loading;
	ucl_object_t	*bird;		/* what its BIRD says, if it has one */
	bool		 bird_loading;
	int		 fwd4, fwd6;	/* forwards: 0 unknown, 1 no, 2 yes */
	bool		 fwd_loading;
	double		 fwd_fetched;
};

/*
 * A routing neighbour that is not a host of this console: drawn beside
 * the host that speaks to it.
 */
#define	EXT_MAX		512
struct ext {
	int	host;			/* the server it is a neighbour of */
	bool	ospf;			/* or BGP */
	bool	up;
	char	label[40];		/* AS65001, or a router ID */
	char	sub[64];		/* its address, or the protocol */
	int	slot, of;		/* its place among the host's */
};
static struct ext	exts[EXT_MAX];
static int		nexts;

/*
 * A WireGuard tunnel being made between two hosts: each makes its
 * interface and its key, and once both public keys are known each is
 * told of the other as its peer.
 */
#define	WG_PAIRS	8
struct wgpair {
	bool	active;
	char	a[80], b[80];		/* the nodes */
	char	ifa[16], ifb[16];
	char	enda[96], endb[96];	/* where each is reached */
	char	ina[64], inb[64];	/* what each may send from */
	bool	keep;
	double	since;
};
static struct wgpair	wgpairs[WG_PAIRS];

enum { LK_TUNNEL, LK_P2P, LK_LAN, LK_BGP, LK_OSPF, LK_VNET, LK_KINDS };

/* What a line drawn from one host to another makes between them. */
enum { JOIN_TUNNEL, JOIN_BGP, JOIN_OSPF, JOIN_BFD };
static const char *const join_kinds[] = { "tunnel", "bgp", "ospf", "bfd" };

struct tlink {
	int	a, b;			/* servers; b < 0: segment -b - 1 */
	int	kind;
	char	ifa[16], ifb[16];
	char	key[160];		/* what makes it this link */
	char	label[160];
	double	rate;			/* bytes a second, both ways */
	bool	up;
	int	more;			/* networks shared besides the one named */
	bool	ospf_in;		/* an OSPF adjacency runs over it */
	bool	ospf_in_up;
	bool	ospf_stray;		/* OSPF: an adjacency no link carries */
};

/* A network more than two hosts are in: a node of its own. */
struct seg {
	char	net[64];
	int	member[MAX_NODES];
	char	ifn[MAX_NODES][16];
	int	n;
	double	x, y;
	int	same;		/* drawn as segs[same - 1], whose members it has */
	char	more[2][64];	/* the networks drawn as this one too */
};

struct alt {
	char	dest[64], gw[64], ifn[16];
	int	to;			/* the server it leads to, or -1 */
};

struct hop {
	int		from, to;	/* servers; to -1: it leaves the fleet */
	char		dest[64], gw[64], ifn[16], flags[48];
	char		note[160];
	struct alt	alt[TOPO_ALTS];
	int		nalt;
};

/* A node of the map: a server, or a vnet jail of one. */
struct tnode {
	char	key[80];		/* the server's id, or id/jail */
	char	name[65];		/* as its box says it */
	char	label[140];		/* as a list says it: jail · server */
	int	srv;			/* the server, in app.servers */
	char	jail[64];		/* the jail, or "" */
};
static struct tnode	tn[MAX_NODES];
static int		ntn;

static struct thost	hosts[MAX_NODES];
static int		nhosts;
static struct tlink	links[TOPO_LINKS];
static int		nlinks;
static struct seg	segs[TOPO_SEGS];
static bool	seg_same(const struct seg *, const struct seg *);
static bool	node_lone(int);
static bool	node_placed_among(int);
static void	bgp_label(char *, size_t, const char *, const char *);
static int		nsegs;

/* The fleet's shape (topo_shape) and the neighbours' places (peers_layout). */
static bool	tcore[MAX_NODES];
static int	tparent[MAX_NODES];	/* the node a leaf hangs off, or -1 */
static int	tstrip[MAX_NODES], ntstrip;	/* in the order taken away */
static double	peer_x[EXT_MAX], peer_y[EXT_MAX];

static struct {
	double	zoom, panx, pany;
	double	lastcx, lastcy;		/* a pan under way: where it was */
	bool	fitted;			/* shown whole once, at first */
	bool	refitted;		/* and again, with neighbours outside */
	bool	jails;			/* each host's running jails around it */
	bool	novnet;			/* the vnet jails folded into their hosts */
	bool	lonevnet;		/* and those linked to their host alone shown */
	bool	nopeers;		/* routing neighbours outside are hidden */
	char	sel[80];		/* the node picked, or "" */
	char	sel_if[16];		/* and its interface charted */
	char	sel_link[160];		/* or the link picked: its key */
	bool	linking;		/* a link is being drawn */
	char	link_from[80];
	double	link_x, link_y;
	bool	loaded;			/* the places kept were read */
	char	tun_a[80], tun_b[80];	/* the tunnel asked for */
	int	join;			/* what joins them: JOIN_* */
	char	create_sid[80];		/* the node an interface is made on */
	char	create_kind[16];	/* and the kind of interface chosen */
	int	fit_n;			/* the nodes there were when fitted */
	double	vw, vh;			/* the room the map has, in pixels */
	double	fit_w, fit_h;		/* and had when fitted */
	bool	touched;		/* moved, zoomed: no fitting unasked */
	bool	custom;			/* placed by hand: the shape is not followed */
	uint32_t shape_sig;		/* the shape the nodes were placed for */
	int	labels[LK_KINDS];	/* each kind's: 0 as fits, 1 shown,
					   2 left out */
	bool	labels_open;		/* the labels' switches shown */
	bool	no_names, no_rates;	/* the lines' names, their rates, left
					   out of every kind */
	struct bend {
		char	key[160];	/* the link it is of */
		double	bend;		/* how far its middle is drawn out */
	} bends[64];			/* links dragged aside, kept */
	int	nbends;
	bool	bends_loaded;
	struct peerpos {
		char	key[160];	/* host<tab>ospf|bgp<tab>label<tab>sub */
		double	dx, dy;		/* where it was put, from its host */
	} peers[64];			/* neighbours dragged, kept */
	int	npeers;
	bool	peers_loaded;
	bool	hide[LK_KINDS];		/* kinds of links not drawn */
	bool	hide_best, hide_alt;	/* nor the route traced */
	int	fib;			/* the routing table shown alone, or -1 */
	bool	stencil;		/* drawn as a network diagram: glyphs, straight lines */
	double	last_poll;
} tp = { .zoom = 1.0, .fib = -1 };

static struct {
	char		from[80];
	char		to[65];		/* the address looked for */
	char		to_name[80];
	struct hop	hops[TOPO_HOPS];
	int		n;
	int		gen;		/* answers to an older trace are dropped */
	bool		busy;
	bool		done;
	char		error[200];
} path;

static struct thost	*thost(const char *, bool);
static int		 node_index(const char *);
static void		 nodes_build(void);
static int		 node_host(int);
static void		 node_send(int, char *, const char *, const char *);
static void		 node_job(int, const char *, const char *, const char *,
			    ...) __attribute__((format(printf, 4, 5)));
static void		 places_load(void);
static void		 places_save(void);
static void		 poll_cb(int, const ucl_object_t *, const char *, void *);
static bool		 addr_bytes(const char *, int *, unsigned char *);
static bool		 addr_same(const char *, const char *);
static bool		 labels_quiet(int);
static int		 owner(const char *, char *, size_t);
static void		 node_poll(int);
static void		 bird_poll(int);
static void		 node_open(int, int);
static const char	*primary_addr(struct thost *, int);
static void		 links_build(void);
static void		 trace_next(int, const char *);
static void		 fit(void);
static int		 drag_values(const char *, double *, double *, double *,
			    double *, double *, char *, size_t);

/*
 * What the map draws as a node of its own: every server, and every
 * running jail of a server that has a network of its own, which its
 * host's agent reads and changes for it.  A node is known by its key:
 * the server's id, or that and the jail's name.
 */
static void
nodes_build(void)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;
	struct tnode		*n;
	int			 i, remote;

	/*
	 * A host reached by a local socket is the console's own: it has
	 * no place among those reached over the network, unless there
	 * are no others.
	 */
	remote = 0;
	for (i = 0; i < app.nservers; i++)
		if (strncmp(app.servers[i].uri, "unix:", 5) != 0)
			remote++;
	ntn = 0;
	for (i = 0; i < app.nservers; i++) {
		if (remote > 0 && strncmp(app.servers[i].uri, "unix:", 5) == 0)
			continue;
		n = &tn[ntn++];
		memset(n, 0, sizeof(*n));
		n->srv = i;
		snprintf(n->key, sizeof(n->key), "%s", app.servers[i].id);
		snprintf(n->name, sizeof(n->name), "%s", app.servers[i].name);
		snprintf(n->label, sizeof(n->label), "%s", app.servers[i].name);
	}
	for (i = 0; i < app.nservers; i++) {
		if (remote > 0 && strncmp(app.servers[i].uri, "unix:", 5) == 0)
			continue;
		it = NULL;
		while (!tp.novnet && app.servers[i].list != NULL && (j =
		    ucl_object_iterate(jget(app.servers[i].list, "jails"), &it,
		    true)) != NULL && ntn < MAX_NODES) {
			if (!jbool(j, "vnet") || jstr(j, "name") == NULL ||
			    jstr(j, "state") == NULL || strcmp(jstr(j, "state"),
			    "running") != 0 || strlen(jstr(j, "name")) >=
			    sizeof(n->jail) || strpbrk(jstr(j, "name"),
			    " /?&#%") != NULL)
				continue;
			n = &tn[ntn++];
			memset(n, 0, sizeof(*n));
			n->srv = i;
			snprintf(n->jail, sizeof(n->jail), "%s", jstr(j, "name"));
			snprintf(n->key, sizeof(n->key), "%s/%s",
			    app.servers[i].id, n->jail);
			snprintf(n->name, sizeof(n->name), "%s", n->jail);
			snprintf(n->label, sizeof(n->label), "%s · %s", n->jail,
			    app.servers[i].name);
		}
	}
}

/* The node of the server a node is of: itself, for a server. */
static int
node_host(int i)
{

	return (node_index(app.servers[tn[i].srv].id));
}

/* Where the console asks about a node's network. */
static void
node_url(int i, const char *what, const char *more, char *url, size_t len)
{

	snprintf(url, len, "/api/servers/%s/net/%s?%s%s%s",
	    app.servers[tn[i].srv].id, what, more, tn[i].jail[0] != '\0' ?
	    "&jail=" : "", tn[i].jail);
}

/* A job for a node: the server's, naming the jail when it is one. */
static void
node_send(int i, char *json, const char *title, const char *target)
{
	char	*in, t2[200];

	if (tn[i].jail[0] != '\0' && json[0] == '{') {
		if (asprintf(&in, "{\"jail\":\"%s\",%s", tn[i].jail, json +
		    1) == -1)
			abort();
		free(json);
		json = in;
		snprintf(t2, sizeof(t2), "%s: %s", tn[i].jail, title);
		title = t2;
	}
	job_send(&app.servers[tn[i].srv], json, title, JOB_IFACE, target);
}

static void
node_job(int i, const char *title, const char *target, const char *fmt, ...)
{
	va_list	 ap;
	char	*json;

	va_start(ap, fmt);
	if (vasprintf(&json, fmt, ap) == -1)
		abort();
	va_end(ap);
	node_send(i, json, title, target);
}

static struct thost *
thost(const char *sid, bool make)
{
	int	i;

	for (i = 0; i < nhosts; i++)
		if (strcmp(hosts[i].sid, sid) == 0)
			return (&hosts[i]);
	if (!make || nhosts == MAX_NODES)
		return (NULL);
	memset(&hosts[nhosts], 0, sizeof(hosts[0]));
	snprintf(hosts[nhosts].sid, sizeof(hosts[0].sid), "%s", sid);
	return (&hosts[nhosts++]);
}

static int
node_index(const char *sid)
{
	int	i;

	for (i = 0; i < ntn; i++)
		if (strcmp(tn[i].key, sid) == 0)
			return (i);
	return (-1);
}

/* Where the nodes were put, kept in the browser: "sid x y" a line. */
static void
places_load(void)
{
	struct thost	*t;
	char		*text, *p, *line, sid[80];
	double		 x, y;

	tp.loaded = true;
	text = arc_store_get("arc_topo");
	p = text;
	while (p != NULL && (line = strsep(&p, "\n")) != NULL)
		if (sscanf(line, "%79s %lf %lf", sid, &x, &y) == 3 &&
		    (t = thost(sid, true)) != NULL) {
			t->x = x;
			t->y = y;
			t->placed = true;
			tp.custom = true;
		}
	free(text);
}

/* Where the node dragged now was when taken hold of. */
static double	drag_x0, drag_y0;
/* The neighbour being dragged, by its key, or "". */
static char	peer_dragging[160];

static void
places_save(void)
{
	struct html	b;
	int		i;

	memset(&b, 0, sizeof(b));
	for (i = 0; i < nhosts; i++)
		if (hosts[i].placed && node_index(hosts[i].sid) != -1)
			h_fmt(&b, "%s %.0f %.0f\n", hosts[i].sid, hosts[i].x,
			    hosts[i].y);
	arc_store_set("arc_topo", b.s != NULL ? b.s : "");
	free(b.s);
}

/*
 * How far the links dragged aside are bent, kept in the browser:
 * "bend<tab>key" a line.
 */
static void
bends_load(void)
{
	char	*text, *p, *line, *tab;

	tp.bends_loaded = true;
	tp.nbends = 0;
	text = arc_store_get("arc_topo_bends");
	p = text;
	while (p != NULL && (line = strsep(&p, "\n")) != NULL &&
	    tp.nbends < (int)(sizeof(tp.bends) / sizeof(tp.bends[0]))) {
		if ((tab = strchr(line, '\t')) == NULL || tab[1] == '\0')
			continue;
		*tab = '\0';
		tp.bends[tp.nbends].bend = strtod(line, NULL);
		snprintf(tp.bends[tp.nbends].key, sizeof(tp.bends[0].key),
		    "%s", tab + 1);
		tp.nbends++;
	}
	free(text);
}

static void
bends_save(void)
{
	struct html	b;
	int		i;

	memset(&b, 0, sizeof(b));
	for (i = 0; i < tp.nbends; i++)
		h_fmt(&b, "%.0f\t%s\n", tp.bends[i].bend, tp.bends[i].key);
	arc_store_set("arc_topo_bends", b.s != NULL ? b.s : "");
	free(b.s);
}

/* The bend a link was dragged to, or NULL. */
static struct bend *
bend_kept(const char *key, bool make)
{
	int	i;

	if (!tp.bends_loaded)
		bends_load();
	for (i = 0; i < tp.nbends; i++)
		if (strcmp(tp.bends[i].key, key) == 0)
			return (&tp.bends[i]);
	if (!make)
		return (NULL);
	/* Full: the oldest one goes. */
	if (tp.nbends == (int)(sizeof(tp.bends) / sizeof(tp.bends[0]))) {
		memmove(&tp.bends[0], &tp.bends[1], sizeof(tp.bends[0]) *
		    (sizeof(tp.bends) / sizeof(tp.bends[0]) - 1));
		tp.nbends--;
	}
	snprintf(tp.bends[tp.nbends].key, sizeof(tp.bends[0].key), "%s", key);
	tp.bends[tp.nbends].bend = 0;
	return (&tp.bends[tp.nbends++]);
}

/*
 * Where the routing neighbours outside were dragged, from their hosts,
 * kept in the browser: "dx dy key" a line.  They follow their host.
 */
static void
peers_load(void)
{
	char	*text, *p, *line;
	double	 dx, dy;
	int	 used;

	tp.peers_loaded = true;
	tp.npeers = 0;
	/* Whether the vnet jails are shown, as last chosen here. */
	text = arc_store_get("arc_topo_vnet");
	tp.novnet = text != NULL && strcmp(text, "hidden") == 0;
	tp.lonevnet = text != NULL && strcmp(text, "all") == 0;
	free(text);
	text = arc_store_get("arc_topo_peers");
	p = text;
	while (p != NULL && (line = strsep(&p, "\n")) != NULL &&
	    tp.npeers < (int)(sizeof(tp.peers) / sizeof(tp.peers[0]))) {
		used = 0;
		if (sscanf(line, "%lf %lf %n", &dx, &dy, &used) < 2 || used ==
		    0 || line[used] == '\0')
			continue;
		tp.peers[tp.npeers].dx = dx;
		tp.peers[tp.npeers].dy = dy;
		snprintf(tp.peers[tp.npeers].key, sizeof(tp.peers[0].key),
		    "%s", line + used);
		tp.npeers++;
	}
	free(text);
}

static void
peers_save(void)
{
	struct html	b;
	int		i;

	memset(&b, 0, sizeof(b));
	for (i = 0; i < tp.npeers; i++)
		h_fmt(&b, "%.0f %.0f %s\n", tp.peers[i].dx, tp.peers[i].dy,
		    tp.peers[i].key);
	arc_store_set("arc_topo_peers", b.s != NULL ? b.s : "");
	free(b.s);
}

static struct peerpos *
peer_kept(const char *key, bool make)
{
	int	i;

	if (!tp.peers_loaded)
		peers_load();
	for (i = 0; i < tp.npeers; i++)
		if (strcmp(tp.peers[i].key, key) == 0)
			return (&tp.peers[i]);
	if (!make)
		return (NULL);
	if (tp.npeers == (int)(sizeof(tp.peers) / sizeof(tp.peers[0]))) {
		memmove(&tp.peers[0], &tp.peers[1], sizeof(tp.peers[0]) *
		    (sizeof(tp.peers) / sizeof(tp.peers[0]) - 1));
		tp.npeers--;
	}
	snprintf(tp.peers[tp.npeers].key, sizeof(tp.peers[0].key), "%s", key);
	tp.peers[tp.npeers].dx = tp.peers[tp.npeers].dy = 0;
	return (&tp.peers[tp.npeers++]);
}

/* A neighbour outside, as its kept place knows it. */
static void
peer_key(char *buf, size_t len, const struct ext *e)
{

	snprintf(buf, len, "%s\t%s\t%s\t%s", tn[e->host].key, e->ospf ?
	    "ospf" : "bgp", e->label, e->sub);
}

/*
 * Where a neighbour outside is drawn unless it was dragged: away from
 * the middle of the hosts, as it was when first drawn (followed at
 * every move, all of them would swing about while one host is
 * dragged; "Fit" sets it again), on two rings, every other one further
 * out, side by side on one ring they would lie on each other.
 */
static void
peer_place(const struct ext *e, struct thost *t, double *exp, double *eyp)
{
	double	cx, cy, a, step;
	int	m, k;

	cx = cy = 0;
	for (m = 0, k = 0; k < nhosts; k++)
		if (hosts[k].placed && node_index(hosts[k].sid) != -1) {
			cx += hosts[k].x;
			cy += hosts[k].y;
			m++;
		}
	cx = m > 0 ? cx / m : 0;
	cy = m > 0 ? cy / m : 0;
	if (!t->out_set) {
		t->out_a = fabs(t->x - cx) + fabs(t->y - cy) < 1 ? -M_PI / 2 :
		    atan2(t->y - cy, t->x - cx);
		t->out_set = true;
	}
	step = e->of > 1 && 1.6 / (e->of - 1) < 0.36 ? 1.6 / (e->of - 1) : 0.36;
	a = t->out_a + (e->slot - (e->of - 1) / 2.0) * step;
	*exp = t->x + 185 * (1 + 0.4 * (e->slot % 3)) * cos(a);
	*eyp = t->y + 125 * (1 + 0.4 * (e->slot % 3)) * sin(a);
}

/*
 * The diagram draws a BGP neighbour's AS once, a cloud every session
 * to it runs to: its first session leads, and the cloud stands where
 * the leader was dragged to, else at the mean of its sessions' places.
 */
static int
as_leader(int i)
{
	int	k;

	for (k = 0; k < i; k++)
		if (exts[k].ospf == exts[i].ospf && strcmp(exts[k].label,
		    exts[i].label) == 0)
			return (k);
	return (i);
}

static void
as_place_raw(int lead, double *xp, double *yp, bool *keptp)
{
	struct peerpos	*pp;
	struct thost	*t;
	double		 x, y, sx, sy;
	char		 key[160];
	int		 k, n, others;

	*keptp = false;
	peer_key(key, sizeof(key), &exts[lead]);
	if ((pp = peer_kept(key, false)) != NULL && (pp->dx != 0 || pp->dy != 0)
	    && (t = thost(tn[
	    exts[lead].host].key, false)) != NULL) {
		*xp = t->x + pp->dx;
		*yp = t->y + pp->dy;
		*keptp = true;
		return;
	}
	sx = sy = 0;
	n = others = 0;
	for (k = 0; k < nexts; k++) {
		if (exts[k].ospf != exts[lead].ospf || strcmp(exts[k].label,
		    exts[lead].label) != 0 || (t = thost(tn[exts[k].host].key, false)) == NULL)
			continue;
		peer_place(&exts[k], t, &x, &y);
		sx += x;
		sy += y;
		n++;
		others += exts[k].host != exts[lead].host;
	}
	*xp = n > 0 ? sx / n : 0;
	*yp = n > 0 ? sy / n : 0;
	if (others == 0)	/* one host's alone: beside it */
		return;
	/*
	 * Several hosts' neighbour: the mean of their places can fall in
	 * the middle of the fleet, over its links.  Out past the hosts'
	 * box then, just beyond it, the way the mean leans, or by its turn
	 * when it leans nowhere.
	 */
	{
		double	x0, y0, x1, y1, cx, cy, a, tx, ty;
		int	m, nth;

		x0 = y0 = x1 = y1 = 0;
		for (m = 0, k = 0; k < nhosts; k++) {
			if (!hosts[k].placed || node_index(hosts[k].sid) == -1)
				continue;
			if (m == 0 || hosts[k].x < x0)
				x0 = hosts[k].x;
			if (m == 0 || hosts[k].x > x1)
				x1 = hosts[k].x;
			if (m == 0 || hosts[k].y < y0)
				y0 = hosts[k].y;
			if (m == 0 || hosts[k].y > y1)
				y1 = hosts[k].y;
			m++;
		}
		if (*xp < x0 - 120 || *xp > x1 + 120 || *yp < y0 - 80 ||
		    *yp > y1 + 80)
			return;
		cx = (x0 + x1) / 2;
		cy = (y0 + y1) / 2;
		for (nth = 0, k = 0; k < lead; k++)
			nth += as_leader(k) == k;
		a = hypot(*xp - cx, *yp - cy) > 40 ? atan2(*yp - cy, *xp - cx) :
		    -M_PI / 2 + nth * 0.7;
		tx = fabs(cos(a)) > 1e-3 ? ((x1 - x0) / 2 + 170) / fabs(cos(a)) :
		    1e9;
		ty = fabs(sin(a)) > 1e-3 ? ((y1 - y0) / 2 + 110) / fabs(sin(a)) :
		    1e9;
		*xp = cx + (tx < ty ? tx : ty) * cos(a);
		*yp = cy + (tx < ty ? tx : ty) * sin(a);
	}
}

/* The neighbours' nodes kept out of the core's circle: back out along
 * their way from its middle.  How many were moved. */
static int
peers_outside(const bool *fixed)
{
	struct thost	*t;
	double		 cx, cy, r, d, a;
	int		 i, k, m, moved;

	cx = cy = r = 0;
	for (m = 0, k = 0; k < ntn; k++)
		if (tcore[k] && (t = thost(tn[k].key, false)) != NULL &&
		    t->placed) {
			cx += t->x;
			cy += t->y;
			m++;
		}
	if (m < 3)
		return (0);
	cx /= m;
	cy /= m;
	for (k = 0; k < ntn; k++)
		if (tcore[k] && (t = thost(tn[k].key, false)) != NULL &&
		    t->placed && hypot(t->x - cx, t->y - cy) > r)
			r = hypot(t->x - cx, t->y - cy);
	for (moved = 0, i = 0; i < nexts; i++) {
		if (as_leader(i) != i || fixed[i])
			continue;
		d = hypot(peer_x[i] - cx, peer_y[i] - cy);
		if (d >= r + 110)
			continue;
		a = d < 1 ? -M_PI / 2 : atan2(peer_y[i] - cy, peer_x[i] - cx);
		peer_x[i] = cx + (r + 110) * cos(a);
		peer_y[i] = cy + (r + 110) * sin(a);
		moved++;
	}
	return (moved);
}

/*
 * Where every neighbour's node stands, worked out once a drawing: its
 * own place, then pushed apart from the others and from the hosts
 * where they overlap, a few rounds, the dragged ones staying put.
 */
static void
peers_layout(void)
{
	static bool	 fixed[EXT_MAX];
	static uint32_t	 sig;
	struct thost	*h;
	double		 dx, dy, ox, oy, w, hh;
	uint32_t	 s;
	const char	*c;
	int		 i, k, round, moved;

	/*
	 * Worked out again only when what they hang on changes: which they
	 * are, the shape the nodes were placed for, those dragged and where.
	 * A node moved by hand moves none of them.
	 */
	s = 2166136261u ^ (uint32_t)nexts ^ tp.shape_sig ^ (tp.stencil ? 7 : 0);
	for (i = 0; i < nexts; i++) {
		s = (s ^ (uint32_t)(exts[i].host * 2 + exts[i].ospf)) * 16777619u;
		for (c = exts[i].label; *c != '\0'; c++)
			s = (s ^ (unsigned char)*c) * 16777619u;
	}
	if (s == sig && s != 0) {
		/* Only the one being dragged moves, with the hand. */
		for (i = 0; peer_dragging[0] != '\0' && i < nexts; i++) {
			char	key[160];

			if (as_leader(i) != i)
				continue;
			peer_key(key, sizeof(key), &exts[i]);
			if (strcmp(key, peer_dragging) == 0)
				as_place_raw(i, &peer_x[i], &peer_y[i], &fixed[i]);
		}
		return;
	}
	sig = s;
	for (i = 0; i < nexts; i++)
		if (as_leader(i) == i)
			as_place_raw(i, &peer_x[i], &peer_y[i], &fixed[i]);
	for (round = 0; round < 40; round++) {
		moved = 0;
		for (i = 0; i < nexts; i++) {
			if (as_leader(i) != i || fixed[i])
				continue;
			/* Clear of the other neighbours' nodes. */
			for (k = 0; k < nexts; k++) {
				if (k == i || as_leader(k) != k)
					continue;
				dx = peer_x[i] - peer_x[k];
				dy = peer_y[i] - peer_y[k];
				ox = 104 - fabs(dx);
				oy = 62 - fabs(dy);
				if (ox <= 0 || oy <= 0)
					continue;
				/* Along the shorter way out, half each, all
				 * of it when the other is held. */
				w = fixed[k] ? 1.0 : 0.5;
				if (ox < oy) {
					peer_x[i] += (dx >= 0 ? 1 : -1) * ox * w;
					if (!fixed[k])
						peer_x[k] -= (dx >= 0 ? 1 : -1) * ox *
						    w;
				} else {
					peer_y[i] += (dy >= 0 ? 1 : -1) * oy * w;
					if (!fixed[k])
						peer_y[k] -= (dy >= 0 ? 1 : -1) * oy *
						    w;
				}
				moved++;
			}
			/* And of the hosts. */
			for (k = 0; k < nhosts; k++) {
				h = &hosts[k];
				if (!h->placed || node_index(h->sid) == -1)
					continue;
				dx = peer_x[i] - h->x;
				dy = peer_y[i] - h->y;
				hh = NODE_H / 2 + 40;
				ox = NODE_W / 2 + 60 - fabs(dx);
				oy = hh - fabs(dy);
				if (ox <= 0 || oy <= 0)
					continue;
				if (ox < oy)
					peer_x[i] += (dx >= 0 ? 1 : -1) * ox;
				else
					peer_y[i] += (dy >= 0 ? 1 : -1) * oy;
				moved++;
			}
		}
		/* None inside the circle of the core: out past it. */
		moved += peers_outside(fixed);
		if (moved == 0)
			break;
	}
}

/* Where a neighbour's node is drawn, as peers_layout() left it. */
static void
as_place(int lead, double *xp, double *yp)
{

	*xp = peer_x[lead];
	*yp = peer_y[lead];
}

/*
 * Is node i placed among the others: a host, or a vnet jail but one
 * known (read) to be linked to its own host alone, which is not drawn.
 */
static bool
node_placed_among(int i)
{
	struct thost	*t;

	if (tn[i].jail[0] == '\0')
		return (true);
	if ((t = thost(tn[i].key, false)) == NULL || t->ifs == NULL)
		return (true);
	return (!node_lone(i));
}

/*
 * The shape of the fleet, for placing it.  A host and its vnet jails are
 * a family: links inside a family (an epair, a bridge, an uplink network
 * they all have an address on) say nothing of where the family stands.
 * Between families: the core, the nodes on some cycle of links, goes on
 * the circle; a node reached through one other hangs behind it, found
 * by taking away, again and again, the nodes linked to one other only.
 * A node with no link out of its family hangs behind the one of its
 * family that has (a host behind its jail that routes); a family with
 * none is its host on the circle and its jails behind it.
 */
static int
node_family(int i)
{

	return (tn[i].jail[0] != '\0' ? node_host(i) : i);
}

static void
topo_shape(void)
{
	static unsigned char	adj[MAX_NODES][MAX_NODES];
	bool			drawn[MAX_NODES], gone[MAX_NODES], ext[MAX_NODES];
	int			deg[MAX_NODES], inner[MAX_NODES], ninner;
	int			i, k, m, a, b, s, changed, best;

	memset(adj, 0, sizeof(adj));
	for (i = 0; i < ntn; i++) {
		drawn[i] = node_placed_among(i);
		tparent[i] = -1;
	}
	for (k = 0; k < nlinks; k++) {
		a = links[k].a;
		b = links[k].b;
		if (a < 0 || a >= ntn)
			continue;
		if (b >= 0) {
			if (b < ntn && node_family(a) != node_family(b))
				adj[a][b] = adj[b][a] = 1;
			continue;
		}
		/* A network several are in joins each to the others. */
		if ((s = -b - 1) >= nsegs)
			continue;
		for (m = 0; m < segs[s].n; m++)
			if ((b = segs[s].member[m]) >= 0 && b < ntn &&
			    node_family(a) != node_family(b))
				adj[a][b] = adj[b][a] = 1;
	}
	for (i = 0; i < ntn; i++) {
		ext[i] = false;
		for (k = 0; k < ntn; k++)
			ext[i] = ext[i] || (adj[i][k] && drawn[k]);
		gone[i] = !drawn[i] || !ext[i];
	}
	for (i = 0; i < ntn; i++)
		for (deg[i] = 0, k = 0; k < ntn; k++)
			deg[i] += adj[i][k] && !gone[i] && !gone[k];
	ntstrip = 0;
	do {
		changed = 0;
		for (i = 0; i < ntn; i++) {
			if (gone[i] || deg[i] != 1)
				continue;
			for (k = 0; k < ntn; k++)
				if (adj[i][k] && !gone[k])
					break;
			gone[i] = true;
			tparent[i] = k < ntn ? k : -1;
			tstrip[ntstrip++] = i;
			if (k < ntn)
				deg[k]--;
			changed = 1;
		}
	} while (changed);
	for (i = 0; i < ntn; i++)
		tcore[i] = drawn[i] && ext[i] && !gone[i];
	/*
	 * Those with no link out of their family: behind the one of it that
	 * has, in the core first; else the family's host is on the circle
	 * and they hang behind it.  Placed last: first in the strip order.
	 */
	ninner = 0;
	for (i = 0; i < ntn; i++) {
		if (!drawn[i] || ext[i])
			continue;
		best = -1;
		for (k = 0; k < ntn; k++)
			if (k != i && drawn[k] && ext[k] &&
			    node_family(k) == node_family(i) && (best == -1 ||
			    (tcore[k] && !tcore[best])))
				best = k;
		if (best == -1 && tn[i].jail[0] == '\0') {
			tcore[i] = true;	/* a family alone: its host */
			continue;
		}
		tparent[i] = best != -1 ? best : node_family(i);
		inner[ninner++] = i;
	}
	if (ninner > 0 && ntstrip + ninner <= MAX_NODES) {
		memmove(tstrip + ninner, tstrip, ntstrip * sizeof(tstrip[0]));
		memcpy(tstrip, inner, ninner * sizeof(tstrip[0]));
		ntstrip += ninner;
	}
}

/* Node i behind node p, outward from (cx, cy), beside p's other ones. */
static void
place_behind(int i, int p, double cx, double cy, double d)
{
	struct thost	*t, *pt;
	double		 a;
	int		 k, nth;

	if ((t = thost(tn[i].key, true)) == NULL || (pt = thost(tn[p].key,
	    false)) == NULL || !pt->placed)
		return;
	for (nth = 0, k = 0; k < ntn; k++)
		if (k != i && tparent[k] == p && thost(tn[k].key, false) !=
		    NULL && thost(tn[k].key, false)->placed)
			nth++;
	a = (fabs(pt->x - cx) + fabs(pt->y - cy) < 1 ? -M_PI / 2 :
	    atan2(pt->y - cy, pt->x - cx)) + ((nth + 1) / 2) * (nth % 2 == 1 ?
	    -0.6 : 0.6);
	t->x = pt->x + d * cos(a);
	t->y = pt->y + d * 0.8 * sin(a);
	t->placed = true;
}

/* How many leaves hang below node v, itself if none. */
static int
tree_leaves(int v)
{
	int	k, s;

	for (s = 0, k = 0; k < ntn; k++)
		if (tparent[k] == v && !tcore[k])
			s += tree_leaves(k);
	return (s > 0 ? s : 1);
}

static int
tree_depth(int v)
{
	int	k, m, dd;

	for (m = 0, k = 0; k < ntn; k++)
		if (tparent[k] == v && !tcore[k] && (dd = tree_depth(k)) > m)
			m = dd;
	return (m + 1);
}

/* The children of v in the sector a0..a1, round (ox, oy), a depth out. */
static void
tree_ring(int v, double a0, double a1, double ox, double oy, double step,
    int depth)
{
	struct thost	*t;
	double		 a, span;
	int		 k, all, done;

	all = tree_leaves(v);
	for (done = 0, k = 0; k < ntn; k++) {
		if (tparent[k] != v || tcore[k] || (t = thost(tn[k].key,
		    true)) == NULL)
			continue;
		span = (a1 - a0) * tree_leaves(k) / all;
		a = a0 + (a1 - a0) * done / all + span / 2;
		if (!t->placed) {
			t->x = ox + depth * step * cos(a);
			t->y = oy + depth * step * sin(a);
			t->placed = true;
		}
		tree_ring(k, a0 + (a1 - a0) * done / all, a0 + (a1 - a0) * done /
		    all + span, ox, oy, step, depth + 1);
		done += tree_leaves(k);
	}
}

/*
 * A core node's hanging tree: in its sector of the circle (all of it
 * for a core of one), facing out from the middle (cx, cy); each depth a
 * step further, the step widened until the outer ring has room.
 */
static void
place_tree(int c, int ncore, double cx, double cy, double d)
{
	struct thost	*t;
	double		 a, w, step, need;
	int		 leaves, depth;

	if ((t = thost(tn[c].key, false)) == NULL || !t->placed)
		return;
	if (tree_leaves(c) == 1 && tree_depth(c) == 1)
		return;			/* nothing hangs off it */
	w = ncore <= 1 ? 2 * M_PI : 2 * M_PI / ncore;
	if (w > 1.4 * M_PI)
		w = 1.4 * M_PI;
	a = ncore <= 1 || fabs(t->x - cx) + fabs(t->y - cy) < 1 ? -M_PI / 2 :
	    atan2(t->y - cy, t->x - cx);
	leaves = tree_leaves(c);
	depth = tree_depth(c) - 1;
	step = d;
	need = 175.0 * leaves / (w * (depth > 0 ? depth : 1));
	if (need > step)
		step = need;
	tree_ring(c, a - w / 2, a + w / 2, t->x, t->y, step, 1);
}

/*
 * Nodes not placed yet: the core on a circle, each host followed by its
 * vnet jails, a jail as far from the others as hosts are; the others
 * behind the node they hang off, from the core outward.  One seen after
 * the rest were placed goes beside the node it hangs off, or its host.
 */
static void
places_fill(void)
{
	struct thost	*t, *ht;
	double		 r, d, cx, cy;
	int		 order[MAX_NODES], i, k, n, h, slot;
	bool		 any;

	if (!tp.loaded)
		places_load();
	topo_shape();
	n = 0;
	for (h = 0; h < ntn; h++) {
		if (tn[h].jail[0] != '\0')
			continue;
		if (tcore[h])
			order[n++] = h;
		for (i = 0; i < ntn; i++)
			if (tn[i].jail[0] != '\0' && node_host(i) == h &&
			    tcore[i])
				order[n++] = i;
	}
	r = n < 3 ? 170 : 190 + 42.0 * n;
	if (r > 720)
		r = 720;
	if (tp.stencil)
		r *= 1.25;
	/* Behind a node: as far as hosts are on a small circle, never so far
	 * that chains outrun the drawing. */
	d = n > 1 ? 2 * r * sin(M_PI / n) : 260;
	if (d < 200)
		d = 200;
	if (d > 320)
		d = 320;
	any = false;
	cx = cy = 0;
	for (k = 0, i = 0; i < n; i++)
		if ((t = thost(tn[order[i]].key, false)) != NULL && t->placed) {
			any = true;
			cx += t->x;
			cy += t->y;
			k++;
		}
	cx = k > 0 ? cx / k : 0;
	cy = k > 0 ? cy / k : 0;
	for (slot = 0; slot < n; slot++) {
		i = order[slot];
		if ((t = thost(tn[i].key, true)) == NULL || t->placed)
			continue;
		if (any && tn[i].jail[0] != '\0') {
			if ((ht = thost(tn[node_host(i)].key, false)) != NULL &&
			    ht->placed) {
				tparent[i] = node_host(i);
				place_behind(i, node_host(i), cx, cy, d);
			}
			continue;
		}
		{
			double	a = M_PI + 2 * M_PI * slot / (n > 0 ? n : 1);

			/* On a phone the room is tall: the circle is too. */
			t->x = n == 1 ? 0 : r * cos(a) * (arc_narrow() ? 0.5 :
			    1.35);
			t->y = n == 1 ? 0 : r * sin(a) * (arc_narrow() ? 1.5 :
			    0.8);
			t->placed = true;
		}
	}
	/*
	 * What hangs off the core: on a fresh layout, a radial tree around
	 * each core node, in the sector of the circle facing out from it;
	 * one seen later goes behind the node it hangs off.
	 */
	if (!any) {
		double	ccx = 0, ccy = 0;
		int	nc = 0;

		for (i = 0; i < n; i++)
			if ((t = thost(tn[order[i]].key, false)) != NULL &&
			    t->placed) {
				ccx += t->x;
				ccy += t->y;
				nc++;
			}
		ccx = nc > 0 ? ccx / nc : 0;
		ccy = nc > 0 ? ccy / nc : 0;
		for (i = 0; i < n; i++)
			place_tree(order[i], n, ccx, ccy, d);
	}
	for (k = ntstrip - 1; k >= 0; k--) {
		i = tstrip[k];
		if ((t = thost(tn[i].key, true)) == NULL || t->placed ||
		    tparent[i] < 0)
			continue;
		place_behind(i, tparent[i], cx, cy, d);
	}
}

/*
 * Once the links are known, the nodes placed again for the shape they
 * make, as long as none was placed by hand: the first drawing has no
 * links yet, and a jail or a tunnel may come later.
 */
static void
layout_follow(void)
{
	uint32_t	h;
	int		i;

	topo_shape();
	h = 2166136261u ^ (uint32_t)ntn;
	for (i = 0; i < ntn; i++) {
		h = (h ^ (uint32_t)(tcore[i] ? 1 : 0)) * 16777619u;
		h = (h ^ (uint32_t)(tparent[i] + 2)) * 16777619u;
		h = (h ^ (uint32_t)(node_placed_among(i) ? 1 : 0)) * 16777619u;
	}
	if (h == tp.shape_sig)
		return;
	tp.shape_sig = h;
	if (tp.custom)
		return;
	for (i = 0; i < nhosts; i++) {
		hosts[i].placed = false;
		hosts[i].out_set = false;
	}
	places_fill();
	if (!tp.touched)
		fit();
}

/* An address as bytes and its family; a zone after % is left out. */
static bool
addr_bytes(const char *s, int *afp, unsigned char *raw)
{
	char	buf[80];

	if (s == NULL)
		return (false);
	snprintf(buf, sizeof(buf), "%.*s", (int)strcspn(s, "%/"), s);
	if (inet_pton(AF_INET, buf, raw) == 1) {
		*afp = AF_INET;
		return (true);
	}
	if (inet_pton(AF_INET6, buf, raw) == 1) {
		*afp = AF_INET6;
		return (true);
	}
	return (false);
}

static bool
addr_same(const char *a, const char *b)
{
	unsigned char	ra[16], rb[16];
	int		fa, fb;

	return (addr_bytes(a, &fa, ra) && addr_bytes(b, &fb, rb) && fa == fb &&
	    memcmp(ra, rb, fa == AF_INET ? 4 : 16) == 0);
}

/* Not an address to join hosts by: loopback, link-local, unspecified. */
static bool
addr_local(const char *s)
{
	unsigned char	raw[16];
	int		af;

	if (!addr_bytes(s, &af, raw))
		return (true);
	if (af == AF_INET)
		return (raw[0] == 127 || raw[0] == 0 || (raw[0] == 169 &&
		    raw[1] == 254));
	return ((raw[0] == 0xfe && (raw[1] & 0xc0) == 0x80) ||
	    memcmp(raw, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 15) == 0);
}

/* The network an address is in, as text: "10.0.0.0/24". */
static bool
net_of(const char *addr, int plen, char *buf, size_t len)
{
	unsigned char	raw[16];
	char		text[64];
	int		af, max, i;

	if (!addr_bytes(addr, &af, raw))
		return (false);
	max = af == AF_INET ? 32 : 128;
	if (plen <= 0 || plen >= max)
		return (false);
	for (i = 0; i < max / 8; i++) {
		if (i * 8 >= plen)
			raw[i] = 0;
		else if (i * 8 + 8 > plen)
			raw[i] &= (unsigned char)(0xff << (8 - plen % 8));
	}
	if (inet_ntop(af, raw, text, sizeof(text)) == NULL)
		return (false);
	snprintf(buf, len, "%s/%d", text, plen);
	return (true);
}

/* The server that has this address on an interface, and which; or -1. */
static int
owner(const char *addr, char *ifname, size_t len)
{
	const ucl_object_t	*o, *a;
	ucl_object_iter_t	 it, ait;
	int			 i, s;

	for (i = 0; i < nhosts; i++) {
		if (hosts[i].ifs == NULL || (s = node_index(hosts[i].sid)) ==
		    -1)
			continue;
		it = NULL;
		while ((o = ucl_object_iterate(jget(hosts[i].ifs, "interfaces"),
		    &it, true)) != NULL) {
			ait = NULL;
			while ((a = ucl_object_iterate(jget(o, "addresses"),
			    &ait, true)) != NULL)
				if (addr_same(jstr(a, "address"), addr)) {
					if (ifname != NULL)
						snprintf(ifname, len, "%s",
						    jstr(o, "name") != NULL ?
						    jstr(o, "name") : "");
					return (s);
				}
		}
	}
	return (-1);
}

/*
 * The same for the pages beside the map: the server (in app.servers)
 * whose host, or a vnet jail of it, has addr; which interface, and which
 * jail ("" the host itself).  -1 when no host of the fleet has it, or
 * its interfaces have not been read yet.
 */
int
topo_addr_owner(const char *addr, char *ifname, size_t len, char *jail,
    size_t jlen)
{
	int	n;

	nodes_build();
	if ((n = owner(addr, ifname, len)) == -1)
		return (-1);
	snprintf(jail, jlen, "%s", tn[n].jail);
	return (tn[n].srv);
}

/*
 * The next node from i on whose BIRD has answered: its index, with its
 * key, how a list names it and what BIRD said; -1 past the last.
 */
int
topo_bird_next(int i, const char **key, const char **label,
    const ucl_object_t **bird)
{
	struct thost	*t;

	for (i = i < 0 ? 0 : i; i < ntn; i++)
		if ((t = thost(tn[i].key, false)) != NULL && t->bird != NULL) {
			*key = tn[i].key;
			*label = tn[i].label;
			*bird = t->bird;
			return (i);
		}
	return (-1);
}

/* How many nodes have BIRD, and of them how many are still asked. */
int
topo_bird_hosts(int *asking)
{
	struct thost	*t;
	int		 i, n;

	nodes_build();
	n = *asking = 0;
	for (i = 0; i < ntn; i++) {
		if (!plugin_at(&app.servers[tn[i].srv], tn[i].jail, "bird"))
			continue;
		n++;
		if ((t = thost(tn[i].key, false)) == NULL || (t->bird == NULL &&
		    t->bird_loading))
			(*asking)++;
	}
	return (n);
}

/* How a list names the node that has addr, or NULL. */
const char *
topo_addr_node(const char *addr)
{
	int	n;

	return (addr == NULL || (n = owner(addr, NULL, 0)) == -1 ? NULL :
	    tn[n].label);
}

/* Every BIRD read again now: a routing tab was opened. */
void
topo_bird_now(void)
{
	int	i;

	nodes_build();
	for (i = 0; i < ntn; i++)
		bird_poll(i);
}

/* A node's BIRD in its host's network tab. */
bool
topo_bird_open(const char *key)
{
	int	n;

	if ((n = node_index(key)) == -1)
		return (false);
	node_open(n, NET_BIRD);
	return (true);
}

/* Is the address one of a link only (fe80::/10, 169.254/16)? */
static bool
addr_linklocal(const char *s)
{
	unsigned char	raw[16];
	int		af;

	if (!addr_bytes(s, &af, raw))
		return (false);
	return (af == AF_INET ? raw[0] == 169 && raw[1] == 254 :
	    raw[0] == 0xfe && (raw[1] & 0xc0) == 0x80);
}

/* Do two interfaces' addresses share a network beyond their links? */
static bool
if_share_net(const ucl_object_t *a, const ucl_object_t *b)
{
	const ucl_object_t	*x, *y;
	ucl_object_iter_t	 xi, yi;
	char			 na[80], nb[80];

	xi = NULL;
	while ((x = ucl_object_iterate(jget(a, "addresses"), &xi, true)) !=
	    NULL) {
		if (addr_local(jstr(x, "address")) || !net_of(jstr(x,
		    "address"), (int)jint(x, "prefixlen", 0), na, sizeof(na)))
			continue;
		yi = NULL;
		while ((y = ucl_object_iterate(jget(b, "addresses"), &yi,
		    true)) != NULL)
			if (net_of(jstr(y, "address"), (int)jint(y, "prefixlen",
			    0), nb, sizeof(nb)) && strcmp(na, nb) == 0)
				return (true);
	}
	return (false);
}

/* The interface of a host's reading by its name, or NULL. */
static const ucl_object_t *
if_named(const struct thost *t, const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while (t != NULL && name != NULL && (o = ucl_object_iterate(jget(
	    t->ifs, "interfaces"), &it, true)) != NULL)
		if (jstr(o, "name") != NULL && strcmp(jstr(o, "name"), name) ==
		    0)
			return (o);
	return (NULL);
}

/*
 * Who a next hop's gateway is: the server, its interface and jail, as
 * topo_addr_owner says, for the host of server from sending by its
 * interface fromif.  An address of a link only (fe80::1, which many
 * routers and every loopback have) is looked for on that link alone:
 * never on a loopback nor on the sender, and of several hosts that have
 * it the one whose interface shares a network with the sender's.  -1
 * when none, or when which of several it is cannot be told.
 */
int
topo_gw_owner(const char *gw, int from, const char *fromif, char *ifname,
    size_t len, char *jail, size_t jlen)
{
	const ucl_object_t	*o, *a, *mine;
	ucl_object_iter_t	 it, ait;
	const char		*zone, *name;
	int			 i, n, cand, ncand, shared, nshared;
	char			 cif[16], sif[16];

	nodes_build();
	if (!addr_linklocal(gw))
		return (topo_addr_owner(gw, ifname, len, jail, jlen));
	/* The zone, fe80::1%em0, names the sender's interface too. */
	if ((fromif == NULL || fromif[0] == '\0') && (zone = strchr(gw, '%')) !=
	    NULL)
		fromif = zone + 1;
	mine = from >= 0 ? if_named(thost(app.servers[from].id, false),
	    fromif) : NULL;
	cand = shared = -1;
	ncand = nshared = 0;
	cif[0] = sif[0] = '\0';
	for (i = 0; i < nhosts; i++) {
		if (hosts[i].ifs == NULL || (n = node_index(hosts[i].sid)) ==
		    -1 || (tn[n].srv == from && tn[n].jail[0] == '\0'))
			continue;
		it = NULL;
		while ((o = ucl_object_iterate(jget(hosts[i].ifs, "interfaces"),
		    &it, true)) != NULL) {
			name = jstr(o, "name") != NULL ? jstr(o, "name") : "";
			if (strncmp(name, "lo", 2) == 0)
				continue;
			ait = NULL;
			while ((a = ucl_object_iterate(jget(o, "addresses"),
			    &ait, true)) != NULL) {
				if (!addr_same(jstr(a, "address"), gw))
					continue;
				ncand++;
				cand = n;
				snprintf(cif, sizeof(cif), "%s", name);
				if (mine != NULL && if_share_net(mine, o)) {
					nshared++;
					shared = n;
					snprintf(sif, sizeof(sif), "%s", name);
				}
			}
		}
	}
	if (nshared == 1) {
		cand = shared;
		snprintf(cif, sizeof(cif), "%s", sif);
	} else if (ncand != 1)
		return (-1);
	snprintf(ifname, len, "%s", cif);
	snprintf(jail, jlen, "%s", tn[cand].jail);
	return (tn[cand].srv);
}

/* The MTU of a host's interface, as it was read; 0 not known. */
int
topo_if_mtu(int srv, const char *ifname)
{
	const ucl_object_t	*o;

	if (srv < 0 || srv >= app.nservers || (o = if_named(thost(
	    app.servers[srv].id, false), ifname)) == NULL)
		return (0);
	return ((int)jint(o, "mtu", 0));
}

/* An address a host is reached by, of the family af (0 either). */
const char *
topo_host_addr(int srv, int af)
{

	if (srv < 0 || srv >= app.nservers)
		return (NULL);
	return (primary_addr(thost(app.servers[srv].id, false), af));
}

/*
 * Every address the hosts have, as a datalist to offer where one is
 * typed: each with its host, jail and interface.
 */
void
topo_addr_list(struct html *h, const char *id)
{
	const ucl_object_t	*o, *a;
	ucl_object_iter_t	 it, ait;
	const struct tnode	*n;
	int			 i, k;

	h_raw(h, "<datalist");
	h_attr(h, "id", id);
	h_raw(h, ">");
	for (i = 0; i < nhosts; i++) {
		n = NULL;
		for (k = 0; k < ntn; k++)
			if (strcmp(tn[k].key, hosts[i].sid) == 0)
				n = &tn[k];
		it = NULL;
		while ((o = ucl_object_iterate(jget(hosts[i].ifs, "interfaces"),
		    &it, true)) != NULL) {
			ait = NULL;
			while ((a = ucl_object_iterate(jget(o, "addresses"), &ait,
			    true)) != NULL) {
				if (jstr(a, "address") == NULL || addr_local(
				    jstr(a, "address")))
					continue;
				h_raw(h, "<option");
				h_attr(h, "value", jstr(a, "address"));
				h_raw(h, ">");
				h_txt(h, n != NULL ? n->label : hosts[i].sid);
				h_raw(h, " · ");
				h_txt(h, jstr(o, "name"));
				h_raw(h, "</option>");
			}
		}
	}
	h_raw(h, "</datalist>");
}

/* Every host's interfaces read, for whom owns an address. */
void
topo_poll_all(void)
{
	int	i;

	nodes_build();
	for (i = 0; i < ntn; i++)
		node_poll(i);
}

static struct ifrate *
rate_of(struct thost *t, const char *name, bool make)
{
	int	i;

	for (i = 0; i < t->nr; i++)
		if (strcmp(t->r[i].name, name) == 0)
			return (&t->r[i]);
	if (!make || t->nr == TOPO_IFS)
		return (NULL);
	memset(&t->r[t->nr], 0, sizeof(t->r[0]));
	snprintf(t->r[t->nr].name, sizeof(t->r[0].name), "%s", name);
	return (&t->r[t->nr++]);
}

/* The newest rate of an interface, in and out together. */
static double
rate_now(struct thost *t, const char *name)
{
	struct ifrate	*r;

	if (t == NULL || (r = rate_of(t, name, false)) == NULL || r->n == 0)
		return (0);
	return ((double)r->in[r->n - 1] + r->out[r->n - 1]);
}

/*
 * An interface of a jail as this page read it while the network section
 * was open, for the load balance tab (an agent samples its host's
 * interfaces only): when, in seconds, and bytes a second, newest last.
 * How many, or -1 when the page has not read it.
 */
int
topo_if_rates(int srv, const char *jail, const char *ifn, bool out,
    double *t, double *v, int max)
{
	struct thost	*th;
	struct ifrate	*r;
	char		 key[80];
	int		 i, n, k;

	snprintf(key, sizeof(key), "%s/%s", app.servers[srv].id, jail);
	if ((th = thost(key, false)) == NULL || (r = rate_of(th, ifn,
	    false)) == NULL || r->n == 0)
		return (-1);
	n = r->n < max ? r->n : max;
	for (i = 0; i < n; i++) {
		k = r->n - n + i;
		t[i] = th->fetched / 1000.0 - (double)(r->n - 1 - k) *
		    TOPO_POLL_MS / 1000.0;
		v[i] = out ? r->out[k] : r->in[k];
	}
	return (n);
}

/* A reading of a host's interfaces: kept, and made into rates. */
/* Whether a node forwards packets, by family: the diagram draws a
 * router then, a server otherwise. */
static void
fwd_cb(int status, const ucl_object_t *o, const char *err, void *arg, bool v6)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct thost		*t;
	char			*sid;
	int			 on;

	(void)err;
	sid = arg;
	t = thost(sid, false);
	free(sid);
	if (t == NULL)
		return;
	t->fwd_loading = false;
	t->fwd_fetched = arc_now();
	if (status != 200 || !jbool(o, "ok"))
		return;
	on = 1;
	it = NULL;
	while ((e = ucl_object_iterate(jget(o, "data.values"), &it, true)) !=
	    NULL)
		if (jstr(e, "value") != NULL && strcmp(jstr(e, "value"), "1")
		    == 0)
			on = 2;
	if (v6)
		t->fwd6 = on;
	else
		t->fwd4 = on;
}

static void
fwd4_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	fwd_cb(status, o, err, arg, false);
}

static void
fwd6_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	fwd_cb(status, o, err, arg, true);
}

/* Does a node forward packets?  Before its sysctls are read, a host is
 * taken to and a jail not to. */
static bool
node_routes(const struct thost *t, bool jail)
{

	if (t->fwd4 == 2 || t->fwd6 == 2)
		return (true);
	if (t->fwd4 == 1 && t->fwd6 == 1)
		return (false);
	return (!jail);
}

/* A node's bridges, for the map to draw beside it. */
static void
bridges_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct thost	*t;
	char		*sid;

	(void)err;
	sid = arg;
	t = thost(sid, false);
	free(sid);
	if (t == NULL)
		return;
	t->br_loading = false;
	t->br_fetched = arc_now();
	if (status != 200 || !jbool(o, "ok"))
		return;
	if (t->bridges != NULL)
		ucl_object_unref(t->bridges);
	t->bridges = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o,
	    "data.bridges"));
}

static void
poll_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*data, *e;
	ucl_object_iter_t	 it;
	struct thost		*t;
	struct ifrate		*r;
	char			*sid;
	double			 now, dt, ib, ob, in, out;

	sid = arg;
	t = thost(sid, false);
	free(sid);
	if (t == NULL)
		return;
	t->loading = false;
	if (status != 200 || !jbool(o, "ok") || (data = jget(o, "data")) ==
	    NULL) {
		t->failed = true;
		return;
	}
	t->failed = false;
	now = jnum(data, "time", 0);
	dt = t->ifs != NULL && now > t->time ? (now - t->time) / 1000.0 : 0;
	it = NULL;
	while ((e = ucl_object_iterate(jget(data, "interfaces"), &it, true)) !=
	    NULL) {
		if (jstr(e, "name") == NULL || (r = rate_of(t, jstr(e, "name"),
		    true)) == NULL)
			continue;
		ib = jnum(e, "ibytes", 0);
		ob = jnum(e, "obytes", 0);
		if (dt > 0 && ib >= r->ib && ob >= r->ob) {
			in = (ib - r->ib) / dt;
			out = (ob - r->ob) / dt;
			if (r->n == TOPO_HIST) {
				memmove(r->in, r->in + 1, sizeof(r->in) -
				    sizeof(r->in[0]));
				memmove(r->out, r->out + 1, sizeof(r->out) -
				    sizeof(r->out[0]));
				r->n--;
			}
			r->in[r->n] = (float)in;
			r->out[r->n] = (float)out;
			r->n++;
		}
		r->ib = ib;
		r->ob = ob;
	}
	if (t->ifs != NULL)
		ucl_object_unref(t->ifs);
	t->ifs = ucl_object_ref((ucl_object_t *)(uintptr_t)data);
	t->time = now;
	t->fetched = arc_now();
	(void)err;
}

/* Read a host's interfaces, quietly: no entry in the activity list. */
static void
node_poll(int i)
{
	struct thost	*t;
	char		 url[240];

	if (!app.online || (t = thost(tn[i].key, true)) == NULL || t->loading)
		return;
	t->loading = true;
	node_url(i, "interfaces", "", url, sizeof(url));
	api("GET", url, NULL, poll_cb, strdup(tn[i].key));
	/* Its bridges change less often than its counters. */
	if (!t->br_loading && arc_now() - t->br_fetched > 15000) {
		t->br_loading = true;
		node_url(i, "bridges", "", url, sizeof(url));
		api("GET", url, NULL, bridges_cb, strdup(tn[i].key));
	}
	/* The diagram draws a router or a server by whether it forwards. */
	if (tp.stencil && !t->fwd_loading && arc_now() - t->fwd_fetched >
	    60000) {
		t->fwd_loading = true;
		snprintf(url, sizeof(url), "/api/servers/%s/sysctl?filter=net.inet."
		    "ip.forwarding%s%s", app.servers[tn[i].srv].id, tn[i].jail[0] !=
		    '\0' ? "&jail=" : "", tn[i].jail);
		api("GET", url, NULL, fwd4_cb, strdup(tn[i].key));
		snprintf(url, sizeof(url), "/api/servers/%s/sysctl?filter=net.inet6."
		    "ip6.forwarding%s%s", app.servers[tn[i].srv].id, tn[i].jail[0] !=
		    '\0' ? "&jail=" : "", tn[i].jail);
		api("GET", url, NULL, fwd6_cb, strdup(tn[i].key));
	}
}

/* The node a server's page is about: itself, or the jail it shows. */
static const char *
page_key(const struct server *s)
{
	static char	key[80];

	if (s == cur_server() && net_scope()[0] != '\0')
		snprintf(key, sizeof(key), "%s/%s", s->id, net_scope());
	else
		snprintf(key, sizeof(key), "%s", s->id);
	return (key);
}

/* A server's own interfaces, whatever its page shows. */
void
topo_poll_host(struct server *s)
{
	int	i;

	nodes_build();
	if ((i = node_index(s->id)) != -1)
		node_poll(i);
}

/* The same for a server, or the jail shown, asked for from its page. */
void
topo_poll(struct server *s)
{
	int	i;

	nodes_build();
	if ((i = node_index(page_key(s))) != -1)
		node_poll(i);
}

/* The interface of a host with this public key, or NULL. */
static const char *
wg_iface(struct thost *t, const char *key, const char *ifname)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while (t != NULL && (o = ucl_object_iterate(jget(t->wg, "interfaces"),
	    &it, true)) != NULL) {
		if (jstr(o, "name") == NULL || jstr(o, "public-key") == NULL)
			continue;
		if (key != NULL && strcmp(jstr(o, "public-key"), key) == 0)
			return (jstr(o, "name"));
		if (ifname != NULL && strcmp(jstr(o, "name"), ifname) == 0)
			return (jstr(o, "public-key"));
	}
	return (NULL);
}

/* Tunnels waiting for their keys: those that have both get their peers. */
static void
wg_pairs_step(void)
{
	struct wgpair	*p;
	const char	*ka, *kb;
	char		*json, title[160];
	int		 i, a, b;

	for (i = 0; i < WG_PAIRS; i++) {
		p = &wgpairs[i];
		if (!p->active)
			continue;
		if ((a = node_index(p->a)) == -1 || (b = node_index(
		    p->b)) == -1 || arc_now() - p->since > 300000) {
			p->active = false;
			continue;
		}
		ka = wg_iface(thost(p->a, false), NULL, p->ifa);
		kb = wg_iface(thost(p->b, false), NULL, p->ifb);
		if (ka == NULL || kb == NULL)
			continue;
		p->active = false;
		/* Keys are base64 and the rest was checked: as they are. */
		if (asprintf(&json, "{\"kind\":\"wireguard\",\"interface\":"
		    "\"%s\",\"verb\":\"peer\",\"peer\":\"%s\",\"endpoint\":"
		    "\"%s\",\"allowed_ips\":\"%s\",\"persist\":%s}", p->ifa, kb,
		    p->endb, p->inb, p->keep ? "true" : "false") == -1)
			abort();
		snprintf(title, sizeof(title), "%s: wireguard peer", p->ifa);
		node_send(a, json, title, p->ifa);
		if (asprintf(&json, "{\"kind\":\"wireguard\",\"interface\":"
		    "\"%s\",\"verb\":\"peer\",\"peer\":\"%s\",\"endpoint\":"
		    "\"%s\",\"allowed_ips\":\"%s\",\"persist\":%s}", p->ifb, ka,
		    p->enda, p->ina, p->keep ? "true" : "false") == -1)
			abort();
		snprintf(title, sizeof(title), "%s: wireguard peer", p->ifb);
		node_send(b, json, title, p->ifb);
	}
}

static bool
wg_pending(void)
{
	int	i;

	for (i = 0; i < WG_PAIRS; i++)
		if (wgpairs[i].active)
			return (true);
	return (false);
}

static void
wg_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct thost	*t;
	char		*sid;

	(void)err;
	sid = arg;
	t = thost(sid, false);
	free(sid);
	if (t == NULL)
		return;
	t->wg_loading = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL)
		return;
	if (t->wg != NULL)
		ucl_object_unref(t->wg);
	t->wg = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
	wg_pairs_step();
}

static void
bird_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct thost	*t;
	char		*sid;

	(void)err;
	sid = arg;
	t = thost(sid, false);
	free(sid);
	if (t == NULL)
		return;
	t->bird_loading = false;
	if (t->bird != NULL)
		ucl_object_unref(t->bird);
	t->bird = status == 200 && jbool(o, "ok") && jget(o, "data") != NULL ?
	    ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data")) : NULL;
}

/* Read what a host's BIRD says, quietly; a host without one says no. */
static void
bird_poll(int i)
{
	struct thost	*t;
	char		 url[240];

	/* Asked only of who has it: it is a plugin. */
	if (!app.online || !plugin_at(&app.servers[tn[i].srv], tn[i].jail,
	    "bird") || (t = thost(tn[i].key, true)) == NULL || t->bird_loading)
		return;
	t->bird_loading = true;
	node_url(i, "bird", "", url, sizeof(url));
	api("GET", url, NULL, bird_cb, strdup(tn[i].key));
}

/* Read a host's WireGuard interfaces, quietly, for the map's links. */
static void
wg_poll(int i)
{
	struct thost	*t;
	char		 url[240];

	/* wg(8) is the base system's: every host and vnet jail has it. */
	if (!app.online || (t = thost(tn[i].key, true)) == NULL ||
	    t->wg_loading)
		return;
	t->wg_loading = true;
	node_url(i, "wireguard", "", url, sizeof(url));
	api("GET", url, NULL, wg_cb, strdup(tn[i].key));
}

/* From the tick: the map watches every host, a host's tab its own. */
void
topo_tick(double now)
{
	static int	 wg_turn = -1;
	struct server	*s;
	int		 i;

	if (now - tp.last_poll < TOPO_POLL_MS)
		return;
	if (app.node == NODE_NETWORK) {
		tp.last_poll = now;
		/* WireGuard changes seldom: read less often, unless a
		 * tunnel waits for its keys. */
		wg_turn = wg_pending() ? 0 : (wg_turn + 1) % 6;
		nodes_build();
		for (i = 0; i < ntn; i++) {
			node_poll(i);
			if (wg_turn == 0)
				wg_poll(i);
			/* The routing tabs show BIRD itself: read each time. */
			if (wg_turn == 0 || app.netsect >= NETSECT_BGP)
				bird_poll(i);
		}
		render();
	} else if (app.node == NODE_HOST && app.tab == TAB_NETWORK &&
	    app.net.kind == NET_INTERFACES &&
	    (s = cur_server()) != NULL) {
		tp.last_poll = now;
		topo_poll(s);
		render();
	}
}

/* Is name an interface that a host of the fleet could be reached by? */
static bool
if_joins(const ucl_object_t *o)
{
	const char	*name;

	name = jstr(o, "name");
	return (name != NULL && strncmp(name, "lo", 2) != 0 &&
	    strncmp(name, "pflog", 5) != 0 && strncmp(name, "enc", 3) != 0);
}

/*
 * Is name a WireGuard interface of t: one its wg(8) read names, or wg<n>
 * before that is read.  Its peers are tunnels, not a network shared.
 */
static bool
if_wg(const struct thost *t, const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while (t != NULL && (o = ucl_object_iterate(jget(t->wg, "interfaces"),
	    &it, true)) != NULL)
		if (jstr(o, "name") != NULL && strcmp(jstr(o, "name"), name) ==
		    0)
			return (true);
	return (strncmp(name, "wg", 2) == 0 && name[2] >= '0' && name[2] <=
	    '9');
}

/*
 * A link between a and b, once: two ends that name each other are one
 * link, known by its two addresses whichever end it is seen from.
 */
static struct tlink *
link_add(int a, int b, int kind, const char *ifa, const char *ifb,
    const char *one, const char *other)
{
	struct tlink	*l;
	char		 key[160];
	int		 i;

	if (strcmp(one, other) <= 0)
		snprintf(key, sizeof(key), "%d|%s|%s", kind, one, other);
	else
		snprintf(key, sizeof(key), "%d|%s|%s", kind, other, one);
	for (i = 0; i < nlinks; i++) {
		l = &links[i];
		if (strcmp(l->key, key) != 0)
			continue;
		if (l->a == b && l->ifb[0] == '\0')
			snprintf(l->ifb, sizeof(l->ifb), "%s", ifa);
		return (l);
	}
	if (nlinks == TOPO_LINKS)
		return (NULL);
	l = &links[nlinks++];
	memset(l, 0, sizeof(*l));
	l->a = a;
	l->b = b;
	l->kind = kind;
	snprintf(l->key, sizeof(l->key), "%s", key);
	snprintf(l->ifa, sizeof(l->ifa), "%s", ifa);
	snprintf(l->ifb, sizeof(l->ifb), "%s", ifb);
	if (kind == LK_LAN)
		snprintf(l->label, sizeof(l->label), "%s", one);
	else
		snprintf(l->label, sizeof(l->label), "%s ⇄ %s", one, other);
	return (l);
}

/*
 * A link already joining the same two interfaces of the same two hosts,
 * whatever it was made of (a tunnel's ends, a point-to-point pair, a
 * network shared, a WireGuard peering): one link, however many
 * families or networks it carries; -1 for none.
 */
static int
link_same(int a, int b, const char *ifa, const char *ifb)
{
	int	i;

	for (i = 0; i < nlinks; i++) {
		if (links[i].b < 0 || links[i].kind > LK_LAN)
			continue;
		if (links[i].a == a && links[i].b == b && strcmp(links[i].ifa,
		    ifa) == 0 && strcmp(links[i].ifb, ifb) == 0)
			return (i);
		if (links[i].a == b && links[i].b == a && strcmp(links[i].ifa,
		    ifb) == 0 && strcmp(links[i].ifb, ifa) == 0)
			return (i);
	}
	return (-1);
}

/* The links, from the interfaces every host has now. */
/*
 * OSPF over a link drawn already: an adjacency names its interface, and
 * the two hosts' tunnel, point to point link or network on it carries
 * it, drawn inside it.  A pair's OSPF link of its own is drawn only for
 * an adjacency no such link carries.
 */
static void
ospf_carriers(void)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	struct tlink		*l, *c;
	const char		*ifn, *addr, *st;
	int			 i, k, m, s, sg, peer;
	bool			 up;

	for (i = 0; i < nhosts; i++) {
		if (hosts[i].bird == NULL || (s = node_index(hosts[i].sid)) ==
		    -1)
			continue;
		it = NULL;
		while ((o = ucl_object_iterate(jget(hosts[i].bird, "ospf"), &it,
		    true)) != NULL) {
			addr = jstr(o, "address");
			ifn = jstr(o, "interface");
			if (addr == NULL || (peer = owner(addr, NULL, 0)) == -1 ||
			    peer == s)
				continue;
			st = jstr(o, "state") != NULL ? jstr(o, "state") : "";
			up = strncmp(st, "Full", 4) == 0;
			c = NULL;
			for (k = 0; ifn != NULL && c == NULL && k < nlinks; k++) {
				l = &links[k];
				if (l->kind > LK_LAN)
					continue;
				if (l->a == s && strcmp(l->ifa, ifn) == 0) {
					if (l->b == peer)
						c = l;
					else if (l->b < 0 && (sg = -l->b - 1) < nsegs)
						for (m = 0; m < segs[sg].n; m++)
							if (segs[sg].member[m] == peer)
								c = l;
				} else if (l->b == s && l->a == peer &&
				    strcmp(l->ifb, ifn) == 0)
					c = l;
			}
			if (c != NULL) {
				c->ospf_in = true;
				c->ospf_in_up = c->ospf_in_up || up;
				continue;
			}
			for (k = 0; k < nlinks; k++)
				if (links[k].kind == LK_OSPF && ((links[k].a == s &&
				    links[k].b == peer) || (links[k].a == peer &&
				    links[k].b == s)))
					links[k].ospf_stray = true;
		}
	}
}

static void
links_build(void)
{
	const ucl_object_t	*o, *a;
	ucl_object_iter_t	 it, ait;
	struct thost		*t;
	struct tlink		*l;
	struct seg		*sg;
	char			 net[64], ifb[16];
	int			 i, k, m, s, peer;

	nlinks = nsegs = 0;
	for (i = 0; i < nhosts; i++) {
		t = &hosts[i];
		if (t->ifs == NULL || (s = node_index(t->sid)) == -1)
			continue;
		it = NULL;
		while ((o = ucl_object_iterate(jget(t->ifs, "interfaces"), &it,
		    true)) != NULL) {
			if (!if_joins(o))
				continue;
			/* A tunnel whose far end is a host of ours. */
			ifb[0] = '\0';
			if (jstr(o, "tunnel.remote") != NULL && (peer = owner(
			    jstr(o, "tunnel.remote"), NULL, 0)) != -1 &&
			    peer != s) {
				if ((l = link_add(s, peer, LK_TUNNEL, jstr(o,
				    "name"), "", jstr(o, "tunnel.local") !=
				    NULL ? jstr(o, "tunnel.local") : "?",
				    jstr(o, "tunnel.remote"))) != NULL)
					l->up = l->up || jbool(o, "up");
				continue;
			}
			ait = NULL;
			while ((a = ucl_object_iterate(jget(o, "addresses"),
			    &ait, true)) != NULL) {
				if (jstr(a, "address") == NULL || addr_local(
				    jstr(a, "address")))
					continue;
				/* A point-to-point peer that is a host of ours. */
				if (jstr(a, "destination") != NULL) {
					if ((peer = owner(jstr(a, "destination"),
					    ifb, sizeof(ifb))) != -1 && peer !=
					    s) {
						/* The other family of the same
						 * pair: the one link. */
						if ((k = link_same(s, peer, jstr(o,
						    "name"), ifb)) != -1) {
							links[k].more++;
							links[k].up = links[k].up ||
							    jbool(o, "up");
						} else if ((l = link_add(s, peer,
						    LK_P2P, jstr(o, "name"), ifb,
						    jstr(a, "address"),
						    jstr(a, "destination"))) !=
						    NULL)
							l->up = l->up ||
							    jbool(o, "up");
					}
					continue;
				}
				/* A network shared: gathered, joined below;
				 * not WireGuard's, whose peers are drawn as
				 * the tunnels they are. */
				if (if_wg(t, jstr(o, "name")) || !net_of(jstr(a,
				    "address"), (int)jint(a,
				    "prefixlen", 0), net, sizeof(net)))
					continue;
				for (k = 0; k < nsegs; k++)
					if (strcmp(segs[k].net, net) == 0)
						break;
				if (k == nsegs) {
					if (nsegs == TOPO_SEGS)
						continue;
					memset(&segs[nsegs], 0, sizeof(segs[0]));
					snprintf(segs[nsegs].net,
					    sizeof(segs[0].net), "%s", net);
					nsegs++;
				}
				sg = &segs[k];
				for (m = 0; m < sg->n; m++)
					if (sg->member[m] == s)
						break;
				if (m == sg->n && sg->n < MAX_NODES) {
					sg->member[sg->n] = s;
					snprintf(sg->ifn[sg->n],
					    sizeof(sg->ifn[0]), "%s", jstr(o,
					    "name"));
					sg->n++;
				}
			}
		}
	}
	/* A WireGuard peer whose key is an interface's of another host. */
	for (i = 0; i < nhosts; i++) {
		const ucl_object_t	*p;
		const char		*other;

		t = &hosts[i];
		if (t->wg == NULL || (s = node_index(t->sid)) == -1)
			continue;
		it = NULL;
		while ((o = ucl_object_iterate(jget(t->wg, "interfaces"), &it,
		    true)) != NULL) {
			if (jstr(o, "public-key") == NULL)
				continue;
			ait = NULL;
			while ((p = ucl_object_iterate(jget(o, "peers"), &ait,
			    true)) != NULL) {
				for (k = 0; k < nhosts; k++) {
					if (k == i || (peer = node_index(
					    hosts[k].sid)) == -1 || (other =
					    wg_iface(&hosts[k], jstr(p,
					    "public-key"), NULL)) == NULL)
						continue;
					/* Its addresses may have joined the two
					 * already: that link is the peering. */
					if ((m = link_same(s, peer, jstr(o,
					    "name"), other)) != -1) {
						l = &links[m];
						l->kind = LK_TUNNEL;
						l->up = true;
						snprintf(l->label,
						    sizeof(l->label),
						    "WireGuard %s ⇄ %s", jstr(o,
						    "name"), other);
					} else if ((l = link_add(s, peer,
					    LK_TUNNEL, jstr(o, "name"), other,
					    jstr(o, "public-key"), jstr(p,
					    "public-key"))) != NULL) {
						l->up = true;
						snprintf(l->label,
						    sizeof(l->label),
						    "WireGuard %s ⇄ %s", jstr(o,
						    "name"), other);
					}
				}
			}
		}
	}
	/*
	 * Routing: a BGP session or an OSPF adjacency with an address of
	 * another host is a link between the two; with any other address,
	 * a neighbour outside, drawn beside the host.
	 */
	nexts = 0;
	for (i = 0; i < nhosts; i++) {
		const char	*addr, *st;
		bool		 ospf, up;
		int		 mine, pass;

		t = &hosts[i];
		if (t->bird == NULL || (s = node_index(t->sid)) == -1)
			continue;
		mine = 0;
		for (pass = 0; pass < 2; pass++) {
			ospf = pass == 1;
			it = NULL;
			while ((o = ucl_object_iterate(jget(t->bird, ospf ?
			    "ospf" : "protocols"), &it, true)) != NULL) {
				if (!ospf && (jstr(o, "proto") == NULL ||
				    strcmp(jstr(o, "proto"), "BGP") != 0))
					continue;
				addr = jstr(o, ospf ? "address" : "neighbor");
				st = jstr(o, "state") != NULL ? jstr(o,
				    "state") : "";
				up = ospf ? strncmp(st, "Full", 4) == 0 :
				    strcmp(st, "up") == 0;
				if (addr == NULL)
					continue;
				if ((peer = owner(addr, NULL, 0)) != -1) {
					if (peer == s)
						continue;
					/* One for a pair, whichever end says it. */
					if ((l = link_add(s, peer, ospf ?
					    LK_OSPF : LK_BGP, "", "",
					    tn[s].key,
					    tn[peer].key)) != NULL) {
						l->up = l->up || up;
						if (ospf)
							snprintf(l->label,
							    sizeof(l->label),
							    "OSPF");
						else
							bgp_label(l->label,
							    sizeof(l->label), jstr(o,
							    "local-as"), jstr(o,
							    "neighbor-as"));
					}
					continue;
				}
				if (nexts == EXT_MAX)
					continue;
				/* A BGP neighbour outside whose session is down:
				 * left out, it says nothing of the network. */
				if (!ospf && !up)
					continue;
				memset(&exts[nexts], 0, sizeof(exts[0]));
				exts[nexts].host = s;
				exts[nexts].ospf = ospf;
				exts[nexts].up = up;
				exts[nexts].slot = mine++;
				if (ospf)
					snprintf(exts[nexts].label,
					    sizeof(exts[0].label), "%s", jstr(o,
					    "router-id") != NULL ? jstr(o,
					    "router-id") : "OSPF");
				else
					snprintf(exts[nexts].label,
					    sizeof(exts[0].label), "AS%s",
					    jstr(o, "neighbor-as") != NULL ?
					    jstr(o, "neighbor-as") : "?");
				snprintf(exts[nexts].sub, sizeof(exts[0].sub),
				    "%s", addr);
				nexts++;
			}
		}
		/* Fanned out by AS or router, however many sessions. */
		{
			int	j, groups;

			for (groups = 0, k = nexts - mine; k < nexts; k++) {
				for (j = nexts - mine; j < k; j++)
					if (exts[j].ospf == exts[k].ospf &&
					    strcmp(exts[j].label, exts[k].label) == 0)
						break;
				exts[k].slot = j < k ? exts[j].slot : groups++;
			}
			for (k = nexts - mine; k < nexts; k++)
				exts[k].of = groups;
		}
	}
	/* Two hosts in a network: a link.  More: a node they all join. */
	for (k = 0; k < nsegs; k++) {
		sg = &segs[k];
		if (sg->n == 2) {
			/* One link for a pair, however many networks they
			 * share: it says the first and how many more. */
			for (i = 0; i < nlinks; i++)
				if (links[i].kind == LK_LAN && links[i].b >= 0 &&
				    ((links[i].a == sg->member[0] && links[i].b ==
				    sg->member[1]) || (links[i].a ==
				    sg->member[1] && links[i].b ==
				    sg->member[0])))
					break;
			/* Or the tunnel, pair or WireGuard peering between
			 * the same two interfaces: the network rides it. */
			if (i == nlinks)
				i = link_same(sg->member[0], sg->member[1],
				    sg->ifn[0], sg->ifn[1]) == -1 ? nlinks :
				    link_same(sg->member[0], sg->member[1],
				    sg->ifn[0], sg->ifn[1]);
			if (i < nlinks) {
				links[i].more++;
				continue;
			}
			if ((l = link_add(sg->member[0], sg->member[1], LK_LAN,
			    sg->ifn[0], sg->ifn[1], sg->net, "")) != NULL)
				l->up = true;
		} else if (sg->n > 2) {
			/*
			 * The same hosts by the same interfaces as a node
			 * already made (IPv4 and IPv6 of one network): that
			 * node, its label saying both.
			 */
			for (i = 0; i < k; i++)
				if (segs[i].n == sg->n && segs[i].same == 0 &&
				    seg_same(&segs[i], sg))
					break;
			if (i < k) {
				sg->same = i + 1;
				for (m = 0; m < 2; m++)
					if (segs[i].more[m][0] == '\0') {
						snprintf(segs[i].more[m],
						    sizeof(segs[i].more[m]), "%s",
						    sg->net);
						break;
					}
				continue;
			}
			sg->x = sg->y = 0;
			for (m = 0; m < sg->n; m++) {
				t = thost(tn[sg->member[m]].key, false);
				sg->x += t != NULL ? t->x / sg->n : 0;
				sg->y += t != NULL ? t->y / sg->n : 0;
				if ((l = link_add(sg->member[m], -k - 1, LK_LAN,
				    sg->ifn[m], "", sg->net, tn[
				    sg->member[m]].key)) != NULL)
					l->up = true;
			}
		}
	}
	/*
	 * A jail with a network of its own hangs on its host: by the end
	 * of an epair it was given, when it has one, whose other end the
	 * host has.
	 */
	for (i = 0; i < ntn; i++) {
		char	ifa[16], hif[16];

		if (tn[i].jail[0] == '\0')
			continue;
		ifa[0] = hif[0] = '\0';
		t = thost(tn[i].key, false);
		it = NULL;
		while (t != NULL && (o = ucl_object_iterate(jget(t->ifs,
		    "interfaces"), &it, true)) != NULL) {
			size_t	n;

			if (jstr(o, "name") == NULL || strncmp(jstr(o, "name"),
			    "epair", 5) != 0 || (n = strlen(jstr(o, "name"))) <
			    7 || n >= sizeof(ifa) || jstr(o, "name")[n - 1] != 'b')
				continue;
			snprintf(ifa, sizeof(ifa), "%s", jstr(o, "name"));
			snprintf(hif, sizeof(hif), "%s", ifa);
			hif[n - 1] = 'a';
			break;
		}
		if ((l = link_add(i, node_host(i), LK_VNET, ifa, hif, tn[i].key,
		    "host")) != NULL) {
			l->up = t != NULL && t->ifs != NULL;
			snprintf(l->label, sizeof(l->label), "%s is a jail of "
			    "%s", tn[i].jail, tn[node_host(i)].name);
		}
	}
	ospf_carriers();
	for (i = 0; i < nlinks; i++) {
		l = &links[i];
		l->rate = rate_now(thost(tn[l->a].key, false), l->ifa);
	}
}

/* A rate in bits a second, in the unit that keeps it short. */
void
fmt_rate(char *buf, size_t len, double bytes)
{
	static const char *units[] = { "b/s", "kb/s", "Mb/s", "Gb/s" };
	double	v;
	int	u;

	v = bytes * 8;
	for (u = 0; v >= 1000 && u < 3; u++)
		v /= 1000;
	snprintf(buf, len, u == 0 ? "%.0f %s" : "%.1f %s", v, units[u]);
}

/*
 * The rate of an interface over time: what came in above the line,
 * what went out below it, both to the scale of the larger.
 */
static void
chart(struct html *h, const struct ifrate *r, int w, int ht)
{
	char	top[24];
	double	max, x, mid;
	int	i, pass;

	max = 1;
	for (i = 0; r != NULL && i < r->n; i++) {
		if (r->in[i] > max)
			max = r->in[i];
		if (r->out[i] > max)
			max = r->out[i];
	}
	mid = ht / 2.0;
	h_fmt(h, "<svg class=\"bw\" viewBox=\"0 0 %d %d\" "
	    "preserveAspectRatio=\"none\"><line class=\"axis\" x1=\"0\" "
	    "y1=\"%.1f\" x2=\"%d\" y2=\"%.1f\"/>", w, ht, mid, w, mid);
	for (pass = 0; r != NULL && r->n > 1 && pass < 2; pass++) {
		h_fmt(h, "<path class=\"%s\" d=\"M0 %.1f", pass == 0 ? "in" :
		    "out", mid);
		for (i = 0; i < r->n; i++) {
			x = (double)w * (TOPO_HIST - r->n + i) / (TOPO_HIST - 1);
			h_fmt(h, " L%.1f %.1f", x, pass == 0 ? mid -
			    (mid - 2) * r->in[i] / max : mid + (mid - 2) *
			    r->out[i] / max);
		}
		h_fmt(h, " L%d %.1f Z\"/>", w, mid);
	}
	h_raw(h, "</svg>");
	if (r != NULL && r->n > 0) {
		fmt_rate(top, sizeof(top), max);
		h_raw(h, "<span class=\"bw-max\">peak ");
		h_txt(h, top);
		h_raw(h, "</span>");
	}
}

/* A small chart of one interface of a host, for a table's cell. */
void
topo_spark(struct html *h, const struct server *s, const char *ifname)
{
	struct thost	*t;
	struct ifrate	*r;
	char		 in[24], out[24];

	if ((t = thost(page_key(s), false)) == NULL || (r = rate_of(t, ifname,
	    false)) == NULL || r->n == 0) {
		h_raw(h, "<span class=\"dim\">…</span>");
		return;
	}
	fmt_rate(in, sizeof(in), r->in[r->n - 1]);
	fmt_rate(out, sizeof(out), r->out[r->n - 1]);
	h_raw(h, "<div class=\"bw-cell\">");
	chart(h, r, 120, 26);
	h_raw(h, "<small>↓ ");
	h_txt(h, in);
	h_raw(h, " · ↑ ");
	h_txt(h, out);
	h_raw(h, "</small></div>");
}

/* Where a server's node is; false when it has none. */
static bool
place(int s, double *xp, double *yp)
{
	struct thost	*t;

	if (s < 0) {
		if (-s - 1 >= nsegs)
			return (false);
		*xp = segs[-s - 1].x;
		*yp = segs[-s - 1].y;
		return (true);
	}
	if (s >= ntn || (t = thost(tn[s].key, false)) == NULL)
		return (false);
	*xp = t->x;
	*yp = t->y;
	return (true);
}

/*
 * A curve from one point to another, bent sideways by bend; the point
 * of it at t goes to *mx, *my when asked for.
 */
static void
curve(struct html *h, double x1, double y1, double x2, double y2, double bend,
    double t, double *mx, double *my)
{
	double	dx, dy, len, cx, cy;

	dx = x2 - x1;
	dy = y2 - y1;
	len = sqrt(dx * dx + dy * dy);
	if (len < 1)
		len = 1;
	cx = (x1 + x2) / 2 - dy / len * bend;
	cy = (y1 + y2) / 2 + dx / len * bend;
	if (h != NULL)
		h_fmt(h, "M%.1f %.1f Q%.1f %.1f %.1f %.1f", x1, y1, cx, cy, x2,
		    y2);
	if (mx != NULL) {
		*mx = (1 - t) * (1 - t) * x1 + 2 * (1 - t) * t * cx + t * t * x2;
		*my = (1 - t) * (1 - t) * y1 + 2 * (1 - t) * t * cy + t * t * y2;
	}
}

/* How far to bend the i-th link so that those of a pair do not cover
 * each other: none, one side, the other, further out. */
static double
bend_of(int i)
{
	struct bend	*b;
	int		 k, n;

	if ((b = bend_kept(links[i].key, false)) != NULL)
		return (b->bend);
	n = 0;
	for (k = 0; k < i; k++)
		if ((links[k].a == links[i].a && links[k].b == links[i].b) ||
		    (links[k].a == links[i].b && links[k].b == links[i].a))
			n++;
	if (n == 0)
		return (0);
	return ((n % 2 == 1 ? 1 : -1) * 34.0 * ((n + 1) / 2));
}

/* A BGP session's name: "iBGP AS65000" within one AS, "eBGP AS65000 ⇄
 * AS65001" across two. */
static void
bgp_label(char *buf, size_t len, const char *las, const char *nas)
{

	if (las != NULL && nas != NULL && strcmp(las, nas) == 0)
		snprintf(buf, len, "iBGP AS%s", las);
	else
		snprintf(buf, len, "eBGP AS%s ⇄ AS%s", las != NULL ? las : "?",
		    nas != NULL ? nas : "?");
}

/* A link between routing neighbours rather than a wire: BGP, OSPF. */
static bool
neighbourship(int kind)
{

	return (kind == LK_BGP || kind == LK_OSPF);
}

/* The diagram's curve for the i-th neighbourship of a pair: the
 * straight links keep the middle, these bow out one side then the
 * other, further each time. */
static double
neighbour_bend(int i)
{
	int	k, n;

	n = 0;
	for (k = 0; k < i; k++)
		if (neighbourship(links[k].kind) && ((links[k].a == links[i].a
		    && links[k].b == links[i].b) || (links[k].a == links[i].b &&
		    links[k].b == links[i].a)))
			n++;
	return ((n % 2 == 0 ? 1 : -1) * (46.0 + 30.0 * (n / 2)) *
	    (links[i].a > links[i].b ? -1 : 1));
}

/* The i-th link of a pair drawn straight, as the diagram draws them:
 * shifted sideways so that those of the pair lie side by side. */
static void
para_shift(int i, double *x1, double *y1, double *x2, double *y2)
{
	double	dx, dy, len, off, gap;
	int	k, n, of;

	/* Its place among the pair's straight links, and how many there
	 * are: spread at most 20 either side, inside the router's glyph,
	 * so that each meets it however many there are. */
	n = of = 0;
	for (k = 0; k < nlinks; k++) {
		if (neighbourship(links[k].kind) || !((links[k].a == links[i].a
		    && links[k].b == links[i].b) || (links[k].a == links[i].b &&
		    links[k].b == links[i].a)))
			continue;
		if (k < i)
			n++;
		of++;
	}
	if (of < 2)
		return;
	gap = 40.0 / (of - 1);
	if (gap > 14)
		gap = 14;
	off = (n - (of - 1) / 2.0) * gap;
	if (links[i].a > links[i].b)
		off = -off;
	dx = *x2 - *x1;
	dy = *y2 - *y1;
	len = sqrt(dx * dx + dy * dy);
	if (len < 1)
		len = 1;
	*x1 -= dy / len * off;
	*x2 -= dy / len * off;
	*y1 += dx / len * off;
	*y2 += dx / len * off;
}

/*
 * Where along a link, from its end at (x, y), it leaves the host's box
 * there, and a little further: where that end's name is written.
 */
static double
leave_t(double x1, double y1, double x2, double y2, double bend, bool from_a)
{
	double	t, px, py, ex, ey;

	ex = from_a ? x1 : x2;
	ey = from_a ? y1 : y2;
	for (t = 0.02; t < 0.42; t += 0.01) {
		curve(NULL, x1, y1, x2, y2, bend, from_a ? t : 1 - t, &px, &py);
		if (tp.stencil ? hypot(px - ex, py - ey) > 40 : fabs(px - ex) >
		    NODE_W / 2 + 16 || fabs(py - ey) > NODE_H / 2 + 12)
			break;
	}
	return (from_a ? t : 1 - t);
}

/*
 * The routing tables an interface is in: its own (fib), and for a
 * tunnel the one its outer packets are looked up in (tunnelfib), -1
 * when it is no tunnel.  The agent leaves both out when 0.
 */
static void
if_tables(const ucl_object_t *o, int *fibp, int *tfibp)
{

	*fibp = o != NULL ? (int)jint(o, "fib", 0) : 0;
	*tfibp = o != NULL && jget(o, "tunnel") != NULL ? (int)jint(o,
	    "tunnelfib", 0) : -1;
}

/* How many interfaces each routing table has, over the hosts read: by
 * their own table and, a tunnel, by its outer packets' too. */
static void
fibs_present(int n[8])
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	int			 i, f, tf;

	memset(n, 0, 8 * sizeof(int));
	for (i = 0; i < nhosts; i++) {
		it = NULL;
		while ((o = ucl_object_iterate(jget(hosts[i].ifs, "interfaces"),
		    &it, true)) != NULL) {
			if_tables(o, &f, &tf);
			if (f >= 0 && f < 8)
				n[f]++;
			if (tf >= 0 && tf < 8 && tf != f)
				n[tf]++;
		}
	}
}

/* The tables of a link's end: the interface's at node i. */
static void
link_tables(int i, const char *ifn, int *fibp, int *tfibp)
{
	const struct thost	*t;

	*fibp = 0;
	*tfibp = -1;
	if (i < 0 || ifn == NULL || ifn[0] == '\0')
		return;
	t = thost(tn[i].key, false);
	if_tables(if_named(t, ifn), fibp, tfibp);
}

/* Is the link in the table shown?  In it by either end's interface,
 * or by a tunnel's outer packets. */
static bool
link_in_fib(const struct tlink *l, int fib)
{
	int	fa, ta, fb, tb;

	if (fib < 0)
		return (true);
	link_tables(l->a, l->ifa, &fa, &ta);
	link_tables(l->b, l->ifb, &fb, &tb);
	return (fa == fib || ta == fib || (l->b >= 0 && (fb == fib || tb ==
	    fib)));
}

/*
 * Is node i a vnet jail left out of the drawing: one whose links all
 * go to its own host (an epair, the host's bridge), with no other host,
 * no network others are in, and no routing neighbour, unless asked for
 * them all.
 */
static bool
node_lone(int i)
{
	int	k, m, p, s;

	if (tp.lonevnet || i < 0 || i >= ntn || tn[i].jail[0] == '\0')
		return (false);
	p = node_host(i);
	for (k = 0; k < nlinks; k++) {
		if (links[k].a != i && links[k].b != i)
			continue;
		if (links[k].b < 0) {
			s = -links[k].b - 1;
			for (m = 0; s < nsegs && m < segs[s].n; m++)
				if (segs[s].member[m] != i &&
				    segs[s].member[m] != p)
					return (false);
			continue;
		}
		if ((links[k].a == i ? links[k].b : links[k].a) != p)
			return (false);
	}
	for (k = 0; k < nexts; k++)
		if (exts[k].host == i)
			return (false);
	return (true);
}

/* An interface's name with its own table in the table's colour, "gre0
 * fib 1", when the link has to do with any table past the first (say);
 * the name alone otherwise.  Each end says its own: the far end's label
 * says the other, and a tunnel's outer table is its dashed line. */
static void
if_label(struct html *h, const char *name, int fib, bool say)
{

	h_txt(h, name);
	if (say)
		h_fmt(h, " <tspan class=\"fib fib%d\">fib %d</tspan>", fib > 6 ? 6
		    : fib, fib);
}

/*
 * The links' labels, drawn after the links and the nodes so that no line
 * crosses them: a link's go here unless they show only under the
 * pointer (quiet) or the link is dimmed, when they stay in its group.
 */
static struct html	tlab;

static bool	link_probe(const struct tlink *, double *, double *,
		    double *);

/* A link's bytes a second each way, a to b and back, as its a end
 * counted them (else its b end, the other way round). */
static void
link_dirs(const struct tlink *l, double *ab, double *ba)
{
	struct thost	*t;
	struct ifrate	*r;

	*ab = *ba = 0;
	if ((t = thost(tn[l->a].key, false)) != NULL && (r = rate_of(t, l->ifa,
	    false)) != NULL && r->n > 0) {
		*ab = r->out[r->n - 1];
		*ba = r->in[r->n - 1];
		return;
	}
	if (l->b >= 0 && l->ifb[0] != '\0' && (t = thost(tn[l->b].key,
	    false)) != NULL && (r = rate_of(t, l->ifb, false)) != NULL &&
	    r->n > 0) {
		*ab = r->in[r->n - 1];
		*ba = r->out[r->n - 1];
	}
}

static void
map_links(struct html *h)
{
	static const char *const kinds[] = { "tunnel", "p2p", "lan", "bgp",
	    "ospf", "vnet" };
	struct tlink	*l;
	char		 rate[24];
	double		 x1, y1, x2, y2, mx, my, bend, w, ab, ba, pd, pj, pl;
	struct html	*lh;
	int		 i, flow, fa, ta, fb, tb, outer;
	bool		 pr_ok;

	h_reset(&tlab);
	for (i = 0; i < nlinks; i++) {
		l = &links[i];
		if (node_lone(l->a) || node_lone(l->b))
			continue;
		if (l->kind == LK_OSPF && !l->ospf_stray)
			continue;
		if (tp.hide[l->kind] || !place(l->a, &x1, &y1) || !place(l->b,
		    &x2, &y2))
			continue;
		link_tables(l->a, l->ifa, &fa, &ta);
		link_tables(l->b, l->ifb, &fb, &tb);
		/* A link keeps its kind's colour; its tables are said at its
		 * ends, and a tunnel whose outer packets go by another table
		 * gets a thin dashed line of that table's colour along its own.
		 * With one table shown, the links outside it are dimmed, not
		 * gone: the map keeps its shape. */
		outer = ta >= 0 && ta != fa ? ta : tb >= 0 && tb != fb ? tb : -1;
		if (tp.stencil && neighbourship(l->kind) && l->b >= 0)
			bend = neighbour_bend(i);
		else if (tp.stencil) {
			bend = 0;
			para_shift(i, &x1, &y1, &x2, &y2);
		} else
			bend = bend_of(i);
		w = 1.6 + log10(1 + l->rate / 1000.0) * 1.1;
		if (w > 7)
			w = 7;
		flow = l->rate < 1000 ? 0 : l->rate < 100000 ? 1 : l->rate <
		    10000000 ? 2 : 3;
		h_fmt(h, "<g class=\"tlink %s %s flow%d%s%s", kinds[l->kind],
		    l->up ? "up" : "down", flow, strcmp(tp.sel_link, l->key) ==
		    0 ? " sel" : "", labels_quiet(l->kind) ? " quiet" : "");
		if (outer >= 0)
			h_fmt(h, " o%d", outer > 6 ? 6 : outer);
		if (!link_in_fib(l, tp.fib))
			h_raw(h, " dim");
		h_fmt(h, "\"><path class=\"wire\" style=\"stroke-width:%.1f\" d=\"",
		    w);
		curve(h, x1, y1, x2, y2, bend, 0.5, &mx, &my);
		h_raw(h, "\"/>");
		/* A tunnel whose outer packets go by another table: ticks across
		 * it in that table's colour, a rail, unlike OSPF's dots. */
		if (outer >= 0) {
			h_raw(h, "<path class=\"outer\" d=\"");
			curve(h, x1, y1, x2, y2, bend, 0.5, NULL, NULL);
			h_raw(h, "\"/>");
		}
		/* OSPF over it: a dotted line inside it. */
		if (l->ospf_in && !tp.hide[LK_OSPF]) {
			h_fmt(h, "<path class=\"ospfin%s\" d=\"", l->ospf_in_up ? "" :
			    " down");
			curve(h, x1, y1, x2, y2, bend, 0.5, NULL, NULL);
			h_raw(h, "\"/>");
		}
		/* Its state in the WebGL layer (a link down breathes red);
		 * its traffic the SVG's own dashes. */
		if (link_in_fib(l, tp.fib)) {
			link_dirs(l, &ab, &ba);
			glmap_link(x1, y1, x2, y2, bend, l->b >= 0 ? leave_t(x1,
			    y1, x2, y2, bend, true) : 0.08, l->b >= 0 ? leave_t(x1,
			    y1, x2, y2, bend, false) : 0.92, ab, ba, w, l->kind,
			    l->up);
		}
		/* A tunnel measured (Quality's monitors): its probes cross
		 * it as the last sample did. */
		pr_ok = l->kind == LK_TUNNEL && l->b >= 0 && link_in_fib(l,
		    tp.fib) && link_probe(l, &pd, &pj, &pl);
		if (pr_ok)
			glmap_probe(x1, y1, x2, y2, bend, leave_t(x1, y1, x2, y2,
			    bend, true), leave_t(x1, y1, x2, y2, bend, false), pd,
			    pj, pl);
		if (flow > 0) {
			h_raw(h, "<path class=\"flow\" d=\"");
			curve(h, x1, y1, x2, y2, bend, 0.5, NULL, NULL);
			h_raw(h, "\"/>");
		}
		/* Picked, or dragged aside from the others. */
		h_raw(h, "<path class=\"hit\" data-drag=\"topo-bend\"");
		h_attr(h, "data-arg", l->key);
		h_raw(h, " d=\"");
		curve(h, x1, y1, x2, y2, bend, 0.5, NULL, NULL);
		h_raw(h, "\"><title>");
		h_txt(h, l->label);
		if (l->ospf_in)
			h_raw(h, " · OSPF over it");
		if (outer >= 0)
			h_fmt(h, " · its outer packets by FIB %d", outer);
		h_raw(h, "</title></path>");
		if ((labels_quiet(l->kind) && strcmp(tp.sel_link, l->key) != 0) ||
		    !link_in_fib(l, tp.fib))
			lh = h;
		else {
			lh = &tlab;
			h_fmt(lh, "<g class=\"tlabel %s\">", kinds[l->kind]);
		}
		/*
		 * A tunnel's or a point to point link's ends are named each
		 * at its own end, past the host's box; its rate is in the
		 * middle, alone.  Another kind's name is above the middle,
		 * its rate below.
		 */
		if (l->b >= 0 && l->kind < LK_LAN) {
			double	ex, ey;

			curve(NULL, x1, y1, x2, y2, bend, leave_t(x1, y1, x2,
			    y2, bend, true), &ex, &ey);
			h_fmt(lh, "<text class=\"lbl end\" x=\"%.1f\" y=\"%.1f\">",
			    ex, ey - 5);
			if_label(lh, l->ifa, fa, fa > 0 || fb > 0 || ta > 0 || tb > 0);
			h_raw(lh, "</text>");
			if (l->ifb[0] != '\0') {
				curve(NULL, x1, y1, x2, y2, bend, leave_t(x1, y1,
				    x2, y2, bend, false), &ex, &ey);
				h_fmt(lh, "<text class=\"lbl end\" x=\"%.1f\" "
				    "y=\"%.1f\">", ex, ey - 5);
				if_label(lh, l->ifb, fb, fa > 0 || fb > 0 || ta > 0 ||
				    tb > 0);
				h_raw(lh, "</text>");
			}
		} else if (l->b >= 0) {
			h_fmt(lh, "<text class=\"lbl\" x=\"%.1f\" y=\"%.1f\">", mx,
			    my - 7);
			h_txt(lh, l->label);
			if (l->more > 0)
				h_fmt(lh, " +%d", l->more);
			h_raw(lh, "</text>");
		}
		if (l->rate >= 1) {
			fmt_rate(rate, sizeof(rate), l->rate);
			h_fmt(lh, "<text class=\"rate\" x=\"%.1f\" y=\"%.1f\">",
			    mx, l->b >= 0 && l->kind < LK_LAN ? my + 3.5 : my +
			    14);
			h_txt(lh, rate);
			h_raw(lh, "</text>");
		}
		/* What its probes last measured, under the rate. */
		if (pr_ok)
			h_fmt(lh, "<text class=\"probe%s\" x=\"%.1f\" y=\"%.1f\">"
			    "%.1f ms · %.1f ms · %.1f %% lost</text>", pl > 0 ?
			    " lossy" : "", mx, my + (l->rate >= 1 ? 15.5 : 3.5), pd,
			    pj, pl * 100);
		if (lh == &tlab)
			h_raw(lh, "</g>");
		h_raw(h, "</g>");
	}
}

/* The route found, over the map: each hop an arrow, and beside it the
 * routes that would be taken in its place. */
static void
map_path(struct html *h)
{
	struct hop	*p;
	double		 x1, y1, x2, y2, mx, my;
	int		 i, k;

	for (i = 0; i < path.n; i++) {
		p = &path.hops[i];
		if (!place(p->from, &x1, &y1))
			continue;
		for (k = 0; !tp.hide_alt && k < p->nalt; k++) {
			if (p->alt[k].to < 0 || p->alt[k].to == p->to ||
			    !place(p->alt[k].to, &x2, &y2))
				continue;
			h_raw(h, "<path class=\"tpath alt\" marker-end=\""
			    "url(#arrow-alt)\" d=\"");
			curve(h, x1, y1, x2, y2, -58.0 - 22 * k, 0.5, &mx, &my);
			h_raw(h, "\"><title>instead: ");
			h_txt(h, p->alt[k].dest);
			h_raw(h, " via ");
			h_txt(h, p->alt[k].gw);
			h_raw(h, "</title></path>");
		}
		if (tp.hide_best)
			continue;
		if (p->to >= 0 && place(p->to, &x2, &y2)) {
			h_raw(h, "<path class=\"tpath best\" marker-end=\""
			    "url(#arrow)\" d=\"");
			curve(h, x1, y1, x2, y2, 58, 0.5, &mx, &my);
			h_fmt(h, "\"/><g class=\"hopno\" transform=\"translate("
			    "%.1f,%.1f)\"><circle r=\"10\"/><text y=\"4\">%d"
			    "</text></g>", mx, my, i + 1);
		} else if (p->to < 0 && p->gw[0] != '\0') {
			h_fmt(h, "<path class=\"tpath best out\" marker-end=\""
			    "url(#arrow)\" d=\"M%.1f %.1f L%.1f %.1f\"/><text "
			    "class=\"lbl\" x=\"%.1f\" y=\"%.1f\">", x1, y1, x1 +
			    150, y1 - 70, x1 + 156, y1 - 74);
			h_txt(h, p->gw);
			h_raw(h, "</text>");
		}
	}
}

/* Two networks of the same hosts, by the same interfaces. */
static bool
seg_same(const struct seg *a, const struct seg *b)
{
	int	i, j;

	for (i = 0; i < a->n; i++) {
		for (j = 0; j < b->n; j++)
			if (a->member[i] == b->member[j] && strcmp(a->ifn[i],
			    b->ifn[j]) == 0)
				break;
		if (j == b->n)
			return (false);
	}
	return (true);
}

static void
map_nodes(struct html *h)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	struct server		*s;
	struct thost		*t;
	char			 rate[24], sub[64];
	double			 total;
	int			 i, k, nif, f, tf, dim;

	/* A network several are in: with its lines, or not at all. */
	for (k = 0; !tp.hide[LK_LAN] && k < nsegs; k++) {
		if (segs[k].n < 3 || segs[k].same != 0)
			continue;
		/* Outside the table shown: dimmed, with its lines. */
		for (dim = tp.fib >= 0, i = 0; dim && i < segs[k].n; i++) {
			link_tables(segs[k].member[i], segs[k].ifn[i], &f, &tf);
			if (f == tp.fib || tf == tp.fib)
				dim = 0;
		}
		if (tp.stencil)
			/* A hub, as a diagram draws a shared medium. */
			h_fmt(h, "<g class=\"tseg hub%s\" transform=\"translate(%.1f,"
			    "%.1f)\"><rect x=\"-30\" y=\"-9\" width=\"60\" height=\"18\" "
			    "rx=\"3\"/><circle cx=\"-18\" cy=\"0\" r=\"2.2\"/><circle cx=\"-6\" "
			    "cy=\"0\" r=\"2.2\"/><circle cx=\"6\" cy=\"0\" r=\"2.2\"/><circle "
			    "cx=\"18\" cy=\"0\" r=\"2.2\"/><text y=\"28\">", dim ? " dim" :
			    "", segs[k].x, segs[k].y);
		else
			h_fmt(h, "<g class=\"tseg%s\" transform=\"translate(%.1f,%.1f)\">"
			    "<rect x=\"-9\" y=\"-9\" width=\"18\" height=\"18\" "
			    "transform=\"rotate(45)\"/><text y=\"28\">", dim ? " dim" :
			    "", segs[k].x, segs[k].y);
		h_txt(h, segs[k].net);
		h_raw(h, "</text>");
		/* The others of the same hosts, one a line under it. */
		for (i = 0; i < 2 && segs[k].more[i][0] != '\0'; i++) {
			h_fmt(h, "<text y=\"%d\">", 42 + 14 * i);
			h_txt(h, segs[k].more[i]);
			h_raw(h, "</text>");
		}
		h_raw(h, "</g>");
	}
	peers_layout();
	/* The routing neighbours outside, fanned out away from the middle. */
	for (i = 0; !tp.nopeers && i < nexts; i++) {
		if (tp.hide[exts[i].ospf ? LK_OSPF : LK_BGP])
			continue;
		struct ext	*e = &exts[i];
		double		 ex, ey;

		if ((t = thost(tn[e->host].key, false)) == NULL)
			continue;
		{
			char	key[160];
			int	lead, ns, k;

			lead = as_leader(i);
			as_place(lead, &ex, &ey);
			peer_key(key, sizeof(key), &exts[lead]);
			/* Every session or adjacency: a line to its node. */
			h_fmt(h, "<g class=\"tpeer %s session %s\"><path d=\"M%.1f %.1f "
			    "L%.1f %.1f\"><title>", e->ospf ? "ospf" : "bgp", e->up ? "up" :
			    "down", t->x, t->y, ex, ey);
			h_txt(h, tn[e->host].name);
			h_raw(h, " · ");
			h_txt(h, e->label);
			h_raw(h, " · ");
			h_txt(h, e->sub);
			h_raw(h, "</title></path></g>");
			if (lead != i)
				continue;
			for (ns = 0, k = 0; k < nexts; k++)
				ns += as_leader(k) == lead;
			/* The node, dragged as one: an AS a cloud, an OSPF
			 * neighbour a dotted router. */
			h_fmt(h, "<g class=\"tpeer %s %s\" data-drag=\"topo-peer\"",
			    e->ospf ? "ospf" : "bgp", e->up ? "up" : "down");
			h_attr(h, "data-arg", key);
			if (e->ospf)
				h_fmt(h, "><circle class=\"glyph\" cx=\"%.1f\" cy=\"%.1f\" "
				    "r=\"22\"/><path class=\"arrows\" transform=\"translate("
				    "%.1f,%.1f)\" d=\"M-14 -6h24M3 -11l6 5-6 5M14 6h-24M-3 11l-6"
				    "-5 6-5\"/><text class=\"name\" x=\"%.1f\" y=\"%.1f\">", ex,
				    ey, ex, ey, ex, ey + 36);
			else
				h_fmt(h, "><path class=\"cloud\" transform=\"translate("
				    "%.1f,%.1f)\" d=\"M-36 16 A15 15 0 0 1 -30 -12 A18 18 0 0 1 "
				    "0 -26 A18 18 0 0 1 30 -12 A15 15 0 0 1 36 16 Z\"/><text class=\"name\" x=\"%.1f\" y=\"%.1f\">", ex,
				    ey, ex, ey - 2);
			h_fit(h, e->label, 16);
			h_fmt(h, "</text><text class=\"sub\" x=\"%.1f\" y=\"%.1f\">", ex,
			    e->ospf ? ey + 48 : ey + 10);
			if (ns > 1)
				h_fmt(h, "%d %s", ns, e->ospf ? "adjacencies" : "sessions");
			else
				h_fit(h, e->sub, 20);
			h_raw(h, "</text><title>");
			h_txt(h, e->label);
			if (e->ospf)
				h_fmt(h, ": an OSPF neighbour outside this console, %d "
				    "adjacenc%s with it</title></g>", ns, ns == 1 ? "y" : "ies");
			else
				h_fmt(h, ": a BGP neighbour outside this console, %d "
				    "session%s to it</title></g>", ns, ns == 1 ? "" : "s");
		}
	}
	/* The running jails of each host, hung under it. */
	for (i = 0; tp.jails && i < app.nservers; i++) {
		const ucl_object_t	*j;
		double			 jx, jy;
		int			 nj, m;

		s = &app.servers[i];
		if ((t = thost(s->id, false)) == NULL || s->list == NULL)
			continue;
		nj = 0;
		it = NULL;
		while ((j = ucl_object_iterate(jget(s->list, "jails"), &it,
		    true)) != NULL)
			if (jstr(j, "state") != NULL && strcmp(jstr(j, "state"),
			    "running") == 0 && !jbool(j, "vnet"))
				nj++;
		m = 0;
		it = NULL;
		while ((j = ucl_object_iterate(jget(s->list, "jails"), &it,
		    true)) != NULL && m < 12) {
			/* One with a network of its own is a node itself. */
			if (jstr(j, "state") == NULL || strcmp(jstr(j, "state"),
			    "running") != 0 || jstr(j, "name") == NULL ||
			    jbool(j, "vnet"))
				continue;
			jx = t->x + (m - ((nj > 12 ? 12 : nj) - 1) / 2.0) * 46;
			jy = t->y + NODE_H / 2 + 34 + (m % 2) * 16;
			h_fmt(h, "<g class=\"tjail\"><path d=\"M%.1f %.1f L%.1f "
			    "%.1f\"/><circle cx=\"%.1f\" cy=\"%.1f\" r=\"5\"/>"
			    "<text x=\"%.1f\" y=\"%.1f\">", t->x, t->y +
			    NODE_H / 2, jx, jy, jx, jy, jx, jy + 15);
			h_txt(h, jstr(j, "name"));
			h_raw(h, "</text></g>");
			m++;
		}
	}
	/*
	 * The bridges of each node, above it: a box for each, with a dot
	 * for every member in the colour the spanning tree gave it, and a
	 * line to the jail whose end of an epair is in the bridge.
	 */
	for (i = 0; !tp.hide[LK_VNET] && i < ntn; i++) {
		const ucl_object_t	*b, *m, *jf;
		ucl_object_iter_t	 bit, mit, jit;
		struct thost		*jt;
		const char		*mn, *st;
		char			 other[24];
		double			 bx, by;
		int			 nb, nbr, nm, k, np, len;

		if ((t = thost(tn[i].key, false)) == NULL || !t->placed ||
		    t->bridges == NULL)
			continue;
		nb = 0;
		nbr = (int)ucl_array_size(t->bridges);
		if (nbr > 4)
			nbr = 4;
		bit = NULL;
		while ((b = ucl_object_iterate(t->bridges, &bit, true)) != NULL &&
		    nb < 4) {
			/* The diagram: centred above the router, side by side. */
			if (tp.stencil) {
				bx = t->x + (nb - (nbr - 1) / 2.0) * 90;
				by = t->y - 88;
			} else {
				bx = t->x - NODE_W / 2 + 46 + nb * 104;
				by = t->y - NODE_H / 2 - 40;
			}
			/* To the jails behind its members, first: under it. */
			mit = NULL;
			while ((m = ucl_object_iterate(jget(b, "members"), &mit,
			    true)) != NULL) {
				mn = jstr(m, "name");
				len = mn != NULL ? (int)strlen(mn) : 0;
				if (len < 6 || strncmp(mn, "epair", 5) != 0 ||
				    mn[len - 1] != 'a')
					continue;
				snprintf(other, sizeof(other), "%.*sb", len - 1,
				    mn);
				for (k = 0; k < ntn; k++) {
					if (node_lone(k) || tn[k].srv != tn[i].srv ||
					    tn[k].jail[0]
					    == '\0' || (jt = thost(tn[k].key,
					    false)) == NULL || !jt->placed)
						continue;
					jit = NULL;
					while ((jf = ucl_object_iterate(jget(
					    jt->ifs, "interfaces"), &jit,
					    true)) != NULL)
						if (jstr(jf, "name") != NULL &&
						    strcmp(jstr(jf, "name"),
						    other) == 0)
							h_fmt(h, "<path class=\""
							    "tbrlink\" d=\"M%.1f "
							    "%.1f L%.1f %.1f\"/>",
							    bx, by, jt->x,
							    jt->y);
				}
			}
			if_tables(if_named(t, jstr(b, "name")), &f, &tf);
			h_fmt(h, "<g class=\"tbridge%s\" data-act=\"topo-open-bridges\"",
			    tp.fib >= 0 && f != tp.fib ? " dim" : "");
			h_attr(h, "data-arg", tn[i].key);
			/* Its line runs to the host's middle, under the glyph. */
			if (tp.stencil) {
				/* A switch, as the stencils draw one: a flat box, an
				 * arrow each way on two rows; its line runs to the
				 * router's middle, under the router's glyph. */
				h_fmt(h, "><path class=\"up\" d=\"M%.1f %.1f L%.1f %.1f\"/><rect "
				    "x=\"%.1f\" y=\"%.1f\" width=\"60\" height=\"24\" rx=\"3\"/>"
				    "<path class=\"sw\" transform=\"translate(%.1f,%.1f)\" "
				    "d=\"M-20 -5h38m-6 -4l6 4l-6 4M20 5h-38m6 -4l-6 4l6 4\"/>"
				    "<text class=\"name\" x=\"%.1f\" y=\"%.1f\">", bx, by +
				    12, t->x, t->y, bx - 30, by - 12, bx, by, bx, by - 22);
				h_fit(h, jstr(b, "name"), 12);
			} else {
				h_fmt(h, "><path d=\"M%.1f %.1f L%.1f %.1f\"/><rect x=\""
				    "%.1f\" y=\"%.1f\" width=\"96\" height=\"28\" rx=\""
				    "4\"/><text class=\"name\" x=\"%.1f\" y=\"%.1f\">",
				    bx, by + 14, bx, t->y, bx - 48, by - 14, bx - 42, by -
				    2);
				h_fit(h, jstr(b, "name"), 9);
			}
			h_raw(h, "</text>");
			/* The diagram puts them on the switch's top edge. */
			nm = (int)ucl_array_size(jget(b, "members"));
			if (nm > 9)
				nm = 9;
			np = 0;
			mit = NULL;
			while ((m = ucl_object_iterate(jget(b, "members"), &mit,
			    true)) != NULL && np < 9) {
				st = jstr(m, "state");
				h_fmt(h, "<circle class=\"p-%s\" cx=\"%.1f\" cy=\""
				    "%.1f\" r=\"3\"/>", !jbool(m, "stp") ? "off" :
				    st != NULL && strcmp(st, "forwarding") ==
				    0 ? "fwd" : st != NULL && (strcmp(st,
				    "discarding") == 0 || strcmp(st,
				    "blocking") == 0) ? "block" : "learn", tp.stencil ?
				    bx + (np - (nm - 1) / 2.0) * 8 : bx - 40 + np * 10,
				    tp.stencil ? by - 12 : by + 7);
				np++;
			}
			h_raw(h, "<title>");
			h_txt(h, jstr(b, "name"));
			h_fmt(h, ": a bridge with %d members%s%s. Press for its "
			    "ports.</title></g>", (int)ucl_array_size(jget(b,
			    "members")), jbool(b, "vlanfilter") ? ", filtering "
			    "VLANs" : "", jbool(b, "is_root") ? ", root of its "
			    "spanning tree" : "");
			nb++;
		}
	}
	for (i = 0; i < ntn; i++) {
		const char	*key = tn[i].key;

		if (node_lone(i))
			continue;
		s = &app.servers[tn[i].srv];
		if ((t = thost(key, false)) == NULL || !t->placed)
			continue;
		nif = 0;
		total = 0;
		it = NULL;
		while ((o = ucl_object_iterate(jget(t->ifs, "interfaces"), &it,
		    true)) != NULL)
			if (if_joins(o)) {
				nif++;
				total += rate_now(t, jstr(o, "name"));
			}
		h_fmt(h, "<g class=\"tnode %s%s%s%s\" transform=\"translate(%.1f,"
		    "%.1f)\" data-drag=\"topo-node\"", t->failed || s->failed ?
		    "down" : t->ifs != NULL ? "up" : "unknown",
		    strcmp(tp.sel, key) == 0 ? " sel" : "", tp.linking &&
		    strcmp(tp.link_from, key) != 0 ? " target" : "",
		    tn[i].jail[0] != '\0' ? " vjail" : "", t->x, t->y);
		h_attr(h, "data-arg", key);
		h_attr(h, "data-drop", key);
		if (tp.stencil && !node_routes(t, tn[i].jail[0] != '\0'))
			/* It forwards nothing: a server, as the stencils draw one. */
			h_raw(h, "><rect class=\"glyph\" x=\"-22\" y=\"-28\" width=\"44\" "
			    "height=\"56\" rx=\"4\"/><path class=\"lines\" d=\"M-14 -16h28M-14 "
			    "-6h28M-14 4h28\"/><circle class=\"led\" cx=\"12\" cy=\"16\" "
			    "r=\"3\"/><text class=\"name\" x=\"0\" y=\"44\">");
		else if (tp.stencil)
			/* A router: the circle with its four arrows. */
			h_raw(h, "><circle class=\"glyph\" r=\"28\"/><path class=\"arrows\" "
			    "d=\"M-18 -8h30M4 -14l8 6-8 6M18 8h-30M-4 14l-8-6 8-6\"/>"
			    "<circle class=\"led\" cx=\"20\" cy=\"-20\" r=\"4\"/><text "
			    "class=\"name\" x=\"0\" y=\"44\">");
		else
			h_fmt(h, "><rect class=\"box\" x=\"%d\" y=\"%d\" width=\"%d\" "
			    "height=\"%d\" rx=\"10\"/><circle class=\"led\" cx=\"%d\" "
			    "cy=\"-10\" r=\"4\"/><text class=\"name\" x=\"%d\" y=\"-5\">",
			    -NODE_W / 2, -NODE_H / 2, NODE_W, NODE_H, -NODE_W / 2 + 14,
			    -NODE_W / 2 + 26);
		h_fit(h, tn[i].name, tp.stencil ? 16 : 13);
		if (tp.stencil)
			h_raw(h, "</text><text class=\"sub\" x=\"0\" y=\"57\">");
		else
			h_fmt(h, "</text><text class=\"sub\" x=\"%d\" y=\"15\">",
			    -NODE_W / 2 + 12);
		if (t->ifs == NULL)
			snprintf(sub, sizeof(sub), "%s", t->failed ?
			    "no answer" : "reading…");
		else {
			fmt_rate(rate, sizeof(rate), total);
			snprintf(sub, sizeof(sub), "%d if · %s", nif, rate);
		}
		h_fit(h, sub, 20);
		h_raw(h, "</text><title>");
		h_txt(h, tn[i].name);
		h_raw(h, tn[i].jail[0] != '\0' ? " (a jail) · " : " · ");
		h_txt(h, sub);
		h_fmt(h, "</title><circle class=\"port\" cx=\"%d\" cy=\"0\" "
		    "r=\"7\" data-drag=\"topo-link\"", tp.stencil ? 28 : NODE_W / 2);
		h_attr(h, "data-arg", key);
		h_raw(h, "><title>Drag to another host to join them: a "
		    "tunnel, or a BGP, OSPF or BFD session</title></circle></g>");
	}
}

/*
 * Are a kind of link's labels left out?  With many links of a kind their
 * labels run into each other: they are left out then, and a link shows
 * its own when the pointer is on it or it is picked.  "Labels" says
 * otherwise, for each kind on its own.
 */
static bool
labels_quiet(int kind)
{
	int	i, n;

	if (tp.labels[kind] != 0)
		return (tp.labels[kind] == 2);
	/* A jail's line says what its node already shows. */
	if (kind == LK_VNET)
		return (true);
	for (i = n = 0; i < nlinks; i++)
		if (links[i].kind == kind)
			n++;
	return (n > 6);
}

/* The classes of the map's drawing. */
static const char *
wfmt_cls(void)
{
	static char	cls[56];

	snprintf(cls, sizeof(cls), "%s%s%s%s", tp.linking ? " linking" : "",
	    tp.no_names ? " no-names" : "", tp.no_rates ? " no-rates" : "",
	    tp.stencil ? " stencil" : "");
	return (cls);
}

/*
 * The OSPF map: the routers and transit networks of every OSPF area the
 * fleet's BIRDs are in, as their link-state databases tell them.  Every
 * router of an area holds the same database, so a host is asked for its
 * topology only when what is known already lacks it: its router ID, or
 * one of its neighbours, in each of its protocol's areas (a second OSPF
 * domain with the same area number is asked for on its own).  First each
 * host with OSPF is asked which protocols and areas it has, which is
 * cheap; then one host at a time for a topology, until none is missing.
 */
#define	OM_NODES	256
#define	OM_EDGES	1024
#define	OM_ASKED	64
#define	OM_AREAS	12

struct omnode {
	char	id[96];		/* a router ID, or area/network */
	char	label[80];
	bool	net;
	int	node;		/* the fleet's node with this router ID, or -1 */
	int	area;
	int	stubs, exts;
	double	x, y;
};

struct omedge {
	int	a, b, area;
	long	m;		/* a's metric towards b, or -1 */
	long	mb;		/* b's towards a, or -1 */
};

static struct {
	bool		on, built;
	int		wait;
	ucl_object_t	*sum[MAX_NODES];
	struct {
		int		 node;
		char		 proto[64];
		ucl_object_t	*topo;
	}		asked[OM_ASKED];
	int		nasked;
	struct omnode	n[OM_NODES];
	int		nn;
	struct omedge	e[OM_EDGES];
	int		ne;
	char		areas[OM_AREAS][24];
	int		nareas;
	char		note[200];
	int		failed;		/* hosts that could not say */
	char		fail_why[120];
} om;

static void	om_plan(void);
static void	om_fit(void);

/* A node's BIRD's router ID, from its status: true when there is one. */
static bool
node_rid(int i, char *buf, size_t len)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	struct thost		*t;
	const char		*s;

	if ((t = thost(tn[i].key, false)) == NULL || t->bird == NULL)
		return (false);
	it = NULL;
	while ((o = ucl_object_iterate(jget(t->bird, "status"), &it, true)) !=
	    NULL)
		if ((s = ucl_object_tostring(o)) != NULL &&
		    strncmp(s, "Router ID is ", 13) == 0) {
			snprintf(buf, len, "%s", s + 13);
			return (true);
		}
	return (false);
}

static void
om_reset(void)
{
	int	i;

	for (i = 0; i < MAX_NODES; i++)
		if (om.sum[i] != NULL)
			ucl_object_unref(om.sum[i]);
	for (i = 0; i < om.nasked; i++)
		if (om.asked[i].topo != NULL)
			ucl_object_unref(om.asked[i].topo);
	memset(&om, 0, sizeof(om));
}

static void
om_sum_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*key = arg;
	int	 i;

	(void)err;
	om.wait--;
	if ((i = node_index(key)) != -1 && status == 200 && jbool(o, "ok") &&
	    jget(o, "data") != NULL && om.on)
		om.sum[i] = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o,
		    "data"));
	else if (om.on) {
		om.failed++;
		snprintf(om.fail_why, sizeof(om.fail_why), "%s", err != NULL ?
		    err : jstr(o, "error") != NULL ? jstr(o, "error") : "no answer");
	}
	free(key);
	if (om.on)
		om_plan();
}

static void
om_topo_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	intptr_t	k = (intptr_t)arg;
	const ucl_object_t *p;

	om.wait--;
	if (om.on && k >= 0 && k < om.nasked && status == 200 && jbool(o,
	    "ok") && (p = ucl_array_find_index(jget(o, "data.protocols"),
	    0)) != NULL && jget(p, "topology") != NULL)
		om.asked[k].topo = ucl_object_ref((ucl_object_t *)(uintptr_t)
		    jget(p, "topology"));
	else if (om.on && err != NULL)
		snprintf(om.note, sizeof(om.note), "%s", err);
	if (om.on)
		om_plan();
}

/* Does an area of a topology known already hold the router id? */
static bool
om_holds(const char *area, const char *id)
{
	const ucl_object_t	*a, *r;
	ucl_object_iter_t	 it, rit;
	int			 k;

	for (k = 0; k < om.nasked; k++) {
		it = NULL;
		while ((a = ucl_object_iterate(om.asked[k].topo, &it, true)) !=
		    NULL) {
			if (jstr(a, "area") == NULL || (area != NULL &&
			    strcmp(jstr(a, "area"), area) != 0))
				continue;
			rit = NULL;
			while ((r = ucl_object_iterate(jget(a, "routers"), &rit,
			    true)) != NULL)
				if (jstr(r, "id") != NULL && strcmp(jstr(r, "id"),
				    id) == 0)
					return (true);
		}
	}
	return (false);
}

/*
 * Is node i's protocol p known: its router in each of p's areas, and
 * each of p's neighbours somewhere, in what was told already?
 */
static bool
om_covered(int i, const ucl_object_t *p)
{
	const ucl_object_t	*a, *nb;
	ucl_object_iter_t	 it;
	struct thost		*t;
	char			 rid[64];

	if (!node_rid(i, rid, sizeof(rid)))
		return (false);
	it = NULL;
	while ((a = ucl_object_iterate(jget(p, "areas"), &it, true)) != NULL)
		if (!om_holds(ucl_object_tostring(a), rid))
			return (false);
	t = thost(tn[i].key, false);
	it = NULL;
	while (t != NULL && (nb = ucl_object_iterate(jget(t->bird, "ospf"),
	    &it, true)) != NULL)
		if (jstr(nb, "proto") != NULL && jstr(p, "name") != NULL &&
		    strcmp(jstr(nb, "proto"), jstr(p, "name")) == 0 &&
		    jstr(nb, "router-id") != NULL && !om_holds(NULL, jstr(nb,
		    "router-id")))
			return (false);
	return (true);
}

static int
om_area(const char *id)
{
	int	k;

	for (k = 0; k < om.nareas; k++)
		if (strcmp(om.areas[k], id) == 0)
			return (k);
	if (om.nareas == OM_AREAS)
		return (OM_AREAS - 1);
	snprintf(om.areas[om.nareas], sizeof(om.areas[0]), "%s", id);
	return (om.nareas++);
}

static int
om_node(const char *id, bool net, int area)
{
	int	k;

	for (k = 0; k < om.nn; k++)
		if (om.n[k].net == net && strcmp(om.n[k].id, id) == 0)
			return (k);
	if (om.nn == OM_NODES)
		return (-1);
	memset(&om.n[om.nn], 0, sizeof(om.n[0]));
	snprintf(om.n[om.nn].id, sizeof(om.n[0].id), "%s", id);
	snprintf(om.n[om.nn].label, sizeof(om.n[0].label), "%s", net ?
	    strchr(id, '/') + 1 : id);
	om.n[om.nn].net = net;
	om.n[om.nn].node = -1;
	om.n[om.nn].area = area;
	return (om.nn++);
}

static void
om_edge(int a, int b, int area, long m)
{
	int	k;

	if (a < 0 || b < 0 || a == b)
		return;
	for (k = 0; k < om.ne; k++) {
		if (om.e[k].area != area)
			continue;
		if (om.e[k].a == a && om.e[k].b == b) {
			if (m >= 0)
				om.e[k].m = m;
			return;
		}
		if (om.e[k].a == b && om.e[k].b == a) {
			if (m >= 0)
				om.e[k].mb = m;
			return;
		}
	}
	if (om.ne == OM_EDGES)
		return;
	om.e[om.ne].a = a;
	om.e[om.ne].b = b;
	om.e[om.ne].area = area;
	om.e[om.ne].m = m;
	om.e[om.ne].mb = -1;
	om.ne++;
}

/* The graph, from every topology told: routers once, however many areas. */
static void
om_build(void)
{
	const ucl_object_t	*a, *r, *l, *nw, *x;
	ucl_object_iter_t	 it, rit, lit;
	char			 key[96], rid[64];
	const char		*kind;
	int			 k, i, ai, ri, ni;

	om.nn = om.ne = 0;
	for (k = 0; k < om.nasked; k++) {
		it = NULL;
		while ((a = ucl_object_iterate(om.asked[k].topo, &it, true)) !=
		    NULL) {
			if (jstr(a, "area") == NULL)
				continue;
			ai = om_area(jstr(a, "area"));
			rit = NULL;
			while ((r = ucl_object_iterate(jget(a, "routers"), &rit,
			    true)) != NULL) {
				if (jstr(r, "id") == NULL || (ri = om_node(jstr(r,
				    "id"), false, ai)) == -1)
					continue;
				lit = NULL;
				while ((l = ucl_object_iterate(jget(r, "links"),
				    &lit, true)) != NULL) {
					if ((kind = jstr(l, "kind")) == NULL ||
					    jstr(l, "to") == NULL)
						continue;
					if (strcmp(kind, "router") == 0)
						om_edge(ri, om_node(jstr(l, "to"),
						    false, ai), ai, jint(l, "metric",
						    -1));
					else if (strcmp(kind, "network") == 0) {
						snprintf(key, sizeof(key), "%s/%s",
						    jstr(a, "area"), jstr(l, "to"));
						om_edge(ri, om_node(key, true, ai),
						    ai, jint(l, "metric", -1));
					} else if (strcmp(kind, "stubnet") == 0)
						om.n[ri].stubs++;
					else if (strcmp(kind, "external") == 0)
						om.n[ri].exts++;
				}
			}
			rit = NULL;
			while ((nw = ucl_object_iterate(jget(a, "networks"), &rit,
			    true)) != NULL) {
				if (jstr(nw, "id") == NULL)
					continue;
				snprintf(key, sizeof(key), "%s/%s", jstr(a, "area"),
				    jstr(nw, "id"));
				if ((ni = om_node(key, true, ai)) == -1)
					continue;
				lit = NULL;
				while ((x = ucl_object_iterate(jget(nw, "routers"),
				    &lit, true)) != NULL)
					om_edge(om_node(ucl_object_tostring(x),
					    false, ai), ni, ai, -1);
			}
		}
	}
	/* The fleet's own: named as the map names them. */
	for (i = 0; i < ntn; i++)
		if (node_rid(i, rid, sizeof(rid)))
			for (k = 0; k < om.nn; k++)
				if (!om.n[k].net && om.n[k].node == -1 &&
				    strcmp(om.n[k].id, rid) == 0) {
					om.n[k].node = i;
					snprintf(om.n[k].label, sizeof(om.n[k].label),
					    "%s", tn[i].name);
				}
	/* Laid out by springs on the links and a push between all. */
	{
		double	 t, d, dx, dy, f, r0, kk;
		static double vx[OM_NODES], vy[OM_NODES];
		int	 it2, p, q;

		r0 = 80 + 40 * sqrt((double)om.nn);
		for (p = 0; p < om.nn; p++) {
			om.n[p].x = r0 * cos(2 * M_PI * p / (om.nn > 0 ? om.nn :
			    1));
			om.n[p].y = r0 * sin(2 * M_PI * p / (om.nn > 0 ? om.nn :
			    1)) * 0.75;
		}
		kk = 150;
		for (it2 = 0, t = 60; it2 < 300; it2++, t *= 0.985) {
			for (p = 0; p < om.nn; p++)
				vx[p] = vy[p] = 0;
			for (p = 0; p < om.nn; p++)
				for (q = p + 1; q < om.nn; q++) {
					dx = om.n[p].x - om.n[q].x;
					dy = om.n[p].y - om.n[q].y;
					d = sqrt(dx * dx + dy * dy) + 0.01;
					f = kk * kk / d;
					vx[p] += dx / d * f;
					vy[p] += dy / d * f;
					vx[q] -= dx / d * f;
					vy[q] -= dy / d * f;
				}
			for (k = 0; k < om.ne; k++) {
				p = om.e[k].a;
				q = om.e[k].b;
				dx = om.n[p].x - om.n[q].x;
				dy = om.n[p].y - om.n[q].y;
				d = sqrt(dx * dx + dy * dy) + 0.01;
				f = d * d / kk;
				vx[p] -= dx / d * f;
				vy[p] -= dy / d * f;
				vx[q] += dx / d * f;
				vy[q] += dy / d * f;
			}
			for (p = 0; p < om.nn; p++) {
				d = sqrt(vx[p] * vx[p] + vy[p] * vy[p]) + 0.01;
				om.n[p].x += vx[p] / d * (d < t ? d : t);
				om.n[p].y += vy[p] / d * (d < t ? d : t);
			}
		}
	}
	om.built = true;
	{
		int	rn = 0, nn = 0;

		for (k = 0; k < om.nn; k++)
			om.n[k].net ? nn++ : rn++;
		snprintf(om.note, sizeof(om.note), "%d routers, %d transit "
		    "network%s in %d area%s, read from %d link-state "
		    "database%s", rn, nn, nn == 1 ? "" : "s", om.nareas,
		    om.nareas == 1 ? "" : "s", om.nasked, om.nasked == 1 ? "" :
		    "s");
		if (om.failed > 0)
			snprintf(om.note + strlen(om.note), sizeof(om.note) -
			    strlen(om.note), "; %d host%s could not say (an agent "
			    "before 0.201.0?): %s", om.failed, om.failed == 1 ? "" :
			    "s", om.fail_why);
	}
	om_fit();
}

/*
 * The next host to ask for a topology: one whose OSPF the topologies
 * known so far lack, one at a time, so that what one tells spares the
 * others; none left, the graph.
 */
static void
om_plan(void)
{
	const ucl_object_t	*p;
	ucl_object_iter_t	 it;
	char			 more[120], url[240];
	int			 i, k;

	if (om.wait > 0)
		return;
	for (i = 0; i < ntn; i++) {
		if (om.sum[i] == NULL)
			continue;
		it = NULL;
		while ((p = ucl_object_iterate(jget(om.sum[i], "protocols"), &it,
		    true)) != NULL) {
			if (jstr(p, "name") == NULL)
				continue;
			for (k = 0; k < om.nasked; k++)
				if (om.asked[k].node == i && strcmp(
				    om.asked[k].proto, jstr(p, "name")) == 0)
					break;
			if (k < om.nasked || om_covered(i, p))
				continue;
			if (om.nasked == OM_ASKED)
				break;
			om.asked[om.nasked].node = i;
			snprintf(om.asked[om.nasked].proto,
			    sizeof(om.asked[0].proto), "%s", jstr(p, "name"));
			snprintf(more, sizeof(more), "filter=topology,%s",
			    jstr(p, "name"));
			node_url(i, "bird-ospf", more, url, sizeof(url));
			om.wait++;
			api("GET", url, NULL, om_topo_cb, (void *)(intptr_t)
			    om.nasked++);
			snprintf(om.note, sizeof(om.note), "Asking %s for its "
			    "link-state database (%s)…", tn[i].name, jstr(p,
			    "name"));
			return;
		}
	}
	om_build();
}

/* The map's OSPF map, asked for: each host with OSPF told of first. */
static void
om_start(void)
{
	const ucl_object_t	*p;
	ucl_object_iter_t	 it;
	struct thost		*t;
	char			 url[240];
	int			 i;

	om_reset();
	om.on = true;
	for (i = 0; i < ntn; i++) {
		if ((t = thost(tn[i].key, false)) == NULL || t->bird == NULL)
			continue;
		it = NULL;
		while ((p = ucl_object_iterate(jget(t->bird, "protocols"), &it,
		    true)) != NULL)
			if (jstr(p, "proto") != NULL && strcmp(jstr(p, "proto"),
			    "OSPF") == 0)
				break;
		if (p == NULL)
			continue;
		node_url(i, "bird-ospf", "", url, sizeof(url));
		om.wait++;
		api("GET", url, NULL, om_sum_cb, strdup(tn[i].key));
	}
	snprintf(om.note, sizeof(om.note), om.wait > 0 ? "Asking each host "
	    "with OSPF for its areas…" : "No host's BIRD runs OSPF.");
}

static void
om_fit(void)
{
	double	x0, y0, x1, y1, zx, zy;
	int	k;

	if (om.nn == 0)
		return;
	x0 = x1 = om.n[0].x;
	y0 = y1 = om.n[0].y;
	for (k = 1; k < om.nn; k++) {
		x0 = om.n[k].x < x0 ? om.n[k].x : x0;
		x1 = om.n[k].x > x1 ? om.n[k].x : x1;
		y0 = om.n[k].y < y0 ? om.n[k].y : y0;
		y1 = om.n[k].y > y1 ? om.n[k].y : y1;
	}
	zx = VIEW_W / (x1 - x0 + 200);
	zy = (VIEW_H - LEGEND_H - TOOLS_H) / (y1 - y0 + 160);
	tp.zoom = zx < zy ? zx : zy;
	if (tp.zoom > 1.7)
		tp.zoom = 1.7;
	if (tp.zoom < 0.15)
		tp.zoom = 0.15;
	tp.panx = (x0 + x1) / 2;
	tp.pany = (y0 + y1) / 2 + (LEGEND_H - TOOLS_H) / 2 / tp.zoom;
}

/* The OSPF map drawn: links by area with their metrics, then the nodes. */
static void
om_draw(struct html *h)
{
	struct omnode	*n;
	struct omedge	*e;
	int		 k;

	for (k = 0; k < om.ne; k++) {
		e = &om.e[k];
		h_fmt(h, "<g class=\"omedge a%d\"><path d=\"M%.1f %.1f L%.1f "
		    "%.1f\"/>", e->area % 6, om.n[e->a].x, om.n[e->a].y,
		    om.n[e->b].x, om.n[e->b].y);
		if (e->m >= 0 || e->mb >= 0) {
			h_fmt(h, "<text x=\"%.1f\" y=\"%.1f\">", (om.n[e->a].x +
			    om.n[e->b].x) / 2, (om.n[e->a].y + om.n[e->b].y) / 2 -
			    3);
			if (e->m >= 0 && e->mb >= 0 && e->m != e->mb)
				h_fmt(h, "%ld / %ld", e->m, e->mb);
			else
				h_fmt(h, "%ld", e->m >= 0 ? e->m : e->mb);
			h_raw(h, "</text>");
		}
		h_raw(h, "<title>");
		h_txt(h, om.n[e->a].label);
		h_raw(h, " ⇄ ");
		h_txt(h, om.n[e->b].label);
		h_fmt(h, " · area %s</title></g>", om.areas[e->area]);
	}
	for (k = 0; k < om.nn; k++) {
		n = &om.n[k];
		if (n->net) {
			h_fmt(h, "<g class=\"omnet\" transform=\"translate(%.1f,"
			    "%.1f)\"><rect x=\"-26\" y=\"-8\" width=\"52\" height=\""
			    "16\" rx=\"3\"/><circle cx=\"-14\" r=\"2\"/><circle "
			    "r=\"2\"/><circle cx=\"14\" r=\"2\"/><text y=\"24\">",
			    n->x, n->y);
			h_fit(h, n->label, 24);
			h_raw(h, "</text><title>A transit network: ");
			h_txt(h, n->label);
			h_raw(h, "</title></g>");
			continue;
		}
		h_fmt(h, "<g class=\"omr%s\" transform=\"translate(%.1f,%.1f)\">"
		    "<circle class=\"glyph\" r=\"20\"/><path class=\"arrows\" "
		    "d=\"M-13 -5h22M3 -10l6 5-6 5M13 5h-22M-3 10l-6-5 6-5\"/>"
		    "<text class=\"name\" y=\"34\">", n->node != -1 ? " fleet" :
		    "", n->x, n->y);
		h_fit(h, n->label, 22);
		h_raw(h, "</text>");
		if (n->node != -1) {
			h_raw(h, "<text class=\"sub\" y=\"46\">");
			h_txt(h, n->id);
			h_raw(h, "</text>");
		}
		h_raw(h, "<title>");
		h_txt(h, n->label);
		h_fmt(h, " · router ID %s", n->id);
		if (n->stubs > 0 || n->exts > 0)
			h_fmt(h, " · %d stub network%s, %d external route%s",
			    n->stubs, n->stubs == 1 ? "" : "s", n->exts,
			    n->exts == 1 ? "" : "s");
		h_raw(h, n->node != -1 ? " · a host of this console" :
		    " · a router outside this console");
		h_raw(h, "</title></g>");
	}
	if (!om.built) {
		h_fmt(h, "<text class=\"omnote\" x=\"%.1f\" y=\"%.1f\">", tp.panx,
		    tp.pany);
		h_txt(h, om.note);
		h_raw(h, "</text>");
	}
}

/* The OSPF map's legend: the areas by colour, the kinds of node, the count. */
static void
om_legend(struct html *h)
{
	int	k;

	h_raw(h, "<ul class=\"map-legend om\">");
	for (k = 0; k < om.nareas; k++)
		h_fmt(h, "<li class=\"key oma%d\">area %s</li>", k % 6,
		    om.areas[k]);
	h_raw(h, "<li class=\"key omfleet\">a host of this console</li>"
	    "<li class=\"key omout\">a router outside</li>"
	    "<li class=\"key omnetk\">transit network</li><li class=\"key "
	    "note\">");
	h_txt(h, om.note);
	h_raw(h, "</li></ul>");
}

/*
 * A host with a safe change waiting to be confirmed: a fuse round its box
 * (the WebGL layer's), and under it what happens when it burns out.  The
 * console confirms a change by reaching the host after it, so one stays
 * waiting when the change cut the console off.
 */
static void
map_safe(struct html *h)
{
	const struct op	*o;
	struct thost	*t;
	long long	 left;
	int		 i, k;

	for (i = 0; i < ntn; i++) {
		if (tn[i].jail[0] != '\0' || node_lone(i) || (t = thost(tn[i].key,
		    false)) == NULL || !t->placed)
			continue;
		for (k = 0; k < app.nops; k++) {
			o = &app.ops[k];
			if (o->state != OP_RUNNING || o->confirm_by <= 0 ||
			    strcmp(o->sid, app.servers[tn[i].srv].id) != 0)
				continue;
			left = o->confirm_by - (long long)(arc_now() / 1000);
			if (left <= 0)
				continue;
			glmap_fuse(t->x, t->y, NODE_W, NODE_H, o->confirm_by,
			    (double)o->confirm_by - o->started / 1000.0);
			h_fmt(h, "<text class=\"tsafe%s\" x=\"%.1f\" y=\"%.1f\">"
			    "undone in %llds unless confirmed<title>", left <= 10 ?
			    " soon" : "", t->x, t->y + NODE_H / 2 + 22, left);
			h_txt(h, o->title);
			h_raw(h, ": in safe mode; the agent puts it back when the "
			    "console has not reached the host since</title></text>");
			break;
		}
	}
}

static void
map(struct html *h)
{
	struct thost	*t;
	double		 w, ht;

	w = VIEW_W / tp.zoom;
	ht = VIEW_H / tp.zoom;
	/* The traffic's layer under the drawing, in the same view. */
	glmap_begin(tp.panx - w / 2, tp.pany - ht / 2, w, ht);
	h_raw(h, "<div class=\"map-wrap\">");
	glmap_html(h);
	h_fmt(h, "<svg class=\"topo%s\" viewBox=\""
	    "%.1f %.1f %.1f %.1f\" data-wheel=\"topo-zoom\">"
	    "<defs><marker id=\"arrow\" viewBox=\"0 0 10 10\" refX=\"9\" "
	    "refY=\"5\" markerWidth=\"5\" markerHeight=\"5\" orient=\""
	    "auto-start-reverse\"><path class=\"head\" d=\"M0 0L10 5L0 10z\"/>"
	    "</marker><marker id=\"arrow-alt\" viewBox=\"0 0 10 10\" refX=\"9\" "
	    "refY=\"5\" markerWidth=\"5\" markerHeight=\"5\" orient=\""
	    "auto-start-reverse\"><path class=\"head alt\" d=\"M0 0L10 5L0 10z"
	    "\"/></marker><pattern id=\"dots\" width=\"40\" height=\"40\" "
	    "patternUnits=\"userSpaceOnUse\"><circle cx=\"1\" cy=\"1\" r=\"1\"/>"
	    "</pattern></defs>"
	    "<rect class=\"bg\" x=\"%.1f\" y=\"%.1f\" width=\"%.1f\" height=\""
	    "%.1f\" fill=\"url(#dots)\" data-drag=\"topo-pan\" data-arg=\"\"/>",
	    wfmt_cls(), tp.panx - w / 2, tp.pany - ht / 2, w,
	    ht, tp.panx - w * 2, tp.pany - ht * 2, w * 4, ht * 4);
	if (om.on)
		om_draw(h);
	else {
		map_links(h);
		glmap_end();
		map_path(h);
		if (tp.linking && (t = thost(tp.link_from, false)) != NULL) {
			int	k;

			h_fmt(h, "<path class=\"tdraft\" d=\"M%.1f %.1f L%.1f "
			    "%.1f\"/>", t->x + NODE_W / 2, t->y, tp.link_x, tp.link_y);
			/* And in the WebGL layer: the line alive, and every
			 * host it can be dropped on lit. */
			glmap_draft(t->x + NODE_W / 2, t->y, tp.link_x,
			    tp.link_y);
			for (k = 0; k < ntn; k++) {
				struct thost	*o;

				if (node_lone(k) || strcmp(tn[k].key,
				    tp.link_from) == 0 || (o = thost(tn[k].key,
				    false)) == NULL || !o->placed || o->ifs == NULL)
					continue;
				glmap_target(o->x, o->y, NODE_W, NODE_H);
			}
		}
		map_nodes(h);
		map_safe(h);
		if (tlab.len > 0) {
			h_raw(h, "<g class=\"tlabels\">");
			h_raw(h, tlab.s);
			h_raw(h, "</g>");
		}
	}
	h_raw(h, "</svg><div class=\"map-tools\">"
	    "<button class=\"ghost small\" data-act=\"topo-zoom-in\" "
	    "title=\"Closer\">+</button>"
	    "<button class=\"ghost small\" data-act=\"topo-zoom-out\" "
	    "title=\"Further\">−</button>"
	    "<button class=\"ghost small\" data-act=\"topo-fit\" "
	    "title=\"Show every host\">Fit</button>"
	    "<button class=\"ghost small\" data-act=\"topo-arrange\" "
	    "title=\"Put the hosts back on a circle\">Arrange</button>");
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"topo-jails\" "
	    "title=\"Each host's running jails\">Jails</button>", tp.jails ?
	    " on" : "");
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"topo-vnet\" "
	    "title=\"The vnet jails as nodes of their own: those linked to more "
	    "than their own host, all of them, or none; pressed, the next\">VNet "
	    "jails: %s</button>", tp.novnet ? "" : " on", tp.novnet ? "none" :
	    tp.lonevnet ? "all" : "linked");
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"topo-labels\" "
	    "title=\"What each kind of line is and carries, written on it\">"
	    "Labels ▾</button>", tp.labels_open ? " on" : "");
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"topo-peers\" "
	    "title=\"BGP and OSPF neighbours that are not hosts of this "
	    "console\">Peers</button>", tp.nopeers ? "" : " on");
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"topo-stencil\" "
	    "title=\"Drawn as a network diagram: routers, switches, clouds and "
	    "straight lines, as an engineer draws one\">Diagram</button>",
	    tp.stencil ? " on" : "");
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"topo-ospfmap\" "
	    "title=\"Every OSPF area the hosts are in, its routers and transit "
	    "networks, from one host's link-state database per area\">OSPF "
	    "map%s</button>", om.on ? " on" : "", om.on && !om.built ? "…" : "");
	h_raw(h, "<button class=\"ghost small\" data-act=\"topo-png\" title=\"The "
	    "map as it is shown, saved as a PNG picture\">PNG</button>");
	{
		int	f, n[8], more;

		fibs_present(n);
		for (f = 1, more = 0; f < 8; f++)
			more += n[f] > 0;
		if (more > 0) {
			h_fmt(h, "<label class=\"fibsel\" title=\"Only the links in one "
			    "routing table: by an interface in it, or a tunnel whose "
			    "outer packets go by it\">FIB<select data-input=\"topo-fib\">"
			    "<option value=\"-1\"%s>all</option>", tp.fib < 0 ?
			    " selected" : "");
			for (f = 0; f < 8; f++)
				if (n[f] > 0)
					h_fmt(h, "<option value=\"%d\"%s>%d%s</option>", f,
					    tp.fib == f ? " selected" : "", f, f == 0 ?
					    " (default)" : "");
			h_raw(h, "</select></label>");
		}
	}
	h_raw(h, "</div>");
	/* The labels' switches: each kind of line's written or not. */
	if (tp.labels_open) {
		static const struct {
			const char	*cls, *title;
		} lk[LK_KINDS] = {
			{ "tunnel", "Tunnels" }, { "p2p", "Point to point" },
			{ "lan", "Same network" }, { "bgp", "BGP" },
			{ "ospf", "OSPF" }, { "vnet", "Jails" },
		};
		int	k;

		h_raw(h, "<div class=\"map-labels\" role=\"group\" "
		    "aria-label=\"Labels\">");
		/* What is written: the ends' names, the rates, apart. */
		h_fmt(h, "<button type=\"button\" class=\"ghost small what%s\" "
		    "data-act=\"topo-labels-what\" data-arg=\"names\" "
		    "aria-pressed=\"%s\" title=\"The interfaces at each end, "
		    "and the networks' names\">Names</button>", tp.no_names ? "" :
		    " on", tp.no_names ? "false" : "true");
		h_fmt(h, "<button type=\"button\" class=\"ghost small what%s\" "
		    "data-act=\"topo-labels-what\" data-arg=\"rates\" "
		    "aria-pressed=\"%s\" title=\"What each line carries, both "
		    "ways\">Rates</button><span class=\"sep\"></span>",
		    tp.no_rates ? "" : " on", tp.no_rates ? "false" : "true");
		for (k = 0; k < LK_KINDS; k++) {
			bool	on;

			on = !labels_quiet(k);
			h_fmt(h, "<button type=\"button\" class=\"ghost small "
			    "%s%s\" data-act=\"topo-labels-kind\" data-arg=\"%s\" "
			    "aria-pressed=\"%s\" title=\"%s these lines' labels"
			    "%s\">%s</button>", lk[k].cls, on ? " on" : "",
			    lk[k].cls, on ? "true" : "false", on ? "Leave out" :
			    "Write", tp.labels[k] == 0 ? " (as fits, now)" : "",
			    lk[k].title);
		}
		h_raw(h, "</div>");
	}
	if (om.on) {
		om_legend(h);
		h_raw(h, "</div>");
		return;
	}
	/* The legend says what a line is, and takes its kind away or back. */
	h_raw(h, "<ul class=\"map-legend\">");
	{
		static const struct {
			const char	*cls, *title;
			int		 kind;
		} lg[] = {
			{ "tunnel", "tunnel", LK_TUNNEL },
			{ "p2p", "point to point", LK_P2P },
			{ "lan", "same network", LK_LAN },
			{ "bgp", "BGP", LK_BGP }, { "ospf", "OSPF", LK_OSPF },
			{ "vnet", "jail", LK_VNET },
			{ "best", "route", -1 }, { "alt", "instead", -2 },
		};
		size_t	k;
		bool	off;

		for (k = 0; k < sizeof(lg) / sizeof(lg[0]); k++) {
			off = lg[k].kind >= 0 ? tp.hide[lg[k].kind] :
			    lg[k].kind == -1 ? tp.hide_best : tp.hide_alt;
			h_fmt(h, "<li class=\"%s%s\" data-act=\"topo-legend\" "
			    "data-arg=\"%s\" title=\"%s these in the map\">%s"
			    "</li>", lg[k].cls, off ? " off" : "", lg[k].cls,
			    off ? "Show" : "Hide", lg[k].title);
		}
	}
	/* The routing tables' colours, when there is more than the first:
	 * a key, not a switch (the toolbar's FIB picks one). */
	{
		int	f, n[8], more;

		fibs_present(n);
		for (f = 1, more = 0; f < 8; f++)
			more += n[f] > 0;
		if (more > 0)
			h_raw(h, "<li class=\"key outer\" title=\"A tunnel whose outer "
			    "packets go by another table than its own: ticks across it, in "
			    "the colour its ends' labels give that table\">outer table</li>");
	}
	h_raw(h, "</ul></div>");
}

/* The addresses of a host a tunnel could end at or a route lead to. */
static const char *
primary_addr(struct thost *t, int want)
{
	const ucl_object_t	*o, *a;
	ucl_object_iter_t	 it, ait;
	const char		*found;
	unsigned char		 raw[16];
	int			 af;

	found = NULL;
	it = NULL;
	while (t != NULL && (o = ucl_object_iterate(jget(t->ifs, "interfaces"),
	    &it, true)) != NULL) {
		if (!if_joins(o))
			continue;
		ait = NULL;
		while ((a = ucl_object_iterate(jget(o, "addresses"), &ait,
		    true)) != NULL) {
			if (jstr(a, "address") == NULL || addr_local(jstr(a,
			    "address")) || !addr_bytes(jstr(a, "address"), &af,
			    raw))
				continue;
			if (af == want)
				return (jstr(a, "address"));
			if (found == NULL)
				found = jstr(a, "address");
		}
	}
	return (want == 0 ? found : NULL);
}

static void
panel_path(struct html *h)
{
	struct hop	*p;
	int		 i, k;

	h_raw(h, "<section class=\"pane path\"><h4>Look up the route</h4>"
	    "<div class=\"path-form\"><label>From<select data-input=\""
	    "topo-from\">");
	for (i = 0; i < ntn; i++) {
		h_raw(h, "<option");
		h_attr(h, "value", tn[i].key);
		if (strcmp(path.from, tn[i].key) == 0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, tn[i].label);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label><label>To<select data-input=\"topo-to\">"
	    "<option value=\"\">an address…</option>");
	for (i = 0; i < ntn; i++) {
		h_raw(h, "<option");
		h_attr(h, "value", tn[i].key);
		if (strcmp(path.to_name, tn[i].key) == 0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, tn[i].label);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label><label>Address<input data-input=\""
	    "topo-addr\" id=\"topo-addr\" spellcheck=\"false\" autocomplete="
	    "\"off\" placeholder=\"192.0.2.10\"");
	h_attr(h, "value", path.to);
	h_fmt(h, "></label><button class=\"primary small\" data-act=\""
	    "topo-trace\" title=\"Which way each host would send it, as its "
	    "routing table says\"%s>Look up</button>", path.busy ?
	    " disabled" : "");
	if (path.n > 0 || path.error[0] != '\0')
		h_raw(h, "<button class=\"ghost small\" data-act=\""
		    "topo-path-clear\">Clear</button>");
	h_raw(h, "</div>");
	if (path.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, path.error);
		h_raw(h, "</div>");
	}
	if (path.n > 0) {
		h_raw(h, "<ol class=\"hops\">");
		for (i = 0; i < path.n; i++) {
			p = &path.hops[i];
			h_raw(h, "<li><b>");
			h_txt(h, p->from >= 0 && p->from < ntn ?
			    tn[p->from].label : "?");
			h_raw(h, "</b>");
			if (p->ifn[0] != '\0') {
				h_raw(h, " <span class=\"dim\">out</span> ");
				h_txt(h, p->ifn);
				if (p->gw[0] != '\0') {
					h_raw(h, " <span class=\"dim\">via"
					    "</span> ");
					h_txt(h, p->gw);
				}
				h_raw(h, "<small>route ");
				h_txt(h, p->dest);
				h_raw(h, " ");
				h_txt(h, p->flags);
				h_raw(h, "</small>");
			}
			if (p->note[0] != '\0') {
				h_raw(h, "<small class=\"note\">");
				h_txt(h, p->note);
				h_raw(h, "</small>");
			}
			for (k = 0; k < p->nalt; k++) {
				h_raw(h, "<small class=\"alt\">instead: ");
				h_txt(h, p->alt[k].dest);
				h_raw(h, " via ");
				h_txt(h, p->alt[k].gw);
				h_raw(h, " (");
				h_txt(h, p->alt[k].ifn);
				if (p->alt[k].to >= 0) {
					h_raw(h, ", to ");
					h_txt(h, tn[p->alt[k].to].label);
				}
				h_raw(h, ")</small>");
			}
			h_raw(h, "</li>");
		}
		h_raw(h, "</ol>");
		if (path.busy)
			h_raw(h, "<p class=\"dim\">Asking the next host…</p>");
	}
	h_raw(h, "</section>");
}

static void
panel_host(struct html *h, int node, struct thost *t)
{
	const ucl_object_t	*o, *a;
	ucl_object_iter_t	 it, ait;
	struct ifrate		*r;
	const char		*name;
	char			 in[24], out[24];
	int			 fib, tfib;

	h_raw(h, "<section class=\"pane\"><h4>");
	h_txt(h, tn[node].label);
	h_raw(h, "<button class=\"icon\" data-act=\"topo-unselect\" "
	    "title=\"Close\">×</button></h4><div class=\"pane-actions\">"
	    "<button class=\"ghost small\" data-act=\"topo-if-create\"");
	h_attr(h, "data-arg", tn[node].key);
	h_raw(h, ">+ interface</button><button class=\"ghost small\" "
	    "data-act=\"topo-open-host\"");
	h_attr(h, "data-arg", tn[node].key);
	h_raw(h, ">Its network</button><button class=\"ghost small\" "
	    "data-act=\"topo-from-here\"");
	h_attr(h, "data-arg", tn[node].key);
	h_raw(h, ">Route from here</button></div>");
	if (t == NULL || t->ifs == NULL) {
		h_raw(h, "<p class=\"dim\">Its interfaces have not been read "
		    "yet.</p></section>");
		return;
	}
	h_raw(h, "<ul class=\"iflist\">");
	it = NULL;
	while ((o = ucl_object_iterate(jget(t->ifs, "interfaces"), &it,
	    true)) != NULL) {
		if ((name = jstr(o, "name")) == NULL)
			continue;
		r = rate_of(t, name, false);
		if_tables(o, &fib, &tfib);
		h_fmt(h, "<li class=\"%s%s%s\" data-act=\"topo-sel-if\"", jbool(o,
		    "up") ? "up" : "down", strcmp(tp.sel_if, name) == 0 ?
		    " sel" : "", tp.fib >= 0 && fib != tp.fib && tfib != tp.fib ?
		    " dim" : "");
		h_attr(h, "data-arg", name);
		h_raw(h, "><div class=\"ifhead\"><i class=\"led\"></i><b>");
		h_txt(h, name);
		h_raw(h, "</b>");
		if (fib > 0)
			h_fmt(h, "<span class=\"chip fib%d\" title=\"Its routing table\">"
			    "FIB %d</span>", fib > 6 ? 6 : fib, fib);
		if (tfib >= 0 && tfib != fib)
			h_fmt(h, "<span class=\"chip fib%d\" title=\"The table its outer "
			    "packets go by (tunnelfib)\">outer FIB %d</span>", tfib > 6 ? 6 :
			    tfib, tfib);
		if (jstr(o, "description") != NULL) {
			h_raw(h, "<span class=\"dim\">");
			h_txt(h, jstr(o, "description"));
			h_raw(h, "</span>");
		}
		if (r != NULL && r->n > 0) {
			fmt_rate(in, sizeof(in), r->in[r->n - 1]);
			fmt_rate(out, sizeof(out), r->out[r->n - 1]);
			h_raw(h, "<span class=\"io\">↓ ");
			h_txt(h, in);
			h_raw(h, " ↑ ");
			h_txt(h, out);
			h_raw(h, "</span>");
		}
		h_raw(h, "</div>");
		if (jstr(o, "tunnel.remote") != NULL) {
			h_raw(h, "<small>tunnel ");
			h_txt(h, jstr(o, "tunnel.local"));
			h_raw(h, " → ");
			h_txt(h, jstr(o, "tunnel.remote"));
			h_raw(h, "</small>");
		}
		ait = NULL;
		while ((a = ucl_object_iterate(jget(o, "addresses"), &ait,
		    true)) != NULL) {
			if (jstr(a, "address") == NULL || (addr_local(jstr(a,
			    "address")) && strcmp(tp.sel_if, name) != 0))
				continue;
			h_raw(h, "<small class=\"mono\">");
			h_txt(h, jstr(a, "address"));
			if (jget(a, "prefixlen") != NULL)
				h_fmt(h, "/%lld", (long long)jint(a,
				    "prefixlen", 0));
			if (jstr(a, "destination") != NULL) {
				h_raw(h, " → ");
				h_txt(h, jstr(a, "destination"));
			}
			h_raw(h, "</small>");
		}
		if (strcmp(tp.sel_if, name) == 0 || (tp.sel_if[0] == '\0' &&
		    r != NULL && r->n > 1 && rate_now(t, name) >= 1))
			chart(h, r, 260, 54);
		h_raw(h, "</li>");
	}
	h_raw(h, "</ul></section>");
}

static void
panel_link(struct html *h, struct tlink *l)
{
	static const char *const kinds[] = { "Tunnel", "Point to point",
	    "Same network", "BGP session", "OSPF adjacency",
	    "Jail with its own network" };
	struct thost	*t;
	const char	*ifn;
	int		 end, s;

	h_raw(h, "<section class=\"pane\"><h4>");
	h_txt(h, kinds[l->kind]);
	h_raw(h, "<button class=\"icon\" data-act=\"topo-unselect\" "
	    "title=\"Close\">×</button></h4><p class=\"mono\">");
	h_txt(h, l->label);
	h_raw(h, "</p>");
	for (end = 0; end < 2; end++) {
		s = end == 0 ? l->a : l->b;
		ifn = end == 0 ? l->ifa : l->ifb;
		if (s < 0 || s >= ntn)
			continue;
		t = thost(tn[s].key, false);
		h_raw(h, "<div class=\"end\"><b>");
		h_txt(h, tn[s].label);
		h_raw(h, "</b> ");
		if (l->kind >= LK_BGP) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "topo-open-bird\"");
			h_attr(h, "data-arg", tn[s].key);
			h_raw(h, ">Its BIRD</button></div>");
			continue;
		}
		h_raw(h, "<span class=\"mono\">");
		h_txt(h, ifn[0] != '\0' ? ifn : "?");
		h_raw(h, "</span>");
		if (t != NULL && ifn[0] != '\0')
			chart(h, rate_of(t, ifn, false), 260, 54);
		h_raw(h, "</div>");
	}
	if (l->kind == LK_TUNNEL && l->b >= 0) {
		h_raw(h, "<div class=\"pane-actions\"><button class=\"danger "
		    "small\" data-act=\"topo-tunnel-destroy\"");
		h_attr(h, "data-arg", l->key);
		h_raw(h, ">Destroy the tunnel</button></div>");
	}
	h_raw(h, "</section>");
}

/*
 * Every WireGuard peer of every host, with when it last shook hands: a
 * session is one that did within the last three minutes.
 */
static void
wg_sessions(struct html *h)
{
	const ucl_object_t	*o, *p;
	ucl_object_iter_t	 it, pit;
	const char		*other;
	char			 age[32], key[20];
	int64_t			 now, hs;
	int			 i, k, n, peer;

	n = 0;
	for (i = 0; i < nhosts; i++) {
		if (hosts[i].wg == NULL || node_index(hosts[i].sid) == -1)
			continue;
		now = jint(hosts[i].wg, "now", 0);
		it = NULL;
		while ((o = ucl_object_iterate(jget(hosts[i].wg, "interfaces"),
		    &it, true)) != NULL) {
			pit = NULL;
			while ((p = ucl_object_iterate(jget(o, "peers"), &pit,
			    true)) != NULL) {
				if (n++ == 0)
					h_raw(h, "<section class=\"pane\"><h4>"
					    "WireGuard sessions</h4><ul class="
					    "\"iflist wgs\">");
				hs = jint(p, "latest-handshake", 0);
				/* The peer by its host's name, when it is one. */
				other = NULL;
				peer = -1;
				for (k = 0; k < nhosts && other == NULL; k++)
					if (k != i && (other = wg_iface(
					    &hosts[k], jstr(p, "public-key"),
					    NULL)) != NULL)
						peer = node_index(
						    hosts[k].sid);
				h_fmt(h, "<li class=\"%s\" data-act=\""
				    "topo-open-wg\"", hs != 0 && now - hs <
				    180 ? "up" : "down");
				h_attr(h, "data-arg", hosts[i].sid);
				h_raw(h, "><div class=\"ifhead\"><i class=\"led\">"
				    "</i><b>");
				h_txt(h, tn[node_index(hosts[i].sid)].label);
				h_raw(h, "</b><span class=\"dim\">");
				h_txt(h, jstr(o, "name"));
				h_raw(h, " → </span><b>");
				if (peer >= 0)
					h_txt(h, tn[peer].label);
				else {
					snprintf(key, sizeof(key), "%.10s…",
					    jstr(p, "public-key") != NULL ?
					    jstr(p, "public-key") : "");
					h_txt(h, key);
				}
				h_raw(h, "</b><span class=\"io\">");
				if (hs == 0)
					h_raw(h, "never");
				else {
					vpn_age(age, sizeof(age), now - hs);
					h_txt(h, age);
				}
				h_raw(h, "</span></div><small class=\"mono\">");
				h_txt(h, jstr(p, "endpoint") != NULL ? jstr(p,
				    "endpoint") : "no endpoint");
				h_raw(h, "</small></li>");
			}
		}
	}
	if (n > 0)
		h_raw(h, "</ul></section>");
}

/*
 * The Overlay tab: every tunnel of every host, one row an end, its far
 * end named when a host of this console has it: gre(4), gif(4) and the
 * like by their outer addresses, WireGuard by its peers' keys, and the
 * VPNs' tun and tap.  WireGuard's peers with when each last shook hands
 * come under it, as the map's panel had them.
 */
/* A row's cell, as text. */
static void
ov_set(ucl_object_t *o, const char *key, const char *value)
{

	ucl_object_replace_key(o, ucl_object_fromstring(value != NULL ? value :
	    ""), key, 0, true);
}

static const char *
overlay_kind(const struct thost *t, const ucl_object_t *o)
{
	const char	*n = jstr(o, "name");

	if (n == NULL)
		return (NULL);
	if (wg_iface((struct thost *)(uintptr_t)t, NULL, n) != NULL ||
	    strncmp(n, "wg", 2) == 0)
		return ("WireGuard");
	if (strncmp(n, "gre", 3) == 0)
		return ("gre");
	if (strncmp(n, "gif", 3) == 0)
		return ("gif");
	if (strncmp(n, "geneve", 6) == 0)
		return ("geneve");
	if (strncmp(n, "vxlan", 5) == 0)
		return ("vxlan");
	if (strncmp(n, "tun", 3) == 0 || strncmp(n, "tap", 3) == 0)
		return ("VPN (tun)");
	if (strncmp(n, "me", 2) == 0 && jget(o, "tunnel") != NULL)
		return ("minimal encapsulation");
	if (jget(o, "tunnel") != NULL)
		return ("tunnel");
	return (NULL);
}

/* An end's far end: the host with the remote address, and the interface
 * there whose own remote is this end's local. */
static void
overlay_far(const ucl_object_t *o, char *buf, size_t len)
{
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;
	struct thost		*t;
	int			 p;

	buf[0] = '\0';
	if (jstr(o, "tunnel.remote") == NULL || (p = owner(jstr(o,
	    "tunnel.remote"), NULL, 0)) == -1)
		return;
	snprintf(buf, len, "%s", tn[p].label);
	if ((t = thost(tn[p].key, false)) == NULL)
		return;
	it = NULL;
	while ((f = ucl_object_iterate(jget(t->ifs, "interfaces"), &it, true)) !=
	    NULL)
		if (jstr(f, "tunnel.remote") != NULL && jstr(o, "tunnel.local") !=
		    NULL && addr_same(jstr(f, "tunnel.remote"), jstr(o,
		    "tunnel.local")) && jstr(f, "name") != NULL) {
			snprintf(buf + strlen(buf), len - strlen(buf), " · %s",
			    jstr(f, "name"));
			return;
		}
}

static ucl_object_t *
overlay_rows(void)
{
	const ucl_object_t	*o, *a, *nb, *wi, *p;
	ucl_object_iter_t	 it, ait, nit, wit, pit;
	ucl_object_t		*all, *r;
	struct thost		*t;
	const char		*kind, *n;
	char			 buf[256], far[160], rate[24];
	int			 i, k, peers, live;
	int64_t			 now, hs, best;

	all = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < ntn; i++) {
		ucl_object_t	*list;

		if ((t = thost(tn[i].key, false)) == NULL || (t->ifs == NULL &&
		    t->wg == NULL))
			continue;
		/* Its interfaces, and a WireGuard interface its WireGuard
		 * tells of when the interfaces read lack it. */
		list = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((o = ucl_object_iterate(jget(t->ifs, "interfaces"), &it,
		    true)) != NULL)
			ucl_array_append(list, ucl_object_ref((ucl_object_t *)
			    (uintptr_t)o));
		wit = NULL;
		while ((wi = ucl_object_iterate(jget(t->wg, "interfaces"), &wit,
		    true)) != NULL) {
			ucl_object_t	*f;

			if (jstr(wi, "name") == NULL || if_named(t, jstr(wi, "name")) !=
			    NULL)
				continue;
			f = ucl_object_typed_new(UCL_OBJECT);
			ov_set(f, "name", jstr(wi, "name"));
			ucl_object_insert_key(f, ucl_object_frombool(true), "up", 0,
			    false);
			ucl_array_append(list, f);
		}
		it = NULL;
		while ((o = ucl_object_iterate(list, &it, true)) != NULL) {
			if ((kind = overlay_kind(t, o)) == NULL ||
			    (n = jstr(o, "name")) == NULL)
				continue;
			r = ucl_object_typed_new(UCL_OBJECT);
			ov_set(r, "host", tn[i].label);
			ov_set(r, "key", tn[i].key);
			ov_set(r, "if", n);
			ov_set(r, "kind", kind);
			/* Its inner addresses, link-local left out. */
			buf[0] = '\0';
			ait = NULL;
			while ((a = ucl_object_iterate(jget(o, "addresses"),
			    &ait, true)) != NULL)
				if (jstr(a, "address") != NULL && strncmp(jstr(a,
				    "address"), "fe80:", 5) != 0)
					snprintf(buf + strlen(buf), sizeof(buf) -
					    strlen(buf), "%s%s/%lld", buf[0] != '\0' ?
					    " " : "", jstr(a, "address"), (long long)
					    jint(a, "prefixlen", 0));
			ov_set(r, "inner", buf);
			far[0] = '\0';
			if (jstr(o, "tunnel.local") != NULL) {
				snprintf(buf, sizeof(buf), "%s → %s", jstr(o,
				    "tunnel.local"), jstr(o, "tunnel.remote") !=
				    NULL ? jstr(o, "tunnel.remote") : "?");
				overlay_far(o, far, sizeof(far));
			} else
				buf[0] = '\0';
			/* WireGuard: its peers, their endpoints, the last
			 * handshake of any. */
			peers = live = 0;
			best = 0;
			now = t->wg != NULL ? jint(t->wg, "now", 0) : 0;
			wit = NULL;
			while (t->wg != NULL && (wi = ucl_object_iterate(jget(t->wg,
			    "interfaces"), &wit, true)) != NULL) {
				if (jstr(wi, "name") == NULL || strcmp(jstr(wi,
				    "name"), n) != 0)
					continue;
				pit = NULL;
				while ((p = ucl_object_iterate(jget(wi, "peers"),
				    &pit, true)) != NULL) {
					const char	*other = NULL;

					peers++;
					hs = jint(p, "latest-handshake", 0);
					if (hs > best)
						best = hs;
					if (hs != 0 && now - hs < 180)
						live++;
					if (jstr(p, "endpoint") != NULL &&
					    strlen(buf) + 40 < sizeof(buf))
						snprintf(buf + strlen(buf), sizeof(buf) -
						    strlen(buf), "%s%s", buf[0] !=
						    '\0' ? ", " : "→ ", jstr(p,
						    "endpoint"));
					for (k = 0; k < nhosts && other == NULL;
					    k++)
						if (&hosts[k] != t && (other =
						    wg_iface(&hosts[k], jstr(p,
						    "public-key"), NULL)) != NULL &&
						    node_index(hosts[k].sid) != -1)
							snprintf(far + strlen(far),
							    sizeof(far) - strlen(far),
							    "%s%s · %s", far[0] !=
							    '\0' ? ", " : "", tn[node_index(
							    hosts[k].sid)].label, other);
				}
			}
			ov_set(r, "outer", buf);
			ov_set(r, "far", far);
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(o, "fib",
			    0));
			ov_set(r, "fib", buf);
			if (jget(o, "tunnel") != NULL) {
				snprintf(buf, sizeof(buf), "%lld", (long long)jint(o,
				    "tunnelfib", 0));
				ov_set(r, "tfib", buf);
			} else
				ov_set(r, "tfib", "");
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(o, "mtu",
			    0));
			ov_set(r, "mtu", buf);
			if (peers > 0) {
				if (best == 0)
					snprintf(buf, sizeof(buf), "%s · %d peer%s, "
					    "none shook hands", jbool(o, "up") ?
					    "up" : "down", peers, peers == 1 ? "" :
					    "s");
				else {
					char	age[32];

					vpn_age(age, sizeof(age), now - best);
					snprintf(buf, sizeof(buf), "%s · %d of %d "
					    "peer%s live · %s", jbool(o, "up") ?
					    "up" : "down", live, peers, peers == 1 ?
					    "" : "s", age);
				}
			} else
				snprintf(buf, sizeof(buf), "%s", jbool(o, "up") ?
				    (jstr(o, "link") == NULL || strcmp(jstr(o,
				    "link"), "up") == 0 ? "up" : "up, no link") :
				    "down");
			ov_set(r, "state", buf);
			fmt_rate(rate, sizeof(rate), rate_now(t, n));
			ov_set(r, "rate", rate);
			snprintf(buf, sizeof(buf), "%.0f", rate_now(t, n));
			ov_set(r, "bps", buf);
			/* OSPF over it, as BIRD's neighbours say. */
			buf[0] = '\0';
			nit = NULL;
			while (t->bird != NULL && (nb = ucl_object_iterate(jget(
			    t->bird, "ospf"), &nit, true)) != NULL)
				if (jstr(nb, "interface") != NULL && strcmp(jstr(nb,
				    "interface"), n) == 0)
					snprintf(buf, sizeof(buf), "%s",
					    jstr(nb, "state") != NULL ? jstr(nb,
					    "state") : "yes");
			ov_set(r, "ospf", buf);
			ucl_array_append(all, r);
		}
		ucl_object_unref(list);
	}
	return (all);
}

void
view_overlay(struct html *h)
{
	static const struct tcol cols[] = {
		{ "Host", "host", false }, { "Interface", "if", false },
		{ "Kind", "kind", false }, { "Inner", "inner", false },
		{ "Outer", "outer", false }, { "Far end", "far", false },
		{ "FIB", "fib", true }, { "Outer FIB", "tfib", true },
		{ "MTU", "mtu", true }, { "State", "state", false },
		{ "Traffic", "bps", true }, { "OSPF", "ospf", false },
	};
	const ucl_object_t	**rows, *r;
	ucl_object_t		*all;
	int			 i, n, total, reading;

	nodes_build();
	links_build();
	if (overlay_quality(h))
		return;
	for (reading = 0, i = 0; i < ntn; i++)
		if (thost(tn[i].key, false) == NULL || thost(tn[i].key,
		    false)->ifs == NULL)
			reading++;
	all = overlay_rows();
	total = (int)ucl_array_size(all);
	if (total == 0) {
		h_raw(h, reading > 0 ? "<div class=\"empty\"><div class=\"loader\">"
		    "</div></div>" : "<div class=\"empty\"><h2>No overlay "
		    "tunnels</h2><p>No host has a gre, gif, WireGuard, geneve, "
		    "vxlan or VPN interface. One is made on the map: drag from a "
		    "host's port onto another.</p></div>");
		ucl_object_unref(all);
		return;
	}
	rows = tbl_rows("overlay", all, cols, (int)nitems(cols), app.filter);
	for (n = 0; rows[n] != NULL; n++)
		;
	h_raw(h, "<div class=\"overlay-page\"><div class=\"toolbar\"><input "
	    "class=\"filter\" id=\"filter\" data-input=\"filter\" placeholder="
	    "\"Filter by host, interface, kind, address…\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_fmt(h, "><span class=\"tally\"><b>%d</b> of %d tunnel end%s</span>"
	    "</div><div class=\"scrollx\"><table class=\"net overlay\">", n, total, total == 1 ? "" :
	    "s");
	tbl_head(h, "overlay", cols, (int)nitems(cols), 0);
	h_raw(h, "<tbody>");
	for (i = 0; (r = rows[i]) != NULL; i++) {
		h_raw(h, "<tr class=\"pick\" data-act=\"topo-open-host\"");
		h_attr(h, "data-arg", jstr(r, "key"));
		h_raw(h, " title=\"Its host's interfaces\"><td><b>");
		h_txt(h, jstr(r, "host"));
		h_raw(h, "</b></td><td class=\"mono\">");
		h_txt(h, jstr(r, "if"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "kind"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "inner")[0] != '\0' ? jstr(r, "inner") :
		    "—");
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "outer")[0] != '\0' ? jstr(r, "outer") :
		    "—");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "far")[0] != '\0' ? jstr(r, "far") :
		    "outside");
		h_raw(h, "</td><td class=\"num\">");
		h_txt(h, jstr(r, "fib"));
		h_raw(h, "</td><td class=\"num\">");
		h_txt(h, jstr(r, "tfib")[0] != '\0' ? jstr(r, "tfib") : "—");
		h_raw(h, "</td><td class=\"num\">");
		h_txt(h, strcmp(jstr(r, "mtu"), "0") != 0 ? jstr(r, "mtu") : "—");
		h_fmt(h, "</td><td class=\"%s\">", strncmp(jstr(r, "state"),
		    "up", 2) == 0 ? "ok" : "bad");
		h_txt(h, jstr(r, "state"));
		h_raw(h, "</td><td class=\"num\">");
		h_txt(h, jstr(r, "rate"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "ospf")[0] != '\0' ? jstr(r, "ospf") : "—");
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table></div>");
	wg_sessions(h);
	h_raw(h, "</div>");
	free(rows);
	ucl_object_unref(all);
}

/*
 * The Leaking tab: where one routing table (FIB) reaches into another.
 * A route of a table that is an interface's own (no gateway, the
 * interface named) while the interface is in another table is a leak:
 * made by net.add_addr_allfibs, which gives every table an address's
 * network, or by a route added there, route(8)'s -fib N ... -iface.
 * Beside them each node's settings: how many tables (net.fibs, at
 * boot), net.add_addr_allfibs (live), and whether sockets bound in one
 * table take traffic of all (net.inet.{tcp,udp,raw}.bind_all_fibs,
 * tunables: for the next boot, in the host's loader.conf.d).
 */
#define	LK_FIBS		16
#define	LK_POLL_MS	30000

enum { LKS_FIBS, LKS_ALLFIBS, LKS_TCP, LKS_UDP, LKS_RAW, LKS_N };
static const char *const lk_names[LKS_N] = { "net.fibs",
    "net.add_addr_allfibs", "net.inet.tcp.bind_all_fibs",
    "net.inet.udp.bind_all_fibs", "net.inet.raw.bind_all_fibs" };

static struct {
	double		 fetched[MAX_NODES];
	int		 wait[MAX_NODES];
	int		 val[MAX_NODES][LKS_N];	/* -1: not known */
	ucl_object_t	*routes[MAX_NODES][LK_FIBS];
	char		*loader[MAX_NODES];	/* a host's loader.conf.d */
	bool		 sys_loading[MAX_NODES];
	int		 boot_k[MAX_NODES], boot_v[MAX_NODES];	/* asked, file not read */
	/* The form: a network of an interface into another table. */
	char		 f_node[80], f_if[16], f_prefix[64];
	int		 f_fib;
	bool		 f_keep;
} lkg;

struct lkreq {
	char	key[80];
	int	what;		/* LKS_*, or 100 + a table's routes */
};

static void	lk_sysctl_cb(int, const ucl_object_t *, const char *, void *);

/* One of a node's settings asked for. */
static void
lk_ask(int i, int k)
{
	struct lkreq	*rq;
	char		 url[240];

	if ((rq = calloc(1, sizeof(*rq))) == NULL)
		abort();
	snprintf(rq->key, sizeof(rq->key), "%s", tn[i].key);
	rq->what = k;
	snprintf(url, sizeof(url), "/api/servers/%s/sysctl?filter=%s%s%s",
	    app.servers[tn[i].srv].id, lk_names[k], tn[i].jail[0] != '\0' ?
	    "&jail=" : "", tn[i].jail);
	lkg.wait[i]++;
	api("GET", url, NULL, lk_sysctl_cb, rq);
}

static void	lk_routes_cb(int, const ucl_object_t *, const char *, void *);

/* A node's table f's routes asked for. */
static void
lk_table(int i, int f)
{
	struct lkreq	*rq;
	char		 url[240], more[32];

	if ((rq = calloc(1, sizeof(*rq))) == NULL)
		abort();
	snprintf(rq->key, sizeof(rq->key), "%s", tn[i].key);
	rq->what = 100 + f;
	snprintf(more, sizeof(more), "fib=%d", f);
	node_url(i, "routes", more, url, sizeof(url));
	lkg.wait[i]++;
	api("GET", url, NULL, lk_routes_cb, rq);
}

static void
lk_routes_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct lkreq	*rq = arg;
	int		 i, f;

	(void)err;
	if ((i = node_index(rq->key)) != -1) {
		lkg.wait[i]--;
		f = rq->what - 100;
		if (f >= 0 && f < LK_FIBS) {
			const ucl_object_t	*fam, *e;
			ucl_object_iter_t	 fit = NULL;
			bool			 other = false;

			/* Its entries say their table: another's reply (a
			 * read of the host's shared) is not this one's. */
			while (status == 200 && (fam = ucl_object_iterate(jget(o,
			    "data.statistics.route-information.route-table."
			    "rt-family"), &fit, true)) != NULL)
				if ((e = ucl_array_find_index(jget(fam, "rt-entry"),
				    0)) != NULL && jint(e, "fib", f) != f)
					other = true;
			if (status == 200 && jbool(o, "ok") && jget(o, "data") !=
			    NULL && !other) {
				if (lkg.routes[i][f] != NULL)
					ucl_object_unref(lkg.routes[i][f]);
				lkg.routes[i][f] = ucl_object_ref((ucl_object_t *)
				    (uintptr_t)jget(o, "data"));
			} else
				lkg.fetched[i] = 0;
			/* The next table. */
			if (f + 1 < lkg.val[i][LKS_FIBS] && f + 1 < LK_FIBS)
				lk_table(i, f + 1);
		}
	}
	free(rq);
}

static void
lk_sysctl_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct lkreq		*rq = arg;
	const ucl_object_t	*v;
	int			 i;

	(void)err;
	if ((i = node_index(rq->key)) != -1) {
		lkg.wait[i]--;
		/* The value of the name asked for alone: a reply of another
		 * read of the host's is not taken for it. */
		{
			ucl_object_iter_t	vit = NULL;

			while ((v = status == 200 && jbool(o, "ok") ?
			    ucl_object_iterate(jget(o, "data.values"), &vit, true) :
			    NULL) != NULL)
				if (jstr(v, "name") != NULL && strcmp(jstr(v, "name"),
				    lk_names[rq->what]) == 0)
					break;
		}
		if (v != NULL && jstr(v, "value") != NULL)
			lkg.val[i][rq->what] = atoi(jstr(v, "value"));
		else
			lkg.fetched[i] = 0;	/* read again */
		/* One read at a time of a host's: the next name, then each
		 * table's routes. */
		if (rq->what + 1 < LKS_N)
			lk_ask(i, rq->what + 1);
		else if (lkg.val[i][LKS_FIBS] > 0)
			lk_table(i, 0);
	}
	free(rq);
}

static void	lk_boot_write(int, int, int);

/* A host's loader.conf.d, read from its system read. */
static void
lk_sys_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*key = arg;
	int	 i;

	(void)err;
	if ((i = node_index(key)) != -1) {
		lkg.sys_loading[i] = false;
		free(lkg.loader[i]);
		lkg.loader[i] = NULL;
		if (status == 200 && jbool(o, "ok")) {
			/* Its name has dots: looked up as one key. */
			const ucl_object_t	*lf = ucl_object_lookup(jget(o,
			    "data.files"), "loader.conf.d");

			lkg.loader[i] = strdup(jstr(lf, "text") != NULL ?
			    jstr(lf, "text") : "");
		}
		/* A change asked for while the file was being read. */
		if (lkg.loader[i] != NULL && lkg.boot_k[i] != 0) {
			lk_boot_write(i, lkg.boot_k[i], lkg.boot_v[i]);
			lkg.boot_k[i] = 0;
		}
	}
	free(key);
}

/* Each node's settings and tables read again, every half minute. */
static void
lk_poll(bool now)
{
	int		 i;

	for (i = 0; i < ntn; i++) {
		if (lkg.wait[i] > 0 || (!now && arc_now() - lkg.fetched[i] <
		    LK_POLL_MS))
			continue;
		lkg.fetched[i] = arc_now();
		lk_ask(i, 0);
	}
}

/* Is dest/plen the network address a/its length? */
static bool
lk_net_of(const char *dest, int plen, const char *addr, int alen)
{
	unsigned char	d[16], a[16];
	int		 df, af, k, bits;

	if (plen != alen || !addr_bytes(dest, &df, d) || !addr_bytes(addr,
	    &af, a) || df != af)
		return (false);
	for (k = 0; k < (df == AF_INET ? 4 : 16); k++) {
		bits = plen - 8 * k;
		if (bits >= 8)
			continue;
		a[k] &= bits <= 0 ? 0 : (unsigned char)(0xff << (8 - bits));
		d[k] &= bits <= 0 ? 0 : (unsigned char)(0xff << (8 - bits));
	}
	return (memcmp(a, d, df == AF_INET ? 4 : 16) == 0);
}

/* Is the route the network of one of the interface's own addresses? */
static bool
lk_own_net(const ucl_object_t *ifo, const char *dest, int plen)
{
	const ucl_object_t	*a;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((a = ucl_object_iterate(jget(ifo, "addresses"), &it, true)) !=
	    NULL)
		if (jstr(a, "address") != NULL && lk_net_of(dest, plen, jstr(a,
		    "address"), (int)jint(a, "prefixlen", -1)))
			return (true);
	return (false);
}

/* Every leak of every node, as rows. */
static ucl_object_t *
lk_rows(void)
{
	const ucl_object_t	*fam, *r, *ifo;
	ucl_object_iter_t	 it, rit;
	ucl_object_t		*all, *row;
	struct thost		*t;
	const char		*ifn, *flags, *dest;
	char			 buf[128];
	int			 i, f, g, plen;

	all = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < ntn; i++) {
		if ((t = thost(tn[i].key, false)) == NULL || t->ifs == NULL)
			continue;
		for (f = 0; f < LK_FIBS; f++) {
			it = NULL;
			while ((fam = ucl_object_iterate(jget(lkg.routes[i][f],
			    "statistics.route-information.route-table.rt-family"),
			    &it, true)) != NULL) {
				rit = NULL;
				while ((r = ucl_object_iterate(jget(fam,
				    "rt-entry"), &rit, true)) != NULL) {
					ifn = jstr(r, "interface-name");
					flags = jstr(r, "flags");
					dest = jstr(r, "destination");
					/* Connected: no gateway; the host's
					 * own addresses (lo0) left out. */
					if (ifn == NULL || dest == NULL || flags ==
					    NULL || strchr(flags, 'G') != NULL ||
					    strncmp(ifn, "lo", 2) == 0 ||
					    strncmp(dest, "fe80:", 5) == 0 ||
					    (ifo = if_named(t, ifn)) == NULL)
						continue;
					g = (int)jint(ifo, "fib", 0);
					if (g == f)
						continue;
					plen = (int)jint(r, "prefixlen", -1);
					row = ucl_object_typed_new(UCL_OBJECT);
					ov_set(row, "key", tn[i].key);
					ov_set(row, "host", tn[i].label);
					/* A network says its length; a host not. */
					if (strchr(dest, '/') != NULL)
						snprintf(buf, sizeof(buf), "%s", dest);
					else
						snprintf(buf, sizeof(buf), "%s/%d",
						    dest, plen);
					ov_set(row, "prefix", buf);
					ov_set(row, "if", ifn);
					snprintf(buf, sizeof(buf), "%d", g);
					ov_set(row, "from", buf);
					snprintf(buf, sizeof(buf), "%d", f);
					ov_set(row, "into", buf);
					/* A static route; or the kernel's own:
					 * every table's by add_addr_allfibs, or
					 * left in the table the interface was
					 * in when it was given the address. */
					ov_set(row, "how", strchr(flags, 'S') !=
					    NULL ? "a route" : lkg.val[i][LKS_ALLFIBS]
					    == 1 && lk_own_net(ifo, dest, plen) ?
					    "net.add_addr_allfibs" : "left from its "
					    "earlier FIB");
					ucl_array_append(all, row);
				}
			}
		}
	}
	return (all);
}

/* The networks of a node's interface, for the form: address/length. */
static void
lk_prefixes(struct html *h, const ucl_object_t *ifo)
{
	const ucl_object_t	*a;
	ucl_object_iter_t	 it;
	unsigned char		 raw[16];
	char			 net[64], pfx[80];
	int			 af, plen, k, bits;

	it = NULL;
	while ((a = ucl_object_iterate(jget(ifo, "addresses"), &it, true)) !=
	    NULL) {
		if (jstr(a, "address") == NULL || strncmp(jstr(a, "address"),
		    "fe80:", 5) == 0 || !addr_bytes(jstr(a, "address"), &af,
		    raw))
			continue;
		plen = (int)jint(a, "prefixlen", af == AF_INET ? 32 : 128);
		for (k = 0; k < (af == AF_INET ? 4 : 16); k++) {
			bits = plen - 8 * k;
			if (bits < 8)
				raw[k] &= bits <= 0 ? 0 : (unsigned char)(0xff <<
				    (8 - bits));
		}
		if (inet_ntop(af, raw, net, sizeof(net)) == NULL)
			continue;
		snprintf(pfx, sizeof(pfx), "%s/%d", net, plen);
		h_raw(h, "<option");
		h_attr(h, "value", pfx);
		if (strcmp(lkg.f_prefix, pfx) == 0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, pfx);
		h_raw(h, "</option>");
	}
}

static const char *
lk_val(int i, int k)
{
	static char	b[8][16];
	static int	n;
	char		*p = b[n++ % 8];

	if (lkg.val[i][k] < 0)
		return ("…");
	snprintf(p, 16, "%d", lkg.val[i][k]);
	return (p);
}

/* What a host's loader.conf.d sets a tunable to: "1", "0", or "". */
static const char *
lk_boot(int i, const char *name)
{
	static char	v[16];
	const char	*p, *q;
	size_t		 n = strlen(name);

	v[0] = '\0';
	for (p = lkg.loader[i]; p != NULL && *p != '\0'; p = q != NULL ? q + 1 :
	    NULL) {
		q = strchr(p, '\n');
		while (*p == ' ' || *p == '\t')
			p++;
		if (strncmp(p, name, n) == 0 && p[n] == '=') {
			p += n + 1;
			if (*p == '"')
				p++;
			snprintf(v, sizeof(v), "%.*s", (int)strcspn(p, "\"\n"),
			    p);
		}
	}
	return (v);
}

void
view_leaks(struct html *h)
{
	static const struct tcol cols[] = {
		{ "Host", "host", false }, { "Network", "prefix", false },
		{ "Interface", "if", false }, { "Its FIB", "from", true },
		{ "Leaked into FIB", "into", true }, { "By", "how", false },
	};
	const ucl_object_t	**rows, *r, *o;
	ucl_object_iter_t	 it;
	ucl_object_t		*all;
	struct thost		*t;
	int			 i, n, total, k, fibs, fn;

	nodes_build();
	lk_poll(false);
	all = lk_rows();
	total = (int)ucl_array_size(all);
	rows = tbl_rows("leaks", all, cols, (int)nitems(cols), app.filter);
	for (n = 0; rows[n] != NULL; n++)
		;
	h_raw(h, "<div class=\"leaks-page\"><p class=\"dim leaks-note\">Where "
	    "one routing table reaches into another: a network of an interface "
	    "of one FIB that another FIB has too, given by <code>net."
	    "add_addr_allfibs</code> or by a route of its own (<code>route add "
	    "-fib N network -iface interface</code>). Sockets bound in one "
	    "table take traffic of all with <code>bind_all_fibs</code>, set at "
	    "boot.</p><div class=\"toolbar\"><input class=\"filter\" id=\""
	    "filter\" data-input=\"filter\" placeholder=\"Filter by host, "
	    "network, interface…\" autocomplete=\"off\" spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_fmt(h, "><span class=\"tally\"><b>%d</b> of %d leak%s</span></div>",
	    n, total, total == 1 ? "" : "s");
	if (total == 0)
		h_raw(h, "<div class=\"empty\"><p>No table reaches into "
		    "another: every interface's networks are in its own FIB "
		    "alone.</p></div>");
	else {
		h_raw(h, "<div class=\"scrollx\"><table class=\"net leaks\">");
		tbl_head(h, "leaks", cols, (int)nitems(cols), 1);
		h_raw(h, "<tbody>");
		for (i = 0; (r = rows[i]) != NULL; i++) {
			h_raw(h, "<tr><td><b>");
			h_txt(h, jstr(r, "host"));
			h_raw(h, "</b></td><td class=\"mono\">");
			h_txt(h, jstr(r, "prefix"));
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(r, "if"));
			h_raw(h, "</td><td class=\"num\">");
			h_txt(h, jstr(r, "from"));
			h_raw(h, "</td><td class=\"num\">");
			h_txt(h, jstr(r, "into"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(r, "how"));
			h_raw(h, "</td><td>");
			if (strcmp(jstr(r, "how"), "net.add_addr_allfibs") != 0) {
				h_raw(h, "<button class=\"ghost small danger\" "
				    "data-act=\"lk-remove\"");
				h_attr(h, "data-arg", jstr(r, "key"));
				h_fmt(h, " data-value=\"%s %s %s\" title=\"route "
				    "delete -fib %s, and out of rc.conf\">Remove"
				    "</button>", jstr(r, "into"), jstr(r,
				    "prefix"), jstr(r, "if"), jstr(r, "into"));
			}
			h_raw(h, "</td></tr>");
		}
		h_raw(h, "</tbody></table></div>");
	}
	free(rows);
	ucl_object_unref(all);

	/* A network leaked by hand. */
	h_raw(h, "<section class=\"pane leaks-form\"><h4>Leak a network into "
	    "another table</h4><div class=\"lkform\"><label>Host<select "
	    "data-input=\"lk-node\"><option value=\"\">a host…</option>");
	for (i = 0; i < ntn; i++) {
		h_raw(h, "<option");
		h_attr(h, "value", tn[i].key);
		if (strcmp(lkg.f_node, tn[i].key) == 0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, tn[i].label);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label>");
	k = node_index(lkg.f_node);
	t = k != -1 ? thost(tn[k].key, false) : NULL;
	h_raw(h, "<label>Interface<select data-input=\"lk-if\"><option value="
	    "\"\">an interface…</option>");
	it = NULL;
	while (t != NULL && (o = ucl_object_iterate(jget(t->ifs, "interfaces"),
	    &it, true)) != NULL) {
		if (jstr(o, "name") == NULL || strncmp(jstr(o, "name"), "lo",
		    2) == 0 || ucl_array_size(jget(o, "addresses")) == 0)
			continue;
		h_raw(h, "<option");
		h_attr(h, "value", jstr(o, "name"));
		if (strcmp(lkg.f_if, jstr(o, "name")) == 0)
			h_raw(h, " selected");
		h_fmt(h, ">%s · FIB %lld</option>", jstr(o, "name"), (long long)
		    jint(o, "fib", 0));
	}
	h_raw(h, "</select></label><label>Network<select name=\"prefix\" "
	    "data-input=\"lk-prefix\"><option value=\"\">a network…</option>");
	if (t != NULL && (o = if_named(t, lkg.f_if)) != NULL)
		lk_prefixes(h, o);
	fibs = k != -1 && lkg.val[k][LKS_FIBS] > 0 ? lkg.val[k][LKS_FIBS] : 1;
	fn = t != NULL && if_named(t, lkg.f_if) != NULL ? (int)jint(if_named(t,
	    lkg.f_if), "fib", 0) : -1;
	h_raw(h, "</select></label><label>Into FIB<select name=\"fib\" "
	    "data-input=\"lk-fib\">");
	for (i = 0; i < fibs && i < LK_FIBS; i++)
		if (i != fn)
			h_fmt(h, "<option value=\"%d\"%s>%d</option>", i,
			    lkg.f_fib == i ? " selected" : "", i);
	h_fmt(h, "</select></label><label class=\"check\"><input type=\""
	    "checkbox\" data-input=\"lk-keep\"%s> Kept in rc.conf</label>"
	    "<button type=\"button\" class=\"primary small\" data-act=\"lk-add\">"
	    "Leak it</button></div><p class=\"dim\">A safe change: undone unless "
	    "the host is still reached after it.</p></section>", lkg.f_keep ?
	    " checked" : "");

	/* Each node's settings. */
	h_raw(h, "<section class=\"pane\"><h4>Each host's tables</h4><div "
	    "class=\"scrollx\"><table class=\"net leaks-sys\"><thead><tr><th>"
	    "Host</th><th title=\"net.fibs, set at boot\">FIBs</th><th title="
	    "\"net.add_addr_allfibs: an address's network in every table, "
	    "changed live\">Addresses in all FIBs</th><th title=\"net.inet.tcp."
	    "bind_all_fibs\">TCP binds all</th><th title=\"net.inet.udp."
	    "bind_all_fibs\">UDP binds all</th><th title=\"net.inet.raw."
	    "bind_all_fibs\">Raw binds all</th></tr></thead><tbody>");
	for (i = 0; i < ntn; i++) {
		h_raw(h, "<tr><td><b>");
		h_txt(h, tn[i].label);
		h_fmt(h, "</b></td><td class=\"num\">%s</td><td>%s ",
		    lk_val(i, LKS_FIBS), lk_val(i, LKS_ALLFIBS));
		if (lkg.val[i][LKS_ALLFIBS] >= 0) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "lk-allfibs\"");
			h_attr(h, "data-arg", tn[i].key);
			h_fmt(h, " data-value=\"%d\">Turn %s</button>",
			    !lkg.val[i][LKS_ALLFIBS], lkg.val[i][LKS_ALLFIBS] ?
			    "off" : "on");
		}
		h_raw(h, "</td>");
		for (k = LKS_TCP; k <= LKS_RAW; k++) {
			h_fmt(h, "<td>%s", lk_val(i, k));
			/* A tunable: the host's next boot. */
			if (tn[i].jail[0] == '\0' && lkg.loader[i] != NULL) {
				const char	*b = lk_boot(i, lk_names[k]);
				int		 next = b[0] != '\0' ? atoi(b) :
				    lkg.val[i][k];

				if (b[0] != '\0' && next != lkg.val[i][k])
					h_fmt(h, " <small class=\"dim\">%d at the "
					    "next boot</small>", next);
				h_raw(h, " <button class=\"ghost small\" "
				    "data-act=\"lk-boot\"");
				h_attr(h, "data-arg", tn[i].key);
				h_fmt(h, " data-value=\"%d %d\" title=\"In "
				    "/boot/loader.conf.d/arcana.conf: from the "
				    "next boot\">%s at boot</button>", k, !next,
				    next ? "Off" : "On");
			} else if (tn[i].jail[0] != '\0')
				h_raw(h, " <small class=\"dim\">its host's"
				    "</small>");
			h_raw(h, "</td>");
		}
		h_raw(h, "</tr>");
	}
	h_raw(h, "</tbody></table></div></section></div>");
}

/* A tunable set for the next boot: the host's loader.conf.d written
 * whole, the line replaced or added. */
static void
lk_boot_write(int i, int k, int v)
{
	struct server	*s;
	char		 title[200], *text, line[96];

		/* The file written whole: the tunable's line replaced, or
		 * added. */
		{
			struct html	 b;
			const char	*p, *q;
			size_t		 n = strlen(lk_names[k]);
			bool		 put = false;

			memset(&b, 0, sizeof(b));
			snprintf(line, sizeof(line), "%s=\"%d\"", lk_names[k], v);
			for (p = lkg.loader[i]; *p != '\0'; p = q != NULL ? q + 1 :
			    p + strlen(p)) {
				q = strchr(p, '\n');
				if (strncmp(p, lk_names[k], n) == 0 && p[n] ==
				    '=') {
					h_raw(&b, line);
					h_raw(&b, "\n");
					put = true;
				} else if (q != NULL || *p != '\0') {
					h_fmt(&b, "%.*s\n", (int)(q != NULL ? (size_t)(q - p) :
					    strlen(p)), p);
				}
				if (q == NULL)
					break;
			}
			if (!put) {
				h_raw(&b, line);
				h_raw(&b, "\n");
			}
			text = h_take(&b);
		}
		s = &app.servers[tn[i].srv];
		snprintf(title, sizeof(title), "%s at the next boot", line);
		job_send(s, job_json("sysfile", "loader.conf.d", NULL, 0, text,
		    NULL), title, JOB_SYSTEM, s->name);
		/* As written: the read after the job says it again. */
		free(lkg.loader[i]);
		lkg.loader[i] = text;
}

bool
leaks_action(const char *act, const char *arg, const char *value)
{
	char	 fib[16], pfx[80], ifn[32], title[200];
	int	 i, k, v;

	if (strcmp(act, "input:lk-node") == 0) {
		snprintf(lkg.f_node, sizeof(lkg.f_node), "%s", value);
		lkg.f_if[0] = lkg.f_prefix[0] = '\0';
		return (true);
	}
	if (strcmp(act, "input:lk-if") == 0) {
		snprintf(lkg.f_if, sizeof(lkg.f_if), "%s", value);
		lkg.f_prefix[0] = '\0';
		return (true);
	}
	if (strcmp(act, "input:lk-prefix") == 0) {
		snprintf(lkg.f_prefix, sizeof(lkg.f_prefix), "%s", value);
		return (true);
	}
	if (strcmp(act, "input:lk-fib") == 0) {
		lkg.f_fib = atoi(value);
		return (true);
	}
	if (strcmp(act, "input:lk-keep") == 0) {
		lkg.f_keep = strcmp(value, "true") == 0 || strcmp(value, "on") ==
		    0 || strcmp(value, "1") == 0;
		return (true);
	}
	if (strcmp(act, "lk-add") == 0) {
		if ((i = node_index(lkg.f_node)) == -1 || lkg.f_if[0] == '\0' ||
		    lkg.f_prefix[0] == '\0') {
			toast(true, "A host, an interface and a network");
			return (true);
		}
		snprintf(title, sizeof(title), "leak %s of %s into FIB %d",
		    lkg.f_prefix, lkg.f_if, lkg.f_fib);
		node_job(i, title, lkg.f_if, "{\"kind\":\"route\",\"destination\":"
		    "\"%s\",\"gateway\":\"%s\",\"remove\":false,\"persist\":%s,"
		    "\"fib\":%d,\"safe\":true}", lkg.f_prefix, lkg.f_if, lkg.f_keep ?
		    "true" : "false", lkg.f_fib);
		lkg.fetched[i] = 0;
		return (true);
	}
	if (strcmp(act, "lk-remove") == 0) {
		if ((i = node_index(arg)) == -1 || sscanf(value, "%15s %79s %31s",
		    fib, pfx, ifn) != 3)
			return (true);
		snprintf(title, sizeof(title), "leak %s of %s out of FIB %s",
		    pfx, ifn, fib);
		node_job(i, title, ifn, "{\"kind\":\"route\",\"destination\":"
		    "\"%s\",\"gateway\":\"%s\",\"remove\":true,\"persist\":true,"
		    "\"fib\":%d,\"safe\":true}", pfx, ifn, atoi(fib));
		lkg.fetched[i] = 0;
		return (true);
	}
	if (strcmp(act, "lk-allfibs") == 0) {
		if ((i = node_index(arg)) == -1)
			return (true);
		snprintf(title, sizeof(title), "sysctl net.add_addr_allfibs=%d",
		    atoi(value));
		node_job(i, title, "net.add_addr_allfibs", "{\"kind\":\"sysctl\","
		    "\"args\":[\"net.add_addr_allfibs\",\"%d\"],\"persist\":true,"
		    "\"safe\":true}", atoi(value));
		lkg.fetched[i] = 0;
		return (true);
	}
	if (strcmp(act, "lk-boot") == 0) {
		if ((i = node_index(arg)) == -1 || tn[i].jail[0] != '\0' ||
		    sscanf(value, "%d %d", &k, &v) != 2 || k < LKS_TCP || k >
		    LKS_RAW)
			return (true);
		/* The file is written whole: read first, when it was not. */
		if (lkg.loader[i] == NULL) {
			char	url[240];

			lkg.boot_k[i] = k;
			lkg.boot_v[i] = v;
			if (!lkg.sys_loading[i]) {
				lkg.sys_loading[i] = true;
				snprintf(url, sizeof(url), "/api/servers/%s/system",
				    app.servers[tn[i].srv].id);
				api("GET", url, NULL, lk_sys_cb, strdup(tn[i].key));
			}
			return (true);
		}
		lk_boot_write(i, k, v);
		return (true);
	}
	return (false);
}

/* Nothing picked: what there is, and where the traffic goes. */
static void
panel_overview(struct html *h)
{
	struct { struct thost *t; struct ifrate *r; double v; } top[6], cur;
	struct ifrate sum;
	char	rate[24];
	double	max;
	int	i, k, m, n, kinds[LK_KINDS];

	memset(kinds, 0, sizeof(kinds));
	for (i = 0; i < nlinks; i++)
		kinds[links[i].kind] += 1 + links[i].more;
	h_fmt(h, "<section class=\"pane\"><h4>The fleet's network</h4>"
	    "<div class=\"facts\"><div><b>%d</b><span>hosts</span></div>"
	    "<div><b>%d</b><span>tunnels</span></div><div><b>%d</b><span>"
	    "point to point</span></div><div><b>%d</b><span>shared networks"
	    "</span></div></div><p class=\"dim\">Drag a host to place it, "
	    "the map to move it, and the dot on a host's edge onto another "
	    "host to join the two with a tunnel. Pick a host or a link for "
	    "its details.</p></section>", ntn, kinds[LK_TUNNEL],
	    kinds[LK_P2P], kinds[LK_LAN]);
	if (kinds[LK_BGP] + kinds[LK_OSPF] + nexts > 0)
		h_fmt(h, "<section class=\"pane\"><h4>Routing</h4><div class=\""
		    "facts three\"><div><b>%d</b><span>BGP between hosts</span>"
		    "</div><div><b>%d</b><span>OSPF between hosts</span></div>"
		    "<div><b>%d</b><span>neighbours outside</span></div></div>"
		    "</section>", kinds[LK_BGP], kinds[LK_OSPF], nexts);
	/* Everything every host receives and sends, over time. */
	memset(&sum, 0, sizeof(sum));
	for (i = 0; i < nhosts; i++) {
		if (node_index(hosts[i].sid) == -1)
			continue;
		for (k = 0; k < hosts[i].nr; k++) {
			const struct ifrate *r = &hosts[i].r[k];

			if (strncmp(r->name, "lo", 2) == 0)
				continue;
			/* The newest readings line up; older ones may lack. */
			for (m = 0; m < r->n; m++) {
				sum.in[TOPO_HIST - r->n + m] += r->in[m];
				sum.out[TOPO_HIST - r->n + m] += r->out[m];
			}
			if (r->n > sum.n)
				sum.n = r->n;
		}
	}
	if (sum.n > 1) {
		memmove(sum.in, sum.in + TOPO_HIST - sum.n, sizeof(sum.in[0]) *
		    (size_t)sum.n);
		memmove(sum.out, sum.out + TOPO_HIST - sum.n,
		    sizeof(sum.out[0]) * (size_t)sum.n);
		fmt_rate(rate, sizeof(rate), sum.in[sum.n - 1]);
		h_raw(h, "<section class=\"pane\"><h4>Fleet traffic</h4><p "
		    "class=\"io-now\"><span class=\"in\">↓ ");
		h_txt(h, rate);
		fmt_rate(rate, sizeof(rate), sum.out[sum.n - 1]);
		h_raw(h, "</span> <span class=\"out\">↑ ");
		h_txt(h, rate);
		h_raw(h, "</span></p>");
		chart(h, &sum, 260, 70);
		h_raw(h, "</section>");
	}
	n = 0;
	for (i = 0; i < nhosts; i++) {
		if (node_index(hosts[i].sid) == -1)
			continue;
		for (k = 0; k < hosts[i].nr; k++) {
			if (strncmp(hosts[i].r[k].name, "lo", 2) == 0)
				continue;
			cur.t = &hosts[i];
			cur.r = &hosts[i].r[k];
			cur.v = rate_now(cur.t, cur.r->name);
			if (cur.v < 1)
				continue;
			/* Kept in order, the six largest. */
			if (n == 6 && top[5].v >= cur.v)
				continue;
			for (m = n < 6 ? n : 5; m > 0 && top[m - 1].v < cur.v;
			    m--)
				top[m] = top[m - 1];
			top[m] = cur;
			if (n < 6)
				n++;
		}
	}
	h_raw(h, "<section class=\"pane\"><h4>Busiest interfaces</h4>");
	if (n == 0)
		h_raw(h, "<p class=\"dim\">No traffic measured yet: it takes "
		    "two readings, a few seconds apart.</p>");
	max = n > 0 ? top[0].v : 1;
	h_raw(h, "<ul class=\"busy\">");
	for (i = 0; i < n; i++) {
		fmt_rate(rate, sizeof(rate), top[i].v);
		h_raw(h, "<li data-act=\"topo-sel-busy\"");
		h_attr(h, "data-arg", top[i].t->sid);
		h_attr(h, "data-value", top[i].r->name);
		h_raw(h, "><span class=\"who\">");
		h_txt(h, tn[node_index(top[i].t->sid)].label);
		h_raw(h, " <b>");
		h_txt(h, top[i].r->name);
		h_raw(h, "</b></span><span class=\"amount\">");
		h_txt(h, rate);
		h_fmt(h, "</span><i class=\"bar\" style=\"width:%.0f%%\"></i>"
		    "</li>", 100.0 * top[i].v / max);
	}
	h_raw(h, "</ul></section>");
}

void
view_netmap(struct html *h)
{
	struct tlink	*l;
	int		 i;

	nodes_build();
	places_fill();
	/* Fitted once, and again when a jail came or went as a node. */
	tp.vw = arc_map_w();
	tp.vh = arc_map_h();
	/* And when its room changed: a window resized, a phone turned. */
	if ((!tp.fitted || ((tp.fit_n != ntn || fabs(VIEW_W - tp.fit_w) > 24 ||
	    fabs(VIEW_H - tp.fit_h) > 24) && !tp.touched)) && ntn > 0) {
		tp.fitted = true;
		tp.fit_n = ntn;
		tp.fit_w = VIEW_W;
		tp.fit_h = VIEW_H;
		fit();
	}
	links_build();
	layout_follow();
	/* The first neighbours outside to show need room: once. */
	if (nexts > 0 && !tp.refitted) {
		tp.refitted = true;
		/* Not under the hand of who is moving things about. */
		if (!tp.touched)
			fit();
	}
	h_raw(h, "<div class=\"netmap\">");
	map(h);
	h_raw(h, "<aside class=\"map-panel\">");
	panel_path(h);
	l = NULL;
	for (i = 0; tp.sel_link[0] != '\0' && i < nlinks; i++)
		if (strcmp(links[i].key, tp.sel_link) == 0)
			l = &links[i];
	if (tp.sel[0] != '\0' && (i = node_index(tp.sel)) != -1)
		panel_host(h, i, thost(tn[i].key, false));
	else if (l != NULL)
		panel_link(h, l);
	else
		panel_overview(h);
	h_raw(h, "</aside></div>");
}

/*
 * The route from one host to an address, a host at a time: each is
 * asked which way it would send, and the host that has the gateway's
 * address is asked next, until the address is reached, the way leaves
 * the hosts of this console, or it comes back to where it was.
 */
struct tctx {
	int	gen;
	int	from;
};

static int
cmp_plen(const void *a, const void *b)
{

	return ((int)(jint(*(const ucl_object_t *const *)b, "prefixlen", 0) -
	    jint(*(const ucl_object_t *const *)a, "prefixlen", 0)));
}

/* The host a packet goes to next, by this gateway out of this interface. */
static int
next_host(int from, const char *gw, const char *ifn)
{
	const ucl_object_t	*o, *a;
	ucl_object_iter_t	 it, ait;
	struct thost		*t;
	unsigned char		 raw[16];
	int			 af, next;

	if (strncmp(gw, "link#", 5) != 0 && addr_bytes(gw, &af, raw) &&
	    (next = owner(gw, NULL, 0)) != from)
		return (next);
	/* Delivered on the interface: to the address's host, if ours. */
	if ((next = owner(path.to, NULL, 0)) != -1)
		return (next);
	/* Or into a tunnel, whose far end is where it comes out. */
	if ((t = thost(tn[from].key, false)) == NULL)
		return (-1);
	it = NULL;
	while ((o = ucl_object_iterate(jget(t->ifs, "interfaces"), &it,
	    true)) != NULL) {
		if (jstr(o, "name") == NULL || strcmp(jstr(o, "name"), ifn) != 0)
			continue;
		if (jstr(o, "tunnel.remote") != NULL && (next = owner(jstr(o,
		    "tunnel.remote"), NULL, 0)) != -1 && next != from)
			return (next);
		ait = NULL;
		while ((a = ucl_object_iterate(jget(o, "addresses"), &ait,
		    true)) != NULL)
			if (jstr(a, "destination") != NULL && (next = owner(
			    jstr(a, "destination"), NULL, 0)) != -1 && next !=
			    from)
				return (next);
	}
	return (-1);
}

static void
trace_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*data, *best, *c, *cand[64];
	ucl_object_iter_t	 it;
	struct tctx		*x;
	struct hop		*p;
	const char		*gw;
	int			 from, i, n;
	bool			 mine, found;

	x = arg;
	found = false;
	from = x->from;
	mine = x->gen == path.gen;
	free(x);
	if (!mine)
		return;
	if (status != 200 || !jbool(o, "ok") || (data = jget(o, "data")) ==
	    NULL) {
		snprintf(path.error, sizeof(path.error), "%s: %s",
		    tn[from].label, status == 200 && jstr(o, "error") !=
		    NULL ? jstr(o, "error") : err != NULL ? err : "no answer");
		path.busy = false;
		return;
	}
	p = &path.hops[path.n++];
	memset(p, 0, sizeof(*p));
	p->from = from;
	p->to = -1;
	n = 0;
	it = NULL;
	while ((c = ucl_object_iterate(jget(data, "candidates"), &it, true)) !=
	    NULL && n < 64)
		cand[n++] = c;
	qsort(cand, (size_t)n, sizeof(cand[0]), cmp_plen);
	best = jget(data, "best");
	gw = jstr(best, "gateway") != NULL ? jstr(best, "gateway") : "";
	if (best != NULL) {
		snprintf(p->gw, sizeof(p->gw), "%s", gw);
		snprintf(p->ifn, sizeof(p->ifn), "%s", jstr(best,
		    "interface") != NULL ? jstr(best, "interface") : "");
		snprintf(p->flags, sizeof(p->flags), "%s", jstr(best,
		    "flags") != NULL ? jstr(best, "flags") : "");
		snprintf(p->dest, sizeof(p->dest), "%s", jstr(best,
		    "destination") != NULL ? jstr(best, "destination") : "");
	}
	/* The most specific route by the same gateway is the one taken;
	 * the others are what would be taken in its place. */
	for (i = 0; i < n; i++) {
		const char *cg = jstr(cand[i], "gateway") != NULL ?
		    jstr(cand[i], "gateway") : "";

		if (best != NULL && !found && strcmp(cg, gw) == 0 &&
		    jstr(cand[i], "destination") != NULL) {
			snprintf(p->dest, sizeof(p->dest), "%s", jstr(cand[i],
			    "destination"));
			found = true;
			continue;
		}
		if (p->nalt == TOPO_ALTS)
			continue;
		snprintf(p->alt[p->nalt].dest, sizeof(p->alt[0].dest), "%s",
		    jstr(cand[i], "destination") != NULL ? jstr(cand[i],
		    "destination") : "?");
		snprintf(p->alt[p->nalt].gw, sizeof(p->alt[0].gw), "%s", cg);
		snprintf(p->alt[p->nalt].ifn, sizeof(p->alt[0].ifn), "%s",
		    jstr(cand[i], "interface-name") != NULL ? jstr(cand[i],
		    "interface-name") : "");
		p->alt[p->nalt].to = strncmp(cg, "link#", 5) != 0 ? owner(cg,
		    NULL, 0) : -1;
		if (p->alt[p->nalt].to == from)
			p->alt[p->nalt].to = -1;
		p->nalt++;
	}
	path.busy = false;
	if (best == NULL) {
		snprintf(p->note, sizeof(p->note), "no route to %s from here",
		    path.to);
		return;
	}
	if ((p->to = next_host(from, p->gw, p->ifn)) == -1) {
		snprintf(p->note, sizeof(p->note), "%s", strncmp(p->gw, "link#",
		    5) == 0 ? "sent out on the interface: the address is not "
		    "on a host of this console" : "the gateway is not a host "
		    "of this console: the route leaves the fleet here");
		path.done = true;
		return;
	}
	for (i = 0; i < path.n; i++)
		if (path.hops[i].from == p->to) {
			snprintf(p->note, sizeof(p->note), "a loop: %s was "
			    "passed already", tn[p->to].label);
			return;
		}
	trace_next(p->to, NULL);
}

static void
trace_next(int from, const char *unused)
{
	struct tctx	*x;
	char		 url[400], to[80];

	(void)unused;
	if (owner(path.to, NULL, 0) == from) {
		path.done = true;
		path.busy = false;
		return;
	}
	if (path.n == TOPO_HOPS) {
		snprintf(path.error, sizeof(path.error), "more than %d hosts "
		    "on the way: given up", TOPO_HOPS);
		path.busy = false;
		return;
	}
	if ((x = calloc(1, sizeof(*x))) == NULL)
		abort();
	x->gen = path.gen;
	x->from = from;
	path.busy = true;
	snprintf(to, sizeof(to), "to=%s", path.to);
	node_url(from, "lookup", to, url, sizeof(url));
	api("GET", url, NULL, trace_cb, x);
}

static void
trace_start(void)
{
	unsigned char	raw[16];
	const char	*a;
	int		from, to, af;

	path.n = 0;
	path.done = false;
	path.error[0] = '\0';
	path.gen++;
	if (path.from[0] == '\0' && ntn > 0)
		snprintf(path.from, sizeof(path.from), "%s", tn[0].key);
	if ((from = node_index(path.from)) == -1) {
		snprintf(path.error, sizeof(path.error), "Pick the host to "
		    "start from");
		return;
	}
	if (path.to[0] == '\0' && (to = node_index(path.to_name)) != -1 &&
	    (a = primary_addr(thost(tn[to].key, false), 0)) != NULL)
		snprintf(path.to, sizeof(path.to), "%.*s", (int)strcspn(a, "%"),
		    a);
	if (!addr_bytes(path.to, &af, raw) || strchr(path.to, '%') != NULL) {
		snprintf(path.error, sizeof(path.error), "Pick the host to "
		    "reach, or give an IPv4 or IPv6 address");
		return;
	}
	if (owner(path.to, NULL, 0) == from) {
		snprintf(path.error, sizeof(path.error), "%s is an address of "
		    "%s itself", path.to, tn[from].label);
		return;
	}
	trace_next(from, NULL);
}

/* The next free unit of a kind of interface on a host: gif0, gif1. */
static int
next_unit(struct thost *t, const char *type)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	const char		*name;
	size_t			 len;
	int			 max;

	max = -1;
	len = strlen(type);
	it = NULL;
	while (t != NULL && (o = ucl_object_iterate(jget(t->ifs, "interfaces"),
	    &it, true)) != NULL)
		if ((name = jstr(o, "name")) != NULL && strncmp(name, type,
		    len) == 0 && name[len] >= '0' && name[len] <= '9' &&
		    atoi(name + len) > max)
			max = atoi(name + len);
	return (max + 1);
}

/* What a tunnel between two hosts could be: offered, to be changed. */
static struct {
	char	oa[64], ob[64];		/* outer ends */
	char	ia[64], ib[64];		/* inner ends, with prefix length */
} offer;

static bool
net_used(const char *prefix)
{
	const ucl_object_t	*o, *a;
	ucl_object_iter_t	 it, ait;
	int			 i;

	for (i = 0; i < nhosts; i++) {
		it = NULL;
		while ((o = ucl_object_iterate(jget(hosts[i].ifs, "interfaces"),
		    &it, true)) != NULL) {
			ait = NULL;
			while ((a = ucl_object_iterate(jget(o, "addresses"),
			    &ait, true)) != NULL)
				if (jstr(a, "address") != NULL && strncmp(jstr(a,
				    "address"), prefix, strlen(prefix)) == 0)
					return (true);
		}
	}
	return (false);
}

static void
tunnel_offer(struct thost *ta, struct thost *tb)
{
	const ucl_object_t	*o, *a, *o2, *a2;
	ucl_object_iter_t	 it, ait, it2, ait2;
	const char		*x, *y;
	unsigned char		 raw[16];
	char			 na[64], nb[64], prefix[24];
	int			 n, pass, af;

	memset(&offer, 0, sizeof(offer));
	/*
	 * Two addresses in one network are how they reach each other:
	 * IPv4 ones when there are, IPv6 ones otherwise.
	 */
	for (pass = 0; pass < 2 && offer.oa[0] == '\0'; pass++) {
	it = NULL;
	while (offer.oa[0] == '\0' && (o = ucl_object_iterate(jget(ta->ifs,
	    "interfaces"), &it, true)) != NULL) {
		ait = NULL;
		while (if_joins(o) && offer.oa[0] == '\0' && (a =
		    ucl_object_iterate(jget(o, "addresses"), &ait, true)) !=
		    NULL) {
			if (jstr(a, "address") == NULL || addr_local(jstr(a,
			    "address")) || !addr_bytes(jstr(a, "address"), &af,
			    raw) || af != (pass == 0 ? AF_INET : AF_INET6) ||
			    !net_of(jstr(a, "address"), (int)jint(a,
			    "prefixlen", 0), na, sizeof(na)))
				continue;
			it2 = NULL;
			while (offer.oa[0] == '\0' && (o2 = ucl_object_iterate(
			    jget(tb->ifs, "interfaces"), &it2, true)) != NULL) {
				ait2 = NULL;
				while ((a2 = ucl_object_iterate(jget(o2,
				    "addresses"), &ait2, true)) != NULL)
					if (jstr(a2, "address") != NULL &&
					    net_of(jstr(a2, "address"),
					    (int)jint(a2, "prefixlen", 0), nb,
					    sizeof(nb)) && strcmp(na, nb) ==
					    0) {
						snprintf(offer.oa,
						    sizeof(offer.oa), "%s",
						    jstr(a, "address"));
						snprintf(offer.ob,
						    sizeof(offer.ob), "%s",
						    jstr(a2, "address"));
						break;
					}
			}
		}
	}
	}
	if (offer.oa[0] == '\0') {
		x = primary_addr(ta, AF_INET);
		y = primary_addr(tb, AF_INET);
		if (x == NULL || y == NULL) {
			x = primary_addr(ta, AF_INET6);
			y = primary_addr(tb, AF_INET6);
		}
		if (x != NULL && y != NULL) {
			snprintf(offer.oa, sizeof(offer.oa), "%s", x);
			snprintf(offer.ob, sizeof(offer.ob), "%s", y);
		}
	}
	/* Inside: the first /30 of 10.255.0.0/16 no host has yet. */
	for (n = 0; n < 256; n++) {
		snprintf(prefix, sizeof(prefix), "10.255.%d.", n);
		if (!net_used(prefix))
			break;
	}
	snprintf(offer.ia, sizeof(offer.ia), "10.255.%d.1/30", n & 255);
	snprintf(offer.ib, sizeof(offer.ib), "10.255.%d.2/30", n & 255);
}

/* The addresses of a host as the options of a select. */
static void
addr_options(struct html *h, struct thost *t, const char *chosen)
{
	const ucl_object_t	*o, *a;
	ucl_object_iter_t	 it, ait;

	it = NULL;
	while (t != NULL && (o = ucl_object_iterate(jget(t->ifs, "interfaces"),
	    &it, true)) != NULL) {
		ait = NULL;
		while (if_joins(o) && (a = ucl_object_iterate(jget(o,
		    "addresses"), &ait, true)) != NULL) {
			if (jstr(a, "address") == NULL || addr_local(jstr(a,
			    "address")))
				continue;
			h_raw(h, "<option");
			h_attr(h, "value", jstr(a, "address"));
			if (strcmp(jstr(a, "address"), chosen) == 0)
				h_raw(h, " selected");
			h_raw(h, ">");
			h_txt(h, jstr(a, "address"));
			h_raw(h, " (");
			h_txt(h, jstr(o, "name"));
			h_raw(h, ")</option>");
		}
	}
}

/*
 * The kinds of interface the host clones, and what each takes in the
 * form: a tunnel its two ends, an ipsec one a reqid, a VXLAN its
 * identifier, a VLAN its tag and parent, a bridge a first member, most
 * an address.
 */
#define	IFK_TUNNEL	1
#define	IFK_REQID	2
#define	IFK_VNI		4
#define	IFK_VLAN	8
#define	IFK_MEMBER	16
#define	IFK_ADDRESS	32
static const struct {
	const char	*kind, *label;
	int		 has;
} if_kinds[] = {
	{ "epair", "epair: a pair of ends, one for a vnet jail", IFK_ADDRESS },
	{ "gif", "gif: IP in IP tunnel", IFK_TUNNEL | IFK_ADDRESS },
	{ "gre", "gre: GRE tunnel", IFK_TUNNEL | IFK_ADDRESS },
	{ "ipsec", "ipsec: if_ipsec(4) tunnel", IFK_TUNNEL | IFK_REQID |
	    IFK_ADDRESS },
	{ "me", "me: minimal encapsulation tunnel", IFK_TUNNEL | IFK_ADDRESS },
	{ "vxlan", "vxlan: VXLAN", IFK_TUNNEL | IFK_VNI | IFK_ADDRESS },
	{ "vlan", "vlan: an 802.1Q VLAN on an interface", IFK_VLAN |
	    IFK_ADDRESS },
	{ "bridge", "bridge: if_bridge(4)", IFK_MEMBER | IFK_ADDRESS },
	{ "lagg", "lagg: link aggregation", IFK_ADDRESS },
	{ "tap", "tap: a layer 2 tunnel device", IFK_ADDRESS },
	{ "tun", "tun: a layer 3 tunnel device", IFK_ADDRESS },
	{ "lo", "lo: another loopback", IFK_ADDRESS },
	{ "wg", "wg: WireGuard", IFK_ADDRESS },
	{ "ovpn", "ovpn: OpenVPN DCO", IFK_ADDRESS },
};

static const char *
if_kind_of(const char *kind)
{
	size_t	i;

	for (i = 0; kind != NULL && i < (sizeof(if_kinds) / sizeof(if_kinds[0])); i++)
		if (strcmp(if_kinds[i].kind, kind) == 0)
			return (if_kinds[i].kind);
	return (NULL);
}

static bool
if_kind_has(const char *kind, int what)
{
	size_t	i;

	for (i = 0; kind != NULL && i < (sizeof(if_kinds) / sizeof(if_kinds[0])); i++)
		if (strcmp(if_kinds[i].kind, kind) == 0)
			return ((if_kinds[i].has & what) == what);
	return (false);
}

/* The interface form opened for a host, a kind chosen; another part's
 * (the WireGuard tab's) way in. */
void
topo_if_create_open(const char *sid, const char *kind)
{

	snprintf(tp.create_sid, sizeof(tp.create_sid), "%s", sid);
	snprintf(tp.create_kind, sizeof(tp.create_kind), "%s", if_kind_of(kind)
	    != NULL ? kind : "epair");
	app.modal = MODAL_IF_CREATE;
	app.modal_error[0] = '\0';
}

/*
 * A way two hosts reach each other, for a routing session between them:
 * a tunnel or a point-to-point link the map has between them (their
 * inner addresses), else a network both have an address in.
 */
#define	JOIN_OVER	8
struct over {
	char	ifa[16], ifb[16];
	char	aa[64], ab[64];		/* the addresses, without a length */
	bool	ptp;
	char	label[160];
};

/* An interface's first address of a family, not link-local. */
static bool
if_addr(const struct thost *t, const char *ifn, int af, char *buf,
    size_t len)
{
	const ucl_object_t	*a;
	ucl_object_iter_t	 it;
	unsigned char		 raw[16];
	int			 f;

	it = NULL;
	while ((a = ucl_object_iterate(jget(if_named(t, ifn), "addresses"), &it,
	    true)) != NULL)
		if (jstr(a, "address") != NULL && !addr_local(jstr(a,
		    "address")) && addr_bytes(jstr(a, "address"), &f, raw) &&
		    f == af) {
			snprintf(buf, len, "%s", jstr(a, "address"));
			return (true);
		}
	return (false);
}

static int
join_over(int a, int b, struct over *v, int max)
{
	const ucl_object_t	*o, *x, *o2, *x2;
	ucl_object_iter_t	 it, xit, it2, xit2;
	struct thost		*ta, *tb;
	const struct tlink	*l;
	unsigned char		 raw[16];
	char			 na[64], nb[64];
	int			 i, n, af, k;
	bool			 fwd;

	if ((ta = thost(tn[a].key, false)) == NULL || (tb = thost(tn[b].key,
	    false)) == NULL)
		return (0);
	n = 0;
	for (i = 0; i < nlinks && n < max; i++) {
		l = &links[i];
		if ((l->kind != LK_TUNNEL && l->kind != LK_P2P) || l->b < 0 ||
		    !((l->a == a && l->b == b) || (l->a == b && l->b == a)))
			continue;
		fwd = l->a == a;
		for (k = 0; k < 2 && n < max; k++) {
			af = k == 0 ? AF_INET : AF_INET6;
			memset(&v[n], 0, sizeof(v[n]));
			snprintf(v[n].ifa, sizeof(v[n].ifa), "%s", fwd ? l->ifa :
			    l->ifb);
			snprintf(v[n].ifb, sizeof(v[n].ifb), "%s", fwd ? l->ifb :
			    l->ifa);
			if (!if_addr(ta, v[n].ifa, af, v[n].aa, sizeof(v[n].aa)) ||
			    !if_addr(tb, v[n].ifb, af, v[n].ab, sizeof(v[n].ab)))
				continue;
			v[n].ptp = true;
			snprintf(v[n].label, sizeof(v[n].label), "%s %s and %s %s "
			    "(the %s)", v[n].ifa, v[n].aa, v[n].ifb, v[n].ab,
			    l->kind == LK_TUNNEL ? "tunnel" : "link");
			n++;
		}
	}
	/* The networks both are in. */
	it = NULL;
	while (n < max && (o = ucl_object_iterate(jget(ta->ifs, "interfaces"),
	    &it, true)) != NULL) {
		xit = NULL;
		while (n < max && if_joins(o) && (x = ucl_object_iterate(jget(o,
		    "addresses"), &xit, true)) != NULL) {
			if (jstr(x, "address") == NULL || addr_local(jstr(x,
			    "address")) || !addr_bytes(jstr(x, "address"), &af,
			    raw) || !net_of(jstr(x, "address"), (int)jint(x,
			    "prefixlen", 0), na, sizeof(na)))
				continue;
			it2 = NULL;
			while (n < max && (o2 = ucl_object_iterate(jget(tb->ifs,
			    "interfaces"), &it2, true)) != NULL) {
				xit2 = NULL;
				while ((x2 = ucl_object_iterate(jget(o2,
				    "addresses"), &xit2, true)) != NULL) {
					if (jstr(x2, "address") == NULL ||
					    !net_of(jstr(x2, "address"), (int)jint(
					    x2, "prefixlen", 0), nb, sizeof(nb)) ||
					    strcmp(na, nb) != 0)
						continue;
					/* A tunnel's own network is above. */
					for (k = 0; k < n; k++)
						if (strcmp(v[k].aa, jstr(x,
						    "address")) == 0)
							break;
					if (k < n)
						break;
					memset(&v[n], 0, sizeof(v[n]));
					snprintf(v[n].ifa, sizeof(v[n].ifa), "%s",
					    jstr(o, "name"));
					snprintf(v[n].ifb, sizeof(v[n].ifb), "%s",
					    jstr(o2, "name"));
					snprintf(v[n].aa, sizeof(v[n].aa), "%s",
					    jstr(x, "address"));
					snprintf(v[n].ab, sizeof(v[n].ab), "%s",
					    jstr(x2, "address"));
					snprintf(v[n].label, sizeof(v[n].label),
					    "%s %s and %s %s (%s)", v[n].ifa,
					    v[n].aa, v[n].ifb, v[n].ab, na);
					n++;
					break;
				}
			}
		}
	}
	return (n);
}

/* A host's own AS, as its BIRD's BGP sessions say it, or "". */
static const char *
node_as(int n)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	struct thost		*t;

	if ((t = thost(tn[n].key, false)) == NULL)
		return ("");
	it = NULL;
	while ((o = ucl_object_iterate(jget(t->bird, "status"), &it, true)) !=
	    NULL)
		if (jstr(o, "proto") != NULL && strcmp(jstr(o, "proto"),
		    "BGP") == 0 && jstr(o, "local-as") != NULL)
			return (jstr(o, "local-as"));
	return ("");
}

/* Letters, digits and _ of a name, for a protocol's. */
static void
proto_name(char *buf, size_t len, const char *prefix, const char *name)
{
	size_t	o;

	o = (size_t)snprintf(buf, len, "%s", prefix);
	for (; *name != '\0' && o + 1 < len && o < 40; name++)
		buf[o++] = isalnum((unsigned char)*name) ? *name : '_';
	buf[o < len ? o : len - 1] = '\0';
}

/* What a line between two hosts makes, picked at the dialog's top. */
static void
join_kinds_nav(struct html *h)
{
	static const char *const titles[] = { "A tunnel", "A BGP session",
	    "An OSPF adjacency", "BFD" };
	size_t	i;

	h_raw(h, "<nav class=\"sub join-kinds\" aria-label=\"What joins "
	    "them\">");
	for (i = 0; i < nitems(titles); i++)
		h_fmt(h, "<button type=\"button\" class=\"ghost small%s\" "
		    "data-act=\"topo-join\" data-arg=\"%s\">%s</button>",
		    (int)i == tp.join ? " on" : "", join_kinds[i], titles[i]);
	h_raw(h, "</nav>");
}

/* A routing session between two hosts: what it goes over, and its own. */
static void
join_form(struct html *h, int a, int b)
{
	struct over	v[JOIN_OVER];
	int		i, n;

	n = join_over(a, b, v, JOIN_OVER);
	h_raw(h, "<form data-form=\"join\"><h2>Join ");
	h_txt(h, tn[a].label);
	h_raw(h, " and ");
	h_txt(h, tn[b].label);
	h_raw(h, "</h2>");
	join_kinds_nav(h);
	h_raw(h, "<p>Written into each host's BIRD, one end at a time: ");
	h_txt(h, tn[a].label);
	h_raw(h, "'s BIRD opens with the protocol filled in, to be looked at "
	    "and saved; BIRD takes a change back by itself unless this page "
	    "still reaches the host after it. Then ");
	h_txt(h, tn[b].label);
	h_raw(h, "'s is offered, filled in the same way.</p>");
	if (n == 0) {
		h_raw(h, "<p class=\"notice warn\">The two have no tunnel and "
		    "no network between them that this page knows of: draw a "
		    "tunnel first.</p>");
		return;
	}
	h_raw(h, "<label>Over<select name=\"over\">");
	for (i = 0; i < n; i++) {
		h_fmt(h, "<option value=\"%d\">", i);
		h_txt(h, v[i].label);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select><small>A session between the hosts' addresses on "
	    "it; OSPF and BFD on its interfaces.</small></label>");
	if (tp.join == JOIN_BGP) {
		h_raw(h, "<div class=\"two\"><label>AS of ");
		h_txt(h, tn[a].label);
		h_raw(h, "<input name=\"as_a\" inputmode=\"numeric\" "
		    "required");
		h_attr(h, "value", node_as(a));
		h_raw(h, "></label><label>AS of ");
		h_txt(h, tn[b].label);
		h_raw(h, "<input name=\"as_b\" inputmode=\"numeric\" "
		    "required");
		h_attr(h, "value", node_as(b));
		h_raw(h, "></label></div><small>As each host's BIRD says it "
		    "in a BGP session it has; the same for iBGP.</small>");
	}
	if (tp.join == JOIN_OSPF)
		h_raw(h, "<p class=\"dim\">Area 0, on the interface of each "
		    "end, added to the OSPF instance of that family the host "
		    "runs, else in a new one.</p>");
	if (tp.join != JOIN_BFD)
		h_raw(h, "<label class=\"toggle\"><input type=\"checkbox\" "
		    "name=\"bfd\" checked><span>With BFD, so that a failure "
		    "is seen in under a second; BIRD's BFD protocol is needed "
		    "on both ends</span></label>");
}

/* The session's two ends as forms: this one's opened, the other's next. */
static void
join_create(const ucl_object_t *f)
{
	struct over	 v[JOIN_OVER];
	struct bfsess	 sa, sb;
	const char	*as_a, *as_b;
	int		 a, b, n, i;

	if ((a = node_index(tp.tun_a)) == -1 || (b = node_index(
	    tp.tun_b)) == -1)
		return;
	n = join_over(a, b, v, JOIN_OVER);
	i = jstr(f, "over") != NULL ? atoi(jstr(f, "over")) : 0;
	if (i < 0 || i >= n) {
		snprintf(app.modal_error, sizeof(app.modal_error), "Pick what "
		    "the session goes over.");
		return;
	}
	as_a = jstr(f, "as_a") != NULL ? jstr(f, "as_a") : "";
	as_b = jstr(f, "as_b") != NULL ? jstr(f, "as_b") : "";
	if (tp.join == JOIN_BGP && (as_a[0] == '\0' || as_b[0] == '\0' ||
	    as_a[strspn(as_a, "0123456789")] != '\0' || as_b[strspn(as_b,
	    "0123456789")] != '\0')) {
		snprintf(app.modal_error, sizeof(app.modal_error), "An AS for "
		    "each end, a number: 64512");
		return;
	}
	memset(&sa, 0, sizeof(sa));
	snprintf(sa.kind, sizeof(sa.kind), "%s", join_kinds[tp.join]);
	sa.bfd = tp.join == JOIN_BFD || jbool(f, "bfd");
	sb = sa;
	/* BGP: a protocol named for the far end; OSPF and BFD: the
	 * instance's name, when one is made. */
	if (tp.join == JOIN_BGP) {
		proto_name(sa.name, sizeof(sa.name), "to_", tn[b].name);
		proto_name(sb.name, sizeof(sb.name), "to_", tn[a].name);
		snprintf(sa.desc, sizeof(sa.desc), "%.80s, drawn on the map",
		    tn[b].label);
		snprintf(sb.desc, sizeof(sb.desc), "%.80s, drawn on the map",
		    tn[a].label);
		snprintf(sa.las, sizeof(sa.las), "%s", as_a);
		snprintf(sa.nas, sizeof(sa.nas), "%s", as_b);
		snprintf(sb.las, sizeof(sb.las), "%s", as_b);
		snprintf(sb.nas, sizeof(sb.nas), "%s", as_a);
	} else {
		snprintf(sa.name, sizeof(sa.name), "%s", tp.join == JOIN_OSPF ?
		    (strchr(v[i].aa, ':') != NULL ? "ospf6" : "ospf4") : "bfd1");
		snprintf(sb.name, sizeof(sb.name), "%s", sa.name);
	}
	snprintf(sa.nbr, sizeof(sa.nbr), "%s", v[i].ab);
	snprintf(sa.src, sizeof(sa.src), "%s", v[i].aa);
	snprintf(sa.ifname, sizeof(sa.ifname), "%s", v[i].ifa);
	snprintf(sb.nbr, sizeof(sb.nbr), "%s", v[i].aa);
	snprintf(sb.src, sizeof(sb.src), "%s", v[i].ab);
	snprintf(sb.ifname, sizeof(sb.ifname), "%s", v[i].ifb);
	sa.ptp = sb.ptp = v[i].ptp;
	bird_session(app.servers[tn[a].srv].id, tn[a].jail, &sa, tn[b].key,
	    tn[b].label, &sb);
	node_open(a, NET_BIRD);
}

/* The other end of a session, from BIRD's page: its node's BIRD, filled
 * in. */
void
topo_bird_session(const char *key, const char *label, const struct bfsess *s)
{
	int	n;

	nodes_build();
	if ((n = node_index(key)) == -1) {
		toast(true, "%s is not on the map any longer", label);
		return;
	}
	bird_session(app.servers[tn[n].srv].id, tn[n].jail, s, NULL, NULL,
	    NULL);
	node_open(n, NET_BIRD);
}

/* Whether the line drawn is to make a routing session, not a tunnel. */
bool
topo_joining(void)
{

	return (app.modal == MODAL_TUNNEL && tp.join != JOIN_TUNNEL);
}

/* The tunnel dialog's fields as they are now: its plan is drawn from
 * them as they are typed. */
static struct {
	char	type[8];
	char	la[64], lb[64], ia[64], ib[64];
	char	mtu[8], vni[12];
	bool	keep;
} tunf;

static void
tunf_set(const char *arg, const char *v)
{
	static const struct {
		const char	*name;
		size_t		 off, len;
	} f[] = {
		{ "type", offsetof(__typeof__(tunf), type), sizeof(tunf.type) },
		{ "local_a", offsetof(__typeof__(tunf), la), sizeof(tunf.la) },
		{ "local_b", offsetof(__typeof__(tunf), lb), sizeof(tunf.lb) },
		{ "inner_a", offsetof(__typeof__(tunf), ia), sizeof(tunf.ia) },
		{ "inner_b", offsetof(__typeof__(tunf), ib), sizeof(tunf.ib) },
		{ "mtu", offsetof(__typeof__(tunf), mtu), sizeof(tunf.mtu) },
		{ "vni", offsetof(__typeof__(tunf), vni), sizeof(tunf.vni) },
	};
	size_t	i;

	if (strcmp(arg, "persist") == 0) {
		tunf.keep = strcmp(v, "true") == 0;
		return;
	}
	for (i = 0; i < nitems(f); i++)
		if (strcmp(arg, f[i].name) == 0)
			snprintf((char *)&tunf + f[i].off, f[i].len, "%s", v);
}

/* A line of the plan: a command as the host runs it. */
static void
plan_line(struct html *h, const char *fmt, ...)
{
	char	buf[400];
	va_list	ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	h_raw(h, "<li><code>");
	h_txt(h, buf);
	h_raw(h, "</code></li>");
}

/*
 * What each end of the tunnel is to run, from the fields as they are:
 * the commands in FreeBSD's own words, as the agent's jobs do them, so
 * that what is drawn is seen before it is made.
 */
static void
tunnel_plan(struct html *h, int a, int b)
{
	const char	*la, *lb, *ia, *ib;
	char		 n[2][16], peer[2][64];
	int		 e, nd;
	bool		 wg, vx;

	wg = strcmp(tunf.type, "wg") == 0;
	vx = strcmp(tunf.type, "vxlan") == 0;
	for (e = 0; e < 2; e++) {
		nd = e == 0 ? a : b;
		snprintf(n[e], sizeof(n[e]), "%s%d", tunf.type, next_unit(
		    thost(tn[nd].key, false), tunf.type));
		snprintf(peer[e], sizeof(peer[e]), "%.*s", (int)strcspn(e == 0 ?
		    tunf.ib : tunf.ia, "/"), e == 0 ? tunf.ib : tunf.ia);
	}
	h_raw(h, "<section class=\"tun-plan\"><h3>What each host is to "
	    "run</h3><div class=\"two\">");
	for (e = 0; e < 2; e++) {
		la = e == 0 ? tunf.la : tunf.lb;
		lb = e == 0 ? tunf.lb : tunf.la;
		ia = e == 0 ? tunf.ia : tunf.ib;
		ib = e == 0 ? tunf.ib : tunf.ia;
		h_raw(h, "<div><b>");
		h_txt(h, tn[e == 0 ? a : b].label);
		h_raw(h, "</b><ol class=\"mono\">");
		plan_line(h, "ifconfig %s create", n[e]);
		if (wg) {
			plan_line(h, "wg genkey > its key, kept on the host");
			plan_line(h, "wg set %s listen-port 51820", n[e]);
			if (ia[0] != '\0')
				plan_line(h, "ifconfig %s inet%s %s", n[e],
				    strchr(ia, ':') != NULL ? "6" : "", ia);
			plan_line(h, "wg set %s peer <%s's public key> endpoint "
			    "%s%s%s:51820 allowed-ips %s", n[e], tn[e == 0 ? b :
			    a].label, strchr(lb, ':') != NULL ? "[" : "", lb,
			    strchr(lb, ':') != NULL ? "]" : "", ib[0] != '\0' ?
			    peer[e] : "0.0.0.0/0");
		} else if (vx) {
			plan_line(h, "ifconfig %s vxlanid %s vxlanlocal %s "
			    "vxlanremote %s", n[e], tunf.vni[0] != '\0' ?
			    tunf.vni : "<id>", la, lb);
			if (ia[0] != '\0')
				plan_line(h, "ifconfig %s inet%s %s", n[e],
				    strchr(ia, ':') != NULL ? "6" : "", ia);
		} else {
			plan_line(h, "ifconfig %s tunnel %s %s", n[e], la, lb);
			if (ia[0] != '\0')
				plan_line(h, "ifconfig %s inet%s %s %s", n[e],
				    strchr(ia, ':') != NULL ? "6" : "", ia, peer[e]);
		}
		if (tunf.mtu[0] != '\0')
			plan_line(h, "ifconfig %s mtu %s", n[e], tunf.mtu);
		plan_line(h, "ifconfig %s up", n[e]);
		if (tunf.keep)
			plan_line(h, "sysrc cloned_interfaces+=%s ifconfig_%s=…",
			    n[e], n[e]);
		h_raw(h, "</ol></div>");
	}
	h_raw(h, "</div><small>In safe mode: a host that cannot be reached "
	    "after its end is made takes it away by itself.</small>"
	    "</section>");
}

static const char keep_field[] = "<label class=\"toggle\"><input type=\""
    "checkbox\" name=\"persist\" checked><span>Keep it in <code>rc.conf"
    "</code>, to be there after a boot</span></label>";

/* The dialogs of the network: true when the one open is one of them. */
bool
topo_modal(struct html *h)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	struct thost		*ht;
	struct server		*s;
	unsigned int		 mtu;
	int			 a, b;

	switch (app.modal) {
	case MODAL_TUNNEL:
		if ((a = node_index(tp.tun_a)) == -1 || (b = node_index(
		    tp.tun_b)) == -1)
			return (false);
		if (tp.join != JOIN_TUNNEL) {
			join_form(h, a, b);
			return (true);
		}
		h_raw(h, "<form data-form=\"tunnel\"><h2>Join ");
		h_txt(h, tn[a].label);
		h_raw(h, " and ");
		h_txt(h, tn[b].label);
		h_raw(h, "</h2>");
		join_kinds_nav(h);
		h_raw(h, "<p>An interface is created on each host, the "
		    "two ends of one tunnel, with <code>ifconfig</code>. Each "
		    "is made in safe mode: a host that cannot be reached "
		    "again afterwards destroys its end by itself. For "
		    "WireGuard each host makes its own key and keeps it; the "
		    "two are told of each other by their public keys once "
		    "both have one.</p>"
		    "<label>Kind<select name=\"type\" data-input=\"topo-tunf\" "
		    "data-arg=\"type\">");
		{
			static const char *const kinds[][2] = { { "gif",
			    "gif: IP in IP" }, { "gre", "gre" }, { "wg",
			    "wg: WireGuard, encrypted" }, { "vxlan",
			    "vxlan: Ethernet over UDP" } };
			size_t	k;

			for (k = 0; k < nitems(kinds); k++)
				h_fmt(h, "<option value=\"%s\"%s>%s</option>",
				    kinds[k][0], strcmp(tunf.type, kinds[k][0]) ==
				    0 ? " selected" : "", kinds[k][1]);
		}
		h_raw(h, "</select></label><div class=\"two\"><label>Outer "
		    "address of ");
		h_txt(h, tn[a].label);
		h_raw(h, "<select name=\"local_a\" data-input=\"topo-tunf\" "
		    "data-arg=\"local_a\">");
		addr_options(h, thost(tp.tun_a, false), tunf.la);
		h_raw(h, "</select></label><label>Outer address of ");
		h_txt(h, tn[b].label);
		h_raw(h, "<select name=\"local_b\" data-input=\"topo-tunf\" "
		    "data-arg=\"local_b\">");
		addr_options(h, thost(tp.tun_b, false), tunf.lb);
		h_raw(h, "</select></label></div><div class=\"two\"><label>"
		    "Inner address of ");
		h_txt(h, tn[a].label);
		h_raw(h, "<input name=\"inner_a\" spellcheck=\"false\" "
		    "autocomplete=\"off\" data-input=\"topo-tunf\" "
		    "data-arg=\"inner_a\"");
		h_attr(h, "value", offer.ia);
		h_raw(h, "></label><label>Inner address of ");
		h_txt(h, tn[b].label);
		h_raw(h, "<input name=\"inner_b\" spellcheck=\"false\" "
		    "autocomplete=\"off\" data-input=\"topo-tunf\" "
		    "data-arg=\"inner_b\"");
		h_attr(h, "value", offer.ib);
		h_raw(h, "></label></div><small>With their prefix length; "
		    "leave both empty for a tunnel without addresses.</small>"
		    "<div class=\"two\"><label>MTU<input name=\"mtu\" "
		    "inputmode=\"numeric\" placeholder=\"as the kernel sets "
		    "it\" data-input=\"topo-tunf\" data-arg=\"mtu\"></label><label>"
		    "VXLAN identifier<input name=\"vni\" inputmode=\"numeric\" "
		    "placeholder=\"for vxlan only\" data-input=\"topo-tunf\" "
		    "data-arg=\"vni\"></label></div>");
		h_raw(h, "<label class=\"toggle\"><input type=\"checkbox\" "
		    "name=\"persist\" data-input=\"topo-tunf\" data-arg=\"persist\"");
		h_raw(h, tunf.keep ? " checked" : "");
		h_raw(h, "><span>Keep it in <code>rc.conf</code>, to be there "
		    "after a boot</span></label>");
		tunnel_plan(h, a, b);
		return (true);
	case MODAL_IF_VNET:
		if ((s = cur_server()) == NULL || net_scope()[0] == '\0')
			return (false);
		h_raw(h, "<form data-form=\"if-vnet\"><h2>Give ");
		h_txt(h, net_scope());
		h_raw(h, " an interface</h2><p>From its host, ");
		h_txt(h, s->name);
		h_raw(h, ", with <code>ifconfig vnet</code>: the interface "
		    "leaves the host and is the jail's until it is taken "
		    "back, or the jail stops.</p><label>Interface<select name="
		    "\"interface\"><option value=\"\">a new epair, made for "
		    "it</option>");
		ht = thost(s->id, false);
		it = NULL;
		while (ht != NULL && (o = ucl_object_iterate(jget(ht->ifs,
		    "interfaces"), &it, true)) != NULL) {
			if (jstr(o, "name") == NULL || strncmp(jstr(o, "name"),
			    "lo", 2) == 0)
				continue;
			h_raw(h, "<option");
			h_attr(h, "value", jstr(o, "name"));
			h_raw(h, ">");
			h_txt(h, jstr(o, "name"));
			if (jstr(o, "description") != NULL) {
				h_raw(h, " · ");
				h_txt(h, jstr(o, "description"));
			}
			h_raw(h, "</option>");
		}
		h_raw(h, "</select><small>Of a new pair the <b>a</b> end stays "
		    "on the host and the <b>b</b> end goes to the jail. An "
		    "interface the host has leaves it; the host refuses to "
		    "give the one the console reaches it by.</small></label>"
		    "<label>The pair's end on the host<select name=\"bridge\">"
		    "<option value=\"\">left as it is made</option>");
		it = NULL;
		while (ht != NULL && (o = ucl_object_iterate(jget(ht->ifs,
		    "interfaces"), &it, true)) != NULL) {
			if (jstr(o, "name") == NULL || strncmp(jstr(o, "name"),
			    "bridge", 6) != 0)
				continue;
			h_raw(h, "<option");
			h_attr(h, "value", jstr(o, "name"));
			h_raw(h, ">a member of ");
			h_txt(h, jstr(o, "name"));
			h_raw(h, "</option>");
		}
		h_raw(h, "</select><small>For a new pair only: in a bridge of "
		    "the host it reaches what the bridge reaches.</small>"
		    "</label>");
		if (jstr(find_jail(s, net_scope()), "scope") != NULL)
			h_raw(h, "<label class=\"toggle\"><input type=\""
			    "checkbox\" name=\"persist\" checked><span>Keep it: "
			    "as the jail's <code>vnet.interface</code> in "
			    "<code>jail.conf</code>, and a new pair in the "
			    "host's <code>rc.conf</code></span></label>");
		return (true);
	case MODAL_IF_CREATE:
		if ((a = node_index(tp.create_sid)) == -1)
			return (false);
		h_raw(h, "<form data-form=\"if-create\"><h2>Create an "
		    "interface on ");
		h_txt(h, tn[a].label);
		h_raw(h, "</h2><p>A cloned interface, with <code>ifconfig "
		    "create</code>; what cannot be finished is destroyed "
		    "again.</p><div class=\"two\"><label>Kind<select name=\""
		    "kind\" data-input=\"topo-if-kind\">");
		for (size_t ki = 0; ki < (sizeof(if_kinds) / sizeof(if_kinds[0])); ki++) {
			h_raw(h, "<option");
			h_attr(h, "value", if_kinds[ki].kind);
			if (strcmp(if_kinds[ki].kind, tp.create_kind) == 0)
				h_raw(h, " selected");
			h_raw(h, ">");
			h_txt(h, if_kinds[ki].label);
			h_raw(h, "</option>");
		}
		h_raw(h, "</select></label><label>Number<input name=\"number\" "
		    "inputmode=\"numeric\" autocomplete=\"off\" placeholder=\""
		    "the next free one\"><small>gif0, vlan100: the unit; empty, "
		    "the host picks the next.</small></label></div>");
		if (if_kind_has(tp.create_kind, IFK_TUNNEL))
			h_raw(h, "<div class=\"two\"><label>Tunnel: this end<input "
			    "name=\"tunnel_local\" spellcheck=\"false\" autocomplete="
			    "\"off\" placeholder=\"192.0.2.1\"><small>An address of "
			    "this host the outer packets leave from.</small></label>"
			    "<label>Tunnel: far end<input name=\"tunnel_remote\" "
			    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\""
			    "192.0.2.2\"></label></div>");
		if (if_kind_has(tp.create_kind, IFK_REQID))
			h_raw(h, "<label>reqid<input name=\"reqid\" inputmode=\""
			    "numeric\" autocomplete=\"off\" placeholder=\"1 to 16383\">"
			    "<small>The IPsec security association's request id "
			    "that if_ipsec(4) binds the interface to.</small></label>");
		if (if_kind_has(tp.create_kind, IFK_VNI))
			h_raw(h, "<label>VXLAN identifier<input name=\"id\" "
			    "inputmode=\"numeric\" autocomplete=\"off\" placeholder=\""
			    "up to 16777215\" required></label>");
		if (if_kind_has(tp.create_kind, IFK_VLAN))
			h_raw(h, "<div class=\"two\"><label>VLAN tag<input name=\"id\" "
			    "inputmode=\"numeric\" autocomplete=\"off\" placeholder=\""
			    "1 to 4094\" required></label><label>Parent<input name="
			    "\"parent\" spellcheck=\"false\" autocomplete=\"off\" "
			    "placeholder=\"the interface it rides\" required></label>"
			    "</div>");
		if (if_kind_has(tp.create_kind, IFK_MEMBER))
			h_raw(h, "<label>First member<input name=\"parent\" "
			    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\""
			    "an interface put in the bridge; empty for none yet\">"
			    "</label>");
		if (if_kind_has(tp.create_kind, IFK_ADDRESS))
			h_raw(h, "<div class=\"two\"><label>Address<input name=\""
			    "address\" spellcheck=\"false\" autocomplete=\"off\" "
			    "placeholder=\"10.0.0.1/30\"></label><label>Peer's "
			    "address<input name=\"peer\" spellcheck=\"false\" "
			    "autocomplete=\"off\" placeholder=\"point to point only\">"
			    "</label></div>");
		h_raw(h, "<div class=\"two\"><label>MTU<input name=\"mtu\" "
		    "inputmode=\"numeric\" autocomplete=\"off\"></label><label>"
		    "Description<input name=\"description\" autocomplete=\"off\">"
		    "</label></div><div class=\"two\"><label>Routing table (FIB)"
		    "<input name=\"fib\" inputmode=\"numeric\" autocomplete=\"off\" "
		    "placeholder=\"0\"><small>Set first: its addresses and "
		    "routes go in it.</small></label><label>Tunnel's outer "
		    "table<input name=\"tunnelfib\" inputmode=\"numeric\" "
		    "autocomplete=\"off\" placeholder=\"0\"><small>Where the far "
		    "end is looked up: an underlay table for an overlay "
		    "tunnel.</small></label></div>");
		if (strcmp(tp.create_kind, "wg") == 0)
			h_raw(h, "<p class=\"dim\">A WireGuard interface gets its key "
			    "and port on the WireGuard tab once it is made, and is "
			    "kept for wg-quick(8) there, not in rc.conf.</p>");
		else
			h_raw(h, "<label class=\"toggle\"><input type=\"checkbox\" "
			    "name=\"persist\" checked><span>Keep it in <code>rc.conf"
			    "</code>: on <code>cloned_interfaces</code>, with its "
			    "<code>create_args_</code> and <code>ifconfig_</code> "
			    "lines, so rc(8) makes it again at boot</span></label>");
		return (true);
	case MODAL_IF_SET:
		mtu = (unsigned int)atoi(app.confirm.value);
		h_raw(h, "<form data-form=\"if-set\"><h2>Set ");
		h_txt(h, app.confirm.arg);
		h_raw(h, "</h2><p>With <code>ifconfig</code>, in safe mode: "
		    "unless the host is reached again afterwards, it puts "
		    "back what was.</p><label>MTU<input name=\"mtu\" "
		    "inputmode=\"numeric\"");
		if (mtu != 0)
			h_fmt(h, " value=\"%u\"", mtu);
		h_raw(h, "></label><label>Description<input name=\""
		    "description\" autocomplete=\"off\"");
		h_attr(h, "value", app.confirm.body);
		h_raw(h, "><small>Empty takes it off.</small></label>");
		/* Its tables: the one its addresses and routes are in, and a
		 * tunnel's for its outer packets (setfib, tunnelfib). */
		h_raw(h, "<div class=\"two\"><label>Routing table (FIB)<input "
		    "name=\"fib\" inputmode=\"numeric\" autocomplete=\"off\"");
		if (app.confirm.fib >= 0)
			h_fmt(h, " value=\"%d\"", app.confirm.fib);
		h_raw(h, "><small>Empty leaves it; 0 is the first. The "
		    "interface's addresses and routes go with it.</small>"
		    "</label><label>Tunnel's outer table<input name=\""
		    "tunnelfib\" inputmode=\"numeric\" autocomplete=\"off\"");
		if (app.confirm.tunnelfib >= 0)
			h_fmt(h, " value=\"%d\"", app.confirm.tunnelfib);
		h_raw(h, "><small>Where a gre, gif, wg or vxlan looks up its far "
		    "end: an underlay table keeps a tunnel from routing its own "
		    "packets into itself.</small></label></div>");
		h_raw(h, keep_field);
		return (true);
	case MODAL_NG_CONNECT:
		h_raw(h, "<form data-form=\"ng-connect\"><h2>Connect two "
		    "nodes</h2><p><code>ngctl connect</code>: a hook of each, "
		    "joined.</p><div class=\"two\"><label>Node<input name=\""
		    "path\" spellcheck=\"false\"");
		h_attr(h, "value", app.confirm.arg);
		h_raw(h, "></label><label>Its hook<input name=\"hook\" "
		    "spellcheck=\"false\" autocomplete=\"off\" autofocus>"
		    "</label></div><div class=\"two\"><label>Other node<input "
		    "name=\"peer\" spellcheck=\"false\"");
		h_attr(h, "value", app.confirm.value);
		h_raw(h, "></label><label>Its hook<input name=\"peerhook\" "
		    "spellcheck=\"false\" autocomplete=\"off\"></label></div>");
		return (true);
	case MODAL_NG_MKPEER:
		h_raw(h, "<form data-form=\"ng-mkpeer\"><h2>Create a node"
		    "</h2><p><code>ngctl mkpeer</code>: a new node of a type, "
		    "joined to an existing one.</p><div class=\"two\"><label>"
		    "Existing node<input name=\"path\" spellcheck=\"false\"");
		h_attr(h, "value", app.confirm.arg);
		h_raw(h, "></label><label>Its hook<input name=\"hook\" "
		    "spellcheck=\"false\" autocomplete=\"off\"></label></div>"
		    "<div class=\"two\"><label>Type of the new node<input "
		    "name=\"type\" spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"bridge, eiface, tee…\" autofocus></label>"
		    "<label>Its hook<input name=\"peerhook\" spellcheck=\""
		    "false\" autocomplete=\"off\"></label></div>");
		return (true);
	default:
		return (false);
	}
}

/* A job for an interface of a host, in safe mode where that can be. */
static void
if_job(struct server *s, const char *title, const char *target,
    const char *fmt, ...)
{
	va_list	 ap;
	char	*json;

	va_start(ap, fmt);
	if (vasprintf(&json, fmt, ap) == -1)
		abort();
	va_end(ap);
	job_send(s, json, title, JOB_IFACE, target);
}

/* ,"key":"value" for a field that was filled in; "" for one left empty. */
static char *
field(const ucl_object_t *f, const char *name, const char *key)
{
	const char	*v;
	char		*q, *out;

	v = jstr(f, name);
	if (v == NULL || v[0] == '\0')
		return (strdup(""));
	q = json_quote(v);
	if (asprintf(&out, ",\"%s\":%s", key, q) == -1)
		abort();
	free(q);
	return (out);
}

/* ,"key":number for a field with a number in it. */
static char *
number(const ucl_object_t *f, const char *name, const char *key)
{
	const char	*v;
	char		*out;

	v = jstr(f, name);
	if (v == NULL || v[0] == '\0' || v[strspn(v, "0123456789")] != '\0' ||
	    strlen(v) > 8)
		return (strdup(""));
	if (asprintf(&out, ",\"%s\":%s", key, v) == -1)
		abort();
	return (out);
}

/*
 * A WireGuard tunnel: each host makes its interface with its inner
 * address, then its key; the peers follow once both keys are known,
 * which only the hosts can say.
 */
static void
wg_create(const ucl_object_t *f, int sa, int sb,
    const char *na, const char *nb, const char *la, const char *lb,
    const char *ia, const char *ib, bool outer6, bool keep)
{
	struct wgpair	*p;
	unsigned char	 raw[16];
	char		 title[160], *json, *qa, *mtu;
	int		 i, pa, pb, af, end;

	if (ia[0] == '\0') {
		snprintf(app.modal_error, sizeof(app.modal_error), "A "
		    "WireGuard tunnel needs its inner addresses: they are "
		    "what each end may send from");
		return;
	}
	for (i = 0; i < WG_PAIRS && wgpairs[i].active; i++)
		;
	if (i == WG_PAIRS) {
		snprintf(app.modal_error, sizeof(app.modal_error), "Too many "
		    "tunnels are being made: let them finish");
		return;
	}
	p = &wgpairs[i];
	memset(p, 0, sizeof(*p));
	pa = 51820 + atoi(na + 2);
	pb = 51820 + atoi(nb + 2);
	snprintf(p->a, sizeof(p->a), "%s", tn[sa].key);
	snprintf(p->b, sizeof(p->b), "%s", tn[sb].key);
	snprintf(p->ifa, sizeof(p->ifa), "%s", na);
	snprintf(p->ifb, sizeof(p->ifb), "%s", nb);
	snprintf(p->enda, sizeof(p->enda), outer6 ? "[%s]:%d" : "%s:%d", la, pa);
	snprintf(p->endb, sizeof(p->endb), outer6 ? "[%s]:%d" : "%s:%d", lb, pb);
	/* What an end may send from: its inner address, and that alone. */
	(void)addr_bytes(ia, &af, raw);
	snprintf(p->ina, sizeof(p->ina), "%.*s/%d", (int)strcspn(ia, "/"), ia,
	    af == AF_INET ? 32 : 128);
	snprintf(p->inb, sizeof(p->inb), "%.*s/%d", (int)strcspn(ib, "/"), ib,
	    af == AF_INET ? 32 : 128);
	p->keep = keep;
	p->since = arc_now();
	mtu = number(f, "mtu", "mtu");
	for (end = 0; end < 2; end++) {
		int	s = end == 0 ? sa : sb;
		const char	*name = end == 0 ? na : nb;

		qa = json_quote(end == 0 ? ia : ib);
		if (asprintf(&json, "{\"kind\":\"if-create\",\"interface\":"
		    "\"%s\",\"address\":%s%s,\"description\":\"arcana tunnel\","
		    "\"safe\":true}", name, qa, mtu) == -1)
			abort();
		free(qa);
		snprintf(title, sizeof(title), "create %s to %s", name,
		    end == 0 ? tn[sb].label : tn[sa].label);
		node_send(s, json, title, name);
		if (asprintf(&json, "{\"kind\":\"wireguard\",\"interface\":"
		    "\"%s\",\"verb\":\"init\",\"listen_port\":%d,\"persist\":"
		    "%s}", name, end == 0 ? pa : pb, keep ? "true" : "false") ==
		    -1)
			abort();
		snprintf(title, sizeof(title), "%s: wireguard init", name);
		node_send(s, json, title, name);
	}
	free(mtu);
	p->active = true;
	app.modal = MODAL_NONE;
	tp.last_poll = 0;
}

/* A node's own network: its host's tab, with the jail picked there. */
static void
node_open(int n, int kind)
{

	app.sel = tn[n].srv;
	app.node = NODE_HOST;
	app.tab = TAB_NETWORK;
	snprintf(app.net_jail, sizeof(app.net_jail), "%s", tn[n].jail);
	app.net.kind = kind;
	app.net.sort = -1;
	app.net.loading = false;
	refresh_network(&app.servers[tn[n].srv], true);
}

/* The two ends of a tunnel, as the form describes it: a job each. */
static void
tunnel_create(const ucl_object_t *f)
{
	unsigned char	 ra[16], rb[16];
	const char	*type, *ia, *ib, *la, *lb;
	char		 na[16], nb[16], title[160], pa[80], pb[80];
	char		*qla, *qlb, *qia, *qib, *qpa, *qpb, *mtu, *vni, *inner_a,
			*inner_b;
	bool		 vx, keep;
	int		 a, b, fa, fb;

	if ((a = node_index(tp.tun_a)) == -1 || (b = node_index(
	    tp.tun_b)) == -1)
		return;
	type = jstr(f, "type") != NULL ? jstr(f, "type") : "gif";
	if (strcmp(type, "gif") != 0 && strcmp(type, "gre") != 0 &&
	    strcmp(type, "vxlan") != 0 && strcmp(type, "wg") != 0)
		type = "gif";
	vx = strcmp(type, "vxlan") == 0;
	la = jstr(f, "local_a") != NULL ? jstr(f, "local_a") : "";
	lb = jstr(f, "local_b") != NULL ? jstr(f, "local_b") : "";
	ia = jstr(f, "inner_a") != NULL ? jstr(f, "inner_a") : "";
	ib = jstr(f, "inner_b") != NULL ? jstr(f, "inner_b") : "";
	if (!addr_bytes(la, &fa, ra) || !addr_bytes(lb, &fb, rb) || fa != fb) {
		snprintf(app.modal_error, sizeof(app.modal_error), "The outer "
		    "addresses are one of each host, of the same family");
		return;
	}
	if ((ia[0] == '\0') != (ib[0] == '\0') || (ia[0] != '\0' &&
	    (!addr_bytes(ia, &fa, ra) || !addr_bytes(ib, &fb, rb) || fa != fb ||
	    addr_same(ia, ib)))) {
		snprintf(app.modal_error, sizeof(app.modal_error), "The inner "
		    "addresses are two different ones of the same family, or "
		    "both left empty");
		return;
	}
	if (vx && (jstr(f, "vni") == NULL || jstr(f, "vni")[0] == '\0')) {
		snprintf(app.modal_error, sizeof(app.modal_error), "A vxlan "
		    "needs its identifier, the same at both ends");
		return;
	}
	keep = jbool(f, "persist");
	snprintf(na, sizeof(na), "%s%d", type, next_unit(thost(tn[a].key, false),
	    type));
	snprintf(nb, sizeof(nb), "%s%d", type, next_unit(thost(tn[b].key, false),
	    type));
	if (strcmp(type, "wg") == 0) {
		wg_create(f, a, b, na, nb, la, lb, ia, ib, fa == AF_INET6,
		    keep);
		return;
	}
	/* The far end's inner address, without its prefix length: what a
	 * point-to-point address names its peer by. */
	snprintf(pa, sizeof(pa), "%.*s", (int)strcspn(ia, "/"), ia);
	snprintf(pb, sizeof(pb), "%.*s", (int)strcspn(ib, "/"), ib);
	qla = json_quote(la);
	qlb = json_quote(lb);
	mtu = number(f, "mtu", "mtu");
	vni = vx ? number(f, "vni", "id") : strdup("");
	/* Everything typed goes into the job quoted, as JSON wants it. */
	qia = json_quote(ia);
	qib = json_quote(ib);
	qpa = json_quote(pa);
	qpb = json_quote(pb);
	if (ia[0] != '\0' && !vx) {
		if (asprintf(&inner_a, ",\"address\":%s,\"destination\":%s",
		    qia, qpb) == -1 || asprintf(&inner_b, ",\"address\":%s,"
		    "\"destination\":%s", qib, qpa) == -1)
			abort();
	} else if (ia[0] != '\0') {
		if (asprintf(&inner_a, ",\"address\":%s", qia) == -1 ||
		    asprintf(&inner_b, ",\"address\":%s", qib) == -1)
			abort();
	} else {
		inner_a = strdup("");
		inner_b = strdup("");
	}
	snprintf(title, sizeof(title), "create %s to %s", na, tn[b].label);
	node_job(a, title, na, "{\"kind\":\"if-create\",\"interface\":\"%s\","
	    "\"tunnel_local\":%s,\"tunnel_remote\":%s%s%s%s,\"description\":"
	    "\"arcana tunnel\",\"persist\":%s,\"safe\":true}", na, qla, qlb,
	    inner_a, mtu, vni, keep ? "true" : "false");
	snprintf(title, sizeof(title), "create %s to %s", nb, tn[a].label);
	node_job(b, title, nb, "{\"kind\":\"if-create\",\"interface\":\"%s\","
	    "\"tunnel_local\":%s,\"tunnel_remote\":%s%s%s%s,\"description\":"
	    "\"arcana tunnel\",\"persist\":%s,\"safe\":true}", nb, qlb, qla,
	    inner_b, mtu, vni, keep ? "true" : "false");
	free(qla);
	free(qlb);
	free(qia);
	free(qib);
	free(qpa);
	free(qpb);
	free(mtu);
	free(vni);
	free(inner_a);
	free(inner_b);
	app.modal = MODAL_NONE;
	tp.last_poll = 0;
}

/* The forms of the network; true when form is one of them. */
bool
topo_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*name;
	char		 title[160], *a, *b, *c, *d, *e, *g, *i, *k, *fb, *tf;
	int		 n;

	nodes_build();

	if (strcmp(form, "tunnel") == 0) {
		tunnel_create(f);
		return (true);
	}
	if (strcmp(form, "join") == 0) {
		join_create(f);
		return (true);
	}
	if (strcmp(form, "if-create") == 0) {
		const char	*kind, *num;
		char		 nbuf[32], *rq;

		if ((n = node_index(tp.create_sid)) == -1)
			return (true);
		kind = jstr(f, "kind") != NULL ? jstr(f, "kind") : tp.create_kind;
		if (if_kind_has(kind, 0) == false && if_kind_of(kind) == NULL) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "Choose the kind of interface");
			return (true);
		}
		num = jstr(f, "number") != NULL ? jstr(f, "number") : "";
		if (num[strspn(num, "0123456789")] != '\0' || strlen(num) > 5) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "The number is digits, or empty for the next free");
			return (true);
		}
		snprintf(nbuf, sizeof(nbuf), "%s%s", kind, num);
		name = nbuf;
		/* What the kind needs, said before the host says it. */
		if (if_kind_has(kind, IFK_TUNNEL) && (jstr(f, "tunnel_local") ==
		    NULL || jstr(f, "tunnel_local")[0] == '\0' || jstr(f,
		    "tunnel_remote") == NULL || jstr(f, "tunnel_remote")[0] ==
		    '\0')) {
			snprintf(app.modal_error, sizeof(app.modal_error), "A %s "
			    "tunnel needs both its ends", kind);
			return (true);
		}
		if (if_kind_has(kind, IFK_VLAN) && (jstr(f, "id") == NULL ||
		    jstr(f, "id")[0] == '\0' || jstr(f, "parent") == NULL || jstr(
		    f, "parent")[0] == '\0')) {
			snprintf(app.modal_error, sizeof(app.modal_error), "A VLAN "
			    "needs its tag and the interface it rides");
			return (true);
		}
		if (if_kind_has(kind, IFK_VNI) && (jstr(f, "id") == NULL ||
		    jstr(f, "id")[0] == '\0')) {
			snprintf(app.modal_error, sizeof(app.modal_error), "A VXLAN "
			    "needs its identifier");
			return (true);
		}
		a = field(f, "tunnel_local", "tunnel_local");
		b = field(f, "tunnel_remote", "tunnel_remote");
		c = field(f, "address", "address");
		d = field(f, "peer", "destination");
		e = field(f, "description", "description");
		g = field(f, "parent", "parent");
		i = number(f, "mtu", "mtu");
		k = number(f, "id", "id");
		rq = number(f, "reqid", "reqid");
		fb = number(f, "fib", "fib");
		tf = number(f, "tunnelfib", "tunnelfib");
		snprintf(title, sizeof(title), "create %s", name);
		/* name is a kind of the list and digits. */
		node_job(n, title, name, "{\"kind\":\"if-create\",\"interface\":"
		    "\"%s\"%s%s%s%s%s%s%s%s%s%s%s,\"persist\":%s,\"safe\":true}",
		    name, a, b, c, d, e, g, i, k, rq, fb, tf, jbool(f,
		    "persist") && strcmp(kind, "wg") != 0 ? "true" : "false");
		free(a);
		free(b);
		free(c);
		free(d);
		free(e);
		free(g);
		free(i);
		free(k);
		free(rq);
		free(fb);
		free(tf);
		app.modal = MODAL_NONE;
		tp.last_poll = 0;
		return (true);
	}
	if (strcmp(form, "if-vnet") == 0) {
		if ((s = cur_server()) == NULL || net_scope()[0] == '\0')
			return (true);
		name = jstr(f, "interface") != NULL && jstr(f,
		    "interface")[0] != '\0' ? jstr(f, "interface") : "epair";
		if (name[strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789"
		    "._")] != '\0' || strlen(name) > 15) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "Name an interface of the host, or leave it empty "
			    "for a new epair");
			return (true);
		}
		/* A bridge for the end of a new pair that stays. */
		c = strcmp(name, "epair") == 0 ? field(f, "bridge", "parent") :
		    strdup("");
		a = json_quote(net_scope());
		snprintf(title, sizeof(title), "give %s to %s", name,
		    net_scope());
		/* name is letters, digits, dots: checked above. */
		if (asprintf(&b, "{\"kind\":\"if-vnet\",\"interface\":\"%s\","
		    "\"jail\":%s%s,\"persist\":%s}", name, a, c, jbool(f,
		    "persist") ? "true" : "false") == -1)
			abort();
		free(a);
		free(c);
		job_send_host(s, b, title, JOB_IFACE, name);
		app.modal = MODAL_NONE;
		tp.last_poll = 0;
		return (true);
	}
	if (strcmp(form, "if-set") == 0) {
		if ((s = cur_server()) == NULL)
			return (true);
		i = number(f, "mtu", "mtu");
		fb = number(f, "fib", "fib");
		tf = number(f, "tunnelfib", "tunnelfib");
		a = json_quote(jstr(f, "description") != NULL ? jstr(f,
		    "description") : "");
		b = json_quote(app.confirm.arg);
		snprintf(title, sizeof(title), "%s: set", app.confirm.arg);
		if_job(s, title, app.confirm.arg, "{\"kind\":\"if-set\","
		    "\"interface\":%s%s%s%s,\"description\":%s,\"persist\":%s,"
		    "\"safe\":true}", b, i, fb, tf, a, jbool(f, "persist") ?
		    "true" : "false");
		free(i);
		free(fb);
		free(tf);
		free(a);
		free(b);
		app.modal = MODAL_NONE;
		return (true);
	}
	if (strcmp(form, "ng-connect") == 0 || strcmp(form, "ng-mkpeer") == 0) {
		bool mk = strcmp(form, "ng-mkpeer") == 0;

		if ((s = cur_server()) == NULL)
			return (true);
		if (jstr(f, "path") == NULL || jstr(f, "hook") == NULL ||
		    jstr(f, "peerhook") == NULL || jstr(f, mk ? "type" :
		    "peer") == NULL || jstr(f, "hook")[0] == '\0' || jstr(f,
		    "peerhook")[0] == '\0' || jstr(f, mk ? "type" : "peer")[0] ==
		    '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "Every field is needed");
			return (true);
		}
		a = json_quote(jstr(f, "path"));
		b = json_quote(jstr(f, mk ? "type" : "peer"));
		c = json_quote(jstr(f, "hook"));
		d = json_quote(jstr(f, "peerhook"));
		snprintf(title, sizeof(title), "ngctl %s %s", mk ? "mkpeer" :
		    "connect", jstr(f, "path"));
		if_job(s, title, "netgraph", "{\"kind\":\"netgraph\",\"verb\":"
		    "\"%s\",\"args\":[%s,%s,%s,%s]}", mk ? "mkpeer" : "connect",
		    a, b, c, d);
		free(a);
		free(b);
		free(c);
		free(d);
		app.modal = MODAL_NONE;
		return (true);
	}
	return (false);
}

/* "x,y,cx,cy,k,drop" as the bridge sends it with a drag. */
static int
drag_values(const char *value, double *x, double *y, double *cx, double *cy,
    double *k, char *drop, size_t len)
{
	int	n, used;

	used = 0;
	n = sscanf(value, "%lf,%lf,%lf,%lf,%lf,%n", x, y, cx, cy, k, &used);
	if (drop != NULL)
		snprintf(drop, len, "%s", n >= 5 && used > 0 ? value + used :
		    "");
	return (n);
}

static void
zoom_by(double f, double x, double y)
{
	double	z;

	z = tp.zoom * f;
	if (z < 0.1)
		z = 0.1;
	if (z > 4)
		z = 4;
	/* What is under the pointer stays under it. */
	tp.panx = x - (x - tp.panx) * tp.zoom / z;
	tp.pany = y - (y - tp.pany) * tp.zoom / z;
	tp.zoom = z;
}

static void
fit(void)
{
	double	x0, y0, x1, y1, zx, zy;
	int	i, n;

	n = 0;
	x0 = y0 = x1 = y1 = 0;
	for (i = 0; i < nhosts; i++) {
		if (!hosts[i].placed || node_index(hosts[i].sid) == -1 ||
		    node_lone(node_index(hosts[i].sid)))
			continue;
		if (n == 0 || hosts[i].x < x0)
			x0 = hosts[i].x;
		if (n == 0 || hosts[i].x > x1)
			x1 = hosts[i].x;
		if (n == 0 || hosts[i].y < y0)
			y0 = hosts[i].y;
		if (n == 0 || hosts[i].y > y1)
			y1 = hosts[i].y;
		n++;
	}
	/* Room around them, and more when neighbours stand beside them;
	 * the legend lies over the drawing's foot, so that much is left
	 * under them. */
	zx = VIEW_W / (x1 - x0 + NODE_W + (nexts > 0 && !tp.nopeers ? 640 :
	    120) * (VIEW_W < 600 ? 0.5 : 1.0));
	zy = (VIEW_H - LEGEND_H - TOOLS_H) / (y1 - y0 + NODE_H + (nexts > 0 &&
	    !tp.nopeers ? 460 : 140) * (VIEW_W < 600 ? 0.5 : 1.0));
	tp.zoom = zx < zy ? zx : zy;
	if (tp.zoom > 1.7)
		tp.zoom = 1.7;
	if (tp.zoom < 0.1)
		tp.zoom = 0.1;
	tp.panx = (x0 + x1) / 2;
	tp.pany = (y0 + y1) / 2 + (LEGEND_H - TOOLS_H) / 2 / tp.zoom;
}

/* Called when the section is opened: read every host at once. */
void
topo_open(void)
{
	int	i;

	app.node = NODE_NETWORK;
	app.jail[0] = '\0';
	app.rail_open = false;
	places_fill();
	tp.last_poll = arc_now();
	nodes_build();
	for (i = 0; i < ntn; i++) {
		node_poll(i);
		wg_poll(i);
		bird_poll(i);
	}
}

/* What the map's buttons, drags and fields do; true when act is one. */
bool
topo_action(const char *act, const char *arg, const char *value)
{
	static double	 grab_x, grab_y;
	struct thost	*t;
	struct server	*s;
	char		 drop[96], body[400], *q;
	double		 x, y, cx, cy, k;
	int		 i, n;

	nodes_build();

	if (strcmp(act, "select-network") == 0) {
		topo_open();
		return (true);
	}
	if (strncmp(act, "topo-", 5) != 0 && strncmp(act, "input:topo-", 11) !=
	    0 && strncmp(act, "do-topo-", 8) != 0)
		return (false);
	if (strcmp(act, "topo-node-start") == 0 || strcmp(act,
	    "topo-node-move") == 0) {
		if ((t = thost(arg, false)) == NULL || drag_values(value, &x,
		    &y, &cx, &cy, &k, NULL, 0) < 2)
			return (true);
		/* It moves by where it was taken hold of, not by its middle. */
		if (act[10] == 's') {
			drag_x0 = t->x;
			drag_y0 = t->y;
			grab_x = t->x - x;
			grab_y = t->y - y;
		} else {
			t->x = x + grab_x;
			t->y = y + grab_y;
		}
		tp.touched = true;
		tp.custom = true;
	} else if (strcmp(act, "topo-node-end") == 0) {
		/* The neighbours dragged beside it are kept from it: by as
		 * much as it moved, so that they stay where they are. */
		if ((t = thost(arg, false)) != NULL) {
			size_t	len = strlen(arg);

			for (i = 0; i < tp.npeers; i++)
				if (strncmp(tp.peers[i].key, arg, len) == 0 &&
				    tp.peers[i].key[len] == '\t') {
					tp.peers[i].dx -= t->x - drag_x0;
					tp.peers[i].dy -= t->y - drag_y0;
				}
			peers_save();
		}
		places_save();
	} else if (strcmp(act, "topo-node-click") == 0) {
		tp.sel_link[0] = tp.sel_if[0] = '\0';
		if (strcmp(tp.sel, arg) == 0)
			tp.sel[0] = '\0';
		else
			snprintf(tp.sel, sizeof(tp.sel), "%s", arg);
	} else if (strcmp(act, "topo-pan-start") == 0 || strcmp(act,
	    "topo-pan-move") == 0) {
		if (drag_values(value, &x, &y, &cx, &cy, &k, NULL, 0) < 5)
			return (true);
		if (act[9] == 'm') {
			tp.panx -= (cx - tp.lastcx) * k;
			tp.pany -= (cy - tp.lastcy) * k;
			tp.touched = true;
		}
		tp.lastcx = cx;
		tp.lastcy = cy;
	} else if (strcmp(act, "topo-pan-end") == 0) {
		;
	} else if (strcmp(act, "topo-pan-click") == 0 || strcmp(act,
	    "topo-unselect") == 0) {
		tp.sel[0] = tp.sel_link[0] = tp.sel_if[0] = '\0';
	} else if (strcmp(act, "topo-link-start") == 0) {
		;
	} else if (strcmp(act, "topo-link-move") == 0) {
		if (drag_values(value, &x, &y, &cx, &cy, &k, NULL, 0) < 2)
			return (true);
		tp.linking = true;
		snprintf(tp.link_from, sizeof(tp.link_from), "%s", arg);
		tp.link_x = x;
		tp.link_y = y;
	} else if (strcmp(act, "topo-link-end") == 0) {
		tp.linking = false;
		(void)drag_values(value, &x, &y, &cx, &cy, &k, drop,
		    sizeof(drop));
		if (drop[0] == '\0' || strcmp(drop, arg) == 0 ||
		    node_index(drop) == -1 || node_index(arg) == -1)
			return (true);
		if (thost(arg, false) == NULL || thost(arg, false)->ifs ==
		    NULL || thost(drop, false) == NULL || thost(drop,
		    false)->ifs == NULL) {
			toast(true, "The interfaces of both hosts must have "
			    "been read first");
			return (true);
		}
		snprintf(tp.tun_a, sizeof(tp.tun_a), "%s", arg);
		snprintf(tp.tun_b, sizeof(tp.tun_b), "%s", drop);
		tunnel_offer(thost(arg, false), thost(drop, false));
		tp.join = JOIN_TUNNEL;
		memset(&tunf, 0, sizeof(tunf));
		snprintf(tunf.type, sizeof(tunf.type), "gif");
		snprintf(tunf.la, sizeof(tunf.la), "%s", offer.oa);
		snprintf(tunf.lb, sizeof(tunf.lb), "%s", offer.ob);
		snprintf(tunf.ia, sizeof(tunf.ia), "%s", offer.ia);
		snprintf(tunf.ib, sizeof(tunf.ib), "%s", offer.ib);
		tunf.keep = true;
		app.modal = MODAL_TUNNEL;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "input:topo-tunf") == 0) {
		tunf_set(arg, value != NULL ? value : "");
	} else if (strcmp(act, "topo-join") == 0) {
		for (i = 0; i < (int)nitems(join_kinds); i++)
			if (strcmp(arg, join_kinds[i]) == 0)
				tp.join = i;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "topo-link-click") == 0) {
		tp.linking = false;
		toast(false, "Drag the dot onto another host to join the two "
		    "with a tunnel or a routing session");
	} else if (strcmp(act, "topo-zoom") == 0) {
		/* The wheel says which way; two fingers say how much. */
		if (sscanf(value, "%lf,%lf,%lf", &k, &x, &y) == 3) {
			if (strcmp(arg, "pinch") == 0)
				zoom_by(k > 0.2 && k < 5 ? k : 1, x, y);
			else
				zoom_by(k < 0 ? 1.15 : 1 / 1.15, x, y);
			tp.touched = true;
		}
	} else if (strcmp(act, "topo-zoom-in") == 0) {
		zoom_by(1.25, tp.panx, tp.pany);
		tp.touched = true;
	} else if (strcmp(act, "topo-zoom-out") == 0) {
		zoom_by(0.8, tp.panx, tp.pany);
		tp.touched = true;
	} else if (strcmp(act, "topo-labels") == 0) {
		tp.labels_open = !tp.labels_open;
	} else if (strcmp(act, "topo-labels-what") == 0) {
		if (strcmp(arg, "names") == 0)
			tp.no_names = !tp.no_names;
		else if (strcmp(arg, "rates") == 0)
			tp.no_rates = !tp.no_rates;
	} else if (strcmp(act, "topo-bend-start") == 0 || strcmp(act,
	    "topo-bend-move") == 0) {
		struct bend	*b;
		double		 x1, y1, x2, y2, dx, dy, len;

		/* The link's middle follows the pointer, across it only. */
		for (i = 0; i < nlinks; i++)
			if (strcmp(links[i].key, arg) == 0)
				break;
		if (i == nlinks || drag_values(value, &x, &y, &cx, &cy, &k,
		    NULL, 0) < 2 || !place(links[i].a, &x1, &y1) ||
		    !place(links[i].b, &x2, &y2) || (b = bend_kept(arg,
		    true)) == NULL)
			return (true);
		dx = x2 - x1;
		dy = y2 - y1;
		if ((len = sqrt(dx * dx + dy * dy)) < 1)
			return (true);
		/* The curve's middle is half way to its control point. */
		b->bend = 2 * ((x - (x1 + x2) / 2) * -dy / len + (y - (y1 +
		    y2) / 2) * dx / len);
		if (b->bend > 600)
			b->bend = 600;
		if (b->bend < -600)
			b->bend = -600;
		snprintf(tp.sel_link, sizeof(tp.sel_link), "%s", arg);
		tp.sel[0] = tp.sel_if[0] = '\0';
	} else if (strcmp(act, "topo-bend-end") == 0) {
		bends_save();
	} else if (strcmp(act, "topo-peer-start") == 0 || strcmp(act,
	    "topo-peer-move") == 0) {
		static double	 peer_gx, peer_gy;
		struct peerpos	*pp;
		char		 sid[80];

		/* The host is the key's first field. */
		snprintf(sid, sizeof(sid), "%.*s", (int)strcspn(arg, "\t"), arg);
		if ((t = thost(sid, false)) == NULL || drag_values(value, &x,
		    &y, &cx, &cy, &k, NULL, 0) < 2 || (pp = peer_kept(arg,
		    true)) == NULL)
			return (true);
		/* It moves by where it was taken hold of. */
		if (act[10] == 's') {
			/* First dragged: from where it was drawn. */
			for (i = 0; pp->dx == 0 && pp->dy == 0 && i < nexts;
			    i++) {
				char	key[160];

				peer_key(key, sizeof(key), &exts[i]);
				if (strcmp(key, arg) == 0) {
					peers_layout();
					/* Where its node is drawn. */
					as_place(as_leader(i), &cx, &cy);
					pp->dx = cx - t->x;
					pp->dy = cy - t->y;
				}
			}
			peer_gx = t->x + pp->dx - x;
			peer_gy = t->y + pp->dy - y;
		} else {
			pp->dx = x + peer_gx - t->x;
			pp->dy = y + peer_gy - t->y;
		}
		snprintf(peer_dragging, sizeof(peer_dragging), "%s", arg);
		tp.touched = true;
	} else if (strcmp(act, "topo-peer-end") == 0) {
		peer_dragging[0] = '\0';
		peers_save();
	} else if (strcmp(act, "topo-peer-click") == 0) {
		char	sid[80];

		snprintf(sid, sizeof(sid), "%.*s", (int)strcspn(arg, "\t"), arg);
		if ((n = node_index(sid)) != -1)
			node_open(n, NET_BIRD);
	} else if (strcmp(act, "topo-bend-click") == 0) {
		tp.sel[0] = tp.sel_if[0] = '\0';
		snprintf(tp.sel_link, sizeof(tp.sel_link), "%s", arg);
	} else if (strcmp(act, "topo-labels-kind") == 0) {
		static const char *const names[] = { "tunnel", "p2p", "lan",
		    "bgp", "ospf", "vnet" };

		for (i = 0; i < LK_KINDS; i++)
			if (strcmp(arg, names[i]) == 0)
				tp.labels[i] = labels_quiet(i) ? 1 : 2;
	} else if (strcmp(act, "input:topo-fib") == 0) {
		tp.fib = atoi(value);
	} else if (strcmp(act, "topo-legend") == 0) {
		static const char *const names[] = { "tunnel", "p2p", "lan",
		    "bgp", "ospf", "vnet" };

		for (i = 0; i < LK_KINDS; i++)
			if (strcmp(arg, names[i]) == 0)
				tp.hide[i] = !tp.hide[i];
		if (strcmp(arg, "best") == 0)
			tp.hide_best = !tp.hide_best;
		if (strcmp(arg, "alt") == 0)
			tp.hide_alt = !tp.hide_alt;
	} else if (strcmp(act, "topo-fit") == 0) {
		/* Asked for: and kept fitted until moved again. */
		for (i = 0; i < nhosts; i++)
			hosts[i].out_set = false;
		fit();
		tp.touched = false;
	} else if (strcmp(act, "topo-jails") == 0) {
		tp.jails = !tp.jails;
	} else if (strcmp(act, "topo-vnet") == 0) {
		/* Linked, all, none, and round again. */
		if (tp.novnet)
			tp.novnet = tp.lonevnet = false;
		else if (tp.lonevnet)
			tp.novnet = !(tp.lonevnet = false);
		else
			tp.lonevnet = true;
		arc_store_set("arc_topo_vnet", tp.novnet ? "hidden" : tp.lonevnet ?
		    "all" : "linked");
		tp.touched = false;
	} else if (strcmp(act, "topo-open-wg") == 0 || strcmp(act,
	    "topo-open-bird") == 0) {
		if ((n = node_index(arg)) == -1)
			return (true);
		node_open(n, act[10] == 'w' ? NET_WIREGUARD : NET_BIRD);
	} else if (strcmp(act, "topo-open-bridges") == 0) {
		if ((n = node_index(arg)) == -1)
			return (true);
		node_open(n, NET_BRIDGES);
	} else if (strcmp(act, "topo-peers") == 0) {
		tp.nopeers = !tp.nopeers;
	} else if (strcmp(act, "topo-png") == 0) {
		arc_svg_png("svg.topo", tp.stencil ? "network-diagram.png" :
		    "network-map.png");
		return (true);		/* nothing to draw again */
	} else if (strcmp(act, "topo-ospfmap") == 0) {
		if (om.on) {
			om_reset();
			fit();
		} else
			om_start();
	} else if (strcmp(act, "topo-stencil") == 0) {
		tp.stencil = !tp.stencil;
	} else if (strcmp(act, "topo-arrange") == 0) {
		tp.custom = false;
		tp.shape_sig = 0;
		for (i = 0; i < nhosts; i++)
			hosts[i].out_set = false;
		for (i = 0; i < nhosts; i++)
			hosts[i].placed = false;
		places_fill();
		places_save();
		/* And the links straight again, or bent apart as at first,
		 * and the neighbours outside where they were drawn. */
		tp.nbends = 0;
		bends_save();
		tp.npeers = 0;
		peers_save();
		fit();
	} else if (strcmp(act, "topo-sel-link") == 0) {
		tp.sel[0] = tp.sel_if[0] = '\0';
		snprintf(tp.sel_link, sizeof(tp.sel_link), "%s", arg);
	} else if (strcmp(act, "topo-sel-if") == 0) {
		if (strcmp(tp.sel_if, arg) == 0)
			tp.sel_if[0] = '\0';
		else
			snprintf(tp.sel_if, sizeof(tp.sel_if), "%s", arg);
	} else if (strcmp(act, "topo-sel-busy") == 0) {
		tp.sel_link[0] = '\0';
		snprintf(tp.sel, sizeof(tp.sel), "%s", arg);
		snprintf(tp.sel_if, sizeof(tp.sel_if), "%s", value);
	} else if (strcmp(act, "topo-open-host") == 0) {
		if ((n = node_index(arg)) == -1)
			return (true);
		node_open(n, NET_INTERFACES);
	} else if (strcmp(act, "topo-from-here") == 0) {
		snprintf(path.from, sizeof(path.from), "%s", arg);
	} else if (strcmp(act, "input:topo-from") == 0) {
		snprintf(path.from, sizeof(path.from), "%s", value);
	} else if (strcmp(act, "input:topo-to") == 0) {
		snprintf(path.to_name, sizeof(path.to_name), "%s", value);
		path.to[0] = '\0';
	} else if (strcmp(act, "input:topo-addr") == 0) {
		snprintf(path.to, sizeof(path.to), "%s", value);
		path.to_name[0] = '\0';
		return (true);		/* typing: nothing to draw again */
	} else if (strcmp(act, "topo-trace") == 0) {
		trace_start();
	} else if (strcmp(act, "topo-path-clear") == 0) {
		path.n = 0;
		path.gen++;
		path.busy = path.done = false;
		path.error[0] = '\0';
	} else if (strcmp(act, "topo-if-create") == 0) {
		if (arg[0] != '\0' ? node_index(arg) == -1 : (s =
		    cur_server()) == NULL)
			return (true);
		topo_if_create_open(arg[0] != '\0' ? arg : s->id, "epair");
	} else if (strcmp(act, "input:topo-if-kind") == 0) {
		if (if_kind_of(value) != NULL)
			snprintf(tp.create_kind, sizeof(tp.create_kind), "%s",
			    value);
	} else if (strcmp(act, "topo-tunnel-destroy") == 0) {
		for (i = 0; i < nlinks; i++)
			if (strcmp(links[i].key, arg) == 0)
				break;
		if (i == nlinks || links[i].b < 0)
			return (true);
		snprintf(body, sizeof(body), "ifconfig %s destroy on %s%s%s%s"
		    "%s, and they are forgotten in rc.conf. A host that the "
		    "console reaches through the tunnel refuses.", links[i].ifa,
		    tn[links[i].a].label, links[i].ifb[0] != '\0' ?
		    ", ifconfig " : "", links[i].ifb, links[i].ifb[0] != '\0' ?
		    " destroy on " : "", links[i].ifb[0] != '\0' ?
		    tn[links[i].b].label : "");
		confirm("Destroy the tunnel", body, "Destroy", true, "",
		    "do-topo-tunnel-destroy", arg, "");
	} else if (strcmp(act, "do-topo-tunnel-destroy") == 0) {
		for (i = 0; i < nlinks; i++)
			if (strcmp(links[i].key, arg) == 0)
				break;
		if (i == nlinks || links[i].b < 0)
			return (true);
		q = json_quote(links[i].ifa);
		snprintf(body, sizeof(body), "destroy %s", links[i].ifa);
		node_job(links[i].a, body, links[i].ifa, "{\"kind\":"
		    "\"if-destroy\",\"interface\":%s,\"persist\":true}", q);
		free(q);
		if (links[i].ifb[0] != '\0') {
			q = json_quote(links[i].ifb);
			snprintf(body, sizeof(body), "destroy %s", links[i].ifb);
			node_job(links[i].b, body, links[i].ifb,
			    "{\"kind\":\"if-destroy\",\"interface\":%s,"
			    "\"persist\":true}", q);
			free(q);
		}
		tp.sel_link[0] = '\0';
		tp.last_poll = 0;
	}
	return (true);
}

/*
 * A host's netgraph(4): its nodes placed on a circle, to be moved, and
 * a line for every pair of hooks joined.  A node is picked for its
 * hooks; its port is dragged onto another node to connect the two.
 */
#define	NG_MAX		64

static struct {
	char	sid[9];
	char	id[NG_MAX][12];
	double	x[NG_MAX], y[NG_MAX];
	int	n;
	char	sel[12];		/* the node picked, by its id */
	bool	linking;
	char	from[12];
	double	lx, ly;
} ng;

/* How ngctl is told of a node: by its name, or by its id when unnamed. */
static void
ng_path(const ucl_object_t *node, char *buf, size_t len)
{
	const char	*name, *id;

	name = jstr(node, "name");
	id = jstr(node, "id") != NULL ? jstr(node, "id") : "0";
	if (name != NULL && name[0] != '<')
		snprintf(buf, len, "%s:", name);
	else
		snprintf(buf, len, "[%s]:", id + strspn(id, "0"));
}

static int
ng_place(const char *id, int i, int total)
{
	double	a;
	int	k;

	for (k = 0; k < ng.n; k++)
		if (strcmp(ng.id[k], id) == 0)
			return (k);
	if (ng.n == NG_MAX)
		return (-1);
	k = ng.n++;
	snprintf(ng.id[k], sizeof(ng.id[k]), "%s", id);
	a = -M_PI / 2 + 2 * M_PI * i / (total > 0 ? total : 1);
	ng.x[k] = 500 + (total == 1 ? 0 : 360 * cos(a));
	ng.y[k] = 250 + (total == 1 ? 0 : 190 * sin(a));
	return (k);
}

void
view_netgraph(struct html *h, struct server *s, const ucl_object_t *nodes)
{
	const ucl_object_t	*o, *hk, *sel, **nrows;
	ucl_object_iter_t	 it, hit;
	const char		*id;
	char			 p[80];
	double			 mx, my;
	int			 i, k, m, total, nr;

	if (strcmp(ng.sid, s->id) != 0) {
		memset(&ng, 0, sizeof(ng));
		snprintf(ng.sid, sizeof(ng.sid), "%s", s->id);
	}
	total = (int)ucl_array_size(nodes);
	h_raw(h, "<div class=\"toolbar\"><button class=\"ghost small\" "
	    "data-act=\"ng-mkpeer\" data-arg=\"\">+ node</button><span class=\""
	    "tally\">");
	h_fmt(h, "%d nodes", total);
	h_raw(h, "</span></div>");
	if (total == 0) {
		h_raw(h, "<div class=\"empty\"><p>No netgraph nodes on this "
		    "host.</p></div>");
		return;
	}
	if (total > NG_MAX)
		h_fmt(h, "<div class=\"notice info\">The graph draws the "
		    "first %d of the %d nodes; the table has them all.</div>",
		    NG_MAX, total);
	h_fmt(h, "<div class=\"netmap ngmap\"><div class=\"map-wrap\"><svg "
	    "class=\"topo big%s\" viewBox=\"0 0 1000 500\">", ng.linking ?
	    " linking" : "");
	/* The hooks first, under the nodes: each pair once. */
	i = 0;
	it = NULL;
	while ((o = ucl_object_iterate(nodes, &it, true)) != NULL) {
		id = jstr(o, "id") != NULL ? jstr(o, "id") : "";
		if ((k = ng_place(id, i++, total > NG_MAX ? NG_MAX : total)) ==
		    -1)
			continue;
		hit = NULL;
		while ((hk = ucl_object_iterate(jget(o, "hooks"), &hit, true)) !=
		    NULL) {
			if (jstr(hk, "peer-id") == NULL || strcmp(id, jstr(hk,
			    "peer-id")) >= 0)
				continue;
			for (m = 0; m < ng.n; m++)
				if (strcmp(ng.id[m], jstr(hk, "peer-id")) == 0)
					break;
			if (m == ng.n)
				continue;
			h_raw(h, "<g class=\"tlink lan up\"><path class=\"wire\" "
			    "d=\"");
			curve(h, ng.x[k], ng.y[k], ng.x[m], ng.y[m], 0, 0.5, &mx,
			    &my);
			h_fmt(h, "\"/><text class=\"lbl\" x=\"%.1f\" y=\"%.1f\">",
			    mx, my - 5);
			h_txt(h, jstr(hk, "hook"));
			h_raw(h, " — ");
			h_txt(h, jstr(hk, "peer-hook"));
			h_raw(h, "</text></g>");
		}
	}
	if (ng.linking)
		for (k = 0; k < ng.n; k++)
			if (strcmp(ng.id[k], ng.from) == 0)
				h_fmt(h, "<path class=\"tdraft\" d=\"M%.1f %.1f "
				    "L%.1f %.1f\"/>", ng.x[k] + 65, ng.y[k],
				    ng.lx, ng.ly);
	sel = NULL;
	it = NULL;
	while ((o = ucl_object_iterate(nodes, &it, true)) != NULL) {
		id = jstr(o, "id") != NULL ? jstr(o, "id") : "";
		for (k = 0; k < ng.n; k++)
			if (strcmp(ng.id[k], id) == 0)
				break;
		if (k == ng.n)
			continue;
		if (strcmp(ng.sel, id) == 0)
			sel = o;
		h_fmt(h, "<g class=\"tnode up ng%s\" transform=\"translate(%.1f,"
		    "%.1f)\" data-drag=\"ng-node\"", sel == o ? " sel" : "",
		    ng.x[k], ng.y[k]);
		h_attr(h, "data-arg", id);
		h_attr(h, "data-drop", id);
		h_raw(h, "><rect class=\"box\" x=\"-65\" y=\"-24\" width=\"130\" "
		    "height=\"48\" rx=\"10\"/><text class=\"name\" x=\"-54\" "
		    "y=\"-3\">");
		h_fit(h, jstr(o, "name"), 12);
		h_raw(h, "</text><text class=\"sub\" x=\"-54\" y=\"14\">");
		h_fit(h, jstr(o, "type"), 15);
		h_raw(h, "</text><title>");
		h_txt(h, jstr(o, "name"));
		h_raw(h, " · ");
		h_txt(h, jstr(o, "type"));
		h_raw(h, "</title><circle class=\"port\" cx=\"65\" cy=\"0\" r=\"7\" "
		    "data-drag=\"ng-link\"");
		h_attr(h, "data-arg", id);
		h_raw(h, "><title>Drag to another node to connect a hook of "
		    "each</title></circle></g>");
	}
	h_raw(h, "</svg></div><aside class=\"map-panel\">");
	if (sel != NULL) {
		ng_path(sel, p, sizeof(p));
		h_raw(h, "<section class=\"pane\"><h4>");
		h_txt(h, jstr(sel, "name"));
		h_raw(h, "</h4><p class=\"mono\">");
		h_txt(h, jstr(sel, "type"));
		h_raw(h, " · ");
		h_txt(h, p);
		h_raw(h, "</p><ul class=\"iflist\">");
		hit = NULL;
		while ((hk = ucl_object_iterate(jget(sel, "hooks"), &hit,
		    true)) != NULL) {
			h_raw(h, "<li><div class=\"ifhead\"><b>");
			h_txt(h, jstr(hk, "hook"));
			h_raw(h, "</b><span class=\"dim\">to ");
			h_txt(h, jstr(hk, "peer"));
			h_raw(h, " (");
			h_txt(h, jstr(hk, "peer-type"));
			h_raw(h, ") ");
			h_txt(h, jstr(hk, "peer-hook"));
			h_raw(h, "</span><button class=\"icon\" data-act=\""
			    "ng-rmhook\" title=\"Remove this hook\"");
			h_attr(h, "data-arg", p);
			h_attr(h, "data-value", jstr(hk, "hook"));
			h_raw(h, ">×</button></div></li>");
		}
		h_raw(h, "</ul><div class=\"pane-actions\"><button class=\""
		    "ghost small\" data-act=\"ng-mkpeer\"");
		h_attr(h, "data-arg", p);
		h_raw(h, ">+ peer</button><button class=\"danger small\" "
		    "data-act=\"ng-shutdown\"");
		h_attr(h, "data-arg", p);
		h_raw(h, ">Shut down</button></div></section>");
	} else
		h_raw(h, "<section class=\"pane\"><h4>Netgraph</h4><p class=\""
		    "dim\">Pick a node for its hooks. Drag the dot on a "
		    "node's edge onto another node to connect a hook of each. "
		    "Changes run <code>ngctl</code> as jobs; they are not "
		    "kept over a boot.</p></section>");
	h_raw(h, "</aside></div><table class=\"net ngnodes\">");
	{
		static const struct tcol ncols[] = {
			{ "Node", "name", false }, { "Type", "type", false },
			{ "ID", "id", false }, { "Hooks", NULL, false },
		};

		tbl_head(h, "ngnodes", ncols, 4, 0);
		h_raw(h, "<tbody>");
		nrows = tbl_rows("ngnodes", nodes, ncols, 4, app.filter);
	}
	for (nr = 0; (o = nrows[nr]) != NULL; nr++) {
		h_raw(h, "<tr><td>");
		h_txt(h, jstr(o, "name"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(o, "type"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(o, "id"));
		h_raw(h, "</td><td>");
		hit = NULL;
		while ((hk = ucl_object_iterate(jget(o, "hooks"), &hit, true)) !=
		    NULL) {
			h_raw(h, "<span class=\"chip\"><span>");
			h_txt(h, jstr(hk, "hook"));
			h_raw(h, " → ");
			h_txt(h, jstr(hk, "peer"));
			h_raw(h, ":");
			h_txt(h, jstr(hk, "peer-hook"));
			h_raw(h, "</span></span> ");
		}
		h_raw(h, "</td></tr>");
	}
	free(nrows);
	h_raw(h, "</tbody></table>");
}

/* The netgraph view's drags and buttons; true when act is one. */
bool
ng_action(const char *act, const char *arg, const char *value)
{
	static double		 grab_x, grab_y;
	const ucl_object_t	*o, *a, *b;
	ucl_object_iter_t	 it;
	struct server		*s;
	char			 drop[64], body[300], pa[80], pb[80], *q, *q2;
	double			 x, y, cx, cy, k;
	int			 i;

	if (strncmp(act, "ng-", 3) != 0 && strncmp(act, "do-ng-", 6) != 0)
		return (false);
	s = cur_server();
	if (strcmp(act, "ng-node-start") == 0 || strcmp(act,
	    "ng-node-move") == 0) {
		if (drag_values(value, &x, &y, &cx, &cy, &k, NULL, 0) < 2)
			return (true);
		for (i = 0; i < ng.n; i++) {
			if (strcmp(ng.id[i], arg) != 0)
				continue;
			if (act[8] == 's') {
				grab_x = ng.x[i] - x;
				grab_y = ng.y[i] - y;
			} else {
				ng.x[i] = x + grab_x;
				ng.y[i] = y + grab_y;
			}
		}
	} else if (strcmp(act, "ng-node-end") == 0 || strcmp(act,
	    "ng-link-start") == 0) {
		;
	} else if (strcmp(act, "ng-node-click") == 0) {
		if (strcmp(ng.sel, arg) == 0)
			ng.sel[0] = '\0';
		else
			snprintf(ng.sel, sizeof(ng.sel), "%s", arg);
	} else if (strcmp(act, "ng-link-move") == 0) {
		if (drag_values(value, &x, &y, &cx, &cy, &k, NULL, 0) < 2)
			return (true);
		ng.linking = true;
		snprintf(ng.from, sizeof(ng.from), "%s", arg);
		ng.lx = x;
		ng.ly = y;
	} else if (strcmp(act, "ng-link-end") == 0) {
		ng.linking = false;
		(void)drag_values(value, &x, &y, &cx, &cy, &k, drop,
		    sizeof(drop));
		if (drop[0] == '\0' || strcmp(drop, arg) == 0)
			return (true);
		a = b = NULL;
		it = NULL;
		while ((o = ucl_object_iterate(jget(app.net.data, "data.nodes"),
		    &it, true)) != NULL) {
			if (jstr(o, "id") != NULL && strcmp(jstr(o, "id"),
			    arg) == 0)
				a = o;
			if (jstr(o, "id") != NULL && strcmp(jstr(o, "id"),
			    drop) == 0)
				b = o;
		}
		if (a == NULL || b == NULL)
			return (true);
		ng_path(a, pa, sizeof(pa));
		ng_path(b, pb, sizeof(pb));
		snprintf(app.confirm.arg, sizeof(app.confirm.arg), "%s", pa);
		snprintf(app.confirm.value, sizeof(app.confirm.value), "%s", pb);
		app.modal = MODAL_NG_CONNECT;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "ng-link-click") == 0) {
		ng.linking = false;
	} else if (strcmp(act, "ng-mkpeer") == 0) {
		snprintf(app.confirm.arg, sizeof(app.confirm.arg), "%s", arg);
		app.modal = MODAL_NG_MKPEER;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "ng-rmhook") == 0 && s != NULL) {
		snprintf(body, sizeof(body), "ngctl rmhook %s %s, on %s. What "
		    "passes through the hook stops.", arg, value, s->name);
		confirm("Remove the hook", body, "Remove", true, "",
		    "do-ng-rmhook", arg, value);
	} else if (strcmp(act, "ng-shutdown") == 0 && s != NULL) {
		snprintf(body, sizeof(body), "ngctl shutdown %s, on %s. The "
		    "node goes, with every hook it has.", arg, s->name);
		confirm("Shut the node down", body, "Shut down", true, "",
		    "do-ng-shutdown", arg, "");
	} else if (strcmp(act, "do-ng-rmhook") == 0 && s != NULL) {
		q = json_quote(arg);
		q2 = json_quote(value);
		snprintf(body, sizeof(body), "ngctl rmhook %s %s", arg, value);
		if_job(s, body, "netgraph", "{\"kind\":\"netgraph\",\"verb\":"
		    "\"rmhook\",\"args\":[%s,%s]}", q, q2);
		free(q);
		free(q2);
	} else if (strcmp(act, "do-ng-shutdown") == 0 && s != NULL) {
		q = json_quote(arg);
		snprintf(body, sizeof(body), "ngctl shutdown %s", arg);
		if_job(s, body, "netgraph", "{\"kind\":\"netgraph\",\"verb\":"
		    "\"shutdown\",\"args\":[%s]}", q);
		free(q);
		ng.sel[0] = '\0';
	}
	return (true);
}

/*
 * The route to an address, asked of the host whose routes are shown:
 * what it would take, and what covers the address besides.
 */
static struct {
	char		 sid[9];
	char		 addr[65];
	ucl_object_t	*data;
	bool		 busy;
	char		 error[200];
} lk;

static void
lookup_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	lk.busy = false;
	if (lk.data != NULL)
		ucl_object_unref(lk.data);
	lk.data = NULL;
	if (status == 200 && jbool(o, "ok") && jget(o, "data") != NULL) {
		lk.data = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o,
		    "data"));
		lk.error[0] = '\0';
	} else
		snprintf(lk.error, sizeof(lk.error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
}

void
topo_lookup(struct server *s, const char *addr, int fib)
{
	unsigned char	raw[16];
	char		url[520], clean[80];
	size_t		n;
	int		af;

	/*
	 * The address as it is meant: blanks around it (pasted) left out,
	 * a prefix's address looked up (10.1.0.0/24), an IPv6 zone
	 * (fe80::1%vtnet0) left out; IPv4 or IPv6 by its form.
	 */
	addr += strspn(addr, " \t\r\n");
	n = strcspn(addr, " \t\r\n/%");
	snprintf(clean, sizeof(clean), "%.*s", (int)(n < sizeof(clean) ? n :
	    sizeof(clean) - 1), addr);
	snprintf(lk.sid, sizeof(lk.sid), "%s", s->id);
	snprintf(lk.addr, sizeof(lk.addr), "%s", clean);
	if (lk.data != NULL)
		ucl_object_unref(lk.data);
	lk.data = NULL;
	if (!addr_bytes(clean, &af, raw)) {
		snprintf(lk.error, sizeof(lk.error), "%s is not an address: "
		    "an IPv4 one (192.0.2.10) or an IPv6 one (2001:db8::10)",
		    clean[0] != '\0' ? clean : "Nothing");
		return;
	}
	addr = lk.addr;
	lk.error[0] = '\0';
	lk.busy = true;
	snprintf(url, sizeof(url), "/api/servers/%s/net/lookup?to=%s&fib=%d"
	    "%s%s", s->id, addr, fib, net_scope()[0] != '\0' ? "&jail=" : "",
	    net_scope());
	api("GET", url, NULL, lookup_cb, NULL);
}

void
topo_lookup_clear(void)
{

	if (lk.data != NULL)
		ucl_object_unref(lk.data);
	lk.data = NULL;
	lk.error[0] = '\0';
	lk.sid[0] = '\0';
}

/* Above the routes: what the last lookup found. */
void
view_lookup(struct html *h, const struct server *s)
{
	const ucl_object_t	*c, *best, *cand[64];
	ucl_object_iter_t	 it;
	int			 i, n;

	if (strcmp(lk.sid, s->id) != 0)
		return;
	if (lk.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, lk.error);
		h_raw(h, "</div>");
		return;
	}
	if (lk.busy || lk.data == NULL)
		return;
	best = jget(lk.data, "best");
	h_raw(h, "<div class=\"notice info lookup\"><button class=\"icon\" "
	    "data-act=\"net-lookup-clear\" title=\"Close\">×</button><b>Route "
	    "to ");
	h_txt(h, lk.addr);
	h_raw(h, "</b>");
	if (best == NULL)
		h_raw(h, "<p>This host has no route to it.</p>");
	else {
		h_raw(h, "<p>out <b>");
		h_txt(h, jstr(best, "interface"));
		h_raw(h, "</b> via <b>");
		h_txt(h, jstr(best, "gateway"));
		h_raw(h, "</b> <span class=\"dim\">");
		h_txt(h, jstr(best, "flags"));
		h_raw(h, "</span></p>");
	}
	n = 0;
	it = NULL;
	while ((c = ucl_object_iterate(jget(lk.data, "candidates"), &it,
	    true)) != NULL && n < 64)
		cand[n++] = c;
	qsort(cand, (size_t)n, sizeof(cand[0]), cmp_plen);
	if (n > 0)
		h_raw(h, "<table class=\"net\"><thead><tr><th>Covering route"
		    "</th><th>Gateway</th><th>Flags</th><th>Interface</th>"
		    "</tr></thead><tbody>");
	for (i = 0; i < n; i++) {
		h_fmt(h, "<tr%s><td>", i == 0 && best != NULL ?
		    " class=\"best\"" : "");
		h_txt(h, jstr(cand[i], "destination"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(cand[i], "gateway"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(cand[i], "flags"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(cand[i], "interface-name"));
		h_raw(h, "</td></tr>");
	}
	if (n > 0)
		h_raw(h, "</tbody></table><small>The most specific is the one "
		    "taken; the others are what is left when it goes.</small>");
	h_raw(h, "</div>");
}

/* ---- Overlay › Quality: a tunnel measured from both its ends -------- */

/*
 * Each tunnel of the fleet with both its ends (gre, gif and the like
 * paired by their outer addresses, WireGuard by its peers' keys), or
 * the one end the fleet has.  Measured, it is four tunnel monitors, two
 * an end, each the agent's ICMP prober in a routing table of that end's:
 * the overlay, the far end's inner address in the interface's own FIB
 * (ov-<if>), and the underlay, the far end's outer address in the
 * interface's tunnelfib (ul-<if>).  Their samples are drawn per
 * criterion, loss, delay and jitter (the delay's variation), one line a
 * monitor.
 */
#define	TQ_PAIRS	256
#define	TQ_SERVERS	64
#define	TQ_TICK_MS	5000

struct tqend {
	int	node;			/* in tn[] */
	char	ifname[32];
	int	fib, tfib;
	char	inner[64];		/* its own inner address */
	char	far_outer[64];		/* the far end's outer, as it has it */
	char	ptp[64];		/* its point-to-point far end */
};
struct tqpair {
	struct tqend	a, b;
	bool		has_b;
	char		kind[24];
	char		key[200];
};
static struct tqpair	tqp[TQ_PAIRS];
static int		ntqp;

static struct {
	bool		 quality;	/* Overlay's sub-tab */
	char		 pick[200];	/* the pair whose charts are shown */
	char		 edit[200];	/* the pair in the dialog */
	struct {
		char		 sid[16];
		ucl_object_t	*o;	/* its monitors read's data */
		bool		 loading;
	}		 mon[TQ_SERVERS];
	int		 nmon;
	double		 fetched;
} tq;

/* An address without its port: host:port, [v6]:port. */
static void
tq_host(const char *ep, char *buf, size_t len)
{
	const char	*c;

	buf[0] = '\0';
	if (ep == NULL || (c = strrchr(ep, ':')) == NULL)
		return;
	if (ep[0] == '[')
		snprintf(buf, len, "%.*s", (int)(c - ep - 2), ep + 1);
	else
		snprintf(buf, len, "%.*s", (int)(c - ep), ep);
}

/* An interface's own inner address (inet first) and its far end. */
static void
tq_end_fill(struct tqend *e, int node, const char *ifname,
    const ucl_object_t *o)
{
	const ucl_object_t	*a;
	ucl_object_iter_t	 it;
	const char		*v6, *p6;

	memset(e, 0, sizeof(*e));
	e->node = node;
	snprintf(e->ifname, sizeof(e->ifname), "%s", ifname);
	e->fib = (int)jint(o, "fib", 0);
	e->tfib = (int)jint(o, "tunnelfib", 0);
	if (jstr(o, "tunnel.remote") != NULL)
		snprintf(e->far_outer, sizeof(e->far_outer), "%s", jstr(o,
		    "tunnel.remote"));
	v6 = p6 = NULL;
	it = NULL;
	while ((a = ucl_object_iterate(jget(o, "addresses"), &it, true)) !=
	    NULL) {
		if (jstr(a, "address") == NULL || strncmp(jstr(a, "address"),
		    "fe80", 4) == 0)
			continue;
		if (strchr(jstr(a, "address"), ':') == NULL) {
			if (e->inner[0] == '\0')
				snprintf(e->inner, sizeof(e->inner), "%s",
				    jstr(a, "address"));
			if (e->ptp[0] == '\0' && jstr(a, "destination") != NULL)
				snprintf(e->ptp, sizeof(e->ptp), "%s", jstr(a,
				    "destination"));
		} else {
			if (v6 == NULL)
				v6 = jstr(a, "address");
			if (p6 == NULL && jstr(a, "destination") != NULL)
				p6 = jstr(a, "destination");
		}
	}
	if (e->inner[0] == '\0' && v6 != NULL)
		snprintf(e->inner, sizeof(e->inner), "%s", v6);
	if (e->ptp[0] == '\0' && p6 != NULL)
		snprintf(e->ptp, sizeof(e->ptp), "%s", p6);
}

/* Its end's interface object: from the interfaces read, else a name. */
static const ucl_object_t *
tq_ifobj(struct thost *t, const char *name)
{

	return (if_named(t, name));
}

static void
tq_add(int i, const char *ifn, const ucl_object_t *o, int p, const char *pf,
    const ucl_object_t *fo, const char *kind)
{
	struct tqpair	*q;
	char		 ka[160], kb[160];

	if (ntqp == TQ_PAIRS)
		return;
	snprintf(ka, sizeof(ka), "%s/%s", tn[i].key, ifn);
	if (p >= 0) {
		snprintf(kb, sizeof(kb), "%s/%s", tn[p].key, pf);
		/* Each pair once, from its first end. */
		if (strcmp(ka, kb) > 0)
			return;
	}
	q = &tqp[ntqp++];
	memset(q, 0, sizeof(*q));
	tq_end_fill(&q->a, i, ifn, o);
	if (p >= 0) {
		tq_end_fill(&q->b, p, pf, fo);
		q->has_b = true;
	}
	snprintf(q->kind, sizeof(q->kind), "%s", kind);
	snprintf(q->key, sizeof(q->key), "%s%s%s", ka, p >= 0 ? " " : "",
	    p >= 0 ? kb : "");
}

/* The fleet's tunnels, paired. */
static void
tq_build(void)
{
	const ucl_object_t	*o, *f, *wi, *pr, *fw, *fp;
	ucl_object_iter_t	 it, fit, wit, pit, fwit, fpit;
	struct thost		*t, *ft;
	const char		*kind, *n, *other, *mykey;
	char			 host[64];
	int			 i, p, k;

	ntqp = 0;
	for (i = 0; i < ntn; i++) {
		if ((t = thost(tn[i].key, false)) == NULL)
			continue;
		/* gre, gif and the like: the far end by the outer addresses. */
		it = NULL;
		while ((o = ucl_object_iterate(jget(t->ifs, "interfaces"), &it,
		    true)) != NULL) {
			if ((n = jstr(o, "name")) == NULL || (kind = overlay_kind(t,
			    o)) == NULL || strcmp(kind, "WireGuard") == 0)
				continue;
			f = NULL;
			p = -1;
			if (jstr(o, "tunnel.remote") != NULL && (p = owner(jstr(o,
			    "tunnel.remote"), NULL, 0)) != -1 && (ft = thost(
			    tn[p].key, false)) != NULL) {
				fit = NULL;
				while ((f = ucl_object_iterate(jget(ft->ifs,
				    "interfaces"), &fit, true)) != NULL)
					if (jstr(f, "tunnel.remote") != NULL &&
					    jstr(o, "tunnel.local") != NULL &&
					    addr_same(jstr(f, "tunnel.remote"),
					    jstr(o, "tunnel.local")) && jstr(f,
					    "name") != NULL)
						break;
			}
			if (f == NULL)
				p = -1;
			tq_add(i, n, o, p, f != NULL ? jstr(f, "name") : "", f,
			    kind);
		}
		/* WireGuard: the far end by its peers' keys; the outer
		 * addresses each end's peer endpoint. */
		wit = NULL;
		while ((wi = ucl_object_iterate(jget(t->wg, "interfaces"), &wit,
		    true)) != NULL) {
			if ((n = jstr(wi, "name")) == NULL)
				continue;
			mykey = jstr(wi, "public-key");
			pit = NULL;
			while ((pr = ucl_object_iterate(jget(wi, "peers"), &pit,
			    true)) != NULL) {
				other = NULL;
				for (k = 0; k < nhosts && other == NULL; k++)
					if (&hosts[k] != t && (other = wg_iface(
					    &hosts[k], jstr(pr, "public-key"),
					    NULL)) != NULL)
						break;
				p = other != NULL ? node_index(hosts[k].sid) : -1;
				if (p == -1)
					other = NULL;
				tq_add(i, n, tq_ifobj(t, n), p, other != NULL ? other :
				    "", other != NULL ? tq_ifobj(&hosts[k], other) :
				    NULL, "WireGuard");
				if (ntqp == 0 || strcmp(tqp[ntqp - 1].a.ifname, n) !=
				    0 || tqp[ntqp - 1].a.node != i)
					continue;
				/* This end's far outer: its peer's endpoint. */
				tq_host(jstr(pr, "endpoint"), host, sizeof(host));
				snprintf(tqp[ntqp - 1].a.far_outer, sizeof(
				    tqp[0].a.far_outer), "%s", host);
				/* The far end's, its peer of this end's key. */
				fwit = NULL;
				while (other != NULL && (fw = ucl_object_iterate(
				    jget(hosts[k].wg, "interfaces"), &fwit,
				    true)) != NULL) {
					if (jstr(fw, "name") == NULL || strcmp(
					    jstr(fw, "name"), other) != 0)
						continue;
					fpit = NULL;
					while ((fp = ucl_object_iterate(jget(fw,
					    "peers"), &fpit, true)) != NULL)
						if (mykey != NULL && jstr(fp,
						    "public-key") != NULL && strcmp(
						    jstr(fp, "public-key"), mykey) ==
						    0) {
							tq_host(jstr(fp, "endpoint"),
							    host, sizeof(host));
							snprintf(tqp[ntqp - 1].b.
							    far_outer, sizeof(tqp[0].
							    b.far_outer), "%s", host);
						}
				}
			}
		}
	}
}

/* What a end probes: the far end's inner address, else its own
 * point-to-point far end. */
static const char *
tq_overlay_to(const struct tqend *e, const struct tqend *far)
{

	if (far != NULL && far->inner[0] != '\0')
		return (far->inner);
	return (e->ptp);
}

static void
tq_mon_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	int	k = (int)(intptr_t)arg;

	(void)err;
	if (k < 0 || k >= tq.nmon)
		return;
	tq.mon[k].loading = false;
	if (status != 200 || jget(o, "data") == NULL)
		return;
	if (tq.mon[k].o != NULL)
		ucl_object_unref(tq.mon[k].o);
	tq.mon[k].o = ucl_object_copy(jget(o, "data"));
	render();
}

/* A server's monitors, read when not yet, or again when asked. */
static const ucl_object_t *
tq_monitors(const char *sid, bool again)
{
	char	url[96];
	int	k;

	for (k = 0; k < tq.nmon; k++)
		if (strcmp(tq.mon[k].sid, sid) == 0)
			break;
	if (k == tq.nmon) {
		if (tq.nmon == TQ_SERVERS)
			return (NULL);
		memset(&tq.mon[k], 0, sizeof(tq.mon[k]));
		snprintf(tq.mon[k].sid, sizeof(tq.mon[k].sid), "%s", sid);
		tq.nmon++;
	}
	if ((tq.mon[k].o == NULL || again) && !tq.mon[k].loading) {
		tq.mon[k].loading = true;
		snprintf(url, sizeof(url), "/api/servers/%s/monitors", sid);
		api("GET", url, NULL, tq_mon_cb, (void *)(intptr_t)k);
	}
	return (tq.mon[k].o);
}

/* An end's monitor by its id (ov-<if>, ul-<if>), or NULL. */
static const ucl_object_t *
tq_find(const struct tqend *e, const char *prefix)
{
	const ucl_object_t	*all, *m;
	ucl_object_iter_t	 it;
	char			 id[48];

	snprintf(id, sizeof(id), "%s%s", prefix, e->ifname);
	if ((all = tq_monitors(app.servers[tn[e->node].srv].id, false)) ==
	    NULL)
		return (NULL);
	it = NULL;
	while ((m = ucl_object_iterate(jget(all, "monitors"), &it, true)) !=
	    NULL)
		if (strcmp(jstr(m, "jail") != NULL ? jstr(m, "jail") : "",
		    tn[e->node].jail) == 0 && jstr(m, "id") != NULL &&
		    strcmp(jstr(m, "id"), id) == 0)
			return (m);
	return (NULL);
}

/*
 * A tunnel's last probe sample, as Quality's monitor over it (ov-<if>)
 * on either end measured it: the one-way delay and its variation in ms,
 * the share lost.
 */
static bool
link_probe(const struct tlink *l, double *delay, double *ipdv, double *loss)
{
	const ucl_object_t	*all, *m, *last;
	ucl_object_iter_t	 it;
	const char		*ifn;
	char			 id[48];
	int			 end, n;

	for (end = 0; end < 2; end++) {
		n = end == 0 ? l->a : l->b;
		ifn = end == 0 ? l->ifa : l->ifb;
		if (n < 0 || n >= ntn || ifn[0] == '\0' || (all = tq_monitors(
		    app.servers[tn[n].srv].id, false)) == NULL)
			continue;
		snprintf(id, sizeof(id), "ov-%s", ifn);
		it = NULL;
		while ((m = ucl_object_iterate(jget(all, "monitors"), &it,
		    true)) != NULL) {
			if (jstr(m, "id") == NULL || strcmp(jstr(m, "id"), id) !=
			    0 || strcmp(jstr(m, "jail") != NULL ? jstr(m, "jail") :
			    "", tn[n].jail) != 0)
				continue;
			last = jget(m, "samples");
			if (last == NULL || ucl_array_size(last) == 0)
				continue;
			last = ucl_array_find_index(last,
			    ucl_array_size(last) - 1);
			if (ucl_array_size(last) < 4)
				continue;
			*delay = ucl_object_todouble(ucl_array_find_index(last,
			    1));
			*ipdv = ucl_object_todouble(ucl_array_find_index(last,
			    2));
			*loss = ucl_object_todouble(ucl_array_find_index(last,
			    3));
			return (true);
		}
	}
	return (false);
}

/* While the map is shown, the monitors of the hosts at a tunnel's end
 * read again now and then: its probes are drawn from them. */
void
topo_probe_tick(double now)
{
	static double	fetched;
	int		i;

	if (!app.visible || app.node != NODE_NETWORK || app.netsect !=
	    NETSECT_MAP || now - fetched < 3 * TQ_TICK_MS)
		return;
	fetched = now;
	for (i = 0; i < nlinks; i++)
		if (links[i].kind == LK_TUNNEL && links[i].b >= 0) {
			(void)tq_monitors(app.servers[tn[links[i].a].srv].id,
			    true);
			(void)tq_monitors(app.servers[tn[links[i].b].srv].id,
			    true);
		}
}

void
tq_refresh(void)
{
	int	k;

	for (k = 0; k < tq.nmon; k++)
		(void)tq_monitors(tq.mon[k].sid, true);
}

/* While Quality is shown, its monitors read again every few seconds. */
void
tq_tick(double now)
{

	if (!app.visible || app.node != NODE_NETWORK || app.netsect !=
	    NETSECT_OVERLAY || !tq.quality || now - tq.fetched < TQ_TICK_MS)
		return;
	tq.fetched = now;
	tq_refresh();
}

/* A monitor's last sample, in a cell: delay · jitter · loss. */
static void
tq_cell(struct html *h, const ucl_object_t *m)
{
	const ucl_object_t	*sm, *last;
	unsigned int		 n;

	if (m == NULL) {
		h_raw(h, "<td class=\"dim\">–</td>");
		return;
	}
	sm = jget(m, "samples");
	n = sm != NULL ? ucl_array_size(sm) : 0;
	if (n == 0 || strcmp(jstr(m, "state") != NULL ? jstr(m, "state") :
	    "", "error") == 0) {
		h_raw(h, "<td class=\"dim\">");
		h_txt(h, jstr(m, "error") != NULL ? jstr(m, "error") : jstr(m,
		    "state") != NULL ? jstr(m, "state") : "no sample yet");
		h_raw(h, "</td>");
		return;
	}
	last = ucl_array_find_index(sm, n - 1);
	h_fmt(h, "<td class=\"num tq-cell st-%s\">%.1f ms<small> ± %.1f · "
	    "%.1f %%</small></td>", jstr(m, "state") != NULL ? jstr(m, "state") :
	    "unknown", ucl_object_todouble(ucl_array_find_index(last, 1)),
	    ucl_object_todouble(ucl_array_find_index(last, 2)),
	    ucl_object_todouble(ucl_array_find_index(last, 3)) * 100);
}

/* A chart's top: 1, 2 or 5 of a power of ten, at or over v. */
static double
nice_top(double v)
{
	double	m = 1;

	while (v / m >= 10)
		m *= 10;
	while (v / m < 1)
		m /= 10;
	return (v / m <= 1 ? m : v / m <= 2 ? 2 * m : v / m <= 5 ? 5 * m :
	    10 * m);
}

/* One criterion's chart: a line for each monitor, over their samples'
 * times. */
static void
tq_chart(struct html *h, const char *title, const char *unit, int col,
    double scale, const ucl_object_t *const *ms, const char *const *names)
{
	const ucl_object_t	*sm, *row;
	double			 t0, t1, top, v, t;
	unsigned int		 n, i;
	int			 k, any;

	t0 = t1 = 0;
	top = 0;
	any = 0;
	for (k = 0; k < 4; k++) {
		if (ms[k] == NULL || (sm = jget(ms[k], "samples")) == NULL)
			continue;
		n = ucl_array_size(sm);
		for (i = 0; i < n; i++) {
			row = ucl_array_find_index(sm, i);
			t = ucl_object_todouble(ucl_array_find_index(row, 0));
			v = ucl_object_todouble(ucl_array_find_index(row, col)) *
			    scale;
			if (any == 0 || t < t0)
				t0 = t;
			if (any == 0 || t > t1)
				t1 = t;
			if (v > top)
				top = v;
			any = 1;
		}
	}
	h_fmt(h, "<figure class=\"tq-chart\"><figcaption><b>%s</b>", title);
	if (!any) {
		h_raw(h, " <span class=\"dim\">no sample yet</span></figcaption>"
		    "</figure>");
		return;
	}
	top = nice_top(top > 0 ? top : 1);
	h_fmt(h, " <span class=\"dim\">up to %g %s</span></figcaption><svg "
	    "viewBox=\"0 0 600 120\" preserveAspectRatio=\"none\" role=\"img\" "
	    "aria-label=\"%s over time, each end, overlay and underlay\">",
	    top, unit, title);
	for (k = 0; k < 4; k++) {
		if (ms[k] == NULL || (sm = jget(ms[k], "samples")) == NULL ||
		    (n = ucl_array_size(sm)) == 0)
			continue;
		h_fmt(h, "<path class=\"tq%d\" d=\"", k);
		for (i = 0; i < n; i++) {
			row = ucl_array_find_index(sm, i);
			t = ucl_object_todouble(ucl_array_find_index(row, 0));
			v = ucl_object_todouble(ucl_array_find_index(row, col)) *
			    scale;
			h_fmt(h, "%c%.1f %.1f ", i == 0 ? 'M' : 'L', t1 > t0 ?
			    (t - t0) / (t1 - t0) * 600 : 600, 118 - v / top *
			    114);
		}
		h_raw(h, "\"/>");
	}
	h_raw(h, "</svg><div class=\"tq-legend\">");
	for (k = 0; k < 4; k++)
		if (ms[k] != NULL) {
			h_fmt(h, "<span class=\"tq%d\">", k);
			h_txt(h, names[k]);
			h_raw(h, "</span>");
		}
	h_raw(h, "</div></figure>");
}

/* A pair's ends, named: host · interface. */
static void
tq_end_name(const struct tqend *e, char *buf, size_t len)
{

	snprintf(buf, len, "%s · %s", tn[e->node].label, e->ifname);
}

static void
tq_view(struct html *h)
{
	const ucl_object_t	*ms[4];
	const struct tqpair	*q;
	char			 an[200], bn[200], names[4][240];
	const char		*np[4];
	int			 i, k;

	tq_build();
	h_raw(h, "<p class=\"dim tq-about\">Each tunnel measured from both its "
	    "ends: over the tunnel (overlay), the far end's inner address in "
	    "the interface's own routing table; under it (underlay), the far "
	    "end's outer address in the interface's tunnelfib. The last "
	    "sample's delay, jitter (its variation) and loss; a tunnel picked, "
	    "each criterion over time.</p>");
	if (ntqp == 0) {
		h_raw(h, "<div class=\"empty\"><h2>No tunnels</h2><p>No host of "
		    "the fleet has a tunnel, or their interfaces are being read."
		    "</p></div>");
		return;
	}
	h_raw(h, "<div class=\"scrollx\"><table class=\"net tq\"><thead><tr><th>"
	    "Tunnel</th><th>Kind</th><th class=\"num\">Overlay A → B</th><th "
	    "class=\"num\">Overlay B → A</th><th class=\"num\">Underlay A → B"
	    "</th><th class=\"num\">Underlay B → A</th><th></th></tr></thead>"
	    "<tbody>");
	for (i = 0; i < ntqp; i++) {
		q = &tqp[i];
		if (app.filter[0] != '\0' && strstr(q->key, app.filter) == NULL)
			continue;
		tq_end_name(&q->a, an, sizeof(an));
		if (q->has_b)
			tq_end_name(&q->b, bn, sizeof(bn));
		ms[0] = tq_find(&q->a, "ov-");
		ms[1] = q->has_b ? tq_find(&q->b, "ov-") : NULL;
		ms[2] = tq_find(&q->a, "ul-");
		ms[3] = q->has_b ? tq_find(&q->b, "ul-") : NULL;
		h_fmt(h, "<tr class=\"pick%s\" data-act=\"tq-pick\"", strcmp(
		    tq.pick, q->key) == 0 ? " on" : "");
		h_attr(h, "data-arg", q->key);
		h_raw(h, "><td><b>A</b> ");
		h_txt(h, an);
		h_raw(h, "<br><b>B</b> ");
		if (q->has_b)
			h_txt(h, bn);
		else
			h_raw(h, "<span class=\"dim\">not in the fleet: measured "
			    "from A alone</span>");
		h_raw(h, "</td><td>");
		h_txt(h, q->kind);
		h_raw(h, "</td>");
		for (k = 0; k < 4; k++)
			tq_cell(h, ms[k]);
		h_raw(h, "<td class=\"acts\">");
		if (ms[0] == NULL && ms[1] == NULL && ms[2] == NULL && ms[3] ==
		    NULL) {
			h_raw(h, "<button class=\"small\" data-act=\"tq-measure\"");
			h_attr(h, "data-arg", q->key);
			h_raw(h, ">Measure</button>");
		} else {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "tq-measure\"");
			h_attr(h, "data-arg", q->key);
			h_fmt(h, ">Change</button> <button class=\"ghost small%s\" "
			    "data-act=\"tq-pick\" title=\"Loss, delay and jitter "
			    "over time\"", strcmp(tq.pick, q->key) == 0 ? " on" : "");
			h_attr(h, "data-arg", q->key);
			h_raw(h, ">Charts</button> <button class=\"ghost small\" "
			    "data-act=\"tq-stop\"");
			h_attr(h, "data-arg", q->key);
			h_raw(h, ">Stop</button>");
		}
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table></div>");
	/* The tunnel picked: each criterion over time, a chart each. */
	for (i = 0; i < ntqp; i++) {
		q = &tqp[i];
		if (strcmp(tq.pick, q->key) != 0)
			continue;
		ms[0] = tq_find(&q->a, "ov-");
		ms[1] = q->has_b ? tq_find(&q->b, "ov-") : NULL;
		ms[2] = tq_find(&q->a, "ul-");
		ms[3] = q->has_b ? tq_find(&q->b, "ul-") : NULL;
		tq_end_name(&q->a, an, sizeof(an));
		if (q->has_b)
			tq_end_name(&q->b, bn, sizeof(bn));
		snprintf(names[0], sizeof(names[0]), "overlay, A → B");
		snprintf(names[1], sizeof(names[1]), "overlay, B → A");
		snprintf(names[2], sizeof(names[2]), "underlay, A → B");
		snprintf(names[3], sizeof(names[3]), "underlay, B → A");
		for (k = 0; k < 4; k++)
			np[k] = names[k];
		h_raw(h, "<section class=\"tq-detail\"><h3><span class=\"tq-a\">"
		    "A</span> ");
		h_txt(h, an);
		h_raw(h, " and <span class=\"tq-b\">B</span> ");
		h_txt(h, q->has_b ? bn : "outside the fleet");
		h_raw(h, "</h3><div class=\"tq-grid\">");
		tq_chart(h, "Loss", "%", 3, 100, ms, np);
		tq_chart(h, "Delay", "ms", 1, 1, ms, np);
		tq_chart(h, "Jitter", "ms", 2, 1, ms, np);
		h_raw(h, "</div></section>");
	}
}

static const struct tqpair *
tq_pair(const char *key)
{
	int	i;

	tq_build();
	for (i = 0; key != NULL && i < ntqp; i++)
		if (strcmp(tqp[i].key, key) == 0)
			return (&tqp[i]);
	return (NULL);
}

/* An end's fields in the dialog: its overlay's and underlay's targets and
 * tables, as now measured or as the hosts say. */
static void
tq_modal_end(struct html *h, const char *side, const struct tqend *e,
    const struct tqend *far)
{
	const ucl_object_t	*ov, *ul;
	char			 nm[200], buf[32];

	ov = tq_find(e, "ov-");
	ul = tq_find(e, "ul-");
	tq_end_name(e, nm, sizeof(nm));
	h_fmt(h, "<fieldset><legend>%s: ", side);
	h_txt(h, nm);
	h_raw(h, "</legend><div class=\"two\"><label>Overlay: probe<input "
	    "spellcheck=\"false\" autocomplete=\"off\"");
	h_fmt(h, " name=\"%s_ov\"", side);
	h_attr(h, "value", ov != NULL ? jstr(ov, "address") : tq_overlay_to(e,
	    far));
	h_raw(h, "><small>The far end's inner address.</small></label><label>"
	    "in FIB<input inputmode=\"numeric\"");
	h_fmt(h, " name=\"%s_ovfib\"", side);
	snprintf(buf, sizeof(buf), "%lld", ov != NULL ? (long long)jint(ov,
	    "fib", 0) : (long long)e->fib);
	h_attr(h, "value", buf);
	h_raw(h, "><small>The interface's.</small></label></div><div class="
	    "\"two\"><label>Underlay: probe<input spellcheck=\"false\" "
	    "autocomplete=\"off\"");
	h_fmt(h, " name=\"%s_ul\"", side);
	h_attr(h, "value", ul != NULL ? jstr(ul, "address") : e->far_outer);
	h_raw(h, "><small>The far end's outer address; empty: not "
	    "measured.</small></label><label>in FIB<input inputmode=\"numeric\"");
	h_fmt(h, " name=\"%s_ulfib\"", side);
	snprintf(buf, sizeof(buf), "%lld", ul != NULL ? (long long)jint(ul,
	    "fib", 0) : (long long)e->tfib);
	h_attr(h, "value", buf);
	h_raw(h, "><small>The tunnel's outer packets' (tunnelfib).</small>"
	    "</label></div></fieldset>");
}

bool
tq_modal(struct html *h)
{
	const struct tqpair	*q;

	if ((q = tq_pair(tq.edit)) == NULL)
		return (false);
	h_raw(h, "<form data-form=\"tq-set\"><h2>Measure the tunnel</h2><p>"
	    "Each end probes the other by ICMP echo, over the tunnel and under "
	    "it, each in its own routing table: four monitors, kept by the "
	    "agents and read here.</p>");
	tq_modal_end(h, "A", &q->a, q->has_b ? &q->b : NULL);
	if (q->has_b)
		tq_modal_end(h, "B", &q->b, &q->a);
	h_raw(h, "<div class=\"two\"><label>Every (ms)<input name=\"interval\" "
	    "inputmode=\"numeric\" value=\"500\"></label><label>A sample of "
	    "(ms)<input name=\"eval\" inputmode=\"numeric\" value=\"10000\">"
	    "</label></div>");
	return (true);
}

/* An end's monitor set (or, address empty, taken away when there). */
static void
tq_send(const struct tqend *e, const char *prefix, const char *addr,
    const char *fib, const char *interval, const char *eval)
{
	struct server	*s;
	const char	*w[6];
	char		 a[6][96], title[160], extra[96], *q, *json;
	size_t		 n;

	s = &app.servers[tn[e->node].srv];
	extra[0] = '\0';
	if (tn[e->node].jail[0] != '\0') {
		q = json_quote(tn[e->node].jail);
		snprintf(extra, sizeof(extra), ",\"jail\":%s", q);
		free(q);
	}
	snprintf(a[0], sizeof(a[0]), "name=%s%s", prefix, e->ifname);
	w[0] = a[0];
	if (addr == NULL || addr[0] == '\0') {
		if (tq_find(e, prefix) == NULL)
			return;
		snprintf(title, sizeof(title), "monitor remove %s%s", prefix,
		    e->ifname);
		json = job_json("monitor", "remove", w, 1, NULL, extra[0] !=
		    '\0' ? extra : NULL);
	} else {
		n = 1;
		snprintf(a[n], sizeof(a[n]), "interface=%s", e->ifname);
		w[n] = a[n];
		n++;
		snprintf(a[n], sizeof(a[n]), "address=%s", addr);
		w[n] = a[n];
		n++;
		snprintf(a[n], sizeof(a[n]), "fib=%s", fib[0] != '\0' ? fib : "0");
		w[n] = a[n];
		n++;
		if (interval[0] != '\0') {
			snprintf(a[n], sizeof(a[n]), "interval=%s", interval);
			w[n] = a[n];
			n++;
		}
		if (eval[0] != '\0') {
			snprintf(a[n], sizeof(a[n]), "eval=%s", eval);
			w[n] = a[n];
			n++;
		}
		snprintf(title, sizeof(title), "monitor set %s%s", prefix,
		    e->ifname);
		json = job_json("monitor", "set", w, n, NULL, extra[0] != '\0' ?
		    extra : NULL);
	}
	job_send(s, json, title, JOB_MONITOR, tn[e->node].jail[0] != '\0' ?
	    tn[e->node].jail : s->name);
}

static const char *
tq_fv(const ucl_object_t *f, const char *key)
{

	return (jstr(f, key) != NULL ? jstr(f, key) : "");
}

bool
tq_form(const char *form, const ucl_object_t *f)
{
	const struct tqpair	*q;
	const char		*iv, *ev;

	if (strcmp(form, "tq-set") != 0)
		return (false);
	if ((q = tq_pair(tq.edit)) != NULL) {
		iv = tq_fv(f, "interval");
		ev = tq_fv(f, "eval");
		tq_send(&q->a, "ov-", tq_fv(f, "A_ov"), tq_fv(f, "A_ovfib"), iv,
		    ev);
		tq_send(&q->a, "ul-", tq_fv(f, "A_ul"), tq_fv(f, "A_ulfib"), iv,
		    ev);
		if (q->has_b) {
			tq_send(&q->b, "ov-", tq_fv(f, "B_ov"), tq_fv(f,
			    "B_ovfib"), iv, ev);
			tq_send(&q->b, "ul-", tq_fv(f, "B_ul"), tq_fv(f,
			    "B_ulfib"), iv, ev);
		}
		snprintf(tq.pick, sizeof(tq.pick), "%s", q->key);
	}
	app.modal = MODAL_NONE;
	return (true);
}

bool
tq_action(const char *act, const char *arg, const char *value)
{
	const struct tqpair	*q;
	char			 body[300];

	(void)value;
	if (strcmp(act, "ov-sub") == 0) {
		tq.quality = arg != NULL && strcmp(arg, "quality") == 0;
		if (tq.quality)
			tq_refresh();
		return (true);
	}
	if (strncmp(act, "tq-", 3) != 0)
		return (false);
	if (strcmp(act, "tq-pick") == 0) {
		snprintf(tq.pick, sizeof(tq.pick), "%s", arg != NULL && strcmp(
		    tq.pick, arg) != 0 ? arg : "");
		return (true);
	}
	if (strcmp(act, "tq-measure") == 0) {
		snprintf(tq.edit, sizeof(tq.edit), "%s", arg != NULL ? arg : "");
		app.modal = MODAL_TQ;
		app.modal_error[0] = '\0';
		return (true);
	}
	if (strcmp(act, "tq-stop") == 0) {
		snprintf(body, sizeof(body), "Its monitors stop, at both ends: "
		    "their samples go with them. The tunnel is not touched.");
		confirm("Stop measuring the tunnel?", body, "Stop", true, "",
		    "tq-do-stop", arg, "");
		return (true);
	}
	if (strcmp(act, "tq-do-stop") == 0 && (q = tq_pair(arg)) != NULL) {
		tq_send(&q->a, "ov-", "", "", "", "");
		tq_send(&q->a, "ul-", "", "", "", "");
		if (q->has_b) {
			tq_send(&q->b, "ov-", "", "", "", "");
			tq_send(&q->b, "ul-", "", "", "", "");
		}
		return (true);
	}
	return (false);
}

/* Overlay's sub-tabs: its tunnels' table, or their quality. */
bool
overlay_quality(struct html *h)
{

	h_fmt(h, "<div class=\"toolbar\"><nav class=\"sub ov-sub\"><button "
	    "class=\"ghost small%s\" "
	    "data-act=\"ov-sub\" data-arg=\"tunnels\">Tunnels</button><button "
	    "class=\"ghost small%s\" data-act=\"ov-sub\" data-arg=\"quality\" "
	    "title=\"Loss, delay and jitter, each tunnel from both its ends, "
	    "over it and under it\">Quality</button></nav></div>", tq.quality ?
	    "" :
	    " on", tq.quality ? " on" : "");
	if (!tq.quality)
		return (false);
	tq_view(h);
	return (true);
}
