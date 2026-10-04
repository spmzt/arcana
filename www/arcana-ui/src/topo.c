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
#define	TOPO_LINKS	256
#define	TOPO_SEGS	48
#define	TOPO_HOPS	16
#define	TOPO_ALTS	3
#define	NODE_W		150
#define	NODE_H		58
#define	VIEW_W		1000.0
#define	VIEW_H		600.0

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
	ucl_object_t	*wg;		/* its WireGuard interfaces */
	bool		 wg_loading;
	ucl_object_t	*bird;		/* what its BIRD says, if it has one */
	bool		 bird_loading;
};

/*
 * A routing neighbour that is not a host of this console: drawn beside
 * the host that speaks to it.
 */
#define	EXT_MAX		160
#define	EXT_PER_HOST	8
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

struct tlink {
	int	a, b;			/* servers; b < 0: segment -b - 1 */
	int	kind;
	char	ifa[16], ifb[16];
	char	key[160];		/* what makes it this link */
	char	label[160];
	double	rate;			/* bytes a second, both ways */
	bool	up;
	int	more;			/* networks shared besides the one named */
};

/* A network more than two hosts are in: a node of its own. */
struct seg {
	char	net[64];
	int	member[MAX_NODES];
	char	ifn[MAX_NODES][16];
	int	n;
	double	x, y;
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
static int		nsegs;

static struct {
	double	zoom, panx, pany;
	double	lastcx, lastcy;		/* a pan under way: where it was */
	bool	fitted;			/* shown whole once, at first */
	bool	refitted;		/* and again, with neighbours outside */
	bool	jails;			/* each host's running jails around it */
	bool	nopeers;		/* routing neighbours outside are hidden */
	char	sel[80];		/* the node picked, or "" */
	char	sel_if[16];		/* and its interface charted */
	char	sel_link[80];		/* or the link picked */
	bool	linking;		/* a link is being drawn */
	char	link_from[80];
	double	link_x, link_y;
	bool	loaded;			/* the places kept were read */
	char	tun_a[80], tun_b[80];	/* the tunnel asked for */
	char	create_sid[80];		/* the node an interface is made on */
	int	fit_n;			/* the nodes there were when fitted */
	bool	touched;		/* moved, zoomed: no fitting unasked */
	int	labels;			/* 0 as fits, 1 shown, 2 left out */
	bool	hide[LK_KINDS];		/* kinds of links not drawn */
	bool	hide_best, hide_alt;	/* nor the route traced */
	double	last_poll;
} tp = { .zoom = 1.0 };

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
static int		 owner(const char *, char *, size_t);
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
		while (app.servers[i].list != NULL && (j = ucl_object_iterate(
		    jget(app.servers[i].list, "jails"), &it, true)) != NULL &&
		    ntn < MAX_NODES) {
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
		}
	free(text);
}

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

/* Hosts not placed yet go on a circle, in the order of the tree. */
static void
places_fill(void)
{
	struct thost	*t;
	double		 r, a;
	int		 i;

	if (!tp.loaded)
		places_load();
	r = app.nservers < 3 ? 170 : 120 + 26.0 * app.nservers;
	if (r > 520)
		r = 520;
	for (i = 0; i < ntn; i++) {
		if ((t = thost(tn[i].key, true)) == NULL || t->placed)
			continue;
		if (tn[i].jail[0] != '\0') {
			/* A jail: under its host, beside the others of it. */
			struct thost	*ht;
			int		 k, nth;

			if ((ht = thost(tn[node_host(i)].key, false)) == NULL ||
			    !ht->placed)
				continue;
			for (nth = 0, k = app.nservers; k < i; k++)
				if (tn[k].srv == tn[i].srv)
					nth++;
			t->x = ht->x + ((nth + 1) / 2) * (nth % 2 == 1 ? -1 :
			    1) * (NODE_W + 30);
			t->y = ht->y + NODE_H + 90;
			t->placed = true;
			continue;
		}
		a = M_PI + 2 * M_PI * i / (app.nservers > 0 ? app.nservers :
		    1);
		t->x = app.nservers == 1 ? 0 : r * cos(a) * 1.35;
		t->y = app.nservers == 1 ? 0 : r * sin(a) * 0.8;
		t->placed = true;
	}
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

/* A reading of a host's interfaces: kept, and made into rates. */
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

	if (!app.online || !plugin_at(&app.servers[tn[i].srv], tn[i].jail,
	    "wireguard") || (t = thost(tn[i].key, true)) == NULL ||
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
			if (wg_turn == 0) {
				wg_poll(i);
				bird_poll(i);
			}
		}
		render();
	} else if (((app.node == NODE_HOST && app.tab == TAB_NETWORK) ||
	    net_scope()[0] != '\0') && app.net.kind == NET_INTERFACES &&
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

/* The links, from the interfaces every host has now. */
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
						if ((l = link_add(s, peer, LK_P2P,
						    jstr(o, "name"), ifb,
						    jstr(a, "address"),
						    jstr(a, "destination"))) !=
						    NULL)
							l->up = l->up ||
							    jbool(o, "up");
					}
					continue;
				}
				/* A network shared: gathered, joined below. */
				if (!net_of(jstr(a, "address"), (int)jint(a,
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
					if ((l = link_add(s, peer, LK_TUNNEL,
					    jstr(o, "name"), other, jstr(o,
					    "public-key"), jstr(p,
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
							snprintf(l->label,
							    sizeof(l->label),
							    "BGP AS%s ⇄ AS%s",
							    jstr(o, "local-as") !=
							    NULL ? jstr(o,
							    "local-as") : "?",
							    jstr(o,
							    "neighbor-as") !=
							    NULL ? jstr(o,
							    "neighbor-as") : "?");
					}
					continue;
				}
				if (nexts == EXT_MAX || mine == EXT_PER_HOST)
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
		for (k = nexts - mine; k < nexts; k++)
			exts[k].of = mine;
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
			if (i < nlinks) {
				links[i].more++;
				continue;
			}
			if ((l = link_add(sg->member[0], sg->member[1], LK_LAN,
			    sg->ifn[0], sg->ifn[1], sg->net, "")) != NULL)
				l->up = true;
		} else if (sg->n > 2) {
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
	int	k, n;

	n = 0;
	for (k = 0; k < i; k++)
		if ((links[k].a == links[i].a && links[k].b == links[i].b) ||
		    (links[k].a == links[i].b && links[k].b == links[i].a))
			n++;
	if (n == 0)
		return (0);
	return ((n % 2 == 1 ? 1 : -1) * 34.0 * ((n + 1) / 2));
}

static void
map_links(struct html *h)
{
	static const char *const kinds[] = { "tunnel", "p2p", "lan", "bgp",
	    "ospf", "vnet" };
	struct tlink	*l;
	char		 rate[24];
	double		 x1, y1, x2, y2, mx, my, bend, w;
	int		 i, flow;

	for (i = 0; i < nlinks; i++) {
		l = &links[i];
		if (tp.hide[l->kind] || !place(l->a, &x1, &y1) || !place(l->b,
		    &x2, &y2))
			continue;
		bend = bend_of(i);
		w = 1.6 + log10(1 + l->rate / 1000.0) * 1.1;
		if (w > 7)
			w = 7;
		flow = l->rate < 1000 ? 0 : l->rate < 100000 ? 1 : l->rate <
		    10000000 ? 2 : 3;
		h_fmt(h, "<g class=\"tlink %s %s flow%d%s\"><path class=\"wire\" "
		    "style=\"stroke-width:%.1f\" d=\"", kinds[l->kind], l->up ?
		    "up" : "down", flow, strcmp(tp.sel_link, l->key) == 0 ?
		    " sel" : "", w);
		curve(h, x1, y1, x2, y2, bend, 0.5, &mx, &my);
		h_raw(h, "\"/>");
		if (flow > 0) {
			h_raw(h, "<path class=\"flow\" d=\"");
			curve(h, x1, y1, x2, y2, bend, 0.5, NULL, NULL);
			h_raw(h, "\"/>");
		}
		h_raw(h, "<path class=\"hit\" data-act=\"topo-sel-link\"");
		h_attr(h, "data-arg", l->key);
		h_raw(h, " d=\"");
		curve(h, x1, y1, x2, y2, bend, 0.5, NULL, NULL);
		h_raw(h, "\"><title>");
		h_txt(h, l->label);
		h_raw(h, "</title></path>");
		if (l->b >= 0) {
			h_fmt(h, "<text class=\"lbl\" x=\"%.1f\" y=\"%.1f\">", mx,
			    my - 6);
			h_txt(h, l->kind == LK_LAN || l->kind >= LK_BGP ?
			    l->label : l->ifa);
			if (l->kind < LK_LAN && l->ifb[0] != '\0') {
				h_raw(h, " ⇄ ");
				h_txt(h, l->ifb);
			}
			if (l->more > 0)
				h_fmt(h, " +%d", l->more);
			h_raw(h, "</text>");
		}
		if (l->rate >= 1) {
			fmt_rate(rate, sizeof(rate), l->rate);
			h_fmt(h, "<text class=\"rate\" x=\"%.1f\" y=\"%.1f\">",
			    mx, my + 12);
			h_txt(h, rate);
			h_raw(h, "</text>");
		}
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

static void
map_nodes(struct html *h)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	struct server		*s;
	struct thost		*t;
	char			 rate[24], sub[64];
	double			 total;
	int			 i, k, nif;

	for (k = 0; k < nsegs; k++) {
		if (segs[k].n < 3)
			continue;
		h_fmt(h, "<g class=\"tseg\" transform=\"translate(%.1f,%.1f)\">"
		    "<rect x=\"-9\" y=\"-9\" width=\"18\" height=\"18\" "
		    "transform=\"rotate(45)\"/><text y=\"28\">", segs[k].x,
		    segs[k].y);
		h_txt(h, segs[k].net);
		h_raw(h, "</text></g>");
	}
	/* The routing neighbours outside, fanned out away from the middle. */
	for (i = 0; !tp.nopeers && i < nexts; i++) {
		if (tp.hide[exts[i].ospf ? LK_OSPF : LK_BGP])
			continue;
		struct ext	*e = &exts[i];
		double		 cx, cy, a, ex, ey;
		int		 m;

		if ((t = thost(tn[e->host].key, false)) == NULL)
			continue;
		cx = cy = 0;
		for (m = 0, k = 0; k < nhosts; k++)
			if (hosts[k].placed && node_index(hosts[k].sid) !=
			    -1) {
				cx += hosts[k].x;
				cy += hosts[k].y;
				m++;
			}
		cx = m > 0 ? cx / m : 0;
		cy = m > 0 ? cy / m : 0;
		a = fabs(t->x - cx) + fabs(t->y - cy) < 1 ? -M_PI / 2 :
		    atan2(t->y - cy, t->x - cx);
		/*
		 * On two rings, every other one further out: side by
		 * side on one ring they would lie on each other.
		 */
		a += (e->slot - (e->of - 1) / 2.0) * 0.36;
		ex = t->x + 185 * (e->slot % 2 == 1 ? 1.5 : 1.0) * cos(a);
		ey = t->y + 125 * (e->slot % 2 == 1 ? 1.5 : 1.0) * sin(a);
		h_fmt(h, "<g class=\"tpeer %s %s\" data-act=\"topo-open-bird\"",
		    e->ospf ? "ospf" : "bgp", e->up ? "up" : "down");
		h_attr(h, "data-arg", tn[e->host].key);
		h_fmt(h, "><path d=\"M%.1f %.1f L%.1f %.1f\"/><rect x=\"%.1f\" "
		    "y=\"%.1f\" width=\"112\" height=\"34\" rx=\"17\"/><text "
		    "class=\"name\" x=\"%.1f\" y=\"%.1f\">", t->x, t->y, ex, ey,
		    ex - 56, ey - 17, ex, ey - 2);
		h_txt(h, e->label);
		h_fmt(h, "</text><text class=\"sub\" x=\"%.1f\" y=\"%.1f\">", ex,
		    ey + 10);
		h_txt(h, e->sub);
		h_raw(h, "</text><title>");
		h_txt(h, e->ospf ? "An OSPF neighbour outside this console" :
		    "A BGP neighbour outside this console");
		h_raw(h, "</title></g>");
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
	for (i = 0; i < ntn; i++) {
		const char	*key = tn[i].key;

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
		    tn[i].jail[0] != '\0' ? " jail" : "", t->x, t->y);
		h_attr(h, "data-arg", key);
		h_attr(h, "data-drop", key);
		h_fmt(h, "><rect class=\"box\" x=\"%d\" y=\"%d\" width=\"%d\" "
		    "height=\"%d\" rx=\"10\"/><circle class=\"led\" cx=\"%d\" "
		    "cy=\"-10\" r=\"4\"/><text class=\"name\" x=\"%d\" y=\"-5\">",
		    -NODE_W / 2, -NODE_H / 2, NODE_W, NODE_H, -NODE_W / 2 + 14,
		    -NODE_W / 2 + 26);
		h_txt(h, tn[i].name);
		h_fmt(h, "</text><text class=\"sub\" x=\"%d\" y=\"15\">",
		    -NODE_W / 2 + 12);
		if (t->ifs == NULL)
			snprintf(sub, sizeof(sub), "%s", t->failed ?
			    "no answer" : "reading…");
		else {
			fmt_rate(rate, sizeof(rate), total);
			snprintf(sub, sizeof(sub), "%s%d if · %s", tn[i].jail[0] !=
			    '\0' ? "jail · " : "", nif, rate);
		}
		h_txt(h, sub);
		h_fmt(h, "</text><circle class=\"port\" cx=\"%d\" cy=\"0\" "
		    "r=\"7\" data-drag=\"topo-link\"", NODE_W / 2);
		h_attr(h, "data-arg", key);
		h_raw(h, "><title>Drag to another host to join them with a "
		    "tunnel</title></circle></g>");
	}
}

/*
 * The classes of the map's drawing.  With many links their labels run
 * into each other: they are left out then, and a link shows its own
 * when the pointer is on it or it is picked; "Labels" says otherwise.
 */
static const char *
wfmt_cls(void)
{
	static char	cls[40];
	bool		quiet;

	quiet = tp.labels == 2 || (tp.labels == 0 && nlinks > 6);
	snprintf(cls, sizeof(cls), "%s%s", tp.linking ? " linking" : "",
	    quiet ? " quiet" : "");
	return (cls);
}

static void
map(struct html *h)
{
	struct thost	*t;
	double		 w, ht;

	w = VIEW_W / tp.zoom;
	ht = VIEW_H / tp.zoom;
	h_fmt(h, "<div class=\"map-wrap\"><svg class=\"topo%s\" viewBox=\""
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
	map_links(h);
	map_path(h);
	if (tp.linking && (t = thost(tp.link_from, false)) != NULL)
		h_fmt(h, "<path class=\"tdraft\" d=\"M%.1f %.1f L%.1f %.1f\"/>",
		    t->x + NODE_W / 2, t->y, tp.link_x, tp.link_y);
	map_nodes(h);
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
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"topo-labels\" "
	    "title=\"What each line is and carries, written on it\">Labels"
	    "</button>", tp.labels == 2 || (tp.labels == 0 && nlinks > 6) ?
	    "" : " on");
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"topo-peers\" "
	    "title=\"BGP and OSPF neighbours that are not hosts of this "
	    "console\">Peers</button>", tp.nopeers ? "" : " on");
	/* The legend says what a line is, and takes its kind away or back. */
	h_raw(h, "</div><ul class=\"map-legend\">");
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

	h_raw(h, "<section class=\"pane path\"><h4>Route between hosts</h4>"
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
	    "topo-trace\"%s>Trace</button>", path.busy ? " disabled" : "");
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
		h_fmt(h, "<li class=\"%s%s\" data-act=\"topo-sel-if\"", jbool(o,
		    "up") ? "up" : "down", strcmp(tp.sel_if, name) == 0 ?
		    " sel" : "");
		h_attr(h, "data-arg", name);
		h_raw(h, "><div class=\"ifhead\"><i class=\"led\"></i><b>");
		h_txt(h, name);
		h_raw(h, "</b>");
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
	wg_sessions(h);
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
	if ((!tp.fitted || (tp.fit_n != ntn && !tp.touched)) && ntn > 0) {
		tp.fitted = true;
		tp.fit_n = ntn;
		fit();
	}
	links_build();
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
		h_raw(h, "<form data-form=\"tunnel\"><h2>Join ");
		h_txt(h, tn[a].label);
		h_raw(h, " and ");
		h_txt(h, tn[b].label);
		h_raw(h, "</h2><p>An interface is created on each host, the "
		    "two ends of one tunnel, with <code>ifconfig</code>. Each "
		    "is made in safe mode: a host that cannot be reached "
		    "again afterwards destroys its end by itself. For "
		    "WireGuard each host makes its own key and keeps it; the "
		    "two are told of each other by their public keys once "
		    "both have one.</p>"
		    "<label>Kind<select name=\"type\"><option value=\"gif\">"
		    "gif: IP in IP</option><option value=\"gre\">gre</option>"
		    "<option value=\"wg\">wg: WireGuard, encrypted</option>"
		    "<option value=\"vxlan\">vxlan: Ethernet over UDP</option>"
		    "</select></label><div class=\"two\"><label>Outer address "
		    "of ");
		h_txt(h, tn[a].label);
		h_raw(h, "<select name=\"local_a\">");
		addr_options(h, thost(tp.tun_a, false), offer.oa);
		h_raw(h, "</select></label><label>Outer address of ");
		h_txt(h, tn[b].label);
		h_raw(h, "<select name=\"local_b\">");
		addr_options(h, thost(tp.tun_b, false), offer.ob);
		h_raw(h, "</select></label></div><div class=\"two\"><label>"
		    "Inner address of ");
		h_txt(h, tn[a].label);
		h_raw(h, "<input name=\"inner_a\" spellcheck=\"false\" "
		    "autocomplete=\"off\"");
		h_attr(h, "value", offer.ia);
		h_raw(h, "></label><label>Inner address of ");
		h_txt(h, tn[b].label);
		h_raw(h, "<input name=\"inner_b\" spellcheck=\"false\" "
		    "autocomplete=\"off\"");
		h_attr(h, "value", offer.ib);
		h_raw(h, "></label></div><small>With their prefix length; "
		    "leave both empty for a tunnel without addresses.</small>"
		    "<div class=\"two\"><label>MTU<input name=\"mtu\" "
		    "inputmode=\"numeric\" placeholder=\"as the kernel sets "
		    "it\"></label><label>VXLAN identifier<input name=\"vni\" "
		    "inputmode=\"numeric\" placeholder=\"for vxlan only\">"
		    "</label></div>");
		h_raw(h, keep_field);
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
		    "again.</p><label>Interface<input name=\"name\" "
		    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\""
		    "epair, gif0, bridge1, vlan100…\" autofocus><small>A kind "
		    "alone, for the next free one, or with its number: epair, "
		    "gif, gre, ipsec, me, vxlan, vlan, bridge, lagg, tap, tun, "
		    "lo, wg, ovpn.</small></label><div class=\"two\"><label>"
		    "Tunnel: this end<input name=\"tunnel_local\" spellcheck="
		    "\"false\" autocomplete=\"off\" placeholder=\"for gif, "
		    "gre, ipsec, vxlan\"></label><label>Tunnel: far end<input "
		    "name=\"tunnel_remote\" spellcheck=\"false\" autocomplete="
		    "\"off\"></label></div><div class=\"two\"><label>Address"
		    "<input name=\"address\" spellcheck=\"false\" autocomplete="
		    "\"off\" placeholder=\"10.0.0.1/30\"></label><label>Peer's "
		    "address<input name=\"peer\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"point to point only\">"
		    "</label></div><div class=\"two\"><label>Number<input "
		    "name=\"id\" inputmode=\"numeric\" placeholder=\"VLAN tag "
		    "or VXLAN identifier\"></label><label>Parent<input name=\""
		    "parent\" spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"a VLAN's interface, a bridge's member\">"
		    "</label></div><div class=\"two\"><label>MTU<input name=\""
		    "mtu\" inputmode=\"numeric\"></label><label>Description"
		    "<input name=\"description\" autocomplete=\"off\"></label>"
		    "</div>");
		h_raw(h, keep_field);
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

/* A node's own network: a host's tab, or a jail's page. */
static void
node_open(int n, int kind)
{

	app.sel = tn[n].srv;
	if (tn[n].jail[0] != '\0') {
		app.node = NODE_JAIL;
		app.peek = false;
		snprintf(app.jail, sizeof(app.jail), "%s", tn[n].jail);
	} else {
		app.node = NODE_HOST;
		app.tab = TAB_NETWORK;
	}
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
	char		 title[160], *a, *b, *c, *d, *e, *g, *i, *k;
	int		 n;

	nodes_build();

	if (strcmp(form, "tunnel") == 0) {
		tunnel_create(f);
		return (true);
	}
	if (strcmp(form, "if-create") == 0) {
		if ((n = node_index(tp.create_sid)) == -1)
			return (true);
		name = jstr(f, "name") != NULL ? jstr(f, "name") : "";
		if (name[0] == '\0' || name[strspn(name, "abcdefghijklmnopqrstu"
		    "vwxyz0123456789")] != '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "Name the kind of interface, with or without its "
			    "number: gif, epair0, vlan100");
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
		snprintf(title, sizeof(title), "create %s", name);
		/* name is letters and digits: checked above. */
		node_job(n, title, name, "{\"kind\":\"if-create\",\"interface\":"
		    "\"%s\"%s%s%s%s%s%s%s%s,\"persist\":%s,\"safe\":true}", name,
		    a, b, c, d, e, g, i, k, jbool(f, "persist") ? "true" :
		    "false");
		free(a);
		free(b);
		free(c);
		free(d);
		free(e);
		free(g);
		free(i);
		free(k);
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
		a = json_quote(jstr(f, "description") != NULL ? jstr(f,
		    "description") : "");
		b = json_quote(app.confirm.arg);
		snprintf(title, sizeof(title), "%s: set", app.confirm.arg);
		if_job(s, title, app.confirm.arg, "{\"kind\":\"if-set\","
		    "\"interface\":%s%s,\"description\":%s,\"persist\":%s,"
		    "\"safe\":true}", b, i, a, jbool(f, "persist") ? "true" :
		    "false");
		free(i);
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
	if (z < 0.25)
		z = 0.25;
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
		if (!hosts[i].placed || node_index(hosts[i].sid) == -1)
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
	tp.panx = (x0 + x1) / 2;
	tp.pany = (y0 + y1) / 2;
	/* Room around them, and more when neighbours stand beside them. */
	zx = VIEW_W / (x1 - x0 + NODE_W + (nexts > 0 && !tp.nopeers ? 640 :
	    120));
	zy = VIEW_H / (y1 - y0 + NODE_H + (nexts > 0 && !tp.nopeers ? 460 :
	    140));
	tp.zoom = zx < zy ? zx : zy;
	if (tp.zoom > 1.7)
		tp.zoom = 1.7;
	if (tp.zoom < 0.25)
		tp.zoom = 0.25;
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
			grab_x = t->x - x;
			grab_y = t->y - y;
		} else {
			t->x = x + grab_x;
			t->y = y + grab_y;
		}
		tp.touched = true;
	} else if (strcmp(act, "topo-node-end") == 0) {
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
		app.modal = MODAL_TUNNEL;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "topo-link-click") == 0) {
		tp.linking = false;
		toast(false, "Drag the dot onto another host to join the two "
		    "with a tunnel");
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
		tp.labels = tp.labels == 2 || (tp.labels == 0 && nlinks > 6) ?
		    1 : 2;
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
		fit();
		tp.touched = false;
	} else if (strcmp(act, "topo-jails") == 0) {
		tp.jails = !tp.jails;
	} else if (strcmp(act, "topo-open-wg") == 0 || strcmp(act,
	    "topo-open-bird") == 0) {
		if ((n = node_index(arg)) == -1)
			return (true);
		node_open(n, act[10] == 'w' ? NET_WIREGUARD : NET_BIRD);
	} else if (strcmp(act, "topo-peers") == 0) {
		tp.nopeers = !tp.nopeers;
	} else if (strcmp(act, "topo-arrange") == 0) {
		for (i = 0; i < nhosts; i++)
			hosts[i].placed = false;
		places_fill();
		places_save();
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
		snprintf(tp.create_sid, sizeof(tp.create_sid), "%s", arg[0] !=
		    '\0' ? arg : s->id);
		app.modal = MODAL_IF_CREATE;
		app.modal_error[0] = '\0';
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
	const ucl_object_t	*o, *hk, *sel;
	ucl_object_iter_t	 it, hit;
	const char		*id;
	char			 p[80];
	double			 mx, my;
	int			 i, k, m, total;

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
		h_txt(h, jstr(o, "name"));
		h_raw(h, "</text><text class=\"sub\" x=\"-54\" y=\"14\">");
		h_txt(h, jstr(o, "type"));
		h_raw(h, "</text><circle class=\"port\" cx=\"65\" cy=\"0\" r=\"7\" "
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
	h_raw(h, "</aside></div><table class=\"net\"><thead><tr><th>Node</th>"
	    "<th>Type</th><th>ID</th><th>Hooks</th></tr></thead><tbody>");
	it = NULL;
	while ((o = ucl_object_iterate(nodes, &it, true)) != NULL) {
		if (app.filter[0] != '\0' && (jstr(o, "name") == NULL ||
		    strstr(jstr(o, "name"), app.filter) == NULL) && (jstr(o,
		    "type") == NULL || strstr(jstr(o, "type"), app.filter) ==
		    NULL))
			continue;
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
	char		url[520];
	int		af;

	snprintf(lk.sid, sizeof(lk.sid), "%s", s->id);
	snprintf(lk.addr, sizeof(lk.addr), "%s", addr);
	if (lk.data != NULL)
		ucl_object_unref(lk.data);
	lk.data = NULL;
	if (!addr_bytes(addr, &af, raw) || strchr(addr, '/') != NULL ||
	    strchr(addr, '%') != NULL) {
		snprintf(lk.error, sizeof(lk.error), "Type the address to find "
		    "the route to in the filter, an IPv4 or IPv6 one, then "
		    "press Lookup");
		return;
	}
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
