/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * SD-WAN on the edges: what each edge is to have for the services kept
 * (sdwan.c), and that made there, as jobs.
 *
 * An edge has, for each service on it, things the console makes with
 * jobs, each under a key:
 *
 *	fibs		net.fibs raised to the highest service FIB on it
 *	ipsec		strongSwan's key and daemon, when a tunnel wants it
 *	tvc:ID		its end of a tunnel (a Tunnel Virtual Connection,
 *			MEF 70.2 §7.10): gre, gif or geneve, maybe under
 *			IPsec IKEv2, or wg; in the service's FIB, its outer
 *			packets in FIB 0, an inner /31 and /127 from the
 *			service's reserved prefixes
 *	peer:ID		the tunnel's far end told: the wg peer, or the
 *			IKEv2 connection, with the far host's key
 *	route:S:P	a route in the service's FIB: a far UNI's prefix
 *			by a tunnel, or a UNI's static route
 *	uni:EP		the SD-WAN UNI: its interface (or a VLAN on it) in
 *			the service's FIB, the provider's addresses on it
 *
 * Each is the jobs that make it.  What was made is kept in
 * sdwan-state.json with the jobs that take it away again: made from
 * other jobs now, it is taken away and made again; no longer there, it
 * is taken away.  The tunnels' units and inner addresses are kept
 * there too, so that one added does not move the others.
 *
 * An apply takes away what goes, last made first, and then makes what
 * comes in this order, Mplify 119 §12.1's, each step on every edge
 * before the next: the FIBs, IPsec, the tunnels, their peers (the far
 * end's key is read once both ends have one), the routes, and the UNIs
 * last.  One thread does it, and one worker at a time (sdwan.lock).
 *
 *	GET  /api/sdwan/plan	what an apply would do, edge by edge
 *	POST /api/sdwan/apply	do it; {"fresh": true} takes everything
 *				made away first and makes it again
 *	GET  /api/sdwan/apply	how the last apply went, and the tunnels
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "console.h"

#define	STATE_FILE	"sdwan-state.json"
#define	LOCK_FILE	"sdwan.lock"
#define	UNIT_FIRST	100	/* tunnels' and VLANs' units, from here */
#define	WG_PORT		51000	/* + the unit: a wg tunnel's port */
#define	JOB_POLL_US	300000
#define	JOB_WAIT_S	600
#define	PHASES		6
#define	LIST_SUBS	16	/* a UNI's subnets, the first and more */

enum { PH_FIBS = 1, PH_IPSEC, PH_TVC, PH_PEER, PH_ROUTE, PH_UNI };

static pthread_mutex_t	st_lock = PTHREAD_MUTEX_INITIALIZER;
static bool		applying;

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	(void)ucl_object_delete_key(o, key);
	ucl_object_insert_key(o, v, key, 0, true);
}

static const char *
str(const ucl_object_t *o, const char *key)
{

	return (ucl_str(o, key));
}

static bool
in_list(const ucl_object_t *arr, const char *s)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;

	it = NULL;
	while (s != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL)
		if (ucl_object_type(v) == UCL_STRING &&
		    strcmp(ucl_object_tostring(v), s) == 0)
			return (true);
	return (false);
}

static const ucl_object_t *
by(const ucl_object_t *arr, const char *key, const char *s)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;

	it = NULL;
	while (s != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL)
		if (str(v, key) != NULL && strcmp(str(v, key), s) == 0)
			return (v);
	return (NULL);
}

static char *
emit(const ucl_object_t *o)
{

	return ((char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT));
}

/* ---- Addresses ------------------------------------------------------ */

struct net {
	int	af;
	uint8_t	a[16];
	int	len;
};

static bool
net_parse(const char *s, struct net *n)
{
	char	buf[64], *slash;

	memset(n, 0, sizeof(*n));
	if (s == NULL || strlen(s) >= sizeof(buf))
		return (false);
	snprintf(buf, sizeof(buf), "%s", s);
	if ((slash = strchr(buf, '/')) != NULL)
		*slash++ = '\0';
	if (inet_pton(AF_INET, buf, n->a) == 1)
		n->af = AF_INET;
	else if (inet_pton(AF_INET6, buf, n->a) == 1)
		n->af = AF_INET6;
	else
		return (false);
	n->len = slash != NULL ? atoi(slash) : n->af == AF_INET ? 32 : 128;
	return (true);
}

static int
family(const char *s)
{
	struct net	n;

	return (net_parse(s, &n) ? n.af : 0);
}

/* The address k after a's, as text. */
static void
net_nth(const struct net *n, uint64_t k, char *buf, size_t len)
{
	uint8_t		a[16];
	int		i, w;
	unsigned int	carry;

	memcpy(a, n->a, sizeof(a));
	w = n->af == AF_INET ? 4 : 16;
	for (i = w - 1; i >= 0 && k != 0; i--) {
		carry = (unsigned int)a[i] + (unsigned int)(k & 0xff);
		a[i] = (uint8_t)carry;
		k = (k >> 8) + (carry >> 8);
	}
	inet_ntop(n->af, a, buf, (socklen_t)len);
}

/*
 * The k-th pair of a reserved prefix: a /31 or /127, its first and its
 * second address.  False when the prefix has no k-th.
 */
static bool
pair_of(const char *prefix, uint64_t k, char *p, char *a, char *b,
    size_t len)
{
	struct net	n;
	int		bits;

	if (!net_parse(prefix, &n))
		return (false);
	bits = (n.af == AF_INET ? 31 : 127) - n.len;
	if (bits < 0 || (bits < 40 && k >= ((uint64_t)1 << bits)))
		return (false);
	net_nth(&n, 2 * k, a, len);
	net_nth(&n, 2 * k + 1, b, len);
	snprintf(p, len, "%s/%d", a, n.af == AF_INET ? 31 : 127);
	return (true);
}

/* ---- The state ------------------------------------------------------ */

static ucl_object_t *
state_load(void)
{
	ucl_object_t	*st;

	if ((st = store_load(STATE_FILE)) == NULL)
		st = ucl_object_typed_new(UCL_OBJECT);
	if (ucl_object_lookup(st, "alloc") == NULL)
		put(st, "alloc", ucl_object_typed_new(UCL_OBJECT));
	if (ucl_object_lookup(st, "applied") == NULL)
		put(st, "applied", ucl_object_typed_new(UCL_OBJECT));
	return (st);
}

static void
state_save(const ucl_object_t *st)
{

	pthread_mutex_lock(&st_lock);
	(void)store_save(STATE_FILE, st);
	pthread_mutex_unlock(&st_lock);
}

/* A unit no allocation has: the lowest from UNIT_FIRST. */
static int64_t
unit_new(const ucl_object_t *alloc)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	int64_t			 u;
	bool			 used;

	for (u = UNIT_FIRST; u < 32767; u++) {
		used = false;
		it = NULL;
		while (!used && (v = ucl_object_iterate(alloc, &it, true)) !=
		    NULL) {
			const ucl_object_t	*n;
			ucl_object_iter_t	 nit;

			used = ucl_object_toint(ucl_object_lookup(v, "unit")) ==
			    u;
			nit = NULL;
			while (!used && (n = ucl_object_iterate(
			    ucl_object_lookup(v, "units"), &nit, true)) != NULL)
				used = ucl_object_toint(n) == u;
		}
		if (!used)
			return (u);
	}
	return (-1);
}

/* The lowest pair of a service's reserved prefix of af none has. */
static bool
pair_new(const ucl_object_t *alloc, const ucl_object_t *sw, int af,
    const char *key, char *p, size_t len)
{
	const ucl_object_t	*v, *r;
	ucl_object_iter_t	 it, rit;
	char			 a[64], b[64];
	uint64_t		 k;
	bool			 used;

	rit = NULL;
	while ((r = ucl_object_iterate(ucl_object_lookup(sw,
	    "reserved_prefixes"), &rit, true)) != NULL) {
		if (family(ucl_object_tostring_forced(r)) != af)
			continue;
		for (k = 0; k < 65536; k++) {
			if (!pair_of(ucl_object_tostring_forced(r), k, p, a, b,
			    len))
				break;
			used = false;
			it = NULL;
			while (!used && (v = ucl_object_iterate(alloc, &it,
			    true)) != NULL)
				used = str(v, key) != NULL && strcmp(str(v, key),
				    p) == 0;
			if (!used)
				return (true);
		}
	}
	return (false);
}

/* ---- What each edge is to have ------------------------------------- */

struct plan {
	const ucl_object_t	*doc;
	ucl_object_t		*alloc;		/* the state's, with new ones */
	ucl_object_t		*edges;		/* sid: [objects] */
	ucl_object_t		*tunnels;	/* the tunnels, both ends */
	ucl_object_t		*used;		/* the allocations they have */
	char			 why[300];
};

static ucl_object_t *
edge_list(struct plan *pl, const char *sid)
{
	ucl_object_t	*a;

	if ((a = (ucl_object_t *)(uintptr_t)ucl_object_lookup(pl->edges,
	    sid)) == NULL) {
		a = ucl_object_typed_new(UCL_ARRAY);
		ucl_object_insert_key(pl->edges, a, sid, 0, true);
	}
	return (a);
}

/* An object an edge is to have: its key, its step, what it is. */
static ucl_object_t *
object(struct plan *pl, const char *sid, const char *key, int phase,
    const char *fmt, ...)
{
	ucl_object_t	*o, *a;
	const ucl_object_t *e;
	ucl_object_iter_t it;
	char		 title[300];
	va_list		 ap;

	a = edge_list(pl, sid);
	it = NULL;
	while ((e = ucl_object_iterate(a, &it, true)) != NULL)
		if (strcmp(str(e, "key"), key) == 0)
			return (NULL);	/* the first says it */
	va_start(ap, fmt);
	vsnprintf(title, sizeof(title), fmt, ap);
	va_end(ap);
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "key", ucl_object_fromstring(key));
	put(o, "phase", ucl_object_fromint(phase));
	put(o, "title", ucl_object_fromstring(title));
	put(o, "make", ucl_object_typed_new(UCL_ARRAY));
	put(o, "unmake", ucl_object_typed_new(UCL_ARRAY));
	ucl_array_append(a, o);
	return (o);
}

/* A job, of a kind, its fields after: name, value, ..., NULL. */
static ucl_object_t *
job(const char *kind, ...)
{
	ucl_object_t	*j;
	va_list		 ap;
	const char	*k;

	j = ucl_object_typed_new(UCL_OBJECT);
	put(j, "kind", ucl_object_fromstring(kind));
	va_start(ap, kind);
	while ((k = va_arg(ap, const char *)) != NULL)
		put(j, k, va_arg(ap, ucl_object_t *));
	va_end(ap);
	return (j);
}

#define	S(x)	ucl_object_fromstring(x)
#define	I(x)	ucl_object_fromint(x)
#define	B(x)	ucl_object_frombool(x)

static void
make(ucl_object_t *o, ucl_object_t *j)
{

	ucl_array_append((ucl_object_t *)(uintptr_t)ucl_object_lookup(o,
	    "make"), j);
}

static void
unmake(ucl_object_t *o, ucl_object_t *j)
{

	ucl_array_append((ucl_object_t *)(uintptr_t)ucl_object_lookup(o,
	    "unmake"), j);
}

/* What a tunnel over a UCS is, when the UCS does not say. */
static void
tunnel_of(const ucl_object_t *ucs, const char **kindp, bool *ipsecp)
{
	const ucl_object_t	*t;
	bool			 public;

	public = str(ucs, "type") != NULL && strcmp(str(ucs, "type"),
	    "public") == 0;
	t = ucl_object_lookup(ucs, "tunnel");
	*kindp = t != NULL && str(t, "kind") != NULL ? str(t, "kind") : "gre";
	if (strcmp(*kindp, "wg") == 0)
		*ipsecp = false;
	else if (t != NULL && ucl_object_lookup(t, "ipsec") != NULL)
		*ipsecp = ucl_flag(t, "ipsec");
	else
		*ipsecp = public;	/* the Internet's, encrypted */
}

static const char *
ifname_of(const char *kind, int64_t unit, char *buf, size_t len)
{

	snprintf(buf, len, "%s%jd", strcmp(kind, "wg") == 0 ? "wg" :
	    strcmp(kind, "geneve") == 0 ? "geneve" : strcmp(kind, "gif") ==
	    0 ? "gif" : "gre", (intmax_t)unit);
	return (buf);
}

/* What IPsec protects of a tunnel: its own outer packets. */
static const char *
ts_of(const char *kind)
{

	return (strcmp(kind, "gif") == 0 ? "dynamic[4],dynamic[41]" :
	    strcmp(kind, "geneve") == 0 ? "dynamic[udp]" : "dynamic[gre]");
}

/* FNV-1a, to say a far end changed without its whole jobs. */
static char *
digest(const ucl_object_t *o, char *buf, size_t len)
{
	char		*s;
	uint64_t	 h;
	size_t		 i;

	s = emit(o);
	h = 0xcbf29ce484222325ULL;
	for (i = 0; s != NULL && s[i] != '\0'; i++) {
		h ^= (unsigned char)s[i];
		h *= 0x100000001b3ULL;
	}
	free(s);
	snprintf(buf, len, "%016jx", (uintmax_t)h);
	return (buf);
}

/* One end of a tunnel: its interface, and how it knows the far end. */
static void
tvc_end(struct plan *pl, const ucl_object_t *t, int me)
{
	const ucl_object_t	*a, *b;
	ucl_object_t		*o, *p;
	const char		*kind, *id, *sid;
	char			 ifn[32], key[200], h[20], port[80];
	int64_t			 unit, fib;
	bool			 ipsec;

	a = ucl_array_find_index(ucl_object_lookup(t, "ends"),
	    (unsigned int)me);
	b = ucl_array_find_index(ucl_object_lookup(t, "ends"),
	    (unsigned int)!me);
	kind = str(t, "kind");
	id = str(t, "id");
	sid = str(a, "edge");
	unit = ucl_object_toint(ucl_object_lookup(a, "unit"));
	fib = ucl_object_toint(ucl_object_lookup(t, "fib"));
	ipsec = ucl_flag(t, "ipsec");
	snprintf(ifn, sizeof(ifn), "%s", str(a, "ifname"));
	snprintf(key, sizeof(key), "tvc:%s", id);
	o = object(pl, sid, key, PH_TVC, "%s, %s to %s over %s", ifn, kind,
	    str(b, "underlay"), str(a, "ucs_ep"));
	if (o == NULL)
		return;
	if (strcmp(kind, "geneve") == 0) {
		ucl_object_t	*args;

		args = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(args, S("mode"));
		ucl_array_append(args, S("l3"));
		ucl_array_append(args, S("id"));
		snprintf(port, sizeof(port), "%jd", (intmax_t)ucl_object_toint(
		    ucl_object_lookup(t, "vni")));
		ucl_array_append(args, S(port));
		ucl_array_append(args, S("local"));
		ucl_array_append(args, S(str(a, "underlay")));
		ucl_array_append(args, S("remote"));
		ucl_array_append(args, S(str(b, "underlay")));
		make(o, job("geneve", "verb", S("create"), "interface", S(ifn),
		    "args", args, "persist", B(true), NULL));
		make(o, job("if-set", "interface", S(ifn), "fib", I(fib),
		    "persist", B(true), NULL));
		if (str(a, "inner4") != NULL) {
			snprintf(port, sizeof(port), "%s/31", str(a, "inner4"));
			make(o, job("if-address", "interface", S(ifn),
			    "address", S(port), "persist", B(true), NULL));
		}
	} else {
		/*
		 * Made in its table, its inner IPv4 address with it: the
		 * agent sets the table first, so the address's route is
		 * made there.
		 */
		p = job("if-create", "interface", S(ifn), "fib", I(fib),
		    "description", S("sdwan"), "persist", B(true), NULL);
		if (strcmp(kind, "wg") != 0) {
			put(p, "tunnel_local", S(str(a, "underlay")));
			put(p, "tunnel_remote", S(str(b, "underlay")));
		}
		if (str(a, "inner4") != NULL) {
			snprintf(port, sizeof(port), "%s/31", str(a, "inner4"));
			put(p, "address", S(port));
			if (strcmp(kind, "wg") != 0)
				put(p, "destination", S(str(b, "inner4")));
		}
		make(o, p);
	}
	if (str(a, "inner6") != NULL) {
		snprintf(port, sizeof(port), "%s/127", str(a, "inner6"));
		make(o, job("if-address", "interface", S(ifn), "address",
		    S(port), "persist", B(true), NULL));
	}
	if (strcmp(kind, "wg") == 0)
		make(o, job("wireguard", "verb", S("init"), "interface", S(ifn),
		    "listen_port", I(WG_PORT + unit), "persist", B(true), NULL));
	unmake(o, job("if-destroy", "interface", S(ifn), "persist", B(true),
	    NULL));

	/* The far end, as it is known: its key, made again with it. */
	if (strcmp(kind, "wg") != 0 && !ipsec)
		return;
	snprintf(key, sizeof(key), "peer:%s", id);
	o = object(pl, sid, key, PH_PEER, "%s: the far end, %s, %s", ifn,
	    str(b, "underlay"), strcmp(kind, "wg") == 0 ? "a wg peer" :
	    "IPsec IKEv2");
	if (o == NULL)
		return;
	if (strcmp(kind, "wg") == 0) {
		snprintf(key, sizeof(key), "${wg:%s:%s}", str(b, "edge"), str(b,
		    "ifname"));
		snprintf(port, sizeof(port), "%s%s%s:%jd", family(str(b,
		    "underlay")) == AF_INET6 ? "[" : "", str(b, "underlay"),
		    family(str(b, "underlay")) == AF_INET6 ? "]" : "",
		    (intmax_t)(WG_PORT + ucl_object_toint(ucl_object_lookup(b,
		    "unit"))));
		p = job("wireguard", "verb", S("peer"), "interface", S(ifn),
		    "peer", S(key), "endpoint", S(port), "allowed_ips",
		    S("0.0.0.0/0,::/0"), "keepalive", I(25), "persist", B(true),
		    NULL);
	} else {
		snprintf(key, sizeof(key), "${ipsec:%s}", str(b, "edge"));
		snprintf(port, sizeof(port), "sdw%jd", (intmax_t)unit);
		p = job("ipsec", "verb", S("conn"), "conn", S(port),
		    "tunnel_local", S(str(a, "underlay")), "tunnel_remote",
		    S(str(b, "underlay")), "ipsec_mode", S("transport"),
		    "pubkey", S(key), "local_ts", S(ts_of(kind)), "remote_ts",
		    S(ts_of(kind)), "start_action", S("trap"), "persist",
		    B(true), NULL);
		unmake(o, job("ipsec", "verb", S("unconn"), "conn", S(port),
		    "persist", B(true), NULL));
	}
	/* Made again when the far end's interface is: a new key. */
	put(p, "_after", S(digest(t, h, sizeof(h))));
	make(o, p);
}

/* The tunnels of a service: between each two of its edges, over each
 * two of their UCS End Points a tunnel can join (§7.10). */
static bool
tunnels(struct plan *pl, const ucl_object_t *sw)
{
	const ucl_object_t	*doc, *e1, *e2, *x, *y, *ux, *uy, *ep;
	ucl_object_iter_t	 it, it2, xit, yit;
	ucl_object_t		*edges, *t, *ends, *end, *al;
	const char		*kind, *k2, *sid;
	char			 id[300], p[80], a[64], b[64];
	int64_t			 unit;
	bool			 ipsec, ip2, public;
	size_t			 i, j;

	doc = pl->doc;
	/* Its edges, each once, in the order its end points name them. */
	edges = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL)
		if (!in_list(edges, str(ep, "edge")))
			ucl_array_append(edges, S(str(ep, "edge")));
	for (i = 0; i < ucl_array_size(edges); i++)
		for (j = i + 1; j < ucl_array_size(edges); j++) {
			e1 = by(ucl_object_lookup(doc, "edges"), "server",
			    ucl_object_tostring(ucl_array_find_index(edges,
			    (unsigned int)i)));
			e2 = by(ucl_object_lookup(doc, "edges"), "server",
			    ucl_object_tostring(ucl_array_find_index(edges,
			    (unsigned int)j)));
			xit = NULL;
			while ((x = ucl_object_iterate(ucl_object_lookup(e1,
			    "ucs_end_points"), &xit, true)) != NULL) {
				if (!in_list(ucl_object_lookup(sw, "ucs"),
				    str(x, "ucs")))
					continue;
				ux = by(ucl_object_lookup(doc, "ucs"), "id",
				    str(x, "ucs"));
				yit = NULL;
				while ((y = ucl_object_iterate(
				    ucl_object_lookup(e2, "ucs_end_points"),
				    &yit, true)) != NULL) {
					if (!in_list(ucl_object_lookup(sw,
					    "ucs"), str(y, "ucs")))
						continue;
					uy = by(ucl_object_lookup(doc, "ucs"),
					    "id", str(y, "ucs"));
					public = strcmp(str(ux, "type"),
					    "public") == 0 || strcmp(str(uy,
					    "type"), "public") == 0;
					/* One UCS, or two Internet Accesses. */
					if (strcmp(str(x, "ucs"), str(y, "ucs"))
					    != 0 && !(strcmp(str(ux, "type"),
					    "public") == 0 && strcmp(str(uy,
					    "type"), "public") == 0))
						continue;
					if (str(x, "address") == NULL ||
					    str(y, "address") == NULL) {
						snprintf(pl->why, sizeof(pl->why),
						    "ucs end point %s has no "
						    "address: a tunnel needs its "
						    "outer one", str(x,
						    "address") == NULL ? str(x,
						    "id") : str(y, "id"));
						ucl_object_unref(edges);
						return (false);
					}
					if (family(str(x, "address")) !=
					    family(str(y, "address")))
						continue;
					tunnel_of(ux, &kind, &ipsec);
					tunnel_of(uy, &k2, &ip2);
					ipsec = ipsec || ip2;
					snprintf(id, sizeof(id), "%s/%s-%s", str(sw,
					    "id"), str(x, "id"), str(y, "id"));
					/* Its unit and inner pair, as kept. */
					if ((al = (ucl_object_t *)(uintptr_t)
					    ucl_object_lookup(pl->alloc, id)) ==
					    NULL) {
						ucl_object_t	*units;

						al = ucl_object_typed_new(
						    UCL_OBJECT);
						/* A unit for each end: two ends
						 * may be one host. */
						units = ucl_object_typed_new(
						    UCL_ARRAY);
						put(al, "units", units);
						ucl_object_insert_key(pl->alloc,
						    al, id, 0, true);
						for (int k = 0; k < 2; k++) {
							if ((unit = unit_new(
							    pl->alloc)) < 0) {
								ucl_object_unref(
								    edges);
								snprintf(pl->why,
								    sizeof(
								    pl->why),
								    "no unit is "
								    "left");
								return (false);
							}
							ucl_array_append(units,
							    I(unit));
						}
						put(al, "swvc", S(str(sw, "id")));
						if (pair_new(pl->alloc, sw,
						    AF_INET, "v4", p, sizeof(p)))
							put(al, "v4", S(p));
						if (pair_new(pl->alloc, sw,
						    AF_INET6, "v6", p, sizeof(p)))
							put(al, "v6", S(p));
					}
					if (str(al, "v4") == NULL && str(al,
					    "v6") == NULL) {
						snprintf(pl->why, sizeof(pl->why),
						    "swvc %s: its reserved "
						    "prefixes have no room for "
						    "tunnel %s", str(sw, "id"),
						    id);
						ucl_object_unref(edges);
						return (false);
					}
					ucl_object_insert_key(pl->used, B(true),
					    id, 0, true);
					t = ucl_object_typed_new(UCL_OBJECT);
					put(t, "id", S(id));
					put(t, "swvc", S(str(sw, "id")));
					put(t, "fib", I(ucl_object_toint(
					    ucl_object_lookup(sw, "fib"))));
					put(t, "kind", S(kind));
					put(t, "ipsec", B(ipsec));
					put(t, "encrypted", B(ipsec ||
					    strcmp(kind, "wg") == 0));
					put(t, "public", B(public));
					put(t, "backup", B(ucl_flag(x,
					    "backup") || ucl_flag(y, "backup")));
					/* A geneve's VNI, the same at both. */
					put(t, "vni", I(ucl_object_toint(
					    ucl_array_find_index(ucl_object_lookup(
					    al, "units"), 0))));
					ends = ucl_object_typed_new(UCL_ARRAY);
					for (int k = 0; k < 2; k++) {
						const ucl_object_t *u = k == 0 ?
						    x : y;

						sid = k == 0 ? str(e1,
						    "server") : str(e2, "server");
						end = ucl_object_typed_new(
						    UCL_OBJECT);
						put(end, "edge", S(sid));
						put(end, "ucs_ep", S(str(u, "id")));
						put(end, "underlay", S(str(u,
						    "address")));
						unit = ucl_object_toint(
						    ucl_array_find_index(
						    ucl_object_lookup(al, "units"),
						    (unsigned int)k));
						put(end, "unit", I(unit));
						put(end, "ifname", S(ifname_of(kind,
						    unit, p, sizeof(p))));
						if (str(al, "v4") != NULL &&
						    pair_of(str(al, "v4"), 0, p, a,
						    b, sizeof(a)))
							put(end, "inner4", S(k ==
							    0 ? a : b));
						if (str(al, "v6") != NULL &&
						    pair_of(str(al, "v6"), 0, p, a,
						    b, sizeof(a)))
							put(end, "inner6", S(k ==
							    0 ? a : b));
						ucl_array_append(ends, end);
					}
					put(t, "ends", ends);
					ucl_array_append(pl->tunnels, t);
				}
			}
		}
	ucl_object_unref(edges);
	(void)it2;
	return (true);
}

/*
 * The tunnel a route from edge a to edge b takes for af: one that is no
 * backup first, a private one before a public one, then by its id.
 */
static const ucl_object_t *
tunnel_for(struct plan *pl, const char *swvc, const char *a, const char *b,
    int af, int *farp)
{
	const ucl_object_t	*t, *e0, *e1, *best;
	ucl_object_iter_t	 it;
	int			 far, bfar, score, bscore;

	best = NULL;
	bfar = 0;
	bscore = 99;
	it = NULL;
	while ((t = ucl_object_iterate(pl->tunnels, &it, true)) != NULL) {
		if (strcmp(str(t, "swvc"), swvc) != 0)
			continue;
		e0 = ucl_array_find_index(ucl_object_lookup(t, "ends"), 0);
		e1 = ucl_array_find_index(ucl_object_lookup(t, "ends"), 1);
		if (strcmp(str(e0, "edge"), a) == 0 && strcmp(str(e1, "edge"),
		    b) == 0)
			far = 1;
		else if (strcmp(str(e1, "edge"), a) == 0 && strcmp(str(e0,
		    "edge"), b) == 0)
			far = 0;
		else
			continue;
		if (str(far ? e1 : e0, af == AF_INET ? "inner4" : "inner6") ==
		    NULL)
			continue;
		score = (ucl_flag(t, "backup") ? 2 : 0) + (ucl_flag(t,
		    "public") ? 1 : 0);
		if (score < bscore) {
			best = t;
			bfar = far;
			bscore = score;
		}
	}
	*farp = bfar;
	return (best);
}

/* The prefixes at an end point's UNI: its subnets and static routes. */
static void
uni_prefixes(const ucl_object_t *ep, ucl_object_t *out)
{
	const ucl_object_t	*u, *v, *e;
	ucl_object_iter_t	 it;
	const char *const	 fams[] = { "ipv4", "ipv6" };
	int			 i;

	u = ucl_object_lookup(ep, "uni");
	for (i = 0; i < 2; i++) {
		v = ucl_object_lookup(u, fams[i]);
		if (str(v, "mode") == NULL || strcmp(str(v, "mode"), "static") !=
		    0)
			continue;
		ucl_array_append(out, S(str(v, "prefix")));
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(v,
		    "secondary"), &it, true)) != NULL)
			ucl_array_append(out, S(str(e, "prefix")));
	}
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(u, "routes"), &it,
	    true)) != NULL)
		ucl_array_append(out, S(str(e, "prefix")));
}

/* A route in a service's FIB, made and taken away. */
static void
route_obj(struct plan *pl, const char *sid, const ucl_object_t *sw,
    const char *prefix, const char *gw, const char *why)
{
	ucl_object_t	*o;
	char		 key[200];
	int64_t		 fib;

	fib = ucl_object_toint(ucl_object_lookup(sw, "fib"));
	snprintf(key, sizeof(key), "route:%s:%s", str(sw, "id"), prefix);
	if ((o = object(pl, sid, key, PH_ROUTE, "%s via %s, fib %jd (%s)",
	    prefix, gw, (intmax_t)fib, why)) == NULL)
		return;
	make(o, job("route", "destination", S(prefix), "gateway", S(gw), "fib",
	    I(fib), "persist", B(true), NULL));
	unmake(o, job("route", "destination", S(prefix), "gateway", S(gw),
	    "fib", I(fib), "remove", B(true), "persist", B(true), NULL));
}

/* The UNI: in the service's FIB, the provider's addresses on it. */
static bool
uni_obj(struct plan *pl, const ucl_object_t *sw, const ucl_object_t *ep)
{
	const ucl_object_t	*u, *v, *e, *a, *subs[LIST_SUBS];
	ucl_object_t		*o, *al, *vjob;
	ucl_object_iter_t	 it, ait;
	const char *const	 fams[] = { "ipv4", "ipv6" };
	const char		*ifn;
	char			 key[200], vif[32], addr[80];
	int64_t			 fib, vlan, unit;
	struct net		 n;
	int			 i, k, ns;

	u = ucl_object_lookup(ep, "uni");
	fib = ucl_object_toint(ucl_object_lookup(sw, "fib"));
	vlan = ucl_object_toint(ucl_object_lookup(u, "vlan"));
	ifn = str(u, "interface");
	snprintf(key, sizeof(key), "uni:%s", str(ep, "id"));
	if (vlan > 0) {
		snprintf(addr, sizeof(addr), "vlan:%s/%s", str(sw, "id"),
		    str(ep, "id"));
		if ((al = (ucl_object_t *)(uintptr_t)ucl_object_lookup(
		    pl->alloc, addr)) == NULL) {
			if ((unit = unit_new(pl->alloc)) < 0) {
				snprintf(pl->why, sizeof(pl->why), "no unit is "
				    "left");
				return (false);
			}
			al = ucl_object_typed_new(UCL_OBJECT);
			put(al, "unit", I(unit));
			put(al, "swvc", S(str(sw, "id")));
			ucl_object_insert_key(pl->alloc, al, addr, 0, true);
		}
		ucl_object_insert_key(pl->used, B(true), addr, 0, true);
		snprintf(vif, sizeof(vif), "vlan%jd", (intmax_t)
		    ucl_object_toint(ucl_object_lookup(al, "unit")));
	}
	o = object(pl, str(ep, "edge"), key, PH_UNI, "UNI %s: %s%s%s in fib "
	    "%jd", str(u, "id"), vlan > 0 ? vif : ifn, vlan > 0 ? ", a VLAN "
	    "on " : "", vlan > 0 ? ifn : "", (intmax_t)fib);
	if (o == NULL)
		return (true);
	vjob = NULL;
	if (vlan > 0) {
		vjob = job("if-create", "interface", S(vif), "id", I(vlan),
		    "parent", S(ifn), "fib", I(fib), "persist", B(true), NULL);
		make(o, vjob);
		unmake(o, job("if-destroy", "interface", S(vif), "persist",
		    B(true), NULL));
		ifn = vif;
	} else {
		make(o, job("if-set", "interface", S(ifn), "fib", I(fib),
		    "persist", B(true), NULL));
	}
	for (i = 0; i < 2; i++) {
		v = ucl_object_lookup(u, fams[i]);
		if (str(v, "mode") == NULL || strcmp(str(v, "mode"), "static") !=
		    0)
			continue;
		ns = 0;
		subs[ns++] = v;
		it = NULL;
		while (ns < LIST_SUBS && (e = ucl_object_iterate(
		    ucl_object_lookup(v, "secondary"), &it, true)) != NULL)
			subs[ns++] = e;
		for (k = 0; k < ns; k++) {
			if (!net_parse(str(subs[k], "prefix"), &n))
				continue;
			ait = NULL;
			while ((a = ucl_object_iterate(ucl_object_lookup(
			    subs[k], "provider"), &ait, true)) != NULL) {
				snprintf(addr, sizeof(addr), "%s/%d",
				    ucl_object_tostring_forced(a), n.len);
				/* A VLAN's first, as it is made. */
				if (vjob != NULL && ucl_object_lookup(vjob,
				    "address") == NULL)
					put(vjob, "address", S(addr));
				else
					make(o, job("if-address", "interface",
					    S(ifn), "address", S(addr), "persist",
					    B(true), NULL));
				if (vlan == 0)
					unmake(o, job("if-address", "interface",
					    S(ifn), "address", S(
					    ucl_object_tostring_forced(a)),
					    "remove", B(true), "persist",
					    B(true), NULL));
			}
		}
	}
	if (vlan == 0)
		unmake(o, job("if-set", "interface", S(ifn), "fib", I(0),
		    "persist", B(true), NULL));
	return (true);
}

/*
 * What every edge is to have: pl->edges, each edge's objects; NULL and
 * pl->why when it cannot be said.
 */
static bool
plan_build(struct plan *pl, const ucl_object_t *doc, const ucl_object_t *st)
{
	const ucl_object_t	*sw, *ep, *ep2, *t, *e, *r;
	ucl_object_iter_t	 it, it2, it3, rit;
	ucl_object_t		*o, *pfx, *args;
	char			 n[16];
	int64_t			 fib;
	int			 far;

	memset(pl, 0, sizeof(*pl));
	pl->doc = doc;
	pl->alloc = ucl_object_copy(ucl_object_lookup(st, "alloc"));
	pl->edges = ucl_object_typed_new(UCL_OBJECT);
	pl->tunnels = ucl_object_typed_new(UCL_ARRAY);
	pl->used = ucl_object_typed_new(UCL_OBJECT);
	/* The tunnels first: their units and pairs, in the document's order. */
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL)
		if (!tunnels(pl, sw))
			return (false);
	/* Each edge's FIBs: as many as its highest service's, and one. */
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL) {
		fib = ucl_object_toint(ucl_object_lookup(sw, "fib"));
		it2 = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
		    "end_points"), &it2, true)) != NULL) {
			o = (ucl_object_t *)(uintptr_t)by(ucl_object_lookup(
			    pl->edges, str(ep, "edge")), "key", "fibs");
			if (o == NULL)
				o = object(pl, str(ep, "edge"), "fibs", PH_FIBS,
				    "net.fibs");
			if (ucl_object_toint(ucl_object_lookup(o, "fibs")) <=
			    fib) {
				put(o, "fibs", I(fib + 1));
				snprintf(n, sizeof(n), "%jd", (intmax_t)fib + 1);
				put(o, "title", S("net.fibs, raised to it when "
				    "lower"));
				put(o, "make", ucl_object_typed_new(UCL_ARRAY));
				args = ucl_object_typed_new(UCL_ARRAY);
				ucl_array_append(args, S("net.fibs"));
				ucl_array_append(args, S(n));
				make(o, job("sysctl", "args", args, "persist",
				    B(true), NULL));
			}
		}
	}
	/* IPsec where a tunnel wants it; then each tunnel's two ends. */
	it = NULL;
	while ((t = ucl_object_iterate(pl->tunnels, &it, true)) != NULL) {
		if (ucl_flag(t, "ipsec")) {
			it2 = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(t,
			    "ends"), &it2, true)) != NULL &&
			    (o = object(pl, str(e, "edge"), "ipsec", PH_IPSEC,
			    "IPsec: strongSwan's key and its daemon")) != NULL) {
				make(o, job("ipsec", "verb", S("init"),
				    "persist", B(true), NULL));
				make(o, job("ipsec", "verb", S("start"),
				    "persist", B(true), NULL));
			}
		}
		tvc_end(pl, t, 0);
		tvc_end(pl, t, 1);
	}
	/* Routes: a far end point's prefixes by a tunnel to its edge; a
	 * UNI's static routes by their next hop. */
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL) {
		it2 = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
		    "end_points"), &it2, true)) != NULL) {
			rit = NULL;
			while ((r = ucl_object_iterate(ucl_object_lookup(
			    ucl_object_lookup(ep, "uni"), "routes"), &rit,
			    true)) != NULL)
				route_obj(pl, str(ep, "edge"), sw, str(r,
				    "prefix"), str(r, "next_hop"), "a static "
				    "route of the UNI");
			it3 = NULL;
			while ((ep2 = ucl_object_iterate(ucl_object_lookup(sw,
			    "end_points"), &it3, true)) != NULL) {
				const ucl_object_t	*p, *tt, *fe;
				ucl_object_iter_t	 pit;

				if (strcmp(str(ep, "edge"), str(ep2, "edge")) ==
				    0)
					continue;
				pfx = ucl_object_typed_new(UCL_ARRAY);
				uni_prefixes(ep2, pfx);
				pit = NULL;
				while ((p = ucl_object_iterate(pfx, &pit,
				    true)) != NULL) {
					tt = tunnel_for(pl, str(sw, "id"),
					    str(ep, "edge"), str(ep2, "edge"),
					    family(ucl_object_tostring(p)),
					    &far);
					if (tt == NULL)
						continue;
					fe = ucl_array_find_index(
					    ucl_object_lookup(tt, "ends"),
					    (unsigned int)far);
					route_obj(pl, str(ep, "edge"), sw,
					    ucl_object_tostring(p), str(fe,
					    family(ucl_object_tostring(p)) ==
					    AF_INET ? "inner4" : "inner6"),
					    str(ep2, "id"));
				}
				ucl_object_unref(pfx);
			}
		}
	}
	/* The UNIs, last. */
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL) {
		it2 = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
		    "end_points"), &it2, true)) != NULL)
			if (!uni_obj(pl, sw, ep))
				return (false);
	}
	return (true);
}

static void
plan_free(struct plan *pl)
{

	if (pl->alloc != NULL)
		ucl_object_unref(pl->alloc);
	if (pl->edges != NULL)
		ucl_object_unref(pl->edges);
	if (pl->tunnels != NULL)
		ucl_object_unref(pl->tunnels);
	if (pl->used != NULL)
		ucl_object_unref(pl->used);
	memset(pl, 0, sizeof(*pl));
}

/* What an object is: its jobs as made, and what it raises net.fibs to. */
static char *
spec_of(const ucl_object_t *o)
{
	ucl_object_t	*s;
	char		*t;

	s = ucl_object_typed_new(UCL_OBJECT);
	put(s, "make", ucl_object_copy(ucl_object_lookup(o, "make")));
	if (ucl_object_lookup(o, "fibs") != NULL)
		put(s, "fibs", ucl_object_copy(ucl_object_lookup(o, "fibs")));
	t = emit(s);
	ucl_object_unref(s);
	return (t);
}

/*
 * The changes: for each edge, each object made, made again, taken
 * away, or kept as it is.  fresh: everything made is taken away and
 * made again.
 */
static ucl_object_t *
changes(const struct plan *pl, const ucl_object_t *st, bool fresh)
{
	const ucl_object_t	*objs, *o, *old, *applied, *eapp;
	ucl_object_iter_t	 it, oit;
	ucl_object_t		*out, *c, *seen;
	char			*spec;

	out = ucl_object_typed_new(UCL_ARRAY);
	applied = ucl_object_lookup(st, "applied");
	seen = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while ((objs = ucl_object_iterate(pl->edges, &it, true)) != NULL) {
		const char *sid = ucl_object_key(objs);

		ucl_object_insert_key(seen, B(true), sid, 0, true);
		eapp = ucl_object_lookup(applied, sid);
		oit = NULL;
		while ((o = ucl_object_iterate(objs, &oit, true)) != NULL) {
			old = ucl_object_lookup(eapp, str(o, "key"));
			spec = spec_of(o);
			c = ucl_object_copy(o);
			put(c, "server", S(sid));
			put(c, "change", S(old == NULL ? "make" : fresh ||
			    str(old, "spec") == NULL || strcmp(str(old, "spec"),
			    spec) != 0 ? "remake" : "keep"));
			put(c, "spec", S(spec));
			if (old != NULL)
				put(c, "unmake", ucl_object_copy(
				    ucl_object_lookup(old, "unmake")));
			free(spec);
			ucl_array_append(out, c);
		}
		/* What it has that it is no longer to have. */
		oit = NULL;
		while ((o = ucl_object_iterate(eapp, &oit, true)) != NULL) {
			if (by(objs, "key", ucl_object_key(o)) != NULL)
				continue;
			c = ucl_object_copy(o);
			put(c, "server", S(sid));
			put(c, "key", S(ucl_object_key(o)));
			put(c, "change", S("unmake"));
			put(c, "make", ucl_object_typed_new(UCL_ARRAY));
			ucl_array_append(out, c);
		}
	}
	/* An edge with nothing to have any more. */
	it = NULL;
	while ((eapp = ucl_object_iterate(applied, &it, true)) != NULL) {
		if (ucl_object_lookup(seen, ucl_object_key(eapp)) != NULL)
			continue;
		oit = NULL;
		while ((o = ucl_object_iterate(eapp, &oit, true)) != NULL) {
			c = ucl_object_copy(o);
			put(c, "server", S(ucl_object_key(eapp)));
			put(c, "key", S(ucl_object_key(o)));
			put(c, "change", S("unmake"));
			put(c, "make", ucl_object_typed_new(UCL_ARRAY));
			ucl_array_append(out, c);
		}
	}
	ucl_object_unref(seen);
	return (out);
}

/* ---- Doing it ------------------------------------------------------- */

struct run {
	ucl_object_t	*st;		/* the state, written as it goes */
	ucl_object_t	*steps;		/* st's apply.steps */
	ucl_object_t	*alloc;		/* allocations, to keep at the end */
	ucl_object_t	*keys;		/* resolved: what was read, cached */
	int		 lockfd;
};

static ucl_object_t *
parse(const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	if (json == NULL)
		return (NULL);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) : NULL;
	ucl_parser_free(p);
	return (o);
}

static const ucl_object_t *
at_path(const ucl_object_t *o, const char *a, const char *b)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, a);
	return (b != NULL ? ucl_object_lookup(v, b) : v);
}

/*
 * ${wg:SID:IF}, the public key of that host's wg interface; ${ipsec:SID},
 * that host's IPsec key: read once, kept for the rest of the run.
 */
static char *
resolve(struct run *r, const char *ref, char *why, size_t wlen)
{
	char		 sid[16], ifn[32], uri[256], peer[256], name[128];
	char		*json, *out;
	const ucl_object_t *v, *i;
	ucl_object_iter_t it;
	ucl_object_t	*ans;
	int		 status;
	bool		 wg;

	if ((v = ucl_object_lookup(r->keys, ref)) != NULL)
		return (strdup(ucl_object_tostring(v)));
	wg = strncmp(ref, "${wg:", 5) == 0;
	ifn[0] = '\0';
	if (wg ? sscanf(ref, "${wg:%15[^:]:%31[^}]}", sid, ifn) != 2 :
	    sscanf(ref, "${ipsec:%15[^}]}", sid) != 1) {
		snprintf(why, wlen, "%s is not a reference", ref);
		return (NULL);
	}
	if (!host_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
	    sizeof(name))) {
		snprintf(why, wlen, "no server %s", sid);
		return (NULL);
	}
	json = hosts_net(uri, peer, name, wg ? "wireguard" : "ipsec", &status);
	ans = parse(json);
	free(json);
	out = NULL;
	if (wg) {
		it = NULL;
		while ((i = ucl_object_iterate(at_path(ans, "data",
		    "interfaces"), &it, true)) != NULL)
			if (str(i, "name") != NULL && strcmp(str(i, "name"),
			    ifn) == 0 && str(i, "public-key") != NULL)
				out = strdup(str(i, "public-key"));
	} else if (str(at_path(ans, "data", NULL), "public-key") != NULL)
		out = strdup(str(at_path(ans, "data", NULL), "public-key"));
	if (ans != NULL)
		ucl_object_unref(ans);
	if (out == NULL) {
		snprintf(why, wlen, "%s has no %s key yet", name, wg ? ifn :
		    "IPsec");
		return (NULL);
	}
	ucl_object_insert_key(r->keys, S(out), ref, 0, true);
	return (out);
}

/* A job's ${...} made what they say, and our own fields taken out. */
static ucl_object_t *
job_ready(struct run *r, const ucl_object_t *j, char *why, size_t wlen)
{
	ucl_object_t		*c;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	char			*val;

	c = ucl_object_copy(j);
	(void)ucl_object_delete_key(c, "_after");
	it = NULL;
	while ((v = ucl_object_iterate(j, &it, true)) != NULL) {
		if (ucl_object_type(v) != UCL_STRING || strncmp(
		    ucl_object_tostring(v), "${", 2) != 0)
			continue;
		if ((val = resolve(r, ucl_object_tostring(v), why, wlen)) ==
		    NULL) {
			ucl_object_unref(c);
			return (NULL);
		}
		put(c, ucl_object_key(v), S(val));
		free(val);
	}
	return (c);
}

/* A job sent to a host and waited for; false and why when it failed. */
static bool
job_run(const char *sid, const ucl_object_t *j, char *why, size_t wlen)
{
	char		 uri[256], peer[256], name[128], *json;
	const char	*e, *st;
	ucl_object_t	*ans, *jr;
	uint64_t	 id;
	time_t		 until;
	int		 status;

	if (!host_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
	    sizeof(name))) {
		snprintf(why, wlen, "no server %s", sid);
		return (false);
	}
	if ((json = hosts_submit(uri, peer, name, j, &status, &e)) == NULL) {
		snprintf(why, wlen, "%s", e != NULL ? e : "not sent");
		return (false);
	}
	ans = parse(json);
	free(json);
	if (status != 200 || ans == NULL || (id = (uint64_t)ucl_object_toint(
	    ucl_object_lookup(ucl_array_find_index(ucl_object_lookup(ans,
	    "jobs"), 0), "id"))) == 0) {
		snprintf(why, wlen, "%s", ans != NULL && at_path(ans, "error",
		    "message") != NULL ? ucl_object_tostring_forced(at_path(ans,
		    "error", "message")) : ans != NULL && str(ans, "error") !=
		    NULL ? str(ans, "error") : "the host did not take it");
		if (ans != NULL)
			ucl_object_unref(ans);
		return (false);
	}
	ucl_object_unref(ans);
	until = time(NULL) + JOB_WAIT_S;
	for (;;) {
		usleep(JOB_POLL_US);
		json = hosts_job(uri, peer, name, id, &status);
		jr = parse(json);
		free(json);
		if (jr == NULL) {
			if (time(NULL) > until) {
				snprintf(why, wlen, "the host did not say how "
				    "the job ended");
				return (false);
			}
			continue;
		}
		st = ucl_object_tostring_forced(at_path(jr, "job", "state"));
		if (strcmp(st, "done") == 0 || strcmp(st, "cancelled") == 0) {
			/* Done is how it ended, ok whether it did it. */
			bool ok = strcmp(st, "done") == 0 && ucl_object_type(
			    at_path(jr, "job", "ok")) == UCL_BOOLEAN &&
			    ucl_object_toboolean(at_path(jr, "job", "ok"));

			if (!ok)
				snprintf(why, wlen, "%s",
				    ucl_object_tostring_forced(at_path(jr,
				    "job", "error")));
			ucl_object_unref(jr);
			return (ok);
		}
		ucl_object_unref(jr);
		if (time(NULL) > until) {
			snprintf(why, wlen, "it took more than %d s",
			    JOB_WAIT_S);
			return (false);
		}
	}
}

/* net.fibs on the host, or -1. */
static int64_t
fibs_now(const char *sid)
{
	char		 uri[256], peer[256], name[128], *json;
	const ucl_object_t *v;
	ucl_object_iter_t it;
	ucl_object_t	*ans;
	int64_t		 n;
	int		 status;

	if (!host_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
	    sizeof(name)))
		return (-1);
	json = hosts_sysctl(uri, peer, name, "net.fibs", &status);
	ans = parse(json);
	free(json);
	n = -1;
	it = NULL;
	while ((v = ucl_object_iterate(at_path(ans, "data", "values"), &it,
	    true)) != NULL)
		if (str(v, "name") != NULL && strcmp(str(v, "name"),
		    "net.fibs") == 0)
			n = strtoll(ucl_object_tostring_forced(
			    ucl_object_lookup(v, "value")), NULL, 10);
	if (ans != NULL)
		ucl_object_unref(ans);
	return (n);
}

static void
step_set(struct run *r, ucl_object_t *s, const char *state,
    const char *detail)
{

	put(s, "state", S(state));
	if (detail != NULL)
		put(s, "detail", S(detail));
	put(s, "at", I(time(NULL)));
	state_save(r->st);
}

static ucl_object_t *
applied_of(struct run *r, const char *sid)
{
	ucl_object_t	*ap, *e;

	ap = (ucl_object_t *)(uintptr_t)ucl_object_lookup(r->st, "applied");
	if ((e = (ucl_object_t *)(uintptr_t)ucl_object_lookup(ap, sid)) ==
	    NULL) {
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(ap, e, sid, 0, true);
	}
	return (e);
}

/* What was made taken away: its jobs, each tried. */
static bool
do_unmake(struct run *r, ucl_object_t *s)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;
	char			 why[600], all[1200];
	bool			 ok;

	ok = true;
	all[0] = '\0';
	it = NULL;
	while ((j = ucl_object_iterate(ucl_object_lookup(s, "unmake"), &it,
	    true)) != NULL)
		if (!job_run(str(s, "server"), j, why, sizeof(why))) {
			ok = false;
			snprintf(all + strlen(all), sizeof(all) - strlen(all),
			    "%s%s", all[0] != '\0' ? "; " : "", why);
		}
	/* Gone or not, it is no longer the console's to keep. */
	(void)ucl_object_delete_key(applied_of(r, str(s, "server")), str(s,
	    "key"));
	step_set(r, s, ok ? "done" : "failed", ok ? NULL : all);
	return (ok);
}

/* What is to be made, made: its jobs in order; the first failing stops. */
static bool
do_make(struct run *r, ucl_object_t *s)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;
	ucl_object_t		*ready, *keep, *un;
	char			 why[600];
	int64_t			 have;
	int			 done;

	/* net.fibs only ever goes up. */
	if (ucl_object_lookup(s, "fibs") != NULL && (have = fibs_now(str(s,
	    "server"))) >= ucl_object_toint(ucl_object_lookup(s, "fibs"))) {
		snprintf(why, sizeof(why), "it has %jd already",
		    (intmax_t)have);
		goto made;
	}
	why[0] = '\0';
	un = ucl_object_copy(ucl_object_lookup(s, "unmake"));
	done = 0;
	it = NULL;
	while ((j = ucl_object_iterate(ucl_object_lookup(s, "make"), &it,
	    true)) != NULL) {
		if ((ready = job_ready(r, j, why, sizeof(why))) == NULL ||
		    !job_run(str(s, "server"), ready, why, sizeof(why))) {
			const ucl_object_t	*u;
			ucl_object_iter_t	 uit;
			char			 e2[300];

			if (ready != NULL)
				ucl_object_unref(ready);
			/* What it made already taken away: none left half. */
			uit = NULL;
			while (done > 0 && (u = ucl_object_iterate(un, &uit,
			    true)) != NULL)
				(void)job_run(str(s, "server"), u, e2,
				    sizeof(e2));
			ucl_object_unref(un);
			step_set(r, s, "failed", why);
			return (false);
		}
		done++;
		/* A wg peer is taken away by the key it was made with. */
		if (strcmp(str(ready, "kind"), "wireguard") == 0 && str(ready,
		    "verb") != NULL && strcmp(str(ready, "verb"), "peer") == 0)
			ucl_array_append(un, job("wireguard", "verb",
			    S("unpeer"), "interface", S(str(ready, "interface")),
			    "peer", S(str(ready, "peer")), "persist", B(true),
			    NULL));
		ucl_object_unref(ready);
	}
	put(s, "unmake", un);
	why[0] = '\0';
made:
	keep = ucl_object_typed_new(UCL_OBJECT);
	put(keep, "title", S(str(s, "title")));
	put(keep, "phase", I(ucl_object_toint(ucl_object_lookup(s, "phase"))));
	put(keep, "spec", S(str(s, "spec")));
	put(keep, "unmake", ucl_object_copy(ucl_object_lookup(s, "unmake")));
	ucl_object_insert_key(applied_of(r, str(s, "server")), keep, str(s,
	    "key"), 0, true);
	step_set(r, s, "done", why[0] != '\0' ? why : NULL);
	return (true);
}

static void *
run_main(void *arg)
{
	struct run		*r = arg;
	ucl_object_t		*s, *ap;
	ucl_object_iter_t	 it;
	const char		*ch;
	int			 ph;
	bool			 ok;

	ok = true;
	/* Taken away first, the last made first. */
	for (ph = PHASES; ph >= 1; ph--) {
		it = NULL;
		while ((s = (ucl_object_t *)(uintptr_t)ucl_object_iterate(
		    r->steps, &it, true)) != NULL) {
			ch = str(s, "change");
			if (ucl_object_toint(ucl_object_lookup(s, "phase")) !=
			    ph || (strcmp(ch, "unmake") != 0 && strcmp(ch,
			    "remake") != 0) || ucl_array_size(
			    ucl_object_lookup(s, "unmake")) == 0)
				continue;
			if (strcmp(ch, "unmake") == 0)
				(void)do_unmake(r, s);
			else {
				/* Its old self, then the new one below. */
				(void)do_unmake(r, s);
				put(s, "state", S("pending"));
			}
		}
	}
	/* Each unmade one with nothing to undo is simply forgotten. */
	it = NULL;
	while ((s = (ucl_object_t *)(uintptr_t)ucl_object_iterate(r->steps,
	    &it, true)) != NULL)
		if (strcmp(str(s, "change"), "unmake") == 0 && strcmp(str(s,
		    "state"), "pending") == 0) {
			(void)ucl_object_delete_key(applied_of(r, str(s,
			    "server")), str(s, "key"));
			step_set(r, s, "done", NULL);
		}
	/* Then made, step by step, every edge before the next step. */
	for (ph = 1; ok && ph <= PHASES; ph++) {
		it = NULL;
		while (ok && (s = (ucl_object_t *)(uintptr_t)ucl_object_iterate(
		    r->steps, &it, true)) != NULL) {
			ch = str(s, "change");
			if (ucl_object_toint(ucl_object_lookup(s, "phase")) !=
			    ph || (strcmp(ch, "make") != 0 && strcmp(ch,
			    "remake") != 0))
				continue;
			put(s, "unmake", ucl_object_copy(ucl_object_lookup(s,
			    "unmake_new")));
			ok = do_make(r, s);
		}
	}
	/* All made: only the allocations of what is there now are kept. */
	if (ok)
		put(r->st, "alloc", ucl_object_ref(r->alloc));
	ap = (ucl_object_t *)(uintptr_t)ucl_object_lookup(r->st, "apply");
	it = NULL;
	while (!ok && (s = (ucl_object_t *)(uintptr_t)ucl_object_iterate(
	    r->steps, &it, true)) != NULL)
		if (strcmp(str(s, "state"), "pending") == 0)
			put(s, "state", S("not run"));
	put(ap, "state", S(ok ? "done" : "failed"));
	put(ap, "ended", I(time(NULL)));
	state_save(r->st);
	thread_log(ok ? LOG_NOTICE : LOG_ERR, "sdwan: apply %s", ok ? "done" :
	    "failed");
	ucl_object_unref(r->st);
	ucl_object_unref(r->alloc);
	ucl_object_unref(r->keys);
	if (r->lockfd != -1)
		close(r->lockfd);
	free(r);
	pthread_mutex_lock(&st_lock);
	applying = false;
	pthread_mutex_unlock(&st_lock);
	return (NULL);
}

/* ---- The API --------------------------------------------------------- */

static const char *
server_name_of(const char *sid)
{
	const struct server	*s;

	return ((s = server_find(sid)) != NULL ? s->name : sid);
}

/* The changes as the API shows them: no job's own fields of ours. */
static ucl_object_t *
plan_reply(const struct plan *pl, const ucl_object_t *chg)
{
	ucl_object_t		*top, *arr, *c;
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((o = ucl_object_iterate(chg, &it, true)) != NULL) {
		c = ucl_object_copy(o);
		(void)ucl_object_delete_key(c, "spec");
		put(c, "name", S(server_name_of(str(o, "server"))));
		ucl_array_append(arr, c);
	}
	put(top, "changes", arr);
	put(top, "tunnels", ucl_object_copy(pl->tunnels));
	return (top);
}

int
api_sdwan_edges(struct http_request *req)
{
	ucl_object_t		*doc, *st, *chg, *body, *ap, *steps, *s;
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	struct plan		 pl;
	struct run		*r;
	pthread_t		 tid;
	char			 why[300], path[MAXPATHLEN];
	bool			 apply, fresh;
	int			 fd;

	apply = strcmp(req->path, "/api/sdwan/apply") == 0;
	if (req->method == HTTP_METHOD_GET) {
		if (!guard(req, false))
			return (KORE_RESULT_OK);
		if (apply) {
			pthread_mutex_lock(&st_lock);
			st = state_load();
			pthread_mutex_unlock(&st_lock);
			body = ucl_object_typed_new(UCL_OBJECT);
			put(body, "apply", ucl_object_lookup(st, "apply") !=
			    NULL ? ucl_object_copy(ucl_object_lookup(st,
			    "apply")) : ucl_object_typed_new(UCL_OBJECT));
			put(body, "applying", B(applying));
			ucl_object_unref(st);
			return (reply_json(req, 200, body));
		}
	} else if (!guard(req, true))
		return (KORE_RESULT_OK);
	doc = sdwan_load();
	if (!sdwan_valid(doc, why, sizeof(why))) {
		ucl_object_unref(doc);
		return (reply_error(req, 409, "invalid", "the kept document is "
		    "not one to make: %s", why));
	}
	fresh = false;
	if (apply && (body = read_json(req)) != NULL) {
		fresh = ucl_flag(body, "fresh");
		ucl_object_unref(body);
	}
	pthread_mutex_lock(&st_lock);
	st = state_load();
	pthread_mutex_unlock(&st_lock);
	if (!plan_build(&pl, doc, st)) {
		snprintf(why, sizeof(why), "%s", pl.why);
		plan_free(&pl);
		ucl_object_unref(doc);
		ucl_object_unref(st);
		return (reply_error(req, 409, "unplanned", "%s", why));
	}
	chg = changes(&pl, st, fresh);
	if (!apply) {
		body = plan_reply(&pl, chg);
		ucl_object_unref(chg);
		plan_free(&pl);
		ucl_object_unref(doc);
		ucl_object_unref(st);
		return (reply_json(req, 200, body));
	}
	/* One apply at a time, in this worker and every other. */
	pthread_mutex_lock(&st_lock);
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, LOCK_FILE);
	fd = -1;
	if (applying || (fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC,
	    0600)) == -1 || flock(fd, LOCK_EX | LOCK_NB) == -1) {
		pthread_mutex_unlock(&st_lock);
		if (fd != -1)
			close(fd);
		ucl_object_unref(chg);
		plan_free(&pl);
		ucl_object_unref(doc);
		ucl_object_unref(st);
		return (reply_error(req, 409, "busy", "an apply is running"));
	}
	applying = true;
	pthread_mutex_unlock(&st_lock);
	/* The servers as they are now, for the thread. */
	host_refs();
	/* The steps: each change but what stays as it is. */
	steps = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((o = ucl_object_iterate(chg, &it, true)) != NULL) {
		if (strcmp(str(o, "change"), "keep") == 0)
			continue;
		s = ucl_object_copy(o);
		/* Its old unmake for taking it away, its new for keeping. */
		if (strcmp(str(o, "change"), "remake") == 0 ||
		    strcmp(str(o, "change"), "make") == 0) {
			const ucl_object_t	*n;

			n = by(edge_list(&pl, str(o, "server")), "key", str(o,
			    "key"));
			put(s, "unmake_new", n != NULL ? ucl_object_copy(
			    ucl_object_lookup(n, "unmake")) :
			    ucl_object_typed_new(UCL_ARRAY));
		}
		put(s, "name", S(server_name_of(str(o, "server"))));
		put(s, "state", S("pending"));
		ucl_array_append(steps, s);
	}
	ap = ucl_object_typed_new(UCL_OBJECT);
	put(ap, "state", S("running"));
	put(ap, "started", I(time(NULL)));
	put(ap, "fresh", B(fresh));
	put(ap, "steps", steps);
	put(ap, "tunnels", ucl_object_copy(pl.tunnels));
	put(st, "apply", ap);
	/* The allocations of what is made: new ones now, gone ones after. */
	{
		ucl_object_t		*keep;
		const ucl_object_t	*a;

		keep = ucl_object_typed_new(UCL_OBJECT);
		it = NULL;
		while ((a = ucl_object_iterate(pl.alloc, &it, true)) != NULL)
			if (ucl_object_lookup(pl.used, ucl_object_key(a)) !=
			    NULL)
				ucl_object_insert_key(keep, ucl_object_copy(a),
				    ucl_object_key(a), 0, true);
		put(st, "alloc", ucl_object_copy(pl.alloc));
		if ((r = calloc(1, sizeof(*r))) == NULL)
			abort();
		r->alloc = keep;
	}
	state_save(st);
	r->st = st;
	r->steps = (ucl_object_t *)(uintptr_t)ucl_object_lookup(ap, "steps");
	r->keys = ucl_object_typed_new(UCL_OBJECT);
	r->lockfd = fd;
	ucl_object_unref(chg);
	body = ucl_object_typed_new(UCL_OBJECT);
	put(body, "steps", I((int64_t)ucl_array_size(r->steps)));
	plan_free(&pl);
	ucl_object_unref(doc);
	if (pthread_create(&tid, NULL, run_main, r) != 0) {
		close(fd);
		pthread_mutex_lock(&st_lock);
		applying = false;
		pthread_mutex_unlock(&st_lock);
		ucl_object_unref(body);
		return (reply_error(req, 500, "thread", "%s", strerror(errno)));
	}
	(void)pthread_detach(tid);
	return (reply_json(req, 200, body));
}
