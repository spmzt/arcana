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
 *	probes		the tunnels measured: each one's far inner address,
 *			pinged by the agent through the service's FIB
 *			(sdwan-probes), as the service's probe settings say
 *	rules		the ipfw rules that classify what comes in at the
 *			UNIs, zone by zone and flow by flow, and steer each
 *			flow by its policy's table (sdwan-rules)
 *	steer		what those tables hold: each far prefix's tunnels in
 *			order, the first not down taken (sdwan-steer)
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
 *	GET  /api/sdwan/apply	how the last apply went, the history, and the tunnels
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
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
#define	PHASES		10
#define	LIST_SUBS	16	/* a UNI's subnets, the first and more */
#define	CANDS_MAX_ORDER	16	/* an entry's candidates the manager orders */

enum { PH_FIBS = 1, PH_IPSEC, PH_TVC, PH_PEER, PH_PROBE, PH_RULES, PH_STEER,
    PH_ROUTE, PH_UNI, PH_BIRD };

static pthread_mutex_t	st_lock = PTHREAD_MUTEX_INITIALIZER;
static bool		applying;

static const char	*server_name_of(const char *);

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
	ucl_object_t		*notes;		/* what the plan leaves out, and why */
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

/*
 * What a tunnel over a UCS is, when the UCS does not say; *saidp,
 * whether the UCS said about IPsec itself.
 */
static void
tunnel_of(const ucl_object_t *ucs, const char **kindp, bool *ipsecp,
    bool *saidp)
{
	const ucl_object_t	*t;
	bool			 public;

	public = str(ucs, "type") != NULL && strcmp(str(ucs, "type"),
	    "public") == 0;
	t = ucl_object_lookup(ucs, "tunnel");
	*kindp = t != NULL && str(t, "kind") != NULL ? str(t, "kind") : "gre";
	*saidp = t != NULL && ucl_object_lookup(t, "ipsec") != NULL;
	if (strcmp(*kindp, "wg") == 0)
		*ipsecp = false;
	else if (*saidp)
		*ipsecp = ucl_flag(t, "ipsec");
	else
		*ipsecp = public;	/* the Internet's, encrypted */
}

/* Does a policy of the service require encryption always (§9.12.2.1)? */
static bool
always_encrypted(const ucl_object_t *sw)
{
	const ucl_object_t	*p;
	ucl_object_iter_t	 it;
	const char		*e;

	it = NULL;
	while ((p = ucl_object_iterate(ucl_object_lookup(sw, "policies"), &it,
	    true)) != NULL) {
		e = str(ucl_object_lookup(p, "criteria"), "encryption");
		if (e != NULL && strcmp(e, "required-always") == 0)
			return (true);
	}
	return (false);
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

/* FNV-1a of a text, as 16 hex digits. */
static char *
digest_text(const char *s, char *buf, size_t len)
{
	uint64_t	h;
	size_t		i;

	h = 0xcbf29ce484222325ULL;
	for (i = 0; s != NULL && s[i] != '\0'; i++) {
		h ^= (unsigned char)s[i];
		h *= 0x100000001b3ULL;
	}
	snprintf(buf, len, "%016jx", (uintmax_t)h);
	return (buf);
}

/* The same of an object, to say a far end changed without its jobs. */
static char *
digest(const ucl_object_t *o, char *buf, size_t len)
{
	char	*s;

	s = emit(o);
	digest_text(s, buf, len);
	free(s);
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
		/*
		 * One connection for the pair of outer addresses and the
		 * kind of tunnel: in transport mode it protects every such
		 * tunnel between the two, and two would conflict.
		 */
		snprintf(key, sizeof(key), "%s|%s|%s", str(a, "underlay"), str(b,
		    "underlay"), kind);
		snprintf(port, sizeof(port), "sdw%.8s", digest_text(key, h,
		    sizeof(h)));
		snprintf(key, sizeof(key), "peer:%s", port);
		if (by(edge_list(pl, sid), "key", key) != NULL) {
			/* Shared with a tunnel before: the one object. */
			ucl_object_t	*a2;

			a2 = edge_list(pl, sid);
			ucl_array_pop_last(a2);
			ucl_object_unref(o);
			return;
		}
		put(o, "key", S(key));
		snprintf(key, sizeof(key), "${ipsec:%s}", str(b, "edge"));
		p = job("ipsec", "verb", S("conn"), "conn", S(port),
		    "tunnel_local", S(str(a, "underlay")), "tunnel_remote",
		    S(str(b, "underlay")), "ipsec_mode", S("transport"),
		    "pubkey", S(key), "local_ts", S(ts_of(kind)), "remote_ts",
		    S(ts_of(kind)), "start_action", S("trap"), "persist",
		    B(true), NULL);
		unmake(o, job("ipsec", "verb", S("unconn"), "conn", S(port),
		    "persist", B(true), NULL));
	}
	/* A wg peer is made again when the far end's interface is: a new
	 * key; an IPsec key is the host's, and stays. */
	if (strcmp(kind, "wg") == 0)
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
	bool			 ipsec, ip2, public, said, said2, always;
	size_t			 i, j;

	doc = pl->doc;
	always = always_encrypted(sw);
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
					tunnel_of(ux, &kind, &ipsec, &said);
					tunnel_of(uy, &k2, &ip2, &said2);
					ipsec = ipsec || ip2;
					/* A policy that wants every tunnel
					 * encrypted (R39): so it is, unless the
					 * UCS says no, which no path mends. */
					if (always && !ipsec && strcmp(kind,
					    "wg") != 0) {
						if ((said && !ucl_flag(
						    ucl_object_lookup(ux,
						    "tunnel"), "ipsec")) ||
						    (said2 && !ucl_flag(
						    ucl_object_lookup(uy,
						    "tunnel"), "ipsec"))) {
							snprintf(pl->why, sizeof(
							    pl->why), "swvc %s: "
							    "a policy requires "
							    "encryption always, "
							    "and UCS %s says no "
							    "IPsec under its "
							    "tunnels (R39)",
							    str(sw, "id"), said
							    ? str(ux, "id") :
							    str(uy, "id"));
							ucl_object_unref(edges);
							return (false);
						}
						ipsec = true;
					}
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
					put(t, "billing", S(str(ux, "billing") !=
					    NULL ? str(ux, "billing") :
					    "flat-rate"));
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
		/* A subnet whoever addresses its hosts. */
		if (str(v, "mode") == NULL || (strcmp(str(v, "mode"), "static")
		    != 0 && strcmp(str(v, "mode"), "dhcp") != 0 && strcmp(str(v,
		    "mode"), "slaac") != 0))
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
		/* The provider's addresses go on, whoever addresses the hosts. */
		if (str(v, "mode") == NULL || (strcmp(str(v, "mode"), "static")
		    != 0 && strcmp(str(v, "mode"), "dhcp") != 0 && strcmp(str(v,
		    "mode"), "slaac") != 0))
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
	/* SLAAC (§11.5): the base system's rtadvd advertises the prefix on
	 * the UNI, and the DNS servers, for the hosts to address
	 * themselves. */
	v = ucl_object_lookup(u, "ipv6");
	if (str(v, "mode") != NULL && strcmp(str(v, "mode"), "slaac") == 0) {
		ucl_object_t	*names;

		snprintf(key, sizeof(key), "rtadvd:%s", str(ep, "id"));
		o = object(pl, str(ep, "edge"), key, PH_UNI, "UNI %s: router "
		    "advertisements of %s on %s by rtadvd (SLAAC)", str(u, "id"),
		    str(v, "prefix"), ifn);
		if (o != NULL) {
			names = ucl_object_typed_new(UCL_ARRAY);
			ucl_array_append(names, S(str(v, "prefix")));
			ait = NULL;
			while ((a = ucl_object_iterate(ucl_object_lookup(v, "dns"),
			    &ait, true)) != NULL)
				ucl_array_append(names, S(ucl_object_tostring_forced(
				    a)));
			make(o, job("rtadvd", "interface", S(ifn), "args", names,
			    "persist", B(true), NULL));
			unmake(o, job("rtadvd", "interface", S(ifn), "args",
			    ucl_object_typed_new(UCL_ARRAY), "remove", B(true),
			    "persist", B(true), NULL));
		}
	}
	return (true);
}

/* ---- DHCP at the UNIs (§11.4, §11.5): dnsmasq, a service an instance -- */

static const char *uni_ifname(struct plan *, const ucl_object_t *,
		    const ucl_object_t *, char *, size_t);

/* An IPv4 address as a number, and back. */
static uint32_t
v4num(const uint8_t *a)
{

	return ((uint32_t)a[0] << 24 | (uint32_t)a[1] << 16 | (uint32_t)a[2] <<
	    8 | a[3]);
}

static const char *
v4str(uint32_t n, char *buf, size_t len)
{

	snprintf(buf, len, "%u.%u.%u.%u", n >> 24, (n >> 16) & 255, (n >> 8) &
	    255, n & 255);
	return (buf);
}

/*
 * The IPv4 ranges dnsmasq gives out at a UNI: the subnet's hosts, less
 * the provider's addresses and the reserved prefixes (§11.4), as
 * dhcp-range lines.
 */
static void
dhcp_ranges4(struct kore_buf *b, const ucl_object_t *v, const char *tag)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct net		 n, r;
	uint32_t		 lo, hi, from, to, x[66][2], t;
	const char		*lease;
	char			 s1[20], s2[20], mask[20];
	int			 nx = 0, i, k;

	if (!net_parse(str(v, "prefix"), &n) || n.af != AF_INET || n.len > 30)
		return;
	lo = v4num(n.a) & (n.len == 0 ? 0 : 0xffffffffu << (32 - n.len));
	hi = lo | (n.len == 0 ? 0xffffffffu : 0xffffffffu >> n.len);
	lease = str(v, "lease") != NULL ? str(v, "lease") : "12h";
	/* What is not given: the provider's, the reserved. */
	it = NULL;
	while (nx < 64 && (e = ucl_object_iterate(ucl_object_lookup(v,
	    "provider"), &it, true)) != NULL)
		if (net_parse(ucl_object_tostring_forced(e), &r) && r.af ==
		    AF_INET) {
			x[nx][0] = x[nx][1] = v4num(r.a);
			nx++;
		}
	it = NULL;
	while (nx < 64 && (e = ucl_object_iterate(ucl_object_lookup(v,
	    "reserved"), &it, true)) != NULL)
		if (net_parse(ucl_object_tostring_forced(e), &r) && r.af ==
		    AF_INET) {
			x[nx][0] = v4num(r.a) & (r.len == 0 ? 0 : 0xffffffffu <<
			    (32 - r.len));
			x[nx][1] = x[nx][0] | (r.len == 0 ? 0xffffffffu :
			    0xffffffffu >> r.len);
			nx++;
		}
	/* In order, by the start. */
	for (i = 1; i < nx; i++)
		for (k = i; k > 0 && x[k][0] < x[k - 1][0]; k--) {
			t = x[k][0]; x[k][0] = x[k - 1][0]; x[k - 1][0] = t;
			t = x[k][1]; x[k][1] = x[k - 1][1]; x[k - 1][1] = t;
		}
	v4str(n.len == 0 ? 0 : 0xffffffffu << (32 - n.len), mask, sizeof(mask));
	from = lo + 1;
	to = hi - 1;
	for (i = 0; i <= nx; i++) {
		uint32_t	end = i < nx ? (x[i][0] > 0 ? x[i][0] - 1 : 0) : to;

		if (i == nx || x[i][0] > from) {
			if (end > to)
				end = to;
			if (from <= end && from > lo)
				kore_buf_appendf(b, "dhcp-range=set:%s,%s,%s,%s,%s\n",
				    tag, v4str(from, s1, sizeof(s1)), v4str(end, s2,
				    sizeof(s2)), mask, lease);
		}
		if (i < nx && x[i][1] + 1 > from)
			from = x[i][1] + 1;
	}
}

/*
 * The IPv6 range at a UNI (§11.5): ::100 to ::ffff of the /64, less a
 * reserved prefix that overlaps it, which splits it, by the low 64 bits.
 */
static void
dhcp_ranges6(struct kore_buf *b, const ucl_object_t *v, const char *tag)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct net		 n, r;
	uint64_t		 from, to, x[66][2], t, rlo, rhi;
	const char		*lease;
	char			 pfx[48], s1[64], s2[64];
	int			 nx = 0, i, k;

	if (!net_parse(str(v, "prefix"), &n) || n.af != AF_INET6 || n.len != 64)
		return;
	snprintf(pfx, sizeof(pfx), "%x:%x:%x:%x", n.a[0] << 8 | n.a[1], n.a[2]
	    << 8 | n.a[3], n.a[4] << 8 | n.a[5], n.a[6] << 8 | n.a[7]);
	lease = str(v, "lease") != NULL ? str(v, "lease") : "12h";
	it = NULL;
	while (nx < 64 && (e = ucl_object_iterate(ucl_object_lookup(v,
	    "reserved"), &it, true)) != NULL) {
		if (!net_parse(ucl_object_tostring_forced(e), &r) || r.af !=
		    AF_INET6 || r.len < 64)
			continue;
		rlo = 0;
		for (k = 8; k < 16; k++)
			rlo = rlo << 8 | r.a[k];
		rlo &= r.len == 128 ? ~(uint64_t)0 : ~(uint64_t)0 << (128 -
		    r.len);
		rhi = rlo | (r.len == 128 ? 0 : ~(uint64_t)0 >> (r.len - 64));
		x[nx][0] = rlo;
		x[nx][1] = rhi;
		nx++;
	}
	for (i = 1; i < nx; i++)
		for (k = i; k > 0 && x[k][0] < x[k - 1][0]; k--) {
			t = x[k][0]; x[k][0] = x[k - 1][0]; x[k - 1][0] = t;
			t = x[k][1]; x[k][1] = x[k - 1][1]; x[k - 1][1] = t;
		}
	from = 0x100;
	to = 0xffff;
	for (i = 0; i <= nx; i++) {
		uint64_t	end = i < nx ? (x[i][0] > 0 ? x[i][0] - 1 : 0) : to;

		if (i == nx || x[i][0] > from) {
			if (end > to)
				end = to;
			if (from <= end) {
				snprintf(s1, sizeof(s1), "%s:%jx:%jx:%jx:%jx", pfx,
				    (uintmax_t)(from >> 48), (uintmax_t)((from >> 32)
				    & 0xffff), (uintmax_t)((from >> 16) & 0xffff),
				    (uintmax_t)(from & 0xffff));
				snprintf(s2, sizeof(s2), "%s:%jx:%jx:%jx:%jx", pfx,
				    (uintmax_t)(end >> 48), (uintmax_t)((end >> 32) &
				    0xffff), (uintmax_t)((end >> 16) & 0xffff),
				    (uintmax_t)(end & 0xffff));
				kore_buf_appendf(b, "dhcp-range=set:%s,%s,%s,64,%s\n",
				    tag, s1, s2, lease);
			}
		}
		if (i < nx && x[i][1] + 1 > from)
			from = x[i][1] + 1;
	}
}

/* dnsmasq's configuration for a service at an edge: its DHCP UNIs. */
static char *
dhcp_conf(struct plan *pl, const ucl_object_t *sw, const char *sid)
{
	struct kore_buf		*b;
	const ucl_object_t	*ep, *u, *v, *a, *e;
	ucl_object_iter_t	 it, ait;
	const char		*ifn;
	char			 vif[32], *out;
	int			 i;
	bool			 ra = false;

	b = kore_buf_alloc(2048);
	kore_buf_appendf(b, "# Written by the Arcana console: SD-WAN service %s "
	    "at %s, in routing table %jd.\n# The hosts' addresses at the UNIs "
	    "(MEF 70.2 §11.4, §11.5); no DNS served here.\nport=0\n"
	    "bind-interfaces\nno-resolv\nno-hosts\ndhcp-authoritative\n", str(sw,
	    "id"), server_name_of(sid), (intmax_t)ucl_object_toint(ucl_object_lookup(sw,
	    "fib")));
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		u = ucl_object_lookup(ep, "uni");
		ifn = uni_ifname(pl, sw, ep, vif, sizeof(vif));
		for (i = 0; i < 2; i++) {
			v = ucl_object_lookup(u, i == 0 ? "ipv4" : "ipv6");
			if (str(v, "mode") == NULL || strcmp(str(v, "mode"), "dhcp")
			    != 0)
				continue;
			kore_buf_appendf(b, "\n# UNI %s, %s\ninterface=%s\n", str(u,
			    "id"), str(v, "prefix"), ifn);
			if (i == 0) {
				dhcp_ranges4(b, v, ifn);
				/* Their router: the provider's first address. */
				a = ucl_array_find_index(ucl_object_lookup(v,
				    "provider"), 0);
				if (a != NULL)
					kore_buf_appendf(b, "dhcp-option=tag:%s,option:"
					    "router,%s\n", ifn,
					    ucl_object_tostring_forced(a));
			} else {
				dhcp_ranges6(b, v, ifn);
				ra = true;
			}
			/* The DNS servers told to the hosts, one line. */
			if (ucl_object_lookup(v, "dns") != NULL && ucl_array_size(
			    ucl_object_lookup(v, "dns")) > 0) {
				kore_buf_appendf(b, "dhcp-option=tag:%s,option%s:"
				    "dns-server", ifn, i == 0 ? "" : "6");
				ait = NULL;
				while ((e = ucl_object_iterate(ucl_object_lookup(v,
				    "dns"), &ait, true)) != NULL)
					kore_buf_appendf(b, ",%s%s%s", i == 0 ? "" : "[",
					    ucl_object_tostring_forced(e), i == 0 ? "" :
					    "]");
				kore_buf_appendf(b, "\n");
			}
		}
	}
	if (ra)
		kore_buf_appendf(b, "\n# IPv6: the hosts told by router advertisements "
		    "to ask (M flag)\nenable-ra\n");
	out = strdup(kore_buf_stringify(b, NULL));
	kore_buf_free(b);
	return (out);
}

/*
 * Each edge's DHCP servers: dnsmasq from packages (the base system has
 * no DHCP server), an instance per service with a DHCP UNI at the edge,
 * in the service's table.
 */
static void
dhcp_build(struct plan *pl, const ucl_object_t *doc)
{
	const ucl_object_t	*sw, *edge, *ep, *u, *v;
	ucl_object_iter_t	 it, eit, pit;
	ucl_object_t		*o, *inst, *list, *names;
	char			 name[32];
	const char		*sid;
	char			*text;
	bool			 here;
	int			 i;

	it = NULL;
	while ((edge = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL) {
		sid = str(edge, "server");
		list = ucl_object_typed_new(UCL_ARRAY);
		eit = NULL;
		while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"),
		    &eit, true)) != NULL) {
			here = false;
			pit = NULL;
			while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
			    "end_points"), &pit, true)) != NULL) {
				if (strcmp(str(ep, "edge"), sid) != 0)
					continue;
				u = ucl_object_lookup(ep, "uni");
				for (i = 0; i < 2; i++) {
					v = ucl_object_lookup(u, i == 0 ? "ipv4" :
					    "ipv6");
					if (str(v, "mode") != NULL && strcmp(str(v,
					    "mode"), "dhcp") == 0)
						here = true;
				}
			}
			if (!here)
				continue;
			snprintf(name, sizeof(name), "sw%jd", (intmax_t)
			    ucl_object_toint(ucl_object_lookup(sw, "fib")));
			inst = ucl_object_typed_new(UCL_OBJECT);
			put(inst, "name", S(name));
			put(inst, "fib", I(ucl_object_toint(ucl_object_lookup(sw,
			    "fib"))));
			text = dhcp_conf(pl, sw, sid);
			put(inst, "conf", S(text));
			free(text);
			ucl_array_append(list, inst);
		}
		if (ucl_array_size(list) == 0) {
			ucl_object_unref(list);
			continue;
		}
		/* The package, with the tables: once. */
		o = object(pl, sid, "dnsmasq", PH_FIBS, "dnsmasq from packages: "
		    "the DHCP server at the UNIs, which the base system has not");
		if (o != NULL) {
			names = ucl_object_typed_new(UCL_ARRAY);
			ucl_array_append(names, S("dnsmasq"));
			make(o, job("pkg-install", "packages", names, NULL));
		}
		o = object(pl, sid, "dhcp", PH_BIRD, "DHCP: dnsmasq, %u instance%s "
		    "in the services' tables, the hosts' addresses at the UNIs",
		    ucl_array_size(list), ucl_array_size(list) == 1 ? "" : "s");
		if (o == NULL) {
			ucl_object_unref(list);
			continue;
		}
		make(o, job("sdwan-dhcp", "instances", list, NULL));
		unmake(o, job("sdwan-dhcp", "instances", ucl_object_typed_new(
		    UCL_ARRAY), NULL));
	}
}


/* ---- The rules: classification and steering (§8, §9.12, §10.4) ----- */

#define	RULE_FROM	10	/* the rules' numbers, from here */
#define	RULE_TO		99	/* to here, the way out of them */
#define	IPFW_SET	30

/* APPID (Table 8): what each application is, as ports and a protocol. */
static const struct {
	const char	*id, *proto, *ports;
} appids[] = {
	{ "dns", NULL, "53" }, { "http", "tcp", "80" },
	{ "https", "tcp", "443" }, { "ssh", "tcp", "22" },
	{ "sip", NULL, "5060,5061" }, { "ntp", "udp", "123" },
	{ "smtp", "tcp", "25,465,587" }, { "imap", "tcp", "143,993" },
	{ "pop3", "tcp", "110,995" }, { "ldap", "tcp", "389,636" },
	{ "rdp", "tcp", "3389" }, { "snmp", "udp", "161,162" },
	{ "syslog", "udp", "514" }, { "ike", "udp", "500,4500" },
	{ "bgp", "tcp", "179" }, { "quic", "udp", "443" },
	{ "dhcp", "udp", "67,68" }, { "icmp", "icmp", NULL },
};

/* A list's values joined by commas, into buf. */
static const char *
join(const ucl_object_t *arr, char *buf, size_t len)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	size_t			 n;

	buf[0] = '\0';
	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(arr, &it, true)) != NULL && n < len - 1)
		n += (size_t)snprintf(buf + n, len - n, "%s%s", n > 0 ? "," : "",
		    ucl_object_tostring_forced(v));
	return (buf);
}

/*
 * An application flow's criteria as the words of an ipfw rule after
 * its action: "ip from SRC to DST options"; with to_table, DST is the
 * table named (dst addresses then as dst-ip).  Into out; false when
 * no packet can match (IPv4 and IPv6 criteria both), or a criterion
 * cannot be said (ethertype).  fam is 0, 4 or 6 as the criteria say.
 */
static bool
afs_words(const ucl_object_t *cr, const char *to_table, const char *appid,
    char *out, size_t len, int *famp)
{
	const ucl_object_t	*v;
	char			 src[600], dst[600], opt[900], l[600];
	const char		*proto;
	int			 fam;
	size_t			 i;

	fam = 0;
	snprintf(src, sizeof(src), "any");
	snprintf(dst, sizeof(dst), "%s", to_table != NULL ? to_table : "any");
	opt[0] = '\0';
	proto = "ip";
	if (ucl_object_lookup(cr, "ethertype") != NULL)
		return (false);
	if ((v = ucl_object_lookup(cr, "sav4")) != NULL) {
		fam = 4;
		snprintf(src, sizeof(src), "%s", join(v, l, sizeof(l)));
	}
	if ((v = ucl_object_lookup(cr, "sav6")) != NULL) {
		if (fam == 4)
			return (false);
		fam = 6;
		snprintf(src, sizeof(src), "%s", join(v, l, sizeof(l)));
	}
	if ((v = ucl_object_lookup(cr, "dav4")) != NULL ||
	    (v = ucl_object_lookup(cr, "dav6")) != NULL) {
		if (fam != 0 && fam != (ucl_object_lookup(cr, "dav4") != NULL ?
		    4 : 6))
			return (false);
		fam = ucl_object_lookup(cr, "dav4") != NULL ? 4 : 6;
		if (to_table != NULL)
			snprintf(opt + strlen(opt), sizeof(opt) - strlen(opt),
			    " dst-ip %s", join(v, l, sizeof(l)));
		else
			snprintf(dst, sizeof(dst), "%s", join(v, l, sizeof(l)));
	}
	if ((v = ucl_object_lookup(cr, "sdav4")) != NULL ||
	    (v = ucl_object_lookup(cr, "sdav6")) != NULL) {
		if (fam != 0 && fam != (ucl_object_lookup(cr, "sdav4") != NULL ?
		    4 : 6))
			return (false);
		fam = ucl_object_lookup(cr, "sdav4") != NULL ? 4 : 6;
		join(v, l, sizeof(l));
		snprintf(opt + strlen(opt), sizeof(opt) - strlen(opt),
		    " { src-ip %s or dst-ip %s }", l, l);
	}
	if ((v = ucl_object_lookup(cr, "protv4")) != NULL ||
	    (v = ucl_object_lookup(cr, "nextheadv6")) != NULL) {
		const ucl_object_t	*e;
		ucl_object_iter_t	 it;
		int			 n;

		if (ucl_array_size(v) == 1)
			proto = ucl_object_tostring_forced(ucl_array_find_index(
			    v, 0));
		else {
			snprintf(opt + strlen(opt), sizeof(opt) - strlen(opt),
			    " {");
			n = 0;
			it = NULL;
			while ((e = ucl_object_iterate(v, &it, true)) != NULL)
				snprintf(opt + strlen(opt), sizeof(opt) -
				    strlen(opt), "%s proto %s", n++ > 0 ? " or" :
				    "", ucl_object_tostring_forced(e));
			snprintf(opt + strlen(opt), sizeof(opt) - strlen(opt),
			    " }");
		}
	}
	if (appid != NULL) {
		for (i = 0; i < nitems(appids); i++)
			if (strcmp(appids[i].id, appid) == 0)
				break;
		if (i == nitems(appids))
			return (false);
		if (appids[i].proto != NULL)
			proto = appids[i].proto;
		if (appids[i].ports != NULL)
			snprintf(opt + strlen(opt), sizeof(opt) - strlen(opt),
			    " { src-port %s or dst-port %s }", appids[i].ports,
			    appids[i].ports);
	}
	if ((v = ucl_object_lookup(cr, "sport")) != NULL)
		snprintf(opt + strlen(opt), sizeof(opt) - strlen(opt),
		    " src-port %s", join(v, l, sizeof(l)));
	if ((v = ucl_object_lookup(cr, "dport")) != NULL)
		snprintf(opt + strlen(opt), sizeof(opt) - strlen(opt),
		    " dst-port %s", join(v, l, sizeof(l)));
	if ((v = ucl_object_lookup(cr, "sdport")) != NULL) {
		join(v, l, sizeof(l));
		snprintf(opt + strlen(opt), sizeof(opt) - strlen(opt),
		    " { src-port %s or dst-port %s }", l, l);
	}
	if ((v = ucl_object_lookup(cr, "dscp")) != NULL)
		snprintf(opt + strlen(opt), sizeof(opt) - strlen(opt), " dscp %s",
		    join(v, l, sizeof(l)));
	if (strcmp(proto, "ip") == 0 && fam != 0)
		proto = fam == 4 ? "ip4" : "ip6";
	snprintf(out, len, "%s from %s to %s%s", proto, src, dst, opt);
	*famp = fam;
	return (true);
}

/*
 * The ingress policy of a flow in a zone at an end point (§10.4,
 * R109-R112): the end point's map by the flow, then by its group,
 * then the zone's by the flow, then by its group; none, dropped.
 * NULL for none, "Block", or the policy's name.
 */
static const char *
policy_for(const ucl_object_t *ep, const ucl_object_t *zone,
    const ucl_object_t *afs)
{
	const ucl_object_t	*m;
	ucl_object_iter_t	 it;
	const char		*name, *group, *v;
	int			 pass;

	name = str(afs, "name");
	group = str(afs, "group");
	if (group != NULL && strcmp(group, "None") == 0)
		group = NULL;
	for (pass = 0; pass < 4; pass++) {
		const ucl_object_t	*list = pass < 2 ? ucl_object_lookup(ep,
		    "policy_map") : ucl_object_lookup(zone, "policies");
		const char		*want = pass % 2 == 0 ? name : group;

		if (want == NULL)
			continue;
		it = NULL;
		while ((m = ucl_object_iterate(list, &it, true)) != NULL) {
			if (pass < 2 && (str(m, "zone") == NULL || strcmp(str(m,
			    "zone"), str(zone, "name")) != 0))
				continue;
			if (str(m, "app") == NULL || strcmp(str(m, "app"), want)
			    != 0)
				continue;
			v = str(m, pass < 2 ? "ingress" : "policy");
			return (v);
		}
	}
	return (NULL);
}

/* The zone a prefix's hosts are in: by its prefixes, else Default. */
static const ucl_object_t *
zone_of(const ucl_object_t *sw, const char *prefix)
{
	const ucl_object_t	*z, *p, *list, *best, *dflt;
	ucl_object_iter_t	 it, pit;
	struct net		 n, zn;
	int			 blen;

	if (!net_parse(prefix, &n))
		return (NULL);
	best = dflt = NULL;
	blen = -1;
	it = NULL;
	while ((z = ucl_object_iterate(ucl_object_lookup(sw, "zones"), &it,
	    true)) != NULL) {
		list = ucl_object_lookup(z, "prefixes");
		if (ucl_object_type(list) == UCL_STRING) {
			dflt = z;
			continue;
		}
		pit = NULL;
		while ((p = ucl_object_iterate(list, &pit, true)) != NULL) {
			if (!net_parse(ucl_object_tostring_forced(p), &zn) ||
			    zn.af != n.af || zn.len > n.len || zn.len <= blen)
				continue;
			if (memcmp(zn.a, n.a, (size_t)zn.len / 8) == 0 &&
			    (zn.len % 8 == 0 || ((zn.a[zn.len / 8] ^ n.a[zn.len /
			    8]) & (0xff << (8 - zn.len % 8))) == 0)) {
				best = z;
				blen = zn.len;
			}
		}
	}
	return (best != NULL ? best : dflt);
}

/* May a flow of a policy in zone z reach the hosts of zone dz? (R58-R62) */
static bool
zone_allowed(const ucl_object_t *pol, const ucl_object_t *z,
    const ucl_object_t *dz)
{
	const ucl_object_t	*adz;

	if (dz == NULL)
		return (false);
	adz = pol != NULL ? ucl_object_lookup(ucl_object_lookup(pol,
	    "criteria"), "allowed-destination-zones") : NULL;
	if (adz == NULL)
		return (z == dz);		/* [Self], R62 */
	if (ucl_object_type(adz) == UCL_STRING)
		return (true);			/* All */
	if (z == dz && in_list(adz, "Self"))
		return (true);
	return (in_list(adz, str(dz, "name")));
}

/* May a flow of a policy go from end point a to end point b? (§9.6) */
static bool
vt_allows(const ucl_object_t *sw, const ucl_object_t *pol, const char *a,
    const char *b)
{
	const ucl_object_t	*t;
	const char		*vt;

	vt = pol != NULL ? str(ucl_object_lookup(pol, "criteria"),
	    "virtual-topology") : NULL;
	if (vt == NULL || strcmp(vt, "Swvc") == 0 || (t = by(ucl_object_lookup(
	    sw, "topologies"), "name", vt)) == NULL)
		return (true);
	if (ucl_object_lookup(t, "end_points") != NULL)
		return (in_list(ucl_object_lookup(t, "end_points"), a) &&
		    in_list(ucl_object_lookup(t, "end_points"), b));
	/* Rooted: a leaf reaches roots only; a root reaches all (R50, R51). */
	if (in_list(ucl_object_lookup(t, "roots"), a))
		return (in_list(ucl_object_lookup(t, "roots"), b) ||
		    in_list(ucl_object_lookup(t, "leaves"), b));
	return (in_list(ucl_object_lookup(t, "leaves"), a) && in_list(
	    ucl_object_lookup(t, "roots"), b));
}

/* Does a tunnel meet a policy's criteria of the way (§9.12.2)? */
static bool
tunnel_fits(const ucl_object_t *t, const ucl_object_t *pol, bool backup_ok)
{
	const ucl_object_t	*cr;
	const char		*v;

	cr = pol != NULL ? ucl_object_lookup(pol, "criteria") : NULL;
	v = str(cr, "encryption");
	if (v != NULL && strcmp(v, "required-always") == 0 && !ucl_flag(t,
	    "encrypted"))
		return (false);
	if (v != NULL && strcmp(v, "required-public-only") == 0 && ucl_flag(t,
	    "public") && !ucl_flag(t, "encrypted"))
		return (false);
	v = str(cr, "public-private");
	if (v != NULL && strcmp(v, "private-only") == 0 && ucl_flag(t,
	    "public"))
		return (false);
	v = str(cr, "billing-method");
	if (v != NULL && str(t, "billing") != NULL && ((strcmp(v,
	    "flat-rate-only") == 0 && strcmp(str(t, "billing"), "flat-rate") !=
	    0) || (strcmp(v, "usage-based-only") == 0 && strcmp(str(t,
	    "billing"), "usage-based") != 0)))
		return (false);
	if (ucl_flag(t, "backup") && !backup_ok)
		return (false);
	return (true);
}

/* The interface an end point's UNI is: its own, or the VLAN made on it. */
static const char *
uni_ifname(struct plan *pl, const ucl_object_t *sw, const ucl_object_t *ep,
    char *buf, size_t len)
{
	const ucl_object_t	*u, *al;
	char			 key[200];

	u = ucl_object_lookup(ep, "uni");
	if (ucl_object_toint(ucl_object_lookup(u, "vlan")) <= 0)
		return (str(u, "interface"));
	snprintf(key, sizeof(key), "vlan:%s/%s", str(sw, "id"), str(ep, "id"));
	al = ucl_object_lookup(pl->alloc, key);
	snprintf(buf, len, "vlan%jd", (intmax_t)ucl_object_toint(
	    ucl_object_lookup(al, "unit")));
	return (buf);
}

static void
rule(ucl_object_t *rules, int num, const char *fmt, ...)
{
	char	line[1200];
	va_list	ap;
	size_t	n;

	n = (size_t)snprintf(line, sizeof(line), "%d ", num);
	va_start(ap, fmt);
	vsnprintf(line + n, sizeof(line) - n, fmt, ap);
	va_end(ap);
	ucl_array_append(rules, S(line));
}

static ucl_object_t *
table(ucl_object_t *tables, const char *name, const char *valtype)
{
	ucl_object_t	*t;

	if ((t = (ucl_object_t *)(uintptr_t)by(tables, "name", name)) != NULL)
		return (t);
	t = ucl_object_typed_new(UCL_OBJECT);
	put(t, "name", S(name));
	put(t, "valtype", S(valtype));
	put(t, "entries", ucl_object_typed_new(UCL_ARRAY));
	ucl_array_append(tables, t);
	return (t);
}

static void
entry(ucl_object_t *t, const char *key, const char *value)
{
	ucl_object_t	*e;

	e = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(e, S(key));
	ucl_array_append(e, S(value));
	ucl_array_append((ucl_object_t *)(uintptr_t)ucl_object_lookup(t,
	    "entries"), e);
}

/*
 * The steering of one table: for each far prefix the tunnels that may
 * carry it, in order: no backup first, a private one before a public
 * one; the console's manager reorders them by the performance.
 */
static void
steer_table(struct plan *pl, ucl_object_t *entries, const ucl_object_t *sw,
    const ucl_object_t *ep, const ucl_object_t *zone, const ucl_object_t *pol,
    const char *tname, int fam, bool backup_ok)
{
	const ucl_object_t	*ep2, *p, *t, *e0, *e1, *far, *dz;
	ucl_object_iter_t	 it, pit, tit;
	ucl_object_t		*pfx, *en, *cands, *c;
	int			 af, pass;

	af = fam == 4 ? AF_INET : AF_INET6;
	it = NULL;
	while ((ep2 = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep2, "edge"), str(ep, "edge")) == 0 ||
		    !vt_allows(sw, pol, str(ep, "id"), str(ep2, "id")))
			continue;
		pfx = ucl_object_typed_new(UCL_ARRAY);
		uni_prefixes(ep2, pfx);
		pit = NULL;
		while ((p = ucl_object_iterate(pfx, &pit, true)) != NULL) {
			if (family(ucl_object_tostring(p)) != af)
				continue;
			dz = zone_of(sw, ucl_object_tostring(p));
			if (!zone_allowed(pol, zone, dz))
				continue;
			if (by(entries, "prefix", ucl_object_tostring(p)) !=
			    NULL)
				continue;
			cands = ucl_object_typed_new(UCL_ARRAY);
			/* Those that are no backup, then the backups. */
			for (pass = 0; pass < 2; pass++) {
				tit = NULL;
				while ((t = ucl_object_iterate(pl->tunnels, &tit,
				    true)) != NULL) {
					if (strcmp(str(t, "swvc"), str(sw, "id"))
					    != 0 || ucl_flag(t, "backup") !=
					    (pass == 1) || !tunnel_fits(t, pol,
					    backup_ok))
						continue;
					e0 = ucl_array_find_index(
					    ucl_object_lookup(t, "ends"), 0);
					e1 = ucl_array_find_index(
					    ucl_object_lookup(t, "ends"), 1);
					if (strcmp(str(e0, "edge"), str(ep,
					    "edge")) == 0 && strcmp(str(e1,
					    "edge"), str(ep2, "edge")) == 0)
						far = e1;
					else if (strcmp(str(e1, "edge"), str(ep,
					    "edge")) == 0 && strcmp(str(e0,
					    "edge"), str(ep2, "edge")) == 0)
						far = e0;
					else
						continue;
					if (str(far, fam == 4 ? "inner4" :
					    "inner6") == NULL)
						continue;
					c = ucl_object_typed_new(UCL_OBJECT);
					put(c, "id", S(str(t, "id")));
					put(c, "via", S(str(far, fam == 4 ?
					    "inner4" : "inner6")));
					put(c, "public", B(ucl_flag(t,
					    "public")));
					ucl_array_append(cands, c);
				}
			}
			if (ucl_array_size(cands) == 0) {
				ucl_object_unref(cands);
				continue;
			}
			/* A private one before a public one. */
			en = ucl_object_typed_new(UCL_OBJECT);
			put(en, "table", S(tname));
			put(en, "prefix", S(ucl_object_tostring(p)));
			put(en, "swvc", S(str(sw, "id")));
			put(en, "policy", S(str(pol, "name")));
			put(en, "candidates", cands);
			ucl_array_append(entries, en);
		}
		ucl_object_unref(pfx);
	}
}


/* ---- Breakout, bandwidth, importance (§9.12.2.5, §9.12.2.8, §9.12.2.11) */

#define	DN_FROM		3000	/* dummynet pipes and queues, nat instances */
#define	DN_MAX		64
#define	QUEUES_MAX	256

/* Does the policy let the flow out to the Internet (R53, R57)? */
static bool
breaks_out(const ucl_object_t *pol)
{
	const char	*v;

	v = pol != NULL ? str(ucl_object_lookup(pol, "criteria"),
	    "internet-breakout") : NULL;
	return (v != NULL && strcmp(v, "enabled") == 0);
}

/*
 * Where a service's Internet traffic leaves from an edge: the edge's
 * own breakout UCS End Point (local, with its interface and gateway),
 * else the first edge of the document that has one and a tunnel to
 * it (remote); NULL when none.  *localp says which.
 */
static const ucl_object_t *
breakout_of(struct plan *pl, const ucl_object_t *sw, const char *sid,
    bool *localp, const char **bo_sid)
{
	const ucl_object_t	*edge, *uep;
	ucl_object_iter_t	 it, uit;
	int			 far, pass;

	for (pass = 0; pass < 2; pass++) {
		it = NULL;
		while ((edge = ucl_object_iterate(ucl_object_lookup(pl->doc,
		    "edges"), &it, true)) != NULL) {
			if ((pass == 0) != (strcmp(str(edge, "server"), sid) ==
			    0))
				continue;
			uit = NULL;
			while ((uep = ucl_object_iterate(ucl_object_lookup(edge,
			    "ucs_end_points"), &uit, true)) != NULL) {
				if (!ucl_flag(uep, "breakout") || !in_list(
				    ucl_object_lookup(sw, "ucs"), str(uep,
				    "ucs")))
					continue;
				if (pass == 1 && tunnel_for(pl, str(sw, "id"),
				    sid, str(edge, "server"), AF_INET, &far) ==
				    NULL && tunnel_for(pl, str(sw, "id"), sid,
				    str(edge, "server"), AF_INET6, &far) == NULL)
					continue;
				*localp = pass == 0;
				*bo_sid = str(edge, "server");
				return (uep);
			}
		}
	}
	return (NULL);
}

/* Does any flow at the edge's UNIs of the service break out (R56)? */
static bool
breaks_here(struct plan *pl, const ucl_object_t *sw, const char *sid)
{
	const ucl_object_t	*ep, *zone, *afs, *pol;
	ucl_object_iter_t	 eit, zit, ait;
	const char		*pname, *bo_sid;
	bool			 local;

	if (breakout_of(pl, sw, sid, &local, &bo_sid) == NULL)
		return (false);
	eit = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &eit, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		zit = NULL;
		while ((zone = ucl_object_iterate(ucl_object_lookup(sw,
		    "zones"), &zit, true)) != NULL) {
			ait = NULL;
			while ((afs = ucl_object_iterate(ucl_object_lookup(sw,
			    "flows"), &ait, true)) != NULL) {
				pname = policy_for(ep, zone, afs);
				pol = pname != NULL && strcmp(pname, "Block") !=
				    0 ? by(ucl_object_lookup(sw, "policies"),
				    "name", pname) : NULL;
				if (breaks_out(pol))
					return (true);
			}
		}
	}
	return (false);
}

/* The first host of an IPv4 prefix: what a NAT translates to. */
static const char *
first_host(const char *prefix, char *buf, size_t len)
{
	struct net	n;

	if (!net_parse(prefix, &n) || n.af != AF_INET)
		return (NULL);
	net_nth(&n, n.len < 31 ? 1 : 0, buf, len);
	return (buf);
}

/*
 * A bandwidth flow (§9.12.2.11): a rate limiter shared by name, or a
 * policy's own commit and limit, at the end point.  One dummynet pipe
 * each, of the limit; each flow in it a queue, weighted by the commit
 * and the business importance (D4).
 */
struct limiter {
	char		key[160];
	int		pipe;
	int64_t		commit, limit;
	int64_t		sum;		/* of its queues' commits */
};

struct queue {
	int		num, lim;
	int64_t		commit;
	int		rank;		/* importance: 0 the highest */
	int		ranks;		/* levels, 1 for none */
};

struct dn {
	struct limiter	lim[DN_MAX];
	struct queue	q[QUEUES_MAX];
	int		nlim, nq, next;
};

/* The policy's bandwidth, as a limiter of dn; -1 for none or too many. */
static int
limiter_of(struct dn *dn, const ucl_object_t *sw, const ucl_object_t *pol,
    const ucl_object_t *ep)
{
	const ucl_object_t	*v, *rl;
	char			 key[160];
	int64_t			 commit, limit;
	int			 i;

	v = ucl_object_lookup(ucl_object_lookup(pol, "criteria"), "bandwidth");
	if (v == NULL)
		return (-1);
	if (ucl_object_type(v) == UCL_STRING) {
		if ((rl = by(ucl_object_lookup(sw, "rate_limiters"), "name",
		    ucl_object_tostring(v))) == NULL)
			return (-1);
		snprintf(key, sizeof(key), "%s/limiter/%s", str(sw, "id"),
		    ucl_object_tostring(v));
		v = rl;
	} else
		snprintf(key, sizeof(key), "%s/%s/%s", str(sw, "id"), str(pol,
		    "name"), str(ep, "id"));
	commit = ucl_object_toint(ucl_object_lookup(v, "commit"));
	limit = ucl_object_lookup(v, "limit") != NULL && ucl_object_type(
	    ucl_object_lookup(v, "limit")) != UCL_NULL ? ucl_object_toint(
	    ucl_object_lookup(v, "limit")) : 0;
	for (i = 0; i < dn->nlim; i++)
		if (strcmp(dn->lim[i].key, key) == 0)
			return (i);
	if (dn->nlim == DN_MAX)
		return (-1);
	snprintf(dn->lim[i].key, sizeof(dn->lim[i].key), "%s", key);
	dn->lim[i].pipe = dn->next++;
	dn->lim[i].commit = commit;
	dn->lim[i].limit = limit;
	dn->lim[i].sum = 0;
	dn->nlim++;
	return (i);
}

/* The importance of a policy's flows: its rank among the levels (R67). */
static void
importance_of(const ucl_object_t *sw, const ucl_object_t *pol, int *rankp,
    int *ranksp)
{
	const ucl_object_t	*imp, *l;
	ucl_object_iter_t	 it;
	const char		*v;
	int			 i;

	*rankp = 0;
	*ranksp = 1;
	imp = ucl_object_lookup(sw, "importance");
	if (imp == NULL || ucl_object_type(imp) == UCL_NULL)
		return;
	v = str(ucl_object_lookup(pol, "criteria"), "business-importance");
	if (v == NULL)
		v = str(imp, "default");
	*ranksp = (int)ucl_array_size(ucl_object_lookup(imp, "levels"));
	if (*ranksp < 1)
		*ranksp = 1;
	i = 0;
	it = NULL;
	while ((l = ucl_object_iterate(ucl_object_lookup(imp, "levels"), &it,
	    true)) != NULL) {
		if (v != NULL && strcmp(ucl_object_tostring_forced(l), v) == 0)
			*rankp = i;
		i++;
	}
}

/* A queue of a limiter for a policy's flow; -1 when there are too many. */
static int
queue_of(struct dn *dn, int lim, const ucl_object_t *sw,
    const ucl_object_t *pol)
{
	struct queue	*q;

	if (dn->nq == QUEUES_MAX)
		return (-1);
	q = &dn->q[dn->nq++];
	q->num = dn->next++;
	q->lim = lim;
	q->commit = dn->lim[lim].commit;
	importance_of(sw, pol, &q->rank, &q->ranks);
	dn->lim[lim].sum += q->commit;
	return (q->num);
}

/*
 * The dummynet objects of the edge: each limiter a pipe of its limit
 * (0: none), each queue in it weighted 1 to 100: half by its commit's
 * share of the pipe's, half by its importance.
 */
static void
dn_objects(const struct dn *dn, ucl_object_t *objects)
{
	const struct limiter	*l;
	const struct queue	*q;
	char			 line[200];
	int			 i, w;

	for (i = 0; i < dn->nlim; i++) {
		l = &dn->lim[i];
		snprintf(line, sizeof(line), "pipe %d config bw %jdbit/s", l->pipe,
		    (intmax_t)l->limit);
		ucl_array_append(objects, S(line));
	}
	for (i = 0; i < dn->nq; i++) {
		q = &dn->q[i];
		l = &dn->lim[q->lim];
		w = l->sum > 0 ? (int)(50 * q->commit / l->sum) : 25;
		w += q->ranks > 1 ? 50 * (q->ranks - 1 - q->rank) / (q->ranks -
		    1) : 25;
		if (w < 1)
			w = 1;
		if (w > 100)
			w = 100;
		snprintf(line, sizeof(line), "queue %d config pipe %d weight %d",
		    q->num, l->pipe, w);
		ucl_array_append(objects, S(line));
	}
}

/* The flows an application names: the one of the name, or a group's. */
static bool
app_has(const ucl_object_t *afs, const char *app)
{

	return (app != NULL && ((str(afs, "name") != NULL && strcmp(str(afs,
	    "name"), app) == 0) || (str(afs, "group") != NULL && strcmp(str(
	    afs, "group"), app) == 0)));
}

/* The tunnel interfaces of the service at the edge, as xmit words. */
static const char *
xmit_words(struct plan *pl, const ucl_object_t *sw, const char *sid,
    char *buf, size_t len)
{
	const ucl_object_t	*t, *e;
	ucl_object_iter_t	 it, eit;
	int			 n;

	n = 0;
	buf[0] = '\0';
	it = NULL;
	while ((t = ucl_object_iterate(pl->tunnels, &it, true)) != NULL) {
		if (strcmp(str(t, "swvc"), str(sw, "id")) != 0)
			continue;
		eit = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(t, "ends"),
		    &eit, true)) != NULL) {
			if (strcmp(str(e, "edge"), sid) != 0 || str(e, "ifname")
			    == NULL)
				continue;
			snprintf(buf + strlen(buf), len - strlen(buf), "%sxmit %s",
			    n++ > 0 ? " or " : "", str(e, "ifname"));
		}
	}
	if (n == 0)
		return (NULL);
	if (n > 1) {
		char	tmp[1200];

		snprintf(tmp, sizeof(tmp), "{ %s }", buf);
		snprintf(buf, len, "%s", tmp);
	}
	return (buf);
}

/*
 * The own prefixes of the edge's UNIs of the service that a policy's
 * flow of a zone may reach (R58-R62), of one family, as an address
 * list; NULL for none.
 */
static const char *
own_words(struct plan *pl, const ucl_object_t *sw, const char *sid,
    const ucl_object_t *zone, const ucl_object_t *pol, int fam, char *buf,
    size_t len)
{
	const ucl_object_t	*ep, *p;
	ucl_object_iter_t	 it, pit;
	ucl_object_t		*pfx;
	int			 n;

	(void)pl;
	n = 0;
	buf[0] = '\0';
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		pfx = ucl_object_typed_new(UCL_ARRAY);
		uni_prefixes(ep, pfx);
		pit = NULL;
		while ((p = ucl_object_iterate(pfx, &pit, true)) != NULL) {
			if (family(ucl_object_tostring(p)) != (fam == 4 ? AF_INET :
			    AF_INET6) || !zone_allowed(pol, zone, zone_of(sw,
			    ucl_object_tostring(p))))
				continue;
			snprintf(buf + strlen(buf), len - strlen(buf), "%s%s",
			    n++ > 0 ? "," : "", ucl_object_tostring(p));
		}
		ucl_object_unref(pfx);
	}
	return (n > 0 ? buf : NULL);
}

/*
 * The rules of one edge, and its steering: for each service with an
 * end point here, the zone table and each zone's block, each flow
 * with the policy it gets, each policy's tables; what a flow may do beyond the tunnels
 * (its own UNIs' hosts, the Internet by breakout), its bandwidth by
 * dummynet, and the way back in from the Internet.
 */
static bool
rules_build(struct plan *pl, const char *sid)
{
	const ucl_object_t	*sw, *ep, *zone, *afs, *pol, *v, *bo, *r;
	ucl_object_iter_t	 it, eit, zit, ait;
	ucl_object_t		*o, *tables, *rules, *entries, *zt, *j, *pre;
	ucl_object_t		*objects, *kt;
	struct dn		*dn;
	char			 ifn[32], tname[64], zname[64], words[2000];
	char			 key[200], kname[64], zp[64], xmit[1200], own[1200];
	char			 host[64], note[400];
	const char		*uni, *pname, *bo_sid, *bif;
	int			 next, zi, pi, fam, nuni, k, lim, q, nat;
	bool			 any, multi, local, breaks;

	tables = ucl_object_typed_new(UCL_ARRAY);
	rules = ucl_object_typed_new(UCL_ARRAY);
	pre = ucl_object_typed_new(UCL_ARRAY);
	entries = ucl_object_typed_new(UCL_ARRAY);
	objects = ucl_object_typed_new(UCL_ARRAY);
	if ((dn = calloc(1, sizeof(*dn))) == NULL)
		return (false);
	dn->next = DN_FROM;
	next = RULE_FROM + 2;
	any = false;
	/* First the way in: the UNIs' packets to their zone's block. */
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(pl->doc, "swvcs"),
	    &it, true)) != NULL) {
		snprintf(zname, sizeof(zname), "sw%jd_zone", (intmax_t)
		    ucl_object_toint(ucl_object_lookup(sw, "fib")));
		eit = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
		    "end_points"), &eit, true)) != NULL) {
			if (strcmp(str(ep, "edge"), sid) != 0)
				continue;
			any = true;
			uni = uni_ifname(pl, sw, ep, ifn, sizeof(ifn));
			/* [D1]: source routing dropped. */
			rule(rules, RULE_FROM, "deny ip from any to any ipoptions "
			    "lsrr,ssrr,rr in recv %s", uni);
			rule(rules, RULE_FROM, "skipto tablearg ip from table(%s) "
			    "to any in recv %s", zname, uni);
			/* No zone: dropped (R23). */
			rule(rules, RULE_FROM + 1, "deny ip from any to any in "
			    "recv %s", uni);
		}
	}
	if (!any) {
		ucl_object_unref(tables);
		ucl_object_unref(rules);
		ucl_object_unref(pre);
		ucl_object_unref(entries);
		ucl_object_unref(objects);
		free(dn);
		return (true);
	}
	/* Then each service's zones: a block each. */
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(pl->doc, "swvcs"),
	    &it, true)) != NULL) {
		nuni = 0;
		eit = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
		    "end_points"), &eit, true)) != NULL)
			if (strcmp(str(ep, "edge"), sid) == 0)
				nuni++;
		if (nuni == 0)
			continue;
		multi = nuni > 1;
		snprintf(zname, sizeof(zname), "sw%jd_zone", (intmax_t)
		    ucl_object_toint(ucl_object_lookup(sw, "fib")));
		zt = table(tables, zname, "skipto");
		/* The service's prefixes, all its UNIs': what is not in it
		 * is the Internet. */
		snprintf(kname, sizeof(kname), "sw%jd_known", (intmax_t)
		    ucl_object_toint(ucl_object_lookup(sw, "fib")));
		kt = table(tables, kname, "legacy");
		eit = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
		    "end_points"), &eit, true)) != NULL) {
			ucl_object_t		*pfx = ucl_object_typed_new(UCL_ARRAY);
			const ucl_object_t	*p;
			ucl_object_iter_t	 pit = NULL;

			uni_prefixes(ep, pfx);
			while ((p = ucl_object_iterate(pfx, &pit, true)) != NULL)
				entry(kt, ucl_object_tostring(p), "0");
			ucl_object_unref(pfx);
		}
		bo = breakout_of(pl, sw, sid, &local, &bo_sid);
		breaks = false;
		xmit_words(pl, sw, sid, xmit, sizeof(xmit));
		zi = 0;
		zit = NULL;
		while ((zone = ucl_object_iterate(ucl_object_lookup(sw, "zones"),
		    &zit, true)) != NULL) {
			char	num[16];

			if (next >= RULE_TO) {
				snprintf(pl->why, sizeof(pl->why), "edge %s: more "
				    "zones than rule numbers %d to %d hold",
				    server_name_of(sid), RULE_FROM, RULE_TO);
				ucl_object_unref(tables);
				ucl_object_unref(rules);
				ucl_object_unref(pre);
				ucl_object_unref(entries);
				ucl_object_unref(objects);
				free(dn);
				return (false);
			}
			snprintf(num, sizeof(num), "%d", next);
			/* Its prefixes: the block they go to, and a table of
			 * their own for the rules on the way out. */
			snprintf(zp, sizeof(zp), "sw%jd_zp%d", (intmax_t)
			    ucl_object_toint(ucl_object_lookup(sw, "fib")), zi);
			v = ucl_object_lookup(zone, "prefixes");
			if (ucl_object_type(v) == UCL_STRING) {
				entry(zt, "0.0.0.0/0", num);
				entry(zt, "::/0", num);
				entry(table(tables, zp, "legacy"), "0.0.0.0/0", "0");
				entry(table(tables, zp, "legacy"), "::/0", "0");
			} else {
				const ucl_object_t	*p;
				ucl_object_iter_t	 pit;

				pit = NULL;
				while ((p = ucl_object_iterate(v, &pit, true)) !=
				    NULL) {
					entry(zt, ucl_object_tostring_forced(p),
					    num);
					entry(table(tables, zp, "legacy"),
					    ucl_object_tostring_forced(p), "0");
				}
			}
			/* The block: each end point's flows, in order. */
			eit = NULL;
			while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
			    "end_points"), &eit, true)) != NULL) {
				char	recv[48];

				if (strcmp(str(ep, "edge"), sid) != 0)
					continue;
				uni = uni_ifname(pl, sw, ep, ifn, sizeof(ifn));
				recv[0] = '\0';
				if (multi)
					snprintf(recv, sizeof(recv), " in recv %s",
					    uni);
				ait = NULL;
				while ((afs = ucl_object_iterate(
				    ucl_object_lookup(sw, "flows"), &ait, true))
				    != NULL) {
					const ucl_object_t	*cr, *ap;
					ucl_object_iter_t	 apit;
					const char		*appid;
					int			 nap;

					pname = policy_for(ep, zone, afs);
					pol = pname != NULL && strcmp(pname,
					    "Block") != 0 ? by(ucl_object_lookup(
					    sw, "policies"), "name", pname) :
					    NULL;
					pi = 0;
					if (pol != NULL) {
						const ucl_object_t *pq;
						ucl_object_iter_t qit = NULL;

						while ((pq = ucl_object_iterate(
						    ucl_object_lookup(sw,
						    "policies"), &qit, true)) !=
						    NULL && pq != pol)
							pi++;
					}
					cr = ucl_object_lookup(afs, "criteria");
					ap = ucl_object_lookup(cr, "appid");
					nap = ap != NULL ? (int)ucl_array_size(
					    ap) : 1;
					/* Its bandwidth: a queue of its
					 * limiter's pipe (R79: after the
					 * policy says it is forwarded). */
					q = -1;
					if (pol != NULL && (lim = limiter_of(dn,
					    sw, pol, ep)) >= 0)
						q = queue_of(dn, lim, sw, pol);
					apit = NULL;
					for (k = 0; k < nap; k++) {
						appid = ap != NULL ?
						    ucl_object_tostring_forced(
						    ucl_object_iterate(ap, &apit,
						    true)) : NULL;
						if (pol == NULL) {
							/* None, or Block (R112,
							 * R113). */
							if (afs_words(cr, NULL,
							    appid, words,
							    sizeof(words), &fam))
								rule(rules, next,
								    "deny %s%s",
								    words, recv);
							continue;
						}
						for (fam = 4; fam <= 6; fam += 2) {
							char	tbl[80];
							int	f2;

							snprintf(tname, sizeof(
							    tname), "sw%jd_z%dp%d_%d",
							    (intmax_t)
							    ucl_object_toint(
							    ucl_object_lookup(sw,
							    "fib")), zi, pi, fam);
							snprintf(tbl, sizeof(tbl),
							    "table(%s)", tname);
							if (!afs_words(cr, tbl,
							    appid, words,
							    sizeof(words), &f2))
								continue;
							if (f2 != 0 && f2 != fam)
								continue;
							/* ip of the family only. */
							if (f2 == 0 && strncmp(
							    words, "ip ", 3) == 0) {
								char	w2[2000];

								snprintf(w2,
								    sizeof(w2),
								    "ip%d %s", fam,
								    words + 3);
								memcpy(words, w2,
								    sizeof(w2));
							}
							table(tables, tname, fam ==
							    4 ? "ipv4" : "ipv6");
							rule(rules, next, "fwd "
							    "tablearg %s%s", words,
							    recv);
							steer_table(pl, entries,
							    sw, ep, zone, pol,
							    tname, fam, str(
							    ucl_object_lookup(pol,
							    "criteria"), "backup")
							    != NULL && strcmp(str(
							    ucl_object_lookup(pol,
							    "criteria"), "backup"),
							    "enabled") == 0);
						}
						/* The rest of the flow: the
						 * hosts of the edge's own UNIs
						 * it may reach, the Internet by
						 * breakout (R53-R57), and
						 * nothing else (R58-R62). */
						for (fam = 4; fam <= 6; fam += 2) {
							int	f2;

							if (own_words(pl, sw, sid,
							    zone, pol, fam, own,
							    sizeof(own)) == NULL ||
							    !afs_words(cr, own,
							    appid, words,
							    sizeof(words), &f2) ||
							    (f2 != 0 && f2 != fam))
								continue;
							if (f2 == 0 && strncmp(
							    words, "ip ", 3) == 0) {
								char	w2[2000];

								snprintf(w2,
								    sizeof(w2),
								    "ip%d %s", fam,
								    words + 3);
								memcpy(words, w2,
								    sizeof(w2));
							}
							if (q >= 0)
								rule(rules, next,
								    "queue %d %s%s",
								    q, words, recv);
							else
								rule(rules, next,
								    "allow %s%s",
								    words, recv);
						}
						if (breaks_out(pol) && bo != NULL) {
							char	nk[80];

							snprintf(nk, sizeof(nk),
							    "not table(%s)", kname);
							if (afs_words(cr, nk,
							    appid, words,
							    sizeof(words), &fam)) {
								if (q >= 0)
									rule(rules,
									    next,
									    "queue %d "
									    "%s%s", q,
									    words,
									    recv);
								else
									rule(rules,
									    next,
									    "allow "
									    "%s%s",
									    words,
									    recv);
								breaks = true;
							}
						} else if (breaks_out(pol) &&
						    zi == 0 && k == 0) {
							snprintf(note, sizeof(note),
							    "swvc %s: policy %s "
							    "breaks out, but no "
							    "edge of the service "
							    "has a breakout UCS "
							    "end point that %s "
							    "reaches: its Internet "
							    "traffic is dropped",
							    str(sw, "id"), str(pol,
							    "name"),
							    server_name_of(sid));
							ucl_array_append(pl->notes,
							    S(note));
						}
						/* What the flow may not do, no
						 * later flow does (R96). */
						if (afs_words(cr, NULL, appid,
						    words, sizeof(words), &fam))
							rule(rules, next,
							    "deny %s%s", words,
							    recv);
						/* By the tunnels, its queue. */
						if (q >= 0 && xmit[0] != '\0' &&
						    afs_words(cr, NULL, appid,
						    words, sizeof(words), &fam))
							rule(pre, RULE_FROM + 1,
							    "queue %d %s src-ip "
							    "table(%s) out %s", q,
							    words, zp, xmit);
					}
				}
				/* No flow matched: dropped (R96). */
				rule(rules, next, "deny ip from any to any%s",
				    recv);
			}
			/* Egress: a flow of the zone leaving by a UNI here
			 * whose egress policy discards it (R85). */
			eit = NULL;
			while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
			    "end_points"), &eit, true)) != NULL) {
				const ucl_object_t	*m, *epol, *cr, *ap;
				ucl_object_iter_t	 mit, apit;
				int			 nap;

				if (strcmp(str(ep, "edge"), sid) != 0)
					continue;
				uni = uni_ifname(pl, sw, ep, ifn, sizeof(ifn));
				mit = NULL;
				while ((m = ucl_object_iterate(ucl_object_lookup(
				    ep, "policy_map"), &mit, true)) != NULL) {
					if (str(m, "zone") == NULL || strcmp(str(
					    m, "zone"), str(zone, "name")) != 0 ||
					    str(m, "egress") == NULL)
						continue;
					epol = by(ucl_object_lookup(sw,
					    "policies"), "name", str(m, "egress"));
					v = epol != NULL ? ucl_object_lookup(
					    ucl_object_lookup(epol, "criteria"),
					    "egress-block") : NULL;
					if (v == NULL || ucl_object_type(v) !=
					    UCL_STRING || strcmp(
					    ucl_object_tostring(v), "discard") != 0)
						continue;
					ait = NULL;
					while ((afs = ucl_object_iterate(
					    ucl_object_lookup(sw, "flows"), &ait,
					    true)) != NULL) {
						if (!app_has(afs, str(m, "app")))
							continue;
						cr = ucl_object_lookup(afs,
						    "criteria");
						ap = ucl_object_lookup(cr, "appid");
						nap = ap != NULL ? (int)
						    ucl_array_size(ap) : 1;
						apit = NULL;
						for (k = 0; k < nap; k++) {
							const char *appid = ap !=
							    NULL ?
							    ucl_object_tostring_forced(
							    ucl_object_iterate(ap,
							    &apit, true)) : NULL;

							if (afs_words(cr, NULL,
							    appid, words,
							    sizeof(words), &fam))
								rule(pre, RULE_FROM +
								    1, "deny %s "
								    "src-ip table(%s) "
								    "out xmit %s",
								    words, zp, uni);
						}
					}
				}
			}
			next++;
			zi++;
		}
		/*
		 * The way back in from the Internet, where it leaves here:
		 * forwarded by the service's table when a flow breaks out,
		 * dropped when none does (R56); translated by the NAT of
		 * the end point here that has one, else the interface's
		 * address (§10.5), its exceptions as they are.
		 */
		if (bo != NULL && local) {
			bif = str(bo, "interface");
			if (!breaks) {
				rule(pre, RULE_FROM + 1, "deny ip from any to "
				    "table(%s) in recv %s", kname, bif);
			} else {
				const ucl_object_t	*nt, *ex;
				ucl_object_iter_t	 xit;
				const char		*natip;

				nat = DN_FROM + (int)ucl_object_toint(
				    ucl_object_lookup(sw, "fib"));
				natip = NULL;
				nt = NULL;
				eit = NULL;
				while ((ep = ucl_object_iterate(ucl_object_lookup(
				    sw, "end_points"), &eit, true)) != NULL) {
					if (strcmp(str(ep, "edge"), sid) != 0)
						continue;
					r = ucl_object_lookup(ep, "nat");
					if (r == NULL || ucl_object_type(r) !=
					    UCL_OBJECT || str(r, "ip_version") ==
					    NULL || strcmp(str(r, "ip_version"),
					    "ipv6") == 0)
						continue;
					nt = r;
					natip = first_host(str(r, "public_prefix"),
					    host, sizeof(host));
					break;
				}
				snprintf(words, sizeof(words), natip != NULL ?
				    "nat %d config ip %s" : "nat %d config if %s",
				    nat, natip != NULL ? natip : bif);
				ucl_array_append(objects, S(words));
				xit = NULL;
				while (nt != NULL && (ex = ucl_object_iterate(
				    ucl_object_lookup(nt, "exceptions"), &xit,
				    true)) != NULL)
					rule(pre, RULE_FROM + 1, "allow ip from %s "
					    "to not table(%s) out xmit %s",
					    ucl_object_tostring_forced(ex), kname,
					    bif);
				rule(pre, RULE_FROM + 1, "nat %d ip4 from table(%s) "
				    "to not table(%s) out xmit %s", nat, kname,
				    kname, bif);
				rule(pre, RULE_FROM + 1, "setfib %jd ip from any "
				    "to %s in recv %s", (intmax_t)
				    ucl_object_toint(ucl_object_lookup(sw, "fib")),
				    natip != NULL ? natip : str(bo, "address") !=
				    NULL ? str(bo, "address") : "me", bif);
				if (natip != NULL)
					rule(pre, RULE_FROM + 1, "nat %d ip4 from "
					    "any to %s in recv %s", nat, natip,
					    bif);
				rule(pre, RULE_FROM + 1, "setfib %jd ip from any "
				    "to table(%s) in recv %s", (intmax_t)
				    ucl_object_toint(ucl_object_lookup(sw, "fib")),
				    kname, bif);
			}
		}
	}
	dn_objects(dn, objects);
	free(dn);
	/* In their order: the way in at the UNIs, then what is on the way
	 * out and back in, then the blocks. */
	{
		ucl_object_t		*all = ucl_object_typed_new(UCL_ARRAY);
		const ucl_object_t	*line;
		ucl_object_iter_t	 lit;
		int			 pass;

		for (pass = 0; pass < 3; pass++) {
			lit = NULL;
			while ((line = ucl_object_iterate(pass == 1 ? pre : rules,
			    &lit, true)) != NULL) {
				if (pass != 1 && (atoi(ucl_object_tostring(line)) ==
				    RULE_FROM) != (pass == 0))
					continue;
				ucl_array_append(all, ucl_object_copy(line));
			}
			if (pass == 1)
				rule(all, RULE_FROM + 1, "skipto %d ip from any to "
				    "any", RULE_TO);
		}
		ucl_object_unref(rules);
		ucl_object_unref(pre);
		rules = all;
	}
	rule(rules, RULE_TO, "count ip from any to any");
	/* The two objects: the rules, then the steering of their tables. */
	snprintf(key, sizeof(key), "rules");
	snprintf(words, sizeof(words), "the rules: %u, in ipfw set %d, numbers "
	    "%d to %d, with %u tables", ucl_array_size(rules), IPFW_SET,
	    RULE_FROM, RULE_TO, ucl_array_size(tables));
	if (ucl_array_size(objects) > 0)
		snprintf(words + strlen(words), sizeof(words) - strlen(words),
		    ", %u dummynet and nat objects", ucl_array_size(objects));
	o = object(pl, sid, key, PH_RULES, "%s", words);
	if (o != NULL) {
		j = job("sdwan-rules", "set", I(IPFW_SET), "tables", tables,
		    "rules", rules, "objects", objects, NULL);
		make(o, j);
		unmake(o, job("sdwan-rules", "set", I(IPFW_SET), "tables",
		    ucl_object_typed_new(UCL_ARRAY), "rules",
		    ucl_object_typed_new(UCL_ARRAY), "objects",
		    ucl_object_typed_new(UCL_ARRAY), NULL));
	} else {
		ucl_object_unref(tables);
		ucl_object_unref(rules);
		ucl_object_unref(objects);
	}
	o = object(pl, sid, "steer", PH_STEER, "the steering: %u far "
	    "prefix%s, each by the tunnels that may carry it",
	    ucl_array_size(entries), ucl_array_size(entries) == 1 ? "" : "es");
	if (o != NULL) {
		make(o, job("sdwan-steer", "entries", entries, NULL));
		unmake(o, job("sdwan-steer", "entries", ucl_object_typed_new(
		    UCL_ARRAY), NULL));
	} else
		ucl_object_unref(entries);
	return (true);
}

/* ---- Routing at the UNIs: BIRD, one instance a service (§11.6) ----- */

#define	DEFAULT_AS	64512

static bool
is_nullish(const ucl_object_t *o)
{

	return (o == NULL || ucl_object_type(o) == UCL_NULL);
}

/* An identifier as a BIRD symbol: letters, digits and _ of it. */
static const char *
symbol(const char *id, char *buf, size_t len)
{
	size_t	i, n;

	n = 0;
	for (i = 0; id != NULL && id[i] != '\0' && n + 1 < len; i++)
		buf[n++] = isalnum((unsigned char)id[i]) ? id[i] : '_';
	buf[n] = '\0';
	return (buf);
}

/* Does the service watch its tunnels by BFD? */
static bool
sw_bfd(const ucl_object_t *sw)
{

	return (!is_nullish(ucl_object_lookup(sw, "bfd")));
}

/* Does the service route at any UNI, BGP or OSPF? */
static bool
sw_routes(const ucl_object_t *sw)
{
	const ucl_object_t	*ep, *u;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		u = ucl_object_lookup(ep, "uni");
		if (!is_nullish(ucl_object_lookup(u, "bgp")) || !is_nullish(
		    ucl_object_lookup(u, "ospf")))
			return (true);
	}
	return (false);
}

/* BIRD's channel of a family, with what comes in and goes out. */
static void
bird_channel(struct kore_buf *b, const char *fam, const char *export)
{

	kore_buf_appendf(b, "\t%s {\n\t\timport all;\n\t\texport %s;\n\t};\n", fam, export);
}

/*
 * The BIRD configuration of a service at an edge: the kernel's table
 * learned and kept (the routes the console made stay), the UNIs'
 * connected routes, iBGP with every other edge by each tunnel (next
 * hop self: the far end's inner address), and at each UNI BGP or
 * OSPF with the subscriber as its entry says, its distance as the
 * preference (R140-R142: the lower, the better; connected first).
 */
static char *
bird_conf(struct plan *pl, const ucl_object_t *sw, const char *sid)
{
	struct kore_buf		*b;
	const ucl_object_t	*ep, *u, *t, *e0, *e1, *me, *far, *r, *m, *v;
	ucl_object_iter_t	 it, tit, nit;
	const char		*rid, *fam, *ifn;
	char			 ifbuf[32], ifaces[1200], sym[80], *out;
	int64_t			 as, dist;
	int			 n, k;

	b = kore_buf_alloc(8192);
	as = ucl_object_lookup(sw, "as") != NULL ? ucl_object_toint(
	    ucl_object_lookup(sw, "as")) : DEFAULT_AS;
	/* The router id: the edge's first inner IPv4 address in the
	 * service, else a UNI's provider address. */
	rid = NULL;
	it = NULL;
	while (rid == NULL && (t = ucl_object_iterate(pl->tunnels, &it, true))
	    != NULL) {
		if (strcmp(str(t, "swvc"), str(sw, "id")) != 0)
			continue;
		tit = NULL;
		while ((me = ucl_object_iterate(ucl_object_lookup(t, "ends"),
		    &tit, true)) != NULL)
			if (strcmp(str(me, "edge"), sid) == 0 && str(me, "inner4")
			    != NULL) {
				rid = str(me, "inner4");
				break;
			}
	}
	ifaces[0] = '\0';
	n = 0;
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		u = ucl_object_lookup(ep, "uni");
		ifn = uni_ifname(pl, sw, ep, ifbuf, sizeof(ifbuf));
		snprintf(ifaces + strlen(ifaces), sizeof(ifaces) - strlen(ifaces),
		    "%s\"%s\"", n++ > 0 ? ", " : "", ifn);
		v = ucl_object_lookup(ucl_object_lookup(u, "ipv4"), "provider");
		if (rid == NULL && v != NULL && ucl_array_size(v) > 0)
			rid = ucl_object_tostring_forced(ucl_array_find_index(v,
			    0));
	}
	kore_buf_appendf(b, "# Written by the Arcana console: SD-WAN service %s at %s, "
	    "in routing table %jd.\n# Changed by the console's next apply.\n"
	    "router id %s;\nlog syslog { warning, error };\n\n"
	    "protocol device {\n}\n\n", str(sw, "id"), server_name_of(sid),
	    (intmax_t)ucl_object_toint(ucl_object_lookup(sw, "fib")), rid !=
	    NULL ? rid : "0.0.0.1");
	/* The tunnels' own interfaces too: a neighbour's next hop is
	 * resolved by them, else its routes would be unreachable. */
	it = NULL;
	while ((t = ucl_object_iterate(pl->tunnels, &it, true)) != NULL) {
		if (strcmp(str(t, "swvc"), str(sw, "id")) != 0)
			continue;
		tit = NULL;
		while ((me = ucl_object_iterate(ucl_object_lookup(t, "ends"),
		    &tit, true)) != NULL)
			if (strcmp(str(me, "edge"), sid) == 0 && str(me, "ifname")
			    != NULL && strlen(ifaces) + 40 < sizeof(ifaces))
				snprintf(ifaces + strlen(ifaces), sizeof(ifaces) -
				    strlen(ifaces), "%s\"%s\"", n++ > 0 ? ", " : "",
				    str(me, "ifname"));
	}
	if (n > 0)
		kore_buf_appendf(b, "protocol direct {\n\tipv4;\n\tipv6;\n\tinterface "
		    "%s;\n}\n\n", ifaces);
	/* The kernel's table: what the console put there is learned and
	 * kept, and outranks what BGP brings (preference 200 to 100), so
	 * the document's routes stay as they are and BGP's fill in the
	 * rest; what is learned here goes in, but not the connected, nor
	 * a route to nowhere. */
	kore_buf_appendf(b, "protocol kernel kernel4 {\n\tkernel table %jd;\n\tlearn;\n"
	    "\tpersist;\n\tipv4 {\n\t\timport filter { preference = 200; accept; "
	    "};\n\t\texport where source != RTS_DEVICE && source != RTS_INHERIT "
	    "&& dest = RTD_UNICAST;\n\t};\n}\n\nprotocol kernel kernel6 {\n\t"
	    "kernel table %jd;\n\tlearn;\n\tpersist;\n\tipv6 {\n\t\timport filter { "
	    "preference = 200; accept; };\n\t\texport where source != RTS_DEVICE "
	    "&& source != RTS_INHERIT && dest = RTD_UNICAST;\n\t};\n}\n\n",
	    (intmax_t)
	    ucl_object_toint(ucl_object_lookup(sw, "fib")), (intmax_t)
	    ucl_object_toint(ucl_object_lookup(sw, "fib")));
	/* BFD on each tunnel interface here (R58, R59, R159): the iBGP
	 * sessions go down with it, and the agent reads the sessions. */
	if (sw_bfd(sw)) {
		const ucl_object_t	*bfd = ucl_object_lookup(sw, "bfd");
		int			 first = 1;

		kore_buf_appendf(b, "protocol bfd {\n\tinterface ");
		it = NULL;
		while ((t = ucl_object_iterate(pl->tunnels, &it, true)) != NULL) {
			if (strcmp(str(t, "swvc"), str(sw, "id")) != 0)
				continue;
			tit = NULL;
			while ((me = ucl_object_iterate(ucl_object_lookup(t,
			    "ends"), &tit, true)) != NULL)
				if (strcmp(str(me, "edge"), sid) == 0 && str(me,
				    "ifname") != NULL) {
					kore_buf_appendf(b, "%s\"%s\"", first ? "" :
					    ", ", str(me, "ifname"));
					first = 0;
				}
		}
		if (first)
			kore_buf_appendf(b, "\"none\"");
		kore_buf_appendf(b, " {\n\t\tinterval %jd ms;\n\t\tmultiplier "
		    "%jd;\n\t};\n}\n\n", (intmax_t)(ucl_object_lookup(bfd,
		    "interval") != NULL ? ucl_object_toint(ucl_object_lookup(bfd,
		    "interval")) : 200), (intmax_t)(ucl_object_lookup(bfd,
		    "multiplier") != NULL ? ucl_object_toint(ucl_object_lookup(
		    bfd, "multiplier")) : 3));
	}
	/* iBGP with each other edge, by each tunnel between them. */
	/* What goes to the other edges: the UNIs' subnets and what the
	 * UNIs learn, not what the kernel's table holds of the console's
	 * (each edge has its own) nor the tunnels' own addresses, which a
	 * peer would resolve its next hop by in a circle. */
	{
		const ucl_object_t	*rp;
		ucl_object_iter_t	 rit;
		char			 resv[600];
		int			 nr = 0;

		resv[0] = '\0';
		rit = NULL;
		while ((rp = ucl_object_iterate(ucl_object_lookup(sw,
		    "reserved_prefixes"), &rit, true)) != NULL && strlen(resv) +
		    60 < sizeof(resv))
			snprintf(resv + strlen(resv), sizeof(resv) - strlen(resv),
			    "%s%s+", nr++ > 0 ? ", " : "",
			    ucl_object_tostring_forced(rp));
		kore_buf_appendf(b, "filter to_edges {\n\tif source = RTS_INHERIT "
		    "then reject;\n%s%s%s\taccept;\n}\n\n", nr > 0 ? "\tif net ~ [ "
		    : "", nr > 0 ? resv : "", nr > 0 ? " ] then reject;\n" : "");
	}
	kore_buf_appendf(b, "template bgp edge {\n\tlocal as %jd;\n\thold time 30;\n"
	    "\terror wait time 10, 60;\n%s", (intmax_t)as, sw_bfd(sw) ?
	    "\tbfd on;\n" : "");
	/* TCP MD5 on the sessions (Mplify 119 R11, R12). */
	if (str(sw, "md5") != NULL)
		kore_buf_appendf(b, "\tpassword \"%s\";\n", str(sw, "md5"));
	kore_buf_appendf(b, "\tipv4 {\n\t\timport all;\n\t\texport filter "
	    "to_edges;\n\t\tnext hop self;\n\t};\n\tipv6 {\n\t\timport all;\n\t\t"
	    "export filter to_edges;\n\t\tnext hop self;\n\t};\n}\n\n");
	k = 0;
	it = NULL;
	while ((t = ucl_object_iterate(pl->tunnels, &it, true)) != NULL) {
		if (strcmp(str(t, "swvc"), str(sw, "id")) != 0)
			continue;
		e0 = ucl_array_find_index(ucl_object_lookup(t, "ends"), 0);
		e1 = ucl_array_find_index(ucl_object_lookup(t, "ends"), 1);
		if (strcmp(str(e0, "edge"), sid) == 0) {
			me = e0;
			far = e1;
		} else if (strcmp(str(e1, "edge"), sid) == 0) {
			me = e1;
			far = e0;
		} else
			continue;
		if (str(far, "inner4") == NULL && str(far, "inner6") == NULL)
			continue;
		kore_buf_appendf(b, "# %s, to %s\nprotocol bgp edge%d from edge {\n\tlocal "
		    "%s as %jd;\n\tneighbor %s as %jd;\n}\n\n", str(t, "id"),
		    server_name_of(str(far, "edge")), k++, str(me, "inner4") !=
		    NULL ? str(me, "inner4") : str(me, "inner6"), (intmax_t)as,
		    str(far, "inner4") != NULL ? str(far, "inner4") : str(far,
		    "inner6"), (intmax_t)as);
	}
	/* At each UNI here: BGP, OSPF, as its entry says. */
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		u = ucl_object_lookup(ep, "uni");
		ifn = uni_ifname(pl, sw, ep, ifbuf, sizeof(ifbuf));
		symbol(str(ep, "id"), sym, sizeof(sym));
		r = ucl_object_lookup(u, "bgp");
		if (!is_nullish(r)) {
			fam = str(r, "family");
			dist = ucl_object_lookup(r, "distance") != NULL ?
			    ucl_object_toint(ucl_object_lookup(r, "distance")) :
			    200;
			n = 0;
			nit = NULL;
			while ((m = ucl_object_iterate(ucl_object_lookup(r,
			    "neighbors"), &nit, true)) != NULL) {
				const ucl_object_t	*cm;
				ucl_object_iter_t	 cit;
				char			 exp[1200];

				/* What goes to the subscriber carries the
				 * communities agreed. */
				snprintf(exp, sizeof(exp), "all");
				if (ucl_array_size(ucl_object_lookup(r,
				    "communities")) > 0) {
					snprintf(exp, sizeof(exp), "filter {\n");
					cit = NULL;
					while ((cm = ucl_object_iterate(
					    ucl_object_lookup(r, "communities"),
					    &cit, true)) != NULL)
						snprintf(exp + strlen(exp),
						    sizeof(exp) - strlen(exp),
						    "\t\t\tbgp_community.add((%jd, "
						    "%jd));\n", (intmax_t)
						    ucl_object_toint(
						    ucl_array_find_index(cm, 0)),
						    (intmax_t)ucl_object_toint(
						    ucl_array_find_index(cm, 1)));
					snprintf(exp + strlen(exp), sizeof(exp) -
					    strlen(exp), "\t\t\taccept;\n\t\t}");
				}
				kore_buf_appendf(b, "# UNI %s, the subscriber's %s\nprotocol "
				    "bgp uni_%s_%d {\n\tlocal as %jd;\n\tneighbor "
				    "%s as %jd;\n\tinterface \"%s\";\n"
				    "\tpreference %jd;\n", str(u, "id"),
				    ucl_object_tostring_forced(m),
				    sym, n++, (intmax_t)as,
				    ucl_object_tostring_forced(m), (intmax_t)
				    ucl_object_toint(ucl_object_lookup(r, "as")),
				    ifn, (intmax_t)(256 - dist));
				if (str(r, "password") != NULL)
					kore_buf_appendf(b, "\tpassword \"%s\";\n", str(r,
					    "password"));
				if (ucl_object_lookup(r, "hold_time") != NULL)
					kore_buf_appendf(b, "\thold time %jd;\n", (intmax_t)
					    ucl_object_toint(ucl_object_lookup(r,
					    "hold_time")));
				if (strcmp(fam, "ipv6") != 0 && family(
				    ucl_object_tostring_forced(m)) == AF_INET)
					bird_channel(b, "ipv4", exp);
				if (strcmp(fam, "ipv4") != 0 && family(
				    ucl_object_tostring_forced(m)) == AF_INET6)
					bird_channel(b, "ipv6", exp);
				kore_buf_appendf(b, "}\n\n");
			}
		}
		r = ucl_object_lookup(u, "ospf");
		if (!is_nullish(r)) {
			const char	*vers[] = { "v2", "v3" };
			int		 vi;

			fam = str(r, "family");
			dist = ucl_object_lookup(r, "distance") != NULL ?
			    ucl_object_toint(ucl_object_lookup(r, "distance")) :
			    200;
			for (vi = 0; vi < 2; vi++) {
				if ((vi == 0 && strcmp(fam, "ipv6") == 0) || (vi ==
				    1 && strcmp(fam, "ipv4") == 0))
					continue;
				kore_buf_appendf(b, "# UNI %s, OSPF%s with the subscriber\n"
				    "protocol ospf %s uni_%s_%s {\n\tpreference "
				    "%jd;\n", str(u, "id"), vi == 0 ? "v2" : "v3",
				    vers[vi], sym, vers[vi],
				    (intmax_t)(256 - dist));
				bird_channel(b, vi == 0 ? "ipv4" : "ipv6", "all");
				kore_buf_appendf(b, "\tarea %jd {\n\t\tinterface \"%s\" {\n",
				    (intmax_t)(ucl_object_lookup(r, "area") != NULL
				    ? ucl_object_toint(ucl_object_lookup(r, "area"))
				    : 0), ifn);
				if (ucl_object_lookup(r, "cost") != NULL)
					kore_buf_appendf(b, "\t\t\tcost %jd;\n", (intmax_t)
					    ucl_object_toint(ucl_object_lookup(r,
					    "cost")));
				if (ucl_object_lookup(r, "hello") != NULL)
					kore_buf_appendf(b, "\t\t\thello %jd;\n", (intmax_t)
					    ucl_object_toint(ucl_object_lookup(r,
					    "hello")));
				if (ucl_object_lookup(r, "dead") != NULL)
					kore_buf_appendf(b, "\t\t\tdead %jd;\n", (intmax_t)
					    ucl_object_toint(ucl_object_lookup(r,
					    "dead")));
				if (str(r, "password") != NULL)
					kore_buf_appendf(b, "\t\t\tauthentication "
					    "cryptographic;\n\t\t\tpassword \"%s\";"
					    "\n", str(r, "password"));
				kore_buf_appendf(b, "\t\t};\n\t};\n}\n\n");
			}
		}
	}
	out = strdup(kore_buf_stringify(b, NULL));
	kore_buf_free(b);
	return (out);
}

/*
 * Each edge's BIRD instances: one for each service that routes at a
 * UNI, on every edge of the service (what one UNI learns reaches the
 * others by iBGP), named sw<fib>.
 */
static void
bird_build(struct plan *pl, const ucl_object_t *doc)
{
	const ucl_object_t	*sw, *edge, *ep;
	ucl_object_iter_t	 it, eit, pit;
	ucl_object_t		*o, *inst, *list, *j;
	char			 name[32];
	const char		*sid;
	char			*text;
	bool			 here;

	it = NULL;
	while ((edge = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL) {
		sid = str(edge, "server");
		list = ucl_object_typed_new(UCL_ARRAY);
		eit = NULL;
		while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"),
		    &eit, true)) != NULL) {
			if (!sw_routes(sw) && !sw_bfd(sw))
				continue;
			here = false;
			pit = NULL;
			while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
			    "end_points"), &pit, true)) != NULL)
				if (strcmp(str(ep, "edge"), sid) == 0)
					here = true;
			if (!here)
				continue;
			snprintf(name, sizeof(name), "sw%jd", (intmax_t)
			    ucl_object_toint(ucl_object_lookup(sw, "fib")));
			inst = ucl_object_typed_new(UCL_OBJECT);
			put(inst, "name", S(name));
			put(inst, "fib", I(ucl_object_toint(ucl_object_lookup(sw,
			    "fib"))));
			text = bird_conf(pl, sw, sid);
			put(inst, "conf", S(text));
			free(text);
			ucl_array_append(list, inst);
		}
		if (ucl_array_size(list) == 0) {
			ucl_object_unref(list);
			continue;
		}
		o = object(pl, sid, "bird", PH_BIRD, "BIRD: %u instance%s in the "
		    "services' tables, BGP or OSPF with the subscriber at a UNI, "
		    "iBGP with the other edges, BFD on the tunnels",
		    ucl_array_size(list), ucl_array_size(list) == 1 ? "" : "s");
		if (o == NULL) {
			ucl_object_unref(list);
			continue;
		}
		j = job("sdwan-bird", "instances", list, NULL);
		make(o, j);
		unmake(o, job("sdwan-bird", "instances", ucl_object_typed_new(
		    UCL_ARRAY), NULL));
	}
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
	char			 n[64], why[200];
	int64_t			 fib;
	int			 far;

	memset(pl, 0, sizeof(*pl));
	pl->doc = doc;
	pl->alloc = ucl_object_copy(ucl_object_lookup(st, "alloc"));
	pl->edges = ucl_object_typed_new(UCL_OBJECT);
	pl->tunnels = ucl_object_typed_new(UCL_ARRAY);
	pl->used = ucl_object_typed_new(UCL_OBJECT);
	pl->notes = ucl_object_typed_new(UCL_ARRAY);
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
	/* An edge routes between its UNIs and its tunnels: the kernel's
	 * forwarding on, both families, kept (sysctl.conf). */
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL) {
		static const char *const oids[] = { "net.inet.ip.forwarding",
		    "net.inet6.ip6.forwarding" };
		int	i;

		o = object(pl, str(e, "server"), "forwarding", PH_FIBS,
		    "forwarding: the kernel routes between the UNIs and the "
		    "tunnels (net.inet.ip.forwarding, net.inet6.ip6.forwarding)");
		if (o == NULL)
			continue;
		for (i = 0; i < 2; i++) {
			args = ucl_object_typed_new(UCL_ARRAY);
			ucl_array_append(args, S(oids[i]));
			ucl_array_append(args, S("1"));
			make(o, job("sysctl", "args", args, "persist", B(true),
			    NULL));
		}
	}
	/* NTP where an edge says its servers: the time for faults to line
	 * up and keys to turn (Mplify 119 §12.2.2), with the FIBs. */
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL) {
		const ucl_object_t	*ns;

		if ((ns = ucl_object_lookup(e, "ntp")) == NULL ||
		    ucl_object_type(ns) != UCL_ARRAY || ucl_array_size(ns) == 0)
			continue;
		o = object(pl, str(e, "server"), "ntp", PH_FIBS, "NTP: ntpd by "
		    "%u server%s, for the time faults and keys go by",
		    ucl_array_size(ns), ucl_array_size(ns) == 1 ? "" : "s");
		if (o == NULL)
			continue;
		make(o, job("ntp", "args", ucl_object_copy(ns), "persist",
		    B(true), NULL));
		unmake(o, job("ntp", "args", ucl_object_typed_new(UCL_ARRAY),
		    "remove", B(true), "persist", B(true), NULL));
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
	/* Each edge's probes: one target per tunnel end it has. */
	it = NULL;
	while ((t = ucl_object_iterate(pl->tunnels, &it, true)) != NULL) {
		const ucl_object_t	*ends = ucl_object_lookup(t, "ends");
		int			 k;

		for (k = 0; k < 2; k++) {
			const ucl_object_t	*a, *b, *swo, *po;
			ucl_object_t		*tg, *targets, *j;
			const char		*faddr;

			a = ucl_array_find_index(ends, (unsigned int)k);
			b = ucl_array_find_index(ends, (unsigned int)!k);
			faddr = str(b, "inner4") != NULL ? str(b, "inner4") :
			    str(b, "inner6");
			if (faddr == NULL)
				continue;
			o = (ucl_object_t *)(uintptr_t)by(ucl_object_lookup(
			    pl->edges, str(a, "edge")), "key", "probes");
			if (o == NULL) {
				o = object(pl, str(a, "edge"), "probes", PH_PROBE,
				    "the tunnels measured: ICMP echo through "
				    "the service's table");
				targets = ucl_object_typed_new(UCL_ARRAY);
				make(o, job("sdwan-probes", "targets", targets,
				    NULL));
				targets = ucl_object_typed_new(UCL_ARRAY);
				unmake(o, job("sdwan-probes", "targets", targets,
				    NULL));
			}
			j = (ucl_object_t *)(uintptr_t)ucl_array_find_index(
			    ucl_object_lookup(o, "make"), 0);
			targets = (ucl_object_t *)(uintptr_t)ucl_object_lookup(j,
			    "targets");
			tg = ucl_object_typed_new(UCL_OBJECT);
			put(tg, "id", S(str(t, "id")));
			put(tg, "address", S(faddr));
			put(tg, "fib", I(ucl_object_toint(ucl_object_lookup(t,
			    "fib"))));
			/* The service's probe settings, and its eval interval. */
			swo = by(ucl_object_lookup(doc, "swvcs"), "id", str(t,
			    "swvc"));
			if ((po = ucl_object_lookup(ucl_object_lookup(swo,
			    "intervals"), "eval")) != NULL)
				put(tg, "eval", ucl_object_copy(po));
			if ((po = ucl_object_lookup(swo, "probe")) != NULL) {
				const ucl_object_t	*v;
				ucl_object_iter_t	 pit;

				pit = NULL;
				while ((v = ucl_object_iterate(po, &pit, true)) !=
				    NULL)
					put(tg, ucl_object_key(v),
					    ucl_object_copy(v));
			}
			/* Its threshold crossing alerts. */
			if ((po = ucl_object_lookup(swo, "tca")) != NULL &&
			    ucl_object_type(po) == UCL_OBJECT)
				put(tg, "tca", ucl_object_copy(po));
			ucl_array_append(targets, tg);
		}
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
					if (tt == NULL) {
						char	note[300];

						snprintf(note, sizeof(note),
						    "swvc %s: no tunnel from %s "
						    "to %s carries %s: none has "
						    "an inner %s address (a "
						    "reserved prefix of that "
						    "family)", str(sw, "id"),
						    server_name_of(str(ep,
						    "edge")), server_name_of(
						    str(ep2, "edge")),
						    ucl_object_tostring(p),
						    family(ucl_object_tostring(
						    p)) == AF_INET ? "IPv4" :
						    "IPv6");
						ucl_array_append(pl->notes,
						    S(note));
						continue;
					}
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
	/*
	 * Breakout (§9.12.2.5): where a flow of an edge's UNI may leave
	 * for the Internet, the service's default route: by the edge's
	 * own breakout UCS end point's gateway, reached by its interface
	 * (local), or by a tunnel to the edge that has one (remote).
	 */
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL) {
		const ucl_object_t	*edge, *bo, *tt, *fe;
		const char		*bo_sid, *gw;
		bool			 local;
		int			 af;

		it2 = NULL;
		while ((edge = ucl_object_iterate(ucl_object_lookup(doc,
		    "edges"), &it2, true)) != NULL) {
			const char	*sid = str(edge, "server");

			if (!breaks_here(pl, sw, sid))
				continue;
			bo = breakout_of(pl, sw, sid, &local, &bo_sid);
			if (local) {
				gw = str(bo, "gateway");
				if (gw == NULL) {
					char	note[300];

					snprintf(note, sizeof(note), "swvc %s: "
					    "%s breaks out by %s, which has no "
					    "gateway: no default route in its "
					    "table", str(sw, "id"),
					    server_name_of(sid), str(bo, "id"));
					ucl_array_append(pl->notes, S(note));
					continue;
				}
				af = family(gw);
				snprintf(n, sizeof(n), "%s/%d", gw, af == AF_INET ?
				    32 : 128);
				route_obj(pl, sid, sw, n, str(bo, "interface"),
				    "the breakout gateway, by its interface");
				route_obj(pl, sid, sw, af == AF_INET ? "0.0.0.0/0"
				    : "::/0", gw, "the Internet, by local "
				    "breakout");
				continue;
			}
			for (af = AF_INET; af != AF_UNSPEC; af = af == AF_INET ?
			    AF_INET6 : AF_UNSPEC) {
				if ((tt = tunnel_for(pl, str(sw, "id"), sid,
				    bo_sid, af, &far)) == NULL)
					continue;
				fe = ucl_array_find_index(ucl_object_lookup(tt,
				    "ends"), (unsigned int)far);
				snprintf(why, sizeof(why), "the Internet, by "
				    "breakout at %s", server_name_of(bo_sid));
				route_obj(pl, sid, sw, af == AF_INET ? "0.0.0.0/0"
				    : "::/0", str(fe, af == AF_INET ? "inner4" :
				    "inner6"), why);
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
	/* The rules of each edge, and the steering of their tables. */
	{
		const ucl_object_t	*edge;

		it = NULL;
		while ((edge = ucl_object_iterate(ucl_object_lookup(doc,
		    "edges"), &it, true)) != NULL)
			if (!rules_build(pl, str(edge, "server")))
				return (false);
	}
	/* Routing at the UNIs, once they are up; the hosts' addresses. */
	bird_build(pl, doc);
	dhcp_build(pl, doc);
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
	if (pl->notes != NULL)
		ucl_object_unref(pl->notes);
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
	/* The probes, rules and steering are the console's own asks, not
	 * jobs of the host. */
	if (strncmp(str(j, "kind"), "sdwan-", 6) == 0) {
		ucl_object_t	*body;
		char		*text;
		bool		 ok;

		if (strcmp(str(j, "kind"), "sdwan-probes") == 0)
			text = emit(ucl_object_lookup(j, "targets"));
		else {
			body = ucl_object_copy(j);
			(void)ucl_object_delete_key(body, "kind");
			text = emit(body);
			ucl_object_unref(body);
		}
		json = hosts_sdwan_set(uri, peer, name, str(j, "kind") + 6,
		    text != NULL ? text : strcmp(str(j, "kind"),
		    "sdwan-probes") == 0 ? "[]" : "{}", &status);
		free(text);
		ans = parse(json);
		free(json);
		ok = status == 200 && ans != NULL && ucl_flag(ans, "ok");
		if (!ok)
			snprintf(why, wlen, "%s", ans != NULL && str(ans,
			    "error") != NULL ? str(ans, "error") : "the host "
			    "did not take the probes");
		if (ans != NULL)
			ucl_object_unref(ans);
		return (ok);
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

/* A sysctl of the host as a number, or -1. */
static int64_t
sysctl_of(const char *sid, const char *name);

static int64_t
fibs_now(const char *sid)
{

	return (sysctl_of(sid, "net.fibs"));
}

static int64_t
sysctl_of(const char *sid, const char *oid)
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
	json = hosts_sysctl(uri, peer, name, oid, &status);
	ans = parse(json);
	free(json);
	n = -1;
	it = NULL;
	while ((v = ucl_object_iterate(at_path(ans, "data", "values"), &it,
	    true)) != NULL)
		if (str(v, "name") != NULL && strcmp(str(v, "name"), oid) == 0)
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

	if (ucl_object_lookup(s, "fibs") != NULL) {
		/* An address's route in every table would cross the
		 * services: the kernel's default, 0, is what works. */
		if (sysctl_of(str(s, "server"), "net.add_addr_allfibs") > 0) {
			step_set(r, s, "failed", "net.add_addr_allfibs is 1 on "
			    "the host: an interface's addresses are routed in "
			    "every table, so a service cannot have one of its "
			    "own; set it to 0 (sysctl.conf) first");
			return (false);
		}
		/* net.fibs only ever goes up. */
		if ((have = fibs_now(str(s, "server"))) >= ucl_object_toint(
		    ucl_object_lookup(s, "fibs"))) {
			snprintf(why, sizeof(why), "it has %jd already",
			    (intmax_t)have);
			goto made;
		}
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
	/* In the old one's place: insert_key would keep both. */
	put(applied_of(r, str(s, "server")), str(s, "key"), keep);
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
			else if (strcmp(str(s, "key"), "probes") != 0 &&
			    strcmp(str(s, "key"), "rules") != 0 &&
			    strcmp(str(s, "key"), "steer") != 0) {
				/* Its old self, then the new one below; the
				 * probes set anew replace the old ones. */
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
	/* Into the history: when, how it went, what it did; 50 kept. */
	{
		ucl_object_t		*hist, *h, *by;
		const ucl_object_t	*hs;
		ucl_object_iter_t	 hit;
		int			 made, remade, unmade, failed, nsteps;

		if ((hist = (ucl_object_t *)(uintptr_t)ucl_object_lookup(r->st,
		    "history")) == NULL) {
			hist = ucl_object_typed_new(UCL_ARRAY);
			put(r->st, "history", hist);
		}
		made = remade = unmade = failed = nsteps = 0;
		by = ucl_object_typed_new(UCL_OBJECT);
		hit = NULL;
		while ((hs = ucl_object_iterate(ucl_object_lookup(ap, "steps"),
		    &hit, true)) != NULL) {
			ucl_object_t	*e;
			const char	*sid = str(hs, "server");

			nsteps++;
			if (str(hs, "state") != NULL && strcmp(str(hs, "state"),
			    "failed") == 0)
				failed++;
			else if (str(hs, "change") != NULL && strcmp(str(hs,
			    "change"), "make") == 0)
				made++;
			else if (str(hs, "change") != NULL && strcmp(str(hs,
			    "change"), "remake") == 0)
				remade++;
			else if (str(hs, "change") != NULL && strcmp(str(hs,
			    "change"), "unmake") == 0)
				unmade++;
			if (sid == NULL)
				continue;
			if ((e = (ucl_object_t *)(uintptr_t)ucl_object_lookup(by,
			    sid)) == NULL) {
				e = ucl_object_typed_new(UCL_OBJECT);
				put(e, "name", S(str(hs, "name") != NULL ? str(hs,
				    "name") : sid));
				put(e, "steps", I(0));
				put(e, "failed", I(0));
				ucl_object_insert_key(by, e, sid, 0, true);
			}
			put(e, "steps", I(ucl_object_toint(ucl_object_lookup(e,
			    "steps")) + 1));
			if (str(hs, "state") != NULL && strcmp(str(hs, "state"),
			    "failed") == 0)
				put(e, "failed", I(ucl_object_toint(
				    ucl_object_lookup(e, "failed")) + 1));
		}
		h = ucl_object_typed_new(UCL_OBJECT);
		put(h, "started", I(ucl_object_toint(ucl_object_lookup(ap,
		    "started"))));
		put(h, "ended", I(time(NULL)));
		put(h, "state", S(ok ? "done" : "failed"));
		put(h, "fresh", B(ucl_flag(ap, "fresh")));
		put(h, "steps", I(nsteps));
		put(h, "made", I(made));
		put(h, "remade", I(remade));
		put(h, "unmade", I(unmade));
		put(h, "failed", I(failed));
		put(h, "edges", by);
		ucl_array_append(hist, h);
		while (ucl_array_size(hist) > 50)
			ucl_object_unref(ucl_array_pop_first(hist));
	}
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


/* ---- The manager: each policy's tunnels ordered by performance ------ */

#define	MGR_LOCK	"sdwan-mgr.lock"
#define	MGR_TICK_S	5
#define	MGR_RESEND_S	300	/* the order sent again, unchanged, after */

/* A tunnel's last sample at an edge: delay, ipdv, loss; false if none. */
static bool
metrics_of(const ucl_object_t *sd, const char *id, double *m)
{
	const ucl_object_t	*t, *s;
	ucl_object_iter_t	 it;
	unsigned int		 n;

	it = NULL;
	while ((t = ucl_object_iterate(ucl_object_lookup(sd, "targets"), &it,
	    true)) != NULL) {
		if (str(t, "id") == NULL || strcmp(str(t, "id"), id) != 0)
			continue;
		if (str(t, "state") != NULL && strcmp(str(t, "state"), "down")
		    == 0)
			return (false);
		n = ucl_object_lookup(t, "samples") != NULL ? ucl_array_size(
		    ucl_object_lookup(t, "samples")) : 0;
		if (n == 0)
			return (false);
		s = ucl_array_find_index(ucl_object_lookup(t, "samples"), n - 1);
		m[0] = ucl_object_todouble(ucl_array_find_index(s, 1));
		m[1] = ucl_object_todouble(ucl_array_find_index(s, 2));
		m[2] = ucl_object_todouble(ucl_array_find_index(s, 3));
		return (true);
	}
	return (false);
}

static int
metric_index(const char *name)
{

	return (name == NULL ? 0 : strcmp(name, "ipdv") == 0 ? 1 : strcmp(name,
	    "loss") == 0 ? 2 : 0);
}

/* Does a path meet every threshold of the performance criterion? */
static bool
meets(const ucl_object_t *perf, const double *m)
{
	const ucl_object_t	*pri, *e, *th;
	ucl_object_iter_t	 it;

	pri = ucl_object_lookup(perf, "primary");
	th = ucl_object_lookup(pri, "threshold");
	if (th != NULL && ucl_object_type(th) != UCL_NULL && m[metric_index(
	    str(pri, "metric"))] > ucl_object_todouble(th))
		return (false);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(perf, "secondary"),
	    &it, true)) != NULL)
		if (m[metric_index(str(e, "metric"))] > ucl_object_todouble(
		    ucl_object_lookup(e, "threshold")))
			return (false);
	return (true);
}

/*
 * One entry's candidates in the order the performance criterion wants
 * them (R69, R70): those that meet every threshold first, by the
 * primary metric; the one in use stays first while it meets them and
 * is under the ceiling (R73, O1).  Those without a measurement keep
 * their place after the measured.  True when the order changed.
 */
static bool
reorder(const ucl_object_t *perf, const ucl_object_t *sd, ucl_object_t *cands,
    const char *current)
{
	const ucl_object_t	*c, *pri, *ce;
	ucl_object_iter_t	 it;
	struct {
		const ucl_object_t	*c;
		double			 m[3];
		bool			 has, ok;
	}			 v[CANDS_MAX_ORDER];
	ucl_object_t		*out;
	int			 n, i, k, idx, first;
	bool			 changed;

	pri = ucl_object_lookup(perf, "primary");
	idx = metric_index(str(pri, "metric"));
	ce = ucl_object_lookup(pri, "ceiling");
	n = 0;
	it = NULL;
	while ((c = ucl_object_iterate(cands, &it, true)) != NULL && n <
	    CANDS_MAX_ORDER) {
		v[n].c = c;
		v[n].has = metrics_of(sd, str(c, "id"), v[n].m);
		v[n].ok = v[n].has && meets(perf, v[n].m);
		n++;
	}
	/* Sort: ok by the primary metric, then measured, then the rest. */
	for (i = 1; i < n; i++)
		for (k = i; k > 0; k--) {
			int	a = (v[k].ok ? 0 : v[k].has ? 1 : 2);
			int	b = (v[k - 1].ok ? 0 : v[k - 1].has ? 1 : 2);

			if (a < b || (a == b && a < 2 && v[k].m[idx] < v[k -
			    1].m[idx])) {
				__typeof__(v[0]) t = v[k];

				v[k] = v[k - 1];
				v[k - 1] = t;
			} else
				break;
		}
	/* The one in use stays, while it is good enough. */
	first = -1;
	for (i = 0; current != NULL && i < n; i++)
		if (strcmp(str(v[i].c, "id"), current) == 0)
			first = i;
	if (first > 0 && v[first].ok && (ce == NULL || ucl_object_type(ce) ==
	    UCL_NULL || v[first].m[idx] < ucl_object_todouble(ce))) {
		__typeof__(v[0]) t = v[first];

		for (i = first; i > 0; i--)
			v[i] = v[i - 1];
		v[0] = t;
	}
	changed = false;
	out = ucl_object_typed_new(UCL_ARRAY);
	i = 0;
	it = NULL;
	while ((c = ucl_object_iterate(cands, &it, true)) != NULL && i < n) {
		if (c != v[i].c)
			changed = true;
		i++;
	}
	for (i = 0; i < n; i++)
		ucl_array_append(out, ucl_object_copy(v[i].c));
	/* cands' own objects replaced by the ordered copies. */
	while (ucl_array_size(cands) > 0)
		ucl_object_unref(ucl_array_pop_last(cands));
	for (i = 0; i < n; i++)
		ucl_array_append(cands, ucl_object_copy(ucl_array_find_index(
		    out, (unsigned int)i)));
	ucl_object_unref(out);
	return (changed);
}

/* The steering an edge was last sent, from the state. */
static const ucl_object_t *
sent_of(const ucl_object_t *st, const char *sid)
{

	return (ucl_object_lookup(ucl_object_lookup(st, "steer_sent"), sid));
}

/* One tick: every edge's steering looked at, and sent where changed. */
static void
manager_tick(void)
{
	ucl_object_t		*st, *doc, *entries, *sent, *e, *cands, *all;
	const ucl_object_t	*ap, *s, *spec, *sw, *pol, *perf, *was, *w;
	ucl_object_iter_t	 it, eit;
	char			 uri[256], peer[256], name[128], *json, *text;
	const char		*sid, *current;
	int			 status;
	bool			 changed, busy;
	time_t			 now;

	pthread_mutex_lock(&st_lock);
	busy = applying;
	st = busy ? NULL : state_load();
	pthread_mutex_unlock(&st_lock);
	if (st == NULL)
		return;
	ap = ucl_object_lookup(st, "applied");
	doc = sdwan_load();
	now = time(NULL);
	all = (ucl_object_t *)(uintptr_t)ucl_object_lookup(st, "steer_sent");
	if (all == NULL) {
		all = ucl_object_typed_new(UCL_OBJECT);
		put(st, "steer_sent", all);
	}
	it = NULL;
	while ((s = ucl_object_iterate(ap, &it, true)) != NULL) {
		ucl_object_t	*sd;

		sid = ucl_object_key(s);
		if ((spec = ucl_object_lookup(s, "steer")) == NULL ||
		    (spec = parse(str(spec, "spec"))) == NULL)
			continue;
		entries = (ucl_object_t *)(uintptr_t)ucl_object_lookup(
		    ucl_array_find_index(ucl_object_lookup(spec, "make"), 0),
		    "entries");
		if (entries == NULL || ucl_array_size(entries) == 0 ||
		    !host_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
		    sizeof(name))) {
			ucl_object_unref((ucl_object_t *)(uintptr_t)spec);
			continue;
		}
		/* What its probes see now. */
		json = hosts_read(uri, peer, name, "sdwan", &status);
		sd = parse(json);
		free(json);
		if (sd == NULL || ucl_object_lookup(sd, "data") == NULL) {
			if (sd != NULL)
				ucl_object_unref(sd);
			ucl_object_unref((ucl_object_t *)(uintptr_t)spec);
			continue;
		}
		was = sent_of(st, sid);
		changed = was == NULL || now - ucl_object_toint(ucl_object_lookup(
		    was, "at")) > MGR_RESEND_S;
		eit = NULL;
		while ((e = (ucl_object_t *)(uintptr_t)ucl_object_iterate(entries,
		    &eit, true)) != NULL) {
			sw = by(ucl_object_lookup(doc, "swvcs"), "id", str(e,
			    "swvc"));
			pol = by(ucl_object_lookup(sw, "policies"), "name", str(e,
			    "policy"));
			perf = ucl_object_lookup(ucl_object_lookup(pol,
			    "criteria"), "performance");
			if (perf == NULL || ucl_object_type(perf) != UCL_OBJECT)
				continue;
			cands = (ucl_object_t *)(uintptr_t)ucl_object_lookup(e,
			    "candidates");
			/* The one in use: the first sent last time. */
			current = NULL;
			if (was != NULL) {
				const ucl_object_t	*o;
				ucl_object_iter_t	 oit;

				oit = NULL;
				while ((o = ucl_object_iterate(
				    ucl_object_lookup(was, "entries"), &oit,
				    true)) != NULL)
					if (strcmp(str(o, "table"), str(e,
					    "table")) == 0 && strcmp(str(o,
					    "prefix"), str(e, "prefix")) == 0)
						current = str(ucl_array_find_index(
						    ucl_object_lookup(o,
						    "candidates"), 0), "id");
			}
			if (reorder(perf, ucl_object_lookup(sd, "data"), cands,
			    current))
				changed = true;
			else if (current != NULL && strcmp(str(
			    ucl_array_find_index(cands, 0), "id"), current) != 0)
				changed = true;
		}
		if (changed) {
			ucl_object_t	*body;

			body = ucl_object_typed_new(UCL_OBJECT);
			put(body, "entries", ucl_object_copy(entries));
			text = emit(body);
			ucl_object_unref(body);
			json = hosts_sdwan_set(uri, peer, name, "steer", text,
			    &status);
			free(text);
			w = parse(json);
			free(json);
			if (status == 200 && w != NULL && ucl_flag(w, "ok")) {
				sent = ucl_object_typed_new(UCL_OBJECT);
				put(sent, "at", I(now));
				put(sent, "entries", ucl_object_copy(entries));
				put(all, sid, sent);
				thread_log(LOG_INFO, "sdwan: %s steered by the "
				    "performance", name);
			} else
				thread_log(LOG_WARNING, "sdwan: %s not steered: "
				    "%s", name, w != NULL && str(w, "error") !=
				    NULL ? str(w, "error") : "no answer");
			if (w != NULL)
				ucl_object_unref((ucl_object_t *)(uintptr_t)w);
		}
		ucl_object_unref(sd);
		ucl_object_unref((ucl_object_t *)(uintptr_t)spec);
	}
	ucl_object_unref(doc);
	pthread_mutex_lock(&st_lock);
	if (!applying)
		(void)store_save(STATE_FILE, st);
	pthread_mutex_unlock(&st_lock);
	ucl_object_unref(st);
}

static void *
manager(void *arg __unused)
{

	for (;;) {
		sleep(MGR_TICK_S);
		manager_tick();
	}
	return (NULL);
}

/* At the worker's start: the one that takes the lock runs the manager. */
void
sdwan_init(void)
{
	pthread_t	tid;
	char		path[MAXPATHLEN];
	int		fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, MGR_LOCK);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return;
	if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
		close(fd);
		return;
	}
	if (pthread_create(&tid, NULL, manager, NULL) == 0)
		(void)pthread_detach(tid);
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
	put(top, "notes", ucl_object_copy(pl->notes));
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
		if (strcmp(req->path, "/api/sdwan/steer") == 0) {
			pthread_mutex_lock(&st_lock);
			st = state_load();
			pthread_mutex_unlock(&st_lock);
			body = ucl_object_typed_new(UCL_OBJECT);
			put(body, "sent", ucl_object_lookup(st, "steer_sent") !=
			    NULL ? ucl_object_copy(ucl_object_lookup(st,
			    "steer_sent")) : ucl_object_typed_new(UCL_OBJECT));
			ucl_object_unref(st);
			return (reply_json(req, 200, body));
		}
		if (apply) {
			pthread_mutex_lock(&st_lock);
			st = state_load();
			pthread_mutex_unlock(&st_lock);
			body = ucl_object_typed_new(UCL_OBJECT);
			put(body, "apply", ucl_object_lookup(st, "apply") !=
			    NULL ? ucl_object_copy(ucl_object_lookup(st,
			    "apply")) : ucl_object_typed_new(UCL_OBJECT));
			put(body, "applying", B(applying));
			put(body, "history", ucl_object_lookup(st, "history") !=
			    NULL ? ucl_object_copy(ucl_object_lookup(st,
			    "history")) : ucl_object_typed_new(UCL_ARRAY));
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
