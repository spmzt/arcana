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
 *			MEF 70.2 §7.10): gre, gif, geneve, wg or uswe, maybe under
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
#include <fetch.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "console.h"

#define	STATE_FILE	"sdwan-state.json"
#define	LOCK_FILE	"sdwan.lock"
#define	UNIT_FIRST	100	/* tunnels' and VLANs' units, from here */
#define	WG_PORT		51000	/* + the unit: a wg tunnel's port */
#define	WG_REMOTE_PORT	51820	/* a remote end point's, unless said */
#define	JOB_POLL_US	300000
#define	JOB_WAIT_S	600
#define	PHASES		10
#define	LIST_SUBS	16	/* a UNI's subnets, the first and more */
#define	CANDS_MAX_ORDER	16	/* an entry's candidates the manager orders */

enum { PH_FIBS = 1, PH_IPSEC, PH_TVC, PH_PEER, PH_PROBE, PH_RULES, PH_STEER,
    PH_ROUTE, PH_UNI, PH_BIRD };

static pthread_mutex_t	st_lock = PTHREAD_MUTEX_INITIALIZER;
static bool		applying;
static bool		rekeying;	/* a uswe tunnel's keys being turned */
#define	USWE_LIFETIME_S	86400	/* a uswe tunnel's keys, unless the UCS says */

static const char	*server_name_of(const char *);
static int		 tunnel_mtu(const ucl_object_t *, const ucl_object_t *,
		    const ucl_object_t *);
static bool		 edge_ref(const char *, char *, size_t, char *, size_t,
			    char *, size_t, char *, size_t);
static ucl_object_t	*sdwan_read(const char *, char *, size_t, int *);
static bool		 jail_kind_ok(const char *, char *, size_t);
static const char	*symbol(const char *, char *, size_t);
static bool		 is_nullish(const ucl_object_t *);
struct plan;
static const char *uni_ifname(struct plan *, const ucl_object_t *,
		    const ucl_object_t *, char *, size_t);

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	(void)ucl_object_delete_key(o, key);
	ucl_object_insert_key(o, v, key, 0, true);
}

/* The keys of o that keys names, copied: what a form needs of it. */
static ucl_object_t *
pick(const ucl_object_t *o, const char *const *keys)
{
	ucl_object_t	*out;

	out = ucl_object_typed_new(UCL_OBJECT);
	for (; *keys != NULL; keys++)
		if (ucl_object_lookup(o, *keys) != NULL)
			ucl_object_insert_key(out, ucl_object_copy(
			    ucl_object_lookup(o, *keys)), *keys, 0, true);
	return (out);
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

/*
 * The lowest pair of af none has: of the service domain's prefix
 * (Mplify 119 §7.3, the tunnels' addresses), else of the service's
 * reserved prefixes.
 */
static bool
pair_new(const ucl_object_t *alloc, const ucl_object_t *sw, int af,
    const char *key, char *p, size_t len)
{
	const ucl_object_t	*v, *r, *sd;
	ucl_object_iter_t	 it, rit;
	char			 a[64], b[64];
	uint64_t		 k;
	bool			 used;
	int			 pass;

	sd = ucl_object_lookup(ucl_object_lookup(sw, "domains"), "service");
	for (pass = 0; pass < 2; pass++) {
	rit = NULL;
	while ((r = pass == 0 ? (rit == NULL && str(sd, "prefix") != NULL ?
	    (rit = (void *)1, ucl_object_lookup(sd, "prefix")) : NULL) :
	    ucl_object_iterate(ucl_object_lookup(sw, "reserved_prefixes"),
	    &rit, true)) != NULL) {
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
	}
	return (false);
}

/* The table a service's breakout goes by: its breakout domain's, else
 * its own (Mplify 119 R20-R26). */
static int64_t
bo_fib_of(const ucl_object_t *sw)
{
	const ucl_object_t	*d;

	d = ucl_object_lookup(ucl_object_lookup(sw, "domains"), "breakout");
	if (d != NULL && ucl_object_lookup(d, "fib") != NULL)
		return (ucl_object_toint(ucl_object_lookup(d, "fib")));
	return (ucl_object_toint(ucl_object_lookup(sw, "fib")));
}

/* ---- What each edge is to have ------------------------------------- */

struct plan;
static const char *ucs_address(struct plan *, const char *,
		    const ucl_object_t *);
static int64_t	 sysctl_of(const char *, const char *);
static ucl_object_t *parse(const char *);
static const ucl_object_t *at_path(const ucl_object_t *, const char *,
		    const char *);

static ucl_object_t *lists_kept(void);

struct plan {
	const ucl_object_t	*doc;
	ucl_object_t		*lists;		/* the lists kept, by name */
	ucl_object_t		*alloc;		/* the state's, with new ones */
	ucl_object_t		*edges;		/* sid: [objects] */
	ucl_object_t		*tunnels;	/* the tunnels, both ends */
	ucl_object_t		*used;		/* the allocations they have */
	ucl_object_t		*notes;		/* what the plan leaves out, and why */
	ucl_object_t		*ready;		/* the document deployed, its own */
	ucl_object_t		*learned;	/* sid/ifname: the host's address */
	ucl_object_t		*boroutes;	/* sid: the breakout's steered routes */
	char			 why[300];
};
/*
 * A host-as-subscriber edge (edges[].own_table): the service's overlay
 * lives in the host's own table, the first, and its uplinks go to
 * underlay tables (the UCS End Points' vrf); nothing of the host's is
 * moved, its jails and daemons stay as they are.  Arcana's own, beside
 * Mplify 119 §7.3.
 */
static bool
edge_own_table(struct plan *pl, const char *sid)
{
	const ucl_object_t	*e;

	e = by(ucl_object_lookup(pl->doc, "edges"), "server", sid);
	return (e != NULL && ucl_flag(e, "own_table"));
}

/* The table a service's overlay is in on an edge: the first on an
 * own-table edge, else the service's own. */
static int64_t
efib(struct plan *pl, const ucl_object_t *sw, const char *sid)
{

	if (sid != NULL && edge_own_table(pl, sid))
		return (0);
	return (ucl_object_toint(ucl_object_lookup(sw, "fib")));
}

/* Is the service's iBGP between the edges' loopbacks (ibgp: loopback),
 * one session with each edge, rather than one by each tunnel? */
static bool
sw_loop(const ucl_object_t *sw)
{

	return (str(sw, "ibgp") != NULL && strcmp(str(sw, "ibgp"), "loopback")
	    == 0);
}

/* Does the edge carry what the other edges exchange (edges[].transit,
 * on unless said otherwise)? */
static bool
edge_transit(struct plan *pl, const char *sid)
{
	const ucl_object_t	*e, *v;

	e = by(ucl_object_lookup(pl->doc, "edges"), "server", sid);
	v = ucl_object_lookup(e, "transit");
	return (v == NULL || ucl_object_type(v) != UCL_BOOLEAN ||
	    ucl_object_toboolean(v));
}

/* Has the service an end point on the edge? */
static bool
edge_in(const ucl_object_t *sw, const char *sid)
{
	const ucl_object_t	*ep;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL)
		if (str(ep, "edge") != NULL && strcmp(str(ep, "edge"), sid) == 0)
			return (true);
	return (false);
}



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

/*
 * A UCS End Point's address: the document's, or, when the host gets it
 * by DHCP or SLAAC (Mplify 119 §12.2.3.2, §12.2.3.3), the first global
 * address its interface has now, asked of the host once a plan and
 * kept; NULL when it has none yet.
 */
static const char *
ucs_address(struct plan *pl, const char *sid, const ucl_object_t *uep)
{
	const ucl_object_t	*ifc, *a, *v;
	ucl_object_iter_t	 it, ait;
	ucl_object_t		*ans;
	char			 key[160], uri[256], peer[256], name[128];
	char			*json, jail[64];
	const char		*s, *found;
	int			 status;

	if (str(uep, "address") != NULL)
		return (str(uep, "address"));
	if (str(uep, "addressing") == NULL || strcmp(str(uep, "addressing"),
	    "static") == 0 || str(uep, "interface") == NULL)
		return (NULL);
	snprintf(key, sizeof(key), "%s/%s", sid, str(uep, "interface"));
	if ((v = ucl_object_lookup(pl->learned, key)) != NULL)
		return (ucl_object_type(v) == UCL_STRING ? ucl_object_tostring(v) :
		    NULL);
	found = NULL;
	if (edge_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
	    sizeof(name), jail, sizeof(jail))) {
		json = hosts_net_in(uri, peer, name, jail[0] != '\0' ? jail :
		    NULL, "interfaces", &status);
		ans = parse(json);
		free(json);
		it = NULL;
		while (found == NULL && (ifc = ucl_object_iterate(at_path(ans,
		    "data", "interfaces"), &it, true)) != NULL) {
			if (str(ifc, "name") == NULL || strcmp(str(ifc, "name"),
			    str(uep, "interface")) != 0)
				continue;
			/* Its first IPv4 address, else its first global IPv6
			 * one: not link-local, not the loopback's. */
			for (int pass = 0; found == NULL && pass < 2; pass++) {
				ait = NULL;
				while (found == NULL && (a = ucl_object_iterate(
				    ucl_object_lookup(ifc, "addresses"), &ait,
				    true)) != NULL) {
					s = str(a, "address");
					if (s == NULL || str(a, "family") == NULL ||
					    strcmp(str(a, "family"), pass == 0 ? "inet"
					    : "inet6") != 0)
						continue;
					if (strncasecmp(s, "fe80:", 5) == 0 ||
					    strncmp(s, "127.", 4) == 0 || strcmp(s,
					    "::1") == 0 || strncmp(s, "169.254.", 8)
					    == 0)
						continue;
					found = s;
				}
			}
		}
		ucl_object_insert_key(pl->learned, found != NULL ? S(found) :
		    ucl_object_typed_new(UCL_NULL), key, 0, true);
		if (ans != NULL)
			ucl_object_unref(ans);
	} else
		ucl_object_insert_key(pl->learned, ucl_object_typed_new(UCL_NULL),
		    key, 0, true);
	v = ucl_object_lookup(pl->learned, key);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}


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
	if (strcmp(*kindp, "wg") == 0 || strcmp(*kindp, "uswe") == 0)
		*ipsecp = false;	/* encrypted by itself */
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
	    0 ? "gif" : strcmp(kind, "uswe") == 0 ? "ipsec" : "gre",
	    (intmax_t)unit);
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

/* The UCS End Point a tunnel's end is on, in the document; or NULL. */
static const ucl_object_t *
uep_of(struct plan *pl, const ucl_object_t *end)
{
	const ucl_object_t	*edge;

	edge = by(ucl_object_lookup(pl->doc, "edges"), "server", str(end,
	    "edge"));
	return (by(ucl_object_lookup(edge, "ucs_end_points"), "id", str(end,
	    "ucs_ep")));
}

/*
 * This end's relay toward the far end's edge, if its UCS End Point names
 * one: a FEC or obfuscating relay on the host (speederv2, say) that the
 * wg peer's endpoint points at, the relay itself reaching the far
 * underlay address at its port.
 */
static const ucl_object_t *
relay_of(struct plan *pl, const ucl_object_t *a, const ucl_object_t *b)
{
	const ucl_object_t	*ua, *r;
	ucl_object_iter_t	 it;

	if ((ua = uep_of(pl, a)) == NULL)
		return (NULL);
	it = NULL;
	while ((r = ucl_object_iterate(ucl_object_lookup(ua, "relay"), &it,
	    true)) != NULL)
		if (str(r, "to") != NULL && strcmp(str(r, "to"), str(b, "edge"))
		    == 0)
			return (r);
	return (NULL);
}

/*
 * The service's loopback on an edge (ibgp loopback): a lo(4) of its own
 * with an address of each family the reserved prefixes have room for,
 * allocated once and kept with the tunnels' (a pair, its first).  NULL
 * when neither family has room.
 */
static const ucl_object_t *
loop_alloc(struct plan *pl, const ucl_object_t *sw, const char *sid)
{
	const ucl_object_t	*al;
	ucl_object_t		*na;
	char			 key[200], p[64];
	int64_t			 unit;

	snprintf(key, sizeof(key), "loop:%s/%s", str(sw, "id"), sid);
	if ((al = ucl_object_lookup(pl->alloc, key)) == NULL) {
		if ((unit = unit_new(pl->alloc)) < 0)
			return (NULL);
		na = ucl_object_typed_new(UCL_OBJECT);
		put(na, "unit", I(unit));
		put(na, "swvc", S(str(sw, "id")));
		ucl_object_insert_key(pl->alloc, na, key, 0, true);
		if (pair_new(pl->alloc, sw, AF_INET, "v4", p, sizeof(p)))
			put(na, "v4", S(p));
		if (pair_new(pl->alloc, sw, AF_INET6, "v6", p, sizeof(p)))
			put(na, "v6", S(p));
		al = na;
	}
	if (str(al, "v4") == NULL && str(al, "v6") == NULL)
		return (NULL);
	ucl_object_insert_key(pl->used, B(true), key, 0, true);
	return (al);
}

/* The loopback's address of the family, into buf; NULL without one. */
static const char *
loop_addr(struct plan *pl, const ucl_object_t *sw, const char *sid, int af,
    char *buf, size_t len)
{
	const ucl_object_t	*al;
	char			 p[64], a[64], b[64];

	if ((al = loop_alloc(pl, sw, sid)) == NULL || str(al, af == AF_INET ?
	    "v4" : "v6") == NULL)
		return (NULL);
	if (!pair_of(str(al, af == AF_INET ? "v4" : "v6"), 0, p, a, b,
	    sizeof(a)))
		return (NULL);
	snprintf(buf, len, "%s", a);
	return (buf);
}
/*
 * The service's loopback on an edge (ibgp loopback): its lo(4), made in
 * the service's table and addressed; the iBGP sessions and the other
 * edges' routes to this edge end at it.
 */
static void
loop_obj(struct plan *pl, const ucl_object_t *sw, const char *sid)
{
	const ucl_object_t	*al;
	ucl_object_t		*o;
	const char		*a4, *a6;
	char			 key[200], ifn[32], b4[64], b6[64], addr[80];
	char			 note[300];
	int64_t			 fib;

	snprintf(key, sizeof(key), "loop:%s", str(sw, "id"));
	if (by(ucl_object_lookup(pl->edges, sid), "key", key) != NULL)
		return;
	if ((al = loop_alloc(pl, sw, sid)) == NULL) {
		snprintf(note, sizeof(note), "swvc %s: its reserved prefixes "
		    "have no room for a loopback on %s", str(sw, "id"),
		    server_name_of(sid));
		ucl_array_append(pl->notes, S(note));
		return;
	}
	a4 = loop_addr(pl, sw, sid, AF_INET, b4, sizeof(b4));
	a6 = loop_addr(pl, sw, sid, AF_INET6, b6, sizeof(b6));
	snprintf(ifn, sizeof(ifn), "lo%jd", (intmax_t)ucl_object_toint(
	    ucl_object_lookup(al, "unit")));
	fib = efib(pl, sw, sid);
	o = object(pl, sid, key, PH_TVC, "%s: the service's loopback, %s%s%s, "
	    "in fib %jd: the other edges' iBGP sessions end here", ifn, a4 !=
	    NULL ? a4 : "", a4 != NULL && a6 != NULL ? " and " : "", a6 != NULL
	    ? a6 : "", (intmax_t)fib);
	if (o == NULL)
		return;
	make(o, job("if-create", "interface", S(ifn), "fib", I(fib), "persist",
	    B(true), NULL));
	if (a4 != NULL) {
		snprintf(addr, sizeof(addr), "%s/32", a4);
		make(o, job("if-address", "interface", S(ifn), "address",
		    S(addr), "persist", B(true), NULL));
	}
	if (a6 != NULL) {
		snprintf(addr, sizeof(addr), "%s/128", a6);
		make(o, job("if-address", "interface", S(ifn), "address",
		    S(addr), "persist", B(true), NULL));
	}
	unmake(o, job("if-destroy", "interface", S(ifn), "persist", B(true),
	    NULL));
}

/* A relay's profile name: letters, digits and _, as its rc script takes. */
static void
relay_profile(char *buf, size_t len, const char *role, const char *ifn)
{
	size_t	o;

	o = (size_t)snprintf(buf, len, "%s_", role);
	for (; *ifn != '\0' && o + 1 < len && o < 32; ifn++)
		buf[o++] = isalnum((unsigned char)*ifn) ? *ifn : '_';
	buf[o < len ? o : len - 1] = '\0';
}

/* A word name=value for a speeder job's args. */
static void
word(ucl_object_t *args, const char *name, const char *fmt, ...)
{
	char	v[200], w[220];
	va_list	ap;

	va_start(ap, fmt);
	vsnprintf(v, sizeof(v), fmt, ap);
	va_end(ap);
	snprintf(w, sizeof(w), "%s=%s", name, v);
	ucl_array_append(args, S(w));
}

/*
 * A relay the document makes (its plugin speederv2): this end's client,
 * listening where the wg peer points (its endpoint) and sending to the
 * far underlay at the relay's port; the far end's server, taking it
 * there and handing it to the far wg's own port.  Each a profile of
 * Arcana's rc script for the relays, arcana_relay, named for its
 * interface, with a fifo of its own so that its ratios change without
 * dropping the tunnel, run in a service jail of rc.subr's
 * (svcj-arcana_relay_<profile>) held to its addresses; started, and
 * taken away when the tunnel is.
 */
static void
relay_objs(struct plan *pl, const ucl_object_t *a, const ucl_object_t *b,
    const ucl_object_t *rl)
{
	ucl_object_t	*o, *args;
	const char	*fec, *bu;
	char		 prof[40], key[200];
	int64_t		 mode;
	int		 side;
	bool		 v6;

	if (str(rl, "plugin") == NULL || strcmp(str(rl, "plugin"),
	    "speederv2") != 0)
		return;
	fec = str(rl, "fec") != NULL ? str(rl, "fec") : "20:10";
	mode = ucl_object_lookup(rl, "mode") != NULL ? ucl_object_toint(
	    ucl_object_lookup(rl, "mode")) : 1;
	bu = str(b, "underlay");
	v6 = family(bu) == AF_INET6;
	for (side = 0; side < 2; side++) {
		const ucl_object_t	*me = side == 0 ? a : b;

		relay_profile(prof, sizeof(prof), side == 0 ? "c" : "s", str(me,
		    "ifname"));
		snprintf(key, sizeof(key), "relay:%s", prof);
		o = object(pl, str(me, "edge"), key, PH_TVC, side == 0 ?
		    "%s: its FEC relay toward %s, speederv2 %s, a client" :
		    "%s: the FEC relay from %s, speederv2 %s, a server",
		    str(me, "ifname"), str(side == 0 ? b : a, "edge"), prof);
		if (o == NULL)
			continue;
		args = ucl_object_typed_new(UCL_ARRAY);
		word(args, "profile", "%s", prof);
		if (side == 0) {
			word(args, "role", "client");
			word(args, "listen", "%s", str(rl, "endpoint"));
			word(args, "remote", "%s%s%s:%jd", v6 ? "[" : "", bu, v6 ?
			    "]" : "", (intmax_t)ucl_object_toint(
			    ucl_object_lookup(rl, "port")));
		} else {
			word(args, "role", "server");
			word(args, "listen", "%s%s%s:%jd", v6 ? "[" : "", bu, v6 ?
			    "]" : "", (intmax_t)ucl_object_toint(
			    ucl_object_lookup(rl, "port")));
			word(args, "remote", "%s:%jd", v6 ? "[::1]" : "127.0.0.1",
			    (intmax_t)(WG_PORT + ucl_object_toint(
			    ucl_object_lookup(b, "unit"))));
		}
		word(args, "fec", "%s", fec);
		word(args, "mode", "%jd", (intmax_t)mode);
		word(args, "report", "10");
		word(args, "fifo", "/var/run/arcana_relay/%s.fifo", prof);
		/* In rc.subr's service jail, held to the addresses it uses:
		 * the client to its underlay and where the wg peer reaches
		 * it, the server to its underlay and the loopback it hands
		 * the packets to wg at. */
		word(args, "svcj", "yes");
		if (side == 0) {
			char		 lh[80];
			const char	*ep, *c;

			ep = str(rl, "endpoint");
			c = strrchr(ep, ':');
			snprintf(lh, sizeof(lh), "%.*s", (int)(c - ep), ep);
			if (lh[0] == '[') {
				memmove(lh, lh + 1, strlen(lh));
				lh[strcspn(lh, "]")] = '\0';
			}
			if (str(a, "underlay") != NULL && strcmp(lh, str(a,
			    "underlay")) != 0)
				word(args, "svcj_ipaddrs", "%s,%s", str(a,
				    "underlay"), lh);
			else
				word(args, "svcj_ipaddrs", "%s", lh);
		} else
			word(args, "svcj_ipaddrs", "%s,%s", bu, v6 ? "::1" :
			    "127.0.0.1");
		make(o, job("speeder", "verb", S("conf"), "args", args, NULL));
		make(o, job("speeder", "verb", S("enable"), NULL));
		args = ucl_object_typed_new(UCL_ARRAY);
		word(args, "profile", "%s", prof);
		make(o, job("speeder", "verb", S("start"), "args", args, NULL));
		args = ucl_object_typed_new(UCL_ARRAY);
		word(args, "profile", "%s", prof);
		unmake(o, job("speeder", "verb", S("remove"), "args", args,
		    NULL));
	}
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
	int			 mtu;
	bool			 ipsec;

	a = ucl_array_find_index(ucl_object_lookup(t, "ends"),
	    (unsigned int)me);
	b = ucl_array_find_index(ucl_object_lookup(t, "ends"),
	    (unsigned int)!me);
	kind = str(t, "kind");
	id = str(t, "id");
	sid = str(a, "edge");
	unit = ucl_object_toint(ucl_object_lookup(a, "unit"));
	/* The table this end is in: the service's, or the host's own. */
	fib = efib(pl, by(ucl_object_lookup(pl->doc, "swvcs"), "id", str(t,
	    "swvc")), sid);
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
		if ((mtu = tunnel_mtu(pl->doc, t, a)) > 0)
			make(o, job("if-set", "interface", S(ifn), "mtu", I(mtu),
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
		/* Its MTU, when the UCS says (auto: the overhead taken off
		 * 1500), so the inner packets are not fragmented. */
		if ((mtu = tunnel_mtu(pl->doc, t, a)) > 0)
			put(p, "mtu", I(mtu));
		if (strcmp(kind, "wg") != 0) {
			put(p, "tunnel_local", S(str(a, "underlay")));
			put(p, "tunnel_remote", S(str(b, "underlay")));
		}
		/* Its outer packets by the underlay's table, wg's too; not
		 * through a relay, which is on this host, in the first
		 * table. */
		if (ucl_object_lookup(a, "vrf") != NULL && relay_of(pl, a, b) ==
		    NULL)
			put(p, "tunnelfib", I(ucl_object_toint(
			    ucl_object_lookup(a, "vrf"))));
		/* A USWE tunnel is an ipsec(4) interface whose SAs the agent
		 * keys: its reqid is its unit. */
		if (strcmp(kind, "uswe") == 0)
			put(p, "reqid", I(unit));
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

	/* A USWE tunnel (Mplify 119 §10): this end's key pair before the
	 * interface, the SAs of both directions derived from the far end's
	 * public half after it, as ${uswe:SID:IF} once that end has one. */
	if (strcmp(kind, "uswe") == 0) {
		const ucl_object_t	*tt;
		ucl_object_t		*args;
		const char		*alg;

		snprintf(key, sizeof(key), "uswekey:%s", ifn);
		o = object(pl, sid, key, PH_IPSEC, "%s: its key pair, X25519, "
		    "kept by the agent", ifn);
		if (o != NULL)
			make(o, job("ipsec-sa", "verb", S("key"), "interface",
			    S(ifn), NULL));
		snprintf(key, sizeof(key), "peer:%s", id);
		o = object(pl, sid, key, PH_PEER, "%s: the far end, %s, its "
		    "keys from the two halves", ifn, str(b, "underlay"));
		if (o == NULL)
			return;
		tt = ucl_object_lookup(t, "tunnel");
		alg = str(tt, "algorithms") != NULL ? str(tt, "algorithms") :
		    "aes-cbc-hmac-sha2-256";
		args = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(args, S("peer"));
		snprintf(key, sizeof(key), "${uswe:%s:%s}", str(b, "edge"), str(b,
		    "ifname"));
		ucl_array_append(args, S(key));
		ucl_array_append(args, S("enc"));
		ucl_array_append(args, S(strcmp(alg, "aes-gcm-16") == 0 ?
		    "aes-gcm-16" : "aes-cbc"));
		if (strcmp(alg, "aes-gcm-16") != 0) {
			ucl_array_append(args, S("auth"));
			ucl_array_append(args, S("hmac-sha2-256"));
		}
		if (tt == NULL || ucl_object_lookup(tt, "encap") == NULL ||
		    ucl_flag(tt, "encap"))
			ucl_array_append(args, S("encap"));
		if (tt == NULL || ucl_object_lookup(tt, "esn") == NULL ||
		    ucl_flag(tt, "esn"))
			ucl_array_append(args, S("esn"));
		ucl_array_append(args, S("epoch"));
		ucl_array_append(args, S("0"));
		/* The lifetime, kept with the SAs: the manager turns the keys
		 * at its half (R110, R112). */
		ucl_array_append(args, S("lifetime"));
		snprintf(key, sizeof(key), "%jd", (intmax_t)(tt != NULL &&
		    ucl_object_lookup(tt, "lifetime") != NULL ? ucl_object_toint(
		    ucl_object_lookup(tt, "lifetime")) : USWE_LIFETIME_S));
		ucl_array_append(args, S(key));
		p = job("ipsec-sa", "verb", S("derive"), "interface", S(ifn),
		    "reqid", I(unit), "tunnel_local", S(str(a, "underlay")),
		    "tunnel_remote", S(str(b, "underlay")), "args", args, NULL);
		/* Made again when the far end's interface is: a new pair. */
		put(p, "_after", S(digest(t, h, sizeof(h))));
		make(o, p);
		unmake(o, job("ipsec-sa", "verb", S("clear"), "interface", S(ifn),
		    "reqid", I(unit), "tunnel_local", S(str(a, "underlay")),
		    "tunnel_remote", S(str(b, "underlay")), NULL));
		return;
	}
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
		const ucl_object_t	*rl, *ub;

		snprintf(key, sizeof(key), "${wg:%s:%s}", str(b, "edge"), str(b,
		    "ifname"));
		/*
		 * Where the far end is: through this end's relay when it
		 * names one toward that edge; nowhere when the far end is
		 * behind NAT (it finds this end, and the keepalive holds
		 * the mapping); else the far underlay's address and port.
		 */
		if ((rl = relay_of(pl, a, b)) != NULL) {
			snprintf(port, sizeof(port), "%s", str(rl, "endpoint"));
			relay_objs(pl, a, b, rl);
		}
		else
			snprintf(port, sizeof(port), "%s%s%s:%jd", family(str(b,
			    "underlay")) == AF_INET6 ? "[" : "", str(b,
			    "underlay"), family(str(b, "underlay")) == AF_INET6 ?
			    "]" : "", (intmax_t)(WG_PORT + ucl_object_toint(
			    ucl_object_lookup(b, "unit"))));
		ub = uep_of(pl, b);
		p = job("wireguard", "verb", S("peer"), "interface", S(ifn),
		    "peer", S(key), "allowed_ips", S("0.0.0.0/0,::/0"),
		    "keepalive", I(25), "persist", B(true), NULL);
		if (rl != NULL || ub == NULL || !ucl_flag(ub, "nat"))
			put(p, "endpoint", S(port));
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
 * two of their UCS End Points a tunnel can join (§7.10); and, where the
 * control plane names a UCS for its own tunnel (Mplify 119 R5, R6, the
 * CTVC), one more between its host and each edge over that UCS, after
 * the others, marked control: the iBGP goes by it and nothing else. */
static bool
tunnels(struct plan *pl, const ucl_object_t *sw)
{
	const ucl_object_t	*doc, *e1, *e2, *x, *y, *ux, *uy, *ep, *cp;
	ucl_object_iter_t	 it, it2, xit, yit;
	ucl_object_t		*edges, *t, *ends, *end, *al;
	const char		*kind, *k2, *sid, *ax, *ay, *ctvc, *cphost;
	char			 id[300], p[80], a[64], b[64];
	int64_t			 unit;
	bool			 ipsec, ip2, public, said, said2, always;
	size_t			 i, j;
	int			 pass;

	doc = pl->doc;
	always = always_encrypted(sw);
	ctvc = cphost = NULL;
	cp = ucl_object_lookup(sw, "control_plane");
	if (cp != NULL && ucl_object_type(cp) == UCL_OBJECT && str(cp, "ctvc")
	    != NULL) {
		ctvc = str(cp, "ctvc");
		cphost = str(cp, "host");
	}
	/* Its edges, each once, in the order its end points name them. */
	edges = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL)
		if (!in_list(edges, str(ep, "edge")))
			ucl_array_append(edges, S(str(ep, "edge")));
	for (pass = 0; pass < (ctvc != NULL ? 2 : 1); pass++)
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
					/* Two Internet Accesses join only when
					 * their tunnels are of one kind, IPsec
					 * alike: K transports on a pair of edges
					 * give K tunnels, not K squared. */
					if (strcmp(str(x, "ucs"), str(y, "ucs"))
					    != 0) {
						tunnel_of(ux, &kind, &ipsec, &said);
						tunnel_of(uy, &k2, &ip2, &said2);
						if (strcmp(kind, k2) != 0 || ipsec !=
						    ip2)
							continue;
					}
					/* The control tunnel: over the UCS named,
					 * between the host and each edge. */
					if (pass == 1 && (strcmp(str(x, "ucs"), ctvc)
					    != 0 || strcmp(str(y, "ucs"), ctvc) != 0 ||
					    (strcmp(str(e1, "server"), cphost) != 0 &&
					    strcmp(str(e2, "server"), cphost) != 0)))
						continue;
					ax = ucs_address(pl, str(e1, "server"), x);
					ay = ucs_address(pl, str(e2, "server"), y);
					if (ax == NULL || ay == NULL) {
						const ucl_object_t *z = ax == NULL ?
						    x : y;

						/* Learned once the host has one
						 * (DHCP, SLAAC): the next plan. */
						if (str(z, "addressing") != NULL &&
						    strcmp(str(z, "addressing"),
						    "static") != 0) {
							char	note[300];

							snprintf(note, sizeof(note),
							    "ucs end point %s has no "
							    "address yet (%s on %s): "
							    "no tunnel over it until "
							    "the host has one; apply "
							    "again then", str(z, "id"),
							    str(z, "addressing"),
							    str(z, "interface"));
							ucl_array_append(pl->notes,
							    S(note));
							continue;
						}
						snprintf(pl->why, sizeof(pl->why),
						    "ucs end point %s has no "
						    "address: a tunnel needs its "
						    "outer one", str(z, "id"));
						ucl_object_unref(edges);
						return (false);
					}
					if (family(ax) != family(ay))
						continue;
					tunnel_of(ux, &kind, &ipsec, &said);
					tunnel_of(uy, &k2, &ip2, &said2);
					ipsec = ipsec || ip2;
					/* A policy that wants every tunnel
					 * encrypted (R39): so it is, unless the
					 * UCS says no, which no path mends. */
					if (always && !ipsec && strcmp(kind,
					    "wg") != 0 && strcmp(kind, "uswe") !=
					    0) {
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
					snprintf(id, sizeof(id), pass == 1 ?
					    "%s/%s-%s/ctvc" : "%s/%s-%s", str(sw,
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
					if (pass == 1)
						put(t, "control", B(true));
					put(t, "swvc", S(str(sw, "id")));
					put(t, "fib", I(ucl_object_toint(
					    ucl_object_lookup(sw, "fib"))));
					put(t, "kind", S(kind));
					/* The UCS's tunnel entry, for what a uswe
					 * tunnel's SAs are made of. */
					if (ucl_object_lookup(ux, "tunnel") != NULL)
						put(t, "tunnel", ucl_object_copy(
						    ucl_object_lookup(ux, "tunnel")));
					put(t, "ipsec", B(ipsec));
					put(t, "encrypted", B(ipsec ||
					    strcmp(kind, "wg") == 0 || strcmp(kind,
					    "uswe") == 0));
					put(t, "public", B(public));
					put(t, "ucs", S(str(x, "ucs")));
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
						put(end, "underlay", S(k == 0 ? ax :
						    ay));
						/* Its own table, when the UCS has
						 * one (§12.2.3.4): the tunnel's
						 * outer packets go by it. */
						if (ucl_object_lookup(u, "vrf") !=
						    NULL)
							put(end, "vrf", I(
							    ucl_object_toint(
							    ucl_object_lookup(u,
							    "vrf"))));
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
		if (strcmp(str(t, "swvc"), swvc) != 0 || ucl_flag(t, "control"))
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

/*
 * Every tunnel a route from edge a to edge b may take for af, as the
 * gateways of one multipath route (ECMP): the far inner addresses of
 * the tunnels that are no backup, with , between; of the backups when
 * there is no other.  "" when none.
 */
static const char *
tunnels_for(struct plan *pl, const char *swvc, const char *a, const char *b,
    int af, char *buf, size_t len)
{
	const ucl_object_t	*t, *e0, *e1, *far;
	ucl_object_iter_t	 it;
	int			 pass, n;

	buf[0] = '\0';
	for (pass = 0; pass < 2 && buf[0] == '\0'; pass++) {
		n = 0;
		it = NULL;
		while ((t = ucl_object_iterate(pl->tunnels, &it, true)) != NULL) {
			if (strcmp(str(t, "swvc"), swvc) != 0 || ucl_flag(t,
			    "control") || ucl_flag(t, "backup") != (pass == 1))
				continue;
			e0 = ucl_array_find_index(ucl_object_lookup(t, "ends"), 0);
			e1 = ucl_array_find_index(ucl_object_lookup(t, "ends"), 1);
			if (strcmp(str(e0, "edge"), a) == 0 && strcmp(str(e1,
			    "edge"), b) == 0)
				far = e1;
			else if (strcmp(str(e1, "edge"), a) == 0 && strcmp(str(e0,
			    "edge"), b) == 0)
				far = e0;
			else
				continue;
			if (str(far, af == AF_INET ? "inner4" : "inner6") == NULL)
				continue;
			if (n++ > 0)
				strlcat(buf, ",", len);
			strlcat(buf, str(far, af == AF_INET ? "inner4" : "inner6"),
			    len);
		}
	}
	return (buf);
}

/*
 * A route to a far prefix over every tunnel to its edge at once: one
 * multipath route, which the kernel shares the flows over.  Not kept in
 * rc.conf (it keeps one gateway); taken away whole, without a gateway,
 * which the host cannot undo by itself: not in safe mode.
 */
static void
route_multi_obj(struct plan *pl, const char *sid, const ucl_object_t *sw,
    const char *prefix, const char *gws, const char *why)
{
	ucl_object_t	*o;
	char		 key[200];
	int64_t		 fib;

	fib = efib(pl, sw, sid);
	snprintf(key, sizeof(key), "route:%jd:%s", (intmax_t)fib, prefix);
	if ((o = object(pl, sid, key, PH_ROUTE, "%s via %s, fib %jd (%s)",
	    prefix, gws, (intmax_t)fib, why)) == NULL)
		return;
	make(o, job("route", "destination", S(prefix), "gateway", S(gws), "fib",
	    I(fib), "persist", B(false), NULL));
	unmake(o, job("route", "destination", S(prefix), "fib", I(fib),
	    "remove", B(true), "persist", B(false), "safe", B(false), NULL));
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
	if (u == NULL && ucl_object_lookup(ep, "remote") != NULL) {
		/* A remote end point's: the identities' addresses. */
		ucl_array_append(out, S(str(ucl_object_lookup(ep, "remote"),
		    "prefix")));
		return;
	}
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
	/* Its CLAT prefix: the IPv4 hosts behind it, as IPv6 (RFC 6877). */
	if (str(ucl_object_lookup(u, "clat"), "prefix") != NULL)
		ucl_array_append(out, S(str(ucl_object_lookup(u, "clat"),
		    "prefix")));
}

/* A route in a table of a service's, made and taken away. */
static void
route_fib_obj(struct plan *pl, const char *sid, const ucl_object_t *sw,
    int64_t fib, int phase, const char *prefix, const char *gw,
    const char *why)
{
	ucl_object_t	*o;
	char		 key[200];

	if (fib == ucl_object_toint(ucl_object_lookup(sw, "fib")))
		snprintf(key, sizeof(key), "route:%s:%s", str(sw, "id"), prefix);
	else
		snprintf(key, sizeof(key), "route:%s:%jd:%s", str(sw, "id"),
		    (intmax_t)fib, prefix);
	if ((o = object(pl, sid, key, phase, "%s via %s, fib %jd (%s)",
	    prefix, gw, (intmax_t)fib, why)) == NULL)
		return;
	make(o, job("route", "destination", S(prefix), "gateway", S(gw), "fib",
	    I(fib), "persist", B(true), NULL));
	unmake(o, job("route", "destination", S(prefix), "gateway", S(gw),
	    "fib", I(fib), "remove", B(true), "persist", B(true), NULL));
}

/* A route in a service's own FIB. */
static void
route_obj(struct plan *pl, const char *sid, const ucl_object_t *sw,
    const char *prefix, const char *gw, const char *why)
{

	route_fib_obj(pl, sid, sw, efib(pl, sw, sid), PH_ROUTE, prefix, gw,
	    why);
}

/*
 * The breakout domain's table (Mplify 119 R25, R26): the edge's own
 * UNIs of the service reachable from it, their subnets by their
 * interfaces and their static routes, so what comes back from the
 * Internet finds the hosts.
 */
static void
breakout_uni_routes(struct plan *pl, const char *sid, const ucl_object_t *sw,
    int64_t fib)
{
	const ucl_object_t	*ep, *u, *v, *e, *r;
	ucl_object_iter_t	 it, sit, rit;
	const char *const	 fams[] = { "ipv4", "ipv6" };
	const char		*ifn;
	char			 ifbuf[32];
	int			 i;

	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		if ((u = ucl_object_lookup(ep, "uni")) == NULL)
			continue;	/* a remote end point */
		ifn = uni_ifname(pl, sw, ep, ifbuf, sizeof(ifbuf));
		for (i = 0; i < 2; i++) {
			v = ucl_object_lookup(u, fams[i]);
			if (str(v, "mode") == NULL || str(v, "prefix") == NULL ||
			    strcmp(str(v, "mode"), "none") == 0 || strcmp(str(v,
			    "mode"), "ll-only") == 0)
				continue;
			route_fib_obj(pl, sid, sw, fib, PH_UNI, str(v, "prefix"),
			    ifn, "the UNI's hosts, in the breakout domain (R25)");
			sit = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(v,
			    "secondary"), &sit, true)) != NULL)
				if (str(e, "prefix") != NULL)
					route_fib_obj(pl, sid, sw, fib, PH_UNI, str(e,
					    "prefix"), ifn, "the UNI's hosts, in the "
					    "breakout domain (R25)");
		}
		rit = NULL;
		while ((r = ucl_object_iterate(ucl_object_lookup(u, "routes"),
		    &rit, true)) != NULL)
			if (str(r, "prefix") != NULL && str(r, "next_hop") != NULL)
				route_fib_obj(pl, sid, sw, fib, PH_UNI, str(r,
				    "prefix"), str(r, "next_hop"), "behind the UNI, "
				    "in the breakout domain (R26)");
	}
}

/* An identity's zone: its group's when it is in one, else its own. */
static const char *
ident_zone(const ucl_object_t *r, const ucl_object_t *id)
{
	const ucl_object_t	*g;

	if (str(id, "group") != NULL && (g = by(ucl_object_lookup(r, "groups"),
	    "name", str(id, "group"))) != NULL && str(g, "zone") != NULL)
		return (str(g, "zone"));
	return (str(id, "zone"));
}

/*
 * The hosts of the remote's prefix a pool covers, as the indexes
 * remote_addr counts by (the last eight bytes count; a remote prefix
 * hands out 65534 at most).
 */
static bool
pool_range(const struct net *n, const char *pool, uint64_t *lo, uint64_t *hi)
{
	struct net	pn;
	uint64_t	base, from;
	int		i, w;

	if (pool == NULL || !net_parse(pool, &pn) || pn.af != n->af)
		return (false);
	w = n->af == AF_INET ? 4 : 16;
	base = from = 0;
	for (i = (w > 8 ? w - 8 : 0); i < w; i++) {
		base = (base << 8) | n->a[i];
		from = (from << 8) | pn.a[i];
	}
	*lo = from - base;
	*hi = *lo + ((pn.len >= (w * 8 - 1)) ? (uint64_t)((w * 8) - pn.len == 1 ?
	    1 : 0) : (1ULL << ((w * 8) - pn.len)) - 1);
	return (true);
}

/* Is a host of the remote's prefix inside some group's pool? */
static bool
host_pooled(const ucl_object_t *r, const struct net *n, uint64_t host)
{
	const ucl_object_t	*g;
	ucl_object_iter_t	 it;
	uint64_t		 lo, hi;

	it = NULL;
	while ((g = ucl_object_iterate(ucl_object_lookup(r, "groups"), &it,
	    true)) != NULL)
		if (pool_range(n, str(g, "pool"), &lo, &hi) && host >= lo &&
		    host <= hi)
			return (true);
	return (false);
}

/*
 * A remote end point's addresses: the edge's own is the
 * prefix's first host; each identity's is kept in the allocations as
 * ident:SWVC/EP/NAME with its host number, so that it keeps it while
 * others come and go, a new one taking the lowest free from the
 * second.
 */
static bool
remote_addr(struct plan *pl, const ucl_object_t *sw, const ucl_object_t *ep,
    const char *name, char *buf, size_t len)
{
	const ucl_object_t	*r, *al, *v, *id, *g;
	ucl_object_iter_t	 it;
	ucl_object_t		*nal;
	struct net		 n;
	const char		*pool;
	char			 key[200], pre[200];
	uint64_t		 host, max, lo, hi;
	bool			 taken;

	r = ucl_object_lookup(ep, "remote");
	if (r == NULL || !net_parse(str(r, "prefix"), &n))
		return (false);
	if (name == NULL) {
		net_nth(&n, 1, buf, len);
		return (true);
	}
	snprintf(pre, sizeof(pre), "ident:%s/%s/", str(sw, "id"), str(ep, "id"));
	snprintf(key, sizeof(key), "%s%s", pre, name);
	if ((al = ucl_object_lookup(pl->alloc, key)) == NULL) {
		max = n.af == AF_INET ? (1ULL << (32 - n.len)) - 2 : 65534;
		/* From its group's pool, when it has one; else from the
		 * second host, outside every pool. */
		lo = 2;
		hi = max;
		pool = NULL;
		id = by(ucl_object_lookup(r, "identities"), "name", name);
		g = id != NULL && str(id, "group") != NULL ? by(ucl_object_lookup(
		    r, "groups"), "name", str(id, "group")) : NULL;
		if (g != NULL && pool_range(&n, str(g, "pool"), &lo, &hi)) {
			pool = str(g, "pool");
			lo = lo < 2 ? 2 : lo;
			hi = hi > max ? max : hi;
		}
		for (host = lo; host <= hi; host++) {
			if (pool == NULL && host_pooled(r, &n, host))
				continue;
			taken = false;
			it = NULL;
			while (!taken && (v = ucl_object_iterate(pl->alloc, &it,
			    true)) != NULL)
				taken = strncmp(ucl_object_key(v), pre, strlen(pre))
				    == 0 && (uint64_t)ucl_object_toint(
				    ucl_object_lookup(v, "host")) == host;
			if (!taken)
				break;
		}
		if (host > hi)
			return (false);
		nal = ucl_object_typed_new(UCL_OBJECT);
		put(nal, "host", I((int64_t)host));
		put(nal, "swvc", S(str(sw, "id")));
		ucl_object_insert_key(pl->alloc, nal, key, 0, true);
		al = nal;
	}
	ucl_object_insert_key(pl->used, B(true), key, 0, true);
	net_nth(&n, (uint64_t)ucl_object_toint(ucl_object_lookup(al, "host")),
	    buf, len);
	return (true);
}

/*
 * Is an identity still authorised: issued within the remote's
 * re-authorisation interval, when it has one?  Not so, it has
 * no peer and no place in the zone table until it is issued again.
 */
static bool
identity_live(const ucl_object_t *r, const ucl_object_t *id, time_t now)
{
	int64_t	issued, reauth;

	if (ucl_object_lookup(r, "reauth") == NULL)
		return (true);
	reauth = ucl_object_toint(ucl_object_lookup(r, "reauth"));
	issued = ucl_object_lookup(id, "issued") != NULL ? ucl_object_toint(
	    ucl_object_lookup(id, "issued")) : 0;
	return (issued + reauth > now);
}

/*
 * A remote end point: its wg interface in the service's table
 * with the edge's own address, listening on its port; each identity a
 * peer allowed its address alone, so that the rules tell it by that
 * address as they do a UNI's host.  An identity gone, or past its
 * re-authorisation, is a peer removed at the next apply.
 */
static bool
remote_obj(struct plan *pl, const ucl_object_t *sw, const ucl_object_t *ep)
{
	const ucl_object_t	*r, *id;
	ucl_object_iter_t	 it;
	ucl_object_t		*o;
	struct net		 n;
	char			 key[200], addr[80], own[80];
	int64_t			 fib, port;
	time_t			 now;

	r = ucl_object_lookup(ep, "remote");
	fib = efib(pl, sw, str(ep, "edge"));
	port = ucl_object_lookup(r, "port") != NULL ? ucl_object_toint(
	    ucl_object_lookup(r, "port")) : WG_REMOTE_PORT;
	if (!net_parse(str(r, "prefix"), &n) || !remote_addr(pl, sw, ep, NULL,
	    own, sizeof(own))) {
		snprintf(pl->why, sizeof(pl->why), "end point %s: its prefix",
		    str(ep, "id"));
		return (false);
	}
	snprintf(key, sizeof(key), "remote:%s", str(ep, "id"));
	o = object(pl, str(ep, "edge"), key, PH_TVC, "remote %s: %s in fib %jd, "
	    "the identities' way in by WireGuard, port %jd", str(ep, "id"),
	    str(r, "interface"), (intmax_t)fib, (intmax_t)port);
	if (o != NULL) {
		snprintf(addr, sizeof(addr), "%s/%d", own, n.len);
		make(o, job("if-create", "interface", S(str(r, "interface")),
		    "fib", I(fib), "description", S("sdwan"), "address", S(addr),
		    "persist", B(true), NULL));
		make(o, job("wireguard", "verb", S("init"), "interface", S(str(r,
		    "interface")), "listen_port", I(port), "persist", B(true),
		    NULL));
		unmake(o, job("if-destroy", "interface", S(str(r, "interface")),
		    "persist", B(true), NULL));
	}
	now = time(NULL);
	it = NULL;
	while ((id = ucl_object_iterate(ucl_object_lookup(r, "identities"), &it,
	    true)) != NULL) {
		if (!remote_addr(pl, sw, ep, str(id, "name"), addr, sizeof(addr))) {
			snprintf(pl->why, sizeof(pl->why), "end point %s: no address "
			    "is left in %s for identity %s", str(ep, "id"), str(r,
			    "prefix"), str(id, "name"));
			return (false);
		}
		if (!identity_live(r, id, now))
			continue;
		snprintf(key, sizeof(key), "ident:%s/%s", str(ep, "id"), str(id,
		    "name"));
		o = object(pl, str(ep, "edge"), key, PH_PEER, "identity %s: a peer "
		    "of %s, %s, zone %s", str(id, "name"), str(r, "interface"),
		    addr, ident_zone(r, id));
		if (o == NULL)
			continue;
		snprintf(own, sizeof(own), "%s/%d", addr, n.af == AF_INET ? 32 :
		    128);
		make(o, job("wireguard", "verb", S("peer"), "interface", S(str(r,
		    "interface")), "peer", S(str(id, "public_key")), "allowed_ips",
		    S(own), "persist", B(true), NULL));
		unmake(o, job("wireguard", "verb", S("unpeer"), "interface", S(str(
		    r, "interface")), "peer", S(str(id, "public_key")), "persist",
		    B(true), NULL));
	}
	return (true);
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
	fib = efib(pl, sw, str(ep, "edge"));
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
	} else if (fib > 0) {
		/* Into the service's table; on an own-table edge it is in
		 * the host's already, and stays. */
		make(o, job("if-set", "interface", S(ifn), "fib", I(fib),
		    "persist", B(true), NULL));
	}
	for (i = 0; i < 2; i++) {
		v = ucl_object_lookup(u, fams[i]);
		/* The provider's addresses go on, whoever addresses the hosts;
		 * not when the host has them already (host_addressed: a
		 * bridge of the host's jails, say). */
		if (str(v, "mode") == NULL || (strcmp(str(v, "mode"), "static")
		    != 0 && strcmp(str(v, "mode"), "dhcp") != 0 && strcmp(str(v,
		    "mode"), "slaac") != 0) || ucl_flag(u, "host_addressed"))
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
	if (vlan == 0 && fib > 0)
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


/* What dnsmasq needs of a UNI's family: the agent renders the rest. */
static const char *const dhcp_keys[] = { "mode", "prefix", "provider",
    "reserved", "lease", "dns", NULL };

/*
 * dnsmasq's form for a service at an edge, which the agent renders
 * (sdconf.c): the service, its table, and its UNIs here addressed by
 * DHCP, each its interface and its families as the service has them.
 */
static ucl_object_t *
dhcp_spec(struct plan *pl, const ucl_object_t *sw, const char *sid)
{
	const ucl_object_t	*ep, *u, *v;
	ucl_object_iter_t	 it;
	ucl_object_t		*spec, *unis, *o;
	char			 vif[32];
	int			 i;
	bool			 dhcp;

	spec = ucl_object_typed_new(UCL_OBJECT);
	put(spec, "service", S(str(sw, "id")));
	put(spec, "fib", I(ucl_object_toint(ucl_object_lookup(sw, "fib"))));
	unis = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		if ((u = ucl_object_lookup(ep, "uni")) == NULL)
			continue;	/* a remote end point */
		dhcp = false;
		for (i = 0; i < 2; i++) {
			v = ucl_object_lookup(u, i == 0 ? "ipv4" : "ipv6");
			if (str(v, "mode") != NULL && strcmp(str(v, "mode"),
			    "dhcp") == 0)
				dhcp = true;
		}
		if (!dhcp)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "id", S(str(u, "id")));
		put(o, "interface", S(uni_ifname(pl, sw, ep, vif, sizeof(vif))));
		for (i = 0; i < 2; i++) {
			v = ucl_object_lookup(u, i == 0 ? "ipv4" : "ipv6");
			if (str(v, "mode") != NULL && strcmp(str(v, "mode"),
			    "dhcp") == 0)
				put(o, i == 0 ? "ipv4" : "ipv6", pick(v, dhcp_keys));
		}
		ucl_array_append(unis, o);
	}
	put(spec, "unis", unis);
	return (spec);
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
	ucl_object_t		*o, *inst, *list;
	char			 name[32];
	const char		*sid;
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
				if ((u = ucl_object_lookup(ep, "uni")) == NULL)
					continue;
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
			put(inst, "fib", I(efib(pl, sw, sid)));
			put(inst, "host", S(server_name_of(sid)));
			put(inst, "spec", dhcp_spec(pl, sw, sid));
			ucl_array_append(list, inst);
		}
		if (ucl_array_size(list) == 0) {
			ucl_object_unref(list);
			continue;
		}
		/*
		 * dnsmasq is a plugin, as BIRD is: installed before, never
		 * by the apply (see plan_needs()).
		 */
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


/* ---- Security functions (MEF 138): ipfw, the base system's unbound,
 * Squid, c-icap; a service an instance ----------------------------------- */

static const ucl_object_t *sec_of(const ucl_object_t *, const ucl_object_t *,
    const char *, int *);
static bool	 remote_addr(struct plan *, const ucl_object_t *,
		    const ucl_object_t *, const char *, char *, size_t);
static const char *uni_ifname(struct plan *, const ucl_object_t *,
		    const ucl_object_t *, char *, size_t);

/*
 * The function policy of a function in a security policy, and its place
 * in the service's list, for the names of its tables and its tag; NULL
 * where the security policy has none.
 */
static const ucl_object_t *
sec_fn(const ucl_object_t *sw, const ucl_object_t *sec, const char *fn,
    int *ip)
{
	const ucl_object_t	*e, *f;
	ucl_object_iter_t	 it, fit;
	int			 i;

	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(sec,
	    "function-policies"), &it, true)) != NULL) {
		i = 0;
		fit = NULL;
		while ((f = ucl_object_iterate(ucl_object_lookup(sw,
		    "security_function_policies"), &fit, true)) != NULL) {
			if (str(f, "id") != NULL && strcmp(str(f, "id"),
			    ucl_object_tostring_forced(e)) == 0 && str(f,
			    "function") != NULL && strcmp(str(f, "function"), fn) ==
			    0) {
				if (ip != NULL)
					*ip = i;
				return (f);
			}
			i++;
		}
	}
	return (NULL);
}

/* The security policy a policy names by af-security-ingress. */
static const ucl_object_t *
sec_in(const ucl_object_t *sw, const char *polname)
{
	const ucl_object_t	*pol;
	const char		*name;

	if (polname == NULL || (pol = by(ucl_object_lookup(sw, "policies"),
	    "name", polname)) == NULL || (name = str(ucl_object_lookup(pol,
	    "criteria"), "af-security-ingress")) == NULL)
		return (NULL);
	return (by(ucl_object_lookup(sw, "security_policies"), "name", name));
}

/*
 * A zone's function policy of a function an edge serves its clients
 * with (dnf, pdns, urlf, mbsf, mdr): as the zone's policies and the end
 * points' maps for it name it; one a zone, as the console checked.
 */
static const ucl_object_t *
zone_fn(const ucl_object_t *sw, const ucl_object_t *zone, const char *fn)
{
	const ucl_object_t	*m, *ep, *f;
	ucl_object_iter_t	 it, eit;

	it = NULL;
	while ((m = ucl_object_iterate(ucl_object_lookup(zone, "policies"),
	    &it, true)) != NULL)
		if ((f = sec_fn(sw, sec_in(sw, str(m, "policy")), fn, NULL)) !=
		    NULL)
			return (f);
	eit = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &eit, true)) != NULL) {
		it = NULL;
		while ((m = ucl_object_iterate(ucl_object_lookup(ep,
		    "policy_map"), &it, true)) != NULL)
			if (str(m, "zone") != NULL && strcmp(str(m, "zone"),
			    str(zone, "name")) == 0 && (f = sec_fn(sw, sec_in(sw,
			    str(m, "ingress")), fn, NULL)) != NULL)
				return (f);
	}
	return (NULL);
}

/* Whether a zone of the service has a function policy of any of fns. */
static bool
svc_fn(const ucl_object_t *sw, const char *const *fns)
{
	const ucl_object_t	*z;
	ucl_object_iter_t	 it;
	size_t			 i;

	it = NULL;
	while ((z = ucl_object_iterate(ucl_object_lookup(sw, "zones"), &it,
	    true)) != NULL)
		for (i = 0; fns[i] != NULL; i++)
			if (zone_fn(sw, z, fns[i]) != NULL)
				return (true);
	return (false);
}

/* Whether a service's flows have a DPF that redirects (the Alter of
 * MEF 138 §6.1): DNS not let through goes to its resolver here. */
static bool
dpf_redirects(const ucl_object_t *sw)
{
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(sw,
	    "security_function_policies"), &it, true)) != NULL)
		if (str(f, "function") != NULL && strcmp(str(f, "function"),
		    "dpf") == 0 && ucl_flag(f, "redirect"))
			return (true);
	return (false);
}

static const char *const fn_dns[] = { "dnf", "pdns", NULL };
static const char *const fn_proxy[] = { "urlf", "mbsf", "mdr", NULL };

/* Whether a name filter's entry has a * inside the name (host.*.tld,
 * R71): unbound, which takes a leading *. alone, has none of it; Squid
 * takes it, at the TLS name and the request's host. */
static bool
dnf_inner(const char *s)
{

	return (s != NULL && strchr(strncmp(s, "*.", 2) == 0 ? s + 2 : s, '*')
	    != NULL);
}

/* A zone's DNF's names with a * inside, its Block's and Quarantine's,
 * which the zone's Squid ends (sdconf.c); NULL for none. */
static ucl_object_t *
zone_dnf_wild(const ucl_object_t *sw, const ucl_object_t *zone)
{
	const ucl_object_t	*f, *e;
	ucl_object_iter_t	 it;
	ucl_object_t		*out;
	int			 k;

	if ((f = zone_fn(sw, zone, "dnf")) == NULL)
		return (NULL);
	out = ucl_object_typed_new(UCL_ARRAY);
	for (k = 0; k < 2; k++) {
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(f, k == 0 ?
		    "block" : "quarantine"), &it, true)) != NULL)
			if (dnf_inner(ucl_object_tostring_forced(e)))
				ucl_array_append(out, S(ucl_object_tostring_forced(
				    e)));
	}
	if (ucl_array_size(out) == 0) {
		ucl_object_unref(out);
		return (NULL);
	}
	return (out);
}

/* Whether a zone's HTTP and TLS go to the service's Squid: its URLF,
 * MBSF or MD+R, or a * inside a name of its DNF's. */
static bool
zone_proxied(const ucl_object_t *sw, const ucl_object_t *zone)
{
	ucl_object_t	*w;
	size_t		 i;

	for (i = 0; fn_proxy[i] != NULL; i++)
		if (zone_fn(sw, zone, fn_proxy[i]) != NULL)
			return (true);
	if ((w = zone_dnf_wild(sw, zone)) == NULL)
		return (false);
	ucl_object_unref(w);
	return (true);
}

/* Whether a zone of the service is. */
static bool
svc_proxied(const ucl_object_t *sw)
{
	const ucl_object_t	*z;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((z = ucl_object_iterate(ucl_object_lookup(sw, "zones"), &it,
	    true)) != NULL)
		if (zone_proxied(sw, z))
			return (true);
	return (false);
}

/* Whether the service has a resolver at its edges: a zone's DNF or
 * PDNS, or a DPF sending DNS to it. */
static bool
svc_resolver(const ucl_object_t *sw)
{

	return (svc_fn(sw, fn_dns) || dpf_redirects(sw));
}

/* Whether a list's entry is a prefix rather than a domain. */
static bool
prefix_like(const char *s)
{

	return (strchr(s, '/') != NULL || strchr(s, ':') != NULL || (isdigit(
	    (unsigned char)s[0]) && strchr(s, '.') != NULL && strpbrk(s,
	    "abcdefghijklmnopqrstuvwxyz") == NULL));
}

/* The order of a function policy's lists: equal entries go to Block
 * (MEF 138 §6.1.6 leaves it), Quarantine blocks too (§6.1.3). */
static const char *const sfl[] = { "block", "quarantine", "allow" };

/*
 * The strings of a function policy's list: its own where own says, then
 * those of the lists it names (feeds or pasted, as kept), domains or
 * prefixes as prefixes says; into out.
 */
static void
sfp_strings(const ucl_object_t *f, const char *list, bool own,
    const ucl_object_t *lists_of, bool prefixes, ucl_object_t *out)
{
	const ucl_object_t	*e, *ln, *le;
	ucl_object_iter_t	 it, lit, eit;
	const char		*s;

	it = NULL;
	while (own && (e = ucl_object_iterate(ucl_object_lookup(f, list), &it,
	    true)) != NULL)
		if (ucl_object_type(e) == UCL_STRING)
			ucl_array_append(out, ucl_object_copy(e));
	lit = NULL;
	while ((ln = ucl_object_iterate(ucl_object_lookup(ucl_object_lookup(f,
	    "lists"), list), &lit, true)) != NULL) {
		eit = NULL;
		while ((le = ucl_object_iterate(at_path(ucl_object_lookup(
		    lists_of, "lists"), ucl_object_tostring_forced(ln),
		    "entries"), &eit, true)) != NULL) {
			s = ucl_object_tostring_forced(le);
			if (prefix_like(s) == prefixes)
				ucl_array_append(out, S(s));
		}
	}
}

/* Whether a function policy tells the matches of a list (R20; Block
 * and Quarantine where it does not say, R21). */
static bool
sfp_notifies(const ucl_object_t *f, const char *list)
{
	const ucl_object_t	*n, *e;
	ucl_object_iter_t	 it;

	if ((n = ucl_object_lookup(f, "notify")) == NULL)
		return (strcmp(list, "allow") != 0);
	it = NULL;
	while ((e = ucl_object_iterate(n, &it, true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(e), list) == 0)
			return (true);
	return (false);
}

/* What the agent renders of a function policy (sdconf.c): its own
 * entries, its No-match and what it tells; the named lists' entries as
 * "listed". */
static const char *const sfp_keys[] = { "no-match", "notify", "block",
    "quarantine", "allow", NULL };
/* And of an MBSF, the versions, the hosts never opened, what of the
 * server's certificate and of HTTP. */
static const char *const mbsf_keys[] = { "no-match", "block", "allow",
    "pass-through", "invalid-server-certificate", "unencrypted", NULL };

/*
 * A function policy as the agent renders it: its keys, and with lists
 * the entries of the named lists it names, of the kind it takes
 * (prefixes or domains), by list ("listed").
 */
static ucl_object_t *
sfp_spec(struct plan *pl, const ucl_object_t *f, const char *const *keys,
    bool lists, bool prefixes)
{
	ucl_object_t	*o, *listed, *a;
	int		 k;

	o = pick(f, keys);
	if (!lists)
		return (o);
	listed = ucl_object_typed_new(UCL_OBJECT);
	for (k = 0; k < 3; k++) {
		a = ucl_object_typed_new(UCL_ARRAY);
		sfp_strings(f, sfl[k], false, pl->lists, prefixes, a);
		if (ucl_array_size(a) > 0)
			put(listed, sfl[k], a);
		else
			ucl_object_unref(a);
	}
	if (ucl_object_lookup(listed, "block") != NULL || ucl_object_lookup(
	    listed, "quarantine") != NULL || ucl_object_lookup(listed,
	    "allow") != NULL)
		put(o, "listed", listed);
	else
		ucl_object_unref(listed);
	return (o);
}

/*
 * The addresses a service's proxy or DNS filter listens on at an edge:
 * each UNI's first IPv4 provider address, and each remote end point's
 * own; into out, one per line as fmt says, with its interface.
 */
static void
edge_own4(struct plan *pl, const ucl_object_t *sw, const char *sid,
    ucl_object_t *out)
{
	const ucl_object_t	*ep, *u, *v, *a;
	ucl_object_iter_t	 it;
	ucl_object_t		*o;
	char			 own[80], ifn[64];

	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		own[0] = '\0';
		if ((u = ucl_object_lookup(ep, "uni")) != NULL) {
			v = ucl_object_lookup(u, "ipv4");
			a = v != NULL && ucl_object_lookup(v, "provider") != NULL ?
			    ucl_array_find_index(ucl_object_lookup(v, "provider"), 0) :
			    NULL;
			if (a != NULL)
				snprintf(own, sizeof(own), "%s",
				    ucl_object_tostring_forced(a));
		} else if (ucl_object_lookup(ep, "remote") != NULL)
			(void)remote_addr(pl, sw, ep, NULL, own, sizeof(own));
		if (own[0] == '\0' || family(own) != AF_INET)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "address", S(own));
		put(o, "interface", S(uni_ifname(pl, sw, ep, ifn, sizeof(ifn))));
		put(o, "end_point", S(str(ep, "id")));
		ucl_array_append(out, o);
	}
}

/*
 * A zone's prefixes at an edge, as its table has them: its own, all of
 * them for Default, and the addresses of its identities at the edge's
 * remote end points; into out.
 */
static void
zone_pfx(struct plan *pl, const ucl_object_t *sw, const char *sid,
    const ucl_object_t *zone, ucl_object_t *out)
{
	const ucl_object_t	*v, *p, *rep, *id;
	ucl_object_iter_t	 it, rit, iit;
	char			 ia[80];

	v = ucl_object_lookup(zone, "prefixes");
	if (ucl_object_type(v) == UCL_STRING) {
		ucl_array_append(out, S("0.0.0.0/0"));
		ucl_array_append(out, S("::/0"));
		return;
	}
	it = NULL;
	while ((p = ucl_object_iterate(v, &it, true)) != NULL)
		ucl_array_append(out, S(ucl_object_tostring_forced(p)));
	rit = NULL;
	while ((rep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &rit, true)) != NULL) {
		if (strcmp(str(rep, "edge"), sid) != 0 || ucl_object_lookup(rep,
		    "remote") == NULL)
			continue;
		iit = NULL;
		while ((id = ucl_object_iterate(ucl_object_lookup(
		    ucl_object_lookup(rep, "remote"), "identities"), &iit, true))
		    != NULL) {
			if (ident_zone(ucl_object_lookup(rep, "remote"), id) ==
			    NULL || strcmp(ident_zone(ucl_object_lookup(rep,
			    "remote"), id), str(zone, "name")) != 0 ||
			    !identity_live(ucl_object_lookup(rep, "remote"), id,
			    time(NULL)) || !remote_addr(pl, sw, rep, str(id,
			    "name"), ia, sizeof(ia)))
				continue;
			snprintf(ia + strlen(ia), sizeof(ia) - strlen(ia), "/%d",
			    family(ia) == AF_INET ? 32 : 128);
			ucl_array_append(out, S(ia));
		}
	}
}

/* Whether a zone is Default: the rest's prefixes are matched first. */
static bool
zone_default(const ucl_object_t *zone)
{

	return (ucl_object_type(ucl_object_lookup(zone, "prefixes")) ==
	    UCL_STRING);
}

/*
 * An end point's own IPv4 address in the service: its UNI's first
 * provider address, or the edge's own at a remote end point; into buf,
 * NULL for none.
 */
static const char *
ep_own4(struct plan *pl, const ucl_object_t *sw, const ucl_object_t *ep,
    char *buf, size_t len)
{
	const ucl_object_t	*pv, *pa;

	pv = ucl_object_lookup(ucl_object_lookup(ep, "uni"), "ipv4");
	pa = pv != NULL ? ucl_array_find_index(ucl_object_lookup(pv,
	    "provider"), 0) : NULL;
	if (pa != NULL) {
		snprintf(buf, len, "%s", ucl_object_tostring_forced(pa));
		return (buf);
	}
	if (ucl_object_lookup(ep, "remote") != NULL && remote_addr(pl, sw, ep,
	    NULL, buf, len) && family(buf) == AF_INET)
		return (buf);
	return (NULL);
}

/*
 * Squid's form for a service at an edge (MEF 138's URLF, MBSF and
 * MD+R), which the agent renders (sdconf.c) as Squid takes it: where it
 * is reached (each UNI's and remote end point's own IPv4 address),
 * whether the service's resolver is here and whether a zone's MD+R
 * scans (c-icap beside it), and its zones with any of them, Default
 * last, each its name, its prefixes here and its function policies as
 * the service has them.  The named lists of a zone's URLF go in
 * *listsp, an object of names (<zone>-allow, <zone>-block) to texts,
 * files of the instance's: its Allow, then its Block and Quarantine
 * together.
 */
static ucl_object_t *
proxy_spec(struct plan *pl, const ucl_object_t *sw, const char *sid,
    ucl_object_t **listsp)
{
	const ucl_object_t	*o, *zone, *uf, *mb, *md, *e;
	ucl_object_iter_t	 it, zit;
	ucl_object_t		*spec, *owns, *listen, *zones, *z, *pfx, *lists;
	ucl_object_t		*hosts, *dw;
	struct buf		*t;
	char			 zn[16], an[40];
	int			 zi, pass, k, n;

	spec = ucl_object_typed_new(UCL_OBJECT);
	put(spec, "flavor", S("sdwan"));
	put(spec, "service", S(str(sw, "id")));
	put(spec, "fib", I(ucl_object_toint(ucl_object_lookup(sw, "fib"))));
	owns = ucl_object_typed_new(UCL_ARRAY);
	edge_own4(pl, sw, sid, owns);
	listen = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((o = ucl_object_iterate(owns, &it, true)) != NULL) {
		z = ucl_object_typed_new(UCL_OBJECT);
		put(z, "end_point", S(str(o, "end_point")));
		put(z, "address", S(str(o, "address")));
		ucl_array_append(listen, z);
	}
	ucl_object_unref(owns);
	put(spec, "listen", listen);
	/* The names it is asked for, resolved by the service's resolver
	 * where there is one, else by the edge's own. */
	if (svc_resolver(sw))
		put(spec, "resolver", B(true));
	if (svc_fn(sw, (const char *const[]){ "mdr", NULL }))
		put(spec, "icap", B(true));
	lists = ucl_object_typed_new(UCL_OBJECT);
	zones = ucl_object_typed_new(UCL_ARRAY);
	/* Each zone with any of them, Default last. */
	for (pass = 0; pass < 2; pass++) {
		zi = -1;
		zit = NULL;
		while ((zone = ucl_object_iterate(ucl_object_lookup(sw, "zones"),
		    &zit, true)) != NULL) {
			zi++;
			if (zone_default(zone) != (pass == 1))
				continue;
			uf = zone_fn(sw, zone, "urlf");
			mb = zone_fn(sw, zone, "mbsf");
			md = zone_fn(sw, zone, "mdr");
			dw = zone_dnf_wild(sw, zone);
			if (uf == NULL && mb == NULL && md == NULL && dw == NULL)
				continue;
			snprintf(zn, sizeof(zn), "z%d", zi);
			z = ucl_object_typed_new(UCL_OBJECT);
			put(z, "name", S(zn));
			/* The DNF's names with a * inside (R71): Squid's. */
			if (dw != NULL)
				put(z, "dnf", dw);
			if (zone_default(zone))
				put(z, "default", B(true));
			else {
				pfx = ucl_object_typed_new(UCL_ARRAY);
				zone_pfx(pl, sw, sid, zone, pfx);
				put(z, "prefixes", pfx);
			}
			if (uf != NULL)
				put(z, "urlf", sfp_spec(pl, uf, sfp_keys, false,
				    false));
			if (mb != NULL)
				put(z, "mbsf", sfp_spec(pl, mb, mbsf_keys, false,
				    false));
			/* MD+R: its hashes, which the agent gives ClamAV as
			 * signatures named by the policy. */
			if (md != NULL) {
				ucl_object_t	*mo;

				mo = sfp_spec(pl, md, sfp_keys, false, false);
				put(mo, "id", S(str(md, "id")));
				put(z, "mdr", mo);
			}
			ucl_array_append(zones, z);
			/* The URLF's named lists: Allow, then Block and
			 * Quarantine together, each a file. */
			for (k = 0; uf != NULL && k < 2; k++) {
				hosts = ucl_object_typed_new(UCL_ARRAY);
				for (n = 0; n < 3; n++)
					if ((n == 2) == (k == 0))
						sfp_strings(uf, sfl[n], false,
						    pl->lists, false, hosts);
				if (ucl_array_size(hosts) > 0) {
					t = buf_alloc(4096);
					it = NULL;
					while ((e = ucl_object_iterate(hosts, &it,
					    true)) != NULL)
						buf_appendf(t, ".%s\n",
						    ucl_object_tostring(e));
					snprintf(an, sizeof(an), "%s-%s", zn, k == 0 ?
					    "allow" : "block");
					ucl_object_insert_key(lists, S(buf_stringify(t,
					    NULL)), an, 0, true);
					buf_free(t);
				}
				ucl_object_unref(hosts);
			}
		}
	}
	put(spec, "zones", zones);
	*listsp = lists;
	return (spec);
}

/*
 * Each edge's proxies: an instance per service whose zones have a URLF,
 * MBSF or MD+R, where the edge has an end point of the service, in the
 * service's table; Squid is a plugin the edge has installed, which the
 * apply tells when it has not, and c-icap with ClamAV beside it where
 * a zone's MD+R scans.
 */
static void
proxy_build(struct plan *pl, const ucl_object_t *doc)
{
	const ucl_object_t	*sw, *edge, *ep;
	ucl_object_iter_t	 it, eit, pit;
	ucl_object_t		*o, *inst, *list, *lists;
	char			 name[32];
	const char		*sid;
	bool			 here, inspect;

	it = NULL;
	while ((edge = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL) {
		sid = str(edge, "server");
		list = ucl_object_typed_new(UCL_ARRAY);
		eit = NULL;
		while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"),
		    &eit, true)) != NULL) {
			if (!svc_proxied(sw))
				continue;
			here = false;
			pit = NULL;
			while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
			    "end_points"), &pit, true)) != NULL)
				if (strcmp(str(ep, "edge"), sid) == 0)
					here = true;
			if (!here)
				continue;
			inspect = svc_fn(sw, (const char *const[]){ "mbsf", NULL });
			snprintf(name, sizeof(name), "sw%jd", (intmax_t)
			    ucl_object_toint(ucl_object_lookup(sw, "fib")));
			inst = ucl_object_typed_new(UCL_OBJECT);
			put(inst, "name", S(name));
			put(inst, "fib", I(efib(pl, sw, sid)));
			put(inst, "mode", S(inspect ? "inspect" : "sni"));
			put(inst, "host", S(server_name_of(sid)));
			put(inst, "spec", proxy_spec(pl, sw, sid, &lists));
			put(inst, "lists", lists);
			ucl_array_append(list, inst);
		}
		if (ucl_array_size(list) == 0) {
			ucl_object_unref(list);
			continue;
		}
		o = object(pl, sid, "proxy", PH_BIRD, "URL filtering, the "
		    "middlebox and malware scanning (MEF 138): Squid (and c-icap "
		    "with ClamAV where malware is scanned), plugins, %u instance%s "
		    "in the services' tables", ucl_array_size(list),
		    ucl_array_size(list) == 1 ? "" : "s");
		if (o == NULL) {
			ucl_object_unref(list);
			continue;
		}
		make(o, job("sdwan-proxy", "instances", list, NULL));
		unmake(o, job("sdwan-proxy", "instances", ucl_object_typed_new(
		    UCL_ARRAY), NULL));
	}
}

/* The divert port of a service's Suricata, where it prevents. */
#define	IDS_PORT(fib)	(8000 + (int)(fib))

/*
 * A service's intrusion detection (the ids criterion, Arcana's
 * own: no MEF Security Function is intrusion detection), as
 * its policies name it: the rules of its own, one a line, each once,
 * whether the ruleset is added, and whether it prevents (one of its
 * policies says prevent).  False when none of its security policies has
 * ids.
 */
static bool
ids_of(const ucl_object_t *sw, struct buf *rules, bool *rulesetp,
    bool *preventp)
{
	const ucl_object_t	*pol, *sec, *ids, *r;
	ucl_object_iter_t	 it, rit;
	ucl_object_t		*seen;
	int			 si, i;
	bool			 any;

	any = false;
	*rulesetp = false;
	if (preventp != NULL)
		*preventp = false;
	seen = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while ((pol = ucl_object_iterate(ucl_object_lookup(sw, "policies"),
	    &it, true)) != NULL)
		for (i = 0; i < 2; i++) {
			sec = sec_of(sw, pol, i == 0 ? "af-security-ingress" :
			    "af-security-egress", &si);
			if (sec == NULL || (ids = ucl_object_lookup(sec, "ids")) ==
			    NULL || ucl_object_type(ids) != UCL_OBJECT)
				continue;
			any = true;
			if (ucl_object_toboolean(ucl_object_lookup(ids, "ruleset")))
				*rulesetp = true;
			if (preventp != NULL && str(ids, "mode") != NULL &&
			    strcmp(str(ids, "mode"), "prevent") == 0)
				*preventp = true;
			rit = NULL;
			while ((r = ucl_object_iterate(ucl_object_lookup(ids,
			    "rules"), &rit, true)) != NULL) {
				if (ucl_object_lookup(seen, ucl_object_tostring(r)) !=
				    NULL)
					continue;
				ucl_object_insert_key(seen, ucl_object_frombool(true),
				    ucl_object_tostring(r), 0, true);
				if (rules != NULL)
					buf_appendf(rules, "%s\n",
					    ucl_object_tostring(r));
			}
		}
	ucl_object_unref(seen);
	return (any);
}

/*
 * A service's instance as its settings, which the agent renders into
 * Suricata's YAML (idsconf.c's SD-WAN shape): its home the UNIs'
 * prefixes, the UNIs' interfaces, the ruleset when the policy says,
 * and oneside where the edge itself answers some of the UNIs' traffic
 * (the URL filter's Squid, malware scanning behind it, the DNS filter)
 * and sees one side of those flows: taken as they come, a packet that
 * looks wrong for want of the other side let by, not dropped.
 */
static ucl_object_t *
ids_spec(const ucl_object_t *sw, const ucl_object_t *ifs, bool ruleset)
{
	const ucl_object_t	*ep, *u, *v;
	ucl_object_iter_t	 it;
	ucl_object_t		*spec, *home;
	int			 i;
	bool			 prevent, rs;

	spec = ucl_object_typed_new(UCL_OBJECT);
	put(spec, "flavor", S("sdwan"));
	put(spec, "service", S(str(sw, "id")));
	home = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if ((u = ucl_object_lookup(ep, "uni")) == NULL)
			continue;
		for (i = 0; i < 2; i++) {
			v = ucl_object_lookup(u, i == 0 ? "ipv4" : "ipv6");
			if (str(v, "prefix") != NULL)
				ucl_array_append(home, S(str(v, "prefix")));
		}
	}
	put(spec, "home", home);
	put(spec, "interfaces", ucl_object_copy(ifs));
	put(spec, "ruleset", ucl_object_frombool(ruleset));
	if (ids_of(sw, NULL, &rs, &prevent) && prevent && (svc_fn(sw,
	    fn_proxy) || svc_proxied(sw) || dpf_redirects(sw)))
		put(spec, "oneside", ucl_object_frombool(true));
	return (spec);
}

/*
 * Each edge's intrusion detection: an instance per service
 * whose policies name a security policy with ids, where the edge has an
 * end point of the service, watching the service's UNIs here; Suricata
 * is a plugin the edge has installed, which the apply tells when it has
 * not.
 */
static void
ids_build(struct plan *pl, const ucl_object_t *doc)
{
	const ucl_object_t	*sw, *edge, *ep;
	ucl_object_iter_t	 it, eit, pit;
	ucl_object_t		*o, *inst, *list, *ifs, *seen;
	struct buf		*rules;
	char			 name[32], ifn[64];
	const char		*sid, *in;
	char			*text;
	bool			 ruleset, prevent, prevents;

	it = NULL;
	while ((edge = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL) {
		sid = str(edge, "server");
		list = ucl_object_typed_new(UCL_ARRAY);
		prevents = false;
		eit = NULL;
		while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"),
		    &eit, true)) != NULL) {
			if (!ids_of(sw, NULL, &ruleset, &prevent))
				continue;
			ifs = ucl_object_typed_new(UCL_ARRAY);
			seen = ucl_object_typed_new(UCL_OBJECT);
			pit = NULL;
			while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
			    "end_points"), &pit, true)) != NULL) {
				if (strcmp(str(ep, "edge"), sid) != 0 || (in =
				    uni_ifname(pl, sw, ep, ifn, sizeof(ifn))) ==
				    NULL || ucl_object_lookup(seen, in) != NULL)
					continue;
				ucl_object_insert_key(seen, ucl_object_frombool(
				    true), in, 0, true);
				ucl_array_append(ifs, S(in));
			}
			ucl_object_unref(seen);
			if (ucl_array_size(ifs) == 0) {
				ucl_object_unref(ifs);
				continue;
			}
			snprintf(name, sizeof(name), "sw%jd", (intmax_t)
			    ucl_object_toint(ucl_object_lookup(sw, "fib")));
			inst = ucl_object_typed_new(UCL_OBJECT);
			put(inst, "name", S(name));
			put(inst, "host", S(server_name_of(sid)));
			put(inst, "spec", ids_spec(sw, ifs, ruleset));
			put(inst, "interfaces", ifs);
			if (prevent) {
				put(inst, "divert", I(IDS_PORT(ucl_object_toint(
				    ucl_object_lookup(sw, "fib")))));
				prevents = true;
			}
			rules = buf_alloc(1024);
			(void)ids_of(sw, rules, &ruleset, NULL);
			text = buf_stringify(rules, NULL);
			put(inst, "rules", S(text));
			buf_free(rules);
			ucl_array_append(list, inst);
		}
		if (ucl_array_size(list) == 0) {
			ucl_object_unref(list);
			continue;
		}
		/* One that prevents runs before the divert rules come, and
		 * stays until they are gone: what is diverted to no one does
		 * not pass. */
		o = object(pl, sid, "ids", prevents ? PH_PROBE : PH_BIRD,
		    "intrusion detection%s: Suricata, a plugin, %u instance%s on "
		    "the services' UNIs", prevents ? " and prevention" : "",
		    ucl_array_size(list), ucl_array_size(list) == 1 ? "" : "s");
		if (o == NULL) {
			ucl_object_unref(list);
			continue;
		}
		make(o, job("sdwan-ids", "instances", list, NULL));
		unmake(o, job("sdwan-ids", "instances", ucl_object_typed_new(
		    UCL_ARRAY), NULL));
	}
}

/* The PDNS of the service whose southbound, northbound and upstream its
 * resolver has: the first a zone has, the console having checked that
 * they agree. */
static const ucl_object_t *
svc_pdns(const ucl_object_t *sw)
{
	const ucl_object_t	*z, *f;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((z = ucl_object_iterate(ucl_object_lookup(sw, "zones"), &it,
	    true)) != NULL)
		if ((f = zone_fn(sw, z, "pdns")) != NULL)
			return (f);
	return (NULL);
}

/* Whether a PDNS carries DNS that way: dot southbound, dot northbound. */
static bool
pdns_says(const ucl_object_t *f, const char *key, const char *how)
{
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;

	if (f == NULL || (v = ucl_object_lookup(f, key)) == NULL)
		return (false);
	if (ucl_object_type(v) != UCL_ARRAY)
		return (strcmp(ucl_object_tostring_forced(v), how) == 0 ||
		    strcmp(ucl_object_tostring_forced(v), "any") == 0);
	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(e), how) == 0 ||
		    strcmp(ucl_object_tostring_forced(e), "any") == 0)
			return (true);
	return (false);
}

/*
 * unbound's form for a service at an edge, which the agent renders
 * (sdconf.c): the UNIs' provider addresses it listens on and the
 * subnets it answers, and each zone with a DNF or PDNS, its name, its
 * prefixes here and its function policies, the named lists' entries
 * with them: domains for the DNF, prefixes for the PDNS; and how the
 * PDNS has DNS carried (D21, D22): "dot", DNS over TLS to the clients
 * too, "upstream", the servers it asks, over TLS where "upstream_tls".
 */
static ucl_object_t *
dns_spec(struct plan *pl, const ucl_object_t *sw, const char *sid)
{
	const ucl_object_t	*ep, *u, *v, *a, *zone, *df, *pd, *sp;
	ucl_object_iter_t	 it, zit;
	ucl_object_t		*spec, *unis, *zones, *z, *pfx;
	char			 zn[16];
	int			 i, zi;

	spec = ucl_object_typed_new(UCL_OBJECT);
	put(spec, "service", S(str(sw, "id")));
	put(spec, "fib", I(ucl_object_toint(ucl_object_lookup(sw, "fib"))));
	sp = svc_pdns(sw);
	if (pdns_says(sp, "southbound", "dot"))
		put(spec, "dot", B(true));
	if (sp != NULL && ucl_array_size(ucl_object_lookup(sp, "upstream")) > 0)
	{
		put(spec, "upstream", ucl_object_copy(ucl_object_lookup(sp,
		    "upstream")));
		if (pdns_says(sp, "northbound", "dot"))
			put(spec, "upstream_tls", B(true));
	}
	unis = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		if ((u = ucl_object_lookup(ep, "uni")) == NULL)
			continue;	/* a remote end point */
		for (i = 0; i < 2; i++) {
			v = ucl_object_lookup(u, i == 0 ? "ipv4" : "ipv6");
			if (str(v, "prefix") == NULL)
				continue;
			a = ucl_array_find_index(ucl_object_lookup(v, "provider"), 0);
			if (a == NULL)
				continue;
			z = ucl_object_typed_new(UCL_OBJECT);
			put(z, "id", S(str(u, "id")));
			put(z, "address", S(ucl_object_tostring_forced(a)));
			put(z, "prefix", S(str(v, "prefix")));
			ucl_array_append(unis, z);
		}
	}
	put(spec, "unis", unis);
	zones = ucl_object_typed_new(UCL_ARRAY);
	zi = -1;
	zit = NULL;
	while ((zone = ucl_object_iterate(ucl_object_lookup(sw, "zones"), &zit,
	    true)) != NULL) {
		zi++;
		df = zone_fn(sw, zone, "dnf");
		pd = zone_fn(sw, zone, "pdns");
		if (df == NULL && pd == NULL)
			continue;
		snprintf(zn, sizeof(zn), "z%d", zi);
		z = ucl_object_typed_new(UCL_OBJECT);
		put(z, "name", S(zn));
		pfx = ucl_object_typed_new(UCL_ARRAY);
		zone_pfx(pl, sw, sid, zone, pfx);
		put(z, "prefixes", pfx);
		if (df != NULL)
			put(z, "dnf", sfp_spec(pl, df, sfp_keys, true, false));
		if (pd != NULL)
			put(z, "pdns", sfp_spec(pl, pd, sfp_keys, true, true));
		ucl_array_append(zones, z);
	}
	put(spec, "zones", zones);
	return (spec);
}

/*
 * Each edge's resolvers: an instance per service with a zone's DNF or
 * PDNS, or a DPF sending DNS to it, where the edge has a UNI of the
 * service, in the service's table.
 */
static void
dns_build(struct plan *pl, const ucl_object_t *doc)
{
	const ucl_object_t	*sw, *edge, *ep;
	ucl_object_iter_t	 it, eit, pit;
	ucl_object_t		*o, *inst, *list;
	char			 name[32];
	const char		*sid;
	bool			 here;

	it = NULL;
	while ((edge = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL) {
		sid = str(edge, "server");
		list = ucl_object_typed_new(UCL_ARRAY);
		eit = NULL;
		while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"),
		    &eit, true)) != NULL) {
			if (!svc_resolver(sw))
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
			put(inst, "fib", I(efib(pl, sw, sid)));
			put(inst, "host", S(server_name_of(sid)));
			put(inst, "spec", dns_spec(pl, sw, sid));
			ucl_array_append(list, inst);
		}
		if (ucl_array_size(list) == 0) {
			ucl_object_unref(list);
			continue;
		}
		o = object(pl, sid, "dns", PH_BIRD, "DNS filtering and protective "
		    "DNS (MEF 138): unbound, %u instance%s in the services' "
		    "tables, a view a zone", ucl_array_size(list),
		    ucl_array_size(list) == 1 ? "" : "s");
		if (o == NULL) {
			ucl_object_unref(list);
			continue;
		}
		make(o, job("sdwan-dns", "instances", list, NULL));
		unmake(o, job("sdwan-dns", "instances", ucl_object_typed_new(
		    UCL_ARRAY), NULL));
	}
}

/* ---- The rules: classification and steering (§8, §9.12, §10.4) ----- */

#define	RULE_IPS	9	/* the diverts to Suricata, before them */
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

/* An ipfw table of a document's named list of prefixes: the prefix,
 * then the list's name. */
#define	NLIST_TABLE	"arcl_"

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
	/* A named list of prefixes: its table, of both families. */
	if ((v = ucl_object_lookup(cr, "src-list")) != NULL)
		snprintf(src, sizeof(src), "table(%s%s)", NLIST_TABLE,
		    ucl_object_tostring_forced(v));
	if ((v = ucl_object_lookup(cr, "dst-list")) != NULL) {
		if (to_table != NULL)
			snprintf(opt + strlen(opt), sizeof(opt) - strlen(opt),
			    " dst-ip table(%s%s)", NLIST_TABLE,
			    ucl_object_tostring_forced(v));
		else
			snprintf(dst, sizeof(dst), "table(%s%s)", NLIST_TABLE,
			    ucl_object_tostring_forced(v));
	}
	if ((v = ucl_object_lookup(cr, "sdst-list")) != NULL)
		snprintf(opt + strlen(opt), sizeof(opt) - strlen(opt),
		    " { src-ip table(%s%s) or dst-ip table(%s%s) }", NLIST_TABLE,
		    ucl_object_tostring_forced(v), NLIST_TABLE,
		    ucl_object_tostring_forced(v));
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

static ucl_object_t	*table(ucl_object_t *, const char *, const char *);
static void		 entry(ucl_object_t *, const char *, const char *);

/* The tables of the named prefix lists an AFS's criteria use, each
 * with the list's prefixes, of both families. */
static void
nlist_tables(struct plan *pl, ucl_object_t *tables, const ucl_object_t *cr)
{
	static const char *const keys[] = { "src-list", "dst-list",
	    "sdst-list" };
	const ucl_object_t	*l, *e;
	ucl_object_iter_t	 it;
	ucl_object_t		*t;
	char			 name[64];
	size_t			 i;

	for (i = 0; i < nitems(keys); i++) {
		if (str(cr, keys[i]) == NULL || (l = by(ucl_object_lookup(
		    pl->doc, "lists"), "name", str(cr, keys[i]))) == NULL)
			continue;
		snprintf(name, sizeof(name), "%s%s", NLIST_TABLE, str(l,
		    "name"));
		if (by(tables, "name", name) != NULL)
			continue;
		t = table(tables, name, "legacy");
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(l, "items"),
		    &it, true)) != NULL)
			entry(t, ucl_object_tostring_forced(e), "0");
	}
}

/* The document's list named in a policy's criterion, or NULL. */
static const ucl_object_t *
pol_list(struct plan *pl, const ucl_object_t *pol, const char *crit)
{
	const char	*name;

	name = str(ucl_object_lookup(pol, "criteria"), crit);
	return (name != NULL ? by(ucl_object_lookup(pl->doc, "lists"), "name",
	    name) : NULL);
}

/* An item of a list, by the string it is or the id it has; NULL else. */
static const ucl_object_t *
list_item(const ucl_object_t *l, const char *s)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while (s != NULL && (e = ucl_object_iterate(ucl_object_lookup(l,
	    "items"), &it, true)) != NULL)
		if ((ucl_object_type(e) == UCL_STRING && strcmp(
		    ucl_object_tostring(e), s) == 0) || (ucl_object_type(e) ==
		    UCL_OBJECT && str(e, "id") != NULL && strcmp(str(e, "id"),
		    s) == 0))
			return (e);
	return (NULL);
}

/*
 * Does a tunnel, from the local end mine, take a way a policy's lists
 * allow: its UCS in ucs-list, its local UCS End Point in
 * ucs-end-point-list?  *prefp: that end point's preference there.
 */
static bool
tunnel_listed(struct plan *pl, const ucl_object_t *t, const ucl_object_t *mine,
    const ucl_object_t *pol, int64_t *prefp)
{
	const ucl_object_t	*l, *e;

	*prefp = 0;
	if ((l = pol_list(pl, pol, "ucs-list")) != NULL && list_item(l, str(t,
	    "ucs")) == NULL)
		return (false);
	if ((l = pol_list(pl, pol, "ucs-end-point-list")) != NULL) {
		if ((e = list_item(l, str(mine, "ucs_ep"))) == NULL)
			return (false);
		if (ucl_object_type(e) == UCL_OBJECT)
			*prefp = ucl_object_toint(ucl_object_lookup(e,
			    "preference"));
	}
	/* The policy naming none: the end point's own preference, the
	 * edge's default order over its uplinks. */
	if (*prefp == 0) {
		const ucl_object_t	*edge, *uep;

		edge = by(ucl_object_lookup(pl->doc, "edges"), "server",
		    str(mine, "edge"));
		uep = by(ucl_object_lookup(edge, "ucs_end_points"), "id",
		    str(mine, "ucs_ep"));
		*prefp = ucl_object_toint(ucl_object_lookup(uep, "preference"));
	}
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
	if (u == NULL && ucl_object_lookup(ep, "remote") != NULL)
		return (str(ucl_object_lookup(ep, "remote"), "interface"));
	if (ucl_object_toint(ucl_object_lookup(u, "vlan")) <= 0)
		return (str(u, "interface"));
	snprintf(key, sizeof(key), "vlan:%s/%s", str(sw, "id"), str(ep, "id"));
	if ((al = ucl_object_lookup(pl->alloc, key)) == NULL) {
		/* Its unit, allocated now and kept; the UNI object finds it. */
		ucl_object_t	*na;
		int64_t		 unit;

		if ((unit = unit_new(pl->alloc)) < 0)
			return (str(u, "interface"));
		na = ucl_object_typed_new(UCL_OBJECT);
		put(na, "unit", I(unit));
		put(na, "swvc", S(str(sw, "id")));
		ucl_object_insert_key(pl->alloc, na, key, 0, true);
		al = na;
	}
	ucl_object_insert_key(pl->used, B(true), key, 0, true);
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
 * Candidates with a preference (a UCS End Point list's) first, the
 * higher first; the order otherwise kept.  Takes cands.
 */
static ucl_object_t *
by_preference(ucl_object_t *cands)
{
	const ucl_object_t	*v[256], *t;
	ucl_object_iter_t	 it;
	ucl_object_t		*out;
	int			 n, i, k;

	n = 0;
	it = NULL;
	while ((v[n] = ucl_object_iterate(cands, &it, true)) != NULL && n <
	    255)
		n++;
	for (i = 1; i < n; i++)
		for (k = i; k > 0 && ucl_object_toint(ucl_object_lookup(v[k],
		    "preference")) > ucl_object_toint(ucl_object_lookup(v[k -
		    1], "preference")); k--) {
			t = v[k];
			v[k] = v[k - 1];
			v[k - 1] = t;
		}
	out = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < n; i++)
		ucl_array_append(out, ucl_object_copy(v[i]));
	ucl_object_unref(cands);
	return (out);
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
	int64_t			 pref;
	int			 af, pass;

	af = fam == 4 ? AF_INET : AF_INET6;
	it = NULL;
	while ((ep2 = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep2, "edge"), str(ep, "edge")) == 0 ||
		    !vt_allows(sw, pol, str(ep, "id"), str(ep2, "id")))
			continue;
		/* The destinations a policy's edge list lets it reach. */
		if (pol_list(pl, pol, "edge-list") != NULL && list_item(
		    pol_list(pl, pol, "edge-list"), str(ep2, "edge")) == NULL)
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
					    != 0 || ucl_flag(t, "control") ||
					    ucl_flag(t, "backup") != (pass == 1) ||
					    !tunnel_fits(t, pol, backup_ok))
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
					if (!tunnel_listed(pl, t, far == e1 ? e0 :
					    e1, pol, &pref))
						continue;
					c = ucl_object_typed_new(UCL_OBJECT);
					put(c, "id", S(str(t, "id")));
					if (pref != 0)
						put(c, "preference", I(pref));
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
			cands = by_preference(cands);
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
	const ucl_object_t	*edge, *uep, *best;
	ucl_object_iter_t	 it, uit;
	int			 far, pass;
	int64_t			 bpref;

	for (pass = 0; pass < 2; pass++) {
		best = NULL;
		bpref = -1;
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
				if (pass == 1 && !edge_transit(pl, str(edge,
				    "server")))
					continue;
				if (pass == 1 && tunnel_for(pl, str(sw, "id"),
				    sid, str(edge, "server"), AF_INET, &far) ==
				    NULL && tunnel_for(pl, str(sw, "id"), sid,
				    str(edge, "server"), AF_INET6, &far) == NULL)
					continue;
				/* Of the edge's own, the one preferred most;
				 * elsewhere the first found. */
				if (pass == 1) {
					*localp = false;
					*bo_sid = str(edge, "server");
					return (uep);
				}
				if (ucl_object_toint(ucl_object_lookup(uep,
				    "preference")) > bpref) {
					bpref = ucl_object_toint(
					    ucl_object_lookup(uep, "preference"));
					best = uep;
					*bo_sid = str(edge, "server");
				}
			}
		}
		if (best != NULL) {
			*localp = true;
			return (best);
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

/*
 * A security policy's rate limit (Arcana's own): a pipe of its own, one per
 * policy of the service; -1 for none or too many.
 */
static int
sec_pipe(struct dn *dn, const ucl_object_t *sw, const ucl_object_t *sec)
{
	const ucl_object_t	*v;
	char			 key[160];
	int			 i;

	v = ucl_object_lookup(sec, "rate-limit");
	if (v == NULL || ucl_object_type(v) != UCL_INT)
		return (-1);
	snprintf(key, sizeof(key), "%s/security/%s", str(sw, "id"), str(sec,
	    "name"));
	for (i = 0; i < dn->nlim; i++)
		if (strcmp(dn->lim[i].key, key) == 0)
			return (dn->lim[i].pipe);
	if (dn->nlim == DN_MAX)
		return (-1);
	snprintf(dn->lim[i].key, sizeof(dn->lim[i].key), "%s", key);
	dn->lim[i].pipe = dn->next++;
	dn->lim[i].commit = dn->lim[i].limit = ucl_object_toint(v);
	dn->lim[i].sum = 0;
	dn->nlim++;
	return (dn->lim[i].pipe);
}

/*
 * The security policy a policy names for a direction, and its place in
 * the service's list (for its tables' names); NULL for none.
 */
static const ucl_object_t *
sec_of(const ucl_object_t *sw, const ucl_object_t *pol, const char *crit,
    int *sip)
{
	const ucl_object_t	*sp;
	ucl_object_iter_t	 it;
	const char		*name;

	*sip = 0;
	if (pol == NULL || (name = str(ucl_object_lookup(pol, "criteria"),
	    crit)) == NULL)
		return (NULL);
	it = NULL;
	while ((sp = ucl_object_iterate(ucl_object_lookup(sw,
	    "security_policies"), &it, true)) != NULL) {
		if (str(sp, "name") != NULL && strcmp(str(sp, "name"), name) == 0)
			return (sp);
		(*sip)++;
	}
	return (NULL);
}

/* A criterion's values as ipfw takes a list: a, b, c. */
static void
vals(const ucl_object_t *v, char *out, size_t len)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	size_t			 n;

	out[0] = '\0';
	if (ucl_object_type(v) != UCL_ARRAY) {
		snprintf(out, len, "%s", ucl_object_tostring_forced(v));
		return;
	}
	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
		n = strlen(out);
		snprintf(out + n, len - n, "%s%s", n > 0 ? "," : "",
		    ucl_object_tostring_forced(e));
	}
}

/*
 * An IPPF or DPF entry (MEF 138 Tables 5, 6) as ipfw options: src-ip,
 * dst-ip, src-port, dst-port, and the protocol the caller is given
 * (proto); its family into *famp (0 for either).
 */
static void
tuple_words(const ucl_object_t *e, const char *proto, char *out, size_t len,
    int *famp)
{
	const ucl_object_t	*v;
	char			 l[600];
	size_t			 n;

	out[0] = '\0';
	*famp = 0;
	if ((v = ucl_object_lookup(e, "sav4")) != NULL ||
	    (v = ucl_object_lookup(e, "sav6")) != NULL) {
		vals(v, l, sizeof(l));
		n = strlen(out);
		snprintf(out + n, len - n, " src-ip %s", l);
	}
	if ((v = ucl_object_lookup(e, "dav4")) != NULL ||
	    (v = ucl_object_lookup(e, "dav6")) != NULL) {
		vals(v, l, sizeof(l));
		n = strlen(out);
		snprintf(out + n, len - n, " dst-ip %s", l);
	}
	if (proto != NULL) {
		n = strlen(out);
		snprintf(out + n, len - n, " proto %s", proto);
	}
	if ((v = ucl_object_lookup(e, "sport")) != NULL) {
		vals(v, l, sizeof(l));
		n = strlen(out);
		snprintf(out + n, len - n, " src-port %s", l);
	}
	if ((v = ucl_object_lookup(e, "dport")) != NULL) {
		vals(v, l, sizeof(l));
		n = strlen(out);
		snprintf(out + n, len - n, " dst-port %s", l);
	}
	if (ucl_object_lookup(e, "sav4") != NULL || ucl_object_lookup(e,
	    "dav4") != NULL || ucl_object_lookup(e, "protv4") != NULL)
		*famp = 4;
	else if (ucl_object_lookup(e, "sav6") != NULL || ucl_object_lookup(e,
	    "dav6") != NULL || ucl_object_lookup(e, "nextheadv6") != NULL)
		*famp = 6;
	if (*famp != 0 && ucl_object_lookup(e, "sav4") == NULL &&
	    ucl_object_lookup(e, "dav4") == NULL && ucl_object_lookup(e,
	    "sav6") == NULL && ucl_object_lookup(e, "dav6") == NULL) {
		n = strlen(out);
		snprintf(out + n, len - n, " ipversion %d", *famp);
	}
}

/* How specific an IPPF or DPF entry is (§6.1.6): its prefixes' lengths
 * (the shortest of a list), a port given, a protocol given. */
static int
tuple_specific(const ucl_object_t *e)
{
	static const char *const addrs[] = { "sav4", "dav4", "sav6", "dav6" };
	const ucl_object_t	*v, *x;
	ucl_object_iter_t	 it;
	const char		*sl;
	int			 n, i, len, min;

	n = 0;
	for (i = 0; i < 4; i++) {
		if ((v = ucl_object_lookup(e, addrs[i])) == NULL)
			continue;
		min = 128;
		it = NULL;
		while ((x = ucl_object_iterate(v, &it, true)) != NULL) {
			sl = strchr(ucl_object_tostring_forced(x), '/');
			len = sl != NULL ? atoi(sl + 1) : i % 2 == 0 && i < 2 ?
			    32 : i < 2 ? 32 : 128;
			if (len < min)
				min = len;
		}
		n += min;
	}
	if (ucl_object_lookup(e, "sport") != NULL)
		n += 16;
	if (ucl_object_lookup(e, "dport") != NULL)
		n += 16;
	if (ucl_object_lookup(e, "protv4") != NULL || ucl_object_lookup(e,
	    "nextheadv6") != NULL)
		n += 8;
	return (n);
}

struct tentry {
	const ucl_object_t	*e;
	int			 list;	/* sfl's */
	int			 spec;
};

static int
tentry_cmp(const void *a, const void *b)
{
	const struct tentry	*x = a, *y = b;

	if (x->spec != y->spec)
		return (y->spec - x->spec);
	return (x->list - y->list);
}

/* A function policy's entries in the order they are tried. */
static struct tentry *
tuple_order(const ucl_object_t *f, size_t *np)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct tentry		*t;
	size_t			 n;
	int			 k;

	n = 0;
	for (k = 0; k < 3; k++)
		n += ucl_object_lookup(f, sfl[k]) != NULL ? ucl_array_size(
		    ucl_object_lookup(f, sfl[k])) : 0;
	t = xcalloc(n + 1, sizeof(*t));
	n = 0;
	for (k = 0; k < 3; k++) {
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(f, sfl[k]), &it,
		    true)) != NULL) {
			t[n].e = e;
			t[n].list = k;
			t[n].spec = tuple_specific(e);
			n++;
		}
	}
	qsort(t, n, sizeof(*t), tentry_cmp);
	*np = n;
	return (t);
}

/*
 * A flow's IPPF (MEF 138 §8.1), as its security policy has one: the
 * function policy's entries most specific first, an Allow tagging the
 * packet (count tag, a tag the function policy's own), a Block or a
 * Quarantine dropping what is not tagged; then the named lists'
 * prefixes, to or from, in a table of the policy's a family with the
 * list as the value (1 Block, 2 Quarantine, 3 Allow), its longest match
 * deciding; then, where its No-match blocks, the rest of the flow
 * dropped.  What a list's notify says is told (logdst rtsock, read by
 * the agent into its record), the No-match's always (R24), each rule's
 * comment naming the service, the function policy and the list.  The
 * tail is what ends each rule: where it comes in, or goes out.
 */
static void
ippf_rules(ucl_object_t *tables, ucl_object_t *rules, int num,
    const ucl_object_t *sw, const ucl_object_t *sec, const ucl_object_t *cr,
    const char *appid, const char *tail, const ucl_object_t *lists_of)
{
	static const char *const vals3[] = { "1", "2", "3" };
	const ucl_object_t	*f, *pv, *p;
	ucl_object_iter_t	 it, pit;
	ucl_object_t		*seen, *pfx;
	struct tentry		*t;
	char			 flow[2000], ew[1600], tbl[64], logw[64];
	size_t			 n, i;
	int			 fi, tag, fam, f2, k, ef;

	if ((f = sec_fn(sw, sec, "ippf", &fi)) == NULL)
		return;
	tag = 1 + fi;
	if (!afs_words(cr, NULL, appid, flow, sizeof(flow), &f2))
		return;
	t = tuple_order(f, &n);
	for (i = 0; i < n; i++) {
		const ucl_object_t	*pr;
		char			 one[16];

		pr = ucl_object_lookup(t[i].e, "protv4") != NULL ?
		    ucl_object_lookup(t[i].e, "protv4") : ucl_object_lookup(
		    t[i].e, "nextheadv6");
		/* A rule a protocol where the entry names several. */
		pit = NULL;
		do {
			p = pr != NULL ? ucl_object_iterate(pr, &pit, true) : NULL;
			if (pr != NULL && p == NULL)
				break;
			snprintf(one, sizeof(one), "%s", p != NULL ?
			    ucl_object_tostring_forced(p) : "");
			tuple_words(t[i].e, p != NULL ? one : NULL, ew, sizeof(ew),
			    &ef);
			if (ef != 0 && f2 != 0 && ef != f2)
				break;
			if (t[i].list == 2)
				rule(rules, num, "count tag %d %s%s%s", tag, flow, ew,
				    tail);
			else
				rule(rules, num, "deny%s %s%s not tagged %d%s // "
				    "security %.30s %.30s %s", sfp_notifies(f,
				    sfl[t[i].list]) ? " log logdst rtsock logamount "
				    "1000" : "", flow, ew, tag, tail, str(sw, "id"),
				    str(f, "id"), sfl[t[i].list]);
		} while (pr != NULL);
	}
	free(t);
	/* The named lists' prefixes: a table a family, each prefix once,
	 * Block before Quarantine before Allow. */
	for (fam = 4; fam <= 6; fam += 2) {
		bool	fresh, has[3] = { false, false, false };

		if (f2 != 0 && f2 != fam)
			continue;
		snprintf(tbl, sizeof(tbl), "sw%jd_f%dv%d", (intmax_t)
		    ucl_object_toint(ucl_object_lookup(sw, "fib")), fi, fam);
		fresh = by(tables, "name", tbl) == NULL;
		seen = ucl_object_typed_new(UCL_OBJECT);
		for (k = 0; k < 3; k++) {
			pfx = ucl_object_typed_new(UCL_ARRAY);
			sfp_strings(f, sfl[k], false, lists_of, true, pfx);
			it = NULL;
			while ((pv = ucl_object_iterate(pfx, &it, true)) != NULL) {
				const char *ps = ucl_object_tostring(pv);

				if ((strchr(ps, ':') != NULL) != (fam == 6) ||
				    ucl_object_lookup(seen, ps) != NULL)
					continue;
				ucl_object_insert_key(seen, ucl_object_frombool(
				    true), ps, 0, true);
				if (fresh)
					entry(table(tables, tbl, "legacy"), ps,
					    vals3[k]);
				has[k] = true;
			}
			ucl_object_unref(pfx);
		}
		ucl_object_unref(seen);
		if (has[2]) {
			rule(rules, num, "count tag %d %s dst-ip table(%s,3)%s",
			    tag, flow, tbl, tail);
			rule(rules, num, "count tag %d %s src-ip table(%s,3)%s",
			    tag, flow, tbl, tail);
		}
		for (k = 0; k < 2; k++) {
			if (!has[k])
				continue;
			snprintf(logw, sizeof(logw), "%s", sfp_notifies(f,
			    sfl[k]) ? " log logdst rtsock logamount 1000" : "");
			rule(rules, num, "deny%s %s dst-ip table(%s,%s) not tagged "
			    "%d%s // security %.30s %.30s %s", logw, flow, tbl,
			    vals3[k], tag, tail, str(sw, "id"), str(f, "id"),
			    sfl[k]);
			rule(rules, num, "deny%s %s src-ip table(%s,%s) not tagged "
			    "%d%s // security %.30s %.30s %s", logw, flow, tbl,
			    vals3[k], tag, tail, str(sw, "id"), str(f, "id"),
			    sfl[k]);
		}
	}
	if (strcmp(str(f, "no-match"), "block") == 0)
		rule(rules, num, "deny log logdst rtsock logamount 1000 %s not "
		    "tagged %d%s // security %.30s %.30s no-match", flow, tag, tail,
		    str(sw, "id"), str(f, "id"));
}

/*
 * A flow's DPF (MEF 138 §8.6.1), as its security policy has one: DNS of
 * the flow (UDP and TCP 53, TCP 853 for DNS over TLS) not to the edge
 * itself, by the function policy's entries most specific first, an
 * Allow tagging it, a Block or Quarantine answered at once (R100: port
 * unreachable); the rest, where its No-match blocks, the
 * same, or, where it redirects (Arcana's: MEF 138's Alter), sent to
 * the service's resolver on the edge (resolver, its address there).
 * An entry's message-type (Table 6) is what ipfw tells of a DNS
 * message by its ports: a query goes to port 53, a response comes from
 * it; any is both.  Updates and the rest are inside the message, which
 * ipfw does not read.
 */
static void
dpf_rules(ucl_object_t *rules, int num, const ucl_object_t *sw,
    const ucl_object_t *sec, const ucl_object_t *cr, const char *appid,
    const char *tail, const char *resolver)
{
	/* Port unreachable for TCP too: it ends the connection's attempt
	 * as a reset would, and the agent takes no rule with "set" in it. */
	static const struct { const char *proto, *rej; int port; } dns[] = {
		{ "udp", "unreach port", 53 },
		{ "tcp", "unreach port", 53 },
		{ "tcp", "unreach port", 853 },
	};
	/* A query to the port, not for the edge; a response from it, not
	 * the edge's own resolver's. */
	static const struct { const char *name, *port, *me; } way[] = {
		{ "query", "dst-port", "not dst-ip me" },
		{ "response", "src-port", "not src-ip me" },
	};
	const ucl_object_t	*f;
	struct tentry		*t;
	char			 flow[2000], ew[1600];
	const char		*mt;
	size_t			 n, i, d, m;
	int			 fi, tag, f2, ef;

	if ((f = sec_fn(sw, sec, "dpf", &fi)) == NULL)
		return;
	tag = 1 + fi;
	if (!afs_words(cr, NULL, appid, flow, sizeof(flow), &f2))
		return;
	t = tuple_order(f, &n);
	for (d = 0; d < nitems(dns); d++) {
		for (i = 0; i < n; i++) {
			tuple_words(t[i].e, dns[d].proto, ew, sizeof(ew), &ef);
			if (ef != 0 && f2 != 0 && ef != f2)
				continue;
			mt = str(t[i].e, "message-type") != NULL ? str(t[i].e,
			    "message-type") : "any";
			for (m = 0; m < nitems(way); m++) {
				if (strcmp(mt, "any") != 0 && strcmp(mt, way[m].name)
				    != 0)
					continue;
				if (t[i].list == 2)
					rule(rules, num, "count tag %d %s%s %s %d %s%s",
					    tag, flow, ew, way[m].port, dns[d].port,
					    way[m].me, tail);
				else
					rule(rules, num, "%s%s %s%s %s %d %s not tagged "
					    "%d%s // security %.30s %.30s %s", dns[d].rej,
					    sfp_notifies(f, sfl[t[i].list]) ? " log logdst "
					    "rtsock logamount 1000" : "", flow, ew,
					    way[m].port, dns[d].port, way[m].me, tag, tail,
					    str(sw, "id"), str(f, "id"), sfl[t[i].list]);
			}
		}
		if (strcmp(str(f, "no-match"), "block") != 0)
			continue;
		for (m = 0; m < nitems(way); m++) {
			if (m == 0 && ucl_flag(f, "redirect") && resolver != NULL &&
			    dns[d].port == 53 && f2 != 6)
				rule(rules, num, "fwd %s,53 %s ipversion 4 proto %s "
				    "dst-port 53 not dst-ip me not tagged %d%s", resolver,
				    flow, dns[d].proto, tag, tail);
			else
				rule(rules, num, "%s log logdst rtsock logamount 1000 %s "
				    "proto %s %s %d %s not tagged %d%s // security %.30s "
				    "%.30s no-match", dns[d].rej, flow, dns[d].proto,
				    way[m].port, dns[d].port, way[m].me, tag, tail,
				    str(sw, "id"), str(f, "id"));
		}
	}
	free(t);
}

/* The flows an application names: the one of the name, or a group's. */
static bool
app_has(const ucl_object_t *afs, const char *app)
{

	return (app != NULL && ((str(afs, "name") != NULL && strcmp(str(afs,
	    "name"), app) == 0) || (str(afs, "group") != NULL && strcmp(str(
	    afs, "group"), app) == 0)));
}

/*
 * What a tunnel's kind takes off the outer MTU: its own header (gre
 * 24 with its key, gif 20, geneve 50, wg 60, uswe 73), IPsec's 64 when
 * ESP is under it, and 20 more when the outer packets are IPv6.
 */
static int
tunnel_overhead(const ucl_object_t *t, const ucl_object_t *end)
{
	const char	*kind;
	int		 over;

	kind = str(t, "kind") != NULL ? str(t, "kind") : "gre";
	over = strcmp(kind, "gif") == 0 ? 20 : strcmp(kind, "geneve") == 0 ?
	    50 : strcmp(kind, "wg") == 0 ? 60 : strcmp(kind, "uswe") == 0 ? 73 :
	    24;
	if (ucl_flag(t, "ipsec"))
		over += 64;
	if (str(end, "underlay") != NULL && strchr(str(end, "underlay"), ':')
	    != NULL)
		over += 20;
	return (over);
}

/*
 * The MTU a tunnel's interface is made with: the UCS's tunnel.mtu in
 * bytes, or with auto 1500 less the overhead (an underlay of 1500 is
 * what the Internet gives); 0 when none is set, the kernel's default.
 * Both ends of a tunnel have the same kind and outer family, so both
 * compute the same.
 */
static int
tunnel_mtu(const ucl_object_t *doc, const ucl_object_t *t,
    const ucl_object_t *end)
{
	const ucl_object_t	*u, *tt, *v;

	if ((u = by(ucl_object_lookup(doc, "ucs"), "id", str(t, "ucs"))) ==
	    NULL || (tt = ucl_object_lookup(u, "tunnel")) == NULL ||
	    (v = ucl_object_lookup(tt, "mtu")) == NULL)
		return (0);
	if (ucl_object_type(v) == UCL_INT)
		return ((int)ucl_object_toint(v));
	return (1500 - tunnel_overhead(t, end));
}

/*
 * The MSS to clamp TCP to on a tunnel of a UCS, for a family: what
 * its tunnel entry says, or for auto 1500 less the tunnel's overhead
 * (gre 24, gif 20, geneve 50, wg 60, uswe 73), IPsec's 64 under gre,
 * gif and geneve, and 20 more over an IPv6 underlay, less the inner
 * headers (40 for IPv4, 60 for IPv6); 0 when none is to be clamped.
 */
static int
tunnel_mss(const ucl_object_t *doc, const ucl_object_t *t,
    const ucl_object_t *end, int fam)
{
	const ucl_object_t	*u, *tt, *v;
	int			 mtu;

	if ((u = by(ucl_object_lookup(doc, "ucs"), "id", str(t, "ucs"))) ==
	    NULL || (tt = ucl_object_lookup(u, "tunnel")) == NULL ||
	    (v = ucl_object_lookup(tt, "mss")) == NULL)
		return (0);
	if (ucl_object_type(v) == UCL_INT)
		return ((int)ucl_object_toint(v));
	/* auto: from the tunnel's MTU, set or computed, less the headers. */
	if ((mtu = tunnel_mtu(doc, t, end)) == 0)
		mtu = 1500 - tunnel_overhead(t, end);
	return (mtu - (fam == 6 ? 60 : 40));
}

/*
 * tcp-setmss rules for the service's tunnels at the edge, each family
 * its own (ipfw_pmod: the search goes on after them); true when any,
 * so that the module is loaded.
 */
static bool
mss_rules(struct plan *pl, const ucl_object_t *sw, const char *sid,
    ucl_object_t *rules)
{
	const ucl_object_t	*t, *e;
	ucl_object_iter_t	 it, eit;
	int			 m;
	bool			 any;

	any = false;
	it = NULL;
	while ((t = ucl_object_iterate(pl->tunnels, &it, true)) != NULL) {
		if (strcmp(str(t, "swvc"), str(sw, "id")) != 0 || ucl_flag(t,
		    "control"))
			continue;
		eit = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(t, "ends"),
		    &eit, true)) != NULL) {
			if (strcmp(str(e, "edge"), sid) != 0 || str(e, "ifname")
			    == NULL)
				continue;
			if ((m = tunnel_mss(pl->doc, t, e, 4)) > 0) {
				rule(rules, RULE_FROM, "tcp-setmss %d tcp from any "
				    "to any via %s tcpflags syn ip4", m, str(e,
				    "ifname"));
				any = true;
			}
			if ((m = tunnel_mss(pl->doc, t, e, 6)) > 0) {
				rule(rules, RULE_FROM, "tcp-setmss %d tcp from any "
				    "to any via %s tcpflags syn ip6", m, str(e,
				    "ifname"));
				any = true;
			}
		}
	}
	return (any);
}

/* The tunnel interfaces of the service at the edge, as xmit words: the
 * data tunnels', not the control plane's own. */
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
		if (strcmp(str(t, "swvc"), str(sw, "id")) != 0 || ucl_flag(t,
		    "control"))
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
 * The groups of a remote end point: a table each of its live
 * members' addresses, and the members of two groups neither of which
 * reaches the other kept apart, both ways, before the zone table
 * sends anyone on.
 */
static void
group_rules(struct plan *pl, const ucl_object_t *sw, const ucl_object_t *ep,
    ucl_object_t *tables, ucl_object_t *rules, const char *uni)
{
	const ucl_object_t	*r, *gs, *g, *h, *id, *e;
	ucl_object_iter_t	 it, it2, iit;
	ucl_object_t		*t;
	char			 name[64], other[64], ia[80];
	int64_t			 fib;
	int			 i, j;
	bool			 meet;

	r = ucl_object_lookup(ep, "remote");
	if ((gs = ucl_object_lookup(r, "groups")) == NULL)
		return;
	fib = ucl_object_toint(ucl_object_lookup(sw, "fib"));
	i = 0;
	it = NULL;
	while ((g = ucl_object_iterate(gs, &it, true)) != NULL) {
		snprintf(name, sizeof(name), "sw%jd_g%d", (intmax_t)fib, i++);
		t = table(tables, name, "legacy");
		iit = NULL;
		while ((id = ucl_object_iterate(ucl_object_lookup(r, "identities"),
		    &iit, true)) != NULL) {
			if (str(id, "group") == NULL || strcmp(str(id, "group"),
			    str(g, "name")) != 0 || !identity_live(r, id, time(NULL))
			    || !remote_addr(pl, sw, ep, str(id, "name"), ia,
			    sizeof(ia)))
				continue;
			snprintf(ia + strlen(ia), sizeof(ia) - strlen(ia), "/%d",
			    family(ia) == AF_INET ? 32 : 128);
			entry(t, ia, "0");
		}
	}
	i = 0;
	it = NULL;
	while ((g = ucl_object_iterate(gs, &it, true)) != NULL) {
		j = 0;
		it2 = NULL;
		while ((h = ucl_object_iterate(gs, &it2, true)) != NULL) {
			if (j++ <= i)
				continue;
			/* Either reaching the other: they meet. */
			meet = false;
			iit = NULL;
			while (!meet && (e = ucl_object_iterate(ucl_object_lookup(g,
			    "reach"), &iit, true)) != NULL)
				meet = strcmp(ucl_object_tostring(e), str(h, "name"))
				    == 0;
			iit = NULL;
			while (!meet && (e = ucl_object_iterate(ucl_object_lookup(h,
			    "reach"), &iit, true)) != NULL)
				meet = strcmp(ucl_object_tostring(e), str(g, "name"))
				    == 0;
			if (meet)
				continue;
			snprintf(name, sizeof(name), "sw%jd_g%d", (intmax_t)fib, i);
			snprintf(other, sizeof(other), "sw%jd_g%d", (intmax_t)fib,
			    j - 1);
			rule(rules, RULE_FROM, "deny ip from table(%s) to table(%s) "
			    "in recv %s", name, other, uni);
			rule(rules, RULE_FROM, "deny ip from table(%s) to table(%s) "
			    "in recv %s", other, name, uni);
		}
		i++;
	}
}

/* A kernel module loaded and kept on an edge, once (an object key). */
static void
kmod_obj(struct plan *pl, const char *sid, const char *key, const char *module,
    const char *what)
{
	ucl_object_t	*ko, *ka;

	if (by(ucl_object_lookup(pl->edges, sid), "key", key) != NULL)
		return;
	ko = object(pl, sid, key, PH_FIBS, "%s loaded and kept, for %s", module,
	    what);
	if (ko == NULL)
		return;
	put(ko, "make", ucl_object_typed_new(UCL_ARRAY));
	ka = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(ka, S(module));
	make(ko, job("kmod", "verb", S("load"), "args", ka, NULL));
	ka = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(ka, S(module));
	make(ko, job("kmod", "verb", S("keep"), "args", ka, NULL));
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
	const ucl_object_t	*sw, *ep, *zone, *afs, *pol, *v, *bo, *r, *sec;
	const ucl_object_t	*n64;
	char			 n64n[32];
	ucl_object_iter_t	 it, eit, zit, ait;
	ucl_object_t		*o, *tables, *rules, *entries, *zt, *j, *pre;
	ucl_object_t		*objects, *kt;
	struct dn		*dn;
	char			 ifn[32], tname[64], zname[64], words[2000];
	char			 key[200], kname[64], zp[64], xmit[1200], own[1200];
	char			 host[64], note[400], tail[120];
	const char		*uni, *pname, *bo_sid, *bif;
	int			 next, zi, pi, fam, nuni, k, lim, q, nat, si, rp;
	bool			 any, multi, local, breaks;
	bool			 mss_done = false;

	tables = ucl_object_typed_new(UCL_ARRAY);
	rules = ucl_object_typed_new(UCL_ARRAY);
	pre = ucl_object_typed_new(UCL_ARRAY);
	entries = ucl_object_typed_new(UCL_ARRAY);
	objects = ucl_object_typed_new(UCL_ARRAY);
	if ((dn = calloc(1, sizeof(*dn))) == NULL)
		return (false);
	/*
	 * A relay's own flow (its process on this host, in the first
	 * table, reaching the far underlay at the relay's port) goes by
	 * the underlay's table like the tunnel's outer packets would.
	 */
	{
		const ucl_object_t	*redge, *ue, *rl, *fe, *fu;
		ucl_object_iter_t	 reit, rrit, rfit;
		const char		*rfar;

		redge = by(ucl_object_lookup(pl->doc, "edges"), "server", sid);
		reit = NULL;
		while ((ue = ucl_object_iterate(ucl_object_lookup(redge,
		    "ucs_end_points"), &reit, true)) != NULL) {
			if (ucl_object_lookup(ue, "vrf") == NULL)
				continue;
			rrit = NULL;
			while ((rl = ucl_object_iterate(ucl_object_lookup(ue,
			    "relay"), &rrit, true)) != NULL) {
				fe = by(ucl_object_lookup(pl->doc, "edges"),
				    "server", str(rl, "to"));
				rfit = NULL;
				rfar = NULL;
				while (rfar == NULL && (fu = ucl_object_iterate(
				    ucl_object_lookup(fe, "ucs_end_points"), &rfit,
				    true)) != NULL)
					if (str(fu, "ucs") != NULL && strcmp(str(fu,
					    "ucs"), str(ue, "ucs")) == 0)
						rfar = ucs_address(pl, str(rl, "to"),
						    fu);
				if (rfar != NULL)
					rule(pre, RULE_FROM + 1, "setfib %jd udp from "
					    "me to %s dst-port %jd out",
					    (intmax_t)ucl_object_toint(
					    ucl_object_lookup(ue, "vrf")), rfar,
					    (intmax_t)ucl_object_toint(
					    ucl_object_lookup(rl, "port")));
			}
		}
	}
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
			/* TCP's MSS clamped on the tunnels, once an edge. */
			if (!mss_done && mss_rules(pl, sw, sid, rules)) {
				ucl_object_t	*ko, *ka;

				ko = (ucl_object_t *)(uintptr_t)by(
				    ucl_object_lookup(pl->edges, sid), "key",
				    "pmod");
				if (ko == NULL) {
					ko = object(pl, sid, "pmod", PH_FIBS,
					    "ipfw_pmod loaded and kept, for "
					    "tcp-setmss");
					put(ko, "make", ucl_object_typed_new(
					    UCL_ARRAY));
					ka = ucl_object_typed_new(UCL_ARRAY);
					ucl_array_append(ka, S("ipfw_pmod"));
					make(ko, job("kmod", "verb", S("load"),
					    "args", ka, NULL));
					ka = ucl_object_typed_new(UCL_ARRAY);
					ucl_array_append(ka, S("ipfw_pmod"));
					make(ko, job("kmod", "verb", S("keep"),
					    "args", ka, NULL));
				}
				mss_done = true;
			}
			/*
			 * Intrusion prevented (ids, prevent): IPv4 that
			 * comes in at the UNI, and that comes in elsewhere for
			 * the UNI's subnet, to the service's Suricata first,
			 * which gives back what it lets by.  Both are taken as
			 * they come in, not as they go out to the UNI: divert(4)
			 * gives back what it takes in routing table 0 (a
			 * PF_DIVERT socket has no table of its own), and one
			 * given back on its way out is routed there before ipfw
			 * sees it again, while one given back on its way in is
			 * put back in the service's table by the rules that
			 * follow.  divert resumes at the next rule number: the
			 * diverts are one before the way in.
			 */
			{
				const ucl_object_t	*pv;
				const char		*pfx[2];
				bool			 rs, prevent;
				int			 port, np, x;

				if (ids_of(sw, NULL, &rs, &prevent) && prevent) {
					port = IDS_PORT(ucl_object_toint(
					    ucl_object_lookup(sw, "fib")));
					np = 0;
					pv = ucl_object_lookup(ucl_object_lookup(ep,
					    "uni"), "ipv4");
					if (str(pv, "prefix") != NULL)
						pfx[np++] = str(pv, "prefix");
					pv = ucl_object_lookup(ep, "remote");
					if (str(pv, "prefix") != NULL && strchr(str(pv,
					    "prefix"), ':') == NULL)
						pfx[np++] = str(pv, "prefix");
					rule(rules, RULE_IPS, "divert %d ip4 from any to "
					    "any in recv %s", port, uni);
					/* Not what is for the edge itself: what
					 * it sends back is not seen, and a flow
					 * seen half from this side is cut. */
					for (x = 0; x < np; x++)
						rule(rules, RULE_IPS, "divert %d ip4 from "
						    "any to %s in not recv %s not dst-ip me",
						    port, pfx[x], uni);
					rule(rules, RULE_FROM, "setfib %jd ip4 from any "
					    "to any in recv %s diverted-loopback",
					    (intmax_t)efib(pl, sw, sid), uni);
					for (x = 0; x < np; x++)
						rule(rules, RULE_FROM, "setfib %jd ip4 from "
						    "any to %s in diverted-loopback not dst-ip "
						    "me",
						    (intmax_t)ucl_object_toint(
						    ucl_object_lookup(sw, "fib")), pfx[x]);
				}
			}
			/* HTTP and TLS to the proxy (MEF 138's URLF, MBSF,
			 * MD+R), on the edge's own address there, from the
			 * zones that have them, each by its table. */
			{
				const ucl_object_t	*pz;
				ucl_object_iter_t	 pzit;
				char			 pown[80];
				const char		*at;
				int			 pzi;

				at = ep_own4(pl, sw, ep, pown, sizeof(pown));
				pzi = -1;
				pzit = NULL;
				while (at != NULL && (pz = ucl_object_iterate(
				    ucl_object_lookup(sw, "zones"), &pzit, true)) !=
				    NULL) {
					pzi++;
					if (!zone_proxied(sw, pz))
						continue;
					rule(rules, RULE_FROM, "fwd %s,3128 tcp from "
					    "table(sw%jd_zp%d) to any dst-port 80 in "
					    "recv %s", at, (intmax_t)ucl_object_toint(
					    ucl_object_lookup(sw, "fib")), pzi, uni);
					rule(rules, RULE_FROM, "fwd %s,3129 tcp from "
					    "table(sw%jd_zp%d) to any dst-port 443 in "
					    "recv %s", at, (intmax_t)ucl_object_toint(
					    ucl_object_lookup(sw, "fib")), pzi, uni);
				}
			}
			if (ucl_object_lookup(ep, "remote") != NULL)
				group_rules(pl, sw, ep, tables, rules, uni);
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
		/*
		 * NAT64 (RFC 6146, Arcana's own beside MEF 70.2 §10.5): at the
		 * edge named, the IPv6 of the service's hosts to the Internet's
		 * IPv4 through ipfw's nat64lsn, its pool among the known
		 * prefixes so that the NAT of the breakout takes it out; CLAT
		 * (RFC 6877) at a UNI that says so, nat64clat: the IPv4 hosts
		 * behind it carried as IPv6 to the NAT64, and back.  Before the
		 * zones' rules, which steer what is left.
		 */
		n64 = is_nullish(ucl_object_lookup(sw, "nat64")) ? NULL :
		    ucl_object_lookup(sw, "nat64");
		snprintf(n64n, sizeof(n64n), "sw%jd_64", (intmax_t)
		    ucl_object_toint(ucl_object_lookup(sw, "fib")));
		if (n64 != NULL && str(n64, "edge") != NULL && strcmp(str(n64,
		    "edge"), sid) == 0 && str(n64, "pool") != NULL && str(n64,
		    "prefix") != NULL) {
			entry(kt, str(n64, "pool"), "0");
			snprintf(words, sizeof(words), "nat64lsn %s create prefix4 %s "
			    "prefix6 %s allow_private", n64n, str(n64, "pool"), str(
			    n64, "prefix"));
			ucl_array_append(objects, S(words));
			rule(rules, RULE_FROM, "nat64lsn %s ip6 from table(%s) to %s "
			    "in", n64n, kname, str(n64, "prefix"));
			kmod_obj(pl, sid, "nat64", "ipfw_nat64", "NAT64 and CLAT");
		}
		eit = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
		    "end_points"), &eit, true)) != NULL) {
			const ucl_object_t	*cl;
			char			 cn[64], csym[40];

			cl = ucl_object_lookup(ucl_object_lookup(ep, "uni"), "clat");
			if (strcmp(str(ep, "edge"), sid) != 0 || str(cl, "prefix") ==
			    NULL || n64 == NULL || str(n64, "prefix") == NULL)
				continue;
			uni = uni_ifname(pl, sw, ep, ifn, sizeof(ifn));
			symbol(str(ep, "id"), csym, sizeof(csym));
			snprintf(cn, sizeof(cn), "sw%jd_c%.20s", (intmax_t)
			    ucl_object_toint(ucl_object_lookup(sw, "fib")), csym);
			snprintf(words, sizeof(words), "nat64clat %s create clat_prefix "
			    "%s plat_prefix %s", cn, str(cl, "prefix"), str(n64,
			    "prefix"));
			ucl_array_append(objects, S(words));
			rule(rules, RULE_FROM, "nat64clat %s ip4 from any to not "
			    "table(%s) in recv %s", cn, kname, uni);
			rule(rules, RULE_FROM, "nat64clat %s ip6 from any to %s in", cn,
			    str(cl, "prefix"));
			kmod_obj(pl, sid, "nat64", "ipfw_nat64", "NAT64 and CLAT");
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
			/* The identities of the zone at this edge's remote end
			 * points: each by its address; a Default
			 * zone has them already. */
			if (ucl_object_type(v) != UCL_STRING) {
				const ucl_object_t	*rep, *id;
				ucl_object_iter_t	 rit, iit;
				char			 ia[80];
				int			 af;

				rit = NULL;
				while ((rep = ucl_object_iterate(ucl_object_lookup(
				    sw, "end_points"), &rit, true)) != NULL) {
					if (strcmp(str(rep, "edge"), sid) != 0 ||
					    ucl_object_lookup(rep, "remote") == NULL)
						continue;
					iit = NULL;
					while ((id = ucl_object_iterate(ucl_object_lookup(
					    ucl_object_lookup(rep, "remote"),
					    "identities"), &iit, true)) != NULL) {
						if (ident_zone(ucl_object_lookup(rep,
						    "remote"), id) == NULL || strcmp(
						    ident_zone(ucl_object_lookup(rep,
						    "remote"), id), str(zone, "name")) != 0 ||
						    !identity_live(ucl_object_lookup(rep,
						    "remote"), id, time(NULL)) ||
						    !remote_addr(pl, sw, rep, str(id,
						    "name"), ia, sizeof(ia)))
							continue;
						af = family(ia);
						snprintf(ia + strlen(ia), sizeof(ia) -
						    strlen(ia), "/%d", af == AF_INET ? 32 :
						    128);
						entry(zt, ia, num);
						entry(table(tables, zp, "legacy"), ia,
						    "0");
					}
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
					nlist_tables(pl, tables, cr);
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
					/* Its security policy (MEF 138, by
					 * af-security-ingress): a pipe for its
					 * rate limit, its denies before the
					 * forward. */
					sec = sec_of(sw, pol, "af-security-ingress",
					    &si);
					rp = sec != NULL ? sec_pipe(dn, sw, sec) : -1;
					apit = NULL;
					for (k = 0; k < nap; k++) {
						appid = ap != NULL ?
						    ucl_object_tostring_forced(
						    ucl_object_iterate(ap, &apit,
						    true)) : NULL;
						if (pol != NULL && sec != NULL) {
							char	rown[80];

							ippf_rules(tables, rules,
							    next, sw, sec, cr, appid,
							    recv, pl->lists);
							dpf_rules(rules, next, sw,
							    sec, cr, appid, recv,
							    svc_resolver(sw) ?
							    ep_own4(pl, sw, ep, rown,
							    sizeof(rown)) : NULL);
						}
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
								/* By the breakout
								 * domain's table
								 * where there is
								 * one (R20-R24):
								 * setfib goes on
								 * to the next
								 * rule. */
								if (bo_fib_of(sw) !=
								    ucl_object_toint(
								    ucl_object_lookup(
								    sw, "fib")))
									rule(rules,
									    next,
									    "setfib "
									    "%jd %s%s",
									    (intmax_t)
									    bo_fib_of(
									    sw),
									    words,
									    recv);
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
						/* By the tunnels, its queue; and the
						 * security policy's pipe. */
						if (q >= 0 && xmit[0] != '\0' &&
						    afs_words(cr, NULL, appid,
						    words, sizeof(words), &fam))
							rule(pre, RULE_FROM + 1,
							    "queue %d %s src-ip "
							    "table(%s) out %s", q,
							    words, zp, xmit);
						if (rp >= 0 && xmit[0] != '\0' &&
						    afs_words(cr, NULL, appid,
						    words, sizeof(words), &fam))
							rule(pre, RULE_FROM + 1,
							    "pipe %d %s src-ip "
							    "table(%s) out %s", rp,
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
					/* And its security policy (MEF 138, by
					 * af-security-egress): the denies on the
					 * way out by the UNI. */
					sec = sec_of(sw, epol, "af-security-egress",
					    &si);
					if (v != NULL && (ucl_object_type(v) !=
					    UCL_STRING || strcmp(
					    ucl_object_tostring(v), "discard") != 0))
						v = NULL;
					if (v == NULL && sec == NULL)
						continue;
					snprintf(tail, sizeof(tail), " src-ip "
					    "table(%s) out xmit %s", zp, uni);
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

							if (sec != NULL) {
								ippf_rules(tables, pre,
								    RULE_FROM + 1, sw,
								    sec, cr, appid, tail,
								    pl->lists);
								dpf_rules(pre,
								    RULE_FROM + 1, sw,
								    sec, cr, appid, tail,
								    NULL);
							}
							if (v != NULL && afs_words(cr,
							    NULL, appid, words,
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
				    "to %s in recv %s", (intmax_t)bo_fib_of(sw),
				    natip != NULL ? natip : ucs_address(pl, sid, bo)
				    != NULL ? ucs_address(pl, sid, bo) : "me", bif);
				if (natip != NULL)
					rule(pre, RULE_FROM + 1, "nat %d ip4 from "
					    "any to %s in recv %s", nat, natip,
					    bif);
				rule(pre, RULE_FROM + 1, "setfib %jd ip from any "
				    "to table(%s) in recv %s", (intmax_t)bo_fib_of(
				    sw), kname, bif);
				/* What comes back for the NAT64's pool, once the NAT
				 * gave it back: IPv6 again, to the host it is for. */
				if (n64 != NULL && str(n64, "edge") != NULL && strcmp(
				    str(n64, "edge"), sid) == 0 && str(n64, "pool") !=
				    NULL)
					rule(pre, RULE_FROM + 1, "nat64lsn %s ip4 from any "
					    "to %s in recv %s", n64n, str(n64, "pool"), bif);
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

		/* The diverts to Suricata before all. */
		lit = NULL;
		while ((line = ucl_object_iterate(rules, &lit, true)) != NULL)
			if (atoi(ucl_object_tostring(line)) == RULE_IPS)
				ucl_array_append(all, ucl_object_copy(line));
		for (pass = 0; pass < 3; pass++) {
			lit = NULL;
			while ((line = ucl_object_iterate(pass == 1 ? pre : rules,
			    &lit, true)) != NULL) {
				if (atoi(ucl_object_tostring(line)) == RULE_IPS)
					continue;
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
	    ucl_array_size(rules) > 0 && atoi(ucl_object_tostring(
	    ucl_array_find_index(rules, 0))) == RULE_IPS ? RULE_IPS : RULE_FROM,
	    RULE_TO, ucl_array_size(tables));
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
	if (o != NULL && ucl_object_lookup(pl->boroutes, sid) != NULL) {
		j = job("sdwan-steer", "entries", entries, NULL);
		put(j, "routes", ucl_object_copy(ucl_object_lookup(pl->boroutes,
		    sid)));
		make(o, j);
		unmake(o, job("sdwan-steer", "entries", ucl_object_typed_new(
		    UCL_ARRAY), NULL));
	} else	if (o != NULL) {
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

/* The k-th entry of a UNI's bgp or ospf: one object, or a list of them
 * (several neighbours, a family each); NULL past the end. */
static const ucl_object_t *
entry_at(const ucl_object_t *rs, int k)
{

	if (is_nullish(rs))
		return (NULL);
	if (ucl_object_type(rs) == UCL_ARRAY)
		return (ucl_array_find_index(rs, (unsigned int)k));
	return (k == 0 ? rs : NULL);
}

/*
 * Do the UNIs of the service at the edge want BFD with their neighbours
 * (an entry with bfd)?  Their interfaces appended to ifs after the
 * tunnels' when ifs is given; *mhp set when a neighbour is multihop.
 */
static bool
uni_bfd(struct plan *pl, const ucl_object_t *sw, const char *sid,
    ucl_object_t *ifs, bool *mhp)
{
	const ucl_object_t	*ep, *u, *r;
	ucl_object_iter_t	 it;
	char			 ifbuf[32];
	bool			 any, here;
	int			 k;

	any = false;
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (str(ep, "edge") == NULL || strcmp(str(ep, "edge"), sid) != 0 ||
		    (u = ucl_object_lookup(ep, "uni")) == NULL)
			continue;
		here = false;
		for (k = 0; (r = entry_at(ucl_object_lookup(u, "bgp"), k)) != NULL;
		    k++)
			if (ucl_flag(r, "bfd")) {
				here = true;
				if (ucl_flag(r, "multihop") && mhp != NULL)
					*mhp = true;
			}
		for (k = 0; (r = entry_at(ucl_object_lookup(u, "ospf"), k)) !=
		    NULL; k++)
			if (ucl_flag(r, "bfd"))
				here = true;
		if (!here)
			continue;
		any = true;
		if (ifs != NULL)
			ucl_array_append(ifs, S(uni_ifname(pl, sw, ep, ifbuf,
			    sizeof(ifbuf))));
	}
	return (any);
}

/* A route of an edge's own, by its interface or by a next hop. */
static void
orig_route(ucl_object_t *arr, const char *prefix, const char *next_hop)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "prefix", S(prefix));
	if (next_hop != NULL)
		put(o, "next_hop", S(next_hop));
	ucl_array_append(arr, o);
}

/*
 * iBGP between the edges' loopbacks (swvcs[].ibgp: "loopback", Arcana's
 * own beside Mplify 119 §8.3), as the agent renders it (sdconf.c): one
 * session with each other edge, multihop, between loopbacks each edge
 * reaches by a static route over every tunnel to it at once (ECMP), each
 * path watched by BFD; the backup tunnels in a second static of lower
 * preference, taken when every other path is down.  An edge that
 * carries transit reflects what it learns (RFC 4456: every edge a
 * client of every other), so a prefix behind an edge whose direct
 * tunnels are all down is reached through a third: the reflected route,
 * the reflector its next hop, loses to the direct one by its longer
 * cluster list while the direct one is there.  The UNIs' prefixes are
 * the edge's own statics (origins), sent to the edges and kept out of
 * the kernel, which has them.  A BGP route cannot resolve its next hop
 * by another BGP route, which is why the reflection, and not a route to
 * the far loopback through the third edge.  Its form: this edge's
 * loopback addresses, whether it reflects, each other edge's name, its
 * loopback's addresses and the far ends' inner addresses of the
 * tunnels to it (paths4, paths6, the backups' backup4, backup6), and
 * the origins, each end point's routes by family.
 */
static ucl_object_t *
loop_spec(struct plan *pl, const ucl_object_t *sw, const char *sid)
{
	const ucl_object_t	*edge, *t, *e0, *e1, *far, *ep, *u, *v, *e;
	ucl_object_iter_t	 it, tit, rit;
	ucl_object_t		*lp, *edges, *fe, *paths, *origins, *og, *rs;
	const char		*fsid, *me4, *me6, *far4, *far6, *fa;
	const char *const	 fams[] = { "ipv4", "ipv6" };
	char			 l4[64], l6[64], f4[64], f6[64], ifbuf[32];
	int			 pass, i, af;

	lp = ucl_object_typed_new(UCL_OBJECT);
	me4 = loop_addr(pl, sw, sid, AF_INET, l4, sizeof(l4));
	me6 = loop_addr(pl, sw, sid, AF_INET6, l6, sizeof(l6));
	if (me4 != NULL)
		put(lp, "local4", S(me4));
	if (me6 != NULL)
		put(lp, "local6", S(me6));
	if (edge_transit(pl, sid))
		put(lp, "transit", B(true));
	edges = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((edge = ucl_object_iterate(ucl_object_lookup(pl->doc, "edges"),
	    &it, true)) != NULL) {
		fsid = str(edge, "server");
		if (strcmp(fsid, sid) == 0 || !edge_in(sw, fsid))
			continue;
		far4 = loop_addr(pl, sw, fsid, AF_INET, f4, sizeof(f4));
		far6 = loop_addr(pl, sw, fsid, AF_INET6, f6, sizeof(f6));
		if (far4 == NULL && far6 == NULL)
			continue;
		fe = ucl_object_typed_new(UCL_OBJECT);
		put(fe, "name", S(server_name_of(fsid)));
		if (far4 != NULL)
			put(fe, "ipv4", S(far4));
		if (far6 != NULL)
			put(fe, "ipv6", S(far6));
		/* Its loopback by every tunnel to it: the ones no backup
		 * first, the backups below them. */
		for (i = 0; i < 2; i++) {
			af = i == 0 ? AF_INET : AF_INET6;
			fa = i == 0 ? far4 : far6;
			if (fa == NULL)
				continue;
			for (pass = 0; pass < 2; pass++) {
				paths = ucl_object_typed_new(UCL_ARRAY);
				tit = NULL;
				while ((t = ucl_object_iterate(pl->tunnels, &tit,
				    true)) != NULL) {
					if (strcmp(str(t, "swvc"), str(sw, "id"))
					    != 0 || ucl_flag(t, "control") ||
					    ucl_flag(t, "backup") != (pass == 1))
						continue;
					e0 = ucl_array_find_index(ucl_object_lookup(
					    t, "ends"), 0);
					e1 = ucl_array_find_index(ucl_object_lookup(
					    t, "ends"), 1);
					if (strcmp(str(e0, "edge"), sid) == 0 &&
					    strcmp(str(e1, "edge"), fsid) == 0)
						far = e1;
					else if (strcmp(str(e1, "edge"), sid) == 0
					    && strcmp(str(e0, "edge"), fsid) == 0)
						far = e0;
					else
						continue;
					if (str(far, af == AF_INET ? "inner4" :
					    "inner6") != NULL)
						ucl_array_append(paths, S(str(far, af ==
						    AF_INET ? "inner4" : "inner6")));
				}
				if (ucl_array_size(paths) > 0)
					put(fe, pass == 0 ? (af == AF_INET ? "paths4" :
					    "paths6") : (af == AF_INET ? "backup4" :
					    "backup6"), paths);
				else
					ucl_object_unref(paths);
			}
		}
		ucl_array_append(edges, fe);
	}
	put(lp, "edges", edges);
	/* This edge's own prefixes: its UNIs' subnets and static routes, a
	 * remote end point's; to the other edges, not to the kernel. */
	origins = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		u = ucl_object_lookup(ep, "uni");
		if (u == NULL && ucl_object_lookup(ep, "remote") == NULL)
			continue;
		og = ucl_object_typed_new(UCL_OBJECT);
		put(og, "id", S(str(ep, "id")));
		put(og, "interface", S(uni_ifname(pl, sw, ep, ifbuf,
		    sizeof(ifbuf))));
		for (i = 0; i < 2; i++) {
			af = i == 0 ? AF_INET : AF_INET6;
			rs = ucl_object_typed_new(UCL_ARRAY);
			if (u == NULL) {
				v = ucl_object_lookup(ep, "remote");
				if (str(v, "prefix") != NULL && family(str(v,
				    "prefix")) == af)
					orig_route(rs, str(v, "prefix"), NULL);
			} else {
				v = ucl_object_lookup(u, fams[i]);
				if (str(v, "mode") != NULL && (strcmp(str(v, "mode"),
				    "static") == 0 || strcmp(str(v, "mode"), "dhcp")
				    == 0 || strcmp(str(v, "mode"), "slaac") == 0) &&
				    str(v, "prefix") != NULL) {
					orig_route(rs, str(v, "prefix"), NULL);
					rit = NULL;
					while ((e = ucl_object_iterate(ucl_object_lookup(
					    v, "secondary"), &rit, true)) != NULL)
						if (str(e, "prefix") != NULL)
							orig_route(rs, str(e, "prefix"),
							    NULL);
				}
				rit = NULL;
				while ((e = ucl_object_iterate(ucl_object_lookup(u,
				    "routes"), &rit, true)) != NULL)
					if (str(e, "prefix") != NULL && str(e,
					    "next_hop") != NULL && family(str(e,
					    "prefix")) == af)
						orig_route(rs, str(e, "prefix"), str(e,
						    "next_hop"));
			}
			if (ucl_array_size(rs) > 0)
				put(og, fams[i], rs);
			else
				ucl_object_unref(rs);
		}
		ucl_array_append(origins, og);
	}
	put(lp, "origins", origins);
	return (lp);
}

/*
 * The destination sets of an edge whose breakout is chosen by BGP
 * attribute (edges[].breakout_sets, bgp_import), as the agent renders
 * them into the filters to the kernel: each set's name, the end point
 * named for it, its gateway, and the AS path and communities it
 * matches; "only" where no other BGP route reaches the kernel.  NULL
 * when the edge has none.
 */
static ucl_object_t *
sets_spec(struct plan *pl, const ucl_object_t *sw, const char *sid)
{
	const ucl_object_t	*edge, *bs, *set, *uep;
	ucl_object_iter_t	 it;
	ucl_object_t		*o, *arr, *e;
	bool			 only;

	edge = by(ucl_object_lookup(pl->doc, "edges"), "server", sid);
	only = str(edge, "bgp_import") != NULL && strcmp(str(edge,
	    "bgp_import"), "sets") == 0;
	if (!only && ucl_array_size(ucl_object_lookup(edge, "breakout_sets")) ==
	    0)
		return (NULL);
	o = ucl_object_typed_new(UCL_OBJECT);
	if (only)
		put(o, "only", B(true));
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((bs = ucl_object_iterate(ucl_object_lookup(edge,
	    "breakout_sets"), &it, true)) != NULL) {
		set = by(ucl_object_lookup(sw, "bgp_sets"), "name", str(bs,
		    "set"));
		uep = by(ucl_object_lookup(edge, "ucs_end_points"), "id",
		    str(bs, "via"));
		if (set == NULL || str(uep, "gateway") == NULL)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "name", S(str(set, "name")));
		put(e, "via", S(str(uep, "id")));
		put(e, "gateway", S(str(uep, "gateway")));
		if (ucl_object_lookup(set, "as_path") != NULL)
			put(e, "as_path", ucl_object_copy(ucl_object_lookup(set,
			    "as_path")));
		if (ucl_object_lookup(set, "communities") != NULL)
			put(e, "communities", ucl_object_copy(ucl_object_lookup(
			    set, "communities")));
		ucl_array_append(arr, e);
	}
	put(o, "sets", arr);
	return (o);
}

/* What the agent renders of a UNI's or UCS End Point's routing: its
 * BGP and OSPF entries as the document has them. */
static void
routing_spec(ucl_object_t *o, const ucl_object_t *u)
{

	if (!is_nullish(ucl_object_lookup(u, "bgp")))
		put(o, "bgp", ucl_object_copy(ucl_object_lookup(u, "bgp")));
	if (!is_nullish(ucl_object_lookup(u, "ospf")))
		put(o, "ospf", ucl_object_copy(ucl_object_lookup(u, "ospf")));
}

/*
 * The BIRD form of a service at an edge, which the agent renders
 * (sdconf.c): the kernel's table learned and kept (the routes the
 * console made stay), the UNIs' and the tunnels' connected routes,
 * iBGP with every other edge by each tunnel (next hop self: the far
 * end's inner address) or between loopbacks, BFD on the tunnels, and
 * at each UNI BGP or OSPF with the subscriber as its entry says, its
 * distance as the preference (R140-R142: the lower, the better;
 * connected first).  What the console works out is in it as it is:
 * the router id, the interfaces, the table, the peers.
 */
static ucl_object_t *
bird_spec(struct plan *pl, const ucl_object_t *sw, const char *sid)
{
	const ucl_object_t	*ep, *u, *t, *e0, *e1, *me, *far, *v, *cp, *bfd;
	const ucl_object_t	*rp;
	ucl_object_iter_t	 it, tit;
	ucl_object_t		*spec, *direct, *bo, *ifs, *peers, *pe, *unis;
	ucl_object_t		*uo, *rej, *sets;
	const char		*rid;
	char			 ifbuf[32], l4[64], ifn[32];
	bool			 mh;

	spec = ucl_object_typed_new(UCL_OBJECT);
	put(spec, "service", S(str(sw, "id")));
	put(spec, "fib", I(ucl_object_toint(ucl_object_lookup(sw, "fib"))));
	/* The service's table on this edge; on an own-table edge the
	 * host's own, the first, which BIRD takes without being told. */
	put(spec, "table", I(efib(pl, sw, sid)));
	put(spec, "as", I(ucl_object_lookup(sw, "as") != NULL ?
	    ucl_object_toint(ucl_object_lookup(sw, "as")) : DEFAULT_AS));
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
	/* The UNIs' interfaces, then the tunnels' own: a neighbour's next
	 * hop is resolved by them, else its routes would be unreachable;
	 * then the loopback's. */
	direct = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		if ((u = ucl_object_lookup(ep, "uni")) == NULL)
			continue;	/* a remote end point */
		ucl_array_append(direct, S(uni_ifname(pl, sw, ep, ifbuf,
		    sizeof(ifbuf))));
		v = ucl_object_lookup(ucl_object_lookup(u, "ipv4"), "provider");
		if (rid == NULL && v != NULL && ucl_array_size(v) > 0)
			rid = ucl_object_tostring_forced(ucl_array_find_index(v,
			    0));
	}
	if (sw_loop(sw) && loop_addr(pl, sw, sid, AF_INET, l4, sizeof(l4)) !=
	    NULL)
		rid = l4;
	put(spec, "router_id", S(rid != NULL ? rid : "0.0.0.1"));
	it = NULL;
	while ((t = ucl_object_iterate(pl->tunnels, &it, true)) != NULL) {
		if (strcmp(str(t, "swvc"), str(sw, "id")) != 0)
			continue;
		tit = NULL;
		while ((me = ucl_object_iterate(ucl_object_lookup(t, "ends"),
		    &tit, true)) != NULL)
			if (strcmp(str(me, "edge"), sid) == 0 && str(me, "ifname")
			    != NULL)
				ucl_array_append(direct, S(str(me, "ifname")));
	}
	if (sw_loop(sw) && loop_alloc(pl, sw, sid) != NULL) {
		snprintf(ifn, sizeof(ifn), "lo%jd", (intmax_t)ucl_object_toint(
		    ucl_object_lookup(loop_alloc(pl, sw, sid), "unit")));
		ucl_array_append(direct, S(ifn));
	}
	put(spec, "direct", direct);
	/* With the iBGP between loopbacks the edge's own prefixes (orig*)
	 * stay out of the kernel, which has them as they are. */
	if (sw_loop(sw))
		put(spec, "loopback", B(true));
	if ((sets = sets_spec(pl, sw, sid)) != NULL)
		put(spec, "sets", sets);
	/* BFD on each tunnel interface here (R58, R59, R159), and on the
	 * UNIs whose neighbours are watched by it. */
	mh = false;
	if (sw_bfd(sw) || uni_bfd(pl, sw, sid, NULL, &mh)) {
		bfd = ucl_object_lookup(sw, "bfd");
		bo = ucl_object_typed_new(UCL_OBJECT);
		ifs = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((t = ucl_object_iterate(pl->tunnels, &it, true)) != NULL) {
			if (strcmp(str(t, "swvc"), str(sw, "id")) != 0)
				continue;
			tit = NULL;
			while ((me = ucl_object_iterate(ucl_object_lookup(t,
			    "ends"), &tit, true)) != NULL)
				if (strcmp(str(me, "edge"), sid) == 0 && str(me,
				    "ifname") != NULL)
					ucl_array_append(ifs, S(str(me, "ifname")));
		}
		(void)uni_bfd(pl, sw, sid, ifs, &mh);
		put(bo, "interfaces", ifs);
		put(bo, "interval", I(ucl_object_lookup(bfd, "interval") != NULL ?
		    ucl_object_toint(ucl_object_lookup(bfd, "interval")) : 200));
		put(bo, "multiplier", I(ucl_object_lookup(bfd, "multiplier") !=
		    NULL ? ucl_object_toint(ucl_object_lookup(bfd, "multiplier")) :
		    3));
		/* The sessions between loopbacks are multihop, watched by
		 * multihop BFD alike. */
		if (sw_loop(sw) || mh)
			put(bo, "multihop", B(true));
		/* The iBGP sessions go down with it. */
		if (sw_bfd(sw))
			put(bo, "sessions", B(true));
		put(spec, "bfd", bo);
	}
	/* Not to the other edges: the reserved prefixes and the service
	 * domain's, the tunnels' addresses, which a peer would resolve its
	 * next hop by in a circle. */
	rej = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((rp = ucl_object_iterate(ucl_object_lookup(sw,
	    "reserved_prefixes"), &it, true)) != NULL)
		ucl_array_append(rej, S(ucl_object_tostring_forced(rp)));
	rp = ucl_object_lookup(ucl_object_lookup(ucl_object_lookup(sw,
	    "domains"), "service"), "prefix");
	if (rp != NULL)
		ucl_array_append(rej, S(ucl_object_tostring_forced(rp)));
	put(spec, "reject", rej);
	/* TCP MD5 on the sessions (Mplify 119 R11, R12). */
	if (str(sw, "md5") != NULL)
		put(spec, "md5", S(str(sw, "md5")));
	/* Between the loopbacks, one session with each edge. */
	if (sw_loop(sw))
		put(spec, "loop", loop_spec(pl, sw, sid));
	/* iBGP with each other edge, by each tunnel between them; or, with
	 * a control plane (Mplify 119 §8.3), with its host alone, which
	 * reflects to all (RFC 4456). */
	cp = is_nullish(ucl_object_lookup(sw, "control_plane")) ? NULL :
	    ucl_object_lookup(sw, "control_plane");
	peers = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while (!sw_loop(sw) && (t = ucl_object_iterate(pl->tunnels, &it,
	    true)) != NULL) {
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
		/* An edge of a service with a control plane peers with its
		 * host alone; the host, with every edge, as their reflector;
		 * by the control tunnel alone where the control plane has one
		 * (the CTVC, R5, R6). */
		if (cp != NULL && strcmp(sid, str(cp, "host")) != 0 && strcmp(
		    str(far, "edge"), str(cp, "host")) != 0)
			continue;
		if ((cp != NULL && str(cp, "ctvc") != NULL) != ucl_flag(t,
		    "control"))
			continue;
		pe = ucl_object_typed_new(UCL_OBJECT);
		put(pe, "tunnel", S(str(t, "id")));
		put(pe, "to", S(server_name_of(str(far, "edge"))));
		put(pe, "local", S(str(me, "inner4") != NULL ? str(me, "inner4") :
		    str(me, "inner6")));
		put(pe, "neighbor", S(str(far, "inner4") != NULL ? str(far,
		    "inner4") : str(far, "inner6")));
		if (cp != NULL && strcmp(sid, str(cp, "host")) == 0) {
			put(pe, "role", S("client"));
			if (str(cp, "cluster_id") != NULL)
				put(pe, "cluster_id", S(str(cp, "cluster_id")));
		} else if (cp != NULL)
			put(pe, "role", S("control"));
		ucl_array_append(peers, pe);
	}
	put(spec, "peers", peers);
	/* At each UNI here: BGP, OSPF, as its entry says. */
	unis = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		if ((u = ucl_object_lookup(ep, "uni")) == NULL)
			continue;	/* a remote end point */
		if (is_nullish(ucl_object_lookup(u, "bgp")) && is_nullish(
		    ucl_object_lookup(u, "ospf")))
			continue;
		uo = ucl_object_typed_new(UCL_OBJECT);
		put(uo, "id", S(str(u, "id")));
		put(uo, "end_point", S(str(ep, "id")));
		put(uo, "interface", S(uni_ifname(pl, sw, ep, ifbuf,
		    sizeof(ifbuf))));
		routing_spec(uo, u);
		ucl_array_append(unis, uo);
	}
	put(spec, "unis", unis);
	return (spec);
}

/* A UCS End Point's BIRD form: routing with the underlay in the end
 * point's table (Mplify 119 §12.2.3.5), its address the router id. */
static ucl_object_t *
ucs_bird_spec(struct plan *pl, const ucl_object_t *edge,
    const ucl_object_t *uep, int64_t vrf)
{
	const ucl_object_t	*bgp;
	ucl_object_t		*spec;
	const char		*addr;

	spec = ucl_object_typed_new(UCL_OBJECT);
	put(spec, "flavor", S("ucs"));
	put(spec, "end_point", S(str(uep, "id")));
	put(spec, "table", I(vrf));
	addr = ucs_address(pl, str(edge, "server"), uep);
	put(spec, "router_id", S(addr != NULL && family(addr) == AF_INET ?
	    addr : "0.0.0.2"));
	put(spec, "interface", S(str(uep, "interface")));
	bgp = ucl_object_lookup(ucl_object_lookup(uep, "routing"), "bgp");
	put(spec, "as", I(ucl_object_lookup(bgp, "as") != NULL &&
	    ucl_object_lookup(bgp, "local_as") != NULL ? ucl_object_toint(
	    ucl_object_lookup(bgp, "local_as")) : DEFAULT_AS));
	routing_spec(spec, ucl_object_lookup(uep, "routing"));
	return (spec);
}

/*
 * Each edge's BIRD instances: one for each service that routes at a
 * UNI, on every edge of the service (what one UNI learns reaches the
 * others by iBGP), named sw<fib>; and one per UCS End Point that routes
 * with the underlay, named ucs<vrf> (ucs0 in the first table).
 */
static void
bird_build(struct plan *pl, const ucl_object_t *doc)
{
	const ucl_object_t	*sw, *edge, *ep;
	ucl_object_iter_t	 it, eit, pit;
	ucl_object_t		*o, *inst, *list, *j;
	char			 name[32];
	char			 esid[80], ejail[64], *q;
	const char		*sid;
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
			/* An edge that is a vnet jail: the instance named by the
			 * jail too, run in it by the host's agent. */
			if (sdwan_edge_split(sid, esid, sizeof(esid), ejail,
			    sizeof(ejail)) && ejail[0] != '\0') {
				snprintf(name, sizeof(name), "sw%jd-%.26s", (intmax_t)
				    ucl_object_toint(ucl_object_lookup(sw, "fib")),
				    ejail);
				for (q = name; *q != '\0'; q++)
					if (*q == '.')
						*q = '_';
			} else
				snprintf(name, sizeof(name), "sw%jd", (intmax_t)
				    ucl_object_toint(ucl_object_lookup(sw, "fib")));
			inst = ucl_object_typed_new(UCL_OBJECT);
			put(inst, "name", S(name));
			put(inst, "fib", I(efib(pl, sw, sid)));
			put(inst, "host", S(server_name_of(sid)));
			put(inst, "spec", bird_spec(pl, sw, sid));
			ucl_array_append(list, inst);
		}
		/* The UCS End Points that route with the underlay. */
		{
			const ucl_object_t	*uep;
			ucl_object_iter_t	 uit;
			int64_t			 vrf;

			uit = NULL;
			while ((uep = ucl_object_iterate(ucl_object_lookup(edge,
			    "ucs_end_points"), &uit, true)) != NULL) {
				if (is_nullish(ucl_object_lookup(uep, "routing")) ||
				    (is_nullish(ucl_object_lookup(ucl_object_lookup(
				    uep, "routing"), "bgp")) && is_nullish(
				    ucl_object_lookup(ucl_object_lookup(uep,
				    "routing"), "ospf"))))
					continue;
				vrf = ucl_object_lookup(uep, "vrf") != NULL ?
				    ucl_object_toint(ucl_object_lookup(uep, "vrf")) :
				    0;
				snprintf(name, sizeof(name), "ucs%jd", (intmax_t)vrf);
				if (by(list, "name", name) != NULL)
					continue;
				inst = ucl_object_typed_new(UCL_OBJECT);
				put(inst, "name", S(name));
				put(inst, "fib", I(vrf));
				put(inst, "host", S(server_name_of(sid)));
				put(inst, "spec", ucs_bird_spec(pl, edge, uep, vrf));
				ucl_array_append(list, inst);
			}
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
 * The edge's own breakout UCS end points of a service, the most
 * preferred first (the order of the document among equals); how many.
 */
static int
breakouts_of(struct plan *pl, const ucl_object_t *sw, const char *sid,
    const ucl_object_t **out, int max)
{
	const ucl_object_t	*edge, *uep, *t;
	ucl_object_iter_t	 it;
	int			 n, i, k;

	edge = by(ucl_object_lookup(pl->doc, "edges"), "server", sid);
	n = 0;
	it = NULL;
	while (n < max && (uep = ucl_object_iterate(ucl_object_lookup(edge,
	    "ucs_end_points"), &it, true)) != NULL)
		if (ucl_flag(uep, "breakout") && in_list(ucl_object_lookup(sw,
		    "ucs"), str(uep, "ucs")))
			out[n++] = uep;
	for (i = 1; i < n; i++) {
		t = out[i];
		for (k = i; k > 0 && ucl_object_toint(ucl_object_lookup(out[k -
		    1], "preference")) < ucl_object_toint(ucl_object_lookup(t,
		    "preference")); k--)
			out[k] = out[k - 1];
		out[k] = t;
	}
	return (n);
}

/*
 * A probe target of an edge's, beside the tunnels': the service's
 * settings, through the table said.
 */
static void
probe_target(struct plan *pl, const char *sid, const ucl_object_t *sw,
    const char *id, const char *address, int64_t fib)
{
	const ucl_object_t	*po, *v;
	ucl_object_iter_t	 pit;
	ucl_object_t		*o, *tg, *targets, *j;

	o = (ucl_object_t *)(uintptr_t)by(ucl_object_lookup(pl->edges, sid),
	    "key", "probes");
	if (o == NULL) {
		o = object(pl, sid, "probes", PH_PROBE, "the tunnels measured: "
		    "ICMP echo through the service's table");
		if (o == NULL)
			return;
		make(o, job("sdwan-probes", "targets", ucl_object_typed_new(
		    UCL_ARRAY), NULL));
		unmake(o, job("sdwan-probes", "targets", ucl_object_typed_new(
		    UCL_ARRAY), NULL));
	}
	j = (ucl_object_t *)(uintptr_t)ucl_array_find_index(ucl_object_lookup(o,
	    "make"), 0);
	targets = (ucl_object_t *)(uintptr_t)ucl_object_lookup(j, "targets");
	tg = ucl_object_typed_new(UCL_OBJECT);
	put(tg, "id", S(id));
	put(tg, "address", S(address));
	put(tg, "fib", I(fib));
	if ((po = ucl_object_lookup(ucl_object_lookup(sw, "intervals"), "eval"))
	    != NULL)
		put(tg, "eval", ucl_object_copy(po));
	if ((po = ucl_object_lookup(sw, "probe")) != NULL) {
		pit = NULL;
		while ((v = ucl_object_iterate(po, &pit, true)) != NULL)
			put(tg, ucl_object_key(v), ucl_object_copy(v));
	}
	ucl_array_append(targets, tg);
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
	pl->notes = ucl_object_typed_new(UCL_ARRAY);
	/* What is deployed: the services complete (sdwan_ready()). */
	doc = pl->ready = sdwan_ready(doc, pl->notes);
	pl->doc = doc;
	pl->alloc = ucl_object_copy(ucl_object_lookup(st, "alloc"));
	pl->edges = ucl_object_typed_new(UCL_OBJECT);
	pl->tunnels = ucl_object_typed_new(UCL_ARRAY);
	pl->lists = lists_kept();
	pl->used = ucl_object_typed_new(UCL_OBJECT);
	pl->boroutes = ucl_object_typed_new(UCL_OBJECT);
	pl->learned = ucl_object_typed_new(UCL_OBJECT);
	/* The hosts as they are reached now: a UCS end point's address may
	 * be asked of its host (ucs_address). */
	host_refs();
	/* The tunnels first: their units and pairs, in the document's order. */
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL)
		if (!tunnels(pl, sw))
			return (false);
	/* Each edge's FIBs: as many as its highest service's, its domains'
	 * among them, and one. */
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL) {
		const ucl_object_t	*sdom;

		fib = ucl_object_toint(ucl_object_lookup(sw, "fib"));
		if (bo_fib_of(sw) > fib)
			fib = bo_fib_of(sw);
		{
			/* The UCS End Points' tables of the service's edges. */
			const ucl_object_t	*ed, *uep;
			ucl_object_iter_t	 dit, uit;

			dit = NULL;
			while ((ed = ucl_object_iterate(ucl_object_lookup(doc,
			    "edges"), &dit, true)) != NULL) {
				uit = NULL;
				while ((uep = ucl_object_iterate(ucl_object_lookup(ed,
				    "ucs_end_points"), &uit, true)) != NULL)
					if (ucl_object_lookup(uep, "vrf") != NULL &&
					    ucl_object_toint(ucl_object_lookup(uep,
					    "vrf")) > fib)
						fib = ucl_object_toint(
						    ucl_object_lookup(uep, "vrf"));
			}
		}
		sdom = ucl_object_lookup(ucl_object_lookup(sw, "domains"),
		    "service");
		if (sdom != NULL && ucl_object_lookup(sdom, "fib") != NULL &&
		    ucl_object_toint(ucl_object_lookup(sdom, "fib")) > fib)
			fib = ucl_object_toint(ucl_object_lookup(sdom, "fib"));
		it2 = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
		    "end_points"), &it2, true)) != NULL) {
			o = (ucl_object_t *)(uintptr_t)by(ucl_object_lookup(
			    pl->edges, str(ep, "edge")), "key", "fibs");
			if (o == NULL) {
				const ucl_object_t	*oe, *ou;
				ucl_object_iter_t	 oit;
				bool			 vrfs = false;

				o = object(pl, str(ep, "edge"), "fibs", PH_FIBS,
				    "net.fibs");
				/* An own-table edge whose uplinks are in tables
				 * of their own keeps their connected routes in
				 * the host's table too (add_addr_allfibs on):
				 * the host's own daemons and jails still reach
				 * the uplinks; a service's own table wants it
				 * off. */
				oe = by(ucl_object_lookup(pl->doc, "edges"),
				    "server", str(ep, "edge"));
				oit = NULL;
				while ((ou = ucl_object_iterate(ucl_object_lookup(
				    oe, "ucs_end_points"), &oit, true)) != NULL)
					if (ucl_object_lookup(ou, "vrf") != NULL)
						vrfs = true;
				put(o, "allfibs", B(edge_own_table(pl, str(ep,
				    "edge")) && vrfs));
			}
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
	/* Each UCS End Point as its entry says (Mplify 119 §12.2.3): its
	 * interface addressed by DHCP or SLAAC, in its own table (vrf). */
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL) {
		const ucl_object_t	*uep;
		ucl_object_t		*j;
		ucl_object_iter_t	 uit;
		const char		*how;
		int64_t			 vrf;

		uit = NULL;
		while ((uep = ucl_object_iterate(ucl_object_lookup(e,
		    "ucs_end_points"), &uit, true)) != NULL) {
			how = str(uep, "addressing");
			vrf = ucl_object_lookup(uep, "vrf") != NULL ?
			    ucl_object_toint(ucl_object_lookup(uep, "vrf")) : 0;
			if ((how == NULL || strcmp(how, "static") == 0) && vrf == 0)
				continue;
			snprintf(n, sizeof(n), "ucs:%s", str(uep, "id"));
			o = object(pl, str(e, "server"), n, PH_FIBS, "UCS end point "
			    "%s: %s%s%s%s", str(uep, "id"), str(uep, "interface"),
			    how != NULL && strcmp(how, "static") != 0 ? " addressed "
			    "by " : "", how != NULL && strcmp(how, "static") != 0 ?
			    (strcmp(how, "dhcp") == 0 ? "DHCP (dhclient)" : "SLAAC "
			    "(rtsol)") : "", vrf > 0 ? ", in its own table" : "");
			if (o == NULL)
				continue;
			j = job("if-set", "interface", S(str(uep, "interface")),
			    "persist", B(true), NULL);
			if (how != NULL && strcmp(how, "static") != 0)
				put(j, "addressing", S(how));
			if (vrf > 0)
				put(j, "fib", I(vrf));
			make(o, j);
			/* Undone: addressed as it was before (a host on
			 * SLAAC or DHCP by rc.conf stays so), not static. */
			j = job("if-set", "interface", S(str(uep, "interface")),
			    "persist", B(true), NULL);
			if (how != NULL && strcmp(how, "static") != 0)
				put(j, "addressing", S("was"));
			if (vrf > 0)
				put(j, "fib", I(0));
			unmake(o, j);
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
	/* Each edge's loopback in a service whose iBGP is between them. */
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL) {
		if (!sw_loop(sw))
			continue;
		it2 = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
		    "end_points"), &it2, true)) != NULL)
			loop_obj(pl, sw, str(ep, "edge"));
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
	/*
	 * Each edge's links watched (Mplify 119's interface faults): its
	 * UCS end points' interfaces and its UNIs', beside the targets.
	 */
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL) {
		ucl_object_t		*links, *lk, *j;
		const ucl_object_t	*u;
		ucl_object_iter_t	 uit;

		links = ucl_object_typed_new(UCL_ARRAY);
		uit = NULL;
		while ((u = ucl_object_iterate(ucl_object_lookup(e,
		    "ucs_end_points"), &uit, true)) != NULL) {
			if (str(u, "interface") == NULL || str(u, "id") == NULL)
				continue;
			lk = ucl_object_typed_new(UCL_OBJECT);
			put(lk, "interface", S(str(u, "interface")));
			put(lk, "id", S(str(u, "id")));
			put(lk, "role", S("ucs"));
			ucl_array_append(links, lk);
		}
		it2 = NULL;
		while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"),
		    &it2, true)) != NULL) {
			it3 = NULL;
			while ((ep = ucl_object_iterate(ucl_object_lookup(sw,
			    "end_points"), &it3, true)) != NULL) {
				u = ucl_object_lookup(ep, "uni");
				if (str(ep, "edge") == NULL || str(e, "server") ==
				    NULL || strcmp(str(ep, "edge"), str(e,
				    "server")) != 0 || str(u, "interface") == NULL)
					continue;
				lk = ucl_object_typed_new(UCL_OBJECT);
				put(lk, "interface", S(str(u, "interface")));
				put(lk, "id", S(str(u, "id") != NULL ? str(u,
				    "id") : str(ep, "id")));
				put(lk, "role", S("uni"));
				ucl_array_append(links, lk);
			}
		}
		if (ucl_array_size(links) == 0) {
			ucl_object_unref(links);
			continue;
		}
		o = (ucl_object_t *)(uintptr_t)by(ucl_object_lookup(pl->edges,
		    str(e, "server")), "key", "probes");
		if (o == NULL) {
			o = object(pl, str(e, "server"), "probes", PH_PROBE,
			    "the tunnels measured: ICMP echo through the "
			    "service's table");
			make(o, job("sdwan-probes", "targets",
			    ucl_object_typed_new(UCL_ARRAY), NULL));
			unmake(o, job("sdwan-probes", "targets",
			    ucl_object_typed_new(UCL_ARRAY), NULL));
		}
		j = (ucl_object_t *)(uintptr_t)ucl_array_find_index(
		    ucl_object_lookup(o, "make"), 0);
		put(j, "links", links);
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
			/* The other edges' prefixes come by iBGP between the
			 * loopbacks, no static for them. */
			if (sw_loop(sw))
				continue;
			it3 = NULL;
			while ((ep2 = ucl_object_iterate(ucl_object_lookup(sw,
			    "end_points"), &it3, true)) != NULL) {
				const ucl_object_t	*p, *tt, *fe;
				ucl_object_iter_t	 pit;
				char			 gws[600];

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
					/* Over every tunnel to that edge at
					 * once when there are several (ECMP);
					 * by the one when there is one. */
					(void)tunnels_for(pl, str(sw, "id"),
					    str(ep, "edge"), str(ep2, "edge"),
					    family(ucl_object_tostring(p)), gws,
					    sizeof(gws));
					if (strchr(gws, ',') != NULL)
						route_multi_obj(pl, str(ep,
						    "edge"), sw,
						    ucl_object_tostring(p), gws,
						    str(ep2, "id"));
					else
						route_obj(pl, str(ep, "edge"), sw,
						    ucl_object_tostring(p), str(fe,
						    family(ucl_object_tostring(p))
						    == AF_INET ? "inner4" :
						    "inner6"), str(ep2, "id"));
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
			if (ucl_object_lookup(ep, "uni") != NULL ? !uni_obj(pl, sw,
			    ep) : ucl_object_lookup(ep, "remote") != NULL &&
			    !remote_obj(pl, sw, ep))
				return (false);
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
		const ucl_object_t	*edge, *tt, *fe;
		const char		*bo_sid, *gw;
		bool			 local;
		int			 af;

		it2 = NULL;
		while ((edge = ucl_object_iterate(ucl_object_lookup(doc,
		    "edges"), &it2, true)) != NULL) {
			const char	*sid = str(edge, "server");

			if (!breaks_here(pl, sw, sid))
				continue;
			(void)breakout_of(pl, sw, sid, &local, &bo_sid);
			/* A breakout domain of its own (Mplify 119 R20-R26):
			 * the default route there, the UNIs' routes with it,
			 * the subscriber's table without a default route. */
			fib = bo_fib_of(sw);
			if (fib != ucl_object_toint(ucl_object_lookup(sw, "fib")))
				breakout_uni_routes(pl, sid, sw, fib);
			if (local) {
				/*
				 * By the edge's own uplinks, the most preferred
				 * first: its gateway the table's default route;
				 * the others stand by, each with a route to its
				 * gateway, and with several the agent probes each
				 * one's beacon (its gateway, unless said) and puts
				 * the first that answers in the default's place
				 * (breakout failover, Arcana's own).
				 */
				const ucl_object_t	*cands[16];
				ucl_object_t		*rts[2], *cd, *arr;
				const char		*beacon;
				char			 key[80];
				int			 nc, c, fam;

				rts[0] = rts[1] = NULL;
				nc = breakouts_of(pl, sw, sid, cands, 16);
				for (c = 0; c < nc; c++) {
					gw = str(cands[c], "gateway");
					if (gw == NULL) {
						char	note[300];

						snprintf(note, sizeof(note), "swvc %s: "
						    "%s breaks out by %s, which has no "
						    "gateway: no default route by it",
						    str(sw, "id"), server_name_of(sid),
						    str(cands[c], "id"));
						ucl_array_append(pl->notes, S(note));
						continue;
					}
					af = family(gw);
					fam = af == AF_INET ? 0 : 1;
					snprintf(n, sizeof(n), "%s/%d", gw, af == AF_INET
					    ? 32 : 128);
					route_fib_obj(pl, sid, sw, fib, PH_ROUTE, n,
					    str(cands[c], "interface"), "the breakout "
					    "gateway, by its interface");
					if (rts[fam] == NULL) {
						route_fib_obj(pl, sid, sw, fib, PH_ROUTE, af
						    == AF_INET ? "0.0.0.0/0" : "::/0", gw,
						    "the Internet, by local breakout");
						rts[fam] = ucl_object_typed_new(UCL_OBJECT);
						put(rts[fam], "fib", I(fib));
						put(rts[fam], "destination", S(af == AF_INET
						    ? "0.0.0.0/0" : "::/0"));
						put(rts[fam], "candidates",
						    ucl_object_typed_new(UCL_ARRAY));
					}
					cd = ucl_object_typed_new(UCL_OBJECT);
					snprintf(key, sizeof(key), "bo:%s", str(cands[c],
					    "id"));
					put(cd, "id", S(key));
					put(cd, "via", S(gw));
					ucl_array_append((ucl_object_t *)(uintptr_t)
					    ucl_object_lookup(rts[fam], "candidates"), cd);
				}
				for (fam = 0; fam < 2; fam++) {
					if (rts[fam] == NULL)
						continue;
					if (ucl_array_size(ucl_object_lookup(rts[fam],
					    "candidates")) < 2) {
						ucl_object_unref(rts[fam]);
						continue;
					}
					for (c = 0; c < nc; c++) {
						gw = str(cands[c], "gateway");
						if (gw == NULL || (family(gw) == AF_INET) !=
						    (fam == 0))
							continue;
						beacon = str(cands[c], "beacon") != NULL ?
						    str(cands[c], "beacon") : gw;
						if (strcmp(beacon, gw) != 0) {
							snprintf(n, sizeof(n), "%s/%d", beacon,
							    fam == 0 ? 32 : 128);
							route_fib_obj(pl, sid, sw, fib,
							    PH_ROUTE, n, gw, "the breakout's "
							    "beacon, by its gateway");
						}
						snprintf(key, sizeof(key), "bo:%s",
						    str(cands[c], "id"));
						probe_target(pl, sid, sw, key, beacon, fib);
					}
					if ((arr = (ucl_object_t *)(uintptr_t)
					    ucl_object_lookup(pl->boroutes, sid)) == NULL) {
						arr = ucl_object_typed_new(UCL_ARRAY);
						ucl_object_insert_key(pl->boroutes, arr, sid,
						    0, true);
					}
					ucl_array_append(arr, rts[fam]);
				}
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
				if (fib != ucl_object_toint(ucl_object_lookup(sw,
				    "fib"))) {
					/* The far end by the tunnel, in that
					 * table too. */
					snprintf(n, sizeof(n), "%s/%d", str(fe, af
					    == AF_INET ? "inner4" : "inner6"), af ==
					    AF_INET ? 32 : 128);
					route_fib_obj(pl, sid, sw, fib, PH_ROUTE, n,
					    str(ucl_array_find_index(
					    ucl_object_lookup(tt, "ends"),
					    (unsigned int)(1 - far)), "ifname"),
					    "the tunnel's far end, in the breakout "
					    "domain");
				}
				route_fib_obj(pl, sid, sw, fib, PH_ROUTE, af ==
				    AF_INET ? "0.0.0.0/0" : "::/0", str(fe, af ==
				    AF_INET ? "inner4" : "inner6"), why);
			}
		}
	}
	/* The uplinks the sets go out by (edges[].breakout_sets): each
	 * gateway by its interface in the service's table here, which the
	 * routes BIRD writes with that gateway need. */
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL) {
		const ucl_object_t	*edge, *bs, *uep;
		ucl_object_iter_t	 bit;

		it2 = NULL;
		while ((edge = ucl_object_iterate(ucl_object_lookup(doc,
		    "edges"), &it2, true)) != NULL) {
			if (!edge_in(sw, str(edge, "server")))
				continue;
			bit = NULL;
			while ((bs = ucl_object_iterate(ucl_object_lookup(edge,
			    "breakout_sets"), &bit, true)) != NULL) {
				if (by(ucl_object_lookup(sw, "bgp_sets"), "name",
				    str(bs, "set")) == NULL)
					continue;
				uep = by(ucl_object_lookup(edge, "ucs_end_points"),
				    "id", str(bs, "via"));
				if (str(uep, "gateway") == NULL || str(uep, "interface")
				    == NULL)
					continue;
				snprintf(n, sizeof(n), "%s/%d", str(uep, "gateway"),
				    family(str(uep, "gateway")) == AF_INET ? 32 : 128);
				route_fib_obj(pl, str(edge, "server"), sw, efib(pl, sw,
				    str(edge, "server")), PH_ROUTE, n, str(uep,
				    "interface"), "the gateway a destination set goes "
				    "out by, by its interface");
			}
		}
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
	/* A control plane host reflects for every other edge of its service:
	 * each must have a tunnel to it (R9). */
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL) {
		const ucl_object_t	*cp, *e0, *e1;

		if (is_nullish(cp = ucl_object_lookup(sw, "control_plane")))
			continue;
		it2 = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
		    &it2, true)) != NULL) {
			bool	joined = false;

			if (strcmp(str(ep, "edge"), str(cp, "host")) == 0)
				continue;
			it3 = NULL;
			while (!joined && (t = ucl_object_iterate(pl->tunnels, &it3,
			    true)) != NULL) {
				if (strcmp(str(t, "swvc"), str(sw, "id")) != 0)
					continue;
				e0 = ucl_array_find_index(ucl_object_lookup(t, "ends"),
				    0);
				e1 = ucl_array_find_index(ucl_object_lookup(t, "ends"),
				    1);
				if ((str(cp, "ctvc") != NULL) != ucl_flag(t, "control"))
					continue;
				joined = (strcmp(str(e0, "edge"), str(ep, "edge")) == 0
				    && strcmp(str(e1, "edge"), str(cp, "host")) == 0) ||
				    (strcmp(str(e1, "edge"), str(ep, "edge")) == 0 &&
				    strcmp(str(e0, "edge"), str(cp, "host")) == 0);
			}
			if (!joined) {
				snprintf(pl->why, sizeof(pl->why), "service %s: its "
				    "control plane host %s has no %stunnel to edge %s, "
				    "which it needs for the edge's routes to be "
				    "reflected", str(sw, "id"), server_name_of(str(cp,
				    "host")), str(cp, "ctvc") != NULL ? "control " :
				    "", server_name_of(str(ep, "edge")));
				return (false);
			}
		}
	}
	bird_build(pl, doc);
	dns_build(pl, doc);
	proxy_build(pl, doc);
	ids_build(pl, doc);
	dhcp_build(pl, doc);
	return (true);
}

static void
plan_free(struct plan *pl)
{

	if (pl->alloc != NULL)
		ucl_object_unref(pl->alloc);
	if (pl->lists != NULL)
		ucl_object_unref(pl->lists);
	if (pl->edges != NULL)
		ucl_object_unref(pl->edges);
	if (pl->tunnels != NULL)
		ucl_object_unref(pl->tunnels);
	if (pl->used != NULL)
		ucl_object_unref(pl->used);
	if (pl->notes != NULL)
		ucl_object_unref(pl->notes);
	if (pl->learned != NULL)
		ucl_object_unref(pl->learned);
	if (pl->boroutes != NULL)
		ucl_object_unref(pl->boroutes);
	if (pl->ready != NULL)
		ucl_object_unref(pl->ready);
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
	char		 sid[96], ifn[32], uri[256], peer[256], name[128];
	char		*json, *out, jail[64];
	const ucl_object_t *v, *i;
	ucl_object_iter_t it;
	ucl_object_t	*ans;
	int		 status;
	bool		 wg, uswe;

	if ((v = ucl_object_lookup(r->keys, ref)) != NULL)
		return (strdup(ucl_object_tostring(v)));
	wg = strncmp(ref, "${wg:", 5) == 0;
	uswe = strncmp(ref, "${uswe:", 7) == 0;
	ifn[0] = '\0';
	if (wg ? sscanf(ref, "${wg:%95[^:]:%31[^}]}", sid, ifn) != 2 : uswe ?
	    sscanf(ref, "${uswe:%95[^:]:%31[^}]}", sid, ifn) != 2 :
	    sscanf(ref, "${ipsec:%95[^}]}", sid) != 1) {
		snprintf(why, wlen, "%s is not a reference", ref);
		return (NULL);
	}
	if (!edge_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
	    sizeof(name), jail, sizeof(jail))) {
		snprintf(why, wlen, "no server %s", sid);
		return (NULL);
	}
	if (uswe)
		ans = sdwan_read(sid, NULL, 0, &status);
	else {
		json = hosts_net_in(uri, peer, name, jail[0] != '\0' ? jail :
		    NULL, wg ? "wireguard" : "ipsec", &status);
		ans = parse(json);
		free(json);
	}
	out = NULL;
	if (uswe) {
		/* The public half of that end's pair, as its agent tells it. */
		it = NULL;
		while ((i = ucl_object_iterate(at_path(ans, "data", "keys"), &it,
		    true)) != NULL)
			if (str(i, "interface") != NULL && strcmp(str(i,
			    "interface"), ifn) == 0 && str(i, "public") != NULL)
				out = strdup(str(i, "public"));
	} else if (wg) {
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
		snprintf(why, wlen, "%s has no %s key yet", name, wg || uswe ?
		    ifn : "IPsec");
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
		if (ucl_object_type(v) == UCL_ARRAY) {
			/* A list of words with a reference among them. */
			const ucl_object_t	*e;
			ucl_object_iter_t	 ait;
			ucl_object_t		*list;
			unsigned int		 k = 0;

			list = (ucl_object_t *)(uintptr_t)ucl_object_lookup(c,
			    ucl_object_key(v));
			ait = NULL;
			while ((e = ucl_object_iterate(v, &ait, true)) != NULL) {
				if (ucl_object_type(e) == UCL_STRING && strncmp(
				    ucl_object_tostring(e), "${", 2) == 0) {
					if ((val = resolve(r, ucl_object_tostring(e),
					    why, wlen)) == NULL) {
						ucl_object_unref(c);
						return (NULL);
					}
					ucl_object_unref(ucl_array_replace_index(
					    list, S(val), k));
					free(val);
				}
				k++;
			}
			continue;
		}
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
	char		 uri[256], peer[256], name[128], *json, jail[64];
	const char	*e, *st, *note;
	ucl_object_t	*ans, *jr, *jj;
	uint64_t	 id;
	time_t		 until;
	int		 status;

	if (!edge_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
	    sizeof(name), jail, sizeof(jail))) {
		snprintf(why, wlen, "no server %s", sid);
		return (false);
	}
	/* An edge that is a vnet jail: what its agent does, done there. */
	if (jail[0] != '\0' && !jail_kind_ok(str(j, "kind"), why, wlen))
		return (false);
	/* The probes, rules and steering are the console's own asks, not
	 * jobs of the host. */
	if (strncmp(str(j, "kind"), "sdwan-", 6) == 0) {
		ucl_object_t	*body;
		char		*text;
		bool		 ok;

		if (strcmp(str(j, "kind"), "sdwan-probes") == 0) {
			/* The edge's targets and links; a jail's apart from
			 * the host's. */
			body = ucl_object_typed_new(UCL_OBJECT);
			if (jail[0] != '\0')
				put(body, "jail", S(jail));
			put(body, "targets", ucl_object_lookup(j, "targets") !=
			    NULL ? ucl_object_copy(ucl_object_lookup(j,
			    "targets")) : ucl_object_typed_new(UCL_ARRAY));
			put(body, "links", ucl_object_lookup(j, "links") != NULL ?
			    ucl_object_copy(ucl_object_lookup(j, "links")) :
			    ucl_object_typed_new(UCL_ARRAY));
			text = emit(body);
			ucl_object_unref(body);
		} else {
			body = ucl_object_copy(j);
			(void)ucl_object_delete_key(body, "kind");
			if (jail[0] != '\0')
				put(body, "jail", S(jail));
			text = emit(body);
			ucl_object_unref(body);
		}
		json = hosts_sdwan_set(uri, peer, name, str(j, "kind") + 6,
		    text != NULL ? text : "{}", &status);
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
	jj = ucl_object_copy(j);
	if (jail[0] != '\0')
		put(jj, "jail", S(jail));
	/* In safe mode where the kind can be undone: the poll below, a
	 * fresh connection to the host, is what confirms it. */
	json = workflow_submit(uri, peer, name, jj, &status, &e, &note);
	if (note != NULL)
		log_msg(LOG_NOTICE, "sdwan apply: %s: %s %s: %s", name, str(j,
		    "kind"), str(j, "interface") != NULL ? str(j, "interface") :
		    "", note);
	ucl_object_unref(jj);
	if (json == NULL) {
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
	char		 uri[256], peer[256], name[128], *json, jail[64];
	const ucl_object_t *v;
	ucl_object_iter_t it;
	ucl_object_t	*ans;
	int64_t		 n;
	int		 status;

	/* A vnet jail's: its network's own (net.fibs is per vnet). */
	if (!edge_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
	    sizeof(name), jail, sizeof(jail)))
		return (-1);
	json = hosts_sysctl_in(uri, peer, name, jail[0] != '\0' ? jail : NULL,
	    oid, &status);
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
		 * services: the kernel's default, 0, is what works.  An
		 * own-table edge with its uplinks in tables of their own
		 * wants the opposite: their connected routes in the host's
		 * table too. */
		if (!ucl_flag(s, "allfibs") && sysctl_of(str(s, "server"),
		    "net.add_addr_allfibs") > 0) {
			step_set(r, s, "failed", "net.add_addr_allfibs is 1 on "
			    "the host: an interface's addresses are routed in "
			    "every table, so a service cannot have one of its "
			    "own; set it to 0 (sysctl.conf) first");
			return (false);
		}
		if (ucl_flag(s, "allfibs") && sysctl_of(str(s, "server"),
		    "net.add_addr_allfibs") == 0) {
			step_set(r, s, "failed", "net.add_addr_allfibs is 0 on "
			    "the host: an own-table edge whose uplinks are in "
			    "tables of their own needs their addresses' routes "
			    "in the host's table too; set it to 1 (sysctl.conf) "
			    "first");
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
	ucl_object_t		*s, *ap, *made_now, *failed_at;
	ucl_object_iter_t	 it;
	const char		*ch;
	int			 ph;
	bool			 ok, rolled;

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
	/* Then made, step by step, every edge before the next step; what
	 * this apply makes is remembered, to be taken away again should
	 * a later step fail. */
	made_now = ucl_object_typed_new(UCL_ARRAY);
	failed_at = NULL;
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
			if (ok)
				ucl_array_append(made_now, ucl_object_ref(s));
			else
				failed_at = s;
		}
	}
	/*
	 * A step failed: the apply is rolled back whole.  Everything it
	 * made before, the last first, is taken away again by the unmake
	 * jobs that making it left (what the apply took away at its start
	 * is not made again: it is gone).  The edges are left as they
	 * were before the apply, but for that.
	 */
	rolled = false;
	while (!ok && ucl_array_size(made_now) > 0) {
		ucl_object_t	*m = ucl_array_pop_last(made_now);
		bool		 undone;

		rolled = true;
		undone = do_unmake(r, m);
		step_set(r, m, undone ? "undone" : "undo failed", undone ?
		    "taken away again: a step after it failed" : str(m,
		    "detail"));
		ucl_object_unref(m);
	}
	ucl_object_unref(made_now);
	/* All made: only the allocations of what is there now are kept. */
	if (ok)
		put(r->st, "alloc", ucl_object_ref(r->alloc));
	ap = (ucl_object_t *)(uintptr_t)ucl_object_lookup(r->st, "apply");
	it = NULL;
	while (!ok && (s = (ucl_object_t *)(uintptr_t)ucl_object_iterate(
	    r->steps, &it, true)) != NULL)
		if (strcmp(str(s, "state"), "pending") == 0)
			put(s, "state", S("not run"));
	put(ap, "state", S(ok ? "done" : rolled ? "rolled back" : "failed"));
	if (failed_at != NULL)
		put(ap, "failed_step", S(str(failed_at, "title") != NULL ?
		    str(failed_at, "title") : str(failed_at, "key")));
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
		put(h, "state", S(ok ? "done" : rolled ? "rolled back" :
		    "failed"));
		if (failed_at != NULL)
			put(h, "failed_step", S(str(ap, "failed_step")));
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
	    rolled ? "rolled back" : "failed");
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


/* ---- The lists (MEF 138): feeds fetched by the console, pasted
 * lists, versioned and named by the security policies -------------------- */

#define	LISTS_FILE	"sdwan-lists.json"
#define	LIST_MAX_BYTES	(8 * 1024 * 1024)
#define	LIST_MAX_ENTRIES	200000
#define	FEED_INTERVAL_H	6

/*
 * What is kept: {"interval": hours, "feeds": [{"name", "url"} or
 * {"name", "entries": [...]} for a pasted list], "lists": {name:
 * {"version", "fetched_at", "entries", "error"}}, "fetched_at"}.
 */
static ucl_object_t *
lists_kept(void)
{
	ucl_object_t	*o;

	if ((o = store_load(LISTS_FILE)) == NULL)
		o = ucl_object_typed_new(UCL_OBJECT);
	if (ucl_object_lookup(o, "feeds") == NULL)
		put(o, "feeds", ucl_object_typed_new(UCL_ARRAY));
	if (ucl_object_lookup(o, "lists") == NULL)
		put(o, "lists", ucl_object_typed_new(UCL_OBJECT));
	return (o);
}

/* A name a list may have: letters, digits, - and _, 32 at most. */
static bool
list_name_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 32)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '-' && s[i] != '_')
			return (false);
	return (true);
}

/* An entry of a list: a prefix or address, or a domain name. */
static bool
list_entry_ok(const char *s)
{
	size_t	n, lab;

	if (s == NULL || (n = strlen(s)) == 0 || n > 253)
		return (false);
	lab = 0;
	for (; *s != '\0'; s++) {
		if (*s == '.' || *s == '/' || *s == ':') {
			lab = 0;
			continue;
		}
		if (!isalnum((unsigned char)*s) && *s != '-' && *s != '_')
			return (false);
		if (++lab > 63)
			return (false);
	}
	return (true);
}

/*
 * The text of a feed or a pasted list into entries: one each line,
 * what follows # or ; left out, blank lines too; false when one is
 * not an entry, or there are too many.
 */
static bool
list_parse(const char *text, ucl_object_t *entries, char *why, size_t wlen)
{
	const char	*p, *nl;
	char		 line[300];
	size_t		 n, k;

	for (p = text; *p != '\0'; p = *nl != '\0' ? nl + 1 : nl) {
		nl = p + strcspn(p, "\n");
		n = (size_t)(nl - p);
		if (n >= sizeof(line))
			n = sizeof(line) - 1;
		memcpy(line, p, n);
		line[n] = '\0';
		line[strcspn(line, "#;\r")] = '\0';
		for (k = 0; line[k] == ' ' || line[k] == '\t'; k++)
			;
		n = strlen(line + k);
		while (n > 0 && (line[k + n - 1] == ' ' || line[k + n - 1] == '\t'))
			line[k + --n] = '\0';
		if (n == 0)
			continue;
		if (!list_entry_ok(line + k)) {
			snprintf(why, wlen, "%.60s is not a prefix nor a domain",
			    line + k);
			return (false);
		}
		if (ucl_array_size(entries) >= LIST_MAX_ENTRIES) {
			snprintf(why, wlen, "more than %d entries", LIST_MAX_ENTRIES);
			return (false);
		}
		ucl_array_append(entries, S(line + k));
	}
	return (true);
}

/* Are two lists' entries the same, in order? */
static bool
list_same(const ucl_object_t *a, const ucl_object_t *b)
{
	const ucl_object_t	*x, *y;
	ucl_object_iter_t	 ix, iy;

	if (a == NULL || b == NULL || ucl_array_size(a) != ucl_array_size(b))
		return (false);
	ix = iy = NULL;
	while ((x = ucl_object_iterate(a, &ix, true)) != NULL) {
		y = ucl_object_iterate(b, &iy, true);
		if (y == NULL || strcmp(ucl_object_tostring_forced(x),
		    ucl_object_tostring_forced(y)) != 0)
			return (false);
	}
	return (true);
}

/*
 * A list's entries made the kept ones: a new version when they differ
 * from the last, the time noted, the error cleared.
 */
static void
list_keep(ucl_object_t *kept, const char *name, ucl_object_t *entries,
    const char *error)
{
	ucl_object_t		*all, *l;
	const ucl_object_t	*was;
	int64_t			 version;

	all = (ucl_object_t *)(uintptr_t)ucl_object_lookup(kept, "lists");
	was = ucl_object_lookup(all, name);
	version = was != NULL ? ucl_object_toint(ucl_object_lookup(was,
	    "version")) : 0;
	l = ucl_object_typed_new(UCL_OBJECT);
	if (entries != NULL) {
		if (was == NULL || !list_same(ucl_object_lookup(was, "entries"),
		    entries))
			version++;
		put(l, "entries", entries);
		put(l, "fetched_at", I(time(NULL)));
	} else {
		/* A failed fetch keeps the last. */
		put(l, "entries", was != NULL && ucl_object_lookup(was,
		    "entries") != NULL ? ucl_object_copy(ucl_object_lookup(was,
		    "entries")) : ucl_object_typed_new(UCL_ARRAY));
		if (was != NULL && ucl_object_lookup(was, "fetched_at") != NULL)
			put(l, "fetched_at", I(ucl_object_toint(ucl_object_lookup(
			    was, "fetched_at"))));
	}
	put(l, "version", I(version));
	put(l, "tried_at", I(time(NULL)));
	if (error != NULL)
		put(l, "error", S(error));
	put(all, name, l);
}

/*
 * Every feed fetched by the console's host with the base system's
 * libfetch (file, http and https), each pasted list taken as it is;
 * what is kept written.  Run by the manager at the interval, and on
 * request.
 */
static void
lists_fetch(ucl_object_t *kept, const char *only)
{
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;
	ucl_object_t		*entries;
	FILE			*fp;
	char			*buf, why[200];
	size_t			 len, n;

	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(kept, "feeds"), &it,
	    true)) != NULL) {
		if (str(f, "name") == NULL || (only != NULL && strcmp(str(f,
		    "name"), only) != 0))
			continue;
		entries = ucl_object_typed_new(UCL_ARRAY);
		if (str(f, "url") == NULL) {
			/* Pasted: its entries are what was given. */
			if (ucl_object_lookup(f, "entries") != NULL) {
				ucl_object_unref(entries);
				entries = ucl_object_copy(ucl_object_lookup(f,
				    "entries"));
			}
			list_keep(kept, str(f, "name"), entries, NULL);
			continue;
		}
		fetchTimeout = 30;
		if ((fp = fetchGetURL(str(f, "url"), "")) == NULL) {
			ucl_object_unref(entries);
			list_keep(kept, str(f, "name"), NULL, fetchLastErrString);
			thread_log(LOG_WARNING, "sdwan: list %s not fetched from "
			    "%s: %s", str(f, "name"), str(f, "url"),
			    fetchLastErrString);
			continue;
		}
		if ((buf = malloc(LIST_MAX_BYTES)) == NULL) {
			fclose(fp);
			ucl_object_unref(entries);
			list_keep(kept, str(f, "name"), NULL, "out of memory");
			continue;
		}
		for (len = 0; len < LIST_MAX_BYTES - 1; len += n)
			if ((n = fread(buf + len, 1, LIST_MAX_BYTES - 1 - len, fp))
			    == 0)
				break;
		buf[len] = '\0';
		fclose(fp);
		if (len >= LIST_MAX_BYTES - 1) {
			free(buf);
			ucl_object_unref(entries);
			list_keep(kept, str(f, "name"), NULL, "more than 8 MB");
			continue;
		}
		if (!list_parse(buf, entries, why, sizeof(why))) {
			free(buf);
			ucl_object_unref(entries);
			list_keep(kept, str(f, "name"), NULL, why);
			thread_log(LOG_WARNING, "sdwan: list %s from %s: %s", str(f,
			    "name"), str(f, "url"), why);
			continue;
		}
		free(buf);
		list_keep(kept, str(f, "name"), entries, NULL);
	}
	put(kept, "fetched_at", I(time(NULL)));
	pthread_mutex_lock(&st_lock);
	(void)store_save(LISTS_FILE, kept);
	pthread_mutex_unlock(&st_lock);
}

/*
 * The shortest Duration (MEF 138, Tables 10-16: the time between
 * updates of the threat data) of the function policies that name
 * lists; 0 for none.
 */
static int64_t
lists_duration(void)
{
	ucl_object_t		*doc;
	const ucl_object_t	*sw, *f;
	ucl_object_iter_t	 it, fit;
	int64_t			 d, min = 0;

	if ((doc = sdwan_load()) == NULL)
		return (0);
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL) {
		fit = NULL;
		while ((f = ucl_object_iterate(ucl_object_lookup(sw,
		    "security_function_policies"), &fit, true)) != NULL) {
			if (ucl_object_lookup(f, "lists") == NULL ||
			    (d = ucl_object_toint(ucl_object_lookup(f,
			    "duration"))) <= 0)
				continue;
			if (min == 0 || d < min)
				min = d;
		}
	}
	ucl_object_unref(doc);
	return (min);
}

/* The feeds fetched again when the interval has passed, or the
 * shortest Duration of the function policies naming lists. */
static void
lists_tick(time_t now)
{
	ucl_object_t	*kept;
	int64_t		 hours, d;

	kept = lists_kept();
	hours = ucl_object_lookup(kept, "interval") != NULL ? ucl_object_toint(
	    ucl_object_lookup(kept, "interval")) : FEED_INTERVAL_H;
	if ((d = lists_duration()) > 0 && d < hours)
		hours = d;
	if (ucl_array_size(ucl_object_lookup(kept, "feeds")) > 0 && now -
	    ucl_object_toint(ucl_object_lookup(kept, "fetched_at")) >= hours *
	    3600)
		lists_fetch(kept, NULL);
	ucl_object_unref(kept);
}

/* Does a list of the name exist, as kept or as a feed to come? */
bool
sdwan_list_exists(const char *name)
{
	ucl_object_t	*kept;
	bool		 yes;

	kept = lists_kept();
	yes = by(ucl_object_lookup(kept, "feeds"), "name", name) != NULL ||
	    ucl_object_lookup(ucl_object_lookup(kept, "lists"), name) != NULL;
	ucl_object_unref(kept);
	return (yes);
}

/*
 * GET /api/sdwan/lists: the feeds and the pasted lists, the interval,
 * and each list as kept (version, fetched_at, count, error).  PUT: the
 * feeds and the interval, checked, the pasted lists' entries parsed;
 * what was kept of a list that is gone, gone.  POST
 * /api/sdwan/lists/fetch, {"name"} or {}: fetched now.
 */
int
api_sdwan_lists(struct http_request *req)
{
	ucl_object_t		*kept, *body, *out, *feeds, *f2, *ls, *entries;
	const ucl_object_t	*f, *l;
	ucl_object_iter_t	 it;
	char			 why[200];
	bool			 fetch;

	fetch = strcmp(req->path, "/api/sdwan/lists/fetch") == 0;
	if (req->method == HTTP_METHOD_GET) {
		if (!guard(req, false))
			return (WEB_OK);
		kept = lists_kept();
		out = ucl_object_typed_new(UCL_OBJECT);
		put(out, "interval", I(ucl_object_lookup(kept, "interval") != NULL
		    ? ucl_object_toint(ucl_object_lookup(kept, "interval")) :
		    FEED_INTERVAL_H));
		put(out, "feeds", ucl_object_copy(ucl_object_lookup(kept, "feeds")));
		ls = ucl_object_typed_new(UCL_OBJECT);
		it = NULL;
		while ((l = ucl_object_iterate(ucl_object_lookup(kept, "lists"),
		    &it, true)) != NULL) {
			f2 = ucl_object_typed_new(UCL_OBJECT);
			put(f2, "version", I(ucl_object_toint(ucl_object_lookup(l,
			    "version"))));
			if (ucl_object_lookup(l, "fetched_at") != NULL)
				put(f2, "fetched_at", I(ucl_object_toint(
				    ucl_object_lookup(l, "fetched_at"))));
			put(f2, "count", I((int64_t)ucl_array_size(ucl_object_lookup(
			    l, "entries"))));
			if (str(l, "error") != NULL)
				put(f2, "error", S(str(l, "error")));
			put(ls, ucl_object_key(l), f2);
		}
		put(out, "lists", ls);
		ucl_object_unref(kept);
		return (reply_json(req, 200, out));
	}
	if (!guard(req, true))
		return (WEB_OK);
	kept = lists_kept();
	if (fetch) {
		body = read_json(req);
		lists_fetch(kept, body != NULL ? str(body, "name") : NULL);
		if (body != NULL)
			ucl_object_unref(body);
		ucl_object_unref(kept);
		out = ucl_object_typed_new(UCL_OBJECT);
		put(out, "fetched", B(true));
		return (reply_json(req, 200, out));
	}
	if ((body = read_json(req)) == NULL) {
		ucl_object_unref(kept);
		return (reply_error(req, 400, "json", "an object with feeds and "
		    "interval"));
	}
	if (ucl_object_lookup(body, "interval") != NULL && (ucl_object_type(
	    ucl_object_lookup(body, "interval")) != UCL_INT || ucl_object_toint(
	    ucl_object_lookup(body, "interval")) < 1 || ucl_object_toint(
	    ucl_object_lookup(body, "interval")) > 24 * 30)) {
		ucl_object_unref(body);
		ucl_object_unref(kept);
		return (reply_error(req, 400, "interval", "interval is hours, 1 "
		    "to 720"));
	}
	feeds = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(body, "feeds"), &it,
	    true)) != NULL) {
		if (!list_name_ok(str(f, "name")) || by(feeds, "name", str(f,
		    "name")) != NULL || (str(f, "url") == NULL && str(f, "text") ==
		    NULL) || ucl_array_size(feeds) >= 64) {
			ucl_object_unref(feeds);
			ucl_object_unref(body);
			ucl_object_unref(kept);
			return (reply_error(req, 400, "feeds", "each feed a name "
			    "of letters, digits, - and _ (32 at most, once) and a "
			    "url, or text pasted; 64 at most"));
		}
		if (str(f, "url") != NULL && (strlen(str(f, "url")) > 500 || (
		    strncmp(str(f, "url"), "https://", 8) != 0 && strncmp(str(f,
		    "url"), "http://", 7) != 0 && strncmp(str(f, "url"),
		    "file:///", 8) != 0))) {
			ucl_object_unref(feeds);
			ucl_object_unref(body);
			ucl_object_unref(kept);
			return (reply_error(req, 400, "feeds", "a feed's url is "
			    "https, http or file"));
		}
		f2 = ucl_object_typed_new(UCL_OBJECT);
		put(f2, "name", S(str(f, "name")));
		if (str(f, "url") != NULL)
			put(f2, "url", S(str(f, "url")));
		else {
			entries = ucl_object_typed_new(UCL_ARRAY);
			if (!list_parse(str(f, "text"), entries, why, sizeof(why))) {
				ucl_object_unref(entries);
				ucl_object_unref(f2);
				ucl_object_unref(feeds);
				ucl_object_unref(body);
				ucl_object_unref(kept);
				return (reply_error(req, 400, "feeds", "list %s: %s",
				    str(f, "name"), why));
			}
			put(f2, "entries", entries);
		}
		ucl_array_append(feeds, f2);
	}
	put(kept, "feeds", feeds);
	if (ucl_object_lookup(body, "interval") != NULL)
		put(kept, "interval", I(ucl_object_toint(ucl_object_lookup(body,
		    "interval"))));
	/* What was kept of a list that is no more, gone. */
	{
		ucl_object_t		*all = (ucl_object_t *)(uintptr_t)
		    ucl_object_lookup(kept, "lists");
		ucl_object_t		*gone = ucl_object_typed_new(UCL_ARRAY);
		const ucl_object_t	*g;
		ucl_object_iter_t	 git;

		it = NULL;
		while ((l = ucl_object_iterate(all, &it, true)) != NULL)
			if (by(feeds, "name", ucl_object_key(l)) == NULL)
				ucl_array_append(gone, S(ucl_object_key(l)));
		git = NULL;
		while ((g = ucl_object_iterate(gone, &git, true)) != NULL)
			(void)ucl_object_delete_key(all, ucl_object_tostring(g));
		ucl_object_unref(gone);
	}
	/* The pasted ones take effect at once; the feeds at the next
	 * fetch, or now when asked. */
	lists_fetch(kept, "");
	it = NULL;
	while ((f = ucl_object_iterate(feeds, &it, true)) != NULL)
		if (str(f, "url") == NULL)
			lists_fetch(kept, str(f, "name"));
	ucl_object_unref(body);
	ucl_object_unref(kept);
	out = ucl_object_typed_new(UCL_OBJECT);
	put(out, "kept", B(true));
	return (reply_json(req, 200, out));
}

static bool	 apply_now(ucl_object_t *, char *, size_t);

/* ---- Identities: issued, listed, revoked ------------------- */

/* A WireGuard key pair, X25519, both halves in base64. */
static bool
wg_keypair(char *priv, size_t plen, char *pub, size_t publen)
{
	EVP_PKEY	*k;
	unsigned char	 raw[32];
	size_t		 n;
	char		*b64;
	bool		 ok;

	if ((k = EVP_PKEY_Q_keygen(NULL, NULL, "X25519")) == NULL)
		return (false);
	ok = false;
	n = sizeof(raw);
	if (EVP_PKEY_get_raw_private_key(k, raw, &n) == 1 && n == sizeof(raw) &&
	    b64_encode(raw, n, &b64) == WEB_OK) {
		snprintf(priv, plen, "%s", b64);
		explicit_bzero(b64, strlen(b64));
		free(b64);
		n = sizeof(raw);
		if (EVP_PKEY_get_raw_public_key(k, raw, &n) == 1 && n ==
		    sizeof(raw) && b64_encode(raw, n, &b64) ==
		    WEB_OK) {
			snprintf(pub, publen, "%s", b64);
			free(b64);
			ok = true;
		}
	}
	explicit_bzero(raw, sizeof(raw));
	EVP_PKEY_free(k);
	return (ok);
}

/*
 * POST /api/wg/keypair: a fresh WireGuard key pair for a client of a
 * host's wg interface (the WireGuard tab's + client), both halves in
 * the reply and kept nowhere, and a preshared key: the page puts the
 * private half and the preshared key in the client's configuration,
 * shown once, and gives the host the public half and the preshared key.
 */
int
api_wg_keypair(struct http_request *req)
{
	ucl_object_t	*out;
	unsigned char	 raw[32];
	char		 priv[64], pub[64], *psk;

	if (!guard(req, true))
		return (WEB_OK);
	if (!wg_keypair(priv, sizeof(priv), pub, sizeof(pub)))
		return (reply_error(req, 500, "keygen", "no X25519 key pair"));
	out = ucl_object_typed_new(UCL_OBJECT);
	put(out, "private_key", S(priv));
	put(out, "public_key", S(pub));
	explicit_bzero(priv, sizeof(priv));
	/* A preshared key too, 32 random bytes, for the client to use. */
	arc4random_buf(raw, sizeof(raw));
	if (b64_encode(raw, sizeof(raw), &psk) == WEB_OK) {
		put(out, "preshared_key", S(psk));
		explicit_bzero(psk, strlen(psk));
		free(psk);
	}
	explicit_bzero(raw, sizeof(raw));
	return (reply_json(req, 200, out));
}

/* The service, the remote end point and its remote, by their ids. */
static const ucl_object_t *
remote_of(const ucl_object_t *doc, const char *swvc, const char *epid,
    const ucl_object_t **swp, const ucl_object_t **epp)
{
	const ucl_object_t	*sw, *ep;

	if ((sw = by(ucl_object_lookup(doc, "swvcs"), "id", swvc)) == NULL ||
	    (ep = by(ucl_object_lookup(sw, "end_points"), "id", epid)) == NULL
	    || ucl_object_lookup(ep, "remote") == NULL)
		return (NULL);
	*swp = sw;
	*epp = ep;
	return (ucl_object_lookup(ep, "remote"));
}

/*
 * An identity's session: its peer as the edge's wg(8) tells it,
 * the last handshake and the bytes each way; the edges' reads kept
 * by server id for the one listing.
 */
static void
identity_session(ucl_object_t *reads, const char *sid, const char *ifn,
    const char *pubkey, ucl_object_t *into)
{
	const ucl_object_t	*ans, *i, *p;
	ucl_object_iter_t	 it, pit;
	ucl_object_t		*s, *got;
	char			 uri[256], peer[256], name[128], *json, jail[64];
	int			 status;

	if ((ans = ucl_object_lookup(reads, sid)) == NULL) {
		got = NULL;
		if (edge_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
		    sizeof(name), jail, sizeof(jail))) {
			json = hosts_net_in(uri, peer, name, jail[0] != '\0' ?
			    jail : NULL, "wireguard", &status);
			got = parse(json);
			free(json);
		}
		if (got == NULL)
			got = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(reads, got, sid, 0, true);
		ans = got;
	}
	it = NULL;
	while ((i = ucl_object_iterate(at_path(ans, "data", "interfaces"), &it,
	    true)) != NULL) {
		if (str(i, "name") == NULL || strcmp(str(i, "name"), ifn) != 0)
			continue;
		pit = NULL;
		while ((p = ucl_object_iterate(ucl_object_lookup(i, "peers"), &pit,
		    true)) != NULL) {
			if (str(p, "public-key") == NULL || pubkey == NULL || strcmp(
			    str(p, "public-key"), pubkey) != 0)
				continue;
			s = ucl_object_typed_new(UCL_OBJECT);
			put(s, "handshake", I(ucl_object_toint(ucl_object_lookup(p,
			    "latest-handshake"))));
			put(s, "rx", I(ucl_object_toint(ucl_object_lookup(p, "rx"))));
			put(s, "tx", I(ucl_object_toint(ucl_object_lookup(p, "tx"))));
			if (str(p, "endpoint") != NULL)
				put(s, "endpoint", S(str(p, "endpoint")));
			put(s, "now", I(ucl_object_toint(at_path(ans, "data", "now"))));
			put(into, "session", s);
			return;
		}
	}
}

/*
 * The identities of every service's remote end points, each with its
 * address, as the plan gives it, whether it is still authorised, and
 * its session where the edge has its peer.
 */
static ucl_object_t *
identities_list(const ucl_object_t *doc, ucl_object_t *st)
{
	struct plan		 pl;
	ucl_object_t		*arr, *o, *reads;
	const ucl_object_t	*sw, *ep, *r, *id;
	ucl_object_iter_t	 it, eit, iit;
	char			 addr[80];
	time_t			 now;
	bool			 planned;

	arr = ucl_object_typed_new(UCL_ARRAY);
	reads = ucl_object_typed_new(UCL_OBJECT);
	host_refs();
	planned = plan_build(&pl, doc, st);
	now = time(NULL);
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL) {
		eit = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
		    &eit, true)) != NULL) {
			if ((r = ucl_object_lookup(ep, "remote")) == NULL)
				continue;
			iit = NULL;
			while ((id = ucl_object_iterate(ucl_object_lookup(r,
			    "identities"), &iit, true)) != NULL) {
				o = ucl_object_typed_new(UCL_OBJECT);
				put(o, "swvc", S(str(sw, "id")));
				put(o, "end_point", S(str(ep, "id")));
				put(o, "edge", S(str(ep, "edge")));
				put(o, "interface", S(str(r, "interface")));
				put(o, "name", S(str(id, "name")));
				put(o, "zone", S(ident_zone(r, id)));
				if (str(id, "group") != NULL)
					put(o, "group", S(str(id, "group")));
				put(o, "public_key", S(str(id, "public_key")));
				put(o, "user", B(ucl_flag(id, "user")));
				put(o, "issued", I(ucl_object_lookup(id, "issued") !=
				    NULL ? ucl_object_toint(ucl_object_lookup(id,
				    "issued")) : 0));
				if (ucl_object_lookup(r, "reauth") != NULL)
					put(o, "expires", I((ucl_object_lookup(id,
					    "issued") != NULL ? ucl_object_toint(
					    ucl_object_lookup(id, "issued")) : 0) +
					    ucl_object_toint(ucl_object_lookup(r,
					    "reauth"))));
				put(o, "live", B(identity_live(r, id, now)));
				if (planned && remote_addr(&pl, sw, ep, str(id, "name"),
				    addr, sizeof(addr)))
					put(o, "address", S(addr));
				identity_session(reads, str(ep, "edge"), str(r,
				    "interface"), str(id, "public_key"), o);
				ucl_array_append(arr, o);
			}
		}
	}
	ucl_object_unref(reads);
	plan_free(&pl);
	return (arr);
}

/*
 * A client's WireGuard configuration for an identity, shown once: its
 * address and the private half; the edge's wg key, its address on the
 * underlay and port, the service's prefixes, and the DNS filter where
 * the service has one.
 */
static char *
identity_config(struct plan *pl, const ucl_object_t *doc,
    const ucl_object_t *sw, const ucl_object_t *ep, const char *name,
    const char *priv)
{
	const ucl_object_t	*r, *edge, *ue, *u, *e2, *p;
	ucl_object_iter_t	 it, pit;
	ucl_object_t		*pfx, *ans;
	struct buf		*b;
	struct net		 n;
	char			 addr[80], own[80], uri[256], peer[256], hname[128];
	char			*json, *text, jail[64];
	const char		*endpoint, *key;
	int			 status, k;

	r = ucl_object_lookup(ep, "remote");
	if (!net_parse(str(r, "prefix"), &n) || !remote_addr(pl, sw, ep, name,
	    addr, sizeof(addr)) || !remote_addr(pl, sw, ep, NULL, own,
	    sizeof(own)))
		return (NULL);
	/* The edge's key, as its agent tells it; none before the apply. */
	key = NULL;
	ans = NULL;
	if (edge_ref(str(ep, "edge"), uri, sizeof(uri), peer, sizeof(peer),
	    hname, sizeof(hname), jail, sizeof(jail))) {
		json = hosts_net_in(uri, peer, hname, jail[0] != '\0' ? jail :
		    NULL, "wireguard", &status);
		ans = parse(json);
		free(json);
		it = NULL;
		while ((e2 = ucl_object_iterate(at_path(ans, "data", "interfaces"),
		    &it, true)) != NULL)
			if (str(e2, "name") != NULL && strcmp(str(e2, "name"), str(r,
			    "interface")) == 0 && str(e2, "public-key") != NULL)
				key = str(e2, "public-key");
	}
	/* Where the edge is reached: a public UCS's address, else any. */
	endpoint = NULL;
	edge = by(ucl_object_lookup(doc, "edges"), "server", str(ep, "edge"));
	it = NULL;
	while ((ue = ucl_object_iterate(ucl_object_lookup(edge, "ucs_end_points"),
	    &it, true)) != NULL) {
		if (str(ue, "address") == NULL)
			continue;
		u = by(ucl_object_lookup(doc, "ucs"), "id", str(ue, "ucs"));
		if (endpoint == NULL || (str(u, "type") != NULL && strcmp(str(u,
		    "type"), "public") == 0))
			endpoint = str(ue, "address");
	}
	b = buf_alloc(2048);
	buf_appendf(b, "# %s, identity %s of %s: shown once, kept nowhere "
	    "by the console.\n[Interface]\nPrivateKey = %s\nAddress = %s/%d\n",
	    str(sw, "id"), name, str(ep, "id"), priv, addr, n.len);
	if (svc_resolver(sw))
		buf_appendf(b, "DNS = %s\n", own);
	buf_appendf(b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s%s%s:%jd\n"
	    "AllowedIPs = ", key != NULL ? key : "(the edge's, once applied: wg "
	    "show the interface public-key there)", endpoint != NULL && strchr(
	    endpoint, ':') != NULL ? "[" : "", endpoint != NULL ? endpoint :
	    "(the edge's address)", endpoint != NULL && strchr(endpoint, ':') !=
	    NULL ? "]" : "", (intmax_t)(ucl_object_lookup(r, "port") != NULL ?
	    ucl_object_toint(ucl_object_lookup(r, "port")) : WG_REMOTE_PORT));
	/* The service's prefixes: every end point's, this one's with. */
	k = 0;
	it = NULL;
	while ((e2 = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		pfx = ucl_object_typed_new(UCL_ARRAY);
		uni_prefixes(e2, pfx);
		pit = NULL;
		while ((p = ucl_object_iterate(pfx, &pit, true)) != NULL)
			buf_appendf(b, "%s%s", k++ > 0 ? ", " : "",
			    ucl_object_tostring(p));
		ucl_object_unref(pfx);
	}
	buf_appendf(b, "\nPersistentKeepalive = 25\n");
	text = buf_stringify(b, NULL);
	text = strdup(text);
	buf_free(b);
	if (ans != NULL)
		ucl_object_unref(ans);
	return (text);
}

/*
 * /api/sdwan/identities: GET lists every remote end point's
 * identities with their addresses; POST {swvc, end_point, name, zone,
 * user} issues one, a console user's (a sign-in key's name) or a
 * name's, its key pair made here, the private half in the WireGuard
 * configuration answered once and kept nowhere, the identity in the
 * document in place of one of the name, and the edges applied; DELETE
 * ?swvc=&end_point=&name= revokes one, its peer removed by the apply
 * that follows.
 */
int
api_sdwan_identities(struct http_request *req)
{
	ucl_object_t		*doc, *st, *body, *out, *ids, *id, *o;
	const ucl_object_t	*sw, *ep, *r, *e, *g;
	ucl_object_iter_t	 it;
	struct plan		 pl;
	char			 where[300], rzone[64];
	char			 why[300], priv[64], pub[64], *v, *swvc, *epid;
	char			*name, *conf;
	const char		*zone, *group;
	bool			 user, applied;
	int			 i;

	if (req->method == HTTP_METHOD_GET) {
		if (!guard(req, false))
			return (WEB_OK);
		doc = sdwan_load();
		pthread_mutex_lock(&st_lock);
		st = state_load();
		pthread_mutex_unlock(&st_lock);
		out = ucl_object_typed_new(UCL_OBJECT);
		put(out, "identities", identities_list(doc, st));
		ucl_object_unref(doc);
		ucl_object_unref(st);
		return (reply_json(req, 200, out));
	}
	if (!guard(req, true))
		return (WEB_OK);
	if (req->method == HTTP_METHOD_DELETE) {
		swvc = epid = name = NULL;
		(void)http_argument_get_string(req, "swvc", &swvc);
		(void)http_argument_get_string(req, "end_point", &epid);
		(void)http_argument_get_string(req, "name", &name);
		doc = sdwan_load();
		if ((r = remote_of(doc, swvc, epid, &sw, &ep)) == NULL) {
			ucl_object_unref(doc);
			return (reply_error(req, 404, "end_point", "no remote end "
			    "point %s in service %s", epid != NULL ? epid : "?", swvc
			    != NULL ? swvc : "?"));
		}
		ids = (ucl_object_t *)(uintptr_t)ucl_object_lookup(r,
		    "identities");
		i = 0;
		it = NULL;
		while ((e = ucl_object_iterate(ids, &it, true)) != NULL && (str(e,
		    "name") == NULL || name == NULL || strcmp(str(e, "name"), name)
		    != 0))
			i++;
		if (e == NULL) {
			ucl_object_unref(doc);
			return (reply_error(req, 404, "identity", "no identity %s",
			    name != NULL ? name : "?"));
		}
		snprintf(rzone, sizeof(rzone), "%s", ident_zone(r, e) != NULL ?
		    ident_zone(r, e) : "");
		ucl_object_unref(ucl_array_delete(ids, (ucl_object_t *)(uintptr_t)
		    e));
		if (sdwan_store(doc, why, sizeof(why)) != 0) {
			ucl_object_unref(doc);
			return (reply_error(req, 409, "invalid", "%s", why));
		}
		/* A Subject Actor's access taken away (MEF 118.1 §15). */
		snprintf(where, sizeof(where), "%s, end point %s of %s", str(ep,
		    "edge") != NULL ? server_name_of(str(ep, "edge")) : "?", epid,
		    swvc);
		audit_add("identity-revoked", "Block", rzone, "its WireGuard peer "
		    "taken away by the apply, its address out of the zone table",
		    where, session_who(req), "identity %s revoked by the System "
		    "Administrator", name);
		why[0] = '\0';
		applied = apply_now(doc, why, sizeof(why));
		log_msg(LOG_NOTICE, "identity %s of %s/%s revoked%s%s", name, swvc,
		    epid, applied ? ", the edges applied" : ": no apply, ",
		    applied ? "" : why);
		out = ucl_object_typed_new(UCL_OBJECT);
		put(out, "revoked", S(name));
		put(out, "applied", B(applied));
		if (!applied)
			put(out, "why", S(why));
		return (reply_json(req, 200, out));
	}
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "a JSON body: swvc, "
		    "end_point, name, zone or group, user"));
	swvc = (char *)(uintptr_t)str(body, "swvc");
	epid = (char *)(uintptr_t)str(body, "end_point");
	name = (char *)(uintptr_t)str(body, "name");
	zone = str(body, "zone");
	user = ucl_flag(body, "user");
	for (i = 0; name != NULL && name[i] != '\0'; i++)
		if (name[i] < 0x20 || name[i] > 0x7e)
			break;
	if (name == NULL || name[0] == '\0' || name[i] != '\0' || i > 64) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "name", "an identity's name is "
		    "printable ASCII, 64 at most"));
	}
	if (user && !cred_named(name)) {
		ucl_object_unref(body);
		return (reply_error(req, 404, "user", "no console user %s: no "
		    "sign-in key of that name", name));
	}
	doc = sdwan_load();
	if ((r = remote_of(doc, swvc, epid, &sw, &ep)) == NULL) {
		ucl_object_unref(doc);
		ucl_object_unref(body);
		return (reply_error(req, 404, "end_point", "no remote end point "
		    "%s in service %s", epid != NULL ? epid : "?", swvc != NULL ?
		    swvc : "?"));
	}
	/* In a group of the remote's, the zone is the group's. */
	group = str(body, "group");
	if (group != NULL && group[0] == '\0')
		group = NULL;
	if (group != NULL) {
		if ((g = by(ucl_object_lookup(r, "groups"), "name", group)) ==
		    NULL) {
			ucl_object_unref(doc);
			ucl_object_unref(body);
			return (reply_error(req, 400, "group", "the group is one "
			    "of end point %s's", epid));
		}
		zone = str(g, "zone");
	} else if (zone == NULL || by(ucl_object_lookup(sw, "zones"), "name",
	    zone) == NULL) {
		ucl_object_unref(doc);
		ucl_object_unref(body);
		return (reply_error(req, 400, "zone", "the zone is one of service "
		    "%s's", swvc));
	}
	if (!wg_keypair(priv, sizeof(priv), pub, sizeof(pub))) {
		ucl_object_unref(doc);
		ucl_object_unref(body);
		return (reply_error(req, 500, "key", "no key pair could be made"));
	}
	/* In place of one of the name: issued again, with a new pair. */
	ids = (ucl_object_t *)(uintptr_t)ucl_object_lookup(r, "identities");
	if (ids == NULL) {
		ids = ucl_object_typed_new(UCL_ARRAY);
		ucl_object_insert_key((ucl_object_t *)(uintptr_t)r, ids,
		    "identities", 0, false);
	}
	it = NULL;
	while ((e = ucl_object_iterate(ids, &it, true)) != NULL)
		if (str(e, "name") != NULL && strcmp(str(e, "name"), name) == 0) {
			ucl_object_unref(ucl_array_delete(ids, (ucl_object_t *)
			    (uintptr_t)e));
			break;
		}
	id = ucl_object_typed_new(UCL_OBJECT);
	put(id, "name", S(name));
	if (group != NULL)
		put(id, "group", S(group));
	else
		put(id, "zone", S(zone));
	put(id, "public_key", S(pub));
	put(id, "issued", I(time(NULL)));
	if (user)
		put(id, "user", B(true));
	ucl_array_append(ids, id);
	if (sdwan_store(doc, why, sizeof(why)) != 0) {
		explicit_bzero(priv, sizeof(priv));
		ucl_object_unref(doc);
		ucl_object_unref(body);
		return (reply_error(req, 409, "invalid", "%s", why));
	}
	/* Its configuration, from the plan the apply will make. */
	pthread_mutex_lock(&st_lock);
	st = state_load();
	pthread_mutex_unlock(&st_lock);
	host_refs();
	conf = NULL;
	if (plan_build(&pl, doc, st))
		conf = identity_config(&pl, doc, sw, ep, name, priv);
	plan_free(&pl);
	ucl_object_unref(st);
	explicit_bzero(priv, sizeof(priv));
	/* A Subject Actor authenticated by its key and let in, its Role
	 * its zone (MEF 118.1 §9.1). */
	snprintf(where, sizeof(where), "%s, end point %s of %s", str(ep,
	    "edge") != NULL ? server_name_of(str(ep, "edge")) : "?", epid, swvc);
	audit_add("identity-issued", "Allow", zone, "a WireGuard peer, its key "
	    "pair made by the console, the private half given once", where,
	    session_who(req), "identity %s%s issued by the System "
	    "Administrator", name, user ? ", a console user's," : "");
	why[0] = '\0';
	applied = apply_now(doc, why, sizeof(why));
	log_msg(LOG_NOTICE, "identity %s of %s/%s issued%s%s%s", name, swvc,
	    epid, user ? ", a console user's" : "", applied ? ", the edges "
	    "applied" : ": no apply, ", applied ? "" : why);
	out = ucl_object_typed_new(UCL_OBJECT);
	put(out, "name", S(name));
	put(out, "public_key", S(pub));
	o = ucl_object_typed_new(UCL_OBJECT);
	put(out, "config", conf != NULL ? S(conf) : ucl_object_typed_new(
	    UCL_NULL));
	ucl_object_unref(o);
	if (conf != NULL) {
		explicit_bzero(conf, strlen(conf));
		free(conf);
	}
	put(out, "applied", B(applied));
	if (!applied)
		put(out, "why", S(why));
	ucl_object_unref(body);
	(void)v;
	return (reply_json(req, 200, out));
}

/*
 * Each tick: an identity whose re-authorisation ran out since the last
 * is a peer to remove, by an apply of the document as it is.
 */
static void
identities_tick(const ucl_object_t *doc, time_t now)
{
	static time_t		 prev;
	const ucl_object_t	*sw, *ep, *r, *id;
	ucl_object_iter_t	 it, eit, iit;
	char			 why[300];
	int64_t			 exp;
	bool			 due;

	due = false;
	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"), &it,
	    true)) != NULL) {
		eit = NULL;
		while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
		    &eit, true)) != NULL) {
			if ((r = ucl_object_lookup(ep, "remote")) == NULL ||
			    ucl_object_lookup(r, "reauth") == NULL)
				continue;
			iit = NULL;
			while ((id = ucl_object_iterate(ucl_object_lookup(r,
			    "identities"), &iit, true)) != NULL) {
				exp = (ucl_object_lookup(id, "issued") != NULL ?
				    ucl_object_toint(ucl_object_lookup(id, "issued")) :
				    0) + ucl_object_toint(ucl_object_lookup(r,
				    "reauth"));
				if (prev != 0 && exp > prev && exp <= now) {
					char	where[300];

					due = true;
					/* Time-based Continuous Monitoring (MEF
					 * 118.1 §18.1): the Subject Actor Blocked
					 * until it authenticates again. */
					snprintf(where, sizeof(where), "%s, end "
					    "point %s of %s", str(ep, "edge") != NULL
					    ? server_name_of(str(ep, "edge")) : "?",
					    str(ep, "id"), str(sw, "id"));
					audit_add("reauthorisation-due", "Block",
					    ident_zone(r, id) != NULL ? ident_zone(r, id)
					    : "", "its peer taken away by the apply",
					    where, "Continuous Monitoring, by time",
					    "identity %s: its re-authorisation "
					    "interval, %jd s, ran out; issued again, "
					    "it comes back", str(id, "name"),
					    (intmax_t)ucl_object_toint(
					    ucl_object_lookup(r, "reauth")));
				}
			}
		}
	}
	prev = now;
	if (due && !apply_now(ucl_object_copy(doc), why, sizeof(why)))
		log_msg(LOG_NOTICE, "identities: an authorisation ran out, no "
		    "apply: %s", why);
}

/* ---- The record: what the edges' security rules logged ----- */

/*
 * GET /api/sdwan/record[.csv]?swvc=&policy=&edge=&since=: the edges'
 * records (each agent keeps a day of what its logged rules saw) read
 * now and put together, newest first, each with its edge; a service
 * or a policy picks by the rules' comments, since by the time.  As
 * CSV with .csv.
 */
int
api_sdwan_record(struct http_request *req)
{
	ucl_object_t		*doc, *out, *all, *e2;
	const ucl_object_t	*edge, *e, *swvc, *policy, *since, *only;
	ucl_object_iter_t	 it, eit;
	char			 name[128], *v;
	char			 want[130];
	ucl_object_t		*ans;
	struct buf		*b;
	int			 status;
	int64_t			 from;
	bool			 csv;

	if (!guard(req, false))
		return (WEB_OK);
	csv = strstr(req->path, ".csv") != NULL;
	swvc = policy = since = only = NULL;
	want[0] = '\0';
	if (http_argument_get_string(req, "swvc", &v))
		snprintf(want, sizeof(want), "%.30s", v);
	if (http_argument_get_string(req, "policy", &v) && want[0] != '\0')
		snprintf(want + strlen(want), sizeof(want) - strlen(want), " %.30s",
		    v);
	from = 0;
	if (http_argument_get_string(req, "since", &v))
		from = strtoll(v, NULL, 10);
	v = NULL;
	(void)http_argument_get_string(req, "edge", &v);
	host_refs();
	doc = sdwan_load();
	all = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((edge = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL) {
		if (v != NULL && strcmp(v, str(edge, "server")) != 0)
			continue;
		if ((ans = sdwan_read(str(edge, "server"), name, sizeof(name),
		    &status)) == NULL)
			continue;
		eit = NULL;
		while (ans != NULL && (e = ucl_object_iterate(at_path(at_path(ans,
		    "data", "record"), "last", NULL), &eit, true)) != NULL) {
			if (from > 0 && ucl_object_toint(ucl_object_lookup(e, "t")) <
			    from)
				continue;
			if (want[0] != '\0' && (str(e, "comment") == NULL ||
			    strncmp(str(e, "comment"), "security ", 9) != 0 ||
			    strncmp(str(e, "comment") + 9, want, strlen(want)) != 0))
				continue;
			e2 = ucl_object_copy(e);
			put(e2, "edge", S(str(edge, "server")));
			put(e2, "name", S(name));
			ucl_array_append(all, e2);
		}
		if (ans != NULL)
			ucl_object_unref(ans);
	}
	ucl_object_unref(doc);
	(void)swvc;
	(void)policy;
	(void)since;
	(void)only;
	if (!csv) {
		out = ucl_object_typed_new(UCL_OBJECT);
		put(out, "record", all);
		return (reply_json(req, 200, out));
	}
	b = buf_alloc(4096);
	buf_appendf(b, "time,edge,rule,action,source,destination,interface,"
	    "comment\n");
	eit = NULL;
	while ((e = ucl_object_iterate(all, &eit, true)) != NULL) {
		char	when[32];
		time_t	t = (time_t)ucl_object_toint(ucl_object_lookup(e, "t"));

		strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
		buf_appendf(b, "%s,%s,%jd,%s,%s,%s,%s,\"%s\"\n", when,
		    str(e, "name"), (intmax_t)ucl_object_toint(ucl_object_lookup(e,
		    "rule")), str(e, "action") != NULL ? str(e, "action") : "",
		    str(e, "src") != NULL ? str(e, "src") : "", str(e, "dst") !=
		    NULL ? str(e, "dst") : "", str(e, "iface") != NULL ? str(e,
		    "iface") : "", str(e, "comment") != NULL ? str(e, "comment") :
		    "");
	}
	ucl_object_unref(all);
	http_response_header(req, "content-type", "text/csv; charset=utf-8");
	http_response_header(req, "content-disposition", "attachment; "
	    "filename=\"sdwan-record.csv\"");
	http_response(req, 200, b->data, b->offset);
	buf_free(b);
	return (WEB_OK);
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

			int64_t	pa = ucl_object_toint(ucl_object_lookup(
				    v[k].c, "preference"));
			int64_t	pb = ucl_object_toint(ucl_object_lookup(
				    v[k - 1].c, "preference"));

			/* Of those that meet the thresholds, a UCS End
			 * Point list's preference first, then the metric. */
			if (a < b || (a == b && a == 0 && pa > pb) || (a == b &&
			    a < 2 && (a != 0 || pa == pb) && v[k].m[idx] <
			    v[k - 1].m[idx])) {
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

/* ---- The keys turned at the half-life (Mplify 119 R110, R112) -------- */

#define	MGR_REKEY_RETRY_S	120	/* a rotation that failed, tried again after */

/*
 * The derive job of one end of a uswe tunnel, as applied, and the
 * server it is on (not the one to skip); NULL when there is none.
 */
static ucl_object_t *
rekey_end(const ucl_object_t *ap, const char *id, const char *skip,
    char *sid, size_t slen)
{
	const ucl_object_t	*s, *d, *j;
	ucl_object_iter_t	 it;
	ucl_object_t		*spec, *c;
	char			 key[200];

	snprintf(key, sizeof(key), "peer:%s", id);
	it = NULL;
	while ((s = ucl_object_iterate(ap, &it, true)) != NULL) {
		if (skip != NULL && strcmp(ucl_object_key(s), skip) == 0)
			continue;
		if ((d = ucl_object_lookup(s, key)) == NULL || (spec = parse(
		    str(d, "spec"))) == NULL)
			continue;
		j = ucl_array_find_index(ucl_object_lookup(spec, "make"), 0);
		if (j != NULL && str(j, "kind") != NULL && strcmp(str(j, "kind"),
		    "ipsec-sa") == 0 && str(j, "verb") != NULL && strcmp(str(j,
		    "verb"), "derive") == 0) {
			c = ucl_object_copy(j);
			ucl_object_unref(spec);
			(void)ucl_object_delete_key(c, "_after");
			snprintf(sid, slen, "%s", ucl_object_key(s));
			return (c);
		}
		ucl_object_unref(spec);
	}
	return (NULL);
}

/* An interface's keys entry of its host's sdwan read, or NULL. */
static ucl_object_t *
rekey_keys_of(const char *sid, const char *ifn, char *why, size_t wlen)
{
	char			 name[128];
	ucl_object_t		*ans, *out;
	const ucl_object_t	*i;
	ucl_object_iter_t	 it;
	int			 status;

	if ((ans = sdwan_read(sid, name, sizeof(name), &status)) == NULL) {
		snprintf(why, wlen, "no server %s", sid);
		return (NULL);
	}
	out = NULL;
	it = NULL;
	while (ans != NULL && (i = ucl_object_iterate(at_path(ans, "data",
	    "keys"), &it, true)) != NULL)
		if (str(i, "interface") != NULL && strcmp(str(i, "interface"),
		    ifn) == 0)
			out = ucl_object_copy(i);
	if (ans != NULL)
		ucl_object_unref(ans);
	if (out == NULL)
		snprintf(why, wlen, "%s tells of no keys for %s", name, ifn);
	return (out);
}

/* What is known of a tunnel's rotation, kept and written as it goes. */
static void
rekey_set(ucl_object_t *st, const char *id, const char *state,
    const char *step, const char *why)
{
	ucl_object_t	*all, *rk;

	if ((all = (ucl_object_t *)(uintptr_t)ucl_object_lookup(st,
	    "rekeys")) == NULL) {
		all = ucl_object_typed_new(UCL_OBJECT);
		put(st, "rekeys", all);
	}
	rk = ucl_object_typed_new(UCL_OBJECT);
	put(rk, "at", I(time(NULL)));
	put(rk, "state", S(state));
	put(rk, "step", S(step));
	if (why != NULL)
		put(rk, "why", S(why));
	put(all, id, rk);
	pthread_mutex_lock(&st_lock);
	if (!applying)
		state_save(st);
	/* Ended: no reader sees it done and still turning. */
	if (strcmp(state, "running") != 0)
		rekeying = false;
	pthread_mutex_unlock(&st_lock);
}

/*
 * One tunnel's keys turned, both ends in step (Mplify 119 R110, R112):
 * the next pair made on each, its public half read, the new SAs from
 * the two put in inbound on both, then outbound, then committed on
 * both; so neither end ever sends on keys the other has not got, and
 * no packet is lost.  What goes wrong is kept here, and the end it
 * went wrong on says so as a fault.
 */
static bool
rekey_run(ucl_object_t *st, const char *id, char *why, size_t wlen)
{
	static const char *const dirs[] = { "in", "out" };
	ucl_object_t		*end[2], *j, *args, *keys;
	const ucl_object_t	*a;
	char			 sid[2][40], *next[2], w2[300];
	const char		*ifn[2], *stage;
	size_t			 k, d, i, n;
	bool			 ok;

	pthread_mutex_lock(&st_lock);
	rekeying = true;
	pthread_mutex_unlock(&st_lock);
	end[0] = rekey_end(ucl_object_lookup(st, "applied"), id, NULL, sid[0],
	    sizeof(sid[0]));
	end[1] = end[0] != NULL ? rekey_end(ucl_object_lookup(st, "applied"),
	    id, sid[0], sid[1], sizeof(sid[1])) : NULL;
	if (end[1] == NULL) {
		snprintf(why, wlen, "%s is not a uswe tunnel applied on two "
		    "edges", id);
		if (end[0] != NULL)
			ucl_object_unref(end[0]);
		rekey_set(st, id, "failed", "ends", why);
		pthread_mutex_lock(&st_lock);
		rekeying = false;
		pthread_mutex_unlock(&st_lock);
		return (false);
	}
	ifn[0] = str(end[0], "interface");
	ifn[1] = str(end[1], "interface");
	next[0] = next[1] = NULL;
	ok = true;
	stage = "keys";
	rekey_set(st, id, "running", stage, NULL);
	/* The next pair on each end. */
	for (k = 0; ok && k < 2; k++) {
		args = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(args, S("next"));
		j = job("ipsec-sa", "verb", S("key"), "interface", S(ifn[k]),
		    "args", args, NULL);
		if (!job_run(sid[k], j, w2, sizeof(w2))) {
			snprintf(why, wlen, "%s: %s", server_name_of(sid[k]), w2);
			ok = false;
		}
		ucl_object_unref(j);
	}
	/* Its public half, read from each. */
	for (k = 0; ok && k < 2; k++) {
		keys = rekey_keys_of(sid[k], ifn[k], w2, sizeof(w2));
		if (keys == NULL || str(keys, "next") == NULL) {
			if (keys != NULL)
				snprintf(w2, sizeof(w2), "%s has no next half for "
				    "%s", server_name_of(sid[k]), ifn[k]);
			snprintf(why, wlen, "%s", w2);
			ok = false;
		} else
			next[k] = strdup(str(keys, "next"));
		if (keys != NULL)
			ucl_object_unref(keys);
	}
	/* The new SAs in, then out, on both: each end's derive as applied,
	 * the far half the far end's next one. */
	for (d = 0; ok && d < 2; d++) {
		stage = dirs[d];
		rekey_set(st, id, "running", stage, NULL);
		for (k = 0; ok && k < 2; k++) {
			j = ucl_object_copy(end[k]);
			args = (ucl_object_t *)(uintptr_t)ucl_object_lookup(j,
			    "args");
			n = args != NULL ? ucl_array_size(args) : 0;
			for (i = 0; i < n; i++) {
				a = ucl_array_find_index(args, (unsigned int)i);
				if (ucl_object_type(a) == UCL_STRING && strncmp(
				    ucl_object_tostring(a), "${uswe:", 7) == 0)
					ucl_object_unref(ucl_array_replace_index(
					    args, S(next[!k]), (unsigned int)i));
			}
			ucl_array_append(args, S("next"));
			ucl_array_append(args, S("install"));
			ucl_array_append(args, S(dirs[d]));
			if (!job_run(sid[k], j, w2, sizeof(w2))) {
				snprintf(why, wlen, "%s, %s: %s", server_name_of(
				    sid[k]), dirs[d], w2);
				ok = false;
			}
			ucl_object_unref(j);
		}
	}
	/* Committed on both: the old out, the next pair the pair. */
	if (ok) {
		stage = "commit";
		rekey_set(st, id, "running", stage, NULL);
	}
	for (k = 0; ok && k < 2; k++) {
		j = job("ipsec-sa", "verb", S("commit"), "interface", S(ifn[k]),
		    "reqid", I(ucl_object_toint(ucl_object_lookup(end[k],
		    "reqid"))), "tunnel_local", S(str(end[k], "tunnel_local")),
		    "tunnel_remote", S(str(end[k], "tunnel_remote")), NULL);
		if (!job_run(sid[k], j, w2, sizeof(w2))) {
			snprintf(why, wlen, "%s, commit: %s", server_name_of(sid[k]),
			    w2);
			ok = false;
		}
		ucl_object_unref(j);
	}
	rekey_set(st, id, ok ? "done" : "failed", stage, ok ? NULL : why);
	thread_log(ok ? LOG_INFO : LOG_WARNING, "sdwan: the keys of %s %s", id,
	    ok ? "turned" : why);
	free(next[0]);
	free(next[1]);
	ucl_object_unref(end[0]);
	ucl_object_unref(end[1]);
	pthread_mutex_lock(&st_lock);
	rekeying = false;
	pthread_mutex_unlock(&st_lock);
	return (ok);
}

/* Is an end past the half-life of its keys, or a rotation left half done? */
static bool
rekey_due(const char *sid, const char *ifn, time_t now)
{
	ucl_object_t	*keys;
	char		 why[300];
	int64_t		 at, life;
	bool		 due;

	if ((keys = rekey_keys_of(sid, ifn, why, sizeof(why))) == NULL)
		return (false);
	at = ucl_object_toint(ucl_object_lookup(keys, "keyed_at"));
	life = ucl_object_toint(ucl_object_lookup(keys, "lifetime"));
	due = ucl_flag(keys, "pending") || (at > 0 && life > 0 && now - at >=
	    life / 2);
	ucl_object_unref(keys);
	return (due);
}

/*
 * Each applied uswe tunnel, once: its keys turned when either end is
 * past the half-life, or was left with a rotation half done; not again
 * for a while after one that failed.
 */
static void
rekey_tick(ucl_object_t *st, time_t now)
{
	const ucl_object_t	*ap, *s, *d, *rk, *j, *a;
	ucl_object_iter_t	 it, dit, ait;
	ucl_object_t		*spec, *seen;
	char			 far[16], farif[32], why[300];
	const char		*id;

	ap = ucl_object_lookup(st, "applied");
	seen = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while ((s = ucl_object_iterate(ap, &it, true)) != NULL) {
		dit = NULL;
		while ((d = ucl_object_iterate(s, &dit, true)) != NULL) {
			if (strncmp(ucl_object_key(d), "peer:", 5) != 0 || (spec =
			    parse(str(d, "spec"))) == NULL)
				continue;
			id = ucl_object_key(d) + 5;
			j = ucl_array_find_index(ucl_object_lookup(spec, "make"), 0);
			if (j == NULL || str(j, "kind") == NULL || strcmp(str(j,
			    "kind"), "ipsec-sa") != 0 || str(j, "verb") == NULL ||
			    strcmp(str(j, "verb"), "derive") != 0 ||
			    ucl_object_lookup(seen, id) != NULL) {
				ucl_object_unref(spec);
				continue;
			}
			put(seen, id, B(true));
			/* Not twice at once, nor right after a failure. */
			rk = at_path(st, "rekeys", id);
			if (rk != NULL && str(rk, "state") != NULL && (strcmp(str(rk,
			    "state"), "running") == 0 || (strcmp(str(rk, "state"),
			    "failed") == 0 && now - ucl_object_toint(
			    ucl_object_lookup(rk, "at")) < MGR_REKEY_RETRY_S))) {
				ucl_object_unref(spec);
				continue;
			}
			/* The far end, from the reference in the words. */
			far[0] = farif[0] = '\0';
			ait = NULL;
			while ((a = ucl_object_iterate(ucl_object_lookup(j, "args"),
			    &ait, true)) != NULL)
				if (ucl_object_type(a) == UCL_STRING)
					(void)sscanf(ucl_object_tostring(a),
					    "${uswe:%15[^:]:%31[^}]}", far, farif);
			if (rekey_due(ucl_object_key(s), str(j, "interface"), now) ||
			    (far[0] != '\0' && rekey_due(far, farif, now)))
				(void)rekey_run(st, id, why, sizeof(why));
			ucl_object_unref(spec);
		}
	}
	ucl_object_unref(seen);
}

/* One tick: every edge's steering looked at, and sent where changed. */
static void
manager_tick(void)
{
	ucl_object_t		*st, *doc, *entries, *sent, *e, *cands, *all;
	const ucl_object_t	*ap, *s, *spec, *sw, *pol, *perf, *was, *w;
	ucl_object_iter_t	 it, eit;
	char			 uri[256], peer[256], name[128], *json, *text;
	char			 jail[64];
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
	identities_tick(doc, now);
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
		    !edge_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
		    sizeof(name), jail, sizeof(jail))) {
			ucl_object_unref((ucl_object_t *)(uintptr_t)spec);
			continue;
		}
		/* What its probes see now, its own. */
		sd = sdwan_read(sid, NULL, 0, &status);
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
			if (jail[0] != '\0')
				put(body, "jail", S(jail));
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
	rekey_tick(st, now);
	lists_tick(now);
	pthread_mutex_lock(&st_lock);
	if (!applying)
		(void)store_save(STATE_FILE, st);
	pthread_mutex_unlock(&st_lock);
	ucl_object_unref(st);
}

/* A rotation asked for by hand, in a thread of the console. */
static void *
rekey_main(void *arg)
{
	ucl_object_t	*st;
	char		 why[300];

	pthread_mutex_lock(&st_lock);
	st = state_load();
	pthread_mutex_unlock(&st_lock);
	(void)rekey_run(st, arg, why, sizeof(why));
	ucl_object_unref(st);
	free(arg);
	return (NULL);
}

int
api_sdwan_rekey(struct http_request *req)
{
	ucl_object_t	*st, *body, *e0, *e1;
	pthread_t	 tid;
	const char	*id;
	char		 sid[2][40], *arg;

	if (req->method == HTTP_METHOD_GET) {
		if (!guard(req, false))
			return (WEB_OK);
		pthread_mutex_lock(&st_lock);
		st = state_load();
		pthread_mutex_unlock(&st_lock);
		body = ucl_object_typed_new(UCL_OBJECT);
		put(body, "rekeys", ucl_object_lookup(st, "rekeys") != NULL ?
		    ucl_object_copy(ucl_object_lookup(st, "rekeys")) :
		    ucl_object_typed_new(UCL_OBJECT));
		put(body, "rekeying", B(rekeying));
		ucl_object_unref(st);
		return (reply_json(req, 200, body));
	}
	if (!guard(req, true))
		return (WEB_OK);
	body = read_json(req);
	id = body != NULL ? str(body, "tunnel") : NULL;
	if (id == NULL || id[0] == '\0' || strlen(id) > 150) {
		if (body != NULL)
			ucl_object_unref(body);
		return (reply_error(req, 400, "tunnel", "say which tunnel: its "
		    "id"));
	}
	pthread_mutex_lock(&st_lock);
	if (applying || rekeying) {
		bool	keys = !applying;

		pthread_mutex_unlock(&st_lock);
		ucl_object_unref(body);
		return (reply_error(req, 409, "busy", keys ? "a key rotation is "
		    "running" : "an apply is running"));
	}
	st = state_load();
	pthread_mutex_unlock(&st_lock);
	/* Both ends applied, else there is nothing to turn. */
	e0 = rekey_end(ucl_object_lookup(st, "applied"), id, NULL, sid[0],
	    sizeof(sid[0]));
	e1 = e0 != NULL ? rekey_end(ucl_object_lookup(st, "applied"), id,
	    sid[0], sid[1], sizeof(sid[1])) : NULL;
	ucl_object_unref(st);
	if (e0 != NULL)
		ucl_object_unref(e0);
	if (e1 != NULL)
		ucl_object_unref(e1);
	if (e1 == NULL) {
		ucl_object_unref(body);
		return (reply_error(req, 404, "tunnel", "no uswe tunnel %s "
		    "applied on two edges", id));
	}
	host_refs();
	arg = strdup(id);
	pthread_mutex_lock(&st_lock);
	rekeying = true;
	pthread_mutex_unlock(&st_lock);
	if (pthread_create(&tid, NULL, rekey_main, arg) != 0) {
		pthread_mutex_lock(&st_lock);
		rekeying = false;
		pthread_mutex_unlock(&st_lock);
		free(arg);
		ucl_object_unref(body);
		return (reply_error(req, 500, "thread", "%s", strerror(errno)));
	}
	(void)pthread_detach(tid);
	st = ucl_object_typed_new(UCL_OBJECT);
	put(st, "tunnel", S(id));
	ucl_object_unref(body);
	return (reply_json(req, 200, st));
}

static void *
manager(void *arg __unused)
{

	for (;;) {
		sleep(MGR_TICK_S);
		/* Of a cluster, the leader's alone. */
		if (cluster_leads())
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
	static __thread char	 buf[4][160];
	static __thread int	 k;
	const struct server	*s;
	char			 srv[64], jail[64];

	if (!sdwan_edge_split(sid, srv, sizeof(srv), jail, sizeof(jail)))
		return (sid);
	if (jail[0] == '\0')
		return ((s = server_find(sid)) != NULL ? s->name : sid);
	/* A jail's edge: its server's name and the jail, name/jail. */
	k = (k + 1) % 4;
	snprintf(buf[k], sizeof(buf[k]), "%s/%s", (s = server_find(srv)) !=
	    NULL ? s->name : srv, jail);
	return (buf[k]);
}

/*
 * Where an edge's agent is reached, as host_ref() has it, and the vnet
 * jail it is ("" for the server itself).
 */
static bool
edge_ref(const char *edge, char *uri, size_t ulen, char *peer, size_t plen,
    char *name, size_t nlen, char *jail, size_t jlen)
{
	char	sid[64];

	if (!sdwan_edge_split(edge, sid, sizeof(sid), jail, jlen))
		return (false);
	return (host_ref(sid, uri, ulen, peer, plen, name, nlen));
}

/* A fault's or target's edge, by the jail its object names (id@jail,
 * id@jail/metric): "" the host's. */
static bool
of_jail(const char *object, const char *jail)
{
	const char	*at;
	size_t		 n;

	if (object == NULL || (at = strchr(object, '@')) == NULL)
		return (jail[0] == '\0');
	n = strcspn(at + 1, "/");
	return (strlen(jail) == n && strncmp(at + 1, jail, n) == 0);
}

/*
 * An edge's sdwan read, parsed, as if the edge were the whole host: of
 * the targets and faults, its own; a jail's rules, steer and steered
 * its edge's, in the host's places, and none of the host's services,
 * keys or record.  NULL when its server is unknown; the host's name in
 * name when asked.
 */
static ucl_object_t *
sdwan_read(const char *edge, char *name, size_t nlen, int *status)
{
	char			 uri[256], peer[256], hname[128], jail[64], *json;
	const ucl_object_t	*t, *e;
	ucl_object_iter_t	 it;
	ucl_object_t		*ans, *data, *keep;
	static const char *const none[] = { "keys", "bird", "dhcp", "dns",
	    "proxy", "ids" };
	size_t			 i;

	if (!edge_ref(edge, uri, sizeof(uri), peer, sizeof(peer), hname,
	    sizeof(hname), jail, sizeof(jail)))
		return (NULL);
	if (name != NULL)
		snprintf(name, nlen, "%s", hname);
	json = hosts_read(uri, peer, hname, "sdwan", status);
	ans = parse(json);
	free(json);
	if (ans == NULL || (data = (ucl_object_t *)(uintptr_t)
	    ucl_object_lookup(ans, "data")) == NULL)
		return (ans);
	keep = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((t = ucl_object_iterate(ucl_object_lookup(data, "targets"), &it,
	    true)) != NULL)
		if (strcmp(str(t, "jail") != NULL ? str(t, "jail") : "", jail) ==
		    0)
			ucl_array_append(keep, ucl_object_copy(t));
	ucl_object_replace_key(data, keep, "targets", 0, false);
	keep = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((t = ucl_object_iterate(ucl_object_lookup(data, "faults"), &it,
	    true)) != NULL)
		if (of_jail(str(t, "object"), jail))
			ucl_array_append(keep, ucl_object_copy(t));
	ucl_object_replace_key(data, keep, "faults", 0, false);
	if (jail[0] != '\0') {
		e = NULL;
		it = NULL;
		while ((t = ucl_object_iterate(ucl_object_lookup(data, "edges"),
		    &it, true)) != NULL)
			if (str(t, "jail") != NULL && strcmp(str(t, "jail"), jail)
			    == 0)
				e = t;
		ucl_object_replace_key(data, e != NULL && ucl_object_lookup(e,
		    "rules") != NULL ? ucl_object_copy(ucl_object_lookup(e,
		    "rules")) : ucl_object_typed_new(UCL_OBJECT), "rules", 0,
		    false);
		ucl_object_replace_key(data, e != NULL && ucl_object_lookup(e,
		    "steer") != NULL ? ucl_object_copy(ucl_object_lookup(e,
		    "steer")) : ucl_object_typed_new(UCL_ARRAY), "steer", 0,
		    false);
		ucl_object_replace_key(data, ucl_object_frombool(e != NULL &&
		    ucl_object_toboolean(ucl_object_lookup(e, "steered"))),
		    "steered", 0, false);
		for (i = 0; i < nitems(none); i++)
			ucl_object_replace_key(data, ucl_object_typed_new(
			    UCL_ARRAY), none[i], 0, false);
		ucl_object_replace_key(data, ucl_object_typed_new(UCL_OBJECT),
		    "record", 0, false);
	}
	(void)ucl_object_delete_key(data, "edges");
	return (ans);
}

/*
 * What an edge that is a vnet jail is not given yet, said: the jail's
 * own network takes its interfaces, routes, tunnels (gre, gif, GENEVE,
 * WireGuard, IKEv2), BIRD (run in the jail by the host's agent, with
 * BFD), ipfw rules and steering, probes and net.* sysctls; the services
 * the host runs for an SD-WAN service (dnsmasq, unbound, Squid,
 * Suricata), NTP, rtadvd and manual SAs (a uswe tunnel) are the host's
 * only.
 */
static bool
jail_kind_ok(const char *kind, char *why, size_t wlen)
{
	static const char *const not[] = { "sdwan-dns", "sdwan-dhcp",
	    "sdwan-proxy", "sdwan-ids", "ntp", "rtadvd", "ipsec-sa" };
	size_t	i;

	for (i = 0; kind != NULL && i < nitems(not); i++)
		if (strcmp(kind, not[i]) == 0) {
			snprintf(why, wlen, "an edge that is a vnet jail has no "
			    "%s yet: the host's own edge has", kind);
			return (false);
		}
	return (true);
}

/*
 * What SD-WAN needs installed on an edge that is not FreeBSD's own, by
 * the kinds of job the plan has for it: each a plugin the agent reports
 * when its program is there.  Nothing is installed for it by the apply:
 * what is missing is said, and the apply waits until it is installed.
 */
static const struct sdwan_need {
	const char	*kind;		/* a job of this kind needs it */
	const char	*plugin;	/* as the agent reports it */
	const char	*package;
	const char	*what;
} sdwan_needs[] = {
	{ "ipsec", "strongswan", "strongswan",
	    "strongSwan, for the tunnels under IPsec IKEv2" },
	{ "speeder", "speederv2", "udpspeeder",
	    "UDPspeeder, for the FEC relays the UCS End Points name" },
	{ "sdwan-bird", "bird", "bird3",
	    "BIRD, for routing at the UNIs, BGP between the edges and BFD" },
	{ "sdwan-dhcp", "dnsmasq", "dnsmasq",
	    "dnsmasq, the DHCP server at the UNIs" },
	{ "sdwan-proxy", "squid", "squid",
	    "Squid, for URL filtering and malware scanning" },
	{ "sdwan-proxy+icap", "c-icap", "c-icap c-icap-modules clamav",
	    "c-icap with ClamAV's module and signatures (freshclam), for "
	    "malware scanning" },
	{ "sdwan-ids", "suricata", "suricata",
	    "Suricata, for intrusion detection on the UNIs (and "
	    "suricata-update for its ruleset)" },
};

/*
 * Each edge's needs, with whether the host has each: [{server, name,
 * plugin, package, what, there}].  An edge that does not answer is
 * said to have none of them.
 */
static ucl_object_t *
plan_needs(const struct plan *pl)
{
	const ucl_object_t	*objs, *o, *j, *pl_list, *p;
	ucl_object_iter_t	 it, oit, jit, pit;
	ucl_object_t		*out, *e, *ans;
	char			 uri[256], peer[256], name[128], *json, jail[64];
	bool			 want[nitems(sdwan_needs)], there;
	size_t			 i;
	int			 status;

	out = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((objs = ucl_object_iterate(pl->edges, &it, true)) != NULL) {
		memset(want, 0, sizeof(want));
		oit = NULL;
		while ((o = ucl_object_iterate(objs, &oit, true)) != NULL) {
			jit = NULL;
			while ((j = ucl_object_iterate(ucl_object_lookup(o,
			    "make"), &jit, true)) != NULL) {
				for (i = 0; i < nitems(sdwan_needs); i++)
					if (str(j, "kind") != NULL && strcmp(str(j,
					    "kind"), sdwan_needs[i].kind) == 0)
						want[i] = true;
				/* A proxy that scans for malware: c-icap. */
				if (str(j, "kind") != NULL && strcmp(str(j,
				    "kind"), "sdwan-proxy") == 0) {
					const ucl_object_t	*in;
					ucl_object_iter_t	 iit = NULL;

					while ((in = ucl_object_iterate(
					    ucl_object_lookup(j, "instances"), &iit,
					    true)) != NULL)
						if (ucl_flag(ucl_object_lookup(in,
						    "spec"), "icap"))
							for (i = 0; i <
							    nitems(sdwan_needs); i++)
								if (strcmp(sdwan_needs[i]
								    .kind,
								    "sdwan-proxy+icap") ==
								    0)
									want[i] = true;
				}
			}
		}
		ans = NULL;
		for (i = 0; i < nitems(sdwan_needs); i++)
			if (want[i])
				break;
		pl_list = NULL;
		if (i < nitems(sdwan_needs) && edge_ref(ucl_object_key(objs),
		    uri, sizeof(uri), peer, sizeof(peer), name, sizeof(name),
		    jail, sizeof(jail))) {
			/* A jail's edge: what is in the jail, as it sees its
			 * files, not the host's. */
			json = hosts_read(uri, peer, name, jail[0] != '\0' ?
			    "jails" : "hello", &status);
			ans = status == 200 ? parse(json) : NULL;
			free(json);
		}
		if (ans != NULL && jail[0] != '\0') {
			const ucl_object_t	*jl;
			ucl_object_iter_t	 jit2 = NULL;

			while ((jl = ucl_object_iterate(ucl_object_lookup(ans,
			    "jails"), &jit2, true)) != NULL)
				if (str(jl, "name") != NULL && strcmp(str(jl,
				    "name"), jail) == 0)
					pl_list = ucl_object_lookup(jl, "plugins");
		} else if (ans != NULL) {
			pl_list = ucl_object_lookup(ans, "host");
			pl_list = pl_list != NULL ? ucl_object_lookup(pl_list,
			    "plugins") : NULL;
		}
		for (i = 0; i < nitems(sdwan_needs); i++) {
			if (!want[i])
				continue;
			there = false;
			pit = NULL;
			while ((p = ucl_object_iterate(pl_list, &pit, true)) !=
			    NULL)
				there = there || strcmp(ucl_object_tostring_forced(
				    p), sdwan_needs[i].plugin) == 0;
			e = ucl_object_typed_new(UCL_OBJECT);
			put(e, "server", S(ucl_object_key(objs)));
			put(e, "name", S(server_name_of(ucl_object_key(objs))));
			put(e, "plugin", S(sdwan_needs[i].plugin));
			put(e, "package", S(sdwan_needs[i].package));
			put(e, "what", S(sdwan_needs[i].what));
			put(e, "there", B(there));
			ucl_array_append(out, e);
		}
		if (ans != NULL)
			ucl_object_unref(ans);
	}
	return (out);
}

/*
 * False, with why, when an edge lacks what the services need there:
 * the apply does not begin, and says what to install where.
 */
static bool
needs_met(const ucl_object_t *needs, char *why, size_t wlen)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	char			 list[600];
	size_t			 n;

	list[0] = '\0';
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(needs, &it, true)) != NULL) {
		if (ucl_object_toboolean(ucl_object_lookup(e, "there")))
			continue;
		if (n++ < 12)
			snprintf(list + strlen(list), sizeof(list) - strlen(list),
			    "%s%s: pkg install %s", list[0] != '\0' ? "; " : "",
			    str(e, "name"), str(e, "package"));
	}
	if (n == 0)
		return (true);
	snprintf(why, wlen, "install what SD-WAN needs on the edges first, "
	    "then deploy (nothing is installed by the apply): %s", list);
	return (false);
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
	put(top, "needs", plan_needs(pl));
	return (top);
}

/*
 * An apply begun from a plan built: the lock, the steps, the thread.
 * The plan, the changes and the state are consumed.  Refused (-1,
 * why, the HTTP status) while one runs, or when no thread could be
 * made; else how many steps there are.
 */
static int
apply_begin(struct plan *plp, ucl_object_t *st, ucl_object_t *chg, bool fresh,
    char *why, size_t wlen, int *statusp)
{
	ucl_object_t		*ap, *steps, *s;
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	struct run		*r;
	pthread_t		 tid;
	char			 path[MAXPATHLEN];
	int			 fd, nsteps, error;

	/* One apply at a time, in this worker and every other. */
	pthread_mutex_lock(&st_lock);
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, LOCK_FILE);
	fd = -1;
	if (applying || rekeying || (fd = open(path, O_RDWR | O_CREAT |
	    O_CLOEXEC, 0600)) == -1 || flock(fd, LOCK_EX | LOCK_NB) == -1) {
		bool	keys = !applying && rekeying;

		pthread_mutex_unlock(&st_lock);
		if (fd != -1)
			close(fd);
		ucl_object_unref(chg);
		plan_free(plp);
		ucl_object_unref(st);
		snprintf(why, wlen, "%s", keys ? "a key rotation is running" :
		    "an apply is running");
		*statusp = 409;
		return (-1);
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

			n = by(edge_list(plp, str(o, "server")), "key", str(o,
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
	put(ap, "tunnels", ucl_object_copy(plp->tunnels));
	put(st, "apply", ap);
	/* The allocations of what is made: new ones now, gone ones after. */
	{
		ucl_object_t		*keep;
		const ucl_object_t	*a;

		keep = ucl_object_typed_new(UCL_OBJECT);
		it = NULL;
		while ((a = ucl_object_iterate(plp->alloc, &it, true)) != NULL)
			if (ucl_object_lookup(plp->used, ucl_object_key(a)) !=
			    NULL)
				ucl_object_insert_key(keep, ucl_object_copy(a),
				    ucl_object_key(a), 0, true);
		put(st, "alloc", ucl_object_copy(plp->alloc));
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
	plan_free(plp);
	/* Counted before the thread runs: it frees r when it is done. */
	nsteps = (int)ucl_array_size(r->steps);
	if ((error = hosts_thread(&tid, run_main, r)) != 0) {
		snprintf(why, wlen, "%s", strerror(error));
		close(fd);
		ucl_object_unref(r->st);
		ucl_object_unref(r->alloc);
		ucl_object_unref(r->keys);
		free(r);
		pthread_mutex_lock(&st_lock);
		applying = false;
		pthread_mutex_unlock(&st_lock);
		*statusp = 500;
		return (-1);
	}
	(void)pthread_detach(tid);
	return (nsteps);
}

/*
 * An apply of a document as it is, for the console's own changes (an
 * identity issued, revoked or expired): the document is consumed.
 */
static bool
apply_now(ucl_object_t *doc, char *why, size_t wlen)
{
	struct plan	 pl;
	ucl_object_t	*st, *chg, *needs;
	int		 status;

	if (!sdwan_valid(doc, why, wlen)) {
		ucl_object_unref(doc);
		return (false);
	}
	pthread_mutex_lock(&st_lock);
	st = state_load();
	pthread_mutex_unlock(&st_lock);
	if (!plan_build(&pl, doc, st)) {
		snprintf(why, wlen, "%s", pl.why);
		plan_free(&pl);
		ucl_object_unref(doc);
		ucl_object_unref(st);
		return (false);
	}
	needs = plan_needs(&pl);
	if (!needs_met(needs, why, wlen)) {
		ucl_object_unref(needs);
		plan_free(&pl);
		ucl_object_unref(doc);
		ucl_object_unref(st);
		return (false);
	}
	ucl_object_unref(needs);
	chg = changes(&pl, st, false);
	if (apply_begin(&pl, st, chg, false, why, wlen, &status) < 0) {
		ucl_object_unref(doc);
		return (false);
	}
	ucl_object_unref(doc);
	return (true);
}

int
api_sdwan_edges(struct http_request *req)
{
	ucl_object_t		*doc, *st, *chg, *body, *needs;
	struct plan		 pl;
	char			 why[300];
	bool			 apply, fresh;
	int			 n, status;

	apply = strcmp(req->path, "/api/sdwan/apply") == 0;
	if (req->method == HTTP_METHOD_GET) {
		if (!guard(req, false))
			return (WEB_OK);
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
		return (WEB_OK);
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
	needs = plan_needs(&pl);
	if (!needs_met(needs, why, sizeof(why))) {
		ucl_object_unref(needs);
		ucl_object_unref(chg);
		plan_free(&pl);
		ucl_object_unref(doc);
		ucl_object_unref(st);
		return (reply_error(req, 409, "missing", "%s", why));
	}
	ucl_object_unref(needs);
	n = apply_begin(&pl, st, chg, fresh, why, sizeof(why), &status);
	ucl_object_unref(doc);
	if (n < 0)
		return (reply_error(req, status, status == 409 ? "busy" : "thread",
		    "%s", why));
	/* The Policies sent to the Policy End Points, the edges. */
	audit_add("policies-applied", "Administer", "the services' document",
	    fresh ? "every job made again on the edges" : "the changes made on "
	    "the edges, in their order", "the edges (Policy End Points)",
	    session_who(req), "%d step%s of the apply", n, n == 1 ? "" : "s");
	body = ucl_object_typed_new(UCL_OBJECT);
	put(body, "steps", I(n));
	return (reply_json(req, 200, body));
}
