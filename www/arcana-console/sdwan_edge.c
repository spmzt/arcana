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
static bool		 edge_ref(const char *, char *, size_t, char *, size_t,
			    char *, size_t, char *, size_t);
static ucl_object_t	*sdwan_read(const char *, char *, size_t, int *);
static bool		 jail_kind_ok(const char *, char *, size_t);
struct plan;
static const char *uni_ifname(struct plan *, const ucl_object_t *,
		    const ucl_object_t *, char *, size_t);

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
static void	 bird_routing(struct kore_buf *, const ucl_object_t *,
		    const char *, const char *, const char *, const char *,
		    int64_t);
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
			if (ucl_object_lookup(a, "vrf") != NULL)
				put(p, "tunnelfib", I(ucl_object_toint(
				    ucl_object_lookup(a, "vrf"))));
		}
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
		/* A remote end point's: the identities' addresses (SASE-3). */
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

	route_fib_obj(pl, sid, sw, ucl_object_toint(ucl_object_lookup(sw,
	    "fib")), PH_ROUTE, prefix, gw, why);
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
			continue;	/* a remote end point (SASE-3) */
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

/*
 * A remote end point's addresses (SASE-3): the edge's own is the
 * prefix's first host; each identity's is kept in the allocations as
 * ident:SWVC/EP/NAME with its host number, so that it keeps it while
 * others come and go, a new one taking the lowest free from the
 * second.
 */
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
 * re-authorisation interval, when it has one (SASE-3)?  Not so, it has
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
 * A remote end point (SASE-3): its wg interface in the service's table
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
	fib = ucl_object_toint(ucl_object_lookup(sw, "fib"));
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
		if ((u = ucl_object_lookup(ep, "uni")) == NULL)
			continue;	/* a remote end point (SASE-3) */
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
	ucl_object_t		*o, *inst, *list;
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


/* ---- DNS filters (MEF 88): the base system's unbound, a service an
 * instance ------------------------------------------------------------- */

static const ucl_object_t *sec_of(const ucl_object_t *, const ucl_object_t *,
    const char *, int *);
static bool	 url_filters(const ucl_object_t *, bool *);
static bool	 malware_scan(const ucl_object_t *);
static bool	 remote_addr(struct plan *, const ucl_object_t *,
		    const ucl_object_t *, const char *, char *, size_t);
static const char *uni_ifname(struct plan *, const ucl_object_t *,
		    const ucl_object_t *, char *, size_t);

/*
 * The security policies of a service that filter DNS, as any of its
 * policies names them by af-security-ingress or -egress: whether any
 * denies domains, whether any keeps DNS to the provider's resolver.
 */
static bool
dns_filters(const ucl_object_t *sw, bool *protop)
{
	const ucl_object_t	*pol, *cr, *sec, *sc;
	ucl_object_iter_t	 it;
	int			 si, i;
	bool			 any = false;

	*protop = false;
	it = NULL;
	while ((pol = ucl_object_iterate(ucl_object_lookup(sw, "policies"),
	    &it, true)) != NULL) {
		for (i = 0; i < 2; i++) {
			sec = sec_of(sw, pol, i == 0 ? "af-security-ingress" :
			    "af-security-egress", &si);
			if (sec == NULL)
				continue;
			sc = ucl_object_lookup(sec, "criteria");
			if (ucl_object_lookup(sc, "dns-domain-filter") != NULL)
				any = true;
			if (ucl_flag(sc, "dns-protocol-filter")) {
				any = true;
				*protop = true;
			}
		}
		(void)cr;
	}
	return (any);
}

/*
 * The security policies of a service that filter URLs (SASE-4), as any
 * of its policies names them: whether any does, and whether any opens
 * TLS (inspect) rather than looking at its names (sni).
 */
static bool
url_filters(const ucl_object_t *sw, bool *inspectp)
{
	const ucl_object_t	*pol, *sec, *sc, *uf;
	ucl_object_iter_t	 it;
	int			 si, i;
	bool			 any = false;

	*inspectp = false;
	it = NULL;
	while ((pol = ucl_object_iterate(ucl_object_lookup(sw, "policies"),
	    &it, true)) != NULL)
		for (i = 0; i < 2; i++) {
			sec = sec_of(sw, pol, i == 0 ? "af-security-ingress" :
			    "af-security-egress", &si);
			if (sec == NULL)
				continue;
			sc = ucl_object_lookup(sec, "criteria");
			if ((uf = ucl_object_lookup(sc, "url-filter")) == NULL)
				continue;
			any = true;
			if (str(uf, "mode") != NULL && strcmp(str(uf, "mode"),
			    "inspect") == 0)
				*inspectp = true;
		}
	return (any);
}

/*
 * Whether a service's security policies, as its policies name them,
 * scan for malware (SASE-4, MEF 88's malware criterion): what comes
 * back over cleartext HTTP, and over TLS where it is opened, goes from
 * Squid to c-icap by ICAP and is scanned there by ClamAV.
 */
static bool
malware_scan(const ucl_object_t *sw)
{
	const ucl_object_t	*pol, *sec;
	ucl_object_iter_t	 it;
	int			 si, i;

	it = NULL;
	while ((pol = ucl_object_iterate(ucl_object_lookup(sw, "policies"),
	    &it, true)) != NULL)
		for (i = 0; i < 2; i++) {
			sec = sec_of(sw, pol, i == 0 ? "af-security-ingress" :
			    "af-security-egress", &si);
			if (sec != NULL && ucl_object_toboolean(ucl_object_lookup(
			    ucl_object_lookup(sec, "criteria"), "malware")))
				return (true);
		}
	return (false);
}

/* The port a service's c-icap answers its Squid on. */
#define	ICAP_PORT(fib)	(1344 + 10 * (int)(fib))

/*
 * c-icap's configuration for a service at an edge: an ICAP service
 * avscan that scans with ClamAV's module (c-icap-modules), on the
 * edge's own address in the service (own), where the service's Squid
 * reaches it, and taking no one else: the loopback is not the
 * service's table's (net.inet.tcp.bind_all_fibs is 0), so nothing in
 * the table can bind it.  The agent places @ICAPPID@ and @ICAPCMD@.
 */
static char *
icap_conf(const ucl_object_t *sw, const char *sid, const char *own)
{
	struct kore_buf	*b;
	char		*out;
	intmax_t	 fib;

	fib = (intmax_t)ucl_object_toint(ucl_object_lookup(sw, "fib"));
	b = kore_buf_alloc(1024);
	kore_buf_appendf(b, "# Written by the Arcana console: SD-WAN service %s "
	    "at %s, in routing table %jd.\n# Malware scanning of its security "
	    "policies (MEF 88), by c-icap and ClamAV, for its Squid.\n"
	    "PidFile @ICAPPID@\nCommandsSocket @ICAPCMD@\n"
	    "Port %s:%d\nacl squid src %s/255.255.255.255\nacl all src "
	    "0.0.0.0/0.0.0.0\nclient_access allow squid\nclient_access deny all\n"
	    "StartServers 1\nMaxServers 4\n"
	    "ServerLog /var/log/c-icap/sdwan-sw%jd-server.log\n"
	    "AccessLog /var/log/c-icap/sdwan-sw%jd-access.log\n"
	    "Module common clamav_mod.so\n"
	    "Service avscan virus_scan.so\n"
	    "virus_scan.ScanFileTypes TEXT DATA EXECUTABLE ARCHIVE DOCUMENT\n"
	    "virus_scan.SendPercentData 5\nvirus_scan.StartSendPercentDataAfter "
	    "2M\nvirus_scan.MaxObjectSize 32M\nvirus_scan.DefaultEngine clamav\n",
	    str(sw, "id"), server_name_of(sid), fib, own, ICAP_PORT(fib), own,
	    fib, fib);
	out = strdup(kore_buf_stringify(b, NULL));
	kore_buf_free(b);
	return (out);
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
 * Squid's configuration for a service at an edge (SASE-4): it takes
 * what ipfw forwards to it on each UNI's address, ports 3128 (HTTP)
 * and 3129 (TLS); it looks at the TLS names (peek) and ends a
 * connection to a denied one (terminate), the rest let through
 * unopened (splice) or, in mode inspect, opened (bump) with the
 * instance's CA; HTTP to a denied domain is denied.  What the agent
 * places is marked: @PID@, @CA@, @SSLDB@, @CERTGEN@, @DENY@.  The
 * domains denied go in the deny text, one a line, each with the names
 * beneath it.
 */
static char *
proxy_conf(struct plan *pl, const ucl_object_t *sw, const char *sid,
    bool inspect, char **denyp)
{
	struct kore_buf		*b, *d;
	const ucl_object_t	*ep, *o, *pol, *sec, *sc, *uf, *e, *p;
	ucl_object_iter_t	 it, pit, dit, eit;
	ucl_object_t		*owns, *pfx;
	char			*out, own[80];
	int			 i, si;
	bool			 dnsproto;

	b = kore_buf_alloc(4096);
	d = kore_buf_alloc(1024);
	kore_buf_appendf(b, "# Written by the Arcana console: SD-WAN service %s "
	    "at %s, in routing table %jd.\n# The URL filter of its security "
	    "policies (MEF 88), by Squid, mode %s.\npid_filename @PID@\n"
	    "access_log /var/log/squid/sdwan-sw%jd-access.log\ncache_log "
	    "/var/log/squid/sdwan-sw%jd-cache.log\ncache deny all\n"
	    "visible_hostname sdwan-sw%jd\n", str(sw, "id"), server_name_of(sid),
	    (intmax_t)ucl_object_toint(ucl_object_lookup(sw, "fib")), inspect ?
	    "inspect" : "sni", (intmax_t)ucl_object_toint(ucl_object_lookup(sw,
	    "fib")), (intmax_t)ucl_object_toint(ucl_object_lookup(sw, "fib")),
	    (intmax_t)ucl_object_toint(ucl_object_lookup(sw, "fib")));
	owns = ucl_object_typed_new(UCL_ARRAY);
	edge_own4(pl, sw, sid, owns);
	it = NULL;
	while ((o = ucl_object_iterate(owns, &it, true)) != NULL)
		kore_buf_appendf(b, "# %s\nhttp_port %s:3128 intercept\n"
		    "https_port %s:3129 intercept ssl-bump tls-cert=@CA@ "
		    "generate-host-certificates=on dynamic_cert_mem_cache_size=4MB"
		    "\n", str(o, "end_point"), str(o, "address"), str(o, "address"));
	/* The names it is asked for, resolved by the service's DNS filter
	 * where there is one, else by the edge's own resolver. */
	if (dns_filters(sw, &dnsproto) && ucl_array_size(owns) > 0)
		kore_buf_appendf(b, "dns_nameservers %s\n", str(
		    ucl_array_find_index(owns, 0), "address"));
	snprintf(own, sizeof(own), "%s", ucl_array_size(owns) > 0 ? str(
	    ucl_array_find_index(owns, 0), "address") : "127.0.0.1");
	ucl_object_unref(owns);
	kore_buf_appendf(b, "sslcrtd_program @CERTGEN@ -s @SSLDB@ -M 4MB\n"
	    "sslcrtd_children 3\n");
	/* The service's own hosts: every end point's prefixes. */
	kore_buf_appendf(b, "acl localnet src");
	i = 0;
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		pfx = ucl_object_typed_new(UCL_ARRAY);
		uni_prefixes(ep, pfx);
		eit = NULL;
		while ((p = ucl_object_iterate(pfx, &eit, true)) != NULL) {
			kore_buf_appendf(b, " %s", ucl_object_tostring(p));
			i++;
		}
		ucl_object_unref(pfx);
	}
	if (i == 0)
		kore_buf_appendf(b, " 0.0.0.0/0");
	/* What comes back, to c-icap by ICAP, where malware is scanned. */
	if (malware_scan(sw))
		kore_buf_appendf(b, "\nicap_enable on\nicap_send_client_ip on\n"
		    "icap_service sdwan_av respmod_precache bypass=off "
		    "icap://%s:%d/avscan\nadaptation_access sdwan_av allow "
		    "all", own, ICAP_PORT(ucl_object_toint(ucl_object_lookup(sw,
		    "fib"))));
	/* Domains let through whatever is denied (url-filter.allow): a
	 * site under a denied one, a list's mistake; inline, few. */
	{
		struct kore_buf	*al = kore_buf_alloc(512);

		pit = NULL;
		while ((pol = ucl_object_iterate(ucl_object_lookup(sw, "policies"),
		    &pit, true)) != NULL)
			for (i = 0; i < 2; i++) {
				sec = sec_of(sw, pol, i == 0 ? "af-security-ingress" :
				    "af-security-egress", &si);
				if (sec == NULL || (uf = ucl_object_lookup(
				    ucl_object_lookup(sec, "criteria"), "url-filter"))
				    == NULL)
					continue;
				dit = NULL;
				while ((e = ucl_object_iterate(ucl_object_lookup(uf,
				    "allow"), &dit, true)) != NULL)
					kore_buf_appendf(al, " .%s",
					    ucl_object_tostring_forced(e));
			}
		if (al->offset > 0) {
			kore_buf_appendf(b, "\nacl allowed_site ssl::server_name%s"
			    "\nacl allowed_url dstdomain%s\n", kore_buf_stringify(
			    al, NULL), kore_buf_stringify(al, NULL));
			kore_buf_appendf(b, "acl denied_site ssl::server_name "
			    "\"@DENY@\"\nacl denied_url dstdomain \"@DENY@\"\nacl "
			    "step1 at_step SslBump1\nssl_bump peek step1\nssl_bump "
			    "splice allowed_site\nssl_bump terminate denied_site\n"
			    "ssl_bump %s all\nhttp_access allow allowed_url\n"
			    "http_access deny denied_url\nhttp_access allow localnet"
			    "\nhttp_access deny all\n", inspect ? "bump" : "splice");
		} else
			kore_buf_appendf(b, "\nacl denied_site ssl::server_name "
			    "\"@DENY@\"\nacl denied_url dstdomain \"@DENY@\"\nacl "
			    "step1 at_step SslBump1\nssl_bump peek step1\nssl_bump "
			    "terminate denied_site\nssl_bump %s all\nhttp_access deny "
			    "denied_url\nhttp_access allow localnet\nhttp_access deny "
			    "all\n", inspect ? "bump" : "splice");
		kore_buf_free(al);
	}
	/* The domains denied, each with the names beneath it. */
	pit = NULL;
	while ((pol = ucl_object_iterate(ucl_object_lookup(sw, "policies"),
	    &pit, true)) != NULL)
		for (i = 0; i < 2; i++) {
			sec = sec_of(sw, pol, i == 0 ? "af-security-ingress" :
			    "af-security-egress", &si);
			if (sec == NULL)
				continue;
			sc = ucl_object_lookup(sec, "criteria");
			if ((uf = ucl_object_lookup(sc, "url-filter")) == NULL)
				continue;
			dit = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(uf, "deny"),
			    &dit, true)) != NULL)
				kore_buf_appendf(d, ".%s\n", ucl_object_tostring_forced(
				    e));
			dit = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(uf, "lists"),
			    &dit, true)) != NULL) {
				const ucl_object_t	*le;
				const char		*s;

				eit = NULL;
				while ((le = ucl_object_iterate(at_path(
				    ucl_object_lookup(pl->lists, "lists"),
				    ucl_object_tostring_forced(e), "entries"), &eit,
				    true)) != NULL) {
					s = ucl_object_tostring_forced(le);
					if (strchr(s, '/') != NULL || strchr(s, ':') !=
					    NULL || (isdigit((unsigned char)s[0]) &&
					    strchr(s, '.') != NULL && strpbrk(s,
					    "abcdefghijklmnopqrstuvwxyz") == NULL))
						continue;	/* a prefix */
					kore_buf_appendf(d, ".%s\n", s);
				}
			}
		}
	*denyp = strdup(kore_buf_stringify(d, NULL));
	kore_buf_free(d);
	out = strdup(kore_buf_stringify(b, NULL));
	kore_buf_free(b);
	return (out);
}

/*
 * Each edge's proxies (SASE-4): an instance per service whose policies
 * name a security policy that filters URLs, where the edge has an end
 * point of the service, in the service's table; Squid is a plugin the
 * edge has installed, which the apply tells when it has not.
 */
static void
proxy_build(struct plan *pl, const ucl_object_t *doc)
{
	const ucl_object_t	*sw, *edge, *ep;
	ucl_object_iter_t	 it, eit, pit;
	ucl_object_t		*o, *inst, *list;
	char			 name[32];
	const char		*sid;
	char			*text, *deny;
	bool			 here, inspect;

	it = NULL;
	while ((edge = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL) {
		sid = str(edge, "server");
		list = ucl_object_typed_new(UCL_ARRAY);
		eit = NULL;
		while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"),
		    &eit, true)) != NULL) {
			if (!url_filters(sw, &inspect) && !malware_scan(sw))
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
			put(inst, "mode", S(inspect ? "inspect" : "sni"));
			text = proxy_conf(pl, sw, sid, inspect, &deny);
			put(inst, "conf", S(text));
			put(inst, "deny", S(deny));
			free(text);
			free(deny);
			if (malware_scan(sw)) {
				ucl_object_t	*owns = ucl_object_typed_new(
				    UCL_ARRAY);

				edge_own4(pl, sw, sid, owns);
				text = icap_conf(sw, sid, ucl_array_size(owns) > 0 ?
				    str(ucl_array_find_index(owns, 0), "address") :
				    "127.0.0.1");
				ucl_object_unref(owns);
				put(inst, "icap", S(text));
				free(text);
			}
			ucl_array_append(list, inst);
		}
		if (ucl_array_size(list) == 0) {
			ucl_object_unref(list);
			continue;
		}
		o = object(pl, sid, "proxy", PH_BIRD, "URL filters and malware "
		    "scanning: Squid (and c-icap with ClamAV where malware is "
		    "scanned), plugins, %u instance%s in the services' tables",
		    ucl_array_size(list), ucl_array_size(list) == 1 ? "" : "s");
		if (o == NULL) {
			ucl_object_unref(list);
			continue;
		}
		make(o, job("sdwan-proxy", "instances", list, NULL));
		unmake(o, job("sdwan-proxy", "instances", ucl_object_typed_new(
		    UCL_ARRAY), NULL));
	}
}

/* The rules suricata-update keeps, where its defaults put them. */
/* The divert port of a service's Suricata, where it prevents. */
#define	IDS_PORT(fib)	(8000 + (int)(fib))

/*
 * A service's intrusion detection (SASE-4, the ids criterion, Arcana's
 * own: no MEF Security Function is intrusion detection), as
 * its policies name it: the rules of its own, one a line, each once,
 * whether the ruleset is added, and whether it prevents (one of its
 * policies says prevent).  False when none of its security policies has
 * ids.
 */
static bool
ids_of(const ucl_object_t *sw, struct kore_buf *rules, bool *rulesetp,
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
			if (sec == NULL || (ids = ucl_object_lookup(
			    ucl_object_lookup(sec, "criteria"), "ids")) == NULL ||
			    ucl_object_type(ids) != UCL_OBJECT)
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
					kore_buf_appendf(rules, "%s\n",
					    ucl_object_tostring(r));
			}
		}
	ucl_object_unref(seen);
	return (any);
}

/*
 * Suricata's configuration for a service at an edge: it watches the
 * interfaces named (the service's UNIs here) by libpcap, its home
 * network the service's UNI subnets, and writes its alerts as eve.json
 * in its log directory, which the agent reads.  The agent places
 * @LOGDIR@, @RULES@ and @PID@.
 */
static char *
ids_conf(const ucl_object_t *sw, const char *sid, const ucl_object_t *ifs,
    bool ruleset)
{
	struct kore_buf		*b;
	const ucl_object_t	*ep, *u, *v, *f;
	ucl_object_iter_t	 it;
	char			*out;
	int			 i, n;

	b = kore_buf_alloc(4096);
	kore_buf_appendf(b, "%%YAML 1.1\n---\n# Written by the Arcana console: "
	    "SD-WAN service %s at %s.\n# The intrusion detection of its "
	    "security policies (MEF 88), by Suricata.\nvars:\n  "
	    "address-groups:\n    HOME_NET: \"[", str(sw, "id"),
	    server_name_of(sid));
	n = 0;
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if ((u = ucl_object_lookup(ep, "uni")) == NULL)
			continue;
		for (i = 0; i < 2; i++) {
			v = ucl_object_lookup(u, i == 0 ? "ipv4" : "ipv6");
			if (str(v, "prefix") == NULL)
				continue;
			kore_buf_appendf(b, "%s%s", n++ > 0 ? "," : "", str(v,
			    "prefix"));
		}
	}
	if (n == 0)
		kore_buf_appendf(b, "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16");
	kore_buf_appendf(b, "]\"\n    EXTERNAL_NET: \"!$HOME_NET\"\n");
	/* The groups the common rule sets name, as Suricata's own file has
	 * them. */
	kore_buf_appendf(b,
	    "    HTTP_SERVERS: \"$HOME_NET\"\n    SMTP_SERVERS: \"$HOME_NET\"\n"
	    "    SQL_SERVERS: \"$HOME_NET\"\n    DNS_SERVERS: \"$HOME_NET\"\n"
	    "    TELNET_SERVERS: \"$HOME_NET\"\n    AIM_SERVERS: "
	    "\"$EXTERNAL_NET\"\n    DC_SERVERS: \"$HOME_NET\"\n    DNP3_SERVER: "
	    "\"$HOME_NET\"\n    DNP3_CLIENT: \"$HOME_NET\"\n    MODBUS_CLIENT: "
	    "\"$HOME_NET\"\n    MODBUS_SERVER: \"$HOME_NET\"\n    ENIP_CLIENT: "
	    "\"$HOME_NET\"\n    ENIP_SERVER: \"$HOME_NET\"\n  port-groups:\n"
	    "    HTTP_PORTS: \"80\"\n    SHELLCODE_PORTS: \"!80\"\n"
	    "    ORACLE_PORTS: 1521\n    SSH_PORTS: 22\n    DNP3_PORTS: 20000\n"
	    "    MODBUS_PORTS: 502\n    FILE_DATA_PORTS: \"[$HTTP_PORTS,110,"
	    "143]\"\n    FTP_PORTS: 21\n    GENEVE_PORTS: 6081\n    VXLAN_PORTS: "
	    "4789\n    TEREDO_PORTS: 3544\n"
	    "default-log-dir: @LOGDIR@\n"
	    "outputs:\n  - eve-log:\n      enabled: yes\n      filetype: regular\n"
	    "      filename: eve.json\n      types:\n        - alert\n"
	    "logging:\n  default-log-level: notice\n  outputs:\n    - console:\n"
	    "        enabled: no\n    - file:\n        enabled: yes\n"
	    "        level: info\n        filename: suricata.log\n"
	    "pcap:\n");
	it = NULL;
	while ((f = ucl_object_iterate(ifs, &it, true)) != NULL)
		kore_buf_appendf(b, "  - interface: %s\n",
		    ucl_object_tostring(f));
	kore_buf_appendf(b, "rule-files:\n  - @RULES@\n");
	if (ruleset)
		kore_buf_appendf(b, "  - @RULESET@\n");
	kore_buf_appendf(b, "classification-file: "
	    "/usr/local/etc/suricata/classification.config\n"
	    "reference-config-file: /usr/local/etc/suricata/reference.config\n"
	    "run-as:\n  user: root\n");
	/*
	 * Where it prevents and the edge itself answers some of the UNI's
	 * traffic (the URL filter's Squid, malware scanning behind it, the
	 * DNS filter), it sees one side of those flows: what the edge sends
	 * back goes out to the UNI without it.  Such a flow is taken as it
	 * comes, and a packet of it that looks wrong for want of the other
	 * side is let by, not dropped; what its rules drop is dropped all
	 * the same, though one side alone may let a packet by before.
	 * Elsewhere it sees both sides and stays strict.
	 */
	{
		bool	x, prevent, rs;

		if (ids_of(sw, NULL, &rs, &prevent) && prevent && (url_filters(
		    sw, &x) || malware_scan(sw) || (dns_filters(sw, &x) && x)))
			kore_buf_appendf(b, "stream:\n  midstream: true\n"
			    "  async-oneside: true\n  drop-invalid: no\n");
	}
	out = strdup(kore_buf_stringify(b, NULL));
	kore_buf_free(b);
	return (out);
}

/*
 * Each edge's intrusion detection (SASE-4): an instance per service
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
	struct kore_buf		*rules;
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
			text = ids_conf(sw, sid, ifs, ruleset);
			put(inst, "interfaces", ifs);
			put(inst, "conf", S(text));
			free(text);
			if (prevent) {
				put(inst, "divert", I(IDS_PORT(ucl_object_toint(
				    ucl_object_lookup(sw, "fib")))));
				prevents = true;
			}
			rules = kore_buf_alloc(1024);
			(void)ids_of(sw, rules, &ruleset, NULL);
			text = kore_buf_stringify(rules, NULL);
			put(inst, "rules", S(text));
			kore_buf_free(rules);
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

/*
 * unbound's configuration for a service at an edge: it listens on the
 * UNIs' provider addresses, answers the UNIs' subnets, resolves by
 * itself, and denies every domain the service's filtering policies
 * deny (always_nxdomain, the names beneath too).
 */
static char *
dns_conf(const ucl_object_t *sw, const char *sid, const ucl_object_t *lists)
{
	struct kore_buf		*b;
	const ucl_object_t	*ep, *u, *v, *a, *pol, *sec, *sc, *d;
	ucl_object_iter_t	 it, pit, dit;
	char			*out;
	int			 i, si;

	b = kore_buf_alloc(2048);
	kore_buf_appendf(b, "# Written by the Arcana console: SD-WAN service %s "
	    "at %s, in routing table %jd.\n# The DNS filter of its security "
	    "policies (MEF 88), by the base system's unbound.\nserver:\n\t"
	    "verbosity: 0\n\tdo-daemonize: yes\n\tmodule-config: \"iterator\"\n"
	    "\tdo-not-query-localhost: no\n", str(sw, "id"), server_name_of(sid),
	    (intmax_t)ucl_object_toint(ucl_object_lookup(sw, "fib")));
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		if ((u = ucl_object_lookup(ep, "uni")) == NULL)
			continue;	/* a remote end point (SASE-3) */
		for (i = 0; i < 2; i++) {
			v = ucl_object_lookup(u, i == 0 ? "ipv4" : "ipv6");
			if (str(v, "prefix") == NULL)
				continue;
			a = ucl_array_find_index(ucl_object_lookup(v, "provider"), 0);
			if (a == NULL)
				continue;
			kore_buf_appendf(b, "\t# UNI %s\n\tinterface: %s\n\t"
			    "access-control: %s allow\n", str(u, "id"),
			    ucl_object_tostring_forced(a), str(v, "prefix"));
		}
	}
	pit = NULL;
	while ((pol = ucl_object_iterate(ucl_object_lookup(sw, "policies"),
	    &pit, true)) != NULL)
		for (i = 0; i < 2; i++) {
			sec = sec_of(sw, pol, i == 0 ? "af-security-ingress" :
			    "af-security-egress", &si);
			if (sec == NULL)
				continue;
			sc = ucl_object_lookup(sec, "criteria");
			dit = NULL;
			while ((d = ucl_object_iterate(ucl_object_lookup(
			    ucl_object_lookup(sc, "dns-domain-filter"), "deny"),
			    &dit, true)) != NULL)
				kore_buf_appendf(b, "\tlocal-zone: \"%s.\" "
				    "always_nxdomain\n",
				    ucl_object_tostring_forced(d));
			/* And the named lists' domains, as kept. */
			dit = NULL;
			while ((d = ucl_object_iterate(ucl_object_lookup(
			    ucl_object_lookup(sc, "dns-domain-filter"), "lists"),
			    &dit, true)) != NULL) {
				const ucl_object_t	*le;
				ucl_object_iter_t	 eit = NULL;
				const char		*s;

				while ((le = ucl_object_iterate(at_path(
				    ucl_object_lookup(lists, "lists"),
				    ucl_object_tostring_forced(d), "entries"), &eit,
				    true)) != NULL) {
					s = ucl_object_tostring_forced(le);
					if (strchr(s, '/') != NULL || strchr(s, ':') !=
					    NULL || (isdigit((unsigned char)s[0]) &&
					    strchr(s, '.') != NULL && strpbrk(s,
					    "abcdefghijklmnopqrstuvwxyz") == NULL))
						continue;	/* a prefix */
					kore_buf_appendf(b, "\tlocal-zone: \"%s.\" "
					    "always_nxdomain\n", s);
				}
			}
		}
	out = strdup(kore_buf_stringify(b, NULL));
	kore_buf_free(b);
	return (out);
}

/*
 * Each edge's DNS filters: an instance per service whose policies name
 * a security policy that filters DNS, where the edge has a UNI of the
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
	char			*text;
	bool			 here, proto;

	it = NULL;
	while ((edge = ucl_object_iterate(ucl_object_lookup(doc, "edges"), &it,
	    true)) != NULL) {
		sid = str(edge, "server");
		list = ucl_object_typed_new(UCL_ARRAY);
		eit = NULL;
		while ((sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"),
		    &eit, true)) != NULL) {
			if (!dns_filters(sw, &proto))
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
			text = dns_conf(sw, sid, pl->lists);
			put(inst, "conf", S(text));
			free(text);
			ucl_array_append(list, inst);
		}
		if (ucl_array_size(list) == 0) {
			ucl_object_unref(list);
			continue;
		}
		o = object(pl, sid, "dns", PH_BIRD, "DNS filters: unbound, %u "
		    "instance%s in the services' tables, the domains the security "
		    "policies deny", ucl_array_size(list), ucl_array_size(list) ==
		    1 ? "" : "s");
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

/*
 * A security policy's rate limit (MEF 88): a pipe of its own, one per
 * policy of the service; -1 for none or too many.
 */
static int
sec_pipe(struct dn *dn, const ucl_object_t *sw, const ucl_object_t *sec)
{
	const ucl_object_t	*v;
	char			 key[160];
	int			 i;

	v = ucl_object_lookup(ucl_object_lookup(sec, "criteria"), "rate-limit");
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

/*
 * The rules of a security policy's ip-block for a flow (MEF 88): what
 * is to or from a denied prefix is dropped, unless the prefix is among
 * the allowed, logged where the policy says; the prefixes in tables of
 * the policy's own, sw<fib>_s<i>d4, d6, a4 and a6, filled once.  The
 * tail is what ends each rule: where it comes in, or goes out.
 */
static void
sec_rules(ucl_object_t *tables, ucl_object_t *rules, int num,
    const ucl_object_t *sw, const ucl_object_t *sec, int si,
    const ucl_object_t *cr, const char *appid, const char *tail,
    const ucl_object_t *lists_of)
{
	static const char *const lists[] = { "deny", "allow" };
	const ucl_object_t	*ib, *p;
	ucl_object_iter_t	 it;
	char			 name[2][64], tbl[80], words[2000], not[100];
	const char		*s;
	bool			 has[2], logit;
	int			 fam, f2, i;

	ib = ucl_object_lookup(ucl_object_lookup(sec, "criteria"), "ip-block");
	if (ib == NULL)
		return;
	logit = ucl_flag(ucl_object_lookup(sec, "criteria"), "log");
	for (fam = 4; fam <= 6; fam += 2) {
		for (i = 0; i < 2; i++) {
			bool	fresh;

			snprintf(name[i], sizeof(name[i]), "sw%jd_s%d%c%d",
			    (intmax_t)ucl_object_toint(ucl_object_lookup(sw, "fib")),
			    si, lists[i][0], fam);
			has[i] = false;
			fresh = by(tables, "name", name[i]) == NULL;
			it = NULL;
			while ((p = ucl_object_iterate(ucl_object_lookup(ib,
			    lists[i]), &it, true)) != NULL) {
				s = ucl_object_tostring_forced(p);
				if ((strchr(s, ':') != NULL) != (fam == 6))
					continue;
				if (fresh)
					entry(table(tables, name[i], "legacy"), s,
					    "0");
				has[i] = true;
			}
			/* And the named lists' prefixes (the deny ones; feeds
			 * and pasted lists, as kept), of the family. */
			if (i == 0) {
				const ucl_object_t	*ln, *le;
				ucl_object_iter_t	 lit, eit;

				lit = NULL;
				while ((ln = ucl_object_iterate(ucl_object_lookup(ib,
				    "lists"), &lit, true)) != NULL) {
					eit = NULL;
					while ((le = ucl_object_iterate(at_path(
					    ucl_object_lookup(lists_of, "lists"),
					    ucl_object_tostring_forced(ln), "entries"),
					    &eit, true)) != NULL) {
						s = ucl_object_tostring_forced(le);
						if (strchr(s, '/') == NULL && !(
						    strchr(s, ':') != NULL || (isdigit(
						    (unsigned char)s[0]) && strchr(s,
						    '.') != NULL)))
							continue;	/* a domain */
						if ((strchr(s, ':') != NULL) != (fam ==
						    6))
							continue;
						if (fresh)
							entry(table(tables, name[i],
							    "legacy"), s, "0");
						has[i] = true;
					}
				}
			}
			if (has[i] && !fresh)
				table(tables, name[i], "legacy");
		}
		if (!has[0])
			continue;
		/* To a denied prefix, and from one.  With log, each packet is
		 * told on the routing socket (ipfw's logdst rtsock), which
		 * the agent reads into its record; the rule's comment names
		 * the service and the policy for it (SASE-2).  A thousand a
		 * rule between resets, which the agent asks for. */
		snprintf(tbl, sizeof(tbl), "table(%s)", name[0]);
		not[0] = '\0';
		if (has[1])
			snprintf(not, sizeof(not), " not dst-ip table(%s)", name[1]);
		if (afs_words(cr, tbl, appid, words, sizeof(words), &f2) && (f2 ==
		    0 || f2 == fam))
			rule(rules, num, "deny%s %s%s%s%s%.30s %.30s dst", logit ?
			    " log logdst rtsock logamount 1000" : "", words, not, tail,
			    logit ? " // security " : "", logit ? str(sw, "id") : "",
			    logit ? str(sec, "name") : "");
		not[0] = '\0';
		if (has[1])
			snprintf(not, sizeof(not), " not src-ip table(%s)", name[1]);
		if (afs_words(cr, NULL, appid, words, sizeof(words), &f2) && (f2 ==
		    0 || f2 == fam))
			rule(rules, num, "deny%s %s src-ip table(%s)%s%s%s%.30s %.30s "
			    "src", logit ? " log logdst rtsock logamount 1000" : "",
			    words, name[0], not, tail, logit ? " // security " : "",
			    logit ? str(sw, "id") : "", logit ? str(sec, "name") : "");
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
	const char		*kind;
	int			 mtu, over;

	if ((u = by(ucl_object_lookup(doc, "ucs"), "id", str(t, "ucs"))) ==
	    NULL || (tt = ucl_object_lookup(u, "tunnel")) == NULL ||
	    (v = ucl_object_lookup(tt, "mss")) == NULL)
		return (0);
	if (ucl_object_type(v) == UCL_INT)
		return ((int)ucl_object_toint(v));
	kind = str(t, "kind") != NULL ? str(t, "kind") : "gre";
	over = strcmp(kind, "gif") == 0 ? 20 : strcmp(kind, "geneve") == 0 ?
	    50 : strcmp(kind, "wg") == 0 ? 60 : strcmp(kind, "uswe") == 0 ? 73 :
	    24;
	if (ucl_flag(t, "ipsec"))
		over += 64;
	if (str(end, "underlay") != NULL && strchr(str(end, "underlay"), ':')
	    != NULL)
		over += 20;
	mtu = 1500 - over;
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
 * The groups of a remote end point (SASE-3): a table each of its live
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
					    (intmax_t)ucl_object_toint(
					    ucl_object_lookup(sw, "fib")), uni);
					for (x = 0; x < np; x++)
						rule(rules, RULE_FROM, "setfib %jd ip4 from "
						    "any to %s in diverted-loopback not dst-ip "
						    "me",
						    (intmax_t)ucl_object_toint(
						    ucl_object_lookup(sw, "fib")), pfx[x]);
				}
			}
			/* DNS kept to the provider's resolver, where a security
			 * policy says so (MEF 88 dns-protocol-filter): every
			 * query from the UNI goes to the filter here. */
			{
				const ucl_object_t	*pv, *pa;
				bool			 proto;

				char			 rown[80];
				const char		*at;

				pv = ucl_object_lookup(ucl_object_lookup(ep, "uni"),
				    "ipv4");
				pa = pv != NULL ? ucl_array_find_index(
				    ucl_object_lookup(pv, "provider"), 0) : NULL;
				at = pa != NULL ? ucl_object_tostring_forced(pa) :
				    NULL;
				/* A remote end point's: the edge's own there. */
				if (pa == NULL && ucl_object_lookup(ep, "remote") !=
				    NULL && remote_addr(pl, sw, ep, NULL, rown,
				    sizeof(rown)) && family(rown) == AF_INET)
					at = rown;
				if (at != NULL && dns_filters(sw, &proto) && proto) {
					rule(rules, RULE_FROM, "fwd %s,53 udp from any "
					    "to any dst-port 53 in recv %s", at, uni);
					rule(rules, RULE_FROM, "fwd %s,53 tcp from any "
					    "to any dst-port 53 in recv %s", at, uni);
				}
				/* URLs filtered by the proxy (SASE-4): HTTP and
				 * TLS from the end point to it, on the edge's own
				 * address there. */
				if (at != NULL && url_filters(sw, &proto)) {
					rule(rules, RULE_FROM, "fwd %s,3128 tcp from any "
					    "to any dst-port 80 in recv %s", at, uni);
					rule(rules, RULE_FROM, "fwd %s,3129 tcp from any "
					    "to any dst-port 443 in recv %s", at, uni);
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
			 * points (SASE-3): each by its address; a Default
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
					/* Its security policy (MEF 88, by
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
						if (pol != NULL && sec != NULL)
							sec_rules(tables, rules, next,
							    sw, sec, si, cr, appid,
							    recv, pl->lists);
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
					/* And its security policy (MEF 88, by
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

							if (sec != NULL)
								sec_rules(tables, pre,
								    RULE_FROM + 1, sw,
								    sec, si, cr, appid,
								    tail, pl->lists);
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
bird_channel(struct kore_buf *b, const char *fam, int64_t pref,
    const char *export)
{

	/* BIRD 3 has a route's preference in the channel, not the
	 * protocol. */
	kore_buf_appendf(b, "\t%s {\n\t\tpreference %jd;\n\t\timport all;\n"
	    "\t\texport %s;\n\t};\n", fam, (intmax_t)pref, export);
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
	const ucl_object_t	*ep, *u, *t, *e0, *e1, *me, *far, *v, *cp;
	ucl_object_iter_t	 it, tit;
	const char		*rid, *ifn;
	char			 ifbuf[32], ifaces[1200], sym[80], *out;
	int64_t			 as;
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
		if ((u = ucl_object_lookup(ep, "uni")) == NULL)
			continue;	/* a remote end point (SASE-3) */
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
	/* iBGP with each other edge, by each tunnel between them; or, with
	 * a control plane (Mplify 119 §8.3), with its host alone, which
	 * reflects to all (RFC 4456). */
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
		/* The service domain's prefix, the tunnels' addresses, too. */
		rp = ucl_object_lookup(ucl_object_lookup(ucl_object_lookup(sw,
		    "domains"), "service"), "prefix");
		if (rp != NULL && strlen(resv) + 60 < sizeof(resv))
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
		kore_buf_appendf(b, "\tauthentication md5;\n\tpassword \"%s\";\n",
		    str(sw, "md5"));
	kore_buf_appendf(b, "\tipv4 {\n\t\timport all;\n\t\texport filter "
	    "to_edges;\n\t\tnext hop self;\n\t};\n\tipv6 {\n\t\timport all;\n\t\t"
	    "export filter to_edges;\n\t\tnext hop self;\n\t};\n}\n\n");
	cp = is_nullish(ucl_object_lookup(sw, "control_plane")) ? NULL :
	    ucl_object_lookup(sw, "control_plane");
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
		kore_buf_appendf(b, "# %s, to %s%s\nprotocol bgp edge%d from edge {\n\t"
		    "local %s as %jd;\n\tneighbor %s as %jd;\n", str(t, "id"),
		    server_name_of(str(far, "edge")), cp == NULL ? "" : strcmp(sid,
		    str(cp, "host")) == 0 ? ", a client of this reflector" : ", "
		    "the control plane", k++, str(me, "inner4") != NULL ? str(me,
		    "inner4") : str(me, "inner6"), (intmax_t)as, str(far, "inner4")
		    != NULL ? str(far, "inner4") : str(far, "inner6"), (intmax_t)as);
		if (cp != NULL && strcmp(sid, str(cp, "host")) == 0) {
			kore_buf_appendf(b, "\trr client;\n");
			if (str(cp, "cluster_id") != NULL)
				kore_buf_appendf(b, "\trr cluster id %s;\n", str(cp,
				    "cluster_id"));
		}
		kore_buf_appendf(b, "}\n\n");
	}
	/* At each UNI here: BGP, OSPF, as its entry says. */
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		if (strcmp(str(ep, "edge"), sid) != 0)
			continue;
		if ((u = ucl_object_lookup(ep, "uni")) == NULL)
			continue;	/* a remote end point (SASE-3) */
		ifn = uni_ifname(pl, sw, ep, ifbuf, sizeof(ifbuf));
		symbol(str(ep, "id"), sym, sizeof(sym));
		bird_routing(b, u, "UNI", str(u, "id"), sym, ifn, as);
	}
	out = strdup(kore_buf_stringify(b, NULL));
	kore_buf_free(b);
	return (out);
}

/*
 * BGP and OSPF with a neighbour at an interface, as an entry says them
 * (§11.6.2, §11.6.3): a UNI's with the subscriber (protocols uni_*), a
 * UCS End Point's with the underlay (ucs_*, Mplify 119 §12.2.3.5).
 */
static void
bird_routing(struct kore_buf *b, const ucl_object_t *u, const char *what,
    const char *id, const char *sym, const char *ifn, int64_t as)
{
	const ucl_object_t	*r, *m;
	ucl_object_iter_t	 nit;
	const char		*fam, *pfx;
	int64_t			 dist;
	int			 n;

	pfx = strcmp(what, "UNI") == 0 ? "uni" : "ucs";
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
				kore_buf_appendf(b, "# %s %s, the neighbour's %s\nprotocol "
				    "bgp %s_%s_%d {\n\tlocal as %jd;\n\tneighbor "
				    "%s as %jd;\n\tinterface \"%s\";\n", what, id,
				    ucl_object_tostring_forced(m),
				    pfx, sym, n++, (intmax_t)as,
				    ucl_object_tostring_forced(m), (intmax_t)
				    ucl_object_toint(ucl_object_lookup(r, "as")),
				    ifn);
				if (str(r, "password") != NULL)
					kore_buf_appendf(b, "\tauthentication md5;\n"
					    "\tpassword \"%s\";\n", str(r, "password"));
				if (ucl_object_lookup(r, "hold_time") != NULL)
					kore_buf_appendf(b, "\thold time %jd;\n", (intmax_t)
					    ucl_object_toint(ucl_object_lookup(r,
					    "hold_time")));
				if (strcmp(fam, "ipv6") != 0 && family(
				    ucl_object_tostring_forced(m)) == AF_INET)
					bird_channel(b, "ipv4", 256 - dist, exp);
				if (strcmp(fam, "ipv4") != 0 && family(
				    ucl_object_tostring_forced(m)) == AF_INET6)
					bird_channel(b, "ipv6", 256 - dist, exp);
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
				kore_buf_appendf(b, "# %s %s, OSPF%s with the neighbour\n"
				    "protocol ospf %s %s_%s_%s {\n", what, id, vi ==
				    0 ? "v2" : "v3", vers[vi], pfx, sym, vers[vi]);
				bird_channel(b, vi == 0 ? "ipv4" : "ipv6", 256 - dist,
				    "all");
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

/* "\tkernel table N;\n" for a table that is not the first. */
static const char *
wfmt_table(int64_t fib)
{
	static char	buf[48];

	snprintf(buf, sizeof(buf), "\tkernel table %jd;\n", (intmax_t)fib);
	return (buf);
}

/* A UCS End Point's BIRD instance text: routing with the underlay in
 * the end point's table (Mplify 119 §12.2.3.5). */
static char *
ucs_bird_conf(struct plan *pl, const ucl_object_t *edge,
    const ucl_object_t *uep, int64_t vrf)
{
	struct kore_buf	*b;
	const char	*addr;
	char		 sym[80], *out;
	int64_t		 as;

	b = kore_buf_alloc(4096);
	addr = ucs_address(pl, str(edge, "server"), uep);
	as = ucl_object_lookup(ucl_object_lookup(ucl_object_lookup(uep,
	    "routing"), "bgp"), "as") != NULL ? ucl_object_toint(
	    ucl_object_lookup(ucl_object_lookup(ucl_object_lookup(uep,
	    "routing"), "bgp"), "local_as")) : DEFAULT_AS;
	if (ucl_object_lookup(ucl_object_lookup(ucl_object_lookup(uep,
	    "routing"), "bgp"), "local_as") == NULL)
		as = DEFAULT_AS;
	kore_buf_appendf(b, "# Written by the Arcana console: UCS end point %s at "
	    "%s, routing with the underlay in table %jd.\n# Changed by the "
	    "console's next apply.\nrouter id %s;\nlog syslog { warning, error "
	    "};\n\nprotocol device {\n}\n\nprotocol direct {\n\tipv4;\n\tipv6;\n\t"
	    "interface \"%s\";\n}\n\nprotocol kernel kernel4 {\n%s\tlearn;\n\t"
	    "persist;\n\tipv4 {\n\t\timport all;\n\t\texport where source != "
	    "RTS_DEVICE && source != RTS_INHERIT && dest = RTD_UNICAST;\n\t};\n}"
	    "\n\nprotocol kernel kernel6 {\n%s\tlearn;\n\tpersist;\n\tipv6 {\n\t\t"
	    "import all;\n\t\texport where source != RTS_DEVICE && source != "
	    "RTS_INHERIT && dest = RTD_UNICAST;\n\t};\n}\n\n", str(uep, "id"),
	    server_name_of(str(edge, "server")), (intmax_t)vrf, addr != NULL &&
	    family(addr) == AF_INET ? addr : "0.0.0.2", str(uep, "interface"),
	    vrf > 0 ? wfmt_table(vrf) : "", vrf > 0 ? wfmt_table(vrf) : "");
	symbol(str(uep, "id"), sym, sizeof(sym));
	bird_routing(b, ucl_object_lookup(uep, "routing"), "UCS", str(uep, "id"),
	    sym, str(uep, "interface"), as);
	out = strdup(kore_buf_stringify(b, NULL));
	kore_buf_free(b);
	return (out);
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
				text = ucs_bird_conf(pl, edge, uep, vrf);
				put(inst, "conf", S(text));
				free(text);
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
			/* A breakout domain of its own (Mplify 119 R20-R26):
			 * the default route there, the UNIs' routes with it,
			 * the subscriber's table without a default route. */
			fib = bo_fib_of(sw);
			if (fib != ucl_object_toint(ucl_object_lookup(sw, "fib")))
				breakout_uni_routes(pl, sid, sw, fib);
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
				route_fib_obj(pl, sid, sw, fib, PH_ROUTE, n, str(bo,
				    "interface"), "the breakout gateway, by its "
				    "interface");
				route_fib_obj(pl, sid, sw, fib, PH_ROUTE, af ==
				    AF_INET ? "0.0.0.0/0" : "::/0", gw, "the Internet, "
				    "by local breakout");
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
	const char	*e, *st;
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
	json = hosts_submit(uri, peer, name, jj, &status, &e);
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


/* ---- The lists (MEF 88, SASE-2): feeds fetched by the console, pasted
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

/* The feeds fetched again when the interval has passed. */
static void
lists_tick(time_t now)
{
	ucl_object_t	*kept;
	int64_t		 hours;

	kept = lists_kept();
	hours = ucl_object_lookup(kept, "interval") != NULL ? ucl_object_toint(
	    ucl_object_lookup(kept, "interval")) : FEED_INTERVAL_H;
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
			return (KORE_RESULT_OK);
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
		return (KORE_RESULT_OK);
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

/* ---- Identities (SASE-3): issued, listed, revoked ------------------- */

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
	    kore_base64_encode(raw, n, &b64) == KORE_RESULT_OK) {
		snprintf(priv, plen, "%s", b64);
		explicit_bzero(b64, strlen(b64));
		kore_free(b64);
		n = sizeof(raw);
		if (EVP_PKEY_get_raw_public_key(k, raw, &n) == 1 && n ==
		    sizeof(raw) && kore_base64_encode(raw, n, &b64) ==
		    KORE_RESULT_OK) {
			snprintf(pub, publen, "%s", b64);
			kore_free(b64);
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
		return (KORE_RESULT_OK);
	if (!wg_keypair(priv, sizeof(priv), pub, sizeof(pub)))
		return (reply_error(req, 500, "keygen", "no X25519 key pair"));
	out = ucl_object_typed_new(UCL_OBJECT);
	put(out, "private_key", S(priv));
	put(out, "public_key", S(pub));
	explicit_bzero(priv, sizeof(priv));
	/* A preshared key too, 32 random bytes, for the client to use. */
	arc4random_buf(raw, sizeof(raw));
	if (kore_base64_encode(raw, sizeof(raw), &psk) == KORE_RESULT_OK) {
		put(out, "preshared_key", S(psk));
		explicit_bzero(psk, strlen(psk));
		kore_free(psk);
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
 * An identity's session (S3.4): its peer as the edge's wg(8) tells it,
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
	struct kore_buf		*b;
	struct net		 n;
	char			 addr[80], own[80], uri[256], peer[256], hname[128];
	char			*json, *text, jail[64];
	const char		*endpoint, *key;
	int			 status, k;
	bool			 proto;

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
	b = kore_buf_alloc(2048);
	kore_buf_appendf(b, "# %s, identity %s of %s: shown once, kept nowhere "
	    "by the console.\n[Interface]\nPrivateKey = %s\nAddress = %s/%d\n",
	    str(sw, "id"), name, str(ep, "id"), priv, addr, n.len);
	if (dns_filters(sw, &proto))
		kore_buf_appendf(b, "DNS = %s\n", own);
	kore_buf_appendf(b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s%s%s:%jd\n"
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
			kore_buf_appendf(b, "%s%s", k++ > 0 ? ", " : "",
			    ucl_object_tostring(p));
		ucl_object_unref(pfx);
	}
	kore_buf_appendf(b, "\nPersistentKeepalive = 25\n");
	text = kore_buf_stringify(b, NULL);
	text = strdup(text);
	kore_buf_free(b);
	if (ans != NULL)
		ucl_object_unref(ans);
	return (text);
}

/*
 * /api/sdwan/identities (SASE-3): GET lists every remote end point's
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
			return (KORE_RESULT_OK);
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
		return (KORE_RESULT_OK);
	if (req->method == HTTP_METHOD_DELETE) {
		http_populate_qs(req);
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
		kore_log(LOG_NOTICE, "identity %s of %s/%s revoked%s%s", name, swvc,
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
	kore_log(LOG_NOTICE, "identity %s of %s/%s issued%s%s%s", name, swvc,
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
		kore_log(LOG_NOTICE, "identities: an authorisation ran out, no "
		    "apply: %s", why);
}

/* ---- The record (SASE-2): what the edges' security rules logged ----- */

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
	struct kore_buf		*b;
	int			 status;
	int64_t			 from;
	bool			 csv;

	if (!guard(req, false))
		return (KORE_RESULT_OK);
	csv = strstr(req->path, ".csv") != NULL;
	http_populate_get(req);
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
	b = kore_buf_alloc(4096);
	kore_buf_appendf(b, "time,edge,rule,action,source,destination,interface,"
	    "comment\n");
	eit = NULL;
	while ((e = ucl_object_iterate(all, &eit, true)) != NULL) {
		char	when[32];
		time_t	t = (time_t)ucl_object_toint(ucl_object_lookup(e, "t"));

		strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
		kore_buf_appendf(b, "%s,%s,%jd,%s,%s,%s,%s,\"%s\"\n", when,
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
	kore_buf_free(b);
	return (KORE_RESULT_OK);
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

/* One tick: every edge's steering looked at, and sent where changed. */
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
			return (KORE_RESULT_OK);
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
		return (KORE_RESULT_OK);
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
 * WireGuard, IKEv2), BIRD, ipfw rules and steering, probes and net.*
 * sysctls; the services the host runs for an SD-WAN service (dnsmasq,
 * unbound, Squid, Suricata, its BIRD), NTP, rtadvd and manual SAs (a
 * uswe tunnel) are the host's only.
 */
static bool
jail_kind_ok(const char *kind, char *why, size_t wlen)
{
	static const char *const not[] = { "sdwan-dns", "sdwan-dhcp",
	    "sdwan-proxy", "sdwan-ids", "sdwan-bird", "ntp", "rtadvd",
	    "ipsec-sa" };
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
						if (ucl_object_lookup(in, "icap") !=
						    NULL)
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
	int			 fd;
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
	fd = r->lockfd;
	plan_free(plp);
	if (pthread_create(&tid, NULL, run_main, r) != 0) {
		snprintf(why, wlen, "%s", strerror(errno));
		close(fd);
		pthread_mutex_lock(&st_lock);
		applying = false;
		pthread_mutex_unlock(&st_lock);
		*statusp = 500;
		return (-1);
	}
	(void)pthread_detach(tid);
	return ((int)ucl_array_size(r->steps));
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
