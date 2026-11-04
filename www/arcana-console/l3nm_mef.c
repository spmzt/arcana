/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The SD-WAN document (MEF 70.2, sdwan.c's) and the L3NM the console
 * stores (RFC 9182 and arcana-l3nm): mef_import() makes the one into
 * the other, mef_export() the other back, as PLAN-SDN-YANG 4.5.2 maps
 * them.  An SWVC is a vpn-service with arcana-l3nm's sdwan in it, its
 * routing domains its VPN instance profiles, an edge with end points a
 * vpn-node, an end point a vpn-network-access; the UCSs, edges and
 * named lists are the top's augment.  A vpn-service without the
 * augment is no SWVC: the import keeps it, the export leaves it out.
 *
 * What does not come back as it went in: null and absent alike, an
 * empty list and none alike, a list of one where an object may be (a
 * UNI's BGP or OSPF, an underlay's, a PDNS entry's encryption,
 * southbound), true for a flow's any of null, BGP multihop false as
 * absent, an OSPF area of none as the backbone, the order of a
 * UNI's static routes across the two families and of a service's end
 * points across its edges (by edge, then as they were), a prefix in
 * inet_ntop(3)'s form.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "console.h"

#define	SD	"arcana-l3nm:sdwan"
#define	VC	"ietf-vpn-common:"

/* How a member is carried. */
enum how {
	C,	/* as it is */
	N,	/* a number, a string in L3NM (64 bits, decimal64) */
	O,	/* an object, a container */
	L,	/* a list of objects */
	OL,	/* an object or a list, a list each with an id, 1 on */
	CM,	/* communities, [as, value] each */
};

struct fm {
	const char	*d;	/* the document's name */
	const char	*y;	/* L3NM's member */
	enum how	 h;
	const struct fm	*sub;
	/* What the table does not say, of each object, after it. */
	void		(*ih)(const ucl_object_t *, ucl_object_t *);
	void		(*eh)(const ucl_object_t *, ucl_object_t *);
	bool		 pre;	/* eh before the table, its members first */
};
#define	F(d, y, h)		{ d, y, h, NULL, NULL, NULL, false }
#define	FS(d, y, h, s)		{ d, y, h, s, NULL, NULL, false }
#define	FH(d, y, h, s, i, e)	{ d, y, h, s, i, e, false }
#define	FP(d, y, h, s, i, e)	{ d, y, h, s, i, e, true }
#define	FEND			{ NULL, NULL, C, NULL, NULL, NULL, false }

/* ---- Small things ---------------------------------------------------- */

/* A member, null as absent. */
static const ucl_object_t *
get(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	if (o == NULL || ucl_object_type(o) != UCL_OBJECT ||
	    (v = ucl_object_lookup(o, k)) == NULL ||
	    ucl_object_type(v) == UCL_NULL)
		return (NULL);
	return (v);
}

static const char *
gstr(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	v = get(o, k);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

static void
put(ucl_object_t *o, const char *k, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, k, 0, true);
}

static void
puts_(ucl_object_t *o, const char *k, const char *s)
{

	put(o, k, ucl_object_fromstring(s));
}

static ucl_object_t *
obj(void)
{

	return (ucl_object_typed_new(UCL_OBJECT));
}

static ucl_object_t *
arr(void)
{

	return (ucl_object_typed_new(UCL_ARRAY));
}

/* An object with members, an array with items. */
static bool
full(const ucl_object_t *o)
{

	return (o != NULL && ucl_object_iterate(o, &(ucl_object_iter_t){
	    NULL }, true) != NULL);
}

/* An object, or nothing put when it has nothing. */
static void
put_full(ucl_object_t *o, const char *k, ucl_object_t *v)
{

	if (full(v))
		put(o, k, v);
	else
		ucl_object_unref(v);
}

/* YANG's empty: [null]. */
static ucl_object_t *
empty(void)
{
	ucl_object_t	*a;

	a = arr();
	ucl_array_append(a, ucl_object_typed_new(UCL_NULL));
	return (a);
}

/* A number as RFC 7951 writes a 64-bit or decimal64 one. */
static ucl_object_t *
numstr(const ucl_object_t *v)
{
	char	b[64];
	size_t	n;

	switch (ucl_object_type(v)) {
	case UCL_INT:
		snprintf(b, sizeof(b), "%jd", (intmax_t)ucl_object_toint(v));
		break;
	case UCL_FLOAT:
		snprintf(b, sizeof(b), "%.6f", ucl_object_todouble(v));
		for (n = strlen(b); n > 1 && b[n - 1] == '0'; n--)
			b[n - 1] = '\0';
		if (n > 1 && b[n - 1] == '.')
			b[n - 1] = '\0';
		break;
	default:
		return (ucl_object_copy(v));
	}
	return (ucl_object_fromstring(b));
}

/* And back: an integer where it is one. */
static ucl_object_t *
strnum(const ucl_object_t *v)
{
	const char	*s;
	char		*end;
	double		 d;

	if (ucl_object_type(v) != UCL_STRING)
		return (ucl_object_copy(v));
	s = ucl_object_tostring(v);
	if (strpbrk(s, ".eE") == NULL)
		return (ucl_object_fromint(strtoll(s, NULL, 10)));
	d = strtod(s, &end);
	if (end == s || *end != '\0')
		return (ucl_object_copy(v));
	if (d == floor(d) && fabs(d) < 9.0e15)
		return (ucl_object_fromint((int64_t)d));
	return (ucl_object_fromdouble(d));
}

/* An identityref's name, its module's prefix off. */
static const char *
ident(const char *s)
{
	const char	*c;

	return (s == NULL ? NULL : (c = strchr(s, ':')) != NULL ? c + 1 : s);
}

static const char *
fam_y(const char *f)
{

	return (f == NULL ? NULL : strcmp(f, "both") == 0 ? VC "dual-stack" :
	    strcmp(f, "ipv6") == 0 ? VC "ipv6" : VC "ipv4");
}

static const char *
fam_d(const char *f)
{

	f = ident(f);
	return (f == NULL ? NULL : strcmp(f, "dual-stack") == 0 ? "both" :
	    strcmp(f, "ipv6") == 0 ? "ipv6" : "ipv4");
}

/* ---- The tables, both ways ------------------------------------------- */

static void
imp(const struct fm *m, const ucl_object_t *d, ucl_object_t *y)
{
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;
	ucl_object_t		*a, *o, *c;
	int			 i;

	for (; m->d != NULL; m++) {
		if ((v = get(d, m->d)) == NULL)
			continue;
		switch (m->h) {
		case C:
			if (ucl_object_type(v) == UCL_ARRAY && !full(v))
				break;
			put(y, m->y, ucl_object_copy(v));
			break;
		case N:
			put(y, m->y, numstr(v));
			break;
		case O:
			if (ucl_object_type(v) != UCL_OBJECT)
				break;
			o = obj();
			imp(m->sub, v, o);
			if (m->ih != NULL)
				m->ih(v, o);
			put(y, m->y, o);
			break;
		case L:
		case OL:
			if (ucl_object_type(v) != UCL_ARRAY && !(m->h == OL &&
			    ucl_object_type(v) == UCL_OBJECT))
				break;
			a = arr();
			it = NULL;
			i = 0;
			for (e = ucl_object_type(v) == UCL_OBJECT ? v :
			    ucl_object_iterate(v, &it, true); e != NULL;
			    e = ucl_object_type(v) == UCL_OBJECT ? NULL :
			    ucl_object_iterate(v, &it, true)) {
				if (ucl_object_type(e) != UCL_OBJECT)
					continue;
				o = obj();
				if (m->h == OL)
					put(o, "id", ucl_object_fromint(++i));
				imp(m->sub, e, o);
				if (m->ih != NULL)
					m->ih(e, o);
				ucl_array_append(a, o);
			}
			put_full(y, m->y, a);
			break;
		case CM:
			a = arr();
			it = NULL;
			while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
				if (ucl_object_type(e) != UCL_ARRAY ||
				    ucl_array_size(e) != 2)
					continue;
				c = obj();
				put(c, "as", ucl_object_copy(
				    ucl_array_find_index(e, 0)));
				put(c, "value", ucl_object_copy(
				    ucl_array_find_index(e, 1)));
				ucl_array_append(a, c);
			}
			put_full(y, m->y, a);
			break;
		}
	}
}

static void
exp_(const struct fm *m, const ucl_object_t *y, ucl_object_t *d)
{
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;
	ucl_object_t		*a, *o, *c;

	for (; m->d != NULL; m++) {
		if ((v = get(y, m->y)) == NULL)
			continue;
		switch (m->h) {
		case C:
			put(d, m->d, ucl_object_copy(v));
			break;
		case N:
			put(d, m->d, strnum(v));
			break;
		case O:
			o = obj();
			exp_(m->sub, v, o);
			if (m->eh != NULL)
				m->eh(v, o);
			put(d, m->d, o);
			break;
		case L:
		case OL:
			a = arr();
			it = NULL;
			while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
				o = obj();
				if (m->pre)
					m->eh(e, o);
				exp_(m->sub, e, o);
				if (m->eh != NULL && !m->pre)
					m->eh(e, o);
				ucl_array_append(a, o);
			}
			if (m->h == OL && ucl_array_size(a) == 1) {
				o = ucl_array_pop_first(a);
				ucl_object_unref(a);
				a = o;
			}
			put(d, m->d, a);
			break;
		case CM:
			a = arr();
			it = NULL;
			while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
				c = arr();
				ucl_array_append(c, ucl_object_copy(get(e,
				    "as")));
				ucl_array_append(c, ucl_object_copy(get(e,
				    "value")));
				ucl_array_append(a, c);
			}
			put(d, m->d, a);
			break;
		}
	}
}

/* ---- The underlay ---------------------------------------------------- */

static const struct fm tunnel_m[] = {
	F("kind", "kind", C), F("ipsec", "ipsec", C), F("mss", "mss", C),
	F("mtu", "mtu", C), F("algorithms", "algorithms", C),
	F("esn", "esn", C), F("encap", "encap", C),
	F("lifetime", "lifetime", C), FEND
};
static const struct fm ucs_m[] = {
	F("id", "id", C), F("type", "type", C), F("billing", "billing", C),
	FS("tunnel", "tunnel", O, tunnel_m), FEND
};
static const struct fm relay_m[] = {
	F("to", "to", C), F("endpoint", "endpoint", C), F("port", "port", C),
	F("plugin", "plugin", C), F("fec", "fec", C), F("mode", "mode", C),
	FEND
};
static const struct fm ubgp_m[] = {
	F("family", "family", C), F("as", "as", C),
	F("neighbors", "neighbor", C), F("password", "password", C),
	F("hold_time", "hold-time", C), F("source", "source", C),
	F("multihop", "multihop", C), F("distance", "distance", C),
	F("bfd", "bfd", C), F("communities", "community", CM), FEND
};
static const struct fm uospf_m[] = {
	F("family", "family", C), F("area", "area", C), F("cost", "cost", C),
	F("password", "password", C), F("hello", "hello", C),
	F("dead", "dead", C), F("distance", "distance", C),
	F("bfd", "bfd", C), FEND
};
static const struct fm urouting_m[] = {
	FS("bgp", "bgp", OL, ubgp_m), FS("ospf", "ospf", OL, uospf_m),
	FEND
};
static const struct fm ucsep_m[] = {
	F("id", "id", C), F("ucs", "ucs", C), F("interface", "interface", C),
	F("address", "address", C), F("gateway", "gateway", C),
	F("beacon", "beacon", C), F("breakout", "breakout", C),
	F("backup", "backup", C), F("bandwidth", "bandwidth", N),
	F("preference", "preference", C), F("nat", "nat", C),
	FS("relay", "relay", L, relay_m), F("addressing", "addressing", C),
	F("vrf", "vrf", C), FS("routing", "routing", O, urouting_m),
	FEND
};
static const struct fm bset_m[] = {
	F("set", "set", C), F("via", "via", C), FEND
};
static const struct fm edge_m[] = {
	F("server", "server", C), F("own_table", "own-table", C),
	F("host_bird", "host-bird", C), F("transit", "transit", C),
	F("bgp_import", "bgp-import", C),
	FS("breakout_sets", "breakout-set", L, bset_m), F("ntp", "ntp", C),
	FS("ucs_end_points", "ucs-end-point", L, ucsep_m), FEND
};

/* A named list: a UCS End Point's {id, preference} in end-point, every
 * item's id in item, in order. */
static void
nlist_imp(const ucl_object_t *d, ucl_object_t *y)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*items, *eps, *o;

	items = arr();
	eps = arr();
	it = NULL;
	while ((e = ucl_object_iterate(get(d, "items"), &it, true)) != NULL) {
		if (ucl_object_type(e) == UCL_OBJECT) {
			if (gstr(e, "id") == NULL)
				continue;
			ucl_array_append(items, ucl_object_fromstring(gstr(e,
			    "id")));
			o = obj();
			puts_(o, "id", gstr(e, "id"));
			if (get(e, "preference") != NULL)
				put(o, "preference", ucl_object_copy(get(e,
				    "preference")));
			ucl_array_append(eps, o);
		} else
			ucl_array_append(items, ucl_object_copy(e));
	}
	put_full(y, "item", items);
	put_full(y, "end-point", eps);
}

static void
nlist_exp(const ucl_object_t *y, ucl_object_t *d)
{
	const ucl_object_t	*e, *ep, *x;
	ucl_object_iter_t	 it, it2;
	ucl_object_t		*items, *o;

	items = arr();
	it = NULL;
	while ((e = ucl_object_iterate(get(y, "item"), &it, true)) != NULL) {
		ep = NULL;
		it2 = NULL;
		while ((x = ucl_object_iterate(get(y, "end-point"), &it2,
		    true)) != NULL)
			if (gstr(x, "id") != NULL && strcmp(gstr(x, "id"),
			    ucl_object_tostring_forced(e)) == 0)
				ep = x;
		if (ep == NULL) {
			ucl_array_append(items, ucl_object_copy(e));
			continue;
		}
		o = obj();
		puts_(o, "id", gstr(ep, "id"));
		if (get(ep, "preference") != NULL)
			put(o, "preference", ucl_object_copy(get(ep,
			    "preference")));
		ucl_array_append(items, o);
	}
	if (full(items))
		put(d, "items", items);
	else
		ucl_object_unref(items);
}

static const struct fm nlist_m[] = {
	F("name", "name", C), F("kind", "kind", C),
	F("protocols", "protocol", C), F("ports", "port", C), FEND
};
static const struct fm top_m[] = {
	FS("ucs", "ucs", L, ucs_m), FS("edges", "edge", L, edge_m),
	FH("lists", "named-list", L, nlist_m, nlist_imp, nlist_exp),
	FEND
};

/* ---- An SWVC's own --------------------------------------------------- */

/* A zone's prefixes: Default, YANG's empty default. */
static void
zone_imp(const ucl_object_t *d, ucl_object_t *y)
{
	const ucl_object_t	*v;

	if ((v = get(d, "prefixes")) == NULL)
		return;
	if (ucl_object_type(v) == UCL_STRING)
		put(y, "default", empty());
	else if (full(v))
		put(y, "prefix", ucl_object_copy(v));
}

static void
zone_exp(const ucl_object_t *y, ucl_object_t *d)
{

	if (ucl_object_lookup(y, "default") != NULL)
		puts_(d, "prefixes", "Default");
	else if (get(y, "prefix") != NULL)
		put(d, "prefixes", ucl_object_copy(get(y, "prefix")));
}

/* A function policy's lists: IPPF's and DPF's entries tuples, PDNS's
 * its own, the others' values; southbound one or a list. */
static const char *const sf_lists[] = { "block", "allow", "quarantine",
    NULL };

static void
sfp_imp(const ucl_object_t *d, ucl_object_t *y)
{
	const ucl_object_t	*v, *e, *x;
	ucl_object_iter_t	 it, it2;
	ucl_object_t		*c, *a, *o, *z;
	const char		*fn, *kind, *k;
	int			 i, n;

	fn = gstr(d, "function") != NULL ? gstr(d, "function") : "";
	kind = strcmp(fn, "ippf") == 0 || strcmp(fn, "dpf") == 0 ? "tuple" :
	    strcmp(fn, "pdns") == 0 ? "pdns" : "value";
	for (i = 0; sf_lists[i] != NULL; i++) {
		if ((v = get(d, sf_lists[i])) == NULL ||
		    ucl_object_type(v) != UCL_ARRAY)
			continue;
		a = arr();
		n = 0;
		it = NULL;
		while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
			if (strcmp(kind, "value") == 0) {
				ucl_array_append(a, ucl_object_copy(e));
				continue;
			}
			if (ucl_object_type(e) != UCL_OBJECT)
				continue;
			o = obj();
			put(o, "id", ucl_object_fromint(++n));
			it2 = NULL;
			while ((x = ucl_object_iterate(e, &it2, true)) !=
			    NULL) {
				k = ucl_object_key(x);
				if (ucl_object_type(x) == UCL_NULL)
					continue;
				if (strcmp(k, "encryption") == 0 &&
				    ucl_object_type(x) != UCL_ARRAY) {
					z = arr();
					ucl_array_append(z, ucl_object_copy(x));
					put(o, k, z);
				} else
					put(o, k, ucl_object_copy(x));
			}
			ucl_array_append(a, o);
		}
		c = obj();
		put_full(c, kind, a);
		put(y, sf_lists[i], c);
	}
	if ((v = get(d, "southbound")) != NULL) {
		if (ucl_object_type(v) == UCL_ARRAY) {
			if (full(v))
				put(y, "southbound", ucl_object_copy(v));
		} else {
			a = arr();
			ucl_array_append(a, ucl_object_copy(v));
			put(y, "southbound", a);
		}
	}
}

static void
sfp_exp(const ucl_object_t *y, ucl_object_t *d)
{
	/* An entry's members, in the order the document has them. */
	static const char *const entry_keys[] = { "type", "value",
	    "encryption", "sav4", "dav4", "protv4", "sav6", "dav6",
	    "nextheadv6", "sport", "dport", "message-type", NULL };
	const ucl_object_t	*c, *v, *e, *x;
	ucl_object_iter_t	 it;
	ucl_object_t		*a, *o;
	const char *const	*k;
	int			 i;

	for (i = 0; sf_lists[i] != NULL; i++) {
		if ((c = get(y, sf_lists[i])) == NULL)
			continue;
		a = arr();
		if ((v = get(c, "value")) != NULL) {
			it = NULL;
			while ((e = ucl_object_iterate(v, &it, true)) != NULL)
				ucl_array_append(a, ucl_object_copy(e));
		}
		if ((v = get(c, "tuple")) != NULL ||
		    (v = get(c, "pdns")) != NULL) {
			it = NULL;
			while ((e = ucl_object_iterate(v, &it, true)) !=
			    NULL) {
				o = obj();
				for (k = entry_keys; *k != NULL; k++) {
					if ((x = get(e, *k)) == NULL)
						continue;
					/* An encryption of one: it. */
					if (strcmp(*k, "encryption") == 0 &&
					    ucl_array_size(x) == 1)
						x = ucl_array_find_index(x, 0);
					put(o, *k, ucl_object_copy(x));
				}
				ucl_array_append(a, o);
			}
		}
		put(d, sf_lists[i], a);
	}
	if ((v = get(y, "southbound")) != NULL)
		put(d, "southbound", ucl_object_copy(v));
}

/* A flow's any: true, null as true. */
static void
flow_imp(const ucl_object_t *d, ucl_object_t *y)
{
	const ucl_object_t	*cr;
	ucl_object_t		*c;

	cr = get(d, "criteria");
	if (cr == NULL || ucl_object_lookup(cr, "any") == NULL ||
	    get(cr, "any") != NULL)
		return;
	if ((c = __DECONST(ucl_object_t *, ucl_object_lookup(y,
	    "criteria"))) == NULL) {
		c = obj();
		put(y, "criteria", c);
	}
	put(c, "any", ucl_object_frombool(true));
}

/* A policy's ALLOWED-DESTINATION-ZONES (All, a list, none) and its
 * BANDWIDTH (a rate limiter's name, or a commit and a limit). */
static const struct fm bw_m[] = {
	F("commit", "commit", N), F("limit", "limit", N), FEND
};

static void
crit_imp(const ucl_object_t *d, ucl_object_t *y)
{
	const ucl_object_t	*v;
	ucl_object_t		*o;

	if ((v = get(d, "allowed-destination-zones")) != NULL) {
		o = obj();
		if (ucl_object_type(v) == UCL_STRING)
			put(o, "all", empty());
		else if (full(v))
			put(o, "zone", ucl_object_copy(v));
		put(y, "allowed-destination-zones", o);
	}
	if ((v = get(d, "bandwidth")) != NULL) {
		if (ucl_object_type(v) == UCL_STRING)
			put(y, "rate-limiter", ucl_object_copy(v));
		else {
			o = obj();
			imp(bw_m, v, o);
			put(y, "bandwidth", o);
		}
	}
}

static void
crit_exp(const ucl_object_t *y, ucl_object_t *d)
{
	const ucl_object_t	*v;
	ucl_object_t		*o;

	if ((v = get(y, "allowed-destination-zones")) != NULL) {
		if (ucl_object_lookup(v, "all") != NULL)
			puts_(d, "allowed-destination-zones", "All");
		else if (get(v, "zone") != NULL)
			put(d, "allowed-destination-zones", ucl_object_copy(
			    get(v, "zone")));
		else
			put(d, "allowed-destination-zones", arr());
	}
	if ((v = get(y, "rate-limiter")) != NULL)
		put(d, "bandwidth", ucl_object_copy(v));
	else if ((v = get(y, "bandwidth")) != NULL) {
		o = obj();
		exp_(bw_m, v, o);
		put(d, "bandwidth", o);
	}
}

static const struct fm bgpset_m[] = {
	F("name", "name", C), F("as_path", "as-path", C),
	F("communities", "community", CM), FEND
};
static const struct fm nat64_m[] = {
	F("prefix", "prefix", C), F("pool", "pool", C), F("edge", "edge", C),
	FEND
};
static const struct fm cp_m[] = {
	F("host", "host", C), F("cluster_id", "cluster-id", C),
	F("ctvc", "ctvc", C), FEND
};
static const struct fm zpol_m[] = {
	F("app", "app", C), F("policy", "policy", C), FEND
};
static const struct fm zone_m[] = {
	F("name", "name", C), F("prefix-list", "prefix-list", C),
	FS("policies", "policy", L, zpol_m), FEND
};
static const struct fm vt_m[] = {
	F("name", "name", C), F("type", "type", C),
	F("end_points", "end-point", C), F("roots", "root", C),
	F("leaves", "leaf", C), FEND
};
static const struct fm intervals_m[] = {
	F("eval", "eval", C), F("arrival", "arrival", C), F("ir", "ir", C),
	FEND
};
static const struct fm bfd_m[] = {
	F("interval", "interval", C), F("multiplier", "multiplier", C),
	FEND
};
static const struct fm tca_m[] = {
	F("delay", "delay", N), F("ipdv", "ipdv", N), F("loss", "loss", N),
	F("damping", "damping", C), FEND
};
static const struct fm probe_m[] = {
	F("interval", "interval", C), F("size", "size", C),
	F("count", "count", C), F("dscp", "dscp", C), F("down", "down", C),
	F("up", "up", C), F("timeout", "timeout", C),
	F("history", "history", C), F("report", "report", C), FEND
};
static const struct fm rl_m[] = {
	F("name", "name", C), F("commit", "commit", N),
	F("limit", "limit", N), FEND
};
static const struct fm sflists_m[] = {
	F("block", "block", C), F("allow", "allow", C),
	F("quarantine", "quarantine", C), FEND
};
static const struct fm sfp_m[] = {
	F("id", "id", C), F("function", "function", C),
	FS("lists", "lists", O, sflists_m), F("no-match", "no-match", C),
	F("duration", "duration", C), F("notify", "notify", C),
	F("detection-type", "detection-type", C),
	F("removal", "removal", C),
	F("invalid-server-certificate", "invalid-server-certificate", C),
	F("invalid-client-certificate", "invalid-client-certificate", C),
	F("unencrypted", "unencrypted", C),
	F("trusted-cas", "trusted-cas", C),
	F("pass-through", "pass-through", C), F("redirect", "redirect", C),
	F("northbound", "northbound", C), F("upstream", "upstream", C),
	FEND
};
static const struct fm ids_m[] = {
	F("mode", "mode", C), F("ruleset", "ruleset", C),
	F("rules", "rule", C), FEND
};
static const struct fm sp_m[] = {
	F("name", "name", C), F("function-policies", "function-policy", C),
	F("rate-limit", "rate-limit", N), FS("ids", "ids", O, ids_m),
	FEND
};
static const struct fm importance_m[] = {
	F("levels", "level", C), F("default", "default", C), FEND
};
static const struct fm fcrit_m[] = {
	F("any", "any", C), F("sav4", "sav4", C), F("dav4", "dav4", C),
	F("sdav4", "sdav4", C), F("sav6", "sav6", C), F("dav6", "dav6", C),
	F("sdav6", "sdav6", C), F("protv4", "protv4", C),
	F("nextheadv6", "nextheadv6", C), F("dscp", "dscp", C),
	F("sport", "sport", C), F("dport", "dport", C),
	F("sdport", "sdport", C), F("ethertype", "ethertype", C),
	F("appid", "appid", C), F("src-list", "src-list", C),
	F("dst-list", "dst-list", C), F("sdst-list", "sdst-list", C),
	F("service-list", "service-list", C), FEND
};
static const struct fm flow_m[] = {
	F("name", "name", C), F("group", "group", C),
	FS("criteria", "criteria", O, fcrit_m), FEND
};
static const struct fm perfp_m[] = {
	F("metric", "metric", C), F("threshold", "threshold", N),
	F("ceiling", "ceiling", N), F("remediation", "remediation", N),
	FEND
};
static const struct fm perfs_m[] = {
	F("metric", "metric", C), F("threshold", "threshold", N), FEND
};
static const struct fm perf_m[] = {
	FS("primary", "primary", O, perfp_m),
	FS("secondary", "secondary", L, perfs_m), FEND
};
static const struct fm pcrit_m[] = {
	F("ucs-list", "ucs-list", C), F("edge-list", "edge-list", C),
	F("ucs-end-point-list", "ucs-end-point-list", C),
	F("encryption", "encryption", C),
	F("public-private", "public-private", C),
	F("internet-breakout", "internet-breakout", C),
	F("backup", "backup", C), F("billing-method", "billing-method", C),
	F("virtual-topology", "virtual-topology", C),
	F("business-importance", "business-importance", C),
	FS("performance", "performance", O, perf_m),
	F("af-security-ingress", "af-security-ingress", C),
	F("af-security-egress", "af-security-egress", C),
	F("egress-block", "egress-block", C), FEND
};
static const struct fm pol_m[] = {
	F("name", "name", C), F("direction", "direction", C),
	FH("criteria", "criteria", O, pcrit_m, crit_imp, crit_exp),
	FEND
};
static const struct fm sw_m[] = {
	F("fib", "fib", C), F("md5", "md5", C), F("ucs", "ucs", C),
	F("reserved_prefixes", "reserved-prefix", C),
	FS("bgp_sets", "bgp-set", L, bgpset_m),
	FS("nat64", "nat64", O, nat64_m), F("ibgp", "ibgp", C),
	FS("control_plane", "control-plane", O, cp_m),
	FH("zones", "zone", L, zone_m, zone_imp, zone_exp),
	FS("topologies", "virtual-topology", L, vt_m),
	FS("intervals", "intervals", O, intervals_m),
	FS("bfd", "bfd", O, bfd_m), FS("tca", "tca", O, tca_m),
	FS("probe", "probe", O, probe_m),
	FS("rate_limiters", "rate-limiter", L, rl_m),
	FP("security_function_policies", "security-function-policy", L,
	    sfp_m, sfp_imp, sfp_exp),
	FS("security_policies", "security-policy", L, sp_m),
	FS("importance", "importance", O, importance_m),
	F("groups", "application-flow-group", C),
	FH("flows", "application-flow", L, flow_m, flow_imp, NULL),
	FS("policies", "policy", L, pol_m), FEND
};

/* ---- The routing domains: the VPN instance profiles ------------------ */

/* An RD or RT, ASN:n or A.B.C.D:n, as L3NM's: its type first. */
static void
rd_y(const char *s, char *b, size_t len)
{
	const char	*c;

	c = strchr(s, ':');
	if (c != NULL && memchr(s, '.', (size_t)(c - s)) != NULL)
		snprintf(b, len, "1:%s", s);
	else if (c != NULL && strtoull(s, NULL, 10) > 65535)
		snprintf(b, len, "2:%s", s);
	else
		snprintf(b, len, "0:%s", s);
}

static const char *
rd_d(const char *s)
{

	if (s != NULL && (s[0] == '0' || s[0] == '1' || s[0] == '2') &&
	    s[1] == ':' && strchr(s + 2, ':') != NULL)
		return (s + 2);
	return (s);
}

static const char *const dom_names[] = { "subscriber", "service",
    "breakout", NULL };

/* A domain's RD, RTs, label, table and prefix into profile p. */
static void
dom_imp(const ucl_object_t *dom, ucl_object_t *p, bool sub)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*rts, *o, *t, *af;
	char			 b[96];

	if (gstr(dom, "rd") != NULL) {
		rd_y(gstr(dom, "rd"), b, sizeof(b));
		puts_(p, "rd", b);
	}
	rts = arr();
	it = NULL;
	while ((e = ucl_object_iterate(get(dom, "rt"), &it, true)) != NULL) {
		rd_y(ucl_object_tostring_forced(e), b, sizeof(b));
		o = obj();
		puts_(o, "route-target", b);
		ucl_array_append(rts, o);
	}
	if (full(rts)) {
		t = obj();
		put(t, "id", ucl_object_fromint(1));
		put(t, "route-targets", rts);
		puts_(t, "route-target-type", "both");
		o = obj();
		put(o, "vpn-target", arr());
		ucl_array_append(__DECONST(ucl_object_t *, ucl_object_lookup(o,
		    "vpn-target")), t);
		af = obj();
		puts_(af, "address-family", VC "dual-stack");
		put(af, "vpn-targets", o);
		o = arr();
		ucl_array_append(o, af);
		put(p, "address-family", o);
	} else
		ucl_object_unref(rts);
	if (get(dom, "label") != NULL)
		put(p, "arcana-l3nm:label", ucl_object_copy(get(dom, "label")));
	if (!sub && get(dom, "fib") != NULL)
		put(p, "arcana-l3nm:fib", ucl_object_copy(get(dom, "fib")));
	if (get(dom, "prefix") != NULL)
		put(p, "arcana-l3nm:prefix", ucl_object_copy(get(dom,
		    "prefix")));
}

static ucl_object_t *
profiles_imp(const ucl_object_t *sw)
{
	const ucl_object_t	*doms, *d;
	ucl_object_t		*a, *p;
	int			 i;

	doms = get(sw, "domains");
	a = arr();
	for (i = 0; dom_names[i] != NULL; i++) {
		d = get(doms, dom_names[i]);
		if (i > 0 && (d == NULL || ucl_object_type(d) != UCL_OBJECT))
			continue;
		p = obj();
		puts_(p, "profile-id", dom_names[i]);
		if (get(sw, "as") != NULL)
			put(p, "local-as", ucl_object_copy(get(sw, "as")));
		dom_imp(d, p, i == 0);
		puts_(p, "arcana-l3nm:domain", dom_names[i]);
		if (i == 0 && get(sw, "fib") != NULL)
			put(p, "arcana-l3nm:fib", ucl_object_copy(get(sw,
			    "fib")));
		ucl_array_append(a, p);
	}
	return (a);
}

/* The service's domains, AS and table from its profiles, into sw. */
static void
profiles_exp(const ucl_object_t *svc, ucl_object_t *sw)
{
	const ucl_object_t	*p, *af, *t, *rt;
	ucl_object_iter_t	 it, it2, it3, it4;
	ucl_object_t		*doms, *d, *rts;
	const char		*dn;
	int			 i;

	doms = obj();
	it = NULL;
	while ((p = ucl_object_iterate(get(get(svc, "vpn-instance-profiles"),
	    "vpn-instance-profile"), &it, true)) != NULL) {
		if ((dn = gstr(p, "arcana-l3nm:domain")) == NULL)
			dn = gstr(p, "profile-id");
		for (i = 0; dn != NULL && dom_names[i] != NULL; i++)
			if (strcmp(dn, dom_names[i]) == 0)
				break;
		if (dn == NULL || dom_names[i] == NULL)
			continue;
		if (get(p, "local-as") != NULL && (get(sw, "as") == NULL ||
		    i == 0)) {
			(void)ucl_object_delete_key(sw, "as");
			put(sw, "as", ucl_object_copy(get(p, "local-as")));
		}
		if (i == 0 && get(sw, "fib") == NULL &&
		    get(p, "arcana-l3nm:fib") != NULL)
			put(sw, "fib", ucl_object_copy(get(p,
			    "arcana-l3nm:fib")));
		d = obj();
		if (i > 0 && get(p, "arcana-l3nm:fib") != NULL)
			put(d, "fib", ucl_object_copy(get(p,
			    "arcana-l3nm:fib")));
		if (get(p, "arcana-l3nm:prefix") != NULL)
			put(d, "prefix", ucl_object_copy(get(p,
			    "arcana-l3nm:prefix")));
		if (gstr(p, "rd") != NULL)
			puts_(d, "rd", rd_d(gstr(p, "rd")));
		rts = arr();
		it2 = NULL;
		while ((af = ucl_object_iterate(get(p, "address-family"), &it2,
		    true)) != NULL) {
			it3 = NULL;
			while ((t = ucl_object_iterate(get(get(af,
			    "vpn-targets"), "vpn-target"), &it3, true)) !=
			    NULL) {
				it4 = NULL;
				while ((rt = ucl_object_iterate(get(t,
				    "route-targets"), &it4, true)) != NULL)
					if (gstr(rt, "route-target") != NULL)
						ucl_array_append(rts,
						    ucl_object_fromstring(rd_d(
						    gstr(rt, "route-target"))));
			}
		}
		put_full(d, "rt", rts);
		if (get(p, "arcana-l3nm:label") != NULL)
			put(d, "label", ucl_object_copy(get(p,
			    "arcana-l3nm:label")));
		if (i == 0 && !full(d))
			ucl_object_unref(d);
		else
			put(doms, dom_names[i], d);
	}
	put_full(sw, "domains", doms);
}

/* ---- An end point: a vpn-network-access ------------------------------- */

/* An address in the form inet_ntop(3) writes, its prefix of len. */
static bool
masked(const char *addr, int len, char *b, size_t blen)
{
	unsigned char	a[16];
	int		af, n, i;
	char		t[INET6_ADDRSTRLEN];

	af = strchr(addr, ':') != NULL ? AF_INET6 : AF_INET;
	n = af == AF_INET ? 4 : 16;
	if (inet_pton(af, addr, a) != 1 || len < 0 || len > n * 8)
		return (false);
	for (i = 0; i < n; i++)
		if (i * 8 >= len)
			a[i] = 0;
		else if (i * 8 + 8 > len)
			a[i] &= (unsigned char)(0xff << (8 - (len - i * 8)));
	if (inet_ntop(af, a, t, sizeof(t)) == NULL)
		return (false);
	snprintf(b, blen, "%s/%d", t, len);
	return (true);
}

static const struct fm sec_m[] = {
	F("prefix", "prefix", C), F("provider", "provider", C), FEND
};
static const struct fm addr_m[] = {
	F("mode", "arcana-l3nm:mode", C),
	F("provider", "arcana-l3nm:provider", C),
	F("reserved", "arcana-l3nm:reserved", C),
	F("dns", "arcana-l3nm:dns", C), F("lease", "arcana-l3nm:lease", C),
	FS("secondary", "arcana-l3nm:secondary", L, sec_m), FEND
};

/* A UNI's IPv4 or IPv6: the subnet's length and the provider's first
 * address L3NM's, the rest arcana-l3nm's. */
static void
addr_imp(const ucl_object_t *v, ucl_object_t *y)
{
	const ucl_object_t	*pv;
	const char		*mode, *p, *s;

	mode = gstr(v, "mode");
	p = gstr(v, "prefix");
	pv = get(v, "provider");
	if (p != NULL && (s = strchr(p, '/')) != NULL && pv != NULL &&
	    ucl_object_type(pv) == UCL_ARRAY && ucl_array_size(pv) > 0) {
		put(y, "local-address", ucl_object_copy(ucl_array_find_index(
		    pv, 0)));
		put(y, "prefix-length", ucl_object_fromint(strtol(s + 1, NULL,
		    10)));
	}
	if (mode != NULL && strcmp(mode, "static") == 0)
		puts_(y, "address-allocation-type",
		    "ietf-l3vpn-ntw:static-address");
	else if (mode != NULL && strcmp(mode, "dhcp") == 0)
		puts_(y, "address-allocation-type",
		    "ietf-l3vpn-ntw:provider-dhcp");
	else if (mode != NULL && strcmp(mode, "slaac") == 0)
		puts_(y, "address-allocation-type", "ietf-l3vpn-ntw:slaac");
	imp(addr_m, v, y);
}

static void
addr_exp(const ucl_object_t *y, ucl_object_t *d)
{
	const char	*a, *t;
	ucl_object_t	*pv;
	char		 b[INET6_ADDRSTRLEN + 8];

	exp_(addr_m, y, d);
	if (get(d, "mode") == NULL && (t = ident(gstr(y,
	    "address-allocation-type"))) != NULL)
		puts_(d, "mode", strcmp(t, "static-address") == 0 ? "static" :
		    strcmp(t, "slaac") == 0 ? "slaac" : "dhcp");
	if ((a = gstr(y, "local-address")) != NULL && get(y,
	    "prefix-length") != NULL && masked(a, (int)ucl_object_toint(get(y,
	    "prefix-length")), b, sizeof(b))) {
		puts_(d, "prefix", b);
		if (get(d, "provider") == NULL) {
			pv = arr();
			ucl_array_append(pv, ucl_object_fromstring(a));
			put(d, "provider", pv);
		}
	}
}

/* Static routes, BGP and OSPF at a UNI: L3NM's routing-protocols. */
static ucl_object_t *
auth_imp(const char *pw, bool md5)
{
	ucl_object_t	*a, *k;

	k = obj();
	puts_(k, "key", pw);
	if (md5)
		puts_(k, "crypto-algorithm", "ietf-key-chain:md5");
	a = obj();
	put(a, "enable", ucl_object_frombool(true));
	put(a, "keying-material", k);
	return (a);
}

static const struct fm bgp_x[] = {
	F("distance", "arcana-l3nm:distance", C),
	F("bfd", "arcana-l3nm:bfd", C),
	F("communities", "arcana-l3nm:community", CM), FEND
};
static const struct fm ospf_x[] = {
	F("hello", "arcana-l3nm:hello", C), F("dead", "arcana-l3nm:dead", C),
	F("distance", "arcana-l3nm:distance", C),
	F("bfd", "arcana-l3nm:bfd", C), FEND
};

static ucl_object_t *
proto(const char *id, const char *type, const char *what, ucl_object_t *v)
{
	ucl_object_t	*p;

	p = obj();
	puts_(p, "id", id);
	puts_(p, "type", type);
	put(p, what, v);
	return (p);
}

static void
routing_imp(const ucl_object_t *u, ucl_object_t *acc)
{
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;
	ucl_object_t		*rps, *v4, *v6, *o, *b, *t, *c;
	const char		*s;
	char			 id[32];
	int			 n, k;

	rps = arr();
	v4 = arr();
	v6 = arr();
	it = NULL;
	while ((e = ucl_object_iterate(get(u, "routes"), &it, true)) != NULL) {
		if ((s = gstr(e, "prefix")) == NULL)
			continue;
		o = obj();
		puts_(o, "lan", s);
		if (get(e, "next_hop") != NULL)
			put(o, "next-hop", ucl_object_copy(get(e, "next_hop")));
		if (get(e, "distance") != NULL)
			put(o, "arcana-l3nm:distance", ucl_object_copy(get(e,
			    "distance")));
		ucl_array_append(strchr(s, ':') != NULL ? v6 : v4, o);
	}
	if (full(v4) || full(v6)) {
		c = obj();
		put_full(c, "ipv4-lan-prefixes", v4);
		put_full(c, "ipv6-lan-prefixes", v6);
		o = obj();
		put(o, "cascaded-lan-prefixes", c);
		ucl_array_append(rps, proto("static", VC "static-routing",
		    "static", o));
	} else {
		ucl_object_unref(v4);
		ucl_object_unref(v6);
	}
	for (k = 0; k < 2; k++) {
		v = get(u, k == 0 ? "bgp" : "ospf");
		n = 0;
		it = NULL;
		for (e = v != NULL && ucl_object_type(v) == UCL_OBJECT ? v :
		    ucl_object_iterate(v, &it, true); e != NULL;
		    e = ucl_object_type(v) == UCL_OBJECT ? NULL :
		    ucl_object_iterate(v, &it, true)) {
			if (ucl_object_type(e) != UCL_OBJECT)
				continue;
			b = obj();
			if (gstr(e, "family") != NULL)
				puts_(b, "address-family", fam_y(gstr(e,
				    "family")));
			if (k == 0) {
				if (get(e, "as") != NULL)
					put(b, "peer-as", ucl_object_copy(
					    get(e, "as")));
				if (get(e, "source") != NULL)
					put(b, "local-address",
					    ucl_object_copy(get(e, "source")));
				if (get(e, "neighbors") != NULL &&
				    full(get(e, "neighbors")))
					put(b, "neighbor", ucl_object_copy(
					    get(e, "neighbors")));
				if (ucl_object_toboolean(get(e, "multihop")))
					put(b, "multihop",
					    ucl_object_fromint(255));
				if (get(e, "hold_time") != NULL) {
					t = obj();
					put(t, "hold-time", ucl_object_copy(
					    get(e, "hold_time")));
					put(b, "bgp-timers", t);
				}
				if (gstr(e, "password") != NULL)
					put(b, "authentication", auth_imp(
					    gstr(e, "password"), true));
				imp(bgp_x, e, b);
			} else {
				int64_t a = get(e, "area") != NULL ?
				    ucl_object_toint(get(e, "area")) : 0;

				snprintf(id, sizeof(id), "%u.%u.%u.%u",
				    (unsigned)(a >> 24) & 0xff,
				    (unsigned)(a >> 16) & 0xff,
				    (unsigned)(a >> 8) & 0xff,
				    (unsigned)a & 0xff);
				puts_(b, "area-id", id);
				if (get(e, "cost") != NULL)
					put(b, "metric", ucl_object_copy(
					    get(e, "cost")));
				if (gstr(e, "password") != NULL)
					put(b, "authentication", auth_imp(
					    gstr(e, "password"), false));
				imp(ospf_x, e, b);
			}
			snprintf(id, sizeof(id), "%s-%d", k == 0 ? "bgp" :
			    "ospf", ++n);
			ucl_array_append(rps, proto(id, k == 0 ? VC
			    "bgp-routing" : VC "ospf-routing", k == 0 ? "bgp" :
			    "ospf", b));
		}
	}
	if (full(rps)) {
		o = obj();
		put(o, "routing-protocol", rps);
		put(acc, "routing-protocols", o);
	} else
		ucl_object_unref(rps);
}

static void
routing_exp(const ucl_object_t *acc, ucl_object_t *u)
{
	const ucl_object_t	*p, *b, *e, *cl;
	ucl_object_iter_t	 it, it2;
	ucl_object_t		*rts, *bgp, *ospf, *o, *x;
	const char		*t, *s;
	unsigned		 q[4];
	int			 k;

	rts = arr();
	bgp = arr();
	ospf = arr();
	it = NULL;
	while ((p = ucl_object_iterate(get(get(acc, "routing-protocols"),
	    "routing-protocol"), &it, true)) != NULL) {
		if ((t = ident(gstr(p, "type"))) == NULL)
			continue;
		if (strcmp(t, "static-routing") == 0) {
			cl = get(get(p, "static"), "cascaded-lan-prefixes");
			for (k = 0; k < 2; k++) {
				it2 = NULL;
				while ((e = ucl_object_iterate(get(cl, k == 0 ?
				    "ipv4-lan-prefixes" : "ipv6-lan-prefixes"),
				    &it2, true)) != NULL) {
					o = obj();
					if (get(e, "lan") != NULL)
						put(o, "prefix",
						    ucl_object_copy(get(e,
						    "lan")));
					if (get(e, "next-hop") != NULL)
						put(o, "next_hop",
						    ucl_object_copy(get(e,
						    "next-hop")));
					if (get(e, "arcana-l3nm:distance") !=
					    NULL)
						put(o, "distance",
						    ucl_object_copy(get(e,
						    "arcana-l3nm:distance")));
					ucl_array_append(rts, o);
				}
			}
		} else if (strcmp(t, "bgp-routing") == 0 &&
		    (b = get(p, "bgp")) != NULL) {
			o = obj();
			if ((s = fam_d(gstr(b, "address-family"))) != NULL)
				puts_(o, "family", s);
			if (get(b, "peer-as") != NULL)
				put(o, "as", ucl_object_copy(get(b,
				    "peer-as")));
			if (get(b, "neighbor") != NULL)
				put(o, "neighbors", ucl_object_copy(get(b,
				    "neighbor")));
			if ((s = gstr(get(get(b, "authentication"),
			    "keying-material"), "key")) != NULL)
				puts_(o, "password", s);
			if (get(get(b, "bgp-timers"), "hold-time") != NULL)
				put(o, "hold_time", ucl_object_copy(get(get(b,
				    "bgp-timers"), "hold-time")));
			if (get(b, "local-address") != NULL)
				put(o, "source", ucl_object_copy(get(b,
				    "local-address")));
			if (ucl_object_toint(get(b, "multihop")) > 1)
				put(o, "multihop", ucl_object_frombool(true));
			exp_(bgp_x, b, o);
			ucl_array_append(bgp, o);
		} else if (strcmp(t, "ospf-routing") == 0 &&
		    (b = get(p, "ospf")) != NULL) {
			o = obj();
			if ((s = fam_d(gstr(b, "address-family"))) != NULL)
				puts_(o, "family", s);
			if ((s = gstr(b, "area-id")) != NULL && sscanf(s,
			    "%u.%u.%u.%u", &q[0], &q[1], &q[2], &q[3]) == 4)
				put(o, "area", ucl_object_fromint(
				    ((int64_t)q[0] << 24) | (q[1] << 16) |
				    (q[2] << 8) | q[3]));
			if (get(b, "metric") != NULL)
				put(o, "cost", ucl_object_copy(get(b,
				    "metric")));
			if ((s = gstr(get(get(b, "authentication"),
			    "keying-material"), "key")) != NULL)
				puts_(o, "password", s);
			exp_(ospf_x, b, o);
			ucl_array_append(ospf, o);
		}
	}
	put_full(u, "routes", rts);
	for (k = 0; k < 2; k++) {
		x = k == 0 ? bgp : ospf;
		if (ucl_array_size(x) == 1) {
			o = ucl_array_pop_first(x);
			ucl_object_unref(x);
			put(u, k == 0 ? "bgp" : "ospf", o);
		} else
			put_full(u, k == 0 ? "bgp" : "ospf", x);
	}
}

static const struct fm clat_m[] = {
	F("prefix", "prefix", C), FEND
};
static const struct fm uni_m[] = {
	F("id", "uni-id", C), F("host_addressed", "host-addressed", C),
	F("max_frame", "max-frame", C), FS("clat", "clat", O, clat_m),
	FEND
};
static const struct fm pmap_m[] = {
	F("zone", "zone", C), F("app", "app", C), F("ingress", "ingress", C),
	F("egress", "egress", C), FEND
};
static const struct fm group_m[] = {
	F("name", "name", C), F("zone", "zone", C), F("pool", "pool", C),
	F("reach", "reach", C), FEND
};
static const struct fm identity_m[] = {
	F("name", "name", C), F("zone", "zone", C), F("group", "group", C),
	F("public_key", "public-key", C), F("issued", "issued", N),
	F("user", "user", C), FEND
};
static const struct fm remote_m[] = {
	F("prefix", "prefix", C), F("port", "port", C),
	F("reauth", "reauth", C), FS("groups", "group", L, group_m),
	FS("identities", "identity", L, identity_m), FEND
};
static const struct fm natx_m[] = {
	F("ip_version", "ip-version", C),
	F("public_prefix", "public-prefix", C),
	F("exceptions", "exception", C), FEND
};
static const struct fm ep_m[] = {
	FS("policy_map", "policy-map", L, pmap_m),
	F("availability", "availability", N),
	FS("remote", "remote", O, remote_m), FEND
};

static ucl_object_t *
access_imp(const ucl_object_t *ep)
{
	const ucl_object_t	*u, *r, *v;
	ucl_object_t		*acc, *sd, *o, *c;
	int			 k;

	u = get(ep, "uni");
	r = get(ep, "remote");
	acc = obj();
	if (gstr(ep, "id") != NULL)
		puts_(acc, "id", gstr(ep, "id"));
	if ((v = get(r != NULL ? r : u, "interface")) != NULL)
		put(acc, "interface-id", ucl_object_copy(v));
	puts_(acc, "vpn-network-access-type", VC "multipoint");
	puts_(acc, "vpn-instance-profile", "subscriber");
	sd = obj();
	if (r == NULL && u != NULL) {
		if ((v = get(u, "vlan")) != NULL) {
			o = obj();
			if (ucl_object_toint(v) == 0)
				puts_(o, "type", VC "untagged-int");
			else {
				puts_(o, "type", VC "dot1q");
				c = obj();
				put(c, "cvlan-id", ucl_object_copy(v));
				put(o, "dot1q", c);
			}
			c = obj();
			put(c, "encapsulation", o);
			put(acc, "connection", c);
		}
		c = obj();
		for (k = 0; k < 2; k++) {
			if ((v = get(u, k == 0 ? "ipv4" : "ipv6")) == NULL ||
			    ucl_object_type(v) != UCL_OBJECT)
				continue;
			o = obj();
			addr_imp(v, o);
			put_full(c, k == 0 ? "ipv4" : "ipv6", o);
		}
		put_full(acc, "ip-connection", c);
		routing_imp(u, acc);
		imp(uni_m, u, sd);
	}
	imp(ep_m, ep, sd);
	if ((v = get(ep, "nat")) != NULL) {
		o = obj();
		if (ucl_object_type(v) == UCL_STRING)
			put(o, "disabled", empty());
		else
			imp(natx_m, v, o);
		put(sd, "nat", o);
	}
	put_full(acc, SD, sd);
	return (acc);
}

static ucl_object_t *
access_exp(const ucl_object_t *acc, const char *edge)
{
	const ucl_object_t	*sd, *v, *enc;
	ucl_object_t		*ep, *u, *o;
	int			 k;

	sd = get(acc, SD);
	ep = obj();
	if (gstr(acc, "id") != NULL)
		puts_(ep, "id", gstr(acc, "id"));
	puts_(ep, "edge", edge);
	exp_(ep_m, sd, ep);
	if ((v = get(sd, "nat")) != NULL) {
		if (ucl_object_lookup(v, "disabled") != NULL)
			puts_(ep, "nat", "disabled");
		else {
			o = obj();
			exp_(natx_m, v, o);
			put(ep, "nat", o);
		}
	}
	if ((o = __DECONST(ucl_object_t *, ucl_object_lookup(ep,
	    "remote"))) != NULL) {
		if (get(acc, "interface-id") != NULL)
			put(o, "interface", ucl_object_copy(get(acc,
			    "interface-id")));
		return (ep);
	}
	u = obj();
	exp_(uni_m, sd, u);
	if (get(acc, "interface-id") != NULL)
		put(u, "interface", ucl_object_copy(get(acc, "interface-id")));
	enc = get(get(acc, "connection"), "encapsulation");
	if (get(get(enc, "dot1q"), "cvlan-id") != NULL)
		put(u, "vlan", ucl_object_copy(get(get(enc, "dot1q"),
		    "cvlan-id")));
	else if (ident(gstr(enc, "type")) != NULL && strcmp(ident(gstr(enc,
	    "type")), "untagged-int") == 0)
		put(u, "vlan", ucl_object_fromint(0));
	for (k = 0; k < 2; k++) {
		if ((v = get(get(acc, "ip-connection"), k == 0 ? "ipv4" :
		    "ipv6")) == NULL)
			continue;
		o = obj();
		addr_exp(v, o);
		put_full(u, k == 0 ? "ipv4" : "ipv6", o);
	}
	routing_exp(acc, u);
	put(ep, "uni", u);
	return (ep);
}

/* ---- An SWVC: a vpn-service ------------------------------------------ */

static ucl_object_t *
service_imp(const ucl_object_t *sw)
{
	const ucl_object_t	*ep, *n;
	ucl_object_iter_t	 it, it2;
	ucl_object_t		*svc, *sd, *nodes, *node, *o, *a;
	const char		*edge;
	char			 sid[64], jail[64];

	svc = obj();
	if (gstr(sw, "id") != NULL)
		puts_(svc, "vpn-id", gstr(sw, "id"));
	o = obj();
	put(o, "vpn-instance-profile", profiles_imp(sw));
	put(svc, "vpn-instance-profiles", o);
	nodes = arr();
	it = NULL;
	while ((ep = ucl_object_iterate(get(sw, "end_points"), &it, true)) !=
	    NULL) {
		if ((edge = gstr(ep, "edge")) == NULL)
			continue;
		node = NULL;
		it2 = NULL;
		while ((n = ucl_object_iterate(nodes, &it2, true)) != NULL)
			if (strcmp(gstr(n, "vpn-node-id"), edge) == 0)
				node = __DECONST(ucl_object_t *, n);
		if (node == NULL) {
			node = obj();
			puts_(node, "vpn-node-id", edge);
			puts_(node, "ne-id", sdwan_edge_split(edge, sid,
			    sizeof(sid), jail, sizeof(jail)) ? sid : edge);
			a = arr();
			o = obj();
			puts_(o, "profile-id", "subscriber");
			ucl_array_append(a, o);
			o = obj();
			put(o, "vpn-instance-profile", a);
			put(node, "active-vpn-instance-profiles", o);
			o = obj();
			put(o, "vpn-network-access", arr());
			put(node, "vpn-network-accesses", o);
			ucl_array_append(nodes, node);
		}
		ucl_array_append(__DECONST(ucl_object_t *, get(get(node,
		    "vpn-network-accesses"), "vpn-network-access")),
		    access_imp(ep));
	}
	if (full(nodes)) {
		o = obj();
		put(o, "vpn-node", nodes);
		put(svc, "vpn-nodes", o);
	} else
		ucl_object_unref(nodes);
	sd = obj();
	imp(sw_m, sw, sd);
	put(svc, SD, sd);
	return (svc);
}

static ucl_object_t *
service_exp(const ucl_object_t *svc)
{
	const ucl_object_t	*n, *acc;
	ucl_object_iter_t	 it, it2;
	ucl_object_t		*sw, *eps;

	sw = obj();
	if (gstr(svc, "vpn-id") != NULL)
		puts_(sw, "id", gstr(svc, "vpn-id"));
	exp_(sw_m, get(svc, SD), sw);
	profiles_exp(svc, sw);
	eps = arr();
	it = NULL;
	while ((n = ucl_object_iterate(get(get(svc, "vpn-nodes"), "vpn-node"),
	    &it, true)) != NULL) {
		if (gstr(n, "vpn-node-id") == NULL)
			continue;
		it2 = NULL;
		while ((acc = ucl_object_iterate(get(get(n,
		    "vpn-network-accesses"), "vpn-network-access"), &it2,
		    true)) != NULL)
			ucl_array_append(eps, access_exp(acc, gstr(n,
			    "vpn-node-id")));
	}
	put_full(sw, "end_points", eps);
	return (sw);
}

/* ---- Both ways ------------------------------------------------------- */

/*
 * The document doc into y, L3NM's l3vpn-ntw: the SD-WAN in it before
 * replaced, the vpn-services that are no SWVC kept.
 */
void
mef_import(const ucl_object_t *doc, ucl_object_t *y)
{
	const ucl_object_t	*sv, *sw;
	ucl_object_iter_t	 it;
	ucl_object_t		*top, *svcs, *o;

	(void)ucl_object_delete_key(y, SD);
	top = obj();
	imp(top_m, doc, top);
	put_full(y, SD, top);
	svcs = arr();
	it = NULL;
	while ((sv = ucl_object_iterate(get(get(y, "vpn-services"),
	    "vpn-service"), &it, true)) != NULL)
		if (get(sv, SD) == NULL)
			ucl_array_append(svcs, ucl_object_copy(sv));
	it = NULL;
	while ((sw = ucl_object_iterate(get(doc, "swvcs"), &it, true)) != NULL)
		if (ucl_object_type(sw) == UCL_OBJECT)
			ucl_array_append(svcs, service_imp(sw));
	(void)ucl_object_delete_key(y, "vpn-services");
	if (full(svcs)) {
		o = obj();
		put(o, "vpn-service", svcs);
		put(y, "vpn-services", o);
	} else
		ucl_object_unref(svcs);
}

/* L3NM's l3vpn-ntw y as the document, without its version. */
ucl_object_t *
mef_export(const ucl_object_t *y)
{
	const ucl_object_t	*sv;
	ucl_object_iter_t	 it;
	ucl_object_t		*doc, *sws;

	doc = obj();
	exp_(top_m, get(y, SD), doc);
	sws = arr();
	it = NULL;
	while ((sv = ucl_object_iterate(get(get(y, "vpn-services"),
	    "vpn-service"), &it, true)) != NULL)
		if (get(sv, SD) != NULL)
			ucl_array_append(sws, service_exp(sv));
	put_full(doc, "swvcs", sws);
	return (doc);
}

/* Whether y has an SD-WAN in it: the top's augment, or an SWVC. */
bool
mef_has_sdwan(const ucl_object_t *y)
{
	const ucl_object_t	*sv;
	ucl_object_iter_t	 it;

	if (get(y, SD) != NULL)
		return (true);
	it = NULL;
	while ((sv = ucl_object_iterate(get(get(y, "vpn-services"),
	    "vpn-service"), &it, true)) != NULL)
		if (get(sv, SD) != NULL)
			return (true);
	return (false);
}
