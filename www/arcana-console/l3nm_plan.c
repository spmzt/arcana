/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The L3NM as the SD-WAN planner reads it (PLAN-SDN-YANG 4.5.4): the
 * services kept (l3nm.c), each vpn-service's VPN instance profiles
 * resolved for each vpn-node (RFC 9182 section 7.6.1: the node's
 * active profile, then the node's own leaves, over the service's), and
 * what the L3NM leaves to the provider allocated from the ledger, the
 * allocations sdwan_edge.c keeps with what it made:
 *
 *	fib:VPN		the service's table where no profile names one:
 *			the lowest no service, domain or entry has
 *	fib:VPN/NODE	its table on the node, one per vpn-node (D-6)
 *	rd:VPN/NODE	the RD an rd-auto or rd-auto-suffix asks for:
 *			0:AS:n, n the lowest no other entry has
 *	(sdwan_edge.c)	the tunnels' units and VNIs, their inner pairs and
 *			the loopbacks' from the service domain's prefix, the
 *			remote identities' addresses; the ipfw tables are
 *			named by the service's table (sw<fib>_...)
 *
 * An entry made once stays the service's as long as it is there: a
 * plan takes what the ledger has before it allocates.
 *
 * The planner works on each service with its augments in MEF 70.2's
 * terms (l3nm_mef.c's tables, D-4's vocabulary); the nodes' own in
 * nodes, {"VPN/NODE": {as, router_id, rd, rt, fib}}: an AS or router
 * id there is the edge's BGP's (bird_spec()).
 */

#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "console.h"

#define	SD	"arcana-l3nm:sdwan"
#define	DOM	"arcana-l3nm:domain"
#define	PFIB	"arcana-l3nm:fib"
#define	FIB_MAX	65535		/* the kernel's, as sdwan.c checks */

static const ucl_object_t *
get(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	if (o == NULL || ucl_object_type(o) != UCL_OBJECT)
		return (NULL);
	v = ucl_object_lookup(o, k);
	return (v == NULL || ucl_object_type(v) == UCL_NULL ? NULL : v);
}

static const char *
gstr(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	v = get(o, k);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

/* A number, as L3NM's JSON has it: a string for 64 bits. */
static bool
num(const ucl_object_t *v, int64_t *n)
{

	if (v == NULL)
		return (false);
	if (ucl_object_type(v) == UCL_INT) {
		*n = ucl_object_toint(v);
		return (true);
	}
	if (ucl_object_type(v) == UCL_STRING) {
		char	*e;

		*n = strtoll(ucl_object_tostring(v), &e, 10);
		return (e != ucl_object_tostring(v) && *e == '\0');
	}
	return (false);
}

static const ucl_object_t *
by_id(const ucl_object_t *arr, const char *key, const char *id)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;

	it = NULL;
	while (id != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL)
		if (gstr(v, key) != NULL && strcmp(gstr(v, key), id) == 0)
			return (v);
	return (NULL);
}

static const ucl_object_t *
profiles(const ucl_object_t *svc)
{

	return (get(get(svc, "vpn-instance-profiles"),
	    "vpn-instance-profile"));
}

/* The service's own table: its profile subscriber's, its sdwan's. */
static const ucl_object_t *
sub_profile(const ucl_object_t *svc)
{
	const ucl_object_t	*p;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((p = ucl_object_iterate(profiles(svc), &it, true)) != NULL)
		if ((gstr(p, DOM) != NULL ? gstr(p, DOM) : gstr(p,
		    "profile-id")) != NULL && strcmp(gstr(p, DOM) != NULL ?
		    gstr(p, DOM) : gstr(p, "profile-id"), "subscriber") == 0)
			return (p);
	return (NULL);
}

static bool
fib_of(const ucl_object_t *svc, int64_t *fib)
{

	return (num(get(get(svc, SD), "fib"), fib) ||
	    num(get(sub_profile(svc), PFIB), fib));
}

/* Is table fib any service's or domain's, or an entry's but key's? */
static bool
fib_taken(const ucl_object_t *y, const ucl_object_t *alloc, int64_t fib,
    const char *key)
{
	const ucl_object_t	*svc, *p, *a;
	ucl_object_iter_t	 it, pit;
	int64_t			 n;

	it = NULL;
	while ((svc = ucl_object_iterate(get(get(y, "vpn-services"),
	    "vpn-service"), &it, true)) != NULL) {
		if (fib_of(svc, &n) && n == fib)
			return (true);
		pit = NULL;
		while ((p = ucl_object_iterate(profiles(svc), &pit, true)) !=
		    NULL)
			if (num(get(p, PFIB), &n) && n == fib)
				return (true);
	}
	it = NULL;
	while ((a = ucl_object_iterate(alloc, &it, true)) != NULL)
		if (strncmp(ucl_object_key(a), "fib:", 4) == 0 &&
		    strchr(ucl_object_key(a), '/') == NULL &&
		    strcmp(ucl_object_key(a), key) != 0 &&
		    ucl_object_toint(ucl_object_lookup(a, "fib")) == fib)
			return (true);
	return (false);
}

static void
entry(ucl_object_t *alloc, ucl_object_t *used, const char *key,
    ucl_object_t *v)
{

	(void)ucl_object_delete_key(alloc, key);
	ucl_object_insert_key(alloc, v, key, 0, true);
	(void)ucl_object_delete_key(used, key);
	ucl_object_insert_key(used, ucl_object_frombool(true), key, 0, true);
}

/* An RD's number n no entry but key has, for AS as. */
static int64_t
rd_free(const ucl_object_t *alloc, const char *key, int64_t as)
{
	const ucl_object_t	*a;
	ucl_object_iter_t	 it;
	char			 rd[64];
	int64_t			 n;
	bool			 used;

	for (n = 1; n < 65536; n++) {
		snprintf(rd, sizeof(rd), "0:%jd:%jd", (intmax_t)as,
		    (intmax_t)n);
		used = false;
		it = NULL;
		while (!used && (a = ucl_object_iterate(alloc, &it, true)) !=
		    NULL)
			used = strncmp(ucl_object_key(a), "rd:", 3) == 0 &&
			    strcmp(ucl_object_key(a), key) != 0 &&
			    ucl_object_lookup(a, "rd") != NULL &&
			    strcmp(ucl_object_tostring(ucl_object_lookup(a,
			    "rd")), rd) == 0;
		if (!used)
			return (n);
	}
	return (-1);
}

/* Has the profile an RD choice of its own? */
static bool
has_rd(const ucl_object_t *p)
{

	return (get(p, "rd") != NULL || get(p, "rd-suffix") != NULL ||
	    get(p, "rd-auto") != NULL || get(p, "rd-auto-suffix") != NULL ||
	    get(p, "no-rd") != NULL);
}

/*
 * A node's RD of its profile p (the node's over the service's), into
 * o: as written, a suffix to its router id, or allocated.  False and
 * why: none is left.
 */
static bool
node_rd(const ucl_object_t *p, const char *rid, int64_t as, const char *key,
    ucl_object_t *alloc, ucl_object_t *used, ucl_object_t *o, char *why,
    size_t len)
{
	const ucl_object_t	*a;
	ucl_object_t		*e;
	char			 rd[80];
	int64_t			 n, sfx;

	if (gstr(p, "rd") != NULL) {
		ucl_object_insert_key(o, ucl_object_fromstring(gstr(p, "rd")),
		    "rd", 0, true);
		return (true);
	}
	if (num(get(p, "rd-suffix"), &sfx)) {
		if (rid != NULL && strchr(rid, ':') == NULL)
			snprintf(rd, sizeof(rd), "1:%s:%jd", rid, (intmax_t)sfx);
		else
			snprintf(rd, sizeof(rd), "0:%jd:%jd", (intmax_t)as,
			    (intmax_t)sfx);
		ucl_object_insert_key(o, ucl_object_fromstring(rd), "rd", 0,
		    true);
		return (true);
	}
	if (get(p, "rd-auto") == NULL && get(p, "rd-auto-suffix") == NULL)
		return (true);
	if ((a = ucl_object_lookup(alloc, key)) != NULL &&
	    ucl_object_lookup(a, "rd") != NULL)
		snprintf(rd, sizeof(rd), "%s", ucl_object_tostring(
		    ucl_object_lookup(a, "rd")));
	else if ((n = rd_free(alloc, key, as)) < 0) {
		snprintf(why, len, "no RD is left for AS %jd", (intmax_t)as);
		return (false);
	} else
		snprintf(rd, sizeof(rd), "0:%jd:%jd", (intmax_t)as,
		    (intmax_t)n);
	e = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(e, ucl_object_fromstring(rd), "rd", 0, true);
	entry(alloc, used, key, e);
	ucl_object_insert_key(o, ucl_object_fromstring(rd), "rd", 0, true);
	return (true);
}

/* The route targets of profile p, "type:value" each, into o. */
static void
node_rt(const ucl_object_t *p, ucl_object_t *o)
{
	const ucl_object_t	*af, *t, *rt;
	ucl_object_iter_t	 it, it2, it3;
	ucl_object_t		*rts;

	rts = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((af = ucl_object_iterate(get(p, "address-family"), &it,
	    true)) != NULL) {
		it2 = NULL;
		while ((t = ucl_object_iterate(get(get(af, "vpn-targets"),
		    "vpn-target"), &it2, true)) != NULL) {
			it3 = NULL;
			while ((rt = ucl_object_iterate(get(t, "route-targets"),
			    &it3, true)) != NULL)
				if (gstr(rt, "route-target") != NULL)
					ucl_array_append(rts,
					    ucl_object_fromstring(gstr(rt,
					    "route-target")));
		}
	}
	if (ucl_array_size(rts) > 0)
		ucl_object_insert_key(o, rts, "rt", 0, true);
	else
		ucl_object_unref(rts);
}

/* An IPv4 router id of a node's profile's list, else of the node. */
static const char *
router_id(const ucl_object_t *np, const ucl_object_t *node)
{
	const ucl_object_t	*r;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((r = ucl_object_iterate(get(np, "router-id"), &it, true)) !=
	    NULL)
		if (gstr(r, "router-id") != NULL && strchr(gstr(r,
		    "router-id"), ':') == NULL)
			return (gstr(r, "router-id"));
	return (gstr(node, "router-id"));
}

/*
 * A service's nodes, each with its profiles resolved, into nodes; the
 * RDs it asks for from the ledger.  False and why: one cannot be.
 */
static bool
resolve(const ucl_object_t *svc, int64_t fib, ucl_object_t *alloc,
    ucl_object_t *used, ucl_object_t *nodes, char *why, size_t len)
{
	const ucl_object_t	*node, *sub, *sp, *np, *ap;
	ucl_object_iter_t	 it, ait;
	ucl_object_t		*o, *e;
	const char		*vpn, *nid, *rid;
	char			 key[300], w[200];
	int64_t			 as, sas;

	vpn = gstr(svc, "vpn-id");
	sub = sub_profile(svc);
	sas = 0;
	(void)num(get(sub, "local-as"), &sas);
	it = NULL;
	while ((node = ucl_object_iterate(get(get(svc, "vpn-nodes"),
	    "vpn-node"), &it, true)) != NULL) {
		if ((nid = gstr(node, "vpn-node-id")) == NULL)
			continue;
		/* The node's active profile of the service's own table,
		 * else the first it activates. */
		ap = get(get(node, "active-vpn-instance-profiles"),
		    "vpn-instance-profile");
		sp = sub;
		if ((np = by_id(ap, "profile-id", gstr(sub, "profile-id"))) ==
		    NULL) {
			ait = NULL;
			np = ucl_object_iterate(ap, &ait, true);
			if (by_id(profiles(svc), "profile-id", gstr(np,
			    "profile-id")) != NULL)
				sp = by_id(profiles(svc), "profile-id", gstr(np,
				    "profile-id"));
		}
		o = ucl_object_typed_new(UCL_OBJECT);
		as = sas;
		(void)num(get(sp, "local-as"), &as);
		if (num(get(np, "local-as"), &as) || num(get(node, "local-as"),
		    &as))
			ucl_object_insert_key(o, ucl_object_fromint(as), "as", 0,
			    true);
		if ((rid = router_id(np, node)) != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(rid),
			    "router_id", 0, true);
		snprintf(key, sizeof(key), "rd:%s/%s", vpn, nid);
		if (!node_rd(has_rd(np) ? np : sp, rid, as, key, alloc, used, o,
		    w, sizeof(w))) {
			snprintf(why, len, "service %s, node %s: %s", vpn, nid,
			    w);
			ucl_object_unref(o);
			return (false);
		}
		node_rt(get(np, "address-family") != NULL ? np : sp, o);
		ucl_object_insert_key(o, ucl_object_fromint(fib), "fib", 0,
		    true);
		/* Its table on the node, kept with the others. */
		snprintf(key, sizeof(key), "fib:%s/%s", vpn, nid);
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromint(fib), "fib", 0,
		    true);
		ucl_object_insert_key(e, ucl_object_fromstring(gstr(node,
		    "ne-id") != NULL ? gstr(node, "ne-id") : nid), "ne", 0,
		    true);
		entry(alloc, used, key, e);
		snprintf(key, sizeof(key), "%s/%s", vpn, nid);
		ucl_object_insert_key(nodes, o, key, 0, true);
	}
	return (true);
}

/*
 * The planner's input of L3NM y (l3nm_kept()): its SD-WAN services in
 * the planner's terms, a table allocated to each that names none, the
 * nodes resolved into nodes; the ledger's entries in alloc, those it
 * uses in used.  NULL and why: it cannot be planned.
 */
ucl_object_t *
l3nm_plan_input(const ucl_object_t *y, ucl_object_t *alloc,
    ucl_object_t *used, ucl_object_t *nodes, char *why, size_t len)
{
	const ucl_object_t	*svc, *a;
	ucl_object_iter_t	 it;
	ucl_object_t		*yc, *sd, *e, *doc;
	char			 key[300];
	int64_t			 fib;

	yc = y != NULL ? ucl_object_copy(y) : ucl_object_typed_new(
	    UCL_OBJECT);
	it = NULL;
	while ((svc = ucl_object_iterate(get(get(yc, "vpn-services"),
	    "vpn-service"), &it, true)) != NULL) {
		if ((sd = __DECONST(ucl_object_t *, get(svc, SD))) == NULL ||
		    gstr(svc, "vpn-id") == NULL)
			continue;
		snprintf(key, sizeof(key), "fib:%s", gstr(svc, "vpn-id"));
		if (!fib_of(svc, &fib)) {
			/* None named: the ledger's, else the lowest free. */
			if ((a = ucl_object_lookup(alloc, key)) != NULL)
				fib = ucl_object_toint(ucl_object_lookup(a,
				    "fib"));
			else {
				for (fib = 1; fib <= FIB_MAX && fib_taken(yc,
				    alloc, fib, key); fib++)
					;
				if (fib > FIB_MAX) {
					snprintf(why, len, "service %s names no "
					    "table and none is left (1 to %d)",
					    gstr(svc, "vpn-id"), FIB_MAX);
					ucl_object_unref(yc);
					return (NULL);
				}
			}
			e = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(e, ucl_object_fromint(fib), "fib",
			    0, true);
			entry(alloc, used, key, e);
			ucl_object_insert_key(sd, ucl_object_fromint(fib),
			    "fib", 0, true);
		}
		if (!resolve(svc, fib, alloc, used, nodes, why, len)) {
			ucl_object_unref(yc);
			return (NULL);
		}
	}
	doc = mef_export(yc);
	ucl_object_unref(yc);
	return (doc);
}
