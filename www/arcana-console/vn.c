/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The services' customer view: RFC 9731's VN (ietf-vn), made from the
 * L3NM kept (l3nm.c) at each read, with no store of its own:
 *
 *	/restconf/data/ietf-vn:access-point[/<api-path>]
 *	/restconf/data/ietf-vn:virtual-network[/<api-path>]
 *
 * A VN each vpn-service: its id the vpn-id, its admin-status the
 * service's.  An AP each place a host attaches accesses, the SAP
 * (RFC 9408's sap-id on its node): "<ne-id>:<interface-id>", the
 * access's own id where it names no interface.  A VNAP each access
 * there, "<vpn-id>:<access-id>", of its service's VN.  A VN member each
 * pair of a service's accesses on two vpn-nodes, the tunnel between
 * them, "<node>:<access>~<node>:<access>", its source the first as the
 * L3NM lists them; none between two spokes (RFC 9181's spoke-role, by
 * the access's VPN instance profile).  No TE topology is kept, so pe,
 * abstract-node, ltp and connectivity-matrix-id are left out.  Read
 * alone: a change is the L3NM's.
 *
 * arcana-sdwan-underlay's: a VN's path-metric-bounds its service's TCA
 * thresholds (delay and delay variation in microseconds, loss in
 * millionths); a member's underlay the tunnels the plan makes between
 * its two edges (sdwan_plan_tunnels()), each with what the steering at
 * either end (arcana-steer, read through the fleet mount) says of it.
 * A member's oper-status: up where one of its tunnels is up, down where
 * all are, unknown else; left out where neither edge has arcana-steer.
 * if-selected is left out: a member has no multi-source or
 * multi-destination alternatives, its tunnels being its alternatives,
 * each one's selected in the underlay.
 *
 *	/restconf/operations/ietf-vn:vn-compute
 *
 * RFC 9731's VN compute as the console's check, nothing made: each
 * member asked for found in the view (its APs, VNAPs and the member
 * between them), the plan's tunnels between its edges, and what it
 * asks (its own, else the input's): its bounds against what the
 * steering at either end last measured of them, its te-bandwidth
 * against the uplinks (4.5.6's sums), its cos among its service's
 * business importance levels, its disjointness and the input's
 * vn-level-diversity by UCS End Point (a link) and UCS (an SRLG, and
 * the underlay's nodes); infeasible, compute-status down with
 * error-info's reason and why; unmeasured, unknown; an optimization
 * Arcana does not weigh, unknown and said.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <cbl_data.h>
#include <ucl.h>

#include "console.h"
#include "restconf.h"
#include "ymodel.h"
#include "ytrans.h"

#define	VN_PREFIX	"/restconf/data/ietf-vn:"
#define	VN_AP		"access-point"
#define	VN_VN		"virtual-network"
/* The L3NM's entity-tags': the view changes with it. */
#define	VN_URI		"console:l3nm"
#define	ACC_MAX		256

/* A view's making: the plan's tunnels, the edges' steering read. */
struct vctx {
	struct http_request *req;	/* whose: hosts it may not read unread */
	ucl_object_t	*tunnels;
	ucl_object_t	*steer;		/* edge: its policies, or null */
};

struct acc {
	const char	*node;		/* its vpn-node-id */
	const char	*id;
	char		 vnap[192];
	char		 ap[192];
	bool		 spoke;
};

bool
vn_path(const char *path)
{
	static const char *const tops[] = { VN_AP, VN_VN };
	size_t	 n = sizeof(VN_PREFIX) - 1, k;

	if (strncmp(path, VN_PREFIX, n) != 0)
		return (false);
	for (size_t i = 0; i < nitems(tops); i++) {
		k = strlen(tops[i]);
		if (strncmp(path + n, tops[i], k) == 0 && (path[n + k] ==
		    '\0' || path[n + k] == '/'))
			return (true);
	}
	return (false);
}

/* An identity's name, its module's prefix taken off. */
static const char *
bare(const char *v)
{
	const char	*c;

	if (v == NULL)
		return ("");
	return ((c = strchr(v, ':')) != NULL ? c + 1 : v);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0, true);
}

/* Profile pid of service s: of RFC 9181's spoke-role. */
static bool
spoke_profile(const ucl_object_t *s, const char *pid)
{
	const ucl_object_t	*p;
	ucl_object_iter_t	 it = NULL;
	const char		*id;

	if (pid == NULL)
		return (false);
	while ((p = ucl_object_iterate(ucl_object_lookup_path(s,
	    "vpn-instance-profiles.vpn-instance-profile"), &it, true)) !=
	    NULL)
		if ((id = ucl_str(p, "profile-id")) != NULL &&
		    strcmp(id, pid) == 0)
			return (strcmp(bare(ucl_str(p, "role")),
			    "spoke-role") == 0);
	return (false);
}

/* VN admin-status (te-types' te-admin-status) of an L3NM status. */
static const char *
admin_of(const ucl_object_t *s)
{
	const char	*v;

	v = bare(ucl_object_tostring(ucl_object_lookup_path(s,
	    "status.admin-status.status")));
	if (strcmp(v, "admin-down") == 0)
		return ("down");
	if (strcmp(v, "admin-testing") == 0)
		return ("testing");
	return (NULL);
}

/* AP id's entry of aps (an object by id), made with its vn-ap list. */
static ucl_object_t *
ap_entry(ucl_object_t *aps, const char *id)
{
	ucl_object_t	*e;

	if ((e = __DECONST(ucl_object_t *, ucl_object_lookup(aps, id))) !=
	    NULL)
		return (e);
	e = ucl_object_typed_new(UCL_OBJECT);
	put_str(e, "id", id);
	ucl_object_insert_key(e, ucl_object_typed_new(UCL_ARRAY), "vn-ap",
	    0, false);
	ucl_object_insert_key(aps, e, id, 0, true);
	return (e);
}

static ucl_object_t *
end_of(const struct acc *c)
{
	ucl_object_t	*e;

	e = ucl_object_typed_new(UCL_OBJECT);
	put_str(e, "ap", c->ap);
	put_str(e, "vn-ap-id", c->vnap);
	return (e);
}

/* ---- Bounds and underlay (arcana-sdwan-underlay) ---------------------- */

/* The TCA's thresholds as path-metric-bounds: each its metric, scaled. */
static const struct {
	const char	*tca;
	const char	*metric;
	double		 scale;
} bounds[] = {
	{ "delay", "ietf-te-types:path-metric-delay-average", 1e3 },
	{ "ipdv", "arcana-sdwan-underlay:path-metric-delay-variation", 1e3 },
	{ "loss", "arcana-sdwan-underlay:path-metric-loss", 1e6 },
};

/* A number, as RFC 7951 writes a decimal64 (a string) or not. */
static bool
num_of(const ucl_object_t *v, double *d)
{
	const char	*s;
	char		*e;

	if (v == NULL)
		return (false);
	if (ucl_object_type(v) == UCL_INT || ucl_object_type(v) == UCL_FLOAT) {
		*d = ucl_object_todouble(v);
		return (true);
	}
	if ((s = ucl_object_tostring(v)) == NULL || *s == '\0')
		return (false);
	*d = strtod(s, &e);
	return (*e == '\0');
}

/* Service s's TCA as path-metric-bounds; NULL: it has none. */
static ucl_object_t *
bounds_of(const ucl_object_t *s)
{
	const ucl_object_t	*tca;
	ucl_object_t		*arr, *b, *o;
	double			 d;
	char			 v[32];

	tca = ucl_object_lookup_path(s, "arcana-l3nm:sdwan.tca");
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; tca != NULL && i < nitems(bounds); i++) {
		if (!num_of(ucl_object_lookup(tca, bounds[i].tca), &d) ||
		    d < 0)
			continue;
		snprintf(v, sizeof(v), "%.0f", round(d * bounds[i].scale));
		b = ucl_object_typed_new(UCL_OBJECT);
		put_str(b, "metric-type", bounds[i].metric);
		put_str(b, "upper-bound", v);
		ucl_array_append(arr, b);
	}
	if (ucl_array_size(arr) == 0) {
		ucl_object_unref(arr);
		return (NULL);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, arr, "path-metric-bound", 0, false);
	return (o);
}

/*
 * A path-metric-bound (metric, upper) as the TCA has it: its leaf
 * (delay, ipdv, loss) and value in the TCA's units; false, a metric of
 * none or unbounded (0).
 */
bool
vn_bound_tca(const char *metric, uint64_t upper, const char **leaf,
    double *v)
{

	for (size_t i = 0; i < nitems(bounds); i++)
		if (strcmp(bare(metric), bare(bounds[i].metric)) == 0 &&
		    upper > 0) {
			*leaf = bounds[i].tca;
			*v = (double)upper / bounds[i].scale;
			return (true);
		}
	return (false);
}

static bool
is_addr(const char *s, int af)
{
	struct in6_addr	 a;

	return (s != NULL && inet_pton(af, s, &a) == 1);
}

/* Edge's policies of arcana-steer's state, read through the fleet
 * mount once a view; NULL: none (no such host, or no arcana-steer). */
static const ucl_object_t *
steer_at(struct vctx *x, const char *edge)
{
	struct ucl_parser	*p;
	const ucl_object_t	*v, *pol;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*o = NULL, *arr;
	const char		*j;
	char			 sid[64], jail[64], uri[256], peer[256];
	char			 name[128], path[256], *json;
	int			 status;

	if ((v = ucl_object_lookup(x->steer, edge)) != NULL)
		return (ucl_object_type(v) == UCL_ARRAY ? v : NULL);
	arr = NULL;
	if (sdwan_edge_split(edge, sid, sizeof(sid), jail, sizeof(jail)) &&
	    host_role_ok(x->req, sid, false, false) && host_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
	    sizeof(name))) {
		snprintf(path, sizeof(path), "/restconf/data/arcana-fleet:"
		    "fleet/host=%s/arcana-steer:steering/state", sid);
		json = hosts_restconf(sid, uri, peer, name, HTTP_METHOD_GET,
		    path, NULL, &status);
		if (status == 200 && json != NULL) {
			p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
			    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
			if (ucl_parser_add_string(p, json, 0))
				o = ucl_parser_get_object(p);
			ucl_parser_free(p);
		}
		free(json);
	}
	if (o != NULL) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		while ((pol = ucl_object_iterate(ucl_object_lookup_path(o,
		    "arcana-steer:state.policy"), &it, true)) != NULL) {
			j = ucl_str(pol, "jail");
			if (strcmp(j != NULL ? j : "", jail) == 0)
				ucl_array_append(arr, ucl_object_copy(pol));
		}
		ucl_object_unref(o);
	}
	ucl_object_insert_key(x->steer, arr != NULL ? arr :
	    ucl_object_typed_new(UCL_NULL), edge, 0, true);
	return (arr);
}

/* What the steering at edge says of tunnel id: its far end's state
 * (*st, NULL: not a candidate there) and whether it is in use. */
static void
steer_of(struct vctx *x, const char *edge, const char *id, const char **st,
    bool *sel, bool *read)
{
	const ucl_object_t	*pols, *pol, *c;
	ucl_object_iter_t	 it = NULL, ct;
	const char		*s;

	if ((pols = steer_at(x, edge)) == NULL)
		return;
	*read = true;
	while ((pol = ucl_object_iterate(pols, &it, true)) != NULL) {
		if ((s = ucl_str(pol, "chosen")) != NULL && strcmp(s, id) == 0)
			*sel = true;
		ct = NULL;
		while ((c = ucl_object_iterate(ucl_object_lookup(pol,
		    "candidate"), &ct, true)) != NULL)
			if ((s = ucl_str(c, "id")) != NULL && strcmp(s, id) ==
			    0 && (s = ucl_str(c, "state")) != NULL &&
			    (*st == NULL || strcmp(s, "up") == 0))
				*st = s;
	}
}

static ucl_object_t *
tunnel_end(const ucl_object_t *e)
{
	ucl_object_t	*o;
	const char	*s;

	o = ucl_object_typed_new(UCL_OBJECT);
	if ((s = ucl_str(e, "edge")) != NULL)
		put_str(o, "edge", s);
	if ((s = ucl_str(e, "ucs_ep")) != NULL)
		put_str(o, "ucs-end-point", s);
	if (is_addr(s = ucl_str(e, "underlay"), AF_INET) || is_addr(s,
	    AF_INET6))
		put_str(o, "outer-address", s);
	if (ucl_object_lookup(e, "vrf") != NULL)
		ucl_object_insert_key(o, ucl_object_fromint(ucl_object_toint(
		    ucl_object_lookup(e, "vrf"))), "outer-fib", 0, false);
	if ((s = ucl_str(e, "ifname")) != NULL)
		put_str(o, "interface", s);
	if (is_addr(s = ucl_str(e, "inner4"), AF_INET))
		put_str(o, "inner-ipv4", s);
	if (is_addr(s = ucl_str(e, "inner6"), AF_INET6))
		put_str(o, "inner-ipv6", s);
	return (o);
}

static void
put_int(ucl_object_t *o, const char *key, const ucl_object_t *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromint(ucl_object_toint(v)),
		    key, 0, true);
}

static void
put_bool(ucl_object_t *o, const char *key, const ucl_object_t *v)
{

	ucl_object_insert_key(o, ucl_object_frombool(v != NULL &&
	    ucl_object_toboolean(v)), key, 0, true);
}

/*
 * Member m's underlay, the tunnels of service s (vid) between nodes src
 * and dst, and its oper-status where the steering says one.
 */
static void
member_underlay(struct vctx *x, const ucl_object_t *s, const char *vid,
    const char *src, const char *dst, ucl_object_t *m)
{
	const ucl_object_t	*t, *e0, *e1, *es, *ed, *sw, *v;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*arr, *o, *b, *u;
	const char		*id, *k, *st;
	bool			 sel, read = false;
	size_t			 seen = 0, up = 0, down = 0;

	if (x->tunnels == NULL)
		return;
	sw = ucl_object_lookup(s, "arcana-l3nm:sdwan");
	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((t = ucl_object_iterate(x->tunnels, &it, true)) != NULL) {
		if ((id = ucl_str(t, "id")) == NULL || (k = ucl_str(t,
		    "swvc")) == NULL || strcmp(k, vid) != 0)
			continue;
		e0 = ucl_array_find_index(ucl_object_lookup(t, "ends"), 0);
		e1 = ucl_array_find_index(ucl_object_lookup(t, "ends"), 1);
		if (ucl_str(e0, "edge") == NULL || ucl_str(e1, "edge") == NULL)
			continue;
		if (strcmp(ucl_str(e0, "edge"), src) == 0 &&
		    strcmp(ucl_str(e1, "edge"), dst) == 0) {
			es = e0;
			ed = e1;
		} else if (strcmp(ucl_str(e1, "edge"), src) == 0 &&
		    strcmp(ucl_str(e0, "edge"), dst) == 0) {
			es = e1;
			ed = e0;
		} else
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "id", id);
		if ((k = ucl_str(t, "ucs")) != NULL)
			put_str(o, "ucs", k);
		if ((k = ucl_str(t, "kind")) != NULL) {
			put_str(o, "encapsulation", k);
			if (strcmp(k, "geneve") == 0)
				put_int(o, "vni", ucl_object_lookup(t, "vni"));
		}
		put_int(o, "fib", ucl_object_lookup(t, "fib"));
		put_bool(o, "ipsec", ucl_object_lookup(t, "ipsec"));
		put_bool(o, "encrypted", ucl_object_lookup(t, "encrypted"));
		put_bool(o, "backup", ucl_object_lookup(t, "backup"));
		put_int(o, "dscp", ucl_object_lookup_path(sw, "probe.dscp"));
		if ((v = ucl_object_lookup(sw, "bfd")) != NULL) {
			b = ucl_object_typed_new(UCL_OBJECT);
			put_int(b, "interval", ucl_object_lookup(v, "interval"));
			put_int(b, "multiplier", ucl_object_lookup(v,
			    "multiplier"));
			ucl_object_insert_key(o, b, "bfd", 0, false);
		}
		ucl_object_insert_key(o, tunnel_end(es), "src", 0, false);
		ucl_object_insert_key(o, tunnel_end(ed), "dest", 0, false);
		st = NULL;
		sel = false;
		steer_of(x, src, id, &st, &sel, &read);
		steer_of(x, dst, id, &st, &sel, &read);
		if (st != NULL) {
			put_str(o, "state", st);
			seen++;
			up += strcmp(st, "up") == 0;
			down += strcmp(st, "down") == 0;
		}
		if (read)
			ucl_object_insert_key(o, ucl_object_frombool(sel),
			    "selected", 0, false);
		ucl_array_append(arr, o);
	}
	if (ucl_array_size(arr) == 0) {
		ucl_object_unref(arr);
		return;
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, arr, "tunnel", 0, false);
	u = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(u, o, "arcana-sdwan-underlay:sdwan", 0, false);
	ucl_object_insert_key(m, u, "underlay", 0, false);
	if (seen > 0)
		put_str(m, "oper-status", up > 0 ? "up" : down == seen ?
		    "down" : "unknown");
}

/* Service s's VN, its accesses' VNAPs added to aps. */
static ucl_object_t *
vn_of(struct vctx *x, const ucl_object_t *s, ucl_object_t *aps)
{
	struct acc		*c;
	const ucl_object_t	*nd, *na;
	ucl_object_iter_t	 it = NULL, jt;
	ucl_object_t		*vn, *ms, *m, *e;
	const ucl_object_t	*os;
	const char		*vid, *ne, *ifn, *a, *st;
	size_t			 nc = 0, seen = 0, up = 0, down = 0;
	char			 mid[400];

	if ((vid = ucl_str(s, "vpn-id")) == NULL ||
	    (c = calloc(ACC_MAX, sizeof(*c))) == NULL)
		return (NULL);
	while ((nd = ucl_object_iterate(ucl_object_lookup_path(s,
	    "vpn-nodes.vpn-node"), &it, true)) != NULL) {
		if (ucl_str(nd, "vpn-node-id") == NULL)
			continue;
		if ((ne = ucl_str(nd, "ne-id")) == NULL)
			ne = ucl_str(nd, "vpn-node-id");
		jt = NULL;
		while (nc < ACC_MAX && (na = ucl_object_iterate(
		    ucl_object_lookup_path(nd, "vpn-network-accesses."
		    "vpn-network-access"), &jt, true)) != NULL) {
			if ((c[nc].id = ucl_str(na, "id")) == NULL)
				continue;
			c[nc].node = ucl_str(nd, "vpn-node-id");
			ifn = ucl_str(na, "interface-id");
			snprintf(c[nc].ap, sizeof(c[nc].ap), "%s:%s", ne,
			    ifn != NULL ? ifn : c[nc].id);
			snprintf(c[nc].vnap, sizeof(c[nc].vnap), "%s:%s", vid,
			    c[nc].id);
			c[nc].spoke = spoke_profile(s, ucl_str(na,
			    "vpn-instance-profile"));
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "id", c[nc].vnap);
			put_str(e, "vn", vid);
			ucl_array_append(__DECONST(ucl_object_t *,
			    ucl_object_lookup(ap_entry(aps, c[nc].ap),
			    "vn-ap")), e);
			nc++;
		}
	}
	vn = ucl_object_typed_new(UCL_OBJECT);
	put_str(vn, "id", vid);
	ms = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < nc; i++)
		for (size_t k = i + 1; k < nc; k++) {
			if (strcmp(c[i].node, c[k].node) == 0 ||
			    (c[i].spoke && c[k].spoke))
				continue;
			snprintf(mid, sizeof(mid), "%s:%s~%s:%s", c[i].node,
			    c[i].id, c[k].node, c[k].id);
			m = ucl_object_typed_new(UCL_OBJECT);
			put_str(m, "id", mid);
			ucl_object_insert_key(m, end_of(&c[i]), "src", 0,
			    false);
			ucl_object_insert_key(m, end_of(&c[k]), "dest", 0,
			    false);
			member_underlay(x, s, vid, c[i].node, c[k].node, m);
			if ((os = ucl_object_lookup(m, "oper-status")) !=
			    NULL) {
				st = ucl_object_tostring(os);
				seen++;
				up += strcmp(st, "up") == 0;
				down += strcmp(st, "down") == 0;
			}
			ucl_array_append(ms, m);
		}
	if (ucl_array_size(ms) > 0)
		ucl_object_insert_key(vn, ms, "vn-member", 0, false);
	else
		ucl_object_unref(ms);
	if ((a = admin_of(s)) != NULL)
		put_str(vn, "admin-status", a);
	if (seen > 0)
		put_str(vn, "oper-status", up > 0 ? "up" : down == seen ?
		    "down" : "unknown");
	if ((e = bounds_of(s)) != NULL)
		ucl_object_insert_key(vn, e, "arcana-sdwan-underlay:"
		    "path-metric-bounds", 0, false);
	free(c);
	return (vn);
}

/*
 * The VN view of L3NM y (l3nm_kept()'s): RFC 7951's members
 * ietf-vn:access-point and ietf-vn:virtual-network, where there is a
 * service.
 */
static ucl_object_t *
view_make(struct http_request *req, const ucl_object_t *y, struct vctx *x)
{
	const ucl_object_t	*s, *e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*top, *aps, *vns, *arr, *o, *vn;

	x->req = req;
	x->tunnels = ucl_object_lookup_path(y, "vpn-services.vpn-service") !=
	    NULL ? sdwan_plan_tunnels(y) : NULL;
	x->steer = ucl_object_typed_new(UCL_OBJECT);
	top = ucl_object_typed_new(UCL_OBJECT);
	aps = ucl_object_typed_new(UCL_OBJECT);
	vns = ucl_object_typed_new(UCL_ARRAY);
	while ((s = ucl_object_iterate(ucl_object_lookup_path(y,
	    "vpn-services.vpn-service"), &it, true)) != NULL)
		if ((vn = vn_of(x, s, aps)) != NULL)
			ucl_array_append(vns, vn);
	if (ucl_array_size(vns) > 0) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((e = ucl_object_iterate(aps, &it, true)) != NULL)
			ucl_array_append(arr, ucl_object_copy(e));
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, arr, "ap", 0, false);
		ucl_object_insert_key(top, o, "ietf-vn:" VN_AP, 0, false);
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, vns, "vn", 0, false);
		ucl_object_insert_key(top, o, "ietf-vn:" VN_VN, 0, false);
	} else
		ucl_object_unref(vns);
	ucl_object_unref(aps);
	return (top);
}

static void
view_done(struct vctx *x)
{

	if (x->tunnels != NULL)
		ucl_object_unref(x->tunnels);
	ucl_object_unref(x->steer);
}

ucl_object_t *
vn_view(struct http_request *req, const ucl_object_t *y)
{
	struct vctx	 x;
	ucl_object_t	*top;

	top = view_make(req, y, &x);
	view_done(&x);
	return (top);
}

static const struct cbl_ynode *
vn_top(const char *name)
{
	const struct cbl_ymodule	*m;

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, "ietf-vn") != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++)
			if (strcmp(m->top[k]->name, name) == 0)
				return (m->top[k]);
	}
	return (NULL);
}

/* The view as a tree of the console's schema, its strings in a. */
static cbl_dtree *
vn_tree(const ucl_object_t *view, cbl_yarena *a, char *why, size_t len)
{
	static const char *const tops[] = { VN_AP, VN_VN };
	const struct cbl_ynode	*n;
	const ucl_object_t	*v;
	cbl_dtree		*t;
	char			 key[64];

	if ((t = cbl_dtree_new(&ymodel_schema)) == NULL) {
		snprintf(why, len, "out of memory");
		return (NULL);
	}
	for (size_t i = 0; i < nitems(tops); i++) {
		snprintf(key, sizeof(key), "ietf-vn:%s", tops[i]);
		if ((v = ucl_object_lookup(view, key)) == NULL)
			continue;
		if ((n = vn_top(tops[i])) == NULL) {
			snprintf(why, len, "no ietf-vn in the console's schema");
			cbl_dtree_free(t);
			return (NULL);
		}
		if (yjson_member(t, n, v, a, why, len) != 0) {
			cbl_dtree_free(t);
			return (NULL);
		}
	}
	return (t);
}

/* /restconf/data's: the view into top, where the user may read it. */
void
vn_into(struct http_request *req, ucl_object_t *top)
{
	ucl_object_t		*y, *view;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;
	const char		*u;

	if ((u = session_user(req)) != NULL && !user_path_ok(user_console(u),
	    VN_PREFIX VN_VN, false))
		return;
	y = l3nm_kept();
	view = vn_view(req, y);
	ucl_object_unref(y);
	while ((v = ucl_object_iterate(view, &it, true)) != NULL)
		ucl_object_insert_key(top, ucl_object_copy(v),
		    ucl_object_key(v), 0, true);
	ucl_object_unref(view);
}

int
api_vn(struct http_request *req)
{
	struct rcreq	*r;
	ucl_object_t	*y, *view;
	cbl_dtree	*t;
	cbl_yarena	*a;
	const char	*why = NULL;
	char		 err[256], *json = NULL;
	bool		 changed;
	int		 st, status;

	if (!guard(req, false))
		return (WEB_OK);
	if (req->method != HTTP_METHOD_GET) {
		http_response_header(req, "allow", "GET, OPTIONS");
		return (restconf_error(req, 405, "the VN view is made from the "
		    "services kept, and read alone: a change is made to them, "
		    "at /restconf/data/ietf-l3vpn-ntw:l3vpn-ntw"));
	}
	if ((r = restconf_parse_own(req->path, req->query_string, &why)) ==
	    NULL)
		return (restconf_error(req, 400, why));
	if ((st = restconf_prepare(r, req->method, NULL, NULL, &why)) == 0)
		st = restconf_precondition(req, r, VN_URI);
	if (st != 0) {
		(void)restconf_refuse(req, r, VN_URI, st, why);
		restconf_free(r);
		return (WEB_OK);
	}
	if ((a = cbl_yarena_new()) == NULL) {
		restconf_free(r);
		return (restconf_error(req, 500, "out of memory"));
	}
	y = l3nm_kept();
	view = vn_view(req, y);
	ucl_object_unref(y);
	t = vn_tree(view, a, err, sizeof(err));
	ucl_object_unref(view);
	if (t == NULL) {
		thread_log(LOG_ERR, "the VN view: %s", err);
		cbl_yarena_free(a);
		restconf_free(r);
		return (restconf_error(req, 500, "the VN view could not be "
		    "made of the services kept"));
	}
	restconf_run_own(r, t, a, &changed, &json, &status);
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	if (json == NULL) {
		json = restconf_errors(500, "out of memory");
		status = 500;
	}
	http_response_header(req, "content-type", "application/yang-data+json");
	http_response_header(req, "cache-control", "no-store");
	http_response_header(req, "x-content-type-options", "nosniff");
	restconf_headers(req, r, VN_URI, status);
	http_response(req, status, json, strlen(json));
	free(json);
	restconf_free(r);
	return (WEB_OK);
}

/* ---- vn-compute (RFC 9731 section 4.3.1) ------------------------------ */

#define	BOUND_MAX	8
#define	TUN_MAX		16	/* a member's tunnels weighed */
#define	DIV_MAX		64	/* members kept apart */
#define	DIV_STEPS	100000	/* choices tried, at most */

/* te-path-disjointness's bits (RFC 8776). */
#define	DIS_NODE	0x1
#define	DIS_LINK	0x2
#define	DIS_SRLG	0x4

#define	NO_RESOURCE	"ietf-vn:vn-computation-error-no-resource"

/* A bound of path-metric-bounds, as the TCA's leaf has it. */
struct bound {
	const char	*leaf;		/* delay, ipdv, loss; NULL: unmeasured */
	const char	*metric;
	double		 max;
};

/* What a member asks, its own or the input's. */
struct ask {
	struct bound		 b[BOUND_MAX];
	int			 nb;
	double			 bw;	/* te-bandwidth, bit/s; 0: none */
	const char		*bwlist; /* one that is a list */
	int			 cos;	/* -1: none */
	int			 dis;	/* DIS_*, of its own paths */
	const ucl_object_t	*opt;	/* optimizations */
};

/* A member computed: its entry, the tunnels that may carry it. */
struct mres {
	ucl_object_t		*m;
	const ucl_object_t	*tun[TUN_MAX];
	bool			 fit[TUN_MAX];
	int			 ntun;
	bool			 down;
};

/* Entry key=id of list arr; NULL: none. */
static const ucl_object_t *
entry(const ucl_object_t *arr, const char *key, const char *id)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	const char		*s;

	while (id != NULL && (e = ucl_object_iterate(arr, &it, true)) != NULL)
		if ((s = ucl_str(e, key)) != NULL && strcmp(s, id) == 0)
			return (e);
	return (NULL);
}

/* The bounds of path-constraints pc into b; their count, -1 bad. */
static int
bounds_in(const ucl_object_t *pc, struct bound *b)
{
	const ucl_object_t	*e, *u;
	ucl_object_iter_t	 it = NULL;
	const char		*m;
	double			 d;
	char			*end;
	int			 n = 0;

	while ((e = ucl_object_iterate(ucl_object_lookup_path(pc,
	    "path-metric-bounds.path-metric-bound"), &it, true)) != NULL) {
		if ((m = ucl_str(e, "metric-type")) == NULL || n == BOUND_MAX)
			return (-1);
		u = ucl_object_lookup(e, "upper-bound");
		if (u == NULL)
			d = 0;
		else if (ucl_object_type(u) == UCL_STRING) {
			d = strtod(ucl_object_tostring(u), &end);
			if (*end != '\0' || d < 0)
				return (-1);
		} else if (ucl_object_type(u) == UCL_INT &&
		    ucl_object_toint(u) >= 0)
			d = (double)ucl_object_toint(u);
		else
			return (-1);
		if (d == 0)
			continue;	/* unbounded */
		b[n].metric = m;
		if (!vn_bound_tca(m, (uint64_t)d, &b[n].leaf, &b[n].max))
			b[n].leaf = NULL;
		n++;
	}
	return (n);
}

/*
 * Tunnel id's last sample of leaf at edge, as its steering's candidate
 * has it: the worse of what *got has and it (NAN: none yet).
 */
static void
sample_at(struct vctx *x, const char *edge, const char *id, const char *leaf,
    double *got)
{
	const ucl_object_t	*pols, *pol, *c;
	ucl_object_iter_t	 it = NULL, ct;
	const char		*s;
	double			 d;

	if (edge == NULL || (pols = steer_at(x, edge)) == NULL)
		return;
	while ((pol = ucl_object_iterate(pols, &it, true)) != NULL) {
		ct = NULL;
		while ((c = ucl_object_iterate(ucl_object_lookup(pol,
		    "candidate"), &ct, true)) != NULL)
			if ((s = ucl_str(c, "id")) != NULL && strcmp(s, id) ==
			    0 && num_of(ucl_object_lookup(c, leaf), &d) &&
			    (isnan(*got) || d > *got))
				*got = d;
	}
}

static void	info(ucl_object_t *, const char *, const char *, const char *,
		    ...) __printflike(4, 5);
static void	fail_info(ucl_object_t *, const char *, const char *, ...)
		    __printflike(3, 4);

/* Member m's compute-status st, error-info why (reason NULL: none). */
static void
vinfo(ucl_object_t *m, const char *st, const char *reason, const char *fmt,
    va_list ap)
{
	ucl_object_t	*ei;
	struct tm	 tm;
	time_t		 now;
	char		 why[1024], ts[32];

	vsnprintf(why, sizeof(why), fmt, ap);
	now = time(NULL);
	gmtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
	ei = ucl_object_typed_new(UCL_OBJECT);
	put_str(ei, "error-description", why);
	put_str(ei, "error-timestamp", ts);
	if (reason != NULL)
		put_str(ei, "error-reason", reason);
	(void)ucl_object_delete_key(m, "compute-status");
	(void)ucl_object_delete_key(m, "error-info");
	put_str(m, "compute-status", st);
	ucl_object_insert_key(m, ei, "error-info", 0, false);
}

static void
info(ucl_object_t *m, const char *st, const char *reason, const char *fmt,
    ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vinfo(m, st, reason, fmt, ap);
	va_end(ap);
}

/* Member m infeasible: compute-status down, error-info why. */
static void
fail_info(ucl_object_t *m, const char *reason, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vinfo(m, "down", reason, fmt, ap);
	va_end(ap);
}

/* AP ap's VNAP: vnap where named, else its only one; NULL: neither. */
static const ucl_object_t *
vnap_of(const ucl_object_t *ap, const char *vnap)
{
	const ucl_object_t	*l;

	l = ucl_object_lookup(ap, "vn-ap");
	if (vnap != NULL)
		return (entry(l, "id", vnap));
	return (ucl_array_size(l) == 1 ? ucl_array_find_index(l, 0) : NULL);
}

static ucl_object_t *
end_out(const char *ap, const char *vnap)
{
	ucl_object_t	*e;

	e = ucl_object_typed_new(UCL_OBJECT);
	if (ap != NULL)
		put_str(e, "ap", ap);
	if (vnap != NULL)
		put_str(e, "vn-ap-id", vnap);
	return (e);
}

/* The view's member of vn between VNAPs a and b, either way. */
static const ucl_object_t *
member_between(const ucl_object_t *vn, const char *a, const char *b)
{
	const ucl_object_t	*t;
	ucl_object_iter_t	 it = NULL;
	const char		*s, *d;

	while ((t = ucl_object_iterate(ucl_object_lookup(vn, "vn-member"),
	    &it, true)) != NULL) {
		s = ucl_object_tostring(ucl_object_lookup_path(t,
		    "src.vn-ap-id"));
		d = ucl_object_tostring(ucl_object_lookup_path(t,
		    "dest.vn-ap-id"));
		if (s != NULL && d != NULL && ((strcmp(s, a) == 0 &&
		    strcmp(d, b) == 0) || (strcmp(d, a) == 0 &&
		    strcmp(s, b) == 0)))
			return (t);
	}
	return (NULL);
}

/*
 * te-bandwidth's generic of path-constraints pc (RFC 8776): for a
 * packet network an IEEE float32, or a decimal or hex integer, of bytes
 * a second, *bps in bits; a list (OTN's, DWDM's) in *list.  -1 bad.
 */
static int
bw_in(const ucl_object_t *pc, double *bps, const char **list)
{
	const ucl_object_t	*v;
	const char		*s;
	char			*end;
	double			 d;

	if ((v = ucl_object_lookup_path(pc, "te-bandwidth.generic")) == NULL)
		return (0);
	if (ucl_object_type(v) != UCL_STRING ||
	    *(s = ucl_object_tostring(v)) == '\0')
		return (-1);
	if (strchr(s, ',') != NULL) {
		*list = s;
		return (0);
	}
	d = strtod(s, &end);
	if (*end != '\0' || !isfinite(d) || d < 0)
		return (-1);
	*bps = d * 8;
	return (0);
}

/* te-path-disjointness's bits of v (none: 0); -1 bad. */
static int
dis_of(const ucl_object_t *v)
{
	const char	*s;
	size_t		 n;
	int		 bits = 0;

	if (v == NULL)
		return (0);
	if (ucl_object_type(v) != UCL_STRING)
		return (-1);
	for (s = ucl_object_tostring(v); *(s += strspn(s, " ")) != '\0';
	    s += n) {
		n = strcspn(s, " ");
		if (n == 4 && strncmp(s, "node", 4) == 0)
			bits |= DIS_NODE;
		else if (n == 4 && strncmp(s, "link", 4) == 0)
			bits |= DIS_LINK;
		else if (n == 4 && strncmp(s, "srlg", 4) == 0)
			bits |= DIS_SRLG;
		else
			return (-1);
	}
	return (bits);
}

static const char *
dis_name(int bits, char *buf, size_t len)
{

	snprintf(buf, len, "%s%s%s%s%s", bits & DIS_NODE ? "node" : "",
	    (bits & DIS_NODE) && (bits & ~DIS_NODE) ? ", " : "",
	    bits & DIS_LINK ? "link" : "", (bits & DIS_LINK) &&
	    (bits & DIS_SRLG) ? ", " : "", bits & DIS_SRLG ? "SRLG" : "");
	return (buf);
}

/* What o (a member, or the input) asks into a; -1 bad. */
static int
ask_in(const ucl_object_t *o, struct ask *a)
{
	const ucl_object_t	*pc, *v;
	int64_t			 k;

	memset(a, 0, sizeof(*a));
	a->cos = -1;
	pc = ucl_object_lookup(o, "path-constraints");
	if ((a->nb = bounds_in(pc, a->b)) < 0 || bw_in(pc, &a->bw,
	    &a->bwlist) < 0 || (a->dis = dis_of(ucl_object_lookup(pc,
	    "disjointness"))) < 0)
		return (-1);
	if ((v = ucl_object_lookup(o, "cos")) != NULL) {
		if (ucl_object_type(v) != UCL_INT || (k = ucl_object_toint(v)) <
		    0 || k > 7)
			return (-1);
		a->cos = (int)k;
	}
	if ((v = ucl_object_lookup(o, "optimizations")) != NULL) {
		if (ucl_object_type(v) != UCL_OBJECT)
			return (-1);
		a->opt = v;
	}
	return (0);
}

/* What a leaves out, the input's (d). */
static void
ask_merge(struct ask *a, const struct ask *d)
{

	if (a->nb <= 0 && d->nb > 0) {
		memcpy(a->b, d->b, sizeof(*a->b) * (size_t)d->nb);
		a->nb = d->nb;
	}
	if (a->bw == 0 && a->bwlist == NULL) {
		a->bw = d->bw;
		a->bwlist = d->bwlist;
	}
	if (a->cos < 0)
		a->cos = d->cos;
	if (a->dis == 0)
		a->dis = d->dis;
	if (a->opt == NULL)
		a->opt = d->opt;
}

/*
 * Whether the plan's tunnel id carries bps at both ends: its UCS End
 * Point's bandwidth, and its edge's uplinks beyond what its policies
 * commit (4.5.6's sums, sdwan_plan_tunnels()).  1 it does, 0 not said,
 * -1 it does not, why appended.
 */
static int
bw_fits(struct vctx *x, const char *id, double bps, char *why, size_t len)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	int64_t			 bw, cap, com;
	size_t			 n;
	int			 k = 1;

	while ((e = ucl_object_iterate(ucl_object_lookup(entry(x->tunnels,
	    "id", id), "ends"), &it, true)) != NULL) {
		if (ucl_object_lookup(e, "bandwidth") == NULL ||
		    ucl_object_lookup(e, "capacity") == NULL) {
			k = MIN(k, 0);
			continue;
		}
		bw = ucl_object_toint(ucl_object_lookup(e, "bandwidth"));
		cap = ucl_object_toint(ucl_object_lookup(e, "capacity"));
		com = ucl_object_toint(ucl_object_lookup(e, "committed"));
		n = strlen(why);
		if (bw < bps)
			snprintf(why + n, len - n, "%s%s's UCS End Point %s "
			    "carries %jd bit/s", n > 0 ? "; " : "", ucl_str(e,
			    "name"), ucl_str(e, "ucs_ep"), (intmax_t)bw);
		else if (cap - com < bps)
			snprintf(why + n, len - n, "%s%s's uplinks carry %jd "
			    "bit/s, its policies commit %jd", n > 0 ? "; " : "",
			    ucl_str(e, "name"), (intmax_t)cap, (intmax_t)com);
		else
			continue;
		k = -1;
	}
	return (k);
}

/*
 * Whether the view's tunnels a and b are disjoint by bits, the
 * underlay as Arcana knows it: a link an edge's UCS End Point (its
 * uplink), an SRLG a UCS (one network, one risk), and a node of the
 * underlay a UCS's, none known by itself (two paths over one UCS may
 * share one); the edges at the ends are the paths' own.  Why not in
 * why (NULL: not said).
 */
static bool
tun_disjoint(const ucl_object_t *a, const ucl_object_t *b, int bits,
    char *why, size_t len)
{
	static const char *const ends[] = { "src", "dest" };
	const ucl_object_t	*ea, *eb;
	const char		*ua, *ub, *pa, *pb, *xa, *xb;

	ua = ucl_str(a, "ucs");
	ub = ucl_str(b, "ucs");
	if ((bits & (DIS_NODE | DIS_SRLG)) != 0 && (ua == NULL || ub ==
	    NULL || strcmp(ua, ub) == 0)) {
		if (why != NULL)
			snprintf(why, len, "%s and %s are both over UCS %s",
			    ucl_str(a, "id"), ucl_str(b, "id"), ua != NULL ?
			    ua : "unsaid");
		return (false);
	}
	if ((bits & DIS_LINK) == 0)
		return (true);
	for (int i = 0; i < 2; i++)
		for (int j = 0; j < 2; j++) {
			ea = ucl_object_lookup(a, ends[i]);
			eb = ucl_object_lookup(b, ends[j]);
			pa = ucl_str(ea, "ucs-end-point");
			pb = ucl_str(eb, "ucs-end-point");
			xa = ucl_str(ea, "edge");
			xb = ucl_str(eb, "edge");
			if (pa != NULL && pb != NULL && xa != NULL && xb !=
			    NULL && (strcmp(pa, pb) != 0 || strcmp(xa, xb) != 0))
				continue;
			if (why != NULL)
				snprintf(why, len, "%s and %s both go through "
				    "UCS End Point %s", ucl_str(a, "id"),
				    ucl_str(b, "id"), pa != NULL ? pa :
				    "unsaid");
			return (false);
		}
	return (true);
}

/*
 * Class-Type cos (RFC 4124) of service vid of L3NM y: its business
 * importance level at that place (MEF 70.2 §9.11), the first the
 * highest; without levels CT0 alone, every flow's.  Why not in why.
 */
static bool
cos_has(const ucl_object_t *y, const char *vid, int cos, char *why,
    size_t len)
{
	const ucl_object_t	*lv;
	size_t			 n;

	lv = ucl_object_lookup_path(entry(ucl_object_lookup_path(y,
	    "vpn-services.vpn-service"), "vpn-id", vid),
	    "arcana-l3nm:sdwan.importance.level");
	n = ucl_object_type(lv) == UCL_ARRAY ? ucl_array_size(lv) : lv !=
	    NULL ? 1 : 0;
	if (n == 0 ? cos == 0 : (size_t)cos < n)
		return (true);
	if (n == 0)
		snprintf(why, len, "service %s has no business importance "
		    "levels, one class (CT0): class-type %d is not one", vid,
		    cos);
	else
		snprintf(why, len, "service %s has %zu business importance "
		    "levels (CT0 to CT%zu): class-type %d is none of them", vid,
		    n, n - 1, cos);
	return (false);
}

/* What of optimizations o Arcana does not weigh, in buf; NULL: none. */
static const char *
opt_unknown(const ucl_object_t *o, char *buf, size_t len)
{
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it = NULL, mt;
	const char		*k, *leaf;
	double			 d;

	while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
		if (strcmp(ucl_object_key(v), "optimization-metric") != 0) {
			snprintf(buf, len, "%s, of the optimizations, is not "
			    "one Arcana computes", ucl_object_key(v));
			return (buf);
		}
		mt = NULL;
		while ((e = ucl_object_iterate(v, &mt, true)) != NULL) {
			k = ucl_str(e, "metric-type");
			if (k == NULL || !vn_bound_tca(k, 1, &leaf, &d)) {
				snprintf(buf, len, "an optimization by %s is "
				    "not one Arcana computes: the steering "
				    "weighs delay, delay variation and loss",
				    k != NULL ? k : "no metric");
				return (buf);
			}
			if (ucl_object_lookup(e,
			    "explicit-route-exclude-objects") != NULL ||
			    ucl_object_lookup(e,
			    "explicit-route-include-objects") != NULL) {
				snprintf(buf, len, "explicit route objects are "
				    "not computed: no TE topology is kept");
				return (buf);
			}
		}
	}
	return (NULL);
}

/*
 * Input member in computed against view top into res: its APs and
 * VNAPs known, a member of the view between them, the plan's tunnels
 * between their edges, and what it asks (its own, else the input's d)
 * met by one of them: the bounds as the steering at either end last
 * measured them, the bandwidth as the plan's uplinks carry it
 * (bw_fits()), the class among its service's (cos_has()), two of them
 * disjoint (tun_disjoint()); an optimization Arcana does not weigh
 * unknown, said.
 */
static void
compute_one(struct vctx *x, const ucl_object_t *y, const ucl_object_t *top,
    const ucl_object_t *in, const struct ask *d, struct mres *res)
{
	const ucl_object_t	*aps, *sap, *dap, *svn, *dvn, *vn, *mm, *t;
	ucl_object_iter_t	 it = NULL;
	struct ask		 a;
	ucl_object_t		*m;
	const char		*sa, *da, *vid, *tid;
	char			 why[1024], dn[32], ob[256];
	double			 got;
	size_t			 len;
	int			 ntun = 0, nfit = 0, st, k, best;

	res->m = m = ucl_object_typed_new(UCL_OBJECT);
	res->down = true;
	put_str(m, "id", ucl_str(in, "id"));
	sa = ucl_object_tostring(ucl_object_lookup_path(in, "src.ap"));
	da = ucl_object_tostring(ucl_object_lookup_path(in, "dest.ap"));
	aps = ucl_object_lookup_path(top, "ietf-vn:" VN_AP ".ap");
	sap = entry(aps, "id", sa);
	dap = entry(aps, "id", da);
	svn = vnap_of(sap, ucl_object_tostring(ucl_object_lookup_path(in,
	    "src.vn-ap-id")));
	dvn = vnap_of(dap, ucl_object_tostring(ucl_object_lookup_path(in,
	    "dest.vn-ap-id")));
	ucl_object_insert_key(m, end_out(sa, ucl_str(svn, "id")), "src", 0,
	    false);
	ucl_object_insert_key(m, end_out(da, ucl_str(dvn, "id")), "dest", 0,
	    false);
	if (sap == NULL || dap == NULL) {
		fail_info(m, "ietf-vn:vn-computation-ap-unknown", "no AP %s",
		    sap == NULL ? (sa != NULL ? sa : "as its source") :
		    (da != NULL ? da : "as its destination"));
		return;
	}
	if (svn == NULL || dvn == NULL) {
		fail_info(m, "ietf-vn:vn-computation-ap-unknown", "AP %s has "
		    "no such VNAP, or several: name one", svn == NULL ? sa :
		    da);
		return;
	}
	if ((vid = ucl_str(svn, "vn")) == NULL || ucl_str(dvn, "vn") == NULL ||
	    strcmp(vid, ucl_str(dvn, "vn")) != 0) {
		fail_info(m, "ietf-vn:vn-computation-error-path-not-found",
		    "%s and %s are of two VNs", ucl_str(svn, "id"),
		    ucl_str(dvn, "id"));
		return;
	}
	vn = entry(ucl_object_lookup_path(top, "ietf-vn:" VN_VN ".vn"), "id",
	    vid);
	if ((mm = member_between(vn, ucl_str(svn, "id"), ucl_str(dvn,
	    "id"))) == NULL) {
		fail_info(m, "ietf-vn:vn-computation-error-path-not-found",
		    "VN %s has no member between %s and %s: they are on one "
		    "node, or two spokes", vid, ucl_str(svn, "id"),
		    ucl_str(dvn, "id"));
		return;
	}
	(void)ask_in(in, &a);
	ask_merge(&a, d);
	for (int i = 0; i < a.nb; i++)
		if (a.b[i].leaf == NULL) {
			fail_info(m, NO_RESOURCE, "no edge measures %s",
			    a.b[i].metric);
			return;
		}
	if (a.bwlist != NULL) {
		fail_info(m, NO_RESOURCE, "te-bandwidth %s is a list, an OTN's "
		    "or a DWDM's: Arcana's underlay is a packet network's",
		    a.bwlist);
		return;
	}
	if (a.cos >= 0 && !cos_has(y, vid, a.cos, why, sizeof(why))) {
		fail_info(m, NO_RESOURCE, "%s", why);
		return;
	}
	why[0] = '\0';
	while ((t = ucl_object_iterate(ucl_object_lookup_path(mm,
	    "underlay.arcana-sdwan-underlay:sdwan.tunnel"), &it, true)) !=
	    NULL) {
		if ((tid = ucl_str(t, "id")) == NULL)
			continue;
		ntun++;
		st = 1;
		for (int i = 0; i < a.nb; i++) {
			got = NAN;
			sample_at(x, ucl_object_tostring(ucl_object_lookup_path(
			    t, "src.edge")), tid, a.b[i].leaf, &got);
			sample_at(x, ucl_object_tostring(ucl_object_lookup_path(
			    t, "dest.edge")), tid, a.b[i].leaf, &got);
			if (isnan(got))
				st = MIN(st, 0);
			else if (got > a.b[i].max) {
				len = strlen(why);
				snprintf(why + len, sizeof(why) - len, "%s%s's "
				    "%s %g over %g", len > 0 ? "; " : "", tid,
				    a.b[i].leaf, got, a.b[i].max);
				st = -1;
			}
		}
		if (st >= 0 && a.bw > 0 && (k = bw_fits(x, tid, a.bw, why,
		    sizeof(why))) < 1)
			st = MIN(st, k);
		nfit += st == 1;
		if (st >= 0 && res->ntun < TUN_MAX) {
			res->fit[res->ntun] = st == 1;
			res->tun[res->ntun++] = t;
		}
	}
	if (ntun == 0) {
		fail_info(m, "ietf-vn:vn-computation-error-path-not-found",
		    "the plan makes no tunnel between %s and %s", sa, da);
		return;
	}
	if (res->ntun == 0) {
		fail_info(m, NO_RESOURCE, "no tunnel meets what is asked: %s",
		    why);
		return;
	}
	/* Its own paths disjoint: a working one and one to protect it. */
	if (a.dis != 0) {
		best = -1;
		snprintf(why, sizeof(why), "one tunnel alone may carry it");
		for (int i = 0; i < res->ntun; i++)
			for (int j = i + 1; j < res->ntun; j++)
				if (tun_disjoint(res->tun[i], res->tun[j],
				    a.dis, why, sizeof(why)))
					best = MAX(best, res->fit[i] &&
					    res->fit[j] ? 1 : 0);
		if (best < 0) {
			fail_info(m, NO_RESOURCE, "no two of its tunnels are "
			    "%s-disjoint: %s", dis_name(a.dis, dn, sizeof(dn)),
			    why);
			return;
		}
		nfit = best;
	}
	res->down = false;
	if (a.opt != NULL && opt_unknown(a.opt, ob, sizeof(ob)) != NULL)
		info(m, "unknown", NULL, "%s", ob);
	else
		put_str(m, "compute-status", nfit > 0 ? "up" : "unknown");
}

/* Members who[i..n) given a tunnel each, by bits apart from pick's. */
static bool
assign(const struct mres *rs, const int *who, int n, int i,
    const ucl_object_t **pick, int bits, long *steps)
{
	const ucl_object_t	*t;
	int			 j;

	if (i == n)
		return (true);
	for (int k = 0; k < rs[who[i]].ntun; k++) {
		if (++*steps > DIV_STEPS)
			return (false);
		t = rs[who[i]].tun[k];
		for (j = 0; j < i; j++)
			if (!tun_disjoint(pick[j], t, bits, NULL, 0))
				break;
		if (j < i)
			continue;
		pick[i] = t;
		if (assign(rs, who, n, i + 1, pick, bits, steps))
			return (true);
	}
	return (false);
}

/*
 * vn-level-diversity (RFC 9731's vn-policy): the members not down
 * given one tunnel each, all of them disjoint by bits; else each down,
 * with another it shares something with on every choice, or none
 * there is.
 */
static void
diversity(struct mres *rs, size_t n, int bits)
{
	const ucl_object_t	*pick[DIV_MAX];
	const char		*other;
	char			 dn[32], why[400];
	long			 steps = 0;
	int			 who[DIV_MAX], nw = 0;
	bool			 apart;

	for (size_t i = 0; i < n; i++)
		if (!rs[i].down && nw < DIV_MAX)
			who[nw++] = (int)i;
	if (nw < 2 || assign(rs, who, nw, 0, pick, bits, &steps))
		return;
	dis_name(bits, dn, sizeof(dn));
	for (int i = 0; i < nw; i++) {
		if (steps > DIV_STEPS) {
			info(rs[who[i]].m, "unknown", NULL, "vn-level-"
			    "diversity %s: more choices of tunnels than are "
			    "tried", dn);
			continue;
		}
		other = NULL;
		for (int j = 0; other == NULL && j < nw; j++) {
			if (j == i)
				continue;
			apart = false;
			for (int k = 0; !apart && k < rs[who[i]].ntun; k++)
				for (int l = 0; !apart && l < rs[who[j]].ntun;
				    l++)
					apart = tun_disjoint(rs[who[i]].tun[k],
					    rs[who[j]].tun[l], bits, why,
					    sizeof(why));
			if (!apart)
				other = ucl_str(rs[who[j]].m, "id");
		}
		if (other != NULL)
			fail_info(rs[who[i]].m, NO_RESOURCE, "vn-level-"
			    "diversity %s: member %s and it are not, by any "
			    "tunnel of either: %s", dn, other, why);
		else
			fail_info(rs[who[i]].m, NO_RESOURCE, "vn-level-"
			    "diversity %s: no choice of tunnels keeps the %d "
			    "members apart", dn, nw);
	}
}

/*
 * /restconf/operations (RFC 8040 section 3.3.2): GET, the console's
 * operations; POST ietf-vn:vn-compute, each member of its input
 * computed against the VN view (vn_view()'s), nothing made.
 */
int
api_restconf_operations(struct http_request *req)
{
	struct ask		 d, ma;
	struct vctx		 x;
	struct mres		*rs;
	const ucl_object_t	*in, *e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*body, *y, *top, *list, *o;
	size_t			 n;
	int			 ok, vdis = 0;

	if (!guard(req, false))
		return (WEB_OK);
	if (strcmp(req->path, "/restconf/operations") == 0) {
		if (req->method != HTTP_METHOD_GET)
			return (restconf_error(req, 405, "the operations are "
			    "read"));
		list = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(list, ucl_object_typed_new(UCL_NULL));
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, list, "ietf-vn:vn-compute", 0, false);
		/* arcana-console's, routed before this (routes.c). */
		ucl_object_insert_key(o, ucl_object_copy(list),
		    "arcana-console:trace-path", 0, false);
		ucl_object_insert_key(o, ucl_object_copy(list),
		    "arcana-console:wireguard-keypair", 0, false);
		top = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(top, o, "ietf-restconf:operations", 0,
		    false);
		return (restconf_reply(req, top));
	}
	if (strcmp(req->path, "/restconf/operations/ietf-vn:vn-compute") != 0)
		return (restconf_error(req, 404, "no such operation"));
	if (req->method != HTTP_METHOD_POST)
		return (restconf_error(req, 405, "an operation is POSTed"));
	body = read_json(req);
	in = ucl_object_lookup(body, "ietf-vn:input");
	if (body == NULL || ucl_object_type(body) != UCL_OBJECT || in == NULL ||
	    ucl_object_type(in) != UCL_OBJECT) {
		ucl_object_unref(body);
		return (restconf_error_tag(req, 400, "malformed-message",
		    "the body is {\"ietf-vn:input\": {...}}"));
	}
	ok = ask_in(in, &d) == 0 && (vdis = dis_of(ucl_object_lookup(in,
	    "vn-level-diversity"))) >= 0;
	while (ok && (e = ucl_object_iterate(ucl_object_lookup(in,
	    "vn-member-list"), &it, true)) != NULL)
		ok = ucl_str(e, "id") != NULL && ask_in(e, &ma) == 0;
	if (!ok) {
		ucl_object_unref(body);
		return (restconf_error(req, 400, "each vn-member-list entry "
		    "has an id; each path-metric-bound a metric-type and an "
		    "upper-bound; te-bandwidth is a bandwidth, cos 0 to 7, "
		    "disjointness and vn-level-diversity of node, link and "
		    "srlg"));
	}
	y = l3nm_kept();
	top = view_make(req, y, &x);
	n = ucl_array_size(ucl_object_lookup(in, "vn-member-list"));
	rs = xcalloc(n > 0 ? n : 1, sizeof(*rs));
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "vn-member-list"),
	    &it, true)) != NULL)
		compute_one(&x, y, top, e, &d, &rs[n++]);
	if (vdis != 0)
		diversity(rs, n, vdis);
	list = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < n; i++)
		ucl_array_append(list, rs[i].m);
	free(rs);
	ucl_object_unref(top);
	ucl_object_unref(y);
	view_done(&x);
	ucl_object_unref(body);
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, list, "vn-member-list", 0, false);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, o, "ietf-vn:output", 0, false);
	return (restconf_reply(req, top));
}
