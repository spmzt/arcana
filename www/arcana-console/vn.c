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
 * between them), the plan's tunnels between its edges, and its bounds
 * (its own, else the input's) against what the steering at either end
 * last measured of them; infeasible, compute-status down with
 * error-info's reason and why; unmeasured, unknown.
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
	    host_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
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
view_make(const ucl_object_t *y, struct vctx *x)
{
	const ucl_object_t	*s, *e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*top, *aps, *vns, *arr, *o, *vn;

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
vn_view(const ucl_object_t *y)
{
	struct vctx	 x;
	ucl_object_t	*top;

	top = view_make(y, &x);
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
	view = vn_view(y);
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
	view = vn_view(y);
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

/* A bound of path-metric-bounds, as the TCA's leaf has it. */
struct bound {
	const char	*leaf;		/* delay, ipdv, loss; NULL: unmeasured */
	const char	*metric;
	double		 max;
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

static void	fail_info(ucl_object_t *, const char *, const char *, ...)
		    __printflike(3, 4);

/* Member m infeasible: compute-status down, error-info why. */
static void
fail_info(ucl_object_t *m, const char *reason, const char *fmt, ...)
{
	ucl_object_t	*ei;
	va_list		 ap;
	struct tm	 tm;
	time_t		 now;
	char		 why[512], ts[32];

	va_start(ap, fmt);
	vsnprintf(why, sizeof(why), fmt, ap);
	va_end(ap);
	now = time(NULL);
	gmtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
	ei = ucl_object_typed_new(UCL_OBJECT);
	put_str(ei, "error-description", why);
	put_str(ei, "error-timestamp", ts);
	put_str(ei, "error-reason", reason);
	put_str(m, "compute-status", "down");
	ucl_object_insert_key(m, ei, "error-info", 0, false);
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
 * Input member in computed against view top: its APs and VNAPs known,
 * a member of the view between them, the plan's tunnels between their
 * edges, and the bounds (its own, else the input's vb) met by one of
 * them as the steering at either end last measured it.
 */
static ucl_object_t *
compute_one(struct vctx *x, const ucl_object_t *top, const ucl_object_t *in,
    const struct bound *vb, int nvb)
{
	const ucl_object_t	*aps, *sap, *dap, *svn, *dvn, *vn, *mm, *t;
	ucl_object_iter_t	 it = NULL;
	struct bound		 b[BOUND_MAX];
	ucl_object_t		*m;
	const char		*sa, *da, *vid, *tid;
	char			 why[400];
	double			 got;
	size_t			 len;
	int			 nb, unmeasured = 0, ntun = 0;
	bool			 fits = false;

	m = ucl_object_typed_new(UCL_OBJECT);
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
		return (m);
	}
	if (svn == NULL || dvn == NULL) {
		fail_info(m, "ietf-vn:vn-computation-ap-unknown", "AP %s has "
		    "no such VNAP, or several: name one", svn == NULL ? sa :
		    da);
		return (m);
	}
	if ((vid = ucl_str(svn, "vn")) == NULL || ucl_str(dvn, "vn") == NULL ||
	    strcmp(vid, ucl_str(dvn, "vn")) != 0) {
		fail_info(m, "ietf-vn:vn-computation-error-path-not-found",
		    "%s and %s are of two VNs", ucl_str(svn, "id"),
		    ucl_str(dvn, "id"));
		return (m);
	}
	vn = entry(ucl_object_lookup_path(top, "ietf-vn:" VN_VN ".vn"), "id",
	    vid);
	if ((mm = member_between(vn, ucl_str(svn, "id"), ucl_str(dvn,
	    "id"))) == NULL) {
		fail_info(m, "ietf-vn:vn-computation-error-path-not-found",
		    "VN %s has no member between %s and %s: they are on one "
		    "node, or two spokes", vid, ucl_str(svn, "id"),
		    ucl_str(dvn, "id"));
		return (m);
	}
	if ((nb = bounds_in(ucl_object_lookup(in, "path-constraints"), b)) <=
	    0 && nvb > 0) {
		memcpy(b, vb, sizeof(*b) * (size_t)nvb);
		nb = nvb;
	}
	for (int i = 0; i < nb; i++)
		if (b[i].leaf == NULL) {
			fail_info(m, "ietf-vn:vn-computation-error-no-resource",
			    "no edge measures %s", b[i].metric);
			return (m);
		}
	why[0] = '\0';
	while (!fits && (t = ucl_object_iterate(ucl_object_lookup_path(mm,
	    "underlay.arcana-sdwan-underlay:sdwan.tunnel"), &it, true)) !=
	    NULL) {
		if ((tid = ucl_str(t, "id")) == NULL)
			continue;
		ntun++;
		fits = true;
		for (int i = 0; i < nb; i++) {
			got = NAN;
			sample_at(x, ucl_object_tostring(ucl_object_lookup_path(
			    t, "src.edge")), tid, b[i].leaf, &got);
			sample_at(x, ucl_object_tostring(ucl_object_lookup_path(
			    t, "dest.edge")), tid, b[i].leaf, &got);
			if (isnan(got)) {
				unmeasured++;
				fits = false;
				break;
			}
			if (got > b[i].max) {
				len = strlen(why);
				snprintf(why + len, sizeof(why) - len, "%s%s's "
				    "%s %g over %g", len > 0 ? "; " : "", tid,
				    b[i].leaf, got, b[i].max);
				fits = false;
			}
		}
	}
	if (ntun == 0)
		fail_info(m, "ietf-vn:vn-computation-error-path-not-found",
		    "the plan makes no tunnel between %s and %s", sa, da);
	else if (fits)
		put_str(m, "compute-status", "up");
	else if (unmeasured > 0)
		put_str(m, "compute-status", "unknown");
	else
		fail_info(m, "ietf-vn:vn-computation-error-no-resource",
		    "no tunnel within the bounds: %s", why);
	return (m);
}

/*
 * /restconf/operations (RFC 8040 section 3.3.2): GET, the console's
 * operations; POST ietf-vn:vn-compute, each member of its input
 * computed against the VN view (vn_view()'s), nothing made.
 */
int
api_restconf_operations(struct http_request *req)
{
	struct bound		 vb[BOUND_MAX], mb[BOUND_MAX];
	struct vctx		 x;
	const ucl_object_t	*in, *e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*body, *y, *top, *list, *o;
	int			 nvb;

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
	nvb = bounds_in(ucl_object_lookup(in, "path-constraints"), vb);
	while (nvb >= 0 && (e = ucl_object_iterate(ucl_object_lookup(in,
	    "vn-member-list"), &it, true)) != NULL)
		if (ucl_str(e, "id") == NULL || bounds_in(ucl_object_lookup(e,
		    "path-constraints"), mb) < 0)
			nvb = -1;
	if (nvb < 0) {
		ucl_object_unref(body);
		return (restconf_error(req, 400, "each vn-member-list entry "
		    "has an id; each path-metric-bound a metric-type and an "
		    "upper-bound"));
	}
	y = l3nm_kept();
	top = view_make(y, &x);
	ucl_object_unref(y);
	list = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "vn-member-list"),
	    &it, true)) != NULL)
		ucl_array_append(list, compute_one(&x, top, e, vb, nvb));
	ucl_object_unref(top);
	view_done(&x);
	ucl_object_unref(body);
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, list, "vn-member-list", 0, false);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, o, "ietf-vn:output", 0, false);
	return (restconf_reply(req, top));
}
