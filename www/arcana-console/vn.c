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
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
ucl_object_t *
vn_view(const ucl_object_t *y)
{
	const ucl_object_t	*s, *e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*top, *aps, *vns, *arr, *o, *vn;
	struct vctx		 x;

	x.tunnels = ucl_object_lookup_path(y, "vpn-services.vpn-service") !=
	    NULL ? sdwan_plan_tunnels(y) : NULL;
	x.steer = ucl_object_typed_new(UCL_OBJECT);
	top = ucl_object_typed_new(UCL_OBJECT);
	aps = ucl_object_typed_new(UCL_OBJECT);
	vns = ucl_object_typed_new(UCL_ARRAY);
	while ((s = ucl_object_iterate(ucl_object_lookup_path(y,
	    "vpn-services.vpn-service"), &it, true)) != NULL)
		if ((vn = vn_of(&x, s, aps)) != NULL)
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
	if (x.tunnels != NULL)
		ucl_object_unref(x.tunnels);
	ucl_object_unref(x.steer);
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
