/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: arcana-network, the network tables as FreeBSD's tools tell
 * them (network.c and those it calls, which write JSON), each a read
 * action of /network, the host's or a vnet jail's.  A leaf of the model
 * keeps the name the tool gives its value, so one reader makes any of
 * them typed: the JSON as a data tree of the action's output (cblink's
 * dtree), then its struct.  A member the model has no node for, or a
 * value not of its leaf's type, is left out: a tool that says more in
 * a later release breaks no read.
 */

#include <sys/param.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

#include <cblink.h>
#include <cbl_data.h>
#include <cbl_schema.h>

#include "agent.h"
#include "collect.h"
#include "yjson.h"

#define	DEPTH_MAX	16

/* What an action failed of, said for the request: cblink's error. */
static int
said(cbl_req *req, const char *why)
{

	(void)cbl_req_set_yerr(req, why != NULL ? why : "it failed", 0);
	return (EIO);
}

/* A data child of n by its name, a "module:" prefix taken off; NULL: none. */
static const struct cbl_ynode *
child(const struct cbl_ynode *n, const char *name)
{
	const char	*c;

	if ((c = strchr(name, ':')) != NULL)
		name = c + 1;
	for (uint32_t i = 0; i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	return (NULL);
}

const struct cbl_ynode *
ynet_node(const char *mod, const char *top, const char *path)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n = NULL;
	char				 buf[128], *p, *name;

	for (uint32_t i = 0; n == NULL && i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, mod) != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++)
			if (strcmp(m->top[k]->name, top) == 0)
				n = m->top[k];
	}
	if (n == NULL || path == NULL)
		return (n);
	(void)strlcpy(buf, path, sizeof(buf));
	for (p = buf; n != NULL && (name = strsep(&p, "/")) != NULL; )
		n = child(n, name);
	return (n);
}

/* v as the text of leaf sn's value, parsed into a's; NULL: not one. */
static void *
value(const struct cbl_ynode *sn, const ucl_object_t *v, cbl_yarena *a)
{
	const char	*s;
	char		 num[64], *text;
	void		*p;
	size_t		 len;

	switch (ucl_object_type(v)) {
	case UCL_STRING:
		s = ucl_object_tostring(v);
		break;
	case UCL_INT:
		(void)snprintf(num, sizeof(num), "%" PRId64,
		    (int64_t)ucl_object_toint(v));
		s = num;
		break;
	case UCL_FLOAT:
		if (sn->type->kind != CBL_YT_DECIMAL64)
			return (NULL);
		(void)snprintf(num, sizeof(num), "%.*f", sn->type->fdigits > 0 ?
		    sn->type->fdigits : 6, ucl_object_todouble(v));
		s = num;
		break;
	case UCL_BOOLEAN:
		s = ucl_object_toboolean(v) ? "true" : "false";
		break;
	default:
		return (NULL);
	}
	len = strlen(s) + 1;
	if ((text = cbl_yarena_alloc(a, len)) == NULL || (p =
	    cbl_yarena_alloc(a, sn->type->csize > 0 ? sn->type->csize : 1)) ==
	    NULL)
		return (NULL);
	memcpy(text, s, len);
	return (cbl_yvalue_parse(sn, sn->type, text, p, a) == 0 ? p : NULL);
}

static int	members(cbl_dnode *, const struct cbl_ynode *,
		    const ucl_object_t *, cbl_yarena *, int);

/* Node sn's value v under parent; what is no value of it, left out. */
static int
node(cbl_dnode *parent, const struct cbl_ynode *sn, const ucl_object_t *v,
    cbl_yarena *a, int depth)
{
	const ucl_object_t	*e, *k;
	ucl_object_iter_t	 it;
	const void		**keys;
	cbl_dnode		*made;
	void			*val;
	uint16_t		 i;
	int			 error;

	if (depth > DEPTH_MAX)
		return (0);
	switch (sn->kind) {
	case CBL_YN_CONTAINER:
		if (ucl_object_type(v) != UCL_OBJECT || cbl_dnode_add(parent,
		    sn, NULL, &made) != 0)
			return (0);
		return (members(made, sn, v, a, depth));
	case CBL_YN_LEAF:
		if ((val = value(sn, v, a)) != NULL)
			(void)cbl_dnode_add(parent, sn, val, NULL);
		return (0);
	case CBL_YN_LEAFLIST:
		it = NULL;
		while (ucl_object_type(v) == UCL_ARRAY && (e =
		    ucl_object_iterate(v, &it, true)) != NULL)
			if ((val = value(sn, e, a)) != NULL)
				(void)cbl_dnode_add(parent, sn, val, NULL);
		return (0);
	case CBL_YN_LIST:
		if (ucl_object_type(v) != UCL_ARRAY)
			return (0);
		if ((keys = cbl_yarena_alloc(a, (sn->nkeys + 1) *
		    sizeof(*keys))) == NULL)
			return (ENOMEM);
		it = NULL;
		while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
			if (ucl_object_type(e) != UCL_OBJECT)
				continue;
			for (i = 0; i < sn->nkeys; i++) {
				const struct cbl_ynode *kn =
				    sn->child[sn->keys[i]];

				if ((k = ucl_object_lookup(e, kn->name)) ==
				    NULL || (keys[i] = value(kn, k, a)) == NULL)
					break;
			}
			if (i < sn->nkeys || cbl_dnode_add_entry(parent, sn,
			    keys, &made) != 0)
				continue;
			if ((error = members(made, sn, e, a, depth)) != 0)
				return (error);
		}
		return (0);
	default:
		return (0);
	}
}

/* The members of object v, children of made (sn's): a list's keys are
 * its entry's already. */
static int
members(cbl_dnode *made, const struct cbl_ynode *sn, const ucl_object_t *v,
    cbl_yarena *a, int depth)
{
	const struct cbl_ynode	*c;
	const ucl_object_t	*m;
	ucl_object_iter_t	 it;
	int			 error;

	it = NULL;
	while ((m = ucl_object_iterate(v, &it, true)) != NULL) {
		if ((c = child(sn, ucl_object_key(m))) == NULL ||
		    (sn->kind == CBL_YN_LIST &&
		    (c->flags & CBL_YNF_KEY) != 0))
			continue;
		if ((error = node(made, c, m, a, depth + 1)) != 0)
			return (error);
	}
	return (0);
}

static void
tree_free(void *t)
{

	cbl_dtree_free(t);
}

int
ynet_decode(const struct cbl_ynode *on, const ucl_object_t *v, void *out,
    cbl_yarena *a)
{
	cbl_dtree	*t;
	cbl_dnode	*made;
	void		*zero;
	int		 error;

	if (on == NULL)
		return (ENOENT);
	if ((t = cbl_dtree_new(&ymodel_schema)) == NULL)
		return (ENOMEM);
	/* Its struct points into the tree: the tree goes with the answer. */
	if (cbl_yarena_atfree(a, tree_free, t) != 0) {
		cbl_dtree_free(t);
		return (ENOMEM);
	}
	/* The nodes above it first: an output's action and its container. */
	{
		const struct cbl_ynode	*up[DEPTH_MAX];
		cbl_dnode		*at;
		int			 nup = 0;

		for (const struct cbl_ynode *x = on->parent; x != NULL &&
		    nup < DEPTH_MAX; x = x->parent)
			up[nup++] = x;
		at = cbl_dtree_root(t);
		while (nup > 0)
			if ((error = cbl_dnode_add(at, up[--nup], NULL, &at)) !=
			    0)
				return (error);
		if ((zero = cbl_yarena_alloc(a, on->size > 0 ? on->size :
		    1)) == NULL)
			return (ENOMEM);
		memset(zero, 0, on->size > 0 ? on->size : 1);
		if ((error = cbl_dnode_from_struct(at, on, zero, &made)) != 0)
			return (error);
	}
	if (ucl_object_type(v) == UCL_OBJECT && (error = members(made, on, v,
	    a, 0)) != 0)
		return (error);
	return (cbl_dnode_to_struct(made, out, a));
}

/* ---- the actions --------------------------------------------------- */

static uint8_t
family_of(bool has, int family)
{

	return (!has ? ARC_NET_FAMILY_ALL : family == 1 ? ARC_NET_FAMILY_INET :
	    family == 2 ? ARC_NET_FAMILY_INET6 : ARC_NET_FAMILY_ALL);
}

/* A member of top as one of o's, kept. */
static void
take(ucl_object_t *o, const char *key, const ucl_object_t *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_ref(v), key, 0, true);
}

/*
 * An object map (an ipsec model's children) made the list the model
 * has: each value with its key as its name.
 */
static ucl_object_t *
map_list(const ucl_object_t *map)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr, *c;

	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(map, &it, true)) != NULL) {
		if (ucl_object_type(e) != UCL_OBJECT)
			continue;
		c = ucl_object_copy(e);
		ucl_object_replace_key(c, ucl_object_fromstring(
		    ucl_object_key(e)), "name", 0, true);
		ucl_array_append(arr, c);
	}
	return (arr);
}

/* The tool's document as the action's output has it. */
static ucl_object_t *
unwrap(uint8_t kind, ucl_object_t *top, const struct net_rsp *r)
{
	const ucl_object_t	*info, *c;
	ucl_object_iter_t	 it;
	ucl_object_t		*o, *m;

	o = ucl_object_typed_new(UCL_OBJECT);
	switch (kind) {
	case ARC_NET_KIND_ROUTES:
		take(o, "rt-family", ucl_object_lookup_path(top,
		    "statistics.route-information.route-table.rt-family"));
		if (r->has_total)
			ucl_object_insert_key(o, ucl_object_fromint(
			    (int64_t)r->total), "total", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(r->truncated),
		    "truncated", 0, false);
		break;
	case ARC_NET_KIND_NEXTHOPS:
	case ARC_NET_KIND_NHGROUPS:
		info = ucl_object_lookup_path(top, kind ==
		    ARC_NET_KIND_NEXTHOPS ? "statistics.route-nhop-information" :
		    "statistics.route-nhgrp-information");
		take(o, "rt-family", ucl_object_lookup_path(info, kind ==
		    ARC_NET_KIND_NEXTHOPS ? "nhop-table.rt-family" :
		    "nhgrp-table.rt-family"));
		take(o, "fib", ucl_object_lookup(info, "fib"));
		break;
	case ARC_NET_KIND_CONNECTIONS:
		take(o, "socket", ucl_object_lookup_path(top,
		    "statistics.socket"));
		break;
	case ARC_NET_KIND_SOCKETS:
		take(o, "socket", ucl_object_lookup_path(top, "sockstat.socket"));
		break;
	case ARC_NET_KIND_IPSEC:
		/* What Arcana wrote keeps its children by name: a list. */
		it = NULL;
		while ((c = ucl_object_iterate(ucl_object_lookup(top,
		    "connections"), &it, true)) != NULL)
			if ((m = (ucl_object_t *)(uintptr_t)ucl_object_lookup(c,
			    "model")) != NULL && ucl_object_type(
			    ucl_object_lookup(m, "children")) == UCL_OBJECT)
				ucl_object_replace_key(m, map_list(
				    ucl_object_lookup(m, "children")),
				    "children", 0, true);
		/* FALLTHROUGH */
	default:
		ucl_object_unref(o);
		return (ucl_object_ref(top));
	}
	return (o);
}

/*
 * Action act's kind, read by network.c where the input says: its JSON
 * made act's output (out, a's).
 */
static int
net_read(cbl_req *req, const char *act, const char *what, const char *jail,
    uint8_t kind, uint8_t family, const char *filter, uint32_t fib,
    uint32_t offset, void *out, cbl_yarena *a)
{
	struct net_rsp	 r;
	struct work	*w;
	ucl_object_t	*top, *o;
	const char	*e;
	int		 error, root;

	if ((w = ywork_told(req, a, what, &root)) == NULL)
		return (ENOMEM);
	if (jail != NULL && jail[0] != '\0') {
		e = NULL;
		if (!valid_jail(jail))
			e = "invalid jail name";
		else if (scope_enter(w, jail, &e) != 0 && e == NULL)
			e = "the jail is not there";
		if (e != NULL) {
			step_end(w, root, false, NULL);
			return (said(req, e));
		}
	}
	memset(&r, 0, sizeof(r));
	(void)do_network(w, kind, family, filter, fib, offset, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	if ((top = yj_parse(r.json)) == NULL)
		return (said(req, "the table is not JSON"));
	o = unwrap(kind, top, &r);
	error = ynet_decode(ynet_node("arcana-network", "network", wfmt(w,
	    "%s/output", act)), o, out, a);
	ucl_object_unref(o);
	ucl_object_unref(top);
	return (error);
}

int
arcana_network_network_get(cbl_req *req, struct arcana_network *data,
    cbl_yarena *a)
{

	/* Its tables are its actions': nothing to read whole. */
	(void)req;
	(void)data;
	(void)a;
	return (0);
}

int
arcana_network_network_routes_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_routes_input *in,
    struct arcana_network_network_routes_output *out, cbl_yarena *a)
{

	(void)target;
	if (in->filter != NULL && strlen(in->filter) > 128)
		return (said(req, "the text to search for is at most 128 "
		    "bytes"));
	return (net_read(req, "routes", "the routes", in->jail,
	    ARC_NET_KIND_ROUTES, family_of(in->has_family, in->family),
	    in->filter, in->has_fib ? in->fib : 0, in->has_offset ?
	    in->offset : 0, out, a));
}

int
arcana_network_network_nexthops_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_nexthops_input *in,
    struct arcana_network_network_nexthops_output *out, cbl_yarena *a)
{

	(void)target;
	return (net_read(req, "nexthops", "the nexthops", in->jail,
	    ARC_NET_KIND_NEXTHOPS, family_of(in->has_family, in->family), NULL,
	    in->has_fib ? in->fib : 0, 0, out, a));
}

int
arcana_network_network_nhgroups_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_nhgroups_input *in,
    struct arcana_network_network_nhgroups_output *out, cbl_yarena *a)
{

	(void)target;
	return (net_read(req, "nhgroups", "the nexthop groups", in->jail,
	    ARC_NET_KIND_NHGROUPS, family_of(in->has_family, in->family), NULL,
	    in->has_fib ? in->fib : 0, 0, out, a));
}

int
arcana_network_network_connections_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_connections_input *in,
    struct arcana_network_network_connections_output *out, cbl_yarena *a)
{

	(void)target;
	return (net_read(req, "connections", "the connections", in->jail,
	    ARC_NET_KIND_CONNECTIONS, family_of(in->has_family, in->family),
	    NULL, 0, 0, out, a));
}

int
arcana_network_network_sockets_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_sockets_input *in,
    struct arcana_network_network_sockets_output *out, cbl_yarena *a)
{

	(void)target;
	return (net_read(req, "sockets", "the sockets", in->jail,
	    ARC_NET_KIND_SOCKETS, family_of(in->has_family, in->family), NULL,
	    0, 0, out, a));
}

int
arcana_network_network_interfaces_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_interfaces_input *in,
    struct arcana_network_network_interfaces_output *out, cbl_yarena *a)
{

	(void)target;
	return (net_read(req, "interfaces", "the interfaces", in->jail,
	    ARC_NET_KIND_INTERFACES, family_of(in->has_family, in->family),
	    NULL, 0, 0, out, a));
}

int
arcana_network_network_bridges_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_bridges_input *in,
    struct arcana_network_network_bridges_output *out, cbl_yarena *a)
{

	(void)target;
	return (net_read(req, "bridges", "the bridges", in->jail,
	    ARC_NET_KIND_BRIDGES, ARC_NET_FAMILY_ALL, NULL, 0, 0, out, a));
}

int
arcana_network_network_geneve_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_geneve_input *in,
    struct arcana_network_network_geneve_output *out, cbl_yarena *a)
{

	(void)target;
	return (net_read(req, "geneve", "the geneve tunnels", in->jail,
	    ARC_NET_KIND_GENEVE, ARC_NET_FAMILY_ALL, NULL, 0, 0, out, a));
}

int
arcana_network_network_neighbours_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_neighbours_input *in,
    struct arcana_network_network_neighbours_output *out, cbl_yarena *a)
{

	(void)target;
	if (in->filter != NULL && strlen(in->filter) > 128)
		return (said(req, "the text to search for is at most 128 "
		    "bytes"));
	return (net_read(req, "neighbours", "the neighbours", in->jail,
	    ARC_NET_KIND_NEIGHBOURS, family_of(in->has_family, in->family),
	    in->filter, 0, 0, out, a));
}

int
arcana_network_network_multicast_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_multicast_input *in,
    struct arcana_network_network_multicast_output *out, cbl_yarena *a)
{

	(void)target;
	return (net_read(req, "multicast", "IGMP and MLD", in->jail,
	    ARC_NET_KIND_MULTICAST, ARC_NET_FAMILY_ALL, NULL, 0, 0, out, a));
}

int
arcana_network_network_kept_routes_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_kept_routes_input *in,
    struct arcana_network_network_kept_routes_output *out, cbl_yarena *a)
{

	(void)target;
	return (net_read(req, "kept-routes", "the kept routes", in->jail,
	    ARC_NET_KIND_KEPT_ROUTES, ARC_NET_FAMILY_ALL, NULL, 0, 0, out, a));
}

int
arcana_network_network_ipsec_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_ipsec_input *in,
    struct arcana_network_network_ipsec_output *out, cbl_yarena *a)
{

	(void)target;
	return (net_read(req, "ipsec", "IPsec", in->jail, ARC_NET_KIND_IPSEC,
	    ARC_NET_FAMILY_ALL, NULL, 0, 0, out, a));
}

/*
 * A vnet jail's firewall, as arcana-firewall's has it: read in the jail,
 * its struct written as JSON and made the output's (the one grouping).
 */
int
arcana_network_network_ipfw_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_ipfw_input *in,
    struct arcana_network_network_ipfw_output *out, cbl_yarena *a)
{
	struct arcana_firewall_firewall	*f;
	struct cbl_ybuf			 b = { NULL, 0, 0 };
	struct ucl_parser		*p;
	ucl_object_t			*o, *top;
	struct work			*w;
	const char			*e;
	int				 error, root;

	(void)target;
	if ((w = ywork_told(req, a, "the firewall", &root)) == NULL)
		return (ENOMEM);
	e = NULL;
	if (in->jail != NULL && in->jail[0] != '\0' && (!valid_jail(in->jail) ||
	    scope_enter(w, in->jail, &e) != 0)) {
		step_end(w, root, false, NULL);
		return (said(req, e != NULL ? e : "invalid jail name"));
	}
	error = yfw_read(w, a, &f, &e);
	step_end(w, root, error == 0, NULL);
	if (error != 0)
		return (error == EIO ? said(req, e) : error);
	if ((error = cbl_yjson(ynet_node("arcana-firewall", "firewall", NULL),
	    f, &b)) != 0) {
		cbl_ybuf_free(&b);
		return (error);
	}
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_chunk(p, b.p, b.len) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	cbl_ybuf_free(&b);
	if (o == NULL)
		return (said(req, "the firewall could not be written"));
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, o, "firewall", 0, false);
	error = ynet_decode(ynet_node("arcana-network", "network",
	    "ipfw/output"), top, out, a);
	ucl_object_unref(top);
	return (error);
}

/* The route to an address, and those that cover it. */
int
arcana_network_network_lookup_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_network_network_lookup_input *in,
    struct arcana_network_network_lookup_output *out, cbl_yarena *a)
{
	struct json_rsp	 r;
	struct work	*w;
	ucl_object_t	*top;
	const char	*e;
	int		 error, root;

	(void)target;
	if (in->address == NULL || in->address[0] == '-' ||
	    strlen(in->address) > 64)
		return (said(req, "an address to look up is needed"));
	if ((w = ywork_told(req, a, "the route to an address", &root)) ==
	    NULL)
		return (ENOMEM);
	if (in->jail != NULL && in->jail[0] != '\0') {
		e = NULL;
		if (!valid_jail(in->jail))
			e = "invalid jail name";
		else if (scope_enter(w, in->jail, &e) != 0 && e == NULL)
			e = "the jail is not there";
		if (e != NULL) {
			step_end(w, root, false, NULL);
			return (said(req, e));
		}
	}
	memset(&r, 0, sizeof(r));
	(void)do_route_lookup(w, in->address, in->has_fib ? in->fib : 0, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	if ((top = yj_parse(r.json)) == NULL)
		return (said(req, "the route is not JSON"));
	error = ynet_decode(ynet_node("arcana-network", "network",
	    "lookup/output"), top, out, a);
	ucl_object_unref(top);
	return (error);
}
