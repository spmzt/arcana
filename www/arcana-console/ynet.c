/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The network operation's kinds, route-lookup, address and ipfw-rules
 * through their modules (PLAN-SDN-YANG 3.8): arcana-network's read
 * actions, whose leaves keep the names FreeBSD's tools give their
 * values, so that one reader makes any of them the JSON the operation
 * gave: the output as RFC 7951's JSON (cbl_yjson()), its 64-bit numbers
 * numbers again, its empty lists there, the tool's wrapping put back.
 * The ipfw kind is arcana-firewall's state, the kept rules its kept
 * container, written by a commit.  The pages keep reading what they
 * read.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include <openssl/evp.h>

#include <arcana.h>

#include "ymodel.h"
#include "yqueue.h"
#include "ytrans.h"
#include "ynet.h"

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_replace_key(o, v, key, 0, true);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		put(o, key, ucl_object_fromstring(v));
}

/* A data child of n by its name, a "module:" prefix taken off. */
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

/* A leaf's RFC 7951 value as plain JSON: 64-bit numbers numbers. */
static ucl_object_t *
plain_value(const struct cbl_ynode *sn, const ucl_object_t *v)
{
	const char	*s;

	if (ucl_object_type(v) == UCL_STRING && sn->type != NULL) {
		s = ucl_object_tostring(v);
		switch (sn->type->kind) {
		case CBL_YT_INT64:
			return (ucl_object_fromint(strtoll(s, NULL, 10)));
		case CBL_YT_UINT64:
			return (ucl_object_fromint((int64_t)strtoull(s, NULL,
			    10)));
		case CBL_YT_DECIMAL64:
			return (ucl_object_fromdouble(strtod(s, NULL)));
		default:
			break;
		}
	}
	if (ucl_object_type(v) == UCL_ARRAY && sn->type != NULL &&
	    sn->type->kind == CBL_YT_EMPTY)
		return (ucl_object_frombool(true));
	return (ucl_object_copy(v));
}

/*
 * Object o of node sn's children, made plain: each member as its node
 * has it, the names without a prefix, and each list and leaf-list that
 * has no entry there as an empty array, as the tools wrote them.
 */
static ucl_object_t *
plain(const struct cbl_ynode *sn, const ucl_object_t *o)
{
	const struct cbl_ynode	*c;
	const ucl_object_t	*m, *e;
	ucl_object_iter_t	 it, eit;
	ucl_object_t		*out, *arr;
	const char		*key, *col;

	out = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while ((m = ucl_object_iterate(o, &it, true)) != NULL) {
		key = ucl_object_key(m);
		if ((col = strchr(key, ':')) != NULL)
			key = col + 1;
		if ((c = child(sn, key)) == NULL)
			continue;
		switch (c->kind) {
		case CBL_YN_CONTAINER:
			put(out, key, plain(c, m));
			break;
		case CBL_YN_LIST:
			arr = ucl_object_typed_new(UCL_ARRAY);
			eit = NULL;
			while ((e = ucl_object_iterate(m, &eit, true)) != NULL)
				ucl_array_append(arr, plain(c, e));
			put(out, key, arr);
			break;
		case CBL_YN_LEAFLIST:
			arr = ucl_object_typed_new(UCL_ARRAY);
			eit = NULL;
			while ((e = ucl_object_iterate(m, &eit, true)) != NULL)
				ucl_array_append(arr, plain_value(c, e));
			put(out, key, arr);
			break;
		default:
			put(out, key, plain_value(c, m));
			break;
		}
	}
	for (uint32_t i = 0; i < sn->nchild; i++) {
		c = sn->child[i];
		if ((c->kind == CBL_YN_LIST || c->kind == CBL_YN_LEAFLIST) &&
		    ucl_object_lookup(out, c->name) == NULL)
			put(out, c->name, ucl_object_typed_new(UCL_ARRAY));
	}
	return (out);
}

/* Struct p of node n as plain JSON; NULL: no memory. */
static ucl_object_t *
as_json(const struct cbl_ynode *n, const void *p)
{
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	struct ucl_parser	*pr;
	ucl_object_t		*o, *out;

	if (cbl_yjson(n, p, &b) != 0) {
		cbl_ybuf_free(&b);
		return (NULL);
	}
	pr = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_chunk(pr, b.p, b.len))
		o = ucl_parser_get_object(pr);
	ucl_parser_free(pr);
	cbl_ybuf_free(&b);
	out = plain(n, o != NULL ? o : ucl_object_typed_new(UCL_OBJECT));
	if (o != NULL)
		ucl_object_unref(o);
	return (out);
}

ucl_object_t *
ynet_part_json(const struct arcana_network_network_part *p)
{
	const struct cbl_ynode	*n;

	if ((n = yq_top("arcana-network", "network-part")) == NULL)
		return (NULL);
	return (as_json(n, p));
}

/* Action act of /network, given in: its output as plain JSON. */
static int
net_call(cbl_conn *conn, const char *act, const void *in, ucl_object_t **outp,
    char *err, size_t errlen)
{
	const struct cbl_ynode	*n, *an, *on;
	cbl_yarena		*a;
	void			*out;
	int			 error;

	*outp = NULL;
	if ((n = yq_top("arcana-network", "network")) == NULL || (an =
	    yq_child(n, act)) == NULL || (on = yq_child(an, "output")) ==
	    NULL) {
		snprintf(err, errlen, "arcana-network has no %s", act);
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL || (out = cbl_yarena_alloc(a,
	    on->size > 0 ? on->size : 1)) == NULL) {
		cbl_yarena_free(a);
		return (ENOMEM);
	}
	memset(out, 0, on->size > 0 ? on->size : 1);
	if ((error = yq_call(conn, n, NULL, an, in, out, a, err, errlen)) ==
	    0 && (*outp = as_json(on, out)) == NULL)
		error = ENOMEM;
	cbl_yarena_free(a);
	return (error);
}

/* The jail an input names: none for the host. */
static const char *
jail_in(const char *jail)
{

	return (jail != NULL && jail[0] != '\0' ? jail : NULL);
}

/* {k1: {k2: ... {last: v}}}, v the object's. */
static ucl_object_t *
wrap(ucl_object_t *v, int n, ...)
{
	const char	*keys[6];
	ucl_object_t	*o;
	va_list		 ap;

	va_start(ap, n);
	for (int i = 0; i < n && i < 6; i++)
		keys[i] = va_arg(ap, const char *);
	va_end(ap);
	for (int i = MIN(n, 6) - 1; i >= 0; i--) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, keys[i], v);
		v = o;
	}
	return (v);
}

/* A member of o, taken out of it (an empty array where none). */
static ucl_object_t *
take(ucl_object_t *o, const char *key)
{
	ucl_object_t	*v;

	if ((v = ucl_object_pop_key(o, key)) == NULL)
		v = ucl_object_typed_new(UCL_ARRAY);
	return (v);
}

/* An ipsec model's children, a list here, as the map it is there. */
static void
ipsec_models(ucl_object_t *top)
{
	const ucl_object_t	*c, *e;
	ucl_object_iter_t	 it, eit;
	ucl_object_t		*m, *map, *kid;
	const char		*name;

	it = NULL;
	while ((c = ucl_object_iterate(ucl_object_lookup(top, "connections"),
	    &it, true)) != NULL) {
		if ((m = (ucl_object_t *)(uintptr_t)ucl_object_lookup(c,
		    "model")) == NULL)
			continue;
		map = ucl_object_typed_new(UCL_OBJECT);
		eit = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(m, "children"),
		    &eit, true)) != NULL) {
			if ((name = ucl_object_tostring(ucl_object_lookup(e,
			    "name"))) == NULL)
				continue;
			kid = ucl_object_copy(e);
			(void)ucl_object_delete_key(kid, "name");
			put(map, name, kid);
		}
		put(m, "children", map);
	}
}

/* ---- the ipfw kind: arcana-firewall's ------------------------------ */

/* Member from of src as to of dst, when it is there. */
static void
cp(ucl_object_t *dst, const char *to, const ucl_object_t *src,
    const char *from)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(src, from)) != NULL)
		put(dst, to, ucl_object_copy(v));
}

/* Each entry of list from of src, its members renamed by map (pairs of
 * the model's name and the operation's, NULL ended), as array to. */
static void
cp_list(ucl_object_t *dst, const char *to, const ucl_object_t *src,
    const char *from, const char *const *map)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr, *o, *m;

	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(src, from), &it,
	    true)) != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		for (size_t i = 0; map[i] != NULL; i += 2) {
			if (strcmp(map[i], "mask") == 0 &&
			    ucl_object_lookup(e, "mask") != NULL) {
				m = ucl_object_typed_new(UCL_OBJECT);
				cp(m, "src", ucl_object_lookup(e, "mask"), "src");
				cp(m, "dst", ucl_object_lookup(e, "mask"), "dst");
				cp(m, "src_port", ucl_object_lookup(e, "mask"),
				    "src-port");
				cp(m, "dst_port", ucl_object_lookup(e, "mask"),
				    "dst-port");
				cp(m, "proto", ucl_object_lookup(e, "mask"),
				    "proto");
				put(o, "mask", m);
				continue;
			}
			/* An empty leaf of a list is no member: disabled is
			 * there only when true. */
			if (strcmp(map[i], "disabled") == 0 &&
			    !ucl_object_toboolean(ucl_object_lookup(e,
			    "disabled")))
				continue;
			cp(o, map[i + 1], e, map[i]);
		}
		ucl_array_append(arr, o);
	}
	put(dst, to, arr);
}

/*
 * A firewall as arcana-firewall's has it (plain JSON of the model) made
 * what the operation's ipfw kind gave (the agent's ipfw.c, do_ipfw()).
 */
static ucl_object_t *
fw_json(const ucl_object_t *f)
{
	static const char *const rules[] = { "number", "num", "packets",
	    "pkts", "octets", "bytes", "set", "set", "text", "text",
	    "disabled", "disabled", NULL };
	static const char *const dyn[] = { "number", "num", "packets",
	    "pkts", "octets", "bytes", "ttl", "ttl", "kind", "kind", "flow",
	    "flow", NULL };
	static const char *const tables[] = { "name", "name", "set", "set",
	    "type", "type", "entry", "entries", "count", "count", NULL };
	static const char *const tunables[] = { "name", "name", "value",
	    "value", "want", "want", "needed", "needed", "why", "why", NULL };
	static const char *const pipes[] = { "number", "num", "bandwidth",
	    "bw", "delay", "delay", "burst", "burst", "mask", "mask", "slots",
	    "slots", "bytes", "bytes", "plr", "plr", "red", "red", NULL };
	static const char *const scheds[] = { "number", "num", "bandwidth",
	    "bw", "delay", "delay", "burst", "burst", "mask", "mask", "type",
	    "type", "queue", "queues", "params", "params", NULL };
	static const char *const queues[] = { "number", "num", "sched",
	    "sched", "weight", "weight", "priority", "pri", "mask", "mask",
	    "slots", "slots", "bytes", "bytes", "plr", "plr", "red", "red",
	    NULL };
	static const char *const aliases[] = { "name", "name", "kind",
	    "kind", "value", "value", NULL };
	static const char *const kept[] = { "number", "num", "text", "text",
	    "source", "source", "norm", "norm", NULL };
	const ucl_object_t	*st, *k, *rc, *dn, *mo;
	ucl_object_t		*top, *q, *r;

	st = ucl_object_lookup(f, "state");
	k = ucl_object_lookup(f, "kept");
	rc = ucl_object_lookup(f, "rc");
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "loaded", ucl_object_frombool(ucl_object_toboolean(
	    ucl_object_lookup(st, "loaded"))));
	put(top, "enabled", ucl_object_frombool(ucl_object_toboolean(
	    ucl_object_lookup(st, "enabled"))));
	cp(top, "verbose", st, "verbose");
	cp_list(top, "rules", st, "rule", rules);
	cp(top, "dynamic_total", st, "dynamic-total");
	cp_list(top, "dynamic", st, "dynamic", dyn);
	cp_list(top, "tables", st, "table", tables);
	put(top, "nat", ucl_object_lookup(st, "nat") != NULL ?
	    ucl_object_copy(ucl_object_lookup(st, "nat")) :
	    ucl_object_typed_new(UCL_ARRAY));
	put(top, "pipes", ucl_object_lookup(st, "pipes") != NULL ?
	    ucl_object_copy(ucl_object_lookup(st, "pipes")) :
	    ucl_object_typed_new(UCL_ARRAY));
	if ((dn = ucl_object_lookup(st, "dummynet")) != NULL) {
		q = ucl_object_typed_new(UCL_OBJECT);
		cp_list(q, "pipes", dn, "pipe", pipes);
		cp_list(q, "scheds", dn, "sched", scheds);
		cp_list(q, "queues", dn, "queue", queues);
		put(top, "qos", q);
	}
	/* What Apply needs of the kernel, and the objects' modules: told
	 * with ipfw loaded. */
	if (ucl_object_lookup(st, "tunable") != NULL)
		cp_list(top, "tunables", st, "tunable", tunables);
	if ((mo = ucl_object_lookup(st, "modules")) != NULL) {
		q = ucl_object_typed_new(UCL_OBJECT);
		cp(q, "ipfw_nat", mo, "ipfw-nat");
		cp(q, "ipfw_nat64", mo, "ipfw-nat64");
		cp(q, "ipfw_nptv6", mo, "ipfw-nptv6");
		cp(q, "dummynet", mo, "dummynet");
		put(top, "modules", q);
	}
	cp_list(top, "aliases", k, "alias", aliases);
	cp_list(top, "kept", k, "rule", kept);
	put(top, "other", ucl_object_lookup(k, "other") != NULL ?
	    ucl_object_copy(ucl_object_lookup(k, "other")) :
	    ucl_object_typed_new(UCL_ARRAY));
	put(top, "file", ucl_object_frombool(ucl_object_toboolean(
	    ucl_object_lookup(k, "present"))));
	cp(top, "path", k, "path");
	r = ucl_object_typed_new(UCL_OBJECT);
	cp(r, "firewall_enable", rc, "firewall-enable");
	cp(r, "firewall_type", rc, "firewall-type");
	cp(r, "firewall_script", rc, "firewall-script");
	put(top, "rc", r);
	return (top);
}

/* The host's firewall (arcana-firewall's), or a vnet jail's (by
 * arcana-network's ipfw action), as the ipfw kind had it. */
static int
ipfw_kind(cbl_conn *conn, const char *jail, ucl_object_t **data, char *err,
    size_t errlen)
{
	struct arcana_network_network_ipfw_input	 in;
	const struct cbl_ynode				*n;
	struct arcana_firewall				 d;
	cbl_yarena					*a;
	ucl_object_t					*o;
	int						 error;

	if (jail != NULL) {
		memset(&in, 0, sizeof(in));
		in.jail = jail;
		if ((error = net_call(conn, "ipfw", &in, &o, err, errlen)) != 0)
			return (error);
		*data = fw_json(ucl_object_lookup(o, "firewall"));
		ucl_object_unref(o);
		return (0);
	}
	if ((n = yq_top("arcana-firewall", "firewall")) == NULL) {
		snprintf(err, errlen, "arcana-firewall is not in the tables");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&d, 0, sizeof(d));
	if ((error = yq_get(conn, n, CBL_YDS_OPERATIONAL, &d, a, err,
	    errlen)) == 0) {
		if (d.firewall == NULL || (o = as_json(n, d.firewall)) ==
		    NULL) {
			snprintf(err, errlen, "the host told of no firewall");
			error = ENOENT;
		} else {
			*data = fw_json(o);
			ucl_object_unref(o);
		}
	}
	cbl_yarena_free(a);
	return (error);
}

/* ---- the kinds ----------------------------------------------------- */

bool
ynet_kind(int kind)
{

	switch (kind) {
	case ARC_NET_KIND_ROUTES:
	case ARC_NET_KIND_NEXTHOPS:
	case ARC_NET_KIND_CONNECTIONS:
	case ARC_NET_KIND_SOCKETS:
	case ARC_NET_KIND_INTERFACES:
	case ARC_NET_KIND_BRIDGES:
	case ARC_NET_KIND_GENEVE:
	case ARC_NET_KIND_IPFW:
	case ARC_NET_KIND_NHGROUPS:
	case ARC_NET_KIND_NEIGHBOURS:
	case ARC_NET_KIND_IPSEC:
	case ARC_NET_KIND_MULTICAST:
	case ARC_NET_KIND_KEPT_ROUTES:
		return (true);
	default:
		return (false);
	}
}

/* The family an input says: the generated enums' order is all, inet,
 * inet6, as ARC_NET_FAMILY_*. */
#define	FAMILY(in, family)	do {					\
	(in).has_family = true;						\
	(in).family = (family);						\
} while (0)

int
ynet_read(cbl_conn *conn, int kind, int family, const char *filter,
    uint32_t fib, uint32_t offset, const char *jail, ucl_object_t **data,
    uint64_t *total, bool *has_total, bool *truncated, char *err,
    size_t errlen)
{
	ucl_object_t	*o;
	const char	*j;
	int		 error;

	*data = NULL;
	*has_total = *truncated = false;
	*total = 0;
	err[0] = '\0';
	j = jail_in(jail);
	switch (kind) {
	case ARC_NET_KIND_ROUTES: {
		struct arcana_network_network_routes_input in = { 0 };

		in.jail = j;
		FAMILY(in, family);
		in.filter = filter != NULL && filter[0] != '\0' ? filter : NULL;
		in.has_fib = fib != 0;
		in.fib = fib;
		in.has_offset = offset != 0;
		in.offset = offset;
		if ((error = net_call(conn, "routes", &in, &o, err, errlen)) !=
		    0)
			return (error);
		if (ucl_object_lookup(o, "total") != NULL) {
			*has_total = true;
			*total = (uint64_t)ucl_object_toint(ucl_object_lookup(o,
			    "total"));
		}
		*truncated = ucl_object_toboolean(ucl_object_lookup(o,
		    "truncated"));
		*data = wrap(take(o, "rt-family"), 4, "statistics",
		    "route-information", "route-table", "rt-family");
		ucl_object_unref(o);
		return (0);
	}
	case ARC_NET_KIND_NEXTHOPS:
	case ARC_NET_KIND_NHGROUPS: {
		struct arcana_network_network_nexthops_input in = { 0 };
		ucl_object_t *info, *fo;
		bool nh = kind == ARC_NET_KIND_NEXTHOPS;

		/* nhgroups' input has nexthops' layout. */
		in.jail = j;
		FAMILY(in, family);
		in.has_fib = fib != 0;
		in.fib = fib;
		if ((error = net_call(conn, nh ? "nexthops" : "nhgroups", &in,
		    &o, err, errlen)) != 0)
			return (error);
		info = wrap(take(o, "rt-family"), 2, nh ? "nhop-table" :
		    "nhgrp-table", "rt-family");
		if ((fo = ucl_object_pop_key(o, "fib")) != NULL)
			put(info, "fib", fo);
		*data = wrap(info, 2, "statistics", nh ?
		    "route-nhop-information" : "route-nhgrp-information");
		ucl_object_unref(o);
		return (0);
	}
	case ARC_NET_KIND_CONNECTIONS:
	case ARC_NET_KIND_SOCKETS: {
		struct arcana_network_network_connections_input in = { 0 };
		bool so = kind == ARC_NET_KIND_SOCKETS;

		in.jail = j;
		FAMILY(in, family);
		if ((error = net_call(conn, so ? "sockets" : "connections", &in,
		    &o, err, errlen)) != 0)
			return (error);
		*data = wrap(take(o, "socket"), 2, so ? "sockstat" :
		    "statistics", "socket");
		ucl_object_unref(o);
		return (0);
	}
	case ARC_NET_KIND_INTERFACES: {
		struct arcana_network_network_interfaces_input in = { 0 };

		in.jail = j;
		FAMILY(in, family);
		return (net_call(conn, "interfaces", &in, data, err, errlen));
	}
	case ARC_NET_KIND_NEIGHBOURS: {
		struct arcana_network_network_neighbours_input in = { 0 };

		in.jail = j;
		FAMILY(in, family);
		in.filter = filter != NULL && filter[0] != '\0' ? filter : NULL;
		return (net_call(conn, "neighbours", &in, data, err, errlen));
	}
	case ARC_NET_KIND_IPFW:
		return (ipfw_kind(conn, j, data, err, errlen));
	case ARC_NET_KIND_IPSEC: {
		struct arcana_network_network_ipsec_input in = { 0 };

		in.jail = j;
		if ((error = net_call(conn, "ipsec", &in, data, err, errlen)) ==
		    0)
			ipsec_models(*data);
		return (error);
	}
	default: {
		/* Those of the jail alone: bridges' input has their layout. */
		struct arcana_network_network_bridges_input in = { 0 };
		const char *act;

		act = kind == ARC_NET_KIND_BRIDGES ? "bridges" : kind ==
		    ARC_NET_KIND_GENEVE ? "geneve" : kind ==
		    ARC_NET_KIND_MULTICAST ? "multicast" : kind ==
		    ARC_NET_KIND_KEPT_ROUTES ? "kept-routes" : NULL;
		if (act == NULL) {
			snprintf(err, errlen, "no such kind");
			return (EINVAL);
		}
		in.jail = j;
		return (net_call(conn, act, &in, data, err, errlen));
	}
	}
}

int
ynet_lookup(cbl_conn *conn, const char *address, uint32_t fib,
    const char *jail, ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_network_network_lookup_input	in = { 0 };
	ucl_object_t					*o;
	int						 error;

	in.jail = jail_in(jail);
	in.address = address;
	in.has_fib = true;
	in.fib = fib;
	*data = NULL;
	if ((error = net_call(conn, "lookup", &in, &o, err, errlen)) != 0)
		return (error);
	/* No route is an answer too: best left out, as the agent did. */
	if (ucl_object_type(ucl_object_lookup(o, "best")) == UCL_OBJECT &&
	    ucl_object_lookup(ucl_object_lookup(o, "best"), "interface") ==
	    NULL)
		(void)ucl_object_delete_key(o, "best");
	*data = o;
	return (0);
}

int
ynet_address(cbl_conn *conn, const char *jail, const char *address,
    const char *ifname, bool remove, bool live, bool persist, bool dry_run,
    char **diff, char *err, size_t errlen)
{
	struct arcana_jails_jails_jail_arcnet_address_input	 in;
	struct arcana_jails_jails_jail_arcnet_address_output	 out;
	const struct cbl_ynode					*n, *an;
	cbl_yarena						*a;
	int							 error;

	*diff = NULL;
	if ((n = yq_top("arcana-jails", "jails")) == NULL || (n = yq_child(n,
	    "jail")) == NULL || (an = yq_child(n, "address")) == NULL) {
		snprintf(err, errlen, "arcana-jails has no address action");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&in, 0, sizeof(in));
	in.address = address;
	in.interface = ifname != NULL && ifname[0] != '\0' ? ifname : NULL;
	in.has_remove = in.has_live = in.has_persist = in.has_dry_run = true;
	in.remove = remove;
	in.live = live;
	in.persist = persist;
	in.dry_run = dry_run;
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, n, &jail, an, &in, &out, a, err,
	    errlen)) == 0 && out.diff != NULL && (*diff = strdup(out.diff)) ==
	    NULL)
		error = ENOMEM;
	cbl_yarena_free(a);
	return (error);
}

/* ---- the kept rules -------------------------------------------- */

static const char *
sha_of(const char *text, char *buf, size_t len)
{
	unsigned char	md[32];
	unsigned int	n;

	buf[0] = '\0';
	if (EVP_Digest(text, strlen(text), md, &n, EVP_sha256(), NULL) != 1)
		return (buf);
	for (int i = 0; i < 32 && (size_t)i * 2 + 2 < len; i++)
		snprintf(buf + i * 2, len - (size_t)i * 2, "%02x", md[i]);
	return (buf);
}

/* Action act of /firewall, given in, out its output (a's). */
static int
fw_call(cbl_conn *conn, const char *act, const void *in, void *out,
    cbl_yarena *a, char *err, size_t errlen)
{
	const struct cbl_ynode	*n, *an;

	if ((n = yq_top("arcana-firewall", "firewall")) == NULL || (an =
	    yq_child(n, act)) == NULL) {
		snprintf(err, errlen, "arcana-firewall has no %s", act);
		return (ENOENT);
	}
	return (yq_call(conn, n, NULL, an, in, out, a, err, errlen));
}

int
ynet_rules(cbl_conn *conn, const char *jail, bool from_rc, const char *text,
    const char *sha256, bool check, const char *const *acc, size_t nacc,
    ucl_object_t *top, char *err, size_t errlen, char *tag, size_t taglen)
{
	struct arcana_firewall_firewall_from_rc_input	 rin;
	struct arcana_firewall_firewall_from_rc_output	 rout;
	struct arcana_firewall_firewall_check_input	 cin;
	const struct arcana_firewall_firewall		*f;
	struct arcana_firewall_firewall			*nf;
	struct arcana_firewall_firewall_kept		*nk;
	struct arcana_firewall_firewall_jail		*jv;
	const struct cbl_ynode				*n;
	struct arcana_firewall				 d;
	cbl_yarena					*a;
	const char					*was, *from;
	char						 sha[65], token[33];
	size_t						 k;
	int						 error;

	err[0] = tag[0] = '\0';
	jail = jail_in(jail);
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	from = NULL;
	if (from_rc) {
		memset(&rin, 0, sizeof(rin));
		memset(&rout, 0, sizeof(rout));
		rin.jail = jail;
		if ((error = fw_call(conn, "from-rc", &rin, &rout, a, err,
		    errlen)) == 0) {
			put_str(top, "text", rout.text);
			put_str(top, "sha256", rout.sha256);
			put_str(top, "rc_file", rout.rc_file);
		}
		goto out;
	}
	/* The host's from running, a jail's from the host's list there. */
	if ((n = yq_top("arcana-firewall", "firewall")) == NULL) {
		snprintf(err, errlen, "arcana-firewall is not in the tables");
		error = ENOENT;
		goto out;
	}
	memset(&d, 0, sizeof(d));
	if ((error = yq_get(conn, n, CBL_YDS_RUNNING, &d, a, err, errlen)) !=
	    0)
		goto out;
	f = d.firewall;
	was = NULL;
	if (jail == NULL)
		was = f != NULL && f->kept != NULL ? f->kept->text : NULL;
	else
		for (k = 0; f != NULL && k < f->jail.n; k++)
			if (strcmp(f->jail.v[k].name, jail) == 0)
				was = f->jail.v[k].text;
	if (text == NULL) {
		put_str(top, "text", was != NULL ? was : "");
		put_str(top, "sha256", sha_of(was != NULL ? was : "", sha,
		    sizeof(sha)));
		goto out;
	}
	if (sha256 == NULL || strcmp(sha256, sha_of(was != NULL ? was : "",
	    sha, sizeof(sha))) != 0) {
		snprintf(err, errlen, "the file is not the one this was made "
		    "from: somebody changed it meanwhile.  Read it again");
		error = EBUSY;
		goto out;
	}
	if (check) {
		memset(&cin, 0, sizeof(cin));
		cin.jail = jail;
		cin.text = text;
		error = fw_call(conn, "check", &cin, NULL, a, err, errlen);
		goto out;
	}
	/*
	 * A host's first commit migrates (the agent's from-rc says from
	 * where, or that the host boots by Arcana's script already): where
	 * from, said.
	 */
	if (jail == NULL) {
		memset(&rin, 0, sizeof(rin));
		memset(&rout, 0, sizeof(rout));
		if (fw_call(conn, "from-rc", &rin, &rout, a, err, errlen) ==
		    0 && rout.rc_file != NULL && strstr(rout.rc_file,
		    "script already") == NULL)
			from = rout.rc_file;
		err[0] = '\0';
	}
	if ((nf = cbl_yarena_alloc(a, sizeof(*nf))) == NULL ||
	    (nk = cbl_yarena_alloc(a, sizeof(*nk))) == NULL) {
		error = ENOMEM;
		goto out;
	}
	memset(nf, 0, sizeof(*nf));
	memset(nk, 0, sizeof(*nk));
	if (f != NULL)
		*nf = *f;
	if (nf->kept != NULL)
		*nk = *nf->kept;
	if (jail == NULL) {
		nk->text = text;
		nf->kept = nk;
	} else {
		if ((jv = cbl_yarena_alloc(a, (nf->jail.n + 1) *
		    sizeof(*jv))) == NULL) {
			error = ENOMEM;
			goto out;
		}
		for (k = 0; k < nf->jail.n; k++)
			jv[k] = nf->jail.v[k];
		for (k = 0; k < nf->jail.n && strcmp(jv[k].name, jail) != 0;
		    k++)
			;
		if (k == nf->jail.n) {
			memset(&jv[k], 0, sizeof(jv[k]));
			jv[k].name = jail;
			nf->jail.n++;
		}
		jv[k].text = text;
		nf->jail.v = jv;
	}
	d.firewall = nf;
	if ((error = ytrans_commit(conn, n, &d, acc, nacc, 0, token,
	    sizeof(token), err, errlen, tag, taglen)) != 0)
		goto out;
	put_str(top, "text", text);
	put_str(top, "sha256", sha_of(text, sha, sizeof(sha)));
	if (from != NULL)
		put_str(top, "migrated", from);
out:
	cbl_yarena_free(a);
	return (error);
}
