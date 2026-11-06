/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's network tables through the fleet mount (PLAN-SDN-YANG
 * 4.8.1): arcana-network's read actions, the plugins' (arcana-netgraph,
 * arcana-wireguard, arcana-bird), arcana-firewall's state, the
 * interfaces by the standard models (ietf-interfaces with RFC 8529's
 * network instances), arcana-troubleshoot's traceroute and
 * arcana-probe's monitors.  Each is made here the JSON the pages have
 * always drawn: its module's names (the network tables keep those
 * FreeBSD's tools give, "rt-entry"), RFC 7951's 64-bit strings numbers
 * again, the tables wrapped as netstat(1)'s libxo document wraps them.
 * A callback gets {"ok": true, "data": ...} as the tables always came,
 * or the read's failure as rc.c says it.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "app.h"

/* The leaves the modules keep as 64-bit numbers or decimal64. */
static const char *const nums_net[] = { "total", "rekey_time", "use-out",
    "use-in", "use", "uniqueid", "time", "rekey-time", "rekey_packets",
    "rekey_bytes", "refcount", "reauth-time", "reauth_time", "priority",
    "packets-out", "packets-in", "opackets", "oerrors", "obytes", "now",
    "not_before", "not_after", "nhg-refcnt", "life-time", "ipackets",
    "install-time", "ierrors", "ibytes", "established", "dpd_timeout",
    "dpd_delay", "bytes-out", "bytes-in",
    /* arcana-firewall's, a vnet jail's by arcana-network's ipfw */
    "packets", "octets", "updated", "plr", "burst", "bandwidth",
    /* arcana-bird's and arcana-wireguard's */
    "routes", "networks", "imported", "exported", "count", "received",
    "sent", NULL };

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_replace_key(o, v, key, 0, true);
}

static struct server *
server_of(const char *sid)
{

	for (int i = 0; sid != NULL && i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sid) == 0)
			return (&app.servers[i]);
	return (NULL);
}

static bool
named(const char *key, const char *const *names)
{

	for (; names != NULL && *names != NULL; names++)
		if (strcmp(key, *names) == 0)
			return (true);
	return (false);
}

/* A leaf-list's (or a tuple's) values, each a number where it is one. */
static ucl_object_t *
all_nums(const ucl_object_t *v, const char *const *nums)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*a, *n;

	if (ucl_object_type(v) == UCL_STRING && (n = jnumber(
	    ucl_object_tostring(v))) != NULL)
		return (n);
	if (ucl_object_type(v) != UCL_ARRAY)
		return (net_plain(v, nums));
	a = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		ucl_array_append(a, all_nums(e, nums));
	return (a);
}

/*
 * A copy of v by the names its module gives (a "module:" prefix taken
 * off), the leaves nums names numbers where RFC 7951 wrote a string (a
 * leaf-list's, or a flattened list's tuples, each value).
 */
ucl_object_t *
net_plain(const ucl_object_t *v, const char *const *nums)
{
	const ucl_object_t	*m;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*r, *n;
	const char		*key, *c;

	if (nums == NULL)
		nums = nums_net;
	switch (ucl_object_type(v)) {
	case UCL_OBJECT:
		r = ucl_object_typed_new(UCL_OBJECT);
		while ((m = ucl_object_iterate(v, &it, true)) != NULL) {
			key = ucl_object_key(m);
			if ((c = strchr(key, ':')) != NULL)
				key = c + 1;
			if (ucl_object_type(m) == UCL_STRING && named(key, nums) &&
			    (n = jnumber(ucl_object_tostring(m))) != NULL) {
				put(r, key, n);
				continue;
			}
			if (ucl_object_type(m) == UCL_ARRAY && named(key, nums)) {
				put(r, key, all_nums(m, nums));
				continue;
			}
			put(r, key, net_plain(m, nums));
		}
		return (r);
	case UCL_ARRAY:
		r = ucl_object_typed_new(UCL_ARRAY);
		while ((m = ucl_object_iterate(v, &it, true)) != NULL)
			ucl_array_append(r, net_plain(m, nums));
		return (r);
	case UCL_NULL:
		return (ucl_object_typed_new(UCL_NULL));
	default:
		return (v != NULL ? ucl_object_copy(v) :
		    ucl_object_typed_new(UCL_NULL));
	}
}

/* {k1: {k2: ... {last: v}}}. */
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
	for (int i = (n < 6 ? n : 6) - 1; i >= 0; i--) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, keys[i], v);
		v = o;
	}
	return (v);
}

/* A member of o taken out of it: an empty array where there is none. */
static ucl_object_t *
take(ucl_object_t *o, const char *key)
{
	ucl_object_t	*v;

	if ((v = ucl_object_pop_key(o, key)) == NULL)
		v = ucl_object_typed_new(UCL_ARRAY);
	return (v);
}

/* Each of names an array in o, an empty one where the reply had none. */
static void
lists(ucl_object_t *o, const char *const *names)
{

	for (; *names != NULL; names++)
		if (ucl_object_lookup(o, *names) == NULL)
			put(o, *names, ucl_object_typed_new(UCL_ARRAY));
}

/* ---- the firewall: arcana-firewall's ------------------------------- */

static void
cp(ucl_object_t *dst, const char *to, const ucl_object_t *src,
    const char *from)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(src, from)) != NULL)
		put(dst, to, ucl_object_copy(v));
}

/* Each entry of list from of src, its members renamed by map (pairs of
 * the model's name and the page's, NULL ended), as array to. */
static void
cp_list(ucl_object_t *dst, const char *to, const ucl_object_t *src,
    const char *from, const char *const *map)
{
	const ucl_object_t	*e, *mk;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*arr, *o, *m;

	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(ucl_object_lookup(src, from), &it,
	    true)) != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		for (size_t i = 0; map[i] != NULL; i += 2) {
			if (strcmp(map[i], "mask") == 0 &&
			    (mk = ucl_object_lookup(e, "mask")) != NULL) {
				m = ucl_object_typed_new(UCL_OBJECT);
				cp(m, "src", mk, "src");
				cp(m, "dst", mk, "dst");
				cp(m, "src_port", mk, "src-port");
				cp(m, "dst_port", mk, "dst-port");
				cp(m, "proto", mk, "proto");
				put(o, "mask", m);
				continue;
			}
			/* disabled is there only when true. */
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
 * A firewall as arcana-firewall has it (its state, its kept rules and
 * what rc.conf says), plain, made what the Firewall tab draws: ipfw's
 * own names (num, pkts, bytes), the dummynet objects, the rules kept.
 */
ucl_object_t *
net_fw(const ucl_object_t *f)
{
	static const char *const rules[] = { "number", "num", "packets",
	    "pkts", "octets", "bytes", "set", "set", "text", "text",
	    "disabled", "disabled", NULL };
	static const char *const dyn[] = { "number", "num", "packets",
	    "pkts", "octets", "bytes", "ttl", "ttl", "kind", "kind", "flow",
	    "flow", NULL };
	static const char *const tables[] = { "name", "name", "set", "set",
	    "type", "type", "entry", "entries", "count", "count", "feed",
	    "feed", "updated", "updated", NULL };
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

/* ---- the plugins' ------------------------------------------------- */

static ucl_object_t *
netgraph(const ucl_object_t *o)
{
	static const char *const node[] = { "name", "name", "type", "type",
	    "id", "id", NULL };
	static const char *const hook[] = { "name", "hook", "peer", "peer",
	    "peer-type", "peer-type", "peer-id", "peer-id", "peer-hook",
	    "peer-hook", NULL };
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*top, *nodes, *x;

	nodes = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(jget(o, "node"), &it, true)) != NULL) {
		x = jmap(e, node);
		put(x, "hooks", jmap_each(jget(e, "hook"), hook));
		ucl_array_append(nodes, x);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "nodes", nodes);
	return (top);
}

static ucl_object_t *
wireguard(const ucl_object_t *o)
{
	const ucl_object_t	*e, *p;
	ucl_object_iter_t	 it = NULL, pit;
	ucl_object_t		*top, *ifs, *x, *peers, *y;

	ifs = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(jget(o, "interface"), &it, true)) !=
	    NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		cp(x, "name", e, "name");
		put(x, "private-key", ucl_object_frombool(jbool(e,
		    "private-key")));
		cp(x, "public-key", e, "public-key");
		put(x, "listen-port", ucl_object_fromint(jint(e, "listen-port",
		    0)));
		peers = ucl_object_typed_new(UCL_ARRAY);
		pit = NULL;
		while ((p = ucl_object_iterate(jget(e, "peer"), &pit, true)) !=
		    NULL) {
			y = ucl_object_typed_new(UCL_OBJECT);
			cp(y, "public-key", p, "public-key");
			put(y, "preshared-key", ucl_object_frombool(jbool(p,
			    "preshared-key")));
			cp(y, "endpoint", p, "endpoint");
			put(y, "allowed-ips", jget(p, "allowed-ip") != NULL ?
			    ucl_object_copy(jget(p, "allowed-ip")) :
			    ucl_object_typed_new(UCL_ARRAY));
			/* 0: never, as wg says it. */
			put(y, "latest-handshake", ucl_object_fromint(rc_time(
			    jstr(p, "latest-handshake"))));
			put(y, "rx", ucl_object_fromint(jint(p, "received", 0)));
			put(y, "tx", ucl_object_fromint(jint(p, "sent", 0)));
			put(y, "keepalive", ucl_object_fromint(jint(p,
			    "keepalive", 0)));
			ucl_array_append(peers, y);
		}
		put(x, "peers", peers);
		ucl_array_append(ifs, x);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "interfaces", ifs);
	put(top, "now", ucl_object_fromint(jstr(o, "now") != NULL ?
	    rc_time(jstr(o, "now")) : (int64_t)(arc_now() / 1000)));
	return (top);
}

/* A number the agent printed as text, as text again. */
static void
put_num_str(ucl_object_t *o, const char *key, const ucl_object_t *v)
{

	if (v != NULL)
		put(o, key, ucl_object_fromstring(ucl_object_tostring_forced(v)));
}

/* A protocol as show protocols all words it. */
static ucl_object_t *
bird_protocol(const ucl_object_t *y)
{
	static const char *const proto[] = { "name", "name", "type", "proto",
	    "table", "table", "state", "state", "since", "since", "info",
	    "info", "detail", "detail", "description", "description",
	    "bgp.state", "bgp-state", "bgp.neighbor", "neighbor",
	    "bgp.neighbor-id", "neighbor-id", "bgp.source", "source",
	    "bgp.session", "session", "bgp.hold", "hold", "bgp.keepalive",
	    "keepalive", "bgp.last-error", "last-error", "rpki.cache", "cache",
	    "rpki.status", "rpki-status", "rpki.serial", "serial",
	    "rpki.last-update", "last-update", NULL };
	static const char *const chan[] = { "name", "name", "state", "state",
	    "table", "table", "input-filter", "input-filter", "output-filter",
	    "output-filter", "routes", "routes", "imported", "imported",
	    "exported", "exported", NULL };
	ucl_object_t	*o;

	o = jmap(y, proto);
	put_num_str(o, "neighbor-as", jget(y, "bgp.neighbor-as"));
	put_num_str(o, "local-as", jget(y, "bgp.local-as"));
	/* routes is BIRD's own words, the counts numbers. */
	if (jget(y, "channel") != NULL)
		put(o, "channels", jmap_each(jget(y, "channel"), chan));
	return (o);
}

static ucl_object_t *
bird(const ucl_object_t *o)
{
	static const char *const nb[] = { "protocol", "proto", "router-id",
	    "router-id", "priority", "pri", "state", "state", "dead-time",
	    "dtime", "interface", "interface", "address", "address", NULL };
	static const char *const bfd[] = { "protocol", "proto", "address",
	    "address", "interface", "interface", "state", "state", "since",
	    "since", "interval", "interval", "timeout", "timeout", NULL };
	static const char *const tab[] = { "name", "name", "routes", "routes",
	    "networks", "networks", NULL };
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*top, *arr;

	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "status", jget(o, "status") != NULL ? ucl_object_copy(jget(o,
	    "status")) : ucl_object_typed_new(UCL_ARRAY));
	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(jget(o, "protocol"), &it, true)) !=
	    NULL)
		ucl_array_append(arr, bird_protocol(e));
	put(top, "protocols", arr);
	put(top, "ospf", jmap_each(jget(o, "ospf-neighbor"), nb));
	put(top, "bfd", jmap_each(jget(o, "bfd-session"), bfd));
	put(top, "tables", jmap_each(jget(o, "table"), tab));
	return (top);
}

static ucl_object_t *
bird_routes(const ucl_object_t *o)
{
	static const char *const route[] = { "table", "table", "prefix",
	    "prefix", "type", "type", "protocol", "protocol", "from", "from",
	    "since", "since", "preference", "preference", "info", "info",
	    "attribute", "attrs", NULL };
	static const char *const hop[] = { "via", "via", "interface",
	    "interface", NULL };
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*top, *arr, *x;

	top = ucl_object_typed_new(UCL_OBJECT);
	cp(top, "message", o, "message");
	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(jget(o, "route"), &it, true)) != NULL) {
		x = jmap(e, route);
		put(x, "primary", ucl_object_frombool(jbool(e, "primary")));
		if (jget(e, "nexthop") != NULL)
			put(x, "nexthops", jmap_each(jget(e, "nexthop"), hop));
		ucl_array_append(arr, x);
	}
	put(top, "routes", arr);
	put(top, "count", ucl_object_fromint(jint(o, "count", 0)));
	return (top);
}

static ucl_object_t *
bird_ospf(const ucl_object_t *o, bool topology)
{
	static const char *const link[] = { "kind", "kind", "to", "to",
	    "metric", "metric", "metric2", "metric2", NULL };
	static const char *const net[] = { "id", "id", "router", "routers",
	    "dr", "dr", "distance", "distance", NULL };
	const ucl_object_t	*p, *t, *r;
	ucl_object_iter_t	 it = NULL, tit, rit;
	ucl_object_t		*top, *arr, *x, *areas, *a, *routers, *n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((p = ucl_object_iterate(jget(o, "protocol"), &it, true)) !=
	    NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		cp(x, "name", p, "name");
		put(x, "areas", jget(p, "area") != NULL ? ucl_object_copy(jget(p,
		    "area")) : ucl_object_typed_new(UCL_ARRAY));
		if (topology) {
			areas = ucl_object_typed_new(UCL_ARRAY);
			tit = NULL;
			while ((t = ucl_object_iterate(jget(p, "topology"), &tit,
			    true)) != NULL) {
				a = ucl_object_typed_new(UCL_OBJECT);
				cp(a, "area", t, "area");
				routers = ucl_object_typed_new(UCL_ARRAY);
				rit = NULL;
				while ((r = ucl_object_iterate(jget(t, "router"),
				    &rit, true)) != NULL) {
					n = ucl_object_typed_new(UCL_OBJECT);
					cp(n, "id", r, "id");
					put(n, "links", jmap_each(jget(r, "link"),
					    link));
					cp(n, "distance", r, "distance");
					if (jbool(r, "unreachable"))
						put(n, "unreachable",
						    ucl_object_frombool(true));
					ucl_array_append(routers, n);
				}
				put(a, "routers", routers);
				put(a, "networks", jmap_each(jget(t, "network"),
				    net));
				ucl_array_append(areas, a);
			}
			put(x, "topology", areas);
		}
		ucl_array_append(arr, x);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "protocols", arr);
	return (top);
}

/* ---- the interfaces by the standard models ------------------------- */

/* The FIB of the network instance named, 0: none (the host's). */
static int64_t
ni_fib(const ucl_object_t *nis, const char *name)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;

	while (name != NULL && (e = ucl_object_iterate(jget(nis,
	    "network-instance"), &it, true)) != NULL)
		if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"), name) == 0)
			return (jint(e, "fib", 0));
	return (0);
}

static void
if_addresses(ucl_object_t *arr, const char *ifname, const char *family,
    const ucl_object_t *list)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*a;
	const char		*ip;
	char			 zoned[128];

	while ((e = ucl_object_iterate(list, &it, true)) != NULL) {
		if ((ip = jstr(e, "ip")) == NULL)
			continue;
		a = ucl_object_typed_new(UCL_OBJECT);
		put(a, "family", ucl_object_fromstring(family));
		/* A link-local one with its zone, the interface. */
		if (strncasecmp(ip, "fe8", 3) == 0 || strncasecmp(ip, "fe9", 3) ==
		    0 || strncasecmp(ip, "fea", 3) == 0 || strncasecmp(ip, "feb",
		    3) == 0) {
			snprintf(zoned, sizeof(zoned), "%s%%%s", ip, ifname);
			ip = zoned;
		}
		put(a, "address", ucl_object_fromstring(ip));
		if (jget(e, "prefix-length") != NULL)
			put(a, "prefixlen", ucl_object_fromint(jint(e,
			    "prefix-length", 0)));
		if (jstr(e, "peer") != NULL)
			put(a, "destination", ucl_object_fromstring(jstr(e,
			    "peer")));
		ucl_array_append(arr, a);
	}
}

/*
 * An interface of ietf-interfaces' (plain) as the Network tab's row:
 * enabled up, oper-status the link of one with a medium, the counters
 * as the kernel's (unicast and multicast packets together), each
 * address with its prefix length and a point-to-point link's far end.
 */
static ucl_object_t *
if_row(const ucl_object_t *e, const ucl_object_t *nis, int family)
{
	const ucl_object_t	*st;
	const char		*os, *ph;
	ucl_object_t		*o, *arr, *tun;
	int64_t			 fib;

	o = ucl_object_typed_new(UCL_OBJECT);
	cp(o, "name", e, "name");
	put(o, "up", ucl_object_frombool(jbool(e, "enabled")));
	os = jstr(e, "oper-status");
	put(o, "link", ucl_object_fromstring(os == NULL || jget(e, "media") ==
	    NULL ? "unknown" : strcmp(os, "up") == 0 ? "up" : strcmp(os,
	    "down") == 0 ? "down" : "unknown"));
	if (jget(e, "ipv4.mtu") != NULL)
		put(o, "mtu", ucl_object_fromint(jint(e, "ipv4.mtu", 0)));
	else if (jget(e, "ipv6.mtu") != NULL)
		put(o, "mtu", ucl_object_fromint(jint(e, "ipv6.mtu", 0)));
	if ((ph = jstr(e, "phys-address")) != NULL && strlen(ph) == 17)
		put(o, "ether", ucl_object_fromstring(ph));
	cp(o, "description", e, "description");
	if ((fib = ni_fib(nis, jstr(e, "bind-ni-name"))) != 0)
		put(o, "fib", ucl_object_fromint(fib));
	if (jint(e, "tunnel-fib", 0) != 0)
		put(o, "tunnelfib", ucl_object_fromint(jint(e, "tunnel-fib",
		    0)));
	if (jstr(e, "tunnel.local") != NULL) {
		tun = ucl_object_typed_new(UCL_OBJECT);
		cp(tun, "local", jget(e, "tunnel"), "local");
		cp(tun, "remote", jget(e, "tunnel"), "remote");
		put(o, "tunnel", tun);
	}
	if ((st = jget(e, "statistics")) != NULL) {
		put(o, "ibytes", ucl_object_fromint(jint(st, "in-octets", 0)));
		put(o, "obytes", ucl_object_fromint(jint(st, "out-octets", 0)));
		put(o, "ipackets", ucl_object_fromint(jint(st,
		    "in-unicast-pkts", 0) + jint(st, "in-multicast-pkts", 0)));
		put(o, "opackets", ucl_object_fromint(jint(st,
		    "out-unicast-pkts", 0) + jint(st, "out-multicast-pkts", 0)));
		put(o, "ierrors", ucl_object_fromint(jint(st, "in-errors", 0)));
		put(o, "oerrors", ucl_object_fromint(jint(st, "out-errors", 0)));
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	if (family != 6)
		if_addresses(arr, jstr(e, "name"), "inet", jget(e,
		    "ipv4.address"));
	if (family != 4)
		if_addresses(arr, jstr(e, "name"), "inet6", jget(e,
		    "ipv6.address"));
	put(o, "addresses", arr);
	return (o);
}

/* ---- the reads ----------------------------------------------------- */

struct nread {
	api_cb		*cb;
	void		*arg;
	char		 sid[9];
	char		 kind[16];
	int		 family;
	bool		 topology;	/* bird-ospf's */
	ucl_object_t	*held;		/* interfaces: the ones read first */
};

/* The read's answer, as the table has always come. */
static void
answer(struct nread *r, ucl_object_t *data, const ucl_object_t *top)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "ok", ucl_object_frombool(true));
	put(o, "data", data != NULL ? data : ucl_object_typed_new(UCL_NULL));
	if (top != NULL && jget(top, "total") != NULL &&
	    strcmp(r->kind, "routes") == 0) {
		put(o, "total", ucl_object_fromint(jint(top, "total", 0)));
		put(o, "truncated", ucl_object_frombool(jbool(top,
		    "truncated")));
	}
	r->cb(200, o, NULL, r->arg);
	ucl_object_unref(o);
}

static void
nread_free(struct nread *r)
{

	if (r->held != NULL)
		ucl_object_unref(r->held);
	free(r);
}

/* ipsec's children, a list in the model, as the map they always were. */
static void
ipsec_models(ucl_object_t *top)
{
	const ucl_object_t	*c, *e;
	ucl_object_iter_t	 it = NULL, eit;
	ucl_object_t		*m, *map, *kid;

	while ((c = ucl_object_iterate(ucl_object_lookup(top, "connections"),
	    &it, true)) != NULL) {
		if ((m = (ucl_object_t *)(uintptr_t)ucl_object_lookup(c,
		    "model")) == NULL)
			continue;
		map = ucl_object_typed_new(UCL_OBJECT);
		eit = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(m, "children"),
		    &eit, true)) != NULL) {
			if (jstr(e, "name") == NULL)
				continue;
			kid = ucl_object_copy(e);
			(void)ucl_object_delete_key(kid, "name");
			put(map, jstr(e, "name"), kid);
		}
		put(m, "children", map);
	}
}

/* An action's output (or the node read) made the kind's table. */
static ucl_object_t *
table_of(const struct nread *r, const ucl_object_t *out)
{
	static const char *const ifl[] = { "interfaces", NULL };
	static const char *const ipl[] = { "certificates", "connections",
	    "sas", NULL };
	ucl_object_t	*p, *info, *fo, *d;
	const char	*k = r->kind;
	bool		 nh;

	if (strcmp(k, "netgraph") == 0)
		return (netgraph(out));
	if (strcmp(k, "wireguard") == 0)
		return (wireguard(out));
	if (strcmp(k, "bird") == 0)
		return (bird(out));
	if (strcmp(k, "bird-routes") == 0)
		return (bird_routes(out));
	if (strcmp(k, "bird-ospf") == 0)
		return (bird_ospf(out, r->topology));
	p = net_plain(out, NULL);
	if (strcmp(k, "routes") == 0) {
		d = wrap(take(p, "rt-family"), 4, "statistics",
		    "route-information", "route-table", "rt-family");
		ucl_object_unref(p);
		return (d);
	}
	if ((nh = strcmp(k, "nexthops") == 0) || strcmp(k, "nhgroups") == 0) {
		info = wrap(take(p, "rt-family"), 2, nh ? "nhop-table" :
		    "nhgrp-table", "rt-family");
		if ((fo = ucl_object_pop_key(p, "fib")) != NULL)
			put(info, "fib", fo);
		ucl_object_unref(p);
		return (wrap(info, 2, "statistics", nh ?
		    "route-nhop-information" : "route-nhgrp-information"));
	}
	if (strcmp(k, "connections") == 0 || strcmp(k, "sockets") == 0) {
		d = wrap(take(p, "socket"), 2, k[0] == 's' ? "sockstat" :
		    "statistics", "socket");
		ucl_object_unref(p);
		return (d);
	}
	if (strcmp(k, "ipfw") == 0) {
		/* A vnet jail's by arcana-network, the host's its own. */
		d = net_fw(jget(p, "firewall") != NULL ? jget(p, "firewall") :
		    p);
		ucl_object_unref(p);
		return (d);
	}
	if (strcmp(k, "ipsec") == 0) {
		lists(p, ipl);
		ipsec_models(p);
	} else if (strcmp(k, "interfaces") == 0)
		lists(p, ifl);
	else if (strcmp(k, "lookup") == 0) {
		/* No route is an answer too: best left out. */
		if (jget(p, "best") != NULL && jget(p, "best.interface") ==
		    NULL)
			ucl_object_delete_key(p, "best");
	} else if (strcmp(k, "traceroute") == 0) {
		const ucl_object_t	*h;
		ucl_object_iter_t	 it = NULL;
		ucl_object_t		*hops, *x;

		d = ucl_object_typed_new(UCL_OBJECT);
		cp(d, "address", p, "address");
		if (jstr(p, "family") != NULL)
			put(d, "family", ucl_object_fromstring(strcmp(jstr(p,
			    "family"), "ipv6") == 0 ? "inet6" : "inet"));
		hops = ucl_object_typed_new(UCL_ARRAY);
		while ((h = ucl_object_iterate(jget(p, "hop"), &it, true)) !=
		    NULL) {
			x = ucl_object_typed_new(UCL_OBJECT);
			put(x, "ttl", ucl_object_fromint(jint(h, "ttl", 0)));
			if (jbool(h, "lost"))
				put(x, "lost", ucl_object_frombool(true));
			cp(x, "address", h, "address");
			if (jget(h, "rtt") != NULL)
				put(x, "rtt", ucl_object_fromdouble(jnum(h, "rtt",
				    0)));
			cp(x, "note", h, "note");
			ucl_array_append(hops, x);
		}
		put(d, "hops", hops);
		put(d, "reached", ucl_object_frombool(jbool(p, "reached")));
		ucl_object_unref(p);
		return (d);
	}
	return (p);
}

static void
action_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct nread	*r = arg;

	if (status != 200) {
		r->cb(status, o, err, r->arg);
		nread_free(r);
		return;
	}
	answer(r, table_of(r, o), o);
	nread_free(r);
}

/* The interfaces' network instances: their FIBs. */
static void
nis_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct nread		*r = arg;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*nis, *top, *arr;

	(void)err;
	/* None configured: every interface the host's FIB's. */
	nis = status == 200 && o != NULL ? net_plain(o, NULL) :
	    ucl_object_typed_new(UCL_OBJECT);
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(jget(r->held, "interface"), &it,
	    true)) != NULL)
		ucl_array_append(arr, if_row(e, nis, r->family));
	put(top, "interfaces", arr);
	/* When the counters were read, to make rates of two readings. */
	put(top, "time", ucl_object_fromint((int64_t)arc_now()));
	put(top, "source", ucl_object_fromstring("yang"));
	ucl_object_unref(nis);
	answer(r, top, NULL);
	nread_free(r);
}

static void
ifs_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct nread	*r = arg;
	struct server	*s;
	char		 url[300];

	if (status != 200 || (s = server_of(r->sid)) == NULL) {
		r->cb(status != 200 ? status : 404, o, err != NULL ? err :
		    "no such host", r->arg);
		nread_free(r);
		return;
	}
	r->held = net_plain(o, NULL);
	rc_get(rc_h(url, sizeof(url), s->id, "ietf-network-instance:"
	    "network-instances"), NULL, nis_cb, r);
}

/*
 * Host sid's network table q->kind: routes, nexthops, nhgroups,
 * connections, sockets, interfaces, neighbours, bridges, geneve,
 * multicast, kept-routes, ipsec, ipfw, netgraph, wireguard, bird,
 * bird-routes, bird-ospf, lookup or traceroute.  One the user asked for
 * (user) is the task app.ops[0] just made, its steps drawn as the host
 * takes them.
 */
void
net_yread(const char *sid, const struct netq *q, bool user, api_cb *cb,
    void *arg)
{
	struct server	*s;
	struct nread	*r;
	struct html	 b;
	const char	*k = q->kind, *jail, *path;
	char		 act[96], *qs;
	bool		 nojail;

	if ((s = server_of(sid)) == NULL) {
		cb(404, NULL, "no such host", arg);
		return;
	}
	if ((r = calloc(1, sizeof(*r))) == NULL)
		abort();
	r->cb = cb;
	r->arg = arg;
	r->family = q->family;
	snprintf(r->sid, sizeof(r->sid), "%s", sid);
	snprintf(r->kind, sizeof(r->kind), "%s", k);
	jail = q->jail != NULL && q->jail[0] != '\0' ? q->jail : NULL;
	/* The host's interfaces by the standard models. */
	if (strcmp(k, "interfaces") == 0 && q->yang && jail == NULL) {
		host_yread(s, "ietf-interfaces:interfaces", NULL, NULL, user,
		    ifs_cb, r);
		return;
	}
	/* The host's firewall, its own node. */
	if (strcmp(k, "ipfw") == 0 && jail == NULL) {
		host_yread(s, "arcana-firewall:firewall", NULL, NULL, user,
		    action_cb, r);
		return;
	}
	memset(&b, 0, sizeof(b));
	h_raw(&b, "{");
	nojail = strcmp(k, "traceroute") == 0;
	if (jail != NULL && !nojail) {
		qs = json_quote(jail);
		h_fmt(&b, "\"jail\":%s", qs);
		free(qs);
	}
#define	SEP	(b.s != NULL && b.s[strlen(b.s) - 1] != '{' ? "," : "")
	if (strcmp(k, "routes") == 0 || strcmp(k, "nexthops") == 0 ||
	    strcmp(k, "nhgroups") == 0 || strcmp(k, "connections") == 0 ||
	    strcmp(k, "sockets") == 0 || strcmp(k, "interfaces") == 0 ||
	    strcmp(k, "neighbours") == 0)
		h_fmt(&b, "%s\"family\":\"%s\"", SEP, q->family == 4 ? "inet" :
		    q->family == 6 ? "inet6" : "all");
	if ((strcmp(k, "routes") == 0 || strcmp(k, "nexthops") == 0 ||
	    strcmp(k, "nhgroups") == 0 || strcmp(k, "lookup") == 0) &&
	    q->fib > 0)
		h_fmt(&b, "%s\"fib\":%d", SEP, q->fib);
	if (strcmp(k, "routes") == 0 && q->offset > 0)
		h_fmt(&b, "%s\"offset\":%d", SEP, q->offset);
	if ((strcmp(k, "routes") == 0 || strcmp(k, "neighbours") == 0 ||
	    strcmp(k, "bird-routes") == 0) && q->filter != NULL &&
	    q->filter[0] != '\0') {
		qs = json_quote(q->filter);
		h_fmt(&b, "%s\"filter\":%s", SEP, qs);
		free(qs);
	} else if (strcmp(k, "bird-routes") == 0)
		h_fmt(&b, "%s\"filter\":\"\"", SEP);
	if (strcmp(k, "bird-ospf") == 0 && q->topology) {
		r->topology = true;
		h_fmt(&b, "%s\"topology\":true", SEP);
		if (q->filter != NULL && q->filter[0] != '\0') {
			qs = json_quote(q->filter);
			h_fmt(&b, ",\"protocol\":%s", qs);
			free(qs);
		}
	}
	if ((strcmp(k, "lookup") == 0 || strcmp(k, "traceroute") == 0) &&
	    q->address != NULL) {
		qs = json_quote(q->address);
		h_fmt(&b, "%s\"address\":%s", SEP, qs);
		free(qs);
	}
#undef	SEP
	h_raw(&b, "}");
	if (strcmp(k, "netgraph") == 0)
		path = "arcana-netgraph:netgraph/read";
	else if (strcmp(k, "wireguard") == 0)
		path = "arcana-wireguard:wireguard/read";
	else if (strcmp(k, "bird") == 0)
		path = "arcana-bird:bird/read";
	else if (strcmp(k, "bird-routes") == 0)
		path = "arcana-bird:bird/routes";
	else if (strcmp(k, "bird-ospf") == 0)
		path = "arcana-bird:bird/ospf";
	else if (strcmp(k, "traceroute") == 0)
		path = "arcana-troubleshoot:troubleshoot/traceroute";
	else {
		snprintf(act, sizeof(act), "arcana-network:network/%s", k);
		path = act;
	}
	host_yread(s, path, b.s, NULL, user, action_cb, r);
	free(b.s);
}

/* ---- the monitors: arcana-probe's --------------------------------- */

struct mread {
	api_cb		*cb;
	void		*arg;
	char		 sid[9];
	ucl_object_t	*conf;		/* running's probes */
};

/* A monitor's settings as its edge's configuration has them. */
static const ucl_object_t *
monitor_conf(const ucl_object_t *p, const char *jail, const char *id)
{
	const ucl_object_t	*l = NULL, *e;
	ucl_object_iter_t	 it = NULL;

	if (jail == NULL)
		l = jget(p, "monitor");
	else
		while ((e = ucl_object_iterate(jget(p, "jail"), &it, true)) !=
		    NULL)
			if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"),
			    jail) == 0)
				l = jget(e, "monitor");
	it = NULL;
	while (id != NULL && (e = ucl_object_iterate(l, &it, true)) != NULL)
		if (jstr(e, "name") != NULL && strcmp(jstr(e, "name"), id) == 0)
			return (e);
	return (NULL);
}

static void
put_num(ucl_object_t *o, const char *key, const ucl_object_t *from,
    const char *path)
{

	if (jget(from, path) != NULL)
		put(o, key, ucl_object_fromint(jint(from, path, 0)));
}

static void
put_dec(ucl_object_t *o, const char *key, const ucl_object_t *from,
    const char *path)
{

	put(o, key, ucl_object_fromdouble(jnum(from, path, 0)));
}

/* A monitored target as the tabs draw it, c its configuration. */
static ucl_object_t *
target_of(const ucl_object_t *t, const ucl_object_t *c)
{
	static const char *const ints[] = { "fib", "interval", "size", "eval",
	    "dscp", "sent", "received", "misses", NULL };
	const ucl_object_t	*s;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*o, *now, *arr, *row;

	o = ucl_object_typed_new(UCL_OBJECT);
	cp(o, "id", t, "id");
	cp(o, "address", t, "address");
	put(o, "family", ucl_object_fromstring(jstr(t, "family") != NULL &&
	    strcmp(jstr(t, "family"), "ipv6") == 0 ? "inet6" : "inet"));
	cp(o, "jail", t, "jail");
	put(o, "state", ucl_object_fromstring(jstr(t, "state") != NULL ?
	    jstr(t, "state") : "unknown"));
	cp(o, "error", t, "error");
	if (jstr(t, "since") != NULL)
		put(o, "since", ucl_object_fromint(rc_time(jstr(t, "since"))));
	for (size_t i = 0; ints[i] != NULL; i++)
		put_num(o, ints[i], t, ints[i]);
	put_dec(o, "last_rtt", t, "last-rtt");
	if (jget(t, "now") != NULL) {
		now = ucl_object_typed_new(UCL_OBJECT);
		put(now, "sent", ucl_object_fromint(jint(t, "now.sent", 0)));
		put(now, "recv", ucl_object_fromint(jint(t, "now.received", 0)));
		put_dec(now, "delay", t, "now.delay");
		put_dec(now, "ipdv", t, "now.ipdv");
		put_dec(now, "loss", t, "now.loss");
		put_dec(now, "age", t, "now.age");
		put(o, "now", now);
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((s = ucl_object_iterate(jget(t, "sample"), &it, true)) !=
	    NULL) {
		row = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(row, ucl_object_fromint(rc_time(jstr(s,
		    "time"))));
		ucl_array_append(row, ucl_object_fromdouble(jnum(s, "delay",
		    0)));
		ucl_array_append(row, ucl_object_fromdouble(jnum(s, "ipdv",
		    0)));
		ucl_array_append(row, ucl_object_fromdouble(jnum(s, "loss",
		    0)));
		ucl_array_append(row, ucl_object_fromdouble(jnum(s, "min", 0)));
		ucl_array_append(row, ucl_object_fromdouble(jnum(s, "max", 0)));
		ucl_array_append(row, ucl_object_fromint(jint(s, "sent", 0)));
		ucl_array_append(row, ucl_object_fromint(jint(s, "received",
		    0)));
		ucl_array_append(arr, row);
	}
	put(o, "samples", arr);
	put_num(o, "kept", t, "kept");
	if (c != NULL)
		cp(o, "interface", c, "interface");
	/* The settings its edge's configuration has, the prober's own
	 * where it says none. */
	if (c != NULL && (jnum(c, "tca.delay", 0) > 0 || jnum(c, "tca.ipdv",
	    0) > 0 || jnum(c, "tca.loss", 0) > 0)) {
		now = ucl_object_typed_new(UCL_OBJECT);
		put_dec(now, "delay", c, "tca.delay");
		put_dec(now, "ipdv", c, "tca.ipdv");
		put_dec(now, "loss", c, "tca.loss");
		put(now, "damping", ucl_object_fromint(jint(c, "tca.damping",
		    0)));
		put(o, "tca", now);
	}
	put(o, "history", ucl_object_fromint(jint(c, "history", 3600)));
	put(o, "down", ucl_object_fromint(jint(c, "down", 3)));
	put(o, "up", ucl_object_fromint(jint(c, "up", 3)));
	return (o);
}

static void
mread_free(struct mread *m)
{

	if (m->conf != NULL)
		ucl_object_unref(m->conf);
	free(m);
}

static void
probes_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct mread		*m = arg;
	const ucl_object_t	*t;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*top, *arr, *r;

	if (status != 200) {
		m->cb(status, o, err, m->arg);
		mread_free(m);
		return;
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((t = ucl_object_iterate(jget(o, "target"), &it, true)) != NULL)
		ucl_array_append(arr, target_of(t, monitor_conf(m->conf, jstr(t,
		    "jail"), jstr(t, "id"))));
	put(top, "monitors", arr);
	put(top, "time", ucl_object_fromint(jstr(o, "time") != NULL ?
	    rc_time(jstr(o, "time")) : (int64_t)(arc_now() / 1000)));
	put(top, "probing", ucl_object_frombool(jbool(o, "probing")));
	r = ucl_object_typed_new(UCL_OBJECT);
	put(r, "ok", ucl_object_frombool(true));
	put(r, "data", top);
	m->cb(200, r, NULL, m->arg);
	ucl_object_unref(r);
	mread_free(m);
}

/* Running's probes: each monitor's settings. */
static void
mconf_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct mread	*m = arg;
	struct server	*s;

	(void)err;
	if ((s = server_of(m->sid)) == NULL) {
		m->cb(404, NULL, "no such host", m->arg);
		mread_free(m);
		return;
	}
	/* None kept (404): the prober's own settings. */
	m->conf = status == 200 && o != NULL ? ucl_object_copy(o) :
	    ucl_object_typed_new(UCL_OBJECT);
	host_yread(s, "arcana-probe:probes/read", "{\"monitors\":true}", NULL,
	    false, probes_cb, m);
}

/*
 * Host sid's monitors, arcana-probe's read of them with the settings
 * running keeps, as the Tunnel quality and the relay tabs draw them;
 * the callback gets {"ok": true, "data": {"monitors": [...], "time",
 * "probing"}}.
 */
void
monitors_yread(const char *sid, api_cb *cb, void *arg)
{
	struct mread	*m;
	char		 url[300];

	if (server_of(sid) == NULL) {
		cb(404, NULL, "no such host", arg);
		return;
	}
	if ((m = calloc(1, sizeof(*m))) == NULL)
		abort();
	m->cb = cb;
	m->arg = arg;
	snprintf(m->sid, sizeof(m->sid), "%s", sid);
	rc_get(rc_ds(url, sizeof(url), "running", sid, "arcana-probe:probes"),
	    NULL, mconf_cb, m);
}
