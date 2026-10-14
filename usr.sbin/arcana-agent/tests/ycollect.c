/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ycollect: what the YANG collectors find (yang/collect.h), a line an
 * item, for agent_test.sh to set beside ifconfig(8) and netstat(1); and
 * the tree through YANG-CBOR and back, the same bytes.
 *
 *	ycollect interfaces	ietf-interfaces' leaves
 *	ycollect arcif		arcana-interfaces': key=value, '-' for none,
 *				lists joined by '+', bits in hex
 *	ycollect ip		ietf-ip's: v4= and v6= the addresses,
 *				address/length:origin[:status] joined by
 *				'+', ipv6= on/off and its MTU
 *	ycollect ipsys		ietf-ip's host-wide leaves, an interface a
 *				line: fwd4= fwd6= dad= temp= tvl= tpl=
 *				global= (- where absent)
 *	ycollect nb		ietf-ip's neighbours, one a line: the
 *				interface, inet or inet6, the address, the
 *				link-layer address, the origin; an inet6
 *				one's router or -, and state or -
 *	ycollect routes fib	ietf-routing's routes of FIB fib, a next
 *				hop a line: inet or inet6, the prefix, the
 *				gateway, the interface, the special next
 *				hop (- for none each), the source protocol
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "collect.h"

static const char *const lagg_proto[] = { "none", "roundrobin", "failover",
    "loadbalance", "lacp", "broadcast" };
static const char *const media_status[] = { "active", "no-carrier",
    "associated", "running" };

static const char *
str(const char *s)
{

	return (s != NULL ? s : "-");
}

/* A bits value as a number: position n is bit n. */
static uintmax_t
bitsval(const struct cbl_bytes *b)
{
	const uint8_t *p = b->p;
	uintmax_t v = 0;

	for (size_t i = 0; p != NULL && i < b->len && i < sizeof(v); i++)
		v |= (uintmax_t)p[i] << (8 * i);
	return (v);
}

static void
joined(size_t n, const char *const *v)
{

	if (n == 0)
		printf("-");
	for (size_t i = 0; i < n; i++)
		printf("%s%s", i > 0 ? "+" : "", v[i]);
}

/* A medium as ifconfig(8) shows it: subtype[ mode m][ <opts>]. */
static void
mword(const char *subtype, size_t n, const char *const *opt,
    const char *mode)
{

	printf("%s", str(subtype));
	if (mode != NULL)
		printf(" mode %s", mode);
	for (size_t i = 0; i < n; i++)
		printf("%s%s", i == 0 ? " <" : ",", opt[i]);
	if (n > 0)
		printf(">");
}

static void
arcif(const struct ietf_interfaces_interfaces_interface *e)
{
	const struct ietf_interfaces_interfaces_interface_arcif_media *md;

	printf("%s drv=%s", e->name, str(e->arcif_driver_name));
	if (e->has_arcif_mtu)
		printf(" mtu=%u", e->arcif_mtu);
	printf(" ether=%s hw=%s groups=", str(e->arcif_ether),
	    str(e->arcif_hw_address));
	joined(e->arcif_group.n, e->arcif_group.v);
	if (e->has_arcif_fib)
		printf(" fib=%u", e->arcif_fib);
	if (e->has_arcif_tunnel_fib)
		printf(" tunnelfib=%u", e->arcif_tunnel_fib);
	if (e->arcif_capabilities.p != NULL)
		printf(" options=%jx capabilities=%jx",
		    bitsval(&e->arcif_capabilities),
		    bitsval(&e->arcif_capabilities_supported));
	if (e->arcif_vlan != NULL)
		printf(" vlan=%d,%s,%#x,%d", e->arcif_vlan->vlan_id,
		    str(e->arcif_vlan->parent), e->arcif_vlan->protocol,
		    e->arcif_vlan->pcp);
	if (e->arcif_lagg != NULL) {
		printf(" lagg=%s,%jx,", e->arcif_lagg->has_protocol ?
		    lagg_proto[e->arcif_lagg->protocol] : "-",
		    bitsval(&e->arcif_lagg->hash));
		for (size_t i = 0; i < e->arcif_lagg->port.n; i++)
			printf("%s%s:%jx", i > 0 ? "+" : "",
			    e->arcif_lagg->port.v[i].name,
			    bitsval(&e->arcif_lagg->port.v[i].flags));
	}
	if (e->arcif_bridge != NULL) {
		printf(" bridge=");
		if (e->arcif_bridge->member.n == 0)
			printf("-");
		for (size_t i = 0; i < e->arcif_bridge->member.n; i++)
			printf("%s%s:%jx", i > 0 ? "+" : "",
			    e->arcif_bridge->member.v[i].name,
			    bitsval(&e->arcif_bridge->member.v[i].flags));
	}
	if (e->arcif_epair != NULL)
		printf(" epair=%s,%s", str(e->arcif_epair->peer),
		    e->arcif_epair->peer_vnet ? "vnet" : "here");
	/* Last, as it has spaces: what ifconfig(8)'s media and status say. */
	if ((md = e->arcif_media) != NULL) {
		printf(" status=%s media=", md->has_status ?
		    media_status[md->status] : "-");
		mword(md->current->subtype, md->current->option.n,
		    md->current->option.v, md->current->mode);
		printf(" (");
		mword(md->active->subtype, md->active->option.n,
		    md->active->option.v, NULL);
		printf(") supported=");
		joined(md->supported.n, md->supported.v);
	}
	printf("\n");
}

static const char *const origin[] = { "other", "static", "dhcp",
    "link-layer", "random" };
static const char *const v6status[] = { "preferred", "deprecated",
    "invalid", "inaccessible", "unknown", "tentative", "duplicate",
    "optimistic" };

static void
ip(const struct ietf_interfaces_interfaces_interface *e)
{
	const struct ietf_interfaces_interfaces_interface_ip_ipv4 *v4 =
	    e->ip_ipv4;
	const struct ietf_interfaces_interfaces_interface_ip_ipv6 *v6 =
	    e->ip_ipv6;

	printf("%s v4=", e->name);
	if (v4 == NULL || v4->address.n == 0)
		printf("-");
	for (size_t i = 0; v4 != NULL && i < v4->address.n; i++)
		printf("%s%s/%d:%s", i > 0 ? "+" : "", v4->address.v[i].ip,
		    v4->address.v[i].prefix_length,
		    origin[v4->address.v[i].origin]);
	printf(" v6=");
	if (v6 == NULL || v6->address.n == 0)
		printf("-");
	for (size_t i = 0; v6 != NULL && i < v6->address.n; i++)
		printf("%s%s/%d:%s:%s", i > 0 ? "+" : "", v6->address.v[i].ip,
		    v6->address.v[i].prefix_length,
		    origin[v6->address.v[i].origin],
		    v6status[v6->address.v[i].status]);
	if (v6 != NULL)
		printf(" ipv6=%s,%u", v6->enabled ? "on" : "off", v6->mtu);
	else
		printf(" ipv6=-");
	printf("\n");
}

static void
ipsys(const struct ietf_interfaces_interfaces_interface *e)
{
	const struct ietf_interfaces_interfaces_interface_ip_ipv4 *v4 =
	    e->ip_ipv4;
	const struct ietf_interfaces_interfaces_interface_ip_ipv6 *v6 =
	    e->ip_ipv6;
	const struct ietf_interfaces_interfaces_interface_ip_ipv6_autoconf *ac =
	    v6 != NULL ? v6->autoconf : NULL;

	printf("%s fwd4=", e->name);
	printf(v4 != NULL && v4->has_forwarding ? "%d" : "-", v4 != NULL &&
	    v4->forwarding);
	printf(" fwd6=");
	printf(v6 != NULL && v6->has_forwarding ? "%d" : "-", v6 != NULL &&
	    v6->forwarding);
	if (v6 != NULL && v6->has_dup_addr_detect_transmits)
		printf(" dad=%u", v6->dup_addr_detect_transmits);
	else
		printf(" dad=-");
	if (ac != NULL)
		printf(" temp=%d tvl=%u tpl=%u global=%d",
		    ac->create_temporary_addresses,
		    ac->temporary_valid_lifetime,
		    ac->temporary_preferred_lifetime,
		    ac->create_global_addresses);
	else
		printf(" temp=- tvl=- tpl=- global=-");
	printf("\n");
}

static const char *const nb_origin[] = { "other", "static", "dynamic" };
static const char *const nb_state[] = { "incomplete", "reachable", "stale",
    "delay", "probe" };

static void
nb(const struct ietf_interfaces_interfaces_interface *e)
{
	const struct ietf_interfaces_interfaces_interface_ip_ipv4 *v4 =
	    e->ip_ipv4;
	const struct ietf_interfaces_interfaces_interface_ip_ipv6 *v6 =
	    e->ip_ipv6;

	for (size_t i = 0; v4 != NULL && i < v4->neighbor.n; i++)
		printf("%s inet %s %s %s\n", e->name, v4->neighbor.v[i].ip,
		    v4->neighbor.v[i].link_layer_address,
		    nb_origin[v4->neighbor.v[i].origin]);
	for (size_t i = 0; v6 != NULL && i < v6->neighbor.n; i++)
		printf("%s inet6 %s %s %s %s %s\n", e->name,
		    v6->neighbor.v[i].ip,
		    v6->neighbor.v[i].link_layer_address,
		    nb_origin[v6->neighbor.v[i].origin],
		    v6->neighbor.v[i].is_router ? "router" : "-",
		    v6->neighbor.v[i].has_state ?
		    nb_state[v6->neighbor.v[i].state] : "-");
}

static const char *const admin[] = { "?", "up", "down", "testing" };
static const char *const oper[] = { "?", "up", "down", "testing", "unknown",
    "dormant", "not-present", "lower-layer-down" };

/* A leaf-list of names, comma-separated; "-" for none. */
static void
names(const char *what, size_t n, const char *const *v)
{

	printf(" %s=", what);
	if (n == 0)
		printf("-");
	for (size_t i = 0; i < n; i++)
		printf("%s%s", i > 0 ? "," : "", v[i]);
}

static const char *const special[] = { "blackhole", "unreachable",
    "prohibit", "receive" };

static void
routes(int fib, cbl_yarena *a)
{
	struct ietf_routing data = { 0 };
	struct ietf_routing_routing back;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	char why[256];
	int error;

	if ((error = yrt_routing(&data, fib, a)) != 0)
		errc(1, error, "yrt_routing");
	for (size_t i = 0; i < data.routing->ribs->rib.n; i++) {
		const struct ietf_routing_routing_ribs_rib *rib =
		    &data.routing->ribs->rib.v[i];

		for (size_t j = 0; j < rib->routes->route.n; j++) {
			const struct ietf_routing_routing_ribs_rib_routes_route
			    *r = &rib->routes->route.v[j];
			const struct ietf_routing_routing_ribs_rib_routes_route_next_hop
			    *nh = r->next_hop;
			const struct cbl_yident *p = cbl_yschema_ident(
			    &ymodel_schema, r->source_protocol);
			const char *af = i == 0 ? "inet" : "inet6";
			const char *dst = i == 0 ? r->v4ur_destination_prefix :
			    r->v6ur_destination_prefix;

			if (nh->next_hop_list != NULL) {
				for (size_t k = 0; k < nh->next_hop_list->
				    next_hop.n; k++) {
					const struct ietf_routing_routing_ribs_rib_routes_route_next_hop_next_hop_list_next_hop
					    *m = &nh->next_hop_list->next_hop.v[k];

					printf("%s %s %s %s - %s\n", af, dst,
					    str(i == 0 ? m->v4ur_address :
					    m->v6ur_address),
					    str(m->outgoing_interface),
					    p != NULL ? p->name : "-");
				}
				continue;
			}
			printf("%s %s %s %s %s %s\n", af, dst, str(i == 0 ?
			    nh->v4ur_next_hop_address :
			    nh->v6ur_next_hop_address),
			    str(nh->outgoing_interface),
			    nh->has_special_next_hop ?
			    special[nh->special_next_hop] : "-",
			    p != NULL ? p->name : "-");
		}
	}
	if (ietf_routing_routing_encode(data.routing, &b1) != 0)
		errx(1, "encode");
	if (ietf_routing_routing_decode(b1.p, b1.len, &back, a, CBL_YD_STRICT,
	    why, sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	if (ietf_routing_routing_encode(&back, &b2) != 0)
		errx(1, "encode again");
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" : "not the same");
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
}

static void
roundtrip(const struct ietf_interfaces_interfaces *ifs, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces back;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	char why[256];

	if (ietf_interfaces_interfaces_encode(ifs, &b1) != 0)
		errx(1, "encode");
	if (ietf_interfaces_interfaces_decode(b1.p, b1.len, &back, a,
	    CBL_YD_STRICT, why, sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	if (ietf_interfaces_interfaces_encode(&back, &b2) != 0)
		errx(1, "encode again");
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" : "not the same");
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
}

int
main(int argc, char **argv)
{
	struct ietf_interfaces data = { 0 };
	cbl_yarena *a;
	int error;

	if (argc == 3 && strcmp(argv[1], "routes") == 0) {
		if ((a = cbl_yarena_new()) == NULL)
			err(1, "cbl_yarena_new");
		routes(atoi(argv[2]), a);
		cbl_yarena_free(a);
		return (0);
	}
	if (argc != 2 || (strcmp(argv[1], "interfaces") != 0 &&
	    strcmp(argv[1], "arcif") != 0 && strcmp(argv[1], "ip") != 0 &&
	    strcmp(argv[1], "nb") != 0 && strcmp(argv[1], "ipsys") != 0)) {
		fprintf(stderr, "usage: ycollect interfaces | arcif | ip | "
		    "ipsys | nb | routes fib\n");
		return (2);
	}
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if ((error = yif_interfaces(&data, a)) != 0)
		errc(1, error, "yif_interfaces");
	for (size_t i = 0; i < data.interfaces->interface.n; i++) {
		const struct ietf_interfaces_interfaces_interface *e =
		    &data.interfaces->interface.v[i];

		if (strcmp(argv[1], "arcif") == 0) {
			arcif(e);
			continue;
		}
		if (strcmp(argv[1], "ip") == 0) {
			ip(e);
			continue;
		}
		if (strcmp(argv[1], "nb") == 0) {
			nb(e);
			continue;
		}
		if (strcmp(argv[1], "ipsys") == 0) {
			ipsys(e);
			continue;
		}
		const struct cbl_yident *t = e->has_type ?
		    cbl_yschema_ident(&ymodel_schema, e->type) : NULL;
		printf("%s index=%d admin=%s oper=%s type=%s phys=%s "
		    "in-octets=%ju out-octets=%ju", e->name, e->if_index,
		    admin[e->admin_status], oper[e->oper_status],
		    t != NULL ? t->name : "-",
		    e->phys_address != NULL ? e->phys_address : "-",
		    (uintmax_t)e->statistics->in_octets,
		    (uintmax_t)e->statistics->out_octets);
		names("lower", e->lower_layer_if.n, e->lower_layer_if.v);
		names("higher", e->higher_layer_if.n, e->higher_layer_if.v);
		printf("\n");
	}
	roundtrip(data.interfaces, a);
	cbl_yarena_free(a);
	return (0);
}
