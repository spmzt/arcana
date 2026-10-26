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
 *	ycollect arcif		arcana-interfaces', and the standard leaves
 *				for what it once had (frame= max-frame-size,
 *				mac= and bia= ethernet-like's, peer=
 *				peer-interface, vlan= the tag, parent,
 *				tag type and priority, lagg= and aggport=
 *				IEEE 802.1AX's and FreeBSD's, bport= and
 *				rstp= IEEE 802.1Q's and FreeBSD's, eth= IEEE
 *				802.3's
 *				auto-negotiation, duplex and PMD type):
 *				key=value, '-' for none,
 *				lists joined by '+', bits in hex
 *	ycollect ip		ietf-ip's: v4= and v6= the addresses,
 *				address/length:origin[:status] joined by
 *				'+', mtu4= ipv4's MTU (the link's), ipv6=
 *				on/off and its MTU
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
 *				hop (- for none each), the source protocol,
 *				and multipath for one of a next-hop-list
 *	ycollect lne		the logical network elements, a name a
 *				line, and managed or not
 *	ycollect watch fib secs	routes', each with its last-updated (- for
 *				none), after secs of route events heard
 *				and noted as the daemon notes them
 *	ycollect linkagg	IEEE 802.1AX's linkagg: a key group a line,
 *				its system's address and priority, its lags
 *				and aggports; the tree through YANG-CBOR and
 *				back
 *	ycollect bridges	IEEE 802.1Q's bridges: one a line, its
 *				address, type, component's type and ports;
 *				the tree through YANG-CBOR and back
 *	ycollect pmd name ...	each medium's IEEE 802.3 PMD type, a line:
 *				the name, the identity (- for none)
 *	ycollect origins	each netlink(4) origin's source-protocol,
 *				a line: the RTPROT_ number, with a gateway
 *				or not (gw, -), and the identity, module:name,
 *				of an IPv4 route, then of an IPv6 one
 *	ycollect active fib addr	the RIB's active-route action for addr,
 *				its route a line as routes' (none: "none");
 *				and its output through YANG-CBOR and back
 */

#include <sys/param.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "collect.h"
#include "rtimes.h"

#include <sys/socket.h>
#include <poll.h>
#include <time.h>
#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route.h>
#include <netlink/netlink_snl_route_parsers.h>

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
	if (e->has_if_ext_max_frame_size)
		printf(" frame=%u", e->if_ext_max_frame_size);
	if (e->ethlike_ethernet_like != NULL)
		printf(" mac=%s bia=%s",
		    str(e->ethlike_ethernet_like->mac_address),
		    str(e->ethlike_ethernet_like->bia_mac_address));
	printf(" groups=");
	joined(e->arcif_group.n, e->arcif_group.v);
	if (e->has_arcif_tunnel_fib)
		printf(" tunnelfib=%u", e->arcif_tunnel_fib);
	if (e->arcif_capabilities.p != NULL)
		printf(" options=%jx capabilities=%jx",
		    bitsval(&e->arcif_capabilities),
		    bitsval(&e->arcif_capabilities_supported));
	if (e->if_ext_encapsulation != NULL &&
	    e->if_ext_encapsulation->if_vlan_dot1q_vlan != NULL) {
		const struct ietf_interfaces_interfaces_interface_if_ext_encapsulation_if_vlan_dot1q_vlan
		    *dv = e->if_ext_encapsulation->if_vlan_dot1q_vlan;
		const struct cbl_yident *tt = dv->outer_tag != NULL ?
		    cbl_yschema_ident(&ymodel_schema,
		    dv->outer_tag->tag_type) : NULL;

		printf(" vlan=%d,%s,%s,", dv->outer_tag != NULL ?
		    dv->outer_tag->vlan_id : 0,
		    str(e->if_ext_parent_interface), tt != NULL ? tt->name :
		    "-");
		if (dv->has_arcif_pcp)
			printf("%d", dv->arcif_pcp);
		else
			printf("-");
	}
	if (e->dot1ax_lag != NULL) {
		printf(" lagg=%s,%jx,%s", e->dot1ax_lag->has_arcif_protocol ?
		    lagg_proto[e->dot1ax_lag->arcif_protocol] : "-",
		    bitsval(&e->dot1ax_lag->arcif_hash),
		    str(e->dot1ax_lag->mac_address));
		if (e->dot1ax_lag->lacp != NULL)
			printf(",key=%u", e->dot1ax_lag->lacp->actor_oper_key);
	}
	if (e->dot1ax_aggport != NULL) {
		const struct ietf_interfaces_interfaces_interface_dot1ax_aggport
		    *ap = e->dot1ax_aggport;

		printf(" aggport=%s,%u:%jx", ap->key_group_name,
		    ap->arcif_priority, bitsval(&ap->arcif_flags));
		if (ap->lacp != NULL)
			printf(",port=%u,state=%jx", ap->actor_port_number,
			    bitsval(&ap->lacp->actor_oper_state));
	}
	if (e->dot1q_bridge_port != NULL) {
		const struct ietf_interfaces_interfaces_interface_dot1q_bridge_port
		    *bp = e->dot1q_bridge_port;
		const struct ietf_interfaces_interfaces_interface_dot1q_bridge_port_rstp_bridge_rstp
		    *rs = bp->rstp_bridge_rstp;
		static const char *const p2p[] = { "-", "force-true",
		    "force-false", "auto" };
		static const char *const state[] = { "-", "discarding",
		    "learning", "forwarding" };
		static const char *const role[] = { "-", "disabled", "root",
		    "designated", "alternate", "backup" };

		printf(" bport=%s,%u,%s/%s,%jx", bp->bridge_name,
		    bp->port_number, p2p[bp->admin_point_to_point],
		    bp->oper_point_to_point ? "on" : "off",
		    bitsval(&bp->arcif_flags));
		if (rs != NULL)
			printf(" rstp=%s,%s,%u/%u/%u,%u/%s,edge=%d/%d/%d",
			    rs->has_port_state ? state[rs->port_state] : "-",
			    rs->has_port_role ? role[rs->port_role] : "-",
			    rs->port_id->port_priority,
			    rs->port_id->port_number, rs->port_id->port_id,
			    rs->port_path_cost, rs->has_fix_port_path_cost ?
			    "fixed" : "auto", rs->admin_edge_port,
			    rs->oper_edge_port, rs->auto_edge_port);
	}
	if (e->ieee802_eth_if_ethernet != NULL) {
		const struct ietf_interfaces_interfaces_interface_ieee802_eth_if_ethernet
		    *eth = e->ieee802_eth_if_ethernet;
		const struct cbl_yident *pmd = eth->has_pmd_type ?
		    cbl_yschema_ident(&ymodel_schema, eth->pmd_type) : NULL;
		static const char *const dup[] = { "full", "half", "unknown" };
		static const char *const neg[] = { "in-progress", "complete",
		    "failed", "unknown", "no-negotiation" };

		printf(" eth=");
		if (eth->auto_negotiation == NULL)
			printf("-");
		else if (!eth->auto_negotiation->enable)
			printf("fixed");
		else
			printf("auto:%s", eth->auto_negotiation->
			    has_negotiation_status ? neg[eth->auto_negotiation->
			    negotiation_status] : "-");
		printf(",%s,%s", eth->has_duplex ? dup[eth->duplex] : "-",
		    pmd != NULL ? pmd->name + strlen("pmd-type-") : "-");
	}
	if (e->if_ext_peer_interface != NULL)
		printf(" peer=%s", e->if_ext_peer_interface);
	if (e->has_arcif_peer_vnet && e->arcif_peer_vnet)
		printf(" peer=vnet");
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
	if (v4 != NULL && v4->has_mtu)
		printf(" mtu4=%u", v4->mtu);
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

/* RFC 8530's: the vnet jails. */
static void
lne(cbl_yarena *a)
{
	const struct ietf_logical_network_element_logical_network_elements *l;
	struct ietf_logical_network_element_logical_network_elements back;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	char why[256];
	int error;

	if ((error = ylne_elements(a, &l)) != 0)
		errc(1, error, "ylne_elements");
	for (size_t i = 0; i < l->logical_network_element.n; i++)
		printf("%s %s\n", l->logical_network_element.v[i].name,
		    l->logical_network_element.v[i].managed ? "managed" :
		    "unmanaged");
	if (ietf_logical_network_element_logical_network_elements_encode(l,
	    &b1) != 0)
		errx(1, "encode");
	if (ietf_logical_network_element_logical_network_elements_decode(b1.p,
	    b1.len, &back, a, CBL_YD_STRICT, why, sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	if (ietf_logical_network_element_logical_network_elements_encode(&back,
	    &b2) != 0)
		errx(1, "encode again");
	printf("yang-cbor %s\n", b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" : "not the same");
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
}

static bool with_times;

/* Route events for secs, noted as nlroute.c's watcher notes them. */
static void
watch(int secs)
{
	static const int groups[] = { RTNLGRP_IPV4_ROUTE,
	    RTNLGRP_IPV6_ROUTE };
	struct snl_state ss;
	struct nlmsghdr *hdr;
	time_t end = time(NULL) + secs;

	if (!snl_init(&ss, NETLINK_ROUTE))
		err(1, "snl_init");
	for (size_t i = 0; i < nitems(groups); i++)
		if (setsockopt(ss.fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		    &groups[i], sizeof(groups[i])) == -1)
			err(1, "NETLINK_ADD_MEMBERSHIP");
	printf("watching\n");
	fflush(stdout);
	while (time(NULL) < end) {
		struct pollfd pfd = { .fd = ss.fd, .events = POLLIN };

		if (poll(&pfd, 1, 200) <= 0)
			continue;
		if ((hdr = snl_read_message(&ss)) == NULL)
			continue;
		if (hdr->nlmsg_type == NL_RTM_NEWROUTE ||
		    hdr->nlmsg_type == NL_RTM_DELROUTE) {
			struct snl_parsed_route p = { 0 };
			char prefix[64];

			if (snl_parse_nlmsg(&ss, hdr, &snl_rtm_route_parser,
			    &p)) {
				rt_prefix(prefix, sizeof(prefix), p.rta_dst,
				    p.rtm_family, p.rtm_dst_len);
				rt_touched(p.rta_table, prefix, time(NULL),
				    hdr->nlmsg_type == NL_RTM_DELROUTE);
			}
		}
		snl_clear_lb(&ss);
	}
	snl_free(&ss);
}

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

					printf("%s %s %s %s - %s multipath%s%s\n",
					    af, dst,
					    str(i == 0 ? m->v4ur_address :
					    m->v6ur_address),
					    str(m->outgoing_interface),
					    p != NULL ? p->name : "-",
					    with_times ? " " : "", with_times ?
					    str(r->last_updated) : "");
				}
				continue;
			}
			printf("%s %s %s %s %s %s -%s%s\n", af, dst, str(i ==
			    0 ? nh->v4ur_next_hop_address :
			    nh->v6ur_next_hop_address),
			    str(nh->outgoing_interface),
			    nh->has_special_next_hop ?
			    special[nh->special_next_hop] : "-",
			    p != NULL ? p->name : "-", with_times ? " " : "",
			    with_times ? str(r->last_updated) : "");
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
active(int fib, const char *addr, cbl_yarena *a)
{
	struct ietf_routing_routing_ribs_rib_active_route_input in = { 0 };
	struct ietf_routing_routing_ribs_rib_active_route_output out, back;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	const struct ietf_routing_routing_ribs_rib_active_route_output_route
	    *r;
	char why[256];
	bool v6 = strchr(addr, ':') != NULL;
	int error;

	if (v6)
		in.v6ur_destination_address = addr;
	else
		in.v4ur_destination_address = addr;
	if ((error = yrt_active_route(fib, &in, a, &out)) != 0)
		errc(1, error, "yrt_active_route");
	if ((r = out.route) == NULL)
		printf("none\n");
	else {
		const struct cbl_yident *p = cbl_yschema_ident(&ymodel_schema,
		    r->source_protocol);
		const struct ietf_routing_routing_ribs_rib_active_route_output_route_next_hop
		    *nh = r->next_hop;

		if (nh->next_hop_list != NULL)
			for (size_t k = 0; k < nh->next_hop_list->next_hop.n;
			    k++)
				printf("%s %s %s %s - %s multipath\n",
				    v6 ? "inet6" : "inet", v6 ?
				    r->v6ur_destination_prefix :
				    r->v4ur_destination_prefix, str(v6 ?
				    nh->next_hop_list->next_hop.v[k].v6ur_next_hop_address :
				    nh->next_hop_list->next_hop.v[k].v4ur_next_hop_address),
				    str(nh->next_hop_list->next_hop.v[k].outgoing_interface),
				    p != NULL ? p->name : "-");
		else
			printf("%s %s %s %s %s %s -\n", v6 ? "inet6" : "inet",
			    v6 ? r->v6ur_destination_prefix :
			    r->v4ur_destination_prefix, str(v6 ?
			    nh->v6ur_next_hop_address :
			    nh->v4ur_next_hop_address),
			    str(nh->outgoing_interface),
			    nh->has_special_next_hop ?
			    special[nh->special_next_hop] : "-",
			    p != NULL ? p->name : "-");
	}
	if (ietf_routing_routing_ribs_rib_active_route_output_encode(&out,
	    &b1) != 0)
		errx(1, "encode");
	if (ietf_routing_routing_ribs_rib_active_route_output_decode(b1.p,
	    b1.len, &back, a, CBL_YD_STRICT, why, sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	if (ietf_routing_routing_ribs_rib_active_route_output_encode(&back,
	    &b2) != 0)
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

	if (argc == 2 && strcmp(argv[1], "lne") == 0) {
		if ((a = cbl_yarena_new()) == NULL)
			err(1, "cbl_yarena_new");
		lne(a);
		cbl_yarena_free(a);
		return (0);
	}
	if (argc == 4 && strcmp(argv[1], "watch") == 0) {
		if ((a = cbl_yarena_new()) == NULL)
			err(1, "cbl_yarena_new");
		watch(atoi(argv[3]));
		with_times = true;
		routes(atoi(argv[2]), a);
		cbl_yarena_free(a);
		return (0);
	}
	if (argc == 4 && strcmp(argv[1], "active") == 0) {
		if ((a = cbl_yarena_new()) == NULL)
			err(1, "cbl_yarena_new");
		active(atoi(argv[2]), argv[3], a);
		cbl_yarena_free(a);
		return (0);
	}
	if (argc == 2 && strcmp(argv[1], "linkagg") == 0) {
		struct ieee802_dot1ax_linkagg la;
		struct ieee802_dot1ax_linkagg_linkagg back;
		struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
		char why[256];

		if ((a = cbl_yarena_new()) == NULL)
			err(1, "cbl_yarena_new");
		if ((error = yif_interfaces(&data, NULL, a)) != 0 ||
		    (error = yif_linkagg(data.interfaces->interface.v,
		    data.interfaces->interface.n, a, &la)) != 0)
			errc(1, error, "yif_linkagg");
		for (size_t i = 0; i < la.linkagg->key_group.n; i++) {
			const struct ieee802_dot1ax_linkagg_linkagg_key_group
			    *k = &la.linkagg->key_group.v[i];
			const struct ieee802_dot1ax_linkagg_linkagg_agg_system
			    *sy = &la.linkagg->agg_system.v[i];

			printf("%s system=%s,%s,", k->name, sy->name,
			    str(sy->actor_system));
			if (sy->has_actor_system_priority)
				printf("%u", sy->actor_system_priority);
			else
				printf("-");
			printf(" lags=");
			joined(k->lags.n, k->lags.v);
			printf(" aggports=");
			joined(k->aggports.n, k->aggports.v);
			printf("\n");
		}
		if (ieee802_dot1ax_linkagg_linkagg_encode(la.linkagg, &b1) != 0 ||
		    ieee802_dot1ax_linkagg_linkagg_decode(b1.p, b1.len, &back,
		    a, CBL_YD_STRICT, why, sizeof(why)) != 0 ||
		    ieee802_dot1ax_linkagg_linkagg_encode(&back, &b2) != 0)
			errx(1, "the round trip: %s", why);
		printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
		    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" :
		    "not the same");
		return (0);
	}
	if (argc == 2 && strcmp(argv[1], "bridges") == 0) {
		struct ieee802_dot1q_bridge bd;
		struct ieee802_dot1q_bridge_bridges back;
		struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
		char why[256];

		if ((a = cbl_yarena_new()) == NULL)
			err(1, "cbl_yarena_new");
		if ((error = yif_interfaces(&data, NULL, a)) != 0 ||
		    (error = yif_bridges(data.interfaces->interface.v,
		    data.interfaces->interface.n, a, &bd)) != 0)
			errc(1, error, "yif_bridges");
		for (size_t i = 0; i < bd.bridges->bridge.n; i++) {
			const struct ieee802_dot1q_bridge_bridges_bridge *b =
			    &bd.bridges->bridge.v[i];
			const struct ieee802_dot1q_bridge_bridges_bridge_component
			    *c = &b->component.v[0];
			const struct cbl_yident *bt = cbl_yschema_ident(
			    &ymodel_schema, b->bridge_type), *ct =
			    cbl_yschema_ident(&ymodel_schema, c->type);

			printf("%s address=%s type=%s component=%s,%s ports=",
			    b->name, str(b->address), bt != NULL ? bt->name :
			    "-", c->name, ct != NULL ? ct->name : "-");
			joined(c->bridge_port.n, c->bridge_port.v);
			printf("\n");
		}
		if (ieee802_dot1q_bridge_bridges_encode(bd.bridges, &b1) != 0 ||
		    ieee802_dot1q_bridge_bridges_decode(b1.p, b1.len, &back, a,
		    CBL_YD_STRICT, why, sizeof(why)) != 0 ||
		    ieee802_dot1q_bridge_bridges_encode(&back, &b2) != 0)
			errx(1, "the round trip: %s", why);
		printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
		    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" :
		    "not the same");
		return (0);
	}
	if (argc >= 2 && strcmp(argv[1], "pmd") == 0) {
		for (int i = 2; i < argc; i++) {
			const struct cbl_yident *id = cbl_yschema_ident(
			    &ymodel_schema, yif_pmd(argv[i]));

			printf("%s %s\n", argv[i], id != NULL ? id->name : "-");
		}
		return (0);
	}
	if (argc == 2 && strcmp(argv[1], "origins") == 0) {
		static const uint8_t protos[] = { RTPROT_UNSPEC,
		    RTPROT_REDIRECT, RTPROT_KERNEL, RTPROT_BOOT,
		    RTPROT_STATIC, RTPROT_RA, RTPROT_ZEBRA, RTPROT_BIRD,
		    RTPROT_DHCP, RTPROT_BABEL, RTPROT_BGP, RTPROT_ISIS,
		    RTPROT_OSPF, RTPROT_RIP };

		for (size_t i = 0; i < nitems(protos); i++)
			for (int gw = 0; gw < 2; gw++) {
				printf("%u %s", protos[i], gw ? "gw" : "-");
				for (int v6 = 0; v6 < 2; v6++) {
					const struct cbl_yident *id =
					    cbl_yschema_ident(&ymodel_schema,
					    yrt_origin(protos[i], gw, v6));

					printf(" %s:%s", id != NULL ?
					    id->module->name : "-", id != NULL ?
					    id->name : "-");
				}
				printf("\n");
			}
		return (0);
	}
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
	if ((error = yif_interfaces(&data, NULL, a)) != 0)
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
