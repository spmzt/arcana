/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: ietf-routing's RIBs (RFC 8349), a FIB's
 * routes as netlink(4) dumps them (RTM_GETROUTE with RTA_TABLE, as
 * netstat(1) asks), into /routing/ribs: ipv4-master and ipv6-master, the
 * FIB's two tables; another FIB's are its network instance's (2.6).
 *
 * - destination-prefix, v4ur's or v6ur's: the address and its length,
 *   a link-local one without its zone, which a prefix cannot have.
 * - next-hop: a multipath route's next-hop-list (RTA_MULTIPATH); a
 *   blackhole (RTF_BLACKHOLE) or reject (RTF_REJECT, answered with ICMP
 *   unreachable) route's special next hop, and receive for a host route
 *   to the loopback without a gateway, an address of the host's own;
 *   else the outgoing interface and, a gateway being an address, it,
 *   a link-local one with its zone.
 * - source-protocol: from the route's origin (rtm_protocol): static, or
 *   the kernel's own without a gateway, an interface's network, direct;
 *   OSPF's, RIP's, IS-IS's, Babel's and BGP's their modules' identities
 *   (ietf-ospf, ietf-rip, ietf-isis, ietf-babel, ietf-bgp); the others
 *   arcana-routing's.
 * - active: every route netlink dumps is in the FIB, used.
 * - last-updated: when a route event last told of it (rtimes.c); the
 *   kernel keeps no such time, so none for a route not seen to change.
 * - route-preference: FreeBSD has none.
 *
 * The RIB's active-route action (2.4.5): the route a destination
 * address goes by, as route(8)'s get asks netlink(4) for it
 * (RTM_GETROUTE of the address, the longest match), the same leaves.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route.h>
#include <netlink/netlink_snl_route_parsers.h>
/* RTF_*, as netlink(4) has them with <net/route.h>'s. */
#include <netlink/netlink_snl_route_compat.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_schema.h"
#include "collect.h"
#include "rtimes.h"

typedef struct ietf_routing_routing_ribs_rib yrib;
typedef struct ietf_routing_routing_ribs_rib_routes_route yroute;
typedef struct ietf_routing_routing_ribs_rib_routes_route_next_hop ynh;
typedef struct ietf_routing_routing_ribs_rib_routes_route_next_hop_next_hop_list_next_hop
    ynhl;

#define	NH(x)	IETF_ROUTING_ROUTING_RIBS_RIB_ROUTES_ROUTE_NEXT_HOP_##x

/* An identity's SID, by its module and name; 0: none. */
static uint64_t
ident(const char *mod, const char *name)
{

	for (uint32_t i = 0; i < ymodel_schema.nident; i++) {
		const struct cbl_yident *id = &ymodel_schema.ident[i];

		if (strcmp(id->name, name) == 0 &&
		    strcmp(id->module->name, mod) == 0)
			return (id->sid);
	}
	return (0);
}

/*
 * rtm_protocol's identity: RFC 8349's two, a routing protocol's own
 * module's (OSPF and RIP by the version that carries the family, v6:
 * an IPv6 route), else arcana-routing's.
 */
uint64_t
yrt_origin(uint8_t proto, bool gateway, bool v6)
{
	static const struct {
		uint8_t		 proto;
		const char	*name;
	} names[] = {
		{ RTPROT_REDIRECT, "redirect" },
		{ RTPROT_RA, "router-advertisement" },
		{ RTPROT_DHCP, "dhcp" },
		{ RTPROT_ZEBRA, "zebra" },
		{ RTPROT_BIRD, "bird" },
	};

	if (proto == RTPROT_STATIC || proto == RTPROT_BOOT)
		return (ident("ietf-routing", "static"));
	if (proto == RTPROT_KERNEL)
		return (gateway ? ident("arcana-routing", "kernel") :
		    ident("ietf-routing", "direct"));
	if (proto == RTPROT_OSPF)
		return (ident("ietf-ospf", v6 ? "ospfv3" : "ospfv2"));
	if (proto == RTPROT_RIP)
		return (ident("ietf-rip", v6 ? "ripng" : "ripv2"));
	if (proto == RTPROT_ISIS)
		return (ident("ietf-isis", "isis"));
	if (proto == RTPROT_BABEL)
		return (ident("ietf-babel", "babel"));
	if (proto == RTPROT_BGP)
		return (ident("ietf-bgp", "bgp"));
	for (size_t i = 0; i < nitems(names); i++)
		if (names[i].proto == proto)
			return (ident("arcana-routing", names[i].name));
	return (ident("arcana-routing", "other"));
}

static char *
astrdup(cbl_yarena *a, const char *s)
{
	size_t len = strlen(s) + 1;
	char *p;

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

/*
 * An address as text: a link-local IPv6 one with its zone if zone,
 * the interface its scope or ifindex names; NULL if it is no address.
 */
static char *
addr(cbl_yarena *a, const struct sockaddr *sa, uint32_t ifindex, bool zone)
{
	char buf[INET6_ADDRSTRLEN + IF_NAMESIZE + 2], ifn[IF_NAMESIZE];

	if (sa == NULL)
		return (NULL);
	if (sa->sa_family == AF_INET)
		inet_ntop(AF_INET, &((const struct sockaddr_in *)(const void *)
		    sa)->sin_addr, buf, sizeof(buf));
	else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *s6 = (const void *)sa;
		struct in6_addr in6 = s6->sin6_addr;
		bool ll = IN6_IS_ADDR_LINKLOCAL(&in6);

		if (ll)
			in6.s6_addr[2] = in6.s6_addr[3] = 0;
		inet_ntop(AF_INET6, &in6, buf, sizeof(buf));
		if (ll && zone && if_indextoname(s6->sin6_scope_id != 0 ?
		    s6->sin6_scope_id : ifindex, ifn) != NULL) {
			strlcat(buf, "%", sizeof(buf));
			strlcat(buf, ifn, sizeof(buf));
		}
	} else
		return (NULL);
	return (astrdup(a, buf));
}

static const char *
ifname(cbl_yarena *a, uint32_t ifindex)
{
	char ifn[IF_NAMESIZE];

	return (ifindex != 0 && if_indextoname(ifindex, ifn) != NULL ?
	    astrdup(a, ifn) : NULL);
}

/* Whether ifindex is a loopback interface. */
static bool
loopback(uint32_t ifindex)
{
	char ifn[IF_NAMESIZE];

	return (if_indextoname(ifindex, ifn) != NULL &&
	    strncmp(ifn, "lo", 2) == 0);
}

/* A route as the RIB has it: its prefix and next hops, into r. */
static int
route(cbl_yarena *a, int fib, const struct snl_parsed_route *p, yroute *r)
{
	char buf[INET6_ADDRSTRLEN + 8];
	const char *dst;
	ynh *nh;
	bool v6 = p->rtm_family == AF_INET6, gw;

	if ((nh = cbl_yarena_alloc(a, sizeof(*nh))) == NULL)
		return (ENOMEM);
	memset(nh, 0, sizeof(*nh));
	r->next_hop = nh;
	/* The default route: no destination. */
	dst = p->rta_dst != NULL ? addr(a, p->rta_dst, 0, false) : v6 ?
	    "::" : "0.0.0.0";
	if (dst == NULL)
		return (EINVAL);
	snprintf(buf, sizeof(buf), "%s/%u", dst, p->rtm_dst_len);
	if (v6)
		r->v6ur_destination_prefix = astrdup(a, buf);
	else
		r->v4ur_destination_prefix = astrdup(a, buf);
	{
		time_t when;
		struct tm tm;
		char t[32];

		/* yang:date-and-time, in UTC. */
		if (rt_last((uint32_t)fib, buf, &when) &&
		    gmtime_r(&when, &tm) != NULL &&
		    strftime(t, sizeof(t), "%Y-%m-%dT%H:%M:%SZ", &tm) > 0)
			r->last_updated = astrdup(a, t);
	}
	gw = p->rta_gw != NULL && (p->rta_gw->sa_family == AF_INET ||
	    p->rta_gw->sa_family == AF_INET6);
	r->active = true;
	r->has_source_protocol = true;
	r->source_protocol = yrt_origin(p->rtm_protocol, gw ||
	    p->rta_multipath.count > 0, v6);
	if (p->rta_multipath.count > 0) {
		struct ietf_routing_routing_ribs_rib_routes_route_next_hop_next_hop_list
		    *l;
		ynhl *v;

		if ((l = cbl_yarena_alloc(a, sizeof(*l))) == NULL ||
		    (v = cbl_yarena_alloc(a, p->rta_multipath.count *
		    sizeof(*v))) == NULL)
			return (ENOMEM);
		memset(l, 0, sizeof(*l));
		memset(v, 0, p->rta_multipath.count * sizeof(*v));
		for (uint32_t i = 0; i < p->rta_multipath.count; i++) {
			const struct rta_mpath_nh *m =
			    p->rta_multipath.items[i];

			v[i].outgoing_interface = ifname(a, m->ifindex);
			if (v6)
				v[i].v6ur_address = addr(a, m->gw, m->ifindex,
				    true);
			else
				v[i].v4ur_address = addr(a, m->gw, m->ifindex,
				    true);
		}
		l->next_hop.n = p->rta_multipath.count;
		l->next_hop.v = v;
		nh->next_hop_options = NH(NEXT_HOP_OPTIONS_NEXT_HOP_LIST);
		nh->next_hop_list = l;
		return (0);
	}
	if (p->rta_rtflags & (RTF_BLACKHOLE | RTF_REJECT) || (!gw &&
	    (p->rta_rtflags & RTF_HOST) && loopback(p->rta_oif))) {
		nh->next_hop_options = NH(NEXT_HOP_OPTIONS_SPECIAL_NEXT_HOP);
		nh->has_special_next_hop = true;
		nh->special_next_hop = p->rta_rtflags & RTF_BLACKHOLE ?
		    NH(SPECIAL_NEXT_HOP_BLACKHOLE) : p->rta_rtflags &
		    RTF_REJECT ? NH(SPECIAL_NEXT_HOP_UNREACHABLE) :
		    NH(SPECIAL_NEXT_HOP_RECEIVE);
		return (0);
	}
	nh->next_hop_options = NH(NEXT_HOP_OPTIONS_SIMPLE_NEXT_HOP);
	nh->outgoing_interface = ifname(a, p->rta_oif);
	if (gw) {
		if (v6)
			nh->v6ur_next_hop_address = addr(a, p->rta_gw,
			    p->rta_oif, true);
		else
			nh->v4ur_next_hop_address = addr(a, p->rta_gw,
			    p->rta_oif, true);
	}
	return (0);
}

/* A family's routes of FIB fib, into rib. */
static int
dump(cbl_yarena *a, int fib, int af, yrib *rib)
{
	struct {
		struct nlmsghdr	hdr;
		struct rtmsg	rtm;
		struct nlattr	nla;
		uint32_t	fib;
	} msg;
	struct snl_errmsg_data e = { 0 };
	struct snl_state ss;
	struct nlmsghdr *hdr;
	yroute *v = NULL, *nv;
	size_t n = 0, max = 0;
	int error = 0;

	if (!snl_init(&ss, NETLINK_ROUTE))
		return (errno != 0 ? errno : EIO);
	memset(&msg, 0, sizeof(msg));
	msg.hdr.nlmsg_type = RTM_GETROUTE;
	msg.hdr.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	msg.hdr.nlmsg_seq = snl_get_seq(&ss);
	msg.hdr.nlmsg_len = sizeof(msg);
	msg.rtm.rtm_family = af;
	msg.nla.nla_len = sizeof(struct nlattr) + sizeof(uint32_t);
	msg.nla.nla_type = RTA_TABLE;
	msg.fib = (uint32_t)fib;
	if (!snl_send_message(&ss, &msg.hdr)) {
		snl_free(&ss);
		return (errno != 0 ? errno : EIO);
	}
	while (error == 0 && (hdr = snl_read_reply_multi(&ss,
	    msg.hdr.nlmsg_seq, &e)) != NULL) {
		struct snl_parsed_route p = { 0 };

		if (!snl_parse_nlmsg(&ss, hdr, &snl_rtm_route_parser, &p) ||
		    p.rtm_family != af) {
			snl_clear_lb(&ss);
			continue;
		}
		if (n == max) {
			max = max > 0 ? max * 2 : 64;
			if ((nv = cbl_yarena_alloc(a, max * sizeof(*nv))) ==
			    NULL) {
				error = ENOMEM;
				break;
			}
			if (n > 0)
				memcpy(nv, v, n * sizeof(*nv));
			v = nv;
		}
		memset(&v[n], 0, sizeof(v[n]));
		if ((error = route(a, fib, &p, &v[n])) == 0)
			n++;
		snl_clear_lb(&ss);
	}
	if (error == 0 && e.error != 0)
		error = e.error;
	snl_free(&ss);
	if (error != 0)
		return (error);
	{
		struct ietf_routing_routing_ribs_rib_routes *rs;

		if ((rs = cbl_yarena_alloc(a, sizeof(*rs))) == NULL)
			return (ENOMEM);
		memset(rs, 0, sizeof(*rs));
		rs->route.n = n;
		rs->route.v = v;
		rib->routes = rs;
	}
	return (0);
}

int
yrt_routing(struct ietf_routing *data, int fib, cbl_yarena *a)
{
	struct ietf_routing_routing *rt;
	struct ietf_routing_routing_ribs *ribs;
	yrib *v;
	int error;

	if ((rt = cbl_yarena_alloc(a, sizeof(*rt))) == NULL ||
	    (ribs = cbl_yarena_alloc(a, sizeof(*ribs))) == NULL ||
	    (v = cbl_yarena_alloc(a, 2 * sizeof(*v))) == NULL)
		return (ENOMEM);
	memset(rt, 0, sizeof(*rt));
	memset(ribs, 0, sizeof(*ribs));
	memset(v, 0, 2 * sizeof(*v));
	v[0].name = "ipv4-master";
	v[0].has_address_family = true;
	v[0].address_family = ident("ietf-ipv4-unicast-routing",
	    "ipv4-unicast");
	v[1].name = "ipv6-master";
	v[1].has_address_family = true;
	v[1].address_family = ident("ietf-ipv6-unicast-routing",
	    "ipv6-unicast");
	for (int i = 0; i < 2; i++) {
		v[i].has_default_rib = true;
		v[i].default_rib = true;
		if ((error = dump(a, fib, i == 0 ? AF_INET : AF_INET6,
		    &v[i])) != 0)
			return (error);
	}
	ribs->rib.n = 2;
	ribs->rib.v = v;
	rt->ribs = ribs;
	data->routing = rt;
	return (0);
}

/* The action's route and the RIB's: one layout but the preference. */
_Static_assert(sizeof(struct ietf_routing_routing_ribs_rib_active_route_output_route_next_hop) ==
    sizeof(ynh), "active-route's next hop differs from a route's");

int
yrt_active_route(int fib,
    const struct ietf_routing_routing_ribs_rib_active_route_input *in,
    cbl_yarena *a, struct ietf_routing_routing_ribs_rib_active_route_output *out)
{
	struct ietf_routing_routing_ribs_rib_active_route_output_route *o;
	struct sockaddr_storage dst;
	struct snl_errmsg_data e = { 0 };
	struct snl_parsed_route p = { 0 };
	struct snl_writer nw;
	struct snl_state ss;
	struct nlmsghdr *hdr;
	struct rtmsg *rtm;
	char buf[INET6_ADDRSTRLEN + IF_NAMESIZE + 2], *zone;
	const char *addrs = in->v4ur_destination_address != NULL ?
	    in->v4ur_destination_address : in->v6ur_destination_address;
	int af = in->v4ur_destination_address != NULL ? AF_INET : AF_INET6;
	uint32_t scope = 0;
	yroute r;
	int error;

	memset(out, 0, sizeof(*out));
	if (addrs == NULL)
		return (EINVAL);
	memset(&dst, 0, sizeof(dst));
	strlcpy(buf, addrs, sizeof(buf));
	if ((zone = strchr(buf, '%')) != NULL) {
		*zone++ = '\0';
		if (af != AF_INET6 || (scope = if_nametoindex(zone)) == 0)
			return (EINVAL);
	}
	if (af == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&dst;

		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		if (inet_pton(AF_INET, buf, &sin->sin_addr) != 1)
			return (EINVAL);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&dst;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_scope_id = scope;
		if (inet_pton(AF_INET6, buf, &sin6->sin6_addr) != 1)
			return (EINVAL);
	}
	if (!snl_init(&ss, NETLINK_ROUTE))
		return (errno != 0 ? errno : EIO);
	snl_init_writer(&ss, &nw);
	hdr = snl_create_msg_request(&nw, RTM_GETROUTE);
	rtm = snl_reserve_msg_object(&nw, struct rtmsg);
	rtm->rtm_family = af;
	snl_add_msg_attr_ip(&nw, RTA_DST, (struct sockaddr *)&dst);
	snl_add_msg_attr_u32(&nw, RTA_TABLE, (uint32_t)fib);
	if (scope != 0)
		snl_add_msg_attr_u32(&nw, RTA_OIF, scope);
	if ((hdr = snl_finalize_msg(&nw)) == NULL ||
	    !snl_send_message(&ss, hdr)) {
		snl_free(&ss);
		return (ENOMEM);
	}
	if ((hdr = snl_read_reply(&ss, hdr->nlmsg_seq)) == NULL) {
		snl_free(&ss);
		return (EIO);
	}
	if (hdr->nlmsg_type != RTM_NEWROUTE) {
		/* None: ESRCH, an output without a route. */
		error = snl_parse_errmsg(&ss, hdr, &e) ? e.error : EIO;
		snl_free(&ss);
		return (error == ESRCH ? 0 : error != 0 ? error : EIO);
	}
	if (!snl_parse_nlmsg(&ss, hdr, &snl_rtm_route_parser, &p)) {
		snl_free(&ss);
		return (EIO);
	}
	memset(&r, 0, sizeof(r));
	error = route(a, fib, &p, &r);
	snl_free(&ss);
	if (error != 0)
		return (error);
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	memset(o, 0, sizeof(*o));
	o->next_hop = (const void *)r.next_hop;
	o->has_source_protocol = r.has_source_protocol;
	o->source_protocol = r.source_protocol;
	o->active = r.active;
	o->last_updated = r.last_updated;
	o->v4ur_destination_prefix = r.v4ur_destination_prefix;
	o->v6ur_destination_prefix = r.v6ur_destination_prefix;
	out->route = o;
	return (0);
}
