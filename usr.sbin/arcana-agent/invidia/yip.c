/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: each interface's IPv4 and IPv6 as ietf-ip (RFC 8344) has them
 * in the operational datastore (PLAN-SDN-YANG 1.10), read as ifconfig(8)
 * reads them, for yif_interfaces() to give with the rest:
 *
 * - the addresses getifaddrs(3) gives after each interface's link entry
 *   (so that of two interfaces of one name, only the listed one's are
 *   given), with their prefix length;
 * - an IPv6 address's flags (SIOCGIFAFLAG_IN6), as ifconfig shows them:
 *   its status (duplicated, tentative, detached as inaccessible,
 *   deprecated, else preferred) and its origin: a temporary address
 *   (RFC 4941) random, an autoconfigured one link-layer where its
 *   interface identifier is the modified EUI-64 of the link address
 *   and random where not (RFC 7217's stable ones), a link-local one
 *   link-layer or other alike, the rest static;
 * - an IPv4 address's origin: dhcp where dhclient(8) runs for the
 *   interface and its lease names the address, random for one of
 *   169.254/16 (RFC 3927), else static;
 * - IPv6 on the interface (SIOCGIFINFO_IN6): there where the kernel has
 *   it attached, as ifconfig's nd6 line shows, enabled unless
 *   ND6_IFF_IFDISABLED, its MTU the link MTU RAs set, if any below the
 *   interface's.  FreeBSD cannot turn IPv4 off on one interface: it is
 *   there where an address is, enabled, its MTU the interface's.
 *
 * - the neighbours (PLAN-SDN-YANG 1.10.2), ARP's and NDP's, as netlink(4)
 *   dumps them (RTM_GETNEIGH) and arp(8) and ndp(8) list them, but the
 *   interface's own addresses, which the kernel keeps among them
 *   (NTF_SELF), and those not yet resolved, which have no link-layer
 *   address for ietf-ip's mandatory one: static where set by hand
 *   (NTF_STICKY), else dynamic; an IPv6 one's router flag (NTF_ROUTER)
 *   and its state (NUD_*), where it is not static.
 *
 * - what FreeBSD sets for the whole host by sysctl(8), on every
 *   interface (PLAN-SDN-YANG 1.10.3): forwarding (net.inet.ip.forwarding,
 *   net.inet6.ip6.forwarding), DAD's probes (net.inet6.ip6.dad_count),
 *   temporary addresses (net.inet6.ip6.use_tempaddr, tempvltime,
 *   temppltime); arcana-ip-deviations makes them config false.  Whether
 *   an interface makes global addresses from RAs is its own
 *   (ND6_IFF_ACCEPT_RTADV).
 *
 * The scope a link-local IPv6 address carries in the kernel's form is
 * taken out (ietf-ip's addresses have no zone).
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>
#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route.h>
#include <netlink/netlink_snl_route_parsers.h>

#include <errno.h>
#include <ifaddrs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "collect.h"

typedef struct ietf_interfaces_interfaces_interface yif;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv4_address yv4;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_address yv6;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv4_neighbor yn4;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_neighbor yn6;

#define	V4(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV4_ADDRESS_##x
#define	V6(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV6_ADDRESS_##x
#define	N4(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV4_NEIGHBOR_##x
#define	N6(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV6_NEIGHBOR_##x

/* What one interface has, as the addresses are counted and filled. */
struct ifip {
	yif		*e;
	uint8_t		 lladdr[ETHER_ADDR_LEN];
	bool		 havell;
	uint32_t	 mtu;		/* the link's, if_data's; 0: none */
	size_t		 n4, n6;
	yv4		*v4;
	yv6		*v6;
	size_t		 nn4, nn6;
	yn4		*nb4;
	yn6		*nb6;
};

static char *
astrdup(cbl_yarena *a, const char *s)
{
	size_t len = strlen(s) + 1;
	char *p;

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

static int
ones(const uint8_t *p, size_t len, bool *contiguous)
{
	int n = 0;
	bool zero = false;

	*contiguous = true;
	for (size_t i = 0; i < len * 8; i++) {
		if ((p[i / 8] & (0x80 >> (i % 8))) != 0) {
			if (zero)
				*contiguous = false;
			n++;
		} else
			zero = true;
	}
	return (n);
}

/* The entry of the list whose index this is, NULL for one left out. */
static struct ifip *
of_index(struct ifip *ip, size_t n, int index)
{

	for (size_t i = 0; i < n; i++)
		if (ip[i].e->if_index == index)
			return (&ip[i]);
	return (NULL);
}

/*
 * Whether dhclient(8) runs for the interface and its lease names the
 * address: the last fixed-address of /var/db/dhclient.leases.<if>, its
 * pid file /var/run/dhclient/dhclient.<if>.pid naming a live process.
 */
static bool
dhcp_leased(const char *ifname, const char *addr)
{
	char path[MAXPATHLEN], line[256], last[64] = "", *p;
	FILE *f;
	long pid = 0;

	snprintf(path, sizeof(path), "/var/run/dhclient/dhclient.%s.pid",
	    ifname);
	if ((f = fopen(path, "re")) == NULL)
		return (false);
	if (fscanf(f, "%ld", &pid) != 1)
		pid = 0;
	fclose(f);
	if (pid <= 0 || kill((pid_t)pid, 0) != 0)
		return (false);
	snprintf(path, sizeof(path), "/var/db/dhclient.leases.%s", ifname);
	if ((f = fopen(path, "re")) == NULL)
		return (false);
	while (fgets(line, sizeof(line), f) != NULL) {
		p = line + strspn(line, " \t");
		if (strncmp(p, "fixed-address ", 14) != 0)
			continue;
		p += 14;
		p[strcspn(p, "; \t\n")] = '\0';
		strlcpy(last, p, sizeof(last));
	}
	fclose(f);
	return (strcmp(last, addr) == 0);
}

static int
v4_fill(yv4 *x, const struct ifaddrs *ifa, const char *ifname,
    cbl_yarena *a)
{
	const struct sockaddr_in *sin = (const void *)ifa->ifa_addr;
	const struct sockaddr_in *mask = (const void *)ifa->ifa_netmask;
	char buf[INET_ADDRSTRLEN];
	bool contiguous;
	int len;

	if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) == NULL ||
	    (x->ip = astrdup(a, buf)) == NULL)
		return (ENOMEM);
	if (mask != NULL) {
		len = ones((const uint8_t *)&mask->sin_addr, 4, &contiguous);
		/* A mask with holes is no prefix length: ietf-ip's netmask
		 * case is a feature FreeBSD's routing does not take. */
		if (contiguous) {
			x->subnet = V4(SUBNET_PREFIX_LENGTH);
			x->has_prefix_length = true;
			x->prefix_length = (uint8_t)len;
		}
	}
	x->has_origin = true;
	if ((ntohl(sin->sin_addr.s_addr) & 0xffff0000) == 0xa9fe0000)
		x->origin = V4(ORIGIN_RANDOM);
	else if (dhcp_leased(ifname, buf))
		x->origin = V4(ORIGIN_DHCP);
	else
		x->origin = V4(ORIGIN_STATIC);
	return (0);
}

/* Whether the address's interface identifier is lladdr's modified EUI-64. */
static bool
eui64(const struct in6_addr *in6, const struct ifip *ip)
{
	const uint8_t *m = ip->lladdr;
	const uint8_t want[8] = { m[0] ^ 0x02, m[1], m[2], 0xff, 0xfe, m[3],
	    m[4], m[5] };

	return (ip->havell && memcmp(&in6->s6_addr[8], want, 8) == 0);
}

static int
v6_fill(yv6 *x, const struct ifaddrs *ifa, const struct ifip *ip, int s6,
    cbl_yarena *a)
{
	const struct sockaddr_in6 *mask = (const void *)ifa->ifa_netmask;
	char buf[INET6_ADDRSTRLEN];
	struct sockaddr_in6 sin6;
	struct in6_ifreq ifr6;
	bool contiguous, linklocal;
	int flags = 0, len;

	memcpy(&sin6, ifa->ifa_addr, sizeof(sin6));
	memset(&ifr6, 0, sizeof(ifr6));
	strlcpy(ifr6.ifr_name, ifa->ifa_name, sizeof(ifr6.ifr_name));
	ifr6.ifr_addr = sin6;
	if (s6 != -1 && ioctl(s6, SIOCGIFAFLAG_IN6, &ifr6) == 0)
		flags = ifr6.ifr_ifru.ifru_flags6;
	/* The kernel's form keeps the scope in the address: out. */
	linklocal = IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr);
	if (linklocal || IN6_IS_ADDR_MC_LINKLOCAL(&sin6.sin6_addr))
		sin6.sin6_addr.s6_addr[2] = sin6.sin6_addr.s6_addr[3] = 0;
	if (inet_ntop(AF_INET6, &sin6.sin6_addr, buf, sizeof(buf)) == NULL ||
	    (x->ip = astrdup(a, buf)) == NULL)
		return (ENOMEM);
	if (mask != NULL) {
		len = ones(mask->sin6_addr.s6_addr, 16, &contiguous);
		if (contiguous) {
			x->has_prefix_length = true;
			x->prefix_length = (uint8_t)len;
		}
	}
	x->has_origin = true;
	if ((flags & IN6_IFF_TEMPORARY) != 0)
		x->origin = V6(ORIGIN_RANDOM);
	else if ((flags & IN6_IFF_AUTOCONF) != 0)
		x->origin = eui64(&sin6.sin6_addr, ip) ? V6(ORIGIN_LINK_LAYER) :
		    V6(ORIGIN_RANDOM);
	else if (linklocal)
		x->origin = eui64(&sin6.sin6_addr, ip) ? V6(ORIGIN_LINK_LAYER) :
		    V6(ORIGIN_OTHER);
	else
		x->origin = V6(ORIGIN_STATIC);
	x->has_status = true;
	if ((flags & IN6_IFF_DUPLICATED) != 0)
		x->status = V6(STATUS_DUPLICATE);
	else if ((flags & IN6_IFF_TENTATIVE) != 0)
		x->status = V6(STATUS_TENTATIVE);
	else if ((flags & IN6_IFF_DETACHED) != 0)
		x->status = V6(STATUS_INACCESSIBLE);
	else if ((flags & IN6_IFF_DEPRECATED) != 0)
		x->status = V6(STATUS_DEPRECATED);
	else
		x->status = V6(STATUS_PREFERRED);
	return (0);
}

/* What the host sets for every interface; has_*: read. */
struct hostip {
	bool		 has_fwd4, fwd4, has_fwd6, fwd6;
	bool		 has_dad, has_temp, temp, has_tvl, has_tpl;
	uint32_t	 dad, tvl, tpl;
};

static bool
sysctl_int(const char *name, int *v)
{
	size_t len = sizeof(*v);

	return (sysctlbyname(name, v, &len, NULL, 0) == 0 &&
	    len == sizeof(*v));
}

static void
host_read(struct hostip *h)
{
	int v;

	memset(h, 0, sizeof(*h));
	if ((h->has_fwd4 = sysctl_int("net.inet.ip.forwarding", &v)))
		h->fwd4 = v != 0;
	if ((h->has_fwd6 = sysctl_int("net.inet6.ip6.forwarding", &v)))
		h->fwd6 = v != 0;
	if ((h->has_dad = sysctl_int("net.inet6.ip6.dad_count", &v) &&
	    v >= 0))
		h->dad = (uint32_t)v;
	if ((h->has_temp = sysctl_int("net.inet6.ip6.use_tempaddr", &v)))
		h->temp = v != 0;
	if ((h->has_tvl = sysctl_int("net.inet6.ip6.tempvltime", &v) &&
	    v >= 0))
		h->tvl = (uint32_t)v;
	if ((h->has_tpl = sysctl_int("net.inet6.ip6.temppltime", &v) &&
	    v >= 0))
		h->tpl = (uint32_t)v;
}

/* A neighbour as netlink(4) gives it. */
struct nb {
	uint32_t	 ifindex;
	int		 family;
	bool		 sticky, router;
	uint16_t	 state;
	char		 ip[INET6_ADDRSTRLEN];
	char		 ll[64];
};

/* ARP's and NDP's neighbours, but the host's own and those unresolved. */
static int
neighbours(struct nb **out, size_t *nout)
{
	struct {
		struct nlmsghdr	hdr;
		struct ndmsg	ndm;
	} msg;
	struct snl_errmsg_data e = { 0 };
	struct snl_state ss;
	struct nlmsghdr *hdr;
	struct nb *v = NULL, *nv, *x;
	size_t n = 0;
	int error = 0;

	if (!snl_init(&ss, NETLINK_ROUTE))
		return (errno);
	for (int af = 0; af < 2 && error == 0; af++) {
		memset(&msg, 0, sizeof(msg));
		msg.hdr.nlmsg_type = RTM_GETNEIGH;
		msg.hdr.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
		msg.hdr.nlmsg_seq = snl_get_seq(&ss);
		msg.hdr.nlmsg_len = sizeof(msg);
		msg.ndm.ndm_family = af == 0 ? AF_INET : AF_INET6;
		if (!snl_send_message(&ss, &msg.hdr)) {
			error = errno != 0 ? errno : EIO;
			break;
		}
		while ((hdr = snl_read_reply_multi(&ss, msg.hdr.nlmsg_seq,
		    &e)) != NULL) {
			struct snl_parsed_neigh pn = { 0 };
			const uint8_t *p;
			size_t len;

			if (!snl_parse_nlmsg(&ss, hdr, &snl_rtm_neigh_parser,
			    &pn) || pn.nda_dst == NULL || pn.nda_lladdr == NULL ||
			    (pn.ndm_flags & NTF_SELF) != 0 ||
			    (len = pn.nda_lladdr->nla_len - sizeof(struct nlattr)) ==
			    0 || len > 20) {
				snl_clear_lb(&ss);
				continue;
			}
			if ((nv = reallocarray(v, n + 1, sizeof(*v))) == NULL) {
				error = ENOMEM;
				break;
			}
			v = nv;
			x = &v[n++];
			memset(x, 0, sizeof(*x));
			x->ifindex = pn.nda_ifindex;
			x->family = pn.ndm_family;
			x->sticky = (pn.ndm_flags & NTF_STICKY) != 0 ||
			    (pn.ndm_state & NUD_PERMANENT) != 0;
			x->router = (pn.ndm_flags & NTF_ROUTER) != 0;
			x->state = pn.ndm_state;
			if (pn.nda_dst->sa_family == AF_INET6) {
				struct in6_addr in6 =
				    ((const struct sockaddr_in6 *)(const void *)
				    pn.nda_dst)->sin6_addr;

				if (IN6_IS_ADDR_LINKLOCAL(&in6))
					in6.s6_addr[2] = in6.s6_addr[3] = 0;
				inet_ntop(AF_INET6, &in6, x->ip, sizeof(x->ip));
			} else
				inet_ntop(AF_INET, &((const struct sockaddr_in *)
				    (const void *)pn.nda_dst)->sin_addr, x->ip,
				    sizeof(x->ip));
			p = (const uint8_t *)(pn.nda_lladdr + 1);
			for (size_t i = 0; i < len; i++)
				snprintf(x->ll + i * 3, 4, "%02x%s", p[i],
				    i + 1 < len ? ":" : "");
			snl_clear_lb(&ss);
		}
		if (e.error != 0)
			error = e.error;
	}
	snl_free(&ss);
	if (error != 0) {
		free(v);
		return (error);
	}
	*out = v;
	*nout = n;
	return (0);
}

static int
nb_fill(struct ifip *ip, size_t n, const struct nb *v, size_t nv,
    cbl_yarena *a)
{
	struct ifip *x;

	for (size_t i = 0; i < nv; i++)
		if ((x = of_index(ip, n, (int)v[i].ifindex)) != NULL) {
			if (v[i].family == AF_INET)
				x->nn4++;
			else
				x->nn6++;
		}
	for (size_t i = 0; i < n; i++) {
		if ((ip[i].nn4 > 0 && (ip[i].nb4 = cbl_yarena_alloc(a,
		    ip[i].nn4 * sizeof(*ip[i].nb4))) == NULL) ||
		    (ip[i].nn6 > 0 && (ip[i].nb6 = cbl_yarena_alloc(a,
		    ip[i].nn6 * sizeof(*ip[i].nb6))) == NULL))
			return (ENOMEM);
		ip[i].nn4 = ip[i].nn6 = 0;
	}
	for (size_t i = 0; i < nv; i++) {
		if ((x = of_index(ip, n, (int)v[i].ifindex)) == NULL)
			continue;
		if (v[i].family == AF_INET) {
			yn4 *y = &x->nb4[x->nn4++];

			if ((y->ip = astrdup(a, v[i].ip)) == NULL ||
			    (y->link_layer_address = astrdup(a, v[i].ll)) ==
			    NULL)
				return (ENOMEM);
			y->has_origin = true;
			y->origin = v[i].sticky ? N4(ORIGIN_STATIC) :
			    N4(ORIGIN_DYNAMIC);
		} else {
			yn6 *y = &x->nb6[x->nn6++];

			if ((y->ip = astrdup(a, v[i].ip)) == NULL ||
			    (y->link_layer_address = astrdup(a, v[i].ll)) ==
			    NULL)
				return (ENOMEM);
			y->has_origin = true;
			y->origin = v[i].sticky ? N6(ORIGIN_STATIC) :
			    N6(ORIGIN_DYNAMIC);
			y->is_router = v[i].router;
			if (v[i].sticky)
				continue;
			y->has_state = true;
			if ((v[i].state & NUD_REACHABLE) != 0)
				y->state = N6(STATE_REACHABLE);
			else if ((v[i].state & NUD_STALE) != 0)
				y->state = N6(STATE_STALE);
			else if ((v[i].state & NUD_DELAY) != 0)
				y->state = N6(STATE_DELAY);
			else if ((v[i].state & NUD_PROBE) != 0)
				y->state = N6(STATE_PROBE);
			else if ((v[i].state & NUD_INCOMPLETE) != 0)
				y->state = N6(STATE_INCOMPLETE);
			else
				y->has_state = false;
		}
	}
	return (0);
}

/* The interface's IPv6 as the kernel has it attached, if it is. */
static int
v6_on(struct ifip *ip, int s6, const struct hostip *h, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_ip_ipv6_autoconf *ac;
	struct ietf_interfaces_interfaces_interface_ip_ipv6 *v6;
	struct in6_ndireq nd;
	uint32_t mtu;

	memset(&nd, 0, sizeof(nd));
	strlcpy(nd.ifname, ip->e->name, sizeof(nd.ifname));
	if (s6 == -1 || ioctl(s6, SIOCGIFINFO_IN6, &nd) != 0)
		return (0);
	if ((v6 = cbl_yarena_alloc(a, sizeof(*v6))) == NULL ||
	    (ac = cbl_yarena_alloc(a, sizeof(*ac))) == NULL)
		return (ENOMEM);
	v6->has_forwarding = h->has_fwd6;
	v6->forwarding = h->fwd6;
	v6->has_dup_addr_detect_transmits = h->has_dad;
	v6->dup_addr_detect_transmits = h->dad;
	ac->has_create_global_addresses = true;
	ac->create_global_addresses =
	    (nd.ndi.flags & ND6_IFF_ACCEPT_RTADV) != 0;
	ac->has_create_temporary_addresses = h->has_temp;
	ac->create_temporary_addresses = h->temp;
	ac->has_temporary_valid_lifetime = h->has_tvl;
	ac->temporary_valid_lifetime = h->tvl;
	ac->has_temporary_preferred_lifetime = h->has_tpl;
	ac->temporary_preferred_lifetime = h->tpl;
	v6->autoconf = ac;
	v6->has_enabled = true;
	v6->enabled = (nd.ndi.flags & ND6_IFF_IFDISABLED) == 0;
	mtu = ip->mtu;
	if (nd.ndi.linkmtu != 0 && (mtu == 0 || nd.ndi.linkmtu < mtu))
		mtu = nd.ndi.linkmtu;
	if (mtu != 0) {
		v6->has_mtu = true;
		v6->mtu = mtu;
	}
	v6->address.n = ip->n6;
	v6->address.v = ip->v6;
	v6->neighbor.n = ip->nn6;
	v6->neighbor.v = ip->nb6;
	ip->e->ip_ipv6 = v6;
	return (0);
}

static int
v4_on(struct ifip *ip, const struct hostip *h, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_ip_ipv4 *v4;

	/* A neighbour without an address of its own (a static entry the
	 * address went from) is IPv4 there all the same. */
	if (ip->n4 == 0 && ip->nn4 == 0)
		return (0);
	if ((v4 = cbl_yarena_alloc(a, sizeof(*v4))) == NULL)
		return (ENOMEM);
	v4->has_enabled = true;
	v4->enabled = true;
	v4->has_forwarding = h->has_fwd4;
	v4->forwarding = h->fwd4;
	if (ip->mtu != 0) {
		v4->has_mtu = true;
		v4->mtu = (uint16_t)MIN(ip->mtu, UINT16_MAX);
	}
	v4->address.n = ip->n4;
	v4->address.v = ip->v4;
	v4->neighbor.n = ip->nn4;
	v4->neighbor.v = ip->nb4;
	ip->e->ip_ipv4 = v4;
	return (0);
}

int
yip_interfaces(yif *v, size_t n, cbl_yarena *a)
{
	const struct sockaddr_dl *sdl;
	struct ifaddrs *ifa0, *ifa;
	struct ifip *ips, *cur;
	struct nb *nbs = NULL;
	struct hostip h;
	size_t nnbs = 0;
	int s6, error = 0;

	if ((ips = calloc(n > 0 ? n : 1, sizeof(*ips))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < n; i++)
		ips[i].e = &v[i];
	if (getifaddrs(&ifa0) != 0) {
		error = errno;
		free(ips);
		return (error);
	}
	/* Counted first, by the link entry each address comes after. */
	cur = NULL;
	for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		switch (ifa->ifa_addr->sa_family) {
		case AF_LINK:
			sdl = (const void *)ifa->ifa_addr;
			if ((cur = of_index(ips, n, sdl->sdl_index)) != NULL &&
			    sdl->sdl_alen == ETHER_ADDR_LEN) {
				memcpy(cur->lladdr, LLADDR(sdl), ETHER_ADDR_LEN);
				cur->havell = true;
			}
			if (cur != NULL && ifa->ifa_data != NULL)
				cur->mtu = ((const struct if_data *)
				    ifa->ifa_data)->ifi_mtu;
			break;
		case AF_INET:
			if (cur != NULL)
				cur->n4++;
			break;
		case AF_INET6:
			if (cur != NULL)
				cur->n6++;
			break;
		}
	}
	for (size_t i = 0; i < n; i++) {
		if ((ips[i].n4 > 0 && (ips[i].v4 = cbl_yarena_alloc(a,
		    ips[i].n4 * sizeof(*ips[i].v4))) == NULL) ||
		    (ips[i].n6 > 0 && (ips[i].v6 = cbl_yarena_alloc(a,
		    ips[i].n6 * sizeof(*ips[i].v6))) == NULL)) {
			error = ENOMEM;
			goto out;
		}
		ips[i].n4 = ips[i].n6 = 0;
	}
	s6 = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	cur = NULL;
	for (ifa = ifa0; ifa != NULL && error == 0; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		switch (ifa->ifa_addr->sa_family) {
		case AF_LINK:
			sdl = (const void *)ifa->ifa_addr;
			cur = of_index(ips, n, sdl->sdl_index);
			break;
		case AF_INET:
			if (cur != NULL)
				error = v4_fill(&cur->v4[cur->n4++], ifa,
				    cur->e->name, a);
			break;
		case AF_INET6:
			if (cur != NULL)
				error = v6_fill(&cur->v6[cur->n6++], ifa, cur, s6,
				    a);
			break;
		}
	}
	if (error == 0 && (error = neighbours(&nbs, &nnbs)) == 0)
		error = nb_fill(ips, n, nbs, nnbs, a);
	free(nbs);
	host_read(&h);
	for (size_t i = 0; i < n && error == 0; i++)
		if ((error = v4_on(&ips[i], &h, a)) == 0)
			error = v6_on(&ips[i], s6, &h, a);
	if (s6 != -1)
		close(s6);
out:
	freeifaddrs(ifa0);
	free(ips);
	return (error);
}
