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
 * The scope a link-local IPv6 address carries in the kernel's form is
 * taken out (ietf-ip's addresses have no zone).
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>

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

#define	V4(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV4_ADDRESS_##x
#define	V6(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV6_ADDRESS_##x

/* What one interface has, as the addresses are counted and filled. */
struct ifip {
	yif		*e;
	uint8_t		 lladdr[ETHER_ADDR_LEN];
	bool		 havell;
	size_t		 n4, n6;
	yv4		*v4;
	yv6		*v6;
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

/* The interface's IPv6 as the kernel has it attached, if it is. */
static int
v6_on(struct ifip *ip, int s6, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_ip_ipv6 *v6;
	struct in6_ndireq nd;
	uint32_t mtu;

	memset(&nd, 0, sizeof(nd));
	strlcpy(nd.ifname, ip->e->name, sizeof(nd.ifname));
	if (s6 == -1 || ioctl(s6, SIOCGIFINFO_IN6, &nd) != 0)
		return (0);
	if ((v6 = cbl_yarena_alloc(a, sizeof(*v6))) == NULL)
		return (ENOMEM);
	v6->has_enabled = true;
	v6->enabled = (nd.ndi.flags & ND6_IFF_IFDISABLED) == 0;
	mtu = ip->e->has_arcif_mtu ? ip->e->arcif_mtu : 0;
	if (nd.ndi.linkmtu != 0 && (mtu == 0 || nd.ndi.linkmtu < mtu))
		mtu = nd.ndi.linkmtu;
	if (mtu != 0) {
		v6->has_mtu = true;
		v6->mtu = mtu;
	}
	v6->address.n = ip->n6;
	v6->address.v = ip->v6;
	ip->e->ip_ipv6 = v6;
	return (0);
}

static int
v4_on(struct ifip *ip, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_ip_ipv4 *v4;

	if (ip->n4 == 0)
		return (0);
	if ((v4 = cbl_yarena_alloc(a, sizeof(*v4))) == NULL)
		return (ENOMEM);
	v4->has_enabled = true;
	v4->enabled = true;
	if (ip->e->has_arcif_mtu) {
		v4->has_mtu = true;
		v4->mtu = (uint16_t)MIN(ip->e->arcif_mtu, UINT16_MAX);
	}
	v4->address.n = ip->n4;
	v4->address.v = ip->v4;
	ip->e->ip_ipv4 = v4;
	return (0);
}

int
yip_interfaces(yif *v, size_t n, cbl_yarena *a)
{
	const struct sockaddr_dl *sdl;
	struct ifaddrs *ifa0, *ifa;
	struct ifip *ips, *cur;
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
	for (size_t i = 0; i < n && error == 0; i++)
		if ((error = v4_on(&ips[i], a)) == 0)
			error = v6_on(&ips[i], s6, a);
	if (s6 != -1)
		close(s6);
out:
	freeifaddrs(ifa0);
	free(ips);
	return (error);
}
