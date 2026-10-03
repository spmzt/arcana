/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the network interfaces of the host.  They are read with
 * getifaddrs(3) and a few ioctls, as ifconfig(8) reads them, and
 * changed by running ifconfig(8), whose argv and output the trace
 * keeps.  Changes are live only: nothing here touches rc.conf.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <arpa/inet.h>

#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>
#include <unistd.h>

#include "agent.h"

static void		 put(ucl_object_t *, const char *, ucl_object_t *);
static ucl_object_t	*iface(ucl_object_t *, const char *);
static int		 prefixlen(const struct sockaddr *);
static const char	*numeric(const struct sockaddr *, char *, size_t);
static void		 extras(int, int, const char *, ucl_object_t *);
static bool		 parse_addr(struct work *, const char *, int *,
			    const char **, int *);

static const struct {
	unsigned int	 bit;
	const char	*name;
} flag_names[] = {
	{ IFF_UP, "UP" }, { IFF_BROADCAST, "BROADCAST" },
	{ IFF_LOOPBACK, "LOOPBACK" }, { IFF_POINTOPOINT, "POINTOPOINT" },
	{ IFF_DRV_RUNNING, "RUNNING" }, { IFF_NOARP, "NOARP" },
	{ IFF_PROMISC, "PROMISC" }, { IFF_MULTICAST, "MULTICAST" },
};

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

/* The entry of interface name in the array, made at its first address. */
static ucl_object_t *
iface(ucl_object_t *arr, const char *name)
{
	ucl_object_iter_t	 it;
	const ucl_object_t	*e, *n;
	ucl_object_t		*o;

	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL)
		if ((n = ucl_object_lookup(e, "name")) != NULL &&
		    strcmp(ucl_object_tostring(n), name) == 0)
			return ((ucl_object_t *)(uintptr_t)e);
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "name", ucl_object_fromstring(name));
	put(o, "addresses", ucl_object_typed_new(UCL_ARRAY));
	ucl_array_append(arr, o);
	return (o);
}

/* The length of the prefix a netmask stands for. */
static int
prefixlen(const struct sockaddr *sa)
{
	const unsigned char	*p;
	size_t			 len, i;
	int			 n;

	if (sa == NULL)
		return (-1);
	if (sa->sa_family == AF_INET) {
		p = (const unsigned char *)&((const struct sockaddr_in *)
		    (const void *)sa)->sin_addr;
		len = 4;
	} else {
		p = (const unsigned char *)&((const struct sockaddr_in6 *)
		    (const void *)sa)->sin6_addr;
		len = 16;
	}
	n = 0;
	for (i = 0; i < len; i++)
		n += __builtin_popcount(p[i]);
	return (n);
}

static const char *
numeric(const struct sockaddr *sa, char *buf, size_t len)
{

	if (sa == NULL || getnameinfo(sa, sa->sa_len, buf, (socklen_t)len,
	    NULL, 0, NI_NUMERICHOST) != 0)
		return (NULL);
	return (buf);
}

/* What only an ioctl tells: the description and a tunnel's two ends. */
static void
extras(int s4, int s6, const char *name, ucl_object_t *o)
{
	struct ifreq		 ifr;
	struct in6_ifreq	 ifr6;
	ucl_object_t		*t;
	char			 descr[256], a[NI_MAXHOST], b[NI_MAXHOST];

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_buffer.buffer = descr;
	ifr.ifr_buffer.length = sizeof(descr);
	if (s4 != -1 && ioctl(s4, SIOCGIFDESCR, &ifr) == 0 &&
	    ifr.ifr_buffer.buffer == descr && ifr.ifr_buffer.length > 1)
		put(o, "description", ucl_object_fromstring(descr));

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	if (s4 != -1 && ioctl(s4, SIOCGIFPSRCADDR, &ifr) == 0 &&
	    ifr.ifr_addr.sa_family == AF_INET && numeric(&ifr.ifr_addr, a,
	    sizeof(a)) != NULL) {
		t = ucl_object_typed_new(UCL_OBJECT);
		put(t, "local", ucl_object_fromstring(a));
		if (ioctl(s4, SIOCGIFPDSTADDR, &ifr) == 0 && numeric(
		    &ifr.ifr_addr, b, sizeof(b)) != NULL)
			put(t, "remote", ucl_object_fromstring(b));
		put(o, "tunnel", t);
		return;
	}
	memset(&ifr6, 0, sizeof(ifr6));
	strlcpy(ifr6.ifr_name, name, sizeof(ifr6.ifr_name));
	if (s6 != -1 && ioctl(s6, SIOCGIFPSRCADDR_IN6, &ifr6) == 0 &&
	    ifr6.ifr_addr.sin6_family == AF_INET6 && numeric((struct sockaddr *)
	    &ifr6.ifr_addr, a, sizeof(a)) != NULL) {
		t = ucl_object_typed_new(UCL_OBJECT);
		put(t, "local", ucl_object_fromstring(a));
		if (ioctl(s6, SIOCGIFPDSTADDR_IN6, &ifr6) == 0 && numeric(
		    (struct sockaddr *)&ifr6.ifr_addr, b, sizeof(b)) != NULL)
			put(t, "remote", ucl_object_fromstring(b));
		put(o, "tunnel", t);
	}
}

/*
 * {"interfaces": [{"name", "up", "flags", "link", "mtu", "ether",
 * "description", "tunnel": {"local", "remote"}, counters,
 * "addresses": [{"family", "address", "prefixlen", "broadcast" or
 * "destination"}]}]}; family narrows the addresses.
 */
int
do_interfaces(struct work *w, uint8_t family, struct arc_network_rsp *rsp)
{
	struct ifaddrs		*ifap, *ifa;
	const struct sockaddr_dl *sdl;
	const struct if_data	*ifd;
	const unsigned char	*m;
	ucl_object_t		*top, *arr, *o, *a, *f;
	unsigned char		*json;
	char			 buf[NI_MAXHOST], mac[24];
	size_t			 i;
	int			 step, s4, s6, n, af;

	rsp->has_ok = true;
	rsp->ok = false;
	step = step_begin(w, ARC_STEP_KIND_LIB, "getifaddrs(3)", NULL);
	if (getifaddrs(&ifap) == -1) {
		step_end(w, step, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "getifaddrs: %s", strerror(errno));
		return (0);
	}
	s4 = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	s6 = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	n = 0;
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		o = iface(arr, ifa->ifa_name);
		af = ifa->ifa_addr->sa_family;
		if (af == AF_LINK) {
			n++;
			put(o, "up", ucl_object_frombool((ifa->ifa_flags &
			    IFF_UP) != 0));
			f = ucl_object_typed_new(UCL_ARRAY);
			for (i = 0; i < nitems(flag_names); i++)
				if (ifa->ifa_flags & flag_names[i].bit)
					ucl_array_append(f, ucl_object_fromstring(
					    flag_names[i].name));
			put(o, "flags", f);
			sdl = (const struct sockaddr_dl *)(const void *)
			    ifa->ifa_addr;
			if (sdl->sdl_alen == 6) {
				m = (const unsigned char *)LLADDR(sdl);
				snprintf(mac, sizeof(mac),
				    "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1],
				    m[2], m[3], m[4], m[5]);
				put(o, "ether", ucl_object_fromstring(mac));
			}
			if ((ifd = ifa->ifa_data) != NULL) {
				put(o, "mtu", ucl_object_fromint(ifd->ifi_mtu));
				put(o, "link", ucl_object_fromstring(
				    ifd->ifi_link_state == LINK_STATE_UP ? "up" :
				    ifd->ifi_link_state == LINK_STATE_DOWN ?
				    "down" : "unknown"));
				put(o, "ipackets", ucl_object_fromint(
				    (int64_t)ifd->ifi_ipackets));
				put(o, "opackets", ucl_object_fromint(
				    (int64_t)ifd->ifi_opackets));
				put(o, "ibytes", ucl_object_fromint(
				    (int64_t)ifd->ifi_ibytes));
				put(o, "obytes", ucl_object_fromint(
				    (int64_t)ifd->ifi_obytes));
				put(o, "ierrors", ucl_object_fromint(
				    (int64_t)ifd->ifi_ierrors));
				put(o, "oerrors", ucl_object_fromint(
				    (int64_t)ifd->ifi_oerrors));
			}
			extras(s4, s6, ifa->ifa_name, o);
			continue;
		}
		if ((af != AF_INET && af != AF_INET6) ||
		    (family == ARC_NET_FAMILY_INET && af != AF_INET) ||
		    (family == ARC_NET_FAMILY_INET6 && af != AF_INET6) ||
		    numeric(ifa->ifa_addr, buf, sizeof(buf)) == NULL)
			continue;
		a = ucl_object_typed_new(UCL_OBJECT);
		put(a, "family", ucl_object_fromstring(af == AF_INET ? "inet" :
		    "inet6"));
		put(a, "address", ucl_object_fromstring(buf));
		if (prefixlen(ifa->ifa_netmask) >= 0)
			put(a, "prefixlen", ucl_object_fromint(prefixlen(
			    ifa->ifa_netmask)));
		if ((ifa->ifa_flags & IFF_POINTOPOINT) != 0 &&
		    numeric(ifa->ifa_dstaddr, buf, sizeof(buf)) != NULL)
			put(a, "destination", ucl_object_fromstring(buf));
		else if (af == AF_INET && (ifa->ifa_flags & IFF_BROADCAST) !=
		    0 && numeric(ifa->ifa_broadaddr, buf, sizeof(buf)) != NULL)
			put(a, "broadcast", ucl_object_fromstring(buf));
		ucl_array_append((ucl_object_t *)(uintptr_t)ucl_object_lookup(o,
		    "addresses"), a);
	}
	freeifaddrs(ifap);
	if (s4 != -1)
		close(s4);
	if (s6 != -1)
		close(s6);
	step_end(w, step, true, "%d interfaces", n);
	put(top, "interfaces", arr);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "the interfaces are more than a reply carries";
		return (0);
	}
	rsp->json = wadopt(w, json);
	rsp->ok = true;
	return (0);
}

/*
 * "10.0.0.5/24" or "2001:db8::5/64": the family, the address without
 * its prefix length, and that length, the whole address when none is
 * given.
 */
static bool
parse_addr(struct work *w, const char *s, int *afp, const char **addrp,
    int *plenp)
{
	unsigned char	 raw[16];
	const char	*slash, *errstr;
	char		*addr;
	int		 max;

	slash = strchr(s, '/');
	addr = slash != NULL ? wstrndup(w, s, (size_t)(slash - s)) :
	    wstrdup(w, s);
	if (inet_pton(AF_INET, addr, raw) == 1) {
		*afp = AF_INET;
		max = 32;
	} else if (inet_pton(AF_INET6, addr, raw) == 1) {
		*afp = AF_INET6;
		max = 128;
	} else
		return (false);
	*plenp = max;
	if (slash != NULL) {
		*plenp = (int)strtonum(slash + 1, 0, max, &errstr);
		if (errstr != NULL)
			return (false);
	}
	*addrp = addr;
	return (true);
}

/*
 * address as the interface has it now, with its prefix length: what
 * puts it back after it was taken off.  NULL when it is not there.
 */
const char *
if_address_with_prefix(struct work *w, const char *ifname, const char *address)
{
	struct ifaddrs	*ifap, *ifa;
	const char	*addr, *out;
	char		 buf[NI_MAXHOST];
	int		 af, plen;

	if (!parse_addr(w, address, &af, &addr, &plen) || getifaddrs(&ifap) ==
	    -1)
		return (NULL);
	out = NULL;
	for (ifa = ifap; ifa != NULL && out == NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != af ||
		    strcmp(ifa->ifa_name, ifname) != 0 ||
		    numeric(ifa->ifa_addr, buf, sizeof(buf)) == NULL)
			continue;
		buf[strcspn(buf, "%")] = '\0';
		if (strcmp(buf, addr) == 0 && prefixlen(ifa->ifa_netmask) >= 0)
			out = wfmt(w, "%s/%d", addr, prefixlen(
			    ifa->ifa_netmask));
	}
	freeifaddrs(ifap);
	return (out);
}

/* Add an address to an interface as an alias, or take it off. */
int
do_if_address(struct work *w, const char *ifname, const char *address,
    bool remove, const char **errp)
{
	struct execres	 res;
	const char	*addr;
	char		*argv[6];
	int		 af, plen, n;

	if (if_nametoindex(ifname) == 0) {
		*errp = wfmt(w, "no interface %s on this host", ifname);
		return (-1);
	}
	if (!parse_addr(w, address, &af, &addr, &plen)) {
		*errp = wfmt(w, "%s is not an IPv4 or IPv6 address, with or "
		    "without a prefix length", address);
		return (-1);
	}
	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[n++] = (char *)(uintptr_t)ifname;
	argv[n++] = (char *)(uintptr_t)(af == AF_INET ? "inet" : "inet6");
	argv[n++] = remove ? (char *)(uintptr_t)addr : wfmt(w, "%s/%d", addr,
	    plen);
	argv[n++] = (char *)(uintptr_t)(remove ? "-alias" : "alias");
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ifconfig"));
		return (-1);
	}
	return (0);
}

/* Bring an interface up or down. */
int
do_if_state(struct work *w, const char *ifname, bool up, const char **errp)
{
	struct execres	 res;
	char		*argv[4];

	if (if_nametoindex(ifname) == 0) {
		*errp = wfmt(w, "no interface %s on this host", ifname);
		return (-1);
	}
	argv[0] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[1] = (char *)(uintptr_t)ifname;
	argv[2] = (char *)(uintptr_t)(up ? "up" : "down");
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ifconfig"));
		return (-1);
	}
	return (0);
}
