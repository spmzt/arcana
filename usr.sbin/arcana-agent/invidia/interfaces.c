/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the network interfaces of the host.  They are read with
 * getifaddrs(3) and a few ioctls, as ifconfig(8) reads them, and
 * changed by running ifconfig(8), whose argv and output the trace
 * keeps.  A change is made live, and when asked also kept in rc.conf
 * (rcconf.c).
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
#include <syslog.h>
#include <time.h>
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
static const char	*ifq(struct work *, const char *, const char *,
			    const char *);
static bool		 host_is_up(const char *, bool *);
static const char	*host_prefix(struct work *, const char *,
			    const char *);
static void		 host_current(const char *, unsigned int *, int *, int *,
			    char *,
			    size_t);

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
	struct timespec		 ts;
	char			 buf[NI_MAXHOST], mac[24];
	size_t			 i;
	int			 step, s4, s6, n, af;

	rsp->has_ok = true;
	rsp->ok = false;
	/* Of a jail: read by the helper, which attaches to it first. */
	if (w->jail != NULL) {
		if ((rsp->json = ifq(w, "interfaces", NULL, wfmt(w, "%u",
		    family))) == NULL || rsp->json[0] != '{') {
			rsp->json = NULL;
			rsp->error = wfmt(w, "cannot read the interfaces of "
			    "the jail %s", w->jail);
			return (0);
		}
		rsp->ok = true;
		return (0);
	}
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
	carp_read(top, arr);
	put(top, "interfaces", arr);
	/* When the counters were read, to make rates of two readings. */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	put(top, "time", ucl_object_fromint((int64_t)ts.tv_sec * 1000 +
	    ts.tv_nsec / 1000000));
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
 * Has the interface its link, here: up, and its link not down (one
 * whose link state is unknown, as a loopback's, has it)?  False when it
 * could not be told.
 */
static bool
host_link(const char *ifname, bool *okp)
{
	struct ifaddrs	*ifap, *ifa;
	const struct if_data *ifd;
	bool		 found;

	if (getifaddrs(&ifap) == -1)
		return (false);
	found = false;
	for (ifa = ifap; ifa != NULL && !found; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family !=
		    AF_LINK || strcmp(ifa->ifa_name, ifname) != 0 ||
		    (ifd = ifa->ifa_data) == NULL)
			continue;
		found = true;
		*okp = (ifa->ifa_flags & IFF_UP) != 0 && ifd->ifi_link_state !=
		    LINK_STATE_DOWN;
	}
	freeifaddrs(ifap);
	return (found);
}

/* Is the interface up, here?  False when it could not be told. */
static bool
host_is_up(const char *ifname, bool *upp)
{
	struct ifreq	ifr;
	int		s;
	bool		ok;

	if ((s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1 &&
	    (s = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		return (false);
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if ((ok = ioctl(s, SIOCGIFFLAGS, &ifr) == 0))
		*upp = (ifr.ifr_flags & IFF_UP) != 0;
	close(s);
	return (ok);
}

/*
 * address as the interface has it now, with its prefix length: what
 * puts it back after it was taken off.  NULL when it is not there.
 * Without an interface named, as whichever interface has it.
 */
static const char *
host_prefix(struct work *w, const char *ifname, const char *address)
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
		    (ifname != NULL && strcmp(ifa->ifa_name, ifname) != 0) ||
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

/*
 * Add an address to an interface as an alias, or take it off; with
 * persist, in rc.conf as well.
 */
int
do_if_address(struct work *w, const char *ifname, const char *address,
    bool remove, bool persist, const char **errp)
{
	struct execres	 res;
	const char	*addr;
	char		*argv[6];
	int		 af, plen, n;

	/*
	 * A member of a bridge takes no address: the bridge is where the
	 * host's addresses on that network belong, and one on a member
	 * answers on some paths and not on others.  One that is there
	 * may still be taken away.
	 */
	if (!remove) {
		const char	*br;

		if ((br = bridge_holding(w, ifname)) != NULL) {
			*errp = wfmt(w, "%s is a member of %s: an address "
			    "belongs on the bridge, not on its member", ifname,
			    br);
			return (-1);
		}
	}
	if (!if_exists(w, ifname)) {
		*errp = wfmt(w, "no interface %s %s", ifname, w->jail != NULL ?
		    "in that jail" : "on this host");
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
	if (persist && rc_alias(w, ifname, af == AF_INET ? "inet" : "inet6",
	    addr, wfmt(w, "%s/%d", addr, plen), remove, errp) != 0) {
		/* Not kept: not left half done either. */
		argv[3] = remove ? wfmt(w, "%s/%d", addr, plen) :
		    (char *)(uintptr_t)addr;
		argv[4] = (char *)(uintptr_t)(remove ? "alias" : "-alias");
		(void)run_exec(w, argv, &res);
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

	if (!if_exists(w, ifname)) {
		*errp = wfmt(w, "no interface %s %s", ifname, w->jail != NULL ?
		    "in that jail" : "on this host");
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

/* The MTU and the description an interface has now, here. */
static void
host_current(const char *ifname, unsigned int *mtup, int *fibp, int *tfibp,
    char *descr, size_t len)
{
	struct ifreq	ifr;
	char		buf[256];
	int		s;

	*mtup = 0;
	*fibp = *tfibp = -1;
	descr[0] = '\0';
	if ((s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1 &&
	    (s = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		return;
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFMTU, &ifr) == 0)
		*mtup = (unsigned int)ifr.ifr_mtu;
	/* Its table, and a tunnel's for what it sends outside. */
	if (ioctl(s, SIOCGIFFIB, &ifr) == 0)
		*fibp = (int)ifr.ifr_fib;
	if (ioctl(s, SIOCGTUNFIB, &ifr) == 0)
		*tfibp = (int)ifr.ifr_fib;
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_buffer.buffer = buf;
	ifr.ifr_buffer.length = sizeof(buf);
	if (ioctl(s, SIOCGIFDESCR, &ifr) == 0 && ifr.ifr_buffer.buffer == buf &&
	    ifr.ifr_buffer.length > 1)
		strlcpy(descr, buf, len);
	close(s);
}

/* A description is printable, and nothing rc.conf would read as more. */
static bool
valid_descr(const char *s)
{

	for (; *s != '\0'; s++)
		if ((unsigned char)*s < 0x20 || *s == 0x7f || strchr("\"'`$\\",
		    *s) != NULL)
			return (false);
	return (true);
}

/* ifconfig name word value, and its error. */
static int
ifset_word(struct work *w, const char *ifname, const char *word,
    const char *value, const char **errp)
{
	struct execres	 res;
	char		*argv[5];

	argv[0] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[1] = (char *)(uintptr_t)ifname;
	argv[2] = (char *)(uintptr_t)word;
	argv[3] = (char *)(uintptr_t)value;
	argv[4] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ifconfig"));
		return (-1);
	}
	return (0);
}

/*
 * Set an interface's MTU, its description ("" takes it off), the
 * routing table what it receives is looked up in, a tunnel's for what
 * it sends outside, or several: what ch leaves at 0, NULL or -1 stays.
 * Kept, each is a word of ifconfig_<if> (a table of 0 is taken out of
 * it, the kernel's own).
 */
static int	 if_addressing(struct work *, const char *, const char *, bool,
		    const char **);

int
do_if_set(struct work *w, const char *ifname, const struct if_change *ch,
    bool persist, const char **errp)
{
	const char	*descr;
	int		 i;

	descr = ch->descr;
	if (!if_exists(w, ifname)) {
		*errp = wfmt(w, "no interface %s %s", ifname, w->jail != NULL ?
		    "in that jail" : "on this host");
		return (-1);
	}
	/* ifconfig takes any text; rc.conf not what sh(1) reads as more. */
	if (descr != NULL && persist && !valid_descr(descr)) {
		*errp = "a description kept in rc.conf is plain text, without "
		    "quotes, $ or \\";
		return (-1);
	}
	if (ch->mtu != 0 && (ch->mtu < 68 || ch->mtu > 65535)) {
		*errp = "an MTU is between 68 and 65535";
		return (-1);
	}
	if (ch->mtu != 0) {
		if (ifset_word(w, ifname, "mtu", wfmt(w, "%u", ch->mtu),
		    errp) != 0)
			return (-1);
		if (persist && rc_word(w, ifname, "mtu", wfmt(w, "%u",
		    ch->mtu), errp) != 0)
			return (-1);
	}
	for (i = 0; i < 2; i++) {
		const char	*word = i == 0 ? "fib" : "tunnelfib";
		int		 v = i == 0 ? ch->fib : ch->tunnelfib;

		if (v < 0)
			continue;
		if (ifset_word(w, ifname, word, wfmt(w, "%d", v), errp) != 0)
			return (-1);
		if (persist && rc_word(w, ifname, word, v != 0 ? wfmt(w, "%d",
		    v) : NULL, errp) != 0)
			return (-1);
	}
	if (ch->addressing != NULL && if_addressing(w, ifname, ch->addressing,
	    persist, errp) != 0)
		return (-1);
	if (descr != NULL) {
		struct execres	 res;
		char		*argv[5];

		argv[0] = (char *)(uintptr_t)opts.ifconfig_bin;
		argv[1] = (char *)(uintptr_t)ifname;
		argv[2] = (char *)(uintptr_t)(descr[0] != '\0' ? "description" :
		    "-description");
		argv[3] = descr[0] != '\0' ? (char *)(uintptr_t)descr : NULL;
		argv[4] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			*errp = wtext(w, exec_error(w, &res, "ifconfig"));
			return (-1);
		}
		if (persist && descr[0] == '\0')
			rc_unset(w, wfmt(w, "ifconfig_%s_descr", rc_ifname(w,
			    ifname)));
		else if (persist && rc_set(w, wfmt(w, "ifconfig_%s_descr",
		    rc_ifname(w, ifname)), "=", descr, errp) != 0)
			return (-1);
	}
	return (0);
}

/*
 * An interface's addressing as Arcana found it, the first time it was
 * changed (dhcp or slaac): kept in a file beside the agent's other
 * state, by jail and interface, for "was" to put back; let go when it
 * is put back, or static is chosen.
 */
#define	ADDR_WAS_FILE	"addressing-was.json"

static const char *
addr_key(struct work *w, const char *ifname)
{

	return (wfmt(w, "%s%s%s", w->jail != NULL ? w->jail : "", w->jail !=
	    NULL ? "/" : "", ifname));
}

static ucl_object_t *
addr_kept(void)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	char			*json;

	o = NULL;
	if ((json = sdwan_kept_read(ADDR_WAS_FILE)) != NULL) {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_string(p, json, 0))
			o = ucl_parser_get_object(p);
		ucl_parser_free(p);
		free(json);
	}
	if (o == NULL || ucl_object_type(o) != UCL_OBJECT) {
		if (o != NULL)
			ucl_object_unref(o);
		o = ucl_object_typed_new(UCL_OBJECT);
	}
	return (o);
}

static void
addr_keep(struct work *w, ucl_object_t *all)
{
	char		*json;
	const char	*e;

	json = (char *)ucl_object_emit(all, UCL_EMIT_JSON_COMPACT);
	e = NULL;
	if (json == NULL || sdwan_conf_write(ADDR_WAS_FILE, json, &e) != 0)
		logmsg(LOG_WARNING, "%s: %s", ADDR_WAS_FILE, e != NULL ? e :
		    "not written");
	(void)w;
	free(json);
}

/* How the interface is addressed now, by rc.conf's words. */
void
if_addr_state(struct work *w, const char *ifname, struct addr_state *a)
{
	const char	*v;

	memset(a, 0, sizeof(*a));
	v = rc_get(w, wfmt(w, "ifconfig_%s", rc_ifname(w, ifname)));
	a->rc = v != NULL ? wstrdup(w, v) : NULL;
	v = rc_get(w, wfmt(w, "ifconfig_%s_ipv6", rc_ifname(w, ifname)));
	a->rc6 = v != NULL ? wstrdup(w, v) : NULL;
	a->dhcp = a->rc != NULL && (strstr(a->rc, "DHCP") != NULL);
	a->slaac = a->rc6 != NULL && strstr(a->rc6, "-accept_rtadv") == NULL &&
	    strstr(a->rc6, "accept_rtadv") != NULL;
}

/* What was kept of it let go. */
void
if_addr_forget(struct work *w, const char *ifname)
{
	ucl_object_t	*all;

	all = addr_kept();
	if (ucl_object_delete_key(all, addr_key(w, ifname)))
		addr_keep(w, all);
	ucl_object_unref(all);
}

/*
 * The interface addressed as a says: rc.conf's two lines as they were
 * (persist), and now: IPv6's accept_rtadv and rtsol, dhclient started
 * or stopped, and a static line's words given to ifconfig again.
 */
int
if_addr_restore(struct work *w, const char *ifname,
    const struct addr_state *a, bool persist, const char **errp)
{
	struct execres	 res;
	const char	*rcn, *rc6;
	char		*argv[16], *words, *word, *rest;
	int		 n;

	rcn = wfmt(w, "ifconfig_%s", rc_ifname(w, ifname));
	rc6 = wfmt(w, "ifconfig_%s_ipv6", rc_ifname(w, ifname));
	if (persist) {
		if (a->rc == NULL)
			rc_unset(w, rcn);
		else if (rc_set(w, rcn, "=", a->rc, errp) != 0)
			return (-1);
		if (a->rc6 == NULL)
			rc_unset(w, rc6);
		else if (rc_set(w, rc6, "=", a->rc6, errp) != 0)
			return (-1);
	}
	argv[0] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[1] = (char *)(uintptr_t)ifname;
	argv[2] = (char *)(uintptr_t)"inet6";
	argv[3] = (char *)(uintptr_t)(a->slaac ? "accept_rtadv" :
	    "-accept_rtadv");
	argv[4] = (char *)(uintptr_t)(a->slaac ? "-ifdisabled" : NULL);
	argv[5] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ifconfig"));
		return (-1);
	}
	if (a->slaac) {
		argv[0] = (char *)(uintptr_t)opts.rtsol_bin;
		argv[1] = (char *)(uintptr_t)ifname;
		argv[2] = NULL;
		(void)run_exec(w, argv, &res);
	}
	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)"dhclient";
	argv[2] = (char *)(uintptr_t)(a->dhcp ? "restart" : "stop");
	argv[3] = (char *)(uintptr_t)ifname;
	argv[4] = NULL;
	if (run_exec(w, argv, &res) != 0 && a->dhcp) {
		*errp = wtext(w, exec_error(w, &res, "service dhclient"));
		return (-1);
	}
	/* A static IPv4 line's address again: what dhclient left goes. */
	if (!a->dhcp && a->rc != NULL && strstr(a->rc, "inet ") != NULL) {
		n = 0;
		argv[n++] = (char *)(uintptr_t)opts.ifconfig_bin;
		argv[n++] = (char *)(uintptr_t)ifname;
		words = wstrdup(w, strstr(a->rc, "inet "));
		for (rest = words; (word = strsep(&rest, " ")) != NULL &&
		    n < 15; )
			if (word[0] != '\0')
				argv[n++] = word;
		argv[n] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			*errp = wtext(w, exec_error(w, &res, "ifconfig"));
			return (-1);
		}
	}
	return (0);
}

/* line's words but those of drop, a space between them (w's pool). */
static char *
words_but(struct work *w, const char *line, const char *const *drop)
{
	char	*words, *word, *rest, *out;
	size_t	 i, len;

	len = strlen(line) + 1;
	out = wcalloc(w, 1, len);
	words = wstrdup(w, line);
	for (rest = words; (word = strsep(&rest, " \t")) != NULL; ) {
		if (word[0] == '\0')
			continue;
		for (i = 0; drop[i] != NULL && strcmp(word, drop[i]) != 0; i++)
			;
		if (drop[i] != NULL)
			continue;
		if (out[0] != '\0')
			strlcat(out, " ", len);
		strlcat(out, word, len);
	}
	return (out);
}

/* The kept record of an interface, as JSON (w's pool), or NULL. */
const char *
if_addr_record_get(struct work *w, const char *ifname)
{
	ucl_object_t		*all;
	const ucl_object_t	*k;
	char			*json;
	const char		*out;

	all = addr_kept();
	out = NULL;
	if ((k = ucl_object_lookup(all, addr_key(w, ifname))) != NULL &&
	    (json = (char *)ucl_object_emit(k, UCL_EMIT_JSON_COMPACT)) !=
	    NULL) {
		out = wstrdup(w, json);
		free(json);
	}
	ucl_object_unref(all);
	return (out);
}

/* That record kept again, as it was (json), or let go (NULL). */
void
if_addr_record_set(struct work *w, const char *ifname, const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*all, *k;

	if (json == NULL) {
		if_addr_forget(w, ifname);
		return;
	}
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	k = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	if (k == NULL)
		return;
	all = addr_kept();
	ucl_object_insert_key(all, k, addr_key(w, ifname), 0, true);
	addr_keep(w, all);
	ucl_object_unref(all);
}

/*
 * "was": the addressing kept before Arcana first changed it, put back
 * and let go; nothing kept, nothing changes.  Only the addressing goes
 * back: DHCP's word in ifconfig_<if>, accept_rtadv in its _ipv6 line,
 * the other words as they are now (an MTU, a table set since stays); a
 * line taken away since comes back whole.
 */
static int
if_addr_was(struct work *w, const char *ifname, bool persist,
    const char **errp)
{
	ucl_object_t		*all;
	const ucl_object_t	*k;
	struct addr_state	 a, now;
	int			 step, rc;

	all = addr_kept();
	if ((k = ucl_object_lookup(all, addr_key(w, ifname))) == NULL) {
		ucl_object_unref(all);
		step = step_begin(w, ARC_STEP_KIND_FILE, "arcana-agent",
		    "%s: its addressing before is not kept: left as it is",
		    ifname);
		step_end(w, step, true, NULL);
		return (0);
	}
	memset(&a, 0, sizeof(a));
	a.dhcp = ucl_object_toboolean(ucl_object_lookup(k, "dhcp"));
	a.slaac = ucl_object_toboolean(ucl_object_lookup(k, "slaac"));
	if_addr_state(w, ifname, &now);
	{
		static const char *const v4[] = { "DHCP", "SYNCDHCP", NULL };
		static const char *const v6[] = { "inet6", "accept_rtadv",
		    "-accept_rtadv", NULL };
		const char	*rec4, *rec6;
		char		*rest;

		rec4 = ucl_object_lookup(k, "rc") != NULL ?
		    ucl_object_tostring_forced(ucl_object_lookup(k, "rc")) :
		    NULL;
		rec6 = ucl_object_lookup(k, "rc6") != NULL ?
		    ucl_object_tostring_forced(ucl_object_lookup(k, "rc6")) :
		    NULL;
		if (now.rc == NULL)
			a.rc = rec4 != NULL ? wstrdup(w, rec4) : NULL;
		else {
			rest = words_but(w, now.rc, v4);
			a.rc = a.dhcp ? wfmt(w, "DHCP%s%s", rest[0] != '\0' ?
			    " " : "", rest) : rest[0] != '\0' ? rest : NULL;
		}
		if (now.rc6 == NULL)
			a.rc6 = rec6 != NULL ? wstrdup(w, rec6) : a.slaac ?
			    "inet6 accept_rtadv" : NULL;
		else {
			rest = words_but(w, now.rc6, v6);
			a.rc6 = a.slaac ? wfmt(w, "inet6 %s%saccept_rtadv", rest,
			    rest[0] != '\0' ? " " : "") : rest[0] != '\0' ?
			    wfmt(w, "inet6 %s", rest) : NULL;
		}
	}
	step = step_begin(w, ARC_STEP_KIND_FILE, "arcana-agent",
	    "%s: addressed as before: %s%s%s", ifname, a.dhcp ? "DHCP" :
	    "static", a.slaac ? ", SLAAC" : "", a.rc != NULL ? wfmt(w,
	    " (ifconfig_%s=\"%s\")", rc_ifname(w, ifname), a.rc) : "");
	rc = if_addr_restore(w, ifname, &a, persist, errp);
	step_end(w, step, rc == 0, rc == 0 ? NULL : "%s", *errp);
	if (rc == 0) {
		(void)ucl_object_delete_key(all, addr_key(w, ifname));
		addr_keep(w, all);
	}
	ucl_object_unref(all);
	return (rc);
}

/* The addressing as it is, kept unless something is already. */
static void
if_addr_record(struct work *w, const char *ifname)
{
	ucl_object_t		*all, *k;
	struct addr_state	 a;

	all = addr_kept();
	if (ucl_object_lookup(all, addr_key(w, ifname)) == NULL) {
		if_addr_state(w, ifname, &a);
		k = ucl_object_typed_new(UCL_OBJECT);
		if (a.rc != NULL)
			ucl_object_insert_key(k, ucl_object_fromstring(a.rc),
			    "rc", 0, false);
		if (a.rc6 != NULL)
			ucl_object_insert_key(k, ucl_object_fromstring(a.rc6),
			    "rc6", 0, false);
		ucl_object_insert_key(k, ucl_object_frombool(a.dhcp), "dhcp",
		    0, false);
		ucl_object_insert_key(k, ucl_object_frombool(a.slaac), "slaac",
		    0, false);
		ucl_object_insert_key(all, k, addr_key(w, ifname), 0, true);
		addr_keep(w, all);
	}
	ucl_object_unref(all);
}

/*
 * How an interface gets its address (Mplify 119 §12.2.3.2, §12.2.3.3):
 * dhcp, dhclient(8) by the DHCP word of ifconfig_<if> in rc.conf,
 * which its rc script insists on, so kept; slaac, inet6 accept_rtadv on
 * the interface and rtsol(8) once, kept in ifconfig_<if>_ipv6; static,
 * both off, dhclient stopped; was, as it was before Arcana first set
 * dhcp or slaac on it.
 */
static int
if_addressing(struct work *w, const char *ifname, const char *how,
    bool persist, const char **errp)
{
	struct execres	 res;
	const char	*v, *rcn, *rc6;
	char		*argv[6], *words, *word, *rest, out[600];
	bool		 dhcp, slaac;

	dhcp = strcmp(how, "dhcp") == 0;
	slaac = strcmp(how, "slaac") == 0;
	if (strcmp(how, "was") == 0)
		return (if_addr_was(w, ifname, persist, errp));
	if (!dhcp && !slaac && strcmp(how, "static") != 0) {
		*errp = "addressing is dhcp, slaac, static or was";
		return (-1);
	}
	if (dhcp && !persist) {
		*errp = "DHCP on an interface is kept in rc.conf, which its "
		    "rc script reads: say persist";
		return (-1);
	}
	/* What it was before Arcana's first change, for was; a static
	 * chosen lets that go. */
	if (dhcp || slaac)
		if_addr_record(w, ifname);
	else
		if_addr_forget(w, ifname);
	rcn = wfmt(w, "ifconfig_%s", rc_ifname(w, ifname));
	rc6 = wfmt(w, "ifconfig_%s_ipv6", rc_ifname(w, ifname));
	if (persist) {
		/* ifconfig_<if>: DHCP first, or neither word. */
		out[0] = '\0';
		if (dhcp)
			strlcpy(out, "DHCP", sizeof(out));
		words = wstrdup(w, (v = rc_get(w, rcn)) != NULL ? v : "");
		for (rest = words; (word = strsep(&rest, " ")) != NULL; ) {
			if (word[0] == '\0' || strcmp(word, "DHCP") == 0 ||
			    strcmp(word, "SYNCDHCP") == 0 || strcmp(word,
			    "NOAUTO") == 0)
				continue;
			if (strlen(out) + strlen(word) + 2 < sizeof(out))
				snprintf(out + strlen(out), sizeof(out) -
				    strlen(out), "%s%s", out[0] != '\0' ? " " :
				    "", word);
		}
		if (out[0] == '\0')
			rc_unset(w, rcn);
		else if (rc_set(w, rcn, "=", out, errp) != 0)
			return (-1);
		/* ifconfig_<if>_ipv6: inet6 accept_rtadv, or without it. */
		out[0] = '\0';
		words = wstrdup(w, (v = rc_get(w, rc6)) != NULL ? v : "");
		for (rest = words; (word = strsep(&rest, " ")) != NULL; ) {
			if (word[0] == '\0' || strcmp(word, "accept_rtadv") == 0
			    || strcmp(word, "-accept_rtadv") == 0 || strcmp(word,
			    "inet6") == 0)
				continue;
			if (strlen(out) + strlen(word) + 2 < sizeof(out))
				snprintf(out + strlen(out), sizeof(out) -
				    strlen(out), "%s%s", out[0] != '\0' ? " " :
				    "", word);
		}
		if (slaac)
			snprintf(out + strlen(out), sizeof(out) - strlen(out),
			    "%sinet6 accept_rtadv", out[0] != '\0' ? " " : "");
		else if (out[0] != '\0')
			memmove(out, wfmt(w, "inet6 %s", out), strlen(out) + 7);
		if (out[0] == '\0')
			rc_unset(w, rc6);
		else if (rc_set(w, rc6, "=", out, errp) != 0)
			return (-1);
	}
	/* Now: the kernel's flag, and the daemons. */
	argv[0] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[1] = (char *)(uintptr_t)ifname;
	argv[2] = (char *)(uintptr_t)"inet6";
	argv[3] = (char *)(uintptr_t)(slaac ? "accept_rtadv" : "-accept_rtadv");
	argv[4] = (char *)(uintptr_t)(slaac ? "-ifdisabled" : NULL);
	argv[5] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ifconfig"));
		return (-1);
	}
	if (slaac) {
		argv[0] = (char *)(uintptr_t)opts.rtsol_bin;
		argv[1] = (char *)(uintptr_t)ifname;
		argv[2] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			*errp = wtext(w, exec_error(w, &res, "rtsol"));
			return (-1);
		}
	}
	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)"dhclient";
	argv[2] = (char *)(uintptr_t)(dhcp ? "restart" : "stop");
	argv[3] = (char *)(uintptr_t)ifname;
	argv[4] = NULL;
	if (run_exec(w, argv, &res) != 0 && dhcp) {
		*errp = wtext(w, exec_error(w, &res, "service dhclient"));
		return (-1);
	}
	return (0);
}

/*
 * The interfaces that can be made, and what making one takes: a tunnel
 * has two outer ends, a VXLAN an identifier and may have them, a VLAN
 * a tag and the interface it rides, a bridge may take a member in.
 */
enum { CL_PLAIN, CL_TUNNEL, CL_VXLAN, CL_VLAN, CL_BRIDGE, CL_PAIR };

static const struct {
	const char	*type;
	int		 how;
} cloners[] = {
	{ "epair", CL_PAIR }, { "gif", CL_TUNNEL }, { "gre", CL_TUNNEL },
	{ "ipsec", CL_TUNNEL }, { "me", CL_TUNNEL }, { "vxlan", CL_VXLAN },
	{ "vlan", CL_VLAN }, { "bridge", CL_BRIDGE }, { "lagg", CL_PLAIN },
	{ "tap", CL_PLAIN }, { "tun", CL_PLAIN }, { "lo", CL_PLAIN },
	{ "wg", CL_PLAIN }, { "ovpn", CL_PLAIN },
};

/* The kind of the cloner name is of, "gif" or "gif3"; -1 for none. */
static int
cloner_of(const char *name)
{
	size_t	i, len;

	for (i = 0; i < nitems(cloners); i++) {
		len = strlen(cloners[i].type);
		if (strncmp(name, cloners[i].type, len) == 0 &&
		    name[len + strspn(name + len, "0123456789")] == '\0')
			return (cloners[i].how);
	}
	return (-1);
}

/* An address alone, of either family; no option, no name. */
static bool
plain_addr(const char *s)
{
	unsigned char	raw[16];

	return (inet_pton(AF_INET, s, raw) == 1 || inet_pton(AF_INET6, s,
	    raw) == 1);
}

/* What rc.conf lists in cloned_interfaces: an epair without its side. */
static const char *
clone_base(struct work *w, const char *name)
{
	size_t	len;

	len = strlen(name);
	if (strncmp(name, "epair", 5) == 0 && len > 5 && (name[len - 1] ==
	    'a' || name[len - 1] == 'b'))
		return (wstrndup(w, name, len - 1));
	return (name);
}

/* Destroy a cloned interface; with persist, forget it in rc.conf. */
int
do_if_destroy(struct work *w, const char *ifname, bool persist,
    const char **errp)
{
	struct execres	 res;
	const char	*base, *e;
	char		*argv[4];

	base = clone_base(w, ifname);
	if (cloner_of(base) == -1) {
		*errp = wfmt(w, "%s is not an interface that was made: only "
		    "cloned ones are destroyed", ifname);
		return (-1);
	}
	argv[0] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[1] = (char *)(uintptr_t)ifname;
	argv[2] = (char *)(uintptr_t)"destroy";
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ifconfig"));
		return (-1);
	}
	if (persist) {
		e = NULL;
		(void)rc_set(w, "cloned_interfaces", "-=", base, &e);
		wg_forget(w, ifname);
		/* Of a pair, both sides: whichever was named. */
		if (base != ifname) {
			rc_forget_if(w, wfmt(w, "%sa", base));
			rc_forget_if(w, wfmt(w, "%sb", base));
		} else
			rc_forget_if(w, ifname);
	}
	return (0);
}

/*
 * Create a cloned interface and set it up, step by step as one would
 * by hand; what cannot be finished is destroyed again.  *namep is the
 * name it got.
 */
int
do_if_create(struct work *w, const struct arc_job_spec *sp,
    const char **namep, const char **errp)
{
	struct execres	 res;
	const char	*name, *addr, *rcif, *e;
	char		*argv[12], *create, *alias;
	int		 how, n, af, plen;
	bool		 wrote, six;

	wrote = false;
	*namep = NULL;
	if ((how = cloner_of(sp->interface)) == -1) {
		*errp = wfmt(w, "%s is not an interface that can be made: "
		    "epair, gif, gre, ipsec, me, vxlan, vlan, bridge, lagg, "
		    "tap, tun, lo, wg or ovpn, with or without a unit",
		    sp->interface);
		return (-1);
	}
	if ((sp->tunnel_local != NULL && !plain_addr(sp->tunnel_local)) ||
	    (sp->tunnel_remote != NULL && !plain_addr(sp->tunnel_remote))) {
		*errp = "a tunnel's ends are addresses";
		return (-1);
	}
	if ((sp->tunnel_local != NULL) != (sp->tunnel_remote != NULL) ||
	    (how == CL_TUNNEL && sp->tunnel_local == NULL)) {
		*errp = "a tunnel needs both its ends: tunnel-local and "
		    "tunnel-remote";
		return (-1);
	}
	if (sp->tunnel_local != NULL && how != CL_TUNNEL && how != CL_VXLAN) {
		*errp = "only a tunnel has tunnel ends";
		return (-1);
	}
	/*
	 * Both ends of one family; IPv6 ones are said so to ifconfig(8),
	 * which takes the tunnel's ends as IPv4 otherwise, and prints its
	 * refusal yet ends well.
	 */
	six = false;
	if (sp->tunnel_local != NULL && sp->tunnel_remote != NULL) {
		six = strchr(sp->tunnel_local, ':') != NULL;
		if (six != (strchr(sp->tunnel_remote, ':') != NULL)) {
			*errp = "a tunnel's ends are both IPv4 or both IPv6";
			return (-1);
		}
	}
	if (sp->has_reqid && (strncmp(sp->interface, "ipsec", 5) != 0 ||
	    sp->interface[5 + strspn(sp->interface + 5, "0123456789")] !=
	    '\0' || sp->reqid < 1 || sp->reqid > 16383)) {
		*errp = "a reqid, from 1 to 16383, is an ipsec interface's";
		return (-1);
	}
	if (how == CL_VLAN && (!sp->has_id || sp->id < 1 || sp->id > 4094 ||
	    sp->parent == NULL)) {
		*errp = "a vlan needs its tag, 1 to 4094, and the interface "
		    "it rides";
		return (-1);
	}
	if (how == CL_VXLAN && (!sp->has_id || sp->id > 16777215)) {
		*errp = "a vxlan needs its identifier, up to 16777215";
		return (-1);
	}
	if (sp->parent != NULL && !if_exists(w, sp->parent)) {
		*errp = wfmt(w, "no interface %s on this host", sp->parent);
		return (-1);
	}
	if (sp->description != NULL && !valid_descr(sp->description)) {
		*errp = "a description is plain text, without quotes, $ or \\";
		return (-1);
	}
	addr = NULL;
	af = AF_UNSPEC;
	plen = 0;
	if (sp->address != NULL && !parse_addr(w, sp->address, &af, &addr,
	    &plen)) {
		*errp = wfmt(w, "%s is not an IPv4 or IPv6 address, with or "
		    "without a prefix length", sp->address);
		return (-1);
	}
	if (sp->destination != NULL && (addr == NULL || !plain_addr(
	    sp->destination))) {
		*errp = "the far end's inner address is an address, and "
		    "comes with this end's";
		return (-1);
	}

	/* What is given at its creation, and kept as create_args. */
	create = NULL;
	if (how == CL_VLAN)
		create = wfmt(w, "vlan %u vlandev %s", sp->id, sp->parent);
	else if (sp->has_reqid)
		create = wfmt(w, "reqid %u", sp->reqid);
	else if (how == CL_VXLAN)
		create = sp->tunnel_local != NULL && sp->tunnel_remote != NULL ?
		    wfmt(w, "vxlanid %u vxlanlocal %s vxlanremote %s", sp->id,
		    sp->tunnel_local, sp->tunnel_remote) : wfmt(w,
		    "vxlanid %u", sp->id);
	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[n++] = (char *)(uintptr_t)sp->interface;
	argv[n++] = (char *)(uintptr_t)"create";
	if (sp->has_reqid) {
		argv[n++] = (char *)(uintptr_t)"reqid";
		argv[n++] = wfmt(w, "%u", sp->reqid);
	} else if (how == CL_VLAN) {
		argv[n++] = (char *)(uintptr_t)"vlan";
		argv[n++] = wfmt(w, "%u", sp->id);
		argv[n++] = (char *)(uintptr_t)"vlandev";
		argv[n++] = (char *)(uintptr_t)sp->parent;
	} else if (how == CL_VXLAN) {
		argv[n++] = (char *)(uintptr_t)"vxlanid";
		argv[n++] = wfmt(w, "%u", sp->id);
		if (sp->tunnel_local != NULL && sp->tunnel_remote != NULL) {
			argv[n++] = (char *)(uintptr_t)"vxlanlocal";
			argv[n++] = (char *)(uintptr_t)sp->tunnel_local;
			argv[n++] = (char *)(uintptr_t)"vxlanremote";
			argv[n++] = (char *)(uintptr_t)sp->tunnel_remote;
		}
	}
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ifconfig"));
		return (-1);
	}
	/* ifconfig prints the name it made: gif0, or epair0a of a pair. */
	name = res.out != NULL ? wstrndup(w, res.out, strcspn(res.out,
	    " \t\n")) : "";
	if (name[0] == '\0' || cloner_of(clone_base(w, name)) == -1)
		name = how == CL_PAIR && sp->interface[strlen(sp->interface) -
		    1] != 'a' ? wfmt(w, "%sa", sp->interface) : sp->interface;
	*namep = name;
	/* What rc.conf sets up under that name already is not replaced. */
	if (sp->persist && rc_get(w, wfmt(w, "ifconfig_%s", name)) != NULL) {
		e = wfmt(w, "rc.conf sets up %s already: take that out first, "
		    "or do not keep this one", name);
		goto undo_said;
	}

	argv[1] = (char *)(uintptr_t)name;
	/*
	 * Its tables first: an address added after is routed in the
	 * interface's table, and a tunnel's ends are looked up in its own.
	 */
	if (sp->has_fib && ifset_word(w, name, "fib", wfmt(w, "%u", sp->fib),
	    &e) != 0)
		goto undo_said;
	if (sp->has_tunnelfib && ifset_word(w, name, "tunnelfib", wfmt(w,
	    "%u", sp->tunnelfib), &e) != 0)
		goto undo_said;
	if (how == CL_TUNNEL) {
		n = 2;
		if (six)
			argv[n++] = (char *)(uintptr_t)"inet6";
		argv[n++] = (char *)(uintptr_t)"tunnel";
		argv[n++] = (char *)(uintptr_t)sp->tunnel_local;
		argv[n++] = (char *)(uintptr_t)sp->tunnel_remote;
		argv[n] = NULL;
		if (run_exec(w, argv, &res) != 0)
			goto undo;
	}
	if (how == CL_BRIDGE && sp->parent != NULL) {
		argv[2] = (char *)(uintptr_t)"addm";
		argv[3] = (char *)(uintptr_t)sp->parent;
		argv[4] = NULL;
		if (run_exec(w, argv, &res) != 0)
			goto undo;
	}
	alias = NULL;
	if (addr != NULL) {
		/* With a far end, a point-to-point address: this, then that. */
		n = 2;
		argv[n++] = (char *)(uintptr_t)(af == AF_INET ? "inet" :
		    "inet6");
		if (sp->destination != NULL && af == AF_INET6) {
			argv[n++] = (char *)(uintptr_t)addr;
			argv[n++] = (char *)(uintptr_t)sp->destination;
			argv[n++] = (char *)(uintptr_t)"prefixlen";
			argv[n++] = (char *)(uintptr_t)"128";
			alias = wfmt(w, "inet6 %s %s prefixlen 128", addr,
			    sp->destination);
		} else {
			argv[n++] = wfmt(w, "%s/%d", addr, plen);
			if (sp->destination != NULL)
				argv[n++] = (char *)(uintptr_t)sp->destination;
			alias = wfmt(w, "%s %s/%d%s%s", af == AF_INET ? "inet" :
			    "inet6", addr, plen, sp->destination != NULL ?
			    " " : "", sp->destination != NULL ?
			    sp->destination : "");
		}
		argv[n] = NULL;
		if (run_exec(w, argv, &res) != 0)
			goto undo;
	}
	if (sp->has_mtu && sp->mtu != 0) {
		if (sp->mtu < 68 || sp->mtu > 65535) {
			e = "an MTU is between 68 and 65535";
			goto undo_said;
		}
		argv[2] = (char *)(uintptr_t)"mtu";
		argv[3] = wfmt(w, "%u", sp->mtu);
		argv[4] = NULL;
		if (run_exec(w, argv, &res) != 0)
			goto undo;
	}
	if (sp->description != NULL && sp->description[0] != '\0') {
		argv[2] = (char *)(uintptr_t)"description";
		argv[3] = (char *)(uintptr_t)sp->description;
		argv[4] = NULL;
		if (run_exec(w, argv, &res) != 0)
			goto undo;
	}
	argv[2] = (char *)(uintptr_t)"up";
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0)
		goto undo;
	if (!sp->persist)
		return (0);
	/*
	 * A WireGuard interface is kept another way, once it has its key:
	 * written for wg-quick(8), which makes the interface itself.
	 */
	if (strncmp(name, "wg", 2) == 0)
		return (0);

	/* As rc(8) will make it again: the clone, its arguments, its setup. */
	rcif = name;
	e = NULL;
	wrote = true;
	if (rc_set(w, "cloned_interfaces", "+=", clone_base(w, name), &e) != 0)
		goto undo_said;
	if (create != NULL && rc_set(w, wfmt(w, "create_args_%s", name), "=",
	    create, &e) != 0)
		goto undo_said;
	if (rc_set(w, wfmt(w, "ifconfig_%s", rcif), "=", wfmt(w, "%s%s%s%s%s%s"
	    "%s%sup", how == CL_TUNNEL ? six ? "inet6 tunnel " : "tunnel " :
	    "", how == CL_TUNNEL ?
	    sp->tunnel_local : "", how == CL_TUNNEL ? " " : "",
	    how == CL_TUNNEL ? sp->tunnel_remote : "", how == CL_TUNNEL ? " " :
	    "", how == CL_BRIDGE && sp->parent != NULL ? wfmt(w, "addm %s ",
	    sp->parent) : "", sp->has_mtu && sp->mtu != 0 ? wfmt(w, "mtu %u ",
	    sp->mtu) : "", wfmt(w, "%s%s", sp->has_fib && sp->fib != 0 ?
	    wfmt(w, "fib %u ", sp->fib) : "", sp->has_tunnelfib &&
	    sp->tunnelfib != 0 ? wfmt(w, "tunnelfib %u ", sp->tunnelfib) :
	    "")), &e) != 0)
		goto undo_said;
	if (alias != NULL && rc_set(w, wfmt(w, "ifconfig_%s_alias0", rcif), "=",
	    alias, &e) != 0)
		goto undo_said;
	if (sp->description != NULL && sp->description[0] != '\0' &&
	    rc_set(w, wfmt(w, "ifconfig_%s_descr", rcif), "=", sp->description,
	    &e) != 0)
		goto undo_said;
	return (0);
undo:
	e = wtext(w, exec_error(w, &res, "ifconfig"));
undo_said:
	/* It goes again, and from rc.conf only what was put there now. */
	*errp = e;
	e = NULL;
	(void)do_if_destroy(w, name, wrote, &e);
	return (-1);
}

/*
 * Does this host have the address sa on an interface, and which?  An
 * IPv4 address inside an IPv6 one is taken out of it first.
 */
bool
if_owning(const struct sockaddr *sa, char *ifname, size_t len)
{
	struct ifaddrs			*ifap, *ifa;
	const struct sockaddr_in6	*s6;
	struct in_addr			 v4;
	bool				 found, mapped;

	mapped = false;
	if (sa->sa_family == AF_INET)
		v4 = ((const struct sockaddr_in *)(const void *)sa)->sin_addr;
	else if (sa->sa_family == AF_INET6) {
		s6 = (const struct sockaddr_in6 *)(const void *)sa;
		if ((mapped = IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr)))
			memcpy(&v4, &s6->sin6_addr.s6_addr[12], sizeof(v4));
	} else
		return (false);
	if (getifaddrs(&ifap) == -1)
		return (false);
	found = false;
	for (ifa = ifap; ifa != NULL && !found; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (ifa->ifa_addr->sa_family == AF_INET &&
		    (sa->sa_family == AF_INET || mapped))
			found = ((const struct sockaddr_in *)(const void *)
			    ifa->ifa_addr)->sin_addr.s_addr == v4.s_addr;
		else if (ifa->ifa_addr->sa_family == AF_INET6 &&
		    sa->sa_family == AF_INET6 && !mapped)
			found = memcmp(&((const struct sockaddr_in6 *)
			    (const void *)ifa->ifa_addr)->sin6_addr,
			    &((const struct sockaddr_in6 *)(const void *)sa)->
			    sin6_addr, sizeof(struct in6_addr)) == 0;
		if (found)
			strlcpy(ifname, ifa->ifa_name, len);
	}
	freeifaddrs(ifap);
	return (found);
}

/*
 * What the daemon asks of the interfaces in its own process, answered
 * as text: the same question is put to the helper when it is about a
 * jail.  what is interfaces (arg the family), exists, current, up or
 * prefix (arg the address).  malloc(3)ed; NULL when it cannot be told.
 */
char *
ifq_text(const char *what, const char *ifname, const char *arg)
{
	struct arc_network_rsp	 rsp;
	struct work		 w;
	const char		*s;
	char			*out, descr[256];
	unsigned int		 mtu;
	int			 fib, tfib;
	bool			 up;

	work_init(&w);
	out = NULL;
	if (strcmp(what, "interfaces") == 0) {
		memset(&rsp, 0, sizeof(rsp));
		do_interfaces(&w, arg != NULL ? (uint8_t)atoi(arg) :
		    ARC_NET_FAMILY_ALL, &rsp);
		if (rsp.ok && rsp.json != NULL)
			out = strdup(rsp.json);
	} else if (strcmp(what, "plugins") == 0) {
		/* The plugins' programs, as this jail sees its files. */
		if (asprintf(&out, "%u", plugins_here()) == -1)
			out = NULL;
	} else if (ifname == NULL && strcmp(what, "prefix") != 0) {
		;
	} else if (strcmp(what, "exists") == 0) {
		out = strdup(if_nametoindex(ifname) != 0 ? "1" : "0");
	} else if (strcmp(what, "current") == 0) {
		host_current(ifname, &mtu, &fib, &tfib, descr, sizeof(descr));
		if (asprintf(&out, "%u\t%d\t%d\t%s", mtu, fib, tfib, descr) ==
		    -1)
			out = NULL;
	} else if (strcmp(what, "up") == 0) {
		out = strdup(!host_is_up(ifname, &up) ? "?" : up ? "1" : "0");
	} else if (strcmp(what, "link") == 0) {
		out = strdup(!host_link(ifname, &up) ? "?" : up ? "1" : "0");
	} else if (strcmp(what, "prefix") == 0 && arg != NULL) {
		s = host_prefix(&w, ifname, arg);
		out = strdup(s != NULL ? s : "");
	}
	work_free(&w);
	return (out);
}

/* The answer for where w works: here, or in its jail by the helper. */
static const char *
ifq(struct work *w, const char *what, const char *ifname, const char *arg)
{
	struct execres	 res;
	char		*argv[7], *out;

	if (w->jail == NULL)
		return ((out = ifq_text(what, ifname, arg)) != NULL ?
		    wadopt(w, out) : NULL);
	argv[0] = (char *)(uintptr_t)opts.helper_bin;
	argv[1] = (char *)(uintptr_t)"--scope-helper";
	argv[2] = wfmt(w, "%d", w->jid);
	argv[3] = (char *)(uintptr_t)what;
	argv[4] = (char *)(uintptr_t)(ifname != NULL ? ifname : "-");
	argv[5] = (char *)(uintptr_t)(arg != NULL ? arg : "-");
	argv[6] = NULL;
	if (run_exec_max(w, argv, &res, ARC_MAX_JSON) != 0 || res.out == NULL)
		return (NULL);
	return (res.out);
}

bool
if_exists(struct work *w, const char *ifname)
{
	const char	*a;

	return ((a = ifq(w, "exists", ifname, NULL)) != NULL && a[0] == '1');
}

/* Is the interface up?  False when it could not be told. */
/* Has it its link, where w works?  False when it could not be told
 * (none of the name, say). */
bool
if_link(struct work *w, const char *ifname, bool *okp)
{
	const char	*a;

	if ((a = ifq(w, "link", ifname, NULL)) == NULL || (a[0] != '0' &&
	    a[0] != '1'))
		return (false);
	*okp = a[0] == '1';
	return (true);
}

bool
if_is_up(struct work *w, const char *ifname, bool *upp)
{
	const char	*a;

	if ((a = ifq(w, "up", ifname, NULL)) == NULL || (a[0] != '0' &&
	    a[0] != '1'))
		return (false);
	*upp = a[0] == '1';
	return (true);
}

/*
 * The MTU, the routing tables (-1 where it has none: tunnelfib is a
 * tunnel's) and the description an interface has now.
 */
void
if_current(struct work *w, const char *ifname, unsigned int *mtup, int *fibp,
    int *tfibp, char *descr, size_t len)
{
	const char	*a;
	char		*p;

	*mtup = 0;
	*fibp = *tfibp = -1;
	descr[0] = '\0';
	if ((a = ifq(w, "current", ifname, NULL)) == NULL)
		return;
	*mtup = (unsigned int)strtoul(a, &p, 10);
	if (*p == '\t')
		*fibp = (int)strtol(p + 1, &p, 10);
	if (*p == '\t')
		*tfibp = (int)strtol(p + 1, &p, 10);
	if (*p == '\t')
		snprintf(descr, len, "%.*s", (int)strcspn(p + 1, "\n"),
		    p + 1);
}

/*
 * address as the interface has it now, with its prefix length: what
 * puts it back after it was taken off.  NULL when it is not there.
 * Without an interface named, as whichever interface has it.
 */
const char *
if_address_with_prefix(struct work *w, const char *ifname, const char *address)
{
	const char	*a;

	a = ifq(w, "prefix", ifname, address);
	return (a != NULL && a[0] != '\0' ? wstrndup(w, a, strcspn(a, "\n")) :
	    NULL);
}

/* The interfaces where w works, as do_interfaces() tells them. */
const char *
if_json(struct work *w)
{

	return (ifq(w, "interfaces", NULL, "0"));
}

