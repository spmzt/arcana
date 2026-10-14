/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the interfaces as ietf-interfaces (RFC 8343) has them in the
 * operational datastore (PLAN-SDN-YANG 1.9.1), read as ifconfig(8) and
 * netstat(1) -i read them:
 *
 * - every interface getifaddrs(3) gives, by its AF_LINK entry: its
 *   index and link-layer address (struct sockaddr_dl), and its struct
 *   if_data (net/if.h): the type, an IANA ifType as iana-if-type's
 *   identities name them (FreeBSD's own, gif, WireGuard, pflog..., as
 *   IANA's tunnel or other); the link state; the speed (ifi_baudrate); the
 *   last change (ifi_lastchange, wall clock); and the counters, which
 *   count from ifi_epoch (uptime, so kern.boottime after it is their
 *   discontinuity-time);
 * - its flags: IFF_UP is enabled and admin-status;
 * - its description: SIOCGIFDESCR, as ifconfig(8) shows it.
 *
 * oper-status is the link state where the driver knows it: up, down, or
 * down for an interface that is not up; where it does not (a loopback,
 * a tunnel), IFF_RUNNING says up, else unknown.  FreeBSD counts
 * broadcast frames with multicast ones (ifi_imcasts, ifi_omcasts): the
 * multicast counters hold both, the broadcast ones are left out, and the
 * unicast ones are the packets less them.  The discard and error
 * counters are counter32: FreeBSD's 64-bit counts modulo 2^32.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "collect.h"

/*
 * FreeBSD's IFT_* are IANA's ifType numbers, their identities named
 * here, up to its own from 0xf0: its tunnels (gif, WireGuard) are IANA's
 * tunnel, the rest (pflog, pfsync, enc) other.
 */
static const struct {
	uint8_t		 ift;
	const char	*name;
} iftypes[] = {
	{ IFT_OTHER, "other" },
	{ IFT_ETHER, "ethernetCsmacd" },
	{ IFT_ISO88023, "iso88023Csmacd" },
	{ IFT_PPP, "ppp" },
	{ IFT_LOOP, "softwareLoopback" },
	{ IFT_SLIP, "slip" },
	{ IFT_RS232, "rs232" },
	{ IFT_PROPVIRTUAL, "propVirtual" },
	{ IFT_TUNNEL, "tunnel" },
	{ IFT_L2VLAN, "l2vlan" },
	{ IFT_IEEE8023ADLAG, "ieee8023adLag" },
	{ IFT_BRIDGE, "bridge" },
	{ IFT_GIF, "tunnel" },
	{ IFT_WIREGUARD, "tunnel" },
	{ IFT_STF, "sixToFour" },
	{ IFT_INFINIBAND, "infiniband" },
	{ IFT_IEEE80211, "ieee80211" },
	{ IFT_USB, "usb" },
};

/* An iana-if-type identity's SID, by its name; 0: none. */
static uint64_t
iftype_sid(const char *name)
{

	for (uint32_t i = 0; i < ymodel_schema.nident; i++) {
		const struct cbl_yident *id = &ymodel_schema.ident[i];

		if (strcmp(id->name, name) == 0 &&
		    strcmp(id->module->name, "iana-if-type") == 0)
			return (id->sid);
	}
	return (0);
}

static uint64_t
type_of(uint8_t ift)
{

	for (size_t i = 0; i < nitems(iftypes); i++)
		if (iftypes[i].ift == ift)
			return (iftype_sid(iftypes[i].name));
	return (iftype_sid("other"));
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

/* A time as yang:date-and-time has it, in UTC. */
static char *
datetime(cbl_yarena *a, time_t sec, long usec)
{
	char buf[sizeof("YYYY-MM-DDThh:mm:ss.uuuuuuZ")];
	struct tm tm;
	size_t n;

	if (gmtime_r(&sec, &tm) == NULL)
		return (NULL);
	n = strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
	snprintf(buf + n, sizeof(buf) - n, ".%06ldZ", usec);
	return (astrdup(a, buf));
}

/* yang:phys-address: the octets in hex, a colon between. */
static char *
physaddr(cbl_yarena *a, const struct sockaddr_dl *sdl)
{
	const uint8_t *p = (const uint8_t *)LLADDR(sdl);
	char *s;

	if (sdl->sdl_alen == 0 ||
	    (s = cbl_yarena_alloc(a, sdl->sdl_alen * 3)) == NULL)
		return (NULL);
	for (size_t i = 0; i < sdl->sdl_alen; i++)
		snprintf(s + i * 3, 4, "%02x%s", p[i],
		    i + 1 < sdl->sdl_alen ? ":" : "");
	return (s);
}

/* What ifconfig(8) shows as its description, if any. */
static char *
description(cbl_yarena *a, int s, const char *name)
{
	char buf[1024];
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_buffer.buffer = buf;
	ifr.ifr_buffer.length = sizeof(buf);
	if (s == -1 || ioctl(s, SIOCGIFDESCR, &ifr) != 0 ||
	    ifr.ifr_buffer.buffer == NULL || buf[0] == '\0')
		return (NULL);
	buf[sizeof(buf) - 1] = '\0';
	return (astrdup(a, buf));
}

static int
one(struct ietf_interfaces_interfaces_interface *e, const struct ifaddrs *ifa,
    int s, const struct timeval *boot, cbl_yarena *a)
{
	const struct sockaddr_dl *sdl = (const void *)ifa->ifa_addr;
	const struct if_data *d = ifa->ifa_data;
	struct ietf_interfaces_interfaces_interface_statistics *st;
	bool up = (ifa->ifa_flags & IFF_UP) != 0;

	if ((e->name = astrdup(a, ifa->ifa_name)) == NULL)
		return (ENOMEM);
	e->description = description(a, s, ifa->ifa_name);
	e->has_enabled = true;
	e->enabled = up;
	e->has_admin_status = true;
	e->admin_status = up ?
	    IETF_INTERFACES_INTERFACES_INTERFACE_ADMIN_STATUS_UP :
	    IETF_INTERFACES_INTERFACES_INTERFACE_ADMIN_STATUS_DOWN;
	e->has_if_index = true;
	e->if_index = sdl->sdl_index;
	e->phys_address = physaddr(a, sdl);
	if (d == NULL)
		return (0);
	if ((e->type = type_of(d->ifi_type)) != 0)
		e->has_type = true;
	e->has_oper_status = true;
	if (!up || d->ifi_link_state == LINK_STATE_DOWN)
		e->oper_status =
		    IETF_INTERFACES_INTERFACES_INTERFACE_OPER_STATUS_DOWN;
	else if (d->ifi_link_state == LINK_STATE_UP ||
	    (ifa->ifa_flags & IFF_RUNNING) != 0)
		e->oper_status =
		    IETF_INTERFACES_INTERFACES_INTERFACE_OPER_STATUS_UP;
	else
		e->oper_status =
		    IETF_INTERFACES_INTERFACES_INTERFACE_OPER_STATUS_UNKNOWN;
	if (d->ifi_lastchange.tv_sec != 0)
		e->last_change = datetime(a, d->ifi_lastchange.tv_sec,
		    d->ifi_lastchange.tv_usec);
	if (d->ifi_baudrate != 0) {
		e->has_speed = true;
		e->speed = d->ifi_baudrate;
	}
	if ((st = cbl_yarena_alloc(a, sizeof(*st))) == NULL)
		return (ENOMEM);
	st->discontinuity_time = datetime(a, boot->tv_sec + d->ifi_epoch,
	    boot->tv_usec);
#define	C64(f, v)	do { st->has_##f = true; st->f = (v); } while (0)
#define	C32(f, v)	do { st->has_##f = true; st->f = (uint32_t)(v); } while (0)
	C64(in_octets, d->ifi_ibytes);
	C64(in_unicast_pkts, d->ifi_ipackets - MIN(d->ifi_imcasts,
	    d->ifi_ipackets));
	C64(in_multicast_pkts, d->ifi_imcasts);
	C32(in_discards, d->ifi_iqdrops);
	C32(in_errors, d->ifi_ierrors);
	C32(in_unknown_protos, d->ifi_noproto);
	C64(out_octets, d->ifi_obytes);
	C64(out_unicast_pkts, d->ifi_opackets - MIN(d->ifi_omcasts,
	    d->ifi_opackets));
	C64(out_multicast_pkts, d->ifi_omcasts);
	C32(out_discards, d->ifi_oqdrops);
	C32(out_errors, d->ifi_oerrors);
#undef C64
#undef C32
	e->statistics = st;
	return (0);
}

/*
 * Whether an interface of that name is listed already.  Names are the
 * list's key, one an entry.  FreeBSD checks them when an interface is
 * renamed or moved in or out of a jail, but not when a vnet jail goes
 * away and its interfaces come home (vnet_if_return(), if_vmove()), so
 * two may share one: the first, of the lowest index, is the one listed.
 */
static bool
named(const struct ietf_interfaces_interfaces_interface *v, size_t n,
    const char *name)
{

	for (size_t i = 0; i < n; i++)
		if (strcmp(v[i].name, name) == 0)
			return (true);
	return (false);
}

int
yif_interfaces(struct ietf_interfaces *data, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface *v;
	struct ietf_interfaces_interfaces *ifs;
	struct ifaddrs *ifa0, *ifa;
	struct timeval boot;
	size_t n = 0, len = sizeof(boot);
	int s, error = 0;

	if (sysctlbyname("kern.boottime", &boot, &len, NULL, 0) != 0)
		return (errno);
	if (getifaddrs(&ifa0) != 0)
		return (errno);
	for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next)
		if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_LINK)
			n++;
	if ((ifs = cbl_yarena_alloc(a, sizeof(*ifs))) == NULL ||
	    (v = cbl_yarena_alloc(a, n * sizeof(*v))) == NULL) {
		freeifaddrs(ifa0);
		return (ENOMEM);
	}
	s = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	n = 0;
	for (ifa = ifa0; ifa != NULL && error == 0; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_LINK ||
		    named(v, n, ifa->ifa_name))
			continue;
		error = one(&v[n++], ifa, s, &boot, a);
	}
	if (s != -1)
		close(s);
	freeifaddrs(ifa0);
	if (error != 0)
		return (error);
	ifs->interface.n = n;
	ifs->interface.v = v;
	data->interfaces = ifs;
	return (0);
}
