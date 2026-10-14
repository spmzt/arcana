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
 * - its description: SIOCGIFDESCR, as ifconfig(8) shows it;
 * - its layers (PLAN-SDN-YANG 1.9.2), lower-layer-if and the other end's
 *   higher-layer-if: a vlan's parent (SIOCGETVLAN), a lagg's ports
 *   (SIOCGLAGG), a bridge's members (SIOCGDRVSPEC, BRDGGIFS), as
 *   ifconfig(8) asks them.  if_type does not tell a lagg: it stays
 *   IFT_ETHER and its ports become IFT_IEEE8023ADLAG (if_lagg.c).  So
 *   SIOCGLAGG, which only lagg answers, is asked of every Ethernet and
 *   InfiniBand interface, and one that answers is IANA's ieee8023adLag,
 *   the aggregate; SIOCGETVLAN of an l2vlan and of a lagg's port, which
 *   may be a vlan; a port that is not is the ethernetCsmacd it was.
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
#include <net/if_bridgevar.h>
#include <net/if_dl.h>
#include <net/if_lagg.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>

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

/* An interface layered on another: hi on lo. */
struct layer {
	char	hi[IFNAMSIZ];
	char	lo[IFNAMSIZ];
};

struct layers {
	struct layer	*v;
	size_t		 n;
};

static void
layer_add(struct layers *l, const char *hi, const char *lo)
{
	struct layer *v;

	if (lo[0] == '\0' ||
	    (v = reallocarray(l->v, l->n + 1, sizeof(*v))) == NULL)
		return;
	l->v = v;
	strlcpy(v[l->n].hi, hi, sizeof(v[l->n].hi));
	strlcpy(v[l->n].lo, lo, sizeof(v[l->n].lo));
	l->n++;
}

/*
 * What interface name of type ift is on, by the ioctl its kind answers;
 * the iana-if-type identity it is, where if_type does not say, or NULL.
 */
static const char *
layers_of(struct layers *l, int s, const char *name, uint8_t ift)
{

	if (s == -1)
		return (NULL);
	if (ift == IFT_ETHER || ift == IFT_INFINIBAND) {
		struct lagg_reqport rp[LAGG_MAX_PORTS];
		struct lagg_reqall ra;

		memset(&ra, 0, sizeof(ra));
		strlcpy(ra.ra_ifname, name, sizeof(ra.ra_ifname));
		ra.ra_size = sizeof(rp);
		ra.ra_port = rp;
		if (ioctl(s, SIOCGLAGG, &ra) != 0)
			return (NULL);
		for (int i = 0; i < ra.ra_ports && i < LAGG_MAX_PORTS; i++)
			layer_add(l, name, rp[i].rp_portname);
		return ("ieee8023adLag");
	} else if (ift == IFT_L2VLAN || ift == IFT_IEEE8023ADLAG) {
		struct vlanreq vr;
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		memset(&vr, 0, sizeof(vr));
		strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
		ifr.ifr_data = (caddr_t)&vr;
		if (ioctl(s, SIOCGETVLAN, &ifr) == 0) {
			layer_add(l, name, vr.vlr_parent);
			return ("l2vlan");
		}
		return (ift == IFT_IEEE8023ADLAG ? "ethernetCsmacd" : NULL);
	} else if (ift == IFT_BRIDGE) {
		struct ifbreq *br = NULL, *nbr;
		struct ifbifconf bc;
		struct ifdrv d;
		size_t len = 16 * sizeof(*br);

		/* Grown until the members fit, as libifconfig does. */
		for (;; len *= 2) {
			if ((nbr = realloc(br, len)) == NULL)
				break;
			br = nbr;
			memset(&d, 0, sizeof(d));
			bc.ifbic_len = len;
			bc.ifbic_req = br;
			strlcpy(d.ifd_name, name, sizeof(d.ifd_name));
			d.ifd_cmd = BRDGGIFS;
			d.ifd_len = sizeof(bc);
			d.ifd_data = &bc;
			if (ioctl(s, SIOCGDRVSPEC, &d) != 0)
				break;
			if (bc.ifbic_len + sizeof(*br) < len) {
				for (size_t i = 0;
				    i < bc.ifbic_len / sizeof(*br); i++)
					layer_add(l, name, br[i].ifbr_ifsname);
				break;
			}
		}
		free(br);
	}
	return (NULL);
}

/*
 * The interfaces name is on (lower) or under (!lower), those the list
 * has, by the list's own strings.
 */
static int
layer_names(const struct layers *l, const char *name, bool lower,
    const struct ietf_interfaces_interfaces_interface *v, size_t n,
    size_t *outn, const char *const **outv, cbl_yarena *a)
{
	const char **names;
	size_t k = 0;

	if ((names = cbl_yarena_alloc(a, (l->n + 1) * sizeof(*names))) ==
	    NULL)
		return (ENOMEM);
	for (size_t i = 0; i < l->n; i++) {
		const char *self = lower ? l->v[i].hi : l->v[i].lo;
		const char *other = lower ? l->v[i].lo : l->v[i].hi;

		if (strcmp(self, name) != 0)
			continue;
		for (size_t j = 0; j < n; j++)
			if (strcmp(v[j].name, other) == 0) {
				names[k++] = v[j].name;
				break;
			}
	}
	*outn = k;
	*outv = names;
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
	struct layers lay = { NULL, 0 };
	const char *kind;
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
		if ((error = one(&v[n], ifa, s, &boot, a)) == 0 &&
		    ifa->ifa_data != NULL &&
		    (kind = layers_of(&lay, s, ifa->ifa_name,
		    ((const struct if_data *)ifa->ifa_data)->ifi_type)) !=
		    NULL && (v[n].type = iftype_sid(kind)) != 0)
			v[n].has_type = true;
		n++;
	}
	for (size_t i = 0; i < n && error == 0; i++)
		if ((error = layer_names(&lay, v[i].name, true, v, n,
		    &v[i].lower_layer_if.n, &v[i].lower_layer_if.v, a)) == 0)
			error = layer_names(&lay, v[i].name, false, v, n,
			    &v[i].higher_layer_if.n, &v[i].higher_layer_if.v,
			    a);
	free(lay.v);
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
