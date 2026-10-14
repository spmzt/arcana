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
 *   may be a vlan; a port that is not is the ethernetCsmacd it was;
 * - what arcana-interfaces adds (PLAN-SDN-YANG 1.9.3), each leaf as its
 *   description in the module says: the driver name, MTU, Ethernet and
 *   hardware addresses, groups, FIBs, capabilities, media, and the parts
 *   of a vlan, a lagg, a bridge and an epair, the first three from the
 *   ioctls that tell their layers.
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
#include <sys/nv.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <net/bridgestp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_bridgevar.h>
#include <net/if_dl.h>
#include <net/if_lagg.h>
#include <net/if_media.h>
#include <net/if_mib.h>
#define	_WANT_IFCAP_BIT_NAMES
#include <net/if_strings.h>
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

typedef struct ietf_interfaces_interfaces_interface yif;

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

/* arcif:capabilities' positions: IFCAP_B_* up to GENEVE_HWTSO. */
#define	YCAP_NBITS	37

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

/* A bits value of positions 0 to 63, as the codec takes it. */
static struct cbl_bytes
bits(cbl_yarena *a, uint64_t v)
{
	struct cbl_bytes b = { NULL, 0 };
	uint8_t *p;

	if ((p = cbl_yarena_alloc(a, sizeof(v))) == NULL)
		return (b);
	for (size_t i = 0; i < sizeof(v); i++)
		p[i] = (uint8_t)(v >> (8 * i));
	b.p = p;
	b.len = sizeof(v);
	return (b);
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
hexaddr(cbl_yarena *a, const uint8_t *p, size_t len)
{
	char *s;

	if (len == 0 || (s = cbl_yarena_alloc(a, len * 3)) == NULL)
		return (NULL);
	for (size_t i = 0; i < len; i++)
		snprintf(s + i * 3, 4, "%02x%s", p[i], i + 1 < len ? ":" : "");
	return (s);
}

static void
ifreq_for(struct ifreq *ifr, const char *name)
{

	memset(ifr, 0, sizeof(*ifr));
	strlcpy(ifr->ifr_name, name, sizeof(ifr->ifr_name));
}

/* What ifconfig(8) shows as its description, if any. */
static char *
description(cbl_yarena *a, int s, const char *name)
{
	char buf[1024];
	struct ifreq ifr;

	ifreq_for(&ifr, name);
	ifr.ifr_buffer.buffer = buf;
	ifr.ifr_buffer.length = sizeof(buf);
	if (ioctl(s, SIOCGIFDESCR, &ifr) != 0 ||
	    ifr.ifr_buffer.buffer == NULL || buf[0] == '\0')
		return (NULL);
	buf[sizeof(buf) - 1] = '\0';
	return (astrdup(a, buf));
}

static int
one(yif *e, const struct ifaddrs *ifa, int s, const struct timeval *boot,
    cbl_yarena *a)
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
	e->phys_address = hexaddr(a, (const uint8_t *)LLADDR(sdl),
	    sdl->sdl_alen);
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
 * arcana-interfaces: what every interface may have.
 */

/* The groups it is in, but "all", which every interface is in. */
static int
groups(yif *e, int s, cbl_yarena *a)
{
	struct ifgroupreq ifgr;
	struct ifg_req *g;
	const char **v;
	size_t n, k = 0;

	memset(&ifgr, 0, sizeof(ifgr));
	strlcpy(ifgr.ifgr_name, e->name, sizeof(ifgr.ifgr_name));
	if (ioctl(s, SIOCGIFGROUP, &ifgr) != 0 || ifgr.ifgr_len == 0)
		return (0);
	if ((g = malloc(ifgr.ifgr_len)) == NULL)
		return (ENOMEM);
	ifgr.ifgr_groups = g;
	if (ioctl(s, SIOCGIFGROUP, &ifgr) != 0) {
		free(g);
		return (0);
	}
	n = ifgr.ifgr_len / sizeof(*g);
	if ((v = cbl_yarena_alloc(a, n * sizeof(*v))) == NULL) {
		free(g);
		return (ENOMEM);
	}
	for (size_t i = 0; i < n; i++)
		if (strcmp(g[i].ifgrq_group, "all") != 0 &&
		    (v[k] = astrdup(a, g[i].ifgrq_group)) != NULL)
			k++;
	free(g);
	e->arcif_group.n = k;
	e->arcif_group.v = v;
	return (0);
}

/*
 * The capabilities, supported and enabled: SIOCGIFCAP's 32, and where
 * the driver speaks it SIOCGIFCAPNV's, by the names <net/if_strings.h>
 * gives the bits, for those from 32.
 */
static int
capabilities(yif *e, int s, cbl_yarena *a)
{
	uint64_t sup, cur;
	struct ifreq ifr;
	const char *name;
	nvlist_t *nv;
	void *buf, *cookie = NULL;
	int type;

	ifreq_for(&ifr, e->name);
	if (ioctl(s, SIOCGIFCAP, &ifr) != 0)
		return (0);
	sup = (uint32_t)ifr.ifr_reqcap;
	cur = (uint32_t)ifr.ifr_curcap;
	if ((sup & IFCAP_NV) != 0) {
		if ((buf = malloc(IFR_CAP_NV_MAXBUFSIZE)) == NULL)
			return (ENOMEM);
		ifreq_for(&ifr, e->name);
		ifr.ifr_cap_nv.buffer = buf;
		ifr.ifr_cap_nv.buf_length = IFR_CAP_NV_MAXBUFSIZE;
		if (ioctl(s, SIOCGIFCAPNV, &ifr) == 0 &&
		    (nv = nvlist_unpack(buf, ifr.ifr_cap_nv.length, 0)) !=
		    NULL) {
			while ((name = nvlist_next(nv, &type, &cookie)) !=
			    NULL) {
				if (type != NV_TYPE_BOOL)
					continue;
				for (size_t i = 0; i < nitems(ifcap_bit_names);
				    i++) {
					if (strcmp(ifcap_bit_names[i], name) !=
					    0)
						continue;
					sup |= UINT64_C(1) << i;
					if (nvlist_get_bool(nv, name))
						cur |= UINT64_C(1) << i;
					break;
				}
			}
			nvlist_destroy(nv);
		}
		free(buf);
	}
	sup &= (UINT64_C(1) << YCAP_NBITS) - 1;
	cur &= (UINT64_C(1) << YCAP_NBITS) - 1;
	e->arcif_capabilities = bits(a, cur);
	e->arcif_capabilities_supported = bits(a, sup);
	return (0);
}

/* Each kind of medium's names, as libifconfig keeps them. */
static const struct ifmedia_description
    ifm_shared_sub[] = IFM_SUBTYPE_SHARED_DESCRIPTIONS,
    ifm_shared_opt[] = IFM_SHARED_OPTION_DESCRIPTIONS,
    ifm_eth_sub[] = IFM_SUBTYPE_ETHERNET_DESCRIPTIONS,
    ifm_eth_opt[] = IFM_SUBTYPE_ETHERNET_OPTION_DESCRIPTIONS,
    ifm_wlan_sub[] = IFM_SUBTYPE_IEEE80211_DESCRIPTIONS,
    ifm_wlan_opt[] = IFM_SUBTYPE_IEEE80211_OPTION_DESCRIPTIONS,
    ifm_wlan_mode[] = IFM_SUBTYPE_IEEE80211_MODE_DESCRIPTIONS,
    ifm_atm_sub[] = IFM_SUBTYPE_ATM_DESCRIPTIONS,
    ifm_atm_opt[] = IFM_SUBTYPE_ATM_OPTION_DESCRIPTIONS;

static const struct ifm_kind {
	int					 type;
	const struct ifmedia_description	*sub, *opt, *mode;
} ifm_kinds[] = {
	{ IFM_ETHER, ifm_eth_sub, ifm_eth_opt, NULL },
	{ IFM_IEEE80211, ifm_wlan_sub, ifm_wlan_opt, ifm_wlan_mode },
	{ IFM_ATM, ifm_atm_sub, ifm_atm_opt, NULL },
};

/* A medium as media-word has it. */
struct mword {
	const char	*subtype;
	const char	**opt;
	size_t		 nopt;
	const char	*mode;
};

static const char *
ifm_name(const struct ifmedia_description *d, int word)
{

	for (; d != NULL && d->ifmt_string != NULL; d++)
		if (d->ifmt_word == word)
			return (d->ifmt_string);
	return (NULL);
}

static const struct ifm_kind *
ifm_kind(int m)
{

	for (size_t i = 0; i < nitems(ifm_kinds); i++)
		if (ifm_kinds[i].type == IFM_TYPE(m))
			return (&ifm_kinds[i]);
	return (NULL);
}

static int
mword(int m, struct mword *w, cbl_yarena *a)
{
	const struct ifmedia_description *ds[2];
	const struct ifm_kind *k;

	memset(w, 0, sizeof(*w));
	if ((k = ifm_kind(m)) == NULL)
		return (0);
	if ((w->subtype = ifm_name(ifm_shared_sub, IFM_SUBTYPE(m))) == NULL)
		w->subtype = ifm_name(k->sub, IFM_SUBTYPE(m));
	ds[0] = ifm_shared_opt;
	ds[1] = k->opt;
	if ((w->opt = cbl_yarena_alloc(a, 32 * sizeof(*w->opt))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < nitems(ds); i++)
		for (const struct ifmedia_description *d = ds[i];
		    d->ifmt_string != NULL && w->nopt < 32; d++)
			if ((IFM_OPTIONS(m) & d->ifmt_word) != 0)
				w->opt[w->nopt++] = d->ifmt_string;
	if (IFM_MODE(m) != 0)
		w->mode = ifm_name(k->mode, IFM_MODE(m));
	return (0);
}

/* A medium as ifconfig(8) -m lists it. */
static char *
mword_text(const struct mword *w, cbl_yarena *a)
{
	char buf[256];

	if (w->subtype == NULL)
		return (NULL);
	strlcpy(buf, w->subtype, sizeof(buf));
	for (size_t i = 0; i < w->nopt; i++) {
		strlcat(buf, i == 0 ? " mediaopt " : ",", sizeof(buf));
		strlcat(buf, w->opt[i], sizeof(buf));
	}
	if (w->mode != NULL) {
		strlcat(buf, " mode ", sizeof(buf));
		strlcat(buf, w->mode, sizeof(buf));
	}
	return (astrdup(a, buf));
}

#define	MWORD_TO(dst, w)	do {					\
	(dst)->subtype = (w).subtype;					\
	(dst)->option.n = (w).nopt;					\
	(dst)->option.v = (w).opt;					\
	(dst)->mode = (w).mode;						\
} while (0)

/* Its medium, as ifconfig(8) shows it, where the driver has one. */
static int
media(yif *e, int s, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_arcif_media *md;
	struct ietf_interfaces_interfaces_interface_arcif_media_current *cur;
	struct ietf_interfaces_interfaces_interface_arcif_media_active *act;
	struct ifmediareq ifmr;
	const char **sv;
	struct mword w;
	int *list, error;
	size_t k = 0;

	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, e->name, sizeof(ifmr.ifm_name));
	if (ioctl(s, SIOCGIFXMEDIA, &ifmr) != 0 &&
	    ioctl(s, SIOCGIFMEDIA, &ifmr) != 0)
		return (0);
	if (ifm_kind(ifmr.ifm_current) == NULL)
		return (0);
	if ((md = cbl_yarena_alloc(a, sizeof(*md))) == NULL ||
	    (cur = cbl_yarena_alloc(a, sizeof(*cur))) == NULL ||
	    (act = cbl_yarena_alloc(a, sizeof(*act))) == NULL)
		return (ENOMEM);
	md->has_type = true;
	md->type = IFM_TYPE(ifmr.ifm_current);
	if ((error = mword(ifmr.ifm_current, &w, a)) != 0)
		return (error);
	MWORD_TO(cur, w);
	md->current = cur;
	if ((error = mword(ifmr.ifm_active, &w, a)) != 0)
		return (error);
	MWORD_TO(act, w);
	md->active = act;
	if ((ifmr.ifm_status & IFM_AVALID) != 0) {
		md->has_status = true;
		if ((ifmr.ifm_status & IFM_ACTIVE) == 0)
			md->status = IETF_INTERFACES_INTERFACES_INTERFACE_ARCIF_MEDIA_STATUS_NO_CARRIER;
		else if (IFM_TYPE(ifmr.ifm_active) != IFM_IEEE80211)
			md->status = IETF_INTERFACES_INTERFACES_INTERFACE_ARCIF_MEDIA_STATUS_ACTIVE;
		/* Only a station associates. */
		else if ((ifmr.ifm_active & (IFM_IEEE80211_ADHOC |
		    IFM_IEEE80211_HOSTAP | IFM_IEEE80211_IBSS |
		    IFM_IEEE80211_WDS | IFM_IEEE80211_MONITOR |
		    IFM_IEEE80211_MBSS)) == 0)
			md->status = IETF_INTERFACES_INTERFACES_INTERFACE_ARCIF_MEDIA_STATUS_ASSOCIATED;
		else
			md->status = IETF_INTERFACES_INTERFACES_INTERFACE_ARCIF_MEDIA_STATUS_RUNNING;
	}
	e->arcif_media = md;
	if (ifmr.ifm_count <= 0)
		return (0);
	if ((list = calloc(ifmr.ifm_count, sizeof(*list))) == NULL)
		return (ENOMEM);
	ifmr.ifm_ulist = list;
	if ((ioctl(s, SIOCGIFXMEDIA, &ifmr) != 0 &&
	    ioctl(s, SIOCGIFMEDIA, &ifmr) != 0) ||
	    (sv = cbl_yarena_alloc(a, ifmr.ifm_count * sizeof(*sv))) == NULL) {
		free(list);
		return (0);
	}
	for (int i = 0; i < ifmr.ifm_count; i++)
		if (mword(list[i], &w, a) == 0 &&
		    (sv[k] = mword_text(&w, a)) != NULL)
			k++;
	free(list);
	md->supported.n = k;
	md->supported.v = sv;
	return (0);
}

/* The parts every interface may have. */
static int
link_parts(yif *e, int s, const struct sockaddr_dl *sdl,
    const struct if_data *d, const char *drv, cbl_yarena *a)
{
	struct ifreq ifr;
	int error;

	if (drv[0] != '\0' &&
	    (e->arcif_driver_name = astrdup(a, drv)) == NULL)
		return (ENOMEM);
	if (d != NULL) {
		e->has_arcif_mtu = true;
		e->arcif_mtu = d->ifi_mtu;
	}
	if (sdl->sdl_alen == ETHER_ADDR_LEN) {
		e->arcif_ether = e->phys_address;
		ifreq_for(&ifr, e->name);
		if (ioctl(s, SIOCGHWADDR, &ifr) == 0 &&
		    memcmp(ifr.ifr_addr.sa_data, "\0\0\0\0\0\0",
		    ETHER_ADDR_LEN) != 0)
			e->arcif_hw_address = hexaddr(a,
			    (const uint8_t *)ifr.ifr_addr.sa_data,
			    ETHER_ADDR_LEN);
	}
	ifreq_for(&ifr, e->name);
	if (ioctl(s, SIOCGIFFIB, &ifr) == 0) {
		e->has_arcif_fib = true;
		e->arcif_fib = ifr.ifr_fib;
	}
	ifreq_for(&ifr, e->name);
	if (ioctl(s, SIOCGTUNFIB, &ifr) == 0) {
		e->has_arcif_tunnel_fib = true;
		e->arcif_tunnel_fib = ifr.ifr_fib;
	}
	if ((error = groups(e, s, a)) != 0 ||
	    (error = capabilities(e, s, a)) != 0)
		return (error);
	return (media(e, s, a));
}

/*
 * Layers, and the kinds of interface that have them.
 */

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

/* A lagg: its protocol, hash and ports; ENOENT: not one. */
static int
lagg(yif *e, struct layers *l, int s, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_arcif_lagg *lg;
	struct ietf_interfaces_interfaces_interface_arcif_lagg_port *pv;
	struct lagg_reqport rp[LAGG_MAX_PORTS];
	struct lagg_reqflags rf;
	struct lagg_reqall ra;
	int n;

	memset(&ra, 0, sizeof(ra));
	strlcpy(ra.ra_ifname, e->name, sizeof(ra.ra_ifname));
	ra.ra_size = sizeof(rp);
	ra.ra_port = rp;
	if (ioctl(s, SIOCGLAGG, &ra) != 0)
		return (ENOENT);
	n = MIN(ra.ra_ports, LAGG_MAX_PORTS);
	if ((lg = cbl_yarena_alloc(a, sizeof(*lg))) == NULL ||
	    (pv = cbl_yarena_alloc(a, n * sizeof(*pv))) == NULL)
		return (ENOMEM);
	if (ra.ra_proto < LAGG_PROTO_MAX) {
		lg->has_protocol = true;
		lg->protocol = ra.ra_proto;
	}
	memset(&rf, 0, sizeof(rf));
	strlcpy(rf.rf_ifname, e->name, sizeof(rf.rf_ifname));
	if (ioctl(s, SIOCGLAGGFLAGS, &rf) == 0)
		lg->hash = bits(a, rf.rf_flags & LAGG_F_HASHMASK);
	for (int i = 0; i < n; i++) {
		if ((pv[i].name = astrdup(a, rp[i].rp_portname)) == NULL)
			return (ENOMEM);
		pv[i].has_priority = true;
		pv[i].priority = rp[i].rp_prio;
		pv[i].flags = bits(a, rp[i].rp_flags & 0x1f);
		layer_add(l, e->name, rp[i].rp_portname);
	}
	lg->port.n = n;
	lg->port.v = pv;
	e->arcif_lagg = lg;
	return (0);
}

/* A vlan: its tag, parent, protocol and priority; ENOENT: not one. */
static int
vlan(yif *e, struct layers *l, int s, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_arcif_vlan *vl;
	struct vlanreq vr;
	struct ifreq ifr;

	memset(&vr, 0, sizeof(vr));
	ifreq_for(&ifr, e->name);
	ifr.ifr_data = (caddr_t)&vr;
	if (ioctl(s, SIOCGETVLAN, &ifr) != 0)
		return (ENOENT);
	if ((vl = cbl_yarena_alloc(a, sizeof(*vl))) == NULL)
		return (ENOMEM);
	if (vr.vlr_tag <= 4095) {
		vl->has_vlan_id = true;
		vl->vlan_id = vr.vlr_tag;
	}
	if (vr.vlr_parent[0] != '\0' &&
	    (vl->parent = astrdup(a, vr.vlr_parent)) == NULL)
		return (ENOMEM);
	if (vr.vlr_proto == ETHERTYPE_VLAN || vr.vlr_proto == ETHERTYPE_QINQ) {
		vl->has_protocol = true;
		vl->protocol = vr.vlr_proto;
	}
	ifreq_for(&ifr, e->name);
	if (ioctl(s, SIOCGVLANPCP, &ifr) == 0 && ifr.ifr_vlan_pcp <= 7) {
		vl->has_pcp = true;
		vl->pcp = ifr.ifr_vlan_pcp;
	}
	layer_add(l, e->name, vr.vlr_parent);
	e->arcif_vlan = vl;
	return (0);
}

/* A bridge's members: their flags, and their STP's where it runs. */
static int
bridge(yif *e, struct layers *l, int s, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_arcif_bridge *bg;
	struct ietf_interfaces_interfaces_interface_arcif_bridge_member *mv;
	struct ifbreq *br = NULL, *nbr;
	struct ifbifconf bc;
	struct ifdrv d;
	size_t n = 0, len = 16 * sizeof(*br);
	int error = 0;

	/* Grown until the members fit, as libifconfig does. */
	for (;; len *= 2) {
		if ((nbr = realloc(br, len)) == NULL) {
			free(br);
			return (ENOMEM);
		}
		br = nbr;
		memset(&d, 0, sizeof(d));
		bc.ifbic_len = len;
		bc.ifbic_req = br;
		strlcpy(d.ifd_name, e->name, sizeof(d.ifd_name));
		d.ifd_cmd = BRDGGIFS;
		d.ifd_len = sizeof(bc);
		d.ifd_data = &bc;
		if (ioctl(s, SIOCGDRVSPEC, &d) != 0) {
			free(br);
			return (0);
		}
		if (bc.ifbic_len + sizeof(*br) < len) {
			n = bc.ifbic_len / sizeof(*br);
			break;
		}
	}
	if ((bg = cbl_yarena_alloc(a, sizeof(*bg))) == NULL ||
	    (mv = cbl_yarena_alloc(a, n * sizeof(*mv))) == NULL) {
		free(br);
		return (ENOMEM);
	}
	for (size_t i = 0; i < n && error == 0; i++) {
		if ((mv[i].name = astrdup(a, br[i].ifbr_ifsname)) == NULL) {
			error = ENOMEM;
			break;
		}
		mv[i].flags = bits(a, br[i].ifbr_ifsflags & 0x1fff);
		mv[i].has_path_cost = true;
		mv[i].path_cost = br[i].ifbr_path_cost;
		mv[i].has_priority = true;
		mv[i].priority = br[i].ifbr_priority;
		mv[i].has_port_number = true;
		mv[i].port_number = br[i].ifbr_portno;
		if ((br[i].ifbr_ifsflags & IFBIF_STP) != 0) {
			mv[i].has_stp_state =
			    br[i].ifbr_state <= BSTP_IFSTATE_DISCARDING;
			mv[i].stp_state = br[i].ifbr_state;
			mv[i].has_stp_role =
			    br[i].ifbr_role <= BSTP_ROLE_BACKUP;
			mv[i].stp_role = br[i].ifbr_role;
		}
		layer_add(l, e->name, br[i].ifbr_ifsname);
	}
	free(br);
	bg->member.n = n;
	bg->member.v = mv;
	e->arcif_bridge = bg;
	return (error);
}

/*
 * What an interface of type ift is on, by the ioctl its kind answers,
 * and that kind's parts; *kindp the iana-if-type identity it is where
 * if_type does not say, else NULL.
 */
static int
kind_of(yif *e, struct layers *l, int s, uint8_t ift, const char **kindp,
    cbl_yarena *a)
{
	int error;

	*kindp = NULL;
	if (ift == IFT_ETHER || ift == IFT_INFINIBAND) {
		if ((error = lagg(e, l, s, a)) == 0)
			*kindp = "ieee8023adLag";
	} else if (ift == IFT_L2VLAN || ift == IFT_IEEE8023ADLAG) {
		if ((error = vlan(e, l, s, a)) == 0)
			*kindp = "l2vlan";
		else if (ift == IFT_IEEE8023ADLAG)
			*kindp = "ethernetCsmacd";
	} else if (ift == IFT_BRIDGE)
		error = bridge(e, l, s, a);
	else
		error = 0;
	return (error == ENOENT ? 0 : error);
}

/*
 * The interfaces name is on (lower) or under (!lower), those the list
 * has, by the list's own strings.
 */
static int
layer_names(const struct layers *l, const char *name, bool lower,
    const yif *v, size_t n, size_t *outn, const char *const **outv,
    cbl_yarena *a)
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
 * Every interface getifaddrs(3) gives by its driver name, those the list
 * leaves out (named()) too: an epair(4) end's other may be one.
 */
struct drvname {
	int		 index;
	char		 drv[IFNAMSIZ];
	const char	*listed;	/* its name in the list, or NULL */
};

static void
drv_name(int index, char *buf, size_t size)
{
	int mib[6] = { CTL_NET, PF_LINK, NETLINK_GENERIC, IFMIB_IFDATA,
	    index, IFDATA_DRIVERNAME };
	size_t len = size;

	if (sysctl(mib, nitems(mib), buf, &len, NULL, 0) != 0 || len == 0)
		len = 0;
	buf[MIN(len, size - 1)] = '\0';
}

/*
 * An epair(4) end's other: the kernel tells none, but both ends have
 * one driver name ('epair' and the pair's unit), which a rename does not
 * change.  No other of it here, the other end is in another vnet.
 */
static int
epair(yif *e, const struct drvname *dn, size_t ndn, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_arcif_epair *ep;
	const char *drv = e->arcif_driver_name;

	if (drv == NULL || strncmp(drv, "epair", 5) != 0 || drv[5] == '\0' ||
	    strspn(drv + 5, "0123456789") != strlen(drv + 5))
		return (0);
	if ((ep = cbl_yarena_alloc(a, sizeof(*ep))) == NULL)
		return (ENOMEM);
	ep->has_peer_vnet = true;
	ep->peer_vnet = true;
	for (size_t i = 0; i < ndn; i++)
		if (dn[i].index != e->if_index &&
		    strcmp(dn[i].drv, drv) == 0) {
			ep->peer = dn[i].listed;
			ep->peer_vnet = false;
			break;
		}
	e->arcif_epair = ep;
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
named(const yif *v, size_t n, const char *name)
{

	for (size_t i = 0; i < n; i++)
		if (strcmp(v[i].name, name) == 0)
			return (true);
	return (false);
}

int
yif_interfaces(struct ietf_interfaces *data, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces *ifs;
	struct layers lay = { NULL, 0 };
	struct ifaddrs *ifa0, *ifa;
	const struct if_data *d;
	struct drvname *dn = NULL;
	struct timeval boot;
	const char *kind;
	size_t n = 0, ndn = 0, len = sizeof(boot);
	int s, error = 0;
	yif *v;

	if (sysctlbyname("kern.boottime", &boot, &len, NULL, 0) != 0)
		return (errno);
	if ((s = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		return (errno);
	if (getifaddrs(&ifa0) != 0) {
		error = errno;
		close(s);
		return (error);
	}
	for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next)
		if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_LINK)
			n++;
	if ((ifs = cbl_yarena_alloc(a, sizeof(*ifs))) == NULL ||
	    (v = cbl_yarena_alloc(a, n * sizeof(*v))) == NULL ||
	    (dn = calloc(n, sizeof(*dn))) == NULL) {
		freeifaddrs(ifa0);
		close(s);
		return (ENOMEM);
	}
	n = 0;
	for (ifa = ifa0; ifa != NULL && error == 0; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		dn[ndn].index =
		    ((const struct sockaddr_dl *)(const void *)ifa->ifa_addr)->
		    sdl_index;
		drv_name(dn[ndn].index, dn[ndn].drv, sizeof(dn[ndn].drv));
		if (named(v, n, ifa->ifa_name)) {
			ndn++;
			continue;
		}
		d = ifa->ifa_data;
		if ((error = one(&v[n], ifa, s, &boot, a)) == 0 &&
		    (error = link_parts(&v[n], s, (const void *)ifa->ifa_addr,
		    d, dn[ndn].drv, a)) == 0 && d != NULL &&
		    (error = kind_of(&v[n], &lay, s, d->ifi_type, &kind,
		    a)) == 0 && kind != NULL &&
		    (v[n].type = iftype_sid(kind)) != 0)
			v[n].has_type = true;
		dn[ndn++].listed = v[n++].name;
	}
	for (size_t i = 0; i < n && error == 0; i++)
		if ((error = layer_names(&lay, v[i].name, true, v, n,
		    &v[i].lower_layer_if.n, &v[i].lower_layer_if.v, a)) != 0 ||
		    (error = layer_names(&lay, v[i].name, false, v, n,
		    &v[i].higher_layer_if.n, &v[i].higher_layer_if.v,
		    a)) != 0 ||
		    (error = epair(&v[i], dn, ndn, a)) != 0)
			break;
	free(lay.v);
	free(dn);
	close(s);
	freeifaddrs(ifa0);
	if (error != 0)
		return (error);
	ifs->interface.n = n;
	ifs->interface.v = v;
	data->interfaces = ifs;
	return (0);
}
