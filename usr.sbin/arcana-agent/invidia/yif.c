/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the interfaces as ietf-interfaces (RFC 8343) has them in the
 * operational datastore, read as ifconfig(8) and
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
 * - its layers, lower-layer-if and the other end's
 *   higher-layer-if: a vlan's parent (SIOCGETVLAN), a lagg's ports
 *   (SIOCGLAGG), a bridge's members (SIOCGDRVSPEC, BRDGGIFS), as
 *   ifconfig(8) asks them.  if_type does not tell a lagg: it stays
 *   IFT_ETHER and its ports become IFT_IEEE8023ADLAG (if_lagg.c).  So
 *   SIOCGLAGG, which only lagg answers, is asked of every Ethernet and
 *   InfiniBand interface, and one that answers is IANA's ieee8023adLag,
 *   the aggregate; SIOCGETVLAN of an l2vlan and of a lagg's port, which
 *   may be a vlan; a port that is not is the ethernetCsmacd it was;
 * - what arcana-interfaces adds, each leaf as its
 *   description in the module says: the driver name, groups, the tunnel
 *   FIB, capabilities, media, and the parts of a vlan, a lagg and a
 *   bridge, from the ioctls that tell their layers; an epair end's other
 *   in a vnet;
 * - the standard models' leaves for what arcana-interfaces once had:
 *   ietf-if-ethernet-like's Ethernet addresses (SIOCGHWADDR the
 *   hardware's), of the interfaces it applies to (ethernetCsmacd,
 *   ieee8023adLag); ietf-if-extensions' max-frame-size, an Ethernet
 *   frame of the MTU: header and frame check sequence, and a VLAN tag
 *   where one may be carried (a vlan, or an interface with vlanmtu on:
 *   a vlan on it keeps its MTU); and its peer-interface, an epair end's
 *   other; the FIB is RFC 8529's bind-ni-name (yni.c), the MTU ietf-ip's
 *   (yip.c);
 * - and ietf-ip's ipv4 and ipv6, in invidia/yip.c.
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
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <arpa/inet.h>

#include <ctype.h>
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

/* An identity's SID, by its module and name; 0: none. */
static uint64_t
ident_sid(const char *mod, const char *name)
{

	for (uint32_t i = 0; i < ymodel_schema.nident; i++) {
		const struct cbl_yident *id = &ymodel_schema.ident[i];

		if (strcmp(id->name, name) == 0 &&
		    strcmp(id->module->name, mod) == 0)
			return (id->sid);
	}
	return (0);
}

/* An iana-if-type identity's SID, by its name; 0: none. */
static uint64_t
iftype_sid(const char *name)
{

	return (ident_sid("iana-if-type", name));
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

/* ieee:mac-address: the octets in hex, upper case, a hyphen between. */
static char *
ieeemac(cbl_yarena *a, const uint8_t *p)
{
	char *s;

	if ((s = cbl_yarena_alloc(a, ETHER_ADDR_LEN * 3)) == NULL)
		return (NULL);
	for (size_t i = 0; i < ETHER_ADDR_LEN; i++)
		snprintf(s + i * 3, 4, "%02X%s", p[i],
		    i + 1 < ETHER_ADDR_LEN ? "-" : "");
	return (s);
}

/* A yang:phys-address of six octets as an ieee:mac-address; NULL: not. */
static char *
ieeephys(cbl_yarena *a, const char *phys)
{
	unsigned int o[ETHER_ADDR_LEN];
	uint8_t mac[ETHER_ADDR_LEN];

	if (phys == NULL || sscanf(phys, "%x:%x:%x:%x:%x:%x", &o[0], &o[1],
	    &o[2], &o[3], &o[4], &o[5]) != ETHER_ADDR_LEN)
		return (NULL);
	for (size_t i = 0; i < ETHER_ADDR_LEN; i++)
		mac[i] = (uint8_t)o[i];
	return (ieeemac(a, mac));
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
link_parts(yif *e, int s, const char *drv, cbl_yarena *a)
{
	struct ifreq ifr;
	int error;

	if (drv[0] != '\0' &&
	    (e->arcif_driver_name = astrdup(a, drv)) == NULL)
		return (ENOMEM);
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
 * A tunnel's outer addresses (gif, gre, me), as ifconfig(8) asks them:
 * SIOCGIFPSRCADDR and SIOCGIFPDSTADDR of an inet socket s4, their _IN6
 * forms of an inet6 one s6.  An interface that is no tunnel answers
 * neither.
 */
static int
tunnel(yif *e, int s4, int s6, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_arcif_tunnel *t;
	struct ifreq ifr;
	struct in6_ifreq ifr6;
	char buf[INET6_ADDRSTRLEN];
	const char *l, *r;
	unsigned which;

	l = r = NULL;
	which = 0;
	ifreq_for(&ifr, e->name);
	if (s4 != -1 && ioctl(s4, SIOCGIFPSRCADDR, &ifr) == 0 &&
	    ifr.ifr_addr.sa_family == AF_INET) {
		l = inet_ntop(AF_INET, &((struct sockaddr_in *)(void *)
		    &ifr.ifr_addr)->sin_addr, buf, sizeof(buf)) != NULL ?
		    astrdup(a, buf) : NULL;
		ifreq_for(&ifr, e->name);
		if (ioctl(s4, SIOCGIFPDSTADDR, &ifr) == 0 &&
		    ifr.ifr_addr.sa_family == AF_INET && inet_ntop(AF_INET,
		    &((struct sockaddr_in *)(void *)&ifr.ifr_addr)->sin_addr,
		    buf, sizeof(buf)) != NULL)
			r = astrdup(a, buf);
	} else {
		memset(&ifr6, 0, sizeof(ifr6));
		strlcpy(ifr6.ifr_name, e->name, sizeof(ifr6.ifr_name));
		if (s6 == -1 || ioctl(s6, SIOCGIFPSRCADDR_IN6, &ifr6) != 0 ||
		    ifr6.ifr_addr.sin6_family != AF_INET6)
			return (0);
		which = 1;
		l = inet_ntop(AF_INET6, &ifr6.ifr_addr.sin6_addr, buf,
		    sizeof(buf)) != NULL ? astrdup(a, buf) : NULL;
		memset(&ifr6, 0, sizeof(ifr6));
		strlcpy(ifr6.ifr_name, e->name, sizeof(ifr6.ifr_name));
		if (ioctl(s6, SIOCGIFPDSTADDR_IN6, &ifr6) == 0 &&
		    ifr6.ifr_addr.sin6_family == AF_INET6 && inet_ntop(AF_INET6,
		    &ifr6.ifr_addr.sin6_addr, buf, sizeof(buf)) != NULL)
			r = astrdup(a, buf);
	}
	if (l == NULL)
		return (0);
	if ((t = cbl_yarena_alloc(a, sizeof(*t))) == NULL)
		return (ENOMEM);
	memset(t, 0, sizeof(*t));
	t->has_local = true;
	t->local.which = which;
	if (which == 0)
		t->local.v.m0 = l;
	else
		t->local.v.m1 = l;
	if (r != NULL) {
		t->has_remote = true;
		t->remote.which = which;
		if (which == 0)
			t->remote.v.m0 = r;
		else
			t->remote.v.m1 = r;
	}
	e->arcif_tunnel = t;
	return (0);
}

/* Whether the interface's type is the iana-if-type identity named. */
static bool
is_type(const yif *e, const char *name)
{

	return (e->has_type && e->type == iftype_sid(name));
}

/*
 * An IEEE 802.3 PMD type's identity by FreeBSD's name of a medium, as
 * <net/if_media.h> gives it ("1000baseT", "10Gbase-SR", "25GBase-CR1"):
 * the speed, "BASE-" and the rest in capitals, 5000 5G, a lane count of
 * 1 dropped where IEEE names none; 0: IEEE names none.
 */
uint64_t
yif_pmd(const char *subtype)
{
	char name[64], rest[32], speed[16];
	size_t n = 0, k;
	const char *p = subtype;
	uint64_t sid;

	while ((*p >= '0' && *p <= '9') || *p == '.')
		if (n < sizeof(speed) - 2)
			speed[n++] = *p++;
		else
			return (0);
	if (n == 0)
		return (0);
	speed[n] = '\0';
	if (*p == 'G' || *p == 'g' || *p == 'M' || *p == 'm') {
		speed[n++] = (char)toupper((unsigned char)*p++);
		speed[n] = '\0';
	} else if (strcmp(speed, "5000") == 0)
		strlcpy(speed, "5G", sizeof(speed));
	if (strncasecmp(p, "base", 4) != 0)
		return (0);
	p += 4;
	if (*p == '-')
		p++;
	for (k = 0; *p != '\0' && *p != '/' && k < sizeof(rest) - 1; p++)
		rest[k++] = (char)toupper((unsigned char)*p);
	rest[k] = '\0';
	snprintf(name, sizeof(name), "pmd-type-%sBASE-%s", speed, rest);
	if ((sid = ident_sid("ieee802-ethernet-phy-type", name)) != 0 ||
	    k < 2 || rest[k - 1] != '1')
		return (sid);
	name[strlen(name) - 1] = '\0';
	return (ident_sid("ieee802-ethernet-phy-type", name));
}

/*
 * An Ethernet's medium as IEEE 802.3's ieee802-ethernet-interface has
 * it: auto-negotiation where autoselect is offered, enabled when set,
 * complete with a carrier, else unknown; the duplex and the PMD type of
 * the medium active.
 */
static int
eth_media(yif *e, int s, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_ieee802_eth_if_ethernet *eth;
	struct ietf_interfaces_interfaces_interface_ieee802_eth_if_ethernet_auto_negotiation
	    *an = NULL;
	struct ietf_interfaces_interfaces_interface_ieee802_eth_if_ethernet_capabilities
	    *cap;
	struct ifmediareq ifmr;
	const char *sub;
	bool autosel = false;
	int *list;

	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, e->name, sizeof(ifmr.ifm_name));
	if ((ioctl(s, SIOCGIFXMEDIA, &ifmr) != 0 &&
	    ioctl(s, SIOCGIFMEDIA, &ifmr) != 0) ||
	    IFM_TYPE(ifmr.ifm_current) != IFM_ETHER)
		return (0);
	if (ifmr.ifm_count > 0 &&
	    (list = calloc(ifmr.ifm_count, sizeof(*list))) != NULL) {
		ifmr.ifm_ulist = list;
		if (ioctl(s, SIOCGIFXMEDIA, &ifmr) == 0 ||
		    ioctl(s, SIOCGIFMEDIA, &ifmr) == 0)
			for (int i = 0; i < ifmr.ifm_count; i++)
				if (IFM_SUBTYPE(list[i]) == IFM_AUTO)
					autosel = true;
		free(list);
		ifmr.ifm_ulist = NULL;
	}
	if ((eth = cbl_yarena_alloc(a, sizeof(*eth))) == NULL ||
	    (cap = cbl_yarena_alloc(a, sizeof(*cap))) == NULL ||
	    (autosel && (an = cbl_yarena_alloc(a, sizeof(*an))) == NULL))
		return (ENOMEM);
	cap->has_auto_negotiation = true;
	cap->auto_negotiation = autosel;
	eth->capabilities = cap;
	if (an != NULL) {
		an->has_enable = true;
		an->enable = IFM_SUBTYPE(ifmr.ifm_current) == IFM_AUTO;
		if (an->enable) {
			an->has_negotiation_status = true;
			an->negotiation_status =
			    (ifmr.ifm_status & (IFM_AVALID | IFM_ACTIVE)) ==
			    (IFM_AVALID | IFM_ACTIVE) ?
			    IETF_INTERFACES_INTERFACES_INTERFACE_IEEE802_ETH_IF_ETHERNET_AUTO_NEGOTIATION_NEGOTIATION_STATUS_COMPLETE :
			    IETF_INTERFACES_INTERFACES_INTERFACE_IEEE802_ETH_IF_ETHERNET_AUTO_NEGOTIATION_NEGOTIATION_STATUS_UNKNOWN;
		}
		eth->auto_negotiation = an;
	}
	eth->has_duplex = true;
	eth->duplex = (ifmr.ifm_active & IFM_FDX) != 0 ?
	    IETF_INTERFACES_INTERFACES_INTERFACE_IEEE802_ETH_IF_ETHERNET_DUPLEX_FULL :
	    (ifmr.ifm_active & IFM_HDX) != 0 ?
	    IETF_INTERFACES_INTERFACES_INTERFACE_IEEE802_ETH_IF_ETHERNET_DUPLEX_HALF :
	    IETF_INTERFACES_INTERFACES_INTERFACE_IEEE802_ETH_IF_ETHERNET_DUPLEX_UNKNOWN;
	sub = ifm_name(ifm_eth_sub, IFM_SUBTYPE(ifmr.ifm_active));
	if (IFM_SUBTYPE(ifmr.ifm_active) == IFM_AUTO ||
	    IFM_SUBTYPE(ifmr.ifm_active) == IFM_NONE || sub == NULL)
		eth->pmd_type = ident_sid("ieee802-ethernet-phy-type",
		    "pmd-type-unknown");
	else if ((eth->pmd_type = yif_pmd(sub)) == 0)
		eth->pmd_type = ident_sid("ieee802-ethernet-phy-type",
		    "pmd-type-other");
	eth->has_pmd_type = eth->pmd_type != 0;
	e->ieee802_eth_if_ethernet = eth;
	return (0);
}

/*
 * Once its type is known: ietf-if-ethernet-like's addresses, of an
 * Ethernet or a lagg with a 6-octet address, the hardware's where it
 * has one apart; ietf-if-extensions' max-frame-size, of those, a vlan
 * and a bridge.
 */
static int
ether_parts(yif *e, int s, const struct sockaddr_dl *sdl,
    const struct if_data *d, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_ethlike_ethernet_like *el;
	bool ether = is_type(e, "ethernetCsmacd") ||
	    is_type(e, "ieee8023adLag"), vlan = is_type(e, "l2vlan");
	struct ifreq ifr;
	int error;

	if (is_type(e, "ethernetCsmacd") && (error = eth_media(e, s, a)) != 0)
		return (error);
	if (ether && sdl->sdl_alen == ETHER_ADDR_LEN) {
		if ((el = cbl_yarena_alloc(a, sizeof(*el))) == NULL)
			return (ENOMEM);
		el->mac_address = e->phys_address;
		ifreq_for(&ifr, e->name);
		if (ioctl(s, SIOCGHWADDR, &ifr) == 0 &&
		    memcmp(ifr.ifr_addr.sa_data, "\0\0\0\0\0\0",
		    ETHER_ADDR_LEN) != 0)
			el->bia_mac_address = hexaddr(a,
			    (const uint8_t *)ifr.ifr_addr.sa_data,
			    ETHER_ADDR_LEN);
		e->ethlike_ethernet_like = el;
	}
	if (d != NULL && (ether || vlan || is_type(e, "bridge"))) {
		ifreq_for(&ifr, e->name);
		e->has_if_ext_max_frame_size = true;
		e->if_ext_max_frame_size = d->ifi_mtu + ETHER_HDR_LEN +
		    ETHER_CRC_LEN + (vlan || (ioctl(s, SIOCGIFCAP, &ifr) ==
		    0 && (ifr.ifr_curcap & IFCAP_VLAN_MTU) != 0) ?
		    ETHER_VLAN_ENCAP_LEN : 0);
	}
	return (0);
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

/*
 * A lagg port's aggport, a bridge member's bridge-port, for the port's
 * entry once all are listed.
 */
struct port {
	char		 port[IFNAMSIZ];
	const struct ietf_interfaces_interfaces_interface_dot1ax_aggport *ap;
	const struct ietf_interfaces_interfaces_interface_dot1q_bridge_port *bp;
};

struct ports {
	struct port	*v;
	size_t		 n;
};

static int
port_add(struct ports *pp, const char *name,
    const struct ietf_interfaces_interfaces_interface_dot1ax_aggport *ap,
    const struct ietf_interfaces_interfaces_interface_dot1q_bridge_port *bp)
{
	struct port *v;

	if ((v = reallocarray(pp->v, pp->n + 1, sizeof(*v))) == NULL)
		return (ENOMEM);
	pp->v = v;
	strlcpy(v[pp->n].port, name, sizeof(v[pp->n].port));
	v[pp->n].ap = ap;
	v[pp->n++].bp = bp;
	return (0);
}

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
 * A lagg, as IEEE 802.1AX has it: its lag, naming the key group of its
 * own name, its address, and with LACP the keys and partner of its
 * lacp_opreq; each port's aggport, kept in ag for the port's entry, with
 * LACP its number, priority, keys and states (FreeBSD's LACP_STATE_*
 * bits are IEEE's lacp-state's, one position on).  Its protocol and hash,
 * a port's priority and flags, arcana-interfaces'.  ENOENT: not one.
 */
static int
lagg(yif *e, struct layers *l, struct ports *pp, int s, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_dot1ax_lag *lg;
	struct ietf_interfaces_interfaces_interface_dot1ax_lag_lacp *ll;
	struct ietf_interfaces_interfaces_interface_dot1ax_aggport *ap;
	struct ietf_interfaces_interfaces_interface_dot1ax_aggport_lacp *pl;
	struct lagg_reqport rp[LAGG_MAX_PORTS];
	struct lagg_reqflags rf;
	struct lagg_reqall ra;
	bool lacp;
	int n;

	memset(&ra, 0, sizeof(ra));
	strlcpy(ra.ra_ifname, e->name, sizeof(ra.ra_ifname));
	ra.ra_size = sizeof(rp);
	ra.ra_port = rp;
	if (ioctl(s, SIOCGLAGG, &ra) != 0)
		return (ENOENT);
	n = MIN(ra.ra_ports, LAGG_MAX_PORTS);
	lacp = ra.ra_proto == LAGG_PROTO_LACP;
	if ((lg = cbl_yarena_alloc(a, sizeof(*lg))) == NULL)
		return (ENOMEM);
	lg->key_group_name = e->name;
	/* The aggregator's address: the lagg's own. */
	lg->mac_address = ieeephys(a, e->phys_address);
	if (ra.ra_proto < LAGG_PROTO_MAX) {
		lg->has_arcif_protocol = true;
		lg->arcif_protocol = ra.ra_proto;
	}
	memset(&rf, 0, sizeof(rf));
	strlcpy(rf.rf_ifname, e->name, sizeof(rf.rf_ifname));
	if (ioctl(s, SIOCGLAGGFLAGS, &rf) == 0)
		lg->arcif_hash = bits(a, rf.rf_flags & LAGG_F_HASHMASK);
	if (lacp) {
		const struct lacp_opreq *o = &ra.ra_lacpreq;

		if ((ll = cbl_yarena_alloc(a, sizeof(*ll))) == NULL)
			return (ENOMEM);
		ll->has_actor_oper_key = true;
		ll->actor_oper_key = o->actor_key;
		ll->partner_system = ieeemac(a, o->partner_mac);
		ll->has_partner_system_priority = true;
		ll->partner_system_priority = o->partner_prio;
		ll->has_partner_oper_key = true;
		ll->partner_oper_key = o->partner_key;
		lg->lacp = ll;
	}
	for (int i = 0; i < n; i++) {
		if ((ap = cbl_yarena_alloc(a, sizeof(*ap))) == NULL ||
		    port_add(pp, rp[i].rp_portname, ap, NULL) != 0)
			return (ENOMEM);
		ap->key_group_name = e->name;
		ap->has_arcif_priority = true;
		ap->arcif_priority = rp[i].rp_prio;
		ap->arcif_flags = bits(a, rp[i].rp_flags & 0x1f);
		if (lacp) {
			const struct lacp_opreq *o = &rp[i].rp_psc.rpsc_lacp;

			if ((pl = cbl_yarena_alloc(a, sizeof(*pl))) == NULL)
				return (ENOMEM);
			ap->has_actor_port_number = true;
			ap->actor_port_number = o->actor_portno;
			ap->has_actor_port_priority = true;
			ap->actor_port_priority = o->actor_portprio;
			pl->has_actor_oper_key = true;
			pl->actor_oper_key = o->actor_key;
			pl->actor_oper_state = bits(a,
			    (uint64_t)o->actor_state << 1);
			pl->has_partner_oper_system_priority = true;
			pl->partner_oper_system_priority = o->partner_prio;
			pl->partner_oper_system = ieeemac(a, o->partner_mac);
			pl->has_partner_oper_key = true;
			pl->partner_oper_key = o->partner_key;
			pl->has_partner_oper_port = true;
			pl->partner_oper_port = o->partner_portno;
			pl->has_partner_oper_port_priority = true;
			pl->partner_oper_port_priority = o->partner_portprio;
			pl->partner_oper_state = bits(a,
			    (uint64_t)o->partner_state << 1);
			ap->lacp = pl;
		}
		layer_add(l, e->name, rp[i].rp_portname);
	}
	e->dot1ax_lag = lg;
	return (0);
}

/*
 * IEEE 802.1AX's linkagg of the interfaces v (yif_interfaces()'): a
 * lagg's aggregation system, its LACP address and priority (SIOCGLAGG)
 * or else the lagg's own address, and its key group, of its name, the
 * lagg and the ports whose aggport names it.
 */
int
yif_linkagg(const struct ietf_interfaces_interfaces_interface *v, size_t n,
    cbl_yarena *a, struct ieee802_dot1ax_linkagg *data)
{
	struct ieee802_dot1ax_linkagg_linkagg *la;
	struct ieee802_dot1ax_linkagg_linkagg_agg_system *sv;
	struct ieee802_dot1ax_linkagg_linkagg_key_group *kv;
	struct lagg_reqall ra;
	size_t nl = 0, k = 0;
	int s;

	for (size_t i = 0; i < n; i++)
		nl += v[i].dot1ax_lag != NULL;
	if ((la = cbl_yarena_alloc(a, sizeof(*la))) == NULL ||
	    (nl > 0 && ((sv = cbl_yarena_alloc(a, nl * sizeof(*sv))) == NULL ||
	    (kv = cbl_yarena_alloc(a, nl * sizeof(*kv))) == NULL)))
		return (ENOMEM);
	if (nl == 0) {
		data->linkagg = la;
		return (0);
	}
	if ((s = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		return (errno);
	for (size_t i = 0; i < n; i++) {
		const struct ietf_interfaces_interfaces_interface_dot1ax_lag *lg =
		    v[i].dot1ax_lag;
		const char **lags, **ports;
		size_t np = 0;

		if (lg == NULL)
			continue;
		for (size_t j = 0; j < n; j++)
			np += v[j].dot1ax_aggport != NULL &&
			    strcmp(v[j].dot1ax_aggport->key_group_name,
			    v[i].name) == 0;
		if ((lags = cbl_yarena_alloc(a, sizeof(*lags))) == NULL ||
		    (ports = cbl_yarena_alloc(a, (np + 1) *
		    sizeof(*ports))) == NULL) {
			close(s);
			return (ENOMEM);
		}
		np = 0;
		for (size_t j = 0; j < n; j++)
			if (v[j].dot1ax_aggport != NULL &&
			    strcmp(v[j].dot1ax_aggport->key_group_name,
			    v[i].name) == 0)
				ports[np++] = v[j].name;
		sv[k].name = v[i].name;
		sv[k].actor_system = lg->mac_address;
		memset(&ra, 0, sizeof(ra));
		strlcpy(ra.ra_ifname, v[i].name, sizeof(ra.ra_ifname));
		if (ioctl(s, SIOCGLAGG, &ra) == 0 &&
		    ra.ra_proto == LAGG_PROTO_LACP) {
			sv[k].actor_system = ieeemac(a,
			    ra.ra_lacpreq.actor_mac);
			sv[k].has_actor_system_priority = true;
			sv[k].actor_system_priority = ra.ra_lacpreq.actor_prio;
		}
		lags[0] = v[i].name;
		kv[k].name = v[i].name;
		kv[k].agg_system_name = v[i].name;
		kv[k].lags.n = 1;
		kv[k].lags.v = lags;
		kv[k].aggports.n = np;
		kv[k].aggports.v = ports;
		k++;
	}
	close(s);
	la->agg_system.n = la->key_group.n = k;
	la->agg_system.v = sv;
	la->key_group.v = kv;
	data->linkagg = la;
	return (0);
}

/*
 * A vlan, as ietf-if-vlan-encapsulation has it: its tag the outer one,
 * of 802.1Q (c-vlan) or 802.1ad (s-vlan), a tag it cannot hold (0,
 * 4095) none; its parent ietf-if-extensions'; its priority
 * arcana-interfaces'.  ENOENT: not one.
 */
static int
vlan(yif *e, struct layers *l, int s, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_if_ext_encapsulation *en;
	struct ietf_interfaces_interfaces_interface_if_ext_encapsulation_if_vlan_dot1q_vlan
	    *dv;
	struct ietf_interfaces_interfaces_interface_if_ext_encapsulation_if_vlan_dot1q_vlan_outer_tag
	    *ot;
	struct vlanreq vr;
	struct ifreq ifr;

	memset(&vr, 0, sizeof(vr));
	ifreq_for(&ifr, e->name);
	ifr.ifr_data = (caddr_t)&vr;
	if (ioctl(s, SIOCGETVLAN, &ifr) != 0)
		return (ENOENT);
	if ((en = cbl_yarena_alloc(a, sizeof(*en))) == NULL ||
	    (dv = cbl_yarena_alloc(a, sizeof(*dv))) == NULL)
		return (ENOMEM);
	if (vr.vlr_tag >= 1 && vr.vlr_tag <= 4094 &&
	    (vr.vlr_proto == ETHERTYPE_VLAN || vr.vlr_proto == ETHERTYPE_QINQ)) {
		if ((ot = cbl_yarena_alloc(a, sizeof(*ot))) == NULL)
			return (ENOMEM);
		ot->has_vlan_id = true;
		ot->vlan_id = vr.vlr_tag;
		ot->tag_type = ident_sid("ieee802-dot1q-types",
		    vr.vlr_proto == ETHERTYPE_VLAN ? "c-vlan" : "s-vlan");
		ot->has_tag_type = ot->tag_type != 0;
		dv->outer_tag = ot;
	}
	if (vr.vlr_parent[0] != '\0' &&
	    (e->if_ext_parent_interface = astrdup(a, vr.vlr_parent)) == NULL)
		return (ENOMEM);
	ifreq_for(&ifr, e->name);
	if (ioctl(s, SIOCGVLANPCP, &ifr) == 0 && ifr.ifr_vlan_pcp <= 7) {
		dv->has_arcif_pcp = true;
		dv->arcif_pcp = ifr.ifr_vlan_pcp;
	}
	en->encaps_type =
	    IETF_INTERFACES_INTERFACES_INTERFACE_IF_EXT_ENCAPSULATION_ENCAPS_TYPE_DOT1Q_VLAN;
	en->if_vlan_dot1q_vlan = dv;
	layer_add(l, e->name, vr.vlr_parent);
	e->if_ext_encapsulation = en;
	return (0);
}

/*
 * A bridge's members, as IEEE 802.1Q has them: each a bridge port of
 * the bridge's one component, its number and point-to-point state, kept
 * in pp for the member's entry; where its spanning tree is on, RSTP's
 * state, role, identifier, cost and edge.  Its other flags
 * arcana-interfaces'.
 */
static int
bridge(yif *e, struct layers *l, struct ports *pp, int s, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces_interface_dot1q_bridge_port *bp;
	struct ietf_interfaces_interfaces_interface_dot1q_bridge_port_rstp_bridge_rstp
	    *rs;
	struct ietf_interfaces_interfaces_interface_dot1q_bridge_port_rstp_bridge_rstp_port_id
	    *pid;
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
	for (size_t i = 0; i < n && error == 0; i++) {
		uint32_t f = br[i].ifbr_ifsflags;

		if ((bp = cbl_yarena_alloc(a, sizeof(*bp))) == NULL ||
		    port_add(pp, br[i].ifbr_ifsname, NULL, bp) != 0) {
			error = ENOMEM;
			break;
		}
		bp->bridge_name = e->name;
		bp->component_name = e->name;
		if (br[i].ifbr_portno != 0) {
			bp->has_port_number = true;
			bp->port_number = br[i].ifbr_portno;
		}
		bp->has_admin_point_to_point = true;
		bp->admin_point_to_point = (f & IFBIF_BSTP_AUTOPTP) != 0 ?
		    IETF_INTERFACES_INTERFACES_INTERFACE_DOT1Q_BRIDGE_PORT_ADMIN_POINT_TO_POINT_AUTO :
		    (f & IFBIF_BSTP_PTP) != 0 ?
		    IETF_INTERFACES_INTERFACES_INTERFACE_DOT1Q_BRIDGE_PORT_ADMIN_POINT_TO_POINT_FORCE_TRUE :
		    IETF_INTERFACES_INTERFACES_INTERFACE_DOT1Q_BRIDGE_PORT_ADMIN_POINT_TO_POINT_FORCE_FALSE;
		bp->has_oper_point_to_point = true;
		bp->oper_point_to_point = (f & IFBIF_BSTP_PTP) != 0;
		bp->arcif_flags = bits(a, f & (IFBIF_LEARNING | IFBIF_DISCOVER |
		    IFBIF_SPAN | IFBIF_STICKY | IFBIF_PRIVATE | IFBIF_QINQ));
		if ((f & IFBIF_STP) != 0) {
			if ((rs = cbl_yarena_alloc(a, sizeof(*rs))) == NULL ||
			    (pid = cbl_yarena_alloc(a, sizeof(*pid))) == NULL) {
				error = ENOMEM;
				break;
			}
			/* RSTP's: disabled, listening, blocking discard. */
			rs->has_port_state = true;
			rs->port_state = br[i].ifbr_state ==
			    BSTP_IFSTATE_LEARNING ?
			    IETF_INTERFACES_INTERFACES_INTERFACE_DOT1Q_BRIDGE_PORT_RSTP_BRIDGE_RSTP_PORT_STATE_LEARNING :
			    br[i].ifbr_state == BSTP_IFSTATE_FORWARDING ?
			    IETF_INTERFACES_INTERFACES_INTERFACE_DOT1Q_BRIDGE_PORT_RSTP_BRIDGE_RSTP_PORT_STATE_FORWARDING :
			    IETF_INTERFACES_INTERFACES_INTERFACE_DOT1Q_BRIDGE_PORT_RSTP_BRIDGE_RSTP_PORT_STATE_DISCARDING;
			if (br[i].ifbr_role <= BSTP_ROLE_BACKUP) {
				rs->has_port_role = true;
				rs->port_role = br[i].ifbr_role + 1;
			}
			pid->has_port_priority = true;
			pid->port_priority = br[i].ifbr_priority >> 4;
			pid->has_port_number = true;
			pid->port_number = br[i].ifbr_portno;
			pid->has_port_id = true;
			pid->port_id = (uint16_t)((br[i].ifbr_priority >> 4) << 12 |
			    (br[i].ifbr_portno & 0xfff));
			rs->port_id = pid;
			if (br[i].ifbr_path_cost >= 1) {
				rs->has_port_path_cost = true;
				rs->port_path_cost = br[i].ifbr_path_cost;
			}
			if ((f & IFBIF_BSTP_ADMCOST) != 0) {
				rs->has_fix_port_path_cost = true;
				rs->fix_port_path_cost = br[i].ifbr_path_cost;
			}
			rs->has_admin_edge_port = true;
			rs->admin_edge_port = (f & IFBIF_BSTP_ADMEDGE) != 0;
			rs->has_oper_edge_port = true;
			rs->oper_edge_port = (f & IFBIF_BSTP_EDGE) != 0;
			rs->has_auto_edge_port = true;
			rs->auto_edge_port = (f & IFBIF_BSTP_AUTOEDGE) != 0;
			bp->rstp_bridge_rstp = rs;
		}
		layer_add(l, e->name, br[i].ifbr_ifsname);
	}
	free(br);
	return (error);
}

/*
 * IEEE 802.1Q's bridges of the interfaces v (yif_interfaces()'): each
 * bridge(4) a customer VLAN bridge of its name and address, of one
 * component of its name, VLAN-unaware or, with vlanfilter (BRDGGFLAGS),
 * a C-VLAN component, its bridge ports the members whose bridge-port
 * names it.
 */
int
yif_bridges(const struct ietf_interfaces_interfaces_interface *v, size_t n,
    cbl_yarena *a, struct ieee802_dot1q_bridge *data)
{
	struct ieee802_dot1q_bridge_bridges *bs;
	struct ieee802_dot1q_bridge_bridges_bridge *bv = NULL;
	struct ieee802_dot1q_bridge_bridges_bridge_component *cv;
	struct ifbrparam param;
	struct ifdrv d;
	size_t nb = 0, k = 0;
	int s;

	for (size_t i = 0; i < n; i++)
		nb += is_type(&v[i], "bridge");
	if ((bs = cbl_yarena_alloc(a, sizeof(*bs))) == NULL ||
	    (nb > 0 && (bv = cbl_yarena_alloc(a, nb * sizeof(*bv))) == NULL))
		return (ENOMEM);
	if ((s = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		return (errno);
	for (size_t i = 0; i < n && nb > 0; i++) {
		const char **ports;
		size_t np = 0;

		if (!is_type(&v[i], "bridge"))
			continue;
		for (size_t j = 0; j < n; j++)
			np += v[j].dot1q_bridge_port != NULL &&
			    strcmp(v[j].dot1q_bridge_port->bridge_name,
			    v[i].name) == 0;
		if ((cv = cbl_yarena_alloc(a, sizeof(*cv))) == NULL ||
		    (ports = cbl_yarena_alloc(a, (np + 1) * sizeof(*ports))) ==
		    NULL) {
			close(s);
			return (ENOMEM);
		}
		np = 0;
		for (size_t j = 0; j < n; j++)
			if (v[j].dot1q_bridge_port != NULL &&
			    strcmp(v[j].dot1q_bridge_port->bridge_name,
			    v[i].name) == 0)
				ports[np++] = v[j].name;
		memset(&param, 0, sizeof(param));
		memset(&d, 0, sizeof(d));
		strlcpy(d.ifd_name, v[i].name, sizeof(d.ifd_name));
		d.ifd_cmd = BRDGGFLAGS;
		d.ifd_len = sizeof(param);
		d.ifd_data = &param;
		cv->name = v[i].name;
		cv->type = ident_sid("ieee802-dot1q-bridge",
		    ioctl(s, SIOCGDRVSPEC, &d) == 0 &&
		    (param.ifbrp_flags & IFBRF_VLANFILTER) != 0 ?
		    "c-vlan-component" : "d-bridge-component");
		cv->has_type = cv->type != 0;
		cv->has_ports = true;
		cv->ports = (uint16_t)np;
		cv->bridge_port.n = np;
		cv->bridge_port.v = ports;
		bv[k].name = v[i].name;
		bv[k].address = ieeephys(a, v[i].phys_address);
		bv[k].bridge_type = ident_sid("ieee802-dot1q-bridge",
		    "customer-vlan-bridge");
		bv[k].has_bridge_type = bv[k].bridge_type != 0;
		bv[k].has_ports = true;
		bv[k].ports = (uint16_t)np;
		bv[k].has_components = true;
		bv[k].components = 1;
		bv[k].component.n = 1;
		bv[k].component.v = cv;
		k++;
	}
	close(s);
	bs->bridge.n = k;
	bs->bridge.v = bv;
	data->bridges = bs;
	return (0);
}

/*
 * What an interface of type ift is on, by the ioctl its kind answers,
 * and that kind's parts; *kindp the iana-if-type identity it is where
 * if_type does not say, else NULL.
 */
static int
kind_of(yif *e, struct layers *l, struct ports *pp, int s, uint8_t ift,
    const char **kindp, cbl_yarena *a)
{
	int error;

	*kindp = NULL;
	if (ift == IFT_ETHER || ift == IFT_INFINIBAND) {
		if ((error = lagg(e, l, pp, s, a)) == 0)
			*kindp = "ieee8023adLag";
	} else if (ift == IFT_L2VLAN || ift == IFT_IEEE8023ADLAG) {
		if ((error = vlan(e, l, s, a)) == 0)
			*kindp = "l2vlan";
		else if (ift == IFT_IEEE8023ADLAG)
			*kindp = "ethernetCsmacd";
	} else if (ift == IFT_BRIDGE)
		error = bridge(e, l, pp, s, a);
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
static void
epair(yif *e, const struct drvname *dn, size_t ndn)
{
	const char *drv = e->arcif_driver_name;

	if (drv == NULL || strncmp(drv, "epair", 5) != 0 || drv[5] == '\0' ||
	    strspn(drv + 5, "0123456789") != strlen(drv + 5))
		return;
	e->has_arcif_peer_vnet = true;
	e->arcif_peer_vnet = true;
	for (size_t i = 0; i < ndn; i++)
		if (dn[i].index != e->if_index &&
		    strcmp(dn[i].drv, drv) == 0) {
			e->if_ext_peer_interface = dn[i].listed;
			e->arcif_peer_vnet = false;
			break;
		}
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
yif_interfaces(struct ietf_interfaces *data,
    const struct ietf_network_instance_network_instances *ni, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces *ifs;
	struct layers lay = { NULL, 0 };
	struct ports pp = { NULL, 0 };
	struct ifaddrs *ifa0, *ifa;
	const struct if_data *d;
	struct drvname *dn = NULL;
	struct timeval boot;
	const char *kind;
	size_t n = 0, ndn = 0, len = sizeof(boot);
	int s, s4, s6, error = 0;
	yif *v;

	if (sysctlbyname("kern.boottime", &boot, &len, NULL, 0) != 0)
		return (errno);
	if ((s = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		return (errno);
	/* A tunnel's addresses are asked of a socket of their family. */
	s4 = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	s6 = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (getifaddrs(&ifa0) != 0) {
		error = errno;
		close(s);
		if (s4 != -1)
			close(s4);
		if (s6 != -1)
			close(s6);
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
		if (s4 != -1)
			close(s4);
		if (s6 != -1)
			close(s6);
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
		    (error = link_parts(&v[n], s, dn[ndn].drv, a)) == 0 &&
		    d != NULL &&
		    (error = kind_of(&v[n], &lay, &pp, s, d->ifi_type, &kind,
		    a)) == 0 && kind != NULL &&
		    (v[n].type = iftype_sid(kind)) != 0)
			v[n].has_type = true;
		if (error == 0)
			error = ether_parts(&v[n], s,
			    (const void *)ifa->ifa_addr, d, a);
		if (error == 0)
			error = tunnel(&v[n], s4, s6, a);
		dn[ndn++].listed = v[n++].name;
	}
	for (size_t i = 0; i < n && error == 0; i++)
		if ((error = layer_names(&lay, v[i].name, true, v, n,
		    &v[i].lower_layer_if.n, &v[i].lower_layer_if.v, a)) == 0 &&
		    (error = layer_names(&lay, v[i].name, false, v, n,
		    &v[i].higher_layer_if.n, &v[i].higher_layer_if.v,
		    a)) == 0)
			epair(&v[i], dn, ndn);
	/*
	 * Each lagg port's aggport and bridge member's bridge-port on its
	 * entry, the first of its name.
	 */
	for (size_t i = 0; i < pp.n; i++)
		for (size_t j = 0; j < n; j++)
			if (strcmp(v[j].name, pp.v[i].port) == 0) {
				if (pp.v[i].ap != NULL)
					v[j].dot1ax_aggport = pp.v[i].ap;
				if (pp.v[i].bp != NULL)
					v[j].dot1q_bridge_port = pp.v[i].bp;
				break;
			}
	free(pp.v);
	free(lay.v);
	free(dn);
	close(s);
	if (s4 != -1)
		close(s4);
	if (s6 != -1)
		close(s6);
	freeifaddrs(ifa0);
	/* What ietf-ip adds to each (invidia/yip.c), and the network
	 * instance each is bound to (invidia/yni.c). */
	if (error == 0)
		error = yip_interfaces(v, n, a);
	if (error == 0 && ni != NULL)
		error = yni_bind(v, n, ni, a);
	if (error != 0)
		return (error);
	ifs->interface.n = n;
	ifs->interface.v = v;
	data->interfaces = ifs;
	return (0);
}
