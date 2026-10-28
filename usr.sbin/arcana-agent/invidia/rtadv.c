/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: rtadvd.conf(5) and RFC 8349's router advertisement submodule
 * (ietf-ipv6-router-advertisements, an interface's ipv6-router-
 * advertisements) with arcana-ra's augments, both ways; and what
 * rtadvd(8) sends, rtadvctl(8) show parsed into arcana-ra's rtadvd.
 *
 * Read as rtadvd(8)'s config.c reads it, the interface's record and
 * what its tc= brings: maxinterval, mininterval, chlim, rltime
 * (default-lifetime), rtime (reachable-time), retrans (retrans-timer),
 * mtu (a number, or "auto": link-mtu-auto), raflags ("m" managed, "o"
 * other, "h" and "l" the router preference, or a number's bits 0x80,
 * 0x40, 0x08 and 0x18), noifprefix (interface-prefixes off), nolladdr
 * (source-link-layer-address off), clockskew; prefixes as config.c takes
 * them, addr, prefixlen, pinfoflags ("l" on-link, "a" autonomous),
 * vltime, pltime, vltimedecr, pltimedecr, unnumbered then 0 to 99; the
 * route information (rtprefix, rtplen, rtflags, rtltime; their rtr
 * spellings read, not written), rdnss and rdnssltime, dnssl and
 * dnsslltime (a set's names by commas, one lifetime), pref64,
 * pref64len and pref64lifetime, numbered the same way.  A field of the
 * record's own that none of these is goes to other-capability as it was
 * written, a tc= last.
 *
 * Written as one record (vc_cap_set_record()): the fields above in
 * rtadvd.conf(5)'s order, then the other capabilities; what a tc=
 * brings that the record did not have of its own and does not change is
 * left to it.  send-advertisements is not the file's: rtadvd(8)
 * advertises on the interfaces it is run on (rc.conf's
 * rtadvd_interfaces).  A no-advertise prefix is refused: rtadvd(8)
 * cannot keep one of the interface's own prefixes from its
 * advertisements, only all of them (noifprefix).
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cbl_schema.h"
#include "collect.h"
#include "varconf.h"

typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements
    yra;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_prefix_list
    ypfxl;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_prefix_list_prefix
    ypfx;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_route
    yroute;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_rdnss
    yrdnss;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_dnssl
    ydnssl;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_pref64
    ypref64;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_rtadvd
    yrtadvd;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_rtadvd_prefix
    yspfx;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_rtadvd_route
    ysroute;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_rtadvd_rdnss
    ysrdnss;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_rtadvd_dnssl
    ysdnssl;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_rtadvd_pref64
    yspref64;

#define	PFX(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV6_V6UR_IPV6_ROUTER_ADVERTISEMENTS_PREFIX_LIST_PREFIX_CONTROL_ADV_PREFIXES_##x
#define	RAPREF(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV6_V6UR_IPV6_ROUTER_ADVERTISEMENTS_ARCRA_ROUTER_PREFERENCE_##x
#define	RTPREF(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV6_V6UR_IPV6_ROUTER_ADVERTISEMENTS_ARCRA_ROUTE_PREFERENCE_##x
#define	SRAPREF(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV6_V6UR_IPV6_ROUTER_ADVERTISEMENTS_ARCRA_RTADVD_ROUTER_PREFERENCE_##x
#define	SRTPREF(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV6_V6UR_IPV6_ROUTER_ADVERTISEMENTS_ARCRA_RTADVD_ROUTE_PREFERENCE_##x
#define	ORIGIN(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV6_V6UR_IPV6_ROUTER_ADVERTISEMENTS_ARCRA_RTADVD_PREFIX_ORIGIN_##x
#define	MAXENT		100		/* config.h's MAXPREFIX and the rest */
#define	DEF_VLTIME	2592000		/* rtadvd.h's DEF_ADVVALIDLIFETIME */
#define	DEF_PLTIME	604800		/* DEF_ADVPREFERREDLIFETIME */
#define	RTPREF_HIGH	0x08		/* ND_RA_FLAG_RTPREF_HIGH */
#define	RTPREF_LOW	0x18		/* ND_RA_FLAG_RTPREF_LOW */
#define	RTPREF_MASK	0x18

/* The fields, a line each, as the writer gathers them. */
struct fields {
	char	**v;
	size_t	  n, cap;
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

/* A number field of the record, tc= followed; false: none. */
static bool
num(const struct vc_capfile *f, const char *rec, const char *cap,
    unsigned long long *v)
{
	const struct vc_cap *c = vc_cap_get(f, rec, cap, '#');

	if (c == NULL)
		return (false);
	*v = strtoull(c->value, NULL, 10);
	return (true);
}

static const char *
str(const struct vc_capfile *f, const char *rec, const char *cap)
{
	const struct vc_cap *c = vc_cap_get(f, rec, cap, '=');

	return (c != NULL ? c->value : NULL);
}

static bool
flag(const struct vc_capfile *f, const char *rec, const char *cap)
{

	return (vc_cap_get(f, rec, cap, 0) != NULL);
}

/* An index's name, as config.c's makeentry(): -1 the bare one. */
static void
entry(char *buf, size_t len, int i, const char *s)
{

	if (i < 0)
		snprintf(buf, len, "%s", s);
	else
		snprintf(buf, len, "%s%d", s, i);
}

/* A preference's bits as RFC 4191 has them, from a string or a number
 * field; -1: none. */
static int
pref_of(const struct vc_capfile *f, const char *rec, const char *cap)
{
	const char *s;
	unsigned long long v;

	if ((s = str(f, rec, cap)) != NULL) {
		if (strchr(s, 'l') != NULL)
			return (RTPREF_LOW);
		if (strchr(s, 'h') != NULL)
			return (RTPREF_HIGH);
		return (0);
	}
	if (num(f, rec, cap, &v))
		return ((int)(v & RTPREF_MASK));
	return (-1);
}

/* A prefix as a spec, "addr/len". */
static char *
spec(cbl_yarena *a, const char *addr, unsigned long long plen)
{
	char buf[INET6_ADDRSTRLEN + 8];
	struct in6_addr in6;

	if (inet_pton(AF_INET6, addr, &in6) != 1)
		return (NULL);
	inet_ntop(AF_INET6, &in6, buf, sizeof(buf));
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "/%llu", plen);
	return (astrdup(a, buf));
}

/* Room for one more of an array of items of size sz, in a. */
static void *
grow(cbl_yarena *a, void *v, size_t n, size_t sz)
{
	void *nv;

	if ((nv = cbl_yarena_alloc(a, (n + 1) * sz)) == NULL)
		return (NULL);
	if (n > 0)
		memcpy(nv, v, n * sz);
	memset((char *)nv + n * sz, 0, sz);
	return (nv);
}

/* The capabilities read into leaves: a field of another name is one of
 * the record's other-capability.  A name is a base, with an index
 * after it or not. */
static bool
known(const char *name)
{
	static const char *const bases[] = { "maxinterval", "mininterval",
	    "chlim", "raflags", "rltime", "rtime", "retrans", "mtu",
	    "noifprefix", "nolladdr", "clockskew", "addr", "prefixlen",
	    "pinfoflags", "vltime", "vltimedecr", "pltime", "pltimedecr",
	    "rtprefix", "rtplen", "rtflags", "rtltime", "rtrprefix",
	    "rtrplen", "rtrflags", "rtrltime", "rdnss", "rdnssltime",
	    "dnssl", "dnsslltime", "pref64", "pref64len", "pref64lifetime" };

	for (size_t i = 0; i < nitems(bases); i++) {
		size_t l = strlen(bases[i]);
		const char *p;

		if (strncmp(name, bases[i], l) != 0)
			continue;
		for (p = name + l; isdigit((unsigned char)*p); p++)
			;
		if (*p == '\0')
			return (true);
	}
	return (false);
}

/* A record's own field of the name: not one tc= brings. */
static const struct vc_cap *
own(const struct vc_capfile *f, const char *rec, const char *cap)
{
	const struct vc_record *r = vc_cap_record(f, rec);

	if (r == NULL)
		return (NULL);
	for (size_t i = 0; i < r->ncaps; i++)
		if (!r->caps[i].inner && strcmp(r->caps[i].name, cap) == 0)
			return (&r->caps[i]);
	return (NULL);
}

/* A comma-separated string's words, each a line of the list given. */
static int
words_in(cbl_yarena *a, const char *s, const char ***outv, size_t *outn)
{
	const char **v = NULL;
	size_t n = 0;

	while (*s != '\0') {
		size_t l = strcspn(s, ",");
		char *w;

		if (l > 0) {
			if ((v = grow(a, v, n, sizeof(*v))) == NULL ||
			    (w = cbl_yarena_alloc(a, l + 1)) == NULL)
				return (ENOMEM);
			memcpy(w, s, l);
			w[l] = '\0';
			v[n++] = w;
		}
		s += l + (s[l] == ',' ? 1 : 0);
	}
	*outv = v;
	*outn = n;
	return (0);
}

static int
read_prefixes(const struct vc_capfile *f, const char *ifname, cbl_yarena *a,
    yra *ra)
{
	ypfx *pv = NULL;
	size_t np = 0;
	unsigned long long v;
	const char *s;

	for (int i = -1; i < MAXENT; i++) {
		char e[32];
		unsigned long long plen = 64;
		const char *addr;

		entry(e, sizeof(e), i, "addr");
		if ((addr = str(f, ifname, e)) == NULL)
			continue;
		entry(e, sizeof(e), i, "prefixlen");
		(void)num(f, ifname, e, &plen);
		if ((pv = grow(a, pv, np, sizeof(*pv))) == NULL)
			return (ENOMEM);
		if ((pv[np].prefix_spec = spec(a, addr, plen)) == NULL)
			continue;	/* config.c skips it too */
		pv[np].control_adv_prefixes = PFX(ADVERTISE);
		pv[np].has_on_link_flag = pv[np].has_autonomous_flag = true;
		entry(e, sizeof(e), i, "pinfoflags");
		if ((s = str(f, ifname, e)) != NULL) {
			pv[np].on_link_flag = strchr(s, 'l') != NULL;
			pv[np].autonomous_flag = strchr(s, 'a') != NULL;
		} else if (num(f, ifname, e, &v)) {
			pv[np].on_link_flag = (v & 0x80) != 0;
			pv[np].autonomous_flag = (v & 0x40) != 0;
		} else
			pv[np].on_link_flag = pv[np].autonomous_flag = true;
		pv[np].has_valid_lifetime = pv[np].has_preferred_lifetime =
		    true;
		entry(e, sizeof(e), i, "vltime");
		pv[np].valid_lifetime = num(f, ifname, e, &v) ? (uint32_t)v :
		    DEF_VLTIME;
		entry(e, sizeof(e), i, "pltime");
		pv[np].preferred_lifetime = num(f, ifname, e, &v) ?
		    (uint32_t)v : DEF_PLTIME;
		entry(e, sizeof(e), i, "vltimedecr");
		if (flag(f, ifname, e)) {
			pv[np].has_arcra_valid_lifetime_decrements = true;
			pv[np].arcra_valid_lifetime_decrements = true;
		}
		entry(e, sizeof(e), i, "pltimedecr");
		if (flag(f, ifname, e)) {
			pv[np].has_arcra_preferred_lifetime_decrements = true;
			pv[np].arcra_preferred_lifetime_decrements = true;
		}
		np++;
	}
	if (np > 0) {
		ypfxl *pl;

		if ((pl = cbl_yarena_alloc(a, sizeof(*pl))) == NULL)
			return (ENOMEM);
		pl->prefix.n = np;
		pl->prefix.v = pv;
		ra->prefix_list = pl;
	}
	return (0);
}

/* The route information: rt<cap>, or its rtr spelling, as config.c. */
static int
read_routes(const struct vc_capfile *f, const char *ifname, cbl_yarena *a,
    yra *ra)
{
	yroute *rv = NULL;
	size_t n = 0;

	for (int i = -1; i < MAXENT; i++) {
		char e[32], o[32];
		unsigned long long plen, v;
		const char *addr;
		int pref;

		entry(e, sizeof(e), i, "rtprefix");
		entry(o, sizeof(o), i, "rtrprefix");
		if ((addr = str(f, ifname, e)) == NULL &&
		    (addr = str(f, ifname, o)) == NULL)
			continue;
		entry(e, sizeof(e), i, "rtplen");
		entry(o, sizeof(o), i, "rtrplen");
		if (!num(f, ifname, e, &plen) && !num(f, ifname, o, &plen))
			plen = 64;
		if ((rv = grow(a, rv, n, sizeof(*rv))) == NULL)
			return (ENOMEM);
		if ((rv[n].prefix = spec(a, addr, plen)) == NULL)
			continue;
		entry(e, sizeof(e), i, "rtflags");
		entry(o, sizeof(o), i, "rtrflags");
		if ((pref = pref_of(f, ifname, e)) == -1)
			pref = pref_of(f, ifname, o);
		if (pref != -1) {
			rv[n].has_preference = true;
			rv[n].preference = pref == RTPREF_HIGH ? RTPREF(HIGH) :
			    pref == RTPREF_LOW ? RTPREF(LOW) : RTPREF(MEDIUM);
		}
		entry(e, sizeof(e), i, "rtltime");
		entry(o, sizeof(o), i, "rtrltime");
		if (num(f, ifname, e, &v) || num(f, ifname, o, &v)) {
			rv[n].has_lifetime = true;
			rv[n].lifetime = (uint32_t)v;
		}
		n++;
	}
	ra->arcra_route.n = n;
	ra->arcra_route.v = rv;
	return (0);
}

/* rdnss and dnssl: a set's words with its lifetime, an entry each. */
static int
read_dns(const struct vc_capfile *f, const char *ifname, cbl_yarena *a,
    yra *ra)
{
	yrdnss *rv = NULL;
	ydnssl *dv = NULL;
	size_t nr = 0, nd = 0;

	for (int i = -1; i < MAXENT; i++) {
		char e[32];
		const char *s, **w;
		size_t nw;
		unsigned long long v;
		bool has;
		int error;

		entry(e, sizeof(e), i, "rdnss");
		if ((s = str(f, ifname, e)) != NULL) {
			if ((error = words_in(a, s, &w, &nw)) != 0)
				return (error);
			entry(e, sizeof(e), i, "rdnssltime");
			has = num(f, ifname, e, &v);
			for (size_t k = 0; k < nw; k++) {
				struct in6_addr in6;

				if (inet_pton(AF_INET6, w[k], &in6) != 1)
					continue;
				if ((rv = grow(a, rv, nr, sizeof(*rv))) == NULL)
					return (ENOMEM);
				rv[nr].address = w[k];
				rv[nr].has_lifetime = has;
				rv[nr].lifetime = (uint32_t)v;
				nr++;
			}
		}
		entry(e, sizeof(e), i, "dnssl");
		if ((s = str(f, ifname, e)) != NULL) {
			if ((error = words_in(a, s, &w, &nw)) != 0)
				return (error);
			entry(e, sizeof(e), i, "dnsslltime");
			has = num(f, ifname, e, &v);
			for (size_t k = 0; k < nw; k++) {
				if ((dv = grow(a, dv, nd, sizeof(*dv))) == NULL)
					return (ENOMEM);
				dv[nd].domain = w[k];
				dv[nd].has_lifetime = has;
				dv[nd].lifetime = (uint32_t)v;
				nd++;
			}
		}
	}
	ra->arcra_rdnss.n = nr;
	ra->arcra_rdnss.v = rv;
	ra->arcra_dnssl.n = nd;
	ra->arcra_dnssl.v = dv;
	return (0);
}

static int
read_pref64(const struct vc_capfile *f, const char *ifname, cbl_yarena *a,
    yra *ra)
{
	ypref64 *pv = NULL;
	size_t n = 0;

	for (int i = -1; i < MAXENT; i++) {
		char e[32];
		unsigned long long plen = 96, v;
		const char *addr;

		entry(e, sizeof(e), i, "pref64");
		if ((addr = str(f, ifname, e)) == NULL)
			continue;
		entry(e, sizeof(e), i, "pref64len");
		(void)num(f, ifname, e, &plen);
		if ((pv = grow(a, pv, n, sizeof(*pv))) == NULL)
			return (ENOMEM);
		if ((pv[n].prefix = spec(a, addr, plen)) == NULL)
			continue;
		entry(e, sizeof(e), i, "pref64lifetime");
		if (num(f, ifname, e, &v)) {
			pv[n].has_lifetime = true;
			pv[n].lifetime = (uint16_t)(v > 65528 ? 65528 : v);
		}
		n++;
	}
	ra->arcra_pref64.n = n;
	ra->arcra_pref64.v = pv;
	return (0);
}

/* The record's own fields no leaf holds, as written; its tc= last. */
static int
read_other(const struct vc_capfile *f, const char *ifname, cbl_yarena *a,
    yra *ra)
{
	const struct vc_record *r = vc_cap_record(f, ifname);
	const char **v = NULL;
	size_t n = 0;

	for (size_t i = 0; r != NULL && i < r->ncaps; i++) {
		const struct vc_cap *c = &r->caps[i];
		bool tc = r->tc != NULL && i == r->ncaps - 1;
		char *s;

		size_t len = c->end - c->off;

		/* A "\" newline's empty field; a known one, unless
		 * cancelled (name@), which a leaf cannot say. */
		if (c->inner || c->name[0] == '\0' || (!tc && c->type !=
		    '@' && known(c->name)))
			continue;
		while (len > 0 && isspace((unsigned char)f->text[c->off +
		    len - 1]))
			len--;
		if (len == 0)
			continue;
		if ((v = grow(a, v, n, sizeof(*v))) == NULL ||
		    (s = cbl_yarena_alloc(a, len + 1)) == NULL)
			return (ENOMEM);
		memcpy(s, f->text + c->off, len);
		s[len] = '\0';
		v[n++] = s;
	}
	ra->arcra_other_capability.n = n;
	ra->arcra_other_capability.v = v;
	return (0);
}

int
rtadv_read(const struct vc_capfile *f, const char *ifname, cbl_yarena *a,
    const yra **out)
{
	unsigned long long v;
	const char *s;
	yra *ra;
	int error, pref;

	*out = NULL;
	if (vc_cap_record(f, ifname) == NULL)
		return (0);
	if ((ra = cbl_yarena_alloc(a, sizeof(*ra))) == NULL)
		return (ENOMEM);
	memset(ra, 0, sizeof(*ra));
	if (num(f, ifname, "maxinterval", &v)) {
		ra->has_max_rtr_adv_interval = true;
		ra->max_rtr_adv_interval = (uint16_t)v;
	}
	if (num(f, ifname, "mininterval", &v)) {
		ra->has_min_rtr_adv_interval = true;
		ra->min_rtr_adv_interval = (uint16_t)v;
	}
	if (num(f, ifname, "chlim", &v)) {
		ra->has_cur_hop_limit = true;
		ra->cur_hop_limit = (uint8_t)v;
	}
	if (num(f, ifname, "rltime", &v)) {
		ra->has_default_lifetime = true;
		ra->default_lifetime = (uint16_t)v;
	}
	if (num(f, ifname, "rtime", &v)) {
		ra->has_reachable_time = true;
		ra->reachable_time = (uint32_t)v;
	}
	if (num(f, ifname, "retrans", &v)) {
		ra->has_retrans_timer = true;
		ra->retrans_timer = (uint32_t)v;
	}
	if ((s = str(f, ifname, "mtu")) != NULL && strcmp(s, "auto") == 0) {
		ra->has_arcra_link_mtu_auto = true;
		ra->arcra_link_mtu_auto = true;
	} else if (num(f, ifname, "mtu", &v)) {
		ra->has_link_mtu = true;
		ra->link_mtu = (uint32_t)v;
	}
	/* raflags: a string's letters, or a number's bits. */
	if ((s = str(f, ifname, "raflags")) != NULL) {
		ra->has_managed_flag = ra->has_other_config_flag = true;
		ra->managed_flag = strchr(s, 'm') != NULL;
		ra->other_config_flag = strchr(s, 'o') != NULL;
	} else if (num(f, ifname, "raflags", &v)) {
		ra->has_managed_flag = ra->has_other_config_flag = true;
		ra->managed_flag = (v & 0x80) != 0;
		ra->other_config_flag = (v & 0x40) != 0;
	}
	if ((pref = pref_of(f, ifname, "raflags")) != -1) {
		ra->has_arcra_router_preference = true;
		ra->arcra_router_preference = pref == RTPREF_HIGH ?
		    RAPREF(HIGH) : pref == RTPREF_LOW ? RAPREF(LOW) :
		    RAPREF(MEDIUM);
	}
	if (flag(f, ifname, "noifprefix")) {
		ra->has_arcra_interface_prefixes = true;
		ra->arcra_interface_prefixes = false;
	}
	if (flag(f, ifname, "nolladdr")) {
		ra->has_arcra_source_link_layer_address = true;
		ra->arcra_source_link_layer_address = false;
	}
	if (num(f, ifname, "clockskew", &v)) {
		ra->has_arcra_clock_skew = true;
		ra->arcra_clock_skew = (uint16_t)v;
	}
	if ((error = read_prefixes(f, ifname, a, ra)) != 0 ||
	    (error = read_routes(f, ifname, a, ra)) != 0 ||
	    (error = read_dns(f, ifname, a, ra)) != 0 ||
	    (error = read_pref64(f, ifname, a, ra)) != 0 ||
	    (error = read_other(f, ifname, a, ra)) != 0)
		return (error);
	*out = ra;
	return (0);
}

/* ---- Writing ----------------------------------------------------------- */

static int
field(struct fields *fl, const char *cap, char type, const char *value)
{
	char *s, **nv;

	if (fl->n == fl->cap) {
		if ((nv = realloc(fl->v, (fl->cap + 16) * sizeof(*nv))) ==
		    NULL)
			return (ENOMEM);
		fl->v = nv;
		fl->cap += 16;
	}
	if ((s = vc_cap_field(cap, type, value)) == NULL)
		return (EINVAL);
	fl->v[fl->n++] = s;
	return (0);
}

static int
fieldnum(struct fields *fl, const char *cap, unsigned long long v)
{
	char buf[32];

	snprintf(buf, sizeof(buf), "%llu", v);
	return (field(fl, cap, '#', buf));
}

static int
fieldtext(struct fields *fl, const char *text)
{
	char **nv;

	if (fl->n == fl->cap) {
		if ((nv = realloc(fl->v, (fl->cap + 16) * sizeof(*nv))) ==
		    NULL)
			return (ENOMEM);
		fl->v = nv;
		fl->cap += 16;
	}
	if ((fl->v[fl->n] = strdup(text)) == NULL)
		return (ENOMEM);
	fl->n++;
	return (0);
}

static void
fields_free(struct fields *fl)
{

	for (size_t i = 0; i < fl->n; i++)
		free(fl->v[i]);
	free(fl->v);
	memset(fl, 0, sizeof(*fl));
}

/* Two sets of fields the same. */
static bool
fields_same(const struct fields *x, const struct fields *y)
{

	if (x->n != y->n)
		return (false);
	for (size_t i = 0; i < x->n; i++)
		if (strcmp(x->v[i], y->v[i]) != 0)
			return (false);
	return (true);
}

/* Whether the record has a field of its own of base, any index. */
static bool
own_indexed(const struct vc_capfile *f, const char *rec, const char *base)
{
	const struct vc_record *r = vc_cap_record(f, rec);
	size_t l = strlen(base);

	for (size_t i = 0; r != NULL && i < r->ncaps; i++) {
		const char *p = r->caps[i].name;

		if (r->caps[i].inner || strncmp(p, base, l) != 0)
			continue;
		for (p += l; isdigit((unsigned char)*p); p++)
			;
		if (*p == '\0')
			return (true);
	}
	return (false);
}

static const char *
pref_letter(bool high, bool low)
{

	return (high ? "h" : low ? "l" : "");
}

/* A spec's address and length. */
static bool
split(const char *s, char *addr, size_t len, unsigned long long *plen)
{
	const char *slash;

	if ((slash = strchr(s, '/')) == NULL || (size_t)(slash - s) >= len)
		return (false);
	memcpy(addr, s, slash - s);
	addr[slash - s] = '\0';
	*plen = strtoull(slash + 1, NULL, 10);
	return (true);
}

/* Whether a tc= base (none: tc NULL) could bring the capability: where
 * it cannot, rtadvd's default need not be written. */
static bool
brought(const struct vc_capfile *f, const char *tc, const char *cap)
{

	return (tc != NULL && (vc_cap_get(f, tc, cap, '#') != NULL ||
	    vc_cap_get(f, tc, cap, '=') != NULL));
}

/* The prefixes' fields; rtadvd's defaults (pinfoflags "la", the
 * lifetimes) left out where no tc= brings another, as rtadvd.conf(5)'s
 * examples have them. */
static int
prefix_fields(const struct vc_capfile *f, const char *tc, const yra *ra,
    struct fields *fl, char *err, size_t errlen)
{
	int error;

	for (size_t i = 0; ra->prefix_list != NULL &&
	    i < ra->prefix_list->prefix.n; i++) {
		const ypfx *p = &ra->prefix_list->prefix.v[i];
		char e[32], addr[INET6_ADDRSTRLEN + 8], flags[3] = "";
		unsigned long long plen;
		int k = (int)i - 1;

		if (!split(p->prefix_spec, addr, sizeof(addr), &plen)) {
			snprintf(err, errlen, "%s: not a prefix",
			    p->prefix_spec);
			return (EINVAL);
		}
		entry(e, sizeof(e), k, "addr");
		if ((error = field(fl, e, '=', addr)) != 0)
			return (error);
		entry(e, sizeof(e), k, "prefixlen");
		if ((error = fieldnum(fl, e, plen)) != 0)
			return (error);
		if (!p->has_on_link_flag || p->on_link_flag)
			strlcat(flags, "l", sizeof(flags));
		if (!p->has_autonomous_flag || p->autonomous_flag)
			strlcat(flags, "a", sizeof(flags));
		entry(e, sizeof(e), k, "pinfoflags");
		if ((strcmp(flags, "la") != 0 || brought(f, tc, e)) &&
		    (error = field(fl, e, '=', flags)) != 0)
			return (error);
		entry(e, sizeof(e), k, "vltime");
		if (p->has_valid_lifetime && (p->valid_lifetime != DEF_VLTIME ||
		    brought(f, tc, e))) {
			if ((error = fieldnum(fl, e, p->valid_lifetime)) != 0)
				return (error);
		}
		if (p->has_arcra_valid_lifetime_decrements &&
		    p->arcra_valid_lifetime_decrements) {
			entry(e, sizeof(e), k, "vltimedecr");
			if ((error = field(fl, e, 0, NULL)) != 0)
				return (error);
		}
		entry(e, sizeof(e), k, "pltime");
		if (p->has_preferred_lifetime && (p->preferred_lifetime !=
		    DEF_PLTIME || brought(f, tc, e))) {
			if ((error = fieldnum(fl, e, p->preferred_lifetime)) !=
			    0)
				return (error);
		}
		if (p->has_arcra_preferred_lifetime_decrements &&
		    p->arcra_preferred_lifetime_decrements) {
			entry(e, sizeof(e), k, "pltimedecr");
			if ((error = field(fl, e, 0, NULL)) != 0)
				return (error);
		}
	}
	return (0);
}

static int
route_fields(const yra *ra, struct fields *fl, char *err, size_t errlen)
{
	int error;

	for (size_t i = 0; i < ra->arcra_route.n; i++) {
		const yroute *r = &ra->arcra_route.v[i];
		char e[32], addr[INET6_ADDRSTRLEN + 8];
		unsigned long long plen;
		int k = (int)i - 1;

		if (!split(r->prefix, addr, sizeof(addr), &plen)) {
			snprintf(err, errlen, "%s: not a prefix", r->prefix);
			return (EINVAL);
		}
		entry(e, sizeof(e), k, "rtprefix");
		if ((error = field(fl, e, '=', addr)) != 0)
			return (error);
		entry(e, sizeof(e), k, "rtplen");
		if ((error = fieldnum(fl, e, plen)) != 0)
			return (error);
		if (r->has_preference && r->preference != RTPREF(MEDIUM)) {
			entry(e, sizeof(e), k, "rtflags");
			if ((error = field(fl, e, '=', pref_letter(
			    r->preference == RTPREF(HIGH), r->preference ==
			    RTPREF(LOW)))) != 0)
				return (error);
		}
		if (r->has_lifetime) {
			entry(e, sizeof(e), k, "rtltime");
			if ((error = fieldnum(fl, e, r->lifetime)) != 0)
				return (error);
		}
	}
	return (0);
}

/*
 * rdnss or dnssl: entries that follow one another with one lifetime
 * (or none) make one set, its words by commas.
 */
static int
dns_fields(struct fields *fl, const char *cap, const char *ltcap,
    const char *const *words, const bool *has, const uint32_t *lt, size_t n)
{
	size_t i = 0;
	int set = -1, error;

	while (i < n) {
		char e[32], *s = NULL;
		size_t j, len = 0;

		for (j = i; j < n && has[j] == has[i] && (!has[i] || lt[j] ==
		    lt[i]); j++)
			len += strlen(words[j]) + 1;
		if ((s = malloc(len)) == NULL)
			return (ENOMEM);
		s[0] = '\0';
		for (size_t k = i; k < j; k++) {
			if (k > i)
				strlcat(s, ",", len);
			strlcat(s, words[k], len);
		}
		entry(e, sizeof(e), set, cap);
		error = field(fl, e, '=', s);
		free(s);
		if (error != 0)
			return (error);
		if (has[i]) {
			entry(e, sizeof(e), set, ltcap);
			if ((error = fieldnum(fl, e, lt[i])) != 0)
				return (error);
		}
		set++;
		i = j;
	}
	return (0);
}

static int
rdnss_fields(const yra *ra, struct fields *fl)
{
	size_t n = ra->arcra_rdnss.n;
	const char **w;
	bool *has;
	uint32_t *lt;
	int error;

	if (n == 0)
		return (0);
	if ((w = calloc(n, sizeof(*w))) == NULL ||
	    (has = calloc(n, sizeof(*has))) == NULL ||
	    (lt = calloc(n, sizeof(*lt))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < n; i++) {
		w[i] = ra->arcra_rdnss.v[i].address;
		has[i] = ra->arcra_rdnss.v[i].has_lifetime;
		lt[i] = ra->arcra_rdnss.v[i].lifetime;
	}
	error = dns_fields(fl, "rdnss", "rdnssltime", w, has, lt, n);
	free(w);
	free(has);
	free(lt);
	return (error);
}

static int
dnssl_fields(const yra *ra, struct fields *fl)
{
	size_t n = ra->arcra_dnssl.n;
	const char **w;
	bool *has;
	uint32_t *lt;
	int error;

	if (n == 0)
		return (0);
	if ((w = calloc(n, sizeof(*w))) == NULL ||
	    (has = calloc(n, sizeof(*has))) == NULL ||
	    (lt = calloc(n, sizeof(*lt))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < n; i++) {
		w[i] = ra->arcra_dnssl.v[i].domain;
		has[i] = ra->arcra_dnssl.v[i].has_lifetime;
		lt[i] = ra->arcra_dnssl.v[i].lifetime;
	}
	error = dns_fields(fl, "dnssl", "dnsslltime", w, has, lt, n);
	free(w);
	free(has);
	free(lt);
	return (error);
}

static int
pref64_fields(const yra *ra, struct fields *fl, char *err, size_t errlen)
{
	int error;

	for (size_t i = 0; i < ra->arcra_pref64.n; i++) {
		const ypref64 *p = &ra->arcra_pref64.v[i];
		char e[32], addr[INET6_ADDRSTRLEN + 8];
		unsigned long long plen;
		int k = (int)i - 1;

		if (!split(p->prefix, addr, sizeof(addr), &plen) || (plen !=
		    96 && plen != 64 && plen != 56 && plen != 48 && plen !=
		    40 && plen != 32)) {
			snprintf(err, errlen, "%s: a PREF64 prefix is of "
			    "length 96, 64, 56, 48, 40 or 32", p->prefix);
			return (EINVAL);
		}
		entry(e, sizeof(e), k, "pref64");
		if ((error = field(fl, e, '=', addr)) != 0)
			return (error);
		if (plen != 96) {
			entry(e, sizeof(e), k, "pref64len");
			if ((error = fieldnum(fl, e, plen)) != 0)
				return (error);
		}
		if (p->has_lifetime) {
			entry(e, sizeof(e), k, "pref64lifetime");
			if ((error = fieldnum(fl, e, p->lifetime)) != 0)
				return (error);
		}
	}
	return (0);
}

/*
 * A leaf's field: written where ra has it, unless the tc= base has
 * the same and the record did not have it of its own.
 */
#define	LEAF(h, v, cap, fn) do {					\
	if (ra->h && (base == NULL || !base->h || base->v != ra->v ||	\
	    own(f, ifname, cap) != NULL) && (error = fn) != 0)		\
		goto out;						\
} while (0)

/* A family's fields: kept to the base where the same and not the
 * record's own. */
static int
family(const struct vc_capfile *f, const char *ifname, const yra *base,
    struct fields *fl, struct fields *mine, struct fields *theirs,
    const char *const *bases, size_t nbases)
{
	bool keep = base != NULL && fields_same(mine, theirs);

	for (size_t i = 0; keep && i < nbases; i++)
		if (own_indexed(f, ifname, bases[i]))
			keep = false;
	for (size_t i = 0; !keep && i < mine->n; i++) {
		int error;

		if ((error = fieldtext(fl, mine->v[i])) != 0)
			return (error);
	}
	fields_free(mine);
	fields_free(theirs);
	return (0);
}

static int
write_record(struct vc_capfile *f, const char *ifname, const yra *ra,
    const yra *base, char *err, size_t errlen)
{
	static const char *const pbases[] = { "addr", "prefixlen",
	    "pinfoflags", "vltime", "vltimedecr", "pltime", "pltimedecr" };
	static const char *const rbases[] = { "rtprefix", "rtplen", "rtflags",
	    "rtltime", "rtrprefix", "rtrplen", "rtrflags", "rtrltime" };
	static const char *const dbases[] = { "rdnss", "rdnssltime" };
	static const char *const sbases[] = { "dnssl", "dnsslltime" };
	static const char *const p64bases[] = { "pref64", "pref64len",
	    "pref64lifetime" };
	const struct vc_record *r = vc_cap_record(f, ifname);
	struct fields fl, mine, theirs;
	yra none;
	const char *tc = r != NULL ? r->tc : NULL, *tcfield = NULL;
	int error;

	memset(&fl, 0, sizeof(fl));
	memset(&mine, 0, sizeof(mine));
	memset(&theirs, 0, sizeof(theirs));
	memset(&none, 0, sizeof(none));
	LEAF(has_max_rtr_adv_interval, max_rtr_adv_interval, "maxinterval",
	    fieldnum(&fl, "maxinterval", ra->max_rtr_adv_interval));
	LEAF(has_min_rtr_adv_interval, min_rtr_adv_interval, "mininterval",
	    fieldnum(&fl, "mininterval", ra->min_rtr_adv_interval));
	LEAF(has_cur_hop_limit, cur_hop_limit, "chlim",
	    fieldnum(&fl, "chlim", ra->cur_hop_limit));
	/* raflags: the letters, or 0 where set to nothing. */
	{
		bool has = ra->has_managed_flag || ra->has_other_config_flag ||
		    ra->has_arcra_router_preference;
		bool m = ra->has_managed_flag && ra->managed_flag;
		bool o = ra->has_other_config_flag && ra->other_config_flag;
		bool h = ra->has_arcra_router_preference &&
		    ra->arcra_router_preference == RAPREF(HIGH);
		bool l = ra->has_arcra_router_preference &&
		    ra->arcra_router_preference == RAPREF(LOW);
		bool same = base != NULL && (base->has_managed_flag &&
		    base->managed_flag) == m && (base->has_other_config_flag &&
		    base->other_config_flag) == o &&
		    (base->has_arcra_router_preference &&
		    base->arcra_router_preference == RAPREF(HIGH)) == h &&
		    (base->has_arcra_router_preference &&
		    base->arcra_router_preference == RAPREF(LOW)) == l;

		if (has && (!same || own(f, ifname, "raflags") != NULL)) {
			char flags[5] = "";

			if (m)
				strlcat(flags, "m", sizeof(flags));
			if (o)
				strlcat(flags, "o", sizeof(flags));
			strlcat(flags, pref_letter(h, l), sizeof(flags));
			if ((error = flags[0] != '\0' ? field(&fl, "raflags",
			    '=', flags) : fieldnum(&fl, "raflags", 0)) != 0)
				goto out;
		}
	}
	LEAF(has_default_lifetime, default_lifetime, "rltime",
	    fieldnum(&fl, "rltime", ra->default_lifetime));
	LEAF(has_reachable_time, reachable_time, "rtime",
	    fieldnum(&fl, "rtime", ra->reachable_time));
	LEAF(has_retrans_timer, retrans_timer, "retrans",
	    fieldnum(&fl, "retrans", ra->retrans_timer));
	LEAF(has_arcra_interface_prefixes, arcra_interface_prefixes,
	    "noifprefix", ra->arcra_interface_prefixes ? 0 : field(&fl,
	    "noifprefix", 0, NULL));
	LEAF(has_arcra_clock_skew, arcra_clock_skew, "clockskew",
	    fieldnum(&fl, "clockskew", ra->arcra_clock_skew));
	if ((error = prefix_fields(f, tc, ra, &mine, err, errlen)) != 0 ||
	    (error = prefix_fields(f, tc, base != NULL ? base : &none, &theirs,
	    err, errlen)) != 0 ||
	    (error = family(f, ifname, base, &fl, &mine, &theirs, pbases,
	    nitems(pbases))) != 0)
		goto out;
	if (ra->has_arcra_link_mtu_auto && ra->arcra_link_mtu_auto) {
		if ((base == NULL || !base->has_arcra_link_mtu_auto ||
		    own(f, ifname, "mtu") != NULL) && (error = field(&fl, "mtu",
		    '=', "auto")) != 0)
			goto out;
	} else
		LEAF(has_link_mtu, link_mtu, "mtu", fieldnum(&fl, "mtu",
		    ra->link_mtu));
	LEAF(has_arcra_source_link_layer_address,
	    arcra_source_link_layer_address, "nolladdr",
	    ra->arcra_source_link_layer_address ? 0 : field(&fl, "nolladdr", 0,
	    NULL));
	if ((error = route_fields(ra, &mine, err, errlen)) != 0 ||
	    (error = route_fields(base != NULL ? base : &none, &theirs, err,
	    errlen)) != 0 ||
	    (error = family(f, ifname, base, &fl, &mine, &theirs, rbases,
	    nitems(rbases))) != 0)
		goto out;
	if ((error = rdnss_fields(ra, &mine)) != 0 ||
	    (error = rdnss_fields(base != NULL ? base : &none, &theirs)) != 0 ||
	    (error = family(f, ifname, base, &fl, &mine, &theirs, dbases,
	    nitems(dbases))) != 0)
		goto out;
	if ((error = dnssl_fields(ra, &mine)) != 0 ||
	    (error = dnssl_fields(base != NULL ? base : &none, &theirs)) != 0 ||
	    (error = family(f, ifname, base, &fl, &mine, &theirs, sbases,
	    nitems(sbases))) != 0)
		goto out;
	if ((error = pref64_fields(ra, &mine, err, errlen)) != 0 ||
	    (error = pref64_fields(base != NULL ? base : &none, &theirs, err,
	    errlen)) != 0 ||
	    (error = family(f, ifname, base, &fl, &mine, &theirs, p64bases,
	    nitems(p64bases))) != 0)
		goto out;
	/* The other capabilities as they are; a tc= last, whatever its
	 * place in the list. */
	for (size_t i = 0; i < ra->arcra_other_capability.n; i++) {
		const char *s = ra->arcra_other_capability.v[i];

		if (strncmp(s, "tc=", 3) == 0) {
			tcfield = s;
			continue;
		}
		if (strchr(s, '\n') != NULL || s[0] == '\0') {
			snprintf(err, errlen, "%s: not a capability", s);
			error = EINVAL;
			goto out;
		}
		if ((error = fieldtext(&fl, s)) != 0)
			goto out;
	}
	if (tcfield != NULL && (error = fieldtext(&fl, tcfield)) != 0)
		goto out;
	error = vc_cap_set_record(f, ifname, (const char *const *)fl.v, fl.n,
	    err, errlen) == -1 ? (errno != 0 ? errno : EIO) : 0;
out:
	fields_free(&fl);
	fields_free(&mine);
	fields_free(&theirs);
	return (error);
}
#undef LEAF

int
rtadv_write(struct vc_capfile *f, const char *ifname, const yra *ra,
    char *err, size_t errlen)
{
	const struct vc_record *r;
	const yra *base = NULL;
	cbl_yarena *a;
	int error;

	for (size_t i = 0; ra->prefix_list != NULL &&
	    i < ra->prefix_list->prefix.n; i++)
		if (ra->prefix_list->prefix.v[i].control_adv_prefixes ==
		    PFX(NO_ADVERTISE)) {
			snprintf(err, errlen, "%s: rtadvd(8) cannot keep one "
			    "prefix of the interface's out of its "
			    "advertisements",
			    ra->prefix_list->prefix.v[i].prefix_spec);
			return (EINVAL);
		}
	if ((ra->prefix_list != NULL && ra->prefix_list->prefix.n > MAXENT) ||
	    ra->arcra_route.n > MAXENT || ra->arcra_rdnss.n > MAXENT ||
	    ra->arcra_dnssl.n > MAXENT || ra->arcra_pref64.n > MAXENT) {
		snprintf(err, errlen, "%s: more than %d of a kind", ifname,
		    MAXENT);
		return (EINVAL);
	}
	/* What a tc= brings, to be left to it. */
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((r = vc_cap_record(f, ifname)) != NULL && r->tc != NULL &&
	    (error = rtadv_read(f, r->tc, a, &base)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	error = write_record(f, ifname, ra, base, err, errlen);
	cbl_yarena_free(a);
	return (error);
}

/* ---- rtadvctl show ------------------------------------------------------ */

/* sec2str()'s text back to its number: NdNhNmNs; infinity. */
static bool
seconds(const char *s, uint32_t *out)
{
	unsigned long long v = 0;
	char *end;

	if (strncmp(s, "infinity", 8) == 0) {
		*out = UINT32_MAX;
		return (true);
	}
	if (!isdigit((unsigned char)*s))
		return (false);
	while (isdigit((unsigned char)*s)) {
		unsigned long long n = strtoull(s, &end, 10);

		switch (*end) {
		case 'd':
			v += n * 86400;
			break;
		case 'h':
			v += n * 3600;
			break;
		case 'm':
			v += n * 60;
			break;
		case 's':
			v += n;
			break;
		default:
			return (false);
		}
		s = end + 1;
	}
	*out = (uint32_t)(v > UINT32_MAX ? UINT32_MAX : v);
	return (true);
}

/* ctime(3)'s text as yang:date-and-time, UTC; NULL for "never". */
static const char *
when(cbl_yarena *a, const char *s)
{
	struct tm tm;
	time_t t;
	char buf[32];

	memset(&tm, 0, sizeof(tm));
	if (strncmp(s, "never", 5) == 0 || strptime(s, "%a %b %e %H:%M:%S %Y",
	    &tm) == NULL)
		return (NULL);
	tm.tm_isdst = -1;
	if ((t = mktime(&tm)) == (time_t)-1 || gmtime_r(&t, &tm) == NULL ||
	    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		return (NULL);
	return (astrdup(a, buf));
}

/* The text after "key: " in line, or NULL. */
static const char *
after(const char *line, const char *key)
{
	const char *p = strstr(line, key);

	return (p != NULL ? p + strlen(key) : NULL);
}

static int
pref_enum(const char *s)
{

	return (strncmp(s, "high", 4) == 0 ? 0 : strncmp(s, "low", 3) == 0 ?
	    2 : 1);
}

/* A line of the block parsed into st; what is not known is skipped. */
static int
show_line(cbl_yarena *a, yrtadvd *st, const char *line, int *section)
{
	const char *p, *q;
	uint32_t v;

	if (line[0] == '\t' && line[1] != ' ') {
		*section = 0;
		if ((p = after(line, "DefaultLifetime: ")) != NULL &&
		    seconds(p, &v)) {
			st->has_default_lifetime = true;
			st->default_lifetime = v;
		} else if ((p = after(line, "MinAdvInterval/MaxAdvInterval: "))
		    != NULL) {
			if (seconds(p, &v)) {
				st->has_min_rtr_adv_interval = true;
				st->min_rtr_adv_interval = v;
			}
			if ((q = strchr(p, '/')) != NULL && seconds(q + 1, &v)) {
				st->has_max_rtr_adv_interval = true;
				st->max_rtr_adv_interval = v;
			}
		} else if ((p = after(line, "AdvLinkMTU: ")) != NULL) {
			st->has_link_mtu = true;
			st->link_mtu = isdigit((unsigned char)*p) ?
			    (uint32_t)strtoul(p, NULL, 10) : 0;
			if ((q = after(line, "Flags: ")) != NULL) {
				size_t fl = strcspn(q, ",");

				st->has_managed_flag = st->has_other_config_flag =
				    true;
				st->managed_flag = memchr(q, 'M', fl) != NULL;
				st->other_config_flag = memchr(q, 'O', fl) !=
				    NULL;
			}
			if ((q = after(line, "Preference: ")) != NULL) {
				st->has_router_preference = true;
				st->router_preference = pref_enum(q);
			}
		} else if ((p = after(line, "ReachableTime: ")) != NULL) {
			if (seconds(p, &v)) {
				st->has_reachable_time = true;
				st->reachable_time = v;
			}
			if ((q = after(line, "RetransTimer: ")) != NULL &&
			    seconds(q, &v)) {
				st->has_retrans_timer = true;
				st->retrans_timer = v;
			}
			if ((q = after(line, "CurHopLimit: ")) != NULL) {
				st->has_cur_hop_limit = true;
				st->cur_hop_limit = (uint8_t)strtoul(q, NULL,
				    10);
			}
		} else if ((p = after(line, "AdvIfPrefixes: ")) != NULL) {
			st->has_interface_prefixes = true;
			st->interface_prefixes = strncmp(p, "yes", 3) == 0;
		} else if ((p = after(line, "Next RA send: ")) != NULL)
			st->next_send = when(a, p);
		else if ((p = after(line, "Last RA send: ")) != NULL)
			st->last_send = when(a, p);
		else if ((p = after(line, "Clock skew: ")) != NULL) {
			st->has_clock_skew = true;
			st->clock_skew = (uint16_t)strtoul(p, NULL, 10);
		} else if (strstr(line, "Route Info:") != NULL)
			*section = 1;
		else if (strstr(line, "Prefixes (") != NULL)
			*section = 2;
		else if (strstr(line, "RDNSS entries:") != NULL)
			*section = 3;
		else if (strstr(line, "DNSSL entries:") != NULL)
			*section = 4;
		else if (strstr(line, "PREF64:") != NULL)
			*section = 5;
		return (0);
	}
	if (line[0] != '\t' || line[1] != ' ' || line[2] != ' ')
		return (0);
	line += 3;
	switch (*section) {
	case 1: {
		ysroute *r;
		size_t l = strcspn(line, " ");

		if ((r = grow(a, (void *)(uintptr_t)st->route.v, st->route.n,
		    sizeof(*r))) == NULL)
			return (ENOMEM);
		st->route.v = r;
		r = &r[st->route.n++];
		if ((r->prefix = cbl_yarena_alloc(a, l + 1)) == NULL)
			return (ENOMEM);
		memcpy((char *)(uintptr_t)r->prefix, line, l);
		((char *)(uintptr_t)r->prefix)[l] = '\0';
		if ((p = after(line, "pref: ")) != NULL) {
			r->has_preference = true;
			r->preference = pref_enum(p);
		}
		if ((p = after(line, "ltime: ")) != NULL && seconds(p, &v)) {
			r->has_lifetime = true;
			r->lifetime = v;
		}
		break;
	}
	case 2: {
		yspfx *x;
		size_t l = strcspn(line, " ");

		if ((x = grow(a, (void *)(uintptr_t)st->prefix.v, st->prefix.n,
		    sizeof(*x))) == NULL)
			return (ENOMEM);
		st->prefix.v = x;
		x = &x[st->prefix.n++];
		if ((x->prefix = cbl_yarena_alloc(a, l + 1)) == NULL)
			return (ENOMEM);
		memcpy((char *)(uintptr_t)x->prefix, line, l);
		((char *)(uintptr_t)x->prefix)[l] = '\0';
		if ((p = strchr(line, '(')) != NULL) {
			x->has_origin = true;
			x->origin = strncmp(p + 1, "KERNEL", 6) == 0 ?
			    ORIGIN(KERNEL) : strncmp(p + 1, "CONFIG", 6) == 0 ?
			    ORIGIN(CONFIG) : ORIGIN(DYNAMIC);
		}
		if ((p = after(line, "vltime=")) != NULL && seconds(p, &v)) {
			x->has_valid_lifetime = true;
			x->valid_lifetime = v;
			if ((q = after(p, "(expire: ")) != NULL &&
			    seconds(q, &v)) {
				x->has_valid_expires = true;
				x->valid_expires = v;
			}
		}
		if ((p = after(line, "pltime=")) != NULL && seconds(p, &v)) {
			x->has_preferred_lifetime = true;
			x->preferred_lifetime = v;
			if ((q = after(p, "(expire ")) != NULL &&
			    seconds(q, &v)) {
				x->has_preferred_expires = true;
				x->preferred_expires = v;
			}
		}
		if ((p = after(line, "flags=")) != NULL) {
			size_t fl = strcspn(p, " )");

			x->has_on_link_flag = x->has_autonomous_flag = true;
			x->on_link_flag = memchr(p, 'L', fl) != NULL;
			x->autonomous_flag = memchr(p, 'A', fl) != NULL;
		}
		break;
	}
	case 3:
	case 4: {
		size_t l = strcspn(line, " ");
		char *name;

		if ((name = cbl_yarena_alloc(a, l + 1)) == NULL)
			return (ENOMEM);
		memcpy(name, line, l);
		name[l] = '\0';
		if (*section == 3) {
			ysrdnss *x;

			if ((x = grow(a, (void *)(uintptr_t)st->rdnss.v,
			    st->rdnss.n, sizeof(*x))) == NULL)
				return (ENOMEM);
			st->rdnss.v = x;
			x = &x[st->rdnss.n++];
			x->address = name;
			if ((p = after(line, "ltime=")) != NULL &&
			    seconds(p, &v)) {
				x->has_lifetime = true;
				x->lifetime = v;
			}
		} else {
			ysdnssl *x;

			if ((x = grow(a, (void *)(uintptr_t)st->dnssl.v,
			    st->dnssl.n, sizeof(*x))) == NULL)
				return (ENOMEM);
			st->dnssl.v = x;
			x = &x[st->dnssl.n++];
			x->domain = name;
			if ((p = after(line, "ltime=")) != NULL &&
			    seconds(p, &v)) {
				x->has_lifetime = true;
				x->lifetime = v;
			}
		}
		break;
	}
	case 5: {
		yspref64 *x;
		size_t l = strcspn(line, " ");

		if ((x = grow(a, (void *)(uintptr_t)st->pref64.v, st->pref64.n,
		    sizeof(*x))) == NULL)
			return (ENOMEM);
		st->pref64.v = x;
		x = &x[st->pref64.n++];
		if ((x->prefix = cbl_yarena_alloc(a, l + 1)) == NULL)
			return (ENOMEM);
		memcpy((char *)(uintptr_t)x->prefix, line, l);
		((char *)(uintptr_t)x->prefix)[l] = '\0';
		if ((p = after(line, "ltime: ")) != NULL && seconds(p, &v)) {
			x->has_lifetime = true;
			x->lifetime = v;
		}
		break;
	}
	}
	return (0);
}

/* The text between < and > after key in line, in a. */
static const char *
angled(cbl_yarena *a, const char *line, const char *key)
{
	const char *p, *q;
	char *s;

	if ((p = after(line, key)) == NULL || *p != '<' || (q = strchr(p,
	    '>')) == NULL)
		return (NULL);
	if ((s = cbl_yarena_alloc(a, q - p)) == NULL)
		return (NULL);
	memcpy(s, p + 1, q - p - 1);
	s[q - p - 1] = '\0';
	return (s);
}

int
rtadvctl_parse(const char *text, const char *ifname, cbl_yarena *a,
    const yrtadvd **out)
{
	yrtadvd *st = NULL;
	const char *p = text;
	size_t nl = strlen(ifname);
	int section = 0, error;

	*out = NULL;
	while (*p != '\0') {
		size_t len = strcspn(p, "\n");
		char *line;

		if ((line = malloc(len + 1)) == NULL)
			return (ENOMEM);
		memcpy(line, p, len);
		line[len] = '\0';
		p += len + (p[len] == '\n' ? 1 : 0);
		if (line[0] != '\t' && line[0] != '\0') {
			/* An interface's head: ours begins, another's ends. */
			if (st != NULL) {
				free(line);
				break;
			}
			if (strncmp(line, ifname, nl) == 0 && line[nl] == ':') {
				if ((st = cbl_yarena_alloc(a, sizeof(*st))) ==
				    NULL) {
					free(line);
					return (ENOMEM);
				}
				memset(st, 0, sizeof(*st));
				st->flags = angled(a, line, "flags=");
				st->status = angled(a, line, "status=");
			}
		} else if (st != NULL && (error = show_line(a, st, line,
		    &section)) != 0) {
			free(line);
			return (error);
		}
		free(line);
	}
	*out = st;
	return (0);
}
