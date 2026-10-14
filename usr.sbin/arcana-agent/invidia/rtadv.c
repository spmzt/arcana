/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: rtadvd.conf(5) and RFC 8349's router advertisement submodule
 * (ietf-ipv6-router-advertisements, an interface's ipv6-router-
 * advertisements), both ways (PLAN-SDN-YANG 2.5.1).  rtadvd.conf is read
 * as rtadvd(8)'s config.c reads it, the interface's record and what its
 * tc= brings: maxinterval, mininterval, chlim, rltime (default-
 * lifetime), rtime (reachable-time), retrans (retrans-timer), mtu (a
 * number; "auto", the link's, none), raflags ("m" managed, "o" other,
 * or a number's 0x80 and 0x40); prefixes as config.c takes them, addr,
 * prefixlen, pinfoflags ("l" on-link, "a" autonomous), vltime and
 * pltime, unnumbered then 0 to 99.  Written to the record's own fields,
 * the record made if it is not there; a leaf not given, its field taken
 * out.  send-advertisements is not the file's: rtadvd(8) advertises on
 * the interfaces it is run on (rc.conf's rtadvd_interfaces).  A
 * no-advertise prefix is refused: rtadvd(8) cannot keep one of the
 * interface's own prefixes from its advertisements, only all of them
 * (noifprefix).
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_schema.h"
#include "collect.h"
#include "varconf.h"

typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements
    yra;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_prefix_list_prefix
    ypfx;

#define	PFX(x)	IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV6_V6UR_IPV6_ROUTER_ADVERTISEMENTS_PREFIX_LIST_PREFIX_CONTROL_ADV_PREFIXES_##x
#define	MAXPREFIX	100		/* config.c's */
#define	DEF_VLTIME	2592000		/* rtadvd.h's DEF_ADVVALIDLIFETIME */
#define	DEF_PLTIME	604800		/* DEF_ADVPREFERREDLIFETIME */

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

/* An index's name, as config.c's makeentry(): -1 the bare one. */
static void
entry(char *buf, size_t len, int i, const char *s)
{

	if (i < 0)
		snprintf(buf, len, "%s", s);
	else
		snprintf(buf, len, "%s%d", s, i);
}

int
rtadv_read(const struct vc_capfile *f, const char *ifname, cbl_yarena *a,
    const yra **out)
{
	unsigned long long v;
	const char *s;
	yra *ra;
	ypfx *pv = NULL;
	size_t np = 0;

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
	if (num(f, ifname, "mtu", &v)) {
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
	for (int i = -1; i < MAXPREFIX; i++) {
		char e[32], spec[INET6_ADDRSTRLEN + 8];
		unsigned long long plen = 64;
		struct in6_addr in6;
		ypfx *nv;
		const char *addr;

		entry(e, sizeof(e), i, "addr");
		if ((addr = str(f, ifname, e)) == NULL ||
		    inet_pton(AF_INET6, addr, &in6) != 1)
			continue;
		entry(e, sizeof(e), i, "prefixlen");
		(void)num(f, ifname, e, &plen);
		if ((nv = cbl_yarena_alloc(a, (np + 1) * sizeof(*nv))) ==
		    NULL)
			return (ENOMEM);
		if (np > 0)
			memcpy(nv, pv, np * sizeof(*nv));
		pv = nv;
		memset(&pv[np], 0, sizeof(pv[np]));
		inet_ntop(AF_INET6, &in6, spec, sizeof(spec));
		snprintf(spec + strlen(spec), sizeof(spec) - strlen(spec),
		    "/%llu", plen);
		pv[np].prefix_spec = astrdup(a, spec);
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
		np++;
	}
	if (np > 0) {
		struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_prefix_list
		    *pl;

		if ((pl = cbl_yarena_alloc(a, sizeof(*pl))) == NULL)
			return (ENOMEM);
		pl->prefix.n = np;
		pl->prefix.v = pv;
		ra->prefix_list = pl;
	}
	*out = ra;
	return (0);
}

/*
 * A number field set, or taken out; not touched where the file reads
 * so already (was, wv), its own field or one tc= brings.
 */
static int
setnum(struct vc_capfile *f, const char *rec, const char *cap, bool has,
    unsigned long long v, bool washas, unsigned long long wv, char *err,
    size_t errlen)
{
	char buf[32];

	if (has == washas && (!has || v == wv))
		return (0);
	if (!has)
		return (vc_cap_unset(f, rec, cap, err, errlen) == -1 ? errno :
		    0);
	snprintf(buf, sizeof(buf), "%llu", v);
	return (vc_cap_set(f, rec, cap, '#', buf, err, errlen) == -1 ? errno :
	    0);
}

static int	write_leaves(struct vc_capfile *, const char *, const yra *,
		    const yra *, char *, size_t);

int
rtadv_write(struct vc_capfile *f, const char *ifname, const yra *ra,
    char *err, size_t errlen)
{
	const yra *was;
	cbl_yarena *a;
	int error;

	if (ra->prefix_list != NULL)
		for (size_t i = 0; i < ra->prefix_list->prefix.n; i++)
			if (ra->prefix_list->prefix.v[i].control_adv_prefixes ==
			    PFX(NO_ADVERTISE)) {
				snprintf(err, errlen, "%s: rtadvd(8) cannot "
				    "keep one prefix of the interface's out "
				    "of its advertisements",
				    ra->prefix_list->prefix.v[i].prefix_spec);
				return (EINVAL);
			}
	if (ra->prefix_list != NULL &&
	    ra->prefix_list->prefix.n > MAXPREFIX) {
		snprintf(err, errlen, "%s: more than %d prefixes", ifname,
		    MAXPREFIX);
		return (EINVAL);
	}
	if (vc_cap_record(f, ifname) == NULL &&
	    vc_cap_add_record(f, ifname, NULL, 0, err, errlen) == -1)
		return (errno);
	/* What the file reads as now: what is the same is left as it is. */
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((error = rtadv_read(f, ifname, a, &was)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	error = write_leaves(f, ifname, ra, was, err, errlen);
	cbl_yarena_free(a);
	return (error);
}

static bool
prefixes_same(const yra *x, const yra *y)
{
	size_t n = x->prefix_list != NULL ? x->prefix_list->prefix.n : 0;
	size_t m = y->prefix_list != NULL ? y->prefix_list->prefix.n : 0;

	if (n != m)
		return (false);
	for (size_t i = 0; i < n; i++) {
		const ypfx *p = &x->prefix_list->prefix.v[i];
		const ypfx *q = &y->prefix_list->prefix.v[i];

		if (strcmp(p->prefix_spec, q->prefix_spec) != 0 ||
		    (!p->has_on_link_flag || p->on_link_flag) !=
		    (!q->has_on_link_flag || q->on_link_flag) ||
		    (!p->has_autonomous_flag || p->autonomous_flag) !=
		    (!q->has_autonomous_flag || q->autonomous_flag) ||
		    (p->has_valid_lifetime ? p->valid_lifetime : DEF_VLTIME) !=
		    (q->has_valid_lifetime ? q->valid_lifetime : DEF_VLTIME) ||
		    (p->has_preferred_lifetime ? p->preferred_lifetime :
		    DEF_PLTIME) != (q->has_preferred_lifetime ?
		    q->preferred_lifetime : DEF_PLTIME))
			return (false);
	}
	return (true);
}

static int
write_leaves(struct vc_capfile *f, const char *ifname, const yra *ra,
    const yra *was, char *err, size_t errlen)
{
	static const char *const pcaps[] = { "addr", "prefixlen",
	    "pinfoflags", "vltime", "pltime", "vltimedecr", "pltimedecr" };
	yra none;
	int error;

	if (was == NULL) {
		memset(&none, 0, sizeof(none));
		was = &none;
	}
#define	W(cap, h, v)	setnum(f, ifname, cap, ra->h, ra->v, was->h, was->v, \
	    err, errlen)
	if ((error = W("maxinterval", has_max_rtr_adv_interval,
	    max_rtr_adv_interval)) != 0 ||
	    (error = W("mininterval", has_min_rtr_adv_interval,
	    min_rtr_adv_interval)) != 0 ||
	    (error = W("chlim", has_cur_hop_limit, cur_hop_limit)) != 0 ||
	    (error = W("rltime", has_default_lifetime,
	    default_lifetime)) != 0 ||
	    (error = W("rtime", has_reachable_time, reachable_time)) != 0 ||
	    (error = W("retrans", has_retrans_timer, retrans_timer)) != 0 ||
	    (error = W("mtu", has_link_mtu, link_mtu)) != 0)
		return (error);
#undef W
	if (ra->has_managed_flag == was->has_managed_flag &&
	    ra->has_other_config_flag == was->has_other_config_flag &&
	    ra->managed_flag == was->managed_flag &&
	    ra->other_config_flag == was->other_config_flag)
		;
	else if (!ra->has_managed_flag && !ra->has_other_config_flag) {
		if (vc_cap_unset(f, ifname, "raflags", err, errlen) == -1)
			return (errno);
	} else {
		char flags[3] = "";

		if (ra->managed_flag)
			strlcat(flags, "m", sizeof(flags));
		if (ra->other_config_flag)
			strlcat(flags, "o", sizeof(flags));
		if (vc_cap_set(f, ifname, "raflags", '=', flags, err,
		    errlen) == -1)
			return (errno);
	}
	/* The prefixes, if not the same: those there out, the given ones
	 * numbered. */
	if (prefixes_same(ra, was))
		return (0);
	for (int i = -1; i < MAXPREFIX; i++)
		for (size_t k = 0; k < nitems(pcaps); k++) {
			char e[32];

			entry(e, sizeof(e), i, pcaps[k]);
			if (vc_cap_unset(f, ifname, e, err, errlen) == -1)
				return (errno);
		}
	for (size_t i = 0; ra->prefix_list != NULL &&
	    i < ra->prefix_list->prefix.n; i++) {
		const ypfx *p = &ra->prefix_list->prefix.v[i];
		char e[32], addr[INET6_ADDRSTRLEN + 8], *slash;
		char flags[3] = "";

		strlcpy(addr, p->prefix_spec, sizeof(addr));
		if ((slash = strchr(addr, '/')) == NULL) {
			snprintf(err, errlen, "%s: not a prefix", addr);
			return (EINVAL);
		}
		*slash++ = '\0';
		entry(e, sizeof(e), (int)i, "addr");
		if (vc_cap_set(f, ifname, e, '=', addr, err, errlen) == -1)
			return (errno);
		entry(e, sizeof(e), (int)i, "prefixlen");
		if ((error = setnum(f, ifname, e, true, strtoull(slash, NULL,
		    10), false, 0, err, errlen)) != 0)
			return (error);
		if (!p->has_on_link_flag || p->on_link_flag)
			strlcat(flags, "l", sizeof(flags));
		if (!p->has_autonomous_flag || p->autonomous_flag)
			strlcat(flags, "a", sizeof(flags));
		entry(e, sizeof(e), (int)i, "pinfoflags");
		if (vc_cap_set(f, ifname, e, '=', flags, err, errlen) == -1)
			return (errno);
		entry(e, sizeof(e), (int)i, "vltime");
		if ((error = setnum(f, ifname, e, p->has_valid_lifetime,
		    p->valid_lifetime, false, 0, err, errlen)) != 0)
			return (error);
		entry(e, sizeof(e), (int)i, "pltime");
		if ((error = setnum(f, ifname, e, p->has_preferred_lifetime,
		    p->preferred_lifetime, false, 0, err, errlen)) != 0)
			return (error);
	}
	return (0);
}
