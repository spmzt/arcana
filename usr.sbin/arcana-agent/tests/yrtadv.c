/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yrtadv: rtadvd.conf as RFC 8349's router advertisement submodule and
 * arcana-ra have it (rtadv.c), for agent_test.sh and agent_root_test.sh.
 *
 *	yrtadv conf if			the interface's leaves, one a line,
 *					name=value; a prefix a line, "prefix
 *					spec on-link auto valid preferred
 *					vdecr pdecr"; "route spec pref
 *					ltime", "rdnss addr ltime", "dnssl
 *					name ltime", "pref64 spec ltime" (-
 *					where none), "other text"
 *	yrtadv -w conf if out		the same, written to out's record of
 *					the interface (made), read back
 *	yrtadv -m conf if n		max-rtr-adv-interval made n, in conf
 *	yrtadv -s show if		rtadvctl -v show's text in file show,
 *					the interface's block as arcana-ra's
 *					rtadvd, a leaf a line
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "collect.h"
#include "varconf.h"

typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements
    yra;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_rtadvd
    yrtadvd;

static const char *const prefs[] = { "high", "medium", "low" };
static const char *const origins[] = { "kernel", "config", "dynamic" };

static void
show(const yra *ra)
{

	if (ra == NULL) {
		printf("none\n");
		return;
	}
#define	LEAF(has, name, v) \
	if (ra->has) \
		printf("%s=%ju\n", name, (uintmax_t)(v))
	LEAF(has_max_rtr_adv_interval, "max-rtr-adv-interval",
	    ra->max_rtr_adv_interval);
	LEAF(has_min_rtr_adv_interval, "min-rtr-adv-interval",
	    ra->min_rtr_adv_interval);
	LEAF(has_managed_flag, "managed-flag", ra->managed_flag);
	LEAF(has_other_config_flag, "other-config-flag",
	    ra->other_config_flag);
	LEAF(has_link_mtu, "link-mtu", ra->link_mtu);
	LEAF(has_reachable_time, "reachable-time", ra->reachable_time);
	LEAF(has_retrans_timer, "retrans-timer", ra->retrans_timer);
	LEAF(has_cur_hop_limit, "cur-hop-limit", ra->cur_hop_limit);
	LEAF(has_default_lifetime, "default-lifetime", ra->default_lifetime);
	if (ra->has_arcra_router_preference)
		printf("router-preference=%s\n",
		    prefs[ra->arcra_router_preference]);
	LEAF(has_arcra_link_mtu_auto, "link-mtu-auto", ra->arcra_link_mtu_auto);
	LEAF(has_arcra_interface_prefixes, "interface-prefixes",
	    ra->arcra_interface_prefixes);
	LEAF(has_arcra_source_link_layer_address, "source-link-layer-address",
	    ra->arcra_source_link_layer_address);
	LEAF(has_arcra_clock_skew, "clock-skew", ra->arcra_clock_skew);
#undef LEAF
	for (size_t i = 0; ra->prefix_list != NULL &&
	    i < ra->prefix_list->prefix.n; i++) {
		const struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_prefix_list_prefix
		    *p = &ra->prefix_list->prefix.v[i];

		printf("prefix %s %d %d %u %u %d %d\n", p->prefix_spec,
		    p->on_link_flag, p->autonomous_flag, p->valid_lifetime,
		    p->preferred_lifetime,
		    p->has_arcra_valid_lifetime_decrements &&
		    p->arcra_valid_lifetime_decrements,
		    p->has_arcra_preferred_lifetime_decrements &&
		    p->arcra_preferred_lifetime_decrements);
	}
	for (size_t i = 0; i < ra->arcra_route.n; i++) {
		const struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_route
		    *r = &ra->arcra_route.v[i];

		printf("route %s %s ", r->prefix, r->has_preference ?
		    prefs[r->preference] : "-");
		if (r->has_lifetime)
			printf("%u\n", r->lifetime);
		else
			printf("-\n");
	}
	for (size_t i = 0; i < ra->arcra_rdnss.n; i++) {
		printf("rdnss %s ", ra->arcra_rdnss.v[i].address);
		if (ra->arcra_rdnss.v[i].has_lifetime)
			printf("%u\n", ra->arcra_rdnss.v[i].lifetime);
		else
			printf("-\n");
	}
	for (size_t i = 0; i < ra->arcra_dnssl.n; i++) {
		printf("dnssl %s ", ra->arcra_dnssl.v[i].domain);
		if (ra->arcra_dnssl.v[i].has_lifetime)
			printf("%u\n", ra->arcra_dnssl.v[i].lifetime);
		else
			printf("-\n");
	}
	for (size_t i = 0; i < ra->arcra_pref64.n; i++) {
		printf("pref64 %s ", ra->arcra_pref64.v[i].prefix);
		if (ra->arcra_pref64.v[i].has_lifetime)
			printf("%u\n", ra->arcra_pref64.v[i].lifetime);
		else
			printf("-\n");
	}
	for (size_t i = 0; i < ra->arcra_other_capability.n; i++)
		printf("other %s\n", ra->arcra_other_capability.v[i]);
}

static void
show_state(const yrtadvd *st)
{

	if (st == NULL) {
		printf("none\n");
		return;
	}
	if (st->flags != NULL)
		printf("flags=%s\n", st->flags);
	if (st->status != NULL)
		printf("status=%s\n", st->status);
#define	LEAF(has, name, v) \
	if (st->has) \
		printf("%s=%ju\n", name, (uintmax_t)(v))
	LEAF(has_link_mtu, "link-mtu", st->link_mtu);
	LEAF(has_default_lifetime, "default-lifetime", st->default_lifetime);
	LEAF(has_min_rtr_adv_interval, "min-rtr-adv-interval",
	    st->min_rtr_adv_interval);
	LEAF(has_max_rtr_adv_interval, "max-rtr-adv-interval",
	    st->max_rtr_adv_interval);
	LEAF(has_managed_flag, "managed-flag", st->managed_flag);
	LEAF(has_other_config_flag, "other-config-flag",
	    st->other_config_flag);
	if (st->has_router_preference)
		printf("router-preference=%s\n", prefs[st->router_preference]);
	LEAF(has_reachable_time, "reachable-time", st->reachable_time);
	LEAF(has_retrans_timer, "retrans-timer", st->retrans_timer);
	LEAF(has_cur_hop_limit, "cur-hop-limit", st->cur_hop_limit);
	LEAF(has_interface_prefixes, "interface-prefixes",
	    st->interface_prefixes);
	if (st->next_send != NULL)
		printf("next-send=%s\n", st->next_send);
	if (st->last_send != NULL)
		printf("last-send=%s\n", st->last_send);
	LEAF(has_clock_skew, "clock-skew", st->clock_skew);
#undef LEAF
	for (size_t i = 0; i < st->prefix.n; i++) {
		const struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_rtadvd_prefix
		    *p = &st->prefix.v[i];

		printf("prefix %s %s %u %u %d %d", p->prefix, p->has_origin ?
		    origins[p->origin] : "-", p->valid_lifetime,
		    p->preferred_lifetime, p->on_link_flag, p->autonomous_flag);
		if (p->has_valid_expires)
			printf(" vexpire=%u", p->valid_expires);
		if (p->has_preferred_expires)
			printf(" pexpire=%u", p->preferred_expires);
		printf("\n");
	}
	for (size_t i = 0; i < st->route.n; i++)
		printf("route %s %s %u\n", st->route.v[i].prefix,
		    st->route.v[i].has_preference ?
		    prefs[st->route.v[i].preference] : "-",
		    st->route.v[i].lifetime);
	for (size_t i = 0; i < st->rdnss.n; i++)
		printf("rdnss %s %u\n", st->rdnss.v[i].address,
		    st->rdnss.v[i].lifetime);
	for (size_t i = 0; i < st->dnssl.n; i++)
		printf("dnssl %s %u\n", st->dnssl.v[i].domain,
		    st->dnssl.v[i].lifetime);
	for (size_t i = 0; i < st->pref64.n; i++)
		printf("pref64 %s %u\n", st->pref64.v[i].prefix,
		    st->pref64.v[i].lifetime);
}

int
main(int argc, char **argv)
{
	struct vc_capfile f, o;
	const yra *ra;
	cbl_yarena *a;
	char why[256];
	int error;

	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if (argc == 3) {
		if (vc_cap_read(&f, argv[1], why, sizeof(why)) == -1)
			errx(1, "%s", why);
		if ((error = rtadv_read(&f, argv[2], a, &ra)) != 0)
			errc(1, error, "rtadv_read");
		show(ra);
		return (0);
	}
	if (argc == 5 && strcmp(argv[1], "-w") == 0) {
		if (vc_cap_read(&f, argv[2], why, sizeof(why)) == -1 ||
		    vc_cap_read(&o, argv[4], why, sizeof(why)) == -1)
			errx(1, "%s", why);
		if ((error = rtadv_read(&f, argv[3], a, &ra)) != 0)
			errc(1, error, "rtadv_read");
		if (ra == NULL)
			errx(1, "%s: no record", argv[3]);
		if (rtadv_write(&o, argv[3], ra, why, sizeof(why)) != 0 ||
		    vc_cap_write(&o, argv[4], 0644, why, sizeof(why)) == -1)
			errx(1, "%s", why);
		vc_cap_free(&o);
		if (vc_cap_read(&o, argv[4], why, sizeof(why)) == -1)
			errx(1, "%s", why);
		if ((error = rtadv_read(&o, argv[3], a, &ra)) != 0)
			errc(1, error, "rtadv_read");
		show(ra);
		return (0);
	}
	if (argc == 5 && strcmp(argv[1], "-m") == 0) {
		yra copy;

		if (vc_cap_read(&f, argv[2], why, sizeof(why)) == -1)
			errx(1, "%s", why);
		if ((error = rtadv_read(&f, argv[3], a, &ra)) != 0)
			errc(1, error, "rtadv_read");
		if (ra != NULL)
			copy = *ra;
		else
			memset(&copy, 0, sizeof(copy));
		copy.has_max_rtr_adv_interval = true;
		copy.max_rtr_adv_interval = (uint16_t)atoi(argv[4]);
		if (rtadv_write(&f, argv[3], &copy, why, sizeof(why)) != 0 ||
		    vc_cap_write(&f, argv[2], 0644, why, sizeof(why)) == -1)
			errx(1, "%s", why);
		return (0);
	}
	if (argc == 4 && strcmp(argv[1], "-s") == 0) {
		const yrtadvd *st;
		FILE *fp;
		char *text = NULL;
		size_t len = 0, n;

		if ((fp = fopen(argv[2], "r")) == NULL)
			err(1, "%s", argv[2]);
		while ((text = realloc(text, len + 4096)) != NULL &&
		    (n = fread(text + len, 1, 4095, fp)) > 0)
			len += n;
		if (text == NULL)
			err(1, "realloc");
		text[len] = '\0';
		fclose(fp);
		if ((error = rtadvctl_parse(text, argv[3], a, &st)) != 0)
			errc(1, error, "rtadvctl_parse");
		show_state(st);
		return (0);
	}
	errx(2, "usage: yrtadv conf if | -w conf if out | -m conf if n | "
	    "-s show if");
}
