/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yrtadv: rtadvd.conf as RFC 8349's router advertisement submodule has
 * it (rtadv.c), for agent_test.sh and agent_root_test.sh.
 *
 *	yrtadv conf if			the interface's leaves, one a line,
 *					name=value; a prefix a line, "prefix
 *					spec on-link auto valid preferred"
 *	yrtadv -w conf if out		the same, written to out's record of
 *					the interface (made), read back
 *	yrtadv -m conf if n		max-rtr-adv-interval made n, in conf
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "collect.h"
#include "varconf.h"

typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements
    yra;

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
#undef LEAF
	for (size_t i = 0; ra->prefix_list != NULL &&
	    i < ra->prefix_list->prefix.n; i++) {
		const struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_prefix_list_prefix
		    *p = &ra->prefix_list->prefix.v[i];

		printf("prefix %s %d %d %u %u\n", p->prefix_spec,
		    p->on_link_flag, p->autonomous_flag, p->valid_lifetime,
		    p->preferred_lifetime);
	}
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
	errx(2, "usage: yrtadv conf if | -w conf if out | -m conf if n");
}
