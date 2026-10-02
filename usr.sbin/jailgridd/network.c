/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The host's network tables, as netstat(1) and sockstat(1) print them
 * with --libxo json: the daemon runs the program and hands its JSON on
 * untouched, so what the console shows is what the program said.
 */

#include <sys/types.h>

#include <string.h>

#include "jailgridd.h"

int
do_network(struct work *w, uint8_t kind, uint8_t family,
    struct jg_network_rsp *rsp)
{
	struct execres	 res;
	const char	*fam;
	char		*argv[8];
	int		 i;

	rsp->has_ok = true;
	rsp->ok = false;
	fam = family == JG_NET_FAMILY_INET ? "inet" :
	    family == JG_NET_FAMILY_INET6 ? "inet6" : NULL;
	i = 0;
	switch (kind) {
	case JG_NET_KIND_ROUTES:
	case JG_NET_KIND_NEXTHOPS:
	case JG_NET_KIND_CONNECTIONS:
		argv[i++] = (char *)(uintptr_t)opts.netstat_bin;
		argv[i++] = (char *)(uintptr_t)"--libxo";
		argv[i++] = (char *)(uintptr_t)"json";
		argv[i++] = (char *)(uintptr_t)(kind == JG_NET_KIND_ROUTES ?
		    "-rnW" : kind == JG_NET_KIND_NEXTHOPS ? "-onW" : "-n");
		if (fam != NULL) {
			argv[i++] = (char *)(uintptr_t)"-f";
			argv[i++] = (char *)(uintptr_t)fam;
		}
		break;
	default:
		argv[i++] = (char *)(uintptr_t)opts.sockstat_bin;
		argv[i++] = (char *)(uintptr_t)"--libxo";
		argv[i++] = (char *)(uintptr_t)"json";
		argv[i++] = (char *)(uintptr_t)(family == JG_NET_FAMILY_INET ?
		    "-4" : family == JG_NET_FAMILY_INET6 ? "-6" : "-46");
		break;
	}
	argv[i] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, argv[0]));
		return (0);
	}
	if (res.outlen > JG_MAX_JSON) {
		rsp->error = wfmt(w, "%s printed %zu bytes, more than the "
		    "%d the reply can carry", argv[0], res.outlen, JG_MAX_JSON);
		return (0);
	}
	rsp->json = wtext(w, res.out);
	rsp->ok = true;
	return (0);
}
