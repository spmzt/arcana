/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: static routes, added and deleted by running route(8), whose
 * argv and output the trace keeps.  The table itself is read through
 * netstat(1) (network.c).  Changes are live only: nothing here touches
 * rc.conf.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

/*
 * A destination: "default", a network or host address with or without
 * a prefix length.  0.0.0.0/0 and ::/0 are the defaults of their
 * families.  Sets the family and what route(8) is given.
 */
static bool
parse_dest(struct work *w, const char *s, int *afp, const char **destp)
{
	unsigned char	 raw[16];
	const char	*slash, *errstr;
	char		*addr;
	int		 plen, max;

	if (strcmp(s, "default") == 0) {
		*afp = AF_UNSPEC;
		*destp = "default";
		return (true);
	}
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
	plen = max;
	if (slash != NULL) {
		plen = (int)strtonum(slash + 1, 0, max, &errstr);
		if (errstr != NULL)
			return (false);
	}
	*destp = plen == 0 ? "default" : slash != NULL ? wfmt(w, "%s/%d", addr,
	    plen) : addr;
	return (true);
}

/*
 * Add a static route to destination by gateway, an address or the name
 * of an interface, or delete the route to destination.
 */
int
do_route(struct work *w, const char *destination, const char *gateway,
    bool remove, const char **errp)
{
	struct execres	 res;
	unsigned char	 raw[16];
	const char	*dest;
	char		*argv[9];
	bool		 iface;
	int		 af, gaf, n;

	if (!parse_dest(w, destination, &af, &dest)) {
		*errp = wfmt(w, "%s is not a destination: default, or an "
		    "address with or without a prefix length", destination);
		return (-1);
	}
	iface = false;
	gaf = AF_UNSPEC;
	if (gateway != NULL && gateway[0] != '\0') {
		if (inet_pton(AF_INET, gateway, raw) == 1)
			gaf = AF_INET;
		else if (inet_pton(AF_INET6, gateway, raw) == 1)
			gaf = AF_INET6;
		else if (if_nametoindex(gateway) != 0)
			iface = true;
		else {
			*errp = wfmt(w, "%s is neither an address nor an "
			    "interface of this host", gateway);
			return (-1);
		}
	} else if (!remove) {
		*errp = "a route needs a gateway: an address or an interface";
		return (-1);
	}
	/* "default" alone is IPv4's, unless the gateway says otherwise. */
	if (af == AF_UNSPEC)
		af = gaf == AF_INET6 ? AF_INET6 : AF_INET;
	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.route_bin;
	argv[n++] = (char *)(uintptr_t)"-n";
	argv[n++] = (char *)(uintptr_t)(remove ? "delete" : "add");
	argv[n++] = (char *)(uintptr_t)(af == AF_INET ? "-inet" : "-inet6");
	argv[n++] = (char *)(uintptr_t)dest;
	if (iface)
		argv[n++] = (char *)(uintptr_t)"-iface";
	if (gateway != NULL && gateway[0] != '\0')
		argv[n++] = (char *)(uintptr_t)gateway;
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "route"));
		return (-1);
	}
	return (0);
}
