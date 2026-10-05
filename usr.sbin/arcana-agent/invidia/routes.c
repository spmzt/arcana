/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: static routes, added and deleted through netlink(4) by the
 * helper (nlroute.c), whose words the trace keeps.  The table itself
 * is read the same way (network.c).  A change is made live, and when asked also
 * kept in rc.conf: a route this daemon keeps is named after its
 * destination in static_routes, or in ipv6_static_routes.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
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

/* The name rc.conf knows the route to dest by: arc_10_77_0_0_16. */
static char *
route_name(struct work *w, const char *dest, uint32_t fib)
{
	char	*name, *p;

	name = fib != 0 ? wfmt(w, "arc_%s_fib%u", dest, fib) : wfmt(w, "arc_%s",
	    dest);
	for (p = name; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p))
			*p = '_';
	return (name);
}

/*
 * Add a static route to destination by gateway, an address or the name
 * of an interface, or delete the route to destination; in the routing
 * table fib, and with persist in rc.conf as well.
 */
int
do_route(struct work *w, const char *destination, const char *gateway,
    bool remove, uint32_t fib, const struct route_more *more, bool persist,
    const char **errp)
{
	static const struct route_more	none;
	struct execres	 res;
	unsigned char	 raw[16];
	const char	*dest, *name, *list, *e, *mods, *words[7];
	bool		 iface;
	int		 af, gaf, n;

	if (more == NULL)
		more = &none;

	if (!parse_dest(w, destination, &af, &dest)) {
		*errp = wfmt(w, "%s is not a destination: default, or an "
		    "address with or without a prefix length", destination);
		return (-1);
	}
	iface = false;
	gaf = AF_UNSPEC;
	if (gateway != NULL && strchr(gateway, ',') != NULL) {
		/*
		 * Several gateways, each with its share after an @: one
		 * route with as many next hops (ECMP).
		 */
		char	*copy, *it, *one, *at;
		int	 n1;

		if (remove) {
			*errp = "one way of a route is deleted by its gateway; "
			    "all of them without one";
			return (-1);
		}
		if (persist) {
			*errp = "rc.conf keeps a route of one gateway: a route "
			    "of several is not kept from here";
			return (-1);
		}
		copy = wstrdup(w, gateway);
		for (it = copy; (one = strsep(&it, ",")) != NULL; ) {
			if ((at = strchr(one, '@')) != NULL) {
				*at++ = '\0';
				n1 = (int)strtonum(at, 1, 255, &e);
				if (e != NULL || n1 == 0) {
					*errp = wfmt(w, "%s: a share is from "
					    "1 to 255", at);
					return (-1);
				}
			}
			n1 = inet_pton(AF_INET, one, raw) == 1 ? AF_INET :
			    inet_pton(AF_INET6, one, raw) == 1 ? AF_INET6 :
			    AF_UNSPEC;
			if (n1 == AF_UNSPEC) {
				*errp = wfmt(w, "%s is not an address: each "
				    "of several gateways is one", one);
				return (-1);
			}
			if (gaf == AF_UNSPEC)
				gaf = n1;
		}
	} else if (gateway != NULL && gateway[0] != '\0') {
		if (inet_pton(AF_INET, gateway, raw) == 1)
			gaf = AF_INET;
		else if (inet_pton(AF_INET6, gateway, raw) == 1)
			gaf = AF_INET6;
		else if (if_exists(w, gateway))
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
	/*
	 * What tells one route to a destination from another: its cost,
	 * its share among those of one cost, and the address of this
	 * host that is sent from.  mods is the same for rc.conf.
	 */
	mods = "";
	if (more->source != NULL && more->source[0] != '\0') {
		if (inet_pton(af, more->source, raw) != 1) {
			*errp = wfmt(w, "%s is no address of the route's "
			    "family to send from", more->source);
			return (-1);
		}
		mods = wfmt(w, " -ifa %s", more->source);
	}
	if (more->metric != 0)
		mods = wfmt(w, "%s -metric %u", mods, more->metric);
	if (more->weight != 0)
		mods = wfmt(w, "%s -weight %u", mods, more->weight);
	/*
	 * Asked of the kernel by the helper, through netlink(4): the
	 * destination, its gateway or its interface, the table, the
	 * cost, and for a new one its share and where it sends from.
	 */
	n = 0;
	words[n++] = strcmp(dest, "default") != 0 ? dest : af == AF_INET ?
	    "0.0.0.0/0" : "::/0";
	words[n++] = !iface && gateway != NULL && gateway[0] != '\0' ?
	    gateway : "-";
	words[n++] = iface ? gateway : "-";
	words[n++] = wfmt(w, "%u", fib);
	words[n++] = wfmt(w, "%u", more->metric);
	if (!remove) {
		words[n++] = wfmt(w, "%u", more->weight);
		words[n++] = more->source != NULL && more->source[0] !=
		    '\0' ? more->source : "-";
	}
	if (run_exec(w, helper_argv(w, remove ? "route-del" : "route-add",
	    (size_t)n, words), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "route"));
		return (-1);
	}
	if (!persist)
		return (0);
	/* route_<name> is what rc(8) gives route add, the family aside. */
	name = route_name(w, dest, fib);
	list = af == AF_INET ? "static_routes" : "ipv6_static_routes";
	if (remove) {
		e = NULL;
		(void)rc_set(w, list, "-=", name, &e);
		rc_unset(w, wfmt(w, "%sroute_%s", af == AF_INET ? "" : "ipv6_",
		    name));
		return (0);
	}
	if (rc_set(w, wfmt(w, "%sroute_%s", af == AF_INET ? "" : "ipv6_", name),
	    "=", wfmt(w, "%s%s %s%s%s%s", dest, iface ? " -iface" : "", gateway,
	    fib != 0 ? " -fib " : "", fib != 0 ? wfmt(w, "%u", fib) : "",
	    mods), errp) != 0 || rc_set(w, list, "+=", name, errp) != 0) {
		/* Not kept: not left half done either. */
		e = NULL;
		(void)do_route(w, destination, gateway, true, fib, more, false,
		    &e);
		return (-1);
	}
	return (0);
}
