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

#include <ucl.h>

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
/*
 * The name of an interface of a kind that is cloned, with its unit:
 * one not there yet may be made by the same apply (a tunnel before
 * its routes), and the kernel refuses a route by it otherwise.
 */
static bool
ifname_cloneable(const char *s)
{
	static const char *const kinds[] = { "gre", "gif", "wg", "geneve",
	    "vxlan", "vlan", "ipsec", "tun", "lo", "epair", "bridge", "ng" };
	size_t	i, k;

	if (s == NULL || strlen(s) > 15)
		return (false);
	for (k = 0; k < nitems(kinds); k++) {
		i = strlen(kinds[k]);
		if (strncmp(s, kinds[k], i) == 0 && isdigit((unsigned char)s[i]))
			break;
	}
	if (k == nitems(kinds))
		return (false);
	for (; s[i] != '\0'; i++)
		if (!isdigit((unsigned char)s[i]) && s[i] != 'a' && s[i] != 'b')
			return (false);
	return (true);
}

int
do_route(struct work *w, const char *destination, const char *gateway,
    bool remove, uint32_t fib, const struct route_more *more, bool persist,
    const char **errp)
{
	static const struct route_more	none;
	struct execres	 res;
	unsigned char	 raw[16];
	const char	*dest, *name, *list, *e, *mods, *pfx, *var, *words[7];
	bool		 iface, added;
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
		const char	*zone;

		if (inet_pton(AF_INET, gateway, raw) == 1)
			gaf = AF_INET;
		else if (inet_pton(AF_INET6, gateway, raw) == 1)
			gaf = AF_INET6;
		/* A link-local gateway with its zone, fe80::1%em0, as route(8)
		 * and a router advertisement give it. */
		else if ((zone = strchr(gateway, '%')) != NULL && zone > gateway
		    && inet_pton(AF_INET6, wstrndup(w, gateway, (size_t)(zone -
		    gateway)), raw) == 1 && IN6_IS_ADDR_LINKLOCAL((struct in6_addr *)
		    raw) && if_exists(w, zone + 1))
			gaf = AF_INET6;
		else if (if_exists(w, gateway) || ifname_cloneable(gateway))
			/* One not there yet (a tunnel the same apply makes) is
			 * the kernel's to refuse, by the helper. */
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
	added = false;
	if (run_exec(w, helper_argv(w, remove ? "route-del" : "route-add",
	    (size_t)n, words), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "route"));
		/* One there already (set by hand, say) is kept all the same
		 * when that is asked. */
		if (remove || !persist || strstr(*errp, "there already") == NULL)
			return (-1);
	} else
		added = !remove;
	if (!persist)
		return (0);
	name = route_name(w, dest, fib);
	list = af == AF_INET ? "static_routes" : "ipv6_static_routes";
	pfx = af == AF_INET ? "" : "ipv6_";
	/*
	 * A default route is rc.conf's defaultrouter, of its table's own
	 * past the first (rc.d/routing); one by an interface, or with a
	 * cost, share or source, goes among the static routes as route(8)
	 * takes it, as every other route does, route_<name> being what
	 * rc(8) gives route add.
	 */
	if (strcmp(dest, "default") == 0 && !iface && mods[0] == '\0') {
		var = wfmt(w, "%sdefaultrouter%s", pfx, fib != 0 ? wfmt(w,
		    "_fib%u", fib) : "");
		if (remove) {
			rc_unset(w, var);
			return (0);
		}
		if (rc_set(w, var, "=", gateway, errp) != 0) {
			if (added) {
				e = NULL;
				(void)do_route(w, destination, gateway, true, fib,
				    more, false, &e);
			}
			return (-1);
		}
		/* Kept by a name before: that goes, the variable says it. */
		if (rc_get(w, wfmt(w, "%sroute_%s", pfx, name)) != NULL) {
			e = NULL;
			(void)rc_set(w, list, "-=", name, &e);
			rc_unset(w, wfmt(w, "%sroute_%s", pfx, name));
		}
		return (0);
	}
	if (remove) {
		e = NULL;
		(void)rc_set(w, list, "-=", name, &e);
		rc_unset(w, wfmt(w, "%sroute_%s", af == AF_INET ? "" : "ipv6_",
		    name));
		return (0);
	}
	if (rc_set(w, wfmt(w, "%sroute_%s", pfx, name), "=", wfmt(w,
	    "%s%s %s%s%s%s", dest, iface ? " -iface" : "", gateway, fib != 0 ?
	    " -fib " : "", fib != 0 ? wfmt(w, "%u", fib) : "", mods), errp) !=
	    0 || rc_set(w, list, "+=", name, errp) != 0) {
		/* Not kept: not left half done either. */
		if (added) {
			e = NULL;
			(void)do_route(w, destination, gateway, true, fib, more,
			    false, &e);
		}
		return (-1);
	}
	return (0);
}

/*
 * What the kernel has for a destination in a FIB, as its list says it,
 * before a safe delete without a gateway: the gateway (or interface),
 * cost, share and source to add it back with, and whether rc.conf keeps
 * it.  One line, or it cannot be put back: none is no such route, two
 * are two ways (ECMP) of which the delete takes both.
 */
struct found {
	struct work		*w;
	const char		*dest;
	const char		*gw;
	struct route_more	 more;
	int			 n;
};

static void
found_line(const char *line, void *arg)
{
	struct found		*f = arg;
	struct ucl_parser	*p;
	ucl_object_t		*o;
	const ucl_object_t	*v;
	const char		*s;

	if (line[0] != '{')
		return;
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_chunk(p, (const unsigned char *)line, strlen(line)) ?
	    ucl_parser_get_object(p) : NULL;
	ucl_parser_free(p);
	if (o == NULL)
		return;
	if ((v = ucl_object_lookup(o, "destination")) != NULL && (s =
	    ucl_object_tostring(v)) != NULL && strcmp(s, f->dest) == 0) {
		f->n++;
		s = (v = ucl_object_lookup(o, "gateway")) != NULL ?
		    ucl_object_tostring(v) : NULL;
		/* A route of an interface, not of an address: by its name. */
		if (s != NULL && strncmp(s, "link#", 5) == 0)
			s = (v = ucl_object_lookup(o, "interface-name")) !=
			    NULL ? ucl_object_tostring(v) : NULL;
		f->gw = s != NULL ? wstrdup(f->w, s) : NULL;
		f->more.metric = (v = ucl_object_lookup(o, "metric")) != NULL ?
		    (uint32_t)ucl_object_toint(v) : 0;
		/* The share of one among several: 1 alone is the kernel's default,
		 * not a choice to carry into rc.conf. */
		f->more.weight = (v = ucl_object_lookup(o, "weight")) != NULL &&
		    ucl_object_toint(v) != 1 ? (uint32_t)ucl_object_toint(v) : 0;
		f->more.source = (v = ucl_object_lookup(o, "source")) != NULL &&
		    (s = ucl_object_tostring(v)) != NULL ? wstrdup(f->w, s) :
		    NULL;
	}
	ucl_object_unref(o);
}

int
route_snapshot(struct work *w, const char *destination, uint32_t fib,
    const char **gwp, struct route_more *more, bool *keptp, const char **errp)
{
	struct found	 f;
	const char	*dest, *pfx, *words[4];
	int		 af;

	if (!parse_dest(w, destination, &af, &dest)) {
		*errp = wfmt(w, "%s is not a destination: default, or an "
		    "address with or without a prefix length", destination);
		return (-1);
	}
	memset(&f, 0, sizeof(f));
	f.w = w;
	f.dest = dest;
	words[0] = "0";
	words[1] = wfmt(w, "%u", fib);
	words[2] = dest;
	words[3] = "-";
	if (helper_lines(w, "routes", 4, words, found_line, &f) != 0) {
		*errp = "the kernel did not list its routes";
		return (-1);
	}
	if (f.n == 0) {
		*errp = wfmt(w, "no route to %s in FIB %u", dest, fib);
		return (-1);
	}
	if (f.n > 1) {
		*errp = wfmt(w, "%s in FIB %u has %d ways: a route of several "
		    "gateways is not put back from here", dest, fib, f.n);
		return (-1);
	}
	if (f.gw == NULL) {
		*errp = wfmt(w, "%s in FIB %u has no gateway or interface to "
		    "add it back by", dest, fib);
		return (-1);
	}
	*gwp = f.gw;
	*more = f.more;
	pfx = af == AF_INET6 || (af == AF_UNSPEC && strchr(f.gw, ':') != NULL) ?
	    "ipv6_" : "";
	*keptp = rc_get(w, wfmt(w, "%sroute_%s", pfx, route_name(w, dest,
	    fib))) != NULL || (strcmp(dest, "default") == 0 && rc_get(w, wfmt(w,
	    "%sdefaultrouter%s", pfx, fib != 0 ? wfmt(w, "_fib%u", fib) : ""))
	    != NULL);
	return (0);
}
