/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: static routes, added and deleted through netlink(4) by the
 * helper (nlroute.c), whose words the trace keeps.  The table itself
 * is read the same way (network.c).  A change is made live, and when asked also
 * kept in rc.conf, or kept there alone: a route is kept in static_routes,
 * or in ipv6_static_routes, by the name it is given, or by one made of
 * its destination; one rc.conf keeps already, by any name, is found by
 * its destination and table.
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

/* The name rc.conf knows the route to dest by when none is given:
 * arc_10_77_0_0_16. */
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
 * A route as rc.conf keeps it: route_<name> (ipv6_route_<name>) is what
 * rc.d/routing gives route(8), whoever wrote it, so its words are read
 * as route(8) reads them: the destination and gateway where they stand,
 * -gateway, -iface, -fib and the rest by their flags.
 */
struct kept {
	const char	*name;
	const char	*value;
	const char	*dest;		/* as parse_dest() gives it */
	const char	*gw;		/* an address or an interface, or NULL */
	const char	*kind;		/* gateway, interface, blackhole, reject */
	uint32_t	 fib;
};

/* route(8)'s flags that take a word after them. */
static bool
kept_flag_arg(const char *f)
{
	static const char *const with[] = { "-fib", "-gateway", "-ifa",
	    "-ifp", "-metric", "-weight", "-mtu", "-netmask", "-prefixlen",
	    "-expire", "-hopcount", "-sendpipe", "-recvpipe", "-ssthresh",
	    "-rtt", "-rttvar", "-genmask", "-label" };
	size_t	i;

	for (i = 0; i < nitems(with); i++)
		if (strcmp(f, with[i]) == 0)
			return (true);
	return (false);
}

static bool
kept_parse(struct work *w, const char *name, const char *value,
    struct kept *k)
{
	char		*copy, *it, *word, *arg;
	const char	*dest, *first, *e;
	bool		 iface;
	int		 af;

	memset(k, 0, sizeof(*k));
	k->name = name;
	k->value = value;
	k->kind = "gateway";
	first = NULL;
	iface = false;
	copy = wstrdup(w, value);
	for (it = copy; (word = strsep(&it, " \t")) != NULL; ) {
		if (*word == '\0')
			continue;
		if (word[0] != '-') {
			if (first == NULL)
				first = word;
			else if (k->gw == NULL)
				k->gw = word;
			continue;
		}
		if (strcmp(word, "-iface") == 0 || strcmp(word,
		    "-interface") == 0)
			iface = true;
		else if (strcmp(word, "-blackhole") == 0)
			k->kind = "blackhole";
		else if (strcmp(word, "-reject") == 0)
			k->kind = "reject";
		if (!kept_flag_arg(word))
			continue;
		arg = NULL;
		while (it != NULL && (arg = strsep(&it, " \t")) != NULL &&
		    *arg == '\0')
			;
		if (arg == NULL || *arg == '\0')
			return (false);
		if (strcmp(word, "-fib") == 0) {
			k->fib = (uint32_t)strtonum(arg, 0, 65535, &e);
			if (e != NULL)
				return (false);
		} else if (strcmp(word, "-gateway") == 0)
			k->gw = arg;
	}
	if (first == NULL || !parse_dest(w, first, &af, &dest))
		return (false);
	k->dest = dest;
	if (iface && k->gw != NULL)
		k->kind = "interface";
	if (strcmp(k->kind, "blackhole") == 0 || strcmp(k->kind, "reject") == 0)
		k->gw = NULL;
	return (true);
}

/*
 * Two spellings of one destination: 10.0.0.1 and 10.0.0.1/32, a
 * default by any of its names.
 */
static bool
same_dest(struct work *w, const char *a, const char *b)
{
	const char	*full[2], *s;
	int		 i;

	for (i = 0; i < 2; i++) {
		s = i == 0 ? a : b;
		full[i] = strcmp(s, "default") == 0 || strchr(s, '/') != NULL ?
		    s : wfmt(w, "%s/%d", s, strchr(s, ':') != NULL ? 128 : 32);
	}
	return (strcmp(full[0], full[1]) == 0);
}

/*
 * The route rc.conf keeps to dest in table fib, of the family pfx says
 * ("" or "ipv6_"), by whatever name: its name in *k.  None: false.
 */
static bool
kept_find(struct work *w, const char *pfx, const char *dest, uint32_t fib,
    struct kept *k)
{
	const char	*list, *v;
	char		*copy, *it, *name;

	if ((list = rc_get(w, wfmt(w, "%sstatic_routes", pfx))) == NULL)
		return (false);
	copy = wstrdup(w, list);
	for (it = copy; (name = strsep(&it, " \t")) != NULL; ) {
		if (*name == '\0' || (v = rc_get(w, wfmt(w, "%sroute_%s", pfx,
		    name))) == NULL)
			continue;
		if (kept_parse(w, name, v, k) && k->fib == fib &&
		    same_dest(w, k->dest, dest))
			return (true);
	}
	return (false);
}
/*
 * The route rc.conf keeps to dest in table fib, of either family, kept
 * by name instead: its words as they are, whoever wrote them.
 */
static int
route_rename(struct work *w, const char *dest, uint32_t fib,
    const char *name, const char **errp)
{
	struct kept	 k, other;
	const char	*pfx, *list, *v, *e;
	int		 i;

	if (name == NULL || name[0] == '\0') {
		*errp = "a route kept is renamed by a name, or changed by a "
		    "gateway";
		return (-1);
	}
	for (i = 0; i < 2; i++) {
		pfx = i == 0 ? "" : "ipv6_";
		if (kept_find(w, pfx, dest, fib, &k))
			break;
	}
	if (i == 2) {
		*errp = wfmt(w, "rc.conf keeps no route to %s in FIB %u", dest,
		    fib);
		return (-1);
	}
	if (strcmp(k.name, name) == 0)
		return (0);
	list = i == 0 ? "static_routes" : "ipv6_static_routes";
	if ((v = rc_get(w, wfmt(w, "%sroute_%s", pfx, name))) != NULL &&
	    (!kept_parse(w, name, v, &other) || other.fib != fib ||
	    !same_dest(w, other.dest, dest))) {
		*errp = wfmt(w, "rc.conf keeps another route by the name %s: "
		    "%s", name, v);
		return (-1);
	}
	if (rc_set(w, wfmt(w, "%sroute_%s", pfx, name), "=", k.value,
	    errp) != 0 || rc_set(w, list, "+=", name, errp) != 0)
		return (-1);
	e = NULL;
	(void)rc_set(w, list, "-=", k.name, &e);
	rc_unset(w, wfmt(w, "%sroute_%s", pfx, k.name));
	return (0);
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
	struct kept	 k;
	const char	*dest, *name, *old, *list, *e, *mods, *pfx, *var,
			*words[7];
	bool		 iface, added;
	int		 af, gaf, n;

	if (more == NULL)
		more = &none;

	if (!parse_dest(w, destination, &af, &dest)) {
		*errp = wfmt(w, "%s is not a destination: default, or an "
		    "address with or without a prefix length", destination);
		return (-1);
	}
	if (more->rc_only && !remove && (gateway == NULL || gateway[0] ==
	    '\0'))
		return (route_rename(w, dest, fib, more->name, errp));
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
	if (more->rc_only && !persist) {
		*errp = "a route kept in rc.conf alone is one to keep: say so";
		return (-1);
	}
	if (more->name != NULL && more->name[0] != '\0' &&
	    (!rc_name_ok(more->name) || strlen(more->name) > 64)) {
		*errp = wfmt(w, "%s cannot name a route in rc.conf: letters, "
		    "digits and _, not first a digit, 64 at most", more->name);
		return (-1);
	}
	if (more->rc_only)
		;	/* the kernel's table as it is */
	else if (run_exec(w, helper_argv(w, remove ? "route-del" : "route-add",
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
	list = af == AF_INET ? "static_routes" : "ipv6_static_routes";
	pfx = af == AF_INET ? "" : "ipv6_";
	/* Kept already by some name: the one it goes on by, unless another
	 * is given. */
	old = kept_find(w, pfx, dest, fib, &k) ? k.name : NULL;
	name = more->name != NULL && more->name[0] != '\0' ? more->name :
	    old != NULL ? old : route_name(w, dest, fib);
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
		if (old != NULL) {
			e = NULL;
			(void)rc_set(w, list, "-=", old, &e);
			rc_unset(w, wfmt(w, "%sroute_%s", pfx, old));
		}
		return (0);
	}
	if (remove) {
		e = NULL;
		(void)rc_set(w, list, "-=", name, &e);
		rc_unset(w, wfmt(w, "%sroute_%s", pfx, name));
		return (0);
	}
	/* A name is one route's: another's is not taken over. */
	if (old == NULL || strcmp(old, name) != 0) {
		const char	*v;
		struct kept	 other;

		if ((v = rc_get(w, wfmt(w, "%sroute_%s", pfx, name))) != NULL &&
		    (!kept_parse(w, name, v, &other) || other.fib != fib ||
		    !same_dest(w, other.dest, dest))) {
			*errp = wfmt(w, "rc.conf keeps another route by the name "
			    "%s: %s", name, v);
			if (added) {
				e = NULL;
				(void)do_route(w, destination, gateway, true,
				    fib, more, false, &e);
			}
			return (-1);
		}
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
	/* Renamed: the old name goes. */
	if (old != NULL && strcmp(old, name) != 0) {
		e = NULL;
		(void)rc_set(w, list, "-=", old, &e);
		rc_unset(w, wfmt(w, "%sroute_%s", pfx, old));
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
	struct kept	 k;
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
	/* Kept by its name, which it is put back by. */
	if (kept_find(w, pfx, dest, fib, &k)) {
		*keptp = true;
		more->name = k.name;
	} else
		*keptp = strcmp(dest, "default") == 0 && rc_get(w, wfmt(w,
		    "%sdefaultrouter%s", pfx, fib != 0 ? wfmt(w, "_fib%u", fib) :
		    "")) != NULL;
	return (0);
}

static void
kput(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

/* Is name one of the words of list? */
static bool
listed_in(struct work *w, const char *list, const char *name)
{
	char	*copy, *it, *word;

	copy = wstrdup(w, list != NULL ? list : "");
	for (it = copy; (word = strsep(&it, " \t")) != NULL; )
		if (strcmp(word, name) == 0)
			return (true);
	return (false);
}

/*
 * The routes rc.conf keeps, for a reader: of each family, each name
 * static_routes lists with its route_<name> read as route(8) would,
 * those it lists that have no variable ("missing"), and the variables
 * of routes it does not list ("listed" false: rc.d/routing leaves
 * them); and the default routers, of each table.  sysrc(8) -a says
 * them all at once, of the host or of the jail worked in.
 */
int
do_kept_routes(struct work *w, struct arc_network_rsp *rsp)
{
	static const char *const pfxs[] = { "", "ipv6_" };
	struct execres	 res;
	struct kept	 k;
	ucl_object_t	*top, *routes, *defs, *o, *vars;
	const ucl_object_t *v;
	unsigned char	*json;
	const char	*val, *e, *rest;
	char		*argv[3], *copy, *it, *line, *colon, *name;
	size_t		 i, plen;
	uint32_t	 fib;

	rsp->has_ok = true;
	rsp->ok = false;
	argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
	argv[1] = (char *)(uintptr_t)"-a";
	argv[2] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL) {
		rsp->error = wtext(w, exec_error(w, &res, "sysrc"));
		return (0);
	}
	/* "name: value" a line. */
	vars = ucl_object_typed_new(UCL_OBJECT);
	copy = wstrdup(w, res.out);
	for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
		if ((colon = strstr(line, ": ")) == NULL)
			continue;
		*colon = '\0';
		if (rc_name_ok(line))
			kput(vars, line, ucl_object_fromstring(colon + 2));
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	routes = ucl_object_typed_new(UCL_ARRAY);
	defs = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nitems(pfxs); i++) {
		const char	*fam = i == 0 ? "inet" : "inet6";
		const char	*list = i == 0 ? "static_routes" :
				    "ipv6_static_routes";
		ucl_object_iter_t it2 = NULL;

		/* Listed, in their order. */
		v = ucl_object_lookup(vars, list);
		copy = wstrdup(w, v != NULL ? ucl_object_tostring(v) : "");
		for (it = copy; (name = strsep(&it, " \t")) != NULL; ) {
			if (*name == '\0' || !rc_name_ok(name))
				continue;
			o = ucl_object_typed_new(UCL_OBJECT);
			kput(o, "name", ucl_object_fromstring(name));
			kput(o, "family", ucl_object_fromstring(fam));
			kput(o, "list", ucl_object_fromstring(list));
			kput(o, "variable", ucl_object_fromstring(wfmt(w,
			    "%sroute_%s", pfxs[i], name)));
			kput(o, "listed", ucl_object_frombool(true));
			v = ucl_object_lookup(vars, wfmt(w, "%sroute_%s",
			    pfxs[i], name));
			if (v == NULL)
				kput(o, "missing", ucl_object_frombool(true));
			else {
				val = ucl_object_tostring(v);
				kput(o, "value", ucl_object_fromstring(val));
				if (kept_parse(w, name, val, &k)) {
					kput(o, "destination",
					    ucl_object_fromstring(k.dest));
					if (k.gw != NULL)
						kput(o, "gateway",
						    ucl_object_fromstring(k.gw));
					kput(o, "kind",
					    ucl_object_fromstring(k.kind));
					kput(o, "fib", ucl_object_fromint(
					    k.fib));
				}
			}
			ucl_array_append(routes, o);
		}
		/* Variables of routes the list does not name. */
		plen = strlen(wfmt(w, "%sroute_", pfxs[i]));
		while ((v = ucl_object_iterate(vars, &it2, true)) != NULL) {
			const char *key = ucl_object_key(v);

			if (strncmp(key, wfmt(w, "%sroute_", pfxs[i]),
			    plen) != 0)
				continue;
			name = wstrdup(w, key + plen);
			v = ucl_object_lookup(vars, list);
			if (v != NULL && listed_in(w, ucl_object_tostring(v), name))
				continue;
			v = ucl_object_lookup(vars, key);
			o = ucl_object_typed_new(UCL_OBJECT);
			kput(o, "name", ucl_object_fromstring(name));
			kput(o, "family", ucl_object_fromstring(fam));
			kput(o, "list", ucl_object_fromstring(list));
			kput(o, "variable", ucl_object_fromstring(key));
			kput(o, "listed", ucl_object_frombool(false));
			val = ucl_object_tostring(v);
			kput(o, "value", ucl_object_fromstring(val));
			if (kept_parse(w, name, val, &k)) {
				kput(o, "destination",
				    ucl_object_fromstring(k.dest));
				if (k.gw != NULL)
					kput(o, "gateway",
					    ucl_object_fromstring(k.gw));
				kput(o, "kind", ucl_object_fromstring(k.kind));
				kput(o, "fib", ucl_object_fromint(k.fib));
			}
			ucl_array_append(routes, o);
		}
		/* defaultrouter, and defaultrouter_fib<N> of the others. */
		it2 = NULL;
		while ((v = ucl_object_iterate(vars, &it2, true)) != NULL) {
			const char *key = ucl_object_key(v);
			const char *base = wfmt(w, "%sdefaultrouter", pfxs[i]);

			if (strncmp(key, base, strlen(base)) != 0)
				continue;
			rest = key + strlen(base);
			if (*rest == '\0')
				fib = 0;
			else if (strncmp(rest, "_fib", 4) == 0) {
				fib = (uint32_t)strtonum(rest + 4, 0, 65535, &e);
				if (e != NULL)
					continue;
			} else
				continue;
			val = ucl_object_tostring(v);
			if (val == NULL || *val == '\0' || strcasecmp(val,
			    "NO") == 0)
				continue;
			o = ucl_object_typed_new(UCL_OBJECT);
			kput(o, "variable", ucl_object_fromstring(key));
			kput(o, "family", ucl_object_fromstring(fam));
			kput(o, "fib", ucl_object_fromint(fib));
			kput(o, "gateway", ucl_object_fromstring(val));
			ucl_array_append(defs, o);
		}
	}
	ucl_object_unref(vars);
	kput(top, "routes", routes);
	kput(top, "defaults", defs);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "rc.conf keeps more routes than a reply carries";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}
