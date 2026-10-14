/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: static routes in rc.conf, as rc.d/routing installs them, and
 * ietf-routing's static control-plane-protocol (RFC 8349, PLAN-SDN-YANG
 * 2.4.3), both ways.
 *
 * rc.d/routing's static_inet(): each name of static_routes (a name, or
 * name:interface, installed when the interface is), route_<name> its
 * route(8) arguments, the name's ".-/+" made "_" (get_if_var); then
 * defaultrouter, "default <it>", and defaultrouter_fib<N>, with "-fib
 * N".  static_inet6() likewise: ipv6_static_routes, ipv6_route_<name>,
 * route(8) -inet6, ipv6_defaultrouter[_fib<N>].  Its own routes (the
 * loopback's, IPv6's reserved prefixes rejected) are FreeBSD's, not
 * configuration: not read.
 *
 * route(8)'s arguments as far as the model holds them: -inet, -inet6;
 * -net, -host; the destination ("default", an address, address/length,
 * -netmask, -prefixlen); the gateway; -interface and -iface (the
 * gateway is an interface), -ifp (the interface besides the gateway);
 * -blackhole, -reject (unreachable); -fib; -static.  Anything else, a
 * value not settled by reading, two routes of one prefix and one
 * gateway: unread, said why.  Routes of one prefix with gateways of
 * their own are one route, its next-hop-list, as the kernel makes them
 * (multipath).  A name:interface route's description says it.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_schema.h"
#include "collect.h"
#include "varconf.h"

typedef struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes
    ysr;
typedef struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes_v4ur_ipv4_route
    yr4;
typedef struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes_v4ur_ipv4_route_next_hop
    ynh4;
typedef struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes_v4ur_ipv4_route_next_hop_next_hop_list_next_hop
    ynl4;

#define	NH4(x)	IETF_ROUTING_ROUTING_CONTROL_PLANE_PROTOCOLS_CONTROL_PLANE_PROTOCOL_STATIC_ROUTES_V4UR_IPV4_ROUTE_NEXT_HOP_##x
#define	ONLY_WITH	"rc.conf: only with "

/*
 * The v4ur and v6ur structs of a static route are one layout, field for
 * field: what is read is built in v4ur's, and a v6ur one is the same.
 */
_Static_assert(sizeof(yr4) == sizeof(struct
    ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes_v6ur_ipv6_route),
    "v4ur and v6ur static routes differ");
_Static_assert(sizeof(ynh4) == sizeof(struct
    ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes_v6ur_ipv6_route_next_hop),
    "v4ur and v6ur next hops differ");

static char *
astrdup(cbl_yarena *a, const char *s)
{
	size_t len = strlen(s) + 1;
	char *p;

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

/*
 * A variable as rc(8) has it after reading files in order: the last
 * assignment's value; NULL if none.  *settled false where one of them
 * is not read as a literal (an expansion, an if, a command's).
 */
static const char *
rcvar(const struct vc_file *files, size_t n, const char *name, bool *settled)
{
	const char *v = NULL;

	*settled = true;
	for (size_t i = 0; i < n; i++) {
		const struct vc_assign *a = vc_get(&files[i], name);

		if (a == NULL)
			continue;
		if (!vc_settled(&files[i], name)) {
			*settled = false;
			return (NULL);
		}
		v = a->value;
	}
	return (v);
}

/* get_if_var(): a name's ".-/+" made "_". */
static void
varname(char *buf, size_t len, const char *prefix, const char *name)
{
	char *p;

	snprintf(buf, len, "%s%s", prefix, name);
	for (p = buf + strlen(prefix); *p != '\0'; p++)
		if (strchr(".-/+", *p) != NULL)
			*p = '_';
}

/* A route read, before routes of one prefix are put together. */
struct rd {
	char	*prefix;
	char	*gw;		/* an address, or NULL */
	char	*ifn;		/* an interface, or NULL */
	int	 special;	/* -1 none, else NH4(SPECIAL_NEXT_HOP_*) */
	char	*only;		/* name:interface's interface */
	char	*var;
};

/* A netmask's length; -1 if not contiguous. */
static int
masklen(int af, const char *mask)
{
	unsigned char b[16];
	int n = 0, i, max = af == AF_INET ? 4 : 16;
	bool zero = false;

	if (inet_pton(af, mask, b) != 1)
		return (-1);
	for (i = 0; i < max; i++)
		for (int k = 7; k >= 0; k--) {
			if (b[i] & (1 << k)) {
				if (zero)
					return (-1);
				n++;
			} else
				zero = true;
		}
	return (n);
}

/*
 * route(8)'s arguments of var into r, for FIB fib and family af: 1 a
 * route, 0 another FIB's, -1 unread (*why).
 */
static int
parse_args(const char *args, int af, int fib, struct rd *r, const char **why)
{
	char *copy, *p, *tok, *dst = NULL, *gw = NULL, *mask = NULL;
	char *plen = NULL, buf[INET6_ADDRSTRLEN + 8];
	unsigned char bin[16];
	bool host = false, net = false, iface = false;
	int rfib = 0, len, rc = -1;

	memset(r, 0, sizeof(*r));
	r->special = -1;
	if ((copy = strdup(args)) == NULL) {
		*why = "out of memory";
		return (-1);
	}
	for (p = copy; (tok = strsep(&p, " \t")) != NULL; ) {
		if (*tok == '\0')
			continue;
		if (strcmp(tok, "-inet") == 0)
			af = AF_INET;
		else if (strcmp(tok, "-inet6") == 0)
			af = AF_INET6;
		else if (strcmp(tok, "-net") == 0)
			net = true;
		else if (strcmp(tok, "-host") == 0)
			host = true;
		else if (strcmp(tok, "-interface") == 0 ||
		    strcmp(tok, "-iface") == 0)
			iface = true;
		else if (strcmp(tok, "-blackhole") == 0)
			r->special = NH4(SPECIAL_NEXT_HOP_BLACKHOLE);
		else if (strcmp(tok, "-reject") == 0)
			r->special = NH4(SPECIAL_NEXT_HOP_UNREACHABLE);
		else if (strcmp(tok, "-static") == 0)
			;
		else if (strcmp(tok, "-netmask") == 0 ||
		    strcmp(tok, "-prefixlen") == 0 ||
		    strcmp(tok, "-fib") == 0 || strcmp(tok, "-ifp") == 0) {
			char *v;

			while ((v = strsep(&p, " \t")) != NULL && *v == '\0')
				;
			if (v == NULL) {
				*why = "an option without its value";
				goto out;
			}
			if (tok[1] == 'n')
				mask = v;
			else if (tok[1] == 'p')
				plen = v;
			else if (tok[1] == 'f') {
				char *end;
				long f = strtol(v, &end, 10);

				if (*end != '\0' || f < 0) {
					*why = "-fib not a number";
					goto out;
				}
				rfib = (int)f;
			} else
				r->ifn = strdup(v);
		} else if (*tok == '-') {
			*why = "a route(8) option the model has no leaf for";
			goto out;
		} else if (dst == NULL)
			dst = tok;
		else if (gw == NULL)
			gw = tok;
		else {
			*why = "more arguments than a destination and a gateway";
			goto out;
		}
	}
	if (dst == NULL) {
		*why = "no destination";
		goto out;
	}
	if (rfib != fib) {
		rc = 0;
		goto out;
	}
	/* The destination and its length. */
	if (strcmp(dst, "default") == 0) {
		snprintf(buf, sizeof(buf), "%s", af == AF_INET ? "0.0.0.0/0" :
		    "::/0");
	} else {
		char *slash = strchr(dst, '/');

		if (slash != NULL) {
			*slash = '\0';
			len = atoi(slash + 1);
		} else if (mask != NULL)
			len = af == AF_INET ? masklen(af, mask) : -1;
		else if (plen != NULL)
			len = atoi(plen);
		else if (host || !net)
			len = af == AF_INET ? 32 : 128;
		else {
			*why = "a network without its length";
			goto out;
		}
		if (inet_pton(af, dst, bin) != 1 || len < 0 ||
		    len > (af == AF_INET ? 32 : 128)) {
			*why = "not a destination of its family";
			goto out;
		}
		inet_ntop(af, bin, buf, sizeof(buf));
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "/%d",
		    len);
	}
	r->prefix = strdup(buf);
	if (r->special >= 0) {
		/* The gateway of a blackhole or reject route is no hop. */
		rc = 1;
		goto out;
	}
	if (gw == NULL) {
		*why = "no gateway";
		goto out;
	}
	if (iface) {
		free(r->ifn);
		r->ifn = strdup(gw);
	} else {
		/* A link-local one's zone, "%em0", kept: an address
		 * (ietf-inet-types) may have it, as route(8)'s may. */
		char *zone = af == AF_INET6 ? strchr(gw, '%') : NULL;

		if (zone != NULL)
			*zone++ = '\0';
		if (inet_pton(af, gw, bin) != 1 || (zone != NULL &&
		    (*zone == '\0' || !IN6_IS_ADDR_LINKLOCAL((struct in6_addr *)
		    (void *)bin)))) {
			*why = "a gateway not an address of its family";
			goto out;
		}
		inet_ntop(af, bin, buf, sizeof(buf));
		if (zone != NULL)
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
			    "%%%s", zone);
		r->gw = strdup(buf);
	}
	rc = 1;
out:
	if (rc != 1) {
		free(r->prefix);
		free(r->ifn);
		r->prefix = r->ifn = NULL;
	}
	free(copy);
	return (rc);
}

static void
rd_free(struct rd *v, size_t n)
{

	for (size_t i = 0; i < n; i++) {
		free(v[i].prefix);
		free(v[i].gw);
		free(v[i].ifn);
		free(v[i].only);
		free(v[i].var);
	}
	free(v);
}

static int
unread(cbl_yarena *a, struct rcr_unread **u, size_t *nu, const char *var,
    const char *why)
{
	struct rcr_unread *nv;

	if ((nv = reallocarray(*u, *nu + 1, sizeof(*nv))) == NULL)
		return (ENOMEM);
	*u = nv;
	nv[*nu].var = astrdup(a, var);
	nv[*nu].why = why;
	(*nu)++;
	return (0);
}

/* One family's routes of FIB fib, read; put together by prefix. */
static int
family(const struct vc_file *files, size_t nfiles, int fib, int af,
    cbl_yarena *a, const yr4 **outv, size_t *outn, struct rcr_unread **u,
    size_t *nu)
{
	const char *pre = af == AF_INET ? "" : "ipv6_";
	char var[256], dvar[64], *list = NULL, *p, *name;
	const char *v;
	struct rd *rv = NULL, *nr;
	size_t n = 0, nout = 0;
	yr4 *out = NULL;
	bool settled;
	int error = 0;

	snprintf(var, sizeof(var), "%sstatic_routes", pre);
	v = rcvar(files, nfiles, var, &settled);
	if (!settled && (error = unread(a, u, nu, var, "not a value reading "
	    "tells")) != 0)
		return (error);
	if (v != NULL && (list = strdup(v)) == NULL)
		return (ENOMEM);
	/* The default route, rc.d/routing's _default. */
	if (fib == 0)
		snprintf(dvar, sizeof(dvar), "%sdefaultrouter", pre);
	else
		snprintf(dvar, sizeof(dvar), "%sdefaultrouter_fib%d", pre, fib);
	for (p = list; error == 0; ) {
		struct rd r;
		const char *why = NULL, *args;
		char *colon, *only = NULL;
		int rc;

		if (p != NULL) {
			if ((name = strsep(&p, " \t")) == NULL)
				name = NULL;
			else if (*name == '\0')
				continue;
		} else
			name = NULL;
		if (name != NULL) {
			if ((colon = strchr(name, ':')) != NULL) {
				*colon = '\0';
				only = colon + 1;
			}
			varname(var, sizeof(var), af == AF_INET ? "route_" :
			    "ipv6_route_", name);
			args = rcvar(files, nfiles, var, &settled);
			if (!settled || args == NULL) {
				error = unread(a, u, nu, var, !settled ?
				    "not a value reading tells" : "not set");
				continue;
			}
			rc = parse_args(args, af, fib, &r, &why);
		} else {
			/* The list done: the default router, last. */
			args = rcvar(files, nfiles, dvar, &settled);
			if (!settled)
				error = unread(a, u, nu, dvar, "not a value "
				    "reading tells");
			if (!settled || args == NULL ||
			    strcasecmp(args, "NO") == 0)
				break;
			snprintf(var, sizeof(var), "%s", dvar);
			{
				char d[300];

				snprintf(d, sizeof(d), "default %s", args);
				rc = parse_args(d, af, 0, &r, &why);
			}
		}
		if (rc == -1) {
			error = unread(a, u, nu, var, why);
		} else if (rc == 1) {
			if ((nr = reallocarray(rv, n + 1, sizeof(*rv))) ==
			    NULL) {
				free(r.prefix);
				free(r.gw);
				free(r.ifn);
				error = ENOMEM;
				break;
			}
			rv = nr;
			r.only = only != NULL ? strdup(only) : NULL;
			r.var = strdup(var);
			rv[n++] = r;
		}
		if (name == NULL)
			break;
	}
	free(list);
	if (error != 0) {
		rd_free(rv, n);
		return (error);
	}
	/* Put together by prefix: one, a simple or special next hop;
	 * more, a next-hop-list. */
	if (n > 0 && (out = cbl_yarena_alloc(a, n * sizeof(*out))) == NULL) {
		rd_free(rv, n);
		return (ENOMEM);
	}
	for (size_t i = 0; i < n && error == 0; i++) {
		size_t k, m = 0;
		ynh4 *nh;
		bool seen = false;

		for (k = 0; k < i && !seen; k++)
			seen = strcmp(rv[k].prefix, rv[i].prefix) == 0;
		if (seen)
			continue;
		for (k = i; k < n; k++)
			if (strcmp(rv[k].prefix, rv[i].prefix) == 0)
				m++;
		if ((nh = cbl_yarena_alloc(a, sizeof(*nh))) == NULL) {
			error = ENOMEM;
			break;
		}
		memset(nh, 0, sizeof(*nh));
		memset(&out[nout], 0, sizeof(out[nout]));
		out[nout].destination_prefix = astrdup(a, rv[i].prefix);
		out[nout].next_hop = nh;
		if (rv[i].only != NULL) {
			char d[128];

			snprintf(d, sizeof(d), ONLY_WITH "%s", rv[i].only);
			out[nout].description = astrdup(a, d);
		}
		if (m == 1 && rv[i].special >= 0) {
			nh->next_hop_options = NH4(NEXT_HOP_OPTIONS_SPECIAL_NEXT_HOP);
			nh->has_special_next_hop = true;
			nh->special_next_hop = rv[i].special;
		} else if (m == 1) {
			nh->next_hop_options = NH4(NEXT_HOP_OPTIONS_SIMPLE_NEXT_HOP);
			nh->next_hop_address = rv[i].gw != NULL ?
			    astrdup(a, rv[i].gw) : NULL;
			nh->outgoing_interface = rv[i].ifn != NULL ?
			    astrdup(a, rv[i].ifn) : NULL;
		} else {
			struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes_v4ur_ipv4_route_next_hop_next_hop_list
			    *l;
			ynl4 *lv;
			size_t j = 0;

			if ((l = cbl_yarena_alloc(a, sizeof(*l))) == NULL ||
			    (lv = cbl_yarena_alloc(a, m * sizeof(*lv))) ==
			    NULL) {
				error = ENOMEM;
				break;
			}
			memset(lv, 0, m * sizeof(*lv));
			for (k = i; k < n && error == 0; k++) {
				char idx[16];
				bool dup = false;

				if (strcmp(rv[k].prefix, rv[i].prefix) != 0)
					continue;
				/* A list holds hops, not a special one. */
				if (rv[k].special >= 0) {
					error = unread(a, u, nu, rv[k].var,
					    "a blackhole or reject route of a "
					    "prefix that has another");
					break;
				}
				for (size_t q = 0; q < j && !dup; q++)
					dup = (lv[q].next_hop_address == NULL) ==
					    (rv[k].gw == NULL) && (rv[k].gw ==
					    NULL || strcmp(lv[q].next_hop_address,
					    rv[k].gw) == 0);
				/* The kernel would refuse it: EEXIST. */
				if (dup) {
					error = unread(a, u, nu, rv[k].var,
					    "the same prefix and gateway as "
					    "another");
					continue;
				}
				snprintf(idx, sizeof(idx), "%zu", j + 1);
				lv[j].index = astrdup(a, idx);
				lv[j].next_hop_address = rv[k].gw != NULL ?
				    astrdup(a, rv[k].gw) : NULL;
				lv[j].outgoing_interface = rv[k].ifn != NULL ?
				    astrdup(a, rv[k].ifn) : NULL;
				j++;
			}
			if (j == 1) {
				/* A duplicate gone: a simple next hop. */
				nh->next_hop_options =
				    NH4(NEXT_HOP_OPTIONS_SIMPLE_NEXT_HOP);
				nh->next_hop_address = lv[0].next_hop_address;
				nh->outgoing_interface =
				    lv[0].outgoing_interface;
			} else {
				l->next_hop.n = j;
				l->next_hop.v = lv;
				nh->next_hop_options =
				    NH4(NEXT_HOP_OPTIONS_NEXT_HOP_LIST);
				nh->next_hop_list = l;
			}
		}
		nout++;
	}
	rd_free(rv, n);
	if (error != 0)
		return (error);
	*outv = out;
	*outn = nout;
	return (0);
}

int
rcr_read(const struct vc_file *files, size_t nfiles, int fib,
    cbl_yarena *a, const ysr **out, struct rcr_unread **u, size_t *nu)
{
	struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes_v4ur_ipv4
	    *v4;
	struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes_v6ur_ipv6
	    *v6;
	ysr *sr;
	const yr4 *rv;
	size_t n;
	int error;

	*u = NULL;
	*nu = 0;
	if ((sr = cbl_yarena_alloc(a, sizeof(*sr))) == NULL ||
	    (v4 = cbl_yarena_alloc(a, sizeof(*v4))) == NULL ||
	    (v6 = cbl_yarena_alloc(a, sizeof(*v6))) == NULL)
		return (ENOMEM);
	memset(sr, 0, sizeof(*sr));
	memset(v4, 0, sizeof(*v4));
	memset(v6, 0, sizeof(*v6));
	if ((error = family(files, nfiles, fib, AF_INET, a, &rv, &n, u,
	    nu)) != 0)
		return (error);
	v4->route.n = n;
	v4->route.v = rv;
	if ((error = family(files, nfiles, fib, AF_INET6, a, &rv, &n, u,
	    nu)) != 0)
		return (error);
	v6->route.n = n;
	v6->route.v = (const void *)rv;
	sr->v4ur_ipv4 = v4;
	sr->v6ur_ipv6 = v6;
	*out = sr;
	return (0);
}

/*
 * Writing: a family's routes into fragment f, which Arcana owns: its
 * static_routes (and ipv6_), a route_<name> each, the default router.
 */

/* A route's name: its prefix, made a variable's ("." ":" "/" "_"). */
static void
route_name(char *buf, size_t len, const char *prefix, size_t k)
{
	char *p;

	snprintf(buf, len, "arc_%s", prefix);
	for (p = buf; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p))
			*p = '_';
	if (k > 0)
		snprintf(buf + strlen(buf), len - strlen(buf), "_%zu", k);
}

static int
put(struct vc_file *f, const char *name, const char *value, char *err,
    size_t errlen)
{

	return (vc_set(f, name, value, err, errlen) == -1 ? errno : 0);
}

/* route(8)'s arguments of a hop; -1: none for it. */
static int
hop_args(char *buf, size_t len, int af, const char *prefix, const char *gw,
    const char *ifn, int special, int fib)
{
	const char *slash = strchr(prefix, '/');
	int plen = slash != NULL ? atoi(slash + 1) : 0;
	char dst[INET6_ADDRSTRLEN + 8];
	char fibs[32] = "";

	if (fib != 0)
		snprintf(fibs, sizeof(fibs), " -fib %d", fib);
	snprintf(dst, sizeof(dst), "%s", prefix);
	if (plen == 0)
		snprintf(dst, sizeof(dst), "default");
	else if (plen == (af == AF_INET ? 32 : 128)) {
		snprintf(dst, sizeof(dst), "-host %.*s", (int)(slash - prefix),
		    prefix);
	} else
		snprintf(dst, sizeof(dst), "-net %s", prefix);
	if (special == NH4(SPECIAL_NEXT_HOP_BLACKHOLE) ||
	    special == NH4(SPECIAL_NEXT_HOP_UNREACHABLE)) {
		snprintf(buf, len, "%s %s %s%s", dst, af == AF_INET ?
		    "127.0.0.1" : "::1", special ==
		    NH4(SPECIAL_NEXT_HOP_BLACKHOLE) ? "-blackhole" : "-reject",
		    fibs);
		return (0);
	}
	if (special >= 0)
		return (-1);
	if (gw != NULL && ifn != NULL)
		snprintf(buf, len, "%s %s -ifp %s%s", dst, gw, ifn, fibs);
	else if (gw != NULL)
		snprintf(buf, len, "%s %s%s", dst, gw, fibs);
	else if (ifn != NULL)
		snprintf(buf, len, "%s -iface %s%s", dst, ifn, fibs);
	else
		return (-1);
	return (0);
}

/* The variables a write sets, by name. */
struct wvar {
	char	 name[256];
	char	 value[512];
};

static bool
wv_has(const struct wvar *v, size_t n, const char *name)
{

	for (size_t i = 0; i < n; i++)
		if (strcmp(v[i].name, name) == 0)
			return (true);
	return (false);
}

/*
 * A family's routes of FIB fib, written: each variable set in place
 * where it is, the ones Arcana wrote before and no longer needs taken
 * out; so writing the same twice leaves the bytes as they were.
 */
static int
write_family(struct vc_file *f, int fib, int af, const yr4 *rv, size_t n,
    char *err, size_t errlen)
{
	const char *pre = af == AF_INET ? "" : "ipv6_";
	char list[4096] = "", var[256], dvar[64], args[512], name[128];
	const char *dflt = NULL;
	const struct vc_assign *old;
	struct wvar *nv = NULL;
	size_t nn = 0;
	int error = 0;

	if (fib == 0)
		snprintf(dvar, sizeof(dvar), "%sdefaultrouter", pre);
	else
		snprintf(dvar, sizeof(dvar), "%sdefaultrouter_fib%d", pre, fib);
	if ((nv = calloc(n * 8 + 1, sizeof(*nv))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < n && error == 0; i++) {
		const yr4 *r = &rv[i];
		const ynh4 *nh = r->next_hop;
		const char *only = r->description != NULL && strncmp(
		    r->description, ONLY_WITH, strlen(ONLY_WITH)) == 0 ?
		    r->description + strlen(ONLY_WITH) : NULL;
		size_t hops = nh->next_hop_list != NULL ?
		    nh->next_hop_list->next_hop.n : 1;

		/* A default by an address alone: the default router. */
		if (nh->next_hop_list == NULL && only == NULL &&
		    !nh->has_special_next_hop &&
		    nh->next_hop_address != NULL &&
		    nh->outgoing_interface == NULL &&
		    strcmp(r->destination_prefix, af == AF_INET ?
		    "0.0.0.0/0" : "::/0") == 0) {
			dflt = nh->next_hop_address;
			continue;
		}
		if (hops > 8) {
			snprintf(err, errlen, "%s: more than 8 next hops",
			    r->destination_prefix);
			error = EINVAL;
			break;
		}
		for (size_t k = 0; k < hops; k++) {
			const char *gw = nh->next_hop_list != NULL ?
			    nh->next_hop_list->next_hop.v[k].next_hop_address :
			    nh->next_hop_address;
			const char *ifn = nh->next_hop_list != NULL ?
			    nh->next_hop_list->next_hop.v[k].outgoing_interface :
			    nh->outgoing_interface;

			if (hop_args(args, sizeof(args), af,
			    r->destination_prefix, gw, ifn,
			    nh->has_special_next_hop && nh->next_hop_list ==
			    NULL ? (int)nh->special_next_hop : -1, fib) ==
			    -1) {
				snprintf(err, errlen, "%s: route(8) has no "
				    "route of that next hop",
				    r->destination_prefix);
				error = EINVAL;
				break;
			}
			route_name(name, sizeof(name), r->destination_prefix,
			    hops > 1 ? k + 1 : 0);
			varname(nv[nn].name, sizeof(nv[nn].name), af ==
			    AF_INET ? "route_" : "ipv6_route_", name);
			strlcpy(nv[nn].value, args, sizeof(nv[nn].value));
			nn++;
			snprintf(list + strlen(list), sizeof(list) -
			    strlen(list), "%s%s%s%s", list[0] != '\0' ? " " :
			    "", name, only != NULL ? ":" : "", only != NULL ?
			    only : "");
		}
	}
	/* Set, each where it is. */
	for (size_t i = 0; i < nn && error == 0; i++)
		error = put(f, nv[i].name, nv[i].value, err, errlen);
	/* What Arcana wrote before and does not now: out. */
	snprintf(var, sizeof(var), "%sstatic_routes", pre);
	if (error == 0 && (old = vc_get(f, var)) != NULL &&
	    old->value != NULL) {
		char *copy = strdup(old->value), *p, *w;

		if (copy == NULL)
			error = ENOMEM;
		for (p = copy; error == 0 && (w = strsep(&p, " \t")) != NULL; ) {
			char ov[256], *colon = strchr(w, ':');

			if (*w == '\0')
				continue;
			if (colon != NULL)
				*colon = '\0';
			varname(ov, sizeof(ov), af == AF_INET ? "route_" :
			    "ipv6_route_", w);
			if (!wv_has(nv, nn, ov) && vc_unset(f, ov, err,
			    errlen) == -1)
				error = errno;
		}
		free(copy);
	}
	free(nv);
	if (error != 0)
		return (error);
	if ((list[0] == '\0' ? vc_unset(f, var, err, errlen) : vc_set(f, var,
	    list, err, errlen)) == -1)
		return (errno);
	if ((dflt == NULL ? vc_unset(f, dvar, err, errlen) : vc_set(f, dvar,
	    dflt, err, errlen)) == -1)
		return (errno);
	return (0);
}

int
rcr_write(struct vc_file *f, int fib, const ysr *sr, char *err,
    size_t errlen)
{
	int error;

	if ((error = write_family(f, fib, AF_INET, sr->v4ur_ipv4 != NULL ?
	    sr->v4ur_ipv4->route.v : NULL, sr->v4ur_ipv4 != NULL ?
	    sr->v4ur_ipv4->route.n : 0, err, errlen)) != 0)
		return (error);
	return (write_family(f, fib, AF_INET6, sr->v6ur_ipv6 != NULL ?
	    (const yr4 *)(const void *)sr->v6ur_ipv6->route.v : NULL,
	    sr->v6ur_ipv6 != NULL ? sr->v6ur_ipv6->route.n : 0, err,
	    errlen));
}
