/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The host's network tables, as netstat(1) and sockstat(1) print them
 * with --libxo json.  One address family is the program's own output;
 * both families are two runs, one per family (netstat -o needs one),
 * with the second's entries appended to the first's array.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

#include "agent.h"

static int	run_kind(struct work *, uint8_t, uint8_t, uint32_t,
		    struct execres *);
static ucl_object_t *parse(const char *, size_t);
static const char *array_path(uint8_t);
static int	routes_scan(struct work *, uint8_t, const char *, uint32_t,
		    struct arc_network_rsp *);

/* The program for kind, for one family (never ARC_NET_FAMILY_ALL). */
static int
run_kind(struct work *w, uint8_t kind, uint8_t family, uint32_t fib,
    struct execres *res)
{
	char	*argv[11];
	int	 i;

	i = 0;
	if (kind == ARC_NET_KIND_SOCKETS) {
		argv[i++] = (char *)(uintptr_t)opts.sockstat_bin;
		argv[i++] = (char *)(uintptr_t)"--libxo";
		argv[i++] = (char *)(uintptr_t)"json";
		argv[i++] = (char *)(uintptr_t)"-w";
		argv[i++] = (char *)(uintptr_t)(family == ARC_NET_FAMILY_INET ?
		    "-4" : "-6");
	} else {
		argv[i++] = (char *)(uintptr_t)opts.netstat_bin;
		argv[i++] = (char *)(uintptr_t)"--libxo";
		argv[i++] = (char *)(uintptr_t)"json";
		argv[i++] = (char *)(uintptr_t)(kind == ARC_NET_KIND_ROUTES ?
		    "-rnW" : kind == ARC_NET_KIND_NEXTHOPS ? "-onW" : "-nW");
		argv[i++] = (char *)(uintptr_t)"-f";
		argv[i++] = (char *)(uintptr_t)(family == ARC_NET_FAMILY_INET ?
		    "inet" : "inet6");
		if (fib != 0 && kind != ARC_NET_KIND_CONNECTIONS) {
			argv[i++] = (char *)(uintptr_t)"-F";
			argv[i++] = wfmt(w, "%u", fib);
		}
	}
	argv[i] = NULL;
	/* The whole table, not the 256 KB a trace step keeps. */
	return (run_exec_max(w, argv, res, ARC_MAX_JSON));
}

static ucl_object_t *
parse(const char *s, size_t len)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_chunk(p, (const unsigned char *)s, len))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

/* Where the entries of each kind live, to join two families' output. */
static const char *
array_path(uint8_t kind)
{

	switch (kind) {
	case ARC_NET_KIND_ROUTES:
		return ("statistics.route-information.route-table.rt-family");
	case ARC_NET_KIND_NEXTHOPS:
		return ("statistics.route-nhop-information.nhop-table."
		    "rt-family");
	case ARC_NET_KIND_CONNECTIONS:
		return ("statistics.socket");
	default:
		return ("sockstat.socket");
	}
}

/*
 * A routing table too large to send, or one to search: netstat(1)'s
 * plain listing is read line by line, nothing of it kept but the rows
 * wanted, up to ROUTES_MAX of them.  The reply has the shape of the
 * libxo document, so that it is shown the same, with how many rows the
 * table has and whether more matched than were sent.
 */
#define	ROUTES_MAX	2000

struct scan {
	ucl_object_t	*entries;	/* of the family being read */
	const char	*filter;
	const uint8_t	*cover;		/* keep the rows this address is in */
	int		 af;		/* its family */
	size_t		 max;		/* rows kept at most */
	uint64_t	 total;
	size_t		 kept;
	bool		 body;		/* past the header line */
	bool		 truncated;
};

/*
 * The length of the prefix of the route a line of netstat -rn starts
 * with, when the address is inside it; -1 when it is not, or when the
 * line's destination is not of the family.
 */
static int
covers(const char *line, int af, const uint8_t *addr)
{
	uint8_t		 net[16];
	const char	*errstr;
	char		 dest[80], *slash, *zone;
	size_t		 len;
	int		 plen, max, i;

	len = strcspn(line, " \t");
	if (len == 0 || len >= sizeof(dest))
		return (-1);
	memcpy(dest, line, len);
	dest[len] = '\0';
	if (strcmp(dest, "default") == 0)
		return (0);
	max = af == AF_INET ? 32 : 128;
	plen = max;
	if ((slash = strchr(dest, '/')) != NULL) {
		*slash = '\0';
		plen = (int)strtonum(slash + 1, 0, max, &errstr);
		if (errstr != NULL)
			return (-1);
	}
	if ((zone = strchr(dest, '%')) != NULL)
		*zone = '\0';
	if (inet_pton(af, dest, net) != 1)
		return (-1);
	for (i = 0; i < plen / 8; i++)
		if (net[i] != addr[i])
			return (-1);
	if (plen % 8 != 0 && ((net[i] ^ addr[i]) & (0xff << (8 - plen % 8))) !=
	    0)
		return (-1);
	return (plen);
}

static void
scan_line(const char *line, void *arg)
{
	struct scan	*sc;
	ucl_object_t	*e;
	char		*copy, *f[8], *p, *tok;
	int		 n, plen;

	sc = arg;
	if (!sc->body) {
		sc->body = strncmp(line, "Destination", 11) == 0;
		return;
	}
	if (line[0] == '\0')
		return;
	sc->total++;
	if (sc->filter != NULL && strstr(line, sc->filter) == NULL)
		return;
	plen = -1;
	if (sc->cover != NULL && (plen = covers(line, sc->af, sc->cover)) < 0)
		return;
	if (sc->kept == sc->max) {
		sc->truncated = true;
		return;
	}
	if ((copy = strdup(line)) == NULL)
		err(1, "strdup");
	n = 0;
	p = copy;
	while (n < 8 && (tok = strsep(&p, " \t")) != NULL)
		if (tok[0] != '\0')
			f[n++] = tok;
	/* Destination Gateway Flags Nhop# Mtu Netif [Metric] [Expire] */
	if (n >= 6) {
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromstring(f[0]),
		    "destination", 0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(f[1]),
		    "gateway", 0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(f[2]), "flags",
		    0, false);
		ucl_object_insert_key(e, ucl_object_fromint(strtoll(f[3], NULL,
		    10)), "nhop", 0, false);
		ucl_object_insert_key(e, ucl_object_fromint(strtoll(f[4], NULL,
		    10)), "mtu", 0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(f[5]),
		    "interface-name", 0, false);
		if (n == 8)
			ucl_object_insert_key(e, ucl_object_fromstring(f[7]),
			    "expire-time", 0, false);
		if (plen >= 0)
			ucl_object_insert_key(e, ucl_object_fromint(plen),
			    "prefixlen", 0, false);
		ucl_array_append(sc->entries, e);
		sc->kept++;
	}
	free(copy);
}

static int
routes_scan(struct work *w, uint8_t family, const char *filter, uint32_t fib,
    struct arc_network_rsp *rsp)
{
	static const struct {
		uint8_t		 family;
		const char	*arg, *name;
	} fams[] = {
		{ ARC_NET_FAMILY_INET, "inet", "Internet" },
		{ ARC_NET_FAMILY_INET6, "inet6", "Internet6" },
	};
	struct scan	 sc;
	ucl_object_t	*top, *st, *ri, *rt, *arr, *fo;
	unsigned char	*json;
	char		*argv[7];
	size_t		 i;
	bool		 any;

	memset(&sc, 0, sizeof(sc));
	sc.filter = filter;
	sc.max = ROUTES_MAX;
	arr = ucl_object_typed_new(UCL_ARRAY);
	any = false;
	for (i = 0; i < nitems(fams); i++) {
		if (family != ARC_NET_FAMILY_ALL && family != fams[i].family)
			continue;
		sc.entries = ucl_object_typed_new(UCL_ARRAY);
		sc.body = false;
		argv[0] = (char *)(uintptr_t)opts.netstat_bin;
		argv[1] = (char *)(uintptr_t)"-rnW";
		argv[2] = (char *)(uintptr_t)"-f";
		argv[3] = (char *)(uintptr_t)fams[i].arg;
		argv[4] = fib != 0 ? (char *)(uintptr_t)"-F" : NULL;
		argv[5] = fib != 0 ? wfmt(w, "%u", fib) : NULL;
		argv[6] = NULL;
		if (run_exec_lines(w, argv, scan_line, &sc) != 0) {
			ucl_object_unref(sc.entries);
			continue;
		}
		any = true;
		fo = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(fo, ucl_object_fromstring(fams[i].name),
		    "address-family", 0, false);
		ucl_object_insert_key(fo, sc.entries, "rt-entry", 0, false);
		ucl_array_append(arr, fo);
	}
	if (!any) {
		ucl_object_unref(arr);
		rsp->error = "netstat could not list the routes";
		return (0);
	}
	rt = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(rt, arr, "rt-family", 0, false);
	ri = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(ri, rt, "route-table", 0, false);
	st = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(st, ri, "route-information", 0, false);
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, st, "statistics", 0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "cannot build the reply";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->has_total = true;
	rsp->total = sc.total;
	rsp->truncated = sc.truncated;
	rsp->ok = true;
	return (0);
}

int
do_network(struct work *w, uint8_t kind, uint8_t family, const char *filter,
    uint32_t fib, struct arc_network_rsp *rsp)
{
	struct execres		 res, res6;
	ucl_object_t		*o, *o6, *dst, *e;
	const ucl_object_t	*src;
	ucl_object_iter_t	 it;
	unsigned char		*json;
	bool			 ok4, ok6;

	/* The interfaces are read here, not printed by a program. */
	if (kind == ARC_NET_KIND_INTERFACES)
		return (do_interfaces(w, family, rsp));
	if (kind == ARC_NET_KIND_NETGRAPH)
		return (do_netgraph(w, rsp));
	if (kind == ARC_NET_KIND_WIREGUARD)
		return (do_wireguard(w, rsp));
	if (kind == ARC_NET_KIND_BIRD)
		return (do_bird(w, rsp));
	if (kind == ARC_NET_KIND_BIRD_ROUTES)
		return (do_bird_routes(w, filter, rsp));
	rsp->has_ok = true;
	rsp->ok = false;
	/* Searched for on the host: read line by line from the start. */
	if (kind == ARC_NET_KIND_ROUTES && filter != NULL && filter[0] != '\0')
		return (routes_scan(w, family, filter, fib, rsp));
	if (family != ARC_NET_FAMILY_ALL) {
		if (run_kind(w, kind, family, fib, &res) != 0) {
			rsp->error = wtext(w, exec_error(w, &res,
			    kind == ARC_NET_KIND_SOCKETS ? "sockstat" :
			    "netstat"));
			return (0);
		}
		if (res.truncated) {
			if (kind == ARC_NET_KIND_ROUTES)
				return (routes_scan(w, family, NULL, fib, rsp));
			rsp->error = wfmt(w, "the table is larger than the %d "
			    "bytes a reply carries; narrow it to one family or "
			    "ask the host directly", ARC_MAX_JSON);
			return (0);
		}
		rsp->json = wtext(w, res.out);
		rsp->ok = true;
		return (0);
	}

	/* Both families: a run each; a family the kernel lacks is skipped. */
	ok4 = run_kind(w, kind, ARC_NET_FAMILY_INET, fib, &res) == 0;
	ok6 = run_kind(w, kind, ARC_NET_FAMILY_INET6, fib, &res6) == 0;
	if (!ok4 && !ok6) {
		rsp->error = wtext(w, exec_error(w, &res,
		    kind == ARC_NET_KIND_SOCKETS ? "sockstat" : "netstat"));
		return (0);
	}
	if ((ok4 && res.truncated) || (ok6 && res6.truncated)) {
		if (kind == ARC_NET_KIND_ROUTES)
			return (routes_scan(w, family, NULL, fib, rsp));
		rsp->error = wfmt(w, "the table is larger than the %d bytes a "
		    "reply carries; ask for one family", ARC_MAX_JSON);
		return (0);
	}
	o = ok4 ? parse(res.out, res.outlen) : NULL;
	o6 = ok6 ? parse(res6.out, res6.outlen) : NULL;
	if (o == NULL && o6 == NULL) {
		rsp->error = "the program's output is not JSON";
		return (0);
	}
	if (o != NULL && o6 != NULL) {
		dst = (ucl_object_t *)(uintptr_t)ucl_object_lookup_path(o,
		    array_path(kind));
		src = ucl_object_lookup_path(o6, array_path(kind));
		it = NULL;
		while (dst != NULL && ucl_object_type(dst) == UCL_ARRAY &&
		    (e = (ucl_object_t *)(uintptr_t)ucl_object_iterate(src, &it,
		    true)) != NULL)
			ucl_array_append(dst, ucl_object_ref(e));
		if (dst == NULL) {
			/* Nothing on the inet side: take the inet6 document. */
			ucl_object_unref(o);
			o = o6;
			o6 = NULL;
		}
	} else if (o == NULL) {
		o = o6;
		o6 = NULL;
	}
	if (o6 != NULL)
		ucl_object_unref(o6);
	json = ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	if (json == NULL) {
		rsp->error = "cannot build the reply";
		return (0);
	}
	if (strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		if (kind == ARC_NET_KIND_ROUTES)
			return (routes_scan(w, family, NULL, fib, rsp));
		rsp->error = wfmt(w, "the tables are larger than the %d bytes "
		    "a reply carries", ARC_MAX_JSON);
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

/* "   gateway: 10.0.0.1" of route(8) get into best, as "gateway". */
static void
lookup_line(const char *line, void *arg)
{
	static const char *const keys[] = { "route to", "destination", "mask",
	    "gateway", "fib", "interface", "flags" };
	ucl_object_t	*best;
	const char	*p, *colon;
	size_t		 i, len;

	best = arg;
	p = line + strspn(line, " \t");
	if ((colon = strstr(p, ": ")) == NULL)
		return;
	len = (size_t)(colon - p);
	for (i = 0; i < nitems(keys); i++)
		if (strlen(keys[i]) == len && strncmp(p, keys[i], len) == 0) {
			ucl_object_insert_key(best, ucl_object_fromstring(
			    colon + 2), i == 0 ? "to" : keys[i], 0, true);
			return;
		}
}

/*
 * The route to an address: what route(8) get says the kernel would
 * use, and every route of the table the address is in, the most
 * specific first being the same and the rest what would be used in
 * its place.
 */
#define	CANDIDATES_MAX	64

int
do_route_lookup(struct work *w, const char *address, uint32_t fib,
    struct arc_route_lookup_rsp *rsp)
{
	struct scan	 sc;
	ucl_object_t	*top, *best;
	unsigned char	*json;
	uint8_t		 raw[16];
	char		*argv[9];
	int		 af, n;

	rsp->has_ok = true;
	rsp->ok = false;
	if (inet_pton(AF_INET, address, raw) == 1)
		af = AF_INET;
	else if (inet_pton(AF_INET6, address, raw) == 1)
		af = AF_INET6;
	else {
		rsp->error = wfmt(w, "%s is not an IPv4 or IPv6 address",
		    address);
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_fromstring(address), "address", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromstring(af == AF_INET ?
	    "inet" : "inet6"), "family", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(fib), "fib", 0, false);

	best = ucl_object_typed_new(UCL_OBJECT);
	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.route_bin;
	argv[n++] = (char *)(uintptr_t)"-n";
	argv[n++] = (char *)(uintptr_t)"get";
	argv[n++] = (char *)(uintptr_t)(af == AF_INET ? "-inet" : "-inet6");
	argv[n++] = (char *)(uintptr_t)address;
	if (fib != 0) {
		argv[n++] = (char *)(uintptr_t)"-fib";
		argv[n++] = wfmt(w, "%u", fib);
	}
	argv[n] = NULL;
	/* No route is an answer too: route(8) fails, and best stays out. */
	if (run_exec_lines(w, argv, lookup_line, best) == 0 &&
	    ucl_object_lookup(best, "interface") != NULL)
		ucl_object_insert_key(top, best, "best", 0, false);
	else
		ucl_object_unref(best);

	memset(&sc, 0, sizeof(sc));
	sc.entries = ucl_object_typed_new(UCL_ARRAY);
	sc.cover = raw;
	sc.af = af;
	sc.max = CANDIDATES_MAX;
	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.netstat_bin;
	argv[n++] = (char *)(uintptr_t)"-rnW";
	argv[n++] = (char *)(uintptr_t)"-f";
	argv[n++] = (char *)(uintptr_t)(af == AF_INET ? "inet" : "inet6");
	if (fib != 0) {
		argv[n++] = (char *)(uintptr_t)"-F";
		argv[n++] = wfmt(w, "%u", fib);
	}
	argv[n] = NULL;
	(void)run_exec_lines(w, argv, scan_line, &sc);
	ucl_object_insert_key(top, sc.entries, "candidates", 0, false);

	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "cannot build the reply";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

