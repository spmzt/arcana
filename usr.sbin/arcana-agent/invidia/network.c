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

#include <ctype.h>
#include <err.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

#include "agent.h"

static int	run_kind(struct work *, uint8_t, uint8_t, uint32_t,
		    struct execres *);
static ucl_object_t *parse(const char *, size_t);
static const char *array_path(uint8_t);
static int	routes_scan(struct work *, uint8_t, const char *, uint32_t,
		    uint32_t, struct arc_network_rsp *);

/* The program for kind, for one family (never ARC_NET_FAMILY_ALL). */
static int
run_kind(struct work *w, uint8_t kind, uint8_t family, uint32_t fib,
    struct execres *res)
{
	char	*argv[11];
	int	 i;

	i = 0;
	{
		argv[i++] = (char *)(uintptr_t)opts.netstat_bin;
		argv[i++] = (char *)(uintptr_t)"--libxo";
		argv[i++] = (char *)(uintptr_t)"json";
		argv[i++] = (char *)(uintptr_t)(kind == ARC_NET_KIND_NEXTHOPS ?
		    "-onW" : kind == ARC_NET_KIND_NHGROUPS ? "-OnW" : "-nW");
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
	case ARC_NET_KIND_NHGROUPS:
		return ("statistics.route-nhgrp-information.nhgrp-table."
		    "rt-family");
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
 * The routing tables, read by the helper through netlink(4), a route
 * a line as a JSON object (nlroute.c).  Nothing of a table is kept but
 * the rows wanted, up to ROUTES_MAX of them, so one of any size is
 * read; the reply says how many routes the table has and whether more
 * were wanted than are sent.  Its shape is that of netstat(1)'s libxo
 * document, the tables of two families in one array.
 */
#define	ROUTES_MAX	2000

struct scan {
	FILE		*out;
	size_t		 max;		/* rows kept at most */
	uint64_t	 skip;		/* of those wanted, left out first */
	uint64_t	 total;
	size_t		 kept;
	bool		 six;		/* the family being read */
	bool		 open;		/* its array is */
	bool		 some;		/* and has a row */
	bool		 truncated;
};

static void
scan_family(struct scan *sc)
{

	if (sc->open)
		fputs("]},", sc->out);
	fprintf(sc->out, "{\"address-family\":\"%s\",\"rt-entry\":[", sc->six ?
	    "Internet6" : "Internet");
	sc->open = true;
	sc->some = false;
}

static void
scan_line(const char *line, void *arg)
{
	struct scan	*sc;

	sc = arg;
	if (strncmp(line, "#total ", 7) == 0) {
		sc->total = strtoull(line + 7, NULL, 10);
		return;
	}
	if (strcmp(line, "#family 6") == 0) {
		sc->six = true;
		scan_family(sc);
		return;
	}
	if (line[0] != '{')
		return;
	/* Read on from where a reply before this one ended. */
	if (sc->skip > 0) {
		sc->skip--;
		return;
	}
	if (sc->kept == sc->max) {
		sc->truncated = true;
		return;
	}
	if (!sc->open)
		scan_family(sc);
	fprintf(sc->out, "%s%s", sc->some ? "," : "", line);
	sc->some = true;
	sc->kept++;
}

static int
routes_scan(struct work *w, uint8_t family, const char *filter, uint32_t fib,
    uint32_t offset, struct arc_network_rsp *rsp)
{
	struct scan	 sc;
	const char	*words[4];
	char		*json;
	size_t		 len;
	int		 rc;

	memset(&sc, 0, sizeof(sc));
	sc.max = ROUTES_MAX;
	sc.skip = offset;
	sc.six = family == ARC_NET_FAMILY_INET6;
	json = NULL;
	if ((sc.out = open_memstream(&json, &len)) == NULL) {
		rsp->error = "cannot build the reply";
		return (0);
	}
	fputs("{\"statistics\":{\"route-information\":{\"route-table\":{"
	    "\"rt-family\":[", sc.out);
	words[0] = family == ARC_NET_FAMILY_INET ? "4" : family ==
	    ARC_NET_FAMILY_INET6 ? "6" : "0";
	words[1] = wfmt(w, "%u", fib);
	words[2] = filter != NULL && filter[0] != '\0' ? filter : "-";
	words[3] = "-";
	rc = helper_lines(w, "routes", 4, words, scan_line, &sc);
	if (!sc.open)
		scan_family(&sc);
	fputs("]}]}}}}", sc.out);
	if (fclose(sc.out) != 0 || json == NULL || rc != 0) {
		free(json);
		rsp->error = "the kernel did not list its routes";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->has_total = true;
	rsp->total = sc.total;
	rsp->truncated = sc.truncated;
	rsp->ok = true;
	return (0);
}

/* The first line given, kept. */
static void
first_line(const char *line, void *arg)
{
	char	**p = arg;

	if (*p == NULL && line[0] == '{')
		*p = strdup(line);
}

/* A row of the connections, sockets or neighbours, into the array. */
struct pscan {
	FILE		*out;
	bool		 some;
	uintmax_t	 total;
};

static void
pcb_line(const char *line, void *arg)
{
	struct pscan	*ps = arg;

	if (strncmp(line, "#total ", 7) == 0)
		ps->total = strtoumax(line + 7, NULL, 10);
	if (line[0] != '{')
		return;
	fprintf(ps->out, "%s%s", ps->some ? "," : "", line);
	ps->some = true;
}

/*
 * The connections or the sockets, read from the kernel (pcb.c), in the
 * shape netstat and sockstat give them with --libxo json; or the
 * neighbours, through netlink (nlroute.c), with their total.
 */
static int
pcb_scan(struct work *w, uint8_t kind, uint8_t family, const char *filter,
    struct arc_network_rsp *rsp)
{
	struct pscan	 ps;
	const char	*words[2];
	char		*json;
	size_t		 len;
	int		 rc;

	json = NULL;
	memset(&ps, 0, sizeof(ps));
	if ((ps.out = open_memstream(&json, &len)) == NULL) {
		rsp->error = "cannot build the reply";
		return (0);
	}
	fputs(kind == ARC_NET_KIND_SOCKETS ? "{\"sockstat\":{\"socket\":[" :
	    kind == ARC_NET_KIND_NEIGHBOURS ? "{\"neighbours\":[" :
	    "{\"statistics\":{\"socket\":[", ps.out);
	words[0] = family == ARC_NET_FAMILY_INET ? "4" : family ==
	    ARC_NET_FAMILY_INET6 ? "6" : "0";
	words[1] = filter != NULL && filter[0] != '\0' ? filter : "-";
	if (kind == ARC_NET_KIND_NEIGHBOURS) {
		rc = helper_lines(w, "route-neighs", 2, words, pcb_line, &ps);
		fprintf(ps.out, "],\"total\":%ju}", ps.total);
	} else {
		rc = helper_lines(w, kind == ARC_NET_KIND_SOCKETS ?
		    "pcb-socks" : "pcb-conns", 1, words, pcb_line, &ps);
		fputs("]}}", ps.out);
	}
	if (fclose(ps.out) != 0 || json == NULL || rc != 0) {
		free(json);
		rsp->error = "the kernel did not list them";
		return (0);
	}
	if (strlen(json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = wfmt(w, "more than the %d bytes a reply carries: "
		    "they come in parts", ARC_MAX_JSON);
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

int
do_network(struct work *w, uint8_t kind, uint8_t family, const char *filter,
    uint32_t fib, uint32_t offset, struct arc_network_rsp *rsp)
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
	if (kind == ARC_NET_KIND_IPSEC)
		return (do_ipsec(w, rsp));
	if (kind == ARC_NET_KIND_BIRD_ROUTES)
		return (do_bird_routes(w, filter, rsp));
	if (kind == ARC_NET_KIND_BRIDGES || kind == ARC_NET_KIND_GENEVE)
		return (do_l2(w, kind == ARC_NET_KIND_GENEVE, rsp));
	if (kind == ARC_NET_KIND_IPFW)
		return (do_ipfw(w, rsp));
	rsp->has_ok = true;
	rsp->ok = false;
	if (kind == ARC_NET_KIND_ROUTES)
		return (routes_scan(w, family, filter, fib, offset, rsp));
	if (kind == ARC_NET_KIND_CONNECTIONS || kind == ARC_NET_KIND_SOCKETS ||
	    kind == ARC_NET_KIND_NEIGHBOURS)
		return (pcb_scan(w, kind, family, filter, rsp));
	if (family != ARC_NET_FAMILY_ALL) {
		if (run_kind(w, kind, family, fib, &res) != 0) {
			rsp->error = wtext(w, exec_error(w, &res,
			    kind == ARC_NET_KIND_SOCKETS ? "sockstat" :
			    "netstat"));
			return (0);
		}
		if (res.truncated) {
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
		rsp->error = wfmt(w, "the tables are larger than the %d bytes "
		    "a reply carries", ARC_MAX_JSON);
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

/* A covering route, a line of the helper's, among the candidates. */
struct cands {
	ucl_object_t	*arr;
	size_t		 max;
};

static void
cand_line(const char *line, void *arg)
{
	struct cands	*c;
	ucl_object_t	*o;

	c = arg;
	if (line[0] != '{' || ucl_array_size(c->arr) >= c->max)
		return;
	if ((o = parse(line, strlen(line))) != NULL)
		ucl_array_append(c->arr, o);
}

/*
 * The route to an address: what the kernel says it would use, and
 * every route of the table the address is in, the most
 * specific first being the same and the rest what would be used in
 * its place.
 */
#define	CANDIDATES_MAX	64

int
do_route_lookup(struct work *w, const char *address, uint32_t fib,
    struct arc_route_lookup_rsp *rsp)
{
	struct cands	 cands;
	char		*got;
	ucl_object_t	*top, *best;
	unsigned char	*json;
	const char	*words[4];
	uint8_t		 raw[16];
	int		 af;

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

	/* No route is an answer too: nothing is said, and best stays out. */
	words[0] = address;
	words[1] = wfmt(w, "%u", fib);
	got = NULL;
	(void)helper_lines(w, "route-get", 2, words, first_line, &got);
	if (got != NULL && (best = parse(got, strlen(got))) != NULL) {
		if (ucl_object_lookup(best, "interface") != NULL)
			ucl_object_insert_key(top, best, "best", 0, false);
		else
			ucl_object_unref(best);
	}
	free(got);
	cands.arr = ucl_object_typed_new(UCL_ARRAY);
	cands.max = CANDIDATES_MAX;
	words[0] = "0";
	words[1] = wfmt(w, "%u", fib);
	words[2] = "-";
	words[3] = address;
	(void)helper_lines(w, "routes", 4, words, cand_line, &cands);
	ucl_object_insert_key(top, cands.arr, "candidates", 0, false);

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


/*
 * One round of traceroute(8) to an address: a probe a hop, numeric, a
 * second's wait.  " 3  10.0.0.1  0.312 ms !H" or " 4  *", a line a hop;
 * the first, "traceroute to …", goes to standard error.
 */
int
do_traceroute(struct work *w, const char *address,
    struct arc_traceroute_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *hops, *h;
	unsigned char	*json;
	char		*argv[10], *text, *line, *p, *tok, *last;
	uint8_t		 raw[16];
	int		 af, ttl;

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
	argv[0] = af == AF_INET ? (char *)(uintptr_t)opts.traceroute_bin :
	    wfmt(w, "%s6", opts.traceroute_bin);
	argv[1] = (char *)(uintptr_t)"-n";
	argv[2] = (char *)(uintptr_t)"-q";
	argv[3] = (char *)(uintptr_t)"1";
	argv[4] = (char *)(uintptr_t)"-w";
	argv[5] = (char *)(uintptr_t)"1";
	argv[6] = (char *)(uintptr_t)"-m";
	argv[7] = (char *)(uintptr_t)"30";
	argv[8] = (char *)(uintptr_t)address;
	argv[9] = NULL;
	if (run_exec(w, argv, &res) != 0 && res.outlen == 0) {
		rsp->error = wtext(w, exec_error(w, &res, "traceroute"));
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_fromstring(address), "address", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromstring(af == AF_INET ?
	    "inet" : "inet6"), "family", 0, false);
	hops = ucl_object_typed_new(UCL_ARRAY);
	text = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
	last = NULL;
	p = text;
	while ((line = strsep(&p, "\n")) != NULL) {
		if ((tok = strsep(&line, " \t")) != NULL && tok[0] == '\0')
			while (line != NULL && (tok = strsep(&line, " \t")) !=
			    NULL && tok[0] == '\0')
				;
		if (tok == NULL || (ttl = atoi(tok)) <= 0)
			continue;
		h = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(h, ucl_object_fromint(ttl), "ttl", 0,
		    false);
		while (line != NULL && (tok = strsep(&line, " \t")) != NULL) {
			if (tok[0] == '\0' || strcmp(tok, "ms") == 0)
				continue;
			if (strcmp(tok, "*") == 0) {
				if (ucl_object_lookup(h, "lost") == NULL)
					ucl_object_insert_key(h,
					    ucl_object_frombool(true), "lost", 0,
					    true);
			}
			else if (tok[0] == '!')
				ucl_object_insert_key(h, ucl_object_fromstring(
				    tok), "note", 0, true);
			else if (inet_pton(af, tok, raw) == 1) {
				if (ucl_object_lookup(h, "address") == NULL)
					ucl_object_insert_key(h,
					    ucl_object_fromstring(tok), "address",
					    0, true);
				last = tok;
			} else if (isdigit((unsigned char)tok[0]) &&
			    ucl_object_lookup(h, "rtt") == NULL)
				ucl_object_insert_key(h, ucl_object_fromdouble(
				    strtod(tok, NULL)), "rtt", 0, true);
		}
		if (ucl_object_lookup(h, "address") == NULL &&
		    ucl_object_lookup(h, "lost") == NULL)
			ucl_object_insert_key(h, ucl_object_frombool(true),
			    "lost", 0, true);
		ucl_array_append(hops, h);
	}
	ucl_object_insert_key(top, hops, "hops", 0, false);
	ucl_object_insert_key(top, ucl_object_frombool(last != NULL &&
	    strcmp(last, address) == 0), "reached", 0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}
