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

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>
#include <ucl.h>

#include "jailgridd.h"

static int	run_kind(struct work *, uint8_t, uint8_t, struct execres *);
static ucl_object_t *parse(const char *, size_t);
static const char *array_path(uint8_t);

/* The program for kind, for one family (never JG_NET_FAMILY_ALL). */
static int
run_kind(struct work *w, uint8_t kind, uint8_t family, struct execres *res)
{
	char	*argv[9];
	int	 i;

	i = 0;
	if (kind == JG_NET_KIND_SOCKETS) {
		argv[i++] = (char *)(uintptr_t)opts.sockstat_bin;
		argv[i++] = (char *)(uintptr_t)"--libxo";
		argv[i++] = (char *)(uintptr_t)"json";
		argv[i++] = (char *)(uintptr_t)"-w";
		argv[i++] = (char *)(uintptr_t)(family == JG_NET_FAMILY_INET ?
		    "-4" : "-6");
	} else {
		argv[i++] = (char *)(uintptr_t)opts.netstat_bin;
		argv[i++] = (char *)(uintptr_t)"--libxo";
		argv[i++] = (char *)(uintptr_t)"json";
		argv[i++] = (char *)(uintptr_t)(kind == JG_NET_KIND_ROUTES ?
		    "-rnW" : kind == JG_NET_KIND_NEXTHOPS ? "-onW" : "-nW");
		argv[i++] = (char *)(uintptr_t)"-f";
		argv[i++] = (char *)(uintptr_t)(family == JG_NET_FAMILY_INET ?
		    "inet" : "inet6");
	}
	argv[i] = NULL;
	/* The whole table, not the 256 KB a trace step keeps. */
	return (run_exec_max(w, argv, res, JG_MAX_JSON));
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
	case JG_NET_KIND_ROUTES:
		return ("statistics.route-information.route-table.rt-family");
	case JG_NET_KIND_NEXTHOPS:
		return ("statistics.route-nhop-information.nhop-table."
		    "rt-family");
	case JG_NET_KIND_CONNECTIONS:
		return ("statistics.socket");
	default:
		return ("sockstat.socket");
	}
}

int
do_network(struct work *w, uint8_t kind, uint8_t family,
    struct jg_network_rsp *rsp)
{
	struct execres		 res, res6;
	ucl_object_t		*o, *o6, *dst, *e;
	const ucl_object_t	*src;
	ucl_object_iter_t	 it;
	unsigned char		*json;
	bool			 ok4, ok6;

	rsp->has_ok = true;
	rsp->ok = false;
	if (family != JG_NET_FAMILY_ALL) {
		if (run_kind(w, kind, family, &res) != 0) {
			rsp->error = wtext(w, exec_error(w, &res,
			    kind == JG_NET_KIND_SOCKETS ? "sockstat" :
			    "netstat"));
			return (0);
		}
		if (res.truncated) {
			rsp->error = wfmt(w, "the table is larger than the %d "
			    "bytes a reply carries; narrow it to one family or "
			    "ask the host directly", JG_MAX_JSON);
			return (0);
		}
		rsp->json = wtext(w, res.out);
		rsp->ok = true;
		return (0);
	}

	/* Both families: a run each; a family the kernel lacks is skipped. */
	ok4 = run_kind(w, kind, JG_NET_FAMILY_INET, &res) == 0;
	ok6 = run_kind(w, kind, JG_NET_FAMILY_INET6, &res6) == 0;
	if (!ok4 && !ok6) {
		rsp->error = wtext(w, exec_error(w, &res,
		    kind == JG_NET_KIND_SOCKETS ? "sockstat" : "netstat"));
		return (0);
	}
	if ((ok4 && res.truncated) || (ok6 && res6.truncated)) {
		rsp->error = wfmt(w, "the table is larger than the %d bytes a "
		    "reply carries; ask for one family", JG_MAX_JSON);
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
	if (strlen((char *)json) > JG_MAX_JSON) {
		free(json);
		rsp->error = wfmt(w, "the tables are larger than the %d bytes "
		    "a reply carries", JG_MAX_JSON);
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}
