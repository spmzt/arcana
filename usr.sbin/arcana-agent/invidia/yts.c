/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: what the host says of a packet, as YANG, arcana-troubleshoot
 * (PLAN-SDN-YANG 3.1.10): the path-check operation's JSON (pathcheck.c)
 * as the path-check action's output, the traceroute operation's
 * (network.c) as traceroute's, the capture operation's (capture.c) as
 * capture's, each read back into the module's structs.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

typedef struct arcana_troubleshoot_troubleshoot_path_check_output ypath;
typedef struct arcana_troubleshoot_troubleshoot_path_check_output_firewall_in ywalk;
typedef struct arcana_troubleshoot_troubleshoot_path_check_output_firewall_in_step ystep;
typedef struct arcana_troubleshoot_troubleshoot_path_check_output_firewall_in_uncertain yunsure;

/* An address into a union of ip-address-no-zone (v4 first, v6 after). */
static bool
addr_union(cbl_yarena *a, const ucl_object_t *o, const char *key, void *u)
{
	struct arcana_troubleshoot_troubleshoot_path_check_output_address_address
	    *s = u;
	const char *v;

	if ((v = yj_str(a, o, key)) == NULL)
		return (false);
	s->which = strchr(v, ':') != NULL ? 1 : 0;
	s->v.m0 = v;
	return (true);
}

static const char *const verdicts[] = { "allow", "deny", "fwd", "nat",
    "pipe", "divert", "unknown", "none" };

/* One walk; the four walks have one layout. */
static int
walk_of(cbl_yarena *a, const ucl_object_t *o, const ywalk **outp)
{
	ywalk			*w;
	ystep			*st;
	yunsure			*un;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*v;
	size_t			 i, n;

	*outp = NULL;
	if (o == NULL)
		return (0);
	if ((w = cbl_yarena_alloc(a, sizeof(*w))) == NULL)
		return (ENOMEM);
	memset(w, 0, sizeof(*w));
	if ((v = yj_str(a, o, "verdict")) != NULL) {
		w->has_verdict = true;
		w->verdict =
		    ARCANA_TROUBLESHOOT_TROUBLESHOOT_PATH_CHECK_OUTPUT_FIREWALL_IN_VERDICT_OTHER;
		for (i = 0; i < nitems(verdicts); i++)
			if (strcmp(v, verdicts[i]) == 0)
				w->verdict = (int)i;
	}
	YJ_NUM(o, "rule", w, rule);
	w->text = yj_str(a, o, "text");
	w->by_state = yj_yes(o, "by_state", &w->has_by_state);
	w->keep_state = yj_yes(o, "keep_state", &w->has_keep_state);
	YJ_NUM(o, "setfib", w, setfib);
	w->fwd = yj_str(a, o, "fwd");
	w->note = yj_str(a, o, "note");
	if ((st = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(o, "walk"))
	    + 1) * sizeof(*st))) == NULL || (un = cbl_yarena_alloc(a,
	    (yj_count(ucl_object_lookup(o, "uncertain")) + 1) *
	    sizeof(*un))) == NULL)
		return (ENOMEM);
	n = 0;
	YJ_EACH(ucl_object_lookup(o, "walk"), it, e) {
		memset(&st[n], 0, sizeof(st[n]));
		YJ_NUM(e, "rule", &st[n], rule);
		st[n].text = yj_str(a, e, "text");
		st[n].how = yj_str(a, e, "how");
		n++;
	}
	w->step.n = n;
	w->step.v = st;
	n = 0;
	YJ_EACH(ucl_object_lookup(o, "uncertain"), it, e) {
		memset(&un[n], 0, sizeof(un[n]));
		un[n].text = yj_str(a, e, "text");
		un[n].because = yj_str(a, e, "because");
		n++;
	}
	w->uncertain.n = n;
	w->uncertain.v = un;
	*outp = w;
	return (0);
}

int
yts_path_from_json(const char *json, cbl_yarena *a, ypath *out)
{
	struct arcana_troubleshoot_troubleshoot_path_check_output_address	*ad;
	struct arcana_troubleshoot_troubleshoot_path_check_output_source	*src;
	struct arcana_troubleshoot_troubleshoot_path_check_output_destination	*dst;
	struct arcana_troubleshoot_troubleshoot_path_check_output_ingress	*in;
	struct arcana_troubleshoot_troubleshoot_path_check_output_route	*rt;
	struct arcana_troubleshoot_troubleshoot_path_check_output_neighbor	*nb;
	struct arcana_troubleshoot_troubleshoot_path_check_output_return	*ret;
	struct arcana_troubleshoot_troubleshoot_path_check_output_firewall	*fw;
	struct arcana_troubleshoot_troubleshoot_path_check_output_finding	*fd;
	const ucl_object_t	*e, *o;
	ucl_object_iter_t	 it;
	ucl_object_t		*top;
	const char		*v;
	size_t			 n;
	int			 error = ENOMEM;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->host = yj_str(a, top, "host");
	if ((ad = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "addresses")) + 1) * sizeof(*ad))) == NULL)
		goto out;
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "addresses"), it, e) {
		memset(&ad[n], 0, sizeof(ad[n]));
		ad[n].has_address = addr_union(a, e, "address", &ad[n].address);
		YJ_NUM(e, "prefixlen", &ad[n], prefix_length);
		ad[n].interface = yj_str(a, e, "interface");
		YJ_NUM(e, "fib", &ad[n], fib);
		ad[n].up = yj_yes(e, "up", &ad[n].has_up);
		n++;
	}
	out->address.n = n;
	out->address.v = ad;
	if ((o = ucl_object_lookup(top, "src")) != NULL) {
		if ((src = cbl_yarena_alloc(a, sizeof(*src))) == NULL)
			goto out;
		memset(src, 0, sizeof(*src));
		src->local = yj_yes(o, "local", &src->has_local);
		src->connected = yj_str(a, o, "connected");
		out->source = src;
	}
	if ((o = ucl_object_lookup(top, "dst")) != NULL) {
		if ((dst = cbl_yarena_alloc(a, sizeof(*dst))) == NULL)
			goto out;
		memset(dst, 0, sizeof(*dst));
		dst->local = yj_yes(o, "local", &dst->has_local);
		dst->connected = yj_str(a, o, "connected");
		out->destination = dst;
	}
	out->forwarding = yj_yes(top, "forwarding", &out->has_forwarding);
	if ((o = ucl_object_lookup(top, "ingress")) != NULL) {
		if ((in = cbl_yarena_alloc(a, sizeof(*in))) == NULL)
			goto out;
		in->interface = yj_str(a, o, "interface");
		in->how = yj_str(a, o, "how");
		out->ingress = in;
	}
	YJ_NUM(top, "fib", out, fib);
	if ((o = ucl_object_lookup(top, "route")) != NULL) {
		int64_t	f;

		if ((rt = cbl_yarena_alloc(a, sizeof(*rt))) == NULL)
			goto out;
		memset(rt, 0, sizeof(*rt));
		rt->has_destination = addr_union(a, o, "destination",
		    &rt->destination);
		YJ_NUM(o, "prefixlen", rt, prefix_length);
		rt->gateway = yj_str(a, o, "gateway");
		rt->interface = yj_str(a, o, "interface");
		/* The route's fib is printed as a string. */
		if ((v = yj_str(a, o, "fib")) != NULL) {
			rt->has_fib = true;
			rt->fib = (uint16_t)strtoul(v, NULL, 10);
		} else if (yj_num(o, "fib", &f)) {
			rt->has_fib = true;
			rt->fib = (uint16_t)f;
		}
		rt->flags = yj_str(a, o, "flags");
		out->route = rt;
	}
	if ((o = ucl_object_lookup(top, "neighbor")) != NULL) {
		if ((nb = cbl_yarena_alloc(a, sizeof(*nb))) == NULL)
			goto out;
		memset(nb, 0, sizeof(*nb));
		nb->has_address = addr_union(a, o, "address", &nb->address);
		nb->state = yj_str(a, o, "state");
		out->neighbor = nb;
	}
	if ((o = ucl_object_lookup(top, "return")) != NULL) {
		if ((ret = cbl_yarena_alloc(a, sizeof(*ret))) == NULL)
			goto out;
		memset(ret, 0, sizeof(*ret));
		YJ_NUM(o, "fib", ret, fib);
		ret->interface = yj_str(a, o, "interface");
		ret->gateway = yj_str(a, o, "gateway");
		ret->symmetric = yj_yes(o, "symmetric", &ret->has_symmetric);
		out->return_ = ret;
	}
	if ((o = ucl_object_lookup(top, "firewall")) != NULL) {
		if ((fw = cbl_yarena_alloc(a, sizeof(*fw))) == NULL)
			goto out;
		memset(fw, 0, sizeof(*fw));
		fw->on = yj_yes(o, "on", &fw->has_on);
		if ((error = walk_of(a, ucl_object_lookup(o, "in"), &fw->in)) !=
		    0 || (error = walk_of(a, ucl_object_lookup(o, "out"),
		    (const ywalk **)&fw->out)) != 0 || (error = walk_of(a,
		    ucl_object_lookup(o, "reply_in"), (const ywalk **)
		    &fw->reply_in)) != 0 || (error = walk_of(a,
		    ucl_object_lookup(o, "reply_out"), (const ywalk **)
		    &fw->reply_out)) != 0)
			goto out;
		out->firewall = fw;
	}
	out->delivered = yj_yes(top, "delivered", &out->has_delivered);
	error = ENOMEM;
	if ((fd = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "findings")) + 1) * sizeof(*fd))) == NULL)
		goto out;
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "findings"), it, e) {
		memset(&fd[n], 0, sizeof(fd[n]));
		if ((v = yj_str(a, e, "severity")) != NULL) {
			fd[n].has_severity = true;
			fd[n].severity = strcmp(v, "bad") == 0 ?
			    ARCANA_TROUBLESHOOT_TROUBLESHOOT_PATH_CHECK_OUTPUT_FINDING_SEVERITY_BAD :
			    strcmp(v, "warn") == 0 ?
			    ARCANA_TROUBLESHOOT_TROUBLESHOOT_PATH_CHECK_OUTPUT_FINDING_SEVERITY_WARN :
			    strcmp(v, "info") == 0 ?
			    ARCANA_TROUBLESHOOT_TROUBLESHOOT_PATH_CHECK_OUTPUT_FINDING_SEVERITY_INFO :
			    ARCANA_TROUBLESHOOT_TROUBLESHOOT_PATH_CHECK_OUTPUT_FINDING_SEVERITY_OK;
		}
		fd[n].what = yj_str(a, e, "what");
		n++;
	}
	out->finding.n = n;
	out->finding.v = fd;
	error = 0;
out:
	ucl_object_unref(top);
	return (error);
}

/* A double of o's as a decimal64 of 3 fraction digits. */
static bool
dec3(const ucl_object_t *o, const char *key, int64_t *v)
{
	const ucl_object_t	*e;

	if ((e = ucl_object_lookup(o, key)) == NULL || (ucl_object_type(e) !=
	    UCL_FLOAT && ucl_object_type(e) != UCL_INT))
		return (false);
	*v = (int64_t)(ucl_object_todouble(e) * 1000.0 + 0.5);
	return (true);
}

int
yts_traceroute_from_json(const char *json, cbl_yarena *a,
    struct arcana_troubleshoot_troubleshoot_traceroute_output *out)
{
	struct arcana_troubleshoot_troubleshoot_traceroute_output_hop	*h;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*top;
	const char		*v;
	int64_t			 ttl;
	size_t			 n = 0;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->has_address = addr_union(a, top, "address", &out->address);
	if ((v = yj_str(a, top, "family")) != NULL) {
		out->has_family = true;
		out->family = strcmp(v, "inet6") == 0 ?
		    ARCANA_TROUBLESHOOT_TROUBLESHOOT_TRACEROUTE_OUTPUT_FAMILY_IPV6 :
		    ARCANA_TROUBLESHOOT_TROUBLESHOOT_TRACEROUTE_OUTPUT_FAMILY_IPV4;
	}
	out->reached = yj_yes(top, "reached", &out->has_reached);
	if ((h = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top, "hops"))
	    + 1) * sizeof(*h))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "hops"), it, e) {
		if (!yj_num(e, "ttl", &ttl))
			continue;
		memset(&h[n], 0, sizeof(h[n]));
		h[n].ttl = (uint8_t)ttl;
		h[n].has_address = addr_union(a, e, "address", &h[n].address);
		h[n].has_rtt = dec3(e, "rtt", &h[n].rtt);
		h[n].note = yj_str(a, e, "note");
		h[n].lost = yj_yes(e, "lost", &h[n].has_lost);
		n++;
	}
	out->hop.n = n;
	out->hop.v = h;
	ucl_object_unref(top);
	return (0);
}

/* Base64, as capture writes its pcap, decoded into the arena. */
static bool
b64(cbl_yarena *a, const char *s, struct cbl_bytes *out)
{
	static const char	tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789+/";
	uint8_t			*p;
	const char		*q;
	size_t			 n = 0;
	unsigned		 acc = 0;
	int			 bits = 0;

	if ((p = cbl_yarena_alloc(a, strlen(s) * 3 / 4 + 3)) == NULL)
		return (false);
	for (; *s != '\0' && *s != '='; s++) {
		if ((q = strchr(tbl, *s)) == NULL)
			continue;
		acc = acc << 6 | (unsigned)(q - tbl);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			p[n++] = (uint8_t)(acc >> bits);
			acc &= (1u << bits) - 1;
		}
	}
	out->p = p;
	out->len = n;
	return (true);
}

int
yts_capture_from_json(const char *json, cbl_yarena *a,
    struct arcana_troubleshoot_troubleshoot_capture_output *out)
{
	ucl_object_t	*top;
	const char	*v;
	char		 buf[32];
	struct tm	 tm;
	time_t		 now;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->source = yj_str(a, top, "source");
	out->filter = yj_str(a, top, "filter");
	if (yj_strs(a, ucl_object_lookup(top, "lines"), &out->line.n,
	    &out->line.v) != 0) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_NUM(top, "packets", out, packets);
	YJ_NUM(top, "limit", out, limit);
	YJ_NUM(top, "seconds", out, seconds);
	out->timed_out = yj_yes(top, "timed_out", &out->has_timed_out);
	YJ_NUM(top, "bytes", out, bytes);
	if ((v = yj_str(a, top, "pcap")) != NULL && !b64(a, v, &out->pcap)) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	/* When: now, as the reply is made of a capture just ended. */
	now = time(NULL);
	if (gmtime_r(&now, &tm) != NULL && strftime(buf, sizeof(buf),
	    "%Y-%m-%dT%H:%M:%SZ", &tm) > 0) {
		char	*t;

		if ((t = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL) {
			memcpy(t, buf, strlen(buf) + 1);
			out->taken = t;
		}
	}
	ucl_object_unref(top);
	return (0);
}
