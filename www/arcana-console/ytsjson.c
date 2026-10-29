/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * arcana-firewall's trace and arcana-troubleshoot's path-check,
 * traceroute and capture outputs as the operations gave them, their
 * members in the order the agent wrote them (ipfw.c, pathcheck.c,
 * network.c, capture.c).  Apart from ytshoot.c, which asks for them, so
 * that the agent's tests take a reply there and back.
 */

#include <sys/param.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "ymodel.h"
#include "ytsjson.h"

typedef struct arcana_troubleshoot_troubleshoot_path_check_output ypath;
typedef struct arcana_troubleshoot_troubleshoot_path_check_output_firewall_in
    ywalk;

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		put(o, key, ucl_object_fromstring(v));
}

#define	PUT_NUM(o, key, y, m) do {					\
	if ((y)->has_##m)						\
		put((o), (key), ucl_object_fromint((int64_t)(y)->m));	\
} while (0)

#define	PUT_YES(o, key, y, m) do {					\
	if ((y)->has_##m)						\
		put((o), (key), ucl_object_frombool((y)->m));		\
} while (0)

/* A list's array, its items made by fn; the module's struct, v and n. */
#define	PUT_EACH(o, key, l, fn) do {					\
	ucl_object_t *arr_ = ucl_object_typed_new(UCL_ARRAY);		\
									\
	for (size_t i_ = 0; i_ < (l).n; i_++)				\
		ucl_array_append(arr_, fn(&(l).v[i_]));			\
	put((o), (key), arr_);						\
} while (0)

static ucl_object_t *
packet_of(const struct arcana_firewall_firewall_trace_output_packet *p)
{
	static const char *const dirs[] = { "in", "out" };
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	PUT_NUM(o, "ms", p, ms);
	put_str(o, "verdict", p->verdict);
	if (p->has_family)
		put_str(o, "family", p->family ==
		    ARCANA_FIREWALL_FIREWALL_TRACE_OUTPUT_PACKET_FAMILY_IPV6 ?
		    "inet6" : "inet");
	if (p->has_source)
		put_str(o, "source", p->source.v.m0);
	if (p->has_destination)
		put_str(o, "destination", p->destination.v.m0);
	PUT_NUM(o, "proto", p, proto);
	PUT_NUM(o, "sport", p, sport);
	PUT_NUM(o, "dport", p, dport);
	PUT_NUM(o, "rule", p, rule);
	put_str(o, "interface", p->interface);
	if (p->has_direction && (size_t)p->direction < nitems(dirs))
		put_str(o, "direction", dirs[p->direction]);
	return (o);
}

ucl_object_t *
yts_trace_json(const struct arcana_firewall_firewall_trace_output *out)
{
	ucl_object_t	*top;

	top = ucl_object_typed_new(UCL_OBJECT);
	PUT_EACH(top, "packets", out->packet, packet_of);
	PUT_NUM(top, "seconds", out, seconds);
	PUT_NUM(top, "limit", out, limit);
	return (top);
}

static ucl_object_t *
address_of(const struct arcana_troubleshoot_troubleshoot_path_check_output_address
    *a)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	if (a->has_address)
		put_str(o, "address", a->address.v.m0);
	PUT_NUM(o, "prefixlen", a, prefix_length);
	put_str(o, "interface", a->interface);
	PUT_NUM(o, "fib", a, fib);
	PUT_YES(o, "up", a, up);
	PUT_YES(o, "loopback", a, loopback);
	return (o);
}

/* A side of the packet: is it the host's, and the network it is on. */
static ucl_object_t *
end_of(bool has_local, bool local, const char *connected)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	if (has_local)
		put(o, "local", ucl_object_frombool(local));
	put_str(o, "connected", connected);
	return (o);
}

static ucl_object_t *
step_of(const struct arcana_troubleshoot_troubleshoot_path_check_output_firewall_in_step
    *s)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	PUT_NUM(o, "rule", s, rule);
	put_str(o, "text", s->text);
	put_str(o, "how", s->how);
	return (o);
}

static ucl_object_t *
unsure_of(const struct arcana_troubleshoot_troubleshoot_path_check_output_firewall_in_uncertain
    *u)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "text", u->text);
	put_str(o, "because", u->because);
	return (o);
}

/* One walk of the ruleset; the four have one layout. */
static ucl_object_t *
walk_of(const ywalk *w)
{
	static const char *const verdicts[] = { "allow", "deny", "fwd",
	    "nat", "pipe", "divert", "unknown", "none" };
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	if (w->has_verdict)
		put_str(o, "verdict", (size_t)w->verdict < nitems(verdicts) ?
		    verdicts[w->verdict] : w->action != NULL ? w->action :
		    "other");
	PUT_NUM(o, "rule", w, rule);
	put_str(o, "text", w->text);
	if (w->has_by_state && w->by_state)
		put(o, "by_state", ucl_object_frombool(true));
	if (w->has_keep_state && w->keep_state)
		put(o, "keep_state", ucl_object_frombool(true));
	PUT_NUM(o, "setfib", w, setfib);
	put_str(o, "fwd", w->fwd);
	put_str(o, "note", w->note);
	if (w->step.n > 0)
		PUT_EACH(o, "walk", w->step, step_of);
	if (w->uncertain.n > 0)
		PUT_EACH(o, "uncertain", w->uncertain, unsure_of);
	return (o);
}

static ucl_object_t *
finding_of(const struct arcana_troubleshoot_troubleshoot_path_check_output_finding
    *f)
{
	static const char *const sevs[] = { "bad", "warn", "info", "ok" };
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	if (f->has_severity && (size_t)f->severity < nitems(sevs))
		put_str(o, "severity", sevs[f->severity]);
	put_str(o, "what", f->what);
	return (o);
}

ucl_object_t *
yts_path_json(const ypath *p)
{
	ucl_object_t	*top, *o;
	char		 num[16];

	top = ucl_object_typed_new(UCL_OBJECT);
	put_str(top, "host", p->host);
	PUT_EACH(top, "addresses", p->address, address_of);
	if (p->source != NULL)
		put(top, "src", end_of(p->source->has_local, p->source->local,
		    p->source->connected));
	if (p->destination != NULL)
		put(top, "dst", end_of(p->destination->has_local,
		    p->destination->local, p->destination->connected));
	PUT_YES(top, "forwarding", p, forwarding);
	if (p->ingress != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "interface", p->ingress->interface);
		put_str(o, "how", p->ingress->how);
		put(top, "ingress", o);
	}
	if (p->has_delivered && p->delivered)
		put(top, "delivered", ucl_object_frombool(true));
	/* The route as the agent's route lookup has it, its FIB a string. */
	if (p->route != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "to", p->route->to);
		put_str(o, "destination", p->route->destination);
		PUT_NUM(o, "prefixlen", p->route, prefix_length);
		put_str(o, "gateway", p->route->gateway);
		if (p->route->has_fib) {
			snprintf(num, sizeof(num), "%u", p->route->fib);
			put_str(o, "fib", num);
		}
		put_str(o, "interface", p->route->interface);
		put_str(o, "flags", p->route->flags);
		PUT_NUM(o, "metric", p->route, metric);
		PUT_NUM(o, "weight", p->route, weight);
		put(top, "route", o);
	}
	if (p->neighbor != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		if (p->neighbor->has_address)
			put_str(o, "address", p->neighbor->address.v.m0);
		put_str(o, "state", p->neighbor->state);
		put(top, "neighbor", o);
	}
	if (p->return_ != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		PUT_NUM(o, "fib", p->return_, fib);
		put_str(o, "interface", p->return_->interface);
		put_str(o, "gateway", p->return_->gateway);
		PUT_YES(o, "symmetric", p->return_, symmetric);
		put(top, "return", o);
	}
	if (p->firewall != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		if (p->firewall->has_on)
			put(o, "on", ucl_object_frombool(p->firewall->on));
		/* The four walks have one layout. */
		if (p->firewall->in != NULL)
			put(o, "in", walk_of(p->firewall->in));
		if (p->firewall->out != NULL)
			put(o, "out", walk_of((const void *)p->firewall->out));
		if (p->firewall->reply_in != NULL)
			put(o, "reply_in", walk_of((const void *)
			    p->firewall->reply_in));
		if (p->firewall->reply_out != NULL)
			put(o, "reply_out", walk_of((const void *)
			    p->firewall->reply_out));
		put(top, "firewall", o);
	}
	PUT_NUM(top, "fib", p, fib);
	PUT_EACH(top, "findings", p->finding, finding_of);
	return (top);
}

static ucl_object_t *
hop_of(const struct arcana_troubleshoot_troubleshoot_traceroute_output_hop *h)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "ttl", ucl_object_fromint(h->ttl));
	if (h->has_lost && h->lost)
		put(o, "lost", ucl_object_frombool(true));
	if (h->has_address)
		put_str(o, "address", h->address.v.m0);
	if (h->has_rtt)
		put(o, "rtt", ucl_object_fromdouble((double)h->rtt / 1000));
	put_str(o, "note", h->note);
	return (o);
}

ucl_object_t *
yts_traceroute_json(
    const struct arcana_troubleshoot_troubleshoot_traceroute_output *t)
{
	ucl_object_t	*top;

	top = ucl_object_typed_new(UCL_OBJECT);
	if (t->has_address)
		put_str(top, "address", t->address.v.m0);
	if (t->has_family)
		put_str(top, "family", t->family ==
		    ARCANA_TROUBLESHOOT_TROUBLESHOOT_TRACEROUTE_OUTPUT_FAMILY_IPV6 ?
		    "inet6" : "inet");
	PUT_EACH(top, "hops", t->hop, hop_of);
	put(top, "reached", ucl_object_frombool(t->has_reached &&
	    t->reached));
	return (top);
}

/* Bytes as base64, as capture.c wrote the pcap (EVP_EncodeBlock). */
static char *
base64(const uint8_t *p, size_t len)
{
	static const char	tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789+/";
	char			*s, *q;
	uint32_t		 v;

	if ((s = malloc(4 * ((len + 2) / 3) + 1)) == NULL)
		return (NULL);
	q = s;
	for (size_t i = 0; i < len; i += 3) {
		v = (uint32_t)p[i] << 16 | (i + 1 < len ? (uint32_t)p[i + 1] <<
		    8 : 0) | (i + 2 < len ? p[i + 2] : 0);
		*q++ = tbl[v >> 18 & 63];
		*q++ = tbl[v >> 12 & 63];
		*q++ = i + 1 < len ? tbl[v >> 6 & 63] : '=';
		*q++ = i + 2 < len ? tbl[v & 63] : '=';
	}
	*q = '\0';
	return (s);
}

ucl_object_t *
yts_capture_json(
    const struct arcana_troubleshoot_troubleshoot_capture_output *c)
{
	ucl_object_t	*top, *arr;
	char		*b;

	top = ucl_object_typed_new(UCL_OBJECT);
	/* No interface asked: the sources alone. */
	if (c->source == NULL) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < c->capture_source.n; i++)
			ucl_array_append(arr, ucl_object_fromstring(
			    c->capture_source.v[i]));
		put(top, "sources", arr);
		return (top);
	}
	if (c->pcap.p != NULL && (b = base64(c->pcap.p, c->pcap.len)) !=
	    NULL) {
		put_str(top, "pcap", b);
		free(b);
	}
	PUT_NUM(top, "bytes", c, bytes);
	put_str(top, "source", c->source);
	put_str(top, "filter", c->filter);
	PUT_NUM(top, "packets", c, packets);
	PUT_NUM(top, "limit", c, limit);
	PUT_NUM(top, "seconds", c, seconds);
	PUT_YES(top, "timed_out", c, timed_out);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < c->line.n; i++)
		ucl_array_append(arr, ucl_object_fromstring(c->line.v[i]));
	put(top, "lines", arr);
	return (top);
}
