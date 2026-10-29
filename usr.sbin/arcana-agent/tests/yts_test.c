/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yts: path-check, traceroute and capture as arcana-troubleshoot has
 * them (yts.c), for agent_test.sh.
 *
 *	yts path reply.json		path-check's JSON
 *	yts traceroute reply.json	traceroute's
 *	yts capture reply.json		capture's
 *
 * Through YANG-CBOR and back, the same bytes.
 */

#include "ycommon.h"
#include "ytsjson.h"

static const char *const verdicts[] = { "allow", "deny", "fwd", "nat",
    "pipe", "divert", "unknown", "none", "other" };
static const char *const sevs[] = { "bad", "warn", "info", "ok" };

static void
walk(const char *name,
    const struct arcana_troubleshoot_troubleshoot_path_check_output_firewall_in *w)
{

	if (w == NULL)
		return;
	printf("%s %s rule=%u by-state=%s keep=%s setfib=%d fwd=%s\n", name,
	    w->has_verdict ? verdicts[w->verdict] : "-", w->rule,
	    w->has_by_state && w->by_state ? "yes" : "-", w->has_keep_state &&
	    w->keep_state ? "yes" : "-", w->has_setfib ? w->setfib : -1,
	    str(w->fwd));
	for (size_t i = 0; i < w->step.n; i++)
		printf("  %u %s\n", w->step.v[i].rule, str(w->step.v[i].how));
	for (size_t i = 0; i < w->uncertain.n; i++)
		printf("  ? %s: %s\n", str(w->uncertain.v[i].text), str(
		    w->uncertain.v[i].because));
}

int
main(int argc, char **argv)
{
	cbl_yarena *a;
	int error;

	if (argc != 3)
		errx(2, "usage: yts path|traceroute|capture|back-* reply.json");
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if (strcmp(argv[1], "path") == 0) {
		struct arcana_troubleshoot_troubleshoot_path_check_output p, back;

		if ((error = yts_path_from_json(slurp(argv[2]), a, &p)) != 0)
			errc(1, error, "yts_path_from_json");
		printf("host %s forwarding=%s fib=%d delivered=%s\n", str(p.host),
		    p.has_forwarding ? (p.forwarding ? "yes" : "no") : "-",
		    p.has_fib ? p.fib : -1, p.has_delivered && p.delivered ?
		    "yes" : "-");
		for (size_t i = 0; i < p.address.n; i++)
			printf("address %s/%u %s fib=%d up=%s\n",
			    p.address.v[i].address.v.m0,
			    p.address.v[i].prefix_length, str(
			    p.address.v[i].interface), p.address.v[i].has_fib ?
			    p.address.v[i].fib : -1, p.address.v[i].up ? "yes" :
			    "no");
		if (p.source != NULL)
			printf("source local=%s connected=%s\n", p.source->local ?
			    "yes" : "no", str(p.source->connected));
		if (p.destination != NULL)
			printf("destination local=%s connected=%s\n",
			    p.destination->local ? "yes" : "no", str(
			    p.destination->connected));
		if (p.ingress != NULL)
			printf("ingress %s (%s)\n", str(p.ingress->interface),
			    str(p.ingress->how));
		if (p.route != NULL)
			printf("route %s/%u via %s on %s fib=%d flags=%s\n",
			    str(p.route->destination), p.route->prefix_length,
			    str(p.route->gateway), str(p.route->interface),
			    p.route->has_fib ? p.route->fib : -1,
			    str(p.route->flags));
		if (p.neighbor != NULL)
			printf("neighbor %s %s\n", p.neighbor->has_address ?
			    p.neighbor->address.v.m0 : "-", str(
			    p.neighbor->state));
		if (p.return_ != NULL)
			printf("return fib=%d %s via %s symmetric=%s\n",
			    p.return_->has_fib ? p.return_->fib : -1, str(
			    p.return_->interface), str(p.return_->gateway),
			    p.return_->symmetric ? "yes" : "no");
		if (p.firewall != NULL) {
			printf("firewall on=%s\n", p.firewall->has_on &&
			    p.firewall->on ? "yes" : "no");
			walk("in", p.firewall->in);
			walk("out", (const void *)p.firewall->out);
			walk("reply-in", (const void *)p.firewall->reply_in);
			walk("reply-out", (const void *)p.firewall->reply_out);
		}
		for (size_t i = 0; i < p.finding.n; i++)
			printf("finding %s %s\n", p.finding.v[i].has_severity ?
			    sevs[p.finding.v[i].severity] : "-", str(
			    p.finding.v[i].what));
		same((void *)arcana_troubleshoot_troubleshoot_path_check_output_encode,
		    (void *)arcana_troubleshoot_troubleshoot_path_check_output_decode,
		    &p, &back, a);
	} else if (strcmp(argv[1], "traceroute") == 0) {
		struct arcana_troubleshoot_troubleshoot_traceroute_output t, back;

		if ((error = yts_traceroute_from_json(slurp(argv[2]), a, &t)) !=
		    0)
			errc(1, error, "yts_traceroute_from_json");
		printf("traceroute %s %s reached=%s\n", t.has_address ?
		    t.address.v.m0 : "-", t.has_family ? (t.family == 1 ? "ipv6"
		    : "ipv4") : "-", t.has_reached && t.reached ? "yes" : "no");
		for (size_t i = 0; i < t.hop.n; i++)
			printf("hop %u %s rtt=%jd note=%s lost=%s\n",
			    t.hop.v[i].ttl, t.hop.v[i].has_address ?
			    t.hop.v[i].address.v.m0 : "-", t.hop.v[i].has_rtt ?
			    (intmax_t)t.hop.v[i].rtt : -1, str(t.hop.v[i].note),
			    t.hop.v[i].has_lost && t.hop.v[i].lost ? "yes" : "-");
		same((void *)arcana_troubleshoot_troubleshoot_traceroute_output_encode,
		    (void *)arcana_troubleshoot_troubleshoot_traceroute_output_decode,
		    &t, &back, a);
	} else if (strcmp(argv[1], "capture") == 0) {
		struct arcana_troubleshoot_troubleshoot_capture_output c, back;

		if ((error = yts_capture_from_json(slurp(argv[2]), a, &c)) != 0)
			errc(1, error, "yts_capture_from_json");
		printf("capture %s filter=%s packets=%u limit=%u seconds=%u "
		    "timed-out=%s bytes=%ju pcap=%zu taken=%s\n", str(c.source),
		    str(c.filter), c.packets, c.limit, c.seconds, c.timed_out ?
		    "yes" : "no", (uintmax_t)c.bytes, c.pcap.len, c.taken !=
		    NULL ? "yes" : "-");
		for (size_t i = 0; i < c.line.n; i++)
			printf("line %s\n", c.line.v[i]);
		same((void *)arcana_troubleshoot_troubleshoot_capture_output_encode,
		    (void *)arcana_troubleshoot_troubleshoot_capture_output_decode,
		    &c, &back, a);
	} else if (strncmp(argv[1], "back-", 5) == 0) {
		struct arcana_troubleshoot_troubleshoot_path_check_output p;
		struct arcana_troubleshoot_troubleshoot_traceroute_output t;
		struct arcana_troubleshoot_troubleshoot_capture_output c;
		ucl_object_t *o;
		unsigned char *s;

		/* As the console makes the operation's JSON of the output. */
		if (strcmp(argv[1], "back-path") == 0) {
			if ((error = yts_path_from_json(slurp(argv[2]), a,
			    &p)) != 0)
				errc(1, error, "yts_path_from_json");
			o = yts_path_json(&p);
		} else if (strcmp(argv[1], "back-traceroute") == 0) {
			if ((error = yts_traceroute_from_json(slurp(argv[2]), a,
			    &t)) != 0)
				errc(1, error, "yts_traceroute_from_json");
			o = yts_traceroute_json(&t);
		} else {
			if ((error = yts_capture_from_json(slurp(argv[2]), a,
			    &c)) != 0)
				errc(1, error, "yts_capture_from_json");
			o = yts_capture_json(&c);
		}
		if ((s = ucl_object_emit(o, UCL_EMIT_JSON_COMPACT)) == NULL)
			errx(1, "ucl_object_emit");
		printf("%s\n", (char *)s);
		free(s);
		ucl_object_unref(o);
	} else
		errx(2, "%s: path, traceroute, capture or back-*", argv[1]);
	return (0);
}
