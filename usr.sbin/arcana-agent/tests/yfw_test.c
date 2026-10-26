/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yfw: the firewall as arcana-firewall has it (yfw.c), for
 * agent_test.sh.
 *
 *	yfw read ipfw.json	the network operation's ipfw kind
 *	yfw kept file [sha256]	the kept rules file, as ipfw-rules reads it
 *	yfw trace reply.json	fw-trace's packets, the trace action's output
 *
 * Through YANG-CBOR and back, the same bytes.
 */

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arcana.h>

#include "collect.h"

static char *
slurp(const char *path)
{
	char *buf;
	ssize_t r;
	int fd;

	if ((buf = malloc(1 << 20)) == NULL)
		err(1, "malloc");
	if ((fd = open(path, O_RDONLY)) == -1)
		err(1, "%s", path);
	if ((r = read(fd, buf, (1 << 20) - 1)) < 0)
		err(1, "%s", path);
	close(fd);
	buf[r] = '\0';
	return (buf);
}

static const char *
str(const char *s)
{

	return (s != NULL ? s : "-");
}

static void
same(int (*enc)(const void *, struct cbl_ybuf *),
    int (*dec)(const void *, size_t, void *, cbl_yarena *, int, char *,
    size_t), const void *v, void *back, cbl_yarena *a)
{
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	char why[256] = "";

	if (enc(v, &b1) != 0 || dec(b1.p, b1.len, back, a, CBL_YD_STRICT,
	    why, sizeof(why)) != 0 || enc(back, &b2) != 0)
		errx(1, "the round trip: %s", why);
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" :
	    "not the same");
}

static const char *const kinds[] = { "addr", "ports", "value" };

static void
kept(const struct arcana_firewall_firewall_kept *k)
{

	printf("kept path=%s present=%s sha256=%s text=%zu\n", str(k->path),
	    k->has_present ? (k->present ? "yes" : "no") : "-", str(k->sha256),
	    k->text != NULL ? strlen(k->text) : 0);
	for (size_t i = 0; i < k->rule.n; i++)
		printf("rule %u %s%s%s\n", k->rule.v[i].number, str(
		    k->rule.v[i].text), k->rule.v[i].source != NULL ? " <- " :
		    "", k->rule.v[i].source != NULL ? k->rule.v[i].source : "");
	for (size_t i = 0; i < k->other.n; i++)
		printf("other %s\n", k->other.v[i]);
	for (size_t i = 0; i < k->alias.n; i++)
		printf("alias %s %s %s\n", k->alias.v[i].name,
		    k->alias.v[i].has_kind ? kinds[k->alias.v[i].kind] : "-",
		    str(k->alias.v[i].value));
}

static void
mask(const struct arcana_firewall_firewall_state_dummynet_pipe_mask *m)
{

	if (m == NULL)
		return;
	printf(" mask=%d/%d:%d/%d/%d", m->has_src ? m->src : -1, m->has_dst ?
	    m->dst : -1, m->has_src_port ? m->src_port : -1, m->has_dst_port ?
	    m->dst_port : -1, m->has_proto ? m->proto : -1);
}

int
main(int argc, char **argv)
{
	cbl_yarena *a;
	int error;

	if (argc < 3 || argc > 4)
		errx(2, "usage: yfw read ipfw.json | kept file [sha256] | "
		    "trace reply.json");
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if (strcmp(argv[1], "read") == 0) {
		struct arcana_firewall_firewall f, back;
		const struct arcana_firewall_firewall_state *s;

		if ((error = yfw_from_json(slurp(argv[2]), a, &f)) != 0)
			errc(1, error, "yfw_from_json");
		kept(f.kept);
		printf("rc enable=%s type=%s script=%s\n", str(
		    f.rc->firewall_enable), str(f.rc->firewall_type), str(
		    f.rc->firewall_script));
		s = f.state;
		printf("state loaded=%s enabled=%s verbose=%s dynamic-total=%d\n",
		    s->has_loaded ? (s->loaded ? "yes" : "no") : "-",
		    s->has_enabled ? (s->enabled ? "yes" : "no") : "-",
		    s->has_verbose ? (s->verbose ? "yes" : "no") : "-",
		    s->has_dynamic_total ? (int)s->dynamic_total : -1);
		for (size_t i = 0; i < s->rule.n; i++)
			printf("rule %u set=%u packets=%ju octets=%ju%s %s\n",
			    s->rule.v[i].number, s->rule.v[i].set, (uintmax_t)
			    s->rule.v[i].packets, (uintmax_t)s->rule.v[i].octets,
			    s->rule.v[i].has_disabled && s->rule.v[i].disabled ?
			    " disabled" : "", str(s->rule.v[i].text));
		for (size_t i = 0; i < s->dynamic.n; i++)
			printf("dynamic %u packets=%ju ttl=%d %s %s\n",
			    s->dynamic.v[i].number, (uintmax_t)
			    s->dynamic.v[i].packets, s->dynamic.v[i].has_ttl ?
			    (int)s->dynamic.v[i].ttl : -1, str(
			    s->dynamic.v[i].kind), str(s->dynamic.v[i].flow));
		for (size_t i = 0; i < s->table.n; i++) {
			printf("table %s type=%s count=%d", s->table.v[i].name,
			    str(s->table.v[i].type), s->table.v[i].has_count ?
			    (int)s->table.v[i].count : -1);
			for (size_t k = 0; k < s->table.v[i].entry.n; k++)
				printf(" %s=%s", s->table.v[i].entry.v[k].key,
				    str(s->table.v[i].entry.v[k].value));
			printf("\n");
		}
		for (size_t i = 0; i < s->nat.n; i++)
			printf("nat %s\n", s->nat.v[i]);
		if (s->dummynet != NULL) {
			const struct arcana_firewall_firewall_state_dummynet *d =
			    s->dummynet;

			for (size_t i = 0; i < d->pipe.n; i++) {
				printf("pipe %u bw=%ju delay=%u slots=%d plr=%jd",
				    d->pipe.v[i].number, (uintmax_t)
				    d->pipe.v[i].bandwidth, d->pipe.v[i].delay,
				    d->pipe.v[i].has_slots ? (int)d->pipe.v[i].slots
				    : -1, d->pipe.v[i].has_plr ? (intmax_t)
				    d->pipe.v[i].plr : -1);
				mask(d->pipe.v[i].mask);
				printf("\n");
			}
			for (size_t i = 0; i < d->sched.n; i++) {
				printf("sched %u bw=%ju type=%s queues=",
				    d->sched.v[i].number, (uintmax_t)
				    d->sched.v[i].bandwidth, str(
				    d->sched.v[i].type));
				for (size_t k = 0; k < d->sched.v[i].queue.n; k++)
					printf("%s%u", k > 0 ? "," : "",
					    d->sched.v[i].queue.v[k]);
				mask((const void *)d->sched.v[i].mask);
				printf("\n");
			}
			for (size_t i = 0; i < d->queue.n; i++) {
				printf("queue %u sched=%u weight=%u slots=%d",
				    d->queue.v[i].number, d->queue.v[i].sched,
				    d->queue.v[i].weight, d->queue.v[i].has_slots
				    ? (int)d->queue.v[i].slots : -1);
				mask((const void *)d->queue.v[i].mask);
				printf("\n");
			}
		}
		same((void *)arcana_firewall_firewall_encode, (void *)
		    arcana_firewall_firewall_decode, &f, &back, a);
	} else if (strcmp(argv[1], "kept") == 0) {
		struct arcana_firewall_firewall_kept k, back;

		if ((error = yfw_kept_from_text(slurp(argv[2]), argc > 3 ?
		    argv[3] : NULL, a, &k)) != 0)
			errc(1, error, "yfw_kept_from_text");
		kept(&k);
		same((void *)arcana_firewall_firewall_kept_encode, (void *)
		    arcana_firewall_firewall_kept_decode, &k, &back, a);
	} else if (strcmp(argv[1], "trace") == 0) {
		struct arcana_firewall_firewall_trace_output t, back;

		if ((error = yfw_trace_from_json(slurp(argv[2]), a, &t)) != 0)
			errc(1, error, "yfw_trace_from_json");
		printf("trace seconds=%d limit=%d\n", t.has_seconds ?
		    t.seconds : -1, t.has_limit ? t.limit : -1);
		for (size_t i = 0; i < t.packet.n; i++) {
			const struct arcana_firewall_firewall_trace_output_packet
			    *p = &t.packet.v[i];

			printf("packet ms=%u %s %s %s -> %s proto=%d %d->%d rule="
			    "%u %s %s\n", p->ms, str(p->verdict), p->has_family ?
			    (p->family == 1 ? "ipv6" : "ipv4") : "-",
			    p->has_source ? p->source.v.m0 : "-",
			    p->has_destination ? p->destination.v.m0 : "-",
			    p->has_proto ? p->proto : -1, p->has_sport ? p->sport
			    : -1, p->has_dport ? p->dport : -1, p->rule, str(
			    p->interface), p->has_direction ? (p->direction == 1
			    ? "out" : "in") : "-");
		}
		same((void *)arcana_firewall_firewall_trace_output_encode,
		    (void *)arcana_firewall_firewall_trace_output_decode, &t,
		    &back, a);
	} else
		errx(2, "%s: read, kept or trace", argv[1]);
	return (0);
}
