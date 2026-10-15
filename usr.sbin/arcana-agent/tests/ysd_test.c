/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ysd: the probes and the SD-WAN edge as arcana-probe and arcana-sdwan
 * have them (yprobe.c, ysd.c), for agent_test.sh.
 *
 *	ysd targets probes.json		sdwan-probes' targets
 *	ysd probes reply.json		the sdwan read's targets
 *	ysd rules rules.json		sdwan-rules
 *	ysd steer steer.json		sdwan-steer
 *	ysd bird|dhcp|dns|proxy|ids instances.json
 *					the instances of one kind
 *	ysd state reply.json		the sdwan read, all of it
 *
 * Through YANG-CBOR and back, the same bytes.
 */

#include "ycommon.h"

static const char *const tstates[] = { "unknown", "up", "down", "ended",
    "error" };
static const char *const cstates[] = { "up", "down", "unknown" };

int
main(int argc, char **argv)
{
	cbl_yarena *a;
	int error;

	if (argc != 3)
		errx(2, "usage: ysd targets|probes|rules|steer|bird|dhcp|dns|"
		    "proxy|ids|state file.json");
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if (strcmp(argv[1], "targets") == 0) {
		struct arcana_probe_probes p = { 0 }, back;

		if ((error = yprobe_targets_from_json(slurp(argv[2]), a,
		    &p.target.n, &p.target.v)) != 0)
			errc(1, error, "yprobe_targets_from_json");
		for (size_t i = 0; i < p.target.n; i++) {
			const struct arcana_probe_probes_target *t =
			    &p.target.v[i];

			printf("target %s %s fib=%u interval=%u size=%u count=%u "
			    "dscp=%u down=%u up=%u timeout=%u eval=%u history=%u "
			    "report=%u", t->id, t->has_address ? t->address.v.m0 :
			    "-", t->fib, t->interval, t->size, t->count, t->dscp,
			    t->down, t->up, t->timeout, t->eval, t->history,
			    t->report);
			if (t->tca != NULL)
				printf(" tca delay=%jd ipdv=%jd loss=%jd damping=%u",
				    (intmax_t)t->tca->delay, (intmax_t)t->tca->ipdv,
				    (intmax_t)t->tca->loss, t->tca->damping);
			printf("\n");
		}
		same((void *)arcana_probe_probes_encode, (void *)
		    arcana_probe_probes_decode, &p, &back, a);
	} else if (strcmp(argv[1], "probes") == 0) {
		struct arcana_probe_probes_state s, back;

		if ((error = yprobe_state_from_json(slurp(argv[2]), a, &s)) != 0)
			errc(1, error, "yprobe_state_from_json");
		printf("probing=%s time=%s\n", s.probing ? "yes" : "no", str(
		    s.time));
		for (size_t i = 0; i < s.target.n; i++) {
			const struct arcana_probe_probes_state_target *t =
			    &s.target.v[i];

			printf("target %s %s %s fib=%u %s error=%s since=%s "
			    "interval=%u size=%u eval=%u dscp=%u sent=%ju "
			    "received=%ju misses=%u last-rtt=%jd kept=%u\n", t->id,
			    t->has_address ? t->address.v.m0 : "-", t->has_family
			    ? (t->family == 1 ? "ipv6" : "ipv4") : "-", t->fib,
			    t->has_state ? tstates[t->state] : "-", str(t->error),
			    str(t->since), t->interval, t->size, t->eval, t->dscp,
			    (uintmax_t)t->sent, (uintmax_t)t->received, t->misses,
			    (intmax_t)t->last_rtt, t->kept);
			if (t->now != NULL)
				printf("  now sent=%u received=%u delay=%jd ipdv=%jd "
				    "loss=%jd age=%jd\n", t->now->sent,
				    t->now->received, (intmax_t)t->now->delay,
				    (intmax_t)t->now->ipdv, (intmax_t)t->now->loss,
				    (intmax_t)t->now->age);
			for (size_t k = 0; k < t->sample.n; k++)
				printf("  sample %s delay=%jd ipdv=%jd loss=%jd min=%jd "
				    "max=%jd sent=%u received=%u\n",
				    t->sample.v[k].time, (intmax_t)
				    t->sample.v[k].delay, (intmax_t)
				    t->sample.v[k].ipdv, (intmax_t)
				    t->sample.v[k].loss, (intmax_t)t->sample.v[k].min,
				    (intmax_t)t->sample.v[k].max, t->sample.v[k].sent,
				    t->sample.v[k].received);
		}
		same((void *)arcana_probe_probes_state_encode, (void *)
		    arcana_probe_probes_state_decode, &s, &back, a);
	} else if (strcmp(argv[1], "rules") == 0) {
		static const char *const vt[] = { "skipto", "ipv4", "ipv6",
		    "legacy" };
		struct arcana_sdwan_sdwan_rules r, back;

		if ((error = ysd_rules_from_json(slurp(argv[2]), a, &r)) != 0)
			errc(1, error, "ysd_rules_from_json");
		printf("rules set=%u\n", r.set);
		for (size_t i = 0; i < r.table.n; i++) {
			printf("table %s %s", r.table.v[i].name,
			    r.table.v[i].has_valtype ? vt[r.table.v[i].valtype] :
			    "-");
			for (size_t k = 0; k < r.table.v[i].entry.n; k++)
				printf(" %s=%s", r.table.v[i].entry.v[k].prefix, str(
				    r.table.v[i].entry.v[k].value));
			printf("\n");
		}
		for (size_t i = 0; i < r.object.n; i++)
			printf("object %s\n", r.object.v[i]);
		for (size_t i = 0; i < r.rule.n; i++)
			printf("rule %u %s\n", r.rule.v[i].number, str(
			    r.rule.v[i].text));
		same((void *)arcana_sdwan_sdwan_rules_encode, (void *)
		    arcana_sdwan_sdwan_rules_decode, &r, &back, a);
	} else if (strcmp(argv[1], "steer") == 0) {
		struct arcana_sdwan_sdwan_steer s, back;

		if ((error = ysd_steer_from_json(slurp(argv[2]), a, &s)) != 0)
			errc(1, error, "ysd_steer_from_json");
		for (size_t i = 0; i < s.entry.n; i++) {
			printf("entry %s %s:", s.entry.v[i].table,
			    s.entry.v[i].prefix);
			for (size_t k = 0; k < s.entry.v[i].candidate.n; k++)
				printf(" %s via %s", s.entry.v[i].candidate.v[k].id,
				    s.entry.v[i].candidate.v[k].has_via ?
				    s.entry.v[i].candidate.v[k].via.v.m0 : "-");
			printf("\n");
		}
		same((void *)arcana_sdwan_sdwan_steer_encode, (void *)
		    arcana_sdwan_sdwan_steer_decode, &s, &back, a);
	} else if (strcmp(argv[1], "bird") == 0 || strcmp(argv[1], "dhcp") == 0
	    || strcmp(argv[1], "dns") == 0) {
		struct arcana_sdwan_sdwan w = { 0 }, back;
		const void *v;
		size_t n;

		if ((error = ysd_instances_from_json(slurp(argv[2]), YSD_PLAIN, a,
		    &n, &v)) != 0)
			errc(1, error, "ysd_instances_from_json");
		w.bird_instance.n = n;
		w.bird_instance.v = v;
		for (size_t i = 0; i < n; i++)
			printf("instance %s fib=%u conf=%zu\n",
			    w.bird_instance.v[i].name, w.bird_instance.v[i].fib,
			    w.bird_instance.v[i].conf != NULL ? strlen(
			    w.bird_instance.v[i].conf) : 0);
		same((void *)arcana_sdwan_sdwan_encode, (void *)
		    arcana_sdwan_sdwan_decode, &w, &back, a);
	} else if (strcmp(argv[1], "proxy") == 0) {
		struct arcana_sdwan_sdwan w = { 0 }, back;
		const void *v;
		size_t n;

		if ((error = ysd_instances_from_json(slurp(argv[2]), YSD_PROXY, a,
		    &n, &v)) != 0)
			errc(1, error, "ysd_instances_from_json");
		w.proxy_instance.n = n;
		w.proxy_instance.v = v;
		for (size_t i = 0; i < n; i++)
			printf("proxy %s fib=%u mode=%s conf=%zu deny=%s\n",
			    w.proxy_instance.v[i].name, w.proxy_instance.v[i].fib,
			    w.proxy_instance.v[i].has_mode ? (
			    w.proxy_instance.v[i].mode == 1 ? "inspect" : "sni") :
			    "-", w.proxy_instance.v[i].conf != NULL ? strlen(
			    w.proxy_instance.v[i].conf) : 0, str(
			    w.proxy_instance.v[i].deny));
		same((void *)arcana_sdwan_sdwan_encode, (void *)
		    arcana_sdwan_sdwan_decode, &w, &back, a);
	} else if (strcmp(argv[1], "ids") == 0) {
		struct arcana_sdwan_sdwan w = { 0 }, back;
		const void *v;
		size_t n;

		if ((error = ysd_instances_from_json(slurp(argv[2]), YSD_IDS, a,
		    &n, &v)) != 0)
			errc(1, error, "ysd_instances_from_json");
		w.ids_instance.n = n;
		w.ids_instance.v = v;
		for (size_t i = 0; i < n; i++) {
			printf("ids %s divert=%u conf=%zu rules=%zu interfaces=",
			    w.ids_instance.v[i].name, w.ids_instance.v[i].divert,
			    w.ids_instance.v[i].conf != NULL ? strlen(
			    w.ids_instance.v[i].conf) : 0,
			    w.ids_instance.v[i].rules != NULL ? strlen(
			    w.ids_instance.v[i].rules) : 0);
			for (size_t k = 0; k < w.ids_instance.v[i].interface.n; k++)
				printf("%s%s", k > 0 ? "," : "",
				    w.ids_instance.v[i].interface.v[k]);
			printf("\n");
		}
		same((void *)arcana_sdwan_sdwan_encode, (void *)
		    arcana_sdwan_sdwan_decode, &w, &back, a);
	} else if (strcmp(argv[1], "state") == 0) {
		struct arcana_sdwan_sdwan_state s, back;

		if ((error = ysd_state_from_json(slurp(argv[2]), a, &s)) != 0)
			errc(1, error, "ysd_state_from_json");
		if (s.rules != NULL) {
			printf("rules set=%u rules=%u objects=%u\n", s.rules->set,
			    s.rules->rules, s.rules->objects);
			for (size_t i = 0; i < s.rules->table.n; i++)
				printf("  table %s count=%u\n", s.rules->table.v[i].name,
				    s.rules->table.v[i].count);
			for (size_t i = 0; i < s.rules->counter.n; i++)
				printf("  counter %u packets=%ju octets=%ju %s\n",
				    s.rules->counter.v[i].rule, (uintmax_t)
				    s.rules->counter.v[i].packets, (uintmax_t)
				    s.rules->counter.v[i].octets, str(
				    s.rules->counter.v[i].text));
		}
		printf("steered=%s\n", s.steered ? "yes" : "no");
		for (size_t i = 0; i < s.steer.n; i++) {
			printf("steer %s %s chosen=%d:", s.steer.v[i].table,
			    s.steer.v[i].prefix, s.steer.v[i].chosen);
			for (size_t k = 0; k < s.steer.v[i].candidate.n; k++)
				printf(" %s via %s %s", s.steer.v[i].candidate.v[k].id,
				    s.steer.v[i].candidate.v[k].has_via ?
				    s.steer.v[i].candidate.v[k].via.v.m0 : "-",
				    s.steer.v[i].candidate.v[k].has_state ? cstates[
				    s.steer.v[i].candidate.v[k].state] : "-");
			printf("\n");
		}
		for (size_t i = 0; i < s.bird.n; i++) {
			printf("bird %s fib=%u running=%s\n", s.bird.v[i].name,
			    s.bird.v[i].fib, s.bird.v[i].running ? "yes" : "no");
			for (size_t k = 0; k < s.bird.v[i].protocol.n; k++)
				printf("  protocol %s %s %s %s\n",
				    s.bird.v[i].protocol.v[k].name, str(
				    s.bird.v[i].protocol.v[k].proto), str(
				    s.bird.v[i].protocol.v[k].state), str(
				    s.bird.v[i].protocol.v[k].info));
			for (size_t k = 0; k < s.bird.v[i].bfd.n; k++)
				printf("  bfd %s %s %s since=%s\n", str(
				    s.bird.v[i].bfd.v[k].address), str(
				    s.bird.v[i].bfd.v[k].interface),
				    s.bird.v[i].bfd.v[k].has_state ? cstates[
				    s.bird.v[i].bfd.v[k].state] : "-", str(
				    s.bird.v[i].bfd.v[k].since));
		}
		for (size_t i = 0; i < s.dhcp.n; i++) {
			printf("dhcp %s fib=%u running=%s\n", s.dhcp.v[i].name,
			    s.dhcp.v[i].fib, s.dhcp.v[i].running ? "yes" : "no");
			for (size_t k = 0; k < s.dhcp.v[i].lease.n; k++)
				printf("  lease %s %s %s %s\n", str(
				    s.dhcp.v[i].lease.v[k].expires), str(
				    s.dhcp.v[i].lease.v[k].id),
				    s.dhcp.v[i].lease.v[k].has_address ?
				    s.dhcp.v[i].lease.v[k].address.v.m0 : "-", str(
				    s.dhcp.v[i].lease.v[k].hostname));
		}
		for (size_t i = 0; i < s.dns.n; i++)
			printf("dns %s fib=%u running=%s\n", s.dns.v[i].name,
			    s.dns.v[i].fib, s.dns.v[i].running ? "yes" : "no");
		for (size_t i = 0; i < s.proxy.n; i++)
			printf("proxy %s fib=%u running=%s mode=%s icap=%s ca=%zu\n",
			    s.proxy.v[i].name, s.proxy.v[i].fib,
			    s.proxy.v[i].running ? "yes" : "no", str(
			    s.proxy.v[i].mode), s.proxy.v[i].icap ? "yes" : "no",
			    s.proxy.v[i].ca != NULL ? strlen(s.proxy.v[i].ca) : 0);
		for (size_t i = 0; i < s.ids.n; i++) {
			printf("ids %s %s divert=%u running=%s seen=%ju\n",
			    s.ids.v[i].name, s.ids.v[i].has_mode ? (
			    s.ids.v[i].mode == 1 ? "prevent" : "detect") : "-",
			    s.ids.v[i].divert, s.ids.v[i].running ? "yes" : "no",
			    (uintmax_t)s.ids.v[i].alerts_seen);
			for (size_t k = 0; k < s.ids.v[i].alert.n; k++)
				printf("  alert %s %s %s:%u -> %s:%u %s\n", str(
				    s.ids.v[i].alert.v[k].time), str(
				    s.ids.v[i].alert.v[k].name), str(
				    s.ids.v[i].alert.v[k].source),
				    s.ids.v[i].alert.v[k].source_port, str(
				    s.ids.v[i].alert.v[k].destination),
				    s.ids.v[i].alert.v[k].destination_port, str(
				    s.ids.v[i].alert.v[k].proto));
		}
		if (s.record != NULL) {
			printf("record count=%ju seq=%ju\n", (uintmax_t)
			    s.record->count, (uintmax_t)s.record->sequence);
			for (size_t k = 0; k < s.record->last.n; k++)
				printf("  %s %ju rule=%u %s %s -> %s %s (%s)\n", str(
				    s.record->last.v[k].time), (uintmax_t)
				    s.record->last.v[k].sequence,
				    s.record->last.v[k].rule, str(
				    s.record->last.v[k].action), str(
				    s.record->last.v[k].source), str(
				    s.record->last.v[k].destination), str(
				    s.record->last.v[k].interface), str(
				    s.record->last.v[k].comment));
		}
		for (size_t i = 0; i < s.key.n; i++)
			printf("key %s public=%s next=%s at=%s lifetime=%u spi=%u/%u "
			    "next-spi=%u pending=%s\n", s.key.v[i].interface, str(
			    s.key.v[i].public), str(s.key.v[i].next), str(
			    s.key.v[i].keyed_at), s.key.v[i].lifetime,
			    s.key.v[i].spi_in, s.key.v[i].spi_out,
			    s.key.v[i].next_spi_in, s.key.v[i].pending ? "yes" :
			    "no");
		for (size_t i = 0; i < s.fault.n; i++)
			printf("fault %s %s %s was=%s %s by=%s cleared=%s at=%s: %s\n",
			    str(s.fault.v[i].time), str(s.fault.v[i].type), str(
			    s.fault.v[i].severity), str(s.fault.v[i].was), str(
			    s.fault.v[i].object), str(s.fault.v[i].by),
			    s.fault.v[i].cleared ? "yes" : "no", str(
			    s.fault.v[i].cleared_at), str(
			    s.fault.v[i].description));
		same((void *)arcana_sdwan_sdwan_state_encode, (void *)
		    arcana_sdwan_sdwan_state_decode, &s, &back, a);
	} else
		errx(2, "%s: not a kind", argv[1]);
	return (0);
}
