/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yhist: the history operation's reply as arcana-history has it
 * (yhist.c), for agent_test.sh: yhist reply.json.  Through YANG-CBOR
 * and back, the same bytes.
 */

#include "ycommon.h"

static const char *const kinds[] = { "net", "disk", "jail-cpu", "jail-mem" };

int
main(int argc, char **argv)
{
	struct arcana_history_history h, back;
	const struct arcana_history_history_state *s;
	cbl_yarena *a;
	int error;

	if (argc != 2)
		errx(2, "usage: yhist reply.json");
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if ((error = yhist_from_json(slurp(argv[1]), a, &h)) != 0)
		errc(1, error, "yhist_from_json");
	printf("sampling step=%u keep=%u limits cpu=%u mem=%u swap=%u%s",
	    h.sampling->step, h.sampling->keep, h.limits->cpu, h.limits->memory,
	    h.limits->swap, h.limits->has_storage ? "" : "\n");
	if (h.limits->has_storage)
		printf(" storage=%u\n", h.limits->storage);
	for (size_t i = 0; i < h.rule.n; i++)
		printf("rule %s %s limit=%ju over=%s\n", kinds[h.rule.v[i].kind],
		    h.rule.v[i].name, (uintmax_t)h.rule.v[i].limit,
		    h.rule.v[i].over ? "yes" : "no");
	s = h.state;
	printf("state bytes=%ju ncpu=%u memory=%ju swap=%ju racct=%s\n",
	    (uintmax_t)s->bytes, s->ncpu, (uintmax_t)s->memory_total,
	    (uintmax_t)s->swap_total, s->racct ? "yes" : "no");
	for (size_t i = 0; i < s->interface.n; i++)
		printf("interface %s\n", s->interface.v[i]);
	for (size_t i = 0; i < s->disk.n; i++)
		printf("disk %s\n", s->disk.v[i]);
	for (size_t i = 0; i < s->jail.n; i++)
		printf("jail %s\n", s->jail.v[i]);
	for (size_t i = 0; i < s->sample.n; i++) {
		const struct arcana_history_history_state_sample *p =
		    &s->sample.v[i];

		printf("sample %s cpu=%jd load=%jd memory=%ju swap=%ju rx=%ju "
		    "tx=%ju read=%ju written=%ju", p->time, (intmax_t)p->cpu,
		    (intmax_t)p->load, (uintmax_t)p->memory, (uintmax_t)p->swap,
		    (uintmax_t)p->received, (uintmax_t)p->sent, (uintmax_t)
		    p->read, (uintmax_t)p->written);
		for (size_t k = 0; k < p->interface.n; k++)
			printf(" %s=%ju/%ju", p->interface.v[k].name, (uintmax_t)
			    p->interface.v[k].received, (uintmax_t)
			    p->interface.v[k].sent);
		for (size_t k = 0; k < p->disk.n; k++)
			printf(" %s=%ju/%ju", p->disk.v[k].name, (uintmax_t)
			    p->disk.v[k].read, (uintmax_t)p->disk.v[k].written);
		for (size_t k = 0; k < p->jail.n; k++)
			printf(" %s=%jd/%ju", p->jail.v[k].name, (intmax_t)
			    p->jail.v[k].cpu, (uintmax_t)p->jail.v[k].memory);
		printf("\n");
	}
	same((void *)arcana_history_history_encode, (void *)
	    arcana_history_history_decode, &h, &back, a);
	return (0);
}
