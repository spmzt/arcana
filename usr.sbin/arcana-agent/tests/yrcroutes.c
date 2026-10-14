/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yrcroutes: rc.conf's static routes as ietf-routing has them
 * (rcroutes.c), for agent_test.sh.
 *
 *	yrcroutes fib file ...		FIB fib's, of the files rc(8) reads
 *					in that order: a hop a line, inet or
 *					inet6, the prefix, the gateway, the
 *					interface, the special next hop (-
 *					none each), the description; then
 *					"unread var: why" each
 *	yrcroutes -w fib out file ...	the same, written to fragment out
 *					(made), read back from it alone
 *	yrcroutes -a fib old new	FIB fib's routes made the kernel's
 *					new file's, from old file's
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "collect.h"
#include "varconf.h"

typedef struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes_v4ur_ipv4_route
    yr4;

static const char *const special[] = { "blackhole", "unreachable",
    "prohibit", "receive" };

static const char *
str(const char *s)
{

	return (s != NULL ? s : "-");
}

static void
show(const char *af, const yr4 *v, size_t n)
{

	for (size_t i = 0; i < n; i++) {
		const yr4 *r = &v[i];

		if (r->next_hop->next_hop_list != NULL) {
			for (size_t k = 0; k < r->next_hop->next_hop_list->
			    next_hop.n; k++)
				printf("%s %s %s %s - %s\n", af,
				    r->destination_prefix, str(r->next_hop->
				    next_hop_list->next_hop.v[k].next_hop_address),
				    str(r->next_hop->next_hop_list->next_hop.v[k].
				    outgoing_interface), str(r->description));
			continue;
		}
		printf("%s %s %s %s %s %s\n", af, r->destination_prefix,
		    str(r->next_hop->next_hop_address),
		    str(r->next_hop->outgoing_interface),
		    r->next_hop->has_special_next_hop ?
		    special[r->next_hop->special_next_hop] : "-",
		    str(r->description));
	}
}

static const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes *
readall(struct vc_file *files, size_t n, int fib, cbl_yarena *a, bool print)
{
	const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes
	    *sr;
	struct rcr_unread *u;
	size_t nu;
	int error;

	if ((error = rcr_read(files, n, fib, a, &sr, &u, &nu)) != 0)
		errc(1, error, "rcr_read");
	if (print) {
		show("inet", sr->v4ur_ipv4->route.v, sr->v4ur_ipv4->route.n);
		show("inet6", (const void *)sr->v6ur_ipv6->route.v,
		    sr->v6ur_ipv6->route.n);
		for (size_t i = 0; i < nu; i++)
			printf("unread %s: %s\n", u[i].var, u[i].why);
	}
	free(u);
	return (sr);
}

int
main(int argc, char **argv)
{
	struct vc_file *files, frag;
	char why[256];
	cbl_yarena *a;
	const char *out = NULL;
	int fib, first;

	if (argc == 5 && strcmp(argv[1], "-a") == 0) {
		struct vc_file of, nf;

		if ((a = cbl_yarena_new()) == NULL)
			err(1, "cbl_yarena_new");
		if (vc_read(&of, VC_SH, argv[3], why, sizeof(why)) == -1 ||
		    vc_read(&nf, VC_SH, argv[4], why, sizeof(why)) == -1)
			errx(1, "%s", why);
		fib = atoi(argv[2]);
		if (rcr_apply(fib, readall(&of, 1, fib, a, false),
		    readall(&nf, 1, fib, a, false), why, sizeof(why)) != 0)
			errx(1, "%s", why);
		return (0);
	}
	if (argc > 1 && strcmp(argv[1], "-w") == 0) {
		if (argc < 5)
			errx(2, "usage: yrcroutes -w fib out file ...");
		fib = atoi(argv[2]);
		out = argv[3];
		first = 4;
	} else {
		if (argc < 3)
			errx(2, "usage: yrcroutes fib file ...");
		fib = atoi(argv[1]);
		first = 2;
	}
	if ((a = cbl_yarena_new()) == NULL ||
	    (files = calloc((size_t)(argc - first), sizeof(*files))) == NULL)
		err(1, "alloc");
	for (int i = first; i < argc; i++)
		if (vc_read(&files[i - first], VC_SH, argv[i], why,
		    sizeof(why)) == -1)
			errx(1, "%s", why);
	if (out == NULL) {
		readall(files, (size_t)(argc - first), fib, a, true);
		return (0);
	}
	if (vc_read(&frag, VC_SH, out, why, sizeof(why)) == -1 ||
	    rcr_write(&frag, fib, readall(files, (size_t)(argc - first), fib,
	    a, false), why, sizeof(why)) != 0 ||
	    vc_write(&frag, out, 0644, why, sizeof(why)) == -1)
		errx(1, "%s", why);
	vc_free(&frag);
	if (vc_read(&frag, VC_SH, out, why, sizeof(why)) == -1)
		errx(1, "%s", why);
	readall(&frag, 1, fib, a, true);
	return (0);
}
