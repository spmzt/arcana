/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yni: FreeBSD's FIBs as network instances (yni.c), for agent_test.sh
 * and agent_root_test.sh.
 *
 *	yni [-n nfibs] conf		the instances, one a line: name, FIB,
 *					description (- for none); "unread
 *					var: why" for what conf has that
 *					cannot be read so; the tree through
 *					YANG-CBOR and back.  conf - for none;
 *					nfibs net.fibs unless given
 *	yni -n nfibs -w conf		instances read from stdin, a line
 *					each, "fib name [description]",
 *					written into conf
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "collect.h"
#include "varconf.h"

typedef struct ietf_network_instance_network_instances_network_instance
    yni;

static void
show(const struct ietf_network_instance_network_instances *ni,
    const struct yunread *u, size_t nu, cbl_yarena *a)
{
	struct ietf_network_instance_network_instances back;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	char why[256];

	for (size_t i = 0; i < ni->network_instance.n; i++) {
		const yni *e = &ni->network_instance.v[i];

		printf("%s %u %s\n", e->name, e->arcni_fib,
		    e->description != NULL ? e->description : "-");
	}
	for (size_t i = 0; i < nu; i++)
		printf("unread %s: %s\n", u[i].var, u[i].why);
	if (ietf_network_instance_network_instances_encode(ni, &b1) != 0)
		errx(1, "encode");
	if (ietf_network_instance_network_instances_decode(b1.p, b1.len,
	    &back, a, CBL_YD_STRICT, why, sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	if (ietf_network_instance_network_instances_encode(&back, &b2) != 0)
		errx(1, "encode again");
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" : "not the same");
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
}

int
main(int argc, char **argv)
{
	const struct ietf_network_instance_network_instances *ni;
	struct vc_file f, *fp = NULL;
	struct yunread *u;
	cbl_yarena *a;
	char why[256];
	bool write = false;
	int ch, nfibs = -1, error;
	size_t nu;

	while ((ch = getopt(argc, argv, "n:w")) != -1)
		switch (ch) {
		case 'n':
			nfibs = atoi(optarg);
			break;
		case 'w':
			write = true;
			break;
		default:
			errx(2, "usage: yni [-n nfibs] [-w] conf");
		}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		errx(2, "usage: yni [-n nfibs] [-w] conf");
	if (nfibs == -1 && (nfibs = yni_nfibs()) == -1)
		err(1, "net.fibs");
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if (strcmp(argv[0], "-") != 0) {
		if (vc_read(&f, VC_SH, argv[0], why, sizeof(why)) == -1)
			errx(1, "%s", why);
		fp = &f;
	}
	if (write) {
		struct ietf_network_instance_network_instances in = { 0 };
		static yni v[64];
		char line[512];
		size_t n = 0;

		while (n < 64 && fgets(line, sizeof(line), stdin) != NULL) {
			char *p = line, *fib, *name, *desc;

			line[strcspn(line, "\n")] = '\0';
			fib = strsep(&p, " ");
			name = strsep(&p, " ");
			desc = p;
			if (fib == NULL || name == NULL)
				continue;
			v[n].name = strdup(name);
			v[n].ni_type =
			    IETF_NETWORK_INSTANCE_NETWORK_INSTANCES_NETWORK_INSTANCE_NI_TYPE_FIB;
			v[n].has_arcni_fib = true;
			v[n].arcni_fib = (uint16_t)atoi(fib);
			v[n].description = desc != NULL ? strdup(desc) : NULL;
			n++;
		}
		in.network_instance.n = n;
		in.network_instance.v = v;
		if (fp == NULL)
			errx(2, "-w needs a file");
		if (yni_write(fp, nfibs, &in, why, sizeof(why)) != 0)
			errx(1, "%s", why);
		if (vc_write(fp, argv[0], 0644, why, sizeof(why)) == -1)
			errx(1, "%s", why);
		return (0);
	}
	if ((error = yni_read(fp, nfibs, a, &ni, &u, &nu)) != 0)
		errc(1, error, "yni_read");
	show(ni, u, nu, a);
	cbl_yarena_free(a);
	return (0);
}
