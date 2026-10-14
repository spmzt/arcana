/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ycollect: what the YANG collectors find (yang/collect.h), a line an
 * item, for agent_test.sh to set beside ifconfig(8) and netstat(1); and
 * the tree through YANG-CBOR and back, the same bytes.
 *
 *	ycollect interfaces
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "collect.h"

static const char *const admin[] = { "?", "up", "down", "testing" };
static const char *const oper[] = { "?", "up", "down", "testing", "unknown",
    "dormant", "not-present", "lower-layer-down" };

/* A leaf-list of names, comma-separated; "-" for none. */
static void
names(const char *what, size_t n, const char *const *v)
{

	printf(" %s=", what);
	if (n == 0)
		printf("-");
	for (size_t i = 0; i < n; i++)
		printf("%s%s", i > 0 ? "," : "", v[i]);
}

static void
roundtrip(const struct ietf_interfaces_interfaces *ifs, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces back;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	char why[256];

	if (ietf_interfaces_interfaces_encode(ifs, &b1) != 0)
		errx(1, "encode");
	if (ietf_interfaces_interfaces_decode(b1.p, b1.len, &back, a,
	    CBL_YD_STRICT, why, sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	if (ietf_interfaces_interfaces_encode(&back, &b2) != 0)
		errx(1, "encode again");
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" : "not the same");
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
}

int
main(int argc, char **argv)
{
	struct ietf_interfaces data = { 0 };
	cbl_yarena *a;
	int error;

	if (argc != 2 || strcmp(argv[1], "interfaces") != 0) {
		fprintf(stderr, "usage: ycollect interfaces\n");
		return (2);
	}
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if ((error = yif_interfaces(&data, a)) != 0)
		errc(1, error, "yif_interfaces");
	for (size_t i = 0; i < data.interfaces->interface.n; i++) {
		const struct ietf_interfaces_interfaces_interface *e =
		    &data.interfaces->interface.v[i];
		const struct cbl_yident *t = e->has_type ?
		    cbl_yschema_ident(&ymodel_schema, e->type) : NULL;

		printf("%s index=%d admin=%s oper=%s type=%s phys=%s "
		    "in-octets=%ju out-octets=%ju", e->name, e->if_index,
		    admin[e->admin_status], oper[e->oper_status],
		    t != NULL ? t->name : "-",
		    e->phys_address != NULL ? e->phys_address : "-",
		    (uintmax_t)e->statistics->in_octets,
		    (uintmax_t)e->statistics->out_octets);
		names("lower", e->lower_layer_if.n, e->lower_layer_if.v);
		names("higher", e->higher_layer_if.n, e->higher_layer_if.v);
		printf("\n");
	}
	roundtrip(data.interfaces, a);
	cbl_yarena_free(a);
	return (0);
}
