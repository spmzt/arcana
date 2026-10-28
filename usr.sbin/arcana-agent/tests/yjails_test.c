/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yjails: the jails read as arcana-jails has it (yjails.c),
 * for agent_test.sh: a reply of two jails, one running with a vnet of its
 * own, one configured and stopped, made into the module's data, written
 * a field a line, and through YANG-CBOR and back, the same bytes.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arcana.h>

#include "agent.h"
#include "collect.h"

static const char *const scopes[] = { "/etc/jail.conf",
    "/etc/jail.conf.d/web.conf" };
static const char *const ip4[] = { "lo1|192.0.2.10/24" };
static const char *const ip6[] = { "2001:db8::10" };
static const char *const allow[] = { "1" };
static const char *const plugins[] = { "bird", "wireguard" };
static const struct arc_param params[] = {
	{ .key = "allow.raw_sockets", .values = { 1, allow } },
	{ .key = "persist", .values = { 0, NULL } },
};
static const struct conf_error cerr[] = {
	{ .scope = "/etc/jail.conf.d/bad.conf", .message = "line 3: syntax "
	    "error" },
};
static const struct arc_jail jails[] = {
	{
		.name = "web", .has_state = true,
		.state = ARC_JAIL_STATE_RUNNING, .has_jid = true, .jid = 7,
		.has_configured = true, .configured = true,
		.scope = "/etc/jail.conf.d/web.conf", .hostname = "web.example",
		.path = "/jails/web", .ip4 = { 1, ip4 }, .ip6 = { 1, ip6 },
		.has_vnet = true, .vnet = true, .osrelease = "15.0-RELEASE",
		.has_persist = true, .persist = true,
		.has_securelevel = true, .securelevel = 2,
		.has_parent = true, .parent = 0, .has_children = true,
		.children = 1, .has_nproc = true, .nproc = 12,
		.has_rss_kb = true, .rss_kb = 81920, .has_cpu_pct = true,
		.cpu_pct = 346, .interface = "lo1",
		.params = { 2, params }, .plugins = { 2, plugins },
	},
	{
		.name = "db", .has_state = true,
		.state = ARC_JAIL_STATE_STOPPED, .has_configured = true,
		.configured = true, .scope = "/etc/jail.conf",
		.path = "/jails/db", .has_vnet = true, .vnet = true,
	},
};

static const char *
str(const char *s)
{

	return (s != NULL ? s : "-");
}

static void
show(const struct arcana_jails *d)
{
	const struct arcana_jails_jails *js = d->jails;

	for (size_t i = 0; i < js->scope.n; i++)
		printf("scope %s\n", js->scope.v[i]);
	for (size_t i = 0; i < js->conf_error.n; i++)
		printf("conf-error %s: %s\n", js->conf_error.v[i].scope,
		    js->conf_error.v[i].message);
	for (size_t i = 0; i < js->jail.n; i++) {
		const struct arcana_jails_jails_jail *j = &js->jail.v[i];

		printf("jail %s state=%d jid=%s configured=%d scope=%s "
		    "hostname=%s path=%s vnet=%d osrelease=%s persist=%s "
		    "securelevel=%s nproc=%s rss=%s cpu=%s interface=%s "
		    "lne=%s\n", j->name, j->has_state ? (int)j->state : -1,
		    j->has_jid ? "yes" : "-", j->configured, str(j->scope),
		    str(j->hostname), str(j->path), j->vnet,
		    str(j->osrelease), j->has_persist ? "yes" : "-",
		    j->has_securelevel ? "yes" : "-",
		    j->has_nproc ? "yes" : "-", j->has_rss ? "yes" : "-",
		    j->has_cpu ? "yes" : "-", str(j->interface), str(j->lne));
		if (j->has_jid)
			printf("  jid %u nproc %u rss %ju cpu %jd securelevel "
			    "%d\n", j->jid, j->nproc, (uintmax_t)j->rss,
			    (intmax_t)j->cpu, j->securelevel);
		for (size_t k = 0; k < j->ip4.n; k++)
			printf("  ip4 %s\n", j->ip4.v[k]);
		for (size_t k = 0; k < j->ip6.n; k++)
			printf("  ip6 %s\n", j->ip6.v[k]);
		for (size_t k = 0; k < j->param.n; k++) {
			printf("  param %s", j->param.v[k].name);
			for (size_t m = 0; m < j->param.v[k].value.n; m++)
				printf(" %s", j->param.v[k].value.v[m]);
			printf("\n");
		}
		for (size_t k = 0; k < j->plugin.n; k++)
			printf("  plugin %s\n", j->plugin.v[k]);
	}
}

int
main(void)
{
	struct jails_read rsp;
	struct arcana_jails d, back;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	cbl_yarena *a;
	char why[256];
	int error;

	memset(&rsp, 0, sizeof(rsp));
	rsp.ok = true;
	rsp.nscopes = 2;
	rsp.scopes = scopes;
	rsp.nerrors = 1;
	rsp.errors = (struct conf_error *)(uintptr_t)cerr;
	rsp.njails = 2;
	rsp.jails = (struct arc_jail *)(uintptr_t)jails;
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if ((error = yjails_from_list(&rsp, a, &d)) != 0)
		errc(1, error, "yjails_from_list");
	show(&d);
	if (arcana_jails_jails_encode(d.jails, &b1) != 0)
		errx(1, "encode");
	memset(&back, 0, sizeof(back));
	if ((back.jails = cbl_yarena_alloc(a, sizeof(*back.jails))) == NULL)
		err(1, "cbl_yarena_alloc");
	if (arcana_jails_jails_decode(b1.p, b1.len,
	    (struct arcana_jails_jails *)(uintptr_t)back.jails, a,
	    CBL_YD_STRICT, why, sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	if (arcana_jails_jails_encode(back.jails, &b2) != 0)
		errx(1, "encode again");
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" : "not the same");
	printf("-- back\n");
	show(&back);
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
	cbl_yarena_free(a);
	return (0);
}
