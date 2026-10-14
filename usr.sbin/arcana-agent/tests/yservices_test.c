/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yservices: the services operations' replies as arcana-services has
 * them (yservices.c), for agent_test.sh: a services reply of three
 * scripts and the service-config reply of one, written a field a line
 * and through YANG-CBOR and back; then what yservices_diff() makes of a
 * configuration wanted, a case a line.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"

typedef struct arcana_services_services_service yservice;
typedef struct arcana_services_services_service_variable yvar;

static const struct arc_service svcs[] = {
	{ .name = "sshd", .path = "/etc/rc.d/sshd", .rcvar = "sshd_enable",
	    .has_enabled = true, .enabled = true, .has_running = true,
	    .running = true, .has_pid = true, .pid = 812,
	    .status = "sshd is running as pid 812." },
	{ .name = "ntpd", .path = "/etc/rc.d/ntpd", .rcvar = "ntpd_enable",
	    .has_enabled = true, .enabled = false },
	{ .name = "bird", .path = "/usr/local/etc/rc.d/bird",
	    .rcvar = "bird_enable", .has_enabled = true, .enabled = true,
	    .has_running = true, .running = false,
	    .status = "bird is not running." },
};
static const struct arc_service sshd_after = { .name = "sshd" };
static const struct arc_variable sshd_vars[] = {
	{ .key = "sshd_flags", .value = "-o UseDNS=no" },
	{ .key = "sshd_program", .value = "/usr/sbin/sshd" },
};
static const char *const sshd_cmds[] = { "configtest", "keygen",
    "reload" };

static const char *
str(const char *s)
{

	return (s != NULL ? s : "-");
}

static void
show(const struct arcana_services *d)
{

	for (size_t i = 0; i < d->services->service.n; i++) {
		const yservice *s = &d->services->service.v[i];

		printf("service %s enabled=%s path=%s rcvar=%s running=%s "
		    "pid=%s status=%s description=%s\n", s->name,
		    s->has_enabled ? (s->enabled ? "yes" : "no") : "-",
		    str(s->path), str(s->rcvar), s->has_running ?
		    (s->running ? "yes" : "no") : "-", s->has_pid ? "yes" :
		    "-", str(s->status), str(s->description));
		for (size_t k = 0; k < s->variable.n; k++)
			printf("  variable %s=%s\n", s->variable.v[k].name,
			    s->variable.v[k].value);
		for (size_t k = 0; k < s->command.n; k++)
			printf("  command %s\n", s->command.v[k]);
	}
}

static void
diff(const char *what, const yservice *have, const yservice *want,
    cbl_yarena *a)
{
	struct arc_variable *v;
	size_t n;
	int enable, error;

	printf("%s:", what);
	if ((error = yservices_diff(have, want, a, &enable, &v, &n)) != 0) {
		printf(" refused (%s)\n", strerror(error));
		return;
	}
	if (enable != 0)
		printf(" %s", enable > 0 ? "enable" : "disable");
	for (size_t i = 0; i < n; i++)
		if (v[i].remove)
			printf(" unset %s", v[i].key);
		else
			printf(" set %s=%s", v[i].key, v[i].value);
	if (enable == 0 && n == 0)
		printf(" nothing");
	printf("\n");
}

int
main(void)
{
	struct arc_services_rsp list;
	struct arc_service_config_rsp cfg;
	const struct arc_service_config_rsp *cfgs[] = { &cfg };
	struct arcana_services d, back;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	const yservice *sshd;
	yservice want;
	yvar wv[3];
	cbl_yarena *a;
	char why[256];
	int error;

	memset(&list, 0, sizeof(list));
	list.has_ok = list.ok = true;
	list.services.n = 3;
	list.services.v = svcs;
	memset(&cfg, 0, sizeof(cfg));
	cfg.has_ok = cfg.ok = true;
	cfg.service_result = &sshd_after;
	cfg.variables.n = 2;
	cfg.variables.v = sshd_vars;
	cfg.description = "Secure Shell Daemon";
	cfg.commands.n = 3;
	cfg.commands.v = sshd_cmds;
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if ((error = yservices_from(&list, cfgs, 1, a, &d)) != 0)
		errc(1, error, "yservices_from");
	show(&d);
	if (arcana_services_services_encode(d.services, &b1) != 0)
		errx(1, "encode");
	memset(&back, 0, sizeof(back));
	if ((back.services = cbl_yarena_alloc(a, sizeof(*back.services))) ==
	    NULL)
		err(1, "cbl_yarena_alloc");
	if (arcana_services_services_decode(b1.p, b1.len,
	    (struct arcana_services_services *)(uintptr_t)back.services, a,
	    CBL_YD_STRICT, why, sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	if (arcana_services_services_encode(back.services, &b2) != 0)
		errx(1, "encode again");
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" : "not the same");
	printf("-- back\n");
	show(&back);

	/* What a configuration wanted makes of sshd's. */
	sshd = &d.services->service.v[0];
	memset(&want, 0, sizeof(want));
	want.name = "sshd";
	want.has_enabled = true;
	want.enabled = true;
	wv[0] = (yvar){ "sshd_flags", "-o UseDNS=yes" };
	wv[1] = (yvar){ "sshd_program", "/usr/sbin/sshd" };
	wv[2] = (yvar){ "sshd_rsa_enable", "NO" };
	want.variable.n = 3;
	want.variable.v = wv;
	diff("changed", sshd, &want, a);
	want.variable.n = 2;
	wv[0].value = "-o UseDNS=no";
	diff("the same", sshd, &want, a);
	want.variable.n = 1;
	want.enabled = false;
	diff("disabled, one gone", sshd, &want, a);
	wv[0] = (yvar){ "sshd_enable", "NO" };
	diff("its rcvar", sshd, &want, a);
	want.name = "ntpd";
	diff("another", sshd, &want, a);
	want.variable.n = 0;
	want.enabled = true;
	diff("new", NULL, &want, a);
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
	cbl_yarena_free(a);
	return (0);
}
