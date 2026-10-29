/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yservices: the services as arcana-services has them (yservices.c),
 * for agent_test.sh: a list of three scripts, sshd's variables as the
 * files rc(8) reads give them, written a field a line and through
 * YANG-CBOR and back; one service as the read action gives it; then
 * what yservices_diff() makes of a configuration wanted, a case a
 * line.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

#include <arcana.h>

#include "agent.h"
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
static yvar sshd_vars[] = {
	{ .name = "sshd_flags", .value = "-o UseDNS=no" },
	{ .name = "sshd_program", .value = "/usr/sbin/sshd" },
};
static const char *sshd_cmds[] = { "configtest", "keygen", "reload" };

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
	struct services_rsp list;
	struct service_config_rsp rd;
	struct arcana_services_services_service_read_output ro;
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
	list.services.v = (struct arc_service *)(uintptr_t)svcs;
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if ((error = yservices_from(&list, a, &d)) != 0)
		errc(1, error, "yservices_from");
	/* As the files rc(8) reads give them (ysvcedit.c). */
	((yservice *)(uintptr_t)&d.services->service.v[0])->variable.n = 2;
	((yservice *)(uintptr_t)&d.services->service.v[0])->variable.v =
	    sshd_vars;
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

	/* One service as the read action has it. */
	memset(&rd, 0, sizeof(rd));
	rd.has_ok = rd.ok = true;
	rd.service_result = (struct arc_service *)(uintptr_t)&svcs[0];
	rd.description = "Secure Shell Daemon";
	rd.commands.n = 3;
	rd.commands.v = sshd_cmds;
	yservices_read(&rd, &ro);
	printf("read enabled=%s path=%s rcvar=%s running=%s pid=%u "
	    "status=%s description=%s\n", ro.has_enabled ? (ro.enabled ?
	    "yes" : "no") : "-", str(ro.path), str(ro.rcvar), ro.has_running ?
	    (ro.running ? "yes" : "no") : "-", ro.has_pid ? ro.pid : 0,
	    str(ro.status), str(ro.description));
	for (size_t k = 0; k < ro.command.n; k++)
		printf("  command %s\n", ro.command.v[k]);

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
