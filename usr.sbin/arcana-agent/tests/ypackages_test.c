/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ypackages: the packages operations' replies as arcana-packages has
 * them (ypackages.c), for agent_test.sh: pkg-installed's reply of three
 * packages and the outdated reply of two, one of them not installed,
 * merged, a package a line; the host's through YANG-CBOR and back, and
 * a jail's, in arcana-jails's jail; pkg-upgrade's reply as the upgrade
 * action's output.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"

typedef struct arcana_packages_packages_package ypkg;

static const struct arc_package inst[] = {
	{ .name = "bash", .installed = "5.3.3", .has_automatic = true,
	    .automatic = false, .comment = "GNU Project's Bourne Again "
	    "SHell", .has_size = true, .size = 9123456,
	    .origin = "shells/bash" },
	{ .name = "curl", .installed = "8.16.0", .has_automatic = true,
	    .automatic = true, .comment = "Command line tool and library "
	    "for transferring data with URLs", .has_size = true,
	    .size = 4567890, .origin = "ftp/curl" },
	{ .name = "git", .installed = "2.51.0", .has_automatic = true,
	    .automatic = false, .origin = "devel/git" },
};
static const struct arc_package outd[] = {
	{ .name = "curl", .installed = "8.16.0", .available = "8.17.0" },
	{ .name = "vim", .installed = "9.1.1", .available = "9.1.2" },
};
static const struct arc_package upg[] = {
	{ .name = "curl", .installed = "8.16.0", .available = "8.17.0" },
};

static const char *
str(const char *s)
{

	return (s != NULL ? s : "-");
}

static void
show(const char *who, size_t n, const ypkg *v)
{

	for (size_t i = 0; i < n; i++)
		printf("%s %s installed=%s available=%s automatic=%s size=%s "
		    "origin=%s comment=%s\n", who, v[i].name,
		    str(v[i].installed), str(v[i].available),
		    v[i].has_automatic ? (v[i].automatic ? "yes" : "no") :
		    "-", v[i].has_size ? "yes" : "-", str(v[i].origin),
		    str(v[i].comment));
}

static void
same(const char *what, const struct cbl_ybuf *b1, const struct cbl_ybuf *b2)
{

	printf("%s yang-cbor %zu bytes, %s\n", what, b1->len, b1->len ==
	    b2->len && memcmp(b1->p, b2->p, b1->len) == 0 ? "the same back" :
	    "not the same");
}

int
main(void)
{
	struct arc_packages_rsp ri, ro;
	struct arc_pkg_upgrade_rsp ru;
	struct arcana_packages_packages host, hback;
	struct arcana_packages_packages_upgrade_output up;
	struct arcana_jails_jails js, jback;
	struct arcana_jails_jails_jail jail;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	cbl_yarena *a;
	char why[256];
	int error;

	static const char *const repos[] = { "FreeBSD-ports", "builder" };

	memset(&ri, 0, sizeof(ri));
	ri.packages.n = 3;
	ri.packages.v = inst;
	ri.pkg_repos.n = 2;
	ri.pkg_repos.v = repos;
	memset(&ro, 0, sizeof(ro));
	ro.packages.n = 2;
	ro.packages.v = outd;
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if ((error = ypackages_from(&ri, &ro, a, &host)) != 0)
		errc(1, error, "ypackages_from");
	show("host", host.package.n, host.package.v);
	if (arcana_packages_packages_encode(&host, &b1) != 0)
		errx(1, "encode");
	if (arcana_packages_packages_decode(b1.p, b1.len, &hback, a,
	    CBL_YD_STRICT, why, sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	if (arcana_packages_packages_encode(&hback, &b2) != 0)
		errx(1, "encode again");
	same("host", &b1, &b2);
	show("back", hback.package.n, hback.package.v);
	for (size_t i = 0; i < hback.repository.n; i++)
		printf("back repository %s\n", hback.repository.v[i]);
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);

	/* A jail's: the same, in arcana-jails's jail. */
	memset(&jail, 0, sizeof(jail));
	jail.name = "web";
	jail.arcpkg_packages = (const void *)&host;
	memset(&js, 0, sizeof(js));
	js.jail.n = 1;
	js.jail.v = &jail;
	if (arcana_jails_jails_encode(&js, &b1) != 0)
		errx(1, "encode the jail");
	if (arcana_jails_jails_decode(b1.p, b1.len, &jback, a, CBL_YD_STRICT,
	    why, sizeof(why)) != 0)
		errx(1, "decode the jail: %s", why);
	if (arcana_jails_jails_encode(&jback, &b2) != 0)
		errx(1, "encode the jail again");
	same("jail", &b1, &b2);
	if (jback.jail.n == 1 && jback.jail.v[0].arcpkg_packages != NULL)
		show(jback.jail.v[0].name,
		    jback.jail.v[0].arcpkg_packages->package.n,
		    (const ypkg *)(const void *)
		    jback.jail.v[0].arcpkg_packages->package.v);
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);

	memset(&ru, 0, sizeof(ru));
	ru.has_upgraded = true;
	ru.upgraded = 1;
	ru.packages.n = 1;
	ru.packages.v = upg;
	if ((error = ypackages_upgraded(&ru, a, &up)) != 0)
		errc(1, error, "ypackages_upgraded");
	printf("upgraded %u\n", up.upgraded);
	show("upgrade", up.package.n, (const ypkg *)(const void *)
	    up.package.v);
	cbl_yarena_free(a);
	return (0);
}
