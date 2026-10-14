/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: the packages as arcana-packages has them (PLAN-SDN-YANG 3.1.3),
 * the host's or a jail's alike: those installed, as the packages
 * operation reads them with pkg-installed (pkg query), each with the
 * version the repository has where that is newer, as it reads them
 * without (pkg version -vRl '<'); and an upgrade's output, as
 * pkg-upgrade's reply has it.  The actions are the operations'
 * (packages.c).
 */

#include <errno.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"

typedef struct arcana_packages_packages_package ypkg;

/* A jail's are the same grouping's: the same layout, another name. */
_Static_assert(sizeof(struct arcana_jails_jails_jail_arcpkg_packages) ==
    sizeof(struct arcana_packages_packages), "the grouping's structs");
_Static_assert(sizeof(struct arcana_jails_jails_jail_arcpkg_packages_package)
    == sizeof(ypkg), "the grouping's structs");

static void
pkg_of(ypkg *y, const struct arc_package *p)
{

	memset(y, 0, sizeof(*y));
	y->name = p->name;
	y->installed = p->installed;
	y->available = p->available;
	if ((y->has_automatic = p->has_automatic))
		y->automatic = p->automatic;
	y->comment = p->comment;
	if ((y->has_size = p->has_size))
		y->size = p->size;
	y->origin = p->origin;
}

/*
 * The packages of installed (pkg-installed's reply), each with its
 * newer version from outdated (the reply without; NULL: not asked); one
 * only outdated has is added.  Strings the replies'.
 */
int
ypackages_from(const struct arc_packages_rsp *installed,
    const struct arc_packages_rsp *outdated, cbl_yarena *a,
    struct arcana_packages_packages *out)
{
	size_t n = installed->packages.n, max;
	ypkg *v;

	memset(out, 0, sizeof(*out));
	max = n + (outdated != NULL ? outdated->packages.n : 0);
	if (max == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, max * sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < n; i++)
		pkg_of(&v[i], &installed->packages.v[i]);
	for (size_t i = 0; outdated != NULL && i < outdated->packages.n;
	    i++) {
		const struct arc_package *p = &outdated->packages.v[i];
		size_t k;

		for (k = 0; k < n && strcmp(v[k].name, p->name) != 0; k++)
			;
		if (k == n)
			pkg_of(&v[n++], p);
		else
			v[k].available = p->available;
	}
	out->package.n = n;
	out->package.v = v;
	return (0);
}

/* pkg-upgrade's reply as the upgrade action's output. */
int
ypackages_upgraded(const struct arc_pkg_upgrade_rsp *rsp, cbl_yarena *a,
    struct arcana_packages_packages_upgrade_output *out)
{
	struct arcana_packages_packages_upgrade_output_package *v = NULL;

	_Static_assert(sizeof(*v) == sizeof(ypkg), "the grouping's structs");
	memset(out, 0, sizeof(*out));
	if ((out->has_upgraded = rsp->has_upgraded))
		out->upgraded = rsp->upgraded;
	if (rsp->packages.n == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, rsp->packages.n * sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < rsp->packages.n; i++)
		pkg_of((ypkg *)(void *)&v[i], &rsp->packages.v[i]);
	out->package.n = rsp->packages.n;
	out->package.v = v;
	return (0);
}
