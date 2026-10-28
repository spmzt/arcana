/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: the packages as arcana-packages has them, the host's or a
 * jail's alike: those installed, as pkg query reads them, each with
 * the version the repository has where that is newer, as pkg version
 * -vRl '<' reads them (packages.c); the repositories pkg has and
 * whether a jail's base is pkgbase beside; and an upgrade's output.
 * The container's and the read and refresh actions' outputs have the
 * same leaves: one filler, ypackages_listed().
 */

#include <errno.h>
#include <string.h>

#include <arcana.h>
#include "agent.h"

#include "collect.h"

/* The host's, a jail's and an upgrade's: one struct (cg:struct). */
typedef struct arcana_packages_package ypkg;

static void
pkg_of(ypkg *y, const struct package *p)
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
 * The packages of installed (pkg query's), each with its newer version
 * from outdated (pkg version's; NULL: not asked); one only outdated has
 * is added.  Strings the reads'; the list a's.
 */
int
ypackages_listed(const struct pkg_read *installed,
    const struct pkg_read *outdated, cbl_yarena *a, const ypkg **vp,
    size_t *np, const char *const **rp, size_t *nrp, bool *has_pkgbase,
    bool *pkgbase)
{
	size_t n = installed->npackages, max;
	ypkg *v;

	/* pkg's repositories there, as the read has them. */
	*rp = installed->repos;
	*nrp = installed->nrepos;
	if ((*has_pkgbase = installed->has_pkgbase))
		*pkgbase = installed->pkgbase;
	*vp = NULL;
	*np = 0;
	max = n + (outdated != NULL ? outdated->npackages : 0);
	if (max == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, max * sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < n; i++)
		pkg_of(&v[i], &installed->packages[i]);
	for (size_t i = 0; outdated != NULL && i < outdated->npackages;
	    i++) {
		const struct package *p = &outdated->packages[i];
		size_t k;

		for (k = 0; k < n && strcmp(v[k].name, p->name) != 0; k++)
			;
		if (k == n)
			pkg_of(&v[n++], p);
		else
			v[k].available = p->available;
	}
	*vp = v;
	*np = n;
	return (0);
}

/* The container's. */
int
ypackages_from(const struct pkg_read *installed,
    const struct pkg_read *outdated, cbl_yarena *a,
    struct arcana_packages_packages *out)
{

	memset(out, 0, sizeof(*out));
	return (ypackages_listed(installed, outdated, a, &out->package.v,
	    &out->package.n, &out->repository.v, &out->repository.n,
	    &out->has_pkgbase, &out->pkgbase));
}

/* An upgrade's outcome as the upgrade action's output. */
int
ypackages_upgraded(const struct pkg_upgraded *rsp, cbl_yarena *a,
    struct arcana_packages_packages_upgrade_output *out)
{
	ypkg	*v = NULL;

	memset(out, 0, sizeof(*out));
	if ((out->has_upgraded = rsp->has_upgraded))
		out->upgraded = rsp->upgraded;
	if (rsp->npackages == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, rsp->npackages * sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < rsp->npackages; i++)
		pkg_of(&v[i], &rsp->packages[i]);
	out->package.n = rsp->npackages;
	out->package.v = v;
	return (0);
}
