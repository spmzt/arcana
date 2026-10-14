/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: FreeBSD's FIBs as RFC 8529's network instances (PLAN-SDN-YANG
 * 2.6.1, docs/notes/rfc8529.md).  The kernel makes net.fibs FIBs at boot
 * (a vnet jail its own), numbered from 0, and none after; FIB 0 is the
 * host's, ietf-routing's at the top, and each other one an instance, a
 * VRF (arcana-network-instance: the fib case, the vrf-root root).
 *
 * A FIB has no name.  Arcana keeps the names, and the descriptions, in
 * fibs.conf, sh(1) assignments as rc.conf's (libvarconf):
 *
 *	fib2_name="blue"
 *	fib2_description="the blue customer's"
 *
 * A FIB not named there is fibN.  A name is one no other instance has,
 * of printable characters; one of the form fibM is FIB M's alone.  What
 * the file has that cannot be read so is said, not guessed: the
 * variable and why.
 */

#include <sys/types.h>
#include <sys/sysctl.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_schema.h"
#include "collect.h"
#include "varconf.h"

typedef struct ietf_network_instance_network_instances_network_instance
    yni;

#define	NI_TYPE(x)	IETF_NETWORK_INSTANCE_NETWORK_INSTANCES_NETWORK_INSTANCE_NI_TYPE_##x
#define	ROOT_TYPE(x)	IETF_NETWORK_INSTANCE_NETWORK_INSTANCES_NETWORK_INSTANCE_ROOT_TYPE_##x

static const struct ietf_network_instance_network_instances_network_instance_vrf_root
    vrf_root;

static char *
astrdup(cbl_yarena *a, const char *s)
{
	size_t len = strlen(s) + 1;
	char *p;

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

/* net.fibs: how many FIBs the kernel has, this vnet's. */
int
yni_nfibs(void)
{
	int n;
	size_t len = sizeof(n);

	if (sysctlbyname("net.fibs", &n, &len, NULL, 0) == -1)
		return (-1);
	return (n);
}

/* fibM: FIB M's name, M; else -1. */
static long
fib_form(const char *name)
{
	char *end;
	long n;

	if (strncmp(name, "fib", 3) != 0 || !isdigit((unsigned char)name[3]) ||
	    (name[3] == '0' && name[4] != '\0'))
		return (-1);
	n = strtol(name + 3, &end, 10);
	return (*end == '\0' && n >= 0 && n <= 65535 ? n : -1);
}

/* Why name cannot be FIB fib's; NULL: it can. */
static const char *
bad_name(const char *name, int fib)
{
	long m;

	if (name[0] == '\0')
		return ("an empty name");
	for (const char *p = name; *p != '\0'; p++)
		if (!isprint((unsigned char)*p))
			return ("a name of other than printable characters");
	if ((m = fib_form(name)) != -1 && m != fib)
		return ("another FIB's name");
	return (NULL);
}

static int
unread(cbl_yarena *a, struct yunread **u, size_t *nu, const char *var,
    const char *why)
{
	struct yunread *nv;

	if ((nv = cbl_yarena_alloc(a, (*nu + 1) * sizeof(*nv))) == NULL)
		return (ENOMEM);
	if (*nu > 0)
		memcpy(nv, *u, *nu * sizeof(*nv));
	nv[*nu].var = astrdup(a, var);
	nv[*nu].why = why;
	*u = nv;
	(*nu)++;
	return (0);
}

/* FIB n's variable v: its value, or NULL, what is wrong said. */
static const char *
var(const struct vc_file *f, int n, const char *v, cbl_yarena *a,
    struct yunread **u, size_t *nu, int *error)
{
	const struct vc_assign *as;
	char name[32];

	snprintf(name, sizeof(name), "fib%d_%s", n, v);
	if (f == NULL || (as = vc_get(f, name)) == NULL)
		return (NULL);
	if (!vc_settled(f, name) || as->value == NULL) {
		*error = unread(a, u, nu, name,
		    "not settled by reading the file");
		return (NULL);
	}
	return (as->value);
}

int
yni_read(const struct vc_file *f, int nfibs, cbl_yarena *a,
    const struct ietf_network_instance_network_instances **out,
    struct yunread **u, size_t *nu)
{
	struct ietf_network_instance_network_instances *nis;
	yni *v;
	size_t n = 0;
	int error = 0;

	*out = NULL;
	*u = NULL;
	*nu = 0;
	if ((nis = cbl_yarena_alloc(a, sizeof(*nis))) == NULL)
		return (ENOMEM);
	memset(nis, 0, sizeof(*nis));
	if (nfibs > 1 && (v = cbl_yarena_alloc(a, (size_t)(nfibs - 1) *
	    sizeof(*v))) == NULL)
		return (ENOMEM);
	for (int fib = 1; fib < nfibs && error == 0; fib++) {
		const char *name, *why, *desc;
		char def[16], vname[32];

		memset(&v[n], 0, sizeof(v[n]));
		snprintf(def, sizeof(def), "fib%d", fib);
		snprintf(vname, sizeof(vname), "fib%d_name", fib);
		name = var(f, fib, "name", a, u, nu, &error);
		if (name != NULL && (why = bad_name(name, fib)) != NULL) {
			error = unread(a, u, nu, vname, why);
			name = NULL;
		}
		/* Taken by one before it: this one is fibN. */
		for (size_t k = 0; name != NULL && k < n; k++)
			if (strcmp(v[k].name, name) == 0) {
				error = unread(a, u, nu, vname,
				    "another FIB's name");
				name = NULL;
			}
		v[n].name = astrdup(a, name != NULL ? name : def);
		v[n].has_enabled = true;
		v[n].enabled = true;
		if ((desc = var(f, fib, "description", a, u, nu, &error)) !=
		    NULL)
			v[n].description = astrdup(a, desc);
		v[n].ni_type = NI_TYPE(FIB);
		v[n].has_arcni_fib = true;
		v[n].arcni_fib = (uint16_t)fib;
		v[n].root_type = ROOT_TYPE(VRF_ROOT);
		v[n].vrf_root = &vrf_root;
		n++;
	}
	if (error != 0)
		return (error);
	/* Names for FIBs there are not. */
	for (size_t i = 0; f != NULL && i < f->na; i++) {
		const char *nm = f->a[i].name;
		char *end;
		long fib;

		if (strncmp(nm, "fib", 3) != 0)
			continue;
		fib = strtol(nm + 3, &end, 10);
		if (end == nm + 3 || (strcmp(end, "_name") != 0 &&
		    strcmp(end, "_description") != 0))
			continue;
		if (fib == 0)
			error = unread(a, u, nu, nm, "FIB 0 is the host's, "
			    "not an instance");
		else if (fib >= nfibs)
			error = unread(a, u, nu, nm, "no such FIB: net.fibs "
			    "is fewer");
		if (error != 0)
			return (error);
	}
	nis->network_instance.n = n;
	nis->network_instance.v = n > 0 ? v : NULL;
	*out = nis;
	return (0);
}

/*
 * ni's names and descriptions into fibs.conf f: each instance's FIB its
 * fib leaf's, below nfibs; the name fibN, or none, the variable taken
 * out.  Refused, nothing changed: what cannot be.
 */
int
yni_write(struct vc_file *f, int nfibs,
    const struct ietf_network_instance_network_instances *ni, char *err,
    size_t errlen)
{
	size_t n = ni != NULL ? ni->network_instance.n : 0;
	const yni *v = n > 0 ? ni->network_instance.v : NULL;

	for (size_t i = 0; i < n; i++) {
		const char *why;

		if (v[i].ni_type != NI_TYPE(FIB) || !v[i].has_arcni_fib) {
			snprintf(err, errlen, "%s: no FIB", v[i].name);
			return (EINVAL);
		}
		if (v[i].arcni_fib >= nfibs) {
			snprintf(err, errlen, "%s: FIB %u, net.fibs is %d",
			    v[i].name, v[i].arcni_fib, nfibs);
			return (EINVAL);
		}
		if (v[i].has_enabled && !v[i].enabled) {
			snprintf(err, errlen, "%s: a FIB cannot be disabled",
			    v[i].name);
			return (EINVAL);
		}
		if ((why = bad_name(v[i].name, v[i].arcni_fib)) != NULL) {
			snprintf(err, errlen, "%s: %s", v[i].name, why);
			return (EINVAL);
		}
		for (size_t k = 0; k < i; k++)
			if (v[k].arcni_fib == v[i].arcni_fib) {
				snprintf(err, errlen, "%s, %s: FIB %u twice",
				    v[k].name, v[i].name, v[i].arcni_fib);
				return (EINVAL);
			}
	}
	for (int fib = 1; fib < nfibs; fib++) {
		const yni *e = NULL;
		char name[32], def[16];

		for (size_t i = 0; i < n && e == NULL; i++)
			if (v[i].arcni_fib == fib)
				e = &v[i];
		snprintf(def, sizeof(def), "fib%d", fib);
		snprintf(name, sizeof(name), "fib%d_name", fib);
		if (e != NULL && strcmp(e->name, def) != 0) {
			if (vc_set(f, name, e->name, err, errlen) == -1)
				return (errno);
		} else if (vc_unset(f, name, err, errlen) == -1)
			return (errno);
		snprintf(name, sizeof(name), "fib%d_description", fib);
		if (e != NULL && e->description != NULL) {
			if (vc_set(f, name, e->description, err, errlen) == -1)
				return (errno);
		} else if (vc_unset(f, name, err, errlen) == -1)
			return (errno);
	}
	return (0);
}
