/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: FreeBSD's vnet jails as RFC 8530's logical network elements.
 * A jail with a vnet of
 * its own (jail(8)'s vnet = new, VIMAGE) has a whole network stack:
 * interfaces, addresses, FIBs, sockets, firewalls, net.* sysctls, an
 * LNE.  One sharing the host's stack is not.  Each is listed as
 * jail_get(2) gives it, as jls(8) does, the dying ones left out; named
 * as the jail is; managed, the host being able to attach to it.  Its
 * root, lneroot.c's helper in the jail answering, is yserve.c's.
 */

#include <sys/param.h>
#include <sys/jail.h>

#include <errno.h>
#include <jail.h>
#include <stdio.h>
#include <string.h>

#include "cbl_schema.h"
#include "collect.h"

typedef struct ietf_logical_network_element_logical_network_elements_logical_network_element
    ylne;

static const struct ietf_logical_network_element_logical_network_elements_logical_network_element_root
    root;

static char *
astrdup(cbl_yarena *a, const char *s)
{
	size_t len = strlen(s) + 1;
	char *p;

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

int
ylne_elements(cbl_yarena *a,
    const struct ietf_logical_network_element_logical_network_elements **out)
{
	struct ietf_logical_network_element_logical_network_elements *l;
	ylne *v = NULL, *nv;
	size_t n = 0;
	int jid, lastjid;

	*out = NULL;
	for (lastjid = 0;; lastjid = jid) {
		char last[16], name[MAXHOSTNAMELEN], vnet[16];

		snprintf(last, sizeof(last), "%d", lastjid);
		name[0] = vnet[0] = '\0';
		if ((jid = jail_getv(0, "lastjid", last, "name", name, "vnet",
		    vnet, NULL)) == -1) {
			if (errno == ENOENT)
				break;
			return (errno);
		}
		if (strcmp(vnet, "new") != 0)
			continue;
		if ((nv = cbl_yarena_alloc(a, (n + 1) * sizeof(*nv))) == NULL)
			return (ENOMEM);
		if (n > 0)
			memcpy(nv, v, n * sizeof(*nv));
		v = nv;
		memset(&v[n], 0, sizeof(v[n]));
		if ((v[n].name = astrdup(a, name)) == NULL)
			return (ENOMEM);
		v[n].has_managed = true;
		v[n].managed = true;
		v[n].root = &root;
		n++;
	}
	if ((l = cbl_yarena_alloc(a, sizeof(*l))) == NULL)
		return (ENOMEM);
	memset(l, 0, sizeof(*l));
	l->logical_network_element.n = n;
	l->logical_network_element.v = v;
	*out = l;
	return (0);
}
