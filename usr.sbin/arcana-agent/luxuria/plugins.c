/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: what is not FreeBSD's own.  A plugin works through a program
 * that has to be installed, and is there only where its program is:
 * BIRD through birdc(8), WireGuard's keys and peers through wg(8) (the
 * interface itself, if_wg(4) made by ifconfig(8), is the base system's
 * and Invidia's).  A host says which it has, and so does a jail with a
 * network of its own, where the program is the jail's.
 */

#include <sys/param.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"

static const struct {
	const char		*name;
	const char *const	*program;
} plugins[] = {
	{ "bird", &opts.birdc_bin },
	{ "wireguard", &opts.wg_bin },
};

/*
 * The plugins there are beneath root, the root of a jail, or on the
 * host when root is NULL: those whose program can be run there.
 */
void
plugins_there(struct work *w, const char *root, const char *const **vp,
    size_t *np)
{
	const char	**v, *path;
	size_t		  i, n;

	v = wcalloc(w, nitems(plugins), sizeof(*v));
	n = 0;
	for (i = 0; i < nitems(plugins); i++) {
		path = *plugins[i].program;
		if (root != NULL && strcmp(root, "/") != 0)
			path = wfmt(w, "%s%s", root, path);
		if (access(path, X_OK) == 0)
			v[n++] = plugins[i].name;
	}
	*vp = v;
	*np = n;
}
