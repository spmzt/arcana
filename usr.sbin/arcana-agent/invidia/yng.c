/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: netgraph as YANG, arcana-netgraph (PLAN-SDN-YANG 3.1.8): the
 * netgraph kind of the network operation (netgraph.c, ngctl list -l)
 * read back as the module has it.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

int
yng_from_json(const char *json, cbl_yarena *a,
    struct arcana_netgraph_netgraph *out)
{
	struct arcana_netgraph_netgraph_node		*v;
	struct arcana_netgraph_netgraph_node_hook	*h;
	const ucl_object_t				*e, *he;
	ucl_object_iter_t				 it, hit;
	ucl_object_t					*top;
	size_t						 n = 0, k;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if ((v = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "nodes")) + 1) * sizeof(*v))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "nodes"), it, e) {
		memset(&v[n], 0, sizeof(v[n]));
		if ((v[n].id = yj_str(a, e, "id")) == NULL)
			continue;
		v[n].name = yj_str(a, e, "name");
		v[n].type = yj_str(a, e, "type");
		if ((h = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(e,
		    "hooks")) + 1) * sizeof(*h))) == NULL) {
			ucl_object_unref(top);
			return (ENOMEM);
		}
		k = 0;
		YJ_EACH(ucl_object_lookup(e, "hooks"), hit, he) {
			memset(&h[k], 0, sizeof(h[k]));
			if ((h[k].name = yj_str(a, he, "hook")) == NULL)
				continue;
			h[k].peer = yj_str(a, he, "peer");
			h[k].peer_type = yj_str(a, he, "peer-type");
			h[k].peer_id = yj_str(a, he, "peer-id");
			h[k].peer_hook = yj_str(a, he, "peer-hook");
			k++;
		}
		v[n].hook.n = k;
		v[n].hook.v = h;
		n++;
	}
	out->node.n = n;
	out->node.v = v;
	ucl_object_unref(top);
	return (0);
}
