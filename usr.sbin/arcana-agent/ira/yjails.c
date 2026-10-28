/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: the jails as arcana-jails has them, from what the jails read
 * finds (do_list(): jail_get(2) and jail(8) -e of each configuration
 * file); its actions, start, stop, restart and kill, do_action()'s
 * (lifecycle.c, yarcana.c).  One source for the state and the module's
 * data: they cannot drift.
 */

#include <errno.h>
#include <string.h>

#include <arcana.h>
#include "agent.h"
#include "collect.h"

typedef struct arcana_jails_jails_jail yjail;

/* The strings point into rsp's; a's the rest. */
int
yjails_from_list(const struct jails_read *rsp, cbl_yarena *a,
    struct arcana_jails *out)
{
	struct arcana_jails_jails *js;
	struct arcana_jails_jails_conf_error *ce = NULL;
	yjail *v = NULL;

	memset(out, 0, sizeof(*out));
	if ((js = cbl_yarena_alloc(a, sizeof(*js))) == NULL ||
	    (rsp->njails > 0 && (v = cbl_yarena_alloc(a, rsp->njails *
	    sizeof(*v))) == NULL) ||
	    (rsp->nerrors > 0 && (ce = cbl_yarena_alloc(a,
	    rsp->nerrors * sizeof(*ce))) == NULL))
		return (ENOMEM);
	memset(js, 0, sizeof(*js));
	js->scope.n = rsp->nscopes;
	js->scope.v = rsp->scopes;
	for (size_t i = 0; i < rsp->nerrors; i++) {
		ce[i].scope = rsp->errors[i].scope;
		ce[i].message = rsp->errors[i].message;
	}
	js->conf_error.n = rsp->nerrors;
	js->conf_error.v = ce;
	for (size_t i = 0; i < rsp->njails; i++) {
		const struct arc_jail *j = &rsp->jails[i];
		yjail *y = &v[i];

		memset(y, 0, sizeof(*y));
		y->name = j->name;
		if ((y->has_boot = j->has_boot))
			y->boot = j->boot;
		/* jail-state's values are the wire's. */
		if ((y->has_state = j->has_state))
			y->state = (enum arcana_jails_jails_jail_state)j->state;
		if ((y->has_jid = j->has_jid))
			y->jid = j->jid;
		if ((y->has_configured = j->has_configured))
			y->configured = j->configured;
		y->scope = j->scope;
		y->hostname = j->hostname;
		y->path = j->path;
		y->ip4.n = j->ip4.n;
		y->ip4.v = j->ip4.v;
		y->ip6.n = j->ip6.n;
		y->ip6.v = j->ip6.v;
		if ((y->has_vnet = j->has_vnet))
			y->vnet = j->vnet;
		y->osrelease = j->osrelease;
		if ((y->has_persist = j->has_persist))
			y->persist = j->persist;
		if ((y->has_securelevel = j->has_securelevel))
			y->securelevel = j->securelevel;
		if ((y->has_parent = j->has_parent))
			y->parent = j->parent;
		if ((y->has_children = j->has_children))
			y->children = j->children;
		if ((y->has_nproc = j->has_nproc))
			y->nproc = j->nproc;
		if ((y->has_rss = j->has_rss_kb))
			y->rss = j->rss_kb;
		/* Hundredths on the wire and in the module alike. */
		if ((y->has_cpu = j->has_cpu_pct))
			y->cpu = j->cpu_pct;
		y->interface = j->interface;
		if (j->params.n > 0) {
			struct arcana_jails_jails_jail_param *p;

			if ((p = cbl_yarena_alloc(a, j->params.n *
			    sizeof(*p))) == NULL)
				return (ENOMEM);
			for (size_t k = 0; k < j->params.n; k++) {
				p[k].name = j->params.v[k].key;
				p[k].value.n = j->params.v[k].values.n;
				p[k].value.v = j->params.v[k].values.v;
			}
			y->param.n = j->params.n;
			y->param.v = p;
		}
		y->allow.n = j->allow.n;
		y->allow.v = j->allow.v;
		y->plugin.n = j->plugins.n;
		y->plugin.v = j->plugins.v;
		/* An LNE while it runs with a vnet of its own (ylne.c). */
		if (j->has_vnet && j->vnet && j->has_state &&
		    j->state == ARC_JAIL_STATE_RUNNING)
			y->lne = j->name;
	}
	js->jail.n = rsp->njails;
	js->jail.v = v;
	out->jails = js;
	return (0);
}
