/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#include "agent.h"

static void	split_list(struct work *, const char *, const char *const **,
		    size_t *);

/* "a,b,c" as an array of pool strings. */
static void
split_list(struct work *w, const char *list, const char *const **vp,
    size_t *np)
{
	const char	**v;
	const char	*p, *q;
	size_t		 n;

	*vp = NULL;
	*np = 0;
	if (list == NULL || *list == '\0')
		return;
	for (n = 1, p = list; (p = strchr(p, ',')) != NULL; p++)
		n++;
	v = wcalloc(w, n, sizeof(*v));
	for (n = 0, p = list; ; p = q + 1) {
		if ((q = strchr(p, ',')) == NULL) {
			v[n++] = wtext(w, wstrdup(w, p));
			break;
		}
		v[n++] = wtext(w, wstrndup(w, p, (size_t)(q - p)));
	}
	*vp = v;
	*np = n;
}

/*
 * One jail record.  ji is the running jail or NULL, cj its configuration
 * or NULL.  Runtime values win; configured ones describe stopped jails.
 */
void
jail_record(struct work *w, struct arc_jail *j, const char *name,
    const struct jinfo *ji, const struct cjail *cj)
{
	const struct arc_param	*p;

	memset(j, 0, sizeof(*j));
	j->name = wtext(w, name);
	j->has_state = true;
	if (ji == NULL && cj == NULL) {
		j->state = ARC_JAIL_STATE_ABSENT;
		return;
	}
	j->state = ji == NULL ? ARC_JAIL_STATE_STOPPED : ji->dying ?
	    ARC_JAIL_STATE_DYING : ARC_JAIL_STATE_RUNNING;
	j->has_configured = true;
	j->configured = cj != NULL;
	if (cj != NULL) {
		j->scope = wtext(w, cj->scope);
		j->interface = cjail_param1(cj, "interface");
		j->params.v = cj->params;
		j->params.n = cj->nparams;
	}
	if (ji != NULL) {
		j->has_jid = true;
		j->jid = (uint32_t)ji->jid;
		j->hostname = wtext(w, ji->hostname);
		j->path = wtext(w, ji->path);
		split_list(w, ji->ip4, &j->ip4.v, &j->ip4.n);
		split_list(w, ji->ip6, &j->ip6.v, &j->ip6.n);
		j->has_vnet = true;
		j->vnet = ji->vnet;
		j->osrelease = wtext(w, ji->osrelease);
		j->has_persist = true;
		j->persist = ji->persist;
		j->has_securelevel = true;
		j->securelevel = ji->securelevel;
		j->has_parent = true;
		j->parent = (uint32_t)ji->parent;
		j->has_children = true;
		j->children = (uint32_t)ji->children;
		j->has_nproc = true;
		j->nproc = ji->nproc;
		j->has_rss_kb = true;
		j->rss_kb = ji->rss_kb;
		j->has_cpu_pct = true;
		j->cpu_pct = ji->cpu_pct;
		return;
	}
	j->hostname = cjail_param1(cj, "host.hostname");
	j->path = cjail_param1(cj, "path");
	if ((p = cjail_param(cj, "ip4.addr")) != NULL) {
		j->ip4.v = p->values.v;
		j->ip4.n = p->values.n;
	}
	if ((p = cjail_param(cj, "ip6.addr")) != NULL) {
		j->ip6.v = p->values.v;
		j->ip6.n = p->values.n;
	}
	p = cjail_param(cj, "vnet");
	j->has_vnet = true;
	j->vnet = p != NULL && (p->values.n == 0 ||
	    strcmp(p->values.v[0], "new") == 0);
	j->has_persist = true;
	j->persist = cjail_param(cj, "persist") != NULL;
}

/* The jail as it is now: re-read runtime state, use conf for the rest. */
struct arc_jail *
jail_current(struct work *w, const char *name, const struct cconf *conf)
{
	struct arc_jail	*j;
	struct jinfo	*list, *ji;
	const char	*e;
	size_t		 n, i;

	list = NULL;
	n = 0;
	(void)jails_running(w, &list, &n, &e);
	ji = NULL;
	for (i = 0; i < n; i++)
		if (list[i].name != NULL && strcmp(list[i].name, name) == 0)
			ji = &list[i];
	if (ji != NULL)
		jails_procstats(w, ji, 1);
	j = wcalloc(w, 1, sizeof(*j));
	jail_record(w, j, name, ji, conf_jail(conf, name));
	return (j);
}
