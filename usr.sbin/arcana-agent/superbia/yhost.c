/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: the host as YANG, arcana-host (PLAN-SDN-YANG 3.1.9): the
 * host attribute set of hello and list, the stats attribute set, and
 * the certs operation's JSON (certs.c) read back into the module's
 * structs.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

static char *
datetime(cbl_yarena *a, int64_t t)
{
	char		buf[32], *p;
	struct tm	tm;
	time_t		tt = (time_t)t;

	if (gmtime_r(&tt, &tm) == NULL || strftime(buf, sizeof(buf),
	    "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		return (NULL);
	if ((p = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL)
		memcpy(p, buf, strlen(buf) + 1);
	return (p);
}

static uint64_t
ident(const char *mod, const char *name)
{

	for (uint32_t i = 0; i < ymodel_schema.nident; i++) {
		const struct cbl_yident *id = &ymodel_schema.ident[i];

		if (strcmp(id->name, name) == 0 &&
		    strcmp(id->module->name, mod) == 0)
			return (id->sid);
	}
	return (0);
}

/* A certificate of the trust store; the two lists have one layout. */
static void
cert_of(cbl_yarena *a, const ucl_object_t *o,
    struct arcana_host_host_certificates_trusted *c)
{
	int64_t	t;

	memset(c, 0, sizeof(*c));
	c->file = yj_str(a, o, "file");
	c->subject = yj_str(a, o, "subject");
	c->common_name = yj_str(a, o, "cn");
	c->organization = yj_str(a, o, "org");
	c->country = yj_str(a, o, "country");
	c->issuer = yj_str(a, o, "issuer");
	if (yj_num(o, "not_before", &t))
		c->not_before = datetime(a, t);
	if (yj_num(o, "not_after", &t))
		c->not_after = datetime(a, t);
	c->sha256 = yj_str(a, o, "sha256");
	c->key = yj_str(a, o, "key");
	c->ca = yj_yes(o, "ca", &c->has_ca);
	c->self_signed = yj_yes(o, "self_signed", &c->has_self_signed);
	c->local = yj_str(a, o, "local");
}

int
yhost_certs_from_json(const char *json, cbl_yarena *a,
    struct arcana_host_host_certificates *out)
{
	struct arcana_host_host_certificates_trusted	*t;
	struct arcana_host_host_certificates_untrusted	*u;
	const ucl_object_t				*e;
	ucl_object_iter_t				 it;
	ucl_object_t					*top;
	int64_t						 n;
	size_t						 k;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->localbase = yj_str(a, top, "localbase");
	out->added_dir = yj_str(a, top, "added_dir");
	out->distrusted_dir = yj_str(a, top, "distrusted_dir");
	out->certctl = yj_yes(top, "certctl", &out->has_certctl);
	if (yj_num(top, "now", &n))
		out->now = datetime(a, n);
	if ((t = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "trusted")) + 1) * sizeof(*t))) == NULL || (u = cbl_yarena_alloc(a,
	    (yj_count(ucl_object_lookup(top, "untrusted")) + 1) *
	    sizeof(*u))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "trusted"), it, e) {
		cert_of(a, e, &t[k]);
		if (t[k].file != NULL)
			k++;
	}
	out->trusted.n = k;
	out->trusted.v = t;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "untrusted"), it, e) {
		cert_of(a, e, (void *)&u[k]);
		if (u[k].file != NULL)
			k++;
	}
	out->untrusted.n = k;
	out->untrusted.v = u;
	ucl_object_unref(top);
	return (0);
}

int
yhost_from(const struct arc_host *h, const struct arc_stats *st,
    const struct arcana_host_host_certificates *certs, cbl_yarena *a,
    struct arcana_host_host *out)
{
	struct arcana_host_host_agent		*ag;
	struct arcana_host_host_stats		*s;
	struct arcana_host_host_stats_pool	*p;
	uint64_t				*pl;
	size_t					 i, n;

	memset(out, 0, sizeof(*out));
	out->hostname = h->hostname;
	out->sysname = h->sysname;
	out->release = h->release;
	out->machine = h->machine;
	out->has_osreldate = h->has_osreldate;
	out->osreldate = h->osreldate;
	out->has_ncpu = h->has_ncpu;
	out->ncpu = h->ncpu;
	out->has_physmem = h->has_physmem;
	out->physmem = h->physmem;
	if (h->has_boottime)
		out->boot_time = datetime(a, h->boottime);
	if (h->has_time)
		out->time = datetime(a, h->time);
	out->has_securelevel = h->has_securelevel;
	out->securelevel = h->securelevel;
	out->has_privileged = h->has_privileged;
	out->privileged = h->privileged;
	if ((ag = cbl_yarena_alloc(a, sizeof(*ag))) == NULL || (pl =
	    cbl_yarena_alloc(a, (h->plugins.n + 1) * sizeof(*pl))) == NULL)
		return (ENOMEM);
	ag->version = h->version;
	ag->build = h->build;
	out->agent = ag;
	/* A plugin the model does not know is left out. */
	for (i = n = 0; i < h->plugins.n; i++)
		if ((pl[n] = ident("arcana-host", h->plugins.v[i])) != 0)
			n++;
	out->plugin.n = n;
	out->plugin.v = pl;
	if (st != NULL) {
		if ((s = cbl_yarena_alloc(a, sizeof(*s))) == NULL || (p =
		    cbl_yarena_alloc(a, (st->pools.n + 1) * sizeof(*p))) ==
		    NULL)
			return (ENOMEM);
		memset(s, 0, sizeof(*s));
		if ((s->has_cpu = st->has_cpu_pct))
			s->cpu = (int64_t)(st->cpu_pct * 10 + 0.5);
		if ((s->has_load1 = st->has_load1))
			s->load1 = (int64_t)(st->load1 * 100 + 0.5);
		if ((s->has_load5 = st->has_load5))
			s->load5 = (int64_t)(st->load5 * 100 + 0.5);
		if ((s->has_load15 = st->has_load15))
			s->load15 = (int64_t)(st->load15 * 100 + 0.5);
		s->has_memory_total = st->has_mem_total;
		s->memory_total = st->mem_total;
		s->has_memory_used = st->has_mem_used;
		s->memory_used = st->mem_used;
		s->has_memory_inactive = st->has_mem_inactive;
		s->memory_inactive = st->mem_inactive;
		s->has_memory_free = st->has_mem_free;
		s->memory_free = st->mem_free;
		s->has_swap_total = st->has_swap_total;
		s->swap_total = st->swap_total;
		s->has_swap_used = st->has_swap_used;
		s->swap_used = st->swap_used;
		for (i = n = 0; i < st->pools.n; i++) {
			if (st->pools.v[i].name == NULL)
				continue;
			memset(&p[n], 0, sizeof(p[n]));
			p[n].name = st->pools.v[i].name;
			p[n].has_size = st->pools.v[i].has_size;
			p[n].size = st->pools.v[i].size;
			p[n].has_allocated = st->pools.v[i].has_alloc;
			p[n].allocated = st->pools.v[i].alloc;
			p[n].has_free = st->pools.v[i].has_free;
			p[n].free = st->pools.v[i].free;
			p[n].health = st->pools.v[i].health;
			n++;
		}
		s->pool.n = n;
		s->pool.v = p;
		out->stats = s;
	}
	out->certificates = certs;
	return (0);
}
