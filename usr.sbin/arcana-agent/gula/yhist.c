/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the history as YANG, arcana-history: the
 * history operation's JSON (history.c) read back into the module's
 * structs: how the agent samples and its limits as configuration,
 * the sampler and its samples as state.  A sample is an array of the
 * fields the reply names, then each interface's in and out, each
 * disk's read and written, each jail's CPU and memory, each FEC relay's
 * plain and added rates: it is taken apart by those names.
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

typedef struct arcana_history_sample ysample;

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

/* The i-th number of an array, as a double; false when none. */
static bool
nth(const ucl_object_t *arr, size_t i, double *v)
{
	const ucl_object_t	*e;

	if ((e = ucl_array_find_index(arr, (unsigned)i)) == NULL ||
	    (ucl_object_type(e) != UCL_INT && ucl_object_type(e) != UCL_FLOAT))
		return (false);
	*v = ucl_object_todouble(e);
	return (true);
}

#define	NTH_U64(arr, i, y, f)	do {					\
	double v_;							\
									\
	if (((y)->has_##f = nth((arr), (i), &v_)))			\
		(y)->f = (uint64_t)(v_ < 0 ? 0 : v_);			\
} while (0)

/* The samples of a reply, each taken apart by the names given. */
static int
samples_of(cbl_yarena *a, const ucl_object_t *top, const char *const *nets,
    size_t nnets, const char *const *disks, size_t ndisks,
    const char *const *jails, size_t njails, const char *const *relays,
    size_t nrelays, size_t *np, const ysample **vp)
{
	struct arcana_history_sample_interface	*ni;
	struct arcana_history_sample_disk		*nd;
	struct arcana_history_sample_jail		*nj;
	struct arcana_history_sample_relay		*nr;
	const ucl_object_t					*e;
	ucl_object_iter_t					 it;
	ysample							*v;
	double							 d;
	size_t							 n = 0, k, i;

	if ((v = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "samples")) + 1) * sizeof(*v))) == NULL)
		return (ENOMEM);
	YJ_EACH(ucl_object_lookup(top, "samples"), it, e) {
		if (ucl_object_type(e) != UCL_ARRAY || !nth(e, 0, &d))
			continue;
		memset(&v[n], 0, sizeof(v[n]));
		v[n].time = datetime(a, (int64_t)d);
		if ((v[n].has_cpu = nth(e, 1, &d)))
			v[n].cpu = (int64_t)(d * 10 + 0.5);
		if ((v[n].has_load = nth(e, 2, &d)))
			v[n].load = (int64_t)(d * 100 + 0.5);
		NTH_U64(e, 3, &v[n], memory);
		NTH_U64(e, 4, &v[n], swap);
		NTH_U64(e, 5, &v[n], received);
		NTH_U64(e, 6, &v[n], sent);
		NTH_U64(e, 7, &v[n], read);
		NTH_U64(e, 8, &v[n], written);
		k = 9;
		if ((ni = cbl_yarena_alloc(a, (nnets + 1) * sizeof(*ni))) ==
		    NULL || (nd = cbl_yarena_alloc(a, (ndisks + 1) *
		    sizeof(*nd))) == NULL || (nj = cbl_yarena_alloc(a,
		    (njails + 1) * sizeof(*nj))) == NULL || (nr =
		    cbl_yarena_alloc(a, (nrelays + 1) * sizeof(*nr))) == NULL)
			return (ENOMEM);
		for (i = 0; i < nnets; i++, k += 2) {
			memset(&ni[i], 0, sizeof(ni[i]));
			ni[i].name = nets[i];
			NTH_U64(e, k, &ni[i], received);
			NTH_U64(e, k + 1, &ni[i], sent);
		}
		for (i = 0; i < ndisks; i++, k += 2) {
			memset(&nd[i], 0, sizeof(nd[i]));
			nd[i].name = disks[i];
			NTH_U64(e, k, &nd[i], read);
			NTH_U64(e, k + 1, &nd[i], written);
		}
		for (i = 0; i < njails; i++, k += 2) {
			memset(&nj[i], 0, sizeof(nj[i]));
			nj[i].name = jails[i];
			if ((nj[i].has_cpu = nth(e, k, &d)))
				nj[i].cpu = (int64_t)(d * 10 + 0.5);
			NTH_U64(e, k + 1, &nj[i], memory);
		}
		for (i = 0; i < nrelays; i++, k += 2) {
			memset(&nr[i], 0, sizeof(nr[i]));
			nr[i].name = relays[i];
			NTH_U64(e, k, &nr[i], plain);
			NTH_U64(e, k + 1, &nr[i], added);
		}
		v[n].interface.n = nnets;
		v[n].interface.v = ni;
		v[n].disk.n = ndisks;
		v[n].disk.v = nd;
		v[n].jail.n = njails;
		v[n].jail.v = nj;
		v[n].relay.n = nrelays;
		v[n].relay.v = nr;
		if (v[n].time != NULL)
			n++;
	}
	*np = n;
	*vp = v;
	return (0);
}

static const char *const rule_kinds[] = { "net", "disk", "jail-cpu",
    "jail-mem" };

int
yhist_from_json(const char *json, cbl_yarena *a,
    struct arcana_history_history *out)
{
	struct arcana_history_history_sampling	*sp;
	struct arcana_history_history_limits	*li;
	struct arcana_history_history_rule	*ru;
	struct arcana_history_history_state	*st;
	const ucl_object_t			*e, *o;
	ucl_object_iter_t			 it;
	ucl_object_t				*top;
	const char				*v;
	size_t					 n, i;
	int					 error = ENOMEM;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if ((sp = cbl_yarena_alloc(a, sizeof(*sp))) == NULL || (li =
	    cbl_yarena_alloc(a, sizeof(*li))) == NULL || (st =
	    cbl_yarena_alloc(a, sizeof(*st))) == NULL)
		goto out;
	memset(sp, 0, sizeof(*sp));
	memset(li, 0, sizeof(*li));
	memset(st, 0, sizeof(*st));
	YJ_NUM(top, "step", sp, step);
	YJ_NUM(top, "keep", sp, keep);
	if ((o = ucl_object_lookup(top, "limits")) != NULL) {
		YJ_NUM(o, "cpu", li, cpu);
		YJ_NUM(o, "mem", li, memory);
		YJ_NUM(o, "swap", li, swap);
		YJ_NUM(o, "storage", li, storage);
	}
	if ((ru = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "rules")) + 1) * sizeof(*ru))) == NULL)
		goto out;
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "rules"), it, e) {
		memset(&ru[n], 0, sizeof(ru[n]));
		if ((v = yj_str(a, e, "kind")) == NULL || (ru[n].name = yj_str(
		    a, e, "name")) == NULL)
			continue;
		ru[n].kind = ARCANA_HISTORY_HISTORY_RULE_KIND_NET;
		for (i = 0; i < nitems(rule_kinds); i++)
			if (strcmp(v, rule_kinds[i]) == 0)
				ru[n].kind = (int)i;
		YJ_NUM(e, "limit", &ru[n], limit);
		ru[n].over = yj_yes(e, "over", &ru[n].has_over);
		n++;
	}
	out->rule.n = n;
	out->rule.v = ru;
	YJ_NUM(top, "bytes", st, bytes);
	YJ_NUM(top, "ncpu", st, ncpu);
	YJ_NUM(top, "mem_total", st, memory_total);
	YJ_NUM(top, "swap_total", st, swap_total);
	st->racct = yj_yes(top, "racct", &st->has_racct);
	if (yj_strs(a, ucl_object_lookup(top, "nets"), &st->interface.n,
	    &st->interface.v) != 0 || yj_strs(a, ucl_object_lookup(top,
	    "disks"), &st->disk.n, &st->disk.v) != 0 || yj_strs(a,
	    ucl_object_lookup(top, "jails"), &st->jail.n, &st->jail.v) != 0 ||
	    yj_strs(a, ucl_object_lookup(top, "relays"), &st->relay.n,
	    &st->relay.v) != 0)
		goto out;
	if ((error = samples_of(a, top, st->interface.v, st->interface.n,
	    st->disk.v, st->disk.n, st->jail.v, st->jail.n, st->relay.v,
	    st->relay.n, &st->sample.n, &st->sample.v)) != 0)
		goto out;
	out->sampling = sp;
	out->limits = li;
	out->state = st;
	error = 0;
out:
	ucl_object_unref(top);
	return (error);
}
