/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the probes as YANG, arcana-probe (PLAN-SDN-YANG 3.1.11): the
 * sdwan-probes operation's targets (probe.c) as configuration, the
 * sdwan read's targets as state, each sample taken apart from its
 * row.
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

static bool
addr_union(cbl_yarena *a, const ucl_object_t *o, const char *key, void *u)
{
	struct arcana_probe_probes_target_address	*s = u;
	const char					*v;

	if ((v = yj_str(a, o, key)) == NULL)
		return (false);
	s->which = strchr(v, ':') != NULL ? 1 : 0;
	s->v.m0 = v;
	return (true);
}

/* A number of o's as a decimal64 of d fraction digits. */
static bool
dec(const ucl_object_t *o, const char *key, int d, int64_t *v)
{
	const ucl_object_t	*e;
	double			 m = d == 6 ? 1000000.0 : 1000.0;

	if ((e = ucl_object_lookup(o, key)) == NULL || (ucl_object_type(e) !=
	    UCL_FLOAT && ucl_object_type(e) != UCL_INT))
		return (false);
	*v = (int64_t)(ucl_object_todouble(e) * m + (ucl_object_todouble(e) <
	    0 ? -0.5 : 0.5));
	return (true);
}

static const char *const states[] = { "unknown", "up", "down", "ended",
    "error" };

int
yprobe_targets_from_json(const char *json, cbl_yarena *a, size_t *np,
    const struct arcana_probe_probes_target **vp)
{
	struct arcana_probe_probes_target	*v;
	struct arcana_probe_probes_target_tca	*t;
	const ucl_object_t			*e, *o, *list;
	ucl_object_iter_t			 it;
	ucl_object_t				*top;
	const char				*jail;
	size_t					 n = 0;

	*np = 0;
	*vp = NULL;
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	/* A jail's edge's: {"jail", "targets"}, each target its. */
	list = top;
	jail = NULL;
	if (ucl_object_type(top) == UCL_OBJECT) {
		jail = yj_str(a, top, "jail");
		list = ucl_object_lookup(top, "targets");
	}
	if ((v = cbl_yarena_alloc(a, (yj_count(list) + 1) * sizeof(*v))) ==
	    NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(list, it, e) {
		memset(&v[n], 0, sizeof(v[n]));
		if ((v[n].id = yj_str(a, e, "id")) == NULL)
			continue;
		v[n].jail = jail;
		v[n].has_address = addr_union(a, e, "address", &v[n].address);
		YJ_NUM(e, "fib", &v[n], fib);
		YJ_NUM(e, "interval", &v[n], interval);
		YJ_NUM(e, "size", &v[n], size);
		YJ_NUM(e, "count", &v[n], count);
		YJ_NUM(e, "dscp", &v[n], dscp);
		YJ_NUM(e, "down", &v[n], down);
		YJ_NUM(e, "up", &v[n], up);
		YJ_NUM(e, "timeout", &v[n], timeout);
		YJ_NUM(e, "eval", &v[n], eval);
		YJ_NUM(e, "history", &v[n], history);
		YJ_NUM(e, "report", &v[n], report);
		if ((o = ucl_object_lookup(e, "tca")) != NULL) {
			if ((t = cbl_yarena_alloc(a, sizeof(*t))) == NULL) {
				ucl_object_unref(top);
				return (ENOMEM);
			}
			memset(t, 0, sizeof(*t));
			t->has_delay = dec(o, "delay", 3, &t->delay);
			t->has_ipdv = dec(o, "ipdv", 3, &t->ipdv);
			t->has_loss = dec(o, "loss", 6, &t->loss);
			YJ_NUM(o, "damping", t, damping);
			v[n].tca = t;
		}
		n++;
	}
	*np = n;
	*vp = v;
	ucl_object_unref(top);
	return (0);
}

/* The i-th number of a row, as a double. */
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

#define	ROW_DEC(arr, i, y, f, m)	do {				\
	double v_;							\
									\
	if (((y)->has_##f = nth((arr), (i), &v_)))			\
		(y)->f = (int64_t)(v_ * (m) + 0.5);			\
} while (0)

/* A target's samples, each a row. */
static int
samples_of(cbl_yarena *a, const ucl_object_t *arr, size_t *np,
    const struct arcana_probe_probes_state_target_sample **vp)
{
	struct arcana_probe_probes_state_target_sample	*v;
	const ucl_object_t				*e;
	ucl_object_iter_t				 it;
	double						 d;
	size_t						 n = 0;

	if ((v = cbl_yarena_alloc(a, (yj_count(arr) + 1) * sizeof(*v))) ==
	    NULL)
		return (ENOMEM);
	YJ_EACH(arr, it, e) {
		if (ucl_object_type(e) != UCL_ARRAY || !nth(e, 0, &d))
			continue;
		memset(&v[n], 0, sizeof(v[n]));
		v[n].time = datetime(a, (int64_t)d);
		ROW_DEC(e, 1, &v[n], delay, 1000.0);
		ROW_DEC(e, 2, &v[n], ipdv, 1000.0);
		ROW_DEC(e, 3, &v[n], loss, 1000000.0);
		ROW_DEC(e, 4, &v[n], min, 1000.0);
		ROW_DEC(e, 5, &v[n], max, 1000.0);
		if ((v[n].has_sent = nth(e, 6, &d)))
			v[n].sent = (uint32_t)d;
		if ((v[n].has_received = nth(e, 7, &d)))
			v[n].received = (uint32_t)d;
		if (v[n].time != NULL)
			n++;
	}
	*np = n;
	*vp = v;
	return (0);
}

int
yprobe_state_from_json(const char *json, cbl_yarena *a,
    struct arcana_probe_probes_state *out)
{
	struct arcana_probe_probes_state_target		*v;
	struct arcana_probe_probes_state_target_now	*nw;
	const ucl_object_t				*e, *o;
	ucl_object_iter_t				 it;
	ucl_object_t					*top;
	const char					*s;
	int64_t						 n;
	size_t						 k = 0, i;
	int						 error;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->probing = yj_yes(top, "probing", &out->has_probing);
	if (yj_num(top, "time", &n))
		out->time = datetime(a, n);
	if ((v = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "targets")) + 1) * sizeof(*v))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "targets"), it, e) {
		memset(&v[k], 0, sizeof(v[k]));
		if ((v[k].id = yj_str(a, e, "id")) == NULL)
			continue;
		v[k].jail = yj_str(a, e, "jail");
		v[k].has_address = addr_union(a, e, "address", &v[k].address);
		if ((s = yj_str(a, e, "family")) != NULL) {
			v[k].has_family = true;
			v[k].family = strcmp(s, "inet6") == 0 ?
			    ARCANA_PROBE_PROBES_STATE_TARGET_FAMILY_IPV6 :
			    ARCANA_PROBE_PROBES_STATE_TARGET_FAMILY_IPV4;
		}
		YJ_NUM(e, "fib", &v[k], fib);
		if ((s = yj_str(a, e, "state")) != NULL)
			for (i = 0; i < nitems(states); i++)
				if (strcmp(s, states[i]) == 0) {
					v[k].has_state = true;
					v[k].state = (int)i;
				}
		v[k].error = yj_str(a, e, "error");
		if (yj_num(e, "since", &n))
			v[k].since = datetime(a, n);
		YJ_NUM(e, "interval", &v[k], interval);
		YJ_NUM(e, "size", &v[k], size);
		YJ_NUM(e, "eval", &v[k], eval);
		YJ_NUM(e, "dscp", &v[k], dscp);
		YJ_NUM(e, "sent", &v[k], sent);
		YJ_NUM(e, "received", &v[k], received);
		YJ_NUM(e, "misses", &v[k], misses);
		v[k].has_last_rtt = dec(e, "last_rtt", 3, &v[k].last_rtt);
		if ((o = ucl_object_lookup(e, "now")) != NULL) {
			if ((nw = cbl_yarena_alloc(a, sizeof(*nw))) == NULL) {
				ucl_object_unref(top);
				return (ENOMEM);
			}
			memset(nw, 0, sizeof(*nw));
			YJ_NUM(o, "sent", nw, sent);
			YJ_NUM(o, "recv", nw, received);
			nw->has_delay = dec(o, "delay", 3, &nw->delay);
			nw->has_ipdv = dec(o, "ipdv", 3, &nw->ipdv);
			nw->has_loss = dec(o, "loss", 6, &nw->loss);
			nw->has_age = dec(o, "age", 3, &nw->age);
			v[k].now = nw;
		}
		YJ_NUM(e, "kept", &v[k], kept);
		if ((error = samples_of(a, ucl_object_lookup(e, "samples"),
		    &v[k].sample.n, &v[k].sample.v)) != 0) {
			ucl_object_unref(top);
			return (error);
		}
		k++;
	}
	out->target.n = k;
	out->target.v = v;
	ucl_object_unref(top);
	return (0);
}
