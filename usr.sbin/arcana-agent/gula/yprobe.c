/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the probes as YANG, arcana-probe: each edge's targets, links
 * and monitors (probe.c's probe_conf_json()) as configuration, and
 * back as the JSON do_probes_set() and do_monitors_set() take; the
 * sdwan read's targets as state, each sample taken apart from its row.
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
	struct arcana_probe_target_address	*s = u;
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

/* The thresholds of o's, NULL with none. */
static int
tca_of(cbl_yarena *a, const ucl_object_t *o, const struct arcana_probe_tca **tp)
{
	struct arcana_probe_tca	*t;
	const ucl_object_t	*c;

	*tp = NULL;
	if ((c = ucl_object_lookup(o, "tca")) == NULL)
		return (0);
	if ((t = cbl_yarena_alloc(a, sizeof(*t))) == NULL)
		return (ENOMEM);
	memset(t, 0, sizeof(*t));
	t->has_delay = dec(c, "delay", 3, &t->delay);
	t->has_ipdv = dec(c, "ipdv", 3, &t->ipdv);
	t->has_loss = dec(c, "loss", 6, &t->loss);
	YJ_NUM(c, "damping", t, damping);
	*tp = t;
	return (0);
}

/* An edge's lists, e's ("targets", "links", "monitors"), into its. */
static int
edge_of(cbl_yarena *a, const ucl_object_t *e,
    struct arcana_probe_probes_jail *out)
{
	struct arcana_probe_target	*t;
	struct arcana_probe_link	*l;
	struct arcana_probe_monitor	*m;
	const ucl_object_t		*o, *list;
	ucl_object_iter_t		 it;
	const char			*s;
	size_t				 n;
	int				 error;

	list = ucl_object_lookup(e, "targets");
	if ((t = cbl_yarena_alloc(a, (yj_count(list) + 1) * sizeof(*t))) ==
	    NULL)
		return (ENOMEM);
	n = 0;
	YJ_EACH(list, it, o) {
		memset(&t[n], 0, sizeof(t[n]));
		if ((t[n].id = yj_str(a, o, "id")) == NULL)
			continue;
		t[n].has_address = addr_union(a, o, "address", &t[n].address);
		YJ_NUM(o, "count", &t[n], count);
		YJ_NUM(o, "report", &t[n], report);
		YJ_NUM(o, "fib", &t[n], fib);
		YJ_NUM(o, "interval", &t[n], interval);
		YJ_NUM(o, "size", &t[n], size);
		YJ_NUM(o, "dscp", &t[n], dscp);
		YJ_NUM(o, "down", &t[n], down);
		YJ_NUM(o, "up", &t[n], up);
		YJ_NUM(o, "timeout", &t[n], timeout);
		YJ_NUM(o, "eval", &t[n], eval);
		YJ_NUM(o, "history", &t[n], history);
		if ((error = tca_of(a, o, &t[n].tca)) != 0)
			return (error);
		n++;
	}
	out->target.n = n;
	out->target.v = t;
	list = ucl_object_lookup(e, "links");
	if ((l = cbl_yarena_alloc(a, (yj_count(list) + 1) * sizeof(*l))) ==
	    NULL)
		return (ENOMEM);
	n = 0;
	YJ_EACH(list, it, o) {
		memset(&l[n], 0, sizeof(l[n]));
		if ((l[n].id = yj_str(a, o, "id")) == NULL)
			continue;
		l[n].interface = yj_str(a, o, "interface");
		if ((s = yj_str(a, o, "role")) != NULL) {
			l[n].has_role = true;
			l[n].role = strcmp(s, "uni") == 0 ?
			    ARCANA_PROBE_LINK_ROLE_UNI :
			    ARCANA_PROBE_LINK_ROLE_UCS;
		}
		n++;
	}
	out->link.n = n;
	out->link.v = l;
	list = ucl_object_lookup(e, "monitors");
	if ((m = cbl_yarena_alloc(a, (yj_count(list) + 1) * sizeof(*m))) ==
	    NULL)
		return (ENOMEM);
	n = 0;
	YJ_EACH(list, it, o) {
		memset(&m[n], 0, sizeof(m[n]));
		if ((m[n].name = yj_str(a, o, "id")) == NULL)
			continue;
		m[n].interface = yj_str(a, o, "interface");
		m[n].has_address = addr_union(a, o, "address", &m[n].address);
		YJ_NUM(o, "fib", &m[n], fib);
		YJ_NUM(o, "interval", &m[n], interval);
		YJ_NUM(o, "size", &m[n], size);
		YJ_NUM(o, "dscp", &m[n], dscp);
		YJ_NUM(o, "down", &m[n], down);
		YJ_NUM(o, "up", &m[n], up);
		YJ_NUM(o, "timeout", &m[n], timeout);
		YJ_NUM(o, "eval", &m[n], eval);
		YJ_NUM(o, "history", &m[n], history);
		if ((error = tca_of(a, o, &m[n].tca)) != 0)
			return (error);
		n++;
	}
	out->monitor.n = n;
	out->monitor.v = m;
	return (0);
}

int
yprobe_conf_from_json(const char *json, cbl_yarena *a,
    struct arcana_probe_probes *out)
{
	struct arcana_probe_probes_jail	*j, host;
	const ucl_object_t		*e;
	ucl_object_iter_t		 it;
	ucl_object_t			*top;
	const char			*name;
	size_t				 n = 0;
	int				 error = 0;

	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if ((j = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "edges")) + 1) * sizeof(*j))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "edges"), it, e) {
		name = yj_str(a, e, "jail");
		if (name == NULL || name[0] == '\0') {
			memset(&host, 0, sizeof(host));
			if ((error = edge_of(a, e, &host)) != 0)
				break;
			out->target.n = host.target.n;
			out->target.v = host.target.v;
			out->link.n = host.link.n;
			out->link.v = host.link.v;
			out->monitor.n = host.monitor.n;
			out->monitor.v = host.monitor.v;
			continue;
		}
		memset(&j[n], 0, sizeof(j[n]));
		j[n].name = name;
		if ((error = edge_of(a, e, &j[n])) != 0)
			break;
		n++;
	}
	out->jail.n = n;
	out->jail.v = j;
	ucl_object_unref(top);
	return (error);
}

/* A decimal64 of d fraction digits as a number of o's. */
static void
put_dec(ucl_object_t *o, const char *key, bool has, int64_t v, int d)
{

	if (has)
		ucl_object_insert_key(o, ucl_object_fromdouble((double)v / (d ==
		    6 ? 1000000.0 : 1000.0)), key, 0, true);
}

#define	PUT_INT(o, key, y, f) do {					\
	if ((y)->has_##f)						\
		ucl_object_insert_key((o), ucl_object_fromint((int64_t)	\
		    (y)->f), (key), 0, true);				\
} while (0)

static void
put_tca(ucl_object_t *o, const struct arcana_probe_tca *t)
{
	ucl_object_t	*c;

	if (t == NULL)
		return;
	c = ucl_object_typed_new(UCL_OBJECT);
	put_dec(c, "delay", t->has_delay, t->delay, 3);
	put_dec(c, "ipdv", t->has_ipdv, t->ipdv, 3);
	put_dec(c, "loss", t->has_loss, t->loss, 6);
	PUT_INT(c, "damping", t, damping);
	ucl_object_insert_key(o, c, "tca", 0, true);
}

static char *
emit(ucl_object_t *top)
{
	char	*json;

	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (json);
}

char *
yprobe_edge_json(const char *jail, size_t nt,
    const struct arcana_probe_target *tv, size_t nl,
    const struct arcana_probe_link *lv)
{
	ucl_object_t	*top, *arr, *o;

	top = ucl_object_typed_new(UCL_OBJECT);
	if (jail != NULL && jail[0] != '\0')
		ucl_object_insert_key(top, ucl_object_fromstring(jail), "jail",
		    0, true);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < nt; i++) {
		const struct arcana_probe_target *t = &tv[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(t->id), "id", 0,
		    true);
		if (t->has_address)
			ucl_object_insert_key(o, ucl_object_fromstring(
			    t->address.v.m0), "address", 0, true);
		PUT_INT(o, "count", t, count);
		PUT_INT(o, "report", t, report);
		PUT_INT(o, "fib", t, fib);
		PUT_INT(o, "interval", t, interval);
		PUT_INT(o, "size", t, size);
		PUT_INT(o, "dscp", t, dscp);
		PUT_INT(o, "down", t, down);
		PUT_INT(o, "up", t, up);
		PUT_INT(o, "timeout", t, timeout);
		PUT_INT(o, "eval", t, eval);
		PUT_INT(o, "history", t, history);
		put_tca(o, t->tca);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, "targets", 0, true);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < nl; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(lv[i].id), "id",
		    0, true);
		if (lv[i].interface != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(
			    lv[i].interface), "interface", 0, true);
		ucl_object_insert_key(o, ucl_object_fromstring(lv[i].has_role &&
		    lv[i].role == ARCANA_PROBE_LINK_ROLE_UNI ? "uni" : "ucs"),
		    "role", 0, true);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, "links", 0, true);
	return (emit(top));
}

char *
yprobe_monitors_json(const char *jail, size_t n,
    const struct arcana_probe_monitor *v)
{
	ucl_object_t	*top, *arr, *o;

	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_fromstring(jail != NULL ? jail :
	    ""), "jail", 0, true);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < n; i++) {
		const struct arcana_probe_monitor *m = &v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(m->name), "id", 0,
		    true);
		if (m->interface != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(
			    m->interface), "interface", 0, true);
		if (m->has_address)
			ucl_object_insert_key(o, ucl_object_fromstring(
			    m->address.v.m0), "address", 0, true);
		PUT_INT(o, "fib", m, fib);
		PUT_INT(o, "interval", m, interval);
		PUT_INT(o, "size", m, size);
		PUT_INT(o, "dscp", m, dscp);
		PUT_INT(o, "down", m, down);
		PUT_INT(o, "up", m, up);
		PUT_INT(o, "timeout", m, timeout);
		PUT_INT(o, "eval", m, eval);
		PUT_INT(o, "history", m, history);
		put_tca(o, m->tca);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, "targets", 0, true);
	return (emit(top));
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
    const struct arcana_probe_sample **vp)
{
	struct arcana_probe_sample	*v;
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
	struct arcana_probe_target_state		*v;
	struct arcana_probe_target_state_now	*nw;
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
			    ARCANA_PROBE_TARGET_STATE_FAMILY_IPV6 :
			    ARCANA_PROBE_TARGET_STATE_FAMILY_IPV4;
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
