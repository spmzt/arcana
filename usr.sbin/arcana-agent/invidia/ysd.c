/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the SD-WAN edge as YANG, arcana-sdwan.  Its configuration is
 * what the setters keep (sdwan.c's rules and steering, the luxuria
 * instances of BIRD, dnsmasq, unbound, Squid and Suricata), read back
 * from their files, and made again the JSON they take when an EDIT
 * changes it; its state is the sdwan read (do_sdwan_state(): sdwan.c's,
 * the luxuria instances', record.c's, sa.c's and faults.c's parts).
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

#define	SEC_PREFIX	"sec-"

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

static const char *
dup(cbl_yarena *a, const char *s)
{
	char	*d;

	if (s == NULL || (d = cbl_yarena_alloc(a, strlen(s) + 1)) == NULL)
		return (NULL);
	memcpy(d, s, strlen(s) + 1);
	return (d);
}

/* An address of o's into a union of ip-address-no-zone's layout. */
struct addr_u {
	unsigned	 which;
	union {
		const char	*m0;
		const char	*m1;
	} v;
};

static bool
addr_union(cbl_yarena *a, const ucl_object_t *o, const char *key, void *u)
{
	struct addr_u	*s = u;
	const char	*v;

	if ((v = yj_str(a, o, key)) == NULL)
		return (false);
	s->which = strchr(v, ':') != NULL ? 1 : 0;
	s->v.m0 = v;
	return (true);
}

#define	ALLOC_N(a, p, n)	(((p) = cbl_yarena_alloc((a), ((n) + 1) * \
	sizeof(*(p)))) != NULL)

/* An object of o's (lists, lua) as name and text pairs. */
struct named {
	const char	*name;
	const char	*text;
};

static int
named_of(cbl_yarena *a, const ucl_object_t *o, size_t *np,
    const struct named **vp)
{
	struct named		*v;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	size_t			 n = 0;

	*np = 0;
	*vp = NULL;
	if (o == NULL || ucl_object_type(o) != UCL_OBJECT)
		return (0);
	if (!ALLOC_N(a, v, o->len))
		return (ENOMEM);
	YJ_EACH(o, it, e) {
		if (ucl_object_type(e) != UCL_STRING)
			continue;
		v[n].name = dup(a, ucl_object_key(e));
		v[n].text = dup(a, ucl_object_tostring(e));
		n++;
	}
	*np = n;
	*vp = v;
	return (0);
}

/* A form of o's as JSON text, the arena's. */
static const char *
spec_of(cbl_yarena *a, const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;
	unsigned char		*t;
	const char		*s;

	if ((v = ucl_object_lookup(o, key)) == NULL || ucl_object_type(v) !=
	    UCL_OBJECT || (t = ucl_object_emit(v, UCL_EMIT_JSON_COMPACT)) ==
	    NULL)
		return (NULL);
	s = dup(a, (const char *)t);
	free(t);
	return (s);
}

/* A string of o's, a number made one. */
static const char *
forced(cbl_yarena *a, const ucl_object_t *o)
{

	return (o == NULL ? NULL : dup(a, ucl_object_tostring_forced(o)));
}

int
ysd_rules_from_json(const char *json, cbl_yarena *a,
    struct arcana_sdwan_rules_config *out)
{
	struct arcana_sdwan_rules_config_table		*t;
	struct arcana_sdwan_rules_config_table_entry	*en;
	struct arcana_sdwan_rules_config_rule		*r;
	const ucl_object_t				*e, *ee;
	ucl_object_iter_t				 it, eit;
	ucl_object_t					*top;
	const char					*v;
	size_t						 n, k;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	YJ_NUM(top, "set", out, set);
	if (!ALLOC_N(a, t, yj_count(ucl_object_lookup(top, "tables"))) ||
	    !ALLOC_N(a, r, yj_count(ucl_object_lookup(top, "rules"))) ||
	    yj_strs(a, ucl_object_lookup(top, "objects"), &out->object.n,
	    &out->object.v) != 0)
		goto nomem;
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "tables"), it, e) {
		memset(&t[n], 0, sizeof(t[n]));
		if ((t[n].name = yj_str(a, e, "name")) == NULL)
			continue;
		if ((v = yj_str(a, e, "valtype")) != NULL) {
			t[n].has_valtype = true;
			t[n].valtype = strcmp(v, "ipv4") == 0 ?
			    ARCANA_SDWAN_RULES_CONFIG_TABLE_VALTYPE_IPV4 :
			    strcmp(v, "ipv6") == 0 ?
			    ARCANA_SDWAN_RULES_CONFIG_TABLE_VALTYPE_IPV6 :
			    strcmp(v, "legacy") == 0 ?
			    ARCANA_SDWAN_RULES_CONFIG_TABLE_VALTYPE_LEGACY :
			    ARCANA_SDWAN_RULES_CONFIG_TABLE_VALTYPE_SKIPTO;
		}
		if (!ALLOC_N(a, en, yj_count(ucl_object_lookup(e, "entries"))))
			goto nomem;
		k = 0;
		/* An entry is [prefix, value], or {prefix, value}. */
		YJ_EACH(ucl_object_lookup(e, "entries"), eit, ee) {
			const ucl_object_t	*p, *q;

			if (ucl_object_type(ee) == UCL_ARRAY) {
				p = ucl_array_find_index(ee, 0);
				q = ucl_array_find_index(ee, 1);
				if (p == NULL || ucl_object_type(p) != UCL_STRING)
					continue;
				en[k].prefix = forced(a, p);
				en[k].value = forced(a, q);
			} else {
				if ((en[k].prefix = yj_str(a, ee, "prefix")) ==
				    NULL)
					continue;
				en[k].value = forced(a, ucl_object_lookup(ee,
				    "value"));
			}
			k++;
		}
		t[n].entry.n = k;
		t[n].entry.v = en;
		n++;
	}
	out->table.n = n;
	out->table.v = t;
	n = 0;
	/* A rule is "number words", or {number, text}; their order kept. */
	YJ_EACH(ucl_object_lookup(top, "rules"), it, e) {
		memset(&r[n], 0, sizeof(r[n]));
		if (ucl_object_type(e) == UCL_STRING) {
			const char	*s = ucl_object_tostring(e);
			char		*end;

			r[n].number = (uint32_t)strtoul(s, &end, 10);
			if (end == s)
				continue;
			end += strspn(end, " ");
			r[n].text = dup(a, end);
		} else {
			int64_t	num;

			if (!yj_num(e, "number", &num) && !yj_num(e, "num", &num))
				continue;
			r[n].number = (uint32_t)num;
			r[n].text = yj_str(a, e, "text");
		}
		r[n].has_number = true;
		r[n].index = (uint32_t)n;
		n++;
	}
	out->rule.n = n;
	out->rule.v = r;
	ucl_object_unref(top);
	return (0);
nomem:
	ucl_object_unref(top);
	return (ENOMEM);
}

int
ysd_steer_from_json(const char *json, cbl_yarena *a,
    struct arcana_sdwan_steer_config *out)
{
	struct arcana_sdwan_steer_config_entry		*en;
	struct arcana_sdwan_steer_config_entry_candidate *c;
	struct arcana_sdwan_steer_config_route		*ro;
	struct arcana_sdwan_steer_config_route_candidate *rc;
	const ucl_object_t				*e, *ce;
	ucl_object_iter_t				 it, cit;
	ucl_object_t					*top;
	int64_t						 num;
	size_t						 n = 0, k;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if (!ALLOC_N(a, en, yj_count(ucl_object_lookup(top, "entries")))) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "entries"), it, e) {
		memset(&en[n], 0, sizeof(en[n]));
		if ((en[n].table = yj_str(a, e, "table")) == NULL || (
		    en[n].prefix = yj_str(a, e, "prefix")) == NULL)
			continue;
		if (!ALLOC_N(a, c, yj_count(ucl_object_lookup(e,
		    "candidates")))) {
			ucl_object_unref(top);
			return (ENOMEM);
		}
		k = 0;
		YJ_EACH(ucl_object_lookup(e, "candidates"), cit, ce) {
			memset(&c[k], 0, sizeof(c[k]));
			if ((c[k].id = yj_str(a, ce, "id")) == NULL)
				continue;
			c[k].has_via = addr_union(a, ce, "via", &c[k].via);
			k++;
		}
		en[n].candidate.n = k;
		en[n].candidate.v = c;
		n++;
	}
	out->entry.n = n;
	out->entry.v = en;
	/* The breakout's routes. */
	if (!ALLOC_N(a, ro, yj_count(ucl_object_lookup(top, "routes")))) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "routes"), it, e) {
		memset(&ro[n], 0, sizeof(ro[n]));
		if (!yj_num(e, "fib", &num) || (ro[n].destination = yj_str(a,
		    e, "destination")) == NULL)
			continue;
		ro[n].fib = (uint16_t)num;
		if (!ALLOC_N(a, rc, yj_count(ucl_object_lookup(e,
		    "candidates")))) {
			ucl_object_unref(top);
			return (ENOMEM);
		}
		k = 0;
		YJ_EACH(ucl_object_lookup(e, "candidates"), cit, ce) {
			memset(&rc[k], 0, sizeof(rc[k]));
			if ((rc[k].id = yj_str(a, ce, "id")) == NULL)
				continue;
			rc[k].has_via = addr_union(a, ce, "via", &rc[k].via);
			k++;
		}
		ro[n].candidate.n = k;
		ro[n].candidate.v = rc;
		n++;
	}
	out->route.n = n;
	out->route.v = ro;
	ucl_object_unref(top);
	return (0);
}

/*
 * The instances of one kind, as the setters keep them: name, fib, host
 * and spec, the form, as JSON text; the proxy's mode and lists beside;
 * the ids' interfaces, conf, rules, divert, capture, offload, lua,
 * plugins, stopped and thresholds.  BIRD's, dnsmasq's and unbound's
 * entries have one layout.
 */
int
ysd_instances_from_json(const char *json, int kind, cbl_yarena *a,
    size_t *np, const void **vp)
{
	const ucl_object_t	*e, *f;
	ucl_object_iter_t	 it;
	ucl_object_t		*top;
	size_t			 n = 0, cnt;

	*np = 0;
	*vp = NULL;
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	cnt = yj_count(ucl_object_lookup(top, "instances"));
	if (kind == YSD_PROXY) {
		struct arcana_sdwan_sdwan_proxy_instance	*v;
		const char					*m;

		if (!ALLOC_N(a, v, cnt))
			goto nomem;
		YJ_EACH(ucl_object_lookup(top, "instances"), it, e) {
			memset(&v[n], 0, sizeof(v[n]));
			if ((v[n].name = yj_str(a, e, "name")) == NULL)
				continue;
			YJ_NUM(e, "fib", &v[n], fib);
			v[n].host = yj_str(a, e, "host");
			v[n].spec = spec_of(a, e, "spec");
			if ((m = yj_str(a, e, "mode")) != NULL) {
				v[n].has_mode = true;
				v[n].mode = strcmp(m, "inspect") == 0 ?
				    ARCANA_SDWAN_SDWAN_PROXY_INSTANCE_MODE_INSPECT :
				    ARCANA_SDWAN_SDWAN_PROXY_INSTANCE_MODE_SNI;
			}
			if (named_of(a, ucl_object_lookup(e, "lists"),
			    &v[n].named_list.n, (const struct named **)(void *)
			    &v[n].named_list.v) != 0)
				goto nomem;
			n++;
		}
		*vp = v;
	} else if (kind == YSD_IDS) {
		struct arcana_sdwan_sdwan_ids_instance	*v;

		if (!ALLOC_N(a, v, cnt))
			goto nomem;
		YJ_EACH(ucl_object_lookup(top, "instances"), it, e) {
			memset(&v[n], 0, sizeof(v[n]));
			if ((v[n].name = yj_str(a, e, "name")) == NULL)
				continue;
			if (yj_strs(a, ucl_object_lookup(e, "interfaces"),
			    &v[n].interface.n, &v[n].interface.v) != 0 ||
			    yj_strs(a, ucl_object_lookup(e, "plugins"),
			    &v[n].plugin.n, &v[n].plugin.v) != 0 ||
			    named_of(a, ucl_object_lookup(e, "lua"),
			    &v[n].lua.n, (const struct named **)(void *)
			    &v[n].lua.v) != 0)
				goto nomem;
			v[n].conf = yj_str(a, e, "conf");
			v[n].rules = yj_str(a, e, "rules");
			YJ_NUM(e, "divert", &v[n], divert);
			v[n].host = yj_str(a, e, "host");
			v[n].spec = spec_of(a, e, "spec");
			if ((f = ucl_object_lookup(e, "capture")) != NULL &&
			    ucl_object_type(f) == UCL_STRING) {
				v[n].has_capture = true;
				v[n].capture = strcmp(ucl_object_tostring(f),
				    "netmap") == 0 ?
				    ARCANA_SDWAN_SDWAN_IDS_INSTANCE_CAPTURE_NETMAP :
				    ARCANA_SDWAN_SDWAN_IDS_INSTANCE_CAPTURE_PCAP;
			}
			v[n].offload = yj_yes(e, "offload", &v[n].has_offload);
			v[n].stopped = yj_yes(e, "stopped", &v[n].has_stopped);
			v[n].thresholds = yj_str(a, e, "thresholds");
			n++;
		}
		*vp = v;
	} else {
		struct arcana_sdwan_bird_instance	*v;

		if (!ALLOC_N(a, v, cnt))
			goto nomem;
		YJ_EACH(ucl_object_lookup(top, "instances"), it, e) {
			memset(&v[n], 0, sizeof(v[n]));
			if ((v[n].name = yj_str(a, e, "name")) == NULL)
				continue;
			YJ_NUM(e, "fib", &v[n], fib);
			v[n].host = yj_str(a, e, "host");
			v[n].spec = spec_of(a, e, "spec");
			n++;
		}
		*vp = v;
	}
	*np = n;
	ucl_object_unref(top);
	return (0);
nomem:
	ucl_object_unref(top);
	return (ENOMEM);
}

/* ---- Back to the JSON the setters take ------------------------------ */

static char *
emit(ucl_object_t *top)
{
	char	*json;

	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (json);
}

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

static void
put_str(ucl_object_t *o, const char *key, const char *s)
{

	if (s != NULL)
		put(o, key, ucl_object_fromstring(s));
}

static ucl_object_t *
top_of(const char *jail)
{
	ucl_object_t	*top;

	top = ucl_object_typed_new(UCL_OBJECT);
	if (jail != NULL && jail[0] != '\0')
		put(top, "jail", ucl_object_fromstring(jail));
	return (top);
}

static int
rule_cmp(const void *x, const void *y)
{
	uint32_t a = (*(const struct arcana_sdwan_rules_config_rule *const *)
	    x)->index;
	uint32_t b = (*(const struct arcana_sdwan_rules_config_rule *const *)
	    y)->index;

	return (a < b ? -1 : a > b);
}

char *
ysd_rules_json(const char *jail, const struct arcana_sdwan_rules_config *r,
    unsigned set)
{
	static const char *const vt[] = { "skipto", "ipv4", "ipv6", "legacy" };
	const struct arcana_sdwan_rules_config_rule	**byidx;
	ucl_object_t	*top, *arr, *t, *ent, *e;
	char		*line;

	top = top_of(jail);
	put(top, "set", ucl_object_fromint(r != NULL && r->has_set ? r->set :
	    set));
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; r != NULL && i < r->table.n; i++) {
		t = ucl_object_typed_new(UCL_OBJECT);
		put_str(t, "name", r->table.v[i].name);
		put_str(t, "valtype", r->table.v[i].has_valtype &&
		    r->table.v[i].valtype < nitems(vt) ?
		    vt[r->table.v[i].valtype] : "skipto");
		ent = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < r->table.v[i].entry.n; k++) {
			e = ucl_object_typed_new(UCL_ARRAY);
			ucl_array_append(e, ucl_object_fromstring(
			    r->table.v[i].entry.v[k].prefix));
			ucl_array_append(e, ucl_object_fromstring(
			    r->table.v[i].entry.v[k].value != NULL ?
			    r->table.v[i].entry.v[k].value : ""));
			ucl_array_append(ent, e);
		}
		put(t, "entries", ent);
		ucl_array_append(arr, t);
	}
	put(top, "tables", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; r != NULL && i < r->object.n; i++)
		ucl_array_append(arr, ucl_object_fromstring(r->object.v[i]));
	put(top, "objects", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	/* In their places' order, whatever order they came in. */
	if (r != NULL && r->rule.n > 0 && (byidx = calloc(r->rule.n,
	    sizeof(*byidx))) != NULL) {
		for (size_t i = 0; i < r->rule.n; i++)
			byidx[i] = &r->rule.v[i];
		qsort(byidx, r->rule.n, sizeof(*byidx), rule_cmp);
		for (size_t i = 0; i < r->rule.n; i++) {
			if (asprintf(&line, "%u %s", byidx[i]->number,
			    byidx[i]->text != NULL ? byidx[i]->text : "") == -1)
				continue;
			ucl_array_append(arr, ucl_object_fromstring(line));
			free(line);
		}
		free(byidx);
	}
	put(top, "rules", arr);
	return (emit(top));
}

char *
ysd_steer_json(const char *jail, const struct arcana_sdwan_steer_config *s)
{
	ucl_object_t	*top, *arr, *e, *cs, *c;

	top = top_of(jail);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; s != NULL && i < s->entry.n; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "table", s->entry.v[i].table);
		put_str(e, "prefix", s->entry.v[i].prefix);
		cs = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < s->entry.v[i].candidate.n; k++) {
			const struct arcana_sdwan_steer_config_entry_candidate *v =
			    &s->entry.v[i].candidate.v[k];

			c = ucl_object_typed_new(UCL_OBJECT);
			put_str(c, "id", v->id);
			if (v->has_via)
				put_str(c, "via", v->via.v.m0);
			ucl_array_append(cs, c);
		}
		put(e, "candidates", cs);
		ucl_array_append(arr, e);
	}
	put(top, "entries", arr);
	if (s == NULL || s->route.n == 0)
		return (emit(top));
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < s->route.n; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "fib", ucl_object_fromint(s->route.v[i].fib));
		put_str(e, "destination", s->route.v[i].destination);
		cs = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < s->route.v[i].candidate.n; k++) {
			const struct arcana_sdwan_steer_config_route_candidate *v =
			    &s->route.v[i].candidate.v[k];

			c = ucl_object_typed_new(UCL_OBJECT);
			put_str(c, "id", v->id);
			if (v->has_via)
				put_str(c, "via", v->via.v.m0);
			ucl_array_append(cs, c);
		}
		put(e, "candidates", cs);
		ucl_array_append(arr, e);
	}
	put(top, "routes", arr);
	return (emit(top));
}

/* A form's JSON text as an object; NULL where it is none. */
static ucl_object_t *
spec_object(const char *spec)
{
	ucl_object_t	*o;

	if (spec == NULL || (o = yj_parse(spec)) == NULL)
		return (NULL);
	if (ucl_object_type(o) != UCL_OBJECT) {
		ucl_object_unref(o);
		return (NULL);
	}
	return (o);
}

static ucl_object_t *
named_object(size_t n, const struct named *v)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	for (size_t i = 0; i < n; i++)
		put(o, v[i].name, ucl_object_fromstring(v[i].text != NULL ?
		    v[i].text : ""));
	return (o);
}

static bool
is_sec(const char *name)
{

	return (name != NULL && strncmp(name, SEC_PREFIX, strlen(SEC_PREFIX))
	    == 0);
}

/*
 * The instances of one kind, of an edge (jail; NULL the host's), as its
 * setter takes them; for the proxies and the IDS those of one group
 * (group 1 the Security section's, sec-; 0 SD-WAN's), group -1 for the
 * others.  NULL and why when a form is no JSON object.
 */
char *
ysd_instances_json(int kind, const char *jail, int group, size_t n,
    const void *vp, const char **errp)
{
	ucl_object_t	*top, *arr, *o, *sp;

	top = top_of(jail);
	if (group == 1)
		put(top, "group", ucl_object_fromstring("security"));
	arr = ucl_object_typed_new(UCL_ARRAY);
	put(top, "instances", arr);
	for (size_t i = 0; i < n; i++) {
		const char	*name, *spec;

		if (kind == YSD_PROXY) {
			name = ((const struct arcana_sdwan_sdwan_proxy_instance *)
			    vp)[i].name;
			spec = ((const struct arcana_sdwan_sdwan_proxy_instance *)
			    vp)[i].spec;
		} else if (kind == YSD_IDS) {
			name = ((const struct arcana_sdwan_sdwan_ids_instance *)
			    vp)[i].name;
			spec = ((const struct arcana_sdwan_sdwan_ids_instance *)
			    vp)[i].spec;
		} else {
			name = ((const struct arcana_sdwan_bird_instance *)
			    vp)[i].name;
			spec = ((const struct arcana_sdwan_bird_instance *)
			    vp)[i].spec;
		}
		if (group >= 0 && is_sec(name) != (group == 1))
			continue;
		sp = NULL;
		if (spec != NULL && (sp = spec_object(spec)) == NULL) {
			*errp = "an instance's spec is no JSON object";
			ucl_object_unref(top);
			return (NULL);
		}
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", name);
		if (kind == YSD_IDS) {
			const struct arcana_sdwan_sdwan_ids_instance *v =
			    &((const struct arcana_sdwan_sdwan_ids_instance *)
			    vp)[i];
			ucl_object_t	*l;

			put_str(o, "host", v->host);
			l = ucl_object_typed_new(UCL_ARRAY);
			for (size_t k = 0; k < v->interface.n; k++)
				ucl_array_append(l, ucl_object_fromstring(
				    v->interface.v[k]));
			put(o, "interfaces", l);
			if (v->has_capture)
				put_str(o, "capture", v->capture ==
				    ARCANA_SDWAN_SDWAN_IDS_INSTANCE_CAPTURE_NETMAP ?
				    "netmap" : "pcap");
			if (v->has_offload)
				put(o, "offload", ucl_object_frombool(v->offload));
			if (v->lua.n > 0)
				put(o, "lua", named_object(v->lua.n,
				    (const struct named *)(const void *)v->lua.v));
			if (v->plugin.n > 0) {
				l = ucl_object_typed_new(UCL_ARRAY);
				for (size_t k = 0; k < v->plugin.n; k++)
					ucl_array_append(l, ucl_object_fromstring(
					    v->plugin.v[k]));
				put(o, "plugins", l);
			}
			if (v->has_divert)
				put(o, "divert", ucl_object_fromint(v->divert));
			if (v->has_stopped)
				put(o, "stopped", ucl_object_frombool(v->stopped));
			put_str(o, "rules", v->rules);
			put_str(o, "thresholds", v->thresholds);
			put_str(o, "conf", v->conf);
		} else if (kind == YSD_PROXY) {
			const struct arcana_sdwan_sdwan_proxy_instance *v =
			    &((const struct arcana_sdwan_sdwan_proxy_instance *)
			    vp)[i];

			if (v->has_fib)
				put(o, "fib", ucl_object_fromint(v->fib));
			if (v->has_mode)
				put_str(o, "mode", v->mode ==
				    ARCANA_SDWAN_SDWAN_PROXY_INSTANCE_MODE_INSPECT ?
				    "inspect" : "sni");
			put_str(o, "host", v->host);
			put(o, "lists", named_object(v->named_list.n,
			    (const struct named *)(const void *)
			    v->named_list.v));
		} else {
			const struct arcana_sdwan_bird_instance *v =
			    &((const struct arcana_sdwan_bird_instance *)vp)[i];

			if (v->has_fib)
				put(o, "fib", ucl_object_fromint(v->fib));
			put_str(o, "host", v->host);
		}
		if (sp != NULL)
			put(o, "spec", sp);
		ucl_array_append(arr, o);
	}
	return (emit(top));
}

/* ---- The state -------------------------------------------------------- */

/* What runs: name, fib, running, the lists' first fields. */
static void
running_of(cbl_yarena *a, const ucl_object_t *e,
    struct arcana_sdwan_sdwan_state_dns *r)
{

	memset(r, 0, sizeof(*r));
	r->name = yj_str(a, e, "name");
	YJ_NUM(e, "fib", r, fib);
	r->running = yj_yes(e, "running", &r->has_running);
}

/* A far end's state: up, down, unknown, not probed; -1 none. */
static int
far_state(const char *s)
{

	return (s == NULL ? -1 : strcmp(s, "up") == 0 ? 0 : strcmp(s, "down")
	    == 0 ? 1 : strcmp(s, "not probed") == 0 ? 3 : 2);
}

/* A candidate of the steering's or a route's: id, via, state (and bfd). */
#define	CANDIDATE_OF(a, ee, c, s) do {					\
	(c)->has_via = addr_union((a), (ee), "via", &(c)->via);		\
	if (((s) = far_state(ucl_object_tostring(ucl_object_lookup(	\
	    (ee), "state")))) >= 0) {					\
		(c)->has_state = true;					\
		(c)->state = (s);					\
	}								\
} while (0)

static int
candidates_of(cbl_yarena *a, const ucl_object_t *arr, size_t *np,
    const struct arcana_sdwan_steer_candidate **vp)
{
	struct arcana_sdwan_steer_candidate	*sc;
	const ucl_object_t			*ee;
	ucl_object_iter_t			 it;
	int					 s;
	size_t					 m = 0;

	if (!ALLOC_N(a, sc, yj_count(arr)))
		return (ENOMEM);
	YJ_EACH(arr, it, ee) {
		memset(&sc[m], 0, sizeof(sc[m]));
		if ((sc[m].id = yj_str(a, ee, "id")) == NULL)
			continue;
		CANDIDATE_OF(a, ee, &sc[m], s);
		if ((s = far_state(ucl_object_tostring(ucl_object_lookup(ee,
		    "bfd")))) >= 0) {
			sc[m].has_bfd = true;
			sc[m].bfd = s;
		}
		m++;
	}
	*np = m;
	*vp = sc;
	return (0);
}

static int
route_candidates_of(cbl_yarena *a, const ucl_object_t *arr, size_t *np,
    const struct arcana_sdwan_steered_route_candidate **vp)
{
	struct arcana_sdwan_steered_route_candidate	*sc;
	const ucl_object_t				*ee;
	ucl_object_iter_t				 it;
	int						 s;
	size_t						 m = 0;

	if (!ALLOC_N(a, sc, yj_count(arr)))
		return (ENOMEM);
	YJ_EACH(arr, it, ee) {
		memset(&sc[m], 0, sizeof(sc[m]));
		if ((sc[m].id = yj_str(a, ee, "id")) == NULL)
			continue;
		CANDIDATE_OF(a, ee, &sc[m], s);
		m++;
	}
	*np = m;
	*vp = sc;
	return (0);
}

/*
 * An edge's rules, as the kernel has them, and its steering, from o
 * (the sdwan read, or one of its edges) into out's rules, steered,
 * steer and route: the grouping edge-state's structs (cg:struct), the
 * host's and a jail edge's alike.
 */
static int
edge_state(cbl_yarena *a, const ucl_object_t *top,
    struct arcana_sdwan_sdwan_state *out)
{
	struct arcana_sdwan_rules		*ru;
	struct arcana_sdwan_rules_table		*rt;
	struct arcana_sdwan_rules_counter	*rc;
	struct arcana_sdwan_steer		*st;
	struct arcana_sdwan_steered_route	*sr;
	const ucl_object_t			*e, *o;
	ucl_object_iter_t			 it;
	int64_t					 n;
	size_t					 k;

	/* The rules, as the kernel has them. */
	if ((o = ucl_object_lookup(top, "rules")) != NULL && ucl_object_type(o)
	    == UCL_OBJECT) {
		if (!ALLOC_N(a, ru, 0) || !ALLOC_N(a, rt, yj_count(
		    ucl_object_lookup(o, "tables"))) || !ALLOC_N(a, rc, yj_count(
		    ucl_object_lookup(o, "counters"))))
			return (ENOMEM);
		memset(ru, 0, sizeof(*ru));
		YJ_NUM(o, "set", ru, set);
		YJ_NUM(o, "rules", ru, rules);
		YJ_NUM(o, "objects", ru, objects);
		k = 0;
		YJ_EACH(ucl_object_lookup(o, "tables"), it, e) {
			memset(&rt[k], 0, sizeof(rt[k]));
			if (ucl_object_type(e) == UCL_STRING)
				rt[k].name = dup(a, ucl_object_tostring(e));
			else {
				if ((rt[k].name = yj_str(a, e, "name")) == NULL)
					continue;
				YJ_NUM(e, "count", &rt[k], count);
			}
			k++;
		}
		ru->table.n = k;
		ru->table.v = rt;
		k = 0;
		YJ_EACH(ucl_object_lookup(o, "counters"), it, e) {
			memset(&rc[k], 0, sizeof(rc[k]));
			if (!yj_num(e, "rule", &n))
				continue;
			rc[k].rule = (uint32_t)n;
			YJ_NUM(e, "pkts", &rc[k], packets);
			YJ_NUM(e, "bytes", &rc[k], octets);
			rc[k].text = yj_str(a, e, "text");
			k++;
		}
		ru->counter.n = k;
		ru->counter.v = rc;
		out->rules = ru;
	}
	out->steered = yj_yes(top, "steered", &out->has_steered);
	if (!ALLOC_N(a, st, yj_count(ucl_object_lookup(top, "steer"))))
		return (ENOMEM);
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "steer"), it, e) {
		memset(&st[k], 0, sizeof(st[k]));
		if ((st[k].table = yj_str(a, e, "table")) == NULL || (
		    st[k].prefix = yj_str(a, e, "prefix")) == NULL)
			continue;
		YJ_NUM(e, "chosen", &st[k], chosen);
		if (candidates_of(a, ucl_object_lookup(e, "candidates"),
		    &st[k].candidate.n, &st[k].candidate.v) != 0)
			return (ENOMEM);
		k++;
	}
	out->steer.n = k;
	out->steer.v = st;
	/* The breakout's routes steered. */
	if (!ALLOC_N(a, sr, yj_count(ucl_object_lookup(top, "routes"))))
		return (ENOMEM);
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "routes"), it, e) {
		memset(&sr[k], 0, sizeof(sr[k]));
		YJ_NUM(e, "fib", &sr[k], fib);
		sr[k].destination = yj_str(a, e, "destination");
		YJ_NUM(e, "chosen", &sr[k], chosen);
		if (route_candidates_of(a, ucl_object_lookup(e, "candidates"),
		    &sr[k].candidate.n, &sr[k].candidate.v) != 0)
			return (ENOMEM);
		k++;
	}
	out->route.n = k;
	out->route.v = sr;
	return (0);
}

/* A file's path, size and time (at), as pcap and the like have them. */
#define	FILE_OF(a, e, y) do {						\
	int64_t t_;							\
									\
	(y)->path = yj_str((a), (e), "path");				\
	YJ_NUM((e), "size", (y), size);					\
	if (yj_num((e), "at", &t_))					\
		(y)->at = datetime((a), t_);				\
} while (0)

/* An object of e's as JSON text, the arena's. */
static const char *
text_of(cbl_yarena *a, const ucl_object_t *e, const char *key)
{
	const ucl_object_t	*v;
	unsigned char		*t;
	const char		*s;

	if ((v = ucl_object_lookup(e, key)) == NULL || (t = ucl_object_emit(v,
	    UCL_EMIT_JSON_COMPACT)) == NULL)
		return (NULL);
	s = dup(a, (const char *)t);
	free(t);
	return (s);
}

static int
ids_of(cbl_yarena *a, const ucl_object_t *e,
    struct arcana_sdwan_sdwan_state_ids *id)
{
	struct arcana_sdwan_sdwan_state_ids_alert	*al;
	struct arcana_sdwan_sdwan_state_ids_stats	*sts;
	struct arcana_sdwan_sdwan_state_ids_stats_series *ser;
	struct arcana_sdwan_sdwan_state_ids_pcap	*pc;
	struct arcana_sdwan_sdwan_state_ids_replay_capture *rc;
	struct arcana_sdwan_sdwan_state_ids_offload	*of;
	const ucl_object_t				*ee, *o, *x;
	ucl_object_iter_t				 eit, xit;
	const char					*v;
	int64_t						*vals;
	size_t						 m, q;

	if (yj_strs(a, ucl_object_lookup(e, "interfaces"), &id->interface.n,
	    &id->interface.v) != 0)
		return (ENOMEM);
	if ((v = yj_str(a, e, "mode")) != NULL) {
		id->has_mode = true;
		id->mode = strcmp(v, "prevent") == 0 ?
		    ARCANA_SDWAN_SDWAN_STATE_IDS_MODE_PREVENT :
		    ARCANA_SDWAN_SDWAN_STATE_IDS_MODE_DETECT;
	}
	YJ_NUM(e, "divert", id, divert);
	id->running = yj_yes(e, "running", &id->has_running);
	id->stopped = yj_yes(e, "stopped", &id->has_stopped);
	YJ_NUM(e, "alerts_seen", id, alerts_seen);
	if (!ALLOC_N(a, al, yj_count(ucl_object_lookup(e, "alerts"))))
		return (ENOMEM);
	m = 0;
	YJ_EACH(ucl_object_lookup(e, "alerts"), eit, ee) {
		memset(&al[m], 0, sizeof(al[m]));
		al[m].time = yj_str(a, ee, "time");
		if ((al[m].name = yj_str(a, ee, "signature")) == NULL)
			al[m].name = yj_str(a, ee, "name");
		al[m].source = yj_str(a, ee, "src");
		YJ_NUM(ee, "sport", &al[m], source_port);
		al[m].destination = yj_str(a, ee, "dst");
		YJ_NUM(ee, "dport", &al[m], destination_port);
		al[m].proto = yj_str(a, ee, "proto");
		al[m].interface = yj_str(a, ee, "iface");
		YJ_NUM(ee, "sid", &al[m], signature_id);
		YJ_NUM(ee, "rev", &al[m], rev);
		al[m].category = yj_str(a, ee, "category");
		YJ_NUM(ee, "severity", &al[m], severity);
		al[m].action = yj_str(a, ee, "action");
		m++;
	}
	id->alert.n = m;
	id->alert.v = al;
	if ((o = ucl_object_lookup(e, "stats")) != NULL) {
		if (!ALLOC_N(a, sts, 0) || !ALLOC_N(a, ser, yj_count(
		    ucl_object_lookup(o, "series"))))
			return (ENOMEM);
		memset(sts, 0, sizeof(*sts));
		if (yj_strs(a, ucl_object_lookup(o, "fields"), &sts->field.n,
		    &sts->field.v) != 0)
			return (ENOMEM);
		m = 0;
		YJ_EACH(ucl_object_lookup(o, "series"), eit, ee) {
			if (!ALLOC_N(a, vals, yj_count(ee)))
				return (ENOMEM);
			q = 0;
			YJ_EACH(ee, xit, x)
				vals[q++] = ucl_object_toint(x);
			ser[m].value.n = q;
			ser[m].value.v = vals;
			m++;
		}
		sts->series.n = m;
		sts->series.v = ser;
		sts->flows = text_of(a, o, "flows");
		id->stats = sts;
	}
	if ((v = yj_str(a, e, "capture")) != NULL) {
		id->has_capture = true;
		id->capture = strcmp(v, "netmap") == 0 ?
		    ARCANA_SDWAN_SDWAN_STATE_IDS_CAPTURE_NETMAP : strcmp(v,
		    "divert") == 0 ? ARCANA_SDWAN_SDWAN_STATE_IDS_CAPTURE_DIVERT :
		    ARCANA_SDWAN_SDWAN_STATE_IDS_CAPTURE_PCAP;
	}
	if (!ALLOC_N(a, pc, yj_count(ucl_object_lookup(e, "pcaps"))) ||
	    !ALLOC_N(a, rc, yj_count(ucl_object_lookup(e, "captures"))))
		return (ENOMEM);
	m = 0;
	YJ_EACH(ucl_object_lookup(e, "pcaps"), eit, ee) {
		memset(&pc[m], 0, sizeof(pc[m]));
		FILE_OF(a, ee, &pc[m]);
		YJ_NUM(ee, "from", &pc[m], from);
		if (pc[m].path != NULL)
			m++;
	}
	id->pcap.n = m;
	id->pcap.v = pc;
	m = 0;
	YJ_EACH(ucl_object_lookup(e, "captures"), eit, ee) {
		memset(&rc[m], 0, sizeof(rc[m]));
		FILE_OF(a, ee, &rc[m]);
		if (rc[m].path != NULL)
			m++;
	}
	id->replay_capture.n = m;
	id->replay_capture.v = rc;
	id->replay = text_of(a, e, "replay");
	o = ucl_object_lookup(e, "offload");
	if (!ALLOC_N(a, of, o != NULL ? o->len : 0))
		return (ENOMEM);
	m = 0;
	if (o != NULL && ucl_object_type(o) == UCL_OBJECT)
		YJ_EACH(o, eit, ee) {
			memset(&of[m], 0, sizeof(of[m]));
			of[m].interface = dup(a, ucl_object_key(ee));
			if (yj_strs(a, ee, &of[m].capability.n,
			    &of[m].capability.v) != 0)
				return (ENOMEM);
			m++;
		}
	id->offload.n = m;
	id->offload.v = of;
	return (0);
}

/* The host-wide parts of the IDS and ClamAV. */
static int
ids_host_of(cbl_yarena *a, const ucl_object_t *top,
    struct arcana_sdwan_sdwan_state *out)
{
	struct arcana_sdwan_sdwan_state_ids_build	*b;
	struct arcana_sdwan_sdwan_state_ids_host	*h;
	struct arcana_sdwan_sdwan_state_ids_host_irq	*iq;
	struct arcana_sdwan_sdwan_state_ids_ruleset	*rs;
	struct arcana_sdwan_sdwan_state_clamav		*cv;
	struct arcana_sdwan_sdwan_state_clamav_database	*db;
	const ucl_object_t				*o, *e;
	ucl_object_iter_t				 it;
	int64_t						 n;
	size_t						 m;

	if ((o = ucl_object_lookup(top, "ids_build")) != NULL) {
		if (!ALLOC_N(a, b, 0))
			return (ENOMEM);
		memset(b, 0, sizeof(*b));
		b->version = yj_str(a, o, "version");
		b->lua = yj_yes(o, "lua", &b->has_lua);
		b->profiling = yj_yes(o, "profiling", &b->has_profiling);
		b->profiling_rules = yj_yes(o, "profiling_rules",
		    &b->has_profiling_rules);
		b->profiling_locks = yj_yes(o, "profiling_locks",
		    &b->has_profiling_locks);
		b->hyperscan = yj_yes(o, "hyperscan", &b->has_hyperscan);
		b->netmap = yj_yes(o, "netmap", &b->has_netmap);
		b->ipfw = yj_yes(o, "ipfw", &b->has_ipfw);
		b->plugins = yj_yes(o, "plugins", &b->has_plugins);
		out->ids_build = b;
	}
	if ((o = ucl_object_lookup(top, "ids_host")) != NULL) {
		if (!ALLOC_N(a, h, 0) || !ALLOC_N(a, iq, yj_count(
		    ucl_object_lookup(o, "irqs"))))
			return (ENOMEM);
		memset(h, 0, sizeof(*h));
		YJ_NUM(o, "ncpu", h, ncpu);
		YJ_NUM(o, "ndomains", h, ndomains);
		m = 0;
		YJ_EACH(ucl_object_lookup(o, "irqs"), it, e) {
			memset(&iq[m], 0, sizeof(iq[m]));
			if (!yj_num(e, "irq", &n))
				continue;
			iq[m].irq = (uint32_t)n;
			iq[m].name = yj_str(a, e, "name");
			iq[m].cpus = yj_str(a, e, "cpus");
			m++;
		}
		h->irq.n = m;
		h->irq.v = iq;
		out->ids_host = h;
	}
	if ((o = ucl_object_lookup(top, "ids_ruleset")) != NULL) {
		if (!ALLOC_N(a, rs, 0))
			return (ENOMEM);
		memset(rs, 0, sizeof(*rs));
		FILE_OF(a, o, rs);
		out->ids_ruleset = rs;
	}
	if ((o = ucl_object_lookup(top, "clamav")) != NULL) {
		if (!ALLOC_N(a, cv, 0) || !ALLOC_N(a, db, yj_count(
		    ucl_object_lookup(o, "databases"))))
			return (ENOMEM);
		memset(cv, 0, sizeof(*cv));
		m = 0;
		YJ_EACH(ucl_object_lookup(o, "databases"), it, e) {
			memset(&db[m], 0, sizeof(db[m]));
			if ((db[m].name = yj_str(a, e, "name")) == NULL)
				continue;
			db[m].file = yj_str(a, e, "file");
			db[m].built = yj_str(a, e, "built");
			YJ_NUM(e, "version", &db[m], version);
			YJ_NUM(e, "signatures", &db[m], signatures);
			m++;
		}
		cv->database.n = m;
		cv->database.v = db;
		cv->freshclam = yj_yes(o, "freshclam", &cv->has_freshclam);
		cv->conf = yj_yes(o, "conf", &cv->has_conf);
		if (yj_strs(a, ucl_object_lookup(o, "mirrors"), &cv->mirror.n,
		    &cv->mirror.v) != 0 || yj_strs(a, ucl_object_lookup(o,
		    "log"), &cv->log.n, &cv->log.v) != 0)
			return (ENOMEM);
		out->clamav = cv;
	}
	return (0);
}

int
ysd_state_from_json(const char *json, cbl_yarena *a,
    struct arcana_sdwan_sdwan_state *out)
{
	struct arcana_sdwan_sdwan_state_edge		*ed;
	struct arcana_sdwan_sdwan_state_bird		*bi;
	struct arcana_sdwan_sdwan_state_bird_protocol	*bp;
	struct arcana_sdwan_sdwan_state_bird_bfd	*bb;
	struct arcana_sdwan_sdwan_state_dhcp		*dh;
	struct arcana_sdwan_sdwan_state_dhcp_lease	*dl;
	struct arcana_sdwan_sdwan_state_dns		*dn;
	struct arcana_sdwan_sdwan_state_proxy		*px;
	struct arcana_sdwan_sdwan_state_ids		*id;
	struct arcana_sdwan_sdwan_state_record		*re;
	struct arcana_sdwan_sdwan_state_record_last	*rl;
	struct arcana_sdwan_sdwan_state_key		*ky;
	struct arcana_sdwan_sdwan_state_fault		*fa;
	const ucl_object_t				*e, *o, *ee;
	ucl_object_iter_t				 it, eit;
	ucl_object_t					*top;
	int64_t						 n;
	size_t						 k, m;
	int						 s;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if (edge_state(a, top, out) != 0)
		goto nomem;
	/* Each edge that is a vnet jail: the same, its own ipfw's. */
	if (!ALLOC_N(a, ed, yj_count(ucl_object_lookup(top, "edges"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "edges"), it, e) {
		struct arcana_sdwan_sdwan_state	one;

		memset(&ed[k], 0, sizeof(ed[k]));
		if ((ed[k].jail = yj_str(a, e, "jail")) == NULL)
			continue;
		memset(&one, 0, sizeof(one));
		if (edge_state(a, e, &one) != 0)
			goto nomem;
		ed[k].rules = one.rules;
		ed[k].has_steered = one.has_steered;
		ed[k].steered = one.steered;
		ed[k].steer.n = one.steer.n;
		ed[k].steer.v = one.steer.v;
		ed[k].route.n = one.route.n;
		ed[k].route.v = one.route.v;
		ed[k].error = yj_str(a, e, "error");
		k++;
	}
	out->edge.n = k;
	out->edge.v = ed;
	/* BIRD. */
	if (!ALLOC_N(a, bi, yj_count(ucl_object_lookup(top, "bird"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "bird"), it, e) {
		memset(&bi[k], 0, sizeof(bi[k]));
		if ((bi[k].name = yj_str(a, e, "name")) == NULL)
			continue;
		YJ_NUM(e, "fib", &bi[k], fib);
		bi[k].running = yj_yes(e, "running", &bi[k].has_running);
		bi[k].jail = yj_str(a, e, "jail");
		if (!ALLOC_N(a, bp, yj_count(ucl_object_lookup(e, "protocols")))
		    || !ALLOC_N(a, bb, yj_count(ucl_object_lookup(e, "bfd"))))
			goto nomem;
		m = 0;
		YJ_EACH(ucl_object_lookup(e, "protocols"), eit, ee) {
			memset(&bp[m], 0, sizeof(bp[m]));
			if ((bp[m].name = yj_str(a, ee, "name")) == NULL)
				continue;
			bp[m].proto = yj_str(a, ee, "proto");
			bp[m].state = yj_str(a, ee, "state");
			bp[m].info = yj_str(a, ee, "info");
			m++;
		}
		bi[k].protocol.n = m;
		bi[k].protocol.v = bp;
		m = 0;
		YJ_EACH(ucl_object_lookup(e, "bfd"), eit, ee) {
			memset(&bb[m], 0, sizeof(bb[m]));
			bb[m].address = yj_str(a, ee, "address");
			bb[m].interface = yj_str(a, ee, "interface");
			if ((s = far_state(ucl_object_tostring(ucl_object_lookup(
			    ee, "state")))) >= 0) {
				bb[m].has_state = true;
				bb[m].state = s > 2 ? 2 : s;
			}
			bb[m].since = yj_str(a, ee, "since");
			m++;
		}
		bi[k].bfd.n = m;
		bi[k].bfd.v = bb;
		k++;
	}
	out->bird.n = k;
	out->bird.v = bi;
	/* DHCP, with the leases. */
	if (!ALLOC_N(a, dh, yj_count(ucl_object_lookup(top, "dhcp"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "dhcp"), it, e) {
		running_of(a, e, (void *)&dh[k]);
		memset(&dh[k].lease, 0, sizeof(dh[k].lease));
		if (dh[k].name == NULL)
			continue;
		if (!ALLOC_N(a, dl, yj_count(ucl_object_lookup(e, "leases"))))
			goto nomem;
		m = 0;
		YJ_EACH(ucl_object_lookup(e, "leases"), eit, ee) {
			memset(&dl[m], 0, sizeof(dl[m]));
			if (yj_num(ee, "expires", &n))
				dl[m].expires = datetime(a, n);
			dl[m].id = yj_str(a, ee, "id");
			dl[m].has_address = addr_union(a, ee, "address",
			    &dl[m].address);
			dl[m].hostname = yj_str(a, ee, "name");
			m++;
		}
		dh[k].lease.n = m;
		dh[k].lease.v = dl;
		k++;
	}
	out->dhcp.n = k;
	out->dhcp.v = dh;
	/* DNS. */
	if (!ALLOC_N(a, dn, yj_count(ucl_object_lookup(top, "dns"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "dns"), it, e) {
		running_of(a, e, &dn[k]);
		dn[k].tls_cert = yj_str(a, e, "tls_cert");
		if (dn[k].name != NULL)
			k++;
	}
	out->dns.n = k;
	out->dns.v = dn;
	/* The proxies. */
	if (!ALLOC_N(a, px, yj_count(ucl_object_lookup(top, "proxy"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "proxy"), it, e) {
		running_of(a, e, (void *)&px[k]);
		px[k].mode = yj_str(a, e, "mode");
		px[k].icap = yj_yes(e, "icap", &px[k].has_icap);
		px[k].ca = yj_str(a, e, "ca");
		if (px[k].name != NULL)
			k++;
	}
	out->proxy.n = k;
	out->proxy.v = px;
	/* The IDS, with its alerts. */
	if (!ALLOC_N(a, id, yj_count(ucl_object_lookup(top, "ids"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "ids"), it, e) {
		memset(&id[k], 0, sizeof(id[k]));
		if ((id[k].name = yj_str(a, e, "name")) == NULL)
			continue;
		if (ids_of(a, e, &id[k]) != 0)
			goto nomem;
		k++;
	}
	out->ids.n = k;
	out->ids.v = id;
	if (ids_host_of(a, top, out) != 0)
		goto nomem;
	/* The record. */
	if ((o = ucl_object_lookup(top, "record")) != NULL) {
		if (!ALLOC_N(a, re, 0) || !ALLOC_N(a, rl, yj_count(
		    ucl_object_lookup(o, "last"))))
			goto nomem;
		memset(re, 0, sizeof(*re));
		YJ_NUM(o, "count", re, count);
		YJ_NUM(o, "seq", re, sequence);
		YJ_NUM(o, "untold", re, untold);
		k = 0;
		YJ_EACH(ucl_object_lookup(o, "last"), it, e) {
			memset(&rl[k], 0, sizeof(rl[k]));
			if (yj_num(e, "t", &n))
				rl[k].time = datetime(a, n);
			YJ_NUM(e, "seq", &rl[k], sequence);
			YJ_NUM(e, "rule", &rl[k], rule);
			rl[k].action = yj_str(a, e, "action");
			rl[k].source = yj_str(a, e, "src");
			rl[k].destination = yj_str(a, e, "dst");
			rl[k].interface = yj_str(a, e, "iface");
			rl[k].comment = yj_str(a, e, "comment");
			k++;
		}
		re->last.n = k;
		re->last.v = rl;
		out->record = re;
	}
	/* The keys. */
	if (!ALLOC_N(a, ky, yj_count(ucl_object_lookup(top, "keys"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "keys"), it, e) {
		memset(&ky[k], 0, sizeof(ky[k]));
		if ((ky[k].interface = yj_str(a, e, "interface")) == NULL)
			continue;
		ky[k].public = yj_str(a, e, "public");
		ky[k].next = yj_str(a, e, "next");
		if (yj_num(e, "keyed_at", &n))
			ky[k].keyed_at = datetime(a, n);
		YJ_NUM(e, "lifetime", &ky[k], lifetime);
		YJ_NUM(e, "spi_in", &ky[k], spi_in);
		YJ_NUM(e, "spi_out", &ky[k], spi_out);
		YJ_NUM(e, "next_spi_in", &ky[k], next_spi_in);
		ky[k].pending = yj_yes(e, "pending", &ky[k].has_pending);
		k++;
	}
	out->key.n = k;
	out->key.v = ky;
	/* The faults. */
	if (!ALLOC_N(a, fa, yj_count(ucl_object_lookup(top, "faults"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "faults"), it, e) {
		memset(&fa[k], 0, sizeof(fa[k]));
		if (yj_num(e, "t", &n))
			fa[k].time = datetime(a, n);
		fa[k].type = yj_str(a, e, "type");
		fa[k].severity = yj_str(a, e, "severity");
		fa[k].was = yj_str(a, e, "was");
		fa[k].object = yj_str(a, e, "object");
		fa[k].by = yj_str(a, e, "by");
		fa[k].description = yj_str(a, e, "description");
		fa[k].cleared = yj_yes(e, "cleared", &fa[k].has_cleared);
		if (yj_num(e, "cleared_at", &n))
			fa[k].cleared_at = datetime(a, n);
		fa[k].compressed = yj_yes(e, "compressed", &fa[k].has_compressed);
		k++;
	}
	out->fault.n = k;
	out->fault.v = fa;
	ucl_object_unref(top);
	return (0);
nomem:
	ucl_object_unref(top);
	return (ENOMEM);
}
