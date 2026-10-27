/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the SD-WAN edge as YANG, arcana-sdwan: what the console
 * writes (sdwan-rules, sdwan-steer, the instances of sdwan-bird, -dhcp,
 * -dns, -proxy and -ids) read back as the module's configuration, and
 * the sdwan read (probe.c do_sdwan() with sdwan.c's, the luxuria
 * instances', record.c's, sa.c's and faults.c's parts) as its state.
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
	struct arcana_sdwan_sdwan_steer_entry_candidate_via	*s = u;
	const char						*v;

	if ((v = yj_str(a, o, key)) == NULL)
		return (false);
	s->which = strchr(v, ':') != NULL ? 1 : 0;
	s->v.m0 = v;
	return (true);
}

#define	ALLOC_N(a, p, n)	(((p) = cbl_yarena_alloc((a), ((n) + 1) * \
	sizeof(*(p)))) != NULL)

int
ysd_rules_from_json(const char *json, cbl_yarena *a,
    struct arcana_sdwan_sdwan_rules *out)
{
	struct arcana_sdwan_sdwan_rules_table		*t;
	struct arcana_sdwan_sdwan_rules_table_entry	*en;
	struct arcana_sdwan_sdwan_rules_rule		*r;
	const ucl_object_t				*e, *ee;
	ucl_object_iter_t				 it, eit;
	ucl_object_t					*top;
	const char					*v;
	size_t						 n, k;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	YJ_NUM(top, "set", out, set);
	out->jail = yj_str(a, top, "jail");
	if (!ALLOC_N(a, t, yj_count(ucl_object_lookup(top, "tables"))) ||
	    !ALLOC_N(a, r, yj_count(ucl_object_lookup(top, "rules"))) ||
	    yj_strs(a, ucl_object_lookup(top, "objects"), &out->object.n,
	    &out->object.v) != 0) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "tables"), it, e) {
		memset(&t[n], 0, sizeof(t[n]));
		if ((t[n].name = yj_str(a, e, "name")) == NULL)
			continue;
		if ((v = yj_str(a, e, "valtype")) != NULL) {
			t[n].has_valtype = true;
			t[n].valtype = strcmp(v, "ipv4") == 0 ?
			    ARCANA_SDWAN_SDWAN_RULES_TABLE_VALTYPE_IPV4 : strcmp(v,
			    "ipv6") == 0 ? ARCANA_SDWAN_SDWAN_RULES_TABLE_VALTYPE_IPV6 :
			    strcmp(v, "legacy") == 0 ?
			    ARCANA_SDWAN_SDWAN_RULES_TABLE_VALTYPE_LEGACY :
			    ARCANA_SDWAN_SDWAN_RULES_TABLE_VALTYPE_SKIPTO;
		}
		if (!ALLOC_N(a, en, yj_count(ucl_object_lookup(e, "entries")))) {
			ucl_object_unref(top);
			return (ENOMEM);
		}
		k = 0;
		/* An entry is [prefix, value], or {prefix, value}. */
		YJ_EACH(ucl_object_lookup(e, "entries"), eit, ee) {
			const ucl_object_t	*p, *q;

			if (ucl_object_type(ee) == UCL_ARRAY) {
				p = ucl_array_find_index(ee, 0);
				q = ucl_array_find_index(ee, 1);
				if (p == NULL || ucl_object_type(p) != UCL_STRING)
					continue;
				en[k].prefix = yj_str(a, ee, "0");
				if (en[k].prefix == NULL) {
					char	*d;
					const char *s = ucl_object_tostring(p);

					if ((d = cbl_yarena_alloc(a, strlen(s) +
					    1)) == NULL) {
						ucl_object_unref(top);
						return (ENOMEM);
					}
					memcpy(d, s, strlen(s) + 1);
					en[k].prefix = d;
				}
				en[k].value = NULL;
				if (q != NULL) {
					char		*d;
					const char	*s = ucl_object_tostring_forced(
					    q);

					if ((d = cbl_yarena_alloc(a, strlen(s) +
					    1)) == NULL) {
						ucl_object_unref(top);
						return (ENOMEM);
					}
					memcpy(d, s, strlen(s) + 1);
					en[k].value = d;
				}
			} else {
				if ((en[k].prefix = yj_str(a, ee, "prefix")) ==
				    NULL)
					continue;
				en[k].value = yj_str(a, ee, "value");
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
	/* A rule is "number words", or {number, text}. */
	YJ_EACH(ucl_object_lookup(top, "rules"), it, e) {
		memset(&r[n], 0, sizeof(r[n]));
		if (ucl_object_type(e) == UCL_STRING) {
			const char	*s = ucl_object_tostring(e);
			char		*end, *d;

			r[n].number = (uint32_t)strtoul(s, &end, 10);
			if (end == s)
				continue;
			end += strspn(end, " ");
			if ((d = cbl_yarena_alloc(a, strlen(end) + 1)) == NULL) {
				ucl_object_unref(top);
				return (ENOMEM);
			}
			memcpy(d, end, strlen(end) + 1);
			r[n].text = d;
		} else {
			int64_t	num;

			if (!yj_num(e, "number", &num) && !yj_num(e, "num", &num))
				continue;
			r[n].number = (uint32_t)num;
			r[n].text = yj_str(a, e, "text");
		}
		n++;
	}
	out->rule.n = n;
	out->rule.v = r;
	ucl_object_unref(top);
	return (0);
}

int
ysd_steer_from_json(const char *json, cbl_yarena *a,
    struct arcana_sdwan_sdwan_steer *out)
{
	struct arcana_sdwan_sdwan_steer_entry		*en;
	struct arcana_sdwan_sdwan_steer_entry_candidate	*c;
	const ucl_object_t				*e, *ce;
	ucl_object_iter_t				 it, cit;
	ucl_object_t					*top;
	size_t						 n = 0, k;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->jail = yj_str(a, top, "jail");
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
	ucl_object_unref(top);
	return (0);
}

/* The instances of one kind, as the console writes them: name, fib,
 * conf; the proxy's mode and deny, the ids' interfaces, rules and
 * divert beside.  The five lists' entries begin alike. */
int
ysd_instances_from_json(const char *json, int kind, cbl_yarena *a,
    size_t *np, const void **vp)
{
	const ucl_object_t	*e;
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
			v[n].conf = yj_str(a, e, "conf");
			if ((m = yj_str(a, e, "mode")) != NULL) {
				v[n].has_mode = true;
				v[n].mode = strcmp(m, "inspect") == 0 ?
				    ARCANA_SDWAN_SDWAN_PROXY_INSTANCE_MODE_INSPECT :
				    ARCANA_SDWAN_SDWAN_PROXY_INSTANCE_MODE_SNI;
			}
			v[n].deny = yj_str(a, e, "deny");
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
			    &v[n].interface.n, &v[n].interface.v) != 0)
				goto nomem;
			v[n].conf = yj_str(a, e, "conf");
			v[n].rules = yj_str(a, e, "rules");
			YJ_NUM(e, "divert", &v[n], divert);
			n++;
		}
		*vp = v;
	} else {
		struct arcana_sdwan_sdwan_bird_instance	*v;

		if (!ALLOC_N(a, v, cnt))
			goto nomem;
		YJ_EACH(ucl_object_lookup(top, "instances"), it, e) {
			memset(&v[n], 0, sizeof(v[n]));
			if ((v[n].name = yj_str(a, e, "name")) == NULL)
				continue;
			YJ_NUM(e, "fib", &v[n], fib);
			v[n].conf = yj_str(a, e, "conf");
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

/* What runs: name, fib, running, the three lists' first fields. */
static void
running_of(cbl_yarena *a, const ucl_object_t *e,
    struct arcana_sdwan_sdwan_state_dns *r)
{

	memset(r, 0, sizeof(*r));
	r->name = yj_str(a, e, "name");
	YJ_NUM(e, "fib", r, fib);
	r->running = yj_yes(e, "running", &r->has_running);
}

static int
state_enum(const char *s)
{

	return (s == NULL ? 2 : strcmp(s, "up") == 0 ? 0 : strcmp(s, "down")
	    == 0 ? 1 : 2);
}

/*
 * An edge's rules, as the kernel has them, and its steering, from o
 * (the sdwan read, or one of its edges) into out's rules, steered and
 * steer: the grouping edge-state's structs (cg:struct), the host's and
 * a jail edge's alike.
 */

static int
edge_state(cbl_yarena *a, const ucl_object_t *top,
    struct arcana_sdwan_sdwan_state *out)
{
	struct arcana_sdwan_rules		*ru;
	struct arcana_sdwan_rules_table	*rt;
	struct arcana_sdwan_rules_counter	*rc;
	struct arcana_sdwan_steer		*st;
	struct arcana_sdwan_steer_candidate	*sc;
	const ucl_object_t				*e, *o, *ee;
	ucl_object_iter_t				 it, eit;
	const char					*v;
	int64_t						 n;
	size_t						 k, m;

	/* The rules, as the kernel has them. */
	if ((o = ucl_object_lookup(top, "rules")) != NULL && ucl_object_type(o)
	    == UCL_OBJECT) {
		if (!ALLOC_N(a, ru, 0) || !ALLOC_N(a, rt, yj_count(
		    ucl_object_lookup(o, "tables"))) || !ALLOC_N(a, rc, yj_count(
		    ucl_object_lookup(o, "counters"))))
			goto nomem;
		memset(ru, 0, sizeof(*ru));
		YJ_NUM(o, "set", ru, set);
		YJ_NUM(o, "rules", ru, rules);
		YJ_NUM(o, "objects", ru, objects);
		k = 0;
		YJ_EACH(ucl_object_lookup(o, "tables"), it, e) {
			memset(&rt[k], 0, sizeof(rt[k]));
			if (ucl_object_type(e) == UCL_STRING) {
				rt[k].name = yj_str(a, o, "-");
				if (rt[k].name == NULL) {
					const char *s = ucl_object_tostring(e);
					char *d;

					if ((d = cbl_yarena_alloc(a, strlen(s) +
					    1)) == NULL)
						goto nomem;
					memcpy(d, s, strlen(s) + 1);
					rt[k].name = d;
				}
			} else {
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
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "steer"), it, e) {
		memset(&st[k], 0, sizeof(st[k]));
		if ((st[k].table = yj_str(a, e, "table")) == NULL || (
		    st[k].prefix = yj_str(a, e, "prefix")) == NULL)
			continue;
		YJ_NUM(e, "chosen", &st[k], chosen);
		if (!ALLOC_N(a, sc, yj_count(ucl_object_lookup(e, "candidates"))))
			goto nomem;
		m = 0;
		YJ_EACH(ucl_object_lookup(e, "candidates"), eit, ee) {
			memset(&sc[m], 0, sizeof(sc[m]));
			if ((sc[m].id = yj_str(a, ee, "id")) == NULL)
				continue;
			sc[m].has_via = addr_union(a, ee, "via", &sc[m].via);
			if ((v = yj_str(a, ee, "state")) != NULL) {
				sc[m].has_state = true;
				sc[m].state = state_enum(v);
			}
			m++;
		}
		st[k].candidate.n = m;
		st[k].candidate.v = sc;
		k++;
	}
	out->steer.n = k;
	out->steer.v = st;
	return (0);
nomem:
	return (ENOMEM);
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
	struct arcana_sdwan_sdwan_state_ids_alert	*al;
	struct arcana_sdwan_sdwan_state_record		*re;
	struct arcana_sdwan_sdwan_state_record_last	*rl;
	struct arcana_sdwan_sdwan_state_key		*ky;
	struct arcana_sdwan_sdwan_state_fault		*fa;
	const ucl_object_t				*e, *o, *ee;
	ucl_object_iter_t				 it, eit;
	ucl_object_t					*top;
	const char					*v;
	int64_t						 n;
	size_t						 k, m;

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
		k++;
	}
	out->edge.n = k;
	out->edge.v = ed;
	/* BIRD. */
	if (!ALLOC_N(a, bi, yj_count(ucl_object_lookup(top, "bird"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "bird"), it, e) {
		running_of(a, e, (void *)&bi[k]);
		memset(&bi[k].protocol, 0, sizeof(bi[k].protocol));
		memset(&bi[k].bfd, 0, sizeof(bi[k].bfd));
		if (bi[k].name == NULL)
			continue;
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
			if ((v = yj_str(a, ee, "state")) != NULL) {
				bb[m].has_state = true;
				bb[m].state = state_enum(v);
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
		if (yj_strs(a, ucl_object_lookup(e, "interfaces"),
		    &id[k].interface.n, &id[k].interface.v) != 0)
			goto nomem;
		if ((v = yj_str(a, e, "mode")) != NULL) {
			id[k].has_mode = true;
			id[k].mode = strcmp(v, "prevent") == 0 ?
			    ARCANA_SDWAN_SDWAN_STATE_IDS_MODE_PREVENT :
			    ARCANA_SDWAN_SDWAN_STATE_IDS_MODE_DETECT;
		}
		YJ_NUM(e, "divert", &id[k], divert);
		id[k].running = yj_yes(e, "running", &id[k].has_running);
		YJ_NUM(e, "alerts_seen", &id[k], alerts_seen);
		if (!ALLOC_N(a, al, yj_count(ucl_object_lookup(e, "alerts"))))
			goto nomem;
		m = 0;
		YJ_EACH(ucl_object_lookup(e, "alerts"), eit, ee) {
			memset(&al[m], 0, sizeof(al[m]));
			al[m].time = yj_str(a, ee, "time");
			al[m].name = yj_str(a, ee, "name");
			al[m].source = yj_str(a, ee, "src");
			YJ_NUM(ee, "sport", &al[m], source_port);
			al[m].destination = yj_str(a, ee, "dst");
			YJ_NUM(ee, "dport", &al[m], destination_port);
			al[m].proto = yj_str(a, ee, "proto");
			m++;
		}
		id[k].alert.n = m;
		id[k].alert.v = al;
		k++;
	}
	out->ids.n = k;
	out->ids.v = id;
	/* The record. */
	if ((o = ucl_object_lookup(top, "record")) != NULL) {
		if (!ALLOC_N(a, re, 0) || !ALLOC_N(a, rl, yj_count(
		    ucl_object_lookup(o, "last"))))
			goto nomem;
		memset(re, 0, sizeof(*re));
		YJ_NUM(o, "count", re, count);
		YJ_NUM(o, "seq", re, sequence);
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
