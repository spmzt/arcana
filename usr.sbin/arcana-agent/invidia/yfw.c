/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the firewall as YANG, arcana-firewall.  The network
 * operation's ipfw kind (ipfw.c, read_ipfw()) read back into the
 * module's structs: the kept rules with their aliases and what rc.conf
 * says as configuration, what the kernel has (the rules with their
 * counters, the dynamic rules, the tables, NAT, dummynet) as state; the
 * ipfw-rules operation's text with its SHA-256 as the kept container;
 * the fw-trace operation's packets as the trace action's output.  A rule
 * stays ipfw's words: the model carries them.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

typedef struct arcana_firewall_firewall yfw;
typedef struct arcana_firewall_firewall_kept ykept;
typedef struct arcana_firewall_firewall_state ystate;

static char *
astrdup(cbl_yarena *a, const char *s)
{
	size_t	 len = strlen(s) + 1;
	char	*p;

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

static char *
astrndup(cbl_yarena *a, const char *s, size_t n)
{
	char	*p;

	if ((p = cbl_yarena_alloc(a, n + 1)) != NULL) {
		memcpy(p, s, n);
		p[n] = '\0';
	}
	return (p);
}

/* A double of o's as a decimal64 of 6 fraction digits. */
static bool
dec6(const ucl_object_t *o, const char *key, int64_t *v)
{
	const ucl_object_t	*e;

	if ((e = ucl_object_lookup(o, key)) == NULL || (ucl_object_type(e) !=
	    UCL_FLOAT && ucl_object_type(e) != UCL_INT))
		return (false);
	*v = (int64_t)(ucl_object_todouble(e) * 1000000.0 + 0.5);
	return (true);
}

/* A dummynet mask (the three masks have one layout). */
static void *
mask_of(cbl_yarena *a, const ucl_object_t *o)
{
	struct arcana_firewall_firewall_state_dummynet_pipe_mask	*m;
	const ucl_object_t					*mo;

	if ((mo = ucl_object_lookup(o, "mask")) == NULL || (m =
	    cbl_yarena_alloc(a, sizeof(*m))) == NULL)
		return (NULL);
	memset(m, 0, sizeof(*m));
	YJ_NUM(mo, "src", m, src);
	YJ_NUM(mo, "dst", m, dst);
	YJ_NUM(mo, "src_port", m, src_port);
	YJ_NUM(mo, "dst_port", m, dst_port);
	YJ_NUM(mo, "proto", m, proto);
	return (m);
}

/* The kept file's add lines and #arcana lines, as read_ipfw() keeps
 * them: rules (number, text, source), other lines, aliases. */
static int
kept_lists(cbl_yarena *a, const ucl_object_t *top, ykept *k)
{
	struct arcana_firewall_firewall_kept_rule	*r;
	struct arcana_firewall_firewall_kept_alias	*al;
	const ucl_object_t				*e;
	ucl_object_iter_t				 it;
	const char					*kind;
	size_t						 n = 0;

	if ((r = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "kept")) + 1) * sizeof(*r))) == NULL)
		return (ENOMEM);
	YJ_EACH(ucl_object_lookup(top, "kept"), it, e) {
		int64_t	num;

		if (!yj_num(e, "num", &num))
			continue;
		memset(&r[n], 0, sizeof(r[n]));
		r[n].number = (uint32_t)num;
		r[n].text = yj_str(a, e, "text");
		r[n].source = yj_str(a, e, "source");
		n++;
	}
	k->rule.n = n;
	k->rule.v = r;
	if (yj_strs(a, ucl_object_lookup(top, "other"), &k->other.n,
	    &k->other.v) != 0)
		return (ENOMEM);
	if ((al = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "aliases")) + 1) * sizeof(*al))) == NULL)
		return (ENOMEM);
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "aliases"), it, e) {
		memset(&al[n], 0, sizeof(al[n]));
		if ((al[n].name = yj_str(a, e, "name")) == NULL)
			continue;
		kind = yj_str(a, e, "kind");
		al[n].has_kind = kind != NULL;
		al[n].kind = kind == NULL || strcmp(kind, "addr") == 0 ?
		    ARCANA_FIREWALL_FIREWALL_KEPT_ALIAS_KIND_ADDR : strcmp(kind,
		    "ports") == 0 ? ARCANA_FIREWALL_FIREWALL_KEPT_ALIAS_KIND_PORTS :
		    ARCANA_FIREWALL_FIREWALL_KEPT_ALIAS_KIND_VALUE;
		al[n].value = yj_str(a, e, "value");
		n++;
	}
	k->alias.n = n;
	k->alias.v = al;
	return (0);
}

/* dummynet's pipes, schedulers and queues (the qos object). */
static int
dummynet_of(cbl_yarena *a, const ucl_object_t *q,
    const struct arcana_firewall_firewall_state_dummynet **outp)
{
	struct arcana_firewall_firewall_state_dummynet		*d;
	struct arcana_firewall_firewall_state_dummynet_pipe	*p;
	struct arcana_firewall_firewall_state_dummynet_sched	*s;
	struct arcana_firewall_firewall_state_dummynet_queue	*u;
	const ucl_object_t					*e, *qe;
	ucl_object_iter_t					 it, qit;
	int64_t							 num;
	size_t							 n;

	*outp = NULL;
	if (q == NULL)
		return (0);
	if ((d = cbl_yarena_alloc(a, sizeof(*d))) == NULL || (p =
	    cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(q, "pipes")) + 1) *
	    sizeof(*p))) == NULL || (s = cbl_yarena_alloc(a, (yj_count(
	    ucl_object_lookup(q, "scheds")) + 1) * sizeof(*s))) == NULL ||
	    (u = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(q,
	    "queues")) + 1) * sizeof(*u))) == NULL)
		return (ENOMEM);
	memset(d, 0, sizeof(*d));
	n = 0;
	YJ_EACH(ucl_object_lookup(q, "pipes"), it, e) {
		if (!yj_num(e, "num", &num))
			continue;
		memset(&p[n], 0, sizeof(p[n]));
		p[n].number = (uint16_t)num;
		YJ_NUM(e, "bw", &p[n], bandwidth);
		YJ_NUM(e, "delay", &p[n], delay);
		YJ_NUM(e, "burst", &p[n], burst);
		p[n].mask = mask_of(a, e);
		YJ_NUM(e, "slots", &p[n], slots);
		YJ_NUM(e, "bytes", &p[n], bytes);
		p[n].has_plr = dec6(e, "plr", &p[n].plr);
		p[n].red = yj_str(a, e, "red");
		n++;
	}
	d->pipe.n = n;
	d->pipe.v = p;
	n = 0;
	YJ_EACH(ucl_object_lookup(q, "scheds"), it, e) {
		uint16_t	*qv;
		size_t		 nq = 0;

		if (!yj_num(e, "num", &num))
			continue;
		memset(&s[n], 0, sizeof(s[n]));
		s[n].number = (uint16_t)num;
		YJ_NUM(e, "bw", &s[n], bandwidth);
		YJ_NUM(e, "delay", &s[n], delay);
		YJ_NUM(e, "burst", &s[n], burst);
		s[n].mask = mask_of(a, e);
		s[n].type = yj_str(a, e, "type");
		s[n].params = yj_str(a, e, "params");
		if ((qv = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(e,
		    "queues")) + 1) * sizeof(*qv))) == NULL)
			return (ENOMEM);
		YJ_EACH(ucl_object_lookup(e, "queues"), qit, qe)
			if (ucl_object_type(qe) == UCL_INT)
				qv[nq++] = (uint16_t)ucl_object_toint(qe);
		s[n].queue.n = nq;
		s[n].queue.v = qv;
		n++;
	}
	d->sched.n = n;
	d->sched.v = s;
	n = 0;
	YJ_EACH(ucl_object_lookup(q, "queues"), it, e) {
		if (!yj_num(e, "num", &num))
			continue;
		memset(&u[n], 0, sizeof(u[n]));
		u[n].number = (uint16_t)num;
		YJ_NUM(e, "sched", &u[n], sched);
		YJ_NUM(e, "weight", &u[n], weight);
		YJ_NUM(e, "pri", &u[n], priority);
		u[n].mask = mask_of(a, e);
		YJ_NUM(e, "slots", &u[n], slots);
		YJ_NUM(e, "bytes", &u[n], bytes);
		u[n].has_plr = dec6(e, "plr", &u[n].plr);
		u[n].red = yj_str(a, e, "red");
		n++;
	}
	d->queue.n = n;
	d->queue.v = u;
	*outp = d;
	return (0);
}

int
yfw_from_json(const char *json, cbl_yarena *a, yfw *out)
{
	struct arcana_firewall_firewall_rc		*rc;
	struct arcana_firewall_firewall_state_rule	*r;
	struct arcana_firewall_firewall_state_dynamic	*dy;
	struct arcana_firewall_firewall_state_table	*t;
	const ucl_object_t				*e, *ee, *ro;
	ucl_object_iter_t				 it, eit;
	ucl_object_t					*top;
	ykept						*k;
	ystate						*st;
	int64_t						 num;
	size_t						 n;
	int						 error;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if ((k = cbl_yarena_alloc(a, sizeof(*k))) == NULL || (rc =
	    cbl_yarena_alloc(a, sizeof(*rc))) == NULL || (st =
	    cbl_yarena_alloc(a, sizeof(*st))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	memset(k, 0, sizeof(*k));
	memset(rc, 0, sizeof(*rc));
	memset(st, 0, sizeof(*st));

	/* The kept rules, and rc.conf's say. */
	k->path = yj_str(a, top, "path");
	k->present = yj_yes(top, "file", &k->has_present);
	if ((error = kept_lists(a, top, k)) != 0)
		goto out;
	if ((ro = ucl_object_lookup(top, "rc")) != NULL) {
		rc->firewall_enable = yj_str(a, ro, "firewall_enable");
		rc->firewall_type = yj_str(a, ro, "firewall_type");
		rc->firewall_script = yj_str(a, ro, "firewall_script");
	}

	/* The kernel's. */
	st->loaded = yj_yes(top, "loaded", &st->has_loaded);
	st->enabled = yj_yes(top, "enabled", &st->has_enabled);
	st->verbose = yj_yes(top, "verbose", &st->has_verbose);
	error = ENOMEM;
	if ((r = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "rules")) + 1) * sizeof(*r))) == NULL)
		goto out;
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "rules"), it, e) {
		if (!yj_num(e, "num", &num))
			continue;
		memset(&r[n], 0, sizeof(r[n]));
		r[n].number = (uint32_t)num;
		if (yj_num(e, "set", &num))
			r[n].set = (uint8_t)num;
		YJ_NUM(e, "pkts", &r[n], packets);
		YJ_NUM(e, "bytes", &r[n], octets);
		r[n].text = yj_str(a, e, "text");
		r[n].disabled = yj_yes(e, "disabled", &r[n].has_disabled);
		n++;
	}
	st->rule.n = n;
	st->rule.v = r;
	YJ_NUM(top, "dynamic_total", st, dynamic_total);
	if ((dy = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "dynamic")) + 1) * sizeof(*dy))) == NULL)
		goto out;
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "dynamic"), it, e) {
		memset(&dy[n], 0, sizeof(dy[n]));
		YJ_NUM(e, "num", &dy[n], number);
		YJ_NUM(e, "pkts", &dy[n], packets);
		YJ_NUM(e, "bytes", &dy[n], octets);
		YJ_NUM(e, "ttl", &dy[n], ttl);
		dy[n].kind = yj_str(a, e, "kind");
		dy[n].flow = yj_str(a, e, "flow");
		n++;
	}
	st->dynamic.n = n;
	st->dynamic.v = dy;
	if ((t = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "tables")) + 1) * sizeof(*t))) == NULL)
		goto out;
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "tables"), it, e) {
		struct arcana_firewall_firewall_state_table_entry	*en;
		size_t							 ne = 0;

		memset(&t[n], 0, sizeof(t[n]));
		if ((t[n].name = yj_str(a, e, "name")) == NULL)
			continue;
		t[n].type = yj_str(a, e, "type");
		YJ_NUM(e, "count", &t[n], count);
		if ((en = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(e,
		    "entries")) + 1) * sizeof(*en))) == NULL)
			goto out;
		YJ_EACH(ucl_object_lookup(e, "entries"), eit, ee) {
			memset(&en[ne], 0, sizeof(en[ne]));
			if ((en[ne].key = yj_str(a, ee, "key")) == NULL)
				continue;
			en[ne].value = yj_str(a, ee, "value");
			ne++;
		}
		t[n].entry.n = ne;
		t[n].entry.v = en;
		n++;
	}
	st->table.n = n;
	st->table.v = t;
	if (yj_strs(a, ucl_object_lookup(top, "nat"), &st->nat.n, &st->nat.v)
	    != 0)
		goto out;
	if ((error = dummynet_of(a, ucl_object_lookup(top, "qos"),
	    &st->dummynet)) != 0)
		goto out;
	out->kept = k;
	out->rc = rc;
	out->state = st;
	error = 0;
out:
	ucl_object_unref(top);
	return (error);
}

/*
 * The kept file as the ipfw-rules operation reads it: its text, its
 * SHA-256, and from the text the rules (add lines), the other lines,
 * and the aliases (#arcana alias name kind value).
 */
int
yfw_kept_from_text(const char *text, const char *sha256, cbl_yarena *a,
    ykept *out)
{
	struct arcana_firewall_firewall_kept_rule	*r;
	struct arcana_firewall_firewall_kept_alias	*al;
	const char					**other;
	const char					*p, *e, *w, *src;
	size_t						 nl, nr = 0, no = 0,
							 na = 0, len;
	char						*num;

	memset(out, 0, sizeof(*out));
	out->text = astrdup(a, text);
	out->sha256 = sha256 != NULL ? astrdup(a, sha256) : NULL;
	out->present = true;
	out->has_present = true;
	nl = 1;
	for (p = text; *p != '\0'; p++)
		if (*p == '\n')
			nl++;
	if ((r = cbl_yarena_alloc(a, (nl + 1) * sizeof(*r))) == NULL ||
	    (other = cbl_yarena_alloc(a, (nl + 1) * sizeof(*other))) == NULL ||
	    (al = cbl_yarena_alloc(a, (nl + 1) * sizeof(*al))) == NULL)
		return (ENOMEM);
	src = NULL;
	for (p = text; *p != '\0'; p = *e == '\n' ? e + 1 : e) {
		e = p + strcspn(p, "\n");
		len = (size_t)(e - p);
		w = p + strspn(p, " \t");
		if (strncmp(w, "#arcana alias ", 14) == 0) {
			/* name kind value... */
			const char	*q = w + 14, *k;

			memset(&al[na], 0, sizeof(al[na]));
			al[na].name = astrndup(a, q, strcspn(q, " "));
			q += strcspn(q, " ");
			q += strspn(q, " ");
			k = q;
			q += strcspn(q, " ");
			al[na].has_kind = true;
			al[na].kind = strncmp(k, "addr", 4) == 0 ?
			    ARCANA_FIREWALL_FIREWALL_KEPT_ALIAS_KIND_ADDR :
			    strncmp(k, "ports", 5) == 0 ?
			    ARCANA_FIREWALL_FIREWALL_KEPT_ALIAS_KIND_PORTS :
			    ARCANA_FIREWALL_FIREWALL_KEPT_ALIAS_KIND_VALUE;
			q += strspn(q, " ");
			al[na].value = astrndup(a, q, (size_t)(e - q));
			if (al[na].name[0] != '\0')
				na++;
			continue;
		}
		if (strncmp(w, "#arcana add ", 12) == 0) {
			/* The rule's own words, before its expansion. */
			src = w + 12;
			src += strspn(src, "0123456789");
			src += strspn(src, " ");
			src = astrndup(a, src, (size_t)(e - src));
			continue;
		}
		if (strncmp(w, "add ", 4) == 0 && isdigit((unsigned char)w[4])) {
			memset(&r[nr], 0, sizeof(r[nr]));
			r[nr].number = (uint32_t)strtoul(w + 4, &num, 10);
			num += strspn(num, " ");
			r[nr].text = astrndup(a, num, (size_t)(e - num));
			r[nr].source = src;
			src = NULL;
			nr++;
			continue;
		}
		if (len > 0)
			other[no++] = astrndup(a, p, len);
	}
	out->rule.n = nr;
	out->rule.v = r;
	out->other.n = no;
	out->other.v = other;
	out->alias.n = na;
	out->alias.v = al;
	return (0);
}

/* An address into the union of the ip-address-no-zone type. */
static bool
addr_union(cbl_yarena *a, const ucl_object_t *o, const char *key, void *u)
{
	struct arcana_firewall_firewall_trace_output_packet_source	*s = u;
	const char							*v;

	if ((v = yj_str(a, o, key)) == NULL)
		return (false);
	s->which = strchr(v, ':') != NULL ? 1 : 0;
	s->v.m0 = v;
	return (true);
}

int
yfw_trace_from_json(const char *json, cbl_yarena *a,
    struct arcana_firewall_firewall_trace_output *out)
{
	struct arcana_firewall_firewall_trace_output_packet	*v;
	const ucl_object_t					*e;
	ucl_object_iter_t					 it;
	ucl_object_t						*top;
	const char						*s;
	size_t							 n = 0;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	YJ_NUM(top, "seconds", out, seconds);
	YJ_NUM(top, "limit", out, limit);
	if ((v = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "packets")) + 1) * sizeof(*v))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "packets"), it, e) {
		memset(&v[n], 0, sizeof(v[n]));
		YJ_NUM(e, "ms", &v[n], ms);
		v[n].verdict = yj_str(a, e, "verdict");
		if ((s = yj_str(a, e, "family")) != NULL) {
			v[n].has_family = true;
			v[n].family = strcmp(s, "ipv6") == 0 ?
			    ARCANA_FIREWALL_FIREWALL_TRACE_OUTPUT_PACKET_FAMILY_IPV6 :
			    ARCANA_FIREWALL_FIREWALL_TRACE_OUTPUT_PACKET_FAMILY_IPV4;
		}
		v[n].has_source = addr_union(a, e, "source", &v[n].source);
		v[n].has_destination = addr_union(a, e, "destination",
		    &v[n].destination);
		YJ_NUM(e, "proto", &v[n], proto);
		YJ_NUM(e, "sport", &v[n], sport);
		YJ_NUM(e, "dport", &v[n], dport);
		YJ_NUM(e, "rule", &v[n], rule);
		v[n].interface = yj_str(a, e, "interface");
		if ((s = yj_str(a, e, "direction")) != NULL) {
			v[n].has_direction = true;
			v[n].direction = strcmp(s, "out") == 0 ?
			    ARCANA_FIREWALL_FIREWALL_TRACE_OUTPUT_PACKET_DIRECTION_OUT :
			    ARCANA_FIREWALL_FIREWALL_TRACE_OUTPUT_PACKET_DIRECTION_IN;
		}
		n++;
	}
	out->packet.n = n;
	out->packet.v = v;
	ucl_object_unref(top);
	return (0);
}
