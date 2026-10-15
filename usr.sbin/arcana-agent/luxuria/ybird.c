/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: BIRD as YANG, arcana-bird (PLAN-SDN-YANG 3.1.8): the bird
 * kind of the network operation (bird.c, do_bird()) read back as the
 * module's state, the bird-routes kind as the routes action's output,
 * the bird-config operation's reply as the configuration's file.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

typedef struct arcana_bird_bird_state ystate;
typedef struct arcana_bird_bird_state_protocol yproto;

static bool
addr_union(cbl_yarena *a, const ucl_object_t *o, const char *key, void *u)
{
	struct arcana_bird_bird_state_protocol_bgp_neighbor	*s = u;
	const char						*v;

	if ((v = yj_str(a, o, key)) == NULL)
		return (false);
	s->which = strchr(v, ':') != NULL ? 1 : 0;
	s->v.m0 = v;
	return (true);
}

/* A number printed as text ("65001"), into its has_ and value. */
#define	YJ_TEXTNUM(o, key, y, f)	do {				\
	const ucl_object_t *e_ = ucl_object_lookup((o), (key));		\
									\
	if (e_ != NULL && ucl_object_type(e_) == UCL_STRING) {		\
		(y)->has_##f = true;					\
		(y)->f = (__typeof__((y)->f))strtoull(			\
		    ucl_object_tostring(e_), NULL, 10);			\
	} else								\
		YJ_NUM((o), (key), (y), f);				\
} while (0)

static int
protocol_of(cbl_yarena *a, const ucl_object_t *o, yproto *p)
{
	struct arcana_bird_bird_state_protocol_bgp	*b;
	struct arcana_bird_bird_state_protocol_rpki	*r;
	struct arcana_bird_bird_state_protocol_channel	*c;
	const ucl_object_t				*e;
	ucl_object_iter_t				 it;
	size_t						 n = 0;

	memset(p, 0, sizeof(*p));
	p->name = yj_str(a, o, "name");
	p->type = yj_str(a, o, "proto");
	p->table = yj_str(a, o, "table");
	p->state = yj_str(a, o, "state");
	p->since = yj_str(a, o, "since");
	p->info = yj_str(a, o, "info");
	p->description = yj_str(a, o, "description");
	if (ucl_object_lookup(o, "bgp-state") != NULL || ucl_object_lookup(o,
	    "neighbor") != NULL) {
		if ((b = cbl_yarena_alloc(a, sizeof(*b))) == NULL)
			return (ENOMEM);
		memset(b, 0, sizeof(*b));
		b->state = yj_str(a, o, "bgp-state");
		b->has_neighbor = addr_union(a, o, "neighbor", &b->neighbor);
		YJ_TEXTNUM(o, "neighbor-as", b, neighbor_as);
		YJ_TEXTNUM(o, "local-as", b, local_as);
		b->neighbor_id = yj_str(a, o, "neighbor-id");
		b->has_source = addr_union(a, o, "source", &b->source);
		b->session = yj_str(a, o, "session");
		b->hold = yj_str(a, o, "hold");
		b->keepalive = yj_str(a, o, "keepalive");
		b->last_error = yj_str(a, o, "last-error");
		p->bgp = b;
	}
	if (ucl_object_lookup(o, "cache") != NULL || ucl_object_lookup(o,
	    "rpki-status") != NULL) {
		if ((r = cbl_yarena_alloc(a, sizeof(*r))) == NULL)
			return (ENOMEM);
		r->cache = yj_str(a, o, "cache");
		r->status = yj_str(a, o, "rpki-status");
		r->serial = yj_str(a, o, "serial");
		r->last_update = yj_str(a, o, "last-update");
		p->rpki = r;
	}
	if ((c = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(o,
	    "channels")) + 1) * sizeof(*c))) == NULL)
		return (ENOMEM);
	YJ_EACH(ucl_object_lookup(o, "channels"), it, e) {
		memset(&c[n], 0, sizeof(c[n]));
		if ((c[n].name = yj_str(a, e, "name")) == NULL)
			continue;
		c[n].state = yj_str(a, e, "state");
		c[n].table = yj_str(a, e, "table");
		c[n].input_filter = yj_str(a, e, "input-filter");
		c[n].output_filter = yj_str(a, e, "output-filter");
		c[n].routes = yj_str(a, e, "routes");
		YJ_NUM(e, "imported", &c[n], imported);
		YJ_NUM(e, "exported", &c[n], exported);
		n++;
	}
	p->channel.n = n;
	p->channel.v = c;
	return (0);
}

int
ybird_from_json(const char *json, cbl_yarena *a, ystate *out)
{
	struct arcana_bird_bird_state_ospf_neighbor	*on;
	struct arcana_bird_bird_state_bfd_session	*bs;
	struct arcana_bird_bird_state_table		*t;
	yproto						*p;
	const ucl_object_t				*e;
	ucl_object_iter_t				 it;
	ucl_object_t					*top;
	size_t						 n;
	int						 error = ENOMEM;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if (yj_strs(a, ucl_object_lookup(top, "status"), &out->status.n,
	    &out->status.v) != 0)
		goto out;
	if ((p = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "protocols")) + 1) * sizeof(*p))) == NULL)
		goto out;
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "protocols"), it, e) {
		if ((error = protocol_of(a, e, &p[n])) != 0)
			goto out;
		if (p[n].name != NULL)
			n++;
	}
	out->protocol.n = n;
	out->protocol.v = p;
	error = ENOMEM;
	if ((on = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "ospf")) + 1) * sizeof(*on))) == NULL)
		goto out;
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "ospf"), it, e) {
		on[n].protocol = yj_str(a, e, "proto");
		on[n].router_id = yj_str(a, e, "router-id");
		on[n].priority = yj_str(a, e, "pri");
		on[n].state = yj_str(a, e, "state");
		on[n].dead_time = yj_str(a, e, "dtime");
		on[n].interface = yj_str(a, e, "interface");
		on[n].address = yj_str(a, e, "address");
		n++;
	}
	out->ospf_neighbor.n = n;
	out->ospf_neighbor.v = on;
	if ((bs = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "bfd")) + 1) * sizeof(*bs))) == NULL)
		goto out;
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "bfd"), it, e) {
		bs[n].protocol = yj_str(a, e, "proto");
		bs[n].address = yj_str(a, e, "address");
		bs[n].interface = yj_str(a, e, "interface");
		bs[n].state = yj_str(a, e, "state");
		bs[n].since = yj_str(a, e, "since");
		bs[n].interval = yj_str(a, e, "interval");
		bs[n].timeout = yj_str(a, e, "timeout");
		n++;
	}
	out->bfd_session.n = n;
	out->bfd_session.v = bs;
	if ((t = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "tables")) + 1) * sizeof(*t))) == NULL)
		goto out;
	n = 0;
	YJ_EACH(ucl_object_lookup(top, "tables"), it, e) {
		memset(&t[n], 0, sizeof(t[n]));
		if ((t[n].name = yj_str(a, e, "name")) == NULL)
			continue;
		YJ_NUM(e, "routes", &t[n], routes);
		YJ_NUM(e, "networks", &t[n], networks);
		n++;
	}
	out->table.n = n;
	out->table.v = t;
	error = 0;
out:
	ucl_object_unref(top);
	return (error);
}

int
ybird_routes_from_json(const char *json, cbl_yarena *a,
    struct arcana_bird_bird_routes_output *out)
{
	struct arcana_bird_bird_routes_output_route		*r;
	struct arcana_bird_bird_routes_output_route_nexthop	*nh;
	const ucl_object_t					*e, *h;
	ucl_object_iter_t					 it, hit;
	ucl_object_t						*top;
	size_t							 n = 0, k;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	YJ_NUM(top, "count", out, count);
	out->message = yj_str(a, top, "message");
	if ((r = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "routes")) + 1) * sizeof(*r))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "routes"), it, e) {
		memset(&r[n], 0, sizeof(r[n]));
		r[n].table = yj_str(a, e, "table");
		r[n].prefix = yj_str(a, e, "prefix");
		r[n].type = yj_str(a, e, "type");
		r[n].protocol = yj_str(a, e, "protocol");
		r[n].from = yj_str(a, e, "from");
		r[n].since = yj_str(a, e, "since");
		r[n].primary = yj_yes(e, "primary", &r[n].has_primary);
		r[n].preference = yj_str(a, e, "preference");
		r[n].info = yj_str(a, e, "info");
		if ((nh = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(e,
		    "nexthops")) + 1) * sizeof(*nh))) == NULL) {
			ucl_object_unref(top);
			return (ENOMEM);
		}
		k = 0;
		YJ_EACH(ucl_object_lookup(e, "nexthops"), hit, h) {
			nh[k].via = yj_str(a, h, "via");
			nh[k].interface = yj_str(a, h, "interface");
			k++;
		}
		r[n].nexthop.n = k;
		r[n].nexthop.v = nh;
		if (yj_strs(a, ucl_object_lookup(e, "attrs"), &r[n].attribute.n,
		    &r[n].attribute.v) != 0) {
			ucl_object_unref(top);
			return (ENOMEM);
		}
		n++;
	}
	out->route.n = n;
	out->route.v = r;
	ucl_object_unref(top);
	return (0);
}

/* The bird-config reply: the file read, with the files the
 * configuration is made of (their texts not read here). */
int
ybird_config_from(const char *path, const char *text, const char *sha256,
    const char *const *files, size_t nfiles, cbl_yarena *a,
    struct arcana_bird_bird_configuration *out)
{
	struct arcana_bird_bird_configuration_file	*f;
	size_t						 i, n = 0;
	bool						 seen = false;

	memset(out, 0, sizeof(*out));
	if ((f = cbl_yarena_alloc(a, (nfiles + 2) * sizeof(*f))) == NULL)
		return (ENOMEM);
	for (i = 0; i < nfiles; i++) {
		memset(&f[n], 0, sizeof(f[n]));
		f[n].path = files[i];
		if (path != NULL && strcmp(files[i], path) == 0) {
			f[n].text = text;
			f[n].sha256 = sha256;
			seen = true;
		}
		n++;
	}
	if (!seen && path != NULL) {
		memset(&f[n], 0, sizeof(f[n]));
		f[n].path = path;
		f[n].text = text;
		f[n].sha256 = sha256;
		n++;
	}
	out->path = nfiles > 0 ? files[0] : path;
	out->file.n = n;
	out->file.v = f;
	return (0);
}
