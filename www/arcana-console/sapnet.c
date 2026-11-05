/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The fleet's service attachment points (RFC 9408 over RFC 8345), the
 * console's own data:
 *
 *	GET /restconf/data/ietf-network:networks[/network=<id>]
 *
 * Each agent serves its host as network arcana-sap, one node
 * (invidia/ysap.c); the console reads every host's through the fleet
 * mount, the user's hosts alone, and merges them: network
 * arcana-physical, a node each host (node-id its id, the L3NM's ne-id),
 * its interfaces termination points and an epair(4)'s two ends a link;
 * over it network arcana-sap, the same nodes with their SAPs.  A host
 * not read, or whose agent has no SAP network (a release before
 * 4.6.1), is left out.
 *
 * service-status is the console's, of the L3NM kept (where the user may
 * read it): an access names a SAP by its interface-id, the SAP's
 * attachment-interface, at the vpn-node whose ne-id is the SAP's node
 * (RFC 9408 Appendix D).  Its admin-status the access's (else its
 * node's, its service's; admin-up where none says), admin-down where
 * none names it; oper-status op-up where the last apply made the UNI
 * and the SAP is up.  The SAP's anomalies (section 5): a service
 * admin-up at a SAP down (its own sap-status, or its parent's, which
 * overrides it), a service admin-down where it is operationally up.  A
 * UNI that is up, that no access names and that has no anomaly is free
 * (arcana-l3nm's free, attachment and anomaly).
 *
 * Appendix D's flow, a service placed on a free SAP (4.6.3):
 *
 *	POST /api/sdwan/attach	{"vpn-id", "vpn-node-id"[, "sap-id"]
 *				[, "access"]}
 *
 * the edge's host read, the SAP named (or the first free one fit for
 * the access: a dot1q or qinq one where child SAPs are allowed) taken
 * when free, and an access made of it at the edge's vpn-node of the
 * service (the node made where the service has none, its ne-id the
 * host): its id the sap-id, its interface-id the attachment-interface,
 * the rest "access" (L3NM's vpn-network-access).  201 with what was
 * made; 404, no such service, host or SAP; 409, the SAP not free, or
 * none is.
 *
 * The hosts are read on a task of the pool, one after another.
 */

#include <sys/param.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <cbl_data.h>
#include <ucl.h>

#include "console.h"
#include "restconf.h"
#include "ymodel.h"
#include "yjsonin.h"

#define	SN_PATH		"/restconf/data/ietf-network:networks"
#define	SN_MEMBER	"ietf-network:networks"
#define	SN_SAP		"arcana-sap"
#define	SN_PHYS		"arcana-physical"
#define	L3NM_PATH	"/restconf/data/ietf-l3vpn-ntw:l3vpn-ntw"
#define	TP		"ietf-network-topology:termination-point"
#define	SVC		"ietf-sap-ntw:service"

struct snhost {
	char	 sid[16];
	char	*uri;
	char	*peer;
	char	*name;
};

struct snreq {
	struct task	 task;		/* first: the server frees it */
	struct snhost	*h;
	size_t		 nh;
	bool		 l3nm;		/* the user may read the L3NM */
	char		 net[64];	/* one network asked; "": all */
	ucl_object_t	*top;		/* the reply */
	int		 status;
	char		 why[300];
	/* An attach's: */
	bool		 attach;
	char		*svc;
	char		*edge;
	char		*sap;		/* asked; NULL: the first free */
	ucl_object_t	*access;	/* the rest of the access, or NULL */
};

static const ucl_object_t *
get(const ucl_object_t *o, const char *k)
{

	return (o != NULL ? ucl_object_lookup(o, k) : NULL);
}

static const char *
gstr(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v = get(o, k);

	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

/* Entry i of array l; NULL past its last, or where l is none. */
static const ucl_object_t *
at(const ucl_object_t *l, unsigned i)
{

	return (l != NULL && ucl_object_type(l) == UCL_ARRAY ?
	    ucl_array_find_index(l, i) : NULL);
}

/* Whether identity value v (module:name, or name) is name. */
static bool
ident_is(const char *v, const char *name)
{
	const char	*c;

	if (v == NULL)
		return (false);
	c = strchr(v, ':');
	return (strcmp(c != NULL ? c + 1 : v, name) == 0);
}

static void
put(ucl_object_t *o, const char *k, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, k, 0, true);
}

static void
puts_(ucl_object_t *o, const char *k, const char *v)
{

	put(o, k, ucl_object_fromstring(v));
}

static ucl_object_t *
obj(void)
{

	return (ucl_object_typed_new(UCL_OBJECT));
}

static ucl_object_t *
arr(void)
{

	return (ucl_object_typed_new(UCL_ARRAY));
}

/* ---- The L3NM at a SAP --------------------------------------------- */

/* Entry i of list member k of o's container c; NULL past the last. */
static const ucl_object_t *
entry(const ucl_object_t *o, const char *c, const char *k, unsigned i)
{
	const ucl_object_t	*l = get(get(o, c), k);

	return (l != NULL && ucl_object_type(l) == UCL_ARRAY ?
	    ucl_array_find_index(l, i) : NULL);
}

static const char *
admin_of(const ucl_object_t *o)
{

	return (gstr(get(get(o, "status"), "admin-status"), "status"));
}

/* The host (a server's id) of vpn-node n, in buf. */
static const char *
node_host(const ucl_object_t *n, char *buf, size_t len)
{
	const char	*ne = gstr(n, "ne-id"), *id = gstr(n, "vpn-node-id");
	char		 jail[64];

	if (ne != NULL)
		return (ne);
	if (id != NULL && sdwan_edge_split(id, buf, len, jail, sizeof(jail)))
		return (buf);
	return (id);
}

/* Whether access a names SAP s. */
static bool
names(const ucl_object_t *a, const ucl_object_t *s)
{
	const char	*ifn = gstr(a, "interface-id");
	const char	*at = gstr(s, "attachment-interface");

	if (ifn != NULL)
		return (strcmp(ifn, at != NULL ? at : gstr(s, "sap-id")) == 0);
	return (gstr(a, "id") != NULL && strcmp(gstr(a, "id"),
	    gstr(s, "sap-id")) == 0);
}

/* The status of SAP s of node sn, its parent's where that is down. */
static const char *
sap_status(const ucl_object_t *sn, const ucl_object_t *s)
{
	const ucl_object_t	*svc, *p;
	const char		*st, *parent;

	st = gstr(get(s, "sap-status"), "status");
	if ((parent = gstr(s, "parent-termination-point")) == NULL)
		return (st);
	for (unsigned i = 0; (svc = at(get(sn, SVC), i)) !=
	    NULL; i++)
		for (unsigned k = 0; (p = at(get(svc, "sap"),
		    k)) != NULL; k++)
			if (gstr(p, "sap-id") != NULL && strcmp(gstr(p,
			    "sap-id"), parent) == 0 &&
			    ident_is(gstr(get(p, "sap-status"), "status"),
			    "op-down"))
				return (gstr(get(p, "sap-status"), "status"));
	return (st);
}

/*
 * SAP s of host sid (its node sn) with what the L3NM y has at it, the
 * UNIs applied has made: its service-status, attachments, anomalies and
 * whether it is free.
 */
static void
sap_fill(ucl_object_t *s, const ucl_object_t *sn, const char *sid,
    const ucl_object_t *y, const ucl_object_t *applied)
{
	const ucl_object_t	*svc, *n, *a;
	ucl_object_t		*atts, *e, *ss, *an;
	const char		*adm, *st;
	char			 host[64], key[200];
	bool			 up, aup = false, oup = false, made;
	bool			 down_up = false, up_down = false;

	st = sap_status(sn, s);
	up = ident_is(st, "op-up");
	atts = arr();
	for (unsigned i = 0; (svc = entry(y, "vpn-services", "vpn-service",
	    i)) != NULL; i++)
		for (unsigned k = 0; (n = entry(svc, "vpn-nodes", "vpn-node",
		    k)) != NULL; k++) {
			const char *h = node_host(n, host, sizeof(host));

			if (h == NULL || strcmp(h, sid) != 0)
				continue;
			for (unsigned j = 0; (a = entry(n,
			    "vpn-network-accesses", "vpn-network-access", j)) !=
			    NULL; j++) {
				if (gstr(a, "id") == NULL || !names(a, s))
					continue;
				if ((adm = admin_of(a)) == NULL &&
				    (adm = admin_of(n)) == NULL)
					adm = admin_of(svc);
				snprintf(key, sizeof(key), "uni:%s",
				    gstr(a, "id"));
				made = get(get(applied, gstr(n, "vpn-node-id")),
				    key) != NULL;
				if (adm == NULL || ident_is(adm, "admin-up")) {
					aup = true;
					if (!up)
						down_up = true;
				} else if (made && up)
					up_down = true;
				if (made && up)
					oup = true;
				e = obj();
				puts_(e, "vpn-id", gstr(svc, "vpn-id"));
				puts_(e, "access-id", gstr(a, "id"));
				puts_(e, "vpn-node-id", gstr(n, "vpn-node-id"));
				put(e, "made", ucl_object_frombool(made));
				ucl_array_append(atts, e);
			}
		}
	ss = obj();
	e = obj();
	puts_(e, "status", aup ? "ietf-vpn-common:admin-up" :
	    "ietf-vpn-common:admin-down");
	put(ss, "admin-status", e);
	if (ucl_array_size(atts) > 0) {
		e = obj();
		puts_(e, "status", oup ? "ietf-vpn-common:op-up" :
		    "ietf-vpn-common:op-down");
		put(ss, "oper-status", e);
	}
	put(s, "service-status", ss);
	an = arr();
	if (down_up)
		ucl_array_append(an, ucl_object_fromstring(
		    "arcana-l3nm:sap-down-service-up"));
	if (up_down)
		ucl_array_append(an, ucl_object_fromstring(
		    "arcana-l3nm:service-down-oper-up"));
	put(s, "arcana-l3nm:free", ucl_object_frombool(ident_is(gstr(s,
	    "role"), "uni") && up && ucl_array_size(atts) == 0 &&
	    ucl_array_size(an) == 0));
	if (ucl_array_size(atts) > 0)
		put(s, "arcana-l3nm:attachment", atts);
	else
		ucl_object_unref(atts);
	if (ucl_array_size(an) > 0)
		put(s, "arcana-l3nm:anomaly", an);
	else
		ucl_object_unref(an);
}

/* ---- The hosts' nodes, merged ---------------------------------------- */

/* The SAP network's network-types. */
static ucl_object_t *
sap_types(void)
{
	ucl_object_t	*o, *a, *t;

	a = arr();
	ucl_array_append(a, ucl_object_fromstring("ietf-sap-ntw:sdwan"));
	o = obj();
	put(o, "service-type", a);
	t = obj();
	put(t, "ietf-sap-ntw:sap-network", o);
	return (t);
}

static const struct cbl_ynode *
networks_node(void)
{
	const struct cbl_ymodule	*m;

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, "ietf-network") != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++)
			if (strcmp(m->top[k]->name, "networks") == 0)
				return (m->top[k]);
	}
	return (NULL);
}

/* Whether networks nws (ietf-network:networks' value) is of the schema:
 * its types, references and conditions; why where not. */
static bool
valid(const ucl_object_t *nws, char *why, size_t len)
{
	const struct cbl_ynode	*n;
	struct cbl_dederr	 derr;
	cbl_dtree		*t;
	cbl_yarena		*a;
	bool			 ok;

	if ((n = networks_node()) == NULL || (a = cbl_yarena_new()) == NULL) {
		snprintf(why, len, "out of memory");
		return (false);
	}
	if ((t = cbl_dtree_new(&ymodel_schema)) == NULL) {
		cbl_yarena_free(a);
		snprintf(why, len, "out of memory");
		return (false);
	}
	ok = yjson_member(t, n, nws, a, why, len) == 0;
	if (ok && (cbl_dtree_check_refs(t, &derr) != 0 ||
	    cbl_dtree_check_conds(t, &derr) != 0)) {
		snprintf(why, len, "%s", derr.msg);
		ok = false;
	}
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	return (ok);
}

/* Host h's SAP node, its agent's; NULL: none (why says). */
static ucl_object_t *
host_node(const struct snhost *h, char *why, size_t len)
{
	const ucl_object_t	*nw, *nd;
	struct ucl_parser	*p;
	ucl_object_t		*o = NULL, *out = NULL;
	char			 path[256], *json;
	int			 status;

	snprintf(path, sizeof(path), "/restconf/ds/ietf-datastores:"
	    "operational/arcana-fleet:fleet/host=%s/" SN_MEMBER, h->sid);
	json = hosts_restconf(h->sid, h->uri, h->peer, h->name,
	    HTTP_METHOD_GET, path, NULL, &status);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	if (json != NULL && ucl_parser_add_string(p, json, 0))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	if (status != 200) {
		snprintf(why, len, "%d: %s", status, o != NULL &&
		    ucl_object_tostring(ucl_object_lookup_path(o,
		    "ietf-restconf:errors.error.0.error-message")) != NULL ?
		    ucl_object_tostring(ucl_object_lookup_path(o,
		    "ietf-restconf:errors.error.0.error-message")) :
		    "no SAP network");
		free(json);
		ucl_object_unref(o);
		return (NULL);
	}
	free(json);
	for (unsigned i = 0; (nw = at(get(get(o, SN_MEMBER),
	    "network"), i)) != NULL; i++)
		if (gstr(nw, "network-id") != NULL && strcmp(gstr(nw,
		    "network-id"), SN_SAP) == 0 && (nd = at(
		    get(nw, "node"), 0)) != NULL)
			out = ucl_object_copy(nd);
	ucl_object_unref(o);
	if (out == NULL)
		snprintf(why, len, "no node in %s", SN_SAP);
	return (out);
}

/* "network-ref": SN_PHYS, and "node-ref": sid, "tp-ref": tp where said. */
static ucl_object_t *
ref(const char *sid, const char *tp)
{
	ucl_object_t	*r = obj();

	puts_(r, "network-ref", SN_PHYS);
	if (sid != NULL)
		puts_(r, "node-ref", sid);
	if (tp != NULL)
		puts_(r, "tp-ref", tp);
	return (r);
}

/* What node sd (the agent's) gives the physical network, of host sid:
 * its node, and a link each epair's pair into links. */
static ucl_object_t *
phys_node(const ucl_object_t *sd, const char *sid, ucl_object_t *links)
{
	const ucl_object_t	*tp, *svc, *s, *peer;
	ucl_object_t		*nd, *tps, *l, *e;
	const char		*a, *b;
	char			 id[200];
	bool			 ha, hb;

	nd = obj();
	puts_(nd, "node-id", sid);
	tps = arr();
	for (unsigned i = 0; (tp = at(get(sd, TP), i)) !=
	    NULL; i++)
		if (gstr(tp, "tp-id") != NULL) {
			e = obj();
			puts_(e, "tp-id", gstr(tp, "tp-id"));
			ucl_array_append(tps, e);
		}
	put(nd, TP, tps);
	for (unsigned i = 0; (svc = at(get(sd, SVC), i)) !=
	    NULL; i++)
		for (unsigned k = 0; (s = at(get(svc, "sap"),
		    k)) != NULL; k++) {
			a = gstr(s, "sap-id");
			peer = at(get(s, "peer-sap-id"), 0);
			b = peer != NULL ? ucl_object_tostring(peer) : NULL;
			/* Each pair once, both its ends here. */
			if (a == NULL || b == NULL || strcmp(a, b) >= 0)
				continue;
			ha = hb = false;
			for (unsigned j = 0; (tp = at(get(sd,
			    TP), j)) != NULL; j++) {
				ha |= gstr(tp, "tp-id") != NULL && strcmp(gstr(
				    tp, "tp-id"), a) == 0;
				hb |= gstr(tp, "tp-id") != NULL && strcmp(gstr(
				    tp, "tp-id"), b) == 0;
			}
			if (!ha || !hb)
				continue;
			snprintf(id, sizeof(id), "%s/%s,%s", sid, a, b);
			l = obj();
			puts_(l, "link-id", id);
			e = obj();
			puts_(e, "source-node", sid);
			puts_(e, "source-tp", a);
			put(l, "source", e);
			e = obj();
			puts_(e, "dest-node", sid);
			puts_(e, "dest-tp", b);
			put(l, "destination", e);
			ucl_array_append(links, l);
		}
	return (nd);
}

/* Node sd of host sid as the SAP network has it: its supporting node
 * and termination points, each SAP with the L3NM's (y NULL: none). */
static ucl_object_t *
sap_node(const ucl_object_t *sd, const char *sid, const ucl_object_t *y,
    const ucl_object_t *applied)
{
	const ucl_object_t	*tp, *svc, *s;
	ucl_object_t		*nd, *a, *e, *svcs, *sv, *saps;

	nd = obj();
	puts_(nd, "node-id", sid);
	a = arr();
	ucl_array_append(a, ref(sid, NULL));
	put(nd, "supporting-node", a);
	a = arr();
	for (unsigned i = 0; (tp = at(get(sd, TP), i)) !=
	    NULL; i++) {
		if (gstr(tp, "tp-id") == NULL)
			continue;
		e = obj();
		puts_(e, "tp-id", gstr(tp, "tp-id"));
		sv = arr();
		ucl_array_append(sv, ref(sid, gstr(tp, "tp-id")));
		put(e, "supporting-termination-point", sv);
		ucl_array_append(a, e);
	}
	put(nd, TP, a);
	svcs = arr();
	for (unsigned i = 0; (svc = at(get(sd, SVC), i)) !=
	    NULL; i++) {
		sv = obj();
		put(sv, "service-type", ucl_object_copy(get(svc,
		    "service-type")));
		saps = arr();
		for (unsigned k = 0; (s = at(get(svc, "sap"),
		    k)) != NULL; k++) {
			e = ucl_object_copy(s);
			if (y != NULL)
				sap_fill(e, sd, sid, y, applied);
			ucl_array_append(saps, e);
		}
		put(sv, "sap", saps);
		ucl_array_append(svcs, sv);
	}
	put(nd, SVC, svcs);
	return (nd);
}

/* The fleet's SAP network and the physical network under it, of the
 * hosts of r: ietf-network:networks' value. */
static ucl_object_t *
merge(struct snreq *r)
{
	ucl_object_t	*nws, *list, *phys, *sap, *pn, *sn, *links, *o, *a;
	ucl_object_t	*y, *applied, *one;
	char		 why[300];

	y = r->l3nm ? l3nm_kept() : NULL;
	applied = r->l3nm ? sdwan_applied() : NULL;
	pn = arr();
	sn = arr();
	links = arr();
	for (size_t i = 0; i < r->nh; i++) {
		ucl_object_t *sd;

		why[0] = '\0';
		if ((sd = host_node(&r->h[i], why, sizeof(why))) == NULL) {
			log_msg(LOG_INFO, "%s: SAP network not read: %s",
			    r->h[i].name, why);
			continue;
		}
		/* Its node of the schema, or left out. */
		one = obj();
		o = obj();
		puts_(o, "network-id", SN_SAP);
		put(o, "network-types", sap_types());
		a = arr();
		ucl_array_append(a, ucl_object_copy(sd));
		put(o, "node", a);
		a = arr();
		ucl_array_append(a, o);
		put(one, "network", a);
		if (!valid(one, why, sizeof(why))) {
			log_msg(LOG_WARNING, "%s: SAP network left out: %s",
			    r->h[i].name, why);
			ucl_object_unref(one);
			ucl_object_unref(sd);
			continue;
		}
		ucl_object_unref(one);
		ucl_array_append(pn, phys_node(sd, r->h[i].sid, links));
		ucl_array_append(sn, sap_node(sd, r->h[i].sid, y, applied));
		ucl_object_unref(sd);
	}
	if (y != NULL)
		ucl_object_unref(y);
	if (applied != NULL)
		ucl_object_unref(applied);

	phys = obj();
	puts_(phys, "network-id", SN_PHYS);
	put(phys, "network-types", obj());
	put(phys, "node", pn);
	if (ucl_array_size(links) > 0)
		put(phys, "ietf-network-topology:link", links);
	else
		ucl_object_unref(links);

	sap = obj();
	puts_(sap, "network-id", SN_SAP);
	put(sap, "network-types", sap_types());
	a = arr();
	ucl_array_append(a, ref(NULL, NULL));
	put(sap, "supporting-network", a);
	put(sap, "node", sn);

	list = arr();
	ucl_array_append(list, phys);
	ucl_array_append(list, sap);
	nws = obj();
	put(nws, "network", list);
	return (nws);
}

static int
sapnet_run(struct task *t)
{
	struct snreq		*r = (struct snreq *)t;
	ucl_object_t		*nws;
	const ucl_object_t	*nw;

	nws = merge(r);
	if (!valid(nws, r->why, sizeof(r->why))) {
		log_msg(LOG_ERR, "the SAP network made is not of its schema: "
		    "%s", r->why);
		ucl_object_unref(nws);
		r->status = 500;
		return (0);
	}
	r->top = obj();
	if (r->net[0] == '\0') {
		put(r->top, SN_MEMBER, nws);
		r->status = 200;
		return (0);
	}
	r->status = 404;
	snprintf(r->why, sizeof(r->why), "no such network");
	for (unsigned i = 0; (nw = at(get(nws, "network"),
	    i)) != NULL; i++)
		if (gstr(nw, "network-id") != NULL && strcmp(gstr(nw,
		    "network-id"), r->net) == 0) {
			ucl_object_t *a = arr();

			ucl_array_append(a, ucl_object_copy(nw));
			put(r->top, "ietf-network:network", a);
			r->status = 200;
		}
	ucl_object_unref(nws);
	return (0);
}

/* ---- A service placed on a free SAP (Appendix D) -------------------- */

/* Whether SAP s can take access a: free, and with child SAPs where the
 * access is tagged. */
static bool
fits(const ucl_object_t *s, const ucl_object_t *a)
{
	const char	*enc;

	if (!ucl_object_toboolean(get(s, "arcana-l3nm:free")))
		return (false);
	enc = gstr(get(get(a, "connection"), "encapsulation"), "type");
	if (enc != NULL && (ident_is(enc, "dot1q") || ident_is(enc, "qinq")))
		return (ucl_object_toboolean(get(s, "allows-child-saps")));
	return (true);
}

/* Why SAP s is not free, in why. */
static void
not_free(const ucl_object_t *s, char *why, size_t len)
{
	const ucl_object_t	*e;

	if ((e = at(get(s, "arcana-l3nm:attachment"), 0)) != NULL)
		snprintf(why, len, "SAP %s is not free: access %s of %s names "
		    "it", gstr(s, "sap-id"), gstr(e, "access-id"), gstr(e,
		    "vpn-id"));
	else if (at(get(s, "arcana-l3nm:anomaly"), 0) != NULL)
		snprintf(why, len, "SAP %s is not free: %s", gstr(s, "sap-id"),
		    ucl_object_tostring(at(get(s, "arcana-l3nm:anomaly"), 0)));
	else if (!ident_is(gstr(s, "role"), "uni"))
		snprintf(why, len, "SAP %s is not free: not a UNI", gstr(s,
		    "sap-id"));
	else
		snprintf(why, len, "SAP %s is not free: it is %s, not up",
		    gstr(s, "sap-id"), gstr(get(s, "sap-status"), "status") !=
		    NULL ? gstr(get(s, "sap-status"), "status") : "unknown");
}

static int
attach_run(struct task *t)
{
	struct snreq		*r = (struct snreq *)t;
	const ucl_object_t	*svc, *s, *n, *node = NULL;
	ucl_object_t		*sd, *y, *applied, *c, *pick = NULL, *acc;
	ucl_object_t		*ny, *o, *l, *nn;
	char			 why[300];
	const char		*ifn;
	int			 st;

	if ((sd = host_node(&r->h[0], why, sizeof(why))) == NULL) {
		r->status = 409;
		snprintf(r->why, sizeof(r->why), "%s's SAPs were not read: %s",
		    r->h[0].name, why);
		return (0);
	}
	y = l3nm_kept();
	applied = sdwan_applied();
	for (unsigned i = 0; (svc = entry(y, "vpn-services", "vpn-service",
	    i)) != NULL; i++)
		if (gstr(svc, "vpn-id") != NULL && strcmp(gstr(svc, "vpn-id"),
		    r->svc) == 0)
			for (unsigned k = 0; (n = entry(svc, "vpn-nodes",
			    "vpn-node", k)) != NULL; k++)
				if (gstr(n, "vpn-node-id") != NULL &&
				    strcmp(gstr(n, "vpn-node-id"), r->edge) == 0)
					node = n;
	r->status = r->sap != NULL ? 404 : 409;
	snprintf(r->why, sizeof(r->why), r->sap != NULL ? "%s has no SAP "
	    "%s" : "%s has no free SAP fit for the access", r->h[0].name,
	    r->sap != NULL ? r->sap : "");
	for (unsigned i = 0; pick == NULL && (svc = at(get(sd, SVC), i)) !=
	    NULL; i++)
		for (unsigned k = 0; pick == NULL && (s = at(get(svc, "sap"),
		    k)) != NULL; k++) {
			if (gstr(s, "sap-id") == NULL || (r->sap != NULL &&
			    strcmp(gstr(s, "sap-id"), r->sap) != 0))
				continue;
			c = ucl_object_copy(s);
			sap_fill(c, sd, r->h[0].sid, y, applied);
			if (fits(c, r->access)) {
				pick = c;
				continue;
			}
			if (r->sap != NULL) {
				r->status = 409;
				if (!ucl_object_toboolean(get(c,
				    "arcana-l3nm:free")))
					not_free(c, r->why, sizeof(r->why));
				else
					snprintf(r->why, sizeof(r->why), "SAP "
					    "%s takes no tagged access: it "
					    "allows no child SAP", r->sap);
			}
			ucl_object_unref(c);
		}
	if (pick != NULL) {
		/* Its id the sap-id: none of the node's may have it. */
		for (unsigned j = 0; (n = entry(node, "vpn-network-accesses",
		    "vpn-network-access", j)) != NULL; j++)
			if (gstr(n, "id") != NULL && strcmp(gstr(n, "id"),
			    gstr(pick, "sap-id")) == 0) {
				r->status = 409;
				snprintf(r->why, sizeof(r->why), "%s has an "
				    "access %s already", r->edge, gstr(pick,
				    "sap-id"));
				ucl_object_unref(pick);
				pick = NULL;
				break;
			}
	}
	if (pick != NULL) {
		ifn = gstr(pick, "attachment-interface") != NULL ? gstr(pick,
		    "attachment-interface") : gstr(pick, "sap-id");
		acc = r->access != NULL ? ucl_object_copy(r->access) : obj();
		ucl_object_delete_key(acc, "id");
		ucl_object_delete_key(acc, "interface-id");
		puts_(acc, "id", gstr(pick, "sap-id"));
		puts_(acc, "interface-id", ifn);
		/* The access at the edge's node of the service. */
		nn = obj();
		puts_(nn, "vpn-node-id", r->edge);
		if (node == NULL)
			puts_(nn, "ne-id", r->h[0].sid);
		l = arr();
		ucl_array_append(l, acc);
		o = obj();
		put(o, "vpn-network-access", l);
		put(nn, "vpn-network-accesses", o);
		l = arr();
		ucl_array_append(l, nn);
		o = obj();
		put(o, "vpn-node", l);
		c = obj();
		puts_(c, "vpn-id", r->svc);
		put(c, "vpn-nodes", o);
		l = arr();
		ucl_array_append(l, c);
		o = obj();
		put(o, "vpn-service", l);
		ny = obj();
		put(ny, "vpn-services", o);
		if ((st = l3nm_merge(ny, r->why, sizeof(r->why))) != 0)
			r->status = st;
		else {
			r->status = 201;
			r->top = obj();
			puts_(r->top, "vpn-id", r->svc);
			puts_(r->top, "vpn-node-id", r->edge);
			puts_(r->top, "access-id", gstr(pick, "sap-id"));
			puts_(r->top, "sap-id", gstr(pick, "sap-id"));
			puts_(r->top, "interface-id", ifn);
			puts_(r->top, "host", r->h[0].sid);
		}
		ucl_object_unref(ny);
		ucl_object_unref(pick);
	}
	ucl_object_unref(sd);
	ucl_object_unref(y);
	ucl_object_unref(applied);
	return (0);
}

/* ---- The routes ------------------------------------------------------ */

/* The hosts the user may read, as they are now: the server's list is
 * the loop's. */
static void
hosts_of(struct http_request *req, struct snreq *r)
{
	const struct server	*s;
	int			 i, n;

	for (n = 0; server_at(n) != NULL; n++)
		;
	r->h = xcalloc((size_t)n + 1, sizeof(*r->h));
	for (i = 0; (s = server_at(i)) != NULL; i++) {
		if (!host_role_ok(req, s->id, false, false))
			continue;
		snprintf(r->h[r->nh].sid, sizeof(r->h[r->nh].sid), "%s",
		    s->id);
		r->h[r->nh].uri = xstrdup(s->uri);
		r->h[r->nh].peer = s->peer_name != NULL ? xstrdup(
		    s->peer_name) : NULL;
		r->h[r->nh].name = xstrdup(s->name);
		r->nh++;
	}
}

static int
attach_finish(struct http_request *req, struct snreq *r)
{
	ucl_object_t	*top;

	if (r->status != 201)
		return (reply_error(req, r->status, r->status == 404 ?
		    "unknown" : r->status == 409 ? "refused" : "invalid", "%s",
		    r->why));
	audit_add("policies-changed", "Administer", r->svc, "a service "
	    "placed on a free SAP (RFC 9408 Appendix D)", "the console (the "
	    "Policy Administration Point)", session_who(req), "access %s at "
	    "%s", ucl_object_tostring(ucl_object_lookup(r->top, "access-id")),
	    r->edge);
	top = r->top;
	r->top = NULL;
	return (reply_json(req, 201, top));
}

int
api_sapnet(struct http_request *req)
{
	struct snreq	*r;
	const char	*p, *u;
	ucl_object_t	*top;

	if ((r = req->hdlr_extra) != NULL) {
		if (task_state(&r->task) != TASK_STATE_FINISHED) {
			http_request_sleep(req);
			return (WEB_RETRY);
		}
		if (r->attach)
			return (attach_finish(req, r));
		if (r->status != 200)
			return (restconf_error(req, r->status, r->why));
		top = r->top;
		r->top = NULL;
		return (restconf_reply(req, top));
	}
	if (req->method == HTTP_METHOD_OPTIONS)
		return (api_restconf_data(req));
	if (req->method != HTTP_METHOD_GET)
		return (restconf_error(req, 405, "the SAP network is the "
		    "hosts' state, read alone"));
	if (!guard(req, false))
		return (WEB_OK);
	if (req->query_string != NULL && req->query_string[0] != '\0')
		return (restconf_error(req, 400, "no query parameter is taken "
		    "of the console's own data"));
	r = xcalloc(1, sizeof(*r));
	p = req->path + sizeof(SN_PATH) - 1;
	if (*p == '/') {
		if (strncmp(p, "/network=", 9) != 0 || strlen(p + 9) == 0 ||
		    strlen(p + 9) >= sizeof(r->net) || strchr(p + 9, '/') !=
		    NULL) {
			free(r);
			return (restconf_error(req, 400, "of the SAP network, "
			    "the networks or one network=<network-id>"));
		}
		snprintf(r->net, sizeof(r->net), "%s", p + 9);
	}
	u = session_user(req);
	r->l3nm = u == NULL || user_path_ok(user_console(u), L3NM_PATH, false);
	hosts_of(req, r);
	req->hdlr_extra = r;
	task_create(&r->task, sapnet_run);
	task_bind_request(&r->task, req);
	task_run(&r->task);
	return (WEB_RETRY);
}

/* POST /api/sdwan/attach: a service's access placed on a free SAP. */
int
api_sapnet_attach(struct http_request *req)
{
	const struct server	*sv;
	const ucl_object_t	*svc, *n, *found = NULL, *v;
	ucl_object_t		*body, *y;
	struct snreq		*r;
	const char		*vid, *edge, *host, *sap;
	char			 hbuf[64];

	if ((r = req->hdlr_extra) != NULL)
		return (api_sapnet(req));
	if (!guard(req, true))
		return (WEB_OK);
	if ((body = read_json(req)) == NULL || (vid = gstr(body, "vpn-id")) ==
	    NULL || (edge = gstr(body, "vpn-node-id")) == NULL ||
	    ((v = get(body, "sap-id")) != NULL && ucl_object_type(v) !=
	    UCL_STRING) || ((v = get(body, "access")) != NULL &&
	    ucl_object_type(v) != UCL_OBJECT)) {
		if (body != NULL)
			ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "a JSON object: "
		    "vpn-id, vpn-node-id, and sap-id (none: the first free) "
		    "and access (L3NM's vpn-network-access) where said"));
	}
	sap = gstr(body, "sap-id");
	/* The service, and its node's host: its ne-id, else the edge's. */
	y = l3nm_kept();
	host = NULL;
	for (unsigned i = 0; (svc = entry(y, "vpn-services", "vpn-service",
	    i)) != NULL; i++)
		if (gstr(svc, "vpn-id") != NULL && strcmp(gstr(svc, "vpn-id"),
		    vid) == 0) {
			found = svc;
			for (unsigned k = 0; (n = entry(svc, "vpn-nodes",
			    "vpn-node", k)) != NULL; k++)
				if (gstr(n, "vpn-node-id") != NULL &&
				    strcmp(gstr(n, "vpn-node-id"), edge) == 0)
					host = node_host(n, hbuf,
					    sizeof(hbuf));
		}
	if (found != NULL && host == NULL) {
		char	jail[64];

		if (sdwan_edge_split(edge, hbuf, sizeof(hbuf), jail,
		    sizeof(jail)))
			host = hbuf;
	}
	if (host != NULL)
		snprintf(hbuf, sizeof(hbuf), "%s", host);
	ucl_object_unref(y);
	if (found == NULL) {
		ucl_object_unref(body);
		return (reply_error(req, 404, "unknown", "no such service"));
	}
	if (host == NULL || (sv = server_find(hbuf)) == NULL) {
		ucl_object_unref(body);
		return (reply_error(req, 404, "unknown", "no host of edge %s",
		    edge));
	}
	if (!host_role_ok(req, sv->id, true, false)) {
		ucl_object_unref(body);
		return (reply_error(req, 403, "forbidden", "the host %s is not "
		    "yours to change", sv->name));
	}
	r = xcalloc(1, sizeof(*r));
	r->attach = true;
	r->svc = xstrdup(vid);
	r->edge = xstrdup(edge);
	r->sap = sap != NULL ? xstrdup(sap) : NULL;
	r->access = get(body, "access") != NULL ? ucl_object_copy(get(body,
	    "access")) : NULL;
	ucl_object_unref(body);
	r->h = xcalloc(1, sizeof(*r->h));
	snprintf(r->h[0].sid, sizeof(r->h[0].sid), "%s", sv->id);
	r->h[0].uri = xstrdup(sv->uri);
	r->h[0].peer = sv->peer_name != NULL ? xstrdup(sv->peer_name) : NULL;
	r->h[0].name = xstrdup(sv->name);
	r->nh = 1;
	req->hdlr_extra = r;
	task_create(&r->task, attach_run);
	task_bind_request(&r->task, req);
	task_run(&r->task);
	return (WEB_RETRY);
}

/* on_free: what the request holds, once its task is done. */
void
api_sapnet_free(struct http_request *req)
{
	struct snreq	*r;

	if ((r = req->hdlr_extra) == NULL || !task_finished(&r->task))
		return;
	for (size_t i = 0; i < r->nh; i++) {
		free(r->h[i].uri);
		free(r->h[i].peer);
		free(r->h[i].name);
	}
	free(r->h);
	r->h = NULL;
	r->nh = 0;
	if (r->top != NULL)
		ucl_object_unref(r->top);
	r->top = NULL;
	free(r->svc);
	free(r->edge);
	free(r->sap);
	r->svc = r->edge = r->sap = NULL;
	if (r->access != NULL)
		ucl_object_unref(r->access);
	r->access = NULL;
}
