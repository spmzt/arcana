/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Network tab's interfaces from the standard models: a GET of
 * ietf-interfaces' interfaces and of RFC 8529's network instances, by
 * cblink's YANG family (family 1), made into the rows the agent's
 * interfaces table has:
 *
 *	name, description		the interface's
 *	up				enabled (IFF_UP)
 *	link				oper-status, up or down, of one with a
 *					medium; else unknown (oper-status is
 *					IFF_RUNNING's where the driver knows
 *					no link state: a loopback, a tunnel)
 *	mtu				ietf-ip's ipv4 mtu, else ipv6's
 *	ether				phys-address, six octets
 *	fib				the FIB of its bind-ni-name's instance
 *	tunnelfib			arcana-interfaces' tunnel-fib
 *	tunnel {local, remote}		arcana-interfaces' tunnel
 *	ibytes, obytes			in-octets, out-octets
 *	ipackets, opackets		unicast and multicast packets (FreeBSD
 *					counts broadcast with multicast)
 *	ierrors, oerrors		in-errors, out-errors
 *	addresses			ietf-ip's, IPv4's first, each with its
 *					prefix length and a point-to-point
 *					link's peer as its destination; a
 *					link-local one with its zone, the
 *					interface (the model's has none)
 *	time				when read: the console's clock, ms
 *
 * What the models do not carry (CARP, the interface flags) is not
 * here: the other tabs that read the agent's table keep asking it.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "ymodel.h"
#include "ytrans.h"

typedef struct ietf_interfaces_interfaces_interface yif;

/* The top-level node name of module mod, NULL where it is not. */
static const struct cbl_ynode *
top_of(const char *mod, const char *name, const struct cbl_ymodule **mp)
{
	const struct cbl_ymodule	*m;
	uint32_t			 i, k;

	for (i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, mod) != 0)
			continue;
		for (k = 0; k < m->ntop; k++)
			if (strcmp(m->top[k]->name, name) == 0) {
				*mp = m;
				return (m->top[k]);
			}
	}
	return (NULL);
}

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

/* The FIB of the instance named, 0 for none (the host's). */
static int
fib_of(const struct ietf_network_instance *nis, const char *name)
{
	const struct ietf_network_instance_network_instances *ni;
	size_t	i;

	if (name == NULL || (ni = nis->network_instances) == NULL)
		return (0);
	for (i = 0; i < ni->network_instance.n; i++)
		if (strcmp(ni->network_instance.v[i].name, name) == 0)
			return (ni->network_instance.v[i].has_arcni_fib ?
			    ni->network_instance.v[i].arcni_fib : 0);
	return (0);
}

static void
address(ucl_object_t *arr, const char *ifname, const char *family,
    const char *ip, bool has_plen, int plen, const char *peer)
{
	ucl_object_t	*a;
	char		 zoned[INET6_ADDRSTRLEN + IFNAMSIZ + 2];

	a = ucl_object_typed_new(UCL_OBJECT);
	put(a, "family", ucl_object_fromstring(family));
	if (strncasecmp(ip, "fe8", 3) == 0 || strncasecmp(ip, "fe9", 3) == 0 ||
	    strncasecmp(ip, "fea", 3) == 0 || strncasecmp(ip, "feb", 3) == 0) {
		snprintf(zoned, sizeof(zoned), "%s%%%s", ip, ifname);
		ip = zoned;
	}
	put(a, "address", ucl_object_fromstring(ip));
	if (has_plen)
		put(a, "prefixlen", ucl_object_fromint(plen));
	if (peer != NULL)
		put(a, "destination", ucl_object_fromstring(peer));
	ucl_array_append(arr, a);
}

/* One interface's row. */
static ucl_object_t *
row(const yif *e, const struct ietf_network_instance *nis, bool v4, bool v6)
{
	const struct ietf_interfaces_interfaces_interface_statistics *st;
	const struct ietf_interfaces_interfaces_interface_arcif_tunnel *t;
	ucl_object_t	*o, *arr, *tun;
	size_t		 i;
	int		 fib;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "name", ucl_object_fromstring(e->name));
	put(o, "up", ucl_object_frombool(e->has_enabled && e->enabled));
	put(o, "link", ucl_object_fromstring(!e->has_oper_status ||
	    e->arcif_media == NULL ? "unknown" : e->oper_status ==
	    IETF_INTERFACES_INTERFACES_INTERFACE_OPER_STATUS_UP ? "up" :
	    e->oper_status ==
	    IETF_INTERFACES_INTERFACES_INTERFACE_OPER_STATUS_DOWN ? "down" :
	    "unknown"));
	if (e->ip_ipv4 != NULL && e->ip_ipv4->has_mtu)
		put(o, "mtu", ucl_object_fromint(e->ip_ipv4->mtu));
	else if (e->ip_ipv6 != NULL && e->ip_ipv6->has_mtu)
		put(o, "mtu", ucl_object_fromint(e->ip_ipv6->mtu));
	if (e->phys_address != NULL && strlen(e->phys_address) == 17)
		put(o, "ether", ucl_object_fromstring(e->phys_address));
	if (e->description != NULL)
		put(o, "description", ucl_object_fromstring(e->description));
	if ((fib = fib_of(nis, e->ni_bind_ni_name)) != 0)
		put(o, "fib", ucl_object_fromint(fib));
	if (e->has_arcif_tunnel_fib && e->arcif_tunnel_fib != 0)
		put(o, "tunnelfib", ucl_object_fromint(e->arcif_tunnel_fib));
	if ((t = e->arcif_tunnel) != NULL && t->has_local) {
		tun = ucl_object_typed_new(UCL_OBJECT);
		put(tun, "local", ucl_object_fromstring(t->local.which == 0 ?
		    t->local.v.m0 : t->local.v.m1));
		if (t->has_remote)
			put(tun, "remote", ucl_object_fromstring(
			    t->remote.which == 0 ? t->remote.v.m0 :
			    t->remote.v.m1));
		put(o, "tunnel", tun);
	}
	if ((st = e->statistics) != NULL) {
		put(o, "ibytes", ucl_object_fromint((int64_t)st->in_octets));
		put(o, "obytes", ucl_object_fromint((int64_t)st->out_octets));
		put(o, "ipackets", ucl_object_fromint((int64_t)(
		    st->in_unicast_pkts + st->in_multicast_pkts)));
		put(o, "opackets", ucl_object_fromint((int64_t)(
		    st->out_unicast_pkts + st->out_multicast_pkts)));
		put(o, "ierrors", ucl_object_fromint(st->in_errors));
		put(o, "oerrors", ucl_object_fromint(st->out_errors));
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; v4 && e->ip_ipv4 != NULL && i < e->ip_ipv4->address.n; i++)
		address(arr, e->name, "inet", e->ip_ipv4->address.v[i].ip,
		    e->ip_ipv4->address.v[i].has_prefix_length,
		    e->ip_ipv4->address.v[i].prefix_length,
		    e->ip_ipv4->address.v[i].arcif_peer);
	for (i = 0; v6 && e->ip_ipv6 != NULL && i < e->ip_ipv6->address.n; i++)
		address(arr, e->name, "inet6", e->ip_ipv6->address.v[i].ip,
		    e->ip_ipv6->address.v[i].has_prefix_length,
		    e->ip_ipv6->address.v[i].prefix_length,
		    e->ip_ipv6->address.v[i].arcif_peer);
	put(o, "addresses", arr);
	return (o);
}

int
ytrans_interfaces(cbl_conn *conn, bool v4, bool v6, ucl_object_t **out,
    char *err, size_t errlen)
{
	const struct cbl_ymodule	*mi, *mn;
	const struct cbl_ynode		*ni, *nn;
	struct ietf_interfaces		 ifs;
	struct ietf_network_instance	 nis;
	struct timespec			 ts;
	cbl_msg				*req, *rep = NULL;
	cbl_yarena			*a;
	ucl_object_t			*top, *arr;
	uint64_t			 sids[2];
	size_t				 i;
	int				 error;

	*out = NULL;
	err[0] = '\0';
	if ((ni = top_of("ietf-interfaces", "interfaces", &mi)) == NULL ||
	    (nn = top_of("ietf-network-instance", "network-instances",
	    &mn)) == NULL) {
		snprintf(err, errlen, "the models are not in this console");
		return (ENOENT);
	}
	sids[0] = ni->sid;
	sids[1] = nn->sid;
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_GET, 0, &req)) != 0 ||
	    (error = cbl_msg_put_yget(req, sids, nitems(sids))) != 0) {
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = cbl_request(conn, req, &rep, -1)) != 0) {
		snprintf(err, errlen, "%s", rep != NULL &&
		    cbl_msg_err_str(rep) != NULL ? cbl_msg_err_str(rep) :
		    strerror(error));
		cbl_msg_free(rep);
		return (error);
	}
	if ((a = cbl_yarena_new()) == NULL) {
		cbl_msg_free(rep);
		return (ENOMEM);
	}
	memset(&ifs, 0, sizeof(ifs));
	memset(&nis, 0, sizeof(nis));
	if (((error = cbl_msg_ydecode_member(rep, ni, &ifs, a, 0, err,
	    errlen)) != 0 && error != ENOENT) ||
	    ((error = cbl_msg_ydecode_member(rep, nn, &nis, a, 0, err,
	    errlen)) != 0 && error != ENOENT)) {
		cbl_yarena_free(a);
		cbl_msg_free(rep);
		return (error);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; ifs.interfaces != NULL && i < ifs.interfaces->interface.n;
	    i++)
		ucl_array_append(arr, row(&ifs.interfaces->interface.v[i], &nis,
		    v4, v6));
	put(top, "interfaces", arr);
	/* When the counters were read, to make rates of two readings. */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	put(top, "time", ucl_object_fromint((int64_t)ts.tv_sec * 1000 +
	    ts.tv_nsec / 1000000));
	put(top, "source", ucl_object_fromstring("yang"));
	cbl_yarena_free(a);
	cbl_msg_free(rep);
	*out = top;
	return (0);
}

/* A top-level data node by its name, in any module; NULL: none. */
static const struct cbl_ynode *
top_named(const char *name)
{
	const struct cbl_ymodule	*m;
	uint32_t			 i, k;

	for (i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		for (k = 0; k < m->ntop; k++)
			if ((m->top[k]->kind == CBL_YN_CONTAINER ||
			    m->top[k]->kind == CBL_YN_LIST) &&
			    strcmp(m->top[k]->name, name) == 0)
				return (m->top[k]);
	}
	return (NULL);
}

int
ytrans_data(cbl_conn *conn, const char *names, ucl_object_t **out,
    char *err, size_t errlen)
{
	const struct cbl_ynode		*n;
	uint64_t			 sids[16];
	char				 copy[256], *s, *w;
	size_t				 ns = 0;

	*out = NULL;
	err[0] = '\0';
	snprintf(copy, sizeof(copy), "%s", names != NULL ? names : "");
	for (s = copy; (w = strsep(&s, ",")) != NULL;) {
		if (w[0] == '\0')
			continue;
		if ((n = top_named(w)) == NULL) {
			snprintf(err, errlen, "%s is no node the agent serves",
			    w);
			return (ENOENT);
		}
		if (ns == nitems(sids)) {
			snprintf(err, errlen, "%zu nodes at most",
			    nitems(sids));
			return (E2BIG);
		}
		sids[ns++] = n->sid;
	}
	return (ytrans_get(conn, sids, ns, NULL, out, err, errlen, NULL));
}

int
ytrans_get(cbl_conn *conn, const uint64_t *sids, size_t ns,
    const char *xpath, ucl_object_t **out, char *err, size_t errlen,
    uint64_t *errsid)
{

	return (ytrans_get_ds(conn, sids, ns, xpath, -1, out, err, errlen,
	    errsid));
}

int
ytrans_get_ds(cbl_conn *conn, const uint64_t *sids, size_t ns,
    const char *xpath, int ds, ucl_object_t **out, char *err, size_t errlen,
    uint64_t *errsid)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n;
	struct cbl_ybuf			 b = { NULL, 0, 0 };
	struct ucl_parser		*p;
	cbl_msg				*req, *rep = NULL;
	cbl_yarena			*a;
	char				*json;
	uint32_t			 i, k;
	void				*data;
	bool				 first = true;
	int				 error;

	*out = NULL;
	err[0] = '\0';
	if (errsid != NULL)
		*errsid = 0;
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_GET, 0, &req)) != 0 || (xpath != NULL ?
	    (error = cbl_msg_put_yget_xpath(req, sids, ns, xpath)) != 0 :
	    ns > 0 && (error = cbl_msg_put_yget(req, sids, ns)) != 0) ||
	    (ds >= 0 && (error = cbl_msg_set_datastore(req,
	    (enum cbl_yds_name)ds)) != 0)) {
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = cbl_request(conn, req, &rep, -1)) != 0) {
		snprintf(err, errlen, "%s", rep != NULL &&
		    cbl_msg_err_str(rep) != NULL ? cbl_msg_err_str(rep) :
		    strerror(error));
		if (errsid != NULL && rep != NULL)
			*errsid = cbl_msg_err_sid(rep);
		cbl_msg_free(rep);
		return (error);
	}
	if ((a = cbl_yarena_new()) == NULL) {
		cbl_msg_free(rep);
		return (ENOMEM);
	}
	/* Each module's top-level nodes the reply has, as RFC 7951 has
	 * them: one object of all, its members qualified. */
	for (i = 0; error == 0 && i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (m->size == 0 || (data = cbl_yarena_alloc(a, m->size)) ==
		    NULL)
			continue;
		for (k = 0; error == 0 && k < m->ntop; k++) {
			n = m->top[k];
			if (n->kind != CBL_YN_CONTAINER && n->kind != CBL_YN_LIST)
				continue;
			if ((error = cbl_msg_ydecode_member(rep, n, data, a, 0,
			    err, errlen)) == ENOENT)
				error = 0;
		}
		if (error == 0)
			error = cbl_yjson_members(m, data, &b, &first);
	}
	cbl_yarena_free(a);
	cbl_msg_free(rep);
	if (error != 0) {
		cbl_ybuf_free(&b);
		return (error);
	}
	if (asprintf(&json, "{%.*s}", (int)b.len, b.p != NULL ?
	    (const char *)b.p : "") == -1) {
		cbl_ybuf_free(&b);
		return (ENOMEM);
	}
	cbl_ybuf_free(&b);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	if (ucl_parser_add_string(p, json, 0))
		*out = ucl_parser_get_object(p);
	ucl_parser_free(p);
	free(json);
	if (*out == NULL) {
		snprintf(err, errlen, "the agent's JSON did not read back");
		return (EINVAL);
	}
	return (0);
}
