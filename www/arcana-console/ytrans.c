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
 *
 * And the pages' /sysctl and /kernel from arcana-sysctl and
 * arcana-kernel, their jails, packages and services from their modules,
 * their shapes kept; a change of a host's configuration committed
 * confirmed (the end of this file).
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
#include <cbl_data.h>
#include <cbl_schema.h>
#include <cbl_data.h>
#include <ucl.h>

#include <arcana.h>

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
ytrans_get_tree(cbl_conn *conn, const struct cbl_ynode *const *tops,
    size_t ntop, int ds, cbl_dtree **tp, char *err, size_t errlen,
    uint64_t *errsid)
{

	return (ytrans_get_tree_origin(conn, tops, ntop, ds, false, tp, err,
	    errlen, errsid));
}

int
ytrans_get_tree_origin(cbl_conn *conn, const struct cbl_ynode *const *tops,
    size_t ntop, int ds, bool origin, cbl_dtree **tp, char *err,
    size_t errlen, uint64_t *errsid)
{
	uint64_t	 sids[32];
	cbl_msg		*req, *rep = NULL;
	cbl_dtree	*t;
	const void	*p;
	size_t		 len;
	int		 error;

	*tp = NULL;
	err[0] = '\0';
	*errsid = 0;
	if (ntop > nitems(sids))
		return (E2BIG);
	for (size_t i = 0; i < ntop; i++)
		sids[i] = tops[i]->sid;
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_GET, 0, &req)) != 0 ||
	    (error = cbl_msg_put_yget_opts(req, sids, ntop, NULL,
	    CBL_YWD_EXPLICIT, origin)) != 0 ||
	    (ds >= 0 && (error = cbl_msg_set_datastore(req,
	    (enum cbl_yds_name)ds)) != 0)) {
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = cbl_request(conn, req, &rep, -1)) != 0) {
		snprintf(err, errlen, "%s", rep != NULL &&
		    cbl_msg_err_str(rep) != NULL ? cbl_msg_err_str(rep) :
		    strerror(error));
		if (rep != NULL)
			*errsid = cbl_msg_err_sid(rep);
		cbl_msg_free(rep);
		return (error);
	}
	if ((t = cbl_dtree_new(&ymodel_schema)) == NULL) {
		cbl_msg_free(rep);
		return (ENOMEM);
	}
	/* Each node the reply has; one not there is none.  Every one, as
	 * the reply has them, with their annotations. */
	if (ntop == 0)
		error = cbl_msg_ydtree(rep, t, 0, err, errlen);
	for (size_t i = 0; error == 0 && i < ntop; i++)
		if (cbl_msg_sid_raw(rep, sids[i], &p, &len) == 0)
			error = cbl_dnode_decode(cbl_dtree_root(t), tops[i], p,
			    len, 0, err, errlen, NULL);
	cbl_msg_free(rep);
	if (error != 0) {
		cbl_dtree_free(t);
		return (error);
	}
	*tp = t;
	return (0);
}

int
ytrans_get_ds(cbl_conn *conn, const uint64_t *sids, size_t ns,
    const char *xpath, int ds, ucl_object_t **out, char *err, size_t errlen,
    uint64_t *errsid)
{

	return (ytrans_get_origin(conn, sids, ns, xpath, ds, false, out, err,
	    errlen, errsid));
}

int
ytrans_get_origin(cbl_conn *conn, const uint64_t *sids, size_t ns,
    const char *xpath, int ds, bool origin, ucl_object_t **out, char *err,
    size_t errlen, uint64_t *errsid)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n;
	struct cbl_ybuf			 b = { NULL, 0, 0 };
	struct ucl_parser		*p;
	cbl_msg				*req, *rep = NULL;
	cbl_yarena			*a;
	cbl_dtree			*t;
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
	    CBL_YCMD_GET, 0, &req)) != 0 ||
	    (error = cbl_msg_put_yget_opts(req, sids, ns, xpath,
	    CBL_YWD_EXPLICIT, origin)) != 0 ||
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
	/* Annotated: as an instance tree, which has them. */
	if (origin) {
		if ((t = cbl_dtree_new(&ymodel_schema)) == NULL)
			error = ENOMEM;
		else if ((error = cbl_msg_ydtree(rep, t, 0, err, errlen)) ==
		    0)
			error = cbl_dtree_json(t, &b);
		cbl_dtree_free(t);
		cbl_msg_free(rep);
		if (error != 0) {
			cbl_ybuf_free(&b);
			return (error);
		}
		json = strndup(b.p != NULL ? (const char *)b.p : "{}",
		    b.p != NULL ? b.len : 2);
		cbl_ybuf_free(&b);
		if (json == NULL)
			return (ENOMEM);
		goto parse;
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
parse:
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

/*
 * arcana-sysctl and arcana-kernel (PLAN-SDN-YANG 3.1.6), as the pages'
 * /sysctl and /kernel have them: the kernel's values by the module's
 * read action, a part at a time; what sysctl.conf sets from running;
 * the modules and memory by a GET.
 */

/* The child of n named; NULL where there is none. */
static const struct cbl_ynode *
child_of(const struct cbl_ynode *n, const char *name)
{

	for (uint32_t i = 0; n != NULL && i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	return (NULL);
}

/* A request of family 1 answered, rep the answer; err says why not. */
static int
ask(cbl_conn *conn, cbl_msg *req, cbl_msg **rep, char *err, size_t errlen)
{
	int	error;

	*rep = NULL;
	if ((error = cbl_request(conn, req, rep, -1)) != 0) {
		snprintf(err, errlen, "%s", *rep != NULL &&
		    cbl_msg_err_str(*rep) != NULL ? cbl_msg_err_str(*rep) :
		    strerror(error));
		cbl_msg_free(*rep);
		*rep = NULL;
	}
	return (error);
}

/* Top-level node n of datastore ds, decoded into its module's data. */
static int
yget_into(cbl_conn *conn, const struct cbl_ynode *n, int ds, void *data,
    cbl_yarena *a, char *err, size_t errlen)
{
	cbl_msg	*req, *rep;
	int	 error;

	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_GET, 0, &req)) != 0 || (error = cbl_msg_put_yget(req,
	    &n->sid, 1)) != 0 || (ds >= 0 && (error = cbl_msg_set_datastore(req,
	    (enum cbl_yds_name)ds)) != 0)) {
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = ask(conn, req, &rep, err, errlen)) != 0)
		return (error);
	error = cbl_msg_ydecode_member(rep, n, data, a, 0, err, errlen);
	cbl_msg_free(rep);
	return (error == ENOENT ? 0 : error);
}

/*
 * Action act of node n, the list entry of keys vals (nvals of them) or
 * a container's, in its input (NULL: none given), out its output.
 */
static int
yaction_at(cbl_conn *conn, const struct cbl_ynode *n, const void *const *vals,
    size_t nvals, const struct cbl_ynode *act, const void *in, void *out,
    cbl_yarena *a, char *err, size_t errlen)
{
	const struct cbl_ynode	*inode, *onode;
	struct cbl_ybuf		 t = { NULL, 0, 0 };
	cbl_msg			*req, *rep;
	int			 error;

	if ((inode = child_of(act, "input")) == NULL || (onode = child_of(act,
	    "output")) == NULL) {
		snprintf(err, errlen, "%s: not in the tables", act->name);
		return (ENOENT);
	}
	if (in == NULL && (in = cbl_yarena_alloc(a, inode->size)) == NULL)
		return (ENOMEM);
	if ((error = cbl_yiid_write(n, (const void **)(uintptr_t)vals, nvals,
	    &t)) != 0 ||
	    (error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_RPC, 0, &req)) != 0) {
		cbl_ybuf_free(&t);
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = cbl_msg_put_ynode(req, inode, in)) != 0 ||
	    (error = cbl_msg_put_yaction(req, t.p, t.len)) != 0) {
		cbl_msg_free(req);
		cbl_ybuf_free(&t);
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	cbl_ybuf_free(&t);
	if ((error = ask(conn, req, &rep, err, errlen)) != 0)
		return (error);
	error = out != NULL ? cbl_msg_ydecode(rep, onode, out, a, 0, err,
	    errlen) : 0;
	cbl_msg_free(rep);
	return (error == ENOENT ? 0 : error);
}

/* Action act of container n (no keys), in its input, out its output. */
static int
yaction(cbl_conn *conn, const struct cbl_ynode *n,
    const struct cbl_ynode *act, const void *in, void *out, cbl_yarena *a,
    char *err, size_t errlen)
{

	return (yaction_at(conn, n, NULL, 0, act, in, out, a, err, errlen));
}

/* A value as the sysctl page's row: name, value, type, rw, tun, descr. */
static ucl_object_t *
sysctl_row(const char *name, const char *value, const char *type,
    bool has_rw, bool rw, bool has_tun, bool tun, const char *descr)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "name", ucl_object_fromstring(name != NULL ? name : ""));
	put(o, "value", ucl_object_fromstring(value != NULL ? value : ""));
	if (type != NULL)
		put(o, "type", ucl_object_fromstring(type));
	if (has_rw)
		put(o, "rw", ucl_object_frombool(rw));
	if (has_tun && tun)
		put(o, "tun", ucl_object_frombool(true));
	if (descr != NULL)
		put(o, "descr", ucl_object_fromstring(descr));
	return (o);
}

int
ytrans_sysctl_part(cbl_conn *conn, const char *prefix, const char *jail,
    const char *after, uint16_t count, ucl_object_t **rows, char **next,
    uint64_t *total, char *err, size_t errlen)
{
	const struct cbl_ymodule		*m;
	const struct cbl_ynode			*n, *act;
	struct arcana_sysctl_sysctl_read_input	 in;
	struct arcana_sysctl_sysctl_read_output	 out;
	cbl_yarena				*a;
	int					 error;

	*rows = NULL;
	*next = NULL;
	*total = 0;
	err[0] = '\0';
	if ((n = top_of("arcana-sysctl", "sysctl", &m)) == NULL ||
	    (act = child_of(n, "read")) == NULL) {
		snprintf(err, errlen, "arcana-sysctl is not in the tables");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&in, 0, sizeof(in));
	in.prefix = prefix != NULL && prefix[0] != '\0' ? prefix : NULL;
	in.jail = jail != NULL && jail[0] != '\0' ? jail : NULL;
	in.after = after != NULL && after[0] != '\0' ? after : NULL;
	in.has_count = count > 0;
	in.count = count;
	memset(&out, 0, sizeof(out));
	if ((error = yaction(conn, n, act, &in, &out, a, err, errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	*rows = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < out.value.n; i++) {
		const struct arcana_sysctl_sysctl_read_output_value *v =
		    &out.value.v[i];

		ucl_array_append(*rows, sysctl_row(v->name, v->value, v->type,
		    v->has_writable, v->writable, v->has_tunable, v->tunable,
		    v->description));
	}
	if (out.next != NULL)
		*next = strdup(out.next);
	*total = out.has_total ? out.total : out.value.n;
	cbl_yarena_free(a);
	return (0);
}

int
ytrans_sysctl(cbl_conn *conn, const char *prefix, const char *jail,
    ucl_object_t **data, uint64_t *total, bool *truncated, char *err,
    size_t errlen)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n;
	struct arcana_sysctl		 s;
	ucl_object_t			*rows, *kept;
	cbl_yarena			*a;
	char				*next;
	int				 error;

	*data = NULL;
	*truncated = false;
	if ((error = ytrans_sysctl_part(conn, prefix, jail, NULL, 0, &rows,
	    &next, total, err, errlen)) != 0)
		return (error);
	*truncated = next != NULL;
	free(next);
	/* What sysctl.conf sets at boot: running's. */
	kept = ucl_object_typed_new(UCL_ARRAY);
	if ((jail == NULL || jail[0] == '\0') && (n = top_of("arcana-sysctl",
	    "sysctl", &m)) != NULL && (a = cbl_yarena_new()) != NULL) {
		memset(&s, 0, sizeof(s));
		if ((error = yget_into(conn, n, CBL_YDS_RUNNING, &s, a, err,
		    errlen)) != 0) {
			cbl_yarena_free(a);
			ucl_object_unref(kept);
			ucl_object_unref(rows);
			return (error);
		}
		for (size_t i = 0; s.sysctl != NULL && i < s.sysctl->kept.n;
		    i++) {
			ucl_object_t *k = ucl_object_typed_new(UCL_OBJECT);

			put(k, "name", ucl_object_fromstring(
			    s.sysctl->kept.v[i].name));
			put(k, "value", ucl_object_fromstring(
			    s.sysctl->kept.v[i].value));
			ucl_array_append(kept, k);
		}
		cbl_yarena_free(a);
	}
	*data = ucl_object_typed_new(UCL_OBJECT);
	put(*data, "values", rows);
	put(*data, "kept", kept);
	return (0);
}

static ucl_object_t *
strings(size_t n, const char *const *v)
{
	ucl_object_t	*arr;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < n; i++)
		ucl_array_append(arr, ucl_object_fromstring(v[i]));
	return (arr);
}

static void
put_u64(ucl_object_t *o, const char *key, bool has, uint64_t v)
{

	if (has)
		put(o, key, ucl_object_fromint((int64_t)v));
}

int
ytrans_kernel(cbl_conn *conn, ucl_object_t **data, char *err, size_t errlen)
{
	const struct cbl_ymodule		*m;
	const struct cbl_ynode			*n;
	const struct arcana_kernel_kernel	*k;
	struct arcana_kernel			 d;
	ucl_object_t				*files, *o, *mem, *arr;
	cbl_yarena				*a;
	int					 error;

	*data = NULL;
	err[0] = '\0';
	if ((n = top_of("arcana-kernel", "kernel", &m)) == NULL) {
		snprintf(err, errlen, "arcana-kernel is not in the tables");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&d, 0, sizeof(d));
	if ((error = yget_into(conn, n, -1, &d, a, err, errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	if ((k = d.kernel) == NULL) {
		cbl_yarena_free(a);
		snprintf(err, errlen, "the agent serves no kernel");
		return (ENOENT);
	}
	*data = ucl_object_typed_new(UCL_OBJECT);
	files = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < k->file.n; i++) {
		const struct arcana_kernel_kernel_file *f = &k->file.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "id", ucl_object_fromint(f->id));
		if (f->name != NULL)
			put(o, "name", ucl_object_fromstring(f->name));
		if (f->path != NULL)
			put(o, "path", ucl_object_fromstring(f->path));
		put_u64(o, "refs", f->has_refs, f->refs);
		put_u64(o, "size", f->has_size, f->size);
		if (f->address != NULL)
			put(o, "address", ucl_object_fromstring(f->address));
		put(o, "modules", strings(f->module.n, f->module.v));
		ucl_array_append(files, o);
	}
	put(*data, "files", files);
	put(*data, "available", strings(k->available.n, k->available.v));
	put(*data, "kept", strings(k->kept.n, k->kept.v));
	if (k->memory != NULL) {
		const struct arcana_kernel_kernel_memory *km = k->memory;

		mem = ucl_object_typed_new(UCL_OBJECT);
		put_u64(mem, "files", km->has_files, km->files);
		put_u64(mem, "kmem_size", km->has_kmem_size, km->kmem_size);
		put_u64(mem, "kmem_map_size", km->has_kmem_map_size,
		    km->kmem_map_size);
		put_u64(mem, "kmem_map_free", km->has_kmem_map_free,
		    km->kmem_map_free);
		put_u64(mem, "malloc_total", km->has_malloc_total,
		    km->malloc_total);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < km->malloc.n; i++) {
			const struct arcana_kernel_kernel_memory_malloc *t =
			    &km->malloc.v[i];

			o = ucl_object_typed_new(UCL_OBJECT);
			if (t->name != NULL)
				put(o, "name", ucl_object_fromstring(t->name));
			put_u64(o, "bytes", t->has_bytes, t->bytes);
			put_u64(o, "count", t->has_count, t->count);
			put_u64(o, "requests", t->has_requests, t->requests);
			ucl_array_append(arr, o);
		}
		put(mem, "malloc", arr);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < km->zone.n; i++) {
			const struct arcana_kernel_kernel_memory_zone *z =
			    &km->zone.v[i];

			o = ucl_object_typed_new(UCL_OBJECT);
			if (z->name != NULL)
				put(o, "name", ucl_object_fromstring(z->name));
			put_u64(o, "bytes", z->has_bytes, z->bytes);
			put_u64(o, "count", z->has_count, z->count);
			put_u64(o, "free", z->has_free, z->free);
			put_u64(o, "size", z->has_size, z->size);
			put_u64(o, "requests", z->has_requests, z->requests);
			ucl_array_append(arr, o);
		}
		put(mem, "zones", arr);
		put(*data, "memory", mem);
	}
	cbl_yarena_free(a);
	return (0);
}

static const char *const jail_states[] = {
	[ARCANA_JAILS_JAILS_JAIL_STATE_RUNNING] = "running",
	[ARCANA_JAILS_JAILS_JAIL_STATE_STOPPED] = "stopped",
	[ARCANA_JAILS_JAILS_JAIL_STATE_DYING] = "dying",
	[ARCANA_JAILS_JAILS_JAIL_STATE_ABSENT] = "absent",
};

static void
put_text(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		put(o, key, ucl_object_fromstring(v));
}

/* A jail as the page has it (hosts.c's jail_object()'s keys). */
static ucl_object_t *
jail_row(const struct arcana_jails_jails_jail *j)
{
	ucl_object_t	*o, *ps, *p;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_text(o, "name", j->name);
	put_text(o, "state", j->has_state && (size_t)j->state <
	    nitems(jail_states) ? jail_states[j->state] : "unknown");
	put(o, "jid", j->has_jid ? ucl_object_fromint(j->jid) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "configured", ucl_object_frombool(j->configured));
	put_text(o, "scope", j->scope);
	put_text(o, "hostname", j->hostname);
	put_text(o, "path", j->path);
	put(o, "ip4", strings(j->ip4.n, j->ip4.v));
	put(o, "ip6", strings(j->ip6.n, j->ip6.v));
	put(o, "vnet", ucl_object_frombool(j->vnet));
	if (j->plugin.n > 0)
		put(o, "plugins", strings(j->plugin.n, j->plugin.v));
	put_text(o, "osrelease", j->osrelease);
	put(o, "persist", ucl_object_frombool(j->persist));
	/* Started at boot (rc.conf's jail_list): told of a jail defined. */
	if (j->has_boot)
		put(o, "boot", ucl_object_frombool(j->boot));
	if (j->allow.n > 0)
		put(o, "allow", strings(j->allow.n, j->allow.v));
	put_text(o, "interface", j->interface);
	if (j->has_nproc) {
		put(o, "nproc", ucl_object_fromint(j->nproc));
		put(o, "rss_kb", ucl_object_fromint((int64_t)j->rss));
		put(o, "cpu_pct", ucl_object_fromdouble((double)j->cpu /
		    100.0));
		put(o, "securelevel", ucl_object_fromint(j->securelevel));
		put(o, "children", ucl_object_fromint(j->children));
	}
	ps = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < j->param.n; i++) {
		p = ucl_object_typed_new(UCL_OBJECT);
		put_text(p, "key", j->param.v[i].name);
		put(p, "values", strings(j->param.v[i].value.n,
		    j->param.v[i].value.v));
		ucl_array_append(ps, p);
	}
	put(o, "params", ps);
	return (o);
}

/* arcana-jails' jails of the operational state, d's (a's). */
static int
jails_get(cbl_conn *conn, struct arcana_jails *d, cbl_yarena *a, char *err,
    size_t errlen)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n;

	if ((n = top_of("arcana-jails", "jails", &m)) == NULL) {
		snprintf(err, errlen, "arcana-jails is not in the tables");
		return (ENOENT);
	}
	memset(d, 0, sizeof(*d));
	return (yget_into(conn, n, -1, d, a, err, errlen));
}

int
ytrans_jails(cbl_conn *conn, bool config_only, ucl_object_t *top, char *err,
    size_t errlen)
{
	const struct arcana_jails_jails	*js;
	struct arcana_jails		 d;
	ucl_object_t			*rows, *errs, *e;
	cbl_yarena			*a;
	int				 error;

	err[0] = '\0';
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((error = jails_get(conn, &d, a, err, errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	rows = ucl_object_typed_new(UCL_ARRAY);
	errs = ucl_object_typed_new(UCL_ARRAY);
	if ((js = d.jails) != NULL) {
		for (size_t i = 0; i < js->jail.n; i++)
			if (!config_only || js->jail.v[i].configured)
				ucl_array_append(rows, jail_row(&js->jail.v[i]));
		for (size_t i = 0; i < js->conf_error.n; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_text(e, "scope", js->conf_error.v[i].scope);
			put_text(e, "message", js->conf_error.v[i].message);
			ucl_array_append(errs, e);
		}
	}
	put(top, "jails", rows);
	put(top, "scopes", js != NULL ? strings(js->scope.n, js->scope.v) :
	    ucl_object_typed_new(UCL_ARRAY));
	put(top, "conf_errors", errs);
	cbl_yarena_free(a);
	return (0);
}

ucl_object_t *
ytrans_jail(cbl_conn *conn, const char *name)
{
	struct arcana_jails	 d;
	ucl_object_t		*o = NULL;
	cbl_yarena		*a;
	char			 err[256];

	if ((a = cbl_yarena_new()) == NULL)
		return (NULL);
	if (jails_get(conn, &d, a, err, sizeof(err)) == 0 && d.jails != NULL)
		for (size_t i = 0; o == NULL && i < d.jails->jail.n; i++)
			if (strcmp(d.jails->jail.v[i].name, name) == 0)
				o = jail_row(&d.jails->jail.v[i]);
	cbl_yarena_free(a);
	return (o);
}

int
ytrans_jail_action(cbl_conn *conn, const char *name, const char *verb,
    char *err, size_t errlen)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n, *act;
	const void			*vals[1];
	cbl_yarena			*a;
	int				 error;

	err[0] = '\0';
	if ((n = top_of("arcana-jails", "jails", &m)) == NULL ||
	    (n = child_of(n, "jail")) == NULL || (act = child_of(n, verb)) ==
	    NULL) {
		snprintf(err, errlen, "arcana-jails has no %s", verb);
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	vals[0] = &name;
	error = yaction_at(conn, n, vals, 1, act, NULL, NULL, a, err, errlen);
	cbl_yarena_free(a);
	return (error);
}

typedef struct arcana_packages_package ypkg;

/* Packages as the page has them; with all, what pkg query says too. */
static ucl_object_t *
pkg_rows(const ypkg *v, size_t n, bool all)
{
	ucl_object_t	*rows, *e;

	rows = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < n; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put_text(e, "name", v[i].name);
		put_text(e, "installed", v[i].installed);
		put_text(e, "available", v[i].available);
		if (all) {
			put_text(e, "origin", v[i].origin);
			put_text(e, "comment", v[i].comment);
			if (v[i].has_automatic)
				put(e, "automatic", ucl_object_frombool(
				    v[i].automatic));
			if (v[i].has_size)
				put(e, "size", ucl_object_fromint((int64_t)
				    v[i].size));
		}
		ucl_array_append(rows, e);
	}
	return (rows);
}

/* arcana-packages' node: the host's, or jail's (vals[0] its key). */
static const struct cbl_ynode *
pkg_node(const char **jail, const void **vals, size_t *nvals)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n;

	*nvals = 0;
	if (*jail == NULL || (*jail)[0] == '\0')
		return (top_of("arcana-packages", "packages", &m));
	if ((n = top_of("arcana-jails", "jails", &m)) == NULL || (n =
	    child_of(n, "jail")) == NULL)
		return (NULL);
	vals[0] = jail;
	*nvals = 1;
	return (child_of(n, "packages"));
}

int
ytrans_packages(cbl_conn *conn, const char *jail, bool installed, bool refresh,
    uint8_t ip, bool anyos, ucl_object_t *top, char *err, size_t errlen)
{
	struct arcana_packages_packages_refresh_input	 ri;
	struct arcana_packages_packages_refresh_output	 ro;
	struct arcana_packages_packages_read_output	 io;
	const struct cbl_ynode				*n, *act;
	const void					*vals[1];
	cbl_yarena					*a;
	size_t						 nvals;
	int						 error;

	err[0] = '\0';
	if ((n = pkg_node(&jail, vals, &nvals)) == NULL || (act = child_of(n,
	    installed ? "read" : "refresh")) == NULL) {
		snprintf(err, errlen, "arcana-packages is not in the tables");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&ri, 0, sizeof(ri));
	memset(&ro, 0, sizeof(ro));
	memset(&io, 0, sizeof(io));
	if (installed)
		error = yaction_at(conn, n, vals, nvals, act, NULL, &io, a,
		    err, errlen);
	else {
		ri.has_update = ri.update = refresh;
		/* ip-version's values are pkg's: 0, 4, 6. */
		ri.has_ip_version = ip != 0;
		ri.ip_version = ip;
		ri.has_ignore_osversion = ri.ignore_osversion = anyos;
		error = yaction_at(conn, n, vals, nvals, act, &ri, &ro, a, err,
		    errlen);
	}
	if (error == 0 && installed) {
		put(top, "packages", pkg_rows(io.package.v, io.package.n, true));
		put(top, "repos", strings(io.repository.n, io.repository.v));
		if (io.has_pkgbase)
			put(top, "pkgbase", ucl_object_frombool(io.pkgbase));
	} else if (error == 0) {
		put(top, "packages", pkg_rows(ro.package.v, ro.package.n, true));
		put(top, "repos", strings(ro.repository.n, ro.repository.v));
		if (ro.has_pkgbase)
			put(top, "pkgbase", ucl_object_frombool(ro.pkgbase));
	} else {
		put(top, "packages", ucl_object_typed_new(UCL_ARRAY));
		put(top, "repos", ucl_object_typed_new(UCL_ARRAY));
	}
	cbl_yarena_free(a);
	return (error);
}

int
ytrans_pkg_upgrade(cbl_conn *conn, const char *jail,
    const char *const *names, size_t nnames, bool dry_run, bool anyos,
    uint8_t ip, const char *repo, ucl_object_t *top, char *err, size_t errlen)
{
	struct arcana_packages_packages_upgrade_input	 ui;
	struct arcana_packages_packages_upgrade_output	 uo;
	const struct cbl_ynode				*n, *act;
	const void					*vals[1];
	cbl_yarena					*a;
	size_t						 nvals;
	int						 error;

	err[0] = '\0';
	memset(&ui, 0, sizeof(ui));
	/* In every running jail: the host's, every-jail. */
	if (jail != NULL && strcmp(jail, "*") == 0) {
		jail = NULL;
		ui.has_every_jail = ui.every_jail = true;
	}
	if ((n = pkg_node(&jail, vals, &nvals)) == NULL || (act = child_of(n,
	    "upgrade")) == NULL) {
		snprintf(err, errlen, "arcana-packages is not in the tables");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	ui.name.v = names;
	ui.name.n = nnames;
	ui.has_dry_run = ui.dry_run = dry_run;
	ui.has_ignore_osversion = ui.ignore_osversion = anyos;
	ui.has_ip_version = ip != 0;
	ui.ip_version = ip;
	ui.repository = repo != NULL && repo[0] != '\0' ? repo : NULL;
	memset(&uo, 0, sizeof(uo));
	error = yaction_at(conn, n, vals, nvals, act, &ui, &uo, a, err, errlen);
	put(top, "upgraded", error == 0 && uo.has_upgraded ?
	    ucl_object_fromint(uo.upgraded) : ucl_object_typed_new(UCL_NULL));
	put(top, "packages", error == 0 ? pkg_rows(uo.package.v, uo.package.n,
	    false) : ucl_object_typed_new(UCL_ARRAY));
	cbl_yarena_free(a);
	return (error);
}

/*
 * A change of the configuration (PLAN-SDN-YANG 3.1.2): top-level node
 * n's data put in the candidate, then committed confirmed (RFC 6241
 * section 8.4) with a token of the console's and confirmed at once,
 * the warnings acc (nacc of them) accepted.  The data is running's
 * with the change, every entry of it: the commit's undo has them all.
 * Refused, the candidate as running is; err the agent's words and tag
 * its error-app-tag, "" none.
 */
#define	CONFIRM_TIMEOUT	120	/* s the host waits for the confirm */

static int
ask_tag(cbl_conn *conn, cbl_msg *req, const char *const *acc, size_t nacc,
    char *err, size_t errlen, char *tag, size_t taglen)
{
	cbl_msg	*rep = NULL;
	int	 error;

	if (nacc > 0 && (error = cbl_msg_set_accept(req, acc, nacc)) != 0) {
		cbl_msg_free(req);
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = cbl_request(conn, req, &rep, -1)) != 0) {
		snprintf(err, errlen, "%s", rep != NULL &&
		    cbl_msg_err_str(rep) != NULL ? cbl_msg_err_str(rep) :
		    strerror(error));
		if (rep != NULL && cbl_msg_err_apptag(rep) != NULL)
			snprintf(tag, taglen, "%s", cbl_msg_err_apptag(rep));
	}
	cbl_msg_free(rep);
	return (error);
}

/* ietf-netconf's rpc name, its input in. */
static int
netconf_rpc(cbl_conn *conn, const char *name, const void *in,
    const char *const *acc, size_t nacc, char *err, size_t errlen, char *tag,
    size_t taglen)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*rpc, *inode;
	cbl_msg				*req = NULL;
	int				 error;

	if ((rpc = top_of("ietf-netconf", name, &m)) == NULL ||
	    (inode = child_of(rpc, "input")) == NULL) {
		snprintf(err, errlen, "%s: not in the tables", name);
		return (ENOENT);
	}
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_RPC, 0, &req)) != 0 || (error = cbl_msg_put_ynode(req,
	    inode, in)) != 0) {
		cbl_msg_free(req);
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	return (ask_tag(conn, req, acc, nacc, err, errlen, tag, taglen));
}

static int
ycommit(cbl_conn *conn, const struct cbl_ynode *n, const void *d,
    const char *const *acc, size_t nacc, char *err, size_t errlen, char *tag,
    size_t taglen)
{
	struct ietf_netconf_commit_input		 cin;
	struct ietf_netconf_discard_changes_input	 din;
	cbl_msg						*req;
	char						 token[33], why[16], none[8];
	int						 error;

	err[0] = tag[0] = '\0';
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_EDIT, 0, &req)) != 0) {
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = cbl_msg_set_datastore(req, CBL_YDS_CANDIDATE)) != 0 ||
	    (error = cbl_msg_put_ymember(req, n, d)) != 0) {
		cbl_msg_free(req);
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = ask_tag(conn, req, acc, nacc, err, errlen, tag,
	    taglen)) != 0)
		return (error);
	snprintf(token, sizeof(token), "%08x%08x%08x%08x", arc4random(),
	    arc4random(), arc4random(), arc4random());
	memset(&cin, 0, sizeof(cin));
	cin.confirmed = true;
	cin.has_confirm_timeout = true;
	cin.confirm_timeout = CONFIRM_TIMEOUT;
	cin.persist = token;
	if ((error = netconf_rpc(conn, "commit", &cin, acc, nacc, err, errlen,
	    tag, taglen)) != 0) {
		memset(&din, 0, sizeof(din));
		(void)netconf_rpc(conn, "discard-changes", &din, NULL, 0, why,
		    sizeof(why), none, sizeof(none));
		return (error);
	}
	/* Here still: the change stays. */
	memset(&cin, 0, sizeof(cin));
	cin.persist_id = token;
	return (netconf_rpc(conn, "commit", &cin, NULL, 0, err, errlen, none,
	    sizeof(none)));
}

/*
 * arcana-services, as the Services page and the app have it: the
 * services, service-action and service-config operations' replies, a
 * service as hosts.c's service_object() made it.
 */
typedef struct arcana_services_services_service ysvc;

static ucl_object_t *
service_row(const char *name, const char *path, const char *rcvar,
    bool has_enabled, bool enabled, bool has_running, bool running,
    bool has_pid, uint32_t pid, const char *status)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "name", ucl_object_fromstring(name));
	put(o, "path", path != NULL ? ucl_object_fromstring(path) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "rcvar", rcvar != NULL ? ucl_object_fromstring(rcvar) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "enabled", has_enabled ? ucl_object_frombool(enabled) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "running", has_running ? ucl_object_frombool(running) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "pid", has_pid ? ucl_object_fromint(pid) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "status", status != NULL ? ucl_object_fromstring(status) :
	    ucl_object_typed_new(UCL_NULL));
	return (o);
}

/* arcana-services' services of datastore ds (-1: the state), d's. */
static int
services_get(cbl_conn *conn, int ds, struct arcana_services *d,
    cbl_yarena *a, char *err, size_t errlen)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n;

	if ((n = top_of("arcana-services", "services", &m)) == NULL) {
		snprintf(err, errlen, "arcana-services is not in the tables");
		return (ENOENT);
	}
	memset(d, 0, sizeof(*d));
	return (yget_into(conn, n, ds, d, a, err, errlen));
}

int
ytrans_services(cbl_conn *conn, ucl_object_t *top, char *err, size_t errlen)
{
	struct arcana_services	 d;
	ucl_object_t		*rows;
	cbl_yarena		*a;
	int			 error;

	err[0] = '\0';
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	rows = ucl_object_typed_new(UCL_ARRAY);
	if ((error = services_get(conn, -1, &d, a, err, errlen)) == 0 &&
	    d.services != NULL)
		for (size_t i = 0; i < d.services->service.n; i++) {
			const ysvc *y = &d.services->service.v[i];

			ucl_array_append(rows, service_row(y->name, y->path,
			    y->rcvar, y->has_enabled, y->enabled,
			    y->has_running, y->running, y->has_pid, y->pid,
			    y->status));
		}
	put(top, "services", rows);
	cbl_yarena_free(a);
	return (error);
}

int
ytrans_service(cbl_conn *conn, const char *name, bool config,
    ucl_object_t *top, char *err, size_t errlen)
{
	struct arcana_services_services_service_read_output	 o;
	const struct cbl_ymodule				*m;
	const struct cbl_ynode					*n, *act;
	struct arcana_services					 d;
	ucl_object_t						*vars, *cmds;
	const void						*vals[1];
	cbl_yarena						*a;
	int							 error;

	err[0] = '\0';
	if ((n = top_of("arcana-services", "services", &m)) == NULL ||
	    (n = child_of(n, "service")) == NULL || (act = child_of(n,
	    "read")) == NULL) {
		snprintf(err, errlen, "arcana-services is not in the tables");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	vals[0] = &name;
	memset(&o, 0, sizeof(o));
	if ((error = yaction_at(conn, n, vals, 1, act, NULL, &o, a, err,
	    errlen)) == 0)
		put(top, "service", service_row(name, o.path, o.rcvar,
		    o.has_enabled, o.enabled, o.has_running, o.running,
		    o.has_pid, o.pid, o.status));
	if (error == 0 && config) {
		/* Its variables as running has them. */
		vars = ucl_object_typed_new(UCL_OBJECT);
		if ((error = services_get(conn, CBL_YDS_RUNNING, &d, a, err,
		    errlen)) == 0 && d.services != NULL)
			for (size_t i = 0; i < d.services->service.n; i++) {
				const ysvc *y = &d.services->service.v[i];

				if (strcmp(y->name, name) != 0)
					continue;
				for (size_t k = 0; k < y->variable.n; k++)
					put(vars, y->variable.v[k].name,
					    ucl_object_fromstring(
					    y->variable.v[k].value != NULL ?
					    y->variable.v[k].value : ""));
			}
		put(top, "variables", vars);
		put(top, "description", o.description != NULL ?
		    ucl_object_fromstring(o.description) :
		    ucl_object_typed_new(UCL_NULL));
		cmds = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < o.command.n; i++)
			ucl_array_append(cmds, ucl_object_fromstring(
			    o.command.v[i]));
		put(top, "commands", cmds);
	}
	cbl_yarena_free(a);
	return (error);
}

int
ytrans_service_action(cbl_conn *conn, const char *name, const char *verb,
    char *err, size_t errlen)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n, *act;
	const void			*vals[1];
	cbl_yarena			*a;
	int				 error;

	err[0] = '\0';
	if ((n = top_of("arcana-services", "services", &m)) == NULL ||
	    (n = child_of(n, "service")) == NULL || (act = child_of(n,
	    verb)) == NULL) {
		snprintf(err, errlen, "arcana-services has no %s", verb);
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	vals[0] = &name;
	error = yaction_at(conn, n, vals, 1, act, NULL, NULL, a, err, errlen);
	cbl_yarena_free(a);
	return (error);
}

int
ytrans_service_set(cbl_conn *conn, const char *name, int enable,
    const struct arc_variable *v, size_t nv, const char *const *acc,
    size_t nacc, char *err, size_t errlen, char *tag, size_t taglen)
{
	const struct cbl_ymodule			*m;
	const struct cbl_ynode				*n;
	struct arcana_services_services_service_variable *vv;
	struct arcana_services				 d;
	ysvc						*y = NULL;
	cbl_yarena					*a;
	size_t						 k, nn;
	int						 error;

	err[0] = tag[0] = '\0';
	if ((n = top_of("arcana-services", "services", &m)) == NULL) {
		snprintf(err, errlen, "arcana-services is not in the tables");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((error = services_get(conn, CBL_YDS_RUNNING, &d, a, err,
	    errlen)) != 0)
		goto out;
	for (k = 0; d.services != NULL && k < d.services->service.n; k++)
		if (strcmp(d.services->service.v[k].name, name) == 0)
			y = (ysvc *)(uintptr_t)&d.services->service.v[k];
	if (y == NULL) {
		snprintf(err, errlen, "no rc.d script '%s'", name);
		error = ENOENT;
		goto out;
	}
	if (enable != 0) {
		y->has_enabled = true;
		y->enabled = enable > 0;
	}
	if (nv > 0) {
		if ((vv = cbl_yarena_alloc(a, (y->variable.n + nv) *
		    sizeof(*vv))) == NULL) {
			error = ENOMEM;
			goto out;
		}
		nn = 0;
		for (k = 0; k < y->variable.n; k++)
			vv[nn++] = y->variable.v[k];
		for (size_t i = 0; i < nv; i++) {
			for (k = 0; k < nn && strcmp(vv[k].name, v[i].key) != 0;
			    k++)
				;
			if (v[i].remove) {
				if (k < nn)
					vv[k] = vv[--nn];
				continue;
			}
			vv[k].name = v[i].key;
			vv[k].value = v[i].value != NULL ? v[i].value : "";
			if (k == nn)
				nn++;
		}
		y->variable.v = vv;
		y->variable.n = nn;
	}
	error = ycommit(conn, n, &d, acc, nacc, err, errlen, tag, taglen);
out:
	cbl_yarena_free(a);
	return (error);
}

int
ytrans_jail_boot(cbl_conn *conn, const char *name, bool on,
    const char *const *acc, size_t nacc, char *err, size_t errlen, char *tag,
    size_t taglen)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n;
	struct arcana_jails		 d;
	struct arcana_jails_jails_jail	*j = NULL;
	cbl_yarena			*a;
	int				 error;

	err[0] = tag[0] = '\0';
	if ((n = top_of("arcana-jails", "jails", &m)) == NULL) {
		snprintf(err, errlen, "arcana-jails is not in the tables");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&d, 0, sizeof(d));
	if ((error = yget_into(conn, n, CBL_YDS_RUNNING, &d, a, err,
	    errlen)) != 0)
		goto out;
	for (size_t i = 0; d.jails != NULL && i < d.jails->jail.n; i++)
		if (strcmp(d.jails->jail.v[i].name, name) == 0)
			j = (struct arcana_jails_jails_jail *)(uintptr_t)
			    &d.jails->jail.v[i];
	if (j == NULL) {
		snprintf(err, errlen, "jail '%s' is not defined", name);
		error = ENOENT;
		goto out;
	}
	/* As it is already: nothing to commit. */
	if (j->has_boot && j->boot == on)
		goto out;
	j->has_boot = true;
	j->boot = on;
	error = ycommit(conn, n, &d, acc, nacc, err, errlen, tag, taglen);
out:
	cbl_yarena_free(a);
	return (error);
}
