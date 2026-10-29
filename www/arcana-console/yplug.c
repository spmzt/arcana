/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The plugins' programs through their modules (PLAN-SDN-YANG 3.1.8):
 * netgraph(4) by arcana-netgraph's read action, WireGuard by
 * arcana-wireguard's, BIRD by arcana-bird's read, routes and ospf
 * actions, the host's or a vnet jail's, made the JSON the network
 * operation's kind gave (the agent's netgraph.c, wireguard.c, bird.c),
 * so that the pages keep reading what they read.  BIRD's configuration
 * as the bird-config operation had it: a file read from running, put in
 * place by a commit (confirmed at once, or in safe mode left waiting
 * for the page's confirm), checked by the check action.
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include <openssl/evp.h>

#include <arcana.h>

#include "ymodel.h"
#include "yqueue.h"
#include "ytrans.h"
#include "yplug.h"

/* key's value in o, the one it had replaced. */
static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_replace_key(o, v, key, 0, true);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		put(o, key, ucl_object_fromstring(v));
}

/*
 * Action act of module mod's top-level node top, given in (which names
 * the vnet jail, if one), out its output (a's).
 */
static int
plug_call(cbl_conn *conn, const char *mod, const char *top, const char *act,
    const void *in, void *out, cbl_yarena *a, char *err, size_t errlen)
{
	const struct cbl_ynode	*n, *an;

	if ((n = yq_top(mod, top)) == NULL || (an = yq_child(n, act)) ==
	    NULL) {
		snprintf(err, errlen, "%s has no %s", mod, act);
		return (ENOENT);
	}
	return (yq_call(conn, n, NULL, an, in, out, a, err, errlen));
}

/* A jail as an action's input names it: none for the host. */
static const char *
jail_in(const char *jail)
{

	return (jail != NULL && jail[0] != '\0' ? jail : NULL);
}

/* ---- netgraph ---------------------------------------------------- */

static int
netgraph(cbl_conn *conn, const char *jail, ucl_object_t **data, char *err,
    size_t errlen)
{
	struct arcana_netgraph_netgraph_read_input	 in;
	struct arcana_netgraph_netgraph_read_output	 r;
	ucl_object_t					*nodes, *o, *hooks, *h;
	cbl_yarena					*a;
	int						 error;

	*data = NULL;
	err[0] = '\0';
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&in, 0, sizeof(in));
	in.jail = jail_in(jail);
	memset(&r, 0, sizeof(r));
	if ((error = plug_call(conn, "arcana-netgraph", "netgraph", "read",
	    &in, &r, a, err, errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	nodes = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r.node.n; i++) {
		const struct arcana_netgraph_node *y = &r.node.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", y->name);
		put_str(o, "type", y->type);
		put_str(o, "id", y->id);
		hooks = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < y->hook.n; k++) {
			h = ucl_object_typed_new(UCL_OBJECT);
			put_str(h, "hook", y->hook.v[k].name);
			put_str(h, "peer", y->hook.v[k].peer);
			put_str(h, "peer-type", y->hook.v[k].peer_type);
			put_str(h, "peer-id", y->hook.v[k].peer_id);
			put_str(h, "peer-hook", y->hook.v[k].peer_hook);
			ucl_array_append(hooks, h);
		}
		put(o, "hooks", hooks);
		ucl_array_append(nodes, o);
	}
	*data = ucl_object_typed_new(UCL_OBJECT);
	put(*data, "nodes", nodes);
	cbl_yarena_free(a);
	return (0);
}

/* ---- WireGuard --------------------------------------------------- */

/* A yang:date-and-time the agent wrote (UTC, Z) as seconds; 0: none. */
static int64_t
epoch_of(const char *s)
{
	struct tm	 tm;
	const char	*p;

	memset(&tm, 0, sizeof(tm));
	if (s == NULL || (p = strptime(s, "%Y-%m-%dT%H:%M:%S", &tm)) == NULL)
		return (0);
	return ((int64_t)timegm(&tm));
}

static int
wireguard(cbl_conn *conn, const char *jail, ucl_object_t **data, char *err,
    size_t errlen)
{
	struct arcana_wireguard_wireguard_read_input	 in;
	struct arcana_wireguard_wireguard_read_output	 r;
	ucl_object_t					*ifs, *o, *peers, *p, *ips;
	cbl_yarena					*a;
	int						 error;

	*data = NULL;
	err[0] = '\0';
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&in, 0, sizeof(in));
	in.jail = jail_in(jail);
	memset(&r, 0, sizeof(r));
	if ((error = plug_call(conn, "arcana-wireguard", "wireguard", "read",
	    &in, &r, a, err, errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	ifs = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r.interface.n; i++) {
		const struct arcana_wireguard_interface *y = &r.interface.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", y->name);
		put(o, "private-key", ucl_object_frombool(y->has_private_key &&
		    y->private_key));
		put_str(o, "public-key", y->public_key);
		put(o, "listen-port", ucl_object_fromint(y->listen_port));
		peers = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < y->peer.n; k++) {
			const struct arcana_wireguard_interface_peer *q =
			    &y->peer.v[k];

			p = ucl_object_typed_new(UCL_OBJECT);
			put_str(p, "public-key", q->public_key);
			put(p, "preshared-key", ucl_object_frombool(
			    q->has_preshared_key && q->preshared_key));
			put_str(p, "endpoint", q->endpoint);
			ips = ucl_object_typed_new(UCL_ARRAY);
			for (size_t m = 0; m < q->allowed_ip.n; m++)
				ucl_array_append(ips, ucl_object_fromstring(
				    q->allowed_ip.v[m].v.m0));
			put(p, "allowed-ips", ips);
			/* 0: never, as wg says it. */
			put(p, "latest-handshake", ucl_object_fromint(epoch_of(
			    q->latest_handshake)));
			put(p, "rx", ucl_object_fromint((int64_t)q->received));
			put(p, "tx", ucl_object_fromint((int64_t)q->sent));
			put(p, "keepalive", ucl_object_fromint(q->keepalive));
			ucl_array_append(peers, p);
		}
		put(o, "peers", peers);
		ucl_array_append(ifs, o);
	}
	*data = ucl_object_typed_new(UCL_OBJECT);
	put(*data, "interfaces", ifs);
	put(*data, "now", ucl_object_fromint(r.now != NULL ? epoch_of(r.now) :
	    (int64_t)time(NULL)));
	cbl_yarena_free(a);
	return (0);
}

/* ---- BIRD --------------------------------------------------------- */

/* A GET of module mod's top-level node top, datastore ds, into data. */
static int
plug_get(cbl_conn *conn, const char *mod, const char *top, int ds, void *data,
    cbl_yarena *a, char *err, size_t errlen)
{
	const struct cbl_ynode	*n;
	cbl_msg			*req, *rep = NULL;
	int			 error;

	if ((n = yq_top(mod, top)) == NULL) {
		snprintf(err, errlen, "%s is not in the tables", mod);
		return (ENOENT);
	}
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_GET, 0, &req)) != 0 || (error = cbl_msg_put_yget(req,
	    &n->sid, 1)) != 0 || (error = cbl_msg_set_datastore(req,
	    (enum cbl_yds_name)ds)) != 0) {
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = cbl_request(conn, req, &rep, -1)) != 0) {
		snprintf(err, errlen, "%s", rep != NULL && cbl_msg_err_str(rep) !=
		    NULL ? cbl_msg_err_str(rep) : strerror(error));
		cbl_msg_free(rep);
		return (error);
	}
	error = cbl_msg_ydecode_member(rep, n, data, a, 0, err, errlen);
	cbl_msg_free(rep);
	return (error == ENOENT ? 0 : error);
}

static ucl_object_t *
strs_of(size_t n, const char *const *v)
{
	ucl_object_t	*arr;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < n; i++)
		ucl_array_append(arr, ucl_object_fromstring(v[i]));
	return (arr);
}

/* A number the agent printed as text, as text again. */
static void
put_num_str(ucl_object_t *o, const char *key, bool has, uint64_t v)
{
	char	buf[24];

	if (!has)
		return;
	snprintf(buf, sizeof(buf), "%ju", (uintmax_t)v);
	put(o, key, ucl_object_fromstring(buf));
}

/* A protocol as do_bird() made it: show protocols all's own words. */
static ucl_object_t *
bird_protocol(const struct arcana_bird_protocol *y)
{
	const struct arcana_bird_protocol_bgp	*b = y->bgp;
	const struct arcana_bird_protocol_rpki	*r = y->rpki;
	ucl_object_t				*o, *chans, *c;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", y->name);
	put_str(o, "proto", y->type);
	put_str(o, "table", y->table);
	put_str(o, "state", y->state);
	put_str(o, "since", y->since);
	put_str(o, "info", y->info);
	if (y->detail.n > 0)
		put(o, "detail", strs_of(y->detail.n, y->detail.v));
	put_str(o, "description", y->description);
	if (b != NULL) {
		put_str(o, "bgp-state", b->state);
		if (b->has_neighbor)
			put_str(o, "neighbor", b->neighbor.v.m0);
		put_num_str(o, "neighbor-as", b->has_neighbor_as,
		    b->neighbor_as);
		put_num_str(o, "local-as", b->has_local_as, b->local_as);
		put_str(o, "neighbor-id", b->neighbor_id);
		if (b->has_source)
			put_str(o, "source", b->source.v.m0);
		put_str(o, "session", b->session);
		put_str(o, "hold", b->hold);
		put_str(o, "keepalive", b->keepalive);
		put_str(o, "last-error", b->last_error);
	}
	if (r != NULL) {
		put_str(o, "cache", r->cache);
		put_str(o, "rpki-status", r->status);
		put_str(o, "serial", r->serial);
		put_str(o, "last-update", r->last_update);
	}
	if (y->channel.n > 0) {
		chans = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < y->channel.n; i++) {
			const struct arcana_bird_protocol_channel *q =
			    &y->channel.v[i];

			c = ucl_object_typed_new(UCL_OBJECT);
			put_str(c, "name", q->name);
			put_str(c, "state", q->state);
			put_str(c, "table", q->table);
			put_str(c, "input-filter", q->input_filter);
			put_str(c, "output-filter", q->output_filter);
			put_str(c, "routes", q->routes);
			if (q->has_imported)
				put(c, "imported", ucl_object_fromint((int64_t)
				    q->imported));
			if (q->has_exported)
				put(c, "exported", ucl_object_fromint((int64_t)
				    q->exported));
			ucl_array_append(chans, c);
		}
		put(o, "channels", chans);
	}
	return (o);
}

static int
bird(cbl_conn *conn, const char *jail, ucl_object_t **data, char *err,
    size_t errlen)
{
	struct arcana_bird_bird_read_input	 in;
	struct arcana_bird_state		 r;
	ucl_object_t				*top, *arr, *o;
	cbl_yarena				*a;
	int					 error;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&in, 0, sizeof(in));
	in.jail = jail_in(jail);
	memset(&r, 0, sizeof(r));
	if ((error = plug_call(conn, "arcana-bird", "bird", "read", &in, &r, a,
	    err, errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "status", strs_of(r.status.n, r.status.v));
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r.protocol.n; i++)
		ucl_array_append(arr, bird_protocol(&r.protocol.v[i]));
	put(top, "protocols", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r.ospf_neighbor.n; i++) {
		const struct arcana_bird_state_ospf_neighbor *y =
		    &r.ospf_neighbor.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "proto", y->protocol);
		put_str(o, "router-id", y->router_id);
		put_str(o, "pri", y->priority);
		put_str(o, "state", y->state);
		put_str(o, "dtime", y->dead_time);
		put_str(o, "interface", y->interface);
		put_str(o, "address", y->address);
		ucl_array_append(arr, o);
	}
	put(top, "ospf", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r.bfd_session.n; i++) {
		const struct arcana_bird_state_bfd_session *y =
		    &r.bfd_session.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "proto", y->protocol);
		put_str(o, "address", y->address);
		put_str(o, "interface", y->interface);
		put_str(o, "state", y->state);
		put_str(o, "since", y->since);
		put_str(o, "interval", y->interval);
		put_str(o, "timeout", y->timeout);
		ucl_array_append(arr, o);
	}
	put(top, "bfd", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r.table.n; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", r.table.v[i].name);
		put(o, "routes", ucl_object_fromint((int64_t)
		    r.table.v[i].routes));
		put(o, "networks", ucl_object_fromint((int64_t)
		    r.table.v[i].networks));
		ucl_array_append(arr, o);
	}
	put(top, "tables", arr);
	*data = top;
	cbl_yarena_free(a);
	return (0);
}

static int
bird_routes(cbl_conn *conn, const char *jail, const char *filter,
    ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_bird_bird_routes_input	 in;
	struct arcana_bird_routes		 r;
	ucl_object_t				*top, *arr, *o, *hops, *h;
	cbl_yarena				*a;
	int					 error;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&in, 0, sizeof(in));
	in.jail = jail_in(jail);
	/* None said: all of them, without their attributes. */
	in.filter = filter != NULL ? filter : "";
	memset(&r, 0, sizeof(r));
	if ((error = plug_call(conn, "arcana-bird", "bird", "routes", &in, &r,
	    a, err, errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	put_str(top, "message", r.message);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r.route.n; i++) {
		const struct arcana_bird_routes_route *y = &r.route.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "table", y->table);
		put_str(o, "prefix", y->prefix);
		put_str(o, "type", y->type);
		put_str(o, "protocol", y->protocol);
		put_str(o, "from", y->from);
		put_str(o, "since", y->since);
		put(o, "primary", ucl_object_frombool(y->has_primary &&
		    y->primary));
		put_str(o, "preference", y->preference);
		put_str(o, "info", y->info);
		if (y->nexthop.n > 0) {
			hops = ucl_object_typed_new(UCL_ARRAY);
			for (size_t k = 0; k < y->nexthop.n; k++) {
				h = ucl_object_typed_new(UCL_OBJECT);
				put_str(h, "via", y->nexthop.v[k].via);
				put_str(h, "interface",
				    y->nexthop.v[k].interface);
				ucl_array_append(hops, h);
			}
			put(o, "nexthops", hops);
		}
		if (y->attribute.n > 0)
			put(o, "attrs", strs_of(y->attribute.n,
			    y->attribute.v));
		ucl_array_append(arr, o);
	}
	put(top, "routes", arr);
	put(top, "count", ucl_object_fromint((int64_t)r.count));
	*data = top;
	cbl_yarena_free(a);
	return (0);
}

static ucl_object_t *
ospf_area(const struct arcana_bird_ospf_protocol_topology *t)
{
	ucl_object_t	*o, *arr, *n, *links, *l;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "area", t->area);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < t->router.n; i++) {
		const struct arcana_bird_ospf_protocol_topology_router *r =
		    &t->router.v[i];

		n = ucl_object_typed_new(UCL_OBJECT);
		put_str(n, "id", r->id);
		links = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < r->link.n; k++) {
			l = ucl_object_typed_new(UCL_OBJECT);
			put_str(l, "kind", r->link.v[k].kind);
			put_str(l, "to", r->link.v[k].to);
			if (r->link.v[k].has_metric)
				put(l, "metric", ucl_object_fromint(
				    r->link.v[k].metric));
			if (r->link.v[k].has_metric2)
				put(l, "metric2", ucl_object_fromint(
				    r->link.v[k].metric2));
			ucl_array_append(links, l);
		}
		put(n, "links", links);
		if (r->has_distance)
			put(n, "distance", ucl_object_fromint(r->distance));
		if (r->has_unreachable && r->unreachable)
			put(n, "unreachable", ucl_object_frombool(true));
		ucl_array_append(arr, n);
	}
	put(o, "routers", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < t->network.n; i++) {
		const struct arcana_bird_ospf_protocol_topology_network *w =
		    &t->network.v[i];

		n = ucl_object_typed_new(UCL_OBJECT);
		put_str(n, "id", w->id);
		put(n, "routers", strs_of(w->router.n, w->router.v));
		put_str(n, "dr", w->dr);
		if (w->has_distance)
			put(n, "distance", ucl_object_fromint(w->distance));
		ucl_array_append(arr, n);
	}
	put(o, "networks", arr);
	return (o);
}

/* filter: "topology", or "topology" and a protocol's name, or none. */
static int
bird_ospf(cbl_conn *conn, const char *jail, const char *filter,
    ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_bird_bird_ospf_input	 in;
	struct arcana_bird_ospf			 r;
	ucl_object_t				*top, *arr, *o, *areas;
	cbl_yarena				*a;
	int					 error;

	memset(&in, 0, sizeof(in));
	in.jail = jail_in(jail);
	if (filter != NULL && filter[0] != '\0') {
		if (strncmp(filter, "topology", 8) != 0 || (filter[8] != '\0' &&
		    filter[8] != ' ')) {
			snprintf(err, errlen, "the filter is topology, or "
			    "topology and an OSPF protocol's name");
			return (EINVAL);
		}
		in.has_topology = in.topology = true;
		if (filter[8] == ' ' && filter[9] != '\0')
			in.protocol = filter + 9;
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	if ((error = plug_call(conn, "arcana-bird", "bird", "ospf", &in, &r, a,
	    err, errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r.protocol.n; i++) {
		const struct arcana_bird_ospf_protocol *y = &r.protocol.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", y->name);
		put(o, "areas", strs_of(y->area.n, y->area.v));
		if (in.topology) {
			areas = ucl_object_typed_new(UCL_ARRAY);
			for (size_t k = 0; k < y->topology.n; k++)
				ucl_array_append(areas, ospf_area(
				    &y->topology.v[k]));
			put(o, "topology", areas);
		}
		ucl_array_append(arr, o);
	}
	put(top, "protocols", arr);
	*data = top;
	cbl_yarena_free(a);
	return (0);
}

/*
 * The confirmed commits of BIRD's configuration that wait for the page
 * to confirm them: a host's (its id) and jail's, its persist-id.
 */
#define	SAFE_WAIT	60	/* s, the agent's own when the host says none */

static pthread_mutex_t	 wait_lock = PTHREAD_MUTEX_INITIALIZER;
static struct {
	char	 key[96];
	char	 token[33];
} waits[32];

static void
wait_key(char *buf, size_t len, const char *host, const char *jail)
{

	snprintf(buf, len, "%s@%s", host, jail != NULL ? jail : "");
}

static void
wait_put(const char *host, const char *jail, const char *token)
{
	char	key[96];
	size_t	i, free_at = nitems(waits);

	wait_key(key, sizeof(key), host, jail);
	pthread_mutex_lock(&wait_lock);
	for (i = 0; i < nitems(waits); i++) {
		if (strcmp(waits[i].key, key) == 0)
			break;
		if (waits[i].key[0] == '\0' && free_at == nitems(waits))
			free_at = i;
	}
	if (i == nitems(waits))
		i = free_at < nitems(waits) ? free_at : 0;
	snprintf(waits[i].key, sizeof(waits[i].key), "%s", key);
	snprintf(waits[i].token, sizeof(waits[i].token), "%s", token);
	pthread_mutex_unlock(&wait_lock);
}

/* The token waiting for host's jail's, taken; false where none. */
static bool
wait_take(const char *host, const char *jail, char *token, size_t len)
{
	char	key[96];
	bool	found = false;

	wait_key(key, sizeof(key), host, jail);
	pthread_mutex_lock(&wait_lock);
	for (size_t i = 0; i < nitems(waits); i++)
		if (strcmp(waits[i].key, key) == 0) {
			snprintf(token, len, "%s", waits[i].token);
			memset(&waits[i], 0, sizeof(waits[i]));
			found = true;
			break;
		}
	pthread_mutex_unlock(&wait_lock);
	return (found);
}

static const char *
sha_of(const char *text, char *buf, size_t len)
{
	unsigned char	md[32];
	unsigned int	n;

	buf[0] = '\0';
	if (EVP_Digest(text, strlen(text), md, &n, EVP_sha256(), NULL) != 1)
		return (buf);
	for (int i = 0; i < 32 && (size_t)i * 2 + 2 < len; i++)
		snprintf(buf + i * 2, len - (size_t)i * 2, "%02x", md[i]);
	return (buf);
}

/* The configuration of the host's BIRD or the jail's, in d. */
static struct arcana_bird_configuration *
conf_in(struct arcana_bird *d, const char *jail)
{

	if (d->bird == NULL)
		return (NULL);
	if (jail == NULL || jail[0] == '\0')
		return ((struct arcana_bird_configuration *)(uintptr_t)
		    d->bird->configuration);
	for (size_t i = 0; i < d->bird->jail.n; i++)
		if (strcmp(d->bird->jail.v[i].name, jail) == 0)
			return ((struct arcana_bird_configuration *)
			    (uintptr_t)d->bird->jail.v[i].configuration);
	return (NULL);
}

/* The file of path in c, its text and SHA-256, the files in top. */
static const struct arcana_bird_configuration_file *
conf_put(ucl_object_t *top, const struct arcana_bird_configuration *c,
    const char *path)
{
	const struct arcana_bird_configuration_file	*f = NULL;
	ucl_object_t					*files;
	char						 sha[65];

	files = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; c != NULL && i < c->file.n; i++) {
		ucl_array_append(files, ucl_object_fromstring(
		    c->file.v[i].path));
		if (strcmp(c->file.v[i].path, path) == 0)
			f = &c->file.v[i];
	}
	put(top, "files", files);
	put_str(top, "path", path);
	if (f != NULL && f->text != NULL) {
		put_str(top, "text", f->text);
		put_str(top, "sha256", sha_of(f->text, sha, sizeof(sha)));
	}
	return (f);
}

int
yplug_bird_config(cbl_conn *conn, const char *host, const char *jail,
    const char *path, const char *text, const char *sha256, bool check,
    bool safe, int wait, bool confirm, ucl_object_t *top, char *err,
    size_t errlen)
{
	struct arcana_bird_bird_check_input		 cin;
	const struct arcana_bird_configuration_file	*f;
	struct arcana_bird_configuration_file		*nf;
	struct arcana_bird_configuration		*c, *nc;
	struct arcana_bird_bird_jail			*jv;
	struct arcana_bird_bird				*b;
	const struct cbl_ynode				*n;
	struct arcana_bird				 d;
	cbl_yarena					*a;
	char						 token[33], tag[80];
	char						 sha[65];
	size_t						 k;
	int						 error;

	err[0] = '\0';
	if (jail != NULL && jail[0] == '\0')
		jail = NULL;
	/* The change that waits stays: its commit confirmed. */
	if (confirm) {
		if (!wait_take(host, jail, token, sizeof(token))) {
			snprintf(err, errlen, "no change to BIRD waits to be "
			    "confirmed: it was taken back when its time was up");
			return (ENOENT);
		}
		return (ytrans_confirm(conn, token, err, errlen));
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&d, 0, sizeof(d));
	if ((error = plug_get(conn, "arcana-bird", "bird", CBL_YDS_RUNNING, &d,
	    a, err, errlen)) != 0)
		goto out;
	c = conf_in(&d, jail);
	if (path == NULL || path[0] == '\0')
		path = c != NULL && c->path != NULL ? c->path :
		    "/usr/local/etc/bird.conf";
	f = conf_put(top, c, path);
	if (text == NULL) {
		if (f == NULL) {
			snprintf(err, errlen, "%s: %s", path, c == NULL ?
			    "BIRD has no configuration there" :
			    "no such file of BIRD's configuration");
			error = ENOENT;
		}
		goto out;
	}
	if (check) {
		memset(&cin, 0, sizeof(cin));
		cin.jail = jail;
		cin.path = path;
		cin.text = text;
		error = plug_call(conn, "arcana-bird", "bird", "check", &cin,
		    NULL, a, err, errlen);
		goto out;
	}
	/* Made from what is there now, or refused. */
	if (sha256 == NULL || strcmp(sha256, sha_of(f != NULL && f->text !=
	    NULL ? f->text : "", sha, sizeof(sha))) != 0) {
		snprintf(err, errlen, "the file is not the one this was made "
		    "from: somebody changed it meanwhile.  Read it again");
		error = EBUSY;
		goto out;
	}
	/* Running's, the file's text in its place or the file added. */
	if ((n = yq_top("arcana-bird", "bird")) == NULL ||
	    (b = cbl_yarena_alloc(a, sizeof(*b))) == NULL ||
	    (nc = cbl_yarena_alloc(a, sizeof(*nc))) == NULL ||
	    (nf = cbl_yarena_alloc(a, ((c != NULL ? c->file.n : 0) + 1) *
	    sizeof(*nf))) == NULL) {
		error = ENOMEM;
		goto out;
	}
	memset(b, 0, sizeof(*b));
	memset(nc, 0, sizeof(*nc));
	if (d.bird != NULL)
		*b = *d.bird;
	k = 0;
	for (size_t i = 0; c != NULL && i < c->file.n; i++)
		nf[k++] = c->file.v[i];
	for (k = 0; k < (c != NULL ? c->file.n : 0) && strcmp(nf[k].path,
	    path) != 0; k++)
		;
	if (c == NULL || k == c->file.n) {
		memset(&nf[k], 0, sizeof(nf[k]));
		nf[k].path = path;
	}
	nf[k].text = text;
	nc->path = c != NULL ? c->path : NULL;
	nc->file.n = c != NULL ? c->file.n : 0;
	if (c == NULL || k == c->file.n)
		nc->file.n++;
	nc->file.v = nf;
	if (jail == NULL)
		b->configuration = nc;
	else {
		if ((jv = cbl_yarena_alloc(a, (b->jail.n + 1) *
		    sizeof(*jv))) == NULL) {
			error = ENOMEM;
			goto out;
		}
		for (size_t i = 0; i < b->jail.n; i++)
			jv[i] = b->jail.v[i];
		for (k = 0; k < b->jail.n && strcmp(jv[k].name, jail) != 0; k++)
			;
		if (k == b->jail.n) {
			memset(&jv[k], 0, sizeof(jv[k]));
			jv[k].name = jail;
			b->jail.n++;
		}
		jv[k].configuration = nc;
		b->jail.v = jv;
	}
	d.bird = b;
	/*
	 * Safe: a confirmed commit the page confirms, BIRD's timer beside;
	 * else a plain one, BIRD told to read it, as the operation did.
	 */
	if (safe && wait <= 0)
		wait = SAFE_WAIT;
	if ((error = ytrans_commit(conn, n, &d, NULL, 0, safe ? wait : -1,
	    token, sizeof(token), err, errlen, tag, sizeof(tag))) != 0)
		goto out;
	if (safe) {
		wait_put(host, jail, token);
		put(top, "confirm_by", ucl_object_fromint((int64_t)time(NULL) +
		    wait));
	}
	(void)conf_put(top, nc, path);
out:
	cbl_yarena_free(a);
	return (error);
}

/* ---- the kinds ----------------------------------------------------- */

bool
yplug_kind(int kind)
{

	return (kind == ARC_NET_KIND_NETGRAPH || kind ==
	    ARC_NET_KIND_WIREGUARD || kind == ARC_NET_KIND_BIRD || kind ==
	    ARC_NET_KIND_BIRD_ROUTES || kind == ARC_NET_KIND_BIRD_OSPF);
}

int
yplug_net(cbl_conn *conn, int kind, const char *jail, const char *filter,
    ucl_object_t **data, char *err, size_t errlen)
{

	*data = NULL;
	switch (kind) {
	case ARC_NET_KIND_NETGRAPH:
		return (netgraph(conn, jail, data, err, errlen));
	case ARC_NET_KIND_WIREGUARD:
		return (wireguard(conn, jail, data, err, errlen));
	case ARC_NET_KIND_BIRD:
		return (bird(conn, jail, data, err, errlen));
	case ARC_NET_KIND_BIRD_ROUTES:
		return (bird_routes(conn, jail, filter != NULL && filter[0] !=
		    '\0' ? filter : NULL, data, err, errlen));
	case ARC_NET_KIND_BIRD_OSPF:
		return (bird_ospf(conn, jail, filter, data, err, errlen));
	default:
		snprintf(err, errlen, "no module reads that kind");
		return (EINVAL);
	}
}
