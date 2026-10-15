/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yplug: BIRD, WireGuard and netgraph as arcana-bird, arcana-wireguard
 * and arcana-netgraph have them (ybird.c, ywg.c, yng.c), for
 * agent_test.sh.
 *
 *	yplug bird reply.json		the network operation's bird kind
 *	yplug bird-routes reply.json	its bird-routes kind
 *	yplug bird-config path file sha256 included...
 *					bird-config's reply
 *	yplug wireguard reply.json	the wireguard kind
 *	yplug netgraph reply.json	the netgraph kind
 *
 * Through YANG-CBOR and back, the same bytes.
 */

#include "ycommon.h"

int
main(int argc, char **argv)
{
	cbl_yarena *a;
	int error;

	if (argc < 3)
		errx(2, "usage: yplug bird|bird-routes|wireguard|netgraph "
		    "reply.json | bird-config path file sha256 included...");
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if (strcmp(argv[1], "bird") == 0) {
		struct arcana_bird_bird_state s, back;

		if ((error = ybird_from_json(slurp(argv[2]), a, &s)) != 0)
			errc(1, error, "ybird_from_json");
		for (size_t i = 0; i < s.status.n; i++)
			printf("status %s\n", s.status.v[i]);
		for (size_t i = 0; i < s.protocol.n; i++) {
			const struct arcana_bird_bird_state_protocol *p =
			    &s.protocol.v[i];

			printf("protocol %s %s table=%s %s since=%s info=%s "
			    "description=%s\n", p->name, str(p->type), str(
			    p->table), str(p->state), str(p->since), str(
			    p->info), str(p->description));
			if (p->bgp != NULL)
				printf("  bgp %s neighbor=%s as=%u local-as=%u id=%s "
				    "source=%s session=%s hold=%s keepalive=%s "
				    "error=%s\n", str(p->bgp->state),
				    p->bgp->has_neighbor ? p->bgp->neighbor.v.m0 :
				    "-", p->bgp->neighbor_as, p->bgp->local_as,
				    str(p->bgp->neighbor_id), p->bgp->has_source ?
				    p->bgp->source.v.m0 : "-", str(
				    p->bgp->session), str(p->bgp->hold), str(
				    p->bgp->keepalive), str(p->bgp->last_error));
			if (p->rpki != NULL)
				printf("  rpki cache=%s status=%s serial=%s "
				    "update=%s\n", str(p->rpki->cache), str(
				    p->rpki->status), str(p->rpki->serial), str(
				    p->rpki->last_update));
			for (size_t k = 0; k < p->channel.n; k++)
				printf("  channel %s %s table=%s in=%s out=%s "
				    "routes=%s imported=%ju exported=%ju\n",
				    p->channel.v[k].name, str(p->channel.v[k].state),
				    str(p->channel.v[k].table), str(
				    p->channel.v[k].input_filter), str(
				    p->channel.v[k].output_filter), str(
				    p->channel.v[k].routes), (uintmax_t)
				    p->channel.v[k].imported, (uintmax_t)
				    p->channel.v[k].exported);
		}
		for (size_t i = 0; i < s.ospf_neighbor.n; i++)
			printf("ospf %s %s pri=%s %s dead=%s %s %s\n", str(
			    s.ospf_neighbor.v[i].protocol), str(
			    s.ospf_neighbor.v[i].router_id), str(
			    s.ospf_neighbor.v[i].priority), str(
			    s.ospf_neighbor.v[i].state), str(
			    s.ospf_neighbor.v[i].dead_time), str(
			    s.ospf_neighbor.v[i].interface), str(
			    s.ospf_neighbor.v[i].address));
		for (size_t i = 0; i < s.bfd_session.n; i++)
			printf("bfd %s %s %s %s since=%s %s/%s\n", str(
			    s.bfd_session.v[i].protocol), str(
			    s.bfd_session.v[i].address), str(
			    s.bfd_session.v[i].interface), str(
			    s.bfd_session.v[i].state), str(
			    s.bfd_session.v[i].since), str(
			    s.bfd_session.v[i].interval), str(
			    s.bfd_session.v[i].timeout));
		for (size_t i = 0; i < s.table.n; i++)
			printf("table %s routes=%ju networks=%ju\n",
			    s.table.v[i].name, (uintmax_t)s.table.v[i].routes,
			    (uintmax_t)s.table.v[i].networks);
		same((void *)arcana_bird_bird_state_encode, (void *)
		    arcana_bird_bird_state_decode, &s, &back, a);
	} else if (strcmp(argv[1], "bird-routes") == 0) {
		struct arcana_bird_bird_routes_output r, back;

		if ((error = ybird_routes_from_json(slurp(argv[2]), a, &r)) != 0)
			errc(1, error, "ybird_routes_from_json");
		printf("routes count=%ju message=%s\n", (uintmax_t)r.count, str(
		    r.message));
		for (size_t i = 0; i < r.route.n; i++) {
			const struct arcana_bird_bird_routes_output_route *o =
			    &r.route.v[i];

			printf("route %s %s %s %s from=%s since=%s primary=%s "
			    "pref=%s info=%s", str(o->table), str(o->prefix),
			    str(o->type), str(o->protocol), str(o->from), str(
			    o->since), o->primary ? "yes" : "no", str(
			    o->preference), str(o->info));
			for (size_t k = 0; k < o->nexthop.n; k++)
				printf(" via %s on %s", str(o->nexthop.v[k].via),
				    str(o->nexthop.v[k].interface));
			for (size_t k = 0; k < o->attribute.n; k++)
				printf(" [%s]", o->attribute.v[k]);
			printf("\n");
		}
		same((void *)arcana_bird_bird_routes_output_encode, (void *)
		    arcana_bird_bird_routes_output_decode, &r, &back, a);
	} else if (strcmp(argv[1], "bird-config") == 0) {
		struct arcana_bird_bird_configuration c, back;

		if (argc < 5)
			errx(2, "bird-config path file sha256 included...");
		if ((error = ybird_config_from(argv[2], slurp(argv[3]), argv[4],
		    (const char *const *)argv + 5, (size_t)(argc - 5), a, &c)) !=
		    0)
			errc(1, error, "ybird_config_from");
		printf("configuration %s\n", str(c.path));
		for (size_t i = 0; i < c.file.n; i++)
			printf("file %s text=%zu sha256=%s\n", c.file.v[i].path,
			    c.file.v[i].text != NULL ? strlen(c.file.v[i].text) :
			    0, str(c.file.v[i].sha256));
		same((void *)arcana_bird_bird_configuration_encode, (void *)
		    arcana_bird_bird_configuration_decode, &c, &back, a);
	} else if (strcmp(argv[1], "wireguard") == 0) {
		struct arcana_wireguard_wireguard w, back;

		if ((error = ywg_from_json(slurp(argv[2]), a, &w)) != 0)
			errc(1, error, "ywg_from_json");
		printf("wireguard now=%s\n", str(w.now));
		for (size_t i = 0; i < w.interface.n; i++) {
			const struct arcana_wireguard_wireguard_interface *f =
			    &w.interface.v[i];

			printf("interface %s private=%s public=%s port=%u\n",
			    f->name, f->private_key ? "yes" : "no", str(
			    f->public_key), f->listen_port);
			for (size_t k = 0; k < f->peer.n; k++) {
				const struct arcana_wireguard_wireguard_interface_peer
				    *p = &f->peer.v[k];

				printf("  peer %s preshared=%s endpoint=%s "
				    "handshake=%s rx=%ju tx=%ju keepalive=%u "
				    "allowed=", p->public_key, p->preshared_key ?
				    "yes" : "no", str(p->endpoint), str(
				    p->latest_handshake), (uintmax_t)p->received,
				    (uintmax_t)p->sent, p->keepalive);
				for (size_t m = 0; m < p->allowed_ip.n; m++)
					printf("%s%s", m > 0 ? "," : "",
					    p->allowed_ip.v[m].v.m0);
				printf("\n");
			}
		}
		same((void *)arcana_wireguard_wireguard_encode, (void *)
		    arcana_wireguard_wireguard_decode, &w, &back, a);
	} else if (strcmp(argv[1], "netgraph") == 0) {
		struct arcana_netgraph_netgraph g, back;

		if ((error = yng_from_json(slurp(argv[2]), a, &g)) != 0)
			errc(1, error, "yng_from_json");
		for (size_t i = 0; i < g.node.n; i++) {
			printf("node %s %s %s\n", g.node.v[i].id, str(
			    g.node.v[i].name), str(g.node.v[i].type));
			for (size_t k = 0; k < g.node.v[i].hook.n; k++)
				printf("  hook %s -> %s %s %s %s\n",
				    g.node.v[i].hook.v[k].name, str(
				    g.node.v[i].hook.v[k].peer), str(
				    g.node.v[i].hook.v[k].peer_type), str(
				    g.node.v[i].hook.v[k].peer_id), str(
				    g.node.v[i].hook.v[k].peer_hook));
		}
		same((void *)arcana_netgraph_netgraph_encode, (void *)
		    arcana_netgraph_netgraph_decode, &g, &back, a);
	} else
		errx(2, "%s: bird, bird-routes, bird-config, wireguard or "
		    "netgraph", argv[1]);
	return (0);
}
