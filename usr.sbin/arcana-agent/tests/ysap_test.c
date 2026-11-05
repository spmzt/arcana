/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ysap: stand-in interfaces as RFC 9408's SAP network (ysap.c), for
 * agent_test.sh: a termination point or a SAP a line, through YANG-CBOR
 * and back.
 *
 *	ysap file
 *
 * The file: {"host", "interfaces": [{"name", "type" (iana-if-type's),
 * "oper" (ietf-interfaces' oper-status), "driver", "groups", "parent",
 * "peer", "peer-vnet", "qinq", "aggport", "bridge-port", "lne", "descr",
 * "address", "last"}]}.
 */

#include <sys/param.h>

#include "ycommon.h"
#include "yjson.h"

typedef struct ietf_interfaces_interfaces_interface yif;

static const char *const opers[] = { "", "up", "down", "testing", "unknown",
    "dormant", "not-present", "lower-layer-down" };

static uint64_t
ident_sid(const char *mod, const char *name)
{

	for (uint32_t i = 0; i < ymodel_schema.nident; i++)
		if (strcmp(ymodel_schema.ident[i].name, name) == 0 &&
		    strcmp(ymodel_schema.ident[i].module->name, mod) == 0)
			return (ymodel_schema.ident[i].sid);
	return (0);
}

static const char *
ident(uint64_t sid)
{

	for (uint32_t i = 0; i < ymodel_schema.nident; i++)
		if (ymodel_schema.ident[i].sid == sid)
			return (ymodel_schema.ident[i].name);
	return ("-");
}

static int
enc(const void *v, struct cbl_ybuf *b)
{

	return (ietf_network_networks_encode(v, b));
}

static int
dec(const void *p, size_t len, void *v, cbl_yarena *a, int flags,
    char *why, size_t whylen)
{

	return (ietf_network_networks_decode(p, len, v, a, flags, why,
	    whylen));
}

static void
one(cbl_yarena *a, const ucl_object_t *o, yif *e)
{
	static struct ietf_interfaces_interfaces_interface_dot1ax_aggport ap;
	static struct ietf_interfaces_interfaces_interface_dot1q_bridge_port bp;
	static struct ietf_interfaces_interfaces_interface_if_ext_encapsulation_if_vlan_dot1q_vlan_second_tag st;
	struct ietf_interfaces_interfaces_interface_if_ext_encapsulation *en;
	struct ietf_interfaces_interfaces_interface_if_ext_encapsulation_if_vlan_dot1q_vlan *q;
	struct ietf_interfaces_interfaces_interface_ip_ipv4 *v4;
	const char *s;
	bool has;

	memset(e, 0, sizeof(*e));
	e->name = yj_str(a, o, "name");
	if ((s = yj_str(a, o, "type")) != NULL)
		e->has_type = (e->type = ident_sid("iana-if-type", s)) != 0;
	if ((s = yj_str(a, o, "oper")) != NULL)
		for (size_t i = 1; i < nitems(opers); i++)
			if (strcmp(s, opers[i]) == 0) {
				e->has_oper_status = true;
				e->oper_status = i;
			}
	e->arcif_driver_name = yj_str(a, o, "driver");
	if (yj_strs(a, ucl_object_lookup(o, "groups"), &e->arcif_group.n,
	    &e->arcif_group.v) != 0)
		errx(1, "groups");
	e->if_ext_parent_interface = yj_str(a, o, "parent");
	e->if_ext_peer_interface = yj_str(a, o, "peer");
	e->arcif_peer_vnet = yj_yes(o, "peer-vnet", &e->has_arcif_peer_vnet);
	if (yj_yes(o, "qinq", &has) && has) {
		if ((en = calloc(1, sizeof(*en))) == NULL ||
		    (q = calloc(1, sizeof(*q))) == NULL)
			err(1, "calloc");
		q->second_tag = &st;
		en->if_vlan_dot1q_vlan = q;
		e->if_ext_encapsulation = en;
	}
	if (yj_yes(o, "aggport", &has) && has)
		e->dot1ax_aggport = &ap;
	if (yj_yes(o, "bridge-port", &has) && has)
		e->dot1q_bridge_port = &bp;
	e->lne_bind_lne_name = yj_str(a, o, "lne");
	e->description = yj_str(a, o, "descr");
	e->last_change = yj_str(a, o, "last");
	if (yj_yes(o, "address", &has) && has) {
		if ((v4 = calloc(1, sizeof(*v4))) == NULL)
			err(1, "calloc");
		v4->address.n = 1;
		e->ip_ipv4 = v4;
	}
}

int
main(int argc, char **argv)
{
	struct ietf_interfaces ifs;
	struct ietf_interfaces_interfaces c;
	struct ietf_network nw;
	struct ietf_network_networks back;
	const struct ietf_network_networks_network *n;
	const struct ietf_network_networks_network_node *nd;
	const struct ietf_network_networks_network_node_sap_service_sap *s;
	const ucl_object_t *arr, *o;
	ucl_object_iter_t it;
	ucl_object_t *top;
	cbl_yarena *a;
	yif *v;
	size_t k;
	int error;

	if (argc != 2)
		errx(2, "usage: ysap file");
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if ((top = yj_parse(slurp(argv[1]))) == NULL)
		errx(1, "%s: not JSON", argv[1]);
	arr = ucl_object_lookup(top, "interfaces");
	if ((v = calloc(yj_count(arr) + 1, sizeof(*v))) == NULL)
		err(1, "calloc");
	k = 0;
	YJ_EACH(arr, it, o)
		one(a, o, &v[k++]);
	memset(&c, 0, sizeof(c));
	c.interface.n = k;
	c.interface.v = v;
	ifs.interfaces = &c;
	if ((error = ysap_network(&ifs, yj_str(a, top, "host"), a, &nw)) != 0)
		errc(1, error, "ysap_network");
	n = &nw.networks->network.v[0];
	nd = &n->node.v[0];
	printf("network %s %s node %s\n", n->network_id,
	    ident(n->network_types->sap_sap_network->service_type.v[0]),
	    nd->node_id);
	for (size_t i = 0; i < nd->nt_termination_point.n; i++)
		printf("tp %s\n", nd->nt_termination_point.v[i].tp_id);
	for (size_t i = 0; i < nd->sap_service.n; i++)
		for (size_t j = 0; j < nd->sap_service.v[i].sap.n; j++) {
			s = &nd->sap_service.v[i].sap.v[j];
			printf("sap %s %s if=%s type=%s encap=%s role=%s "
			    "children=%s parent=%s peer=%s status=%s "
			    "since=%s descr=%s\n", ident(nd->sap_service.v[i].
			    service_type), s->sap_id, str(s->attachment_interface),
			    ident(s->interface_type),
			    ident(s->encapsulation_type), ident(s->role),
			    s->allows_child_saps ? "yes" : "no",
			    str(s->parent_termination_point),
			    s->peer_sap_id.n > 0 ? s->peer_sap_id.v[0] : "-",
			    ident(s->sap_status->status),
			    str(s->sap_status->last_change), str(s->description));
		}
	same(enc, dec, nw.networks, &back, a);
	return (0);
}
