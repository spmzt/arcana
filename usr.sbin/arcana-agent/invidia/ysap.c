/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the host as RFC 9408's SAP network, over RFC 8345's network
 * and topology.  One network, YSAP_NETWORK, the same on every host so
 * that the console joins them; its node the host; a termination point
 * each interface the agent reads (ietf-interfaces' list, the vnet
 * jails' with it); and a service attachment point each interface a
 * service can be attached to, a UNI candidate:
 *
 * - an Ethernet interface of the hardware is phy, a cloned one
 *   (epair(4), tap(4), vxlan(4): if_clone(9) puts it in its cloner's
 *   group, which a driver's own never is) logical; both untagged-int,
 *   child SAPs allowed (a vlan(4) on it);
 * - a lagg(4) is lag, lag-int, child SAPs allowed;
 * - a vlan(4) is logical, dot1q (qinq with a second tag), its parent
 *   the parent-termination-point;
 * - an if_bridge(4) is irb where it has an address, else local-bridge;
 * - a lagg's port or a bridge's member is taken: no SAP; nor is a
 *   loopback, a tunnel (gif, gre, wg, ipsec: what an SD-WAN carries its
 *   UCS over), pflog, pfsync or enc.
 *
 * Each SAP is a UNI by role, of the sdwan service type (sap:sdwan, MEF
 * 70.2's SD-WAN UNI); its sap-id and attachment-interface the
 * interface's name, its description the interface's, else the vnet
 * jail it is in; its peer-sap-id an epair(4) end's other end, where the
 * two are in different vnets the listed one of the same driver-name.
 * sap-status is the interface's oper-status: up op-up, testing and
 * unknown op-unknown, any other op-down; its last-change the
 * interface's.  service-status is not the agent's: the console holds
 * the L3NM whose vpn-network-access names the interface.
 */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <cbl_schema.h>

#include "collect.h"

typedef struct ietf_interfaces_interfaces_interface		yif;
typedef struct ietf_network_networks_network			ynet;
typedef struct ietf_network_networks_network_node		ynode;
typedef struct ietf_network_networks_network_node_nt_termination_point ytp;
typedef struct ietf_network_networks_network_node_sap_service	ysvc;
typedef struct ietf_network_networks_network_node_sap_service_sap ysap;
typedef struct ietf_network_networks_network_node_sap_service_sap_sap_status
    ystatus;
typedef struct ietf_interfaces_interfaces_interface_if_ext_encapsulation_if_vlan_dot1q_vlan
    ydot1q;

/* An identity's SID, by its module and name; 0: none. */
static uint64_t
ident_sid(const char *mod, const char *name)
{
	const struct cbl_yident	*id;
	uint32_t		 i;

	for (i = 0; i < ymodel_schema.nident; i++) {
		id = &ymodel_schema.ident[i];
		if (strcmp(id->name, name) == 0 &&
		    strcmp(id->module->name, mod) == 0)
			return (id->sid);
	}
	return (0);
}

/* Whether e is in its cloner's group: its driver-name less the unit. */
static bool
cloned(const yif *e)
{
	const char	*d = e->arcif_driver_name;
	size_t		 n;

	if (d == NULL)
		return (false);
	for (n = strlen(d); n > 0 && isdigit((unsigned char)d[n - 1]); n--)
		;
	for (size_t i = 0; n > 0 && i < e->arcif_group.n; i++)
		if (strlen(e->arcif_group.v[i]) == n &&
		    strncmp(e->arcif_group.v[i], d, n) == 0)
			return (true);
	return (false);
}

static bool
addressed(const yif *e)
{

	return ((e->ip_ipv4 != NULL && e->ip_ipv4->address.n > 0) ||
	    (e->ip_ipv6 != NULL && e->ip_ipv6->address.n > 0));
}

/* The SAP of e in s, false where e is none. */
static bool
sap_of(const yif *e, ysap *s)
{
	const ydot1q	*q;
	const char	*it, *enc;
	uint64_t	 t = e->has_type ? e->type : 0;

	if (e->dot1ax_aggport != NULL || e->dot1q_bridge_port != NULL)
		return (false);
	enc = "untagged-int";
	s->has_allows_child_saps = true;
	if (t == ident_sid("iana-if-type", "ethernetCsmacd")) {
		it = cloned(e) ? "logical" : "phy";
		s->allows_child_saps = true;
	} else if (t == ident_sid("iana-if-type", "ieee8023adLag")) {
		it = "lag";
		enc = "lag-int";
		s->allows_child_saps = true;
	} else if (t == ident_sid("iana-if-type", "l2vlan")) {
		it = "logical";
		q = e->if_ext_encapsulation != NULL ?
		    e->if_ext_encapsulation->if_vlan_dot1q_vlan : NULL;
		enc = q != NULL && q->second_tag != NULL ? "qinq" : "dot1q";
		s->parent_termination_point = e->if_ext_parent_interface;
	} else if (t == ident_sid("iana-if-type", "bridge"))
		it = addressed(e) ? "irb" : "local-bridge";
	else
		return (false);
	s->sap_id = e->name;
	s->attachment_interface = e->name;
	s->interface_type = ident_sid("ietf-sap-ntw", it);
	s->has_interface_type = s->interface_type != 0;
	s->encapsulation_type = ident_sid("ietf-vpn-common", enc);
	s->has_encapsulation_type = s->encapsulation_type != 0;
	s->role = ident_sid("ietf-sap-ntw", "uni");
	s->has_role = s->role != 0;
	return (true);
}

/* "vnet jail name", in a. */
static const char *
in_jail(cbl_yarena *a, const char *name)
{
	char	*p;
	size_t	 len = sizeof("vnet jail ") + strlen(name);

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		snprintf(p, len, "vnet jail %s", name);
	return (p);
}

/* RFC 9181's operational status of an interface's oper-status. */
static uint64_t
oper_of(const yif *e)
{

	if (!e->has_oper_status)
		return (ident_sid("ietf-vpn-common", "op-unknown"));
	switch (e->oper_status) {
	case IETF_INTERFACES_INTERFACES_INTERFACE_OPER_STATUS_UP:
		return (ident_sid("ietf-vpn-common", "op-up"));
	case IETF_INTERFACES_INTERFACES_INTERFACE_OPER_STATUS_TESTING:
	case IETF_INTERFACES_INTERFACES_INTERFACE_OPER_STATUS_UNKNOWN:
		return (ident_sid("ietf-vpn-common", "op-unknown"));
	default:
		return (ident_sid("ietf-vpn-common", "op-down"));
	}
}

int
ysap_network(const struct ietf_interfaces *ifs, const char *host,
    cbl_yarena *a, struct ietf_network *out)
{
	struct ietf_network_networks *nws;
	struct ietf_network_networks_network_network_types *nt;
	struct ietf_network_networks_network_network_types_sap_sap_network *sn;
	const yif	*v;
	ynet		*nw;
	ynode		*nd;
	ytp		*tp;
	ysvc		*svc;
	ysap		*sv;
	ystatus		*st;
	uint64_t	*types;
	size_t		 n, ns;

	memset(out, 0, sizeof(*out));
	n = ifs->interfaces != NULL ? ifs->interfaces->interface.n : 0;
	v = n > 0 ? ifs->interfaces->interface.v : NULL;
	if ((nws = cbl_yarena_alloc(a, sizeof(*nws))) == NULL ||
	    (nw = cbl_yarena_alloc(a, sizeof(*nw))) == NULL ||
	    (nt = cbl_yarena_alloc(a, sizeof(*nt))) == NULL ||
	    (sn = cbl_yarena_alloc(a, sizeof(*sn))) == NULL ||
	    (types = cbl_yarena_alloc(a, sizeof(*types))) == NULL ||
	    (nd = cbl_yarena_alloc(a, sizeof(*nd))) == NULL ||
	    (svc = cbl_yarena_alloc(a, sizeof(*svc))) == NULL ||
	    (tp = cbl_yarena_alloc(a, (n + 1) * sizeof(*tp))) == NULL ||
	    (sv = cbl_yarena_alloc(a, (n + 1) * sizeof(*sv))) == NULL ||
	    (st = cbl_yarena_alloc(a, (n + 1) * sizeof(*st))) == NULL)
		return (ENOMEM);
	memset(nws, 0, sizeof(*nws));
	memset(nw, 0, sizeof(*nw));
	memset(nt, 0, sizeof(*nt));
	memset(sn, 0, sizeof(*sn));
	memset(nd, 0, sizeof(*nd));
	memset(svc, 0, sizeof(*svc));
	memset(tp, 0, (n + 1) * sizeof(*tp));
	memset(sv, 0, (n + 1) * sizeof(*sv));
	memset(st, 0, (n + 1) * sizeof(*st));

	types[0] = ident_sid("ietf-sap-ntw", "sdwan");
	sn->service_type.n = 1;
	sn->service_type.v = types;
	nt->sap_sap_network = sn;
	ns = 0;
	for (size_t i = 0; i < n; i++) {
		tp[i].tp_id = v[i].name;
		if (!sap_of(&v[i], &sv[ns]))
			continue;
		sv[ns].description = v[i].description;
		if (sv[ns].description == NULL && v[i].lne_bind_lne_name !=
		    NULL && (sv[ns].description = in_jail(a,
		    v[i].lne_bind_lne_name)) == NULL)
			return (ENOMEM);
		if (v[i].if_ext_peer_interface != NULL) {
			sv[ns].peer_sap_id.n = 1;
			sv[ns].peer_sap_id.v = &v[i].if_ext_peer_interface;
		} else if (v[i].has_arcif_peer_vnet && v[i].arcif_peer_vnet &&
		    v[i].arcif_driver_name != NULL) {
			/* In another vnet: the listed end of its driver-name. */
			for (size_t k = 0; k < n; k++)
				if (k != i && v[k].arcif_driver_name != NULL &&
				    strcmp(v[k].arcif_driver_name,
				    v[i].arcif_driver_name) == 0) {
					sv[ns].peer_sap_id.n = 1;
					sv[ns].peer_sap_id.v = &v[k].name;
					break;
				}
		}
		st[ns].status = oper_of(&v[i]);
		st[ns].has_status = st[ns].status != 0;
		st[ns].last_change = v[i].last_change;
		sv[ns].sap_status = &st[ns];
		ns++;
	}
	svc->service_type = types[0];
	svc->sap.n = ns;
	svc->sap.v = ns > 0 ? sv : NULL;
	nd->node_id = host;
	nd->nt_termination_point.n = n;
	nd->nt_termination_point.v = n > 0 ? tp : NULL;
	nd->sap_service.n = 1;
	nd->sap_service.v = svc;
	nw->network_id = YSAP_NETWORK;
	nw->network_types = nt;
	nw->node.n = 1;
	nw->node.v = nd;
	nws->network.n = 1;
	nws->network.v = nw;
	out->networks = nws;
	return (0);
}
