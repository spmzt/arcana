/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the standard models served (docs/PLAN-SDN-YANG.md 1.11), by
 * cblink's YANG family, family 1, beside the agent's own: a GET of
 * ietf-interfaces' interfaces, with ietf-ip and what augments them,
 * read as it is asked (yif.c, yip.c), each bound to the network
 * instance of its FIB; of those instances, RFC 8529's, the FIBs named
 * in fibs.conf (yni.c); of the IEEE 802.1AX link aggregations and the
 * 802.1Q bridges the interfaces make; of RFC 8349's routing, the host's
 * FIB's routes as netlink(4) dumps them (yrt.c) and rc.conf's static
 * routes as rc.d/routing installs them (rcroutes.c), and its RIBs'
 * active-route; and of RFC 8530's logical network elements, the vnet
 * jails (ylne.c).  The deprecated routing-state is not kept either.  The
 * deprecated interfaces-state is not kept: NMDA's interfaces holds the
 * same.  Another host asks nothing here, as of the agent's own family
 * (superbia/admit.c).
 */

#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "agent.h"
#include "collect.h"
#include "varconf.h"

/* Where the FIBs' names are: fibs.conf, beside the agent's own files. */
#define	FIBS_CONF	"fibs.conf"

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

/* Another host's certificate: refused, as of the agent's own family. */
bool
yang_refused(cbl_req *req)
{
	const cbl_peer	*p;

	if (!peer_is_host(p = cbl_req_peer(req)))
		return (false);
	logmsg(LOG_WARNING, "%s: a host's certificate asked for a model: "
	    "refused, only the console asks", cbl_peer_subject(p) != NULL ?
	    cbl_peer_subject(p) : "?");
	return (true);
}

/*
 * The FIBs as network instances, their names from fibs.conf; what it
 * has that cannot be read so is logged, the instance fibN meanwhile.
 */
static int
instances(cbl_yarena *a,
    const struct ietf_network_instance_network_instances **out)
{
	struct vc_file	 f;
	struct yunread	*u;
	char		 path[MAXPATHLEN], err[256];
	size_t		 nu, i;
	bool		 have;
	int		 error;

	memset(&f, 0, sizeof(f));
	sdwan_conf_path(FIBS_CONF, path, sizeof(path));
	if (!(have = vc_read(&f, VC_SH, path, err, sizeof(err)) == 0))
		logmsg(LOG_WARNING, "%s: %s", path, err);
	error = yni_read(have ? &f : NULL, yni_nfibs(), a, out, &u, &nu);
	for (i = 0; error == 0 && i < nu; i++)
		logmsg(LOG_WARNING, "%s: %s: %s", path, u[i].var, u[i].why);
	if (have)
		vc_free(&f);
	return (error);
}

int
ietf_interfaces_interfaces_get(cbl_req *req, struct ietf_interfaces *data,
    cbl_yarena *a)
{
	const struct ietf_network_instance_network_instances *ni;
	int	error;

	if (yang_refused(req))
		return (EACCES);
	if ((error = instances(a, &ni)) != 0)
		return (error);
	return (yif_interfaces(data, ni, a));
}

int
ietf_network_instance_network_instances_get(cbl_req *req,
    struct ietf_network_instance *data, cbl_yarena *a)
{
	const struct ietf_network_instance_network_instances *ni;
	int	error;

	if (yang_refused(req))
		return (EACCES);
	if ((error = instances(a, &ni)) != 0)
		return (error);
	/* None but the host's FIB 0: no instance, no container. */
	if (ni->network_instance.n > 0)
		data->network_instances = ni;
	return (0);
}

/* Deprecated, and NMDA's interfaces says it all: not there. */
int
ietf_interfaces_interfaces_state_get(cbl_req *req,
    struct ietf_interfaces *data, cbl_yarena *a)
{

	(void)data;
	(void)a;
	if (yang_refused(req))
		return (EACCES);
	return (0);
}

int
ieee802_dot1ax_linkagg_linkagg_get(cbl_req *req,
    struct ieee802_dot1ax_linkagg *data, cbl_yarena *a)
{
	struct ietf_interfaces	 ifs;
	int			 error;

	if (yang_refused(req))
		return (EACCES);
	memset(&ifs, 0, sizeof(ifs));
	if ((error = yif_interfaces(&ifs, NULL, a)) != 0)
		return (error);
	if (ifs.interfaces == NULL)
		return (0);
	return (yif_linkagg(ifs.interfaces->interface.v,
	    ifs.interfaces->interface.n, a, data));
}

int
ieee802_dot1q_bridge_bridges_get(cbl_req *req,
    struct ieee802_dot1q_bridge *data, cbl_yarena *a)
{
	struct ietf_interfaces	 ifs;
	int			 error;

	if (yang_refused(req))
		return (EACCES);
	memset(&ifs, 0, sizeof(ifs));
	if ((error = yif_interfaces(&ifs, NULL, a)) != 0)
		return (error);
	if (ifs.interfaces == NULL)
		return (0);
	return (yif_bridges(ifs.interfaces->interface.v,
	    ifs.interfaces->interface.n, a, data));
}

/*
 * Changes go by the agent's jobs still: an EDIT, or the RSTP's
 * protocol-migration-check, is not supported here yet (cblink says
 * operation-not-supported).
 */
int
ietf_interfaces_interfaces_edit(cbl_req *req,
    const struct ietf_interfaces *before, const struct ietf_interfaces *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

/*
 * FIB 0's static routes, as rc.d/routing installs them from the files
 * rc(8) reads for it; what they have that the model cannot hold is
 * logged.  NULL with none.
 */
static int
statics(cbl_yarena *a,
    const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes **out)
{
	struct vc_file	*f;
	struct yunread	*u;
	char		**paths, err[256];
	size_t		 n, i, nu;
	int		 error;

	*out = NULL;
	if (vc_rc_files("", "/usr/local", "routing", "arcana", &paths, &n, err,
	    sizeof(err)) != 0) {
		logmsg(LOG_WARNING, "static routes: %s", err);
		return (0);
	}
	if ((f = calloc(n > 0 ? n : 1, sizeof(*f))) == NULL) {
		vc_rc_files_free(paths, n);
		return (ENOMEM);
	}
	for (i = 0; i < n; i++)
		if (vc_read(&f[i], VC_SH, paths[i], err, sizeof(err)) != 0)
			logmsg(LOG_WARNING, "%s: %s", paths[i], err);
	u = NULL;
	nu = 0;
	error = rcr_read(f, n, 0, a, out, &u, &nu);
	for (i = 0; error == 0 && i < nu; i++)
		logmsg(LOG_WARNING, "static routes: %s: %s", u[i].var,
		    u[i].why);
	free(u);
	for (i = 0; i < n; i++)
		vc_free(&f[i]);
	free(f);
	vc_rc_files_free(paths, n);
	return (error);
}

int
ietf_routing_routing_get(cbl_req *req, struct ietf_routing *data,
    cbl_yarena *a)
{
	const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes *sr;
	struct ietf_routing_routing				*rt;
	struct ietf_routing_routing_control_plane_protocols	*cpp;
	struct ietf_routing_routing_control_plane_protocols_control_plane_protocol *p;
	int	error;

	if (yang_refused(req))
		return (EACCES);
	if ((error = yrt_routing(data, 0, a)) != 0 ||
	    (error = statics(a, &sr)) != 0)
		return (error);
	if (sr == NULL || data->routing == NULL)
		return (0);
	/* The static routes as the one protocol instance rc(8) is. */
	if ((rt = cbl_yarena_alloc(a, sizeof(*rt))) == NULL ||
	    (cpp = cbl_yarena_alloc(a, sizeof(*cpp))) == NULL ||
	    (p = cbl_yarena_alloc(a, sizeof(*p))) == NULL)
		return (ENOMEM);
	memcpy(rt, data->routing, sizeof(*rt));
	memset(cpp, 0, sizeof(*cpp));
	memset(p, 0, sizeof(*p));
	p->type = ident_sid("ietf-routing", "static");
	p->name = "rc.conf";
	p->description = "static_routes and ipv6_static_routes, as "
	    "rc.d/routing installs them";
	p->static_routes = sr;
	cpp->control_plane_protocol.n = 1;
	cpp->control_plane_protocol.v = p;
	rt->control_plane_protocols = cpp;
	data->routing = rt;
	return (0);
}

/* Deprecated, and NMDA's routing says it all: not there. */
int
ietf_routing_routing_state_get(cbl_req *req, struct ietf_routing *data,
    cbl_yarena *a)
{

	(void)data;
	(void)a;
	if (yang_refused(req))
		return (EACCES);
	return (0);
}

/* The route an address goes by, in the host's FIB. */
int
ietf_routing_routing_ribs_rib_active_route_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct ietf_routing_routing_ribs_rib_active_route_input *in,
    struct ietf_routing_routing_ribs_rib_active_route_output *out,
    cbl_yarena *a)
{

	(void)target;
	if (yang_refused(req))
		return (EACCES);
	return (yrt_active_route(0, in, a, out));
}

int
ietf_routing_routing_state_ribs_rib_active_route_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct ietf_routing_routing_state_ribs_rib_active_route_input *in,
    struct ietf_routing_routing_state_ribs_rib_active_route_output *out,
    cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
ietf_logical_network_element_logical_network_elements_get(cbl_req *req,
    struct ietf_logical_network_element *data, cbl_yarena *a)
{
	const struct ietf_logical_network_element_logical_network_elements *l;
	int	error;

	if (yang_refused(req))
		return (EACCES);
	if ((error = ylne_elements(a, &l)) != 0)
		return (error);
	if (l != NULL && l->logical_network_element.n > 0)
		data->logical_network_elements = l;
	return (0);
}

int
ietf_routing_routing_edit(cbl_req *req, const struct ietf_routing *before,
    const struct ietf_routing *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
ietf_logical_network_element_logical_network_elements_edit(cbl_req *req,
    const struct ietf_logical_network_element *before,
    const struct ietf_logical_network_element *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
ietf_network_instance_network_instances_edit(cbl_req *req,
    const struct ietf_network_instance *before,
    const struct ietf_network_instance *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
ieee802_dot1ax_linkagg_linkagg_edit(cbl_req *req,
    const struct ieee802_dot1ax_linkagg *before,
    const struct ieee802_dot1ax_linkagg *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
ieee802_dot1q_bridge_bridges_edit(cbl_req *req,
    const struct ieee802_dot1q_bridge *before,
    const struct ieee802_dot1q_bridge *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
ietf_interfaces_interfaces_interface_dot1q_bridge_port_rstp_bridge_rstp_port_protocol_migration_check_action(
    cbl_req *req, const struct cbl_bytes *target,
    const struct ietf_interfaces_interfaces_interface_dot1q_bridge_port_rstp_bridge_rstp_port_protocol_migration_check_input *in,
    struct ietf_interfaces_interfaces_interface_dot1q_bridge_port_rstp_bridge_rstp_port_protocol_migration_check_output *out,
    cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

/* The models served, family 1 beside the agent's own. */
int
yang_serve(cbl_ctx *ctx)
{
	int	error;

	/* Each request on a thread of its own: a read of the storage or of
	 * BIRD holds no other, as the agent's own family's slow reads. */
	if ((error = cbl_yserver_add(ctx, &ymodel_server, NULL)) != 0)
		return (error);
	return (cbl_yserver_threads(ctx, true));
}
