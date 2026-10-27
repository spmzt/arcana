/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the standard models served, by
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
#include <ucl.h>
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

	(void)target;
	(void)in;
	(void)out;
	(void)a;
	(void)cbl_req_set_yerr(req, "routing-state is not served: ask "
	    "/routing/ribs/rib/active-route", 0);
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

/*
 * RFC 8525's YANG library: one module set of every module the tables
 * implement, with the features they have on, and those imported only
 * (ARC_YIMPORT_LIST, the build's); one schema of it; the operational
 * datastore's, the only one served.  Its content-id changes
 * with what the set has (FNV-1a of its words).
 */
int
ietf_yang_library_yang_library_get(cbl_req *req, struct ietf_yang_library *data,
    cbl_yarena *a)
{
	struct ietf_yang_library_yang_library			*yl;
	struct ietf_yang_library_yang_library_module_set	*ms;
	struct ietf_yang_library_yang_library_module_set_module *mv;
	struct ietf_yang_library_yang_library_module_set_import_only_module *iv;
	struct ietf_yang_library_yang_library_schema		*sc;
	struct ietf_yang_library_yang_library_datastore	*ds;
	const struct cbl_ymodule				*m;
	const char						**fv, **sets;
	char							*imports, *s, *w,
								*at, id[24];
	uint64_t						 h;
	size_t							 ni, nf, k;
	uint32_t						 i, j;

	if (yang_refused(req))
		return (EACCES);
	if ((yl = cbl_yarena_alloc(a, sizeof(*yl))) == NULL ||
	    (ms = cbl_yarena_alloc(a, sizeof(*ms))) == NULL ||
	    (sc = cbl_yarena_alloc(a, sizeof(*sc))) == NULL ||
	    (ds = cbl_yarena_alloc(a, sizeof(*ds))) == NULL ||
	    (sets = cbl_yarena_alloc(a, sizeof(*sets))) == NULL ||
	    (mv = cbl_yarena_alloc(a, (ymodel_schema.nmod + 1) *
	    sizeof(*mv))) == NULL)
		return (ENOMEM);
	h = UINT64_C(0xcbf29ce484222325);
#define	FNV(s)	do {							\
	for (const char *p_ = (s); p_ != NULL && *p_ != '\0'; p_++)	\
		h = (h ^ (uint8_t)*p_) * UINT64_C(0x100000001b3);	\
	h = (h ^ ' ') * UINT64_C(0x100000001b3);			\
} while (0)
	for (i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		mv[i].name = m->name;
		mv[i].revision = m->revision;
		mv[i].namespace = m->ns;
		FNV(m->name);
		FNV(m->revision);
		for (j = nf = 0; j < m->nfeature; j++)
			nf += m->feature[j].enabled;
		if (nf > 0 && (fv = cbl_yarena_alloc(a, nf * sizeof(*fv))) ==
		    NULL)
			return (ENOMEM);
		for (j = k = 0; j < m->nfeature; j++)
			if (m->feature[j].enabled) {
				fv[k++] = m->feature[j].name;
				FNV(m->feature[j].name);
			}
		mv[i].feature.n = nf;
		mv[i].feature.v = nf > 0 ? fv : NULL;
	}
	/* name@revision, by commas. */
	if ((imports = cbl_yarena_alloc(a, sizeof(ARC_YIMPORT_LIST))) == NULL)
		return (ENOMEM);
	memcpy(imports, ARC_YIMPORT_LIST, sizeof(ARC_YIMPORT_LIST));
	for (ni = 1, s = imports; *s != '\0'; s++)
		ni += *s == ',';
	if ((iv = cbl_yarena_alloc(a, ni * sizeof(*iv))) == NULL)
		return (ENOMEM);
	for (ni = 0, s = imports; (w = strsep(&s, ",")) != NULL;) {
		if (w[0] == '\0')
			continue;
		if ((at = strchr(w, '@')) != NULL)
			*at++ = '\0';
		iv[ni].name = w;
		/* A revision-identifier, or the empty string. */
		iv[ni].revision.which = at != NULL ? 0 : 1;
		iv[ni].revision.v.m0 = at != NULL ? at : "";
		/* Its namespace, by an identity of it the tables have. */
		for (j = 0; j < ymodel_schema.nident; j++)
			if (strcmp(ymodel_schema.ident[j].module->name, w) ==
			    0) {
				iv[ni].namespace =
				    ymodel_schema.ident[j].module->ns;
				break;
			}
		ni++;
		FNV(w);
		FNV(at);
	}
#undef	FNV
	ms->name = "arcana-agent";
	ms->module.n = ymodel_schema.nmod;
	ms->module.v = mv;
	ms->import_only_module.n = ni;
	ms->import_only_module.v = ni > 0 ? iv : NULL;
	sets[0] = ms->name;
	sc->name = "arcana-agent";
	sc->module_set.n = 1;
	sc->module_set.v = sets;
	ds->name = ident_sid("ietf-datastores", "operational");
	ds->schema = sc->name;
	yl->module_set.n = 1;
	yl->module_set.v = ms;
	yl->schema.n = 1;
	yl->schema.v = sc;
	yl->datastore.n = 1;
	yl->datastore.v = ds;
	snprintf(id, sizeof(id), "%016jx", (uintmax_t)h);
	if ((yl->content_id = cbl_yarena_alloc(a, strlen(id) + 1)) == NULL)
		return (ENOMEM);
	memcpy((char *)(uintptr_t)yl->content_id, id, strlen(id) + 1);
	data->yang_library = yl;
	return (0);
}

/* Deprecated, and yang-library says it all: not there. */
int
ietf_yang_library_modules_state_get(cbl_req *req, struct ietf_yang_library *data,
    cbl_yarena *a)
{

	(void)data;
	(void)a;
	return (yang_refused(req) ? EACCES : 0);
}

/* RFC 8348's hardware: the chassis, CPUs and disks (superbia/yhw.c). */
int
ietf_hardware_hardware_get(cbl_req *req, struct ietf_hardware *data,
    cbl_yarena *a)
{
	char	*json;
	int	 error;

	if (yang_refused(req))
		return (EACCES);
	if ((error = yhw_json(&json)) != 0)
		return (error);
	error = yhw_from_json(json, a, data);
	free(json);
	return (error);
}

/* Its configuration (alias, asset-id, uri) is not kept. */
int
ietf_hardware_hardware_edit(cbl_req *req, const struct ietf_hardware *before,
    const struct ietf_hardware *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

/* RFC 8632's alarms: the agent's faults (gula/yalarms.c). */
int
ietf_alarms_alarms_get(cbl_req *req, struct ietf_alarms *data, cbl_yarena *a)
{
	ucl_object_t	*top;
	char		*json;
	int		 error;

	if (yang_refused(req))
		return (EACCES);
	top = ucl_object_typed_new(UCL_OBJECT);
	faults_json(top);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL)
		return (ENOMEM);
	error = yalarms_from_json(json, a, data);
	free(json);
	return (error);
}

/* Its control is configuration, and purging and compressing operator
 * actions: neither served. */
int
ietf_alarms_alarms_edit(cbl_req *req, const struct ietf_alarms *before,
    const struct ietf_alarms *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

/* An alarm type's name in arcana-alarms, by its SID; NULL: none. */
static const char *
ident_name(uint64_t sid)
{
	const struct cbl_yident	*id;
	uint32_t		 i;

	for (i = 0; i < ymodel_schema.nident; i++) {
		id = &ymodel_schema.ident[i];
		if (id->sid == sid && strcmp(id->module->name,
		    "arcana-alarms") == 0)
			return (id->name);
	}
	return (NULL);
}

/* purge-alarms on the faults: how many went in *np. */
static int
alarms_purge(const struct ietf_alarms_alarms_alarm_list_purge_alarms_input
    *in, uint32_t *np)
{
	const struct ietf_alarms_alarms_alarm_list_purge_alarms_input_older_than
	    *o = in->older_than;
	const struct ietf_alarms_alarms_alarm_list_purge_alarms_input_severity
	    *s = in->severity;
	time_t	before = 0;
	int	clearance = 0, sevop = 0, sev = 0;

	if (in->has_alarm_clearance_status)
		clearance = in->alarm_clearance_status ==
		    IETF_ALARMS_ALARMS_ALARM_LIST_PURGE_ALARMS_INPUT_ALARM_CLEARANCE_STATUS_CLEARED ?
		    1 : in->alarm_clearance_status ==
		    IETF_ALARMS_ALARMS_ALARM_LIST_PURGE_ALARMS_INPUT_ALARM_CLEARANCE_STATUS_NOT_CLEARED ?
		    2 : 0;
	if (o != NULL) {
		/* In time_t: 25000 days of seconds are past an int. */
		time_t	age = o->has_seconds ? (time_t)o->seconds :
		    o->has_minutes ? (time_t)o->minutes * 60 : o->has_hours ?
		    (time_t)o->hours * 3600 : o->has_days ? (time_t)o->days *
		    86400 : o->has_weeks ? (time_t)o->weeks * 7 * 86400 : 0;

		before = time(NULL) - age;
	}
	if (s != NULL) {
		/* The three are one enumeration, the same values. */
		if (s->has_below) {
			sevop = -1;
			sev = (int)s->below;
		} else if (s->has_is)
			sev = (int)s->is;
		else if (s->has_above) {
			sevop = 1;
			sev = (int)s->above;
		}
	}
	*np = (uint32_t)faults_purge(clearance, before, sevop, sev);
	return (0);
}

/* compress-alarms on the faults: how many in *np. */
static int
alarms_compress(
    const struct ietf_alarms_alarms_alarm_list_compress_alarms_input *in,
    uint32_t *np)
{
	const char	*object = NULL, *type = NULL;

	/* Only the string member is ever a fault's resource. */
	if (in->has_resource) {
		if (in->resource.which != 2) {
			*np = 0;
			return (0);
		}
		object = in->resource.v.m2;
	}
	if (in->has_alarm_type_id && (type = ident_name(in->alarm_type_id)) ==
	    NULL) {
		*np = 0;
		return (0);
	}
	/* No fault has a qualifier: one asked for matches none. */
	if (in->alarm_type_qualifier != NULL &&
	    in->alarm_type_qualifier[0] != '\0') {
		*np = 0;
		return (0);
	}
	*np = (uint32_t)faults_compress(object, type);
	return (0);
}

int
ietf_alarms_alarms_alarm_list_purge_alarms_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct ietf_alarms_alarms_alarm_list_purge_alarms_input *in,
    struct ietf_alarms_alarms_alarm_list_purge_alarms_output *out,
    cbl_yarena *a)
{

	(void)target;
	(void)a;
	if (yang_refused(req))
		return (EACCES);
	out->has_purged_alarms = true;
	return (alarms_purge(in, &out->purged_alarms));
}

int
ietf_alarms_alarms_alarm_list_compress_alarms_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct ietf_alarms_alarms_alarm_list_compress_alarms_input *in,
    struct ietf_alarms_alarms_alarm_list_compress_alarms_output *out,
    cbl_yarena *a)
{

	(void)target;
	(void)a;
	if (yang_refused(req))
		return (EACCES);
	out->has_compressed_alarms = true;
	return (alarms_compress(in, &out->compressed_alarms));
}

/* The context the models are served on, for their notifications. */
static cbl_ctx		*yctx;

/* A module's top-level node of that name, in the tables. */
static const struct cbl_ynode *
ynode_named(const char *mod, const char *name)
{
	const struct cbl_ymodule	*m;
	uint32_t			 i, j;

	for (i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, mod) != 0)
			continue;
		for (j = 0; j < m->ntop; j++)
			if (strcmp(m->top[j]->name, name) == 0)
				return (m->top[j]);
	}
	return (NULL);
}

/* yang:date-and-time of t, in the arena. */
static const char *
ytime(cbl_yarena *a, time_t t)
{
	struct tm	 tm;
	char		 buf[32], *p;

	if (gmtime_r(&t, &tm) == NULL)
		return (NULL);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
	if ((p = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL)
		memcpy(p, buf, strlen(buf) + 1);
	return (p);
}

/*
 * A stream subscription's replay: the events kept since from, each as
 * its arcana-events:event at its time; the subscription live before the
 * event ring's lock is let go, so that none is lost or told twice.
 */
static void
yreplay_one(const char *json, time_t t, void *arg)
{
	struct cbl_ysub_replay		*r = arg;
	struct arcana_events_event	 ev;
	struct timespec			 ts = { t, 0 };
	cbl_yarena			*a;

	if ((a = cbl_yarena_new()) == NULL)
		return;
	memset(&ev, 0, sizeof(ev));
	if (yev_one_from_json(json, a, &ev) == 0)
		(void)cbl_ysub_replay_emit(r, ynode_named("arcana-events",
		    "event"), &ev, &ts);
	cbl_yarena_free(a);
}

static void
yreplay_live(void *arg)
{

	cbl_ysub_replay_live(arg);
}

static int
yreplay(const struct timespec *from, struct cbl_ysub_replay *r, void *arg)
{
	struct timespec	 ts;
	time_t		 since, oldest;
	bool		 aged;

	(void)arg;
	events_replay(from->tv_sec, yreplay_one, yreplay_live, r, &since,
	    &oldest, &aged);
	ts.tv_sec = oldest != 0 ? oldest : time(NULL);
	ts.tv_nsec = 0;
	cbl_ysub_replay_oldest(r, &ts);
	return (0);
}

/*
 * RFC 8639's subscriptions and RFC 8641's YANG-Push: cblink keeps them
 * (cbl_ysub.c), each a SUBSCRIBE stream; establish-subscription is that
 * stream's open, not an rpc.  The NETCONF stream is every event the
 * agent tells (yang_event()).
 */
typedef struct ietf_subscribed_notifications_subscriptions_subscription
    ysubscription;
#define	YSUB(x)	IETF_SUBSCRIBED_NOTIFICATIONS_SUBSCRIPTIONS_SUBSCRIPTION_##x

int
ietf_subscribed_notifications_streams_get(cbl_req *req,
    struct ietf_subscribed_notifications *data, cbl_yarena *a)
{
	struct ietf_subscribed_notifications_streams		*st;
	struct ietf_subscribed_notifications_streams_stream	*v;

	if (yang_refused(req))
		return (EACCES);
	if ((st = cbl_yarena_alloc(a, sizeof(*st))) == NULL ||
	    (v = cbl_yarena_alloc(a, sizeof(*v))) == NULL)
		return (ENOMEM);
	v->name = "NETCONF";
	v->description = "every event the agent tells: arcana-events' event "
	    "notifications";
	/* Replayed from the events kept (gula/events.c). */
	{
		time_t	 since, oldest;
		bool	 aged;

		events_replay(time(NULL) + 1, NULL, NULL, NULL, &since,
		    &oldest, &aged);
		v->replay_support = true;
		v->replay_log_creation_time = ytime(a, since);
		if (aged && oldest != 0)
			v->replay_log_aged_time = ytime(a, oldest);
	}
	st->stream.n = 1;
	st->stream.v = v;
	data->streams = st;
	return (0);
}

/* No filters are kept: a subscription carries its own. */
int
ietf_subscribed_notifications_filters_get(cbl_req *req,
    struct ietf_subscribed_notifications *data, cbl_yarena *a)
{

	(void)data;
	(void)a;
	return (yang_refused(req) ? EACCES : 0);
}

int
ietf_subscribed_notifications_filters_edit(cbl_req *req,
    const struct ietf_subscribed_notifications *before,
    const struct ietf_subscribed_notifications *after)
{

	(void)before;
	(void)after;
	(void)cbl_req_set_yerr(req, "no filters are kept: a subscription "
	    "carries its own", 0);
	return (EOPNOTSUPP);
}

struct ysubs {
	cbl_yarena	*a;
	ysubscription	*v;
	size_t		 n, cap;
};

static const char *
ystr(cbl_yarena *a, const char *s)
{
	char	*p;

	if (s == NULL || (p = cbl_yarena_alloc(a, strlen(s) + 1)) == NULL)
		return (NULL);
	memcpy(p, s, strlen(s) + 1);
	return (p);
}

/* One of cblink's subscriptions, copied into the arena. */
static int
ysub_one(const struct cbl_ysub_info *in, void *arg)
{
	struct ietf_subscribed_notifications_subscriptions_subscription_receivers
	    *rs;
	struct ietf_subscribed_notifications_subscriptions_subscription_receivers_receiver
	    *r;
	struct ietf_subscribed_notifications_subscriptions_subscription_yp_periodic
	    *per;
	struct ietf_subscribed_notifications_subscriptions_subscription_yp_on_change
	    *oc;
	struct ysubs	*ys = arg;
	ysubscription	*v, *s;

	if (ys->n == ys->cap) {
		if ((v = cbl_yarena_alloc(ys->a, (ys->cap + 8) *
		    sizeof(*v))) == NULL)
			return (ENOMEM);
		if (ys->n > 0)
			memcpy(v, ys->v, ys->n * sizeof(*v));
		ys->v = v;
		ys->cap += 8;
	}
	s = &ys->v[ys->n];
	memset(s, 0, sizeof(*s));
	if ((rs = cbl_yarena_alloc(ys->a, sizeof(*rs))) == NULL ||
	    (r = cbl_yarena_alloc(ys->a, sizeof(*r))) == NULL)
		return (ENOMEM);
	s->id = in->id;
	if (in->stream != NULL) {
		s->target = YSUB(TARGET_STREAM);
		s->stream = ystr(ys->a, in->stream);
		if (in->xpath != NULL) {
			s->stream_filter =
			    YSUB(STREAM_FILTER_WITHIN_SUBSCRIPTION);
			s->filter_spec = YSUB(FILTER_SPEC_STREAM_XPATH_FILTER);
			s->stream_xpath_filter = ystr(ys->a, in->xpath);
		}
	} else {
		s->target = YSUB(TARGET_DATASTORE);
		s->has_yp_datastore = true;
		s->yp_datastore = in->datastore;
		if (in->xpath != NULL) {
			s->yp_selection_filter =
			    YSUB(YP_SELECTION_FILTER_WITHIN_SUBSCRIPTION);
			s->yp_filter_spec =
			    YSUB(YP_FILTER_SPEC_DATASTORE_XPATH_FILTER);
			s->yp_datastore_xpath_filter = ystr(ys->a, in->xpath);
		}
		if (in->on_change) {
			if ((oc = cbl_yarena_alloc(ys->a, sizeof(*oc))) ==
			    NULL)
				return (ENOMEM);
			memset(oc, 0, sizeof(*oc));
			oc->has_dampening_period = true;
			oc->dampening_period = in->dampening;
			s->yp_update_trigger = YSUB(YP_UPDATE_TRIGGER_ON_CHANGE);
			s->yp_on_change = oc;
		} else {
			if ((per = cbl_yarena_alloc(ys->a, sizeof(*per))) ==
			    NULL)
				return (ENOMEM);
			per->has_period = true;
			per->period = in->period;
			per->anchor_time = ystr(ys->a, in->anchor_time);
			s->yp_update_trigger = YSUB(YP_UPDATE_TRIGGER_PERIODIC);
			s->yp_periodic = per;
		}
	}
	s->stop_time = ystr(ys->a, in->stop_time);
	r->name = in->receiver != NULL ? ystr(ys->a, in->receiver) :
	    "the subscriber";
	r->has_sent_event_records = true;
	r->sent_event_records = in->sent;
	r->has_excluded_event_records = true;
	r->excluded_event_records = in->excluded;
	r->has_state = true;
	r->state = in->suspended ? YSUB(RECEIVERS_RECEIVER_STATE_SUSPENDED) :
	    YSUB(RECEIVERS_RECEIVER_STATE_ACTIVE);
	rs->receiver.n = 1;
	rs->receiver.v = r;
	s->receivers = rs;
	ys->n++;
	return (0);
}

int
ietf_subscribed_notifications_subscriptions_get(cbl_req *req,
    struct ietf_subscribed_notifications *data, cbl_yarena *a)
{
	struct ietf_subscribed_notifications_subscriptions	*ss;
	struct ysubs						 ys;
	int							 error;

	if (yang_refused(req))
		return (EACCES);
	memset(&ys, 0, sizeof(ys));
	ys.a = a;
	if (yctx != NULL && (error = cbl_ysub_each(yctx, ysub_one, &ys)) != 0)
		return (error);
	if (ys.n == 0)
		return (0);
	if ((ss = cbl_yarena_alloc(a, sizeof(*ss))) == NULL)
		return (ENOMEM);
	ss->subscription.n = ys.n;
	ss->subscription.v = ys.v;
	data->subscriptions = ss;
	return (0);
}

/* Configured subscriptions are not made: dynamic ones alone. */
int
ietf_subscribed_notifications_subscriptions_edit(cbl_req *req,
    const struct ietf_subscribed_notifications *before,
    const struct ietf_subscribed_notifications *after)
{

	(void)before;
	(void)after;
	(void)cbl_req_set_yerr(req, "configured subscriptions are not "
	    "made: a subscription is a SUBSCRIBE stream", 0);
	return (EOPNOTSUPP);
}

int
ietf_subscribed_notifications_establish_subscription_rpc(cbl_req *req,
    const struct ietf_subscribed_notifications_establish_subscription_input
    *in,
    struct ietf_subscribed_notifications_establish_subscription_output *out,
    cbl_yarena *a)
{

	(void)in;
	(void)out;
	(void)a;
	(void)cbl_req_set_yerr(req, "a subscription is established by "
	    "opening a SUBSCRIBE stream (family 1, command 6), its records "
	    "on it", 0);
	return (EOPNOTSUPP);
}

/* The filter, stop-time or period of one's own subscription: cblink's. */
int
ietf_subscribed_notifications_modify_subscription_rpc(cbl_req *req,
    const struct ietf_subscribed_notifications_modify_subscription_input *in,
    struct ietf_subscribed_notifications_modify_subscription_output *out,
    cbl_yarena *a)
{

	(void)out;
	(void)a;
	if (yang_refused(req))
		return (EACCES);
	return (cbl_ysub_modify(req, in));
}

/* An on-change subscription's whole contents pushed again. */
int
ietf_yang_push_resync_subscription_rpc(cbl_req *req,
    const struct ietf_yang_push_resync_subscription_input *in,
    struct ietf_yang_push_resync_subscription_output *out, cbl_yarena *a)
{

	(void)out;
	(void)a;
	if (yang_refused(req))
		return (EACCES);
	return (cbl_ysub_resync(req, in->id));
}

/* The subscriber's own, on this connection. */
int
ietf_subscribed_notifications_delete_subscription_rpc(cbl_req *req,
    const struct ietf_subscribed_notifications_delete_subscription_input *in,
    struct ietf_subscribed_notifications_delete_subscription_output *out,
    cbl_yarena *a)
{

	(void)out;
	(void)a;
	if (yang_refused(req))
		return (EACCES);
	if (cbl_ysub_delete(req, in->id) != 0) {
		(void)cbl_req_set_yerr(req, "no such subscription of this "
		    "connection", 0);
		return (ENOENT);
	}
	return (0);
}

/* Any one: the console's to do. */
int
ietf_subscribed_notifications_kill_subscription_rpc(cbl_req *req,
    const struct ietf_subscribed_notifications_kill_subscription_input *in,
    struct ietf_subscribed_notifications_kill_subscription_output *out,
    cbl_yarena *a)
{

	(void)out;
	(void)a;
	if (yang_refused(req))
		return (EACCES);
	if (yctx == NULL || cbl_ysub_kill(yctx, in->id) != 0) {
		(void)cbl_req_set_yerr(req, "no such subscription", 0);
		return (ENOENT);
	}
	return (0);
}

/*
 * An event (gula/events.c's JSON of it, as the agent's own family tells
 * it) told as arcana-events' event notification too, to the subscribers
 * of family 1's group: nobody subscribed, no work (cblink's).
 */
void
yang_event(const char *json)
{
	struct arcana_events_event	 ev;
	cbl_yarena			*a;

	if (yctx == NULL || (a = cbl_yarena_new()) == NULL)
		return;
	memset(&ev, 0, sizeof(ev));
	if (yev_one_from_json(json, a, &ev) == 0)
		(void)arcana_events_event_notify(yctx, &ev);
	cbl_yarena_free(a);
}

/*
 * What the agent tells the changes of, so that an on-change subscription
 * of them is read when told and not every period: the events, each
 * added (events.c); the alarms, each fault set, cleared, said anew,
 * purged or compressed (faults.c).  A fault older than a day goes with
 * the next of those.
 */
void
yang_changed(int what)
{
	static const char *const tops[][2] = {
		[YANG_EVENTS] = { "arcana-events", "events" },
		[YANG_ALARMS] = { "ietf-alarms", "alarms" },
	};
	const struct cbl_ynode	*n;

	if (yctx != NULL && what >= 0 && what < (int)nitems(tops) &&
	    (n = ynode_named(tops[what][0], tops[what][1])) != NULL)
		cbl_ysub_changed(yctx, n);
}

/* The models served, family 1 beside the agent's own. */
int
yang_serve(cbl_ctx *ctx)
{
	const struct cbl_ynode	*told[2];
	int			 error;

	/* Each request on a thread of its own: a read of the storage or of
	 * BIRD holds no other, as the agent's own family's slow reads. */
	if ((error = cbl_yserver_add(ctx, &ymodel_server, NULL)) != 0)
		return (error);
	yctx = ctx;
	(void)cbl_ysub_set_replay(ctx, yreplay, NULL);
	if ((told[0] = ynode_named("arcana-events", "events")) != NULL &&
	    (told[1] = ynode_named("ietf-alarms", "alarms")) != NULL)
		(void)cbl_ysub_told(ctx, told, nitems(told));
	return (cbl_yserver_threads(ctx, true));
}
