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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>

#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

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

/*
 * The FIBs as network instances, their names from fibs.conf; what it
 * has that cannot be read so is logged, the instance fibN meanwhile.
 */
int
yni_instances(cbl_yarena *a,
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

	if ((error = yni_instances(a, &ni)) != 0 ||
	    (error = yif_interfaces(data, ni, a)) != 0)
		return (error);
	/* Their router advertisements, rtadvd.conf's (RFC 8349). */
	if ((error = yif_rtadv(data, a)) != 0)
		return (error);
	/* Running: what was configured, not what DHCP or SLAAC made. */
	if (cbl_req_ydatastore(req) == CBL_YDS_RUNNING &&
	    (error = yif_running(data, a)) != 0)
		return (error);
	/* Those in the vnet jails, each bound to its jail (RFC 8530). */
	return (lne_bound_interfaces(data, a));
}

static int	routing_of(cbl_yarena *, int, struct ietf_routing *);

/* The mount point vrf-root of a network instance (RFC 8529, 8528). */
static const struct cbl_ynode *
vrf_root(void)
{
	static const struct cbl_ynode *n;
	const struct cbl_ynode *c;

	if (n != NULL)
		return (n);
	c = ynode_named("ietf-network-instance", "network-instances");
	for (int depth = 0; c != NULL && depth < 2; depth++) {
		const char *want = depth == 0 ? "network-instance" : "vrf-root";
		const struct cbl_ynode *k = NULL;

		for (uint32_t i = 0; i < c->nchild && k == NULL; i++)
			if (strcmp(c->child[i]->name, want) == 0)
				k = c->child[i];
		c = k;
	}
	return (n = c);
}

/*
 * Each instance's vrf-root, mounted: its FIB's routing (ietf-routing,
 * the v4ur and v6ur augments with it), a shared schema, and the YANG
 * library that says it (RFC 8528 section 3), the host's own.
 */
static int
vrf_mounts(cbl_yarena *a,
    const struct ietf_network_instance_network_instances *ni)
{
	struct ietf_network_instance_network_instances_network_instance *v;
	struct ietf_network_instance_network_instances_network_instance_vrf_root *r;
	struct ietf_yang_library *yl;
	struct ietf_routing *rt;
	const struct cbl_ynode *n = vrf_root();
	int error;

	if (n == NULL || ni == NULL || ni->network_instance.n == 0)
		return (0);
	/* The list is the read's own, in a: filled in place. */
	v = (struct ietf_network_instance_network_instances_network_instance *)
	    (uintptr_t)ni->network_instance.v;
	for (size_t i = 0; i < ni->network_instance.n; i++) {
		if (!v[i].has_arcni_fib)
			continue;
		if ((r = cbl_yarena_alloc(a, sizeof(*r))) == NULL)
			return (ENOMEM);
		memset(r, 0, sizeof(*r));
		if ((rt = cbl_ymount_data(n, r, ynode_named("ietf-routing",
		    "routing")->module, a)) == NULL)
			return (ENOMEM);
		if ((error = routing_of(a, (int)v[i].arcni_fib, rt)) != 0)
			return (error);
		if ((yl = cbl_ymount_data(n, r, ynode_named("ietf-yang-library",
		    "yang-library")->module, a)) == NULL)
			return (ENOMEM);
		if ((error = ietf_yang_library_yang_library_get(NULL, yl,
		    a)) != 0)
			return (error);
		v[i].vrf_root = r;
	}
	return (0);
}

int
ietf_network_instance_network_instances_get(cbl_req *req,
    struct ietf_network_instance *data, cbl_yarena *a)
{
	const struct ietf_network_instance_network_instances *ni;
	int	error;

	(void)req;
	if ((error = yni_instances(a, &ni)) != 0 ||
	    (error = vrf_mounts(a, ni)) != 0)
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

	(void)req;
	(void)data;
	(void)a;
	return (0);
}

int
ieee802_dot1ax_linkagg_linkagg_get(cbl_req *req,
    struct ieee802_dot1ax_linkagg *data, cbl_yarena *a)
{
	struct ietf_interfaces	 ifs;
	int			 error;

	(void)req;
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

	(void)req;
	memset(&ifs, 0, sizeof(ifs));
	if ((error = yif_interfaces(&ifs, NULL, a)) != 0)
		return (error);
	if (ifs.interfaces == NULL)
		return (0);
	return (yif_bridges(ifs.interfaces->interface.v,
	    ifs.interfaces->interface.n, a, data));
}

/*
 * FIB 0's static routes, as rc.d/routing installs them from the files
 * rc(8) reads for it; what they have that the model cannot hold is
 * logged.  NULL with none.
 */
static int
statics(cbl_yarena *a, int fib,
    const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes **out)
{
	struct vc_file	*f;
	struct yunread	*u;
	char		**paths, err[256];
	size_t		 n, i, nu;
	int		 error;

	*out = NULL;
	if (vc_rc_files(opts.root != NULL ? opts.root : "", "/usr/local",
	    "routing", "arcana", &paths, &n, err, sizeof(err)) != 0) {
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
	error = rcr_read(f, n, fib, a, out, &u, &nu);
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

/* FIB fib's routing: its RIBs from the kernel, its static routes as
 * rc.d/routing installs them, the one protocol instance rc(8) is. */
static int
routing_of(cbl_yarena *a, int fib, struct ietf_routing *data)
{
	const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes *sr;
	struct ietf_routing_routing				*rt;
	struct ietf_routing_routing_control_plane_protocols	*cpp;
	struct ietf_routing_routing_control_plane_protocols_control_plane_protocol *p;
	int	error;

	if ((error = yrt_routing(data, fib, a)) != 0 ||
	    (error = statics(a, fib, &sr)) != 0)
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

int
ietf_routing_routing_get(cbl_req *req, struct ietf_routing *data,
    cbl_yarena *a)
{

	(void)req;
	return (routing_of(a, 0, data));
}

/* Deprecated, and NMDA's routing says it all: not there. */
int
ietf_routing_routing_state_get(cbl_req *req, struct ietf_routing *data,
    cbl_yarena *a)
{

	(void)req;
	(void)data;
	(void)a;
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

	(void)req;
	(void)target;
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

typedef struct ietf_logical_network_element_logical_network_elements_logical_network_element
    ylne;
typedef struct ietf_logical_network_element_logical_network_elements_logical_network_element_root
    ylneroot;

/*
 * RFC 8530's logical network elements, the vnet jails (ylne.c), each
 * with its root: an inline mount, what the jail has of the models the
 * agent serves, as a helper attached to it reads (lneroot.c).
 */
int
ietf_logical_network_element_logical_network_elements_get(cbl_req *req,
    struct ietf_logical_network_element *data, cbl_yarena *a)
{
	const struct ietf_logical_network_element_logical_network_elements *l;
	ylne	*v;
	int	error;

	if ((error = ylne_elements(a, &l)) != 0)
		return (error);
	if (l == NULL || l->logical_network_element.n == 0)
		return (0);
	/* Each root as its helper reads it in the jail; in running none,
	 * nothing in it being changed here. */
	v = (ylne *)(uintptr_t)l->logical_network_element.v;
	for (size_t i = 0; cbl_req_ydatastore(req) != CBL_YDS_RUNNING &&
	    i < l->logical_network_element.n; i++) {
		const ylneroot *r;

		if ((error = lne_root(a, v[i].name, &r)) != 0)
			return (error);
		if (r != NULL)
			v[i].root = r;
	}
	data->logical_network_elements = l;
	return (0);
}

/* The static routes of a routing tree, rc.conf's protocol of type
 * static; *other: it has a protocol of another type. */
static const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes *
static_of(const struct ietf_routing *r, bool *other)
{
	const struct ietf_routing_routing_control_plane_protocols *cpp;
	const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes *sr = NULL;
	uint64_t	st = ident_sid("ietf-routing", "static");

	if (r == NULL || r->routing == NULL ||
	    (cpp = r->routing->control_plane_protocols) == NULL)
		return (NULL);
	for (size_t i = 0; i < cpp->control_plane_protocol.n; i++) {
		if (cpp->control_plane_protocol.v[i].type == st)
			sr = cpp->control_plane_protocol.v[i].static_routes;
		else
			*other = true;
	}
	return (sr);
}

/* What r has, but its protocols, as YANG-CBOR, malloc'd. */
static int
but_protocols(const struct ietf_routing *r, struct cbl_ybuf *b)
{
	struct ietf_routing_routing	rt;
	struct ietf_routing		ro;

	memset(&ro, 0, sizeof(ro));
	if (r->routing != NULL) {
		rt = *r->routing;
		rt.control_plane_protocols = NULL;
		ro.routing = &rt;
	}
	if (!cbl_ymember_present(ynode_named("ietf-routing", "routing"), &ro))
		return (0);
	return (cbl_yencode_member(ynode_named("ietf-routing", "routing"), &ro,
	    b));
}

/*
 * A commit of FIB 0's static routes (PLAN-SDN-YANG 2.3.5, 2.4.3,
 * 2.4.4): written to Arcana's rc.conf file as rc.d/routing reads them
 * (rcr_write(), rcarcana.c's rules: rc_conf_files, the user's
 * variables), then made the kernel's (rcr_apply()), tried again once
 * where it fails, a route the table changed meanwhile; failing still,
 * the files put back.  What else the tree changes is not done here yet.
 */
static int	statics_commit(cbl_req *, int, const struct ietf_routing *,
		    const struct ietf_routing *);

/* Whether two routings' configuration differ, as YANG-CBOR. */
static bool
routing_differs(const struct ietf_routing *a, const struct ietf_routing *b)
{
	const struct cbl_ynode *n = ynode_named("ietf-routing", "routing");
	struct cbl_ybuf ba = { NULL, 0, 0 }, bb = { NULL, 0, 0 };
	bool differ;

	if (a != NULL && cbl_ymember_present(n, a))
		(void)cbl_yencode_member(n, a, &ba);
	if (b != NULL && cbl_ymember_present(n, b))
		(void)cbl_yencode_member(n, b, &bb);
	differ = ba.len != bb.len || (ba.len > 0 && memcmp(ba.p, bb.p,
	    ba.len) != 0);
	cbl_ybuf_free(&ba);
	cbl_ybuf_free(&bb);
	return (differ);
}

int
ietf_routing_routing_edit(cbl_req *req, const struct ietf_routing *before,
    const struct ietf_routing *after)
{

	return (statics_commit(req, 0, before, after));
}

/* The same of FIB fib's routing, a network instance's (vrf-root). */
static int
statics_commit(cbl_req *req, int fib, const struct ietf_routing *before,
    const struct ietf_routing *after)
{
	const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes *old, *new;
	struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes none;
	struct cbl_ybuf	 b1 = { NULL, 0, 0 }, b2 = { NULL, 0, 0 };
	struct rca	 x;
	char		 err[512];
	bool		 other = false;
	int		 error;

	err[0] = '\0';
	old = static_of(before, &other);
	new = static_of(after, &other);
	if ((error = but_protocols(before, &b1)) == 0)
		error = but_protocols(after, &b2);
	if (error == 0 && (other || b1.len != b2.len || (b1.len > 0 &&
	    memcmp(b1.p, b2.p, b1.len) != 0)))
		error = EOPNOTSUPP;
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
	if (error != 0) {
		if (error == EOPNOTSUPP)
			(void)cbl_req_set_yerr(req, "only rc.conf's static "
			    "routes are changed here yet", 0);
		return (error);
	}
	memset(&none, 0, sizeof(none));
	if (old == NULL)
		old = &none;
	if (new == NULL)
		new = &none;
	if ((error = rca_open(&x, "routing", err, sizeof(err))) != 0) {
		(void)cbl_req_set_yerr(req, err, 0);
		return (error);
	}
	if ((error = rcr_write(x.f, fib, new, err, sizeof(err))) != 0 ||
	    (error = rca_write(&x, req, err, sizeof(err))) != 0) {
		if (error != EEXIST)
			(void)cbl_req_set_yerr(req, err, 0);
		rca_close(&x);
		return (error);
	}
	for (int tries = 0; tries < 2; tries++) {
		if ((error = rcr_apply(fib, old, new, err, sizeof(err))) == 0)
			break;
		if (tries == 0)
			(void)usleep(200000);
	}
	if (error != 0) {
		rca_undo(&x);
		(void)cbl_req_set_yerr(req, err, 0);
		logmsg(LOG_WARNING, "static routes: %s: rc.conf as it was",
		    err);
	}
	rca_close(&x);
	return (error);
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

/* A file's text as it is, to put back; *there: it was. */
static char *
file_text(const char *path, size_t *lenp, bool *there)
{
	FILE	*fp;
	char	*buf = NULL;
	size_t	 cap = 0;

	*lenp = 0;
	*there = false;
	if ((fp = fopen(path, "re")) == NULL)
		return (NULL);
	*there = true;
	for (;;) {
		char	*nb;
		size_t	 n;

		if (cap - *lenp < 4096) {
			if ((nb = realloc(buf, cap + 8192)) == NULL)
				break;
			buf = nb;
			cap += 8192;
		}
		if ((n = fread(buf + *lenp, 1, cap - *lenp, fp)) == 0)
			break;
		*lenp += n;
	}
	fclose(fp);
	return (buf);
}

static void
file_back(const char *path, const char *text, size_t len, bool there)
{
	FILE	*fp;

	if (!there) {
		(void)unlink(path);
		return;
	}
	if ((fp = fopen(path, "we")) == NULL)
		return;
	if (len > 0)
		(void)fwrite(text, 1, len, fp);
	fclose(fp);
}

/* An interface whose FIB is fib, in name (IFNAMSIZ); false: none. */
static bool
fib_in_use(int fib, char *name, size_t len)
{
	struct ifaddrs	*ifa0, *ifa;
	struct ifreq	 ifr;
	bool		 found = false;
	int		 s;

	if (getifaddrs(&ifa0) == -1)
		return (false);
	if ((s = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1) {
		freeifaddrs(ifa0);
		return (false);
	}
	for (ifa = ifa0; ifa != NULL && !found; ifa = ifa->ifa_next) {
		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, ifa->ifa_name, sizeof(ifr.ifr_name));
		if (ioctl(s, SIOCGIFFIB, &ifr) == 0 && (int)ifr.ifr_fib ==
		    fib) {
			strlcpy(name, ifa->ifa_name, len);
			found = true;
		}
	}
	close(s);
	freeifaddrs(ifa0);
	return (found);
}

/*
 * A commit of the network instances (RFC 8529, D-6: a FIB each): the
 * names and descriptions into fibs.conf; an instance past the last FIB
 * grows them (yni_grow(): net.fibs raised live where the kernel lets
 * it, kept in loader.conf.d for the boot).  FreeBSD never lowers
 * net.fibs, not even for an undo: that is said first, a warning to
 * accept (net-fibs); a FIB made at the next boot alone is told after
 * (after-reboot).  An instance taken away while an interface is in
 * its FIB is refused.
 */
int
ietf_network_instance_network_instances_edit(cbl_req *req,
    const struct ietf_network_instance *before,
    const struct ietf_network_instance *after)
{
	const struct ietf_network_instance_network_instances *ni =
	    after != NULL ? after->network_instances : NULL;
	const struct ietf_network_instance_network_instances *was =
	    before != NULL ? before->network_instances : NULL;
	struct vc_file	 lf, ff;
	char		 lpath[MAXPATHLEN], fpath[MAXPATHLEN], err[512];
	char		*ltext, *ftext, ifname[IFNAMSIZ];
	size_t		 llen, flen;
	bool		 lthere, fthere, reboot = false;
	int		 nfibs = yni_nfibs(), had = nfibs, want = nfibs;
	int		 error = 0;

	err[0] = '\0';
	/* What goes: no interface in its FIB. */
	for (size_t i = 0; was != NULL && i < was->network_instance.n; i++) {
		const char *name = was->network_instance.v[i].name;
		int fib = was->network_instance.v[i].has_arcni_fib ?
		    (int)was->network_instance.v[i].arcni_fib : -1;

		if (fib <= 0 || yni_fib(ni, name) == fib)
			continue;
		if (fib_in_use(fib, ifname, sizeof(ifname))) {
			(void)snprintf(err, sizeof(err), "%s: %s is in its FIB "
			    "%d: bound elsewhere first", name, ifname, fib);
			(void)cbl_req_set_yerr(req, err, 0);
			return (EBUSY);
		}
	}
	for (size_t i = 0; ni != NULL && i < ni->network_instance.n; i++)
		if (ni->network_instance.v[i].has_arcni_fib &&
		    (int)ni->network_instance.v[i].arcni_fib >= want)
			want = (int)ni->network_instance.v[i].arcni_fib + 1;
	if (want > nfibs && !cbl_req_yaccepts(req, "net-fibs")) {
		(void)snprintf(err, sizeof(err), "FIB %d asks net.fibs to go "
		    "from %d to %d, which FreeBSD never lowers again, not even "
		    "for an undo: accept net-fibs to raise it", want - 1, nfibs,
		    want);
		(void)cbl_req_set_yapptag(req, "net-fibs");
		(void)cbl_req_set_yerr(req, err, 0);
		return (EEXIST);
	}
	(void)snprintf(lpath, sizeof(lpath), "%s/boot/loader.conf.d/arcana.conf",
	    opts.root != NULL ? opts.root : "");
	sdwan_conf_path(FIBS_CONF, fpath, sizeof(fpath));
	ltext = file_text(lpath, &llen, &lthere);
	ftext = file_text(fpath, &flen, &fthere);
	memset(&lf, 0, sizeof(lf));
	memset(&ff, 0, sizeof(ff));
	if (vc_read(&lf, VC_LOADER, lpath, err, sizeof(err)) == -1 ||
	    vc_read(&ff, VC_SH, fpath, err, sizeof(err)) == -1)
		error = errno != 0 ? errno : EIO;
	else if ((error = yni_grow(&lf, &nfibs, ni, &reboot, err,
	    sizeof(err))) == 0 && want > had && vc_write(&lf, lpath, 0644,
	    err, sizeof(err)) == -1)
		error = errno != 0 ? errno : EIO;
	if (error == 0 && (error = yni_write(&ff, nfibs, ni, err,
	    sizeof(err))) == 0 && vc_write(&ff, fpath, 0644, err,
	    sizeof(err)) == -1)
		error = errno != 0 ? errno : EIO;
	if (error != 0)
		(void)cbl_req_set_yerr(req, err, 0);
	/* Each instance's routing, mounted at its vrf-root: its FIB's
	 * static routes, as FIB 0's are committed. */
	for (size_t i = 0; error == 0 && ni != NULL &&
	    i < ni->network_instance.n; i++) {
		const struct ietf_network_instance_network_instances_network_instance *e =
		    &ni->network_instance.v[i];
		const struct ietf_routing *ra, *rb = NULL;
		int fib = e->has_arcni_fib ? (int)e->arcni_fib : -1;

		if (fib <= 0)
			continue;
		ra = cbl_ymount_find(vrf_root(), e->vrf_root,
		    ynode_named("ietf-routing", "routing")->module);
		for (size_t k = 0; was != NULL && k < was->network_instance.n;
		    k++)
			if (was->network_instance.v[k].has_arcni_fib &&
			    (int)was->network_instance.v[k].arcni_fib == fib)
				rb = cbl_ymount_find(vrf_root(),
				    was->network_instance.v[k].vrf_root,
				    ynode_named("ietf-routing", "routing")->module);
		if (!routing_differs(rb, ra))
			continue;
		if (fib >= yni_nfibs()) {
			(void)snprintf(err, sizeof(err), "%s: FIB %d is made at "
			    "the next boot: its routes then", e->name, fib);
			(void)cbl_req_set_yerr(req, err, 0);
			error = EAGAIN;
			break;
		}
		error = statics_commit(req, fib, rb, ra);
	}
	if (error != 0) {
		file_back(lpath, ltext, llen, lthere);
		file_back(fpath, ftext, flen, fthere);
	} else if (reboot)
		(void)cbl_req_ywarn(req, ynode_named("ietf-network-instance",
		    "network-instances")->sid, "after-reboot",
		    "the kernel makes the new FIBs at the next boot");
	vc_free(&lf);
	vc_free(&ff);
	free(ltext);
	free(ftext);
	return (error);
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

	(void)req;
	if ((yl = cbl_yarena_alloc(a, sizeof(*yl))) == NULL ||
	    (ms = cbl_yarena_alloc(a, sizeof(*ms))) == NULL ||
	    (sc = cbl_yarena_alloc(a, sizeof(*sc))) == NULL ||
	    (ds = cbl_yarena_alloc(a, 3 * sizeof(*ds))) == NULL ||
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
	/* NMDA's three (RFC 8342), one schema. */
	ds[0].name = ident_sid("ietf-datastores", "running");
	ds[1].name = ident_sid("ietf-datastores", "candidate");
	ds[2].name = ident_sid("ietf-datastores", "operational");
	ds[0].schema = ds[1].schema = ds[2].schema = sc->name;
	yl->module_set.n = 1;
	yl->module_set.v = ms;
	yl->schema.n = 1;
	yl->schema.v = sc;
	yl->datastore.n = 3;
	yl->datastore.v = ds;
	snprintf(id, sizeof(id), "%016jx", (uintmax_t)h);
	if ((yl->content_id = cbl_yarena_alloc(a, strlen(id) + 1)) == NULL)
		return (ENOMEM);
	memcpy((char *)(uintptr_t)yl->content_id, id, strlen(id) + 1);
	data->yang_library = yl;
	return (0);
}

/*
 * RFC 8528's schema-mounts: the vrf-root of a network instance (RFC
 * 8529), a shared schema whose routing names the host's interfaces
 * (its parent-reference); its config: an instance's static routes are
 * changed by an EDIT.  The root of a logical network element (RFC
 * 8530), inline: the YANG library in it says its schema.
 */
int
ietf_yang_schema_mount_schema_mounts_get(cbl_req *req,
    struct ietf_yang_schema_mount *data, cbl_yarena *a)
{
	static const char *const parents[] = { "/if:interfaces" };
	static const struct ietf_yang_schema_mount_schema_mounts_mount_point_shared_schema
	    shared = { { nitems(parents), parents } };
	static const struct ietf_yang_schema_mount_schema_mounts_mount_point_inline
	    inl;
	static const struct ietf_yang_schema_mount_schema_mounts_mount_point
	    mp[] = { {
		.module = "ietf-network-instance",
		.label = "vrf-root",
		.schema_ref =
		    IETF_YANG_SCHEMA_MOUNT_SCHEMA_MOUNTS_MOUNT_POINT_SCHEMA_REF_SHARED_SCHEMA,
		.shared_schema = &shared,
	}, {
		.module = "ietf-logical-network-element",
		.label = "root",
		.schema_ref =
		    IETF_YANG_SCHEMA_MOUNT_SCHEMA_MOUNTS_MOUNT_POINT_SCHEMA_REF_INLINE,
		.inline_ = &inl,
	} };
	struct ietf_yang_schema_mount_schema_mounts_namespace	*ns;
	struct ietf_yang_schema_mount_schema_mounts		*sm;
	const struct cbl_ynode					*n;

	(void)req;
	if (vrf_root() == NULL ||
	    (n = ynode_named("ietf-interfaces", "interfaces")) == NULL)
		return (0);
	if ((sm = cbl_yarena_alloc(a, sizeof(*sm))) == NULL ||
	    (ns = cbl_yarena_alloc(a, sizeof(*ns))) == NULL)
		return (ENOMEM);
	ns->prefix = "if";
	ns->uri = n->module->ns;
	sm->namespace.n = 1;
	sm->namespace.v = ns;
	sm->mount_point.n = nitems(mp);
	sm->mount_point.v = mp;
	data->schema_mounts = sm;
	return (0);
}

/* Deprecated, and yang-library says it all: not there. */
int
ietf_yang_library_modules_state_get(cbl_req *req, struct ietf_yang_library *data,
    cbl_yarena *a)
{

	(void)data;
	(void)a;
	(void)req;
	return (0);
}

/* RFC 8348's hardware: the chassis, CPUs and disks (superbia/yhw.c). */
int
ietf_hardware_hardware_get(cbl_req *req, struct ietf_hardware *data,
    cbl_yarena *a)
{
	char	*json;
	int	 error;

	(void)req;
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

	(void)req;
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

	(void)req;
	(void)target;
	(void)a;
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

	(void)req;
	(void)target;
	(void)a;
	out->has_compressed_alarms = true;
	return (alarms_compress(in, &out->compressed_alarms));
}

/* The context the models are served on, for their notifications. */
static cbl_ctx		*yctx;

/* A module's top-level node of that name, in the tables. */
const struct cbl_ynode *
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

	(void)req;
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
	(void)req;
	return (0);
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

/* The subscriptions container, its get, its edit and its receivers'
 * reset: invidia/ynotif.c, where the configured ones are kept. */
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

/* RFC 8530's bind-lne-name-failed: an interface bound to a logical
 * network element is not there, after the commit that bound it. */
void
yang_lne_failed(const char *ifname, const char *lne, const char *why)
{
	struct ietf_logical_network_element_bind_lne_name_failed	f;

	if (yctx == NULL)
		return;
	f.name = ifname;
	f.bind_lne_name = lne;
	f.error_info = why;
	(void)ietf_logical_network_element_bind_lne_name_failed_notify(yctx,
	    &f);
}

/*
 * What the agent tells the changes of, so that an on-change subscription
 * of them is read when told and not every period: the events, each
 * added (events.c); the alarms, each fault set, cleared, said anew,
 * purged or compressed (faults.c), a fault older than a day going with
 * the next of those; the jobs, each queued, begun, confirmed, finished
 * or forgotten, each step of one, and what holds the changes (jobs.c,
 * trace.c, handlers.c); the interfaces, the routing, the instances and
 * the jails' networks by the events that say they changed
 * (yang_event_changed()), by a commit (cblink tells those itself), and
 * a minute on for what the kernel announces nowhere (hostwatch.c).
 * The rest is read every period.
 */
static const char *const told_tops[YANG_COUNT][2] = {
	[YANG_EVENTS] = { "arcana-events", "events" },
	[YANG_ALARMS] = { "ietf-alarms", "alarms" },
	[YANG_JOBS] = { "arcana-jobs", "jobs" },
	[YANG_INTERFACES] = { "ietf-interfaces", "interfaces" },
	[YANG_ROUTING] = { "ietf-routing", "routing" },
	[YANG_INSTANCES] = { "ietf-network-instance", "network-instances" },
	[YANG_LNES] = { "ietf-logical-network-element",
	    "logical-network-elements" },
};

void
yang_changed(int what)
{
	const struct cbl_ynode	*n;

	if (yctx != NULL && what >= 0 && what < YANG_COUNT &&
	    (n = ynode_named(told_tops[what][0], told_tops[what][1])) != NULL)
		cbl_ysub_changed(yctx, n);
}

/*
 * What an event says changed: netlink(4)'s links, addresses and
 * neighbours the interfaces, its routes the routing and the instances'
 * (each FIB's), of a jail's network its logical network element; a
 * jail's state those and the interfaces (a vnet's move); a job, or a
 * file rc(8) reads changed, any of them.
 */
void
yang_event_changed(const char *kind, bool jailed)
{
	static const char *const ifs[] = { "link", "link-del", "address-add",
	    "address-del", "neigh", "neigh-del" };
	static const char *const rts[] = { "route-add", "route-del",
	    "routes" };
	bool	any;

	any = strcmp(kind, "job") == 0 || strcmp(kind, "conf") == 0;
	for (size_t i = 0; !any && i < nitems(ifs); i++)
		if (strcmp(kind, ifs[i]) == 0) {
			yang_changed(jailed ? YANG_LNES : YANG_INTERFACES);
			return;
		}
	for (size_t i = 0; !any && i < nitems(rts); i++)
		if (strcmp(kind, rts[i]) == 0) {
			if (jailed)
				yang_changed(YANG_LNES);
			else {
				yang_changed(YANG_ROUTING);
				yang_changed(YANG_INSTANCES);
			}
			return;
		}
	if (any || strcmp(kind, "jail-state") == 0) {
		yang_changed(YANG_INTERFACES);
		yang_changed(YANG_LNES);
	}
	if (any) {
		yang_changed(YANG_ROUTING);
		yang_changed(YANG_INSTANCES);
	}
}

/* The models served, family 1 beside the agent's own. */
int
yang_serve(cbl_ctx *ctx)
{
	const struct cbl_ynode	*told[YANG_COUNT];
	size_t			 k;
	int			 error;

	/* Each request on a thread of its own: a read of the storage or of
	 * BIRD holds no other, as the agent's own family's slow reads. */
	if ((error = cbl_yserver_add(ctx, &ymodel_server, NULL)) != 0 ||
	    (error = ynetconf_datastores(ctx)) != 0)
		return (error);
	yctx = ctx;
	(void)cbl_ysub_set_replay(ctx, yreplay, NULL);
	for (k = 0; k < YANG_COUNT && (told[k] = ynode_named(told_tops[k][0],
	    told_tops[k][1])) != NULL; k++)
		;
	if (k == YANG_COUNT)
		(void)cbl_ysub_told(ctx, told, nitems(told));
	if ((error = ysubs_init(ctx)) != 0)
		return (error);
	return (cbl_yserver_threads(ctx, true));
}
