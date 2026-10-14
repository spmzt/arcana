/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The YANG collectors (PLAN-SDN-YANG 1.9, 1.10, 2.4): the host's state as
 * the IETF modules model it, into the structs cblink-gen made of them
 * (ymodel.h, ymodel_schema.c, from share/yang).  What a collector
 * allocates is the arena's.  0, or an errno.
 */

#ifndef _ARCANA_COLLECT_H_
#define	_ARCANA_COLLECT_H_

#include "ymodel.h"

/*
 * ietf-interfaces (RFC 8343): /interfaces, operational (invidia/yif.c),
 * with the modules that augment it: arcana-interfaces, ietf-ip.
 */
int	yif_interfaces(struct ietf_interfaces *data, cbl_yarena *a);

/* ietf-ip (RFC 8344): the n interfaces' ipv4 and ipv6 (invidia/yip.c). */
int	yip_interfaces(struct ietf_interfaces_interfaces_interface *v,
	    size_t n, cbl_yarena *a);

/*
 * ietf-routing (RFC 8349): /routing/ribs of FIB fib, its IPv4 and IPv6
 * routes, with v4ur's and v6ur's leaves (invidia/yrt.c).
 */
int	yrt_routing(struct ietf_routing *data, int fib, cbl_yarena *a);
/* The RIB's active-route action: the route in's address goes by in
 * FIB fib; none, out without a route. */
int	yrt_active_route(int fib,
	    const struct ietf_routing_routing_ribs_rib_active_route_input *in,
	    cbl_yarena *a,
	    struct ietf_routing_routing_ribs_rib_active_route_output *out);

/*
 * rc.conf's static routes, as rc.d/routing installs them, and
 * ietf-routing's static control-plane-protocol (invidia/rcroutes.c).
 * rcr_read(): FIB fib's of the files rc(8) reads, in its order; what
 * the model cannot hold, or reading cannot tell, in *u (malloc'd), the
 * variable and why.  rcr_write(): sr's into fragment f, Arcana's, what
 * it wrote there before replaced; err says what is refused.
 */
struct vc_file;
struct yunread {
	const char	*var;
	const char	*why;
};

int	rcr_read(const struct vc_file *files, size_t nfiles, int fib,
	    cbl_yarena *a,
	    const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes **out,
	    struct yunread **u, size_t *nu);
/* FIB fib's static routes made new's, the kernel's as old applied
 * them: by netlink(4), what was done undone on failure. */
int	rcr_apply(int fib,
	    const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes *old,
	    const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes *new,
	    char *err, size_t errlen);
int	rcr_write(struct vc_file *f, int fib,
	    const struct ietf_routing_routing_control_plane_protocols_control_plane_protocol_static_routes *sr,
	    char *err, size_t errlen);

/*
 * FreeBSD's FIBs as RFC 8529's network instances, invidia/yni.c: FIB 1
 * to net.fibs - 1, named and described in fibs.conf f (NULL: none).
 * yni_nfibs(): net.fibs, this vnet's.  yni_read(): the instances, what
 * f has that cannot be read so in *u.  yni_write(): ni's names and
 * descriptions into f; err says what is refused.
 */
int	yni_nfibs(void);
int	yni_read(const struct vc_file *f, int nfibs, cbl_yarena *a,
	    const struct ietf_network_instance_network_instances **out,
	    struct yunread **u, size_t *nu);
int	yni_write(struct vc_file *f, int nfibs,
	    const struct ietf_network_instance_network_instances *ni,
	    char *err, size_t errlen);
/*
 * bind-ni-name: yni_bind() each of the n interfaces', its address
 * families' too, from its FIB; yni_fib() the FIB of the instance named
 * name, -1 for none; yni_rc_fib() the "fib N" words of rc.conf f's
 * ifconfig_<if>; yni_bind_apply() ifname bound to name (v4, v6 its
 * families' if given), by SIOCSIFFIB and in f if not NULL; refused,
 * *fail says why as RFC 8529's bind-ni-name-failed.
 */
int	yni_bind(struct ietf_interfaces_interfaces_interface *v, size_t n,
	    const struct ietf_network_instance_network_instances *ni,
	    cbl_yarena *a);
int	yni_fib(const struct ietf_network_instance_network_instances *ni,
	    const char *name);
int	yni_rc_fib(struct vc_file *f, const char *ifname, int fib, char *err,
	    size_t errlen);
int	yni_bind_apply(const char *ifname, const char *name, const char *v4,
	    const char *v6,
	    const struct ietf_network_instance_network_instances *ni,
	    struct vc_file *f, cbl_yarena *a,
	    const struct ietf_network_instance_bind_ni_name_failed **fail);

/*
 * rtadvd.conf and an interface's ipv6-router-advertisements (RFC 8349's
 * submodule), invidia/rtadv.c.  rtadv_read(): the interface's record,
 * tc= followed (none: *out NULL).  rtadv_write(): ra into the record's
 * own fields, the record made if not there; err says what is refused.
 */
struct vc_capfile;
int	rtadv_read(const struct vc_capfile *f, const char *ifname,
	    cbl_yarena *a,
	    const struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements **out);
int	rtadv_write(struct vc_capfile *f, const char *ifname,
	    const struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements *ra,
	    char *err, size_t errlen);

#endif /* !_ARCANA_COLLECT_H_ */
