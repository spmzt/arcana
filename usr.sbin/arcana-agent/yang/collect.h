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
 * arcana-jails (ira/yjails.c): yjails_from_list() the list operation's
 * reply as the module has it, its strings rsp's; yjails_action() one of
 * its actions (ARC_ACTION_*), as the action operation does it, the jail
 * after it: -1 and *errp, not done.
 */
struct arc_list_rsp;
struct work;
int	yjails_from_list(const struct arc_list_rsp *rsp, cbl_yarena *a,
	    struct arcana_jails *out);
int	yjails_action(struct work *w, const char *name, uint8_t action,
	    uint8_t *state, bool *has_jid, uint32_t *jid, const char **errp);

/*
 * arcana-services (ira/yservices.c, ira/services.c): yservices_from()
 * the services operation's reply as the module has it, each service with
 * its service-config reply where one is given; yservices_diff() what
 * makes have's configuration want's, as service-action (*enable) and
 * service-config (*vars) take it; yservices_action() one of its actions
 * (ARC_SERVICE_ACTION_START to _RELOAD); yservices_apply() what
 * yservices_diff() said, done.
 */
struct arc_services_rsp;
struct arc_service_config_rsp;
struct arc_variable;
int	yservices_from(const struct arc_services_rsp *list,
	    const struct arc_service_config_rsp *const *cfg, size_t ncfg,
	    cbl_yarena *a, struct arcana_services *out);
int	yservices_diff(const struct arcana_services_services_service *have,
	    const struct arcana_services_services_service *want,
	    cbl_yarena *a, int *enable, struct arc_variable **vars,
	    size_t *nvars);
int	yservices_action(struct work *w, const char *name, uint8_t action,
	    bool *running, bool *has_pid, uint32_t *pid, const char **status,
	    const char **errp);
int	yservices_apply(struct work *w, const char *name, int enable,
	    const struct arc_variable *vars, size_t nvars, const char **errp);

/*
 * arcana-packages (ira/ypackages.c, ira/packages.c), the host's or a
 * jail's alike (a jail's structs have the host's layout):
 * ypackages_from() pkg-installed's reply, each with its newer version
 * from the outdated reply (NULL: not asked); ypackages_upgraded()
 * pkg-upgrade's reply as the upgrade action's output; the refresh and
 * upgrade actions, as the operations do them.
 */
struct arc_packages_rsp;
struct arc_pkg_upgrade_rsp;
int	ypackages_from(const struct arc_packages_rsp *installed,
	    const struct arc_packages_rsp *outdated, cbl_yarena *a,
	    struct arcana_packages_packages *out);
int	ypackages_upgraded(const struct arc_pkg_upgrade_rsp *rsp,
	    cbl_yarena *a, struct arcana_packages_packages_upgrade_output *out);
int	ypackages_refresh(struct work *w, const char *jail, uint8_t ip,
	    const char **errp);
int	ypackages_upgrade(struct work *w, const char *jail,
	    const struct arcana_packages_packages_upgrade_input *in,
	    cbl_yarena *a, struct arcana_packages_packages_upgrade_output *out,
	    const char **errp);

/*
 * arcana-jobs (ira/yjobs.c, yang/yjobs_spec.c): yjobs_from() jobs as the
 * module has them, each with its trace, a flat list of steps; yjobs_spec()
 * one change of a submit made a job-spec (made from jobs.yaml);
 * yjobs_specs() all of them, *bad the one refused.
 */
struct arc_job;
struct arc_job_spec;
int	yjobs_from(const struct arc_job *v, size_t n, const char *activity,
	    int64_t since, bool stopping, cbl_yarena *a,
	    struct arcana_jobs *out);
int	yjobs_spec(const struct arcana_jobs_submit_input_change *in,
	    cbl_yarena *a, struct arc_job_spec *sp);
int	yjobs_specs(const struct arcana_jobs_submit_input *in, cbl_yarena *a,
	    const struct arc_job_spec **out, size_t *n, size_t *bad);

/*
 * arcana-storage (acedia/ystorage.c): ystorage_from_json() the storage
 * operation's reply of a kind (ARC_STORAGE_KIND_*) put in st, the other
 * kinds' parts kept, health's on its disks; ystorage_fstab() fstab(5)'s
 * text and SHA-256, the fstab operation's.
 */
int	ystorage_from_json(int kind, const char *json, uint64_t total,
	    bool truncated, cbl_yarena *a, struct arcana_storage_storage *st);
int	ystorage_fstab(const char *text, const char *sha256, cbl_yarena *a,
	    struct arcana_storage_storage *st);

/*
 * arcana-sysctl and arcana-kernel (superbia/ysystem.c): the sysctl and
 * kernel operations' JSON as the modules have them; their configuration
 * written in place: sysctl.conf's settings (f: VC_SYSCTL), rc.conf's
 * kld_list (f: VC_SH).
 */
int	ysysctl_from_json(const char *json, uint64_t total, bool truncated,
	    cbl_yarena *a, struct arcana_sysctl_sysctl *out);
int	ykernel_from_json(const char *json, cbl_yarena *a,
	    struct arcana_kernel_kernel *out);
int	ysysctl_conf_write(struct vc_file *f,
	    const struct arcana_sysctl_sysctl *want, char *err, size_t errlen);
int	ykernel_kld_write(struct vc_file *f,
	    const struct arcana_kernel_kernel *want, char *err, size_t errlen);

/*
 * RFC 8530's logical network elements: the vnet jails, as jls(8) lists
 * them (invidia/ylne.c).
 */
int	ylne_elements(cbl_yarena *a,
	    const struct ietf_logical_network_element_logical_network_elements **out);

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
/* net.fibs raised to the FIBs ni asks for, live and in loader.conf lf;
 * *nfibs as many as there are, or will be; *reboot: at the next boot. */
int	yni_grow(struct vc_file *lf, int *nfibs,
	    const struct ietf_network_instance_network_instances *ni,
	    bool *reboot, char *err, size_t errlen);
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
