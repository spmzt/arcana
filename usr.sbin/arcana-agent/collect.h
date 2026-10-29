/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_COLLECT_H_
#define	_ARCANA_COLLECT_H_

/*
 * The collectors: what the host has, read into the standard models'
 * structs (ymodel.h, cblink-gen's from share/yang), as cblink's YANG
 * family serves them (invidia/yserve.c).
 */

#include <cblink.h>

#include "ymodel.h"

/* The interfaces; with ni, each bound to its FIB's instance of ni. */
int	yif_interfaces(struct ietf_interfaces *data,
	    const struct ietf_network_instance_network_instances *ni,
	    cbl_yarena *a);
int	yif_linkagg(const struct ietf_interfaces_interfaces_interface *v,
	    size_t n, cbl_yarena *a, struct ieee802_dot1ax_linkagg *data);
int	yif_bridges(const struct ietf_interfaces_interfaces_interface *v,
	    size_t n, cbl_yarena *a, struct ieee802_dot1q_bridge *data);
uint64_t yif_pmd(const char *subtype);
int	yip_interfaces(struct ietf_interfaces_interfaces_interface *v,
	    size_t n, cbl_yarena *a);

/*
 * ietf-routing (RFC 8349): /routing/ribs of FIB fib, its IPv4 and IPv6
 * routes, with v4ur's and v6ur's leaves (invidia/yrt.c).
 */
int	yrt_routing(struct ietf_routing *data, int fib, cbl_yarena *a);
/*
 * A route's source-protocol, the identity's SID, by its netlink(4)
 * origin (rtm_protocol), whether it has a gateway, and its family.
 */
uint64_t yrt_origin(uint8_t proto, bool gateway, bool v6);
/* The RIB's active-route action: the route in's address goes by in
 * FIB fib; none, out without a route. */
int	yrt_active_route(int fib,
	    const struct ietf_routing_routing_ribs_rib_active_route_input *in,
	    cbl_yarena *a,
	    struct ietf_routing_routing_ribs_rib_active_route_output *out);

/* What a file has that the model cannot hold, or reading cannot tell:
 * the variable and why. */
struct vc_file;
struct yunread {
	const char	*var;
	const char	*why;
};

/* Running's interfaces: what the get read but addresses and neighbours
 * whose origin is not static (invidia/yifedit.c). */
int	yif_running(struct ietf_interfaces *data, cbl_yarena *a);
/* Their router advertisements, as rtadvd.conf and rc.conf have them. */
int	yif_rtadv(struct ietf_interfaces *data, cbl_yarena *a);
int	yif_rtadv_show(struct ietf_interfaces *data, cbl_yarena *a);
/* The FIBs as network instances, their names from fibs.conf
 * (invidia/yserve.c). */
int	yni_instances(cbl_yarena *a,
	    const struct ietf_network_instance_network_instances **out);

/*
 * Arcana's rc.conf variables in a file of its own, named in
 * rc_conf_files (invidia/rcarcana.c).  rca_open(): it, and the user's
 * files rc(8) reads for service svc; rca_write(): f written, what the
 * user has not accepted (rc-conf-files, rc-conf-conflict) refused for
 * req (EEXIST, its error-app-tag), each file kept as it was; rca_undo():
 * them put back.  A variable of the user's that Arcana's file takes is
 * commented out where it is, the line kept under "#" with RCA_TAKEN
 * after it (libvarconf's vc_comment()), never removed.
 */
#define	RC_ARCANA	"/usr/local/etc/rc.conf.d/arcana"
#define	RCA_TAKEN	"taken by Arcana"

struct rca_was {
	char		*path;
	char		*text;
	size_t		 len;
	mode_t		 mode;
	bool		 there;
};

struct rca {
	char		 path[1024];	/* MAXPATHLEN */
	struct vc_file	*f;
	char		**user;
	size_t		 nuser;
	struct rca_was	*was;
	size_t		 nwas;
	struct vc_file	*uf;		/* the user's, read by rca_get() */
	char		**drop;		/* out of Arcana's, commented in theirs */
	size_t		 ndrop;
	/* What rca_write() takes as accepted without a req (a job's), its
	 * refusal then in err alone. */
	const char	*const *accept;
	size_t		 naccept;
};

int	rca_open(struct rca *x, const char *svc, char *err, size_t errlen);
int	rca_write(struct rca *x, cbl_req *req, char *err, size_t errlen);
void	rca_undo(struct rca *x);
/* What rc(8) would have for name: Arcana's file's, else the last of the
 * user's files that sets it; NULL, none.  rca_set(): name's value in
 * Arcana's file ("" ends a list of aliases, as rc(8) reads it). */
const char *rca_get(struct rca *x, const char *name);
int	rca_set(struct rca *x, const char *name, const char *value,
	    char *err, size_t errlen);
/* name taken out: of Arcana's file at once, of the user's files by
 * rca_write() under rc-conf-conflict. */
int	rca_drop(struct rca *x, const char *name);
/* Another file a commit changes, kept as it is for rca_undo(). */
int	rca_keep(struct rca *x, const char *path);
/* name out of Arcana's file, the user's files as they are (the release
 * action).  rca_put(): f, Arcana's file or one of the user's, written
 * to path, kept as it was first for rca_undo(). */
int	rca_unset(struct rca *x, const char *name, char *err, size_t errlen);
int	rca_put(struct rca *x, const struct vc_file *f, const char *path,
	    char *err, size_t errlen);
void	rca_close(struct rca *x);

/*
 * rc.conf's static routes, as rc.d/routing installs them, and
 * ietf-routing's static control-plane-protocol (invidia/rcroutes.c).
 * rcr_read(): FIB fib's of the files rc(8) reads, in its order; what
 * the model cannot hold, or reading cannot tell, in *u (malloc'd), the
 * variable and why.  rcr_write(): sr's into fragment f, Arcana's, what
 * it wrote there before replaced; err says what is refused.
 */
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
 * rtadvd.conf and an interface's ipv6-router-advertisements (RFC 8349's
 * submodule with arcana-ra's augments), invidia/rtadv.c.  rtadv_read():
 * the interface's record, tc= followed (none: *out NULL).
 * rtadv_write(): ra written as the record, whole, made if not there;
 * err says what is refused.  rtadvctl_parse(): rtadvctl -v show's text,
 * the interface's block as arcana-ra's rtadvd (none: *out NULL).
 */
struct vc_capfile;
int	rtadv_read(const struct vc_capfile *f, const char *ifname,
	    cbl_yarena *a,
	    const struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements **out);
int	rtadv_write(struct vc_capfile *f, const char *ifname,
	    const struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements *ra,
	    char *err, size_t errlen);
int	rtadvctl_parse(const char *text, const char *ifname, cbl_yarena *a,
	    const struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements_arcra_rtadvd **out);

/*
 * RFC 8530's logical network elements: the vnet jails, as jls(8) lists
 * them (invidia/ylne.c).
 */
int	ylne_elements(cbl_yarena *a,
	    const struct ietf_logical_network_element_logical_network_elements **out);

/*
 * Their roots, each served by a helper attached to the jail
 * (invidia/lneroot.c): lne_get() a GET of the top-level nodes sids
 * there; lne_root() the root of the jail name, NULL where it could not
 * be read; lne_bound_interfaces() the interfaces in the jails put in
 * the host's data, with the jail each is bound to.
 */
int	lne_get(int jid, const uint64_t *sids, size_t n, cbl_msg **reply);
const struct cbl_ynode *lne_root_node(void);
int	lne_root(cbl_yarena *a, const char *name,
	    const struct ietf_logical_network_element_logical_network_elements_logical_network_element_root **out);
int	lne_bound_interfaces(struct ietf_interfaces *data, cbl_yarena *a);

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
 * arcana-jails (ira/yjails.c): yjails_from_list() the jails read as
 * the module has it, its strings rsp's.  Served, the read and the
 * commits, by ira/yjailedit.c; its actions do_action()'s
 * (invidia/yarcana.c).
 */
struct jails_read;
struct work;
int	yjails_from_list(const struct jails_read *rsp, cbl_yarena *a,
	    struct arcana_jails *out);

/*
 * arcana-services (ira/yservices.c, ira/services.c): yservices_from()
 * do_services()' list as the module has it; yservices_read() the read
 * action's output from service_read()'s; yservices_diff() what makes
 * have's configuration want's, its rcvar YES or NO (*enable) and its
 * variables set or unset (*vars).  Its actions are services.c's
 * (invidia/yarcana.c).
 */
struct services_rsp;
struct service_config_rsp;
struct arc_variable;
int	yservices_from(const struct services_rsp *list, cbl_yarena *a,
	    struct arcana_services *out);
void	yservices_read(const struct service_config_rsp *r,
	    struct arcana_services_services_service_read_output *out);
int	yservices_diff(const struct arcana_services_services_service *have,
	    const struct arcana_services_services_service *want,
	    cbl_yarena *a, int *enable, struct arc_variable **vars,
	    size_t *nvars);
/* The convert action's work (ira/ysvcedit.c): the n services named
 * (none: every script) moved under Arcana's rc.conf file by
 * rca_write()'s rules, dry says what would be; out's strings are a's. */
int	yservices_convert(cbl_req *req, const char *const *names, size_t n,
	    bool dry, cbl_yarena *a,
	    struct arcana_services_services_convert_output *out);
/* The release action's, convert's inverse: the n services named given
 * back to the user's files, out of Arcana's; dry says what would be. */
int	yservices_release(cbl_req *req, const char *const *names, size_t n,
	    bool dry, cbl_yarena *a,
	    struct arcana_services_services_release_output *out);

/*
 * arcana-packages (ira/ypackages.c, ira/packages.c), the host's or a
 * jail's alike (a jail's structs have the host's layout):
 * ypackages_listed() the packages installed (pkg query's read), each
 * with its newer version from the outdated read (NULL: not asked), the
 * repositories and pkgbase beside, as the container and the read and
 * refresh actions' outputs have them; ypackages_from() the container;
 * ypackages_upgraded() an upgrade's outcome as the upgrade action's
 * output.
 */
struct pkg_read;
struct pkg_upgraded;
int	ypackages_listed(const struct pkg_read *installed,
	    const struct pkg_read *outdated, cbl_yarena *a,
	    const struct arcana_packages_package **vp, size_t *np,
	    const char *const **rp, size_t *nrp, bool *has_pkgbase,
	    bool *pkgbase);
int	ypackages_from(const struct pkg_read *installed,
	    const struct pkg_read *outdated, cbl_yarena *a,
	    struct arcana_packages_packages *out);
int	ypackages_upgraded(const struct pkg_upgraded *rsp,
	    cbl_yarena *a, struct arcana_packages_packages_upgrade_output *out);

/*
 * arcana-jobs (ira/yjobs.c): yjobs_from() jobs as the module has them,
 * without their traces; the change going on (activity, since), whether
 * the agent is stopping, and its lanes.  yjobs_read() one job with its
 * trace, a flat list of steps, as its read action gives it.  Its submit
 * makes changes job-specs, as jobs.yaml says.
 */
struct arc_job;
struct arc_job_spec;
int	yjobs_from(const struct arc_job *v, size_t n, const char *activity,
	    int64_t since, bool stopping, int lanes, cbl_yarena *a,
	    struct arcana_jobs *out);
void	yjobs_read(const struct arc_job *j,
	    const struct arcana_jobs_step *steps, size_t nsteps,
	    struct arcana_jobs_jobs_job_read_output *out);
/* A submit's change made a job-spec (yjobs_spec.c, jobs.awk's), and
 * all of them (*bad, the one refused). */
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
 * arcana-kernel and arcana-sysctl (superbia/ysystem.c): do_kernel()'s
 * JSON as the module has it; their configuration written in place:
 * sysctl.conf's settings (f: VC_SYSCTL), rc.conf's kld_list (f: VC_SH).
 * Served, the read action and the commits, by superbia/ysysedit.c.
 */
int	ykernel_from_json(const char *json, cbl_yarena *a,
	    struct arcana_kernel_kernel *out);
int	ysysctl_conf_write(struct vc_file *f,
	    const struct arcana_sysctl_sysctl *want, char *err, size_t errlen);
int	ykernel_kld_write(struct vc_file *f,
	    const struct arcana_kernel_kernel *want, char *err, size_t errlen);

/*
 * arcana-processes (gula/yprocs.c): do_processes()' JSON in OpenConfig
 * procmon's shape with FreeBSD's besides; detail, do_process()'s (NULL:
 * none), its files and threads put on its entry.  yprocs_read_from_json():
 * do_process()'s as the process's read action gives it.
 */
int	yprocs_from_json(const char *json, const char *detail, cbl_yarena *a,
	    struct arcana_processes_processes *out);
int	yprocs_read_from_json(const char *detail, cbl_yarena *a,
	    struct arcana_processes_processes_process_read_output *out);

/*
 * arcana-log (gula/ylog.c): do_log()'s JSON, the log directory's files
 * (dir, the directory's path), or a read's lines with the files of the
 * directory read, each line's facility and severity as ietf-syslog's.
 */
int	ylog_files_from_json(const char *json, const char *dir, cbl_yarena *a,
	    struct arcana_log_logs *out);
int	ylog_read_from_json(const char *json, cbl_yarena *a,
	    struct arcana_log_logs_read_output *out);
/*
 * ietf-syslog: syslog.conf conf, and the files it includes (under root,
 * NULL: the host's), with each file's rotation from newsyslog.conf
 * newsyslog (NULL: none); what the model cannot hold in *u (the
 * arena's), "file:line" and why.
 */
int	ysyslog_read(const char *root, const char *conf, const char *newsyslog,
	    cbl_yarena *a, struct ietf_syslog *out, struct yunread **u,
	    size_t *nu);

#define	SYSLOG_CONF		"/etc/syslog.conf"
#define	NEWSYSLOG_CONF		"/etc/newsyslog.conf"
#define	SYSLOG_ARCANA		"/usr/local/etc/syslog.d/arcana.conf"
#define	NEWSYSLOG_ARCANA	"/usr/local/etc/newsyslog.conf.d/arcana.conf"

/*
 * A commit of ietf-syslog (gula/ylog.c), planned on the files under root
 * as they are: Arcana's two files' text (NULL: not written), whether
 * syslog.conf and newsyslog.conf include them, the user's lines taken
 * over ("file:line", under root) and the log files to be made.  err
 * says what is refused.  ysyslog_take() comments the lines out;
 * ysyslog_check(): the files written read back as after asked.
 */
struct ysyslog_take {
	const char	*path;
	int		 line;
};
struct ysyslog_plan {
	bool			 changed;
	const char		*conf, *rot;
	bool			 included, rot_included;
	struct ysyslog_take	*take;
	size_t			 ntake;
	const char		**create;
	size_t			 ncreate;
};
int	ysyslog_plan(const char *root, const struct ietf_syslog *after,
	    cbl_yarena *a, struct ysyslog_plan *out, char *err, size_t errlen);
int	ysyslog_take(const struct ysyslog_plan *pl);
int	ysyslog_check(const char *root, const struct ietf_syslog *after,
	    char *err, size_t errlen);

/*
 * arcana-firewall (invidia/yfw.c): the network operation's ipfw kind
 * read back as the module has it (yfw_from_json()); the kept file as
 * the ipfw-rules operation reads it, its text and SHA-256, the rules,
 * other lines and aliases taken from the text (yfw_kept_from_text());
 * the fw-trace operation's packets as the trace action's output
 * (yfw_trace_from_json()).
 */
int	yfw_from_json(const char *json, cbl_yarena *a,
	    struct arcana_firewall_firewall *out);
int	yfw_kept_from_text(const char *text, const char *sha256,
	    cbl_yarena *a, struct arcana_firewall_firewall_kept *out);
int	yfw_trace_from_json(const char *json, cbl_yarena *a,
	    struct arcana_firewall_firewall_trace_output *out);

/*
 * arcana-troubleshoot (invidia/yts.c): the path-check, traceroute and
 * capture operations' JSON as the actions' outputs.
 */
int	yts_path_from_json(const char *json, cbl_yarena *a,
	    struct arcana_troubleshoot_troubleshoot_path_check_output *out);
int	yts_traceroute_from_json(const char *json, cbl_yarena *a,
	    struct arcana_troubleshoot_troubleshoot_traceroute_output *out);
int	yts_capture_from_json(const char *json, cbl_yarena *a,
	    struct arcana_troubleshoot_troubleshoot_capture_output *out);

/* ietf-hardware (superbia/yhw.c): the host's hardware read as JSON,
 * malloc'd, and that JSON as RFC 8348's components. */
int	yhw_json(char **jsonp);
int	yhw_from_json(const char *json, cbl_yarena *a,
	    struct ietf_hardware *out);

/* ietf-alarms (gula/yalarms.c): the faults' JSON (faults_json()) as
 * RFC 8632's alarms. */
int	yalarms_from_json(const char *json, cbl_yarena *a,
	    struct ietf_alarms *out);

/* arcana-history (gula/yhist.c): the history operation's JSON. */
int	yhist_from_json(const char *json, cbl_yarena *a,
	    struct arcana_history_history *out);

/* arcana-events (gula/yev.c): the events operation's JSON, and one
 * event's (the event mcast) as the notification. */
int	yev_from_json(const char *json, cbl_yarena *a,
	    struct arcana_events_events *out);
int	yev_one_from_json(const char *json, cbl_yarena *a,
	    struct arcana_events_event *out);

/*
 * arcana-bird (luxuria/ybird.c): what birdc says as the module's state
 * (the read action's output too), the routes and ospf actions'
 * output.
 */
int	ybird_from_json(const char *json, cbl_yarena *a,
	    struct arcana_bird_state *out);
int	ybird_routes_from_json(const char *json, cbl_yarena *a,
	    struct arcana_bird_routes *out);
int	ybird_ospf_from_json(const char *json, cbl_yarena *a,
	    struct arcana_bird_ospf *out);

/* arcana-wireguard (invidia/ywg.c): wg's interfaces, *nifp of them in
 * *ifp, when read in *now. */
int	ywg_from_json(const char *json, cbl_yarena *a, const char **now,
	    size_t *nifp, const struct arcana_wireguard_interface **ifp);

/* arcana-netgraph (invidia/yng.c): ngctl's nodes, *np of them in *vp. */
int	yng_from_json(const char *json, cbl_yarena *a, size_t *np,
	    const struct arcana_netgraph_node **vp);

/*
 * arcana-host (superbia/yhost.c): the host attribute set with the
 * stats (st NULL: none), and the trust store's JSON as the
 * read-certificates action's output (yhost_certs_from_json()).
 */
struct host_facts;
struct host_stats;
int	yhost_certs_from_json(const char *json, cbl_yarena *a,
	    struct arcana_host_host_read_certificates_output *out);
int	yhost_from(const struct host_facts *h, const struct host_stats *st,
	    cbl_yarena *a, struct arcana_host_host *out);

/*
 * arcana-agent (superbia/yagent.c): the transport and tls operations'
 * JSON as state; config-export's bundle and config-apply's report, and
 * source-log's commits and tags, as the actions' outputs; the apply's
 * bundle as the JSON config-export writes.
 */
int	yagent_transport_from_json(const char *json, cbl_yarena *a,
	    struct arcana_agent_agent_transport *out);
int	yagent_tls_from_json(const char *json, cbl_yarena *a,
	    struct arcana_agent_agent_tls *out);
int	yagent_bundle_from_json(const char *json, cbl_yarena *a,
	    struct arcana_agent_agent_config_export_output *out);
char	*yagent_bundle_json(
	    const struct arcana_agent_agent_config_apply_input_bundle *b);
int	yagent_apply_from_json(const char *json, cbl_yarena *a,
	    struct arcana_agent_agent_config_apply_output *out);
int	yagent_log_from_json(const char *commit, const char *log,
	    const char *tags, cbl_yarena *a,
	    struct arcana_agent_agent_source_log_output *out);

/*
 * arcana-jail-files (ira/yjf.c): the files' JSON (do_jail_files()) as
 * the read-files action's output.
 */
int	yjf_from_json(const char *json, cbl_yarena *a,
	    struct arcana_jails_jails_arcjf_read_files_output *out);

/*
 * arcana-probe (gula/yprobe.c): the edges' targets, links and monitors
 * (probe_conf_json()) as configuration; an edge's (jail NULL or "" the
 * host's) targets and links, or its monitors, as the JSON
 * do_probes_set() and do_monitors_set() take, malloc'd; the sdwan
 * read's targets as state.
 */
int	yprobe_conf_from_json(const char *json, cbl_yarena *a,
	    struct arcana_probe_probes *out);
char	*yprobe_edge_json(const char *jail, size_t nt,
	    const struct arcana_probe_target *tv, size_t nl,
	    const struct arcana_probe_link *lv);
char	*yprobe_monitors_json(const char *jail, size_t n,
	    const struct arcana_probe_monitor *v);
int	yprobe_state_from_json(const char *json, cbl_yarena *a,
	    struct arcana_probe_probes_state *out);

/*
 * arcana-sdwan (invidia/ysd.c): what the setters keep (an edge's rules
 * and steer, the instances of each kind) as configuration, and back as
 * the JSON they take, malloc'd: an edge's (jail NULL or "" the host's)
 * rules (none: emptied, in set), steer, or instances of a kind, for
 * the proxies and the IDS those of a group (1 the Security section's,
 * sec-; 0 SD-WAN's; -1 all), NULL and *errp for a spec that is no JSON
 * object; the sdwan read as state.  The plain instances (bird, dhcp,
 * dns) have one layout.
 */
#define	YSD_PLAIN	0
#define	YSD_PROXY	1
#define	YSD_IDS		2
int	ysd_rules_from_json(const char *json, cbl_yarena *a,
	    struct arcana_sdwan_rules_config *out);
int	ysd_steer_from_json(const char *json, cbl_yarena *a,
	    struct arcana_sdwan_steer_config *out);
int	ysd_instances_from_json(const char *json, int kind, cbl_yarena *a,
	    size_t *np, const void **vp);
char	*ysd_rules_json(const char *jail,
	    const struct arcana_sdwan_rules_config *r, unsigned set);
char	*ysd_steer_json(const char *jail,
	    const struct arcana_sdwan_steer_config *s);
char	*ysd_instances_json(int kind, const char *jail, int group, size_t n,
	    const void *v, const char **errp);
int	ysd_state_from_json(const char *json, cbl_yarena *a,
	    struct arcana_sdwan_sdwan_state *out);

/* arcana-sshd (superbia/ysshd.c): the ssh operation's JSON. */
int	ysshd_from_json(const char *json, cbl_yarena *a,
	    struct arcana_sshd_sshd *out);

/* arcana-builder (luxuria/ybuilder.c): the builder and builder-options
 * operations' JSON. */
int	ybuilder_from_json(const char *json, cbl_yarena *a,
	    struct arcana_builder_builder *out);
int	ybuilder_options_from_json(const char *json, cbl_yarena *a,
	    struct arcana_builder_builder_port_options_output *out);

/* running and the candidate, by confirmed commit (invidia/ynetconf.c). */
int	ynetconf_datastores(cbl_ctx *);

/* The models served (invidia/yserve.c, yarcana.c).  ywork(): the work
 * of a read, freed with the answer's arena; ywork_told(): one whose
 * steps the requester hears (the steps group), its root step what. */
int	yang_serve(cbl_ctx *);
struct work *ywork(cbl_yarena *a);
struct work *ywork_told(cbl_req *req, cbl_yarena *a, const char *what,
	    int *root);

/*
 * arcana-network (invidia/ynet.c): ynet_node(), node path ("a/b", or
 * NULL) under module mod's top-level node top; ynet_decode(), JSON v
 * made the struct out of node on (an output, a structure), a's, what
 * the model has no node or type for left out.
 */
struct ucl_object_s;
const struct cbl_ynode *ynet_node(const char *mod, const char *top,
	    const char *path);
/* arcana-firewall's firewall where w is (yarcana.c): EIO and *errp, ipfw's. */
int	yfw_read(struct work *w, cbl_yarena *a,
	    struct arcana_firewall_firewall **op, const char **errp);
int	ynet_decode(const struct cbl_ynode *on, const struct ucl_object_s *v,
	    void *out, cbl_yarena *a);

#endif	/* !_ARCANA_COLLECT_H_ */
