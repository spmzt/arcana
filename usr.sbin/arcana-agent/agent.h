/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _AGENT_H_
#define _AGENT_H_

#include <sys/types.h>
#include <sys/socket.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* Generated into the object directory; <> so that a stale copy next
 * to the sources is never picked up. */
#include <arcana.h>

#define	ARCANA_AGENT_VERSION	"0.91.0"

#define	PATH_JAIL_CONF		"/etc/jail.conf"
#define	PATH_JAIL_CONF_D	"/etc/jail.conf.d"
#define	PATH_JAIL_BIN		"/usr/sbin/jail"
#define	PATH_RC_DIRS		"/etc/rc.d:/usr/local/etc/rc.d"
#define	PATH_SERVICE_BIN	"/usr/sbin/service"
#define	PATH_SYSRC_BIN		"/usr/sbin/sysrc"
#define	PATH_NETSTAT_BIN	"/usr/bin/netstat"
#define	PATH_SWAPINFO_BIN	"/usr/sbin/swapinfo"
#define	PATH_ZPOOL_BIN		"/sbin/zpool"
#define	PATH_PKG_BIN		"/usr/sbin/pkg"
#define	PATH_GIT_BIN		"/usr/local/bin/git"
#define	PATH_TRACEROUTE_BIN	"/usr/sbin/traceroute"
#define	PATH_IFCONFIG_BIN	"/sbin/ifconfig"
#define	PATH_NGCTL_BIN		"/usr/sbin/ngctl"
#define	PATH_JLS_BIN		"/usr/sbin/jls"
#define	PATH_JEXEC_BIN		"/usr/sbin/jexec"
#define	PATH_KLDLOAD_BIN	"/sbin/kldload"
#define	PATH_KLDUNLOAD_BIN	"/sbin/kldunload"
#define	PATH_ZFS_BIN		"/sbin/zfs"
#define	PATH_GPART_BIN		"/sbin/gpart"
#define	PATH_CAMCONTROL_BIN	"/sbin/camcontrol"
#define	PATH_MOUNT_BIN		"/sbin/mount"
#define	PATH_UMOUNT_BIN		"/sbin/umount"
#define	PATH_FSTAB		"/etc/fstab"
#define	PATH_WG_BIN		"/usr/local/bin/wg"
#define	PATH_WG_BASE_BIN	"/usr/bin/wg"	/* FreeBSD 15 and later */
#define	PATH_WG_DIR		"/usr/local/etc/wireguard"
#define	PATH_SWANCTL_BIN	"/usr/local/sbin/swanctl"
#define	PATH_SQUID_BIN		"/usr/local/sbin/squid"
#define	PATH_CICAP_BIN		"/usr/local/bin/c-icap"
#define	PATH_SURICATA_BIN	"/usr/local/bin/suricata"
#define	PATH_CICAP_MODULES	"/usr/local/lib/c_icap"
#define	PATH_CLAMAV_DB		"/var/db/clamav"
#define	PATH_SWANCTL_DIR	"/usr/local/etc/swanctl"
#define	PATH_BIRDC_BIN		"/usr/local/sbin/birdc"
#define	PATH_BIRD_BIN		"/usr/local/sbin/bird"
#define	PATH_SETFIB_BIN		"/usr/sbin/setfib"
#define	PATH_NTP_CONF		"/etc/ntp.conf"
#define	PATH_RTADVD_CONF	"/etc/rtadvd.conf"
#define	PATH_DNSMASQ_BIN	"/usr/local/sbin/dnsmasq"
#define	PATH_UNBOUND_BIN	"/usr/sbin/local-unbound"
#define	PATH_RTSOL_BIN		"/sbin/rtsol"
#define	PATH_SETKEY_BIN		"/sbin/setkey"
#define	PATH_BIRD_CONF		"/usr/local/etc/bird.conf"
#define	OWN_SERVICE		"arcana_agent"	/* the rc.d name of this daemon */
#define	PATH_MAKE_BIN		"/usr/bin/make"
#define	PATH_KEYSCAN_BIN	"/usr/bin/ssh-keyscan"
#define	PATH_KEYGEN_BIN		"/usr/bin/ssh-keygen"
#define	PATH_BUILD_DIR		"/var/cache/arcana-build"
#define	PATH_BUILD_CONF		"/usr/local/etc/arcana/config.mk"

/* jail -e separator: ASCII unit separator, never in a jail.conf value. */
#define	JAIL_E_SEP		"\037"

#define	EXEC_TIMEOUT_SEC	3600	/* a pkg upgrade can take a while */
#define	TRACE_MAX		ARC_MAX_STEPS
#define	TRACE_DEPTH		16

struct opts {
	const char	*jail_conf;
	const char	*jail_conf_d;
	const char	*jail_bin;
	const char	*rc_dirs;	/* colon separated */
	const char	*service_bin;
	const char	*sysrc_bin;
	const char	*netstat_bin;
	const char	*swapinfo_bin;
	const char	*zpool_bin;
	const char	*pkg_bin;
	const char	*self_path;	/* the program an update replaces */
	const char	*ifconfig_bin;
	const char	*ngctl_bin;
	const char	*jls_bin;
	const char	*jexec_bin;
	const char	*kldload_bin;
	const char	*kldunload_bin;
	const char	*zfs_bin;
	const char	*gpart_bin;
	const char	*camcontrol_bin;
	const char	*mount_bin;
	const char	*umount_bin;
	const char	*fstab_path;
	const char	*sysctl_bin;
	const char	*ipfw_bin;
	const char	*ipfw_rules;
	const char	*sysctl_conf;
	const char	*log_dir;	/* where syslogd(8) writes */
	const char	*history_conf;	/* how the host is sampled */
	const char	*tools_dir;	/* where programs without an option are */
	const char	*helper_bin;	/* this program, run again with -Q */
	bool		 helper_self;	/* it is this program: the host's own is read here */
	const char	*wg_bin;
	const char	*wg_dir;	/* where wg-quick(8) reads from */
	const char	*swanctl_bin;
	const char	*squid_bin;	/* squid(8): the proxies, a plugin */
	const char	*cicap_bin;	/* c-icap: malware scanning, a plugin */
	const char	*suricata_bin;	/* suricata: intrusion detection, a plugin */
	const char	*swanctl_dir;	/* where swanctl(8) reads from */
	const char	*birdc_bin;
	const char	*bird_bin;	/* bird(8), to parse a configuration */
	const char	*setfib_bin;	/* setfib(1): a daemon in a table */
	const char	*ntp_conf;	/* ntp.conf, for the ntp job */
	const char	*rtadvd_conf;	/* rtadvd.conf, for the rtadvd job */
	const char	*dnsmasq_bin;	/* dnsmasq(8): the UNIs' DHCP */
	const char	*unbound_bin;	/* local-unbound(8): the DNS filters */
	const char	*rtsol_bin;	/* rtsol(8): an interface's SLAAC */
	const char	*setkey_bin;	/* setkey(8): manual SAs */
	const char	*bird_conf;	/* its main file */
	int		 safe_wait;	/* s, for a safe change to be confirmed */
	const char	*git_bin;
	const char	*traceroute_bin;	/* and the same with 6 */
	const char	*keyscan_bin;	/* ssh-keyscan(1) */
	const char	*keygen_bin;	/* ssh-keygen(1) */
	const char	*make_bin;
	const char	*build_dir;	/* where a tree is cloned and built */
	const char	*build_conf;	/* this host's config.mk for it */
	char		 build[65];	/* SHA-256 of the running program */
	bool		 debug;
};

extern struct opts opts;

/*
 * work.c: one request.  Everything a reply points to is allocated from
 * the request's pool and released with it, and the request records what
 * it did in its own trace.
 */
struct step {
	uint8_t		 kind;		/* ARC_STEP_KIND_* */
	const char	*label;
	const char	*detail;
	int		 parent;
	bool		 done;
	bool		 ok;
	uint64_t	 start;
	uint64_t	 dur;
	const char	**argv;
	size_t		 argc;
	int		 status;
	const char	*out;
	size_t		 outlen;
	const char	*err;
	size_t		 errlen;
};

struct work {
	void		**ptrs;		/* allocations owned by the request */
	size_t		 nptrs;
	size_t		 capptrs;
	struct step	 steps[TRACE_MAX];
	int		 nsteps;
	int		 stack[TRACE_DEPTH];
	int		 depth;
	/* The jail whose network the request is about; NULL the host's. */
	const char	*jail;
	int		 jid;
	const char	*jroot;
	/*
	 * A job's trace is read by other threads while the job runs: the
	 * step functions change it under this lock, and trace_copy() of
	 * this work into another reads it under it.
	 */
	pthread_mutex_t	 lock;
};

void		 work_init(struct work *);
void		 work_free(struct work *);
void		*wadopt(struct work *, void *);
void		*wmalloc(struct work *, size_t);
void		*wcalloc(struct work *, size_t, size_t);
char		*wstrdup(struct work *, const char *);
char		*wstrndup(struct work *, const char *, size_t);
char		*wfmt(struct work *, const char *, ...) __printflike(2, 3);
char		*wvis(struct work *, const char *);
const char	*wtext(struct work *, const char *);

int		 step_begin(struct work *, uint8_t, const char *,
		    const char *, ...) __printflike(4, 5);
void		 step_end(struct work *, int, bool, const char *, ...)
		    __printflike(4, 5);
void		 step_exec(struct work *, int, char *const [], int,
		    const char *, size_t, const char *, size_t);
void		 trace_steps(struct work *, const struct arc_step **, size_t *);
void		 trace_copy(struct work *, struct work *,
		    const struct arc_step **, size_t *);
uint64_t	 now_us(void);

/* ira/exec.c: run a program without a shell, capturing its output. */
struct execres {
	int		 status;	/* exit status, 128 + signal, or -1 */
	const char	*out;
	size_t		 outlen;
	const char	*err;
	size_t		 errlen;
	bool		 truncated;	/* more output than was kept */
};

int		 run_exec(struct work *, char *const [], struct execres *);
void		 exec_set_home(struct work *, const char *);
void		 exec_set_secret(bool);
int		 run_exec_lines(struct work *, char *const [],
		    void (*)(const char *, void *), void *);
int		 run_exec_max(struct work *, char *const [], struct execres *,
		    size_t);
const char	*exec_error(struct work *, const struct execres *,
		    const char *);

/* ira/jails.c: running jails (libjail) and their processes (libprocstat). */
struct jinfo {
	int		 jid;
	const char	*name;
	const char	*hostname;
	const char	*path;
	const char	*ip4;		/* comma separated */
	const char	*ip6;
	const char	*osrelease;
	bool		 vnet;
	bool		 dying;
	bool		 persist;
	int		 parent;
	int		 children;
	int		 securelevel;
	uint32_t	 nproc;
	uint64_t	 rss_kb;
	double		 cpu_pct;
};

int		 jails_running(struct work *, struct jinfo **, size_t *,
		    const char **);
void		 jails_procstats(struct work *, struct jinfo *, size_t);
int		 jail_lookup(struct work *, const char *);

/* superbia/confread.c: configured jails, as jail(8) -e resolves them. */
struct cjail {
	const char	*name;
	const char	*scope;		/* file to give jail(8) -f */
	struct arc_param	*params;
	size_t		 nparams;
};

struct cconf {
	const char	**scopes;
	size_t		 nscopes;
	struct cjail	*jails;
	size_t		 njails;
	struct arc_conf_error *errors;
	size_t		 nerrors;
};

void		 conf_read(struct work *, struct cconf *);
int		 conf_scope_read(struct work *, const char *, struct cjail **,
		    size_t *, const char **);
const struct cjail *conf_jail(const struct cconf *, const char *);
const struct arc_param *cjail_param(const struct cjail *, const char *);
const char	*cjail_param1(const struct cjail *, const char *);

/* superbia/host.c */
void		 host_info(struct work *, struct arc_host *);

/* ira/jail.c: one jail record from runtime and configured state. */
void		 jail_record(struct work *, struct arc_jail *, const char *,
		    const struct jinfo *, const struct cjail *);
struct arc_jail	*jail_current(struct work *, const char *,
		    const struct cconf *);

/* ira/lifecycle.c, invidia/address.c */
int		 do_list(struct work *, bool, struct arc_list_rsp *);
int		 do_action(struct work *, const char *, uint8_t,
		    struct arc_action_rsp *);
/* ira/jailmake.c: jails made and taken away, their defaults, templates */
const char	*jail_conf_check(const struct arc_job_spec *);
int		 do_jail_conf(struct work *, const struct arc_job_spec *,
		    const char **);
void		 do_jail_files(struct work *, struct arc_jail_files_rsp *);

/* superbia/certs.c: the certificates OpenSSL trusts */
void		 do_certs(struct work *, struct arc_certs_rsp *);
const char	*cert_check(const struct arc_job_spec *);
int		 do_cert(struct work *, const struct arc_job_spec *,
		    const char **);

/* superbia/ssh.c: the base system's sshd */
void		 do_ssh(struct work *, struct arc_ssh_rsp *);
const char	*ssh_check(const struct arc_job_spec *);
int		 do_ssh_job(struct work *, const struct arc_job_spec *,
		    const char **);
int		 ssh_undo(struct work *, const struct arc_job_spec *,
		    const char **);
/* invidia/neigh.c: a neighbour set by hand, or taken away */
const char	*neigh_check(const struct arc_job_spec *);
int		 do_neigh(struct work *, const struct arc_job_spec *,
		    const char **);
int		 do_address(struct work *, const struct arc_address_req *,
		    struct arc_address_rsp *);

/* ira/services.c */
int		 do_services(struct work *, struct arc_services_rsp *);
int		 do_service_action(struct work *, const char *, uint8_t,
		    struct arc_service_action_rsp *);
int		 do_service_config(struct work *,
		    const struct arc_service_config_req *,
		    struct arc_service_config_rsp *);
void		 service_state(struct work *, const char *, bool *, bool *);

/* invidia/network.c */
int		 do_network(struct work *, uint8_t, uint8_t, const char *,
		    uint32_t, uint32_t, struct arc_network_rsp *);
int		 do_route_lookup(struct work *, const char *, uint32_t,
		    struct arc_route_lookup_rsp *);
int		 do_traceroute(struct work *, const char *,
		    struct arc_traceroute_rsp *);

/* invidia/interfaces.c */
int		 do_interfaces(struct work *, uint8_t, struct arc_network_rsp *);
int		 do_if_address(struct work *, const char *, const char *, bool,
		    bool, const char **);
int		 do_if_state(struct work *, const char *, bool, const char **);
/* What an if-set changes: 0, -1 and NULL leave each as it is. */
struct if_change {
	unsigned int	 mtu;
	const char	*descr;		/* "" takes it off */
	int		 fib;
	int		 tunnelfib;
	const char	*addressing;	/* dhcp, slaac or static; NULL as is */
};
int		 do_if_set(struct work *, const char *,
		    const struct if_change *, bool, const char **);
int		 do_if_create(struct work *, const struct arc_job_spec *,
		    const char **, const char **);
int		 do_if_destroy(struct work *, const char *, bool, const char **);
void		 if_current(struct work *, const char *, unsigned int *, int *,
		    int *, char *, size_t);
bool		 if_is_up(struct work *, const char *, bool *);
bool		 if_exists(struct work *, const char *);
const char	*if_json(struct work *);
bool		 if_owning(const struct sockaddr *, char *, size_t);
const char	*if_address_with_prefix(struct work *, const char *,
		    const char *);

/* invidia/routes.c */
/* What a route has besides where it leads. */
struct route_more {
	uint32_t	 metric;	/* 0: the system's */
	uint32_t	 weight;
	const char	*source;	/* the address sent from, or NULL */
};
int		 do_route(struct work *, const char *, const char *, bool,
		    uint32_t, const struct route_more *, bool, const char **);

/* invidia/rcconf.c: what of the network rc.conf keeps. */
bool		 rc_name_ok(const char *);
bool		 rc_value_ok(const char *);
const char	*rc_ifname(struct work *, const char *);
const char	*rc_get(struct work *, const char *);
int		 rc_set(struct work *, const char *, const char *, const char *,
		    const char **);
void		 rc_unset(struct work *, const char *);
int		 rc_alias(struct work *, const char *, const char *,
		    const char *, const char *, bool, const char **);
int		 rc_word(struct work *, const char *, const char *,
		    const char *, const char **);
void		 rc_forget_if(struct work *, const char *);

/* luxuria/wireguard.c: a plugin, through wg(8). */
int		 do_wireguard(struct work *, struct arc_network_rsp *);
const char	*wg_check(struct work *, const struct arc_job_spec *);
int		 do_wg(struct work *, const struct arc_job_spec *,
		    const char **);
void		 wg_forget(struct work *, const char *);
bool		 wg_key_ok(const char *);

/* luxuria/ipsec.c: a plugin, strongSwan through swanctl(8). */
int		 do_ipsec(struct work *, struct arc_network_rsp *);
const char	*ipsec_check(const struct arc_job_spec *);
int		 do_ipsec_job(struct work *, const struct arc_job_spec *,
		    const char **);

/* luxuria/bird.c: a plugin, through birdc(8). */
int		 do_bird(struct work *, struct arc_network_rsp *);
const char	*bird_check(const char *, const char *const *, size_t);
int		 do_bird_verb(struct work *, const char *, const char *const *,
		    size_t, const char **);
int		 do_bird_config(struct work *,
		    const struct arc_bird_config_req *,
		    struct arc_bird_config_rsp *);

/* invidia/scope.c: the network of a vnet jail, from the host. */
int		 scope_enter(struct work *, const char *, const char **);
int		 scope_enter_jail(struct work *, const char *, const char **,
		    bool);
int		 do_bird_routes(struct work *, const char *,
		    struct arc_network_rsp *);
/* superbia/kernel.c: the kernel's modules and memory. */
int		 do_kernel(struct work *, struct arc_kernel_rsp *);
int		 do_kmod(struct work *, const char *, const char *, bool,
		    const char **);
bool		 kmod_name_ok(const char *);

/* superbia/ntp.c: the NTP servers. */
int		 do_ntp(struct work *, const char *const *, size_t, bool, bool,
		    const char **);
bool		 ntp_server_ok(const char *);
/* gula: what runs, what was written down, how busy it has been. */
int		 do_processes(struct work *, const char *,
		    struct arc_processes_rsp *);
const char	*proc_check(const struct arc_job_spec *);
char		*proc_title(const struct arc_job_spec *);
int		 do_proc_job(struct work *, const struct arc_job_spec *,
		    const char **);
bool		 log_name_ok(const char *);
int		 do_log(struct work *, const char *, const char *, bool,
		    uint64_t, uint32_t, struct arc_log_rsp *);
void		 history_start(void);
int		 do_history(struct work *, uint64_t, bool, uint32_t, uint32_t,
		    const uint32_t *, const char *, struct arc_history_rsp *);
/* gula/kmsg.c: the kernel's messages, numbered as they come. */
struct kmsg_line {
	uint64_t	 n;
	time_t		 t;
	char		*text;
};
void		 kmsg_start(void);
bool		 kmsg_lines(struct work *, uint64_t, const char *, uint32_t,
		    struct kmsg_line **, size_t *, uint64_t *);
void		 history_save(void);
/* gula/probe.c: the tunnels measured, ICMP echo again and again. */
enum { PROBE_NONE = -1, PROBE_UNKNOWN, PROBE_UP, PROBE_DOWN, PROBE_ENDED,
    PROBE_ERROR };
void		 probe_start(void);
int		 do_probes_set(struct work *, const char *, const char **);
int		 do_sdwan(struct work *, uint64_t, struct arc_sdwan_rsp *);
int		 probe_state_of(const char *);
/* invidia/sdwan.c: the rules that steer, and the steering. */
void		 sdwan_start(void);
int		 do_sdwan_rules(struct work *, const char *, const char **);
int		 do_sdwan_steer(struct work *, const char *, const char **);
void		 sdwan_probe_changed(void);
struct ucl_object_s;
void		 sdwan_json(struct work *, struct ucl_object_s *);
const char	*sdwan_conf_path(const char *, char *, size_t);
int		 sdwan_conf_write(const char *, const char *, const char **);
char		*sdwan_kept_read(const char *);

/* luxuria/sdbird.c: a BIRD instance of each service, at the UNIs. */
int		 do_sdwan_bird(struct work *, const char *, const char **);
void		 sdwan_bird_start(void);
void		 sdwan_bird_json(struct work *, struct ucl_object_s *);
int		 do_sdwan_dhcp(struct work *, const char *, const char **);
void		 sdwan_dhcp_start(void);
void		 sdwan_dhcp_json(struct work *, struct ucl_object_s *);
int		 do_sdwan_dns(struct work *, const char *, const char **);
void		 sdwan_dns_start(void);
void		 sdwan_dns_json(struct work *, struct ucl_object_s *);
/* luxuria/sdproxy.c: the services' proxies, Squid. */
int		 do_sdwan_proxy(struct work *, const char *, const char **);
void		 sdwan_proxy_start(void);
void		 sdwan_proxy_json(struct work *, struct ucl_object_s *);
int		 do_sdwan_ids(struct work *, const char *, const char **);
void		 sdwan_ids_start(void);
void		 sdwan_ids_json(struct work *, struct ucl_object_s *);
int		 do_rtadvd(struct work *, const char *, const char *const *,
		    size_t, bool, bool, const char **);
/* invidia/sa.c: manually keyed SAs by setkey(8). */
const char	*sa_check(const struct arc_job_spec *);
int		 do_sa_job(struct work *, const struct arc_job_spec *,
		    const char **);
void		 sa_keys_json(struct work *, struct ucl_object_s *);
bool		 rtadvd_prefix_ok(const char *);
int		 sdwan_bfd_state(const char *);
const char	*sdwan_tunnel_by_via(const char *);

/* gula/faults.c: the faults, kept a day. */
void		 fault_set(const char *, const char *, const char *, const char *,
		    const char *, ...) __printflike(5, 6);
void		 fault_clear(const char *, const char *, const char *, ...)
		    __printflike(3, 4);
void		 faults_json(struct ucl_object_s *);
void		 faults_start(void);
/* gula/record.c: what the security rules logged, a day of it. */
void		 record_start(void);
void		 record_json(struct ucl_object_s *);
int		 do_process(struct work *, uint32_t, struct arc_processes_rsp *);

int		 do_sysctl(struct work *, const char *,
		    struct arc_sysctl_rsp *);
int		 do_sysctl_set(struct work *, const char *, const char *, bool,
		    const char **);
bool		 sysctl_name_ok(const char *);
bool		 valid_jail(const char *);
bool		 sysctl_part(struct cbl_dump_state *, const char *, char **,
		    uint64_t *);
bool		 sysctl_value_ok(const char *);
int		 do_l2(struct work *, bool, struct arc_network_rsp *);
const char	*bridge_holding(struct work *, const char *);
const char	*l2_check(const struct arc_job_spec *);
char		*l2_title(const struct arc_job_spec *);
int		 do_l2_job(struct work *, const struct arc_job_spec *,
		    const char **);
int		 do_ipfw(struct work *, struct arc_network_rsp *);
int		 do_fw_trace(struct work *, const char *, uint32_t, uint32_t,
		    struct arc_fw_trace_rsp *);
int		 do_ipfw_rules(struct work *, const struct arc_ipfw_rules_req *,
		    struct arc_ipfw_rules_rsp *);
const char	*ipfw_check(const struct arc_job_spec *);
char		*ipfw_title(const struct arc_job_spec *);
int		 do_ipfw_job(struct work *, const struct arc_job_spec *, bool *,
		    const char **);
const char	*ipfw_settle(struct work *, bool);
const char	*ipfw_unadd(struct work *, const struct arc_job_spec *);
int		 transport_watch(cbl_ctx *);
void		 transport_add(const char *, cbl_listener *);
void		 transport_init(cbl_ctx *, cbl_loop *, cbl_tls *);
int		 do_transport(struct work *, bool, struct arc_transport_rsp *);
bool		 kmod_loaded(const char *);

/* acedia/storage.c: disks, pools, datasets, mounts. */
int		 do_storage(struct work *, uint8_t, const char *,
		    struct arc_storage_rsp *);
int		 do_fstab(struct work *, const struct arc_fstab_req *,
		    struct arc_fstab_rsp *);
char		**storage_argv(struct work *, const struct arc_job_spec *,
		    const char **);
const char	*storage_check(const struct arc_job_spec *);
char		*storage_title(const struct arc_job_spec *);
int		 do_storage_job(struct work *, const struct arc_job_spec *,
		    const char **);

/* luxuria/plugins.c */
void		 plugins_there(struct work *, int, const char *,
		    const char *const **, size_t *);
const char	*plugin_bin(struct work *, const char *);
void		 plugins_forget(void);
extern const char wg_base_bin[];
int		 do_if_vnet(struct work *, const char *, const char *, bool,
		    bool, const char **);
char *const	*scope_argv(struct work *, char *const []);
char *const	*scope_jexec(struct work *, char *const []);
int		 scope_dirfd(struct work *, const char *);
int		 scope_open_dir(struct work *, const char *, const char **);
char		*scope_slurp(struct work *, const char *, size_t *);
int		 scope_replace(struct work *, const char *, const char *,
		    size_t, mode_t, const char *);
int		 scope_rename(struct work *, const char *, const char *,
		    const char *);
int		 scope_helper(int, char **);
const char	*scope_missing(struct work *, const struct execres *,
		    const char *, const char *);
char		*ifq_text(const char *, const char *, const char *);
char		**helper_argv(struct work *, const char *, size_t,
		    const char *const []);
int		 route_helper(int, char **);
int		 route_list(FILE *, int, uint32_t, const char *, const char *);
int		 route_lookup(FILE *, const char *, uint32_t);
int		 neigh_list(FILE *, int, const char *);
int		 route_socket(void);
int		 helper_netlink(int);
int		 jail_jid_name(int, char *, size_t, char *, size_t);
int		 jail_next(int);
int		 pcb_helper(int, char **);
int		 pcb_list(FILE *, bool, int);
int		 helper_lines(struct work *, const char *, size_t,
		    const char *const [], void (*)(const char *, void *), void *);
struct cbl_dump_state;
struct arc_network_dump_req;
bool		 network_part(struct cbl_dump_state *,
		    const struct arc_network_dump_req *, char **, uint64_t *,
		    const char **);
struct ucl_object_s;
int		 network_routes(const char *, struct arc_route **, size_t *,
		    struct ucl_object_s **);
void		 network_routes_free(struct ucl_object_s *);
int		 zfs_pipe(int, char **);
const char	*tool(struct work *, const char *);
int		 do_health(struct work *, struct arc_storage_rsp *);
struct ucl_object_s;
struct ucl_object_s *swap_list(struct work *);
void		 route_watch_start(void);
void		 event_add(const char *, const char *, ...) __printflike(2, 3);
void		 event_family(cbl_family *);
void		 event_add_jail(const char *, const char *, const char *, ...)
		    __printflike(3, 4);
int		 do_events(struct work *, uint64_t, struct arc_events_rsp *);

/* invidia/netgraph.c */
int		 do_netgraph(struct work *, struct arc_network_rsp *);
const char	*ng_check(const char *, const char *const *, size_t);
int		 do_ng(struct work *, const char *, const char *const *, size_t,
		    const char **);

/* gula/stats.c */
int		 do_stats(struct work *, struct arc_stats_rsp *);

/* ira/packages.c */
int		 do_packages(struct work *, const char *, bool, bool, uint8_t,
		    struct arc_packages_rsp *);
int		 do_pkg_upgrade(struct work *, const struct arc_pkg_upgrade_req *,
		    struct arc_pkg_upgrade_rsp *);
int		 do_pkg_clean(struct work *, const char *, bool, const char **);
int		 do_pkg_install(struct work *, const struct arc_job_spec *,
		    const char **);

/* ira/jobs.c: queued changes, run in order whoever is or is not connected. */
void		 jobs_init(void);
int		 jobs_submit(const struct arc_job_spec *, size_t, const char *,
		    struct work *, const struct arc_job **, size_t *);
void		 jobs_list(struct work *, const struct arc_job **, size_t *);
size_t		 jobs_waiting(void);
const struct arc_job *jobs_get(struct work *, uint64_t);
const struct arc_job *jobs_cancel(struct work *, uint64_t, const char **);
const struct arc_job *jobs_confirm(struct work *, uint64_t, const char **);

/* handlers.c */
/* invidia/address.c, superbia/confedit.c */
int		 ifaddr_change(struct work *, const char *, int, const void *,
		    int, bool, const char **);
const char	*list_edit(struct work *, const char *, const char *,
		    const char *, bool);
bool		 list_has(const char *, const char *, const char *);
int		 write_backup(struct work *, const char *, const char *, size_t,
		    const char **);
bool		 verify_jail8(struct work *, const char *, const char *,
		    const char *, const char *, bool);

/* avaritia/resources.c, acedia/pools.c */
void		 resources_measure(struct work *, struct arc_stats *);
void		 pools_measure(struct work *, struct arc_stats *);

/* ira/build.c */
int		 do_agent_build(struct work *, const char *, const char *,
		    const char *, const char *, struct arc_agent_build_rsp *);
int		 do_source_head(struct work *, const char *, const char *,
		    const char *, const char *, struct arc_source_head_rsp *);
int		 do_source_log(struct work *, const char *, const char *,
		    const char *, const char *, uint32_t,
		    struct arc_source_log_rsp *);

int		 do_console_update(struct work *, const char *, const char *,
		    const char *, const char *, struct arc_console_update_rsp *);

/* ira/update.c */
int		 do_agent_update(struct work *, const uint8_t *, size_t,
		    const char *, struct arc_agent_update_rsp *);
void		 service_restart(const char *);
void		 service_detached(const char *, const char *);

bool		 change_note(const char *, ...) __printflike(1, 2);
void		 changes_stop(bool);
void		 changes_log(int);
void		 jobs_log(int);
void		 jobs_wake(void);
bool		 changes_stopping(void);
const char	*changes_current(struct work *, time_t *);

extern pthread_mutex_t	change_lock;	/* one change at a time */

/* main.c */
void		 logmsg(int, const char *, ...) __printflike(2, 3);

#endif /* !_AGENT_H_ */
