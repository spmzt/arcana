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

#define	ARCANA_AGENT_VERSION	"0.231.0"

/* The nice(1) value of a program a read runs. */
#define	READ_NICE		10

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
#define	PATH_JEXEC_BIN		"/usr/sbin/jexec"
#define	PATH_KLDLOAD_BIN	"/sbin/kldload"
#define	PATH_KLDUNLOAD_BIN	"/sbin/kldunload"
#define	PATH_ZFS_BIN		"/sbin/zfs"
#define	PATH_GPART_BIN		"/sbin/gpart"
#define	PATH_CAMCONTROL_BIN	"/sbin/camcontrol"
#define	PATH_MOUNT_BIN		"/sbin/mount"
#define	PATH_UMOUNT_BIN		"/sbin/umount"
#define	PATH_FSTAB		"/etc/fstab"
#define	PATH_WG_BIN		"/usr/bin/wg"
#define	PATH_WG_DIR		"/usr/local/etc/wireguard"
#define	PATH_SWANCTL_BIN	"/usr/local/sbin/swanctl"
#define	PATH_SQUID_BIN		"/usr/local/sbin/squid"
#define	PATH_CICAP_BIN		"/usr/local/bin/c-icap"
#define	PATH_SURICATA_BIN	"/usr/local/bin/suricata"
#define	SURICATA_ETC		"/usr/local/etc/suricata"
#define	PATH_POUDRIERE_BIN	"/usr/local/bin/poudriere"
#define	PATH_IFMCSTAT_BIN	"/usr/sbin/ifmcstat"
#define	PATH_RTADVCTL_BIN	"/usr/sbin/rtadvctl"
#define	PATH_FRESHCLAM_CONF	"/usr/local/etc/freshclam.conf"
#define	PATH_SURICATA_RULES	"/var/lib/suricata/rules"
#define	PATH_POUDRIERE_ETC	"/usr/local/etc"
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
/*
 * pkg is stopped when nothing has come from it for this long (default
 * of --pkg-idle): off a terminal it prints a dot each tenth of a
 * download, so a large package on a slow link is quiet for minutes, but
 * not for ten.
 */
#define	PKG_IDLE_SEC		600
/* Jobs of pkg in jails, each its own jail, at work at once. */
#define	PKG_LANES		4
#define	TRACE_MAX		ARC_MAX_STEPS
#define	TRACE_DEPTH		16

struct opts {
	const char	*jail_conf;
	const char	*jail_conf_d;
	const char	*jail_bin;
	const char	*rc_dirs;	/* colon separated */
	gid_t		 sock_gid;	/* -g: the socket's group, the console's; -1 none */
	const char	*service_bin;
	const char	*sysrc_bin;
	const char	*netstat_bin;
	const char	*swapinfo_bin;
	const char	*zpool_bin;
	const char	*pkg_bin;
	const char	*self_path;	/* the program an update replaces */
	const char	*ifconfig_bin;
	const char	*ngctl_bin;
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
	const char	*smtpd_bin;	/* OpenSMTPD, a plugin: smtpd(8) */
	const char	*smtpctl_bin;	/* and smtpctl(8) */
	const char	*smtpd_conf;	/* its smtpd.conf(5) */
	const char	*smtpd_dir;	/* the agent's tables and kept form */
	const char	*speederv2_bin;	/* UDPspeeder's FEC relay, a plugin */
	const char	*speederv2_log;	/* where syslogd(8) writes its lines */
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
	const char	*poudriere_bin;	/* poudriere(8): the package builder, a plugin */
	const char	*ifmcstat_bin;	/* ifmcstat(8): IGMP's and MLD's state */
	const char	*rtadvctl_bin;	/* rtadvctl(8): rtadvd's reload and show */
	const char	*freshclam_conf; /* ClamAV's freshclam.conf, its mirrors */
	const char	*suricata_rules; /* where suricata-update writes the ruleset */
	const char	*exports_file;	/* exports(5) */
	const char	*ctl_conf;	/* ctl.conf(5) */
	const char	*hast_conf;	/* hast.conf(5) */
	const char	*poudriere_etc;	/* where poudriere.conf and poudriere.d are */
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
	const char	*sctp_also;	/* more addresses for SCTP listeners */
	const char	*telegram_api;	/* the Bot API's base, for notify */
	const char	*git_bin;
	const char	*traceroute_bin;	/* and the same with 6 */
	const char	*keyscan_bin;	/* ssh-keyscan(1) */
	const char	*keygen_bin;	/* ssh-keygen(1) */
	const char	*make_bin;
	const char	*build_dir;	/* where a tree is cloned and built */
	const char	*build_conf;	/* this host's config.mk for it */
	const char	*root;		/* --root: the system's files under it */
	int		 bird_watch_s;	/* --bird-watch: BIRD's sessions, how often */
	int		 smtpd_watch_s;	/* --smtpd-watch: OpenSMTPD, how often */
	int		 pkg_idle_s;	/* --pkg-idle: a silent pkg, stopped after */
	int		 pkg_lanes;	/* jobs of pkg in jails at once, at start */
	const char	*jobs_conf;	/* where lanes is kept */
	const char	*nacm_file;	/* NACM's rules (superbia/ynacm.c) */
	const char	*subs_file;	/* the configured subscriptions
					 * (invidia/ynotif.c) */
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
	 * A read's: the programs it runs are given READ_NICE, so that
	 * what the console asks for, often, does not crowd the host's
	 * own work or a job's.
	 */
	bool		 nice;
	/*
	 * A job's trace is read by other threads while the job runs: the
	 * step functions change it under this lock, and trace_copy() of
	 * this work into another reads it under it.
	 */
	pthread_mutex_t	 lock;
	/* The peer told each step as it begins and ends, or NULL. */
	cbl_conn	*tell;
	/* A job's: its steps changing are the jobs' change (yang_changed). */
	bool		 told;
	/*
	 * A job's, set by another thread when it is cancelled at work: a
	 * watched program it runs (exec_set_watch()) is stopped.
	 */
	_Atomic bool	 cancel;
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
void		 trace_family(cbl_family *);
void		 trace_tell(struct work *, cbl_req *);
uint64_t	 now_us(void);

/* ira/exec.c: run a program without a shell, capturing its output. */
struct execres {
	int		 status;	/* exit status, 128 + signal, or -1 */
	const char	*out;
	size_t		 outlen;
	const char	*err;
	size_t		 errlen;
	bool		 truncated;	/* more output than was kept */
	bool		 timedout;	/* killed: it did not finish in time */
	int		 stalled;	/* killed: silent this many seconds */
	bool		 cancelled;	/* killed: its job was cancelled */
};

int		 run_exec(struct work *, char *const [], struct execres *);
bool		 pid_alive(pid_t);
bool		 pid_is(pid_t, const char *);
pid_t		 pidfile_of(const char *, const char *);
void		 pid_stop(pid_t, const char *, int);
void		 exec_set_home(struct work *, const char *);
void		 exec_set_env(struct work *, const char *, const char *);
void		 exec_set_stdin(const char *, size_t);
void		 exec_set_secret(bool);
void		 exec_set_hide(const char *);
void		 exec_set_watch(int);
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
int		 jail_named(struct work *, const char *, struct jinfo *);
int		 jail_lookup(struct work *, const char *);

/* superbia/confread.c: configured jails, as jail(8) -e resolves them;
 * a file it could not read, and why. */
struct conf_error {
	const char	*scope;
	const char	*message;
};

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
	struct conf_error *errors;
	size_t		 nerrors;
};

/* rc.d/jail's say on what starts at boot: jail_enable, jail_list. */
struct jboot {
	bool		 on;		/* jail_enable is yes */
	const char	*list;		/* jail_list, or NULL: every jail */
};
void		 jail_boot_read(struct work *, struct jboot *);
void		 jail_boot_files(struct work *, struct jboot *);
bool		 jail_boot_of(const struct jboot *, const char *);
int		 jail_boot_set(struct work *, const char *, bool,
		    const struct cconf *, const char **);
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

/* ira/lifecycle.c: the jails, configured and running merged (do_list(),
 * with config_only the configured alone), and what an action left. */
struct jails_read {
	bool			 ok;
	const char		*error;
	struct arc_jail		*jails;
	size_t			 njails;
	const char *const	*scopes;
	size_t			 nscopes;
	struct conf_error	*errors;
	size_t			 nerrors;
};
struct jail_done {
	bool		 ok;
	const char	*error;
	struct arc_jail	*result;	/* the jail as it is after */
};
int		 do_list(struct work *, bool, struct jails_read *);
int		 do_action(struct work *, const char *, uint8_t,
		    struct jail_done *);
/* invidia/address.c */
/* ira/jailmake.c: jails made and taken away, their defaults, templates */
const char	*jail_conf_check(const struct arc_job_spec *);
int		 do_jail_conf(struct work *, const struct arc_job_spec *,
		    const char **);
int		 jail_allow_names(struct work *, const char ***, size_t *);
int		 jail_allow_live(struct work *, int, const char **, size_t,
		    const char ***);
const char	*jail_allow_check(const struct arc_job_spec *);
int		 do_jail_allow(struct work *, const struct arc_job_spec *,
		    const char **);
int		 jail_allow_undo_prepare(struct work *, const struct arc_job_spec *,
		    const char **, struct arc_variable **, size_t *, const char **);
int		 jail_allow_undo(struct work *, const struct arc_job_spec *,
		    const struct arc_variable *, size_t, const char **);
void		 do_jail_files(struct work *, struct arc_jail_files_rsp *);

/* superbia/certs.c: the certificates OpenSSL trusts */
void		 do_certs(struct work *, struct arc_certs_rsp *);
const char	*cert_check(const struct arc_job_spec *);
int		 do_cert(struct work *, const struct arc_job_spec *,
		    const char **);

/* acedia/zfskey.c: a dataset's key, typed */
void		 do_zfs_key(struct work *, const struct arc_zfs_key_req *,
		    struct arc_zfs_key_rsp *);

/* invidia/capture.c: packets taken with tcpdump */
void		 do_capture(struct work *, const struct arc_capture_req *,
		    struct arc_capture_rsp *);

/* superbia/ssh.c: the base system's sshd */
void		 do_ssh(struct work *, struct arc_ssh_rsp *);
const char	*ssh_check(const struct arc_job_spec *);
/* luxuria/poudriere.c: the package builder, its runs left to go on. */
const char	*poudriere_check(const struct arc_job_spec *);
int		 do_poudriere_job(struct work *, const struct arc_job_spec *,
		    const char **);
char		*poudriere_title(const struct arc_job_spec *);

/* gula/crashes.c: the cores dumped, and a backtrace of one. */
struct arc_crashes_rsp;
void		 do_crashes(struct work *, const char *const *, size_t,
		    struct arc_crashes_rsp *);

/* luxuria/clamav.c: freshclam's mirrors. */
const char	*clamav_check(const struct arc_job_spec *);
char		*clamav_title(const struct arc_job_spec *);
int		 do_clamav_job(struct work *, const struct arc_job_spec *,
		    const char **);
struct arc_builder_rsp;
void		 do_builder(struct work *, struct arc_builder_rsp *);
struct arc_builder_options_rsp;
void		 do_builder_options(struct work *, const struct arc_job_spec *,
		    struct arc_builder_options_rsp *);
int		 do_ssh_job(struct work *, const struct arc_job_spec *,
		    const char **);
int		 ssh_undo(struct work *, const struct arc_job_spec *,
		    const char **);
/* invidia/carp.c: carp(4)'s vhids, read and set by netlink */
struct ucl_object_s;
void		 carp_read(struct ucl_object_s *, struct ucl_object_s *);
int		 carp_helper(int, char **);
const char	*carp_check(const struct arc_job_spec *);
const char	*carp_vhid_of(const struct arc_job_spec *);
int		 do_carp(struct work *, const struct arc_job_spec *,
		    const char **);
/* invidia/neigh.c: a neighbour set by hand, or taken away */
const char	*neigh_check(const struct arc_job_spec *);
int		 do_neigh(struct work *, const struct arc_job_spec *,
		    const char **);
int		 do_address(struct work *, const struct arc_address_req *,
		    struct arc_address_rsp *);

/* ira/services.c */
int		 do_services(struct work *, struct arc_services_rsp *);
void		 service_scripts(struct work *, struct arc_services_rsp *);
const char	*service_rcvar(struct work *, const char *, const char **);
bool		 valid_var_name(const char *);
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
	const char	*addressing;	/* dhcp, slaac, static or was; NULL as
					 * is */
};
/* An interface's addressing by rc.conf: its two lines (NULL unset). */
struct addr_state {
	const char	*rc;		/* ifconfig_<if> */
	const char	*rc6;		/* ifconfig_<if>_ipv6 */
	bool		 dhcp;
	bool		 slaac;
};
void		 if_addr_state(struct work *, const char *,
		    struct addr_state *);
int		 if_addr_restore(struct work *, const char *,
		    const struct addr_state *, bool, const char **);
void		 if_addr_forget(struct work *, const char *);
const char	*if_addr_record_get(struct work *, const char *);
void		 if_addr_record_set(struct work *, const char *, const char *);
int		 do_if_set(struct work *, const char *,
		    const struct if_change *, bool, const char **);
int		 do_if_create(struct work *, const struct arc_job_spec *,
		    const char **, const char **);
int		 do_if_destroy(struct work *, const char *, bool, const char **);
bool		 if_clonable(struct work *, const char *, const char **);
void		 if_current(struct work *, const char *, unsigned int *, int *,
		    int *, char *, size_t);
bool		 if_is_up(struct work *, const char *, bool *);
bool		 if_link(struct work *, const char *, bool *);
bool		 if_exists(struct work *, const char *);
const char	*if_json(struct work *);
struct ucl_object_s *if_object(struct work *, const char *);
int		 if_recreate(struct work *, const char *, const struct ucl_object_s *, int,
		    int, const char **);
bool		 if_owning(const struct sockaddr *, char *, size_t);
const char	*if_address_with_prefix(struct work *, const char *,
		    const char *);

/* invidia/routes.c */
/* What a route has besides where it leads. */
struct route_more {
	uint32_t	 metric;	/* 0: the system's */
	uint32_t	 weight;
	const char	*source;	/* the address sent from, or NULL */
	const char	*name;		/* rc.conf's for it, or NULL: arc_... */
	bool		 rc_only;	/* rc.conf alone, the kernel as it is */
};
int		 do_route(struct work *, const char *, const char *, bool,
		    uint32_t, const struct route_more *, bool, const char **);
int		 route_snapshot(struct work *, const char *, uint32_t,
		    const char **, struct route_more *, bool *, const char **);
int		 do_kept_routes(struct work *, struct arc_network_rsp *);

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

/* invidia/wireguard.c: WireGuard, through the base system's wg(8). */
int		 do_wireguard(struct work *, struct arc_network_rsp *);
const char	*wg_check(struct work *, const struct arc_job_spec *);
int		 do_wg(struct work *, const struct arc_job_spec *,
		    const char **);
void		 wg_forget(struct work *, const char *);
char		*wg_conf_path(struct work *, const char *);
int		 wg_showconf(struct work *, const char *, char **, const char **);
int		 wg_syncconf(struct work *, const char *, const char *,
		    const char **);
bool		 wg_key_ok(const char *);

/* luxuria/ipsec.c: a plugin, strongSwan through swanctl(8). */
int		 do_ipsec(struct work *, struct arc_network_rsp *);
const char	*ipsec_check(const struct arc_job_spec *);
int		 do_ipsec_job(struct work *, const struct arc_job_spec *,
		    const char **);
void		 ipsec_conn_files(struct work *, const char *, const char **,
		    const char **, const char **);
int		 ipsec_undo(struct work *, const char *, bool, const char **);
int		 ipsec_toggle(struct work *, const char *, bool, const char **);

/* luxuria/bird.c: a plugin, through birdc(8). */
int		 do_bird(struct work *, struct arc_network_rsp *);
void		 bird_watch_start(void);
void		 smtpd_watch_start(void);
void		 smtpd_cert_renewed(struct work *);
const char	*bird_check(const char *, const char *const *, size_t);
int		 bird_proto_enabled(struct work *, const char *, bool *,
		    const char **);
int		 bird_configure_safe(struct work *, int, const char **);
int		 bird_configure_confirm(struct work *, const char **);
int		 bird_configure_undo(struct work *, const char **);
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
int		 do_bird_ospf(struct work *, const char *,
		    struct arc_network_rsp *);
/* superbia/kernel.c: the kernel's modules and memory. */
const char	*do_kernel(struct work *, const char **);
bool		 kld_listed(struct work *, const char *);
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
void		 host_watch_start(void);
bool		 kmsg_lines(struct work *, uint64_t, const char *, uint32_t,
		    struct kmsg_line **, size_t *, uint64_t *);
bool		 kmsg_crash_line(const char *, time_t);
void		 kmsg_crash_sweep(time_t);
void		 history_save(void);
/* gula/probe.c: the tunnels measured, ICMP echo again and again. */
enum { PROBE_NONE = -1, PROBE_UNKNOWN, PROBE_UP, PROBE_DOWN, PROBE_ENDED,
    PROBE_ERROR };
void		 probe_start(void);
int		 do_probes_set(struct work *, const char *, const char **);
int		 do_sdwan(struct work *, uint64_t, struct arc_sdwan_rsp *);
/* ... and the admin's own monitors on any tunnel, by the same prober. */
struct arc_monitors_rsp;
int		 do_monitors(struct work *, uint64_t, struct arc_monitors_rsp *);
const char	*monitor_check(const struct arc_job_spec *);
char		*monitor_title(const struct arc_job_spec *);
int		 do_monitor_job(struct work *, const struct arc_job_spec *,
		    const char **);
int		 probe_state_of(const char *, const char *);
void		 probe_link(const char *, const char *, bool);
/* invidia/sdwan.c: the rules that steer, and the steering. */
void		 sdwan_start(void);
int		 do_sdwan_rules(struct work *, const char *, const char **);
int		 do_sdwan_steer(struct work *, const char *, const char **);
void		 sdwan_probe_changed(void);
struct ucl_object_s;
void		 sdwan_json(struct work *, struct ucl_object_s *);
const char	*sdwan_conf_path(const char *, char *, size_t);
int		 sdwan_conf_write(const char *, const char *, const char **);
const char	*sdwan_subst(struct work *, const char *, const char *const *,
		    const char *const *, size_t);
char		*sdwan_kept_read(const char *);
const char	*sdwan_payload_jail(const struct ucl_object_s *, const char **);

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
void		 clamav_mirrors_json(struct ucl_object_s *);
void		 security_specs(const char *, struct ucl_object_s *, const char *);
int		 do_sdwan_ids(struct work *, const char *, const char **);
/*
 * luxuria/sdconf.c: dnsmasq's, unbound's, Squid's, c-icap's and BIRD's files
 * from the console's forms.  Where an instance's files are: Squid's
 * and c-icap's own, a list's its name between list_pre and list_suf.
 */
struct sqpaths {
	const char	*pid, *ca, *ssldb, *certgen, *deny;
	const char	*list_pre, *list_suf;
	const char	*icap_pid, *icap_cmd;
};
/* The port an SD-WAN service's c-icap answers its Squid on; the
 * Security section's i-th, on the loopback. */
#define	SDWAN_ICAP_PORT(fib)	(1344 + 10 * (int)(fib))
#define	SEC_ICAP_PORT(i)	(1345 + 10 * (int)(i))
char		*dhcp_conf_render(struct work *, const struct ucl_object_s *,
		    const char *, const char **);
/* Where an unbound instance's files are, as its configuration names
 * them: its key and certificate for DNS over TLS, a response policy
 * zone's file (rpz_pre + the zone's name). */
struct dnspaths {
	const char	*tlskey, *tlspem, *rpz_pre;
};
char		*dns_conf_render(struct work *, const struct ucl_object_s *,
		    const char *, const struct dnspaths *, struct ucl_object_s *,
		    const char **);
char		*squid_conf_render(struct work *, const struct ucl_object_s *,
		    const char *, const char *, int, const struct ucl_object_s *,
		    const struct sqpaths *, char **, const char **);
bool		 squid_conf_icap(const struct ucl_object_s *);
struct ucl_object_s *clamav_sigs_render(struct work *,
		    const struct ucl_object_s *, const char **);
char		*icap_conf_render(struct work *, const struct ucl_object_s *,
		    const char *, const char *, int, const struct sqpaths *,
		    const char **);
char		*bird_conf_render(struct work *, const struct ucl_object_s *,
		    const char *, const char **);
/* luxuria/idsconf.c: Suricata's YAML from an instance's settings. */
char		*ids_conf_render(struct work *, const struct ucl_object_s *,
		    const char *, const char *, int64_t, struct ucl_object_s *,
		    const char **);
char		*ids_conf_sdwan(struct work *, const struct ucl_object_s *,
		    const char *, const char *, struct ucl_object_s *,
		    const char **);
int		 do_notify(struct work *, const char *, const char *,
		    const char *, const char **);
void		 sdwan_ids_start(void);
/* superbia/geomjob.c: GEOM's classes at work. */
const char	*geom_check(const struct arc_job_spec *);
char		*geom_title(const struct arc_job_spec *);
int		 do_geom_job(struct work *, const struct arc_job_spec *,
		    const char **);
struct ucl_object_s *geom_classes_json(struct work *);
/* superbia/sysfiles.c: the system's own configuration files. */
struct arc_system_rsp;
void		 do_system(struct work *, const char *const *, size_t,
		    struct arc_system_rsp *);
const char	*sysfile_check(const struct arc_job_spec *);
char		*sysfile_title(const struct arc_job_spec *);
int		 do_sysfile_job(struct work *, const struct arc_job_spec *,
		    const char **);
const char	*sysfile_path(struct work *, const char *);
int		 sysfile_tell(struct work *, const char *, const char **);
/* superbia/netstore.c: NFS, iSCSI and HAST. */
struct arc_netstore_rsp;
void		 do_netstore(struct work *, const char *const *, size_t,
		    struct arc_netstore_rsp *);
const char	*netstore_check(const struct arc_job_spec *);
char		*netstore_title(const struct arc_job_spec *);
int		 do_netstore_job(struct work *, const struct arc_job_spec *,
		    const char **);
/* luxuria/speeder.c: UDPspeeder's FEC relay, a plugin. */
struct arc_speeder_rsp;
void		 do_speeder(struct work *, struct arc_speeder_rsp *);
const char	*speeder_check(const struct arc_job_spec *);
char		*speeder_title(const struct arc_job_spec *);
int		 do_speeder_job(struct work *, const struct arc_job_spec *,
		    const char **);
/* A relay as it was, for safe mode: its profile (NULL: the plain one). */
struct speeder_was {
	const char	*profile, *flags, *enable, *profiles;
	const char	*svcj, *svcj_options, *svcj_ipaddrs;
	bool		 running;
};
void		 speeder_snap(struct work *, const struct arc_job_spec *,
		    struct speeder_was *);
int		 speeder_back(struct work *, const struct speeder_was *,
		    const char **);
/* A relay's rates, for the history: by its syslog tag, bytes a second
 * taken in plain and added by the FEC, both ways, over its last report. */
struct speeder_rate {
	char		 tag[48];
	double		 plain, added;
};
size_t		 speeder_rates(struct speeder_rate *, size_t, unsigned int);

/* luxuria/smtpd.c: OpenSMTPD, a plugin: its read, and its job. */
struct arc_smtpd_rsp;
void		 do_smtpd(struct work *, struct arc_smtpd_rsp *);
const char	*smtpd_check(const struct arc_job_spec *);
char		*smtpd_title(const struct arc_job_spec *);
int		 do_smtpd_job(struct work *, const struct arc_job_spec *,
		    const char **);
char		*smtpd_render(struct work *, const struct ucl_object_s *,
		    const char **);
const char	*suricata_ruleset(void);
/* luxuria/surules.c: the ruleset's rules, and those the admin set. */
struct arc_suricata_rules_rsp;
void		 do_suricata_rules(struct work *, const char *const *, size_t,
		    struct arc_suricata_rules_rsp *);
const char	*suricata_rule_check(const struct arc_job_spec *);
int		 suricata_rule_set(struct work *, const struct arc_job_spec *,
		    const char **);
int		 suricata_rule_args(struct work *, char **, int *,
		    const char **);
const char	*suricata_data_dir(struct work *);
bool		 suricata_sources_secret(struct work *);
bool		 suricata_name_ok(const char *);
const char	*suricata_socket(struct work *, const char *);
const char	*suricata_source_check(const struct arc_job_spec *);
char		*suricata_source_title(const struct arc_job_spec *);
int		 suricata_source_job(struct work *, const struct arc_job_spec *,
		    const char **);
const char	*suricata_check(const struct arc_job_spec *);
char		*suricata_title(const struct arc_job_spec *);
int		 do_suricata_job(struct work *, const struct arc_job_spec *,
		    const char **);
void		 sdwan_ids_json(struct work *, struct ucl_object_s *);
void		 suricata_inst_path(const char *, const char *, char *, size_t);
struct ucl_object_s *suricata_build_json(struct work *);
/* luxuria/idsfiles.c: captures in, pcap-log out, profiling read. */
struct ucl_object_s *suricata_captures_json(const char *);
void		 suricata_profiling(struct work *, const char *,
		    struct arc_suricata_rules_rsp *);
int		 do_rtadvd(struct work *, const char *, const char *const *,
		    size_t, bool, bool, const char **);
/* invidia/sa.c: manually keyed SAs by setkey(8). */
const char	*sa_check(const struct arc_job_spec *);
int		 do_sa_job(struct work *, const struct arc_job_spec *,
		    const char **);
void		 sa_files(struct work *, const char *, const char **,
		    const char **, const char **);
const char	*sa_undo_check(struct work *, const struct arc_job_spec *);
int		 sa_undo(struct work *, const struct arc_job_spec *,
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
bool		 fault_update(const char *, const char *, const char *, ...)
		    __printflike(3, 4);
void		 faults_json(struct ucl_object_s *);
void		 faults_start(void);
int		 faults_purge(int, time_t, int, int);
int		 faults_compress(const char *, const char *);
/* gula/record.c: what the security rules logged, a day of it. */
void		 record_start(void);
void		 record_json(struct ucl_object_s *);
int		 do_process(struct work *, uint32_t, struct arc_processes_rsp *);

/* superbia/sysctl.c: the kernel's values, as sysctl_read() gives them
 * (arcana-sysctl's), the host's whole or a jail's network's. */
struct sysctl_value {
	const char	*name, *value, *type, *descr;
	bool		 rw, tun;
};
typedef void	 sysctl_value_f(void *, const struct sysctl_value *);
int		 sysctl_read(struct work *, const char *, const char *,
		    size_t, sysctl_value_f *, void *, uint64_t *,
		    const char **, const char **);
int		 sysctl_read_jail(struct work *, const char *,
		    sysctl_value_f *, void *, const char **);
bool		 sysctl_flags(const char *, bool *, bool *);
const char	*sysctl_conf_path(char *, size_t);
void		 sysctl_conf_lock(void);
void		 sysctl_conf_unlock(void);
int		 do_sysctl_set(struct work *, const char *, const char *, bool,
		    const char **);
bool		 sysctl_name_ok(const char *);
const char	*sysctl_get(struct work *, const char *, const char **);
const char	*sysctl_conf_get(struct work *, const char *);
int		 sysctl_conf_restore(struct work *, const char *, const char *,
		    const char **);
bool		 valid_jail(const char *);
/* What builds share: the build directory's keys and clones. */
extern pthread_mutex_t	 build_lock;
/* After an update's answer, the console's service restarted, then the
 * agent's. */
void		 restart_after(bool, bool);
const char	*change_busy(struct work *);
bool		 valid_service(const char *);
bool		 valid_ifname(const char *);
bool		 sysctl_value_ok(const char *);
int		 do_l2(struct work *, bool, struct arc_network_rsp *);
const char	*bridge_holding(struct work *, const char *);
const char	*l2_check(const struct arc_job_spec *);
int		 l2_destroy(struct work *, const char *, const char **);
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
/* superbia/admit.c: only the console asks */
bool		 peer_is_host(const cbl_peer *);
int		 admit_register(cbl_ctx *, cbl_family **);
/* superbia/tlsfiles.c: the agent's own TLS files renewed */
const char	*tls_files_ca(void);
const char	*tls_files_cert(void);
bool		 tls_cert_dates(struct work *, time_t *, time_t *);
const char	*tls_files_key(void);
void		 tls_files_init(cbl_tls *, const char *, const char *,
		    const char *);
void		 do_tls(struct work *, const char *, const char *,
		    const char *, const char *, const uint8_t *,
		    struct arc_tls_rsp *);
void		 transport_fini(void);
int		 do_transport(struct work *, bool, const char *, const char *,
		    bool, const char *, struct arc_transport_rsp *);
bool		 tls_file_is(const char *);
/* superbia/bundle.c: the host as a bundle, a bundle made the host. */
int		 do_config_export(struct work *, bool,
		    struct arc_config_export_rsp *);
int		 do_config_apply(struct work *, const char *, bool, bool,
		    const char *, struct arc_config_apply_rsp *);
/* invidia/pathcheck.c: what this host does with a packet and its reply. */
int		 do_path_check(struct work *, const char *, const char *,
		    const char *, uint32_t, const char *, bool, uint32_t, bool,
		    struct arc_path_check_rsp *);
bool		 kmod_loaded(const char *);
bool		 prefix_covers(const uint8_t *, const uint8_t *, int);
int		 if_fib(const char *);

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
void		 plugins_forget(void);
int		 do_if_vnet(struct work *, const char *, const char *, bool,
		    bool, const char **);
char *const	*scope_argv(struct work *, char *const []);
char *const	*scope_jexec(struct work *, char *const []);
int		 scope_dirfd(struct work *, const char *);
int		 scope_open_dir(struct work *, const char *, const char **);
char		*scope_slurp(struct work *, const char *, size_t *);
int		 scope_replace(struct work *, const char *, const char *,
		    size_t, mode_t, const char *);
int		 scope_unlink(struct work *, const char *);
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
int		 addr_lines(FILE *);
int		 route_socket(void);
int		 helper_netlink(int);
int		 helper_icmp_socket(int, int);
unsigned int	 plugins_here(void);
int		 jail_jid_name(int, char *, size_t, char *, size_t);
int		 jail_next(int);
/* ira/jailwatch.c: jail-state events, from EVFILT_JAIL */
void		 jail_watch_start(void);
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
void		 events_replay(time_t, void (*)(const char *, time_t, void *),
		    void (*)(void *), void *, time_t *, time_t *, bool *);
/* invidia/yserve.c: an event's JSON told as arcana-events' notification
 * on cblink's YANG family too; the events or the alarms changed, for
 * their on-change subscriptions. */
void		 yang_event(const char *);
#define	YANG_EVENTS	0
#define	YANG_ALARMS	1
#define	YANG_JOBS	2
#define	YANG_INTERFACES	3
#define	YANG_ROUTING	4
#define	YANG_INSTANCES	5
#define	YANG_LNES	6
#define	YANG_COUNT	7
void		 yang_changed(int);
/* What an event of that kind changed (of a jail's network, jailed). */
void		 yang_event_changed(const char *, bool);
struct cbl_ynode;
const struct cbl_ynode *ynode_named(const char *, const char *);
/* A logical network element's root, by a helper attached to its jail
 * (invidia/lneroot.c). */
void		 yang_lne_failed(const char *, const char *, const char *);
int		 lne_serve(void);
void		 lne_gone(int);
void		 lne_bound(const char *, const char *, bool);
/* invidia/ynotif.c: the configured subscriptions kept, told to cblink,
 * their receivers reached over HTTPS-notif; at the start. */
int		 ysubs_init(struct cbl_ctx *);

/* superbia/admit.c, ynacm.c: NACM (RFC 8341).  The console's users in
 * group admin by default: its admin, and the console itself for the
 * requests it makes for nobody. */
#define	NACM_ADMIN	"admin"
#define	NACM_CONSOLE	"console"
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

/* ira/packages.c: a package as pkg(8) says of it; a read of pkg's
 * (those installed, or what the repository has newer); an upgrade
 * asked and its outcome. */
struct package {
	const char	*name;
	const char	*installed;
	const char	*available;	/* the repository's, where newer */
	bool		 has_automatic;
	bool		 automatic;
	const char	*comment;
	bool		 has_size;
	uint64_t	 size;
	const char	*origin;
};
struct pkg_read {
	bool			 ok;
	const char		*error;
	struct package	*packages;
	size_t			 npackages;
	const char *const	*repos;		/* pkg -vv's, enabled or not */
	size_t			 nrepos;
	bool			 has_pkgbase;	/* a jail's base: pkgbase */
	bool			 pkgbase;
};
struct pkg_upgrade {
	const char		*jail;		/* NULL the host; "*" every one */
	struct {
		size_t		 n;		/* none: all */
		const char *const *v;
	}			 names;
	bool			 dry_run;
	bool			 ignore_osversion;
	uint8_t			 pkg_ip;	/* 4, 6, or 0 */
	const char		*pkg_repo;	/* from it alone, or NULL */
};
struct pkg_upgraded {
	bool			 ok;
	const char		*error;
	bool			 has_upgraded;
	uint32_t		 upgraded;
	struct package	*packages;	/* still pending */
	size_t			 npackages;
};
int		 do_packages(struct work *, const char *, bool, bool, uint8_t,
		    bool, struct pkg_read *);
int		 do_pkg_upgrade(struct work *, const struct pkg_upgrade *,
		    struct pkg_upgraded *);
int		 do_pkg_clean(struct work *, const char *, bool, const char **);
int		 do_jail_base(struct work *, const struct arc_job_spec *,
		    const char **);
const char	*pkg_repo_error(struct work *, const struct execres *,
		    const char *);
const char	*pkg_repo_check(struct work *, const char *, const char *);
int		 jobs_lanes(void);
const char	*jobs_set_lanes(int);
void		 jobs_conf_load(void);
int		 do_pkg_install(struct work *, const struct arc_job_spec *,
		    const char **);

/* ira/jobs.c: queued changes, run in order whoever is or is not connected. */
void		 jobs_init(void);
int		 jobs_submit(const struct arc_job_spec *, size_t, const char *,
		    struct work *, const struct arc_job **, size_t *);
void		 jobs_list(struct work *, const struct arc_job **, size_t *);
int		 jobs_submit_checked(cbl_req *, const struct arc_job_spec *,
		    size_t, struct work *, const struct arc_job **, size_t *,
		    const char **);
size_t		 jobs_waiting(void);
const struct arc_job *jobs_get(struct work *, uint64_t);
const struct arc_job *jobs_cancel(struct work *, uint64_t, const char **);
const struct arc_job *jobs_confirm(struct work *, uint64_t, const char **);

/* invidia/address.c, superbia/confedit.c */
int		 ifaddr_change(struct work *, const char *, int, const void *,
		    int, bool, const char **);
int		 ifaddr_change_peer(struct work *, const char *, int,
		    const void *, int, const void *, bool, const char **);
const char	*list_edit(struct work *, const char *, const char *,
		    const char *, bool);
bool		 list_has(const char *, const char *, const char *);
char		*block_cut(struct work *, const char *, const char *, const char *,
		    char **);
char		*block_add(struct work *, const char *, const char *, const char *,
		    const char *);
int		 file_put(struct work *, const char *, const char *, mode_t,
		    const char **);
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
		    const char *, const uint8_t *, size_t, bool,
		    struct arc_agent_update_rsp *);
void		 service_restart(const char *);
void		 service_detached(const char *, const char *);

/* handlers.c */
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
