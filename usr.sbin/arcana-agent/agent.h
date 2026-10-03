/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _AGENT_H_
#define _AGENT_H_

#include <sys/types.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

/* Generated into the object directory; <> so that a stale copy next
 * to the sources is never picked up. */
#include <arcana.h>

#define	ARCANA_AGENT_VERSION	"0.1.0"

#define	PATH_JAIL_CONF		"/etc/jail.conf"
#define	PATH_JAIL_CONF_D	"/etc/jail.conf.d"
#define	PATH_JAIL_BIN		"/usr/sbin/jail"
#define	PATH_RC_DIRS		"/etc/rc.d:/usr/local/etc/rc.d"
#define	PATH_SERVICE_BIN	"/usr/sbin/service"
#define	PATH_SYSRC_BIN		"/usr/sbin/sysrc"
#define	PATH_NETSTAT_BIN	"/usr/bin/netstat"
#define	PATH_SOCKSTAT_BIN	"/usr/bin/sockstat"
#define	PATH_SWAPINFO_BIN	"/usr/sbin/swapinfo"
#define	PATH_ZPOOL_BIN		"/sbin/zpool"
#define	PATH_PKG_BIN		"/usr/sbin/pkg"

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
	const char	*sockstat_bin;
	const char	*swapinfo_bin;
	const char	*zpool_bin;
	const char	*pkg_bin;
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

/* exec.c: run a program without a shell, capturing its output. */
struct execres {
	int		 status;	/* exit status, 128 + signal, or -1 */
	const char	*out;
	size_t		 outlen;
	const char	*err;
	size_t		 errlen;
	bool		 truncated;	/* more output than was kept */
};

int		 run_exec(struct work *, char *const [], struct execres *);
int		 run_exec_max(struct work *, char *const [], struct execres *,
		    size_t);
const char	*exec_error(struct work *, const struct execres *,
		    const char *);

/* jails.c: running jails (libjail) and their processes (libprocstat). */
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

/* confread.c: configured jails, as jail(8) -e resolves them. */
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

/* host.c */
void		 host_info(struct work *, struct arc_host *);

/* jail.c: one jail record from runtime and configured state. */
void		 jail_record(struct work *, struct arc_jail *, const char *,
		    const struct jinfo *, const struct cjail *);
struct arc_jail	*jail_current(struct work *, const char *,
		    const struct cconf *);

/* actions.c */
int		 do_list(struct work *, bool, struct arc_list_rsp *);
int		 do_action(struct work *, const char *, uint8_t,
		    struct arc_action_rsp *);
int		 do_address(struct work *, const struct arc_address_req *,
		    struct arc_address_rsp *);

/* services.c */
int		 do_services(struct work *, struct arc_services_rsp *);
int		 do_service_action(struct work *, const char *, uint8_t,
		    struct arc_service_action_rsp *);
int		 do_service_config(struct work *,
		    const struct arc_service_config_req *,
		    struct arc_service_config_rsp *);

/* network.c */
int		 do_network(struct work *, uint8_t, uint8_t,
		    struct arc_network_rsp *);

/* stats.c */
int		 do_stats(struct work *, struct arc_stats_rsp *);

/* packages.c */
int		 do_packages(struct work *, const char *, bool,
		    struct arc_packages_rsp *);
int		 do_pkg_upgrade(struct work *, const struct arc_pkg_upgrade_req *,
		    struct arc_pkg_upgrade_rsp *);

/* jobs.c: queued changes, run in order whoever is or is not connected. */
void		 jobs_init(void);
int		 jobs_submit(const struct arc_job_spec *, size_t, const char *,
		    struct work *, const struct arc_job **, size_t *);
void		 jobs_list(struct work *, const struct arc_job **, size_t *);
const struct arc_job *jobs_get(struct work *, uint64_t);
const struct arc_job *jobs_cancel(struct work *, uint64_t, const char **);

/* handlers.c */
extern pthread_mutex_t	change_lock;	/* one change at a time */

/* main.c */
void		 logmsg(int, const char *, ...) __printflike(2, 3);

#endif /* !_AGENT_H_ */
