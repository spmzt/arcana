/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _JAILGRIDD_H_
#define _JAILGRIDD_H_

#include <sys/types.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include "jailgrid.h"

#define	JAILGRIDD_VERSION	"0.1.0"

#define	PATH_JAIL_CONF		"/etc/jail.conf"
#define	PATH_JAIL_CONF_D	"/etc/jail.conf.d"
#define	PATH_JAIL_BIN		"/usr/sbin/jail"

/* jail -e separator: ASCII unit separator, never in a jail.conf value. */
#define	JAIL_E_SEP		"\037"

#define	EXEC_TIMEOUT_SEC	600
#define	TRACE_MAX		JG_MAX_STEPS
#define	TRACE_DEPTH		16

struct opts {
	const char	*jail_conf;
	const char	*jail_conf_d;
	const char	*jail_bin;
	bool		 debug;
};

extern struct opts opts;

/*
 * work.c: one request.  Everything a reply points to is allocated from
 * the request's pool and released with it, and the request records what
 * it did in its own trace.
 */
struct step {
	uint8_t		 kind;		/* JG_STEP_KIND_* */
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
void		 trace_steps(struct work *, const struct jg_step **, size_t *);
uint64_t	 now_us(void);

/* exec.c: run a program without a shell, capturing its output. */
struct execres {
	int		 status;	/* exit status, 128 + signal, or -1 */
	const char	*out;
	size_t		 outlen;
	const char	*err;
	size_t		 errlen;
};

int		 run_exec(struct work *, char *const [], struct execres *);
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
	struct jg_param	*params;
	size_t		 nparams;
};

struct cconf {
	const char	**scopes;
	size_t		 nscopes;
	struct cjail	*jails;
	size_t		 njails;
	struct jg_conf_error *errors;
	size_t		 nerrors;
};

void		 conf_read(struct work *, struct cconf *);
int		 conf_scope_read(struct work *, const char *, struct cjail **,
		    size_t *, const char **);
const struct cjail *conf_jail(const struct cconf *, const char *);
const struct jg_param *cjail_param(const struct cjail *, const char *);
const char	*cjail_param1(const struct cjail *, const char *);

/* host.c */
void		 host_info(struct work *, struct jg_host *);

/* jail.c: one jail record from runtime and configured state. */
void		 jail_record(struct work *, struct jg_jail *, const char *,
		    const struct jinfo *, const struct cjail *);
struct jg_jail	*jail_current(struct work *, const char *,
		    const struct cconf *);

/* actions.c */
int		 do_list(struct work *, bool, struct jg_list_rsp *);
int		 do_action(struct work *, const char *, uint8_t,
		    struct jg_action_rsp *);
int		 do_address(struct work *, const struct jg_address_req *,
		    struct jg_address_rsp *);

/* main.c */
void		 logmsg(int, const char *, ...) __printflike(2, 3);

#endif /* !_JAILGRIDD_H_ */
