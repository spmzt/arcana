/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Jobs: changes that are queued and run one after another by a thread of
 * the daemon's own, in the order they were given.  A job does not belong
 * to the connection that queued it: restarting the jail or the interface
 * the console is reached through cuts the console off, and the job, and
 * those queued behind it, still run to their end.  Their state and their
 * trace, which grows while a job runs, are kept for whoever asks later.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	JOBS_KEPT	64	/* finished jobs remembered */

struct qjob {
	uint64_t		 id;
	uint8_t			 state;		/* ARC_JOB_STATE_* */
	bool			 ok;
	bool			 begun;		/* has the lock, is at work */
	bool			 confirmed;	/* a safe change may stay */
	bool			 rejected;	/* cancelled while unconfirmed:
						 * undone now, not at the timer */
	time_t			 confirm_by;	/* or is undone at this time */
	const char		*undo_address;	/* in w's pool, or NULL */
	unsigned int		 undo_mtu;	/* if-set: what it was */
	int			 undo_fib;
	int			 undo_tunnelfib;
	const char		*undo_descr;
	struct addr_state	 undo_addr;	/* if-set addressing: as it was */
	const char		*undo_addr_rec;	/* its record for was, or NULL */
	const char		*made;		/* if-create: the name it got */
	struct arc_variable	*undo_vars;	/* service-config: as they were */
	size_t			 undo_nvars;
	const char		*undo_value;	/* sysctl: the kernel's before */
	const char		*undo_conf;	/* sysctl: sysctl.conf's, or NULL */
	const char		*undo_gateway;	/* route deleted: as listed */
	struct route_more	 undo_more;
	bool			 undo_kept;	/* rc.conf had the route */
	bool			 undo_enabled;	/* bird: the protocol was */
	const char		*undo_note;	/* why nothing is put back */
	char			*undo_secret;	/* malloc'd, zeroed at the end:
						 * wireguard: showconf before */
	struct undo_file {		/* files as they were: text, or none */
		const char	*path;
		char		*text;	/* malloc'd, zeroed at the end */
		size_t		 len;
		bool		 had;
	}			 undo_files[4];
	int			 undo_nfiles;
	struct undo_rc {		/* rc.conf variables as they were */
		const char	*name;
		const char	*value;	/* NULL: unset */
	}			 undo_rc[6];
	int			 undo_nrc;
	bool			 undo_none;	/* it changed nothing: as it was */
	bool			 undo_live;	/* rc.conf had it before: keep that */
	char			*title;
	char			*peer;
	const char		*error;		/* in w's pool */
	time_t			 created;
	time_t			 started;
	time_t			 finished;
	struct arc_job_spec	 spec;		/* its strings are ours */
	struct work		 w;		/* its trace */
	TAILQ_ENTRY(qjob)	 link;
};

static TAILQ_HEAD(, qjob) jobs = TAILQ_HEAD_INITIALIZER(jobs);
static pthread_mutex_t	jobs_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	jobs_cv = PTHREAD_COND_INITIALIZER;
static pthread_cond_t	confirm_cv = PTHREAD_COND_INITIALIZER;
/* Jobs of pkg in jails at work in lanes of their own, and how many
 * lanes there are (jobs-set, kept in jobs.conf); under jobs_lock. */
static int		lanes_busy;
static int		lanes_max = PKG_LANES;
static uint64_t		nextid = 1;

static char	*xdup(const char *);
static char	*title_of(const struct arc_job_spec *);
static void	 spec_copy(struct arc_job_spec *, const struct arc_job_spec *);
static void	 job_free(struct qjob *);
static void	 trim(void);
static void	 run(struct qjob *, bool) __no_lock_analysis;
static bool	 pkg_lane(const struct arc_job_spec *);
static bool	 lane_jail_busy(const char *);
static bool	 await_confirm(struct qjob *);
static const char *undo_prepare(struct qjob *);
static const char *confirm_apply(struct qjob *);
static const char *undo(struct qjob *);
static void	*runner(void *);
static void	 fill(struct work *, struct arc_job *, struct qjob *, bool);

static const char *action_names[] = { "start", "stop", "restart", "kill" };
static const char *svc_names[] = { "start", "stop", "restart", "reload",
    "enable", "disable" };

static char *
xdup(const char *s)
{
	char	*p;

	if (s == NULL)
		return (NULL);
	if ((p = strdup(s)) == NULL)
		err(1, "strdup");
	return (p);
}

/*
 * Does the job work on a network, the jail's that it names when it names
 * one?  Giving an interface to a jail does not: the host does that, and
 * the jail is where the interface goes.
 */
static bool
scoped(const struct arc_job_spec *sp)
{

	return ((sp->kind >= ARC_JOB_KIND_IF_ADDRESS && sp->kind <=
	    ARC_JOB_KIND_BIRD) || sp->kind == ARC_JOB_KIND_IPFW || sp->kind ==
	    ARC_JOB_KIND_BRIDGE || sp->kind == ARC_JOB_KIND_GENEVE ||
	    sp->kind == ARC_JOB_KIND_IPSEC || sp->kind == ARC_JOB_KIND_NEIGHBOUR ||
	    sp->kind == ARC_JOB_KIND_CARP ||
	    /* A vnet jail's own network's numbers, net.*: its own. */
	    (sp->kind == ARC_JOB_KIND_SYSCTL && sp->jail != NULL &&
	    sp->jail[0] != '\0'));
}

/* What the job does, in words: the activity log's line for it. */
static char *
title_of(const struct arc_job_spec *sp)
{
	char	*t, *in;
	int	 rc;

	switch (sp->kind) {
	case ARC_JOB_KIND_JAIL_ACTION:
		rc = asprintf(&t, "%s %s", action_names[sp->action], sp->jail);
		break;
	case ARC_JOB_KIND_ADDRESS:
		rc = asprintf(&t, "%s %s %s %s%s", sp->remove ? "remove" : "add",
		    sp->address, sp->remove ? "from" : "to", sp->jail,
		    sp->live && sp->persist ? " (live + config)" : sp->persist ?
		    " (config)" : "");
		break;
	case ARC_JOB_KIND_SERVICE_ACTION:
		rc = asprintf(&t, "service %s %s", sp->service,
		    svc_names[sp->service_action]);
		break;
	case ARC_JOB_KIND_SERVICE_CONFIG:
		rc = asprintf(&t, "service %s configure", sp->service);
		break;
	case ARC_JOB_KIND_IF_ADDRESS:
		rc = asprintf(&t, "%s: %s %s", sp->interface, sp->remove ?
		    "remove" : "add", sp->address);
		break;
	case ARC_JOB_KIND_IF_STATE:
		rc = asprintf(&t, "%s: %s", sp->interface, sp->up ? "up" :
		    "down");
		break;
	case ARC_JOB_KIND_ROUTE:
		rc = asprintf(&t, "route %s %s%s%s%s%s%s%s", sp->remove ?
		    "delete" : "add", sp->destination, sp->gateway != NULL ?
		    " via " : "", sp->gateway != NULL ? sp->gateway : "",
		    sp->has_fib && sp->fib != 0 ? " (fib)" : "",
		    sp->has_metric && sp->metric != 0 ? " (metric)" : "",
		    sp->has_weight && sp->weight != 0 ? " (weight)" : "",
		    sp->persist ? " (kept)" : "");
		break;
	case ARC_JOB_KIND_IF_SET:
		rc = asprintf(&t, "%s: set%s%s%s%s%s%s", sp->interface,
		    sp->has_mtu && sp->mtu != 0 ? " mtu" : "",
		    sp->description != NULL ? " description" : "",
		    sp->has_fib ? " fib" : "", sp->has_tunnelfib ?
		    " tunnelfib" : "", sp->addressing != NULL ? " addressing " :
		    "", sp->addressing != NULL ? sp->addressing : "");
		break;
	case ARC_JOB_KIND_IF_CREATE:
		rc = asprintf(&t, "create %s%s%s%s%s", sp->interface,
		    sp->tunnel_remote != NULL ? " to " : "",
		    sp->tunnel_remote != NULL ? sp->tunnel_remote : "",
		    sp->address != NULL ? " with " : "", sp->address != NULL ?
		    sp->address : "");
		break;
	case ARC_JOB_KIND_IF_DESTROY:
		rc = asprintf(&t, "destroy %s", sp->interface);
		break;
	case ARC_JOB_KIND_NETGRAPH:
		rc = asprintf(&t, "ngctl %s %s%s%s", sp->verb, sp->names.n > 0 ?
		    sp->names.v[0] : "", sp->names.n > 1 ? " " : "",
		    sp->names.n > 1 ? sp->names.v[1] : "");
		break;
	case ARC_JOB_KIND_SSH:
		rc = asprintf(&t, "sshd %s%s%s%s%s", sp->verb,
		    strcmp(sp->verb, "set") == 0 && sp->path != NULL ? " " : "",
		    strcmp(sp->verb, "set") == 0 && sp->path != NULL ? sp->path :
		    "", sp->user != NULL ? " of " : "", sp->user != NULL ?
		    sp->user : "");
		break;
	case ARC_JOB_KIND_POUDRIERE:
		rc = (t = poudriere_title(sp)) != NULL ? 0 : -1;
		break;
	case ARC_JOB_KIND_CLAMAV:
		rc = (t = clamav_title(sp)) != NULL ? 0 : -1;
		break;
	case ARC_JOB_KIND_SURICATA:
		rc = (t = suricata_title(sp)) != NULL ? 0 : -1;
		break;
	case ARC_JOB_KIND_NFS:
	case ARC_JOB_KIND_ISCSI:
	case ARC_JOB_KIND_HAST:
		rc = (t = netstore_title(sp)) != NULL ? 0 : -1;
		break;
	case ARC_JOB_KIND_SYSFILE:
		rc = (t = sysfile_title(sp)) != NULL ? 0 : -1;
		break;
	case ARC_JOB_KIND_GEOM:
		rc = (t = geom_title(sp)) != NULL ? 0 : -1;
		break;
	case ARC_JOB_KIND_SMTPD:
		rc = (t = smtpd_title(sp)) != NULL ? 0 : -1;
		break;
	case ARC_JOB_KIND_CARP:
		rc = asprintf(&t, "%s: carp %s vhid %s%s%s", sp->interface,
		    sp->verb, carp_vhid_of(sp), sp->address != NULL &&
		    strcmp(sp->verb, "set") != 0 ? " " : "", sp->address !=
		    NULL && strcmp(sp->verb, "set") != 0 ? sp->address : "");
		break;
	case ARC_JOB_KIND_CERT:
		rc = asprintf(&t, "certificate %s%s%s", sp->verb, sp->path !=
		    NULL && strcmp(sp->verb, "rehash") != 0 ? " " : "", sp->path !=
		    NULL && strcmp(sp->verb, "rehash") != 0 ? sp->path : "");
		break;
	case ARC_JOB_KIND_NEIGHBOUR:
		rc = asprintf(&t, "neighbour %s %s%s%s%s%s", sp->verb,
		    sp->address, sp->lladdr != NULL && strcmp(sp->verb, "add") ==
		    0 ? " " : "", sp->lladdr != NULL && strcmp(sp->verb, "add") ==
		    0 ? sp->lladdr : "", sp->temporary ? " (ages out)" : "",
		    sp->persist ? sp->live ? " (now, and kept)" : " (kept)" : "");
		break;
	case ARC_JOB_KIND_JAIL_CONF:
		rc = asprintf(&t, "jail %s%s%s%s%s", sp->verb, sp->jail != NULL &&
		    sp->jail[0] != '\0' ? " " : sp->names.n > 0 ? " " : "",
		    sp->jail != NULL && sp->jail[0] != '\0' ? sp->jail :
		    sp->names.n > 0 ? sp->names.v[0] : "", sp->snapshot != NULL &&
		    sp->snapshot[0] != '\0' ? " from " : "", sp->snapshot != NULL ?
		    sp->snapshot : "");
		break;
	case ARC_JOB_KIND_WIREGUARD:
		rc = asprintf(&t, "%s: wireguard %s%s%.12s%s", sp->interface,
		    sp->verb, sp->peer != NULL ? " " : "", sp->peer != NULL ?
		    sp->peer : "", sp->peer != NULL ? "…" : "");
		break;
	case ARC_JOB_KIND_BIRD:
		rc = asprintf(&t, "bird %s%s%s", sp->verb, sp->names.n > 0 ?
		    " " : "", sp->names.n > 0 ? sp->names.v[0] : "");
		break;
	case ARC_JOB_KIND_KMOD:
		rc = strcmp(sp->verb, "keep") == 0 || strcmp(sp->verb,
		    "forget") == 0 ? asprintf(&t, "%s %s kld_list",
		    sp->names.v[0], sp->verb[0] == 'k' ? "into" : "out of") :
		    asprintf(&t, "kld%s %s%s", sp->verb, sp->names.v[0],
		    sp->persist ? " (kept)" : "");
		break;
	case ARC_JOB_KIND_RTADVD:
		rc = asprintf(&t, "rtadvd %s %s%s%s", sp->remove ? "off" : "on",
		    sp->interface, !sp->remove && sp->names.n > 0 ? " " : "",
		    !sp->remove && sp->names.n > 0 ? sp->names.v[0] : "");
		break;
	case ARC_JOB_KIND_NTP:
		rc = asprintf(&t, "ntp %s%s%s%s", sp->remove ? "servers removed" :
		    "servers ", sp->remove || sp->names.n == 0 ? "" :
		    sp->names.v[0], !sp->remove && sp->names.n > 1 ? " and more" :
		    "", sp->persist ? " (kept)" : "");
		break;
	case ARC_JOB_KIND_SYSCTL:
		rc = asprintf(&t, "sysctl %s=%s%s", sp->names.v[0],
		    sp->names.v[1], sp->persist ? " (kept)" : "");
		break;
	case ARC_JOB_KIND_IPFW:
		rc = (t = ipfw_title(sp)) != NULL ? 0 : -1;
		break;
	case ARC_JOB_KIND_PROCESS:
		rc = (t = proc_title(sp)) != NULL ? 0 : -1;
		break;
	case ARC_JOB_KIND_IPSEC:
		rc = asprintf(&t, "ipsec %s%s%s%s%s%s%s%s", sp->verb, sp->conn !=
		    NULL ? " " : "", sp->conn != NULL ? sp->conn : "",
		    sp->child != NULL ? " " : "", sp->child != NULL ? sp->child :
		    "", sp->ipsec_mode != NULL ? " (" : "", sp->ipsec_mode !=
		    NULL ? sp->ipsec_mode : "", sp->ipsec_mode != NULL ? ")" :
		    "");
		break;
	case ARC_JOB_KIND_IPSEC_SA:
		/* Never the keys. */
		rc = asprintf(&t, "ipsec sa %s %s reqid %u", sp->verb, sp->interface,
		    sp->reqid);
		break;
	case ARC_JOB_KIND_PKG_INSTALL:
		rc = asprintf(&t, "pkg install %s%s%s%s%s%s%s", sp->names.n > 0 ?
		    sp->names.v[0] : "", sp->names.n > 1 ? " and more" : "",
		    sp->jail != NULL && sp->jail[0] != '\0' ? " in " : "",
		    sp->jail != NULL ? sp->jail : "", sp->pkg_repo != NULL ?
		    " from " : "", sp->pkg_repo != NULL ? sp->pkg_repo : "",
		    sp->force ? " (any OSVERSION)" : "");
		break;
	case ARC_JOB_KIND_PKG_CLEAN:
		rc = asprintf(&t, "pkg clean%s%s%s", sp->force ? " -a" : "",
		    sp->jail != NULL && sp->jail[0] != '\0' ? " in " : "",
		    sp->jail != NULL ? sp->jail : "");
		break;
	case ARC_JOB_KIND_JAIL_BASE:
		rc = asprintf(&t, "jail %s: %s%s%s", sp->jail != NULL ? sp->jail :
		    "?", sp->verb != NULL && strcmp(sp->verb, "upgrade") == 0 ?
		    "base to " : "to pkgbase", sp->verb != NULL && strcmp(sp->verb,
		    "upgrade") == 0 && sp->release != NULL ? sp->release : "",
		    sp->force ? " (any OSVERSION)" : "");
		break;
	case ARC_JOB_KIND_BRIDGE:
	case ARC_JOB_KIND_GENEVE:
		rc = (t = l2_title(sp)) != NULL ? 0 : -1;
		break;
	case ARC_JOB_KIND_ZFS:
	case ARC_JOB_KIND_ZPOOL:
	case ARC_JOB_KIND_MOUNT:
	case ARC_JOB_KIND_GPART:
	case ARC_JOB_KIND_CAM:
		return (storage_title(sp));
	case ARC_JOB_KIND_IF_VNET:
		rc = asprintf(&t, sp->remove ? "take %s back from %s%s%s%s" :
		    "give %s to %s%s%s%s", sp->interface, sp->jail,
		    sp->parent != NULL && sp->parent[0] != '\0' ? ", on " : "",
		    sp->parent != NULL ? sp->parent : "", sp->persist ?
		    " (kept)" : "");
		break;
	default:
		rc = asprintf(&t, "pkg upgrade%s%s%s%s", sp->jail != NULL ?
		    " in " : "", sp->jail == NULL ? "" : strcmp(sp->jail,
		    "*") == 0 ? "every jail" : sp->jail,
		    sp->names.n > 0 ? " of some" : "", sp->force ?
		    ", ignoring OSVERSION" : "");
		break;
	}
	if (rc == -1)
		err(1, "asprintf");
	/* A change to a jail's network says whose it is. */
	if ((scoped(sp) || sp->kind == ARC_JOB_KIND_CERT ||
	    sp->kind == ARC_JOB_KIND_SSH) && sp->jail != NULL &&
	    sp->jail[0] != '\0') {
		in = t;
		if (asprintf(&t, "%s: %s", sp->jail, in) == -1)
			err(1, "asprintf");
		free(in);
	}
	return (t);
}

static void
spec_copy(struct arc_job_spec *d, const struct arc_job_spec *s)
{
	struct arc_variable	*vars;
	const char		**names;
	size_t			 i;

	*d = *s;
	d->jail = xdup(s->jail);
	d->address = xdup(s->address);
	d->interface = xdup(s->interface);
	d->service = xdup(s->service);
	d->destination = xdup(s->destination);
	d->gateway = xdup(s->gateway);
	d->description = xdup(s->description);
	d->tunnel_local = xdup(s->tunnel_local);
	d->tunnel_remote = xdup(s->tunnel_remote);
	d->parent = xdup(s->parent);
	d->verb = xdup(s->verb);
	d->peer = xdup(s->peer);
	d->endpoint = xdup(s->endpoint);
	d->allowed_ips = xdup(s->allowed_ips);
	d->source = xdup(s->source);
	/* Every text the spec can carry: one left pointing into the request
	 * that brought it is freed memory by the time the job runs. */
	d->conn = xdup(s->conn);
	d->pkg_repo = xdup(s->pkg_repo);
	d->ipsec_mode = xdup(s->ipsec_mode);
	d->local_ts = xdup(s->local_ts);
	d->remote_ts = xdup(s->remote_ts);
	d->pubkey = xdup(s->pubkey);
	d->start_action = xdup(s->start_action);
	d->local_id = xdup(s->local_id);
	d->remote_id = xdup(s->remote_id);
	d->child = xdup(s->child);
	d->local_cert = xdup(s->local_cert);
	d->remote_cert = xdup(s->remote_cert);
	d->remote_ca = xdup(s->remote_ca);
	d->addressing = xdup(s->addressing);
	d->dataset = xdup(s->dataset);
	d->snapshot = xdup(s->snapshot);
	d->copy = xdup(s->copy);
	d->path = xdup(s->path);
	d->text = xdup(s->text);
	d->preshared_key = xdup(s->preshared_key);
	d->lladdr = xdup(s->lladdr);
	d->user = xdup(s->user);
	d->variables.v = NULL;
	d->names.v = NULL;
	if (s->variables.n > 0) {
		if ((vars = calloc(s->variables.n, sizeof(*vars))) == NULL)
			err(1, "calloc");
		for (i = 0; i < s->variables.n; i++) {
			vars[i].key = xdup(s->variables.v[i].key);
			vars[i].value = xdup(s->variables.v[i].value);
			vars[i].remove = s->variables.v[i].remove;
		}
		d->variables.v = vars;
	}
	if (s->names.n > 0) {
		if ((names = calloc(s->names.n, sizeof(*names))) == NULL)
			err(1, "calloc");
		for (i = 0; i < s->names.n; i++)
			names[i] = xdup(s->names.v[i]);
		d->names.v = names;
	}
}

static void
job_free(struct qjob *j)
{
	size_t	i;

	for (i = 0; i < j->spec.variables.n; i++) {
		free((char *)(uintptr_t)j->spec.variables.v[i].key);
		free((char *)(uintptr_t)j->spec.variables.v[i].value);
	}
	free((void *)(uintptr_t)j->spec.variables.v);
	for (i = 0; i < j->spec.names.n; i++)
		free((char *)(uintptr_t)j->spec.names.v[i]);
	free((void *)(uintptr_t)j->spec.names.v);
	free((char *)(uintptr_t)j->spec.jail);
	free((char *)(uintptr_t)j->spec.address);
	free((char *)(uintptr_t)j->spec.interface);
	free((char *)(uintptr_t)j->spec.service);
	free((char *)(uintptr_t)j->spec.destination);
	free((char *)(uintptr_t)j->spec.gateway);
	free((char *)(uintptr_t)j->spec.description);
	free((char *)(uintptr_t)j->spec.tunnel_local);
	free((char *)(uintptr_t)j->spec.tunnel_remote);
	free((char *)(uintptr_t)j->spec.parent);
	free((char *)(uintptr_t)j->spec.verb);
	free((char *)(uintptr_t)j->spec.peer);
	free((char *)(uintptr_t)j->spec.endpoint);
	free((char *)(uintptr_t)j->spec.allowed_ips);
	free((char *)(uintptr_t)j->spec.source);
	free((char *)(uintptr_t)j->spec.conn);
	free((char *)(uintptr_t)j->spec.pkg_repo);
	free((char *)(uintptr_t)j->spec.ipsec_mode);
	free((char *)(uintptr_t)j->spec.local_ts);
	free((char *)(uintptr_t)j->spec.remote_ts);
	free((char *)(uintptr_t)j->spec.pubkey);
	free((char *)(uintptr_t)j->spec.start_action);
	free((char *)(uintptr_t)j->spec.local_id);
	free((char *)(uintptr_t)j->spec.remote_id);
	free((char *)(uintptr_t)j->spec.child);
	free((char *)(uintptr_t)j->spec.local_cert);
	free((char *)(uintptr_t)j->spec.remote_cert);
	free((char *)(uintptr_t)j->spec.remote_ca);
	free((char *)(uintptr_t)j->spec.addressing);
	free((char *)(uintptr_t)j->spec.dataset);
	free((char *)(uintptr_t)j->spec.snapshot);
	free((char *)(uintptr_t)j->spec.copy);
	free((char *)(uintptr_t)j->spec.path);
	/* A key may ride in either: not left in freed memory. */
	if (j->spec.text != NULL)
		explicit_bzero((char *)(uintptr_t)j->spec.text,
		    strlen(j->spec.text));
	free((char *)(uintptr_t)j->spec.text);
	if (j->spec.preshared_key != NULL)
		explicit_bzero((char *)(uintptr_t)j->spec.preshared_key,
		    strlen(j->spec.preshared_key));
	free((char *)(uintptr_t)j->spec.preshared_key);
	free((char *)(uintptr_t)j->spec.lladdr);
	free((char *)(uintptr_t)j->spec.user);
	free(j->title);
	free(j->peer);
	work_free(&j->w);
	free(j);
}

/* Forget the oldest finished jobs beyond JOBS_KEPT.  jobs_lock held. */
static void
trim(void)
{
	struct qjob	*j, *next;
	int		 n;

	n = 0;
	TAILQ_FOREACH(j, &jobs, link)
		if (j->state == ARC_JOB_STATE_DONE ||
		    j->state == ARC_JOB_STATE_CANCELLED)
			n++;
	TAILQ_FOREACH_SAFE(j, &jobs, link, next) {
		if (n <= JOBS_KEPT)
			break;
		if (j->state != ARC_JOB_STATE_DONE &&
		    j->state != ARC_JOB_STATE_CANCELLED)
			continue;
		TAILQ_REMOVE(&jobs, j, link);
		job_free(j);
		n--;
	}
}

/* How long a safe change waits: the console's timer, else the agent's. */
static int
safe_wait(const struct arc_job_spec *sp)
{

	return (sp->has_safe_wait && sp->safe_wait > 0 ? (int)sp->safe_wait :
	    opts.safe_wait);
}

/*
 * The change is made: wait for the client to confirm it.  True when it
 * did; false when the time allowed passed without it, or the daemon is
 * stopping.
 */
static bool
await_confirm(struct qjob *j)
{
	struct timespec	ts;
	bool		confirmed, rejected;
	int		step;

	step = step_begin(&j->w, ARC_STEP_KIND_DAEMON, "safe mode",
	    "the change is made; waiting %d s to hear from the client again",
	    safe_wait(&j->spec));
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += safe_wait(&j->spec);
	pthread_mutex_lock(&jobs_lock);
	j->state = ARC_JOB_STATE_UNCONFIRMED;
	j->confirm_by = ts.tv_sec;
	while (!j->confirmed && !j->rejected && !changes_stopping())
		if (pthread_cond_timedwait(&confirm_cv, &jobs_lock, &ts) != 0)
			break;
	confirmed = j->confirmed;
	rejected = j->rejected;
	j->state = ARC_JOB_STATE_RUNNING;
	pthread_mutex_unlock(&jobs_lock);
	if (rejected)
		step_end(&j->w, step, false, "cancelled by the client while it "
		    "waited: undone now");
	else
		step_end(&j->w, step, confirmed, confirmed ? "confirmed: it "
		    "stays (the timer was %d s)" : "not confirmed within %d s",
		    safe_wait(&j->spec));
	logmsg(confirmed ? LOG_INFO : LOG_WARNING, "job %ju: %s: %s",
	    (uintmax_t)j->id, j->title, confirmed ? "confirmed" : rejected ?
	    "cancelled while unconfirmed: undoing it" :
	    "not confirmed in time: undoing it");
	/* Cancelled, then confirmed before the runner woke: the cancel
	 * came first, and the client was told "undone". */
	return (confirmed && !rejected);
}

/* What undoes an action on a service: the one that reverses it. */
static const uint8_t svc_reverse[] = {
	[ARC_SERVICE_ACTION_START] = ARC_SERVICE_ACTION_STOP,
	[ARC_SERVICE_ACTION_STOP] = ARC_SERVICE_ACTION_START,
	[ARC_SERVICE_ACTION_ENABLE] = ARC_SERVICE_ACTION_DISABLE,
	[ARC_SERVICE_ACTION_DISABLE] = ARC_SERVICE_ACTION_ENABLE,
};

/*
 * A file as it is before a safe change (its text, or that there is
 * none), to be put back after; the text may hold a key, so it is
 * malloc'd and zeroed at the job's end.  False when it cannot be read.
 */
static bool
undo_snap_file(struct qjob *j, const char *path)
{
	struct undo_file	*f;
	char			*text;
	size_t			 len;

	if (j->undo_nfiles == (int)nitems(j->undo_files))
		return (false);
	f = &j->undo_files[j->undo_nfiles];
	f->path = path;
	f->text = NULL;
	f->len = 0;
	if ((text = scope_slurp(&j->w, path, &len)) != NULL) {
		if ((f->text = malloc(len + 1)) == NULL)
			err(1, "malloc");
		memcpy(f->text, text, len);
		f->text[len] = '\0';
		explicit_bzero(text, len);
		f->len = len;
		f->had = true;
	} else if (errno == ENOENT)
		f->had = false;
	else
		return (false);
	j->undo_nfiles++;
	return (true);
}

/* The files back as they were: the text written, or the file gone. */
static int
undo_files_back(struct qjob *j, const char **errp)
{
	const struct undo_file	*f;
	int			 i, step, rc;

	rc = 0;
	for (i = 0; i < j->undo_nfiles; i++) {
		f = &j->undo_files[i];
		step = step_begin(&j->w, ARC_STEP_KIND_FILE, f->had ? "write" :
		    "remove", "%s, as it was", f->path);
		if (f->had)
			rc = scope_replace(&j->w, f->path, f->text, f->len, 0600,
			    NULL) == 0 ? rc : -1;
		else if (scope_unlink(&j->w, f->path) != 0 && errno != ENOENT)
			rc = -1;
		step_end(&j->w, step, rc == 0, rc == 0 ? NULL : "%s",
		    strerror(errno));
		if (rc != 0) {
			*errp = wfmt(&j->w, "%s: %s", f->path, strerror(errno));
			return (-1);
		}
	}
	return (0);
}

/* An rc.conf variable as it is, whole: a list comes back exactly. */
static void
undo_snap_rc(struct qjob *j, const char *name)
{

	if (j->undo_nrc == (int)nitems(j->undo_rc))
		return;
	j->undo_rc[j->undo_nrc].name = name;
	j->undo_rc[j->undo_nrc].value = rc_get(&j->w, name);
	j->undo_nrc++;
}

static int
undo_rc_back(struct qjob *j, const char **errp)
{
	const struct undo_rc	*r;
	int			 i;

	for (i = 0; i < j->undo_nrc; i++) {
		r = &j->undo_rc[i];
		if (r->value == NULL)
			rc_unset(&j->w, r->name);
		else if (rc_set(&j->w, r->name, "=", r->value, errp) != 0)
			return (-1);
	}
	return (0);
}

/* What a safe change kept to put things back: gone, keys zeroed. */
static void
undo_forget(struct qjob *j)
{
	int	i;

	if (j->undo_secret != NULL) {
		explicit_bzero(j->undo_secret, strlen(j->undo_secret));
		free(j->undo_secret);
		j->undo_secret = NULL;
	}
	for (i = 0; i < j->undo_nfiles; i++)
		if (j->undo_files[i].text != NULL) {
			explicit_bzero(j->undo_files[i].text,
			    j->undo_files[i].len);
			free(j->undo_files[i].text);
			j->undo_files[i].text = NULL;
		}
	j->undo_nfiles = 0;
	j->undo_nrc = 0;
}

/*
 * Before a safe change: what it will take to put things back, which
 * afterwards can no longer be read.
 */
static const char *
undo_prepare(struct qjob *j)
{
	const struct arc_job_spec	*sp;
	const char			*v, *e;
	char				 descr[256];
	size_t				 i;
	bool				 running, enabled, up;

	/*
	 * What is undone is what the job changed, not what it was asked:
	 * an interface that was up already is not brought down for having
	 * been told to come up.  What cannot be read now cannot be put
	 * back later: the job fails here, before the change.
	 */
	sp = &j->spec;
	switch (sp->kind) {
	case ARC_JOB_KIND_SYSCTL:
		e = NULL;
		if ((j->undo_value = sysctl_get(&j->w, sp->names.v[0], &e)) ==
		    NULL)
			return (wfmt(&j->w, "not changed: its value now could "
			    "not be read, so it could not be put back: %s", e));
		if (sp->persist)
			j->undo_conf = sysctl_conf_get(&j->w, sp->names.v[0]);
		if (strcmp(j->undo_value, sp->names.v[1]) == 0 && (!sp->persist ||
		    (j->undo_conf != NULL && strcmp(j->undo_conf,
		    sp->names.v[1]) == 0)))
			j->undo_none = true;
		break;
	case ARC_JOB_KIND_WIREGUARD:
		/* The interface whole as wg prints it (key, port, peers), to
		 * sync it back; with persist, wg-quick's file and the rc.conf
		 * variables that bring it up, as they are. */
		e = NULL;
		if (wg_showconf(&j->w, sp->interface, &j->undo_secret, &e) != 0)
			return (wfmt(&j->w, "not changed: %s could not be read, "
			    "so it could not be put back: %s", sp->interface, e));
		if (sp->persist) {
			if (!undo_snap_file(j, wg_conf_path(&j->w,
			    sp->interface)))
				return (wfmt(&j->w, "not changed: %s could not "
				    "be read, so it could not be put back: %s",
				    wg_conf_path(&j->w, sp->interface),
				    strerror(errno)));
			undo_snap_rc(j, "wireguard_interfaces");
			undo_snap_rc(j, "wireguard_enable");
			undo_snap_rc(j, "cloned_interfaces");
			undo_snap_rc(j, wfmt(&j->w, "ifconfig_%s", rc_ifname(&j->w,
			    sp->interface)));
		}
		break;
	case ARC_JOB_KIND_BIRD:
		/* Enabled or disabled: from the state it has now.  A restart
		 * or reload leaves nothing to put back, and the job says so.
		 * configure is BIRD's own timer, taken at the change. */
		if (strcmp(sp->verb, "enable") == 0 || strcmp(sp->verb,
		    "disable") == 0) {
			e = NULL;
			if (bird_proto_enabled(&j->w, sp->names.v[0],
			    &j->undo_enabled, &e) != 0)
				return (wfmt(&j->w, "not changed: its state "
				    "now could not be read, so it could not be "
				    "put back: %s", e));
			if (j->undo_enabled == (sp->verb[0] == 'e'))
				j->undo_none = true;
		} else if (strcmp(sp->verb, "configure") != 0)
			j->undo_note = wfmt(&j->w, "a %s is not undone: there "
			    "is nothing to put back", sp->verb);
		break;
	case ARC_JOB_KIND_ROUTE:
		/* Deleted without its gateway: the kernel's list says what
		 * to add back, and must say one thing. */
		if (!sp->remove || (sp->gateway != NULL && sp->gateway[0] !=
		    '\0'))
			break;
		e = NULL;
		if (route_snapshot(&j->w, sp->destination, sp->has_fib ?
		    sp->fib : 0, &j->undo_gateway, &j->undo_more, &j->undo_kept,
		    &e) != 0)
			return (wfmt(&j->w, "not changed: it could not be put "
			    "back: %s", e));
		break;
	case ARC_JOB_KIND_IF_ADDRESS:
		/* To put an address back, its prefix length is needed. */
		j->undo_address = if_address_with_prefix(&j->w, sp->interface,
		    sp->address);
		if (!sp->remove && j->undo_address != NULL)
			j->undo_none = true;
		break;
	case ARC_JOB_KIND_IF_STATE:
		if (if_is_up(&j->w, sp->interface, &up) && up == sp->up)
			j->undo_none = true;
		break;
	case ARC_JOB_KIND_KMOD:
		/* One that was in already, or out, is left so: in the
		 * kernel for load and unload, in kld_list for keep and
		 * forget. */
		if (strcmp(sp->verb, "keep") == 0 || strcmp(sp->verb,
		    "forget") == 0) {
			if (kld_listed(&j->w, sp->names.v[0]) == (sp->verb[0] ==
			    'k'))
				j->undo_none = true;
		} else if (kmod_loaded(sp->names.v[0]) == (strcmp(sp->verb,
		    "load") == 0))
			j->undo_none = true;
		break;
	case ARC_JOB_KIND_IF_CREATE:
		/* A name rc.conf sets up already keeps what it has there. */
		if (rc_get(&j->w, wfmt(&j->w, "ifconfig_%s", rc_ifname(&j->w,
		    sp->interface))) != NULL)
			j->undo_live = true;
		break;
	case ARC_JOB_KIND_ADDRESS:
		/* With the prefix length it has on whichever interface. */
		if (sp->remove)
			j->undo_address = if_address_with_prefix(&j->w, NULL,
			    sp->address);
		break;
	case ARC_JOB_KIND_SERVICE_ACTION:
		service_state(&j->w, sp->service, &running, &enabled);
		if ((sp->service_action == ARC_SERVICE_ACTION_START &&
		    running) || (sp->service_action ==
		    ARC_SERVICE_ACTION_STOP && !running) ||
		    (sp->service_action == ARC_SERVICE_ACTION_ENABLE &&
		    enabled) || (sp->service_action ==
		    ARC_SERVICE_ACTION_DISABLE && !enabled))
			j->undo_none = true;
		break;
	case ARC_JOB_KIND_IF_SET:
		if_current(&j->w, sp->interface, &j->undo_mtu, &j->undo_fib,
		    &j->undo_tunnelfib, descr, sizeof(descr));
		j->undo_descr = wstrdup(&j->w, descr);
		if (sp->addressing != NULL) {
			if_addr_state(&j->w, sp->interface, &j->undo_addr);
			j->undo_addr_rec = if_addr_record_get(&j->w,
			    sp->interface);
		}
		break;
	case ARC_JOB_KIND_SERVICE_CONFIG:
		j->undo_vars = wcalloc(&j->w, sp->variables.n + 1,
		    sizeof(*j->undo_vars));
		for (i = 0; i < sp->variables.n; i++) {
			v = rc_get(&j->w, sp->variables.v[i].key);
			j->undo_vars[i].key = sp->variables.v[i].key;
			j->undo_vars[i].value = v;
			j->undo_vars[i].remove = v == NULL;
		}
		j->undo_nvars = sp->variables.n;
		break;
	default:
		break;
	}
	return (NULL);
}

/*
 * A bridge's member, as rc.conf keeps it: "addm name" among what
 * ifconfig_<bridge> says, added or taken out.
 */
static void
bridge_keep(struct work *w, const char *bridge, const char *member, bool add)
{
	const char	*cur, *e, *var;
	char		*v, *p, *word;

	var = wfmt(w, "ifconfig_%s", bridge);
	cur = rc_get(w, var);
	word = wfmt(w, "addm %s", member);
	e = NULL;
	if (add) {
		if (cur == NULL)
			(void)rc_set(w, var, "=", wfmt(w, "%s up", word), &e);
		else if (strstr(wfmt(w, " %s ", cur), wfmt(w, " %s ", word)) ==
		    NULL)
			(void)rc_set(w, var, "=", wfmt(w, "%s %s", word, cur),
			    &e);
		return;
	}
	if (cur == NULL)
		return;
	v = wfmt(w, " %s ", cur);
	if ((p = strstr(v, wfmt(w, " %s ", word))) == NULL)
		return;
	memmove(p, p + strlen(word) + 1, strlen(p + strlen(word) + 1) + 1);
	v[strlen(v) - 1] = '\0';
	(void)rc_set(w, var, "=", v + 1, &e);
}

/* The bridge's member on the host, live: in, and up; or out. */
static int
bridge_member(struct work *w, const char *bridge, const char *member,
    bool add, const char **errp)
{
	struct execres	 res;
	char		*argv[5];

	argv[0] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[1] = (char *)(uintptr_t)bridge;
	argv[2] = (char *)(uintptr_t)(add ? "addm" : "deletem");
	argv[3] = (char *)(uintptr_t)member;
	argv[4] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ifconfig"));
		return (-1);
	}
	if (!add)
		return (0);
	argv[1] = (char *)(uintptr_t)member;
	argv[2] = (char *)(uintptr_t)"up";
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ifconfig"));
		return (-1);
	}
	return (0);
}

/*
 * A new epair(4) for a jail: made on the host, where its a end stays,
 * in the bridge named by parent when one is, and its b end given to the
 * jail.  A pair that cannot be given is destroyed again.
 */
static bool
give_pair(struct qjob *j, const char **errp)
{
	struct arc_job_spec	 cs;
	const char		*a, *e, *br;
	char			*b;

	memset(&cs, 0, sizeof(cs));
	cs.has_kind = true;
	cs.kind = ARC_JOB_KIND_IF_CREATE;
	cs.interface = (char *)(uintptr_t)"epair";
	cs.persist = j->spec.persist;
	a = NULL;
	if (do_if_create(&j->w, &cs, &a, errp) != 0)
		return (false);
	b = wstrdup(&j->w, a);
	if (b[0] == '\0' || b[strlen(b) - 1] != 'a') {
		*errp = wfmt(&j->w, "ifconfig made %s, which is no end of a "
		    "pair", a);
		return (false);
	}
	b[strlen(b) - 1] = 'b';
	br = j->spec.parent != NULL && j->spec.parent[0] != '\0' ?
	    j->spec.parent : NULL;
	if ((br != NULL && bridge_member(&j->w, br, a, true, errp) != 0) ||
	    do_if_vnet(&j->w, b, j->spec.jail, false, j->spec.persist,
	    errp) != 0) {
		(void)do_if_destroy(&j->w, a, j->spec.persist, &e);
		return (false);
	}
	if (br != NULL && j->spec.persist)
		bridge_keep(&j->w, br, a, true);
	j->made = b;
	return (true);
}

/*
 * Confirmed: what was made on a timer of its own is told to stay.  NULL,
 * or what to say of a job whose change did not stay after all.
 */
static const char *
confirm_apply(struct qjob *j)
{
	const char	*e;
	int		 step;

	if (j->spec.kind != ARC_JOB_KIND_BIRD || strcmp(j->spec.verb,
	    "configure") != 0)
		return (NULL);
	e = NULL;
	step = step_begin(&j->w, ARC_STEP_KIND_EXEC, "birdc", "configure "
	    "confirm");
	if (bird_configure_confirm(&j->w, &e) == 0) {
		step_end(&j->w, step, true, NULL);
		return (NULL);
	}
	step_end(&j->w, step, false, "%s", e);
	return (wfmt(&j->w, "confirmed, but BIRD did not keep it: %s", e));
}

/* Take a safe change back; returns what to say of the job. */
static const char *
undo(struct qjob *j)
{
	struct arc_address_req		 dq;
	struct arc_address_rsp		 dr;
	struct arc_service_action_rsp	 sar;
	struct arc_service_config_req	 scq;
	struct arc_service_config_rsp	 scr;
	struct route_more		 rm;
	const struct arc_job_spec	*sp;
	const char			*e;
	int				 rc;

	sp = &j->spec;
	e = NULL;
	if (j->undo_none)
		return (wfmt(&j->w, "not confirmed within %d s; it was so "
		    "before, and is left so", safe_wait(sp)));
	if (j->undo_note != NULL)
		return (wfmt(&j->w, "not confirmed within %d s; %s",
		    safe_wait(sp), j->undo_note));
	switch (sp->kind) {
	case ARC_JOB_KIND_WIREGUARD:
		rc = wg_syncconf(&j->w, sp->interface, j->undo_secret, &e);
		if (sp->persist && (undo_files_back(j, &e) != 0 ||
		    undo_rc_back(j, &e) != 0))
			rc = -1;
		break;
	case ARC_JOB_KIND_BIRD:
		if (strcmp(sp->verb, "configure") == 0)
			rc = bird_configure_undo(&j->w, &e);
		else
			rc = do_bird_verb(&j->w, sp->verb[0] == 'e' ? "disable" :
			    "enable", sp->names.v, sp->names.n, &e);
		break;
	case ARC_JOB_KIND_IF_ADDRESS:
		rc = do_if_address(&j->w, sp->interface, j->undo_address != NULL ?
		    j->undo_address : sp->address, !sp->remove, sp->persist,
		    &e);
		break;
	case ARC_JOB_KIND_IF_STATE:
		rc = do_if_state(&j->w, sp->interface, !sp->up, &e);
		break;
	case ARC_JOB_KIND_CARP:
		/* Only an address added is in safe mode: off again. */
		rc = do_if_address(&j->w, sp->interface, sp->address, true,
		    sp->persist, &e);
		break;
	case ARC_JOB_KIND_KMOD:
		/* Each verb's opposite: load and unload, keep and
		 * forget. */
		rc = do_kmod(&j->w, strcmp(sp->verb, "load") == 0 ? "unload" :
		    strcmp(sp->verb, "unload") == 0 ? "load" : strcmp(sp->verb,
		    "keep") == 0 ? "forget" : "keep", sp->names.v[0],
		    sp->persist, &e);
		break;
	case ARC_JOB_KIND_NTP:
		rc = do_ntp(&j->w, NULL, 0, true, sp->persist, &e);
		break;
	case ARC_JOB_KIND_SSH:
		rc = ssh_undo(&j->w, sp, &e);
		break;
	case ARC_JOB_KIND_RTADVD:
		rc = do_rtadvd(&j->w, sp->interface, NULL, 0, true, sp->persist,
		    &e);
		break;
	case ARC_JOB_KIND_IPFW:
		/*
		 * The rules that were there are swapped back in; a rule
		 * added is deleted; on becomes off, and off on.
		 */
		if (strcmp(sp->verb, "apply") == 0)
			e = ipfw_settle(&j->w, false);
		else if (strcmp(sp->verb, "add") == 0)
			e = ipfw_unadd(&j->w, sp);
		else {
			struct arc_job_spec	back;
			bool			held;

			back = *sp;
			back.safe = false;
			back.verb = strcmp(sp->verb, "enable") == 0 ?
			    "disable" : "enable";
			(void)do_ipfw_job(&j->w, &back, &held, &e);
		}
		rc = e == NULL ? 0 : -1;
		break;
	case ARC_JOB_KIND_IF_VNET:
		rc = do_if_vnet(&j->w, j->made != NULL ? j->made :
		    sp->interface, sp->jail, !sp->remove, sp->persist, &e);
		/* A pair made for the jail goes with it. */
		if (rc == 0 && j->made != NULL) {
			if (sp->parent != NULL && sp->parent[0] != '\0' &&
			    sp->persist)
				bridge_keep(&j->w, sp->parent, wfmt(&j->w,
				    "%.*sa", (int)strlen(j->made) - 1, j->made),
				    false);
			rc = do_if_destroy(&j->w, j->made, sp->persist, &e);
		}
		break;
	case ARC_JOB_KIND_IF_SET:
		{
			struct if_change	 ch;

			ch.mtu = sp->has_mtu && sp->mtu != 0 ? j->undo_mtu : 0;
			ch.descr = sp->description != NULL ? j->undo_descr :
			    NULL;
			ch.fib = sp->has_fib ? j->undo_fib : -1;
			ch.tunnelfib = sp->has_tunnelfib ? j->undo_tunnelfib :
			    -1;
			ch.addressing = NULL;
			rc = do_if_set(&j->w, sp->interface, &ch, sp->persist,
			    &e);
			/* Its addressing as it was before the job, not
			 * static: a host on SLAAC or DHCP stays so. */
			if (rc == 0 && sp->addressing != NULL) {
				rc = if_addr_restore(&j->w, sp->interface,
				    &j->undo_addr, sp->persist, &e);
				/* And was's record as it was: kept again
				 * when the job let it go, let go when the
				 * job made it. */
				if (rc == 0)
					if_addr_record_set(&j->w, sp->interface,
					    j->undo_addr_rec);
			}
		}
		break;
	case ARC_JOB_KIND_IF_CREATE:
		rc = do_if_destroy(&j->w, j->made != NULL ? j->made :
		    sp->interface, sp->persist && !j->undo_live, &e);
		break;
	case ARC_JOB_KIND_ADDRESS:
		memset(&dq, 0, sizeof(dq));
		memset(&dr, 0, sizeof(dr));
		dq.jail = sp->jail;
		dq.address = j->undo_address != NULL ? j->undo_address :
		    sp->address;
		dq.interface = sp->interface;
		dq.remove = !sp->remove;
		dq.live = sp->live;
		dq.persist = sp->persist;
		do_address(&j->w, &dq, &dr);
		rc = dr.ok ? 0 : -1;
		e = dr.error;
		break;
	case ARC_JOB_KIND_SERVICE_ACTION:
		memset(&sar, 0, sizeof(sar));
		do_service_action(&j->w, sp->service,
		    svc_reverse[sp->service_action], &sar);
		rc = sar.ok ? 0 : -1;
		e = sar.error;
		break;
	case ARC_JOB_KIND_SERVICE_CONFIG:
		memset(&scq, 0, sizeof(scq));
		memset(&scr, 0, sizeof(scr));
		scq.service = sp->service;
		scq.variables.v = j->undo_vars;
		scq.variables.n = j->undo_nvars;
		do_service_config(&j->w, &scq, &scr);
		rc = scr.ok ? 0 : -1;
		e = scr.error;
		break;
	case ARC_JOB_KIND_ROUTE:
		if (j->undo_gateway != NULL) {
			/* Back as the kernel listed it; into rc.conf only
			 * when it was there. */
			rc = do_route(&j->w, sp->destination, j->undo_gateway,
			    false, sp->has_fib ? sp->fib : 0, &j->undo_more,
			    sp->persist && j->undo_kept, &e);
			break;
		}
		rm.metric = sp->has_metric ? sp->metric : 0;
		rm.weight = sp->has_weight ? sp->weight : 0;
		rm.source = sp->source;
		rc = do_route(&j->w, sp->destination, sp->gateway, !sp->remove,
		    sp->has_fib ? sp->fib : 0, &rm, sp->persist, &e);
		break;
	case ARC_JOB_KIND_SYSCTL:
		/*
		 * The kernel's value as it was, and sysctl.conf's line as it
		 * was, or none.  A tunable that takes a value once (net.fibs,
		 * say) refuses the first: the file is still put back, and
		 * the job says the kernel keeps the new value until a boot.
		 */
		{
			const char	*ce;

			rc = do_sysctl_set(&j->w, sp->names.v[0], j->undo_value,
			    false, &e);
			ce = NULL;
			if (sp->persist && sysctl_conf_restore(&j->w,
			    sp->names.v[0], j->undo_conf, &ce) != 0) {
				e = e != NULL ? wfmt(&j->w, "%s; and %s", e, ce) :
				    ce;
				rc = -1;
			} else if (rc != 0) {
				e = wfmt(&j->w, "%s: the kernel keeps %s=%s "
				    "until it boots again%s", e, sp->names.v[0],
				    sp->names.v[1], sp->persist ? ", when "
				    "sysctl.conf, put back as it was, sets it" :
				    "");
			}
		}
		break;
	default:
		/* A kind with no undo is refused as safe at its check: this
		 * is never reached, and says so rather than doing harm. */
		rc = -1;
		e = "this kind of job cannot be undone";
		break;
	}
	if (rc != 0)
		return (wfmt(&j->w, "not confirmed within %d s, and it could "
		    "not be undone: %s", safe_wait(sp), e != NULL ? e :
		    "failed"));
	return (wfmt(&j->w, "not confirmed within %d s: undone",
	    safe_wait(sp)));
}

/*
 * Do what the job says; its outcome goes into the job.  In a lane, the
 * runner holds change_lock for every lane at once (lanes()).
 */
static void
run(struct qjob *j, bool lane)
{
	struct arc_action_rsp		 ar;
	struct arc_address_req		 dq;
	struct arc_address_rsp		 dr;
	struct arc_service_action_rsp	 sar;
	struct arc_service_config_req	 scq;
	struct arc_service_config_rsp	 scr;
	struct route_more		 rm;
	struct arc_pkg_upgrade_req	 uq;
	struct arc_pkg_upgrade_rsp	 ur;
	const struct arc_job_spec	*sp;
	const char			*error;
	bool				 ok, go, inside, held;
	int				 root;

	held = false;
	sp = &j->spec;
	root = step_begin(&j->w, ARC_STEP_KIND_DAEMON, "arcana-agent", "job %ju: %s",
	    (uintmax_t)j->id, j->title);
	if (lane)
		go = !changes_stopping();
	else {
		pthread_mutex_lock(&change_lock);
		go = change_note("job %ju: %s, from %s", (uintmax_t)j->id,
		    j->title, j->peer);
	}
	pthread_mutex_lock(&jobs_lock);
	j->begun = go;
	pthread_mutex_unlock(&jobs_lock);
	/* What changes a network works in the jail named, if one is. */
	error = NULL;
	inside = scoped(sp);
	if (go && inside && scope_enter(&j->w, sp->jail, &error) != 0) {
		ok = false;
		go = false;
	} else if (go && sp->safe && (error = undo_prepare(j)) != NULL) {
		ok = false;
		go = false;
	}
	if (!go) {
		ok = false;
		if (error == NULL)
			error = "not run: arcana-agent was stopping";
	} else switch (sp->kind) {
	case ARC_JOB_KIND_JAIL_ACTION:
		memset(&ar, 0, sizeof(ar));
		do_action(&j->w, sp->jail, sp->action, &ar);
		ok = ar.ok;
		error = ar.error;
		break;
	case ARC_JOB_KIND_ADDRESS:
		memset(&dq, 0, sizeof(dq));
		memset(&dr, 0, sizeof(dr));
		dq.jail = sp->jail;
		dq.address = sp->address;
		dq.interface = sp->interface;
		dq.remove = sp->remove;
		dq.live = sp->live;
		dq.persist = sp->persist;
		do_address(&j->w, &dq, &dr);
		ok = dr.ok;
		error = dr.error;
		break;
	case ARC_JOB_KIND_SERVICE_ACTION:
		memset(&sar, 0, sizeof(sar));
		do_service_action(&j->w, sp->service, sp->service_action, &sar);
		ok = sar.ok;
		error = sar.error;
		break;
	case ARC_JOB_KIND_IF_ADDRESS:
		error = NULL;
		ok = do_if_address(&j->w, sp->interface, sp->address,
		    sp->remove, sp->persist, &error) == 0;
		break;
	case ARC_JOB_KIND_IF_SET:
		error = NULL;
		{
			struct if_change	 ch;

			ch.mtu = sp->has_mtu ? sp->mtu : 0;
			ch.descr = sp->description;
			ch.fib = sp->has_fib ? (int)sp->fib : -1;
			ch.tunnelfib = sp->has_tunnelfib ? (int)sp->tunnelfib :
			    -1;
			ch.addressing = sp->addressing;
			ok = do_if_set(&j->w, sp->interface, &ch, sp->persist,
			    &error) == 0;
		}
		break;
	case ARC_JOB_KIND_IF_CREATE:
		error = NULL;
		ok = do_if_create(&j->w, sp, &j->made, &error) == 0;
		break;
	case ARC_JOB_KIND_IF_DESTROY:
		error = NULL;
		ok = do_if_destroy(&j->w, sp->interface, sp->persist,
		    &error) == 0;
		break;
	case ARC_JOB_KIND_NETGRAPH:
		error = NULL;
		ok = do_ng(&j->w, sp->verb, sp->names.v, sp->names.n,
		    &error) == 0;
		break;
	case ARC_JOB_KIND_WIREGUARD:
		error = NULL;
		ok = do_wg(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_JAIL_CONF:
		error = NULL;
		ok = do_jail_conf(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_NEIGHBOUR:
		error = NULL;
		ok = do_neigh(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_CARP:
		error = NULL;
		ok = do_carp(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_SSH:
		/* As a certificate: any jail's. */
		error = NULL;
		ok = scope_enter_jail(&j->w, sp->jail, &error, false) == 0 &&
		    do_ssh_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_POUDRIERE:
		error = NULL;
		ok = do_poudriere_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_CLAMAV:
		error = NULL;
		ok = do_clamav_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_SURICATA:
		error = NULL;
		ok = do_suricata_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_NFS:
	case ARC_JOB_KIND_ISCSI:
	case ARC_JOB_KIND_HAST:
		error = NULL;
		ok = do_netstore_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_SYSFILE:
		error = NULL;
		ok = do_sysfile_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_GEOM:
		error = NULL;
		ok = do_geom_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_SMTPD:
		/* A jail's, with or without a network of its own. */
		error = NULL;
		ok = scope_enter_jail(&j->w, sp->jail, &error, false) == 0 &&
		    do_smtpd_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_CERT:
		/* Any jail's: its files, not its network. */
		error = NULL;
		ok = scope_enter_jail(&j->w, sp->jail, &error, false) == 0 &&
		    do_cert(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_BIRD:
		/* Safe, configure runs on BIRD's own timer, a little longer
		 * than the job's wait: the job confirms it, or BIRD takes it
		 * back by itself should the daemon be stopped. */
		error = NULL;
		if (sp->safe && strcmp(sp->verb, "configure") == 0)
			ok = bird_configure_safe(&j->w, safe_wait(sp) + 5,
			    &error) == 0;
		else
			ok = do_bird_verb(&j->w, sp->verb, sp->names.v,
			    sp->names.n, &error) == 0;
		break;
	case ARC_JOB_KIND_KMOD:
		error = NULL;
		ok = do_kmod(&j->w, sp->verb, sp->names.v[0], sp->persist,
		    &error) == 0;
		break;
	case ARC_JOB_KIND_NTP:
		error = NULL;
		ok = do_ntp(&j->w, sp->names.v, sp->names.n, sp->remove,
		    sp->persist, &error) == 0;
		break;
	case ARC_JOB_KIND_RTADVD:
		error = NULL;
		ok = do_rtadvd(&j->w, sp->interface, sp->names.v, sp->names.n,
		    sp->remove, sp->persist, &error) == 0;
		break;
	case ARC_JOB_KIND_SYSCTL:
		error = NULL;
		ok = do_sysctl_set(&j->w, sp->names.v[0], sp->names.v[1],
		    sp->persist, &error) == 0;
		break;
	case ARC_JOB_KIND_IPFW:
		error = NULL;
		ok = do_ipfw_job(&j->w, sp, &held, &error) == 0;
		break;
	case ARC_JOB_KIND_PROCESS:
		error = NULL;
		ok = do_proc_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_PKG_CLEAN:
		error = NULL;
		ok = do_pkg_clean(&j->w, sp->jail, sp->force, &error) == 0;
		break;
	case ARC_JOB_KIND_JAIL_BASE:
		error = NULL;
		ok = do_jail_base(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_PKG_INSTALL:
		error = NULL;
		ok = do_pkg_install(&j->w, sp, &error) == 0;
		/* A plugin may be there now: asked again, not remembered. */
		plugins_forget();
		break;
	case ARC_JOB_KIND_IPSEC:
		error = NULL;
		ok = do_ipsec_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_IPSEC_SA:
		error = NULL;
		ok = do_sa_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_BRIDGE:
	case ARC_JOB_KIND_GENEVE:
		error = NULL;
		ok = do_l2_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_ZFS:
	case ARC_JOB_KIND_ZPOOL:
	case ARC_JOB_KIND_MOUNT:
	case ARC_JOB_KIND_GPART:
	case ARC_JOB_KIND_CAM:
		error = NULL;
		ok = do_storage_job(&j->w, sp, &error) == 0;
		break;
	case ARC_JOB_KIND_IF_VNET:
		error = NULL;
		if (!sp->remove && strcmp(sp->interface, "epair") == 0) {
			ok = give_pair(j, &error);
			break;
		}
		ok = do_if_vnet(&j->w, sp->interface, sp->jail, sp->remove,
		    sp->persist, &error) == 0;
		break;
	case ARC_JOB_KIND_IF_STATE:
		error = NULL;
		ok = do_if_state(&j->w, sp->interface, sp->up, &error) == 0;
		break;
	case ARC_JOB_KIND_ROUTE:
		error = NULL;
		rm.metric = sp->has_metric ? sp->metric : 0;
		rm.weight = sp->has_weight ? sp->weight : 0;
		rm.source = sp->source;
		ok = do_route(&j->w, sp->destination, sp->gateway, sp->remove,
		    sp->has_fib ? sp->fib : 0, &rm, sp->persist, &error) == 0;
		break;
	case ARC_JOB_KIND_SERVICE_CONFIG:
		memset(&scq, 0, sizeof(scq));
		memset(&scr, 0, sizeof(scr));
		scq.service = sp->service;
		scq.variables.v = sp->variables.v;
		scq.variables.n = sp->variables.n;
		do_service_config(&j->w, &scq, &scr);
		ok = scr.ok;
		error = scr.error;
		break;
	default:
		memset(&uq, 0, sizeof(uq));
		memset(&ur, 0, sizeof(ur));
		uq.jail = sp->jail;
		uq.names.v = sp->names.v;
		uq.names.n = sp->names.n;
		/* Forced: to packages built for a newer FreeBSD too. */
		uq.has_ignore_osversion = sp->force;
		uq.ignore_osversion = sp->force;
		uq.has_pkg_ip = sp->has_pkg_ip;
		uq.pkg_ip = sp->pkg_ip;
		uq.pkg_repo = sp->pkg_repo;
		do_pkg_upgrade(&j->w, &uq, &ur);
		ok = ur.ok;
		error = ur.error;
		break;
	}
	/* A safe change stays only when the client is heard from again;
	 * and what runs on a timer of its own (BIRD) is then told so. */
	if (ok && go && sp->safe && !await_confirm(j)) {
		ok = false;
		error = undo(j);
		held = false;
	} else if (ok && go && sp->safe && (error = confirm_apply(j)) != NULL)
		ok = false;
	undo_forget(j);
	/* The firewall's old rules waited for that: now they go. */
	if (held)
		(void)ipfw_settle(&j->w, true);
	if (!lane) {
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
	}
	/* Cancelled at work: said so, whatever the program said. */
	if (!ok && j->w.cancel)
		error = "cancelled while at work: pkg was stopped";
	step_end(&j->w, root, ok, NULL);

	/* Said while the job is still ours: once done, it may be forgotten. */
	logmsg(ok ? LOG_INFO : LOG_NOTICE, "%s: job %ju: %s: %s", j->peer,
	    (uintmax_t)j->id, j->title, ok ? "ok" : error != NULL ? error :
	    "failed");
	{
		ucl_object_t	*e;
		char		*js;

		/* An event too, for whoever is told of them (mail). */
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromint((int64_t)j->id),
		    "id", 0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(j->title),
		    "title", 0, false);
		ucl_object_insert_key(e, ucl_object_frombool(ok), "ok", 0,
		    false);
		if (!ok)
			ucl_object_insert_key(e, ucl_object_fromstring(error !=
			    NULL ? error : "failed"), "error", 0, false);
		if ((js = (char *)ucl_object_emit(e, UCL_EMIT_JSON_COMPACT)) !=
		    NULL)
			event_add("job", "%s", js);
		free(js);
		ucl_object_unref(e);
	}
	pthread_mutex_lock(&jobs_lock);
	j->ok = ok;
	j->error = error;
	j->finished = time(NULL);
	j->state = ARC_JOB_STATE_DONE;
	trim();
	pthread_mutex_unlock(&jobs_lock);
}

/*
 * May the job run beside others in a lane: pkg in a jail named (each
 * jail its own packages, database and lock), not a safe change, which
 * waits for its confirmation alone.
 */
static bool
pkg_lane(const struct arc_job_spec *sp)
{

	return ((sp->kind == ARC_JOB_KIND_PKG_UPGRADE ||
	    sp->kind == ARC_JOB_KIND_PKG_INSTALL ||
	    sp->kind == ARC_JOB_KIND_PKG_CLEAN ||
	    sp->kind == ARC_JOB_KIND_JAIL_BASE) && !sp->safe &&
	    sp->jail != NULL && sp->jail[0] != '\0' &&
	    strcmp(sp->jail, "*") != 0);
}

/* The first job in the queue still to run, or NULL; jobs_lock held. */
static struct qjob *
next_queued(void)
{
	struct qjob	*j;

	TAILQ_FOREACH(j, &jobs, link)
		if (j->state == ARC_JOB_STATE_QUEUED)
			return (j);
	return (NULL);
}

/*
 * The next job for a lane: the first queued one of pkg in a jail not at
 * work already, before the first queued job of another kind; NULL if
 * none.  A jail's own are taken in order: one behind a busy jail's is
 * busy too.  *morep: a job of pkg in a jail is queued there still.
 * jobs_lock held.
 */
static struct qjob *
next_lane(bool *morep)
{
	struct qjob	*j;

	*morep = false;
	TAILQ_FOREACH(j, &jobs, link) {
		if (j->state != ARC_JOB_STATE_QUEUED)
			continue;
		if (!pkg_lane(&j->spec))
			break;
		*morep = true;
		if (!lane_jail_busy(j->spec.jail))
			return (j);
	}
	return (NULL);
}

/* Is a job of pkg in that jail at work in a lane?  jobs_lock held. */
static bool
lane_jail_busy(const char *jail)
{
	struct qjob	*j;

	TAILQ_FOREACH(j, &jobs, link)
		if (j->state == ARC_JOB_STATE_RUNNING && pkg_lane(&j->spec) &&
		    strcmp(j->spec.jail, jail) == 0)
			return (true);
	return (false);
}

static void *
lane(void *arg)
{
	struct qjob	*j = arg;

	run(j, true);
	pthread_mutex_lock(&jobs_lock);
	lanes_busy--;
	pthread_cond_broadcast(&jobs_cv);
	pthread_mutex_unlock(&jobs_lock);
	return (NULL);
}

/*
 * The jobs of pkg in jails at the head of the queue, up to PKG_LANES at
 * once under one hold of change_lock: a jail's download that stalls
 * holds up no other jail.  Taken in the queue's order, a jail's own one
 * after another; the first job of another kind waits for every lane.
 */
static void
lanes(void)
{
	pthread_attr_t	 attr;
	pthread_t	 tid;
	struct qjob	*j;
	bool		 more;
	int		 error;

	pthread_mutex_lock(&change_lock);
	(void)change_note("pkg in jails, %d at once", jobs_lanes());
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_mutex_lock(&jobs_lock);
	for (;;) {
		j = lanes_busy < lanes_max ? next_lane(&more) : NULL;
		if (lanes_busy >= lanes_max)
			more = true;
		if (j != NULL) {
			j->state = ARC_JOB_STATE_RUNNING;
			j->started = time(NULL);
			lanes_busy++;
			if ((error = pthread_create(&tid, &attr, lane, j)) != 0)
				errc(1, error, "pthread_create");
			continue;
		}
		if (lanes_busy == 0 && !more)
			break;
		pthread_cond_wait(&jobs_cv, &jobs_lock);
	}
	pthread_mutex_unlock(&jobs_lock);
	pthread_attr_destroy(&attr);
	(void)change_note(NULL);
	pthread_mutex_unlock(&change_lock);
}

/* How many lanes there are: 1 to 32. */
int
jobs_lanes(void)
{
	int	n;

	pthread_mutex_lock(&jobs_lock);
	n = lanes_max;
	pthread_mutex_unlock(&jobs_lock);
	return (n);
}

/*
 * The lanes set, and kept in jobs.conf for the next start; a lane at
 * work beyond a smaller number finishes, and no new one starts until
 * fewer are busy.  NULL, or why not.
 */
const char *
jobs_set_lanes(int n)
{
	FILE	*fp;
	char	 tmp[PATH_MAX];

	if (n < 1 || n > 32)
		return ("lanes is 1 to 32");
	snprintf(tmp, sizeof(tmp), "%s.new", opts.jobs_conf);
	if ((fp = fopen(tmp, "we")) == NULL)
		return ("jobs.conf could not be written");
	fprintf(fp, "# Written by arcana-agent: jobs-set.\nlanes=%d\n", n);
	if (fclose(fp) != 0 || rename(tmp, opts.jobs_conf) == -1) {
		(void)unlink(tmp);
		return ("jobs.conf could not be written");
	}
	pthread_mutex_lock(&jobs_lock);
	lanes_max = n;
	pthread_cond_broadcast(&jobs_cv);
	pthread_mutex_unlock(&jobs_lock);
	logmsg(LOG_INFO, "jobs: pkg in jails, %d at once", n);
	return (NULL);
}

/* jobs.conf read at start: lanes=N; absent or odd, the default. */
void
jobs_conf_load(void)
{
	FILE	*fp;
	char	 line[128];
	long	 n;

	lanes_max = opts.pkg_lanes;
	if ((fp = fopen(opts.jobs_conf, "re")) == NULL)
		return;
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (strncmp(line, "lanes=", 6) != 0)
			continue;
		n = strtol(line + 6, NULL, 10);
		if (n >= 1 && n <= 32)
			lanes_max = (int)n;
	}
	fclose(fp);
}

static void *
runner(void *arg __unused)
{
	struct qjob	*j;

	for (;;) {
		pthread_mutex_lock(&jobs_lock);
		while ((j = next_queued()) == NULL)
			pthread_cond_wait(&jobs_cv, &jobs_lock);
		if (pkg_lane(&j->spec)) {
			pthread_mutex_unlock(&jobs_lock);
			lanes();
			continue;
		}
		j->state = ARC_JOB_STATE_RUNNING;
		j->started = time(NULL);
		pthread_mutex_unlock(&jobs_lock);
		run(j, false);
	}
	return (NULL);
}

/* Start the thread that runs the queue; after daemon(3). */
void
jobs_init(void)
{
	pthread_attr_t	attr;
	pthread_t	tid;
	int		error;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if ((error = pthread_create(&tid, &attr, runner, NULL)) != 0)
		errc(1, error, "pthread_create");
	pthread_attr_destroy(&attr);
}

/* j as a reply structure in w's pool; jobs_lock held. */
static void
fill(struct work *w, struct arc_job *o, struct qjob *j, bool trace)
{

	memset(o, 0, sizeof(*o));
	o->has_id = true;
	o->id = j->id;
	o->has_kind = true;
	o->kind = j->spec.kind;
	o->title = wtext(w, wstrdup(w, j->title));
	o->has_state = true;
	o->state = j->state;
	o->has_created = true;
	o->created = j->created;
	o->peer = wtext(w, wstrdup(w, j->peer));
	if (j->state != ARC_JOB_STATE_QUEUED &&
	    j->state != ARC_JOB_STATE_CANCELLED) {
		o->has_started = true;
		o->started = j->started;
	}
	if (j->state == ARC_JOB_STATE_UNCONFIRMED) {
		o->has_confirm_by = true;
		o->confirm_by = j->confirm_by;
	}
	if (j->state == ARC_JOB_STATE_DONE) {
		o->has_ok = true;
		o->ok = j->ok;
		o->error = wtext(w, wstrdup(w, j->error));
		o->has_finished = true;
		o->finished = j->finished;
	}
	if (trace)
		trace_copy(w, &j->w, &o->trace.v, &o->trace.n);
}

/*
 * Queue n jobs in order.  The specs have been checked by the caller.
 * The queued jobs come back in w's pool.
 */
int
jobs_submit(const struct arc_job_spec *specs, size_t n, const char *peer,
    struct work *w, const struct arc_job **vp, size_t *np)
{
	struct arc_job	*v;
	struct qjob	*j;
	size_t		 i;

	v = wcalloc(w, n + 1, sizeof(*v));
	pthread_mutex_lock(&jobs_lock);
	for (i = 0; i < n; i++) {
		if ((j = calloc(1, sizeof(*j))) == NULL)
			err(1, "calloc");
		j->id = nextid++;
		j->state = ARC_JOB_STATE_QUEUED;
		j->created = time(NULL);
		spec_copy(&j->spec, &specs[i]);
		j->title = title_of(&j->spec);
		j->peer = xdup(peer);
		work_init(&j->w);
		TAILQ_INSERT_TAIL(&jobs, j, link);
		fill(w, &v[i], j, false);
		logmsg(LOG_INFO, "%s: job %ju queued: %s", peer,
		    (uintmax_t)j->id, j->title);
	}
	pthread_cond_signal(&jobs_cv);
	pthread_mutex_unlock(&jobs_lock);
	*vp = v;
	*np = n;
	return (0);
}

/* The jobs that have not finished: each holds its trace in memory. */
size_t
jobs_waiting(void)
{
	struct qjob	*j;
	size_t		 n;

	n = 0;
	pthread_mutex_lock(&jobs_lock);
	TAILQ_FOREACH(j, &jobs, link)
		if (j->state != ARC_JOB_STATE_DONE &&
		    j->state != ARC_JOB_STATE_CANCELLED)
			n++;
	pthread_mutex_unlock(&jobs_lock);
	return (n);
}

/* Every job known, oldest first, without traces. */
void
jobs_list(struct work *w, const struct arc_job **vp, size_t *np)
{
	struct arc_job	*v;
	struct qjob	*j;
	size_t		 n;

	pthread_mutex_lock(&jobs_lock);
	n = 0;
	TAILQ_FOREACH(j, &jobs, link)
		n++;
	v = wcalloc(w, n + 1, sizeof(*v));
	n = 0;
	TAILQ_FOREACH(j, &jobs, link)
		fill(w, &v[n++], j, false);
	pthread_mutex_unlock(&jobs_lock);
	*vp = v;
	*np = n;
}

/* One job with its trace so far, or NULL. */
const struct arc_job *
jobs_get(struct work *w, uint64_t id)
{
	struct arc_job	*o;
	struct qjob	*j;

	o = NULL;
	pthread_mutex_lock(&jobs_lock);
	TAILQ_FOREACH(j, &jobs, link)
		if (j->id == id) {
			o = wcalloc(w, 1, sizeof(*o));
			fill(w, o, j, true);
			break;
		}
	pthread_mutex_unlock(&jobs_lock);
	return (o);
}

/*
 * Take a queued job out of the queue; a safe change waiting to be
 * confirmed is undone now, as it would be when its timer runs out.
 * NULL and *errp if neither can be: a job at work is left to finish,
 * a change stopped half way being what would not be safe.
 */
const struct arc_job *
jobs_cancel(struct work *w, uint64_t id, const char **errp)
{
	struct arc_job	*o;
	struct qjob	*j;

	o = NULL;
	*errp = "no such job";
	pthread_mutex_lock(&jobs_lock);
	TAILQ_FOREACH(j, &jobs, link) {
		if (j->id != id)
			continue;
		if (j->state == ARC_JOB_STATE_UNCONFIRMED) {
			j->rejected = true;
			pthread_cond_broadcast(&confirm_cv);
			o = wcalloc(w, 1, sizeof(*o));
			fill(w, o, j, false);
			break;
		}
		/* pkg in a jail at work: stopped, which a download or
		 * the catalogue's update survives; a change it was making
		 * pkg's own database rolls back. */
		if (j->state == ARC_JOB_STATE_RUNNING && pkg_lane(&j->spec)) {
			j->w.cancel = true;
			o = wcalloc(w, 1, sizeof(*o));
			fill(w, o, j, false);
			break;
		}
		if (j->state != ARC_JOB_STATE_QUEUED) {
			*errp = j->state == ARC_JOB_STATE_RUNNING ?
			    "the job is running; it cannot be taken back" :
			    "the job has finished";
			break;
		}
		j->state = ARC_JOB_STATE_CANCELLED;
		j->finished = time(NULL);
		o = wcalloc(w, 1, sizeof(*o));
		fill(w, o, j, false);
		break;
	}
	pthread_mutex_unlock(&jobs_lock);
	return (o);
}

/* The jobs that have not started, to the log: they go with the daemon. */
void
jobs_log(int pri)
{
	struct qjob	*j;

	pthread_mutex_lock(&jobs_lock);
	TAILQ_FOREACH(j, &jobs, link)
		if (j->state == ARC_JOB_STATE_QUEUED ||
		    (j->state == ARC_JOB_STATE_RUNNING && !j->begun))
			logmsg(pri, "queued, will not run: job %ju: %s, from %s",
			    (uintmax_t)j->id, j->title, j->peer);
	pthread_mutex_unlock(&jobs_lock);
}

/* The client is still there: an unconfirmed job's change stays. */
const struct arc_job *
jobs_confirm(struct work *w, uint64_t id, const char **errp)
{
	struct arc_job	*o;
	struct qjob	*j;

	o = NULL;
	*errp = "no such job";
	pthread_mutex_lock(&jobs_lock);
	TAILQ_FOREACH(j, &jobs, link) {
		if (j->id != id)
			continue;
		if (j->state != ARC_JOB_STATE_UNCONFIRMED || j->rejected) {
			*errp = j->rejected ? "the job was cancelled: it is being "
			    "undone" : "the job is not waiting to be confirmed";
			break;
		}
		j->confirmed = true;
		pthread_cond_broadcast(&confirm_cv);
		o = wcalloc(w, 1, sizeof(*o));
		fill(w, o, j, false);
		break;
	}
	pthread_mutex_unlock(&jobs_lock);
	return (o);
}

/* The daemon is stopping: those who wait for a confirmation stop. */
void
jobs_wake(void)
{

	pthread_mutex_lock(&jobs_lock);
	pthread_cond_broadcast(&confirm_cv);
	pthread_mutex_unlock(&jobs_lock);
}

