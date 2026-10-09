/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Requests to arcana-agent.  Each one runs in a Kore task thread, which
 * makes a synchronous cblink call (mutual TLS over TCP, or the local
 * socket) so the event loop never waits on a jail(8) that takes minutes.
 * The reply's typed structures become JSON here, and the console's own
 * steps are put on top of the daemon's trace.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <vis.h>

#include <openssl/evp.h>

#include "console.h"

enum op {
	OP_HELLO,
	OP_LIST,
	OP_ACTION,
	OP_ADDRESS,
	OP_SERVICES,
	OP_SERVICE_ACTION,
	OP_SERVICE_CONFIG,
	OP_NETWORK,
	OP_STATS,
	OP_PACKAGES,
	OP_PKG_UPGRADE,
	OP_JOB_SUBMIT,
	OP_JOBS,
	OP_JOB,
	OP_JOB_CANCEL,
	OP_AGENT_UPDATE,
	OP_AGENT_BUILD,
	OP_CONSOLE_UPDATE,
	OP_ROUTE_LOOKUP,
	OP_BIRD_CONFIG,
	OP_KERNEL,
	OP_STORAGE,
	OP_FSTAB,
	OP_IPFW_RULES,
	OP_TRANSPORT,
	OP_SYSCTL,
	OP_PROCESSES,
	OP_LOG,
	OP_HISTORY,
	OP_EVENTS,
	OP_FW_TRACE,
};

struct call {
	struct kore_task	 task;		/* first: Kore frees the call */
	enum op			 op;
	char			 sid[9];
	char			*sname;
	char			*uri;
	char			*peer;
	char			 route[128];
	uint64_t		 t0;		/* µs, request arrived */
	uint64_t		 auth_us;	/* the session check */
	bool			 config_only;
	char			 jail[256];
	uint8_t			 action;
	struct arc_address_req	 addr;
	char			 address[65];
	char			 ifname[16];
	uint8_t			 family;	/* network */
	uint32_t		 fib;		/* network, route lookup */
	uint32_t		 offset;		/* network: rows to leave out */
	char			 scope[256];	/* the vnet jail whose network it is */
	bool			 refresh;	/* packages */
	bool			 dry_run;	/* pkg-upgrade */
	bool			 anyos;		/* pkg-upgrade: IGNORE_OSVERSION */
	bool			 installed;	/* packages: those installed */
	uint8_t			 pkg_ip;	/* packages: pkg -4, -6, or 0 */
	char			**names;	/* pkg-upgrade: packages */
	size_t			 nnames;
	struct arc_job_spec	*specs;		/* job-submit: the batch */
	size_t			 nspecs;
	uint64_t		 jobid;		/* job, job-cancel */
	bool			 restart;	/* agent-update */
	char			*host_keys;	/* agent-build: confirmed */
	char			*text;		/* bird-config: the new text */
	struct arc_variable	*vars;		/* service-config: to set */
	size_t			 nvars;
	bool			 reads;		/* changes nothing: may be asked twice */
	bool			 retry;		/* transport: try SCTP again */
	char			 logname[129];	/* log: the file */
	uint64_t		 pos;		/* log: from where; history: after when */
	bool			 has_pos;
	uint32_t		 lines;		/* log: at most */
	bool			 fresh;		/* a connection of its own, not kept */
	bool			 moved;		/* transport switch: it answered */
	char			*json;		/* the reply, from the thread */
	int			 status;
};

/*
 * The connections to the agents, kept open between requests: a request
 * takes one that is idle, or makes one, and gives it back when it has
 * its answer.  Several requests to one host at once have one each, and
 * leave as many behind.  One that nobody took for a while is closed,
 * and so is one the other end has closed or written to unasked.
 *
 * An SCTP association is not taken but shared: the requests to a host
 * that run at once all go over the one association, which a thread of
 * its own runs (a cbl_loop), each request waiting for its own answer.
 * A dump is not sent over it: a reader that is slow holds the reading
 * of the connection its dump came on, which would hold every other
 * request with it; it has a connection of its own, as on TCP.
 */
#define	POOL_MAX	48
#define	POOL_PER_HOST	4
#define	POOL_IDLE_US	(90 * 1000000ULL)

struct pooled {
	char		*uri;
	char		*peer;
	cbl_conn	*conn;
	cbl_tls		*tls;
	uint16_t	 family;
	uint32_t	 version;
	uint32_t	 groups[ARC_MCGRP_COUNT];	/* the family's, resolved */
	uint64_t	 since;		/* µs, when it was given back */
};

static struct pooled	pool[POOL_MAX];
static int		npool;
static pthread_mutex_t	pool_lock = PTHREAD_MUTEX_INITIALIZER;

struct shared {
	struct pooled	 p;
	int		 users;		/* requests on it now */
	bool		 dead;		/* to be closed once nobody uses it */
};

static struct shared	shared[POOL_MAX];
static int		nshared;
static cbl_loop		*sloop;		/* runs the shared associations */
static pthread_once_t	sloop_once = PTHREAD_ONCE_INIT;

static cbl_ctx	*ctx;

static const char *state_names[] = {
	[ARC_JAIL_STATE_RUNNING] = "running",
	[ARC_JAIL_STATE_STOPPED] = "stopped",
	[ARC_JAIL_STATE_DYING] = "dying",
	[ARC_JAIL_STATE_ABSENT] = "absent",
};

static const char *kind_names[] = {
	[ARC_STEP_KIND_DAEMON] = "daemon",
	[ARC_STEP_KIND_LIB] = "lib",
	[ARC_STEP_KIND_SYSCALL] = "syscall",
	[ARC_STEP_KIND_FILE] = "file",
	[ARC_STEP_KIND_EXEC] = "exec",
};

static const char *status_names[] = {
	[ARC_STEP_STATUS_OK] = "ok",
	[ARC_STEP_STATUS_FAILED] = "failed",
	[ARC_STEP_STATUS_INCOMPLETE] = "incomplete",
};

static const char *action_names[] = {
	[ARC_ACTION_START] = "start",
	[ARC_ACTION_STOP] = "stop",
	[ARC_ACTION_RESTART] = "restart",
	[ARC_ACTION_KILL] = "kill",
};

static const char *net_kind_names[] = {
	[ARC_NET_KIND_ROUTES] = "routes",
	[ARC_NET_KIND_NEXTHOPS] = "nexthops",
	[ARC_NET_KIND_CONNECTIONS] = "connections",
	[ARC_NET_KIND_SOCKETS] = "sockets",
	[ARC_NET_KIND_INTERFACES] = "interfaces",
	[ARC_NET_KIND_NETGRAPH] = "netgraph",
	[ARC_NET_KIND_WIREGUARD] = "wireguard",
	[ARC_NET_KIND_BIRD] = "bird",
	[ARC_NET_KIND_BIRD_ROUTES] = "bird-routes",
	[ARC_NET_KIND_BRIDGES] = "bridges",
	[ARC_NET_KIND_GENEVE] = "geneve",
	[ARC_NET_KIND_IPFW] = "ipfw",
	[ARC_NET_KIND_NHGROUPS] = "nhgroups",
	[ARC_NET_KIND_NEIGHBOURS] = "neighbours",
	[ARC_NET_KIND_IPSEC] = "ipsec",
};

static const char *service_action_names[] = {
	[ARC_SERVICE_ACTION_START] = "start",
	[ARC_SERVICE_ACTION_STOP] = "stop",
	[ARC_SERVICE_ACTION_RESTART] = "restart",
	[ARC_SERVICE_ACTION_RELOAD] = "reload",
	[ARC_SERVICE_ACTION_ENABLE] = "enable",
	[ARC_SERVICE_ACTION_DISABLE] = "disable",
};

static uint64_t	 now_us(void);
static void	 put(ucl_object_t *, const char *, ucl_object_t *);
static void	 put_str(ucl_object_t *, const char *, const char *);
static ucl_object_t *strs(const char *const *, size_t);
static ucl_object_t *output(const struct cbl_bytes *);
static ucl_object_t *host_object(const struct arc_host *);
static ucl_object_t *jail_object(const struct arc_jail *);
static ucl_object_t *service_object(const struct arc_service *);
static void	 call_free_vars(struct call *);
static ucl_object_t *job_object(struct call *, const struct arc_job *, bool,
		    uint64_t);
static const char *spec_from_json(const ucl_object_t *, struct arc_job_spec *);
static bool	 query_param(struct http_request *, const char *, char *,
		    size_t);
static void	 spec_free(struct arc_job_spec *);
static char	*jdup(const ucl_object_t *, const char *);
static ucl_object_t *step_object(int, int, const char *, const char *,
		    const char *, bool, uint64_t);
static ucl_object_t *trace_object(struct call *, const struct arc_step *,
		    size_t, const char *, bool, uint64_t);
static int	 call_run(struct kore_task *);
static int	 call_start(struct http_request *, struct call *);
static int	 call_finish(struct http_request *);
static struct call *call_new(struct http_request *, enum op);

static uint64_t
now_us(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000);
}

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	put(o, key, v != NULL ? ucl_object_fromstring(v) :
	    ucl_object_typed_new(UCL_NULL));
}

static ucl_object_t *
strs(const char *const *v, size_t n)
{
	ucl_object_t	*a;
	size_t		 i;

	a = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < n; i++)
		ucl_array_append(a, ucl_object_fromstring(v[i]));
	return (a);
}

/*
 * What a program printed, as text: control characters other than
 * newlines and tabs, and bytes that are not UTF-8, as vis(3) escapes
 * ("\037"), the way arcanactl(8) shows them.
 */
static ucl_object_t *
output(const struct cbl_bytes *b)
{
	ucl_object_t	*o;
	char		*v;

	/* ucl_object_fromlstring() takes length 0 to mean strlen(). */
	if (b->len == 0)
		return (ucl_object_fromstring(""));
	if ((v = malloc(b->len * 4 + 1)) == NULL)
		return (ucl_object_fromstring(""));
	strvisx(v, b->p, b->len, VIS_SAFE | VIS_OCTAL | VIS_CSTYLE);
	o = ucl_object_fromstring(v);
	free(v);
	return (o);
}

static bool
same(const char *a, const char *b)
{

	return ((a == NULL && b == NULL) || (a != NULL && b != NULL &&
	    strcmp(a, b) == 0));
}

static void
pooled_close(struct pooled *p)
{

	cbl_conn_free(p->conn);
	cbl_tls_free(p->tls);
	free(p->uri);
	free(p->peer);
}

static bool	pool_take_own(const char *, const char *, struct pooled *);

static bool
is_sctp(const char *uri)
{

	return (strncmp(uri, "sctp:", 5) == 0);
}

static void *
sloop_run(void *arg __unused)
{

	(void)cbl_loop_run(sloop);
	return (NULL);
}

/* The thread that runs the shared associations, once. */
static void
sloop_start(void)
{
	pthread_t	tid;
	int		error;

	if ((error = cbl_loop_new(ctx, &sloop)) != 0) {
		kore_log(LOG_ERR, "cbl_loop_new: %s", strerror(error));
		sloop = NULL;
		return;
	}
	if ((error = pthread_create(&tid, NULL, sloop_run, NULL)) != 0) {
		kore_log(LOG_ERR, "pthread_create: %s", strerror(error));
		cbl_loop_free(sloop);
		sloop = NULL;
		return;
	}
	(void)pthread_detach(tid);
}

/* Closed once its last user is done; called with the lock held. */
static void
shared_drop(int i)
{

	if (shared[i].users > 0)
		return;
	pooled_close(&shared[i].p);
	shared[i] = shared[--nshared];
}

/* The shared association to uri, with one user more; false if none. */
static bool
shared_take(const char *uri, const char *peer, struct pooled *out)
{
	uint64_t	now;
	int		i;
	bool		found;

	found = false;
	now = now_us();
	pthread_mutex_lock(&pool_lock);
	for (i = nshared - 1; i >= 0; i--) {
		if (!shared[i].dead && (!cbl_conn_is_open(shared[i].p.conn) ||
		    (shared[i].users == 0 && now - shared[i].p.since >
		    POOL_IDLE_US)))
			shared[i].dead = true;
		if (shared[i].dead) {
			shared_drop(i);
			continue;
		}
		if (found || strcmp(shared[i].p.uri, uri) != 0 ||
		    !same(shared[i].p.peer, peer))
			continue;
		*out = shared[i].p;
		out->uri = strdup(uri);
		out->peer = peer != NULL ? strdup(peer) : NULL;
		shared[i].users++;
		found = true;
	}
	pthread_mutex_unlock(&pool_lock);
	return (found);
}

/*
 * A request is done with a shared association, or one of its own over
 * SCTP becomes the shared one: attached to the loop, unless there is
 * one already.  False when conn is not and is not to be shared.
 */
static bool
shared_give(const char *uri, const char *peer, cbl_conn *conn, cbl_tls *tls,
    const struct arc_client *cl)
{
	struct shared	n;
	int		i;

	pthread_mutex_lock(&pool_lock);
	for (i = 0; i < nshared; i++)
		if (shared[i].p.conn == conn) {
			shared[i].users--;
			shared[i].p.since = now_us();
			if (shared[i].dead)
				shared_drop(i);
			pthread_mutex_unlock(&pool_lock);
			return (true);
		}
	for (i = 0; i < nshared; i++)
		if (!shared[i].dead && strcmp(shared[i].p.uri, uri) == 0 &&
		    same(shared[i].p.peer, peer))
			break;
	pthread_mutex_unlock(&pool_lock);
	/* One is shared already, or there is no room: this one goes. */
	if (i < nshared || nshared >= POOL_MAX)
		return (false);
	(void)pthread_once(&sloop_once, sloop_start);
	if (sloop == NULL || cbl_conn_attach(conn, sloop) != 0)
		return (false);
	memset(&n, 0, sizeof(n));
	n.p.conn = conn;
	n.p.tls = tls;
	n.p.family = cl->family;
	n.p.version = cl->version;
	memcpy(n.p.groups, cl->groups, sizeof(n.p.groups));
	n.p.since = now_us();
	if ((n.p.uri = strdup(uri)) == NULL || (peer != NULL && (n.p.peer =
	    strdup(peer)) == NULL)) {
		pooled_close(&n.p);
		return (true);
	}
	pthread_mutex_lock(&pool_lock);
	if (nshared < POOL_MAX)
		shared[nshared++] = n;
	else
		n.p.conn = NULL;
	pthread_mutex_unlock(&pool_lock);
	if (n.p.conn == NULL)
		pooled_close(&n.p);
	return (true);
}

/*
 * A connection not to be used again: closed, or for a shared one,
 * closed once the requests on it now are done.
 */
static void
pool_drop(cbl_conn *conn, cbl_tls *tls)
{
	int	i;

	pthread_mutex_lock(&pool_lock);
	for (i = 0; i < nshared; i++)
		if (shared[i].p.conn == conn) {
			shared[i].users--;
			shared[i].dead = true;
			shared_drop(i);
			pthread_mutex_unlock(&pool_lock);
			return;
		}
	pthread_mutex_unlock(&pool_lock);
	cbl_conn_free(conn);
	cbl_tls_free(tls);
}

/* An idle connection to uri, if one is there and still good. */
static bool
pool_take(const char *uri, const char *peer, struct pooled *out)
{

	if (is_sctp(uri))
		return (shared_take(uri, peer, out));
	return (pool_take_own(uri, peer, out));
}

/* The same, of the connections that are not shared. */
static bool
pool_take_own(const char *uri, const char *peer, struct pooled *out)
{
	struct pollfd	pfd;
	uint64_t	now;
	int		i;
	bool		found;

	found = false;
	now = now_us();
	pthread_mutex_lock(&pool_lock);
	for (i = npool - 1; i >= 0; i--) {
		bool	mine, dead;

		mine = !found && strcmp(pool[i].uri, uri) == 0 && same(
		    pool[i].peer, peer);
		dead = now - pool[i].since > POOL_IDLE_US ||
		    !cbl_conn_is_open(pool[i].conn);
		if (!dead && mine) {
			/* Closed by the other end, or written to unasked. */
			pfd.fd = cbl_conn_fd(pool[i].conn);
			pfd.events = POLLIN;
			pfd.revents = 0;
			dead = pfd.fd == -1 || poll(&pfd, 1, 0) != 0;
		}
		if (!dead && !mine)
			continue;
		if (dead)
			pooled_close(&pool[i]);
		else {
			*out = pool[i];
			found = true;
		}
		pool[i] = pool[--npool];
	}
	pthread_mutex_unlock(&pool_lock);
	return (found);
}

/* Back for the next request; closed when there are enough already. */
static void
pool_give(const char *uri, const char *peer, cbl_conn *conn, cbl_tls *tls,
    const struct arc_client *cl)
{
	struct pooled	p;
	int		i, n;

	if (is_sctp(uri)) {
		if (!shared_give(uri, peer, conn, tls, cl)) {
			cbl_conn_free(conn);
			cbl_tls_free(tls);
		}
		return;
	}

	memset(&p, 0, sizeof(p));
	p.conn = conn;
	p.tls = tls;
	p.family = cl->family;
	p.version = cl->version;
	memcpy(p.groups, cl->groups, sizeof(p.groups));
	p.since = now_us();
	if ((p.uri = strdup(uri)) == NULL || (peer != NULL && (p.peer =
	    strdup(peer)) == NULL)) {
		pooled_close(&p);
		return;
	}
	pthread_mutex_lock(&pool_lock);
	for (i = 0, n = 0; i < npool; i++)
		if (strcmp(pool[i].uri, uri) == 0)
			n++;
	if (npool < POOL_MAX && n < POOL_PER_HOST) {
		pool[npool++] = p;
		p.conn = NULL;
	}
	pthread_mutex_unlock(&pool_lock);
	if (p.conn != NULL)
		pooled_close(&p);
}

/* A server went, or is reached another way: its connections go. */
void
hosts_forget(const char *uri)
{
	int	i;

	pthread_mutex_lock(&pool_lock);
	for (i = npool - 1; i >= 0; i--)
		if (strcmp(pool[i].uri, uri) == 0) {
			pooled_close(&pool[i]);
			pool[i] = pool[--npool];
		}
	for (i = nshared - 1; i >= 0; i--)
		if (strcmp(shared[i].p.uri, uri) == 0) {
			shared[i].dead = true;
			shared_drop(i);
		}
	pthread_mutex_unlock(&pool_lock);
}

/*
 * A connection to an agent for something that is not a call: one kept
 * from before or a new one, with the client set up on it.  NULL, or
 * why not.  hosts_release() gives it back, or closes it when it is not
 * to be trusted any more.
 */
const char *
hosts_connect(const char *uri, const char *peer, cbl_conn **connp,
    cbl_tls **tlsp, struct arc_client *cl)
{
	struct pooled	 kept;
	cbl_conn	*conn;
	cbl_tls		*tls;
	const char	*msg;
	int		 error;

	memset(cl, 0, sizeof(*cl));
	*connp = NULL;
	*tlsp = NULL;
	/* Not a shared one: see above. */
	if (pool_take_own(uri, peer, &kept)) {
		free(kept.uri);
		free(kept.peer);
		cl->conn = kept.conn;
		cl->family = kept.family;
		cl->version = kept.version;
		memcpy(cl->groups, kept.groups, sizeof(kept.groups));
		*connp = kept.conn;
		*tlsp = kept.tls;
		return (NULL);
	}
	conn = NULL;
	tls = NULL;
	if ((error = cbl_conn_new(ctx, uri, 0, &conn)) != 0)
		return (strerror(error));
	if (strncmp(uri, "unix:", 5) != 0) {
		if (cfg.tls_ca == NULL || cfg.tls_cert == NULL ||
		    cfg.tls_key == NULL) {
			cbl_conn_free(conn);
			return ("no tls { ca cert key } in web.conf");
		}
		if (cbl_tls_new(&tls) != 0 ||
		    cbl_tls_set_cert(tls, cfg.tls_cert, cfg.tls_key) != 0 ||
		    cbl_tls_set_ca(tls, cfg.tls_ca, NULL) != 0 ||
		    (peer != NULL && cbl_tls_set_peer_name(tls, peer) != 0)) {
			cbl_conn_free(conn);
			cbl_tls_free(tls);
			return ("the console's certificate could not be used");
		}
		(void)cbl_conn_set_tls(conn, tls);
	}
	if (cbl_conn_connect(conn) != 0) {
		/* The words are the connection's: said before it goes. */
		static _Thread_local char	why[256];

		msg = cbl_conn_errstr(conn);
		snprintf(why, sizeof(why), "%s", msg != NULL && msg[0] !=
		    '\0' ? msg : "cannot connect");
		cbl_conn_free(conn);
		cbl_tls_free(tls);
		return (why);
	}
	if (arc_client_init(cl, conn) != 0) {
		cbl_conn_free(conn);
		cbl_tls_free(tls);
		memset(cl, 0, sizeof(*cl));
		return ("no arcana family there");
	}
	*connp = conn;
	*tlsp = tls;
	return (NULL);
}

void
hosts_release(const char *uri, const char *peer, cbl_conn *conn, cbl_tls *tls,
    struct arc_client *cl, bool good)
{

	arc_client_fini(cl);
	/* A dump's own SCTP association may be the shared one after. */
	if (good && cbl_conn_is_open(conn))
		pool_give(uri, peer, conn, tls, cl);
	else
		pool_drop(conn, tls);
}

int
hosts_init(void)
{
	int	error;

	if ((error = cbl_ctx_new(&ctx)) != 0) {
		kore_log(LOG_ERR, "cbl_ctx_new: %s", strerror(error));
		return (-1);
	}
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_FRAME, CBLINK_MAX_FRAME);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_ATTRS, CBLINK_MAX_ATTRS);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_REQUEST_MS, CBLINK_TIMEOUT_MS);
	return (0);
}

static ucl_object_t *
host_object(const struct arc_host *h)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	if (h == NULL)
		return (o);
	put_str(o, "hostname", h->hostname);
	put_str(o, "sysname", h->sysname);
	put_str(o, "release", h->release);
	put_str(o, "machine", h->machine);
	put(o, "ncpu", ucl_object_fromint(h->ncpu));
	put(o, "physmem", ucl_object_fromint((int64_t)h->physmem));
	put(o, "boottime", ucl_object_fromint(h->boottime));
	put(o, "time", ucl_object_fromint(h->time));
	put(o, "securelevel", ucl_object_fromint(h->securelevel));
	put(o, "privileged", ucl_object_frombool(h->privileged));
	put_str(o, "version", h->version);
	put_str(o, "build", h->build);
	put(o, "plugins", strs(h->plugins.v, h->plugins.n));
	return (o);
}

static ucl_object_t *
jail_object(const struct arc_jail *j)
{
	ucl_object_t	*o, *ps, *p;
	size_t		 i;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", j->name);
	put_str(o, "state", j->has_state && j->state < nitems(state_names) ?
	    state_names[j->state] : "unknown");
	put(o, "jid", j->has_jid ? ucl_object_fromint(j->jid) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "configured", ucl_object_frombool(j->configured));
	put_str(o, "scope", j->scope);
	put_str(o, "hostname", j->hostname);
	put_str(o, "path", j->path);
	put(o, "ip4", strs(j->ip4.v, j->ip4.n));
	put(o, "ip6", strs(j->ip6.v, j->ip6.n));
	put(o, "vnet", ucl_object_frombool(j->vnet));
	if (j->plugins.n > 0)
		put(o, "plugins", strs(j->plugins.v, j->plugins.n));
	put_str(o, "osrelease", j->osrelease);
	put(o, "persist", ucl_object_frombool(j->persist));
	put_str(o, "interface", j->interface);
	if (j->has_nproc) {
		put(o, "nproc", ucl_object_fromint(j->nproc));
		put(o, "rss_kb", ucl_object_fromint((int64_t)j->rss_kb));
		put(o, "cpu_pct", ucl_object_fromdouble(j->cpu_pct));
		put(o, "securelevel", ucl_object_fromint(j->securelevel));
		put(o, "children", ucl_object_fromint(j->children));
	}
	ps = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < j->params.n; i++) {
		p = ucl_object_typed_new(UCL_OBJECT);
		put_str(p, "key", j->params.v[i].key);
		put(p, "values", strs(j->params.v[i].values.v,
		    j->params.v[i].values.n));
		ucl_array_append(ps, p);
	}
	put(o, "params", ps);
	return (o);
}

static ucl_object_t *
service_object(const struct arc_service *s)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", s->name);
	put_str(o, "path", s->path);
	put_str(o, "rcvar", s->rcvar);
	put(o, "enabled", s->has_enabled ? ucl_object_frombool(s->enabled) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "running", s->has_running ? ucl_object_frombool(s->running) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "pid", s->has_pid ? ucl_object_fromint(s->pid) :
	    ucl_object_typed_new(UCL_NULL));
	put_str(o, "status", s->status);
	return (o);
}

static void
call_free_vars(struct call *c)
{
	size_t	i;

	for (i = 0; i < c->nvars; i++) {
		kore_free((char *)(uintptr_t)c->vars[i].key);
		kore_free((char *)(uintptr_t)c->vars[i].value);
	}
	kore_free(c->vars);
	c->vars = NULL;
	c->nvars = 0;
}

static ucl_object_t *
step_object(int id, int parent, const char *kind, const char *label,
    const char *detail, bool ok, uint64_t us)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "id", ucl_object_fromint(id));
	put(o, "parent", ucl_object_fromint(parent));
	put_str(o, "kind", kind);
	put_str(o, "label", label);
	put_str(o, "detail", detail);
	put_str(o, "status", ok ? "ok" : "failed");
	put(o, "duration_us", ucl_object_fromint((int64_t)us));
	return (o);
}

/*
 * The console's steps (the API call, the session check, the cblink
 * request) with the daemon's trace under the request.
 */
static ucl_object_t *
trace_object(struct call *c, const struct arc_step *v, size_t n,
    const char *calldetail, bool callok, uint64_t callus)
{
	ucl_object_t	*a, *o;
	const char	*fn;
	char		 label[64];
	size_t		 i;
	bool		 ok;

	fn = c->op == OP_HELLO ? "arc_hello" : c->op == OP_LIST ? "arc_list" :
	    c->op == OP_ACTION ? "arc_action" : c->op == OP_ADDRESS ?
	    "arc_address" : c->op == OP_SERVICES ? "arc_services" :
	    c->op == OP_SERVICE_ACTION ? "arc_service_action" :
	    c->op == OP_NETWORK ? "arc_network" : c->op == OP_STORAGE ?
	    "arc_storage" : c->op == OP_FSTAB ? "arc_fstab" : c->op ==
	    OP_KERNEL ? "arc_kernel" : c->op == OP_TRANSPORT ? "arc_transport" :
	    c->op == OP_IPFW_RULES ? "arc_ipfw_rules" :
	    c->op == OP_PROCESSES ? "arc_processes" : c->op == OP_LOG ?
	    "arc_log" : c->op == OP_HISTORY ? "arc_history" : c->op ==
	    OP_EVENTS ? "arc_events" : c->op == OP_FW_TRACE ? "arc_fw_trace" :
	    c->op == OP_SYSCTL ? "arc_sysctl" : c->op == OP_STATS ? "arc_stats" : c->op == OP_PACKAGES ? "arc_packages" :
	    c->op == OP_PKG_UPGRADE ? "arc_pkg_upgrade" :
	    c->op == OP_JOB_SUBMIT ? "arc_job_submit" : c->op == OP_JOBS ?
	    "arc_jobs" : c->op == OP_JOB ? "arc_job" : c->op == OP_JOB_CANCEL ?
	    "arc_job_cancel" : c->op == OP_AGENT_UPDATE ? "arc_agent_update" :
	    c->op == OP_AGENT_BUILD ? "arc_agent_build" :
	    c->op == OP_CONSOLE_UPDATE ? "arc_console_update" :
	    c->op == OP_ROUTE_LOOKUP ? "arc_route_lookup" :
	    c->op == OP_BIRD_CONFIG ? "arc_bird_config" :
	    "arc_service_config";
	snprintf(label, sizeof(label), "libcblink %s()", fn);
	ok = callok;
	for (i = 0; i < n; i++)
		if (v[i].parent < 0 && v[i].status != ARC_STEP_STATUS_OK)
			ok = false;
	a = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(a, step_object(0, -1, "api", c->route, c->sname, ok,
	    now_us() - c->t0));
	ucl_array_append(a, step_object(1, 0, "auth", "session check",
	    "WebAuthn session cookie", true, c->auth_us));
	ucl_array_append(a, step_object(2, 0, "lib", label, calldetail,
	    callok, callus));
	for (i = 0; i < n; i++) {
		o = step_object((int)i + 3, v[i].parent < 0 ? 2 :
		    v[i].parent + 3, v[i].kind < nitems(kind_names) ?
		    kind_names[v[i].kind] : "lib", v[i].label, v[i].detail,
		    true, v[i].duration_us);
		put_str(o, "status", v[i].status < nitems(status_names) ?
		    status_names[v[i].status] : "incomplete");
		if (v[i].argv.n > 0) {
			put(o, "argv", strs(v[i].argv.v, v[i].argv.n));
			put(o, "exit", ucl_object_fromint(v[i].exit));
			put(o, "output", output(&v[i].output));
			put(o, "error_output", output(&v[i].error_output));
		}
		ucl_array_append(a, o);
	}
	return (a);
}

/* In a task thread: one cblink request, its reply as JSON. */
/*
 * The arcana-agent this console hands to hosts: the one a host built
 * for it from agent_source, once there is one, and otherwise the one
 * installed with it.
 */
static const char *
agent_path(bool *builtp)
{
	static char	built[MAXPATHLEN];
	struct stat	sb, si;
	bool		isbuilt;

	/*
	 * The one a host built, unless the one installed with the console
	 * is newer: after the console itself was updated, that is the
	 * agent of its version, and the built one is of the one before.
	 */
	snprintf(built, sizeof(built), "%s/agent/arcana-agent", cfg.datadir);
	isbuilt = cfg.agent_source != NULL && stat(built, &sb) == 0 &&
	    (stat(cfg.agent_binary, &si) == -1 || sb.st_mtim.tv_sec >=
	    si.st_mtim.tv_sec);
	if (builtp != NULL)
		*builtp = isbuilt;
	return (isbuilt ? built : cfg.agent_binary);
}

/*
 * Returns what is wrong, or NULL with the program, to be freed, and its
 * SHA-256 in hex.
 */
static const char *
agent_binary(uint8_t **binp, size_t *lenp, char sha[65])
{
	struct stat	 sb;
	unsigned char	 md[EVP_MAX_MD_SIZE];
	uint8_t		*bin;
	ssize_t		 n;
	size_t		 off;
	unsigned int	 i, mdlen;
	int		 fd;

	if ((fd = open(agent_path(NULL), O_RDONLY | O_CLOEXEC)) == -1)
		return (errno == ENOENT ? "the console has no arcana-agent to "
		    "send: agent_binary in web.conf names none" :
		    "the console cannot read its arcana-agent");
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode) || sb.st_size == 0 ||
	    sb.st_size > ARC_MAX_BINARY || (bin = malloc((size_t)sb.st_size)) ==
	    NULL) {
		close(fd);
		return ("the console's arcana-agent is not a program an "
		    "update can carry");
	}
	for (off = 0; off < (size_t)sb.st_size; off += (size_t)n)
		if ((n = read(fd, bin + off, (size_t)sb.st_size - off)) <= 0)
			break;
	close(fd);
	if (off < (size_t)sb.st_size || EVP_Digest(bin, off, md, &mdlen,
	    EVP_sha256(), NULL) != 1) {
		free(bin);
		return ("the console cannot read its arcana-agent");
	}
	for (i = 0; i < mdlen; i++)
		snprintf(sha + 2 * i, 3, "%02x", md[i]);
	*binp = bin;
	*lenp = off;
	return (NULL);
}

/* What "<program> -V" prints after "arcana-agent ", or nothing. */
static void
version_of(const char *path, char *buf, size_t len)
{
	posix_spawn_file_actions_t	 fa;
	char				*argv[3], *env[1] = { NULL };
	char				 out[128];
	ssize_t				 n;
	pid_t				 pid;
	int				 p[2], status;

	buf[0] = '\0';
	if (pipe2(p, O_CLOEXEC) == -1)
		return;
	argv[0] = (char *)(uintptr_t)path;
	argv[1] = (char *)(uintptr_t)"-V";
	argv[2] = NULL;
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null",
	    O_RDONLY, 0);
	posix_spawn_file_actions_adddup2(&fa, p[1], STDOUT_FILENO);
	posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null",
	    O_WRONLY, 0);
	if (posix_spawn(&pid, path, &fa, NULL, argv, env) == 0) {
		close(p[1]);
		p[1] = -1;
		if ((n = read(p[0], out, sizeof(out) - 1)) > 0) {
			out[n] = '\0';
			out[strcspn(out, "\n")] = '\0';
			if (strncmp(out, "arcana-agent ", 13) == 0)
				strlcpy(buf, out + 13, len);
		}
		while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
			;
	}
	posix_spawn_file_actions_destroy(&fa);
	close(p[0]);
	if (p[1] != -1)
		close(p[1]);
}

/*
 * The SHA-256 and the version of the arcana-agent the console would
 * send, for the page to tell which hosts run another build; kept until
 * the file changes.  The version of one a host built is what that host
 * said: it need not run on this machine.
 */
static char	agent_sha[65], agent_ver[64];

static bool
agent_refresh(void)
{
	static struct timespec	 mtime;
	static off_t		 size;
	static ino_t		 ino;
	struct stat		 sb;
	const char		*path;
	char			 vpath[MAXPATHLEN];
	uint8_t			*bin;
	size_t			 len;
	bool			 built;
	FILE			*fp;

	path = agent_path(&built);
	if (stat(path, &sb) == -1)
		return (false);
	if (agent_sha[0] != '\0' && sb.st_ino == ino && sb.st_size == size &&
	    sb.st_mtim.tv_sec == mtime.tv_sec && sb.st_mtim.tv_nsec ==
	    mtime.tv_nsec)
		return (true);
	if (agent_binary(&bin, &len, agent_sha) != NULL) {
		agent_sha[0] = '\0';
		return (false);
	}
	free(bin);
	agent_ver[0] = '\0';
	if (built) {
		snprintf(vpath, sizeof(vpath), "%s/agent/version", cfg.datadir);
		if ((fp = fopen(vpath, "r")) != NULL) {
			if (fgets(agent_ver, sizeof(agent_ver), fp) != NULL)
				agent_ver[strcspn(agent_ver, "\n")] = '\0';
			fclose(fp);
		}
	} else
		version_of(path, agent_ver, sizeof(agent_ver));
	ino = sb.st_ino;
	size = sb.st_size;
	mtime = sb.st_mtim;
	return (true);
}

const char *
agent_build(void)
{

	return (agent_refresh() ? agent_sha : NULL);
}

const char *
agent_version(void)
{

	return (agent_refresh() && agent_ver[0] != '\0' ? agent_ver : NULL);
}

/*
 * Keep the arcana-agent a host built, with the version it reported, in
 * datadir/agent.  Returns what went wrong, or NULL.
 */
static const char *
agent_keep(const void *bin, size_t len, const char *version)
{
	char	 dir[MAXPATHLEN], tmp[MAXPATHLEN], path[MAXPATHLEN];
	FILE	*fp;
	int	 fd;

	snprintf(dir, sizeof(dir), "%s/agent", cfg.datadir);
	snprintf(tmp, sizeof(tmp), "%s/arcana-agent.new", dir);
	snprintf(path, sizeof(path), "%s/arcana-agent", dir);
	if (mkdir(dir, 0755) == -1 && errno != EEXIST)
		return ("the console cannot make its agent directory");
	(void)unlink(tmp);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
	    0755)) == -1)
		return ("the console cannot write the program");
	if (write(fd, bin, len) != (ssize_t)len || fsync(fd) == -1) {
		close(fd);
		(void)unlink(tmp);
		return ("the console cannot write the program");
	}
	close(fd);
	if (rename(tmp, path) == -1) {
		(void)unlink(tmp);
		return ("the console cannot put the program in place");
	}
	snprintf(tmp, sizeof(tmp), "%s/version", dir);
	if ((fp = fopen(tmp, "w")) != NULL) {
		fprintf(fp, "%s\n", version != NULL ? version : "");
		fclose(fp);
	}
	return (NULL);
}

/* The host's own JSON, as the reply's data. */
static void
put_json(ucl_object_t *top, const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*e;

	if (json == NULL)
		return;
	e = NULL;
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	if (ucl_parser_add_string(p, json, 0))
		e = ucl_parser_get_object(p);
	ucl_parser_free(p);
	if (e != NULL)
		put(top, "data", e);
}

static int
call_run(struct kore_task *t)
{
	struct call		*c;
	struct arc_client	 cl;
	struct arc_hello_rsp	*hr;
	struct arc_list_req	 lq;
	struct arc_list_rsp	*lr;
	struct arc_action_req	 aq;
	struct arc_action_rsp	*ar;
	struct arc_address_rsp	*dr;
	struct arc_services_rsp	*sr;
	struct arc_service_action_req saq;
	struct arc_service_action_rsp *sar;
	struct arc_service_config_req scq;
	struct arc_service_config_rsp *scr;
	struct arc_network_req	 nq;
	struct arc_network_rsp	*nr;
	struct arc_route_lookup_req rlq;
	struct arc_route_lookup_rsp *rlr;
	struct arc_bird_config_req bcq;
	struct arc_bird_config_rsp *bcr;
	struct arc_stats_rsp	*str;
	struct arc_kernel_rsp	*kr;
	struct arc_transport_req tpq;
	struct arc_transport_rsp *tpr;
	struct arc_sysctl_req	 syq;
	struct arc_sysctl_rsp	*syr;
	struct arc_processes_req prq;
	struct arc_processes_rsp *prr;
	struct arc_log_req	 lgq;
	struct arc_log_rsp	*lgr;
	struct arc_history_req	 hsq;
	struct arc_history_rsp	*hsr;
	struct arc_events_req	 evq;
	struct arc_events_rsp	*evr;
	struct arc_fw_trace_req	 ftq;
	struct arc_fw_trace_rsp	*ftr;
	struct pooled		 kept;
	struct arc_storage_req	 sgq;
	struct arc_storage_rsp	*sgr;
	struct arc_fstab_req	 fsq;
	struct arc_fstab_rsp	*fsr;
	struct arc_ipfw_rules_req irq;
	struct arc_ipfw_rules_rsp *irr;
	struct arc_packages_req	 pq;
	struct arc_packages_rsp	*pr;
	struct arc_pkg_upgrade_req uq;
	struct arc_pkg_upgrade_rsp *ur;
	struct arc_job_submit_req jsq;
	struct arc_job_submit_rsp *jsr;
	struct arc_jobs_rsp	*jlr;
	struct arc_job_req	 jq;
	struct arc_job_rsp	*jr;
	struct arc_job_cancel_req jcq;
	struct arc_job_cancel_rsp *jcr;
	struct arc_job_confirm_req jfq;
	struct arc_job_confirm_rsp *jfr;
	struct arc_agent_update_req auq;
	struct arc_agent_update_rsp *aur;
	struct arc_agent_build_req abq;
	struct arc_agent_build_rsp *abr;
	struct arc_console_update_req cuq;
	struct arc_console_update_rsp *cur;
	uint8_t			*bin;
	size_t			 binlen;
	char			 sha[65];
	unsigned char		 md[EVP_MAX_MD_SIZE];
	unsigned int		 mdlen;
	const struct arc_step	*steps;
	ucl_object_t		*top, *srv, *a, *e;
	cbl_conn		*conn;
	cbl_tls			*tls;
	const char		*msg;
	char			 detail[512];
	uint64_t		 t1, us;
	size_t			 nsteps, i;
	bool			 local, ok, reused, again;
	int			 error;

	c = (struct call *)t;
	top = ucl_object_typed_new(UCL_OBJECT);
	srv = ucl_object_typed_new(UCL_OBJECT);
	put_str(srv, "id", c->sid);
	put_str(srv, "name", c->sname);
	put(top, "server", srv);
	put(top, "fetched_at", ucl_object_fromint(time(NULL)));

	conn = NULL;
	tls = NULL;
	steps = NULL;
	nsteps = 0;
	hr = NULL;
	lr = NULL;
	ar = NULL;
	dr = NULL;
	sr = NULL;
	sar = NULL;
	scr = NULL;
	nr = NULL;
	rlr = NULL;
	bcr = NULL;
	str = NULL;
	kr = NULL;
	tpr = NULL;
	syr = NULL;
	prr = NULL;
	lgr = NULL;
	hsr = NULL;
	evr = NULL;
	ftr = NULL;
	reused = again = false;
	sgr = NULL;
	fsr = NULL;
	irr = NULL;
	pr = NULL;
	ur = NULL;
	jsr = NULL;
	jlr = NULL;
	jr = NULL;
	jcr = NULL;
	aur = NULL;
	abr = NULL;
	cur = NULL;
	bin = NULL;
	msg = NULL;
	local = strncmp(c->uri, "unix:", 5) == 0;
	t1 = now_us();
connect:
	memset(&cl, 0, sizeof(cl));
	/* One kept from before, when there is one. */
	if (!c->fresh && !again && pool_take(c->uri, c->peer, &kept)) {
		conn = kept.conn;
		tls = kept.tls;
		free(kept.uri);
		free(kept.peer);
		cl.conn = conn;
		cl.family = kept.family;
		cl.version = kept.version;
		memcpy(cl.groups, kept.groups, sizeof(kept.groups));
		reused = true;
		snprintf(detail, sizeof(detail), "%s, %s, kept open", c->uri,
		    local ? "local socket" : strncmp(c->uri, "sctp:", 5) ==
		    0 ? "mutual DTLS 1.2, one association shared by the "
		    "requests to this host" : "mutual TLS 1.3");
		goto connected;
	}
	reused = false;
	snprintf(detail, sizeof(detail), "%s, %s", c->uri, local ?
	    "local socket" : strncmp(c->uri, "sctp:", 5) == 0 ?
	    "mutual DTLS 1.2" : "mutual TLS 1.3");
	if ((error = cbl_conn_new(ctx, c->uri, 0, &conn)) != 0) {
		msg = strerror(error);
		goto fail;
	}
	if (!local) {
		if (cfg.tls_ca == NULL || cfg.tls_cert == NULL ||
		    cfg.tls_key == NULL) {
			msg = "no tls { ca cert key } in web.conf";
			goto fail;
		}
		if (cbl_tls_new(&tls) != 0 ||
		    cbl_tls_set_cert(tls, cfg.tls_cert, cfg.tls_key) != 0 ||
		    cbl_tls_set_ca(tls, cfg.tls_ca, NULL) != 0 ||
		    (c->peer != NULL &&
		    cbl_tls_set_peer_name(tls, c->peer) != 0)) {
			msg = tls != NULL ? cbl_tls_errstr(tls) :
			    "cbl_tls_new failed";
			goto fail;
		}
		(void)cbl_conn_set_tls(conn, tls);
	}
	if ((error = cbl_conn_connect(conn)) != 0) {
		msg = cbl_conn_errstr(conn);
		goto fail;
	}
	if ((error = arc_client_init(&cl, conn)) != 0) {
		msg = "no arcana family there";
		goto fail;
	}
connected:

	switch (c->op) {
	case OP_HELLO:
		if ((error = arc_hello(&cl, &hr)) != 0)
			goto rpcfail;
		put(top, "host", host_object(hr->host));
		ok = true;
		break;
	case OP_LIST:
		memset(&lq, 0, sizeof(lq));
		lq.config_only = c->config_only;
		if ((error = arc_list(&cl, &lq, &lr)) != 0)
			goto rpcfail;
		ok = lr->ok;
		put_str(top, "error", lr->error);
		put(top, "host", host_object(lr->host));
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < lr->jails.n; i++)
			ucl_array_append(a, jail_object(&lr->jails.v[i]));
		put(top, "jails", a);
		put(top, "scopes", strs(lr->scopes.v, lr->scopes.n));
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < lr->conf_errors.n; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "scope", lr->conf_errors.v[i].scope);
			put_str(e, "message", lr->conf_errors.v[i].message);
			ucl_array_append(a, e);
		}
		put(top, "conf_errors", a);
		steps = lr->trace.v;
		nsteps = lr->trace.n;
		break;
	case OP_ACTION:
		memset(&aq, 0, sizeof(aq));
		aq.jail = c->jail;
		aq.has_action = true;
		aq.action = c->action;
		if ((error = arc_action(&cl, &aq, &ar)) != 0)
			goto rpcfail;
		ok = ar->ok;
		put_str(top, "error", ar->error);
		if (ar->result != NULL)
			put(top, "jail", jail_object(ar->result));
		steps = ar->trace.v;
		nsteps = ar->trace.n;
		break;
	case OP_ADDRESS:
		if ((error = arc_address(&cl, &c->addr, &dr)) != 0)
			goto rpcfail;
		ok = dr->ok;
		put_str(top, "error", dr->error);
		put_str(top, "diff", dr->diff);
		if (dr->result != NULL)
			put(top, "jail", jail_object(dr->result));
		steps = dr->trace.v;
		nsteps = dr->trace.n;
		break;
	case OP_SERVICES:
		if ((error = arc_services(&cl, &sr)) != 0)
			goto rpcfail;
		ok = sr->ok;
		put_str(top, "error", sr->error);
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < sr->services.n; i++)
			ucl_array_append(a, service_object(&sr->services.v[i]));
		put(top, "services", a);
		steps = sr->trace.v;
		nsteps = sr->trace.n;
		break;
	case OP_SERVICE_ACTION:
		memset(&saq, 0, sizeof(saq));
		saq.service = c->jail;
		saq.has_service_action = true;
		saq.service_action = c->action;
		if ((error = arc_service_action(&cl, &saq, &sar)) != 0)
			goto rpcfail;
		ok = sar->ok;
		put_str(top, "error", sar->error);
		if (sar->service_result != NULL)
			put(top, "service", service_object(sar->service_result));
		steps = sar->trace.v;
		nsteps = sar->trace.n;
		break;
	case OP_PACKAGES:
		memset(&pq, 0, sizeof(pq));
		pq.jail = c->jail[0] != '\0' ? c->jail : NULL;
		pq.refresh = c->refresh;
		pq.has_pkg_installed = c->installed;
		pq.pkg_installed = c->installed;
		pq.has_pkg_ip = c->pkg_ip != 0;
		pq.pkg_ip = c->pkg_ip;
		if ((error = arc_packages(&cl, &pq, &pr)) != 0)
			goto rpcfail;
		ok = pr->ok;
		put_str(top, "error", pr->error);
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < pr->packages.n; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "name", pr->packages.v[i].name);
			put_str(e, "installed", pr->packages.v[i].installed);
			put_str(e, "available", pr->packages.v[i].available);
			put_str(e, "origin", pr->packages.v[i].origin);
			put_str(e, "comment", pr->packages.v[i].comment);
			if (pr->packages.v[i].has_automatic)
				put(e, "automatic", ucl_object_frombool(
				    pr->packages.v[i].automatic));
			if (pr->packages.v[i].has_size)
				put(e, "size", ucl_object_fromint((int64_t)
				    pr->packages.v[i].size));
			ucl_array_append(a, e);
		}
		put(top, "packages", a);
		steps = pr->trace.v;
		nsteps = pr->trace.n;
		break;
	case OP_PKG_UPGRADE:
		memset(&uq, 0, sizeof(uq));
		uq.jail = c->jail[0] != '\0' ? c->jail : NULL;
		uq.dry_run = c->dry_run;
		uq.has_ignore_osversion = c->anyos;
		uq.ignore_osversion = c->anyos;
		uq.has_pkg_ip = c->pkg_ip != 0;
		uq.pkg_ip = c->pkg_ip;
		uq.names.v = (const char *const *)c->names;
		uq.names.n = c->nnames;
		if ((error = arc_pkg_upgrade(&cl, &uq, &ur)) != 0)
			goto rpcfail;
		ok = ur->ok;
		put_str(top, "error", ur->error);
		put(top, "upgraded", ur->has_upgraded ?
		    ucl_object_fromint(ur->upgraded) :
		    ucl_object_typed_new(UCL_NULL));
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < ur->packages.n; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "name", ur->packages.v[i].name);
			put_str(e, "installed", ur->packages.v[i].installed);
			put_str(e, "available", ur->packages.v[i].available);
			ucl_array_append(a, e);
		}
		put(top, "packages", a);
		steps = ur->trace.v;
		nsteps = ur->trace.n;
		break;
	case OP_JOB_SUBMIT:
		memset(&jsq, 0, sizeof(jsq));
		jsq.batch.v = c->specs;
		jsq.batch.n = c->nspecs;
		if ((error = arc_job_submit(&cl, &jsq, &jsr)) != 0)
			goto rpcfail;
		ok = jsr->ok;
		put_str(top, "error", jsr->error);
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < jsr->jobs.n; i++)
			ucl_array_append(a, job_object(c, &jsr->jobs.v[i], false,
			    0));
		put(top, "jobs", a);
		break;
	case OP_JOBS:
		if ((error = arc_jobs(&cl, &jlr)) != 0)
			goto rpcfail;
		ok = jlr->ok;
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < jlr->jobs.n; i++)
			ucl_array_append(a, job_object(c, &jlr->jobs.v[i], false,
			    0));
		put(top, "jobs", a);
		/* What the agent is at that is not a job. */
		if (jlr->activity != NULL) {
			put_str(top, "activity", jlr->activity);
			put(top, "since", ucl_object_fromint(jlr->since));
		}
		put(top, "stopping", ucl_object_frombool(jlr->stopping));
		break;
	case OP_JOB:
		memset(&jq, 0, sizeof(jq));
		jq.has_id = true;
		jq.id = c->jobid;
		if ((error = arc_job(&cl, &jq, &jr)) != 0)
			goto rpcfail;
		ok = jr->ok;
		put_str(top, "error", jr->error);
		/*
		 * A safe change waits to hear from the console again, and
		 * here the console is: the change stays.  Had it cut the
		 * host off, this would not have got through, and the host
		 * would undo it by itself.
		 */
		if (jr->job != NULL && jr->job->state ==
		    ARC_JOB_STATE_UNCONFIRMED) {
			memset(&jfq, 0, sizeof(jfq));
			jfq.has_id = true;
			jfq.id = c->jobid;
			if (arc_job_confirm(&cl, &jfq, &jfr) == 0)
				arc_job_confirm_rsp_free(jfr);
		}
		if (jr->job != NULL) {
			put(top, "job", job_object(c, jr->job, true,
			    now_us() - t1));
			/* The job's own trace is the reply's. */
			put(top, "ok", ucl_object_frombool(ok));
			c->status = 200;
			goto done;
		}
		break;
	case OP_JOB_CANCEL:
		memset(&jcq, 0, sizeof(jcq));
		jcq.has_id = true;
		jcq.id = c->jobid;
		if ((error = arc_job_cancel(&cl, &jcq, &jcr)) != 0)
			goto rpcfail;
		ok = jcr->ok;
		put_str(top, "error", jcr->error);
		if (jcr->job != NULL)
			put(top, "job", job_object(c, jcr->job, false, 0));
		break;
	case OP_STATS:
		if ((error = arc_stats(&cl, &str)) != 0)
			goto rpcfail;
		ok = str->ok;
		put_str(top, "error", str->error);
		e = ucl_object_typed_new(UCL_OBJECT);
		if (str->stats != NULL) {
			const struct arc_stats *st = str->stats;
			ucl_object_t *pl, *po;

			put(e, "cpu_pct", ucl_object_fromdouble(st->cpu_pct));
			put(e, "load1", ucl_object_fromdouble(st->load1));
			put(e, "load5", ucl_object_fromdouble(st->load5));
			put(e, "load15", ucl_object_fromdouble(st->load15));
			put(e, "mem_total", ucl_object_fromint((int64_t)
			    st->mem_total));
			put(e, "mem_used", ucl_object_fromint((int64_t)
			    st->mem_used));
			put(e, "mem_inactive", ucl_object_fromint((int64_t)
			    st->mem_inactive));
			put(e, "mem_free", ucl_object_fromint((int64_t)
			    st->mem_free));
			put(e, "swap_total", ucl_object_fromint((int64_t)
			    st->swap_total));
			put(e, "swap_used", ucl_object_fromint((int64_t)
			    st->swap_used));
			pl = ucl_object_typed_new(UCL_ARRAY);
			for (i = 0; i < st->pools.n; i++) {
				po = ucl_object_typed_new(UCL_OBJECT);
				put_str(po, "name", st->pools.v[i].name);
				put(po, "size", ucl_object_fromint((int64_t)
				    st->pools.v[i].size));
				put(po, "alloc", ucl_object_fromint((int64_t)
				    st->pools.v[i].alloc));
				put(po, "free", ucl_object_fromint((int64_t)
				    st->pools.v[i].free));
				put_str(po, "health", st->pools.v[i].health);
				ucl_array_append(pl, po);
			}
			put(e, "pools", pl);
		}
		put(top, "stats", e);
		steps = str->trace.v;
		nsteps = str->trace.n;
		break;
	case OP_NETWORK:
		memset(&nq, 0, sizeof(nq));
		nq.has_net_kind = true;
		nq.net_kind = c->action;
		nq.has_net_family = true;
		nq.net_family = c->family;
		/* The text searched for is kept where a jail's name is. */
		nq.net_filter = c->jail[0] != '\0' ? c->jail : NULL;
		nq.has_net_fib = c->fib != 0;
		nq.net_fib = c->fib;
		nq.has_offset = c->offset != 0;
		nq.offset = c->offset;
		nq.jail = c->scope[0] != '\0' ? c->scope : NULL;
		if ((error = arc_network(&cl, &nq, &nr)) != 0)
			goto rpcfail;
		ok = nr->ok;
		put_str(top, "error", nr->error);
		/* A table too large to send: how large, and whether cut. */
		if (nr->has_total) {
			put(top, "total", ucl_object_fromint((int64_t)nr->total));
			put(top, "truncated", ucl_object_frombool(nr->truncated));
		}
		/* The program's JSON becomes part of ours. */
		e = NULL;
		if (nr->json != NULL) {
			struct ucl_parser *p;

			p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
			    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
			if (ucl_parser_add_string(p, nr->json, 0))
				e = ucl_parser_get_object(p);
			ucl_parser_free(p);
		}
		put(top, "data", e != NULL ? e : ucl_object_typed_new(UCL_NULL));
		steps = nr->trace.v;
		nsteps = nr->trace.n;
		break;
	case OP_BIRD_CONFIG:
		/* The path rides where a jail's name does, the SHA-256 of
		 * what the text was made from where an address does. */
		memset(&bcq, 0, sizeof(bcq));
		bcq.conf_path = c->jail[0] != '\0' ? c->jail : NULL;
		bcq.conf_text = c->text;
		bcq.sha256 = c->address[0] != '\0' ? c->address : NULL;
		bcq.dry_run = c->dry_run;
		bcq.jail = c->scope[0] != '\0' ? c->scope : NULL;
		bcq.safe = c->refresh && c->text != NULL && !c->dry_run;
		bcq.confirm = c->config_only;
		if ((error = arc_bird_config(&cl, &bcq, &bcr)) != 0)
			goto rpcfail;
		ok = bcr->ok;
		if (bcr->has_confirm_by)
			put(top, "confirm_by", ucl_object_fromint(
			    bcr->confirm_by));
		put_str(top, "error", bcr->error);
		put_str(top, "path", bcr->conf_path);
		put_str(top, "text", bcr->conf_text);
		put_str(top, "sha256", bcr->sha256);
		if (bcr->files.n > 0)
			put(top, "files", strs(bcr->files.v, bcr->files.n));
		steps = bcr->trace.v;
		nsteps = bcr->trace.n;
		break;
	case OP_ROUTE_LOOKUP:
		memset(&rlq, 0, sizeof(rlq));
		rlq.lookup = c->address;
		rlq.has_net_fib = c->fib != 0;
		rlq.net_fib = c->fib;
		rlq.jail = c->scope[0] != '\0' ? c->scope : NULL;
		if ((error = arc_route_lookup(&cl, &rlq, &rlr)) != 0)
			goto rpcfail;
		ok = rlr->ok;
		put_str(top, "error", rlr->error);
		e = NULL;
		if (rlr->json != NULL) {
			struct ucl_parser *p;

			p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
			    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
			if (ucl_parser_add_string(p, rlr->json, 0))
				e = ucl_parser_get_object(p);
			ucl_parser_free(p);
		}
		if (e != NULL)
			put(top, "data", e);
		steps = rlr->trace.v;
		nsteps = rlr->trace.n;
		break;
	case OP_STORAGE:
		/* The dataset rides where a jail's name does. */
		memset(&sgq, 0, sizeof(sgq));
		sgq.has_storage_kind = true;
		sgq.storage_kind = c->action;
		sgq.net_filter = c->jail[0] != '\0' ? c->jail : NULL;
		if ((error = arc_storage(&cl, &sgq, &sgr)) != 0)
			goto rpcfail;
		ok = sgr->ok;
		put_str(top, "error", sgr->error);
		if (sgr->has_total) {
			put(top, "total", ucl_object_fromint(
			    (int64_t)sgr->total));
			put(top, "truncated", ucl_object_frombool(
			    sgr->truncated));
		}
		e = NULL;
		if (sgr->json != NULL) {
			struct ucl_parser *p;

			p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
			    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
			if (ucl_parser_add_string(p, sgr->json, 0))
				e = ucl_parser_get_object(p);
			ucl_parser_free(p);
		}
		if (e != NULL)
			put(top, "data", e);
		steps = sgr->trace.v;
		nsteps = sgr->trace.n;
		break;
	case OP_IPFW_RULES:
		/* As fstab: the checksum rides where an address does. */
		memset(&irq, 0, sizeof(irq));
		irq.conf_text = c->text;
		irq.sha256 = c->address[0] != '\0' ? c->address : NULL;
		irq.dry_run = c->dry_run;
		irq.jail = c->scope[0] != '\0' ? c->scope : NULL;
		if ((error = arc_ipfw_rules(&cl, &irq, &irr)) != 0)
			goto rpcfail;
		ok = irr->ok;
		put_str(top, "error", irr->error);
		put_str(top, "text", irr->conf_text);
		put_str(top, "sha256", irr->sha256);
		steps = irr->trace.v;
		nsteps = irr->trace.n;
		break;
	case OP_FSTAB:
		/* The checksum rides where an address does. */
		memset(&fsq, 0, sizeof(fsq));
		fsq.conf_text = c->text;
		fsq.sha256 = c->address[0] != '\0' ? c->address : NULL;
		fsq.dry_run = c->dry_run;
		if ((error = arc_fstab(&cl, &fsq, &fsr)) != 0)
			goto rpcfail;
		ok = fsr->ok;
		put_str(top, "error", fsr->error);
		put_str(top, "text", fsr->conf_text);
		put_str(top, "sha256", fsr->sha256);
		steps = fsr->trace.v;
		nsteps = fsr->trace.n;
		break;
	case OP_TRANSPORT:
		memset(&tpq, 0, sizeof(tpq));
		tpq.retry = c->retry;
		if ((error = arc_transport(&cl, &tpq, &tpr)) != 0)
			goto rpcfail;
		ok = tpr->ok;
		put_str(top, "error", tpr->error);
		e = NULL;
		if (tpr->json != NULL) {
			struct ucl_parser *p;

			p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
			    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
			if (ucl_parser_add_string(p, tpr->json, 0))
				e = ucl_parser_get_object(p);
			ucl_parser_free(p);
		}
		if (e != NULL)
			put(top, "data", e);
		/* How the console itself reaches it. */
		put_str(top, "uri", c->uri);
		steps = tpr->trace.v;
		nsteps = tpr->trace.n;
		break;
	case OP_PROCESSES:
		memset(&prq, 0, sizeof(prq));
		prq.jail = c->scope[0] != '\0' ? c->scope : NULL;
		prq.has_pid = c->fib != 0;
		prq.pid = c->fib;
		if ((error = arc_processes(&cl, &prq, &prr)) != 0)
			goto rpcfail;
		ok = prr->ok;
		put_str(top, "error", prr->error);
		put_json(top, prr->json);
		steps = prr->trace.v;
		nsteps = prr->trace.n;
		break;
	case OP_LOG:
		/* The text looked for rides where a jail's name does. */
		memset(&lgq, 0, sizeof(lgq));
		lgq.log_name = c->logname[0] != '\0' ? c->logname : NULL;
		lgq.net_filter = c->jail[0] != '\0' ? c->jail : NULL;
		lgq.has_position = c->has_pos;
		lgq.position = c->pos;
		lgq.has_lines = c->lines > 0;
		lgq.lines = c->lines;
		lgq.jail = c->scope[0] != '\0' ? c->scope : NULL;
		if ((error = arc_log(&cl, &lgq, &lgr)) != 0)
			goto rpcfail;
		ok = lgr->ok;
		put_str(top, "error", lgr->error);
		put_json(top, lgr->json);
		steps = lgr->trace.v;
		nsteps = lgr->trace.n;
		break;
	case OP_HISTORY:
		memset(&hsq, 0, sizeof(hsq));
		hsq.has_after = c->has_pos;
		hsq.after = c->pos;
		/* How to sample rides where the routes' fib and offset do. */
		hsq.has_sample_step = hsq.has_sample_keep = c->retry;
		hsq.sample_step = c->fib;
		hsq.sample_keep = c->offset;
		hsq.has_limit_cpu = hsq.has_limit_mem = hsq.has_limit_swap =
		    c->retry && c->names != NULL;
		if (c->names != NULL) {
			hsq.limit_cpu = (uint32_t)atoi(c->names[0]);
			hsq.limit_mem = (uint32_t)atoi(c->names[1]);
			hsq.limit_swap = (uint32_t)atoi(c->names[2]);
		}
		if ((error = arc_history(&cl, &hsq, &hsr)) != 0)
			goto rpcfail;
		ok = hsr->ok;
		put_str(top, "error", hsr->error);
		put_json(top, hsr->json);
		steps = hsr->trace.v;
		nsteps = hsr->trace.n;
		break;
	case OP_EVENTS:
		memset(&evq, 0, sizeof(evq));
		evq.has_after = c->has_pos;
		evq.after = c->pos;
		if ((error = arc_events(&cl, &evq, &evr)) != 0)
			goto rpcfail;
		ok = evr->ok;
		put_str(top, "error", evr->error);
		put_json(top, evr->json);
		steps = evr->trace.v;
		nsteps = evr->trace.n;
		break;
	case OP_FW_TRACE:
		/* How long rides in fib, how many in pos. */
		memset(&ftq, 0, sizeof(ftq));
		ftq.jail = c->scope[0] != '\0' ? c->scope : NULL;
		ftq.net_filter = c->address;
		ftq.has_seconds = c->fib != 0;
		ftq.seconds = c->fib;
		ftq.has_packets = c->has_pos;
		ftq.packets = (uint32_t)c->pos;
		if ((error = arc_fw_trace(&cl, &ftq, &ftr)) != 0)
			goto rpcfail;
		ok = ftr->ok;
		put_str(top, "error", ftr->error);
		put_json(top, ftr->json);
		steps = ftr->trace.v;
		nsteps = ftr->trace.n;
		break;
	case OP_SYSCTL:
		/* Where to begin rides where a jail's name does. */
		memset(&syq, 0, sizeof(syq));
		syq.net_filter = c->jail[0] != '\0' ? c->jail : NULL;
		if ((error = arc_sysctl(&cl, &syq, &syr)) != 0)
			goto rpcfail;
		ok = syr->ok;
		put_str(top, "error", syr->error);
		if (syr->has_total) {
			put(top, "total", ucl_object_fromint(
			    (int64_t)syr->total));
			put(top, "truncated", ucl_object_frombool(
			    syr->truncated));
		}
		e = NULL;
		if (syr->json != NULL) {
			struct ucl_parser *p;

			p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
			    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
			if (ucl_parser_add_string(p, syr->json, 0))
				e = ucl_parser_get_object(p);
			ucl_parser_free(p);
		}
		if (e != NULL)
			put(top, "data", e);
		steps = syr->trace.v;
		nsteps = syr->trace.n;
		break;
	case OP_KERNEL:
		if ((error = arc_kernel(&cl, &kr)) != 0)
			goto rpcfail;
		ok = kr->ok;
		put_str(top, "error", kr->error);
		e = NULL;
		if (kr->json != NULL) {
			struct ucl_parser *p;

			p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
			    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
			if (ucl_parser_add_string(p, kr->json, 0))
				e = ucl_parser_get_object(p);
			ucl_parser_free(p);
		}
		if (e != NULL)
			put(top, "data", e);
		steps = kr->trace.v;
		nsteps = kr->trace.n;
		break;
	case OP_CONSOLE_UPDATE:
		memset(&cuq, 0, sizeof(cuq));
		cuq.source = cfg.agent_source;
		cuq.ref = cfg.agent_ref;
		cuq.ssh_key = cfg.agent_ssh_key;
		cuq.host_keys = c->host_keys;
		if ((error = arc_console_update(&cl, &cuq, &cur)) != 0)
			goto rpcfail;
		ok = cur->ok;
		put_str(top, "error", cur->error);
		put_str(top, "host_keys", cur->host_keys);
		if (cur->fingerprints.n > 0)
			put(top, "fingerprints", strs(cur->fingerprints.v,
			    cur->fingerprints.n));
		put_str(top, "deploy_key", cur->deploy_key);
		put(top, "restarting", ucl_object_frombool(cur->restarting));
		steps = cur->trace.v;
		nsteps = cur->trace.n;
		break;
	case OP_AGENT_BUILD:
		memset(&abq, 0, sizeof(abq));
		abq.source = cfg.agent_source;
		abq.ref = cfg.agent_ref;
		abq.ssh_key = cfg.agent_ssh_key;
		abq.host_keys = c->host_keys;
		if ((error = arc_agent_build(&cl, &abq, &abr)) != 0)
			goto rpcfail;
		ok = abr->ok;
		put_str(top, "error", abr->error);
		/* An SSH server the host does not know: for the user to
		 * confirm, with the key the host shows that server. */
		put_str(top, "host_keys", abr->host_keys);
		if (abr->fingerprints.n > 0)
			put(top, "fingerprints", strs(abr->fingerprints.v,
			    abr->fingerprints.n));
		put_str(top, "deploy_key", abr->deploy_key);
		steps = abr->trace.v;
		nsteps = abr->trace.n;
		if (!ok)
			break;
		/* What arrived has to be what the host says it built. */
		if (abr->sha256 == NULL || abr->binary.len == 0 ||
		    EVP_Digest(abr->binary.p, abr->binary.len, md, &mdlen,
		    EVP_sha256(), NULL) != 1) {
			ok = false;
			put_str(top, "error", "the host sent no program");
			break;
		}
		for (i = 0; i < mdlen; i++)
			snprintf(sha + 2 * i, 3, "%02x", md[i]);
		if (strcmp(sha, abr->sha256) != 0)
			msg = "the program does not match its SHA-256";
		else
			msg = agent_keep(abr->binary.p, abr->binary.len,
			    abr->agent_version);
		if (msg != NULL) {
			ok = false;
			put_str(top, "error", msg);
			break;
		}
		put_str(top, "version", abr->agent_version);
		put_str(top, "sha256", sha);
		break;
	case OP_AGENT_UPDATE:
		if ((msg = agent_binary(&bin, &binlen, sha)) != NULL) {
			ok = false;
			put_str(top, "error", msg);
			break;
		}
		memset(&auq, 0, sizeof(auq));
		auq.binary.p = bin;
		auq.binary.len = binlen;
		auq.sha256 = sha;
		auq.restart = c->restart;
		if ((error = arc_agent_update(&cl, &auq, &aur)) != 0)
			goto rpcfail;
		ok = aur->ok;
		put_str(top, "error", aur->error);
		put_str(top, "version", aur->agent_version);
		put(top, "restarting", ucl_object_frombool(aur->restarting));
		steps = aur->trace.v;
		nsteps = aur->trace.n;
		break;
	default:
		memset(&scq, 0, sizeof(scq));
		scq.service = c->jail;
		scq.variables.v = c->vars;
		scq.variables.n = c->nvars;
		if ((error = arc_service_config(&cl, &scq, &scr)) != 0)
			goto rpcfail;
		ok = scr->ok;
		put_str(top, "error", scr->error);
		if (scr->service_result != NULL)
			put(top, "service", service_object(scr->service_result));
		e = ucl_object_typed_new(UCL_OBJECT);
		for (i = 0; i < scr->variables.n; i++)
			put_str(e, scr->variables.v[i].key,
			    scr->variables.v[i].value);
		put(top, "variables", e);
		put_str(top, "description", scr->description);
		put(top, "commands", strs(scr->commands.v, scr->commands.n));
		steps = scr->trace.v;
		nsteps = scr->trace.n;
		break;
	}
	us = now_us() - t1;
	put(top, "ok", ucl_object_frombool(ok));
	put(top, "trace", trace_object(c, steps, nsteps, detail, true, us));
	c->status = 200;
	c->moved = c->op == OP_HELLO && ok;
	goto done;

rpcfail:
	/*
	 * A connection kept from before may have been closed at the other
	 * end since it was looked at: what only asks is asked again, on a
	 * new one.  What changes something is not: it may have arrived.
	 */
	if (reused && c->reads && cl.err == NULL) {
		arc_client_fini(&cl);
		pool_drop(conn, tls);
		conn = NULL;
		tls = NULL;
		again = true;
		goto connect;
	}
	msg = cl.err != NULL && cbl_msg_err_str(cl.err) != NULL ?
	    cbl_msg_err_str(cl.err) : strerror(error);
	c->status = 502;
	e = ucl_object_typed_new(UCL_OBJECT);
	put_str(e, "code", "rejected");
	put_str(e, "message", msg);
	put(top, "error", e);
	put(top, "trace", trace_object(c, NULL, 0, msg, false,
	    now_us() - t1));
	goto done;
fail:
	c->status = 502;
	e = ucl_object_typed_new(UCL_OBJECT);
	put_str(e, "code", "unreachable");
	put_str(e, "message", msg != NULL ? msg : "cannot connect");
	put(top, "error", e);
	put(top, "trace", trace_object(c, NULL, 0, msg, false,
	    now_us() - t1));
done:
	c->json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (hr != NULL)
		arc_hello_rsp_free(hr);
	if (lr != NULL)
		arc_list_rsp_free(lr);
	if (ar != NULL)
		arc_action_rsp_free(ar);
	if (dr != NULL)
		arc_address_rsp_free(dr);
	if (sr != NULL)
		arc_services_rsp_free(sr);
	if (sar != NULL)
		arc_service_action_rsp_free(sar);
	if (scr != NULL)
		arc_service_config_rsp_free(scr);
	if (nr != NULL)
		arc_network_rsp_free(nr);
	if (rlr != NULL)
		arc_route_lookup_rsp_free(rlr);
	if (bcr != NULL)
		arc_bird_config_rsp_free(bcr);
	if (str != NULL)
		arc_stats_rsp_free(str);
	if (kr != NULL)
		arc_kernel_rsp_free(kr);
	if (tpr != NULL)
		arc_transport_rsp_free(tpr);
	if (syr != NULL)
		arc_sysctl_rsp_free(syr);
	if (prr != NULL)
		arc_processes_rsp_free(prr);
	if (lgr != NULL)
		arc_log_rsp_free(lgr);
	if (hsr != NULL)
		arc_history_rsp_free(hsr);
	if (evr != NULL)
		arc_events_rsp_free(evr);
	if (ftr != NULL)
		arc_fw_trace_rsp_free(ftr);
	if (sgr != NULL)
		arc_storage_rsp_free(sgr);
	if (fsr != NULL)
		arc_fstab_rsp_free(fsr);
	if (irr != NULL)
		arc_ipfw_rules_rsp_free(irr);
	if (pr != NULL)
		arc_packages_rsp_free(pr);
	if (ur != NULL)
		arc_pkg_upgrade_rsp_free(ur);
	if (jsr != NULL)
		arc_job_submit_rsp_free(jsr);
	if (jlr != NULL)
		arc_jobs_rsp_free(jlr);
	if (jr != NULL)
		arc_job_rsp_free(jr);
	if (jcr != NULL)
		arc_job_cancel_rsp_free(jcr);
	if (aur != NULL)
		arc_agent_update_rsp_free(aur);
	if (abr != NULL)
		arc_agent_build_rsp_free(abr);
	if (cur != NULL)
		arc_console_update_rsp_free(cur);
	free(bin);
	/*
	 * Kept for the next request when it answered: also when the agent
	 * refused what was asked, which says nothing against the
	 * connection.  Not after an update, which restarts the agent.
	 */
	if (cl.conn != NULL && !c->fresh && c->op != OP_AGENT_UPDATE &&
	    c->op != OP_CONSOLE_UPDATE && (c->status == 200 || cl.err !=
	    NULL) && cbl_conn_is_open(conn)) {
		arc_client_fini(&cl);
		pool_give(c->uri, c->peer, conn, tls, &cl);
		return (KORE_RESULT_OK);
	}
	if (cl.conn != NULL)
		arc_client_fini(&cl);
	if (conn != NULL)
		pool_drop(conn, tls);
	else
		cbl_tls_free(tls);
	return (KORE_RESULT_OK);
}

/*
 * Common start of the host routes: session, server id from the path.
 * Returns NULL with the reply sent when the request goes no further.
 */
static struct call *
call_new(struct http_request *req, enum op op)
{
	const struct server	*s;
	struct call		*c;
	uint64_t		 t0, t1;
	char			 sid[16];

	t0 = now_us();
	if (!guard(req, op == OP_ACTION || op == OP_ADDRESS ||
	    op == OP_SERVICE_ACTION || op == OP_PKG_UPGRADE ||
	    op == OP_JOB_SUBMIT || op == OP_JOB_CANCEL ||
	    op == OP_AGENT_UPDATE || op == OP_AGENT_BUILD ||
	    op == OP_CONSOLE_UPDATE ||
	    ((op == OP_SERVICE_CONFIG || op == OP_TRANSPORT || op ==
	    OP_IPFW_RULES || op == OP_FSTAB || op == OP_HISTORY) &&
	    req->method ==
	    HTTP_METHOD_POST)))
		return (NULL);
	t1 = now_us();
	if (!capture(req, 3, sid, sizeof(sid)) || (s = server_find(sid)) ==
	    NULL) {
		reply_error(req, 404, "not_found", "no such server");
		return (NULL);
	}
	c = kore_calloc(1, sizeof(*c));
	c->op = op;
	c->reads = req->method == HTTP_METHOD_GET;
	c->t0 = t0;
	c->auth_us = t1 - t0;
	strlcpy(c->sid, s->id, sizeof(c->sid));
	c->sname = kore_strdup(s->name);
	c->uri = kore_strdup(s->uri);
	c->peer = s->peer_name != NULL ? kore_strdup(s->peer_name) : NULL;
	snprintf(c->route, sizeof(c->route), "%s %s",
	    req->method == HTTP_METHOD_GET ? "GET" :
	    req->method == HTTP_METHOD_DELETE ? "DELETE" : "POST", req->path);
	return (c);
}

static int
call_start(struct http_request *req, struct call *c)
{

	req->hdlr_extra = c;
	kore_task_create(&c->task, call_run);
	kore_task_bind_request(&c->task, req);
	kore_task_run(&c->task);
	return (KORE_RESULT_RETRY);
}

/* Called again by Kore until the task is done, then replies. */
static int
call_finish(struct http_request *req)
{
	struct call	*c;

	c = req->hdlr_extra;
	if (kore_task_state(&c->task) != KORE_TASK_STATE_FINISHED) {
		http_request_sleep(req);
		return (KORE_RESULT_RETRY);
	}
	http_response_header(req, "content-type",
	    "application/json; charset=utf-8");
	http_response_header(req, "cache-control", "no-store");
	http_response_header(req, "x-content-type-options", "nosniff");
	if (c->json != NULL)
		http_response(req, c->status, c->json, strlen(c->json));
	else
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
	return (KORE_RESULT_OK);
}

/*
 * on_free of the host routes: what the call holds goes with the request,
 * whether it was answered or the browser went away first.  Kore asks
 * every time it tries to free the request, also while the task still
 * runs; it destroys the finished task and frees the call itself.
 */
void
api_call_free(struct http_request *req)
{
	struct call	*c;
	size_t		 i;

	if ((c = req->hdlr_extra) == NULL || !kore_task_finished(&c->task))
		return;
	free(c->json);
	c->json = NULL;
	kore_free(c->sname);
	kore_free(c->uri);
	kore_free(c->peer);
	c->sname = c->uri = c->peer = NULL;
	kore_free(c->host_keys);
	c->host_keys = NULL;
	kore_free(c->text);
	c->text = NULL;
	call_free_vars(c);
	for (i = 0; i < c->nnames; i++)
		kore_free(c->names[i]);
	kore_free(c->names);
	c->names = NULL;
	c->nnames = 0;
	for (i = 0; i < c->nspecs; i++)
		spec_free(&c->specs[i]);
	kore_free(c->specs);
	c->specs = NULL;
	c->nspecs = 0;
}

/* GET /api/servers/<id>/services */
int
api_services(struct http_request *req)
{
	struct call	*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_SERVICES)) == NULL)
		return (KORE_RESULT_OK);
	return (call_start(req, c));
}

/* POST /api/servers/<id>/services/<name>/action {"action": "restart"} */
int
api_service_action(struct http_request *req)
{
	ucl_object_t	*body;
	struct call	*c;
	const char	*a;
	size_t		 i;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_SERVICE_ACTION)) == NULL)
		return (KORE_RESULT_OK);
	body = read_json(req);
	a = body != NULL ? ucl_str(body, "action") : NULL;
	for (i = 0; a != NULL && i < nitems(service_action_names); i++)
		if (strcmp(a, service_action_names[i]) == 0)
			break;
	ucl_object_unref(body);
	if (a == NULL || i == nitems(service_action_names) ||
	    !capture(req, 5, c->jail, sizeof(c->jail))) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "action is one of "
		    "start, stop, restart, reload, enable, disable"));
	}
	c->action = (uint8_t)i;
	return (call_start(req, c));
}

/*
 * POST /api/servers/<id>/agent-build: have the host build arcana-agent
 * from agent_source, and keep it as the one the console sends.
 */
int
api_agent_build(struct http_request *req)
{
	ucl_object_t		*body;
	const ucl_object_t	*v;
	struct call		*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	/* The same repository, for the console itself, where it runs. */
	if ((c = call_new(req, strstr(req->path, "/console-update") != NULL ?
	    OP_CONSOLE_UPDATE : OP_AGENT_BUILD)) == NULL)
		return (KORE_RESULT_OK);
	if (cfg.agent_source == NULL) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 409, "unconfigured", "agent_source "
		    "in web.conf names no repository to build from"));
	}
	if (c->op == OP_CONSOLE_UPDATE && strncmp(c->uri, "unix:", 5) != 0) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 409, "remote", "the console is "
		    "updated through the agent of the host it runs on: a "
		    "server added by its local socket"));
	}
	/* {"host_keys": "..."}: the lines the user confirmed. */
	if ((body = read_json(req)) != NULL) {
		if ((v = ucl_object_lookup(body, "host_keys")) != NULL &&
		    ucl_object_type(v) == UCL_STRING)
			c->host_keys = kore_strdup(ucl_object_tostring(v));
		ucl_object_unref(body);
	}
	return (call_start(req, c));
}

/*
 * POST /api/servers/<id>/agent-update, {"restart": true}: send the host
 * the console's arcana-agent; with restart, have it restart its service.
 */
int
api_agent_update(struct http_request *req)
{
	ucl_object_t	*body;
	struct call	*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_AGENT_UPDATE)) == NULL)
		return (KORE_RESULT_OK);
	if ((body = read_json(req)) != NULL) {
		c->restart = ucl_object_toboolean(ucl_object_lookup(body,
		    "restart"));
		ucl_object_unref(body);
	}
	return (call_start(req, c));
}

/*
 * GET /api/servers/<id>/services/<name>/config: the variables.
 * POST, {"set": {"sshd_flags": "-4"}, "unset": ["sshd_x"]}: change them
 * first.
 */
int
api_service_config(struct http_request *req)
{
	ucl_object_t		*body;
	const ucl_object_t	*set, *unset, *v;
	ucl_object_iter_t	 it;
	struct call		*c;
	size_t			 n;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_SERVICE_CONFIG)) == NULL)
		return (KORE_RESULT_OK);
	if (!capture(req, 5, c->jail, sizeof(c->jail))) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "bad service name"));
	}
	if (req->method == HTTP_METHOD_POST && (body = read_json(req)) != NULL) {
		set = ucl_object_lookup(body, "set");
		unset = ucl_object_lookup(body, "unset");
		n = ucl_array_size(unset);
		it = NULL;
		while (set != NULL && ucl_object_type(set) == UCL_OBJECT &&
		    ucl_object_iterate(set, &it, true) != NULL)
			n++;
		if (n > 0 && n <= 64) {
			c->vars = kore_calloc(n, sizeof(*c->vars));
			it = NULL;
			while (set != NULL && ucl_object_type(set) == UCL_OBJECT &&
			    (v = ucl_object_iterate(set, &it, true)) != NULL) {
				c->vars[c->nvars].key =
				    kore_strdup(ucl_object_key(v));
				c->vars[c->nvars].value = kore_strdup(
				    ucl_object_tostring_forced(v));
				c->nvars++;
			}
			it = NULL;
			while ((v = ucl_object_iterate(unset, &it, true)) != NULL &&
			    c->nvars < n) {
				if (ucl_object_type(v) != UCL_STRING)
					continue;
				c->vars[c->nvars].key =
				    kore_strdup(ucl_object_tostring(v));
				c->vars[c->nvars].remove = true;
				c->nvars++;
			}
		}
		ucl_object_unref(body);
	}
	return (call_start(req, c));
}

/* GET /api/servers/<id>/hello */
int
api_hello(struct http_request *req)
{
	struct call	*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_HELLO)) == NULL)
		return (KORE_RESULT_OK);
	return (call_start(req, c));
}

/* GET /api/servers/<id>/jails[?config_only=1] */
int
api_jails(struct http_request *req)
{
	struct call	*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_LIST)) == NULL)
		return (KORE_RESULT_OK);
	c->config_only = req->query_string != NULL &&
	    strstr(req->query_string, "config_only=1") != NULL;
	return (call_start(req, c));
}

/* POST /api/servers/<id>/jails/<jail>/action {"action": "start"} */
int
api_action(struct http_request *req)
{
	ucl_object_t	*body;
	struct call	*c;
	const char	*a;
	size_t		 i;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_ACTION)) == NULL)
		return (KORE_RESULT_OK);
	body = read_json(req);
	a = body != NULL ? ucl_str(body, "action") : NULL;
	for (i = 0; a != NULL && i < nitems(action_names); i++)
		if (strcmp(a, action_names[i]) == 0)
			break;
	ucl_object_unref(body);
	if (a == NULL || i == nitems(action_names) ||
	    !capture(req, 5, c->jail, sizeof(c->jail))) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid",
		    "action is one of start, stop, restart, kill"));
	}
	c->action = (uint8_t)i;
	return (call_start(req, c));
}

/*
 * POST /api/servers/<id>/jails/<jail>/address
 * {"address": "10.0.0.5/24", "interface": "em0", "remove": false,
 *  "live": true, "persist": false, "dry_run": false}
 */
int
api_address(struct http_request *req)
{
	ucl_object_t	*body;
	struct call	*c;
	const char	*addr, *ifname;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_ADDRESS)) == NULL)
		return (KORE_RESULT_OK);
	body = read_json(req);
	addr = body != NULL ? ucl_str(body, "address") : NULL;
	ifname = body != NULL ? ucl_str(body, "interface") : NULL;
	if (addr == NULL || strlcpy(c->address, addr, sizeof(c->address)) >=
	    sizeof(c->address) || (ifname != NULL && *ifname != '\0' &&
	    strlcpy(c->ifname, ifname, sizeof(c->ifname)) >=
	    sizeof(c->ifname)) || !capture(req, 5, c->jail,
	    sizeof(c->jail))) {
		ucl_object_unref(body);
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "an address is "
		    "needed, an interface name is at most 15 characters"));
	}
	c->addr.jail = c->jail;
	c->addr.address = c->address;
	c->addr.interface = c->ifname[0] != '\0' ? c->ifname : NULL;
	c->addr.remove = ucl_flag(body, "remove");
	c->addr.live = ucl_flag(body, "live");
	c->addr.persist = ucl_flag(body, "persist");
	c->addr.dry_run = ucl_flag(body, "dry_run");
	ucl_object_unref(body);
	return (call_start(req, c));
}

/*
 * ?jail=name into the call: the vnet jail whose network is meant.
 * False when it is no name of a jail.
 */
static bool
pick_scope(struct http_request *req, struct call *c)
{
	const char	*p;

	if (!query_param(req, "jail", c->scope, sizeof(c->scope)))
		return (true);
	for (p = c->scope; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p) && strchr("_.-", *p) == NULL)
			return (false);
	return (true);
}

/* ?fib=N into the call; false when it is not a number of a table. */
static bool
pick_fib(struct http_request *req, struct call *c)
{
	const char	*errstr;
	char		 buf[16];

	if (!query_param(req, "fib", buf, sizeof(buf)) || buf[0] == '\0')
		return (true);
	c->fib = (uint32_t)strtonum(buf, 0, 65535, &errstr);
	return (errstr == NULL);
}

/*
 * GET /api/servers/<id>/net/<kind>[?family=inet|inet6&fib=N]
 * GET /api/servers/<id>/net/lookup?to=<address>[&fib=N]
 */
int
api_network(struct http_request *req)
{
	struct call	*c;
	const char	*q;
	char		 kind[16];
	size_t		 i;
	bool		 lookup;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	lookup = capture(req, 5, kind, sizeof(kind)) && strcmp(kind,
	    "lookup") == 0;
	if ((c = call_new(req, lookup ? OP_ROUTE_LOOKUP : OP_NETWORK)) == NULL)
		return (KORE_RESULT_OK);
	if (lookup) {
		/* An address is hex digits, dots and colons: no escaping. */
		(void)query_param(req, "to", c->address, sizeof(c->address));
		if (c->address[0] == '\0' || c->address[strspn(c->address,
		    "0123456789abcdefABCDEF.:")] != '\0' || !pick_fib(req, c) ||
		    !pick_scope(req, c)) {
			kore_free(c->sname);
			kore_free(c->uri);
			kore_free(c->peer);
			kore_free(c);
			return (reply_error(req, 400, "invalid", "to is an "
			    "IPv4 or IPv6 address, fib a number"));
		}
		return (call_start(req, c));
	}
	for (i = 0; i < nitems(net_kind_names); i++)
		if (strcmp(kind, net_kind_names[i]) == 0)
			break;
	if (i == nitems(net_kind_names) || !pick_fib(req, c) ||
	    !pick_scope(req, c)) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "kind is one of "
		    "routes, nexthops, nhgroups, connections, sockets, interfaces, "
		    "netgraph, wireguard, bird, bird-routes, bridges, geneve, "
		    "ipfw, neighbours, ipsec, lookup; fib a number"));
	}
	c->action = (uint8_t)i;
	/* Read on in a table too large for one reply. */
	{
		const char	*errstr;
		char		 off[16];

		if (query_param(req, "offset", off, sizeof(off)) && off[0] !=
		    '\0') {
			c->offset = (uint32_t)strtonum(off, 0, 100000000,
			    &errstr);
			if (errstr != NULL)
				c->offset = 0;
		}
	}
	c->family = ARC_NET_FAMILY_ALL;
	if (req->query_string != NULL) {
		if (strstr(req->query_string, "family=inet6") != NULL)
			c->family = ARC_NET_FAMILY_INET6;
		else if (strstr(req->query_string, "family=inet") != NULL)
			c->family = ARC_NET_FAMILY_INET;
	}
	/*
	 * ?filter=text searches the routes on the host.  It is taken as
	 * it is, so only what needs no escaping in a URL is taken.
	 */
	if (query_param(req, "filter", c->jail, sizeof(c->jail))) {
		/* BIRD's routes are asked for in words, with , between. */
		for (q = c->jail; *q != '\0'; q++)
			if (*q == ',' && c->action == ARC_NET_KIND_BIRD_ROUTES)
				c->jail[q - c->jail] = ' ';
			else if (!isalnum((unsigned char)*q) && strchr(".:/_-",
			    *q) == NULL)
				break;
		if (*q != '\0' || strlen(c->jail) > 128) {
			kore_free(c->sname);
			kore_free(c->uri);
			kore_free(c->peer);
			kore_free(c);
			return (reply_error(req, 400, "invalid", "the text to "
			    "search for is letters, digits and . : / _ -"));
		}
	}
	return (call_start(req, c));
}

/* A path of a configuration file: nothing a URL or a shell reads into. */
static bool
conf_path_ok(const char *s)
{

	if (s[0] != '/' || strlen(s) > 255 || strstr(s, "..") != NULL)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("._/-", *s) == NULL)
			return (false);
	return (true);
}

/*
 * GET /api/servers/<id>/bird/config[?path=<file>]: a file of BIRD's
 * configuration, its SHA-256, and the files there are.
 * POST {"path", "text", "sha256", "check"}: put text in its place,
 * sha256 being that of the text it was made from; with check, only
 * have it parsed.
 */
int
api_bird_config(struct http_request *req)
{
	struct call	*c;
	ucl_object_t	*body;
	const char	*s;
	bool		 bad;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_BIRD_CONFIG)) == NULL)
		return (KORE_RESULT_OK);
	bad = false;
	if (req->method == HTTP_METHOD_GET) {
		(void)query_param(req, "path", c->jail, sizeof(c->jail));
		bad = (c->jail[0] != '\0' && !conf_path_ok(c->jail)) ||
		    !pick_scope(req, c);
	} else if ((body = read_json(req)) == NULL)
		bad = true;
	else {
		if ((s = ucl_str(body, "path")) != NULL && s[0] != '\0') {
			bad = !conf_path_ok(s);
			strlcpy(c->jail, s, sizeof(c->jail));
		}
		if ((s = ucl_str(body, "sha256")) != NULL)
			strlcpy(c->address, s, sizeof(c->address));
		/* Safe rides where a refresh does, confirm where config-only. */
		c->refresh = ucl_flag(body, "safe");
		c->config_only = ucl_flag(body, "confirm");
		if ((s = ucl_str(body, "text")) != NULL)
			c->text = kore_strdup(s);
		else if (!c->config_only)
			bad = true;
		c->dry_run = ucl_flag(body, "check");
		if ((s = ucl_str(body, "jail")) != NULL) {
			strlcpy(c->scope, s, sizeof(c->scope));
			for (; *s != '\0'; s++)
				if (!isalnum((unsigned char)*s) && strchr("_.-",
				    *s) == NULL)
					bad = true;
		}
		ucl_object_unref(body);
	}
	if (bad) {
		kore_free(c->text);
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "path is a whole path "
		    "of letters, digits and . _ / -; a change needs text and "
		    "the sha256 of what it was made from"));
	}
	return (call_start(req, c));
}

/* GET /api/servers/<id>/stats */
/* GET /api/servers/<id>/storage/<kind>[?filter=dataset]. */
int
api_storage(struct http_request *req)
{
	static const char *const kinds[] = { "disks", "pools", "datasets",
	    "snapshots", "mounts", "importable", "health" };
	struct call	*c;
	const char	*kind, *q;
	size_t		 i;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_STORAGE)) == NULL)
		return (KORE_RESULT_OK);
	kind = strrchr(req->path, '/') + 1;
	for (i = 0; i < nitems(kinds); i++)
		if (strcmp(kind, kinds[i]) == 0)
			break;
	(void)query_param(req, "filter", c->jail, sizeof(c->jail));
	for (q = c->jail; *q != '\0'; q++)
		if (!isalnum((unsigned char)*q) && strchr("_.:/-", *q) == NULL)
			break;
	if (i == nitems(kinds) || *q != '\0') {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "kind is one of "
		    "disks, pools, datasets, snapshots, mounts; a dataset is "
		    "letters, digits and _ . : / -"));
	}
	c->action = (uint8_t)i;
	return (call_start(req, c));
}

/*
 * GET /api/servers/<id>/ipfw/rules[?jail=]: the kept rules of the
 * firewall and the SHA-256 of their text.  POST {"text", "sha256",
 * "check"}: put the text in their place, once ipfw has nothing against
 * it.
 */
int
api_ipfw_rules(struct http_request *req)
{
	struct call	*c;
	ucl_object_t	*body;
	const char	*s;
	bool		 bad;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_IPFW_RULES)) == NULL)
		return (KORE_RESULT_OK);
	bad = !pick_scope(req, c);
	if (!bad && req->method != HTTP_METHOD_GET) {
		if ((body = read_json(req)) == NULL)
			bad = true;
		else {
			if ((s = ucl_str(body, "sha256")) != NULL)
				strlcpy(c->address, s, sizeof(c->address));
			if ((s = ucl_str(body, "text")) != NULL)
				c->text = kore_strdup(s);
			else
				bad = true;
			c->dry_run = ucl_flag(body, "check");
			ucl_object_unref(body);
		}
	}
	if (bad) {
		kore_free(c->text);
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "a change needs text "
		    "and the sha256 of what it was made from; jail is a "
		    "jail's name"));
	}
	return (call_start(req, c));
}

/*
 * GET /api/servers/<id>/fstab: its text and the SHA-256 of that.
 * POST {"text", "sha256", "check"}: put the text in its place.
 */
int
api_fstab(struct http_request *req)
{
	struct call	*c;
	ucl_object_t	*body;
	const char	*s;
	bool		 bad;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_FSTAB)) == NULL)
		return (KORE_RESULT_OK);
	bad = false;
	if (req->method != HTTP_METHOD_GET) {
		if ((body = read_json(req)) == NULL)
			bad = true;
		else {
			if ((s = ucl_str(body, "sha256")) != NULL)
				strlcpy(c->address, s, sizeof(c->address));
			if ((s = ucl_str(body, "text")) != NULL)
				c->text = kore_strdup(s);
			else
				bad = true;
			c->dry_run = ucl_flag(body, "check");
			ucl_object_unref(body);
		}
	}
	if (bad) {
		kore_free(c->text);
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "a change needs text "
		    "and the sha256 of what it was made from"));
	}
	return (call_start(req, c));
}

/*
 * GET /api/servers/<id>/transport: the agent's listeners and the
 * connections open to it.  POST {"retry": true}: it starts the SCTP
 * listeners that are not up.
 */
int
api_transport(struct http_request *req)
{
	struct call	*c;
	ucl_object_t	*body;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_TRANSPORT)) == NULL)
		return (KORE_RESULT_OK);
	if (req->method != HTTP_METHOD_GET && (body = read_json(req)) !=
	    NULL) {
		c->retry = ucl_flag(body, "retry");
		ucl_object_unref(body);
	}
	return (call_start(req, c));
}

/*
 * POST /api/servers/<id>/transport/switch {"transport": "sctp" | "tcp"}:
 * reach the agent the other way, at the same address and port.  The
 * agent is asked there first, on a connection of its own, and the
 * server is changed only when it answers: there is no falling back
 * from one to the other by itself.
 */
int
api_transport_switch(struct http_request *req)
{
	struct call	*c;
	ucl_object_t	*body;
	const char	*to, *rest;
	char		*uri;
	size_t		 len;

	if ((c = req->hdlr_extra) != NULL) {
		if (kore_task_state(&c->task) == KORE_TASK_STATE_FINISHED &&
		    c->moved) {
			c->moved = false;
			if (servers_move(c->sid, c->uri) == -1) {
				c->status = 500;
				free(c->json);
				c->json = strdup("{\"error\":{\"code\":"
				    "\"store\",\"message\":\"it answers "
				    "there, but the change could not be "
				    "saved\"}}");
			}
		}
		return (call_finish(req));
	}
	if ((c = call_new(req, OP_HELLO)) == NULL)
		return (KORE_RESULT_OK);
	to = NULL;
	if ((body = read_json(req)) != NULL)
		to = ucl_str(body, "transport");
	rest = strncmp(c->uri, "tcp://", 6) == 0 ? c->uri + 6 : strncmp(
	    c->uri, "sctp://", 7) == 0 ? c->uri + 7 : NULL;
	if (to == NULL || rest == NULL || (strcmp(to, "sctp") != 0 &&
	    strcmp(to, "tcp") != 0)) {
		if (body != NULL)
			ucl_object_unref(body);
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "transport is sctp "
		    "or tcp, for a server reached over one of them"));
	}
	len = strlen(rest) + 8;
	uri = kore_malloc(len);
	snprintf(uri, len, "%s://%s", to, rest);
	ucl_object_unref(body);
	kore_free(c->uri);
	c->uri = uri;
	c->fresh = true;
	c->reads = false;
	return (call_start(req, c));
}

/* A number of the query, when it is there and is one. */
static bool
query_u64(struct http_request *req, const char *name, uint64_t max,
    uint64_t *v)
{
	const char	*errstr;
	char		 buf[24];

	if (!query_param(req, name, buf, sizeof(buf)) || buf[0] == '\0')
		return (false);
	*v = (uint64_t)strtonum(buf, 0, (long long)max, &errstr);
	return (errstr == NULL);
}

/* GET /api/servers/<id>/processes[?jail=name]: what runs there. */
int
api_processes(struct http_request *req)
{
	struct call	*c;
	uint64_t	 v;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_PROCESSES)) == NULL)
		return (KORE_RESULT_OK);
	(void)query_param(req, "jail", c->scope, sizeof(c->scope));
	if (query_u64(req, "pid", 99999, &v))
		c->fib = (uint32_t)v;
	return (call_start(req, c));
}

/*
 * GET /api/servers/<id>/log[?name=file][&filter=text][&position=n]
 * [&lines=n]: the end of a log, or what came after position.
 */
int
api_log(struct http_request *req)
{
	struct call	*c;
	uint64_t	 v;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_LOG)) == NULL)
		return (KORE_RESULT_OK);
	(void)query_param(req, "name", c->logname, sizeof(c->logname));
	(void)query_param(req, "jail", c->scope, sizeof(c->scope));
	/* The text may be any: it comes escaped, as a URL has it. */
	if (query_param(req, "filter", c->jail, sizeof(c->jail)) &&
	    (!http_argument_urldecode(c->jail, 1) || strlen(c->jail) > 128)) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "the text looked "
		    "for is at most 128 bytes, escaped as a URL has it"));
	}
	c->has_pos = query_u64(req, "position", INT64_MAX, &c->pos);
	if (query_u64(req, "lines", 5000, &v))
		c->lines = (uint32_t)v;
	return (call_start(req, c));
}

/*
 * GET /api/servers/<id>/history[?after=time]: how busy it has been.
 * POST {"step": seconds, "keep": samples}: how its agent samples it
 * from now on; the reply is as the GET's.
 */
int
api_history(struct http_request *req)
{
	struct call	*c;
	ucl_object_t	*body;
	int64_t		 step, keep;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_HISTORY)) == NULL)
		return (KORE_RESULT_OK);
	c->has_pos = query_u64(req, "after", INT64_MAX, &c->pos);
	if (req->method == HTTP_METHOD_GET)
		return (call_start(req, c));
	body = read_json(req);
	step = body != NULL ? ucl_object_toint(ucl_object_lookup(body,
	    "step")) : 0;
	keep = body != NULL && ucl_object_lookup(body, "keep") != NULL ?
	    ucl_object_toint(ucl_object_lookup(body, "keep")) : -1;
	/* The limits, all three or none, as percentages. */
	if (body != NULL && ucl_object_lookup(body, "cpu") != NULL) {
		int64_t	l[3];
		size_t	k;

		l[0] = ucl_object_toint(ucl_object_lookup(body, "cpu"));
		l[1] = ucl_object_toint(ucl_object_lookup(body, "mem"));
		l[2] = ucl_object_toint(ucl_object_lookup(body, "swap"));
		for (k = 0; k < 3; k++)
			if (l[k] < 0 || l[k] > 100)
				step = 0;
		c->names = kore_calloc(3, sizeof(*c->names));
		c->nnames = 3;
		for (k = 0; k < 3; k++) {
			c->names[k] = kore_malloc(8);
			snprintf(c->names[k], 8, "%lld", (long long)l[k]);
		}
	}
	if (body != NULL)
		ucl_object_unref(body);
	if (step < 1 || step > 3600 || keep < 0 || keep > 5000) {
		for (keep = 0; keep < (int64_t)c->nnames; keep++)
			kore_free(c->names[keep]);
		kore_free(c->names);
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "step is 1 to 3600 "
		    "seconds, keep 0 to 5000 samples"));
	}
	c->retry = true;
	c->fib = (uint32_t)step;
	c->offset = (uint32_t)keep;
	return (call_start(req, c));
}

/* GET /api/servers/<id>/events[?after=number]: what happened there. */
int
api_events(struct http_request *req)
{
	struct call	*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_EVENTS)) == NULL)
		return (KORE_RESULT_OK);
	c->has_pos = query_u64(req, "after", INT64_MAX, &c->pos);
	return (call_start(req, c));
}

/*
 * GET /api/servers/<id>/ipfw/trace?address=a[&seconds=s][&packets=n]
 * [&jail=j]: packets of an address followed through the firewall by
 * the kernel, for a few seconds.
 */
int
api_fw_trace(struct http_request *req)
{
	struct call	*c;
	uint64_t	 v;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_FW_TRACE)) == NULL)
		return (KORE_RESULT_OK);
	/* An address is hex digits, dots and colons: no escaping. */
	(void)query_param(req, "address", c->address, sizeof(c->address));
	if (c->address[0] == '\0' || c->address[strspn(c->address,
	    "0123456789abcdefABCDEF.:")] != '\0' || !pick_scope(req, c)) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "address is an IPv4 "
		    "or IPv6 address"));
	}
	if (query_u64(req, "seconds", 60, &v))
		c->fib = (uint32_t)v;
	c->has_pos = query_u64(req, "packets", 1000, &c->pos);
	return (call_start(req, c));
}

/* GET /api/servers/<id>/sysctl[?filter=name]: the kernel's state. */
int
api_sysctl(struct http_request *req)
{
	struct call	*c;
	const char	*q;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_SYSCTL)) == NULL)
		return (KORE_RESULT_OK);
	(void)query_param(req, "filter", c->jail, sizeof(c->jail));
	for (q = c->jail; *q != '\0'; q++)
		if (!isalnum((unsigned char)*q) && strchr("._-%", *q) == NULL)
			break;
	if (*q != '\0') {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "a sysctl is named "
		    "with letters, digits and . _ - %%"));
	}
	return (call_start(req, c));
}

/* GET /api/servers/<id>/kernel: its modules and its memory. */
int
api_kernel(struct http_request *req)
{
	struct call	*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_KERNEL)) == NULL)
		return (KORE_RESULT_OK);
	return (call_start(req, c));
}

int
api_stats(struct http_request *req)
{
	struct call	*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_STATS)) == NULL)
		return (KORE_RESULT_OK);
	return (call_start(req, c));
}

/* A query string parameter's value, raw (no %-decoding needed here). */
static bool
query_param(struct http_request *req, const char *name, char *buf, size_t len)
{
	const char	*q, *e;
	size_t		 nl;

	buf[0] = '\0';
	nl = strlen(name);
	for (q = req->query_string; q != NULL && *q != '\0'; q = e != NULL ?
	    e + 1 : NULL) {
		e = strchr(q, '&');
		if (strncmp(q, name, nl) == 0 && q[nl] == '=') {
			snprintf(buf, len, "%.*s", (int)(e != NULL ?
			    (size_t)(e - q) - nl - 1 : strlen(q + nl + 1)),
			    q + nl + 1);
			return (true);
		}
	}
	return (false);
}

/* The jail named by ?jail=<name> or by the body, into the call. */
static bool
pick_jail(struct call *c, const char *name)
{
	const char	*p;

	if (name == NULL || *name == '\0')
		return (true);
	for (p = name; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p) && strchr("_.-", *p) == NULL)
			return (false);
	return (strlcpy(c->jail, name, sizeof(c->jail)) < sizeof(c->jail));
}

/* GET /api/servers/<id>/packages[?jail=<name>&refresh=1] */
int
api_packages(struct http_request *req)
{
	struct call	*c;
	char		 jail[256], v[8];

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_PACKAGES)) == NULL)
		return (KORE_RESULT_OK);
	query_param(req, "jail", jail, sizeof(jail));
	c->refresh = query_param(req, "refresh", v, sizeof(v)) &&
	    strcmp(v, "1") == 0;
	c->installed = query_param(req, "installed", v, sizeof(v)) &&
	    strcmp(v, "1") == 0;
	c->pkg_ip = query_param(req, "ip", v, sizeof(v)) ? (uint8_t)(strcmp(v,
	    "4") == 0 ? 4 : strcmp(v, "6") == 0 ? 6 : 0) : 0;
	if (!pick_jail(c, jail)) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "bad jail name"));
	}
	return (call_start(req, c));
}

/*
 * POST /api/servers/<id>/packages/upgrade
 * {"jail": "web", "packages": ["pimd"], "dry_run": false}
 */
int
api_pkg_upgrade(struct http_request *req)
{
	ucl_object_t		*body;
	const ucl_object_t	*a, *v;
	ucl_object_iter_t	 it;
	struct call		*c;
	size_t			 n;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_PKG_UPGRADE)) == NULL)
		return (KORE_RESULT_OK);
	body = read_json(req);
	if (body == NULL || !pick_jail(c, ucl_str(body, "jail"))) {
		ucl_object_unref(body);
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "a JSON object with "
		    "an optional jail and packages"));
	}
	c->dry_run = ucl_flag(body, "dry_run");
	c->anyos = ucl_flag(body, "ignore_osversion");
	c->pkg_ip = (uint8_t)(ucl_object_toint(ucl_object_lookup(body,
	    "pkg_ip")) == 4 ? 4 : ucl_object_toint(ucl_object_lookup(body,
	    "pkg_ip")) == 6 ? 6 : 0);
	a = ucl_object_lookup(body, "packages");
	if ((n = ucl_array_size(a)) > 0) {
		c->names = kore_calloc(n, sizeof(*c->names));
		it = NULL;
		while ((v = ucl_object_iterate(a, &it, true)) != NULL &&
		    c->nnames < n)
			if (ucl_object_type(v) == UCL_STRING)
				c->names[c->nnames++] =
				    kore_strdup(ucl_object_tostring(v));
	}
	ucl_object_unref(body);
	return (call_start(req, c));
}

static const char *job_kind_names[] = {
	[ARC_JOB_KIND_JAIL_ACTION] = "jail-action",
	[ARC_JOB_KIND_ADDRESS] = "address",
	[ARC_JOB_KIND_SERVICE_ACTION] = "service-action",
	[ARC_JOB_KIND_SERVICE_CONFIG] = "service-config",
	[ARC_JOB_KIND_PKG_UPGRADE] = "pkg-upgrade",
	[ARC_JOB_KIND_IF_ADDRESS] = "if-address",
	[ARC_JOB_KIND_IF_STATE] = "if-state",
	[ARC_JOB_KIND_ROUTE] = "route",
	[ARC_JOB_KIND_IF_SET] = "if-set",
	[ARC_JOB_KIND_IF_CREATE] = "if-create",
	[ARC_JOB_KIND_IF_DESTROY] = "if-destroy",
	[ARC_JOB_KIND_NETGRAPH] = "netgraph",
	[ARC_JOB_KIND_WIREGUARD] = "wireguard",
	[ARC_JOB_KIND_BIRD] = "bird",
	[ARC_JOB_KIND_IF_VNET] = "if-vnet",
	[ARC_JOB_KIND_KMOD] = "kmod",
	[ARC_JOB_KIND_ZFS] = "zfs",
	[ARC_JOB_KIND_ZPOOL] = "zpool",
	[ARC_JOB_KIND_MOUNT] = "mount",
	[ARC_JOB_KIND_GPART] = "gpart",
	[ARC_JOB_KIND_CAM] = "cam",
	[ARC_JOB_KIND_SYSCTL] = "sysctl",
	[ARC_JOB_KIND_IPFW] = "ipfw",
	[ARC_JOB_KIND_BRIDGE] = "bridge",
	[ARC_JOB_KIND_GENEVE] = "geneve",
	[ARC_JOB_KIND_PROCESS] = "process",
	[ARC_JOB_KIND_PKG_CLEAN] = "pkg-clean",
	[ARC_JOB_KIND_IPSEC] = "ipsec",
	[ARC_JOB_KIND_PKG_INSTALL] = "pkg-install",
};

static const char *job_state_names[] = {
	[ARC_JOB_STATE_QUEUED] = "queued",
	[ARC_JOB_STATE_RUNNING] = "running",
	[ARC_JOB_STATE_DONE] = "done",
	[ARC_JOB_STATE_CANCELLED] = "cancelled",
	[ARC_JOB_STATE_UNCONFIRMED] = "unconfirmed",
};

/* A job; with its trace, under the console's own steps. */
static ucl_object_t *
job_object(struct call *c, const struct arc_job *j, bool trace, uint64_t us)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "id", ucl_object_fromint((int64_t)j->id));
	put_str(o, "kind", j->has_kind && j->kind < nitems(job_kind_names) ?
	    job_kind_names[j->kind] : NULL);
	put_str(o, "title", j->title);
	put_str(o, "state", j->has_state && j->state <
	    nitems(job_state_names) ? job_state_names[j->state] : "unknown");
	put(o, "ok", j->has_ok ? ucl_object_frombool(j->ok) :
	    ucl_object_typed_new(UCL_NULL));
	put_str(o, "error", j->error);
	put_str(o, "peer", j->peer);
	put(o, "created", ucl_object_fromint(j->created));
	put(o, "started", j->has_started ? ucl_object_fromint(j->started) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "finished", j->has_finished ? ucl_object_fromint(j->finished) :
	    ucl_object_typed_new(UCL_NULL));
	if (trace)
		put(o, "trace", trace_object(c, j->trace.v, j->trace.n, c->uri,
		    true, us));
	return (o);
}

static void
spec_free(struct arc_job_spec *sp)
{
	size_t	i;

	kore_free((char *)(uintptr_t)sp->jail);
	kore_free((char *)(uintptr_t)sp->address);
	kore_free((char *)(uintptr_t)sp->interface);
	kore_free((char *)(uintptr_t)sp->service);
	kore_free((char *)(uintptr_t)sp->destination);
	kore_free((char *)(uintptr_t)sp->gateway);
	kore_free((char *)(uintptr_t)sp->tunnel_local);
	kore_free((char *)(uintptr_t)sp->tunnel_remote);
	kore_free((char *)(uintptr_t)sp->parent);
	kore_free((char *)(uintptr_t)sp->verb);
	kore_free((char *)(uintptr_t)sp->source);
	kore_free((char *)(uintptr_t)sp->peer);
	kore_free((char *)(uintptr_t)sp->endpoint);
	kore_free((char *)(uintptr_t)sp->allowed_ips);
	kore_free((char *)(uintptr_t)sp->description);
	kore_free((char *)(uintptr_t)sp->conn);
	kore_free((char *)(uintptr_t)sp->ipsec_mode);
	kore_free((char *)(uintptr_t)sp->local_ts);
	kore_free((char *)(uintptr_t)sp->remote_ts);
	kore_free((char *)(uintptr_t)sp->pubkey);
	kore_free((char *)(uintptr_t)sp->start_action);
	kore_free((char *)(uintptr_t)sp->local_id);
	kore_free((char *)(uintptr_t)sp->remote_id);
	for (i = 0; i < sp->variables.n; i++) {
		kore_free((char *)(uintptr_t)sp->variables.v[i].key);
		kore_free((char *)(uintptr_t)sp->variables.v[i].value);
	}
	kore_free((void *)(uintptr_t)sp->variables.v);
	for (i = 0; i < sp->names.n; i++)
		kore_free((char *)(uintptr_t)sp->names.v[i]);
	kore_free((void *)(uintptr_t)sp->names.v);
	memset(sp, 0, sizeof(*sp));
}

static char *
jdup(const ucl_object_t *o, const char *key)
{
	const char	*s;

	return ((s = ucl_str(o, key)) != NULL && *s != '\0' ? kore_strdup(s) :
	    NULL);
}

/*
 * {"kind": "jail-action", "jail": "web", "action": "restart"} and its
 * siblings into a spec; NULL, or what is wrong.  The daemon checks the
 * names again.
 */
static const char *
spec_from_json(const ucl_object_t *o, struct arc_job_spec *sp)
{
	const ucl_object_t	*set, *unset, *names, *v;
	ucl_object_iter_t	 it;
	struct arc_variable	*vars;
	const char		**nv, *kind, *a;
	size_t			 i, n;

	memset(sp, 0, sizeof(*sp));
	if (ucl_object_type(o) != UCL_OBJECT || (kind = ucl_str(o, "kind")) ==
	    NULL)
		return ("every job is an object with a kind");
	for (i = 0; i < nitems(job_kind_names); i++)
		if (strcmp(kind, job_kind_names[i]) == 0)
			break;
	if (i == nitems(job_kind_names))
		return ("unknown kind of job");
	sp->has_kind = true;
	sp->kind = (uint8_t)i;
	sp->jail = jdup(o, "jail");
	sp->address = jdup(o, "address");
	sp->interface = jdup(o, "interface");
	sp->service = jdup(o, "service");
	sp->destination = jdup(o, "destination");
	sp->gateway = jdup(o, "gateway");
	sp->tunnel_local = jdup(o, "tunnel_local");
	sp->tunnel_remote = jdup(o, "tunnel_remote");
	sp->parent = jdup(o, "parent");
	sp->verb = jdup(o, "verb");
	sp->source = jdup(o, "source");
	sp->peer = jdup(o, "peer");
	sp->endpoint = jdup(o, "endpoint");
	/* IPsec's connection, for an ipsec job. */
	sp->conn = jdup(o, "conn");
	sp->ipsec_mode = jdup(o, "ipsec_mode");
	sp->local_ts = jdup(o, "local_ts");
	sp->remote_ts = jdup(o, "remote_ts");
	sp->pubkey = jdup(o, "pubkey");
	sp->start_action = jdup(o, "start_action");
	sp->local_id = jdup(o, "local_id");
	sp->remote_id = jdup(o, "remote_id");
	if ((v = ucl_object_lookup(o, "reqid")) != NULL && ucl_object_toint(v) >
	    0 && ucl_object_toint(v) <= 16383) {
		sp->has_reqid = true;
		sp->reqid = (uint32_t)ucl_object_toint(v);
	}
	/* Empty allowed-ips says a peer may send from nowhere: it is kept. */
	if ((kind = ucl_str(o, "allowed_ips")) != NULL)
		sp->allowed_ips = kore_strdup(kind);
	if ((v = ucl_object_lookup(o, "keepalive")) != NULL &&
	    ucl_object_toint(v) >= 0 && ucl_object_toint(v) <= 65535) {
		sp->has_keepalive = true;
		sp->keepalive = (uint32_t)ucl_object_toint(v);
	}
	if ((v = ucl_object_lookup(o, "listen_port")) != NULL &&
	    ucl_object_toint(v) > 0 && ucl_object_toint(v) <= 65535) {
		sp->has_listen_port = true;
		sp->listen_port = (uint32_t)ucl_object_toint(v);
	}
	/* A description may be empty: that takes it off. */
	if ((kind = ucl_str(o, "description")) != NULL)
		sp->description = kore_strdup(kind);
	if ((v = ucl_object_lookup(o, "mtu")) != NULL && ucl_object_toint(v) >
	    0 && ucl_object_toint(v) <= 65535) {
		sp->has_mtu = true;
		sp->mtu = (uint32_t)ucl_object_toint(v);
	}
	if ((v = ucl_object_lookup(o, "fib")) != NULL && ucl_object_toint(v) >
	    0 && ucl_object_toint(v) <= 65535) {
		sp->has_fib = true;
		sp->fib = (uint32_t)ucl_object_toint(v);
	}
	if ((v = ucl_object_lookup(o, "metric")) != NULL && ucl_object_toint(
	    v) > 0 && ucl_object_toint(v) <= UINT32_MAX) {
		sp->has_metric = true;
		sp->metric = (uint32_t)ucl_object_toint(v);
	}
	if ((v = ucl_object_lookup(o, "weight")) != NULL && ucl_object_toint(
	    v) > 0 && ucl_object_toint(v) <= UINT32_MAX) {
		sp->has_weight = true;
		sp->weight = (uint32_t)ucl_object_toint(v);
	}
	if ((v = ucl_object_lookup(o, "id")) != NULL && ucl_object_toint(v) >=
	    0 && ucl_object_toint(v) <= 16777215) {
		sp->has_id = true;
		sp->id = (uint32_t)ucl_object_toint(v);
	}
	sp->remove = ucl_flag(o, "remove");
	sp->recursive = ucl_flag(o, "recursive");
	sp->force = ucl_flag(o, "force");
	/* pkg -4 or -6, for a pkg-upgrade. */
	if (ucl_object_toint(ucl_object_lookup(o, "pkg_ip")) == 4 ||
	    ucl_object_toint(ucl_object_lookup(o, "pkg_ip")) == 6) {
		sp->has_pkg_ip = true;
		sp->pkg_ip = (uint8_t)ucl_object_toint(ucl_object_lookup(o,
		    "pkg_ip"));
	}
	sp->safe = ucl_flag(o, "safe");
	sp->live = ucl_flag(o, "live");
	sp->persist = ucl_flag(o, "persist");
	a = ucl_str(o, "action");
	switch (sp->kind) {
	case ARC_JOB_KIND_JAIL_ACTION:
		for (i = 0; a != NULL && i < nitems(action_names); i++)
			if (strcmp(a, action_names[i]) == 0)
				break;
		if (a == NULL || i == nitems(action_names) || sp->jail == NULL)
			return ("a jail-action needs a jail and an action");
		sp->has_action = true;
		sp->action = (uint8_t)i;
		break;
	case ARC_JOB_KIND_ADDRESS:
		if (sp->jail == NULL || sp->address == NULL)
			return ("an address job needs a jail and an address");
		break;
	case ARC_JOB_KIND_SERVICE_ACTION:
		for (i = 0; a != NULL && i < nitems(service_action_names); i++)
			if (strcmp(a, service_action_names[i]) == 0)
				break;
		if (a == NULL || i == nitems(service_action_names) ||
		    sp->service == NULL)
			return ("a service-action needs a service and an "
			    "action");
		sp->has_service_action = true;
		sp->service_action = (uint8_t)i;
		break;
	case ARC_JOB_KIND_IF_ADDRESS:
		if (sp->interface == NULL || sp->address == NULL)
			return ("an if-address job needs an interface and an "
			    "address");
		break;
	case ARC_JOB_KIND_ROUTE:
		if (sp->destination == NULL || (!sp->remove && sp->gateway ==
		    NULL))
			return ("a route job needs a destination, and a "
			    "gateway to add one");
		break;
	case ARC_JOB_KIND_IF_VNET:
		if (sp->interface == NULL || sp->jail == NULL)
			return ("an if-vnet job needs an interface and a jail");
		break;
	case ARC_JOB_KIND_IF_SET:
	case ARC_JOB_KIND_IF_CREATE:
	case ARC_JOB_KIND_IF_DESTROY:
		if (sp->interface == NULL)
			return ("the job needs an interface");
		break;
	case ARC_JOB_KIND_WIREGUARD:
		if (sp->interface == NULL || sp->verb == NULL)
			return ("a wireguard job needs an interface and a verb");
		break;
	case ARC_JOB_KIND_IPSEC:
		if (sp->verb == NULL || (strcmp(sp->verb, "init") != 0 &&
		    strcmp(sp->verb, "start") != 0 && sp->conn == NULL))
			return ("an ipsec job needs a verb, and a connection "
			    "but for init");
		break;
	case ARC_JOB_KIND_NETGRAPH:
	case ARC_JOB_KIND_BIRD:
	case ARC_JOB_KIND_KMOD:
	case ARC_JOB_KIND_ZFS:
	case ARC_JOB_KIND_ZPOOL:
	case ARC_JOB_KIND_MOUNT:
	case ARC_JOB_KIND_GPART:
	case ARC_JOB_KIND_CAM:
	case ARC_JOB_KIND_SYSCTL:
	case ARC_JOB_KIND_IPFW:
	case ARC_JOB_KIND_BRIDGE:
	case ARC_JOB_KIND_GENEVE:
	case ARC_JOB_KIND_PROCESS:
		/* Storage's verbs take more words; the host checks each. */
		names = ucl_object_lookup(o, "args");
		if (sp->kind == ARC_JOB_KIND_SYSCTL) {
			/* A name and its value, and no verb. */
			if (ucl_array_size(names) != 2)
				return ("a sysctl job needs a name and a "
				    "value as its args");
			sp->verb = NULL;
		} else
		if (sp->verb == NULL || (n = ucl_array_size(names)) >
		    (sp->kind >= ARC_JOB_KIND_IPFW ? 120u : sp->kind >=
		    ARC_JOB_KIND_ZFS ? 24u : 4u) ||
		    (n == 0 && sp->kind == ARC_JOB_KIND_NETGRAPH) ||
		    (n != 1 && sp->kind == ARC_JOB_KIND_KMOD))
			return ("the job needs a verb and its args");
		n = ucl_array_size(names);
		if (n == 0)
			break;
		nv = kore_calloc(n, sizeof(*nv));
		sp->names.v = nv;
		it = NULL;
		while ((v = ucl_object_iterate(names, &it, true)) != NULL &&
		    sp->names.n < n)
			if (ucl_object_type(v) == UCL_STRING)
				nv[sp->names.n++] =
				    kore_strdup(ucl_object_tostring(v));
		break;
	case ARC_JOB_KIND_IF_STATE:
		if (sp->interface == NULL || (v = ucl_object_lookup(o,
		    "up")) == NULL || ucl_object_type(v) != UCL_BOOLEAN)
			return ("an if-state job needs an interface and up, "
			    "true or false");
		sp->has_up = true;
		sp->up = ucl_object_toboolean(v);
		break;
	case ARC_JOB_KIND_SERVICE_CONFIG:
		if (sp->service == NULL)
			return ("a service-config needs a service");
		set = ucl_object_lookup(o, "set");
		unset = ucl_object_lookup(o, "unset");
		n = ucl_array_size(unset);
		it = NULL;
		while (set != NULL && ucl_object_type(set) == UCL_OBJECT &&
		    ucl_object_iterate(set, &it, true) != NULL)
			n++;
		if (n == 0 || n > 64)
			return ("a service-config needs variables to set");
		vars = kore_calloc(n, sizeof(*vars));
		sp->variables.v = vars;
		it = NULL;
		while (set != NULL && ucl_object_type(set) == UCL_OBJECT &&
		    (v = ucl_object_iterate(set, &it, true)) != NULL) {
			vars[sp->variables.n].key = kore_strdup(ucl_object_key(v));
			vars[sp->variables.n].value =
			    kore_strdup(ucl_object_tostring_forced(v));
			sp->variables.n++;
		}
		it = NULL;
		while ((v = ucl_object_iterate(unset, &it, true)) != NULL &&
		    sp->variables.n < n) {
			if (ucl_object_type(v) != UCL_STRING)
				continue;
			vars[sp->variables.n].key =
			    kore_strdup(ucl_object_tostring(v));
			vars[sp->variables.n].remove = true;
			sp->variables.n++;
		}
		break;
	default:
		names = ucl_object_lookup(o, "packages");
		if ((n = ucl_array_size(names)) > 0) {
			nv = kore_calloc(n, sizeof(*nv));
			sp->names.v = nv;
			it = NULL;
			while ((v = ucl_object_iterate(names, &it, true)) !=
			    NULL && sp->names.n < n)
				if (ucl_object_type(v) == UCL_STRING)
					nv[sp->names.n++] =
					    kore_strdup(ucl_object_tostring(v));
		}
		break;
	}
	return (NULL);
}

/*
 * GET /api/servers/<id>/jobs: the host's jobs.
 * POST, {"jobs": [{"kind": ...}, ...]}: queue them, in that order.
 */
int
api_jobs(struct http_request *req)
{
	ucl_object_t		*body;
	const ucl_object_t	*a, *v;
	ucl_object_iter_t	 it;
	struct call		*c;
	const char		*e;
	size_t			 n;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, req->method == HTTP_METHOD_POST ?
	    OP_JOB_SUBMIT : OP_JOBS)) == NULL)
		return (KORE_RESULT_OK);
	if (req->method != HTTP_METHOD_POST)
		return (call_start(req, c));
	e = NULL;
	body = read_json(req);
	a = body != NULL ? ucl_object_lookup(body, "jobs") : NULL;
	if ((n = ucl_array_size(a)) == 0 || n > ARC_MAX_BATCH)
		e = "jobs is a list of 1 to 64 jobs";
	else {
		c->specs = kore_calloc(n, sizeof(*c->specs));
		it = NULL;
		while (e == NULL && (v = ucl_object_iterate(a, &it, true)) !=
		    NULL)
			e = spec_from_json(v, &c->specs[c->nspecs++]);
	}
	ucl_object_unref(body);
	if (e != NULL) {
		for (n = 0; n < c->nspecs; n++)
			spec_free(&c->specs[n]);
		kore_free(c->specs);
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "%s", e));
	}
	return (call_start(req, c));
}

/* GET /api/servers/<id>/jobs/<n>: a job with its trace; DELETE: cancel. */
int
api_job(struct http_request *req)
{
	struct call	*c;
	char		 id[24];

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, req->method == HTTP_METHOD_DELETE ?
	    OP_JOB_CANCEL : OP_JOB)) == NULL)
		return (KORE_RESULT_OK);
	if (!capture(req, 5, id, sizeof(id))) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "bad job number"));
	}
	c->jobid = strtoull(id, NULL, 10);
	return (call_start(req, c));
}
