/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: a logical network element's root (RFC 8530, an inline schema
 * mount of RFC 8528's), the models as its vnet jail has them.
 *
 * A helper for each running vnet jail, this program run again
 * ("--scope-helper JID lne-serve"), attaches to the jail
 * (jail_attach(2)) and serves there what the agent serves, by cblink's
 * YANG family over a socketpair(2): what its handlers read of the
 * kernel, by netlink(4) and the ioctls, is then the jail's network, and
 * the files they read the jail's.  It is started at the first read of
 * the jail, kept while the jail runs, stopped when the jail goes
 * (EVFILT_JAIL, ira/jailwatch.c; jail_remove(2) has killed it), and
 * started again where it died meanwhile.  The agent asks it as a
 * blocking client of a context of its own, one request at a time per
 * jail, the connection on no loop: nothing comes from the helper
 * unasked.  A jail inside the jail is not asked by the helper.
 *
 * The interfaces in the jails are the host's too, each with the jail it
 * is bound to (bind-lne-name, RFC 8530 section 3.1 and Appendix A): one
 * of a jail's that the host has none of the name of, as one given to
 * it from the host (ifconfig(8) vnet) is.  An interface a commit bound
 * is remembered: when its jail goes, the kernel gives it back to the
 * host, and bind-lne-name-failed tells so.
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <locale.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "agent.h"
#include "collect.h"

/* As the agent's own context has them (main.c). */
#define	LNE_MAX_FRAME	(8 * 1024 * 1024)
#define	LNE_MAX_ATTRS	(1024 * 1024)
#define	LNE_MAX_DEPTH	32
#define	LNE_WAIT_MS	15000

typedef struct ietf_logical_network_element_logical_network_elements_logical_network_element_root
    ylneroot;
typedef struct ietf_interfaces_interfaces_interface yif;

struct lneh {
	LIST_ENTRY(lneh) link;
	int		 jid;
	pid_t		 pid;
	cbl_conn	*conn;
	unsigned	 refs;		/* the list's, and each request's */
	bool		 listed;
	pthread_mutex_t	 mtx;		/* one request at a time */
};

static LIST_HEAD(, lneh) helpers = LIST_HEAD_INITIALIZER(helpers);
static pthread_mutex_t	 helpers_lock = PTHREAD_MUTEX_INITIALIZER;
static cbl_ctx		*lctx;

/* An interface a commit bound to a jail. */
struct lnebind {
	LIST_ENTRY(lnebind) link;
	int		 jid;
	char		*ifname;
	char		*lne;
};

static LIST_HEAD(, lnebind) binds = LIST_HEAD_INITIALIZER(binds);
static pthread_mutex_t	 binds_lock = PTHREAD_MUTEX_INITIALIZER;

/* The context the helpers are asked on: limits before its first use. */
static int
ctx_make(void)
{
	int	error;

	if ((error = cbl_ctx_new(&lctx)) != 0)
		return (error);
	(void)cbl_ctx_set_limit(lctx, CBL_LIM_MAX_FRAME, LNE_MAX_FRAME);
	(void)cbl_ctx_set_limit(lctx, CBL_LIM_MAX_ATTRS, LNE_MAX_ATTRS);
	(void)cbl_ctx_set_limit(lctx, CBL_LIM_MAX_DEPTH, LNE_MAX_DEPTH);
	(void)cbl_ctx_set_limit(lctx, CBL_LIM_IDLE_MS, 0);
	return (0);
}

/* The helper of jail jid, held: made (not yet started) if there is none. */
static struct lneh *
hold(int jid)
{
	struct lneh	*h;

	pthread_mutex_lock(&helpers_lock);
	if (lctx == NULL && ctx_make() != 0) {
		pthread_mutex_unlock(&helpers_lock);
		return (NULL);
	}
	LIST_FOREACH(h, &helpers, link)
		if (h->jid == jid)
			break;
	if (h == NULL) {
		if ((h = calloc(1, sizeof(*h))) == NULL) {
			pthread_mutex_unlock(&helpers_lock);
			return (NULL);
		}
		h->jid = jid;
		h->pid = -1;
		h->refs = 1;
		h->listed = true;
		pthread_mutex_init(&h->mtx, NULL);
		LIST_INSERT_HEAD(&helpers, h, link);
	}
	h->refs++;
	pthread_mutex_unlock(&helpers_lock);
	return (h);
}

/* The helper's process ended and its connection closed. */
static void
halt(struct lneh *h)
{

	if (h->conn != NULL) {
		cbl_conn_free(h->conn);
		h->conn = NULL;
	}
	if (h->pid > 0) {
		(void)kill(h->pid, SIGKILL);
		while (waitpid(h->pid, NULL, 0) == -1 && errno == EINTR)
			;
		h->pid = -1;
	}
}

static void
rele(struct lneh *h)
{
	bool	last;

	pthread_mutex_lock(&helpers_lock);
	last = --h->refs == 0;
	pthread_mutex_unlock(&helpers_lock);
	if (!last)
		return;
	halt(h);
	pthread_mutex_destroy(&h->mtx);
	free(h);
}

/* Off the list: the next request makes another. */
static void
unlist(struct lneh *h)
{
	bool	was;

	pthread_mutex_lock(&helpers_lock);
	if ((was = h->listed)) {
		LIST_REMOVE(h, link);
		h->listed = false;
	}
	pthread_mutex_unlock(&helpers_lock);
	if (was)
		rele(h);
}

/* The helper run, attached to its jail, the socketpair's other side its
 * standard input. */
static int
start(struct lneh *h)
{
	static char *const		 noenv[] = { NULL };
	posix_spawn_file_actions_t	 fa;
	posix_spawnattr_t		 sa;
	sigset_t			 none;
	char				 js[16], *argv[5];
	int				 sp[2], rc;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) == -1)
		return (errno);
	snprintf(js, sizeof(js), "%d", h->jid);
	argv[0] = (char *)(uintptr_t)opts.helper_bin;
	argv[1] = (char *)(uintptr_t)"--scope-helper";
	argv[2] = js;
	argv[3] = (char *)(uintptr_t)"lne-serve";
	argv[4] = NULL;
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_adddup2(&fa, sp[1], STDIN_FILENO);
	posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null",
	    O_WRONLY, 0);
	/* The agent's threads block SIGTERM; the helper does not. */
	posix_spawnattr_init(&sa);
	sigemptyset(&none);
	posix_spawnattr_setsigmask(&sa, &none);
	posix_spawnattr_setflags(&sa, POSIX_SPAWN_SETSIGMASK);
	rc = posix_spawn(&h->pid, argv[0], &fa, &sa, argv, noenv);
	posix_spawnattr_destroy(&sa);
	posix_spawn_file_actions_destroy(&fa);
	close(sp[1]);
	if (rc != 0) {
		close(sp[0]);
		h->pid = -1;
		return (rc);
	}
	if ((rc = cbl_conn_new_fd(lctx, sp[0], 0, &h->conn)) != 0) {
		h->conn = NULL;
		halt(h);
	}
	return (rc);
}

/*
 * A GET of the top-level nodes sids (their SIDs) in the jail jid, by its
 * helper: *reply the answer, the caller's to free; failing, *reply the
 * helper's ERROR, or NULL when it could not be asked.  A helper that
 * went is started again, once.
 */
int
lne_get(int jid, const uint64_t *sids, size_t n, cbl_msg **reply)
{
	struct lneh	*h;
	cbl_msg		*m;
	int		 error = EAGAIN;

	*reply = NULL;
	/* Only this program can be the helper: not -H's, nor in a jail. */
	if (!opts.helper_self || opts.helper_bin == NULL)
		return (EOPNOTSUPP);
	if ((h = hold(jid)) == NULL)
		return (ENOMEM);
	pthread_mutex_lock(&h->mtx);
	for (int tries = 0; tries < 2; tries++) {
		if (h->conn == NULL && (error = start(h)) != 0)
			break;
		if ((error = cbl_msg_new(lctx, CBL_YANG_FAMILY, CBL_YCMD_GET, 0,
		    &m)) != 0)
			break;
		if ((error = cbl_msg_put_yget(m, sids, n)) != 0) {
			cbl_msg_free(m);
			break;
		}
		if ((error = cbl_request(h->conn, m, reply, LNE_WAIT_MS)) == 0 ||
		    *reply != NULL)
			break;
		halt(h);
	}
	pthread_mutex_unlock(&h->mtx);
	if (error != 0 && *reply == NULL)
		unlist(h);
	rele(h);
	return (error);
}

/* A container's child of that name. */
static const struct cbl_ynode *
ychild(const struct cbl_ynode *n, const char *name)
{

	for (uint32_t i = 0; n != NULL && i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	return (NULL);
}

/* The mount point root of a logical network element. */
const struct cbl_ynode *
lne_root_node(void)
{
	static const struct cbl_ynode *n;

	if (n == NULL)
		n = ychild(ychild(ynode_named("ietf-logical-network-element",
		    "logical-network-elements"), "logical-network-element"),
		    "root");
	return (n);
}

/*
 * The root of the jail name's logical network element: what its helper
 * answers of the interfaces, the routing, the network instances (each
 * with its vrf-root), the YANG library and the schema mounts, each a
 * module's data in the mount (cbl_ymount_data()).  *out NULL, and a
 * note in the log, when it could not be read.
 */
int
lne_root(cbl_yarena *a, const char *name, const ylneroot **out)
{
	static const char *const tops[][2] = {
		{ "ietf-interfaces", "interfaces" },
		{ "ietf-routing", "routing" },
		{ "ietf-network-instance", "network-instances" },
		{ "ietf-yang-library", "yang-library" },
		{ "ietf-yang-schema-mount", "schema-mounts" },
	};
	const struct cbl_ynode	*mp = lne_root_node(), *n[nitems(tops)];
	uint64_t		 sids[nitems(tops)];
	ylneroot		*r;
	cbl_msg			*rep;
	const void		*raw;
	char			 why[128];
	size_t			 len;
	void			*data;
	int			 jid, error;

	*out = NULL;
	if (mp == NULL || (jid = jail_getid(name)) <= 0)
		return (0);
	for (size_t i = 0; i < nitems(tops); i++) {
		if ((n[i] = ynode_named(tops[i][0], tops[i][1])) == NULL)
			return (0);
		sids[i] = n[i]->sid;
	}
	if ((error = lne_get(jid, sids, nitems(sids), &rep)) != 0) {
		if (error != EOPNOTSUPP)
			logmsg(LOG_NOTICE, "the jail %s's root not read: %s",
			    name, rep != NULL && cbl_msg_err_str(rep) != NULL ?
			    cbl_msg_err_str(rep) : strerror(error));
		cbl_msg_free(rep);
		return (0);
	}
	if ((r = cbl_yarena_alloc(a, sizeof(*r))) == NULL) {
		cbl_msg_free(rep);
		return (ENOMEM);
	}
	memset(r, 0, sizeof(*r));
	for (size_t i = 0; error == 0 && i < nitems(tops); i++) {
		if (cbl_msg_sid_raw(rep, sids[i], &raw, &len) != 0)
			continue;
		if ((data = cbl_ymount_data(mp, r, n[i]->module, a)) == NULL)
			error = ENOMEM;
		else if ((error = cbl_msg_ydecode_member(rep, n[i], data, a, 0,
		    why, sizeof(why))) != 0)
			logmsg(LOG_NOTICE, "the jail %s's %s: %s", name,
			    tops[i][1], why);
	}
	cbl_msg_free(rep);
	if (error == ENOMEM)
		return (error);
	if (error == 0)
		*out = r;
	return (0);
}

static const char *
astr(cbl_yarena *a, const char *s)
{
	char	*p;

	if ((p = cbl_yarena_alloc(a, strlen(s) + 1)) != NULL)
		memcpy(p, s, strlen(s) + 1);
	return (p);
}

/*
 * The interfaces in the vnet jails, put in the host's: each that the
 * host has none of the name of, with its type and the jail it is
 * bound to.
 */
int
lne_bound_interfaces(struct ietf_interfaces *data, cbl_yarena *a)
{
	const struct cbl_ynode	*ifs = ynode_named("ietf-interfaces",
				    "interfaces");
	struct ietf_interfaces_interfaces *c;
	yif			*v;
	size_t			 n, cap;
	int			 jid, lastjid;

	if (ifs == NULL || !opts.helper_self || opts.helper_bin == NULL)
		return (0);
	n = data->interfaces != NULL ? data->interfaces->interface.n : 0;
	cap = n;
	v = NULL;
	for (lastjid = 0;; lastjid = jid) {
		struct ietf_interfaces	 in;
		char			 last[16], name[MAXHOSTNAMELEN],
					 vnet[16], why[128];
		cbl_msg			*rep;
		const char		*lne;

		snprintf(last, sizeof(last), "%d", lastjid);
		name[0] = vnet[0] = '\0';
		if ((jid = jail_getv(0, "lastjid", last, "name", name, "vnet",
		    vnet, NULL)) == -1)
			break;
		if (strcmp(vnet, "new") != 0)
			continue;
		if (lne_get(jid, &ifs->sid, 1, &rep) != 0) {
			cbl_msg_free(rep);
			continue;
		}
		memset(&in, 0, sizeof(in));
		if (cbl_msg_ydecode_member(rep, ifs, &in, a, 0, why,
		    sizeof(why)) != 0 || in.interfaces == NULL) {
			cbl_msg_free(rep);
			continue;
		}
		cbl_msg_free(rep);
		lne = NULL;
		for (size_t i = 0; i < in.interfaces->interface.n; i++) {
			const yif *e = &in.interfaces->interface.v[i];
			bool here = false;

			for (size_t k = 0; k < n && !here; k++)
				here = strcmp((v != NULL ? v :
				    data->interfaces->interface.v)[k].name,
				    e->name) == 0;
			if (here)
				continue;
			if (n == cap) {
				yif *nv;

				cap = cap * 2 + 8;
				if ((nv = cbl_yarena_alloc(a, cap *
				    sizeof(*nv))) == NULL)
					return (ENOMEM);
				if (n > 0)
					memcpy(nv, v != NULL ? v :
					    data->interfaces->interface.v,
					    n * sizeof(*nv));
				v = nv;
			}
			if (lne == NULL && (lne = astr(a, name)) == NULL)
				return (ENOMEM);
			memset(&v[n], 0, sizeof(v[n]));
			v[n].name = e->name;
			v[n].has_type = e->has_type;
			v[n].type = e->type;
			v[n].lne_bind_lne_name = lne;
			n++;
		}
	}
	if (v == NULL)
		return (0);
	if ((c = cbl_yarena_alloc(a, sizeof(*c))) == NULL)
		return (ENOMEM);
	memset(c, 0, sizeof(*c));
	if (data->interfaces != NULL)
		*c = *data->interfaces;
	c->interface.n = n;
	c->interface.v = v;
	data->interfaces = c;
	return (0);
}

/* An interface a commit bound to the jail lne (on), or took back. */
void
lne_bound(const char *ifname, const char *lne, bool on)
{
	struct lnebind	*b, *nb;
	int		 jid;

	pthread_mutex_lock(&binds_lock);
	LIST_FOREACH_SAFE(b, &binds, link, nb)
		if (strcmp(b->ifname, ifname) == 0) {
			LIST_REMOVE(b, link);
			free(b->ifname);
			free(b->lne);
			free(b);
		}
	if (on && (jid = jail_getid(lne)) > 0 &&
	    (b = calloc(1, sizeof(*b))) != NULL) {
		b->jid = jid;
		b->ifname = strdup(ifname);
		b->lne = strdup(lne);
		if (b->ifname == NULL || b->lne == NULL) {
			free(b->ifname);
			free(b->lne);
			free(b);
		} else
			LIST_INSERT_HEAD(&binds, b, link);
	}
	pthread_mutex_unlock(&binds_lock);
}

/*
 * The jail jid went: its helper's connection closed and the process
 * reaped (jail_remove(2) killed it); each interface a commit bound to
 * it is the host's again, which bind-lne-name-failed tells.
 */
void
lne_gone(int jid)
{
	struct lnebind	*b, *nb;
	struct lneh	*h;
	char		 why[256];

	pthread_mutex_lock(&helpers_lock);
	LIST_FOREACH(h, &helpers, link)
		if (h->jid == jid)
			break;
	if (h != NULL)
		h->refs++;
	pthread_mutex_unlock(&helpers_lock);
	if (h != NULL) {
		unlist(h);
		pthread_mutex_lock(&h->mtx);
		halt(h);
		pthread_mutex_unlock(&h->mtx);
		rele(h);
	}
	pthread_mutex_lock(&binds_lock);
	LIST_FOREACH_SAFE(b, &binds, link, nb) {
		if (b->jid != jid)
			continue;
		snprintf(why, sizeof(why), "the jail %s stopped: its vnet "
		    "gave %s back to the host", b->lne, b->ifname);
		yang_lne_failed(b->ifname, b->lne, why);
		LIST_REMOVE(b, link);
		free(b->ifname);
		free(b->lne);
		free(b);
	}
	pthread_mutex_unlock(&binds_lock);
}

static void
served_closed(cbl_conn *c, int error, void *arg)
{

	(void)c;
	(void)error;
	(void)cbl_loop_stop(*(cbl_loop **)arg);
}

/*
 * The helper's side, attached to its jail already: the models served on
 * its standard input, until the agent closes it.  Nothing is read here
 * by a helper again: this process is in the jail, where it reads.
 */
int
lne_serve(void)
{
	static const struct cbl_conn_cbs	 cbs = {
		.on_close = served_closed,
	};
	static cbl_loop				*loop;
	cbl_conn				*c;
	cbl_ctx					*ctx;
	int					 error;

	opts.helper_self = true;
	opts.helper_bin = NULL;
	(void)setlocale(LC_CTYPE, "C.UTF-8");
	(void)signal(SIGPIPE, SIG_IGN);
	if ((error = cbl_ctx_new(&ctx)) != 0)
		goto fail;
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_FRAME, LNE_MAX_FRAME);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_ATTRS, LNE_MAX_ATTRS);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_DEPTH, LNE_MAX_DEPTH);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_IDLE_MS, 0);
	if ((error = cbl_ctx_set_conn_cbs(ctx, &cbs, &loop)) != 0 ||
	    (error = cbl_yserver_add(ctx, &ymodel_server, NULL)) != 0 ||
	    (error = cbl_loop_new(ctx, &loop)) != 0 ||
	    (error = cbl_conn_new_fd(ctx, STDIN_FILENO, CBL_CF_ACCEPT,
	    &c)) != 0 || (error = cbl_conn_attach(c, loop)) != 0)
		goto fail;
	error = cbl_loop_run(loop);
	return (error == 0 ? 0 : 1);
fail:
	fprintf(stderr, "arcana-agent: lne-serve: %s\n", strerror(error));
	return (1);
}
