/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cblink handlers for the arcana family.  Requests are checked here,
 * then run on a thread of their own so a jail(8) that takes minutes does
 * not hold up the event loop; changes run one at a time.
 */

#include <sys/param.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>

#include "agent.h"

struct job {
	cbl_req			*req;
	uint16_t		 cmd;
	bool			 config_only;
	char			*jail;
	uint8_t			 action;
	struct arc_address_req	 addr;
	struct arc_service_config_req svc;
	uint8_t			 family;
	struct arc_pkg_upgrade_req pkg;
	bool			 refresh;
	uint8_t			*binary;	/* agent-update */
	size_t			 binlen;
	char			*sha256;
	bool			 restart;
	char			*peer;
};

#define	STOPPING	"not done: arcana-agent is stopping"
#define	RESTART_WAIT	10	/* s, for service(8) to stop the daemon */

pthread_mutex_t	change_lock = PTHREAD_MUTEX_INITIALIZER;

/* What holds change_lock now, for the log when asked to stop. */
static pthread_mutex_t	note_lock = PTHREAD_MUTEX_INITIALIZER;
static char		note[256];
static bool		stopping;

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
};

static const char *service_action_names[] = {
	[ARC_SERVICE_ACTION_START] = "start",
	[ARC_SERVICE_ACTION_STOP] = "stop",
	[ARC_SERVICE_ACTION_RESTART] = "restart",
	[ARC_SERVICE_ACTION_RELOAD] = "reload",
	[ARC_SERVICE_ACTION_ENABLE] = "enable",
	[ARC_SERVICE_ACTION_DISABLE] = "disable",
};

static bool	valid_jail(const char *);
static bool	valid_ifname(const char *);
static bool	valid_service(const char *);
static char	*peer_name(cbl_req *);
static void	*worker(void *);
static int	start(struct job *);
static int	reject(cbl_req *, const char *);
static char	*xstrdup(const char *);
static void	job_free(struct job *);
static const char *check_spec(const struct arc_job_spec *);

/*
 * Jail names: letters, digits, '_', '-', and '.' for hierarchical jails.
 * All-digit names are refused because jail(8) reads them as jids.
 */
static bool
valid_jail(const char *s)
{
	const char	*p;
	bool		 digits;

	if (*s == '\0' || *s == '.' || *s == '-' || strstr(s, "..") != NULL)
		return (false);
	digits = true;
	for (p = s; *p != '\0'; p++) {
		if (!isalnum((unsigned char)*p) && strchr("_.-", *p) == NULL)
			return (false);
		if (!isdigit((unsigned char)*p))
			digits = false;
	}
	return (!digits);
}

static bool
valid_ifname(const char *s)
{

	if (!isalpha((unsigned char)*s))
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && *s != '_' && *s != '.')
			return (false);
	return (true);
}

/* rc.d script names: letters, digits, '_', '-', '.'; not hidden. */
static bool
valid_service(const char *s)
{

	if (*s == '\0' || *s == '.' || *s == '-' || strlen(s) > 64)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.-", *s) == NULL)
			return (false);
	return (true);
}

static char *
xstrdup(const char *s)
{
	char	*p;

	if (s == NULL)
		return (NULL);
	if ((p = strdup(s)) == NULL)
		err(1, "strdup");
	return (p);
}

/* Who asked: the certificate subject, or the local uid. */
static char *
peer_name(cbl_req *req)
{
	const cbl_peer	*peer;
	const char	*subj;
	uid_t		 uid;
	gid_t		 gid;
	char		*s;

	peer = cbl_req_peer(req);
	if (peer != NULL && (subj = cbl_peer_subject(peer)) != NULL)
		return (xstrdup(subj));
	if (peer != NULL && cbl_peer_cred(peer, &uid, &gid) == 0) {
		if (asprintf(&s, "uid %u", (unsigned)uid) == -1)
			err(1, "asprintf");
		return (s);
	}
	return (xstrdup("unknown peer"));
}

/* Refuse a request whose attributes are well-formed but not acceptable. */
static int
reject(cbl_req *req, const char *msg)
{

	(void)cbl_req_set_err(req, msg, NULL, 0, -1);
	return (EINVAL);
}

/*
 * Say what the holder of change_lock is about to do; NULL when it is
 * done.  False when the daemon is stopping: the change must not start.
 */
bool
change_note(const char *fmt, ...)
{
	va_list	ap;
	bool	go;

	pthread_mutex_lock(&note_lock);
	go = fmt != NULL && !stopping;
	if (!go)
		note[0] = '\0';
	else {
		va_start(ap, fmt);
		vsnprintf(note, sizeof(note), fmt, ap);
		va_end(ap);
	}
	pthread_mutex_unlock(&note_lock);
	return (go);
}

/* The daemon was told to stop: no change starts from here on. */
void
changes_stop(void)
{

	pthread_mutex_lock(&note_lock);
	stopping = true;
	pthread_mutex_unlock(&note_lock);
}

/* The change under way and the jobs that wait, to the log. */
void
changes_log(int pri)
{
	char	now[sizeof(note)];

	pthread_mutex_lock(&note_lock);
	strlcpy(now, note, sizeof(now));
	pthread_mutex_unlock(&note_lock);
	if (now[0] != '\0')
		logmsg(pri, "under way: %s", now);
	jobs_log(pri);
}

static void *
worker(void *arg)
{
	struct job		*j;
	struct work		 w;
	struct arc_list_rsp	 lr;
	struct arc_action_rsp	 ar;
	struct arc_address_rsp	 dr;
	struct arc_services_rsp	 sr;
	struct arc_service_action_rsp sar;
	struct arc_service_config_rsp scr;
	struct arc_network_rsp	 nr;
	struct arc_stats_rsp	 str;
	struct arc_packages_rsp	 pr;
	struct arc_pkg_upgrade_rsp ur;
	struct arc_agent_update_rsp aur;
	const char		*what, *error;
	bool			 restart;
	bool			 ok;
	int			 root, rc;

	j = arg;
	work_init(&w);
	restart = false;
	switch (j->cmd) {
	case ARC_CMD_LIST:
		what = j->config_only ? "list (configuration only)" : "list";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&lr, 0, sizeof(lr));
		do_list(&w, j->config_only, &lr);
		ok = lr.ok;
		error = lr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &lr.trace.v, &lr.trace.n);
		rc = arc_list_reply(j->req, &lr);
		break;
	case ARC_CMD_ACTION:
		what = wfmt(&w, "%s %s", action_names[j->action], j->jail);
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&ar, 0, sizeof(ar));
		pthread_mutex_lock(&change_lock);
		if (change_note("%s", what))
			do_action(&w, j->jail, j->action, &ar);
		else {
			ar.has_ok = true;
			ar.error = STOPPING;
		}
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		ok = ar.ok;
		error = ar.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &ar.trace.v, &ar.trace.n);
		rc = arc_action_reply(j->req, &ar);
		break;
	case ARC_CMD_PACKAGES:
		what = wfmt(&w, "packages%s%s%s", j->jail != NULL ? " of jail " :
		    "", j->jail != NULL ? j->jail : "", j->refresh ?
		    " (refresh)" : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&pr, 0, sizeof(pr));
		pthread_mutex_lock(&change_lock);
		if (change_note("%s", what))
			do_packages(&w, j->jail, j->refresh, &pr);
		else {
			pr.has_ok = true;
			pr.error = STOPPING;
		}
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		ok = pr.ok;
		error = pr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &pr.trace.v, &pr.trace.n);
		rc = arc_packages_reply(j->req, &pr);
		break;
	case ARC_CMD_PKG_UPGRADE:
		what = wfmt(&w, "pkg upgrade%s%s%s%s", j->jail != NULL ?
		    " in jail " : "", j->jail != NULL ? j->jail : "",
		    j->pkg.names.n > 0 ? " (some)" : " (all)",
		    j->pkg.dry_run ? " dry-run" : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&ur, 0, sizeof(ur));
		pthread_mutex_lock(&change_lock);
		if (change_note("%s", what))
			do_pkg_upgrade(&w, &j->pkg, &ur);
		else {
			ur.has_ok = true;
			ur.error = STOPPING;
		}
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		ok = ur.ok;
		error = ur.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &ur.trace.v, &ur.trace.n);
		rc = arc_pkg_upgrade_reply(j->req, &ur);
		break;
	case ARC_CMD_STATS:
		what = "stats";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "stats");
		memset(&str, 0, sizeof(str));
		do_stats(&w, &str);
		ok = str.ok;
		error = str.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &str.trace.v, &str.trace.n);
		rc = arc_stats_reply(j->req, &str);
		break;
	case ARC_CMD_NETWORK:
		what = wfmt(&w, "network %s%s", net_kind_names[j->action],
		    j->family == ARC_NET_FAMILY_INET ? " inet" :
		    j->family == ARC_NET_FAMILY_INET6 ? " inet6" : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&nr, 0, sizeof(nr));
		do_network(&w, j->action, j->family, &nr);
		ok = nr.ok;
		error = nr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &nr.trace.v, &nr.trace.n);
		rc = arc_network_reply(j->req, &nr);
		break;
	case ARC_CMD_SERVICES:
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "services");
		what = "services";
		memset(&sr, 0, sizeof(sr));
		do_services(&w, &sr);
		ok = sr.ok;
		error = sr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sr.trace.v, &sr.trace.n);
		rc = arc_services_reply(j->req, &sr);
		break;
	case ARC_CMD_SERVICE_ACTION:
		what = wfmt(&w, "service %s %s", j->jail,
		    service_action_names[j->action]);
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&sar, 0, sizeof(sar));
		pthread_mutex_lock(&change_lock);
		if (change_note("%s", what))
			do_service_action(&w, j->jail, j->action, &sar);
		else {
			sar.has_ok = true;
			sar.error = STOPPING;
		}
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		ok = sar.ok;
		error = sar.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sar.trace.v, &sar.trace.n);
		rc = arc_service_action_reply(j->req, &sar);
		break;
	case ARC_CMD_AGENT_UPDATE:
		what = wfmt(&w, "agent update%s", j->restart ?
		    " and restart" : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&aur, 0, sizeof(aur));
		/* Not while a job changes the host: a restart would cut
		 * it short. */
		pthread_mutex_lock(&change_lock);
		if (change_note("%s", what))
			do_agent_update(&w, j->binary, j->binlen, j->sha256, &aur);
		else {
			aur.has_ok = true;
			aur.error = STOPPING;
		}
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		ok = aur.ok;
		error = aur.error;
		restart = ok && j->restart;
		aur.restarting = restart;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &aur.trace.v, &aur.trace.n);
		rc = arc_agent_update_reply(j->req, &aur);
		break;
	case ARC_CMD_SERVICE_CONFIG:
		what = wfmt(&w, "service %s config%s", j->jail,
		    j->svc.variables.n > 0 ? " (set)" : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&scr, 0, sizeof(scr));
		pthread_mutex_lock(&change_lock);
		if (change_note("%s", what))
			do_service_config(&w, &j->svc, &scr);
		else {
			scr.has_ok = true;
			scr.error = STOPPING;
		}
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		ok = scr.ok;
		error = scr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &scr.trace.v, &scr.trace.n);
		rc = arc_service_config_reply(j->req, &scr);
		break;
	default:
		what = wfmt(&w, "address %s %s %s%s%s%s", j->addr.jail,
		    j->addr.remove ? "remove" : "add", j->addr.address,
		    j->addr.live ? " live" : "",
		    j->addr.persist ? " persist" : "",
		    j->addr.dry_run ? " dry-run" : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&dr, 0, sizeof(dr));
		pthread_mutex_lock(&change_lock);
		if (change_note("%s", what))
			do_address(&w, &j->addr, &dr);
		else {
			dr.has_ok = true;
			dr.error = STOPPING;
		}
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		ok = dr.ok;
		error = dr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &dr.trace.v, &dr.trace.n);
		rc = arc_address_reply(j->req, &dr);
		break;
	}
	if (rc != 0)
		logmsg(LOG_ERR, "%s: %s: reply failed: %s", j->peer, what,
		    strerror(rc));
	else
		logmsg(ok ? LOG_INFO : LOG_NOTICE, "%s: %s: %s", j->peer,
		    what, ok ? "ok" : error);
	(void)cbl_req_complete(j->req, rc);
	work_free(&w);
	job_free(j);
	if (restart) {
		/*
		 * No change starts while the service is on its way to
		 * stop this daemon.  Still here after a while, it did
		 * not: the daemon is not run by the service.
		 */
		pthread_mutex_lock(&change_lock);
		(void)change_note("restarting the service after an update");
		agent_restart();
		sleep(RESTART_WAIT);
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		logmsg(LOG_ERR, "restart: still running after %d s; is "
		    "arcana_agent the service that runs this daemon?",
		    RESTART_WAIT);
	}
	return (NULL);
}

static void
job_free(struct job *j)
{
	size_t	i;

	for (i = 0; i < j->svc.variables.n; i++) {
		free((char *)(uintptr_t)j->svc.variables.v[i].key);
		free((char *)(uintptr_t)j->svc.variables.v[i].value);
	}
	free((void *)(uintptr_t)j->svc.variables.v);
	for (i = 0; i < j->pkg.names.n; i++)
		free((char *)(uintptr_t)j->pkg.names.v[i]);
	free((void *)(uintptr_t)j->pkg.names.v);
	free(j->jail);
	free(j->binary);
	free(j->sha256);
	free((char *)(uintptr_t)j->addr.jail);
	free((char *)(uintptr_t)j->addr.address);
	free((char *)(uintptr_t)j->addr.interface);
	free(j->peer);
	free(j);
}

/* Hand the request to a thread; it replies and completes it. */
static int
start(struct job *j)
{
	pthread_attr_t	attr;
	pthread_t	tid;
	int		error;

	j->peer = peer_name(j->req);
	if ((error = cbl_req_defer(j->req)) != 0)
		return (error);
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	error = pthread_create(&tid, &attr, worker, j);
	pthread_attr_destroy(&attr);
	if (error != 0) {
		logmsg(LOG_ERR, "pthread_create: %s", strerror(error));
		(void)cbl_req_complete(j->req, error);
		job_free(j);
	}
	return (0);
}

int
arc_hello_doit(cbl_req *req, void *arg __unused)
{
	struct arc_hello_rsp	rsp;
	struct arc_host		host;
	struct work		w;
	int			error;

	work_init(&w);
	host_info(&w, &host);
	memset(&rsp, 0, sizeof(rsp));
	rsp.host = &host;
	error = arc_hello_reply(req, &rsp);
	work_free(&w);
	return (error);
}

int
arc_list_doit(cbl_req *req, const struct arc_list_req *rq, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_LIST;
	j->config_only = rq->config_only;
	return (start(j));
}

int
arc_action_doit(cbl_req *req, const struct arc_action_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (!valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if (rq->action >= nitems(action_names))
		return (reject(req, "invalid action"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_ACTION;
	j->jail = xstrdup(rq->jail);
	j->action = rq->action;
	return (start(j));
}

int
arc_address_doit(cbl_req *req, const struct arc_address_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (!valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if (strchr(rq->address, '|') != NULL)
		return (reject(req, "give the interface separately"));
	if (rq->interface != NULL && !valid_ifname(rq->interface))
		return (reject(req, "invalid interface name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_ADDRESS;
	j->addr = *rq;
	j->addr.jail = xstrdup(rq->jail);
	j->addr.address = xstrdup(rq->address);
	j->addr.interface = xstrdup(rq->interface);
	return (start(j));
}

int
arc_services_doit(cbl_req *req, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SERVICES;
	return (start(j));
}

int
arc_service_action_doit(cbl_req *req, const struct arc_service_action_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (!valid_service(rq->service))
		return (reject(req, "invalid service name"));
	if (rq->service_action >= nitems(service_action_names))
		return (reject(req, "invalid action"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SERVICE_ACTION;
	j->jail = xstrdup(rq->service);
	j->action = rq->service_action;
	return (start(j));
}

int
arc_agent_update_doit(cbl_req *req, const struct arc_agent_update_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->binary.len == 0 || strlen(rq->sha256) != 64)
		return (reject(req, "a program and its SHA-256 are needed"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_AGENT_UPDATE;
	if ((j->binary = malloc(rq->binary.len)) == NULL)
		err(1, "malloc");
	memcpy(j->binary, rq->binary.p, rq->binary.len);
	j->binlen = rq->binary.len;
	j->sha256 = xstrdup(rq->sha256);
	j->restart = rq->restart;
	return (start(j));
}

int
arc_service_config_doit(cbl_req *req, const struct arc_service_config_req *rq,
    void *arg __unused)
{
	struct arc_variable	*v;
	struct job		*j;
	size_t			 i;

	if (!valid_service(rq->service))
		return (reject(req, "invalid service name"));
	for (i = 0; i < rq->variables.n; i++)
		if (rq->variables.v[i].key == NULL)
			return (reject(req, "a variable without a key"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SERVICE_CONFIG;
	j->jail = xstrdup(rq->service);
	j->svc.service = j->jail;
	if (rq->variables.n > 0) {
		if ((v = calloc(rq->variables.n, sizeof(*v))) == NULL)
			err(1, "calloc");
		for (i = 0; i < rq->variables.n; i++) {
			v[i].key = xstrdup(rq->variables.v[i].key);
			v[i].value = xstrdup(rq->variables.v[i].value);
			v[i].remove = rq->variables.v[i].remove;
		}
		j->svc.variables.v = v;
		j->svc.variables.n = rq->variables.n;
	}
	return (start(j));
}

int
arc_network_doit(cbl_req *req, const struct arc_network_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->net_kind >= nitems(net_kind_names))
		return (reject(req, "invalid kind"));
	if (rq->has_net_family && rq->net_family > ARC_NET_FAMILY_INET6)
		return (reject(req, "invalid family"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_NETWORK;
	j->action = rq->net_kind;
	j->family = rq->has_net_family ? rq->net_family : ARC_NET_FAMILY_ALL;
	return (start(j));
}

int
arc_stats_doit(cbl_req *req, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_STATS;
	return (start(j));
}

int
arc_packages_doit(cbl_req *req, const struct arc_packages_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->jail != NULL && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_PACKAGES;
	j->jail = xstrdup(rq->jail);
	j->refresh = rq->refresh;
	return (start(j));
}

int
arc_pkg_upgrade_doit(cbl_req *req, const struct arc_pkg_upgrade_req *rq,
    void *arg __unused)
{
	struct job	*j;
	const char	**v;
	size_t		 i;

	if (rq->jail != NULL && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	for (i = 0; i < rq->names.n; i++)
		if (rq->names.v[i] == NULL)
			return (reject(req, "a package without a name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_PKG_UPGRADE;
	j->jail = xstrdup(rq->jail);
	j->pkg.jail = j->jail;
	j->pkg.dry_run = rq->dry_run;
	if (rq->names.n > 0) {
		if ((v = calloc(rq->names.n, sizeof(*v))) == NULL)
			err(1, "calloc");
		for (i = 0; i < rq->names.n; i++)
			v[i] = xstrdup(rq->names.v[i]);
		j->pkg.names.v = v;
		j->pkg.names.n = rq->names.n;
	}
	return (start(j));
}

/* Is the spec complete and are its names fit?  NULL, or what is wrong. */
static const char *
check_spec(const struct arc_job_spec *sp)
{
	size_t	i;

	if (!sp->has_kind || sp->kind > ARC_JOB_KIND_PKG_UPGRADE)
		return ("a job needs a kind");
	switch (sp->kind) {
	case ARC_JOB_KIND_JAIL_ACTION:
		if (sp->jail == NULL || !valid_jail(sp->jail))
			return ("invalid jail name");
		if (!sp->has_action || sp->action >= nitems(action_names))
			return ("invalid action");
		break;
	case ARC_JOB_KIND_ADDRESS:
		if (sp->jail == NULL || !valid_jail(sp->jail))
			return ("invalid jail name");
		if (sp->address == NULL || strlen(sp->address) < 2 ||
		    strchr(sp->address, '|') != NULL)
			return ("invalid address");
		if (sp->interface != NULL && !valid_ifname(sp->interface))
			return ("invalid interface name");
		if (!sp->live && !sp->persist)
			return ("say live, persist or both");
		break;
	case ARC_JOB_KIND_SERVICE_ACTION:
		if (sp->service == NULL || !valid_service(sp->service))
			return ("invalid service name");
		if (!sp->has_service_action ||
		    sp->service_action >= nitems(service_action_names))
			return ("invalid action");
		break;
	case ARC_JOB_KIND_SERVICE_CONFIG:
		if (sp->service == NULL || !valid_service(sp->service))
			return ("invalid service name");
		if (sp->variables.n == 0)
			return ("nothing to set");
		for (i = 0; i < sp->variables.n; i++)
			if (sp->variables.v[i].key == NULL)
				return ("a variable without a key");
		break;
	default:
		if (sp->jail != NULL && !valid_jail(sp->jail))
			return ("invalid jail name");
		for (i = 0; i < sp->names.n; i++)
			if (sp->names.v[i] == NULL)
				return ("a package without a name");
		break;
	}
	return (NULL);
}

/* Jobs are queued, listed and read on the loop: none of it waits. */
int
arc_job_submit_doit(cbl_req *req, const struct arc_job_submit_req *rq,
    void *arg __unused)
{
	struct arc_job_submit_rsp	 rsp;
	struct work			 w;
	const char			*e;
	char				*peer;
	size_t				 i;
	int				 error;

	for (i = 0; i < rq->batch.n; i++)
		if ((e = check_spec(&rq->batch.v[i])) != NULL)
			return (reject(req, e));
	work_init(&w);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	peer = peer_name(req);
	jobs_submit(rq->batch.v, rq->batch.n, peer, &w, &rsp.jobs.v,
	    &rsp.jobs.n);
	free(peer);
	error = arc_job_submit_reply(req, &rsp);
	work_free(&w);
	return (error);
}

int
arc_jobs_doit(cbl_req *req, void *arg __unused)
{
	struct arc_jobs_rsp	rsp;
	struct work		w;
	int			error;

	work_init(&w);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	jobs_list(&w, &rsp.jobs.v, &rsp.jobs.n);
	error = arc_jobs_reply(req, &rsp);
	work_free(&w);
	return (error);
}

int
arc_job_doit(cbl_req *req, const struct arc_job_req *rq, void *arg __unused)
{
	struct arc_job_rsp	rsp;
	struct work		w;
	int			error;

	work_init(&w);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.job = jobs_get(&w, rq->id);
	rsp.ok = rsp.job != NULL;
	if (!rsp.ok)
		rsp.error = "no such job; the daemon keeps the last finished "
		    "ones and forgets all when it restarts";
	error = arc_job_reply(req, &rsp);
	work_free(&w);
	return (error);
}

int
arc_job_cancel_doit(cbl_req *req, const struct arc_job_cancel_req *rq,
    void *arg __unused)
{
	struct arc_job_cancel_rsp	rsp;
	struct work			w;
	int				error;

	work_init(&w);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.job = jobs_cancel(&w, rq->id, &rsp.error);
	rsp.ok = rsp.job != NULL;
	if (rsp.ok)
		rsp.error = NULL;
	error = arc_job_cancel_reply(req, &rsp);
	work_free(&w);
	return (error);
}
