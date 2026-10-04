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
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
	uint32_t		 fib;
	struct arc_pkg_upgrade_req pkg;
	bool			 refresh;
	uint8_t			*binary;	/* agent-update */
	size_t			 binlen;
	char			*sha256;
	bool			 restart;
	char			*source;	/* agent-build */
	char			*ref;
	char			*host_keys;
	char			*ssh_key;
	char			*peer;
};

#define	STOPPING	"not done: arcana-agent is stopping"
#define	RESTART_WAIT	10	/* s, for service(8) to stop the daemon */
#define	JOBS_WAITING_MAX 256	/* jobs queued or running, at most */

pthread_mutex_t	change_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t build_lock = PTHREAD_MUTEX_INITIALIZER;

/* What holds change_lock now, for the log when asked to stop. */
static pthread_mutex_t	note_lock = PTHREAD_MUTEX_INITIALIZER;
static char		note[256];
static time_t		note_since;
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
	[ARC_NET_KIND_INTERFACES] = "interfaces",
	[ARC_NET_KIND_NETGRAPH] = "netgraph",
	[ARC_NET_KIND_WIREGUARD] = "wireguard",
	[ARC_NET_KIND_BIRD] = "bird",
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
static const char *cuts_off(cbl_req *, const struct arc_job_spec *);

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
		note_since = time(NULL);
	}
	pthread_mutex_unlock(&note_lock);
	return (go);
}

/* The daemon is about to stop: no change starts while that holds. */
void
changes_stop(bool on)
{

	pthread_mutex_lock(&note_lock);
	stopping = on;
	pthread_mutex_unlock(&note_lock);
}

bool
changes_stopping(void)
{
	bool	on;

	pthread_mutex_lock(&note_lock);
	on = stopping;
	pthread_mutex_unlock(&note_lock);
	return (on);
}

/*
 * What holds the change lock now and since when, for those who ask for
 * the jobs; NULL when nothing does.  A job says so itself in the list.
 */
const char *
changes_current(struct work *w, time_t *sincep)
{
	const char	*s;

	pthread_mutex_lock(&note_lock);
	s = note[0] != '\0' && strncmp(note, "job ", 4) != 0 ? wstrdup(w,
	    note) : NULL;
	*sincep = note_since;
	pthread_mutex_unlock(&note_lock);
	return (s);
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
	struct arc_route_lookup_rsp rlr;
	struct arc_bird_config_req bcq;
	struct arc_bird_config_rsp bcr;
	struct arc_stats_rsp	 str;
	struct arc_packages_rsp	 pr;
	struct arc_pkg_upgrade_rsp ur;
	struct arc_agent_update_rsp aur;
	struct arc_agent_build_rsp abr;
	struct arc_console_update_rsp cur;
	const char		*what, *error;
	bool			 console;
	bool			 restart;
	bool			 ok;
	int			 root, rc;

	j = arg;
	work_init(&w);
	restart = console = false;
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
		do_network(&w, j->action, j->family, j->source, j->fib, &nr);
		ok = nr.ok;
		error = nr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &nr.trace.v, &nr.trace.n);
		rc = arc_network_reply(j->req, &nr);
		break;
	case ARC_CMD_ROUTE_LOOKUP:
		what = wfmt(&w, "route to %s", j->source);
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&rlr, 0, sizeof(rlr));
		do_route_lookup(&w, j->source, j->fib, &rlr);
		ok = rlr.ok;
		error = rlr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &rlr.trace.v, &rlr.trace.n);
		rc = arc_route_lookup_reply(j->req, &rlr);
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
	case ARC_CMD_CONSOLE_UPDATE:
		what = wfmt(&w, "console update from %s%s%s", j->source,
		    j->ref != NULL ? " at " : "", j->ref != NULL ? j->ref : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&cur, 0, sizeof(cur));
		pthread_mutex_lock(&build_lock);
		do_console_update(&w, j->source, j->ref, j->host_keys,
		    j->ssh_key, &cur);
		pthread_mutex_unlock(&build_lock);
		ok = cur.ok;
		error = cur.error;
		console = ok;
		cur.restarting = console;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &cur.trace.v, &cur.trace.n);
		rc = arc_console_update_reply(j->req, &cur);
		break;
	case ARC_CMD_AGENT_BUILD:
		what = wfmt(&w, "agent build from %s%s%s", j->source,
		    j->ref != NULL ? " at " : "", j->ref != NULL ? j->ref : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&abr, 0, sizeof(abr));
		/* One build at a time: they share the directory. */
		pthread_mutex_lock(&build_lock);
		do_agent_build(&w, j->source, j->ref, j->host_keys,
		    j->ssh_key, &abr);
		pthread_mutex_unlock(&build_lock);
		ok = abr.ok;
		error = abr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &abr.trace.v, &abr.trace.n);
		rc = arc_agent_build_reply(j->req, &abr);
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
	case ARC_CMD_BIRD_CONFIG:
		/* The path rides in source, the text in ref. */
		what = wfmt(&w, "bird config %s%s", j->ref == NULL ? "read" :
		    j->refresh ? "check" : "write", j->source != NULL ? " " :
		    "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s%s",
		    what, j->source != NULL ? j->source : "");
		memset(&bcq, 0, sizeof(bcq));
		memset(&bcr, 0, sizeof(bcr));
		bcq.conf_path = j->source;
		bcq.conf_text = j->ref;
		bcq.sha256 = j->sha256;
		bcq.dry_run = j->refresh;
		if (j->ref == NULL)
			do_bird_config(&w, &bcq, &bcr);
		else {
			pthread_mutex_lock(&change_lock);
			if (change_note("%s", what))
				do_bird_config(&w, &bcq, &bcr);
			else {
				bcr.has_ok = true;
				bcr.error = STOPPING;
			}
			(void)change_note(NULL);
			pthread_mutex_unlock(&change_lock);
		}
		ok = bcr.ok;
		error = bcr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &bcr.trace.v, &bcr.trace.n);
		rc = arc_bird_config_reply(j->req, &bcr);
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
	/* The console's own service, once it has its answer. */
	if (console)
		service_restart("arcana_console");
	if (restart) {
		/*
		 * No change starts while the service is on its way to stop
		 * this daemon, and nothing is held that would keep it from
		 * stopping.  Still here after a while, the service did not
		 * stop it: say so, and take changes again.
		 */
		changes_stop(true);
		service_restart("arcana_agent");
		sleep(RESTART_WAIT);
		changes_stop(false);
		logmsg(LOG_ERR, "restart: still running %d s after an update: "
		    "\"service arcana_agent restart\" did not stop this "
		    "daemon; is the service enabled, and is it what runs it? "
		    "The new program is in place and runs from the next "
		    "start", RESTART_WAIT);
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
	free(j->source);
	free(j->ref);
	free(j->host_keys);
	free(j->ssh_key);
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
arc_agent_build_doit(cbl_req *req, const struct arc_agent_build_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_AGENT_BUILD;
	j->source = xstrdup(rq->source);
	j->ref = rq->ref != NULL && rq->ref[0] != '\0' ? xstrdup(rq->ref) :
	    NULL;
	j->host_keys = rq->host_keys != NULL ? xstrdup(rq->host_keys) : NULL;
	j->ssh_key = rq->ssh_key != NULL ? xstrdup(rq->ssh_key) : NULL;
	return (start(j));
}

int
arc_console_update_doit(cbl_req *req, const struct arc_console_update_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_CONSOLE_UPDATE;
	j->source = xstrdup(rq->source);
	j->ref = rq->ref != NULL && rq->ref[0] != '\0' ? xstrdup(rq->ref) :
	    NULL;
	j->host_keys = rq->host_keys != NULL ? xstrdup(rq->host_keys) : NULL;
	j->ssh_key = rq->ssh_key != NULL ? xstrdup(rq->ssh_key) : NULL;
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
	/* The text to search for rides where a build's source does. */
	j->source = rq->net_filter != NULL && rq->net_filter[0] != '\0' ?
	    xstrdup(rq->net_filter) : NULL;
	j->action = rq->net_kind;
	j->family = rq->has_net_family ? rq->net_family : ARC_NET_FAMILY_ALL;
	j->fib = rq->has_net_fib ? rq->net_fib : 0;
	return (start(j));
}

int
arc_route_lookup_doit(cbl_req *req, const struct arc_route_lookup_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->lookup == NULL || rq->lookup[0] == '-')
		return (reject(req, "an address to look up is needed"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_ROUTE_LOOKUP;
	j->source = xstrdup(rq->lookup);
	j->fib = rq->has_net_fib ? rq->net_fib : 0;
	return (start(j));
}

int
arc_bird_config_doit(cbl_req *req, const struct arc_bird_config_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->conf_path != NULL && rq->conf_path[0] != '\0' &&
	    rq->conf_path[0] != '/')
		return (reject(req, "a configuration file is named by its "
		    "whole path"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_BIRD_CONFIG;
	j->source = rq->conf_path != NULL && rq->conf_path[0] != '\0' ?
	    xstrdup(rq->conf_path) : NULL;
	j->ref = rq->conf_text != NULL ? xstrdup(rq->conf_text) : NULL;
	j->sha256 = rq->sha256 != NULL ? xstrdup(rq->sha256) : NULL;
	j->refresh = rq->dry_run;
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
	struct work	 cw;
	const char	*e;
	size_t		 i;

	if (!sp->has_kind || sp->kind > ARC_JOB_KIND_BIRD)
		return ("a job needs a kind");
	switch (sp->kind) {
	case ARC_JOB_KIND_JAIL_ACTION:
		if (sp->jail == NULL || !valid_jail(sp->jail))
			return ("invalid jail name");
		if (!sp->has_action || sp->action >= nitems(action_names))
			return ("invalid action");
		if (sp->safe)
			return ("what a jail was doing cannot be put back: not "
			    "in safe mode");
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
	case ARC_JOB_KIND_IF_ADDRESS:
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		if (sp->address == NULL || strlen(sp->address) < 2)
			return ("invalid address");
		break;
	case ARC_JOB_KIND_IF_STATE:
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		if (!sp->has_up)
			return ("say up or down");
		break;
	case ARC_JOB_KIND_IF_SET:
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		if ((!sp->has_mtu || sp->mtu == 0) && sp->description == NULL)
			return ("say what to set: mtu, description or both");
		break;
	case ARC_JOB_KIND_IF_CREATE:
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		if (sp->parent != NULL && !valid_ifname(sp->parent))
			return ("invalid interface name");
		break;
	case ARC_JOB_KIND_IF_DESTROY:
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		if (sp->safe)
			return ("an interface destroyed cannot be made again "
			    "as it was: not in safe mode");
		break;
	case ARC_JOB_KIND_NETGRAPH:
		if (sp->safe)
			return ("netgraph changes cannot be undone: not in "
			    "safe mode");
		return (ng_check(sp->verb, sp->names.v, sp->names.n));
	case ARC_JOB_KIND_WIREGUARD:
		if (sp->safe)
			return ("wireguard changes are not undone: not in "
			    "safe mode");
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		work_init(&cw);
		e = wg_check(&cw, sp);
		work_free(&cw);
		return (e);
	case ARC_JOB_KIND_BIRD:
		if (sp->safe)
			return ("what BIRD was told is not taken back: not in "
			    "safe mode");
		return (bird_check(sp->verb, sp->names.v, sp->names.n));
	case ARC_JOB_KIND_ROUTE:
		if (sp->destination == NULL || sp->destination[0] == '\0' ||
		    sp->destination[0] == '-')
			return ("a route needs a destination");
		if (sp->safe && sp->remove && (sp->gateway == NULL ||
		    sp->gateway[0] == '\0'))
			return ("to delete a route safely, name its gateway: "
			    "it is what puts the route back");
		if (sp->gateway != NULL && sp->gateway[0] == '-')
			return ("invalid gateway");
		if (!sp->remove && (sp->gateway == NULL ||
		    sp->gateway[0] == '\0'))
			return ("a route to add needs a gateway");
		break;
	case ARC_JOB_KIND_SERVICE_ACTION:
		if (sp->service == NULL || !valid_service(sp->service))
			return ("invalid service name");
		if (!sp->has_service_action ||
		    sp->service_action >= nitems(service_action_names))
			return ("invalid action");
		if (sp->safe && (sp->service_action ==
		    ARC_SERVICE_ACTION_RESTART || sp->service_action ==
		    ARC_SERVICE_ACTION_RELOAD))
			return ("a restart or a reload cannot be undone: not "
			    "in safe mode");
		break;
	case ARC_JOB_KIND_SERVICE_CONFIG:
		if (sp->service == NULL || !valid_service(sp->service))
			return ("invalid service name");
		if (sp->variables.n == 0)
			return ("nothing to set");
		for (i = 0; i < sp->variables.n; i++) {
			if (!rc_name_ok(sp->variables.v[i].key))
				return ("a variable's name is letters, digits "
				    "and _");
			if (!rc_value_ok(sp->variables.v[i].value))
				return ("a variable's value has a quote, $, ` "
				    "or \\: rc.conf would read it as more");
		}
		break;
	default:
		if (sp->jail != NULL && !valid_jail(sp->jail))
			return ("invalid jail name");
		for (i = 0; i < sp->names.n; i++)
			if (sp->names.v[i] == NULL)
				return ("a package without a name");
		if (sp->safe)
			return ("an upgrade cannot be undone: not in safe mode");
		break;
	}
	return (NULL);
}

/*
 * Would the change take away the address this request came in by?  It
 * would cut off the one who asks, who could then not take it back: it
 * is done only in safe mode, where the host takes it back itself.
 */
static const char *
cuts_off(cbl_req *req, const struct arc_job_spec *sp)
{
	struct sockaddr_storage	 ss;
	socklen_t		 len;
	unsigned char		 raw[16], *mine;
	char			 ifname[IF_NAMESIZE], addr[65];
	bool			 hit;
	int			 fd;

	if (sp->safe || (sp->kind != ARC_JOB_KIND_IF_ADDRESS &&
	    sp->kind != ARC_JOB_KIND_IF_STATE && sp->kind !=
	    ARC_JOB_KIND_IF_DESTROY))
		return (NULL);
	len = sizeof(ss);
	if ((fd = cbl_conn_fd(cbl_req_conn(req))) == -1 || getsockname(fd,
	    (struct sockaddr *)&ss, &len) == -1 || (ss.ss_family != AF_INET &&
	    ss.ss_family != AF_INET6) || !if_owning((struct sockaddr *)&ss,
	    ifname, sizeof(ifname)))
		return (NULL);
	hit = false;
	if (sp->kind == ARC_JOB_KIND_IF_ADDRESS) {
		if (!sp->remove || strcmp(sp->interface, ifname) != 0)
			return (NULL);
		strlcpy(addr, sp->address, sizeof(addr));
		addr[strcspn(addr, "/")] = '\0';
		if (ss.ss_family == AF_INET) {
			mine = (unsigned char *)&((struct sockaddr_in *)&ss)->
			    sin_addr;
			hit = inet_pton(AF_INET, addr, raw) == 1 &&
			    memcmp(raw, mine, 4) == 0;
		} else {
			mine = (unsigned char *)&((struct sockaddr_in6 *)&ss)->
			    sin6_addr;
			hit = (inet_pton(AF_INET6, addr, raw) == 1 &&
			    memcmp(raw, mine, 16) == 0) ||
			    (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)
			    (void *)mine) && inet_pton(AF_INET, addr, raw) ==
			    1 && memcmp(raw, mine + 12, 4) == 0);
		}
	} else
		hit = strcmp(sp->interface, ifname) == 0 &&
		    (sp->kind == ARC_JOB_KIND_IF_DESTROY || !sp->up);
	return (hit ? "this request came in by that address: the change "
	    "would cut you off.  Ask for it in safe mode, and the host takes "
	    "it back when it does not hear from you again" : NULL);
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
		if ((e = check_spec(&rq->batch.v[i])) != NULL ||
		    (e = cuts_off(req, &rq->batch.v[i])) != NULL)
			return (reject(req, e));
	if (jobs_waiting() + rq->batch.n > JOBS_WAITING_MAX)
		return (reject(req, "too many jobs wait already: let some "
		    "finish, or cancel them"));
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
	time_t			since;
	int			error;

	work_init(&w);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	jobs_list(&w, &rsp.jobs.v, &rsp.jobs.n);
	if ((rsp.activity = changes_current(&w, &since)) != NULL) {
		rsp.has_since = true;
		rsp.since = since;
	}
	rsp.stopping = changes_stopping();
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
arc_job_confirm_doit(cbl_req *req, const struct arc_job_confirm_req *rq,
    void *arg __unused)
{
	struct arc_job_confirm_rsp	rsp;
	struct work			w;
	int				error;

	work_init(&w);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.job = jobs_confirm(&w, rq->id, &rsp.error);
	rsp.ok = rsp.job != NULL;
	if (rsp.ok)
		rsp.error = NULL;
	error = arc_job_confirm_reply(req, &rsp);
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
