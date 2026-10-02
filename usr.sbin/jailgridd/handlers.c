/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cblink handlers for the jailgrid family.  Requests are checked here,
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
#include <syslog.h>

#include "jailgridd.h"

struct job {
	cbl_req			*req;
	uint16_t		 cmd;
	bool			 config_only;
	char			*jail;
	uint8_t			 action;
	struct jg_address_req	 addr;
	struct jg_service_config_req svc;
	uint8_t			 family;
	char			*peer;
};

static pthread_mutex_t	change_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *action_names[] = {
	[JG_ACTION_START] = "start",
	[JG_ACTION_STOP] = "stop",
	[JG_ACTION_RESTART] = "restart",
	[JG_ACTION_KILL] = "kill",
};

static const char *net_kind_names[] = {
	[JG_NET_KIND_ROUTES] = "routes",
	[JG_NET_KIND_NEXTHOPS] = "nexthops",
	[JG_NET_KIND_CONNECTIONS] = "connections",
	[JG_NET_KIND_SOCKETS] = "sockets",
};

static const char *service_action_names[] = {
	[JG_SERVICE_ACTION_START] = "start",
	[JG_SERVICE_ACTION_STOP] = "stop",
	[JG_SERVICE_ACTION_RESTART] = "restart",
	[JG_SERVICE_ACTION_RELOAD] = "reload",
	[JG_SERVICE_ACTION_ENABLE] = "enable",
	[JG_SERVICE_ACTION_DISABLE] = "disable",
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

static void *
worker(void *arg)
{
	struct job		*j;
	struct work		 w;
	struct jg_list_rsp	 lr;
	struct jg_action_rsp	 ar;
	struct jg_address_rsp	 dr;
	struct jg_services_rsp	 sr;
	struct jg_service_action_rsp sar;
	struct jg_service_config_rsp scr;
	struct jg_network_rsp	 nr;
	struct jg_stats_rsp	 str;
	const char		*what, *error;
	bool			 ok;
	int			 root, rc;

	j = arg;
	work_init(&w);
	switch (j->cmd) {
	case JG_CMD_LIST:
		what = j->config_only ? "list (configuration only)" : "list";
		root = step_begin(&w, JG_STEP_KIND_DAEMON, "jailgridd", "%s",
		    what);
		memset(&lr, 0, sizeof(lr));
		do_list(&w, j->config_only, &lr);
		ok = lr.ok;
		error = lr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &lr.trace.v, &lr.trace.n);
		rc = jg_list_reply(j->req, &lr);
		break;
	case JG_CMD_ACTION:
		what = wfmt(&w, "%s %s", action_names[j->action], j->jail);
		root = step_begin(&w, JG_STEP_KIND_DAEMON, "jailgridd", "%s",
		    what);
		memset(&ar, 0, sizeof(ar));
		pthread_mutex_lock(&change_lock);
		do_action(&w, j->jail, j->action, &ar);
		pthread_mutex_unlock(&change_lock);
		ok = ar.ok;
		error = ar.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &ar.trace.v, &ar.trace.n);
		rc = jg_action_reply(j->req, &ar);
		break;
	case JG_CMD_STATS:
		what = "stats";
		root = step_begin(&w, JG_STEP_KIND_DAEMON, "jailgridd", "stats");
		memset(&str, 0, sizeof(str));
		do_stats(&w, &str);
		ok = str.ok;
		error = str.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &str.trace.v, &str.trace.n);
		rc = jg_stats_reply(j->req, &str);
		break;
	case JG_CMD_NETWORK:
		what = wfmt(&w, "network %s%s", net_kind_names[j->action],
		    j->family == JG_NET_FAMILY_INET ? " inet" :
		    j->family == JG_NET_FAMILY_INET6 ? " inet6" : "");
		root = step_begin(&w, JG_STEP_KIND_DAEMON, "jailgridd", "%s",
		    what);
		memset(&nr, 0, sizeof(nr));
		do_network(&w, j->action, j->family, &nr);
		ok = nr.ok;
		error = nr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &nr.trace.v, &nr.trace.n);
		rc = jg_network_reply(j->req, &nr);
		break;
	case JG_CMD_SERVICES:
		root = step_begin(&w, JG_STEP_KIND_DAEMON, "jailgridd",
		    "services");
		what = "services";
		memset(&sr, 0, sizeof(sr));
		do_services(&w, &sr);
		ok = sr.ok;
		error = sr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sr.trace.v, &sr.trace.n);
		rc = jg_services_reply(j->req, &sr);
		break;
	case JG_CMD_SERVICE_ACTION:
		what = wfmt(&w, "service %s %s", j->jail,
		    service_action_names[j->action]);
		root = step_begin(&w, JG_STEP_KIND_DAEMON, "jailgridd", "%s",
		    what);
		memset(&sar, 0, sizeof(sar));
		pthread_mutex_lock(&change_lock);
		do_service_action(&w, j->jail, j->action, &sar);
		pthread_mutex_unlock(&change_lock);
		ok = sar.ok;
		error = sar.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sar.trace.v, &sar.trace.n);
		rc = jg_service_action_reply(j->req, &sar);
		break;
	case JG_CMD_SERVICE_CONFIG:
		what = wfmt(&w, "service %s config%s", j->jail,
		    j->svc.variables.n > 0 ? " (set)" : "");
		root = step_begin(&w, JG_STEP_KIND_DAEMON, "jailgridd", "%s",
		    what);
		memset(&scr, 0, sizeof(scr));
		pthread_mutex_lock(&change_lock);
		do_service_config(&w, &j->svc, &scr);
		pthread_mutex_unlock(&change_lock);
		ok = scr.ok;
		error = scr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &scr.trace.v, &scr.trace.n);
		rc = jg_service_config_reply(j->req, &scr);
		break;
	default:
		what = wfmt(&w, "address %s %s %s%s%s%s", j->addr.jail,
		    j->addr.remove ? "remove" : "add", j->addr.address,
		    j->addr.live ? " live" : "",
		    j->addr.persist ? " persist" : "",
		    j->addr.dry_run ? " dry-run" : "");
		root = step_begin(&w, JG_STEP_KIND_DAEMON, "jailgridd", "%s",
		    what);
		memset(&dr, 0, sizeof(dr));
		pthread_mutex_lock(&change_lock);
		do_address(&w, &j->addr, &dr);
		pthread_mutex_unlock(&change_lock);
		ok = dr.ok;
		error = dr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &dr.trace.v, &dr.trace.n);
		rc = jg_address_reply(j->req, &dr);
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
	free(j->jail);
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
jg_hello_doit(cbl_req *req, void *arg __unused)
{
	struct jg_hello_rsp	rsp;
	struct jg_host		host;
	struct work		w;
	int			error;

	work_init(&w);
	host_info(&w, &host);
	memset(&rsp, 0, sizeof(rsp));
	rsp.host = &host;
	error = jg_hello_reply(req, &rsp);
	work_free(&w);
	return (error);
}

int
jg_list_doit(cbl_req *req, const struct jg_list_req *rq, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = JG_CMD_LIST;
	j->config_only = rq->config_only;
	return (start(j));
}

int
jg_action_doit(cbl_req *req, const struct jg_action_req *rq,
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
	j->cmd = JG_CMD_ACTION;
	j->jail = xstrdup(rq->jail);
	j->action = rq->action;
	return (start(j));
}

int
jg_address_doit(cbl_req *req, const struct jg_address_req *rq,
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
	j->cmd = JG_CMD_ADDRESS;
	j->addr = *rq;
	j->addr.jail = xstrdup(rq->jail);
	j->addr.address = xstrdup(rq->address);
	j->addr.interface = xstrdup(rq->interface);
	return (start(j));
}

int
jg_services_doit(cbl_req *req, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = JG_CMD_SERVICES;
	return (start(j));
}

int
jg_service_action_doit(cbl_req *req, const struct jg_service_action_req *rq,
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
	j->cmd = JG_CMD_SERVICE_ACTION;
	j->jail = xstrdup(rq->service);
	j->action = rq->service_action;
	return (start(j));
}

int
jg_service_config_doit(cbl_req *req, const struct jg_service_config_req *rq,
    void *arg __unused)
{
	struct jg_variable	*v;
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
	j->cmd = JG_CMD_SERVICE_CONFIG;
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
jg_network_doit(cbl_req *req, const struct jg_network_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->net_kind >= nitems(net_kind_names))
		return (reject(req, "invalid kind"));
	if (rq->has_net_family && rq->net_family > JG_NET_FAMILY_INET6)
		return (reject(req, "invalid family"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = JG_CMD_NETWORK;
	j->action = rq->net_kind;
	j->family = rq->has_net_family ? rq->net_family : JG_NET_FAMILY_ALL;
	return (start(j));
}

int
jg_stats_doit(cbl_req *req, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = JG_CMD_STATS;
	return (start(j));
}
