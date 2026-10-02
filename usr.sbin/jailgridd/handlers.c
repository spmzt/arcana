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
	char			*peer;
};

static pthread_mutex_t	change_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *action_names[] = {
	[JG_ACTION_START] = "start",
	[JG_ACTION_STOP] = "stop",
	[JG_ACTION_RESTART] = "restart",
	[JG_ACTION_KILL] = "kill",
};

static bool	valid_jail(const char *);
static bool	valid_ifname(const char *);
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
