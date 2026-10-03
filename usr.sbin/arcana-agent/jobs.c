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

#include <sys/types.h>
#include <sys/queue.h>

#include <err.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "agent.h"

#define	JOBS_KEPT	64	/* finished jobs remembered */

struct qjob {
	uint64_t		 id;
	uint8_t			 state;		/* ARC_JOB_STATE_* */
	bool			 ok;
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
static uint64_t		nextid = 1;

static char	*xdup(const char *);
static char	*title_of(const struct arc_job_spec *);
static void	 spec_copy(struct arc_job_spec *, const struct arc_job_spec *);
static void	 job_free(struct qjob *);
static void	 trim(void);
static void	 run(struct qjob *);
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

/* What the job does, in words: the activity log's line for it. */
static char *
title_of(const struct arc_job_spec *sp)
{
	char	*t;
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
	default:
		rc = asprintf(&t, "pkg upgrade%s%s%s", sp->jail != NULL ?
		    " in " : "", sp->jail != NULL ? sp->jail : "",
		    sp->names.n > 0 ? " of some" : "");
		break;
	}
	if (rc == -1)
		err(1, "asprintf");
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

/* Do what the job says; its outcome goes into the job. */
static void
run(struct qjob *j)
{
	struct arc_action_rsp		 ar;
	struct arc_address_req		 dq;
	struct arc_address_rsp		 dr;
	struct arc_service_action_rsp	 sar;
	struct arc_service_config_req	 scq;
	struct arc_service_config_rsp	 scr;
	struct arc_pkg_upgrade_req	 uq;
	struct arc_pkg_upgrade_rsp	 ur;
	const struct arc_job_spec	*sp;
	const char			*error;
	bool				 ok;
	int				 root;

	sp = &j->spec;
	root = step_begin(&j->w, ARC_STEP_KIND_DAEMON, "arcana-agent", "job %ju: %s",
	    (uintmax_t)j->id, j->title);
	pthread_mutex_lock(&change_lock);
	switch (sp->kind) {
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
		do_pkg_upgrade(&j->w, &uq, &ur);
		ok = ur.ok;
		error = ur.error;
		break;
	}
	pthread_mutex_unlock(&change_lock);
	step_end(&j->w, root, ok, NULL);

	pthread_mutex_lock(&jobs_lock);
	j->ok = ok;
	j->error = error;
	j->finished = time(NULL);
	j->state = ARC_JOB_STATE_DONE;
	trim();
	pthread_mutex_unlock(&jobs_lock);
	logmsg(ok ? LOG_INFO : LOG_NOTICE, "%s: job %ju: %s: %s", j->peer,
	    (uintmax_t)j->id, j->title, ok ? "ok" : error != NULL ? error :
	    "failed");
}

static void *
runner(void *arg __unused)
{
	struct qjob	*j;

	for (;;) {
		pthread_mutex_lock(&jobs_lock);
		for (;;) {
			TAILQ_FOREACH(j, &jobs, link)
				if (j->state == ARC_JOB_STATE_QUEUED)
					break;
			if (j != NULL)
				break;
			pthread_cond_wait(&jobs_cv, &jobs_lock);
		}
		j->state = ARC_JOB_STATE_RUNNING;
		j->started = time(NULL);
		pthread_mutex_unlock(&jobs_lock);
		run(j);
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

/* Take a queued job out of the queue; NULL and *errp if that cannot be. */
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
