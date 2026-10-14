/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: the jobs as arcana-jobs has them (PLAN-SDN-YANG 3.1.4): the
 * queue the jobs operation lists (jobs_list()) and one job with its trace
 * (jobs_get()), the trace a flat list of steps each naming its parent;
 * and a submit's changes made the job-specs jobs_submit() queues
 * (yjobs_spec(), made from jobs.yaml).  cancel and confirm are
 * jobs_cancel() and jobs_confirm() as they are.
 */

#include <errno.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"

typedef struct arcana_jobs_jobs_job yjob;
typedef struct arcana_jobs_jobs_job_step ystep;

static int
job_of(yjob *y, const struct arc_job *j, cbl_yarena *a)
{
	ystep *s = NULL;

	memset(y, 0, sizeof(*y));
	y->id = j->id;
	/* job-kind's, job-state's values are the operation's. */
	if ((y->has_kind = j->has_kind))
		y->kind = (enum arcana_jobs_jobs_job_kind)j->kind;
	y->title = j->title;
	if ((y->has_state = j->has_state))
		y->state = (enum arcana_jobs_jobs_job_state)j->state;
	if ((y->has_ok = j->has_ok))
		y->ok = j->ok;
	y->error = j->error;
	if ((y->has_created = j->has_created))
		y->created = j->created;
	if ((y->has_started = j->has_started))
		y->started = j->started;
	if ((y->has_finished = j->has_finished))
		y->finished = j->finished;
	y->peer = j->peer;
	if ((y->has_confirm_by = j->has_confirm_by))
		y->confirm_by = j->confirm_by;
	if (j->trace.n > 0 && (s = cbl_yarena_alloc(a, j->trace.n *
	    sizeof(*s))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < j->trace.n; i++) {
		const struct arc_step *t = &j->trace.v[i];

		memset(&s[i], 0, sizeof(s[i]));
		/* A step without its number is numbered by its place. */
		s[i].id = t->has_id ? t->id : (uint32_t)i;
		if ((s[i].has_parent = t->has_parent))
			s[i].parent = t->parent;
		if ((s[i].has_kind = t->has_kind))
			s[i].kind = (enum arcana_jobs_jobs_job_step_kind)t->kind;
		s[i].label = t->label;
		s[i].detail = t->detail;
		if ((s[i].has_status = t->has_status))
			s[i].status =
			    (enum arcana_jobs_jobs_job_step_status)t->status;
		if ((s[i].has_duration = t->has_duration_us))
			s[i].duration = t->duration_us;
		s[i].argv.n = t->argv.n;
		s[i].argv.v = t->argv.v;
		if ((s[i].has_exit = t->has_exit))
			s[i].exit = t->exit;
		s[i].output = t->output;
		s[i].error_output = t->error_output;
	}
	y->step.n = j->trace.n;
	y->step.v = s;
	return (0);
}

/*
 * The jobs v (jobs_list()'s, or one jobs_get() gave with its trace) as
 * the module's, with what the agent does now that is no job (activity,
 * since: 0 none) and whether it stops.  Strings the jobs'.
 */
int
yjobs_from(const struct arc_job *v, size_t n, const char *activity,
    int64_t since, bool stopping, cbl_yarena *a, struct arcana_jobs *out)
{
	struct arcana_jobs_jobs *js;
	yjob *y = NULL;
	int error;

	memset(out, 0, sizeof(*out));
	if ((js = cbl_yarena_alloc(a, sizeof(*js))) == NULL ||
	    (n > 0 && (y = cbl_yarena_alloc(a, n * sizeof(*y))) == NULL))
		return (ENOMEM);
	memset(js, 0, sizeof(*js));
	js->activity = activity;
	if ((js->has_since = since != 0))
		js->since = since;
	js->has_stopping = true;
	js->stopping = stopping;
	for (size_t i = 0; i < n; i++)
		if ((error = job_of(&y[i], &v[i], a)) != 0)
			return (error);
	js->job.n = n;
	js->job.v = y;
	out->jobs = js;
	return (0);
}

/*
 * A submit's changes made the job-specs jobs_submit() takes, in the
 * order given, a's.  EINVAL, *bad the change's place: one of no kind.
 */
int
yjobs_specs(const struct arcana_jobs_submit_input *in, cbl_yarena *a,
    const struct arc_job_spec **out, size_t *n, size_t *bad)
{
	struct arc_job_spec *v;
	int error;

	*out = NULL;
	*n = 0;
	if (in->change.n == 0)
		return (EINVAL);
	if ((v = cbl_yarena_alloc(a, in->change.n * sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < in->change.n; i++)
		if ((error = yjobs_spec(&in->change.v[i], a, &v[i])) != 0) {
			*bad = i;
			return (error);
		}
	*out = v;
	*n = in->change.n;
	return (0);
}
