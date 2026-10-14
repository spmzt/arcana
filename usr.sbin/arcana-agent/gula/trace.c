/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: what a request did, step by step, with what each program it ran
 * printed.  Every reply carries it; a job's is read while the job runs;
 * a peer that subscribed to steps is told each step of its own requests
 * as it begins and as it ends, on its connection.
 */

#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vis.h>
#include <wchar.h>

#include "agent.h"

static cbl_family	*tell_family;

static void	tell(struct work *, int);

uint64_t
now_us(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000);
}

/*
 * Start a step as a child of the innermost open one.  Returns its index,
 * or -1 when the trace is full; the other step functions ignore -1.
 */
int
step_begin(struct work *w, uint8_t kind, const char *label,
    const char *fmt, ...)
{
	struct step	*s;
	va_list		 ap;
	char		*d;

	const char	*l, *dt;
	int		 idx;

	if (w->nsteps >= TRACE_MAX)
		return (-1);
	/* Strings first: the pool is this thread's alone. */
	l = wstrdup(w, label);
	dt = NULL;
	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&d, fmt, ap) == -1)
			err(1, "vasprintf");
		va_end(ap);
		dt = wstrdup(w, d);
		free(d);
	}
	pthread_mutex_lock(&w->lock);
	s = &w->steps[w->nsteps];
	memset(s, 0, sizeof(*s));
	s->kind = kind;
	s->label = l;
	s->detail = dt;
	s->parent = w->depth > 0 ? w->stack[w->depth - 1] : -1;
	s->start = now_us();
	s->status = -1;
	if (w->depth < TRACE_DEPTH)
		w->stack[w->depth++] = w->nsteps;
	idx = w->nsteps++;
	pthread_mutex_unlock(&w->lock);
	tell(w, idx);
	return (idx);
}

/* Finish a step; a non-NULL fmt replaces its detail with the outcome. */
void
step_end(struct work *w, int idx, bool ok, const char *fmt, ...)
{
	struct step	*s;
	va_list		 ap;
	char		*d;
	int		 i;

	const char	*dt;

	if (idx < 0 || idx >= w->nsteps)
		return;
	dt = NULL;
	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&d, fmt, ap) == -1)
			err(1, "vasprintf");
		va_end(ap);
		dt = wstrdup(w, d);
		free(d);
	}
	pthread_mutex_lock(&w->lock);
	s = &w->steps[idx];
	s->done = true;
	s->ok = ok;
	s->dur = now_us() - s->start;
	if (dt != NULL)
		s->detail = dt;
	/* Close this step and anything left open inside it. */
	for (i = w->depth; i > 0; i--)
		if (w->stack[i - 1] == idx) {
			w->depth = i - 1;
			break;
		}
	pthread_mutex_unlock(&w->lock);
	tell(w, idx);
}

/* Attach what a program was run with and what it printed. */
void
step_exec(struct work *w, int idx, char *const argv[], int status,
    const char *out, size_t outlen, const char *errout, size_t errlen)
{
	struct step	*s;
	size_t		 n, i;

	const char	**av;

	if (idx < 0 || idx >= w->nsteps)
		return;
	for (n = 0; argv[n] != NULL; n++)
		;
	av = wcalloc(w, n, sizeof(char *));
	for (i = 0; i < n; i++)
		av[i] = wvis(w, argv[i]);
	pthread_mutex_lock(&w->lock);
	s = &w->steps[idx];
	s->argv = av;
	s->argc = n;
	s->status = status;
	s->out = out;
	s->outlen = outlen;
	s->err = errout;
	s->errlen = errlen;
	pthread_mutex_unlock(&w->lock);
}

/*
 * Step s, the trace's i-th, in the shape the family's replies carry it,
 * allocated from dst; with copy, its strings too, as from another work.
 */
static void
step_fill(struct work *dst, const struct step *s, int i, bool copy,
    struct arc_step *v)
{
	const char	**av;
	size_t		 k;

	v->has_id = true;
	v->id = (uint32_t)i;
	v->has_parent = true;
	v->parent = s->parent;
	v->has_kind = true;
	v->kind = s->kind;
	v->label = wtext(dst, copy ? wstrdup(dst, s->label) : s->label);
	v->detail = wtext(dst, copy ? wstrdup(dst, s->detail) : s->detail);
	v->has_status = true;
	v->status = !s->done ? ARC_STEP_STATUS_INCOMPLETE :
	    s->ok ? ARC_STEP_STATUS_OK : ARC_STEP_STATUS_FAILED;
	v->has_duration_us = s->done;
	v->duration_us = s->dur;
	if (s->kind == ARC_STEP_KIND_EXEC && s->argv != NULL) {
		av = s->argv;
		if (copy) {
			av = wcalloc(dst, s->argc + 1, sizeof(*av));
			for (k = 0; k < s->argc; k++)
				av[k] = wstrdup(dst, s->argv[k]);
		}
		v->argv.n = s->argc;
		v->argv.v = av;
		v->has_exit = true;
		v->exit = s->status;
		v->output.p = s->out == NULL ? "" : copy ?
		    wstrndup(dst, s->out, s->outlen) : s->out;
		v->output.len = s->outlen;
		v->error_output.p = s->err == NULL ? "" : copy ?
		    wstrndup(dst, s->err, s->errlen) : s->err;
		v->error_output.len = s->errlen;
	}
}

/* The trace in the shape the family's replies carry it. */
void
trace_steps(struct work *w, const struct arc_step **vp, size_t *np)
{

	trace_copy(w, w, vp, np);
}

/*
 * The trace of src as reply structures allocated from dst.  With dst
 * another work than src, everything is copied, under src's lock: the
 * snapshot of a job that may still be running.
 */
void
trace_copy(struct work *dst, struct work *src, const struct arc_step **vp,
    size_t *np)
{
	struct arc_step	*v;
	int		 i, n;
	bool		 copy;

	copy = dst != src;
	pthread_mutex_lock(&src->lock);
	n = src->nsteps;
	v = wcalloc(dst, (size_t)n + 1, sizeof(*v));
	for (i = 0; i < n; i++)
		step_fill(dst, &src->steps[i], i, copy, &v[i]);
	pthread_mutex_unlock(&src->lock);
	*vp = v;
	*np = (size_t)n;
}

/* The family the steps are told in; set once, before any request. */
void
trace_family(cbl_family *fam)
{

	tell_family = fam;
}

/*
 * The request's steps are told to the peer that made it, as they begin
 * and end, when it subscribed to steps; else nothing is.
 */
void
trace_tell(struct work *w, cbl_req *req)
{
	cbl_conn	*conn;

	conn = req != NULL ? cbl_req_conn(req) : NULL;
	if (conn != NULL && tell_family != NULL &&
	    cbl_conn_subscribed(conn, tell_family, ARC_MCGRP_STEPS))
		w->tell = conn;
}

/*
 * Tell the peer about step idx as it is now.  Only the work's own
 * thread changes its steps, and this runs on it: the step is read
 * without copying, and what it holds stays while the message is made.
 */
static void
tell(struct work *w, int idx)
{
	struct arc_step_ntf	 ntf;
	struct arc_step		 v;
	cbl_msg			*msg;

	if (w->tell == NULL || idx < 0)
		return;
	memset(&v, 0, sizeof(v));
	pthread_mutex_lock(&w->lock);
	step_fill(w, &w->steps[idx], idx, false, &v);
	pthread_mutex_unlock(&w->lock);
	memset(&ntf, 0, sizeof(ntf));
	ntf.trace.n = 1;
	ntf.trace.v = &v;
	if (cbl_notify_msg_new(tell_family, ARC_CMD_STEP, &msg) != 0)
		return;
	if (arc_step_ntf_put_fields(msg, &ntf) != 0) {
		cbl_msg_free(msg);
		return;
	}
	/* A peer that is gone, or too slow, misses it: the reply has it. */
	(void)cbl_conn_notify(w->tell, tell_family, ARC_MCGRP_STEPS, msg);
}
