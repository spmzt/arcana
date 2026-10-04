/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: what a request did, step by step, with what each program it ran
 * printed.  Every reply carries it; a job's is read while the job runs.
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
	struct step	*s;
	const char	**av;
	size_t		 k;
	int		 i, n;
	bool		 copy;

	copy = dst != src;
	pthread_mutex_lock(&src->lock);
	n = src->nsteps;
	v = wcalloc(dst, (size_t)n + 1, sizeof(*v));
	for (i = 0; i < n; i++) {
		s = &src->steps[i];
		v[i].has_id = true;
		v[i].id = (uint32_t)i;
		v[i].has_parent = true;
		v[i].parent = s->parent;
		v[i].has_kind = true;
		v[i].kind = s->kind;
		v[i].label = wtext(dst, copy ? wstrdup(dst, s->label) :
		    s->label);
		v[i].detail = wtext(dst, copy ? wstrdup(dst, s->detail) :
		    s->detail);
		v[i].has_status = true;
		v[i].status = !s->done ? ARC_STEP_STATUS_INCOMPLETE :
		    s->ok ? ARC_STEP_STATUS_OK : ARC_STEP_STATUS_FAILED;
		v[i].has_duration_us = s->done;
		v[i].duration_us = s->dur;
		if (s->kind == ARC_STEP_KIND_EXEC && s->argv != NULL) {
			av = s->argv;
			if (copy) {
				av = wcalloc(dst, s->argc + 1, sizeof(*av));
				for (k = 0; k < s->argc; k++)
					av[k] = wstrdup(dst, s->argv[k]);
			}
			v[i].argv.n = s->argc;
			v[i].argv.v = av;
			v[i].has_exit = true;
			v[i].exit = s->status;
			v[i].output.p = s->out == NULL ? "" : copy ?
			    wstrndup(dst, s->out, s->outlen) : s->out;
			v[i].output.len = s->outlen;
			v[i].error_output.p = s->err == NULL ? "" : copy ?
			    wstrndup(dst, s->err, s->errlen) : s->err;
			v[i].error_output.len = s->errlen;
		}
	}
	pthread_mutex_unlock(&src->lock);
	*vp = v;
	*np = (size_t)n;
}
