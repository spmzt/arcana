/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Per-request state: an allocation pool that the reply points into, and
 * the trace of what the request did.
 */

#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vis.h>
#include <wchar.h>

#include "jailgridd.h"

void
work_init(struct work *w)
{

	memset(w, 0, sizeof(*w));
}

void
work_free(struct work *w)
{
	size_t	i;

	for (i = 0; i < w->nptrs; i++)
		free(w->ptrs[i]);
	free(w->ptrs);
	w->ptrs = NULL;
	w->nptrs = w->capptrs = 0;
}

/* Take ownership of p, a malloc(3)ed pointer; it goes with the request. */
void *
wadopt(struct work *w, void *p)
{

	if (p == NULL)
		return (NULL);
	if (w->nptrs == w->capptrs) {
		w->capptrs = w->capptrs == 0 ? 64 : w->capptrs * 2;
		if ((w->ptrs = reallocarray(w->ptrs, w->capptrs,
		    sizeof(*w->ptrs))) == NULL)
			err(1, "reallocarray");
	}
	w->ptrs[w->nptrs++] = p;
	return (p);
}

void *
wmalloc(struct work *w, size_t n)
{
	void	*p;

	if ((p = malloc(n == 0 ? 1 : n)) == NULL)
		err(1, "malloc");
	return (wadopt(w, p));
}

void *
wcalloc(struct work *w, size_t nmemb, size_t size)
{
	void	*p;

	if (size != 0 && nmemb > SIZE_MAX / size)
		errx(1, "wcalloc: overflow");
	p = wmalloc(w, nmemb * size);
	memset(p, 0, nmemb * size);
	return (p);
}

char *
wstrndup(struct work *w, const char *s, size_t n)
{
	char	*p;

	p = wmalloc(w, n + 1);
	memcpy(p, s, n);
	p[n] = '\0';
	return (p);
}

char *
wstrdup(struct work *w, const char *s)
{

	return (s == NULL ? NULL : wstrndup(w, s, strlen(s)));
}

char *
wfmt(struct work *w, const char *fmt, ...)
{
	va_list	 ap;
	char	*s, *p;

	va_start(ap, fmt);
	if (vasprintf(&s, fmt, ap) == -1)
		err(1, "vasprintf");
	va_end(ap);
	p = wstrdup(w, s);
	free(s);
	return (p);
}

/* s with unprintable characters as C escapes, for display. */
char *
wvis(struct work *w, const char *s)
{
	char	*v, *p;

	if (s == NULL)
		return (NULL);
	if (stravis(&v, s, VIS_CSTYLE | VIS_OCTAL | VIS_TAB | VIS_NL) == -1)
		err(1, "stravis");
	p = wstrdup(w, v);
	free(v);
	return (p);
}

/*
 * s, made fit for a CBOR text string: valid UTF-8 without control
 * characters is returned as is, anything else through vis(3).
 */
const char *
wtext(struct work *w, const char *s)
{
	mbstate_t	 st;
	const char	*p;
	size_t		 n, len;
	wchar_t		 wc;

	if (s == NULL)
		return (NULL);
	memset(&st, 0, sizeof(st));
	len = strlen(s);
	for (p = s; *p != '\0'; p += n) {
		n = mbrtowc(&wc, p, len - (size_t)(p - s), &st);
		if (n == (size_t)-1 || n == (size_t)-2 || n == 0 ||
		    (wc < 0x20 && wc != '\t' && wc != '\n') || wc == 0x7f)
			return (wvis(w, s));
	}
	return (s);
}

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

	if (w->nsteps >= TRACE_MAX)
		return (-1);
	s = &w->steps[w->nsteps];
	memset(s, 0, sizeof(*s));
	s->kind = kind;
	s->label = wstrdup(w, label);
	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&d, fmt, ap) == -1)
			err(1, "vasprintf");
		va_end(ap);
		s->detail = wstrdup(w, d);
		free(d);
	}
	s->parent = w->depth > 0 ? w->stack[w->depth - 1] : -1;
	s->start = now_us();
	s->status = -1;
	if (w->depth < TRACE_DEPTH)
		w->stack[w->depth++] = w->nsteps;
	return (w->nsteps++);
}

/* Finish a step; a non-NULL fmt replaces its detail with the outcome. */
void
step_end(struct work *w, int idx, bool ok, const char *fmt, ...)
{
	struct step	*s;
	va_list		 ap;
	char		*d;
	int		 i;

	if (idx < 0 || idx >= w->nsteps)
		return;
	s = &w->steps[idx];
	s->done = true;
	s->ok = ok;
	s->dur = now_us() - s->start;
	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&d, fmt, ap) == -1)
			err(1, "vasprintf");
		va_end(ap);
		s->detail = wstrdup(w, d);
		free(d);
	}
	/* Close this step and anything left open inside it. */
	for (i = w->depth; i > 0; i--)
		if (w->stack[i - 1] == idx) {
			w->depth = i - 1;
			break;
		}
}

/* Attach what a program was run with and what it printed. */
void
step_exec(struct work *w, int idx, char *const argv[], int status,
    const char *out, size_t outlen, const char *errout, size_t errlen)
{
	struct step	*s;
	size_t		 n, i;

	if (idx < 0 || idx >= w->nsteps)
		return;
	s = &w->steps[idx];
	for (n = 0; argv[n] != NULL; n++)
		;
	s->argv = wcalloc(w, n, sizeof(char *));
	for (i = 0; i < n; i++)
		s->argv[i] = wvis(w, argv[i]);
	s->argc = n;
	s->status = status;
	s->out = out;
	s->outlen = outlen;
	s->err = errout;
	s->errlen = errlen;
}

/* The trace in the shape the family's replies carry it. */
void
trace_steps(struct work *w, const struct jg_step **vp, size_t *np)
{
	struct jg_step	*v;
	struct step	*s;
	int		 i;

	v = wcalloc(w, (size_t)w->nsteps + 1, sizeof(*v));
	for (i = 0; i < w->nsteps; i++) {
		s = &w->steps[i];
		v[i].has_id = true;
		v[i].id = (uint32_t)i;
		v[i].has_parent = true;
		v[i].parent = s->parent;
		v[i].has_kind = true;
		v[i].kind = s->kind;
		v[i].label = wtext(w, s->label);
		v[i].detail = wtext(w, s->detail);
		v[i].has_status = true;
		v[i].status = !s->done ? JG_STEP_STATUS_INCOMPLETE :
		    s->ok ? JG_STEP_STATUS_OK : JG_STEP_STATUS_FAILED;
		v[i].has_duration_us = s->done;
		v[i].duration_us = s->dur;
		if (s->kind == JG_STEP_KIND_EXEC && s->argv != NULL) {
			v[i].argv.n = s->argc;
			v[i].argv.v = s->argv;
			v[i].has_exit = true;
			v[i].exit = s->status;
			v[i].output.p = s->out != NULL ? s->out : "";
			v[i].output.len = s->outlen;
			v[i].error_output.p = s->err != NULL ? s->err : "";
			v[i].error_output.len = s->errlen;
		}
	}
	*vp = v;
	*np = (size_t)w->nsteps;
}
