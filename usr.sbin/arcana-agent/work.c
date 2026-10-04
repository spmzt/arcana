/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Per-request state: the allocation pool that the reply points into.
 * The trace of what the request did is Gula's (gula/trace.c).
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

void
work_init(struct work *w)
{

	memset(w, 0, sizeof(*w));
	pthread_mutex_init(&w->lock, NULL);
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
	pthread_mutex_destroy(&w->lock);
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
