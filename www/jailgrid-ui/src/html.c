/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Building markup.  h_raw() takes literal markup from this program;
 * anything that came from the network goes through h_txt() or h_attr().
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static void	grow(struct html *, size_t);

static void
grow(struct html *h, size_t n)
{

	if (h->len + n + 1 <= h->cap)
		return;
	while (h->len + n + 1 > h->cap)
		h->cap = h->cap == 0 ? 8192 : h->cap * 2;
	if ((h->s = realloc(h->s, h->cap)) == NULL)
		abort();
}

void
h_raw(struct html *h, const char *s)
{
	size_t	n;

	n = strlen(s);
	grow(h, n);
	memcpy(h->s + h->len, s, n + 1);
	h->len += n;
}

void
h_txt(struct html *h, const char *s)
{
	char	c[2];

	if (s == NULL)
		return;
	c[1] = '\0';
	for (; *s != '\0'; s++) {
		switch (*s) {
		case '&':
			h_raw(h, "&amp;");
			break;
		case '<':
			h_raw(h, "&lt;");
			break;
		case '>':
			h_raw(h, "&gt;");
			break;
		case '"':
			h_raw(h, "&quot;");
			break;
		case '\'':
			h_raw(h, "&#39;");
			break;
		default:
			c[0] = *s;
			h_raw(h, c);
			break;
		}
	}
}

void
h_fmt(struct html *h, const char *fmt, ...)
{
	va_list	 ap;
	char	*s;

	va_start(ap, fmt);
	if (vasprintf(&s, fmt, ap) == -1)
		abort();
	va_end(ap);
	h_raw(h, s);
	free(s);
}

/*
 * s where a class name is built from it: as it is when it is a plain
 * word, def otherwise.
 */
const char *
h_word(const char *s, const char *def)
{
	const char	*p;

	if (s == NULL || *s == '\0')
		return (def);
	for (p = s; *p != '\0'; p++)
		if ((*p < 'a' || *p > 'z') && *p != '-')
			return (def);
	return (s);
}

/* name="value", value escaped. */
void
h_attr(struct html *h, const char *name, const char *value)
{

	h_raw(h, " ");
	h_raw(h, name);
	h_raw(h, "=\"");
	h_txt(h, value != NULL ? value : "");
	h_raw(h, "\"");
}

char *
h_take(struct html *h)
{
	char	*s;

	grow(h, 0);
	s = h->s;
	memset(h, 0, sizeof(*h));
	return (s);
}

void
h_reset(struct html *h)
{

	h->len = 0;
	if (h->s != NULL)
		h->s[0] = '\0';
}
