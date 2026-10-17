/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * kmsg: the kernel's line for a program that died of a signal, as the
 * event and the fault kmsg.c makes of it, for agent_test.sh.  Each
 * line of the standard input is "<seconds> <the kernel's line>", or
 * "sweep <seconds>"; what the events and faults are told is printed
 * in their place, one line each.
 */

#include <sys/param.h>

#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

struct opts	opts;

/* The faults open, as faults.c keeps them: a type and an object. */
static char	open_faults[16][160];
static int	nopen;

static int
find(const char *type, const char *object)
{
	char	key[160];
	int	i;

	snprintf(key, sizeof(key), "%s %s", type, object);
	for (i = 0; i < nopen; i++)
		if (strcmp(open_faults[i], key) == 0)
			return (i);
	return (-1);
}

void
event_add(const char *kind, const char *fmt, ...)
{
	va_list	ap;

	printf("event %s ", kind);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

void
fault_set(const char *type, const char *severity, const char *object,
    const char *by, const char *fmt, ...)
{
	va_list	ap;

	if (find(type, object) >= 0) {
		printf("set again %s %s\n", type, object);
		return;
	}
	if (nopen < 16)
		snprintf(open_faults[nopen++], sizeof(open_faults[0]), "%s %s",
		    type, object);
	printf("set %s %s %s %s: ", type, severity, object, by);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

bool
fault_update(const char *type, const char *object, const char *fmt, ...)
{
	va_list	ap;

	if (find(type, object) < 0)
		return (false);
	printf("update %s %s: ", type, object);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	return (true);
}

void
fault_clear(const char *type, const char *object, const char *fmt, ...)
{
	va_list	ap;
	int	i;

	if ((i = find(type, object)) < 0) {
		printf("clear of none %s %s\n", type, object);
		return;
	}
	memmove(open_faults[i], open_faults[i + 1], sizeof(open_faults[0]) *
	    (size_t)(nopen - i - 1));
	nopen--;
	printf("clear %s %s: ", type, object);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

void
logmsg(int level __unused, const char *fmt __unused, ...)
{
}

char *
wstrdup(struct work *w __unused, const char *s)
{

	return (strdup(s));
}

void *
wcalloc(struct work *w __unused, size_t n, size_t size)
{

	return (calloc(n, size));
}

int
main(void)
{
	char	*line, *p;
	size_t	 cap;
	ssize_t	 len;
	long	 t;

	line = NULL;
	cap = 0;
	while ((len = getline(&line, &cap, stdin)) > 0) {
		if (line[len - 1] == '\n')
			line[len - 1] = '\0';
		if (strncmp(line, "sweep ", 6) == 0) {
			kmsg_crash_sweep((time_t)strtol(line + 6, NULL, 10));
			continue;
		}
		t = strtol(line, &p, 10);
		if (p == line || *p != ' ')
			errx(1, "not a line of the test: %s", line);
		if (!kmsg_crash_line(p + 1, (time_t)t))
			printf("not a crash: %s\n", p + 1);
	}
	free(line);
	return (0);
}
