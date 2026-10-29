/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libjail's jail_getv(3) for the tests, preloaded (LD_PRELOAD) into the
 * agent they start: a jail looked up by name or jid is answered from
 * the file FAKEJAIL names, one jail a line,
 *
 *	name jid vnet path [osrelease]
 *
 * as "gw 4 new /tmp/t/jroot 16.0-CURRENT": jails nobody made, there for
 * the agent alone.  A jail not in it, or no file, is not running; a
 * walk by lastjid goes through the file's, by their jids.  Without
 * FAKEJAIL, or without the file for a walk, the real one answers: the
 * list of every jail stays the host's.
 *
 * Nothing of libjail is linked: the library is loaded into whatever the
 * agent runs too, and libjail's own symbols are looked for when called.
 */

#include <sys/param.h>

#include <dlfcn.h>
#include <errno.h>
#include <jail.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The pairs a call may have: the agent asks four. */
#define	FJ_PAIRS	8
/* A line's fields: name, jid, vnet, path, osrelease. */
#define	FJ_FIELDS	5

typedef int	getv_fn(int, ...);

static char	empty[] = "";

static void	errmsg(const char *, ...) __printflike(1, 2);

/* libjail's jail_errmsg, when libjail is there to have one. */
static void
errmsg(const char *fmt, ...)
{
	va_list	 ap;
	char	*m;

	if ((m = dlsym(RTLD_DEFAULT, "jail_errmsg")) == NULL)
		return;
	va_start(ap, fmt);
	vsnprintf(m, JAIL_ERRMSGLEN, fmt, ap);
	va_end(ap);
}

/* The real jail_getv(3), with the pairs given, NULL after the last. */
static int
real(int flags, char *av[])
{
	getv_fn	*fn;

	if ((fn = (getv_fn *)dlsym(RTLD_NEXT, "jail_getv")) == NULL) {
		errno = ENOSYS;
		return (-1);
	}
	return (fn(flags, av[0], av[1], av[2], av[3], av[4], av[5], av[6],
	    av[7], av[8], av[9], av[10], av[11], av[12], av[13], av[14],
	    av[15], av[16]));
}

/*
 * The file's line for the jail, by jid when one is given, else by
 * name, or with after (a walk) the one of the least jid above it; its
 * fields in f, split in place in line.
 */
static bool
lookup(const char *file, const char *jid, const char *name, long after,
    char *line, size_t len, char *f[FJ_FIELDS])
{
	FILE	*fp;
	char	*p, *s, best[MAXPATHLEN + 256];
	long	 bj = -1, j;
	int	 n;

	if ((fp = fopen(file, "r")) == NULL)
		return (false);
	while (fgets(line, (int)len, fp) != NULL) {
		if (line[0] == '#')
			continue;
		line[strcspn(line, "\n")] = '\0';
		n = 0;
		p = line;
		while (n < FJ_FIELDS && (s = strsep(&p, " \t")) != NULL)
			if (s[0] != '\0')
				f[n++] = s;
		if (n < 2)
			continue;
		while (n < FJ_FIELDS)
			f[n++] = empty;
		if (after >= 0) {
			if ((j = strtol(f[1], NULL, 10)) > after && (bj < 0 ||
			    j < bj)) {
				bj = j;
				snprintf(best, sizeof(best), "%s %s %s %s %s",
				    f[0], f[1], f[2], f[3], f[4]);
			}
			continue;
		}
		if (jid != NULL ? strcmp(f[1], jid) == 0 :
		    strcmp(f[0], name) == 0) {
			fclose(fp);
			return (true);
		}
	}
	fclose(fp);
	if (bj < 0)
		return (false);
	/* The one found, split again. */
	snprintf(line, len, "%s", best);
	n = 0;
	p = line;
	while (n < FJ_FIELDS && (s = strsep(&p, " ")) != NULL)
		f[n++] = s;
	while (n < FJ_FIELDS)
		f[n++] = empty;
	return (true);
}

int
jail_getv(int flags, ...)
{
	va_list		 ap;
	char		*av[2 * FJ_PAIRS + 1], *f[FJ_FIELDS];
	char		 line[MAXPATHLEN + 256];
	const char	*file, *jid, *name, *key, *s;
	long		 after;
	int		 n, i;
	FILE		*fp;

	va_start(ap, flags);
	for (n = 0; n < 2 * FJ_PAIRS && (av[n] = va_arg(ap, char *)) != NULL;
	    n += 2)
		av[n + 1] = va_arg(ap, char *);
	if (n == 2 * FJ_PAIRS && va_arg(ap, char *) != NULL) {
		va_end(ap);
		errmsg("%s: too many parameters", "jail_getv");
		errno = E2BIG;
		return (-1);
	}
	va_end(ap);
	for (i = n; i <= 2 * FJ_PAIRS; i++)
		av[i] = NULL;
	/* The key, as libjail takes it: lastjid, a jid not 0, the name. */
	jid = name = NULL;
	after = -1;
	for (i = 0; i < n; i += 2) {
		if (strcmp(av[i], "lastjid") == 0) {
			if ((file = getenv("FAKEJAIL")) == NULL || (fp =
			    fopen(file, "r")) == NULL)
				return (real(flags, av));
			fclose(fp);
			after = strtol(av[i + 1], NULL, 10);
			key = av[i + 1];
			continue;
		}
		if (strcmp(av[i], "jid") == 0 &&
		    strtol(av[i + 1], NULL, 10) != 0)
			jid = av[i + 1];
		else if (strcmp(av[i], "name") == 0)
			name = av[i + 1];
	}
	if ((file = getenv("FAKEJAIL")) == NULL)
		return (real(flags, av));
	if (after < 0 && (key = jid != NULL ? jid : name) == NULL) {
		errmsg("%s", "no jail specified");
		errno = ENOENT;
		return (-1);
	}
	if (!lookup(file, after >= 0 ? NULL : jid, name, after, line,
	    sizeof(line), f)) {
		errmsg("jail \"%s\" not found", key);
		errno = ENOENT;
		return (-1);
	}
	for (i = 0; i < n; i += 2) {
		if (av[i + 1] == key)
			continue;
		if (strcmp(av[i], "lastjid") == 0)
			continue;
		if (strcmp(av[i], "name") == 0)
			s = f[0];
		else if (strcmp(av[i], "jid") == 0)
			s = f[1];
		else if (strcmp(av[i], "vnet") == 0)
			s = f[2];
		else if (strcmp(av[i], "path") == 0)
			s = f[3];
		else if (strcmp(av[i], "osrelease") == 0)
			s = f[4];
		else {
			errmsg("unknown parameter: %s", av[i]);
			errno = ENOENT;
			return (-1);
		}
		/* It is up to the caller to have room, as with libjail. */
		strcpy(av[i + 1], s);
	}
	return ((int)strtol(f[1], NULL, 10));
}
