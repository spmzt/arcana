/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Packages of the host or of a running jail, through pkg(8): "pkg -j
 * <jail>" runs inside the jail.  What has a newer version comes from
 * "pkg version -vRl '<'" (one line per package: name-version, '<',
 * "needs updating (remote has <version>)"), and upgrades are
 * "pkg upgrade -y [names]".  Every run is a step in the trace, so the
 * upgrade's output reaches the console.
 */

#include <sys/types.h>

#include <ctype.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

static int	pkg_run(struct work *, const char *, bool, uint8_t,
		    const char *const *, size_t, struct execres *);
static void	parse_versions(struct work *, const struct execres *,
		    struct arc_package **, size_t *);
static bool	valid_pkg(const char *);
static const char *check_jail(struct work *, const char *);

/*
 * "pkg [-4 | -6] [-o IGNORE_OSVERSION=yes] [-j jail] args...": with
 * anyos, also packages built for a newer FreeBSD than this one; ip 4
 * or 6, the repository reached over that only.
 */
static int
pkg_run(struct work *w, const char *jail, bool anyos, uint8_t ip,
    const char *const *args, size_t n, struct execres *res)
{
	char	**argv;
	size_t	 i, k;

	argv = wcalloc(w, n + 8, sizeof(*argv));
	k = 0;
	argv[k++] = (char *)(uintptr_t)opts.pkg_bin;
	if (ip == 4 || ip == 6)
		argv[k++] = (char *)(uintptr_t)(ip == 4 ? "-4" : "-6");
	if (anyos) {
		argv[k++] = (char *)(uintptr_t)"-o";
		argv[k++] = (char *)(uintptr_t)"IGNORE_OSVERSION=yes";
	}
	if (jail != NULL && *jail != '\0') {
		argv[k++] = (char *)(uintptr_t)"-j";
		argv[k++] = (char *)(uintptr_t)jail;
	}
	for (i = 0; i < n; i++)
		argv[k++] = (char *)(uintptr_t)args[i];
	argv[k] = NULL;
	return (run_exec(w, argv, res));
}

/* The lines of "pkg version -vRl '<'" as packages. */
static void
parse_versions(struct work *w, const struct execres *res,
    struct arc_package **outp, size_t *np)
{
	struct arc_package	*v;
	char			*copy, *it, *line, *nv, *dash, *p, *e;
	size_t			 n;

	v = NULL;
	n = 0;
	copy = wstrndup(w, res->out, res->outlen);
	for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
		if ((nv = strsep(&line, " \t")) == NULL || *nv == '\0' ||
		    (dash = strrchr(nv, '-')) == NULL)
			continue;
		if ((v = reallocarray(v, n + 1, sizeof(*v))) == NULL)
			err(1, "reallocarray");
		memset(&v[n], 0, sizeof(v[n]));
		v[n].name = wtext(w, wstrndup(w, nv, (size_t)(dash - nv)));
		v[n].installed = wtext(w, dash + 1);
		if (line != NULL && (p = strstr(line, "remote has ")) != NULL) {
			p += 11;
			if ((e = strchr(p, ')')) != NULL)
				*e = '\0';
			v[n].available = wtext(w, p);
		}
		n++;
	}
	*outp = wadopt(w, v);
	*np = n;
}

/* Package names as pkg(8) takes them. */
static bool
valid_pkg(const char *s)
{

	if (*s == '\0' || *s == '-' || strlen(s) > 128)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.+-", *s) == NULL)
			return (false);
	return (true);
}

/* A jail named in a request must be running for pkg -j. */
static const char *
check_jail(struct work *w, const char *jail)
{

	if (jail == NULL || *jail == '\0')
		return (NULL);
	if (jail_lookup(w, jail) < 0)
		return (wfmt(w, "jail '%s' is not running; pkg -j needs it",
		    jail));
	return (NULL);
}

/*
 * The packages installed, from the host's own database: name, version,
 * whether it came automatically, its size, origin and comment, a line
 * each with tabs between (pkg query).
 */
static int
installed(struct work *w, const char *jail, struct arc_packages_rsp *rsp)
{
	static const char *const query[] = { "query",
	    "%n\t%v\t%a\t%sb\t%o\t%c" };
	struct arc_package	*v;
	struct execres		 res;
	char			*copy, *it, *line, *f[6];
	size_t			 n, i;

	if (pkg_run(w, jail, false, 0, query, 2, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "pkg query"));
		return (0);
	}
	v = NULL;
	n = 0;
	copy = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
	for (it = copy; (line = strsep(&it, "\n")) != NULL; ) {
		for (i = 0; i < 6 && (f[i] = strsep(&line, "\t")) != NULL; i++)
			;
		if (i < 5 || f[0][0] == '\0')
			continue;
		if ((v = reallocarray(v, n + 1, sizeof(*v))) == NULL)
			err(1, "reallocarray");
		memset(&v[n], 0, sizeof(v[n]));
		v[n].name = wtext(w, f[0]);
		v[n].installed = wtext(w, f[1]);
		v[n].has_automatic = true;
		v[n].automatic = strcmp(f[2], "1") == 0;
		v[n].has_size = true;
		v[n].size = strtoull(f[3], NULL, 10);
		v[n].origin = wtext(w, f[4]);
		v[n].comment = i > 5 ? wtext(w, f[5]) : NULL;
		n++;
	}
	rsp->packages.v = wadopt(w, v);
	rsp->packages.n = n;
	rsp->ok = true;
	return (0);
}

int
do_packages(struct work *w, const char *jail, bool refresh, bool inst,
    uint8_t ip, struct arc_packages_rsp *rsp)
{
	static const char *const update[] = { "update", "-q" };
	static const char *const version[] = { "version", "-vRl", "<" };
	struct arc_package	*v;
	struct execres		 res;
	const char		*e;
	size_t			 n;

	rsp->has_ok = true;
	rsp->ok = false;
	if ((e = check_jail(w, jail)) != NULL) {
		rsp->error = e;
		return (0);
	}
	if (inst)
		return (installed(w, jail, rsp));
	if (refresh && pkg_run(w, jail, false, ip, update, 2, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "pkg update"));
		return (0);
	}
	/* pkg version exits 0 with matches and 1 without, as grep does. */
	if (pkg_run(w, jail, false, ip, version, 3, &res) != 0 && res.status !=
	    1) {
		rsp->error = wtext(w, exec_error(w, &res, "pkg version"));
		return (0);
	}
	parse_versions(w, &res, &v, &n);
	rsp->packages.v = v;
	rsp->packages.n = n;
	rsp->ok = true;
	return (0);
}

int
do_pkg_upgrade(struct work *w, const struct arc_pkg_upgrade_req *rq,
    struct arc_pkg_upgrade_rsp *rsp)
{
	static const char *const version[] = { "version", "-vRl", "<" };
	struct arc_package	*v;
	struct execres		 res;
	const char		**args, *e, *p;
	size_t			 n, i;

	rsp->has_ok = true;
	rsp->ok = false;
	if ((e = check_jail(w, rq->jail)) != NULL) {
		rsp->error = e;
		return (0);
	}
	for (i = 0; i < rq->names.n; i++)
		if (rq->names.v[i] == NULL || !valid_pkg(rq->names.v[i])) {
			rsp->error = wfmt(w, "'%s' is not a package name",
			    rq->names.v[i] != NULL ? rq->names.v[i] : "");
			return (0);
		}
	args = wcalloc(w, rq->names.n + 4, sizeof(*args));
	n = 0;
	args[n++] = "upgrade";
	args[n++] = rq->dry_run ? "-n" : "-y";
	for (i = 0; i < rq->names.n; i++)
		args[n++] = rq->names.v[i];
	/* pkg upgrade -n exits 1 when it would change nothing. */
	if (pkg_run(w, rq->jail, rq->ignore_osversion, rq->pkg_ip, args, n,
	    &res) != 0 &&
	    !(rq->dry_run && res.status == 1)) {
		rsp->error = wtext(w, exec_error(w, &res, "pkg upgrade"));
	} else {
		rsp->ok = true;
		rsp->has_upgraded = true;
		rsp->upgraded = 0;
		for (p = res.out; (p = strstr(p, "Upgrading ")) != NULL; p += 10)
			rsp->upgraded++;
	}
	/* What is still pending, for the reply. */
	if (pkg_run(w, rq->jail, false, rq->pkg_ip, version, 3, &res) == 0 ||
	    res.status == 1) {
		parse_versions(w, &res, &v, &n);
		rsp->packages.v = v;
		rsp->packages.n = n;
	}
	return (0);
}

/*
 * pkg clean -y: the cached packages no longer needed, or no longer in
 * the repository, deleted; with all, the whole cache (-a).
 */
int
do_pkg_clean(struct work *w, const char *jail, bool all, const char **errp)
{
	static const char *const some[] = { "clean", "-y" };
	static const char *const every[] = { "clean", "-ay" };
	struct execres	res;
	const char	*e;

	if ((e = check_jail(w, jail)) != NULL) {
		*errp = e;
		return (-1);
	}
	if (pkg_run(w, jail, false, 0, all ? every : some, 2, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "pkg clean"));
		return (-1);
	}
	return (0);
}
