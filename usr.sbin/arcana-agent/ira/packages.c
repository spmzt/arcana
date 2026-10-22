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

#include <sys/param.h>

#include <ctype.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

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
	int	 rc;

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
	/* Watched: a pkg that hangs (a stalled fetch) is stopped, its
	 * child in the jail with it. */
	exec_set_watch(opts.pkg_idle_s);
	rc = run_exec(w, argv, res);
	exec_set_watch(0);
	return (rc);
}

/*
 * What pkg said of repositories it could not update or open, its lines
 * of "pkg:" joined, or NULL when it said none: pkg upgrade and install
 * exit 0 then, with nothing to do, as if every package were up to date.
 * A repository of packages for a newer FreeBSD (pkg's "wrong OS
 * version") is said to need IGNORE_OSVERSION, for the console to ask
 * whether to go on past it.
 */
const char *
pkg_repo_error(struct work *w, const struct execres *res, const char *prog)
{
	const char	*text[] = { res->err, res->out };
	char		*copy, *it, *line, *why;
	bool		 failed;
	size_t		 i;

	failed = false;
	why = NULL;
	for (i = 0; i < nitems(text); i++) {
		if (text[i] == NULL)
			continue;
		if (strstr(text[i], "Error updating repositories") != NULL ||
		    strstr(text[i], "cannot be opened") != NULL)
			failed = true;
		copy = wstrdup(w, text[i]);
		for (it = copy; (line = strsep(&it, "\n")) != NULL;) {
			if (strncmp(line, "pkg: ", 5) != 0)
				continue;
			why = why == NULL ? wstrdup(w, line + 5) :
			    wfmt(w, "%s; %s", why, line + 5);
		}
	}
	if (!failed)
		return (NULL);
	if (why != NULL && strstr(why, "wrong OS version") != NULL)
		return (wtext(w, wfmt(w, "%s: a repository has packages for a "
		    "newer FreeBSD than this one, refused unless "
		    "IGNORE_OSVERSION=yes: %s", prog, why)));
	return (wtext(w, wfmt(w, "%s: the repositories could not be read%s%s",
	    prog, why != NULL ? ": " : "", why != NULL ? why : "")));
}

/*
 * The repositories pkg is configured with there (pkg -vv), enabled or
 * not, by name: "  NAME: {" under "Repositories:".  *np 0 when pkg did
 * not say.
 */
static void
pkg_repos(struct work *w, const char *jail, const char ***vp, size_t *np)
{
	static const char *const vv[] = { "-vv" };
	struct execres	 res;
	const char	**v;
	char		*copy, *it, *line, *end;
	bool		 in;
	size_t		 n;

	*vp = NULL;
	*np = 0;
	if (pkg_run(w, jail, false, 0, vv, 1, &res) != 0 || res.out == NULL)
		return;
	v = wcalloc(w, 65, sizeof(*v));
	n = 0;
	in = false;
	copy = wstrndup(w, res.out, res.outlen);
	for (it = copy; (line = strsep(&it, "\n")) != NULL && n < 64; ) {
		if (strcmp(line, "Repositories:") == 0) {
			in = true;
			continue;
		}
		if (!in)
			continue;
		if (line[0] != ' ') {
			in = false;
			continue;
		}
		/* Two spaces, the name, ": {"; its settings deeper. */
		if (line[1] != ' ' || line[2] == ' ' || line[2] == '\0' ||
		    (end = strstr(line + 2, ": {")) == NULL)
			continue;
		*end = '\0';
		v[n++] = line + 2;
	}
	*vp = v;
	*np = n;
}

/* Is repo one of pkg's repositories there?  NULL, or why not. */
static const char *
repo_check(struct work *w, const char *jail, const char *repo)
{
	const char	**v;
	const char	*p;
	size_t		 n, i;

	if (repo == NULL || repo[0] == '\0')
		return (NULL);
	for (p = repo; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p) && strchr("-_.", *p) == NULL)
			return (wfmt(w, "'%s' is not a repository's name", repo));
	pkg_repos(w, jail, &v, &n);
	for (i = 0; i < n; i++)
		if (strcmp(v[i], repo) == 0)
			return (NULL);
	return (wfmt(w, "pkg has no repository %s%s%s", repo, jail != NULL &&
	    jail[0] != '\0' ? " in jail " : "", jail != NULL ? jail : ""));
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
		/*
		 * A package's line has the comparison after its name,
		 * "<"; what else pkg says, each repository's "FreeBSD-ports
		 * repository is up to date." among it, is no package.
		 */
		if (line != NULL)
			line += strspn(line, " \t");
		if (line == NULL || strchr("<=>?!", line[0]) == NULL ||
		    (line[1] != '\0' && line[1] != ' ' && line[1] != '\t'))
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
    uint8_t ip, bool anyos, struct arc_packages_rsp *rsp)
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
	/* The repositories an upgrade or an install may be held to. */
	{
		const char	**rv;

		pkg_repos(w, jail, &rv, &rsp->pkg_repos.n);
		rsp->pkg_repos.v = rv;
	}
	/* A jail's base: pkgbase when FreeBSD-runtime is a package of it. */
	if (jail != NULL && *jail != '\0') {
		static const char *const runtime[] = { "info", "-q",
		    "FreeBSD-runtime" };

		rsp->has_pkgbase = true;
		rsp->pkgbase = pkg_run(w, jail, false, 0, runtime, 3, &res) == 0;
	}
	if (inst)
		return (installed(w, jail, rsp));
	/* A repository for a newer FreeBSD is named as such, for the
	 * console to ask whether to read past it. */
	if (refresh && pkg_run(w, jail, anyos, ip, update, 2, &res) != 0) {
		rsp->error = (e = pkg_repo_error(w, &res, "pkg update")) != NULL ? e :
		    wtext(w, exec_error(w, &res, "pkg update"));
		return (0);
	}
	/* pkg version exits 0 with matches and 1 without, as grep does;
	 * a repository it could not read is an error whatever it exits. */
	if (pkg_run(w, jail, anyos, ip, version, 3, &res) != 0 && ((e =
	    pkg_repo_error(w, &res, "pkg version")) != NULL || res.status != 1)) {
		rsp->error = e != NULL ? e : wtext(w, exec_error(w, &res,
		    "pkg version"));
		return (0);
	}
	parse_versions(w, &res, &v, &n);
	rsp->packages.v = v;
	rsp->packages.n = n;
	rsp->ok = true;
	return (0);
}

/*
 * Every running jail's packages upgraded, one jail after the other: one
 * without pkg (never bootstrapped, pkg -N says) left out and said so,
 * one that fails not stopping the rest; what each did is a step of the
 * trace, and the error, when there is one, names each that failed.
 */
static int
upgrade_every_jail(struct work *w, const struct arc_pkg_upgrade_req *rq,
    struct arc_pkg_upgrade_rsp *rsp)
{
	struct arc_pkg_upgrade_req	 one;
	struct arc_pkg_upgrade_rsp	 r;
	struct execres			 res;
	struct jinfo			*list;
	const char			*e, *failed, *skipped;
	static const char *const	 bootstrapped[] = { "-N" };
	size_t				 n, i, done;

	rsp->has_ok = true;
	rsp->ok = false;
	list = NULL;
	n = 0;
	if (jails_running(w, &list, &n, &e) != 0) {
		rsp->error = e != NULL ? e : "the jails could not be listed";
		return (0);
	}
	failed = skipped = NULL;
	done = 0;
	rsp->has_upgraded = true;
	rsp->upgraded = 0;
	for (i = 0; i < n; i++) {
		if (list[i].dying || list[i].name == NULL)
			continue;
		if (pkg_run(w, list[i].name, false, rq->pkg_ip, bootstrapped,
		    1, &res) != 0) {
			skipped = skipped == NULL ? list[i].name : wfmt(w,
			    "%s, %s", skipped, list[i].name);
			continue;
		}
		one = *rq;
		one.jail = list[i].name;
		memset(&r, 0, sizeof(r));
		(void)do_pkg_upgrade(w, &one, &r);
		if (!r.ok)
			failed = wfmt(w, "%s%s%s: %s", failed != NULL ? failed :
			    "", failed != NULL ? "; " : "", list[i].name,
			    r.error != NULL ? r.error : "failed");
		else
			rsp->upgraded += r.upgraded;
		done++;
	}
	if (skipped != NULL)
		logmsg(LOG_INFO, "pkg upgrade of every jail: without pkg, "
		    "left out: %s", skipped);
	if (failed != NULL)
		rsp->error = wfmt(w, "pkg upgrade failed in %s", failed);
	else if (done == 0)
		rsp->error = skipped != NULL ? wfmt(w, "no running jail has pkg "
		    "(%s have none)", skipped) : "no jail is running";
	else
		rsp->ok = true;
	return (0);
}

int
do_pkg_upgrade(struct work *w, const struct arc_pkg_upgrade_req *rq,
    struct arc_pkg_upgrade_rsp *rsp)
{
	const char		*version[] = { "version", "-vRl", "<", NULL,
				    NULL, NULL };
	struct arc_package	*v;
	struct execres		 res;
	const char		**args, *e, *p;
	size_t			 n, i, nv;

	if (rq->jail != NULL && strcmp(rq->jail, "*") == 0)
		return (upgrade_every_jail(w, rq, rsp));
	rsp->has_ok = true;
	rsp->ok = false;
	if ((e = check_jail(w, rq->jail)) != NULL ||
	    (e = repo_check(w, rq->jail, rq->pkg_repo)) != NULL) {
		rsp->error = e;
		return (0);
	}
	nv = 3;
	if (rq->pkg_repo != NULL && rq->pkg_repo[0] != '\0') {
		/* What that repository has newer: pkg version -R -r. */
		version[1] = "-vR";
		version[2] = "-r";
		version[3] = rq->pkg_repo;
		version[4] = "-l";
		version[5] = "<";
		nv = 6;
	}
	for (i = 0; i < rq->names.n; i++)
		if (rq->names.v[i] == NULL || !valid_pkg(rq->names.v[i])) {
			rsp->error = wfmt(w, "'%s' is not a package name",
			    rq->names.v[i] != NULL ? rq->names.v[i] : "");
			return (0);
		}
	args = wcalloc(w, rq->names.n + 6, sizeof(*args));
	n = 0;
	args[n++] = "upgrade";
	/* From that repository alone. */
	if (rq->pkg_repo != NULL && rq->pkg_repo[0] != '\0') {
		args[n++] = "-r";
		args[n++] = rq->pkg_repo;
	}
	args[n++] = rq->dry_run ? "-n" : "-y";
	for (i = 0; i < rq->names.n; i++)
		args[n++] = rq->names.v[i];
	/* pkg upgrade -n exits 1 when it would change nothing. */
	if (pkg_run(w, rq->jail, rq->ignore_osversion, rq->pkg_ip, args, n,
	    &res) != 0 &&
	    !(rq->dry_run && res.status == 1)) {
		/* A repository it could not read is said as such, the newer
		 * FreeBSD's named, whatever pkg exited. */
		rsp->error = (e = pkg_repo_error(w, &res, "pkg upgrade")) != NULL ? e :
		    wtext(w, exec_error(w, &res, "pkg upgrade"));
	} else if ((e = pkg_repo_error(w, &res, "pkg upgrade")) != NULL) {
		rsp->error = e;
	} else {
		rsp->ok = true;
		rsp->has_upgraded = true;
		rsp->upgraded = 0;
		for (p = res.out; (p = strstr(p, "Upgrading ")) != NULL; p += 10)
			rsp->upgraded++;
	}
	/* What is still pending, for the reply. */
	if (pkg_run(w, rq->jail, false, rq->pkg_ip, version, nv, &res) == 0 ||
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
/* pkg install -y of the packages named, there or in a running jail. */
int
do_pkg_install(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct execres	 res;
	const char	**args, *e;
	size_t		 i, n;

	if ((e = check_jail(w, sp->jail)) != NULL ||
	    (e = repo_check(w, sp->jail, sp->pkg_repo)) != NULL) {
		*errp = e;
		return (-1);
	}
	args = wcalloc(w, sp->names.n + 5, sizeof(*args));
	n = 0;
	args[n++] = "install";
	if (sp->pkg_repo != NULL && sp->pkg_repo[0] != '\0') {
		args[n++] = "-r";
		args[n++] = sp->pkg_repo;
	}
	args[n++] = "-y";
	for (i = 0; i < sp->names.n; i++) {
		if (sp->names.v[i] == NULL || !valid_pkg(sp->names.v[i])) {
			*errp = wfmt(w, "'%s' is not a package name",
			    sp->names.v[i] != NULL ? sp->names.v[i] : "");
			return (-1);
		}
		args[n++] = sp->names.v[i];
	}
	if (pkg_run(w, sp->jail, sp->force, sp->has_pkg_ip ? sp->pkg_ip : 0,
	    args, n, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "pkg install"));
		return (-1);
	}
	if ((e = pkg_repo_error(w, &res, "pkg install")) != NULL) {
		*errp = e;
		return (-1);
	}
	return (0);
}

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

