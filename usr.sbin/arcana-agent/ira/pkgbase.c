/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A running jail's base system by pkg(8), as pkgbase: converted to it
 * from the official FreeBSD-base repository of its own release, or
 * taken to a newer release once it is on it.  "pkg -j <jail>" runs in
 * the jail; the official repository's file is written under the jail's
 * root under a name of arcana's own, or one of the jail's own
 * repositories is used (pkg-repo);
 * its /etc is kept aside in a tar before anything changes; the jail's
 * own files that pkg put aside come back (keep_own()); and what is left
 * beside them (.pkgnew) is named at the end, for the admin to merge.
 * The jail is to be restarted after either, for the new base to run.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

/* The official repository, defined under a name of arcana's own so
 * that a definition of the admin's (a mirror of base, often named
 * FreeBSD-base) is never merged into it; or one of the jail's own
 * repositories, named by pkg-repo, used as it is. */
#define	BASE_REPO	"arcana-base"
#define	BASE_SET	"FreeBSD-set-base-jail"
#define	REPO_FILE	"/usr/local/etc/pkg/repos/arcana-base.conf"
#define	ETC_BACKUP	"/var/backups/etc-before-pkgbase.tar"
#define	PATH_TAR	"/usr/bin/tar"
#define	PATH_FIND	"/usr/bin/find"

/* A release as a jail says it (15.1-RELEASE-p2, 16.0-CURRENT) or as
 * the job names it ("16", "15.2"). */
struct release {
	int	 major, minor;
	bool	 branch;	/* -STABLE or -CURRENT: no release of its own */
};

static bool
parse_release(const char *s, struct release *r)
{
	char	*end;
	long	 m;

	memset(r, 0, sizeof(*r));
	if (s == NULL)
		return (false);
	m = strtol(s, &end, 10);
	if (end == s || m < 1 || m > 99)
		return (false);
	r->major = (int)m;
	if (*end == '.') {
		m = strtol(end + 1, &end, 10);
		if (m < 0 || m > 99)
			return (false);
		r->minor = (int)m;
	}
	r->branch = strstr(end, "CURRENT") != NULL || strstr(end, "STABLE") !=
	    NULL;
	return (*end == '\0' || *end == '-');
}

/* The repository's branch for a release: a release's own, or the
 * latest of a major for -STABLE, -CURRENT, or a major alone. */
static const char *
branch_of(struct work *w, const struct release *r, bool major_alone)
{

	if (r->branch || major_alone)
		return ("base_latest");
	return (wfmt(w, "base_release_%d", r->minor));
}

/*
 * pkg -j jail, with -4/-6, IGNORE_OSVERSION, and the ABI and OSVERSION
 * of a release to go to when given: watched, as every pkg is.
 */
static int
pkg(struct work *w, const struct arc_job_spec *sp, bool anyos,
    const char *abi, const char *osversion, const char *const *args,
    size_t n, struct execres *res)
{
	char	**argv;
	size_t	  i, k;
	int	  rc;

	argv = wcalloc(w, n + 12, sizeof(*argv));
	k = 0;
	argv[k++] = (char *)(uintptr_t)opts.pkg_bin;
	if (sp->has_pkg_ip && (sp->pkg_ip == 4 || sp->pkg_ip == 6))
		argv[k++] = (char *)(uintptr_t)(sp->pkg_ip == 4 ? "-4" : "-6");
	if (anyos) {
		argv[k++] = (char *)(uintptr_t)"-o";
		argv[k++] = (char *)(uintptr_t)"IGNORE_OSVERSION=yes";
	}
	if (abi != NULL) {
		argv[k++] = (char *)(uintptr_t)"-o";
		argv[k++] = wfmt(w, "ABI=%s", abi);
		argv[k++] = (char *)(uintptr_t)"-o";
		argv[k++] = wfmt(w, "OSVERSION=%s", osversion);
	}
	argv[k++] = (char *)(uintptr_t)"-j";
	argv[k++] = (char *)(uintptr_t)sp->jail;
	for (i = 0; i < n; i++)
		argv[k++] = (char *)(uintptr_t)args[i];
	argv[k] = NULL;
	exec_set_watch(opts.pkg_idle_s);
	rc = run_exec(w, argv, res);
	exec_set_watch(0);
	return (rc);
}

/* What pkg said went wrong: its repository lines, or its last words. */
static const char *
pkg_failed(struct work *w, const struct execres *res, const char *prog)
{
	const char	*e;

	if ((e = pkg_repo_error(w, res, prog)) != NULL)
		return (e);
	return (wtext(w, exec_error(w, res, prog)));
}

/*
 * The jail named, running: w works in it (its root, for the files),
 * and its release as jail_getv(3) gives it.
 */
static const char *
jail_of(struct work *w, const char *name, const char **releasep)
{
	struct jinfo	 ji;
	const char	*e;

	if (name == NULL || name[0] == '\0' || strcmp(name, "*") == 0)
		return ("name the jail");
	if (scope_enter_jail(w, name, &e, false) != 0)
		return (e);
	if (jail_named(w, name, &ji) < 0 || ji.osrelease[0] == '\0')
		return (wfmt(w, "jail_getv(3) did not say the release of "
		    "jail %s", name));
	*releasep = ji.osrelease;
	return (NULL);
}

/* Is the jail on pkgbase: is FreeBSD-runtime one of its packages? */
static bool
on_pkgbase(struct work *w, const struct arc_job_spec *sp)
{
	static const char *const info[] = { "info", "-q", "FreeBSD-runtime" };
	struct execres	res;

	return (pkg(w, sp, false, NULL, NULL, info, 3, &res) == 0);
}

/* The directories above path made, as mkdir -p would. */
static int
mkdirs(const char *path)
{
	char	buf[PATH_MAX], *p;

	if (strlcpy(buf, path, sizeof(buf)) >= sizeof(buf))
		return (-1);
	if ((p = strrchr(buf, '/')) == NULL)
		return (0);
	*p = '\0';
	for (p = buf + 1; *p != '\0'; p++)
		if (*p == '/') {
			*p = '\0';
			if (mkdir(buf, 0755) == -1 && errno != EEXIST)
				return (-1);
			*p = '/';
		}
	if (mkdir(buf, 0755) == -1 && errno != EEXIST)
		return (-1);
	return (0);
}

/* The FreeBSD-base repository's file under the jail's root, for a
 * branch; a step of the trace. */
static const char *
repo_write(struct work *w, const char *root, const char *branch)
{
	const char	*path, *e;
	char		*text;
	size_t		 len;
	int		 step, rc;

	/* The directory on the host, the file by its name in the jail. */
	path = REPO_FILE;
	text = wfmt(w, BASE_REPO ": {\n  url: \"pkg+https://pkg.FreeBSD.org/"
	    "${ABI}/%s\",\n  mirror_type: \"srv\",\n  signature_type: "
	    "\"fingerprints\",\n  fingerprints: \"/usr/share/keys/pkg\",\n  "
	    "enabled: yes\n}\n", branch);
	len = strlen(text);
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", path);
	e = NULL;
	rc = mkdirs(wfmt(w, "%s" REPO_FILE, root)) == -1 ? -1 : scope_replace(w,
	    path, text, len, 0644, NULL);
	if (rc != 0)
		e = wfmt(w, "%s: %s", path, strerror(errno));
	step_end(w, step, e == NULL, "%s", e != NULL ? e : branch);
	return (e);
}

/* The jail's /etc kept aside, whole, before the base changes. */
static const char *
etc_backup(struct work *w, const char *root)
{
	struct execres	 res;
	char		*argv[8];
	const char	*tar;

	tar = wfmt(w, "%s" ETC_BACKUP, root);
	if (mkdirs(tar) == -1)
		return (wfmt(w, "%s: %s", tar, strerror(errno)));
	argv[0] = (char *)(uintptr_t)PATH_TAR;
	argv[1] = (char *)(uintptr_t)"-C";
	argv[2] = (char *)(uintptr_t)root;
	argv[3] = (char *)(uintptr_t)"-cf";
	argv[4] = (char *)(uintptr_t)tar;
	argv[5] = (char *)(uintptr_t)"etc";
	argv[6] = NULL;
	if (run_exec(w, argv, &res) != 0)
		return (wtext(w, exec_error(w, &res, "tar of etc")));
	return (NULL);
}

/*
 * The files named name under the jail's /etc, as the jail has them
 * ("/etc/group.pkgsave"), one a line; "" for none.
 */
static char *
etc_named(struct work *w, const char *root, const char *name)
{
	struct execres	 res;
	char		*argv[8], *out, *line, *next, *o;
	size_t		 rl;

	argv[0] = (char *)(uintptr_t)PATH_FIND;
	argv[1] = wfmt(w, "%s/etc", root);
	argv[2] = (char *)(uintptr_t)"-type";
	argv[3] = (char *)(uintptr_t)"f";
	argv[4] = (char *)(uintptr_t)"-name";
	argv[5] = (char *)(uintptr_t)name;
	argv[6] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return (wstrdup(w, ""));
	rl = strlen(root);
	out = o = wcalloc(w, res.outlen + 1, 1);
	for (line = wstrndup(w, res.out, res.outlen); line != NULL &&
	    *line != '\0'; line = next) {
		if ((next = strchr(line, '\n')) != NULL)
			*next++ = '\0';
		if (strncmp(line, root, rl) != 0 || line[rl] != '/')
			continue;
		o = stpcpy(o, line + rl);
		*o++ = '\n';
	}
	*o = '\0';
	return (out);
}

/* Is path one of the lines of list? */
static bool
listed(const char *list, const char *path)
{
	const char	*p;
	size_t		 n;

	n = strlen(path);
	for (p = list; (p = strstr(p, path)) != NULL; p += n)
		if ((p == list || p[-1] == '\n') && p[n] == '\n')
			return (true);
	return (false);
}

/* Does a line of an account file have value as its field n (0: the
 * name, 2: the uid or gid)? */
static bool
has_field(const char *text, int n, const char *value, size_t len)
{
	const char	*l, *f;
	int		 i;

	for (l = text; *l != '\0'; l += strcspn(l, "\n"), l += *l == '\n') {
		if (*l == '#')
			continue;
		for (f = l, i = 0; i < n; i++) {
			f += strcspn(f, ":\n");
			if (*f != ':')
				break;
			f++;
		}
		if (i == n && strncmp(f, value, len) == 0 && (f[len] == ':' ||
		    f[len] == '\n' || f[len] == '\0'))
			return (true);
	}
	return (false);
}

/*
 * The jail's account file (master.passwd, group) with the accounts of
 * the package's that it has not, added at its end: the jail's users
 * and groups are kept, and the new base's own (a daemon's user that
 * came with the release) are there too.  One whose name or id the jail
 * has already is left out, and named in *skippedp.
 */
static char *
accounts_merge(struct work *w, const char *own, const char *pkgs,
    int *addedp, const char **skippedp)
{
	const char	*l, *colon, *id;
	char		*out, *o;
	size_t		 ll, nl, il;

	*addedp = 0;
	*skippedp = NULL;
	out = o = wcalloc(w, strlen(own) + strlen(pkgs) + 2, 1);
	o = stpcpy(o, own);
	if (o > out && o[-1] != '\n')
		*o++ = '\n';
	for (l = pkgs; *l != '\0'; l += ll + (l[ll] == '\n')) {
		ll = strcspn(l, "\n");
		if (ll == 0 || *l == '#' || (colon = memchr(l, ':', ll)) ==
		    NULL)
			continue;
		nl = (size_t)(colon - l);
		if (has_field(own, 0, l, nl))
			continue;
		/* The id: the third field. */
		id = colon + 1;
		id += strcspn(id, ":\n");
		id += *id == ':';
		il = strcspn(id, ":\n");
		if (il > 0 && has_field(own, 2, id, il)) {
			*skippedp = *skippedp == NULL ? wstrndup(w, l, nl) :
			    wfmt(w, "%s, %.*s", *skippedp, (int)nl, l);
			continue;
		}
		memcpy(o, l, ll);
		o += ll;
		*o++ = '\n';
		(*addedp)++;
	}
	*o = '\0';
	return (out);
}

/* A program of the jail's own run in it; NULL, or what went wrong. */
static const char *
in_jail(struct work *w, const char *prog, const char *a1, const char *a2,
    const char *a3, const char *a4)
{
	struct execres	 res;
	char		*argv[6];

	argv[0] = (char *)(uintptr_t)prog;
	argv[1] = (char *)(uintptr_t)a1;
	argv[2] = (char *)(uintptr_t)a2;
	argv[3] = (char *)(uintptr_t)a3;
	argv[4] = (char *)(uintptr_t)a4;
	argv[5] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0)
		return (wtext(w, exec_error(w, &res, prog)));
	return (NULL);
}

/*
 * The jail's own files back, those of /etc that pkg put aside as it
 * installed the packages' in their place: on a conversion no package
 * had them before, so pkg had nothing to merge with, moved the jail's
 * master.passwd, group, login.conf... to .pkgsave and put the stock
 * ones there, and FreeBSD-runtime's pwd_mkdb then made the user
 * database of the stock master.passwd: the jail's users and groups
 * were gone.  Each comes back in its place, the package's left beside
 * it as .pkgnew; the account files are merged instead (accounts_merge());
 * the databases made of them are made again, in the jail.  Only the
 * .pkgsave files that were not there before (before) are taken.
 * NULL, or what went wrong.
 */
static const char *
keep_own(struct work *w, const char *root, const char *before)
{
	const char	*e, *skipped, *done, *base;
	char		*list, *p, *next, *live, *own, *pkgs, *merged, *keep;
	size_t		 n;
	int		 step, added, users, groups;
	bool		 pw, cap, svc, ok;

	list = etc_named(w, root, "*.pkgsave");
	done = NULL;
	e = NULL;
	users = groups = 0;
	pw = cap = svc = false;
	for (p = list; *p != '\0'; p = next) {
		next = p + strcspn(p, "\n");
		if (*next == '\n')
			*next++ = '\0';
		if (listed(before, p))
			continue;
		n = strlen(p) - strlen(".pkgsave");
		live = wstrndup(w, p, n);
		base = strrchr(live, '/') + 1;
		keep = wfmt(w, "%s.pkgnew", base);
		if (strcmp(live, "/etc/master.passwd") == 0 ||
		    strcmp(live, "/etc/group") == 0) {
			if ((own = scope_slurp(w, p, NULL)) == NULL ||
			    (pkgs = scope_slurp(w, live, NULL)) == NULL) {
				e = wfmt(w, "%s: %s", own == NULL ? p : live,
				    strerror(errno));
				break;
			}
			merged = accounts_merge(w, own, pkgs, &added, &skipped);
			if (scope_replace(w, live, merged, strlen(merged),
			    live[5] == 'm' ? 0600 : 0644, keep) == -1 ||
			    scope_unlink(w, p) == -1) {
				e = wfmt(w, "%s: %s", live, strerror(errno));
				break;
			}
			if (live[5] == 'm')
				users += added;
			else
				groups += added;
			if (skipped != NULL)
				done = wfmt(w, "%s%s%s (not added from the new "
				    "base, its name or id taken: %s)", done !=
				    NULL ? done : "", done != NULL ? ", " : "",
				    base, skipped);
			else
				done = wfmt(w, "%s%s%s", done != NULL ? done : "",
				    done != NULL ? ", " : "", base);
			pw = pw || live[5] == 'm';
			continue;
		}
		/* The package's aside, the jail's back in its place. */
		if ((scope_rename(w, live, base, keep) == -1 && errno !=
		    ENOENT) || scope_rename(w, live, wfmt(w, "%s.pkgsave",
		    base), base) == -1) {
			e = wfmt(w, "%s: %s", live, strerror(errno));
			break;
		}
		done = wfmt(w, "%s%s%s", done != NULL ? done : "", done != NULL ?
		    ", " : "", base);
		cap = cap || strcmp(live, "/etc/login.conf") == 0;
		svc = svc || strcmp(live, "/etc/services") == 0;
	}
	if (done == NULL && e == NULL)
		return (NULL);
	step = step_begin(w, ARC_STEP_KIND_FILE, "keep", "the jail's own files "
	    "that pkg put aside");
	ok = e == NULL;
	if (ok && pw)
		e = in_jail(w, "/usr/sbin/pwd_mkdb", "-p", "/etc/master.passwd",
		    NULL, NULL);
	if (ok && e == NULL && cap)
		e = in_jail(w, "/usr/bin/cap_mkdb", "/etc/login.conf", NULL,
		    NULL, NULL);
	if (ok && e == NULL && svc)
		e = in_jail(w, "/usr/sbin/services_mkdb", "-q", "-o",
		    "/var/db/services.db", "/etc/services");
	if (e != NULL) {
		step_end(w, step, false, "%s%s%s: the jail's /etc is in %s",
		    done != NULL ? done : "", done != NULL ? " kept; " : "", e,
		    ETC_BACKUP);
		return (wfmt(w, "the jail's own files: %s", e));
	}
	step_end(w, step, true, "kept: %s%s%s", done, users > 0 ? wfmt(w,
	    "; the new base's users added: %d", users) : "", groups > 0 ?
	    wfmt(w, "; its groups added: %d", groups) : "");
	return (NULL);
}

/* What pkg left beside the jail's files, under /etc, named in a step
 * for the admin to merge; nothing is an error. */
static void
leftovers(struct work *w, const char *root)
{
	char	*list, *p;
	int	 step;

	list = etc_named(w, root, "*.pkgnew");
	for (p = list; (p = strchr(p, '\n')) != NULL; p++)
		if (p[1] != '\0')
			*p = ' ';
	if ((p = strrchr(list, '\n')) != NULL)
		*p = '\0';
	step = step_begin(w, ARC_STEP_KIND_FILE, "merge", "what pkg left beside "
	    "the files it kept");
	step_end(w, step, true, "%s%s", list[0] != '\0' ? list : "none: restart "
	    "the jail for the new base to run", list[0] != '\0' ? ": the "
	    "packages' versions of the jail's own files, which were kept; "
	    "merge what is new in them, then restart the jail" : "");
}

/* A set's name as the repository has them. */
static bool
valid_set(const char *s)
{

	if (strncmp(s, "FreeBSD-set-", 12) != 0 || strlen(s) > 64)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.+-", *s) == NULL)
			return (false);
	return (true);
}

/*
 * The sets the repository offers (FreeBSD-set-*), a step of the trace;
 * NULL and *errp when one asked for is not among them.
 */
static const char *
sets_check(struct work *w, const struct arc_job_spec *sp, const char *repo,
    bool anyos, const char *abi, const char *osversion,
    const char *const *sets, size_t nsets)
{
	const char	*query[] = { "rquery", "-a", "-r", repo, "%n" };
	struct execres	 res;
	const char	*have, *missing;
	char		*copy, *it, *line;
	size_t		 i;
	bool		 found;

	if (pkg(w, sp, anyos, abi, osversion, query, 5, &res) != 0)
		return (pkg_failed(w, &res, "pkg rquery"));
	have = NULL;
	copy = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
	for (it = copy; (line = strsep(&it, "\n")) != NULL; )
		if (strncmp(line, "FreeBSD-set-", 12) == 0 && strstr(line,
		    "-dbg") == NULL)
			have = have == NULL ? wstrdup(w, line) : wfmt(w, "%s, %s",
			    have, line);
	missing = NULL;
	for (i = 0; i < nsets; i++) {
		found = false;
		copy = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
		for (it = copy; (line = strsep(&it, "\n")) != NULL; )
			if (strcmp(line, sets[i]) == 0)
				found = true;
		if (!found)
			missing = missing == NULL ? sets[i] : wfmt(w, "%s, %s",
			    missing, sets[i]);
	}
	if (missing != NULL)
		return (wfmt(w, "repository %s has no %s; its sets: %s", repo,
		    missing, have != NULL ? have : "none"));
	return (NULL);
}

/*
 * convert: the base system packages installed over the jail's files
 * from the FreeBSD-base repository of its release (or of the branch
 * release names): the sets named, FreeBSD-set-base-jail when none.
 */
/*
 * The repository the base comes from: one of the jail's own when the
 * job names it (pkg-repo; it must be there), else the official one,
 * written under arcana's name for the branch.  NULL and *errp when
 * neither can be.
 */
static const char *
base_repo(struct work *w, const struct arc_job_spec *sp, const char *root,
    const char *branch, const char **errp)
{
	const char	*e;

	if (sp->pkg_repo != NULL && sp->pkg_repo[0] != '\0') {
		if ((e = pkg_repo_check(w, sp->jail, sp->pkg_repo)) != NULL) {
			*errp = e;
			return (NULL);
		}
		return (sp->pkg_repo);
	}
	if ((e = repo_write(w, root, branch)) != NULL) {
		*errp = e;
		return (NULL);
	}
	return (BASE_REPO);
}

static int
convert(struct work *w, const struct arc_job_spec *sp, const char *root,
    const char *osrelease, const char **errp)
{
	struct release	 r;
	struct execres	 res;
	const char *const *sets;
	const char	**args, **one, *e, *branch, *repo, *update[3];
	char		 *before;
	size_t		 nsets, n, i;
	bool		 major_alone;

	if (!parse_release(osrelease, &r)) {
		*errp = wfmt(w, "the jail's release is not known (%s)",
		    osrelease != NULL ? osrelease : "none");
		return (-1);
	}
	if (r.major < 15 || (r.major == 15 && r.minor < 1 && !r.branch)) {
		*errp = wfmt(w, "pkgbase needs FreeBSD 15.1 or later; the jail "
		    "runs %s", osrelease);
		return (-1);
	}
	if (on_pkgbase(w, sp)) {
		*errp = wfmt(w, "jail %s is on pkgbase already (FreeBSD-runtime "
		    "is installed)", sp->jail);
		return (-1);
	}
	if (sp->names.n > 0) {
		sets = sp->names.v;
		nsets = sp->names.n;
		for (i = 0; i < nsets; i++)
			if (sets[i] == NULL || !valid_set(sets[i])) {
				*errp = wfmt(w, "'%s' is not a set's name "
				    "(FreeBSD-set-...)", sets[i] != NULL ?
				    sets[i] : "");
				return (-1);
			}
	} else {
		one = wcalloc(w, 1, sizeof(*one));
		one[0] = BASE_SET;
		sets = one;
		nsets = 1;
	}
	/* The branch: the jail's own release, unless one is named. */
	major_alone = false;
	if (sp->release != NULL && sp->release[0] != '\0') {
		if (!parse_release(sp->release, &r)) {
			*errp = wfmt(w, "'%s' is not a release: 16, or 15.2",
			    sp->release);
			return (-1);
		}
		major_alone = strchr(sp->release, '.') == NULL;
	}
	branch = branch_of(w, &r, major_alone);
	if ((repo = base_repo(w, sp, root, branch, errp)) == NULL)
		return (-1);
	if ((e = etc_backup(w, root)) != NULL) {
		*errp = e;
		return (-1);
	}
	update[0] = "update";
	update[1] = "-r";
	update[2] = repo;
	if (pkg(w, sp, sp->force, NULL, NULL, update, 3, &res) != 0 || (e =
	    pkg_repo_error(w, &res, "pkg update")) != NULL) {
		*errp = wfmt(w, "repository %s: %s", repo, e != NULL ? e :
		    pkg_failed(w, &res, "pkg update"));
		return (-1);
	}
	if ((e = sets_check(w, sp, repo, sp->force, NULL, NULL, sets, nsets))
	    != NULL) {
		*errp = e;
		return (-1);
	}
	before = etc_named(w, root, "*.pkgsave");
	args = wcalloc(w, nsets + 5, sizeof(*args));
	n = 0;
	args[n++] = "install";
	args[n++] = "-r";
	args[n++] = repo;
	args[n++] = "-y";
	for (i = 0; i < nsets; i++)
		args[n++] = sets[i];
	if (pkg(w, sp, sp->force, NULL, NULL, args, n, &res) != 0 || (e =
	    pkg_repo_error(w, &res, "pkg install")) != NULL) {
		*errp = e != NULL ? e : pkg_failed(w, &res, "pkg install");
		keep_own(w, root, before);
		return (-1);
	}
	if ((e = keep_own(w, root, before)) != NULL) {
		*errp = e;
		return (-1);
	}
	leftovers(w, root);
	return (0);
}

/*
 * upgrade: a jail on pkgbase taken to release ("16": the latest of
 * that major; "15.2": that release): its base packages from the
 * FreeBSD-base repository of the new ABI, then its other packages for
 * it.  Never beyond the host's kernel: a userland newer than the
 * kernel does not run.
 */
static int
upgrade(struct work *w, const struct arc_job_spec *sp, const char *root,
    const char **errp)
{
	static const char *const rest[] = { "upgrade", "-y" };
	struct release	 r;
	struct execres	 res;
	const char	*e, *abi, *osversion, *repo, *update[3], *base[4];
	char		*before;
	char		 arch[64];
	size_t		 len;
	int		 hostrel;
	bool		 major_alone;

	if (sp->release == NULL || sp->release[0] == '\0' || !parse_release(
	    sp->release, &r)) {
		*errp = wfmt(w, "'%s' is not a release to go to: 16, or 15.2",
		    sp->release != NULL ? sp->release : "");
		return (-1);
	}
	major_alone = strchr(sp->release, '.') == NULL;
	if (!on_pkgbase(w, sp)) {
		*errp = wfmt(w, "jail %s is not on pkgbase: convert it first",
		    sp->jail);
		return (-1);
	}
	len = sizeof(hostrel);
	if (sysctlbyname("kern.osreldate", &hostrel, &len, NULL, 0) == -1)
		hostrel = 0;
	if (hostrel > 0 && r.major > hostrel / 100000) {
		*errp = wfmt(w, "the host's kernel is FreeBSD %d: a jail cannot "
		    "run a newer userland than that", hostrel / 100000);
		return (-1);
	}
	len = sizeof(arch);
	if (sysctlbyname("hw.machine_arch", arch, &len, NULL, 0) == -1) {
		*errp = "hw.machine_arch is not known";
		return (-1);
	}
	abi = wfmt(w, "FreeBSD:%d:%s", r.major, arch);
	osversion = wfmt(w, "%d", r.major * 100000 + r.minor * 1000);
	if ((repo = base_repo(w, sp, root, branch_of(w, &r, major_alone),
	    errp)) == NULL)
		return (-1);
	if ((e = etc_backup(w, root)) != NULL) {
		*errp = e;
		return (-1);
	}
	update[0] = "update";
	update[1] = "-r";
	update[2] = repo;
	base[0] = "upgrade";
	base[1] = "-r";
	base[2] = repo;
	base[3] = "-y";
	/* The new release's repository is for a newer FreeBSD by design:
	 * read past OSVERSION for the base; the rest as asked. */
	if (pkg(w, sp, true, abi, osversion, update, 3, &res) != 0 || (e =
	    pkg_repo_error(w, &res, "pkg update")) != NULL) {
		*errp = wfmt(w, "repository %s: %s", repo, e != NULL ? e :
		    pkg_failed(w, &res, "pkg update"));
		return (-1);
	}
	before = etc_named(w, root, "*.pkgsave");
	if (pkg(w, sp, true, abi, osversion, base, 4, &res) != 0 || (e =
	    pkg_repo_error(w, &res, "pkg upgrade")) != NULL) {
		*errp = wfmt(w, "repository %s: %s", repo, e != NULL ? e :
		    pkg_failed(w, &res, "pkg upgrade of the base"));
		keep_own(w, root, before);
		return (-1);
	}
	if ((e = keep_own(w, root, before)) != NULL) {
		*errp = e;
		return (-1);
	}
	if (pkg(w, sp, sp->force, abi, osversion, rest, 2, &res) != 0 || (e =
	    pkg_repo_error(w, &res, "pkg upgrade")) != NULL) {
		leftovers(w, root);
		*errp = wfmt(w, "the base is on %s; the other packages are not: "
		    "%s", sp->release, e != NULL ? e : pkg_failed(w, &res,
		    "pkg upgrade"));
		return (-1);
	}
	leftovers(w, root);
	return (0);
}

int
do_jail_base(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const char	*root, *osrelease, *e;

	if (sp->verb == NULL) {
		*errp = "verb convert or upgrade";
		return (-1);
	}
	osrelease = NULL;
	if ((e = jail_of(w, sp->jail, &osrelease)) != NULL) {
		*errp = e;
		return (-1);
	}
	root = w->jroot;
	if (strcmp(sp->verb, "convert") == 0)
		return (convert(w, sp, root, osrelease, errp));
	if (strcmp(sp->verb, "upgrade") == 0)
		return (upgrade(w, sp, root, errp));
	*errp = wfmt(w, "'%s': verb convert or upgrade", sp->verb);
	return (-1);
}
