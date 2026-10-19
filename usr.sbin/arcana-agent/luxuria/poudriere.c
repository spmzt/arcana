/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: poudriere(8), the ports' package builder, a plugin of the
 * host's (it is not looked for in a jail, as it makes jails itself).
 *
 * What it has is read where poudriere keeps it, not parsed from its
 * tables: each build jail is a directory of poudriere.d/jails, each
 * ports tree one of poudriere.d/ports, a file a value (version, arch,
 * method, mnt, fs, timestamp: what its jset and pset write); the
 * make.conf files beside them, read whole; poudriere.conf's
 * assignments; each package repository under the data directory's
 * packages (BASEFS/data unless POUDRIERE_DATA says), with how many
 * packages it has; and the latest build of each, as poudriere status
 * -f -H -l tells it, a tab between its fields.
 *
 * A build takes hours, a jail or a ports tree made minutes: what would
 * hold the job queue that long is a run instead, started and left.  The
 * job starts poudriere under a process of its own that waits for it
 * (two forks: init reaps that one, so neither is the agent's child, and
 * both outlive the agent's restart), and comes back with the run's
 * number.  The run's output goes to its log, beside a file the waiter
 * writes poudriere's pid to and one it writes the exit status to when
 * poudriere ends; what the agent knows of a run is those files.  A run
 * is stopped as a terminal stops it, SIGINT to its process group:
 * poudriere's traps tear its build jails down.  The last RUNS_KEPT are
 * kept.
 *
 * The rest is done in the job: a jail or ports tree deleted (-y, as
 * nothing answers poudriere's question), a make.conf written or taken
 * away, poudriere.conf's variables set by sysrc -f.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	RUNS_DIR	"builder"
#define	RUNS_KEPT	20
#define	RUNS_TAILED	10		/* the newest, with their log's end */
#define	TAIL_BYTES	8192
#define	VALUE_MAX	4096		/* a jset/pset file, read */
#define	MAKECONF_MAX	(64 * 1024)
#define	LIST_MAX	256		/* jails, trees, repositories */
#define	FAILED_MAX	32		/* a build's failed ports, with their log */

extern char	**environ;

static int		 options_set(struct work *, const struct arc_job_spec *,
			    const char **);
static ucl_object_t	*options_dirs(struct work *);
static bool		 option_ok(const char *);

/* poudriere.conf's variables a job may set. */
static const char *const conf_keys[] = {
	"ZPOOL", "ZROOTFS", "NO_ZFS", "BASEFS", "POUDRIERE_DATA",
	"FREEBSD_HOST", "DISTFILES_CACHE", "USE_TMPFS", "TMPFS_LIMIT",
	"MAX_MEMORY", "PARALLEL_JOBS", "PREPARE_PARALLEL_JOBS",
	"ALLOW_MAKE_JOBS", "ALLOW_MAKE_JOBS_PACKAGES", "CCACHE_DIR",
	"USE_PORTLINT", "CHECK_CHANGED_OPTIONS", "CHECK_CHANGED_DEPS",
	"KEEP_OLD_PACKAGES", "KEEP_OLD_PACKAGES_COUNT", "PKG_REPO_SIGNING_KEY",
	"URL_BASE", "BUILDER_HOSTNAME", "TIMESTAMP_LOGS", "NOLINUX",
	"RESOLV_CONF",
};

static const char *
pd_bin(struct work *w __unused)
{

	return (opts.poudriere_bin);
}

static const char *
pd_conf(struct work *w)
{

	return (wfmt(w, "%s/poudriere.conf", opts.poudriere_etc));
}

static const char *
pd_dir(struct work *w)
{

	return (wfmt(w, "%s/poudriere.d", opts.poudriere_etc));
}

/* ---- Names and words ---------------------------------------------- */

/*
 * A jail's, a ports tree's or a set's name: letters, digits and _ : +
 * -, not first a -.  Not a dot, which poudriere refuses; a colon, which
 * it takes (a jail named as an ABI, FreeBSD:16:amd64).
 */
static bool
pd_name_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || s[0] == '-' || strlen(s) > 64)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && strchr("_:+-", s[i]) ==
		    NULL)
			return (false);
	return (true);
}

/* category/port, with @flavor: as the ports tree names them. */
static bool
origin_ok(const char *s)
{
	const char	*slash;
	size_t		 i;

	if (s == NULL || (slash = strchr(s, '/')) == NULL || slash == s ||
	    slash[1] == '\0' || strchr(slash + 1, '/') != NULL ||
	    strlen(s) > 128 || s[0] == '-')
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && strchr("_.+-/@", s[i]) ==
		    NULL)
			return (false);
	return (strstr(s, "..") == NULL);
}

/* A word given to poudriere as it is: a version, an arch, a method, a
 * branch, a URL.  No space, no quote, not an option. */
static bool
word_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || s[0] == '-' || strlen(s) > 256)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if ((unsigned char)s[i] <= ' ' || s[i] == '\'' || s[i] == '"' ||
		    s[i] == '\\' || s[i] == '`' || s[i] == '$' || s[i] == 0x7f)
			return (false);
	return (true);
}

/* A method of poudriere jail -m: the release's sets fetched (http,
 * ftp, ftp-archive, freebsdci), pkgbase (the official repository, or
 * one at a path), a source tree or a tarball at a path, or a checkout
 * (git, svn, each with a scheme: git+https). */
static bool
from_vcs(const char *m)
{

	return (strcmp(m, "git") == 0 || strcmp(m, "svn") == 0 ||
	    strncmp(m, "git+", 4) == 0 || strncmp(m, "svn+", 4) == 0);
}

static bool
method_ok(const char *m)
{
	const char	*p;

	if (!word_ok(m))
		return (false);
	if (strcmp(m, "http") == 0 || strcmp(m, "ftp") == 0 || strcmp(m,
	    "ftp-archive") == 0 || strcmp(m, "freebsdci") == 0 || strcmp(m,
	    "pkgbase") == 0)
		return (true);
	if (strcmp(m, "git") == 0 || strcmp(m, "svn") == 0)
		return (true);
	if (from_vcs(m))
		return (m[4] != '\0' && strspn(m + 4,
		    "abcdefghijklmnopqrstuvwxyz") == strlen(m + 4));
	if (strncmp(m, "pkgbase=", 8) == 0)
		p = m + 8;
	else if (strncmp(m, "src=", 4) == 0 || strncmp(m, "tar=", 4) == 0)
		p = m + 4;
	else
		return (false);
	return (p[0] == '/' && strstr(p, "/../") == NULL && (strlen(p) < 3 ||
	    strcmp(p + strlen(p) - 3, "/..") != 0));
}

/* The value of key= among the job's words, or NULL; the n-th of it
 * when there are several. */
static const char *
arg(const struct arc_job_spec *sp, const char *key, size_t nth)
{
	size_t	i, k;

	k = strlen(key);
	for (i = 0; i < sp->names.n; i++)
		if (strncmp(sp->names.v[i], key, k) == 0 &&
		    sp->names.v[i][k] == '=' && nth-- == 0)
			return (sp->names.v[i] + k + 1);
	return (NULL);
}

/* Is key=yes among the job's words? */
static bool
yes(const struct arc_job_spec *sp, const char *key)
{
	const char	*v;

	return ((v = arg(sp, key, 0)) != NULL && strcmp(v, "yes") == 0);
}

static bool
conf_key_ok(const char *k, size_t len)
{
	size_t	i;

	for (i = 0; i < nitems(conf_keys); i++)
		if (strlen(conf_keys[i]) == len && strncmp(conf_keys[i], k,
		    len) == 0)
			return (true);
	return (false);
}

/* A run's number: digits. */
static bool
run_id_ok(const char *s)
{

	return (s != NULL && s[0] != '\0' && strlen(s) < 12 && strspn(s,
	    "0123456789") == strlen(s));
}

const char *
poudriere_check(const struct arc_job_spec *sp)
{
	const char	*v, *verb;
	size_t		 i;

	if (sp->jail != NULL && sp->jail[0] != '\0')
		return ("poudriere is the host's: it makes jails of its own");
	if (sp->safe)
		return ("what poudriere builds or removes is not taken back by "
		    "itself: not in safe mode");
	if ((verb = sp->verb) == NULL)
		return ("say what poudriere does: jail-create, jail-update, "
		    "jail-delete, ports-create, ports-update, ports-delete, "
		    "bulk, stop, make-conf, conf or options");
	for (i = 0; i < sp->names.n; i++)
		if (strchr(sp->names.v[i], '=') == NULL)
			return ("poudriere's words are key=value");
	if (strcmp(verb, "jail-create") == 0) {
		if (!pd_name_ok(arg(sp, "name", 0)))
			return ("a jail's name is letters, digits and _ : + -, "
			    "64 at most");
		if (!word_ok(arg(sp, "version", 0)))
			return ("say the FreeBSD version the jail has: "
			    "15.1-RELEASE, 16.0-CURRENT");
		if ((v = arg(sp, "arch", 0)) != NULL && !word_ok(v))
			return ("an arch is one word: amd64, arm64.aarch64");
		if ((v = arg(sp, "method", 0)) != NULL && !method_ok(v))
			return ("a method is http, ftp, ftp-archive, freebsdci, "
			    "pkgbase or pkgbase=/path, src=/path, tar=/path, "
			    "git or svn (git+https, svn+ssh ...)");
		/* -K: a kernel installed, GENERIC when it is empty. */
		if ((v = arg(sp, "kernel", 0)) != NULL && v[0] != '\0' &&
		    !pd_name_ok(v))
			return ("a kernel's name is its configuration's: "
			    "GENERIC, letters, digits and _ - ; empty for "
			    "GENERIC");
		if ((v = arg(sp, "build", 0)) != NULL && strcmp(v, "yes") !=
		    0 && strcmp(v, "no") != 0)
			return ("build is yes or no");
		if ((v = arg(sp, "pkgbase-set", 0)) != NULL && strcmp(v,
		    "yes") != 0 && strcmp(v, "no") != 0)
			return ("pkgbase-set is yes or no");
		/* -b builds a src= tree, which is otherwise installed as
		 * it was built; git and svn always build. */
		v = arg(sp, "method", 0);
		if (yes(sp, "build") && (v == NULL || strncmp(v, "src=", 4) !=
		    0))
			return ("build is for method src=/path (git and svn "
			    "always build; the others install what is built)");
		/* -B: the pkgbase set, of what is built here. */
		if (yes(sp, "pkgbase-set") && (v == NULL || !((strncmp(v,
		    "src=", 4) == 0 && yes(sp, "build")) || from_vcs(v))))
			return ("pkgbase-set is built from source: method "
			    "src=/path with build=yes, or git or svn");
		return (NULL);
	}
	if (strcmp(verb, "ports-create") == 0) {
		if (!pd_name_ok(arg(sp, "name", 0)))
			return ("a ports tree's name is letters, digits and "
			    "_ : + -, 64 at most");
		if ((v = arg(sp, "method", 0)) != NULL && !word_ok(v))
			return ("a method is one word: git+https, null");
		if ((v = arg(sp, "branch", 0)) != NULL && !word_ok(v))
			return ("a branch is one word: main, 2026Q4");
		if ((v = arg(sp, "url", 0)) != NULL && !word_ok(v))
			return ("a URL is one word");
		if ((v = arg(sp, "path", 0)) != NULL && (v[0] != '/' ||
		    !word_ok(v + 1)))
			return ("a ports tree's path is absolute");
		return (NULL);
	}
	if (strcmp(verb, "jail-update") == 0 || strcmp(verb,
	    "jail-delete") == 0 || strcmp(verb, "ports-update") == 0 ||
	    strcmp(verb, "ports-delete") == 0)
		return (pd_name_ok(arg(sp, "name", 0)) ? NULL : "name the jail "
		    "or the ports tree: letters, digits and _ : + -");
	if (strcmp(verb, "bulk") == 0) {
		if (!pd_name_ok(arg(sp, "jail", 0)))
			return ("name the jail the packages are built in");
		if ((v = arg(sp, "ports", 0)) != NULL && !pd_name_ok(v))
			return ("a ports tree's name is letters, digits and "
			    "_ : + -");
		if ((v = arg(sp, "set", 0)) != NULL && v[0] != '\0' &&
		    (!pd_name_ok(v) || strchr(v, '-') != NULL))
			return ("a set's name is letters, digits and _ : +: "
			    "a - would split the name poudriere makes of it");
		if ((v = arg(sp, "jobs", 0)) != NULL && (strspn(v,
		    "0123456789") != strlen(v) || v[0] == '\0' || atoi(v) < 1 ||
		    atoi(v) > 1024))
			return ("jobs is how many builders: 1 to 1024");
		if (arg(sp, "origin", 0) == NULL)
			return ("say what to build: origin=net/bird3, as many "
			    "as there are ports");
		for (i = 0; (v = arg(sp, "origin", i)) != NULL; i++)
			if (!origin_ok(v))
				return ("a port is its category and name: "
				    "net/bird3, www/py-requests@py311");
		return (NULL);
	}
	if (strcmp(verb, "stop") == 0)
		return (run_id_ok(arg(sp, "run", 0)) ? NULL : "say which run "
		    "is stopped: run=, its number");
	if (strcmp(verb, "options") == 0) {
		if (!pd_name_ok(arg(sp, "jail", 0)) || ((v = arg(sp, "ports",
		    0)) != NULL && !pd_name_ok(v)) || ((v = arg(sp, "set", 0)) !=
		    NULL && v[0] != '\0' && (!pd_name_ok(v) || strchr(v, '-') !=
		    NULL)))
			return ("name the jail, the ports tree and the set the "
			    "options are for");
		if (!origin_ok(arg(sp, "origin", 0)))
			return ("a port is its category and name: net/bird3");
		for (i = 0; (v = arg(sp, "on", i)) != NULL; i++)
			if (!option_ok(v))
				return ("an option is capitals, digits and _: "
				    "DEBUG, BGP");
		for (i = 0; (v = arg(sp, "off", i)) != NULL; i++)
			if (!option_ok(v))
				return ("an option is capitals, digits and _: "
				    "DEBUG, BGP");
		return (NULL);
	}
	if (strcmp(verb, "make-conf") == 0) {
		/* make.conf itself, or <name>-make.conf: a jail's, a
		 * tree's, a set's, or their names joined by -. */
		if ((v = arg(sp, "name", 0)) != NULL && v[0] != '\0' &&
		    !pd_name_ok(v))
			return ("a make.conf is named for a jail, a ports tree, "
			    "a set or those joined by -: letters, digits and "
			    "_ : + -");
		if (sp->text != NULL && (strlen(sp->text) > MAKECONF_MAX))
			return ("a make.conf is 64 KB at most");
		return (NULL);
	}
	if (strcmp(verb, "conf") == 0) {
		if (sp->names.n == 0)
			return ("say which of poudriere.conf's variables are "
			    "set: ZPOOL=zroot; an empty value unsets it");
		for (i = 0; i < sp->names.n; i++) {
			v = strchr(sp->names.v[i], '=');
			if (!conf_key_ok(sp->names.v[i], (size_t)(v -
			    sp->names.v[i])))
				return ("poudriere.conf's variables set from here "
				    "are ZPOOL, ZROOTFS, NO_ZFS, BASEFS, "
				    "POUDRIERE_DATA, FREEBSD_HOST, "
				    "DISTFILES_CACHE, USE_TMPFS, ...: see "
				    "arcana-agent(8)");
			if (v[1] != '\0' && !word_ok(v + 1))
				return ("a value is one word, without quotes");
		}
		return (NULL);
	}
	return ("poudriere does jail-create, jail-update, jail-delete, "
	    "ports-create, ports-update, ports-delete, bulk, stop, make-conf, "
	    "conf or options");
}

/* ---- Runs ------------------------------------------------------------ */

static const char *
runs_dir(struct work *w)
{
	char	buf[MAXPATHLEN];

	return (wstrdup(w, sdwan_conf_path(RUNS_DIR, buf, sizeof(buf))));
}

/* The runs' numbers, newest first. */
static int
runs_list(struct work *w, long **idsp)
{
	DIR		*d;
	struct dirent	*de;
	long		*ids, id;
	char		*end;
	int		 n, cap, i, k;

	*idsp = NULL;
	if ((d = opendir(runs_dir(w))) == NULL)
		return (0);
	ids = NULL;
	n = cap = 0;
	while ((de = readdir(d)) != NULL) {
		id = strtol(de->d_name, &end, 10);
		if (end == de->d_name || strcmp(end, ".json") != 0 || id <= 0)
			continue;
		if (n == cap) {
			cap = cap == 0 ? 32 : cap * 2;
			if ((ids = reallocf(ids, sizeof(*ids) * (size_t)cap)) ==
			    NULL) {
				closedir(d);
				return (0);
			}
		}
		ids[n++] = id;
	}
	closedir(d);
	/* Few: an insertion sort, descending. */
	for (i = 1; i < n; i++)
		for (k = i; k > 0 && ids[k - 1] < ids[k]; k--) {
			id = ids[k];
			ids[k] = ids[k - 1];
			ids[k - 1] = id;
		}
	if (ids != NULL)
		wadopt(w, ids);
	*idsp = ids;
	return (n);
}

/* A small file's first line, or NULL. */
static char *
first_line(struct work *w, const char *path)
{
	char	buf[VALUE_MAX];
	ssize_t	n;
	int	fd;

	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
		return (NULL);
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0)
		return (NULL);
	buf[n] = '\0';
	buf[strcspn(buf, "\n")] = '\0';
	return (wstrdup(w, buf));
}

/* A run's pid, when it has one and it still runs; 0 otherwise. */
static pid_t
run_pid(struct work *w, long id, int *exitp)
{
	const char	*dir, *s;
	pid_t		 pid;

	dir = runs_dir(w);
	*exitp = -1;
	if ((s = first_line(w, wfmt(w, "%s/%ld.exit", dir, id))) != NULL) {
		*exitp = atoi(s);
		return (0);
	}
	if ((s = first_line(w, wfmt(w, "%s/%ld.pid", dir, id))) == NULL ||
	    (pid = (pid_t)atoi(s)) <= 1)
		return (0);
	return (kill(pid, 0) == 0 || errno == EPERM ? pid : 0);
}

/* The last bytes of a run's log, from a line's start. */
static char *
log_tail(struct work *w, const char *path)
{
	char		*buf, *p;
	struct stat	 st;
	off_t		 from;
	ssize_t		 n;
	size_t		 i;
	int		 fd;

	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
		return (NULL);
	if (fstat(fd, &st) == -1 || (buf = wmalloc(w, TAIL_BYTES + 1)) ==
	    NULL) {
		close(fd);
		return (NULL);
	}
	from = st.st_size > TAIL_BYTES ? st.st_size - TAIL_BYTES : 0;
	n = pread(fd, buf, TAIL_BYTES, from);
	close(fd);
	if (n < 0)
		return (NULL);
	buf[n] = '\0';
	/* From the first whole line. */
	p = buf;
	if (from > 0 && strchr(buf, '\n') != NULL)
		p = strchr(buf, '\n') + 1;
	/* Not the colours a terminal would draw: their escape is left
	 * out, as any byte it would act on. */
	for (i = 0; p[i] != '\0'; i++)
		if ((unsigned char)p[i] < 0x20 && p[i] != '\n' && p[i] != '\t')
			p[i] = ' ';
	return (p);
}

/* Runs beyond the kept: their files taken away. */
static void
runs_prune(struct work *w)
{
	static const char *const ext[] = { "json", "log", "pid", "exit" };
	const char	*dir;
	long		*ids;
	size_t		 e;
	int		 n, i, x;

	n = runs_list(w, &ids);
	dir = runs_dir(w);
	for (i = RUNS_KEPT; i < n; i++) {
		if (run_pid(w, ids[i], &x) != 0)
			continue;	/* still running: kept */
		for (e = 0; e < nitems(ext); e++)
			(void)unlink(wfmt(w, "%s/%ld.%s", dir, ids[i], ext[e]));
	}
}

/* A number written with write(2) alone: after fork, nothing else. */
static void
put_num(int fd, long v)
{
	char	buf[24];
	int	i;
	bool	neg;

	neg = v < 0;
	if (neg)
		v = -v;
	i = sizeof(buf);
	buf[--i] = '\n';
	do {
		buf[--i] = (char)('0' + v % 10);
		v /= 10;
	} while (v > 0 && i > 1);
	if (neg)
		buf[--i] = '-';
	(void)write(fd, buf + i, sizeof(buf) - (size_t)i);
}

/*
 * poudriere started with argv as run id, its output in the run's log:
 * the agent forks a child that forks the waiter and ends; the waiter,
 * in a session of its own, forks poudriere, writes its pid, waits for
 * it and writes how it ended.  Between fork and exec only what is safe
 * in a child of a threaded process is called.
 */
static int
run_start(struct work *w, char *const argv[], const char *title, long *idp,
    const char **errp)
{
	struct sigaction	 sa;
	ucl_object_t		*meta, *words;
	sigset_t		 none;
	const char		*dir;
	char			*json, pidpath[MAXPATHLEN], exitpath[MAXPATHLEN];
	long			*ids, id;
	pid_t			 a, b, c;
	int			 logfd, nullfd, fd, st, step, i;

	dir = runs_dir(w);
	(void)mkdir(dir, 0750);
	id = runs_list(w, &ids) > 0 ? ids[0] + 1 : 1;
	meta = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(meta, ucl_object_fromint(id), "id", 0, false);
	ucl_object_insert_key(meta, ucl_object_fromstring(title), "title", 0,
	    false);
	ucl_object_insert_key(meta, ucl_object_fromint(time(NULL)), "started",
	    0, false);
	words = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; argv[i] != NULL; i++)
		ucl_array_append(words, ucl_object_fromstring(argv[i]));
	ucl_object_insert_key(meta, words, "argv", 0, false);
	json = (char *)ucl_object_emit(meta, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(meta);
	if (json == NULL || (fd = open(wfmt(w, "%s/%ld.json", dir, id),
	    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0640)) == -1) {
		free(json);
		*errp = wfmt(w, "%s: %s", dir, strerror(errno));
		return (-1);
	}
	(void)write(fd, json, strlen(json));
	close(fd);
	free(json);
	snprintf(pidpath, sizeof(pidpath), "%s/%ld.pid", dir, id);
	snprintf(exitpath, sizeof(exitpath), "%s/%ld.exit", dir, id);
	if ((logfd = open(wfmt(w, "%s/%ld.log", dir, id), O_WRONLY | O_CREAT |
	    O_TRUNC | O_CLOEXEC, 0640)) == -1 || (nullfd = open("/dev/null",
	    O_RDONLY | O_CLOEXEC)) == -1) {
		*errp = wfmt(w, "%s: %s", dir, strerror(errno));
		if (logfd != -1)
			close(logfd);
		return (-1);
	}
	step = step_begin(w, ARC_STEP_KIND_EXEC, argv[0], "run %ld: %s", id,
	    title);
	sigemptyset(&none);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	if ((a = fork()) == -1) {
		*errp = wfmt(w, "fork: %s", strerror(errno));
		close(logfd);
		close(nullfd);
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	if (a == 0) {
		/* The child: the waiter forked, then gone, so that init
		 * has the waiter. */
		if ((b = fork()) != 0)
			_exit(b == -1 ? 1 : 0);
		(void)setsid();
		(void)sigprocmask(SIG_SETMASK, &none, NULL);
		/*
		 * The waiter lives as long as the build: none of the agent's
		 * descriptors with it (its listening sockets would keep the
		 * port from an agent started again), only what poudriere is
		 * given.
		 */
		(void)dup2(nullfd, 0);
		(void)dup2(logfd, 1);
		(void)dup2(logfd, 2);
		closefrom(3);
		if ((c = fork()) == -1)
			_exit(1);
		if (c == 0) {
			/* poudriere: a process group of its own, which a
			 * stop signals whole, as a terminal would. */
			(void)setpgid(0, 0);
			(void)sigaction(SIGINT, &sa, NULL);
			(void)sigaction(SIGTERM, &sa, NULL);
			(void)sigaction(SIGHUP, &sa, NULL);
			(void)sigaction(SIGPIPE, &sa, NULL);
			(void)sigaction(SIGCHLD, &sa, NULL);
			execve(argv[0], argv, environ);
			(void)write(2, "poudriere could not be started\n", 31);
			_exit(127);
		}
		/* The waiter: what the stop is not for. */
		sa.sa_handler = SIG_IGN;
		(void)sigaction(SIGINT, &sa, NULL);
		(void)sigaction(SIGHUP, &sa, NULL);
		if ((fd = open(pidpath, O_WRONLY | O_CREAT | O_TRUNC, 0640)) !=
		    -1) {
			put_num(fd, (long)c);
			(void)close(fd);
		}
		while (waitpid(c, &st, 0) == -1)
			if (errno != EINTR)
				_exit(1);
		if ((fd = open(exitpath, O_WRONLY | O_CREAT | O_TRUNC, 0640)) !=
		    -1) {
			put_num(fd, WIFEXITED(st) ? WEXITSTATUS(st) :
			    WIFSIGNALED(st) ? 128 + WTERMSIG(st) : 255);
			(void)close(fd);
		}
		_exit(0);
	}
	close(logfd);
	close(nullfd);
	while (waitpid(a, &st, 0) == -1 && errno == EINTR)
		;
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		*errp = "the run's waiter could not be started";
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, "started; its log is %s/%ld.log", dir, id);
	*idp = id;
	runs_prune(w);
	return (0);
}

static int
run_stop(struct work *w, const char *ids, const char **errp)
{
	pid_t	pid;
	long	id;
	int	x, step;

	id = strtol(ids, NULL, 10);
	if ((pid = run_pid(w, id, &x)) == 0) {
		*errp = x >= 0 ? wfmt(w, "run %ld has ended already (exit %d)",
		    id, x) : wfmt(w, "run %ld is not running", id);
		return (-1);
	}
	step = step_begin(w, ARC_STEP_KIND_SYSCALL, "kill(2)",
	    "SIGINT to run %ld's process group %d", id, (int)pid);
	if (kill(-pid, SIGINT) == -1) {
		*errp = wfmt(w, "kill: %s", strerror(errno));
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, "poudriere tears its jails down and ends");
	return (0);
}

/* ---- The job ----------------------------------------------------------- */

static int
make_conf(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const char	*name, *path, *tmp;
	FILE		*fp;
	int		 step;
	bool		 ok;

	name = arg(sp, "name", 0);
	path = name != NULL && name[0] != '\0' ? wfmt(w, "%s/%s-make.conf",
	    pd_dir(w), name) : wfmt(w, "%s/make.conf", pd_dir(w));
	if (sp->text == NULL || sp->text[strspn(sp->text, " \t\r\n")] ==
	    '\0') {
		step = step_begin(w, ARC_STEP_KIND_FILE, path, "taken away");
		ok = unlink(path) == 0 || errno == ENOENT;
		if (!ok)
			*errp = wfmt(w, "%s: %s", path, strerror(errno));
		step_end(w, step, ok, ok ? NULL : "%s", *errp);
		return (ok ? 0 : -1);
	}
	step = step_begin(w, ARC_STEP_KIND_FILE, path, "written, %zu bytes",
	    strlen(sp->text));
	(void)mkdir(pd_dir(w), 0755);
	tmp = wfmt(w, "%s.arcana-new", path);
	ok = (fp = fopen(tmp, "w")) != NULL;
	if (ok) {
		ok = fputs(sp->text, fp) != EOF && (sp->text[strlen(sp->text) -
		    1] == '\n' || fputc('\n', fp) != EOF);
		ok = fclose(fp) == 0 && ok;
	}
	ok = ok && chmod(tmp, 0644) == 0 && rename(tmp, path) == 0;
	if (!ok) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		(void)unlink(tmp);
	}
	step_end(w, step, ok, ok ? NULL : "%s", *errp);
	return (ok ? 0 : -1);
}

/* poudriere.conf's variables by sysrc -f, an empty value by -x. */
static int
conf_set(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct execres	 res;
	char		*argv[6], *eq;
	size_t		 i;

	for (i = 0; i < sp->names.n; i++) {
		eq = strchr(sp->names.v[i], '=');
		argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
		argv[1] = (char *)(uintptr_t)"-f";
		argv[2] = (char *)(uintptr_t)pd_conf(w);
		if (eq[1] == '\0') {
			argv[3] = (char *)(uintptr_t)"-x";
			argv[4] = wfmt(w, "%.*s", (int)(eq - sp->names.v[i]),
			    sp->names.v[i]);
			argv[5] = NULL;
		} else {
			argv[3] = (char *)(uintptr_t)sp->names.v[i];
			argv[4] = NULL;
		}
		if (run_exec(w, argv, &res) != 0 && !(eq[1] == '\0' &&
		    res.err != NULL && strstr(res.err, "not set") != NULL)) {
			*errp = exec_error(w, &res, "sysrc");
			return (-1);
		}
	}
	return (0);
}

/* poudriere run in the job, to its end: a delete. */
static int
pd_now(struct work *w, char *const argv[], const char **errp)
{
	struct execres	res;

	if (run_exec(w, argv, &res) != 0) {
		*errp = exec_error(w, &res, "poudriere");
		return (-1);
	}
	return (0);
}

int
do_poudriere_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	const char	*verb, *v;
	char		*argv[64 + 16];
	long		 id;
	size_t		 i;
	int		 n;

	if ((*errp = poudriere_check(sp)) != NULL)
		return (-1);
	verb = sp->verb;
	if (strcmp(verb, "make-conf") == 0)
		return (make_conf(w, sp, errp));
	if (strcmp(verb, "conf") == 0)
		return (conf_set(w, sp, errp));
	if (strcmp(verb, "stop") == 0)
		return (run_stop(w, arg(sp, "run", 0), errp));
	if (strcmp(verb, "options") == 0)
		return (options_set(w, sp, errp));
	if (access(pd_bin(w), X_OK) != 0) {
		*errp = wfmt(w, "%s: not installed: poudriere is a plugin, "
		    "installed by hand (pkg install poudriere)", pd_bin(w));
		return (-1);
	}
	n = 0;
	argv[n++] = (char *)(uintptr_t)pd_bin(w);
#define	ADD(s)	(argv[n++] = (char *)(uintptr_t)(s))
	if (strncmp(verb, "jail-", 5) == 0) {
		ADD("jail");
		ADD(strcmp(verb, "jail-create") == 0 ? "-c" : strcmp(verb,
		    "jail-update") == 0 ? "-u" : "-d");
		if (strcmp(verb, "jail-delete") == 0)
			ADD("-y");
		ADD("-j");
		ADD(arg(sp, "name", 0));
		if (strcmp(verb, "jail-create") == 0) {
			ADD("-v");
			ADD(arg(sp, "version", 0));
			if ((v = arg(sp, "arch", 0)) != NULL) {
				ADD("-a");
				ADD(v);
			}
			if ((v = arg(sp, "method", 0)) != NULL) {
				ADD("-m");
				ADD(v);
			}
			if ((v = arg(sp, "kernel", 0)) != NULL) {
				ADD("-K");
				ADD(v);
			}
			if (yes(sp, "build"))
				ADD("-b");
			if (yes(sp, "pkgbase-set"))
				ADD("-B");
		}
	} else if (strncmp(verb, "ports-", 6) == 0) {
		ADD("ports");
		ADD(strcmp(verb, "ports-create") == 0 ? "-c" : strcmp(verb,
		    "ports-update") == 0 ? "-u" : "-d");
		if (strcmp(verb, "ports-delete") == 0)
			ADD("-y");
		ADD("-p");
		ADD(arg(sp, "name", 0));
		if (strcmp(verb, "ports-create") == 0) {
			if ((v = arg(sp, "method", 0)) != NULL) {
				ADD("-m");
				ADD(v);
			}
			if ((v = arg(sp, "branch", 0)) != NULL) {
				ADD("-B");
				ADD(v);
			}
			if ((v = arg(sp, "url", 0)) != NULL) {
				ADD("-U");
				ADD(v);
			}
			if ((v = arg(sp, "path", 0)) != NULL) {
				ADD("-M");
				ADD(v);
			}
		}
	} else {
		ADD("bulk");
		ADD("-j");
		ADD(arg(sp, "jail", 0));
		if ((v = arg(sp, "ports", 0)) != NULL) {
			ADD("-p");
			ADD(v);
		}
		if ((v = arg(sp, "set", 0)) != NULL && v[0] != '\0') {
			ADD("-z");
			ADD(v);
		}
		if ((v = arg(sp, "jobs", 0)) != NULL) {
			ADD("-J");
			ADD(v);
		}
		if ((v = arg(sp, "clean", 0)) != NULL && strcmp(v, "yes") == 0)
			ADD("-C");
		if ((v = arg(sp, "test", 0)) != NULL && strcmp(v, "yes") == 0)
			ADD("-t");
		for (i = 0; (v = arg(sp, "origin", i)) != NULL && n < 64 + 14;
		    i++)
			ADD(v);
	}
#undef	ADD
	argv[n] = NULL;
	if (strcmp(verb, "jail-delete") == 0 || strcmp(verb,
	    "ports-delete") == 0)
		return (pd_now(w, argv, errp));
	if (run_start(w, argv, poudriere_title(sp), &id, errp) != 0)
		return (-1);
	return (0);
}

/* The job's line. */
char *
poudriere_title(const struct arc_job_spec *sp)
{
	const char	*verb, *ports, *set, *name;
	char		*t;
	int		 rc;

	verb = sp->verb != NULL ? sp->verb : "";
	ports = arg(sp, "ports", 0);
	set = arg(sp, "set", 0);
	name = arg(sp, "name", 0);
	if (strcmp(verb, "bulk") == 0)
		rc = asprintf(&t, "poudriere bulk %s%s in %s%s%s%s%s",
		    arg(sp, "origin", 0) != NULL ? arg(sp, "origin", 0) : "",
		    arg(sp, "origin", 1) != NULL ? " and more" : "",
		    arg(sp, "jail", 0) != NULL ? arg(sp, "jail", 0) : "",
		    ports != NULL ? " with " : "", ports != NULL ? ports : "",
		    set != NULL && set[0] != '\0' ? ", set " : "", set != NULL ?
		    set : "");
	else if (strcmp(verb, "stop") == 0)
		rc = asprintf(&t, "poudriere run %s stopped", arg(sp, "run", 0) !=
		    NULL ? arg(sp, "run", 0) : "");
	else if (strcmp(verb, "make-conf") == 0)
		rc = asprintf(&t, "poudriere %s%smake.conf %s", name != NULL ?
		    name : "", name != NULL && name[0] != '\0' ? "-" : "",
		    sp->text == NULL || sp->text[0] == '\0' ? "taken away" :
		    "written");
	else if (strcmp(verb, "options") == 0)
		rc = asprintf(&t, "poudriere options of %s%s", arg(sp, "origin",
		    0) != NULL ? arg(sp, "origin", 0) : "", arg(sp, "reset", 0) !=
		    NULL ? ": the port's defaults" : "");
	else if (strcmp(verb, "conf") == 0)
		rc = asprintf(&t, "poudriere.conf: %s%s", sp->names.n > 0 ?
		    sp->names.v[0] : "", sp->names.n > 1 ? " and more" : "");
	else
		rc = asprintf(&t, "poudriere %s %s", verb, name != NULL ? name :
		    "");
	if (rc == -1)
		err(1, "asprintf");
	return (t);
}

/* ---- The read ------------------------------------------------------- */

/* Each small file of a directory a key of o, its first line the value:
 * what jset and pset write. */
static void
dir_values(struct work *w, const char *dir, ucl_object_t *o)
{
	DIR		*d;
	struct dirent	*de;
	struct stat	 st;
	const char	*p;
	char		*v, *end;
	long long	 num;

	if ((d = opendir(dir)) == NULL)
		return;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		p = wfmt(w, "%s/%s", dir, de->d_name);
		if (stat(p, &st) == -1 || !S_ISREG(st.st_mode) ||
		    st.st_size > VALUE_MAX || (v = first_line(w, p)) == NULL)
			continue;
		num = strtoll(v, &end, 10);
		if (strcmp(de->d_name, "timestamp") == 0 && end != v &&
		    *end == '\0')
			ucl_object_insert_key(o, ucl_object_fromint(num),
			    de->d_name, 0, true);
		else
			ucl_object_insert_key(o, ucl_object_fromstring(v),
			    de->d_name, 0, true);
	}
	closedir(d);
}

/* poudriere.d/jails or ports: an object for each, with its name. */
static ucl_object_t *
entries(struct work *w, const char *kind)
{
	ucl_object_t	*arr, *o;
	struct dirent	*de;
	DIR		*d;
	const char	*dir;
	int		 n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	dir = wfmt(w, "%s/%s", pd_dir(w), kind);
	if ((d = opendir(dir)) == NULL)
		return (arr);
	n = 0;
	while ((de = readdir(d)) != NULL && n < LIST_MAX) {
		if (de->d_name[0] == '.')
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(de->d_name),
		    "name", 0, false);
		dir_values(w, wfmt(w, "%s/%s", dir, de->d_name), o);
		ucl_array_append(arr, o);
		n++;
	}
	closedir(d);
	return (arr);
}

/* A shell assignment's value: quotes taken off, ${VAR} of an earlier
 * one put in. */
static char *
conf_value(struct work *w, const char *v, const ucl_object_t *conf)
{
	const ucl_object_t	*e;
	char			*out, *p, name[64];
	size_t			 k, used;
	char			 q;

	q = (v[0] == '"' || v[0] == '\'') ? v[0] : '\0';
	if (q != '\0')
		v++;
	out = wmalloc(w, VALUE_MAX);
	used = 0;
	for (p = (char *)(uintptr_t)v; *p != '\0' && used + 1 < VALUE_MAX;
	    p++) {
		if (q != '\0' && *p == q)
			break;
		if (q == '\0' && (*p == ' ' || *p == '\t' || *p == '#'))
			break;
		if (*p == '$' && p[1] == '{' && q != '\'' &&
		    (k = strcspn(p + 2, "}:")) < sizeof(name) && p[2 + k] ==
		    '}') {
			snprintf(name, sizeof(name), "%.*s", (int)k, p + 2);
			if ((e = ucl_object_lookup(conf, name)) != NULL) {
				used += strlcpy(out + used,
				    ucl_object_tostring(e), VALUE_MAX - used);
				if (used >= VALUE_MAX)
					used = VALUE_MAX - 1;
			}
			p += k + 2;
			continue;
		}
		out[used++] = *p;
	}
	out[used] = '\0';
	return (out);
}

static void
pd_conf_read(struct work *w, const char *path, ucl_object_t *conf)
{
	char	*text, *line, *p, *eq;
	size_t	 len;

	if ((text = scope_slurp(w, path, &len)) == NULL)
		return;
	while ((line = strsep(&text, "\n")) != NULL) {
		p = line + strspn(line, " \t");
		if (*p == '#' || !isupper((unsigned char)*p) ||
		    (eq = strchr(p, '=')) == NULL)
			continue;
		*eq = '\0';
		if (p[strspn(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")] !=
		    '\0')
			continue;
		ucl_object_insert_key(conf, ucl_object_fromstring(conf_value(w,
		    eq + 1, conf)), p, 0, true);
	}
}

static ucl_object_t *
makeconfs(struct work *w)
{
	ucl_object_t	*arr, *o;
	struct dirent	*de;
	DIR		*d;
	const char	*dir, *p;
	char		*text;
	size_t		 len, nl;
	int		 n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	dir = pd_dir(w);
	if ((d = opendir(dir)) == NULL)
		return (arr);
	n = 0;
	while ((de = readdir(d)) != NULL && n < LIST_MAX) {
		nl = strlen(de->d_name);
		if (strcmp(de->d_name, "make.conf") != 0 && (nl <= 10 ||
		    strcmp(de->d_name + nl - 10, "-make.conf") != 0))
			continue;
		p = wfmt(w, "%s/%s", dir, de->d_name);
		if ((text = scope_slurp(w, p, &len)) == NULL ||
		    len > MAKECONF_MAX)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(strcmp(
		    de->d_name, "make.conf") == 0 ? "" : wfmt(w, "%.*s",
		    (int)(nl - 10), de->d_name)), "name", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(p), "file", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromlstring(text, len),
		    "text", 0, false);
		ucl_array_append(arr, o);
		n++;
	}
	closedir(d);
	return (arr);
}

/* Each repository under the data directory's packages, with how many
 * packages its All has. */
static ucl_object_t *
repos(struct work *w, const char *data)
{
	ucl_object_t	*arr, *o;
	struct dirent	*de, *pe;
	DIR		*d, *pd;
	const char	*dir;
	long long	 count;
	size_t		 nl;
	int		 n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	dir = wfmt(w, "%s/packages", data);
	if ((d = opendir(dir)) == NULL)
		return (arr);
	n = 0;
	while ((de = readdir(d)) != NULL && n < LIST_MAX) {
		if (de->d_name[0] == '.')
			continue;
		count = 0;
		if ((pd = opendir(wfmt(w, "%s/%s/All", dir, de->d_name))) !=
		    NULL) {
			while ((pe = readdir(pd)) != NULL)
				if ((nl = strlen(pe->d_name)) > 4 &&
				    strcmp(pe->d_name + nl - 4, ".pkg") == 0)
					count++;
			closedir(pd);
		}
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(de->d_name),
		    "name", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(wfmt(w, "%s/%s",
		    dir, de->d_name)), "path", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(count), "packages",
		    0, false);
		ucl_array_append(arr, o);
		n++;
	}
	closedir(d);
	return (arr);
}

/*
 * A build's ports that failed and were skipped, from its log
 * directory: .poudriere.ports.failed's lines are "origin pkgname phase
 * errortype elapsed" (errortype empty unless poudriere was told to
 * find one), each with the end of its log in logs/errors; skipped's
 * "origin pkgname" and the package that failed before them.
 */
static void
build_ports(struct work *w, ucl_object_t *o, const char *logs)
{
	ucl_object_t	*arr, *e;
	char		*text, *line, *f[6], *tail;
	size_t		 len;
	int		 n, k;

	if (logs == NULL || logs[0] != '/')
		return;
	arr = ucl_object_typed_new(UCL_ARRAY);
	if ((text = scope_slurp(w, wfmt(w, "%s/.poudriere.ports.failed",
	    logs), &len)) != NULL) {
		n = 0;
		while ((line = strsep(&text, "\n")) != NULL && n < FAILED_MAX) {
			for (k = 0; k < 6 && (f[k] = strsep(&line, " ")) != NULL;
			    k++)
				if (f[k][0] == '\0')
					k--;	/* an empty errortype's space */
			if (k < 3)
				continue;
			e = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(e, ucl_object_fromstring(f[0]),
			    "origin", 0, false);
			ucl_object_insert_key(e, ucl_object_fromstring(f[1]),
			    "package", 0, false);
			ucl_object_insert_key(e, ucl_object_fromstring(f[2]),
			    "phase", 0, false);
			/* The last word a number: the seconds it took. */
			if (k >= 4 && strspn(f[k - 1], "0123456789") ==
			    strlen(f[k - 1])) {
				ucl_object_insert_key(e, ucl_object_fromint(
				    strtoll(f[k - 1], NULL, 10)), "elapsed", 0,
				    false);
				k--;
			}
			if (k >= 4)
				ucl_object_insert_key(e, ucl_object_fromstring(
				    f[3]), "reason", 0, false);
			ucl_object_insert_key(e, ucl_object_fromstring(wfmt(w,
			    "%s/logs/errors/%s.log", logs, f[1])), "log_file", 0,
			    false);
			if ((tail = log_tail(w, wfmt(w, "%s/logs/errors/%s.log",
			    logs, f[1]))) != NULL)
				ucl_object_insert_key(e, ucl_object_fromstring(
				    tail), "log", 0, false);
			ucl_array_append(arr, e);
			n++;
		}
	}
	ucl_object_insert_key(o, arr, "failed_ports", 0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	if ((text = scope_slurp(w, wfmt(w, "%s/.poudriere.ports.skipped",
	    logs), &len)) != NULL) {
		n = 0;
		while ((line = strsep(&text, "\n")) != NULL && n < LIST_MAX) {
			for (k = 0; k < 3 && (f[k] = strsep(&line, " ")) != NULL;
			    k++)
				;
			if (k < 2 || f[0][0] == '\0')
				continue;
			e = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(e, ucl_object_fromstring(f[0]),
			    "origin", 0, false);
			ucl_object_insert_key(e, ucl_object_fromstring(f[1]),
			    "package", 0, false);
			if (k == 3)
				ucl_object_insert_key(e, ucl_object_fromstring(
				    f[2]), "because", 0, false);
			ucl_array_append(arr, e);
			n++;
		}
	}
	ucl_object_insert_key(o, arr, "skipped_ports", 0, false);
}

/* poudriere status -f -H -l: the latest build of each, a tab between
 * the fields. */
static ucl_object_t *
builds(struct work *w, const char **errp)
{
	static const char *const keys[] = { "set", "ports", "jail", "build",
	    "status", "queued", "inspected", "ignored", "built", "failed",
	    "skipped", "fetched", "remaining", "time", "logs" };
	struct execres	 res;
	ucl_object_t	*arr, *o;
	char		*argv[6], *text, *line, *f;
	char		*end;
	long long	 num;
	size_t		 k;

	arr = ucl_object_typed_new(UCL_ARRAY);
	argv[0] = (char *)(uintptr_t)pd_bin(w);
	argv[1] = (char *)(uintptr_t)"status";
	argv[2] = (char *)(uintptr_t)"-f";
	argv[3] = (char *)(uintptr_t)"-H";
	argv[4] = (char *)(uintptr_t)"-l";
	argv[5] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		/* None yet is said as a failure. */
		if (res.err == NULL || (strstr(res.err, "No ") == NULL &&
		    strstr(res.err, "no ") == NULL))
			*errp = exec_error(w, &res, "poudriere status");
		return (arr);
	}
	text = wstrdup(w, res.out != NULL ? res.out : "");
	while ((line = strsep(&text, "\n")) != NULL) {
		if (line[0] == '\0')
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		for (k = 0; k < nitems(keys) && (f = strsep(&line, "\t")) !=
		    NULL; k++) {
			num = strtoll(f, &end, 10);
			if (k >= 5 && k <= 12 && end != f && *end == '\0')
				ucl_object_insert_key(o, ucl_object_fromint(num),
				    keys[k], 0, false);
			else
				ucl_object_insert_key(o, ucl_object_fromstring(
				    strcmp(f, "-") == 0 ? "" : f), keys[k], 0,
				    false);
		}
		build_ports(w, o, ucl_object_tostring(ucl_object_lookup(o,
		    "logs")));
		ucl_array_append(arr, o);
	}
	return (arr);
}

static ucl_object_t *
runs(struct work *w)
{
	ucl_object_t		*arr, *o;
	struct ucl_parser	*p;
	const char		*dir;
	char			*meta, *tail;
	size_t			 len;
	long			*ids;
	pid_t			 pid;
	int			 n, i, x;

	arr = ucl_object_typed_new(UCL_ARRAY);
	n = runs_list(w, &ids);
	dir = runs_dir(w);
	for (i = 0; i < n && i < RUNS_KEPT; i++) {
		if ((meta = scope_slurp(w, wfmt(w, "%s/%ld.json", dir, ids[i]),
		    &len)) == NULL)
			continue;
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		o = ucl_parser_add_chunk(p, (unsigned char *)meta, len) ?
		    ucl_parser_get_object(p) : NULL;
		ucl_parser_free(p);
		if (o == NULL || ucl_object_type(o) != UCL_OBJECT) {
			if (o != NULL)
				ucl_object_unref(o);
			continue;
		}
		pid = run_pid(w, ids[i], &x);
		ucl_object_insert_key(o, ucl_object_fromstring(pid != 0 ?
		    "running" : x >= 0 ? (x == 0 ? "done" : "failed") : "lost"),
		    "state", 0, true);
		if (pid != 0)
			ucl_object_insert_key(o, ucl_object_fromint(pid), "pid",
			    0, true);
		if (x >= 0)
			ucl_object_insert_key(o, ucl_object_fromint(x), "exit",
			    0, true);
		ucl_object_insert_key(o, ucl_object_fromstring(wfmt(w,
		    "%s/%ld.log", dir, ids[i])), "log_file", 0, true);
		if ((i < RUNS_TAILED || pid != 0) && (tail = log_tail(w, wfmt(w,
		    "%s/%ld.log", dir, ids[i]))) != NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(tail),
			    "log", 0, true);
		ucl_array_append(arr, o);
	}
	return (arr);
}

void
do_builder(struct work *w, struct arc_builder_rsp *rsp)
{
	ucl_object_t		*top, *conf;
	const ucl_object_t	*v;
	const char		*basefs, *data, *berr;
	char			*json;
	bool			 have;

	have = access(pd_bin(w), X_OK) == 0;
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_frombool(have), "installed", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromstring(pd_bin(w)), "program",
	    0, false);
	ucl_object_insert_key(top, ucl_object_fromstring(pd_conf(w)),
	    "conf_file", 0, false);
	conf = ucl_object_typed_new(UCL_OBJECT);
	pd_conf_read(w, pd_conf(w), conf);
	pd_conf_read(w, wfmt(w, "%s/poudriere.conf", pd_dir(w)), conf);
	basefs = (v = ucl_object_lookup(conf, "BASEFS")) != NULL ?
	    ucl_object_tostring(v) : "/usr/local/poudriere";
	data = (v = ucl_object_lookup(conf, "POUDRIERE_DATA")) != NULL ?
	    ucl_object_tostring(v) : wfmt(w, "%s/data", basefs);
	ucl_object_insert_key(top, ucl_object_fromstring(basefs), "basefs", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromstring(data), "data", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_frombool(access(pd_conf(w),
	    F_OK) == 0), "configured", 0, false);
	ucl_object_insert_key(top, conf, "conf", 0, false);
	ucl_object_insert_key(top, entries(w, "jails"), "jails", 0, false);
	ucl_object_insert_key(top, entries(w, "ports"), "ports", 0, false);
	ucl_object_insert_key(top, makeconfs(w), "makeconf", 0, false);
	ucl_object_insert_key(top, options_dirs(w), "options", 0, false);
	ucl_object_insert_key(top, repos(w, data), "repos", 0, false);
	berr = NULL;
	ucl_object_insert_key(top, have ? builds(w, &berr) :
	    ucl_object_typed_new(UCL_ARRAY), "builds", 0, false);
	if (berr != NULL)
		ucl_object_insert_key(top, ucl_object_fromstring(berr),
		    "builds_error", 0, false);
	ucl_object_insert_key(top, runs(w), "runs", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	rsp->json = json != NULL ? wtext(w, wstrdup(w, json)) : NULL;
	free(json);
	rsp->ok = rsp->json != NULL;
	if (!rsp->ok)
		rsp->error = "out of memory";
}

/* ---- A port's options ------------------------------------------------ */

/*
 * A port's options as a build of jail, tree and set takes them: the
 * first options directory there is of those poudriere's bulk looks for
 * (the build's own name, jail-tree-set, then jail-set, jail-tree,
 * tree-set, set, tree, jail and options), the whole of it copied as the
 * build's /var/db/ports; the build's own when none is there yet, as
 * poudriere options -j -p -z makes it.  *existsp says which.
 */
static const char *
options_dir(struct work *w, const char *jail, const char *tree,
    const char *set, bool *existsp)
{
	const char	*cand[9], *master, *p;
	struct stat	 st;
	int		 n, i;

	master = set != NULL && set[0] != '\0' ? wfmt(w, "%s-%s-%s", jail,
	    tree, set) : wfmt(w, "%s-%s", jail, tree);
	n = 0;
	cand[n++] = master;
	if (set != NULL && set[0] != '\0')
		cand[n++] = wfmt(w, "%s-%s", jail, set);
	cand[n++] = wfmt(w, "%s-%s", jail, tree);
	if (set != NULL && set[0] != '\0') {
		cand[n++] = wfmt(w, "%s-%s", tree, set);
		cand[n++] = set;
	}
	cand[n++] = tree;
	cand[n++] = jail;
	for (i = 0; i <= n; i++) {
		p = i == n ? wfmt(w, "%s/options", pd_dir(w)) :
		    wfmt(w, "%s/%s-options", pd_dir(w), cand[i]);
		if (stat(p, &st) == 0 && S_ISDIR(st.st_mode)) {
			*existsp = true;
			return (p);
		}
	}
	*existsp = false;
	return (wfmt(w, "%s/%s-options", pd_dir(w), master));
}

/* Where a tree's ports are: its mnt, or the ports beneath it. */
static const char *
tree_dir(struct work *w, const char *tree)
{
	struct stat	 st;
	const char	*mnt;

	if ((mnt = first_line(w, wfmt(w, "%s/ports/%s/mnt", pd_dir(w),
	    tree))) == NULL || mnt[0] != '/')
		return (NULL);
	if (stat(wfmt(w, "%s/ports", mnt), &st) == 0 && S_ISDIR(st.st_mode))
		return (wfmt(w, "%s/ports", mnt));
	return (mnt);
}

/* An option's name, as the ports framework has them. */
static bool
option_ok(const char *s)
{

	return (s != NULL && s[0] != '\0' && strlen(s) <= 64 &&
	    strspn(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == strlen(s));
}

/*
 * The port's words, checked: jail, ports (default), set, origin; the
 * tree's port directory and the options directory with them.
 */
static int
port_where(struct work *w, const struct arc_job_spec *sp, const char **jail,
    const char **tree, const char **set, const char **origin,
    const char **portdir, const char **treedir, const char **optdir,
    bool *exists, const char **errp)
{
	char	*o;

	*jail = arg(sp, "jail", 0);
	*tree = arg(sp, "ports", 0) != NULL ? arg(sp, "ports", 0) :
	    "default";
	*set = arg(sp, "set", 0);
	*origin = arg(sp, "origin", 0);
	if (!pd_name_ok(*jail) || !pd_name_ok(*tree) || (*set != NULL &&
	    (*set)[0] != '\0' && (!pd_name_ok(*set) || strchr(*set, '-') !=
	    NULL))) {
		*errp = "name the jail, the ports tree and the set the options "
		    "are for";
		return (-1);
	}
	if (!origin_ok(*origin)) {
		*errp = "a port is its category and name: net/bird3";
		return (-1);
	}
	if ((*treedir = tree_dir(w, *tree)) == NULL) {
		*errp = wfmt(w, "no ports tree %s", *tree);
		return (-1);
	}
	o = wstrdup(w, *origin);
	o[strcspn(o, "@")] = '\0';
	*portdir = wfmt(w, "%s/%s", *treedir, o);
	if (access(*portdir, F_OK) != 0) {
		*errp = wfmt(w, "%s has no port %s", *tree, o);
		return (-1);
	}
	*optdir = options_dir(w, *jail, *tree, *set, exists);
	return (0);
}

/* make in the port's directory, as poudriere options runs it: the
 * options directory, the tree, the flavor; no make.conf of the host's. */
static int
port_make(struct work *w, const char *portdir, const char *treedir,
    const char *optdir, const char *origin, const char *const *what,
    struct execres *res)
{
	char		*argv[16];
	const char	*fl;
	int		 n, i;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.make_bin;
	argv[n++] = (char *)(uintptr_t)"-C";
	argv[n++] = (char *)(uintptr_t)portdir;
	argv[n++] = wfmt(w, "PORT_DBDIR=%s", optdir);
	argv[n++] = wfmt(w, "PORTSDIR=%s", treedir);
	argv[n++] = (char *)(uintptr_t)"__MAKE_CONF=/dev/null";
	if ((fl = strchr(origin, '@')) != NULL)
		argv[n++] = wfmt(w, "FLAVOR=%s", fl + 1);
	for (i = 0; what[i] != NULL && n < 15; i++)
		argv[n++] = (char *)(uintptr_t)what[i];
	argv[n] = NULL;
	return (run_exec(w, argv, res));
}

/* PKGNAME, OPTIONS_FILE and COMPLETE_OPTIONS_LIST, a line each. */
static int
port_vars(struct work *w, const char *portdir, const char *treedir,
    const char *optdir, const char *origin, char **pkgname, char **file,
    char **list, const char **errp)
{
	static const char *const what[] = { "-V", "PKGNAME", "-V",
	    "OPTIONS_FILE", "-V", "COMPLETE_OPTIONS_LIST", NULL };
	struct execres	 res;
	char		*text;

	if (port_make(w, portdir, treedir, optdir, origin, what, &res) != 0) {
		*errp = exec_error(w, &res, "make");
		return (-1);
	}
	text = wstrdup(w, res.out != NULL ? res.out : "");
	*pkgname = strsep(&text, "\n");
	*file = text != NULL ? strsep(&text, "\n") : NULL;
	*list = text != NULL ? strsep(&text, "\n") : NULL;
	if (*pkgname == NULL || *file == NULL || (*file)[0] != '/' ||
	    *list == NULL) {
		*errp = "make did not say the port's options file";
		return (-1);
	}
	return (0);
}

/* Whether name is one of list's words. */
static bool
in_list(const char *list, const char *name)
{
	const char	*p;
	size_t		 n;

	n = strlen(name);
	for (p = list; (p = strstr(p, name)) != NULL; p += n)
		if ((p == list || p[-1] == ' ') && (p[n] == '\0' || p[n] == ' '))
			return (true);
	return (false);
}

void
do_builder_options(struct work *w, const struct arc_job_spec *sp,
    struct arc_builder_options_rsp *rsp)
{
	static const char *const what[] = { "showconfig", NULL };
	struct execres	 res;
	ucl_object_t	*top, *secs, *sec, *opt, *list;
	const char	*jail, *tree, *set, *origin, *portdir, *treedir, *optdir;
	char		*pkgname, *file, *all, *text, *line, *p, *eq, *colon;
	char		*json;
	bool		 exists;

	rsp->ok = false;
	if (port_where(w, sp, &jail, &tree, &set, &origin, &portdir, &treedir,
	    &optdir, &exists, &rsp->error) != 0 || port_vars(w, portdir,
	    treedir, optdir, origin, &pkgname, &file, &all, &rsp->error) != 0)
		return;
	if (port_make(w, portdir, treedir, optdir, origin, what, &res) != 0) {
		rsp->error = exec_error(w, &res, "make showconfig");
		return;
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_fromstring(jail), "jail", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromstring(tree), "ports", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromstring(set != NULL ? set :
	    ""), "set", 0, false);
	ucl_object_insert_key(top, ucl_object_fromstring(origin), "origin", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromstring(pkgname), "pkgname",
	    0, false);
	ucl_object_insert_key(top, ucl_object_fromstring(optdir),
	    "options_dir", 0, false);
	ucl_object_insert_key(top, ucl_object_frombool(exists),
	    "options_dir_exists", 0, false);
	ucl_object_insert_key(top, ucl_object_fromstring(file), "options_file",
	    0, false);
	ucl_object_insert_key(top, ucl_object_frombool(access(file, F_OK) ==
	    0), "configured", 0, false);
	/*
	 * showconfig: "====> A group's or a single's words" begins a part,
	 * "     NAME=on: what it is" is an option; those before any part
	 * are the port's own.
	 */
	secs = ucl_object_typed_new(UCL_ARRAY);
	sec = NULL;
	list = NULL;
	text = wstrdup(w, res.out != NULL ? res.out : "");
	while ((line = strsep(&text, "\n")) != NULL) {
		if (strncmp(line, "====> ", 6) == 0 || sec == NULL) {
			sec = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(sec, ucl_object_fromstring(
			    strncmp(line, "====> ", 6) == 0 ? line + 6 : ""),
			    "title", 0, false);
			list = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(sec, list, "options", 0, false);
			ucl_array_append(secs, sec);
			if (strncmp(line, "====> ", 6) == 0)
				continue;
		}
		p = line + strspn(line, " \t");
		if (p == line || (eq = strchr(p, '=')) == NULL ||
		    (colon = strchr(eq, ':')) == NULL)
			continue;
		*eq = '\0';
		*colon = '\0';
		if (!option_ok(p) || (strcmp(eq + 1, "on") != 0 &&
		    strcmp(eq + 1, "off") != 0))
			continue;
		opt = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(opt, ucl_object_fromstring(p), "name", 0,
		    false);
		ucl_object_insert_key(opt, ucl_object_frombool(strcmp(eq + 1,
		    "on") == 0), "on", 0, false);
		ucl_object_insert_key(opt, ucl_object_fromstring(colon + 1 +
		    strspn(colon + 1, " ")), "description", 0, false);
		ucl_array_append(list, opt);
	}
	/* Parts without options (the first, when the port has only
	 * groups) are left out. */
	{
		ucl_object_t	*kept;
		ucl_object_iter_t it;
		const ucl_object_t *e;

		kept = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((e = ucl_object_iterate(secs, &it, true)) != NULL)
			if (ucl_array_size(ucl_object_lookup(e, "options")) > 0)
				ucl_array_append(kept, ucl_object_ref(e));
		ucl_object_unref(secs);
		secs = kept;
	}
	ucl_object_insert_key(top, secs, "sections", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	rsp->json = json != NULL ? wtext(w, wstrdup(w, json)) : NULL;
	free(json);
	rsp->ok = rsp->json != NULL;
	if (!rsp->ok)
		rsp->error = "out of memory";
}

/* The options verb: the port's options file written as make config
 * writes it, or taken away (reset=yes). */
static int
options_set(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const char	*jail, *tree, *set, *origin, *portdir, *treedir, *optdir;
	const char	*v, *tmp;
	char		*pkgname, *file, *all, *dir;
	FILE		*fp;
	size_t		 i;
	int		 step;
	bool		 exists, ok;

	if (port_where(w, sp, &jail, &tree, &set, &origin, &portdir, &treedir,
	    &optdir, &exists, errp) != 0 || port_vars(w, portdir, treedir,
	    optdir, origin, &pkgname, &file, &all, errp) != 0)
		return (-1);
	if ((v = arg(sp, "reset", 0)) != NULL && strcmp(v, "yes") == 0) {
		step = step_begin(w, ARC_STEP_KIND_FILE, file, "taken away: "
		    "the port's defaults");
		ok = unlink(file) == 0 || errno == ENOENT;
		if (!ok)
			*errp = wfmt(w, "%s: %s", file, strerror(errno));
		else if ((dir = wstrdup(w, file)) != NULL &&
		    strrchr(dir, '/') != NULL) {
			*strrchr(dir, '/') = '\0';
			(void)rmdir(dir);
		}
		step_end(w, step, ok, ok ? NULL : "%s", *errp);
		return (ok ? 0 : -1);
	}
	for (i = 0; (v = arg(sp, "on", i)) != NULL; i++)
		if (!in_list(all, v)) {
			*errp = wfmt(w, "%s has no option %s", pkgname, v);
			return (-1);
		}
	for (i = 0; (v = arg(sp, "off", i)) != NULL; i++)
		if (!in_list(all, v)) {
			*errp = wfmt(w, "%s has no option %s", pkgname, v);
			return (-1);
		}
	step = step_begin(w, ARC_STEP_KIND_FILE, file, "%s's options%s",
	    pkgname, exists ? "" : wfmt(w, ", in %s, made", optdir));
	dir = wstrdup(w, file);
	*strrchr(dir, '/') = '\0';
	(void)mkdir(optdir, 0755);
	(void)mkdir(dir, 0755);
	tmp = wfmt(w, "%s.arcana-new", file);
	ok = (fp = fopen(tmp, "w")) != NULL;
	if (ok) {
		fprintf(fp, "# This file is auto-generated by 'make config'.\n"
		    "# Options for %s, set by Arcana\n_OPTIONS_READ=%s\n"
		    "_FILE_COMPLETE_OPTIONS_LIST=%s\n", pkgname, pkgname, all);
		for (i = 0; (v = arg(sp, "on", i)) != NULL; i++)
			fprintf(fp, "OPTIONS_FILE_SET+=%s\n", v);
		for (i = 0; (v = arg(sp, "off", i)) != NULL; i++)
			fprintf(fp, "OPTIONS_FILE_UNSET+=%s\n", v);
		ok = fclose(fp) == 0;
	}
	ok = ok && chmod(tmp, 0644) == 0 && rename(tmp, file) == 0;
	if (!ok) {
		*errp = wfmt(w, "%s: %s", file, strerror(errno));
		(void)unlink(tmp);
	}
	step_end(w, step, ok, ok ? NULL : "%s", *errp);
	return (ok ? 0 : -1);
}

/*
 * The options directories of poudriere.d, each with the ports it sets,
 * read from their files: what _OPTIONS_READ names, those set and those
 * unset.
 */
static ucl_object_t *
options_dirs(struct work *w)
{
	ucl_object_t	*arr, *o, *ports, *p, *on, *off;
	struct dirent	*de, *pe;
	DIR		*d, *pd;
	const char	*dir;
	char		*text, *line;
	size_t		 nl, len;
	int		 n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if ((d = opendir(pd_dir(w))) == NULL)
		return (arr);
	n = 0;
	while ((de = readdir(d)) != NULL && n < LIST_MAX) {
		nl = strlen(de->d_name);
		if (strcmp(de->d_name, "options") != 0 && (nl <= 8 ||
		    strcmp(de->d_name + nl - 8, "-options") != 0))
			continue;
		dir = wfmt(w, "%s/%s", pd_dir(w), de->d_name);
		if ((pd = opendir(dir)) == NULL)
			continue;
		ports = ucl_object_typed_new(UCL_ARRAY);
		while ((pe = readdir(pd)) != NULL) {
			if (pe->d_name[0] == '.' || (text = scope_slurp(w,
			    wfmt(w, "%s/%s/options", dir, pe->d_name), &len)) ==
			    NULL)
				continue;
			p = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(p, ucl_object_fromstring(
			    pe->d_name), "name", 0, false);
			on = ucl_object_typed_new(UCL_ARRAY);
			off = ucl_object_typed_new(UCL_ARRAY);
			while ((line = strsep(&text, "\n")) != NULL) {
				if (strncmp(line, "_OPTIONS_READ=", 14) == 0)
					ucl_object_insert_key(p,
					    ucl_object_fromstring(line + 14),
					    "pkgname", 0, true);
				else if (strncmp(line, "OPTIONS_FILE_SET+=", 18) ==
				    0)
					ucl_array_append(on,
					    ucl_object_fromstring(line + 18));
				else if (strncmp(line, "OPTIONS_FILE_UNSET+=",
				    20) == 0)
					ucl_array_append(off,
					    ucl_object_fromstring(line + 20));
			}
			ucl_object_insert_key(p, on, "set", 0, false);
			ucl_object_insert_key(p, off, "unset", 0, false);
			ucl_array_append(ports, p);
		}
		closedir(pd);
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(strcmp(
		    de->d_name, "options") == 0 ? "" : wfmt(w, "%.*s",
		    (int)(nl - 8), de->d_name)), "name", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(dir), "dir", 0,
		    false);
		ucl_object_insert_key(o, ports, "ports", 0, false);
		ucl_array_append(arr, o);
		n++;
	}
	closedir(d);
	return (arr);
}
