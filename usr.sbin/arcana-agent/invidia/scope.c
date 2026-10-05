/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the network of a jail that has one of its own (vnet), worked
 * on from the host.  Nothing is installed in the jail: there is no
 * agent in it.
 *
 * A request names the jail, and from then on what the request runs is
 * run for that jail:
 *
 *   ifconfig, route, netstat, sockstat, ngctl
 *		the host's own programs, with their -j: they attach to
 *		the jail themselves, and need nothing in it.
 *   sysrc	the host's, with -R and the jail's root: the jail's own
 *		rc.conf is where its network is kept for its next start.
 *   birdc, bird, wg
 *		the jail's own programs, through jexec(8): the daemon in
 *		the jail is the jail's version, and so must be what
 *		parses its configuration and speaks to it.
 *
 * What the daemon reads in its own process, the interfaces with their
 * counters, is read for a jail by this same program run again as a
 * helper (-Q), which attaches to the jail first.
 *
 * Files in a jail are the jail's: its root user can make any name
 * there a link to anywhere.  They are opened beneath the jail's root
 * and never through a link that leads out of it.
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"

/*
 * Have w work in the jail named, when one is: it must be running and
 * have a network of its own.  jls(8) says: "4 new /usr/jails/gateway".
 */
int
scope_enter(struct work *w, const char *jail, const char **errp)
{
	struct execres	 res;
	char		*argv[7], *line, *p, *vnet;

	w->jail = NULL;
	w->jid = 0;
	w->jroot = NULL;
	if (jail == NULL || jail[0] == '\0')
		return (0);
	argv[0] = (char *)(uintptr_t)opts.jls_bin;
	argv[1] = (char *)(uintptr_t)"-j";
	argv[2] = (char *)(uintptr_t)jail;
	argv[3] = (char *)(uintptr_t)"jid";
	argv[4] = (char *)(uintptr_t)"vnet";
	argv[5] = (char *)(uintptr_t)"path";
	argv[6] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL) {
		*errp = wfmt(w, "the jail %s is not running: its network is "
		    "there only while it runs", jail);
		return (-1);
	}
	line = wstrndup(w, res.out, strcspn(res.out, "\n"));
	p = line;
	w->jid = atoi(p);
	p += strcspn(p, " ");
	p += strspn(p, " ");
	vnet = p;
	p += strcspn(p, " ");
	if (*p != '\0')
		*p++ = '\0';
	p += strspn(p, " ");
	if (w->jid <= 0 || p[0] != '/') {
		*errp = wfmt(w, "jls did not say where the jail %s is", jail);
		return (-1);
	}
	if (strcmp(vnet, "new") != 0 && strcmp(vnet, "1") != 0) {
		*errp = wfmt(w, "the jail %s has no network of its own (vnet): "
		    "its addresses are the host's, and are managed there",
		    jail);
		return (-1);
	}
	w->jail = wstrdup(w, jail);
	w->jroot = wstrdup(w, p);
	return (0);
}

/*
 * argv as it is run for the jail w works in; argv itself when w works
 * on the host, or the program is none that has to do with a network.
 */
char *const *
scope_argv(struct work *w, char *const argv[])
{
	char	**v;
	size_t	  n, i, k;

	if (w->jail == NULL)
		return (argv);
	for (n = 0; argv[n] != NULL; n++)
		;
	v = wcalloc(w, n + 4, sizeof(*v));
	k = 0;
	if (argv[0] == opts.ifconfig_bin || argv[0] == opts.netstat_bin || argv[0] == opts.sockstat_bin ||
	    argv[0] == opts.ngctl_bin) {
		v[k++] = argv[0];
		v[k++] = (char *)(uintptr_t)"-j";
		v[k++] = wfmt(w, "%d", w->jid);
		i = 1;
	} else if (argv[0] == opts.sysrc_bin) {
		v[k++] = argv[0];
		v[k++] = (char *)(uintptr_t)"-R";
		v[k++] = (char *)(uintptr_t)w->jroot;
		i = 1;
	} else if (argv[0] == opts.birdc_bin || argv[0] == opts.bird_bin ||
	    argv[0] == opts.wg_bin) {
		v[k++] = (char *)(uintptr_t)opts.jexec_bin;
		v[k++] = wfmt(w, "%d", w->jid);
		i = 0;
	} else
		return (argv);
	for (; i < n; i++)
		v[k++] = argv[i];
	v[k] = NULL;
	return (v);
}

/*
 * The helper's argv for a verb and its n words: this program again,
 * told the jail w works in, or 0 for the host.
 */
char **
helper_argv(struct work *w, const char *verb, size_t n,
    const char *const words[])
{
	char	**v;
	size_t	  i;

	v = wcalloc(w, n + 5, sizeof(*v));
	v[0] = (char *)(uintptr_t)opts.helper_bin;
	v[1] = (char *)(uintptr_t)"-Q";
	v[2] = wfmt(w, "%d", w->jail != NULL ? w->jid : 0);
	v[3] = (char *)(uintptr_t)verb;
	for (i = 0; i < n; i++)
		v[4 + i] = (char *)(uintptr_t)words[i];
	v[4 + n] = NULL;
	return (v);
}

/*
 * Why a program of the jail's own did not run, when the jail has no
 * such program: said so, rather than as jexec says it.  NULL otherwise.
 */
const char *
scope_missing(struct work *w, const struct execres *res, const char *prog,
    const char *package)
{

	if (w->jail == NULL || res->err == NULL || strstr(res->err,
	    "execvp") == NULL)
		return (NULL);
	return (wfmt(w, "the jail %s has no %s: it is the jail's own that is "
	    "run there (pkg -j %s install %s)", w->jail, prog, w->jail,
	    package));
}

/*
 * A directory of the host, or of the jail w works in: opened beneath
 * the jail's root, whatever links the jail has put on the way.
 */
int
scope_dirfd(struct work *w, const char *dir)
{
	int	root, fd;

	if (w->jail == NULL)
		return (open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	if ((root = open(w->jroot, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1)
		return (-1);
	dir += strspn(dir, "/");
	fd = openat(root, dir[0] != '\0' ? dir : ".", O_RDONLY | O_DIRECTORY |
	    O_CLOEXEC | O_RESOLVE_BENEATH);
	close(root);
	return (fd);
}

/* path as its directory, opened, and the name in it; -1 for no such. */
int
scope_open_dir(struct work *w, const char *path, const char **basep)
{
	const char	*slash;
	char		*dir;

	if ((slash = strrchr(path, '/')) == NULL || slash[1] == '\0') {
		errno = EINVAL;
		return (-1);
	}
	dir = slash == path ? wstrdup(w, "/") : wstrndup(w, path,
	    (size_t)(slash - path));
	*basep = slash + 1;
	return (scope_dirfd(w, dir));
}

/* A file of the host or of w's jail, whole; NULL, with errno, for none. */
char *
scope_slurp(struct work *w, const char *path, size_t *lenp)
{
	struct stat	 sb;
	const char	*base;
	char		*buf;
	ssize_t		 n;
	int		 dfd, fd, e;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (NULL);
	fd = openat(dfd, base, O_RDONLY | O_CLOEXEC | (w->jail != NULL ?
	    O_NOFOLLOW : 0));
	e = errno;
	close(dfd);
	errno = e;
	if (fd == -1)
		return (NULL);
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode) || sb.st_size >
	    ARC_MAX_JSON) {
		close(fd);
		errno = EFBIG;
		return (NULL);
	}
	buf = wmalloc(w, (size_t)sb.st_size + 1);
	n = read(fd, buf, (size_t)sb.st_size);
	close(fd);
	if (n != sb.st_size) {
		errno = EIO;
		return (NULL);
	}
	buf[n] = '\0';
	if (lenp != NULL)
		*lenp = (size_t)n;
	return (buf);
}

/*
 * Put text in a file's place, there or in w's jail: written beside it
 * and moved over it, so that it is whole or as it was.  With keep, the
 * file as it was stays beside it under that name.
 */
int
scope_replace(struct work *w, const char *path, const char *text, size_t len,
    mode_t mode, const char *keep)
{
	const char	*base;
	char		 tmp[NAME_MAX + 1];
	int		 dfd, fd, e;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (-1);
	snprintf(tmp, sizeof(tmp), ".%.200s.%08x", base, arc4random());
	if ((fd = openat(dfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, mode)) == -1)
		goto fail;
	if (write(fd, text, len) != (ssize_t)len || fsync(fd) == -1) {
		e = errno;
		close(fd);
		(void)unlinkat(dfd, tmp, 0);
		errno = e;
		goto fail;
	}
	close(fd);
	if (keep != NULL) {
		(void)unlinkat(dfd, keep, 0);
		if (linkat(dfd, base, dfd, keep, 0) == -1 && errno != ENOENT) {
			e = errno;
			(void)unlinkat(dfd, tmp, 0);
			errno = e;
			goto fail;
		}
	}
	if (renameat(dfd, tmp, dfd, base) == -1) {
		e = errno;
		(void)unlinkat(dfd, tmp, 0);
		errno = e;
		goto fail;
	}
	close(dfd);
	return (0);
fail:
	e = errno;
	close(dfd);
	errno = e;
	return (-1);
}

/* Move a file's name in its directory, or with to NULL take it away. */
int
scope_rename(struct work *w, const char *path, const char *from,
    const char *to)
{
	const char	*base;
	int		 dfd, rc, e;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (-1);
	rc = to != NULL ? renameat(dfd, from, dfd, to) : unlinkat(dfd, from, 0);
	e = errno;
	close(dfd);
	errno = e;
	return (rc);
}

/*
 * The helper: this program run as "arcana-agent -Q jid what name arg".
 * It attaches to the jail, asks what the daemon would have asked in
 * its own process, prints the answer and ends.
 */
int
scope_helper(int argc, char **argv)
{
	char	*out;
	int	 jid;

	if (argc < 2)
		return (2);
	jid = atoi(argv[0]);
	if (jid > 0 && jail_attach(jid) == -1) {
		fprintf(stderr, "arcana-agent: jail_attach(%d): %s\n", jid,
		    strerror(errno));
		return (1);
	}
	/* The routing tables, through netlink(4). */
	if (strncmp(argv[1], "route", 5) == 0)
		return (route_helper(argc - 1, argv + 1));
	if (strcmp(argv[1], "zfs-pipe") == 0)
		return (zfs_pipe(argc - 1, argv + 1));
	if (argc != 4)
		return (2);
	if ((out = ifq_text(argv[1], strcmp(argv[2], "-") == 0 ? NULL :
	    argv[2], strcmp(argv[3], "-") == 0 ? NULL : argv[3])) == NULL)
		return (1);
	fputs(out, stdout);
	return (0);
}
