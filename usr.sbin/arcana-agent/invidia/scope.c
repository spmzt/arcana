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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
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

	return (scope_enter_jail(w, jail, errp, true));
}

/* The same; with vnet false, a jail without a network of its own too. */
int
scope_enter_jail(struct work *w, const char *jail, const char **errp,
    bool vnet)
{
	struct execres	 res;
	char		*argv[7], *line, *p, *vnetv;

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
	vnetv = p;
	p += strcspn(p, " ");
	if (*p != '\0')
		*p++ = '\0';
	p += strspn(p, " ");
	if (w->jid <= 0 || p[0] != '/') {
		*errp = wfmt(w, "jls did not say where the jail %s is", jail);
		return (-1);
	}
	if (vnet && strcmp(vnetv, "new") != 0 && strcmp(vnetv, "1") != 0) {
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
	if (argv[0] == opts.ifconfig_bin || argv[0] == opts.netstat_bin ||
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
	    argv[0] == opts.wg_bin || argv[0] == wg_base_bin ||
	    argv[0] == opts.ipfw_bin ||
	    argv[0] == opts.swanctl_bin) {
		/* The jail's own: ipfw(8) has no way to name a jail. */
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
 * argv run in the jail w works in, by jexec(8), whatever the program:
 * for one this daemon has no option of its own for (arp, ndp), which
 * scope_argv() does not know.  argv itself on the host.
 */
char *const *
scope_jexec(struct work *w, char *const argv[])
{
	char	**v;
	size_t	  n, i;

	if (w->jail == NULL)
		return (argv);
	for (n = 0; argv[n] != NULL; n++)
		;
	v = wcalloc(w, n + 3, sizeof(*v));
	v[0] = (char *)(uintptr_t)opts.jexec_bin;
	v[1] = wfmt(w, "%d", w->jid);
	for (i = 0; i < n; i++)
		v[2 + i] = argv[i];
	v[2 + n] = NULL;
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
 * A jail's name and whether it has a network of its own ("new"), by
 * its number; -1 when it is not there.
 */
int
jail_jid_name(int jid, char *name, size_t nlen, char *vnet, size_t vlen)
{
	char	js[16], nb[MAXHOSTNAMELEN], vb[16];

	snprintf(js, sizeof(js), "%d", jid);
	if (jail_getv(0, "jid", js, "name", nb, "vnet", vb, NULL) == -1)
		return (-1);
	strlcpy(name, nb, nlen);
	strlcpy(vnet, vb, vlen);
	return (0);
}

/* The jail after jid, by number (0 for the first); 0 when none. */
int
jail_next(int jid)
{
	char	ls[16], js[16];
	int	next;

	snprintf(ls, sizeof(ls), "%d", jid);
	js[0] = '\0';
	if ((next = jail_getv(0, "lastjid", ls, "jid", js, NULL)) == -1)
		return (0);
	return (next);
}

/*
 * A netlink(4) socket in a jail's own network, told of what is
 * watched: the helper makes it there and hands it over on a socket
 * that is its standard output.  -1 when it could not.
 */
int
helper_netlink(int jid)
{
	static char *const		 noenv[] = { NULL };
	posix_spawn_file_actions_t	 fa;
	struct msghdr			 msg;
	struct cmsghdr			*cm;
	struct iovec			 iov;
	struct pollfd			 pfd;
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	}				 cbuf;
	char				 js[16], one, *argv[5];
	pid_t				 pid;
	int				 sp[2], fd, rc, status;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) == -1)
		return (-1);
	snprintf(js, sizeof(js), "%d", jid);
	argv[0] = (char *)(uintptr_t)opts.helper_bin;
	argv[1] = (char *)(uintptr_t)"-Q";
	argv[2] = js;
	argv[3] = (char *)(uintptr_t)"route-socket";
	argv[4] = NULL;
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null",
	    O_RDONLY, 0);
	posix_spawn_file_actions_adddup2(&fa, sp[1], STDOUT_FILENO);
	rc = posix_spawn(&pid, argv[0], &fa, NULL, argv, noenv);
	posix_spawn_file_actions_destroy(&fa);
	close(sp[1]);
	if (rc != 0) {
		close(sp[0]);
		return (-1);
	}
	fd = -1;
	pfd.fd = sp[0];
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 5000) == 1) {
		memset(&msg, 0, sizeof(msg));
		iov.iov_base = &one;
		iov.iov_len = 1;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cbuf.buf;
		msg.msg_controllen = sizeof(cbuf.buf);
		if (recvmsg(sp[0], &msg, MSG_CMSG_CLOEXEC) == 1 &&
		    (cm = CMSG_FIRSTHDR(&msg)) != NULL && cm->cmsg_level ==
		    SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS &&
		    cm->cmsg_len == CMSG_LEN(sizeof(int)))
			memcpy(&fd, CMSG_DATA(cm), sizeof(int));
	}
	close(sp[0]);
	if (fd == -1)
		(void)kill(pid, SIGKILL);
	while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
		;
	return (fd);
}

/* Lines written into a stream of the daemon's, each given on. */
struct lines {
	void	(*fn)(const char *, void *);
	void	*arg;
	char	*buf;
	size_t	 len, cap;
};

static int
lines_write(void *cookie, const char *data, int n)
{
	struct lines	*l = cookie;
	char		*nl;
	size_t		 k;

	if (l->len + (size_t)n + 1 > l->cap) {
		l->cap = (l->len + (size_t)n + 1) * 2;
		if ((l->buf = realloc(l->buf, l->cap)) == NULL)
			return (-1);
	}
	memcpy(l->buf + l->len, data, (size_t)n);
	l->len += (size_t)n;
	while ((nl = memchr(l->buf, '\n', l->len)) != NULL) {
		*nl = '\0';
		l->fn(l->buf, l->arg);
		k = (size_t)(nl - l->buf) + 1;
		memmove(l->buf, nl + 1, l->len - k);
		l->len -= k;
	}
	return (n);
}

/*
 * What the helper's verb prints, a line at a time to fn: of the host's
 * own stack read here, by the daemon itself, as it is written; of a
 * jail's, or when the helper is another program (-H), by the helper.
 */
int
helper_lines(struct work *w, const char *verb, size_t n,
    const char *const words[], void (*fn)(const char *, void *), void *arg)
{
	struct lines	 l;
	FILE		*fp;
	int		 step, rc;

	if (w->jail != NULL || !opts.helper_self)
		return (run_exec_lines(w, helper_argv(w, verb, n, words), fn,
		    arg));
	step = step_begin(w, ARC_STEP_KIND_LIB, strncmp(verb, "pcb-", 4) == 0 ?
	    "sysctl(3)" : "netlink(4)", "%s %s", verb, n > 0 ? words[0] : "");
	memset(&l, 0, sizeof(l));
	l.fn = fn;
	l.arg = arg;
	if ((fp = fwopen(&l, lines_write)) == NULL) {
		step_end(w, step, false, "fwopen");
		return (-1);
	}
	/* Line by line: each is given on when it is whole. */
	(void)setvbuf(fp, NULL, _IOLBF, 0);
	if (strcmp(verb, "routes") == 0 && n == 4)
		rc = route_list(fp, atoi(words[0]), (uint32_t)strtoul(words[1],
		    NULL, 10), strcmp(words[2], "-") != 0 ? words[2] : NULL,
		    strcmp(words[3], "-") != 0 ? words[3] : NULL);
	else if (strcmp(verb, "route-get") == 0 && n == 2)
		rc = route_lookup(fp, words[0], (uint32_t)strtoul(words[1],
		    NULL, 10));
	else if (strcmp(verb, "route-neighs") == 0 && n == 2)
		rc = neigh_list(fp, atoi(words[0]), strcmp(words[1], "-") != 0 ?
		    words[1] : NULL);
	else if (strncmp(verb, "pcb-", 4) == 0 && n == 1)
		rc = pcb_list(fp, strcmp(verb, "pcb-socks") == 0, atoi(
		    words[0]));
	else
		rc = 2;
	fclose(fp);
	free(l.buf);
	step_end(w, step, rc == 0, NULL);
	return (rc == 0 ? 0 : -1);
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
	if (strncmp(argv[1], "pcb-", 4) == 0)
		return (pcb_helper(argc - 1, argv + 1));
	if (strcmp(argv[1], "zfs-pipe") == 0)
		return (zfs_pipe(argc - 1, argv + 1));
	/* A number of the network's, as the jail's own network has it. */
	if (strcmp(argv[1], "sysctl-int") == 0 && argc == 3 &&
	    strncmp(argv[2], "net.", 4) == 0) {
		int	v;
		size_t	len;

		len = sizeof(v);
		if (sysctlbyname(argv[2], &v, &len, NULL, 0) == -1) {
			fprintf(stderr, "%s: %s\n", argv[2], strerror(errno));
			return (1);
		}
		printf("%d\n", v);
		return (0);
	}
	if (argc != 4)
		return (2);
	if ((out = ifq_text(argv[1], strcmp(argv[2], "-") == 0 ? NULL :
	    argv[2], strcmp(argv[3], "-") == 0 ? NULL : argv[3])) == NULL)
		return (1);
	fputs(out, stdout);
	return (0);
}
