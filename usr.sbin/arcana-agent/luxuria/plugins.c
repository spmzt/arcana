/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: what is not FreeBSD's own.  A plugin works through a program
 * that has to be installed, and is there only where its program is:
 * BIRD through birdc(8), strongSwan's IPsec through swanctl(8),
 * Squid and dnsmasq for SD-WAN's proxy and DHCP, poudriere(8) to
 * build packages,
 * WireGuard's keys and peers through wg(8), the base system's (the
 * interface itself, if_wg(4) made by ifconfig(8), is Invidia's).  A
 * host says which it has, and so does a jail with a network of its own,
 * where the program is the jail's.
 *
 * A jail's programs are looked for as the jail sees them: a child
 * attaches to it and asks there, so that its own links (a /usr/local
 * that leads elsewhere inside it) and mounts lead where they do for the
 * jail, and never out of it.  An agent the kernel does not let attach
 * looks beneath the jail's root instead, without following a link out
 * of it.  What a jail has is kept a few seconds: it is asked at every
 * list, and changes when a package is installed.
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"

#define	PLUGINS_KEPT_S	10	/* a jail's answer, kept */
#define	PLUGINS_JAILS	64

static const struct {
	const char		*name;
	const char *const	*program;
} plugins[] = {
	{ "bird", &opts.birdc_bin },
	{ "wireguard", &opts.wg_bin },
	{ "strongswan", &opts.swanctl_bin },
	{ "squid", &opts.squid_bin },
	{ "dnsmasq", &opts.dnsmasq_bin },
	{ "c-icap", &opts.cicap_bin },
	{ "suricata", &opts.suricata_bin },
	{ "poudriere", &opts.poudriere_bin },
	{ "snort", &opts.snort_bin },
};

/*
 * A bit for each plugin's program: a child in a jail writes them to its
 * parent through a pipe.
 */
#define	BIT_PROG(i)	(1u << (i))
#define	FOUND_NONE	0xffffffffu
_Static_assert(nitems(plugins) < 32, "the bits of an unsigned int");

static struct {
	int		jid;
	time_t		at;
	unsigned int	found;
}			kept[PLUGINS_JAILS];
static pthread_mutex_t	kept_lock = PTHREAD_MUTEX_INITIALIZER;

/* What is there to run, by access(2) where this process is. */
static unsigned int
found_here(void)
{
	unsigned int	m;
	size_t		i;

	m = 0;
	for (i = 0; i < nitems(plugins); i++)
		if (access(*plugins[i].program, X_OK) == 0)
			m |= BIT_PROG(i);
	return (m);
}

/*
 * On the host, a program of the tools directory (-2) counts as the
 * plugin's, as it does where the program is run.
 */
static unsigned int
found_tools(void)
{
	const char	*base;
	char		 path[MAXPATHLEN];
	unsigned int	 m;
	size_t		 i;

	m = 0;
	for (i = 0; opts.tools_dir != NULL && i < nitems(plugins); i++) {
		base = strrchr(*plugins[i].program, '/');
		base = base != NULL ? base + 1 : *plugins[i].program;
		snprintf(path, sizeof(path), "%s/%s", opts.tools_dir, base);
		if (access(path, X_OK) == 0)
			m |= BIT_PROG(i);
	}
	return (m);
}

/* The same beneath a jail's root, never through a link out of it. */
static unsigned int
found_beneath(const char *root)
{
	const char	*prog;
	unsigned int	 m;
	size_t		 i;
	int		 fd;

	if (root == NULL || (fd = open(root, O_RDONLY | O_DIRECTORY |
	    O_CLOEXEC)) == -1)
		return (0);
	m = 0;
	for (i = 0; i < nitems(plugins); i++) {
		prog = *plugins[i].program;
		if (faccessat(fd, prog + strspn(prog, "/"), X_OK,
		    AT_RESOLVE_BENEATH) == 0)
			m |= BIT_PROG(i);
	}
	close(fd);
	return (m);
}

/* found_here(), for the helper in a jail to answer (ifq_text()). */
unsigned int
plugins_here(void)
{

	return (found_here());
}

/*
 * In the jail itself, by the helper (-Q jid plugins), which attaches:
 * a kernel that refuses jail_attach(2) to a process that has had
 * threads lets an exec'd one.  FOUND_NONE when it could not tell.
 */
static unsigned int
found_by_helper(int jid)
{
	struct execres	 res;
	struct work	 w;
	char		*argv[7], *end;
	unsigned long	 m;

	if (opts.helper_bin == NULL)
		return (FOUND_NONE);
	work_init(&w);
	argv[0] = (char *)(uintptr_t)opts.helper_bin;
	argv[1] = (char *)(uintptr_t)"-Q";
	argv[2] = wfmt(&w, "%d", jid);
	argv[3] = (char *)(uintptr_t)"plugins";
	argv[4] = (char *)(uintptr_t)"-";
	argv[5] = (char *)(uintptr_t)"-";
	argv[6] = NULL;
	m = FOUND_NONE;
	if (run_exec(&w, argv, &res) == 0 && res.status == 0 && res.out !=
	    NULL && res.out[0] >= '0' && res.out[0] <= '9') {
		errno = 0;
		m = strtoul(res.out, &end, 10);
		if (errno != 0 || (*end != '\0' && *end != '\n') || m >=
		    FOUND_NONE)
			m = FOUND_NONE;
	}
	work_free(&w);
	return ((unsigned int)m);
}

/*
 * In the jail itself: a child attaches and writes what it found through
 * a pipe; FOUND_NONE when it could not.  The child only makes system
 * calls, as a child of a process with threads must.
 */
static unsigned int
found_attached(int jid)
{
	unsigned int	m;
	pid_t		pid;
	ssize_t		n;
	int		fd[2], status;

	if (pipe2(fd, O_CLOEXEC) == -1)
		return (FOUND_NONE);
	if ((pid = fork()) == -1) {
		close(fd[0]);
		close(fd[1]);
		return (FOUND_NONE);
	}
	if (pid == 0) {
		close(fd[0]);
		if (jail_attach(jid) == -1)
			_exit(1);
		m = found_here();
		_exit(write(fd[1], &m, sizeof(m)) == sizeof(m) ? 0 : 1);
	}
	close(fd[1]);
	while ((n = read(fd[0], &m, sizeof(m))) == -1 && errno == EINTR)
		;
	close(fd[0]);
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			return (FOUND_NONE);
	if (n != sizeof(m) || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return (FOUND_NONE);
	return (m);
}

/* What jail jid (rooted at root) has, or the host for jid 0. */
static unsigned int
found_in(int jid, const char *root)
{
	unsigned int	 m;
	time_t		 now;
	size_t		 i, slot;

	if (jid <= 0)
		return (found_here() | found_tools());
	now = time(NULL);
	pthread_mutex_lock(&kept_lock);
	slot = 0;
	for (i = 0; i < nitems(kept); i++) {
		if (kept[i].jid == jid && now - kept[i].at < PLUGINS_KEPT_S) {
			m = kept[i].found;
			pthread_mutex_unlock(&kept_lock);
			return (m);
		}
		if (kept[i].at < kept[slot].at)
			slot = i;
	}
	pthread_mutex_unlock(&kept_lock);
	if ((m = found_by_helper(jid)) == FOUND_NONE &&
	    (m = found_attached(jid)) == FOUND_NONE)
		m = found_beneath(root);
	pthread_mutex_lock(&kept_lock);
	kept[slot].jid = jid;
	kept[slot].at = now;
	kept[slot].found = m;
	pthread_mutex_unlock(&kept_lock);
	return (m);
}

/* What the jails have, forgotten: packages were installed. */
void
plugins_forget(void)
{

	pthread_mutex_lock(&kept_lock);
	memset(kept, 0, sizeof(kept));
	pthread_mutex_unlock(&kept_lock);
}

/*
 * The plugins there are in jail jid, beneath root, or on the host when
 * jid is 0: those whose program can be run there.
 */
void
plugins_there(struct work *w, int jid, const char *root,
    const char *const **vp, size_t *np)
{
	const char	**v;
	unsigned int	  m;
	size_t		  i, n;

	m = found_in(jid, root);
	v = wcalloc(w, nitems(plugins), sizeof(*v));
	n = 0;
	for (i = 0; i < nitems(plugins); i++)
		if ((m & BIT_PROG(i)) != 0)
			v[n++] = plugins[i].name;
	*vp = v;
	*np = n;
}

/* The program that runs the plugin named. */
const char *
plugin_bin(struct work *w __unused, const char *name)
{
	size_t	i;

	for (i = 0; i < nitems(plugins); i++)
		if (strcmp(plugins[i].name, name) == 0)
			return (*plugins[i].program);
	return (NULL);
}
