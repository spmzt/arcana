/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: what else changes on the host, told by the kernel as it
 * happens, so that a page that shows it reads it again then and not on
 * a timer.  One thread waits on one kqueue(2) for:
 *
 * - the base system's configuration files (EVFILT_VNODE): rc.conf and
 *   rc.conf.local, sysctl.conf, fstab, jail.conf, loader.conf,
 *   sshd_config, those the agent is told of where it is told (-f, -2's
 *   fstab, sysctl.conf); a file written, or replaced (renamed over, as
 *   an editor and sysrc(8) do: the directory it is in is watched too,
 *   and the file opened again), is the event conf, {"file": path};
 * - the processes (EVFILT_PROC): every process is watched for its exit
 *   and, with NOTE_TRACK, for its children, which the kernel then
 *   watches the same way; those the agent itself started, and theirs,
 *   are left out, as their jobs and reads say what they did.  What came
 *   and went in a second is the event procs, {"started": n, "exited":
 *   m};
 * - devd(8)'s notifications, on its seqpacket socket: ZFS's (a pool
 *   imported, exported, scrubbed, a vdev's state, the event zfs,
 *   {"type", "pool"}) and a disk's device node made or destroyed
 *   (DEVFS's CDEV, the event device, {"cdev", "state"}).  Without devd
 *   it is tried again every half minute.
 *
 * Each kind is said at most once a second, of each file, pool or disk
 * once: a storm of them is one event.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/user.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"

#define	DEVD_SOCK	"/var/run/devd.seqpacket.pipe"
#define	DEVD_RETRY	30	/* seconds before devd is tried again */
#define	TICK_MS		1000	/* what was seen is said this often */
#define	DEVD_MSG	8192

#define	CONF_FILES	7

/* What kqueue's udata says an event is of. */
enum what { W_FILE = 1, W_DIR, W_PROC, W_DEVD, W_TICK };

struct watched_file {
	const char	*path;
	int		 fd;		/* -1: not there now */
	bool		 changed;	/* not yet said */
};

static struct watched_file	files[CONF_FILES];

/* The agent and what it started: their processes are not counted. */
static pid_t	*mine;
static size_t	 nmine, mine_size;
static unsigned	 started, exited;

/* devd's: the pools and disks seen since the last tick. */
#define	SEEN_MAX	16
struct seen {
	char	kind[8];	/* zfs, device */
	char	a[64];		/* the type, the device */
	char	b[64];		/* the pool, the state */
};
static struct seen	seen[SEEN_MAX];
static size_t		nseen;
static int		devd = -1;
static time_t		devd_next;

static bool
is_mine(pid_t pid)
{

	for (size_t i = 0; i < nmine; i++)
		if (mine[i] == pid)
			return (true);
	return (false);
}

static void
mine_add(pid_t pid)
{
	pid_t	*v;

	if (nmine == mine_size) {
		if ((v = reallocarray(mine, mine_size + 64, sizeof(*v))) ==
		    NULL)
			return;
		mine = v;
		mine_size += 64;
	}
	mine[nmine++] = pid;
}

static void
mine_del(pid_t pid)
{

	for (size_t i = 0; i < nmine; i++)
		if (mine[i] == pid) {
			mine[i] = mine[--nmine];
			return;
		}
}

/* A file opened again and watched, as it is now; -1 when not there. */
static void
file_watch(int kq, struct watched_file *f)
{
	struct kevent	ev;

	if (f->fd != -1)
		close(f->fd);
	if ((f->fd = open(f->path, O_RDONLY | O_CLOEXEC)) == -1)
		return;
	EV_SET(&ev, f->fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE |
	    NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME | NOTE_ATTRIB, 0,
	    (void *)(intptr_t)W_FILE);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
		close(f->fd);
		f->fd = -1;
	}
}

/* The directory file is in, watched, once whichever file asks. */
static void
dir_watch(int kq, const char *file)
{
	static char	 dirs[CONF_FILES][PATH_MAX];
	struct kevent	 ev;
	const char	*e;
	size_t		 i;
	int		 fd;

	if ((e = strrchr(file, '/')) == NULL || (size_t)(e - file) >=
	    sizeof(dirs[0]))
		return;
	for (i = 0; i < nitems(dirs) && dirs[i][0] != '\0'; i++)
		if (strncmp(dirs[i], file, (size_t)(e - file)) == 0 &&
		    dirs[i][e - file] == '\0')
			return;
	if (i == nitems(dirs))
		return;
	snprintf(dirs[i], sizeof(dirs[i]), "%.*s", (int)(e - file), file);
	if (dirs[i][0] == '\0')
		strlcpy(dirs[i], "/", sizeof(dirs[i]));
	if ((fd = open(dirs[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1)
		return;
	EV_SET(&ev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE, 0,
	    (void *)(intptr_t)W_DIR);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1)
		close(fd);
}

/* A directory's names changed: a file there may be another one now. */
static void
dir_changed(int kq)
{
	struct stat	 st, now;

	for (size_t i = 0; i < nitems(files); i++) {
		struct watched_file	*f = &files[i];

		if (stat(f->path, &now) == -1) {
			if (f->fd != -1) {
				close(f->fd);
				f->fd = -1;
				f->changed = true;
			}
			continue;
		}
		if (f->fd != -1 && fstat(f->fd, &st) == 0 &&
		    st.st_ino == now.st_ino && st.st_dev == now.st_dev)
			continue;
		file_watch(kq, f);
		f->changed = true;
	}
}

static void
proc_watch(int kq, pid_t pid)
{
	struct kevent	ev;

	EV_SET(&ev, pid, EVFILT_PROC, EV_ADD, NOTE_EXIT | NOTE_TRACK, 0,
	    (void *)(intptr_t)W_PROC);
	(void)kevent(kq, &ev, 1, NULL, 0, NULL);
}

/* Every process there is, watched; the agent's own are its. */
static void
procs_watch_all(int kq)
{
	struct kinfo_proc	*kp;
	size_t			 len;
	int			 mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC };
	pid_t			 self;

	self = getpid();
	mine_add(self);
	if (sysctl(mib, nitems(mib), NULL, &len, NULL, 0) == -1 ||
	    (kp = malloc(len += len / 4)) == NULL)
		return;
	if (sysctl(mib, nitems(mib), kp, &len, NULL, 0) == 0)
		for (size_t i = 0; i < len / sizeof(*kp); i++) {
			/* The agent's children are of no use to watch. */
			if (kp[i].ki_pid == self || kp[i].ki_ppid == self)
				continue;
			proc_watch(kq, kp[i].ki_pid);
		}
	free(kp);
}

static void
proc_event(const struct kevent *ev)
{
	pid_t	pid = (pid_t)ev->ident;

	if ((ev->fflags & NOTE_CHILD) != 0) {
		/* A child of one of the agent's is the agent's too. */
		if (is_mine((pid_t)ev->data))
			mine_add(pid);
		else
			started++;
	}
	if ((ev->fflags & NOTE_EXIT) != 0) {
		if (is_mine(pid))
			mine_del(pid);
		else
			exited++;
	}
}

/* devd's notification: "!system=ZFS subsystem=ZFS type=... pool=...". */
static const char *
field(const char *msg, const char *key, char *buf, size_t len)
{
	const char	*p, *e;
	size_t		 kl = strlen(key);

	for (p = msg; (p = strstr(p, key)) != NULL; p += kl) {
		if ((p != msg && p[-1] != ' ' && p[-1] != '!') || p[kl] != '=')
			continue;
		p += kl + 1;
		e = p + strcspn(p, " \n");
		snprintf(buf, len, "%.*s", (int)(e - p), p);
		return (buf);
	}
	return (NULL);
}

/* A disk's node, as storage lists the disks: not a partition's. */
static bool
disk_node(const char *cdev)
{
	static const char *const prefixes[] = { "ada", "da", "nda", "nvd",
	    "vtbd", "mmcsd", "md", "xbd", "mfid", "mfisyspd" };
	size_t	n;

	for (size_t i = 0; i < nitems(prefixes); i++) {
		n = strlen(prefixes[i]);
		if (strncmp(cdev, prefixes[i], n) == 0 && cdev[n] >= '0' &&
		    cdev[n] <= '9' && cdev[n + strspn(cdev + n,
		    "0123456789")] == '\0')
			return (true);
	}
	return (false);
}

static void
seen_add(const char *kind, const char *a, const char *b)
{

	for (size_t i = 0; i < nseen; i++)
		if (strcmp(seen[i].kind, kind) == 0 &&
		    strcmp(seen[i].a, a) == 0 && strcmp(seen[i].b, b) == 0)
			return;
	if (nseen == SEEN_MAX)
		return;
	strlcpy(seen[nseen].kind, kind, sizeof(seen[nseen].kind));
	strlcpy(seen[nseen].a, a, sizeof(seen[nseen].a));
	strlcpy(seen[nseen].b, b, sizeof(seen[nseen].b));
	nseen++;
}

/* Letters, digits and ._-: what goes into an event as it is. */
static bool
plain(const char *s)
{

	return (s[strspn(s, "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/")] == '\0');
}

static void
devd_message(const char *msg)
{
	char	 sys[16], sub[16], type[96], a[64], *t;

	if (msg[0] != '!' || field(msg, "system", sys, sizeof(sys)) == NULL)
		return;
	if (strcmp(sys, "ZFS") == 0 && field(msg, "type", type,
	    sizeof(type)) != NULL) {
		/* sysevent.fs.zfs.pool_import: pool_import. */
		t = strrchr(type, '.') != NULL ? strrchr(type, '.') + 1 : type;
		if (field(msg, "pool_name", a, sizeof(a)) == NULL &&
		    field(msg, "pool", a, sizeof(a)) == NULL)
			a[0] = '\0';
		if (plain(t) && plain(a))
			seen_add("zfs", t, a);
		return;
	}
	if (strcmp(sys, "DEVFS") == 0 && field(msg, "subsystem", sub,
	    sizeof(sub)) != NULL && strcmp(sub, "CDEV") == 0 &&
	    field(msg, "type", type, sizeof(type)) != NULL &&
	    field(msg, "cdev", a, sizeof(a)) != NULL && disk_node(a) &&
	    (strcmp(type, "CREATE") == 0 || strcmp(type, "DESTROY") == 0))
		seen_add("device", a, strcmp(type, "CREATE") == 0 ? "created" :
		    "destroyed");
}

static void
devd_open(int kq)
{
	struct sockaddr_un	 sun;
	struct kevent		 ev;
	int			 s;

	devd_next = time(NULL) + DEVD_RETRY;
	if ((s = socket(PF_LOCAL, SOCK_SEQPACKET | SOCK_CLOEXEC, 0)) == -1)
		return;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, DEVD_SOCK, sizeof(sun.sun_path));
	if (connect(s, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		close(s);
		return;
	}
	EV_SET(&ev, s, EVFILT_READ, EV_ADD, 0, 0, (void *)(intptr_t)W_DEVD);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
		close(s);
		return;
	}
	devd = s;
}

static void
devd_read(void)
{
	char	buf[DEVD_MSG];
	ssize_t	n;

	if ((n = recv(devd, buf, sizeof(buf) - 1, MSG_DONTWAIT)) <= 0) {
		if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
			/* devd went: closing takes it out of the kqueue. */
			close(devd);
			devd = -1;
		}
		return;
	}
	buf[n] = '\0';
	devd_message(buf);
}

/* What was seen since the last tick, said. */
static void
tick(int kq)
{
	static unsigned	ticks;

	for (size_t i = 0; i < nitems(files); i++)
		if (files[i].changed) {
			files[i].changed = false;
			event_add("conf", "{\"file\":\"%s\"}", files[i].path);
		}
	if (started > 0 || exited > 0) {
		event_add("procs", "{\"started\":%u,\"exited\":%u}", started,
		    exited);
		started = exited = 0;
	}
	for (size_t i = 0; i < nseen; i++)
		if (strcmp(seen[i].kind, "zfs") == 0)
			event_add("zfs", "{\"type\":\"%s\",\"pool\":\"%s\"}",
			    seen[i].a, seen[i].b);
		else
			event_add("device", "{\"cdev\":\"%s\",\"state\":"
			    "\"%s\"}", seen[i].a, seen[i].b);
	nseen = 0;
	if (devd == -1 && time(NULL) >= devd_next)
		devd_open(kq);
	/* What the kernel announces nowhere (a description, a FIB, a
	 * group, media; a jail's), read again a minute on. */
	if (++ticks % (60000 / TICK_MS) == 0) {
		yang_changed(YANG_INTERFACES);
		yang_changed(YANG_INSTANCES);
		yang_changed(YANG_LNES);
	}
}

static void *
watcher(void *arg)
{
	struct kevent	 ev[32];
	int		 kq = (int)(intptr_t)arg, n;

	for (;;) {
		if ((n = kevent(kq, NULL, 0, ev, nitems(ev), NULL)) == -1) {
			if (errno == EINTR)
				continue;
			logmsg(LOG_NOTICE, "the host's changes are no longer "
			    "watched: kevent: %s", strerror(errno));
			break;
		}
		for (int i = 0; i < n; i++)
			switch ((enum what)(intptr_t)ev[i].udata) {
			case W_FILE:
				for (size_t j = 0; j < nitems(files); j++)
					if (files[j].fd == (int)ev[i].ident) {
						files[j].changed = true;
						/* Gone or renamed over: the
						 * name is another file now. */
						if ((ev[i].fflags &
						    (NOTE_DELETE |
						    NOTE_RENAME)) != 0)
							dir_changed(kq);
					}
				break;
			case W_DIR:
				dir_changed(kq);
				break;
			case W_PROC:
				proc_event(&ev[i]);
				break;
			case W_DEVD:
				if (devd != -1)
					devd_read();
				break;
			case W_TICK:
				tick(kq);
				break;
			}
	}
	close(kq);
	return (NULL);
}

void
host_watch_start(void)
{
	struct kevent	ev;
	pthread_t	tid;
	int		kq, error;

	if ((kq = kqueue()) == -1) {
		logmsg(LOG_NOTICE, "the host's changes are not watched: "
		    "kqueue: %s", strerror(errno));
		return;
	}
	files[0].path = "/etc/rc.conf";
	files[1].path = "/etc/rc.conf.local";
	files[2].path = opts.sysctl_conf;
	files[3].path = opts.fstab_path;
	files[4].path = opts.jail_conf != NULL ? opts.jail_conf :
	    "/etc/jail.conf";
	files[5].path = "/boot/loader.conf";
	files[6].path = "/etc/ssh/sshd_config";
	for (size_t i = 0; i < nitems(files); i++) {
		files[i].fd = -1;
		file_watch(kq, &files[i]);
		dir_watch(kq, files[i].path);
	}
	procs_watch_all(kq);
	devd_open(kq);
	EV_SET(&ev, 1, EVFILT_TIMER, EV_ADD, 0, TICK_MS,
	    (void *)(intptr_t)W_TICK);
	(void)kevent(kq, &ev, 1, NULL, 0, NULL);
	if ((error = pthread_create(&tid, NULL, watcher,
	    (void *)(intptr_t)kq)) != 0) {
		logmsg(LOG_WARNING, "the host's changes are not watched: "
		    "pthread_create: %s", strerror(error));
		close(kq);
		return;
	}
	(void)pthread_detach(tid);
}
