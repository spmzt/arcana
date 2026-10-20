/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Run a program with posix_spawn(3), never through a shell, capturing
 * stdout and stderr and recording it as an exec step.
 */

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <libutil.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"

struct capture {
	char	*buf;
	size_t	 len;
	size_t	 max;
	bool	 truncated;
};

static void	capture_read(int *, struct capture *);

static void
capture_read(int *fd, struct capture *c)
{
	char	buf[8192];
	ssize_t	n;

	n = read(*fd, buf, sizeof(buf));
	if (n <= 0) {
		close(*fd);
		*fd = -1;
		return;
	}
	if (c->len + (size_t)n > c->max) {
		n = (ssize_t)(c->max - c->len);
		c->truncated = true;
	}
	if (n > 0) {
		if ((c->buf = realloc(c->buf, c->len + (size_t)n)) == NULL)
			err(1, "realloc");
		memcpy(c->buf + c->len, buf, (size_t)n);
		c->len += (size_t)n;
	}
}

/*
 * Returns the exit status (128 + signal when killed), or -1 if the
 * program could not be started.  The output in *res lives in w's pool.
 */
int
run_exec(struct work *w, char *const argv[], struct execres *res)
{

	return (run_exec_max(w, argv, res, ARC_MAX_OUTPUT));
}

/*
 * HOME for the programs this thread runs, or none.  A build sets it to
 * its directory: compilers keep caches under it (emcc refuses to run
 * without one), and the build user has no home of its own.
 */
static _Thread_local char	*exec_home;

/*
 * What the next program run by this thread reads on its standard input,
 * through a pipe: a key, which no file and no argument list holds.  Once
 * only; /dev/null otherwise.
 */
static _Thread_local const char	*exec_in;
static _Thread_local size_t	 exec_inlen;

void
exec_set_stdin(const char *text, size_t len)
{

	exec_in = text;
	exec_inlen = len;
}

/*
 * What the programs this thread runs print is kept out of the trace,
 * while this is set: it has keys in it, and a trace is read far away.
 */
static _Thread_local bool	exec_secret;

void
exec_set_secret(bool on)
{

	exec_secret = on;
}

void
exec_set_home(struct work *w, const char *dir)
{

	exec_home = dir != NULL ? wfmt(w, "HOME=%s", dir) : NULL;
}

/* One more NAME=value in the environment of what this thread runs
 * (SSH_AUTH_SOCK for ssh-add and ssh-keygen -U), or none with NULL. */
static _Thread_local char	*exec_extra;

void
exec_set_env(struct work *w, const char *name, const char *value)
{

	exec_extra = name != NULL ? wfmt(w, "%s=%s", name, value) : NULL;
}

/*
 * As run_exec(), keeping up to max bytes of standard output for the
 * caller; the trace step still carries at most ARC_MAX_OUTPUT of them.
 * res->truncated says the program printed more than was kept.
 */
int
run_exec_max(struct work *w, char *const argv[], struct execres *res,
    size_t max)
{
	posix_spawn_file_actions_t	 fa;
	posix_spawnattr_t		 sa;
	sigset_t			 none, dfl;
	struct pollfd			 pfd[3];
	struct capture			 out, eout;
	static char			 pathenv[] =
	    "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin";
	/* git reads no configuration but the repository's own. */
	static char			 gitglobal[] =
	    "GIT_CONFIG_GLOBAL=/dev/null";
	static char			 gitsystem[] = "GIT_CONFIG_NOSYSTEM=1";
	char				*env[6];
	const char			*cmdline;
	size_t				 i;
	time_t				 deadline;
	int				 ne;

	ne = 0;
	env[ne++] = pathenv;
	env[ne++] = gitglobal;
	env[ne++] = gitsystem;
	if (exec_home != NULL)
		env[ne++] = exec_home;
	if (exec_extra != NULL)
		env[ne++] = exec_extra;
	env[ne] = NULL;
	pid_t				 pid;
	int				 op[2], ep[2], ip[2], status, rc, step,
					 n;
	bool				 exited;
	const char			*in;
	size_t				 inlen, off;
	ssize_t				 wr;

	argv = scope_argv(w, argv);
	in = exec_in;
	inlen = exec_inlen;
	exec_in = NULL;
	exec_inlen = 0;

	memset(res, 0, sizeof(*res));
	cmdline = wvis(w, argv[0]);
	for (i = 1; argv[i] != NULL; i++)
		cmdline = wfmt(w, "%s %s", cmdline, wvis(w, argv[i]));
	step = step_begin(w, ARC_STEP_KIND_EXEC, cmdline,
	    "posix_spawn(3), no shell");

	memset(&out, 0, sizeof(out));
	memset(&eout, 0, sizeof(eout));
	out.max = max;
	eout.max = ARC_MAX_OUTPUT;
	if (pipe2(op, O_CLOEXEC) == -1 || pipe2(ep, O_CLOEXEC) == -1)
		err(1, "pipe2");
	ip[0] = ip[1] = -1;
	if (in != NULL && pipe2(ip, O_CLOEXEC) == -1)
		err(1, "pipe2");
	posix_spawn_file_actions_init(&fa);
	if (in != NULL)
		posix_spawn_file_actions_adddup2(&fa, ip[0], STDIN_FILENO);
	else
		posix_spawn_file_actions_addopen(&fa, STDIN_FILENO,
		    "/dev/null", O_RDONLY, 0);
	posix_spawn_file_actions_adddup2(&fa, op[1], STDOUT_FILENO);
	posix_spawn_file_actions_adddup2(&fa, ep[1], STDERR_FILENO);
	/* The daemon keeps its stop signals blocked; a program does not. */
	sigemptyset(&none);
	sigemptyset(&dfl);
	sigaddset(&dfl, SIGTERM);
	sigaddset(&dfl, SIGINT);
	posix_spawnattr_init(&sa);
	posix_spawnattr_setsigmask(&sa, &none);
	posix_spawnattr_setsigdefault(&sa, &dfl);
	posix_spawnattr_setflags(&sa, POSIX_SPAWN_SETSIGMASK |
	    POSIX_SPAWN_SETSIGDEF);
	rc = posix_spawn(&pid, argv[0], &fa, &sa, argv, env);
	if (rc == 0 && w->nice)
		(void)setpriority(PRIO_PROCESS, pid, READ_NICE);
	posix_spawnattr_destroy(&sa);
	posix_spawn_file_actions_destroy(&fa);
	close(op[1]);
	close(ep[1]);
	/*
	 * What the program reads is written as it reads it, beside its
	 * output being read: a large input (a ruleset for ipfw -n) does not
	 * wait on a pipe the program cannot empty while its own output
	 * fills the other.
	 */
	off = 0;
	if (in != NULL) {
		close(ip[0]);
		if (rc != 0 || inlen == 0) {
			close(ip[1]);
			ip[1] = -1;
		} else
			(void)fcntl(ip[1], F_SETFL, fcntl(ip[1], F_GETFL) |
			    O_NONBLOCK);
	} else
		ip[1] = -1;
	if (rc != 0) {
		close(op[0]);
		close(ep[0]);
		res->status = -1;
		res->err = wfmt(w, "cannot run %s: %s", argv[0],
		    strerror(rc));
		res->errlen = strlen(res->err);
		step_exec(w, step, argv, -1, NULL, 0, res->err, res->errlen);
		step_end(w, step, false, "%s", res->err);
		return (-1);
	}

	/*
	 * Read until the program has exited and its output is drained, not
	 * until the pipes close: what a jail's exec.start leaves running may
	 * keep them open for as long as it lives.
	 */
	exited = false;
	deadline = time(NULL) + EXEC_TIMEOUT_SEC;
	while (op[0] != -1 || ep[0] != -1) {
		pfd[0].fd = op[0];
		pfd[0].events = POLLIN;
		pfd[1].fd = ep[0];
		pfd[1].events = POLLIN;
		pfd[2].fd = ip[1];
		pfd[2].events = POLLOUT;
		n = poll(pfd, 3, exited ? 0 : 1000);
		if (n == -1 && errno != EINTR)
			err(1, "poll");
		if (n > 0 && ip[1] != -1 && (pfd[2].revents & (POLLOUT | POLLHUP |
		    POLLERR))) {
			wr = (pfd[2].revents & POLLOUT) ? write(ip[1], in + off,
			    inlen - off) : -1;
			if (wr > 0)
				off += (size_t)wr;
			/* All of it written, or the program is not reading. */
			if (off >= inlen || (wr == -1 && errno != EAGAIN &&
			    errno != EINTR) || (pfd[2].revents & (POLLHUP |
			    POLLERR))) {
				close(ip[1]);
				ip[1] = -1;
			}
		}
		if (n > 0) {
			if (op[0] != -1 &&
			    (pfd[0].revents & (POLLIN | POLLHUP)))
				capture_read(&op[0], &out);
			if (ep[0] != -1 &&
			    (pfd[1].revents & (POLLIN | POLLHUP)))
				capture_read(&ep[0], &eout);
		} else if (n == 0 && exited)
			break;
		if (exited)
			continue;
		if (waitpid(pid, &status, WNOHANG) == pid) {
			exited = true;
			continue;
		}
		if (time(NULL) > deadline) {
			kill(pid, SIGTERM);
			sleep(2);
			kill(pid, SIGKILL);
			res->timedout = true;
			break;
		}
	}
	if (op[0] != -1)
		close(op[0]);
	if (ep[0] != -1)
		close(ep[0]);
	if (ip[1] != -1)
		close(ip[1]);
	while (!exited && waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			err(1, "waitpid");
	rc = WIFEXITED(status) ? WEXITSTATUS(status) :
	    128 + WTERMSIG(status);

	res->status = rc;
	res->out = out.len > 0 ? wstrndup(w, out.buf, out.len) : "";
	res->outlen = out.len;
	res->err = eout.len > 0 ? wstrndup(w, eout.buf, eout.len) : "";
	res->errlen = eout.len;
	res->truncated = out.truncated;
	free(out.buf);
	free(eout.buf);
	if (exec_secret)
		step_exec(w, step, argv, rc, "(not kept: it has keys in it)\n",
		    30, res->err, res->errlen);
	else
		step_exec(w, step, argv, rc, res->out, MIN(res->outlen,
		    (size_t)ARC_MAX_OUTPUT), res->err, res->errlen);
	step_end(w, step, rc == 0, "exit status %d%s", rc,
	    out.truncated || eout.truncated ? ", output truncated" : "");
	return (rc);
}

/* "jail exited with status 1: <last line of stderr>" */
const char *
exec_error(struct work *w, const struct execres *res, const char *prog)
{
	const char	*p;
	size_t		 len;

	len = res->err != NULL ? res->errlen : 0;
	while (len > 0 && res->err[len - 1] == '\n')
		len--;
	if (res->timedout)
		return (wfmt(w, "%s was killed: it did not finish in time", prog));
	if (len == 0)
		return (wfmt(w, "%s exited with status %d", prog,
		    res->status));
	for (p = res->err + len; p > res->err && p[-1] != '\n'; p--)
		;
	return (wfmt(w, "%s exited with status %d: %.*s", prog,
	    res->status, (int)(res->err + len - p), p));
}

/*
 * Run a program for its lines: each goes to fn as it comes and none is
 * kept, for output too large to hold.  Standard error is dropped.
 * Returns the exit status, or -1 if the program could not be started.
 */
int
run_exec_lines(struct work *w, char *const argv[],
    void (*fn)(const char *, void *), void *arg)
{
	posix_spawn_file_actions_t	 fa;
	posix_spawnattr_t		 sa;
	sigset_t			 none, dfl;
	static char			 pathenv[] =
	    "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin";
	char				*env[] = { pathenv, NULL };
	const char			*cmdline;
	char				*line;
	size_t				 cap, i, lines;
	ssize_t				 len;
	FILE				*fp;
	pid_t				 pid;
	int				 op[2], status, rc, step;

	argv = scope_argv(w, argv);

	cmdline = wvis(w, argv[0]);
	for (i = 1; argv[i] != NULL; i++)
		cmdline = wfmt(w, "%s %s", cmdline, wvis(w, argv[i]));
	step = step_begin(w, ARC_STEP_KIND_EXEC, cmdline,
	    "posix_spawn(3), no shell; read line by line");
	if (pipe2(op, O_CLOEXEC) == -1)
		err(1, "pipe2");
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null",
	    O_RDONLY, 0);
	posix_spawn_file_actions_adddup2(&fa, op[1], STDOUT_FILENO);
	posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null",
	    O_WRONLY, 0);
	sigemptyset(&none);
	sigemptyset(&dfl);
	sigaddset(&dfl, SIGTERM);
	sigaddset(&dfl, SIGINT);
	posix_spawnattr_init(&sa);
	posix_spawnattr_setsigmask(&sa, &none);
	posix_spawnattr_setsigdefault(&sa, &dfl);
	posix_spawnattr_setflags(&sa, POSIX_SPAWN_SETSIGMASK |
	    POSIX_SPAWN_SETSIGDEF);
	rc = posix_spawn(&pid, argv[0], &fa, &sa, argv, env);
	if (rc == 0 && w->nice)
		(void)setpriority(PRIO_PROCESS, pid, READ_NICE);
	posix_spawnattr_destroy(&sa);
	posix_spawn_file_actions_destroy(&fa);
	close(op[1]);
	if (rc != 0 || (fp = fdopen(op[0], "r")) == NULL) {
		int	e = rc != 0 ? rc : errno;

		close(op[0]);
		/* Spawned but not read: reaped all the same, no zombie. */
		if (rc == 0)
			while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
				;
		step_end(w, step, false, "%s", strerror(e));
		return (-1);
	}
	line = NULL;
	cap = 0;
	lines = 0;
	while ((len = getline(&line, &cap, fp)) > 0) {
		if (line[len - 1] == '\n')
			line[len - 1] = '\0';
		fn(line, arg);
		lines++;
	}
	free(line);
	fclose(fp);
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			err(1, "waitpid");
	rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
	step_end(w, step, rc == 0, "exit status %d, %zu lines read", rc,
	    lines);
	return (rc);
}


/*
 * Is the process of a pid the program it is taken for?  A pid file
 * left by a crash or a reboot names a number that may be another's by
 * now: its name (ki_comm) or what it was started as (argv[0]) must be
 * the program's before it is believed, let alone signalled.
 */
bool
pid_is(pid_t pid, const char *prog)
{
	struct kinfo_proc	*kp;
	const char		*base;
	bool			 is;

	if (pid <= 1 || prog == NULL)
		return (false);
	if ((kp = kinfo_getproc(pid)) == NULL)
		return (false);
	base = strrchr(prog, '/') != NULL ? strrchr(prog, '/') + 1 : prog;
	is = strcmp(kp->ki_comm, base) == 0;
	free(kp);
	if (!is) {
		/* What it was started as: its argv[0], or, a script's (whose
		 * name the kernel gives its interpreter), argv[1]. */
		int	mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ARGS, pid };
		char	av[2 * MAXPATHLEN], *p, *e;
		size_t	len = sizeof(av) - 1;
		int	k;

		if (sysctl(mib, 4, av, &len, NULL, 0) == 0 && len > 0) {
			av[len] = '\0';
			for (p = av, k = 0; !is && k < 2 && p < av + len; p = e +
			    1, k++) {
				e = p + strlen(p);
				is = strcmp(p, prog) == 0 || (strrchr(p, '/') !=
				    NULL && strcmp(strrchr(p, '/') + 1, base) == 0);
			}
		}
	}
	return (is);
}

/* The pid a file holds, when that process is prog's; 0 otherwise. */
pid_t
pidfile_of(const char *path, const char *prog)
{
	FILE	*fp;
	long	 pid = 0;

	if ((fp = fopen(path, "re")) == NULL)
		return (0);
	if (fscanf(fp, "%ld", &pid) != 1)
		pid = 0;
	fclose(fp);
	return (pid > 1 && pid_is((pid_t)pid, prog) ? (pid_t)pid : 0);
}

/*
 * A program's process stopped: SIGTERM, up to wait_ms for it to go,
 * then SIGKILL; each signal only while the pid is still that program's.
 */
void
pid_stop(pid_t pid, const char *prog, int wait_ms)
{
	int	i;

	if (!pid_is(pid, prog))
		return;
	(void)kill(pid, SIGTERM);
	for (i = 0; i < wait_ms / 20 && pid_is(pid, prog); i++)
		usleep(20000);
	if (pid_is(pid, prog))
		(void)kill(pid, SIGKILL);
}
