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
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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
	struct pollfd			 pfd[2];
	struct capture			 out, eout;
	static char			 pathenv[] =
	    "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	char				*env[] = { pathenv, NULL };
	const char			*cmdline;
	size_t				 i;
	time_t				 deadline;
	pid_t				 pid;
	int				 op[2], ep[2], status, rc, step, n;
	bool				 exited;

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
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null",
	    O_RDONLY, 0);
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
	posix_spawnattr_destroy(&sa);
	posix_spawn_file_actions_destroy(&fa);
	close(op[1]);
	close(ep[1]);
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
		n = poll(pfd, 2, exited ? 0 : 1000);
		if (n == -1 && errno != EINTR)
			err(1, "poll");
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
			break;
		}
	}
	if (op[0] != -1)
		close(op[0]);
	if (ep[0] != -1)
		close(ep[0]);
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
	if (len == 0)
		return (wfmt(w, "%s exited with status %d", prog,
		    res->status));
	for (p = res->err + len; p > res->err && p[-1] != '\n'; p--)
		;
	return (wfmt(w, "%s exited with status %d: %.*s", prog,
	    res->status, (int)(res->err + len - p), p));
}
