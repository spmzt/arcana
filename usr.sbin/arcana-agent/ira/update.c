/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A new arcana-agent, sent by the console.  It is written beside the
 * installed one, checked against the SHA-256 that came with it, and run
 * with -V: a program for another machine or system does not run, and
 * never takes the place of one that does.  The one installed stays as
 * <path>.old.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "agent.h"

#define	VERSION_PREFIX	"arcana-agent "

static bool
sha256_is(const uint8_t *data, size_t len, const char *hex)
{
	unsigned char	md[EVP_MAX_MD_SIZE];
	char		got[2 * EVP_MAX_MD_SIZE + 1];
	unsigned int	i, n;

	if (EVP_Digest(data, len, md, &n, EVP_sha256(), NULL) != 1)
		return (false);
	for (i = 0; i < n; i++)
		snprintf(got + 2 * i, 3, "%02x", md[i]);
	return (strcasecmp(got, hex) == 0);
}

int
do_agent_update(struct work *w, const uint8_t *data, size_t len,
    const char *sha256, struct arc_agent_update_rsp *rsp)
{
	struct execres	 res;
	const char	*path, *nl;
	char		*new, *old, *argv[3];
	ssize_t		 n;
	size_t		 off;
	int		 fd, s;

	rsp->has_ok = true;
	rsp->ok = false;
	path = opts.self_path;
	new = wfmt(w, "%s.new", path);
	old = wfmt(w, "%s.old", path);

	s = step_begin(w, ARC_STEP_KIND_LIB, "SHA-256", "%zu bytes", len);
	if (!sha256_is(data, len, sha256)) {
		step_end(w, s, false, "not %s", sha256);
		rsp->error = "the program does not match its SHA-256";
		return (0);
	}
	step_end(w, s, true, "%s", sha256);

	s = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", new);
	(void)unlink(new);
	if ((fd = open(new, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
	    0555)) == -1) {
		step_end(w, s, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "%s: %s", new, strerror(errno));
		return (0);
	}
	for (off = 0; off < len; off += (size_t)n)
		if ((n = write(fd, data + off, len - off)) == -1)
			break;
	if (off < len || fsync(fd) == -1) {
		step_end(w, s, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "%s: %s", new, strerror(errno));
		close(fd);
		(void)unlink(new);
		return (0);
	}
	close(fd);
	step_end(w, s, true, "%zu bytes", len);

	/* It has to run here, and say what it is. */
	argv[0] = new;
	argv[1] = (char *)(uintptr_t)"-V";
	argv[2] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.outlen <= strlen(
	    VERSION_PREFIX) || strncmp(res.out, VERSION_PREFIX, strlen(
	    VERSION_PREFIX)) != 0) {
		rsp->error = "the program does not run on this host as "
		    "arcana-agent";
		(void)unlink(new);
		return (0);
	}
	nl = memchr(res.out, '\n', res.outlen);
	rsp->agent_version = wstrndup(w, res.out + strlen(VERSION_PREFIX),
	    (nl != NULL ? (size_t)(nl - res.out) : res.outlen) -
	    strlen(VERSION_PREFIX));

	s = step_begin(w, ARC_STEP_KIND_FILE, "replace", "%s", path);
	(void)unlink(old);
	if ((link(path, old) == -1 && errno != ENOENT) ||
	    rename(new, path) == -1) {
		step_end(w, s, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "%s: %s", path, strerror(errno));
		(void)unlink(new);
		return (0);
	}
	step_end(w, s, true, "the one before is %s", old);
	rsp->ok = true;
	return (0);
}

/*
 * Restart the service, from a process of its own that outlives this
 * one: service(8) stops this daemon and starts the new program.  It
 * waits a moment first, for the reply to leave.
 */
void
agent_restart(void)
{
	struct timespec	 ts = { 1, 0 };
	sigset_t	 none;
	pid_t		 pid;

	if ((pid = fork()) == -1) {
		logmsg(LOG_ERR, "restart: fork: %s", strerror(errno));
		return;
	}
	if (pid > 0) {
		(void)waitpid(pid, NULL, 0);
		return;
	}
	if (fork() != 0)
		_exit(0);
	(void)setsid();
	sigemptyset(&none);
	(void)sigprocmask(SIG_SETMASK, &none, NULL);
	closefrom(3);
	(void)nanosleep(&ts, NULL);
	execl(opts.service_bin, opts.service_bin, "arcana_agent", "restart",
	    (char *)NULL);
	_exit(127);
}
