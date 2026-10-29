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
 * <path>.old.  A program sent compressed is inflated first, to no more
 * than max-program bytes: what is checked, signed and installed is the
 * program, as it runs.
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
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "agent.h"
#include "zprog.h"

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

/*
 * Is the program signed by a CA this host trusts (-A)?  The console's
 * CA key signs what it sends (SHA-256; Ed25519 with its own hash), and
 * any certificate of the CA file verifies.
 */
static bool
signed_by_ca(const uint8_t *data, size_t len, const uint8_t *sig,
    size_t siglen, const char **why)
{
	FILE		*fp;
	X509		*x;
	EVP_PKEY	*pk;
	EVP_MD_CTX	*ctx;
	const char	*ca;
	bool		 ok, any;

	if ((ca = tls_files_ca()) == NULL || (fp = fopen(ca, "r")) == NULL) {
		*why = "this host trusts no CA (-A): nothing can sign a program "
		    "for it";
		return (false);
	}
	ok = any = false;
	while (!ok && (x = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
		any = true;
		if ((pk = X509_get0_pubkey(x)) != NULL && (ctx = EVP_MD_CTX_new())
		    != NULL) {
			ok = EVP_DigestVerifyInit(ctx, NULL, EVP_PKEY_id(pk) ==
			    EVP_PKEY_ED25519 ? NULL : EVP_sha256(), NULL, pk) == 1 &&
			    EVP_DigestVerify(ctx, sig, siglen, data, len) == 1;
			EVP_MD_CTX_free(ctx);
		}
		X509_free(x);
	}
	fclose(fp);
	if (!ok)
		*why = any ? "the program is not signed by a CA this host trusts" :
		    "the CA file holds no certificate";
	return (ok);
}

static int
agent_install(struct work *w, const uint8_t *data, size_t len,
    const char *sha256, const uint8_t *sig, size_t siglen, bool local,
    struct arc_agent_update_rsp *rsp)
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

	/* Signed by the CA, unless asked by the local socket, whose root
	 * could replace the program by hand. */
	if (!local) {
		const char	*why;

		s = step_begin(w, ARC_STEP_KIND_LIB, "signature", "%zu bytes by "
		    "the CA's key", siglen);
		if (siglen == 0) {
			step_end(w, s, false, "none");
			rsp->error = "the program is not signed: a console signs "
			    "what it sends with its CA key";
			return (0);
		}
		if (!signed_by_ca(data, len, sig, siglen, &why)) {
			step_end(w, s, false, "%s", why);
			rsp->error = why;
			return (0);
		}
		step_end(w, s, true, "verified");
	}
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
 * The program of len bytes at data, or, with size, compressed and to
 * inflate to size bytes.
 */
int
do_agent_update(struct work *w, const uint8_t *data, size_t len,
    size_t size, const char *sha256, const uint8_t *sig, size_t siglen,
    bool local, struct arc_agent_update_rsp *rsp)
{
	const char	*why;
	uint8_t		*prog;
	int		 rc, s;

	if (size == 0)
		return (agent_install(w, data, len, sha256, sig, siglen, local,
		    rsp));
	rsp->has_ok = true;
	rsp->ok = false;
	s = step_begin(w, ARC_STEP_KIND_LIB, "inflate(3)", "%zu bytes of "
	    "gzip into %zu", len, size);
	if ((why = zprog_inflate(data, len, size, ARC_MAX_PROGRAM,
	    &prog)) != NULL) {
		step_end(w, s, false, "%s", why);
		rsp->error = why;
		return (0);
	}
	step_end(w, s, true, "%zu bytes", size);
	rc = agent_install(w, prog, size, sha256, sig, siglen, local, rsp);
	free(prog);
	return (rc);
}

/*
 * Restart the service, from a process of its own that outlives this
 * one: service(8) stops this daemon and starts the new program.  It
 * waits a moment first, for the reply to leave.
 */
void
service_restart(const char *name)
{

	service_detached(name, "restart");
}

/*
 * service(8) name verb, from a process of its own that outlives this
 * daemon.  For what is done to the daemon's own service: run and waited
 * for like any other, service(8) would wait for the daemon to stop
 * while the daemon waits for service(8) to end.
 */
void
service_detached(const char *name, const char *verb)
{
	struct timespec	 ts = { 1, 0 };
	sigset_t	 none;
	pid_t		 pid;
	int		 status;

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
	/*
	 * service(8) runs in a child, so that its failing is not lost:
	 * a service that is not enabled, or not there, refuses, and
	 * nothing else would say why the old program still runs.
	 */
	if ((pid = fork()) == 0) {
		execl(opts.service_bin, opts.service_bin, name, verb,
		    (char *)NULL);
		_exit(127);
	}
	if (pid == -1 || waitpid(pid, &status, 0) == -1 ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		execl("/usr/bin/logger", "logger", "-t", "arcana-agent", "-p",
		    "daemon.err", "service(8) failed:", name, verb,
		    "(is it enabled in rc.conf?)", (char *)NULL);
	_exit(0);
}
