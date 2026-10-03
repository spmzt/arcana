/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * arcana-agent built from a git repository, for the console to hand to
 * the other hosts.  The tree is cloned afresh into the build directory
 * and built there with make(1); as root, git and make run as nobody, so
 * what a repository's makefiles do is done without privilege.  Nothing
 * is installed: the program goes back in the reply.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "agent.h"

#define	BUILD_USER	"nobody"
#define	VERSION_PREFIX	"arcana-agent "
#define	MAX_ARGS	16

static int	run_as(struct work *, bool, const char *const *,
		    struct execres *);
static bool	valid_source(const char *);
static bool	valid_ref(const char *);

/* What git clone takes: a URL or a path, and never an option. */
static bool
valid_source(const char *s)
{

	if (s[0] == '\0' || s[0] == '-')
		return (false);
	for (; *s != '\0'; s++)
		if (!isgraph((unsigned char)*s))
			return (false);
	return (true);
}

static bool
valid_ref(const char *s)
{

	if (s[0] == '-')
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("._/-", *s) == NULL)
			return (false);
	return (true);
}

/* Run argv, through chroot(8) -u as the build user when unpriv is set. */
static int
run_as(struct work *w, bool unpriv, const char *const *argv,
    struct execres *res)
{
	char	*full[MAX_ARGS + 5];
	int	 n, i;

	n = 0;
	if (unpriv) {
		full[n++] = (char *)(uintptr_t)"/usr/sbin/chroot";
		full[n++] = (char *)(uintptr_t)"-u";
		full[n++] = (char *)(uintptr_t)BUILD_USER;
		full[n++] = (char *)(uintptr_t)"/";
	}
	for (i = 0; argv[i] != NULL && i < MAX_ARGS; i++)
		full[n++] = (char *)(uintptr_t)argv[i];
	full[n] = NULL;
	return (run_exec(w, full, res));
}

int
do_agent_build(struct work *w, const char *source, const char *ref,
    struct arc_agent_build_rsp *rsp)
{
	struct execres	 res;
	struct passwd	*pw;
	struct stat	 sb;
	unsigned char	 md[EVP_MAX_MD_SIZE];
	const char	*argv[MAX_ARGS], *nl;
	char		*src, *objdir, *prog, *sha, *conf;
	uint8_t		*bin;
	ssize_t		 r;
	size_t		 off;
	unsigned int	 i, mdlen;
	bool		 unpriv;
	int		 fd, n, s;

	rsp->has_ok = true;
	rsp->ok = false;
	if (!valid_source(source)) {
		rsp->error = "not a repository git clone can take";
		return (0);
	}
	if (ref != NULL && !valid_ref(ref)) {
		rsp->error = "not a branch or tag name";
		return (0);
	}
	unpriv = geteuid() == 0;
	src = wfmt(w, "%s/src", opts.build_dir);

	/* The build directory, the build user's when there is one. */
	s = step_begin(w, ARC_STEP_KIND_FILE, "mkdir", "%s", opts.build_dir);
	if (mkdir(opts.build_dir, 0755) == -1 && errno != EEXIST) {
		step_end(w, s, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "%s: %s", opts.build_dir, strerror(errno));
		return (0);
	}
	if (unpriv && ((pw = getpwnam(BUILD_USER)) == NULL ||
	    chown(opts.build_dir, pw->pw_uid, pw->pw_gid) == -1)) {
		step_end(w, s, false, "no user %s to build as", BUILD_USER);
		rsp->error = "no user to build as";
		return (0);
	}
	step_end(w, s, true, unpriv ? "owned by " BUILD_USER : NULL);

	n = 0;
	argv[n++] = "/bin/rm";
	argv[n++] = "-rf";
	argv[n++] = "--";
	argv[n++] = src;
	argv[n] = NULL;
	if (run_as(w, unpriv, argv, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "rm"));
		return (0);
	}
	n = 0;
	argv[n++] = opts.git_bin;
	argv[n++] = "clone";
	argv[n++] = "--depth";
	argv[n++] = "1";
	if (ref != NULL && ref[0] != '\0') {
		argv[n++] = "--branch";
		argv[n++] = ref;
	}
	argv[n++] = "--";
	argv[n++] = source;
	argv[n++] = src;
	argv[n] = NULL;
	if (run_as(w, unpriv, argv, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "git clone"));
		return (0);
	}

	/* This host's settings for the build, where it has any. */
	if (access(opts.build_conf, R_OK) == 0) {
		conf = wfmt(w, "%s/config.mk", src);
		n = 0;
		argv[n++] = "/bin/cp";
		argv[n++] = opts.build_conf;
		argv[n++] = conf;
		argv[n] = NULL;
		if (run_as(w, unpriv, argv, &res) != 0) {
			rsp->error = wtext(w, exec_error(w, &res, "cp"));
			return (0);
		}
	}

	/* The library the agent links, then the agent; no tests. */
	n = 0;
	argv[n++] = opts.make_bin;
	argv[n++] = "-C";
	argv[n++] = wfmt(w, "%s/lib/libjailconf", src);
	argv[n++] = "MK_TESTS=no";
	argv[n] = NULL;
	if (run_as(w, unpriv, argv, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "make libjailconf"));
		return (0);
	}
	argv[2] = wfmt(w, "%s/usr.sbin/arcana-agent", src);
	if (run_as(w, unpriv, argv, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "make arcana-agent"));
		return (0);
	}
	n = 3;
	argv[n++] = "-V";
	argv[n++] = ".OBJDIR";
	argv[n] = NULL;
	if (run_as(w, unpriv, argv, &res) != 0 || res.outlen < 2) {
		rsp->error = wtext(w, exec_error(w, &res, "make -V .OBJDIR"));
		return (0);
	}
	nl = memchr(res.out, '\n', res.outlen);
	objdir = wstrndup(w, res.out, nl != NULL ? (size_t)(nl - res.out) :
	    res.outlen);
	prog = wfmt(w, "%s/arcana-agent", objdir);

	s = step_begin(w, ARC_STEP_KIND_FILE, "read", "%s", prog);
	if ((fd = open(prog, O_RDONLY | O_CLOEXEC)) == -1 || fstat(fd,
	    &sb) == -1 || sb.st_size == 0 || sb.st_size > ARC_MAX_BINARY) {
		step_end(w, s, false, "%s", fd == -1 ? strerror(errno) :
		    "not a program an update can carry");
		rsp->error = wfmt(w, "%s: no program to send back", prog);
		if (fd != -1)
			close(fd);
		return (0);
	}
	bin = wmalloc(w, (size_t)sb.st_size);
	for (off = 0; off < (size_t)sb.st_size; off += (size_t)r)
		if ((r = read(fd, bin + off, (size_t)sb.st_size - off)) <= 0)
			break;
	close(fd);
	if (off < (size_t)sb.st_size || EVP_Digest(bin, off, md, &mdlen,
	    EVP_sha256(), NULL) != 1) {
		step_end(w, s, false, "short read");
		rsp->error = wfmt(w, "%s: cannot read", prog);
		return (0);
	}
	sha = wmalloc(w, 2 * mdlen + 1);
	for (i = 0; i < mdlen; i++)
		snprintf(sha + 2 * i, 3, "%02x", md[i]);
	step_end(w, s, true, "%zu bytes, SHA-256 %s", off, sha);

	/* What it says it is. */
	argv[0] = prog;
	argv[1] = "-V";
	argv[2] = NULL;
	if (run_as(w, unpriv, argv, &res) != 0 || res.outlen <= strlen(
	    VERSION_PREFIX) || strncmp(res.out, VERSION_PREFIX, strlen(
	    VERSION_PREFIX)) != 0) {
		rsp->error = "what was built does not run as arcana-agent";
		return (0);
	}
	nl = memchr(res.out, '\n', res.outlen);
	rsp->agent_version = wstrndup(w, res.out + strlen(VERSION_PREFIX),
	    (nl != NULL ? (size_t)(nl - res.out) : res.outlen) -
	    strlen(VERSION_PREFIX));
	rsp->binary.p = bin;
	rsp->binary.len = off;
	rsp->sha256 = sha;
	rsp->ok = true;
	return (0);
}
