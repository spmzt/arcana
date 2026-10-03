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
#define	MAX_ARGS	20

/* What fetching a tree came to, when it did not come to a tree. */
struct fetched {
	const char	*error;
	const char	*host_keys;	/* for a person to confirm */
	const char	*deploy_key;	/* this host's, for the server */
	struct {
		const char *const	*v;
		size_t			 n;
	} fingerprints;
};

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

/*
 * A repository reached over SSH, as "ssh://[user@]host[:port]/path" or
 * "[user@]host:path": its server's name as known_hosts has it, "host"
 * or "[host]:port", with the host and port apart.  False for the rest:
 * a path, or another scheme.
 */
static bool
ssh_source(struct work *w, const char *source, const char **namep,
    const char **hostp, const char **portp)
{
	const char	*p, *at, *end;
	char		*host, *colon;

	*portp = NULL;
	if (strncmp(source, "ssh://", 6) == 0) {
		p = source + 6;
		end = p + strcspn(p, "/");
		at = memchr(p, '@', (size_t)(end - p));
		if (at != NULL)
			p = at + 1;
		host = wstrndup(w, p, (size_t)(end - p));
		if ((colon = strrchr(host, ':')) != NULL && strchr(colon,
		    ']') == NULL) {
			*colon = '\0';
			*portp = colon + 1;
		}
	} else {
		if (strstr(source, "://") != NULL || source[0] == '/' ||
		    source[0] == '.')
			return (false);
		end = source + strcspn(source, ":/");
		if (*end != ':')
			return (false);
		at = memchr(source, '@', (size_t)(end - source));
		p = at != NULL ? at + 1 : source;
		host = wstrndup(w, p, (size_t)(end - p));
	}
	if (host[0] == '\0' || host[0] == '-')
		return (false);
	*hostp = host;
	*namep = *portp != NULL ? wfmt(w, "[%s]:%s", host, *portp) : host;
	return (true);
}

/* known_hosts lines for name and nobody else, a few of them, in ASCII. */
static bool
valid_host_keys(const char *keys, const char *name)
{
	const char	*p, *nl;
	size_t		 nlen;
	int		 lines;

	nlen = strlen(name);
	lines = 0;
	for (p = keys; *p != '\0'; p = *nl != '\0' ? nl + 1 : nl) {
		nl = p + strcspn(p, "\n");
		if (nl == p)
			continue;
		if (++lines > 8 || strncmp(p, name, nlen) != 0 || p[nlen] != ' ')
			return (false);
		for (; p < nl; p++)
			if (*p < 0x20 || *p > 0x7e)
				return (false);
	}
	return (lines > 0);
}

/*
 * The key lines for name in what ssh-keyscan printed: it also prints
 * the server's banner as comments, on standard output in some versions.
 */
static const char *
key_lines(struct work *w, const char *out, size_t len, const char *name)
{
	const char	*p, *nl, *end;
	char		*buf;
	size_t		 nlen, n;

	buf = wmalloc(w, len + 2);
	nlen = strlen(name);
	n = 0;
	end = out + len;
	for (p = out; p < end; p = nl + 1) {
		if ((nl = memchr(p, '\n', (size_t)(end - p))) == NULL)
			nl = end;
		if ((size_t)(nl - p) > nlen && strncmp(p, name, nlen) == 0 &&
		    p[nlen] == ' ') {
			memcpy(buf + n, p, (size_t)(nl - p));
			n += (size_t)(nl - p);
			buf[n++] = '\n';
		}
		if (nl == end)
			break;
	}
	buf[n] = '\0';
	return (buf);
}

static int
write_text(const char *path, const char *text)
{
	FILE	*fp;

	(void)unlink(path);
	if ((fp = fopen(path, "w")) == NULL)
		return (-1);
	fputs(text, fp);
	if (text[0] != '\0' && text[strlen(text) - 1] != '\n')
		fputc('\n', fp);
	return (fclose(fp) == 0 ? 0 : -1);
}

/*
 * Ask the server for its host keys and hand them to the client with
 * their fingerprints, for a person to confirm: nothing is trusted here.
 */
static void
offer_host_keys(struct work *w, bool unpriv, const char *name,
    const char *host, const char *port, struct fetched *rsp)
{
	struct execres	 res;
	const char	*argv[MAX_ARGS], **fps, *p, *nl;
	char		*scan;
	size_t		 nf;
	int		 n;

	n = 0;
	argv[n++] = opts.keyscan_bin;
	argv[n++] = "-q";
	argv[n++] = "-T";
	argv[n++] = "10";
	if (port != NULL) {
		argv[n++] = "-p";
		argv[n++] = port;
	}
	argv[n++] = "-t";
	argv[n++] = "ed25519,ecdsa,rsa";
	argv[n++] = "--";
	argv[n++] = host;
	argv[n] = NULL;
	if (run_as(w, unpriv, argv, &res) != 0 || res.outlen == 0) {
		rsp->error = wfmt(w, "%s did not give its SSH host keys: is it "
		    "reachable from this host?", name);
		return;
	}
	rsp->host_keys = key_lines(w, res.out, res.outlen, name);
	if (!valid_host_keys(rsp->host_keys, name)) {
		rsp->host_keys = NULL;
		rsp->error = wfmt(w, "%s gave no host keys that can be kept",
		    name);
		return;
	}
	scan = wfmt(w, "%s/scan", opts.build_dir);
	if (write_text(scan, rsp->host_keys) == 0) {
		n = 0;
		argv[n++] = opts.keygen_bin;
		argv[n++] = "-l";
		argv[n++] = "-f";
		argv[n++] = scan;
		argv[n] = NULL;
		if (run_as(w, unpriv, argv, &res) == 0) {
			fps = wcalloc(w, 9, sizeof(*fps));
			nf = 0;
			for (p = res.out; p < res.out + res.outlen && nf < 8;
			    p = nl + 1) {
				if ((nl = memchr(p, '\n', (size_t)(res.out +
				    res.outlen - p))) == NULL)
					nl = res.out + res.outlen;
				if (nl > p)
					fps[nf++] = wtext(w, wstrndup(w, p,
					    (size_t)(nl - p)));
				if (nl == res.out + res.outlen)
					break;
			}
			rsp->fingerprints.v = fps;
			rsp->fingerprints.n = nf;
		}
		(void)unlink(scan);
	}
}

/*
 * What git said, all of it that says something: its last line alone is
 * "and the repository exists.", the end of its advice, and the reason
 * is in the lines before.
 */
static const char *
git_error(struct work *w, const struct execres *res)
{
	const char	*p, *nl, *end;
	char		*out;
	size_t		 n;

	out = wmalloc(w, res->errlen + 64);
	n = (size_t)sprintf(out, "git clone failed (status %d)", res->status);
	end = res->err + res->errlen;
	for (p = res->err; p < end; p = nl + 1) {
		if ((nl = memchr(p, '\n', (size_t)(end - p))) == NULL)
			nl = end;
		/* Not the progress line, and not the advice. */
		if (nl > p && strncmp(p, "Cloning into", 12) != 0 &&
		    strncmp(p, "Please make sure", 16) != 0 &&
		    strncmp(p, "and the repository exists", 25) != 0) {
			n += (size_t)sprintf(out + n, "%s%.*s", n > 0 ? ": " :
			    "", (int)(nl - p), p);
		}
		if (nl == end)
			break;
	}
	out[n] = '\0';
	return (wtext(w, out));
}

/*
 * A fresh clone of the repository in the build directory, with this
 * host's config.mk in it.  False with f->error when there is none; over
 * SSH that may be for want of a person: f then has the server's host
 * keys to confirm, or this host's key to allow there.
 */
static bool
tree_fetch(struct work *w, const char *source, const char *ref,
    const char *accepted, const char *sshkey, bool unpriv, char **srcp,
    struct fetched *rsp)
{
	struct execres	 res;
	struct passwd	*pw;
	const char	*argv[MAX_ARGS], *name, *host, *port, *sshcmd;
	char		*src, *conf, *kh, *key, *pub;
	char		 line[1024];
	FILE		*fp;
	bool		 ssh;
	int		 n, s;

	memset(rsp, 0, sizeof(*rsp));
	if (!valid_source(source)) {
		rsp->error = "not a repository git clone can take";
		return (false);
	}
	if (ref != NULL && !valid_ref(ref)) {
		rsp->error = "not a branch or tag name";
		return (false);
	}
	src = wfmt(w, "%s/src", opts.build_dir);

	/* The build directory, the build user's when there is one. */
	s = step_begin(w, ARC_STEP_KIND_FILE, "mkdir", "%s", opts.build_dir);
	if (mkdir(opts.build_dir, 0755) == -1 && errno != EEXIST) {
		step_end(w, s, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "%s: %s", opts.build_dir, strerror(errno));
		return (false);
	}
	if (unpriv && ((pw = getpwnam(BUILD_USER)) == NULL ||
	    chown(opts.build_dir, pw->pw_uid, pw->pw_gid) == -1)) {
		step_end(w, s, false, "no user %s to build as", BUILD_USER);
		rsp->error = "no user to build as";
		return (false);
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
		return (false);
	}
	/*
	 * Over SSH, git runs ssh as the build user, who has no known
	 * hosts and no key.  Both are kept in the build directory: the
	 * host keys a person confirmed, never one taken on trust, and a
	 * key of this host's own for the server to allow.
	 */
	sshcmd = NULL;
	ssh = ssh_source(w, source, &name, &host, &port);
	if (ssh) {
		kh = wfmt(w, "%s/known_hosts", opts.build_dir);
		key = wfmt(w, "%s/id_ed25519", opts.build_dir);
		if (sshkey != NULL && sshkey[0] != '\0') {
			/* A key the administrator keeps on this host. */
			if (sshkey[0] != '/' || !valid_source(sshkey)) {
				rsp->error = "the SSH key is not an absolute "
				    "path";
				return (false);
			}
			argv[0] = "/bin/test";
			argv[1] = "-r";
			argv[2] = sshkey;
			argv[3] = NULL;
			if (run_as(w, unpriv, argv, &res) != 0) {
				rsp->error = wfmt(w, "the SSH key %s is not "
				    "there, or not readable by %s, whom git "
				    "runs as", sshkey, unpriv ? BUILD_USER :
				    "the agent");
				return (false);
			}
			key = wstrdup(w, sshkey);
		}
		pub = wfmt(w, "%s.pub", key);
		if (access(key, F_OK) == -1) {
			n = 0;
			argv[n++] = opts.keygen_bin;
			argv[n++] = "-q";
			argv[n++] = "-t";
			argv[n++] = "ed25519";
			argv[n++] = "-N";
			argv[n++] = "";
			argv[n++] = "-C";
			argv[n++] = "arcana-build";
			argv[n++] = "-f";
			argv[n++] = key;
			argv[n] = NULL;
			if (run_as(w, unpriv, argv, &res) != 0) {
				rsp->error = wtext(w, exec_error(w, &res,
				    "ssh-keygen"));
				return (false);
			}
		}
		if ((fp = fopen(pub, "r")) != NULL) {
			if (fgets(line, sizeof(line), fp) != NULL) {
				line[strcspn(line, "\n")] = '\0';
				rsp->deploy_key = wtext(w, wstrdup(w, line));
			}
			fclose(fp);
		}
		if (accepted != NULL && accepted[0] != '\0') {
			s = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", kh);
			if (!valid_host_keys(accepted, name) || write_text(kh,
			    accepted) == -1) {
				step_end(w, s, false, "not host keys of %s",
				    name);
				rsp->error = wfmt(w, "those are not host keys "
				    "of %s that can be kept", name);
				return (false);
			}
			step_end(w, s, true, "the host keys of %s, as "
			    "confirmed", name);
		}
		/* Known already?  ssh-keygen -F finds the server's lines. */
		n = 0;
		argv[n++] = opts.keygen_bin;
		argv[n++] = "-F";
		argv[n++] = name;
		argv[n++] = "-f";
		argv[n++] = kh;
		argv[n] = NULL;
		if (access(kh, R_OK) == -1 || run_as(w, unpriv, argv,
		    &res) != 0 || res.outlen == 0) {
			offer_host_keys(w, unpriv, name, host, port, rsp);
			if (rsp->host_keys != NULL)
				rsp->error = wfmt(w, "this host does not know "
				    "the SSH host key of %s: confirm it", name);
			return (false);
		}
		sshcmd = wfmt(w, "core.sshCommand=ssh -i %s -o IdentitiesOnly="
		    "yes -o UserKnownHostsFile=%s -o GlobalKnownHostsFile="
		    "/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes",
		    key, kh);
	}
	n = 0;
	argv[n++] = opts.git_bin;
	if (sshcmd != NULL) {
		argv[n++] = "-c";
		argv[n++] = sshcmd;
	}
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
		rsp->error = git_error(w, &res);
		if (!ssh || res.err == NULL)
			return (false);
		/*
		 * The server showing another key than the one confirmed is
		 * not something to pass over: say so, and offer the new
		 * keys for a person to judge.
		 */
		if (memmem(res.err, res.errlen, "verification failed",
		    19) != NULL || memmem(res.err, res.errlen,
		    "IDENTIFICATION HAS CHANGED", 26) != NULL) {
			offer_host_keys(w, unpriv, name, host, port, rsp);
			rsp->error = wfmt(w, "THE SSH HOST KEY OF %s HAS "
			    "CHANGED since it was confirmed: someone may be "
			    "in between, or the server was reinstalled", name);
		} else if (memmem(res.err, res.errlen, "Permission denied (",
		    19) != NULL)
			rsp->error = wfmt(w, "%s refused the key %s of this "
			    "host; its public half has to be allowed there "
			    "for this repository. %s", name, key,
			    git_error(w, &res));
		return (false);
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
			return (false);
		}
	}

	*srcp = src;
	return (true);
}

static int
agent_build(struct work *w, const char *source, const char *ref,
    const char *accepted, const char *sshkey,
    struct arc_agent_build_rsp *rsp)
{
	struct fetched	 f;
	struct execres	 res;
	struct stat	 sb;
	unsigned char	 md[EVP_MAX_MD_SIZE];
	const char	*argv[MAX_ARGS], *nl;
	char		*src, *objdir, *prog, *sha;
	uint8_t		*bin;
	ssize_t		 r;
	size_t		 off;
	unsigned int	 i, mdlen;
	bool		 unpriv;
	int		 fd, n, s;

	rsp->has_ok = true;
	rsp->ok = false;
	unpriv = geteuid() == 0;
	if (!tree_fetch(w, source, ref, accepted, sshkey, unpriv, &src, &f)) {
		rsp->error = f.error;
		rsp->host_keys = f.host_keys;
		rsp->deploy_key = f.deploy_key;
		rsp->fingerprints.v = f.fingerprints.v;
		rsp->fingerprints.n = f.fingerprints.n;
		return (0);
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

/*
 * The whole tree built and installed on this host from the repository,
 * for the console to update itself where it runs: make as the build
 * user, make install as the daemon.  The caller restarts the console's
 * service once the reply has left.
 */
static int
console_update(struct work *w, const char *source, const char *ref,
    const char *accepted, const char *sshkey,
    struct arc_console_update_rsp *rsp)
{
	struct fetched	 f;
	struct execres	 res;
	const char	*argv[MAX_ARGS];
	char		*src;
	bool		 unpriv;
	int		 n;

	rsp->has_ok = true;
	rsp->ok = false;
	unpriv = geteuid() == 0;
	if (!tree_fetch(w, source, ref, accepted, sshkey, unpriv, &src, &f)) {
		rsp->error = f.error;
		rsp->host_keys = f.host_keys;
		rsp->deploy_key = f.deploy_key;
		rsp->fingerprints.v = f.fingerprints.v;
		rsp->fingerprints.n = f.fingerprints.n;
		return (0);
	}
	n = 0;
	argv[n++] = opts.make_bin;
	argv[n++] = "-C";
	argv[n++] = src;
	argv[n++] = "MK_TESTS=no";
	argv[n] = NULL;
	if (run_as(w, unpriv, argv, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "make"));
		return (0);
	}
	argv[n++] = "install";
	argv[n] = NULL;
	if (run_as(w, false, argv, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "make install"));
		return (0);
	}
	rsp->ok = true;
	return (0);
}

/* The builds, with the build directory as the home of what they run. */
int
do_agent_build(struct work *w, const char *source, const char *ref,
    const char *accepted, const char *sshkey,
    struct arc_agent_build_rsp *rsp)
{
	int	rc;

	exec_set_home(w, opts.build_dir);
	rc = agent_build(w, source, ref, accepted, sshkey, rsp);
	exec_set_home(w, NULL);
	return (rc);
}

int
do_console_update(struct work *w, const char *source, const char *ref,
    const char *accepted, const char *sshkey,
    struct arc_console_update_rsp *rsp)
{
	int	rc;

	exec_set_home(w, opts.build_dir);
	rc = console_update(w, source, ref, accepted, sshkey, rsp);
	exec_set_home(w, NULL);
	return (rc);
}

