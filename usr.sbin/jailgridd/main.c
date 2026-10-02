/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * jailgridd: serve the jailgrid cblink family for the jails of this host.
 */

#include <sys/param.h>

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <libutil.h>
#include <locale.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "jailgridd.h"

#define	PATH_SOCKET	"unix:/var/run/jailgridd.sock"
#define	PATH_PIDFILE	"/var/run/jailgridd.pid"
#define	MAX_LISTEN	8
#define	MAX_FRAME	(8 * 1024 * 1024)
/* A list of many jails with their parameters is many attributes. */
#define	MAX_ATTRS	(1024 * 1024)

struct opts opts = {
	.jail_conf = PATH_JAIL_CONF,
	.jail_conf_d = PATH_JAIL_CONF_D,
	.jail_bin = PATH_JAIL_BIN,
	.rc_dirs = PATH_RC_DIRS,
	.service_bin = PATH_SERVICE_BIN,
	.sysrc_bin = PATH_SYSRC_BIN,
	.netstat_bin = PATH_NETSTAT_BIN,
	.sockstat_bin = PATH_SOCKSTAT_BIN,
	.swapinfo_bin = PATH_SWAPINFO_BIN,
	.zpool_bin = PATH_ZPOOL_BIN,
	.pkg_bin = PATH_PKG_BIN,
};

static bool	foreground;

static void	usage(void) __dead2;
static void	fatal(struct pidfh *, const char *, ...) __dead2
		    __printflike(2, 3);
static void	on_signal(int, void *);

static void
usage(void)
{

	fprintf(stderr, "usage: jailgridd [-dF] [-A cafile] [-C certfile] "
	    "[-K keyfile] [-D confdir]\n"
	    "                 [-f jail.conf] [-g group] [-j jail] "
	    "[-l uri] [-p pidfile]\n"
	    "                 [-R rc.d dirs] [-s service] [-y sysrc]\n"
	    "                 [-N netstat] [-X sockstat] [-W swapinfo] "
	    "[-Z zpool] [-P pkg]\n");
	exit(2);
}

/* syslog(3) when detached, standard error in the foreground. */
void
logmsg(int pri, const char *fmt, ...)
{
	va_list	ap;

	if (pri == LOG_DEBUG && !opts.debug)
		return;
	va_start(ap, fmt);
	if (foreground) {
		fprintf(stderr, "jailgridd: ");
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
	} else
		vsyslog(pri, fmt, ap);
	va_end(ap);
}

static void
fatal(struct pidfh *pfh, const char *fmt, ...)
{
	va_list	 ap;
	char	*msg;

	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		msg = NULL;
	va_end(ap);
	logmsg(LOG_ERR, "%s", msg != NULL ? msg : fmt);
	if (pfh != NULL)
		pidfile_remove(pfh);
	exit(1);
}

static void
on_signal(int sig, void *arg)
{

	logmsg(LOG_INFO, "signal %d, stopping", sig);
	(void)cbl_loop_stop(arg);
}

int
main(int argc, char *argv[])
{
	struct pidfh	*pfh;
	struct group	*gr;
	cbl_listener	*ls[MAX_LISTEN];
	cbl_family	*fam;
	cbl_loop	*loop;
	cbl_ctx		*ctx;
	cbl_tls		*tls;
	const char	*uris[MAX_LISTEN], *cafile, *certfile, *keyfile;
	const char	*pidpath;
	gid_t		 gid;
	pid_t		 other;
	bool		 network;
	int		 ch, i, nl, error;

	cafile = certfile = keyfile = NULL;
	pidpath = PATH_PIDFILE;
	gid = (gid_t)-1;
	nl = 0;
	while ((ch = getopt(argc, argv, "A:C:D:dFf:g:j:K:l:N:P:p:R:s:W:X:y:Z:")) != -1) {
		switch (ch) {
		case 'A':
			cafile = optarg;
			break;
		case 'C':
			certfile = optarg;
			break;
		case 'D':
			opts.jail_conf_d = optarg;
			break;
		case 'd':
			opts.debug = true;
			break;
		case 'F':
			foreground = true;
			break;
		case 'f':
			opts.jail_conf = optarg;
			break;
		case 'g':
			if ((gr = getgrnam(optarg)) == NULL)
				errx(1, "unknown group %s", optarg);
			gid = gr->gr_gid;
			break;
		case 'j':
			opts.jail_bin = optarg;
			break;
		case 'K':
			keyfile = optarg;
			break;
		case 'l':
			if (nl == MAX_LISTEN)
				errx(1, "at most %d listeners", MAX_LISTEN);
			uris[nl++] = optarg;
			break;
		case 'p':
			pidpath = optarg;
			break;
		case 'R':
			opts.rc_dirs = optarg;
			break;
		case 's':
			opts.service_bin = optarg;
			break;
		case 'y':
			opts.sysrc_bin = optarg;
			break;
		case 'N':
			opts.netstat_bin = optarg;
			break;
		case 'X':
			opts.sockstat_bin = optarg;
			break;
		case 'W':
			opts.swapinfo_bin = optarg;
			break;
		case 'Z':
			opts.zpool_bin = optarg;
			break;
		case 'P':
			opts.pkg_bin = optarg;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();
	if (nl == 0)
		uris[nl++] = PATH_SOCKET;

	/* vis(3) and the text checks treat UTF-8 as printable. */
	if (setlocale(LC_CTYPE, "C.UTF-8") == NULL)
		errx(1, "no C.UTF-8 locale");
	signal(SIGPIPE, SIG_IGN);

	network = false;
	for (i = 0; i < nl; i++)
		if (strncmp(uris[i], "unix:", 5) != 0)
			network = true;
	tls = NULL;
	if (network) {
		if (cafile == NULL || certfile == NULL || keyfile == NULL)
			errx(1, "network listeners need -A, -C and -K");
		if (cbl_tls_new(&tls) != 0 ||
		    cbl_tls_set_cert(tls, certfile, keyfile) != 0 ||
		    cbl_tls_set_ca(tls, cafile, NULL) != 0)
			errx(1, "TLS: %s", tls != NULL ? cbl_tls_errstr(tls) :
			    "cbl_tls_new failed");
	}

	/*
	 * Detach first: the loop is a kqueue, which a fork does not pass
	 * on.  Problems after this point go to syslog.
	 */
	pfh = NULL;
	if (!foreground) {
		if ((pfh = pidfile_open(pidpath, 0600, &other)) == NULL) {
			if (errno == EEXIST)
				errx(1, "already running, pid %d", (int)other);
			err(1, "pidfile %s", pidpath);
		}
		if (daemon(0, 0) == -1) {
			pidfile_remove(pfh);
			err(1, "daemon");
		}
		openlog("jailgridd", LOG_PID, LOG_DAEMON);
		pidfile_write(pfh);
	}

	if ((error = cbl_ctx_new(&ctx)) != 0)
		fatal(pfh, "cbl_ctx_new: %s", strerror(error));
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_FRAME, MAX_FRAME);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_ATTRS, MAX_ATTRS);
	if ((error = jg_register(ctx, NULL, &fam)) != 0)
		fatal(pfh, "registering the %s family: %s", JG_FAMILY_NAME,
		    strerror(error));
	if ((error = cbl_loop_new(ctx, &loop)) != 0)
		fatal(pfh, "cbl_loop_new: %s", strerror(error));
	for (i = 0; i < nl; i++) {
		bool	local;

		local = strncmp(uris[i], "unix:", 5) == 0;
		/* A local socket is guarded by its mode: 0600, or 0660 to
		 * let a group in. */
		if ((error = cbl_listener_new(ctx, uris[i], local ?
		    CBL_LF_UNIX_TRUSTED : 0, &ls[i])) != 0)
			fatal(pfh, "%s: %s", uris[i], strerror(error));
		if (local)
			error = cbl_listener_set_unix_perm(ls[i],
			    gid != (gid_t)-1 ? 0660 : 0600, (uid_t)-1, gid);
		else
			error = cbl_listener_set_tls(ls[i], tls);
		if (error != 0 ||
		    (error = cbl_listener_start(ls[i], loop)) != 0)
			fatal(pfh, "%s: %s", uris[i],
			    cbl_listener_errstr(ls[i]));
		logmsg(LOG_INFO, "listening on %s", uris[i]);
	}
	logmsg(LOG_INFO, "version %s ready", JAILGRIDD_VERSION);
	(void)cbl_loop_signal(loop, SIGINT, on_signal, loop);
	(void)cbl_loop_signal(loop, SIGTERM, on_signal, loop);

	error = cbl_loop_run(loop);

	for (i = 0; i < nl; i++)
		cbl_listener_free(ls[i]);
	(void)cbl_family_unregister(fam);
	cbl_loop_free(loop);
	cbl_tls_free(tls);
	(void)cbl_ctx_free(ctx);
	if (pfh != NULL)
		pidfile_remove(pfh);
	return (error == 0 ? 0 : 1);
}
