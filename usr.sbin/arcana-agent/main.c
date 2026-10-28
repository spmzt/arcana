/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * arcana-agent: serve the arcana cblink family for the jails of this host.
 */

#include <sys/param.h>
#include <sys/sysctl.h>

#include <err.h>
#include <errno.h>
#include <getopt.h>
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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "agent.h"
#include "collect.h"

#define	PATH_SOCKET	"unix:/var/run/arcana-agent.sock"
#define	PATH_PIDFILE	"/var/run/arcana-agent.pid"
#define	MAX_LISTEN	8
#define	MAX_FRAME	(8 * 1024 * 1024)
/* A list of many jails with their parameters is many attributes. */
#define	MAX_ATTRS	(1024 * 1024)
/* A logical network element's root holds the jail's network instances,
 * each with its routing mounted: deeper than the 16 of the default. */
#define	MAX_DEPTH	32
#define	STOP_GRACE	5	/* s, for the loop to stop */
#define	STOP_REMIND	30	/* s, between reports while waiting */

struct opts opts = {
	.jail_conf = PATH_JAIL_CONF,
	.jail_conf_d = PATH_JAIL_CONF_D,
	.jail_bin = PATH_JAIL_BIN,
	.rc_dirs = PATH_RC_DIRS,
	.service_bin = PATH_SERVICE_BIN,
	.sysrc_bin = PATH_SYSRC_BIN,
	.netstat_bin = PATH_NETSTAT_BIN,
	.swapinfo_bin = PATH_SWAPINFO_BIN,
	.zpool_bin = PATH_ZPOOL_BIN,
	.pkg_bin = PATH_PKG_BIN,
	.git_bin = PATH_GIT_BIN,
	.traceroute_bin = PATH_TRACEROUTE_BIN,
	.ifconfig_bin = PATH_IFCONFIG_BIN,
	.ngctl_bin = PATH_NGCTL_BIN,
	.jexec_bin = PATH_JEXEC_BIN,
	.kldload_bin = PATH_KLDLOAD_BIN,
	.kldunload_bin = PATH_KLDUNLOAD_BIN,
	.zfs_bin = PATH_ZFS_BIN,
	.gpart_bin = PATH_GPART_BIN,
	.camcontrol_bin = PATH_CAMCONTROL_BIN,
	.mount_bin = PATH_MOUNT_BIN,
	.umount_bin = PATH_UMOUNT_BIN,
	.fstab_path = PATH_FSTAB,
	.sysctl_bin = "/sbin/sysctl",
	.ipfw_bin = "/sbin/ipfw",
	.ipfw_rules = "/usr/local/etc/arcana/ipfw.rules",
	.sysctl_conf = "/etc/sysctl.conf",
	.smtpd_bin = "/usr/local/sbin/smtpd",
	.smtpctl_bin = "/usr/local/sbin/smtpctl",
	.smtpd_conf = "/usr/local/etc/mail/smtpd.conf",
	.smtpd_dir = "/usr/local/etc/mail/arcana",
	.speederv2_bin = "/usr/local/bin/speederv2",
	.speederv2_log = "/var/log/messages",
	.log_dir = "/var/log",
	.history_conf = "/usr/local/etc/arcana/history.conf",
	.jobs_conf = "/usr/local/etc/arcana/jobs.conf",
	.nacm_file = "/usr/local/etc/arcana/nacm.cbor",
	.subs_file = "/usr/local/etc/arcana/subscriptions.cbor",
	.wg_bin = PATH_WG_BIN,
	.wg_dir = PATH_WG_DIR,
	.swanctl_bin = PATH_SWANCTL_BIN,
	.squid_bin = PATH_SQUID_BIN,
	.cicap_bin = PATH_CICAP_BIN,
	.suricata_bin = PATH_SURICATA_BIN,
	.poudriere_bin = PATH_POUDRIERE_BIN,
	.ifmcstat_bin = PATH_IFMCSTAT_BIN,
	.freshclam_conf = PATH_FRESHCLAM_CONF,
	.suricata_rules = PATH_SURICATA_RULES,
	.exports_file = "/etc/exports",
	.ctl_conf = "/etc/ctl.conf",
	.hast_conf = "/etc/hast.conf",
	.poudriere_etc = PATH_POUDRIERE_ETC,
	.swanctl_dir = PATH_SWANCTL_DIR,
	.birdc_bin = PATH_BIRDC_BIN,
	.bird_watch_s = 15,
	.smtpd_watch_s = 60,
	.pkg_idle_s = PKG_IDLE_SEC,
	.pkg_lanes = PKG_LANES,
	.bird_bin = PATH_BIRD_BIN,
	.bird_conf = PATH_BIRD_CONF,
	.setfib_bin = PATH_SETFIB_BIN,
	.ntp_conf = PATH_NTP_CONF,
	.rtadvd_conf = PATH_RTADVD_CONF,
	.dnsmasq_bin = PATH_DNSMASQ_BIN,
	.unbound_bin = PATH_UNBOUND_BIN,
	.rtsol_bin = PATH_RTSOL_BIN,
	.setkey_bin = PATH_SETKEY_BIN,
	.safe_wait = 60,
	.telegram_api = "https://api.telegram.org",
	.make_bin = PATH_MAKE_BIN,
	.keyscan_bin = PATH_KEYSCAN_BIN,
	.keygen_bin = PATH_KEYGEN_BIN,
	.build_dir = PATH_BUILD_DIR,
	.build_conf = PATH_BUILD_CONF,
};

static bool	foreground;

enum { OPT_ROOT = 1000, OPT_BIRD_WATCH, OPT_SCTP_ALSO, OPT_TELEGRAM_API,
    OPT_POUDRIERE, OPT_POUDRIERE_ETC, OPT_IFMCSTAT, OPT_FRESHCLAM_CONF,
    OPT_SURICATA_RULES, OPT_EXPORTS, OPT_CTL_CONF, OPT_HAST_CONF,
    OPT_SMTPD_CONF, OPT_SMTPD_DIR, OPT_PKG_IDLE, OPT_JOBS_CONF,
    OPT_SPEEDER_LOG, OPT_SMTPD_WATCH, OPT_NACM, OPT_SUBSCRIPTIONS };
static const struct option longopts[] = {
	/* The system's files read and written under a directory: a test's
	 * tree (config-export, config-apply). */
	{ "root", required_argument, NULL, OPT_ROOT },
	/* A pkg that says nothing for this long is stopped. */
	{ "pkg-idle", required_argument, NULL, OPT_PKG_IDLE },
	{ "jobs-conf", required_argument, NULL, OPT_JOBS_CONF },
	/* NACM's rules (RFC 8341), as family 1 serves and edits them. */
	{ "nacm", required_argument, NULL, OPT_NACM },
	/* The configured subscriptions (RFC 8639 section 2.5), as family 1
	 * serves and edits them. */
	{ "subscriptions", required_argument, NULL, OPT_SUBSCRIPTIONS },
	/* How often BIRD's sessions are looked at for faults; 0, never. */
	{ "bird-watch", required_argument, NULL, OPT_BIRD_WATCH },
	{ "smtpd-watch", required_argument, NULL, OPT_SMTPD_WATCH },
	/* More addresses each SCTP listener is bound to (sctp_bindx(3)),
	 * separated by spaces: an association with the console over
	 * several paths. */
	{ "sctp-also", required_argument, NULL, OPT_SCTP_ALSO },
	/* Where the Telegram Bot API is, for notify: a test's own. */
	{ "telegram-api", required_argument, NULL, OPT_TELEGRAM_API },
	/* poudriere(8), and where its poudriere.conf and poudriere.d are:
	 * a test's own. */
	{ "poudriere", required_argument, NULL, OPT_POUDRIERE },
	{ "poudriere-etc", required_argument, NULL, OPT_POUDRIERE_ETC },
	{ "ifmcstat", required_argument, NULL, OPT_IFMCSTAT },
	{ "freshclam-conf", required_argument, NULL, OPT_FRESHCLAM_CONF },
	{ "suricata-rules", required_argument, NULL, OPT_SURICATA_RULES },
	/* The storage services' files: exports(5), ctl.conf(5), hast.conf(5). */
	{ "exports", required_argument, NULL, OPT_EXPORTS },
	{ "ctl-conf", required_argument, NULL, OPT_CTL_CONF },
	{ "hast-conf", required_argument, NULL, OPT_HAST_CONF },
	/* OpenSMTPD's smtpd.conf, and the directory of the agent's tables. */
	{ "smtpd-conf", required_argument, NULL, OPT_SMTPD_CONF },
	{ "smtpd-dir", required_argument, NULL, OPT_SMTPD_DIR },
	/* The log UDPspeeder's relay writes to, through syslogd. */
	{ "speederv2-log", required_argument, NULL, OPT_SPEEDER_LOG },
	{ NULL, 0, NULL, 0 },
};

static void	usage(void) __dead2;
static void	fatal(struct pidfh *, const char *, ...) __dead2
		    __printflike(2, 3);
static void	stop_now(void *);
static void	*stopper(void *) __no_lock_analysis;

static cbl_loop		*stop_loop;
static struct pidfh	*stop_pfh;

static void
usage(void)
{

	fprintf(stderr, "usage: arcana-agent [-dF] [-A cafile] [-C certfile] "
	    "[-K keyfile] [-D confdir]\n"
	    "                 [-f jail.conf] [-g group] [-j jail] "
	    "[-l uri] [-p pidfile]\n"
	    "                 [-R rc.d dirs] [-s service] [-y sysrc] "
	    "[-U program]\n"
	    "                 [-B build dir] [-c config.mk] [-G git] "
	    "[-M make]\n"
	    "                 [-Y ssh-keyscan] [-E ssh-keygen] "
	    "[-I ifconfig]\n"
	    "                 [-w seconds] [-Q sysctl] "
	    "[-O sysctl.conf]\n"
	    "                 [-v log-directory] [-1 history.conf] [-2 directory]\n"
	    "                 [-h ipfw] [-J ipfw.rules] [-r swanctl] "
	    "[-5 swanctl-directory]\n"
	    "                 [-N netstat] [-W swapinfo] "
	    "[-Z zpool] [-P pkg]\n"
	    "                 [-X traceroute] [--bird-watch seconds]\n"
	    "                 [--sctp-also addresses] [--telegram-api url]\n"
	    "                 [--poudriere poudriere] [--poudriere-etc directory]\n"
	    "                 [--ifmcstat ifmcstat]\n"
	    "                 [--freshclam-conf file]\n"
	    "                 [--suricata-rules directory]\n"
	    "                 [--exports file] [--ctl-conf file] [--hast-conf file]\n"
	    "                 [--smtpd-conf file] [--smtpd-dir directory]\n"
	    "                 [--smtpd-watch seconds]\n"
	    "                 [--speederv2-log file]\n"
	    "                 [--jobs-conf file] [--nacm file]\n"
	    "                 [--subscriptions file]\n");
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
		fprintf(stderr, "arcana-agent: ");
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
stop_now(void *arg __unused)
{

	(void)cbl_loop_stop(stop_loop);
}

/*
 * SIGTERM and SIGINT are blocked in every thread and taken here, so a
 * stop does not depend on what the loop or a request is busy with.
 *
 * A change under way is not cut short: the log says what it is and what
 * waits behind it, and the daemon stops when it ends, keeping the lock
 * so that nothing else starts.  A second signal stops it at once.  If
 * the loop does not wind down after that, the process exits anyway.
 */
static void *
stopper(void *arg __unused)
{
	struct timespec	one = { 1, 0 };
	sigset_t	set;
	int		sig, waited;
	bool		cut;

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	while (sigwait(&set, &sig) != 0)
		;
	logmsg(LOG_NOTICE, "signal %d, stopping", sig);
	history_save();
	changes_stop(true);
	jobs_wake();
	cut = false;
	for (waited = 0; pthread_mutex_trylock(&change_lock) != 0; waited++) {
		if (waited == 0)
			logmsg(LOG_NOTICE, "a change is under way: stopping "
			    "when it ends; signal again to stop at once");
		if (waited % STOP_REMIND == 0)
			changes_log(LOG_NOTICE);
		if (sigtimedwait(&set, NULL, &one) > 0) {
			logmsg(LOG_WARNING, "signalled again: stopping at "
			    "once, with this cut short");
			cut = true;
			break;
		}
	}
	changes_log(cut ? LOG_WARNING : LOG_NOTICE);
	if (cbl_loop_post(stop_loop, stop_now, NULL) != 0)
		(void)cbl_loop_stop(stop_loop);
	/* main() ends the process when the loop has stopped; cut short,
	 * what is under way is not waited for, the loop barely. */
	sleep(cut ? 1 : STOP_GRACE);
	logmsg(LOG_NOTICE, "the loop did not stop in %d s; exiting",
	    cut ? 1 : STOP_GRACE);
	if (stop_pfh != NULL)
		pidfile_remove(stop_pfh);
	_exit(cut ? 1 : 0);
}

/*
 * The TLS files are read when a listener starts, after the daemon has
 * detached, and OpenSSL then says only "system lib" for a file it could
 * not open.  Read them here first, and say what is wrong with which.
 */
static void
check_pem(const char *flag, const char *path, bool cert, EVP_PKEY **pkp)
{
	FILE		*fp;
	X509		*x;
	EVP_PKEY	*pk;

	if ((fp = fopen(path, "r")) == NULL)
		err(1, "%s %s", flag, path);
	if (cert) {
		x = PEM_read_X509(fp, NULL, NULL, NULL);
		pk = x != NULL ? X509_get_pubkey(x) : NULL;
		X509_free(x);
	} else
		pk = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (pk == NULL)
		errx(1, "%s %s: not a PEM %s", flag, path, cert ?
		    "certificate" : "private key");
	ERR_clear_error();
	if (pkp != NULL)
		*pkp = pk;
	else
		EVP_PKEY_free(pk);
}

static void
check_tls_files(const char *cafile, const char *certfile, const char *keyfile)
{
	EVP_PKEY	*pub, *key;

	check_pem("-A", cafile, true, NULL);
	check_pem("-C", certfile, true, &pub);
	check_pem("-K", keyfile, false, &key);
	if (EVP_PKEY_eq(pub, key) != 1)
		errx(1, "-K %s is not the key of the certificate -C %s",
		    keyfile, certfile);
	EVP_PKEY_free(pub);
	EVP_PKEY_free(key);
}

/* The SHA-256 of the program at path into opts.build; none if unread. */
static void
build_id(const char *path)
{
	EVP_MD_CTX	*md;
	unsigned char	 buf[65536], sum[EVP_MAX_MD_SIZE];
	unsigned int	 i, n;
	size_t		 r;
	FILE		*fp;

	if ((fp = fopen(path, "r")) == NULL)
		return;
	if ((md = EVP_MD_CTX_new()) != NULL && EVP_DigestInit_ex(md,
	    EVP_sha256(), NULL) == 1) {
		while ((r = fread(buf, 1, sizeof(buf), fp)) > 0)
			EVP_DigestUpdate(md, buf, r);
		if (!ferror(fp) && EVP_DigestFinal_ex(md, sum, &n) == 1)
			for (i = 0; i < n; i++)
				snprintf(opts.build + 2 * i, 3, "%02x", sum[i]);
	}
	EVP_MD_CTX_free(md);
	fclose(fp);
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
	const char	*pidpath, *errstr;
	gid_t		 gid;
	pid_t		 other;
	pthread_t	 tid;
	sigset_t	 stopset;
	bool		 network;
	int		 ch, i, nl, error;

	cafile = certfile = keyfile = NULL;
	pidpath = PATH_PIDFILE;
	gid = (gid_t)-1;
	opts.sock_gid = (gid_t)-1;
	nl = 0;
	/* Run again by the daemon, to look at a jail from inside it: a
	 * word no one gives as an option (-Q is sysctl's). */
	if (argc >= 2 && strcmp(argv[1], "--scope-helper") == 0)
		return (scope_helper(argc - 2, argv + 2));
	/* The letters are all taken: what comes after has a name. */
	while ((ch = getopt_long(argc, argv, "A:a:B:b:C:c:D:dE:e:Ff:G:g:H:h:I:J:j:K:k:l:M:N:n:O:o:P:p:Q:R:r:s:i:m:q:S:T:t:u:U:Vv:w:W:X:0:1:2:3:4:5:6:7:8:9:x:Y:y:Z:z:", longopts, NULL)) != -1) {
		switch (ch) {
		case OPT_ROOT:
			opts.root = optarg;
			break;
		case OPT_SCTP_ALSO:
			opts.sctp_also = optarg;
			break;
		case OPT_TELEGRAM_API:
			opts.telegram_api = optarg;
			break;
		case OPT_POUDRIERE:
			opts.poudriere_bin = optarg;
			break;
		case OPT_POUDRIERE_ETC:
			opts.poudriere_etc = optarg;
			break;
		case OPT_IFMCSTAT:
			opts.ifmcstat_bin = optarg;
			break;
		case OPT_FRESHCLAM_CONF:
			opts.freshclam_conf = optarg;
			break;
		case OPT_SURICATA_RULES:
			opts.suricata_rules = optarg;
			break;
		case OPT_EXPORTS:
			opts.exports_file = optarg;
			break;
		case OPT_CTL_CONF:
			opts.ctl_conf = optarg;
			break;
		case OPT_HAST_CONF:
			opts.hast_conf = optarg;
			break;
		case OPT_SMTPD_CONF:
			opts.smtpd_conf = optarg;
			break;
		case OPT_SMTPD_DIR:
			opts.smtpd_dir = optarg;
			break;
		case OPT_SPEEDER_LOG:
			opts.speederv2_log = optarg;
			break;
		case OPT_JOBS_CONF:
			opts.jobs_conf = optarg;
			break;
		case OPT_NACM:
			opts.nacm_file = optarg;
			break;
		case OPT_SUBSCRIPTIONS:
			opts.subs_file = optarg;
			break;
		case OPT_PKG_IDLE:
			opts.pkg_idle_s = (int)strtonum(optarg, 1, 86400, &errstr);
			if (errstr != NULL)
				errx(1, "--pkg-idle %s: %s", optarg, errstr);
			break;
		case OPT_BIRD_WATCH:
			opts.bird_watch_s = (int)strtonum(optarg, 0, 3600, &errstr);
			if (errstr != NULL)
				errx(1, "--bird-watch %s: %s", optarg, errstr);
			break;
		case OPT_SMTPD_WATCH:
			opts.smtpd_watch_s = (int)strtonum(optarg, 0, 3600, &errstr);
			if (errstr != NULL)
				errx(1, "--smtpd-watch %s: %s", optarg, errstr);
			break;
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
			opts.sock_gid = gid;
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
		case 'h':
			opts.ipfw_bin = optarg;
			break;
		case 'J':
			opts.ipfw_rules = optarg;
			break;
		case 'O':
			opts.sysctl_conf = optarg;
			break;
		case 'p':
			pidpath = optarg;
			break;
		case 'Q':
			opts.sysctl_bin = optarg;
			break;
		case 'v':
			opts.log_dir = optarg;
			break;
		case '1':
			opts.history_conf = optarg;
			break;
		case '2':
			opts.tools_dir = optarg;
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
		case 'W':
			opts.swapinfo_bin = optarg;
			break;
		case 'Z':
			opts.zpool_bin = optarg;
			break;
		case 'P':
			opts.pkg_bin = optarg;
			break;
		case 'U':
			opts.self_path = optarg;
			break;
		case 'B':
			opts.build_dir = optarg;
			break;
		case 'c':
			opts.build_conf = optarg;
			break;
		case 'E':
			opts.keygen_bin = optarg;
			break;
		case 'I':
			opts.ifconfig_bin = optarg;
			break;
		case 'n':
			opts.ngctl_bin = optarg;
			break;
		case 'x':
			opts.jexec_bin = optarg;
			break;
		case 'T':
			opts.kldload_bin = optarg;
			break;
		case 't':
			opts.kldunload_bin = optarg;
			break;
		case 'z':
			opts.zfs_bin = optarg;
			break;
		case 'q':
			opts.gpart_bin = optarg;
			break;
		case 'i':
			opts.camcontrol_bin = optarg;
			break;
		case 'm':
			opts.mount_bin = optarg;
			break;
		case 'u':
			opts.umount_bin = optarg;
			break;
		case 'S':
			opts.fstab_path = optarg;
			break;
		case 'H':
			opts.helper_bin = optarg;
			break;
		case 'k':
			opts.wg_bin = optarg;
			break;
		case 'o':
			opts.wg_dir = optarg;
			break;
		case 'r':
			opts.swanctl_bin = optarg;
			break;
		case '5':
			opts.swanctl_dir = optarg;
			break;
		case '3':
			opts.setfib_bin = optarg;
			break;
		case '4':
			opts.ntp_conf = optarg;
			break;
		case '6':
			opts.rtadvd_conf = optarg;
			break;
		case '7':
			opts.dnsmasq_bin = optarg;
			break;
		case '0':
			opts.unbound_bin = optarg;
			break;
		case '8':
			opts.rtsol_bin = optarg;
			break;
		case '9':
			opts.setkey_bin = optarg;
			break;
		case 'b':
			opts.birdc_bin = optarg;
			break;
		case 'e':
			opts.bird_bin = optarg;
			break;
		case 'a':
			opts.bird_conf = optarg;
			break;
		case 'w':
			opts.safe_wait = (int)strtonum(optarg, 1, 3600, &errstr);
			if (errstr != NULL)
				errx(1, "-w %s: %s", optarg, errstr);
			break;
		case 'Y':
			opts.keyscan_bin = optarg;
			break;
		case 'G':
			opts.git_bin = optarg;
			break;
		case 'X':
			opts.traceroute_bin = optarg;
			break;
		case 'M':
			opts.make_bin = optarg;
			break;
		case 'V':
			printf("arcana-agent %s\n", ARCANA_AGENT_VERSION);
			return (0);
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();
	{
		static char	self[MAXPATHLEN];
		size_t		len = sizeof(self);
		int		mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME,
				    -1 };

		if (sysctl(mib, 4, self, &len, NULL, 0) == -1)
			err(1, "sysctl kern.proc.pathname");
		if (opts.self_path == NULL)
			opts.self_path = self;
		/* The program that is running, not one put in its place. */
		if (opts.helper_bin == NULL) {
			opts.helper_bin = self;
			opts.helper_self = true;
		}
		/* Which build this is, before an update changes the file. */
		build_id(self);
	}
	if (nl == 0)
		uris[nl++] = PATH_SOCKET;

	/* vis(3) and the text checks treat UTF-8 as printable. */
	if (setlocale(LC_CTYPE, "C.UTF-8") == NULL)
		errx(1, "no C.UTF-8 locale");
	signal(SIGPIPE, SIG_IGN);
	/* Before any thread: they all inherit the mask. */
	sigemptyset(&stopset);
	sigaddset(&stopset, SIGTERM);
	sigaddset(&stopset, SIGINT);
	if ((error = pthread_sigmask(SIG_BLOCK, &stopset, NULL)) != 0)
		errc(1, error, "pthread_sigmask");

	network = false;
	for (i = 0; i < nl; i++)
		if (strncmp(uris[i], "unix:", 5) != 0)
			network = true;
	tls = NULL;
	if (network && (cafile == NULL || certfile == NULL || keyfile == NULL))
		errx(1, "network listeners need -A, -C and -K");
	/* Given without a network listener, they are the agent's own as a
	 * client: a configured subscription's receiver is reached by them. */
	if (cafile != NULL || certfile != NULL || keyfile != NULL) {
		if (cafile == NULL || certfile == NULL || keyfile == NULL)
			errx(1, "-A, -C and -K go together");
		check_tls_files(cafile, certfile, keyfile);
		if (cbl_tls_new(&tls) != 0 ||
		    cbl_tls_set_cert(tls, certfile, keyfile) != 0 ||
		    cbl_tls_set_ca(tls, cafile, NULL) != 0)
			errx(1, "TLS: %s", tls != NULL ? cbl_tls_errstr(tls) :
			    "cbl_tls_new failed");
		tls_files_init(tls, cafile, certfile, keyfile);
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
		openlog("arcana-agent", LOG_PID, LOG_DAEMON);
		pidfile_write(pfh);
	}

	if ((error = cbl_ctx_new(&ctx)) != 0)
		fatal(pfh, "cbl_ctx_new: %s", strerror(error));
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_FRAME, MAX_FRAME);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_ATTRS, MAX_ATTRS);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_DEPTH, MAX_DEPTH);
	if ((error = transport_watch(ctx)) != 0)
		fatal(pfh, "cbl_ctx_set_conn_cbs: %s", strerror(error));
	if ((error = admit_register(ctx, &fam)) != 0)
		fatal(pfh, "registering the %s family: %s", ARC_FAMILY_NAME,
		    strerror(error));
	event_family(fam);
	trace_family(fam);
	/* The standard models, by cblink's YANG family. */
	if ((error = yang_serve(ctx)) != 0)
		fatal(pfh, "serving the models: %s", strerror(error));
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
		transport_add(uris[i], ls[i]);
	}
	/* And on SCTP where it listens on TCP, if the kernel has it. */
	transport_init(ctx, loop, tls);
	jobs_conf_load();
	jobs_init();
	history_start();
	probe_start();
	faults_start();
	record_start();
	sdwan_start();
	sdwan_bird_start();
	sdwan_dhcp_start();
	sdwan_dns_start();
	sdwan_proxy_start();
	sdwan_ids_start();
	kmsg_start();
	route_watch_start();
	jail_watch_start();
	host_watch_start();
	bird_watch_start();
	smtpd_watch_start();
	logmsg(LOG_INFO, "version %s ready", ARCANA_AGENT_VERSION);
	stop_loop = loop;
	stop_pfh = pfh;
	if ((error = pthread_create(&tid, NULL, stopper, NULL)) != 0)
		fatal(pfh, "pthread_create: %s", strerror(error));
	(void)pthread_detach(tid);

	error = cbl_loop_run(loop);
	/* Asked to stop, or the loop failed: said either way, as a
	 * detached agent that ends silently leaves nothing to go on. */
	if (error != 0)
		logmsg(LOG_ERR, "the loop failed: %s; exiting",
		    strerror(error));
	else
		logmsg(LOG_NOTICE, "stopped");

	/* The listeners are transport.c's now: some closed, some added
	 * while it ran. */
	transport_fini();
	event_family(NULL);
	(void)cbl_family_unregister(fam);
	cbl_loop_free(loop);
	cbl_tls_free(tls);
	(void)cbl_ctx_free(ctx);
	if (pfh != NULL)
		pidfile_remove(pfh);
	return (error == 0 ? 0 : 1);
}
