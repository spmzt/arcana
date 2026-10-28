/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: ietf-syslog (RFC 9742) served.  Running is what syslogd(8)
 * reads, syslog.conf and the files it includes, and newsyslog.conf
 * (ylog.c); a commit of the candidate writes Arcana's lines in files
 * of its own, SYSLOG_ARCANA and NEWSYSLOG_ARCANA (ylog.c's rules), and
 * leaves the user's files as they are but for what the user accepts:
 *
 *	syslog-include		syslog.conf or newsyslog.conf does not
 *				include Arcana's file: included, once, at
 *				its end
 *	syslog-conf-conflict	a line of the user's writes to an action
 *				the commit changes or takes away, or turns
 *				over a log whose rotation it changes:
 *				commented out where it is
 *
 * Unaccepted, the request is refused with that error-app-tag and says
 * what it would do.  syslogd has no check of its files of its own: what
 * was written is read back first, as running is, and must be what was
 * asked.  A log file new to syslogd is made (0600, as syslogd -C), for
 * syslogd writes to none that is not there.  syslogd, where it runs, is
 * told to read them again (service syslogd onereload, SIGHUP); failing,
 * every file is put back as it was and syslogd told again.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <cblink.h>

#include "agent.h"
#include "collect.h"

int
ietf_syslog_syslog_get(cbl_req *req, struct ietf_syslog *data, cbl_yarena *a)
{
	struct yunread	*u;
	char		 conf[MAXPATHLEN], ns[MAXPATHLEN];
	size_t		 nu, i;
	int		 error;

	(void)req;
	snprintf(conf, sizeof(conf), "%s%s", opts.root != NULL ? opts.root :
	    "", SYSLOG_CONF);
	snprintf(ns, sizeof(ns), "%s%s", opts.root != NULL ? opts.root : "",
	    NEWSYSLOG_CONF);
	if ((error = ysyslog_read(opts.root, conf, ns, a, data, &u, &nu)) !=
	    0)
		return (error);
	for (i = 0; i < nu; i++)
		logmsg(LOG_INFO, "syslog.conf: %s: %s", u[i].var, u[i].why);
	return (0);
}

/* A refusal with its app-tag, text its words, for req. */
static int
refuse(cbl_req *req, const char *tag, const char *text)
{

	(void)cbl_req_set_yapptag(req, tag);
	(void)cbl_req_set_yerr(req, text, 0);
	return (EEXIST);
}

/* text as the whole of path, its directory made where it is not. */
static int
put(const char *path, const char *text)
{
	char	 dir[MAXPATHLEN], *slash;
	FILE	*fp;
	int	 error = 0;

	(void)snprintf(dir, sizeof(dir), "%s", path);
	if ((slash = strrchr(dir, '/')) != NULL && slash != dir) {
		*slash = '\0';
		(void)mkdir(dir, 0755);
	}
	if ((fp = fopen(path, "we")) == NULL)
		return (errno);
	if (fputs(text, fp) == EOF)
		error = errno != 0 ? errno : EIO;
	(void)fchmod(fileno(fp), 0644);
	if (fclose(fp) == EOF && error == 0)
		error = errno;
	return (error);
}

/* line at the end of path, on a line of its own. */
static int
append(const char *path, const char *line)
{
	struct stat	 sb;
	FILE		*fp;
	int		 c = '\n', error = 0;

	if ((fp = fopen(path, "a+e")) == NULL)
		return (errno);
	if (fstat(fileno(fp), &sb) == 0 && sb.st_size > 0 &&
	    fseeko(fp, -1, SEEK_END) == 0)
		c = fgetc(fp);
	if ((c != '\n' && fputc('\n', fp) == EOF) || fputs(line, fp) == EOF)
		error = errno != 0 ? errno : EIO;
	if (fclose(fp) == EOF && error == 0)
		error = errno;
	return (error);
}

/* syslogd made to read its files again, where it runs (*running). */
static int
syslogd_again(struct work *w, bool *running, const char **errp)
{
	struct execres	 res;
	char		*argv[4];

	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)"syslogd";
	argv[2] = (char *)(uintptr_t)"onestatus";
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*running = false;
		return (0);
	}
	*running = true;
	argv[2] = (char *)(uintptr_t)"onereload";
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "service syslogd "
		    "onereload"));
		return (-1);
	}
	return (0);
}

int
ietf_syslog_syslog_edit(cbl_req *req, const struct ietf_syslog *before,
    const struct ietf_syslog *after)
{
	struct ysyslog_plan	 pl;
	struct work		 w;
	struct rca		 x;
	cbl_yarena		*a;
	const char		*root = opts.root != NULL ? opts.root : "";
	const char		*e = NULL;
	char			 err[1024], conf[MAXPATHLEN], rot[MAXPATHLEN];
	char			 sconf[MAXPATHLEN], nconf[MAXPATHLEN];
	size_t			 rl = strlen(root), off = 0;
	bool			 inc, rinc, running = false;
	int			 error;

	/* Running is read again: the files as they are now. */
	(void)before;
	err[0] = '\0';
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((error = ysyslog_plan(root, after, a, &pl, err, sizeof(err))) !=
	    0 || !pl.changed) {
		if (error != 0)
			(void)cbl_req_set_yerr(req, err, 0);
		cbl_yarena_free(a);
		return (error);
	}
	(void)snprintf(conf, sizeof(conf), "%s%s", root, SYSLOG_ARCANA);
	(void)snprintf(rot, sizeof(rot), "%s%s", root, NEWSYSLOG_ARCANA);
	(void)snprintf(sconf, sizeof(sconf), "%s%s", root, SYSLOG_CONF);
	(void)snprintf(nconf, sizeof(nconf), "%s%s", root, NEWSYSLOG_CONF);
	inc = pl.conf != NULL && !pl.included;
	rinc = pl.rot != NULL && !pl.rot_included;
	if ((inc || rinc) && !cbl_req_yaccepts(req, "syslog-include")) {
		(void)snprintf(err, sizeof(err), "Arcana keeps what it writes "
		    "of syslog.conf in %s and of newsyslog.conf in %s, read "
		    "where they include them: accept syslog-include to have "
		    "%s%s%s include them, once", SYSLOG_ARCANA,
		    NEWSYSLOG_ARCANA, inc ? SYSLOG_CONF : "", inc && rinc ?
		    " and " : "", rinc ? NEWSYSLOG_CONF : "");
		cbl_yarena_free(a);
		return (refuse(req, "syslog-include", err));
	}
	if (pl.ntake > 0 && !cbl_req_yaccepts(req, "syslog-conf-conflict")) {
		char	text[1200];

		for (size_t i = 0; i < pl.ntake && off < sizeof(err); i++)
			off += (size_t)snprintf(err + off, sizeof(err) - off,
			    "%s%s:%d", i > 0 ? ", " : "", pl.take[i].path + rl,
			    pl.take[i].line);
		(void)snprintf(text, sizeof(text), "your lines write what "
		    "Arcana would change: %s; accept syslog-conf-conflict to "
		    "have it in Arcana's files alone, those commented out",
		    err);
		cbl_yarena_free(a);
		return (refuse(req, "syslog-conf-conflict", text));
	}
	/* Every file kept as it is first, for rca_undo(). */
	memset(&x, 0, sizeof(x));
	work_init(&w);
	error = 0;
	if (pl.conf != NULL)
		error = rca_keep(&x, conf);
	if (error == 0 && pl.rot != NULL)
		error = rca_keep(&x, rot);
	if (error == 0 && inc)
		error = rca_keep(&x, sconf);
	if (error == 0 && rinc)
		error = rca_keep(&x, nconf);
	for (size_t i = 0; error == 0 && i < pl.ntake; i++)
		error = rca_keep(&x, pl.take[i].path);
	for (size_t i = 0; error == 0 && i < pl.ncreate; i++)
		error = rca_keep(&x, pl.create[i]);
	if (error != 0) {
		rca_close(&x);
		work_free(&w);
		cbl_yarena_free(a);
		return (error);
	}
	if ((error = ysyslog_take(&pl)) != 0)
		(void)snprintf(err, sizeof(err), "taking your lines: %s",
		    strerror(error));
	else if (inc && (error = append(sconf, "include\t\t\t\t\t\t"
	    "/usr/local/etc/syslog.d\n")) != 0)
		(void)snprintf(err, sizeof(err), "%s: %s", SYSLOG_CONF,
		    strerror(error));
	else if (rinc && (error = append(nconf, "<include> "
	    "/usr/local/etc/newsyslog.conf.d/[!.]*.conf\n")) != 0)
		(void)snprintf(err, sizeof(err), "%s: %s", NEWSYSLOG_CONF,
		    strerror(error));
	else if ((pl.conf != NULL && (error = put(conf, pl.conf)) != 0) ||
	    (pl.rot != NULL && (error = put(rot, pl.rot)) != 0))
		(void)snprintf(err, sizeof(err), "Arcana's files: %s",
		    strerror(error));
	for (size_t i = 0; error == 0 && i < pl.ncreate; i++) {
		int fd;

		if ((fd = open(pl.create[i], O_WRONLY | O_CREAT | O_EXCL |
		    O_CLOEXEC, 0600)) == -1) {
			error = errno;
			(void)snprintf(err, sizeof(err), "%s: %s",
			    pl.create[i] + rl, strerror(error));
		} else
			close(fd);
	}
	if (error == 0)
		error = ysyslog_check(root, after, err, sizeof(err));
	if (error == 0 && syslogd_again(&w, &running, &e) != 0) {
		(void)snprintf(err, sizeof(err), "%s", e != NULL ? e :
		    "service syslogd onereload failed");
		error = EIO;
	}
	if (error != 0) {
		rca_undo(&x);
		if (running)
			(void)syslogd_again(&w, &running, &e);
		(void)cbl_req_set_yerr(req, err, 0);
		logmsg(LOG_WARNING, "syslog: %s: the files as they were", err);
	} else if (!running)
		(void)cbl_req_ywarn(req, ynode_named("ietf-syslog",
		    "syslog")->sid, "syslogd-stopped", "syslogd is not "
		    "running: it reads the files when it starts");
	rca_close(&x);
	work_free(&w);
	cbl_yarena_free(a);
	return (error);
}
