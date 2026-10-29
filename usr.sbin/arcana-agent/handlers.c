/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cblink handlers for the arcana family.  Requests are checked here,
 * then run on a thread of their own so a jail(8) that takes minutes does
 * not hold up the event loop; changes run one at a time.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>

#include "agent.h"
#include "zprog.h"

struct job {
	cbl_req			*req;
	uint16_t		 cmd;
	char			*jail;
	uint8_t			 action;
	struct arc_address_req	 addr;
	uint8_t			 family;
	uint32_t		 fib;
	uint32_t		 offset;		/* network: rows to leave out */
	uint64_t		 pos;		/* log: where to read on; history: since */
	bool			 has_pos;
	struct pkg_upgrade	 pkg;	/* its names: what many take */
	bool			 refresh;
	bool			 from_rc;	/* ipfw-rules: rc.conf's file */
	uint8_t			*binary;	/* agent-update */
	size_t			 binlen;
	size_t			 progsize;	/* inflated; 0 not compressed */
	char			*sha256;
	uint8_t			*sig;		/* by the console's CA key */
	size_t			 siglen;
	bool			 local;		/* asked by the local socket */
	bool			 restart;
	char			*source;	/* agent-build */
	char			*ref;
	bool			 compress;
	char			*host_keys;
	char			*ssh_key;
	char			*peer;
	char			*psrc, *pdst, *pproto, *piface;	/* path-check */
	uint32_t		 pport;
	bool			 has_fib;
	bool			 preply;
	char			*token;		/* notify: zeroed when used */
};

#define	STOPPING	"not done: arcana-agent is stopping"
#define	RESTART_WAIT	10	/* s, for service(8) to stop the daemon */
#define	JOBS_WAITING_MAX 256	/* jobs queued or running, at most */

pthread_mutex_t	change_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t build_lock = PTHREAD_MUTEX_INITIALIZER;

/* What holds change_lock now, for the log when asked to stop. */
static pthread_mutex_t	note_lock = PTHREAD_MUTEX_INITIALIZER;
static char		note[256];
static time_t		note_since;
static bool		stopping;

static const char *net_kind_names[] = {
	[ARC_NET_KIND_ROUTES] = "routes",
	[ARC_NET_KIND_NEXTHOPS] = "nexthops",
	[ARC_NET_KIND_CONNECTIONS] = "connections",
	[ARC_NET_KIND_SOCKETS] = "sockets",
	[ARC_NET_KIND_INTERFACES] = "interfaces",
	[ARC_NET_KIND_NETGRAPH] = "netgraph",
	[ARC_NET_KIND_WIREGUARD] = "wireguard",
	[ARC_NET_KIND_BIRD] = "bird",
	[ARC_NET_KIND_BIRD_ROUTES] = "bird-routes",
	[ARC_NET_KIND_BRIDGES] = "bridges",
	[ARC_NET_KIND_GENEVE] = "geneve",
	[ARC_NET_KIND_IPFW] = "ipfw",
	[ARC_NET_KIND_NHGROUPS] = "nhgroups",
	[ARC_NET_KIND_NEIGHBOURS] = "neighbours",
	[ARC_NET_KIND_IPSEC] = "ipsec",
	[ARC_NET_KIND_MULTICAST] = "multicast",
	[ARC_NET_KIND_BIRD_OSPF] = "bird-ospf",
	[ARC_NET_KIND_KEPT_ROUTES] = "kept-routes",
};

static char	*peer_name(cbl_req *);
static void	*worker(void *);
static int	start(struct job *);
static int	reject(cbl_req *, const char *);
static char	*xstrdup(const char *);
static void	job_free(struct job *);
static const char *check_spec(const struct arc_job_spec *);
static const char *cuts_off(cbl_req *, const struct arc_job_spec *);

/*
 * Jail names: letters, digits, '_', '-', and '.' for hierarchical jails.
 * All-digit names are refused because jail(8) reads them as jids.
 */
bool
valid_jail(const char *s)
{
	const char	*p;
	bool		 digits;

	if (*s == '\0' || *s == '.' || *s == '-' || strstr(s, "..") != NULL)
		return (false);
	digits = true;
	for (p = s; *p != '\0'; p++) {
		if (!isalnum((unsigned char)*p) && strchr("_.-", *p) == NULL)
			return (false);
		if (!isdigit((unsigned char)*p))
			digits = false;
	}
	return (!digits);
}

bool
valid_ifname(const char *s)
{

	if (!isalpha((unsigned char)*s))
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && *s != '_' && *s != '.')
			return (false);
	return (true);
}

/* rc.d script names: letters, digits, '_', '-', '.'; not hidden. */
bool
valid_service(const char *s)
{

	if (*s == '\0' || *s == '.' || *s == '-' || strlen(s) > 64)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.-", *s) == NULL)
			return (false);
	return (true);
}

static char *
xstrdup(const char *s)
{
	char	*p;

	if (s == NULL)
		return (NULL);
	if ((p = strdup(s)) == NULL)
		err(1, "strdup");
	return (p);
}

/* Who asked: the certificate subject, or the local uid. */
static char *
peer_name(cbl_req *req)
{
	const cbl_peer	*peer;
	const char	*subj;
	uid_t		 uid;
	gid_t		 gid;
	char		*s;

	peer = cbl_req_peer(req);
	if (peer != NULL && (subj = cbl_peer_subject(peer)) != NULL)
		return (xstrdup(subj));
	if (peer != NULL && cbl_peer_cred(peer, &uid, &gid) == 0) {
		if (asprintf(&s, "uid %u", (unsigned)uid) == -1)
			err(1, "asprintf");
		return (s);
	}
	return (xstrdup("unknown peer"));
}

/* Refuse a request whose attributes are well-formed but not acceptable. */
static int
reject(cbl_req *req, const char *msg)
{

	(void)cbl_req_set_err(req, msg, NULL, 0, -1);
	return (EINVAL);
}

/*
 * Say what the holder of change_lock is about to do; NULL when it is
 * done.  False when the daemon is stopping: the change must not start.
 */
bool
change_note(const char *fmt, ...)
{
	va_list	ap;
	bool	go;

	pthread_mutex_lock(&note_lock);
	go = fmt != NULL && !stopping;
	if (!go)
		note[0] = '\0';
	else {
		va_start(ap, fmt);
		vsnprintf(note, sizeof(note), fmt, ap);
		va_end(ap);
		note_since = time(NULL);
	}
	pthread_mutex_unlock(&note_lock);
	yang_changed(YANG_JOBS);
	return (go);
}

/* The daemon is about to stop: no change starts while that holds. */
void
changes_stop(bool on)
{

	pthread_mutex_lock(&note_lock);
	stopping = on;
	pthread_mutex_unlock(&note_lock);
	yang_changed(YANG_JOBS);
}

bool
changes_stopping(void)
{
	bool	on;

	pthread_mutex_lock(&note_lock);
	on = stopping;
	pthread_mutex_unlock(&note_lock);
	return (on);
}

/*
 * What holds the change lock now and since when, for those who ask for
 * the jobs; NULL when nothing does.  A job says so itself in the list.
 */
const char *
changes_current(struct work *w, time_t *sincep)
{
	const char	*s;

	pthread_mutex_lock(&note_lock);
	s = note[0] != '\0' && strncmp(note, "job ", 4) != 0 ? wstrdup(w,
	    note) : NULL;
	*sincep = note_since;
	pthread_mutex_unlock(&note_lock);
	return (s);
}

/*
 * What holds the change lock, a job too, and for how long: for a request
 * that does not wait for it.
 */
const char *
change_busy(struct work *w)
{
	const char	*s;
	time_t		 since;

	pthread_mutex_lock(&note_lock);
	since = note_since;
	s = wfmt(w, "a change is under way on the host (%s, for %jd s): try "
	    "again when it ends", note[0] != '\0' ? note : "a job",
	    (intmax_t)(time(NULL) - since));
	pthread_mutex_unlock(&note_lock);
	return (s);
}

/* The change under way and the jobs that wait, to the log. */
void
changes_log(int pri)
{
	char	now[sizeof(note)];

	pthread_mutex_lock(&note_lock);
	strlcpy(now, note, sizeof(now));
	pthread_mutex_unlock(&note_lock);
	if (now[0] != '\0')
		logmsg(pri, "under way: %s", now);
	jobs_log(pri);
}

static void *
worker(void *arg)
{
	struct job		*j;
	struct work		 w;
	struct arc_address_rsp	 dr;
	struct arc_network_rsp	 nr;
	struct arc_route_lookup_rsp rlr;
	struct arc_builder_rsp	 bur;
	struct arc_builder_options_rsp bor;
	struct arc_crashes_rsp	 crr;
	struct arc_suricata_rules_rsp surr;
	struct arc_netstore_rsp	 nsr;
	struct arc_smtpd_rsp	 smr;
	struct arc_speeder_rsp	 sper;
	struct arc_monitors_rsp	 monr;
	struct arc_system_rsp	 syr;
	struct arc_job_spec	 bsp;
	struct arc_ssh_rsp	 sshr;
	struct arc_notify_rsp	 ntr;
	struct arc_ipfw_rules_req irq;
	struct arc_ipfw_rules_rsp irr;
	struct arc_agent_update_rsp aur;
	struct arc_agent_build_rsp abr;
	struct arc_source_head_rsp shr;
	struct arc_console_update_rsp cur;
	const char		*what, *error;
	bool			 console;
	bool			 restart;
	bool			 ok;
	int			 root, rc;

	j = arg;
	work_init(&w);
	trace_tell(&w, j->req);
	restart = console = false;
	/* A read's programs run at READ_NICE; what changes the host at
	 * its own priority, as jobs do. */
	switch (j->cmd) {
	case ARC_CMD_NOTIFY:
	case ARC_CMD_CONSOLE_UPDATE:
	case ARC_CMD_AGENT_BUILD:
	case ARC_CMD_AGENT_UPDATE:
		break;
	default:
		w.nice = true;
		break;
	}
	switch (j->cmd) {
	case ARC_CMD_IPFW_RULES:
		/* The text rides in ref, its checksum in sha256. */
		what = wfmt(&w, "ipfw rules %s", j->from_rc ? "from rc.conf" :
		    j->ref == NULL ? "read" : j->refresh ? "check" : "write");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "%s", what);
		memset(&irq, 0, sizeof(irq));
		memset(&irr, 0, sizeof(irr));
		irq.conf_text = j->ref;
		irq.sha256 = j->sha256;
		irq.dry_run = j->refresh;
		irq.from_rc = j->from_rc;
		irr.has_ok = true;
		if (scope_enter(&w, j->jail, &irr.error) != 0)
			;
		else if (j->ref == NULL || j->refresh)
			do_ipfw_rules(&w, &irq, &irr);
		else {
			pthread_mutex_lock(&change_lock);
			if (change_note("%s", what))
				do_ipfw_rules(&w, &irq, &irr);
			else
				irr.error = STOPPING;
			change_note(NULL);
			pthread_mutex_unlock(&change_lock);
		}
		ok = irr.ok;
		error = irr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &irr.trace.v, &irr.trace.n);
		rc = arc_ipfw_rules_reply(j->req, &irr);
		break;
	case ARC_CMD_NOTIFY:
		what = "notify";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "notify chat %s", j->psrc);
		memset(&ntr, 0, sizeof(ntr));
		ntr.has_ok = true;
		error = NULL;
		ntr.ok = do_notify(&w, j->token, j->psrc, j->pdst, &error) ==
		    0;
		ntr.error = error;
		/* The token goes as soon as it is used. */
		explicit_bzero(j->token, strlen(j->token));
		ok = ntr.ok;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &ntr.trace.v, &ntr.trace.n);
		rc = arc_notify_reply(j->req, &ntr);
		break;
	case ARC_CMD_SSH:
		what = j->jail != NULL ? wfmt(&w, "sshd of %s", j->jail) : "sshd";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "%s", what);
		memset(&sshr, 0, sizeof(sshr));
		sshr.has_ok = true;
		if (scope_enter_jail(&w, j->jail, &sshr.error, false) == 0)
			do_ssh(&w, &sshr);
		ok = sshr.ok;
		error = sshr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sshr.trace.v, &sshr.trace.n);
		rc = arc_ssh_reply(j->req, &sshr);
		break;
	case ARC_CMD_BUILDER:
		what = "poudriere";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "poudriere");
		memset(&bur, 0, sizeof(bur));
		bur.has_ok = true;
		do_builder(&w, &bur);
		ok = bur.ok;
		error = bur.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &bur.trace.v, &bur.trace.n);
		rc = arc_builder_reply(j->req, &bur);
		break;
	case ARC_CMD_BUILDER_OPTIONS:
		what = "a port's options";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "a port's options for poudriere");
		memset(&bor, 0, sizeof(bor));
		memset(&bsp, 0, sizeof(bsp));
		bor.has_ok = true;
		/* Its words, kept where a pkg-upgrade's names are. */
		bsp.names.v = j->pkg.names.v;
		bsp.names.n = j->pkg.names.n;
		do_builder_options(&w, &bsp, &bor);
		ok = bor.ok;
		error = bor.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &bor.trace.v, &bor.trace.n);
		rc = arc_builder_options_reply(j->req, &bor);
		break;
	case ARC_CMD_CRASHES:
		what = "crashes";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "the cores dumped");
		memset(&crr, 0, sizeof(crr));
		crr.has_ok = true;
		do_crashes(&w, j->pkg.names.v, j->pkg.names.n, &crr);
		ok = crr.ok;
		error = crr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &crr.trace.v, &crr.trace.n);
		rc = arc_crashes_reply(j->req, &crr);
		break;
	case ARC_CMD_SYSTEM:
		what = "system";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "the system's files read");
		memset(&syr, 0, sizeof(syr));
		do_system(&w, j->pkg.names.v, j->pkg.names.n, &syr);
		ok = syr.ok;
		error = syr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &syr.trace.v, &syr.trace.n);
		rc = arc_system_reply(j->req, &syr);
		break;
	case ARC_CMD_SMTPD:
		what = "smtpd";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "OpenSMTPD read");
		memset(&smr, 0, sizeof(smr));
		if (scope_enter_jail(&w, j->jail, &smr.error, false) == 0)
			do_smtpd(&w, &smr);
		else
			smr.has_ok = true;
		ok = smr.ok;
		error = smr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &smr.trace.v, &smr.trace.n);
		rc = arc_smtpd_reply(j->req, &smr);
		break;
	case ARC_CMD_SPEEDER:
		what = "speeder";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "UDPspeeder's relay read");
		memset(&sper, 0, sizeof(sper));
		if (scope_enter_jail(&w, j->jail, &sper.error, false) == 0)
			do_speeder(&w, &sper);
		else
			sper.has_ok = true;
		ok = sper.ok;
		error = sper.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sper.trace.v, &sper.trace.n);
		rc = arc_speeder_reply(j->req, &sper);
		break;
	case ARC_CMD_NETSTORE:
		what = "netstore";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "the storage services read");
		memset(&nsr, 0, sizeof(nsr));
		do_netstore(&w, j->pkg.names.v, j->pkg.names.n, &nsr);
		ok = nsr.ok;
		error = nsr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &nsr.trace.v, &nsr.trace.n);
		rc = arc_netstore_reply(j->req, &nsr);
		break;
	case ARC_CMD_SURICATA_RULES:
		what = "suricata-rules";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "Suricata's rules read");
		memset(&surr, 0, sizeof(surr));
		do_suricata_rules(&w, j->pkg.names.v, j->pkg.names.n, &surr);
		ok = surr.ok;
		error = surr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &surr.trace.v, &surr.trace.n);
		rc = arc_suricata_rules_reply(j->req, &surr);
		break;
	case ARC_CMD_NETWORK:
		what = wfmt(&w, "network %s%s", net_kind_names[j->action],
		    j->family == ARC_NET_FAMILY_INET ? " inet" :
		    j->family == ARC_NET_FAMILY_INET6 ? " inet6" : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&nr, 0, sizeof(nr));
		nr.has_ok = true;
		if (scope_enter(&w, j->jail, &nr.error) == 0)
			do_network(&w, j->action, j->family, j->source, j->fib,
			    j->offset, &nr);
		ok = nr.ok;
		error = nr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &nr.trace.v, &nr.trace.n);
		rc = arc_network_reply(j->req, &nr);
		break;
	case ARC_CMD_ROUTE_LOOKUP:
		what = wfmt(&w, "route to %s", j->source);
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&rlr, 0, sizeof(rlr));
		rlr.has_ok = true;
		if (scope_enter(&w, j->jail, &rlr.error) == 0)
			do_route_lookup(&w, j->source, j->fib, &rlr);
		ok = rlr.ok;
		error = rlr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &rlr.trace.v, &rlr.trace.n);
		rc = arc_route_lookup_reply(j->req, &rlr);
		break;
	case ARC_CMD_MONITORS:
		what = "monitors";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&monr, 0, sizeof(monr));
		do_monitors(&w, j->pos, &monr);
		ok = monr.ok;
		error = monr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &monr.trace.v, &monr.trace.n);
		rc = arc_monitors_reply(j->req, &monr);
		break;
	case ARC_CMD_CONSOLE_UPDATE:
		what = wfmt(&w, "console update from %s%s%s", j->source,
		    j->ref != NULL ? " at " : "", j->ref != NULL ? j->ref : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&cur, 0, sizeof(cur));
		pthread_mutex_lock(&build_lock);
		do_console_update(&w, j->source, j->ref, j->host_keys,
		    j->ssh_key, &cur);
		pthread_mutex_unlock(&build_lock);
		ok = cur.ok;
		error = cur.error;
		/*
		 * The tree that was installed has this daemon in it too:
		 * both are restarted, or the console would talk to an agent
		 * of the version before.
		 */
		console = ok;
		restart = ok;
		cur.restarting = console;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &cur.trace.v, &cur.trace.n);
		rc = arc_console_update_reply(j->req, &cur);
		break;
	case ARC_CMD_AGENT_BUILD:
		what = wfmt(&w, "agent build from %s%s%s", j->source,
		    j->ref != NULL ? " at " : "", j->ref != NULL ? j->ref : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&abr, 0, sizeof(abr));
		/* One build at a time: they share the directory. */
		pthread_mutex_lock(&build_lock);
		do_agent_build(&w, j->source, j->ref, j->host_keys,
		    j->ssh_key, j->compress, &abr);
		pthread_mutex_unlock(&build_lock);
		ok = abr.ok;
		error = abr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &abr.trace.v, &abr.trace.n);
		rc = arc_agent_build_reply(j->req, &abr);
		break;
	case ARC_CMD_SOURCE_HEAD:
		what = wfmt(&w, "source head of %s%s%s", j->source,
		    j->ref != NULL ? " at " : "", j->ref != NULL ? j->ref : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&shr, 0, sizeof(shr));
		/* The build directory's keys are shared with the builds. */
		pthread_mutex_lock(&build_lock);
		do_source_head(&w, j->source, j->ref, j->host_keys, j->ssh_key,
		    &shr);
		pthread_mutex_unlock(&build_lock);
		ok = shr.ok;
		error = shr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &shr.trace.v, &shr.trace.n);
		rc = arc_source_head_reply(j->req, &shr);
		break;
	case ARC_CMD_AGENT_UPDATE:
		what = wfmt(&w, "agent update%s", j->restart ?
		    " and restart" : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&aur, 0, sizeof(aur));
		/*
		 * Not while a job changes the host: a restart would cut it
		 * short.  Nor after it, unasked: a safe change waits for its
		 * confirmation holding the lock, a package upgrade takes
		 * minutes, and the console would wait on, not told why.
		 */
		if (pthread_mutex_trylock(&change_lock) != 0) {
			aur.has_ok = true;
			aur.error = change_busy(&w);
		} else {
			if (change_note("%s", what))
				do_agent_update(&w, j->binary, j->binlen,
				    j->progsize, j->sha256, j->sig, j->siglen,
				    j->local, &aur);
			else {
				aur.has_ok = true;
				aur.error = STOPPING;
			}
			(void)change_note(NULL);
			pthread_mutex_unlock(&change_lock);
		}
		ok = aur.ok;
		error = aur.error;
		restart = ok && j->restart;
		aur.restarting = restart;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &aur.trace.v, &aur.trace.n);
		rc = arc_agent_update_reply(j->req, &aur);
		break;
	default:
		what = wfmt(&w, "address %s %s %s%s%s%s", j->addr.jail,
		    j->addr.remove ? "remove" : "add", j->addr.address,
		    j->addr.live ? " live" : "",
		    j->addr.persist ? " persist" : "",
		    j->addr.dry_run ? " dry-run" : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&dr, 0, sizeof(dr));
		pthread_mutex_lock(&change_lock);
		if (change_note("%s", what))
			do_address(&w, &j->addr, &dr);
		else {
			dr.has_ok = true;
			dr.error = STOPPING;
		}
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		ok = dr.ok;
		error = dr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &dr.trace.v, &dr.trace.n);
		rc = arc_address_reply(j->req, &dr);
		break;
	}
	if (rc != 0)
		logmsg(LOG_ERR, "%s: %s: reply failed: %s", j->peer, what,
		    strerror(rc));
	else
		logmsg(ok ? LOG_INFO : LOG_NOTICE, "%s: %s: %s", j->peer,
		    what, ok ? "ok" : error);
	(void)cbl_req_complete(j->req, rc);
	work_free(&w);
	job_free(j);
	restart_after(console, restart);
	return (NULL);
}

/* The console's own service, once it has its answer; then ours. */
void
restart_after(bool console, bool agent)
{

	if (console)
		service_restart("arcana_console");
	if (agent) {
		/*
		 * No change starts while the service is on its way to stop
		 * this daemon, and nothing is held that would keep it from
		 * stopping.  Still here after a while, the service did not
		 * stop it: say so, and take changes again.
		 */
		changes_stop(true);
		service_restart("arcana_agent");
		sleep(RESTART_WAIT);
		changes_stop(false);
		logmsg(LOG_ERR, "restart: still running %d s after an update: "
		    "\"service arcana_agent restart\" did not stop this "
		    "daemon; is the service enabled, and is it what runs it? "
		    "The new program is in place and runs from the next "
		    "start", RESTART_WAIT);
	}
}

static void
job_free(struct job *j)
{
	size_t	i;

	free((char *)(uintptr_t)j->pkg.pkg_repo);
	for (i = 0; i < j->pkg.names.n; i++)
		free((char *)(uintptr_t)j->pkg.names.v[i]);
	free((void *)(uintptr_t)j->pkg.names.v);
	free(j->jail);
	free(j->binary);
	free(j->sig);
	free(j->sha256);
	free(j->source);
	free(j->ref);
	free(j->host_keys);
	free(j->ssh_key);
	free((char *)(uintptr_t)j->addr.jail);
	free((char *)(uintptr_t)j->addr.address);
	free((char *)(uintptr_t)j->addr.interface);
	free(j->peer);
	if (j->token != NULL)
		explicit_bzero(j->token, strlen(j->token));
	free(j->token);
	free(j->psrc);
	free(j->pdst);
	free(j->pproto);
	free(j->piface);
	free(j);
}

/* Hand the request to a thread; it replies and completes it. */
static int
start(struct job *j)
{
	pthread_attr_t	attr;
	pthread_t	tid;
	int		error;

	j->peer = peer_name(j->req);
	if ((error = cbl_req_defer(j->req)) != 0) {
		job_free(j);
		return (error);
	}
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	error = pthread_create(&tid, &attr, worker, j);
	pthread_attr_destroy(&attr);
	if (error != 0) {
		logmsg(LOG_ERR, "pthread_create: %s", strerror(error));
		(void)cbl_req_complete(j->req, error);
		job_free(j);
	}
	return (0);
}

int
arc_hello_doit(cbl_req *req, void *arg __unused)
{
	struct arc_hello_rsp	rsp;
	struct arc_host		host;
	struct work		w;
	int			error;

	work_init(&w);
	host_info(&w, &host);
	memset(&rsp, 0, sizeof(rsp));
	rsp.host = &host;
	error = arc_hello_reply(req, &rsp);
	work_free(&w);
	return (error);
}

int
arc_address_doit(cbl_req *req, const struct arc_address_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (!valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if (strchr(rq->address, '|') != NULL)
		return (reject(req, "give the interface separately"));
	if (rq->interface != NULL && !valid_ifname(rq->interface))
		return (reject(req, "invalid interface name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_ADDRESS;
	j->addr = *rq;
	j->addr.jail = xstrdup(rq->jail);
	j->addr.address = xstrdup(rq->address);
	j->addr.interface = xstrdup(rq->interface);
	return (start(j));
}

int
arc_agent_build_doit(cbl_req *req, const struct arc_agent_build_req *rq,
    void *arg __unused)
{
	struct job	*j;

	/* An agent before gzip-update decodes no compress at all. */
	if (rq->compress && !has_feature(ZPROG_FEATURE))
		return (reject(req, "unknown attribute compress"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_AGENT_BUILD;
	j->source = xstrdup(rq->source);
	j->ref = rq->ref != NULL && rq->ref[0] != '\0' ? xstrdup(rq->ref) :
	    NULL;
	j->host_keys = rq->host_keys != NULL ? xstrdup(rq->host_keys) : NULL;
	j->ssh_key = rq->ssh_key != NULL ? xstrdup(rq->ssh_key) : NULL;
	j->compress = rq->compress;
	return (start(j));
}

int
arc_source_head_doit(cbl_req *req, const struct arc_source_head_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SOURCE_HEAD;
	j->source = xstrdup(rq->source);
	j->ref = rq->ref != NULL && rq->ref[0] != '\0' ? xstrdup(rq->ref) :
	    NULL;
	j->host_keys = rq->host_keys != NULL ? xstrdup(rq->host_keys) : NULL;
	j->ssh_key = rq->ssh_key != NULL ? xstrdup(rq->ssh_key) : NULL;
	return (start(j));
}

int
arc_console_update_doit(cbl_req *req, const struct arc_console_update_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_CONSOLE_UPDATE;
	j->source = xstrdup(rq->source);
	j->ref = rq->ref != NULL && rq->ref[0] != '\0' ? xstrdup(rq->ref) :
	    NULL;
	j->host_keys = rq->host_keys != NULL ? xstrdup(rq->host_keys) : NULL;
	j->ssh_key = rq->ssh_key != NULL ? xstrdup(rq->ssh_key) : NULL;
	return (start(j));
}

int
arc_agent_update_doit(cbl_req *req, const struct arc_agent_update_req *rq,
    void *arg __unused)
{
	struct job	*j;
	const cbl_peer	*peer;

	if (rq->binary.len == 0 || strlen(rq->sha256) != 64)
		return (reject(req, "a program and its SHA-256 are needed"));
	/* An agent before gzip-update decodes no program-size at all. */
	if (rq->has_program_size && !has_feature(ZPROG_FEATURE))
		return (reject(req, "unknown attribute program-size"));
	if (rq->has_program_size && (rq->program_size == 0 ||
	    rq->program_size > ARC_MAX_PROGRAM))
		return (reject(req, "the program would inflate past what this "
		    "host takes"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_AGENT_UPDATE;
	/* The local socket's root is root already: its program is taken
	 * unsigned; any other peer's must be signed by the CA. */
	peer = cbl_req_peer(req);
	j->local = peer != NULL && cbl_peer_transport(peer) == CBL_TR_UNIX;
	if (rq->signature.len > 0) {
		if ((j->sig = malloc(rq->signature.len)) == NULL)
			err(1, "malloc");
		memcpy(j->sig, rq->signature.p, rq->signature.len);
		j->siglen = rq->signature.len;
	}
	if ((j->binary = malloc(rq->binary.len)) == NULL)
		err(1, "malloc");
	memcpy(j->binary, rq->binary.p, rq->binary.len);
	j->binlen = rq->binary.len;
	j->progsize = rq->has_program_size ? rq->program_size : 0;
	j->sha256 = xstrdup(rq->sha256);
	j->restart = rq->restart;
	return (start(j));
}

int
arc_network_doit(cbl_req *req, const struct arc_network_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->net_kind >= nitems(net_kind_names))
		return (reject(req, "invalid kind"));
	/* Read through their modules now (Y-3), their numbers kept. */
	if (rq->net_kind == ARC_NET_KIND_NETGRAPH)
		return (reject(req, "the netgraph kind is retired: "
		    "arcana-netgraph's netgraph, its read action"));
	if (rq->net_kind == ARC_NET_KIND_WIREGUARD)
		return (reject(req, "the wireguard kind is retired: "
		    "arcana-wireguard's wireguard, its read action"));
	if (rq->net_kind == ARC_NET_KIND_BIRD || rq->net_kind ==
	    ARC_NET_KIND_BIRD_ROUTES || rq->net_kind == ARC_NET_KIND_BIRD_OSPF)
		return (reject(req, "the bird, bird-routes and bird-ospf kinds "
		    "are retired: arcana-bird's bird, its read, routes and ospf "
		    "actions"));
	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if (rq->has_net_family && rq->net_family > ARC_NET_FAMILY_INET6)
		return (reject(req, "invalid family"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_NETWORK;
	/* The text to search for rides where a build's source does. */
	j->source = rq->net_filter != NULL && rq->net_filter[0] != '\0' ?
	    xstrdup(rq->net_filter) : NULL;
	j->action = rq->net_kind;
	j->family = rq->has_net_family ? rq->net_family : ARC_NET_FAMILY_ALL;
	j->fib = rq->has_net_fib ? rq->net_fib : 0;
	j->offset = rq->has_offset ? rq->offset : 0;
	j->jail = rq->jail != NULL && rq->jail[0] != '\0' ? xstrdup(rq->jail) :
	    NULL;
	return (start(j));
}

int
arc_route_lookup_doit(cbl_req *req, const struct arc_route_lookup_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->lookup == NULL || rq->lookup[0] == '-')
		return (reject(req, "an address to look up is needed"));
	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_ROUTE_LOOKUP;
	j->source = xstrdup(rq->lookup);
	j->fib = rq->has_net_fib ? rq->net_fib : 0;
	j->jail = rq->jail != NULL && rq->jail[0] != '\0' ? xstrdup(rq->jail) :
	    NULL;
	return (start(j));
}

int
arc_monitors_doit(cbl_req *req, const struct arc_monitors_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_MONITORS;
	j->pos = rq->has_after ? rq->after : 0;
	return (start(j));
}

int
arc_ipfw_rules_doit(cbl_req *req, const struct arc_ipfw_rules_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_IPFW_RULES;
	j->from_rc = rq->from_rc;
	j->ref = rq->conf_text != NULL && !rq->from_rc ? xstrdup(
	    rq->conf_text) : NULL;
	j->sha256 = rq->sha256 != NULL ? xstrdup(rq->sha256) : NULL;
	j->refresh = rq->dry_run;
	j->jail = rq->jail != NULL && rq->jail[0] != '\0' ? xstrdup(rq->jail) :
	    NULL;
	return (start(j));
}

/* notify: the token, the chat and the text, the job's own copies. */
int
arc_notify_doit(cbl_req *req, const struct arc_notify_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_NOTIFY;
	j->token = xstrdup(rq->notify_token);
	j->psrc = xstrdup(rq->notify_chat);
	j->pdst = xstrdup(rq->notify_text);
	return (start(j));
}

/* A network table in parts, from a thread of the dump's own. */
int
arc_network_dumpit(cbl_req *req, const struct arc_network_dump_req *rq,
    struct cbl_dump_state *st, void *arg __unused)
{
	struct arc_network_dump_rsp	 rsp;
	struct arc_route		*routes;
	struct ucl_object_s		*keep;
	const char			*err;
	char				*json;
	uint64_t			 total;
	size_t				 nroutes;
	bool				 more;
	int				 error;

	if (rq->net_kind != ARC_NET_KIND_ROUTES && rq->net_kind !=
	    ARC_NET_KIND_CONNECTIONS && rq->net_kind != ARC_NET_KIND_SOCKETS)
		return (reject(req, "the routes, connections and sockets "
		    "come in parts; the rest whole"));
	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if (rq->net_filter != NULL && strlen(rq->net_filter) > 128)
		return (reject(req, "the text to search for is at most 128 "
		    "bytes"));
	more = network_part(st, rq, &json, &total, &err);
	if (json == NULL)
		return (err != NULL ? reject(req, err) : ENOMEM);
	if (err != NULL && !more) {
		free(json);
		return (reject(req, err));
	}
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_total = true;
	rsp.total = total;
	routes = NULL;
	keep = NULL;
	/* The routes typed, as the spec has a route; the rest as JSON. */
	if (rq->net_kind == ARC_NET_KIND_ROUTES) {
		if ((error = network_routes(json, &routes, &nroutes, &keep)) !=
		    0) {
			free(json);
			return (error);
		}
		rsp.routes.v = routes;
		rsp.routes.n = nroutes;
	} else
		rsp.json = json;
	error = arc_network_dump_reply(req, &rsp);
	free(routes);
	network_routes_free(keep);
	free(json);
	if (error != 0)
		return (error);
	return (more ? EAGAIN : 0);
}

int
arc_ssh_doit(cbl_req *req, const struct arc_ssh_req *rq, void *arg __unused)
{
	struct job	*j;

	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SSH;
	j->jail = rq->jail != NULL && rq->jail[0] != '\0' ? xstrdup(rq->jail) :
	    NULL;
	return (start(j));
}

int
arc_builder_doit(cbl_req *req, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_BUILDER;
	return (start(j));
}

int
arc_builder_options_doit(cbl_req *req, const struct arc_builder_options_req *rq,
    void *arg __unused)
{
	struct job	*j;
	const char	**v;
	size_t		 i;

	if (rq->names.n > 16)
		return (reject(req, "a port's options are asked with jail, "
		    "ports, set and origin"));
	for (i = 0; i < rq->names.n; i++)
		if (rq->names.v[i] == NULL)
			return (reject(req, "a word is missing"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_BUILDER_OPTIONS;
	if (rq->names.n > 0) {
		if ((v = calloc(rq->names.n, sizeof(*v))) == NULL) {
			free(j);
			return (ENOMEM);
		}
		for (i = 0; i < rq->names.n; i++)
			v[i] = xstrdup(rq->names.v[i]);
		j->pkg.names.v = v;
		j->pkg.names.n = rq->names.n;
	}
	return (start(j));
}

/* The system's own files, and the host's settings beside them. */
int
arc_system_doit(cbl_req *req, const struct arc_system_req *rq,
    void *arg __unused)
{
	struct job	*j;
	const char	**v;
	size_t		 i;

	if (rq->names.n > 16)
		return (reject(req, "system reads its files by name, and host"));
	for (i = 0; i < rq->names.n; i++)
		if (rq->names.v[i] == NULL)
			return (reject(req, "a word is missing"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SYSTEM;
	if (rq->names.n > 0) {
		if ((v = calloc(rq->names.n, sizeof(*v))) == NULL) {
			free(j);
			return (ENOMEM);
		}
		for (i = 0; i < rq->names.n; i++)
			v[i] = xstrdup(rq->names.v[i]);
		j->pkg.names.v = v;
		j->pkg.names.n = rq->names.n;
	}
	return (start(j));
}

int
arc_smtpd_doit(cbl_req *req, const struct arc_smtpd_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->names.n > 0)
		return (reject(req, "smtpd is read whole: no words"));
	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SMTPD;
	j->jail = rq->jail != NULL && rq->jail[0] != '\0' ? xstrdup(rq->jail) :
	    NULL;
	return (start(j));
}

int
arc_speeder_doit(cbl_req *req, const struct arc_speeder_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->names.n > 0)
		return (reject(req, "speeder is read whole: no words"));
	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SPEEDER;
	j->jail = rq->jail != NULL && rq->jail[0] != '\0' ? xstrdup(rq->jail) :
	    NULL;
	return (start(j));
}

/* The storage services: NFS, iSCSI, HAST, or all. */
int
arc_netstore_doit(cbl_req *req, const struct arc_netstore_req *rq,
    void *arg __unused)
{
	struct job	*j;
	const char	**v;
	size_t		 i;

	if (rq->names.n > 3)
		return (reject(req, "netstore reads nfs, iscsi and hast"));
	for (i = 0; i < rq->names.n; i++)
		if (rq->names.v[i] == NULL)
			return (reject(req, "a word is missing"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_NETSTORE;
	if (rq->names.n > 0) {
		if ((v = calloc(rq->names.n, sizeof(*v))) == NULL) {
			free(j);
			return (ENOMEM);
		}
		for (i = 0; i < rq->names.n; i++)
			v[i] = xstrdup(rq->names.v[i]);
		j->pkg.names.v = v;
		j->pkg.names.n = rq->names.n;
	}
	return (start(j));
}

/* The ruleset's rules, searched: a page of them. */
int
arc_suricata_rules_doit(cbl_req *req, const struct arc_suricata_rules_req *rq,
    void *arg __unused)
{
	struct job	*j;
	const char	**v;
	size_t		 i;

	if (rq->names.n > 10)
		return (reject(req, "the rules are searched by q=, sid=, only=, "
		    "classtype=, offset= and limit=; sources=1 says the rule "
		    "sources"));
	for (i = 0; i < rq->names.n; i++)
		if (rq->names.v[i] == NULL)
			return (reject(req, "a word is missing"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SURICATA_RULES;
	if (rq->names.n > 0) {
		if ((v = calloc(rq->names.n, sizeof(*v))) == NULL) {
			free(j);
			return (ENOMEM);
		}
		for (i = 0; i < rq->names.n; i++)
			v[i] = xstrdup(rq->names.v[i]);
		j->pkg.names.v = v;
		j->pkg.names.n = rq->names.n;
	}
	return (start(j));
}

int
arc_crashes_doit(cbl_req *req, const struct arc_crashes_req *rq,
    void *arg __unused)
{
	struct job	*j;
	const char	**v;
	size_t		 i;

	if (rq->names.n > 3)
		return (reject(req, "crashes are read, or one's backtrace: "
		    "backtrace core [program]"));
	for (i = 0; i < rq->names.n; i++)
		if (rq->names.v[i] == NULL)
			return (reject(req, "a word is missing"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_CRASHES;
	if (rq->names.n > 0) {
		if ((v = calloc(rq->names.n, sizeof(*v))) == NULL) {
			free(j);
			return (ENOMEM);
		}
		for (i = 0; i < rq->names.n; i++)
			v[i] = xstrdup(rq->names.v[i]);
		j->pkg.names.v = v;
		j->pkg.names.n = rq->names.n;
	}
	return (start(j));
}

/* Is the spec complete and are its names fit?  NULL, or what is wrong. */
static const char *
check_spec(const struct arc_job_spec *sp)
{
	struct work	 cw;
	const char	*e;
	size_t		 i;

	if (!sp->has_kind || sp->kind >= ARC_JOB_KIND_COUNT)
		return ("a job needs a kind");
	/* For what changes a network, jail is the jail whose it is. */
	if (sp->kind >= ARC_JOB_KIND_IF_ADDRESS && sp->jail != NULL &&
	    sp->jail[0] != '\0' && !valid_jail(sp->jail))
		return ("invalid jail name");
	switch (sp->kind) {
	case ARC_JOB_KIND_JAIL_ACTION:
		if (sp->jail == NULL || !valid_jail(sp->jail))
			return ("invalid jail name");
		if (!sp->has_action || sp->action > ARC_ACTION_DISABLE)
			return ("invalid action");
		if (sp->safe)
			return ("what a jail was doing cannot be put back: not "
			    "in safe mode");
		break;
	case ARC_JOB_KIND_ADDRESS:
		if (sp->jail == NULL || !valid_jail(sp->jail))
			return ("invalid jail name");
		if (sp->address == NULL || strlen(sp->address) < 2 ||
		    strchr(sp->address, '|') != NULL)
			return ("invalid address");
		if (sp->interface != NULL && !valid_ifname(sp->interface))
			return ("invalid interface name");
		if (!sp->live && !sp->persist)
			return ("say live, persist or both");
		break;
	case ARC_JOB_KIND_IF_ADDRESS:
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		if (sp->address == NULL || strlen(sp->address) < 2)
			return ("invalid address");
		break;
	case ARC_JOB_KIND_IF_STATE:
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		if (!sp->has_up)
			return ("say up or down");
		break;
	case ARC_JOB_KIND_IF_SET:
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		if ((!sp->has_mtu || sp->mtu == 0) && sp->description == NULL &&
		    !sp->has_fib && !sp->has_tunnelfib && sp->addressing == NULL)
			return ("say what to set: mtu, description, fib, "
			    "tunnelfib, addressing, or several");
		if (sp->addressing != NULL && strcmp(sp->addressing, "dhcp") != 0
		    && strcmp(sp->addressing, "slaac") != 0 && strcmp(
		    sp->addressing, "static") != 0 && strcmp(sp->addressing,
		    "was") != 0)
			return ("addressing is dhcp, slaac, static or was");
		if ((sp->has_fib && sp->fib > 65535) || (sp->has_tunnelfib &&
		    sp->tunnelfib > 65535))
			return ("a routing table is a number of one");
		break;
	case ARC_JOB_KIND_IF_CREATE:
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		if (sp->parent != NULL && !valid_ifname(sp->parent))
			return ("invalid interface name");
		break;
	case ARC_JOB_KIND_ZFS:
	case ARC_JOB_KIND_ZPOOL:
	case ARC_JOB_KIND_MOUNT:
	case ARC_JOB_KIND_GPART:
	case ARC_JOB_KIND_CAM:
		if ((e = storage_check(sp)) != NULL)
			return (e);
		break;
	case ARC_JOB_KIND_IPFW:
		if ((e = ipfw_check(sp)) != NULL)
			return (e);
		break;
	case ARC_JOB_KIND_BRIDGE:
	case ARC_JOB_KIND_GENEVE:
		/* Undone by the inverse word, where there is one: a member
		 * in or out, a flag, vlanfilter, a static address, a geneve
		 * made.  What sets a value over another, or forgets what
		 * was learned, is not. */
		if (sp->safe && sp->verb != NULL && !((sp->kind ==
		    ARC_JOB_KIND_BRIDGE && (strcmp(sp->verb, "addm") == 0 ||
		    strcmp(sp->verb, "deletem") == 0 || strcmp(sp->verb,
		    "vlanfilter") == 0 || strcmp(sp->verb, "flag") == 0 ||
		    strcmp(sp->verb, "static") == 0)) || (sp->kind ==
		    ARC_JOB_KIND_GENEVE && strcmp(sp->verb, "create") == 0)))
			return ("only addm, deletem, vlanfilter, flag and static "
			    "of a bridge, and a geneve made, are taken back: "
			    "not in safe mode");
		if ((e = l2_check(sp)) != NULL)
			return (e);
		break;
	case ARC_JOB_KIND_PROCESS:
		if ((e = proc_check(sp)) != NULL)
			return (e);
		break;
	case ARC_JOB_KIND_IPSEC:
		/* A key made, a daemon started: nothing to put back. */
		if (sp->safe && sp->verb != NULL && (strcmp(sp->verb, "init") ==
		    0 || strcmp(sp->verb, "start") == 0))
			return ("IPsec init and start are not undone: not in "
			    "safe mode");
		return (ipsec_check(sp));
	case ARC_JOB_KIND_IPSEC_SA:
		/* In safe mode, the key files and the state go back, the SAs
		 * derived again from the words kept; the runner refuses, before
		 * the change, SAs set by hand, whose keys are nowhere. */
		return (sa_check(sp));
	case ARC_JOB_KIND_PKG_INSTALL:
		if (sp->safe)
			return ("an install is not taken back by itself");
		if (sp->names.n == 0)
			return ("name the packages to install");
		break;
	case ARC_JOB_KIND_REBOOT:
		if (sp->safe)
			return ("a reboot is not undone: not in safe mode");
		if (sp->jail != NULL && sp->jail[0] != '\0')
			return ("a jail is restarted (jail-action), not rebooted");
		break;
	case ARC_JOB_KIND_JAIL_BASE:
		if (sp->safe)
			return ("a jail's base is not taken back by itself");
		if (sp->jail == NULL || sp->jail[0] == '\0' || strcmp(sp->jail,
		    "*") == 0)
			return ("name the jail");
		if (sp->verb == NULL || (strcmp(sp->verb, "convert") != 0 &&
		    strcmp(sp->verb, "upgrade") != 0))
			return ("verb convert or upgrade");
		if (strcmp(sp->verb, "upgrade") == 0 && (sp->release == NULL ||
		    sp->release[0] == '\0'))
			return ("name the release to go to: 16, or 15.2");
		break;
	case ARC_JOB_KIND_PKG_CLEAN:
		if (sp->safe)
			return ("a clean is not taken back by itself");
		if (sp->names.n > 0)
			return ("pkg clean takes no names: the cache is cleaned "
			    "whole");
		break;
	case ARC_JOB_KIND_SYSCTL:
		/* A vnet jail's own network's: net.*, its vnet's; the rest
		 * are the host's kernel's. */
		if (sp->jail != NULL && sp->jail[0] != '\0' && (sp->names.n < 1 ||
		    strncmp(sp->names.v[0], "net.", 4) != 0))
			return ("a jail's sysctls are not set from here, but its "
			    "network's (net.*), which are its own");
		if (sp->names.n != 2 || !sysctl_name_ok(sp->names.v[0]))
			return ("name one sysctl, with letters, digits and "
			    ". _ - %, and its value");
		if (!sysctl_value_ok(sp->names.v[1]))
			return ("a sysctl's value is one line");
		break;
	case ARC_JOB_KIND_KMOD:
		if (sp->jail != NULL && sp->jail[0] != '\0')
			return ("a jail has no kernel of its own");
		if (sp->verb == NULL || (strcmp(sp->verb, "load") != 0 &&
		    strcmp(sp->verb, "unload") != 0 && strcmp(sp->verb,
		    "keep") != 0 && strcmp(sp->verb, "forget") != 0))
			return ("a module is loaded, unloaded, kept or "
			    "forgotten: load, unload, keep, forget");
		if (sp->names.n != 1 || !kmod_name_ok(sp->names.v[0]))
			return ("name one module, as kldload(8) finds it, "
			    "without a path: letters, digits and . _ -");
		if (strcmp(sp->verb, "unload") == 0 && (strcmp(sp->names.v[0],
		    "kernel") == 0 || strcmp(sp->names.v[0], "kernel.ko") == 0))
			return ("the kernel itself is not unloaded");
		break;
	case ARC_JOB_KIND_RTADVD:
		if (sp->interface == NULL || sp->interface[0] == '\0')
			return ("an rtadvd job needs an interface");
		if (sp->safe)
			return ("rtadvd's prefix is not undone: not in safe "
			    "mode");
		if (!sp->remove && (sp->names.n == 0 || !rtadvd_prefix_ok(
		    sp->names.v[0])))
			return ("an rtadvd job names the prefix advertised, an "
			    "IPv6 one of length 64, then the DNS servers; or "
			    "says remove");
		if (sp->names.n > 9)
			return ("at most 8 DNS servers are advertised");
		for (i = 1; !sp->remove && i < sp->names.n; i++) {
			struct in6_addr	a6;

			if (inet_pton(AF_INET6, sp->names.v[i], &a6) != 1)
				return ("a DNS server advertised is an IPv6 "
				    "address: not an IPv6 address");
		}
		break;
	case ARC_JOB_KIND_NTP:
		if (sp->jail != NULL && sp->jail[0] != '\0')
			return ("a jail keeps the host's time");
		/* Its undo would take arcana's block out, not put the old
		 * servers back: not undone, so not safe. */
		if (sp->safe)
			return ("NTP servers are not undone: not in safe mode");
		if (!sp->remove && sp->names.n == 0)
			return ("name the NTP servers, or say remove");
		for (i = 0; i < sp->names.n; i++)
			if (!ntp_server_ok(sp->names.v[i]))
				return ("a server is a name or an address: "
				    "letters, digits and . - :");
		break;
	case ARC_JOB_KIND_IF_VNET:
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		if (sp->jail == NULL || sp->jail[0] == '\0')
			return ("name the jail the interface goes to");
		if (sp->parent != NULL && sp->parent[0] != '\0' &&
		    (!valid_ifname(sp->parent) || sp->remove ||
		    strcmp(sp->interface, "epair") != 0))
			return ("a bridge is named for a new epair's end on "
			    "the host only");
		break;
	case ARC_JOB_KIND_IF_DESTROY:
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		/* Made again as it was: a tunnel, a tap or tun, a loopback;
		 * not what has keys, members or a pair's other end. */
		if (sp->safe) {
			static const char *const again[] = { "gif", "gre", "me",
			    "tap", "tun", "lo" };
			size_t	k, alen;

			for (k = 0; k < nitems(again); k++) {
				alen = strlen(again[k]);
				if (strncmp(sp->interface, again[k], alen) == 0 &&
				    sp->interface[alen + strspn(sp->interface +
				    alen, "0123456789")] == '\0')
					break;
			}
			if (k == nitems(again))
				return ("only a gif, gre, me, tap, tun or lo "
				    "interface destroyed is made again as it "
				    "was: not in safe mode");
		}
		break;
	case ARC_JOB_KIND_NETGRAPH:
		if (sp->safe)
			return ("netgraph changes cannot be undone: not in "
			    "safe mode");
		return (ng_check(sp->verb, sp->names.v, sp->names.n));
	case ARC_JOB_KIND_JAIL_ALLOW:
		return (jail_allow_check(sp));
	case ARC_JOB_KIND_JAIL_CONF:
		return (jail_conf_check(sp));
	case ARC_JOB_KIND_NEIGHBOUR:
		return (neigh_check(sp));
	case ARC_JOB_KIND_CARP:
		return (carp_check(sp));
	case ARC_JOB_KIND_CERT:
		return (cert_check(sp));
	case ARC_JOB_KIND_SSH:
		return (ssh_check(sp));
	case ARC_JOB_KIND_POUDRIERE:
		return (poudriere_check(sp));
	case ARC_JOB_KIND_CLAMAV:
		return (clamav_check(sp));
	case ARC_JOB_KIND_SURICATA:
		return (suricata_check(sp));
	case ARC_JOB_KIND_NFS:
	case ARC_JOB_KIND_ISCSI:
	case ARC_JOB_KIND_HAST:
		return (netstore_check(sp));
	case ARC_JOB_KIND_SYSFILE:
		return (sysfile_check(sp));
	case ARC_JOB_KIND_GEOM:
		return (geom_check(sp));
	case ARC_JOB_KIND_SMTPD:
		return (smtpd_check(sp));
	case ARC_JOB_KIND_SPEEDER:
		return (speeder_check(sp));
	case ARC_JOB_KIND_MONITOR:
		return (monitor_check(sp));
	case ARC_JOB_KIND_WIREGUARD:
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		work_init(&cw);
		e = wg_check(&cw, sp);
		work_free(&cw);
		return (e);
	case ARC_JOB_KIND_BIRD:
		return (bird_check(sp->verb, sp->names.v, sp->names.n));
	case ARC_JOB_KIND_ROUTE:
		if (sp->destination == NULL || sp->destination[0] == '\0' ||
		    sp->destination[0] == '-')
			return ("a route needs a destination");
		if (sp->gateway != NULL && sp->gateway[0] == '-')
			return ("invalid gateway");
		if (sp->source != NULL && sp->source[strspn(sp->source,
		    "0123456789abcdefABCDEF.:")] != '\0')
			return ("the address to send from is an address");
		if (!sp->remove && (sp->gateway == NULL ||
		    sp->gateway[0] == '\0') && (sp->verb == NULL ||
		    sp->names.n == 0))
			return ("a route to add needs a gateway; one kept is "
			    "renamed with keep and a name alone");
		if (sp->names.n > 1)
			return ("a route is kept by one name");
		if (sp->verb != NULL && strcmp(sp->verb, "keep") != 0)
			return ("a route's verb is keep (rc.conf alone), or none");
		if (sp->verb != NULL && !sp->persist)
			return ("keep is rc.conf's: say persist too");
		if (sp->verb != NULL && sp->safe)
			return ("a route kept or forgotten in rc.conf alone "
			    "changes nothing live: there is nothing to undo, "
			    "so not in safe mode");
		break;
	case ARC_JOB_KIND_SERVICE_ACTION:
		if (sp->service == NULL || !valid_service(sp->service))
			return ("invalid service name");
		if (!sp->has_service_action ||
		    sp->service_action > ARC_SERVICE_ACTION_DISABLE)
			return ("invalid action");
		if (sp->safe && (sp->service_action ==
		    ARC_SERVICE_ACTION_RESTART || sp->service_action ==
		    ARC_SERVICE_ACTION_RELOAD))
			return ("a restart or a reload cannot be undone: not "
			    "in safe mode");
		break;
	case ARC_JOB_KIND_SERVICE_CONFIG:
		if (sp->service == NULL || !valid_service(sp->service))
			return ("invalid service name");
		if (sp->variables.n == 0)
			return ("nothing to set");
		for (i = 0; i < sp->variables.n; i++) {
			if (!rc_name_ok(sp->variables.v[i].key))
				return ("a variable's name is letters, digits "
				    "and _");
			if (!rc_value_ok(sp->variables.v[i].value))
				return ("a variable's value has a quote, $, ` "
				    "or \\: rc.conf would read it as more");
		}
		break;
	default:
		/* "*": every running jail's, one after the other. */
		if (sp->jail != NULL && strcmp(sp->jail, "*") != 0 &&
		    !valid_jail(sp->jail))
			return ("invalid jail name");
		for (i = 0; i < sp->names.n; i++)
			if (sp->names.v[i] == NULL)
				return ("a package without a name");
		if (sp->safe)
			return ("an upgrade cannot be undone: not in safe mode");
		break;
	}
	return (NULL);
}

/*
 * Would the change take away the address this request came in by?  It
 * would cut off the one who asks, who could then not take it back: it
 * is done only in safe mode, where the host takes it back itself.
 */
static const char *
cuts_off(cbl_req *req, const struct arc_job_spec *sp)
{
	struct sockaddr_storage	 ss;
	socklen_t		 len;
	unsigned char		 raw[16], *mine;
	char			 ifname[IF_NAMESIZE], addr[65];
	bool			 hit;
	int			 fd;

	/*
	 * In a jail the request did not come in by any address of its;
	 * an interface given to a jail is one the host has no more.
	 */
	if (sp->safe || (sp->kind == ARC_JOB_KIND_ROUTE && sp->verb != NULL))
		return (NULL);
	if (sp->kind == ARC_JOB_KIND_IF_VNET) {
		if (sp->remove)
			return (NULL);
	} else if ((sp->jail != NULL && sp->jail[0] != '\0') ||
	    (sp->kind != ARC_JOB_KIND_IF_ADDRESS && sp->kind !=
	    ARC_JOB_KIND_IF_STATE && sp->kind != ARC_JOB_KIND_IF_DESTROY &&
	    sp->kind != ARC_JOB_KIND_IF_SET && sp->kind != ARC_JOB_KIND_ROUTE &&
	    sp->kind != ARC_JOB_KIND_SYSCTL && sp->kind != ARC_JOB_KIND_IPFW))
		return (NULL);
	len = sizeof(ss);
	if ((fd = cbl_conn_fd(cbl_req_conn(req))) == -1 || getsockname(fd,
	    (struct sockaddr *)&ss, &len) == -1 || (ss.ss_family != AF_INET &&
	    ss.ss_family != AF_INET6) || !if_owning((struct sockaddr *)&ss,
	    ifname, sizeof(ifname)))
		return (NULL);
	hit = false;
	if (sp->kind == ARC_JOB_KIND_SYSCTL) {
		/* Forwarding, or the tables, turned over under the path. */
		static const char *const cut[] = { "net.fibs",
		    "net.add_addr_allfibs", "net.inet.ip.forwarding",
		    "net.inet6.ip6.forwarding" };
		size_t	i;

		for (i = 0; i < nitems(cut) && !hit; i++)
			hit = sp->names.n > 0 && strcmp(sp->names.v[0], cut[i]) ==
			    0;
	} else if (sp->kind == ARC_JOB_KIND_IPFW)
		/* A rule set swapped in, or the firewall turned on: the
		 * path is whatever the rules say. */
		hit = sp->verb != NULL && (strcmp(sp->verb, "apply") == 0 ||
		    strcmp(sp->verb, "enable") == 0);
	else if (sp->kind == ARC_JOB_KIND_IF_SET)
		/* Moved to another table, the interface's addresses go
		 * with it; a tunnel's outer path is the tunnelfib's. */
		hit = strcmp(sp->interface, ifname) == 0 && (sp->has_fib ||
		    sp->has_tunnelfib);
	else if (sp->kind == ARC_JOB_KIND_ROUTE) {
		/*
		 * A route added or deleted that covers the peer, in the
		 * table this interface is in: the way back may change.
		 */
		struct sockaddr_storage	 ps;
		socklen_t		 plen;
		const unsigned char	*pa;
		unsigned char		 net[16];
		char			 dest[65];
		const char		*slash;
		int			 af, plen_bits, max;

		plen = sizeof(ps);
		if (getpeername(fd, (struct sockaddr *)&ps, &plen) == -1 ||
		    (sp->has_fib ? (int)sp->fib : 0) != if_fib(ifname))
			return (NULL);
		strlcpy(dest, sp->destination, sizeof(dest));
		slash = strchr(dest, '/');
		dest[strcspn(dest, "/")] = '\0';
		if (ps.ss_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(
		    &((struct sockaddr_in6 *)&ps)->sin6_addr)) {
			af = AF_INET;
			pa = (const unsigned char *)&((struct sockaddr_in6 *)
			    &ps)->sin6_addr + 12;
		} else if (ps.ss_family == AF_INET6) {
			af = AF_INET6;
			pa = (const unsigned char *)&((struct sockaddr_in6 *)
			    &ps)->sin6_addr;
		} else {
			af = AF_INET;
			pa = (const unsigned char *)&((struct sockaddr_in *)
			    &ps)->sin_addr;
		}
		max = af == AF_INET ? 32 : 128;
		if (strcmp(dest, "default") == 0) {
			memset(net, 0, sizeof(net));
			plen_bits = 0;
		} else if (inet_pton(af, dest, net) != 1)
			return (NULL);
		else
			plen_bits = slash != NULL ? atoi(slash + 1) : max;
		hit = plen_bits >= 0 && plen_bits <= max && prefix_covers(pa,
		    net, plen_bits);
	} else if (sp->kind == ARC_JOB_KIND_IF_ADDRESS) {
		if (!sp->remove || strcmp(sp->interface, ifname) != 0)
			return (NULL);
		strlcpy(addr, sp->address, sizeof(addr));
		addr[strcspn(addr, "/")] = '\0';
		if (ss.ss_family == AF_INET) {
			mine = (unsigned char *)&((struct sockaddr_in *)&ss)->
			    sin_addr;
			hit = inet_pton(AF_INET, addr, raw) == 1 &&
			    memcmp(raw, mine, 4) == 0;
		} else {
			mine = (unsigned char *)&((struct sockaddr_in6 *)&ss)->
			    sin6_addr;
			hit = (inet_pton(AF_INET6, addr, raw) == 1 &&
			    memcmp(raw, mine, 16) == 0) ||
			    (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)
			    (void *)mine) && inet_pton(AF_INET, addr, raw) ==
			    1 && memcmp(raw, mine + 12, 4) == 0);
		}
	} else
		hit = strcmp(sp->interface, ifname) == 0 &&
		    (sp->kind != ARC_JOB_KIND_IF_STATE || !sp->up);
	return (hit ? "this request came in by that address: the change "
	    "would cut you off.  Ask for it in safe mode, and the host takes "
	    "it back when it does not hear from you again" : NULL);
}

/*
 * A batch of jobs req asks for, checked and queued: each spec's own
 * checks, what would cut its sender off, the queue's room; the jobs
 * into *v, *n, w's.  -1 and *errp: none queued.  arcana-jobs' submit's
 * (yarcana.c).
 */
int
jobs_submit_checked(cbl_req *req, const struct arc_job_spec *specs, size_t n,
    struct work *w, const struct arc_job **v, size_t *nv, const char **errp)
{
	char	*peer;
	size_t	 i;

	for (i = 0; i < n; i++)
		if ((*errp = check_spec(&specs[i])) != NULL ||
		    (*errp = cuts_off(req, &specs[i])) != NULL)
			return (-1);
	if (jobs_waiting() + n > JOBS_WAITING_MAX) {
		*errp = "too many jobs wait already: let some finish, or "
		    "cancel them";
		return (-1);
	}
	peer = peer_name(req);
	jobs_submit(specs, n, peer, w, v, nv);
	free(peer);
	return (0);
}
