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

struct job {
	cbl_req			*req;
	uint16_t		 cmd;
	bool			 config_only;
	char			*jail;
	uint8_t			 action;
	struct arc_address_req	 addr;
	struct arc_service_config_req svc;
	uint8_t			 family;
	uint32_t		 fib;
	uint32_t		 offset;		/* network: rows to leave out */
	uint64_t		 pos;		/* log: where to read on; history: since */
	bool			 has_pos;
	uint32_t		 lim[4];	/* history: the limits */
	struct arc_pkg_upgrade_req pkg;
	bool			 refresh;
	bool			 installed;	/* packages: pkg query */
	bool			 from_rc;	/* ipfw-rules: rc.conf's file */
	uint8_t			 pkg_ip;	/* packages: pkg -4, -6 */
	uint8_t			*binary;	/* agent-update */
	size_t			 binlen;
	char			*sha256;
	bool			 restart;
	char			*source;	/* agent-build */
	char			*ref;
	char			*host_keys;
	char			*ssh_key;
	uint32_t		 log_count;	/* source-log: commits at most */
	int			 safe_wait;	/* bird-config: s, 0 the agent's */
	char			*peer;
	char			*bundle;	/* config-apply */
	bool			 anyway;
	char			*new_host;
	char			*psrc, *pdst, *pproto, *piface;	/* path-check */
	uint32_t		 pport;
	bool			 has_fib;
	bool			 preply;
	char			*listen;	/* transport */
	char			*unlisten;
	bool			 listen_keep;
	char			*sctp_also;	/* transport: "" none */
	char			*token;		/* notify: zeroed when used */
};

#define	STOPPING	"not done: arcana-agent is stopping"
#define	RESTART_WAIT	10	/* s, for service(8) to stop the daemon */
#define	JOBS_WAITING_MAX 256	/* jobs queued or running, at most */

pthread_mutex_t	change_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t build_lock = PTHREAD_MUTEX_INITIALIZER;

/* What holds change_lock now, for the log when asked to stop. */
static pthread_mutex_t	note_lock = PTHREAD_MUTEX_INITIALIZER;
static char		note[256];
static time_t		note_since;
static bool		stopping;

static const char *action_names[] = {
	[ARC_ACTION_START] = "start",
	[ARC_ACTION_STOP] = "stop",
	[ARC_ACTION_RESTART] = "restart",
	[ARC_ACTION_KILL] = "kill",
};

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
};

static const char *service_action_names[] = {
	[ARC_SERVICE_ACTION_START] = "start",
	[ARC_SERVICE_ACTION_STOP] = "stop",
	[ARC_SERVICE_ACTION_RESTART] = "restart",
	[ARC_SERVICE_ACTION_RELOAD] = "reload",
	[ARC_SERVICE_ACTION_ENABLE] = "enable",
	[ARC_SERVICE_ACTION_DISABLE] = "disable",
};

static bool	valid_service(const char *);
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
static bool
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
	return (go);
}

/* The daemon is about to stop: no change starts while that holds. */
void
changes_stop(bool on)
{

	pthread_mutex_lock(&note_lock);
	stopping = on;
	pthread_mutex_unlock(&note_lock);
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
static const char *
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
	struct arc_list_rsp	 lr;
	struct arc_action_rsp	 ar;
	struct arc_address_rsp	 dr;
	struct arc_services_rsp	 sr;
	struct arc_service_action_rsp sar;
	struct arc_service_config_rsp scr;
	struct arc_network_rsp	 nr;
	struct arc_route_lookup_rsp rlr;
	struct arc_traceroute_rsp trr;
	struct arc_sdwan_probes_rsp spr;
	struct arc_sdwan_rsp	sdr;
	struct arc_sdwan_rules_rsp srr;
	struct arc_sdwan_steer_rsp sstr;
	struct arc_sdwan_bird_rsp sbr;
	struct arc_sdwan_dhcp_rsp sdhr;
	struct arc_sdwan_dns_rsp sdnr;
	struct arc_sdwan_proxy_rsp sdpr;
	struct arc_sdwan_ids_rsp sdir;
	struct arc_bird_config_req bcq;
	struct arc_bird_config_rsp bcr;
	struct arc_stats_rsp	 str;
	struct arc_kernel_rsp	 kr;
	struct arc_jail_files_rsp jfr;
	struct arc_builder_rsp	 bur;
	struct arc_builder_options_rsp bor;
	struct arc_job_spec	 bsp;
	struct arc_certs_rsp	 cer;
	struct arc_ssh_rsp	 sshr;
	struct arc_capture_req	 capq;
	struct arc_capture_rsp	 capr;
	struct arc_zfs_key_rsp	 zkr;
	struct arc_tls_rsp	 tlr;
	struct arc_transport_rsp tpr;
	struct arc_config_export_rsp cxr;
	struct arc_config_apply_rsp car;
	struct arc_path_check_rsp pcr;
	struct arc_notify_rsp	 ntr;
	struct arc_ipfw_rules_req irq;
	struct arc_ipfw_rules_rsp irr;
	struct arc_sysctl_rsp	 scr2;
	struct arc_processes_rsp prr;
	struct arc_log_rsp	 lgr;
	struct arc_fw_trace_rsp	 ftr;
	struct arc_history_rsp	 hsr;
	struct arc_events_rsp	 evr;
	struct arc_storage_rsp	 stg;
	struct arc_fstab_req	 fq;
	struct arc_fstab_rsp	 fr;
	struct arc_packages_rsp	 pr;
	struct arc_pkg_upgrade_rsp ur;
	struct arc_agent_update_rsp aur;
	struct arc_agent_build_rsp abr;
	struct arc_source_head_rsp shr;
	struct arc_source_log_rsp slr;
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
	switch (j->cmd) {
	case ARC_CMD_LIST:
		what = j->config_only ? "list (configuration only)" : "list";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&lr, 0, sizeof(lr));
		do_list(&w, j->config_only, &lr);
		ok = lr.ok;
		error = lr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &lr.trace.v, &lr.trace.n);
		rc = arc_list_reply(j->req, &lr);
		break;
	case ARC_CMD_ACTION:
		what = wfmt(&w, "%s %s", action_names[j->action], j->jail);
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&ar, 0, sizeof(ar));
		pthread_mutex_lock(&change_lock);
		if (change_note("%s", what))
			do_action(&w, j->jail, j->action, &ar);
		else {
			ar.has_ok = true;
			ar.error = STOPPING;
		}
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		ok = ar.ok;
		error = ar.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &ar.trace.v, &ar.trace.n);
		rc = arc_action_reply(j->req, &ar);
		break;
	case ARC_CMD_PACKAGES:
		what = wfmt(&w, "packages%s%s%s%s", j->installed ?
		    " installed" : "", j->jail != NULL ? " of jail " : "",
		    j->jail != NULL ? j->jail : "", j->refresh ?
		    " (refresh)" : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&pr, 0, sizeof(pr));
		/*
		 * Only pkg update writes (the catalogue): a reading waits for
		 * no change, and none waits for it.
		 */
		if (!j->refresh)
			do_packages(&w, j->jail, false, j->installed, j->pkg_ip,
			    &pr);
		else {
			pthread_mutex_lock(&change_lock);
			if (change_note("%s", what))
				do_packages(&w, j->jail, true, false, j->pkg_ip,
				    &pr);
			else {
				pr.has_ok = true;
				pr.error = STOPPING;
			}
			(void)change_note(NULL);
			pthread_mutex_unlock(&change_lock);
		}
		ok = pr.ok;
		error = pr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &pr.trace.v, &pr.trace.n);
		rc = arc_packages_reply(j->req, &pr);
		break;
	case ARC_CMD_PKG_UPGRADE:
		what = wfmt(&w, "pkg upgrade%s%s%s%s", j->jail != NULL ?
		    " in jail " : "", j->jail != NULL ? j->jail : "",
		    j->pkg.names.n > 0 ? " (some)" : " (all)",
		    j->pkg.dry_run ? " dry-run" : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&ur, 0, sizeof(ur));
		pthread_mutex_lock(&change_lock);
		if (change_note("%s", what))
			do_pkg_upgrade(&w, &j->pkg, &ur);
		else {
			ur.has_ok = true;
			ur.error = STOPPING;
		}
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		ok = ur.ok;
		error = ur.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &ur.trace.v, &ur.trace.n);
		rc = arc_pkg_upgrade_reply(j->req, &ur);
		break;
	case ARC_CMD_STATS:
		what = "stats";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "stats");
		memset(&str, 0, sizeof(str));
		do_stats(&w, &str);
		ok = str.ok;
		error = str.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &str.trace.v, &str.trace.n);
		rc = arc_stats_reply(j->req, &str);
		break;
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
	case ARC_CMD_PATH_CHECK:
		what = "path-check";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "path-check %s to %s", j->psrc, j->pdst);
		memset(&pcr, 0, sizeof(pcr));
		pcr.has_ok = true;
		if (scope_enter(&w, j->jail, &pcr.error) == 0)
			do_path_check(&w, j->psrc, j->pdst, j->pproto, j->pport,
			    j->piface, j->has_fib, j->fib, j->preply, &pcr);
		ok = pcr.ok;
		error = pcr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &pcr.trace.v, &pcr.trace.n);
		rc = arc_path_check_reply(j->req, &pcr);
		break;
	case ARC_CMD_CONFIG_EXPORT:
		what = j->refresh ? "config-export, secrets too" :
		    "config-export";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "%s", what);
		memset(&cxr, 0, sizeof(cxr));
		do_config_export(&w, j->refresh, &cxr);
		ok = cxr.ok;
		error = cxr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &cxr.trace.v, &cxr.trace.n);
		rc = arc_config_export_reply(j->req, &cxr);
		break;
	case ARC_CMD_CONFIG_APPLY:
		what = j->refresh ? "config-apply, a dry run" : "config-apply";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "%s", what);
		memset(&car, 0, sizeof(car));
		do_config_apply(&w, j->bundle, j->refresh, j->anyway,
		    j->new_host, &car);
		ok = car.ok;
		error = car.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &car.trace.v, &car.trace.n);
		rc = arc_config_apply_reply(j->req, &car);
		break;
	case ARC_CMD_TRANSPORT:
		what = j->refresh ? "transport retry" : j->listen != NULL ||
		    j->unlisten != NULL || j->sctp_also != NULL ?
		    "transport listeners" : "transport";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "%s", what);
		memset(&tpr, 0, sizeof(tpr));
		do_transport(&w, j->refresh, j->listen, j->unlisten,
		    j->listen_keep, j->sctp_also, &tpr);
		ok = tpr.ok;
		error = tpr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &tpr.trace.v, &tpr.trace.n);
		rc = arc_transport_reply(j->req, &tpr);
		break;
	case ARC_CMD_SYSCTL:
		what = "sysctl";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "sysctl");
		memset(&scr2, 0, sizeof(scr2));
		if (j->jail == NULL)
			do_sysctl(&w, j->source, &scr2);
		else if (scope_enter(&w, j->jail, &scr2.error) == 0)
			do_sysctl_jail(&w, j->source, &scr2);
		else
			scr2.has_ok = true;
		ok = scr2.ok;
		error = scr2.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &scr2.trace.v, &scr2.trace.n);
		rc = arc_sysctl_reply(j->req, &scr2);
		break;
	case ARC_CMD_PROCESSES:
		what = "processes";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "processes");
		memset(&prr, 0, sizeof(prr));
		if (j->fib != 0)
			do_process(&w, j->fib, &prr);
		else
			do_processes(&w, j->jail, &prr);
		ok = prr.ok;
		error = prr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &prr.trace.v, &prr.trace.n);
		rc = arc_processes_reply(j->req, &prr);
		break;
	case ARC_CMD_LOG:
		what = "log";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "log %s", j->ref != NULL ? j->ref : "messages");
		memset(&lgr, 0, sizeof(lgr));
		if (scope_enter_jail(&w, j->jail, &lgr.error, false) != 0)
			lgr.has_ok = true;
		else
			do_log(&w, j->ref, j->source, j->has_pos, j->pos,
			    j->offset, &lgr);
		ok = lgr.ok;
		error = lgr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &lgr.trace.v, &lgr.trace.n);
		rc = arc_log_reply(j->req, &lgr);
		break;
	case ARC_CMD_FW_TRACE:
		/* The address rides in source, seconds in fib, packets in
		 * offset. */
		what = "fw-trace";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "follow %s through the firewall", j->source);
		memset(&ftr, 0, sizeof(ftr));
		if (scope_enter_jail(&w, j->jail, &ftr.error, true) != 0)
			ftr.has_ok = true;
		else
			do_fw_trace(&w, j->source, j->fib, j->offset, &ftr);
		ok = ftr.ok;
		error = ftr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &ftr.trace.v, &ftr.trace.n);
		rc = arc_fw_trace_reply(j->req, &ftr);
		break;
	case ARC_CMD_HISTORY:
		/* How to sample rides in fib and offset. */
		what = j->refresh ? "history set" : "history";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "%s", what);
		memset(&hsr, 0, sizeof(hsr));
		do_history(&w, j->pos, j->refresh, j->fib, j->offset,
		    j->restart ? j->lim : NULL, j->source, &hsr);
		ok = hsr.ok;
		error = hsr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &hsr.trace.v, &hsr.trace.n);
		rc = arc_history_reply(j->req, &hsr);
		break;
	case ARC_CMD_EVENTS:
		what = "events";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "events");
		memset(&evr, 0, sizeof(evr));
		do_events(&w, j->pos, &evr);
		ok = evr.ok;
		error = evr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &evr.trace.v, &evr.trace.n);
		rc = arc_events_reply(j->req, &evr);
		break;
	case ARC_CMD_STORAGE:
		what = "storage";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "storage");
		memset(&stg, 0, sizeof(sr));
		/* A jail's: what its own zfs sees, the datasets given it. */
		if (j->jail != NULL && j->action != ARC_STORAGE_KIND_DATASETS &&
		    j->action != ARC_STORAGE_KIND_SNAPSHOTS) {
			stg.has_ok = true;
			stg.error = "of a jail, its datasets and snapshots only";
		} else if (scope_enter_jail(&w, j->jail, &stg.error, false) ==
		    0)
			do_storage(&w, j->action, j->source, &stg);
		ok = stg.ok;
		error = stg.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &stg.trace.v, &stg.trace.n);
		rc = arc_storage_reply(j->req, &stg);
		break;
	case ARC_CMD_FSTAB:
		/* The text rides in ref, its checksum in sha256. */
		what = wfmt(&w, "fstab %s", j->ref == NULL ? "read" :
		    j->refresh ? "check" : "write");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "%s", what);
		memset(&fq, 0, sizeof(fq));
		memset(&fr, 0, sizeof(fr));
		fq.conf_text = j->ref;
		fq.sha256 = j->sha256;
		fq.dry_run = j->refresh;
		fr.has_ok = true;
		if (j->ref == NULL || j->refresh)
			do_fstab(&w, &fq, &fr);
		else {
			pthread_mutex_lock(&change_lock);
			if (change_note("%s", what))
				do_fstab(&w, &fq, &fr);
			else
				fr.error = STOPPING;
			change_note(NULL);
			pthread_mutex_unlock(&change_lock);
		}
		ok = fr.ok;
		error = fr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &fr.trace.v, &fr.trace.n);
		rc = arc_fstab_reply(j->req, &fr);
		break;
	case ARC_CMD_CERTS:
		what = j->jail != NULL ? wfmt(&w, "certificates of %s", j->jail) :
		    "certificates";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "%s", what);
		memset(&cer, 0, sizeof(cer));
		cer.has_ok = true;
		if (scope_enter_jail(&w, j->jail, &cer.error, false) == 0)
			do_certs(&w, &cer);
		ok = cer.ok;
		error = cer.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &cer.trace.v, &cer.trace.n);
		rc = arc_certs_reply(j->req, &cer);
		break;
	case ARC_CMD_ZFS_KEY:
		/* The keys ride in source and ref: in nothing logged. */
		what = wfmt(&w, "zfs key of %s", j->sha256);
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "%s", what);
		memset(&zkr, 0, sizeof(zkr));
		zkr.has_ok = true;
		{
			struct arc_zfs_key_req	zq;

			memset(&zq, 0, sizeof(zq));
			zq.zfs_dataset = j->sha256;
			zq.zfs_key = j->source;
			zq.zfs_new_key = j->ref;
			pthread_mutex_lock(&change_lock);
			if (change_note("%s", what))
				do_zfs_key(&w, &zq, &zkr);
			else
				zkr.error = STOPPING;
			change_note(NULL);
			pthread_mutex_unlock(&change_lock);
		}
		if (j->source != NULL)
			explicit_bzero(j->source, strlen(j->source));
		if (j->ref != NULL)
			explicit_bzero(j->ref, strlen(j->ref));
		ok = zkr.ok;
		error = zkr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &zkr.trace.v, &zkr.trace.n);
		rc = arc_zfs_key_reply(j->req, &zkr);
		break;
	case ARC_CMD_TLS:
		/* The verb in sha256, the PEMs in source, ref and host_keys. */
		what = wfmt(&w, "tls %s", j->sha256);
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "%s", what);
		memset(&tlr, 0, sizeof(tlr));
		{
			const cbl_peer	*pe;
			uint8_t		 fp[64];
			size_t		 fplen;
			bool		 have;

			fplen = sizeof(fp);
			pe = cbl_req_peer(j->req);
			have = pe != NULL && (cbl_peer_flags(pe) &
			    CBL_PEER_AUTHENTICATED) != 0 &&
			    cbl_peer_fingerprint(pe, "sha256", fp, &fplen) == 0 &&
			    fplen == 32;
			pthread_mutex_lock(&change_lock);
			if (strcmp(j->sha256, "status") == 0 || change_note("%s",
			    what))
				do_tls(&w, j->sha256, j->source, j->ref, j->host_keys,
				    have ? fp : NULL, &tlr);
			else
				tlr.error = STOPPING;
			if (strcmp(j->sha256, "status") != 0)
				change_note(NULL);
			pthread_mutex_unlock(&change_lock);
		}
		ok = tlr.ok;
		error = tlr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &tlr.trace.v, &tlr.trace.n);
		rc = arc_tls_reply(j->req, &tlr);
		break;
	case ARC_CMD_CAPTURE:
		what = wfmt(&w, "capture %s%s%s", j->ref != NULL ? j->ref :
		    "sources", j->jail != NULL ? " in " : "", j->jail != NULL ?
		    j->jail : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "%s", what);
		memset(&capq, 0, sizeof(capq));
		memset(&capr, 0, sizeof(capr));
		capr.has_ok = true;
		capq.interface = j->ref;
		capq.net_filter = j->sha256;
		capq.has_seconds = j->fib > 0;
		capq.seconds = j->fib;
		capq.has_packets = j->offset > 0;
		capq.packets = j->offset;
		if (scope_enter(&w, j->jail, &capr.error) == 0)
			do_capture(&w, &capq, &capr);
		ok = capr.ok;
		error = capr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &capr.trace.v, &capr.trace.n);
		rc = arc_capture_reply(j->req, &capr);
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
	case ARC_CMD_JAIL_FILES:
		what = "jail files";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "jail files");
		memset(&jfr, 0, sizeof(jfr));
		do_jail_files(&w, &jfr);
		ok = jfr.ok;
		error = jfr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &jfr.trace.v, &jfr.trace.n);
		rc = arc_jail_files_reply(j->req, &jfr);
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
	case ARC_CMD_KERNEL:
		what = "kernel";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "kernel");
		memset(&kr, 0, sizeof(kr));
		do_kernel(&w, &kr);
		ok = kr.ok;
		error = kr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &kr.trace.v, &kr.trace.n);
		rc = arc_kernel_reply(j->req, &kr);
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
	case ARC_CMD_TRACEROUTE:
		what = wfmt(&w, "traceroute to %s", j->source);
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&trr, 0, sizeof(trr));
		do_traceroute(&w, j->source, &trr);
		ok = trr.ok;
		error = trr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &trr.trace.v, &trr.trace.n);
		rc = arc_traceroute_reply(j->req, &trr);
		break;
	case ARC_CMD_SDWAN_PROBES:
		what = "sdwan probes";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&spr, 0, sizeof(spr));
		error = NULL;
		ok = do_probes_set(&w, j->ref, &error) == 0;
		spr.has_ok = true;
		spr.ok = ok;
		spr.error = error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &spr.trace.v, &spr.trace.n);
		rc = arc_sdwan_probes_reply(j->req, &spr);
		break;
	case ARC_CMD_SDWAN_RULES:
		what = "sdwan rules";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&srr, 0, sizeof(srr));
		error = NULL;
		ok = do_sdwan_rules(&w, j->ref, &error) == 0;
		srr.has_ok = true;
		srr.ok = ok;
		srr.error = error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &srr.trace.v, &srr.trace.n);
		rc = arc_sdwan_rules_reply(j->req, &srr);
		break;
	case ARC_CMD_SDWAN_STEER:
		what = "sdwan steer";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&sstr, 0, sizeof(sstr));
		error = NULL;
		ok = do_sdwan_steer(&w, j->ref, &error) == 0;
		sstr.has_ok = true;
		sstr.ok = ok;
		sstr.error = error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sstr.trace.v, &sstr.trace.n);
		rc = arc_sdwan_steer_reply(j->req, &sstr);
		break;
	case ARC_CMD_SDWAN_BIRD:
		what = "sdwan bird";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&sbr, 0, sizeof(sbr));
		error = NULL;
		ok = do_sdwan_bird(&w, j->ref, &error) == 0;
		sbr.has_ok = true;
		sbr.ok = ok;
		sbr.error = error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sbr.trace.v, &sbr.trace.n);
		rc = arc_sdwan_bird_reply(j->req, &sbr);
		break;
	case ARC_CMD_SDWAN_DHCP:
		what = "sdwan dhcp";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&sdhr, 0, sizeof(sdhr));
		error = NULL;
		ok = do_sdwan_dhcp(&w, j->ref, &error) == 0;
		sdhr.has_ok = true;
		sdhr.ok = ok;
		sdhr.error = error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sdhr.trace.v, &sdhr.trace.n);
		rc = arc_sdwan_dhcp_reply(j->req, &sdhr);
		break;
	case ARC_CMD_SDWAN_DNS:
		what = "sdwan dns";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&sdnr, 0, sizeof(sdnr));
		error = NULL;
		ok = do_sdwan_dns(&w, j->ref, &error) == 0;
		sdnr.has_ok = true;
		sdnr.ok = ok;
		sdnr.error = error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sdnr.trace.v, &sdnr.trace.n);
		rc = arc_sdwan_dns_reply(j->req, &sdnr);
		break;
	case ARC_CMD_SDWAN_PROXY:
		what = "sdwan proxy";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&sdpr, 0, sizeof(sdpr));
		error = NULL;
		ok = do_sdwan_proxy(&w, j->ref, &error) == 0;
		sdpr.has_ok = true;
		sdpr.ok = ok;
		sdpr.error = error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sdpr.trace.v, &sdpr.trace.n);
		rc = arc_sdwan_proxy_reply(j->req, &sdpr);
		break;
	case ARC_CMD_SDWAN_IDS:
		what = "sdwan ids";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&sdir, 0, sizeof(sdir));
		error = NULL;
		ok = do_sdwan_ids(&w, j->ref, &error) == 0;
		sdir.has_ok = true;
		sdir.ok = ok;
		sdir.error = error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sdir.trace.v, &sdir.trace.n);
		rc = arc_sdwan_ids_reply(j->req, &sdir);
		break;
	case ARC_CMD_SDWAN:
		what = "sdwan";
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&sdr, 0, sizeof(sdr));
		do_sdwan(&w, j->pos, &sdr);
		ok = sdr.ok;
		error = sdr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sdr.trace.v, &sdr.trace.n);
		rc = arc_sdwan_reply(j->req, &sdr);
		break;
	case ARC_CMD_SERVICES:
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "services");
		what = "services";
		memset(&sr, 0, sizeof(sr));
		do_services(&w, &sr);
		ok = sr.ok;
		error = sr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sr.trace.v, &sr.trace.n);
		rc = arc_services_reply(j->req, &sr);
		break;
	case ARC_CMD_SERVICE_ACTION:
		what = wfmt(&w, "service %s %s", j->jail,
		    service_action_names[j->action]);
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&sar, 0, sizeof(sar));
		pthread_mutex_lock(&change_lock);
		if (change_note("%s", what))
			do_service_action(&w, j->jail, j->action, &sar);
		else {
			sar.has_ok = true;
			sar.error = STOPPING;
		}
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		ok = sar.ok;
		error = sar.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &sar.trace.v, &sar.trace.n);
		rc = arc_service_action_reply(j->req, &sar);
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
		    j->ssh_key, &abr);
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
	case ARC_CMD_SOURCE_LOG:
		what = wfmt(&w, "source log of %s%s%s", j->source,
		    j->ref != NULL ? " at " : "", j->ref != NULL ? j->ref : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&slr, 0, sizeof(slr));
		pthread_mutex_lock(&build_lock);
		do_source_log(&w, j->source, j->ref, j->host_keys, j->ssh_key,
		    j->log_count, &slr);
		pthread_mutex_unlock(&build_lock);
		ok = slr.ok;
		error = slr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &slr.trace.v, &slr.trace.n);
		rc = arc_source_log_reply(j->req, &slr);
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
				    j->sha256, &aur);
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
	case ARC_CMD_BIRD_CONFIG:
		/* The path rides in source, the text in ref. */
		what = wfmt(&w, "bird config %s%s", j->config_only ? "confirm" :
		    j->ref == NULL ? "read" : j->refresh ? "check" : j->restart ?
		    "write (safe)" : "write", j->source != NULL ? " " : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s%s",
		    what, j->source != NULL ? j->source : "");
		memset(&bcq, 0, sizeof(bcq));
		memset(&bcr, 0, sizeof(bcr));
		bcq.conf_path = j->source;
		bcq.conf_text = j->ref;
		bcq.sha256 = j->sha256;
		bcq.dry_run = j->refresh;
		bcq.safe = j->restart;
		bcq.confirm = j->config_only;
		bcq.has_safe_wait = j->safe_wait > 0;
		bcq.safe_wait = (uint32_t)j->safe_wait;
		bcr.has_ok = true;
		if (scope_enter(&w, j->jail, &bcr.error) != 0)
			;
		else if (j->ref == NULL && !bcq.confirm)
			do_bird_config(&w, &bcq, &bcr);
		else {
			pthread_mutex_lock(&change_lock);
			if (change_note("%s", what))
				do_bird_config(&w, &bcq, &bcr);
			else {
				bcr.has_ok = true;
				bcr.error = STOPPING;
			}
			(void)change_note(NULL);
			pthread_mutex_unlock(&change_lock);
		}
		ok = bcr.ok;
		error = bcr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &bcr.trace.v, &bcr.trace.n);
		rc = arc_bird_config_reply(j->req, &bcr);
		break;
	case ARC_CMD_SERVICE_CONFIG:
		what = wfmt(&w, "service %s config%s", j->jail,
		    j->svc.variables.n > 0 ? " (set)" : "");
		root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
		    what);
		memset(&scr, 0, sizeof(scr));
		pthread_mutex_lock(&change_lock);
		if (change_note("%s", what))
			do_service_config(&w, &j->svc, &scr);
		else {
			scr.has_ok = true;
			scr.error = STOPPING;
		}
		(void)change_note(NULL);
		pthread_mutex_unlock(&change_lock);
		ok = scr.ok;
		error = scr.error;
		step_end(&w, root, ok, NULL);
		trace_steps(&w, &scr.trace.v, &scr.trace.n);
		rc = arc_service_config_reply(j->req, &scr);
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
	/* The console's own service, once it has its answer; then ours. */
	if (console)
		service_restart("arcana_console");
	if (restart) {
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
	return (NULL);
}

static void
job_free(struct job *j)
{
	size_t	i;

	for (i = 0; i < j->svc.variables.n; i++) {
		free((char *)(uintptr_t)j->svc.variables.v[i].key);
		free((char *)(uintptr_t)j->svc.variables.v[i].value);
	}
	free((void *)(uintptr_t)j->svc.variables.v);
	for (i = 0; i < j->pkg.names.n; i++)
		free((char *)(uintptr_t)j->pkg.names.v[i]);
	free((void *)(uintptr_t)j->pkg.names.v);
	free(j->jail);
	free(j->binary);
	free(j->sha256);
	free(j->source);
	free(j->listen);
	free(j->unlisten);
	free(j->sctp_also);
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
	free(j->bundle);
	free(j->new_host);
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
	if ((error = cbl_req_defer(j->req)) != 0)
		return (error);
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
arc_list_doit(cbl_req *req, const struct arc_list_req *rq, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_LIST;
	j->config_only = rq->config_only;
	return (start(j));
}

int
arc_action_doit(cbl_req *req, const struct arc_action_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (!valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if (rq->action >= nitems(action_names))
		return (reject(req, "invalid action"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_ACTION;
	j->jail = xstrdup(rq->jail);
	j->action = rq->action;
	return (start(j));
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
arc_services_doit(cbl_req *req, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SERVICES;
	return (start(j));
}

int
arc_service_action_doit(cbl_req *req, const struct arc_service_action_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (!valid_service(rq->service))
		return (reject(req, "invalid service name"));
	if (rq->service_action >= nitems(service_action_names))
		return (reject(req, "invalid action"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SERVICE_ACTION;
	j->jail = xstrdup(rq->service);
	j->action = rq->service_action;
	return (start(j));
}

int
arc_agent_build_doit(cbl_req *req, const struct arc_agent_build_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_AGENT_BUILD;
	j->source = xstrdup(rq->source);
	j->ref = rq->ref != NULL && rq->ref[0] != '\0' ? xstrdup(rq->ref) :
	    NULL;
	j->host_keys = rq->host_keys != NULL ? xstrdup(rq->host_keys) : NULL;
	j->ssh_key = rq->ssh_key != NULL ? xstrdup(rq->ssh_key) : NULL;
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
arc_source_log_doit(cbl_req *req, const struct arc_source_log_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SOURCE_LOG;
	j->source = xstrdup(rq->source);
	j->ref = rq->ref != NULL && rq->ref[0] != '\0' ? xstrdup(rq->ref) :
	    NULL;
	j->host_keys = rq->host_keys != NULL ? xstrdup(rq->host_keys) : NULL;
	j->ssh_key = rq->ssh_key != NULL ? xstrdup(rq->ssh_key) : NULL;
	j->log_count = rq->has_count ? rq->count : 0;
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

	if (rq->binary.len == 0 || strlen(rq->sha256) != 64)
		return (reject(req, "a program and its SHA-256 are needed"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_AGENT_UPDATE;
	if ((j->binary = malloc(rq->binary.len)) == NULL)
		err(1, "malloc");
	memcpy(j->binary, rq->binary.p, rq->binary.len);
	j->binlen = rq->binary.len;
	j->sha256 = xstrdup(rq->sha256);
	j->restart = rq->restart;
	return (start(j));
}

int
arc_service_config_doit(cbl_req *req, const struct arc_service_config_req *rq,
    void *arg __unused)
{
	struct arc_variable	*v;
	struct job		*j;
	size_t			 i;

	if (!valid_service(rq->service))
		return (reject(req, "invalid service name"));
	for (i = 0; i < rq->variables.n; i++)
		if (rq->variables.v[i].key == NULL)
			return (reject(req, "a variable without a key"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SERVICE_CONFIG;
	j->jail = xstrdup(rq->service);
	j->svc.service = j->jail;
	if (rq->variables.n > 0) {
		if ((v = calloc(rq->variables.n, sizeof(*v))) == NULL)
			err(1, "calloc");
		for (i = 0; i < rq->variables.n; i++) {
			v[i].key = xstrdup(rq->variables.v[i].key);
			v[i].value = xstrdup(rq->variables.v[i].value);
			v[i].remove = rq->variables.v[i].remove;
		}
		j->svc.variables.v = v;
		j->svc.variables.n = rq->variables.n;
	}
	return (start(j));
}

int
arc_network_doit(cbl_req *req, const struct arc_network_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->net_kind >= nitems(net_kind_names))
		return (reject(req, "invalid kind"));
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
arc_traceroute_doit(cbl_req *req, const struct arc_traceroute_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->lookup == NULL || rq->lookup[0] == '-' || rq->lookup[strspn(
	    rq->lookup, "0123456789abcdefABCDEF.:")] != '\0')
		return (reject(req, "an address to trace the route to is "
		    "needed"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_TRACEROUTE;
	j->source = xstrdup(rq->lookup);
	return (start(j));
}

int
arc_sdwan_probes_doit(cbl_req *req, const struct arc_sdwan_probes_req *rq,
    void *arg __unused)
{
	struct job	*j;

	/* An array, the host's; {"jail", "targets"}, a jail's. */
	if (rq->json == NULL || (rq->json[0] != '[' && rq->json[0] != '{'))
		return (reject(req, "the targets are a JSON array"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SDWAN_PROBES;
	j->ref = xstrdup(rq->json);
	return (start(j));
}

int
arc_sdwan_rules_doit(cbl_req *req, const struct arc_sdwan_rules_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->json == NULL || rq->json[0] != '{')
		return (reject(req, "the rules are a JSON object"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SDWAN_RULES;
	j->ref = xstrdup(rq->json);
	return (start(j));
}

int
arc_sdwan_steer_doit(cbl_req *req, const struct arc_sdwan_steer_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->json == NULL || rq->json[0] != '{')
		return (reject(req, "the steering is a JSON object"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SDWAN_STEER;
	j->ref = xstrdup(rq->json);
	return (start(j));
}

int
arc_sdwan_bird_doit(cbl_req *req, const struct arc_sdwan_bird_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->json == NULL || rq->json[0] != '{')
		return (reject(req, "the instances are a JSON object"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SDWAN_BIRD;
	j->ref = xstrdup(rq->json);
	return (start(j));
}

int
arc_sdwan_dhcp_doit(cbl_req *req, const struct arc_sdwan_dhcp_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->json == NULL || rq->json[0] != '{')
		return (reject(req, "the instances are a JSON object"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SDWAN_DHCP;
	j->ref = xstrdup(rq->json);
	return (start(j));
}

int
arc_sdwan_ids_doit(cbl_req *req, const struct arc_sdwan_ids_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->json == NULL || rq->json[0] != '{')
		return (reject(req, "the instances are a JSON object"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SDWAN_IDS;
	j->ref = xstrdup(rq->json);
	return (start(j));
}

int
arc_sdwan_proxy_doit(cbl_req *req, const struct arc_sdwan_proxy_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->json == NULL || rq->json[0] != '{')
		return (reject(req, "the instances are a JSON object"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SDWAN_PROXY;
	j->ref = xstrdup(rq->json);
	return (start(j));
}

int
arc_sdwan_dns_doit(cbl_req *req, const struct arc_sdwan_dns_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->json == NULL || rq->json[0] != '{')
		return (reject(req, "the instances are a JSON object"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SDWAN_DNS;
	j->ref = xstrdup(rq->json);
	return (start(j));
}

int
arc_sdwan_doit(cbl_req *req, const struct arc_sdwan_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SDWAN;
	j->pos = rq->has_after ? rq->after : 0;
	return (start(j));
}

int
arc_bird_config_doit(cbl_req *req, const struct arc_bird_config_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->conf_path != NULL && rq->conf_path[0] != '\0' &&
	    rq->conf_path[0] != '/')
		return (reject(req, "a configuration file is named by its "
		    "whole path"));
	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_BIRD_CONFIG;
	j->source = rq->conf_path != NULL && rq->conf_path[0] != '\0' ?
	    xstrdup(rq->conf_path) : NULL;
	j->ref = rq->conf_text != NULL ? xstrdup(rq->conf_text) : NULL;
	j->sha256 = rq->sha256 != NULL ? xstrdup(rq->sha256) : NULL;
	j->refresh = rq->dry_run;
	/* Safe rides where a restart does, confirm where config-only. */
	j->restart = rq->safe;
	j->config_only = rq->confirm;
	j->safe_wait = rq->has_safe_wait ? (int)rq->safe_wait : 0;
	j->jail = rq->jail != NULL && rq->jail[0] != '\0' ? xstrdup(rq->jail) :
	    NULL;
	return (start(j));
}

int
arc_storage_doit(cbl_req *req, const struct arc_storage_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->storage_kind > ARC_STORAGE_KIND_HEALTH)
		return (reject(req, "no such kind of storage"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_STORAGE;
	j->action = rq->storage_kind;
	if (rq->jail != NULL && rq->jail[0] != '\0') {
		if (!valid_jail(rq->jail)) {
			free(j);
			return (reject(req, "invalid jail name"));
		}
		j->jail = xstrdup(rq->jail);
	}
	j->source = rq->net_filter != NULL && rq->net_filter[0] != '\0' ?
	    xstrdup(rq->net_filter) : NULL;
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

int
arc_path_check_doit(cbl_req *req, const struct arc_path_check_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_PATH_CHECK;
	j->psrc = xstrdup(rq->path_src);
	j->pdst = xstrdup(rq->path_dst);
	j->pproto = rq->path_proto != NULL ? xstrdup(rq->path_proto) : NULL;
	j->piface = rq->interface != NULL ? xstrdup(rq->interface) : NULL;
	j->pport = rq->has_path_port ? rq->path_port : 0;
	j->preply = rq->path_reply;
	j->has_fib = rq->has_net_fib;
	j->fib = rq->has_net_fib ? rq->net_fib : 0;
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

int
arc_config_export_doit(cbl_req *req, const struct arc_config_export_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_CONFIG_EXPORT;
	j->refresh = rq->secrets;
	return (start(j));
}

int
arc_config_apply_doit(cbl_req *req, const struct arc_config_apply_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_CONFIG_APPLY;
	j->bundle = xstrdup(rq->bundle);
	j->refresh = rq->dry_run;
	j->anyway = rq->anyway;
	j->new_host = rq->new_hostname != NULL ? xstrdup(rq->new_hostname) :
	    NULL;
	return (start(j));
}

int
arc_transport_doit(cbl_req *req, const struct arc_transport_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_TRANSPORT;
	j->refresh = rq->retry;
	j->listen = rq->listen != NULL && rq->listen[0] != '\0' ?
	    xstrdup(rq->listen) : NULL;
	j->unlisten = rq->unlisten != NULL && rq->unlisten[0] != '\0' ?
	    xstrdup(rq->unlisten) : NULL;
	j->listen_keep = rq->listen_keep;
	j->sctp_also = rq->sctp_also != NULL ? xstrdup(rq->sctp_also) : NULL;
	return (start(j));
}

int
arc_sysctl_doit(cbl_req *req, const struct arc_sysctl_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_SYSCTL;
	j->source = rq->net_filter != NULL && rq->net_filter[0] != '\0' ?
	    xstrdup(rq->net_filter) : NULL;
	/* A vnet jail's network's, as its sysctl reads them. */
	if (rq->jail != NULL && rq->jail[0] != '\0') {
		if (!valid_jail(rq->jail)) {
			free(j->source);
			free(j);
			return (reject(req, "invalid jail name"));
		}
		if (j->source == NULL || strncmp(j->source, "net.", 4) != 0) {
			free(j->source);
			free(j);
			return (reject(req, "a jail's sysctls are read under its "
			    "network's, net."));
		}
		j->jail = xstrdup(rq->jail);
	}
	return (start(j));
}

int
arc_processes_doit(cbl_req *req, const struct arc_processes_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_PROCESSES;
	j->jail = rq->jail != NULL && rq->jail[0] != '\0' ? xstrdup(rq->jail) :
	    NULL;
	j->fib = rq->has_pid ? rq->pid : 0;
	return (start(j));
}

int
arc_log_doit(cbl_req *req, const struct arc_log_req *rq, void *arg __unused)
{
	struct job	*j;

	if (rq->log_name != NULL && rq->log_name[0] != '\0' &&
	    rq->log_name[0] != '@' && !log_name_ok(rq->log_name))
		return (reject(req, "a log is named with letters, digits "
		    "and . _ -"));
	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_LOG;
	j->jail = rq->jail != NULL && rq->jail[0] != '\0' ? xstrdup(rq->jail) :
	    NULL;
	j->ref = rq->log_name != NULL && rq->log_name[0] != '\0' ?
	    xstrdup(rq->log_name) : NULL;
	j->source = rq->net_filter != NULL && rq->net_filter[0] != '\0' ?
	    xstrdup(rq->net_filter) : NULL;
	j->has_pos = rq->has_position;
	j->pos = rq->position;
	j->offset = rq->has_lines ? rq->lines : 0;
	return (start(j));
}

int
arc_fw_trace_doit(cbl_req *req, const struct arc_fw_trace_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if (rq->net_filter == NULL || strlen(rq->net_filter) > 64)
		return (reject(req, "the address to follow is an IPv4 or IPv6 "
		    "address"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_FW_TRACE;
	j->jail = rq->jail != NULL && rq->jail[0] != '\0' ? xstrdup(rq->jail) :
	    NULL;
	j->source = xstrdup(rq->net_filter);
	j->fib = rq->has_seconds ? rq->seconds : 0;
	j->offset = rq->has_packets ? rq->packets : 0;
	return (start(j));
}

int
arc_history_doit(cbl_req *req, const struct arc_history_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->has_sample_step != rq->has_sample_keep)
		return (reject(req, "how to sample is both: every how many "
		    "seconds, and how many are kept"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_HISTORY;
	j->pos = rq->has_after ? rq->after : 0;
	j->refresh = rq->has_sample_step;
	j->fib = rq->sample_step;
	j->offset = rq->sample_keep;
	j->restart = rq->has_limit_cpu && rq->has_limit_mem &&
	    rq->has_limit_swap;
	j->lim[0] = rq->limit_cpu;
	j->lim[1] = rq->limit_mem;
	j->lim[2] = rq->limit_swap;
	/* Not said: as it was. */
	j->lim[3] = rq->has_limit_storage ? rq->limit_storage : UINT32_MAX;
	/* The rules ride in source; empty takes them all away. */
	j->source = j->refresh && rq->limit_rules != NULL ?
	    xstrdup(rq->limit_rules) : NULL;
	return (start(j));
}

int
arc_events_doit(cbl_req *req, const struct arc_events_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_EVENTS;
	j->pos = rq->has_after ? rq->after : 0;
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

/*
 * The kernel's state in parts: one for each call, in the loop's own
 * thread, which a part is short enough for.
 */
int
arc_sysctl_dumpit(cbl_req *req, const struct arc_sysctl_dump_req *rq,
    struct cbl_dump_state *st, void *arg __unused)
{
	struct arc_sysctl_dump_rsp	 rsp;
	char				*json;
	uint64_t			 sent;
	bool				 more;
	int				 error;

	if (rq->net_filter != NULL && rq->net_filter[0] != '\0' &&
	    !sysctl_name_ok(rq->net_filter))
		return (reject(req, "a sysctl is named with letters, digits "
		    "and . _ - %"));
	more = sysctl_part(st, rq->net_filter, &json, &sent);
	if (json == NULL)
		return (ENOMEM);
	memset(&rsp, 0, sizeof(rsp));
	rsp.json = json;
	rsp.has_total = true;
	rsp.total = sent;
	error = arc_sysctl_dump_reply(req, &rsp);
	free(json);
	if (error != 0)
		return (error);
	return (more ? EAGAIN : 0);
}

int
arc_fstab_doit(cbl_req *req, const struct arc_fstab_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_FSTAB;
	j->ref = rq->conf_text != NULL ? xstrdup(rq->conf_text) : NULL;
	j->sha256 = rq->sha256 != NULL ? xstrdup(rq->sha256) : NULL;
	j->refresh = rq->dry_run;
	return (start(j));
}

int
arc_kernel_doit(cbl_req *req, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_KERNEL;
	return (start(j));
}

int
arc_certs_doit(cbl_req *req, const struct arc_certs_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_CERTS;
	j->jail = rq->jail != NULL && rq->jail[0] != '\0' ? xstrdup(rq->jail) :
	    NULL;
	return (start(j));
}

int
arc_zfs_key_doit(cbl_req *req, const struct arc_zfs_key_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_ZFS_KEY;
	j->sha256 = xstrdup(rq->zfs_dataset);
	j->source = rq->zfs_key != NULL ? xstrdup(rq->zfs_key) : NULL;
	j->ref = rq->zfs_new_key != NULL ? xstrdup(rq->zfs_new_key) : NULL;
	return (start(j));
}

int
arc_tls_doit(cbl_req *req, const struct arc_tls_req *rq, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_TLS;
	j->sha256 = xstrdup(rq->tls_verb);
	j->source = rq->tls_cert != NULL ? xstrdup(rq->tls_cert) : NULL;
	j->ref = rq->tls_ca != NULL ? xstrdup(rq->tls_ca) : NULL;
	j->host_keys = rq->tls_peer != NULL ? xstrdup(rq->tls_peer) : NULL;
	return (start(j));
}

int
arc_capture_doit(cbl_req *req, const struct arc_capture_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_CAPTURE;
	j->jail = rq->jail != NULL && rq->jail[0] != '\0' ? xstrdup(rq->jail) :
	    NULL;
	/* The source rides in ref, the filter in sha256. */
	j->ref = rq->interface != NULL && rq->interface[0] != '\0' ?
	    xstrdup(rq->interface) : NULL;
	j->sha256 = rq->net_filter != NULL ? xstrdup(rq->net_filter) : NULL;
	/* As fw-trace's: seconds in fib, packets in offset. */
	j->fib = rq->has_seconds ? rq->seconds : 0;
	j->offset = rq->has_packets ? rq->packets : 0;
	return (start(j));
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
arc_jail_files_doit(cbl_req *req, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_JAIL_FILES;
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

int
arc_stats_doit(cbl_req *req, void *arg __unused)
{
	struct job	*j;

	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_STATS;
	return (start(j));
}

int
arc_packages_doit(cbl_req *req, const struct arc_packages_req *rq,
    void *arg __unused)
{
	struct job	*j;

	if (rq->jail != NULL && !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_PACKAGES;
	j->jail = xstrdup(rq->jail);
	j->refresh = rq->refresh;
	j->installed = rq->pkg_installed;
	j->pkg_ip = rq->has_pkg_ip ? rq->pkg_ip : 0;
	return (start(j));
}

int
arc_pkg_upgrade_doit(cbl_req *req, const struct arc_pkg_upgrade_req *rq,
    void *arg __unused)
{
	struct job	*j;
	const char	**v;
	size_t		 i;

	if (rq->jail != NULL && strcmp(rq->jail, "*") != 0 &&
	    !valid_jail(rq->jail))
		return (reject(req, "invalid jail name"));
	for (i = 0; i < rq->names.n; i++)
		if (rq->names.v[i] == NULL)
			return (reject(req, "a package without a name"));
	if ((j = calloc(1, sizeof(*j))) == NULL)
		return (ENOMEM);
	j->req = req;
	j->cmd = ARC_CMD_PKG_UPGRADE;
	j->jail = xstrdup(rq->jail);
	j->pkg.jail = j->jail;
	j->pkg.dry_run = rq->dry_run;
	j->pkg.has_ignore_osversion = rq->has_ignore_osversion;
	j->pkg.ignore_osversion = rq->ignore_osversion;
	j->pkg.has_pkg_ip = rq->has_pkg_ip;
	j->pkg.pkg_ip = rq->pkg_ip;
	if (rq->names.n > 0) {
		if ((v = calloc(rq->names.n, sizeof(*v))) == NULL)
			err(1, "calloc");
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

	if (!sp->has_kind || sp->kind > ARC_JOB_KIND_POUDRIERE)
		return ("a job needs a kind");
	/* For what changes a network, jail is the jail whose it is. */
	if (sp->kind >= ARC_JOB_KIND_IF_ADDRESS && sp->jail != NULL &&
	    sp->jail[0] != '\0' && !valid_jail(sp->jail))
		return ("invalid jail name");
	switch (sp->kind) {
	case ARC_JOB_KIND_JAIL_ACTION:
		if (sp->jail == NULL || !valid_jail(sp->jail))
			return ("invalid jail name");
		if (!sp->has_action || sp->action >= nitems(action_names))
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
		if (sp->safe)
			return ("it is not taken back by itself");
		if ((e = l2_check(sp)) != NULL)
			return (e);
		break;
	case ARC_JOB_KIND_PROCESS:
		if ((e = proc_check(sp)) != NULL)
			return (e);
		break;
	case ARC_JOB_KIND_IPSEC:
		if (sp->safe)
			return ("IPsec changes are not undone: not in safe mode");
		return (ipsec_check(sp));
	case ARC_JOB_KIND_IPSEC_SA:
		if (sp->safe)
			return ("security associations are not undone: not in "
			    "safe mode");
		return (sa_check(sp));
	case ARC_JOB_KIND_PKG_INSTALL:
		if (sp->safe)
			return ("an install is not taken back by itself");
		if (sp->names.n == 0)
			return ("name the packages to install");
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
		if (sp->safe)
			return ("a sysctl is not taken back by itself");
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
		if (sp->safe)
			return ("an interface destroyed cannot be made again "
			    "as it was: not in safe mode");
		break;
	case ARC_JOB_KIND_NETGRAPH:
		if (sp->safe)
			return ("netgraph changes cannot be undone: not in "
			    "safe mode");
		return (ng_check(sp->verb, sp->names.v, sp->names.n));
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
	case ARC_JOB_KIND_WIREGUARD:
		if (sp->safe)
			return ("wireguard changes are not undone: not in "
			    "safe mode");
		if (sp->interface == NULL || !valid_ifname(sp->interface))
			return ("invalid interface name");
		work_init(&cw);
		e = wg_check(&cw, sp);
		work_free(&cw);
		return (e);
	case ARC_JOB_KIND_BIRD:
		if (sp->safe)
			return ("what BIRD was told is not taken back: not in "
			    "safe mode");
		return (bird_check(sp->verb, sp->names.v, sp->names.n));
	case ARC_JOB_KIND_ROUTE:
		if (sp->destination == NULL || sp->destination[0] == '\0' ||
		    sp->destination[0] == '-')
			return ("a route needs a destination");
		if (sp->safe && sp->remove && (sp->gateway == NULL ||
		    sp->gateway[0] == '\0'))
			return ("to delete a route safely, name its gateway: "
			    "it is what puts the route back");
		if (sp->gateway != NULL && sp->gateway[0] == '-')
			return ("invalid gateway");
		if (sp->source != NULL && sp->source[strspn(sp->source,
		    "0123456789abcdefABCDEF.:")] != '\0')
			return ("the address to send from is an address");
		if (!sp->remove && (sp->gateway == NULL ||
		    sp->gateway[0] == '\0'))
			return ("a route to add needs a gateway");
		break;
	case ARC_JOB_KIND_SERVICE_ACTION:
		if (sp->service == NULL || !valid_service(sp->service))
			return ("invalid service name");
		if (!sp->has_service_action ||
		    sp->service_action >= nitems(service_action_names))
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
	if (sp->safe)
		return (NULL);
	if (sp->kind == ARC_JOB_KIND_IF_VNET) {
		if (sp->remove)
			return (NULL);
	} else if ((sp->jail != NULL && sp->jail[0] != '\0') ||
	    (sp->kind != ARC_JOB_KIND_IF_ADDRESS && sp->kind !=
	    ARC_JOB_KIND_IF_STATE && sp->kind != ARC_JOB_KIND_IF_DESTROY))
		return (NULL);
	len = sizeof(ss);
	if ((fd = cbl_conn_fd(cbl_req_conn(req))) == -1 || getsockname(fd,
	    (struct sockaddr *)&ss, &len) == -1 || (ss.ss_family != AF_INET &&
	    ss.ss_family != AF_INET6) || !if_owning((struct sockaddr *)&ss,
	    ifname, sizeof(ifname)))
		return (NULL);
	hit = false;
	if (sp->kind == ARC_JOB_KIND_IF_ADDRESS) {
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

/* Jobs are queued, listed and read on the loop: none of it waits. */
int
arc_job_submit_doit(cbl_req *req, const struct arc_job_submit_req *rq,
    void *arg __unused)
{
	struct arc_job_submit_rsp	 rsp;
	struct work			 w;
	const char			*e;
	char				*peer;
	size_t				 i;
	int				 error;

	for (i = 0; i < rq->batch.n; i++)
		if ((e = check_spec(&rq->batch.v[i])) != NULL ||
		    (e = cuts_off(req, &rq->batch.v[i])) != NULL)
			return (reject(req, e));
	if (jobs_waiting() + rq->batch.n > JOBS_WAITING_MAX)
		return (reject(req, "too many jobs wait already: let some "
		    "finish, or cancel them"));
	work_init(&w);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	peer = peer_name(req);
	jobs_submit(rq->batch.v, rq->batch.n, peer, &w, &rsp.jobs.v,
	    &rsp.jobs.n);
	free(peer);
	error = arc_job_submit_reply(req, &rsp);
	work_free(&w);
	return (error);
}

int
arc_jobs_doit(cbl_req *req, void *arg __unused)
{
	struct arc_jobs_rsp	rsp;
	struct work		w;
	time_t			since;
	int			error;

	work_init(&w);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	jobs_list(&w, &rsp.jobs.v, &rsp.jobs.n);
	if ((rsp.activity = changes_current(&w, &since)) != NULL) {
		rsp.has_since = true;
		rsp.since = since;
	}
	rsp.stopping = changes_stopping();
	error = arc_jobs_reply(req, &rsp);
	work_free(&w);
	return (error);
}

int
arc_job_doit(cbl_req *req, const struct arc_job_req *rq, void *arg __unused)
{
	struct arc_job_rsp	rsp;
	struct work		w;
	int			error;

	work_init(&w);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.job = jobs_get(&w, rq->id);
	rsp.ok = rsp.job != NULL;
	if (!rsp.ok)
		rsp.error = "no such job; the daemon keeps the last finished "
		    "ones and forgets all when it restarts";
	error = arc_job_reply(req, &rsp);
	work_free(&w);
	return (error);
}

int
arc_job_confirm_doit(cbl_req *req, const struct arc_job_confirm_req *rq,
    void *arg __unused)
{
	struct arc_job_confirm_rsp	rsp;
	struct work			w;
	int				error;

	work_init(&w);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.job = jobs_confirm(&w, rq->id, &rsp.error);
	rsp.ok = rsp.job != NULL;
	if (rsp.ok)
		rsp.error = NULL;
	error = arc_job_confirm_reply(req, &rsp);
	work_free(&w);
	return (error);
}

int
arc_job_cancel_doit(cbl_req *req, const struct arc_job_cancel_req *rq,
    void *arg __unused)
{
	struct arc_job_cancel_rsp	rsp;
	struct work			w;
	int				error;

	work_init(&w);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.job = jobs_cancel(&w, rq->id, &rsp.error);
	rsp.ok = rsp.job != NULL;
	if (rsp.ok)
		rsp.error = NULL;
	error = arc_job_cancel_reply(req, &rsp);
	work_free(&w);
	return (error);
}
