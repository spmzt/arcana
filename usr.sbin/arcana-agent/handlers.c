/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What the models' handlers share: the names a request may give (a
 * jail's, an interface's, a service's), the lock that runs changes one
 * at a time and what holds it, a job's spec checked before it is
 * queued, and the restart after an update.
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

static char	*peer_name(cbl_req *);
static char	*xstrdup(const char *);
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
	jobs_submit(specs, n, peer, cbl_req_user(req), w, v, nv);
	free(peer);
	return (0);
}

/*
 * The same batch run dry (jobs_dry_run()), refused as submit would
 * refuse it: its steps w's trace, *notesp what they do not say.
 * arcana-jobs' dry-run's (yarcana.c).
 */
int
jobs_dry_checked(cbl_req *req, const struct arc_job_spec *specs, size_t n,
    struct work *w, const char ***notesp, size_t *nnotesp, const char **errp)
{
	size_t	i;

	for (i = 0; i < n; i++)
		if ((*errp = check_spec(&specs[i])) != NULL ||
		    (*errp = cuts_off(req, &specs[i])) != NULL)
			return (-1);
	return (jobs_dry_run(specs, n, w, notesp, nnotesp, errp));
}
