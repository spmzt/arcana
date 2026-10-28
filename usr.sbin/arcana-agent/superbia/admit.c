/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: who may ask, and what.  A host's certificate is for a server
 * and a client both, so that hosts can reach each other (the mesh), and
 * it says so: a SAN URI urn:arcana:role:agent.  A peer that shows one is
 * another host, and asks nothing here but the mesh's, which there is
 * none of yet: it is refused.  The console's own certificate may say
 * urn:arcana:role:console; one from before the roles says nothing, and
 * is taken as the console's.
 *
 * What a request may do is NACM's (RFC 8341), as cblink checks it
 * (ynacm.c has the rules): its user is the one the console says it asks
 * for, the console's own requests user "console"; root, or the user the
 * agent runs as, on the unix socket is the recovery session, which may
 * say a user too (who can write the rules' file needs no rule); another
 * local user is its login name.  Every command of the family is an rpc
 * of module "arcana"; those that change the host, or give out what
 * should stay on it, are as nacm:default-deny-all marks them: run only
 * by a rule that permits them.
 */

#include <sys/param.h>

#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "agent.h"

#define	ROLE_AGENT	"URI:urn:arcana:role:agent"

static struct cbl_op		*ops;
static struct cbl_family_def	 def;

/* The commands that change the host, or give out a packet capture, its
 * whole configuration or a dataset. */
static const char *const changes[] = {
	"action", "address", "service-action", "service-config",
	"pkg-upgrade", "job-submit", "jobs-set", "job-cancel", "job-confirm",
	"agent-update", "agent-build", "console-update", "bird-config",
	"fstab", "ipfw-rules", "zfs-receive", "sdwan-probes", "sdwan-rules",
	"sdwan-steer", "sdwan-bird", "sdwan-dhcp", "sdwan-dns", "sdwan-proxy",
	"sdwan-ids", "zfs-key", "tls", "config-apply", "notify",
	"builder-options", "capture", "config-export", "zfs-send",
	"suricata-pcap-put", "suricata-pcap-get",
};

/* Is the peer another host? */
bool
peer_is_host(const cbl_peer *p)
{
	size_t	i, n;

	if (p == NULL)
		return (false);
	n = cbl_peer_san_count(p);
	for (i = 0; i < n; i++)
		if (cbl_peer_san(p, i) != NULL && strcmp(cbl_peer_san(p, i),
		    ROLE_AGENT) == 0)
			return (true);
	return (false);
}

/*
 * Whom a request of peer p is for (cbl_user_f): root's or the agent's
 * own on the unix socket, the user it says or the recovery session;
 * another local account, "local:<login>"; the console, the user it
 * says or "console".  A host's certificate asks nothing.
 */
static int
admit_user(const cbl_peer *p, const char *said, char *name, size_t len,
    bool *recovery, void *arg __unused)
{
	struct passwd	 pw, *res;
	char		 buf[1024];
	uid_t		 uid;
	gid_t		 gid;

	if (peer_is_host(p)) {
		logmsg(LOG_WARNING, "%s: a host's certificate asked: refused, "
		    "only the console asks", cbl_peer_subject(p) != NULL ?
		    cbl_peer_subject(p) : "?");
		return (EACCES);
	}
	if (cbl_peer_transport(p) == CBL_TR_UNIX) {
		if (cbl_peer_cred(p, &uid, &gid) != 0)
			return (EACCES);
		if (uid == 0 || uid == geteuid()) {
			if (said != NULL)
				(void)strlcpy(name, said, len);
			else
				*recovery = true;
			return (0);
		}
		if (said != NULL)
			return (EACCES);
		/* A name of its own: a local account called admin is not
		 * the console's admin. */
		if (getpwuid_r(uid, &pw, buf, sizeof(buf), &res) == 0 &&
		    res != NULL)
			(void)snprintf(name, len, "local:%s", res->pw_name);
		else
			(void)snprintf(name, len, "local:%u", (unsigned)uid);
		return (0);
	}
	(void)strlcpy(name, said != NULL ? said : NACM_CONSOLE, len);
	return (0);
}

/* arc_register(), each command NACM's to let through. */
int
admit_register(cbl_ctx *ctx, cbl_family **famp)
{
	uint32_t	i;
	size_t		j;
	int		error;

	if ((error = cbl_ctx_set_user(ctx, admit_user, NULL)) != 0)
		return (error);
	if ((ops = calloc(arc_family_def.nops, sizeof(*ops))) == NULL)
		return (ENOMEM);
	for (i = 0; i < arc_family_def.nops; i++) {
		ops[i] = arc_family_def.ops[i];
		ops[i].flags |= CBL_OPF_NACM;
	}
	/* A name that is no command's would hold nothing back. */
	for (j = 0; j < nitems(changes); j++) {
		for (i = 0; i < arc_family_def.nops; i++)
			if (strcmp(ops[i].name, changes[j]) == 0) {
				ops[i].flags |= CBL_OPF_DENY;
				break;
			}
		if (i == arc_family_def.nops) {
			logmsg(LOG_ERR, "admit: no command %s", changes[j]);
			free(ops);
			return (EINVAL);
		}
	}
	def = arc_family_def;
	def.ops = ops;
	return (cbl_family_register(ctx, &def, NULL, famp));
}
