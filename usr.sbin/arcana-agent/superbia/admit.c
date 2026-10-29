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
 * local user is its login name.  Every rpc and action of the models is
 * NACM's; those that change the host, or give out what should stay on
 * it, are marked nacm:default-deny-all: run only by a rule that permits
 * them.  So are the commands of the agent's own stream families.
 */

#include <sys/param.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "agent.h"
#include "ystream.h"

#define	ROLE_AGENT	"URI:urn:arcana:role:agent"

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

/* Whether uid is in the socket's group (-g), the console's by the
 * configuration: its own, or one it is a member of. */
static bool
in_sock_group(uid_t uid, gid_t gid)
{
	struct passwd	 pw, *res;
	char		 buf[1024];
	gid_t		 groups[64];
	int		 n = sizeof(groups) / sizeof(groups[0]);

	if (opts.sock_gid == (gid_t)-1)
		return (false);
	if (gid == opts.sock_gid)
		return (true);
	if (getpwuid_r(uid, &pw, buf, sizeof(buf), &res) != 0 || res == NULL ||
	    getgrouplist(res->pw_name, res->pw_gid, groups, &n) == -1)
		return (false);
	for (int i = 0; i < n; i++)
		if (groups[i] == opts.sock_gid)
			return (true);
	return (false);
}

/*
 * Whom a request of peer p is for (cbl_user_f): root's or the agent's
 * own on the unix socket, the user it says or the recovery session; a
 * local account in the socket's group (-g, the console's user by the
 * configuration), the console; another local account, "local:<login>";
 * the console by its certificate, the user it says or "console".  A
 * host's certificate asks nothing.
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
		if (in_sock_group(uid, gid)) {
			(void)strlcpy(name, said != NULL ? said : NACM_CONSOLE,
			    len);
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

/* Whom each request is for, admit_user()'s, for NACM; before any
 * family is registered. */
int
admit_init(cbl_ctx *ctx)
{

	return (cbl_ctx_set_user(ctx, admit_user, NULL));
}

/* ---- arcana-stream: the streams' family ------------------------------ */

typedef int	open_f(cbl_req *, const struct arcana_stream_open *,
		    cbl_stream *);

/* A stream's opening: its open structure, to the command's handler. */
static int
stream_opened(cbl_req *req, const cbl_msg *msg, cbl_stream *s, open_f *fn)
{
	struct arcana_stream_open	 in;
	cbl_yarena			*a;
	char				 why[256];
	int				 error;

	/* The console's alone; admit_user() refuses a host too, before
	 * NACM. */
	if (peer_is_host(cbl_req_peer(req))) {
		(void)cbl_req_set_err(req, "only the console may open this "
		    "stream", NULL, 0, -1);
		return (EPERM);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&in, 0, sizeof(in));
	if (arcana_stream_open_parse(msg, &in, a, CBL_YD_STRICT, why,
	    sizeof(why)) != 0) {
		(void)cbl_req_set_err(req, why, NULL, 0, -1);
		cbl_yarena_free(a);
		return (EINVAL);
	}
	error = fn(req, &in, s);
	cbl_yarena_free(a);
	return (error);
}

static int
zfs_send_sopen(cbl_req *req, const cbl_msg *msg, cbl_stream *s,
    void *arg __unused)
{

	return (stream_opened(req, msg, s, zfs_send_open));
}

static int
zfs_receive_sopen(cbl_req *req, const cbl_msg *msg, cbl_stream *s,
    void *arg __unused)
{

	return (stream_opened(req, msg, s, zfs_receive_open));
}

static int
pcap_put_sopen(cbl_req *req, const cbl_msg *msg, cbl_stream *s,
    void *arg __unused)
{

	return (stream_opened(req, msg, s, pcap_put_open));
}

static int
pcap_get_sopen(cbl_req *req, const cbl_msg *msg, cbl_stream *s,
    void *arg __unused)
{

	return (stream_opened(req, msg, s, pcap_get_open));
}

/*
 * Each gives out a dataset or a capture, or writes them: NACM's to let
 * through, by its name, and refused to any other unless a rule says.
 */
#define	STREAM_OPF	(CBL_OPF_STREAM | CBL_OPF_AUTH | CBL_OPF_NACM | \
	CBL_OPF_DENY)

static const struct cbl_op stream_ops[] = {
	{ .cmd = YS_ZFS_SEND, .flags = STREAM_OPF, .name = "zfs-send",
	    .stream_open = zfs_send_sopen },
	{ .cmd = YS_ZFS_RECEIVE, .flags = STREAM_OPF, .name = "zfs-receive",
	    .stream_open = zfs_receive_sopen },
	{ .cmd = YS_PCAP_PUT, .flags = STREAM_OPF,
	    .name = "suricata-pcap-put", .stream_open = pcap_put_sopen },
	{ .cmd = YS_PCAP_GET, .flags = STREAM_OPF,
	    .name = "suricata-pcap-get", .stream_open = pcap_get_sopen },
};

static const struct cbl_family_def stream_def = {
	.abi = CBL_FAMILY_ABI,
	.name = YS_FAMILY_NAME,
	.version = 1,
	.ops = stream_ops,
	.nops = nitems(stream_ops),
};

int
stream_register(cbl_ctx *ctx)
{
	cbl_family	*fam;

	return (cbl_family_register(ctx, &stream_def, NULL, &fam));
}
