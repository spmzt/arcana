/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: who may ask.  A host's certificate is for a server and a
 * client both, so that hosts can reach each other (the mesh), and it
 * says so: a SAN URI urn:arcana:role:agent.  A peer that shows one is
 * another host, and asks nothing here but the mesh's, which there is
 * none of yet: every command is refused to it.  The console's own
 * certificate may say urn:arcana:role:console; one from before the
 * roles says nothing, and is taken as the console's.
 *
 * The family's commands are registered through a copy of the generated
 * table whose handlers look at the peer first.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "agent.h"

#define	ROLE_AGENT	"URI:urn:arcana:role:agent"

static struct cbl_op		*ops;
static struct cbl_family_def	 def;

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

static const struct cbl_op *
orig_of(uint16_t cmd)
{
	uint32_t	i;

	for (i = 0; i < arc_family_def.nops; i++)
		if (arc_family_def.ops[i].cmd == cmd)
			return (&arc_family_def.ops[i]);
	return (NULL);
}

static bool
refused(cbl_req *req, const cbl_msg *msg)
{
	const cbl_peer	*p;

	if (!peer_is_host(p = cbl_req_peer(req)))
		return (false);
	logmsg(LOG_WARNING, "%s: a host's certificate asked for %s: refused, "
	    "only the console asks", cbl_peer_subject(p) != NULL ?
	    cbl_peer_subject(p) : "?", orig_of(cbl_msg_cmd(msg)) != NULL ?
	    orig_of(cbl_msg_cmd(msg))->name : "?");
	return (true);
}

static int
doit(cbl_req *req, const cbl_msg *msg, void *arg)
{

	if (refused(req, msg))
		return (EACCES);
	return (orig_of(cbl_msg_cmd(msg))->doit(req, msg, arg));
}

static int
dumpit(cbl_req *req, const cbl_msg *msg, struct cbl_dump_state *st,
    void *arg)
{

	if (refused(req, msg))
		return (EACCES);
	return (orig_of(cbl_msg_cmd(msg))->dumpit(req, msg, st, arg));
}

static int
stream_open(cbl_req *req, const cbl_msg *msg, cbl_stream *s, void *arg)
{

	if (refused(req, msg))
		return (EACCES);
	return (orig_of(cbl_msg_cmd(msg))->stream_open(req, msg, s, arg));
}

/* arc_register(), with each handler behind the look at the peer. */
int
admit_register(cbl_ctx *ctx, cbl_family **famp)
{
	uint32_t	i;

	if ((ops = calloc(arc_family_def.nops, sizeof(*ops))) == NULL)
		return (ENOMEM);
	for (i = 0; i < arc_family_def.nops; i++) {
		ops[i] = arc_family_def.ops[i];
		if (ops[i].doit != NULL)
			ops[i].doit = doit;
		if (ops[i].dumpit != NULL)
			ops[i].dumpit = dumpit;
		if (ops[i].stream_open != NULL)
			ops[i].stream_open = stream_open;
	}
	def = arc_family_def;
	def.ops = ops;
	return (cbl_family_register(ctx, &def, NULL, famp));
}
