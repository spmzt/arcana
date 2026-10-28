/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: RFC 6241's ietf-netconf, served for the datastores (RFC 8342)
 * of family 1.  running changes by a confirmed commit of the candidate
 * alone (CBL_YDS_CONFIRMED): cblink answers commit, cancel-commit and
 * discard-changes itself; NETCONF's own session operations, which a
 * cblink peer has no use for, are refused.
 *
 * An undo of a commit not confirmed in time that a handler fails stops
 * there, what is left as committed: a Critical alarm, and an event the
 * console shows as a report to file as a bug, of the failure alone (the
 * node, why, the agent's version), not of the host's configuration.
 */

#include <sys/param.h>
#include <sys/utsname.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <ucl.h>

#include "agent.h"
#include "collect.h"
#include "ymodel.h"

#define	REFUSED(op)							\
int									\
ietf_netconf_##op##_rpc(cbl_req *req,					\
    const struct ietf_netconf_##op##_input *in,				\
    struct ietf_netconf_##op##_output *out, cbl_yarena *a)		\
{									\
									\
	(void)in;							\
	(void)out;							\
	(void)a;							\
	(void)cbl_req_set_yerr(req, "a NETCONF session's operation: not "	\
	    "served over cblink", 0);					\
	return (EOPNOTSUPP);						\
}

REFUSED(get_config)
REFUSED(edit_config)
REFUSED(copy_config)
REFUSED(delete_config)
REFUSED(lock)
REFUSED(unlock)
REFUSED(get)
REFUSED(close_session)
REFUSED(kill_session)
/* The datastores': cblink's own, never asked of the agent. */
REFUSED(commit)
REFUSED(discard_changes)
REFUSED(cancel_commit)

static void
undo_failed(cbl_ctx *ctx, const struct cbl_ynode *n, int error,
    const char *why, void *arg)
{
	struct utsname	 u;
	ucl_object_t	*o;
	char		 node[160], report[1024], when[32];
	unsigned char	*json;
	struct tm	 tm;
	time_t		 now;

	(void)ctx;
	(void)arg;
	(void)snprintf(node, sizeof(node), "%s:%s", n != NULL ?
	    n->module->name : "?", n != NULL ? n->name : "?");
	now = time(NULL);
	(void)gmtime_r(&now, &tm);
	(void)strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%SZ", &tm);
	if (uname(&u) != 0)
		memset(&u, 0, sizeof(u));
	(void)snprintf(report, sizeof(report),
	    "arcana-agent %s on FreeBSD %s\n"
	    "when: %s\n"
	    "what: a confirmed commit was not confirmed in time, and "
	    "undoing %s failed; the undo stopped there\n"
	    "error: %d (%s)\n"
	    "why: %s\n",
	    ARCANA_AGENT_VERSION, u.release, when, node, error,
	    strerror(error), why != NULL ? why : "");
	logmsg(LOG_ERR, "undoing %s failed: %s: what is left stays as "
	    "committed", node, why != NULL ? why : strerror(error));
	fault_set("undo", "Critical", node, "datastore", "the undo of a "
	    "commit not confirmed failed: %s", why != NULL ? why :
	    strerror(error));
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(node), "node", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(error), "errno", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(why != NULL ? why :
	    strerror(error)), "message", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(report), "report", 0,
	    false);
	if ((json = ucl_object_emit(o, UCL_EMIT_JSON_COMPACT)) != NULL)
		event_add("undo-failed", "%s", json);
	free(json);
	ucl_object_unref(o);
}

/* The datastores: running, changed by a confirmed commit alone. */
int
ynetconf_datastores(cbl_ctx *ctx)
{

	return (cbl_ydatastores(ctx, CBL_YDS_CONFIRMED, undo_failed, NULL));
}
