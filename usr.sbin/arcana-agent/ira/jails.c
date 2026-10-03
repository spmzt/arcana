/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Running jails from libjail(3), and their processes from libprocstat(3).
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <errno.h>
#include <jail.h>
#include <libprocstat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"

enum {
	P_LASTJID,
	P_JID,
	P_NAME,
	P_HOSTNAME,
	P_PATH,
	P_IP4,
	P_IP6,
	P_OSRELEASE,
	P_VNET,
	P_DYING,
	P_PERSIST,
	P_PARENT,
	P_CHILDREN,
	P_SECURELEVEL,
	P_COUNT
};

static const char *pnames[P_COUNT] = {
	[P_LASTJID] = "lastjid",
	[P_JID] = "jid",
	[P_NAME] = "name",
	[P_HOSTNAME] = "host.hostname",
	[P_PATH] = "path",
	[P_IP4] = "ip4.addr",
	[P_IP6] = "ip6.addr",
	[P_OSRELEASE] = "osrelease",
	[P_VNET] = "vnet",
	[P_DYING] = "dying",
	[P_PERSIST] = "persist",
	[P_PARENT] = "parent",
	[P_CHILDREN] = "children.cur",
	[P_SECURELEVEL] = "securelevel",
};

static const char	*export(struct work *, struct jailparam *, const int *,
			    int);
static int		 export_int(struct work *, struct jailparam *,
			    const int *, int);
static bool		 export_bool(struct work *, struct jailparam *,
			    const int *, int);

/* jp is compacted: idx[i] is where parameter i lives, or -1. */
static const char *
export(struct work *w, struct jailparam *jp, const int *idx, int i)
{
	char		*s;
	const char	*v;

	if (idx[i] < 0 || (s = jailparam_export(&jp[idx[i]])) == NULL)
		return (NULL);
	v = wstrdup(w, s);
	free(s);
	return (v);
}

static int
export_int(struct work *w, struct jailparam *jp, const int *idx, int i)
{
	const char	*s;

	return ((s = export(w, jp, idx, i)) == NULL ? 0 :
	    (int)strtol(s, NULL, 10));
}

static bool
export_bool(struct work *w, struct jailparam *jp, const int *idx, int i)
{
	const char	*s;

	return ((s = export(w, jp, idx, i)) != NULL &&
	    (strcmp(s, "true") == 0 || strcmp(s, "1") == 0));
}

/*
 * Every jail visible to us, dying ones included: what jls(8) does,
 * without parsing its output.
 */
int
jails_running(struct work *w, struct jinfo **out, size_t *nout,
    const char **errp)
{
	struct jailparam	 jp[P_COUNT];
	struct jinfo		*list, *ji;
	const char		*s;
	size_t			 n, cap;
	int			 idx[P_COUNT];
	int			 i, np, jid, lastjid, step;

	step = step_begin(w, ARC_STEP_KIND_LIB, "jailparam_get(3)",
	    "iterate jails by lastjid, flags JAIL_DYING");
	/* Parameters this kernel lacks (ip6.addr without INET6) go. */
	memset(jp, 0, sizeof(jp));
	for (i = np = 0; i < P_COUNT; i++)
		idx[i] = jailparam_init(&jp[np], pnames[i]) == 0 ? np++ : -1;
	list = NULL;
	n = cap = 0;
	if (idx[P_LASTJID] != 0 || idx[P_NAME] < 0) {
		*errp = wfmt(w, "jailparam_init: %s", jail_errmsg);
		goto fail;
	}
	for (lastjid = 0;; lastjid = jid) {
		if (jailparam_import_raw(&jp[0], &lastjid,
		    sizeof(lastjid)) == -1) {
			*errp = wfmt(w, "jailparam_import_raw: %s",
			    jail_errmsg);
			goto fail;
		}
		if ((jid = jailparam_get(jp, np, JAIL_DYING)) < 0) {
			if (errno == ENOENT)
				break;
			*errp = wfmt(w, "jailparam_get: %s", jail_errmsg);
			goto fail;
		}
		if (n == cap) {
			struct jinfo *nl;

			cap = cap == 0 ? 16 : cap * 2;
			nl = wcalloc(w, cap, sizeof(*nl));
			if (n > 0)
				memcpy(nl, list, n * sizeof(*nl));
			list = nl;
		}
		ji = &list[n++];
		memset(ji, 0, sizeof(*ji));
		ji->jid = jid;
		ji->name = export(w, jp, idx, P_NAME);
		ji->hostname = export(w, jp, idx, P_HOSTNAME);
		ji->path = export(w, jp, idx, P_PATH);
		ji->ip4 = export(w, jp, idx, P_IP4);
		ji->ip6 = export(w, jp, idx, P_IP6);
		ji->osrelease = export(w, jp, idx, P_OSRELEASE);
		s = export(w, jp, idx, P_VNET);
		ji->vnet = s != NULL && (strcmp(s, "new") == 0 ||
		    strcmp(s, "1") == 0);
		ji->dying = export_bool(w, jp, idx, P_DYING);
		ji->persist = export_bool(w, jp, idx, P_PERSIST);
		ji->parent = export_int(w, jp, idx, P_PARENT);
		ji->children = export_int(w, jp, idx, P_CHILDREN);
		ji->securelevel = export_int(w, jp, idx, P_SECURELEVEL);
	}
	jailparam_free(jp, np);
	step_end(w, step, true, "%zu running jail%s", n, n == 1 ? "" : "s");
	*out = list;
	*nout = n;
	return (0);

fail:
	step_end(w, step, false, "%s", *errp);
	jailparam_free(jp, np);
	return (-1);
}

/* Process count, resident memory and CPU for each jail. */
void
jails_procstats(struct work *w, struct jinfo *list, size_t n)
{
	struct procstat		*ps;
	struct kinfo_proc	*kp;
	unsigned int		 cnt, i;
	size_t			 j;
	long			 pagekb;
	int			 step;

	if (n == 0)
		return;
	step = step_begin(w, ARC_STEP_KIND_LIB, "procstat_getprocs(3)",
	    "KERN_PROC_PROC, grouped by ki_jid");
	if ((ps = procstat_open_sysctl()) == NULL) {
		step_end(w, step, false, "procstat_open_sysctl failed");
		return;
	}
	if ((kp = procstat_getprocs(ps, KERN_PROC_PROC, 0, &cnt)) == NULL) {
		step_end(w, step, false, "procstat_getprocs failed");
		procstat_close(ps);
		return;
	}
	pagekb = getpagesize() / 1024;
	for (i = 0; i < cnt; i++) {
		if (kp[i].ki_jid == 0)
			continue;
		for (j = 0; j < n; j++) {
			if (list[j].jid != kp[i].ki_jid)
				continue;
			list[j].nproc++;
			list[j].rss_kb += (uint64_t)kp[i].ki_rssize * pagekb;
			list[j].cpu_pct +=
			    100.0 * (double)kp[i].ki_pctcpu / FSCALE;
			break;
		}
	}
	procstat_freeprocs(ps, kp);
	procstat_close(ps);
	step_end(w, step, true, "%u processes scanned", cnt);
}

/* jail_getid(3): the jid, or -1 if the jail is not running. */
int
jail_lookup(struct work *w, const char *name)
{
	int	jid, step;

	step = step_begin(w, ARC_STEP_KIND_LIB, "jail_getid(3)", "%s", name);
	jid = jail_getid(name);
	if (jid < 0)
		step_end(w, step, true, "not running");
	else
		step_end(w, step, true, "jid %d", jid);
	return (jid);
}
