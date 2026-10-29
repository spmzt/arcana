/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: the jails of the host and what is done to them.
 *
 * start/stop/restart are delegated to jail(8): it runs the exec.* hooks,
 * mounts and interface setup from jail.conf, which libjail(3) does not.
 * kill uses jail_remove(2).
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jailconf.h"
#include "agent.h"

static int	cmp_jail(const void *, const void *);
static void	drop_aliases(struct work *, const struct jinfo *,
		    const struct cjail *, bool);

struct jref {
	const char		*name;
	const struct jinfo	*ji;
};

static int
cmp_jail(const void *a, const void *b)
{

	return (strcmp(((const struct jref *)a)->name,
	    ((const struct jref *)b)->name));
}

/*
 * Running jails merged with configured ones, sorted by name.  With
 * config_only the running ones are not looked at.
 */
int
do_list(struct work *w, bool config_only, struct jails_read *rsp)
{
	struct arc_jail	*jails;
	struct cconf	 conf;
	struct jboot	 boot;
	struct jinfo	*list;
	struct jref	*refs;
	size_t		 n, i, k, m;
	bool		 seen;

	list = NULL;
	n = 0;
	memset(rsp, 0, sizeof(*rsp));
	rsp->ok = true;
	if (!config_only) {
		if (jails_running(w, &list, &n, &rsp->error) == -1)
			rsp->ok = false;
		jails_procstats(w, list, n);
	}
	conf_read(w, &conf);
	rsp->scopes = conf.scopes;
	rsp->nscopes = conf.nscopes;
	rsp->errors = conf.errors;
	rsp->nerrors = conf.nerrors;

	refs = wcalloc(w, n + conf.njails + 1, sizeof(*refs));
	for (k = 0; k < n; k++) {
		refs[k].name = list[k].name != NULL ? list[k].name : "";
		refs[k].ji = &list[k];
	}
	for (i = 0; i < conf.njails; i++) {
		seen = false;
		for (m = 0; m < n; m++)
			if (strcmp(refs[m].name, conf.jails[i].name) == 0)
				seen = true;
		if (!seen) {
			refs[k].name = conf.jails[i].name;
			refs[k++].ji = NULL;
		}
	}
	qsort(refs, k, sizeof(*refs), cmp_jail);
	jails = wcalloc(w, k + 1, sizeof(*jails));
	/* What starts at boot: rc.conf read once for them all, as the
	 * files rc(8) reads have it for running (the configured alone),
	 * as sysrc(8) resolves it for the state. */
	if (config_only)
		jail_boot_files(w, &boot);
	else
		jail_boot_read(w, &boot);
	for (i = 0; i < k; i++) {
		jail_record(w, &jails[i], refs[i].name, refs[i].ji,
		    conf_jail(&conf, refs[i].name));
		if (jails[i].configured) {
			jails[i].has_boot = true;
			jails[i].boot = jail_boot_of(&boot, refs[i].name);
		}
	}
	rsp->jails = jails;
	rsp->njails = k;
	return (0);
}

/*
 * Remove the interface aliases of a jail that is gone or has been made
 * again from its configuration.  jail(8) -r removes the aliases of the
 * configured addresses itself, but not of addresses added while the jail
 * ran; jail_remove(2) removes none.  Only for jails with an interface
 * parameter: without one, nobody added aliases for them.
 */
static void
drop_aliases(struct work *w, const struct jinfo *ji, const struct cjail *cj,
    bool all)
{
	const struct arc_param	*p;
	unsigned char		 addr[sizeof(struct in6_addr)];
	const char		*ifname, *lists[2], *e;
	char			*copy, *it, *tok;
	size_t			 i, k;
	bool			 configured;
	int			 af, plen;

	if (ji == NULL || (ifname = cjail_param1(cj, "interface")) == NULL)
		return;
	lists[0] = ji->ip4;
	lists[1] = ji->ip6;
	for (k = 0; k < 2; k++) {
		if (lists[k] == NULL || *lists[k] == '\0')
			continue;
		if ((copy = strdup(lists[k])) == NULL)
			err(1, "strdup");
		for (it = copy; (tok = strsep(&it, ",")) != NULL; ) {
			p = cjail_param(cj, k == 0 ? "ip4.addr" : "ip6.addr");
			configured = false;
			for (i = 0; p != NULL && i < p->values.n; i++)
				if (jc_value_equal(k == 0 ? "ip4.addr" :
				    "ip6.addr", p->values.v[i], tok))
					configured = true;
			if ((configured && !all) ||
			    !jc_addr_split(tok, &af, addr, &plen))
				continue;
			(void)ifaddr_change(w, ifname, af, addr, 0, false, &e);
		}
		free(copy);
	}
}

int
do_action(struct work *w, const char *name, uint8_t action,
    struct jail_done *rsp)
{
	const struct cjail	*cj;
	struct execres		 res;
	struct cconf		 conf;
	struct jinfo		*list, *ji;
	const char		*flag, *e;
	char			*argv[6], fopt[] = "-f";
	size_t			 n, i;
	int			 jid, step;

	memset(rsp, 0, sizeof(*rsp));
	/* Whoever asks (the operation, a YANG action): jail(8) gets it. */
	if (name == NULL || !valid_jail(name)) {
		rsp->error = "invalid jail name";
		return (0);
	}
	conf_read(w, &conf);
	cj = conf_jail(&conf, name);
	jid = jail_lookup(w, name);
	/* The addresses it has now, to clean up after it. */
	ji = NULL;
	if (jid >= 0 && action != ARC_ACTION_START && action !=
	    ARC_ACTION_ENABLE && action != ARC_ACTION_DISABLE &&
	    jails_running(w, &list, &n, &e) == 0)
		for (i = 0; i < n; i++)
			if (list[i].jid == jid)
				ji = &list[i];

	if (action == ARC_ACTION_KILL) {
		if (jid < 0) {
			rsp->error = wfmt(w, "jail '%s' is not running",
			    name);
			goto out;
		}
		step = step_begin(w, STEP_SYSCALL, "jail_remove(2)",
		    "jid %d", jid);
		if (jail_remove(jid) == -1) {
			rsp->error = wfmt(w, "jail_remove: %s",
			    strerror(errno));
			step_end(w, step, false, "%s", strerror(errno));
			goto out;
		}
		step_end(w, step, true, "jid %d removed", jid);
		rsp->ok = true;
		drop_aliases(w, ji, cj, true);
		goto out;
	}

	if (cj == NULL) {
		if (jid >= 0 && action == ARC_ACTION_STOP)
			rsp->error = wfmt(w, "jail '%s' is running but not "
			    "defined in any jail.conf; kill removes it", name);
		else
			rsp->error = wfmt(w, "jail '%s' is not defined in "
			    "%s or %s/*.conf", name, opts.jail_conf,
			    opts.jail_conf_d);
		goto out;
	}
	/* Started at boot or not: rc.conf alone, the jail as it is. */
	if (action == ARC_ACTION_ENABLE || action == ARC_ACTION_DISABLE) {
		e = NULL;
		if (jail_boot_set(w, name, action == ARC_ACTION_ENABLE, &conf,
		    &e) == 0)
			rsp->ok = true;
		else
			rsp->error = e;
		goto out;
	}
	switch (action) {
	case ARC_ACTION_START:
		if (jid >= 0) {
			rsp->error = wfmt(w, "jail '%s' is already running "
			    "(jid %d)", name, jid);
			goto out;
		}
		flag = "-c";
		break;
	case ARC_ACTION_STOP:
		if (jid < 0) {
			rsp->error = wfmt(w, "jail '%s' is not running",
			    name);
			goto out;
		}
		flag = "-r";
		break;
	default:
		/* Restarting a stopped jail is starting it. */
		flag = jid >= 0 ? "-rc" : "-c";
		break;
	}
	argv[0] = (char *)(uintptr_t)opts.jail_bin;
	argv[1] = fopt;
	argv[2] = (char *)(uintptr_t)cj->scope;
	argv[3] = (char *)(uintptr_t)flag;
	argv[4] = (char *)(uintptr_t)name;
	argv[5] = NULL;
	if (run_exec(w, argv, &res) == 0) {
		rsp->ok = true;
		drop_aliases(w, ji, cj, false);
	} else
		rsp->error = wtext(w, exec_error(w, &res, "jail"));
out:
	rsp->result = jail_current(w, name, &conf);
	return (0);
}

