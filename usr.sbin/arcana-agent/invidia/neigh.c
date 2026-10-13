/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: a neighbour, ARP's or NDP's, set by hand or taken away, with
 * arp(8) or ndp(8): one that stays (permanent) or one that ages out as
 * the others do (temp).  Kept for a boot, it is a pair of rc.conf's
 * static_arp_pairs or static_ndp_pairs, which rc.d/static_arp and
 * static_ndp set at boot.  In the jail whose network it is, when one
 * is named.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

/* Six bytes of hex, : between them. */
static bool
lladdr_ok(const char *s)
{
	unsigned int	b[6];
	char		end;

	return (s != NULL && strlen(s) <= 17 && sscanf(s,
	    "%2x:%2x:%2x:%2x:%2x:%2x%c", &b[0], &b[1], &b[2], &b[3], &b[4],
	    &b[5], &end) == 6);
}

/* The address's family, 4 or 6, or 0 when it is not one. */
static int
family_of(const char *s)
{
	struct in_addr	a4;
	struct in6_addr	a6;
	const char	*z;
	char		buf[INET6_ADDRSTRLEN + IF_NAMESIZE + 2];

	if (s == NULL || strlen(s) >= sizeof(buf))
		return (0);
	if (inet_pton(AF_INET, s, &a4) == 1)
		return (4);
	snprintf(buf, sizeof(buf), "%s", s);
	/* A zone is an interface's name, and nothing else: it goes into
	 * rc.conf, which sh reads. */
	if ((z = strchr(s, '%')) != NULL) {
		z++;
		if (*z == '\0' || strlen(z) >= IF_NAMESIZE)
			return (0);
		for (; *z != '\0'; z++)
			if (!isalnum((unsigned char)*z) && strchr("._-", *z) ==
			    NULL)
				return (0);
	}
	buf[strcspn(buf, "%")] = '\0';
	return (inet_pton(AF_INET6, buf, &a6) == 1 ? 6 : 0);
}

const char *
neigh_check(const struct arc_job_spec *sp)
{

	if (sp->verb == NULL || (strcmp(sp->verb, "add") != 0 &&
	    strcmp(sp->verb, "delete") != 0))
		return ("a neighbour is added or deleted");
	if (family_of(sp->address) == 0)
		return ("a neighbour is an IPv4 or IPv6 address");
	if (strcmp(sp->verb, "add") == 0 && !lladdr_ok(sp->lladdr))
		return ("a neighbour's link address is six bytes of hex, "
		    "00:11:22:33:44:55");
	if (sp->safe)
		return ("a neighbour set is not put back by itself: not in "
		    "safe mode");
	if (strcmp(sp->verb, "add") == 0 && sp->temporary && sp->persist)
		return ("one that ages out is not kept for a boot");
	return (NULL);
}

/* rc.conf's name for the pair: the address, its . : and % as _. */
static const char *
pair_name(struct work *w, const char *addr)
{
	char	*n, *p;

	n = wfmt(w, "arcana_%s", addr);
	for (p = n; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p))
			*p = '_';
	return (n);
}

/* sysrc, in the scope of the job's jail, its output dropped. */
static int
sysrc(struct work *w, const char *a1, const char *a2, const char *a3,
    const char **errp)
{
	struct execres	 res;
	char		*argv[5];
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.sysrc_bin;
	argv[n++] = (char *)(uintptr_t)a1;
	if (a2 != NULL)
		argv[n++] = (char *)(uintptr_t)a2;
	if (a3 != NULL)
		argv[n++] = (char *)(uintptr_t)a3;
	argv[n] = NULL;
	if (run_exec(w, scope_argv(w, argv), &res) != 0) {
		if (errp != NULL)
			*errp = wtext(w, exec_error(w, &res, "sysrc"));
		return (-1);
	}
	return (0);
}

int
do_neigh(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct execres	 res;
	const char	*prog, *list, *name, *e;
	char		*argv[7];
	bool		 add;
	int		 n, fam;

	if ((*errp = neigh_check(sp)) != NULL)
		return (-1);
	add = strcmp(sp->verb, "add") == 0;
	fam = family_of(sp->address);
	prog = tool(w, fam == 4 ? "arp" : "ndp");
	if (prog == NULL) {
		*errp = fam == 4 ? "the host has no arp(8)" :
		    "the host has no ndp(8)";
		return (-1);
	}
	if (sp->live || !sp->persist) {
		n = 0;
		argv[n++] = (char *)(uintptr_t)prog;
		argv[n++] = (char *)(uintptr_t)(add ? "-s" : "-d");
		argv[n++] = (char *)(uintptr_t)sp->address;
		if (add) {
			argv[n++] = (char *)(uintptr_t)sp->lladdr;
			if (sp->temporary)
				argv[n++] = (char *)(uintptr_t)"temp";
		}
		argv[n] = NULL;
		/* arp -s says what it cannot do and still exits 0: what
		 * it says on standard error is its failure. */
		if (run_exec(w, scope_jexec(w, argv), &res) != 0 ||
		    res.errlen > 0) {
			e = scope_missing(w, &res, fam == 4 ? "arp" : "ndp",
			    NULL);
			*errp = e != NULL ? e : res.errlen > 0 ? wtext(w,
			    wstrndup(w, res.err, res.err[res.errlen - 1] ==
			    '\n' ? res.errlen - 1 : res.errlen)) : wtext(w,
			    exec_error(w, &res, fam == 4 ? "arp" : "ndp"));
			return (-1);
		}
	}
	if (!sp->persist)
		return (0);
	list = fam == 4 ? "static_arp_pairs" : "static_ndp_pairs";
	name = pair_name(w, sp->address);
	if (!add) {
		(void)sysrc(w, wfmt(w, "%s-=%s", list, name), NULL, NULL,
		    NULL);
		(void)sysrc(w, "-i", "-x", wfmt(w, "static_%s_%s", fam == 4 ?
		    "arp" : "ndp", name), NULL);
		return (0);
	}
	if (sysrc(w, wfmt(w, "static_%s_%s=%s %s", fam == 4 ? "arp" : "ndp",
	    name, sp->address, sp->lladdr), NULL, NULL, errp) != 0 ||
	    sysrc(w, wfmt(w, "%s+=%s", list, name), NULL, NULL, errp) != 0)
		return (-1);
	return (0);
}
