/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Router advertisements on an interface, by the base system's rtadvd(8),
 * for the hosts behind it to address themselves (SLAAC, MEF 70.2 §11.5):
 * an entry per interface in rtadvd.conf between arcana's marks, the
 * interface on rtadvd_interfaces, rtadvd enabled and restarted.
 */

#include <sys/param.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

#define	BEGIN	"# arcana: the UNIs' router advertisements, set by the console; begin\n"
#define	END	"# arcana: end\n"

/* A prefix of length 64 (R137: a SLAAC prefix is a /64). */
bool
rtadvd_prefix_ok(const char *s)
{
	char		 buf[64], *slash;
	struct in6_addr	 a;

	if (s == NULL || strlen(s) >= sizeof(buf))
		return (false);
	snprintf(buf, sizeof(buf), "%s", s);
	if ((slash = strchr(buf, '/')) == NULL || strcmp(slash, "/64") != 0)
		return (false);
	*slash = '\0';
	return (inet_pton(AF_INET6, buf, &a) == 1);
}

static bool
ifname_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 15)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '.' && s[i] != '_')
			return (false);
	return (true);
}

/*
 * The block's entries, each "ifname:\" and an attributes line, with
 * the one of ifname left out, into out; how many stayed.
 */
static int
entries_keep(const char *block, const char *ifname, char *out, size_t len)
{
	const char	*p, *nl, *nl2;
	size_t		 l;
	int		 kept = 0;

	out[0] = '\0';
	for (p = block; *p != '\0'; p = nl2 + 1) {
		if ((nl = strchr(p, '\n')) == NULL)
			break;
		if ((nl2 = strchr(nl + 1, '\n')) == NULL)
			nl2 = nl + 1 + strlen(nl + 1) - 1;
		l = (size_t)(nl2 + 1 - p);
		if (strncmp(p, ifname, strlen(ifname)) == 0 && p[strlen(
		    ifname)] == ':')
			continue;
		if (strlen(out) + l + 1 > len)
			break;
		strncat(out, p, l);
		kept++;
	}
	return (kept);
}

/*
 * rtadvd.conf with the interface's entry in arcana's block (prefix, and
 * the DNS servers as RDNSS), or without it; with persist, rtadvd
 * enabled and the interface on rtadvd_interfaces; rtadvd restarted, or
 * stopped when nothing is left.
 */
int
do_rtadvd(struct work *w, const char *ifname, const char *const *names,
    size_t n, bool remove, bool persist, const char **errp)
{
	struct execres	 res;
	struct in6_addr	 a;
	char		*old, *out, *b, *e, *kept, *argv[4], pfx[64];
	size_t		 len, i;
	int		 step, left;
	bool		 enabled;

	if (!ifname_ok(ifname)) {
		*errp = "an interface's name is letters, digits, . and _";
		return (-1);
	}
	if (!remove && (n == 0 || !rtadvd_prefix_ok(names[0]))) {
		*errp = "the prefix advertised is an IPv6 one of length 64, "
		    "the hosts' subnet (§11.5)";
		return (-1);
	}
	if (!remove && n > 9) {
		*errp = "at most 8 DNS servers are advertised";
		return (-1);
	}
	for (i = 1; !remove && i < n; i++)
		if (inet_pton(AF_INET6, names[i], &a) != 1) {
			*errp = wfmt(w, "%s is not an IPv6 address of a DNS "
			    "server", names[i]);
			return (-1);
		}
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", opts.rtadvd_conf);
	if ((old = scope_slurp(w, opts.rtadvd_conf, &len)) == NULL) {
		if (errno != ENOENT) {
			step_end(w, step, false, "%s", strerror(errno));
			*errp = wfmt(w, "%s: %s", opts.rtadvd_conf, strerror(
			    errno));
			return (-1);
		}
		old = wstrdup(w, "");
	}
	out = wcalloc(w, strlen(old) + 128 + n * 80, 1);
	kept = wcalloc(w, strlen(old) + 1, 1);
	left = 0;
	if ((b = strstr(old, BEGIN)) != NULL && (e = strstr(b, END)) != NULL) {
		/* The other interfaces' entries stay. */
		*e = '\0';
		left = entries_keep(b + strlen(BEGIN), ifname, kept, strlen(old)
		    + 1);
		*e = '#';
		memcpy(out, old, (size_t)(b - old));
		strcat(out, e + strlen(END));
	} else
		strcpy(out, old);
	if (!remove || left > 0) {
		if (out[0] != '\0' && out[strlen(out) - 1] != '\n')
			strcat(out, "\n");
		strcat(out, BEGIN);
		strcat(out, kept);
		if (!remove) {
			snprintf(pfx, sizeof(pfx), "%s", names[0]);
			*strchr(pfx, '/') = '\0';
			sprintf(out + strlen(out), "%s:\\\n\t:addr=\"%s\":prefixlen"
			    "#64:", ifname, pfx);
			if (n > 1) {
				strcat(out, "rdnss=\"");
				for (i = 1; i < n; i++)
					sprintf(out + strlen(out), "%s%s", i > 1 ?
					    "," : "", names[i]);
				strcat(out, "\":");
			}
			strcat(out, "\n");
			left++;
		}
		strcat(out, END);
	}
	if (scope_replace(w, opts.rtadvd_conf, out, strlen(out), 0644,
	    ".rtadvd.conf.was") != 0) {
		step_end(w, step, false, "%s", strerror(errno));
		*errp = wfmt(w, "%s: %s", opts.rtadvd_conf, strerror(errno));
		return (-1);
	}
	step_end(w, step, true, NULL);
	if (persist) {
		if (rc_set(w, "rtadvd_interfaces", remove ? "-=" : "+=", ifname,
		    errp) != 0)
			return (-1);
		if (!remove && rc_set(w, "rtadvd_enable", "=", "YES", errp) != 0)
			return (-1);
		if (remove && left == 0 && rc_set(w, "rtadvd_enable", "=", "NO",
		    errp) != 0)
			return (-1);
	}
	enabled = rc_get(w, "rtadvd_enable") != NULL && strcasecmp(rc_get(w,
	    "rtadvd_enable"), "YES") == 0;
	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)"rtadvd";
	argv[2] = (char *)(uintptr_t)(remove && left == 0 ? "onestop" :
	    enabled ? "restart" : "onerestart");
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0 && !remove) {
		*errp = wtext(w, exec_error(w, &res, "service rtadvd"));
		return (-1);
	}
	return (0);
}
