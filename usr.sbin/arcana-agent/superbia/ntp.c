/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The NTP servers the host keeps time by: ntp.conf's lines between
 * arcana's marks, ntpd enabled and restarted.  An SD-WAN edge needs the
 * time for key rotation and for faults to line up (Mplify 119 §12.2.2).
 */

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

#define	BEGIN	"# arcana: the NTP servers, set by the console; begin\n"
#define	END	"# arcana: end\n"

bool
ntp_server_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 253)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && strchr(".-:", s[i]) == NULL)
			return (false);
	return (true);
}

/*
 * ntp.conf with the servers in arcana's block, or without the block;
 * ntpd enabled (persist) and restarted.
 */
int
do_ntp(struct work *w, const char *const *servers, size_t n, bool remove,
    bool persist, const char **errp)
{
	struct execres	 res;
	char		*old, *out, *b, *e, *argv[4];
	size_t		 len, i;
	int		 step;
	bool		 enabled;

	if (!remove && n == 0) {
		*errp = "name a server at least, or say remove";
		return (-1);
	}
	for (i = 0; i < n; i++)
		if (!ntp_server_ok(servers[i])) {
			*errp = wfmt(w, "%s is not a server's name or address",
			    servers[i]);
			return (-1);
		}
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", opts.ntp_conf);
	if ((old = scope_slurp(w, opts.ntp_conf, &len)) == NULL) {
		if (errno != ENOENT) {
			step_end(w, step, false, "%s", strerror(errno));
			*errp = wfmt(w, "%s: %s", opts.ntp_conf, strerror(errno));
			return (-1);
		}
		old = wstrdup(w, "");
	}
	/* The block as it was, out; the new one at the end. */
	out = wcalloc(w, strlen(old) + 64 + n * 300, 1);
	if ((b = strstr(old, BEGIN)) != NULL && (e = strstr(b, END)) != NULL) {
		memcpy(out, old, (size_t)(b - old));
		strcat(out, e + strlen(END));
	} else
		strcpy(out, old);
	if (!remove) {
		if (out[0] != '\0' && out[strlen(out) - 1] != '\n')
			strcat(out, "\n");
		strcat(out, BEGIN);
		for (i = 0; i < n; i++)
			sprintf(out + strlen(out), "server %s iburst\n",
			    servers[i]);
		strcat(out, END);
	}
	if (scope_replace(w, opts.ntp_conf, out, strlen(out), 0644,
	    ".ntp.conf.was") != 0) {
		step_end(w, step, false, "%s", strerror(errno));
		*errp = wfmt(w, "%s: %s", opts.ntp_conf, strerror(errno));
		return (-1);
	}
	step_end(w, step, true, NULL);
	if (persist && !remove && rc_set(w, "ntpd_enable", "=", "YES", errp) !=
	    0)
		return (-1);
	enabled = rc_get(w, "ntpd_enable") != NULL && strcasecmp(rc_get(w,
	    "ntpd_enable"), "YES") == 0;
	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)"ntpd";
	argv[2] = (char *)(uintptr_t)(remove && !enabled ? "onestop" :
	    enabled ? "restart" : "onerestart");
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0 && !remove) {
		*errp = wtext(w, exec_error(w, &res, "service ntpd"));
		return (-1);
	}
	return (0);
}
