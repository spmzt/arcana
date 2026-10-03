/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: what of the network is kept in rc.conf, so that a change
 * made live is there again after a boot.  Everything is read and
 * written through sysrc(8), each run a step of the trace.
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

#define	ALIAS_MAX	256	/* aliases of one interface looked through */

/* The value of name, or NULL when rc.conf does not set it. */
const char *
rc_get(struct work *w, const char *name)
{
	struct execres	 res;
	char		*argv[5], *v;

	argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
	argv[1] = (char *)(uintptr_t)"-i";
	argv[2] = (char *)(uintptr_t)"-n";
	argv[3] = (char *)(uintptr_t)name;
	argv[4] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return (NULL);
	v = wstrndup(w, res.out, strcspn(res.out, "\n"));
	return (v[0] != '\0' ? v : NULL);
}

/* name=value, or with op "+=" and "-=" an item on or off its list. */
int
rc_set(struct work *w, const char *name, const char *op, const char *value,
    const char **errp)
{
	struct execres	 res;
	char		*argv[3];

	argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
	argv[1] = wfmt(w, "%s%s%s", name, op, value);
	argv[2] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "sysrc"));
		return (-1);
	}
	return (0);
}

/* Take name out of rc.conf; that it was not there is no failure. */
void
rc_unset(struct work *w, const char *name)
{
	struct execres	 res;
	char		*argv[5];

	argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
	argv[1] = (char *)(uintptr_t)"-i";
	argv[2] = (char *)(uintptr_t)"-x";
	argv[3] = (char *)(uintptr_t)name;
	argv[4] = NULL;
	(void)run_exec(w, argv, &res);
}

/* Is word one of the words of value? */
static bool
has_word(const char *value, const char *word)
{
	const char	*p;
	size_t		 len;

	len = strlen(word);
	for (p = value; (p = strstr(p, word)) != NULL; p += len)
		if ((p == value || p[-1] == ' ') && (p[len] == '\0' ||
		    p[len] == ' ' || p[len] == '/'))
			return (true);
	return (false);
}

/*
 * An address of an interface, kept as ifconfig_<if>_alias<n>.  rc(8)
 * reads the aliases from 0 up and stops at the first that is missing,
 * so a new one takes the first free number, and one taken out has the
 * ones after it moved down.  af is "inet" or "inet6"; addr the address
 * without its prefix length, spec what follows the family.
 */
int
rc_alias(struct work *w, const char *ifname, const char *af, const char *addr,
    const char *spec, bool remove, const char **errp)
{
	const char	*v, *next;
	int		 n, at;

	at = -1;
	for (n = 0; n < ALIAS_MAX; n++) {
		if ((v = rc_get(w, wfmt(w, "ifconfig_%s_alias%d", ifname,
		    n))) == NULL)
			break;
		if (at == -1 && has_word(v, addr))
			at = n;
	}
	if (!remove) {
		if (at != -1)
			return (0);	/* kept already */
		if (n == ALIAS_MAX) {
			*errp = "too many aliases in rc.conf";
			return (-1);
		}
		return (rc_set(w, wfmt(w, "ifconfig_%s_alias%d", ifname, n),
		    "=", wfmt(w, "%s %s", af, spec), errp));
	}
	if (at == -1)
		return (0);		/* not kept: nothing to forget */
	for (; at + 1 < n; at++) {
		next = rc_get(w, wfmt(w, "ifconfig_%s_alias%d", ifname,
		    at + 1));
		if (next == NULL || rc_set(w, wfmt(w, "ifconfig_%s_alias%d",
		    ifname, at), "=", next, errp) != 0)
			return (-1);
	}
	rc_unset(w, wfmt(w, "ifconfig_%s_alias%d", ifname, at));
	return (0);
}

/*
 * "mtu N" in ifconfig_<if>: the number replaced where the word is,
 * the pair added where it is not.
 */
int
rc_mtu(struct work *w, const char *ifname, unsigned int mtu,
    const char **errp)
{
	const char	*v, *p, *e;
	char		*name;

	name = wfmt(w, "ifconfig_%s", ifname);
	if ((v = rc_get(w, name)) == NULL)
		return (rc_set(w, name, "=", wfmt(w, "mtu %u", mtu), errp));
	for (p = v; (p = strstr(p, "mtu ")) != NULL; p += 4) {
		if (p != v && p[-1] != ' ')
			continue;
		e = p + 4 + strspn(p + 4, "0123456789");
		return (rc_set(w, name, "=", wfmt(w, "%.*smtu %u%s",
		    (int)(p - v), v, mtu, e), errp));
	}
	return (rc_set(w, name, "=", wfmt(w, "%s mtu %u", v, mtu), errp));
}

/* Every variable rc.conf keeps of a cloned interface that is no more. */
void
rc_forget_if(struct work *w, const char *ifname)
{
	int	n;

	rc_unset(w, wfmt(w, "ifconfig_%s", ifname));
	rc_unset(w, wfmt(w, "ifconfig_%s_descr", ifname));
	rc_unset(w, wfmt(w, "ifconfig_%s_ipv6", ifname));
	rc_unset(w, wfmt(w, "create_args_%s", ifname));
	for (n = 0; n < ALIAS_MAX; n++) {
		if (rc_get(w, wfmt(w, "ifconfig_%s_alias%d", ifname, n)) ==
		    NULL)
			break;
		rc_unset(w, wfmt(w, "ifconfig_%s_alias%d", ifname, n));
	}
}
