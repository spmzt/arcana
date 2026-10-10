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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

#define	ALIAS_MAX	256	/* aliases of one interface looked through */

/*
 * A name sysrc(8) may be given: it evaluates what it is asked for, so
 * nothing but what a variable of sh(1) is made of.
 */
bool
rc_name_ok(const char *s)
{

	if (s == NULL || *s == '\0' || isdigit((unsigned char)*s) ||
	    strlen(s) > 128)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && *s != '_')
			return (false);
	return (true);
}

/*
 * A value rc.conf can hold between double quotes as it is: nothing
 * sh(1) would expand, end the quotes with, or read as another line.
 */
bool
rc_value_ok(const char *s)
{

	if (s == NULL)
		return (true);
	for (; *s != '\0'; s++)
		if ((unsigned char)*s < 0x20 || *s == 0x7f || strchr("\"`$\\",
		    *s) != NULL)
			return (false);
	return (true);
}

/* An interface in the name of a variable, as rc(8) spells it: em0_100. */
const char *
rc_ifname(struct work *w, const char *ifname)
{
	char	*s, *p;

	s = wstrdup(w, ifname);
	for (p = s; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p))
			*p = '_';
	return (s);
}

/* The value of name, or NULL when rc.conf does not set it. */
const char *
rc_get(struct work *w, const char *name)
{
	struct execres	 res;
	char		*argv[5], *v;

	if (!rc_name_ok(name))
		return (NULL);

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

	if (!rc_name_ok(name) || !rc_value_ok(value)) {
		*errp = wfmt(w, "%s cannot be kept in rc.conf as it is: a "
		    "name is letters, digits and _, a value has no quote, $, "
		    "` or \\", name);
		return (-1);
	}
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

	if (!rc_name_ok(name))
		return;
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

	ifname = rc_ifname(w, ifname);
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
 * "word N" in ifconfig_<if>, word mtu, fib or tunnelfib: the number
 * replaced where the word is, the pair added where it is not; with
 * value NULL, the pair taken out.
 */
int
rc_word(struct work *w, const char *ifname, const char *word,
    const char *value, const char **errp)
{
	const char	*v, *p, *e;
	char		*name, *key;
	size_t		 len;

	name = wfmt(w, "ifconfig_%s", rc_ifname(w, ifname));
	key = wfmt(w, "%s ", word);
	len = strlen(key);
	if ((v = rc_get(w, name)) == NULL)
		return (value == NULL ? 0 : rc_set(w, name, "=", wfmt(w,
		    "%s%s", key, value), errp));
	for (p = v; (p = strstr(p, key)) != NULL; p += len) {
		if (p != v && p[-1] != ' ')
			continue;
		e = p + len + strspn(p + len, "0123456789");
		if (value != NULL)
			return (rc_set(w, name, "=", wfmt(w, "%.*s%s%s%s",
			    (int)(p - v), v, key, value, e), errp));
		/* Out, and the space after it, or before it at the end. */
		e += strspn(e, " ");
		if (*e == '\0')
			while (p > v && p[-1] == ' ')
				p--;
		if (p == v && *e == '\0') {
			rc_unset(w, name);
			return (0);
		}
		return (rc_set(w, name, "=", wfmt(w, "%.*s%s", (int)(p - v),
		    v, e), errp));
	}
	return (value == NULL ? 0 : rc_set(w, name, "=", wfmt(w, "%s %s%s", v,
	    key, value), errp));
}

/* Every variable rc.conf keeps of a cloned interface that is no more. */
void
rc_forget_if(struct work *w, const char *ifname)
{
	int	n;

	ifname = rc_ifname(w, ifname);
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
