/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the BIRD routing daemon, through birdc(8): what it says of
 * itself and of its protocols, and the few things it is told about one
 * of them.
 */

#include <sys/param.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

#include "agent.h"

static void
put(ucl_object_t *o, const char *key, const char *v)
{

	ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0, true);
}

/* birdc with these words; restricted, when it is only to read. */
static int
birdc(struct work *w, bool readonly, const char *a, const char *b,
    const char *c, struct execres *res)
{
	char	*argv[6];
	int	 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.birdc_bin;
	if (readonly)
		argv[n++] = (char *)(uintptr_t)"-r";
	argv[n++] = (char *)(uintptr_t)a;
	if (b != NULL)
		argv[n++] = (char *)(uintptr_t)b;
	if (c != NULL)
		argv[n++] = (char *)(uintptr_t)c;
	argv[n] = NULL;
	return (run_exec(w, argv, res));
}

/*
 * {"status": ["BIRD 2.15", "Router ID is ...", ...], "protocols":
 * [{"name", "proto", "table", "state", "since", "info"}]}: the lines
 * of "show status", and the table of "show protocols", whose last
 * column is whatever is left of the line.
 */
int
do_bird(struct work *w, struct arc_network_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *st, *arr, *o;
	unsigned char	*json;
	char		*text, *line, *f[6], *p;
	int		 n;

	rsp->has_ok = true;
	rsp->ok = false;
	if (birdc(w, true, "show", "status", NULL, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "birdc"));
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	st = ucl_object_typed_new(UCL_ARRAY);
	text = wstrdup(w, res.out != NULL ? res.out : "");
	while ((line = strsep(&text, "\n")) != NULL)
		if (line[0] != '\0' && strstr(line, " ready.") == NULL &&
		    strncmp(line, "Access restricted", 17) != 0)
			ucl_array_append(st, ucl_object_fromstring(line));
	ucl_object_insert_key(top, st, "status", 0, false);

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (birdc(w, true, "show", "protocols", NULL, &res) == 0) {
		text = wstrdup(w, res.out != NULL ? res.out : "");
		while ((line = strsep(&text, "\n")) != NULL) {
			/* Name Proto Table State Since Info */
			p = line;
			for (n = 0; n < 5; n++) {
				p += strspn(p, " \t");
				if (*p == '\0')
					break;
				f[n] = p;
				p += strcspn(p, " \t");
				if (*p != '\0')
					*p++ = '\0';
			}
			if (n < 5 || strcmp(f[0], "Name") == 0 ||
			    strcmp(f[0], "BIRD") == 0 || strcmp(f[0],
			    "Access") == 0)
				continue;
			f[5] = p + strspn(p, " \t");
			f[5][strcspn(f[5], "\r")] = '\0';
			while (f[5][0] != '\0' && f[5][strlen(f[5]) - 1] == ' ')
				f[5][strlen(f[5]) - 1] = '\0';
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "name", f[0]);
			put(o, "proto", f[1]);
			put(o, "table", f[2]);
			put(o, "state", f[3]);
			put(o, "since", f[4]);
			put(o, "info", f[5]);
			ucl_array_append(arr, o);
		}
	}
	ucl_object_insert_key(top, arr, "protocols", 0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "what birdc says is more than a reply carries";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

/* NULL when birdc may be told verb, about the protocol named or all. */
const char *
bird_check(const char *verb, const char *const *names, size_t n)
{
	static const char *const verbs[] = { "enable", "disable", "restart",
	    "reload" };
	const char	*p;
	size_t		 i;

	if (verb != NULL && strcmp(verb, "configure") == 0)
		return (n == 0 ? NULL : "bird: configure takes no protocol");
	for (i = 0; i < nitems(verbs); i++)
		if (verb != NULL && strcmp(verb, verbs[i]) == 0)
			break;
	if (i == nitems(verbs))
		return ("bird: say enable, disable, restart, reload or "
		    "configure");
	if (n != 1 || names[0] == NULL || names[0][0] == '\0' ||
	    strlen(names[0]) > 64)
		return ("bird: name the protocol, or all");
	for (p = names[0]; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p) && *p != '_')
			return ("bird: a protocol's name is letters, digits "
			    "and _");
	return (NULL);
}

/*
 * birdc(8) ends well whatever the daemon answered: what it printed
 * says whether it was done.
 */
int
do_bird_verb(struct work *w, const char *verb, const char *const *names,
    size_t n, const char **errp)
{
	struct execres	 res;
	const char	*line, *nl;

	if ((*errp = bird_check(verb, names, n)) != NULL)
		return (-1);
	if (birdc(w, false, verb, n == 1 ? names[0] : NULL, NULL, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "birdc"));
		return (-1);
	}
	for (line = res.out; line != NULL && *line != '\0'; line = *nl !=
	    '\0' ? nl + 1 : nl) {
		nl = line + strcspn(line, "\n");
		if (strncasecmp(line, "syntax error", 12) == 0 ||
		    strncmp(line, "No protocols match", 18) == 0 ||
		    strncmp(line, "Not enough privileges", 21) == 0 ||
		    strstr(line, "error") != NULL || strstr(line,
		    "Unable to connect") != NULL) {
			*errp = wtext(w, wstrndup(w, line, (size_t)(nl - line)));
			return (-1);
		}
	}
	return (0);
}
