/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the netgraph(4) graph of the host, its nodes and the hooks
 * that join them, read from what ngctl(8) lists and changed by running
 * ngctl(8) with one of a few commands.
 */

#include <sys/param.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

#include "agent.h"

#define	NG_NODES_MAX	4096

struct nglist {
	ucl_object_t	*nodes;
	ucl_object_t	*hooks;		/* of the node being read */
	size_t		 n;
};

static void
put(ucl_object_t *o, const char *key, const char *v)
{

	ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0, true);
}

/*
 * "  Name: em0   Type: ether   ID: 00000002   Num hooks: 1" starts a
 * node; under it, after two lines of heading, a line per hook:
 * "  lower   bridge0   bridge   0000000c   link0".
 */
static void
ng_line(const char *line, void *arg)
{
	struct nglist	*l;
	ucl_object_t	*o;
	char		*copy, *f[12], *p, *tok;
	int		 n;

	l = arg;
	if ((copy = strdup(line)) == NULL)
		return;
	n = 0;
	p = copy;
	while (n < 12 && (tok = strsep(&p, " \t")) != NULL)
		if (tok[0] != '\0')
			f[n++] = tok;
	if (n >= 6 && strcmp(f[0], "Name:") == 0 && strcmp(f[2], "Type:") ==
	    0 && strcmp(f[4], "ID:") == 0) {
		if (l->n++ < NG_NODES_MAX) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "name", f[1]);
			put(o, "type", f[3]);
			put(o, "id", f[5]);
			l->hooks = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(o, l->hooks, "hooks", 0, false);
			ucl_array_append(l->nodes, o);
		} else
			l->hooks = NULL;
	} else if (n == 5 && l->hooks != NULL && strcmp(f[0], "Local") != 0 &&
	    f[0][0] != '-') {
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "hook", f[0]);
		put(o, "peer", f[1]);
		put(o, "peer-type", f[2]);
		put(o, "peer-id", f[3]);
		put(o, "peer-hook", f[4]);
		ucl_array_append(l->hooks, o);
	}
	free(copy);
}

/* {"nodes": [{"name", "type", "id", "hooks": [{"hook", "peer", ...}]}]} */
int
do_netgraph(struct work *w, struct arc_network_rsp *rsp)
{
	struct nglist	 l;
	struct execres	 res;
	ucl_object_t	*top;
	unsigned char	*json;
	const char	*p, *nl;
	char		*argv[4], *line;

	rsp->has_ok = true;
	rsp->ok = false;
	argv[0] = (char *)(uintptr_t)opts.ngctl_bin;
	argv[1] = (char *)(uintptr_t)"list";
	argv[2] = (char *)(uintptr_t)"-l";
	argv[3] = NULL;
	if (run_exec_max(w, argv, &res, ARC_MAX_JSON) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "ngctl"));
		return (0);
	}
	memset(&l, 0, sizeof(l));
	l.nodes = ucl_object_typed_new(UCL_ARRAY);
	for (p = res.out; p != NULL && *p != '\0'; p = *nl != '\0' ? nl + 1 :
	    nl) {
		nl = p + strcspn(p, "\n");
		line = wstrndup(w, p, (size_t)(nl - p));
		ng_line(line, &l);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, l.nodes, "nodes", 0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "the graph is more than a reply carries";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

/* The commands taken, and how many arguments each has. */
static const struct {
	const char	*verb;
	size_t		 min, max;
} ng_verbs[] = {
	{ "mkpeer", 3, 4 },	/* [path] type hook peerhook */
	{ "connect", 3, 4 },	/* [path] relpath hook peerhook */
	{ "rmhook", 1, 2 },	/* [path] hook */
	{ "shutdown", 1, 1 },	/* path */
	{ "name", 2, 2 },	/* path name */
};

/* A path, a type or a hook: nothing ngctl could read as an option. */
static bool
ng_word(const char *s)
{

	if (s == NULL || s[0] == '\0' || s[0] == '-' || strlen(s) > 64)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("._:-[]", *s) == NULL)
			return (false);
	return (true);
}

/* NULL when ngctl may be run with verb and these arguments. */
const char *
ng_check(const char *verb, const char *const *args, size_t n)
{
	size_t	i, v;

	for (v = 0; v < nitems(ng_verbs); v++)
		if (verb != NULL && strcmp(verb, ng_verbs[v].verb) == 0)
			break;
	if (v == nitems(ng_verbs))
		return ("netgraph: the command is mkpeer, connect, rmhook, "
		    "shutdown or name");
	if (n < ng_verbs[v].min || n > ng_verbs[v].max)
		return ("netgraph: not the arguments the command takes");
	for (i = 0; i < n; i++)
		if (!ng_word(args[i]))
			return ("netgraph: a path, type or hook is letters, "
			    "digits and . _ : - [ ]");
	return (NULL);
}

int
do_ng(struct work *w, const char *verb, const char *const *args, size_t n,
    const char **errp)
{
	struct execres	 res;
	char		*argv[8];
	size_t		 i;

	if ((*errp = ng_check(verb, args, n)) != NULL)
		return (-1);
	argv[0] = (char *)(uintptr_t)opts.ngctl_bin;
	argv[1] = (char *)(uintptr_t)verb;
	for (i = 0; i < n; i++)
		argv[2 + i] = (char *)(uintptr_t)args[i];
	argv[2 + n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ngctl"));
		return (-1);
	}
	return (0);
}
