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
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <ucl.h>
#include <unistd.h>

#include <openssl/evp.h>

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
 * Does the daemon answer?  birdc ends badly when it cannot reach it, or
 * when it goes away under it; a daemon on its way down does not count.
 */
static bool
alive(struct work *w)
{
	struct execres	res;

	return (birdc(w, true, "show", "status", NULL, &res) == 0 &&
	    res.out != NULL && strstr(res.out, "BIRD") != NULL &&
	    strstr(res.out, "Shutdown") == NULL);
}

/*
 * Did BIRD take the configuration it was told to read?  Only what it
 * says when it did counts (cmd_reconfig_msg() in its sysdep/unix/main.c):
 * what it says of a file it cannot parse has no word to look for, and
 * a daemon shutting down ignores the request.
 */
static bool
took(const struct execres *res)
{

	return (res->out != NULL && (strstr(res->out, "Reconfigured") != NULL ||
	    strstr(res->out, "Reconfiguration in progress") != NULL ||
	    strstr(res->out, "queueing new config") != NULL));
}

/* What birdc said, for an error: its lines but the greeting. */
static const char *
said(struct work *w, const struct execres *res)
{
	const char	*p;
	char		*t;

	p = res->out != NULL ? res->out : "";
	if (strncmp(p, "BIRD ", 5) == 0 && strstr(p, " ready.") != NULL &&
	    strchr(p, '\n') != NULL)
		p = strchr(p, '\n') + 1;
	if (p[0] == '\0')
		p = res->err != NULL && res->err[0] != '\0' ? res->err :
		    "it said nothing";
	t = wstrdup(w, p);
	while (t[0] != '\0' && t[strlen(t) - 1] == '\n')
		t[strlen(t) - 1] = '\0';
	return (t);
}

static bool	pending(void);

/* The text after "key:" of a line, when the line starts with key. */
static const char *
after(const char *line, const char *key)
{
	size_t	len;

	len = strlen(key);
	if (strncmp(line, key, len) != 0 || line[len] != ':')
		return (NULL);
	line += len + 1;
	return (line + strspn(line, " \t"));
}

#define	DETAIL_MAX	60	/* lines of a protocol kept as they are */

/*
 * What "show protocols all" says under a protocol's line: kept as it
 * is, up to a point, and the parts a page draws picked out of it.  A
 * BGP neighbour's address and AS, the state of its session; of each
 * channel its table, its filters, and its routes.
 */
static void
proto_line(ucl_object_t *o, ucl_object_t **chanp, char *line)
{
	static const struct {
		const char	*key, *name;
	} top[] = {
		{ "Description", "description" },
		{ "BGP state", "bgp-state" },
		{ "Neighbor address", "neighbor" },
		{ "Neighbor AS", "neighbor-as" },
		{ "Local AS", "local-as" },
		{ "Neighbor ID", "neighbor-id" },
		{ "Source address", "source" },
		{ "Session", "session" },
		{ "Hold timer", "hold" },
		{ "Keepalive timer", "keepalive" },
		{ "Last error", "last-error" },
		{ "Cache server", "cache" },
		{ "Status", "rpki-status" },
		{ "Serial number", "serial" },
		{ "Last update", "last-update" },
	}, chan[] = {
		{ "State", "state" },
		{ "Table", "table" },
		{ "Input filter", "input-filter" },
		{ "Output filter", "output-filter" },
		{ "Routes", "routes" },
	};
	ucl_object_t		*d, *chans, *c;
	const ucl_object_t	*v;
	const char		*t, *val;
	size_t			 i;
	long long		 imp, exp, pref;

	if ((v = ucl_object_lookup(o, "detail")) == NULL) {
		d = ucl_object_typed_new(UCL_ARRAY);
		ucl_object_insert_key(o, d, "detail", 0, false);
	} else
		d = (ucl_object_t *)(uintptr_t)v;
	line[strcspn(line, "\r")] = '\0';
	if (ucl_array_size(d) < DETAIL_MAX)
		ucl_array_append(d, ucl_object_fromstring(line));
	t = line + strspn(line, " \t");
	if (strncmp(t, "Channel ", 8) == 0) {
		if ((v = ucl_object_lookup(o, "channels")) == NULL) {
			chans = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(o, chans, "channels", 0, false);
		} else
			chans = (ucl_object_t *)(uintptr_t)v;
		c = ucl_object_typed_new(UCL_OBJECT);
		put(c, "name", t + 8);
		ucl_array_append(chans, c);
		*chanp = c;
		return;
	}
	if (*chanp != NULL) {
		for (i = 0; i < nitems(chan); i++) {
			if ((val = after(t, chan[i].key)) == NULL)
				continue;
			put(*chanp, chan[i].name, val);
			/* "845233 imported, 12 exported, 400000 preferred" */
			if (i == 4 && sscanf(val, "%lld imported, %lld "
			    "exported, %lld preferred", &imp, &exp, &pref) >=
			    2) {
				ucl_object_insert_key(*chanp, ucl_object_fromint(
				    imp), "imported", 0, false);
				ucl_object_insert_key(*chanp, ucl_object_fromint(
				    exp), "exported", 0, false);
			}
			return;
		}
	}
	for (i = 0; i < nitems(top); i++)
		if ((val = after(t, top[i].key)) != NULL &&
		    ucl_object_lookup(o, top[i].name) == NULL) {
			put(o, top[i].name, val);
			return;
		}
}

static const char *const ospf_cols[] = { "router-id", "pri", "state",
    "dtime", "interface", "address", NULL };
static const char *const bfd_cols[] = { "address", "interface", "state",
    "since", "interval", "timeout", NULL };

/*
 * What "show <what> <which>" lists: "proto1:", a heading whose first
 * word is head, then a line of the columns cols for each, as objects
 * with "proto" besides.
 */
static ucl_object_t *
table(struct work *w, const char *what, const char *which, const char *head,
    const char *const *cols)
{
	struct execres	 res;
	ucl_object_t	*arr, *o;
	char		*text, *line, *proto, *p, *f[8];
	int		 n, ncol;

	for (ncol = 0; cols[ncol] != NULL; ncol++)
		;
	arr = ucl_object_typed_new(UCL_ARRAY);
	if (birdc(w, true, "show", what, which, &res) != 0)
		return (arr);
	proto = NULL;
	text = wstrdup(w, res.out != NULL ? res.out : "");
	while ((line = strsep(&text, "\n")) != NULL) {
		line[strcspn(line, "\r")] = '\0';
		n = (int)strlen(line);
		if (n > 1 && line[n - 1] == ':' && strchr(line, ' ') == NULL) {
			line[n - 1] = '\0';
			proto = line;
			continue;
		}
		p = line;
		for (n = 0; n < ncol; n++) {
			p += strspn(p, " \t");
			if (*p == '\0')
				break;
			f[n] = p;
			p += strcspn(p, " \t");
			if (*p != '\0')
				*p++ = '\0';
		}
		if (n < ncol || proto == NULL || strcmp(f[0], head) == 0)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "proto", proto);
		for (n = 0; n < ncol; n++)
			put(o, cols[n], f[n]);
		ucl_array_append(arr, o);
	}
	return (arr);
}

/*
 * {"status": [...], "protocols": [{"name", "proto", "table", "state",
 * "since", "info", and what proto_line() adds}], "ospf": [{"proto",
 * "router-id", "pri", "state", "dtime", "interface", "address"}],
 * "bfd": [{"proto", "address", "interface", "state", "since",
 * "interval", "timeout"}],
 * "tables": [{"name", "routes", "networks"}]}.
 */
int
do_bird(struct work *w, struct arc_network_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *st, *arr, *o, *chan, *tabs;
	unsigned char	*json;
	char		*text, *line, *f[6], *p, *copy, *names[16];
	long long	 routes, total, nets;
	int		 n, i, ntab, pass;

	rsp->has_ok = true;
	rsp->ok = false;
	if (birdc(w, true, "show", "status", NULL, &res) != 0) {
		if ((rsp->error = scope_missing(w, &res, "birdc(8)",
		    "bird3")) == NULL)
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
	o = chan = NULL;
	if (birdc(w, true, "show", "protocols", "all", &res) == 0) {
		text = wstrdup(w, res.out != NULL ? res.out : "");
		while ((line = strsep(&text, "\n")) != NULL) {
			/* Indented: of the protocol whose line came before. */
			if (line[0] == ' ' || line[0] == '\t') {
				if (o != NULL)
					proto_line(o, &chan, line);
				continue;
			}
			/* Name Proto Table State Since Info */
			copy = wstrdup(w, line);
			p = copy;
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
			chan = NULL;
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

	/* The OSPF neighbours, and the BFD sessions, alike. */
	ucl_object_insert_key(top, table(w, "ospf", "neighbors", "Router",
	    ospf_cols), "ospf", 0, false);
	ucl_object_insert_key(top, table(w, "bfd", "sessions", "IP",
	    bfd_cols), "bfd", 0, false);

	/* The tables, and how much each holds: ROA tables among them. */
	tabs = ucl_object_typed_new(UCL_ARRAY);
	ntab = 0;
	if (birdc(w, true, "show", "symbols", "table", &res) == 0) {
		text = wstrdup(w, res.out != NULL ? res.out : "");
		while ((line = strsep(&text, "\n")) != NULL && ntab < 16) {
			n = (int)strcspn(line, " \t");
			if (n == 0 || strstr(line + n, "table") == NULL ||
			    strncmp(line, "BIRD", 4) == 0)
				continue;
			line[n] = '\0';
			for (i = 0; line[i] != '\0'; i++)
				if (!isalnum((unsigned char)line[i]) &&
				    line[i] != '_')
					break;
			if (line[i] == '\0')
				names[ntab++] = line;
		}
	}
	for (i = 0; i < ntab; i++) {
		char *argv[8];

		argv[0] = (char *)(uintptr_t)opts.birdc_bin;
		argv[1] = (char *)(uintptr_t)"-r";
		argv[2] = (char *)(uintptr_t)"show";
		argv[3] = (char *)(uintptr_t)"route";
		argv[4] = (char *)(uintptr_t)"table";
		argv[5] = names[i];
		argv[6] = (char *)(uintptr_t)"count";
		argv[7] = NULL;
		if (run_exec(w, argv, &res) != 0 || res.out == NULL)
			continue;
		for (p = wstrdup(w, res.out); p != NULL && *p != '\0';
		    p = strchr(p, '\n'), p = p != NULL ? p + 1 : NULL)
			if (sscanf(p, "%lld of %lld routes for %lld networks",
			    &routes, &total, &nets) == 3) {
				o = ucl_object_typed_new(UCL_OBJECT);
				put(o, "name", names[i]);
				ucl_object_insert_key(o, ucl_object_fromint(
				    total), "routes", 0, false);
				ucl_object_insert_key(o, ucl_object_fromint(nets),
				    "networks", 0, false);
				ucl_array_append(tabs, o);
				break;
			}
	}
	ucl_object_insert_key(top, tabs, "tables", 0, false);

	/* Too much to carry: again, without the lines kept as they are. */
	json = NULL;
	for (pass = 0; pass < 2; pass++) {
		json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
		if (json == NULL || strlen((char *)json) <= ARC_MAX_JSON)
			break;
		free(json);
		json = NULL;
		for (i = 0; i < (int)ucl_array_size(arr); i++)
			ucl_object_delete_key((ucl_object_t *)(uintptr_t)
			    ucl_array_find_index(arr, (unsigned int)i),
			    "detail");
	}
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "what birdc says is more than a reply carries";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

/* A word birdc is given as it is: a name, an address, a prefix. */
static bool
route_word(const char *s, const char *more)
{

	if (s[0] == '\0' || s[0] == '-' || strlen(s) > 64)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr(more, *s) == NULL)
			return (false);
	return (true);
}

/*
 * What to show of the routes, in birdc's own words, each checked: for
 * and an address, or a prefix; protocol or export and a name; table and
 * a name; all.  The words, NULL-ended, or NULL with why not.
 */
static char **
route_words(struct work *w, const char *filter, const char **errp)
{
	char	**v, *text, *word, *next;
	int	  n;

	v = wcalloc(w, 12, sizeof(*v));
	n = 0;
	text = wstrdup(w, filter != NULL ? filter : "");
	while ((word = strsep(&text, " ,")) != NULL) {
		if (word[0] == '\0')
			continue;
		if (n > 8)
			goto bad;
		if (strcmp(word, "all") == 0 || strcmp(word, "primary") == 0) {
			v[n++] = word;
			continue;
		}
		if (strcmp(word, "for") == 0 || strcmp(word, "protocol") == 0 ||
		    strcmp(word, "export") == 0 || strcmp(word, "table") == 0) {
			do
				next = strsep(&text, " ,");
			while (next != NULL && next[0] == '\0');
			if (next == NULL || !route_word(next, word[0] == 'f' ?
			    ".:/" : "_"))
				goto bad;
			v[n++] = word;
			v[n++] = next;
			continue;
		}
		/* A prefix, or an address for the route that covers it. */
		if (!route_word(word, ".:/") || !isxdigit((unsigned char)
		    word[0]) || (strchr(word, '.') == NULL && strchr(word,
		    ':') == NULL))
			goto bad;
		if (strchr(word, '/') == NULL)
			v[n++] = wstrdup(w, "for");
		v[n++] = word;
	}
	v[n] = NULL;
	return (v);
bad:
	*errp = "say which routes in birdc's words: a prefix, for and an "
	    "address, protocol or export and a protocol's name, table and a "
	    "table's name, all";
	return (NULL);
}

#define	BIRD_ROUTES_MAX	2000

/*
 * {"routes": [{"table", "prefix", "type", "protocol", "since", "from",
 * "primary", "preference", "info", "nexthops": [{"via", "interface"}],
 * "attrs": [...]}], "count"}.  A table can hold a million routes: they
 * are counted first, and more than a page shows are not asked for.
 */
int
do_bird_routes(struct work *w, const char *filter, struct arc_network_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *arr, *o, *nh, *hops, *attrs;
	unsigned char	*json;
	char		**words, *argv[16], *text, *line, *p, *q, *e;
	char		 table[64], prefix[80];
	long long	 routes, total, nets, sum;
	int		 n, i;

	rsp->has_ok = true;
	rsp->ok = false;
	if ((words = route_words(w, filter, &rsp->error)) == NULL)
		return (0);
	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.birdc_bin;
	argv[n++] = (char *)(uintptr_t)"-r";
	argv[n++] = (char *)(uintptr_t)"show";
	argv[n++] = (char *)(uintptr_t)"route";
	for (i = 0; words[i] != NULL; i++)
		if (strcmp(words[i], "all") != 0)
			argv[n++] = words[i];
	argv[n] = (char *)(uintptr_t)"count";
	argv[n + 1] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		if ((rsp->error = scope_missing(w, &res, "birdc(8)",
		    "bird3")) == NULL)
			rsp->error = wtext(w, exec_error(w, &res, "birdc"));
		return (0);
	}
	sum = 0;
	for (p = wstrdup(w, res.out != NULL ? res.out : ""); p != NULL &&
	    *p != '\0'; p = strchr(p, '\n'), p = p != NULL ? p + 1 : NULL)
		if (sscanf(p, "%lld of %lld routes for %lld networks", &routes,
		    &total, &nets) == 3)
			sum += routes;
	rsp->has_total = true;
	rsp->total = (uint64_t)sum;
	if (sum > BIRD_ROUTES_MAX) {
		rsp->truncated = true;
		rsp->error = wfmt(w, "%lld routes: more than the %d shown at "
		    "once.  Say which: a prefix, or for and an address", sum,
		    BIRD_ROUTES_MAX);
		return (0);
	}
	n = 4;
	for (i = 0; words[i] != NULL; i++)
		argv[n++] = words[i];
	argv[n] = NULL;
	if (run_exec_max(w, argv, &res, ARC_MAX_JSON / 2) != 0 ||
	    res.truncated) {
		rsp->error = res.truncated ? "what birdc says of these routes "
		    "is more than a reply carries: ask for fewer, or without "
		    "all" : wtext(w, exec_error(w, &res, "birdc"));
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	o = hops = attrs = NULL;
	table[0] = prefix[0] = '\0';
	text = wstrdup(w, res.out != NULL ? res.out : "");
	while ((line = strsep(&text, "\n")) != NULL) {
		if (line[0] == '\0' || strstr(line, " ready.") != NULL ||
		    strncmp(line, "Access restricted", 17) == 0)
			continue;
		if (strncmp(line, "Table ", 6) == 0) {
			snprintf(table, sizeof(table), "%.*s", (int)strcspn(
			    line + 6, ":"), line + 6);
			continue;
		}
		p = line + strspn(line, " \t");
		/* A route's own line has its protocol in brackets second. */
		q = p + strcspn(p, " \t");
		if (line[0] != ' ' && line[0] != '\t') {
			/* It starts with the prefix; the route follows. */
			if (*q == '\0' || !isxdigit((unsigned char)p[0]) ||
			    strchr(q, '[') == NULL) {
				put(top, "message", line);
				continue;
			}
			snprintf(prefix, sizeof(prefix), "%.*s", (int)(q - p),
			    p);
			p = q + strspn(q, " \t");
			q = p + strcspn(p, " \t");
		}
		if (q[0] != '\0' && q[strspn(q, " \t")] == '[') {
			o = ucl_object_typed_new(UCL_OBJECT);
			hops = attrs = NULL;
			put(o, "table", table);
			put(o, "prefix", prefix);
			put(o, "type", wstrndup(w, p, (size_t)(q - p)));
			p = strchr(q, '[') + 1;
			if ((e = strchr(p, ']')) == NULL)
				e = p + strlen(p);
			q = wstrndup(w, p, (size_t)(e - p));
			put(o, "protocol", wstrndup(w, q, strcspn(q, " ")));
			if ((p = strstr(q, " from ")) != NULL) {
				put(o, "from", p + 6);
				*p = '\0';
			}
			if (strchr(q, ' ') != NULL)
				put(o, "since", strchr(q, ' ') + 1);
			p = *e != '\0' ? e + 1 : e;
			q = strchr(p, '(');
			/* The best one: *, or ! when the kernel has not got it. */
			n = (int)(q != NULL ? (size_t)(q - p) : strlen(p));
			ucl_object_insert_key(o, ucl_object_frombool(memchr(p,
			    '*', (size_t)n) != NULL || memchr(p, '!',
			    (size_t)n) != NULL), "primary", 0, false);
			if (q != NULL && (e = strchr(q, ')')) != NULL) {
				put(o, "preference", wstrndup(w, q + 1,
				    (size_t)(e - q - 1)));
				if ((p = strchr(e, '[')) != NULL && (e =
				    strchr(p, ']')) != NULL)
					put(o, "info", wstrndup(w, p + 1,
					    (size_t)(e - p - 1)));
			}
			ucl_array_append(arr, o);
			continue;
		}
		if (o == NULL)
			continue;
		/* Of the route above: where it leads, or what it carries. */
		if (strncmp(p, "via ", 4) == 0 || strncmp(p, "dev ", 4) == 0) {
			nh = ucl_object_typed_new(UCL_OBJECT);
			if (p[0] == 'v') {
				put(nh, "via", wstrndup(w, p + 4, strcspn(p + 4,
				    " ")));
				if ((q = strstr(p, " on ")) != NULL)
					put(nh, "interface", wstrndup(w, q + 4,
					    strcspn(q + 4, " ")));
			} else
				put(nh, "interface", wstrndup(w, p + 4,
				    strcspn(p + 4, " ")));
			if (hops == NULL) {
				hops = ucl_object_typed_new(UCL_ARRAY);
				ucl_object_insert_key(o, hops, "nexthops", 0,
				    false);
			}
			ucl_array_append(hops, nh);
			continue;
		}
		if (attrs == NULL) {
			attrs = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(o, attrs, "attrs", 0, false);
		}
		ucl_array_append(attrs, ucl_object_fromstring(p));
	}
	ucl_object_insert_key(top, arr, "routes", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(sum), "count", 0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "these routes are more than a reply carries";
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
	/* Told to read its configuration, BIRD stops its own undo timer. */
	if (strcmp(verb, "configure") == 0 && pending()) {
		*errp = "a change to BIRD's configuration waits to be "
		    "confirmed: it stays or is taken back first";
		return (-1);
	}
	if (birdc(w, false, verb, n == 1 ? names[0] : NULL, NULL, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "birdc"));
		return (-1);
	}
	if (strcmp(verb, "configure") == 0 && !took(&res)) {
		*errp = wfmt(w, "BIRD did not take its configuration: %s",
		    said(w, &res));
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

/*
 * BIRD's configuration: its main file and what that includes.  A file
 * is read whole and put back whole; before the daemon is told of a new
 * one, bird(8) parses the whole configuration, and what it refuses
 * does not stay.
 */

/*
 * Is path the main file, or a .conf under the directory it is in?  In
 * a jail the names are the jail's, and say nothing of where they lead:
 * there the file is opened beneath the jail's root in any case.
 */
static bool
conf_file_ok(struct work *w, const char *path)
{
	char		 real[PATH_MAX], dir[PATH_MAX], *slash;
	size_t		 len;

	if (strcmp(path, opts.bird_conf) == 0)
		return (true);
	len = strlen(path);
	if (len < 6 || strcmp(path + len - 5, ".conf") != 0 || strstr(path,
	    "/../") != NULL || strstr(path, "/./") != NULL)
		return (false);
	if (w->jail != NULL) {
		strlcpy(dir, opts.bird_conf, sizeof(dir));
		if ((slash = strrchr(dir, '/')) == NULL)
			return (false);
		slash[1] = '\0';
		return (strncmp(path, dir, strlen(dir)) == 0);
	}
	if (realpath(path, real) == NULL || realpath(opts.bird_conf, dir) ==
	    NULL || (slash = strrchr(dir, '/')) == NULL)
		return (false);
	slash[1] = '\0';
	return (strncmp(real, dir, strlen(dir)) == 0);
}

static const char *
sha_hex(struct work *w, const char *data, size_t len)
{
	unsigned char	md[32];
	unsigned int	n;
	char		*hex;
	int		 i;

	if (EVP_Digest(data, len, md, &n, EVP_sha256(), NULL) != 1)
		return ("");
	hex = wmalloc(w, 65);
	for (i = 0; i < 32; i++)
		snprintf(hex + i * 2, 3, "%02x", md[i]);
	return (hex);
}

/*
 * A configuration put in place in safe mode, waiting to be confirmed:
 * BIRD was told to take it back by itself when the time is up
 * (configure timeout), and the file is put back then too.  One at a
 * time.
 */
static pthread_mutex_t	pend_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	pend_cv = PTHREAD_COND_INITIALIZER;
static struct {
	bool	 active, confirmed;
	char	*jail;			/* whose BIRD, or NULL the host's */
	char	*path, *base, *bak;
	char	*sha;			/* of the text put in place */
	bool	 had;
	time_t	 by;
} pend;

static bool
pending(void)
{
	bool	p;

	pthread_mutex_lock(&pend_lock);
	p = pend.active;
	pthread_mutex_unlock(&pend_lock);
	return (p);
}

/*
 * The file as it was before the change that was not confirmed, and BIRD
 * running what the file says.  Only a file that is still the text put
 * there is touched: what somebody changed since is theirs.  And only
 * for a BIRD that answers: one that died is not undone after.
 */
static void
pend_back(struct work *w, bool dead)
{
	struct execres	 res;
	const char	*e;
	char		*now;
	size_t		 len;

	e = NULL;
	if (scope_enter(w, pend.jail, &e) != 0) {
		logmsg(LOG_ERR, "bird: the change to %s was not confirmed, and "
		    "the file could not be put back: %s", pend.path, e);
		return;
	}
	if ((now = scope_slurp(w, pend.path, &len)) == NULL || strcmp(
	    sha_hex(w, now, len), pend.sha) != 0) {
		logmsg(LOG_WARNING, "bird: the change to %s was not confirmed, "
		    "but the file is no longer the one put there: left as "
		    "it is", pend.path);
		return;
	}
	/*
	 * A BIRD that went away has no timer left to take anything back
	 * with, and nothing is taken back for it: the file parses, and is
	 * what it reads when it is started again.
	 */
	if (dead || !alive(w)) {
		logmsg(LOG_ERR, "bird: BIRD stopped answering after the change "
		    "to %s, which was not confirmed: the file is left in "
		    "place, for BIRD to read when it is started again",
		    pend.path);
		return;
	}
	if (scope_rename(w, pend.path, pend.had ? pend.bak : pend.base,
	    pend.had ? pend.base : NULL) != 0) {
		logmsg(LOG_ERR, "bird: the change to %s was not confirmed, and "
		    "the file could not be put back: %s", pend.path,
		    strerror(errno));
		return;
	}
	/*
	 * BIRD went back by itself when its time was up, and reading the
	 * file again changes nothing then.  Had it been started anew
	 * meanwhile, it would run what the file said then: this is what
	 * takes that back.
	 */
	if (birdc(w, false, "configure", NULL, NULL, &res) != 0 ||
	    !took(&res))
		logmsg(LOG_ERR, "bird: the change to %s was not confirmed; the "
		    "file is as it was, but BIRD did not read it: %s",
		    pend.path, said(w, &res));
	else
		logmsg(LOG_WARNING, "bird: the change to %s was not confirmed "
		    "in time: BIRD took it back, and the file is as it was",
		    pend.path);
}

static void *
pend_wait(void *arg __unused)
{
	struct timespec	 ts;
	struct work	 w;
	const char	*e;
	bool		 keep, dead;
	int		 n;

	dead = false;
	pthread_mutex_lock(&pend_lock);
	for (n = 1; !pend.confirmed && !dead && !changes_stopping() &&
	    time(NULL) < pend.by + 2; n++) {
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 1;
		(void)pthread_cond_timedwait(&pend_cv, &pend_lock, &ts);
		if (pend.confirmed || n % 3 != 0)
			continue;
		/* A daemon the change brought down is not waited for. */
		pthread_mutex_unlock(&pend_lock);
		work_init(&w);
		e = NULL;
		dead = scope_enter(&w, pend.jail, &e) == 0 && !alive(&w);
		work_free(&w);
		pthread_mutex_lock(&pend_lock);
	}
	keep = pend.confirmed;
	/* From here a confirmation comes too late. */
	if (!keep)
		pend.confirmed = true;
	pthread_mutex_unlock(&pend_lock);
	if (!keep) {
		work_init(&w);
		pthread_mutex_lock(&change_lock);
		pend_back(&w, dead);
		pthread_mutex_unlock(&change_lock);
		work_free(&w);
	} else
		logmsg(LOG_INFO, "bird: the change to %s was confirmed",
		    pend.path);
	pthread_mutex_lock(&pend_lock);
	free(pend.jail);
	free(pend.path);
	free(pend.base);
	free(pend.bak);
	free(pend.sha);
	memset(&pend, 0, sizeof(pend));
	pthread_cond_broadcast(&pend_cv);
	pthread_mutex_unlock(&pend_lock);
	return (NULL);
}

static bool
same_jail(const char *a, const char *b)
{

	return (strcmp(a != NULL ? a : "", b != NULL ? b : "") == 0);
}

/* The change that waits stays: BIRD is told, and the file is left. */
static void
pend_confirm(struct work *w, struct arc_bird_config_rsp *rsp)
{
	struct execres	res;

	pthread_mutex_lock(&pend_lock);
	if (!pend.active || pend.confirmed || !same_jail(pend.jail, w->jail)) {
		pthread_mutex_unlock(&pend_lock);
		rsp->error = "no change to BIRD waits to be confirmed: it was "
		    "taken back when its time was up";
		return;
	}
	/* "Nothing to do" is BIRD's word for an undo timer not running. */
	if (birdc(w, false, "configure", "confirm", NULL, &res) != 0 ||
	    res.out == NULL || strstr(res.out, "Reconfiguration confirmed") ==
	    NULL) {
		pthread_mutex_unlock(&pend_lock);
		rsp->error = wfmt(w, "BIRD did not confirm it, and the change "
		    "is taken back: %s", said(w, &res));
		return;
	}
	pend.confirmed = true;
	pthread_cond_broadcast(&pend_cv);
	pthread_mutex_unlock(&pend_lock);
	rsp->ok = true;
}

/* The main file, and the files its include lines name. */
static void
conf_files(struct work *w, struct arc_bird_config_rsp *rsp)
{
	const char	**v, *p, *q, *e;
	char		*text, *pat;
	glob_t		 g;
	size_t		 len, n, i, skip;

	v = wcalloc(w, 66, sizeof(*v));
	n = 0;
	v[n++] = opts.bird_conf;
	if ((text = scope_slurp(w, opts.bird_conf, &len)) != NULL) {
		for (p = text; (p = strstr(p, "include")) != NULL && n < 64;
		    p += 7) {
			if ((p != text && p[-1] != '\n' && p[-1] != ' ' &&
			    p[-1] != '\t') || (q = strchr(p, '"')) == NULL ||
			    (e = strchr(q + 1, '"')) == NULL || memchr(p, '\n',
			    (size_t)(q - p)) != NULL)
				continue;
			pat = wstrndup(w, q + 1, (size_t)(e - q - 1));
			if (pat[0] != '/') {
				/* As BIRD reads it: beside the main file. */
				q = strrchr(opts.bird_conf, '/');
				pat = wfmt(w, "%.*s/%s", q != NULL ? (int)(q -
				    opts.bird_conf) : 1, q != NULL ?
				    opts.bird_conf : ".", pat);
			}
			/* In a jail the names are looked for under its root,
			 * and told as the jail knows them. */
			skip = w->jail != NULL ? strlen(w->jroot) : 0;
			if (glob(skip > 0 ? wfmt(w, "%s%s", w->jroot, pat) :
			    pat, 0, NULL, &g) != 0)
				continue;
			for (i = 0; i < g.gl_pathc && n < 64; i++)
				if (strlen(g.gl_pathv[i]) > skip &&
				    conf_file_ok(w, g.gl_pathv[i] + skip))
					v[n++] = wstrdup(w, g.gl_pathv[i] +
					    skip);
			globfree(&g);
		}
	}
	rsp->files.v = v;
	rsp->files.n = n;
}

int
do_bird_config(struct work *w, const struct arc_bird_config_req *rq,
    struct arc_bird_config_rsp *rsp)
{
	struct execres	 res;
	const char	*path, *sha, *base;
	char		*old, *tmp, *bak, *argv[5];
	size_t		 oldlen, len;
	pthread_t	 thr;
	int		 step, wait;
	bool		 had, up;

	rsp->has_ok = true;
	rsp->ok = false;
	if (rq->confirm) {
		pend_confirm(w, rsp);
		return (0);
	}
	path = rq->conf_path != NULL && rq->conf_path[0] != '\0' ?
	    rq->conf_path : opts.bird_conf;
	if (path[0] != '/' || strstr(path, "/../") != NULL ||
	    (rq->conf_text == NULL && !conf_file_ok(w, path))) {
		rsp->error = wfmt(w, "%s is not a file of BIRD's configuration "
		    "(%s and the .conf files beside it)", path, opts.bird_conf);
		return (0);
	}
	rsp->conf_path = wtext(w, wstrdup(w, path));
	step = step_begin(w, ARC_STEP_KIND_FILE, "read", "%s", path);
	old = scope_slurp(w, path, &oldlen);
	had = old != NULL;
	step_end(w, step, had || (errno == ENOENT && rq->conf_text != NULL),
	    had ? NULL : "%s", strerror(errno));
	if (rq->conf_text == NULL) {
		if (!had) {
			rsp->error = wfmt(w, "%s: %s", path, strerror(errno));
			return (0);
		}
		rsp->conf_text = wtext(w, old);
		rsp->sha256 = sha_hex(w, old, oldlen);
		conf_files(w, rsp);
		rsp->ok = true;
		return (0);
	}
	/* A file to be made: it must be one the configuration would read. */
	if (!had) {
		len = strlen(path);
		tmp = wstrdup(w, opts.bird_conf);
		if (strrchr(tmp, '/') != NULL)
			*(strrchr(tmp, '/') + 1) = '\0';
		if (errno != ENOENT || strncmp(path, tmp, strlen(tmp)) != 0 ||
		    len < 6 || strcmp(path + len - 5, ".conf") != 0) {
			rsp->error = wfmt(w, "%s is not a file of BIRD's "
			    "configuration", path);
			return (0);
		}
		old = wstrdup(w, "");
		oldlen = 0;
	} else if (!conf_file_ok(w, path)) {
		rsp->error = wfmt(w, "%s is not a file of BIRD's configuration",
		    path);
		return (0);
	}
	sha = sha_hex(w, old, oldlen);
	if (rq->sha256 == NULL || strcmp(rq->sha256, sha) != 0) {
		rsp->error = "the file is not the one this was made from: "
		    "somebody changed it meanwhile.  Read it again";
		return (0);
	}
	if (pending()) {
		rsp->error = "a change to BIRD waits to be confirmed: it "
		    "stays or is taken back first";
		return (0);
	}

	len = strlen(rq->conf_text);
	base = strrchr(path, '/') + 1;
	bak = wfmt(w, "%s.arcana-old", base);
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", path);
	/* The old one aside, the new one in its place, to be parsed. */
	if (scope_replace(w, path, rq->conf_text, len, 0640, had ? bak :
	    NULL) == -1) {
		step_end(w, step, false, "%s", strerror(errno));
		rsp->error = wfmt(w, "%s: %s", path, strerror(errno));
		return (0);
	}
	step_end(w, step, true, "the one before it is kept as %s.arcana-old",
	    path);
	argv[0] = (char *)(uintptr_t)opts.bird_bin;
	argv[1] = (char *)(uintptr_t)"-p";
	argv[2] = (char *)(uintptr_t)"-c";
	argv[3] = (char *)(uintptr_t)opts.bird_conf;
	argv[4] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		rsp->error = wfmt(w, "bird does not take it: %s", res.errlen >
		    0 ? res.err : res.out != NULL ? res.out : "no reason given");
		goto back;
	}
	if (rq->dry_run) {
		rsp->ok = true;
		goto back;
	}
	/*
	 * Safe mode is BIRD's own: a daemon that does not answer has no
	 * timer to take the change back with.
	 */
	/* The console's rollback timer for the host, else the agent's. */
	wait = rq->has_safe_wait && rq->safe_wait > 0 ? (int)rq->safe_wait :
	    opts.safe_wait;
	up = alive(w);
	if (!up && rq->safe) {
		rsp->error = "BIRD does not answer: nothing can be changed in "
		    "safe mode, where it is BIRD that takes the change back";
		goto back;
	}
	if (!up) {
		/* Nothing runs to be told: it reads the file when started. */
		rsp->error = "the file is in place and parses; BIRD does not "
		    "answer, and reads it when it is started";
		rsp->conf_text = wtext(w, wstrdup(w, rq->conf_text));
		rsp->sha256 = sha_hex(w, rq->conf_text, len);
		return (0);
	}
	/*
	 * What a BIRD that answers does not take does not stay in the
	 * file either.  One that goes away while it is told is another
	 * matter: the file parses, bird(8) said so, and it stays for BIRD
	 * to read when it is started again.
	 */
	if (birdc(w, false, "configure", rq->safe ? "timeout" : NULL,
	    rq->safe ? wfmt(w, "%d", wait) : NULL, &res) != 0 ||
	    !took(&res)) {
		if (alive(w)) {
			rsp->error = wfmt(w, "BIRD did not take it, and the "
			    "file is as it was: %s", said(w, &res));
			goto back;
		}
		rsp->error = wfmt(w, "BIRD stopped answering when told to read "
		    "the new configuration (%s).  The file is in place and "
		    "parses: BIRD reads it when it is started again",
		    said(w, &res));
		rsp->conf_text = wtext(w, wstrdup(w, rq->conf_text));
		rsp->sha256 = sha_hex(w, rq->conf_text, len);
		return (0);
	}
	(void)usleep(700000);
	if (!alive(w)) {
		rsp->error = "BIRD took the new configuration and then stopped "
		    "answering.  The file is in place and parses: BIRD reads "
		    "it when it is started again";
		rsp->conf_text = wtext(w, wstrdup(w, rq->conf_text));
		rsp->sha256 = sha_hex(w, rq->conf_text, len);
		return (0);
	}
	if (rq->safe) {
		/* BIRD counts from now; so does the file. */
		pthread_mutex_lock(&pend_lock);
		pend.active = true;
		pend.confirmed = false;
		pend.jail = w->jail != NULL ? strdup(w->jail) : NULL;
		pend.path = strdup(path);
		pend.base = strdup(base);
		pend.bak = strdup(bak);
		pend.sha = strdup(sha_hex(w, rq->conf_text, len));
		pend.had = had;
		pend.by = time(NULL) + wait;
		rsp->has_confirm_by = true;
		rsp->confirm_by = pend.by;
		if (pend.path == NULL || pend.base == NULL || pend.bak ==
		    NULL || pend.sha == NULL || pthread_create(&thr, NULL, pend_wait, NULL) != 0)
			err(1, "bird: safe mode");
		pthread_detach(thr);
		pthread_mutex_unlock(&pend_lock);
	}
	rsp->conf_text = wtext(w, wstrdup(w, rq->conf_text));
	rsp->sha256 = sha_hex(w, rq->conf_text, len);
	conf_files(w, rsp);
	rsp->ok = true;
	return (0);
back:
	/* As it was: the one before it back, or the new file gone. */
	step = step_begin(w, ARC_STEP_KIND_FILE, "restore", "%s", path);
	step_end(w, step, scope_rename(w, path, had ? bak : base, had ? base :
	    NULL) == 0, NULL);
	rsp->conf_text = wtext(w, old);
	rsp->sha256 = sha;
	return (0);
}
