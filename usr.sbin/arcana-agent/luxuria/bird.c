/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: the BIRD routing daemon, through birdc(8): what it says of
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

#include <cblink.h>

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
/*
 * One read of BIRD at a time, and the tables' route counts at most
 * every TABLES_EVERY seconds: "show route table X count" walks the
 * whole table (an export feed in BIRD 3), and several at once, the
 * watcher's and the pages', cost BIRD memory it does not give back;
 * on a router with millions of routes, enough to be the end of it.
 */
#define	TABLES_EVERY	300

static pthread_mutex_t	read_lock = PTHREAD_MUTEX_INITIALIZER;
static struct {
	char		 place[64];	/* the jail, "" the host */
	time_t		 at;
	ucl_object_t	*tabs;
} tcache[8];

static int	do_bird_locked(struct work *, struct arc_network_rsp *);

int
do_bird(struct work *w, struct arc_network_rsp *rsp)
{
	int	rc;

	pthread_mutex_lock(&read_lock);
	rc = do_bird_locked(w, rsp);
	pthread_mutex_unlock(&read_lock);
	return (rc);
}

static int
do_bird_locked(struct work *w, struct arc_network_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *st, *arr, *o, *chan, *tabs;
	unsigned char	*json;
	char		*text, *line, *f[6], *p, *copy, *names[16];
	long long	 routes, total, nets;
	int		 n, i, ntab, pass;
	size_t		 cslot = 0;

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

	/* The tables, and how much each holds: ROA tables among them; as
	 * counted the last time, within TABLES_EVERY. */
	{
		const char	*place = w->jail != NULL ? w->jail : "";
		time_t		 now = time(NULL);
		size_t		 k, slot = 0;

		for (k = 0; k < nitems(tcache); k++) {
			if (tcache[k].tabs != NULL && strcmp(tcache[k].place,
			    place) == 0)
				break;
			if (tcache[k].tabs == NULL || tcache[k].at <
			    tcache[slot].at)
				slot = k;
		}
		if (k < nitems(tcache) && now - tcache[k].at < TABLES_EVERY) {
			ucl_object_insert_key(top, ucl_object_copy(tcache[k].tabs),
			    "tables", 0, false);
			goto counted;
		}
		cslot = k < nitems(tcache) ? k : slot;
	}
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
	if (tcache[cslot].tabs != NULL)
		ucl_object_unref(tcache[cslot].tabs);
	tcache[cslot].tabs = ucl_object_ref(tabs);
	tcache[cslot].at = time(NULL);
	snprintf(tcache[cslot].place, sizeof(tcache[cslot].place), "%s",
	    w->jail != NULL ? w->jail : "");
	ucl_object_insert_key(top, tabs, "tables", 0, false);
counted:

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

/*
 * What "show ospf topology all <proto>" says, made an array of areas:
 * each with its routers (distance or unreachable, and links: what, to,
 * metric or metric2) and its transit networks (dr, distance, routers).
 * A line's tabs say where it belongs: none an area, one a router or a
 * network, two what it has.
 */
static ucl_object_t *
ospf_topology(struct work *w, char *text)
{
	ucl_object_t	*areas, *area, *node, *links, *l;
	char		*line, *p, w1[24], w2[80], w3[16];
	long long	 num;
	int		 tabs, n, isnet;

	areas = ucl_object_typed_new(UCL_ARRAY);
	area = node = NULL;
	isnet = 0;
	while ((line = strsep(&text, "\n")) != NULL) {
		for (tabs = 0; line[tabs] == '\t'; tabs++)
			;
		p = line + tabs;
		if ((n = sscanf(p, "%23s %79s %15s %lld", w1, w2, w3, &num)) < 1)
			continue;
		if (tabs == 0 && strcmp(w1, "area") == 0 && n >= 2) {
			area = ucl_object_typed_new(UCL_OBJECT);
			put(area, "area", wstrdup(w, w2));
			ucl_object_insert_key(area, ucl_object_typed_new(
			    UCL_ARRAY), "routers", 0, false);
			ucl_object_insert_key(area, ucl_object_typed_new(
			    UCL_ARRAY), "networks", 0, false);
			ucl_array_append(areas, area);
			node = NULL;
		} else if (tabs == 1 && area != NULL && n >= 2 &&
		    (strcmp(w1, "router") == 0 || strcmp(w1, "network") == 0)) {
			isnet = w1[0] == 'n';
			node = ucl_object_typed_new(UCL_OBJECT);
			put(node, "id", wstrdup(w, w2));
			ucl_object_insert_key(node, ucl_object_typed_new(
			    UCL_ARRAY), isnet ? "routers" : "links", 0, false);
			ucl_array_append((ucl_object_t *)(uintptr_t)
			    ucl_object_lookup(area, isnet ? "networks" :
			    "routers"), node);
		} else if (tabs >= 2 && node != NULL) {
			if (strcmp(w1, "distance") == 0 && n >= 2)
				ucl_object_insert_key(node, ucl_object_fromint(
				    strtoll(w2, NULL, 10)), "distance", 0, false);
			else if (strcmp(w1, "unreachable") == 0)
				ucl_object_insert_key(node,
				    ucl_object_frombool(true), "unreachable", 0,
				    false);
			else if (strcmp(w1, "dr") == 0 && n >= 2)
				put(node, "dr", wstrdup(w, w2));
			else if (isnet && strcmp(w1, "router") == 0 && n >= 2)
				ucl_array_append((ucl_object_t *)(uintptr_t)
				    ucl_object_lookup(node, "routers"),
				    ucl_object_fromstring(w2));
			else if (!isnet && n >= 2) {
				l = ucl_object_typed_new(UCL_OBJECT);
				put(l, "kind", wstrdup(w, w1));
				put(l, "to", wstrdup(w, w2));
				if (n == 4 && (strcmp(w3, "metric") == 0 ||
				    strcmp(w3, "metric2") == 0))
					ucl_object_insert_key(l,
					    ucl_object_fromint(num), w3[6] ==
					    '2' ? "metric2" : "metric", 0, true);
				links = (ucl_object_t *)(uintptr_t)
				    ucl_object_lookup(node, "links");
				ucl_array_append(links, l);
			}
		}
	}
	return (areas);
}

/*
 * BIRD's OSPF protocols, each with the areas it is in; with the filter
 * "topology", or "topology" and a protocol's name, each area's routers
 * and transit networks too, from its link-state database.  Asking one
 * router of an area is enough: every router of it holds the same.
 */
int
do_bird_ospf(struct work *w, const char *filter, struct arc_network_rsp *rsp)
{
	struct execres	 res, r2;
	ucl_object_t	*top, *arr, *po, *areas;
	unsigned char	*json;
	char		*text, *line, *t2, *l2, *argv[8], name[64], proto[16];
	char		 only[64], area[24];
	const char	*p;
	bool		 topology;

	rsp->has_ok = true;
	rsp->ok = false;
	only[0] = '\0';
	topology = false;
	if (filter != NULL && filter[0] != '\0') {
		if (strncmp(filter, "topology", 8) != 0 || (filter[8] != '\0' &&
		    filter[8] != ' ' && filter[8] != ',')) {
			rsp->error = "the filter is topology, or topology and an "
			    "OSPF protocol's name";
			return (0);
		}
		topology = true;
		if (filter[8] != '\0')
			snprintf(only, sizeof(only), "%s", filter + 9);
		for (p = only; *p != '\0'; p++)
			if (!isalnum((unsigned char)*p) && *p != '_') {
				rsp->error = "a protocol's name is letters, "
				    "digits and _";
				return (0);
			}
	}
	if (birdc(w, true, "show", "protocols", NULL, &res) != 0) {
		if ((rsp->error = scope_missing(w, &res, "birdc(8)",
		    "bird3")) == NULL)
			rsp->error = wtext(w, exec_error(w, &res, "birdc"));
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	text = wstrdup(w, res.out != NULL ? res.out : "");
	while ((line = strsep(&text, "\n")) != NULL) {
		if (sscanf(line, "%63s %15s", name, proto) != 2 ||
		    strcmp(proto, "OSPF") != 0 || (only[0] != '\0' &&
		    strcmp(only, name) != 0))
			continue;
		po = ucl_object_typed_new(UCL_OBJECT);
		put(po, "name", wstrdup(w, name));
		areas = ucl_object_typed_new(UCL_ARRAY);
		if (birdc(w, true, "show", "ospf", name, &r2) == 0)
			for (t2 = wstrdup(w, r2.out != NULL ? r2.out : "");
			    (l2 = strsep(&t2, "\n")) != NULL; )
				if (sscanf(l2, " Area: %23s", area) == 1)
					ucl_array_append(areas,
					    ucl_object_fromstring(area));
		ucl_object_insert_key(po, areas, "areas", 0, false);
		if (topology) {
			argv[0] = (char *)(uintptr_t)opts.birdc_bin;
			argv[1] = (char *)(uintptr_t)"-r";
			argv[2] = (char *)(uintptr_t)"show";
			argv[3] = (char *)(uintptr_t)"ospf";
			argv[4] = (char *)(uintptr_t)"topology";
			argv[5] = (char *)(uintptr_t)"all";
			argv[6] = name;
			argv[7] = NULL;
			if (run_exec(w, argv, &r2) == 0)
				ucl_object_insert_key(po, ospf_topology(w,
				    wstrdup(w, r2.out != NULL ? r2.out : "")),
				    "topology", 0, false);
		}
		ucl_array_append(arr, po);
	}
	ucl_object_insert_key(top, arr, "protocols", 0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "this topology is more than a reply carries: ask "
		    "for one protocol";
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
 * BIRD's configuration: its main file and what that includes, the
 * host's or a vnet jail's, as arcana-bird holds it.  A file is read
 * whole and put back whole; before the daemon is told of a new one,
 * bird(8) parses the whole configuration, and what it refuses does
 * not stay.
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

const char *
bird_sha(struct work *w, const char *data, size_t len)
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
 * A configuration put in place by a confirmed commit, waiting to be
 * confirmed: BIRD was told to take it back by itself a little after the
 * commit's timeout (configure timeout), should the agent be gone by
 * then; the commit confirmed, BIRD is told to keep it; undone, to take
 * it back now, and the file is put back.  One at a time.
 */
static pthread_mutex_t	pend_lock = PTHREAD_MUTEX_INITIALIZER;
static struct {
	bool	 active, done;
	char	*jail;			/* whose BIRD, or NULL the host's */
	char	*path, *base, *bak;
	char	*sha;			/* of the text put in place */
	bool	 had;
	time_t	 by;			/* BIRD's own timer runs out */
	cbl_ctx	*ctx;			/* whose datastores say confirmed */
} pend;

/* A job's safe configure: BIRD's own timer runs, and the job's confirm
 * or undo is to come; until then no other change goes to BIRD.  Under
 * pend_lock. */
static bool	job_timer;

static bool
pending(void)
{
	bool	p;

	pthread_mutex_lock(&pend_lock);
	p = pend.active || job_timer;
	pthread_mutex_unlock(&pend_lock);
	return (p);
}

static bool
same_jail(const char *a, const char *b)
{

	return (strcmp(a != NULL ? a : "", b != NULL ? b : "") == 0);
}

/*
 * The file as it was before the change that was not confirmed, and BIRD
 * running what the file says: told to go back (configure undo) where
 * its timer still runs, else to read the file.  Only a file that is
 * still the text put there is touched: what somebody changed since is
 * theirs.  And only for a BIRD that answers: one that died is not
 * undone after.  Under pend_lock.
 */
static void
pend_back(struct work *w)
{
	struct execres	 res;
	const char	*e;
	char		*now;
	size_t		 len;
	bool		 undone;

	e = NULL;
	if (scope_enter(w, pend.jail, &e) != 0) {
		logmsg(LOG_ERR, "bird: the change to %s was not confirmed, and "
		    "the file could not be put back: %s", pend.path, e);
		return;
	}
	if ((now = scope_slurp(w, pend.path, &len)) == NULL || strcmp(
	    bird_sha(w, now, len), pend.sha) != 0) {
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
	if (!alive(w)) {
		logmsg(LOG_ERR, "bird: BIRD stopped answering after the change "
		    "to %s, which was not confirmed: the file is left in "
		    "place, for BIRD to read when it is started again",
		    pend.path);
		return;
	}
	undone = birdc(w, false, "configure", "undo", NULL, &res) == 0 &&
	    res.out != NULL && strstr(res.out, "not available") == NULL &&
	    strstr(res.out, "error") == NULL && strstr(res.out,
	    "Nothing to do") == NULL;
	if (scope_rename(w, pend.path, pend.had ? pend.bak : pend.base,
	    pend.had ? pend.base : NULL) != 0) {
		logmsg(LOG_ERR, "bird: the change to %s was not confirmed, and "
		    "the file could not be put back: %s", pend.path,
		    strerror(errno));
		return;
	}
	/* Its timer gone (BIRD started anew meanwhile): the file read. */
	if (!undone && (birdc(w, false, "configure", NULL, NULL, &res) != 0 ||
	    !took(&res)))
		logmsg(LOG_ERR, "bird: the change to %s was not confirmed; the "
		    "file is as it was, but BIRD did not read it: %s",
		    pend.path, said(w, &res));
	else
		logmsg(LOG_WARNING, "bird: the change to %s was not confirmed "
		    "in time: BIRD took it back, and the file is as it was",
		    pend.path);
}

static void
pend_clear(void)
{

	free(pend.jail);
	free(pend.path);
	free(pend.base);
	free(pend.bak);
	free(pend.sha);
	memset(&pend, 0, sizeof(pend));
}

/*
 * The commit's fate, as its datastores tell it: no longer waiting and
 * not undone (the undo is the edit's, which ends pend), it was
 * confirmed, and BIRD is told to keep the change.  BIRD's timer run
 * out first, the commit gone without a word: the file put back.
 * pend_lock is not held while the datastores are asked: an undo holds
 * their lock and takes it.
 */
static void *
pend_wait(void *arg __unused)
{
	struct execres	 res;
	struct work	 w;
	const char	*e;
	cbl_ctx		*ctx;
	bool		 waits, late;

	for (;;) {
		pthread_mutex_lock(&pend_lock);
		if (pend.done || !pend.active) {
			pthread_mutex_unlock(&pend_lock);
			break;
		}
		ctx = pend.ctx;
		late = time(NULL) >= pend.by + 2;
		pthread_mutex_unlock(&pend_lock);
		waits = !late && cbl_ydatastore_pending(ctx, NULL);
		if (waits) {
			(void)usleep(200000);
			continue;
		}
		pthread_mutex_lock(&change_lock);
		pthread_mutex_lock(&pend_lock);
		if (pend.done || !pend.active) {
			pthread_mutex_unlock(&pend_lock);
			pthread_mutex_unlock(&change_lock);
			break;
		}
		work_init(&w);
		e = NULL;
		if (late)
			pend_back(&w);
		else if (scope_enter(&w, pend.jail, &e) != 0)
			logmsg(LOG_ERR, "bird: the change to %s was confirmed, "
			    "but BIRD could not be told: %s", pend.path, e);
		else if (birdc(&w, false, "configure", "confirm", NULL, &res) !=
		    0 || res.out == NULL || strstr(res.out,
		    "Reconfiguration confirmed") == NULL)
			logmsg(LOG_ERR, "bird: the change to %s was confirmed, "
			    "but BIRD did not keep it: %s", pend.path,
			    said(&w, &res));
		else
			logmsg(LOG_INFO, "bird: the change to %s was confirmed",
			    pend.path);
		work_free(&w);
		pend_clear();
		pthread_mutex_unlock(&pend_lock);
		pthread_mutex_unlock(&change_lock);
		break;
	}
	return (NULL);
}

/*
 * A commit that changes the configuration while a confirmed one waited:
 * that one was confirmed (one undone ended pend, and the datastores let
 * no other commit in while one waits), maybe by this very commit, and
 * BIRD is told to keep it now rather than when the thread next asks.
 * Under change_lock.
 */
void
bird_conf_settle(void)
{
	struct execres	 res;
	struct work	 w;
	const char	*e;

	pthread_mutex_lock(&pend_lock);
	if (!pend.active || pend.done) {
		pthread_mutex_unlock(&pend_lock);
		return;
	}
	work_init(&w);
	e = NULL;
	if (scope_enter(&w, pend.jail, &e) != 0)
		logmsg(LOG_ERR, "bird: the change to %s was confirmed, but BIRD "
		    "could not be told: %s", pend.path, e);
	else if (birdc(&w, false, "configure", "confirm", NULL, &res) != 0 ||
	    res.out == NULL || strstr(res.out, "Reconfiguration confirmed") ==
	    NULL)
		logmsg(LOG_ERR, "bird: the change to %s was confirmed, but BIRD "
		    "did not keep it: %s", pend.path, said(&w, &res));
	else
		logmsg(LOG_INFO, "bird: the change to %s was confirmed",
		    pend.path);
	work_free(&w);
	pend_clear();
	pthread_mutex_unlock(&pend_lock);
}

/* The main file, and the files its include lines name; *np of them. */
const char **
bird_conf_files(struct work *w, size_t *np)
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
	*np = n;
	return (v);
}

/*
 * path, a file of the configuration to be read or put in place: the
 * main one or a .conf beside it, there or (with make) to be made.
 * NULL, or why not.
 */
static const char *
conf_path_bad(struct work *w, const char *path, bool make)
{
	char	*dir;
	size_t	 len;

	if (path[0] != '/' || strstr(path, "/../") != NULL)
		return (wfmt(w, "%s is not a file of BIRD's configuration (%s "
		    "and the .conf files beside it)", path, opts.bird_conf));
	if (conf_file_ok(w, path))
		return (NULL);
	len = strlen(path);
	dir = wstrdup(w, opts.bird_conf);
	if (strrchr(dir, '/') != NULL)
		*(strrchr(dir, '/') + 1) = '\0';
	if (make && strncmp(path, dir, strlen(dir)) == 0 && len >= 6 &&
	    strcmp(path + len - 5, ".conf") == 0)
		return (NULL);
	return (wfmt(w, "%s is not a file of BIRD's configuration", path));
}

/* As it was: the one before it back, or the new file gone. */
static void
conf_unplace(struct work *w, const char *path, bool had, const char *base,
    const char *bak)
{
	int	step;

	step = step_begin(w, ARC_STEP_KIND_FILE, "restore", "%s", path);
	step_end(w, step, scope_rename(w, path, had ? bak : base, had ? base :
	    NULL) == 0, NULL);
}

/*
 * text in path's place (made where it is none), the one before kept
 * beside it as .arcana-old, and the whole configuration parsed: 0, or
 * -1 with the file as it was and why in *errp.  *hadp: there was one;
 * *basep, *bakp: the names to put it back with.
 */
static int
conf_place(struct work *w, const char *path, const char *text, bool *hadp,
    const char **basep, const char **bakp, const char **errp)
{
	struct execres	 res;
	char		*argv[5];
	size_t		 oldlen;
	int		 step;

	*basep = strrchr(path, '/') + 1;
	*bakp = wfmt(w, "%s.arcana-old", *basep);
	*hadp = scope_slurp(w, path, &oldlen) != NULL;
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", path);
	if (scope_replace(w, path, text, strlen(text), 0640, *hadp ? *bakp :
	    NULL) == -1) {
		step_end(w, step, false, "%s", strerror(errno));
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		return (-1);
	}
	step_end(w, step, true, "the one before it is kept as %s.arcana-old",
	    path);
	argv[0] = (char *)(uintptr_t)opts.bird_bin;
	argv[1] = (char *)(uintptr_t)"-p";
	argv[2] = (char *)(uintptr_t)"-c";
	argv[3] = (char *)(uintptr_t)opts.bird_conf;
	argv[4] = NULL;
	if (run_exec(w, argv, &res) == 0)
		return (0);
	*errp = wfmt(w, "bird does not take it: %s", res.errlen > 0 ? res.err :
	    res.out != NULL ? res.out : "no reason given");
	conf_unplace(w, path, *hadp, *basep, *bakp);
	return (-1);
}

int
bird_conf_check(struct work *w, const char *path, const char *text,
    const char **errp)
{
	const char	*base, *bak;
	size_t		 len;
	bool		 had;

	if ((*errp = conf_path_bad(w, path, scope_slurp(w, path, &len) ==
	    NULL)) != NULL)
		return (-1);
	if (pending()) {
		*errp = "a change to BIRD waits to be confirmed: it stays or is "
		    "taken back first";
		return (-1);
	}
	if (conf_place(w, path, text, &had, &base, &bak, errp) != 0)
		return (-1);
	conf_unplace(w, path, had, base, bak);
	return (0);
}

int
bird_conf_put(struct work *w, const char *path, const char *text,
    const char *was, int timeout, cbl_ctx *ctx, const char **errp,
    const char **warnp)
{
	struct execres	 res;
	const char	*base, *bak, *sha;
	char		*old;
	size_t		 oldlen;
	pthread_t	 thr;
	bool		 had;

	*warnp = NULL;
	old = scope_slurp(w, path, &oldlen);
	if ((*errp = conf_path_bad(w, path, old == NULL)) != NULL)
		return (-1);
	sha = bird_sha(w, old != NULL ? old : "", old != NULL ? oldlen : 0);
	if (was != NULL && strcmp(was, sha) != 0) {
		*errp = wfmt(w, "%s is not the one this was made from: somebody "
		    "changed it meanwhile.  Read it again", path);
		return (-1);
	}
	if (pending()) {
		*errp = "a change to BIRD waits to be confirmed: it stays or is "
		    "taken back first";
		return (-1);
	}
	if (conf_place(w, path, text, &had, &base, &bak, errp) != 0)
		return (-1);
	/* Nothing runs to be told: it reads the file when started. */
	if (!alive(w)) {
		*warnp = "the file is in place and parses; BIRD does not "
		    "answer, and reads it when it is started";
		return (0);
	}
	/*
	 * What a BIRD that answers does not take does not stay in the
	 * file either.  One that goes away while it is told is another
	 * matter: the file parses, bird(8) said so, and it stays for BIRD
	 * to read when it is started again.
	 */
	if (birdc(w, false, "configure", timeout > 0 ? "timeout" : NULL,
	    timeout > 0 ? wfmt(w, "%d", timeout + 5) : NULL, &res) != 0 ||
	    !took(&res)) {
		if (alive(w)) {
			*errp = wfmt(w, "BIRD did not take it, and the file is as "
			    "it was: %s", said(w, &res));
			conf_unplace(w, path, had, base, bak);
			return (-1);
		}
		*warnp = wfmt(w, "BIRD stopped answering when told to read the "
		    "new configuration (%s).  The file is in place and parses: "
		    "BIRD reads it when it is started again", said(w, &res));
		return (0);
	}
	(void)usleep(700000);
	if (!alive(w)) {
		*warnp = "BIRD took the new configuration and then stopped "
		    "answering.  The file is in place and parses: BIRD reads "
		    "it when it is started again";
		return (0);
	}
	if (timeout <= 0)
		return (0);
	/* BIRD counts from now, a little longer than the commit. */
	pthread_mutex_lock(&pend_lock);
	pend.active = true;
	pend.done = false;
	pend.jail = w->jail != NULL ? strdup(w->jail) : NULL;
	pend.path = strdup(path);
	pend.base = strdup(base);
	pend.bak = strdup(bak);
	pend.sha = strdup(bird_sha(w, text, strlen(text)));
	pend.had = had;
	pend.by = time(NULL) + timeout + 5;
	pend.ctx = ctx;
	if (pend.path == NULL || pend.base == NULL || pend.bak == NULL ||
	    pend.sha == NULL || pthread_create(&thr, NULL, pend_wait, NULL) !=
	    0)
		err(1, "bird: a confirmed commit");
	pthread_detach(thr);
	pthread_mutex_unlock(&pend_lock);
	return (0);
}

int
bird_conf_undo(struct work *w, const char *path, const char *text,
    const char **errp)
{
	const char	*warn;

	/* The change that waits: BIRD told to go back, the file back. */
	pthread_mutex_lock(&pend_lock);
	if (pend.active && !pend.done && same_jail(pend.jail, w->jail) &&
	    strcmp(pend.path, path) == 0) {
		pend.done = true;
		pend_back(w);
		pend_clear();
		pthread_mutex_unlock(&pend_lock);
		return (0);
	}
	pthread_mutex_unlock(&pend_lock);
	/* One that was not waiting: the text before it put back. */
	if (bird_conf_put(w, path, text, NULL, 0, NULL, errp, &warn) != 0)
		return (-1);
	if (warn != NULL)
		logmsg(LOG_WARNING, "bird: %s put back: %s", path, warn);
	return (0);
}

/*
 * A job's verbs in safe mode.  Enable and disable are undone by their
 * opposite, from the protocol's state before: "down" is disabled, any
 * other state (up, start, …) is enabled, as show protocols says it.
 */
int
bird_proto_enabled(struct work *w, const char *name, bool *enabledp,
    const char **errp)
{
	struct execres	 res;
	const char	*line, *nl, *p;
	size_t		 nl_len, col;

	if (birdc(w, true, "show", "protocols", name, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "birdc"));
		return (-1);
	}
	nl_len = strlen(name);
	for (line = res.out; line != NULL && *line != '\0'; line = *nl !=
	    '\0' ? nl + 1 : nl) {
		nl = line + strcspn(line, "\n");
		if (strncmp(line, "No protocols match", 18) == 0)
			break;
		if (strncmp(line, name, nl_len) != 0 || (line[nl_len] != ' ' &&
		    line[nl_len] != '\t'))
			continue;
		/* Name, Proto, Table, State: the fourth word. */
		p = line + nl_len;
		for (col = 1; col < 3; col++) {
			p += strspn(p, " \t");
			p += strcspn(p, " \t\n");
		}
		p += strspn(p, " \t");
		*enabledp = strncmp(p, "down", 4) != 0 || (p[4] != ' ' &&
		    p[4] != '\t' && p[4] != '\n' && p[4] != '\0');
		return (0);
	}
	*errp = wfmt(w, "BIRD has no protocol %s", name);
	return (-1);
}

/*
 * configure, with BIRD's own timer a little longer than the job's wait:
 * confirmed by the job, or taken back by BIRD itself, whichever comes
 * first.  One at a time: the operation's change, or another job's.
 */
int
bird_configure_safe(struct work *w, int wait, const char **errp)
{
	struct execres	res;

	pthread_mutex_lock(&pend_lock);
	if (pend.active || job_timer) {
		pthread_mutex_unlock(&pend_lock);
		*errp = "a change to BIRD's configuration waits to be "
		    "confirmed: it stays or is taken back first";
		return (-1);
	}
	job_timer = true;
	pthread_mutex_unlock(&pend_lock);
	if (birdc(w, false, "configure", "timeout", wfmt(w, "%d", wait), &res) !=
	    0 || !took(&res)) {
		pthread_mutex_lock(&pend_lock);
		job_timer = false;
		pthread_mutex_unlock(&pend_lock);
		*errp = wfmt(w, "BIRD did not take its configuration: %s",
		    said(w, &res));
		return (-1);
	}
	return (0);
}

/* The job was confirmed: BIRD is told to keep it.  "Nothing to do" is
 * BIRD's word for a timer that has run out: the change is gone. */
int
bird_configure_confirm(struct work *w, const char **errp)
{
	struct execres	res;
	int		rc;

	rc = birdc(w, false, "configure", "confirm", NULL, &res);
	pthread_mutex_lock(&pend_lock);
	job_timer = false;
	pthread_mutex_unlock(&pend_lock);
	if (rc == 0 && res.out != NULL && strstr(res.out, "Reconfiguration "
	    "confirmed") != NULL)
		return (0);
	*errp = res.out != NULL && strstr(res.out, "Nothing to do") != NULL ?
	    "its timer had run out, and BIRD had taken the change back" :
	    wfmt(w, "BIRD did not confirm it: %s", said(w, &res));
	return (-1);
}

/* The job was not confirmed: BIRD is told to take it back now. */
int
bird_configure_undo(struct work *w, const char **errp)
{
	struct execres	res;
	int		rc;

	rc = birdc(w, false, "configure", "undo", NULL, &res);
	pthread_mutex_lock(&pend_lock);
	job_timer = false;
	pthread_mutex_unlock(&pend_lock);
	if (rc != 0) {
		*errp = wtext(w, exec_error(w, &res, "birdc"));
		return (-1);
	}
	if (res.out != NULL && (strstr(res.out, "not available") != NULL ||
	    strstr(res.out, "error") != NULL)) {
		*errp = wfmt(w, "BIRD did not take it back: %s", said(w, &res));
		return (-1);
	}
	return (0);
}
