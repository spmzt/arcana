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
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/*
 * {"status": [...], "protocols": [{"name", "proto", "table", "state",
 * "since", "info", and what proto_line() adds}], "ospf": [{"proto",
 * "router-id", "pri", "state", "dtime", "interface", "address"}],
 * "tables": [{"name", "routes", "networks"}]}.
 */
int
do_bird(struct work *w, struct arc_network_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *st, *arr, *o, *chan, *os, *tabs;
	unsigned char	*json;
	char		*text, *line, *f[6], *p, *copy, *proto, *names[16];
	long long	 routes, total, nets;
	int		 n, i, ntab, pass;

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

	/* "ospf1:", a heading, then a line for each neighbour. */
	os = ucl_object_typed_new(UCL_ARRAY);
	if (birdc(w, true, "show", "ospf", "neighbors", &res) == 0) {
		proto = NULL;
		text = wstrdup(w, res.out != NULL ? res.out : "");
		while ((line = strsep(&text, "\n")) != NULL) {
			line[strcspn(line, "\r")] = '\0';
			n = (int)strlen(line);
			if (n > 1 && line[n - 1] == ':' && strchr(line, ' ') ==
			    NULL) {
				line[n - 1] = '\0';
				proto = line;
				continue;
			}
			p = line;
			for (n = 0; n < 6; n++) {
				p += strspn(p, " \t");
				if (*p == '\0')
					break;
				f[n] = p;
				p += strcspn(p, " \t");
				if (*p != '\0')
					*p++ = '\0';
			}
			if (n < 6 || proto == NULL || strcmp(f[0], "Router") == 0)
				continue;
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "proto", proto);
			put(o, "router-id", f[0]);
			put(o, "pri", f[1]);
			put(o, "state", f[2]);
			put(o, "dtime", f[3]);
			put(o, "interface", f[4]);
			put(o, "address", f[5]);
			ucl_array_append(os, o);
		}
	}
	ucl_object_insert_key(top, os, "ospf", 0, false);

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
	int		 step;
	bool		 had;

	rsp->has_ok = true;
	rsp->ok = false;
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
	if (birdc(w, false, "configure", NULL, NULL, &res) != 0 ||
	    (res.out != NULL && (strstr(res.out, "error") != NULL ||
	    strstr(res.out, "Unable to connect") != NULL))) {
		rsp->error = wfmt(w, "the file is in place and parses, but "
		    "the daemon was not told: %s", res.out != NULL &&
		    res.out[0] != '\0' ? res.out : res.err);
		rsp->conf_text = wtext(w, wstrdup(w, rq->conf_text));
		rsp->sha256 = sha_hex(w, rq->conf_text, len);
		return (0);
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
