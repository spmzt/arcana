/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Configured jails, read through jail(8) itself: "jail -f file -e sep"
 * prints every non-wildcard jail with its parameters resolved (globals,
 * "*" blocks, variables, includes).  This file only splits that output.
 */

#include <sys/types.h>

#include <ctype.h>
#include <err.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jailgridd.h"

struct sbuf {
	char	*s;
	size_t	 len;
	size_t	 cap;
};

#define	VEC_PUSH(v, n, cap, x) do {					\
	if ((n) == (cap)) {						\
		(cap) = (cap) == 0 ? 8 : (cap) * 2;			\
		if (((v) = reallocarray((v), (cap), sizeof(*(v)))) ==	\
		    NULL)						\
			err(1, "reallocarray");				\
	}								\
	(v)[(n)++] = (x);						\
} while (0)

static void	sb_add(struct sbuf *, char);
static char	*sb_take(struct work *, struct sbuf *);
static bool	includes_confdir(struct work *, const char *, const char *);

static void
sb_add(struct sbuf *sb, char c)
{

	if (sb->len + 2 > sb->cap) {
		sb->cap = sb->cap == 0 ? 64 : sb->cap * 2;
		if ((sb->s = realloc(sb->s, sb->cap)) == NULL)
			err(1, "realloc");
	}
	sb->s[sb->len++] = c;
	sb->s[sb->len] = '\0';
}

/* The text so far, as a pool string, fit for CBOR; the buffer restarts. */
static char *
sb_take(struct work *w, struct sbuf *sb)
{
	const char	*s;

	s = wtext(w, sb->s != NULL ? wstrndup(w, sb->s, sb->len) : "");
	sb->len = 0;
	if (sb->s != NULL)
		sb->s[0] = '\0';
	return ((char *)(uintptr_t)s);
}

/*
 * Run jail(8) -e on one scope and split what it prints.  Values are
 * written by quoted_print() in usr.sbin/jail/jail.c: quoted with " or '
 * when they contain blanks or quotes, '\' escaping '\' and the quote.
 * Values of one parameter are separated by ','.
 */
int
conf_scope_read(struct work *w, const char *scope, struct cjail **outp,
    size_t *noutp, const char **errp)
{
	struct execres	 res;
	struct sbuf	 cur;
	struct cjail	*jails, j;
	struct jg_param	*params, p;
	const char	**vals;
	char		*argv[6], fopt[] = "-f", eopt[] = "-e";
	char		 sep[] = JAIL_E_SEP;
	const char	*key;
	size_t		 nj, capj, np, capp, nv, capv, i;
	bool		 haveeq, injail;
	char		 c, quote;

	argv[0] = (char *)(uintptr_t)opts.jail_bin;
	argv[1] = fopt;
	argv[2] = (char *)(uintptr_t)scope;
	argv[3] = eopt;
	argv[4] = sep;
	argv[5] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = res.errlen > 0 ? wtext(w, wstrndup(w, res.err,
		    res.errlen > 0 && res.err[res.errlen - 1] == '\n' ?
		    res.errlen - 1 : res.errlen)) : exec_error(w, &res, "jail");
		return (-1);
	}

	jails = NULL;
	nj = capj = 0;
	params = NULL;
	np = capp = 0;
	vals = NULL;
	nv = capv = 0;
	memset(&cur, 0, sizeof(cur));
	memset(&j, 0, sizeof(j));
	key = NULL;
	haveeq = injail = false;
	quote = 0;
	for (i = 0; i <= res.outlen; i++) {
		c = i < res.outlen ? res.out[i] : '\n';
		if (quote != 0) {
			if (c == '\\' && i + 1 < res.outlen)
				sb_add(&cur, res.out[++i]);
			else if (c == quote)
				quote = 0;
			else
				sb_add(&cur, c);
			continue;
		}
		if (c != '\n')
			injail = true;
		if (c == sep[0] || c == '\n' || (c == ',' && haveeq)) {
			if (haveeq)
				VEC_PUSH(vals, nv, capv, sb_take(w, &cur));
			if (c == ',')
				continue;
			if (!haveeq)
				key = sb_take(w, &cur);
			if (key != NULL && strcmp(key, "name") == 0 && nv > 0) {
				j.name = vals[0];
			} else if (key != NULL && *key != '\0') {
				memset(&p, 0, sizeof(p));
				p.key = key;
				p.values.n = nv;
				p.values.v = wadopt(w, vals);
				vals = NULL;
				capv = 0;
				VEC_PUSH(params, np, capp, p);
			}
			free(vals);
			vals = NULL;
			nv = capv = 0;
			key = NULL;
			haveeq = false;
			if (c == '\n' && injail) {
				if (j.name != NULL) {
					j.scope = scope;
					j.params = wadopt(w, params);
					j.nparams = np;
					params = NULL;
					capp = 0;
					VEC_PUSH(jails, nj, capj, j);
				}
				free(params);
				params = NULL;
				np = capp = 0;
				memset(&j, 0, sizeof(j));
				injail = false;
			}
		} else if (c == '=' && !haveeq) {
			key = sb_take(w, &cur);
			haveeq = true;
		} else if ((c == '"' || c == '\'') && haveeq) {
			quote = c;
		} else if (c == '\\' && i + 1 < res.outlen) {
			sb_add(&cur, res.out[++i]);
		} else
			sb_add(&cur, c);
	}
	free(cur.s);
	free(vals);
	free(params);
	*outp = wadopt(w, jails);
	*noutp = nj;
	return (0);
}

/*
 * As rc.d/jail decides: jail.conf.d/<name>.conf files are configurations
 * of their own unless jail.conf includes that directory.
 */
static bool
includes_confdir(struct work *w, const char *main, const char *dir)
{
	FILE	*fp;
	char	*line, *p;
	size_t	 cap, dlen;
	bool	 found;
	int	 step;

	if ((fp = fopen(main, "r")) == NULL)
		return (false);
	step = step_begin(w, JG_STEP_KIND_FILE, "read",
	    "%s: look for .include of %s/", main, dir);
	dlen = strlen(dir);
	line = NULL;
	cap = 0;
	found = false;
	while (!found && getline(&line, &cap, fp) > 0) {
		for (p = line; isspace((unsigned char)*p); p++)
			;
		if (strncmp(p, ".include", 8) != 0)
			continue;
		for (p += 8; isspace((unsigned char)*p) || *p == '"' ||
		    *p == '\''; p++)
			;
		found = strncmp(p, dir, dlen) == 0 && p[dlen] == '/';
	}
	free(line);
	fclose(fp);
	step_end(w, step, true, "%s", found ? "includes it" :
	    "does not include it");
	return (found);
}

void
conf_read(struct work *w, struct cconf *conf)
{
	struct jg_conf_error	 e;
	struct cjail		*js;
	const char		*errs, **scopes;
	glob_t			 g;
	size_t			 i, k, n, ns, caps, capj, cape;
	FILE			*fp;
	char			*pat;

	memset(conf, 0, sizeof(*conf));
	scopes = NULL;
	ns = caps = 0;
	if ((fp = fopen(opts.jail_conf, "r")) != NULL) {
		fclose(fp);
		VEC_PUSH(scopes, ns, caps, wstrdup(w, opts.jail_conf));
	}
	if (!includes_confdir(w, opts.jail_conf, opts.jail_conf_d)) {
		if (asprintf(&pat, "%s/*.conf", opts.jail_conf_d) == -1)
			err(1, "asprintf");
		memset(&g, 0, sizeof(g));
		if (glob(pat, 0, NULL, &g) == 0)
			for (i = 0; i < g.gl_pathc; i++)
				VEC_PUSH(scopes, ns, caps,
				    wstrdup(w, g.gl_pathv[i]));
		globfree(&g);
		free(pat);
	}
	conf->scopes = wadopt(w, scopes);
	conf->nscopes = ns;

	capj = cape = 0;
	for (i = 0; i < ns; i++) {
		if (conf_scope_read(w, scopes[i], &js, &n, &errs) == -1) {
			e.scope = wtext(w, scopes[i]);
			e.message = errs;
			VEC_PUSH(conf->errors, conf->nerrors, cape, e);
			continue;
		}
		/* A name already seen in an earlier scope wins. */
		for (k = 0; k < n; k++)
			if (conf_jail(conf, js[k].name) == NULL)
				VEC_PUSH(conf->jails, conf->njails, capj,
				    js[k]);
	}
	wadopt(w, conf->jails);
	wadopt(w, conf->errors);
}

const struct cjail *
conf_jail(const struct cconf *conf, const char *name)
{
	size_t	i;

	for (i = 0; i < conf->njails; i++)
		if (strcmp(conf->jails[i].name, name) == 0)
			return (&conf->jails[i]);
	return (NULL);
}

const struct jg_param *
cjail_param(const struct cjail *j, const char *key)
{
	size_t	i;

	for (i = 0; j != NULL && i < j->nparams; i++)
		if (strcmp(j->params[i].key, key) == 0)
			return (&j->params[i]);
	return (NULL);
}

const char *
cjail_param1(const struct cjail *j, const char *key)
{
	const struct jg_param	*p;

	if ((p = cjail_param(j, key)) == NULL || p->values.n == 0)
		return (NULL);
	return (p->values.v[0]);
}
