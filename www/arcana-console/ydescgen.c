/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What the console's schema tables (cblink-gen's) leave out of Arcana's
 * modules and a form needs (PLAN-SDN-YANG 4.8.3): each node's
 * description, its place among its siblings as the module writes them
 * (the tables keep them by SID), its type's name where a typedef gives
 * one; the descriptions of each enum, identity and module.  Run at the
 * build over the modules the tables are made of, compiled by libyang as
 * cblink-gen compiles them (the same features, the deviations applied),
 * it writes them as a C table sorted by key (ydesc.h):
 *
 *	/m:a/b		a data node, by its schema-node path as RFC 9595's
 *			.sid files name it (ysids_node_path())
 *	/m:a/b=x	enum x of leaf or leaf-list /m:a/b
 *	/m:a/(c)	choice c below /m:a, /m:a/(c)/(k) its case k
 *	m:i		identity i of module m
 *	m		module m
 *
 * Only what modules named arcana-* define.
 *
 *	ydescgen [-F module:features] [-p dir] -o out.c module.yang ...
 */

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

struct ent {
	char		*key;
	const char	*dsc;
	const char	*tname;
	uint32_t	 order;
};

static struct ent	*ents;
static size_t		 nents, capents;
static uint32_t		 counter;

static bool
ours(const struct lys_module *m)
{

	return (m != NULL && strncmp(m->name, "arcana-", 7) == 0);
}

static void
add(char *key, const char *dsc, const char *tname, uint32_t order)
{

	if (nents == capents) {
		capents = capents == 0 ? 1024 : capents * 2;
		if ((ents = reallocarray(ents, capents, sizeof(*ents))) ==
		    NULL)
			err(1, "reallocarray");
	}
	ents[nents].key = key;
	ents[nents].dsc = dsc;
	ents[nents].tname = tname;
	ents[nents++].order = order;
}

/* A node's schema-node path: choices and cases left out, each name with
 * its module where that is not its parent's. */
static char *
path_of(const struct lysc_node *n)
{
	const struct lysc_node	*chain[128];
	const struct lys_module	*prev = NULL;
	size_t			 nc = 0, len = 0;
	char			*buf, *p;

	for (; n != NULL; n = n->parent) {
		if ((n->nodetype & (LYS_CHOICE | LYS_CASE)) != 0)
			continue;
		if (nc == sizeof(chain) / sizeof(chain[0]))
			errx(1, "a path too deep");
		chain[nc++] = n;
		len += strlen(n->module->name) + strlen(n->name) + 3;
	}
	if ((buf = malloc(len + 1)) == NULL)
		err(1, "malloc");
	p = buf;
	*p = '\0';
	while (nc-- > 0) {
		n = chain[nc];
		if (n->module != prev)
			p += sprintf(p, "/%s:%s", n->module->name, n->name);
		else
			p += sprintf(p, "/%s", n->name);
		prev = n->module;
	}
	return (buf);
}

/* The data node a choice or a case is below: its path, "" at the top. */
static char *
choice_key(const struct lysc_node *n)
{
	const struct lysc_node	*p, *ch, *cs;
	char			*base, *key;

	for (p = n->parent; p != NULL && (p->nodetype & (LYS_CHOICE |
	    LYS_CASE)) != 0; p = p->parent)
		;
	base = p != NULL ? path_of(p) : strdup("");
	if (base == NULL)
		err(1, "strdup");
	if (n->nodetype == LYS_CHOICE) {
		ch = n;
		cs = NULL;
	} else {
		ch = n->parent;
		cs = n;
	}
	if (cs != NULL) {
		if (asprintf(&key, "%s/(%s)/(%s)", base, ch->name,
		    cs->name) == -1)
			err(1, "asprintf");
	} else if (asprintf(&key, "%s/(%s)", base, ch->name) == -1)
		err(1, "asprintf");
	free(base);
	return (key);
}

static const struct lysc_type *
type_of(const struct lysc_node *n)
{

	if (n->nodetype == LYS_LEAF)
		return (((const struct lysc_node_leaf *)n)->type);
	if (n->nodetype == LYS_LEAFLIST)
		return (((const struct lysc_node_leaflist *)n)->type);
	return (NULL);
}

static LY_ERR
visit(struct lysc_node *n, void *data, ly_bool *dfs_continue)
{
	const struct lysc_type	*t;
	char			*path, *key;

	(void)data;
	(void)dfs_continue;
	counter++;
	if (!ours(n->module))
		return (LY_SUCCESS);
	if ((n->nodetype & (LYS_CHOICE | LYS_CASE)) != 0) {
		add(choice_key(n), n->dsc, NULL, counter);
		return (LY_SUCCESS);
	}
	path = path_of(n);
	t = type_of(n);
	add(path, n->dsc, t != NULL ? t->name : NULL, counter);
	if (t != NULL && t->basetype == LY_TYPE_ENUM) {
		const struct lysc_type_enum *e =
		    (const struct lysc_type_enum *)t;
		LY_ARRAY_COUNT_TYPE i;

		LY_ARRAY_FOR(e->enums, i) {
			if (e->enums[i].dsc == NULL)
				continue;
			if (asprintf(&key, "%s=%s", path, e->enums[i].name) ==
			    -1)
				err(1, "asprintf");
			add(key, e->enums[i].dsc, NULL, 0);
		}
	}
	return (LY_SUCCESS);
}

static int
by_key(const void *a, const void *b)
{
	const struct ent *x = a, *y = b;

	return (strcmp(x->key, y->key));
}

static void
put_str(FILE *fp, const char *s)
{

	if (s == NULL) {
		fputs("NULL", fp);
		return;
	}
	fputc('"', fp);
	for (; *s != '\0'; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\')
			fprintf(fp, "\\%c", c);
		else if (c == '\n')
			fputs("\\n", fp);
		else if (c == '?')
			fputs("\\?", fp);	/* no trigraph */
		else if (c < 0x20 || c == 0x7f)
			fprintf(fp, "\\%03o", c);
		else
			fputc(c, fp);
	}
	fputc('"', fp);
}

static void
usage(void)
{

	fprintf(stderr, "usage: ydescgen [-F module:features] [-p dir] "
	    "-o out.c module.yang ...\n");
	exit(2);
}

static void
logged(LY_LOG_LEVEL level, const char *msg, const char *data_path,
    const char *schema_path, uint64_t line)
{

	(void)data_path;
	(void)line;
	if (level == LY_LLERR)
		warnx("libyang: %s%s%s", msg, schema_path != NULL ? " at " :
		    "", schema_path != NULL ? schema_path : "");
}

int
main(int argc, char **argv)
{
	const char		*specs[128], *dirs[16], *out = NULL;
	const char		*none[] = { NULL };
	size_t			 nspecs = 0, ndirs = 0;
	struct ly_ctx		*ctx;
	struct lys_module	*mod;
	uint32_t		 idx;
	FILE			*fp;
	char			*tmp, *key;
	int			 ch;

	while ((ch = getopt(argc, argv, "F:o:p:")) != -1)
		switch (ch) {
		case 'F':
			if (nspecs == sizeof(specs) / sizeof(specs[0]))
				errx(2, "too many -F");
			specs[nspecs++] = optarg;
			break;
		case 'o':
			out = optarg;
			break;
		case 'p':
			if (ndirs == sizeof(dirs) / sizeof(dirs[0]))
				errx(2, "too many -p");
			dirs[ndirs++] = optarg;
			break;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;
	if (out == NULL || argc == 0)
		usage();
	ly_set_log_clb(logged);
	if (ly_ctx_new(".", LY_CTX_DISABLE_SEARCHDIR_CWD |
	    LY_CTX_REF_IMPLEMENTED, &ctx) != LY_SUCCESS)
		errx(1, "libyang: no context");
	for (size_t i = 0; i < ndirs; i++)
		if (ly_ctx_set_searchdir(ctx, dirs[i]) != LY_SUCCESS)
			errx(1, "libyang: %s: not a search directory", dirs[i]);
	for (int i = 0; i < argc; i++)
		if (lys_parse_path(ctx, argv[i], LYS_IN_YANG, NULL) !=
		    LY_SUCCESS)
			errx(1, "%s: does not compile", argv[i]);
	/* The features as cblink-gen sets them: each module's spec, none
	 * for a module named in no spec. */
	idx = 0;
	while ((mod = ly_ctx_get_module_iter(ctx, &idx)) != NULL) {
		const char	*list[64], **feats = none;
		size_t		 nlist = 0, len = strlen(mod->name);
		char		*dup[16];
		size_t		 ndup = 0;

		if (!mod->implemented)
			continue;
		for (size_t j = 0; j < nspecs; j++) {
			char *p, *f;

			if (strncmp(specs[j], mod->name, len) != 0 ||
			    specs[j][len] != ':' || ndup == 16)
				continue;
			if ((dup[ndup] = strdup(specs[j] + len + 1)) == NULL)
				err(1, "strdup");
			for (p = dup[ndup++]; (f = strsep(&p, ",")) != NULL;)
				if (*f != '\0' && nlist < 63)
					list[nlist++] = f;
		}
		list[nlist] = NULL;
		if (nlist > 0)
			feats = list;
		if (!(feats == none && mod->parsed != NULL &&
		    mod->parsed->features == NULL) &&
		    lys_set_implemented(mod, feats) != LY_SUCCESS)
			errx(1, "%s: its features cannot be set", mod->name);
		while (ndup > 0)
			free(dup[--ndup]);
	}
	idx = 0;
	while ((mod = ly_ctx_get_module_iter(ctx, &idx)) != NULL) {
		LY_ARRAY_COUNT_TYPE i;

		if (ours(mod)) {
			if ((key = strdup(mod->name)) == NULL)
				err(1, "strdup");
			add(key, mod->dsc, NULL, 0);
			LY_ARRAY_FOR(mod->identities, i) {
				if (asprintf(&key, "%s:%s", mod->name,
				    mod->identities[i].name) == -1)
					err(1, "asprintf");
				add(key, mod->identities[i].dsc, NULL, 0);
			}
		}
		if (mod->implemented && mod->compiled != NULL &&
		    lysc_module_dfs_full(mod, visit, NULL) != LY_SUCCESS)
			errx(1, "%s: not walked", mod->name);
	}
	qsort(ents, nents, sizeof(*ents), by_key);
	if (asprintf(&tmp, "%s.tmp", out) == -1)
		err(1, "asprintf");
	if ((fp = fopen(tmp, "w")) == NULL)
		err(1, "%s", tmp);
	fputs("/* Written by ydescgen from the modules: do not edit. */\n\n"
	    "#include <stddef.h>\n#include <stdint.h>\n\n#include \"ydesc.h\""
	    "\n\nconst struct ydesc ydesc[] = {\n", fp);
	for (size_t i = 0; i < nents; i++) {
		/* A key twice (a choice's name again in another case): the
		 * first. */
		if (i > 0 && strcmp(ents[i].key, ents[i - 1].key) == 0)
			continue;
		fputs("\t{ ", fp);
		put_str(fp, ents[i].key);
		fputs(", ", fp);
		put_str(fp, ents[i].dsc);
		fputs(", ", fp);
		put_str(fp, ents[i].tname);
		fprintf(fp, ", %u },\n", ents[i].order);
	}
	fputs("};\n\nconst size_t nydesc = sizeof(ydesc) / sizeof(ydesc[0]);\n",
	    fp);
	if (fclose(fp) != 0)
		err(1, "%s", tmp);
	if (rename(tmp, out) != 0)
		err(1, "%s", out);
	ly_ctx_destroy(ctx);
	return (0);
}
