/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * GEOM's classes at work: the geom job, its verb a class (geom(8) runs
 * each's own command, gmirror(8), gstripe(8), geli(8)...), its first
 * word the class's subcommand, of that class's own, the rest its words,
 * flags and names alone, never through a shell.  A GELI passphrase is
 * the job's text, given to geli by a file of the job's own (-J, -j),
 * never on a command line.  gpart(8) has its own job.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

static const struct gclass {
	const char	*name;
	const char	*verbs;		/* its subcommands, space-separated */
} classes[] = {
	{ "mirror", "label clear create configure rebuild insert remove "
	    "deactivate activate forget destroy stop" },
	{ "stripe", "label clear create destroy stop" },
	{ "concat", "label clear create destroy stop" },
	{ "raid3", "label clear configure rebuild insert remove destroy stop" },
	{ "label", "label clear create destroy stop" },
	{ "nop", "create configure destroy reset" },
	{ "multipath", "label clear create add remove fail restore rotate "
	    "destroy stop" },
	{ "shsec", "label clear destroy stop" },
	{ "virstor", "label clear add remove destroy stop" },
	{ "cache", "label clear create configure reset destroy stop" },
	{ "journal", "label clear stop" },
	{ "eli", "init attach detach onetime configure setkey delkey kill "
	    "backup restore resize version clear" },
	{ "union", "create destroy reset commit revert" },
};

/* Those that take a passphrase, and its flag: -J to init and setkey a
 * new one, -j to attach and setkey with the old. */
static const char *
pass_flag(const char *verb)
{

	if (strcmp(verb, "init") == 0)
		return ("-J");
	if (strcmp(verb, "attach") == 0)
		return ("-j");
	if (strcmp(verb, "setkey") == 0)
		return ("-J");
	return (NULL);
}

static const struct gclass *
class_of(const char *name)
{
	size_t	i;

	for (i = 0; i < nitems(classes); i++)
		if (name != NULL && strcmp(classes[i].name, name) == 0)
			return (&classes[i]);
	return (NULL);
}

static bool
has_verb(const struct gclass *c, const char *v)
{
	const char	*p;
	size_t		 n;

	if (strcmp(v, "load") == 0 || strcmp(v, "unload") == 0 || strcmp(v,
	    "list") == 0 || strcmp(v, "status") == 0)
		return (true);
	n = strlen(v);
	for (p = c->verbs; (p = strstr(p, v)) != NULL; p += n)
		if ((p == c->verbs || p[-1] == ' ') && (p[n] == ' ' ||
		    p[n] == '\0'))
			return (true);
	return (false);
}

/* A word of a class's command: a flag, or a name, a size, a provider. */
static bool
word_ok(const char *w)
{
	size_t	n;

	n = strlen(w);
	return (n > 0 && n <= 128 && strspn(w, "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/:=,+-") == n &&
	    strstr(w, "..") == NULL && w[0] != '=');
}

const char *
geom_check(const struct arc_job_spec *sp)
{
	const struct gclass	*c;
	size_t			 i;

	if (sp->jail != NULL && sp->jail[0] != '\0')
		return ("GEOM is the host's");
	if (sp->safe)
		return ("GEOM's changes are not undone: not in safe mode");
	if ((c = class_of(sp->verb)) == NULL)
		return ("a geom job's verb is its class: mirror, stripe, concat, "
		    "raid3, label, nop, multipath, shsec, virstor, cache, "
		    "journal, eli or union");
	if (sp->names.n == 0 || sp->names.v[0] == NULL || !has_verb(c,
	    sp->names.v[0]))
		return ("not a subcommand of the class (its manual says "
		    "them), nor load or unload");
	if (sp->names.n > 32)
		return ("32 words at most");
	for (i = 1; i < sp->names.n; i++)
		if (sp->names.v[i] == NULL || !word_ok(sp->names.v[i]))
			return ("a word is a flag or a name: letters, digits and "
			    ". _ / : = , + -");
	if (sp->text != NULL && sp->text[0] != '\0' && (strcmp(sp->verb,
	    "eli") != 0 || pass_flag(sp->names.v[0]) == NULL))
		return ("a passphrase is geli init's, attach's and setkey's");
	return (NULL);
}

char *
geom_title(const struct arc_job_spec *sp)
{
	char	*t;
	size_t	 i, len;

	if (asprintf(&t, "geom %s %s", sp->verb, sp->names.n > 0 ?
	    sp->names.v[0] : "") == -1)
		return (NULL);
	/* Its last word, the provider most often. */
	if (sp->names.n > 1 && (len = strlen(t)) < 200) {
		i = sp->names.n - 1;
		free(t);
		if (asprintf(&t, "geom %s %s %s", sp->verb, sp->names.v[0],
		    sp->names.v[i]) == -1)
			return (NULL);
	}
	return (t);
}

int
do_geom_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct execres	 res;
	const char	*bin, *pf, *passfile;
	char		*argv[40];
	size_t		 i;
	int		 n, fd, step, rc;

	if ((*errp = geom_check(sp)) != NULL)
		return (-1);
	if ((bin = tool(w, "geom")) == NULL)
		bin = "/sbin/geom";
	passfile = NULL;
	n = 0;
	argv[n++] = (char *)(uintptr_t)bin;
	argv[n++] = (char *)(uintptr_t)sp->verb;
	argv[n++] = (char *)(uintptr_t)sp->names.v[0];
	/* The passphrase by a file of its own, root's alone, gone after. */
	if (sp->text != NULL && sp->text[0] != '\0' &&
	    (pf = pass_flag(sp->names.v[0])) != NULL) {
		passfile = wfmt(w, "%s/arcana-geli.%d", opts.root != NULL ?
		    opts.root : "/tmp", (int)getpid());
		if ((fd = open(passfile, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
		    0600)) == -1 || write(fd, sp->text, strlen(sp->text)) !=
		    (ssize_t)strlen(sp->text) || close(fd) != 0) {
			*errp = wfmt(w, "a file for the passphrase: %s",
			    strerror(errno));
			(void)unlink(passfile);
			return (-1);
		}
		argv[n++] = (char *)(uintptr_t)pf;
		argv[n++] = (char *)(uintptr_t)passfile;
	}
	for (i = 1; i < sp->names.n; i++)
		argv[n++] = (char *)(uintptr_t)sp->names.v[i];
	argv[n] = NULL;
	step = step_begin(w, STEP_EXEC, "geom", "%s %s", sp->verb,
	    sp->names.v[0]);
	rc = run_exec(w, argv, &res);
	if (passfile != NULL) {
		(void)unlink(passfile);
	}
	if (rc != 0) {
		*errp = wtext(w, exec_error(w, &res, wfmt(w, "geom %s %s",
		    sp->verb, sp->names.v[0])));
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, NULL);
	return (0);
}

/* Each class loaded, its providers' status (geom CLASS status -s). */
ucl_object_t *
geom_classes_json(struct work *w)
{
	struct execres	 res;
	ucl_object_t	*o;
	const char	*bin;
	char		*argv[5];
	size_t		 i;

	o = ucl_object_typed_new(UCL_OBJECT);
	if ((bin = tool(w, "geom")) == NULL)
		return (o);
	for (i = 0; i < nitems(classes); i++) {
		argv[0] = (char *)(uintptr_t)bin;
		argv[1] = (char *)(uintptr_t)classes[i].name;
		argv[2] = (char *)(uintptr_t)"status";
		argv[3] = (char *)(uintptr_t)"-s";
		argv[4] = NULL;
		/* A class not loaded says so; it is left out. */
		if (run_exec(w, argv, &res) != 0)
			continue;
		ucl_object_insert_key(o, ucl_object_fromstring(wtext(w,
		    res.out)), classes[i].name, 0, true);
	}
	return (o);
}
