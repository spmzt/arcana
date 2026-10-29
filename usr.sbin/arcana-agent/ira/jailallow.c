/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A jail's permissions: the allow.* parameters of jail(8) (allow.
 * raw_sockets, allow.mount.zfs and the rest this kernel has, read from
 * it by jailparam_all(3)).  The jail-allow job sets each named one on
 * the running jail (jail_set(2) with JAIL_UPDATE, as jail -m does) and
 * in the jail's own file (libjailconf: the statement replaced, or
 * taken out with "unset"), one or both as the job says; a safe job
 * not confirmed puts the live values back and the file as it was.
 * The list read of a running jail carries them as "allow.x=0|1".
 */

#include <sys/param.h>
#include <sys/jail.h>

#include <ctype.h>
#include <errno.h>
#include <jail.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jailconf.h"
#include "agent.h"

#define	ALLOW_MAX	32		/* parameters in one job */

/* One of a job's words: the parameter, and 0, 1 or -1 for unset. */
struct allow_word {
	const char	*name;
	int		 value;
};

/* The allow.* parameters this kernel's jails have, from libjail. */
int
jail_allow_names(struct work *w, const char ***namesp, size_t *np)
{
	struct jailparam	*jp;
	const char		**names;
	size_t			 n, i, k;
	int			 all;

	if ((all = jailparam_all(&jp)) < 0)
		return (-1);
	n = (size_t)all;
	names = wcalloc(w, n + 1, sizeof(*names));
	for (i = k = 0; i < n; i++)
		if (strncmp(jp[i].jp_name, "allow.", 6) == 0)
			names[k++] = wstrdup(w, jp[i].jp_name);
	jailparam_free(jp, n);
	free(jp);
	*namesp = names;
	*np = k;
	return (0);
}

/*
 * The values of a running jail's allow.* parameters, as "name=0|1";
 * names and n as jail_allow_names gives them.  How many, or -1.
 */
int
jail_allow_live(struct work *w, int jid, const char **names, size_t n,
    const char ***outp)
{
	struct jailparam	*jp;
	const char		**out;
	char			*s;
	size_t			 i, k;
	bool			 on;

	if (n == 0) {
		*outp = NULL;
		return (0);
	}
	jp = wcalloc(w, n + 1, sizeof(*jp));
	if (jailparam_init(&jp[0], "jid") == -1 || jailparam_import_raw(&jp[0],
	    &jid, sizeof(jid)) == -1)
		return (-1);
	for (i = k = 0; i < n; i++)
		if (jailparam_init(&jp[k + 1], names[i]) == 0)
			k++;
	if (jailparam_get(jp, k + 1, 0) < 0) {
		jailparam_free(jp, k + 1);
		return (-1);
	}
	out = wcalloc(w, k + 1, sizeof(*out));
	for (i = 0; i < k; i++) {
		s = jailparam_export(&jp[i + 1]);
		on = s != NULL && (strcmp(s, "true") == 0 || strcmp(s, "1") ==
		    0);
		free(s);
		out[i] = wfmt(w, "%s=%d", jp[i + 1].jp_name, on ? 1 : 0);
	}
	jailparam_free(jp, k + 1);
	*outp = out;
	return ((int)k);
}

static bool
jail_word_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 64)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && strchr("_-.", s[i]) == NULL)
			return (false);
	return (true);
}

/* A word "allow.x=0|1|true|false|unset" taken apart; NULL, or why not. */
static const char *
word_parse(const char *word, struct allow_word *aw, char *name, size_t len)
{
	const char	*eq, *v;
	size_t		 i;

	if (word == NULL || (eq = strchr(word, '=')) == NULL || eq == word ||
	    (size_t)(eq - word) >= len)
		return ("each word is allow.name=0, 1 or unset");
	memcpy(name, word, (size_t)(eq - word));
	name[eq - word] = '\0';
	if (strncmp(name, "allow.", 6) != 0 || name[6] == '\0')
		return ("the parameters are jail(8)'s allow.*");
	for (i = 0; name[i] != '\0'; i++)
		if (!isalnum((unsigned char)name[i]) && name[i] != '.' &&
		    name[i] != '_')
			return ("a parameter's name is letters, digits, . and _");
	v = eq + 1;
	if (strcmp(v, "1") == 0 || strcmp(v, "true") == 0)
		aw->value = 1;
	else if (strcmp(v, "0") == 0 || strcmp(v, "false") == 0)
		aw->value = 0;
	else if (strcmp(v, "unset") == 0)
		aw->value = -1;
	else
		return ("a value is 0, 1 or unset (taken out of the file)");
	aw->name = name;
	return (NULL);
}

/* What is wrong with a jail-allow job, or NULL. */
const char *
jail_allow_check(const struct arc_job_spec *sp)
{
	struct allow_word	aw;
	const char		*e;
	char			name[80];
	size_t			i;

	if (!jail_word_ok(sp->jail))
		return ("a jail's name is letters, digits and _ - ., 64 at "
		    "most");
	if (sp->names.n == 0 || sp->names.n > ALLOW_MAX)
		return ("jail-allow takes allow.name=0|1|unset words, 1 to 32");
	if (!sp->live && !sp->persist)
		return ("say live, persist or both");
	for (i = 0; i < sp->names.n; i++) {
		if ((e = word_parse(sp->names.v[i], &aw, name, sizeof(name))) !=
		    NULL)
			return (e);
		if (aw.value < 0 && !sp->persist)
			return ("unset takes a parameter out of the jail's file: "
			    "say persist");
	}
	return (NULL);
}

/* The words parsed, each name one this kernel has; -1 and why not. */
static int
words_parse(struct work *w, const struct arc_job_spec *sp,
    struct allow_word *aws, const char **errp)
{
	const char	**names, *e;
	char		 name[80];
	size_t		 n, i, k;

	if (jail_allow_names(w, &names, &n) != 0) {
		*errp = wfmt(w, "the kernel's jail parameters: %s", jail_errmsg);
		return (-1);
	}
	for (i = 0; i < sp->names.n; i++) {
		if ((e = word_parse(sp->names.v[i], &aws[i], name, sizeof(name)))
		    != NULL) {
			*errp = e;
			return (-1);
		}
		for (k = 0; k < n; k++)
			if (strcmp(names[k], name) == 0)
				break;
		if (k == n) {
			*errp = wfmt(w, "%s: no such parameter on this kernel",
			    name);
			return (-1);
		}
		aws[i].name = wstrdup(w, name);
	}
	return (0);
}

/*
 * The file: the jail's block found through jail.conf and its includes,
 * each statement replaced or taken out, the whole read back, written.
 * -1 and why not; 0 and the diff.
 */
static int
file_change(struct work *w, const struct arc_job_spec *sp,
    const struct allow_word *aws, const char **diffp, const char **errp)
{
	struct cconf		 conf;
	struct jc_conf		 jc;
	struct jc_block		*b;
	struct jc_file		*f;
	const struct cjail	*cj;
	const char		*path, *orig;
	char			*buf, *out, ebuf[512];
	size_t			 len, outlen, origlen, i;
	int			 step, n;

	conf_read(w, &conf);
	if ((cj = conf_jail(&conf, sp->jail)) == NULL) {
		*errp = wfmt(w, "jail '%s' is not defined in any jail.conf; "
		    "nothing to persist to", sp->jail);
		return (-1);
	}
	step = step_begin(w, STEP_LIB, "jc_load(3)", "libjailconf: %s "
	    "and its includes", cj->scope);
	memset(&jc, 0, sizeof(jc));
	if (jc_load(&jc, cj->scope) == -1 || (b = jc_find(&jc, sp->jail, &f)) ==
	    NULL) {
		*errp = wfmt(w, "cannot find the block of jail '%s' in %s%s%s",
		    sp->jail, cj->scope, jc.error != NULL ? ": " : "", jc.error !=
		    NULL ? jc.error : "");
		step_end(w, step, false, "%s", *errp);
		jc_free(&jc);
		return (-1);
	}
	step_end(w, step, true, "block '%s' at %s line %d", sp->jail, f->path,
	    b->line);
	path = wstrdup(w, f->path);
	orig = wtext(w, wstrndup(w, f->buf, f->len));
	origlen = f->len;
	buf = wstrndup(w, f->buf, f->len);
	len = f->len;
	jc_free(&jc);
	/* One at a time, the text parsed again between: a statement's
	 * offsets hold for one edit. */
	for (i = 0; i < sp->names.n; i++) {
		step = step_begin(w, STEP_LIB, "jc_replace(3)", "%s %s "
		    "in %s", aws[i].name, aws[i].value < 0 ? "taken out" :
		    aws[i].value ? "= 1" : "= 0", path);
		memset(&jc, 0, sizeof(jc));
		if (jc_load_buf(&jc, path, buf, len) == -1 || (b = jc_find(&jc,
		    sp->jail, &f)) == NULL) {
			*errp = wfmt(w, "%s: not read back after an edit%s%s",
			    path, jc.error != NULL ? ": " : "", jc.error != NULL ?
			    jc.error : "");
			step_end(w, step, false, "%s", *errp);
			jc_free(&jc);
			return (-1);
		}
		if ((n = jc_replace(f, b, aws[i].name, aws[i].value < 0 ? NULL :
		    aws[i].value ? "1" : "0", &out, &outlen)) < 0) {
			*errp = "out of memory";
			step_end(w, step, false, "%s", *errp);
			jc_free(&jc);
			return (-1);
		}
		jc_free(&jc);
		buf = wadopt(w, out);
		len = outlen;
		step_end(w, step, true, "%d statement%s replaced", n, n == 1 ? "" :
		    "s");
	}
	step = step_begin(w, STEP_LIB, "jc_verify(3)", "re-parse %s",
	    path);
	memset(&jc, 0, sizeof(jc));
	if (jc_load_buf(&jc, path, buf, len) == -1) {
		*errp = wfmt(w, "the edited configuration does not check out%s%s; "
		    "nothing was changed", jc.error != NULL ? ": " : "", jc.error
		    != NULL ? jc.error : "");
		step_end(w, step, false, "%s", *errp);
		jc_free(&jc);
		return (-1);
	}
	jc_free(&jc);
	step_end(w, step, true, NULL);
	*diffp = wtext(w, wadopt(w, jc_diff(path, orig, origlen, buf, len)));
	step = step_begin(w, STEP_LIB, "jc_write(3)", "%s, %zu bytes",
	    path, len);
	if (jc_write(path, buf, len, ebuf, sizeof(ebuf)) == -1) {
		*errp = wtext(w, wstrdup(w, ebuf));
		step_end(w, step, false, "%s", ebuf);
		return (-1);
	}
	step_end(w, step, true, NULL);
	return (0);
}

/* The running jail's parameters set at once: jail -m. */
static int
live_change(struct work *w, int jid, const struct allow_word *aws, size_t n,
    const char **errp)
{
	struct jailparam	*jp;
	size_t			 i, k;
	int			 step;

	jp = wcalloc(w, n + 1, sizeof(*jp));
	if (jailparam_init(&jp[0], "jid") == -1 || jailparam_import_raw(&jp[0],
	    &jid, sizeof(jid)) == -1) {
		*errp = wfmt(w, "%s", jail_errmsg);
		return (-1);
	}
	for (i = 0, k = 1; i < n; i++) {
		if (aws[i].value < 0)
			continue;
		if (jailparam_init(&jp[k], aws[i].name) == -1 || jailparam_import(
		    &jp[k], aws[i].value ? "true" : "false") == -1) {
			*errp = wfmt(w, "%s: %s", aws[i].name, jail_errmsg);
			jailparam_free(jp, k);
			return (-1);
		}
		k++;
	}
	if (k == 1) {
		jailparam_free(jp, 1);
		return (0);
	}
	step = step_begin(w, STEP_LIB, "jailparam_set(3)", "jid %d: "
	    "JAIL_UPDATE, %zu parameter%s", jid, k - 1, k == 2 ? "" : "s");
	if (jailparam_set(jp, (unsigned int)k, JAIL_UPDATE) == -1) {
		*errp = wfmt(w, "%s", jail_errmsg);
		step_end(w, step, false, "%s", *errp);
		jailparam_free(jp, k);
		return (-1);
	}
	step_end(w, step, true, NULL);
	jailparam_free(jp, k);
	return (0);
}

int
do_jail_allow(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct allow_word	 aws[ALLOW_MAX];
	const char		*diff;
	int			 jid, step;

	if (words_parse(w, sp, aws, errp) != 0)
		return (-1);
	jid = jail_lookup(w, sp->jail);
	if (sp->live && jid < 0 && !sp->persist) {
		*errp = wfmt(w, "jail '%s' is not running", sp->jail);
		return (-1);
	}
	diff = NULL;
	if (sp->persist && file_change(w, sp, aws, &diff, errp) != 0)
		return (-1);
	if (sp->live && jid >= 0 && live_change(w, jid, aws, sp->names.n,
	    errp) != 0)
		return (-1);
	if (sp->live && jid < 0) {
		step = step_begin(w, STEP_DAEMON, "arcana-agent", "%s is "
		    "not running: its file alone, for the next start", sp->jail);
		step_end(w, step, true, NULL);
	}
	return (0);
}

/*
 * Before a safe change: the file the jail's block is in, to be put
 * back, and the live values of the parameters named, to be set again.
 */
int
jail_allow_undo_prepare(struct work *w, const struct arc_job_spec *sp,
    const char **pathp, struct arc_variable **varsp, size_t *nvarsp,
    const char **errp)
{
	struct cconf		 conf;
	struct jc_conf		 jc;
	struct jc_file		*f;
	struct arc_variable	*vars;
	const struct cjail	*cj;
	const char		**names, **live, *eq;
	size_t			 n, i, k, m;
	int			 jid, nl;

	*pathp = NULL;
	*varsp = NULL;
	*nvarsp = 0;
	if (sp->persist) {
		conf_read(w, &conf);
		if ((cj = conf_jail(&conf, sp->jail)) == NULL) {
			*errp = wfmt(w, "jail '%s' is not defined in any jail.conf",
			    sp->jail);
			return (-1);
		}
		memset(&jc, 0, sizeof(jc));
		if (jc_load(&jc, cj->scope) == -1 || jc_find(&jc, sp->jail, &f) ==
		    NULL) {
			*errp = wfmt(w, "cannot find the block of jail '%s' in %s",
			    sp->jail, cj->scope);
			jc_free(&jc);
			return (-1);
		}
		*pathp = wstrdup(w, f->path);
		jc_free(&jc);
	}
	if (!sp->live || (jid = jail_lookup(w, sp->jail)) < 0)
		return (0);
	if (jail_allow_names(w, &names, &n) != 0 || (nl = jail_allow_live(w,
	    jid, names, n, &live)) < 0) {
		*errp = wfmt(w, "%s: its parameters now could not be read: %s",
		    sp->jail, jail_errmsg);
		return (-1);
	}
	vars = wcalloc(w, sp->names.n + 1, sizeof(*vars));
	m = 0;
	for (i = 0; i < sp->names.n; i++) {
		if ((eq = strchr(sp->names.v[i], '=')) == NULL)
			continue;
		for (k = 0; k < (size_t)nl; k++)
			if (strncmp(live[k], sp->names.v[i], (size_t)(eq -
			    sp->names.v[i])) == 0 && live[k][eq - sp->names.v[i]]
			    == '=') {
				vars[m].key = wstrndup(w, sp->names.v[i], (size_t)
				    (eq - sp->names.v[i]));
				vars[m].value = live[k] + (eq - sp->names.v[i]) + 1;
				m++;
				break;
			}
	}
	*varsp = vars;
	*nvarsp = m;
	return (0);
}

/* The live values back as they were, on the jail still running. */
int
jail_allow_undo(struct work *w, const struct arc_job_spec *sp,
    const struct arc_variable *vars, size_t nvars, const char **errp)
{
	struct allow_word	 aws[ALLOW_MAX];
	size_t			 i;
	int			 jid;

	if (nvars == 0 || (jid = jail_lookup(w, sp->jail)) < 0)
		return (0);
	for (i = 0; i < nvars && i < ALLOW_MAX; i++) {
		aws[i].name = vars[i].key;
		aws[i].value = vars[i].value != NULL && strcmp(vars[i].value,
		    "1") == 0;
	}
	return (live_change(w, jid, aws, i, errp));
}
