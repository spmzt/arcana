/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: arcana-sysctl's boot, the kernel's tunables the loader sets
 * at the next boot, kept in /boot/loader.conf.d/arcana.conf, Arcana's
 * file (libvarconf's VC_LOADER, every other line kept); the same file
 * net.fibs is raised in for the network instances (yserve.c).  Only a
 * name with a dot is a tunable here; the loader's own (a module's
 * _load, console) are left as they are.
 *
 * The loader (stand/lua/config.lua, readConf()) reads loader_conf_files
 * (/boot/device.hints /boot/loader.conf), then each *.conf of
 * loader_conf_dirs (/boot/loader.conf.d) in the directory's order, not
 * sorted, then local_loader_conf_files (/boot/loader.conf.local); the
 * last assignment of a name wins.  A commit warns, to be accepted:
 *
 *	unknown-tunable		the kernel has no such sysctl (a module's
 *				not loaded yet), or one it does not fetch
 *				from the loader (no CTLFLAG_TUN)
 *	loader-conf-conflict	another loader file sets it: which wins
 *
 * A value is checked as the kernel's sysctl_load_tunable_by_oid() reads
 * it for its type (getenv_array(): numbers by blanks or commas, a k, m,
 * g or t after each).  net.fibs is never lowered below the FIBs the
 * kernel has, nor taken out while it has more than one.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <cblink.h>

#include "agent.h"
#include "collect.h"
#include "varconf.h"

#define	BOOT_CONF	"/boot/loader.conf.d/arcana.conf"
#define	BOOT_DIR	"/boot/loader.conf.d"
#define	BOOT_NUMS	64		/* numbers of one value, at most */

typedef struct arcana_sysctl_boot_tunable ytun;

static const char *
rooted(char *buf, size_t len, const char *path)
{

	(void)snprintf(buf, len, "%s%s", opts.root != NULL ? opts.root : "",
	    path);
	return (buf);
}

static char *
astrdup(cbl_yarena *a, const char *s)
{
	size_t	len = strlen(s) + 1;
	char	*p;

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

/* A tunable's name: a dot in it, the loader's own have none. */
static bool
boot_name(const char *name)
{

	return (strchr(name, '.') != NULL && vc_name_ok(VC_LOADER, name));
}

static bool
signed_type(u_int type)
{

	switch (type) {
	case CTLTYPE_INT:
	case CTLTYPE_LONG:
	case CTLTYPE_S8:
	case CTLTYPE_S16:
	case CTLTYPE_S32:
	case CTLTYPE_S64:
		return (true);
	default:
		return (false);
	}
}

static int
type_size(u_int type)
{

	switch (type) {
	case CTLTYPE_S8:
	case CTLTYPE_U8:
		return (1);
	case CTLTYPE_S16:
	case CTLTYPE_U16:
		return (2);
	case CTLTYPE_INT:
	case CTLTYPE_UINT:
	case CTLTYPE_S32:
	case CTLTYPE_U32:
		return (4);
	case CTLTYPE_LONG:
	case CTLTYPE_ULONG:
		return ((int)sizeof(long));
	default:
		return (8);
	}
}

/*
 * s's numbers as getenv_array() reads them for type, into v (*n of
 * them): -1 and why for what the kernel would refuse.
 */
static int
numbers(const char *s, u_int type, int64_t *v, size_t *n, const char **why)
{
	bool	 sgn = signed_type(type);
	int	 sz = type_size(type);
	int64_t	 x, old, lo, hi;
	char	*end;
	int	 shift;

	*n = 0;
	if (sz == 8) {
		lo = sgn ? INT64_MIN : 0;
		hi = INT64_MAX;
	} else {
		lo = sgn ? -((int64_t)1 << (sz * 8 - 1)) : 0;
		hi = sgn ? ((int64_t)1 << (sz * 8 - 1)) - 1 :
		    ((int64_t)1 << (sz * 8)) - 1;
	}
	if (*s == '\0') {
		*why = "no number";
		return (-1);
	}
	while (*s != '\0') {
		errno = 0;
		x = strtoq(s, &end, 0);
		if (end == s || errno == ERANGE) {
			*why = end == s ? "not a number" : "too large";
			return (-1);
		}
		shift = 0;
		switch (*end) {
		case 't': case 'T':
			shift = 40;
			end++;
			break;
		case 'g': case 'G':
			shift = 30;
			end++;
			break;
		case 'm': case 'M':
			shift = 20;
			end++;
			break;
		case 'k': case 'K':
			shift = 10;
			end++;
			break;
		case ' ': case '\t': case ',': case '\0':
			break;
		default:
			*why = "not a number (a k, m, g or t may follow one)";
			return (-1);
		}
		if (*end != '\0' && *end != ' ' && *end != '\t' && *end != ',') {
			*why = "not a number";
			return (-1);
		}
		while (*end == ' ' || *end == '\t' || *end == ',')
			end++;
		s = end;
		old = x;
		x = (int64_t)((uint64_t)x << shift);
		if ((x >> shift) != old || x < lo || x > hi) {
			*why = sgn || x >= 0 ? "out of its type's range" :
			    "negative, its type unsigned";
			return (-1);
		}
		if (*n == BOOT_NUMS) {
			*why = "too many numbers";
			return (-1);
		}
		v[(*n)++] = x;
	}
	return (0);
}

/* Whether the loader's value s is what the kernel has now, run. */
static bool
same(const char *s, const char *run, u_int type)
{
	int64_t		 a[BOOT_NUMS], b[BOOT_NUMS];
	const char	*why;
	size_t		 na, nb;

	if (type == CTLTYPE_STRING)
		return (strcmp(s, run) == 0);
	if (numbers(s, type, a, &na, &why) == -1 || numbers(run, type, b,
	    &nb, &why) == -1 || na != nb)
		return (false);
	for (size_t i = 0; i < na; i++)
		if (a[i] != b[i])
			return (false);
	return (true);
}

/*
 * Arcana's file read into tun (its dotted names, the last value of
 * each), *n of them, a's; with the kernel's value now and whether the
 * boot's differs when oper.  *any: one does.
 */
static int
boot_read(struct work *w, cbl_yarena *a, ytun **tun, size_t *n, bool oper,
    bool *any)
{
	struct vc_file		 f;
	struct sysctl_value	 sv;
	char			 path[MAXPATHLEN], err[256];
	ytun			*t;
	size_t			 k = 0;
	u_int			 type;

	*tun = NULL;
	*n = 0;
	*any = false;
	if (vc_read(&f, VC_LOADER, rooted(path, sizeof(path), BOOT_CONF), err,
	    sizeof(err)) == -1) {
		if (errno != ENOENT)
			logmsg(LOG_WARNING, "%s: %s", path, err);
		return (0);
	}
	if (f.na == 0 || (t = cbl_yarena_alloc(a, f.na * sizeof(*t))) ==
	    NULL) {
		vc_free(&f);
		return (f.na == 0 ? 0 : ENOMEM);
	}
	for (size_t i = 0; i < f.na; i++) {
		const struct vc_assign *as = &f.a[i];
		size_t j;

		if (as->value == NULL || !boot_name(as->name))
			continue;
		for (j = 0; j < k && strcmp(t[j].name, as->name) != 0; j++)
			;
		if (j == k) {
			memset(&t[k], 0, sizeof(t[k]));
			if ((t[k].name = astrdup(a, as->name)) == NULL)
				goto nomem;
			k++;
		}
		if ((t[j].value = astrdup(a, as->value)) == NULL)
			goto nomem;
	}
	vc_free(&f);
	for (size_t j = 0; oper && j < k; j++) {
		if (!sysctl_tunable(w, t[j].name, &sv, &type))
			continue;
		if ((t[j].running = astrdup(a, sv.value != NULL ? sv.value :
		    "")) == NULL)
			return (ENOMEM);
		t[j].has_pending = true;
		t[j].pending = !same(t[j].value, t[j].running, type);
		*any |= t[j].pending;
	}
	*tun = t;
	*n = k;
	return (0);
nomem:
	vc_free(&f);
	return (ENOMEM);
}

int
arcana_sysctl_boot_get(cbl_req *req, struct arcana_sysctl *data,
    cbl_yarena *a)
{
	struct arcana_sysctl_boot	*o;
	struct work			*w;
	ytun				*t;
	bool				 any;
	int				 error;

	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL ||
	    (w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(o, 0, sizeof(*o));
	if ((error = boot_read(w, a, &t, &o->tunable.n,
	    cbl_req_ydatastore(req) == CBL_YDS_OPERATIONAL, &any)) != 0)
		return (error);
	o->tunable.v = t;
	data->boot = o;
	return (0);
}

/* Whether a tunable Arcana keeps for the boot is not the kernel's now. */
bool
yboot_reboot_required(cbl_yarena *a)
{
	struct work	*w;
	ytun		*t;
	size_t		 n;
	bool		 any = false;

	if ((w = ywork(a)) == NULL || boot_read(w, a, &t, &n, true, &any) != 0)
		return (false);
	return (any);
}

static const ytun *
find(const struct arcana_sysctl_boot *b, const char *name)
{

	for (size_t i = 0; b != NULL && i < b->tunable.n; i++)
		if (strcmp(b->tunable.v[i].name, name) == 0)
			return (&b->tunable.v[i]);
	return (NULL);
}

/* What is said, a line at a time, into buf. */
static void
add(char *buf, size_t len, const char *fmt, ...) __printflike(3, 4);

static void
add(char *buf, size_t len, const char *fmt, ...)
{
	va_list	ap;
	size_t	at = strlen(buf);

	if (at >= len)
		return;
	if (at > 0)
		(void)strlcat(buf, "; ", len);
	at = strlen(buf);
	va_start(ap, fmt);
	(void)vsnprintf(buf + at, len - at, fmt, ap);
	va_end(ap);
}

/*
 * The other loader files that set name, said in buf: which of them
 * wins over Arcana's.
 */
static void
conflicts(const char *name, char *buf, size_t len)
{
	static const char *const before[] = { "/boot/device.hints",
	    "/boot/loader.conf" };
	struct vc_file		 f;
	const struct vc_assign	*as;
	struct dirent		*de;
	DIR			*d;
	char			 path[MAXPATHLEN], rel[MAXPATHLEN], err[256];

	for (size_t i = 0; i <= nitems(before); i++) {
		const char *p = i < nitems(before) ? before[i] :
		    "/boot/loader.conf.local";

		if (vc_read(&f, VC_LOADER, rooted(path, sizeof(path), p), err,
		    sizeof(err)) == -1)
			continue;
		if ((as = vc_get(&f, name)) != NULL)
			add(buf, len, i < nitems(before) ? "%s sets %s=\"%s\": "
			    "arcana.conf is read after it and wins" : "%s sets "
			    "%s=\"%s\": it is read last and wins over "
			    "arcana.conf", p, name, as->value != NULL ?
			    as->value : "(computed)");
		vc_free(&f);
	}
	if ((d = opendir(rooted(path, sizeof(path), BOOT_DIR))) == NULL)
		return;
	while ((de = readdir(d)) != NULL) {
		size_t nl = strlen(de->d_name);

		if (nl < 6 || strcmp(de->d_name + nl - 5, ".conf") != 0 ||
		    strcmp(de->d_name, "arcana.conf") == 0)
			continue;
		(void)snprintf(rel, sizeof(rel), BOOT_DIR "/%s", de->d_name);
		if (vc_read(&f, VC_LOADER, rooted(path, sizeof(path), rel), err,
		    sizeof(err)) == -1)
			continue;
		if ((as = vc_get(&f, name)) != NULL)
			add(buf, len, "%s sets %s=\"%s\": the loader reads "
			    "loader.conf.d in the directory's order, not sorted, "
			    "and the last wins", rel, name, as->value != NULL ?
			    as->value : "(computed)");
		vc_free(&f);
	}
	closedir(d);
}

static int
said(cbl_req *req, const char *why)
{

	(void)cbl_req_set_yerr(req, why, 0);
	return (EINVAL);
}

static int
refuse(cbl_req *req, const char *tag, const char *text)
{

	(void)cbl_req_set_yapptag(req, tag);
	(void)cbl_req_set_yerr(req, text, 0);
	return (EEXIST);
}

/* A value the kernel's type of name takes, *known whether it has one. */
static int
check(struct work *w, cbl_req *req, const ytun *t, bool *known)
{
	struct sysctl_value	 sv;
	int64_t			 v[BOOT_NUMS];
	const char		*why;
	char			 err[512];
	size_t			 n;
	u_int			 type;

	*known = false;
	if (!boot_name(t->name))
		return (said(req, "a tunable is named as the kernel names it, "
		    "with a dot: kern.racct.enable"));
	if (t->value == NULL || strchr(t->value, '"') != NULL ||
	    !sysctl_value_ok(t->value)) {
		(void)snprintf(err, sizeof(err), "%s: loader.conf holds a "
		    "value of one line, without a \"", t->name);
		return (said(req, err));
	}
	if (!sysctl_tunable(w, t->name, &sv, &type) || !sv.tun)
		return (0);
	*known = true;
	if (type == CTLTYPE_STRING)
		return (0);
	if (numbers(t->value, type, v, &n, &why) == -1) {
		(void)snprintf(err, sizeof(err), "%s=\"%s\": %s, for its "
		    "type, %s", t->name, t->value, why, sv.type);
		return (said(req, err));
	}
	return (0);
}

/* net.fibs: never below the FIBs the kernel has. */
static int
fibs_check(cbl_req *req, const ytun *t, bool gone)
{
	char	err[256];
	int	nfibs = yni_nfibs();
	long	want;

	if (gone) {
		if (nfibs <= 1)
			return (0);
		(void)snprintf(err, sizeof(err), "net.fibs stays: the kernel "
		    "has %d FIBs, which FreeBSD never lowers; taken out, the "
		    "next boot would have one", nfibs);
		return (said(req, err));
	}
	want = strtol(t->value, NULL, 0);
	if (want >= nfibs)
		return (0);
	(void)snprintf(err, sizeof(err), "net.fibs=%s: the kernel has %d "
	    "FIBs, which FreeBSD never lowers", t->value, nfibs);
	return (said(req, err));
}

int
arcana_sysctl_boot_edit(cbl_req *req, const struct arcana_sysctl *before,
    const struct arcana_sysctl *after)
{
	const struct arcana_sysctl_boot *old, *new;
	struct vc_file	 f;
	struct work	 w;
	char		 path[MAXPATHLEN], err[512], unknown[2048];
	char		 conflict[4096];
	bool		 known, undo = cbl_req_yundo(req);
	int		 error = 0;

	old = before != NULL ? before->boot : NULL;
	new = after != NULL ? after->boot : NULL;
	unknown[0] = conflict[0] = '\0';
	work_init(&w);
	for (size_t i = 0; new != NULL && i < new->tunable.n; i++) {
		const ytun *t = &new->tunable.v[i], *was = find(old, t->name);

		if (was != NULL && strcmp(was->value, t->value) == 0)
			continue;
		if ((error = check(&w, req, t, &known)) != 0 ||
		    (strcmp(t->name, "net.fibs") == 0 && !undo &&
		    (error = fibs_check(req, t, false)) != 0))
			goto out;
		if (!known)
			add(unknown, sizeof(unknown), "%s", t->name);
		conflicts(t->name, conflict, sizeof(conflict));
	}
	for (size_t i = 0; old != NULL && !undo && i < old->tunable.n; i++)
		if (strcmp(old->tunable.v[i].name, "net.fibs") == 0 &&
		    find(new, "net.fibs") == NULL &&
		    (error = fibs_check(req, NULL, true)) != 0)
			goto out;
	if (!undo && unknown[0] != '\0' && !cbl_req_yaccepts(req,
	    "unknown-tunable")) {
		(void)snprintf(err, sizeof(err), "the kernel takes no tunable "
		    "%.300s now, or reads none of that name from the loader (a "
		    "module's, not loaded yet?): accept unknown-tunable to keep "
		    "it for the next boot", unknown);
		error = refuse(req, "unknown-tunable", err);
		goto out;
	}
	if (!undo && conflict[0] != '\0' && !cbl_req_yaccepts(req,
	    "loader-conf-conflict")) {
		(void)snprintf(err, sizeof(err), "%.400s: accept "
		    "loader-conf-conflict to set it in arcana.conf all the same",
		    conflict);
		error = refuse(req, "loader-conf-conflict", err);
		goto out;
	}
	if (mkdir(rooted(path, sizeof(path), BOOT_DIR), 0755) == -1 &&
	    errno != EEXIST) {
		(void)snprintf(err, sizeof(err), "%s: %s", path,
		    strerror(errno));
		error = said(req, err);
		goto out;
	}
	rooted(path, sizeof(path), BOOT_CONF);
	if (vc_read(&f, VC_LOADER, path, err, sizeof(err)) == -1) {
		error = said(req, err);
		goto out;
	}
	/* Taken out: each dotted name not kept; the rest set in place. */
	for (size_t i = 0; error == 0 && i < f.na; i++) {
		if (!boot_name(f.a[i].name) || find(new, f.a[i].name) != NULL)
			continue;
		if (vc_unset(&f, f.a[i].name, err, sizeof(err)) == -1)
			error = said(req, err);
		i = (size_t)-1;			/* the file is another now */
	}
	for (size_t i = 0; error == 0 && new != NULL && i < new->tunable.n;
	    i++)
		if (vc_set(&f, new->tunable.v[i].name, new->tunable.v[i].value,
		    err, sizeof(err)) == -1)
			error = said(req, err);
	if (error == 0 && vc_write(&f, path, 0644, err, sizeof(err)) == -1)
		error = said(req, err);
	vc_free(&f);
out:
	work_free(&w);
	return (error);
}
