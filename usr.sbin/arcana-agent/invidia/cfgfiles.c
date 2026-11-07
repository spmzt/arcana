/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: which files a commit writes the host's rc.conf(5) variables
 * and the loader's tunables (loader.conf(5)) in, arcana-agent's
 * config-files (docs/notes/config-files.md):
 *
 *	arcana	Arcana's own, /usr/local/etc/rc.conf.d/arcana named last in
 *		rc_conf_files and /boot/loader.conf.d/arcana.conf (the
 *		default; rcarcana.c, yboot.c)
 *	system	the system's: each variable in the file rc(8) or the loader
 *		takes it from, the last of the admin's that sets it, else
 *		/etc/rc.conf and /boot/loader.conf
 *
 * kept in /usr/local/etc/arcana/config-files.conf, read at start, and
 * changed by the switch action alone, which moves the files: arcana to
 * system writes each variable of Arcana's files where the admin's is, a
 * word list merged as sysrc(8)'s += merges it unless the admin chose
 * otherwise; system to arcana clones the admin's variables into
 * Arcana's files, theirs as they are, rc(8) and the loader reading
 * Arcana's last.  Every file changed is copied first into
 * /var/db/arcana/config-switch/<UTC time>, and a failure puts every
 * file back.  The firewall's kept rules move to /etc/ipfw.rules and
 * /etc/ipfw.sh with it, unless the admin's own files are there.
 *
 * The ledger, /var/db/arcana/config-ledger, is what Arcana changed of a
 * variable the admin's files set (its value before, what Arcana wrote,
 * Arcana's own): release gives it back from there.  pending is the last
 * rc-conf-merge refusal's rows, resolve the values the admin merged.
 * Every path is under --root, a test's tree.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <cblink.h>

#include "agent.h"
#include "collect.h"
#include "varconf.h"

#define	CF_CONF		"/usr/local/etc/arcana/config-files.conf"
#define	CF_LEDGER	"/var/db/arcana/config-ledger"
#define	CF_BACKUP	"/var/db/arcana/config-switch"
#define	RC_CONF		"/etc/rc.conf"
#define	RC_DEFAULTS	"/etc/defaults/rc.conf"
#define	IPFW_RULES_SYS	"/etc/ipfw.rules"
#define	IPFW_SH_SYS	"/etc/ipfw.sh"
#define	FW_MARK		"# Written by arcana-agent"

static bool		 cf_sys;
static char		 cf_ipfw[MAXPATHLEN];	/* rooted, when moved */
static const char	*cf_ipfw_own;		/* opts.ipfw_rules at start */

/*
 * The base's word lists: rc.conf(5) and /etc/defaults/rc.conf say each
 * is a list of words (names, routes, ports, paths), which sysrc(8)'s +=
 * adds to and rc.d reads a word at a time.  A pattern ends in "*".
 * ifconfig_<if>_aliases is not one: its entries are "inet <address>",
 * two words each, which a merge of words would break.
 */
static const char *const cf_lists[] = {
	"jail_list", "cloned_interfaces", "kld_list", "static_routes",
	"ipv6_static_routes", "static_arp_pairs", "static_ndp_pairs",
	"rtadvd_interfaces", "gif_interfaces", "wireguard_interfaces",
	"rc_conf_files", "local_startup", "ntpdate_hosts", "netwait_ip",
	"devmatch_blocklist", "firewall_myservices",
	"firewall_allowservices", "firewall_trusted", "firewall_coscripts",
	"firewall_nologports", "geli_devices", "geli_groups", "iovctl_files",
	"ldconfig_paths", "ldconfig32_paths", "ldconfig_local_dirs",
	"ldconfig_local32_dirs", "altlog_proglist", "msconvd_ports",
	"devfs_set_rulesets", "zfskeys_datasets",
	"vlans_*", "wlans_*", "ipv4_addrs_*",
};

bool
cf_list_var(const char *name)
{

	for (size_t i = 0; i < nitems(cf_lists); i++) {
		size_t n = strlen(cf_lists[i]);

		if (cf_lists[i][n - 1] == '*' ? strncmp(name, cf_lists[i],
		    n - 1) == 0 && name[n - 1] != '\0' : strcmp(name,
		    cf_lists[i]) == 0)
			return (true);
	}
	return (false);
}

const char *
cf_rooted(char *buf, size_t len, const char *path)
{

	(void)snprintf(buf, len, "%s%s", opts.root != NULL ? opts.root : "",
	    path);
	return (buf);
}

/* path without the root before it, as a file names it. */
const char *
cf_unrooted(const char *path)
{
	size_t	rl = opts.root != NULL ? strlen(opts.root) : 0;

	if (rl > 0 && strncmp(path, opts.root, rl) == 0 && path[rl] == '/')
		return (path + rl);
	return (path);
}

bool
cf_system(void)
{

	return (cf_sys);
}

/* Words of s, by blanks: a copy, *n of them. */
static char **
words(const char *s, size_t *n)
{
	char	**v = NULL, **t, *c, *p, *w;

	*n = 0;
	if (s == NULL || (c = strdup(s)) == NULL)
		return (NULL);
	for (p = c; (w = strsep(&p, " \t\n")) != NULL; ) {
		if (*w == '\0')
			continue;
		if ((t = reallocarray(v, *n + 2, sizeof(*v))) == NULL)
			break;
		v = t;
		if ((v[*n] = strdup(w)) == NULL)
			break;
		(*n)++;
		v[*n] = NULL;
	}
	free(c);
	return (v);
}

static void
words_free(char **v, size_t n)
{

	for (size_t i = 0; v != NULL && i < n; i++)
		free(v[i]);
	free(v);
}

static bool
has_word(char *const *v, size_t n, const char *w)
{

	for (size_t i = 0; i < n; i++)
		if (strcmp(v[i], w) == 0)
			return (true);
	return (false);
}

/* s and more appended, a blank between: s grown, or NULL. */
static char *
append(char *s, const char *more)
{
	char	*t;

	if (asprintf(&t, "%s%s%s", s != NULL ? s : "", s != NULL &&
	    s[0] != '\0' ? " " : "", more) == -1) {
		free(s);
		return (NULL);
	}
	free(s);
	return (t);
}

/*
 * The admin's words in their order, less those removed, then Arcana's
 * not among them: what sysrc(8)'s += gives for each of Arcana's words.
 */
char *
cf_merge(const char *yours, const char *arcana, const char *removed)
{
	char	**y, **a, **r, *out;
	size_t	 ny, na, nr;

	y = words(yours, &ny);
	a = words(arcana, &na);
	r = words(removed, &nr);
	out = strdup("");
	for (size_t i = 0; out != NULL && i < ny; i++)
		if (!has_word(r, nr, y[i]) && !has_word(y, i, y[i]))
			out = append(out, y[i]);
	for (size_t i = 0; out != NULL && i < na; i++)
		if (!has_word(y, ny, a[i]) && !has_word(a, i, a[i]))
			out = append(out, a[i]);
	words_free(y, ny);
	words_free(a, na);
	words_free(r, nr);
	return (out);
}

/* The words of a that are not b's, in a's order. */
char *
cf_minus(const char *a, const char *b)
{
	char	**av, **bv, *out;
	size_t	 na, nb;

	av = words(a, &na);
	bv = words(b, &nb);
	out = strdup("");
	for (size_t i = 0; out != NULL && i < na; i++)
		if (!has_word(bv, nb, av[i]))
			out = append(out, av[i]);
	words_free(av, na);
	words_free(bv, nb);
	return (out);
}

/* Whether a and b have the same words in the same order. */
bool
cf_same_words(const char *a, const char *b)
{
	char	**av, **bv;
	size_t	 na, nb;
	bool	 same;

	av = words(a, &na);
	bv = words(b, &nb);
	same = na == nb;
	for (size_t i = 0; same && i < na; i++)
		same = strcmp(av[i], bv[i]) == 0;
	words_free(av, na);
	words_free(bv, nb);
	return (same);
}

/*
 * The ledger: a line an entry, its fields by tabs, a value's tab,
 * newline and backslash escaped; "-" a value that is none.
 */
static void
esc(FILE *fp, const char *s)
{

	if (s == NULL) {
		fputc('-', fp);
		return;
	}
	fputc('=', fp);
	for (; *s != '\0'; s++)
		if (*s == '\t')
			fputs("\\t", fp);
		else if (*s == '\n')
			fputs("\\n", fp);
		else if (*s == '\\')
			fputs("\\\\", fp);
		else
			fputc(*s, fp);
}

static char *
unesc(const char *s, bool *bad)
{
	char	*o, *p;

	if (strcmp(s, "-") == 0)
		return (NULL);
	if (*s != '=' || (o = malloc(strlen(s) + 1)) == NULL) {
		*bad = true;
		return (NULL);
	}
	for (p = o, s++; *s != '\0'; s++) {
		if (*s != '\\' || s[1] == '\0') {
			*p++ = *s;
			continue;
		}
		s++;
		*p++ = *s == 't' ? '\t' : *s == 'n' ? '\n' : *s;
	}
	*p = '\0';
	return (o);
}

const char *
cf_ledger_path(char *buf, size_t len)
{

	return (cf_rooted(buf, len, CF_LEDGER));
}

void
cf_ledger_free(struct cf_ledger *l)
{

	for (size_t i = 0; i < l->n; i++) {
		free(l->v[i].var);
		free(l->v[i].file);
		free(l->v[i].before);
		free(l->v[i].after);
		free(l->v[i].arcana);
	}
	free(l->v);
	memset(l, 0, sizeof(*l));
}

int
cf_ledger_read(struct cf_ledger *l)
{
	char	 path[MAXPATHLEN], *line = NULL, *f[6], *p;
	size_t	 cap = 0;
	ssize_t	 n;
	FILE	*fp;

	memset(l, 0, sizeof(*l));
	if ((fp = fopen(cf_ledger_path(path, sizeof(path)), "re")) == NULL)
		return (errno == ENOENT ? 0 : errno);
	while ((n = getline(&line, &cap, fp)) > 0) {
		struct cf_led e;
		bool bad = false;
		int k = 0;

		if (line[n - 1] == '\n')
			line[n - 1] = '\0';
		if (line[0] == '#' || line[0] == '\0')
			continue;
		for (p = line; k < 6 && (f[k] = strsep(&p, "\t")) != NULL; k++)
			;
		if (k != 6 || (strcmp(f[0], "rc") != 0 && strcmp(f[0],
		    "loader") != 0))
			continue;
		memset(&e, 0, sizeof(e));
		e.kind = strcmp(f[0], "rc") == 0 ? CF_RC : CF_LOADER;
		e.var = unesc(f[1], &bad);
		e.file = unesc(f[2], &bad);
		e.before = unesc(f[3], &bad);
		e.after = unesc(f[4], &bad);
		e.arcana = unesc(f[5], &bad);
		if (!bad && e.var != NULL && e.file != NULL && cf_ledger_put(l,
		    e.kind, e.var, e.file, e.before, e.after, e.arcana) != 0)
			bad = true;
		free(e.var);
		free(e.file);
		free(e.before);
		free(e.after);
		free(e.arcana);
	}
	free(line);
	fclose(fp);
	return (0);
}

const struct cf_led *
cf_ledger_get(const struct cf_ledger *l, int kind, const char *var)
{

	for (size_t i = 0; i < l->n; i++)
		if (l->v[i].kind == kind && strcmp(l->v[i].var, var) == 0)
			return (&l->v[i]);
	return (NULL);
}

static char *
dup0(const char *s)
{

	return (s != NULL ? strdup(s) : NULL);
}

int
cf_ledger_put(struct cf_ledger *l, int kind, const char *var,
    const char *file, const char *before, const char *after,
    const char *arcana)
{
	struct cf_led	*e = NULL, *t, n;

	memset(&n, 0, sizeof(n));
	n.kind = kind;
	if ((n.var = strdup(var)) == NULL || (n.file = strdup(file)) ==
	    NULL || (before != NULL && (n.before = strdup(before)) == NULL) ||
	    (after != NULL && (n.after = strdup(after)) == NULL) ||
	    (arcana != NULL && (n.arcana = strdup(arcana)) == NULL))
		goto nomem;
	for (size_t i = 0; i < l->n && e == NULL; i++)
		if (l->v[i].kind == kind && strcmp(l->v[i].var, var) == 0)
			e = &l->v[i];
	if (e == NULL) {
		if ((t = reallocarray(l->v, l->n + 1, sizeof(*t))) == NULL)
			goto nomem;
		l->v = t;
		e = &l->v[l->n++];
	} else {
		free(e->var);
		free(e->file);
		free(e->before);
		free(e->after);
		free(e->arcana);
	}
	*e = n;
	return (0);
nomem:
	free(n.var);
	free(n.file);
	free(n.before);
	free(n.after);
	free(n.arcana);
	return (ENOMEM);
}

void
cf_ledger_del(struct cf_ledger *l, int kind, const char *var)
{

	for (size_t i = 0; i < l->n; i++) {
		if (l->v[i].kind != kind || strcmp(l->v[i].var, var) != 0)
			continue;
		free(l->v[i].var);
		free(l->v[i].file);
		free(l->v[i].before);
		free(l->v[i].after);
		free(l->v[i].arcana);
		memmove(&l->v[i], &l->v[i + 1], (l->n - i - 1) *
		    sizeof(*l->v));
		l->n--;
		return;
	}
}

/* Its directories made, as mkdir -p makes them. */
static int
mkdirs(const char *dir)
{
	char	buf[MAXPATHLEN], *p;

	(void)snprintf(buf, sizeof(buf), "%s", dir);
	for (p = buf + 1; *p != '\0'; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(buf, 0755) == -1 && errno != EEXIST)
			return (errno);
		*p = '/';
	}
	if (mkdir(buf, 0755) == -1 && errno != EEXIST)
		return (errno);
	return (0);
}

/* The directory of path made. */
static int
mkparent(const char *path)
{
	char	dir[MAXPATHLEN], *s;

	(void)snprintf(dir, sizeof(dir), "%s", path);
	if ((s = strrchr(dir, '/')) == NULL || s == dir)
		return (0);
	*s = '\0';
	return (mkdirs(dir));
}

int
cf_ledger_write(const struct cf_ledger *l, char *err, size_t errlen)
{
	char	 path[MAXPATHLEN], tmp[MAXPATHLEN];
	FILE	*fp;
	int	 fd;

	cf_ledger_path(path, sizeof(path));
	if (l->n == 0) {
		if (unlink(path) == -1 && errno != ENOENT) {
			(void)snprintf(err, errlen, "%s: %s", path,
			    strerror(errno));
			return (errno);
		}
		return (0);
	}
	(void)mkparent(path);
	(void)snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
	if ((fd = mkstemp(tmp)) == -1 || (fp = fdopen(fd, "w")) == NULL) {
		(void)snprintf(err, errlen, "%s: %s", tmp, strerror(errno));
		if (fd != -1) {
			close(fd);
			unlink(tmp);
		}
		return (EIO);
	}
	fprintf(fp, "# Written by arcana-agent: what Arcana changed of "
	    "variables your files set\n# (kind, variable, file, before, "
	    "after, Arcana's own); release gives it back.\n");
	for (size_t i = 0; i < l->n; i++) {
		fputs(l->v[i].kind == CF_RC ? "rc" : "loader", fp);
		fputc('\t', fp);
		esc(fp, l->v[i].var);
		fputc('\t', fp);
		esc(fp, l->v[i].file);
		fputc('\t', fp);
		esc(fp, l->v[i].before);
		fputc('\t', fp);
		esc(fp, l->v[i].after);
		fputc('\t', fp);
		esc(fp, l->v[i].arcana);
		fputc('\n', fp);
	}
	(void)fchmod(fd, 0600);
	if (fflush(fp) != 0 || fsync(fd) == -1 || fclose(fp) != 0 ||
	    rename(tmp, path) == -1) {
		(void)snprintf(err, errlen, "%s: %s", path, strerror(errno));
		unlink(tmp);
		return (EIO);
	}
	return (0);
}

/*
 * pending: the last rc-conf-merge refusal's rows; a value resolve gave
 * one, taken by the commit that writes it.
 */
struct pend {
	int	 kind;
	char	*var, *file, *yours, *proposed, *value;
	int	 line;
};
static pthread_mutex_t	 pend_lock = PTHREAD_MUTEX_INITIALIZER;
static struct pend	*pend;
static size_t		 npend;

static void
pend_clear(void)
{

	for (size_t i = 0; i < npend; i++) {
		free(pend[i].var);
		free(pend[i].file);
		free(pend[i].yours);
		free(pend[i].proposed);
		free(pend[i].value);
	}
	free(pend);
	pend = NULL;
	npend = 0;
}

void
cf_pending_set(const struct cf_pend *v, size_t n)
{
	struct pend	*p;

	pthread_mutex_lock(&pend_lock);
	/* A value resolve gave stays with its row, the rest are new. */
	if ((p = calloc(n + 1, sizeof(*p))) != NULL) {
		for (size_t i = 0; i < n; i++) {
			p[i].kind = v[i].kind;
			p[i].var = dup0(v[i].var);
			p[i].file = dup0(v[i].file);
			p[i].line = v[i].line;
			p[i].yours = dup0(v[i].yours);
			p[i].proposed = dup0(v[i].proposed);
			for (size_t k = 0; k < npend; k++)
				if (pend[k].kind == v[i].kind &&
				    pend[k].var != NULL && v[i].var != NULL &&
				    strcmp(pend[k].var, v[i].var) == 0)
					p[i].value = dup0(pend[k].value);
		}
		pend_clear();
		pend = p;
		npend = n;
	}
	pthread_mutex_unlock(&pend_lock);
}

char *
cf_resolution(int kind, const char *var)
{
	char	*v = NULL;

	pthread_mutex_lock(&pend_lock);
	for (size_t i = 0; i < npend && v == NULL; i++)
		if (pend[i].kind == kind && strcmp(pend[i].var, var) == 0)
			v = dup0(pend[i].value);
	pthread_mutex_unlock(&pend_lock);
	return (v);
}

void
cf_resolved(int kind, const char *var)
{

	pthread_mutex_lock(&pend_lock);
	for (size_t i = 0; i < npend; i++) {
		if (pend[i].kind != kind || strcmp(pend[i].var, var) != 0)
			continue;
		free(pend[i].var);
		free(pend[i].file);
		free(pend[i].yours);
		free(pend[i].proposed);
		free(pend[i].value);
		memmove(&pend[i], &pend[i + 1], (npend - i - 1) *
		    sizeof(*pend));
		npend--;
		break;
	}
	pthread_mutex_unlock(&pend_lock);
}

/*
 * The loader's files that set tunables, in the order it reads them
 * (stand/lua/config.lua): loader.conf, each *.conf of loader.conf.d in
 * the directory's order, loader.conf.local; rooted, *n of them, those
 * there.  device.hints is not among them: its hints are no tunables.
 */
int
cf_loader_files(char ***pathsp, size_t *np)
{
	char		 path[MAXPATHLEN], **v = NULL, **t;
	struct dirent	*de;
	DIR		*d;
	size_t		 n = 0;

	*pathsp = NULL;
	*np = 0;
#define	ADD(p) do {							\
	if ((t = reallocarray(v, n + 1, sizeof(*v))) == NULL ||		\
	    (t[n] = strdup(p)) == NULL) {				\
		if (t != NULL)						\
			v = t;						\
		vc_rc_files_free(v, n);					\
		return (ENOMEM);					\
	}								\
	v = t;								\
	n++;								\
} while (0)
	if (access(cf_rooted(path, sizeof(path), LOADER_CONF), F_OK) == 0)
		ADD(path);
	if ((d = opendir(cf_rooted(path, sizeof(path), LOADER_DIR))) !=
	    NULL) {
		while ((de = readdir(d)) != NULL) {
			size_t nl = strlen(de->d_name);
			char p[MAXPATHLEN];

			if (nl < 6 || strcmp(de->d_name + nl - 5, ".conf") != 0)
				continue;
			(void)snprintf(p, sizeof(p), "%s/%s", path, de->d_name);
			ADD(p);
		}
		closedir(d);
	}
	if (access(cf_rooted(path, sizeof(path), LOADER_LOCAL), F_OK) == 0)
		ADD(path);
#undef ADD
	*pathsp = v;
	*np = n;
	return (0);
}

/* Where a tunable goes in system mode: the last loader file that sets
 * it, else loader.conf; rooted, in buf. */
const char *
cf_loader_target(const char *name, char *buf, size_t len)
{
	struct vc_file	 f;
	char		**v, err[128];
	size_t		 n;

	cf_rooted(buf, len, LOADER_CONF);
	if (cf_loader_files(&v, &n) != 0)
		return (buf);
	for (size_t i = 0; i < n; i++) {
		if (vc_read(&f, VC_LOADER, v[i], err, sizeof(err)) == -1)
			continue;
		if (vc_get(&f, name) != NULL)
			(void)snprintf(buf, len, "%s", v[i]);
		vc_free(&f);
	}
	vc_rc_files_free(v, n);
	return (buf);
}

/*
 * The mode, read at start: config-files.conf's config_files, and where
 * the kept firewall rules went with it (config_files_ipfw_rules).
 */
void
cf_load(void)
{
	const struct vc_assign	*a;
	struct vc_file		 f;
	char			 path[MAXPATHLEN], err[256];

	if (cf_ipfw_own == NULL)
		cf_ipfw_own = opts.ipfw_rules;
	cf_sys = false;
	cf_ipfw[0] = '\0';
	if (vc_read(&f, VC_SH, cf_rooted(path, sizeof(path), CF_CONF), err,
	    sizeof(err)) == -1) {
		logmsg(LOG_WARNING, "%s: %s", path, err);
		return;
	}
	cf_sys = (a = vc_get(&f, "config_files")) != NULL && a->value !=
	    NULL && strcmp(a->value, "system") == 0;
	if (cf_sys && (a = vc_get(&f, "config_files_ipfw_rules")) != NULL &&
	    a->value != NULL && a->value[0] == '/') {
		cf_rooted(cf_ipfw, sizeof(cf_ipfw), a->value);
		opts.ipfw_rules = cf_ipfw;
	}
	vc_free(&f);
}

/* The directory Arcana's own files were in: the feeds' beside them. */
const char *
cf_ipfw_home(void)
{

	return (cf_ipfw_own != NULL ? cf_ipfw_own : opts.ipfw_rules);
}

static int
write_mode(struct rca *k, bool sys, const char *ipfw, char *err,
    size_t errlen)
{
	struct vc_file	 f;
	char		 path[MAXPATHLEN];
	int		 error = 0;

	cf_rooted(path, sizeof(path), CF_CONF);
	if ((error = rca_keep(k, path)) != 0)
		return (error);
	(void)mkparent(path);
	if (vc_parse(&f, VC_SH, "# Written by arcana-agent: the files a "
	    "commit writes (arcana-agent's\n# config-files), changed by its "
	    "switch.\n", strlen("# Written by arcana-agent: the files a "
	    "commit writes (arcana-agent's\n# config-files), changed by its "
	    "switch.\n"), err, errlen) == -1)
		return (EIO);
	if (vc_set(&f, "config_files", sys ? "system" : "arcana", err,
	    errlen) == -1 || (ipfw != NULL && vc_set(&f,
	    "config_files_ipfw_rules", ipfw, err, errlen) == -1) ||
	    vc_write(&f, path, 0644, err, errlen) == -1)
		error = errno != 0 ? errno : EIO;
	vc_free(&f);
	return (error);
}

/* A file's bytes, NULL where it is not there. */
static char *
slurp(const char *path, size_t *len)
{
	struct stat	 sb;
	char		*b;
	int		 fd;
	ssize_t		 r;

	*len = 0;
	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
		return (NULL);
	if (fstat(fd, &sb) == -1 || (b = malloc((size_t)sb.st_size + 1)) ==
	    NULL) {
		close(fd);
		return (NULL);
	}
	while (*len < (size_t)sb.st_size && (r = read(fd, b + *len,
	    (size_t)sb.st_size - *len)) > 0)
		*len += (size_t)r;
	b[*len] = '\0';
	close(fd);
	return (b);
}

static int
put_file(const char *path, const char *text, size_t len, mode_t mode)
{
	char	tmp[MAXPATHLEN];
	int	fd;

	(void)mkparent(path);
	(void)snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
	if ((fd = mkstemp(tmp)) == -1)
		return (errno);
	if ((len > 0 && write(fd, text, len) != (ssize_t)len) ||
	    fchmod(fd, mode) == -1 || fsync(fd) == -1) {
		int e = errno;

		close(fd);
		unlink(tmp);
		return (e != 0 ? e : EIO);
	}
	close(fd);
	if (rename(tmp, path) == -1) {
		int e = errno;

		unlink(tmp);
		return (e);
	}
	return (0);
}

/* The boot script of a kept rules file: .sh for .rules. */
static void
script_of(const char *rules, char *buf, size_t len)
{
	size_t	n = strlen(rules);

	if (n > 6 && strcmp(rules + n - 6, ".rules") == 0)
		(void)snprintf(buf, len, "%.*s.sh", (int)(n - 6), rules);
	else
		(void)snprintf(buf, len, "%s.sh", rules);
}

static char *
script_text(const char *rules)
{
	char	*s;

	if (asprintf(&s, "#!/bin/sh\n" FW_MARK ": rc.d/ipfw runs it at boot "
	    "(firewall_script) to load\n# the kept rules.  The host's own "
	    "firewall script is left as it was.\n%s -q -f flush\n%s -q %s\n",
	    opts.ipfw_bin, opts.ipfw_bin, rules) == -1)
		return (NULL);
	return (s);
}

/*
 * The firewall's move: Arcana's kept rules and boot script (from, a
 * rooted rules path) to to's; never over a file of the admin's, which
 * is no script of Arcana's or rules other than these.  *why, when not.
 */
struct fwmove {
	char	 from[MAXPATHLEN], fromsh[MAXPATHLEN];
	char	 to[MAXPATHLEN], tosh[MAXPATHLEN];	/* rooted */
	bool	 go, has_sh;
	char	 why[400];
};

static void
fw_plan(struct fwmove *m, const char *from, const char *to)
{
	char	*a, *b;
	size_t	 la, lb;

	memset(m, 0, sizeof(*m));
	(void)snprintf(m->from, sizeof(m->from), "%s", from);
	script_of(from, m->fromsh, sizeof(m->fromsh));
	(void)snprintf(m->to, sizeof(m->to), "%s", to);
	script_of(to, m->tosh, sizeof(m->tosh));
	if (strcmp(m->from, m->to) == 0)
		return;
	if ((a = slurp(m->from, &la)) == NULL) {
		(void)snprintf(m->why, sizeof(m->why), "no kept firewall rules "
		    "(%s): nothing of the firewall's to move",
		    cf_unrooted(m->from));
		return;
	}
	m->has_sh = access(m->fromsh, F_OK) == 0;
	if ((b = slurp(m->to, &lb)) != NULL && (la != lb || memcmp(a, b,
	    la) != 0))
		(void)snprintf(m->why, sizeof(m->why), "%s is the admin's own "
		    "(not Arcana's kept rules): the firewall's files stay at "
		    "%s, firewall_script naming them", cf_unrooted(m->to),
		    cf_unrooted(m->from));
	free(b);
	b = NULL;
	if (m->why[0] == '\0' && (b = slurp(m->tosh, &lb)) != NULL &&
	    strstr(b, FW_MARK) == NULL)
		(void)snprintf(m->why, sizeof(m->why), "%s is the admin's own "
		    "script: the firewall's files stay at %s, firewall_script "
		    "naming them", cf_unrooted(m->tosh), cf_unrooted(m->from));
	free(b);
	b = NULL;
	if (m->why[0] == '\0' && m->has_sh && ((b = slurp(m->fromsh, &lb)) ==
	    NULL || strstr(b, FW_MARK) == NULL))
		(void)snprintf(m->why, sizeof(m->why), "%s is not Arcana's "
		    "script: the firewall's files stay as they are",
		    cf_unrooted(m->fromsh));
	free(b);
	free(a);
	m->go = m->why[0] == '\0';
}

static int
fw_keep(struct rca *k, const struct fwmove *m)
{
	int	error;

	if (!m->go)
		return (0);
	if ((error = rca_keep(k, m->from)) != 0 ||
	    (error = rca_keep(k, m->to)) != 0)
		return (error);
	if (m->has_sh && ((error = rca_keep(k, m->fromsh)) != 0 ||
	    (error = rca_keep(k, m->tosh)) != 0))
		return (error);
	return (0);
}

static int
fw_do(const struct fwmove *m, char *err, size_t errlen)
{
	char	*a, *s;
	size_t	 la;
	int	 error;

	if (!m->go)
		return (0);
	if ((a = slurp(m->from, &la)) == NULL)
		return (errno != 0 ? errno : EIO);
	error = put_file(m->to, a, la, 0600);
	free(a);
	if (error == 0 && m->has_sh) {
		if ((s = script_text(cf_unrooted(m->to))) == NULL)
			return (ENOMEM);
		error = put_file(m->tosh, s, strlen(s), 0700);
		free(s);
	}
	if (error == 0 && (unlink(m->from) == -1 || (m->has_sh &&
	    unlink(m->fromsh) == -1)))
		error = errno;
	if (error != 0)
		(void)snprintf(err, errlen, "the firewall's files to %s: %s",
		    cf_unrooted(m->to), strerror(error));
	return (error);
}

/*
 * The switch's rows: a variable of Arcana's files, what the admin's
 * say, what is written where.
 */
struct row {
	int	 kind;
	char	*var;
	char	*yours;		/* active, else taken by Arcana; NULL none */
	char	*arcana;
	int	 at;		/* the admin's file it ends in; -1 the default */
	bool	 list;
	const char *choice;	/* NULL: one is needed */
	char	*result;
};

static void
rows_free(struct row *r, size_t n)
{

	for (size_t i = 0; i < n; i++) {
		free(r[i].var);
		free(r[i].yours);
		free(r[i].arcana);
		free(r[i].result);
	}
	free(r);
}

typedef struct arcana_agent_agent_config_files_switch_input yswin;
typedef struct arcana_agent_agent_config_files_switch_output yswout;
typedef struct arcana_agent_agent_config_files_switch_output_row yswrow;

static const struct arcana_agent_agent_config_files_switch_input_merge *
merge_of(const yswin *in, int kind, const char *var)
{

	for (size_t i = 0; in != NULL && i < in->merge.n; i++)
		if ((int)in->merge.v[i].kind == (kind == CF_RC ?
		    ARCANA_AGENT_AGENT_CONFIG_FILES_SWITCH_INPUT_MERGE_KIND_RC :
		    ARCANA_AGENT_AGENT_CONFIG_FILES_SWITCH_INPUT_MERGE_KIND_LOADER) &&
		    in->merge.v[i].variable != NULL &&
		    strcmp(in->merge.v[i].variable, var) == 0)
			return (&in->merge.v[i]);
	return (NULL);
}

/* The value commented out as taken by Arcana in f, the last; NULL. */
static char *
taken_value(const struct vc_file *f, const char *var)
{
	const struct vc_assign	*a;
	struct vc_file		 c;
	char			 err[128], *v = NULL;
	int			 r;

	if (f->len == 0 || vc_parse(&c, f->dialect, f->text, f->len, err,
	    sizeof(err)) == -1)
		return (NULL);
	/* The active lines first out, the taken ones then read back. */
	if (vc_unset(&c, var, err, sizeof(err)) == 0 && (r = vc_uncomment(&c,
	    var, RCA_TAKEN, err, sizeof(err))) > 0 && (a = vc_get(&c, var)) !=
	    NULL && a->value != NULL)
		v = strdup(a->value);
	vc_free(&c);
	return (v);
}

static bool
has_taken(const struct vc_file *f, const char *var)
{
	char	*v = taken_value(f, var);
	bool	 has = v != NULL;

	free(v);
	return (has);
}

/* A row's choice and result, from in's merge or the defaults. */
static int
choose(struct row *r, const yswin *in, char *err, size_t errlen)
{
	const struct arcana_agent_agent_config_files_switch_input_merge *m;

	r->choice = NULL;
	free(r->result);
	r->result = NULL;
	m = merge_of(in, r->kind, r->var);
	if (m != NULL && m->has_choice) {
		switch (m->choice) {
		case ARCANA_AGENT_AGENT_CONFIG_FILES_SWITCH_INPUT_MERGE_CHOICE_ADDITIVE:
			if (!r->list) {
				(void)snprintf(err, errlen, "%s: additive is for a "
				    "word list; this is a value: arcana, yours, "
				    "edit or remove", r->var);
				return (EINVAL);
			}
			r->choice = "additive";
			break;
		case ARCANA_AGENT_AGENT_CONFIG_FILES_SWITCH_INPUT_MERGE_CHOICE_ARCANA:
			r->choice = "arcana";
			break;
		case ARCANA_AGENT_AGENT_CONFIG_FILES_SWITCH_INPUT_MERGE_CHOICE_YOURS:
			if (r->yours == NULL) {
				(void)snprintf(err, errlen, "%s: your files do "
				    "not set it", r->var);
				return (EINVAL);
			}
			r->choice = "yours";
			break;
		case ARCANA_AGENT_AGENT_CONFIG_FILES_SWITCH_INPUT_MERGE_CHOICE_EDIT:
			if (m->value == NULL) {
				(void)snprintf(err, errlen, "%s: edit needs its "
				    "value", r->var);
				return (EINVAL);
			}
			r->choice = "edit";
			break;
		case ARCANA_AGENT_AGENT_CONFIG_FILES_SWITCH_INPUT_MERGE_CHOICE_REMOVE:
			/* Written nowhere, unset wherever it is. */
			r->choice = "remove";
			return (0);
		}
	} else if (r->yours == NULL || strcmp(r->yours, r->arcana) == 0)
		r->choice = "arcana";
	else if (r->list)
		r->choice = "additive";
	if (r->choice == NULL)
		return (0);
	if (strcmp(r->choice, "additive") == 0)
		r->result = cf_merge(r->yours, r->arcana, NULL);
	else if (strcmp(r->choice, "yours") == 0)
		r->result = strdup(r->yours);
	else if (strcmp(r->choice, "edit") == 0)
		r->result = strdup(m->value);
	else
		r->result = strdup(r->arcana);
	return (r->result == NULL ? ENOMEM : 0);
}

/* The admin's rc files: rc_conf_files', in rc(8)'s order, Arcana's not
 * among them; rooted. */
static int
user_rc_files(char ***v, size_t *n, char *err, size_t errlen)
{
	char	**all, path[MAXPATHLEN];
	size_t	 na, k = 0;

	if (vc_rc_files(opts.root != NULL ? opts.root : "", "/usr/local",
	    "arcana", "arcana", &all, &na, err, errlen) == -1)
		return (errno != 0 ? errno : EIO);
	cf_rooted(path, sizeof(path), RC_ARCANA);
	for (size_t i = 0; i < na; i++) {
		if (strcmp(all[i], path) == 0) {
			free(all[i]);
			continue;
		}
		all[k++] = all[i];
	}
	*v = all;
	*n = k;
	return (0);
}

/* rc_conf_files in rc.conf f without Arcana's file (with: add). */
static int
rcf_fix(struct vc_file *f, bool add, bool *changed, char *err,
    size_t errlen)
{
	const struct vc_assign	*a;
	struct vc_file		 d;
	char			 path[MAXPATHLEN], *dflt = NULL, *now, *nl;
	int			 error = 0;

	*changed = false;
	if (vc_read(&d, VC_SH, cf_rooted(path, sizeof(path), RC_DEFAULTS),
	    err, errlen) == 0) {
		a = vc_get(&d, "rc_conf_files");
		dflt = strdup(a != NULL && a->value != NULL ? a->value :
		    "/etc/rc.conf /etc/rc.conf.local");
		vc_free(&d);
	} else
		dflt = strdup("/etc/rc.conf /etc/rc.conf.local");
	if (dflt == NULL)
		return (ENOMEM);
	a = vc_get(f, "rc_conf_files");
	now = strdup(a != NULL && a->value != NULL ? a->value : dflt);
	if (now == NULL) {
		free(dflt);
		return (ENOMEM);
	}
	if (add) {
		char *m = cf_minus(RC_ARCANA, now);

		if (m != NULL && m[0] != '\0') {
			nl = append(strdup(now), RC_ARCANA);
			if (nl == NULL || vc_set(f, "rc_conf_files", nl, err,
			    errlen) == -1)
				error = nl == NULL ? ENOMEM : EIO;
			*changed = error == 0;
			free(nl);
		}
		free(m);
	} else if (a != NULL && (nl = cf_minus(now, RC_ARCANA)) != NULL) {
		if (!cf_same_words(nl, now)) {
			/* As the defaults have it: the line out. */
			if (cf_same_words(nl, dflt))
				error = vc_unset(f, "rc_conf_files", err,
				    errlen) == -1 ? EIO : 0;
			else
				error = vc_set(f, "rc_conf_files", nl, err,
				    errlen) == -1 ? EIO : 0;
			*changed = error == 0;
		}
		free(nl);
	}
	free(now);
	free(dflt);
	return (error);
}

/* The backup: each file kept that was there, copied as it was. */
static int
backup(const struct rca *k, char *dir, size_t dlen, char *err,
    size_t errlen)
{
	char		 stamp[32], path[MAXPATHLEN], base[MAXPATHLEN];
	struct tm	 tm;
	time_t		 now = time(NULL);
	int		 error;

	(void)gmtime_r(&now, &tm);
	(void)strftime(stamp, sizeof(stamp), "%Y%m%dT%H%M%SZ", &tm);
	cf_rooted(base, sizeof(base), CF_BACKUP);
	(void)snprintf(dir, dlen, "%s/%s", base, stamp);
	for (int i = 1; access(dir, F_OK) == 0 && i < 100; i++)
		(void)snprintf(dir, dlen, "%s/%s.%d", base, stamp, i);
	if ((error = mkdirs(dir)) != 0) {
		(void)snprintf(err, errlen, "%s: %s", dir, strerror(error));
		return (error);
	}
	for (size_t i = 0; i < k->nwas; i++) {
		const struct rca_was *w = &k->was[i];

		if (!w->there)
			continue;
		(void)snprintf(path, sizeof(path), "%s%s", dir,
		    cf_unrooted(w->path));
		if ((error = put_file(path, w->text != NULL ? w->text : "",
		    w->len, w->mode != 0 ? w->mode : 0644)) != 0) {
			(void)snprintf(err, errlen, "%s: %s", path,
			    strerror(error));
			return (error);
		}
	}
	return (0);
}

/* The output's strings, a's. */
static char *
adup(cbl_yarena *a, const char *s)
{
	size_t	 len;
	char	*p;

	if (s == NULL)
		return (NULL);
	len = strlen(s) + 1;
	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

struct notes {
	const char	**v;
	size_t		  n;
};

static void
note(cbl_yarena *a, struct notes *nt, const char *fmt, ...)
    __printflike(3, 4);

static void
note(cbl_yarena *a, struct notes *nt, const char *fmt, ...)
{
	const char	**t;
	va_list		  ap;
	char		  buf[1024];

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if ((t = cbl_yarena_alloc(a, (nt->n + 1) * sizeof(*t))) == NULL)
		return;
	if (nt->n > 0)
		memcpy(t, nt->v, nt->n * sizeof(*t));
	t[nt->n] = adup(a, buf);
	nt->v = t;
	nt->n++;
}

/* rows into out, a's. */
static int
rows_out(cbl_yarena *a, const struct row *r, size_t n, char **files,
    const char *dflt_rc, const char *dflt_ld, yswout *out)
{
	yswrow	*o;

	if (n == 0)
		return (0);
	if ((o = cbl_yarena_alloc(a, n * sizeof(*o))) == NULL)
		return (ENOMEM);
	memset(o, 0, n * sizeof(*o));
	for (size_t i = 0; i < n; i++) {
		o[i].kind = r[i].kind == CF_RC ? "rc" : "loader";
		o[i].variable = adup(a, r[i].var);
		o[i].file = adup(a, r[i].at >= 0 ? cf_unrooted(files[r[i].at]) :
		    r[i].kind == CF_RC ? dflt_rc : dflt_ld);
		o[i].yours = adup(a, r[i].yours);
		o[i].arcana = adup(a, r[i].arcana);
		o[i].has_list = true;
		o[i].list = r[i].list;
		o[i].choice = r[i].choice;
		o[i].result = adup(a, r[i].result);
	}
	out->row.v = o;
	out->row.n = n;
	return (0);
}

/*
 * arcana to system.  files: the admin's rc files then the loader's,
 * nrc of the first; uf each read.
 */
static int
to_system(cbl_req *req, const yswin *in, bool dry, cbl_yarena *a,
    yswout *out, struct notes *nt)
{
	struct vc_file	 af, lf, *uf = NULL;
	struct row	*r = NULL;
	struct rca	 k;
	struct fwmove	 fm;
	struct cf_ledger led;
	char		**rcf = NULL, **ldf = NULL, **files = NULL;
	char		 path[MAXPATHLEN], lpath[MAXPATHLEN], err[1024];
	char		 dir[MAXPATHLEN], need[1024];
	size_t		 nrc = 0, nld = 0, nf, nr = 0, rcat;
	bool		*changed = NULL, chg;
	int		 error = 0;

	memset(&k, 0, sizeof(k));
	memset(&led, 0, sizeof(led));
	memset(&af, 0, sizeof(af));
	memset(&lf, 0, sizeof(lf));
	err[0] = need[0] = '\0';
	cf_rooted(path, sizeof(path), RC_ARCANA);
	cf_rooted(lpath, sizeof(lpath), LOADER_ARCANA);
	if (vc_read(&af, VC_SH, path, err, sizeof(err)) == -1 ||
	    vc_read(&lf, VC_LOADER, lpath, err, sizeof(err)) == -1) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}
	if ((error = user_rc_files(&rcf, &nrc, err, sizeof(err))) != 0 ||
	    (error = cf_loader_files(&ldf, &nld)) != 0)
		goto out;
	/* The loader's but Arcana's own. */
	{
		size_t j = 0;

		for (size_t i = 0; i < nld; i++) {
			if (strcmp(ldf[i], lpath) == 0) {
				free(ldf[i]);
				continue;
			}
			ldf[j++] = ldf[i];
		}
		nld = j;
	}
	/* Room for rc.conf and loader.conf where they are not there. */
	nf = nrc + nld + 4;
	if ((files = calloc(nf, sizeof(*files))) == NULL ||
	    (uf = calloc(nf, sizeof(*uf))) == NULL ||
	    (changed = calloc(nf, sizeof(*changed))) == NULL) {
		error = ENOMEM;
		goto out;
	}
	/* /etc/rc.conf the last if it is not there, to write to. */
	rcat = SIZE_MAX;
	for (size_t i = 0; i < nrc; i++) {
		files[i] = rcf[i];
		if (strcmp(cf_unrooted(rcf[i]), RC_CONF) == 0)
			rcat = i;
	}
	for (size_t i = 0; i < nld; i++)
		files[nrc + i] = ldf[i];
	nf = nrc + nld;
	if (rcat == SIZE_MAX) {
		if ((files[nf] = strdup(cf_rooted(dir, sizeof(dir), RC_CONF))) ==
		    NULL) {
			error = ENOMEM;
			goto out;
		}
		rcat = nf++;
	}
	for (size_t i = 0; i < nf; i++)
		if (vc_read(&uf[i], i < nrc || i == rcat ? VC_SH : VC_LOADER,
		    files[i], err, sizeof(err)) == -1) {
			error = errno != 0 ? errno : EIO;
			goto out;
		}
	/* A row a variable of Arcana's, the last value of each. */
	for (int kind = CF_RC; kind <= CF_LOADER; kind++) {
		const struct vc_file *src = kind == CF_RC ? &af : &lf;

		for (size_t i = 0; i < src->na; i++) {
			const struct vc_assign *as = &src->a[i];
			struct row *t, *e;
			size_t lo = kind == CF_RC ? 0 : nrc;
			size_t hi = kind == CF_RC ? nrc : nrc + nld;
			bool dup = false;

			if (as->value == NULL || (kind == CF_RC &&
			    strcmp(as->name, "rc_conf_files") == 0))
				continue;
			for (size_t j = 0; j < nr && !dup; j++)
				dup = r[j].kind == kind && strcmp(r[j].var,
				    as->name) == 0;
			if (dup || vc_get(src, as->name) != as)
				continue;
			if ((t = reallocarray(r, nr + 1, sizeof(*r))) == NULL) {
				error = ENOMEM;
				goto out;
			}
			r = t;
			e = &r[nr++];
			memset(e, 0, sizeof(*e));
			e->kind = kind;
			e->at = -1;
			e->list = kind == CF_RC && cf_list_var(as->name);
			if ((e->var = strdup(as->name)) == NULL ||
			    (e->arcana = strdup(as->value)) == NULL) {
				error = ENOMEM;
				goto out;
			}
			/* Theirs: the last active line, else the last line
			 * taken by Arcana. */
			for (size_t j = hi; j-- > lo && e->yours == NULL; ) {
				const struct vc_assign *u = vc_get(&uf[j],
				    as->name);

				if (u != NULL) {
					e->at = (int)j;
					e->yours = strdup(u->value != NULL ?
					    u->value : "");
				}
			}
			for (size_t j = hi; j-- > lo && e->at < 0; )
				if ((e->yours = taken_value(&uf[j],
				    as->name)) != NULL)
					e->at = (int)j;
			if ((error = choose(e, in, err, sizeof(err))) != 0)
				goto out;
			if (e->choice == NULL && strlen(need) + strlen(e->var) +
			    2 < sizeof(need))
				(void)snprintf(need + strlen(need), sizeof(need) -
				    strlen(need), "%s%s", need[0] != '\0' ? ", " :
				    "", e->var);
		}
	}
	fw_plan(&fm, opts.ipfw_rules, cf_rooted(dir, sizeof(dir),
	    IPFW_RULES_SYS));
	if (fm.go) {
		/* firewall_script follows the script it names. */
		for (size_t i = 0; i < nr; i++)
			if (r[i].kind == CF_RC && strcmp(r[i].var,
			    "firewall_script") == 0 && r[i].result != NULL &&
			    strcmp(r[i].result, fm.fromsh) == 0) {
				free(r[i].result);
				if ((r[i].result = strdup(IPFW_SH_SYS)) == NULL) {
					error = ENOMEM;
					goto out;
				}
			}
	} else if (fm.why[0] != '\0')
		note(a, nt, "%s", fm.why);
	if ((error = rows_out(a, r, nr, files, RC_CONF, LOADER_CONF, out)) !=
	    0)
		goto out;
	if (fm.go) {
		const char **mv;

		if ((mv = cbl_yarena_alloc(a, 2 * sizeof(*mv))) == NULL) {
			error = ENOMEM;
			goto out;
		}
		(void)snprintf(err, sizeof(err), "%s -> %s",
		    cf_unrooted(fm.from), IPFW_RULES_SYS);
		mv[0] = adup(a, err);
		mv[1] = NULL;
		out->moved.n = 1;
		if (fm.has_sh) {
			(void)snprintf(err, sizeof(err), "%s -> %s",
			    cf_unrooted(fm.fromsh), IPFW_SH_SYS);
			mv[1] = adup(a, err);
			out->moved.n = 2;
		}
		out->moved.v = mv;
		err[0] = '\0';
	}
	if (need[0] != '\0') {
		(void)snprintf(err, sizeof(err), "your files and Arcana's set "
		    "different values of %s: choose for each (arcana, yours, "
		    "edit or remove; additive for a word list)", need);
		if (dry) {
			note(a, nt, "%s", err);
			err[0] = '\0';
			goto out;
		}
		(void)cbl_req_set_yapptag(req, "config-merge");
		error = EEXIST;
		goto out;
	}
	if (dry)
		goto out;
	/* Every file it changes kept, and copied, before one is written. */
	for (size_t i = 0; i < nf && error == 0; i++)
		error = rca_keep(&k, files[i]);
	if (error == 0)
		error = rca_keep(&k, path);
	if (error == 0)
		error = rca_keep(&k, lpath);
	if (error == 0)
		error = rca_keep(&k, cf_ledger_path(dir, sizeof(dir)));
	if (error == 0)
		error = fw_keep(&k, &fm);
	if (error == 0)
		error = rca_keep(&k, cf_rooted(dir, sizeof(dir), CF_CONF));
	if (error != 0 || (error = backup(&k, dir, sizeof(dir), err,
	    sizeof(err))) != 0)
		goto out;
	out->backup = adup(a, cf_unrooted(dir));
	/* Their lines taken by Arcana put back, the result where theirs
	 * is, else in rc.conf and loader.conf. */
	for (size_t i = 0; i < nr && error == 0; i++) {
		size_t lo = r[i].kind == CF_RC ? 0 : nrc;
		size_t hi = r[i].kind == CF_RC ? nrc : nrc + nld;
		size_t at;

		for (size_t j = lo; j < hi && error == 0; j++) {
			int n;

			if (!has_taken(&uf[j], r[i].var))
				continue;
			if ((n = vc_uncomment(&uf[j], r[i].var, RCA_TAKEN, err,
			    sizeof(err))) == -1)
				error = errno != 0 ? errno : EINVAL;
			else if (n > 0)
				changed[j] = true;
		}
		if (error != 0)
			break;
		if (strcmp(r[i].choice, "remove") == 0) {
			/* Out of every file of theirs; nothing to give back. */
			for (size_t j = lo; j < hi && error == 0; j++) {
				if (vc_get(&uf[j], r[i].var) == NULL)
					continue;
				if (vc_unset(&uf[j], r[i].var, err,
				    sizeof(err)) == -1)
					error = errno != 0 ? errno : EIO;
				else
					changed[j] = true;
			}
			continue;
		}
		if (r[i].at >= 0)
			at = (size_t)r[i].at;
		else if (r[i].kind == CF_RC)
			at = rcat;
		else {
			char lc[MAXPATHLEN];

			/* loader.conf, made if it is not there. */
			cf_rooted(lc, sizeof(lc), LOADER_CONF);
			for (at = nrc; at < nrc + nld && strcmp(files[at],
			    lc) != 0; at++)
				;
			if (at == nrc + nld) {
				if ((files[nf] = strdup(lc)) == NULL ||
				    vc_read(&uf[nf], VC_LOADER, lc, err,
				    sizeof(err)) == -1 || (error = rca_keep(&k,
				    lc)) != 0) {
					error = error != 0 ? error : EIO;
					break;
				}
				at = nf++;
				/* Kept, nothing to copy: it was not there. */
			}
		}
		if (vc_set(&uf[at], r[i].var, r[i].result, err,
		    sizeof(err)) == -1) {
			error = errno != 0 ? errno : EIO;
			break;
		}
		changed[at] = true;
		/* What Arcana wrote of theirs, for release. */
		error = cf_ledger_put(&led, r[i].kind, r[i].var,
		    cf_unrooted(files[at]), r[i].yours, r[i].result,
		    r[i].arcana);
	}
	/* rc_conf_files without Arcana's file. */
	if (error == 0 && (error = rcf_fix(&uf[rcat], false, &chg, err,
	    sizeof(err))) == 0 && chg)
		changed[rcat] = true;
	for (size_t i = 0; i < nf && error == 0; i++)
		if (changed[i] && vc_write(&uf[i], files[i], 0644, err,
		    sizeof(err)) == -1)
			error = errno != 0 ? errno : EIO;
	if (error == 0 && ((unlink(path) == -1 && errno != ENOENT) ||
	    (unlink(lpath) == -1 && errno != ENOENT))) {
		error = errno;
		(void)snprintf(err, sizeof(err), "Arcana's files out: %s",
		    strerror(error));
	}
	if (error == 0)
		error = fw_do(&fm, err, sizeof(err));
	if (error == 0)
		error = cf_ledger_write(&led, err, sizeof(err));
	if (error == 0)
		error = write_mode(&k, true, fm.go ? IPFW_RULES_SYS : NULL, err,
		    sizeof(err));
	if (error != 0) {
		rca_undo(&k);
		note(a, nt, "every file put back as it was; the copies stay "
		    "in %s", cf_unrooted(dir));
		goto out;
	}
	cf_sys = true;
	if (fm.go) {
		(void)snprintf(cf_ipfw, sizeof(cf_ipfw), "%s", fm.to);
		opts.ipfw_rules = cf_ipfw;
	}
	out->has_done = out->done = true;
	logmsg(LOG_NOTICE, "config-files: the system's files from now on "
	    "(copies of those changed in %s)", cf_unrooted(dir));
out:
	if (error != 0 && error != EEXIST && err[0] == '\0')
		(void)snprintf(err, sizeof(err), "%s", strerror(error));
	if (error != 0)
		(void)cbl_req_set_yerr(req, err, 0);
	for (size_t i = 0; uf != NULL && i < nf; i++)
		vc_free(&uf[i]);
	free(uf);
	free(changed);
	if (files != NULL)
		for (size_t i = nrc + nld; files[i] != NULL; i++)
			free(files[i]);
	free(files);
	vc_rc_files_free(rcf, nrc);
	vc_rc_files_free(ldf, nld);
	rows_free(r, nr);
	vc_free(&af);
	vc_free(&lf);
	cf_ledger_free(&led);
	rca_close(&k);
	return (error);
}

/*
 * system to arcana: the admin's rc.conf variables (rc_conf_files'
 * files, the last value of each) and the loader's tunables cloned into
 * Arcana's files, which rc(8) and the loader read last; rc_conf_files
 * names Arcana's file; nothing else of theirs changed.
 */
static int
to_arcana(cbl_req *req, bool dry, cbl_yarena *a, yswout *out,
    struct notes *nt)
{
	struct vc_file	 af, lf, rc, f;
	struct row	*r = NULL;
	struct rca	 k;
	struct fwmove	 fm;
	struct cf_ledger none;
	char		**rcf = NULL, **ldf = NULL;
	char		 path[MAXPATHLEN], lpath[MAXPATHLEN], rcp[MAXPATHLEN];
	char		 dir[MAXPATHLEN], err[1024], fsh[MAXPATHLEN];
	size_t		 nrc = 0, nld = 0, nr = 0;
	bool		 chg;
	int		 error = 0;

	memset(&k, 0, sizeof(k));
	memset(&none, 0, sizeof(none));
	memset(&af, 0, sizeof(af));
	memset(&lf, 0, sizeof(lf));
	memset(&rc, 0, sizeof(rc));
	err[0] = '\0';
	cf_rooted(path, sizeof(path), RC_ARCANA);
	cf_rooted(lpath, sizeof(lpath), LOADER_ARCANA);
	cf_rooted(rcp, sizeof(rcp), RC_CONF);
	if ((error = user_rc_files(&rcf, &nrc, err, sizeof(err))) != 0 ||
	    (error = cf_loader_files(&ldf, &nld)) != 0)
		goto out;
	if (vc_parse(&af, VC_SH, "", 0, err, sizeof(err)) == -1 ||
	    vc_parse(&lf, VC_LOADER, "", 0, err, sizeof(err)) == -1 ||
	    vc_read(&rc, VC_SH, rcp, err, sizeof(err)) == -1) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}
	for (int kind = CF_RC; kind <= CF_LOADER && error == 0; kind++) {
		char **v = kind == CF_RC ? rcf : ldf;
		size_t n = kind == CF_RC ? nrc : nld;

		for (size_t i = 0; i < n && error == 0; i++) {
			if (vc_read(&f, kind == CF_RC ? VC_SH : VC_LOADER, v[i],
			    err, sizeof(err)) == -1) {
				error = errno != 0 ? errno : EIO;
				break;
			}
			for (size_t j = 0; j < f.na && error == 0; j++) {
				const struct vc_assign *as = &f.a[j];
				struct row *t, *e = NULL;

				if (as->value == NULL || (as->flags & (VC_COND |
				    VC_OPAQUE)) != 0 || (kind == CF_RC &&
				    strcmp(as->name, "rc_conf_files") == 0) ||
				    (kind == CF_LOADER && strchr(as->name, '.') ==
				    NULL))
					continue;
				for (size_t m = 0; m < nr && e == NULL; m++)
					if (r[m].kind == kind && strcmp(r[m].var,
					    as->name) == 0)
						e = &r[m];
				if (e == NULL) {
					if ((t = reallocarray(r, nr + 1,
					    sizeof(*r))) == NULL) {
						error = ENOMEM;
						break;
					}
					r = t;
					e = &r[nr++];
					memset(e, 0, sizeof(*e));
					e->kind = kind;
					e->list = kind == CF_RC &&
					    cf_list_var(as->name);
					if ((e->var = strdup(as->name)) == NULL) {
						error = ENOMEM;
						break;
					}
				}
				free(e->yours);
				free(e->arcana);
				free(e->result);
				e->yours = strdup(as->value);
				e->arcana = strdup(as->value);
				e->result = strdup(as->value);
				e->choice = "clone";
				if (e->yours == NULL || e->arcana == NULL ||
				    e->result == NULL)
					error = ENOMEM;
			}
			vc_free(&f);
		}
	}
	if (error != 0)
		goto out;
	/* The firewall's files back to Arcana's directory, theirs alone. */
	fw_plan(&fm, opts.ipfw_rules, cf_ipfw_home());
	if (fm.go) {
		script_of(cf_unrooted(fm.from), fsh, sizeof(fsh));
		for (size_t i = 0; i < nr; i++)
			if (r[i].kind == CF_RC && strcmp(r[i].var,
			    "firewall_script") == 0 && strcmp(r[i].result,
			    fsh) == 0) {
				free(r[i].result);
				if ((r[i].result = strdup(fm.tosh)) == NULL) {
					error = ENOMEM;
					goto out;
				}
			}
		out->moved.n = fm.has_sh ? 2 : 1;
		{
			const char **mv;

			if ((mv = cbl_yarena_alloc(a, 2 * sizeof(*mv))) ==
			    NULL) {
				error = ENOMEM;
				goto out;
			}
			(void)snprintf(err, sizeof(err), "%s -> %s",
			    cf_unrooted(fm.from), cf_unrooted(fm.to));
			mv[0] = adup(a, err);
			(void)snprintf(err, sizeof(err), "%s -> %s",
			    cf_unrooted(fm.fromsh), cf_unrooted(fm.tosh));
			mv[1] = adup(a, err);
			out->moved.v = mv;
			err[0] = '\0';
		}
	} else if (strcmp(opts.ipfw_rules, cf_ipfw_home()) != 0 &&
	    fm.why[0] != '\0')
		note(a, nt, "%s", fm.why);
	for (size_t i = 0; i < nr; i++)
		r[i].at = -1;
	if ((error = rows_out(a, r, nr, NULL, RC_ARCANA, LOADER_ARCANA,
	    out)) != 0 || dry)
		goto out;
	for (size_t i = 0; i < nr && error == 0; i++)
		if (vc_set(r[i].kind == CF_RC ? &af : &lf, r[i].var,
		    r[i].result, err, sizeof(err)) == -1)
			error = errno != 0 ? errno : EIO;
	if (error != 0)
		goto out;
	if ((error = rca_keep(&k, path)) != 0 ||
	    (error = rca_keep(&k, lpath)) != 0 ||
	    (error = rca_keep(&k, rcp)) != 0 ||
	    (error = rca_keep(&k, cf_ledger_path(dir, sizeof(dir)))) != 0 ||
	    (error = fw_keep(&k, &fm)) != 0 ||
	    (error = rca_keep(&k, cf_rooted(dir, sizeof(dir), CF_CONF))) !=
	    0 || (error = backup(&k, dir, sizeof(dir), err, sizeof(err))) != 0)
		goto out;
	out->backup = adup(a, cf_unrooted(dir));
	(void)mkparent(path);
	(void)mkparent(lpath);
	if (vc_write(&af, path, 0644, err, sizeof(err)) == -1 ||
	    (lf.na > 0 && vc_write(&lf, lpath, 0644, err, sizeof(err)) == -1))
		error = errno != 0 ? errno : EIO;
	if (error == 0 && (error = rcf_fix(&rc, true, &chg, err,
	    sizeof(err))) == 0 && chg && vc_write(&rc, rcp, 0644, err,
	    sizeof(err)) == -1)
		error = errno != 0 ? errno : EIO;
	if (error == 0)
		error = fw_do(&fm, err, sizeof(err));
	/* The ledger's merges are the admin's lines now, as they are. */
	if (error == 0)
		error = cf_ledger_write(&none, err, sizeof(err));
	if (error == 0)
		error = write_mode(&k, false, NULL, err, sizeof(err));
	if (error != 0) {
		rca_undo(&k);
		note(a, nt, "every file put back as it was; the copies stay "
		    "in %s", cf_unrooted(dir));
		goto out;
	}
	cf_sys = false;
	cf_ipfw[0] = '\0';
	opts.ipfw_rules = cf_ipfw_home();
	out->has_done = out->done = true;
	logmsg(LOG_NOTICE, "config-files: Arcana's own files from now on, "
	    "a clone of the system's (copies of those changed in %s)",
	    cf_unrooted(dir));
out:
	if (error != 0 && err[0] == '\0')
		(void)snprintf(err, sizeof(err), "%s", strerror(error));
	if (error != 0)
		(void)cbl_req_set_yerr(req, err, 0);
	vc_rc_files_free(rcf, nrc);
	vc_rc_files_free(ldf, nld);
	rows_free(r, nr);
	vc_free(&af);
	vc_free(&lf);
	vc_free(&rc);
	rca_close(&k);
	return (error);
}

/*
 * The switch action: in's to, dry a dry run; out the rows, the moves,
 * the backup and notes.
 */
int
cf_switch(cbl_req *req, const yswin *in, cbl_yarena *a, yswout *out)
{
	struct notes	 nt = { NULL, 0 };
	bool		 dry = in->has_dry_run && in->dry_run;
	bool		 sys = in->has_to && in->to ==
			    ARCANA_AGENT_AGENT_CONFIG_FILES_SWITCH_INPUT_TO_SYSTEM;
	int		 error;

	if (!in->has_to) {
		(void)cbl_req_set_yerr(req, "to: arcana or system", 0);
		return (EINVAL);
	}
	out->from = cf_sys ? "system" : "arcana";
	out->to = sys ? "system" : "arcana";
	out->has_done = true;
	out->done = false;
	if (sys == cf_sys) {
		note(a, &nt, "the host is on %s already: nothing to do",
		    sys ? "the system's files" : "Arcana's own files");
		out->note.v = nt.v;
		out->note.n = nt.n;
		return (0);
	}
	error = sys ? to_system(req, in, dry, a, out, &nt) :
	    to_arcana(req, dry, a, out, &nt);
	if (error == 0) {
		if (sys)
			note(a, &nt, "nothing is loaded now: rc(8) reads rc.conf "
			    "at each service's start and at boot, the loader "
			    "loader.conf at the next boot");
		else
			note(a, &nt, "Arcana's files are a clone of yours, read "
			    "after them (rc_conf_files; loader.conf.d): what "
			    "boots is the same; your files are as they were but "
			    "rc_conf_files, which names Arcana's");
		if (dry)
			note(a, &nt, "a dry run: nothing written");
	}
	out->note.v = nt.v;
	out->note.n = nt.n;
	return (error);
}

/* resolve: values for pending rows; *n those given one. */
int
cf_resolve(const struct arcana_agent_agent_config_files_resolve_input *in,
    uint32_t *n)
{

	*n = 0;
	pthread_mutex_lock(&pend_lock);
	for (size_t i = 0; i < in->row.n; i++) {
		const struct arcana_agent_agent_config_files_resolve_input_row
		    *r = &in->row.v[i];
		int kind = r->kind ==
		    ARCANA_AGENT_AGENT_CONFIG_FILES_RESOLVE_INPUT_ROW_KIND_RC ?
		    CF_RC : CF_LOADER;

		if (r->variable == NULL || r->value == NULL)
			continue;
		for (size_t k = 0; k < npend; k++) {
			char *v;

			if (pend[k].kind != kind || strcmp(pend[k].var,
			    r->variable) != 0 || (v = strdup(r->value)) == NULL)
				continue;
			free(pend[k].value);
			pend[k].value = v;
			(*n)++;
		}
	}
	pthread_mutex_unlock(&pend_lock);
	return (0);
}

/* config-files as state, a's. */
int
cf_state(cbl_yarena *a, const struct arcana_agent_agent_config_files **op)
{
	struct arcana_agent_agent_config_files		*o;
	struct arcana_agent_agent_config_files_pending	*p = NULL;
	struct arcana_agent_agent_config_files_ledger	*l = NULL;
	struct cf_ledger				 led;

	*op = NULL;
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	memset(o, 0, sizeof(*o));
	o->has_mode = true;
	o->mode = cf_sys ? ARCANA_AGENT_AGENT_CONFIG_FILES_MODE_SYSTEM :
	    ARCANA_AGENT_AGENT_CONFIG_FILES_MODE_ARCANA;
	o->rc_file = cf_sys ? RC_CONF : RC_ARCANA;
	o->loader_file = cf_sys ? LOADER_CONF : LOADER_ARCANA;
	o->firewall_rules = adup(a, cf_unrooted(opts.ipfw_rules));
	pthread_mutex_lock(&pend_lock);
	if (npend > 0 && (p = cbl_yarena_alloc(a, npend * sizeof(*p))) !=
	    NULL) {
		memset(p, 0, npend * sizeof(*p));
		for (size_t i = 0; i < npend; i++) {
			p[i].kind = pend[i].kind == CF_RC ?
			    ARCANA_AGENT_AGENT_CONFIG_FILES_PENDING_KIND_RC :
			    ARCANA_AGENT_AGENT_CONFIG_FILES_PENDING_KIND_LOADER;
			p[i].variable = adup(a, pend[i].var);
			p[i].file = adup(a, pend[i].file);
			p[i].has_line = pend[i].line > 0;
			p[i].line = (uint32_t)pend[i].line;
			p[i].yours = adup(a, pend[i].yours);
			p[i].proposed = adup(a, pend[i].proposed);
			p[i].value = adup(a, pend[i].value);
		}
		o->pending.v = p;
		o->pending.n = npend;
	}
	pthread_mutex_unlock(&pend_lock);
	if (cf_ledger_read(&led) == 0 && led.n > 0 && (l =
	    cbl_yarena_alloc(a, led.n * sizeof(*l))) != NULL) {
		memset(l, 0, led.n * sizeof(*l));
		for (size_t i = 0; i < led.n; i++) {
			l[i].kind = led.v[i].kind == CF_RC ?
			    ARCANA_AGENT_AGENT_CONFIG_FILES_LEDGER_KIND_RC :
			    ARCANA_AGENT_AGENT_CONFIG_FILES_LEDGER_KIND_LOADER;
			l[i].variable = adup(a, led.v[i].var);
			l[i].file = adup(a, led.v[i].file);
			l[i].before = adup(a, led.v[i].before);
			l[i].after = adup(a, led.v[i].after);
			l[i].arcana = adup(a, led.v[i].arcana);
		}
		o->ledger.v = l;
		o->ledger.n = led.n;
	}
	cf_ledger_free(&led);
	*op = o;
	return (0);
}
