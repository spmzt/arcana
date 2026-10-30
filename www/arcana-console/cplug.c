/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Console plugins: extensions of the console's page, served by the
 * console.  Not the hosts' plugins (BIRD, Suricata and the others of
 * hosts.c and yplug.c), which run on the hosts.
 *
 * A console plugin is a directory under web.conf's plugins_dir, named
 * by its id, with a plugin.json:
 *
 *	{ "id": "x", "name": "X", "version": "1.0", "arcana": "0.337.0",
 *	  "description": "...", "author": "...",
 *	  "entry": [ "main.js" ], "styles": [ "x.css" ],
 *	  "assets": [ "img/a.png", "pack.json" ], "provides": [ "theme" ] }
 *
 * arcana is the least console version it runs on; an asset may be a
 * glob(3) pattern, of files of those kinds alone.  Every file it lists
 * is checked, sized and hashed (SHA-384, the page's integrity); a
 * plugin with anything wrong is listed with why, and none of it is
 * served.  What is served is a listed file of a plugin a console owner
 * enabled, to a signed-in session, from inside the plugin's directory
 * (symbolic links followed only as far as that).  A plugin runs with
 * the page's rights: what the console host's administrator installed
 * and a console owner enabled alone.
 *
 * The directory is looked at again, at most once a CHECK_MS, on each
 * /api/plugins and plugin file asked for: rescanned when it, a plugin's
 * directory, a plugin.json or a directory of a listed file changed; a
 * listed file whose time or size changed hashed again.  Which are
 * enabled is console-plugins.json in the data directory, {"enabled":
 * {"<id>": {"by": who, "at": time}}}, read again when it changed (a
 * cluster's other node wrote it).
 *
 * And a store each, for what a plugin keeps of a user's or of all its
 * users' (api_cplug_store(), below): not for secrets.
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "console.h"

#define	CPLUG_STATE	"console-plugins.json"
#define	CPLUGS_MAX	64		/* plugins */
#define	CPLUG_FILES	256		/* files a plugin lists */
#define	CPLUG_DIRS	32		/* directories looked at a plugin */
#define	CPLUG_FILE_MAX	(8 * 1024 * 1024)
#define	MANIFEST_MAX	(64 * 1024)
#define	CHECK_MS	1000
#define	ID_MAX		40
#define	PATH_MAX_REL	200

enum fkind { F_SCRIPT, F_STYLE, F_ASSET };

struct cfile {
	char		*path;		/* in the plugin's directory */
	enum fkind	 kind;
	off_t		 size;
	ino_t		 ino;
	struct timespec	 mtim;
	char		 sri[72];	/* base64 of the SHA-384 */
};

struct cwatch {
	char		*path;
	struct timespec	 mtim;
};

struct cplug {
	char		 id[ID_MAX + 1];
	char		*dir;		/* real path, its files' bound */
	ucl_object_t	*m;		/* plugin.json, or NULL */
	char		*error;		/* why it is not served, or NULL */
	struct cfile	*files;
	int		 nfiles;
	struct cwatch	 watch[CPLUG_DIRS];	/* plugin.json the first */
	int		 nwatch;
};

static struct {
	char		*dir;		/* plugins_dir scanned */
	struct timespec	 mtim;
	bool		 scanned;
	uint64_t	 checked;	/* ms, monotonic */
	struct cplug	*v;
	int		 n;
	struct timespec	 state_mtim;	/* of console-plugins.json */
	bool		 state_read;
	ucl_object_t	*state;
} cp;

static const struct {
	const char	*ext;
	const char	*type;
	enum fkind	 kind;
} types[] = {
	{ "js", "text/javascript; charset=utf-8", F_SCRIPT },
	{ "css", "text/css; charset=utf-8", F_STYLE },
	{ "png", "image/png", F_ASSET },
	{ "svg", "image/svg+xml", F_ASSET },
	{ "webp", "image/webp", F_ASSET },
	{ "json", "application/json", F_ASSET },
	{ "woff2", "font/woff2", F_ASSET },
};

static uint64_t
now_ms(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

static bool
same_time(const struct timespec *a, const struct timespec *b)
{

	return (a->tv_sec == b->tv_sec && a->tv_nsec == b->tv_nsec);
}

/* An id: [a-z0-9-], 1 to 40. */
static bool
id_ok(const char *s)
{
	size_t	n;

	n = strlen(s);
	return (n > 0 && n <= ID_MAX && strspn(s,
	    "abcdefghijklmnopqrstuvwxyz0123456789-") == n);
}

/* What a file's name says it is; -1 for none served. */
static int
type_of(const char *path)
{
	const char	*dot;
	size_t		 i;

	if ((dot = strrchr(path, '.')) == NULL || strchr(dot, '/') != NULL)
		return (-1);
	for (i = 0; i < nitems(types); i++)
		if (strcmp(dot + 1, types[i].ext) == 0)
			return ((int)i);
	return (-1);
}

/*
 * A path in a plugin's directory as plugin.json may name it: relative,
 * no part empty or hidden (".", ".." and dot files with them), of
 * letters, digits and _ . - @ +; with glob, * ? [ ] too.
 */
static bool
path_ok(const char *p, bool glob)
{
	const char	*s;
	size_t		 n;

	n = strlen(p);
	if (n == 0 || n > PATH_MAX_REL || strspn(p, glob ?
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789_.-@+/*?[]" :
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789_.-@+/") != n)
		return (false);
	/* Each part's first character. */
	for (s = p;; s++) {
		if (*s == '/' || *s == '.' || *s == '\0')
			return (false);
		if ((s = strchr(s, '/')) == NULL)
			return (true);
	}
}

/* "a.b.c" of numbers, into v. */
static bool
version_of(const char *s, long v[3])
{
	char	*e;
	int	 i;

	for (i = 0; i < 3; i++) {
		if (*s < '0' || *s > '9')
			return (false);
		errno = 0;
		v[i] = strtol(s, &e, 10);
		if (errno != 0 || e - s > 6)
			return (false);
		s = e;
		if (i < 2 && *s++ != '.')
			return (false);
	}
	return (*s == '\0');
}

/* Printable text, without controls, at most max bytes. */
static bool
text_ok(const char *s, size_t max)
{
	size_t	n;

	n = strlen(s);
	if (n > max)
		return (false);
	for (; *s != '\0'; s++)
		if ((unsigned char)*s < 0x20 || *s == 0x7f)
			return (false);
	return (true);
}

static void
plug_free(struct cplug *p)
{
	int	i;

	free(p->dir);
	if (p->m != NULL)
		ucl_object_unref(p->m);
	free(p->error);
	for (i = 0; i < p->nfiles; i++)
		free(p->files[i].path);
	free(p->files);
	for (i = 0; i < p->nwatch; i++)
		free(p->watch[i].path);
	memset(p, 0, sizeof(*p));
}

static void
plugs_clear(void)
{
	int	i;

	for (i = 0; i < cp.n; i++)
		plug_free(&cp.v[i]);
	free(cp.v);
	cp.v = NULL;
	cp.n = 0;
}

static bool
fail(struct cplug *p, const char *fmt, ...) __printflike(2, 3);

static bool
fail(struct cplug *p, const char *fmt, ...)
{
	va_list	ap;

	if (p->error != NULL)
		return (false);
	va_start(ap, fmt);
	if (vasprintf(&p->error, fmt, ap) == -1)
		p->error = xstrdup("cannot be read");
	va_end(ap);
	return (false);
}

/*
 * A file of the plugin, read whole into *bufp (when bufp is not NULL)
 * and hashed: its real path inside the plugin's directory, a regular
 * file, not larger than CPLUG_FILE_MAX.  NULL, or why not.
 */
static const char *
file_read(const struct cplug *p, const char *rel, struct stat *sb,
    char sri[72], uint8_t **bufp)
{
	uint8_t		 md[EVP_MAX_MD_SIZE], *buf;
	char		 full[MAXPATHLEN], real[MAXPATHLEN], *b64;
	unsigned int	 mdlen;
	size_t		 dl, got;
	ssize_t		 r;
	int		 fd;

	if (bufp != NULL)
		*bufp = NULL;
	snprintf(full, sizeof(full), "%s/%s", p->dir, rel);
	if (realpath(full, real) == NULL)
		return ("missing");
	dl = strlen(p->dir);
	if (strncmp(real, p->dir, dl) != 0 || real[dl] != '/')
		return ("outside the plugin's directory");
	if ((fd = open(real, O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
	    O_NONBLOCK)) == -1)
		return ("cannot be opened");
	if (fstat(fd, sb) == -1 || !S_ISREG(sb->st_mode)) {
		close(fd);
		return ("not a file");
	}
	if (sb->st_size > CPLUG_FILE_MAX) {
		close(fd);
		return ("larger than 8 MB");
	}
	buf = xmalloc((size_t)sb->st_size + 1);
	for (got = 0; got < (size_t)sb->st_size; got += (size_t)r)
		if ((r = read(fd, buf + got, (size_t)sb->st_size - got)) <= 0)
			break;
	close(fd);
	if (got != (size_t)sb->st_size) {
		free(buf);
		return ("cannot be read");
	}
	EVP_Digest(buf, got, md, &mdlen, EVP_sha384(), NULL);
	b64_encode(md, mdlen, &b64);
	snprintf(sri, 72, "%s", b64);
	free(b64);
	if (bufp != NULL)
		*bufp = buf;
	else
		free(buf);
	return (NULL);
}

/* A directory whose change is looked for. */
static void
watch_add(struct cplug *p, const char *path)
{
	struct stat	sb;
	int		i;

	for (i = 0; i < p->nwatch; i++)
		if (strcmp(p->watch[i].path, path) == 0)
			return;
	if (p->nwatch == CPLUG_DIRS || stat(path, &sb) == -1)
		return;
	p->watch[p->nwatch].path = xstrdup(path);
	p->watch[p->nwatch++].mtim = sb.st_mtim;
}

/* A file listed: checked and hashed once, however often named. */
static bool
file_add(struct cplug *p, const char *rel, enum fkind kind)
{
	struct cfile	*f;
	struct stat	 sb;
	const char	*why;
	char		 dir[MAXPATHLEN], *s;
	int		 i, t;

	for (i = 0; i < p->nfiles; i++)
		if (strcmp(p->files[i].path, rel) == 0)
			return (true);
	if ((t = type_of(rel)) == -1 || types[t].kind != kind)
		return (fail(p, "%s: %s", rel, kind == F_SCRIPT ? "a script is "
		    "a .js" : kind == F_STYLE ? "a style is a .css" : "an asset "
		    "is a .png, .svg, .webp, .json or .woff2"));
	if (p->nfiles == CPLUG_FILES)
		return (fail(p, "more than %d files", CPLUG_FILES));
	p->files = xrealloc(p->files, sizeof(*p->files) * (size_t)(p->nfiles +
	    1));
	f = &p->files[p->nfiles];
	memset(f, 0, sizeof(*f));
	if ((why = file_read(p, rel, &sb, f->sri, NULL)) != NULL)
		return (fail(p, "%s: %s", rel, why));
	f->path = xstrdup(rel);
	f->kind = kind;
	f->size = sb.st_size;
	f->ino = sb.st_ino;
	f->mtim = sb.st_mtim;
	p->nfiles++;
	snprintf(dir, sizeof(dir), "%s/%s", p->dir, rel);
	if ((s = strrchr(dir, '/')) != NULL) {
		*s = '\0';
		watch_add(p, dir);
	}
	return (true);
}

/* An asset's glob, under the plugin's directory. */
static bool
glob_add(struct cplug *p, const char *pat)
{
	glob_t		 g;
	char		 full[MAXPATHLEN * 2], *o;
	const char	*s, *rel;
	size_t		 i, dl;
	int		 rc;

	/* The directory's own name taken as it is, whatever it holds. */
	for (o = full, s = p->dir; *s != '\0' && o < full + MAXPATHLEN; s++) {
		if (strchr("*?[]\\", *s) != NULL)
			*o++ = '\\';
		*o++ = *s;
	}
	snprintf(o, sizeof(full) - (size_t)(o - full), "/%s", pat);
	memset(&g, 0, sizeof(g));
	if ((rc = glob(full, 0, NULL, &g)) != 0 && rc != GLOB_NOMATCH) {
		globfree(&g);
		return (fail(p, "%s: cannot be looked for", pat));
	}
	dl = strlen(p->dir);
	for (i = 0; i < g.gl_pathc; i++) {
		rel = g.gl_pathv[i] + dl + 1;
		if (!path_ok(rel, false)) {
			globfree(&g);
			return (fail(p, "%s: %s is not a name served", pat, rel));
		}
		if (!file_add(p, rel, F_ASSET)) {
			globfree(&g);
			return (false);
		}
	}
	globfree(&g);
	return (true);
}

/* A list of plugin.json's: of files, or with globs, or of words. */
static bool
list_check(struct cplug *p, const char *key, enum fkind kind, bool words)
{
	const ucl_object_t	*a, *e;
	ucl_object_iter_t	 it;
	const char		*s;

	if ((a = ucl_object_lookup(p->m, key)) == NULL)
		return (true);
	if (ucl_object_type(a) != UCL_ARRAY)
		return (fail(p, "%s is a list", key));
	it = NULL;
	while ((e = ucl_object_iterate(a, &it, true)) != NULL) {
		if (ucl_object_type(e) != UCL_STRING)
			return (fail(p, "%s: a list of strings", key));
		s = ucl_object_tostring(e);
		if (words) {
			if (!id_ok(s) || strlen(s) > 32)
				return (fail(p, "%s: \"%s\" is not a word of "
				    "a-z, 0-9 and -", key, s));
			continue;
		}
		if (!path_ok(s, kind == F_ASSET))
			return (fail(p, "%s: \"%s\" is not a path in the "
			    "plugin's directory", key, s));
		if (kind == F_ASSET && strpbrk(s, "*?[") != NULL) {
			if (!glob_add(p, s))
				return (false);
		} else if (!file_add(p, s, kind))
			return (false);
	}
	return (true);
}

/* A text of plugin.json's: required or not, at most max. */
static bool
text_check(struct cplug *p, const char *key, bool required, size_t max)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(p->m, key)) == NULL)
		return (required ? fail(p, "%s is missing", key) : true);
	if (ucl_object_type(v) != UCL_STRING || !text_ok(ucl_object_tostring(v),
	    max) || (required && ucl_object_tostring(v)[0] == '\0'))
		return (fail(p, "%s: a line of text, %zu bytes at most", key,
		    max));
	return (true);
}

/* plugin.json read and checked, and the files it lists. */
static void
plug_load(struct cplug *p, const char *top, const char *name)
{
	static const char	*keys[] = { "id", "name", "version", "arcana",
				    "description", "author", "entry", "styles",
				    "assets", "provides" };
	struct ucl_parser	*ps;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	struct stat		 sb;
	char			 path[MAXPATHLEN], real[MAXPATHLEN];
	const char		*s;
	long			 want[3], have[3];
	size_t			 i;
	int			 fd;

	snprintf(p->id, sizeof(p->id), "%s", name);
	if (!id_ok(name)) {
		fail(p, "the directory's name is not an id: a-z, 0-9 and -, "
		    "%d at most", ID_MAX);
		return;
	}
	snprintf(path, sizeof(path), "%s/%s", top, name);
	if (realpath(path, real) == NULL) {
		fail(p, "cannot be read");
		return;
	}
	p->dir = xstrdup(real);
	snprintf(path, sizeof(path), "%s/plugin.json", p->dir);
	watch_add(p, path);
	watch_add(p, p->dir);
	if (p->nwatch != 2) {
		fail(p, "no plugin.json");
		return;
	}
	if ((fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) == -1 ||
	    fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode) ||
	    sb.st_size > MANIFEST_MAX) {
		if (fd != -1)
			close(fd);
		fail(p, "plugin.json is not a file of %d KB at most",
		    MANIFEST_MAX / 1024);
		return;
	}
	/* No macros: nothing included from elsewhere. */
	ps = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	if (!ucl_parser_add_fd(ps, fd)) {
		fail(p, "plugin.json: %s", ucl_parser_get_error(ps));
		ucl_parser_free(ps);
		close(fd);
		return;
	}
	close(fd);
	p->m = ucl_parser_get_object(ps);
	ucl_parser_free(ps);
	if (p->m == NULL || ucl_object_type(p->m) != UCL_OBJECT) {
		fail(p, "plugin.json is not an object");
		return;
	}
	/* What it needs first: a newer console's plugin may say more. */
	if (!text_check(p, "arcana", true, 20))
		return;
	s = ucl_str(p->m, "arcana");
	if (!version_of(s, want)) {
		fail(p, "arcana: the least console version, as 0.337.0");
		return;
	}
	if (!version_of(ARCW_VERSION, have)) {
		fail(p, "this console's version %s is not a.b.c",
		    ARCW_VERSION);
		return;
	}
	for (i = 0; i < 3 && want[i] == have[i]; i++)
		;
	if (i < 3 && want[i] > have[i]) {
		fail(p, "needs console %s or newer; this is %s", s,
		    ARCW_VERSION);
		return;
	}
	it = NULL;
	while ((v = ucl_object_iterate(p->m, &it, true)) != NULL) {
		for (i = 0; i < nitems(keys); i++)
			if (strcmp(ucl_object_key(v), keys[i]) == 0)
				break;
		if (i == nitems(keys)) {
			fail(p, "plugin.json: unknown key %s",
			    ucl_object_key(v));
			return;
		}
	}
	if (!text_check(p, "id", true, ID_MAX))
		return;
	if (strcmp(ucl_str(p->m, "id"), name) != 0) {
		fail(p, "id %s is not the directory's name", ucl_str(p->m,
		    "id"));
		return;
	}
	if (!text_check(p, "name", true, 64) ||
	    !text_check(p, "version", true, 32) ||
	    !text_check(p, "description", false, 1024) ||
	    !text_check(p, "author", false, 128))
		return;
	s = ucl_str(p->m, "version");
	if (strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789.+-") != strlen(s)) {
		fail(p, "version: letters, digits and . + -");
		return;
	}
	(void)(list_check(p, "provides", F_ASSET, true) &&
	    list_check(p, "entry", F_SCRIPT, false) &&
	    list_check(p, "styles", F_STYLE, false) &&
	    list_check(p, "assets", F_ASSET, false));
}

static int
plug_cmp(const void *a, const void *b)
{

	return (strcmp(((const struct cplug *)a)->id,
	    ((const struct cplug *)b)->id));
}

/* plugins_dir read again whole. */
static void
rescan(const char *top, const struct stat *tsb)
{
	DIR		*d;
	struct dirent	*e;
	struct stat	 sb;
	char		 path[MAXPATHLEN];

	plugs_clear();
	cp.mtim = tsb->st_mtim;
	if ((d = opendir(top)) == NULL)
		return;
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		/* A directory of its own; not a link to one elsewhere. */
		snprintf(path, sizeof(path), "%s/%s", top, e->d_name);
		if (lstat(path, &sb) == -1 || !S_ISDIR(sb.st_mode))
			continue;
		if (cp.n == CPLUGS_MAX) {
			log_msg(LOG_WARNING, "%s: more than %d console plugins, "
			    "the rest not read", top, CPLUGS_MAX);
			break;
		}
		cp.v = xrealloc(cp.v, sizeof(*cp.v) * (size_t)(cp.n + 1));
		memset(&cp.v[cp.n], 0, sizeof(cp.v[cp.n]));
		plug_load(&cp.v[cp.n], top, e->d_name);
		if (cp.v[cp.n].error != NULL)
			log_msg(LOG_WARNING, "console plugin %s: %s",
			    cp.v[cp.n].id, cp.v[cp.n].error);
		cp.n++;
	}
	closedir(d);
	qsort(cp.v, (size_t)cp.n, sizeof(*cp.v), plug_cmp);
}

/* A listed file changed since: hashed again; false when it is gone or
 * no longer what may be served. */
static bool
file_fresh(struct cplug *p, struct cfile *f)
{
	struct stat	 sb;
	char		 full[MAXPATHLEN];

	snprintf(full, sizeof(full), "%s/%s", p->dir, f->path);
	if (stat(full, &sb) == -1)
		return (false);
	if (sb.st_size == f->size && sb.st_ino == f->ino &&
	    same_time(&sb.st_mtim, &f->mtim))
		return (true);
	if (file_read(p, f->path, &sb, f->sri, NULL) != NULL)
		return (false);
	f->size = sb.st_size;
	f->ino = sb.st_ino;
	f->mtim = sb.st_mtim;
	return (true);
}

/* The directory looked at, at most once a CHECK_MS. */
static void
cplug_check(void)
{
	struct stat	 sb;
	const char	*top;
	uint64_t	 now;
	bool		 again;
	int		 i, j;

	now = now_ms();
	if (cp.scanned && now - cp.checked < CHECK_MS)
		return;
	cp.checked = now;
	top = cfg.plugins_dir;
	if (top == NULL || top[0] == '\0' || stat(top, &sb) == -1 ||
	    !S_ISDIR(sb.st_mode)) {
		plugs_clear();
		cp.scanned = true;
		free(cp.dir);
		cp.dir = NULL;
		return;
	}
	again = !cp.scanned || cp.dir == NULL || strcmp(cp.dir, top) != 0 ||
	    !same_time(&sb.st_mtim, &cp.mtim);
	for (i = 0; !again && i < cp.n; i++) {
		struct cplug	*p = &cp.v[i];
		struct stat	 wsb;

		for (j = 0; !again && j < p->nwatch; j++)
			again = stat(p->watch[j].path, &wsb) == -1 ||
			    !same_time(&wsb.st_mtim, &p->watch[j].mtim);
		for (j = 0; !again && p->error == NULL && j < p->nfiles; j++)
			again = !file_fresh(p, &p->files[j]);
	}
	if (again) {
		free(cp.dir);
		cp.dir = xstrdup(top);
		rescan(top, &sb);
	}
	cp.scanned = true;
}

/* console-plugins.json, read again when it changed. */
static void
state_check(void)
{
	struct stat	sb;
	char		path[MAXPATHLEN];

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, CPLUG_STATE);
	if (stat(path, &sb) == -1)
		memset(&sb, 0, sizeof(sb));
	if (cp.state_read && same_time(&sb.st_mtim, &cp.state_mtim))
		return;
	if (cp.state != NULL)
		ucl_object_unref(cp.state);
	if ((cp.state = store_load(CPLUG_STATE)) == NULL ||
	    ucl_object_type(cp.state) != UCL_OBJECT) {
		if (cp.state != NULL)
			ucl_object_unref(cp.state);
		cp.state = ucl_object_typed_new(UCL_OBJECT);
	}
	if (ucl_object_lookup(cp.state, "enabled") == NULL)
		ucl_object_insert_key(cp.state, ucl_object_typed_new(UCL_OBJECT),
		    "enabled", 0, false);
	cp.state_mtim = sb.st_mtim;
	cp.state_read = true;
}

static bool
enabled(const char *id)
{

	return (ucl_object_lookup(ucl_object_lookup(cp.state, "enabled"), id)
	    != NULL);
}

static struct cplug *
plug_find(const char *id)
{
	int	i;

	for (i = 0; i < cp.n; i++)
		if (strcmp(cp.v[i].id, id) == 0)
			return (&cp.v[i]);
	return (NULL);
}

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

static ucl_object_t *
plug_json(const struct cplug *p)
{
	static const char	*texts[] = { "name", "version", "arcana",
				    "description", "author" };
	const ucl_object_t	*v;
	ucl_object_t		*o, *a, *f;
	char			 sri[80];
	size_t			 i;
	int			 j;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "id", ucl_object_fromstring(p->id));
	for (i = 0; i < nitems(texts); i++)
		if (p->m != NULL && (v = ucl_object_lookup(p->m, texts[i])) !=
		    NULL && ucl_object_type(v) == UCL_STRING)
			put(o, texts[i], ucl_object_copy(v));
	if (p->m != NULL && (v = ucl_object_lookup(p->m, "provides")) !=
	    NULL && ucl_object_type(v) == UCL_ARRAY && p->error == NULL)
		put(o, "provides", ucl_object_copy(v));
	else
		put(o, "provides", ucl_object_typed_new(UCL_ARRAY));
	put(o, "enabled", ucl_object_frombool(enabled(p->id)));
	if (p->error != NULL) {
		put(o, "error", ucl_object_fromstring(p->error));
		return (o);
	}
	a = ucl_object_typed_new(UCL_ARRAY);
	for (j = 0; j < p->nfiles; j++) {
		f = ucl_object_typed_new(UCL_OBJECT);
		put(f, "path", ucl_object_fromstring(p->files[j].path));
		put(f, "kind", ucl_object_fromstring(p->files[j].kind ==
		    F_SCRIPT ? "script" : p->files[j].kind == F_STYLE ? "style" :
		    "asset"));
		put(f, "size", ucl_object_fromint(p->files[j].size));
		snprintf(sri, sizeof(sri), "sha384-%s", p->files[j].sri);
		put(f, "integrity", ucl_object_fromstring(sri));
		ucl_array_append(a, f);
	}
	put(o, "files", a);
	return (o);
}

/* GET /api/plugins: every console plugin, its state and files. */
int
api_cplugs(struct http_request *req)
{
	ucl_object_t	*o, *a;
	int		 i;

	if (!guard(req, false))
		return (WEB_OK);
	cplug_check();
	state_check();
	a = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < cp.n; i++)
		ucl_array_append(a, plug_json(&cp.v[i]));
	o = ucl_object_typed_new(UCL_OBJECT);
	/* Where they are installed, for who may enable them. */
	if (user_console(session_user(req)) == CROLE_OWNER)
		put(o, "dir", ucl_object_fromstring(cfg.plugins_dir != NULL ?
		    cfg.plugins_dir : ""));
	put(o, "plugins", a);
	return (reply_json(req, 200, o));
}

/* POST /api/plugins/<id> {"enabled": bool}: by a console owner. */
int
api_cplug(struct http_request *req)
{
	ucl_object_t		*body, *st, *e, *rec;
	const ucl_object_t	*v;
	struct stat		 sb;
	char			 path[MAXPATHLEN];
	struct cplug		*p;
	const char		*who;
	char			 id[ID_MAX + 1];
	bool			 on;

	if (!guard(req, true))
		return (WEB_OK);
	if (user_console(session_user(req)) != CROLE_OWNER)
		return (reply_error(req, 403, "role", "a console plugin is "
		    "enabled or disabled by an owner of this console alone"));
	if (!capture(req, 3, id, sizeof(id)) || !id_ok(id))
		return (reply_error(req, 404, "not_found", "no such plugin"));
	if ((body = read_json(req)) == NULL ||
	    (v = ucl_object_lookup(body, "enabled")) == NULL ||
	    ucl_object_type(v) != UCL_BOOLEAN) {
		if (body != NULL)
			ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "{\"enabled\": true "
		    "or false}"));
	}
	on = ucl_object_toboolean(v);
	ucl_object_unref(body);
	cplug_check();
	state_check();
	p = plug_find(id);
	if (on && p == NULL)
		return (reply_error(req, 404, "not_found", "no plugin %s in %s",
		    id, cfg.plugins_dir != NULL ? cfg.plugins_dir : "(none)"));
	if (on && p->error != NULL)
		return (reply_error(req, 409, "plugin", "plugin %s: %s", id,
		    p->error));
	who = session_who(req) != NULL ? session_who(req) : "?";
	if (on != enabled(id)) {
		st = ucl_object_copy(cp.state);
		e = (ucl_object_t *)(uintptr_t)ucl_object_lookup(st, "enabled");
		if (on) {
			rec = ucl_object_typed_new(UCL_OBJECT);
			put(rec, "by", ucl_object_fromstring(who));
			put(rec, "at", ucl_object_fromint(time(NULL)));
			put(e, id, rec);
		} else
			ucl_object_delete_key(e, id);
		if (store_save(CPLUG_STATE, st) != 0) {
			ucl_object_unref(st);
			return (reply_error(req, 500, "store", "%s could not be "
			    "written", CPLUG_STATE));
		}
		/* In force at once; a cluster's write, when it comes, the
		 * same read again. */
		ucl_object_unref(cp.state);
		cp.state = st;
		snprintf(path, sizeof(path), "%s/%s", cfg.datadir, CPLUG_STATE);
		if (stat(path, &sb) == 0)
			cp.state_mtim = sb.st_mtim;
		audit_add(on ? "plugin-enabled" : "plugin-disabled",
		    "Administer", id, CPLUG_STATE, "the console", who,
		    "plugin %s %s", id, on ? "enabled" : "disabled");
		log_msg(LOG_NOTICE, "console plugin %s %s by %s", id, on ?
		    "enabled" : "disabled", who);
	}
	return (api_cplugs(req));
}

/* A 404 of the plugin files' own: plain, as the web root's. */
static int
not_found(struct http_request *req)
{

	http_response_header(req, "content-type", "text/plain; charset=utf-8");
	http_response(req, 404, "Not Found\n", 10);
	return (WEB_OK);
}

/*
 * GET /plugins/<id>/<file>: a file a plugin lists, the plugin enabled,
 * to a signed-in session; anything else not found.  Its tag the hash,
 * looked at each time.
 */
int
api_cplug_file(struct http_request *req)
{
	struct cplug	*p;
	struct stat	 sb;
	const char	*rel, *why, *v;
	uint8_t		*buf;
	char		 id[ID_MAX + 1], sri[72], etag[96];
	int		 i, t;

	if (!guard(req, false))
		return (WEB_OK);
	if (!capture(req, 2, id, sizeof(id)) || !id_ok(id))
		return (not_found(req));
	rel = req->path + strlen("/plugins/") + strlen(id) + 1;
	if (!path_ok(rel, false))
		return (not_found(req));
	cplug_check();
	state_check();
	if ((p = plug_find(id)) == NULL || p->error != NULL || !enabled(id))
		return (not_found(req));
	for (i = 0; i < p->nfiles; i++)
		if (strcmp(p->files[i].path, rel) == 0)
			break;
	if (i == p->nfiles || (t = type_of(rel)) == -1)
		return (not_found(req));
	/* Read and hashed as it is now: what is sent is what is tagged. */
	if ((why = file_read(p, rel, &sb, sri, &buf)) != NULL) {
		log_msg(LOG_WARNING, "console plugin %s: %s: %s", id, rel, why);
		cp.scanned = false;
		return (not_found(req));
	}
	if (strcmp(sri, p->files[i].sri) != 0) {
		snprintf(p->files[i].sri, sizeof(p->files[i].sri), "%s", sri);
		p->files[i].size = sb.st_size;
		p->files[i].ino = sb.st_ino;
		p->files[i].mtim = sb.st_mtim;
	}
	snprintf(etag, sizeof(etag), "\"sha384-%s\"", sri);
	http_response_header(req, "cache-control", "no-cache");
	http_response_header(req, "etag", etag);
	if (http_request_header(req, "if-none-match", &v) &&
	    strcmp(v, etag) == 0) {
		free(buf);
		http_response(req, 304, NULL, 0);
		return (WEB_OK);
	}
	http_response_header(req, "content-type", types[t].type);
	http_response(req, 200, buf, (size_t)sb.st_size);
	free(buf);
	return (WEB_OK);
}

/*
 * A plugin's store: a JSON object of 16 KB at most for each console user
 * and one its users share, in plugin-store/ of the data directory,
 *
 *	<plugin>.shared.json
 *	<plugin>.user.<user>.json
 *
 * the user's name with its '_', '.' and '@' written _5f, _2e and _40:
 * a name the cluster replicates (store_save()), which no user's can be
 * mistaken for the shared one's.  Written under a lock every worker
 * and the cluster's nodes take, each tagged by the SHA-256 of its
 * compact JSON: a write names the tag it replaces (If-Match), or finds
 * none stored.  Kept while the plugin is disabled; a user's go with the
 * user.
 */
#define	PSTORE_DIR	"plugin-store"
#define	PSTORE_LOCK	"plugin-store.lock"
#define	PSTORE_MAX	(16 * 1024)
#define	PSTORE_USER	(3 * 64 + 1)

/* user's name as its file has it; false when it does not fit. */
static bool
pstore_user(const char *user, char *buf, size_t len)
{
	size_t	i, n;

	for (i = n = 0; user[i] != '\0'; i++) {
		if (n + 4 > len)
			return (false);
		if (user[i] == '_' || user[i] == '.' || user[i] == '@')
			n += (size_t)snprintf(buf + n, len - n, "_%02x",
			    (unsigned char)user[i]);
		else
			buf[n++] = user[i];
	}
	buf[n] = '\0';
	return (n > 0);
}

/* The store of plugin id: user's, or with user NULL the shared one. */
static bool
pstore_name(const char *id, const char *user, char *buf, size_t len)
{
	char	u[PSTORE_USER];

	if (user == NULL) {
		snprintf(buf, len, "%s/%s.shared.json", PSTORE_DIR, id);
		return (true);
	}
	if (!pstore_user(user, u, sizeof(u)))
		return (false);
	snprintf(buf, len, "%s/%s.user.%s.json", PSTORE_DIR, id, u);
	return (true);
}

/* o's tag, "<32 hex>" quoted, into etag; its compact JSON's length, or
 * -1. */
static ssize_t
pstore_tag(const ucl_object_t *o, char etag[36])
{
	unsigned char	 md[EVP_MAX_MD_SIZE];
	unsigned int	 mdlen;
	char		*js;
	size_t		 len;
	int		 i;

	if ((js = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT)) == NULL)
		return (-1);
	len = strlen(js);
	if (EVP_Digest(js, len, md, &mdlen, EVP_sha256(), NULL) != 1) {
		free(js);
		return (-1);
	}
	free(js);
	etag[0] = '"';
	for (i = 0; i < 16; i++)
		snprintf(etag + 1 + 2 * i, 3, "%02x", md[i]);
	etag[33] = '"';
	etag[34] = '\0';
	return ((ssize_t)len);
}

/* What name holds, and its tag; or NULL and "". */
static ucl_object_t *
pstore_load(const char *name, char etag[36])
{
	ucl_object_t	*o;

	etag[0] = '\0';
	if ((o = store_load(name)) == NULL)
		return (NULL);
	if (ucl_object_type(o) != UCL_OBJECT || pstore_tag(o, etag) == -1) {
		ucl_object_unref(o);
		etag[0] = '\0';
		return (NULL);
	}
	return (o);
}

static int
pstore_lock(void)
{
	char	path[MAXPATHLEN];
	int	fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, PSTORE_LOCK);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return (-1);
	(void)flock(fd, LOCK_EX);
	/* And of the cluster's other nodes, when it is one. */
	(void)cluster_lock(PSTORE_LOCK);
	return (fd);
}

static void
pstore_unlock(int fd)
{

	if (fd != -1) {
		cluster_unlock(PSTORE_LOCK);
		close(fd);
	}
}

/* The body, a JSON object of PSTORE_MAX bytes at most, into *op: 0, else
 * 413 or 400. */
static int
pstore_body(struct http_request *req, ucl_object_t **op)
{
	struct ucl_parser	*p;
	char			*buf;
	size_t			 len, i;
	ssize_t			 r;
	int			 status;

	*op = NULL;
	buf = xmalloc(PSTORE_MAX + 1);
	for (len = 0; len < PSTORE_MAX + 1; len += (size_t)r)
		if ((r = http_body_read(req, buf + len, PSTORE_MAX + 1 - len)) <=
		    0)
			break;
	if (len > PSTORE_MAX) {
		free(buf);
		return (413);
	}
	/* An object as JSON writes one; what else libucl reads is not. */
	for (i = 0; i < len && strchr(" \t\r\n", buf[i]) != NULL; i++)
		;
	status = 400;
	if (i < len && buf[i] == '{') {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_chunk(p, (unsigned char *)buf, len) &&
		    (*op = ucl_parser_get_object(p)) != NULL) {
			if (ucl_object_type(*op) == UCL_OBJECT)
				status = 0;
			else {
				ucl_object_unref(*op);
				*op = NULL;
			}
		}
		ucl_parser_free(p);
	}
	free(buf);
	return (status);
}

/*
 * GET /api/plugins/<id>/store[/shared]: {"data": the object or null,
 * "etag": its tag or null}, the tag as ETag too.  PUT: the object, in
 * place of the one If-Match names (*: any one), or without If-Match
 * where none is stored yet; {"etag"}.  The session user's own, or the
 * one shared, which any console role reads and an operator or an owner
 * writes.  Not an API token's; the plugin enabled and served, else not
 * found.
 */
int
api_cplug_store(struct http_request *req)
{
	ucl_object_t	*o, *cur, *top;
	const char	*user, *v;
	char		 id[ID_MAX + 1], name[MAXPATHLEN], etag[36], now[36];
	struct cplug	*p;
	ssize_t		 len;
	size_t		 plen;
	bool		 shared, ok;
	int		 fd, status;

	plen = strlen(req->path);
	shared = plen > 7 && strcmp(req->path + plen - 7, "/shared") == 0;
	if (!guard(req, req->method != HTTP_METHOD_GET))
		return (WEB_OK);
	if ((user = session_user(req)) == NULL)
		return (reply_error(req, 403, "token", "a plugin's store is a "
		    "console user's, not an API token's"));
	if (!capture(req, 3, id, sizeof(id)) || !id_ok(id))
		return (reply_error(req, 404, "not_found", "no such plugin"));
	cplug_check();
	state_check();
	if ((p = plug_find(id)) == NULL || p->error != NULL || !enabled(id))
		return (reply_error(req, 404, "not_found", "no plugin %s "
		    "enabled", id));
	if (!pstore_name(id, shared ? NULL : user, name, sizeof(name)))
		return (reply_error(req, 400, "invalid", "a user's name"));
	if (req->method == HTTP_METHOD_GET) {
		top = ucl_object_typed_new(UCL_OBJECT);
		if ((o = pstore_load(name, etag)) != NULL) {
			http_response_header(req, "etag", etag);
			put(top, "data", o);
			put(top, "etag", ucl_object_fromstring(etag));
		} else {
			put(top, "data", ucl_object_typed_new(UCL_NULL));
			put(top, "etag", ucl_object_typed_new(UCL_NULL));
		}
		http_response_header(req, "cache-control", "no-store");
		return (reply_json(req, 200, top));
	}
	if (shared && user_console(user) != CROLE_OWNER &&
	    user_console(user) != CROLE_OPERATOR)
		return (reply_error(req, 403, "role", "a plugin's shared store "
		    "is written by an operator or an owner of this console"));
	if ((status = pstore_body(req, &o)) != 0)
		return (reply_error(req, status, status == 413 ? "too_large" :
		    "invalid", status == 413 ? "%d bytes at most" :
		    "a JSON object", PSTORE_MAX));
	if ((len = pstore_tag(o, etag)) == -1 || len > PSTORE_MAX) {
		ucl_object_unref(o);
		return (len == -1 ? reply_error(req, 500, "store", "out of "
		    "memory") : reply_error(req, 413, "too_large", "%d bytes at "
		    "most", PSTORE_MAX));
	}
	fd = pstore_lock();
	cur = pstore_load(name, now);
	if (http_request_header(req, "if-match", &v))
		ok = cur != NULL && (strcmp(v, "*") == 0 || strcmp(v, now) == 0);
	else
		ok = cur == NULL;
	if (cur != NULL)
		ucl_object_unref(cur);
	if (!ok) {
		pstore_unlock(fd);
		ucl_object_unref(o);
		return (reply_error(req, 412, "changed", "the store is not what "
		    "the tag given says: read it again"));
	}
	status = store_save(name, o);
	pstore_unlock(fd);
	ucl_object_unref(o);
	if (status != 0)
		return (reply_error(req, 500, "store", "%s could not be "
		    "written", name));
	http_response_header(req, "etag", etag);
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "etag", ucl_object_fromstring(etag));
	return (reply_json(req, 200, top));
}

/* A user gone (users.c): their stores, of every plugin, with them. */
void
cplug_store_forget(const char *user)
{
	DIR		*d;
	struct dirent	*e;
	char		 u[PSTORE_USER], tail[PSTORE_USER + 16];
	char		 path[MAXPATHLEN], name[MAXPATHLEN];
	size_t		 n, t;
	int		 fd;

	if (!pstore_user(user, u, sizeof(u)))
		return;
	snprintf(tail, sizeof(tail), ".user.%s.json", u);
	t = strlen(tail);
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, PSTORE_DIR);
	if ((d = opendir(path)) == NULL)
		return;
	fd = pstore_lock();
	while ((e = readdir(d)) != NULL) {
		/* <id> has no dot: the first is the tail's. */
		n = strlen(e->d_name);
		if (e->d_type != DT_REG || n <= t || strcmp(e->d_name + n - t,
		    tail) != 0 || strchr(e->d_name, '.') != e->d_name + n - t)
			continue;
		snprintf(name, sizeof(name), "%s/%s", PSTORE_DIR, e->d_name);
		if (store_remove(name) != 0)
			log_msg(LOG_ERR, "%s: not removed with user %s", name,
			    user);
	}
	pstore_unlock(fd);
	closedir(d);
}
