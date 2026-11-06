/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the threat feeds' tables.  The console fetches a feed, a list
 * of scanners', spammers' or abusers' prefixes, and sends it whole; it
 * becomes an ipfw(8) table of type addr, IPv4 and IPv6 in one, kept in
 * a file beside the kept rules (feeds/<table>) and filled into a scratch
 * table of the same set that is then swapped in (ipfw table T swap S),
 * so that a lookup sees the old entries or the new ones, never half.
 *
 * The file is the mark of a table a feed made: no other is replaced or
 * destroyed, but an empty one of type addr that a rule made by naming
 * it.  The kernel forgets the tables at a reboot, and Apply makes set
 * 1's anew and swaps them in: the agent fills them again from the files
 * when it starts and before Apply's swap.  An entry covering the address
 * the request came from, the console's, is left out.  The host's alone:
 * a vnet jail's firewall is not fed.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
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
#include <ucl.h>
#include <unistd.h>

#include "agent.h"
#include "collect.h"

#define	FEED_MAX	250000		/* entries of a table */
#define	FEED_LINE	64		/* entries an add line: ipfw reads 4 KB a line */
#define	FEED_TEXT_MAX	(8 * 1024 * 1024)

static pthread_mutex_t	feeds_lock = PTHREAD_MUTEX_INITIALIZER;

/* A table's name a feed may give: letters, digits, _ . -, 48 at most. */
bool
feed_name_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 48)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] !=
		    '.' && s[i] != '-')
			return (false);
	return (true);
}

/* Where the feeds' files are: feeds/ beside Arcana's own kept rules
 * (not /etc's, where config-files system moves them). */
static const char *
feeds_dir(struct work *w)
{
	const char	*s, *r = cf_ipfw_home();

	if ((s = strrchr(r, '/')) == NULL)
		return ("feeds");
	return (wfmt(w, "%.*s/feeds", (int)(s - r), r));
}

/* An address or prefix, its host bits cleared. */
struct pfx {
	int		 af;
	uint8_t		 a[16];
	int		 len;
};

static bool
pfx_parse(const char *s, struct pfx *p)
{
	char	buf[64], *slash, *end;
	long	l;
	int	i, bits;

	if (strlen(s) >= sizeof(buf))
		return (false);
	strlcpy(buf, s, sizeof(buf));
	memset(p, 0, sizeof(*p));
	if ((slash = strchr(buf, '/')) != NULL)
		*slash++ = '\0';
	if (inet_pton(AF_INET, buf, p->a) == 1) {
		p->af = AF_INET;
		bits = 32;
	} else if (inet_pton(AF_INET6, buf, p->a) == 1) {
		p->af = AF_INET6;
		bits = 128;
	} else
		return (false);
	p->len = bits;
	if (slash != NULL) {
		l = strtol(slash, &end, 10);
		if (*slash == '\0' || *end != '\0' || l < 0 || l > bits)
			return (false);
		p->len = (int)l;
	}
	for (i = p->len; i < bits; i++)
		p->a[i / 8] &= ~(0x80 >> (i % 8));
	return (true);
}

static const char *
pfx_text(struct work *w, const struct pfx *p)
{
	char	buf[INET6_ADDRSTRLEN];

	if (inet_ntop(p->af, p->a, buf, sizeof(buf)) == NULL)
		return (NULL);
	return (wfmt(w, "%s/%d", buf, p->len));
}

/* Does p cover the address a (of family af)? */
static bool
pfx_covers(const struct pfx *p, int af, const uint8_t *a)
{
	int	i;

	if (p->af != af)
		return (false);
	for (i = 0; i < p->len; i++)
		if ((p->a[i / 8] ^ a[i / 8]) & (0x80 >> (i % 8)))
			return (false);
	return (true);
}

static int
strpcmp(const void *a, const void *b)
{

	return (strcmp(*(const char *const *)a, *(const char *const *)b));
}

/*
 * The entries of a text, one a line (what follows # left out), made
 * canonical, sorted, each once; those covering the address of af and a
 * (none: af 0) left out and counted.  NULL and why when one is no
 * prefix or there are too many.
 */
static const char **
entries_of(struct work *w, const char *text, int af, const uint8_t *a,
    size_t *np, size_t *leftp, const char **errp)
{
	const char	**v, *p, *e, *t;
	char		  line[80];
	struct pfx	  x;
	size_t		  n, k, len, cap;

	*np = *leftp = 0;
	cap = 1024;
	v = wcalloc(w, cap, sizeof(*v));
	n = 0;
	for (p = text; *p != '\0'; p = *e == '\n' ? e + 1 : e) {
		e = p + strcspn(p, "\n");
		len = (size_t)(e - p);
		while (len > 0 && isspace((unsigned char)*p)) {
			p++;
			len--;
		}
		len = strcspn(p, "#\r\n \t") < len ? strcspn(p, "#\r\n \t") :
		    len;
		if (len == 0)
			continue;
		if (len >= sizeof(line)) {
			*errp = wfmt(w, "%.40s…: not a prefix", p);
			return (NULL);
		}
		memcpy(line, p, len);
		line[len] = '\0';
		if (!pfx_parse(line, &x)) {
			*errp = wfmt(w, "%s: not an IPv4 or IPv6 address or "
			    "prefix", line);
			return (NULL);
		}
		if (af != 0 && pfx_covers(&x, af, a)) {
			(*leftp)++;
			continue;
		}
		if (n >= FEED_MAX) {
			*errp = wfmt(w, "more than %d entries", FEED_MAX);
			return (NULL);
		}
		if (n + 1 >= cap) {
			const char	**nv;

			nv = wcalloc(w, cap * 2, sizeof(*v));
			memcpy(nv, v, n * sizeof(*v));
			v = nv;
			cap *= 2;
		}
		if ((t = pfx_text(w, &x)) == NULL) {
			*errp = wfmt(w, "%s: not an address", line);
			return (NULL);
		}
		v[n++] = t;
	}
	qsort(v, n, sizeof(*v), strpcmp);
	for (k = 0, len = 0; k < n; k++)
		if (len == 0 || strcmp(v[len - 1], v[k]) != 0)
			v[len++] = v[k];
	*np = len;
	return (v);
}

/* A feed's file: its feed, when, and its entries, as written. */
struct feedfile {
	const char	*feed;
	time_t		 updated;
	const char	*body;		/* the entries, a line each */
	size_t		 count;
};

static bool
file_of(struct work *w, const char *name, struct feedfile *ff)
{
	struct stat	 sb;
	char		*text, *p;
	const char	*path;
	ssize_t		 r;
	int		 fd;

	memset(ff, 0, sizeof(*ff));
	path = wfmt(w, "%s/%s", feeds_dir(w), name);
	if ((fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) == -1)
		return (false);
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size >
	    FEED_TEXT_MAX) {
		close(fd);
		return (false);
	}
	text = wcalloc(w, (size_t)sb.st_size + 1, 1);
	r = read(fd, text, (size_t)sb.st_size);
	close(fd);
	if (r != sb.st_size)
		return (false);
	/* "# arcana feed <feed>" and "# updated <seconds>" first. */
	p = text;
	while (*p == '#') {
		char	*nl = p + strcspn(p, "\n");

		if (*nl != '\0')
			*nl++ = '\0';
		if (strncmp(p, "# arcana feed ", 14) == 0)
			ff->feed = p + 14;
		else if (strncmp(p, "# updated ", 10) == 0)
			ff->updated = (time_t)strtoll(p + 10, NULL, 10);
		p = nl;
	}
	if (ff->feed == NULL)
		return (false);
	ff->body = p;
	for (; *p != '\0'; p++)
		if (*p == '\n')
			ff->count++;
	return (true);
}

/* A table of the kernel's, as table all info tells it. */
struct ktable {
	const char	*name;
	int		 set;
	const char	*type;
	long		 items;
};

static size_t
ktables(struct work *w, struct ktable **tp)
{
	struct execres	 res;
	struct ktable	*t;
	char		*argv[5], *text, *p, *line, *s;
	size_t		 n, cap;

	*tp = NULL;
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"table";
	argv[2] = (char *)(uintptr_t)"all";
	argv[3] = (char *)(uintptr_t)"info";
	argv[4] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return (0);
	text = wstrndup(w, res.out, res.outlen);
	cap = 16;
	t = wcalloc(w, cap, sizeof(*t));
	n = 0;
	for (p = text; (line = strsep(&p, "\n")) != NULL; ) {
		if (strncmp(line, "--- table(", 10) == 0) {
			if (n == cap) {
				struct ktable	*nt;

				nt = wcalloc(w, cap * 2, sizeof(*t));
				memcpy(nt, t, n * sizeof(*t));
				t = nt;
				cap *= 2;
			}
			line += 10;
			s = strstr(line, "), set(");
			line[strcspn(line, ")")] = '\0';
			t[n].name = line;
			t[n].set = s != NULL ? (int)strtol(s + 7, NULL, 10) : 0;
			t[n].items = -1;
			n++;
		} else if (n > 0 && (s = strstr(line, " type: ")) != NULL) {
			s += 7;
			s[strcspn(s, ", ")] = '\0';
			t[n - 1].type = s;
		} else if (n > 0 && (s = strstr(line, "items: ")) != NULL)
			t[n - 1].items = strtol(s + 7, NULL, 10);
	}
	*tp = t;
	return (n);
}

static const struct ktable *
ktable(const struct ktable *t, size_t n, const char *name, int set)
{
	size_t	i;

	for (i = 0; i < n; i++)
		if (strcmp(t[i].name, name) == 0 && (set < 0 || t[i].set == set))
			return (&t[i]);
	return (NULL);
}

static long
tables_sets(struct work *w)
{
	struct execres	 res;
	char		*argv[4];
	int		 v;
	size_t		 len;

	if (strcmp(opts.sysctl_bin, "/sbin/sysctl") == 0) {
		len = sizeof(v);
		return (sysctlbyname("net.inet.ip.fw.tables_sets", &v, &len,
		    NULL, 0) == 0 ? v : 0);
	}
	argv[0] = (char *)(uintptr_t)opts.sysctl_bin;
	argv[1] = (char *)(uintptr_t)"-n";
	argv[2] = (char *)(uintptr_t)"net.inet.ip.fw.tables_sets";
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return (0);
	return (strtol(wstrndup(w, res.out, res.outlen), NULL, 10));
}

/*
 * The set a feed's table is in: with tables_sets=1 that of the first
 * rule of the kernel's that names it, else 0.
 */
static int
table_set(struct work *w, const char *name)
{
	struct execres	 res;
	char		*argv[4], *text, *p, *line, *t, *want;
	int		 set;

	if (tables_sets(w) != 1)
		return (0);
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-S";
	argv[2] = (char *)(uintptr_t)"list";
	argv[3] = NULL;
	if (run_exec_max(w, argv, &res, 16 * 1024 * 1024) != 0 ||
	    res.out == NULL)
		return (0);
	want = wfmt(w, "table(%s)", name);
	text = wstrndup(w, res.out, res.outlen);
	for (p = text; (line = strsep(&p, "\n")) != NULL; ) {
		if ((t = strstr(line, " set ")) == NULL || strstr(line, want) ==
		    NULL)
			continue;
		set = (int)strtol(t + 5, NULL, 10);
		if (set >= 0 && set < 31)
			return (set);
	}
	return (0);
}

/* ipfw with the words, in set when set >= 0; 0 or -1 and why. */
static int
fw(struct work *w, const char **errp, int set, ...)
{
	struct execres	 res;
	va_list		 ap;
	char		*argv[16];
	const char	*a;
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[n++] = (char *)(uintptr_t)"-q";
	if (set >= 0) {
		argv[n++] = (char *)(uintptr_t)"set";
		argv[n++] = wfmt(w, "%d", set);
	}
	va_start(ap, set);
	while ((a = va_arg(ap, const char *)) != NULL && n < 15)
		argv[n++] = (char *)(uintptr_t)a;
	va_end(ap);
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		if (errp != NULL)
			*errp = wtext(w, exec_error(w, &res, "ipfw"));
		return (-1);
	}
	return (0);
}

/*
 * The table filled whole with the entries (body, a line each), in set
 * (-1: tables_sets is 0 and a table is in every set): a scratch table
 * filled by one ipfw run of a file and swapped in, then destroyed.
 */
static int
fill(struct work *w, const char *name, int set, const char *body,
    bool exists, const char **errp)
{
	struct execres	 res;
	FILE		*fp;
	char		*buf, *argv[4];
	const char	*scratch, *sp, *p, *e, *path;
	size_t		 len, k;
	int		 fd, rc;

	scratch = wfmt(w, "%s_load", name);
	sp = set >= 0 ? wfmt(w, "set %d ", set) : "";
	(void)fw(w, NULL, set, "table", scratch, "destroy", NULL);
	if ((fp = open_memstream(&buf, &len)) == NULL) {
		*errp = "out of memory";
		return (-1);
	}
	fprintf(fp, "%stable %s create type addr\n", sp, scratch);
	k = 0;
	for (p = body; *p != '\0'; p = *e == '\n' ? e + 1 : e) {
		e = p + strcspn(p, "\n");
		if (e == p)
			continue;
		if (k % FEED_LINE == 0)
			fprintf(fp, "%s%stable %s add", k > 0 ? "\n" : "", sp,
			    scratch);
		fprintf(fp, " %.*s 0", (int)(e - p), p);
		k++;
	}
	if (k > 0)
		fputc('\n', fp);
	if (fclose(fp) != 0) {
		*errp = "out of memory";
		return (-1);
	}
	wadopt(w, buf);
	path = wfmt(w, "%s/.%s.load", feeds_dir(w), name);
	if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1 || write(fd, buf, len) != (ssize_t)len) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		if (fd != -1)
			close(fd);
		return (-1);
	}
	close(fd);
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-q";
	argv[2] = (char *)(uintptr_t)path;
	argv[3] = NULL;
	rc = run_exec(w, argv, &res);
	(void)unlink(path);
	if (rc != 0) {
		*errp = wtext(w, exec_error(w, &res, "ipfw"));
		(void)fw(w, NULL, set, "table", scratch, "destroy", NULL);
		return (-1);
	}
	if ((!exists && fw(w, errp, set, "table", name, "create", "type",
	    "addr", NULL) != 0) || fw(w, errp, set, "table", name, "swap",
	    scratch, NULL) != 0) {
		(void)fw(w, NULL, set, "table", scratch, "destroy", NULL);
		return (-1);
	}
	(void)fw(w, NULL, set, "table", scratch, "destroy", NULL);
	return (0);
}

/* Added and removed, between two sorted lists of entries. */
static void
diff_count(const char **a, size_t na, const char **b, size_t nb,
    uint32_t *addp, uint32_t *remp)
{
	size_t	i, j;
	int	c;

	*addp = *remp = 0;
	for (i = j = 0; i < na || j < nb; ) {
		c = i == na ? 1 : j == nb ? -1 : strcmp(a[i], b[j]);
		if (c == 0) {
			i++;
			j++;
		} else if (c < 0) {
			(*remp)++;
			i++;
		} else {
			(*addp)++;
			j++;
		}
	}
}

int
feed_load(struct work *w, const struct feed_req *rq, struct feed_rsp *rs,
    const char **errp)
{
	struct feedfile		 ff;
	struct ktable		*kt;
	const struct ktable	*t;
	const char		**v, **old, *dir, *path, *tmp, *body;
	struct stat		 sb;
	FILE			*fp;
	char			*buf;
	size_t			 n, nold, left, i, len, nk;
	int			 set, fd, step;
	bool			 had, exists;

	memset(rs, 0, sizeof(*rs));
	if (w->jail != NULL) {
		*errp = "a vnet jail's firewall is not fed: the host's alone";
		return (-1);
	}
	if (!feed_name_ok(rq->name)) {
		*errp = "a feed's table is named by letters, digits, _ . and -, "
		    "48 at most";
		return (-1);
	}
	if (rq->feed == NULL || rq->feed[0] == '\0' || strlen(rq->feed) > 64 ||
	    strchr(rq->feed, '\n') != NULL) {
		*errp = "the feed's name, of a line, is needed";
		return (-1);
	}
	if (rq->entries == NULL || strlen(rq->entries) > FEED_TEXT_MAX) {
		*errp = "the entries, 8 MB at most, are needed";
		return (-1);
	}
	if ((v = entries_of(w, rq->entries, rq->peer_af, rq->peer, &n, &left,
	    errp)) == NULL)
		return (-1);
	rs->left_out = (uint32_t)left;
	pthread_mutex_lock(&feeds_lock);
	had = file_of(w, rq->name, &ff);
	nold = 0;
	old = NULL;
	if (had && (old = entries_of(w, ff.body, 0, NULL, &nold, &i, errp)) ==
	    NULL)
		had = false;
	diff_count(old, nold, v, n, &rs->added, &rs->removed);
	rs->count = (uint32_t)n;
	/* A table there that no feed made, with entries: the host's own. */
	nk = ktables(w, &kt);
	exists = false;
	set = table_set(w, rq->name);
	if ((t = ktable(kt, nk, rq->name, tables_sets(w) == 1 ? set : -1)) !=
	    NULL) {
		exists = true;
		if (!had && (t->items != 0 || (t->type != NULL && strcmp(t->type,
		    "addr") != 0))) {
			pthread_mutex_unlock(&feeds_lock);
			*errp = wfmt(w, "table %s is the host's own, not a feed's: "
			    "it is not replaced. Give the feed another table",
			    rq->name);
			return (-1);
		}
	}
	rs->set = (uint8_t)set;
	if (rq->dry_run) {
		pthread_mutex_unlock(&feeds_lock);
		step = step_begin(w, STEP_DAEMON, "feed", "%s", rq->name);
		step_end(w, step, true, "would have %zu entries: %u added, %u "
		    "removed", n, rs->added, rs->removed);
		return (0);
	}
	/* The file first, so that a restart fills the table again. */
	dir = feeds_dir(w);
	if (stat(dir, &sb) != 0 && mkdir(dir, 0700) != 0) {
		pthread_mutex_unlock(&feeds_lock);
		*errp = wfmt(w, "%s: %s", dir, strerror(errno));
		return (-1);
	}
	if ((fp = open_memstream(&buf, &len)) == NULL) {
		pthread_mutex_unlock(&feeds_lock);
		*errp = "out of memory";
		return (-1);
	}
	fprintf(fp, "# arcana feed %s\n# updated %jd\n", rq->feed,
	    (intmax_t)time(NULL));
	for (i = 0; i < n; i++)
		fprintf(fp, "%s\n", v[i]);
	(void)fclose(fp);
	wadopt(w, buf);
	path = wfmt(w, "%s/%s", dir, rq->name);
	tmp = wfmt(w, "%s/.%s.tmp", dir, rq->name);
	step = step_begin(w, STEP_FILE, "write", "%s", path);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1 || write(fd, buf, len) != (ssize_t)len ||
	    fsync(fd) != 0 || close(fd) != 0 || rename(tmp, path) != 0) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		step_end(w, step, false, "%s", *errp);
		(void)unlink(tmp);
		pthread_mutex_unlock(&feeds_lock);
		return (-1);
	}
	step_end(w, step, true, NULL);
	body = buf + strcspn(buf, "\n") + 1;
	body += strcspn(body, "\n") + 1;
	step = step_begin(w, STEP_DAEMON, "feed", "table %s, set %d", rq->name,
	    set);
	if (fill(w, rq->name, tables_sets(w) == 1 ? set : -1, body, exists,
	    errp) != 0) {
		step_end(w, step, false, "%s", *errp);
		/* The file says what the table is to be; the next load or
		 * start makes it so. */
		pthread_mutex_unlock(&feeds_lock);
		return (-1);
	}
	step_end(w, step, true, "%zu entries: %u added, %u removed", n,
	    rs->added, rs->removed);
	pthread_mutex_unlock(&feeds_lock);
	return (0);
}

int
feed_drop(struct work *w, const char *name, bool *destroyedp,
    const char **errp)
{
	struct feedfile		 ff;
	struct ktable		*kt;
	const struct ktable	*t;
	const char		*e;
	size_t			 nk;
	int			 set;

	*destroyedp = false;
	if (w->jail != NULL) {
		*errp = "a vnet jail's firewall is not fed: the host's alone";
		return (-1);
	}
	if (!feed_name_ok(name)) {
		*errp = "not a feed's table";
		return (-1);
	}
	pthread_mutex_lock(&feeds_lock);
	if (!file_of(w, name, &ff)) {
		pthread_mutex_unlock(&feeds_lock);
		*errp = wfmt(w, "table %s is no feed's: it is left as it is",
		    name);
		return (-1);
	}
	nk = ktables(w, &kt);
	set = tables_sets(w) == 1 ? table_set(w, name) : -1;
	if ((t = ktable(kt, nk, name, set)) != NULL) {
		e = NULL;
		if (fw(w, &e, set, "table", name, "destroy", NULL) == 0)
			*destroyedp = true;
		else if (fw(w, errp, set, "table", name, "flush", NULL) != 0) {
			pthread_mutex_unlock(&feeds_lock);
			return (-1);
		}
	} else
		*destroyedp = true;
	if (unlink(wfmt(w, "%s/%s", feeds_dir(w), name)) != 0 && errno !=
	    ENOENT) {
		pthread_mutex_unlock(&feeds_lock);
		*errp = wfmt(w, "%s/%s: %s", feeds_dir(w), name,
		    strerror(errno));
		return (-1);
	}
	pthread_mutex_unlock(&feeds_lock);
	return (0);
}

/* The feeds' tables, by their files: each name in v, at most max. */
static size_t
feeds_names(struct work *w, const char **v, size_t max)
{
	struct dirent	*de;
	DIR		*d;
	size_t		 n;

	if ((d = opendir(feeds_dir(w))) == NULL)
		return (0);
	n = 0;
	while ((de = readdir(d)) != NULL && n < max)
		if (de->d_name[0] != '.' && feed_name_ok(de->d_name))
			v[n++] = wstrdup(w, de->d_name);
	closedir(d);
	return (n);
}

/* The tables read (do_ipfw()'s "tables"), the feeds' marked. */
void
feeds_mark(struct work *w, ucl_object_t *tables)
{
	struct feedfile		 ff;
	const ucl_object_t	*t;
	ucl_object_iter_t	 it;

	if (w->jail != NULL)
		return;
	it = NULL;
	while ((t = ucl_object_iterate(tables, &it, true)) != NULL) {
		const char	*name;

		name = ucl_object_tostring(ucl_object_lookup(t, "name"));
		if (name == NULL || !feed_name_ok(name) || !file_of(w, name,
		    &ff))
			continue;
		ucl_object_insert_key((ucl_object_t *)(uintptr_t)t,
		    ucl_object_fromstring(ff.feed), "feed", 0, false);
		ucl_object_insert_key((ucl_object_t *)(uintptr_t)t,
		    ucl_object_fromint(ff.updated), "updated", 0, false);
	}
}

/*
 * The feeds' tables of set 0 made again in set 1 before Apply swaps the
 * sets (tables_sets=1, which moves a table with its set): Apply's load
 * made them empty there, where a kept rule names one, or not at all.  A
 * feed's table in another set is not Apply's.
 */
int
feeds_fill_set1(struct work *w)
{
	struct feedfile		 ff;
	struct ktable		*kt;
	const struct ktable	*t0, *t1;
	const char		*names[256], *e;
	size_t			 n, i, nk;
	int			 step;

	if (w->jail != NULL || tables_sets(w) != 1)
		return (0);
	pthread_mutex_lock(&feeds_lock);
	n = feeds_names(w, names, nitems(names));
	nk = ktables(w, &kt);
	for (i = 0; i < n; i++) {
		t0 = ktable(kt, nk, names[i], 0);
		t1 = ktable(kt, nk, names[i], 1);
		if ((t0 == NULL && ktable(kt, nk, names[i], -1) != NULL) ||
		    !file_of(w, names[i], &ff))
			continue;
		step = step_begin(w, STEP_DAEMON, "feed", "table %s into set 1",
		    names[i]);
		e = NULL;
		if (fill(w, names[i], 1, ff.body, t1 != NULL, &e) != 0) {
			step_end(w, step, false, "%s", e);
			continue;
		}
		step_end(w, step, true, "%zu entries", ff.count);
	}
	pthread_mutex_unlock(&feeds_lock);
	return (0);
}

/*
 * At the start: each feed's table the kernel has not as its file says
 * (a reboot empties them, a rule names one and makes it empty) filled
 * again.
 */
void
feeds_start(void)
{
	struct feedfile		 ff;
	struct work		 w;
	struct ktable		*kt;
	const struct ktable	*t;
	const char		*names[256], *e;
	size_t			 n, i, nk;
	int			 set, ts;

	if (!kmod_loaded("ipfw") && strcmp(opts.ipfw_bin, "/sbin/ipfw") == 0)
		return;
	work_init(&w);
	pthread_mutex_lock(&feeds_lock);
	n = feeds_names(&w, names, nitems(names));
	nk = n > 0 ? ktables(&w, &kt) : 0;
	ts = n > 0 ? (int)tables_sets(&w) : 0;
	for (i = 0; i < n; i++) {
		if (!file_of(&w, names[i], &ff))
			continue;
		set = ts == 1 ? table_set(&w, names[i]) : -1;
		t = ktable(kt, nk, names[i], set);
		if (t != NULL && t->items == (long)ff.count)
			continue;
		e = NULL;
		if (fill(&w, names[i], set, ff.body, t != NULL, &e) != 0)
			logmsg(LOG_WARNING, "feed table %s not filled: %s",
			    names[i], e);
		else
			logmsg(LOG_INFO, "feed table %s filled: %zu entries",
			    names[i], ff.count);
	}
	pthread_mutex_unlock(&feeds_lock);
	work_free(&w);
}
