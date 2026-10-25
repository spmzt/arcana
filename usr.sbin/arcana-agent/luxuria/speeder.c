/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * UDPspeeder's FEC relay, a plugin: speederv2 (net/udpspeeder) as its
 * rc service runs it, under daemon(8) with the words of speederv2_flags,
 * of the host or of a jail.  The read says how it is set and what it
 * did: the flags (the key never), the redundant packets it adds for each
 * group size (as it logged them at its start), and, given --report, the
 * packets and bytes each way with the overhead the FEC added, read from
 * its lines in syslog (daemon -S: daemon.notice, /var/log/messages).
 * The job writes the flags from words checked one by one (rc.subr hands
 * them to a shell), changes the ratios of a running relay through its
 * --fifo without dropping the tunnel, and starts, stops and enables it.
 * On the host a safe change is undone: the two rc.conf variables and
 * whether it ran, put back (ira/jobs.c).
 *
 * Several relays, where the port's rc script has speederv2_profiles: each
 * a profile, its words in speederv2_<name>_flags, run as "service
 * speederv2 <verb> <name>" and logged with the tag speederv2-<name>.  A
 * job names one with profile=<name>; without, it is the relay of
 * speederv2_flags, which the rc script runs only while no profile is
 * listed.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	SPEEDER		"speederv2"
#define	TAIL_BYTES	(256 * 1024)	/* of the log, read from its end */
#define	LOG_LINES	20		/* its own, said back */
#define	SERIES_MAX	240		/* intervals of the overhead kept */
#define	FLAGS_MAX	1024
#define	KEY_MAX		64
#define	PROFILE_MAX	32

/* The words of speederv2_flags, read or to be written. */
struct sflags {
	const char	*role;		/* "client", "server", or NULL */
	const char	*listen;
	const char	*remote;
	const char	*fec;
	const char	*fifo;
	const char	*key;
	int		 mode, mtu, timeout, report;	/* -1: not given */
	const char	*extra;		/* the other words, as they were */
};

/* The options passed on as extra words, each taking one value or none. */
static const struct {
	const char	*name;
	bool		 value;
} extras[] = {
	{ "-j", true }, { "--jitter", true }, { "-i", true },
	{ "--interval", true }, { "--random-drop", true },
	{ "--disable-obscure", true }, { "--disable-checksum", true },
	{ "-q", true }, { "--queue-len", true }, { "--decode-buf", true },
	{ "--delay-capacity", true }, { "--disable-fec", true },
	{ "--sock-buf", true }, { "--out-addr", true },
	{ "--log-level", true }, { "--log-position", false },
};

static const char *
bin(struct work *w)
{
	const char	*p;

	return ((p = tool(w, SPEEDER)) != NULL ? p : opts.speederv2_bin);
}

/*
 * Words a shell takes as they are: rc.subr expands the flags unquoted
 * (and evaluates the command it builds), so nothing else is let in.
 */
static bool
word_ok(const char *s, size_t max)
{
	size_t	n;

	if (s == NULL || (n = strlen(s)) == 0 || n > max)
		return (false);
	return (strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789._:,/[]@%+=-") == n);
}

/* host:port, [v6]:port: what -l, -r and --out-addr take. */
static bool
hostport_ok(const char *s)
{
	const char	*c;
	long		 port;
	char		*end;

	if (!word_ok(s, 80) || (c = strrchr(s, ':')) == NULL || c == s)
		return (false);
	if (s[0] == '[' && c[-1] != ']')
		return (false);
	errno = 0;
	port = strtol(c + 1, &end, 10);
	return (errno == 0 && *end == '\0' && port >= 0 && port <= 65535 &&
	    strspn(s, "0123456789abcdefABCDEF.:[]") == strlen(s));
}

/* x:y[,x:y...]: x 1 or more, y 0 or more, x + y 254 at most. */
static bool
fec_ok(const char *s)
{
	const char	*p;
	char		*end;
	long		 x, y;

	if (!word_ok(s, 400) || strspn(s, "0123456789:,") != strlen(s))
		return (false);
	for (p = s; *p != '\0'; p = *end == ',' ? end + 1 : end) {
		x = strtol(p, &end, 10);
		if (end == p || *end != ':')
			return (false);
		p = end + 1;
		y = strtol(p, &end, 10);
		if (end == p || (*end != ',' && *end != '\0') || x < 1 || y < 0 ||
		    x + y > 254)
			return (false);
		if (*end == ',' && end[1] == '\0')
			return (false);
	}
	return (true);
}

static int
num_in(const char *s, int lo, int hi)
{
	char	*end;
	long	 v;

	if (s == NULL || *s == '\0')
		return (-1);
	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || *end != '\0' || v < lo || v > hi)
		return (-1);
	return ((int)v);
}

/* The flags' words into f; what is not understood kept in extra. */
static void
flags_parse(struct work *w, const char *flags, struct sflags *f)
{
	char		*s, *word, *last, *val;
	const char	*opt;

	memset(f, 0, sizeof(*f));
	f->mode = f->mtu = f->timeout = f->report = -1;
	f->extra = "";
	if (flags == NULL)
		return;
	s = wstrdup(w, flags);
	for (word = strtok_r(s, " \t", &last); word != NULL;
	    word = strtok_r(NULL, " \t", &last)) {
		if (strcmp(word, "-c") == 0) {
			f->role = "client";
			continue;
		}
		if (strcmp(word, "-s") == 0) {
			f->role = "server";
			continue;
		}
		if (strcmp(word, "--disable-color") == 0)
			continue;
		/* -l, -r, -f and -k take their value joined or apart. */
		opt = NULL;
		val = NULL;
		if (word[0] == '-' && strchr("lrfk", word[1]) != NULL &&
		    word[1] != '\0') {
			opt = wstrndup(w, word, 2);
			val = word[2] != '\0' ? word + 2 : NULL;
		} else if (strcmp(word, "--fec") == 0 || strcmp(word, "--key") ==
		    0 || strcmp(word, "--mode") == 0 || strcmp(word, "--mtu") == 0
		    || strcmp(word, "--timeout") == 0 || strcmp(word, "--report")
		    == 0 || strcmp(word, "--fifo") == 0)
			opt = word;
		if (opt == NULL) {
			f->extra = f->extra[0] != '\0' ? wfmt(w, "%s %s", f->extra,
			    word) : wstrdup(w, word);
			continue;
		}
		if (val == NULL)
			val = strtok_r(NULL, " \t", &last);
		if (val == NULL)
			break;
		if (strcmp(opt, "-l") == 0)
			f->listen = wstrdup(w, val);
		else if (strcmp(opt, "-r") == 0)
			f->remote = wstrdup(w, val);
		else if (strcmp(opt, "-f") == 0 || strcmp(opt, "--fec") == 0)
			f->fec = wstrdup(w, val);
		else if (strcmp(opt, "-k") == 0 || strcmp(opt, "--key") == 0)
			f->key = wstrdup(w, val);
		else if (strcmp(opt, "--mode") == 0)
			f->mode = atoi(val);
		else if (strcmp(opt, "--mtu") == 0)
			f->mtu = atoi(val);
		else if (strcmp(opt, "--timeout") == 0)
			f->timeout = atoi(val);
		else if (strcmp(opt, "--report") == 0)
			f->report = atoi(val);
		else if (strcmp(opt, "--fifo") == 0)
			f->fifo = wstrdup(w, val);
	}
}

/* The flags written back from f, in the order speederv2's help gives. */
static const char *
flags_of(struct work *w, const struct sflags *f)
{
	const char	*s;

	s = wfmt(w, "%s -l%s -r%s", strcmp(f->role, "server") == 0 ? "-s" :
	    "-c", f->listen, f->remote);
	if (f->key != NULL)
		s = wfmt(w, "%s -k %s", s, f->key);
	if (f->mode >= 0)
		s = wfmt(w, "%s --mode %d", s, f->mode);
	if (f->mtu >= 0)
		s = wfmt(w, "%s --mtu %d", s, f->mtu);
	if (f->fec != NULL)
		s = wfmt(w, "%s -f%s", s, f->fec);
	if (f->timeout >= 0)
		s = wfmt(w, "%s --timeout %d", s, f->timeout);
	if (f->report > 0)
		s = wfmt(w, "%s --report %d", s, f->report);
	if (f->fifo != NULL)
		s = wfmt(w, "%s --fifo %s", s, f->fifo);
	if (f->extra != NULL && f->extra[0] != '\0')
		s = wfmt(w, "%s %s", s, f->extra);
	return (s);
}

/* The extra words: each an option of the list, with its value. */
static const char *
extra_check(struct work *w, const char *extra)
{
	char		*s, *word, *last;
	size_t		 i;

	s = wstrdup(w, extra);
	for (word = strtok_r(s, " ", &last); word != NULL;
	    word = strtok_r(NULL, " ", &last)) {
		for (i = 0; i < nitems(extras); i++)
			if (strcmp(word, extras[i].name) == 0)
				break;
		if (i == nitems(extras))
			return (wfmt(w, "extra: %s is not an option passed on "
			    "(jitter, interval, queue-len, sock-buf, out-addr, "
			    "log-level and the like)", wvis(w, word)));
		if (extras[i].value && ((word = strtok_r(NULL, " ", &last)) ==
		    NULL || !word_ok(word, 80)))
			return (wfmt(w, "extra: %s takes one value, letters, "
			    "digits and . : , / alone", extras[i].name));
	}
	return (NULL);
}

/*
 * The relay's rc.conf variables, read and written without the key in the
 * trace: sysrc's output is left out (it says the value before and after)
 * and its command line shows the key as <hidden>.
 */
/* A profile's variable, or the plain relay's (prof NULL). */
static const char *
var_of(struct work *w, const char *prof, const char *what)
{

	return (prof == NULL ? wfmt(w, SPEEDER "_%s", what) : wfmt(w, SPEEDER
	    "_%s_%s", prof, what));
}

static const char *
flags_get(struct work *w, const char *prof)
{
	const char	*v;

	exec_set_secret(true);
	v = rc_get(w, var_of(w, prof, "flags"));
	exec_set_secret(false);
	return (v);
}

static int
flags_set(struct work *w, const char *prof, const char *flags,
    const char **errp)
{
	struct sflags	 f;
	int		 rc;

	if (flags == NULL) {
		rc_unset(w, var_of(w, prof, "flags"));
		return (0);
	}
	flags_parse(w, flags, &f);
	exec_set_secret(true);
	exec_set_hide(f.key);
	rc = rc_set(w, var_of(w, prof, "flags"), "=", flags, errp);
	exec_set_hide(NULL);
	exec_set_secret(false);
	return (rc);
}

/* A profile's name: letters, digits and _, as the rc script takes. */
static bool
profile_ok(const char *s)
{
	size_t	i;

	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_')
			return (false);
	return (i > 0 && i <= PROFILE_MAX);
}

/* speederv2_profiles, its names one by one (n of them), or NULL. */
static const char **
profiles_get(struct work *w, const char **listp, size_t *np)
{
	const char	**v;
	char		 *list, *p, *word;
	size_t		  n;

	*np = 0;
	*listp = rc_get(w, SPEEDER "_profiles");
	if (*listp == NULL)
		return (NULL);
	list = wstrdup(w, *listp);
	v = wcalloc(w, strlen(list) / 2 + 2, sizeof(*v));
	for (n = 0, p = list; (word = strsep(&p, " \t")) != NULL; )
		if (*word != '\0' && profile_ok(word))
			v[n++] = word;
	*np = n;
	return (v);
}

static bool
listed(const char **v, size_t n, const char *prof)
{
	size_t	i;

	for (i = 0; i < n; i++)
		if (strcmp(v[i], prof) == 0)
			return (true);
	return (false);
}

/* speederv2_profiles written with prof added (add) or taken out. */
static int
profiles_put(struct work *w, const char *prof, bool add, const char **errp)
{
	const char	**v, *list, *out;
	size_t		  n, i;

	v = profiles_get(w, &list, &n);
	if (add == listed(v, n, prof))
		return (0);
	out = "";
	for (i = 0; i < n; i++)
		if (strcmp(v[i], prof) != 0)
			out = wfmt(w, "%s%s%s", out, *out != '\0' ? " " : "", v[i]);
	if (add)
		out = wfmt(w, "%s%s%s", out, *out != '\0' ? " " : "", prof);
	if (*out == '\0') {
		rc_unset(w, SPEEDER "_profiles");
		return (0);
	}
	return (rc_set(w, SPEEDER "_profiles", "=", out, errp));
}

/*
 * Does the rc script run several relays?  Its text names
 * speederv2_profiles (the port's since it took them); looked for in the
 * scope's rc.d directories.
 */
static bool
profiles_supported(struct work *w)
{
	char	*dirs, *p, *d, *text;
	bool	 yes;

	yes = false;
	dirs = wstrdup(w, opts.rc_dirs);
	for (p = dirs; !yes && (d = strsep(&p, ":")) != NULL; )
		if (*d != '\0' && (text = scope_slurp(w, wfmt(w, "%s/" SPEEDER,
		    d), NULL)) != NULL)
			yes = strstr(text, SPEEDER "_profiles") != NULL;
	return (yes);
}

/* A profile's relay, by "service speederv2 one<verb> <name>". */
static int
profile_service(struct work *w, const char *prof, const char *verb,
    const char **errp)
{
	struct execres	 res;
	char		*argv[5];

	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)SPEEDER;
	argv[2] = wfmt(w, "one%s", verb);
	argv[3] = (char *)(uintptr_t)prof;
	argv[4] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0 || res.status != 0) {
		if (errp != NULL)
			*errp = wtext(w, exec_error(w, &res, wfmt(w, "service "
			    SPEEDER " one%s %s", verb, prof)));
		return (-1);
	}
	return (0);
}

/* Its service, of the host or of the jail the work is in. */
static bool
running_of(struct work *w, const char *prof)
{

	return (prof == NULL ? speeder_running(w) : profile_service(w, prof,
	    "status", NULL) == 0);
}

static int
service_of(struct work *w, const char *prof, const char *verb,
    const char **errp)
{

	return (prof == NULL ? speeder_service(w, verb, errp) :
	    profile_service(w, prof, verb, errp));
}

bool
speeder_running(struct work *w)
{
	struct execres	 res;
	char		*argv[4];
	bool		 running, enabled;

	if (w->jail == NULL) {
		running = enabled = false;
		service_state(w, SPEEDER, &running, &enabled);
		return (running);
	}
	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)SPEEDER;
	argv[2] = (char *)(uintptr_t)"onestatus";
	argv[3] = NULL;
	return (run_exec(w, scope_jexec(w, argv), &res) == 0 && res.status ==
	    0);
}

static bool
enabled_of(struct work *w)
{
	const char	*v;

	v = rc_get(w, SPEEDER "_enable");
	return (v != NULL && strcasecmp(v, "yes") == 0);
}

/* start, stop or restart it; 0, or -1 with why. */
int
speeder_service(struct work *w, const char *verb, const char **errp)
{
	struct arc_service_action_rsp	 r;
	struct execres			 res;
	char				*argv[4];

	if (w->jail == NULL) {
		memset(&r, 0, sizeof(r));
		if (do_service_action(w, SPEEDER, strcmp(verb, "start") == 0 ?
		    ARC_SERVICE_ACTION_START : strcmp(verb, "stop") == 0 ?
		    ARC_SERVICE_ACTION_STOP : ARC_SERVICE_ACTION_RESTART, &r) !=
		    0 || !r.ok) {
			*errp = r.error != NULL ? r.error : wfmt(w, SPEEDER
			    ": %s failed", verb);
			return (-1);
		}
		return (0);
	}
	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)SPEEDER;
	argv[2] = wfmt(w, "one%s", verb);
	argv[3] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, wfmt(w, "service " SPEEDER
		    " one%s", verb)));
		return (-1);
	}
	return (0);
}

/* ---- The read --------------------------------------------------- */

/* The last bytes of the log, in the scope, from a line's start. */
static char *
log_tail(struct work *w, const char *path)
{
	const char	*base;
	struct stat	 st;
	char		*buf, *p;
	off_t		 from;
	ssize_t		 n;
	int		 dfd, fd;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (NULL);
	fd = openat(dfd, base, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	close(dfd);
	if (fd == -1)
		return (NULL);
	if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || (buf = wmalloc(w,
	    TAIL_BYTES + 1)) == NULL) {
		close(fd);
		return (NULL);
	}
	from = st.st_size > TAIL_BYTES ? st.st_size - TAIL_BYTES : 0;
	n = pread(fd, buf, TAIL_BYTES, from);
	close(fd);
	if (n < 0)
		return (NULL);
	buf[n] = '\0';
	p = buf;
	if (from > 0 && strchr(buf, '\n') != NULL)
		p = strchr(buf, '\n') + 1;
	return (p);
}

/* A line of the relay's: syslog's tag is the service's, " tag[". */
static bool
ours(const char *line, const char *tag)
{
	const char	*t;

	return ((t = strstr(line, tag)) != NULL && strchr(t, ':') != NULL);
}

/* The relay's own time at a line's start, [YYYY-mm-dd HH:MM:SS]. */
static time_t
line_time(const char *line)
{
	struct tm	 tm;
	const char	*p;

	if ((p = strstr(line, "]: [")) == NULL)
		return (-1);
	memset(&tm, 0, sizeof(tm));
	if (strptime(p + 4, "%Y-%m-%d %H:%M:%S", &tm) == NULL)
		return (-1);
	tm.tm_isdst = -1;
	return (mktime(&tm));
}

/* One way's counters: packets and bytes taken in plain and with FEC. */
struct way {
	unsigned long long	 opkt, obyte, fpkt, fbyte;
};

/* The four numbers that follow at, in order; false when not four. */
static bool
four(const char *at, struct way *wy)
{
	unsigned long long	 v[4];
	const char		*p;
	char			*end;
	int			 n;

	for (p = at, n = 0; n < 4 && *p != '\0'; ) {
		if (!isdigit((unsigned char)*p)) {
			p++;
			continue;
		}
		v[n++] = strtoull(p, &end, 10);
		p = end;
	}
	if (n < 4)
		return (false);
	wy->opkt = v[0];
	wy->obyte = v[1];
	wy->fpkt = v[2];
	wy->fbyte = v[3];
	return (true);
}

/* A report line, client's or server's: each way's counters. */
static bool
report_of(const char *line, struct way *up, struct way *down)
{
	const char	*a, *b;

	if (strstr(line, "[report]") == NULL || (a = strstr(line,
	    "client-->server:")) == NULL || (b = strstr(line,
	    "server-->client:")) == NULL)
		return (false);
	return (four(a + 16, up) && four(b + 16, down));
}

/* The FEC's overhead, per cent of the plain bytes, to a hundredth;
 * below -100 with none. */
static double
overhead(unsigned long long plain, unsigned long long fec)
{
	double	v;

	if (plain == 0)
		return (-1000);
	v = ((double)fec / (double)plain - 1) * 10000;
	return ((double)(long long)(v + (v >= 0 ? 0.5 : -0.5)) / 100);
}

static ucl_object_t *
way_json(const struct way *wy, const struct way *was, double secs)
{
	ucl_object_t	*o;
	double		 oh;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)wy->opkt),
	    "plain_packets", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)wy->obyte),
	    "plain_bytes", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)wy->fpkt),
	    "fec_packets", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)wy->fbyte),
	    "fec_bytes", 0, false);
	if ((oh = overhead(wy->obyte, wy->fbyte)) >= -100)
		ucl_object_insert_key(o, ucl_object_fromdouble(oh), "overhead",
		    0, false);
	/* The last interval, when the counters only grew in it. */
	if (was != NULL && secs > 0 && wy->obyte >= was->obyte && wy->fbyte >=
	    was->fbyte && wy->opkt >= was->opkt) {
		if ((oh = overhead(wy->obyte - was->obyte, wy->fbyte -
		    was->fbyte)) >= -100)
			ucl_object_insert_key(o, ucl_object_fromdouble(oh),
			    "overhead_now", 0, false);
		ucl_object_insert_key(o, ucl_object_fromdouble((double)(wy->obyte -
		    was->obyte) / secs), "plain_rate", 0, false);
		ucl_object_insert_key(o, ucl_object_fromdouble((double)(wy->fbyte -
		    was->fbyte) / secs), "fec_rate", 0, false);
	}
	return (o);
}

/* fec_inner_parameter=1:2,2:3,...: each group size and its redundancy. */
static ucl_object_t *
groups_of(struct work *w, const char *line)
{
	ucl_object_t	*arr, *pair;
	const char	*p;
	char		*end;
	long		 x, y;

	if ((p = strstr(line, "fec_inner_parameter=")) == NULL)
		return (NULL);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (p += 20; ; p = end + 1) {
		x = strtol(p, &end, 10);
		if (end == p || *end != ':')
			break;
		p = end + 1;
		y = strtol(p, &end, 10);
		if (end == p)
			break;
		pair = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(pair, ucl_object_fromint(x));
		ucl_array_append(pair, ucl_object_fromint(y));
		ucl_array_append(arr, pair);
		if (*end != ',')
			break;
	}
	(void)w;
	return (arr);
}

/*
 * The log's lines of the relay: the groups it logged at its last start,
 * its last two reports since (the last interval between them), and its
 * last few lines.
 */
static void
log_read(struct work *w, ucl_object_t *top, const char *prof)
{
	struct way	 up[2], down[2], u, d;
	ucl_object_t	*rep, *lines, *groups, *series, *row;
	const char	*last[LOG_LINES];
	char		*text, *line, *nl;
	time_t		 at[2];
	double		 secs;
	const char	*tag;
	int		 n, i, k;

	if ((text = log_tail(w, opts.speederv2_log)) == NULL)
		return;
	tag = prof == NULL ? " " SPEEDER "[" : wfmt(w, " " SPEEDER "-%s[",
	    prof);
	memset(up, 0, sizeof(up));
	memset(down, 0, sizeof(down));
	at[0] = at[1] = -1;
	groups = NULL;
	series = ucl_object_typed_new(UCL_ARRAY);
	n = k = 0;
	for (line = text; line != NULL && *line != '\0'; line = nl) {
		if ((nl = strchr(line, '\n')) != NULL)
			*nl++ = '\0';
		if (!ours(line, tag))
			continue;
		last[n % LOG_LINES] = line;
		n++;
		if (strstr(line, "fec_inner_parameter=") != NULL) {
			if (groups != NULL)
				ucl_object_unref(groups);
			groups = groups_of(w, line);
			/* Started again: its counters begin anew, and the
			 * intervals before are another run's. */
			k = 0;
			ucl_object_unref(series);
			series = ucl_object_typed_new(UCL_ARRAY);
		} else if (report_of(line, &u, &d)) {
			up[0] = up[1];
			down[0] = down[1];
			at[0] = at[1];
			up[1] = u;
			down[1] = d;
			at[1] = line_time(line);
			if (k < 2)
				k++;
			/* An interval of the history: the overhead each way,
			 * and the plain rates, between this report and the
			 * one before, while the counters only grew. */
			if (k == 2 && at[0] != -1 && at[1] > at[0] &&
			    up[1].obyte >= up[0].obyte && up[1].fbyte >=
			    up[0].fbyte && down[1].obyte >= down[0].obyte &&
			    down[1].fbyte >= down[0].fbyte) {
				double	span = difftime(at[1], at[0]);

				row = ucl_object_typed_new(UCL_ARRAY);
				ucl_array_append(row, ucl_object_fromint(at[1]));
				ucl_array_append(row, ucl_object_fromdouble(
				    overhead(up[1].obyte - up[0].obyte,
				    up[1].fbyte - up[0].fbyte)));
				ucl_array_append(row, ucl_object_fromdouble(
				    overhead(down[1].obyte - down[0].obyte,
				    down[1].fbyte - down[0].fbyte)));
				ucl_array_append(row, ucl_object_fromdouble(
				    (double)(up[1].obyte - up[0].obyte) / span));
				ucl_array_append(row, ucl_object_fromdouble(
				    (double)(down[1].obyte - down[0].obyte) /
				    span));
				ucl_array_append(series, row);
				if (ucl_array_size(series) > SERIES_MAX)
					ucl_object_unref(ucl_array_pop_first(
					    series));
			}
		}
	}
	if (groups != NULL)
		ucl_object_insert_key(top, groups, "fec_groups", 0, false);
	/* Each interval: its time, the overhead to the server and to the
	 * client (per cent, below -100 with nothing plain), the plain
	 * rates (bytes a second); the oldest first. */
	ucl_object_insert_key(top, series, "series", 0, false);
	if (k > 0) {
		secs = k == 2 && at[0] != -1 && at[1] != -1 ? difftime(at[1],
		    at[0]) : 0;
		rep = ucl_object_typed_new(UCL_OBJECT);
		if (at[1] != -1)
			ucl_object_insert_key(rep, ucl_object_fromint(at[1]),
			    "time", 0, false);
		if (secs > 0)
			ucl_object_insert_key(rep, ucl_object_fromdouble(secs),
			    "interval", 0, false);
		ucl_object_insert_key(rep, way_json(&up[1], k == 2 ? &up[0] :
		    NULL, secs), "client_to_server", 0, false);
		ucl_object_insert_key(rep, way_json(&down[1], k == 2 ? &down[0] :
		    NULL, secs), "server_to_client", 0, false);
		ucl_object_insert_key(top, rep, "report", 0, false);
	}
	lines = ucl_object_typed_new(UCL_ARRAY);
	for (i = n > LOG_LINES ? n - LOG_LINES : 0; i < n; i++)
		ucl_array_append(lines, ucl_object_fromstring(wvis(w, wstrndup(w,
		    last[i % LOG_LINES], 400))));
	ucl_object_insert_key(top, lines, "log", 0, false);
}

/* s with the key in it shown as <hidden>. */
static const char *
unkeyed(struct work *w, const char *s, const char *key)
{
	const char	*p, *out;

	if (key == NULL || *key == '\0')
		return (s);
	out = "";
	while ((p = strstr(s, key)) != NULL) {
		out = wfmt(w, "%s%.*s<hidden>", out, (int)(p - s), s);
		s = p + strlen(key);
	}
	return (wfmt(w, "%s%s", out, s));
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0, true);
}

static void
put_int(ucl_object_t *o, const char *key, int v)
{

	if (v >= 0)
		ucl_object_insert_key(o, ucl_object_fromint(v), key, 0, true);
}

/* Is its program there, in the scope? */
static bool
installed(struct work *w)
{
	const char	*base;
	int		 dfd, rc;

	if ((dfd = scope_open_dir(w, bin(w), &base)) == -1)
		return (false);
	rc = faccessat(dfd, base, X_OK, AT_EACCESS);
	close(dfd);
	return (rc == 0);
}

/* A relay's flags read into o, the key never. */
static void
relay_json(struct work *w, ucl_object_t *top, const char *prof)
{
	struct sflags	 f;
	const char	*flags;

	if ((flags = flags_get(w, prof)) != NULL && *flags != '\0') {
		flags_parse(w, flags, &f);
		put_str(top, "flags", unkeyed(w, flags, f.key));
		put_str(top, "role", f.role);
		put_str(top, "listen", f.listen);
		put_str(top, "remote", f.remote);
		put_str(top, "fec", f.fec);
		put_str(top, "fifo", f.fifo);
		put_int(top, "mode", f.mode);
		put_int(top, "mtu", f.mtu);
		put_int(top, "timeout", f.timeout);
		put_int(top, "report_every", f.report);
		ucl_object_insert_key(top, ucl_object_frombool(f.key != NULL),
		    "key", 0, false);
		if (f.extra[0] != '\0')
			put_str(top, "extra", unkeyed(w, f.extra, f.key));
	}
	log_read(w, top, prof);
}

void
do_speeder(struct work *w, struct arc_speeder_rsp *rsp)
{
	ucl_object_t	*top, *list, *o;
	const char	**v, *names;
	char		*json;
	size_t		  n, i;

	rsp->has_ok = true;
	rsp->ok = false;
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_frombool(installed(w)),
	    "installed", 0, false);
	ucl_object_insert_key(top, ucl_object_frombool(enabled_of(w)),
	    "enabled", 0, false);
	ucl_object_insert_key(top, ucl_object_frombool(
	    profiles_supported(w)), "profiles_supported", 0, false);
	v = profiles_get(w, &names, &n);
	/* The plain relay runs only while no profile is listed. */
	ucl_object_insert_key(top, ucl_object_frombool(n == 0 &&
	    speeder_running(w)), "running", 0, false);
	relay_json(w, top, NULL);
	if (n > 0) {
		list = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < n; i++) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put_str(o, "name", v[i]);
			ucl_object_insert_key(o, ucl_object_frombool(
			    running_of(w, v[i])), "running", 0, false);
			relay_json(w, o, v[i]);
			ucl_array_append(list, o);
		}
		ucl_object_insert_key(top, list, "profiles", 0, false);
	}
	put_str(top, "log_path", opts.speederv2_log);
	if (w->jail != NULL)
		put_str(top, "jail", w->jail);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "out of memory";
		return;
	}
	rsp->json = wstrdup(w, json);
	free(json);
	rsp->ok = true;
}

/* ---- The job ---------------------------------------------------- */

/* An argument name=value: its value, or NULL when it is not name's. */
static const char *
arg_of(const char *word, const char *name)
{
	size_t	n;

	n = strlen(name);
	return (strncmp(word, name, n) == 0 && word[n] == '=' ? word + n + 1 :
	    NULL);
}

/* The relay a job is for: its profile=, or NULL for the plain one. */
static const char *
profile_of(const struct arc_job_spec *sp)
{
	const char	*v;
	size_t		 i;

	for (i = 0; i < sp->names.n; i++)
		if ((v = arg_of(sp->names.v[i], "profile")) != NULL)
			return (v);
	return (NULL);
}

/* The job's words but profile=, how many. */
static size_t
words_of(const struct arc_job_spec *sp, const char **first)
{
	size_t	i, n;

	*first = NULL;
	for (i = n = 0; i < sp->names.n; i++)
		if (arg_of(sp->names.v[i], "profile") == NULL) {
			if (n++ == 0)
				*first = sp->names.v[i];
		}
	return (n);
}

/*
 * conf's arguments into f: the key kept from the flags before (old) but
 * given key= or nokey.  NULL, or what is wrong.
 */
static const char *
conf_of(struct work *w, const struct arc_job_spec *sp, const char *old,
    struct sflags *f)
{
	struct sflags	 was;
	const char	*a, *v, *e;
	size_t		 i;
	bool		 nokey, key;

	flags_parse(w, old, &was);
	memset(f, 0, sizeof(*f));
	f->mode = f->mtu = f->timeout = f->report = -1;
	f->extra = "";
	nokey = key = false;
	for (i = 0; i < sp->names.n; i++) {
		a = sp->names.v[i];
		if (arg_of(a, "profile") != NULL)
			continue;
		if (strcmp(a, "nokey") == 0)
			nokey = true;
		else if ((v = arg_of(a, "role")) != NULL) {
			if (strcmp(v, "client") != 0 && strcmp(v, "server") != 0)
				return ("role is client or server");
			f->role = v;
		} else if ((v = arg_of(a, "listen")) != NULL) {
			if (!hostport_ok(v))
				return ("listen is an address and a port: "
				    "127.0.0.1:51821, [::1]:51821");
			f->listen = v;
		} else if ((v = arg_of(a, "remote")) != NULL) {
			if (!hostport_ok(v))
				return ("remote is an address and a port: "
				    "192.0.2.1:14350, [2001:db8::1]:14350");
			f->remote = v;
		} else if ((v = arg_of(a, "mode")) != NULL) {
			if ((f->mode = num_in(v, 0, 1)) < 0)
				return ("mode is 0 or 1");
		} else if ((v = arg_of(a, "mtu")) != NULL) {
			if ((f->mtu = num_in(v, 100, 2000)) < 0)
				return ("mtu is 100 to 2000");
		} else if ((v = arg_of(a, "fec")) != NULL) {
			if (!fec_ok(v))
				return ("fec is x:y or x1:y1,x2:y2,...: y redundant "
				    "packets for x, x 1 or more, x + y 254 at most");
			f->fec = v;
		} else if ((v = arg_of(a, "timeout")) != NULL) {
			if ((f->timeout = num_in(v, 0, 1000)) < 0)
				return ("timeout is 0 to 1000 ms");
		} else if ((v = arg_of(a, "report")) != NULL) {
			if ((f->report = num_in(v, 0, 3600)) < 0)
				return ("report is 0 (none) to 3600 s");
		} else if ((v = arg_of(a, "fifo")) != NULL) {
			if (*v != '\0' && (*v != '/' || !word_ok(v, 200) ||
			    strstr(v, "/../") != NULL))
				return ("fifo is a path: /var/run/speederv2/fifo");
			f->fifo = *v != '\0' ? v : NULL;
		} else if ((v = arg_of(a, "key")) != NULL) {
			if (!word_ok(v, KEY_MAX))
				return ("a key is 64 characters at most: letters, "
				    "digits and . _ : , / @ % + = -");
			f->key = v;
			key = true;
		} else if ((v = arg_of(a, "extra")) != NULL) {
			if (*v != '\0' && (e = extra_check(w, v)) != NULL)
				return (e);
			f->extra = v;
		} else
			return (wfmt(w, "conf takes role=, listen=, remote=, "
			    "mode=, mtu=, fec=, timeout=, report=, fifo=, key=, "
			    "nokey, extra= and profile=, not %s", wvis(w,
			    wstrndup(w, a, 40))));
	}
	if (f->role == NULL || f->listen == NULL || f->remote == NULL)
		return ("conf needs role=, listen= and remote=");
	if (!key && !nokey)
		f->key = was.key;
	if (nokey)
		f->key = NULL;
	if (strlen(flags_of(w, f)) > FLAGS_MAX)
		return ("the flags are 1024 characters at most");
	return (NULL);
}

const char *
speeder_check(const struct arc_job_spec *sp)
{
	static _Thread_local char	 errbuf[300];
	struct work			 cw;
	struct sflags			 f;
	const char			*e, *prof, *word;
	size_t				 i, n, np;

	if (sp->verb == NULL)
		return ("a speeder job has a verb: conf, fec, enable, disable, "
		    "start, stop, restart, remove");
	if (sp->safe && sp->jail != NULL && sp->jail[0] != '\0')
		return ("a jail's relay is not undone: not in safe mode");
	for (i = np = 0; i < sp->names.n; i++)
		if ((prof = arg_of(sp->names.v[i], "profile")) != NULL) {
			if (!profile_ok(prof))
				return ("a profile is 32 letters, digits and _ at "
				    "most");
			np++;
		}
	if (np > 1)
		return ("one profile= at most");
	prof = profile_of(sp);
	n = words_of(sp, &word);
	if ((strcmp(sp->verb, "enable") == 0 || strcmp(sp->verb, "disable") ==
	    0) && prof != NULL)
		return ("enable and disable are the service's, every relay's: "
		    "no profile=");
	if (strcmp(sp->verb, "remove") == 0)
		return (prof != NULL && n == 0 ? NULL : "remove takes "
		    "profile=<name> alone");
	if (strcmp(sp->verb, "conf") == 0) {
		work_init(&cw);
		e = conf_of(&cw, sp, NULL, &f);
		if (e != NULL) {
			snprintf(errbuf, sizeof(errbuf), "%s", e);
			e = errbuf;
		}
		work_free(&cw);
		return (e);
	}
	if (strcmp(sp->verb, "fec") == 0)
		return (n == 1 && fec_ok(word) ? NULL : "fec takes the ratios: "
		    "x:y or x1:y1,x2:y2,..., x 1 or more, x + y 254 at most");
	if (strcmp(sp->verb, "enable") == 0 || strcmp(sp->verb, "disable") ==
	    0 || strcmp(sp->verb, "start") == 0 || strcmp(sp->verb, "stop") ==
	    0 || strcmp(sp->verb, "restart") == 0)
		return (n == 0 ? NULL : "enable, disable, start, stop and "
		    "restart take no words but profile=");
	return ("a speeder job is conf, fec, enable, disable, start, stop, "
	    "restart or remove");
}

/* What the job is, the key never in it. */
char *
speeder_title(const struct arc_job_spec *sp)
{
	const char	*role, *listen, *remote, *v, *who, *word;
	size_t		 i;
	char		*t, *out;
	int		 rc;

	who = SPEEDER;
	if ((v = profile_of(sp)) != NULL && asprintf(&t, SPEEDER " %s", v) !=
	    -1)
		who = t;
	else
		t = NULL;
	rc = -1;
	if (strcmp(sp->verb, "conf") == 0) {
		role = listen = remote = "";
		for (i = 0; i < sp->names.n; i++) {
			if ((v = arg_of(sp->names.v[i], "role")) != NULL)
				role = v;
			else if ((v = arg_of(sp->names.v[i], "listen")) != NULL)
				listen = v;
			else if ((v = arg_of(sp->names.v[i], "remote")) != NULL)
				remote = v;
		}
		rc = asprintf(&out, "%s: conf, a %s from %s to %s", who, role,
		    listen, remote);
	} else if (strcmp(sp->verb, "fec") == 0 && words_of(sp, &word) == 1)
		rc = asprintf(&out, "%s: fec %s", who, word);
	else
		rc = asprintf(&out, "%s: %s", who, sp->verb);
	free(t);
	return (rc == -1 ? NULL : out);
}

/* The ratios sent to the running relay by its fifo: "fec x:y,...". */
static int
fifo_send(struct work *w, const char *fifo, const char *fec,
    const char **errp)
{
	const char	*base, *cmd;
	ssize_t		 n;
	int		 dfd, fd, step;

	cmd = wfmt(w, "fec %s\n", fec);
	step = step_begin(w, ARC_STEP_KIND_FILE, fifo, "write(2) \"fec %s\" "
	    "to the relay's fifo", fec);
	fd = -1;
	if ((dfd = scope_open_dir(w, fifo, &base)) != -1) {
		fd = openat(dfd, base, O_WRONLY | O_NONBLOCK | O_CLOEXEC |
		    O_NOFOLLOW);
		close(dfd);
	}
	if (fd == -1) {
		*errp = wfmt(w, "%s: %s", fifo, strerror(errno));
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	n = write(fd, cmd, strlen(cmd));
	close(fd);
	if (n != (ssize_t)strlen(cmd)) {
		*errp = wfmt(w, "%s: %s", fifo, n == -1 ? strerror(errno) :
		    "written in part");
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, NULL);
	return (0);
}

int
do_speeder_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct sflags	 f;
	const char	*old, *e, *prof, *word;
	bool		 running;

	prof = profile_of(sp);
	if (prof != NULL && !profiles_supported(w)) {
		*errp = "the rc script of " SPEEDER " runs one relay: a port "
		    "with " SPEEDER "_profiles runs several";
		return (-1);
	}
	running = strcmp(sp->verb, "enable") == 0 || strcmp(sp->verb,
	    "disable") == 0 ? speeder_running(w) : running_of(w, prof);
	if (strcmp(sp->verb, "conf") == 0) {
		old = flags_get(w, prof);
		if ((e = conf_of(w, sp, old, &f)) != NULL) {
			*errp = e;
			return (-1);
		}
		if (flags_set(w, prof, flags_of(w, &f), errp) != 0)
			return (-1);
		if (prof != NULL && profiles_put(w, prof, true, errp) != 0)
			return (-1);
		/* Taken where it runs; else at its next start. */
		return (running ? service_of(w, prof, "restart", errp) : 0);
	}
	if (strcmp(sp->verb, "remove") == 0) {
		if (running && service_of(w, prof, "stop", errp) != 0)
			return (-1);
		if (flags_set(w, prof, NULL, errp) != 0)
			return (-1);
		rc_unset(w, var_of(w, prof, "user"));
		return (profiles_put(w, prof, false, errp));
	}
	if (strcmp(sp->verb, "fec") == 0) {
		if ((old = flags_get(w, prof)) == NULL || *old == '\0') {
			*errp = wfmt(w, "%s is not set: configure the relay "
			    "first", var_of(w, prof, "flags"));
			return (-1);
		}
		flags_parse(w, old, &f);
		if (f.role == NULL || f.listen == NULL || f.remote == NULL) {
			*errp = wfmt(w, "%s says no role, listen or remote: "
			    "configure the relay again", var_of(w, prof, "flags"));
			return (-1);
		}
		words_of(sp, &word);
		f.fec = word;
		if (flags_set(w, prof, flags_of(w, &f), errp) != 0)
			return (-1);
		/* A running relay takes them by its fifo, the tunnel kept;
		 * without one, by a restart. */
		if (!running)
			return (0);
		if (f.fifo != NULL)
			return (fifo_send(w, f.fifo, f.fec, errp));
		return (service_of(w, prof, "restart", errp));
	}
	if (strcmp(sp->verb, "enable") == 0 || strcmp(sp->verb, "disable") ==
	    0) {
		if (rc_set(w, SPEEDER "_enable", "=", strcmp(sp->verb, "enable")
		    == 0 ? "YES" : "NO", errp) != 0)
			return (-1);
		if (strcmp(sp->verb, "enable") == 0 && !running)
			return (speeder_service(w, "start", errp));
		if (strcmp(sp->verb, "disable") == 0 && running)
			return (speeder_service(w, "stop", errp));
		return (0);
	}
	if (strcmp(sp->verb, "stop") == 0 && !running)
		return (0);
	return (service_of(w, prof, strcmp(sp->verb, "start") == 0 && running ?
	    "restart" : sp->verb, errp));
}

/* ---- Safe mode (ira/jobs.c) -------------------------------------- */

/* The relay the job is for, as it is: its flags, the service's enable,
 * the list of profiles, and whether it runs. */
void
speeder_snap(struct work *w, const struct arc_job_spec *sp,
    struct speeder_was *was)
{
	size_t	n;

	was->profile = profile_of(sp);
	was->flags = flags_get(w, was->profile);
	was->enable = rc_get(w, SPEEDER "_enable");
	profiles_get(w, &was->profiles, &n);
	was->running = running_of(w, was->profile);
}

int
speeder_back(struct work *w, const struct speeder_was *was,
    const char **errp)
{
	const char	*prof;

	prof = was->profile;
	if (flags_set(w, prof, was->flags, errp) != 0)
		return (-1);
	if (was->profiles == NULL)
		rc_unset(w, SPEEDER "_profiles");
	else if (rc_set(w, SPEEDER "_profiles", "=", was->profiles, errp) != 0)
		return (-1);
	if (was->enable == NULL)
		rc_unset(w, SPEEDER "_enable");
	else if (rc_set(w, SPEEDER "_enable", "=", was->enable, errp) != 0)
		return (-1);
	if (was->running)
		return (service_of(w, prof, running_of(w, prof) ? "restart" :
		    "start", errp));
	return (running_of(w, prof) ? service_of(w, prof, "stop", errp) : 0);
}
