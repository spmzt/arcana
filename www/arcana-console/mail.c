/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Mail: what happened on the hosts, told to who asked for it whether or
 * not a page is open.  Faults (of a severity and above), a figure of
 * history over its limit and back, jobs (those that failed, or all) and
 * workflow runs (the same), as the settings say, to the addresses in
 * mail_to.
 *
 * The console's host sends it: sendmail(8) -t, as FreeBSD comes, is
 * mailwrapper(8) and dma(8), which relays as /etc/dma/dma.conf says;
 * web.conf's sendmail names another.  Arcana sets up no mail server.
 *
 * One worker reads each host's events, from the newest it has seen, a
 * tick at a time: those that are mailed go out in one mail a tick, and
 * twenty an hour at most; the rest wait for the next.  A host first
 * read is read from its newest: what happened before is not mailed.
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <kore/kore.h>
#include <kore/http.h>

#include <openssl/evp.h>

#include <ucl.h>

#include "console.h"

#define	MAIL_LOCK	"mail.lock"
#define	MAIL_HOUR_MAX	20
#define	MAIL_HOSTS	64
#define	MAIL_HELD	(64 * 1024)	/* text waiting for the next mail */

extern char	**environ;

static pthread_mutex_t	 lock = PTHREAD_MUTEX_INITIALIZER;
static time_t		 sent_at[MAIL_HOUR_MAX];	/* the last hour's */
static char		*held;		/* lines not yet mailed */
static size_t		 nheld, held_lines;

struct cursor {
	char		id[9];
	uint64_t	last;
};
static struct cursor	cursors[MAIL_HOSTS];
static size_t		ncursors;

/*
 * The mail's settings as they are now, read for each use: the threads
 * here are not the worker's, which alone changes cfg.
 */
struct mailconf {
	char	*to, *from, *faults, *jobs, *runs;
	bool	 limits;
};

static void
mc_load(struct mailconf *mc)
{
	char	*l;

	mc->to = settings_peek("mail_to");
	mc->from = settings_peek("mail_from");
	mc->faults = settings_peek("mail_faults");
	mc->jobs = settings_peek("mail_jobs");
	mc->runs = settings_peek("mail_runs");
	l = settings_peek("mail_limits");
	mc->limits = strcmp(l, "true") == 0;
	free(l);
}

static void
mc_free(struct mailconf *mc)
{

	free(mc->to);
	free(mc->from);
	free(mc->faults);
	free(mc->jobs);
	free(mc->runs);
}

static const char *
from_address(const struct mailconf *mc, char *buf, size_t len)
{
	char	host[MAXHOSTNAMELEN];

	if (mc->from[0] != '\0')
		return (mc->from);
	if (gethostname(host, sizeof(host)) != 0)
		strlcpy(host, "localhost", sizeof(host));
	snprintf(buf, len, "arcana@%s", host);
	return (buf);
}

/* A header's words, =?UTF-8?B?...?= where they are not ASCII. */
static void
header_text(char *out, size_t len, const char *s)
{
	const unsigned char	*p;
	unsigned char		*b;
	size_t			 n;

	for (p = (const unsigned char *)s; *p != '\0'; p++)
		if (*p >= 0x80 || *p < 0x20)
			break;
	if (*p == '\0') {
		snprintf(out, len, "%s", s);
		return;
	}
	n = strlen(s);
	if (n > 300)
		n = 300;
	if ((b = malloc(4 * ((n + 2) / 3) + 1)) == NULL)
		abort();
	EVP_EncodeBlock(b, (const unsigned char *)s, (int)n);
	snprintf(out, len, "=?UTF-8?B?%s?=", b);
	free(b);
}

/* The addresses, a comma between them, as To: has them. */
static void
recipients(const struct mailconf *mc, char *out, size_t len)
{
	const char	*p, *e;
	size_t		 o;

	o = 0;
	out[0] = '\0';
	for (p = mc->to; *p != '\0'; p = e) {
		p += strspn(p, " ,;\t");
		if (*p == '\0')
			break;
		e = p + strcspn(p, " ,;\t");
		if (o + (size_t)(e - p) + 3 >= len)
			break;
		o += (size_t)snprintf(out + o, len - o, "%s%.*s", o > 0 ? ", " :
		    "", (int)(e - p), p);
	}
}

/*
 * subject and body to mail_to, by sendmail -t -i.  0, or -1 with why
 * in err.
 */
static int
send_with(const struct mailconf *mc, const char *subject, const char *body,
    char *err, size_t errlen)
{
	posix_spawn_file_actions_t	 fa;
	char				 to[1024], from[300], subj[600],
					 date[64], host[MAXHOSTNAMELEN],
					 said[300], *msg, *argv[4];
	struct tm			 tm;
	time_t				 now;
	ssize_t				 n;
	size_t				 len, off;
	pid_t				 pid;
	int				 in[2], out[2], st;

	recipients(mc, to, sizeof(to));
	if (to[0] == '\0') {
		snprintf(err, errlen, "no address to mail to");
		return (-1);
	}
	now = time(NULL);
	localtime_r(&now, &tm);
	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", &tm);
	if (gethostname(host, sizeof(host)) != 0)
		strlcpy(host, "localhost", sizeof(host));
	header_text(subj, sizeof(subj), subject);
	if (asprintf(&msg, "From: Arcana <%s>\nTo: %s\nSubject: %s\nDate: %s\n"
	    "Message-ID: <%jd.%08x@%s>\nMIME-Version: 1.0\nContent-Type: "
	    "text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n"
	    "Auto-Submitted: auto-generated\n\n%s%s", from_address(mc, from,
	    sizeof(from)), to, subj, date, (intmax_t)now, arc4random(), host,
	    body, body[0] != '\0' && body[strlen(body) - 1] != '\n' ? "\n" :
	    "") == -1) {
		snprintf(err, errlen, "out of memory");
		return (-1);
	}
	if (pipe2(in, O_CLOEXEC) == -1 || pipe2(out, O_CLOEXEC) == -1) {
		snprintf(err, errlen, "pipe: %s", strerror(errno));
		free(msg);
		return (-1);
	}
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_adddup2(&fa, in[0], STDIN_FILENO);
	posix_spawn_file_actions_adddup2(&fa, out[1], STDOUT_FILENO);
	posix_spawn_file_actions_adddup2(&fa, out[1], STDERR_FILENO);
	argv[0] = (char *)(uintptr_t)"sendmail";
	argv[1] = (char *)(uintptr_t)"-t";
	argv[2] = (char *)(uintptr_t)"-i";
	argv[3] = NULL;
	st = posix_spawn(&pid, cfg.sendmail, &fa, NULL, argv, environ);
	posix_spawn_file_actions_destroy(&fa);
	close(in[0]);
	close(out[1]);
	if (st != 0) {
		snprintf(err, errlen, "%s: %s", cfg.sendmail, strerror(st));
		close(in[1]);
		close(out[0]);
		free(msg);
		return (-1);
	}
	len = strlen(msg);
	for (off = 0; off < len; off += (size_t)n)
		if ((n = write(in[1], msg + off, len - off)) <= 0)
			break;
	close(in[1]);
	free(msg);
	off = 0;
	while (off < sizeof(said) - 1 && (n = read(out[0], said + off,
	    sizeof(said) - 1 - off)) > 0)
		off += (size_t)n;
	said[off] = '\0';
	close(out[0]);
	while (waitpid(pid, &st, 0) == -1 && errno == EINTR)
		;
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		said[strcspn(said, "\n")] = '\0';
		snprintf(err, errlen, "%s: %s", cfg.sendmail, said[0] != '\0' ?
		    said : "failed");
		return (-1);
	}
	return (0);
}

/* subject and body to mail_to, as the settings are now. */
int
mail_send(const char *subject, const char *body, char *err, size_t errlen)
{
	struct mailconf	mc;
	int		rc;

	mc_load(&mc);
	rc = send_with(&mc, subject, body, err, errlen);
	mc_free(&mc);
	return (rc);
}

/* A line for the next mail. */
static void
hold(const char *fmt, ...)
{
	va_list	 ap;
	char	 line[1024];
	int	 n;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	pthread_mutex_lock(&lock);
	if (held == NULL)
		if ((held = calloc(1, MAIL_HELD)) == NULL)
			abort();
	if (nheld + strlen(line) + 2 < MAIL_HELD) {
		nheld += (size_t)snprintf(held + nheld, MAIL_HELD - nheld,
		    "%s\n", line);
		held_lines++;
	}
	pthread_mutex_unlock(&lock);
}

static int
severity_rank(const char *s)
{
	static const char *const r[] = { "Warning", "Minor", "Major",
	    "Critical" };
	size_t	i;

	for (i = 0; s != NULL && i < nitems(r); i++)
		if (strcasecmp(s, r[i]) == 0)
			return ((int)i);
	return (-1);
}

static const char *
str(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(o, k)) == NULL)
		return (NULL);
	return (ucl_object_tostring_forced(v));
}

/* One event of a host, held when it is one asked for. */
static void
event(const struct mailconf *mc, const char *host, const ucl_object_t *e)
{
	const ucl_object_t	*d;
	const char		*kind;
	char			 when[32];
	struct tm		 tm;
	time_t			 t;
	int			 min;

	kind = str(e, "kind");
	d = ucl_object_lookup(e, "data");
	if (kind == NULL || d == NULL)
		return;
	t = (time_t)ucl_object_toint(ucl_object_lookup(e, "t"));
	localtime_r(&t, &tm);
	strftime(when, sizeof(when), "%H:%M:%S", &tm);
	if (strcmp(kind, "sdwan-fault") == 0) {
		min = severity_rank(mc->faults);
		if (min < 0)
			return;
		if (strcmp(str(d, "state") != NULL ? str(d, "state") : "",
		    "cleared") == 0 || strcmp(str(d, "severity") != NULL ?
		    str(d, "severity") : "", "Cleared") == 0)
			hold("%s %s: cleared: %s of %s", when, host, str(d,
			    "type"), str(d, "object"));
		else if (severity_rank(str(d, "severity")) >= min)
			hold("%s %s: fault, %s: %s of %s: %s", when, host,
			    str(d, "severity"), str(d, "type"), str(d, "object"),
			    str(d, "description") != NULL ? str(d,
			    "description") : "");
	} else if (strcmp(kind, "threshold") == 0 && mc->limits) {
		hold("%s %s: %s%s%s %s its limit: %s, the limit %s", when, host,
		    str(d, "what"), str(d, "name") != NULL ? " " : "",
		    str(d, "name") != NULL ? str(d, "name") : "",
		    ucl_object_toboolean(ucl_object_lookup(d, "over")) ?
		    "over" : "back under", str(d, "value"), str(d, "limit"));
	} else if (strcmp(kind, "job") == 0 && strcmp(mc->jobs, "none") != 0) {
		if (ucl_object_toboolean(ucl_object_lookup(d, "ok"))) {
			if (strcmp(mc->jobs, "all") == 0)
				hold("%s %s: job %s done: %s", when, host,
				    str(d, "id"), str(d, "title"));
		} else
			hold("%s %s: job %s failed: %s: %s", when, host,
			    str(d, "id"), str(d, "title"), str(d, "error") !=
			    NULL ? str(d, "error") : "failed");
	}
}

/* A workflow's run, as it ends: held, when runs are mailed. */
void
mail_run(const char *workflow, unsigned int run, const char *state)
{
	struct mailconf	mc;
	bool		ok, no;

	ok = strcmp(state, "done") == 0;
	mc_load(&mc);
	no = mc.to[0] == '\0' || strcmp(mc.runs, "none") == 0 || (ok &&
	    strcmp(mc.runs, "all") != 0);
	mc_free(&mc);
	if (no)
		return;
	hold("workflow %s, run %u: %s", workflow, run, state);
	/* A run ends in a thread of its own: its mail goes out from here
	 * when the worker that runs workflows reads no events. */
	mail_flush();
}

/* What is held, mailed: one mail, within the hour's. */
void
mail_flush(void)
{
	char		*body, subject[200], err[300];
	const char	*nl;
	time_t		 now;
	size_t		 i, lines, free_slot;

	pthread_mutex_lock(&lock);
	if (nheld == 0) {
		pthread_mutex_unlock(&lock);
		return;
	}
	now = time(NULL);
	free_slot = MAIL_HOUR_MAX;
	for (i = 0; i < MAIL_HOUR_MAX; i++)
		if (now - sent_at[i] >= 3600) {
			free_slot = i;
			break;
		}
	if (free_slot == MAIL_HOUR_MAX) {
		pthread_mutex_unlock(&lock);
		return;			/* the next hour's */
	}
	sent_at[free_slot] = now;
	if ((body = strdup(held)) == NULL)
		abort();
	lines = held_lines;
	nheld = 0;
	held_lines = 0;
	held[0] = '\0';
	pthread_mutex_unlock(&lock);
	if (lines == 1) {
		nl = strchr(body, '\n');
		snprintf(subject, sizeof(subject), "Arcana: %.*s", (int)(nl !=
		    NULL ? nl - body : (ptrdiff_t)strlen(body)), body);
	} else
		snprintf(subject, sizeof(subject), "Arcana: %zu things happened",
		    lines);
	if (mail_send(subject, body, err, sizeof(err)) != 0)
		thread_log(LOG_WARNING, "mail: not sent: %s", err);
	free(body);
}

static struct cursor *
cursor_of(const char *id, bool *fresh)
{
	size_t	i;

	*fresh = false;
	for (i = 0; i < ncursors; i++)
		if (strcmp(cursors[i].id, id) == 0)
			return (&cursors[i]);
	if (ncursors == MAIL_HOSTS)
		return (NULL);
	*fresh = true;
	strlcpy(cursors[ncursors].id, id, sizeof(cursors[ncursors].id));
	cursors[ncursors].last = 0;
	return (&cursors[ncursors++]);
}

static void
tick(void)
{
	const struct server	*s;
	struct cursor		*c;
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*data, *e;
	ucl_object_iter_t	 it;
	char			 id[9], *name, *uri, *peer, *ans;
	struct mailconf		 mc;
	int			 i, st;
	bool			 fresh;

	mc_load(&mc);
	if (mc.to[0] == '\0') {
		ncursors = 0;		/* when it is set, from then on */
		mc_free(&mc);
		return;
	}
	for (i = 0; (s = server_at(i)) != NULL; i++) {
		strlcpy(id, s->id, sizeof(id));
		if ((name = strdup(s->name)) == NULL || (uri = strdup(s->uri)) ==
		    NULL || (s->peer_name != NULL && (peer = strdup(
		    s->peer_name)) == NULL))
			abort();
		if (s->peer_name == NULL)
			peer = NULL;
		if ((c = cursor_of(id, &fresh)) == NULL)
			goto next;
		ans = hosts_events(uri, peer, name, c->last, &st);
			if (ans == NULL || st != 200)
			goto done;
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		top = ucl_parser_add_string(p, ans, 0) ?
		    ucl_parser_get_object(p) : NULL;
		ucl_parser_free(p);
		if (top != NULL && (data = ucl_object_lookup(top, "data")) !=
		    NULL) {
			it = NULL;
			while (!fresh && (e = ucl_object_iterate(
			    ucl_object_lookup(data, "events"), &it, true)) !=
			    NULL)
				event(&mc, name, e);
			if (ucl_object_lookup(data, "last") != NULL)
				c->last = (uint64_t)ucl_object_toint(
				    ucl_object_lookup(data, "last"));
		}
		if (top != NULL)
			ucl_object_unref(top);
done:
		free(ans);		/* hosts_events() mallocs it */
next:
		free(name);
		free(uri);
		free(peer);
	}
	mail_flush();
}

static void *
watcher(void *arg __unused)
{

	for (;;) {
		sleep((unsigned int)cfg.mail_tick);
		tick();
	}
	return (NULL);
}

/* At the worker's start: the one that takes the lock reads the hosts. */
void
mail_init(void)
{
	pthread_t	tid;
	char		path[MAXPATHLEN];
	int		fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, MAIL_LOCK);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return;
	if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
		close(fd);
		return;
	}
	if (pthread_create(&tid, NULL, watcher, NULL) == 0)
		(void)pthread_detach(tid);
}

/* POST /api/settings/mail-test: a mail to say mail goes out. */
int
api_mail_test(struct http_request *req)
{
	struct mailconf	 mc;
	ucl_object_t	*o;
	char		 err[300], to[1024];

	if (!guard(req, true))
		return (KORE_RESULT_OK);
	mc_load(&mc);
	recipients(&mc, to, sizeof(to));
	mc_free(&mc);
	if (mail_send("Arcana: a test", "This mail says the console's mail "
	    "reaches you.\n\nIt was sent by sendmail(8) on the console's host; "
	    "faults, limits crossed, jobs and workflow runs come the same "
	    "way, as Settings, Notifications says.\n", err, sizeof(err)) != 0)
		return (reply_error(req, 502, "not-sent", "%s", err));
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_frombool(true), "ok", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(to), "to", 0, false);
	return (reply_json(req, 200, o));
}
