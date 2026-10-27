/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Alerts: what happened on the hosts, told to who asked for it whether
 * or not a page is open, by mail and by Telegram, each as its own
 * settings say: faults (of a severity and above), a figure of history
 * over its limit and back, jobs (those that failed, or all) and
 * workflow runs (the same); by mail to the addresses in mail_to, by
 * Telegram to telegram_chats, through a bot.
 *
 * The console's host sends it: sendmail(8) -t, as FreeBSD comes, is
 * mailwrapper(8) and dma(8), which relays as /etc/dma/dma.conf says;
 * web.conf's sendmail names another.  Arcana sets up no mail server.
 * A Telegram message is sent by an agent (luxuria/telegram.c), the one
 * of the host telegram_via names
 * or the one beside the console: the host that reaches the world
 * outside, not the console.
 *
 * One worker reads each host's events, from the newest it has seen, a
 * tick at a time: those told go out in one message a tick on each way,
 * and twenty an hour at most; the rest wait for the next.  A host first
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

#include <openssl/evp.h>

#include <ucl.h>

#include "console.h"

#define	MAIL_LOCK	"mail.lock"
#define	MAIL_HOUR_MAX	20
#define	MAIL_HOSTS	64
#define	MAIL_HELD	(64 * 1024)	/* text waiting for the next mail */

extern char	**environ;

static pthread_mutex_t	 lock = PTHREAD_MUTEX_INITIALIZER;

/* Each way alerts go: what waits for its next message, the hour's. */
enum { CH_MAIL, CH_TELEGRAM, CH_N };
static struct chan {
	time_t	 sent_at[MAIL_HOUR_MAX];	/* the last hour's */
	char	*held;		/* lines not yet sent */
	size_t	 nheld, held_lines;
} chans[CH_N];

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
	char	*tg_chats, *tg_token, *tg_via, *tg_faults, *tg_jobs, *tg_runs;
	bool	 tg_limits;
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
	mc->tg_chats = settings_peek("telegram_chats");
	mc->tg_token = settings_peek("telegram_token");
	mc->tg_via = settings_peek("telegram_via");
	mc->tg_faults = settings_peek("telegram_faults");
	mc->tg_jobs = settings_peek("telegram_jobs");
	mc->tg_runs = settings_peek("telegram_runs");
	l = settings_peek("telegram_limits");
	mc->tg_limits = strcmp(l, "true") == 0;
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
	free(mc->tg_chats);
	explicit_bzero(mc->tg_token, strlen(mc->tg_token));
	free(mc->tg_token);
	free(mc->tg_via);
	free(mc->tg_faults);
	free(mc->tg_jobs);
	free(mc->tg_runs);
}

/* Is the way on: somewhere to tell, and for Telegram a bot. */
static bool
chan_on(const struct mailconf *mc, int ch)
{

	return (ch == CH_MAIL ? mc->to[0] != '\0' : mc->tg_chats[0] != '\0' &&
	    mc->tg_token[0] != '\0');
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

/* At most max bytes of s, not cutting a UTF-8 character in two. */
static size_t
utf8_cut(const char *s, size_t max)
{
	size_t	n;

	if ((n = strlen(s)) <= max)
		return (n);
	n = max;
	while (n > 0 && ((unsigned char)s[n] & 0xc0) == 0x80)
		n--;
	return (n);
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
	n = utf8_cut(s, 300);
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
	if (pipe2(in, O_CLOEXEC) == -1) {
		snprintf(err, errlen, "pipe: %s", strerror(errno));
		free(msg);
		return (-1);
	}
	if (pipe2(out, O_CLOEXEC) == -1) {
		snprintf(err, errlen, "pipe: %s", strerror(errno));
		close(in[0]);
		close(in[1]);
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

/* A line for the next message on a way. */
static void
hold(int ch, const char *fmt, ...)
{
	struct chan	*c = &chans[ch];
	va_list		 ap;
	char		 line[1024];
	int		 n;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	pthread_mutex_lock(&lock);
	if (c->held == NULL)
		if ((c->held = calloc(1, MAIL_HELD)) == NULL)
			abort();
	if (c->nheld + strlen(line) + 3 < MAIL_HELD) {
		c->nheld += (size_t)snprintf(c->held + c->nheld, MAIL_HELD -
		    c->nheld, ch == CH_TELEGRAM ? "%s\n\n" : "%s\n", line);
		c->held_lines++;
	}
	pthread_mutex_unlock(&lock);
}

/*
 * The host whose agent sends a Telegram message: telegram_via's, by its
 * id or name, or the agent beside the console.  To be freed.
 */
static int
tg_sender(const struct mailconf *mc, char **uri, char **peer, char **name,
    char *err, size_t errlen)
{
	struct hostref	*all;
	int		 i, n;

	*uri = *peer = *name = NULL;
	if (mc->tg_via[0] == '\0') {
		if (cfg.local_agent == NULL) {
			snprintf(err, errlen, "no host to send it from: name one "
			    "in Settings (Telegram sent from), or run an agent "
			    "beside the console");
			return (-1);
		}
		if ((*uri = strdup(cfg.local_agent)) == NULL || (*name = strdup(
		    "the console's host")) == NULL)
			abort();
		return (0);
	}
	/* The table is the worker's: its copy, here. */
	if ((all = calloc(MAIL_HOSTS * 4, sizeof(*all))) == NULL)
		abort();
	n = host_refs_get(all, MAIL_HOSTS * 4);
	for (i = 0; i < n; i++)
		if (strcmp(all[i].id, mc->tg_via) == 0 || strcmp(all[i].name,
		    mc->tg_via) == 0) {
			if ((*uri = strdup(all[i].uri)) == NULL || (*name =
			    strdup(all[i].name)) == NULL || (all[i].peer[0] !=
			    '\0' && (*peer = strdup(all[i].peer)) == NULL))
				abort();
			free(all);
			return (0);
		}
	free(all);
	snprintf(err, errlen, "no host %s to send it from", mc->tg_via);
	return (-1);
}

/*
 * text to every chat of telegram_chats, by the sender's agent: 0, or -1
 * with why in err (the last chat's that failed).
 */
static int
tg_send(const struct mailconf *mc, const char *text, char *err,
    size_t errlen)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	const ucl_object_t	*e;
	char			*uri, *peer, *name, *list, *rest, *chat, *ans;
	char			 msg[4097];
	int			 rc, st;

	if (mc->tg_token[0] == '\0' || mc->tg_chats[0] == '\0') {
		snprintf(err, errlen, "no bot's token, or no chat, in Settings");
		return (-1);
	}
	if (tg_sender(mc, &uri, &peer, &name, err, errlen) != 0)
		return (-1);
	/* What does not fit one message is cut, and says so: between two
	 * characters, the Bot API refusing what is not UTF-8. */
	if (strlen(text) > 4000)
		snprintf(msg, sizeof(msg), "%.*s\n…", (int)utf8_cut(text, 4000),
		    text);
	else
		snprintf(msg, sizeof(msg), "%s", text);
	rc = 0;
	if ((list = strdup(mc->tg_chats)) == NULL)
		abort();
	for (rest = list; (chat = strsep(&rest, " ,")) != NULL; ) {
		if (chat[0] == '\0')
			continue;
		ans = hosts_notify(uri, peer, name, mc->tg_token, chat, msg, &st);
		o = NULL;
		if (ans != NULL) {
			p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
			    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
			if (ucl_parser_add_string(p, ans, 0))
				o = ucl_parser_get_object(p);
			ucl_parser_free(p);
		}
		if (st != 200 || o == NULL || !ucl_object_toboolean(
		    ucl_object_lookup(o, "ok"))) {
			e = o != NULL ? ucl_object_lookup(o, "error") : NULL;
			if (e != NULL && ucl_object_type(e) == UCL_OBJECT)
				e = ucl_object_lookup(e, "message");
			snprintf(err, errlen, "chat %s, by %s: %s", chat, name,
			    e != NULL && ucl_object_type(e) == UCL_STRING ?
			    ucl_object_tostring(e) : "no answer");
			rc = -1;
		}
		if (o != NULL)
			ucl_object_unref(o);
		free(ans);
	}
	free(list);
	free(uri);
	free(peer);
	free(name);
	return (rc);
}

/* A message of the hour's on a way taken: false when they are gone. */
static bool
hour_slot(int ch)
{
	struct chan	*c = &chans[ch];
	time_t		 now;
	size_t		 i;

	now = time(NULL);
	pthread_mutex_lock(&lock);
	for (i = 0; i < MAIL_HOUR_MAX; i++)
		if (now - c->sent_at[i] >= 3600) {
			c->sent_at[i] = now;
			pthread_mutex_unlock(&lock);
			return (true);
		}
	pthread_mutex_unlock(&lock);
	return (false);
}

/*
 * A message sent now, not held: by mail, by Telegram, or both (how is
 * "mail", "telegram" or "all"), each that is set up, within its hour's
 * twenty; for a workflow's notify step.  0 when every way it was to go
 * took it; 1 when some did, what did not in err; -1 when none did.
 */
int
alert_send(const char *how, const char *subject, const char *text, char *err,
    size_t errlen)
{
	struct mailconf	 mc;
	char		 one[300], *msg;
	int		 ch, sent, failed;
	bool		 want;

	mc_load(&mc);
	sent = failed = 0;
	err[0] = '\0';
	for (ch = 0; ch < CH_N; ch++) {
		want = strcmp(how, "all") == 0 || strcmp(how, ch == CH_MAIL ?
		    "mail" : "telegram") == 0;
		if (!want || !chan_on(&mc, ch))
			continue;
		one[0] = '\0';
		if (!hour_slot(ch))
			snprintf(one, sizeof(one), "its twenty of the hour went "
			    "out already");
		else if (ch == CH_MAIL)
			(void)send_with(&mc, subject, text, one, sizeof(one));
		else {
			/* "Arcana: workflow w on h": a sign, and the rest. */
			if (asprintf(&msg, "%s %s\n\n%s", strstr(subject,
			    "approval") != NULL ? "⏳" : "🔔", strncmp(subject,
			    "Arcana: ", 8) == 0 ? subject + 8 : subject, text) == -1)
				abort();
			(void)tg_send(&mc, msg, one, sizeof(one));
			free(msg);
		}
		if (one[0] != '\0') {
			snprintf(err + strlen(err), errlen - strlen(err), "%s%s: "
			    "%s", err[0] != '\0' ? "; " : "", ch == CH_MAIL ?
			    "mail" : "Telegram", one);
			failed++;
		} else
			sent++;
	}
	if (sent == 0 && failed == 0)
		snprintf(err, errlen, "%s is not set up in Settings, "
		    "Notifications", strcmp(how, "mail") == 0 ? "mail" :
		    strcmp(how, "telegram") == 0 ? "Telegram" : "neither mail "
		    "nor Telegram");
	mc_free(&mc);
	return (sent == 0 ? -1 : failed > 0 ? 1 : 0);
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

/*
 * The notices as Telegram shows them: plain text (the agent sends no
 * parse mode), a sign first so a glance says what it is, the host
 * next, then what and when on lines of their own.
 */
static const char *
tg_sign(const char *severity)
{

	if (severity == NULL)
		return ("⚪");
	if (strcasecmp(severity, "Critical") == 0)
		return ("🔴");
	if (strcasecmp(severity, "Major") == 0)
		return ("🟠");
	if (strcasecmp(severity, "Minor") == 0)
		return ("🟡");
	return ("🔵");
}

static void
tg_fault(const char *when, const char *host, const ucl_object_t *d, int min)
{
	const char	*desc = str(d, "description");

	if (strcmp(str(d, "state") != NULL ? str(d, "state") : "",
	    "cleared") == 0 || strcmp(str(d, "severity") != NULL ? str(d,
	    "severity") : "", "Cleared") == 0)
		hold(CH_TELEGRAM, "✅ %s · cleared\n%s of %s\n🕒 %s", host,
		    str(d, "type"), str(d, "object"), when);
	else if (severity_rank(str(d, "severity")) >= min)
		hold(CH_TELEGRAM, "%s %s · %s fault\n%s of %s%s%s\n🕒 %s",
		    tg_sign(str(d, "severity")), host, str(d, "severity"),
		    str(d, "type"), str(d, "object"), desc != NULL &&
		    desc[0] != '\0' ? "\n" : "", desc != NULL ? desc : "",
		    when);
}

static void
tg_job(const char *when, const char *host, const ucl_object_t *d,
    const char *error, const char *jobs)
{
	bool	ok = ucl_object_toboolean(ucl_object_lookup(d, "ok"));

	if (!ok && strstr(error, "could not be undone") != NULL)
		hold(CH_TELEGRAM, "🚨 %s · job %s not confirmed, not undone\n"
		    "The host is left changed.\n%s\n⚠️ %s\n🕒 %s", host,
		    str(d, "id"), str(d, "title"), error, when);
	else if (strcmp(jobs, "none") == 0)
		return;
	else if (ok) {
		if (strcmp(jobs, "all") == 0)
			hold(CH_TELEGRAM, "✅ %s · job %s done\n%s\n🕒 %s", host,
			    str(d, "id"), str(d, "title"), when);
	} else
		hold(CH_TELEGRAM, "❌ %s · job %s failed\n%s\n⚠️ %s\n🕒 %s",
		    host, str(d, "id"), str(d, "title"), error, when);
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
	int			 min, ch;

	kind = str(e, "kind");
	d = ucl_object_lookup(e, "data");
	if (kind == NULL || d == NULL)
		return;
	t = (time_t)ucl_object_toint(ucl_object_lookup(e, "t"));
	localtime_r(&t, &tm);
	strftime(when, sizeof(when), "%H:%M:%S", &tm);
	/* Each way, as its own settings say. */
	for (ch = 0; ch < CH_N; ch++) {
		const char	*faults, *jobs;
		bool		 limits;

		if (!chan_on(mc, ch))
			continue;
		faults = ch == CH_MAIL ? mc->faults : mc->tg_faults;
		jobs = ch == CH_MAIL ? mc->jobs : mc->tg_jobs;
		limits = ch == CH_MAIL ? mc->limits : mc->tg_limits;
		if (strcmp(kind, "sdwan-fault") == 0) {
			min = severity_rank(faults);
			if (min < 0)
				continue;
			if (ch == CH_TELEGRAM) {
				tg_fault(when, host, d, min);
				continue;
			}
			if (strcmp(str(d, "state") != NULL ? str(d, "state") :
			    "", "cleared") == 0 || strcmp(str(d, "severity") !=
			    NULL ? str(d, "severity") : "", "Cleared") == 0)
				hold(ch, "%s %s: cleared: %s of %s", when, host,
				    str(d, "type"), str(d, "object"));
			else if (severity_rank(str(d, "severity")) >= min)
				hold(ch, "%s %s: fault, %s: %s of %s: %s", when,
				    host, str(d, "severity"), str(d, "type"),
				    str(d, "object"), str(d, "description") !=
				    NULL ? str(d, "description") : "");
		} else if (strcmp(kind, "threshold") == 0 && limits) {
			if (ch == CH_TELEGRAM) {
				bool	over = ucl_object_toboolean(ucl_object_lookup(d,
				    "over"));

				hold(ch, "%s %s · %s%s%s %s its limit\n%s, the limit %s\n"
				    "🕒 %s", over ? "📈" : "📉", host, str(d, "what"),
				    str(d, "name") != NULL ? " " : "", str(d, "name") !=
				    NULL ? str(d, "name") : "", over ? "over" :
				    "back under", str(d, "value"), str(d, "limit"), when);
				continue;
			}
			hold(ch, "%s %s: %s%s%s %s its limit: %s, the limit %s",
			    when, host, str(d, "what"), str(d, "name") != NULL ?
			    " " : "", str(d, "name") != NULL ? str(d, "name") :
			    "", ucl_object_toboolean(ucl_object_lookup(d,
			    "over")) ? "over" : "back under", str(d, "value"),
			    str(d, "limit"));
		} else if (strcmp(kind, "job") == 0) {
			const char	*error = str(d, "error") != NULL ?
			    str(d, "error") : "failed";

			/* A safe change that could not be taken back is an
			 * alert whatever the settings say of jobs: the host
			 * is left changed and unconfirmed. */
			if (ch == CH_TELEGRAM) {
				tg_job(when, host, d, error, jobs);
				continue;
			}
			if (!ucl_object_toboolean(ucl_object_lookup(d, "ok")) &&
			    strstr(error, "could not be undone") != NULL)
				hold(ch, "%s %s: ALERT: job %s was not confirmed "
				    "and could not be undone, the host is left "
				    "changed: %s: %s", when, host, str(d, "id"),
				    str(d, "title"), error);
			else if (strcmp(jobs, "none") == 0)
				continue;
			else if (ucl_object_toboolean(ucl_object_lookup(d,
			    "ok"))) {
				if (strcmp(jobs, "all") == 0)
					hold(ch, "%s %s: job %s done: %s", when,
					    host, str(d, "id"), str(d, "title"));
			} else
				hold(ch, "%s %s: job %s failed: %s: %s", when,
				    host, str(d, "id"), str(d, "title"), error);
		}
	}
}

/* A workflow's run, as it ends: held on each way that tells runs. */
void
mail_run(const char *workflow, unsigned int run, const char *state)
{
	struct mailconf	 mc;
	const char	*runs;
	bool		 ok, any;
	int		 ch;

	ok = strcmp(state, "done") == 0;
	mc_load(&mc);
	any = false;
	for (ch = 0; ch < CH_N; ch++) {
		runs = ch == CH_MAIL ? mc.runs : mc.tg_runs;
		if (!chan_on(&mc, ch) || strcmp(runs, "none") == 0 || (ok &&
		    strcmp(runs, "all") != 0))
			continue;
		if (ch == CH_TELEGRAM)
			hold(ch, "🔁 workflow %s · run %u\n%s %s", workflow, run, ok ?
			    "✅" : strcmp(state, "failed") == 0 ? "❌" : strcmp(state,
			    "cancelled") == 0 ? "⏹️" : "ℹ️", state);
		else
			hold(ch, "workflow %s, run %u: %s", workflow, run, state);
		any = true;
	}
	mc_free(&mc);
	/* A run ends in a thread of its own: its message goes out from
	 * here when the worker that runs workflows reads no events. */
	if (any)
		mail_flush();
}

/* What is held, sent: one message on each way, within its hour's. */
void
mail_flush(void)
{
	struct chan	*c;
	struct mailconf	 mc;
	char		*body, *msg, subject[200], err[300];
	const char	*nl;
	time_t		 now;
	size_t		 i, lines, free_slot;
	int		 ch;

	for (ch = 0; ch < CH_N; ch++) {
		c = &chans[ch];
		pthread_mutex_lock(&lock);
		if (c->nheld == 0) {
			pthread_mutex_unlock(&lock);
			continue;
		}
		now = time(NULL);
		free_slot = MAIL_HOUR_MAX;
		for (i = 0; i < MAIL_HOUR_MAX; i++)
			if (now - c->sent_at[i] >= 3600) {
				free_slot = i;
				break;
			}
		if (free_slot == MAIL_HOUR_MAX) {
			pthread_mutex_unlock(&lock);
			continue;		/* the next hour's */
		}
		c->sent_at[free_slot] = now;
		if ((body = strdup(c->held)) == NULL)
			abort();
		lines = c->held_lines;
		c->nheld = 0;
		c->held_lines = 0;
		c->held[0] = '\0';
		pthread_mutex_unlock(&lock);
		if (lines == 1) {
			nl = strchr(body, '\n');
			snprintf(subject, sizeof(subject), "Arcana: %.*s",
			    (int)(nl != NULL ? nl - body : (ptrdiff_t)strlen(
			    body)), body);
		} else
			snprintf(subject, sizeof(subject), "Arcana: %zu things "
			    "happened", lines);
		if (ch == CH_MAIL) {
			if (mail_send(subject, body, err, sizeof(err)) != 0)
				thread_log(LOG_WARNING, "mail: not sent: %s",
				    err);
		} else {
			mc_load(&mc);
			/* A heading, how many, then each, a blank line
			 * between. */
			for (i = strlen(body); i > 0 && body[i - 1] == '\n'; i--)
				body[i - 1] = '\0';
			if ((lines == 1 ? asprintf(&msg, "🛰️ Arcana\n\n%s", body) :
			    asprintf(&msg, "🛰️ Arcana · %zu events\n\n%s", lines,
			    body)) == -1)
				abort();
			if (tg_send(&mc, msg, err, sizeof(err)) != 0)
				thread_log(LOG_WARNING, "telegram: not sent: %s",
				    err);
			free(msg);
			mc_free(&mc);
		}
		free(body);
	}
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
	struct hostref		*all;
	struct cursor		*c;
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*data, *e;
	ucl_object_iter_t	 it;
	char			*name, *uri, *peer, *ans;
	struct mailconf		 mc;
	int			 i, n, st;
	bool			 fresh;

	mc_load(&mc);
	if (!chan_on(&mc, CH_MAIL) && !chan_on(&mc, CH_TELEGRAM)) {
		ncursors = 0;		/* when it is set, from then on */
		mc_free(&mc);
		return;
	}
	/* The servers as the worker copied them: the table is its own. */
	if ((all = calloc(MAIL_HOSTS, sizeof(*all))) == NULL)
		abort();
	n = host_refs_get(all, MAIL_HOSTS);
	for (i = 0; i < n; i++) {
		name = all[i].name;
		uri = all[i].uri;
		peer = all[i].peer[0] != '\0' ? all[i].peer : NULL;
		if ((c = cursor_of(all[i].id, &fresh)) == NULL)
			continue;
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
	}
	free(all);
	mail_flush();
}

static void *
watcher(void *arg __unused)
{

	for (;;) {
		sleep((unsigned int)cfg.mail_tick);
		/* Of a cluster, the leader's alone: one mail, not one a
		 * node. */
		if (cluster_leads())
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
	char		 err[300], to[1024], body[600];

	if (!guard(req, true))
		return (WEB_OK);
	mc_load(&mc);
	recipients(&mc, to, sizeof(to));
	snprintf(body, sizeof(body), "This mail says the console's mail "
	    "reaches you.\n\nIt was sent %s; faults, limits crossed, jobs and "
	    "workflow runs come the same way, as Settings, Notifications "
	    "says.\n", "by sendmail(8) on the console's host");
	mc_free(&mc);
	err[0] = '\0';
	if (mail_send("Arcana: a test", body, err, sizeof(err)) != 0)
		return (reply_error(req, 502, "not-sent", "%s", err));
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_frombool(true), "ok", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(to), "to", 0, false);
	return (reply_json(req, 200, o));
}

/*
 * POST /api/settings/telegram-test: a message to say Telegram reaches
 * the chats, sent by the host Settings name (a task: an agent is asked).
 */
struct tgtest {
	struct task task;		/* first */
	int		 rc;
	char		 err[400];
	char		 chats[512];
};

static int
tgtest_run(struct task *t)
{
	struct tgtest	*tt = (struct tgtest *)t;
	struct mailconf	 mc;

	mc_load(&mc);
	snprintf(tt->chats, sizeof(tt->chats), "%s", mc.tg_chats);
	tt->rc = tg_send(&mc, "🛰️ Arcana: a test.\n\n✅ This message says the "
	    "console's alerts reach this chat: faults, limits crossed, jobs "
	    "and workflow runs come the same way, as Settings, Notifications "
	    "says.", tt->err, sizeof(tt->err));
	mc_free(&mc);
	return (WEB_OK);
}

int
api_telegram_test(struct http_request *req)
{
	struct tgtest	*tt;
	ucl_object_t	*o;

	if ((tt = req->hdlr_extra) != NULL) {
		if (task_state(&tt->task) != TASK_STATE_FINISHED) {
			http_request_sleep(req);
			return (WEB_RETRY);
		}
		if (tt->rc != 0)
			return (reply_error(req, 502, "not-sent", "%s", tt->err));
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_frombool(true), "ok", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(tt->chats), "to",
		    0, false);
		return (reply_json(req, 200, o));
	}
	if (!guard(req, true))
		return (WEB_OK);
	/* The servers as they are now, for the task: one just added. */
	host_refs();
	tt = xcalloc(1, sizeof(*tt));
	req->hdlr_extra = tt;
	task_create(&tt->task, tgtest_run);
	task_bind_request(&tt->task, req);
	task_run(&tt->task);
	return (WEB_RETRY);
}

void
api_telegram_test_free(struct http_request *req)
{
	struct tgtest	*tt = req->hdlr_extra;

	/* Asked while the task runs too: only once it is done. */
	if (tt == NULL || !task_finished(&tt->task))
		return;
	task_destroy(&tt->task);
	free(tt);
	req->hdlr_extra = NULL;
}
