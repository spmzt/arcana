/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the kernel's messages as they come.  The message buffer
 * (kern.msgbuf) is a ring that only grows at its end: a thread of its
 * own reads it every second, finds where it was by the end of what it
 * read before, and takes what follows as new.  Each line is numbered,
 * and the last of them kept, so that @dmesg is followed by its number,
 * as a file is by its position, none missed and none twice; and each
 * is an event (kind kmsg) the moment it is seen.
 *
 * A program that crashed is an event of its own (kind crash): the line
 * the kernel writes for a process ended by a signal that dumps core,
 * SIGSEGV, SIGABRT, SIGBUS and their kin (kern.logsigexit, on unless
 * set off), "pid 812 (nginx), jid 0, uid 80: exited on signal 11 (core
 * dumped)", taken apart: the process's name, its jail, the signal, and
 * why there is no core when there is none ("no core dump - sugid
 * process denied by kern.sugid_coredump": a daemon that set its group,
 * as bird -g does).  It is a fault too (crash, Major, of host:bird or
 * jail:web/nginx), since events come by the hundred and a program that
 * dies three times a night is what a page of faults and a mail are
 * for: the fault says the signal by name, how many times in the day,
 * and the kernel's reason; said anew at each crash, and cleared after
 * an hour without one.
 *
 * A line not finished yet is left for the next read.  When the end of
 * the last read is no longer there (more was written in a second than
 * the ring holds, or it was cleared), all of it is taken as new.
 */

#include <sys/param.h>
#include <sys/sysctl.h>

#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <jail.h>

#include "agent.h"

#define	KMSG_KEPT	1000		/* lines kept, to be read again */
#define	KMSG_TAIL	256		/* bytes of the last read, to find it */
#define	KMSG_EVENTS	20		/* events a read makes at most */
#define	KMSG_LINE	1024
#define	CRASH_MAX	64		/* programs whose crashes are counted */
#define	CRASH_TIMES	64		/* of each, the last ones' times */
#define	CRASH_DAY	(24 * 3600)	/* how long a crash counts */
#define	CRASH_QUIET	3600		/* without one, the fault is cleared */

/* A program's crashes of the day, by what the fault is of. */
struct crashes {
	char	object[128];		/* host:bird, jail:web/nginx */
	char	comm[MAXCOMLEN + 2];
	time_t	times[CRASH_TIMES];	/* oldest first */
	int	ntimes;
	bool	beyond;			/* more in the day than kept */
};

struct kline {
	uint64_t	 n;
	time_t		 t;		/* when seen; 0, before the agent */
	char		*text;
};

static pthread_mutex_t	km_lock = PTHREAD_MUTEX_INITIALIZER;
static struct kline	km_ring[KMSG_KEPT];
static size_t		km_first, km_count;
static uint64_t		km_last;	/* the number of the newest */
static char		km_tail[KMSG_TAIL];
static size_t		km_taillen;
static bool		km_running;
static bool		km_readable;	/* the last read was let */
static struct crashes	cr[CRASH_MAX];	/* under km_lock */
static int		ncr;

/* The buffer, without the priorities "<6>" that dmesg(8) leaves out. */
static char *
msgbuf(size_t *lenp)
{
	char	*buf, *p, *q;
	size_t	 len, n;

	len = 0;
	if (sysctlbyname("kern.msgbuf", NULL, &len, NULL, 0) == -1 ||
	    (buf = calloc(1, len + 1)) == NULL)
		return (NULL);
	if (sysctlbyname("kern.msgbuf", buf, &len, NULL, 0) == -1) {
		free(buf);
		return (NULL);
	}
	for (p = q = buf; p < buf + len; ) {
		/* "<6>", "<118>": one to three digits. */
		if ((p == buf || p[-1] == '\n') && p[0] == '<' &&
		    (n = strspn(p + 1, "0123456789")) >= 1 && n <= 3 &&
		    p[1 + n] == '>') {
			p += n + 2;
			continue;
		}
		*q++ = *p++;
	}
	*q = '\0';
	*lenp = (size_t)(q - buf);
	return (buf);
}

/* The last place the old tail is found at in buf, or NULL. */
static const char *
find_tail(const char *buf, size_t len)
{
	const char	*p, *found;

	if (km_taillen == 0 || km_taillen > len)
		return (NULL);
	found = NULL;
	for (p = buf; (p = memmem(p, (size_t)(buf + len - p), km_tail,
	    km_taillen)) != NULL; p++)
		found = p;
	return (found);
}

/* A signal's name, SIGBUS; or its number, when it has none. */
static const char *
signame(int sig, char *buf, size_t len)
{
	size_t	i;

	if (sig <= 0 || sig >= sys_nsig || sys_signame[sig] == NULL) {
		snprintf(buf, len, "signal %d", sig);
		return (buf);
	}
	snprintf(buf, len, "SIG%s", sys_signame[sig]);
	for (i = 3; buf[i] != '\0'; i++)
		buf[i] = (char)toupper((unsigned char)buf[i]);
	return (buf);
}

/*
 * The program's crashes of the day, one more at now: those of a day
 * ago dropped, the newest kept at the end.  Its record, made when it
 * has none; NULL when there is no room for another program's.
 */
static struct crashes *
crash_note(const char *object, const char *comm, time_t now)
{
	struct crashes	*c;
	int		 i, old;

	for (i = 0; i < ncr && strcmp(cr[i].object, object) != 0; i++)
		;
	if (i == ncr) {
		if (ncr == CRASH_MAX)
			return (NULL);
		c = &cr[ncr++];
		memset(c, 0, sizeof(*c));
		snprintf(c->object, sizeof(c->object), "%s", object);
		snprintf(c->comm, sizeof(c->comm), "%s", comm);
	}
	c = &cr[i];
	for (old = 0; old < c->ntimes && c->times[old] <= now - CRASH_DAY;
	    old++)
		;
	if (old > 0) {
		memmove(c->times, c->times + old, sizeof(c->times[0]) *
		    (size_t)(c->ntimes - old));
		c->ntimes -= old;
		c->beyond = false;
	}
	if (c->ntimes == CRASH_TIMES) {
		memmove(c->times, c->times + 1, sizeof(c->times[0]) *
		    (CRASH_TIMES - 1));
		c->ntimes--;
		c->beyond = true;
	}
	c->times[c->ntimes++] = now;
	return (c);
}

/*
 * A process's crash, as the kernel says it, at now: an event of its
 * own, and the fault of its program set, or said anew.  false for a
 * line that is not one.  Under km_lock.
 */
bool
kmsg_crash_line(const char *text, time_t now)
{
	struct crashes	*c;
	const char	*p, *reason;
	char		 comm[MAXCOMLEN + 2], *jname, object[128], sig_s[24],
			 reason_s[160], descr[200];
	int		 pid, jid, uid, sig, n;
	bool		 core;

	n = 0;
	if (sscanf(text, "pid %d (%" __XSTRING(MAXCOMLEN) "[^)]), jid %d, "
	    "uid %d: exited on signal %d%n", &pid, comm, &jid, &uid, &sig,
	    &n) != 5 || n == 0)
		return (false);
	p = text + n;
	core = strncmp(p, " (core dumped)", 14) == 0;
	/* "(no core dump - bad address)": the kernel's reason, as far as
	 * its closing parenthesis. */
	reason = NULL;
	if (strncmp(p, " (no core dump - ", 17) == 0) {
		p += 17;
		snprintf(reason_s, sizeof(reason_s), "%.*s", (int)strcspn(p,
		    ")"), p);
		reason = reason_s;
	}
	/* A name of the jail's, when it still has one. */
	jname = jid > 0 ? jail_getname(jid) : NULL;
	/* A process's name is the kernel's: no quote or backslash in it
	 * is taken; nor in the reason, which is the kernel's too. */
	if (strpbrk(comm, "\"\\") != NULL || (jname != NULL &&
	    strpbrk(jname, "\"\\") != NULL) || (reason != NULL &&
	    strpbrk(reason, "\"\\") != NULL)) {
		free(jname);
		return (true);
	}
	event_add("crash", "{\"pid\":%d,\"process\":\"%s\",\"jid\":%d,"
	    "\"jail\":\"%s\",\"uid\":%d,\"signal\":%d,\"core\":%s%s%s%s}", pid,
	    comm, jid, jname != NULL ? jname : "", uid, sig, core ? "true" :
	    "false", reason != NULL ? ",\"reason\":\"" : "", reason != NULL ?
	    reason : "", reason != NULL ? "\"" : "");
	if (jid > 0 && jname != NULL)
		snprintf(object, sizeof(object), "jail:%s/%s", jname, comm);
	else if (jid > 0)
		snprintf(object, sizeof(object), "jail:%d/%s", jid, comm);
	else
		snprintf(object, sizeof(object), "host:%s", comm);
	free(jname);
	if ((c = crash_note(object, comm, now)) == NULL)
		return (true);
	snprintf(descr, sizeof(descr), "%s died of %s (pid %d), %s%d time%s "
	    "in 24 h; %s%s%s", comm, signame(sig, sig_s, sizeof(sig_s)), pid,
	    c->beyond ? "at least " : "", c->ntimes, c->ntimes == 1 ? "" :
	    "s", core ? "a core was dumped" : "no core", reason != NULL ?
	    ": " : "", reason != NULL ? reason : "");
	if (!fault_update("crash", object, "%s", descr))
		fault_set("crash", "Major", object, "kernel", "%s", descr);
	return (true);
}

/*
 * The faults of the programs that ran an hour without crashing
 * cleared, their records dropped.  Under km_lock.
 */
void
kmsg_crash_sweep(time_t now)
{
	int	i;

	for (i = 0; i < ncr; ) {
		if (cr[i].times[cr[i].ntimes - 1] > now - CRASH_QUIET) {
			i++;
			continue;
		}
		fault_clear("crash", cr[i].object, "%s ran an hour without "
		    "crashing", cr[i].comm);
		memmove(&cr[i], &cr[i + 1], sizeof(cr[0]) * (size_t)(ncr - i -
		    1));
		ncr--;
	}
}

/* One line more: kept, numbered, and an event if events are wanted. */
static void
add_line(const char *s, size_t n, time_t t, int *events, int *more)
{
	struct kline	*k;
	char		*text, *json, *q;
	size_t		 i;

	if (n > KMSG_LINE)
		n = KMSG_LINE;
	if ((text = strndup(s, n)) == NULL)
		return;
	/* What a terminal would act on is left out. */
	for (i = 0; text[i] != '\0'; i++)
		if ((unsigned char)text[i] < 0x20 && text[i] != '\t')
			text[i] = ' ';
	if (km_count == KMSG_KEPT) {
		free(km_ring[km_first].text);
		km_first = (km_first + 1) % KMSG_KEPT;
		km_count--;
	}
	k = &km_ring[(km_first + km_count) % KMSG_KEPT];
	k->n = ++km_last;
	k->t = t;
	k->text = text;
	km_count++;
	if (events == NULL)
		return;
	(void)kmsg_crash_line(text, t);
	if (*events >= KMSG_EVENTS) {
		(*more)++;
		return;
	}
	(*events)++;
	/* The text as a JSON string. */
	if ((json = malloc(strlen(text) * 6 + 1)) == NULL)
		return;
	for (q = json, i = 0; text[i] != '\0'; i++) {
		if (text[i] == '"' || text[i] == '\\') {
			*q++ = '\\';
			*q++ = text[i];
		} else if (text[i] == '\t') {
			*q++ = '\\';
			*q++ = 't';
		} else
			*q++ = text[i];
	}
	*q = '\0';
	event_add("kmsg", "{\"seq\":%ju,\"text\":\"%s\"}", (uintmax_t)k->n,
	    json);
	free(json);
}

/*
 * One read: the lines after the end of the last, each finished one
 * kept; first is the read at start, whose lines came before the agent
 * and are not events.
 */
static void
kmsg_read(bool first)
{
	const char	*from, *p, *e, *end;
	char		*buf;
	size_t		 len, keep;
	time_t		 now;
	int		 events, more;

	if ((buf = msgbuf(&len)) == NULL) {
		/* Not root, and not let read (unprivileged_read_msgbuf). */
		pthread_mutex_lock(&km_lock);
		km_readable = false;
		pthread_mutex_unlock(&km_lock);
		return;
	}
	/* What is not a whole line yet waits for the next read. */
	end = buf + len;
	while (end > buf && end[-1] != '\n')
		end--;
	pthread_mutex_lock(&km_lock);
	km_readable = true;
	from = find_tail(buf, (size_t)(end - buf));
	from = from != NULL ? from + km_taillen : buf;
	now = time(NULL);
	events = more = 0;
	for (p = from; p < end; p = e + 1) {
		e = memchr(p, '\n', (size_t)(end - p));
		if (e == NULL)
			break;
		if (e > p)
			add_line(p, (size_t)(e - p), first ? 0 : now, first ?
			    NULL : &events, &more);
	}
	if (more > 0)
		event_add("kmsg", "{\"seq\":%ju,\"more\":%d}", (uintmax_t)km_last,
		    more);
	/* The end of what was read, to be found in the next. */
	keep = (size_t)(end - buf) < KMSG_TAIL ? (size_t)(end - buf) :
	    KMSG_TAIL;
	if (keep > 0 || first) {
		memcpy(km_tail, end - keep, keep);
		km_taillen = keep;
	}
	pthread_mutex_unlock(&km_lock);
	free(buf);
}

static void *
reader(void *arg __unused)
{

	for (;;) {
		sleep(1);
		kmsg_read(false);
		pthread_mutex_lock(&km_lock);
		kmsg_crash_sweep(time(NULL));
		pthread_mutex_unlock(&km_lock);
	}
	return (NULL);
}

void
kmsg_start(void)
{
	pthread_t	tid;
	int		error;

	kmsg_read(true);
	if ((error = pthread_create(&tid, NULL, reader, NULL)) != 0) {
		logmsg(LOG_WARNING, "the kernel's messages are not followed: "
		    "pthread_create: %s", strerror(error));
		return;
	}
	(void)pthread_detach(tid);
	pthread_mutex_lock(&km_lock);
	km_running = true;
	pthread_mutex_unlock(&km_lock);
}

/*
 * The lines kept with a number after after, the last max of them,
 * those with filter in them only when it is given; *lastp the number
 * of the newest, to ask after next.  false when nothing is followed.
 */
bool
kmsg_lines(struct work *w, uint64_t after, const char *filter, uint32_t max,
    struct kmsg_line **vp, size_t *np, uint64_t *lastp)
{
	struct kmsg_line	*v;
	struct kline		*k;
	size_t			 i, n, skip;

	pthread_mutex_lock(&km_lock);
	if (!km_running || !km_readable) {
		pthread_mutex_unlock(&km_lock);
		return (false);
	}
	v = wcalloc(w, km_count + 1, sizeof(*v));
	for (i = n = 0; i < km_count; i++) {
		k = &km_ring[(km_first + i) % KMSG_KEPT];
		if (k->n <= after || (filter != NULL && filter[0] != '\0' &&
		    strcasestr(k->text, filter) == NULL))
			continue;
		v[n].n = k->n;
		v[n].t = k->t;
		v[n].text = wstrdup(w, k->text);
		n++;
	}
	*lastp = km_last;
	pthread_mutex_unlock(&km_lock);
	skip = max > 0 && n > max ? n - max : 0;
	*vp = v + skip;
	*np = n - skip;
	return (true);
}
