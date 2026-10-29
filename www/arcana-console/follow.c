/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's events as they happen, to a page: on the stream's WebSocket
 * the page asks
 *
 *	{"id": 9, "server": "<id>", "what": "events"}
 *
 * and is told, for that id, each event the host tells its subscribers
 * (arcana-events' event notifications, each made the JSON the events
 * reply has: ygula.c),
 *
 *	{"id": 9, "event": {"n": 41, "t": 1791234567, "kind": ..., ...}}
 *
 * until it says {"id": 9, "stop": true} or goes; {"id": 9, "error":
 * "why"} when the host is gone, and the page then reads them as before.
 *
 * The host's events are subscribed once, for each user that follows
 * them, on the console's connection for the host's subscriptions
 * (watch.c), whose thread puts each event in the queue of every page
 * following the host for that user (follow_told()); a timer of the
 * worker's empties the queues into the sockets, which only the worker
 * may write to.  An agent that has no such subscription (one of the
 * release before) is followed as it was before: by a thread of the
 * follow's own, on a connection nothing else uses, subscribed to family
 * 1's group notify.
 */

#include <sys/param.h>
#include <sys/queue.h>

#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "console.h"
#include "ygula.h"

#define	FOLLOW_MAX	32		/* at once, on all sockets */
#define	FOLLOW_QUEUE	256		/* events not yet passed on, at most */
#define	FOLLOW_TICK_MS	50		/* how soon one is passed on */
#define	FOLLOW_WAKE_MS	250		/* how soon a stop is seen */

struct said {
	STAILQ_ENTRY(said)	 next;
	char			*text;
};

struct follow {
	LIST_ENTRY(follow)	 list;
	struct conn	*c;	/* NULL once the socket is gone */
	uint64_t		 id;
	char			 sid[9];
	char			 user[64];	/* the socket's, "": the console */
	char			*uri;
	char			*peer;
	bool			 own;	/* followed by a thread of its own */
	pthread_t		 thread;
	atomic_bool		 stop;
	atomic_bool		 ended;	/* the thread is done, or the host */
	pthread_mutex_t		 lock;
	STAILQ_HEAD(, said)	 queue;
	int			 queued;
	bool			 lost;	/* some were dropped: the page was slow */
};

/* The list is the worker's to change, follow_lock held; the watches'
 * threads go through it under the lock. */
static LIST_HEAD(, follow)	follows = LIST_HEAD_INITIALIZER(follows);
static pthread_mutex_t		follow_lock = PTHREAD_MUTEX_INITIALIZER;
static int			nfollows;
static struct timer		*ticker;

/* Something for the page, queued. */
static void
tell(struct follow *f, char *text)
{
	struct said	*s;

	if (text == NULL)
		return;
	pthread_mutex_lock(&f->lock);
	if (f->queued >= FOLLOW_QUEUE) {
		f->lost = true;
		pthread_mutex_unlock(&f->lock);
		free(text);
		return;
	}
	if ((s = malloc(sizeof(*s))) == NULL) {
		pthread_mutex_unlock(&f->lock);
		free(text);
		return;
	}
	s->text = text;
	STAILQ_INSERT_TAIL(&f->queue, s, next);
	f->queued++;
	pthread_mutex_unlock(&f->lock);
}

/* In a watch's thread: an event host sid told for user, to each page
 * that follows it so. */
void
follow_told(const char *sid, const char *user, const char *json)
{
	struct follow	*f;
	char		*text;

	pthread_mutex_lock(&follow_lock);
	LIST_FOREACH(f, &follows, list) {
		if (f->own || atomic_load(&f->ended) || strcmp(f->sid, sid) !=
		    0 || strcmp(f->user, user) != 0)
			continue;
		if (asprintf(&text, "{\"id\":%ju,\"event\":%s}",
		    (uintmax_t)f->id, json) == -1)
			text = NULL;
		tell(f, text);
	}
	pthread_mutex_unlock(&follow_lock);
}

/* In a watch's thread: host sid gone, why; its follows end. */
void
follow_gone(const char *sid, const char *why)
{
	struct follow	*f;
	char		*text;

	pthread_mutex_lock(&follow_lock);
	LIST_FOREACH(f, &follows, list) {
		if (f->own || atomic_load(&f->ended) || strcmp(f->sid, sid) !=
		    0)
			continue;
		if (asprintf(&text, "{\"id\":%ju,\"error\":\"%s\"}",
		    (uintmax_t)f->id, why) == -1)
			text = NULL;
		tell(f, text);
		atomic_store(&f->ended, true);
	}
	pthread_mutex_unlock(&follow_lock);
}

/* An agent before: a notification of the host's models, its events
 * alone passed on. */
static void
heard(cbl_conn *conn, cbl_msg *msg, void *arg)
{
	struct follow	*f = arg;
	ucl_object_t	*o;
	unsigned char	*json;
	char		*text;

	(void)conn;
	if ((o = ygula_event_of(msg)) == NULL)
		return;
	json = ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	if (json == NULL)
		return;
	if (asprintf(&text, "{\"id\":%ju,\"event\":%s}", (uintmax_t)f->id,
	    (char *)json) == -1)
		text = NULL;
	free(json);
	tell(f, text);
}

/* An agent before: the follow's own thread and connection. */
static void *
follow_run(void *arg)
{
	struct follow	*f = arg;
	struct pollfd	 pfd;
	cbl_conn	*conn;
	cbl_tls		*tls;
	cbl_sub		*sub;
	const char	*msg;
	char		*text;
	int		 error, ev, ms;

	if ((msg = hosts_connect(f->uri, f->peer, &conn, &tls)) != NULL) {
		thread_log(LOG_NOTICE, "events %s: %s", f->sid, msg);
		if (asprintf(&text, "{\"id\":%ju,\"error\":\"the host does not "
		    "answer\"}", (uintmax_t)f->id) != -1)
			tell(f, text);
		atomic_store(&f->ended, true);
		return (NULL);
	}
	if ((error = cbl_subscribe(conn, "cblink.yang", "notify", heard, f,
	    &sub)) != 0) {
		if (asprintf(&text, "{\"id\":%ju,\"error\":\"the host refused: "
		    "%s\"}", (uintmax_t)f->id, strerror(error)) != -1)
			tell(f, text);
		hosts_release(f->uri, f->peer, conn, tls, false);
		atomic_store(&f->ended, true);
		return (NULL);
	}
	error = 0;
	while (!atomic_load(&f->stop)) {
		ev = 0;
		ms = -1;
		(void)cbl_conn_interest(conn, &ev, &ms);
		pfd.fd = cbl_conn_fd(conn);
		pfd.events = ((ev & CBL_EV_READ) != 0 ? POLLIN : 0) |
		    ((ev & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
		pfd.revents = 0;
		if (poll(&pfd, 1, ms < 0 || ms > FOLLOW_WAKE_MS ?
		    FOLLOW_WAKE_MS : ms) == -1)
			continue;
		ev = ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0 ?
		    CBL_EV_READ : 0) | ((pfd.revents & POLLOUT) != 0 ?
		    CBL_EV_WRITE : 0);
		if ((error = cbl_conn_process(conn, ev)) != 0)
			break;
	}
	if (!atomic_load(&f->stop) && asprintf(&text, "{\"id\":%ju,\"error\":"
	    "\"the host stopped answering: %s\"}", (uintmax_t)f->id,
	    strerror(error)) != -1)
		tell(f, text);
	/* A connection with a subscription on it is no one else's. */
	hosts_release(f->uri, f->peer, conn, tls, false);
	atomic_store(&f->ended, true);
	return (NULL);
}

static void
follow_free(struct follow *f)
{
	struct said	*s;

	if (f->own)
		(void)pthread_join(f->thread, NULL);
	pthread_mutex_lock(&follow_lock);
	LIST_REMOVE(f, list);
	nfollows--;
	pthread_mutex_unlock(&follow_lock);
	while ((s = STAILQ_FIRST(&f->queue)) != NULL) {
		STAILQ_REMOVE_HEAD(&f->queue, next);
		free(s->text);
		free(s);
	}
	pthread_mutex_destroy(&f->lock);
	free(f->uri);
	free(f->peer);
	free(f);
}

/*
 * A follow on the host's subscription kept asked for; the host's own
 * answer to it: refused, by an agent before, followed by a thread of
 * its own; not made, said.
 */
static void
follow_keep(struct follow *f)
{
	char	*text;

	if (f->own || atomic_load(&f->ended) || atomic_load(&f->stop))
		return;
	switch (watch_events(f->sid, f->uri, f->peer, f->user)) {
	case WATCH_S_REFUSED:
		hosts_act_as(f->user);
		if (hosts_thread(&f->thread, follow_run, f) == 0)
			f->own = true;
		else {
			if (asprintf(&text, "{\"id\":%ju,\"error\":\"cannot "
			    "follow now: try again\"}", (uintmax_t)f->id) != -1)
				tell(f, text);
			atomic_store(&f->ended, true);
		}
		hosts_act_as(NULL);
		break;
	case WATCH_S_LOST:
		if (asprintf(&text, "{\"id\":%ju,\"error\":\"the host does not "
		    "answer\"}", (uintmax_t)f->id) != -1)
			tell(f, text);
		atomic_store(&f->ended, true);
		break;
	}
}

/* In the worker: what each follow heard, to its socket. */
static void
follow_tick(void *arg, u_int64_t now)
{
	struct follow	*f, *next;
	struct said	*s;
	STAILQ_HEAD(, said) q;
	char		 buf[96];
	bool		 lost;
	int		 n;

	(void)arg;
	(void)now;
	LIST_FOREACH_SAFE(f, &follows, list, next) {
		follow_keep(f);
		STAILQ_INIT(&q);
		pthread_mutex_lock(&f->lock);
		STAILQ_CONCAT(&q, &f->queue);
		f->queued = 0;
		lost = f->lost;
		f->lost = false;
		pthread_mutex_unlock(&f->lock);
		/* Some went past while the page was slow: it reads them. */
		if (lost && f->c != NULL) {
			n = snprintf(buf, sizeof(buf), "{\"id\":%ju,\"lost\":"
			    "true}", (uintmax_t)f->id);
			ws_send(f->c, WS_OP_TEXT, buf,
			    (size_t)n);
		}
		while ((s = STAILQ_FIRST(&q)) != NULL) {
			STAILQ_REMOVE_HEAD(&q, next);
			if (f->c != NULL)
				ws_send(f->c, WS_OP_TEXT,
				    s->text, strlen(s->text));
			free(s->text);
			free(s);
		}
		/* Stopped on the watch's: nothing to wait for. */
		if (!f->own && atomic_load(&f->stop))
			atomic_store(&f->ended, true);
		if (atomic_load(&f->ended))
			follow_free(f);
	}
	/* The ticker stays, follows or none. */
}

/* A page's ask for a host's events; NULL, or why it is refused. */
const char *
follow_start(struct conn *c, uint64_t id, const struct server *sv)
{
	struct follow	*f;

	if (nfollows >= FOLLOW_MAX)
		return ("too many are following events at once: try again");
	LIST_FOREACH(f, &follows, list)
		if (f->c == c && f->id == id)
			return ("that id follows already");
	f = xcalloc(1, sizeof(*f));
	f->c = c;
	f->id = id;
	strlcpy(f->sid, sv->id, sizeof(f->sid));
	strlcpy(f->user, c->hdlr_extra != NULL ? c->hdlr_extra : "",
	    sizeof(f->user));
	f->uri = xstrdup(sv->uri);
	f->peer = sv->peer_name != NULL ? xstrdup(sv->peer_name) : NULL;
	atomic_init(&f->stop, false);
	atomic_init(&f->ended, false);
	pthread_mutex_init(&f->lock, NULL);
	STAILQ_INIT(&f->queue);
	pthread_mutex_lock(&follow_lock);
	LIST_INSERT_HEAD(&follows, f, list);
	nfollows++;
	pthread_mutex_unlock(&follow_lock);
	/* Subscribed now, not at the first tick. */
	follow_keep(f);
	if (ticker == NULL)
		ticker = timer_add(follow_tick, FOLLOW_TICK_MS, NULL, 0);
	return (NULL);
}

/* The page's stop: of one id, or of all of a socket's when it went. */
bool
follow_stop(struct conn *c, uint64_t id, bool all)
{
	struct follow	*f;
	bool		 some;

	some = false;
	LIST_FOREACH(f, &follows, list)
		if (f->c == c && (all || f->id == id)) {
			if (all)
				f->c = NULL;
			atomic_store(&f->stop, true);
			some = true;
		}
	return (some);
}
