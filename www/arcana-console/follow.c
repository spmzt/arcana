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
 * and is told, for that id, each event the host tells its subscribers,
 *
 *	{"id": 9, "event": {"n": 41, "t": 1791234567, "kind": ..., ...}}
 *
 * until it says {"id": 9, "stop": true} or goes; {"id": 9, "error":
 * "why"} when the host is gone, and the page then reads them as before.
 *
 * Each is a thread of its own, not one of the tasks': a subscription
 * lasts as long as the page looks, and the tasks are few.  It drives
 * its own connection to the host, which nothing else uses, and puts
 * what it hears in a queue; a timer of the worker's empties the queues
 * into the sockets, which only the worker may write to.
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

#define	FOLLOW_MAX	32		/* at once, on all sockets */
#define	FOLLOW_QUEUE	256		/* events not yet passed on, at most */
#define	FOLLOW_TICK_MS	200		/* how soon one is passed on */
#define	FOLLOW_WAKE_MS	250		/* how soon a stop is seen */

struct said {
	STAILQ_ENTRY(said)	 next;
	char			*text;
};

struct follow {
	LIST_ENTRY(follow)	 list;
	struct connection	*c;	/* NULL once the socket is gone */
	uint64_t		 id;
	char			 sid[9];
	char			*uri;
	char			*peer;
	pthread_t		 thread;
	atomic_bool		 stop;
	atomic_bool		 ended;	/* the thread is done */
	pthread_mutex_t		 lock;
	STAILQ_HEAD(, said)	 queue;
	int			 queued;
	bool			 lost;	/* some were dropped: the page was slow */
};

static LIST_HEAD(, follow)	follows = LIST_HEAD_INITIALIZER(follows);
static int			nfollows;
static struct kore_timer	*ticker;

/* In the follow's thread: something for the page, queued. */
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

static void
heard(const struct arc_event_ntf *ntf, void *arg)
{
	struct follow	*f = arg;
	char		*text;

	if (ntf->json == NULL || ntf->json[0] != '{')
		return;
	if (asprintf(&text, "{\"id\":%ju,\"event\":%s}", (uintmax_t)f->id,
	    ntf->json) == -1)
		return;
	tell(f, text);
}

static void *
follow_run(void *arg)
{
	static const struct arc_events_handlers h = { .event = heard };
	struct follow	*f = arg;
	struct arc_client cl;
	struct pollfd	 pfd;
	cbl_conn	*conn;
	cbl_tls		*tls;
	cbl_sub		*sub;
	const char	*msg;
	char		*text;
	int		 error, ev, ms;

	if ((msg = hosts_connect(f->uri, f->peer, &conn, &tls, &cl)) != NULL) {
		thread_log(LOG_NOTICE, "events %s: %s", f->sid, msg);
		if (asprintf(&text, "{\"id\":%ju,\"error\":\"the host does not "
		    "answer\"}", (uintmax_t)f->id) != -1)
			tell(f, text);
		atomic_store(&f->ended, true);
		return (NULL);
	}
	if ((error = arc_events_subscribe(&cl, &h, f, &sub)) != 0) {
		if (asprintf(&text, "{\"id\":%ju,\"error\":\"the host refused: "
		    "%s\"}", (uintmax_t)f->id, strerror(error)) != -1)
			tell(f, text);
		hosts_release(f->uri, f->peer, conn, tls, &cl, false);
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
	hosts_release(f->uri, f->peer, conn, tls, &cl, false);
	atomic_store(&f->ended, true);
	return (NULL);
}

static void
follow_free(struct follow *f)
{
	struct said	*s;

	(void)pthread_join(f->thread, NULL);
	LIST_REMOVE(f, list);
	nfollows--;
	while ((s = STAILQ_FIRST(&f->queue)) != NULL) {
		STAILQ_REMOVE_HEAD(&f->queue, next);
		free(s->text);
		free(s);
	}
	pthread_mutex_destroy(&f->lock);
	kore_free(f->uri);
	kore_free(f->peer);
	kore_free(f);
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
			kore_websocket_send(f->c, WEBSOCKET_OP_TEXT, buf,
			    (size_t)n);
		}
		while ((s = STAILQ_FIRST(&q)) != NULL) {
			STAILQ_REMOVE_HEAD(&q, next);
			if (f->c != NULL)
				kore_websocket_send(f->c, WEBSOCKET_OP_TEXT,
				    s->text, strlen(s->text));
			free(s->text);
			free(s);
		}
		if (atomic_load(&f->ended))
			follow_free(f);
	}
	/*
	 * The ticker stays, follows or none: a timer taken out in its own
	 * callback is freed under kore_timer_run(), which puts it back in
	 * the list after (the worker died of it when the agent of a page
	 * following its events restarted, an update's).
	 */
}

/* A page's ask for a host's events; NULL, or why it is refused. */
const char *
follow_start(struct connection *c, uint64_t id, const struct server *sv)
{
	struct follow	*f;

	if (nfollows >= FOLLOW_MAX)
		return ("too many are following events at once: try again");
	LIST_FOREACH(f, &follows, list)
		if (f->c == c && f->id == id)
			return ("that id follows already");
	f = kore_calloc(1, sizeof(*f));
	f->c = c;
	f->id = id;
	strlcpy(f->sid, sv->id, sizeof(f->sid));
	f->uri = kore_strdup(sv->uri);
	f->peer = sv->peer_name != NULL ? kore_strdup(sv->peer_name) : NULL;
	atomic_init(&f->stop, false);
	atomic_init(&f->ended, false);
	pthread_mutex_init(&f->lock, NULL);
	STAILQ_INIT(&f->queue);
	if (pthread_create(&f->thread, NULL, follow_run, f) != 0) {
		pthread_mutex_destroy(&f->lock);
		kore_free(f->uri);
		kore_free(f->peer);
		kore_free(f);
		return ("cannot follow now: try again");
	}
	LIST_INSERT_HEAD(&follows, f, list);
	nfollows++;
	if (ticker == NULL)
		ticker = kore_timer_add(follow_tick, FOLLOW_TICK_MS, NULL, 0);
	return (NULL);
}

/* The page's stop: of one id, or of all of a socket's when it went. */
bool
follow_stop(struct connection *c, uint64_t id, bool all)
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
