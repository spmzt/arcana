/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: every jail's coming and going, told by the kernel (kqueue(2)'s
 * EVFILT_JAIL): a jail made is a child of the host's, NOTE_JAIL_CHILD
 * with its number; each is then watched for NOTE_JAIL_REMOVE.  Each is
 * an event, jail-state, with the jail's name and "running" or
 * "stopped", as it happens: nothing has to look again to see it.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/jail.h>
#include <sys/queue.h>

#include <errno.h>
#include <jail.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

struct wj {
	LIST_ENTRY(wj)	 list;
	int		 jid;
	char		*name;
};

static LIST_HEAD(, wj)	jails = LIST_HEAD_INITIALIZER(jails);

static void
told(const char *name, int jid, const char *state)
{
	ucl_object_t	*o;
	char		*json;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(name), "jail", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(state), "state", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(jid), "jid", 0, false);
	if ((json = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT)) != NULL)
		event_add("jail-state", "%s", json);
	free(json);
	ucl_object_unref(o);
}

/* jid watched for its removal; said running when it is new. */
static void
watch(int kq, int jid, bool tell)
{
	struct kevent	 ev;
	struct wj	*w;
	char		*name;

	LIST_FOREACH(w, &jails, list)
		if (w->jid == jid)
			return;
	if ((name = jail_getname(jid)) == NULL)
		return;
	if ((w = calloc(1, sizeof(*w))) == NULL) {
		free(name);
		return;
	}
	w->jid = jid;
	w->name = name;
	EV_SET(&ev, jid, EVFILT_JAIL, EV_ADD, NOTE_JAIL_REMOVE, 0, w);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
		/* Gone already. */
		free(w->name);
		free(w);
		return;
	}
	LIST_INSERT_HEAD(&jails, w, list);
	if (tell)
		told(w->name, jid, "running");
}

static void
watch_all(int kq, bool tell)
{
	int	jid;

	jid = 0;
	while ((jid = jail_next(jid)) > 0)
		watch(kq, jid, tell);
}

static void *
watcher(void *arg __unused)
{
	struct kevent	 ev;
	struct wj	*w;
	int		 kq;

	if ((kq = kqueue()) == -1) {
		logmsg(LOG_NOTICE, "no events of the jails: kqueue: %s",
		    strerror(errno));
		return (NULL);
	}
	EV_SET(&ev, 0, EVFILT_JAIL, EV_ADD, NOTE_JAIL_CHILD, 0, NULL);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
		logmsg(LOG_NOTICE, "no events of the jails: EVFILT_JAIL: %s",
		    strerror(errno));
		close(kq);
		return (NULL);
	}
	watch_all(kq, false);
	for (;;) {
		if (kevent(kq, NULL, 0, &ev, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (ev.filter != EVFILT_JAIL)
			continue;
		if (ev.udata == NULL) {
			/* Made: which one, unless several were. */
			if ((ev.fflags & NOTE_JAIL_CHILD) == 0)
				continue;
			if (ev.data != 0 && (ev.fflags & NOTE_JAIL_MULTI) == 0)
				watch(kq, (int)ev.data, true);
			else
				watch_all(kq, true);
			continue;
		}
		w = ev.udata;
		if ((ev.fflags & NOTE_JAIL_REMOVE) == 0)
			continue;
		told(w->name, w->jid, "stopped");
		LIST_REMOVE(w, list);
		free(w->name);
		free(w);
	}
	close(kq);
	return (NULL);
}

void
jail_watch_start(void)
{
	pthread_t	tid;
	int		error;

	if ((error = pthread_create(&tid, NULL, watcher, NULL)) != 0) {
		logmsg(LOG_WARNING, "no events of the jails: pthread_create: "
		    "%s", strerror(error));
		return;
	}
	(void)pthread_detach(tid);
}
