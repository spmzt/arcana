/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: what happened on the host, as it happened.  An event is a
 * number, a time, a kind and what it is about, a JSON object; whoever
 * sees one happen adds it (the kernel's netlink messages, for one),
 * and the last of them are kept, to be asked for from a number on:
 * who asks again with the number of the last one it has misses none,
 * unless more happened in between than are kept, which the reply's
 * "first" tells.
 */

#include <sys/types.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "agent.h"

#define	EVENTS_KEPT	512
#define	EVENT_MAX	1024		/* bytes of what one is about */

struct event {
	uint64_t	 n;
	time_t		 t;
	const char	*kind;		/* a literal */
	char		*data;
};

static pthread_mutex_t	ev_lock = PTHREAD_MUTEX_INITIALIZER;
static struct event	ring[EVENTS_KEPT];
static size_t		ring_first, ring_n;
static uint64_t		ev_last;
static cbl_family	*ev_family;	/* what a subscriber hears it on */

/*
 * The family the events are told on, to those who subscribed; NULL
 * before it goes, so that no event is told on it after.
 */
void
event_family(cbl_family *fam)
{

	pthread_mutex_lock(&ev_lock);
	ev_family = fam;
	pthread_mutex_unlock(&ev_lock);
}

/* kind is a string that stays; the rest makes a JSON object. */
void
event_add(const char *kind, const char *fmt, ...)
{
	struct arc_event_ntf	 ntf;
	struct event		*e;
	va_list			 ap;
	char			*data, *json;
	int			 n;

	va_start(ap, fmt);
	n = vasprintf(&data, fmt, ap);
	va_end(ap);
	if (n == -1)
		return;
	if (n > EVENT_MAX || data[0] != '{') {
		free(data);
		return;
	}
	pthread_mutex_lock(&ev_lock);
	if (ring_n < EVENTS_KEPT)
		e = &ring[(ring_first + ring_n++) % EVENTS_KEPT];
	else {
		e = &ring[ring_first];
		ring_first = (ring_first + 1) % EVENTS_KEPT;
		free(e->data);
	}
	e->n = ++ev_last;
	e->t = time(NULL);
	e->kind = kind;
	e->data = data;
	/* Told to the subscribers too, as events has it, in its order. */
	json = NULL;
	if (ev_family != NULL && asprintf(&json, "{\"n\":%ju,\"t\":%jd,"
	    "\"kind\":\"%s\",\"data\":%s}", (uintmax_t)e->n, (intmax_t)e->t,
	    kind, data) != -1) {
		memset(&ntf, 0, sizeof(ntf));
		ntf.json = json;
		(void)arc_event_notify(ev_family, &ntf);
	}
	pthread_mutex_unlock(&ev_lock);
	free(json);
}

/* {"last":n,"first":n,"events":[{"n","t","kind","data":{}}]}, after one. */
int
do_events(struct work *w, uint64_t after, struct arc_events_rsp *rsp)
{
	const struct event	*e;
	FILE			*fp;
	char			*json;
	size_t			 len, i, n;
	int			 step;

	rsp->has_ok = true;
	rsp->ok = false;
	step = step_begin(w, ARC_STEP_KIND_DAEMON, "events",
	    "those after number %ju", (uintmax_t)after);
	json = NULL;
	if ((fp = open_memstream(&json, &len)) == NULL) {
		step_end(w, step, false, "open_memstream");
		rsp->error = "out of memory";
		return (0);
	}
	pthread_mutex_lock(&ev_lock);
	fprintf(fp, "{\"last\":%ju,\"first\":%ju,\"kept\":%d,\"events\":[",
	    (uintmax_t)ev_last, (uintmax_t)(ring_n > 0 ? ring[ring_first].n :
	    0), EVENTS_KEPT);
	for (i = n = 0; i < ring_n; i++) {
		e = &ring[(ring_first + i) % EVENTS_KEPT];
		if (e->n <= after)
			continue;
		fprintf(fp, "%s{\"n\":%ju,\"t\":%jd,\"kind\":\"%s\",\"data\":"
		    "%s}", n++ > 0 ? "," : "", (uintmax_t)e->n, (intmax_t)e->t,
		    e->kind, e->data);
	}
	pthread_mutex_unlock(&ev_lock);
	fprintf(fp, "]}");
	if (fclose(fp) != 0 || json == NULL) {
		free(json);
		step_end(w, step, false, "out of memory");
		rsp->error = "out of memory";
		return (0);
	}
	step_end(w, step, true, "%zu events", n);
	rsp->json = wadopt(w, json);
	rsp->ok = true;
	return (0);
}
