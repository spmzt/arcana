/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Reads over the console's socket: what a GET would read, done by the
 * console as {"what": "read"} (stream.c), so that each step of the
 * host's trace reaches the page while the host takes it.  The task of
 * the read draws its steps as they come, a program's box the moment it
 * runs, and says it is live, not pending; the answer goes to the same
 * callback a GET's would.  Without the socket, or when it fails, the
 * read is a GET after all.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	LIVE_MAX	16
#define	LIVE_ID0	1000000		/* above the other streams' ids */

struct liveread {
	int	 id;		/* the socket's request, 0: a free slot */
	int	 op;		/* its task, 0: none */
	api_cb	*cb;
	void	*arg;
	char	 url[160];	/* the GET it would be */
	char	 fn[48];	/* its operation's call, as the trace says it */
};

static struct liveread	live[LIVE_MAX];
static int		live_next = LIVE_ID0;

static struct liveread *
live_find(int id)
{
	int	i;

	for (i = 0; i < LIVE_MAX; i++)
		if (live[i].id != 0 && live[i].id == id)
			return (&live[i]);
	return (NULL);
}

/* The read as a GET after all: the socket is not there, or failed. */
static void
live_fallback(struct liveread *l)
{
	struct liveread	 c = *l;
	struct op	*op;
	int		 req;

	memset(l, 0, sizeof(*l));
	if ((op = c.op != 0 ? op_find(c.op) : NULL) != NULL) {
		op->live = false;
		op->await = true;
	}
	req = api("GET", c.url, NULL, c.cb, c.arg);
	if (op != NULL)
		op->req = req;
}

/*
 * Read url's answer with the console's socket: read is what it reads
 * (jails, services) of server sid; opid, when not 0, is its task.
 */
void
live_read(const char *sid, const char *read, const char *url, int opid,
    api_cb *cb, void *arg)
{
	struct liveread	*l;
	struct op	*op;
	char		 msg[192];
	int		 i;

	op = opid != 0 ? op_find(opid) : NULL;
	for (i = 0, l = NULL; i < LIVE_MAX && l == NULL; i++)
		if (live[i].id == 0)
			l = &live[i];
	if (l == NULL || !app.online) {
		/* Too many at once here: as before. */
		i = api("GET", url, NULL, cb, arg);
		if (op != NULL)
			op->req = i;
		return;
	}
	l->id = live_next++;
	l->op = opid;
	l->cb = cb;
	l->arg = arg;
	snprintf(l->url, sizeof(l->url), "%s", url);
	/* The console's call, by which the schema panel finds it. */
	snprintf(l->fn, sizeof(l->fn), "libcblink arc_%s()",
	    strcmp(read, "jails") == 0 ? "list" : read);
	if (op != NULL) {
		op->live = true;
		op->await = false;
		/* What it reads, as its schema is found by. */
		snprintf(op->method, sizeof(op->method), "GET");
		snprintf(op->url, sizeof(op->url), "%s", url);
		snprintf(op->stage, sizeof(op->stage), "asked the host");
	}
	snprintf(msg, sizeof(msg), "{\"id\":%d,\"server\":\"%s\",\"what\":"
	    "\"read\",\"read\":\"%s\"}", l->id, sid, read);
	arc_stream_send(msg);
}

/* A task's state as the list and the graph say it: live, not pending. */
const char *
op_class(const struct op *o)
{

	return (o->state == OP_RUNNING ? (o->live ? "live" : "running") :
	    o->state == OP_OK ? "ok" : "failed");
}

/* The console's own three steps above the host's, until the answer. */
static ucl_object_t *
own_step(int id, int parent, const char *kind, const char *label)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromint(id), "id", 0, true);
	ucl_object_insert_key(o, ucl_object_fromint(parent), "parent", 0,
	    true);
	ucl_object_insert_key(o, ucl_object_fromstring(kind), "kind", 0,
	    true);
	ucl_object_insert_key(o, ucl_object_fromstring(label), "label", 0,
	    true);
	ucl_object_insert_key(o, ucl_object_fromstring("incomplete"),
	    "status", 0, true);
	return (o);
}

/* A step the host told: put in its task's trace, or its place taken. */
static void
live_step(struct op *op, const char *fn, const ucl_object_t *step)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*copy;
	int64_t			 id;
	unsigned int		 i;

	if (op == NULL || (id = jint(step, "id", -1)) < 0)
		return;
	if (op->trace == NULL) {
		op->trace = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(op->trace, own_step(0, -1, "api",
		    "over the console's socket, live"));
		ucl_array_append(op->trace, own_step(1, 0, "auth",
		    "session check"));
		ucl_array_append(op->trace, own_step(2, 0, "lib", fn));
	}
	copy = ucl_object_copy(step);
	it = NULL;
	i = 0;
	while ((e = ucl_object_iterate(op->trace, &it, true)) != NULL) {
		if (jint(e, "id", -2) == id) {
			ucl_object_unref(ucl_array_replace_index(op->trace,
			    copy, i));
			copy = NULL;
			break;
		}
		i++;
	}
	if (copy != NULL)
		ucl_array_append(op->trace, copy);
	/* Where it is: the step that runs now. */
	if (jstr(step, "label") != NULL)
		snprintf(op->stage, sizeof(op->stage), "%s", jstr(step,
		    "label"));
}

/* What the socket says (arc_on_stream()): a read's step or answer. */
void
live_stream(const ucl_object_t *o)
{
	struct liveread	*l;
	struct op	*op;
	const char	*err;
	int		 i, status;

	if (jbool(o, "closed")) {
		/* Lost: what was asked on it is asked again with GET. */
		for (i = 0; i < LIVE_MAX; i++)
			if (live[i].id != 0)
				live_fallback(&live[i]);
		return;
	}
	if ((l = live_find((int)jint(o, "id", -1))) == NULL)
		return;
	op = l->op != 0 ? op_find(l->op) : NULL;
	if (jget(o, "step") != NULL) {
		live_step(op, l->fn, jget(o, "step"));
		return;
	}
	if (jget(o, "reply") == NULL) {
		/* Refused, or the host did not answer: GET says why. */
		live_fallback(l);
		return;
	}
	status = (int)jint(o, "status", 0);
	err = NULL;
	if (status >= 400 && (err = jstr(jget(o, "reply"),
	    "error.message")) == NULL)
		err = jstr(jget(o, "reply"), "error");
	if (op != NULL)
		op->live = false;
	{
		struct liveread	c = *l;

		memset(l, 0, sizeof(*l));
		c.cb(status, jget(o, "reply"), err, c.arg);
	}
}
