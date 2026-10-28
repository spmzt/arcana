/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the routes, connections and sockets in parts, as
 * a cblink stream.  A dump has the reading of its connection to itself
 * while it lasts; a stream is one of many on a connection, so that over
 * SCTP it shares the association with whatever else asks the host at
 * once.  Each stream has a thread of its own, which takes the parts as
 * a dump does (network_part()) and sends one only when
 * the reader has room for it: the reader gives the room back as it
 * takes them, so a slow one slows its own stream and nothing else.
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "agent.h"

#define	PARTS_MAX	8	/* streams at once */

struct pstream {
	cbl_stream		*s;
	struct arc_network_dump_req rq;	/* what network_part() takes */
	char			*filter;
	char			*jail;
	pthread_mutex_t		 lock;
	pthread_cond_t		 wake;
	bool			 closed;	/* by the reader, or reset */
	int			 refs;		/* the thread's, the stream's */
};

static pthread_mutex_t	parts_lock = PTHREAD_MUTEX_INITIALIZER;
static int		nparts;

static void	ps_unref(struct pstream *);
static void	ps_free(struct pstream *);

static void
ps_writable(cbl_stream *s __unused, size_t credit __unused, void *arg)
{
	struct pstream	*p = arg;

	pthread_mutex_lock(&p->lock);
	pthread_cond_signal(&p->wake);
	pthread_mutex_unlock(&p->lock);
}

static void
ps_close(cbl_stream *s __unused, int code __unused, const char *text __unused,
    void *arg)
{
	struct pstream	*p = arg;

	pthread_mutex_lock(&p->lock);
	p->closed = true;
	pthread_cond_signal(&p->wake);
	pthread_mutex_unlock(&p->lock);
	/* No callback of it runs after this one. */
	ps_unref(p);
}

static const struct arc_network_parts_server_cbs net_cbs = {
	.on_writable = ps_writable,
	.on_close = ps_close,
};


/*
 * A part sent: when the reader has no room for it (EAGAIN), once it
 * gives some back (on_writable), or the reader is gone.
 */
static int
ps_send(struct pstream *p, const struct arc_part *part)
{
	int	error;

	for (;;) {
		error = arc_network_parts_server_send(p->s, part);
		if (error != EAGAIN)
			return (error);
		pthread_mutex_lock(&p->lock);
		while (!p->closed && cbl_stream_credit(p->s) == 0)
			pthread_cond_wait(&p->wake, &p->lock);
		error = p->closed ? EPIPE : 0;
		pthread_mutex_unlock(&p->lock);
		if (error != 0)
			return (error);
	}
}

static void *
ps_run(void *arg)
{
	struct pstream		*p = arg;
	struct cbl_dump_state	 st;
	struct arc_part		 part;
	struct arc_route	*routes;
	struct ucl_object_s	*keep;
	const char		*err;
	char			*json;
	uint64_t		 total;
	size_t			 nroutes;
	bool			 more;
	int			 error;

	memset(&st, 0, sizeof(st));
	error = 0;
	err = NULL;
	do {
		json = NULL;
		err = NULL;
		more = network_part(&st, &p->rq, &json, &total, &err);
		if (json == NULL) {
			error = ENOMEM;
			break;
		}
		if (err != NULL && !more) {
			free(json);
			break;
		}
		memset(&part, 0, sizeof(part));
		part.has_total = true;
		part.total = total;
		routes = NULL;
		keep = NULL;
		/* The routes typed, as the spec has a route; the rest JSON. */
		if (p->rq.net_kind == ARC_NET_KIND_ROUTES) {
			if ((error = network_routes(json, &routes, &nroutes,
			    &keep)) != 0) {
				free(json);
				break;
			}
			part.routes.v = routes;
			part.routes.n = nroutes;
		} else
			part.json = json;
		error = ps_send(p, &part);
		free(routes);
		network_routes_free(keep);
		free(json);
	} while (error == 0 && more);
	if (st.priv != NULL && st.priv_free != NULL)
		st.priv_free(st.priv);
	if (error == 0 && err == NULL)
		(void)cbl_stream_half_close(p->s);
	else if (error != EPIPE)
		(void)cbl_stream_close(p->s, error != 0 ? error : EINVAL,
		    err != NULL ? err : strerror(error));
	cbl_stream_rele(p->s);
	ps_unref(p);
	return (NULL);
}

/* Accepted, and a thread of its own to send the parts. */
static int
ps_start(struct pstream *p)
{
	pthread_t	tid;
	int		error;

	cbl_stream_ref(p->s);
	if ((error = pthread_create(&tid, NULL, ps_run, p)) != 0) {
		(void)cbl_stream_close(p->s, error, "no thread for the parts");
		cbl_stream_rele(p->s);
		ps_unref(p);
		return (error);
	}
	(void)pthread_detach(tid);
	return (0);
}

static struct pstream *
ps_new(cbl_stream *s, const char *filter, const char *jail)
{
	struct pstream	*p;

	pthread_mutex_lock(&parts_lock);
	if (nparts >= PARTS_MAX) {
		pthread_mutex_unlock(&parts_lock);
		return (NULL);
	}
	nparts++;
	pthread_mutex_unlock(&parts_lock);
	if ((p = calloc(1, sizeof(*p))) == NULL ||
	    (filter != NULL && (p->filter = strdup(filter)) == NULL) ||
	    (jail != NULL && (p->jail = strdup(jail)) == NULL)) {
		if (p != NULL) {
			free(p->filter);
			free(p);
		}
		pthread_mutex_lock(&parts_lock);
		nparts--;
		pthread_mutex_unlock(&parts_lock);
		return (NULL);
	}
	p->s = s;
	p->refs = 2;
	pthread_mutex_init(&p->lock, NULL);
	pthread_cond_init(&p->wake, NULL);
	return (p);
}

/* One of its two ends is done with it: gone once both are. */
static void
ps_unref(struct pstream *p)
{
	bool	last;

	pthread_mutex_lock(&p->lock);
	last = --p->refs == 0;
	pthread_mutex_unlock(&p->lock);
	if (last)
		ps_free(p);
}

static void
ps_free(struct pstream *p)
{

	pthread_mutex_destroy(&p->lock);
	pthread_cond_destroy(&p->wake);
	free(p->filter);
	free(p->jail);
	free(p);
	pthread_mutex_lock(&parts_lock);
	nparts--;
	pthread_mutex_unlock(&parts_lock);
}

int
arc_network_parts_stream_open(cbl_req *req,
    const struct arc_network_parts_req *rq, cbl_stream *s, void *arg __unused)
{
	struct arc_network_parts_rsp	 rsp;
	struct pstream			*p;

	if (rq->net_kind != ARC_NET_KIND_ROUTES && rq->net_kind !=
	    ARC_NET_KIND_CONNECTIONS && rq->net_kind != ARC_NET_KIND_SOCKETS) {
		(void)cbl_req_set_err(req, "the routes, connections and "
		    "sockets come in parts; the rest whole", NULL, 0, -1);
		return (EINVAL);
	}
	if (rq->jail != NULL && rq->jail[0] != '\0' && !valid_jail(rq->jail)) {
		(void)cbl_req_set_err(req, "invalid jail name", NULL, 0, -1);
		return (EINVAL);
	}
	if (rq->net_filter != NULL && strlen(rq->net_filter) > 128) {
		(void)cbl_req_set_err(req, "the text to search for is at most "
		    "128 bytes", NULL, 0, -1);
		return (EINVAL);
	}
	if ((p = ps_new(s, rq->net_filter, rq->jail)) == NULL) {
		(void)cbl_req_set_err(req, "too many parts at once", NULL, 0,
		    -1);
		return (EBUSY);
	}
	p->rq.has_net_kind = true;
	p->rq.net_kind = rq->net_kind;
	p->rq.has_net_family = rq->has_net_family;
	p->rq.net_family = rq->net_family;
	p->rq.net_filter = p->filter;
	p->rq.has_net_fib = rq->has_net_fib;
	p->rq.net_fib = rq->net_fib;
	p->rq.jail = p->jail;
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	if (arc_network_parts_accept(s, &rsp, &net_cbs, p) != 0) {
		/* Not accepted: no callback of it runs, and it is ours. */
		ps_free(p);
		return (ECONNREFUSED);
	}
	(void)ps_start(p);
	return (0);
}
