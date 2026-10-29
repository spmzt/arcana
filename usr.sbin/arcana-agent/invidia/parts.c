/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the routes, connections and sockets in parts, as a cblink
 * stream of the agent's own family, arcana-parts, whose every message
 * is arcana-network's network-part structure: the open request names
 * the table, each data message is a part, the next rows typed with the
 * total.  A stream is one of many on a connection, so that over SCTP it
 * shares the association with whatever else asks the host at once.
 * Each stream has a thread of its own, which takes the parts as
 * netdump.c reads them (network_part()) and sends one only when the
 * reader has room for it: the reader gives the room back as it takes
 * them, so a slow one slows its own stream and nothing else.
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ucl.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "agent.h"
#include "collect.h"

#define	PARTS_FAMILY	"arcana-parts"
#define	PARTS_NETWORK	1	/* the network-parts stream */
#define	PARTS_MAX	8	/* streams at once */
#define	PARTS_WINDOW	2097152	/* bytes the reader takes before it grants */

struct pstream {
	cbl_stream		*s;
	struct net_parts_req	 rq;	/* what network_part() takes */
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

static const struct cbl_stream_cbs ps_cbs = {
	.on_writable = ps_writable,
	.on_close = ps_close,
};

/*
 * A part sent: when the reader has no room for it (EAGAIN), once it
 * gives some back (on_writable), or the reader is gone.
 */
static int
ps_send(struct pstream *p, const struct arcana_network_network_part *part)
{
	cbl_msg	*msg;
	int	 error;

	for (;;) {
		if ((error = cbl_stream_msg_new(p->s, &msg)) != 0)
			return (error);
		if ((error = arcana_network_network_part_put(msg, part)) != 0) {
			cbl_msg_free(msg);
			return (error);
		}
		/* EAGAIN (no credit) leaves the message ours. */
		if ((error = cbl_stream_send(p->s, msg)) != EAGAIN)
			return (error);
		cbl_msg_free(msg);
		pthread_mutex_lock(&p->lock);
		while (!p->closed && cbl_stream_credit(p->s) == 0)
			pthread_cond_wait(&p->wake, &p->lock);
		error = p->closed ? EPIPE : 0;
		pthread_mutex_unlock(&p->lock);
		if (error != 0)
			return (error);
	}
}

/* A part's rows, a JSON array, as the structure has them. */
static int
ps_part(const struct pstream *p, const char *json, uint64_t total,
    struct arcana_network_network_part *part, cbl_yarena *a)
{
	struct ucl_parser	*pr;
	ucl_object_t		*rows, *o;
	int			 error;

	pr = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	rows = NULL;
	if (ucl_parser_add_string(pr, json, 0))
		rows = ucl_parser_get_object(pr);
	ucl_parser_free(pr);
	if (rows == NULL)
		return (EINVAL);
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, rows, p->rq.kind == ARC_NET_KIND_ROUTES ?
	    "route" : p->rq.kind == ARC_NET_KIND_CONNECTIONS ? "connection" :
	    "socket", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)total), "total",
	    0, false);
	error = ynet_decode(ynet_node("arcana-network", "network-part", NULL),
	    o, part, a);
	ucl_object_unref(o);
	return (error);
}

static void *
ps_run(void *arg)
{
	struct pstream				*p = arg;
	struct cbl_dump_state			 st;
	struct arcana_network_network_part	 part;
	cbl_yarena				*a;
	const char				*err;
	char					*json;
	uint64_t				 total;
	bool					 more;
	int					 error;

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
		if ((a = cbl_yarena_new()) == NULL) {
			free(json);
			error = ENOMEM;
			break;
		}
		memset(&part, 0, sizeof(part));
		if ((error = ps_part(p, json, total, &part, a)) == 0)
			error = ps_send(p, &part);
		cbl_yarena_free(a);
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

static int
ps_open(cbl_req *req, const cbl_msg *msg, cbl_stream *s, void *arg __unused)
{
	struct arcana_network_network_part	 rq;
	struct pstream				*p;
	cbl_yarena				*a;
	cbl_msg					*accept;
	const char				*why;
	char					 buf[200];
	int					 error;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&rq, 0, sizeof(rq));
	why = NULL;
	if (arcana_network_network_part_parse(msg, &rq, a, CBL_YD_STRICT, buf,
	    sizeof(buf)) != 0)
		why = buf;
	else if (!rq.has_kind)
		why = "the routes, connections and sockets come in parts; the "
		    "rest whole";
	else if (rq.jail != NULL && rq.jail[0] != '\0' && !valid_jail(rq.jail))
		why = "invalid jail name";
	if (why != NULL) {
		(void)cbl_req_set_err(req, why, NULL, 0, -1);
		cbl_yarena_free(a);
		return (EINVAL);
	}
	if ((p = ps_new(s, rq.filter != NULL && rq.filter[0] != '\0' ?
	    rq.filter : NULL, rq.jail != NULL && rq.jail[0] != '\0' ? rq.jail :
	    NULL)) == NULL) {
		cbl_yarena_free(a);
		(void)cbl_req_set_err(req, "too many parts at once", NULL, 0,
		    -1);
		return (EBUSY);
	}
	p->rq.kind = rq.kind == ARCANA_NETWORK_NETWORK_PART_KIND_CONNECTIONS ?
	    ARC_NET_KIND_CONNECTIONS : rq.kind ==
	    ARCANA_NETWORK_NETWORK_PART_KIND_SOCKETS ? ARC_NET_KIND_SOCKETS :
	    ARC_NET_KIND_ROUTES;
	p->rq.family = !rq.has_family ? ARC_NET_FAMILY_ALL : rq.family ==
	    ARCANA_NETWORK_NETWORK_PART_FAMILY_INET ? ARC_NET_FAMILY_INET :
	    rq.family == ARCANA_NETWORK_NETWORK_PART_FAMILY_INET6 ?
	    ARC_NET_FAMILY_INET6 : ARC_NET_FAMILY_ALL;
	p->rq.fib = rq.has_fib ? rq.fib : 0;
	p->rq.filter = p->filter;
	p->rq.jail = p->jail;
	cbl_yarena_free(a);
	if ((error = cbl_stream_msg_new(s, &accept)) != 0) {
		ps_free(p);
		return (error);
	}
	(void)cbl_msg_set_window(accept, PARTS_WINDOW);
	if (cbl_stream_accept(s, accept, 0, &ps_cbs, p) != 0) {
		/* Not accepted: no callback of it runs, and it is ours. */
		ps_free(p);
		return (ECONNREFUSED);
	}
	(void)ps_start(p);
	return (0);
}

static const struct cbl_op parts_ops[] = {
	{ .cmd = PARTS_NETWORK, .flags = CBL_OPF_STREAM | CBL_OPF_AUTH |
	    CBL_OPF_NACM, .name = "network-parts", .stream_open = ps_open },
};

static const struct cbl_family_def parts_def = {
	.abi = CBL_FAMILY_ABI,
	.name = PARTS_FAMILY,
	.version = 1,
	.ops = parts_ops,
	.nops = nitems(parts_ops),
};

int
parts_register(cbl_ctx *ctx)
{

	return (cbl_family_register(ctx, &parts_def, NULL, NULL));
}
