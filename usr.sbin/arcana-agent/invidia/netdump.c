/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: a network table in parts.  A dump is answered in the loop's
 * own thread, a part for each call, which is too little room to read a
 * table in; so a thread of the dump's own reads it and hands the rows
 * over a queue, which holds a few thousand of them: the reading is
 * held back while the client is slow, and nothing of the table is
 * kept whole.  The rows come a line each as they are read from the
 * kernel: the routes through netlink (nlroute.c), the connections and
 * sockets from its lists of control blocks (pcb.c); by the daemon
 * itself for the host, by the helper in a jail.
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

#include "agent.h"

#define	ND_QUEUE	4000		/* rows held between the two threads */
#define	ND_PART		250		/* rows in one part, at most */
#define	ND_WAIT_MS	50		/* the loop's thread waits this long for a row */

struct netdump {
	pthread_mutex_t	 lock;
	pthread_cond_t	 more;		/* a row was put, or the end came */
	pthread_cond_t	 room;		/* a row was taken */
	char		*rows[ND_QUEUE];
	size_t		 head, n;
	uint64_t	 total;
	bool		 done, stop;
	char		 error[200];
	int		 refs;		/* the thread's, and the dump's */
	/* What was asked. */
	uint8_t		 kind, family;
	uint32_t	 fib;
	char		*filter, *jail;
	bool		 six;		/* the family of the rows being read */
};

static void
nd_unref(struct netdump *nd)
{
	size_t	i;

	pthread_mutex_lock(&nd->lock);
	if (--nd->refs > 0) {
		pthread_mutex_unlock(&nd->lock);
		return;
	}
	pthread_mutex_unlock(&nd->lock);
	for (i = 0; i < nd->n; i++)
		free(nd->rows[(nd->head + i) % ND_QUEUE]);
	free(nd->filter);
	free(nd->jail);
	pthread_mutex_destroy(&nd->lock);
	pthread_cond_destroy(&nd->more);
	pthread_cond_destroy(&nd->room);
	free(nd);
}

/* The dump's end: the thread, if it still runs, drains and goes. */
static void
nd_free(void *priv)
{
	struct netdump	*nd = priv;

	pthread_mutex_lock(&nd->lock);
	nd->stop = true;
	pthread_cond_broadcast(&nd->room);
	pthread_mutex_unlock(&nd->lock);
	nd_unref(nd);
}

/* A row, kept until it is taken; dropped once nobody takes any. */
static void
nd_put(struct netdump *nd, char *row)
{

	pthread_mutex_lock(&nd->lock);
	while (nd->n == ND_QUEUE && !nd->stop)
		pthread_cond_wait(&nd->room, &nd->lock);
	if (nd->stop)
		free(row);
	else {
		nd->rows[(nd->head + nd->n++) % ND_QUEUE] = row;
		pthread_cond_signal(&nd->more);
	}
	pthread_mutex_unlock(&nd->lock);
}

/* A line of the helper's: a route, with its family put in. */
static void
nd_line(const char *line, void *arg)
{
	struct netdump	*nd = arg;
	char		*row;

	if (strncmp(line, "#total ", 7) == 0) {
		pthread_mutex_lock(&nd->lock);
		nd->total = strtoull(line + 7, NULL, 10);
		pthread_mutex_unlock(&nd->lock);
		return;
	}
	if (strcmp(line, "#family 6") == 0) {
		nd->six = true;
		return;
	}
	if (line[0] != '{')
		return;
	/* A route says which table it is of; the others say it already. */
	if (nd->kind != ARC_NET_KIND_ROUTES) {
		if ((row = strdup(line)) == NULL)
			return;
	} else if (asprintf(&row, "{\"family\":\"%s\",%s", nd->six ?
	    "Internet6" : "Internet", line + 1) == -1)
		return;
	nd_put(nd, row);
}

static void *
nd_run(void *arg)
{
	struct netdump		*nd = arg;
	struct work		 w;
	const char		*err, *words[4];

	work_init(&w);
	err = NULL;
	if (scope_enter(&w, nd->jail, &err) != 0) {
		pthread_mutex_lock(&nd->lock);
		snprintf(nd->error, sizeof(nd->error), "%s", err);
		nd->done = true;
		pthread_cond_signal(&nd->more);
		pthread_mutex_unlock(&nd->lock);
		work_free(&w);
		nd_unref(nd);
		return (NULL);
	}
	words[0] = nd->family == ARC_NET_FAMILY_INET ? "4" : nd->family ==
	    ARC_NET_FAMILY_INET6 ? "6" : "0";
	if (nd->kind == ARC_NET_KIND_ROUTES) {
		words[1] = wfmt(&w, "%u", nd->fib);
		words[2] = nd->filter != NULL ? nd->filter : "-";
		words[3] = "-";
		nd->six = nd->family == ARC_NET_FAMILY_INET6;
		if (helper_lines(&w, "routes", 4, words, nd_line, nd) != 0)
			err = "the kernel did not list its routes";
	} else if (helper_lines(&w, nd->kind == ARC_NET_KIND_SOCKETS ?
	    "pcb-socks" : "pcb-conns", 1, words, nd_line, nd) != 0)
		err = "the kernel did not list them";
	pthread_mutex_lock(&nd->lock);
	if (err != NULL)
		snprintf(nd->error, sizeof(nd->error), "%s", err);
	nd->done = true;
	pthread_cond_signal(&nd->more);
	pthread_mutex_unlock(&nd->lock);
	work_free(&w);
	nd_unref(nd);
	return (NULL);
}

/*
 * The next part: a JSON array of up to ND_PART rows, waited for a
 * little when none is there yet.  True while more may come; the error,
 * when the table could not be read, in *errp.
 */
bool
network_part(struct cbl_dump_state *st, const struct net_parts_req *rq,
    char **jsonp, uint64_t *totalp, const char **errp)
{
	struct netdump	*nd;
	struct timespec	 until;
	pthread_t	 tid;
	FILE		*fp;
	char		*json;
	size_t		 len, i;
	bool		 more;

	*jsonp = NULL;
	*errp = NULL;
	if ((nd = st->priv) == NULL) {
		if ((nd = calloc(1, sizeof(*nd))) == NULL)
			return (false);
		pthread_mutex_init(&nd->lock, NULL);
		pthread_cond_init(&nd->more, NULL);
		pthread_cond_init(&nd->room, NULL);
		nd->kind = rq->kind;
		nd->family = rq->family;
		nd->fib = rq->fib;
		nd->filter = rq->filter != NULL && rq->filter[0] !=
		    '\0' ? strdup(rq->filter) : NULL;
		nd->jail = rq->jail != NULL && rq->jail[0] != '\0' ?
		    strdup(rq->jail) : NULL;
		nd->refs = 2;
		if (pthread_create(&tid, NULL, nd_run, nd) != 0) {
			nd->refs = 1;
			nd_free(nd);
			*errp = "no thread for it";
			return (false);
		}
		(void)pthread_detach(tid);
		st->priv = nd;
		st->priv_free = nd_free;
	}
	pthread_mutex_lock(&nd->lock);
	if (nd->n == 0 && !nd->done) {
		clock_gettime(CLOCK_REALTIME, &until);
		until.tv_nsec += ND_WAIT_MS * 1000000L;
		if (until.tv_nsec >= 1000000000L) {
			until.tv_sec++;
			until.tv_nsec -= 1000000000L;
		}
		(void)pthread_cond_timedwait(&nd->more, &nd->lock, &until);
	}
	json = NULL;
	if ((fp = open_memstream(&json, &len)) == NULL) {
		pthread_mutex_unlock(&nd->lock);
		return (false);
	}
	fputc('[', fp);
	for (i = 0; i < ND_PART && nd->n > 0; i++) {
		fprintf(fp, "%s%s", i > 0 ? "," : "", nd->rows[nd->head]);
		free(nd->rows[nd->head]);
		nd->head = (nd->head + 1) % ND_QUEUE;
		nd->n--;
	}
	fputc(']', fp);
	if (i > 0)
		pthread_cond_broadcast(&nd->room);
	more = !(nd->done && nd->n == 0);
	*totalp = nd->total;
	if (nd->error[0] != '\0')
		*errp = nd->error;
	pthread_mutex_unlock(&nd->lock);
	if (fclose(fp) != 0) {
		free(json);
		return (false);
	}
	*jsonp = json;
	return (more);
}
