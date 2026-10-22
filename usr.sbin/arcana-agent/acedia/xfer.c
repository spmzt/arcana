/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Acedia: a snapshot sent to another host.  zfs send runs here and what
 * it writes goes out as a cblink stream (zfs-send); on the other host
 * a stream comes in (zfs-receive) and what it carries is what its zfs
 * receive reads.  Whoever holds both streams carries the bytes between
 * them; the console does, and gives the sending host room only as the
 * receiving one takes them, so nothing piles up anywhere.
 *
 * Each stream has a thread of its own: the sender reads zfs send and
 * sends when there is room (EAGAIN until on_writable); the receiver
 * writes what came to zfs receive, and only then gives the room it
 * took back to the sender of it.  A dataset is never overwritten: no
 * -F, and nothing is received into a pool's own dataset.
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"

#define	XFER_MAX	4		/* at once, both ways */
#define	XFER_CHUNK	(256 * 1024)	/* what is read from send at once */
#define	XFER_ERR	1024		/* what is kept of what zfs said */

extern char	**environ;

struct chunk {
	STAILQ_ENTRY(chunk)	 next;
	unsigned char		*p;
	size_t			 len;
	size_t			 took;		/* of the window */
};

struct xfer {
	cbl_stream		*s;
	bool			 recv;
	char			*argv[8];
	pid_t			 pid;
	int			 io;		/* send's stdout, receive's stdin */
	int			 err;		/* its stderr */
	pthread_mutex_t		 lock;
	pthread_cond_t		 wake;
	STAILQ_HEAD(, chunk)	 chunks;	/* to receive, not yet written */
	bool			 eof;		/* the sender is done */
	bool			 closed;	/* the stream ended */
	int			 refs;		/* the thread's, the stream's */
};

static pthread_mutex_t	xfer_lock = PTHREAD_MUTEX_INITIALIZER;
static int		nxfers;

static bool
dataset_name(const char *s)
{

	if (s == NULL || s[0] == '\0' || s[0] == '-' || s[0] == '/' ||
	    strlen(s) > 255 || strstr(s, "//") != NULL || s[strlen(s) - 1] ==
	    '/')
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.:/-", *s) == NULL)
			return (false);
	return (true);
}

/* dataset@snapshot; *lenp the length of the dataset's part. */
static bool
snapshot_name(const char *s, size_t *lenp)
{
	const char	*at, *p;
	char		 ds[256];

	if (s == NULL || (at = strchr(s, '@')) == NULL || at[1] == '\0' ||
	    strlen(s) > 255 || (size_t)(at - s) >= sizeof(ds))
		return (false);
	memcpy(ds, s, (size_t)(at - s));
	ds[at - s] = '\0';
	if (!dataset_name(ds))
		return (false);
	for (p = at + 1; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p) && strchr("_.:-", *p) == NULL)
			return (false);
	*lenp = (size_t)(at - s);
	return (true);
}

static void	xfer_unref(struct xfer *);

static struct xfer *
xfer_new(cbl_stream *s, bool recv)
{
	struct xfer	*x;

	pthread_mutex_lock(&xfer_lock);
	if (nxfers >= XFER_MAX) {
		pthread_mutex_unlock(&xfer_lock);
		return (NULL);
	}
	nxfers++;
	pthread_mutex_unlock(&xfer_lock);
	if ((x = calloc(1, sizeof(*x))) == NULL) {
		pthread_mutex_lock(&xfer_lock);
		nxfers--;
		pthread_mutex_unlock(&xfer_lock);
		return (NULL);
	}
	x->s = s;
	x->recv = recv;
	x->pid = -1;
	x->io = x->err = -1;
	x->refs = 2;
	STAILQ_INIT(&x->chunks);
	pthread_mutex_init(&x->lock, NULL);
	pthread_cond_init(&x->wake, NULL);
	return (x);
}

static void
xfer_free(struct xfer *x)
{
	struct chunk	*c;
	size_t		 i;

	while ((c = STAILQ_FIRST(&x->chunks)) != NULL) {
		STAILQ_REMOVE_HEAD(&x->chunks, next);
		free(c->p);
		free(c);
	}
	for (i = 0; i < nitems(x->argv); i++)
		free(x->argv[i]);
	if (x->io != -1)
		close(x->io);
	if (x->err != -1)
		close(x->err);
	pthread_mutex_destroy(&x->lock);
	pthread_cond_destroy(&x->wake);
	free(x);
	pthread_mutex_lock(&xfer_lock);
	nxfers--;
	pthread_mutex_unlock(&xfer_lock);
}

/* One of its two ends is done with it: gone once both are. */
static void
xfer_unref(struct xfer *x)
{
	bool	last;

	pthread_mutex_lock(&x->lock);
	last = --x->refs == 0;
	pthread_mutex_unlock(&x->lock);
	if (last)
		xfer_free(x);
}

/*
 * zfs send or receive started, its stdout or its stdin and its stderr
 * pipes to this side; -1 and errno when not.
 */
static int
xfer_spawn(struct xfer *x)
{
	posix_spawn_file_actions_t	 fa;
	int				 io[2], er[2], error;

	if (pipe2(io, O_CLOEXEC) == -1)
		return (-1);
	if (pipe2(er, O_CLOEXEC) == -1) {
		close(io[0]);
		close(io[1]);
		return (-1);
	}
	posix_spawn_file_actions_init(&fa);
	if (x->recv)
		posix_spawn_file_actions_adddup2(&fa, io[0], STDIN_FILENO);
	else
		posix_spawn_file_actions_adddup2(&fa, io[1], STDOUT_FILENO);
	posix_spawn_file_actions_adddup2(&fa, er[1], STDERR_FILENO);
	error = posix_spawn(&x->pid, x->argv[0], &fa, NULL, x->argv, environ);
	posix_spawn_file_actions_destroy(&fa);
	close(x->recv ? io[0] : io[1]);
	close(er[1]);
	x->io = x->recv ? io[1] : io[0];
	x->err = er[0];
	if (error != 0) {
		x->pid = -1;
		errno = error;
		return (-1);
	}
	return (0);
}

/*
 * The program's end: true when it did well; what it said into why,
 * its last line, when it did not.
 */
static bool
xfer_wait(struct xfer *x, char *why, size_t len)
{
	char	 buf[XFER_ERR + 1];
	size_t	 got;
	ssize_t	 n;
	int	 st;
	char	*nl;

	got = 0;
	while (got < XFER_ERR && (n = read(x->err, buf + got, XFER_ERR -
	    got)) > 0)
		got += (size_t)n;
	buf[got] = '\0';
	while (got > 0 && (buf[got - 1] == '\n' || buf[got - 1] == '\r'))
		buf[--got] = '\0';
	nl = strrchr(buf, '\n');
	snprintf(why, len, "%s", nl != NULL ? nl + 1 : buf);
	if (x->pid == -1)
		return (false);
	while (waitpid(x->pid, &st, 0) == -1 && errno == EINTR)
		;
	x->pid = -1;
	if (WIFEXITED(st) && WEXITSTATUS(st) == 0)
		return (true);
	if (why[0] == '\0')
		snprintf(why, len, "%s %s", x->argv[1], WIFSIGNALED(st) ?
		    "was stopped" : "failed");
	return (false);
}

/* The other end went: the program is stopped. */
static void
xfer_closed(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg)
{
	struct xfer	*x = arg;

	pthread_mutex_lock(&x->lock);
	x->closed = true;
	pthread_cond_signal(&x->wake);
	pthread_mutex_unlock(&x->lock);
	xfer_unref(x);
}

static void
xfer_writable(cbl_stream *s __unused, size_t credit __unused, void *arg)
{
	struct xfer	*x = arg;

	pthread_mutex_lock(&x->lock);
	pthread_cond_signal(&x->wake);
	pthread_mutex_unlock(&x->lock);
}

/* The sender's thread: zfs send, read and sent as there is room. */
static void *
send_run(void *arg)
{
	struct xfer		*x = arg;
	struct arc_chunk	 c;
	unsigned char		*buf;
	char			 why[XFER_ERR];
	ssize_t			 n;
	int			 error;
	bool			 ok;

	error = 0;
	why[0] = '\0';
	if ((buf = malloc(XFER_CHUNK)) == NULL)
		error = ENOMEM;
	while (error == 0 && (n = read(x->io, buf, XFER_CHUNK)) > 0) {
		memset(&c, 0, sizeof(c));
		c.data.p = buf;
		c.data.len = (size_t)n;
		while ((error = arc_zfs_send_server_send(x->s, &c)) ==
		    EAGAIN) {
			pthread_mutex_lock(&x->lock);
			while (!x->closed && cbl_stream_credit(x->s) == 0)
				pthread_cond_wait(&x->wake, &x->lock);
			error = x->closed ? EPIPE : 0;
			pthread_mutex_unlock(&x->lock);
			if (error != 0)
				break;
		}
	}
	free(buf);
	/* Gone before it ended: send is not left writing to nobody. */
	if (error != 0 && x->pid != -1)
		(void)kill(x->pid, SIGTERM);
	close(x->io);
	x->io = -1;
	ok = xfer_wait(x, why, sizeof(why));
	if (error == 0 && ok)
		(void)cbl_stream_half_close(x->s);
	else if (error != EPIPE)
		(void)cbl_stream_close(x->s, error != 0 ? error : EIO,
		    error != 0 ? strerror(error) : why);
	cbl_stream_rele(x->s);
	xfer_unref(x);
	return (NULL);
}

static const struct arc_zfs_send_server_cbs send_cbs = {
	.on_writable = xfer_writable,
	.on_close = xfer_closed,
};

/* The receiver's: what came, written to zfs receive, then its room back. */
static void *
recv_run(void *arg)
{
	struct xfer	*x = arg;
	struct chunk	*c;
	char		 why[XFER_ERR];
	size_t		 off;
	ssize_t		 n;
	int		 error;
	bool		 ok, closed;

	error = 0;
	why[0] = '\0';
	pthread_mutex_lock(&x->lock);
	for (;;) {
		while (STAILQ_EMPTY(&x->chunks) && !x->eof && !x->closed)
			pthread_cond_wait(&x->wake, &x->lock);
		if (x->closed && !x->eof) {
			error = EPIPE;
			break;
		}
		if ((c = STAILQ_FIRST(&x->chunks)) == NULL)
			break;		/* the sender is done, all written */
		STAILQ_REMOVE_HEAD(&x->chunks, next);
		pthread_mutex_unlock(&x->lock);
		for (off = 0; off < c->len; off += (size_t)n)
			if ((n = write(x->io, c->p + off, c->len - off)) <=
			    0) {
				if (n == -1 && errno == EINTR) {
					n = 0;
					continue;
				}
				error = EPIPE;
				break;
			}
		if (error == 0)
			(void)cbl_stream_consumed(x->s, c->took);
		free(c->p);
		free(c);
		pthread_mutex_lock(&x->lock);
		if (error != 0)
			break;
	}
	closed = x->closed;
	pthread_mutex_unlock(&x->lock);
	/* The end of what is to be read: receive finishes, or fails. */
	close(x->io);
	x->io = -1;
	if (error != 0 && x->pid != -1 && closed)
		(void)kill(x->pid, SIGTERM);
	ok = xfer_wait(x, why, sizeof(why));
	if (!closed) {
		if (ok && error == 0)
			(void)cbl_stream_close(x->s, 0, NULL);
		else
			(void)cbl_stream_close(x->s, EIO, why[0] != '\0' ? why :
			    "zfs receive did not finish");
	}
	cbl_stream_rele(x->s);
	xfer_unref(x);
	return (NULL);
}

static void
recv_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct xfer		*x = arg;
	struct arc_chunk	 d;
	struct chunk		*c;
	cbl_yarena		*a;

	if ((a = cbl_yarena_new()) == NULL) {
		(void)cbl_stream_reset(s, ENOMEM);
		return;
	}
	if (arcana_chunk_parse(data, &d, a, CBL_YD_STRICT, NULL, 0) != 0) {
		cbl_yarena_free(a);
		(void)cbl_stream_reset(s, EBADMSG);
		return;
	}
	/* The bytes are the message's: kept until they are written. */
	if ((c = calloc(1, sizeof(*c))) == NULL || (c->p = malloc(d.data.len +
	    1)) == NULL) {
		free(c);
		cbl_yarena_free(a);
		(void)cbl_stream_reset(s, ENOMEM);
		return;
	}
	memcpy(c->p, d.data.p, d.data.len);
	c->len = d.data.len;
	c->took = cbl_msg_len(data);
	cbl_yarena_free(a);
	pthread_mutex_lock(&x->lock);
	STAILQ_INSERT_TAIL(&x->chunks, c, next);
	pthread_cond_signal(&x->wake);
	pthread_mutex_unlock(&x->lock);
}

static void
recv_hclose(cbl_stream *s __unused, void *arg)
{
	struct xfer	*x = arg;

	pthread_mutex_lock(&x->lock);
	x->eof = true;
	pthread_cond_signal(&x->wake);
	pthread_mutex_unlock(&x->lock);
}

static const struct cbl_stream_cbs recv_cbs = {
	.on_data = recv_data,
	.on_hclose = recv_hclose,
	.on_close = xfer_closed,
};

/* Its thread, which owns the program from here; false when none. */
static bool
xfer_start(struct xfer *x, void *(*run)(void *))
{
	pthread_t	tid;

	cbl_stream_ref(x->s);
	if (pthread_create(&tid, NULL, run, x) != 0) {
		if (x->pid != -1)
			(void)kill(x->pid, SIGTERM);
		(void)cbl_stream_close(x->s, EAGAIN, "no thread for it");
		cbl_stream_rele(x->s);
		xfer_unref(x);
		return (false);
	}
	(void)pthread_detach(tid);
	return (true);
}

int
arc_zfs_send_stream_open(cbl_req *req, const struct arc_zfs_send_req *rq,
    cbl_stream *s, void *arg __unused)
{
	struct arc_zfs_send_rsp	 rsp;
	struct xfer		*x;
	size_t			 l0, l1, n;

	if (rq->names.n < 1 || rq->names.n > 2 || !snapshot_name(
	    rq->names.v[0], &l0) || (rq->names.n == 2 && (!snapshot_name(
	    rq->names.v[1], &l1) || l1 != l0 || strncmp(rq->names.v[0],
	    rq->names.v[1], l0) != 0))) {
		(void)cbl_req_set_err(req, "a snapshot, dataset@name, and the "
		    "one of the same dataset it is to be sent from, if any",
		    NULL, 0, -1);
		return (EINVAL);
	}
	if ((x = xfer_new(s, false)) == NULL) {
		(void)cbl_req_set_err(req, "four transfers at most, at once",
		    NULL, 0, -1);
		return (EBUSY);
	}
	n = 0;
	x->argv[n++] = strdup(opts.zfs_bin);
	x->argv[n++] = strdup("send");
	if (rq->zfs_recursive)
		x->argv[n++] = strdup("-R");
	if (rq->names.n == 2) {
		x->argv[n++] = strdup("-i");
		x->argv[n++] = strdup(rq->names.v[1]);
	}
	x->argv[n++] = strdup(rq->names.v[0]);
	if (xfer_spawn(x) == -1) {
		(void)cbl_req_set_err(req, strerror(errno), NULL, 0, -1);
		x->refs = 1;
		xfer_unref(x);
		return (EIO);
	}
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	if (arc_zfs_send_accept(s, &rsp, &send_cbs, x) != 0) {
		(void)kill(x->pid, SIGTERM);
		(void)waitpid(x->pid, NULL, 0);
		x->refs = 1;
		xfer_unref(x);
		return (ECONNREFUSED);
	}
	(void)xfer_start(x, send_run);
	return (0);
}

int
arc_zfs_receive_stream_open(cbl_req *req,
    const struct arc_zfs_receive_req *rq, cbl_stream *s, void *arg __unused)
{
	struct arc_zfs_receive_rsp	 rsp;
	struct xfer			*x;
	cbl_msg				*msg;

	/* Never into a pool's own dataset: a dataset under one. */
	if (rq->names.n != 1 || !dataset_name(rq->names.v[0]) ||
	    strchr(rq->names.v[0], '/') == NULL) {
		(void)cbl_req_set_err(req, "a dataset under a pool, pool/name, "
		    "that is not there yet or is the one it is sent from",
		    NULL, 0, -1);
		return (EINVAL);
	}
	if ((x = xfer_new(s, true)) == NULL) {
		(void)cbl_req_set_err(req, "four transfers at most, at once",
		    NULL, 0, -1);
		return (EBUSY);
	}
	x->argv[0] = strdup(opts.zfs_bin);
	x->argv[1] = strdup("receive");
	x->argv[2] = strdup("-u");
	x->argv[3] = strdup(rq->names.v[0]);
	if (xfer_spawn(x) == -1) {
		(void)cbl_req_set_err(req, strerror(errno), NULL, 0, -1);
		x->refs = 1;
		xfer_unref(x);
		return (EIO);
	}
	/*
	 * Accepted with the room given back by hand: only what receive
	 * read is given back, so the sender waits for a slow disk.
	 */
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	if (cbl_stream_msg_new(s, &msg) != 0 ||
	    arc_zfs_receive_rsp_put_fields(msg, &rsp) != 0 ||
	    cbl_msg_set_window(msg, 4194304) != 0 || cbl_stream_accept(s, msg,
	    CBL_SF_MANUAL_CREDIT, &recv_cbs, x) != 0) {
		(void)kill(x->pid, SIGTERM);
		(void)waitpid(x->pid, NULL, 0);
		x->refs = 1;
		xfer_unref(x);
		return (ECONNREFUSED);
	}
	(void)xfer_start(x, recv_run);
	return (0);
}
