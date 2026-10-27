/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * arcana-console's HTTP server on libwebsockets(3) (web.h).
 *
 * The program is two processes: a supervisor, which keeps the pid file
 * and starts the worker again when it dies, as root when started as
 * root; and the worker, which listens (as root, for a port below 1024),
 * becomes the console's user, and serves.  One worker: the console's
 * sessions and stores live in its memory.  Its loop is libwebsockets';
 * what takes time runs on task threads, which wake the loop when done.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libutil.h>
#include <pthread.h>
#include <pwd.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include <libwebsockets.h>
#include <openssl/ssl.h>
#include <ucl.h>

#include "keymgr.h"
#include "web.h"

#ifndef ARCW_CONF
#define	ARCW_CONF	"/usr/local/etc/arcana/web.conf"
#endif
#ifndef ARCW_WEBROOT
#define	ARCW_WEBROOT	"/usr/local/www/arcana-console"
#endif
#define	LISTEN_MAX	8
#define	HDR_MAX		16384		/* one header, the query, a cookie */
/* A reply's body goes out this much at a time: over HTTP/2 a write is
 * one DATA frame, which may not be larger than 16 KB (the peer's
 * SETTINGS_MAX_FRAME_SIZE as browsers leave it); a larger one ends the
 * connection and every stream on it. */
#define	WRITE_CHUNK	16384
/*
 * A reply's last piece, at most, written only while nothing waits in the
 * connection's buffer: the socket then takes it whole (a writable socket
 * has room for 2 KB, its low-water mark), so the HTTP/2 stream it ends
 * closes before the client has its end.  Closing one while output waits
 * is put off by libwebsockets until it is sent, the client may open its
 * next stream first, and one stream past libwebsockets' limit (24, which
 * its 50 pending frames, two for each new stream, do not let us raise)
 * ends the whole connection.
 */
#define	FINAL_MAX	1024
#define	WS_IN_MAX	(1024 * 1024)	/* a message from a page, at most */
/* A message goes out in fragments of this much at most: over HTTP/2 a
 * WebSocket frame may not be larger than an HTTP/2 frame (16 KB), and
 * one that is ends the connection, every socket on it. */
#define	WS_FRAG		8192

/* web.conf's server { }. */
static struct {
	char	*listen[LISTEN_MAX];
	int	 lfd[LISTEN_MAX];	/* the supervisor's, every worker's */
	int	 nlisten;
	char	*certfile;
	char	*certkey;
	char	*webroot;
	char	*user;
	char	*pidfile;
	int	 task_threads;
	size_t	 body_max;
} srv;

const char	*web_conf_path = ARCW_CONF;
const char	*web_certfile, *web_certkey;

static bool		 foreground = true;
static struct lws_context *ctx;
static volatile sig_atomic_t quit;
static regex_t		*route_re;

/* Requests to run again; sleeping ones wait for a wakeup. */
#define	F_SLEEPING	0x01
#define	F_DELETED	0x02
#define	F_QUEUED	0x04
#define	F_UPGRADE	0x08
static TAILQ_HEAD(, http_request) runq = TAILQ_HEAD_INITIALIZER(runq);

/* What libwebsockets keeps per connection for us. */
struct pss {
	struct http_request	*req;
	struct conn		*conn;
};

struct wsmsg {
	STAILQ_ENTRY(wsmsg)	 next;
	size_t			 len;
	size_t			 off;		/* sent so far */
	bool			 binary;
	uint8_t			 data[];
};

/* ---------------------------------------------------------------- */
/* Helpers. */

void *
xmalloc(size_t n)
{
	void	*p;

	if ((p = malloc(n == 0 ? 1 : n)) == NULL)
		fatalx("out of memory");
	return (p);
}

void *
xcalloc(size_t n, size_t m)
{
	void	*p;

	if ((p = calloc(n == 0 ? 1 : n, m == 0 ? 1 : m)) == NULL)
		fatalx("out of memory");
	return (p);
}

void *
xrealloc(void *p, size_t n)
{

	if ((p = realloc(p, n == 0 ? 1 : n)) == NULL)
		fatalx("out of memory");
	return (p);
}

char *
xstrdup(const char *s)
{
	char	*p;

	if ((p = strdup(s)) == NULL)
		fatalx("out of memory");
	return (p);
}

static void
vlog(int prio, const char *fmt, va_list ap)
{
	char	msg[4096];

	vsnprintf(msg, sizeof(msg), fmt, ap);
	if (foreground)
		fprintf(stderr, "arcana-console[%d]: %s\n", (int)getpid(), msg);
	else
		syslog(prio, "%s", msg);
}

void
log_msg(int prio, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vlog(prio, fmt, ap);
	va_end(ap);
}

void
fatalx(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vlog(LOG_ERR, fmt, ap);
	va_end(ap);
	_exit(EX_CONFIG);
}

struct buf *
buf_alloc(size_t n)
{
	struct buf	*b;

	b = xcalloc(1, sizeof(*b));
	b->length = n > 0 ? n : 128;
	b->data = xmalloc(b->length);
	return (b);
}

void
buf_free(struct buf *b)
{

	if (b == NULL)
		return;
	free(b->data);
	free(b);
}

static void
buf_grow(struct buf *b, size_t need)
{

	if (b->offset + need + 1 <= b->length)
		return;
	while (b->offset + need + 1 > b->length)
		b->length *= 2;
	b->data = xrealloc(b->data, b->length);
}

void
buf_append(struct buf *b, const void *d, size_t n)
{

	buf_grow(b, n);
	memcpy(b->data + b->offset, d, n);
	b->offset += n;
}

void
buf_appendv(struct buf *b, const char *fmt, va_list ap)
{
	va_list	aq;
	int	n;

	va_copy(aq, ap);
	n = vsnprintf(NULL, 0, fmt, aq);
	va_end(aq);
	if (n < 0)
		return;
	buf_grow(b, (size_t)n);
	vsnprintf(b->data + b->offset, (size_t)n + 1, fmt, ap);
	b->offset += (size_t)n;
}

void
buf_appendf(struct buf *b, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	buf_appendv(b, fmt, ap);
	va_end(ap);
}

char *
buf_stringify(struct buf *b, size_t *lenp)
{

	buf_grow(b, 0);
	b->data[b->offset] = '\0';
	if (lenp != NULL)
		*lenp = b->offset;
	return (b->data);
}

void
buf_reset(struct buf *b)
{

	b->offset = 0;
}

static const char b64std[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64url[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char *
b64(const uint8_t *in, size_t len, const char *alpha, bool pad)
{
	char	*out, *o;
	size_t	 i;
	uint32_t v;

	out = o = xmalloc((len + 2) / 3 * 4 + 1);
	for (i = 0; i + 2 < len; i += 3) {
		v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
		*o++ = alpha[v >> 18 & 63];
		*o++ = alpha[v >> 12 & 63];
		*o++ = alpha[v >> 6 & 63];
		*o++ = alpha[v & 63];
	}
	if (i < len) {
		v = (uint32_t)in[i] << 16 | (i + 1 < len ? (uint32_t)in[i + 1]
		    << 8 : 0);
		*o++ = alpha[v >> 18 & 63];
		*o++ = alpha[v >> 12 & 63];
		if (i + 1 < len)
			*o++ = alpha[v >> 6 & 63];
		else if (pad)
			*o++ = '=';
		if (pad)
			*o++ = '=';
	}
	*o = '\0';
	return (out);
}

int
b64_encode(const void *in, size_t len, char **out)
{

	*out = b64(in, len, b64std, true);
	return (WEB_OK);
}

int
b64url_encode(const void *in, size_t len, char **out, int flags)
{

	*out = b64(in, len, b64url, !(flags & B64_RAW));
	return (WEB_OK);
}

int
b64url_decode(const char *in, uint8_t **out, size_t *lenp, int flags)
{
	const char	*p;
	uint8_t		*o;
	uint32_t	 v;
	size_t		 len;
	int		 n, c;

	(void)flags;
	len = strlen(in);
	o = *out = xmalloc(len / 4 * 3 + 3);
	v = 0;
	n = 0;
	for (p = in; *p != '\0' && *p != '='; p++) {
		if ((c = *p) >= 'A' && c <= 'Z')
			c -= 'A';
		else if (c >= 'a' && c <= 'z')
			c = c - 'a' + 26;
		else if (c >= '0' && c <= '9')
			c = c - '0' + 52;
		else if (c == '-' || c == '+')
			c = 62;
		else if (c == '_' || c == '/')
			c = 63;
		else {
			free(*out);
			*out = NULL;
			return (WEB_ERROR);
		}
		v = v << 6 | (uint32_t)c;
		if (++n == 4) {
			*o++ = (uint8_t)(v >> 16);
			*o++ = (uint8_t)(v >> 8);
			*o++ = (uint8_t)v;
			v = 0;
			n = 0;
		}
	}
	if (n == 1) {
		free(*out);
		*out = NULL;
		return (WEB_ERROR);
	}
	if (n == 2)
		*o++ = (uint8_t)(v >> 4);
	else if (n == 3) {
		*o++ = (uint8_t)(v >> 10);
		*o++ = (uint8_t)(v >> 2);
	}
	*lenp = (size_t)(o - *out);
	return (WEB_OK);
}

/* ---------------------------------------------------------------- */
/* Tasks: a pool of threads; what they finish or write, to the loop. */

struct task_msg {
	STAILQ_ENTRY(task_msg)	 next;
	uint32_t		 len;
	uint8_t			 data[];
};

static pthread_mutex_t	pool_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	pool_cond = PTHREAD_COND_INITIALIZER;
static TAILQ_HEAD(, task) pool_q = TAILQ_HEAD_INITIALIZER(pool_q);
static TAILQ_HEAD(, task) ready_q = TAILQ_HEAD_INITIALIZER(ready_q);
static pthread_mutex_t	ready_lock = PTHREAD_MUTEX_INITIALIZER;

/* For the loop: t has something to say.  Either lock is held by none. */
static void
task_ready(struct task *t)
{

	pthread_mutex_lock(&ready_lock);
	if (!t->queued && !t->destroyed) {
		t->queued = true;
		TAILQ_INSERT_TAIL(&ready_q, t, list);
	}
	pthread_mutex_unlock(&ready_lock);
	if (ctx != NULL)
		lws_cancel_service(ctx);
}

static void *
pool_thread(void *arg)
{
	struct task	*t;
	int		 rc;

	(void)arg;
	for (;;) {
		pthread_mutex_lock(&pool_lock);
		while ((t = TAILQ_FIRST(&pool_q)) == NULL)
			pthread_cond_wait(&pool_cond, &pool_lock);
		TAILQ_REMOVE(&pool_q, t, list);
		pthread_mutex_unlock(&pool_lock);
		pthread_mutex_lock(&t->lock);
		t->state = TASK_STATE_RUNNING;
		pthread_mutex_unlock(&t->lock);
		rc = t->entry(t);
		/*
		 * Finished and on the loop's list in one step: the loop may
		 * destroy and free t as soon as it sees it finished (a
		 * request's on_free), so t is not touched after.
		 */
		pthread_mutex_lock(&ready_lock);
		pthread_mutex_lock(&t->lock);
		t->result = rc;
		t->state = TASK_STATE_FINISHED;
		pthread_mutex_unlock(&t->lock);
		if (!t->queued) {
			t->queued = true;
			TAILQ_INSERT_TAIL(&ready_q, t, list);
		}
		pthread_mutex_unlock(&ready_lock);
		lws_cancel_service(ctx);
	}
	return (NULL);
}

void
task_create(struct task *t, task_fn *entry)
{

	memset(t, 0, sizeof(*t));
	t->entry = entry;
	t->state = TASK_STATE_CREATED;
	pthread_mutex_init(&t->lock, NULL);
	STAILQ_INIT(&t->chan);
}

void
task_bind_request(struct task *t, struct http_request *req)
{

	t->req = req;
	LIST_INSERT_HEAD(&req->tasks, t, rlist);
}

void
task_bind_callback(struct task *t, task_cb *cb)
{

	t->cb = cb;
}

void
task_run(struct task *t)
{

	pthread_mutex_lock(&pool_lock);
	TAILQ_INSERT_TAIL(&pool_q, t, list);
	pthread_cond_signal(&pool_cond);
	pthread_mutex_unlock(&pool_lock);
}

int
task_state(struct task *t)
{
	int	s;

	pthread_mutex_lock(&t->lock);
	s = t->state;
	pthread_mutex_unlock(&t->lock);
	return (s);
}

int
task_finished(struct task *t)
{

	return (task_state(t) == TASK_STATE_FINISHED);
}

/* Once it is finished; again is nothing. */
void
task_destroy(struct task *t)
{
	struct task_msg	*m;

	if (t->destroyed)
		return;
	if (t->req != NULL) {
		LIST_REMOVE(t, rlist);
		t->req = NULL;
	}
	pthread_mutex_lock(&ready_lock);
	if (t->queued) {
		TAILQ_REMOVE(&ready_q, t, list);
		t->queued = false;
	}
	t->destroyed = true;
	pthread_mutex_unlock(&ready_lock);
	while ((m = STAILQ_FIRST(&t->chan)) != NULL) {
		STAILQ_REMOVE_HEAD(&t->chan, next);
		free(m);
	}
	pthread_mutex_destroy(&t->lock);
}

void
task_channel_write(struct task *t, const void *d, uint32_t len)
{
	struct task_msg	*m;

	m = xmalloc(sizeof(*m) + len);
	m->len = len;
	memcpy(m->data, d, len);
	pthread_mutex_lock(&t->lock);
	STAILQ_INSERT_TAIL(&t->chan, m, next);
	pthread_mutex_unlock(&t->lock);
	task_ready(t);
}

uint32_t
task_channel_read(struct task *t, void *out, uint32_t len)
{
	struct task_msg	*m;
	uint32_t	 n;

	pthread_mutex_lock(&t->lock);
	if ((m = STAILQ_FIRST(&t->chan)) != NULL)
		STAILQ_REMOVE_HEAD(&t->chan, next);
	pthread_mutex_unlock(&t->lock);
	if (m == NULL)
		return (0);
	n = m->len;
	memcpy(out, m->data, n < len ? n : len);
	free(m);
	return (n);
}

bool
task_channel_pending(struct task *t)
{
	bool	some;

	pthread_mutex_lock(&t->lock);
	some = !STAILQ_EMPTY(&t->chan);
	pthread_mutex_unlock(&t->lock);
	return (some);
}

/* ---------------------------------------------------------------- */
/* Timers. */

struct timer {
	lws_sorted_usec_list_t	 sul;
	timer_fn		*fn;
	void			*arg;
	uint64_t		 ms;
	int			 flags;
};

static uint64_t
now_ms(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

static void
timer_fire(lws_sorted_usec_list_t *sul)
{
	struct timer	*t = (struct timer *)(void *)sul;	/* first */

	if (!(t->flags & TIMER_ONESHOT))
		lws_sul_schedule(ctx, 0, &t->sul, timer_fire,
		    (lws_usec_t)t->ms * LWS_US_PER_MS);
	t->fn(t->arg, now_ms());
	if (t->flags & TIMER_ONESHOT)
		free(t);
}

struct timer *
timer_add(timer_fn *fn, uint64_t ms, void *arg, int flags)
{
	struct timer	*t;

	t = xcalloc(1, sizeof(*t));
	t->fn = fn;
	t->arg = arg;
	t->ms = ms;
	t->flags = flags;
	lws_sul_schedule(ctx, 0, &t->sul, timer_fire, (lws_usec_t)ms *
	    LWS_US_PER_MS);
	return (t);
}

/* ---------------------------------------------------------------- */
/* Requests. */

static void	req_run(struct http_request *);

static void
hdrs_free(struct http_header_list *l)
{
	struct http_header	*h;

	while ((h = TAILQ_FIRST(l)) != NULL) {
		TAILQ_REMOVE(l, h, list);
		free(h->name);
		free(h->value);
		free(h);
	}
}

static void
hdr_add(struct http_header_list *l, const char *name, size_t nlen,
    const char *value)
{
	struct http_header	*h;
	size_t			 i;

	h = xcalloc(1, sizeof(*h));
	h->name = xmalloc(nlen + 1);
	for (i = 0; i < nlen; i++)
		h->name[i] = (char)tolower((unsigned char)name[i]);
	h->name[nlen] = '\0';
	h->value = xstrdup(value);
	TAILQ_INSERT_TAIL(l, h, list);
}

/*
 * The request gone from the server: answered, or its client gone.  The
 * route's on_free first, every time, as long as a task of it runs (it
 * may destroy one that is done, and free what holds it); then the
 * finished tasks, hdlr_extra and the rest.  Called again when a task of
 * it is done.
 */
static void
req_free(struct http_request *req)
{
	struct http_arg	*a;
	struct task	*t, *nt;

	req->flags |= F_DELETED;
	if (req->flags & F_QUEUED) {
		TAILQ_REMOVE(&runq, req, list);
		req->flags &= ~F_QUEUED;
	}
	if (req->rt != NULL && req->rt->on_free != NULL)
		req->rt->on_free(req);
	LIST_FOREACH(t, &req->tasks, rlist)
		if (!task_finished(t))
			return;
	for (t = LIST_FIRST(&req->tasks); t != NULL; t = nt) {
		nt = LIST_NEXT(t, rlist);
		task_destroy(t);
	}
	free(req->hdlr_extra);
	hdrs_free(&req->headers);
	hdrs_free(&req->resp_headers);
	while ((a = TAILQ_FIRST(&req->args)) != NULL) {
		TAILQ_REMOVE(&req->args, a, list);
		free(a->name);
		free(a->value);
		free(a);
	}
	while ((a = TAILQ_FIRST(&req->cookies)) != NULL) {
		TAILQ_REMOVE(&req->cookies, a, list);
		free(a->name);
		free(a->value);
		free(a);
	}
	if (req->http_body != NULL) {
		explicit_bzero(req->http_body->data, req->http_body->length);
		free(req->http_body->data);
		free(req->http_body);
	}
	free(req->resp);
	if (req->stream != NULL)
		buf_free(req->stream);
	free(req->path);
	free(req->query_string);
	free(req);
}

static void
runq_add(struct http_request *req)
{

	if (req->flags & (F_QUEUED | F_DELETED))
		return;
	req->flags |= F_QUEUED;
	TAILQ_INSERT_TAIL(&runq, req, list);
	lws_cancel_service(ctx);
}

void
http_request_sleep(struct http_request *req)
{

	req->flags |= F_SLEEPING;
}

void
http_request_wakeup(struct http_request *req)
{

	if (req->flags & F_SLEEPING) {
		req->flags &= ~F_SLEEPING;
		runq_add(req);
	}
}

/* On the loop: what the tasks finished or wrote. */
static void
tasks_drain(void)
{
	struct http_request	*req;
	struct task		*t;

	for (;;) {
		pthread_mutex_lock(&ready_lock);
		if ((t = TAILQ_FIRST(&ready_q)) != NULL) {
			TAILQ_REMOVE(&ready_q, t, list);
			t->queued = false;
		}
		pthread_mutex_unlock(&ready_lock);
		if (t == NULL)
			break;
		if (t->cb != NULL) {
			t->cb(t);	/* may destroy and free t */
			continue;
		}
		if ((req = t->req) == NULL || !task_finished(t))
			continue;
		if (req->flags & F_DELETED)
			req_free(req);
		else {
			req->flags &= ~F_SLEEPING;
			runq_add(req);
		}
	}
	while ((req = TAILQ_FIRST(&runq)) != NULL) {
		TAILQ_REMOVE(&runq, req, list);
		req->flags &= ~F_QUEUED;
		req_run(req);
	}
}

void
http_response_header(struct http_request *req, const char *name,
    const char *value)
{

	hdr_add(&req->resp_headers, name, strlen(name), value);
}

void
http_response(struct http_request *req, int status, const void *d,
    size_t len)
{

	if (req->status != 0)
		return;
	req->status = status;
	if (len > 0) {
		req->resp = xmalloc(len);
		memcpy(req->resp, d, len);
	}
	req->resp_len = len;
	if (req->wsi != NULL && !(req->flags & F_UPGRADE))
		lws_callback_on_writable(req->wsi);
}

void
http_stream(struct http_request *req, int status)
{

	if (req->status != 0)
		return;
	req->status = status;
	req->stream = buf_alloc(512);
	if (req->wsi != NULL)
		lws_callback_on_writable(req->wsi);
}

void
http_stream_put(struct http_request *req, const void *d, size_t len)
{

	if (req->stream == NULL || req->stream_end || len == 0)
		return;
	buf_append(req->stream, d, len);
	if (req->wsi != NULL && req->headers_sent)
		lws_callback_on_writable(req->wsi);
}

void
http_stream_end(struct http_request *req)
{

	if (req->stream == NULL)
		return;
	req->stream_end = true;
	if (req->wsi != NULL)
		lws_callback_on_writable(req->wsi);
}

int
http_request_header(struct http_request *req, const char *name,
    const char **out)
{
	struct http_header	*h;

	TAILQ_FOREACH(h, &req->headers, list)
		if (strcasecmp(h->name, name) == 0) {
			*out = h->value;
			return (1);
		}
	return (0);
}

int
http_request_cookie(struct http_request *req, const char *name, char **out)
{
	struct http_arg	*a;
	const char	*v;
	char		*all, *p, *pair, *eq;

	if (TAILQ_EMPTY(&req->cookies) && http_request_header(req, "cookie",
	    &v)) {
		all = xstrdup(v);
		for (p = all; (pair = strsep(&p, ";")) != NULL;) {
			pair += strspn(pair, " \t");
			if ((eq = strchr(pair, '=')) == NULL)
				continue;
			*eq = '\0';
			a = xcalloc(1, sizeof(*a));
			a->name = xstrdup(pair);
			a->value = xstrdup(eq + 1);
			TAILQ_INSERT_TAIL(&req->cookies, a, list);
		}
		free(all);
	}
	TAILQ_FOREACH(a, &req->cookies, list)
		if (strcmp(a->name, name) == 0) {
			*out = a->value;
			return (1);
		}
	return (0);
}

int
http_argument_get_string(struct http_request *req, const char *name,
    void *out)
{
	struct http_arg	*a;

	TAILQ_FOREACH(a, &req->args, list)
		if (strcmp(a->name, name) == 0) {
			*(const char **)out = a->value;
			return (1);
		}
	return (0);
}

/* As a URL escapes it: %XX and + for a space; 0 for a control character
 * (but for \t \n \r when not url). */
int
http_argument_urldecode(char *arg, int url)
{
	char	*p, *in, h[3];
	long	 v;

	for (p = in = arg; *p != '\0';) {
		if (*p == '+') {
			*in++ = ' ';
			p++;
			continue;
		}
		if (*p != '%') {
			*in++ = *p++;
			continue;
		}
		if (p[1] == '\0' || p[2] == '\0')
			return (0);
		if (!isxdigit((unsigned char)p[1]) ||
		    !isxdigit((unsigned char)p[2])) {
			*in++ = *p++;
			continue;
		}
		h[0] = p[1];
		h[1] = p[2];
		h[2] = '\0';
		v = strtol(h, NULL, 16);
		if ((v <= 0x1f || v == 0x7f) && (url || (v != '\n' && v != '\r' &&
		    v != '\t')))
			return (0);
		*in++ = (char)v;
		p += 3;
	}
	*in = '\0';
	return (1);
}

ssize_t
http_body_read(struct http_request *req, void *out, size_t len)
{
	struct http_body	*b;
	size_t			 n;

	if ((b = req->http_body) == NULL)
		return (0);
	n = b->length - b->offset;
	if (n > len)
		n = len;
	memcpy(out, b->data + b->offset, n);
	b->offset += n;
	return ((ssize_t)n);
}

/* A text as a client would have put it in a query: escaped only where
 * it would read otherwise. */
static void
qs_escape(struct buf *b, const char *s)
{
	static const char hex[] = "0123456789ABCDEF";

	for (; *s != '\0'; s++)
		if ((unsigned char)*s > 0x20 && (unsigned char)*s < 0x7f &&
		    strchr("%&=+;#", *s) == NULL)
			buf_append(b, s, 1);
		else
			buf_appendf(b, "%%%c%c", hex[(unsigned char)*s >> 4],
			    hex[(unsigned char)*s & 15]);
}

static void
custom_hdr(const char *name, int nlen, void *arg)
{
	struct lws_ctx_hdr {
		struct lws		*wsi;
		struct http_request	*req;
	} *c = arg;
	char	*v;
	int	 n, vlen;

	if ((vlen = lws_hdr_custom_length(c->wsi, name, nlen)) < 0 || nlen < 1)
		return;
	v = xmalloc((size_t)vlen + 1);
	n = lws_hdr_custom_copy(c->wsi, v, vlen + 1, name, nlen);
	/* "x-arcana:" over HTTP/1.1, "x-arcana" over HTTP/2. */
	if (n >= 0)
		hdr_add(&c->req->headers, name, (size_t)nlen - (name[nlen -
		    1] == ':'), v);
	free(v);
}

/* The request as it came: its method, path, headers and arguments. */
static struct http_request *
req_new(struct lws *wsi, const char *path)
{
	static const struct {
		enum lws_token_indexes	tok;
		int			method;
	} methods[] = {
		{ WSI_TOKEN_GET_URI, HTTP_METHOD_GET },
		{ WSI_TOKEN_POST_URI, HTTP_METHOD_POST },
		{ WSI_TOKEN_PUT_URI, HTTP_METHOD_PUT },
		{ WSI_TOKEN_DELETE_URI, HTTP_METHOD_DELETE },
		{ WSI_TOKEN_PATCH_URI, HTTP_METHOD_PATCH },
		{ WSI_TOKEN_OPTIONS_URI, HTTP_METHOD_OPTIONS },
		{ WSI_TOKEN_HEAD_URI, HTTP_METHOD_HEAD },
	};
	struct {
		struct lws		*wsi;
		struct http_request	*req;
	} c;
	struct http_request	*req;
	struct http_arg		*a;
	struct buf		*q;
	const unsigned char	*name;
	char			*v, *eq;
	size_t			 i;
	int			 tok, len, n;

	req = xcalloc(1, sizeof(*req));
	TAILQ_INIT(&req->headers);
	TAILQ_INIT(&req->args);
	TAILQ_INIT(&req->cookies);
	TAILQ_INIT(&req->resp_headers);
	LIST_INIT(&req->tasks);
	req->wsi = wsi;
	req->path = xstrdup(path);
	for (i = 0; i < nitems(methods); i++)
		if (lws_hdr_total_length(wsi, methods[i].tok) > 0) {
			req->method = methods[i].method;
			break;
		}
	/* The headers lws knows by name, "host:", then the others. */
	for (tok = 0; tok < WSI_TOKEN_COUNT; tok++) {
		if ((len = lws_hdr_total_length(wsi, (enum lws_token_indexes)
		    tok)) <= 0 || tok == WSI_TOKEN_HTTP_URI_ARGS ||
		    (name = lws_token_to_string((enum lws_token_indexes)tok)) ==
		    NULL || name[0] == '\0' || name[strlen((const char *)name) -
		    1] != ':')
			continue;
		v = xmalloc((size_t)len + 1);
		if (lws_hdr_copy(wsi, v, len + 1, (enum lws_token_indexes)tok) >=
		    0)
			hdr_add(&req->headers, (const char *)name, strlen(
			    (const char *)name) - 1, v);
		free(v);
	}
	c.wsi = wsi;
	c.req = req;
	(void)lws_hdr_custom_name_foreach(wsi, custom_hdr, &c);
	/* The arguments, as lws decoded them; and the query again, escaped
	 * as a URL has it, for the handlers that read it whole. */
	q = buf_alloc(128);
	v = xmalloc(HDR_MAX);
	for (n = 0; lws_hdr_copy_fragment(wsi, v, HDR_MAX,
	    WSI_TOKEN_HTTP_URI_ARGS, n) >= 0; n++) {
		a = xcalloc(1, sizeof(*a));
		if ((eq = strchr(v, '=')) != NULL) {
			*eq = '\0';
			a->value = xstrdup(eq + 1);
		} else
			a->value = xstrdup("");
		a->name = xstrdup(v);
		TAILQ_INSERT_TAIL(&req->args, a, list);
		if (q->offset > 0)
			buf_append(q, "&", 1);
		qs_escape(q, a->name);
		if (eq != NULL) {
			buf_append(q, "=", 1);
			qs_escape(q, a->value);
		}
	}
	free(v);
	if (q->offset > 0)
		req->query_string = xstrdup(buf_stringify(q, NULL));
	buf_free(q);
	return (req);
}

/* The route for the path and method; NULL, with *knownp when another
 * method's. */
static const struct route *
route_find(const char *path, int method, bool *knownp)
{
	size_t	i;
	bool	match;

	*knownp = false;
	for (i = 0; i < nroutes; i++) {
		if (routes[i].path[0] == '^')
			match = regexec(&route_re[i], path, 0, NULL, 0) == 0;
		else
			match = strcmp(routes[i].path, path) == 0;
		if (!match)
			continue;
		if (routes[i].methods & method)
			return (&routes[i]);
		*knownp = true;
	}
	return (NULL);
}

static void
req_run(struct http_request *req)
{
	int	rc;

	if (req->flags & F_DELETED)
		return;
	req->flags &= ~F_SLEEPING;
	rc = req->rt->handler(req);
	if (req->status != 0 || (req->flags & F_UPGRADE))
		return;
	if (rc == WEB_RETRY) {
		if (!(req->flags & F_SLEEPING))
			runq_add(req);
		return;
	}
	http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
}

static const struct {
	const char	*ext;
	const char	*type;
} mimes[] = {
	{ "html", "text/html; charset=utf-8" },
	{ "js", "text/javascript; charset=utf-8" },
	{ "mjs", "text/javascript; charset=utf-8" },
	{ "css", "text/css; charset=utf-8" },
	{ "json", "application/json" },
	{ "map", "application/json" },
	{ "wasm", "application/wasm" },
	{ "webmanifest", "application/manifest+json" },
	{ "svg", "image/svg+xml" },
	{ "png", "image/png" },
	{ "jpg", "image/jpeg" },
	{ "jpeg", "image/jpeg" },
	{ "gif", "image/gif" },
	{ "webp", "image/webp" },
	{ "ico", "image/x-icon" },
	{ "woff2", "font/woff2" },
	{ "woff", "font/woff" },
	{ "txt", "text/plain; charset=utf-8" },
	{ "pdf", "application/pdf" },
};

/* A file of the web root; 0 when it is being sent, -1 for none. */
static int
serve_file(struct lws *wsi, const char *path)
{
	struct stat	 sb;
	const char	*dot, *type;
	char		 full[MAXPATHLEN];
	size_t		 i;
	int		 n;

	if (strstr(path, "/../") != NULL || strstr(path, "/./") != NULL ||
	    path[0] != '/')
		return (-1);
	n = snprintf(full, sizeof(full), "%s%s", srv.webroot, path);
	if (n < 0 || (size_t)n >= sizeof(full))
		return (-1);
	if (stat(full, &sb) == 0 && S_ISDIR(sb.st_mode)) {
		n = snprintf(full, sizeof(full), "%s%s%sindex.html",
		    srv.webroot, path, path[strlen(path) - 1] == '/' ? "" : "/");
		if (n < 0 || (size_t)n >= sizeof(full))
			return (-1);
		if (stat(full, &sb) == -1)
			return (-1);
	} else if (stat(full, &sb) == -1 || !S_ISREG(sb.st_mode))
		return (-1);
	type = "application/octet-stream";
	if ((dot = strrchr(full, '.')) != NULL && strchr(dot, '/') == NULL)
		for (i = 0; i < nitems(mimes); i++)
			if (strcasecmp(dot + 1, mimes[i].ext) == 0) {
				type = mimes[i].type;
				break;
			}
	return (lws_serve_http_file(wsi, full, type, NULL, 0) < 0 ? -2 : 0);
}

/* A reply of our own, before any handler: 404, 405, 413. */
static struct http_request *
req_plain(struct lws *wsi, const char *path, int status)
{
	struct http_request	*req;

	req = req_new(wsi, path);
	http_response_header(req, "content-type", "text/plain; charset=utf-8");
	http_response(req, status, status == 404 ? "Not Found\n" : status ==
	    405 ? "Method Not Allowed\n" : "Payload Too Large\n", status ==
	    404 ? 10 : status == 405 ? 19 : 18);
	return (req);
}

/* A connection or stream ended by the server, said when ARCANA_DEBUG is
 * set: libwebsockets says nothing of those its user ends. */
static bool	debug_ends;

static int
ending(struct lws *wsi, const char *why)
{
	char	path[256];

	if (debug_ends) {
		path[0] = '\0';
		(void)lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI);
		if (path[0] == '\0')
			(void)lws_hdr_copy(wsi, path, sizeof(path),
			    WSI_TOKEN_POST_URI);
		log_msg(LOG_NOTICE, "ending %s: %s", path[0] != '\0' ? path :
		    "a connection", why);
	}
	return (-1);
}

/*
 * How much of want may be written now: over HTTP/2 the peer's window
 * (libwebsockets counts it), which is not to be passed, or it ends the
 * connection; 0 is to wait: the window's update calls the stream again.
 */
static size_t
allowed(struct lws *wsi, size_t want)
{
	lws_fileofs_t	a;

	if ((a = lws_get_peer_write_allowance(wsi)) < 0)
		return (want);
	return ((size_t)a < want ? (size_t)a : want);
}

/*
 * A reply sent: the transaction done, -1 when the stream or connection
 * is to close.  An HTTP/2 stream is closed whatever libwebsockets says:
 * while output waits in the connection's buffer it puts the transaction
 * off and, for a stream, never comes back to it, which left the stream
 * open for good, one of the client's concurrent streams.  What waits is
 * the connection's: closing the stream loses none of it.
 */
static int
done(struct lws *wsi, const char *why)
{

	if (lws_http_transaction_completed(wsi) ||
	    lws_get_network_wsi(wsi) != wsi)
		return (ending(wsi, why));
	return (0);
}

/* The next piece of the reply; -1 when the connection is to close. */
static int
req_write(struct lws *wsi, struct pss *pss)
{
	struct http_request	*req = pss->req;
	struct http_header	*h;
	unsigned char		*buf, *start, *p, *end;
	size_t			 n, cap;
	char			 name[128];
	int			 rc;

	if (req == NULL || req->status == 0)
		return (0);
	if (!req->headers_sent) {
		/* A reply without a body is its last piece too. */
		if (req->resp_len == 0 && lws_send_pipe_choked(wsi)) {
			lws_callback_on_writable(wsi);
			return (0);
		}
		cap = LWS_PRE + HDR_MAX;
		TAILQ_FOREACH(h, &req->resp_headers, list)
			cap += strlen(h->name) + strlen(h->value) + 8;
		buf = xmalloc(cap);
		start = p = buf + LWS_PRE;
		end = buf + cap - 1;
		rc = lws_add_http_header_status(wsi, (unsigned int)req->status,
		    &p, end);
		TAILQ_FOREACH(h, &req->resp_headers, list) {
			snprintf(name, sizeof(name), "%s:", h->name);
			if (rc == 0)
				rc = lws_add_http_header_by_name(wsi,
				    (unsigned char *)name, (unsigned char *)
				    h->value, (int)strlen(h->value), &p, end);
		}
		/* A stream's length is not known: it goes until it ends. */
		if (rc == 0 && req->stream == NULL)
			rc = lws_add_http_header_content_length(wsi,
			    (lws_filepos_t)req->resp_len, &p, end);
		if (rc == 0)
			rc = lws_finalize_write_http_header(wsi, start, &p, end);
		free(buf);
		if (rc != 0)
			return (ending(wsi, "the reply's headers could not be written"));
		req->headers_sent = true;
		if (req->stream != NULL || req->resp_len > 0) {
			lws_callback_on_writable(wsi);
			return (0);
		}
		/* No body: HTTP/2's stream still has to be ended. */
		buf = xmalloc(LWS_PRE + 1);
		rc = lws_write(wsi, buf + LWS_PRE, 0, LWS_WRITE_HTTP_FINAL);
		free(buf);
		if (rc < 0)
			return (ending(wsi, "the end of a reply without "
			    "a body could not be written"));
	} else if (req->stream != NULL) {
		/* What was put, a write at a time; its end once all is out. */
		if ((n = req->stream->offset) > 0) {
			if (n > WRITE_CHUNK)
				n = WRITE_CHUNK;
			if ((n = allowed(wsi, n)) == 0)
				return (0);
			buf = xmalloc(LWS_PRE + n);
			memcpy(buf + LWS_PRE, req->stream->data, n);
			rc = lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_HTTP);
			free(buf);
			if (rc < 0)
				return (ending(wsi, "a stream's piece could not be "
				    "written"));
			memmove(req->stream->data, req->stream->data + n,
			    req->stream->offset - n);
			req->stream->offset -= n;
			if (req->stream->offset > 0 || req->stream_end)
				lws_callback_on_writable(wsi);
			return (0);
		}
		if (!req->stream_end)
			return (0);
		buf = xmalloc(LWS_PRE + 1);
		rc = lws_write(wsi, buf + LWS_PRE, 0, LWS_WRITE_HTTP_FINAL);
		free(buf);
		if (rc < 0)
			return (ending(wsi, "a stream's end could not be written"));
	} else if (req->resp_off < req->resp_len) {
		n = req->resp_len - req->resp_off;
		if (n > WRITE_CHUNK)
			n = WRITE_CHUNK;
		else if (n > FINAL_MAX)
			n -= FINAL_MAX;		/* the last piece apart */
		if ((n = allowed(wsi, n)) == 0)
			return (0);
		if (req->resp_off + n == req->resp_len &&
		    lws_send_pipe_choked(wsi)) {
			lws_callback_on_writable(wsi);
			return (0);
		}
		buf = xmalloc(LWS_PRE + n);
		memcpy(buf + LWS_PRE, req->resp + req->resp_off, n);
		req->resp_off += n;
		rc = lws_write(wsi, buf + LWS_PRE, n, req->resp_off ==
		    req->resp_len ? LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP);
		free(buf);
		if (rc < 0)
			return (ending(wsi, "a reply's body could not be written"));
		if (req->resp_off < req->resp_len) {
			lws_callback_on_writable(wsi);
			return (0);
		}
	}
	/* All of it sent. */
	pss->req = NULL;
	req->wsi = NULL;
	req_free(req);
	return (done(wsi, "the reply done, the connection to close"));
}

/* A request whose headers and body are in: to its handler. */
static void
req_dispatch(struct http_request *req)
{

	lws_set_timeout(req->wsi, NO_PENDING_TIMEOUT, 0);
	req_run(req);
}

/* ---------------------------------------------------------------- */
/* WebSockets. */

void
ws_handshake(struct http_request *req, ws_connect_fn *c, ws_message_fn *m,
    ws_disconnect_fn *d)
{

	if (req->owner == NULL) {
		http_response(req, 400, NULL, 0);
		return;
	}
	req->owner->on_connect = c;
	req->owner->on_message = m;
	req->owner->on_disconnect = d;
	req->flags |= F_UPGRADE;
}

void
ws_send(struct conn *c, uint8_t op, const void *d, size_t len)
{
	struct wsmsg	*m;

	if (c->wsi == NULL)
		return;
	m = xmalloc(sizeof(*m) + LWS_PRE + len);
	m->len = len;
	m->off = 0;
	m->binary = op == WS_OP_BINARY;
	memcpy(m->data + LWS_PRE, d, len);
	STAILQ_INSERT_TAIL(&c->out, m, next);
	lws_callback_on_writable(c->wsi);
}

static void
conn_free(struct conn *c)
{
	struct wsmsg	*m;

	while ((m = STAILQ_FIRST(&c->out)) != NULL) {
		STAILQ_REMOVE_HEAD(&c->out, next);
		free(m);
	}
	buf_free(c->in);
	free(c->hdlr_extra);
	free(c);
}

/* An upgrade to a WebSocket: the route's handler says yes or no. */
static int
ws_filter(struct lws *wsi, struct pss *pss)
{
	struct http_request	*req;
	struct conn		*c;
	char			 path[1024];
	bool			 known;
	int			 ok;

	/* Over HTTP/1.1 a GET; over HTTP/2 a CONNECT (RFC 8441), its path
	 * in :path, the query with it. */
	if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI) <= 0 &&
	    lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_HTTP_COLON_PATH) <=
	    0)
		return (ending(wsi, "a WebSocket without a path"));
	path[strcspn(path, "?")] = '\0';
	req = req_new(wsi, path);
	req->method = HTTP_METHOD_GET;
	if ((req->rt = route_find(req->path, req->method, &known)) == NULL) {
		req->wsi = NULL;
		req_free(req);
		return (ending(wsi, "a WebSocket of no route"));
	}
	c = xcalloc(1, sizeof(*c));
	STAILQ_INIT(&c->out);
	req->owner = c;
	req->flags |= F_UPGRADE;	/* a refusal is not written */
	(void)req->rt->handler(req);
	ok = c->on_message != NULL && req->status == 0;
	req->wsi = NULL;
	req->owner = NULL;
	req_free(req);
	if (!ok) {
		conn_free(c);
		return (ending(wsi, "a WebSocket refused"));
	}
	pss->conn = c;
	return (0);
}

/* ---------------------------------------------------------------- */
/* libwebsockets' callback, for HTTP and the WebSocket both. */

static int
callback(struct lws *wsi, enum lws_callback_reasons reason, void *user,
    void *in, size_t len)
{
	struct pss		*pss = user;
	struct http_request	*req;
	struct http_body	*b;
	struct conn		*c;
	struct wsmsg		*m;
	size_t			 n;
	char			 cl[32];
	bool			 known;
	int			 rc;

	if (reason == LWS_CALLBACK_EVENT_WAIT_CANCELLED) {
		tasks_drain();
		return (0);
	}
	/* A vhost's SSL_CTX, in user: its certificate and key. */
	if (reason == LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS)
		return (srv.certfile != NULL && user != NULL && keymgr_tls(user,
		    srv.certfile) != 0 ? -1 : 0);
	/* A connection that went before it was given its data. */
	if (pss == NULL)
		return (lws_callback_http_dummy(wsi, reason, user, in, len));
	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (pss->req != NULL)
			return (ending(wsi, "a request while one is under way"));
		req = req_new(wsi, (const char *)in);
		if ((req->rt = route_find(req->path, req->method, &known)) ==
		    NULL) {
			if (!known && (req->method & (HTTP_METHOD_GET |
			    HTTP_METHOD_HEAD))) {
				req->wsi = NULL;
				req_free(req);
				if ((rc = serve_file(wsi, (const char *)in)) == 0)
					return (0);
				if (rc == -2)
					return (ending(wsi, "a file could not be served"));
				req = req_plain(wsi, (const char *)in, 404);
			} else {
				req->wsi = NULL;
				req_free(req);
				req = req_plain(wsi, (const char *)in, known ? 405 :
				    404);
			}
			pss->req = req;
			return (0);
		}
		pss->req = req;
		cl[0] = '\0';
		/* A chunked body libwebsockets does not take in: its length
		 * is asked for (browsers always say it). */
		if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING) >
		    0) {
			http_response(req, 411, NULL, 0);
			return (0);
		}
		/*
		 * A body to come first.  Its memory grows as it comes, not to
		 * what the client says it will send.
		 */
		if (lws_hdr_copy(wsi, cl, sizeof(cl),
		    WSI_TOKEN_HTTP_CONTENT_LENGTH) > 0 && strtoull(cl, NULL, 10) >
		    0) {
			if (strtoull(cl, NULL, 10) > srv.body_max) {
				http_response(req, 413, NULL, 0);
				return (0);
			}
			req->http_body = xcalloc(1, sizeof(*req->http_body));
			return (0);
		}
		req_dispatch(req);
		return (0);
	case LWS_CALLBACK_HTTP_BODY:
		if ((req = pss->req) == NULL || (b = req->http_body) == NULL ||
		    req->status != 0)
			return (0);
		if (b->length + len > srv.body_max) {
			http_response(req, 413, NULL, 0);
			return (0);
		}
		if (b->length + len > b->cap) {
			b->cap = b->cap == 0 ? 16384 : b->cap;
			while (b->cap < b->length + len)
				b->cap *= 2;
			b->data = xrealloc(b->data, b->cap);
		}
		memcpy(b->data + b->length, in, len);
		b->length += len;
		return (0);
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		if ((req = pss->req) != NULL && req->status == 0)
			req_dispatch(req);
		return (0);
	case LWS_CALLBACK_HTTP_WRITEABLE:
		return (req_write(wsi, pss));
	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
		return (done(wsi, "the file done, the connection to close"));
	case LWS_CALLBACK_CLOSED_HTTP:
		if ((req = pss->req) != NULL) {
			pss->req = NULL;
			req->wsi = NULL;
			req_free(req);
		}
		return (0);
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		return (ws_filter(wsi, pss));
	case LWS_CALLBACK_ESTABLISHED:
		if ((c = pss->conn) == NULL)
			return (ending(wsi, "a WebSocket without its connection"));
		c->wsi = wsi;
		if (c->on_connect != NULL)
			c->on_connect(c);
		return (0);
	case LWS_CALLBACK_RECEIVE:
		if ((c = pss->conn) == NULL)
			return (ending(wsi, "a WebSocket's message without its connection"));
		if (c->in == NULL)
			c->in = buf_alloc(len + 1);
		if (c->in->offset + len > WS_IN_MAX)
			return (ending(wsi, "a WebSocket's message too large"));
		buf_append(c->in, in, len);
		if (!lws_is_final_fragment(wsi) ||
		    lws_remaining_packet_payload(wsi) > 0)
			return (0);
		c->on_message(c, lws_frame_is_binary(wsi) ? WS_OP_BINARY :
		    WS_OP_TEXT, c->in->data, c->in->offset);
		buf_reset(c->in);
		return (0);
	case LWS_CALLBACK_SERVER_WRITEABLE:
		if ((c = pss->conn) == NULL || (m = STAILQ_FIRST(&c->out)) ==
		    NULL)
			return (0);
		/* The next fragment; what lws puts before it overwrites
		 * the end of the one sent before, which is gone. */
		n = m->len - m->off;
		if (n > WS_FRAG)
			n = WS_FRAG;
		/* A message of none (n = 0) is written as it is. */
		if (n > 0 && (n = allowed(wsi, n)) == 0)
			return (0);
		rc = lws_write(wsi, m->data + LWS_PRE + m->off, n,
		    (enum lws_write_protocol)lws_write_ws_flags(m->binary ?
		    LWS_WRITE_BINARY : LWS_WRITE_TEXT, m->off == 0, m->off + n ==
		    m->len));
		if (rc < 0)
			return (ending(wsi, "a WebSocket's message could not be written"));
		if ((m->off += n) == m->len) {
			STAILQ_REMOVE_HEAD(&c->out, next);
			free(m);
		}
		if (!STAILQ_EMPTY(&c->out))
			lws_callback_on_writable(wsi);
		return (0);
	case LWS_CALLBACK_CLOSED:
		if ((c = pss->conn) != NULL) {
			pss->conn = NULL;
			c->wsi = NULL;
			if (c->on_disconnect != NULL)
				c->on_disconnect(c);
			conn_free(c);
		}
		return (0);
	default:
		break;
	}
	return (lws_callback_http_dummy(wsi, reason, user, in, len));
}

static const struct lws_protocols protocols[] = {
	{ "arcana", callback, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* ---------------------------------------------------------------- */
/* The configuration, the worker and its supervisor. */

static void
lws_emit(int level, const char *line)
{
	char	buf[1024];
	size_t	n;

	(void)level;
	strlcpy(buf, line, sizeof(buf));
	n = strlen(buf);
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = '\0';
	log_msg(LOG_ERR, "lws: %s", buf);
}

static const char *
conf_str(const ucl_object_t *o, const char *key, const char *dflt)
{
	const ucl_object_t	*v;

	if (o == NULL || (v = ucl_object_lookup(o, key)) == NULL ||
	    ucl_object_type(v) != UCL_STRING)
		return (dflt);
	return (ucl_object_tostring(v));
}

/* web.conf's server { }; it is read again, whole, by the console. */
static void
conf_read(void)
{
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*s, *l, *e;
	ucl_object_iter_t	 it;
	const char		*v;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO);
	if (!ucl_parser_add_file(p, web_conf_path))
		errx(EX_CONFIG, "%s: %s", web_conf_path, ucl_parser_get_error(p));
	top = ucl_parser_get_object(p);
	ucl_parser_free(p);
	s = ucl_object_lookup(top, "server");
	srv.nlisten = 0;
	if ((l = ucl_object_lookup(s, "listen")) != NULL) {
		it = NULL;
		while ((e = ucl_object_iterate(l, &it, true)) != NULL &&
		    srv.nlisten < LISTEN_MAX)
			if (ucl_object_type(e) == UCL_STRING)
				srv.listen[srv.nlisten++] = xstrdup(
				    ucl_object_tostring(e));
	}
	if (srv.nlisten == 0) {
		srv.listen[srv.nlisten++] = xstrdup("0.0.0.0:443");
		srv.listen[srv.nlisten++] = xstrdup("[::]:443");
	}
	if ((v = conf_str(s, "certfile", NULL)) != NULL)
		srv.certfile = xstrdup(v);
	if ((v = conf_str(s, "certkey", NULL)) != NULL)
		srv.certkey = xstrdup(v);
	if ((srv.certfile == NULL) != (srv.certkey == NULL))
		errx(EX_CONFIG, "%s: server: certfile and certkey go together",
		    web_conf_path);
	srv.webroot = xstrdup(conf_str(s, "webroot", ARCW_WEBROOT));
	srv.user = xstrdup(conf_str(s, "user", "arcana"));
	srv.pidfile = xstrdup(conf_str(s, "pidfile",
	    "/var/run/arcana-console.pid"));
	srv.task_threads = 32;
	if ((e = ucl_object_lookup(s, "task_threads")) != NULL)
		srv.task_threads = (int)ucl_object_toint(e);
	if (srv.task_threads < 1 || srv.task_threads > 1024)
		errx(EX_CONFIG, "%s: server: task_threads is 1 to 1024",
		    web_conf_path);
	srv.body_max = 8 * 1024 * 1024;
	if ((e = ucl_object_lookup(s, "body_max")) != NULL) {
		if (ucl_object_toint(e) < 1024 || ucl_object_toint(e) >
		    1024 * 1024 * 1024)
			errx(EX_CONFIG, "%s: server: body_max is 1 KB to 1 GB",
			    web_conf_path);
		srv.body_max = (size_t)ucl_object_toint(e);
	}
	web_certfile = srv.certfile;
	web_certkey = srv.certkey;
	ucl_object_unref(top);
}

/*
 * A listen line, "unix:/path", "[addr]:port" or "addr:port": its path
 * or address and port.  An IPv6 address listens for IPv6 alone.
 */
static void
listen_parse(const char *spec, char *addr, size_t len, int *portp, int *famp)
{
	char	*c;

	if (strncmp(spec, "unix:", 5) == 0) {
		strlcpy(addr, spec + 5, len);
		*portp = 0;
		*famp = AF_UNIX;
		return;
	}
	if (spec[0] == '[') {
		strlcpy(addr, spec + 1, len);
		if ((c = strchr(addr, ']')) == NULL || c[1] != ':')
			errx(EX_CONFIG, "listen %s: [address]:port", spec);
		*c = '\0';
		*famp = AF_INET6;
	} else {
		strlcpy(addr, spec, len);
		if ((c = strrchr(addr, ':')) == NULL)
			errx(EX_CONFIG, "listen %s: address:port", spec);
		*c = '\0';
		*famp = AF_INET;
	}
	*portp = atoi(c + (*famp == AF_INET6 ? 2 : 1));
	if (*portp <= 0 || *portp > 65535)
		errx(EX_CONFIG, "listen %s: no port", spec);
	if (addr[0] == '\0')
		strlcpy(addr, *famp == AF_INET6 ? "::" : "0.0.0.0", len);
}

/*
 * The listening sockets, made once by the supervisor (as root, for a
 * port below 1024) and kept: a worker started again serves on them, and
 * a client is never refused while it starts.
 */
static void
listen_open(void)
{
	struct sockaddr_storage	 ss;
	struct sockaddr_un	*sun;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	socklen_t		 sl;
	char			 addr[MAXPATHLEN];
	int			 k, fd, port, fam, on;

	for (k = 0; k < srv.nlisten; k++) {
		listen_parse(srv.listen[k], addr, sizeof(addr), &port, &fam);
		memset(&ss, 0, sizeof(ss));
		if (fam == AF_UNIX) {
			sun = (struct sockaddr_un *)&ss;
			sun->sun_family = AF_UNIX;
			if (strlcpy(sun->sun_path, addr, sizeof(sun->sun_path)) >=
			    sizeof(sun->sun_path))
				errx(EX_CONFIG, "listen %s: too long", addr);
			(void)unlink(addr);
			sl = (socklen_t)SUN_LEN(sun);
		} else if (fam == AF_INET) {
			sin = (struct sockaddr_in *)&ss;
			sin->sin_family = AF_INET;
			sin->sin_port = htons((uint16_t)port);
			if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1)
				errx(EX_CONFIG, "listen %s: not an address",
				    srv.listen[k]);
			sl = sizeof(*sin);
		} else {
			sin6 = (struct sockaddr_in6 *)&ss;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons((uint16_t)port);
			if (inet_pton(AF_INET6, addr, &sin6->sin6_addr) != 1)
				errx(EX_CONFIG, "listen %s: not an address",
				    srv.listen[k]);
			sl = sizeof(*sin6);
		}
		if ((fd = socket(fam, SOCK_STREAM, 0)) == -1)
			err(EX_OSERR, "listen %s", srv.listen[k]);
		on = 1;
		if (fam != AF_UNIX)
			(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on,
			    sizeof(on));
		if (fam == AF_INET6)
			(void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on,
			    sizeof(on));
		if (bind(fd, (struct sockaddr *)&ss, sl) == -1 ||
		    listen(fd, SOMAXCONN) == -1)
			err(EX_OSERR, "listen %s", srv.listen[k]);
		/* The console's user connects to a local one too. */
		if (fam == AF_UNIX)
			(void)chmod(addr, 0666);
		(void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
		srv.lfd[k] = fd;
	}
}

/*
 * No validity timer: libwebsockets hangs up a connection it has not
 * seen valid for 50 s, and over HTTP/2 its streams' traffic (a page's
 * WebSocket among them) does not count, so a busy connection went too.
 * A peer that is gone is found by TCP's keepalive instead (vhost_new).
 */
static const lws_retry_bo_t no_validity = {
	.secs_since_valid_ping = 0,
	.secs_since_valid_hangup = 0,
};

static struct lws_vhost *
vhost_new(int k)
{
	struct lws_context_creation_info	 info;
	char					 name[16], addr[MAXPATHLEN];
	int					 port, fam;

	listen_parse(srv.listen[k], addr, sizeof(addr), &port, &fam);
	memset(&info, 0, sizeof(info));
	snprintf(name, sizeof(name), "l%d", k);
	info.vhost_name = name;
	info.protocols = protocols;
	info.max_http_header_data = HDR_MAX;
	/*
	 * HTTP/2 over TLS (no browser speaks it plain), HTTP/1.1 beside it
	 * and on plain connections.  libwebsockets 5.0 drops, over HTTP/2,
	 * a header it has no name for (X-Arcana) when the client sends it
	 * as an index into HPACK's dynamic table, as browsers do from its
	 * second use on a connection: the console judges a browser's
	 * change by its Origin (api.c guard()), a standard header.
	 */
	info.alpn = "http/1.1";
	info.keepalive_timeout = 60;
	info.timeout_secs = 60;
	info.retry_and_idle_policy = &no_validity;
	info.ka_time = 120;
	info.ka_probes = 4;
	info.ka_interval = 15;
	info.vh_listen_sockfd = srv.lfd[k];
	if (fam == AF_UNIX) {
		info.options |= LWS_SERVER_OPTION_UNIX_SOCK;
		info.iface = addr;
		info.port = 0;
	} else {
		info.port = port;
		if (fam == AF_INET)
			info.options |= LWS_SERVER_OPTION_DISABLE_IPV6;
		/* TLS is the vhost's own choice in libwebsockets: without
		 * the option here too it speaks plain HTTP. */
		/*
		 * The vhost's SSL_CTX made empty, its certificate and the
		 * key manager's key put on it by the callback
		 * (LOAD_EXTRA_SERVER_VERIFY_CERTS): the key is never read
		 * here.  TLS 1.2 and 1.3, 1.2's key exchange ECDHE alone:
		 * the key manager signs, it decrypts nothing.
		 */
		if (srv.certfile != NULL) {
			info.alpn = "h2,http/1.1";
			info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
			    LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX;
			info.ssl_cipher_list = "ECDHE+AESGCM:ECDHE+CHACHA20";
			info.ssl_options_set = SSL_OP_NO_TLSv1 |
			    SSL_OP_NO_TLSv1_1;
		}
	}
	return (lws_create_vhost(ctx, &info));
}

static void
on_term(int sig)
{

	(void)sig;
	quit = 1;
	if (ctx != NULL)
		lws_cancel_service(ctx);
}

static void __dead2
worker(void)
{
	struct lws_context_creation_info	 info;
	struct passwd				*pw;
	pthread_t				 th;
	size_t					 i;
	int					 k;

	setproctitle("worker");
	debug_ends = getenv("ARCANA_DEBUG") != NULL;
	/* The key's own process, before anything else is started here. */
	if (srv.certfile != NULL && keymgr_start(srv.certfile, srv.certkey,
	    srv.user, srv.lfd, srv.nlisten) != 0)
		fatalx("the HTTPS key: not starting, see above");
	signal(SIGTERM, on_term);
	signal(SIGINT, on_term);
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	/* libwebsockets' own log: its errors, or what ARCANA_LWS_LOG asks
	 * (its LLL_ bits: 7 adds warnings and notices, 15 information). */
	lws_set_log_level(getenv("ARCANA_LWS_LOG") != NULL ?
	    atoi(getenv("ARCANA_LWS_LOG")) : LLL_ERR, lws_emit);
	route_re = xcalloc(nroutes, sizeof(*route_re));
	for (i = 0; i < nroutes; i++)
		if (routes[i].path[0] == '^' && regcomp(&route_re[i],
		    routes[i].path, REG_EXTENDED | REG_NOSUB) != 0)
			fatalx("route %s: not an expression", routes[i].path);
	memset(&info, 0, sizeof(info));
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
	    LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.gid = (gid_t)-1;
	info.uid = (uid_t)-1;
	if ((ctx = lws_create_context(&info)) == NULL)
		fatalx("cannot start libwebsockets");
	for (k = 0; k < srv.nlisten; k++)
		if (vhost_new(k) == NULL)
			fatalx("cannot serve on %s", srv.listen[k]);
	/* Listening: the console's own user from now on. */
	if (geteuid() == 0 && srv.user[0] != '\0') {
		if ((pw = getpwnam(srv.user)) == NULL)
			fatalx("no user %s to run as", srv.user);
		if (initgroups(pw->pw_name, pw->pw_gid) == -1 ||
		    setgid(pw->pw_gid) == -1 || setuid(pw->pw_uid) == -1)
			fatalx("cannot become %s: %s", srv.user, strerror(errno));
	}
	for (k = 0; k < srv.task_threads; k++)
		if (pthread_create(&th, NULL, pool_thread, NULL) != 0)
			fatalx("cannot start the task threads");
	if (arcw_init() != WEB_OK)
		fatalx("arcana: not starting, see above");
	while (!quit)
		if (lws_service(ctx, 0) < 0)
			break;
	lws_context_destroy(ctx);
	_exit(0);
}

static pid_t			child;
static volatile sig_atomic_t	stopping;

static void
on_stop(int sig)
{

	(void)sig;
	stopping = 1;
	if (child > 0)
		(void)kill(child, SIGTERM);
}

static void __dead2
usage(void)
{

	fprintf(stderr, "usage: arcana-console [-dn] [-c web.conf]\n");
	exit(EX_USAGE);
}

int
main(int argc, char **argv)
{
	struct pidfh	*pfh;
	pid_t		 pid;
	time_t		 started;
	bool		 daemonise, supervise;
	int		 ch, status;
	const char	*env;

	daemonise = false;
	supervise = true;
	if ((env = getenv("ARCANA_WEB_CONF")) != NULL)
		web_conf_path = env;
	while ((ch = getopt(argc, argv, "c:dn")) != -1)
		switch (ch) {
		case 'c':
			web_conf_path = optarg;
			break;
		case 'd':
			daemonise = true;
			break;
		case 'n':
			supervise = false;
			break;
		default:
			usage();
		}
	if (optind != argc)
		usage();
	conf_read();
	listen_open();
	pfh = NULL;
	if (daemonise) {
		pfh = pidfile_open(srv.pidfile, 0644, &pid);
		if (pfh == NULL && errno == EEXIST)
			errx(EX_UNAVAILABLE, "running already, pid %d", (int)pid);
		if (daemon(0, 0) == -1)
			err(EX_OSERR, "daemon");
		foreground = false;
		openlog("arcana-console", LOG_PID | LOG_NDELAY, LOG_DAEMON);
		if (pfh != NULL)
			(void)pidfile_write(pfh);
	}
	if (!supervise)
		worker();
	setproctitle("supervisor");
	signal(SIGTERM, on_stop);
	signal(SIGINT, on_stop);
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	while (!stopping) {
		started = time(NULL);
		if ((child = fork()) == -1) {
			log_msg(LOG_ERR, "fork: %s", strerror(errno));
			sleep(1);
			continue;
		}
		if (child == 0) {
			if (pfh != NULL)
				pidfile_close(pfh);
			worker();
		}
		log_msg(LOG_NOTICE, "worker started (pid %d)", (int)child);
		while (waitpid(child, &status, 0) == -1 && errno == EINTR)
			;
		child = 0;
		if (stopping)
			break;
		if (WIFEXITED(status) && WEXITSTATUS(status) == EX_CONFIG) {
			log_msg(LOG_ERR, "the worker cannot run: stopping");
			break;
		}
		log_msg(LOG_ERR, "worker exited with status %d%s",
		    WIFEXITED(status) ? WEXITSTATUS(status) : 128 +
		    WTERMSIG(status), WIFSIGNALED(status) ? " (killed)" : "");
		/* Not over and over when it dies at once. */
		if (time(NULL) - started < 2)
			sleep(1);
	}
	if (pfh != NULL)
		pidfile_remove(pfh);
	return (0);
}
