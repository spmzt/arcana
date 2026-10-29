/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console's HTTP server, on libwebsockets(3): the requests and their
 * replies, the routes, a WebSocket, the tasks that run what takes time
 * on threads of their own, timers, and the small helpers the handlers
 * share (buffers, allocation, base64, the log).
 *
 * A handler runs on the server's loop, one at a time, and answers with
 * http_response(), returning WEB_OK; or it starts a task and returns
 * WEB_RETRY, and is run again once the task is done (or at once, when
 * it did not put the request to sleep), until it answers.  A request's
 * hdlr_extra is the handler's: the route's on_free is called before the
 * request goes, again while a task of it still runs, and hdlr_extra is
 * then freed with free(3).
 */

#ifndef WEB_H
#define WEB_H

#include <sys/types.h>
#include <sys/queue.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <syslog.h>

#define	WEB_ERROR	0
#define	WEB_OK		1
#define	WEB_RETRY	2

#define	HTTP_METHOD_GET		0x01
#define	HTTP_METHOD_POST	0x02
#define	HTTP_METHOD_PUT		0x04
#define	HTTP_METHOD_DELETE	0x08
#define	HTTP_METHOD_HEAD	0x10
#define	HTTP_METHOD_OPTIONS	0x20
#define	HTTP_METHOD_PATCH	0x40

#define	HTTP_STATUS_INTERNAL_ERROR	500

#define	WS_OP_TEXT	1
#define	WS_OP_BINARY	2

/* What a growing text is kept in. */
struct buf {
	char	*data;
	size_t	 offset;
	size_t	 length;
};

struct buf	*buf_alloc(size_t);
void		 buf_free(struct buf *);
void		 buf_append(struct buf *, const void *, size_t);
void		 buf_appendf(struct buf *, const char *, ...)
		    __printflike(2, 3);
void		 buf_appendv(struct buf *, const char *, va_list);
char		*buf_stringify(struct buf *, size_t *);
void		 buf_reset(struct buf *);

/* Allocation that does not come back without memory. */
void		*xmalloc(size_t);
void		*xcalloc(size_t, size_t);
void		*xrealloc(void *, size_t);
char		*xstrdup(const char *);

/* The log: syslog(3), or the standard error in the foreground; from
 * any thread. */
void		 log_msg(int, const char *, ...) __printflike(2, 3);
/* The console stops, its supervisor too: what is wrong is in the
 * configuration or the data, and starting again would not mend it. */
void		 fatalx(const char *, ...) __printflike(1, 2) __dead2;

/* Base64, the standard alphabet with padding; and the URL one, without
 * padding with B64_RAW.  WEB_OK, or WEB_ERROR. */
#define	B64_RAW		0x01
int		 b64_encode(const void *, size_t, char **);
int		 b64url_encode(const void *, size_t, char **, int);
int		 b64url_decode(const char *, uint8_t **, size_t *, int);

/* A WebSocket's end, for as long as the socket is open. */
struct conn;
typedef void	ws_connect_fn(struct conn *);
typedef void	ws_message_fn(struct conn *, uint8_t, void *, size_t);
typedef void	ws_disconnect_fn(struct conn *);

struct conn {
	void			*hdlr_extra;	/* the handler's */
	struct lws		*wsi;
	ws_connect_fn		*on_connect;
	ws_message_fn		*on_message;
	ws_disconnect_fn	*on_disconnect;
	STAILQ_HEAD(, wsmsg)	 out;		/* to be sent */
	struct buf		*in;		/* a message being received */
};

void		 ws_send(struct conn *, uint8_t, const void *, size_t);

/* The request's body, kept in memory whole. */
struct http_body {
	uint8_t	*data;
	size_t	 cap;		/* of data */
	size_t	 length;
	size_t	 offset;	/* how far http_body_read() has read */
};

struct http_header {
	TAILQ_ENTRY(http_header) list;
	char	*name;		/* in lower case */
	char	*value;
};
TAILQ_HEAD(http_header_list, http_header);

struct http_arg {
	TAILQ_ENTRY(http_arg) list;
	char	*name;
	char	*value;		/* decoded */
};

struct route;
struct task;

struct http_request {
	int			 method;
	char			*path;		/* decoded */
	char			*query_string;	/* escaped, as a URL has it */
	void			*hdlr_extra;	/* the handler's */
	struct conn		*owner;		/* of a WebSocket being made */
	struct http_body	*http_body;	/* NULL when it had none */

	/* The server's own. */
	struct lws		*wsi;		/* NULL once the client went */
	const struct route	*rt;
	struct http_header_list	 headers;
	TAILQ_HEAD(, http_arg)	 args;
	TAILQ_HEAD(, http_arg)	 cookies;
	LIST_HEAD(, task)	 tasks;		/* bound to it */
	struct http_header_list	 resp_headers;
	int			 status;	/* of the reply; 0: none yet */
	uint8_t			*resp;
	size_t			 resp_len, resp_off;
	bool			 headers_sent;
	bool			 chunked;	/* a stream over HTTP/1.1: framed */
	struct buf		*stream;	/* a reply that does not end: what
						 * waits to be written */
	bool			 stream_end;
	int			 flags;
	TAILQ_ENTRY(http_request) list;
};

/* A route: an exact path, or a POSIX extended expression when it starts
 * with ^; its handler for the methods named, and what is called before
 * the request goes. */
typedef int	http_handler(struct http_request *);
typedef void	http_free_fn(struct http_request *);

struct route {
	const char	*path;
	http_handler	*handler;
	http_free_fn	*on_free;
	int		 methods;
};
extern const struct route	routes[];
extern const size_t		nroutes;

void		 http_response(struct http_request *, int, const void *,
		    size_t);
const char	*web_peer(struct http_request *, char *, size_t);
void		 http_response_header(struct http_request *, const char *,
		    const char *);
/*
 * A reply whose length is not known first (Server-Sent Events, a file
 * read from a host): http_stream() sends the headers set, with no
 * length (over HTTP/1.1 chunked, so that a client kept open knows where
 * it ends; HTTP/2 frames its own); http_stream_put() each piece of its
 * body, in the worker; http_stream_end() ends it once what was put is
 * out.  The client going frees the request, its route's on_free first.
 */
void		 http_stream(struct http_request *, int);
void		 http_stream_put(struct http_request *, const void *, size_t);
void		 http_stream_end(struct http_request *);
int		 http_request_header(struct http_request *, const char *,
		    const char **);
int		 http_request_cookie(struct http_request *, const char *,
		    char **);
/* out: a char ** or a const char ** */
int		 http_argument_get_string(struct http_request *, const char *,
		    void *);
int		 http_argument_urldecode(char *, int);
ssize_t		 http_body_read(struct http_request *, void *, size_t);
void		 http_request_sleep(struct http_request *);
void		 http_request_wakeup(struct http_request *);
/* The request becomes a WebSocket with these callbacks, on its own
 * connection (req->owner) whose hdlr_extra the handler may have set. */
void		 ws_handshake(struct http_request *, ws_connect_fn *,
		    ws_message_fn *, ws_disconnect_fn *);

/* Tasks: a function run on a thread of the pool, its struct task first
 * in the caller's.  Bound to a request, the request's handler runs again
 * once it is done; bound to a callback, the callback runs on the loop
 * whenever the task wrote on its channel and once it is done. */
#define	TASK_STATE_CREATED	1
#define	TASK_STATE_RUNNING	2
#define	TASK_STATE_FINISHED	3

struct task_msg;
typedef int	task_fn(struct task *);
typedef void	task_cb(struct task *);

struct task {
	task_fn			*entry;
	task_cb			*cb;
	struct http_request	*req;
	int			 state;
	int			 result;
	bool			 queued;	/* on the loop's list of ready */
	bool			 destroyed;
	pthread_mutex_t		 lock;
	STAILQ_HEAD(, task_msg)	 chan;		/* from the task to the loop */
	TAILQ_ENTRY(task)	 list;
	LIST_ENTRY(task)	 rlist;		/* its request's */
	/* The console user it acts for, its request's: what the hosts'
	 * access rules hold it to (hosts_act_as()); "": the console. */
	char			 user[64];
};

/* The program's: the user a request acts for (NULL: none); this thread
 * acting for a user (NULL: for nobody). */
const char	*web_user(struct http_request *);
void		 web_act_as(const char *);

void		 task_create(struct task *, task_fn *);
void		 task_bind_request(struct task *, struct http_request *);
void		 task_bind_callback(struct task *, task_cb *);
void		 task_run(struct task *);
int		 task_state(struct task *);
int		 task_finished(struct task *);
void		 task_destroy(struct task *);
void		 task_channel_write(struct task *, const void *, uint32_t);
/* The next message's length (what did not fit in len is dropped). */
uint32_t	 task_channel_read(struct task *, void *, uint32_t);
bool		 task_channel_pending(struct task *);

/* Timers on the loop: every ms, or once with TIMER_ONESHOT. */
#define	TIMER_ONESHOT	0x01
struct timer;
typedef void	timer_fn(void *, uint64_t);
struct timer	*timer_add(timer_fn *, uint64_t, void *, int);

/* The application's start, on the loop, once the server listens and
 * runs as its user. */
int		 arcw_init(void);
/* The web.conf the console reads. */
extern const char	*web_conf_path;
/* Its certificate and key, of server { }; NULL without TLS. */
extern const char	*web_certfile, *web_certkey;
/*
 * A client certificate asked for on the TLS listeners, verified by the
 * CA file (the console's), any accepted: web_peer_cert() gives a
 * request's where it verified (freed by the caller), else NULL.
 */
void		 web_client_ca(const char *);
/* Strict-Transport-Security's max-age over TLS, in seconds; 0 for none. */
void		 web_hsts(int);
struct x509_st;
struct x509_st	*web_peer_cert(struct http_request *);

#endif /* !WEB_H */
