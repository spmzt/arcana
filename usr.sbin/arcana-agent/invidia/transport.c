/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * How the agent is reached.  Beside every TCP listener it was told to
 * have, it has an SCTP one at the same address and port: one
 * association carries every request as a message of its own, and is
 * not stalled by one that is lost.  SCTP is in the kernel or it is
 * not: the agent does not load it, and where it is missing it does not
 * try again by itself.  It tries when it is told to (the transport
 * operation with retry), which is what follows loading the module from
 * the console.
 *
 * The connections open now are kept here too, as cblink says they come
 * and go, for who wants to see them.
 *
 * A listener is added or closed while the agent runs, when the console
 * moves the host to another address: the new one listened on beside
 * the old, tried, and only then the old one closed (and the change kept
 * in rc.conf); each in the loop's thread, as the listeners are its.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <ucl.h>

#include "agent.h"

#define	T_LISTEN	32
#define	T_SESSIONS	256

struct tlisten {
	char		 uri[256];
	cbl_listener	*l;
	bool		 up;
	bool		 sctp;		/* one of ours, beside a TCP one */
	char		 error[160];
};

struct tsession {
	cbl_conn	*conn;
	char		 transport[8];
	char		 addr[96];
	char		 subject[128];
	time_t		 since;
};

static pthread_mutex_t	t_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	t_cv = PTHREAD_COND_INITIALIZER;
static struct tlisten	lst[T_LISTEN];
static int		nlst;
static struct tsession	ses[T_SESSIONS];
static int		nses;
static uint64_t		ses_seen;	/* all there ever were */
static cbl_ctx		*t_ctx;
static cbl_loop		*t_loop;
static cbl_tls		*t_tls;
static bool		 t_busy;

static const char *
transport_name(enum cbl_transport t)
{

	return (t == CBL_TR_SCTP ? "sctp" : t == CBL_TR_UNIX ? "unix" : "tcp");
}

static void
on_open(cbl_conn *conn, void *arg __unused)
{
	struct sockaddr_storage	 ss;
	const cbl_peer		*peer;
	const char		*subj;
	struct tsession		*s;
	socklen_t		 len;
	char			 host[64], port[8];

	pthread_mutex_lock(&t_lock);
	ses_seen++;
	if (nses == T_SESSIONS) {
		pthread_mutex_unlock(&t_lock);
		return;
	}
	s = &ses[nses++];
	memset(s, 0, sizeof(*s));
	s->conn = conn;
	s->since = time(NULL);
	snprintf(s->transport, sizeof(s->transport), "%s", transport_name(
	    cbl_conn_transport(conn)));
	peer = cbl_conn_peer(conn);
	len = sizeof(ss);
	if (peer != NULL && cbl_peer_addr(peer, &ss, &len) == 0 &&
	    ss.ss_family != AF_UNIX && getnameinfo((struct sockaddr *)&ss,
	    len, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST |
	    NI_NUMERICSERV) == 0)
		snprintf(s->addr, sizeof(s->addr), ss.ss_family == AF_INET6 ?
		    "[%s]:%s" : "%s:%s", host, port);
	if (peer != NULL && (subj = cbl_peer_subject(peer)) != NULL)
		snprintf(s->subject, sizeof(s->subject), "%s", subj);
	pthread_mutex_unlock(&t_lock);
}

static void
on_close(cbl_conn *conn, int error __unused, void *arg __unused)
{
	int	i;

	pthread_mutex_lock(&t_lock);
	for (i = 0; i < nses; i++)
		if (ses[i].conn == conn) {
			ses[i] = ses[--nses];
			break;
		}
	pthread_mutex_unlock(&t_lock);
}

/*
 * Hear of every connection as it comes and goes.  Before the context
 * has a listener: it takes no callbacks after.
 */
int
transport_watch(cbl_ctx *ctx)
{
	static const struct cbl_conn_cbs	cbs = {
		.on_open = on_open,
		.on_close = on_close,
	};

	return (cbl_ctx_set_conn_cbs(ctx, &cbs, NULL));
}

/* What the loop was given to do is done: the next may begin. */
static void
loop_done(void)
{

	pthread_mutex_lock(&t_lock);
	t_busy = false;
	pthread_cond_broadcast(&t_cv);
	pthread_mutex_unlock(&t_lock);
}

/* A listener the agent was told to have, and has. */
void
transport_add(const char *uri, cbl_listener *l)
{

	if (nlst == T_LISTEN)
		return;
	snprintf(lst[nlst].uri, sizeof(lst[nlst].uri), "%s", uri);
	lst[nlst].l = l;
	lst[nlst].up = true;
	nlst++;
}

/* Start the SCTP listeners that are not up.  In the loop's thread. */
static void
sctp_start(void *arg __unused)
{
	struct tlisten	*t;
	int		 i, error;

	for (i = 0; i < nlst; i++) {
		t = &lst[i];
		if (!t->sctp || t->up)
			continue;
		if (t->l != NULL) {
			cbl_listener_free(t->l);
			t->l = NULL;
		}
		t->error[0] = '\0';
		if ((error = cbl_listener_new(t_ctx, t->uri, 0, &t->l)) != 0) {
			snprintf(t->error, sizeof(t->error), "%s", strerror(
			    error));
			t->l = NULL;
			continue;
		}
		if ((error = cbl_listener_set_tls(t->l, t_tls)) != 0 ||
		    (error = cbl_listener_start(t->l, t_loop)) != 0) {
			snprintf(t->error, sizeof(t->error), "%s",
			    cbl_listener_errstr(t->l) != NULL &&
			    cbl_listener_errstr(t->l)[0] != '\0' ?
			    cbl_listener_errstr(t->l) : strerror(error));
			cbl_listener_free(t->l);
			t->l = NULL;
			logmsg(LOG_WARNING, "%s: %s", t->uri, t->error);
			continue;
		}
		t->up = true;
		logmsg(LOG_INFO, "listening on %s", t->uri);
	}
	loop_done();
}

/*
 * Does the kernel have SCTP: compiled in, which kern.features.sctp
 * says (the module registers it too), or the module loaded.
 */
static bool
kernel_has_sctp(void)
{
	int	have;
	size_t	len;

	len = sizeof(have);
	if (sysctlbyname("kern.features.sctp", &have, &len, NULL, 0) == 0 &&
	    have != 0)
		return (true);
	return (kmod_loaded("sctp"));
}

/*
 * After the listeners asked for are up: an SCTP one for every TCP one,
 * started now when the kernel has SCTP, and left for transport_retry()
 * when it has not.
 */
void
transport_init(cbl_ctx *ctx, cbl_loop *loop, cbl_tls *tls)
{
	int	i, n;
	bool	have;

	t_ctx = ctx;
	t_loop = loop;
	t_tls = tls;
	n = nlst;
	for (i = 0; i < n && nlst < T_LISTEN; i++) {
		int	k;

		if (strncmp(lst[i].uri, "tcp://", 6) != 0)
			continue;
		snprintf(lst[nlst].uri, sizeof(lst[nlst].uri), "sctp://%s",
		    lst[i].uri + 6);
		/* Asked for by itself as well: not twice. */
		for (k = 0; k < n; k++)
			if (strcmp(lst[k].uri, lst[nlst].uri) == 0)
				break;
		if (k < n)
			continue;
		lst[nlst].sctp = true;
		nlst++;
	}
	have = kernel_has_sctp();
	for (i = n; i < nlst; i++)
		if (!have)
			snprintf(lst[i].error, sizeof(lst[i].error), "the "
			    "kernel has no SCTP: not compiled in "
			    "(kern.features.sctp), and the sctp module is not "
			    "loaded");
	if (have && nlst > n)
		sctp_start(NULL);
}

/*
 * From a request's thread: fn run by the loop, one at a time, and waited
 * for; fn says it is done by loop_done().
 */
static const char *
in_loop(void (*fn)(void *), void *arg)
{
	int	error;

	pthread_mutex_lock(&t_lock);
	while (t_busy)
		pthread_cond_wait(&t_cv, &t_lock);
	t_busy = true;
	pthread_mutex_unlock(&t_lock);
	if ((error = cbl_loop_post(t_loop, fn, arg)) != 0) {
		loop_done();
		return (strerror(error));
	}
	pthread_mutex_lock(&t_lock);
	while (t_busy)
		pthread_cond_wait(&t_cv, &t_lock);
	pthread_mutex_unlock(&t_lock);
	return (NULL);
}

/* From a request's thread: have the loop start them, and wait for it. */
static const char *
transport_retry(void)
{

	if (!kernel_has_sctp())
		return ("the kernel has no SCTP: it is not compiled in "
		    "(kern.features.sctp), so load the sctp module first, from "
		    "the kernel's modules");
	return (in_loop(sctp_start, NULL));
}

struct tchange {
	const char	*uri;
	bool		 add;
	char		 error[200];
};

/* A listener at uri, up: its error said when it is not. */
static int
listener_up(const char *uri, cbl_listener **lp, char *why, size_t len)
{
	cbl_listener	*l;
	int		 error;

	*lp = NULL;
	if ((error = cbl_listener_new(t_ctx, uri, 0, &l)) != 0) {
		snprintf(why, len, "%s", strerror(error));
		return (-1);
	}
	if ((error = cbl_listener_set_tls(l, t_tls)) != 0 ||
	    (error = cbl_listener_start(l, t_loop)) != 0) {
		snprintf(why, len, "%s", cbl_listener_errstr(l) != NULL &&
		    cbl_listener_errstr(l)[0] != '\0' ? cbl_listener_errstr(l) :
		    strerror(error));
		cbl_listener_free(l);
		return (-1);
	}
	*lp = l;
	return (0);
}

/*
 * In the loop's thread: a listener added (an SCTP one beside a TCP one,
 * once the kernel has SCTP: its failing is said, not fatal), or one
 * closed with the SCTP one beside it.
 */
static void
listen_change(void *arg)
{
	struct tchange	*tc = arg;
	cbl_listener	*l;
	char		 sib[256], why[160];
	int		 i;

	sib[0] = '\0';
	if (strncmp(tc->uri, "tcp://", 6) == 0)
		snprintf(sib, sizeof(sib), "sctp://%s", tc->uri + 6);
	if (tc->add) {
		for (i = 0; i < nlst; i++)
			if (strcmp(lst[i].uri, tc->uri) == 0 && lst[i].up)
				goto out;
		if (nlst + 2 > T_LISTEN) {
			snprintf(tc->error, sizeof(tc->error), "%d listeners "
			    "at most", T_LISTEN);
			goto out;
		}
		if (listener_up(tc->uri, &l, why, sizeof(why)) != 0) {
			snprintf(tc->error, sizeof(tc->error), "%s: %s",
			    tc->uri, why);
			goto out;
		}
		pthread_mutex_lock(&t_lock);
		memset(&lst[nlst], 0, sizeof(lst[nlst]));
		snprintf(lst[nlst].uri, sizeof(lst[nlst].uri), "%s", tc->uri);
		lst[nlst].l = l;
		lst[nlst].up = true;
		nlst++;
		pthread_mutex_unlock(&t_lock);
		logmsg(LOG_INFO, "listening on %s", tc->uri);
		if (sib[0] == '\0')
			goto out;
		pthread_mutex_lock(&t_lock);
		memset(&lst[nlst], 0, sizeof(lst[nlst]));
		snprintf(lst[nlst].uri, sizeof(lst[nlst].uri), "%s", sib);
		lst[nlst].sctp = true;
		if (!kernel_has_sctp())
			snprintf(lst[nlst].error, sizeof(lst[nlst].error), "the "
			    "kernel has no SCTP");
		nlst++;
		pthread_mutex_unlock(&t_lock);
		if (kernel_has_sctp()) {
			if (listener_up(sib, &l, why, sizeof(why)) != 0) {
				pthread_mutex_lock(&t_lock);
				snprintf(lst[nlst - 1].error,
				    sizeof(lst[nlst - 1].error), "%s", why);
				pthread_mutex_unlock(&t_lock);
			} else {
				pthread_mutex_lock(&t_lock);
				lst[nlst - 1].l = l;
				lst[nlst - 1].up = true;
				pthread_mutex_unlock(&t_lock);
				logmsg(LOG_INFO, "listening on %s", sib);
			}
		}
		goto out;
	}
	pthread_mutex_lock(&t_lock);
	for (i = 0; i < nlst; ) {
		if (strcmp(lst[i].uri, tc->uri) != 0 && (sib[0] == '\0' ||
		    !lst[i].sctp || strcmp(lst[i].uri, sib) != 0)) {
			i++;
			continue;
		}
		if (lst[i].l != NULL)
			cbl_listener_free(lst[i].l);
		logmsg(LOG_INFO, "no longer listening on %s", lst[i].uri);
		memmove(&lst[i], &lst[i + 1], (size_t)(nlst - i - 1) *
		    sizeof(lst[0]));
		nlst--;
	}
	pthread_mutex_unlock(&t_lock);
out:
	loop_done();
}

/*
 * listen kept in rc.conf in unlisten's place: a word of
 * arcana_agent_listen, or of -l in arcana_agent_flags; added to
 * arcana_agent_listen when neither has it.
 */
static const char *
listen_keep(struct work *w, const char *from, const char *to)
{
	static const char *const vars[] = { "arcana_agent_listen",
	    "arcana_agent_flags" };
	const char	*v, *e;
	char		*words, *word, *rest, out[1024];
	size_t		 i;
	bool		 found;

	for (i = 0; i < nitems(vars); i++) {
		if ((v = rc_get(w, vars[i])) == NULL)
			continue;
		out[0] = '\0';
		found = false;
		words = wstrdup(w, v);
		for (rest = words; (word = strsep(&rest, " \t")) != NULL; ) {
			if (word[0] == '\0')
				continue;
			if (strcmp(word, from) == 0) {
				word = (char *)(uintptr_t)to;
				found = true;
			}
			if (strlen(out) + strlen(word) + 2 >= sizeof(out))
				return ("rc.conf's line would be too long");
			snprintf(out + strlen(out), sizeof(out) - strlen(out),
			    "%s%s", out[0] != '\0' ? " " : "", word);
		}
		if (!found)
			continue;
		e = NULL;
		if (rc_set(w, vars[i], "=", out, &e) != 0)
			return (e);
		return (NULL);
	}
	v = rc_get(w, "arcana_agent_listen");
	e = NULL;
	if (rc_set(w, "arcana_agent_listen", "=", v != NULL && v[0] != '\0' ?
	    wfmt(w, "%s %s", v, to) : to, &e) != 0)
		return (e);
	return (NULL);
}

/*
 * A listener added (listen), one closed (unlisten), or both, kept with
 * keep: what the console moving the host asks for.
 */
static const char *
listen_set(struct work *w, const char *listen, const char *unlisten,
    bool keep)
{
	struct tchange	 tc;
	const char	*e;
	int		 i, n, step;

	if (listen != NULL && strncmp(listen, "tcp://", 6) != 0 &&
	    strncmp(listen, "sctp://", 7) != 0)
		return ("listen is tcp:// or sctp://, an address and a port");
	if (unlisten != NULL) {
		if (strncmp(unlisten, "unix:", 5) == 0)
			return ("the local socket is always listened on");
		/* Not the last one the console can reach it by. */
		pthread_mutex_lock(&t_lock);
		for (i = n = 0; i < nlst; i++)
			if (lst[i].up && strncmp(lst[i].uri, "unix:", 5) != 0 &&
			    strcmp(lst[i].uri, unlisten) != 0 && (strncmp(
			    unlisten, "tcp://", 6) != 0 || !lst[i].sctp ||
			    strcmp(lst[i].uri + 7, unlisten + 6) != 0))
				n++;
		pthread_mutex_unlock(&t_lock);
		if (n == 0 && (listen == NULL || strcmp(listen, unlisten) ==
		    0))
			return ("it is the last listener the console reaches the "
			    "agent by");
	}
	if (listen != NULL) {
		memset(&tc, 0, sizeof(tc));
		tc.uri = listen;
		tc.add = true;
		step = step_begin(w, ARC_STEP_KIND_LIB, "libcblink "
		    "cbl_listener_start()", "listening on %s too", listen);
		if ((e = in_loop(listen_change, &tc)) == NULL && tc.error[0] !=
		    '\0')
			e = wtext(w, tc.error);
		step_end(w, step, e == NULL, e != NULL ? "%s" : NULL, e);
		if (e != NULL)
			return (e);
	}
	if (unlisten != NULL) {
		pthread_mutex_lock(&t_lock);
		for (i = 0; i < nlst; i++)
			if (strcmp(lst[i].uri, unlisten) == 0)
				break;
		n = i;
		i = nlst;
		pthread_mutex_unlock(&t_lock);
		if (n == i)
			return (wfmt(w, "it does not listen on %s", unlisten));
		memset(&tc, 0, sizeof(tc));
		tc.uri = unlisten;
		step = step_begin(w, ARC_STEP_KIND_LIB, "libcblink "
		    "cbl_listener_free()", "no longer listening on %s",
		    unlisten);
		e = in_loop(listen_change, &tc);
		step_end(w, step, e == NULL, e != NULL ? "%s" : NULL, e);
		if (e != NULL)
			return (e);
	}
	if (keep && listen != NULL && unlisten != NULL) {
		step = step_begin(w, ARC_STEP_KIND_FILE, "/etc/rc.conf",
		    "%s in %s's place, for the next start", listen, unlisten);
		e = listen_keep(w, unlisten, listen);
		step_end(w, step, e == NULL, e != NULL ? "%s" : NULL, e);
		if (e != NULL)
			return (e);
	}
	return (NULL);
}

static void
put(ucl_object_t *o, const char *key, const char *v)
{

	ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0, false);
}

/* {"listeners":[...],"sctp":bool,"sessions":[...],"seen":n} */
int
do_transport(struct work *w, bool retry, const char *listen,
    const char *unlisten, bool keep, struct arc_transport_rsp *rsp)
{
	ucl_object_t	*top, *arr, *o;
	unsigned char	*json;
	const char	*e;
	int		 i, step;

	rsp->has_ok = true;
	rsp->ok = false;
	if (retry) {
		step = step_begin(w, ARC_STEP_KIND_LIB, "libcblink "
		    "cbl_listener_start()", "the SCTP listeners that are not "
		    "up");
		e = transport_retry();
		step_end(w, step, e == NULL, e != NULL ? "%s" : NULL, e);
		if (e != NULL) {
			rsp->error = e;
			return (0);
		}
	}
	if ((listen != NULL || unlisten != NULL) && (e = listen_set(w, listen,
	    unlisten, keep)) != NULL) {
		rsp->error = e;
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	/* The loop's thread changes them, under t_lock when it adds or
	 * takes one away. */
	pthread_mutex_lock(&t_lock);
	for (i = 0; i < nlst; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "uri", lst[i].uri);
		put(o, "transport", strncmp(lst[i].uri, "sctp:", 5) == 0 ?
		    "sctp" : strncmp(lst[i].uri, "unix:", 5) == 0 ? "unix" :
		    "tcp");
		ucl_object_insert_key(o, ucl_object_frombool(lst[i].up), "up",
		    0, false);
		if (!lst[i].up && lst[i].error[0] != '\0')
			put(o, "error", lst[i].error);
		ucl_array_append(arr, o);
	}
	pthread_mutex_unlock(&t_lock);
	ucl_object_insert_key(top, arr, "listeners", 0, false);
	ucl_object_insert_key(top, ucl_object_frombool(kernel_has_sctp()),
	    "sctp", 0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	pthread_mutex_lock(&t_lock);
	for (i = 0; i < nses; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "transport", ses[i].transport);
		put(o, "address", ses[i].addr);
		put(o, "subject", ses[i].subject);
		ucl_object_insert_key(o, ucl_object_fromint(ses[i].since),
		    "since", 0, false);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)ses_seen),
	    "seen", 0, false);
	pthread_mutex_unlock(&t_lock);
	ucl_object_insert_key(top, arr, "sessions", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(time(NULL)), "time", 0,
	    false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "out of memory";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}
