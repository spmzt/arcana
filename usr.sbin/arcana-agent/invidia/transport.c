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
 * An SCTP listener is bound to more addresses than its URI's where it
 * is told to (--sctp-also, sctp_bindx(3)), and the console's end,
 * unbound, offers all of its: the association has a path from each of
 * the console's addresses to each of the agent's, and goes on over
 * another when one fails.  The paths are told with the sessions.
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

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/sctp.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
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
	char		 also_error[160];	/* --sctp-also's not bound */
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

static void	loop_done(void);

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

/*
 * --sctp-also's addresses added to an SCTP listener (or taken off,
 * add false), at its port: an IPv4 listener takes IPv4 ones, an IPv6
 * one both.  What could not be is said in also_error.
 */
static void
sctp_also_bind(struct tlisten *t, const char *list, bool add)
{
	struct sockaddr_storage	 me, ss;
	struct addrinfo		 hints, *ai;
	socklen_t		 len;
	char			*copy, *rest, *word;
	in_port_t		 port;
	int			 fd;

	if (add)
		t->also_error[0] = '\0';
	if (list == NULL || list[0] == '\0' || t->l == NULL || !t->up ||
	    strncmp(t->uri, "sctp://", 7) != 0 ||
	    (fd = cbl_listener_fd(t->l)) == -1)
		return;
	len = sizeof(me);
	if (getsockname(fd, (struct sockaddr *)&me, &len) != 0)
		return;
	port = me.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&me)->
	    sin6_port : ((struct sockaddr_in *)&me)->sin_port;
	if ((copy = strdup(list)) == NULL)
		return;
	for (rest = copy; (word = strsep(&rest, " \t,")) != NULL; ) {
		if (word[0] == '\0')
			continue;
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_NUMERICHOST;
		hints.ai_family = me.ss_family == AF_INET ? AF_INET : AF_UNSPEC;
		if (getaddrinfo(word, NULL, &hints, &ai) != 0) {
			if (add)
				snprintf(t->also_error + strlen(t->also_error),
				    sizeof(t->also_error) - strlen(t->also_error),
				    "%s%s: not an address %s", t->also_error[0] !=
				    '\0' ? "; " : "", word, me.ss_family ==
				    AF_INET ? "of IPv4" : "");
			continue;
		}
		memset(&ss, 0, sizeof(ss));
		memcpy(&ss, ai->ai_addr, ai->ai_addrlen);
		freeaddrinfo(ai);
		if (ss.ss_family == AF_INET6)
			((struct sockaddr_in6 *)&ss)->sin6_port = port;
		else
			((struct sockaddr_in *)&ss)->sin_port = port;
		if (sctp_bindx(fd, (struct sockaddr *)&ss, 1, add ?
		    SCTP_BINDX_ADD_ADDR : SCTP_BINDX_REM_ADDR) != 0 && add)
			snprintf(t->also_error + strlen(t->also_error),
			    sizeof(t->also_error) - strlen(t->also_error),
			    "%s%s: %s", t->also_error[0] != '\0' ? "; " : "",
			    word, strerror(errno));
	}
	free(copy);
}

/*
 * Are the addresses an SCTP socket is bound to all on loopback
 * interfaces, one of them a routable one (a router's loopback)?  Then
 * FreeBSD's SCTP answers no peer elsewhere: an address on a loopback
 * interface is out of a non-loopback peer's scope
 * (sctp_is_address_in_scope()), so no INIT-ACK leaves, while TCP from
 * the same address works.  ::1 and 127/8 alone are local by intent.
 */
static bool
sctp_loopback_only(int fd)
{
	struct sockaddr		*addrs, *sa;
	struct ifaddrs		*ifap, *ifa;
	bool			 routable, all, on_loop;
	int			 n, i;

	if ((n = sctp_getladdrs(fd, 0, &addrs)) <= 0)
		return (false);
	if (getifaddrs(&ifap) == -1) {
		sctp_freeladdrs(addrs);
		return (false);
	}
	routable = false;
	all = true;
	sa = addrs;
	for (i = 0; i < n && all; i++) {
		on_loop = false;
		for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family !=
			    sa->sa_family)
				continue;
			if ((sa->sa_family == AF_INET6 && memcmp(&((struct
			    sockaddr_in6 *)(void *)sa)->sin6_addr, &((struct
			    sockaddr_in6 *)(void *)ifa->ifa_addr)->sin6_addr,
			    sizeof(struct in6_addr)) == 0) || (sa->sa_family ==
			    AF_INET && ((struct sockaddr_in *)(void *)sa)->
			    sin_addr.s_addr == ((struct sockaddr_in *)(void *)
			    ifa->ifa_addr)->sin_addr.s_addr)) {
				on_loop = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
				break;
			}
		}
		/* The wildcard, or an address no interface has: not this. */
		if (!on_loop)
			all = false;
		else if ((sa->sa_family == AF_INET6 && !IN6_IS_ADDR_LOOPBACK(
		    &((struct sockaddr_in6 *)(void *)sa)->sin6_addr)) ||
		    (sa->sa_family == AF_INET && (ntohl(((struct sockaddr_in *)
		    (void *)sa)->sin_addr.s_addr) >> 24) != IN_LOOPBACKNET))
			routable = true;
		sa = (struct sockaddr *)((char *)sa + sa->sa_len);
	}
	freeifaddrs(ifap);
	sctp_freeladdrs(addrs);
	return (all && routable);
}

/* The addresses a socket of SCTP has at its end, or its peer's. */
static ucl_object_t *
sctp_addrs(int fd, bool peer, ucl_object_t **paths)
{
	struct sockaddr		*addrs, *sa;
	struct sctp_paddrinfo	 pi;
	struct sctp_setprim	 prim;
	ucl_object_t		*arr, *o;
	socklen_t		 len;
	char			 host[64];
	int			 n, i;
	bool			 have_prim;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (paths != NULL)
		*paths = ucl_object_typed_new(UCL_ARRAY);
	n = peer ? sctp_getpaddrs(fd, 0, &addrs) : sctp_getladdrs(fd, 0,
	    &addrs);
	if (n <= 0)
		return (arr);
	have_prim = false;
	if (paths != NULL) {
		memset(&prim, 0, sizeof(prim));
		len = sizeof(prim);
		have_prim = getsockopt(fd, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
		    &prim, &len) == 0;
	}
	sa = addrs;
	for (i = 0; i < n; i++) {
		if (getnameinfo(sa, sa->sa_len, host, sizeof(host), NULL, 0,
		    NI_NUMERICHOST) == 0) {
			ucl_array_append(arr, ucl_object_fromstring(host));
			if (paths != NULL) {
				o = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(o, ucl_object_fromstring(
				    host), "address", 0, false);
				memset(&pi, 0, sizeof(pi));
				memcpy(&pi.spinfo_address, sa, sa->sa_len);
				len = sizeof(pi);
				if (getsockopt(fd, IPPROTO_SCTP,
				    SCTP_GET_PEER_ADDR_INFO, &pi, &len) == 0) {
					ucl_object_insert_key(o,
					    ucl_object_fromstring(pi.spinfo_state ==
					    SCTP_ACTIVE ? "active" : pi.spinfo_state ==
					    SCTP_INACTIVE ? "inactive" :
					    pi.spinfo_state == SCTP_UNCONFIRMED ?
					    "unconfirmed" : "other"), "state", 0,
					    false);
					ucl_object_insert_key(o,
					    ucl_object_fromint(pi.spinfo_srtt),
					    "srtt_ms", 0, false);
					ucl_object_insert_key(o,
					    ucl_object_fromint(pi.spinfo_rto),
					    "rto_ms", 0, false);
				}
				ucl_object_insert_key(o, ucl_object_frombool(
				    have_prim && sa->sa_len <= sizeof(
				    prim.ssp_addr) && memcmp(&prim.ssp_addr, sa,
				    sa->sa_len) == 0), "primary", 0, false);
				ucl_array_append(*paths, o);
			}
		}
		sa = (struct sockaddr *)((char *)sa + sa->sa_len);
	}
	if (peer)
		sctp_freepaddrs(addrs);
	else
		sctp_freeladdrs(addrs);
	return (arr);
}

/* In the loop's thread: --sctp-also's addresses on every SCTP listener
 * that is up, those before taken off first. */
struct talso {
	const char	*was;
	const char	*now;
};

static void
also_change(void *arg)
{
	struct talso	*ta = arg;
	int		 i;

	pthread_mutex_lock(&t_lock);
	for (i = 0; i < nlst; i++) {
		sctp_also_bind(&lst[i], ta->was, false);
		sctp_also_bind(&lst[i], ta->now, true);
	}
	pthread_mutex_unlock(&t_lock);
	loop_done();
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

/*
 * At the end, after the loop: every listener freed, those main() was
 * given and those added or closed since alike, each once.
 */
void
transport_fini(void)
{
	int	i;

	pthread_mutex_lock(&t_lock);
	for (i = 0; i < nlst; i++)
		if (lst[i].l != NULL) {
			cbl_listener_free(lst[i].l);
			lst[i].l = NULL;
		}
	nlst = 0;
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

	/* What the readers read under the lock, written under it. */
	pthread_mutex_lock(&t_lock);
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
		sctp_also_bind(t, opts.sctp_also, true);
		logmsg(LOG_INFO, "listening on %s", t->uri);
	}
	pthread_mutex_unlock(&t_lock);
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
	/* Those asked for as sctp:// themselves: their other addresses. */
	for (i = 0; i < n; i++)
		sctp_also_bind(&lst[i], opts.sctp_also, true);
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
			if (strcmp(lst[i].uri, tc->uri) == 0 && lst[i].up) {
				/*
				 * The SCTP listener opened beside a TCP one, now
				 * asked for by itself (a host moved from tcp:// to
				 * sctp:// at the same address): its own from now
				 * on, not closed with the TCP one.
				 */
				pthread_mutex_lock(&t_lock);
				lst[i].sctp = false;
				pthread_mutex_unlock(&t_lock);
				goto out;
			}
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
		sctp_also_bind(&lst[nlst - 1], opts.sctp_also, true);
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
				sctp_also_bind(&lst[nlst - 1], opts.sctp_also,
				    true);
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
	if (listen != NULL && unlisten != NULL && strcmp(listen, unlisten) ==
	    0)
		return ("listen and unlisten are the same listener");
	if (unlisten != NULL) {
		if (strncmp(unlisten, "unix:", 5) == 0)
			return ("the local socket is always listened on");
		/* There, before anything is changed. */
		pthread_mutex_lock(&t_lock);
		for (i = 0; i < nlst; i++)
			if (strcmp(lst[i].uri, unlisten) == 0)
				break;
		n = i;
		i = nlst;
		pthread_mutex_unlock(&t_lock);
		if (n == i)
			return (wfmt(w, "it does not listen on %s", unlisten));
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

/*
 * --sctp-also changed now: the addresses given, every SCTP listener
 * bound to them and not to those before, and kept in rc.conf
 * (arcana_agent_sctp_also) for the next start; "" for none.
 */
static const char *
also_set(struct work *w, const char *now)
{
	struct talso	 ta;
	struct addrinfo	 hints, *ai;
	const char	*e;
	char		*copy, *rest, *word;
	int		 step;

	if (strlen(now) > 512)
		return ("a list of addresses, 512 characters at most");
	copy = wstrdup(w, now);
	for (rest = copy; (word = strsep(&rest, " \t,")) != NULL; ) {
		if (word[0] == '\0')
			continue;
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_NUMERICHOST;
		if (getaddrinfo(word, NULL, &hints, &ai) != 0)
			return (wfmt(w, "%s is not an address", word));
		freeaddrinfo(ai);
	}
	ta.was = opts.sctp_also;
	/* Kept for as long as the agent runs: listeners read it. */
	if (now[0] == '\0')
		ta.now = NULL;
	else if ((ta.now = strdup(now)) == NULL)
		return ("out of memory");
	step = step_begin(w, ARC_STEP_KIND_LIB, "sctp_bindx(3)", "the SCTP "
	    "listeners bound to %s too", now[0] != '\0' ? now : "nothing "
	    "more");
	e = in_loop(also_change, &ta);
	step_end(w, step, e == NULL, e != NULL ? "%s" : NULL, e);
	if (e != NULL)
		return (e);
	/* Read by the listeners started from now on too; the one before
	 * is let be (the loop may have read it). */
	opts.sctp_also = ta.now;
	step = step_begin(w, ARC_STEP_KIND_FILE, "/etc/rc.conf",
	    "arcana_agent_sctp_also, for the next start");
	e = NULL;
	if (now[0] == '\0')
		rc_unset(w, "arcana_agent_sctp_also");
	else
		(void)rc_set(w, "arcana_agent_sctp_also", "=", now, &e);
	step_end(w, step, e == NULL, e != NULL ? "%s" : NULL, e);
	return (e);
}

/*
 * Is the address one of a loopback interface's?  Such an address gives
 * an SCTP association no path to a peer elsewhere, as for listeners
 * (sctp_loopback_only()): an "SCTP also" address there helps nothing.
 */
static bool
addr_on_loopback(const char *addr)
{
	struct addrinfo	 hints, *ai;
	struct ifaddrs	*ifap, *ifa;
	bool		 on;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(addr, NULL, &hints, &ai) != 0)
		return (false);
	on = false;
	if (getifaddrs(&ifap) == 0) {
		for (ifa = ifap; ifa != NULL && !on; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family !=
			    ai->ai_family || (ifa->ifa_flags & IFF_LOOPBACK) == 0)
				continue;
			if (ai->ai_family == AF_INET6)
				on = memcmp(&((struct sockaddr_in6 *)(void *)
				    ai->ai_addr)->sin6_addr, &((struct sockaddr_in6 *)
				    (void *)ifa->ifa_addr)->sin6_addr,
				    sizeof(struct in6_addr)) == 0;
			else if (ai->ai_family == AF_INET)
				on = ((struct sockaddr_in *)(void *)ai->ai_addr)->
				    sin_addr.s_addr == ((struct sockaddr_in *)(void *)
				    ifa->ifa_addr)->sin_addr.s_addr;
		}
		freeifaddrs(ifap);
	}
	freeaddrinfo(ai);
	return (on);
}

/* {"listeners":[...],"sctp":bool,"sessions":[...],"seen":n} */
int
do_transport(struct work *w, bool retry, const char *listen,
    const char *unlisten, bool keep, const char *sctp_also,
    struct arc_transport_rsp *rsp)
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
	if (sctp_also != NULL && (e = also_set(w, sctp_also)) != NULL) {
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
		/* SCTP's: every address it is bound to. */
		if (lst[i].up && lst[i].l != NULL && strncmp(lst[i].uri,
		    "sctp:", 5) == 0)
			ucl_object_insert_key(o, sctp_addrs(cbl_listener_fd(
			    lst[i].l), false, NULL), "addresses", 0, false);
		if (lst[i].also_error[0] != '\0')
			put(o, "also_error", lst[i].also_error);
		/* Only on a router's loopback: answered over TCP, not SCTP. */
		if (lst[i].up && lst[i].l != NULL && strncmp(lst[i].uri,
		    "sctp:", 5) == 0 && sctp_loopback_only(cbl_listener_fd(
		    lst[i].l)))
			put(o, "warning", "its addresses are all on a loopback "
			    "interface, which FreeBSD's SCTP answers no peer "
			    "elsewhere from (TCP is answered); listen on an "
			    "address of a real interface too (--sctp-also) and "
			    "reach the agent by that one");
		ucl_array_append(arr, o);
	}
	pthread_mutex_unlock(&t_lock);
	ucl_object_insert_key(top, arr, "listeners", 0, false);
	put(top, "sctp_also", opts.sctp_also != NULL ? opts.sctp_also : "");
	/* Those of them on a loopback interface: no help to a peer. */
	if (opts.sctp_also != NULL) {
		char	*copy, *rest, *word;

		arr = ucl_object_typed_new(UCL_ARRAY);
		copy = wstrdup(w, opts.sctp_also);
		for (rest = copy; (word = strsep(&rest, " \t,")) != NULL; )
			if (word[0] != '\0' && addr_on_loopback(word))
				ucl_array_append(arr, ucl_object_fromstring(word));
		ucl_object_insert_key(top, arr, "sctp_also_loopback", 0, false);
	}
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
		/* An association: its addresses here, and each path to the
		 * other end's, as the kernel sees it now.  cblink closes a
		 * connection's socket before on_close takes it off the list:
		 * one closing just now may answer for nothing, or for the
		 * socket that took its number. */
		if (strcmp(ses[i].transport, "sctp") == 0 && ses[i].conn !=
		    NULL && cbl_conn_fd(ses[i].conn) != -1) {
			ucl_object_t	*paths;
			int		 fd = cbl_conn_fd(ses[i].conn);

			ucl_object_insert_key(o, sctp_addrs(fd, false, NULL),
			    "local", 0, false);
			ucl_object_unref(sctp_addrs(fd, true, &paths));
			ucl_object_insert_key(o, paths, "paths", 0, false);
		}
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
