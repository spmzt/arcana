/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the record of what the security rules logged (MEF 138).
 * A rule with "log logdst rtsock" tells each packet it sees on the
 * routing socket (RTM_IPFWLOG): the rule's
 * number, its action, the packet's addresses, the interface and the
 * rule's comment, which the console makes name the service and the
 * policy.  A thread of its own reads them: each is an entry of the
 * record, kept a day in memory and on disk beside the agent's files,
 * and an event (sdwan-security) as it comes, twenty a second at most.
 * When a rule nears its logamount, the agent resets its log so the
 * flow goes on.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>
#include <arpa/inet.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	RECORD_FILE	"sdwan-record.json"
#define	RECORD_MAX	10000
#define	RECORD_KEEP	(24 * 3600)
#define	RECORD_LAST	500
#define	RECORD_EVENTS_S	20
#define	RECORD_SAVE_S	30

struct rec {
	time_t		t;
	uint64_t	seq;
	uint32_t	rule;
	char		action[12];
	char		src[48];
	char		dst[48];
	char		iface[IFNAMSIZ];
	char		comment[82];
};

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
static struct rec	*ring;
static int		 first, count;
static uint64_t		 seq;
static uint64_t		 dropped;	/* events beyond the second's twenty */
static bool		 dirty;

/* A string as JSON's: quotes and backslashes escaped. */
static const char *
jq(const char *s, char *buf, size_t len)
{
	size_t	i, n;

	for (i = 0, n = 0; s != NULL && s[i] != '\0' && n + 2 < len; i++) {
		if (s[i] == '"' || s[i] == '\\')
			buf[n++] = '\\';
		buf[n++] = (unsigned char)s[i] < 0x20 ? ' ' : s[i];
	}
	buf[n] = '\0';
	return (buf);
}

/* The entries of the day, as JSON, oldest first. */
static char *
record_text(void)
{
	ucl_object_t	*arr, *o;
	unsigned char	*json;
	time_t		 now;
	int		 i;

	now = time(NULL);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < count; i++) {
		const struct rec *r = &ring[(first + i) % RECORD_MAX];

		if (now - r->t > RECORD_KEEP)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)r->t), "t", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)r->seq), "seq",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromint(r->rule), "rule", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(r->action), "action",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(r->src), "src", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(r->dst), "dst", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(r->iface), "iface", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(r->comment),
		    "comment", 0, false);
		ucl_array_append(arr, o);
	}
	json = ucl_object_emit(arr, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(arr);
	return ((char *)json);
}

/* Kept on disk, now and then, under the lock. */
static void
record_save(void)
{
	char		*text;
	const char	*e;

	if (!dirty || (text = record_text()) == NULL)
		return;
	e = NULL;
	if (sdwan_conf_write(RECORD_FILE, text, &e) != 0)
		logmsg(LOG_WARNING, "sdwan record: %s: %s", RECORD_FILE, e);
	else
		dirty = false;
	free(text);
}

/* One entry more, under the lock; whether it is one of the second's
 * twenty events. */
static bool
record_add(const struct rec *r)
{
	static time_t	sec;
	static int	in_sec;
	struct rec	*slot;

	if (count == RECORD_MAX) {
		first = (first + 1) % RECORD_MAX;
		count--;
	}
	slot = &ring[(first + count) % RECORD_MAX];
	*slot = *r;
	slot->seq = ++seq;
	count++;
	dirty = true;
	if (r->t != sec) {
		sec = r->t;
		in_sec = 0;
	}
	if (++in_sec > RECORD_EVENTS_S) {
		dropped++;
		return (false);
	}
	return (true);
}

/* The word for a rule's action, from its instruction. */
static const char *
action_word(uint8_t opcode)
{

	switch (opcode) {
	case O_DENY:
		return ("deny");
	case O_REJECT:
	case O_UNREACH6:
		return ("reject");
	case O_ACCEPT:
		return ("allow");
	case O_COUNT:
		return ("count");
	case O_SKIPTO:
		return ("skipto");
	case O_PIPE:
		return ("pipe");
	case O_QUEUE:
		return ("queue");
	case O_FORWARD_IP:
	case O_FORWARD_IP6:
		return ("fwd");
	case O_SETFIB:
		return ("setfib");
	case O_NAT:
		return ("nat");
	default:
		return ("rule");
	}
}

/* The rule's log reset, so it keeps telling; once a second a rule. */
static void
reset_log(uint32_t rule)
{
	static uint32_t	last_rule;
	static time_t	last_t;
	struct work	 w;
	struct execres	 res;
	char		*argv[5], num[16];
	time_t		 now;

	now = time(NULL);
	if (rule == last_rule && now == last_t)
		return;
	last_rule = rule;
	last_t = now;
	work_init(&w);
	w.nice = true;
	snprintf(num, sizeof(num), "%u", rule);
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-q";
	argv[2] = (char *)(uintptr_t)"resetlog";
	argv[3] = num;
	argv[4] = NULL;
	(void)run_exec(&w, argv, &res);
	work_free(&w);
}

/* One message of the routing socket: an entry when it is a log.  The
 * addresses in it are packed, so each is copied before it is read; the
 * interface is the header's index, named. */
static void
record_message(const struct rt_msghdr *rtm, size_t len)
{
	const char			*p, *end;
	struct sockaddr			 sa;
	struct sockaddr_dl		 sdl;
	struct sockaddr_in		 sin;
	struct sockaddr_in6		 sin6;
	ipfwlog_rtsock_hdr_v2		 hdr;
	struct rec			 r;
	char				 jc[200], js[64], jd[64];
	size_t				 salen, n;
	int				 i;
	bool				 tell;

	if (rtm->rtm_type != RTM_IPFWLOG || rtm->rtm_msglen > len)
		return;
	memset(&r, 0, sizeof(r));
	r.t = time(NULL);
	p = (const char *)(rtm + 1);
	end = (const char *)rtm + rtm->rtm_msglen;
	for (i = 0; i < RTAX_MAX && p + sizeof(sa) <= end; i++) {
		if ((rtm->rtm_addrs & (1 << i)) == 0)
			continue;
		memcpy(&sa, p, sizeof(sa));
		salen = sa.sa_len > 0 ? sa.sa_len : sizeof(long);
		if (p + salen > end)
			break;
		if (i == RTAX_DST && sa.sa_family == AF_IPFWLOG) {
			memset(&sdl, 0, sizeof(sdl));
			memcpy(&sdl, p, MIN(salen, sizeof(sdl)));
			n = salen - offsetof(struct sockaddr_dl, sdl_data);
			if (salen > offsetof(struct sockaddr_dl, sdl_data) + sizeof(hdr)) {
				memcpy(&hdr, p + offsetof(struct sockaddr_dl, sdl_data),
				    sizeof(hdr));
				r.rule = hdr.rulenum;
				snprintf(r.action, sizeof(r.action), "%s", action_word(
				    hdr.cmd.opcode));
				if (sdl.sdl_nlen > 0 && n > sizeof(hdr))
					snprintf(r.comment, sizeof(r.comment), "%.*s", (int)
					    MIN((size_t)sdl.sdl_nlen, MIN(n - sizeof(hdr),
					    sizeof(r.comment) - 1)), p + offsetof(struct
					    sockaddr_dl, sdl_data) + sizeof(hdr));
			}
		} else if (i == RTAX_GATEWAY || i == RTAX_NETMASK) {
			char	*out = i == RTAX_GATEWAY ? r.src : r.dst;

			if (sa.sa_family == AF_INET && salen >= sizeof(sin)) {
				memcpy(&sin, p, sizeof(sin));
				inet_ntop(AF_INET, &sin.sin_addr, out, sizeof(r.src));
			} else if (sa.sa_family == AF_INET6 && salen >= sizeof(sin6)) {
				memcpy(&sin6, p, sizeof(sin6));
				inet_ntop(AF_INET6, &sin6.sin6_addr, out, sizeof(r.src));
			}
		} else if (i == RTAX_IFP && sa.sa_family == AF_LINK) {
			memset(&sdl, 0, sizeof(sdl));
			memcpy(&sdl, p, MIN(salen, sizeof(sdl)));
			snprintf(r.iface, sizeof(r.iface), "%.*s", (int)MIN((size_t)
			    sdl.sdl_nlen, sizeof(r.iface) - 1), sdl.sdl_data);
		}
		p += roundup2(salen, sizeof(long));
	}
	if (r.rule == 0)
		return;
	/* The interface, by its index in the message's header. */
	if (r.iface[0] == '\0' && rtm->rtm_index > 0 && if_indextoname(
	    rtm->rtm_index, r.iface) == NULL)
		r.iface[0] = '\0';
	pthread_mutex_lock(&lock);
	tell = record_add(&r);
	pthread_mutex_unlock(&lock);
	if (tell)
		event_add("sdwan-security", "{\"seq\":%ju,\"rule\":%u,\"action\":\"%s"
		    "\",\"src\":\"%s\",\"dst\":\"%s\",\"iface\":\"%s\",\"comment\":\"%s\"}",
		    (uintmax_t)seq, r.rule, r.action, jq(r.src, js, sizeof(js)), jq(
		    r.dst, jd, sizeof(jd)), r.iface, jq(r.comment, jc, sizeof(jc)));
	if (rtm->rtm_flags & RTF_PROTO1)
		reset_log(r.rule);
}

static void *
reader(void *arg __unused)
{
	char		 buf[4096];
	ssize_t		 n;
	time_t		 saved;
	int		 fd;

	if ((fd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)) == -1) {
		logmsg(LOG_WARNING, "sdwan record: routing socket: %s",
		    strerror(errno));
		return (NULL);
	}
	saved = time(NULL);
	for (;;) {
		n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR || errno == ENOBUFS)
				continue;
			break;
		}
		if (n >= (ssize_t)sizeof(struct rt_msghdr))
			record_message((const struct rt_msghdr *)buf, (size_t)n);
		if (time(NULL) - saved >= RECORD_SAVE_S) {
			pthread_mutex_lock(&lock);
			record_save();
			pthread_mutex_unlock(&lock);
			saved = time(NULL);
		}
	}
	close(fd);
	return (NULL);
}

/* At the start: the day's record read back, and the reader started. */
void
record_start(void)
{
	pthread_t		 tid;
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	char			*text;
	struct rec		 r;

	if ((ring = calloc(RECORD_MAX, sizeof(*ring))) == NULL)
		return;
	if ((text = sdwan_kept_read(RECORD_FILE)) != NULL) {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		top = ucl_parser_add_string(p, text, 0) ? ucl_parser_get_object(p)
		    : NULL;
		ucl_parser_free(p);
		free(text);
		it = NULL;
		while (top != NULL && (e = ucl_object_iterate(top, &it, true)) !=
		    NULL) {
			memset(&r, 0, sizeof(r));
			r.t = (time_t)ucl_object_toint(ucl_object_lookup(e, "t"));
			r.rule = (uint32_t)ucl_object_toint(ucl_object_lookup(e,
			    "rule"));
			snprintf(r.action, sizeof(r.action), "%s",
			    ucl_object_tostring_forced(ucl_object_lookup(e, "action")));
			snprintf(r.src, sizeof(r.src), "%s", ucl_object_tostring_forced(
			    ucl_object_lookup(e, "src")));
			snprintf(r.dst, sizeof(r.dst), "%s", ucl_object_tostring_forced(
			    ucl_object_lookup(e, "dst")));
			snprintf(r.iface, sizeof(r.iface), "%s",
			    ucl_object_tostring_forced(ucl_object_lookup(e, "iface")));
			snprintf(r.comment, sizeof(r.comment), "%s",
			    ucl_object_tostring_forced(ucl_object_lookup(e, "comment")));
			if (time(NULL) - r.t <= RECORD_KEEP)
				(void)record_add(&r);
		}
		if (top != NULL)
			ucl_object_unref(top);
		dirty = false;
	}
	if (pthread_create(&tid, NULL, reader, NULL) == 0)
		(void)pthread_detach(tid);
}

/* The day's count, the last sequence number and the latest entries. */
void
record_json(ucl_object_t *top)
{
	ucl_object_t	*o, *arr, *e;
	time_t		 now;
	int		 i, n, from;

	now = time(NULL);
	o = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	pthread_mutex_lock(&lock);
	n = 0;
	for (i = 0; i < count; i++)
		if (now - ring[(first + i) % RECORD_MAX].t <= RECORD_KEEP)
			n++;
	from = count > RECORD_LAST ? count - RECORD_LAST : 0;
	for (i = count - 1; i >= from; i--) {
		const struct rec *r = &ring[(first + i) % RECORD_MAX];

		if (now - r->t > RECORD_KEEP)
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromint((int64_t)r->t), "t", 0,
		    false);
		ucl_object_insert_key(e, ucl_object_fromint((int64_t)r->seq), "seq",
		    0, false);
		ucl_object_insert_key(e, ucl_object_fromint(r->rule), "rule", 0,
		    false);
		ucl_object_insert_key(e, ucl_object_fromstring(r->action), "action",
		    0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(r->src), "src", 0,
		    false);
		ucl_object_insert_key(e, ucl_object_fromstring(r->dst), "dst", 0,
		    false);
		ucl_object_insert_key(e, ucl_object_fromstring(r->iface), "iface", 0,
		    false);
		ucl_object_insert_key(e, ucl_object_fromstring(r->comment),
		    "comment", 0, false);
		ucl_array_append(arr, e);
	}
	ucl_object_insert_key(o, ucl_object_fromint(n), "count", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)seq), "seq", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)dropped),
	    "untold", 0, false);
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(o, arr, "last", 0, false);
	ucl_object_insert_key(top, o, "record", 0, false);
}
