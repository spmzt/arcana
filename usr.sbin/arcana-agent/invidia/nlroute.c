/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the routing tables, spoken to in the kernel's own terms,
 * netlink(4), and not through route(8) and netstat(1).  This is the
 * helper's side: the program run again as "arcana-agent -Q jid verb
 * ...", which attaches to the jail when there is one, asks, and prints
 * what the daemon reads.
 *
 *	routes family fib filter cover
 *		every route of the table, a JSON object a line, with each
 *		attribute the kernel sends under its name; a route with
 *		several next hops is a line for each.  Only the routes that
 *		have filter in them, and only those the address cover is
 *		in, when they are not "-".  The last line is "#total n",
 *		the routes the table has.
 *	route-get address fib
 *		the route the kernel would take to the address, one object.
 *	route-add destination gateway interface fib metric weight source
 *		gateway may be several, "a@3,b@1": the route is then one
 *		with as many next hops, each with its share after the @.
 *	route-del destination gateway interface fib metric
 *		a route added or deleted; "-" and 0 are what is not given.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route.h>
#include <netlink/netlink_snl_route_compat.h>
#include <netlink/netlink_snl_route_parsers.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "agent.h"

/* One listing: where its rows go, and what it keeps count of. */
struct rl {
	FILE		*out;
	const char	*filter;
	const char	*cover_text;	/* the address the routes cover, or NULL */
	unsigned char	 cover[16];
	int		 cover_af;
	uint64_t	 total;
	uint32_t	 paths, path;	/* of the route being written */
};

/* A string as JSON has one. */
static void
jstring(struct rl *c, const char *s)
{

	fputc('"', c->out);
	for (; *s != '\0'; s++) {
		if (*s == '"' || *s == '\\')
			fprintf(c->out, "\\%c", *s);
		else if ((unsigned char)*s < 0x20)
			fprintf(c->out, "\\u%04x", (unsigned int)(unsigned char)*s);
		else
			fputc(*s, c->out);
	}
	fputc('"', c->out);
}

/* The flags of a route as netstat(1) letters them. */
static const char *
flag_letters(uint32_t flags)
{
	static const struct {
		uint32_t	bit;
		char		letter;
	} bits[] = {
		{ RTF_UP, 'U' }, { RTF_GATEWAY, 'G' }, { RTF_HOST, 'H' },
		{ RTF_REJECT, 'R' }, { RTF_DYNAMIC, 'D' },
		{ RTF_MODIFIED, 'M' }, { RTF_DONE, 'd' },
		{ RTF_XRESOLVE, 'X' }, { RTF_STATIC, 'S' },
		{ RTF_PROTO1, '1' }, { RTF_PROTO2, '2' }, { RTF_PROTO3, '3' },
		{ RTF_BLACKHOLE, 'B' }, { RTF_BROADCAST, 'b' },
		{ RTF_LLINFO, 'L' },
	};
	static char	buf[nitems(bits) + 1];
	size_t		i, n;

	for (i = n = 0; i < nitems(bits); i++)
		if ((flags & bits[i].bit) != 0)
			buf[n++] = bits[i].letter;
	buf[n] = '\0';
	return (buf);
}

/* An address as it is written, a link-local one with its interface. */
static const char *
addr_text(const struct sockaddr *sa, char *buf, size_t len)
{
	const struct sockaddr_in6	*s6;
	char				 ifn[IF_NAMESIZE];
	size_t				 n;

	buf[0] = '\0';
	if (sa == NULL)
		return (buf);
	if (sa->sa_family == AF_INET)
		inet_ntop(AF_INET, &((const struct sockaddr_in *)(const void *)
		    sa)->sin_addr, buf, (socklen_t)len);
	else if (sa->sa_family == AF_INET6) {
		s6 = (const struct sockaddr_in6 *)(const void *)sa;
		inet_ntop(AF_INET6, &s6->sin6_addr, buf, (socklen_t)len);
		if (s6->sin6_scope_id != 0 && if_indextoname(s6->sin6_scope_id,
		    ifn) != NULL) {
			n = strlen(buf);
			snprintf(buf + n, len - n, "%%%s", ifn);
		}
	}
	return (buf);
}

/* Is the address asked about inside the route's prefix? */
static bool
covers(struct rl *c, const struct snl_parsed_route *r)
{
	const unsigned char	*net;
	int			 plen, i;

	if (c->cover_text == NULL)
		return (true);
	if (r->rtm_family != c->cover_af || r->rta_dst == NULL)
		return (false);
	net = c->cover_af == AF_INET ? (const unsigned char *)
	    &((const struct sockaddr_in *)(const void *)r->rta_dst)->sin_addr :
	    (const unsigned char *)&((const struct sockaddr_in6 *)
	    (const void *)r->rta_dst)->sin6_addr;
	plen = r->rtm_dst_len;
	for (i = 0; i < plen / 8; i++)
		if (net[i] != c->cover[i])
			return (false);
	return (plen % 8 == 0 || ((net[i] ^ c->cover[i]) & (0xff << (8 - plen %
	    8))) == 0);
}

/* One route by one next hop, as a line. */
static void
row(struct rl *c, const struct snl_parsed_route *r, const struct sockaddr *gw,
    uint32_t ifindex, uint32_t flags, uint32_t weight, uint32_t metric,
    uint32_t mtu, uint32_t expire)
{
	char	dst[INET6_ADDRSTRLEN + IF_NAMESIZE + 8], gwt[INET6_ADDRSTRLEN +
		    IF_NAMESIZE + 8], src[INET6_ADDRSTRLEN + IF_NAMESIZE + 8],
		    ifn[IF_NAMESIZE];
	size_t	n;
	int	max;

	max = r->rtm_family == AF_INET ? 32 : 128;
	if (r->rtm_dst_len == 0)
		strlcpy(dst, "default", sizeof(dst));
	else {
		addr_text(r->rta_dst, dst, sizeof(dst));
		if (r->rtm_dst_len != max) {
			n = strlen(dst);
			snprintf(dst + n, sizeof(dst) - n, "/%u",
			    r->rtm_dst_len);
		}
	}
	if (gw != NULL && (gw->sa_family == AF_INET || gw->sa_family ==
	    AF_INET6))
		addr_text(gw, gwt, sizeof(gwt));
	else
		snprintf(gwt, sizeof(gwt), "link#%u", ifindex);
	if (if_indextoname(ifindex, ifn) == NULL)
		ifn[0] = '\0';
	c->total++;
	if (c->filter != NULL && strstr(dst, c->filter) == NULL && strstr(gwt,
	    c->filter) == NULL && strstr(ifn, c->filter) == NULL)
		return;
	fprintf(c->out, "{\"destination\":");
	jstring(c, dst);
	fprintf(c->out, ",\"gateway\":");
	jstring(c, gwt);
	fprintf(c->out, ",\"flags\":\"%s\",\"nhop\":%u,", flag_letters(flags |
	    RTF_UP), r->rta_knh_id);
	/* The route's own, when it has one: or it is its interface's. */
	if (mtu != 0)
		fprintf(c->out, "\"mtu\":%u,", mtu);
	fprintf(c->out, "\"interface-name\":");
	jstring(c, ifn);
	fprintf(c->out, ",\"metric\":%u,\"weight\":%u,\"fib\":%u,\"prefixlen\":%u",
	    metric, weight, r->rta_table, r->rtm_dst_len);
	if (r->rta_pref_src != NULL) {
		fprintf(c->out, ",\"source\":");
		jstring(c, addr_text(r->rta_pref_src, src, sizeof(src)));
	}
	/* One of several ways the route has: which, of how many. */
	if (c->paths > 1)
		fprintf(c->out, ",\"path\":%u,\"paths\":%u", c->path, c->paths);
	if (expire != 0)
		fprintf(c->out, ",\"expire-time\":\"%u\"", expire);
	fprintf(c->out, "}\n");
}

static void
route_rows(struct rl *c, struct snl_state *ss, struct nlmsghdr *hdr)
{
	struct snl_parsed_route	 r = { .rtax_weight = RT_DEFAULT_WEIGHT };
	const struct rta_mpath_nh *nh;
	uint32_t		 i;

	if (!snl_parse_nlmsg(ss, hdr, &snl_rtm_route_parser, &r))
		return;
	if (!covers(c, &r)) {
		c->total++;
		return;
	}
	c->paths = r.rta_multipath.count;
	if (r.rta_multipath.count == 0) {
		row(c, &r, r.rta_gw, r.rta_oif, r.rta_rtflags, r.rtax_weight,
		    r.rta_metric, r.rtax_mtu, r.rta_expire);
		return;
	}
	for (i = 0; i < r.rta_multipath.count; i++) {
		nh = (const struct rta_mpath_nh *)r.rta_multipath.items[i];
		c->path = i + 1;
		row(c, &r, nh->gw, nh->ifindex, nh->rta_rtflags != 0 ?
		    nh->rta_rtflags : r.rta_rtflags, nh->rtnh_weight,
		    nh->rta_metric != 0 ? nh->rta_metric : r.rta_metric,
		    nh->rtax_mtu, nh->rta_expire);
		/* One route, however many ways it has. */
		if (i > 0)
			c->total--;
	}
}

static int
routes(struct rl *c, struct snl_state *ss, int af, uint32_t fib)
{
	struct {
		struct nlmsghdr	hdr;
		struct rtmsg	rtmsg;
		struct nlattr	nla_fib;
		uint32_t	fib;
	}			 msg;
	struct snl_errmsg_data	 e = { 0 };
	struct nlmsghdr		*hdr;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.nlmsg_type = RTM_GETROUTE;
	msg.hdr.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	msg.hdr.nlmsg_seq = snl_get_seq(ss);
	msg.hdr.nlmsg_len = sizeof(msg);
	msg.rtmsg.rtm_family = (unsigned char)af;
	msg.nla_fib.nla_len = sizeof(struct nlattr) + sizeof(uint32_t);
	msg.nla_fib.nla_type = RTA_TABLE;
	msg.fib = fib;
	if (!snl_send_message(ss, &msg.hdr)) {
		fprintf(stderr, "netlink: %s\n", strerror(errno));
		return (1);
	}
	while ((hdr = snl_read_reply_multi(ss, msg.hdr.nlmsg_seq, &e)) !=
	    NULL) {
		route_rows(c, ss, hdr);
		snl_clear_lb(ss);
	}
	if (e.error != 0) {
		fprintf(stderr, "the routes of table %u: %s\n", fib,
		    strerror(e.error));
		return (1);
	}
	return (0);
}

/* "10.0.0.0/24", "default" with the family af, or an address alone. */
static bool
prefix(const char *s, int af, struct sockaddr_storage *ss, int *plenp)
{
	struct sockaddr_in	*s4;
	struct sockaddr_in6	*s6;
	const char		*slash, *e;
	char			 buf[INET6_ADDRSTRLEN + 1];

	memset(ss, 0, sizeof(*ss));
	s4 = (struct sockaddr_in *)(void *)ss;
	s6 = (struct sockaddr_in6 *)(void *)ss;
	if (strcmp(s, "default") == 0) {
		*plenp = 0;
		ss->ss_family = (sa_family_t)af;
		ss->ss_len = af == AF_INET ? sizeof(*s4) : sizeof(*s6);
		return (af == AF_INET || af == AF_INET6);
	}
	slash = strchr(s, '/');
	snprintf(buf, sizeof(buf), "%.*s", slash != NULL ? (int)(slash - s) :
	    (int)strlen(s), s);
	if (inet_pton(AF_INET, buf, &s4->sin_addr) == 1) {
		s4->sin_family = AF_INET;
		s4->sin_len = sizeof(*s4);
		*plenp = 32;
	} else if (inet_pton(AF_INET6, buf, &s6->sin6_addr) == 1) {
		s6->sin6_family = AF_INET6;
		s6->sin6_len = sizeof(*s6);
		*plenp = 128;
	} else
		return (false);
	if (slash != NULL) {
		*plenp = (int)strtonum(slash + 1, 0, *plenp, &e);
		if (e != NULL)
			return (false);
	}
	return (true);
}

static int
route_get(struct rl *c, struct snl_state *ss, const char *address,
    uint32_t fib)
{
	struct snl_parsed_route	 r = { .rtax_weight = RT_DEFAULT_WEIGHT };
	struct sockaddr_storage	 dst;
	struct snl_writer	 nw;
	struct nlmsghdr		*hdr;
	struct rtmsg		*rtm;
	char			 a[INET6_ADDRSTRLEN + IF_NAMESIZE + 8],
				 ifn[IF_NAMESIZE];
	int			 plen;

	if (!prefix(address, AF_UNSPEC, &dst, &plen))
		return (2);
	snl_init_writer(ss, &nw);
	hdr = snl_create_msg_request(&nw, RTM_GETROUTE);
	rtm = snl_reserve_msg_object(&nw, struct rtmsg);
	rtm->rtm_family = dst.ss_family;
	rtm->rtm_dst_len = (unsigned char)plen;
	snl_add_msg_attr_ip(&nw, RTA_DST, (struct sockaddr *)&dst);
	snl_add_msg_attr_u32(&nw, RTA_TABLE, fib);
	if ((hdr = snl_finalize_msg(&nw)) == NULL || !snl_send_message(ss,
	    hdr) || (hdr = snl_read_reply(ss, hdr->nlmsg_seq)) == NULL ||
	    hdr->nlmsg_type != NL_RTM_NEWROUTE || !snl_parse_nlmsg(ss, hdr,
	    &snl_rtm_route_parser, &r))
		return (1);
	if (if_indextoname(r.rta_oif, ifn) == NULL)
		ifn[0] = '\0';
	fprintf(c->out, "{\"to\":");
	jstring(c, address);
	fprintf(c->out, ",\"destination\":");
	if (r.rtm_dst_len == 0)
		fprintf(c->out, "\"default\"");
	else
		jstring(c, addr_text(r.rta_dst, a, sizeof(a)));
	fprintf(c->out, ",\"prefixlen\":%u,\"gateway\":", r.rtm_dst_len);
	if (r.rta_gw != NULL && (r.rta_gw->sa_family == AF_INET ||
	    r.rta_gw->sa_family == AF_INET6))
		jstring(c, addr_text(r.rta_gw, a, sizeof(a)));
	else
		fprintf(c->out, "\"link#%u\"", r.rta_oif);
	fprintf(c->out, ",\"fib\":\"%u\",\"interface\":", fib);
	jstring(c, ifn);
	fprintf(c->out, ",\"flags\":\"%s\",\"metric\":%u,\"weight\":%u}\n",
	    flag_letters(r.rta_rtflags | RTF_UP), r.rta_metric, r.rtax_weight);
	return (0);
}

/* argv: destination gateway interface fib metric [weight source]. */
static int
route_change(struct snl_state *ss, bool del, int argc, char **argv)
{
	struct sockaddr_storage	 dst, gw, src;
	struct snl_errmsg_data	 e = { 0 };
	struct snl_writer	 nw;
	struct nlmsghdr		*hdr;
	struct rtmsg		*rtm;
	struct rtnexthop	*rtnh;
	char			 first[INET6_ADDRSTRLEN + 1], *copy, *it, *one,
				*at;
	uint32_t		 fib, metric, weight, oif, flags;
	int			 plen, gplen, af, moff, noff;
	bool			 has_gw, has_src, many;

	if (argc != (del ? 5 : 7))
		return (2);
	has_gw = strcmp(argv[1], "-") != 0;
	many = has_gw && strchr(argv[1], ',') != NULL;
	first[0] = '\0';
	if (many)
		snprintf(first, sizeof(first), "%.*s", (int)strcspn(argv[1],
		    "@,"), argv[1]);
	has_src = !del && strcmp(argv[6], "-") != 0;
	oif = strcmp(argv[2], "-") != 0 ? if_nametoindex(argv[2]) : 0;
	if (strcmp(argv[2], "-") != 0 && oif == 0) {
		fprintf(stderr, "%s: no such interface\n", argv[2]);
		return (1);
	}
	fib = (uint32_t)strtoul(argv[3], NULL, 10);
	metric = (uint32_t)strtoul(argv[4], NULL, 10);
	weight = del ? 0 : (uint32_t)strtoul(argv[5], NULL, 10);
	if (has_gw && !prefix(many ? first : argv[1], AF_UNSPEC, &gw, &gplen))
		return (2);
	/* "default" is of its gateway's family, IPv4's when it has none. */
	af = has_gw && gw.ss_family == AF_INET6 ? AF_INET6 : AF_INET;
	if (!prefix(argv[0], af, &dst, &plen) || (has_src && !prefix(argv[6],
	    AF_UNSPEC, &src, &gplen)))
		return (2);
	af = dst.ss_family;
	flags = RTF_UP | RTF_STATIC | (has_gw ? RTF_GATEWAY : 0) |
	    (plen == (af == AF_INET ? 32 : 128) ? RTF_HOST : 0);

	snl_init_writer(ss, &nw);
	hdr = snl_create_msg_request(&nw, del ? RTM_DELROUTE : RTM_NEWROUTE);
	if (!del)
		hdr->nlmsg_flags |= NLM_F_CREATE | NLM_F_APPEND;
	rtm = snl_reserve_msg_object(&nw, struct rtmsg);
	rtm->rtm_family = (unsigned char)af;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_type = RTN_UNICAST;
	rtm->rtm_dst_len = (unsigned char)plen;
	snl_add_msg_attr_ip(&nw, RTA_DST, (struct sockaddr *)&dst);
	if (has_src)
		snl_add_msg_attr_ip(&nw, RTA_PREFSRC, (struct sockaddr *)&src);
	snl_add_msg_attr_u32(&nw, RTA_TABLE, fib);
	if (many) {
		/* Each next hop: its share, then its gateway. */
		moff = snl_add_msg_attr_nested(&nw, RTA_MULTIPATH);
		copy = strdup(argv[1]);
		for (it = copy; copy != NULL && (one = strsep(&it, ",")) !=
		    NULL; ) {
			if ((at = strchr(one, '@')) != NULL)
				*at++ = '\0';
			if (!prefix(one, AF_UNSPEC, &gw, &gplen)) {
				fprintf(stderr, "%s: not an address\n", one);
				return (2);
			}
			noff = snl_get_msg_offset(&nw);
			rtnh = snl_reserve_msg_object(&nw, struct rtnexthop);
			rtnh->rtnh_hops = at != NULL ? (unsigned char)strtoul(
			    at, NULL, 10) : 1;
			if (gw.ss_family == af)
				snl_add_msg_attr_ip(&nw, RTA_GATEWAY,
				    (struct sockaddr *)&gw);
			else
				snl_add_msg_attr_ipvia(&nw, RTA_VIA,
				    (struct sockaddr *)&gw);
			rtnh = snl_restore_msg_offset(&nw, noff,
			    struct rtnexthop);
			rtnh->rtnh_len = (unsigned short)(snl_get_msg_offset(
			    &nw) - noff);
		}
		free(copy);
		snl_end_attr_nested(&nw, moff);
	} else if (has_gw && gw.ss_family == af)
		snl_add_msg_attr_ip(&nw, RTA_GATEWAY, (struct sockaddr *)&gw);
	else if (has_gw)
		snl_add_msg_attr_ipvia(&nw, RTA_VIA, (struct sockaddr *)&gw);
	if (oif != 0)
		snl_add_msg_attr_u32(&nw, RTA_OIF, oif);
	if (!del)
		snl_add_msg_attr_u32(&nw, NL_RTA_RTFLAGS, flags);
	if (metric != 0)
		snl_add_msg_attr_u32(&nw, NL_RTA_PRIORITY, metric);
	if (weight != 0)
		snl_add_msg_attr_u32(&nw, NL_RTA_WEIGHT, weight);
	if ((hdr = snl_finalize_msg(&nw)) == NULL || !snl_send_message(ss,
	    hdr) || !snl_read_reply_code(ss, hdr->nlmsg_seq, &e)) {
		if (e.error == 0)
			e.error = errno != 0 ? errno : EINVAL;
		fprintf(stderr, "%s: %s%s%s\n", argv[0], e.error == ESRCH ?
		    "there is no such route" : e.error == EEXIST ?
		    "the route is there already" : strerror(e.error),
		    e.error_str != NULL ? ": " : "", e.error_str != NULL ?
		    e.error_str : "");
		return (1);
	}
	return (0);
}

/*
 * The routes of a table, a row a line into out, and "#total n" last;
 * of family 4, 6 or 0 for both, those with filter in them, those the
 * address cover is in: each NULL for any.  For the helper, and for the
 * daemon itself, which gives out a stream of its own.
 */
int
route_list(FILE *out, int fam, uint32_t fib, const char *filter,
    const char *cover)
{
	struct snl_state	ss;
	struct rl		c;
	int			rc;

	if (!snl_init(&ss, NETLINK_ROUTE)) {
		fprintf(stderr, "netlink(4): %s\n", strerror(errno));
		return (1);
	}
	memset(&c, 0, sizeof(c));
	c.out = out;
	c.filter = filter;
	if (cover != NULL) {
		c.cover_text = cover;
		c.cover_af = inet_pton(AF_INET, cover, c.cover) == 1 ? AF_INET :
		    inet_pton(AF_INET6, cover, c.cover) == 1 ? AF_INET6 :
		    AF_UNSPEC;
		fam = c.cover_af == AF_INET ? 4 : 6;
	}
	rc = 0;
	if (fam == 0 || fam == 4)
		rc = routes(&c, &ss, AF_INET, fib);
	/* The other family's table is marked where it begins. */
	if (fam == 0)
		fprintf(out, "#family 6\n");
	if (fam == 0 || fam == 6)
		rc = routes(&c, &ss, AF_INET6, fib) != 0 && rc != 0;
	fprintf(out, "#total %ju\n", (uintmax_t)c.total);
	snl_free(&ss);
	return (rc);
}

/* The route the kernel would take to address, one line into out. */
int
route_lookup(FILE *out, const char *address, uint32_t fib)
{
	struct snl_state	ss;
	struct rl		c;
	int			rc;

	if (!snl_init(&ss, NETLINK_ROUTE)) {
		fprintf(stderr, "netlink(4): %s\n", strerror(errno));
		return (1);
	}
	memset(&c, 0, sizeof(c));
	c.out = out;
	rc = route_get(&c, &ss, address, fib);
	snl_free(&ss);
	return (rc);
}

/* The helper's verbs that begin with "route"; argv[0] is the verb. */
int
route_helper(int argc, char **argv)
{
	struct snl_state	ss;
	int			rc;

	if (strcmp(argv[0], "routes") == 0 && argc == 5)
		return (route_list(stdout, atoi(argv[1]), (uint32_t)strtoul(
		    argv[2], NULL, 10), strcmp(argv[3], "-") != 0 ? argv[3] :
		    NULL, strcmp(argv[4], "-") != 0 ? argv[4] : NULL));
	if (strcmp(argv[0], "route-get") == 0 && argc == 3)
		return (route_lookup(stdout, argv[1], (uint32_t)strtoul(
		    argv[2], NULL, 10)));
	if (strcmp(argv[0], "route-add") != 0 && strcmp(argv[0], "route-del") !=
	    0)
		return (2);
	if (!snl_init(&ss, NETLINK_ROUTE)) {
		fprintf(stderr, "netlink(4): %s\n", strerror(errno));
		return (1);
	}
	rc = route_change(&ss, argv[0][6] == 'd', argc - 1, argv + 1);
	snl_free(&ss);
	return (rc);
}

/*
 * The daemon's side: one socket of its own, in a thread of its own,
 * told by the kernel of every route, interface and address that comes,
 * goes or changes.  Each is an event (gula/events.c), which is what a
 * program run now and then cannot give: nothing is missed between two
 * looks.  A storm of routes, a BGP session coming up, is counted and
 * said as one event a second and not as each of its routes.
 */
#define	WATCH_ROUTES_A_SECOND	40

static void
watch_route(struct snl_state *ss, struct nlmsghdr *hdr, bool gone)
{
	struct rl	 rc;
	static time_t	 second;
	static unsigned	 seen, left;
	char		*json;
	size_t		 len;
	time_t		 now;

	now = time(NULL);
	if (now != second) {
		if (left > 0)
			event_add("routes", "{\"changed\":%u}", left);
		second = now;
		seen = left = 0;
	}
	if (++seen > WATCH_ROUTES_A_SECOND) {
		left++;
		return;
	}
	json = NULL;
	memset(&rc, 0, sizeof(rc));
	if ((rc.out = open_memstream(&json, &len)) == NULL)
		return;
	route_rows(&rc, ss, hdr);
	fclose(rc.out);
	if (json != NULL && len > 1) {
		json[strcspn(json, "\n")] = '\0';
		event_add(gone ? "route-del" : "route-add", "%s", json);
	}
	free(json);
}

static void
watch_link(struct snl_state *ss, struct nlmsghdr *hdr, bool gone)
{
	struct rl		 wc, *c;
	struct snl_parsed_link	l = { 0 };
	char			*json;
	size_t			 len;

	if (!snl_parse_nlmsg(ss, hdr, &snl_rtm_link_parser, &l) ||
	    l.ifla_ifname == NULL)
		return;
	json = NULL;
	memset(&wc, 0, sizeof(wc));
	if ((wc.out = open_memstream(&json, &len)) == NULL)
		return;
	c = &wc;
	fprintf(c->out, "{\"interface\":");
	jstring(c, l.ifla_ifname);
	fprintf(c->out, ",\"up\":%s,\"carrier\":%s,\"mtu\":%u}",
	    (l.ifi_flags & IFF_UP) != 0 ? "true" : "false",
	    l.ifla_operstate == IF_OPER_UP || l.ifla_carrier != 0 ? "true" :
	    "false", l.ifla_mtu);
	fclose(c->out);
	if (json != NULL)
		event_add(gone ? "link-del" : "link", "%s", json);
	free(json);
}

static void
watch_addr(struct snl_state *ss, struct nlmsghdr *hdr, bool gone)
{
	struct rl		 wc, *c;
	struct snl_parsed_addr	 a = { 0 };
	const struct sockaddr	*sa;
	char			 text[INET6_ADDRSTRLEN + IF_NAMESIZE + 8],
				 ifn[IF_NAMESIZE], *json;
	size_t			 len;

	if (!snl_parse_nlmsg(ss, hdr, &snl_rtm_addr_parser, &a))
		return;
	sa = a.ifa_local != NULL ? a.ifa_local : a.ifa_address;
	if (sa == NULL)
		return;
	if (if_indextoname(a.ifa_index, ifn) == NULL)
		ifn[0] = '\0';
	json = NULL;
	memset(&wc, 0, sizeof(wc));
	if ((wc.out = open_memstream(&json, &len)) == NULL)
		return;
	c = &wc;
	fprintf(c->out, "{\"interface\":");
	jstring(c, ifn);
	fprintf(c->out, ",\"address\":");
	jstring(c, addr_text(sa, text, sizeof(text)));
	fprintf(c->out, ",\"prefixlen\":%u}", a.ifa_prefixlen);
	fclose(c->out);
	if (json != NULL)
		event_add(gone ? "address-del" : "address-add", "%s", json);
	free(json);
}

static void *
watcher(void *arg __unused)
{
	static const int	 groups[] = { RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR,
				    RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV4_ROUTE,
				    RTNLGRP_IPV6_ROUTE };
	struct snl_state	 ss;
	struct nlmsghdr		*hdr;
	size_t			 i;

	if (!snl_init(&ss, NETLINK_ROUTE)) {
		logmsg(LOG_NOTICE, "no events of the network: netlink(4): %s",
		    strerror(errno));
		return (NULL);
	}
	for (i = 0; i < nitems(groups); i++)
		if (setsockopt(ss.fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		    &groups[i], sizeof(groups[i])) == -1)
			logmsg(LOG_NOTICE, "netlink(4) group %d: %s",
			    groups[i], strerror(errno));
	while ((hdr = snl_read_message(&ss)) != NULL) {
		switch (hdr->nlmsg_type) {
		case NL_RTM_NEWROUTE:
		case NL_RTM_DELROUTE:
			watch_route(&ss, hdr, hdr->nlmsg_type ==
			    NL_RTM_DELROUTE);
			break;
		case NL_RTM_NEWLINK:
		case NL_RTM_DELLINK:
			watch_link(&ss, hdr, hdr->nlmsg_type == NL_RTM_DELLINK);
			break;
		case NL_RTM_NEWADDR:
		case NL_RTM_DELADDR:
			watch_addr(&ss, hdr, hdr->nlmsg_type == NL_RTM_DELADDR);
			break;
		}
		snl_clear_lb(&ss);
	}
	logmsg(LOG_NOTICE, "the events of the network ended: netlink(4): %s",
	    strerror(errno));
	snl_free(&ss);
	return (NULL);
}

void
route_watch_start(void)
{
	pthread_t	tid;
	int		error;

	if ((error = pthread_create(&tid, NULL, watcher, NULL)) != 0) {
		logmsg(LOG_WARNING, "no events of the network: "
		    "pthread_create: %s", strerror(error));
		return;
	}
	(void)pthread_detach(tid);
}
