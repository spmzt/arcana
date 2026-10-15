/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: ipfw(8)'s ruleset walked for one packet, as the kernel walks
 * it (ip_fw2.c), to say which rule decides it: the ruleset as `ipfw
 * list` prints it, which is ipfw's own canonical form, and the tables
 * as `ipfw table all list` does.
 *
 * A packet is its family, addresses, protocol and ports, its direction,
 * the interfaces it came in on and goes out by, whether it opens a TCP
 * connection (SYN) or belongs to one, and what the routing says of its
 * source (verrevpath, versrcreach).  Rules are taken in order; count,
 * setfib, tag and the like go on, skipto jumps, check-state and the
 * first keep-state or limit look the flow up: a reply is let through by
 * the state its request made on this host, and finds none when the
 * request went another way.  What the walk cannot know of a packet
 * that does not exist (a socket's uid or jail, a tag, a MAC address,
 * an option it does not read) makes the rule uncertain: said, and the
 * walk goes on as though it did not match, so that what decides is the
 * first rule that surely does, with the doubtful ones before it named.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <fnmatch.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fwmatch.h"

#define	FW_TOKENS	128

/* The value of the table entry a rule's address last matched: what
 * its tablearg stands for (fwd, setfib, skipto). */
static char	tablearg[64];

/* ---- Tables ---------------------------------------------------------- */

static struct fwtable *
table_of(struct fwset *s, const char *name, bool make)
{
	size_t	i;

	for (i = 0; i < s->ntables; i++)
		if (strcmp(s->tables[i].name, name) == 0)
			return (&s->tables[i]);
	if (!make || s->ntables == FW_TABLES)
		return (NULL);
	memset(&s->tables[s->ntables], 0, sizeof(s->tables[0]));
	snprintf(s->tables[s->ntables].name, sizeof(s->tables[0].name), "%s",
	    name);
	return (&s->tables[s->ntables++]);
}

/* "10.0.0.0/8" or "2001:db8::/32" or "1.2.3.4": a prefix. */
static bool
prefix_parse(const char *s, int *af, uint8_t a[16], int *len)
{
	char	buf[INET6_ADDRSTRLEN + 8], *slash, *colon, *e;
	uint8_t	m[16];
	int	i, n;

	if (strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
		return (false);
	slash = strchr(buf, '/');
	if (slash != NULL)
		*slash++ = '\0';
	if (inet_pton(AF_INET, buf, a) == 1) {
		*af = AF_INET;
		*len = 32;
	} else if (strchr(buf, ':') != NULL && strchr(buf, ':') !=
	    strrchr(buf, ':') && inet_pton(AF_INET6, buf, a) == 1) {
		*af = AF_INET6;
		*len = 128;
	} else if ((colon = strchr(buf, ':')) != NULL) {
		/* addr:mask, IPv4's netmask form: a contiguous one only. */
		*colon++ = '\0';
		if (inet_pton(AF_INET, buf, a) != 1 || inet_pton(AF_INET,
		    colon, m) != 1)
			return (false);
		*af = AF_INET;
		for (n = 0, i = 0; i < 32; i++)
			if ((m[i / 8] & (0x80 >> (i % 8))) != 0)
				n = i + 1;
		*len = n;
		return (true);
	} else
		return (false);
	if (slash != NULL) {
		n = (int)strtol(slash, &e, 10);
		if (*e != '\0' || n < 0 || n > *len)
			return (false);
		*len = n;
	}
	return (true);
}

static bool
in_prefix(int af, const uint8_t *a, int paf, const uint8_t *p, int len)
{
	int	i;

	if (af != paf)
		return (false);
	for (i = 0; i < len / 8; i++)
		if (a[i] != p[i])
			return (false);
	if (len % 8 != 0 && ((a[i] ^ p[i]) & (0xff << (8 - len % 8))) != 0)
		return (false);
	return (true);
}

/* The longest entry of t that covers a; its value, or NULL: none. */
static const struct fwentry *
table_lookup(const struct fwtable *t, int af, const uint8_t *a)
{
	const struct fwentry	*best = NULL;
	size_t			 i;

	for (i = 0; i < t->n; i++)
		if (in_prefix(af, a, t->v[i].af, t->v[i].addr, t->v[i].len) &&
		    (best == NULL || t->v[i].len > best->len))
			best = &t->v[i];
	return (best);
}

/* ---- Rules ------------------------------------------------------------ */

/* Words, "{ a or b }" one of them; "//" and what follows left out. */
static int
tokens(char *line, char **tok, int max)
{
	char	*p, *start;
	int	 n = 0, depth;

	for (p = line; *p != '\0' && n < max; ) {
		while (isspace((unsigned char)*p))
			p++;
		if (*p == '\0' || (p[0] == '/' && p[1] == '/'))
			break;
		start = p;
		if (*p == '{') {
			for (depth = 0; *p != '\0'; p++) {
				if (*p == '{')
					depth++;
				else if (*p == '}' && --depth == 0) {
					p++;
					break;
				}
			}
		} else
			while (*p != '\0' && !isspace((unsigned char)*p))
				p++;
		if (*p != '\0')
			*p++ = '\0';
		tok[n++] = start;
	}
	return (n);
}

/* By number; of one number, as they were (mergesort is stable). */
static int
rule_cmp(const void *a, const void *b)
{
	const struct fwrule	*x = a, *y = b;

	return (x->num < y->num ? -1 : x->num > y->num);
}

int
fw_parse(struct fwset *s, const char *list, const char *tables)
{
	const char	*p, *e;
	struct fwrule	*r;
	struct fwtable	*t;
	char		 line[2048], *sp, *v;
	size_t		 n;

	memset(s, 0, sizeof(*s));
	t = NULL;
	for (p = tables != NULL ? tables : ""; *p != '\0'; p = e) {
		e = strchr(p, '\n');
		n = e != NULL ? (size_t)(e - p) : strlen(p);
		e = e != NULL ? e + 1 : p + n;
		if (n >= sizeof(line))
			continue;
		memcpy(line, p, n);
		line[n] = '\0';
		/* "--- table(name), set(0) ---" begins one. */
		if (strncmp(line, "--- table(", 10) == 0) {
			if ((sp = strchr(line + 10, ')')) != NULL)
				*sp = '\0';
			t = table_of(s, line + 10, true);
			continue;
		}
		if (t == NULL || t->n == FW_TABLE_ENTRIES)
			continue;
		if (t->n == t->cap) {
			struct fwentry	*nv;

			t->cap = t->cap == 0 ? 16 : t->cap * 2;
			if ((nv = realloc(t->v, t->cap * sizeof(*nv))) == NULL)
				return (-1);
			t->v = nv;
		}
		sp = line;
		v = strsep(&sp, " \t");
		if (v == NULL || !prefix_parse(v, &t->v[t->n].af,
		    t->v[t->n].addr, &t->v[t->n].len))
			continue;
		snprintf(t->v[t->n].value, sizeof(t->v[0].value), "%s",
		    sp != NULL ? sp + strspn(sp, " \t") : "0");
		t->n++;
	}
	for (p = list != NULL ? list : ""; *p != '\0' && s->n < FW_RULES;
	    p = e) {
		e = strchr(p, '\n');
		n = e != NULL ? (size_t)(e - p) : strlen(p);
		e = e != NULL ? e + 1 : p + n;
		while (n > 0 && isspace((unsigned char)p[n - 1]))
			n--;
		if (n == 0 || !isdigit((unsigned char)*p) || n >=
		    sizeof(r->text))
			continue;
		if (s->n == s->cap) {
			struct fwrule	*nr;

			s->cap = s->cap == 0 ? 64 : s->cap * 2;
			if ((nr = realloc(s->rules, s->cap * sizeof(*nr))) ==
			    NULL)
				return (-1);
			s->rules = nr;
		}
		r = &s->rules[s->n];
		memset(r, 0, sizeof(*r));
		memcpy(r->text, p, n);
		r->text[n] = '\0';
		r->num = strtol(r->text, NULL, 10);
		/* "65535 count ... not // orphaned dynamic states counter":
		 * the kernel's own, of states, not of packets. */
		if (strstr(r->text, "orphaned dynamic states") != NULL)
			continue;
		s->n++;
	}
	/* In the kernel's order, whatever order they were given in. */
	if (s->n > 1 && mergesort(s->rules, s->n, sizeof(s->rules[0]),
	    rule_cmp) != 0)
		return (-1);
	return (0);
}

void
fw_free(struct fwset *s)
{
	size_t	i;

	for (i = 0; i < s->ntables; i++)
		free(s->tables[i].v);
	free(s->rules);
	memset(s, 0, sizeof(*s));
}

/* A port list, "22", "1024-65535", "80,443": does port match. */
static bool
port_list(const char *s, int port, bool *ok)
{
	char		 buf[512], *sp, *w, *dash, *e;
	struct servent	*se;
	long		 lo, hi;

	*ok = true;
	if (strlcpy(buf, s, sizeof(buf)) >= sizeof(buf)) {
		*ok = false;
		return (false);
	}
	for (sp = buf; (w = strsep(&sp, ",")) != NULL; ) {
		dash = strchr(w, '-');
		if (dash != NULL && dash != w)
			*dash++ = '\0';
		else
			dash = NULL;
		lo = strtol(w, &e, 10);
		if (*e != '\0') {
			if ((se = getservbyname(w, NULL)) == NULL) {
				*ok = false;
				return (false);
			}
			lo = ntohs((uint16_t)se->s_port);
		}
		hi = dash != NULL ? strtol(dash, &e, 10) : lo;
		if (dash != NULL && *e != '\0') {
			*ok = false;
			return (false);
		}
		if (port >= lo && port <= hi)
			return (true);
	}
	return (false);
}

static bool
is_ports(const char *s)
{

	return (s != NULL && s[0] != '\0' && strspn(s, "0123456789,-") ==
	    strlen(s));
}

enum tri { NO, YES, MAYBE };

static enum tri
tri_not(enum tri t, bool neg)
{

	return (t == MAYBE ? MAYBE : (t == YES) != neg ? YES : NO);
}

/* An address word of a rule against a; me: the host's own. */
static enum tri
addr_match(const struct fwset *s, const char *w, const struct fwpkt *k,
    const uint8_t *a)
{
	char		 buf[512], *sp, *x, *comma;
	const struct fwtable *t;
	const struct fwentry *en;
	uint8_t		 pa[16];
	int		 paf, plen;
	size_t		 i;
	enum tri	 r, one;

	if (strcmp(w, "any") == 0)
		return (YES);
	if (strcmp(w, "me") == 0 || strcmp(w, "me6") == 0) {
		if ((strcmp(w, "me") == 0 && k->af != AF_INET) ||
		    (strcmp(w, "me6") == 0 && k->af != AF_INET6))
			return (NO);
		for (i = 0; i < k->nlocal; i++)
			if (k->local_af[i] == k->af && memcmp(k->local[i], a,
			    k->af == AF_INET ? 4 : 16) == 0)
				return (YES);
		return (NO);
	}
	if (strncmp(w, "table(", 6) == 0) {
		if (strlcpy(buf, w + 6, sizeof(buf)) >= sizeof(buf))
			return (MAYBE);
		if ((x = strchr(buf, ')')) != NULL)
			*x = '\0';
		comma = strchr(buf, ',');
		if (comma != NULL)
			*comma++ = '\0';
		if ((t = table_of((struct fwset *)(uintptr_t)s, buf, false)) ==
		    NULL)
			return (NO);
		if ((en = table_lookup(t, k->af, a)) == NULL)
			return (NO);
		if (comma != NULL && strcmp(en->value, comma) != 0)
			return (NO);
		snprintf(tablearg, sizeof(tablearg), "%s", en->value);
		return (YES);
	}
	/* { a or b }, and a,b,c/24 lists: any of them. */
	if (w[0] == '{') {
		if (strlcpy(buf, w + 1, sizeof(buf)) >= sizeof(buf))
			return (MAYBE);
		if ((x = strrchr(buf, '}')) != NULL)
			*x = '\0';
		r = NO;
		for (sp = buf; (x = strsep(&sp, " \t")) != NULL; ) {
			if (*x == '\0' || strcmp(x, "or") == 0)
				continue;
			one = addr_match(s, x, k, a);
			if (one == YES)
				return (YES);
			if (one == MAYBE)
				r = MAYBE;
		}
		return (r);
	}
	if (strchr(w, ',') != NULL && strncmp(w, "table(", 6) != 0) {
		if (strlcpy(buf, w, sizeof(buf)) >= sizeof(buf))
			return (MAYBE);
		r = NO;
		for (sp = buf; (x = strsep(&sp, ",")) != NULL; ) {
			/* 1.2.3.0/24{1,5}: a set; not read here. */
			if (strchr(x, '{') != NULL)
				return (MAYBE);
			one = addr_match(s, x, k, a);
			if (one == YES)
				return (YES);
			if (one == MAYBE)
				r = MAYBE;
		}
		return (r);
	}
	if (!prefix_parse(w, &paf, pa, &plen))
		return (MAYBE);		/* a host name, a set: not known */
	return (in_prefix(k->af, a, paf, pa, plen) ? YES : NO);
}

/* The rule's protocol word against the packet's. */
static enum tri
proto_match(const char *w, const struct fwpkt *k)
{
	char		 buf[256], *sp, *x;
	struct protoent	*pe;
	enum tri	 r, one;
	int		 p;

	if (strcmp(w, "ip") == 0 || strcmp(w, "all") == 0)
		return (YES);
	if (strcmp(w, "ip4") == 0 || strcmp(w, "ipv4") == 0)
		return (k->af == AF_INET ? YES : NO);
	if (strcmp(w, "ip6") == 0 || strcmp(w, "ipv6") == 0)
		return (k->af == AF_INET6 ? YES : NO);
	if (w[0] == '{') {
		if (strlcpy(buf, w + 1, sizeof(buf)) >= sizeof(buf))
			return (MAYBE);
		if ((x = strrchr(buf, '}')) != NULL)
			*x = '\0';
		r = NO;
		for (sp = buf; (x = strsep(&sp, " \t")) != NULL; ) {
			if (*x == '\0' || strcmp(x, "or") == 0)
				continue;
			if ((one = proto_match(x, k)) == YES)
				return (YES);
			if (one == MAYBE)
				r = MAYBE;
		}
		return (r);
	}
	if (strcmp(w, "icmp6") == 0 || strcmp(w, "ipv6-icmp") == 0)
		p = IPPROTO_ICMPV6;
	else if (isdigit((unsigned char)w[0]))
		p = atoi(w);
	else if ((pe = getprotobyname(w)) != NULL)
		p = pe->p_proto;
	else
		return (MAYBE);
	return (p == k->proto ? YES : NO);
}

/* An interface word (via, recv, xmit) against the one the packet has. */
static enum tri
if_match(const struct fwset *s, const char *w, const char *ifname,
    const struct fwpkt *k)
{
	uint8_t	a[16];
	int	af, len;
	size_t	i;

	if (strcmp(w, "any") == 0)
		return (ifname != NULL ? YES : NO);
	if (ifname == NULL)
		return (NO);
	if (strncmp(w, "table(", 6) == 0)
		return (MAYBE);
	/* An address: the interface that has it. */
	if (prefix_parse(w, &af, a, &len)) {
		for (i = 0; i < k->nlocal; i++)
			if (k->local_af[i] == af && memcmp(k->local[i], a,
			    af == AF_INET ? 4 : 16) == 0)
				return (strcmp(k->local_if[i], ifname) == 0 ?
				    YES : NO);
		return (NO);
	}
	(void)s;
	return (fnmatch(w, ifname, 0) == 0 ? YES : NO);
}

static bool
action_word(const char *w)
{
	static const char *const acts[] = { "allow", "accept", "pass",
	    "permit", "deny", "drop", "reject", "unreach", "unreach6",
	    "reset", "reset6", "count", "skipto", "call", "return",
	    "check-state", "divert", "tee", "fwd", "forward", "nat", "pipe",
	    "queue", "netgraph", "ngtee", "setfib", "setdscp", "tag",
	    "untag", "reass", "nat64lsn", "nat64stl", "nat64clat", "nptv6",
	    "tcp-setmss", "eaction", "abort", "abort6", "nat64", "setmark",
	    "skip" };
	size_t	i;

	for (i = 0; i < nitems(acts); i++)
		if (strcmp(w, acts[i]) == 0)
			return (true);
	return (false);
}

/* Does the body of a rule (after its action) match the packet. */
static enum tri
body_match(const struct fwset *s, char **tok, int nt, int i,
    const struct fwpkt *k, bool *keep, char *why, size_t whylen)
{
	enum tri	 r = YES, one;
	bool		 neg, ok;
	const char	*w;

	*keep = false;
	why[0] = '\0';
#define	AND(x)	do {							\
	enum tri x_ = (x);						\
	if (x_ == NO)							\
		return (NO);						\
	if (x_ == MAYBE)						\
		r = MAYBE;						\
} while (0)
	if (i >= nt)
		return (YES);
	/* proto from SRC [ports] to DST [ports]; a rule written with
	 * options alone (return via any) names no protocol. */
	if (strcmp(tok[i], "in") != 0 && strcmp(tok[i], "out") != 0 &&
	    strcmp(tok[i], "via") != 0 && strcmp(tok[i], "recv") != 0 &&
	    strcmp(tok[i], "xmit") != 0 && strcmp(tok[i], "not") != 0)
		AND(proto_match(tok[i++], k));
	if (i < nt && strcmp(tok[i], "from") == 0) {
		i++;
		neg = i < nt && strcmp(tok[i], "not") == 0;
		if (neg)
			i++;
		if (i >= nt)
			return (MAYBE);
		AND(tri_not(addr_match(s, tok[i++], k, k->src), neg));
		if (i < nt && is_ports(tok[i])) {
			if (k->sport < 0)
				return (NO);
			one = port_list(tok[i++], k->sport, &ok) ? YES : NO;
			AND(ok ? one : MAYBE);
		}
		if (i < nt && strcmp(tok[i], "to") == 0) {
			i++;
			neg = i < nt && strcmp(tok[i], "not") == 0;
			if (neg)
				i++;
			if (i >= nt)
				return (MAYBE);
			AND(tri_not(addr_match(s, tok[i++], k, k->dst), neg));
			if (i < nt && is_ports(tok[i])) {
				if (k->dport < 0)
					return (NO);
				one = port_list(tok[i++], k->dport, &ok) ? YES :
				    NO;
				AND(ok ? one : MAYBE);
			}
		}
	}
	/* The options, each and-ed; "not" before one turns it. */
	for (; i < nt; i++) {
		neg = strcmp(tok[i], "not") == 0;
		if (neg && ++i >= nt)
			break;
		w = tok[i];
		if (strcmp(w, "in") == 0)
			one = !k->out ? YES : NO;
		else if (strcmp(w, "out") == 0)
			one = k->out ? YES : NO;
		else if ((strcmp(w, "via") == 0 || strcmp(w, "recv") == 0 ||
		    strcmp(w, "xmit") == 0) && i + 1 < nt) {
			/* via: the interface it goes out by when going out,
			 * else the one it came in on. */
			const char *ifn = strcmp(w, "recv") == 0 ? k->rcvif :
			    strcmp(w, "xmit") == 0 ? k->xmitif : k->out ?
			    k->xmitif : k->rcvif;

			one = if_match(s, tok[++i], ifn, k);
		} else if (strcmp(w, "keep-state") == 0 || strcmp(w,
		    "record-state") == 0 || strcmp(w, "limit") == 0) {
			*keep = true;
			if (strcmp(w, "limit") == 0)
				while (i + 1 < nt && tok[i + 1][0] != ':' &&
				    strcmp(tok[i + 1], "not") != 0 && !isdigit(
				    (unsigned char)tok[i + 1][0]) && (strcmp(
				    tok[i + 1], "src-addr") == 0 || strcmp(
				    tok[i + 1], "dst-addr") == 0 || strcmp(
				    tok[i + 1], "src-port") == 0 || strcmp(
				    tok[i + 1], "dst-port") == 0))
					i++;
			if (strcmp(w, "limit") == 0 && i + 1 < nt &&
			    isdigit((unsigned char)tok[i + 1][0]))
				i++;
			continue;
		} else if (w[0] == ':')
			continue;	/* a state's flow name */
		else if (strcmp(w, "setup") == 0)
			one = k->proto == IPPROTO_TCP && k->syn ? YES : NO;
		else if (strcmp(w, "established") == 0)
			one = k->proto == IPPROTO_TCP && k->ack ? YES : NO;
		else if ((strcmp(w, "icmptypes") == 0 || strcmp(w,
		    "icmp6types") == 0) && i + 1 < nt) {
			ok = true;
			one = (k->proto == IPPROTO_ICMP || k->proto ==
			    IPPROTO_ICMPV6) && k->icmptype >= 0 && port_list(
			    tok[++i], k->icmptype, &ok) ? YES : NO;
			if (!ok)
				one = MAYBE;
		} else if ((strcmp(w, "dst-port") == 0 || strcmp(w,
		    "src-port") == 0) && i + 1 < nt) {
			int port = w[0] == 'd' ? k->dport : k->sport;

			ok = true;
			one = port >= 0 && port_list(tok[++i], port, &ok) ?
			    YES : NO;
			if (!ok)
				one = MAYBE;
		} else if ((strcmp(w, "dst-ip") == 0 || strcmp(w, "src-ip") ==
		    0 || strcmp(w, "dst-ip6") == 0 || strcmp(w, "src-ip6") ==
		    0) && i + 1 < nt)
			one = addr_match(s, tok[++i], k, w[0] == 'd' ? k->dst :
			    k->src);
		else if (strcmp(w, "proto") == 0 && i + 1 < nt)
			one = proto_match(tok[++i], k);
		else if (strcmp(w, "ipv4") == 0 || strcmp(w, "ip4") == 0)
			one = k->af == AF_INET ? YES : NO;
		else if (strcmp(w, "ipv6") == 0 || strcmp(w, "ip6") == 0)
			one = k->af == AF_INET6 ? YES : NO;
		else if (strcmp(w, "verrevpath") == 0)
			one = k->rcvif == NULL || k->rpf ? YES : NO;
		else if (strcmp(w, "versrcreach") == 0)
			one = k->src_reach ? YES : NO;
		else if (strcmp(w, "antispoof") == 0)
			one = k->rcvif == NULL || (k->rpf && !k->src_local) ?
			    YES : NO;
		else if (strcmp(w, "frag") == 0 || strcmp(w, "layer2") == 0 ||
		    strcmp(w, "diverted") == 0 || strcmp(w,
		    "diverted-loopback") == 0 || strcmp(w,
		    "diverted-output") == 0)
			one = NO;	/* not a fragment, not of layer 2 */
		else if (strcmp(w, "fib") == 0 && i + 1 < nt)
			one = atoi(tok[++i]) == k->fib ? YES : NO;
		else if ((strcmp(w, "uid") == 0 || strcmp(w, "gid") == 0 ||
		    strcmp(w, "jail") == 0) && i + 1 < nt && !k->src_local &&
		    !k->dst_local) {
			/* A socket's: a packet passing through has none. */
			i++;
			one = NO;
		}
		else {
			/* Of what the walk cannot know: uid, gid, jail,
			 * tagged, mac, ipoptions, tcpflags, lookup, or. */
			if (why[0] == '\0')
				snprintf(why, whylen, "%s", w);
			one = MAYBE;
			/* Its argument, when it takes one. */
			if (i + 1 < nt && (strcmp(w, "uid") == 0 || strcmp(w,
			    "gid") == 0 || strcmp(w, "jail") == 0 ||
			    strcmp(w, "tagged") == 0 || strcmp(w,
			    "ipoptions") == 0 || strcmp(w, "tcpflags") == 0 ||
			    strcmp(w, "tcpoptions") == 0 || strcmp(w,
			    "iplen") == 0 || strcmp(w, "ipttl") == 0 ||
			    strcmp(w, "iptos") == 0 || strcmp(w, "dscp") == 0 ||
			    strcmp(w, "ipid") == 0 || strcmp(w, "ipversion") ==
			    0 || strcmp(w, "tcpack") == 0 || strcmp(w,
			    "tcpseq") == 0 || strcmp(w, "tcpwin") == 0 ||
			    strcmp(w, "tcpdatalen") == 0 || strcmp(w,
			    "mac-type") == 0 || strcmp(w, "flow") == 0 ||
			    strcmp(w, "ext6hdr") == 0 || strcmp(w,
			    "flow-id") == 0 || strcmp(w, "sockarg") == 0 ||
			    strcmp(w, "mark") == 0))
				i++;
			else if (strcmp(w, "mac") == 0 && i + 2 < nt)
				i += 2;
			else if (strcmp(w, "lookup") == 0 && i + 2 < nt)
				i += 2;
		}
		AND(tri_not(one, neg));
	}
#undef AND
	return (r);
}

static const char *
verdict_of(const char *act)
{

	if (strcmp(act, "allow") == 0 || strcmp(act, "accept") == 0 ||
	    strcmp(act, "pass") == 0 || strcmp(act, "permit") == 0)
		return ("allow");
	if (strcmp(act, "deny") == 0 || strcmp(act, "drop") == 0 ||
	    strcmp(act, "reject") == 0 || strcmp(act, "unreach") == 0 ||
	    strcmp(act, "unreach6") == 0 || strcmp(act, "reset") == 0 ||
	    strcmp(act, "reset6") == 0 || strcmp(act, "abort") == 0 ||
	    strcmp(act, "abort6") == 0)
		return ("deny");
	return (act);
}

/* One rule the walk met, and what it did with it. */
static void
step(struct fwverdict *v, size_t ri, const char *fmt, ...)
{
	va_list	ap;

	if (v->nsteps == FW_STEPS)
		return;
	v->steps[v->nsteps].rule = ri;
	va_start(ap, fmt);
	vsnprintf(v->steps[v->nsteps].how, sizeof(v->steps[0].how), fmt, ap);
	va_end(ap);
	v->nsteps++;
}

void
fw_eval(const struct fwset *s, const struct fwpkt *k, struct fwverdict *v)
{
	char		 buf[sizeof(((struct fwrule *)0)->text)], *tok[FW_TOKENS];
	char		 why[64];
	const char	*act, *arg;
	size_t		 ri;
	long		 to;
	int		 nt, i, steps;
	bool		 keep, looked = false, retnext;
	enum tri	 m;
	size_t		 stack[FW_CALLS], sp = 0;

	memset(v, 0, sizeof(*v));
	v->setfib = -1;
	for (ri = 0, steps = 0; ri < s->n && steps < 100000; ri++, steps++) {
		memcpy(buf, s->rules[ri].text, sizeof(buf));
		nt = tokens(buf, tok, FW_TOKENS);
		if (nt < 2)
			continue;
		/* number [set N] [prob p] action [args] [log ...] body */
		i = 1;
		if (strcmp(tok[i], "set") == 0)
			i += 2;
		if (i < nt && strcmp(tok[i], "prob") == 0)
			i += 2;
		if (i >= nt)
			continue;
		act = tok[i++];
		if (!action_word(act)) {
			if (v->nuncertain < FW_UNCERTAIN) {
				v->uncertain[v->nuncertain] = ri;
				snprintf(v->uncertain_why[v->nuncertain],
				    sizeof(v->uncertain_why[0]), "an action "
				    "not known");
				v->nuncertain++;
			}
			step(v, ri, "may be met: an action not known");
			continue;
		}
		/* check-state has no body: a reply's state looked up. */
		if (strcmp(act, "check-state") == 0) {
			looked = true;
			if (k->state) {
				step(v, ri, "decides: its state lets it by");
				v->verdict = "allow";
				v->rule = ri;
				v->by_state = true;
				return;
			}
			step(v, ri, "check-state: no state of it yet, on");
			continue;
		}
		/* The action's own words. */
		arg = NULL;
		if ((strcmp(act, "skipto") == 0 || strcmp(act, "call") == 0 ||
		    strcmp(act, "divert") == 0 || strcmp(act, "tee") == 0 ||
		    strcmp(act, "nat") == 0 || strcmp(act, "pipe") == 0 ||
		    strcmp(act, "queue") == 0 || strcmp(act, "netgraph") == 0 ||
		    strcmp(act, "ngtee") == 0 || strcmp(act, "setfib") == 0 ||
		    strcmp(act, "setdscp") == 0 || strcmp(act, "tag") == 0 ||
		    strcmp(act, "untag") == 0 || strcmp(act, "unreach") == 0 ||
		    strcmp(act, "unreach6") == 0 || strcmp(act, "fwd") == 0 ||
		    strcmp(act, "forward") == 0 || strcmp(act, "nptv6") == 0 ||
		    strncmp(act, "nat64", 5) == 0 || strcmp(act,
		    "tcp-setmss") == 0 || strcmp(act, "setmark") == 0) &&
		    i < nt)
			arg = tok[i++];
		if (strcmp(act, "eaction") == 0 && i + 1 < nt)
			i += 2;
		retnext = false;
		if (strcmp(act, "return") == 0 && i < nt && (strcmp(tok[i],
		    "next-rule") == 0 || strcmp(tok[i], "next-rulenum") == 0))
			retnext = strcmp(tok[i++], "next-rule") == 0;
		/* log [logamount N] [logdst x], altq q, tag n */
		for (;;) {
			if (i < nt && strcmp(tok[i], "log") == 0)
				i++;
			else if (i + 1 < nt && (strcmp(tok[i], "logamount") ==
			    0 || strcmp(tok[i], "logdst") == 0 || strcmp(
			    tok[i], "altq") == 0 || strcmp(tok[i], "tag") ==
			    0))
				i += 2;
			else
				break;
		}
		tablearg[0] = '\0';
		m = body_match(s, tok, nt, i, k, &keep, why, sizeof(why));
		if (arg != NULL && strcmp(arg, "tablearg") == 0 &&
		    tablearg[0] != '\0')
			arg = tablearg;
		if (m == NO)
			continue;
		/* The first keep-state or limit looks the flow up, matched
		 * or not by its body: as check-state does. */
		if (keep && !looked) {
			looked = true;
			if (k->state) {
				step(v, ri, "decides: its state lets it by");
				v->verdict = "allow";
				v->rule = ri;
				v->by_state = true;
				return;
			}
		}
		if (m == MAYBE) {
			if (v->nuncertain < FW_UNCERTAIN) {
				v->uncertain[v->nuncertain] = ri;
				snprintf(v->uncertain_why[v->nuncertain],
				    sizeof(v->uncertain_why[0]), "%s", why[0] !=
				    '\0' ? why : "an address it names");
				v->nuncertain++;
			}
			step(v, ri, "may be met: %s", why[0] != '\0' ? why :
			    "an address it names");
			continue;
		}
		if (strcmp(act, "count") == 0 || strcmp(act, "setdscp") == 0 ||
		    strcmp(act, "tag") == 0 || strcmp(act, "untag") == 0 ||
		    strcmp(act, "tcp-setmss") == 0 || strcmp(act,
		    "setmark") == 0 || strcmp(act, "reass") == 0) {
			/* reass: a packet that is no fragment goes on. */
			step(v, ri, "met, on");
			continue;
		}
		if (strcmp(act, "call") == 0) {
			size_t	q;

			/* As the kernel's O_CALLRETURN: the rule's index
			 * pushed, the walk goes to the number called
			 * (back or forth); a return comes back to the rule
			 * numbered after it (next-rulenum, the default) or
			 * the one after it (next-rule). */
			if (arg == NULL || strcmp(arg, "tablearg") == 0) {
				step(v, ri, "call tablearg: not known");
				v->verdict = "unknown";
				v->rule = ri;
				v->note = "call tablearg: where to is the "
				    "table's";
				return;
			}
			if (sp == FW_CALLS) {
				step(v, ri, "decides: the call stack overflows");
				v->verdict = "deny";
				v->rule = ri;
				v->note = "the call stack overflows: the kernel "
				    "denies the packet";
				return;
			}
			to = strtol(arg, NULL, 10);
			step(v, ri, "call %ld", to);
			stack[sp++] = ri;
			for (q = 0; q < s->n && s->rules[q].num < to; q++)
				;
			ri = q - 1;
			continue;
		}
		if (strcmp(act, "return") == 0) {
			size_t	q, from;

			/* With nothing called, on to the next rule. */
			if (sp == 0) {
				step(v, ri, "return, nothing called: on");
				continue;
			}
			from = stack[--sp];
			if (retnext)
				q = from + 1;
			else
				for (q = from + 1; q < s->n && s->rules[q].num ==
				    s->rules[from].num; q++)
					;
			step(v, ri, "return, after %ld", s->rules[from].num);
			ri = q - 1;
			continue;
		}
		if (strcmp(act, "setfib") == 0) {
			/* -2: the table's value, not known here. */
			v->setfib = arg == NULL || strcmp(arg, "tablearg") == 0 ?
			    -2 : atoi(arg);
			step(v, ri, "setfib %s, on", arg != NULL ? arg : "?");
			continue;
		}
		if (strcmp(act, "skipto") == 0) {
			size_t	q;

			if (arg == NULL || strcmp(arg, "tablearg") == 0) {
				step(v, ri, "skipto tablearg: not known");
				v->verdict = "unknown";
				v->rule = ri;
				v->note = "skipto tablearg: where to is the "
				    "table's";
				return;
			}
			to = strtol(arg, NULL, 10);
			step(v, ri, "skipto %ld", to);
			/* Only forward: the kernel never jumps back. */
			for (q = ri + 1; q < s->n && s->rules[q].num < to; q++)
				;
			ri = q - 1;
			continue;
		}
		step(v, ri, "decides");
		if (strcmp(act, "fwd") == 0 || strcmp(act, "forward") == 0)
			snprintf(v->fwd, sizeof(v->fwd), "%s", arg != NULL ?
			    arg : "");
		v->verdict = verdict_of(act);
		v->rule = ri;
		v->keep = keep;
		if (strcmp(act, "fwd") == 0 || strcmp(act, "forward") == 0) {
			v->verdict = "fwd";
			v->note = "sent on to another next hop than the route's";
		} else if (strcmp(act, "nat") == 0)
			v->note = "its addresses rewritten by NAT, and let on";
		else if (strcmp(act, "pipe") == 0 || strcmp(act, "queue") == 0)
			v->note = "through dummynet, then on (one_pass)";
		else if (strcmp(act, "divert") == 0 || strcmp(act, "tee") ==
		    0 || strcmp(act, "netgraph") == 0 || strcmp(act,
		    "ngtee") == 0)
			v->note = "given to a program or netgraph: what it does "
			    "with it is its own";
		else if (strcmp(v->verdict, "deny") != 0 && strcmp(v->verdict,
		    "allow") != 0)
			v->note = "an action the walk does not follow";
		return;
	}
	v->verdict = "none";
}
