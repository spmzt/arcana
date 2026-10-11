/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * SD-WAN: the services the console keeps, as MEF 70.2 says them (SD-WAN
 * Service Attributes and Service Framework), and the checks of each
 * against what the standard requires; [Rn] is its requirement n.
 *
 * One document, sdwan.json, holds all of it:
 *
 *	ucs		the underlays (Underlay Connectivity Services, §12):
 *			id, type public or private, billing, and the tunnels
 *			over it: gre, gif, geneve or wg, with IPsec or not
 *	edges		the hosts that are SD-WAN Edges (§7.8): a server and
 *			its UCS End Points, each on an interface, maybe a
 *			backup, maybe one that breaks out to the Internet
 *	swvcs		the services (SD-WAN Virtual Connections, §9): each
 *			with its FIB on the edges, its zones, virtual
 *			topologies, policies, application flows, rate
 *			limiters, and its end points (§10), each at an
 *			SD-WAN UNI (§11) on an edge, with its policy map
 *
 * The tunnels between edges (Tunnel Virtual Connections, §7.10) are not
 * in it: they are what the console makes of it.  A change is the whole
 * document again, with the version it was made from: one made from an
 * older one is refused, so that two pages never undo each other.
 *
 *	GET  /api/sdwan		the document
 *	PUT  /api/sdwan		a new one, checked and kept
 *	POST /api/sdwan/check	one checked, not kept
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "console.h"

#define	SDWAN_FILE	"sdwan.json"
#define	LIST_MAX	256	/* of each list in it */
#define	FIB_MAX		65535

static pthread_mutex_t	sd_lock = PTHREAD_MUTEX_INITIALIZER;

/* Where a check is, and why it failed. */
struct ck {
	char	where[160];
	char	why[400];
};

static bool
fail(struct ck *c, const char *fmt, ...)
{
	char	msg[300];
	va_list	ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	if (c->where[0] != '\0')
		snprintf(c->why, sizeof(c->why), "%s: %s", c->where, msg);
	else
		snprintf(c->why, sizeof(c->why), "%s", msg);
	return (false);
}

static void
at(struct ck *c, size_t keep, const char *fmt, ...)
{
	va_list	ap;

	c->where[keep] = '\0';
	if (keep > 0 && keep + 2 < sizeof(c->where)) {
		c->where[keep] = ',';
		c->where[keep + 1] = ' ';
		keep += 2;
	}
	va_start(ap, fmt);
	vsnprintf(c->where + keep, sizeof(c->where) - keep, fmt, ap);
	va_end(ap);
}

/* ---- Values --------------------------------------------------------- */

/* An Identifier String (§7.17, [R12]): printable ASCII, one at least. */
static bool
ident(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 64)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e)
			return (false);
	return (true);
}

static bool
ifname(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) >= 16)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '.' && s[i] != '_'
		    && s[i] != '-')
			return (false);
	return (true);
}

static const char *
str(const ucl_object_t *o, const char *key)
{

	return (ucl_str(o, key));
}

static bool
one_of(const char *s, const char *const *v)
{

	for (; s != NULL && *v != NULL; v++)
		if (strcmp(s, *v) == 0)
			return (true);
	return (false);
}

static bool
is_int(const ucl_object_t *v, int64_t lo, int64_t hi, int64_t *out)
{
	int64_t	n;

	if (v == NULL || ucl_object_type(v) != UCL_INT)
		return (false);
	n = ucl_object_toint(v);
	if (n < lo || n > hi)
		return (false);
	if (out != NULL)
		*out = n;
	return (true);
}

static bool
is_num(const ucl_object_t *v, double *out)
{

	if (v == NULL || (ucl_object_type(v) != UCL_INT &&
	    ucl_object_type(v) != UCL_FLOAT))
		return (false);
	*out = ucl_object_todouble(v);
	return (*out >= 0);
}

static bool
is_null(const ucl_object_t *v)
{

	return (v == NULL || ucl_object_type(v) == UCL_NULL);
}

static size_t
nkeys(const ucl_object_t *o)
{
	ucl_object_iter_t	 it;
	size_t			 n;

	it = NULL;
	n = 0;
	while (ucl_object_iterate(o, &it, true) != NULL)
		n++;
	return (n);
}

static size_t
count(const ucl_object_t *arr)
{

	return (arr != NULL && ucl_object_type(arr) == UCL_ARRAY ?
	    ucl_array_size(arr) : 0);
}

/* An IPv4 or IPv6 prefix: address/len, host bits clear. */
struct pfx {
	int	af;
	uint8_t	a[16];
	int	len;
};

static int
alen(int af)
{

	return (af == AF_INET ? 32 : 128);
}

static bool
address(const char *s, struct pfx *p)
{

	memset(p, 0, sizeof(*p));
	if (s == NULL)
		return (false);
	if (inet_pton(AF_INET, s, p->a) == 1)
		p->af = AF_INET;
	else if (inet_pton(AF_INET6, s, p->a) == 1)
		p->af = AF_INET6;
	else
		return (false);
	p->len = alen(p->af);
	return (true);
}

static bool
prefix(const char *s, struct pfx *p, bool host_bits)
{
	char		 buf[64], *slash, *end;
	long		 len;
	int		 i;

	if (s == NULL || strlen(s) >= sizeof(buf))
		return (false);
	snprintf(buf, sizeof(buf), "%s", s);
	if ((slash = strchr(buf, '/')) == NULL)
		return (false);
	*slash++ = '\0';
	if (!address(buf, p))
		return (false);
	len = strtol(slash, &end, 10);
	if (*slash == '\0' || *end != '\0' || len < 0 || len > alen(p->af))
		return (false);
	p->len = (int)len;
	if (host_bits)
		return (true);
	for (i = p->len; i < alen(p->af); i++)
		if (p->a[i / 8] & (0x80 >> (i % 8)))
			return (false);
	return (true);
}

/* Whether a holds b, the first len bits alike. */
static bool
holds(const struct pfx *a, const struct pfx *b)
{
	int	i;

	if (a->af != b->af || a->len > b->len)
		return (false);
	for (i = 0; i < a->len; i++)
		if ((a->a[i / 8] ^ b->a[i / 8]) & (0x80 >> (i % 8)))
			return (false);
	return (true);
}

static bool
overlap(const struct pfx *a, const struct pfx *b)
{

	return (holds(a, b) || holds(b, a));
}

/* A list of names, each an Identifier String, none twice. */
static bool
names(struct ck *c, const ucl_object_t *arr, const char *what, bool empty)
{
	const ucl_object_t	*v, *w;
	ucl_object_iter_t	 it, it2;
	size_t			 i, j;

	if (arr == NULL || ucl_object_type(arr) != UCL_ARRAY)
		return (empty && arr == NULL ? true :
		    fail(c, "%s is a list", what));
	if (!empty && ucl_array_size(arr) == 0)
		return (fail(c, "%s has one at least", what));
	if (ucl_array_size(arr) > LIST_MAX)
		return (fail(c, "%s: %d at most", what, LIST_MAX));
	it = NULL;
	i = 0;
	while ((v = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (ucl_object_type(v) != UCL_STRING ||
		    !ident(ucl_object_tostring(v)))
			return (fail(c, "%s: a name is printable ASCII, 64 "
			    "characters at most (R12)", what));
		it2 = NULL;
		j = 0;
		while ((w = ucl_object_iterate(arr, &it2, true)) != NULL &&
		    j++ < i)
			if (strcmp(ucl_object_tostring(v),
			    ucl_object_tostring(w)) == 0)
				return (fail(c, "%s: %s is there twice", what,
				    ucl_object_tostring(v)));
		i++;
	}
	return (true);
}

static bool
in_names(const ucl_object_t *arr, const char *s)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;

	it = NULL;
	while (s != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL)
		if (ucl_object_type(v) == UCL_STRING &&
		    strcmp(ucl_object_tostring(v), s) == 0)
			return (true);
	return (false);
}

/* The element of a list of objects whose key is s. */
static const ucl_object_t *
by(const ucl_object_t *arr, const char *key, const char *s)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;

	it = NULL;
	while (s != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL)
		if (str(v, key) != NULL && strcmp(str(v, key), s) == 0)
			return (v);
	return (NULL);
}

/*
 * A list of objects, each with an Identifier String under key that no
 * other has; seen collects them across lists when they are to be unique
 * further than this one.
 */
static bool
objects(struct ck *c, const ucl_object_t *arr, const char *what,
    const char *key, bool empty, ucl_object_t *seen, const char *rule)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	ucl_object_t		*mine;
	const char		*id;

	if (arr == NULL && empty)
		return (true);
	if (arr == NULL || ucl_object_type(arr) != UCL_ARRAY)
		return (fail(c, "%s is a list", what));
	if (!empty && ucl_array_size(arr) == 0)
		return (fail(c, "%s has one at least", what));
	if (ucl_array_size(arr) > LIST_MAX)
		return (fail(c, "%s: %d at most", what, LIST_MAX));
	mine = seen != NULL ? seen : ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while ((v = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (ucl_object_type(v) != UCL_OBJECT)
			goto bad;
		id = str(v, key);
		if (!ident(id)) {
			fail(c, "%s: each has a %s, printable ASCII, 64 "
			    "characters at most (R12)", what, key);
			goto out;
		}
		if (ucl_object_lookup(mine, id) != NULL) {
			fail(c, "%s: %s is there twice (%s)", what, id, rule);
			goto out;
		}
		ucl_object_insert_key(mine, ucl_object_frombool(true), id, 0,
		    true);
	}
	if (seen == NULL)
		ucl_object_unref(mine);
	return (true);
bad:
	fail(c, "%s: each is an object", what);
out:
	if (seen == NULL)
		ucl_object_unref(mine);
	return (false);
}

/* ---- Application flow criteria (§8.2, §9.14) ---------------------- */

static const char *const proto_names[] = { "icmp", "igmp", "tcp", "udp",
    "gre", "esp", "ah", "ipv6-icmp", "icmp6", "ospf", "pim", "sctp", "vrrp",
    "dccp", "ipip", "ipv6", "l2tp", NULL };

/* APPID (Table 8, [R98]): each says what it matches; see USING.md. */
static const char *const appids[] = { "dns", "http", "https", "ssh", "sip",
    "ntp", "smtp", "imap", "pop3", "ldap", "rdp", "snmp", "syslog", "ike",
    "bgp", "quic", "dhcp", "icmp", NULL };

static bool
port_word(const char *s)
{
	char		*end;
	long		 a, b;

	if (s == NULL || *s == '\0')
		return (false);
	if (isdigit((unsigned char)*s)) {
		a = strtol(s, &end, 10);
		b = a;
		if (*end == '-')
			b = strtol(end + 1, &end, 10);
		return (*end == '\0' && a >= 0 && b <= 65535 && a <= b);
	}
	return (getservbyname(s, NULL) != NULL);
}

/* A list whose every value passes: of ints lo..hi, or of words. */
static bool
values(struct ck *c, const char *crit, const ucl_object_t *v, int64_t lo,
    int64_t hi, const char *const *words, bool ports, int af)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct pfx		 p;

	if (v == NULL || ucl_object_type(v) != UCL_ARRAY ||
	    ucl_array_size(v) == 0 || ucl_array_size(v) > LIST_MAX)
		return (fail(c, "%s is a list of one value at least", crit));
	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
		if (af != 0) {
			if (ucl_object_type(e) != UCL_STRING ||
			    !prefix(ucl_object_tostring(e), &p, false) ||
			    p.af != af)
				return (fail(c, "%s: %s prefixes, as a.b.c.d/n "
				    "with no host bits", crit, af == AF_INET ?
				    "IPv4" : "IPv6"));
			continue;
		}
		if (is_int(e, lo, hi, NULL))
			continue;
		if (ucl_object_type(e) == UCL_STRING && ((ports &&
		    port_word(ucl_object_tostring(e))) || (words != NULL &&
		    one_of(ucl_object_tostring(e), words))))
			continue;
		return (fail(c, "%s: %s is not one of its values", crit,
		    ucl_object_tostring_forced(e)));
	}
	return (true);
}

static bool
flow_criteria(struct ck *c, const ucl_object_t *cr)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	const char		*k;

	if (cr == NULL || ucl_object_type(cr) != UCL_OBJECT || nkeys(cr) == 0)
		return (fail(c, "its criteria are an object, one at least"));
	if (ucl_object_lookup(cr, "any") != NULL && nkeys(cr) != 1)
		return (fail(c, "any is the only criterion where it is (R99)"));
	it = NULL;
	while ((v = ucl_object_iterate(cr, &it, true)) != NULL) {
		k = ucl_object_key(v);
		if (strcmp(k, "any") == 0) {
			if (!is_null(v) && !(ucl_object_type(v) ==
			    UCL_BOOLEAN && ucl_object_toboolean(v)))
				return (fail(c, "any is true or null"));
		} else if (strcmp(k, "sav4") == 0 || strcmp(k, "dav4") == 0 ||
		    strcmp(k, "sdav4") == 0) {
			if (!values(c, k, v, 0, 0, NULL, false, AF_INET))
				return (false);
		} else if (strcmp(k, "sav6") == 0 || strcmp(k, "dav6") == 0 ||
		    strcmp(k, "sdav6") == 0) {
			if (!values(c, k, v, 0, 0, NULL, false, AF_INET6))
				return (false);
		} else if (strcmp(k, "protv4") == 0 ||
		    strcmp(k, "nextheadv6") == 0) {
			if (!values(c, k, v, 0, 255, proto_names, false, 0))
				return (false);
		} else if (strcmp(k, "dscp") == 0) {
			if (!values(c, k, v, 0, 63, NULL, false, 0))
				return (false);
		} else if (strcmp(k, "sport") == 0 || strcmp(k, "dport") == 0 ||
		    strcmp(k, "sdport") == 0) {
			if (!values(c, k, v, 0, 65535, NULL, true, 0))
				return (false);
		} else if (strcmp(k, "ethertype") == 0) {
			if (!values(c, k, v, 0x600, 0xffff, NULL, false, 0))
				return (false);
		} else if (strcmp(k, "appid") == 0) {
			if (!values(c, k, v, 0, -1, appids, false, 0))
				return (false);
		} else
			return (fail(c, "%s is not a criterion of an application "
			    "flow (Table 8, Table 9)", k));
	}
	return (true);
}

/* ---- Policies (§9.12) ---------------------------------------------- */

static const char *const metrics[] = { "delay", "ipdv", "loss", NULL };

static bool
performance(struct ck *c, const ucl_object_t *v)
{
	const ucl_object_t	*pri, *sec, *e, *th, *ce, *re;
	ucl_object_iter_t	 it;
	const char		*m;
	double			 t, cl, r;
	bool			 seen[3] = { false, false, false };
	int			 i;

	if (is_null(v))
		return (true);
	if (ucl_object_type(v) != UCL_OBJECT ||
	    (pri = ucl_object_lookup(v, "primary")) == NULL)
		return (fail(c, "performance has a primary metric"));
	m = str(pri, "metric");
	if (!one_of(m, metrics))
		return (fail(c, "performance: a metric is delay, ipdv or loss "
		    "(Table 7)"));
	for (i = 0; metrics[i] != NULL; i++)
		if (strcmp(m, metrics[i]) == 0)
			seen[i] = true;
	th = ucl_object_lookup(pri, "threshold");
	ce = ucl_object_lookup(pri, "ceiling");
	re = ucl_object_lookup(pri, "remediation");
	if (is_null(th)) {
		if (!is_null(ce) || !is_null(re))
			return (fail(c, "performance: no threshold, so neither "
			    "a ceiling nor remediation (R71)"));
	} else {
		if (!is_num(th, &t))
			return (fail(c, "performance: a threshold is a number, "
			    "0 or more"));
		if (!is_null(ce) && (!is_num(ce, &cl) || cl < t))
			return (fail(c, "performance: the ceiling is the "
			    "threshold or above it (R72)"));
		if (!is_null(re)) {
			if (!is_num(re, &r))
				return (fail(c, "performance: remediation is a "
				    "number"));
			if (!is_null(ce) && r >= cl)
				return (fail(c, "performance: remediation is "
				    "below the ceiling (R75)"));
			if (is_null(ce) && r > t)
				return (fail(c, "performance: with no ceiling, "
				    "remediation is the threshold or below "
				    "(R76)"));
		}
	}
	if (strcmp(m, "loss") == 0 && !is_null(th) && t > 1)
		return (fail(c, "performance: loss is a ratio, 0 to 1"));
	sec = ucl_object_lookup(v, "secondary");
	if (sec != NULL && ucl_object_type(sec) != UCL_ARRAY)
		return (fail(c, "performance: secondary is a list"));
	it = NULL;
	while ((e = ucl_object_iterate(sec, &it, true)) != NULL) {
		m = str(e, "metric");
		if (!one_of(m, metrics))
			return (fail(c, "performance: a metric is delay, ipdv "
			    "or loss (Table 7)"));
		for (i = 0; metrics[i] != NULL; i++)
			if (strcmp(m, metrics[i]) == 0) {
				if (seen[i])
					return (fail(c, "performance: %s is "
					    "there twice (R68)", m));
				seen[i] = true;
			}
		if (!is_num(ucl_object_lookup(e, "threshold"), &t) ||
		    (strcmp(m, "loss") == 0 && t > 1))
			return (fail(c, "performance: a secondary metric has a "
			    "threshold"));
	}
	return (true);
}

/* BANDWIDTH and a rate limiter: commit, limit (§7.15, [R7]). */
static bool
rate(struct ck *c, const ucl_object_t *v, const char *what)
{
	const ucl_object_t	*l;
	int64_t			 commit, limit;

	if (!is_int(ucl_object_lookup(v, "commit"), 0, INT64_MAX, &commit))
		return (fail(c, "%s%scommit is bits per second, 0 or more",
		    what != NULL ? what : "", what != NULL ? ": " : ""));
	l = ucl_object_lookup(v, "limit");
	if (!is_null(l) && (!is_int(l, 0, INT64_MAX, &limit) || limit <
	    commit))
		return (fail(c, "%s%sthe limit is null or the commit or more "
		    "(R7)", what != NULL ? what : "", what != NULL ? ": " :
		    ""));
	return (true);
}

static const char *const enc_values[] = { "required-always",
    "required-public-only", "optional", NULL };
static const char *const pp_values[] = { "private-only", "either", NULL };
static const char *const ed_values[] = { "enabled", "disabled", NULL };
static const char *const bill_values[] = { "flat-rate-only",
    "usage-based-only", "either", NULL };
static const char *const block_values[] = { "allow", "discard", NULL };

static bool
policy(struct ck *c, const ucl_object_t *sw, const ucl_object_t *p)
{
	const ucl_object_t	*cr, *v, *imp;
	ucl_object_iter_t	 it;
	const char		*k, *dir, *s;
	bool			 ingress;

	dir = str(p, "direction");
	if (!one_of(dir, (const char *const[]){ "ingress", "egress", NULL }))
		return (fail(c, "a policy is ingress or egress, not both "
		    "(R34)"));
	ingress = strcmp(dir, "ingress") == 0;
	if ((cr = ucl_object_lookup(p, "criteria")) == NULL)
		return (true);
	if (ucl_object_type(cr) != UCL_OBJECT)
		return (fail(c, "its criteria are an object"));
	it = NULL;
	while ((v = ucl_object_iterate(cr, &it, true)) != NULL) {
		k = ucl_object_key(v);
		s = ucl_object_type(v) == UCL_STRING ? ucl_object_tostring(v) :
		    NULL;
		if (!ingress) {
			if (strcmp(k, "egress-block") == 0) {
				if (!one_of(s, block_values))
					return (fail(c, "egress-block is allow "
					    "or discard"));
			} else if (strcmp(k, "af-security-egress") == 0) {
				if (!is_null(v) && (s == NULL || by(ucl_object_lookup(
				    sw, "security_policies"), "name", s) == NULL))
					return (fail(c, "af-security-egress is "
					    "one of security_policies"));
			} else
				return (fail(c, "%s is not a criterion of an "
				    "egress policy (§9.12.3)", k));
			continue;
		}
		if (strcmp(k, "encryption") == 0) {
			if (!one_of(s, enc_values))
				return (fail(c, "encryption is required-always, "
				    "required-public-only or optional"));
		} else if (strcmp(k, "public-private") == 0) {
			if (!one_of(s, pp_values))
				return (fail(c, "public-private is private-only "
				    "or either"));
		} else if (strcmp(k, "internet-breakout") == 0 ||
		    strcmp(k, "backup") == 0) {
			if (!one_of(s, ed_values))
				return (fail(c, "%s is enabled or disabled", k));
		} else if (strcmp(k, "billing-method") == 0) {
			if (!one_of(s, bill_values))
				return (fail(c, "billing-method is "
				    "flat-rate-only, usage-based-only or "
				    "either"));
		} else if (strcmp(k, "virtual-topology") == 0) {
			if (s == NULL || (strcmp(s, "Swvc") != 0 && by(
			    ucl_object_lookup(sw, "topologies"), "name", s) ==
			    NULL))
				return (fail(c, "virtual-topology is Swvc or one "
				    "of the topologies (R47)"));
		} else if (strcmp(k, "allowed-destination-zones") == 0) {
			if (s != NULL) {
				if (strcmp(s, "All") != 0)
					return (fail(c, "allowed-destination-"
					    "zones is All or a list"));
			} else {
				const ucl_object_t	*z;
				ucl_object_iter_t	 zit;

				if (!names(c, v, k, true))
					return (false);
				zit = NULL;
				while ((z = ucl_object_iterate(v, &zit,
				    true)) != NULL) {
					const char *zn = ucl_object_tostring(z);

					if (strcmp(zn, "Internet") == 0)
						return (fail(c, "Internet is not "
						    "an allowed destination "
						    "zone (R58)"));
					if (strcmp(zn, "Self") != 0 && by(
					    ucl_object_lookup(sw, "zones"),
					    "name", zn) == NULL)
						return (fail(c, "%s is no zone",
						    zn));
				}
				if (ucl_array_size(v) == 0 && (str(cr,
				    "internet-breakout") == NULL || strcmp(str(
				    cr, "internet-breakout"), "enabled") != 0))
					return (fail(c, "no allowed "
					    "destination zone only with "
					    "internet-breakout enabled (R59)"));
			}
		} else if (strcmp(k, "business-importance") == 0) {
			imp = ucl_object_lookup(sw, "importance");
			if (is_null(imp))
				return (fail(c, "business-importance, with no "
				    "importance levels (R66)"));
			if (!in_names(ucl_object_lookup(imp, "levels"), s))
				return (fail(c, "business-importance is one of "
				    "the importance levels"));
		} else if (strcmp(k, "performance") == 0) {
			if (!performance(c, v))
				return (false);
		} else if (strcmp(k, "bandwidth") == 0) {
			if (s != NULL) {
				if (by(ucl_object_lookup(sw, "rate_limiters"),
				    "name", s) == NULL)
					return (fail(c, "bandwidth names no "
					    "rate limiter"));
			} else if (ucl_object_type(v) != UCL_OBJECT ||
			    !rate(c, v, "bandwidth"))
				return (c->why[0] != '\0' ? false : fail(c,
				    "bandwidth is a commit and a limit, or a "
				    "rate limiter's name"));
		} else if (strcmp(k, "af-security-ingress") == 0) {
			if (!is_null(v) && (s == NULL || by(ucl_object_lookup(sw,
			    "security_policies"), "name", s) == NULL))
				return (fail(c, "af-security-ingress is one of "
				    "security_policies"));
		} else
			return (fail(c, "%s is not a criterion of an ingress "
			    "policy (Table 5, Table 6)", k));
	}
	return (true);
}

/* An AFS or an AFS group (an application, in a policy map). */
static bool
app(const ucl_object_t *sw, const char *s)
{

	return (by(ucl_object_lookup(sw, "flows"), "name", s) != NULL ||
	    in_names(ucl_object_lookup(sw, "groups"), s));
}

/* An ingress policy, Block, or none (null). */
static bool
ingress_pol(const ucl_object_t *sw, const ucl_object_t *v, bool block)
{
	const ucl_object_t	*p;
	const char		*s;

	if (is_null(v))
		return (true);
	if (ucl_object_type(v) != UCL_STRING)
		return (false);
	s = ucl_object_tostring(v);
	if (strcmp(s, "Block") == 0)
		return (block);
	p = by(ucl_object_lookup(sw, "policies"), "name", s);
	return (p != NULL && strcmp(str(p, "direction"), "ingress") == 0);
}

/* The virtual topology an ingress policy constrains to, or NULL. */
static const char *
vt_of(const ucl_object_t *sw, const char *pol)
{
	const ucl_object_t	*p;
	const char		*vt;

	if (pol == NULL || (p = by(ucl_object_lookup(sw, "policies"), "name",
	    pol)) == NULL)
		return (NULL);
	vt = str(ucl_object_lookup(p, "criteria"), "virtual-topology");
	return (vt == NULL || strcmp(vt, "Swvc") == 0 ? NULL : vt);
}

static bool
vt_has(const ucl_object_t *sw, const char *vt, const char *ep)
{
	const ucl_object_t	*t;

	t = by(ucl_object_lookup(sw, "topologies"), "name", vt);
	return (t != NULL && (in_names(ucl_object_lookup(t, "end_points"),
	    ep) || in_names(ucl_object_lookup(t, "roots"), ep) ||
	    in_names(ucl_object_lookup(t, "leaves"), ep)));
}

/* ---- The SD-WAN UNI (§11) ------------------------------------------ */

/* A subnet of a UNI: its prefix, and the provider's addresses in it. */
static bool
subnet(struct ck *c, const ucl_object_t *v, int af, const char *what)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct pfx		 p, a;

	if (!prefix(str(v, "prefix"), &p, false) || p.af != af ||
	    (af == AF_INET && p.len > 31))
		return (fail(c, "%s: a prefix is a %s subnet%s", what,
		    af == AF_INET ? "IPv4" : "IPv6", af == AF_INET ?
		    " of length 31 at most (§11.4)" : ""));
	if (count(ucl_object_lookup(v, "provider")) == 0)
		return (fail(c, "%s: %s has the provider's addresses, one at "
		    "least (§11.4)", what, str(v, "prefix")));
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(v, "provider"), &it,
	    true)) != NULL)
		if (!address(ucl_object_tostring_forced(e), &a) ||
		    !holds(&p, &a))
			return (fail(c, "%s: %s is not in %s (R%d)", what,
			    ucl_object_tostring_forced(e), str(v, "prefix"),
			    af == AF_INET ? 131 : 135));
	return (true);
}

static bool
connection(struct ck *c, const ucl_object_t *v, int af, bool *none)
{
	const ucl_object_t	*e, *sec;
	ucl_object_iter_t	 it;
	const char		*mode, *what;

	what = af == AF_INET ? "ipv4" : "ipv6";
	*none = true;
	if (is_null(v))
		return (true);
	mode = str(v, "mode");
	if (mode == NULL || strcmp(mode, "none") == 0)
		return (true);
	*none = false;
	if (af == AF_INET6 && strcmp(mode, "ll-only") == 0)
		return (true);
	if (strcmp(mode, "static") != 0 && strcmp(mode, "dhcp") != 0 &&
	    (af == AF_INET || strcmp(mode, "slaac") != 0))
		return (fail(c, "%s is none, static or dhcp%s (§11.%d)", what,
		    af == AF_INET6 ? ", slaac or ll-only" : "", af == AF_INET ?
		    4 : 5));
	if (!subnet(c, v, af, what))
		return (false);
	if (strcmp(mode, "static") != 0) {
		/* The edge gives the hosts their addresses: by dnsmasq (DHCP)
		 * or by rtadvd (SLAAC), a /64 for IPv6 as hosts expect; the
		 * reserved prefixes are not given out (§11.4, §11.5); the DNS
		 * servers told to the hosts; a lease's length. */
		struct pfx	 p, r;
		const char	*lease;
		size_t		 i;

		(void)prefix(str(v, "prefix"), &p, false);
		if (af == AF_INET6 && p.len != 64)
			return (fail(c, "%s: %s at a UNI is a /64 prefix, as the "
			    "hosts expect (R137)", what, mode));
		if (af == AF_INET && p.len > 30)
			return (fail(c, "%s: dhcp needs a subnet with hosts in it, "
			    "a /30 at most", what));
		e = ucl_object_lookup(v, "reserved");
		if (e != NULL && ucl_object_type(e) != UCL_ARRAY)
			return (fail(c, "%s: reserved is a list of prefixes", what));
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(v, "reserved"),
		    &it, true)) != NULL)
			if (!prefix(ucl_object_tostring_forced(e), &r, false) ||
			    !holds(&p, &r))
				return (fail(c, "%s: a reserved prefix is inside %s "
				    "(§11.%d)", what, str(v, "prefix"), af == AF_INET
				    ? 4 : 5));
		e = ucl_object_lookup(v, "dns");
		if (e != NULL && (ucl_object_type(e) != UCL_ARRAY || count(e) >
		    4))
			return (fail(c, "%s: dns is a list of 4 addresses at most",
			    what));
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(v, "dns"), &it,
		    true)) != NULL)
			if (!address(ucl_object_tostring_forced(e), &r) || r.af !=
			    af)
				return (fail(c, "%s: a dns server is an %s address",
				    what, af == AF_INET ? "IPv4" : "IPv6"));
		if ((lease = str(v, "lease")) != NULL) {
			for (i = 0; isdigit((unsigned char)lease[i]); i++)
				;
			if (i == 0 || i > 6 || strchr("mhd", lease[i]) == NULL ||
			    lease[i + 1] != '\0')
				return (fail(c, "%s: a lease is a number of m, h or "
				    "d, as 12h", what));
		}
	}
	/* Secondary subnets: each a prefix and the provider's addresses. */
	sec = ucl_object_lookup(v, "secondary");
	if (sec != NULL && ucl_object_type(sec) != UCL_ARRAY)
		return (fail(c, "%s: secondary is a list", what));
	it = NULL;
	while ((e = ucl_object_iterate(sec, &it, true)) != NULL)
		if (!subnet(c, e, af, what))
			return (false);
	return (true);
}

/*
 * BGP or OSPF across the UNI (§11.6.2, §11.6.3): one entry each, for
 * one family or both (R139), with what the two sides agree on.  What
 * BIRD has no word for is refused: AS override, damping, extended
 * communities.
 */
static bool
routing(struct ck *c, const ucl_object_t *v, const char *what,
    const struct pfx *nets, int nnets)
{
	const ucl_object_t	*e, *m;
	ucl_object_iter_t	 it;
	struct pfx		 a;
	const char		*fam;
	int			 i;

	if (is_null(v))
		return (true);
	if (ucl_object_type(v) != UCL_OBJECT)
		return (fail(c, "its UNI's %s is an object", what));
	fam = str(v, "family");
	if (!one_of(fam, (const char *const[]){ "ipv4", "ipv6", "both",
	    NULL }))
		return (fail(c, "%s: family is ipv4, ipv6 or both (§11.6)",
		    what));
	if (ucl_object_lookup(v, "distance") != NULL && !is_int(
	    ucl_object_lookup(v, "distance"), 1, 255, NULL))
		return (fail(c, "%s: distance is 1 to 255", what));
	if (str(v, "password") != NULL && (strlen(str(v, "password")) > 80 ||
	    strpbrk(str(v, "password"), "\"\\\n") != NULL))
		return (fail(c, "%s: a password is 80 characters at most, no "
		    "quotes", what));
	if (strcmp(what, "bgp") == 0) {
		if (!is_int(ucl_object_lookup(v, "as"), 1, 4294967295LL, NULL))
			return (fail(c, "bgp: as is the subscriber's AS number"));
		e = ucl_object_lookup(v, "neighbors");
		if (e == NULL || ucl_object_type(e) != UCL_ARRAY ||
		    ucl_array_size(e) == 0 || ucl_array_size(e) > LIST_MAX)
			return (fail(c, "bgp: neighbors are the subscriber's "
			    "addresses at the UNI, one at least"));
		it = NULL;
		while ((m = ucl_object_iterate(e, &it, true)) != NULL) {
			if (!address(ucl_object_tostring_forced(m), &a))
				return (fail(c, "bgp: %s is not an address",
				    ucl_object_tostring_forced(m)));
			if ((a.af == AF_INET && strcmp(fam, "ipv6") == 0) ||
			    (a.af == AF_INET6 && strcmp(fam, "ipv4") == 0))
				return (fail(c, "bgp: %s is not of the family",
				    ucl_object_tostring_forced(m)));
			/* At a UNI, within its prefixes; a UCS has none to
			 * check against. */
			for (i = 0; i < nnets; i++)
				if (holds(&nets[i], &a))
					break;
			if (nnets > 0 && i == nnets)
				return (fail(c, "bgp: %s is not within the UNI's "
				    "prefixes (§11.6.2)",
				    ucl_object_tostring_forced(m)));
		}
		if (ucl_object_lookup(v, "hold_time") != NULL && !is_int(
		    ucl_object_lookup(v, "hold_time"), 3, 65535, NULL))
			return (fail(c, "bgp: hold_time is 3 to 65535 seconds"));
		e = ucl_object_lookup(v, "communities");
		if (e != NULL && (ucl_object_type(e) != UCL_ARRAY ||
		    ucl_array_size(e) > LIST_MAX))
			return (fail(c, "bgp: communities is a list of [as, "
			    "value]"));
		it = NULL;
		while ((m = ucl_object_iterate(e, &it, true)) != NULL)
			if (ucl_object_type(m) != UCL_ARRAY || ucl_array_size(m)
			    != 2 || !is_int(ucl_array_find_index(m, 0), 0,
			    65535, NULL) || !is_int(ucl_array_find_index(m, 1),
			    0, 65535, NULL))
				return (fail(c, "bgp: a community is [as, "
				    "value], each 0 to 65535"));
		if (ucl_object_lookup(v, "ext_communities") != NULL)
			return (fail(c, "bgp: extended communities are not "
			    "written yet"));
		if (ucl_flag(v, "as_override"))
			return (fail(c, "bgp: as_override is not what BIRD does: "
			    "leave it off"));
		if (!is_null(ucl_object_lookup(v, "damping")))
			return (fail(c, "bgp: damping is not what BIRD does: "
			    "leave it off"));
		return (true);
	}
	if (ucl_object_lookup(v, "area") != NULL && !is_int(
	    ucl_object_lookup(v, "area"), 0, 4294967295LL, NULL))
		return (fail(c, "ospf: area is a number, 0 the backbone"));
	if (ucl_object_lookup(v, "cost") != NULL && !is_int(
	    ucl_object_lookup(v, "cost"), 1, 65535, NULL))
		return (fail(c, "ospf: cost is 1 to 65535"));
	if (ucl_object_lookup(v, "hello") != NULL && !is_int(
	    ucl_object_lookup(v, "hello"), 1, 65535, NULL))
		return (fail(c, "ospf: hello is seconds, 1 to 65535"));
	if (ucl_object_lookup(v, "dead") != NULL && !is_int(
	    ucl_object_lookup(v, "dead"), 2, 65535, NULL))
		return (fail(c, "ospf: dead is seconds, 2 to 65535"));
	return (true);
}

static bool
uni(struct ck *c, const ucl_object_t *u, struct pfx *nets, int *nnets)
{
	const ucl_object_t	*r, *e;
	ucl_object_iter_t	 it;
	int64_t			 n;
	bool			 none4, none6;
	struct pfx		 p, nh;
	int			 i;

	if (u == NULL || ucl_object_type(u) != UCL_OBJECT)
		return (fail(c, "it has its SD-WAN UNI"));
	if (!ident(str(u, "id")))
		return (fail(c, "its UNI has an id, printable ASCII (R12)"));
	if (!ifname(str(u, "interface")))
		return (fail(c, "its UNI is on an interface"));
	if (ucl_object_lookup(u, "vlan") != NULL && !is_int(
	    ucl_object_lookup(u, "vlan"), 0, 4094, NULL))
		return (fail(c, "its UNI's vlan is 0, untagged, or 1 to 4094 "
		    "(§11.2)"));
	if (ucl_object_lookup(u, "max_frame") != NULL && !is_int(
	    ucl_object_lookup(u, "max_frame"), 1522, 65535, NULL))
		return (fail(c, "its UNI's max_frame is 1522 or more (R126)"));
	if (!connection(c, ucl_object_lookup(u, "ipv4"), AF_INET, &none4) ||
	    !connection(c, ucl_object_lookup(u, "ipv6"), AF_INET6, &none6))
		return (false);
	if (none4 && none6)
		return (fail(c, "its UNI has IPv4 or IPv6, or both (R128)"));
	*nnets = 0;
	if (!none4 && prefix(str(ucl_object_lookup(u, "ipv4"), "prefix"),
	    &p, false))
		nets[(*nnets)++] = p;
	if (!none6 && prefix(str(ucl_object_lookup(u, "ipv6"), "prefix"),
	    &p, false))
		nets[(*nnets)++] = p;
	/* Static routes (§11.6.1); BGP and OSPF come later. */
	r = ucl_object_lookup(u, "routes");
	if (r != NULL && ucl_object_type(r) != UCL_ARRAY)
		return (fail(c, "its UNI's routes are a list"));
	if (count(r) > LIST_MAX)
		return (fail(c, "its UNI: %d routes at most", LIST_MAX));
	it = NULL;
	while ((e = ucl_object_iterate(r, &it, true)) != NULL) {
		if (!prefix(str(e, "prefix"), &p, false) ||
		    !address(str(e, "next_hop"), &nh) || p.af != nh.af)
			return (fail(c, "a static route is a prefix and a next "
			    "hop of its family"));
		for (i = 0; i < *nnets; i++)
			if (holds(&nets[i], &nh))
				break;
		if (i == *nnets)
			return (fail(c, "route %s: %s is not reached at this "
			    "UNI (§11.6.1)", str(e, "prefix"), str(e,
			    "next_hop")));
		if (ucl_object_lookup(e, "distance") != NULL && !is_int(
		    ucl_object_lookup(e, "distance"), 1, 255, &n))
			return (fail(c, "a route's distance is 1 to 255"));
	}
	if (!routing(c, ucl_object_lookup(u, "bgp"), "bgp", nets, *nnets) ||
	    !routing(c, ucl_object_lookup(u, "ospf"), "ospf", nets, *nnets))
		return (false);
	return (true);
}

/* ---- One SWVC ----------------------------------------------------- */

/* A route distinguisher or target: ASN:n or A.B.C.D:n (RFC 4364 §4.2). */
static bool
rd_ok(const char *s)
{
	const char	*colon;
	struct pfx	 a;
	char		 left[32];
	size_t		 i;

	if (s == NULL || (colon = strrchr(s, ':')) == NULL || colon == s ||
	    colon[1] == '\0' || (size_t)(colon - s) >= sizeof(left))
		return (false);
	for (i = 1; colon[i] != '\0'; i++)
		if (!isdigit((unsigned char)colon[i]))
			return (false);
	snprintf(left, sizeof(left), "%.*s", (int)(colon - s), s);
	for (i = 0; left[i] != '\0'; i++)
		if (!isdigit((unsigned char)left[i]) && left[i] != '.')
			return (false);
	return (strchr(left, '.') == NULL || (address(left, &a) && a.af ==
	    AF_INET));
}

/*
 * The routing domains of a service (Mplify 119 §7.3, R15-R26): the
 * service domain (the tunnels' addresses from its prefix; its FIB kept
 * for the control plane), the breakout domain (a FIB of its own for
 * the Internet, the UNIs' routes imported into it) and the subscriber
 * domain (the service's own FIB); each a route distinguisher, route
 * targets and an MPLS label for the tunnel format to come.
 */
static bool
domains(struct ck *c, const ucl_object_t *sw)
{
	static const char *const names[] = { "service", "breakout",
	    "subscriber" };
	const ucl_object_t	*d, *v, *e;
	ucl_object_iter_t	 it;
	struct pfx		 p;
	int64_t			 own, fib;
	int			 i;

	if ((d = ucl_object_lookup(sw, "domains")) == NULL || is_null(d))
		return (true);
	if (ucl_object_type(d) != UCL_OBJECT)
		return (fail(c, "domains is an object: service, breakout, "
		    "subscriber (Mplify 119 §7.3)"));
	own = ucl_object_toint(ucl_object_lookup(sw, "fib"));
	for (i = 0; i < 3; i++) {
		if ((v = ucl_object_lookup(d, names[i])) == NULL || is_null(v))
			continue;
		if (ucl_object_type(v) != UCL_OBJECT)
			return (fail(c, "domains.%s is an object", names[i]));
		if (i < 2 && ucl_object_lookup(v, "fib") != NULL) {
			if (!is_int(ucl_object_lookup(v, "fib"), 1, FIB_MAX, &fib)
			    || fib == own)
				return (fail(c, "domains.%s.fib is a routing table "
				    "of its own, 1 or more and not the service's "
				    "(R20)", names[i]));
			if (i == 1 && ucl_object_lookup(ucl_object_lookup(d,
			    "service"), "fib") != NULL && ucl_object_toint(
			    ucl_object_lookup(ucl_object_lookup(d, "service"),
			    "fib")) == fib)
				return (fail(c, "domains: the breakout and the "
				    "service domains have a table each"));
		}
		if (i == 0 && str(v, "prefix") != NULL && (!prefix(str(v,
		    "prefix"), &p, false) || p.len > (p.af == AF_INET ? 30 :
		    126)))
			return (fail(c, "domains.service.prefix is the service "
			    "domain's prefix, the tunnels' addresses from it"));
		if (str(v, "rd") != NULL && !rd_ok(str(v, "rd")))
			return (fail(c, "domains.%s.rd is a route distinguisher, "
			    "ASN:n or A.B.C.D:n (R16)", names[i]));
		if ((e = ucl_object_lookup(v, "rt")) != NULL && (ucl_object_type(
		    e) != UCL_ARRAY || ucl_array_size(e) > 8))
			return (fail(c, "domains.%s.rt is a list of route targets, "
			    "8 at most (R17)", names[i]));
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(v, "rt"), &it,
		    true)) != NULL)
			if (!rd_ok(ucl_object_tostring_forced(e)))
				return (fail(c, "domains.%s.rt: %s is not a route "
				    "target, ASN:n or A.B.C.D:n (R17)", names[i],
				    ucl_object_tostring_forced(e)));
		if (ucl_object_lookup(v, "label") != NULL && !is_int(
		    ucl_object_lookup(v, "label"), 16, 1048575, NULL))
			return (fail(c, "domains.%s.label is an MPLS label, 16 to "
			    "1048575 (R19)", names[i]));
	}
	return (true);
}

static bool security_policy(struct ck *, const ucl_object_t *);

static bool
swvc(struct ck *c, const ucl_object_t *doc, const ucl_object_t *sw,
    ucl_object_t *seen_ep, ucl_object_t *seen_uni, ucl_object_t *seen_if)
{
	const ucl_object_t	*v, *e, *z, *zp, *t, *p, *ep, *m;
	ucl_object_iter_t	 it, it2, it3;
	struct pfx		 zones[LIST_MAX], res[LIST_MAX], q;
	struct pfx		 nets[2];
	int			 nz, nr, i, j, defaults, nnets;
	size_t			 base;
	int64_t			 n;
	const char		*s;

	base = strlen(c->where);
	if (str(sw, "md5") != NULL && (strlen(str(sw, "md5")) > 80 ||
	    strpbrk(str(sw, "md5"), "\"\\\n") != NULL))
		return (fail(c, "md5 is the edges' iBGP password, 80 characters "
		    "at most, no quotes (Mplify 119 R12)"));
	if (ucl_object_lookup(sw, "as") != NULL && !is_int(ucl_object_lookup(
	    sw, "as"), 1, 4294967295LL, NULL))
		return (fail(c, "as is the provider's AS number, the edges' "
		    "among themselves and at the UNIs (§11.6.2)"));
	if (!is_int(ucl_object_lookup(sw, "fib"), 1, FIB_MAX, NULL))
		return (fail(c, "its fib is 1 or more: FIB 0 is the "
		    "underlay's"));
	if (!domains(c, sw))
		return (false);
	/* The control plane (Mplify 119 §8.3, R9-R13): an edge of the
	 * service the others' iBGP goes to, a route reflector. */
	if ((v = ucl_object_lookup(sw, "control_plane")) != NULL && !is_null(
	    v)) {
		struct pfx	cid;
		bool		here = false;

		if (ucl_object_type(v) != UCL_OBJECT || str(v, "host") == NULL)
			return (fail(c, "control_plane names its host, the edge "
			    "whose BIRD reflects the others' routes (Mplify 119 "
			    "§8.3)"));
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(sw,
		    "end_points"), &it, true)) != NULL)
			if (str(e, "edge") != NULL && strcmp(str(e, "edge"), str(v,
			    "host")) == 0)
				here = true;
		if (!here)
			return (fail(c, "control_plane.host is an edge of this "
			    "service, with an end point in it"));
		if (str(v, "cluster_id") != NULL && (!address(str(v,
		    "cluster_id"), &cid) || cid.af != AF_INET))
			return (fail(c, "control_plane.cluster_id is an IPv4 "
			    "address, the reflector's cluster (RFC 4456)"));
		/* The CTVC (R5, R6): a tunnel of the control plane's own over
		 * one of the service's UCSs, between the host and each edge. */
		if (str(v, "ctvc") != NULL) {
			here = false;
			it = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(sw, "ucs"),
			    &it, true)) != NULL)
				if (ucl_object_type(e) == UCL_STRING && strcmp(
				    ucl_object_tostring(e), str(v, "ctvc")) == 0)
					here = true;
			if (!here)
				return (fail(c, "control_plane.ctvc is one of the "
				    "service's UCSs, the control tunnel's underlay "
				    "(Mplify 119 R5, R6)"));
		}
	}
	/* SWVC List of UCSs (§9.3). */
	if (!names(c, ucl_object_lookup(sw, "ucs"), "ucs", false))
		return (false);
	it = NULL;
	while ((v = ucl_object_iterate(ucl_object_lookup(sw, "ucs"), &it,
	    true)) != NULL)
		if (by(ucl_object_lookup(doc, "ucs"), "id",
		    ucl_object_tostring(v)) == NULL)
			return (fail(c, "ucs %s is not one of the UCSs",
			    ucl_object_tostring(v)));
	/* SWVC Reserved Prefixes (§9.4). */
	v = ucl_object_lookup(sw, "reserved_prefixes");
	if (v != NULL && ucl_object_type(v) != UCL_ARRAY)
		return (fail(c, "reserved_prefixes is a list"));
	nr = 0;
	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
		if (nr == LIST_MAX || !prefix(ucl_object_tostring_forced(e),
		    &res[nr], false))
			return (fail(c, "reserved_prefixes: %s is not a prefix",
			    ucl_object_tostring_forced(e)));
		nr++;
	}
	/* SWVC List of AFS Groups (§9.13) and AFSs (§9.14). */
	if (!names(c, ucl_object_lookup(sw, "groups"), "groups", true))
		return (false);
	if (in_names(ucl_object_lookup(sw, "groups"), "None"))
		return (fail(c, "groups: None is not a name (R89)"));
	if (!objects(c, ucl_object_lookup(sw, "flows"), "flows", "name", false,
	    NULL, "R91"))
		return (false);
	it = NULL;
	while ((v = ucl_object_iterate(ucl_object_lookup(sw, "flows"), &it,
	    true)) != NULL) {
		at(c, base, "flow %s", str(v, "name"));
		if (in_names(ucl_object_lookup(sw, "groups"), str(v, "name")))
			return (fail(c, "a flow and a group of one name (R92)"));
		s = str(v, "group");
		if (s != NULL && strcmp(s, "None") != 0 && !in_names(
		    ucl_object_lookup(sw, "groups"), s))
			return (fail(c, "group %s is not one of the groups", s));
		if (!flow_criteria(c, ucl_object_lookup(v, "criteria")))
			return (false);
	}
	c->where[base] = '\0';
	/* SWVC List of Virtual Topologies (§9.6). */
	if (!objects(c, ucl_object_lookup(sw, "topologies"), "topologies",
	    "name", true, NULL, "R27"))
		return (false);
	it = NULL;
	while ((t = ucl_object_iterate(ucl_object_lookup(sw, "topologies"),
	    &it, true)) != NULL) {
		at(c, base, "topology %s", str(t, "name"));
		if (strcmp(str(t, "name"), "Swvc") == 0)
			return (fail(c, "Swvc is the SWVC itself (R28)"));
		s = str(t, "type");
		if (s != NULL && strcmp(s, "multipoint-to-multipoint") == 0) {
			if (!names(c, ucl_object_lookup(t, "end_points"),
			    "end_points", false))
				return (false);
			if (count(ucl_object_lookup(t, "end_points")) < 2)
				return (fail(c, "two end points at least "
				    "(R29)"));
			v = ucl_object_lookup(t, "end_points");
		} else if (s != NULL && strcmp(s, "rooted-multipoint") == 0) {
			if (!names(c, ucl_object_lookup(t, "roots"), "roots",
			    false) || !names(c, ucl_object_lookup(t, "leaves"),
			    "leaves", false))
				return (fail(c, "a root and a leaf at least "
				    "(R30)"));
			it2 = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(t,
			    "roots"), &it2, true)) != NULL)
				if (in_names(ucl_object_lookup(t, "leaves"),
				    ucl_object_tostring(e)))
					return (fail(c, "%s is a root and a "
					    "leaf (R31)", ucl_object_tostring(
					    e)));
			v = NULL;
		} else
			return (fail(c, "its type is multipoint-to-multipoint "
			    "or rooted-multipoint (§9.6)"));
		/* Each is one of the SWVC's end points. */
		for (i = 0; i < 3; i++) {
			const char *const lists[] = { "end_points", "roots",
			    "leaves" };

			it2 = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(t,
			    lists[i]), &it2, true)) != NULL)
				if (by(ucl_object_lookup(sw, "end_points"), "id",
				    ucl_object_tostring(e)) == NULL)
					return (fail(c, "%s is not an end point "
					    "of the SWVC", ucl_object_tostring(
					    e)));
		}
	}
	c->where[base] = '\0';
	/* SWVC Performance Time Intervals (§9.7). */
	if ((v = ucl_object_lookup(sw, "intervals")) != NULL) {
		int64_t	ev, ar, ir;

		if (!is_int(ucl_object_lookup(v, "eval"), 100, 86400000, &ev) ||
		    !is_int(ucl_object_lookup(v, "arrival"), 1, 86400000, &ar)
		    || !is_int(ucl_object_lookup(v, "ir"), 1, 86400000, &ir))
			return (fail(c, "intervals: eval, arrival and ir in "
			    "milliseconds, eval 100 or more"));
		if (ar >= ev)
			return (fail(c, "intervals: arrival is shorter than eval "
			    "(§9.7)"));
		if (ir > 1000)
			return (fail(c, "intervals: ir is 1000 ms at most "
			    "(D2)"));
	}
	/* SWVC List of Rate Limiters (§9.9). */
	if (!objects(c, ucl_object_lookup(sw, "rate_limiters"),
	    "rate_limiters", "name", true, NULL, "§9.9"))
		return (false);
	it = NULL;
	while ((v = ucl_object_iterate(ucl_object_lookup(sw, "rate_limiters"),
	    &it, true)) != NULL) {
		at(c, base, "rate limiter %s", str(v, "name"));
		if (!rate(c, v, NULL))
			return (false);
	}
	c->where[base] = '\0';
	/* Security policies (§9.10; their criteria MEF 88's) and importance
	 * levels (§9.11). */
	if (!objects(c, ucl_object_lookup(sw, "security_policies"),
	    "security_policies", "name", true, NULL, "§9.10"))
		return (false);
	it = NULL;
	while ((v = ucl_object_iterate(ucl_object_lookup(sw,
	    "security_policies"), &it, true)) != NULL) {
		at(c, base, "security policy %s", str(v, "name"));
		if (!security_policy(c, v))
			return (false);
	}
	c->where[base] = '\0';
	v = ucl_object_lookup(sw, "importance");
	if (!is_null(v)) {
		if (!names(c, ucl_object_lookup(v, "levels"),
		    "importance levels", false))
			return (false);
		if (!in_names(ucl_object_lookup(v, "levels"), str(v,
		    "default")))
			return (fail(c, "importance: the default is one of the "
			    "levels (§9.11)"));
	}
	/* SWVC List of Policies (§9.12). */
	if (!objects(c, ucl_object_lookup(sw, "policies"), "policies", "name",
	    false, NULL, "R32"))
		return (false);
	it = NULL;
	while ((p = ucl_object_iterate(ucl_object_lookup(sw, "policies"), &it,
	    true)) != NULL) {
		at(c, base, "policy %s", str(p, "name"));
		if (strcmp(str(p, "name"), "None") == 0 || strcmp(str(p,
		    "name"), "Block") == 0)
			return (fail(c, "None and Block are not names of a "
			    "policy (§9.12)"));
		if (!policy(c, sw, p))
			return (false);
	}
	c->where[base] = '\0';
	/* SWVC List of Zones (§9.5). */
	if (!objects(c, ucl_object_lookup(sw, "zones"), "zones", "name",
	    false, NULL, "R19"))
		return (false);
	nz = 0;
	defaults = 0;
	it = NULL;
	while ((z = ucl_object_iterate(ucl_object_lookup(sw, "zones"), &it,
	    true)) != NULL) {
		at(c, base, "zone %s", str(z, "name"));
		s = str(z, "name");
		if (strcmp(s, "Self") == 0 || strcmp(s, "Internet") == 0 ||
		    strcmp(s, "All") == 0)
			return (fail(c, "Self, Internet and All are not names "
			    "of a zone (§9.5)"));
		zp = ucl_object_lookup(z, "prefixes");
		if (ucl_object_type(zp) == UCL_STRING && strcmp(
		    ucl_object_tostring(zp), "Default") == 0) {
			if (++defaults > 1)
				return (fail(c, "one Default zone at most "
				    "(R21)"));
		} else {
			if (count(zp) == 0)
				return (fail(c, "its prefixes are Default or a "
				    "list, one at least"));
			it2 = NULL;
			while ((e = ucl_object_iterate(zp, &it2, true)) !=
			    NULL) {
				if (nz == LIST_MAX || !prefix(
				    ucl_object_tostring_forced(e), &q, false))
					return (fail(c, "%s is not a prefix",
					    ucl_object_tostring_forced(e)));
				for (i = 0; i < nz; i++)
					if (overlap(&zones[i], &q))
						return (fail(c, "%s overlaps "
						    "another zone (R20)",
						    ucl_object_tostring_forced(
						    e)));
				for (i = 0; i < nr; i++)
					if (overlap(&res[i], &q))
						return (fail(c, "%s overlaps a "
						    "reserved prefix (§9.4)",
						    ucl_object_tostring_forced(
						    e)));
				zones[nz++] = q;
			}
		}
		/* Its policies, zone-wide (§9.5). */
		v = ucl_object_lookup(z, "policies");
		if (v != NULL && ucl_object_type(v) != UCL_ARRAY)
			return (fail(c, "its policies are a list"));
		it2 = NULL;
		j = 0;
		while ((e = ucl_object_iterate(v, &it2, true)) != NULL) {
			if (!app(sw, str(e, "app")))
				return (fail(c, "%s is no flow or group",
				    str(e, "app") != NULL ? str(e, "app") :
				    "an app"));
			if (!ingress_pol(sw, ucl_object_lookup(e, "policy"),
			    true) || is_null(ucl_object_lookup(e, "policy")))
				return (fail(c, "%s: its policy is an ingress "
				    "policy or Block", str(e, "app")));
			it3 = NULL;
			i = 0;
			while ((m = ucl_object_iterate(v, &it3, true)) != NULL &&
			    i++ < j)
				if (strcmp(str(m, "app"), str(e, "app")) == 0)
					return (fail(c, "%s is there twice "
					    "(R26)", str(e, "app")));
			j++;
		}
	}
	c->where[base] = '\0';
	/* SWVC List of SWVC End Points (§9.2, §10). */
	if (!objects(c, ucl_object_lookup(sw, "end_points"), "end_points",
	    "id", false, seen_ep, "R101"))
		return (false);
	it = NULL;
	while ((ep = ucl_object_iterate(ucl_object_lookup(sw, "end_points"),
	    &it, true)) != NULL) {
		const ucl_object_t	*u;

		at(c, base, "end point %s", str(ep, "id"));
		if (by(ucl_object_lookup(doc, "edges"), "server", str(ep,
		    "edge")) == NULL)
			return (fail(c, "its edge is one of the edges"));
		u = ucl_object_lookup(ep, "uni");
		if (!uni(c, u, nets, &nnets))
			return (false);
		if (ucl_object_lookup(seen_uni, str(u, "id")) != NULL)
			return (fail(c, "UNI %s is another end point's too "
			    "(R3, R16)", str(u, "id")));
		ucl_object_insert_key(seen_uni, ucl_object_frombool(true),
		    str(u, "id"), 0, true);
		/* One UNI an interface and VLAN of an edge, once: in this
		 * service and in every other (R3, R16). */
		{
			char	ifkey[320];

			snprintf(ifkey, sizeof(ifkey), "%s %s %jd", str(ep,
			    "edge"), str(u, "interface"), (intmax_t)
			    ucl_object_toint(ucl_object_lookup(u, "vlan")));
			if ((e = ucl_object_lookup(seen_if, ifkey)) != NULL)
				return (fail(c, "its UNI is end point %s's "
				    "interface and VLAN too (R3)",
				    ucl_object_tostring(e)));
			ucl_object_insert_key(seen_if, ucl_object_fromstring(
			    str(ep, "id")), ifkey, 0, true);
		}
		for (i = 0; i < nnets; i++)
			for (j = 0; j < nr; j++)
				if (holds(&res[j], &nets[i]))
					return (fail(c, "its UNI's prefix is in "
					    "a reserved prefix (§9.4)"));
		/* Policy map (§10.4). */
		v = ucl_object_lookup(ep, "policy_map");
		if (v != NULL && ucl_object_type(v) != UCL_ARRAY)
			return (fail(c, "policy_map is a list"));
		if (count(v) > LIST_MAX)
			return (fail(c, "policy_map: %d at most", LIST_MAX));
		it2 = NULL;
		j = 0;
		while ((m = ucl_object_iterate(v, &it2, true)) != NULL) {
			const ucl_object_t	*ip, *eg, *o;
			const char		*zn, *an;

			zn = str(m, "zone");
			an = str(m, "app");
			if (zn == NULL || (strcmp(zn, "Internet") != 0 && by(
			    ucl_object_lookup(sw, "zones"), "name", zn) ==
			    NULL))
				return (fail(c, "policy_map: a zone is one of "
				    "the zones or Internet (R103)"));
			if (!app(sw, an))
				return (fail(c, "policy_map: %s is no flow or "
				    "group (R104)", an != NULL ? an : "an app"));
			it3 = NULL;
			i = 0;
			while ((o = ucl_object_iterate(v, &it3, true)) != NULL &&
			    i++ < j)
				if (strcmp(str(o, "zone"), zn) == 0 &&
				    strcmp(str(o, "app"), an) == 0)
					return (fail(c, "policy_map: %s, %s is "
					    "there twice (R105)", zn, an));
			j++;
			ip = ucl_object_lookup(m, "ingress");
			eg = ucl_object_lookup(m, "egress");
			if (!ingress_pol(sw, ip, true))
				return (fail(c, "policy_map: %s, %s: ingress is "
				    "null, Block or an ingress policy (R106)",
				    zn, an));
			if (strcmp(zn, "Internet") == 0 && !is_null(ip))
				return (fail(c, "policy_map: from the Internet, "
				    "no ingress policy (R107)"));
			if (!is_null(eg) && (ucl_object_type(eg) != UCL_STRING
			    || (o = by(ucl_object_lookup(sw, "policies"),
			    "name", ucl_object_tostring(eg))) == NULL ||
			    strcmp(str(o, "direction"), "egress") != 0))
				return (fail(c, "policy_map: %s, %s: egress is "
				    "null or an egress policy (R108)", zn, an));
			if (!is_null(ip) && (s = vt_of(sw, ucl_object_tostring(
			    ip))) != NULL && !vt_has(sw, s, str(ep, "id")))
				return (fail(c, "policy_map: %s, %s: its policy "
				    "keeps to topology %s, which this end point "
				    "is not in (R47)", zn, an, s));
		}
		/*
		 * A zone-wide policy that keeps to a topology this end point
		 * is not in: the end point's map says otherwise (R47).
		 */
		it2 = NULL;
		while ((z = ucl_object_iterate(ucl_object_lookup(sw, "zones"),
		    &it2, true)) != NULL) {
			it3 = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(z,
			    "policies"), &it3, true)) != NULL) {
				const ucl_object_t	*o;
				ucl_object_iter_t	 it4;
				bool			 over;

				if ((s = vt_of(sw, str(e, "policy"))) == NULL ||
				    vt_has(sw, s, str(ep, "id")))
					continue;
				over = false;
				it4 = NULL;
				while ((o = ucl_object_iterate(v, &it4, true))
				    != NULL)
					if (strcmp(str(o, "zone"), str(z,
					    "name")) == 0 && strcmp(str(o,
					    "app"), str(e, "app")) == 0)
						over = true;
				if (!over)
					return (fail(c, "zone %s gives %s policy "
					    "%s, which keeps to topology %s: "
					    "this end point's policy map says "
					    "another (R47)", str(z, "name"),
					    str(e, "app"), str(e, "policy"),
					    s));
			}
		}
		/* NAT (§10.5). */
		v = ucl_object_lookup(ep, "nat");
		if (!is_null(v) && !(ucl_object_type(v) == UCL_STRING &&
		    strcmp(ucl_object_tostring(v), "disabled") == 0)) {
			if (!one_of(str(v, "ip_version"), (const char *const[])
			    { "ipv4", "ipv6", "both", NULL }))
				return (fail(c, "nat: ip_version is ipv4, ipv6 "
				    "or both"));
			if (!prefix(str(v, "public_prefix"), &q, false) ||
			    q.af != AF_INET)
				return (fail(c, "nat: public_prefix is an IPv4 "
				    "prefix (§10.5)"));
			it2 = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(v,
			    "exceptions"), &it2, true)) != NULL)
				if (!prefix(ucl_object_tostring_forced(e), &q,
				    false))
					return (fail(c, "nat: exceptions are "
					    "prefixes"));
		}
		if (ucl_object_lookup(ep, "availability") != NULL && !is_num(
		    ucl_object_lookup(ep, "availability"), &(double){ 0 }))
			return (fail(c, "availability is a percentage"));
	}
	c->where[base] = '\0';
	/* BFD on the tunnels (Mplify 119 §10.5, R58-R60, R159). */
	if ((v = ucl_object_lookup(sw, "bfd")) != NULL && !is_null(v)) {
		if (ucl_object_type(v) != UCL_OBJECT)
			return (fail(c, "bfd is an object: interval, multiplier"));
		if ((e = ucl_object_lookup(v, "interval")) != NULL &&
		    !is_int(e, 100, 300, NULL))
			return (fail(c, "bfd: interval is 100 to 300 ms (R159)"));
		if ((e = ucl_object_lookup(v, "multiplier")) != NULL &&
		    !is_int(e, 2, 10, NULL))
			return (fail(c, "bfd: multiplier is 2 to 10, 3 as a rule "
			    "(R159)"));
	}
	/* Threshold crossing alerts (Mplify 119 §11.4, MEF 105 §7.4). */
	if ((v = ucl_object_lookup(sw, "tca")) != NULL && !is_null(v)) {
		double	d;

		if (ucl_object_type(v) != UCL_OBJECT)
			return (fail(c, "tca is an object: delay, ipdv, loss, "
			    "damping"));
		if (((e = ucl_object_lookup(v, "delay")) != NULL && (!is_num(e,
		    &d) || d <= 0)) || ((e = ucl_object_lookup(v, "ipdv")) !=
		    NULL && (!is_num(e, &d) || d <= 0)))
			return (fail(c, "tca: delay and ipdv are ms, more than 0"));
		if ((e = ucl_object_lookup(v, "loss")) != NULL && (!is_num(e, &d)
		    || d <= 0 || d > 1))
			return (fail(c, "tca: loss is a fraction, 0 to 1"));
		if ((e = ucl_object_lookup(v, "damping")) != NULL && !is_int(e,
		    1, 100, NULL))
			return (fail(c, "tca: damping is intervals in a row, 1 to "
			    "100 (CR2)"));
	}
	/* Probing (Mplify 119 §11.4): the defaults of its tunnels. */
	if ((v = ucl_object_lookup(sw, "probe")) != NULL) {
		if (ucl_object_type(v) != UCL_OBJECT)
			return (fail(c, "probe is an object"));
		if ((e = ucl_object_lookup(v, "interval")) != NULL &&
		    !is_int(e, 10, 60000, NULL))
			return (fail(c, "probe: interval is 10 to 60000 ms"));
		if ((e = ucl_object_lookup(v, "size")) != NULL &&
		    !is_int(e, 64, 10000, NULL))
			return (fail(c, "probe: size is 64 to 10000 bytes"));
		if ((e = ucl_object_lookup(v, "count")) != NULL &&
		    !is_int(e, 0, INT32_MAX, NULL))
			return (fail(c, "probe: count is 0, without end, or "
			    "more"));
		if ((e = ucl_object_lookup(v, "dscp")) != NULL &&
		    !is_int(e, 0, 63, NULL))
			return (fail(c, "probe: dscp is 0 to 63"));
		if ((e = ucl_object_lookup(v, "down")) != NULL &&
		    !is_int(e, 1, 100, NULL))
			return (fail(c, "probe: down is 1 to 100 misses"));
		if ((e = ucl_object_lookup(v, "up")) != NULL &&
		    !is_int(e, 1, 100, NULL))
			return (fail(c, "probe: up is 1 to 100 replies"));
		if ((e = ucl_object_lookup(v, "timeout")) != NULL &&
		    !is_int(e, 10, 60000, NULL))
			return (fail(c, "probe: timeout is 10 to 60000 ms"));
		if ((e = ucl_object_lookup(v, "history")) != NULL &&
		    !is_int(e, 1, 100000, NULL))
			return (fail(c, "probe: history is 1 to 100000 "
			    "intervals"));
		if ((e = ucl_object_lookup(v, "report")) != NULL &&
		    !is_int(e, 1, 1000, &n))
			return (fail(c, "probe: report is so many eval "
			    "intervals, 1 to 1000"));
	}
	return (true);
}

/* A domain name as a DNS filter takes it: labels of letters, digits and
 * hyphens, 253 characters at most. */
static bool
domain_ok(const char *s)
{
	size_t	n, lab;

	if (s == NULL || (n = strlen(s)) == 0 || n > 253 || s[0] == '.' ||
	    s[n - 1] == '.')
		return (false);
	lab = 0;
	for (; *s != '\0'; s++) {
		if (*s == '.') {
			if (lab == 0)
				return (false);
			lab = 0;
			continue;
		}
		if (!isalnum((unsigned char)*s) && *s != '-' && *s != '_')
			return (false);
		if (++lab > 63)
			return (false);
	}
	return (true);
}

/*
 * A security policy (MEF 88): a name and criteria, each optional:
 * ip-block with allow and deny lists of prefixes, dns-domain-filter with
 * the domains denied, dns-protocol-filter, rate-limit in bits per
 * second, and log.
 */
static bool
security_policy(struct ck *c, const ucl_object_t *v)
{
	static const char *const known[] = { "ip-block", "dns-domain-filter",
	    "dns-protocol-filter", "rate-limit", "log", NULL };
	const ucl_object_t	*cr, *k, *e;
	ucl_object_iter_t	 it, eit;
	struct pfx		 p;
	int			 i;

	if ((cr = ucl_object_lookup(v, "criteria")) == NULL ||
	    ucl_object_type(cr) != UCL_OBJECT)
		return (fail(c, "it has criteria: ip-block, dns-domain-filter, "
		    "dns-protocol-filter, rate-limit, log (MEF 88)"));
	it = NULL;
	while ((k = ucl_object_iterate(cr, &it, true)) != NULL) {
		if (!one_of(ucl_object_key(k), known))
			return (fail(c, "%s is not a criterion: ip-block, "
			    "dns-domain-filter, dns-protocol-filter, rate-limit or "
			    "log", ucl_object_key(k)));
		if (strcmp(ucl_object_key(k), "ip-block") == 0) {
			static const char *const lists[] = { "allow", "deny" };

			if (ucl_object_type(k) != UCL_OBJECT)
				return (fail(c, "ip-block has allow and deny, lists "
				    "of prefixes"));
			if ((e = ucl_object_lookup(k, "lists")) != NULL) {
				if (ucl_object_type(e) != UCL_ARRAY)
					return (fail(c, "ip-block.lists names lists, "
					    "feeds or pasted (Security)"));
				eit = NULL;
				while ((e = ucl_object_iterate(ucl_object_lookup(k,
				    "lists"), &eit, true)) != NULL)
					if (ucl_object_type(e) != UCL_STRING ||
					    !sdwan_list_exists(ucl_object_tostring(e)))
						return (fail(c, "ip-block.lists: no list "
						    "%s (a feed or a pasted list, under "
						    "Security)", ucl_object_tostring_forced(
						    e)));
			}
			for (i = 0; i < 2; i++) {
				if ((e = ucl_object_lookup(k, lists[i])) == NULL)
					continue;
				if (ucl_object_type(e) != UCL_ARRAY || ucl_array_size(
				    e) > LIST_MAX)
					return (fail(c, "ip-block.%s is a list of "
					    "prefixes, %d at most", lists[i], LIST_MAX));
				eit = NULL;
				while ((e = ucl_object_iterate(ucl_object_lookup(k,
				    lists[i]), &eit, true)) != NULL)
					if (ucl_object_type(e) != UCL_STRING || !prefix(
					    ucl_object_tostring(e), &p, true))
						return (fail(c, "ip-block.%s: %s is not a "
						    "prefix", lists[i],
						    ucl_object_tostring_forced(e)));
			}
		} else if (strcmp(ucl_object_key(k), "dns-domain-filter") == 0) {
			if (ucl_object_type(k) != UCL_OBJECT || ((e =
			    ucl_object_lookup(k, "deny")) == NULL &&
			    ucl_object_lookup(k, "lists") == NULL) || (e != NULL && (
			    ucl_object_type(e) != UCL_ARRAY || ucl_array_size(e) >
			    LIST_MAX)))
				return (fail(c, "dns-domain-filter has deny, a list "
				    "of domains, %d at most, or lists by name",
				    LIST_MAX));
			eit = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(k, "lists"),
			    &eit, true)) != NULL)
				if (ucl_object_type(e) != UCL_STRING ||
				    !sdwan_list_exists(ucl_object_tostring(e)))
					return (fail(c, "dns-domain-filter.lists: no "
					    "list %s (a feed or a pasted list, under "
					    "Security)", ucl_object_tostring_forced(e)));
			eit = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(k, "deny"),
			    &eit, true)) != NULL)
				if (ucl_object_type(e) != UCL_STRING || !domain_ok(
				    ucl_object_tostring(e)))
					return (fail(c, "dns-domain-filter.deny: %s is "
					    "not a domain name",
					    ucl_object_tostring_forced(e)));
		} else if (strcmp(ucl_object_key(k), "rate-limit") == 0) {
			if (!is_int(k, 1000, 1000000000000LL, NULL))
				return (fail(c, "rate-limit is bits per second, 1000 "
				    "or more"));
		} else if (ucl_object_type(k) != UCL_BOOLEAN)
			return (fail(c, "%s is true or false", ucl_object_key(k)));
	}
	return (true);
}

static const char *const tunnel_kinds[] = { "gre", "gif", "geneve", "wg",
    "uswe", NULL };

/* The whole document, checked; false and why when it is not one. */
static bool
check(const ucl_object_t *doc, struct ck *c)
{
	const ucl_object_t	*v, *e, *sw, *t;
	ucl_object_iter_t	 it, it2, it3;
	ucl_object_t		*seen_ep, *seen_uni, *seen_ucsep, *fibs;
	ucl_object_t		*seen_if;
	const char		*s;
	struct pfx		 a;
	bool			 ok;

	memset(c, 0, sizeof(*c));
	if (ucl_object_type(doc) != UCL_OBJECT)
		return (fail(c, "it is an object"));
	/* UCSs (§12.1). */
	if (!objects(c, ucl_object_lookup(doc, "ucs"), "ucs", "id", true,
	    NULL, "R168"))
		return (false);
	it = NULL;
	while ((v = ucl_object_iterate(ucl_object_lookup(doc, "ucs"), &it,
	    true)) != NULL) {
		at(c, 0, "ucs %s", str(v, "id"));
		if (!one_of(str(v, "type"), (const char *const[]){ "public",
		    "private", NULL }))
			return (fail(c, "its type is public, an Internet "
			    "Access, or private (R170, R171)"));
		if (str(v, "billing") != NULL && !one_of(str(v, "billing"),
		    (const char *const[]){ "flat-rate", "usage-based",
		    "other", NULL }))
			return (fail(c, "its billing is flat-rate, usage-based "
			    "or other (§12.1.3)"));
		if ((t = ucl_object_lookup(v, "tunnel")) != NULL) {
			if (!one_of(str(t, "kind"), tunnel_kinds))
				return (fail(c, "its tunnels are gre, gif, "
				    "geneve, wg or uswe"));
			if ((strcmp(str(t, "kind"), "wg") == 0 || strcmp(str(t,
			    "kind"), "uswe") == 0) && ucl_flag(t, "ipsec"))
				return (fail(c, "%s encrypts by itself: no IPsec "
				    "IKEv2 under it", str(t, "kind")));
			/* The USWE tunnel (Mplify 119 §10): IPsec keyed by the
			 * edges themselves, its algorithms and flags here. */
			if (str(t, "algorithms") != NULL && !one_of(str(t,
			    "algorithms"), (const char *const[]){
			    "aes-cbc-hmac-sha2-256", "aes-gcm-16", NULL }))
				return (fail(c, "algorithms is aes-cbc-hmac-sha2-256 "
				    "or aes-gcm-16 (R44, R45)"));
			if (ucl_object_lookup(t, "lifetime") != NULL && !is_int(
			    ucl_object_lookup(t, "lifetime"), 120, 31536000,
			    NULL))
				return (fail(c, "lifetime is seconds, 120 to a "
				    "year: the keys turn at its half (R110, "
				    "R112)"));
			if (strcmp(str(t, "kind"), "uswe") != 0 && (str(t,
			    "algorithms") != NULL || ucl_object_lookup(t, "esn")
			    != NULL || ucl_object_lookup(t, "encap") != NULL ||
			    ucl_object_lookup(t, "lifetime") != NULL))
				return (fail(c, "algorithms, esn, encap and lifetime "
				    "are a uswe tunnel's"));
		}
	}
	c->where[0] = '\0';
	/* Edges (§7.8) and their UCS End Points (§12.3). */
	if (!objects(c, ucl_object_lookup(doc, "edges"), "edges", "server",
	    true, NULL, "§7.8"))
		return (false);
	seen_ucsep = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	ok = true;
	while (ok && (v = ucl_object_iterate(ucl_object_lookup(doc, "edges"),
	    &it, true)) != NULL) {
		at(c, 0, "edge %s", str(v, "server"));
		if (server_find(str(v, "server")) == NULL) {
			ok = fail(c, "no such server");
			break;
		}
		/* NTP (Mplify 119 §12.2.2): the servers the edge keeps time by. */
		if ((e = ucl_object_lookup(v, "ntp")) != NULL && !is_null(e)) {
			const ucl_object_t	*ns;
			ucl_object_iter_t	 nit;

			if (ucl_object_type(e) != UCL_ARRAY || ucl_array_size(e)
			    == 0 || ucl_array_size(e) > 8) {
				ok = fail(c, "ntp is a list of servers, 1 to 8");
				break;
			}
			nit = NULL;
			while (ok && (ns = ucl_object_iterate(e, &nit, true)) !=
			    NULL) {
				const char	*h = ucl_object_tostring_forced(ns);

				if (h == NULL || h[0] == '\0' || strlen(h) > 253 ||
				    h[strspn(h, "abcdefghijklmnopqrstuvwxyzABCDEFGHI"
				    "JKLMNOPQRSTUVWXYZ0123456789.-:")] != '\0')
					ok = fail(c, "ntp: %s is not a server's name "
					    "or address", h != NULL ? h : "");
			}
			if (!ok)
				break;
		}
		if (!objects(c, ucl_object_lookup(v, "ucs_end_points"),
		    "ucs_end_points", "id", false, seen_ucsep, "R176")) {
			ok = false;
			break;
		}
		it2 = NULL;
		while (ok && (e = ucl_object_iterate(ucl_object_lookup(v,
		    "ucs_end_points"), &it2, true)) != NULL) {
			const ucl_object_t	*u;

			at(c, 0, "edge %s, ucs end point %s", str(v, "server"),
			    str(e, "id"));
			if ((u = by(ucl_object_lookup(doc, "ucs"), "id", str(e,
			    "ucs"))) == NULL)
				ok = fail(c, "its ucs is one of the UCSs");
			else if (!ifname(str(e, "interface")))
				ok = fail(c, "it is on an interface");
			else if (str(e, "address") != NULL && !address(str(e,
			    "address"), &a))
				ok = fail(c, "its address is an address");
			else if (str(e, "gateway") != NULL && !address(str(e,
			    "gateway"), &a))
				ok = fail(c, "its gateway is an address");
			else if (ucl_flag(e, "breakout") && strcmp(str(u,
			    "type"), "public") != 0)
				ok = fail(c, "only an Internet Access, a public "
				    "UCS, breaks out (§12.3)");
			else if (ucl_object_lookup(e, "bandwidth") != NULL &&
			    !is_int(ucl_object_lookup(e, "bandwidth"), 0,
			    INT64_MAX, NULL))
				ok = fail(c, "its bandwidth is bits per second");
			/* How it is addressed and routed (Mplify 119 §12.2.3):
			 * by DHCP or SLAAC the address is learned from the
			 * host; a vrf is a table of its own; bgp or ospf with
			 * the underlay as at a UNI. */
			else if (str(e, "addressing") != NULL && !one_of(str(e,
			    "addressing"), (const char *const[]){ "static", "dhcp",
			    "slaac", NULL }))
				ok = fail(c, "its addressing is static, dhcp or slaac "
				    "(Mplify 119 §12.2.3.2)");
			else if (ucl_object_lookup(e, "vrf") != NULL && !is_int(
			    ucl_object_lookup(e, "vrf"), 1, FIB_MAX, NULL))
				ok = fail(c, "its vrf is a routing table, 1 or more "
				    "(§12.2.3.4)");
			else if (ucl_object_lookup(e, "routing") != NULL &&
			    !is_null(ucl_object_lookup(e, "routing")) &&
			    ucl_object_type(ucl_object_lookup(e, "routing")) !=
			    UCL_OBJECT)
				ok = fail(c, "its routing is an object: bgp, ospf");
			else if (!routing(c, ucl_object_lookup(ucl_object_lookup(e,
			    "routing"), "bgp"), "bgp", NULL, 0) || !routing(c,
			    ucl_object_lookup(ucl_object_lookup(e, "routing"),
			    "ospf"), "ospf", NULL, 0))
				ok = false;
		}
	}
	ucl_object_unref(seen_ucsep);
	if (!ok)
		return (false);
	c->where[0] = '\0';
	/* SWVCs (§9). */
	if (!objects(c, ucl_object_lookup(doc, "swvcs"), "swvcs", "id", true,
	    NULL, "R14"))
		return (false);
	seen_ep = ucl_object_typed_new(UCL_OBJECT);
	seen_uni = ucl_object_typed_new(UCL_OBJECT);
	seen_if = ucl_object_typed_new(UCL_OBJECT);
	fibs = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while (ok && (sw = ucl_object_iterate(ucl_object_lookup(doc, "swvcs"),
	    &it, true)) != NULL) {
		char	fib[16];

		at(c, 0, "swvc %s", str(sw, "id"));
		if (!swvc(c, doc, sw, seen_ep, seen_uni, seen_if)) {
			ok = false;
			break;
		}
		snprintf(fib, sizeof(fib), "%jd", (intmax_t)ucl_object_toint(
		    ucl_object_lookup(sw, "fib")));
		if (ucl_object_lookup(fibs, fib) != NULL) {
			ok = fail(c, "fib %s is another SWVC's", fib);
			break;
		}
		ucl_object_insert_key(fibs, ucl_object_frombool(true), fib, 0,
		    true);
		/* The domains' tables and labels too: one service's each
		 * (Mplify 119 R15-R20). */
		{
			static const char *const dn[] = { "service", "breakout",
			    "subscriber" };
			const ucl_object_t	*dom;
			int			 i;

			for (i = 0; ok && i < 3; i++) {
				dom = ucl_object_lookup(ucl_object_lookup(sw,
				    "domains"), dn[i]);
				if (dom == NULL)
					continue;
				if (ucl_object_lookup(dom, "fib") != NULL) {
					snprintf(fib, sizeof(fib), "%jd", (intmax_t)
					    ucl_object_toint(ucl_object_lookup(dom,
					    "fib")));
					if (ucl_object_lookup(fibs, fib) != NULL) {
						ok = fail(c, "domains.%s.fib %s is "
						    "another's (R20)", dn[i], fib);
						break;
					}
					ucl_object_insert_key(fibs,
					    ucl_object_frombool(true), fib, 0, true);
				}
				if (ucl_object_lookup(dom, "label") != NULL) {
					snprintf(fib, sizeof(fib), "label %jd",
					    (intmax_t)ucl_object_toint(
					    ucl_object_lookup(dom, "label")));
					if (ucl_object_lookup(fibs, fib) != NULL) {
						ok = fail(c, "domains.%s.%s is "
						    "another's (R19)", dn[i], fib);
						break;
					}
					ucl_object_insert_key(fibs,
					    ucl_object_frombool(true), fib, 0, true);
				}
			}
		}
		/* A private UCS is one SWVC's alone (R5). */
		it2 = NULL;
		while (ok && (e = ucl_object_iterate(ucl_object_lookup(sw,
		    "ucs"), &it2, true)) != NULL) {
			const ucl_object_t	*o;

			s = ucl_object_tostring(e);
			if (strcmp(str(by(ucl_object_lookup(doc, "ucs"), "id",
			    s), "type"), "private") != 0)
				continue;
			it3 = NULL;
			while ((o = ucl_object_iterate(ucl_object_lookup(doc,
			    "swvcs"), &it3, true)) != NULL)
				if (o != sw && in_names(ucl_object_lookup(o,
				    "ucs"), s)) {
					ok = fail(c, "private UCS %s is SWVC "
					    "%s's too (R5)", s, str(o, "id"));
					break;
				}
		}
		/* Each end point's edge has an end point of its UCSs. */
		it2 = NULL;
		while (ok && (e = ucl_object_iterate(ucl_object_lookup(sw,
		    "end_points"), &it2, true)) != NULL) {
			const ucl_object_t	*edge, *u;
			ucl_object_iter_t	 it4;
			bool			 any;

			edge = by(ucl_object_lookup(doc, "edges"), "server",
			    str(e, "edge"));
			any = false;
			it4 = NULL;
			while ((u = ucl_object_iterate(ucl_object_lookup(edge,
			    "ucs_end_points"), &it4, true)) != NULL)
				if (in_names(ucl_object_lookup(sw, "ucs"), str(u,
				    "ucs")))
					any = true;
			if (!any)
				ok = fail(c, "end point %s: its edge has no end "
				    "point of the SWVC's UCSs", str(e, "id"));
		}
	}
	ucl_object_unref(seen_ep);
	ucl_object_unref(seen_uni);
	ucl_object_unref(seen_if);
	ucl_object_unref(fibs);
	return (ok);
}

/* ---- The API --------------------------------------------------------- */

static ucl_object_t	*sd_load(void);

/* The document as kept, for another part; to be unref'd. */
ucl_object_t *
sdwan_load(void)
{
	ucl_object_t	*doc;

	pthread_mutex_lock(&sd_lock);
	doc = sd_load();
	pthread_mutex_unlock(&sd_lock);
	return (doc);
}

/* Is it one MEF 70.2 allows, as far as checked; why not, when not. */
bool
sdwan_valid(const ucl_object_t *doc, char *why, size_t len)
{
	struct ck	c;

	if (check(doc, &c))
		return (true);
	snprintf(why, len, "%s", c.why);
	return (false);
}

static ucl_object_t *
sd_load(void)
{
	ucl_object_t	*doc;

	if ((doc = store_load(SDWAN_FILE)) == NULL) {
		doc = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(doc, ucl_object_fromint(0), "version", 0,
		    false);
	}
	return (doc);
}

int
api_sdwan(struct http_request *req)
{
	ucl_object_t	*body, *doc, *o;
	struct ck	 c;
	int64_t		 have, sent;
	bool		 keep;

	if (req->method == HTTP_METHOD_GET) {
		if (!guard(req, false))
			return (KORE_RESULT_OK);
		pthread_mutex_lock(&sd_lock);
		doc = sd_load();
		pthread_mutex_unlock(&sd_lock);
		return (reply_json(req, 200, doc));
	}
	if (!guard(req, true))
		return (KORE_RESULT_OK);
	keep = strcmp(req->path, "/api/sdwan") == 0;
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "the SD-WAN document, "
		    "as JSON"));
	if (!check(body, &c)) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "%s", c.why));
	}
	if (!keep) {
		ucl_object_unref(body);
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_frombool(true), "ok", 0,
		    false);
		return (reply_json(req, 200, o));
	}
	pthread_mutex_lock(&sd_lock);
	doc = sd_load();
	have = ucl_object_toint(ucl_object_lookup(doc, "version"));
	sent = ucl_object_toint(ucl_object_lookup(body, "version"));
	ucl_object_unref(doc);
	if (sent != have) {
		pthread_mutex_unlock(&sd_lock);
		ucl_object_unref(body);
		return (reply_error(req, 409, "stale", "it was changed since: "
		    "version %jd, not %jd", (intmax_t)have, (intmax_t)sent));
	}
	(void)ucl_object_delete_key(body, "version");
	(void)ucl_object_delete_key(body, "changed");
	ucl_object_insert_key(body, ucl_object_fromint(have + 1), "version", 0,
	    false);
	ucl_object_insert_key(body, ucl_object_fromint(time(NULL)), "changed",
	    0, false);
	if (store_save(SDWAN_FILE, body) != 0) {
		pthread_mutex_unlock(&sd_lock);
		ucl_object_unref(body);
		return (reply_error(req, 500, "store", "it could not be "
		    "written"));
	}
	pthread_mutex_unlock(&sd_lock);
	return (reply_json(req, 200, body));
}
