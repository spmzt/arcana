/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: the files of the SD-WAN services' daemons and the Security
 * section's, rendered here from the forms the console sends, as
 * Suricata's YAML is (idsconf.c): dnsmasq's (sddhcp.c), unbound's
 * (sddns.c), Squid's and c-icap's (sdproxy.c), BIRD's (sdbird.c).  Each
 * daemon's checker takes the file before it runs (dnsmasq --test,
 * local-unbound-checkconf, squid -k parse, bird -p); c-icap has none,
 * and says what it refuses as it starts.  The console sends what
 * the admin chose, the SD-WAN objects' fields as the edge has them
 * (its interfaces, its addresses, the named lists' entries); the text
 * is made here, with the agent's own paths in it, so that what the
 * daemon's checker takes is what runs.  Every string that reaches a
 * file is checked first: no control character, quote or backslash,
 * nothing that ends a line or a quoted word early.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ucl.h>

#include "agent.h"

#define	SPEC_DEPTH	8
#define	WORD_MAX	1024
#define	LIST_MAX	4096	/* addresses, prefixes or names a list */

static const char *
sstr(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, k);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

/* A string as the forms' comparisons take it: "" for none. */
static const char *
sval(const ucl_object_t *o, const char *k)
{

	return (sstr(o, k) != NULL ? sstr(o, k) : "");
}

static bool
sflag(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	return ((v = ucl_object_lookup(o, k)) != NULL && ucl_object_type(v) ==
	    UCL_BOOLEAN && ucl_object_toboolean(v));
}

static int64_t
sint(const ucl_object_t *o, const char *k, int64_t def)
{
	const ucl_object_t	*v;

	return ((v = ucl_object_lookup(o, k)) != NULL && ucl_object_type(v) ==
	    UCL_INT ? ucl_object_toint(v) : def);
}

/* The i-th of a list; NULL past its end, or where it is no list. */
static const ucl_object_t *
nth(const ucl_object_t *a, unsigned int i)
{

	return (ucl_object_type(a) == UCL_ARRAY ? ucl_array_find_index(a, i) :
	    NULL);
}

/* A word a file may hold: printable, no quote or backslash. */
static bool
word_ok(const char *s)
{
	size_t	i;

	for (i = 0; s[i] != '\0'; i++)
		if ((unsigned char)s[i] < 0x20 || s[i] == 0x7f || s[i] == '"' ||
		    s[i] == '\\')
			return (false);
	return (i <= WORD_MAX);
}

/*
 * Every key and string of a form a word a file may hold, and its depth
 * bounded; why it is not in *errp.
 */
static bool
spec_clean(struct work *w, const ucl_object_t *o, int depth,
    const char **errp)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	if (depth > SPEC_DEPTH) {
		*errp = "the form is nested too deep";
		return (false);
	}
	switch (ucl_object_type(o)) {
	case UCL_STRING:
		if (!word_ok(ucl_object_tostring(o))) {
			*errp = wfmt(w, "the form's %.64s: a word of printable "
			    "characters, no quote or backslash", ucl_object_key(o)
			    != NULL ? ucl_object_key(o) : "value");
			return (false);
		}
		return (true);
	case UCL_OBJECT:
	case UCL_ARRAY:
		it = NULL;
		while ((e = ucl_object_iterate(o, &it, true)) != NULL) {
			if (ucl_object_key(e) != NULL && ucl_object_type(o) ==
			    UCL_OBJECT && !word_ok(ucl_object_key(e))) {
				*errp = "the form's keys are words";
				return (false);
			}
			if (!spec_clean(w, e, depth + 1, errp))
				return (false);
		}
		return (true);
	default:
		return (true);
	}
}

/* A name in a file's own words (an acl's, a view's): letters, digits
 * and _. */
static bool
ident_ok(const char *s)
{
	size_t	n;

	n = s != NULL ? strlen(s) : 0;
	return (n > 0 && n <= 32 && strspn(s, "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == n);
}

/* The text so far, the stream closed (which may move the buffer: it is
 * read after); NULL and why when it fails. */
static char *
closed(struct work *w, FILE *fp, char **bufp, const char **errp)
{

	if (fclose(fp) != 0 || *bufp == NULL) {
		free(*bufp);
		*errp = "the configuration could not be written";
		return (NULL);
	}
	return (wadopt(w, *bufp));
}

/* ---- Addresses ------------------------------------------------------ */

struct net {
	int	af;
	uint8_t	a[16];
	int	len;
};

static bool
net_parse(const char *s, struct net *n)
{
	char	buf[64], *slash;

	memset(n, 0, sizeof(*n));
	if (s == NULL || strlen(s) >= sizeof(buf))
		return (false);
	snprintf(buf, sizeof(buf), "%s", s);
	if ((slash = strchr(buf, '/')) != NULL)
		*slash++ = '\0';
	if (inet_pton(AF_INET, buf, n->a) == 1)
		n->af = AF_INET;
	else if (inet_pton(AF_INET6, buf, n->a) == 1)
		n->af = AF_INET6;
	else
		return (false);
	n->len = slash != NULL ? atoi(slash) : n->af == AF_INET ? 32 : 128;
	return (n->len >= 0 && n->len <= (n->af == AF_INET ? 32 : 128));
}

static bool
addr_ok(const char *s)
{
	unsigned char	buf[16];

	return (s != NULL && (inet_pton(AF_INET, s, buf) == 1 ||
	    inet_pton(AF_INET6, s, buf) == 1));
}

/* An address, or one with /bits. */
static bool
prefix_ok(const char *s)
{
	unsigned char	 buf[16];
	char		 a[64], *sl, *end;
	long		 bits;
	int		 af;

	if (s == NULL || strlen(s) >= sizeof(a))
		return (false);
	snprintf(a, sizeof(a), "%s", s);
	if ((sl = strchr(a, '/')) != NULL)
		*sl++ = '\0';
	af = strchr(a, ':') != NULL ? AF_INET6 : AF_INET;
	if (inet_pton(af, a, buf) != 1)
		return (false);
	if (sl == NULL)
		return (true);
	bits = strtol(sl, &end, 10);
	return (*sl != '\0' && *end == '\0' && bits >= 0 && bits <= (af ==
	    AF_INET ? 32 : 128));
}

/*
 * A domain: labels of letters, digits and -, a dot between them; one
 * leading dot let be (".example.org" as it is often written).
 */
static bool
domain_ok(const char *s)
{
	size_t	i;

	if (s != NULL && s[0] == '.')
		s++;
	if (s == NULL || s[0] == '\0' || strlen(s) > 253 || s[0] == '.' ||
	    s[0] == '-' || s[strlen(s) - 1] == '.' || s[strlen(s) - 1] ==
	    '-' || strstr(s, "..") != NULL)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '-' && s[i] != '.')
			return (false);
	return (true);
}

/* An IPv4 address as a number, and back. */
static uint32_t
v4num(const uint8_t *a)
{

	return ((uint32_t)a[0] << 24 | (uint32_t)a[1] << 16 | (uint32_t)a[2] <<
	    8 | a[3]);
}

static const char *
v4str(uint32_t n, char *buf, size_t len)
{

	snprintf(buf, len, "%u.%u.%u.%u", n >> 24, (n >> 16) & 255, (n >> 8) &
	    255, n & 255);
	return (buf);
}

/* ---- dnsmasq: DHCP at the UNIs (MEF 70.2 §11.4, §11.5) ---------------- */

/*
 * The IPv4 ranges dnsmasq gives out at a UNI: the subnet's hosts, less
 * the provider's addresses and the reserved prefixes (§11.4), as
 * dhcp-range lines.
 */
static void
dhcp_ranges4(FILE *b, const ucl_object_t *v, const char *tag)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct net		 n, r;
	uint32_t		 lo, hi, from, to, x[66][2], t;
	const char		*lease;
	char			 s1[20], s2[20], mask[20];
	int			 nx = 0, i, k;

	if (!net_parse(sstr(v, "prefix"), &n) || n.af != AF_INET || n.len > 30)
		return;
	lo = v4num(n.a) & (n.len == 0 ? 0 : 0xffffffffu << (32 - n.len));
	hi = lo | (n.len == 0 ? 0xffffffffu : 0xffffffffu >> n.len);
	lease = sstr(v, "lease") != NULL ? sstr(v, "lease") : "12h";
	/* What is not given: the provider's, the reserved. */
	it = NULL;
	while (nx < 64 && (e = ucl_object_iterate(ucl_object_lookup(v,
	    "provider"), &it, true)) != NULL)
		if (net_parse(ucl_object_tostring_forced(e), &r) && r.af ==
		    AF_INET) {
			x[nx][0] = x[nx][1] = v4num(r.a);
			nx++;
		}
	it = NULL;
	while (nx < 64 && (e = ucl_object_iterate(ucl_object_lookup(v,
	    "reserved"), &it, true)) != NULL)
		if (net_parse(ucl_object_tostring_forced(e), &r) && r.af ==
		    AF_INET) {
			x[nx][0] = v4num(r.a) & (r.len == 0 ? 0 : 0xffffffffu <<
			    (32 - r.len));
			x[nx][1] = x[nx][0] | (r.len == 0 ? 0xffffffffu :
			    0xffffffffu >> r.len);
			nx++;
		}
	/* In order, by the start. */
	for (i = 1; i < nx; i++)
		for (k = i; k > 0 && x[k][0] < x[k - 1][0]; k--) {
			t = x[k][0]; x[k][0] = x[k - 1][0]; x[k - 1][0] = t;
			t = x[k][1]; x[k][1] = x[k - 1][1]; x[k - 1][1] = t;
		}
	v4str(n.len == 0 ? 0 : 0xffffffffu << (32 - n.len), mask, sizeof(mask));
	from = lo + 1;
	to = hi - 1;
	for (i = 0; i <= nx; i++) {
		uint32_t	end = i < nx ? (x[i][0] > 0 ? x[i][0] - 1 : 0) : to;

		if (i == nx || x[i][0] > from) {
			if (end > to)
				end = to;
			if (from <= end && from > lo)
				fprintf(b, "dhcp-range=set:%s,%s,%s,%s,%s\n", tag,
				    v4str(from, s1, sizeof(s1)), v4str(end, s2,
				    sizeof(s2)), mask, lease);
		}
		if (i < nx && x[i][1] + 1 > from)
			from = x[i][1] + 1;
	}
}

/*
 * The IPv6 range at a UNI (§11.5): ::100 to ::ffff of the /64, less a
 * reserved prefix that overlaps it, which splits it, by the low 64 bits.
 */
static void
dhcp_ranges6(FILE *b, const ucl_object_t *v, const char *tag)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct net		 n, r;
	uint64_t		 from, to, x[66][2], t, rlo, rhi;
	const char		*lease;
	char			 pfx[48], s1[64], s2[64];
	int			 nx = 0, i, k;

	if (!net_parse(sstr(v, "prefix"), &n) || n.af != AF_INET6 ||
	    n.len != 64)
		return;
	snprintf(pfx, sizeof(pfx), "%x:%x:%x:%x", n.a[0] << 8 | n.a[1], n.a[2]
	    << 8 | n.a[3], n.a[4] << 8 | n.a[5], n.a[6] << 8 | n.a[7]);
	lease = sstr(v, "lease") != NULL ? sstr(v, "lease") : "12h";
	it = NULL;
	while (nx < 64 && (e = ucl_object_iterate(ucl_object_lookup(v,
	    "reserved"), &it, true)) != NULL) {
		if (!net_parse(ucl_object_tostring_forced(e), &r) || r.af !=
		    AF_INET6 || r.len < 64)
			continue;
		rlo = 0;
		for (k = 8; k < 16; k++)
			rlo = rlo << 8 | r.a[k];
		rlo &= r.len == 128 ? ~(uint64_t)0 : ~(uint64_t)0 << (128 -
		    r.len);
		rhi = rlo | (r.len == 128 ? 0 : ~(uint64_t)0 >> (r.len - 64));
		x[nx][0] = rlo;
		x[nx][1] = rhi;
		nx++;
	}
	for (i = 1; i < nx; i++)
		for (k = i; k > 0 && x[k][0] < x[k - 1][0]; k--) {
			t = x[k][0]; x[k][0] = x[k - 1][0]; x[k - 1][0] = t;
			t = x[k][1]; x[k][1] = x[k - 1][1]; x[k - 1][1] = t;
		}
	from = 0x100;
	to = 0xffff;
	for (i = 0; i <= nx; i++) {
		uint64_t	end = i < nx ? (x[i][0] > 0 ? x[i][0] - 1 : 0) : to;

		if (i == nx || x[i][0] > from) {
			if (end > to)
				end = to;
			if (from <= end) {
				snprintf(s1, sizeof(s1), "%s:%jx:%jx:%jx:%jx", pfx,
				    (uintmax_t)(from >> 48), (uintmax_t)((from >> 32)
				    & 0xffff), (uintmax_t)((from >> 16) & 0xffff),
				    (uintmax_t)(from & 0xffff));
				snprintf(s2, sizeof(s2), "%s:%jx:%jx:%jx:%jx", pfx,
				    (uintmax_t)(end >> 48), (uintmax_t)((end >> 32) &
				    0xffff), (uintmax_t)((end >> 16) & 0xffff),
				    (uintmax_t)(end & 0xffff));
				fprintf(b, "dhcp-range=set:%s,%s,%s,64,%s\n", tag, s1,
				    s2, lease);
			}
		}
		if (i < nx && x[i][1] + 1 > from)
			from = x[i][1] + 1;
	}
}

/*
 * dnsmasq's file for a service at this edge, from its form: the
 * service's "service" and "fib", and its "unis" here, each its "id",
 * its "interface" and its "ipv4" and "ipv6" as the service has them;
 * the families addressed by DHCP served: the ranges, the router (the
 * provider's first address) and the DNS servers told.  No DNS is
 * served here.  NULL and why in *errp when the form is not right.
 */
char *
dhcp_conf_render(struct work *w, const ucl_object_t *spec, const char *host,
    const char **errp)
{
	const ucl_object_t	*u, *v, *a, *e;
	ucl_object_iter_t	 it, ait;
	const char		*ifn;
	FILE			*b;
	char			*buf;
	size_t			 len;
	int			 i;
	bool			 ra = false;

	if (ucl_object_type(spec) != UCL_OBJECT || sstr(spec, "service") ==
	    NULL) {
		*errp = "the form is an object: service, fib and unis";
		return (NULL);
	}
	if (!spec_clean(w, spec, 0, errp))
		return (NULL);
	buf = NULL;
	len = 0;
	if ((b = open_memstream(&buf, &len)) == NULL) {
		*errp = strerror(errno);
		return (NULL);
	}
	fprintf(b, "# Written by arcana-agent for the Arcana console: SD-WAN "
	    "service %s at %s, in routing table %jd.\n# The hosts' addresses at "
	    "the UNIs (MEF 70.2 §11.4, §11.5); no DNS served here.\nport=0\n"
	    "bind-interfaces\nno-resolv\nno-hosts\ndhcp-authoritative\n",
	    sstr(spec, "service"), host, (intmax_t)sint(spec, "fib", 0));
	it = NULL;
	while ((u = ucl_object_iterate(ucl_object_lookup(spec, "unis"), &it,
	    true)) != NULL) {
		if ((ifn = sstr(u, "interface")) == NULL) {
			fclose(b);
			free(buf);
			*errp = wfmt(w, "UNI %s: no interface", sval(u, "id"));
			return (NULL);
		}
		for (i = 0; i < 2; i++) {
			v = ucl_object_lookup(u, i == 0 ? "ipv4" : "ipv6");
			if (strcmp(sval(v, "mode"), "dhcp") != 0)
				continue;
			fprintf(b, "\n# UNI %s, %s\ninterface=%s\n", sval(u, "id"),
			    sval(v, "prefix"), ifn);
			if (i == 0) {
				dhcp_ranges4(b, v, ifn);
				/* Their router: the provider's first address. */
				a = nth(ucl_object_lookup(v, "provider"), 0);
				if (a != NULL)
					fprintf(b, "dhcp-option=tag:%s,option:router,"
					    "%s\n", ifn, ucl_object_tostring_forced(a));
			} else {
				dhcp_ranges6(b, v, ifn);
				ra = true;
			}
			/* The DNS servers told to the hosts, one line. */
			if (ucl_array_size(ucl_object_lookup(v, "dns")) > 0) {
				fprintf(b, "dhcp-option=tag:%s,option%s:dns-server",
				    ifn, i == 0 ? "" : "6");
				ait = NULL;
				while ((e = ucl_object_iterate(ucl_object_lookup(v,
				    "dns"), &ait, true)) != NULL)
					fprintf(b, ",%s%s%s", i == 0 ? "" : "[",
					    ucl_object_tostring_forced(e), i == 0 ?
					    "" : "]");
				fprintf(b, "\n");
			}
		}
	}
	if (ra)
		fprintf(b, "\n# IPv6: the hosts told by router advertisements to "
		    "ask (M flag)\nenable-ra\n");
	return (closed(w, b, &buf, errp));
}

/* ---- The function policies (MEF 138) ---------------------------------- */

/* The order of a function policy's lists: equal entries go to Block
 * (MEF 138 §6.1.6 leaves it), Quarantine blocks too (§6.1.3). */
static const char *const sfl[] = { "block", "quarantine", "allow" };

/*
 * The strings of a function policy's list: its own where own says (the
 * policy's entries), then the named lists' as the console resolved them
 * ("listed"); into out.
 */
static void
sfp_strings(const ucl_object_t *f, const char *list, bool own,
    ucl_object_t *out)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while (own && (e = ucl_object_iterate(ucl_object_lookup(f, list), &it,
	    true)) != NULL)
		if (ucl_object_type(e) == UCL_STRING)
			ucl_array_append(out, ucl_object_copy(e));
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(ucl_object_lookup(f,
	    "listed"), list), &it, true)) != NULL)
		ucl_array_append(out, ucl_object_fromstring(
		    ucl_object_tostring_forced(e)));
}

/* Whether a function policy tells the matches of a list (R20; Block
 * and Quarantine where it does not say, R21). */
static bool
sfp_notifies(const ucl_object_t *f, const char *list)
{
	const ucl_object_t	*n, *e;
	ucl_object_iter_t	 it;

	if ((n = ucl_object_lookup(f, "notify")) == NULL)
		return (strcmp(list, "allow") != 0);
	it = NULL;
	while ((e = ucl_object_iterate(n, &it, true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(e), list) == 0)
			return (true);
	return (false);
}

/* A zone of a form: its name an identifier, its prefixes addresses. */
static bool
zone_ok(struct work *w, const ucl_object_t *z, const char **errp)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	if (!ident_ok(sstr(z, "name"))) {
		*errp = "a zone is named by letters, digits and _";
		return (false);
	}
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(z, "prefixes"), &it,
	    true)) != NULL)
		if (!prefix_ok(ucl_object_tostring_forced(e))) {
			*errp = wfmt(w, "zone %s: %.64s is not a prefix",
			    sstr(z, "name"), ucl_object_tostring_forced(e));
			return (false);
		}
	return (true);
}

/* ---- unbound: DNS filtering and protective DNS ------------------------- */

/* A PDNS entry's type, or none. */
static bool
pdns_type(const ucl_object_t *e, const char *t)
{

	return (sstr(e, "type") != NULL && strcmp(sstr(e, "type"), t) == 0);
}

/* Whether a name filter's entry has a * inside the name (host.*.tld,
 * R71): unbound, which takes a leading *. alone, has none of it; the
 * zone's Squid takes it (squid_dnf). */
static bool
dnf_inner(const char *s)
{

	return (s != NULL && strchr(strncmp(s, "*.", 2) == 0 ? s + 2 : s, '*')
	    != NULL);
}

/*
 * An address or a prefix as an RPZ trigger's owner names it: the
 * length, then the address backwards, an IPv4 address's bytes, an IPv6
 * address's eight groups; into buf, false when it is neither.
 */
static bool
rpz_ip(const char *s, char *buf, size_t len)
{
	char		 a[64], *slash;
	uint8_t		 b[16];
	int		 plen, i;
	size_t		 o;

	snprintf(a, sizeof(a), "%s", s);
	plen = -1;
	if ((slash = strchr(a, '/')) != NULL) {
		*slash = '\0';
		plen = (int)strtol(slash + 1, NULL, 10);
	}
	if (inet_pton(AF_INET, a, b) == 1) {
		snprintf(buf, len, "%d.%u.%u.%u.%u", plen < 0 ? 32 : plen, b[3],
		    b[2], b[1], b[0]);
		return (true);
	}
	if (inet_pton(AF_INET6, a, b) != 1)
		return (false);
	o = (size_t)snprintf(buf, len, "%d", plen < 0 ? 128 : plen);
	for (i = 14; i >= 0 && o < len; i -= 2)
		o += (size_t)snprintf(buf + o, len - o, ".%x", (unsigned)(b[i] <<
		    8 | b[i + 1]));
	return (true);
}

/*
 * A zone's PDNS entries that unbound's RPZ takes (R104): a CNAME's,
 * the name an alias leads to (a QNAME trigger, which unbound applies to
 * each name of an answer's chain); an NS's, the name server's name
 * (rpz-nsdname) or address (rpz-nsip).  Block and Quarantine answer
 * NXDOMAIN, Allow passes, each name once, the first list winning.  The
 * zone file's text; NULL when it has none.
 */
static char *
rpz_zone(struct work *w, const ucl_object_t *pd, const char *zn,
    const char **errp)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*seen;
	char			 own[300], ip[80], *buf;
	const char		*v;
	FILE			*b;
	size_t			 len;
	bool			 any;
	int			 k;

	buf = NULL;
	len = 0;
	if ((b = open_memstream(&buf, &len)) == NULL) {
		*errp = strerror(errno);
		return (NULL);
	}
	any = false;
	seen = ucl_object_typed_new(UCL_OBJECT);
	fprintf(b, "$ORIGIN %s.rpz.\n@ 3600 SOA localhost. nobody.localhost. 1 "
	    "3600 600 86400 60\n@ 3600 NS localhost.\n", zn);
	for (k = 0; k < 3; k++) {
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(pd, sfl[k]),
		    &it, true)) != NULL) {
			if ((v = sstr(e, "value")) == NULL)
				continue;
			if (pdns_type(e, "CNAME") && domain_ok(strncmp(v, "*.", 2)
			    == 0 ? v + 2 : v))
				snprintf(own, sizeof(own), "%s", v);
			else if (pdns_type(e, "NS") && rpz_ip(v, ip, sizeof(ip)))
				snprintf(own, sizeof(own), "%s.rpz-nsip", ip);
			else if (pdns_type(e, "NS") && domain_ok(v))
				snprintf(own, sizeof(own), "%s.rpz-nsdname", v);
			else
				continue;
			if (ucl_object_lookup(seen, own) != NULL)
				continue;
			ucl_object_insert_key(seen, ucl_object_frombool(true), own,
			    0, true);
			fprintf(b, "%s CNAME %s\n", own, k == 2 ? "rpz-passthru." :
			    ".");
			any = true;
		}
	}
	ucl_object_unref(seen);
	if (!any) {
		fclose(b);
		free(buf);
		return (NULL);
	}
	return (closed(w, b, &buf, errp));
}

/* A server unbound sends its questions to: address[@port][#name], the
 * name the one its certificate has (DNS over TLS). */
static bool
upstream_ok(const char *s)
{
	char		 a[64];
	const char	*at, *hash, *end;
	long		 port;
	char		*pe;

	if (s == NULL || strlen(s) > 300)
		return (false);
	hash = strchr(s, '#');
	at = strchr(s, '@');
	if (at != NULL && hash != NULL && at > hash)
		return (false);
	end = at != NULL ? at : hash != NULL ? hash : s + strlen(s);
	if ((size_t)(end - s) >= sizeof(a))
		return (false);
	snprintf(a, sizeof(a), "%.*s", (int)(end - s), s);
	if (!addr_ok(a))
		return (false);
	if (at != NULL) {
		port = strtol(at + 1, &pe, 10);
		if (pe == at + 1 || port < 1 || port > 65535 || (*pe != '\0' &&
		    *pe != '#'))
			return (false);
	}
	return (hash == NULL || domain_ok(hash + 1));
}

/*
 * unbound's file for a service at this edge, from its form: the
 * service's "service" and "fib"; its "unis" here, each its "id", the
 * provider's "address" it listens on and the "prefix" it answers; its
 * "zones" with a DNF or PDNS, each its "name", its "prefixes" here and
 * its function policies ("dnf", "pdns") as the service has them, the
 * named lists' entries "listed"; "dot", whether it serves DNS over TLS
 * on port 853 too (D22), with the key and certificate at p's; its
 * "upstream" servers, where it sends its questions instead of
 * resolving by itself, over TLS where "upstream_tls" says (D21).  It
 * serves each zone by a view of its own (access-control-view by the
 * zone's prefixes): the DNF's domains as local zones, Block and
 * Quarantine always_nxdomain and Allow always_transparent, each with
 * the names beneath it, the most specific deciding as unbound has it,
 * the root's where its No-match blocks (a name with a * inside is the
 * Squid's); the PDNS's A and AAAA answers by response-ip (respip), its
 * CNAME and NS entries by a response policy zone of the zone's (RPZ,
 * tagged with the zone's prefixes), whose texts go into rpz, names to
 * texts, each at p->rpz_pre and its name.
 */
char *
dns_conf_render(struct work *w, const ucl_object_t *spec, const char *host,
    const struct dnspaths *p, ucl_object_t *rpz, const char **errp)
{
	static const char *const zt[] = { "always_nxdomain",
	    "always_nxdomain", "always_transparent" };
	const ucl_object_t	*u, *zone, *df, *pd, *e;
	ucl_object_iter_t	 it, zit;
	ucl_object_t		*seen, *names;
	const char		*val, *n;
	FILE			*b, *t;
	char			*buf, *tb, *zt_text;
	size_t			 len, tl;
	bool			 logit = false, dot;
	int			 k;

	if (ucl_object_type(spec) != UCL_OBJECT || sstr(spec, "service") ==
	    NULL) {
		*errp = "the form is an object: service, fib, unis and zones";
		return (NULL);
	}
	if (!spec_clean(w, spec, 0, errp))
		return (NULL);
	zit = NULL;
	while ((zone = ucl_object_iterate(ucl_object_lookup(spec, "zones"),
	    &zit, true)) != NULL)
		if (!zone_ok(w, zone, errp))
			return (NULL);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(spec, "upstream"),
	    &it, true)) != NULL)
		if (ucl_object_type(e) != UCL_STRING || !upstream_ok(
		    ucl_object_tostring(e))) {
			*errp = "upstream: each a server, address[@port][#name]";
			return (NULL);
		}
	dot = sflag(spec, "dot");
	buf = NULL;
	len = 0;
	if ((b = open_memstream(&buf, &len)) == NULL) {
		*errp = strerror(errno);
		return (NULL);
	}
	fprintf(b, "# Written by arcana-agent for the Arcana console: SD-WAN "
	    "service %s at %s, in routing table %jd.\n# The DNS filtering and "
	    "protective DNS of its zones (MEF 138), by the base system's "
	    "unbound.\nserver:\n\tverbosity: 0\n\tdo-daemonize: yes\n\t"
	    "module-config: \"respip iterator\"\n\tdo-not-query-localhost: no\n",
	    sstr(spec, "service"), host, (intmax_t)sint(spec, "fib", 0));
	it = NULL;
	while ((u = ucl_object_iterate(ucl_object_lookup(spec, "unis"), &it,
	    true)) != NULL) {
		fprintf(b, "\t# UNI %s\n\tinterface: %s\n\taccess-control: %s "
		    "allow\n", sval(u, "id"), sval(u, "address"), sval(u,
		    "prefix"));
		if (dot)
			fprintf(b, "\tinterface: %s@853\n", sval(u, "address"));
	}
	if (dot)
		fprintf(b, "\ttls-port: 853\n\ttls-service-key: \"%s\"\n"
		    "\ttls-service-pem: \"%s\"\n", p->tlskey, p->tlspem);
	if (sflag(spec, "upstream_tls"))
		fprintf(b, "\ttls-cert-bundle: \"/etc/ssl/cert.pem\"\n");
	/* The zones whose PDNS has entries for RPZ, each a tag of its
	 * own: defined before the prefixes are given them. */
	tb = NULL;
	if ((t = open_memstream(&tb, &tl)) == NULL) {
		fclose(b);
		free(buf);
		*errp = strerror(errno);
		return (NULL);
	}
	zit = NULL;
	while ((zone = ucl_object_iterate(ucl_object_lookup(spec, "zones"),
	    &zit, true)) != NULL) {
		if ((pd = ucl_object_lookup(zone, "pdns")) == NULL)
			continue;
		if ((zt_text = rpz_zone(w, pd, sstr(zone, "name"), errp)) == NULL)
			continue;
		ucl_object_insert_key(rpz, ucl_object_fromstring(zt_text),
		    sstr(zone, "name"), 0, true);
		fprintf(t, "%s%s", ftell(t) > 0 ? " " : "", sstr(zone, "name"));
	}
	fclose(t);
	if (tb != NULL && tb[0] != '\0')
		fprintf(b, "\tdefine-tag: \"%s\"\n", tb);
	free(tb);
	/* The zones' views: whose prefixes are whose. */
	zit = NULL;
	while ((zone = ucl_object_iterate(ucl_object_lookup(spec, "zones"),
	    &zit, true)) != NULL) {
		df = ucl_object_lookup(zone, "dnf");
		pd = ucl_object_lookup(zone, "pdns");
		for (k = 0; k < 3; k++)
			if ((df != NULL && sfp_notifies(df, sfl[k])) || (pd !=
			    NULL && sfp_notifies(pd, sfl[k])))
				logit = true;
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(zone,
		    "prefixes"), &it, true)) != NULL) {
			fprintf(b, "\taccess-control-view: %s %s\n",
			    ucl_object_tostring_forced(e), sstr(zone, "name"));
			if (ucl_object_lookup(rpz, sstr(zone, "name")) != NULL)
				fprintf(b, "\taccess-control-tag: %s \"%s\"\n",
				    ucl_object_tostring_forced(e), sstr(zone,
				    "name"));
		}
	}
	/* Told, where a zone's DNF or PDNS says so: into unbound's log. */
	if (logit)
		fprintf(b, "\tlog-local-actions: yes\n\tlog-servfail: yes\n");
	zit = NULL;
	while ((zone = ucl_object_iterate(ucl_object_lookup(spec, "zones"),
	    &zit, true)) != NULL) {
		df = ucl_object_lookup(zone, "dnf");
		pd = ucl_object_lookup(zone, "pdns");
		fprintf(b, "view:\n\tname: \"%s\"\n\tview-first: yes\n",
		    sstr(zone, "name"));
		/* DNF: each name once, the first list (Block) winning. */
		seen = ucl_object_typed_new(UCL_OBJECT);
		if (df != NULL && strcmp(sval(df, "no-match"), "block") == 0)
			fprintf(b, "\tlocal-zone: \".\" always_nxdomain\n");
		for (k = 0; df != NULL && k < 3; k++) {
			names = ucl_object_typed_new(UCL_ARRAY);
			sfp_strings(df, sfl[k], true, names);
			it = NULL;
			while ((e = ucl_object_iterate(names, &it, true)) != NULL) {
				n = ucl_object_tostring(e);
				if (dnf_inner(n))
					continue;	/* Squid's */
				if (strncmp(n, "*.", 2) == 0)
					n += 2;
				if (ucl_object_lookup(seen, n) != NULL)
					continue;
				ucl_object_insert_key(seen, ucl_object_frombool(
				    true), n, 0, true);
				fprintf(b, "\tlocal-zone: \"%s.\" %s\n", n, zt[k]);
			}
			ucl_object_unref(names);
		}
		ucl_object_unref(seen);
		/* PDNS: the answers' addresses; its lists' prefixes too. */
		if (pd != NULL && strcmp(sval(pd, "no-match"), "block") == 0)
			fprintf(b, "\tresponse-ip: 0.0.0.0/0 always_nxdomain\n"
			    "\tresponse-ip: ::/0 always_nxdomain\n");
		seen = ucl_object_typed_new(UCL_OBJECT);
		for (k = 0; pd != NULL && k < 3; k++) {
			names = ucl_object_typed_new(UCL_ARRAY);
			it = NULL;
			while ((e = ucl_object_iterate(ucl_object_lookup(pd,
			    sfl[k]), &it, true)) != NULL) {
				if (!pdns_type(e, "A") && !pdns_type(e, "AAAA"))
					continue;
				val = sstr(e, "value");
				if (val != NULL && strcmp(val, "any") == 0)
					val = strcmp(sval(e, "type"), "A") == 0 ?
					    "0.0.0.0/0" : "::/0";
				if (val != NULL)
					ucl_array_append(names,
					    ucl_object_fromstring(val));
			}
			sfp_strings(pd, sfl[k], false, names);
			it = NULL;
			while ((e = ucl_object_iterate(names, &it, true)) != NULL) {
				n = ucl_object_tostring(e);
				if (ucl_object_lookup(seen, n) != NULL)
					continue;
				ucl_object_insert_key(seen, ucl_object_frombool(
				    true), n, 0, true);
				fprintf(b, "\tresponse-ip: %s%s %s\n", n, strchr(n,
				    '/') == NULL ? (strchr(n, ':') != NULL ? "/128" :
				    "/32") : "", zt[k]);
			}
			ucl_object_unref(names);
		}
		ucl_object_unref(seen);
	}
	/* The zones' response policy zones, each for its tag alone. */
	it = NULL;
	while ((e = ucl_object_iterate(rpz, &it, true)) != NULL)
		fprintf(b, "rpz:\n\tname: \"%s.rpz.\"\n\tzonefile: \"%s%s\"\n\ttags: "
		    "\"%s\"\n%s", ucl_object_key(e), p->rpz_pre, ucl_object_key(e),
		    ucl_object_key(e), logit ? "\trpz-log: yes\n" : "");
	/* The servers it asks, where the form names them: over TLS on port
	 * 853 unless one says another, each checked by its name. */
	if (ucl_array_size(ucl_object_lookup(spec, "upstream")) > 0) {
		dot = sflag(spec, "upstream_tls");
		fprintf(b, "forward-zone:\n\tname: \".\"\n%s", dot ?
		    "\tforward-tls-upstream: yes\n" : "");
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(spec, "upstream"),
		    &it, true)) != NULL) {
			n = ucl_object_tostring_forced(e);
			if (dot && strchr(n, '@') == NULL)
				fprintf(b, "\tforward-addr: %.*s@853%s\n", (int)strcspn(
				    n, "#"), n, n + strcspn(n, "#"));
			else
				fprintf(b, "\tforward-addr: %s\n", n);
		}
	}
	return (closed(w, b, &buf, errp));
}

/* ---- Squid: URL filtering, the middlebox, malware scanning ------------- */

/*
 * How specific a URL filter's entry is (MEF 138 §6.1.6: the more
 * specific overrules): a path over a host alone, a longer one over a
 * shorter, a host over *. and one, a longer name over a shorter.
 */
static int
url_specific(const char *s, const char **hostp, size_t *hlenp,
    const char **pathp)
{
	const char	*sl;
	int		 n;

	if (strncmp(s, "http://", 7) == 0)
		s += 7;
	else if (strncmp(s, "https://", 8) == 0)
		s += 8;
	sl = strchr(s, '/');
	*hostp = s;
	*hlenp = sl != NULL ? (size_t)(sl - s) : strlen(s);
	*pathp = sl;
	n = (int)*hlenp + (strncmp(s, "*.", 2) == 0 ? 0 : 300);
	if (sl != NULL)
		n += 1000 + (int)strlen(sl) * 2 - (sl[strlen(sl) - 1] == '*' ?
		    1 : 0);
	return (n);
}

struct uentry {
	const char	*s;
	int		 list;	/* 0 block, 1 quarantine, 2 allow (sfl) */
	int		 spec;
	int		 at;	/* its place, for a stable order */
};

static int
uentry_cmp(const void *a, const void *b)
{
	const struct uentry	*x = a, *y = b;

	if (x->spec != y->spec)
		return (y->spec - x->spec);
	if (x->list != y->list)
		return (x->list - y->list);
	return (x->at - y->at);
}

/* A host as Squid's dstdomain and ssl::server_name take it: *.host as
 * .host, the host and the names beneath it. */
static void
squid_host(FILE *b, const char *h, size_t n)
{

	if (n > 2 && strncmp(h, "*.", 2) == 0)
		fprintf(b, " .%.*s", (int)(n - 2), h + 2);
	else
		fprintf(b, " %.*s", (int)n, h);
}

/* A name with a * inside as a regex of Squid's: each * a whole label,
 * the names beneath it too, anchored. */
static void
squid_wild(FILE *b, const char *s)
{

	if (strncmp(s, "*.", 2) == 0)
		s += 2;
	fprintf(b, " ^(.+\\.)?");
	for (; *s != '\0'; s++) {
		if (*s == '*')
			fprintf(b, "[^.]+");
		else if (*s == '.')
			fprintf(b, "\\.");
		else if (isalnum((unsigned char)*s) || *s == '-' || *s == '_')
			fputc(*s, b);
	}
	fprintf(b, "$");
}

/* A host and a path as Squid's url_regex takes it, anchored, its *
 * anything, both schemes. */
static void
squid_regex(FILE *b, const char *h, size_t n, const char *path)
{
	const char	*p;

	fprintf(b, " ^https?://");
	if (n > 2 && strncmp(h, "*.", 2) == 0) {
		fprintf(b, "([^/]*\\.)?");
		h += 2;
		n -= 2;
	}
	for (; n > 0; h++, n--)
		fprintf(b, "%s%c", *h == '.' ? "\\" : "", *h);
	for (p = path; *p != '\0'; p++) {
		if (*p == '*')
			fprintf(b, ".*");
		else if (strchr(".+?()[]{}|^$\\", *p) != NULL)
			fprintf(b, "\\%c", *p);
		else
			fprintf(b, "%c", *p);
	}
	if (path[0] != '\0' && path[strlen(path) - 1] != '*')
		fprintf(b, "$");
}

/* The lowest TLS version an MBSF lets through: above every one it
 * blocks, and those on no list where its No-match blocks (Table 9). */
static int
mbsf_min(const ucl_object_t *f)
{
	static const char *const v[] = { "ssl3", "tls1.0", "tls1.1", "tls1.2",
	    "tls1.3" };
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int			 i, min = 0;
	bool			 listed;

	for (i = 0; i < (int)nitems(v); i++) {
		listed = false;
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(f, "allow"),
		    &it, true)) != NULL)
			if (strcmp(ucl_object_tostring_forced(e), v[i]) == 0)
				listed = true;
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(f, "block"),
		    &it, true)) != NULL)
			if (strcmp(ucl_object_tostring_forced(e), v[i]) == 0)
				min = i + 1;
		if (!listed && strcmp(sval(f, "no-match"), "block") == 0)
			min = i + 1 > min ? i + 1 : min;
	}
	return (min);
}

/* A text of three streams, the three closed and joined: the head, the
 * TLS steps, the requests' rules. */
struct sqbuf {
	FILE	*fp;
	char	*buf;
	size_t	 len;
};

static bool
sq_open(struct sqbuf *s)
{

	s->buf = NULL;
	s->len = 0;
	return ((s->fp = open_memstream(&s->buf, &s->len)) != NULL);
}

static void
sq_close(struct sqbuf *s)
{

	if (s->fp != NULL)
		fclose(s->fp);
	s->fp = NULL;
	free(s->buf);
	s->buf = NULL;
}

/*
 * A zone's URL filter: its entries most specific first, a run of the
 * same list one acl; the hosts at the TLS name (where TLS is not
 * opened) and in the requests, the paths in the requests; then the
 * named lists the console resolved, files of the instance's (Allow,
 * then Block and Quarantine together).
 */
static void
squid_urlf(FILE *b, FILE *sb, FILE *hb, const char *zn,
    const ucl_object_t *uf, bool mb, const ucl_object_t *lists,
    const struct sqpaths *p)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct uentry		*ue;
	const char		*host, *path;
	char			*tb, an[48], ln[48];
	size_t			 tl, hlen, nue, i, j, k;
	FILE			*t;
	int			 acl;
	bool			 anyhost, anypath;

	nue = ucl_array_size(ucl_object_lookup(uf, "block")) + ucl_array_size(
	    ucl_object_lookup(uf, "quarantine")) + ucl_array_size(
	    ucl_object_lookup(uf, "allow"));
	ue = calloc(nue + 1, sizeof(*ue));
	for (i = k = 0; ue != NULL && k < 3; k++) {
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(uf, sfl[k]), &it,
		    true)) != NULL && i < nue) {
			if (ucl_object_type(e) != UCL_STRING)
				continue;
			ue[i].s = ucl_object_tostring(e);
			ue[i].list = (int)k;
			ue[i].spec = url_specific(ue[i].s, &host, &hlen, &path);
			ue[i].at = (int)i;
			i++;
		}
	}
	nue = ue != NULL ? i : 0;
	if (nue > 0)
		qsort(ue, nue, sizeof(*ue), uentry_cmp);
	acl = 0;
	for (i = 0; i < nue; i = j) {
		for (j = i; j < nue && (ue[j].list != 2) == (ue[i].list != 2); j++)
			;
		/* Hosts at the TLS name; hosts and paths in the requests. */
		anyhost = false;
		tb = NULL;
		if ((t = open_memstream(&tb, &tl)) == NULL)
			break;
		for (k = i; k < j; k++) {
			(void)url_specific(ue[k].s, &host, &hlen, &path);
			if (path == NULL) {
				squid_host(t, host, hlen);
				anyhost = true;
			}
		}
		fclose(t);
		if (anyhost) {
			snprintf(an, sizeof(an), "%s_u%d", zn, acl++);
			if (!mb)
				fprintf(b, "acl %s_n ssl::server_name%s\n", an, tb);
			fprintf(b, "acl %s_d dstdomain%s\n", an, tb);
			if (!mb)
				fprintf(sb, "ssl_bump %s %s %s_n\n", ue[i].list == 2 ?
				    "splice" : "terminate", zn, an);
			fprintf(hb, "http_access %s %s %s_d\n", ue[i].list == 2 ?
			    "allow" : "deny", zn, an);
		}
		free(tb);
		anypath = false;
		tb = NULL;
		if ((t = open_memstream(&tb, &tl)) == NULL)
			break;
		for (k = i; k < j; k++) {
			(void)url_specific(ue[k].s, &host, &hlen, &path);
			if (path != NULL) {
				squid_regex(t, host, hlen, path);
				anypath = true;
			}
		}
		fclose(t);
		if (anypath) {
			snprintf(an, sizeof(an), "%s_u%d", zn, acl++);
			fprintf(b, "acl %s_r url_regex -i%s\n", an, tb);
			fprintf(hb, "http_access %s %s %s_r\n", ue[i].list == 2 ?
			    "allow" : "deny", zn, an);
		}
		free(tb);
	}
	free(ue);
	/* The named lists: Allow, then Block and Quarantine together, each
	 * a file the console sent (lists, "<zone>-allow", "<zone>-block"). */
	for (k = 0; k < 2; k++) {
		const char	*kind = k == 0 ? "allow" : "block";

		snprintf(ln, sizeof(ln), "%s-%s", zn, kind);
		if (ucl_object_lookup(lists, ln) == NULL)
			continue;
		if (!mb)
			fprintf(b, "acl %s_f%s_n ssl::server_name \"%s%s%s\"\n", zn,
			    kind, p->list_pre, ln, p->list_suf);
		fprintf(b, "acl %s_f%s_d dstdomain \"%s%s%s\"\n", zn, kind,
		    p->list_pre, ln, p->list_suf);
		if (!mb)
			fprintf(sb, "ssl_bump %s %s %s_f%s_n\n", k == 0 ? "splice" :
			    "terminate", zn, zn, kind);
		fprintf(hb, "http_access %s %s %s_f%s_d\n", k == 0 ? "allow" :
		    "deny", zn, zn, kind);
	}
}

/*
 * Squid's file for an SD-WAN service at this edge (MEF 138's URLF, MBSF
 * and MD+R), from its form: the service's "service" and "fib"; where
 * it is reached ("listen", each a UNI's or remote end point's
 * "end_point" and its own IPv4 "address"); "resolver", true where the
 * service has its resolver here; "icap", true where a zone's MD+R
 * scans; its "zones", Default last, each its "name", "default" for
 * Default, its "prefixes" here and its function policies ("urlf",
 * "mbsf", "mdr") as the service has them.  It takes what ipfw forwards
 * to it from the zones that have them, on each address, ports 3128
 * (HTTP) and 3129 (TLS), and decides by zone (src).  Where the zone's
 * MBSF opens TLS, all of it is opened (bump) but the hosts its
 * pass-through names, and each request decided by host and path, the
 * URLF's entries most specific first, so that an Allow of a path
 * overrules the Block of its host; elsewhere the TLS name is looked at
 * (peek) and the connection ended (terminate) or let through unopened
 * (splice) by the entries' hosts, as cleartext HTTP's requests are.
 * The named lists are files of the instance's, and the No-match last.
 */
static char *
squid_sdwan(struct work *w, const ucl_object_t *spec, const char *host,
    const ucl_object_t *lists, const struct sqpaths *p, const char **errp)
{
	struct sqbuf		 b = { 0 }, sb = { 0 }, hb = { 0 };
	const ucl_object_t	*o, *zone, *uf, *mb, *md, *dw, *e, *first;
	ucl_object_iter_t	 it, zit;
	const char		*own, *zn;
	char			*out, *tb;
	size_t			 tl;
	FILE			*t;
	int			 tlsmin;
	intmax_t		 fib;

	if (sstr(spec, "service") == NULL) {
		*errp = "the form is an object: service, fib, listen and zones";
		return (NULL);
	}
	zit = NULL;
	while ((zone = ucl_object_iterate(ucl_object_lookup(spec, "zones"),
	    &zit, true)) != NULL)
		if (!zone_ok(w, zone, errp))
			return (NULL);
	it = NULL;
	while ((o = ucl_object_iterate(ucl_object_lookup(spec, "listen"), &it,
	    true)) != NULL)
		if (!addr_ok(sstr(o, "address"))) {
			*errp = "listen: each an end point and its address";
			return (NULL);
		}
	fib = (intmax_t)sint(spec, "fib", 0);
	if (!sq_open(&b) || !sq_open(&sb) || !sq_open(&hb)) {
		sq_close(&b);
		sq_close(&sb);
		sq_close(&hb);
		*errp = strerror(errno);
		return (NULL);
	}
	fprintf(b.fp, "# Written by arcana-agent for the Arcana console: SD-WAN "
	    "service %s at %s, in routing table %jd.\n# The URL filtering, "
	    "middlebox and malware scanning of its zones (MEF 138), by Squid.\n"
	    "pid_filename %s\naccess_log /var/log/squid/sdwan-sw%jd-access.log\n"
	    "cache_log /var/log/squid/sdwan-sw%jd-cache.log\ncache deny all\n"
	    "visible_hostname sdwan-sw%jd\n", sstr(spec, "service"), host, fib,
	    p->pid, fib, fib, fib);
	/* The oldest TLS let through: the strictest zone's MBSF. */
	tlsmin = 0;
	zit = NULL;
	while ((zone = ucl_object_iterate(ucl_object_lookup(spec, "zones"),
	    &zit, true)) != NULL)
		if ((mb = ucl_object_lookup(zone, "mbsf")) != NULL && mbsf_min(mb)
		    > tlsmin)
			tlsmin = mbsf_min(mb);
	it = NULL;
	while ((o = ucl_object_iterate(ucl_object_lookup(spec, "listen"), &it,
	    true)) != NULL) {
		fprintf(b.fp, "# %s\nhttp_port %s:3128 intercept\nhttps_port "
		    "%s:3129 intercept ssl-bump tls-cert=%s "
		    "generate-host-certificates=on dynamic_cert_mem_cache_size=4MB",
		    sval(o, "end_point"), sstr(o, "address"), sstr(o, "address"),
		    p->ca);
		if (tlsmin > 1)
			fprintf(b.fp, " tls-min-version=1.%d", tlsmin - 1);
		fprintf(b.fp, "\n");
	}
	if (tlsmin > 1)
		fprintf(b.fp, "tls_outgoing_options min-version=1.%d\n",
		    tlsmin - 1);
	/* The names it is asked for, resolved by the service's resolver
	 * where there is one, else by the edge's own. */
	first = nth(ucl_object_lookup(spec, "listen"), 0);
	if (sflag(spec, "resolver") && first != NULL)
		fprintf(b.fp, "dns_nameservers %s\n", sstr(first, "address"));
	own = first != NULL ? sstr(first, "address") : "127.0.0.1";
	fprintf(b.fp, "sslcrtd_program %s -s %s -M 4MB\nsslcrtd_children 3\n"
	    "acl step1 at_step SslBump1\nacl plain localport 3128\n", p->certgen,
	    p->ssldb);
	if (sflag(spec, "icap"))
		fprintf(b.fp, "icap_enable on\nicap_send_client_ip on\n"
		    "icap_service sdwan_av respmod_precache bypass=off "
		    "icap://%s:%d/avscan\n", own, SDWAN_ICAP_PORT(fib));
	fprintf(sb.fp, "ssl_bump peek step1\n");
	/* Each zone with any of them, as the console ordered them. */
	zit = NULL;
	while ((zone = ucl_object_iterate(ucl_object_lookup(spec, "zones"),
	    &zit, true)) != NULL) {
		zn = sstr(zone, "name");
		uf = ucl_object_lookup(zone, "urlf");
		mb = ucl_object_lookup(zone, "mbsf");
		md = ucl_object_lookup(zone, "mdr");
		dw = ucl_object_lookup(zone, "dnf");
		if (uf == NULL && mb == NULL && md == NULL && dw == NULL)
			continue;
		fprintf(b.fp, "acl %s src", zn);
		/* Default is all, as Squid will have it said. */
		it = NULL;
		while (!sflag(zone, "default") && (e = ucl_object_iterate(
		    ucl_object_lookup(zone, "prefixes"), &it, true)) != NULL)
			fprintf(b.fp, " %s", ucl_object_tostring_forced(e));
		if (sflag(zone, "default"))
			fprintf(b.fp, " all");
		else if (ucl_array_size(ucl_object_lookup(zone, "prefixes")) == 0)
			fprintf(b.fp, " 127.0.0.255/32");	/* none */
		fprintf(b.fp, "\n");
		/* The DNF's names with a * inside (R71), which unbound does
		 * not take: ended at the TLS name, refused by the request's
		 * host, before anything else of the zone's. */
		if (dw != NULL) {
			tb = NULL;
			if ((t = open_memstream(&tb, &tl)) != NULL) {
				it = NULL;
				while ((e = ucl_object_iterate(dw, &it, true)) != NULL)
					squid_wild(t, ucl_object_tostring_forced(e));
				fclose(t);
				if (tb != NULL && tb[0] != '\0') {
					fprintf(b.fp, "acl %s_dw ssl::server_name_regex "
					    "-i%s\nacl %s_dwd dstdom_regex -i%s\n", zn,
					    tb, zn, tb);
					fprintf(sb.fp, "ssl_bump terminate %s %s_dw\n",
					    zn, zn);
					fprintf(hb.fp, "http_access deny %s %s_dwd\n",
					    zn, zn);
				}
				free(tb);
			}
		}
		/* Malware scanned where the zone's MD+R says. */
		if (md != NULL)
			fprintf(hb.fp, "adaptation_access sdwan_av allow %s\n", zn);
		/* MBSF: hosts never opened (Arcana's), the server's
		 * certificate not trusted let through or not, HTTP. */
		if (mb != NULL) {
			tb = NULL;
			if ((t = open_memstream(&tb, &tl)) != NULL) {
				it = NULL;
				while ((e = ucl_object_iterate(ucl_object_lookup(mb,
				    "pass-through"), &it, true)) != NULL)
					squid_host(t, ucl_object_tostring_forced(e),
					    strlen(ucl_object_tostring_forced(e)));
				fclose(t);
				if (tb != NULL && tb[0] != '\0') {
					fprintf(b.fp, "acl %s_pass ssl::server_name"
					    "%s\n", zn, tb);
					fprintf(sb.fp, "ssl_bump splice %s %s_pass\n",
					    zn, zn);
				}
				free(tb);
			}
			if (strcmp(sval(mb, "invalid-server-certificate"),
			    "allow") == 0)
				fprintf(b.fp, "sslproxy_cert_error allow %s\n", zn);
			if (strcmp(sval(mb, "unencrypted"), "block") == 0)
				fprintf(hb.fp, "http_access deny %s plain\n", zn);
		}
		if (uf != NULL)
			squid_urlf(b.fp, sb.fp, hb.fp, zn, uf, mb != NULL, lists, p);
		/* No-match: the URLF's; without one, let on.  Where TLS is
		 * opened, the requests decide. */
		if (uf != NULL && strcmp(sval(uf, "no-match"), "block") == 0) {
			fprintf(sb.fp, "ssl_bump %s %s\n", mb != NULL ? "bump" :
			    "terminate", zn);
			fprintf(hb.fp, "http_access deny %s\n", zn);
		} else {
			fprintf(sb.fp, "ssl_bump %s %s\n", mb != NULL ? "bump" :
			    "splice", zn);
			fprintf(hb.fp, "http_access allow %s\n", zn);
		}
	}
	fprintf(sb.fp, "ssl_bump splice all\n");
	fprintf(hb.fp, "%shttp_access deny all\n", sflag(spec, "icap") ?
	    "adaptation_access sdwan_av deny all\n" : "");
	if (fclose(sb.fp) != 0 || fclose(hb.fp) != 0 || sb.buf == NULL ||
	    hb.buf == NULL) {
		sb.fp = hb.fp = NULL;
		sq_close(&b);
		sq_close(&sb);
		sq_close(&hb);
		*errp = "the configuration could not be written";
		return (NULL);
	}
	sb.fp = hb.fp = NULL;
	fprintf(b.fp, "%s%s", sb.buf, hb.buf);
	sq_close(&sb);
	sq_close(&hb);
	out = closed(w, b.fp, &b.buf, errp);
	return (out);
}

/*
 * Each string of the list at k checked by ok, into fp (which may be
 * NULL), joined by sep, each after pre; false, and why, for one that is
 * not, or for none when one is needed.  ".example.org" as typed is
 * example.org's, not a dot more, where pre is a dot.
 */
static bool
list_of(struct work *w, const ucl_object_t *in, const char *k,
    bool (*ok)(const char *), bool need, FILE *fp, const char *pre,
    const char *sep, const char *what, const char **errp)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int			 n;

	if (ucl_object_lookup(in, k) != NULL && ucl_object_type(
	    ucl_object_lookup(in, k)) != UCL_ARRAY) {
		*errp = wfmt(w, "%s: a list", what);
		return (false);
	}
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, k), &it, true)) !=
	    NULL) {
		if (n == LIST_MAX) {
			*errp = wfmt(w, "%s: %d at most", what, LIST_MAX);
			return (false);
		}
		if (ucl_object_type(e) != UCL_STRING || !ok(ucl_object_tostring(
		    e))) {
			*errp = wfmt(w, "%s: %.64s is not one", what,
			    ucl_object_tostring_forced(e));
			return (false);
		}
		if (fp != NULL)
			fprintf(fp, "%s%s%s", n > 0 ? sep : "", pre,
			    ucl_object_tostring(e) + (strcmp(pre, ".") == 0 &&
			    ucl_object_tostring(e)[0] == '.' ? 1 : 0));
		n++;
	}
	if (need && n == 0) {
		*errp = wfmt(w, "%s: at least one", what);
		return (false);
	}
	return (true);
}

/*
 * The Security section's URL filter, from its form: an explicit proxy
 * the clients are told of, on each address of "listen", its "port"
 * (3128 unless said) with ssl-bump, so that a TLS name is looked at
 * (mode sni) or TLS opened (inspect); "allow" the networks that may use
 * it; "deny" the domains denied with the names beneath them, a file of
 * their own (*denyp); "malware" sends what it fetches to its c-icap.
 */
static char *
squid_security(struct work *w, const ucl_object_t *in, const char *name,
    const char *host, int idx, const struct sqpaths *p, char **denyp,
    const char **errp)
{
	struct sqbuf		 b = { 0 }, d = { 0 };
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*mode;
	int64_t			 fib, port;
	bool			 malware;

	mode = sstr(in, "mode") != NULL ? sstr(in, "mode") : "sni";
	if (strcmp(mode, "sni") != 0 && strcmp(mode, "inspect") != 0) {
		*errp = "mode is sni or inspect";
		return (NULL);
	}
	fib = sint(in, "fib", 0);
	port = sint(in, "port", 3128);
	if (fib < 0 || fib > 65535 || port < 1 || port > 65535) {
		*errp = "fib is a routing table, port 1 to 65535";
		return (NULL);
	}
	if (ucl_object_type(ucl_object_lookup(in, "listen")) != UCL_ARRAY ||
	    ucl_array_size(ucl_object_lookup(in, "listen")) == 0) {
		*errp = "listen: a list of addresses, one at least";
		return (NULL);
	}
	malware = sflag(in, "malware");
	if (!sq_open(&b) || !sq_open(&d)) {
		sq_close(&b);
		sq_close(&d);
		*errp = strerror(errno);
		return (NULL);
	}
	fprintf(b.fp, "# Written by arcana-agent for the Arcana console: the "
	    "Security section's URL filter %s at %s,\n# by Squid, mode %s, in "
	    "routing table %jd.\npid_filename %s\naccess_log /var/log/squid/%s-"
	    "access.log\ncache_log /var/log/squid/%s-cache.log\ncache deny all\n"
	    "visible_hostname %s\n", name, host, mode, (intmax_t)fib, p->pid,
	    name, name, name);
	/* Where the clients reach it: each address told, its port. */
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "listen"), &it,
	    true)) != NULL) {
		if (ucl_object_type(e) != UCL_STRING || !addr_ok(
		    ucl_object_tostring(e))) {
			*errp = wfmt(w, "listen: %.64s is not an address",
			    ucl_object_tostring_forced(e));
			goto bad;
		}
		fprintf(b.fp, strchr(ucl_object_tostring(e), ':') != NULL ?
		    "http_port [%s]:%jd" : "http_port %s:%jd",
		    ucl_object_tostring(e), (intmax_t)port);
		fprintf(b.fp, " ssl-bump tls-cert=%s generate-host-certificates=on "
		    "dynamic_cert_mem_cache_size=4MB\n", p->ca);
	}
	fprintf(b.fp, "sslcrtd_program %s -s %s -M 4MB\nsslcrtd_children 3\n"
	    "acl localnet src", p->certgen, p->ssldb);
	if (!list_of(w, in, "allow", prefix_ok, true, b.fp, " ", "",
	    "allow (the networks that may use it)", errp))
		goto bad;
	if (malware)
		fprintf(b.fp, "\nicap_enable on\nicap_send_client_ip on\n"
		    "icap_service sec_av respmod_precache bypass=off "
		    "icap://127.0.0.1:%d/avscan\nadaptation_access sec_av allow "
		    "all", SEC_ICAP_PORT(idx));
	fprintf(b.fp, "\nacl denied_site ssl::server_name \"%s\"\n"
	    "acl denied_url dstdomain \"%s\"\nacl step1 at_step SslBump1\n"
	    "ssl_bump peek step1\nssl_bump terminate denied_site\nssl_bump %s all"
	    "\nhttp_access deny denied_url\nhttp_access allow localnet\n"
	    "http_access deny all\n", p->deny, p->deny, strcmp(mode, "inspect")
	    == 0 ? "bump" : "splice");
	/* Each domain denied with the names beneath it: ".a\n.a.b\n";
	 * Squid takes the first of two the second is under, and warns of
	 * the other. */
	if (!list_of(w, in, "deny", domain_ok, false, d.fp, ".", "\n",
	    "deny", errp))
		goto bad;
	if (fflush(d.fp) == 0 && d.buf != NULL && d.buf[0] != '\0')
		fprintf(d.fp, "\n");
	if ((*denyp = closed(w, d.fp, &d.buf, errp)) == NULL) {
		d.fp = NULL;
		d.buf = NULL;
		goto bad;
	}
	return (closed(w, b.fp, &b.buf, errp));
bad:
	sq_close(&b);
	sq_close(&d);
	return (NULL);
}

/*
 * Squid's file of an instance, from its form (spec): an SD-WAN
 * service's ("flavor" sdwan) or the Security section's; the paths the
 * agent keeps its files at in p, the lists the console sent beside it;
 * the domains denied into *denyp ("" for SD-WAN's, which names its
 * lists instead).  NULL and why in *errp when the form is not right.
 */
char *
squid_conf_render(struct work *w, const ucl_object_t *spec, const char *name,
    const char *host, int idx, const ucl_object_t *lists,
    const struct sqpaths *p, char **denyp, const char **errp)
{

	*denyp = (char *)(uintptr_t)"";
	if (ucl_object_type(spec) != UCL_OBJECT) {
		*errp = "an instance's spec is its form, an object";
		return (NULL);
	}
	if (!spec_clean(w, spec, 0, errp))
		return (NULL);
	if (strcmp(sval(spec, "flavor"), "sdwan") == 0)
		return (squid_sdwan(w, spec, host, lists, p, errp));
	return (squid_security(w, spec, name, host, idx, p, denyp, errp));
}

/* Whether an instance's form has its malware scanned, by c-icap. */
bool
squid_conf_icap(const ucl_object_t *spec)
{

	return (strcmp(sval(spec, "flavor"), "sdwan") == 0 ? sflag(spec,
	    "icap") : sflag(spec, "malware"));
}

/* ---- ClamAV: the MD+R policies' hashes as its signatures -------------- */

/* An MD+R entry: an MD5, SHA-1 or SHA-256 in hex, its size in bytes
 * after a colon if one likes, as ClamAV's hash signatures have them. */
static bool
hash_ok(const char *s)
{
	size_t	n, i;
	char	*end;
	long	 size;

	n = strcspn(s, ":");
	if (n != 32 && n != 40 && n != 64)
		return (false);
	for (i = 0; i < n; i++)
		if (!isxdigit((unsigned char)s[i]))
			return (false);
	if (s[n] == '\0')
		return (true);
	size = strtol(s + n + 1, &end, 10);
	return (s[n + 1] != '\0' && *end == '\0' && size > 0 && size <=
	    INT32_MAX);
}

/*
 * The MD+R hashes of the SD-WAN instances' forms as ClamAV's signature
 * files, one text each (hdb, hsb, fp, sfp): a line each, hash:size:name,
 * or hash:*:name:73 where the size is not known (ClamAV 0.98 and
 * after); the name says the service, the function policy and the list,
 * as c-icap's log then tells it.  Block and Quarantine are what is
 * found (MD5 in hdb, SHA-1 and SHA-256 in hsb), Allow ClamAV's false
 * positives (fp, sfp).  Each zone's "mdr" ("id", its lists), each
 * policy once a service.  NULL and why for an entry that is not a hash.
 */
ucl_object_t *
clamav_sigs_render(struct work *w, const ucl_object_t *instances,
    const char **errp)
{
	static const char *const ext[] = { "hdb", "hsb", "fp", "sfp" };
	const ucl_object_t	*in, *spec, *z, *md, *e;
	ucl_object_iter_t	 it, zit, eit;
	ucl_object_t		*seen, *out;
	FILE			*fp[4];
	char			*buf[4], name[200], *q;
	size_t			 len[4], n, i;
	const char		*s;
	int			 k, f;

	for (f = 0; f < 4; f++) {
		buf[f] = NULL;
		len[f] = 0;
		if ((fp[f] = open_memstream(&buf[f], &len[f])) == NULL) {
			while (--f >= 0) {
				fclose(fp[f]);
				free(buf[f]);
			}
			*errp = strerror(errno);
			return (NULL);
		}
	}
	it = NULL;
	while ((in = ucl_object_iterate(instances, &it, true)) != NULL) {
		spec = ucl_object_lookup(in, "spec");
		if (strcmp(sval(spec, "flavor"), "sdwan") != 0)
			continue;
		seen = ucl_object_typed_new(UCL_OBJECT);
		zit = NULL;
		while ((z = ucl_object_iterate(ucl_object_lookup(spec, "zones"),
		    &zit, true)) != NULL) {
			md = ucl_object_lookup(z, "mdr");
			if (md == NULL || ucl_object_type(md) != UCL_OBJECT ||
			    sstr(md, "id") == NULL || ucl_object_lookup(seen, sstr(
			    md, "id")) != NULL)
				continue;
			ucl_object_insert_key(seen, ucl_object_frombool(true),
			    sstr(md, "id"), 0, true);
			for (k = 0; k < 3; k++) {
				/* A name ClamAV takes: letters, digits, . _ -. */
				snprintf(name, sizeof(name), "Arcana.%s.%s.%s", sval(
				    spec, "service"), sstr(md, "id"), sfl[k]);
				for (q = name; *q != '\0'; q++)
					if (!isalnum((unsigned char)*q) && *q != '.' &&
					    *q != '_' && *q != '-')
						*q = '_';
				eit = NULL;
				while ((e = ucl_object_iterate(ucl_object_lookup(md,
				    sfl[k]), &eit, true)) != NULL) {
					s = ucl_object_tostring_forced(e);
					if (!hash_ok(s)) {
						*errp = wfmt(w, "mdr %s: %.70s is not a "
						    "hash", sstr(md, "id"), s);
						ucl_object_unref(seen);
						for (f = 0; f < 4; f++) {
							fclose(fp[f]);
							free(buf[f]);
						}
						return (NULL);
					}
					n = strcspn(s, ":");
					f = (n == 32 ? 0 : 1) + (k == 2 ? 2 : 0);
					for (i = 0; i < n; i++)
						fputc(tolower((unsigned char)s[i]), fp[f]);
					if (s[n] == ':')
						fprintf(fp[f], ":%s:%s\n", s + n + 1, name);
					else
						fprintf(fp[f], ":*:%s:73\n", name);
				}
			}
		}
		ucl_object_unref(seen);
	}
	out = ucl_object_typed_new(UCL_OBJECT);
	for (f = 0; f < 4; f++) {
		if (fclose(fp[f]) == 0 && buf[f] != NULL && buf[f][0] != '\0')
			ucl_object_insert_key(out, ucl_object_fromstring(buf[f]),
			    ext[f], 0, false);
		free(buf[f]);
	}
	return (out);
}

/* ---- c-icap: malware scanning, for the Squid beside it ---------------- */

static const char *const icap_tail =
    "acl all src 0.0.0.0/0.0.0.0\nclient_access allow squid\n"
    "client_access deny all\nStartServers 1\nMaxServers 4\n";
static const char *const icap_scan =
    "Module common clamav_mod.so\nService avscan virus_scan.so\n"
    "virus_scan.ScanFileTypes TEXT DATA EXECUTABLE ARCHIVE DOCUMENT\n"
    "virus_scan.SendPercentData 5\nvirus_scan.StartSendPercentDataAfter 2M\n"
    "virus_scan.MaxObjectSize 32M\nvirus_scan.DefaultEngine clamav\n";

/*
 * c-icap's file of an instance whose form scans for malware: an ICAP
 * service avscan that scans with ClamAV's module (c-icap-modules),
 * taking its Squid alone.  An SD-WAN service's is on the edge's own
 * address in the service (its first "listen", the loopback where there
 * is none), at the service's port: the loopback is not the service's
 * table's (net.inet.tcp.bind_all_fibs is 0), so nothing in the table
 * can bind it.  The Security section's is on the loopback, at the
 * instance's port (by its place, idx).  c-icap has no checker of its
 * own: what it refuses, it says as it starts.
 */
char *
icap_conf_render(struct work *w, const ucl_object_t *spec, const char *name,
    const char *host, int idx, const struct sqpaths *p, const char **errp)
{
	const ucl_object_t	*first;
	const char		*own;
	FILE			*b;
	char			*buf;
	size_t			 len;
	intmax_t		 fib;

	buf = NULL;
	len = 0;
	if ((b = open_memstream(&buf, &len)) == NULL) {
		*errp = strerror(errno);
		return (NULL);
	}
	if (strcmp(sval(spec, "flavor"), "sdwan") == 0) {
		fib = (intmax_t)sint(spec, "fib", 0);
		first = nth(ucl_object_lookup(spec, "listen"), 0);
		own = first != NULL && addr_ok(sstr(first, "address")) ?
		    sstr(first, "address") : "127.0.0.1";
		fprintf(b, "# Written by arcana-agent for the Arcana console: "
		    "SD-WAN service %s at %s, in routing table %jd.\n# Malware "
		    "scanning of its security zones (MEF 138's MD+R), by c-icap "
		    "and ClamAV, for its Squid.\nPidFile %s\nCommandsSocket %s\n"
		    "Port %s:%d\nacl squid src %s/255.255.255.255\n%sServerLog "
		    "/var/log/c-icap/sdwan-sw%jd-server.log\nAccessLog "
		    "/var/log/c-icap/sdwan-sw%jd-access.log\n%s", sval(spec,
		    "service"), host, fib, p->icap_pid, p->icap_cmd, own,
		    SDWAN_ICAP_PORT(fib), own, icap_tail, fib, fib, icap_scan);
	} else
		fprintf(b, "# Written by arcana-agent for the Arcana console: the "
		    "Security section's malware scanning for %s at %s,\n# by "
		    "c-icap and ClamAV, for its Squid.\nPidFile %s\n"
		    "CommandsSocket %s\nPort 127.0.0.1:%d\nacl squid src "
		    "127.0.0.1/255.255.255.255\n%sServerLog /var/log/c-icap/%s-"
		    "server.log\nAccessLog /var/log/c-icap/%s-access.log\n%s",
		    name, host, p->icap_pid, p->icap_cmd, SEC_ICAP_PORT(idx),
		    icap_tail, name, name, icap_scan);
	return (closed(w, b, &buf, errp));
}

/* ---- BIRD: routing at the UNIs, iBGP between the edges ---------------- */

/* The default AS of a service, Arcana's (a private one). */
#define	DEFAULT_AS	64512

static int
family(const char *s)
{
	struct net	n;

	return (net_parse(s, &n) ? n.af : 0);
}

/* An identifier as a BIRD symbol: letters, digits and _ of it. */
static const char *
symbol(struct work *w, const char *id)
{
	char	*buf;
	size_t	 i;

	buf = wstrdup(w, id != NULL ? id : "");
	for (i = 0; buf[i] != '\0'; i++)
		if (!isalnum((unsigned char)buf[i]))
			buf[i] = '_';
	return (buf);
}

static bool
is_nullish(const ucl_object_t *o)
{

	return (o == NULL || ucl_object_type(o) == UCL_NULL);
}

/* The k-th entry of a UNI's bgp or ospf: one object, or a list of them
 * (several neighbours, a family each); NULL past the end. */
static const ucl_object_t *
entry_at(const ucl_object_t *rs, int k)
{

	if (is_nullish(rs))
		return (NULL);
	if (ucl_object_type(rs) == UCL_ARRAY)
		return (ucl_array_find_index(rs, (unsigned int)k));
	return (k == 0 ? rs : NULL);
}

/* A list's words joined, each as fmt has it, into fp. */
static void
words(FILE *fp, const ucl_object_t *arr, const char *fmt, const char *sep)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL) {
		fprintf(fp, "%s", n++ > 0 ? sep : "");
		fprintf(fp, fmt, ucl_object_tostring_forced(e));
	}
}

/* A channel of a protocol, with what else it says (next hop self). */
static void
bird_channel(FILE *b, const char *fam, int64_t pref, const char *export,
    const char *extra)
{

	/* BIRD 3 has a route's preference in the channel, not the
	 * protocol. */
	fprintf(b, "\t%s {\n\t\tpreference %jd;\n\t\timport all;\n"
	    "\t\texport %s;\n%s\t};\n", fam, (intmax_t)pref, export, extra);
}

/*
 * BGP and OSPF with a neighbour at an interface, as an entry says them
 * (§11.6.2, §11.6.3): a UNI's with the subscriber (protocols uni_*), a
 * UCS End Point's with the underlay (ucs_*, Mplify 119 §12.2.3.5).
 * Each may be one entry or a list of them: an OSPF area per family,
 * several BGP neighbours of their own AS, hold time and password; a
 * neighbour of the service's own AS is iBGP, given next hop self; one
 * reached by a source address of this edge's (a loopback's) is a
 * multihop session; bfd watches the one that says so.
 */
static void
bird_routing(struct work *w, FILE *b, const ucl_object_t *u,
    const char *what, const char *id, const char *sym, const char *ifn,
    int64_t as)
{
	const ucl_object_t	*rs, *r, *m, *cm;
	ucl_object_iter_t	 nit, cit;
	const char		*fam, *pfx, *src, *exp;
	int64_t			 dist, ras;
	int			 n, k, vi;
	bool			 ibgp, mh;

	pfx = strcmp(what, "UNI") == 0 ? "uni" : "ucs";
	n = 0;
	rs = ucl_object_lookup(u, "bgp");
	for (k = 0; (r = entry_at(rs, k)) != NULL; k++) {
		fam = sstr(r, "family") != NULL ? sstr(r, "family") : "both";
		dist = sint(r, "distance", 200);
		ras = sint(r, "as", 0);
		ibgp = ras == as;
		mh = sflag(r, "multihop");
		src = sstr(r, "source");
		/* What goes to the subscriber carries the communities
		 * agreed. */
		exp = "all";
		if (ucl_array_size(ucl_object_lookup(r, "communities")) > 0) {
			exp = "filter {\n";
			cit = NULL;
			while ((cm = ucl_object_iterate(ucl_object_lookup(r,
			    "communities"), &cit, true)) != NULL)
				exp = wfmt(w, "%s\t\t\tbgp_community.add((%jd, "
				    "%jd));\n", exp, (intmax_t)ucl_object_toint(
				    nth(cm, 0)), (intmax_t)ucl_object_toint(nth(cm,
				    1)));
			exp = wfmt(w, "%s\t\t\taccept;\n\t\t}", exp);
		}
		nit = NULL;
		while ((m = ucl_object_iterate(ucl_object_lookup(r, "neighbors"),
		    &nit, true)) != NULL) {
			fprintf(b, "# %s %s, the neighbour's %s%s%s\nprotocol "
			    "bgp %s_%s_%d {\n", what, id, ucl_object_tostring_forced(
			    m), ibgp ? ", iBGP" : "", mh ? ", multihop" : "", pfx,
			    sym, n++);
			if (src != NULL)
				fprintf(b, "\tlocal %s as %jd;\n", src, (intmax_t)as);
			else
				fprintf(b, "\tlocal as %jd;\n", (intmax_t)as);
			fprintf(b, "\tneighbor %s as %jd;\n",
			    ucl_object_tostring_forced(m), (intmax_t)ras);
			if (mh)
				fprintf(b, "\tmultihop;\n");
			else
				fprintf(b, "\tinterface \"%s\";\n", ifn);
			if (sflag(r, "bfd"))
				fprintf(b, "\tbfd on;\n");
			if (sstr(r, "password") != NULL)
				fprintf(b, "\tauthentication md5;\n\tpassword "
				    "\"%s\";\n", sstr(r, "password"));
			if (ucl_object_lookup(r, "hold_time") != NULL)
				fprintf(b, "\thold time %jd;\n", (intmax_t)
				    ucl_object_toint(ucl_object_lookup(r,
				    "hold_time")));
			if (strcmp(fam, "ipv6") != 0 && family(
			    ucl_object_tostring_forced(m)) == AF_INET)
				bird_channel(b, "ipv4", 256 - dist, exp, ibgp ?
				    "\t\tnext hop self;\n" : "");
			if (strcmp(fam, "ipv4") != 0 && family(
			    ucl_object_tostring_forced(m)) == AF_INET6)
				bird_channel(b, "ipv6", 256 - dist, exp, ibgp ?
				    "\t\tnext hop self;\n" : "");
			fprintf(b, "}\n\n");
		}
	}
	rs = ucl_object_lookup(u, "ospf");
	for (k = 0; (r = entry_at(rs, k)) != NULL; k++) {
		fam = sstr(r, "family") != NULL ? sstr(r, "family") : "both";
		dist = sint(r, "distance", 200);
		for (vi = 0; vi < 2; vi++) {
			if ((vi == 0 && strcmp(fam, "ipv6") == 0) || (vi == 1 &&
			    strcmp(fam, "ipv4") == 0))
				continue;
			fprintf(b, "# %s %s, OSPF%s with the neighbour\nprotocol "
			    "ospf %s %s_%s_%s", what, id, vi == 0 ? "v2" : "v3",
			    vi == 0 ? "v2" : "v3", pfx, sym, vi == 0 ? "v2" : "v3");
			if (k > 0)
				fprintf(b, "_%d", k);
			fprintf(b, " {\n");
			bird_channel(b, vi == 0 ? "ipv4" : "ipv6", 256 - dist, "all",
			    "");
			fprintf(b, "\tarea %jd {\n\t\tinterface \"%s\" {\n",
			    (intmax_t)sint(r, "area", 0), ifn);
			if (ucl_object_lookup(r, "cost") != NULL)
				fprintf(b, "\t\t\tcost %jd;\n", (intmax_t)
				    ucl_object_toint(ucl_object_lookup(r, "cost")));
			if (ucl_object_lookup(r, "hello") != NULL)
				fprintf(b, "\t\t\thello %jd;\n", (intmax_t)
				    ucl_object_toint(ucl_object_lookup(r, "hello")));
			if (ucl_object_lookup(r, "dead") != NULL)
				fprintf(b, "\t\t\tdead %jd;\n", (intmax_t)
				    ucl_object_toint(ucl_object_lookup(r, "dead")));
			if (sflag(r, "bfd"))
				fprintf(b, "\t\t\tbfd on;\n");
			if (sstr(r, "password") != NULL)
				fprintf(b, "\t\t\tauthentication cryptographic;\n"
				    "\t\t\tpassword \"%s\";\n", sstr(r, "password"));
			fprintf(b, "\t\t};\n\t};\n}\n\n");
		}
	}
}

/*
 * The filters to the kernel of an edge whose breakout is chosen by BGP
 * attribute: one set's routes go by the end point named for it, in the
 * family of its gateway; with only, no other BGP route reaches the
 * kernel, which keeps its own default.
 */
static void
bird_sets(FILE *b, const ucl_object_t *sets, bool loop)
{
	const ucl_object_t	*set, *m;
	ucl_object_iter_t	 it, mit;
	const char		*gw;
	int			 fam, n;

	for (fam = 4; fam <= 6; fam += 2) {
		fprintf(b, "# Destination sets by BGP attribute, each by the "
		    "uplink named for it\nfilter to_kernel%d {\n\tif source = "
		    "RTS_DEVICE || source = RTS_INHERIT || dest != RTD_UNICAST "
		    "then reject;\n%s", fam, loop ? "\tif proto ~ \"orig*\" then "
		    "reject;\n" : "");
		it = NULL;
		while ((set = ucl_object_iterate(ucl_object_lookup(sets, "sets"),
		    &it, true)) != NULL) {
			gw = sval(set, "gateway");
			if ((family(gw) == AF_INET) != (fam == 4))
				continue;
			fprintf(b, "\t# %s, by %s\n\tif ", sval(set, "name"),
			    sval(set, "via"));
			n = 0;
			if (ucl_array_size(ucl_object_lookup(set, "as_path")) > 0) {
				fprintf(b, "bgp_path ~ [");
				mit = NULL;
				while ((m = ucl_object_iterate(ucl_object_lookup(set,
				    "as_path"), &mit, true)) != NULL)
					fprintf(b, "%s%jd", n++ > 0 ? ", " : "",
					    (intmax_t)ucl_object_toint(m));
				fprintf(b, "]");
			}
			if (ucl_array_size(ucl_object_lookup(set, "communities")) >
			    0) {
				fprintf(b, "%sbgp_community ~ [", n > 0 ? " || " :
				    "");
				n = 0;
				mit = NULL;
				while ((m = ucl_object_iterate(ucl_object_lookup(set,
				    "communities"), &mit, true)) != NULL)
					fprintf(b, "%s(%jd, %jd)", n++ > 0 ? ", " : "",
					    (intmax_t)ucl_object_toint(nth(m, 0)),
					    (intmax_t)ucl_object_toint(nth(m, 1)));
				fprintf(b, "]");
			}
			fprintf(b, " then { gw = %s; accept; }\n", gw);
		}
		fprintf(b, "%s\taccept;\n}\n\n", sflag(sets, "only") ? "\tif "
		    "source = RTS_BGP then reject;\n" : "");
	}
}

/*
 * iBGP between the edges' loopbacks: to each other edge, its loopback
 * by a static route over every tunnel to it at once (ECMP), each path
 * watched by BFD, the backups in a second static of lower preference;
 * one session, loopback to loopback, of the family both have; and this
 * edge's own prefixes as statics (orig*), to the other edges.
 */
static void
bird_loop(struct work *w, FILE *b, const ucl_object_t *lp, int64_t as)
{
	static const char *const pk[2][2] = { { "paths4", "backup4" },
	    { "paths6", "backup6" } };
	const ucl_object_t	*fe, *paths, *og, *rt;
	ucl_object_iter_t	 it, pit;
	const char		*me4, *me6, *fa, *sym;
	int			 k, i, pass;
	bool			 transit;

	me4 = sstr(lp, "local4");
	me6 = sstr(lp, "local6");
	transit = sflag(lp, "transit");
	k = 0;
	it = NULL;
	while ((fe = ucl_object_iterate(ucl_object_lookup(lp, "edges"), &it,
	    true)) != NULL) {
		for (i = 0; i < 2; i++) {
			if ((fa = sstr(fe, i == 0 ? "ipv4" : "ipv6")) == NULL)
				continue;
			for (pass = 0; pass < 2; pass++) {
				paths = ucl_object_lookup(fe, pk[i][pass]);
				if (ucl_array_size(paths) == 0)
					continue;
				fprintf(b, "# %s's loopback, by %s tunnel to it, each "
				    "path watched by BFD\nprotocol static loop%d%s_%d "
				    "{\n\t%s%s;\n\troute %s/%d", sval(fe, "name"),
				    pass == 0 ? "every" : "every backup", i == 0 ? 4 :
				    6, pass == 0 ? "" : "b", k, i == 0 ? "ipv4" :
				    "ipv6", pass == 0 ? "" : " { preference 150; }", fa,
				    i == 0 ? 32 : 128);
				words(b, paths, " via %s bfd", "");
				fprintf(b, ";\n}\n\n");
			}
		}
		/* The session, loopback to loopback, of the family both have. */
		if (me4 != NULL && sstr(fe, "ipv4") != NULL)
			fprintf(b, "# to %s, loopback to loopback%s\nprotocol bgp "
			    "edge%d from edge {\n\tlocal %s as %jd;\n\tneighbor %s "
			    "as %jd;\n\tmultihop;\n%s}\n\n", sval(fe, "name"),
			    transit ? ", a client of this edge's reflection" : "", k,
			    me4, (intmax_t)as, sstr(fe, "ipv4"), (intmax_t)as,
			    transit ? "\trr client;\n" : "");
		else if (me6 != NULL && sstr(fe, "ipv6") != NULL)
			fprintf(b, "# to %s, loopback to loopback%s\nprotocol bgp "
			    "edge%d from edge {\n\tlocal %s as %jd;\n\tneighbor %s "
			    "as %jd;\n\tmultihop;\n%s}\n\n", sval(fe, "name"),
			    transit ? ", a client of this edge's reflection" : "", k,
			    me6, (intmax_t)as, sstr(fe, "ipv6"), (intmax_t)as,
			    transit ? "\trr client;\n" : "");
		k++;
	}
	/* This edge's own prefixes: its UNIs' subnets and static routes, a
	 * remote end point's; to the other edges, not to the kernel. */
	it = NULL;
	while ((og = ucl_object_iterate(ucl_object_lookup(lp, "origins"), &it,
	    true)) != NULL) {
		sym = symbol(w, sstr(og, "id"));
		for (i = 0; i < 2; i++) {
			if (ucl_array_size(ucl_object_lookup(og, i == 0 ? "ipv4" :
			    "ipv6")) == 0)
				continue;
			fprintf(b, "# %s's own\nprotocol static orig%d_%s {\n\t%s;\n",
			    sval(og, "id"), i == 0 ? 4 : 6, sym, i == 0 ? "ipv4" :
			    "ipv6");
			pit = NULL;
			while ((rt = ucl_object_iterate(ucl_object_lookup(og, i ==
			    0 ? "ipv4" : "ipv6"), &pit, true)) != NULL)
				if (sstr(rt, "next_hop") != NULL)
					fprintf(b, "\troute %s via %s;\n", sval(rt,
					    "prefix"), sstr(rt, "next_hop"));
				else
					fprintf(b, "\troute %s via \"%s\";\n", sval(rt,
					    "prefix"), sval(og, "interface"));
			fprintf(b, "}\n\n");
		}
	}
}

/* A UCS End Point's file: routing with the underlay in its table. */
static void
bird_ucs(struct work *w, FILE *b, const ucl_object_t *spec, const char *host)
{
	int64_t		 vrf;
	const char	*ktab;

	vrf = sint(spec, "table", 0);
	ktab = vrf > 0 ? wfmt(w, "\tkernel table %jd;\n", (intmax_t)vrf) : "";
	fprintf(b, "# Written by arcana-agent for the Arcana console: UCS end "
	    "point %s at %s, routing with the underlay in table %jd.\n# Changed "
	    "by the console's next apply.\nrouter id %s;\nlog syslog { warning, "
	    "error };\n\nprotocol device {\n}\n\nprotocol direct {\n\tipv4;\n\t"
	    "ipv6;\n\tinterface \"%s\";\n}\n\nprotocol kernel kernel4 {\n%s\t"
	    "learn;\n\tpersist;\n\tipv4 {\n\t\timport all;\n\t\texport where "
	    "source != RTS_DEVICE && source != RTS_INHERIT && dest = "
	    "RTD_UNICAST;\n\t};\n}\n\nprotocol kernel kernel6 {\n%s\tlearn;\n\t"
	    "persist;\n\tipv6 {\n\t\timport all;\n\t\texport where source != "
	    "RTS_DEVICE && source != RTS_INHERIT && dest = RTD_UNICAST;\n\t};\n}"
	    "\n\n", sval(spec, "end_point"), host, (intmax_t)vrf, sval(spec,
	    "router_id"), sval(spec, "interface"), ktab, ktab);
	bird_routing(w, b, spec, "UCS", sval(spec, "end_point"), symbol(w,
	    sstr(spec, "end_point")), sval(spec, "interface"), sint(spec, "as",
	    DEFAULT_AS));
}

/*
 * BIRD's file of an instance, from its form (spec): a UCS End Point's
 * ("flavor" ucs: its "end_point", "table", "router_id", "interface",
 * "as" and its "bgp" and "ospf" as the end point has them), or an
 * SD-WAN service's at this edge: its "service", "fib", the "table"
 * BIRD writes to, its "as" and "router_id"; the interfaces of the
 * connected routes ("direct"); "loopback" where the iBGP is between
 * the edges' loopbacks; the destination "sets" by BGP attribute; "bfd"
 * on its "interfaces" ("interval", "multiplier", "multihop", and
 * "sessions" where the iBGP sessions go down with it); what is not sent
 * to the other edges ("reject", prefixes); the sessions' "md5"; "loop"
 * (bird_loop()) or the iBGP "peers", each by a "tunnel" "to" an edge,
 * its "local" and "neighbor" addresses, and the "role" where a control
 * plane reflects ("client", with its "cluster_id"; "control"); and the
 * "unis" here that route, each its "id", "end_point", "interface" and
 * its "bgp" and "ospf" as the UNI has them.  It learns the kernel's
 * table and keeps it, the console's routes outranking BGP's; the
 * kernel is given what BIRD learned, not the connected, nor a route to
 * nowhere.  bird -p checks it.  NULL and why in *errp when the form is
 * not right.
 */
char *
bird_conf_render(struct work *w, const ucl_object_t *spec, const char *host,
    const char **errp)
{
	const ucl_object_t	*bfd, *pe, *u;
	ucl_object_iter_t	 it;
	const char		*ktab, *kexp, *kexp6, *role;
	FILE			*b;
	char			*buf;
	size_t			 len;
	int64_t			 as, table;
	int			 k;
	bool			 loop;

	if (ucl_object_type(spec) != UCL_OBJECT) {
		*errp = "an instance's spec is its form, an object";
		return (NULL);
	}
	if (!spec_clean(w, spec, 0, errp))
		return (NULL);
	if (!addr_ok(sstr(spec, "router_id"))) {
		*errp = "the form's router_id is an IPv4 address";
		return (NULL);
	}
	buf = NULL;
	len = 0;
	if ((b = open_memstream(&buf, &len)) == NULL) {
		*errp = strerror(errno);
		return (NULL);
	}
	if (strcmp(sval(spec, "flavor"), "ucs") == 0) {
		bird_ucs(w, b, spec, host);
		return (closed(w, b, &buf, errp));
	}
	as = sint(spec, "as", DEFAULT_AS);
	loop = sflag(spec, "loopback");
	fprintf(b, "# Written by arcana-agent for the Arcana console: SD-WAN "
	    "service %s at %s, in routing table %jd.\n# Changed by the console's "
	    "next apply.\nrouter id %s;\nlog syslog { warning, error };\n\n"
	    "protocol device {\n}\n\n", sval(spec, "service"), host, (intmax_t)
	    sint(spec, "fib", 0), sval(spec, "router_id"));
	if (ucl_array_size(ucl_object_lookup(spec, "direct")) > 0) {
		fprintf(b, "protocol direct {\n\tipv4;\n\tipv6;\n\tinterface ");
		words(b, ucl_object_lookup(spec, "direct"), "\"%s\"", ", ");
		fprintf(b, ";\n}\n\n");
	}
	/* The kernel's table: what the console put there is learned and
	 * kept, and outranks what BGP brings (preference 200 to 100), so
	 * the document's routes stay as they are and BGP's fill in the
	 * rest.  merge paths: the iBGP sessions over parallel tunnels, each
	 * with next hop self, give one prefix several equal paths, which
	 * the kernel then carries as one multipath route (ECMP).  The
	 * service's table on this edge; the first, the host's own, BIRD
	 * takes without being told. */
	table = sint(spec, "table", 0);
	ktab = table > 0 ? wfmt(w, "\tkernel table %jd;\n", (intmax_t)table) :
	    "";
	/* What BIRD puts in the kernel: not the connected, not what it
	 * learned there, not a route to nowhere; with the iBGP between
	 * loopbacks not the edge's own prefixes either (orig*). */
	kexp = loop ? "export where source != RTS_DEVICE && source != "
	    "RTS_INHERIT && dest = RTD_UNICAST && proto !~ \"orig*\";" :
	    "export where source != RTS_DEVICE && source != RTS_INHERIT && dest "
	    "= RTD_UNICAST;";
	kexp6 = kexp;
	/* Destination sets by BGP attribute: a route whose AS path or
	 * communities match a set goes out by the uplink named for it, its
	 * gateway written as the route's on its way to the kernel. */
	if (ucl_object_lookup(spec, "sets") != NULL) {
		bird_sets(b, ucl_object_lookup(spec, "sets"), loop);
		kexp = "export filter to_kernel4;";
		kexp6 = "export filter to_kernel6;";
	}
	fprintf(b, "protocol kernel kernel4 {\n%s\tlearn;\n\tmerge paths on;\n"
	    "\tpersist;\n\tipv4 {\n\t\timport filter { preference = 200; accept; "
	    "};\n\t\t%s\n\t};\n}\n\nprotocol kernel kernel6 {\n%s\tlearn;\n\t"
	    "merge paths on;\n\tpersist;\n\tipv6 {\n\t\timport filter { "
	    "preference = 200; accept; };\n\t\t%s\n\t};\n}\n\n", ktab, kexp,
	    ktab, kexp6);
	/* BFD on each tunnel interface here (R58, R59, R159) and the UNIs
	 * whose neighbours are watched by it: the iBGP sessions go down
	 * with it, and the agent reads the sessions. */
	if ((bfd = ucl_object_lookup(spec, "bfd")) != NULL) {
		fprintf(b, "protocol bfd {\n\tinterface ");
		if (ucl_array_size(ucl_object_lookup(bfd, "interfaces")) > 0)
			words(b, ucl_object_lookup(bfd, "interfaces"), "\"%s\"",
			    ", ");
		else
			fprintf(b, "\"none\"");
		fprintf(b, " {\n\t\tinterval %jd ms;\n\t\tmultiplier %jd;\n\t};\n",
		    (intmax_t)sint(bfd, "interval", 200), (intmax_t)sint(bfd,
		    "multiplier", 3));
		/* The sessions between loopbacks are multihop, watched by
		 * multihop BFD alike. */
		if (sflag(bfd, "multihop"))
			fprintf(b, "\tmultihop {\n\t\tinterval %jd ms;\n\t\t"
			    "multiplier %jd;\n\t};\n", (intmax_t)sint(bfd,
			    "interval", 200), (intmax_t)sint(bfd, "multiplier", 3));
		fprintf(b, "}\n\n");
	}
	/* What goes to the other edges: the UNIs' subnets and what the
	 * UNIs learn, not what the kernel's table holds of the console's
	 * (each edge has its own) nor the tunnels' own addresses, which a
	 * peer would resolve its next hop by in a circle. */
	fprintf(b, "filter to_edges {\n\tif source = RTS_INHERIT then reject;\n");
	if (ucl_array_size(ucl_object_lookup(spec, "reject")) > 0) {
		fprintf(b, "\tif net ~ [ ");
		words(b, ucl_object_lookup(spec, "reject"), "%s+", ", ");
		fprintf(b, " ] then reject;\n");
	}
	fprintf(b, "\taccept;\n}\n\n");
	fprintf(b, "template bgp edge {\n\tlocal as %jd;\n\thold time 30;\n"
	    "\terror wait time 10, 60;\n%s", (intmax_t)as, sflag(bfd,
	    "sessions") ? "\tbfd on;\n" : "");
	/* TCP MD5 on the sessions (Mplify 119 R11, R12). */
	if (sstr(spec, "md5") != NULL)
		fprintf(b, "\tauthentication md5;\n\tpassword \"%s\";\n",
		    sstr(spec, "md5"));
	fprintf(b, "\tipv4 {\n\t\timport all;\n\t\texport filter to_edges;\n"
	    "\t\tnext hop self;\n\t};\n\tipv6 {\n\t\timport all;\n\t\texport "
	    "filter to_edges;\n\t\tnext hop self;\n\t};\n}\n\n");
	/* Between the loopbacks, one session with each edge; or by each
	 * tunnel, or with the control plane's host alone, which reflects
	 * to all (RFC 4456). */
	if (loop)
		bird_loop(w, b, ucl_object_lookup(spec, "loop"), as);
	k = 0;
	it = NULL;
	while (!loop && (pe = ucl_object_iterate(ucl_object_lookup(spec,
	    "peers"), &it, true)) != NULL) {
		role = sval(pe, "role");
		fprintf(b, "# %s, to %s%s\nprotocol bgp edge%d from edge {\n\t"
		    "local %s as %jd;\n\tneighbor %s as %jd;\n", sval(pe, "tunnel"),
		    sval(pe, "to"), strcmp(role, "client") == 0 ? ", a client of "
		    "this reflector" : strcmp(role, "control") == 0 ? ", the "
		    "control plane" : "", k++, sval(pe, "local"), (intmax_t)as,
		    sval(pe, "neighbor"), (intmax_t)as);
		if (strcmp(role, "client") == 0) {
			fprintf(b, "\trr client;\n");
			if (sstr(pe, "cluster_id") != NULL)
				fprintf(b, "\trr cluster id %s;\n", sstr(pe,
				    "cluster_id"));
		}
		fprintf(b, "}\n\n");
	}
	/* At each UNI here: BGP, OSPF, as its entry says. */
	it = NULL;
	while ((u = ucl_object_iterate(ucl_object_lookup(spec, "unis"), &it,
	    true)) != NULL)
		bird_routing(w, b, u, "UNI", sval(u, "id"), symbol(w, sstr(u,
		    "end_point")), sval(u, "interface"), as);
	return (closed(w, b, &buf, errp));
}
