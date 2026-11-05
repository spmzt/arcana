/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Threat feeds: lists of scanners', spammers' and abusers' prefixes,
 * fetched from the internet by the console, once for the fleet (a host
 * may have no way out), and kept on the hosts chosen as ipfw(8) tables
 * of type addr, IPv4 and IPv6 in one, by arcana-firewall's feed-load:
 * the agent fills a scratch table and swaps it in.  No rule is added:
 * the Firewall page offers one, which the admin keeps or not.
 *
 * A feed is fetched over HTTP or HTTPS (OpenSSL, verified against the
 * system's CAs for the URL's name) at its interval (an hour at least;
 * the presets' as their sources ask), conditionally (If-Modified-Since),
 * 16 MB and 250 000 entries at most, in a minute; only from an address
 * of the internet, the one resolved and checked connected to, and so at
 * each redirect, followed here (3 at most, none from https to http).  Each entry is made
 * an address or prefix with no host bits, once, those another covers
 * left out; dropped, with why: what is no prefix, the whole address
 * space, what covers the console's own addresses, a host's (the
 * address its servers.json URI names) or a user's last sign-in, and
 * private or reserved space unless the feed lists it on purpose.
 *
 * feeds.json, {"feeds": [...]}, is what the operators keep; the
 * fetches and deliveries, feeds-state.json, and each feed's entries
 * feeds/<id>.json.  The work is a thread's of the worker that takes
 * feeds.lock (and of the cluster's leader alone), asked by
 * feeds-asks.json: a fetch now, or a preview, every host's dry run.  A
 * feed failing FEED_FAILS times raises an alarm, by mail and Telegram
 * as Settings say, and its recovery clears it; an update with other
 * entries is an event of the feed's.  The same as arcana-console's
 * threat-feeds (cyang.c), its view made of feed_json()'s and its
 * changes through feed_put() and feed_remove(), every protection
 * held.
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <fetch.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "console.h"
#include "ynet.h"

#define	FEEDS_FILE	"feeds.json"
#define	FEEDS_STATE	"feeds-state.json"
#define	FEEDS_ASKS	"feeds-asks.json"
#define	FEEDS_LOCK	"feeds.lock"
#define	FEEDS_RUN	"feeds-run.lock"
#define	SIGNINS_FILE	"signins.json"
#define	FEEDS_MAX	32
#define	FEED_MAX_BYTES	(16 * 1024 * 1024)
#define	FEED_MAX	250000
#define	FEED_FLOOR_H	1		/* hours between fetches, at least */
#define	FEED_FAILS	3		/* fetches failed in a row: an alarm */
#define	FEED_DROPPED	500		/* dropped entries kept, with why */
#define	FEED_EVENTS	30
#define	FEED_TIMEOUT	60		/* s a fetch may take */
#define	FEED_HOST_RETRY	300		/* s before a failed delivery again */
#define	FEEDS_TICK	2		/* s between looks at what is asked */
#define	SIGNINS_MAX	64

#define	S(x)	ucl_object_fromstring(x)
#define	I(x)	ucl_object_fromint(x)
#define	B(x)	ucl_object_frombool(x)

/*
 * The presets, off until an operator enables one: each source's own
 * list as it publishes it, at the interval its terms ask for at least.
 */
static const struct preset {
	const char	*id, *name, *url, *format, *what, *terms, *terms_url;
	int		 interval;
	bool		 bogons;
} presets[] = {
	{ "spamhaus-drop-v4", "Spamhaus DROP (IPv4)",
	    "https://www.spamhaus.org/drop/drop_v4.json", "spamhaus-json",
	    "Netblocks hijacked or leased by spammers and cyber-criminals: "
	    "no legitimate traffic comes from them.",
	    "Free for any use under Spamhaus' DROP terms; fetch it no more "
	    "than once an hour.", "https://www.spamhaus.org/drop/terms/", 12,
	    false },
	{ "spamhaus-drop-v6", "Spamhaus DROP (IPv6)",
	    "https://www.spamhaus.org/drop/drop_v6.json", "spamhaus-json",
	    "The IPv6 netblocks of the same list.",
	    "Free for any use under Spamhaus' DROP terms; fetch it no more "
	    "than once an hour.", "https://www.spamhaus.org/drop/terms/", 12,
	    false },
	{ "firehol-level1", "FireHOL level 1",
	    "https://iplists.firehol.org/files/firehol_level1.netset", "plain",
	    "Spamhaus DROP, DShield, Feodo Tracker and the full bogons, "
	    "aggregated: made to drop at an internet-facing interface, it "
	    "lists private and reserved space on purpose.",
	    "FireHOL's aggregation of public lists; each source's own terms "
	    "hold.", "https://iplists.firehol.org/?ipset=firehol_level1", 6,
	    true },
	{ "feodo", "abuse.ch Feodo Tracker",
	    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "plain",
	    "Botnet command-and-control servers (Dridex, Emotet, QakBot and "
	    "others) seen online now.",
	    "CC0: no restriction on use.",
	    "https://feodotracker.abuse.ch/blocklist/", 1, false },
	{ "blocklist-de", "blocklist.de: all",
	    "https://lists.blocklist.de/lists/all.txt", "plain",
	    "Addresses reported in the last 48 hours for attacks on SSH, "
	    "mail, FTP, web logins and more; IPv4 and IPv6.",
	    "Free to use; fetch it no more than every half hour.",
	    "https://www.blocklist.de/en/export.html", 6, false },
	{ "dshield", "DShield recommended block list",
	    "https://feeds.dshield.org/block.txt", "dshield",
	    "The 20 /24 networks that scanned the most targets in the last "
	    "three days, by the SANS Internet Storm Center.",
	    "CC BY-NC-SA 2.5: not for commercial use.",
	    "https://creativecommons.org/licenses/by-nc-sa/2.5/", 6, false },
	{ "et-compromised", "Emerging Threats: compromised hosts",
	    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
	    "plain",
	    "Hosts known to be compromised, by Proofpoint's Emerging Threats "
	    "Open.", "Emerging Threats Open's terms; read them before use.",
	    "https://rules.emergingthreats.net/OPEN_download_instructions.html",
	    12, false },
};

static const char *const formats[] = { "plain", "spamhaus-json", "dshield" };

/* An address or prefix: its family, its bits, its length. */
struct pfx {
	int	af;
	uint8_t	a[16];
	int	len;
};

/* An address no feed may cut off, and why. */
struct prot {
	struct pfx	 p;
	char		 why[96];
	char		 host[9];	/* the host's whose it is, or "" */
};
#define	PROT_MAX	512

static pthread_mutex_t	run_lock = PTHREAD_MUTEX_INITIALIZER;

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_replace_key(o, v, key, 0, true);
}

static const char *
str(const ucl_object_t *o, const char *key)
{

	return (ucl_str(o, key));
}

static size_t
obj_len(const ucl_object_t *o)
{
	ucl_object_iter_t	 it = NULL;
	size_t			 n = 0;

	while (o != NULL && ucl_object_iterate(o, &it, true) != NULL)
		n++;
	return (n);
}

static int64_t
num(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	return ((v = ucl_object_lookup(o, key)) != NULL ? ucl_object_toint(v) :
	    0);
}

/* ---- Prefixes ------------------------------------------------------ */

static bool
pfx_parse(const char *s, struct pfx *p)
{
	char	buf[64], *slash, *end;
	long	l;
	int	i, bits;

	if (strlen(s) >= sizeof(buf))
		return (false);
	strlcpy(buf, s, sizeof(buf));
	memset(p, 0, sizeof(*p));
	if ((slash = strchr(buf, '/')) != NULL)
		*slash++ = '\0';
	if (inet_pton(AF_INET, buf, p->a) == 1) {
		p->af = AF_INET;
		bits = 32;
	} else if (inet_pton(AF_INET6, buf, p->a) == 1) {
		p->af = AF_INET6;
		bits = 128;
	} else
		return (false);
	p->len = bits;
	if (slash != NULL) {
		l = strtol(slash, &end, 10);
		if (*slash == '\0' || *end != '\0' || l < 0 || l > bits)
			return (false);
		p->len = (int)l;
	}
	for (i = p->len; i < bits; i++)
		p->a[i / 8] &= ~(0x80 >> (i % 8));
	return (true);
}

static void
pfx_str(const struct pfx *p, char *out, size_t len)
{
	char	buf[INET6_ADDRSTRLEN];

	if (inet_ntop(p->af, p->a, buf, sizeof(buf)) == NULL)
		buf[0] = '\0';
	snprintf(out, len, "%s/%d", buf, p->len);
}

/* Do a and b share an address: is one within the other? */
static bool
pfx_overlap(const struct pfx *a, const struct pfx *b)
{
	int	i, n;

	if (a->af != b->af)
		return (false);
	n = MIN(a->len, b->len);
	for (i = 0; i < n; i++)
		if ((a->a[i / 8] ^ b->a[i / 8]) & (0x80 >> (i % 8)))
			return (false);
	return (true);
}

/* Is b within a? */
static bool
pfx_covers(const struct pfx *a, const struct pfx *b)
{

	return (a->len <= b->len && pfx_overlap(a, b));
}

static int
pfx_cmp(const void *x, const void *y)
{
	const struct pfx	*a = x, *b = y;
	int			 c;

	if (a->af != b->af)
		return (a->af < b->af ? -1 : 1);
	if ((c = memcmp(a->a, b->a, sizeof(a->a))) != 0)
		return (c);
	return (a->len < b->len ? -1 : a->len > b->len);
}

/* Private, shared, loopback, link-local, multicast and reserved space. */
static const char *const bogons[] = {
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/3", "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96",
	"100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
};

static bool
bogon(const struct pfx *p)
{
	struct pfx	b;
	size_t		i;

	for (i = 0; i < nitems(bogons); i++)
		if (pfx_parse(bogons[i], &b) && pfx_overlap(&b, p))
			return (true);
	return (false);
}

/* ---- What is protected ------------------------------------------- */

static void
prot_add(struct prot *v, size_t *np, int af, const void *addr,
    const char *fmt, ...) __printflike(5, 6);

static void
prot_add(struct prot *v, size_t *np, int af, const void *addr,
    const char *fmt, ...)
{
	va_list	ap;

	if (*np >= PROT_MAX)
		return;
	memset(&v[*np], 0, sizeof(v[*np]));
	v[*np].p.af = af;
	v[*np].p.len = af == AF_INET ? 32 : 128;
	memcpy(v[*np].p.a, addr, af == AF_INET ? 4 : 16);
	va_start(ap, fmt);
	vsnprintf(v[*np].why, sizeof(v[*np].why), fmt, ap);
	va_end(ap);
	(*np)++;
}

/* A name's or an address's addresses, each protected for why; sid's, a
 * host's, or NULL. */
static void
prot_resolve(struct prot *v, size_t *np, const char *host, const char *why,
    const char *sid)
{
	size_t			 first = *np;
	struct addrinfo	 hints, *res, *ai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, NULL, &hints, &res) != 0)
		return;
	for (ai = res; ai != NULL; ai = ai->ai_next)
		if (ai->ai_family == AF_INET)
			prot_add(v, np, AF_INET, &((struct sockaddr_in *)(void *)
			    ai->ai_addr)->sin_addr, "%s", why);
		else if (ai->ai_family == AF_INET6)
			prot_add(v, np, AF_INET6, &((struct sockaddr_in6 *)
			    (void *)ai->ai_addr)->sin6_addr, "%s", why);
	freeaddrinfo(res);
	for (; sid != NULL && first < *np; first++)
		snprintf(v[first].host, sizeof(v[first].host), "%s", sid);
}

/*
 * What no feed may cut off: the console's own addresses, each host's
 * (the address its URI names, resolved), each user's last sign-in.
 */
static size_t
protected(struct prot *v)
{
	struct ifaddrs		*ifa, *i;
	struct hostref		 refs[256];
	ucl_object_t		*si;
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	char			 host[256], why[96];
	const char		*p, *e;
	size_t			 n;
	int			 k, nr;

	n = 0;
	if (getifaddrs(&ifa) == 0) {
		for (i = ifa; i != NULL; i = i->ifa_next) {
			if (i->ifa_addr == NULL)
				continue;
			if (i->ifa_addr->sa_family == AF_INET)
				prot_add(v, &n, AF_INET, &((struct sockaddr_in *)
				    (void *)i->ifa_addr)->sin_addr, "the "
				    "console's, on %s", i->ifa_name);
			else if (i->ifa_addr->sa_family == AF_INET6)
				prot_add(v, &n, AF_INET6, &((struct sockaddr_in6
				    *)(void *)i->ifa_addr)->sin6_addr, "the "
				    "console's, on %s", i->ifa_name);
		}
		freeifaddrs(ifa);
	}
	nr = host_refs_get(refs, (int)nitems(refs));
	for (k = 0; k < nr; k++) {
		/* tcp://host:port, sctp://[v6]:port. */
		if ((p = strstr(refs[k].uri, "://")) == NULL)
			continue;
		p += 3;
		if (*p == '[') {
			p++;
			e = strchr(p, ']');
		} else
			e = strrchr(p, ':');
		if (e == NULL || (size_t)(e - p) >= sizeof(host))
			continue;
		snprintf(host, sizeof(host), "%.*s", (int)(e - p), p);
		snprintf(why, sizeof(why), "host %s's, which the console "
		    "reaches", refs[k].name);
		prot_resolve(v, &n, host, why, refs[k].id);
	}
	if ((si = store_load(SIGNINS_FILE)) != NULL) {
		it = NULL;
		while ((u = ucl_object_iterate(si, &it, true)) != NULL) {
			if (str(u, "addr") == NULL)
				continue;
			snprintf(why, sizeof(why), "%s's last sign-in",
			    ucl_object_key(u));
			prot_resolve(v, &n, str(u, "addr"), why, NULL);
		}
		ucl_object_unref(si);
	}
	return (n);
}

/* A user signed in from the request's address: kept, for protected(). */
void
feeds_signin(struct http_request *req, const char *user)
{
	ucl_object_t		*si, *o;
	const ucl_object_t	*u, *old;
	ucl_object_iter_t	 it;
	char			 addr[INET6_ADDRSTRLEN + 8];
	struct pfx		 p;

	if (user == NULL || user[0] == '\0' || web_peer(req, addr,
	    sizeof(addr)) == NULL || !pfx_parse(addr, &p))
		return;
	if ((si = store_load(SIGNINS_FILE)) == NULL || ucl_object_type(si) !=
	    UCL_OBJECT) {
		if (si != NULL)
			ucl_object_unref(si);
		si = ucl_object_typed_new(UCL_OBJECT);
	}
	if ((u = ucl_object_lookup(si, user)) != NULL && str(u, "addr") !=
	    NULL && strcmp(str(u, "addr"), addr) == 0) {
		ucl_object_unref(si);
		return;
	}
	/* The oldest goes when there are too many. */
	if (ucl_object_lookup(si, user) == NULL && ucl_object_type(si) ==
	    UCL_OBJECT) {
		size_t	 cnt = 0;

		old = NULL;
		it = NULL;
		while ((u = ucl_object_iterate(si, &it, true)) != NULL) {
			cnt++;
			if (old == NULL || num(u, "at") < num(old, "at"))
				old = u;
		}
		if (cnt >= SIGNINS_MAX && old != NULL)
			(void)ucl_object_delete_key(si, ucl_object_key(old));
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "addr", S(addr));
	put(o, "at", I(time(NULL)));
	put(si, user, o);
	(void)store_save(SIGNINS_FILE, si);
	ucl_object_unref(si);
}

/* ---- Parsing a feed ---------------------------------------------- */

/* The entry a line gives, by the feed's format, in buf; false: none. */
static bool
line_entry(const char *format, const char *line, size_t n, char *buf,
    size_t blen)
{
	const char	*p, *q;
	size_t		 k;

	while (n > 0 && isspace((unsigned char)*line)) {
		line++;
		n--;
	}
	if (n == 0 || *line == '#' || *line == ';')
		return (false);
	if (strcmp(format, "spamhaus-json") == 0) {
		/* {"cidr":"1.10.16.0/20","sblid":...}; the metadata line
		 * has none. */
		for (p = line; p + 8 <= line + n; p++)
			if (strncmp(p, "\"cidr\":\"", 8) == 0)
				break;
		if (p + 8 > line + n)
			return (false);
		p += 8;
		for (q = p; q < line + n && *q != '"'; q++)
			;
		k = (size_t)(q - p);
	} else if (strcmp(format, "dshield") == 0) {
		/* start <tab> end <tab> bits <tab> ...; "Start" heads it. */
		char		 a[64];
		const char	*t1, *t2;
		long		 bits;

		if ((t1 = memchr(line, '\t', n)) == NULL || (size_t)(t1 - line) >=
		    sizeof(a))
			return (false);
		snprintf(a, sizeof(a), "%.*s", (int)(t1 - line), line);
		if ((t2 = memchr(t1 + 1, '\t', (size_t)(line + n - t1 - 1))) ==
		    NULL)
			return (false);
		bits = strtol(t2 + 1, NULL, 10);
		if (!isdigit((unsigned char)a[0]) || bits <= 0)
			return (false);
		snprintf(buf, blen, "%s/%ld", a, bits);
		return (true);
	} else {
		/* The first word: "1.2.3.0/24 ; SBL1", "1.2.3.4 # x". */
		p = line;
		k = strcspn(p, " \t#;\r");
		if (k > n)
			k = n;
	}
	if (k == 0 || k >= blen)
		return (false);
	memcpy(buf, p, k);
	buf[k] = '\0';
	return (true);
}

#define	PROTECTED	"covers a protected address: the console, a host, or a " \
			"sign-in"

/*
 * An entry dropped, and why; one that covers a protected address with
 * which, and whose (detail; host, a host's id), which feed_json() gives
 * only to whom may see it.
 */
static void
dropped_add(ucl_object_t *dropped, size_t *ndropped, const char *entry,
    const char *why, const char *detail, const char *host)
{
	ucl_object_t	*o;

	(*ndropped)++;
	if (ucl_array_size(dropped) >= FEED_DROPPED)
		return;
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "entry", S(entry));
	put(o, "reason", S(why));
	if (detail != NULL)
		put(o, "detail", S(detail));
	if (host != NULL && host[0] != '\0')
		put(o, "host", S(host));
	ucl_array_append(dropped, o);
}

/*
 * A feed's text made its entries: each made canonical, once, those
 * another covers left out (counted in *covered); those dropped with why,
 * the first FEED_DROPPED of them, all counted in *ndropped.  NULL and
 * err when it has more than FEED_MAX or none at all.
 */
static ucl_object_t *
feed_parse(const char *text, size_t len, const char *format, bool keep_bogons,
    const struct prot *pv, size_t np, ucl_object_t *dropped, size_t *ndropped,
    size_t *covered, char *err, size_t errlen)
{
	struct pfx	*v, x;
	ucl_object_t	*out;
	const char	*p, *e, *end;
	char		 buf[80], s[80];
	size_t		 n, cap, i, k, lines, ln, nbad;
	bool		 bad;

	*ndropped = *covered = 0;
	cap = 4096;
	if ((v = calloc(cap, sizeof(*v))) == NULL) {
		snprintf(err, errlen, "out of memory");
		return (NULL);
	}
	n = lines = nbad = 0;
	end = text + len;
	for (p = text, ln = 1; p < end; p = e + 1, ln++) {
		if ((e = memchr(p, '\n', (size_t)(end - p))) == NULL)
			e = end;
		if (!line_entry(format, p, (size_t)(e - p), buf, sizeof(buf)))
			continue;
		lines++;
		/* Its line, not its words: a source is not to be read
		 * through the console. */
		if (!pfx_parse(buf, &x)) {
			snprintf(s, sizeof(s), "line %zu", ln);
			nbad++;
			dropped_add(dropped, ndropped, s, "not an address or "
			    "prefix", NULL, NULL);
			continue;
		}
		pfx_str(&x, s, sizeof(s));
		if (x.len == 0) {
			dropped_add(dropped, ndropped, s, "the whole address "
			    "space", NULL, NULL);
			continue;
		}
		bad = false;
		for (i = 0; i < np && !bad; i++)
			if (pfx_covers(&x, &pv[i].p)) {
				char	a[80], why[200];

				pfx_str(&pv[i].p, a, sizeof(a));
				a[strcspn(a, "/")] = '\0';
				snprintf(why, sizeof(why), "covers %s, %s", a,
				    pv[i].why);
				dropped_add(dropped, ndropped, s, PROTECTED, why,
				    pv[i].host);
				bad = true;
			}
		if (bad)
			continue;
		if (!keep_bogons && bogon(&x)) {
			dropped_add(dropped, ndropped, s, "private or reserved "
			    "space, which this feed does not list on purpose",
			    NULL, NULL);
			continue;
		}
		if (n >= FEED_MAX) {
			free(v);
			snprintf(err, errlen, "more than %d entries", FEED_MAX);
			return (NULL);
		}
		if (n == cap) {
			struct pfx	*nv;

			if ((nv = reallocarray(v, cap * 2, sizeof(*v))) == NULL) {
				free(v);
				snprintf(err, errlen, "out of memory");
				return (NULL);
			}
			v = nv;
			cap *= 2;
		}
		v[n++] = x;
	}
	if (lines == 0 || nbad == lines) {
		free(v);
		snprintf(err, errlen, "no entry in it: not a list of the format "
		    "%s", format);
		return (NULL);
	}
	/* Sorted, each once; one within the last kept is left out. */
	qsort(v, n, sizeof(*v), pfx_cmp);
	out = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0, k = SIZE_MAX; i < n; i++) {
		if (k != SIZE_MAX && pfx_covers(&v[k], &v[i])) {
			if (pfx_cmp(&v[k], &v[i]) != 0)
				(*covered)++;
			continue;
		}
		k = i;
		pfx_str(&v[i], s, sizeof(s));
		ucl_array_append(out, S(s));
	}
	free(v);
	return (out);
}

/* ---- What is kept --------------------------------------------------- */

static int
lock_take(void)
{
	char	path[MAXPATHLEN];
	int	fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, FEEDS_LOCK);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return (-1);
	(void)flock(fd, LOCK_EX);
	(void)cluster_lock(FEEDS_LOCK);
	return (fd);
}

static void
lock_give(int fd)
{

	if (fd != -1) {
		cluster_unlock(FEEDS_LOCK);
		close(fd);
	}
}

static ucl_object_t *
doc_load(const char *name, const char *key, int type)
{
	ucl_object_t	*o;

	if ((o = store_load(name)) == NULL || ucl_object_type(o) !=
	    UCL_OBJECT) {
		if (o != NULL)
			ucl_object_unref(o);
		o = ucl_object_typed_new(UCL_OBJECT);
	}
	if (key != NULL && ucl_object_lookup(o, key) == NULL)
		put(o, key, ucl_object_typed_new(type));
	return (o);
}

static const struct preset *
preset_of(const char *id)
{
	size_t	i;

	for (i = 0; id != NULL && i < nitems(presets); i++)
		if (strcmp(presets[i].id, id) == 0)
			return (&presets[i]);
	return (NULL);
}

static const ucl_object_t *
feed_by(const ucl_object_t *doc, const char *id)
{
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(doc, "feeds"), &it,
	    true)) != NULL)
		if (str(f, "id") != NULL && strcmp(str(f, "id"), id) == 0)
			return (f);
	return (NULL);
}

static bool
id_ok(const char *s)
{
	size_t	n;

	n = s != NULL ? strlen(s) : 0;
	return (n > 0 && n <= 24 && strspn(s, "abcdefghijklmnopqrstuvwxyz"
	    "0123456789-") == n && s[0] != '-');
}

/* An ipfw table's name: letters, digits, _ . -, not all digits. */
static bool
table_ok(const char *s)
{
	size_t	n;

	n = s != NULL ? strlen(s) : 0;
	return (n > 0 && n <= 48 && strspn(s, "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") == n &&
	    strspn(s, "0123456789") != n);
}

static void
table_default(const char *id, char *out, size_t len)
{
	size_t	i;

	snprintf(out, len, "feed_%s", id);
	for (i = 0; out[i] != '\0'; i++)
		if (out[i] == '-')
			out[i] = '_';
}

static int64_t
interval_of(const ucl_object_t *f)
{
	int64_t	h;

	h = num(f, "interval");
	return (h < FEED_FLOOR_H ? FEED_FLOOR_H : h);
}

/* A feed's entries, as kept: {"entries": [...], "sha256"}. */
static ucl_object_t *
entries_load(const char *id)
{
	char	name[64];

	snprintf(name, sizeof(name), "feeds/%s.json", id);
	return (store_load(name));
}

static void
sha_hex(const char *data, size_t len, char *out)
{
	unsigned char	md[32];
	unsigned int	n;
	int		i;

	out[0] = '\0';
	if (EVP_Digest(data, len, md, &n, EVP_sha256(), NULL) != 1)
		return;
	for (i = 0; i < 32; i++)
		snprintf(out + i * 2, 3, "%02x", md[i]);
}

/* The entries, a line each, to send; malloc'd. */
static char *
entries_text(const ucl_object_t *entries, size_t *lenp)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	FILE			*fp;
	char			*buf;
	size_t			 len;

	if ((fp = open_memstream(&buf, &len)) == NULL)
		return (NULL);
	it = NULL;
	while ((e = ucl_object_iterate(entries, &it, true)) != NULL)
		fprintf(fp, "%s\n", ucl_object_tostring(e));
	if (fclose(fp) != 0)
		return (NULL);
	if (lenp != NULL)
		*lenp = len;
	return (buf);
}

/* ---- Fetching ------------------------------------------------------ */

/*
 * Where a feed may come from: an address of the internet.  What
 * resolves to loopback, private, shared, link-local (a cloud's metadata
 * at 169.254.169.254), multicast or reserved space is refused, unless
 * Settings' feeds_allow_private lets its prefix through: the console is
 * not to be aimed at what only it can reach.
 */
static bool
addr_allowed(const struct pfx *a, char *err, size_t errlen)
{
	struct pfx	 p;
	char		*allow, *w, *next, s[80];
	bool		 ok;

	if (!bogon(a))
		return (true);
	ok = false;
	allow = settings_peek("feeds_allow_private");
	for (w = allow; w != NULL && *w != '\0' && !ok; w = next) {
		w += strspn(w, " ,");
		next = w + strcspn(w, " ,");
		if (*next != '\0')
			*next++ = '\0';
		if (*w != '\0' && pfx_parse(w, &p) && pfx_covers(&p, a))
			ok = true;
	}
	free(allow);
	if (!ok) {
		pfx_str(a, s, sizeof(s));
		s[strcspn(s, "/")] = '\0';
		snprintf(err, errlen, "%s is a private or reserved address: a "
		    "feed comes from the internet (Settings' "
		    "feeds_allow_private lets a prefix through)", s);
	}
	return (ok);
}

/* An http or https URL taken apart. */
struct hurl {
	bool	 tls;
	char	 host[256];
	char	 port[8];
	char	*doc;		/* the path and query, malloc'd */
};

static bool
hurl_parse(const char *url, struct hurl *h, char *err, size_t errlen)
{
	struct url	*u;

	memset(h, 0, sizeof(*h));
	if ((u = fetchParseURL(url)) == NULL || (strcmp(u->scheme, "http") !=
	    0 && strcmp(u->scheme, "https") != 0) || u->host[0] == '\0' ||
	    u->user[0] != '\0') {
		if (u != NULL)
			fetchFreeURL(u);
		snprintf(err, errlen, "a feed's url is https (or http), with a "
		    "host and no user");
		return (false);
	}
	h->tls = strcmp(u->scheme, "https") == 0;
	/* An IPv6 address without its brackets. */
	snprintf(h->host, sizeof(h->host), "%.*s", (int)strcspn(u->host +
	    (u->host[0] == '['), "]"), u->host + (u->host[0] == '['));
	snprintf(h->port, sizeof(h->port), "%d", u->port > 0 ? u->port :
	    h->tls ? 443 : 80);
	if ((h->doc = strdup(u->doc != NULL && u->doc[0] != '\0' ? u->doc :
	    "/")) == NULL)
		abort();
	fetchFreeURL(u);
	return (true);
}

/*
 * The host's addresses, every one allowed (one that is not and the rest
 * may be the one a second resolution gives); up to max in v.
 */
static int
hurl_resolve(const struct hurl *h, struct sockaddr_storage *v, int max,
    char *err, size_t errlen)
{
	struct addrinfo	 hints, *res, *ai;
	struct pfx	 p;
	int		 n, e;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	if ((e = getaddrinfo(h->host, h->port, &hints, &res)) != 0) {
		snprintf(err, errlen, "%s: %s", h->host, gai_strerror(e));
		return (-1);
	}
	n = 0;
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		memset(&p, 0, sizeof(p));
		if (ai->ai_family == AF_INET) {
			p.af = AF_INET;
			p.len = 32;
			memcpy(p.a, &((struct sockaddr_in *)(void *)ai->ai_addr)->
			    sin_addr, 4);
		} else if (ai->ai_family == AF_INET6) {
			p.af = AF_INET6;
			p.len = 128;
			memcpy(p.a, &((struct sockaddr_in6 *)(void *)ai->
			    ai_addr)->sin6_addr, 16);
		} else
			continue;
		if (!addr_allowed(&p, err, errlen)) {
			freeaddrinfo(res);
			return (-1);
		}
		if (n < max)
			memcpy(&v[n++], ai->ai_addr, ai->ai_addrlen);
	}
	freeaddrinfo(res);
	if (n == 0)
		snprintf(err, errlen, "%s has no address", h->host);
	return (n > 0 ? n : -1);
}

/* May a feed be fetched from the URL now?  Why not in err. */
static bool
url_allowed(const char *url, char *err, size_t errlen)
{
	struct sockaddr_storage	 v[8];
	struct hurl		 h;
	int			 n;

	if (!hurl_parse(url, &h, err, errlen))
		return (false);
	n = hurl_resolve(&h, v, (int)nitems(v), err, errlen);
	free(h.doc);
	return (n > 0);
}

static SSL_CTX		*feeds_ssl;
static pthread_once_t	 feeds_ssl_once = PTHREAD_ONCE_INIT;

/* The system's CAs, as fetch(1) has them; TLS 1.2 at least. */
static void
ssl_init(void)
{

	if ((feeds_ssl = SSL_CTX_new(TLS_client_method())) == NULL)
		return;
	(void)SSL_CTX_set_min_proto_version(feeds_ssl, TLS1_2_VERSION);
	SSL_CTX_set_verify(feeds_ssl, SSL_VERIFY_PEER, NULL);
	(void)SSL_CTX_set_default_verify_paths(feeds_ssl);
	if (access("/usr/local/etc/ssl/cert.pem", R_OK) == 0)
		(void)SSL_CTX_load_verify_locations(feeds_ssl,
		    "/usr/local/etc/ssl/cert.pem", NULL);
}

/* A connection to one of the addresses resolved, in the time left. */
static int
hurl_connect(const struct sockaddr_storage *v, int n, time_t deadline,
    char *err, size_t errlen)
{
	struct pollfd	 pfd;
	struct timeval	 tv;
	socklen_t	 sl;
	int		 i, s, e, left, fl;

	for (i = 0; i < n; i++) {
		if ((s = socket(v[i].ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0)) ==
		    -1)
			continue;
		fl = fcntl(s, F_GETFL);
		(void)fcntl(s, F_SETFL, fl | O_NONBLOCK);
		sl = v[i].ss_family == AF_INET ? sizeof(struct sockaddr_in) :
		    sizeof(struct sockaddr_in6);
		if (connect(s, (const struct sockaddr *)&v[i], sl) == -1 &&
		    errno != EINPROGRESS) {
			snprintf(err, errlen, "connect: %s", strerror(errno));
			close(s);
			continue;
		}
		left = (int)(deadline - time(NULL));
		pfd.fd = s;
		pfd.events = POLLOUT;
		e = 0;
		sl = sizeof(e);
		/* Ten seconds an address, so that one that never answers
		 * (an IPv6 route that goes nowhere) leaves time for the next. */
		if (left <= 0 || poll(&pfd, 1, MIN(left, i + 1 < n ? 10 : left) *
		    1000) != 1 ||
		    getsockopt(s, SOL_SOCKET, SO_ERROR, &e, &sl) != 0 || e != 0) {
			snprintf(err, errlen, "connect: %s", e != 0 ?
			    strerror(e) : "timed out");
			close(s);
			continue;
		}
		(void)fcntl(s, F_SETFL, fl);
		tv.tv_sec = left > 0 ? left : 1;
		tv.tv_usec = 0;
		(void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		(void)setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		return (s);
	}
	return (-1);
}

/* A chunked body made plain, in place; false when it is not one. */
static bool
dechunk(char *b, size_t *lenp)
{
	char	*r, *w, *end, *e;
	size_t	 n;

	r = w = b;
	end = b + *lenp;
	for (;;) {
		n = strtoul(r, &e, 16);
		if (e == r || (e = strstr(e, "\r\n")) == NULL || e >= end)
			return (false);
		r = e + 2;
		if (n == 0)
			break;
		if (n > (size_t)(end - r))
			return (false);
		memmove(w, r, n);
		w += n;
		r += n;
		if (r + 2 > end || r[0] != '\r' || r[1] != '\n')
			return (false);
		r += 2;
	}
	*lenp = (size_t)(w - b);
	return (true);
}

/* A header's value in the head (its lines), copied into out; or NULL. */
static const char *
header(const char *head, const char *name, char *out, size_t len)
{
	const char	*p, *e;
	size_t		 n;

	n = strlen(name);
	for (p = strstr(head, "\r\n"); p != NULL; p = strstr(p + 2, "\r\n")) {
		if (strncasecmp(p + 2, name, n) != 0 || p[2 + n] != ':')
			continue;
		p += 3 + n;
		p += strspn(p, " \t");
		e = strstr(p, "\r\n");
		snprintf(out, len, "%.*s", (int)(e != NULL ? e - p :
		    (ptrdiff_t)strlen(p)), p);
		return (out);
	}
	return (NULL);
}

/*
 * One request: GET of h at an address resolved and allowed (no second
 * resolution), TLS verified for its name; the reply whole in *bufp
 * (malloc'd), its head ending at *bodyp.  Its status, or -1 and err.
 */
static int
hurl_get(const struct hurl *h, time_t ims, time_t deadline, char **bufp,
    size_t *lenp, char **bodyp, char *err, size_t errlen)
{
	struct sockaddr_storage	 v[8];
	struct tm		 tm;
	SSL			*ssl;
	char			*buf, req[2048], date[64], *e;
	size_t			 len, cap;
	ssize_t			 r;
	int			 n, s, status;
	bool			 v6lit;

	*bufp = *bodyp = NULL;
	*lenp = 0;
	if ((n = hurl_resolve(h, v, (int)nitems(v), err, errlen)) < 0)
		return (-1);
	if ((s = hurl_connect(v, n, deadline, err, errlen)) == -1)
		return (-1);
	ssl = NULL;
	if (h->tls) {
		(void)pthread_once(&feeds_ssl_once, ssl_init);
		if (feeds_ssl == NULL || (ssl = SSL_new(feeds_ssl)) == NULL) {
			close(s);
			snprintf(err, errlen, "TLS: out of memory");
			return (-1);
		}
		/* The name the certificate is for: the URL's. */
		if (inet_pton(AF_INET, h->host, date) == 1 || inet_pton(AF_INET6,
		    h->host, date) == 1)
			(void)X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl),
			    h->host);
		else {
			char	sni[256];

			snprintf(sni, sizeof(sni), "%s", h->host);
			(void)SSL_set_tlsext_host_name(ssl, sni);
			(void)SSL_set1_host(ssl, h->host);
		}
		(void)SSL_set_fd(ssl, s);
		if (SSL_connect(ssl) != 1) {
			snprintf(err, errlen, "TLS with %s: %s", h->host,
			    SSL_get_verify_result(ssl) != X509_V_OK ?
			    X509_verify_cert_error_string(SSL_get_verify_result(
			    ssl)) : "handshake failed");
			SSL_free(ssl);
			close(s);
			return (-1);
		}
	}
	v6lit = strchr(h->host, ':') != NULL;
	date[0] = '\0';
	if (ims > 0 && gmtime_r(&ims, &tm) != NULL)
		strftime(date, sizeof(date), "If-Modified-Since: %a, %d %b %Y "
		    "%H:%M:%S GMT\r\n", &tm);
	n = snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: %s%s%s%s%s"
	    "\r\nUser-Agent: arcana-console/%s\r\nAccept: */*\r\nConnection: "
	    "close\r\n%s\r\n", h->doc, v6lit ? "[" : "", h->host, v6lit ? "]" :
	    "", strcmp(h->port, h->tls ? "443" : "80") == 0 ? "" : ":",
	    strcmp(h->port, h->tls ? "443" : "80") == 0 ? "" : h->port,
	    ARCW_VERSION, date);
	if (n <= 0 || (size_t)n >= sizeof(req) || (ssl != NULL ? SSL_write(ssl,
	    req, n) != n : write(s, req, (size_t)n) != n)) {
		snprintf(err, errlen, "the request could not be sent");
		goto fail;
	}
	cap = 65536;
	if ((buf = malloc(cap + 1)) == NULL)
		abort();
	len = 0;
	for (;;) {
		if (time(NULL) > deadline) {
			free(buf);
			snprintf(err, errlen, "timed out after %d s", FEED_TIMEOUT);
			goto fail;
		}
		if (len == cap) {
			if (cap > FEED_MAX_BYTES) {
				free(buf);
				snprintf(err, errlen, "more than 16 MB");
				goto fail;
			}
			cap *= 2;
			if ((buf = reallocf(buf, cap + 1)) == NULL)
				abort();
		}
		r = ssl != NULL ? SSL_read(ssl, buf + len, (int)(cap - len)) :
		    read(s, buf + len, cap - len);
		if (r <= 0) {
			if (ssl != NULL && r < 0 && SSL_get_error(ssl, (int)r) !=
			    SSL_ERROR_ZERO_RETURN && SSL_get_error(ssl, (int)r) !=
			    SSL_ERROR_SYSCALL) {
				free(buf);
				snprintf(err, errlen, "TLS: the reply was cut "
				    "short");
				goto fail;
			}
			if (ssl == NULL && r < 0) {
				free(buf);
				snprintf(err, errlen, "read: %s", strerror(errno));
				goto fail;
			}
			break;
		}
		len += (size_t)r;
	}
	if (ssl != NULL) {
		(void)SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	close(s);
	buf[len] = '\0';
	if (strncmp(buf, "HTTP/1.", 7) != 0 || (e = strstr(buf, "\r\n\r\n")) ==
	    NULL) {
		free(buf);
		snprintf(err, errlen, "no HTTP reply");
		return (-1);
	}
	status = atoi(buf + 9);
	*e = '\0';
	*bufp = buf;
	*bodyp = e + 4;
	*lenp = len - (size_t)(e + 4 - buf);
	return (status);
fail:
	if (ssl != NULL)
		SSL_free(ssl);
	close(s);
	return (-1);
}

/*
 * The feed's text: 0 and *bodyp (malloc'd), 1 when not modified since
 * ims, -1 and err.  Every address it is fetched from allowed, at each
 * of its redirects too, which are followed here (3 at most, never from
 * https to http).
 */
static int
fetch_url(const char *url, time_t ims, char **bodyp, size_t *lenp,
    time_t *lmp, char *err, size_t errlen)
{
	struct hurl	 h;
	struct tm	 tm;
	char		*buf, *body, loc[1024], next[1300], v[128];
	size_t		 len;
	time_t		 deadline;
	int		 status, hop;
	bool		 was_tls;

	*bodyp = NULL;
	*lenp = 0;
	*lmp = 0;
	deadline = time(NULL) + FEED_TIMEOUT;
	snprintf(next, sizeof(next), "%s", url);
	was_tls = false;
	for (hop = 0;; hop++) {
		if (!hurl_parse(next, &h, err, errlen))
			return (-1);
		if (was_tls && !h.tls) {
			free(h.doc);
			snprintf(err, errlen, "redirected from https to http: "
			    "refused");
			return (-1);
		}
		was_tls = h.tls;
		status = hurl_get(&h, ims, deadline, &buf, &len, &body, err,
		    errlen);
		if (status < 0) {
			free(h.doc);
			return (-1);
		}
		if (status != 301 && status != 302 && status != 303 && status !=
		    307 && status != 308)
			break;
		if (hop == 3 || header(buf, "Location", loc, sizeof(loc)) ==
		    NULL) {
			free(buf);
			free(h.doc);
			snprintf(err, errlen, hop == 3 ? "more than 3 redirects" :
			    "a redirect with no Location");
			return (-1);
		}
		/* An absolute path on the same host, or a URL. */
		if (loc[0] == '/')
			snprintf(next, sizeof(next), "%s://%s%s%s:%s%s", h.tls ?
			    "https" : "http", strchr(h.host, ':') != NULL ? "[" :
			    "", h.host, strchr(h.host, ':') != NULL ? "]" : "",
			    h.port, loc);
		else
			snprintf(next, sizeof(next), "%s", loc);
		free(buf);
		free(h.doc);
	}
	free(h.doc);
	if (status == 304) {
		free(buf);
		return (1);
	}
	if (status != 200) {
		free(buf);
		snprintf(err, errlen, "HTTP %d", status);
		return (-1);
	}
	if (header(buf, "Transfer-Encoding", v, sizeof(v)) != NULL &&
	    strcasestr(v, "chunked") != NULL && !dechunk(body, &len)) {
		free(buf);
		snprintf(err, errlen, "a chunked reply cut short");
		return (-1);
	}
	if (header(buf, "Last-Modified", v, sizeof(v)) != NULL) {
		memset(&tm, 0, sizeof(tm));
		if (strptime(v, "%a, %d %b %Y %H:%M:%S GMT", &tm) != NULL)
			*lmp = timegm(&tm);
	}
	if (len > FEED_MAX_BYTES) {
		free(buf);
		snprintf(err, errlen, "more than 16 MB");
		return (-1);
	}
	if ((*bodyp = malloc(len + 1)) == NULL)
		abort();
	memcpy(*bodyp, body, len);
	(*bodyp)[len] = '\0';
	*lenp = len;
	free(buf);
	return (0);
}

/* ---- Delivery ------------------------------------------------------ */

/* A table on a host: loaded (dry, a preview), what came back in o. */
static bool
host_load(const char *sid, const char *table, const char *id,
    const char *text, bool dry, ucl_object_t *o)
{
	cbl_conn	*conn;
	cbl_tls		*tls;
	ucl_object_t	*out;
	const char	*e;
	char		 uri[256], peer[256], name[128], err[300];
	int		 error;

	if (!host_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
	    sizeof(name))) {
		put(o, "error", S("no such host"));
		return (false);
	}
	put(o, "name", S(name));
	hosts_act_as(NULL);
	if ((e = hosts_connect(uri, peer, &conn, &tls)) != NULL) {
		put(o, "error", S(e));
		return (false);
	}
	out = NULL;
	err[0] = '\0';
	error = ynet_feed_load(conn, table, id, text, dry, &out, err,
	    sizeof(err));
	hosts_release(uri, peer, conn, tls, error == 0 || error == EIO);
	if (error != 0) {
		put(o, "error", S(err[0] != '\0' ? err : strerror(error)));
		return (false);
	}
	put(o, "count", I(num(out, "count")));
	put(o, "added", I(num(out, "added")));
	put(o, "removed", I(num(out, "removed")));
	put(o, "set", I(num(out, "set")));
	if (num(out, "left_out") > 0)
		put(o, "left_out", I(num(out, "left_out")));
	ucl_object_unref(out);
	return (true);
}

static bool
host_drop(const char *sid, const char *table, char *err, size_t errlen)
{
	cbl_conn	*conn;
	cbl_tls		*tls;
	const char	*e;
	char		 uri[256], peer[256], name[128];
	bool		 gone;
	int		 error;

	/* A host that is no more has nothing to drop. */
	if (!host_ref(sid, uri, sizeof(uri), peer, sizeof(peer), name,
	    sizeof(name)))
		return (true);
	hosts_act_as(NULL);
	if ((e = hosts_connect(uri, peer, &conn, &tls)) != NULL) {
		snprintf(err, errlen, "%s", e);
		return (false);
	}
	error = ynet_feed_drop(conn, table, &gone, err, errlen);
	hosts_release(uri, peer, conn, tls, error == 0 || error == EIO);
	return (error == 0);
}

/* ---- The work ------------------------------------------------------ */

static void
event_add(ucl_object_t *st, ucl_object_t *ev)
{
	ucl_object_t	*evs, *nv;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	size_t		 skip;

	evs = (ucl_object_t *)(uintptr_t)ucl_object_lookup(st, "events");
	nv = ucl_object_typed_new(UCL_ARRAY);
	skip = evs != NULL && ucl_array_size(evs) >= FEED_EVENTS ?
	    ucl_array_size(evs) - FEED_EVENTS + 1 : 0;
	it = NULL;
	while ((e = ucl_object_iterate(evs, &it, true)) != NULL)
		if (skip > 0)
			skip--;
		else
			ucl_array_append(nv, ucl_object_ref(e));
	ucl_array_append(nv, ev);
	put(st, "events", nv);
}

/* The alarm raised or cleared, and said where Settings say. */
static void
alarm_set(ucl_object_t *st, const ucl_object_t *f, bool raise,
    const char *why)
{
	ucl_object_t	*a;
	char		 subj[200], text[600], err[300];

	if (raise == (ucl_object_lookup(st, "alarm") != NULL))
		return;
	if (raise) {
		a = ucl_object_typed_new(UCL_OBJECT);
		put(a, "since", I(time(NULL)));
		put(a, "text", S(why));
		put(st, "alarm", a);
		snprintf(subj, sizeof(subj), "Arcana: threat feed %s is failing",
		    str(f, "name"));
		snprintf(text, sizeof(text), "The threat feed %s (%s) could "
		    "not be fetched %d times in a row: %s\nThe hosts keep its "
		    "last entries.", str(f, "name"), str(f, "url"), FEED_FAILS,
		    why);
		thread_log(LOG_WARNING, "feed %s: alarm raised: %s", str(f,
		    "id"), why);
	} else {
		(void)ucl_object_delete_key(st, "alarm");
		snprintf(subj, sizeof(subj), "Arcana: threat feed %s is back",
		    str(f, "name"));
		snprintf(text, sizeof(text), "The threat feed %s (%s) was "
		    "fetched again.", str(f, "name"), str(f, "url"));
		thread_log(LOG_NOTICE, "feed %s: alarm cleared", str(f, "id"));
	}
	(void)alert_send("all", subj, text, err, sizeof(err));
}

#define	RUN_FETCH	0	/* fetched when modified since the last */
#define	RUN_PREVIEW	1	/* fetched whole, each host's dry run */
#define	RUN_KEPT	2	/* the kept entries, to the hosts that lack them */

/*
 * One feed fetched, its entries kept when they changed and sent to each
 * of its hosts that has not them; a preview keeps nothing but what it
 * says.  st is the feed's state, changed.
 */
static void
feed_run(const ucl_object_t *f, ucl_object_t *st, int how)
{
	struct prot	*pv;
	ucl_object_t	*entries, *dropped, *kept, *hosts, *h, *o, *ev;
	const ucl_object_t	*sid, *was, *hw;
	ucl_object_iter_t	 it;
	char		*body, *text, err[300], sha[65], name[64], table[64];
	const char	*id;
	size_t		 blen, tlen, ndropped, covered, np;
	time_t		 lm, now;
	int		 rc;
	bool		 changed, dry;

	dry = how == RUN_PREVIEW;
	id = str(f, "id");
	now = time(NULL);
	snprintf(table, sizeof(table), "%s", str(f, "table"));
	if ((pv = calloc(PROT_MAX, sizeof(*pv))) == NULL)
		return;
	np = protected(pv);
	kept = entries_load(id);
	body = NULL;
	if (how == RUN_KEPT)
		rc = 1;
	else {
		put(st, "tried_at", I(now));
		rc = fetch_url(str(f, "url"), dry || kept == NULL ? 0 :
		    (time_t)num(st, "last_modified"), &body, &blen, &lm, err,
		    sizeof(err));
	}
	if (rc < 0) {
		free(pv);
		if (kept != NULL)
			ucl_object_unref(kept);
		if (dry) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "at", I(now));
			put(o, "error", S(err));
			put(st, "preview", o);
			return;
		}
		put(st, "error", S(err));
		put(st, "failures", I(num(st, "failures") + 1));
		thread_log(LOG_WARNING, "feed %s not fetched from %s: %s", id,
		    str(f, "url"), err);
		if (num(st, "failures") >= FEED_FAILS)
			alarm_set(st, f, true, err);
		return;
	}
	if (!dry && how != RUN_KEPT) {
		(void)ucl_object_delete_key(st, "error");
		put(st, "failures", I(0));
		alarm_set(st, f, false, NULL);
	}
	changed = false;
	entries = NULL;
	if (rc == 0) {
		dropped = ucl_object_typed_new(UCL_ARRAY);
		entries = feed_parse(body, blen, str(f, "format"), ucl_flag(f,
		    "bogons"), pv, np, dropped, &ndropped, &covered, err,
		    sizeof(err));
		free(body);
		if (entries == NULL) {
			ucl_object_unref(dropped);
			free(pv);
			if (kept != NULL)
				ucl_object_unref(kept);
			if (dry) {
				o = ucl_object_typed_new(UCL_OBJECT);
				put(o, "at", I(now));
				put(o, "error", S(err));
				put(st, "preview", o);
				return;
			}
			put(st, "error", S(err));
			put(st, "failures", I(num(st, "failures") + 1));
			if (num(st, "failures") >= FEED_FAILS)
				alarm_set(st, f, true, err);
			return;
		}
		if ((text = entries_text(entries, &tlen)) == NULL) {
			ucl_object_unref(entries);
			ucl_object_unref(dropped);
			free(pv);
			if (kept != NULL)
				ucl_object_unref(kept);
			return;
		}
		sha_hex(text, tlen, sha);
		free(text);
		if (dry) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "at", I(now));
			put(o, "count", I((int64_t)ucl_array_size(entries)));
			put(o, "dropped_count", I((int64_t)ndropped));
			put(o, "covered", I((int64_t)covered));
			put(o, "dropped", dropped);
			put(st, "preview", o);
		} else {
			changed = kept == NULL || str(kept, "sha256") == NULL ||
			    strcmp(str(kept, "sha256"), sha) != 0;
			put(st, "fetched_at", I(now));
			if (lm > 0)
				put(st, "last_modified", I(lm));
			put(st, "dropped", dropped);
			put(st, "dropped_count", I((int64_t)ndropped));
			put(st, "covered", I((int64_t)covered));
			if (changed) {
				int64_t	 before;

				before = kept != NULL ? (int64_t)ucl_array_size(
				    ucl_object_lookup(kept, "entries")) : 0;
				o = ucl_object_typed_new(UCL_OBJECT);
				put(o, "entries", ucl_object_ref(entries));
				put(o, "sha256", S(sha));
				snprintf(name, sizeof(name), "feeds/%s.json", id);
				(void)store_save(name, o);
				ucl_object_unref(o);
				put(st, "sha256", S(sha));
				put(st, "count", I((int64_t)ucl_array_size(
				    entries)));
				put(st, "changed_at", I(now));
				ev = ucl_object_typed_new(UCL_OBJECT);
				put(ev, "at", I(now));
				put(ev, "count", I((int64_t)ucl_array_size(
				    entries)));
				put(ev, "was", I(before));
				event_add(st, ev);
				thread_log(LOG_INFO, "feed %s: %u entries, %jd "
				    "before", id, ucl_array_size(entries),
				    (intmax_t)before);
			}
		}
	} else {
		/* Not modified: the kept entries, to the hosts that lack
		 * them. */
		if (how != RUN_KEPT)
			put(st, "fetched_at", I(now));
		if (kept != NULL && ucl_object_lookup(kept, "entries") != NULL)
			entries = ucl_object_ref(ucl_object_lookup(kept,
			    "entries"));
		snprintf(sha, sizeof(sha), "%s", kept != NULL && str(kept,
		    "sha256") != NULL ? str(kept, "sha256") : "");
	}
	free(pv);
	if (kept != NULL)
		ucl_object_unref(kept);
	if (entries == NULL)
		return;
	/* Each host: those that have them already are left alone. */
	if ((text = entries_text(entries, NULL)) == NULL) {
		ucl_object_unref(entries);
		return;
	}
	ucl_object_unref(entries);
	hosts = dry ? (ucl_object_t *)(uintptr_t)ucl_object_lookup(
	    ucl_object_lookup(st, "preview"), "hosts") :
	    (ucl_object_t *)(uintptr_t)ucl_object_lookup(st, "hosts");
	if (hosts == NULL) {
		hosts = ucl_object_typed_new(UCL_OBJECT);
		put(dry ? (ucl_object_t *)(uintptr_t)ucl_object_lookup(st,
		    "preview") : st, "hosts", hosts);
	}
	it = NULL;
	while ((sid = ucl_object_iterate(ucl_object_lookup(f, "hosts"), &it,
	    true)) != NULL) {
		const char	*s = ucl_object_tostring(sid);

		was = ucl_object_lookup(ucl_object_lookup(st, "hosts"), s);
		if (!dry && was != NULL && str(was, "sha256") != NULL &&
		    strcmp(str(was, "sha256"), sha) == 0 && str(was, "table") !=
		    NULL && strcmp(str(was, "table"), table) == 0 && str(was,
		    "error") == NULL)
			continue;
		if (!dry && was != NULL && str(was, "error") != NULL && now -
		    num(was, "tried_at") < FEED_HOST_RETRY && !changed &&
		    how == RUN_KEPT)
			continue;
		/* Its table renamed: the old one given up first. */
		if (!dry && was != NULL && str(was, "sha256") != NULL && str(was,
		    "table") != NULL && strcmp(str(was, "table"), table) != 0 &&
		    !host_drop(s, str(was, "table"), err, sizeof(err)))
			thread_log(LOG_WARNING, "feed %s: table %s on %s not given "
			    "up: %s", id, str(was, "table"), s, err);
		h = ucl_object_typed_new(UCL_OBJECT);
		put(h, "tried_at", I(now));
		put(h, "table", S(table));
		if (host_load(s, table, id, text, dry, h)) {
			put(h, "at", I(now));
			if (!dry)
				put(h, "sha256", S(sha));
		} else if (!dry && was != NULL && str(was, "sha256") != NULL) {
			/* What it has still. */
			put(h, "sha256", S(str(was, "sha256")));
			if ((hw = ucl_object_lookup(was, "at")) != NULL)
				put(h, "at", I(ucl_object_toint(hw)));
			if ((hw = ucl_object_lookup(was, "count")) != NULL &&
			    ucl_object_lookup(h, "count") == NULL)
				put(h, "count", I(ucl_object_toint(hw)));
		}
		put(hosts, s, h);
	}
	free(text);
}

/*
 * The tables of hosts a feed is no longer for, or of a feed disabled or
 * gone, given up on those hosts: only what the feed itself made (the
 * agent refuses any other table).
 */
static void
feed_unload(const ucl_object_t *f, ucl_object_t *st)
{
	ucl_object_t		*hosts, *gone;
	const ucl_object_t	*h, *sid;
	ucl_object_iter_t	 it, sit;
	char			 err[300];
	bool			 want;

	if ((hosts = (ucl_object_t *)(uintptr_t)ucl_object_lookup(st,
	    "hosts")) == NULL)
		return;
	gone = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((h = ucl_object_iterate(hosts, &it, true)) != NULL) {
		want = false;
		sit = NULL;
		while (f != NULL && ucl_flag(f, "enabled") && (sid =
		    ucl_object_iterate(ucl_object_lookup(f, "hosts"), &sit,
		    true)) != NULL)
			if (strcmp(ucl_object_tostring(sid), ucl_object_key(h)) ==
			    0 && str(h, "table") != NULL && strcmp(str(h,
			    "table"), str(f, "table")) == 0)
				want = true;
		if (want)
			continue;
		/* Never loaded there: nothing to give up. */
		if (str(h, "sha256") == NULL) {
			ucl_array_append(gone, S(ucl_object_key(h)));
			continue;
		}
		if (time(NULL) - num(h, "drop_tried") < FEED_HOST_RETRY)
			continue;
		err[0] = '\0';
		if (host_drop(ucl_object_key(h), str(h, "table") != NULL ?
		    str(h, "table") : "", err, sizeof(err)))
			ucl_array_append(gone, S(ucl_object_key(h)));
		else {
			put((ucl_object_t *)(uintptr_t)h, "drop_tried", I(time(
			    NULL)));
			put((ucl_object_t *)(uintptr_t)h, "drop_error", S(err));
		}
	}
	it = NULL;
	while ((h = ucl_object_iterate(gone, &it, true)) != NULL)
		(void)ucl_object_delete_key(hosts, ucl_object_tostring(h));
	ucl_object_unref(gone);
}

/* The asks taken: {id: "fetch" | "preview"}, emptied. */
static ucl_object_t *
asks_take(void)
{
	ucl_object_t	*a;
	int		 fd;

	/* Looked at without the lock, as a rule there is nothing. */
	if ((a = store_load(FEEDS_ASKS)) == NULL || obj_len(a) == 0)
		return (a);
	ucl_object_unref(a);
	fd = lock_take();
	a = store_load(FEEDS_ASKS);
	if (a != NULL && ucl_object_type(a) == UCL_OBJECT && obj_len(a) > 0) {
		ucl_object_t	*empty = ucl_object_typed_new(UCL_OBJECT);

		(void)store_save(FEEDS_ASKS, empty);
		ucl_object_unref(empty);
	}
	lock_give(fd);
	return (a);
}

static void
ask(const char *id, const char *what)
{
	ucl_object_t	*a;
	int		 fd;

	fd = lock_take();
	a = doc_load(FEEDS_ASKS, NULL, UCL_OBJECT);
	put(a, id, S(what));
	(void)store_save(FEEDS_ASKS, a);
	ucl_object_unref(a);
	lock_give(fd);
}

/* One look: what is asked, what is due, what is to be given up. */
static void
feeds_tick(bool due)
{
	ucl_object_t		*doc, *state, *asks, *st;
	const ucl_object_t	*f, *s, *a;
	ucl_object_iter_t	 it;
	ucl_object_t		*gone;
	char			 name[64];
	int			 fd;
	time_t			 now;
	bool			 any;

	asks = asks_take();
	if (!due && obj_len(asks) == 0) {
		if (asks != NULL)
			ucl_object_unref(asks);
		return;
	}
	pthread_mutex_lock(&run_lock);
	host_refs();
	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	state = doc_load(FEEDS_STATE, NULL, UCL_OBJECT);
	lock_give(fd);
	now = time(NULL);
	any = false;
	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(doc, "feeds"), &it,
	    true)) != NULL) {
		const char	*id = str(f, "id");

		if (id == NULL)
			continue;
		if ((st = (ucl_object_t *)(uintptr_t)ucl_object_lookup(state,
		    id)) == NULL) {
			st = ucl_object_typed_new(UCL_OBJECT);
			put(state, id, st);
		}
		a = asks != NULL ? ucl_object_lookup(asks, id) : NULL;
		if (a != NULL && strcmp(ucl_object_tostring(a), "preview") ==
		    0) {
			feed_run(f, st, RUN_PREVIEW);
			any = true;
			continue;
		}
		if (!ucl_flag(f, "enabled") || (a != NULL && strcmp(
		    ucl_object_tostring(a), "fetch") != 0)) {
			feed_unload(f, st);
			any = true;
			continue;
		}
		if (a != NULL || now - num(st, "tried_at") >= interval_of(f) *
		    3600 || (num(st, "failures") > 0 && now - num(st,
		    "tried_at") >= FEED_FLOOR_H * 3600)) {
			feed_run(f, st, RUN_FETCH);
			any = true;
		} else if (due) {
			/* Hosts that lack the entries, or failed. */
			const ucl_object_t	*sid, *h;
			ucl_object_iter_t	 sit;
			bool			 lack = false;

			sit = NULL;
			while ((sid = ucl_object_iterate(ucl_object_lookup(f,
			    "hosts"), &sit, true)) != NULL) {
				h = ucl_object_lookup(ucl_object_lookup(st,
				    "hosts"), ucl_object_tostring(sid));
				if (str(st, "sha256") != NULL && (h == NULL ||
				    str(h, "sha256") == NULL || strcmp(str(h,
				    "sha256"), str(st, "sha256")) != 0 || str(h,
				    "error") != NULL) && (h == NULL || now -
				    num(h, "tried_at") >= FEED_HOST_RETRY))
					lack = true;
			}
			if (lack) {
				feed_run(f, st, RUN_KEPT);
				any = true;
			}
		}
		feed_unload(f, st);
	}
	/* The state of a feed that is gone, once its tables are. */
	gone = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((s = ucl_object_iterate(state, &it, true)) != NULL) {
		if (feed_by(doc, ucl_object_key(s)) != NULL)
			continue;
		feed_unload(NULL, (ucl_object_t *)(uintptr_t)s);
		any = true;
		if (obj_len(ucl_object_lookup(s, "hosts")) == 0)
			ucl_array_append(gone, S(ucl_object_key(s)));
	}
	it = NULL;
	while ((s = ucl_object_iterate(gone, &it, true)) != NULL) {
		(void)ucl_object_delete_key(state, ucl_object_tostring(s));
		snprintf(name, sizeof(name), "feeds/%s.json",
		    ucl_object_tostring(s));
		(void)store_remove(name);
	}
	ucl_object_unref(gone);
	if (any) {
		fd = lock_take();
		(void)store_save(FEEDS_STATE, state);
		lock_give(fd);
		cyang_changed("threat-feeds");
	}
	ucl_object_unref(doc);
	ucl_object_unref(state);
	if (asks != NULL)
		ucl_object_unref(asks);
	pthread_mutex_unlock(&run_lock);
}

static void *
feeds_main(void *arg __unused)
{
	unsigned int	n;

	for (n = 0;; n++) {
		sleep(FEEDS_TICK);
		/* Of a cluster, the leader's alone. */
		if (cluster_leads())
			feeds_tick(n % (60 / FEEDS_TICK) == 0);
	}
	return (NULL);
}

/* At the worker's start: the one that takes the lock does the work. */
void
feeds_init(void)
{
	pthread_t	tid;
	char		path[MAXPATHLEN];
	int		fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, FEEDS_RUN);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return;
	if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
		close(fd);
		return;
	}
	if (pthread_create(&tid, NULL, feeds_main, NULL) == 0)
		(void)pthread_detach(tid);
}

/* ---- The API -------------------------------------------------------- */

static ucl_object_t *
presets_json(void)
{
	ucl_object_t	*arr, *o;
	size_t		 i;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nitems(presets); i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "id", S(presets[i].id));
		put(o, "name", S(presets[i].name));
		put(o, "url", S(presets[i].url));
		put(o, "format", S(presets[i].format));
		put(o, "what", S(presets[i].what));
		put(o, "terms", S(presets[i].terms));
		put(o, "terms_url", S(presets[i].terms_url));
		put(o, "interval", I(presets[i].interval));
		put(o, "bogons", B(presets[i].bogons));
		ucl_array_append(arr, o);
	}
	return (arr);
}

/*
 * What a feed dropped, as the request's user may see it.  The console's
 * owners see it all.  To anyone else an entry dropped as it covers a
 * protected address is listed only when it is a host's that the user
 * may read, with which address; any other (the console's, another
 * host's, a sign-in's) is only counted, in *hiddenp, as a feed of
 * chosen addresses would otherwise tell which of them are protected.
 */
static ucl_object_t *
dropped_for(struct http_request *req, const ucl_object_t *dropped,
    int64_t *hiddenp)
{
	ucl_object_t		*out, *o;
	const ucl_object_t	*d;
	ucl_object_iter_t	 it;
	bool			 owner;

	*hiddenp = 0;
	owner = user_console(session_user(req)) == CROLE_OWNER;
	out = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((d = ucl_object_iterate(dropped, &it, true)) != NULL) {
		if (!owner && str(d, "detail") != NULL && (str(d, "host") ==
		    NULL || !host_role_ok(req, str(d, "host"), false, false))) {
			(*hiddenp)++;
			continue;
		}
		o = ucl_object_copy(d);
		(void)ucl_object_delete_key(o, "host");
		ucl_array_append(out, o);
	}
	return (out);
}

static bool	is_owner(struct http_request *);

/*
 * Every per-host part of a feed as the request's user may see it: of a
 * list of host ids, or an object keyed by them (what each host was sent,
 * its name and errors), those the user may read; the rest only counted
 * in *hiddenp.  The console's owners see them all.
 */
static ucl_object_t *
hosts_for(struct http_request *req, const ucl_object_t *o, int64_t *hiddenp)
{
	ucl_object_t		*out;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*sid;
	bool			 owner, arr;

	*hiddenp = 0;
	arr = ucl_object_type(o) == UCL_ARRAY;
	out = ucl_object_typed_new(arr ? UCL_ARRAY : UCL_OBJECT);
	owner = is_owner(req);
	it = NULL;
	while ((e = ucl_object_iterate(o, &it, true)) != NULL) {
		sid = arr ? ucl_object_tostring_forced(e) : ucl_object_key(e);
		if (sid == NULL || (!owner && (server_find(sid) == NULL ||
		    !host_role_ok(req, sid, false, false)))) {
			(*hiddenp)++;
			continue;
		}
		if (arr)
			ucl_array_append(out, S(sid));
		else
			put(out, sid, ucl_object_copy(e));
	}
	return (out);
}

/* A feed and what its state says, for a page: whole with full. */
static ucl_object_t *
feed_json(struct http_request *req, const ucl_object_t *f,
    const ucl_object_t *st, bool full)
{
	static const char *const keys[] = { "fetched_at", "tried_at",
	    "changed_at", "count", "dropped_count", "covered", "failures" };
	ucl_object_t		*o, *ents, *sample;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int64_t			 hidden;
	size_t			 i;

	o = ucl_object_copy(f);
	/* Its hosts, those the user may read; the others counted. */
	put(o, "hosts", hosts_for(req, ucl_object_lookup(f, "hosts"),
	    &hidden));
	if (hidden > 0)
		put(o, "hosts_hidden", I(hidden));
	for (i = 0; i < nitems(keys); i++)
		if (ucl_object_lookup(st, keys[i]) != NULL)
			put(o, keys[i], I(num(st, keys[i])));
	if (str(st, "error") != NULL)
		put(o, "error", S(str(st, "error")));
	if (ucl_object_lookup(st, "alarm") != NULL)
		put(o, "alarm", ucl_object_copy(ucl_object_lookup(st, "alarm")));
	put(o, "delivered", hosts_for(req, ucl_object_lookup(st, "hosts"),
	    &hidden));
	if (hidden > 0)
		put(o, "delivered_hidden", I(hidden));
	if (!full)
		return (o);
	put(o, "dropped", dropped_for(req, ucl_object_lookup(st, "dropped"),
	    &hidden));
	if (hidden > 0)
		put(o, "protected_hidden", I(hidden));
	put(o, "events", ucl_object_lookup(st, "events") != NULL ?
	    ucl_object_copy(ucl_object_lookup(st, "events")) :
	    ucl_object_typed_new(UCL_ARRAY));
	if (ucl_object_lookup(st, "preview") != NULL) {
		ucl_object_t	*pv;

		pv = ucl_object_copy(ucl_object_lookup(st, "preview"));
		put(pv, "dropped", dropped_for(req, ucl_object_lookup(pv,
		    "dropped"), &hidden));
		if (hidden > 0)
			put(pv, "protected_hidden", I(hidden));
		put(pv, "hosts", hosts_for(req, ucl_object_lookup(pv, "hosts"),
		    &hidden));
		if (hidden > 0)
			put(pv, "hosts_hidden", I(hidden));
		put(o, "preview", pv);
	}
	/* The first entries, to see what it holds. */
	sample = ucl_object_typed_new(UCL_ARRAY);
	if ((ents = entries_load(str(f, "id"))) != NULL) {
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(ents,
		    "entries"), &it, true)) != NULL && ucl_array_size(sample) <
		    200)
			ucl_array_append(sample, ucl_object_ref(e));
		ucl_object_unref(ents);
	}
	put(o, "sample", sample);
	return (o);
}

/* GET /api/feeds: the presets and the feeds, each with its state. */
int
api_feeds(struct http_request *req)
{
	ucl_object_t		*doc, *state, *out, *arr;
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;
	int			 fd;

	if (req->method != HTTP_METHOD_GET)
		return (reply_error(req, 405, "method", "GET"));
	if (!guard(req, false))
		return (WEB_OK);
	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	state = doc_load(FEEDS_STATE, NULL, UCL_OBJECT);
	lock_give(fd);
	out = ucl_object_typed_new(UCL_OBJECT);
	put(out, "presets", presets_json());
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(doc, "feeds"), &it,
	    true)) != NULL)
		ucl_array_append(arr, feed_json(req, f, ucl_object_lookup(state,
		    str(f, "id")), false));
	put(out, "feeds", arr);
	put(out, "floor", I(FEED_FLOOR_H));
	put(out, "max_entries", I(FEED_MAX));
	ucl_object_unref(doc);
	ucl_object_unref(state);
	return (reply_json(req, 200, out));
}

/* A feed as it is to be kept, from body and what a preset says. */
static ucl_object_t *
feed_check(struct http_request *req, const char *id, const ucl_object_t *body,
    const ucl_object_t *doc, char *err, size_t errlen)
{
	const struct preset	*pr;
	const ucl_object_t	*v, *e, *g;
	ucl_object_iter_t	 it, git;
	ucl_object_t		*f, *hosts;
	const char		*url, *fmt, *name, *table;
	char			 tdef[64];
	int64_t			 h;
	size_t			 i;

	pr = preset_of(str(body, "preset") != NULL ? str(body, "preset") :
	    id);
	if (str(body, "preset") != NULL && pr == NULL) {
		snprintf(err, errlen, "no such preset");
		return (NULL);
	}
	url = str(body, "url") != NULL ? str(body, "url") : pr != NULL ?
	    pr->url : NULL;
	if (url == NULL || strlen(url) > 500 || (strncmp(url, "https://", 8) !=
	    0 && strncmp(url, "http://", 7) != 0)) {
		snprintf(err, errlen, "a feed's url is https (or http)");
		return (NULL);
	}
	for (i = 0; url[i] != '\0'; i++)
		if (isspace((unsigned char)url[i]) || iscntrl((unsigned char)
		    url[i])) {
			snprintf(err, errlen, "a url has no spaces");
			return (NULL);
		}
	/* A preset's own source is the internet's; checked at each fetch,
	 * as every other. */
	if ((pr == NULL || strcmp(url, pr->url) != 0) && !url_allowed(url, err,
	    errlen))
		return (NULL);
	fmt = str(body, "format") != NULL ? str(body, "format") : pr != NULL ?
	    pr->format : "plain";
	for (i = 0; i < nitems(formats) && strcmp(formats[i], fmt) != 0; i++)
		;
	if (i == nitems(formats)) {
		snprintf(err, errlen, "a format is plain, spamhaus-json or "
		    "dshield");
		return (NULL);
	}
	name = str(body, "name") != NULL ? str(body, "name") : pr != NULL ?
	    pr->name : id;
	if (strlen(name) == 0 || strlen(name) > 80) {
		snprintf(err, errlen, "a name is 80 characters at most");
		return (NULL);
	}
	for (i = 0; name[i] != '\0'; i++)
		if (iscntrl((unsigned char)name[i])) {
			snprintf(err, errlen, "a name has no control characters");
			return (NULL);
		}
	table_default(id, tdef, sizeof(tdef));
	table = str(body, "table") != NULL && str(body, "table")[0] != '\0' ?
	    str(body, "table") : tdef;
	if (!table_ok(table)) {
		snprintf(err, errlen, "an ipfw table's name is letters, digits, "
		    "_ . and -, 48 at most, not digits alone");
		return (NULL);
	}
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(doc, "feeds"), &it,
	    true)) != NULL)
		if (strcmp(str(e, "id"), id) != 0 && str(e, "table") != NULL &&
		    strcmp(str(e, "table"), table) == 0) {
			snprintf(err, errlen, "feed %s fills table %s already",
			    str(e, "id"), table);
			return (NULL);
		}
	h = (v = ucl_object_lookup(body, "interval")) != NULL ?
	    ucl_object_toint(v) : pr != NULL ? pr->interval : 6;
	if ((v != NULL && ucl_object_type(v) != UCL_INT) || h < FEED_FLOOR_H ||
	    h > 24 * 30) {
		snprintf(err, errlen, "the interval is hours, %d to 720",
		    FEED_FLOOR_H);
		return (NULL);
	}
	hosts = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((g = ucl_object_iterate(ucl_object_lookup(body, "hosts"), &it,
	    true)) != NULL) {
		const char	*sid = ucl_object_tostring_forced(g);

		if (server_find(sid) == NULL || !host_role_ok(req, sid, true,
		    false)) {
			ucl_object_unref(hosts);
			snprintf(err, errlen, "host %s is not one you may change",
			    sid);
			return (NULL);
		}
		git = NULL;
		for (e = NULL; (e = ucl_object_iterate(hosts, &git, true)) !=
		    NULL;)
			if (strcmp(ucl_object_tostring(e), sid) == 0)
				break;
		if (e == NULL)
			ucl_array_append(hosts, S(sid));
	}
	f = ucl_object_typed_new(UCL_OBJECT);
	put(f, "id", S(id));
	put(f, "name", S(name));
	put(f, "url", S(url));
	put(f, "format", S(fmt));
	put(f, "interval", I(h));
	put(f, "enabled", B(ucl_flag(body, "enabled")));
	put(f, "table", S(table));
	put(f, "bogons", B(ucl_object_lookup(body, "bogons") != NULL ?
	    ucl_flag(body, "bogons") : pr != NULL && pr->bogons));
	if (pr != NULL)
		put(f, "preset", S(pr->id));
	put(f, "hosts", hosts);
	return (f);
}

/*
 * May the request's user change every host the feed is on and every one
 * it was sent to, whose tables a change replaces or gives up?  NULL, or
 * the first that the user may not, by its name.
 */
static const char *
hosts_denied(struct http_request *req, const ucl_object_t *f,
    const ucl_object_t *st)
{
	const struct server	*sv;
	const ucl_object_t	*h;
	ucl_object_iter_t	 it;
	const char		*sid;

	it = NULL;
	while ((h = ucl_object_iterate(ucl_object_lookup(f, "hosts"), &it,
	    true)) != NULL) {
		sid = ucl_object_tostring_forced(h);
		if ((sv = server_find(sid)) != NULL && !host_role_ok(req, sid,
		    true, false))
			return (sv->name);
	}
	it = NULL;
	while ((h = ucl_object_iterate(ucl_object_lookup(st, "hosts"), &it,
	    true)) != NULL) {
		sid = ucl_object_key(h);
		if ((sv = server_find(sid)) != NULL && !host_role_ok(req, sid,
		    true, false))
			return (sv->name);
	}
	return (NULL);
}

/*
 * Is the feed fetched from a URL of one's own, not its preset's?  Only a
 * console owner makes one, changes one or previews one: what such a
 * feed drops, counted even, tells of the addresses no feed may cut off.
 */
static bool
feed_custom(const ucl_object_t *f)
{
	const struct preset	*pr;

	return ((pr = preset_of(str(f, "preset"))) == NULL || str(f, "url") ==
	    NULL || strcmp(str(f, "url"), pr->url) != 0);
}

static bool
is_owner(struct http_request *req)
{

	return (user_console(session_user(req)) == CROLE_OWNER);
}

/* Does b say what a does of key? */
static bool
same_key(const ucl_object_t *a, const ucl_object_t *b, const char *key)
{
	const ucl_object_t	*x, *y;

	x = ucl_object_lookup(a, key);
	y = ucl_object_lookup(b, key);
	if (x == NULL || y == NULL)
		return (x == y);
	return (strcmp(ucl_object_tostring_forced(x),
	    ucl_object_tostring_forced(y)) == 0);
}

/* The feed's hosts_denied(), as kept. */
static const char *
feed_denied(struct http_request *req, const char *id)
{
	ucl_object_t		*doc, *state;
	const ucl_object_t	*f;
	static __thread char	 name[128];
	const char		*who;
	int			 fd;

	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	state = doc_load(FEEDS_STATE, NULL, UCL_OBJECT);
	lock_give(fd);
	f = feed_by(doc, id);
	who = hosts_denied(req, f, ucl_object_lookup(state, id));
	if (who != NULL)
		snprintf(name, sizeof(name), "%s", who);
	ucl_object_unref(doc);
	ucl_object_unref(state);
	return (who != NULL ? name : NULL);
}

/*
 * Feed id kept as body says, as the request's user may: every host it
 * is on and was sent to the user's to change, its hosts too, a URL of
 * one's own an owner's (an operator enables, disables or chooses the
 * hosts of such a feed), the URL an address of the internet; fetched at
 * once when enabled.  Dry, checked alone.  The feed kept into *keptp
 * when asked.  0, or the HTTP status and why.
 */
static int
feed_put(struct http_request *req, const char *id, const ucl_object_t *body,
    bool dry, ucl_object_t **keptp, char *err, size_t errlen)
{
	ucl_object_t		*doc, *f, *arr;
	const ucl_object_t	*e, *was;
	ucl_object_iter_t	 it;
	const char		*who;
	int			 fd;

	if (!id_ok(id)) {
		snprintf(err, errlen, "a feed is named by lower-case letters, "
		    "digits and -, 24 at most");
		return (400);
	}
	/* What changes the feed changes its hosts' tables: each of them,
	 * those it was sent to too, the user's to change. */
	if ((who = feed_denied(req, id)) != NULL) {
		snprintf(err, errlen, "host %s is not one you may change, and "
		    "the feed's table is on it", who);
		return (403);
	}
	if (body == NULL || ucl_object_type(body) != UCL_OBJECT) {
		snprintf(err, errlen, "a feed, as {\"name\", \"url\", "
		    "\"format\", \"interval\", \"enabled\", \"hosts\", "
		    "\"table\"}, or {\"preset\"}");
		return (400);
	}
	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	was = feed_by(doc, id);
	if (was == NULL && ucl_array_size(ucl_object_lookup(doc, "feeds")) >=
	    FEEDS_MAX) {
		lock_give(fd);
		ucl_object_unref(doc);
		snprintf(err, errlen, "%d feeds at most", FEEDS_MAX);
		return (400);
	}
	if ((f = feed_check(req, id, body, doc, err, errlen)) == NULL) {
		lock_give(fd);
		ucl_object_unref(doc);
		return (400);
	}
	/* A URL of one's own: a console owner's to set and to change; an
	 * operator enables such a feed, disables it, chooses its hosts. */
	if (!is_owner(req) && feed_custom(f)) {
		static const char *const keys[] = { "name", "url", "format",
		    "bogons", "table", "interval" };
		size_t	 k;
		bool	 same = was != NULL && feed_custom(was);

		for (k = 0; same && k < nitems(keys); k++)
			same = same_key(was, f, keys[k]);
		if (!same) {
			lock_give(fd);
			ucl_object_unref(doc);
			ucl_object_unref(f);
			snprintf(err, errlen, "a feed from a URL of one's own is "
			    "made and changed by a console owner alone: an "
			    "operator uses the presets, and enables, disables or "
			    "chooses the hosts of such a feed");
			return (403);
		}
	}
	if (dry) {
		lock_give(fd);
		ucl_object_unref(doc);
		ucl_object_unref(f);
		return (0);
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(doc, "feeds"), &it,
	    true)) != NULL)
		ucl_array_append(arr, strcmp(str(e, "id"), id) == 0 ?
		    ucl_object_ref(f) : ucl_object_ref(e));
	if (was == NULL)
		ucl_array_append(arr, ucl_object_ref(f));
	put(doc, "feeds", arr);
	if (store_save(FEEDS_FILE, doc) != 0) {
		lock_give(fd);
		ucl_object_unref(doc);
		ucl_object_unref(f);
		snprintf(err, errlen, "the feeds could not be written");
		return (500);
	}
	lock_give(fd);
	audit_add(was == NULL ? "feed-added" : "feed-changed", "Administer",
	    id, FEEDS_FILE, "the console", session_user(req), "threat feed %s "
	    "%s: %s, every %jd h, %s, "
	    "table %s on %u hosts", id, was == NULL ? "added" : "changed",
	    str(f, "url"), (intmax_t)num(f, "interval"), ucl_flag(f, "enabled") ?
	    "enabled" : "disabled", str(f, "table"), ucl_array_size(
	    ucl_object_lookup(f, "hosts")));
	ask(id, ucl_flag(f, "enabled") ? "fetch" : "unload");
	ucl_object_unref(doc);
	cyang_changed("threat-feeds");
	if (keptp != NULL)
		*keptp = f;
	else
		ucl_object_unref(f);
	return (0);
}

/* Feed id taken away, its tables given up, as the request's user may;
 * dry, checked alone.  0, or the HTTP status and why. */
static int
feed_remove(struct http_request *req, const char *id, bool dry, char *err,
    size_t errlen)
{
	ucl_object_t		*doc, *arr;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*who;
	int			 fd;

	if ((who = feed_denied(req, id)) != NULL) {
		snprintf(err, errlen, "host %s is not one you may change, and "
		    "the feed's table is on it", who);
		return (403);
	}
	if (dry)
		return (0);
	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(doc, "feeds"),
	    &it, true)) != NULL)
		if (strcmp(str(e, "id"), id) != 0)
			ucl_array_append(arr, ucl_object_ref(e));
	put(doc, "feeds", arr);
	(void)store_save(FEEDS_FILE, doc);
	lock_give(fd);
	ucl_object_unref(doc);
	audit_add("feed-removed", "Administer", id, FEEDS_FILE,
	    "the console", session_user(req), "threat feed %s removed; "
	    "its tables given up", id);
	ask(id, "unload");
	cyang_changed("threat-feeds");
	return (0);
}

/*
 * Feed id fetched now or previewed (verb), as the request's user may: a
 * feed from a URL of one's own previewed by an owner alone.  0, or the
 * HTTP status and why.
 */
int
feeds_yang_ask(struct http_request *req, const char *id, const char *verb,
    char *err, size_t errlen)
{
	ucl_object_t		*doc;
	const ucl_object_t	*e;
	const char		*who;
	int			 fd;
	bool			 custom;

	if (!id_ok(id)) {
		snprintf(err, errlen, "no such feed");
		return (404);
	}
	if ((who = feed_denied(req, id)) != NULL) {
		snprintf(err, errlen, "host %s is not one you may change, and "
		    "the feed's table is on it", who);
		return (403);
	}
	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	lock_give(fd);
	e = feed_by(doc, id);
	custom = e != NULL && feed_custom(e);
	ucl_object_unref(doc);
	if (e == NULL) {
		snprintf(err, errlen, "no such feed");
		return (404);
	}
	if (strcmp(verb, "preview") == 0 && custom && !is_owner(req)) {
		snprintf(err, errlen, "a feed from a URL of one's own is "
		    "previewed by a console owner alone");
		return (403);
	}
	ask(id, verb);
	return (0);
}

/*
 * GET /api/feeds/<id>: the feed whole, with what it dropped, its events
 * and its hosts; PUT keeps it (fetched at once when enabled), DELETE
 * takes it away (its tables given up); POST .../fetch fetches it now,
 * POST .../preview fetches it and asks each host's dry run.
 */
int
api_feed(struct http_request *req)
{
	ucl_object_t		*doc, *state, *body, *f, *out;
	const ucl_object_t	*e;
	const char		*p, *verb, *who;
	char			 id[32], err[300];
	size_t			 n;
	int			 fd, rc;

	p = req->path + strlen("/api/feeds/");
	n = strcspn(p, "/");
	if (n == 0 || n >= sizeof(id))
		return (reply_error(req, 404, "not_found", "no such feed"));
	snprintf(id, sizeof(id), "%.*s", (int)n, p);
	verb = p[n] == '/' ? p + n + 1 : NULL;
	if (!id_ok(id))
		return (reply_error(req, 400, "invalid", "a feed is named by "
		    "lower-case letters, digits and -, 24 at most"));
	if (req->method == HTTP_METHOD_GET && verb == NULL) {
		if (!guard(req, false))
			return (WEB_OK);
		fd = lock_take();
		doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
		state = doc_load(FEEDS_STATE, NULL, UCL_OBJECT);
		lock_give(fd);
		if ((e = feed_by(doc, id)) == NULL) {
			ucl_object_unref(doc);
			ucl_object_unref(state);
			return (reply_error(req, 404, "not_found", "no such "
			    "feed"));
		}
		out = feed_json(req, e, ucl_object_lookup(state, id), true);
		ucl_object_unref(doc);
		ucl_object_unref(state);
		return (reply_json(req, 200, out));
	}
	if (!guard(req, true))
		return (WEB_OK);
	if (req->method == HTTP_METHOD_POST && verb != NULL &&
	    (strcmp(verb, "fetch") == 0 || strcmp(verb, "preview") == 0)) {
		if ((rc = feeds_yang_ask(req, id, verb, err, sizeof(err))) != 0)
			return (reply_error(req, rc, rc == 404 ? "not_found" :
			    "role", "%s", err));
		out = ucl_object_typed_new(UCL_OBJECT);
		put(out, "asked", S(verb));
		return (reply_json(req, 202, out));
	}
	if (verb != NULL) {
		if ((who = feed_denied(req, id)) != NULL)
			return (reply_error(req, 403, "role", "host %s is not one "
			    "you may change, and the feed's table is on it", who));
		return (reply_error(req, 404, "not_found", "fetch or preview"));
	}
	if (req->method == HTTP_METHOD_DELETE) {
		if ((rc = feed_remove(req, id, false, err, sizeof(err))) != 0)
			return (reply_error(req, rc, "role", "%s", err));
		out = ucl_object_typed_new(UCL_OBJECT);
		put(out, "removed", B(true));
		return (reply_json(req, 200, out));
	}
	if (req->method != HTTP_METHOD_PUT)
		return (reply_error(req, 405, "method", "GET, PUT, DELETE or "
		    "POST"));
	body = read_json(req);
	rc = feed_put(req, id, body, false, &f, err, sizeof(err));
	if (body != NULL)
		ucl_object_unref(body);
	if (rc != 0)
		return (reply_error(req, rc, rc == 403 ? "role" : rc == 400 ?
		    "invalid" : "store", "%s", err));
	out = ucl_object_typed_new(UCL_OBJECT);
	put(out, "feed", f);
	return (reply_json(req, 200, out));
}

/* ---- arcana-console's threat feeds (cyang.c) ------------------------- */

/* Of o, the numbers named copied into to under their leaves' names. */
static void
numbers(ucl_object_t *to, const ucl_object_t *o, const char *const *keys)
{

	for (; keys[0] != NULL; keys += 2)
		if (ucl_object_lookup(o, keys[0]) != NULL)
			put(to, keys[1], I(num(o, keys[0])));
}

/* Of o, the times (seconds since the epoch) named copied into to. */
static void
times(ucl_object_t *to, const ucl_object_t *o, const char *const *keys)
{

	for (; keys[0] != NULL; keys += 2)
		if (ucl_object_lookup(o, keys[0]) != NULL)
			put(to, keys[1], yang_time((double)num(o, keys[0])));
}

/* feed_json()'s hosts, {id: what it was sent}, as feed-host entries. */
static ucl_object_t *
yhosts(const ucl_object_t *hosts)
{
	static const char *const nums[] = { "count", "count", "added",
	    "added", "removed", "removed", "set", "set", "left_out",
	    "left-out", NULL };
	static const char *const ts[] = { "at", "at", "tried_at", "tried-at",
	    NULL };
	ucl_object_t		*arr, *x;
	const ucl_object_t	*h;
	ucl_object_iter_t	 it = NULL;

	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((h = ucl_object_iterate(hosts, &it, true)) != NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		put(x, "host", S(ucl_object_key(h)));
		if (str(h, "name") != NULL)
			put(x, "name", S(str(h, "name")));
		if (str(h, "table") != NULL)
			put(x, "table", S(str(h, "table")));
		times(x, h, ts);
		numbers(x, h, nums);
		if (str(h, "error") != NULL)
			put(x, "error", S(str(h, "error")));
		ucl_array_append(arr, x);
	}
	return (arr);
}

/* feed_json()'s dropped entries and hidden count into to. */
static void
ydropped(ucl_object_t *to, const ucl_object_t *o)
{
	ucl_object_t		*arr, *x;
	const ucl_object_t	*d;
	ucl_object_iter_t	 it = NULL;
	int64_t			 i = 0;

	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((d = ucl_object_iterate(ucl_object_lookup(o, "dropped"), &it,
	    true)) != NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		put(x, "index", I(i++));
		if (str(d, "entry") != NULL)
			put(x, "entry", S(str(d, "entry")));
		if (str(d, "reason") != NULL)
			put(x, "reason", S(str(d, "reason")));
		if (str(d, "detail") != NULL)
			put(x, "detail", S(str(d, "detail")));
		ucl_array_append(arr, x);
	}
	put(to, "dropped", arr);
	if (ucl_object_lookup(o, "protected_hidden") != NULL)
		put(to, "protected-hidden", I(num(o, "protected_hidden")));
}

/*
 * A feed as arcana-console has it, from feed_json()'s whole view, so
 * that what the reader may not see of a host is left out here as there.
 */
static ucl_object_t *
feed_yang(const ucl_object_t *j)
{
	static const char *const cfg_s[] = { "id", "name", "url", "format",
	    "table", "preset", NULL };
	static const char *const nums[] = { "interval", "interval",
	    "hosts_hidden", "hosts-hidden", "count", "count", "dropped_count",
	    "dropped-count", "covered", "covered", "failures", "failures",
	    "delivered_hidden", "delivered-hidden", NULL };
	static const char *const ts[] = { "fetched_at", "fetched-at",
	    "tried_at", "tried-at", "changed_at", "changed-at", NULL };
	static const char *const pnums[] = { "count", "count",
	    "dropped_count", "dropped-count", "covered", "covered",
	    "hosts_hidden", "hosts-hidden", NULL };
	ucl_object_t		*o, *x, *arr;
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;
	int64_t			 i;
	size_t			 k;

	o = ucl_object_typed_new(UCL_OBJECT);
	for (k = 0; cfg_s[k] != NULL; k++)
		if (str(j, cfg_s[k]) != NULL)
			put(o, cfg_s[k], S(str(j, cfg_s[k])));
	put(o, "enabled", B(ucl_flag(j, "enabled")));
	if (ucl_object_lookup(j, "bogons") != NULL)
		put(o, "bogons", B(ucl_flag(j, "bogons")));
	if (ucl_array_size(ucl_object_lookup(j, "hosts")) > 0)
		put(o, "host", ucl_object_copy(ucl_object_lookup(j, "hosts")));
	numbers(o, j, nums);
	times(o, j, ts);
	if (str(j, "error") != NULL)
		put(o, "error", S(str(j, "error")));
	if ((v = ucl_object_lookup(j, "alarm")) != NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		if (ucl_object_lookup(v, "since") != NULL)
			put(x, "since", yang_time((double)num(v, "since")));
		if (str(v, "text") != NULL)
			put(x, "text", S(str(v, "text")));
		put(o, "alarm", x);
	}
	put(o, "delivered", yhosts(ucl_object_lookup(j, "delivered")));
	x = ucl_object_typed_new(UCL_OBJECT);
	ydropped(x, j);
	put(o, "last-fetch", x);
	arr = ucl_object_typed_new(UCL_ARRAY);
	i = 0;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(j, "events"), &it,
	    true)) != NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		put(x, "index", I(i++));
		if (ucl_object_lookup(e, "at") != NULL)
			put(x, "at", yang_time((double)num(e, "at")));
		put(x, "count", I(num(e, "count")));
		put(x, "was", I(num(e, "was")));
		ucl_array_append(arr, x);
	}
	put(o, "event", arr);
	if ((v = ucl_object_lookup(j, "preview")) != NULL) {
		x = ucl_object_typed_new(UCL_OBJECT);
		if (ucl_object_lookup(v, "at") != NULL)
			put(x, "at", yang_time((double)num(v, "at")));
		if (str(v, "error") != NULL)
			put(x, "error", S(str(v, "error")));
		numbers(x, v, pnums);
		ydropped(x, v);
		put(x, "host", yhosts(ucl_object_lookup(v, "hosts")));
		put(o, "last-preview", x);
	}
	if (ucl_array_size(ucl_object_lookup(j, "sample")) > 0)
		put(o, "sample", ucl_object_copy(ucl_object_lookup(j,
		    "sample")));
	return (o);
}

/* arcana-console:threat-feeds's value, as the request may see it. */
ucl_object_t *
feeds_yang(struct http_request *req)
{
	ucl_object_t		*doc, *state, *out, *arr, *j, *p;
	const ucl_object_t	*f, *e;
	ucl_object_iter_t	 it;
	int			 fd;

	fd = lock_take();
	doc = doc_load(FEEDS_FILE, "feeds", UCL_ARRAY);
	state = doc_load(FEEDS_STATE, NULL, UCL_OBJECT);
	lock_give(fd);
	out = ucl_object_typed_new(UCL_OBJECT);
	put(out, "floor", I(FEED_FLOOR_H));
	put(out, "max-entries", I(FEED_MAX));
	arr = presets_json();
	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL) {
		p = (ucl_object_t *)(uintptr_t)e;
		put(p, "terms-url", ucl_object_copy(ucl_object_lookup(p,
		    "terms_url")));
		(void)ucl_object_delete_key(p, "terms_url");
	}
	put(out, "preset", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(doc, "feeds"), &it,
	    true)) != NULL) {
		j = feed_json(req, f, ucl_object_lookup(state, str(f, "id")),
		    true);
		ucl_array_append(arr, feed_yang(j));
		ucl_object_unref(j);
	}
	put(out, "feed", arr);
	ucl_object_unref(doc);
	ucl_object_unref(state);
	return (out);
}

/* A feed's entry y as /api's PUT body. */
static ucl_object_t *
feed_body(const ucl_object_t *y)
{
	static const char *const keys[] = { "name", "url", "format",
	    "table", "preset", NULL };
	ucl_object_t		*b;
	const ucl_object_t	*v;
	size_t			 k;

	b = ucl_object_typed_new(UCL_OBJECT);
	for (k = 0; keys[k] != NULL; k++)
		if (str(y, keys[k]) != NULL)
			put(b, keys[k], S(str(y, keys[k])));
	if ((v = ucl_object_lookup(y, "interval")) != NULL)
		put(b, "interval", I(ucl_object_toint(v)));
	put(b, "enabled", B(ucl_flag(y, "enabled")));
	if (ucl_object_lookup(y, "bogons") != NULL)
		put(b, "bogons", B(ucl_flag(y, "bogons")));
	put(b, "hosts", (v = ucl_object_lookup(y, "host")) != NULL ?
	    ucl_object_copy(v) : ucl_object_typed_new(UCL_ARRAY));
	return (b);
}

/*
 * The feeds changed from was to now, through feed_put() and
 * feed_remove(), every protection of /api's: every change checked
 * before any is kept.  0, or the HTTP status and why.
 */
int
feeds_yang_set(struct http_request *req, const ucl_object_t *was,
    const ucl_object_t *now, char *why, size_t len)
{
	const ucl_object_t	*f, *o;
	ucl_object_iter_t	 it;
	ucl_object_t		*b;
	const char		*id;
	char			 w[300];
	int			 rc, pass;

	for (pass = 0; pass < 2; pass++) {
		it = NULL;
		while ((o = ucl_object_iterate(ucl_object_lookup(was, "feed"),
		    &it, true)) != NULL) {
			id = str(o, "id");
			if (cyang_entry(ucl_object_lookup(now, "feed"), "id",
			    id) == NULL && (rc = feed_remove(req, id, pass == 0,
			    w, sizeof(w))) != 0) {
				snprintf(why, len, "feed %s: %s", id, w);
				return (rc);
			}
		}
		it = NULL;
		while ((f = ucl_object_iterate(ucl_object_lookup(now, "feed"),
		    &it, true)) != NULL) {
			id = str(f, "id");
			o = cyang_entry(ucl_object_lookup(was, "feed"), "id", id);
			b = feed_body(f);
			/* By what /api is given: a default left out or said
			 * is the same. */
			if (o != NULL) {
				ucl_object_t	*a = feed_body(o);
				bool		 same = cyang_same(a, b);

				ucl_object_unref(a);
				if (same) {
					ucl_object_unref(b);
					continue;
				}
			}
			rc = feed_put(req, id, b, pass == 0, NULL, w, sizeof(w));
			ucl_object_unref(b);
			if (rc != 0) {
				snprintf(why, len, "feed %s: %s", id, w);
				return (rc);
			}
		}
	}
	return (0);
}
