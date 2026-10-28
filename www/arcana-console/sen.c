/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * MEF 138's notifications.  A Security Event Notification (SEN, §6.2)
 * is issued for each subset of a Service Flow a Security Function
 * blocks and tells (R24): what the edges' rules logged (the record,
 * sdwan-security) and what their Suricata found (sdwan-ids, Arcana's
 * own function), as the console reads the edges' events for its
 * alerts.  Each has what Table 3 asks: the issuer, a UTC timestamp, an
 * ID (a UUID), the function and its policy, the type (IOC for a list's
 * entry, OTHER for a No-match and for Suricata's rules), the event, the
 * source address, the details, the action, and the UNI where it is
 * known (D2); every domain name and URL in it neutralised, its periods
 * in brackets (R28, D3).  A Security Admin Notification (SAN, §6.3) is
 * issued for each Security Function Policy whose parameter values the
 * document kept changes (R31), one a policy, with Table 4's: the
 * issuer, when, an ID, the address and name of who changed it, the
 * policy, and the values that changed alone, a Block's or Quarantine's
 * names neutralised (R34).  Both are kept in the data directory, one a
 * line, readable by the console's user alone (R26, R32), and told to
 * their recipients (R30, R36: mail_sen, mail_san, telegram_sen,
 * telegram_san in Settings) by mail.c, a message a tick.
 */

#include <sys/param.h>
#include <sys/file.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "console.h"

#define	SEN_FILE	"sdwan-sen.jsonl"
#define	SAN_FILE	"sdwan-san.jsonl"
#define	NOTICE_READ	500		/* in a read, newest */

/* The document, read once a tick of the events (sen_begin, sen_end). */
static ucl_object_t	*doc;

static const char *
str(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(o, key)) == NULL)
		return (NULL);
	return (ucl_object_tostring_forced(v));
}

/* An RFC 4122 UUID, version 4: random. */
static void
uuid(char out[37])
{
	uint8_t	b[16];

	arc4random_buf(b, sizeof(b));
	b[6] = (b[6] & 0x0f) | 0x40;
	b[8] = (b[8] & 0x3f) | 0x80;
	snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x"
	    "%02x%02x%02x%02x", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
	    b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

/* Now, in UTC as RFC 3339 §4.1 has it (R29, R35). */
static void
when_now(char *out, size_t len)
{
	struct timespec	ts;
	struct tm	tm;
	size_t		n;

	clock_gettime(CLOCK_REALTIME, &ts);
	gmtime_r(&ts.tv_sec, &tm);
	n = strftime(out, len, "%Y-%m-%dT%H:%M:%S", &tm);
	snprintf(out + n, len - n, ".%03ldZ", ts.tv_nsec / 1000000);
}

/* The issuer: this console, by its host's name. */
static const char *
issuer(char *buf, size_t len)
{
	char	host[MAXHOSTNAMELEN];

	if (gethostname(host, sizeof(host)) != 0)
		strlcpy(host, "localhost", sizeof(host));
	snprintf(buf, len, "Arcana console at %s", host);
	return (buf);
}

/* Whether a word is an address, which is not neutralised: digits and
 * dots, or hex and colons. */
static bool
address_like(const char *s, size_t n)
{
	size_t	i;
	bool	colon = false, dot = false;

	for (i = 0; i < n; i++) {
		if (s[i] == ':')
			colon = true;
		else if (s[i] == '.')
			dot = true;
		else if (!(colon ? isxdigit((unsigned char)s[i]) : isdigit(
		    (unsigned char)s[i])) && s[i] != '/')
			return (false);
	}
	return (colon || dot);
}

/*
 * s with every domain name and URL in it neutralised (R28, R34, D3,
 * D4): a word with a period and a letter in it, not an address, has
 * each period put in brackets, and :// after its scheme the same, as
 * MEF 138 shows (www[.]domain[.]tld); the rest as it is.  To be freed.
 */
char *
sen_neutralise(const char *s)
{
	struct buf	*b;
	const char	*w, *e;
	size_t		 n;
	bool		 letters, dots;
	char		*out;

	b = buf_alloc(strlen(s) + 64);
	for (w = s; *w != '\0'; w = e) {
		n = strcspn(w, " \t\n,;\"'()<>");
		if (n == 0) {
			buf_append(b, w, 1);
			e = w + 1;
			continue;
		}
		e = w + n;
		letters = dots = false;
		for (const char *p = w; p < e; p++) {
			if (isalpha((unsigned char)*p))
				letters = true;
			if (*p == '.')
				dots = true;
		}
		if (!letters || !dots || address_like(w, n)) {
			buf_append(b, w, n);
			continue;
		}
		for (const char *p = w; p < e; p++) {
			if (*p == '.')
				buf_appendf(b, "[.]");
			else if (*p == ':' && e - p > 2 && p[1] == '/' && p[2] ==
			    '/') {
				buf_appendf(b, "[://]");
				p += 2;
			} else
				buf_append(b, p, 1);
		}
	}
	out = strndup((char *)b->data, b->offset);
	buf_free(b);
	if (out == NULL)
		abort();
	return (out);
}

/* A notice appended to its file, one a line, the console's user's
 * alone (R26, R32). */
static void
keep(const char *file, const ucl_object_t *o)
{
	char	 path[MAXPATHLEN], *line;
	int	 fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, file);
	if ((fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600))
	    == -1) {
		log_msg(LOG_ERR, "%s: %s", path, strerror(errno));
		return;
	}
	line = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	(void)flock(fd, LOCK_EX);
	if (line != NULL && (write(fd, line, strlen(line)) == -1 || write(fd,
	    "\n", 1) == -1))
		log_msg(LOG_ERR, "%s: %s", path, strerror(errno));
	(void)flock(fd, LOCK_UN);
	close(fd);
	free(line);
}

static void
put(ucl_object_t *o, const char *key, const char *v)
{

	ucl_object_insert_key(o, ucl_object_fromstring(v != NULL ? v : ""), key,
	    0, false);
}

/* The service whose edge's table is fib, and its function policy of
 * the ID; NULL for none. */
static const ucl_object_t *
service_by_fib(int64_t fib)
{
	const ucl_object_t	*sw;
	ucl_object_iter_t	 it;

	it = NULL;
	while (doc != NULL && (sw = ucl_object_iterate(ucl_object_lookup(doc,
	    "swvcs"), &it, true)) != NULL)
		if (ucl_object_toint(ucl_object_lookup(sw, "fib")) == fib)
			return (sw);
	return (NULL);
}

static const ucl_object_t *
service_by_id(const char *id)
{
	const ucl_object_t	*sw;
	ucl_object_iter_t	 it;

	it = NULL;
	while (doc != NULL && id != NULL && (sw = ucl_object_iterate(
	    ucl_object_lookup(doc, "swvcs"), &it, true)) != NULL)
		if (str(sw, "id") != NULL && strcmp(str(sw, "id"), id) == 0)
			return (sw);
	return (NULL);
}

static const ucl_object_t *
policy_of(const ucl_object_t *sw, const char *id)
{
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;

	it = NULL;
	while (sw != NULL && id != NULL && (f = ucl_object_iterate(
	    ucl_object_lookup(sw, "security_function_policies"), &it, true)) !=
	    NULL)
		if (str(f, "id") != NULL && strcmp(str(f, "id"), id) == 0)
			return (f);
	return (NULL);
}

/* The UNI of the service at the edge on that interface (D2), or "". */
static const char *
uni_of(const ucl_object_t *sw, const char *edge, const char *iface)
{
	const ucl_object_t	*ep, *u;
	ucl_object_iter_t	 it;

	it = NULL;
	while (sw != NULL && edge != NULL && iface != NULL && (ep =
	    ucl_object_iterate(ucl_object_lookup(sw, "end_points"), &it, true))
	    != NULL) {
		if (str(ep, "edge") == NULL || strcmp(str(ep, "edge"), edge) != 0)
			continue;
		if ((u = ucl_object_lookup(ep, "uni")) != NULL && str(u,
		    "interface") != NULL && strcmp(str(u, "interface"), iface) ==
		    0)
			return (str(u, "id"));
		if (ucl_object_lookup(ep, "remote") != NULL && str(
		    ucl_object_lookup(ep, "remote"), "interface") != NULL &&
		    strcmp(str(ucl_object_lookup(ep, "remote"), "interface"),
		    iface) == 0)
			return (str(ep, "id"));
	}
	return ("");
}

/* MEF 138's name of a function, for a SEN. */
static const char *
function_name(const char *fn)
{
	static const char *const names[][2] = {
		{ "ippf", "IP, Port and Protocol Filtering" },
		{ "dnf", "Domain Name Filtering" },
		{ "urlf", "URL Filtering" },
		{ "mbsf", "Middlebox" },
		{ "mdr", "Malware Detection and Removal" },
		{ "dpf", "DNS Protocol Filtering" },
		{ "pdns", "Protective DNS" },
	};
	size_t	i;

	for (i = 0; fn != NULL && i < nitems(names); i++)
		if (strcmp(names[i][0], fn) == 0)
			return (names[i][1]);
	return (fn != NULL ? fn : "");
}

/* A source address without its port, as the record has it. */
static void
source_of(const char *s, char *out, size_t len)
{
	const char	*c;

	if (s == NULL) {
		out[0] = '\0';
		return;
	}
	if (s[0] == '[' && (c = strchr(s, ']')) != NULL)
		snprintf(out, len, "%.*s", (int)(c - s - 1), s + 1);
	else if ((c = strrchr(s, ':')) != NULL && strchr(s, ':') == c)
		snprintf(out, len, "%.*s", (int)(c - s), s);
	else
		snprintf(out, len, "%s", s);
}

/*
 * The document read for the events of a tick, and let go after: each
 * SEN names its function and UNI by it.
 */
void
sen_begin(void)
{

	if (doc != NULL)
		ucl_object_unref(doc);
	doc = sdwan_load();
}

void
sen_end(void)
{

	if (doc != NULL)
		ucl_object_unref(doc);
	doc = NULL;
}

/*
 * A SEN of an edge's event, where it is one a Security Function told
 * (R24): a rule's deny the record logged (sdwan-security, its comment
 * naming the service, the function policy and the list, or no-match)
 * or a Suricata alert (sdwan-ids, Arcana's own).  Kept, and held for
 * the recipients.
 */
void
sen_event(const char *edge_id, const char *edge_name, const ucl_object_t *e)
{
	const ucl_object_t	*d, *sw, *f;
	ucl_object_t		*o;
	char			 id[37], when[40], iss[MAXHOSTNAMELEN + 24];
	char			 details[1200], src[80], svc[40], pol[40];
	char			 list[20], evt[200], ety[32];
	const char		*kind, *fn, *action, *type, *comment;
	char			*neutral, *text;
	int64_t			 fib;

	kind = str(e, "kind");
	d = ucl_object_lookup(e, "data");
	if (kind == NULL || d == NULL)
		return;
	o = ucl_object_typed_new(UCL_OBJECT);
	if (strcmp(kind, "sdwan-security") == 0) {
		/* "security <service> <policy> <list|no-match>", as the
		 * console wrote the rule's comment. */
		comment = str(d, "comment");
		if (comment == NULL || sscanf(comment, "security %39s %39s %19s",
		    svc, pol, list) != 3) {
			ucl_object_unref(o);
			return;
		}
		sw = service_by_id(svc);
		f = policy_of(sw, pol);
		fn = str(f, "function");
		put(o, "function", function_name(fn));
		put(o, "policy", pol);
		put(o, "service", svc);
		type = strcmp(list, "no-match") == 0 ? "OTHER" : "IOC";
		snprintf(ety, sizeof(ety), "%s", strcmp(list, "no-match") == 0 ?
		    "no match, blocked by policy" : strcmp(list, "quarantine") ==
		    0 ? "Quarantine List match" : strcmp(list, "allow") == 0 ?
		    "Allow List match" : "Block List match");
		action = strcmp(list, "quarantine") == 0 ? "Quarantined" :
		    strcmp(list, "allow") == 0 ? "Allowed" : "Blocked";
		source_of(str(d, "src"), src, sizeof(src));
		snprintf(details, sizeof(details), "rule %s %s: %s to %s on %s "
		    "at %s", str(d, "rule") != NULL ? str(d, "rule") : "",
		    str(d, "action") != NULL ? str(d, "action") : "", str(d,
		    "src") != NULL ? str(d, "src") : "", str(d, "dst") != NULL ?
		    str(d, "dst") : "", str(d, "iface") != NULL ? str(d, "iface")
		    : "", edge_name);
		put(o, "uni", uni_of(sw, edge_id, str(d, "iface")));
	} else if (strcmp(kind, "sdwan-ids") == 0) {
		/* An instance sw<fib> of the service with that table. */
		fib = str(d, "name") != NULL && strncmp(str(d, "name"), "sw", 2)
		    == 0 ? strtoll(str(d, "name") + 2, NULL, 10) : -1;
		sw = service_by_fib(fib);
		put(o, "function", "Intrusion detection (Arcana's own: Suricata)");
		put(o, "policy", "ids");
		put(o, "service", sw != NULL ? str(sw, "id") : "");
		type = "OTHER";
		snprintf(ety, sizeof(ety), "Suricata rule %s rev %s", str(d,
		    "sid") != NULL ? str(d, "sid") : "", str(d, "rev") != NULL ?
		    str(d, "rev") : "");
		action = str(d, "action") != NULL && strcmp(str(d, "action"),
		    "blocked") == 0 ? "Blocked" : "Alerted, let through";
		snprintf(src, sizeof(src), "%s", str(d, "src") != NULL ? str(d,
		    "src") : "");
		snprintf(details, sizeof(details), "%s (%s%sseverity %s): %s:%s "
		    "to %s:%s %s on %s at %s", str(d, "signature") != NULL ?
		    str(d, "signature") : "", str(d, "category") != NULL ? str(d,
		    "category") : "", str(d, "category") != NULL && str(d,
		    "category")[0] != '\0' ? ", " : "", str(d, "severity") != NULL
		    ? str(d, "severity") : "", src, str(d, "sport") != NULL ? str(
		    d, "sport") : "", str(d, "dst") != NULL ? str(d, "dst") : "",
		    str(d, "dport") != NULL ? str(d, "dport") : "", str(d,
		    "proto") != NULL ? str(d, "proto") : "", str(d, "iface") !=
		    NULL ? str(d, "iface") : "", edge_name);
		put(o, "uni", uni_of(sw, edge_id, str(d, "iface")));
	} else {
		ucl_object_unref(o);
		return;
	}
	uuid(id);
	when_now(when, sizeof(when));
	put(o, "id", id);
	put(o, "when", when);
	put(o, "issuer", issuer(iss, sizeof(iss)));
	put(o, "type", type);
	put(o, "event", ety);
	put(o, "source", src);
	neutral = sen_neutralise(details);
	put(o, "details", neutral);
	put(o, "action", action);
	put(o, "edge", edge_name);
	keep(SEN_FILE, o);
	snprintf(evt, sizeof(evt), "%s", str(o, "function"));
	if (asprintf(&text, "Security Event Notification %s\n%s (UTC), %s\n"
	    "Security Function: %s, policy %s, service %s\nType of SEN: %s; "
	    "Security Event: %s\nSource: %s\nDetails: %s\nAction taken: %s\n"
	    "UNI: %s", id, when, iss, evt, str(o, "policy"), str(o, "service"),
	    type, ety, src, neutral, action, str(o, "uni")[0] != '\0' ? str(o,
	    "uni") : "not known") != -1) {
		mail_hold_notice(NOTICE_SEN, text);
		free(text);
	}
	free(neutral);
	ucl_object_unref(o);
}

/* A value's JSON, compact; "" for none.  To be freed. */
static char *
json_of(const ucl_object_t *v)
{
	char	*s;

	if (v == NULL)
		return (xstrdup(""));
	if ((s = (char *)ucl_object_emit(v, UCL_EMIT_JSON_COMPACT)) == NULL)
		abort();
	return (s);
}

/*
 * The entries of a list in a and not in b, by their JSON, into out,
 * neutralised where neutral says (a Block's or Quarantine's, R34).
 */
static void
list_diff(const ucl_object_t *a, const ucl_object_t *b, bool neutral,
    struct buf *out)
{
	const ucl_object_t	*e, *x;
	ucl_object_iter_t	 it, xit;
	char			*ja, *jb, *n;
	bool			 found;
	int			 k;

	k = 0;
	it = NULL;
	while ((e = ucl_object_iterate(a, &it, true)) != NULL) {
		ja = json_of(e);
		found = false;
		xit = NULL;
		while (!found && (x = ucl_object_iterate(b, &xit, true)) != NULL) {
			jb = json_of(x);
			found = strcmp(ja, jb) == 0;
			free(jb);
		}
		if (!found) {
			n = neutral ? sen_neutralise(ja) : xstrdup(ja);
			buf_appendf(out, "%s%s", k++ > 0 ? ", " : "", n);
			free(n);
		}
		free(ja);
	}
}

/*
 * The parameter values of a function policy that changed from a to b,
 * as text: each key whose value differs, a list's entries added and
 * taken away (SAN details, Table 4); "" when none.  To be freed.
 */
static char *
policy_diff(const ucl_object_t *a, const ucl_object_t *b)
{
	static const char *const lists[] = { "block", "allow", "quarantine" };
	struct buf		*out, *t;
	const ucl_object_t	*k, *va, *vb;
	ucl_object_iter_t	 it;
	ucl_object_t		*seen;
	char			*ja, *jb, *s;
	const char		*key;
	size_t			 i;
	bool			 isl, neutral;
	int			 pass;

	out = buf_alloc(512);
	seen = ucl_object_typed_new(UCL_OBJECT);
	/* The keys of both, each once. */
	for (pass = 0; pass < 2; pass++) {
		it = NULL;
		while ((k = ucl_object_iterate(pass == 0 ? a : b, &it, true)) !=
		    NULL) {
			key = ucl_object_key(k);
			if (ucl_object_lookup(seen, key) != NULL)
				continue;
			ucl_object_insert_key(seen, ucl_object_frombool(true), key,
			    0, true);
			va = ucl_object_lookup(a, key);
			vb = ucl_object_lookup(b, key);
			ja = json_of(va);
			jb = json_of(vb);
			if (strcmp(ja, jb) != 0) {
				isl = false;
				for (i = 0; i < nitems(lists); i++)
					if (strcmp(key, lists[i]) == 0)
						isl = true;
				neutral = strcmp(key, "block") == 0 || strcmp(key,
				    "quarantine") == 0 || strcmp(key, "pass-through")
				    == 0;
				buf_appendf(out, "%s%s: ", out->offset > 0 ? "; " :
				    "", key);
				if (isl && (va == NULL || ucl_object_type(va) ==
				    UCL_ARRAY) && (vb == NULL || ucl_object_type(vb)
				    == UCL_ARRAY)) {
					t = buf_alloc(256);
					list_diff(vb, va, neutral, t);
					if (t->offset > 0)
						buf_appendf(out, "added %s", buf_stringify(
						    t, NULL));
					buf_reset(t);
					list_diff(va, vb, neutral, t);
					if (t->offset > 0)
						buf_appendf(out, "%staken away %s",
						    out->data[out->offset - 2] == ':' ?
						    "" : ", ", buf_stringify(t, NULL));
					buf_free(t);
				} else {
					s = neutral ? sen_neutralise(ja) : xstrdup(ja);
					buf_appendf(out, "%s was ", va != NULL ? s :
					    "nothing");
					free(s);
					s = neutral ? sen_neutralise(jb) : xstrdup(jb);
					buf_appendf(out, "now %s", vb != NULL ? s :
					    "nothing");
					free(s);
				}
			}
			free(ja);
			free(jb);
		}
	}
	ucl_object_unref(seen);
	s = strndup((char *)out->data, out->offset);
	buf_free(out);
	if (s == NULL)
		abort();
	return (s);
}

/* The function policy of the ID in a service of the ID, in a document. */
static const ucl_object_t *
policy_in(const ucl_object_t *d, const char *svc, const char *id)
{
	const ucl_object_t	*sw, *f;
	ucl_object_iter_t	 it, fit;

	it = NULL;
	while ((sw = ucl_object_iterate(ucl_object_lookup(d, "swvcs"), &it,
	    true)) != NULL) {
		if (str(sw, "id") == NULL || strcmp(str(sw, "id"), svc) != 0)
			continue;
		fit = NULL;
		while ((f = ucl_object_iterate(ucl_object_lookup(sw,
		    "security_function_policies"), &fit, true)) != NULL)
			if (str(f, "id") != NULL && strcmp(str(f, "id"), id) == 0)
				return (f);
	}
	return (NULL);
}

/* One SAN: kept, and held for the recipients. */
static void
san_one(const char *svc, const char *id, const char *source, const char *who,
    const char *details)
{
	ucl_object_t	*o;
	char		 uid[37], when[40], iss[MAXHOSTNAMELEN + 24], *text;

	uuid(uid);
	when_now(when, sizeof(when));
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "id", uid);
	put(o, "when", when);
	put(o, "issuer", issuer(iss, sizeof(iss)));
	put(o, "source", source);
	put(o, "who", who);
	put(o, "service", svc);
	put(o, "policy", id);
	put(o, "details", details);
	keep(SAN_FILE, o);
	if (asprintf(&text, "Security Admin Notification %s\n%s (UTC), %s\n"
	    "Security Function Policy: %s of service %s\nChanged by %s from "
	    "%s\nDetails: %s", uid, when, iss, id, svc, who, source[0] != '\0' ?
	    source : "the console's host", details) != -1) {
		mail_hold_notice(NOTICE_SAN, text);
		free(text);
	}
	ucl_object_unref(o);
}

/*
 * The SANs of a document kept in place of another (R31): one for each
 * Security Function Policy, by service and ID, whose values differ,
 * was added or taken away.  who changed it, from source.
 */
void
san_changes(const ucl_object_t *old, const ucl_object_t *new,
    const char *source, const char *who)
{
	const ucl_object_t	*sw, *f, *g;
	ucl_object_iter_t	 it, fit;
	ucl_object_t		*none;
	char			*d;
	int			 pass;

	for (pass = 0; pass < 2; pass++) {
		it = NULL;
		while ((sw = ucl_object_iterate(ucl_object_lookup(pass == 0 ? new :
		    old, "swvcs"), &it, true)) != NULL) {
			if (str(sw, "id") == NULL)
				continue;
			fit = NULL;
			while ((f = ucl_object_iterate(ucl_object_lookup(sw,
			    "security_function_policies"), &fit, true)) != NULL) {
				if (str(f, "id") == NULL)
					continue;
				g = policy_in(pass == 0 ? old : new, str(sw, "id"),
				    str(f, "id"));
				if (pass == 1) {
					/* Taken away: not in the new one. */
					if (g == NULL)
						san_one(str(sw, "id"), str(f, "id"), source,
						    who, "the policy taken away");
					continue;
				}
				if (g == NULL) {
					/* Added: every value of it. */
					none = ucl_object_typed_new(UCL_OBJECT);
					d = policy_diff(none, f);
					ucl_object_unref(none);
					san_one(str(sw, "id"), str(f, "id"), source, who,
					    d[0] != '\0' ? d : "the policy added");
					free(d);
					continue;
				}
				d = policy_diff(g, f);
				if (d[0] != '\0')
					san_one(str(sw, "id"), str(f, "id"), source, who,
					    d);
				free(d);
			}
		}
	}
}

/*
 * The notices kept, newest first (at most NOTICE_READ, those the
 * filter keeps), and how many there are.
 */
static ucl_object_t *
notices_read(const char *file, const char *filter, int64_t *countp)
{
	struct ucl_parser	*p;
	ucl_object_t		*all, *o, *out;
	FILE			*fp;
	char			 path[MAXPATHLEN], *line;
	size_t			 cap;
	ssize_t			 n;
	int64_t			 k;

	*countp = 0;
	all = ucl_object_typed_new(UCL_ARRAY);
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, file);
	if ((fp = fopen(path, "r")) == NULL)
		return (all);
	(void)flock(fileno(fp), LOCK_SH);
	line = NULL;
	cap = 0;
	while ((n = getline(&line, &cap, fp)) > 0) {
		(*countp)++;
		if (filter != NULL && filter[0] != '\0' && strcasestr(line,
		    filter) == NULL)
			continue;
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_string(p, line, 0) && (o =
		    ucl_parser_get_object(p)) != NULL)
			ucl_array_append(all, o);
		ucl_parser_free(p);
	}
	free(line);
	(void)flock(fileno(fp), LOCK_UN);
	fclose(fp);
	out = ucl_object_typed_new(UCL_ARRAY);
	for (k = (int64_t)ucl_array_size(all) - 1; k >= 0 && (int64_t)
	    ucl_array_size(out) < NOTICE_READ; k--)
		ucl_array_append(out, ucl_object_copy(ucl_array_find_index(all,
		    (unsigned int)k)));
	ucl_object_unref(all);
	return (out);
}

/*
 * GET /api/sdwan/sen[.csv]?q= and /api/sdwan/san[.csv]?q=: the notices,
 * newest first, q keeping those with it anywhere in them; as CSV with
 * .csv.
 */
static int
notices_api(struct http_request *req, const char *file,
    const char *const *keys, size_t nkeys, const char *name)
{
	ucl_object_t		*events, *out;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct buf		*b;
	char			*q;
	int64_t			 count;
	size_t			 i, j;
	const char		*v;

	if (!guard(req, false))
		return (WEB_OK);
	q = NULL;
	(void)http_argument_get_string(req, "q", &q);
	events = notices_read(file, q, &count);
	if (strstr(req->path, ".csv") == NULL) {
		out = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(out, ucl_object_fromint(count), "count", 0,
		    false);
		ucl_object_insert_key(out, events, "notices", 0, false);
		return (reply_json(req, 200, out));
	}
	b = buf_alloc(4096);
	for (i = 0; i < nkeys; i++)
		buf_appendf(b, "%s%s", i > 0 ? "," : "", keys[i]);
	buf_appendf(b, "\n");
	it = NULL;
	while ((e = ucl_object_iterate(events, &it, true)) != NULL) {
		for (i = 0; i < nkeys; i++) {
			v = str(e, keys[i]) != NULL ? str(e, keys[i]) : "";
			buf_appendf(b, "%s\"", i > 0 ? "," : "");
			for (j = 0; v[j] != '\0'; j++) {
				if (v[j] == '"')
					buf_appendf(b, "\"\"");
				else
					buf_append(b, &v[j], 1);
			}
			buf_appendf(b, "\"");
		}
		buf_appendf(b, "\n");
	}
	ucl_object_unref(events);
	http_response_header(req, "content-type", "text/csv; charset=utf-8");
	http_response_header(req, "content-disposition", name);
	http_response(req, 200, b->data, b->offset);
	buf_free(b);
	return (WEB_OK);
}

int
api_sdwan_sen(struct http_request *req)
{
	static const char *const keys[] = { "id", "when", "issuer", "function",
	    "policy", "service", "type", "event", "source", "details", "action",
	    "uni", "edge" };

	return (notices_api(req, SEN_FILE, keys, nitems(keys), "attachment; "
	    "filename=\"sdwan-sen.csv\""));
}

int
api_sdwan_san(struct http_request *req)
{
	static const char *const keys[] = { "id", "when", "issuer", "source",
	    "who", "service", "policy", "details" };

	return (notices_api(req, SAN_FILE, keys, nitems(keys), "attachment; "
	    "filename=\"sdwan-san.csv\""));
}
