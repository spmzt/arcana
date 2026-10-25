/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Security section: the luxuria plugins that guard a host by
 * themselves, apart from SD-WAN.  Squid filters URLs as a proxy the
 * clients are told of (an explicit one, its port with ssl-bump, so that
 * a TLS name is looked at or TLS opened); c-icap with ClamAV's module
 * scans what it fetches, on the loopback; Suricata watches interfaces
 * by pcap(3), or, where it prevents, takes the packets an ipfw(8)
 * divert rule hands it (divert(4)).  The page sends each instance's
 * form; here it is checked and made into what the agent's sdwan-proxy
 * and sdwan-ids take, as group "security": instances named sec-, kept
 * apart from SD-WAN's, each with its form as spec, to show again.  An
 * intrusion detection the admin stopped stays in the list, not run.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "console.h"

#define	SEC_INSTANCES	16
#define	SEC_LIST_MAX	4096	/* addresses, prefixes or names a list */
/* c-icap of the i-th proxy, on the loopback: apart from SD-WAN's
 * (1344 + 10 * its table). */
#define	SEC_ICAP_PORT(i)	(1345 + 10 * (int)(i))

static const char *
sstr(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, k);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

/* sec- and letters, digits, _ and -: 32 at most, as the agent takes. */
static bool
name_ok(const char *s)
{
	size_t	i;

	if (s == NULL || strncmp(s, "sec-", 4) != 0 || strlen(s) < 5 ||
	    strlen(s) > 32)
		return (false);
	for (i = 4; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '-')
			return (false);
	return (true);
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

/*
 * Each string of the list at k checked by ok, into out (which may be
 * NULL), joined by sep; false, and why, for one that is not, or for
 * none when one is needed.
 */
static bool
list_of(const ucl_object_t *in, const char *k, bool (*ok)(const char *),
    bool need, struct buf *out, const char *pre, const char *sep,
    const char *name, const char *what, char *err, size_t errlen)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int			 n;

	/* A list, not one string standing for it. */
	if (ucl_object_lookup(in, k) != NULL && ucl_object_type(
	    ucl_object_lookup(in, k)) != UCL_ARRAY) {
		snprintf(err, errlen, "%s: %s: a list", name, what);
		return (false);
	}
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, k), &it, true)) !=
	    NULL) {
		if (n == SEC_LIST_MAX) {
			snprintf(err, errlen, "%s: %s: %d at most", name, what,
			    SEC_LIST_MAX);
			return (false);
		}
		if (ucl_object_type(e) != UCL_STRING || !ok(ucl_object_tostring(
		    e))) {
			snprintf(err, errlen, "%s: %s: %.64s is not one", name,
			    what, ucl_object_tostring_forced(e));
			return (false);
		}
		/* ".example.org" as typed is example.org's, not a dot more. */
		if (out != NULL)
			buf_appendf(out, "%s%s%s", n > 0 ? sep : "", pre,
			    ucl_object_tostring(e) + (strcmp(pre, ".") == 0 &&
			    ucl_object_tostring(e)[0] == '.' ? 1 : 0));
		n++;
	}
	if (need && n == 0) {
		snprintf(err, errlen, "%s: %s: at least one", name, what);
		return (false);
	}
	return (true);
}

/* A whole number at k, lo to hi, def when absent. */
static bool
num_of(const ucl_object_t *in, const char *k, int64_t lo, int64_t hi,
    int64_t def, int64_t *v)
{
	const ucl_object_t	*o;

	if ((o = ucl_object_lookup(in, k)) == NULL || ucl_object_type(o) ==
	    UCL_NULL) {
		*v = def;
		return (true);
	}
	if (ucl_object_type(o) != UCL_INT)
		return (false);
	*v = ucl_object_toint(o);
	return (*v >= lo && *v <= hi);
}

static ucl_object_t *
proxy_one(const ucl_object_t *in, int idx, const char *host, char *err,
    size_t errlen)
{
	struct buf		*b, *d;
	ucl_object_t		*o;
	const char		*name, *mode;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int64_t			 fib, port;
	bool			 malware;

	name = sstr(in, "name");
	mode = sstr(in, "mode") != NULL ? sstr(in, "mode") : "sni";
	if (!name_ok(name)) {
		snprintf(err, errlen, "a name is sec- and letters, digits, _ "
		    "and -, 32 at most");
		return (NULL);
	}
	if (strcmp(mode, "sni") != 0 && strcmp(mode, "inspect") != 0) {
		snprintf(err, errlen, "%s: mode is sni or inspect", name);
		return (NULL);
	}
	if (!num_of(in, "fib", 0, 65535, 0, &fib) || !num_of(in, "port", 1,
	    65535, 3128, &port)) {
		snprintf(err, errlen, "%s: fib is a routing table, port 1 to "
		    "65535", name);
		return (NULL);
	}
	malware = ucl_object_toboolean(ucl_object_lookup(in, "malware"));
	b = buf_alloc(4096);
	d = buf_alloc(1024);
	buf_appendf(b, "# Written by the Arcana console: the Security "
	    "section's URL filter %s at %s,\n# by Squid, mode %s, in routing "
	    "table %jd.\npid_filename @PID@\naccess_log /var/log/squid/%s-"
	    "access.log\ncache_log /var/log/squid/%s-cache.log\ncache deny all\n"
	    "visible_hostname %s\n", name, host, mode, (intmax_t)fib, name, name,
	    name);
	/* Where the clients reach it: each address told, its port. */
	if (ucl_object_type(ucl_object_lookup(in, "listen")) != UCL_ARRAY) {
		snprintf(err, errlen, "%s: listen: a list of addresses", name);
		goto bad;
	}
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "listen"), &it,
	    true)) != NULL) {
		if (ucl_object_type(e) != UCL_STRING || !addr_ok(
		    ucl_object_tostring(e))) {
			snprintf(err, errlen, "%s: listen: %.64s is not an "
			    "address", name, ucl_object_tostring_forced(e));
			goto bad;
		}
		buf_appendf(b, strchr(ucl_object_tostring(e), ':') != NULL ?
		    "http_port [%s]:%jd" : "http_port %s:%jd",
		    ucl_object_tostring(e), (intmax_t)port);
		buf_appendf(b, " ssl-bump tls-cert=@CA@ "
		    "generate-host-certificates=on dynamic_cert_mem_cache_size="
		    "4MB\n");
	}
	if (ucl_array_size(ucl_object_lookup(in, "listen")) == 0) {
		snprintf(err, errlen, "%s: listen: at least one address", name);
		goto bad;
	}
	buf_appendf(b, "sslcrtd_program @CERTGEN@ -s @SSLDB@ -M 4MB\n"
	    "sslcrtd_children 3\nacl localnet src");
	if (!list_of(in, "allow", prefix_ok, true, b, " ", "", name, "allow "
	    "(the networks that may use it)", err, errlen))
		goto bad;
	if (malware)
		buf_appendf(b, "\nicap_enable on\nicap_send_client_ip on\n"
		    "icap_service sec_av respmod_precache bypass=off "
		    "icap://127.0.0.1:%d/avscan\nadaptation_access sec_av allow "
		    "all", SEC_ICAP_PORT(idx));
	buf_appendf(b, "\nacl denied_site ssl::server_name \"@DENY@\"\n"
	    "acl denied_url dstdomain \"@DENY@\"\nacl step1 at_step SslBump1\n"
	    "ssl_bump peek step1\nssl_bump terminate denied_site\nssl_bump %s all"
	    "\nhttp_access deny denied_url\nhttp_access allow localnet\n"
	    "http_access deny all\n", strcmp(mode, "inspect") == 0 ? "bump" :
	    "splice");
	/* Each domain denied with the names beneath it. */
	if (!list_of(in, "deny", domain_ok, false, d, ".", "\n", name, "deny",
	    err, errlen))
		goto bad;
	if (buf_stringify(d, NULL)[0] != '\0')
		buf_appendf(d, "\n");
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(name), "name", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(fib), "fib", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(mode), "mode", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(buf_stringify(b,
	    NULL)), "conf", 0, false);
	/* ".a\n.a.b\n": Squid takes the first of two the second is under,
	 * and warns of the other. */
	ucl_object_insert_key(o, ucl_object_fromstring(buf_stringify(d,
	    NULL)), "deny", 0, false);
	if (malware) {
		buf_reset(b);
		buf_appendf(b, "# Written by the Arcana console: the "
		    "Security section's malware scanning for %s at %s,\n# by "
		    "c-icap and ClamAV, for its Squid.\nPidFile @ICAPPID@\n"
		    "CommandsSocket @ICAPCMD@\nPort 127.0.0.1:%d\nacl squid src "
		    "127.0.0.1/255.255.255.255\nacl all src 0.0.0.0/0.0.0.0\n"
		    "client_access allow squid\nclient_access deny all\n"
		    "StartServers 1\nMaxServers 4\n"
		    "ServerLog /var/log/c-icap/%s-server.log\n"
		    "AccessLog /var/log/c-icap/%s-access.log\n"
		    "Module common clamav_mod.so\nService avscan virus_scan.so\n"
		    "virus_scan.ScanFileTypes TEXT DATA EXECUTABLE ARCHIVE "
		    "DOCUMENT\nvirus_scan.SendPercentData 5\n"
		    "virus_scan.StartSendPercentDataAfter 2M\n"
		    "virus_scan.MaxObjectSize 32M\nvirus_scan.DefaultEngine "
		    "clamav\n", name, host, SEC_ICAP_PORT(idx), name, name);
		ucl_object_insert_key(o, ucl_object_fromstring(
		    buf_stringify(b, NULL)), "icap", 0, false);
	}
	ucl_object_insert_key(o, ucl_object_copy(in), "spec", 0, false);
	buf_free(b);
	buf_free(d);
	return (o);
bad:
	buf_free(b);
	buf_free(d);
	return (NULL);
}

/*
 * An intrusion detection's thresholds and suppressions, as Suricata's
 * threshold.config has them: a line each, suppress, threshold,
 * event_filter or rate_filter with its gen_id and sig_id; # a comment.
 */
static bool
thresholds_ok(const char *text, const char *name, char *err, size_t errlen)
{
	static const char *const kinds[] = { "suppress ", "threshold ",
	    "event_filter ", "rate_filter " };
	const char	*p, *e;
	size_t		 i, len, n;

	if (text == NULL)
		return (true);
	if (strlen(text) > 64 * 1024) {
		snprintf(err, errlen, "%s: its thresholds are 64 KB at most",
		    name);
		return (false);
	}
	for (p = text, n = 1; *p != '\0'; p = *e != '\0' ? e + 1 : e, n++) {
		e = p + strcspn(p, "\n");
		len = (size_t)(e - p);
		while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\r'))
			len--;
		if (len == 0 || *p == '#')
			continue;
		for (i = 0; i < nitems(kinds); i++)
			if (strncmp(p, kinds[i], strlen(kinds[i])) == 0)
				break;
		if (i == nitems(kinds) || strnstr(p, "gen_id ", len) == NULL ||
		    strnstr(p, "sig_id ", len) == NULL || strspn(p,
		    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		    "0123456789 ,._:/$![]-") < len) {
			snprintf(err, errlen, "%s: threshold line %zu is "
			    "suppress, threshold, event_filter or rate_filter "
			    "with its gen_id and sig_id, as threshold.config "
			    "has them", name, n);
			return (false);
		}
	}
	return (true);
}

/* A Lua script's name, as the agent takes it: NAME.lua. */
static bool
lua_name_ok(const char *k)
{
	size_t	len;

	len = k != NULL ? strlen(k) : 0;
	return (len >= 5 && len <= 36 && strcmp(k + len - 4, ".lua") == 0 &&
	    strspn(k, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789_-") == len - 4);
}

static void
add_if(ucl_object_t *ifs, const char *name)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(ifs, &it, true)) != NULL)
		if (strcmp(ucl_object_tostring(e), name) == 0)
			return;
	ucl_array_append(ifs, ucl_object_fromstring(name));
}

/*
 * The interfaces an instance watches, as its form names them: each of
 * interfaces, and both of each netmap pair (em0:em1); what the agent
 * is told to watch beside the YAML it renders of the form.
 */
static ucl_object_t *
ids_ifs(const ucl_object_t *in)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*ifs;
	const char		*s, *colon;
	char			 a[24];

	ifs = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "interfaces"),
	    &it, true)) != NULL)
		if (ucl_object_type(e) == UCL_STRING)
			add_if(ifs, ucl_object_tostring(e));
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "pairs"), &it,
	    true)) != NULL) {
		if (ucl_object_type(e) != UCL_STRING || (colon = strchr((s =
		    ucl_object_tostring(e)), ':')) == NULL)
			continue;
		snprintf(a, sizeof(a), "%.*s", (int)(colon - s), s);
		add_if(ifs, a);
		add_if(ifs, colon + 1);
	}
	return (ifs);
}

/*
 * The Security section's instance as the agent takes it: its name,
 * what it watches, how it prevents, its rules and thresholds, and the
 * form itself (spec), which the agent renders into Suricata's YAML and
 * checks as it does: what runs is what was checked.  What can be said
 * wrong before the host is asked is said here.
 */
static ucl_object_t *
ids_one(const ucl_object_t *in, const char *host, char *err, size_t errlen)
{
	ucl_object_t		*o;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*name, *rules;
	int64_t			 divert;
	bool			 ruleset;

	name = sstr(in, "name");
	if (!name_ok(name)) {
		snprintf(err, errlen, "a name is sec- and letters, digits, _ "
		    "and -, 32 at most");
		return (NULL);
	}
	if (!num_of(in, "divert", 0, 65535, 0, &divert)) {
		snprintf(err, errlen, "%s: divert is a port, 1 to 65535, or none "
		    "to detect only", name);
		return (NULL);
	}
	rules = sstr(in, "rules");
	if (!thresholds_ok(sstr(in, "thresholds"), name, err, errlen))
		return (NULL);
	ruleset = ucl_object_toboolean(ucl_object_lookup(in, "ruleset"));
	if ((rules == NULL || rules[strspn(rules, " \t\r\n")] == '\0') &&
	    !ruleset) {
		snprintf(err, errlen, "%s: rules of its own, or the ruleset "
		    "suricata-update keeps, or both", name);
		return (NULL);
	}
	/* Its Lua scripts' names checked here, so its error is the right
	 * one; the agent writes and checks the scripts and the plugins. */
	it = NULL;
	while (ucl_object_lookup(in, "lua") != NULL && (e = ucl_object_iterate(
	    ucl_object_lookup(in, "lua"), &it, true)) != NULL)
		if (!lua_name_ok(ucl_object_key(e)) || ucl_object_type(e) !=
		    UCL_STRING) {
			snprintf(err, errlen, "%s: a Lua script is NAME.lua, of "
			    "letters, digits, _ and -, its text", name);
			return (NULL);
		}
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(name), "name", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(host), "host", 0,
	    false);
	ucl_object_insert_key(o, ids_ifs(in), "interfaces", 0, false);
	if (sstr(in, "capture") != NULL && strcmp(sstr(in, "capture"),
	    "netmap") == 0)
		ucl_object_insert_key(o, ucl_object_fromstring("netmap"),
		    "capture", 0, false);
	/* Its interfaces' offloading turned off as it starts. */
	if (ucl_object_toboolean(ucl_object_lookup(in, "offload_off")))
		ucl_object_insert_key(o, ucl_object_frombool(false), "offload",
		    0, false);
	if (ucl_object_lookup(in, "lua") != NULL)
		ucl_object_insert_key(o, ucl_object_copy(ucl_object_lookup(in,
		    "lua")), "lua", 0, false);
	if (ucl_object_lookup(in, "plugins") != NULL)
		ucl_object_insert_key(o, ucl_object_copy(ucl_object_lookup(in,
		    "plugins")), "plugins", 0, false);
	if (divert > 0)
		ucl_object_insert_key(o, ucl_object_fromint(divert), "divert", 0,
		    false);
	/* Stopped by the admin: kept, not run. */
	if (ucl_object_toboolean(ucl_object_lookup(in, "stopped")))
		ucl_object_insert_key(o, ucl_object_frombool(true), "stopped", 0,
		    false);
	if (rules != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(rules), "rules", 0,
		    false);
	if (sstr(in, "thresholds") != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(sstr(in,
		    "thresholds")), "thresholds", 0, false);
	ucl_object_insert_key(o, ucl_object_copy(in), "spec", 0, false);
	return (o);
}

/*
 * The instances of what ("proxy" or "ids") as the agent takes them,
 * made of the page's forms in list; host names the host in their
 * comments.  NULL and why in err when one is not right.
 */
char *
security_build(const char *what, const ucl_object_t *list, const char *host,
    char *err, size_t errlen)
{
	const ucl_object_t	*in;
	ucl_object_iter_t	 it;
	ucl_object_t		*top, *arr, *o;
	char			*json, *out;
	const char		*seen[SEC_INSTANCES];
	int			 n, i;
	bool			 proxy;

	proxy = strcmp(what, "proxy") == 0;
	if (!proxy && strcmp(what, "ids") != 0) {
		snprintf(err, errlen, "what is proxy or ids");
		return (NULL);
	}
	/* The whole list, always: [] stops them all, nothing is no
	 * list (a word mistyped must not stop them). */
	if (list == NULL || ucl_object_type(list) != UCL_ARRAY) {
		snprintf(err, errlen, "instances is the whole list of them, [] "
		    "for none");
		return (NULL);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_fromstring("security"), "group",
	    0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	ucl_object_insert_key(top, arr, "instances", 0, false);
	n = 0;
	it = NULL;
	while ((in = ucl_object_iterate(list, &it, true)) != NULL) {
		if (n == SEC_INSTANCES) {
			snprintf(err, errlen, "%d instances at most",
			    SEC_INSTANCES);
			ucl_object_unref(top);
			return (NULL);
		}
		o = proxy ? proxy_one(in, n, host, err, errlen) : ids_one(in,
		    host, err, errlen);
		if (o == NULL) {
			ucl_object_unref(top);
			return (NULL);
		}
		for (i = 0; i < n; i++)
			if (strcmp(seen[i], sstr(in, "name")) == 0) {
				snprintf(err, errlen, "%s is named twice", seen[i]);
				ucl_object_unref(o);
				ucl_object_unref(top);
				return (NULL);
			}
		seen[n++] = sstr(in, "name");
		ucl_array_append(arr, o);
	}
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	out = json != NULL ? xstrdup(json) : NULL;
	free(json);
	return (out);
}
