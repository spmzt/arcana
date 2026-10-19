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

static bool
ifname_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 15)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '.')
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
    bool need, struct kore_buf *out, const char *pre, const char *sep,
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
			kore_buf_appendf(out, "%s%s%s", n > 0 ? sep : "", pre,
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
	struct kore_buf		*b, *d;
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
	b = kore_buf_alloc(4096);
	d = kore_buf_alloc(1024);
	kore_buf_appendf(b, "# Written by the Arcana console: the Security "
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
		kore_buf_appendf(b, strchr(ucl_object_tostring(e), ':') != NULL ?
		    "http_port [%s]:%jd" : "http_port %s:%jd",
		    ucl_object_tostring(e), (intmax_t)port);
		kore_buf_appendf(b, " ssl-bump tls-cert=@CA@ "
		    "generate-host-certificates=on dynamic_cert_mem_cache_size="
		    "4MB\n");
	}
	if (ucl_array_size(ucl_object_lookup(in, "listen")) == 0) {
		snprintf(err, errlen, "%s: listen: at least one address", name);
		goto bad;
	}
	kore_buf_appendf(b, "sslcrtd_program @CERTGEN@ -s @SSLDB@ -M 4MB\n"
	    "sslcrtd_children 3\nacl localnet src");
	if (!list_of(in, "allow", prefix_ok, true, b, " ", "", name, "allow "
	    "(the networks that may use it)", err, errlen))
		goto bad;
	if (malware)
		kore_buf_appendf(b, "\nicap_enable on\nicap_send_client_ip on\n"
		    "icap_service sec_av respmod_precache bypass=off "
		    "icap://127.0.0.1:%d/avscan\nadaptation_access sec_av allow "
		    "all", SEC_ICAP_PORT(idx));
	kore_buf_appendf(b, "\nacl denied_site ssl::server_name \"@DENY@\"\n"
	    "acl denied_url dstdomain \"@DENY@\"\nacl step1 at_step SslBump1\n"
	    "ssl_bump peek step1\nssl_bump terminate denied_site\nssl_bump %s all"
	    "\nhttp_access deny denied_url\nhttp_access allow localnet\n"
	    "http_access deny all\n", strcmp(mode, "inspect") == 0 ? "bump" :
	    "splice");
	/* Each domain denied with the names beneath it. */
	if (!list_of(in, "deny", domain_ok, false, d, ".", "\n", name, "deny",
	    err, errlen))
		goto bad;
	if (kore_buf_stringify(d, NULL)[0] != '\0')
		kore_buf_appendf(d, "\n");
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(name), "name", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(fib), "fib", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(mode), "mode", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(kore_buf_stringify(b,
	    NULL)), "conf", 0, false);
	/* ".a\n.a.b\n": Squid takes the first of two the second is under,
	 * and warns of the other. */
	ucl_object_insert_key(o, ucl_object_fromstring(kore_buf_stringify(d,
	    NULL)), "deny", 0, false);
	if (malware) {
		kore_buf_reset(b);
		kore_buf_appendf(b, "# Written by the Arcana console: the "
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
		    kore_buf_stringify(b, NULL)), "icap", 0, false);
	}
	ucl_object_insert_key(o, ucl_object_copy(in), "spec", 0, false);
	kore_buf_free(b);
	kore_buf_free(d);
	return (o);
bad:
	kore_buf_free(b);
	kore_buf_free(d);
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

/* A size as Suricata reads one: 64mb, 512kb, 1gb, or bytes. */
static bool
size_ok(const char *s)
{
	size_t	n;

	n = strspn(s, "0123456789");
	return (n > 0 && n <= 6 && (s[n] == '\0' || strcasecmp(s + n, "kb") ==
	    0 || strcasecmp(s + n, "mb") == 0 || strcasecmp(s + n, "gb") == 0));
}

/* A CPU set as Suricata's cpu-affinity has one: 0, 1-3, 0,2,4-7. */
static bool
cpus_ok(const char *s)
{
	size_t	n;

	n = strlen(s);
	return (n > 0 && n <= 64 && strspn(s, "0123456789,-") == n &&
	    isdigit((unsigned char)s[0]) && isdigit((unsigned char)s[n - 1]));
}

static bool
one_of(const char *v, const char *const *set)
{

	for (; *set != NULL; set++)
		if (strcmp(v, *set) == 0)
			return (true);
	return (false);
}

/*
 * An intrusion detection's settings, Suricata's own YAML: the event
 * types eve.json has (alerts always) and the alert's payload, the
 * statistics every so many seconds, the runmode, the CPUs its threads
 * run on, its memory and the TCP stream and HTTP bodies it inspects,
 * and what it does past a limit (exception-policy).  Each only when
 * given, Suricata's default otherwise; what the form has not, as YAML
 * of the admin's, last (checked by suricata -T with the rest).
 */
static bool
ids_settings(const ucl_object_t *in, const char *name, struct kore_buf *b,
    char *err, size_t errlen)
{
	static const char *const evtypes[] = { "anomaly", "http", "dns",
	    "tls", "ssh", "flow", "netflow", "fileinfo", "drop", "smtp",
	    "dhcp", "smb", "nfs", "ftp", "krb5", "snmp", "sip", "rdp", "mqtt",
	    "quic", "http2", "ike", "rfb", "dnp3", "modbus", NULL };
	static const char *const runmodes[] = { "autofp", "workers", "single",
	    NULL };
	static const char *const mpms[] = { "auto", "ac", "ac-ks", "hs", NULL };
	static const char *const profiles[] = { "low", "medium", "high", NULL };
	static const char *const presets[] = { "small", "medium", "large",
	    NULL };
	static const char *const inlines[] = { "auto", "yes", "no", NULL };
	static const char *const policies[] = { "auto", "drop-packet",
	    "drop-flow", "pass-packet", "pass-flow", "bypass", "reject",
	    "ignore", NULL };
	static const struct {
		const char	*key, *yaml;
	} memcaps[] = {
		{ "flow_memcap", "flow" }, { "stream_memcap", "stream" },
		{ "reassembly_memcap", "reassembly" },
		{ "defrag_memcap", "defrag" }, { "host_memcap", "host" },
		{ "http_memcap", "http" }, { "reassembly_depth", "depth" },
		{ "http_request_body", "request-body-limit" },
		{ "http_response_body", "response-body-limit" },
	};
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*v, *rm, *mpm, *prof, *inl, *pol, *mg, *wk, *extra;
	const char		*preset;
	int			 k;
	const char		*sz[nitems(memcaps)];
	int64_t			 stats, pending;
	size_t			 i;
	bool			 payload;

	/* Each word checked before a line is written. */
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "eve"), &it,
	    true)) != NULL)
		if (ucl_object_type(e) != UCL_STRING ||
		    !one_of(ucl_object_tostring(e), evtypes)) {
			snprintf(err, errlen, "%s: eve's types are of Suricata's: "
			    "anomaly, http, dns, tls, ssh, flow and the others",
			    name);
			return (false);
		}
	if (!num_of(in, "stats_interval", 0, 3600, 10, &stats) ||
	    !num_of(in, "max_pending", 0, 65535, 0, &pending)) {
		snprintf(err, errlen, "%s: statistics every 0 (none) to 3600 "
		    "seconds; max-pending-packets 1 to 65535", name);
		return (false);
	}
	rm = sstr(in, "runmode");
	mpm = sstr(in, "mpm");
	prof = sstr(in, "profile");
	preset = sstr(in, "preset");
	if (preset != NULL && preset[0] != '\0' && !one_of(preset, presets)) {
		snprintf(err, errlen, "%s: a preset is small, medium or large",
		    name);
		return (false);
	}
	inl = sstr(in, "stream_inline");
	pol = sstr(in, "exception_policy");
	if ((rm != NULL && rm[0] != '\0' && !one_of(rm, runmodes)) ||
	    (mpm != NULL && mpm[0] != '\0' && !one_of(mpm, mpms)) ||
	    (prof != NULL && prof[0] != '\0' && !one_of(prof, profiles)) ||
	    (inl != NULL && inl[0] != '\0' && !one_of(inl, inlines)) ||
	    (pol != NULL && pol[0] != '\0' && !one_of(pol, policies))) {
		snprintf(err, errlen, "%s: runmode is autofp, workers or single; "
		    "mpm auto, ac, ac-ks or hs; profile low, medium or high; "
		    "stream inline auto, yes or no; the exception policy one of "
		    "Suricata's", name);
		return (false);
	}
	for (i = 0; i < nitems(memcaps); i++) {
		sz[i] = sstr(in, memcaps[i].key);
		if (sz[i] != NULL && sz[i][0] == '\0')
			sz[i] = NULL;
		if (sz[i] != NULL && !size_ok(sz[i])) {
			snprintf(err, errlen, "%s: %s is a size: 64mb, 512kb, 1gb",
			    name, memcaps[i].key);
			return (false);
		}
	}
	/* A preset: what a field does not say, for a host of its size. */
	if (preset != NULL && preset[0] != '\0') {
		k = strcmp(preset, "small") == 0 ? 0 : strcmp(preset, "medium") ==
		    0 ? 1 : 2;
		if (rm == NULL || rm[0] == '\0')
			rm = k == 0 ? "autofp" : "workers";
		if (prof == NULL || prof[0] == '\0')
			prof = profiles[k];
		if (pending == 0)
			pending = k == 0 ? 1024 : k == 1 ? 2048 : 4096;
		if (sz[0] == NULL)
			sz[0] = k == 0 ? "64mb" : k == 1 ? "256mb" : "1gb";
		if (sz[1] == NULL)
			sz[1] = k == 0 ? "64mb" : k == 1 ? "256mb" : "1gb";
		if (sz[2] == NULL)
			sz[2] = k == 0 ? "256mb" : k == 1 ? "512mb" : "2gb";
	}
	mg = sstr(in, "management_cpus");
	wk = sstr(in, "worker_cpus");
	if ((mg != NULL && mg[0] != '\0' && !cpus_ok(mg)) || (wk != NULL &&
	    wk[0] != '\0' && !cpus_ok(wk))) {
		snprintf(err, errlen, "%s: a CPU set is CPUs and ranges: 0, "
		    "1-3, 0,2,4-7", name);
		return (false);
	}
	extra = sstr(in, "yaml");
	if (extra != NULL && strlen(extra) > 16 * 1024) {
		snprintf(err, errlen, "%s: its own YAML is 16 KB at most", name);
		return (false);
	}
	payload = ucl_object_toboolean(ucl_object_lookup(in, "payload"));

	/* eve.json: alerts, and what else it was told to log. */
	kore_buf_appendf(b, "outputs:\n  - eve-log:\n      enabled: yes\n"
	    "      filetype: regular\n      filename: eve.json\n      types:\n"
	    "        - alert:\n            metadata: yes\n");
	if (payload)
		kore_buf_appendf(b, "            payload: yes\n"
		    "            payload-printable: yes\n            packet: yes\n");
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "eve"), &it,
	    true)) != NULL)
		kore_buf_appendf(b, "        - %s\n", ucl_object_tostring(e));
	if (stats > 0)
		kore_buf_appendf(b, "        - stats:\n            totals: yes\n"
		    "            threads: no\n            deltas: no\n"
		    "stats:\n  enabled: yes\n  interval: %jd\n", (intmax_t)stats);
	else
		kore_buf_appendf(b, "stats:\n  enabled: no\n");
	if (rm != NULL && rm[0] != '\0')
		kore_buf_appendf(b, "runmode: %s\n", rm);
	if (pending > 0)
		kore_buf_appendf(b, "max-pending-packets: %jd\n",
		    (intmax_t)pending);
	if (mpm != NULL && mpm[0] != '\0')
		kore_buf_appendf(b, "mpm-algo: %s\nspm-algo: %s\n", mpm,
		    strcmp(mpm, "hs") == 0 ? "hs" : "auto");
	if (prof != NULL && prof[0] != '\0')
		kore_buf_appendf(b, "detect:\n  profile: %s\n  sgh-mpm-context: "
		    "auto\n", prof);
	/* Its threads on these CPUs alone (cpuset(1) has them). */
	if ((mg != NULL && mg[0] != '\0') || (wk != NULL && wk[0] != '\0')) {
		kore_buf_appendf(b, "threading:\n  set-cpu-affinity: yes\n"
		    "  cpu-affinity:\n");
		if (mg != NULL && mg[0] != '\0')
			kore_buf_appendf(b, "    management-cpu-set:\n"
			    "      cpu: [ %s ]\n", mg);
		if (wk != NULL && wk[0] != '\0')
			kore_buf_appendf(b, "    worker-cpu-set:\n      cpu: [ %s ]\n"
			    "      mode: exclusive\n", wk);
	}
	if (sz[0] != NULL)
		kore_buf_appendf(b, "flow:\n  memcap: %s\n", sz[0]);
	if (sz[1] != NULL || sz[2] != NULL || sz[6] != NULL || (inl != NULL &&
	    inl[0] != '\0') || ucl_object_lookup(in, "midstream") != NULL) {
		kore_buf_appendf(b, "stream:\n");
		if (sz[1] != NULL)
			kore_buf_appendf(b, "  memcap: %s\n", sz[1]);
		if (inl != NULL && inl[0] != '\0')
			kore_buf_appendf(b, "  inline: %s\n", inl);
		if (ucl_object_lookup(in, "midstream") != NULL)
			kore_buf_appendf(b, "  midstream: %s\n",
			    ucl_object_toboolean(ucl_object_lookup(in,
			    "midstream")) ? "true" : "false");
		if (sz[2] != NULL || sz[6] != NULL) {
			kore_buf_appendf(b, "  reassembly:\n");
			if (sz[2] != NULL)
				kore_buf_appendf(b, "    memcap: %s\n", sz[2]);
			if (sz[6] != NULL)
				kore_buf_appendf(b, "    depth: %s\n", sz[6]);
		}
	}
	if (sz[3] != NULL)
		kore_buf_appendf(b, "defrag:\n  memcap: %s\n", sz[3]);
	if (sz[4] != NULL)
		kore_buf_appendf(b, "host:\n  memcap: %s\n", sz[4]);
	/* HTTP: what of a body is inspected, libhtp's limits. */
	if (sz[5] != NULL || sz[7] != NULL || sz[8] != NULL) {
		kore_buf_appendf(b, "app-layer:\n  protocols:\n    http:\n"
		    "      enabled: yes\n");
		if (sz[5] != NULL)
			kore_buf_appendf(b, "      memcap: %s\n", sz[5]);
		if (sz[7] != NULL || sz[8] != NULL) {
			kore_buf_appendf(b, "      libhtp:\n        default-config:\n");
			if (sz[7] != NULL)
				kore_buf_appendf(b, "          request-body-limit: "
				    "%s\n", sz[7]);
			if (sz[8] != NULL)
				kore_buf_appendf(b, "          response-body-limit: "
				    "%s\n", sz[8]);
		}
	}
	if (pol != NULL && pol[0] != '\0')
		kore_buf_appendf(b, "exception-policy: %s\n", pol);
	if (extra != NULL && extra[strspn(extra, " \t\r\n")] != '\0') {
		kore_buf_appendf(b, "# The admin's own:\n%s", extra);
		v = extra + strlen(extra);
		if (v > extra && v[-1] != '\n')
			kore_buf_appendf(b, "\n");
	}
	return (true);
}

/* An interface netmap(4) opens: a name, or em0^, its host stack. */
static bool
nm_ifname_ok(const char *s)
{
	char	buf[24];
	size_t	n;

	if (s == NULL || (n = strlen(s)) < 2 || n > 16)
		return (false);
	snprintf(buf, sizeof(buf), "%.*s", (int)(s[n - 1] == '^' ? n - 1 :
	    n), s);
	return (ifname_ok(buf));
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
 * How it takes packets: by pcap(3) from its interfaces (the default);
 * or by netmap(4), from its interfaces, and where it prevents at L2,
 * between the two of each pair (em0:em1), copy-mode ips both ways, as
 * a bump in the wire; or em0:em0^, between em0 and its host stack.
 * The interfaces the agent watches into ifs.
 */
static bool
ids_capture(const ucl_object_t *in, const char *name, int64_t divert,
    struct kore_buf *b, ucl_object_t *ifs, char *err, size_t errlen)
{
	const ucl_object_t	*e, *pairs;
	ucl_object_iter_t	 it;
	const char		*cap;
	char			 a[24], c[24], *colon;

	cap = sstr(in, "capture");
	pairs = ucl_object_lookup(in, "pairs");
	if (cap == NULL || cap[0] == '\0' || strcmp(cap, "pcap") == 0) {
		if (ucl_array_size(pairs) > 0) {
			snprintf(err, errlen, "%s: pairs of interfaces are "
			    "netmap's (capture netmap)", name);
			return (false);
		}
		kore_buf_appendf(b, "pcap:\n");
		if (!list_of(in, "interfaces", ifname_ok, true, b,
		    "  - interface: ", "\n", name, "interfaces", err, errlen))
			return (false);
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(in,
		    "interfaces"), &it, true)) != NULL)
			add_if(ifs, ucl_object_tostring(e));
		return (true);
	}
	if (strcmp(cap, "netmap") != 0) {
		snprintf(err, errlen, "%s: capture is pcap or netmap", name);
		return (false);
	}
	if (divert > 0) {
		snprintf(err, errlen, "%s: it prevents by divert or by netmap's "
		    "pairs, not both", name);
		return (false);
	}
	kore_buf_appendf(b, "netmap:\n");
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "interfaces"),
	    &it, true)) != NULL) {
		if (ucl_object_type(e) != UCL_STRING ||
		    !nm_ifname_ok(ucl_object_tostring(e))) {
			snprintf(err, errlen, "%s: its interfaces are names, or "
			    "em0^ (a host stack)", name);
			return (false);
		}
		kore_buf_appendf(b, "  - interface: %s\n    threads: auto\n",
		    ucl_object_tostring(e));
		add_if(ifs, ucl_object_tostring(e));
	}
	it = NULL;
	while ((e = ucl_object_iterate(pairs, &it, true)) != NULL) {
		if (ucl_object_type(e) != UCL_STRING || (colon = strchr(
		    ucl_object_tostring(e), ':')) == NULL) {
			snprintf(err, errlen, "%s: a pair is two interfaces, "
			    "em0:em1 or em0:em0^", name);
			return (false);
		}
		snprintf(a, sizeof(a), "%.*s", (int)(colon -
		    ucl_object_tostring(e)), ucl_object_tostring(e));
		snprintf(c, sizeof(c), "%s", colon + 1);
		if (!nm_ifname_ok(a) || !nm_ifname_ok(c) || strcmp(a, c) == 0) {
			snprintf(err, errlen, "%s: a pair is two interfaces, "
			    "em0:em1 or em0:em0^", name);
			return (false);
		}
		kore_buf_appendf(b, "  - interface: %s\n    threads: auto\n"
		    "    copy-mode: ips\n    copy-iface: %s\n  - interface: %s\n"
		    "    threads: auto\n    copy-mode: ips\n    copy-iface: %s\n",
		    a, c, c, a);
		add_if(ifs, a);
		add_if(ifs, c);
	}
	if (ucl_array_size(ifs) == 0) {
		snprintf(err, errlen, "%s: netmap needs interfaces, or pairs of "
		    "them", name);
		return (false);
	}
	/* netmap's IPS is a worker's to the end. */
	if (ucl_array_size(pairs) > 0 && (sstr(in, "runmode") == NULL ||
	    sstr(in, "runmode")[0] == '\0'))
		kore_buf_appendf(b, "runmode: workers\n");
	return (true);
}

static ucl_object_t *
ids_one(const ucl_object_t *in, const char *host, char *err, size_t errlen)
{
	struct kore_buf		*b;
	ucl_object_t		*o, *ifs;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*name, *rules;
	int64_t			 divert;
	bool			 ruleset, home_any;

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
	b = kore_buf_alloc(4096);
	kore_buf_appendf(b, "%%YAML 1.1\n---\n# Written by the Arcana console: "
	    "the Security section's intrusion detection %s at %s,\n# by "
	    "Suricata, %s.\nvars:\n  address-groups:\n    HOME_NET: \"", name,
	    host, divert > 0 ? "preventing: what ipfw diverts to it" :
	    "detecting: what its interfaces see");
	/* "any", alone: every address is home, and so outside too, as
	 * Suricata does not take the whole address space negated. */
	home_any = false;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "home"), &it, true))
	    != NULL)
		if (ucl_object_type(e) == UCL_STRING && strcasecmp(
		    ucl_object_tostring(e), "any") == 0)
			home_any = true;
	if (home_any && ucl_array_size(ucl_object_lookup(in, "home")) != 1) {
		snprintf(err, errlen, "%s: home (the networks it guards): any "
		    "stands alone, every address", name);
		goto bad;
	}
	if (!home_any)
		kore_buf_appendf(b, "[");
	if (home_any)
		kore_buf_appendf(b, "any");
	else if (ucl_array_size(ucl_object_lookup(in, "home")) == 0)
		kore_buf_appendf(b, "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16");
	else if (!list_of(in, "home", prefix_ok, false, b, "", ",", name,
	    "home (the networks it guards, as a.b.c.d/n, x::/n or any)", err,
	    errlen))
		goto bad;
	kore_buf_appendf(b, "%s\"\n    EXTERNAL_NET: \"%s\"\n", home_any ? "" :
	    "]", home_any ? "any" : "!$HOME_NET");
	kore_buf_appendf(b, ""
	    "    HTTP_SERVERS: \"$HOME_NET\"\n    SMTP_SERVERS: \"$HOME_NET\"\n"
	    "    SQL_SERVERS: \"$HOME_NET\"\n    DNS_SERVERS: \"$HOME_NET\"\n"
	    "    TELNET_SERVERS: \"$HOME_NET\"\n    AIM_SERVERS: "
	    "\"$EXTERNAL_NET\"\n    DC_SERVERS: \"$HOME_NET\"\n    DNP3_SERVER: "
	    "\"$HOME_NET\"\n    DNP3_CLIENT: \"$HOME_NET\"\n    MODBUS_CLIENT: "
	    "\"$HOME_NET\"\n    MODBUS_SERVER: \"$HOME_NET\"\n    ENIP_CLIENT: "
	    "\"$HOME_NET\"\n    ENIP_SERVER: \"$HOME_NET\"\n  port-groups:\n"
	    "    HTTP_PORTS: \"80\"\n    SHELLCODE_PORTS: \"!80\"\n"
	    "    ORACLE_PORTS: 1521\n    SSH_PORTS: 22\n    DNP3_PORTS: 20000\n"
	    "    MODBUS_PORTS: 502\n    FILE_DATA_PORTS: \"[$HTTP_PORTS,110,"
	    "143]\"\n    FTP_PORTS: 21\n    GENEVE_PORTS: 6081\n    VXLAN_PORTS: "
	    "4789\n    TEREDO_PORTS: 3544\ndefault-log-dir: @LOGDIR@\n");
	if (!ids_settings(in, name, b, err, errlen))
		goto bad;
	kore_buf_appendf(b, "logging:\n  default-log-level: notice\n  outputs:\n"
	    "    - console:\n        enabled: no\n    - file:\n        enabled: "
	    "yes\n        level: info\n        filename: suricata.log\n");
	ifs = ucl_object_typed_new(UCL_ARRAY);
	if (!ids_capture(in, name, divert, b, ifs, err, errlen)) {
		ucl_object_unref(ifs);
		goto bad;
	}
	kore_buf_appendf(b, "\nrule-files:\n  - @RULES@\n");
	/* The agent's, where it is fetched; left out until it is. */
	if (ruleset)
		kore_buf_appendf(b, "  - @RULESET@\n");
	/* Suricata's own files, which a fresh install has as samples: the
	 * agent names the one there is. */
	kore_buf_appendf(b, "classification-file: @CLASSIFICATION@\n"
	    "reference-config-file: @REFERENCE@\n"
	    "threshold-file: @THRESHOLD@\n"
	    "run-as:\n  user: root\n");
	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(name), "name", 0,
	    false);
	ucl_object_insert_key(o, ifs, "interfaces", 0, false);
	if (sstr(in, "capture") != NULL && strcmp(sstr(in, "capture"),
	    "netmap") == 0)
		ucl_object_insert_key(o, ucl_object_fromstring("netmap"),
		    "capture", 0, false);
	/* Its interfaces' offloading turned off as it starts. */
	if (ucl_object_toboolean(ucl_object_lookup(in, "offload_off")))
		ucl_object_insert_key(o, ucl_object_frombool(false), "offload",
		    0, false);
	if (divert > 0)
		ucl_object_insert_key(o, ucl_object_fromint(divert), "divert", 0,
		    false);
	/* Stopped by the admin: kept, not run. */
	if (ucl_object_toboolean(ucl_object_lookup(in, "stopped")))
		ucl_object_insert_key(o, ucl_object_frombool(true), "stopped", 0,
		    false);
	ucl_object_insert_key(o, ucl_object_fromstring(kore_buf_stringify(b,
	    NULL)), "conf", 0, false);
	if (rules != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(rules), "rules", 0,
		    false);
	if (sstr(in, "thresholds") != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(sstr(in,
		    "thresholds")), "thresholds", 0, false);
	ucl_object_insert_key(o, ucl_object_copy(in), "spec", 0, false);
	kore_buf_free(b);
	return (o);
bad:
	kore_buf_free(b);
	return (NULL);
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
	out = json != NULL ? kore_strdup(json) : NULL;
	free(json);
	return (out);
}
