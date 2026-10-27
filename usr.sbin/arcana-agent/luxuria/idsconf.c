/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Luxuria: Suricata's YAML for an instance, rendered here from its
 * settings, the page's form as the console passes it on, so that what
 * is checked (a plugin's path, a Lua script's name, the keys the form
 * owns) is what runs.  Two shapes: the Security section's, with every
 * setting of the form; and SD-WAN's, a service's security policies
 * (Arcana's own) on its UNIs.  The places the agent fills (@LOGDIR@ and the
 * like) are left in the text for inst_conf().
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

#define	LIST_MAX	256

static const char *
sstr(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, k);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

static bool
one_of(const char *v, const char *const *set)
{

	for (; *set != NULL; set++)
		if (strcmp(v, *set) == 0)
			return (true);
	return (false);
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

/* An interface netmap(4) opens: a name, or em0^, its host stack. */
static bool
nm_ifname_ok(const char *s)
{
	char	buf[24];
	size_t	n;

	/* 15 at most, the ^ of a host stack counted (IFNAMSIZ). */
	if (s == NULL || (n = strlen(s)) < 2 || n > 15)
		return (false);
	snprintf(buf, sizeof(buf), "%.*s", (int)(s[n - 1] == '^' ? n - 1 :
	    n), s);
	return (ifname_ok(buf));
}

/* A Lua script's name, as lua_ok takes it: NAME.lua. */
static bool
lua_name_ok(const char *k)
{
	size_t	len;

	len = k != NULL ? strlen(k) : 0;
	return (len >= 5 && len <= 36 && strcmp(k + len - 4, ".lua") == 0 &&
	    strspn(k, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789_-") == len - 4);
}

/*
 * Each string of the list at k checked by ok, into fp (which may be
 * NULL), joined by sep; false, and why, for one that is not, or for
 * none when one is needed.
 */
static bool
list_of(struct work *w, const ucl_object_t *in, const char *k,
    bool (*ok)(const char *), bool need, FILE *fp, const char *pre,
    const char *sep, const char *name, const char *what, const char **errp)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int			 n;

	if (ucl_object_lookup(in, k) != NULL && ucl_object_type(
	    ucl_object_lookup(in, k)) != UCL_ARRAY) {
		*errp = wfmt(w, "%s: %s: a list", name, what);
		return (false);
	}
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, k), &it, true)) !=
	    NULL) {
		if (n == LIST_MAX) {
			*errp = wfmt(w, "%s: %s: %d at most", name, what, LIST_MAX);
			return (false);
		}
		if (ucl_object_type(e) != UCL_STRING || !ok(ucl_object_tostring(
		    e))) {
			*errp = wfmt(w, "%s: %s: %.64s is not one", name, what,
			    ucl_object_tostring_forced(e));
			return (false);
		}
		if (fp != NULL)
			fprintf(fp, "%s%s%s", n > 0 ? sep : "", pre,
			    ucl_object_tostring(e));
		n++;
	}
	if (need && n == 0) {
		*errp = wfmt(w, "%s: %s: at least one", name, what);
		return (false);
	}
	return (true);
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

/* The variables the common rule sets name, as Suricata's own file. */
static const char *const groups =
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
    "4789\n    TEREDO_PORTS: 3544\n";

/*
 * The settings: the event types eve.json has (alerts always) and the
 * alert's payload, the statistics every so many seconds, the runmode,
 * the CPUs its threads run on, its memory and the TCP stream and HTTP
 * bodies it inspects, and what it does past a limit (exception-policy).
 * Each only when given, Suricata's default otherwise; what the form
 * has not, as YAML of the admin's, last (checked by suricata -T with
 * the rest).
 */
static bool
settings(struct work *w, const ucl_object_t *in, const char *name, FILE *b,
    const char **errp)
{
	static const char *const evtypes[] = { "anomaly", "http", "dns",
	    "tls", "ssh", "flow", "netflow", "fileinfo", "drop", "smtp",
	    "dhcp", "smb", "nfs", "ftp", "krb5", "snmp", "sip", "rdp", "mqtt",
	    "quic", "http2", "ike", "rfb", "dnp3", "modbus", NULL };
	static const char *const runmodes[] = { "autofp", "workers", "single",
	    NULL };
	static const char *const schedulers[] = { "hash", "ippair", "ftp-hash",
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
	static const char *const owned[] = { "plugins:", "run-as:",
	    "unix-command:", "default-rule-path:", "outputs:", "rule-files:",
	    "pcap:", "netmap:", "security:", "threshold-file:",
	    "classification-file:", "reference-config-file:",
	    "default-log-dir:", "logging:", "af-packet:", "ipfw:" };
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*v, *rm, *mpm, *prof, *inl, *pol, *mg, *wk, *extra;
	const char		*sched;
	const char		*preset, *p;
	const char		*sz[nitems(memcaps)];
	int64_t			 k64, stats, pending;
	size_t			 i, oi;
	int			 k;
	bool			 payload;

	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "eve"), &it,
	    true)) != NULL)
		if (ucl_object_type(e) != UCL_STRING ||
		    !one_of(ucl_object_tostring(e), evtypes)) {
			*errp = wfmt(w, "%s: eve's types are of Suricata's: "
			    "anomaly, http, dns, tls, ssh, flow and the others",
			    name);
			return (false);
		}
	if (!num_of(in, "stats_interval", 0, 3600, 10, &stats) ||
	    !num_of(in, "max_pending", 0, 65535, 0, &pending)) {
		*errp = wfmt(w, "%s: statistics every 0 (none) to 3600 seconds; "
		    "max-pending-packets 1 to 65535", name);
		return (false);
	}
	rm = sstr(in, "runmode");
	mpm = sstr(in, "mpm");
	prof = sstr(in, "profile");
	preset = sstr(in, "preset");
	if (preset != NULL && preset[0] != '\0' && !one_of(preset, presets)) {
		*errp = wfmt(w, "%s: a preset is small, medium or large", name);
		return (false);
	}
	inl = sstr(in, "stream_inline");
	pol = sstr(in, "exception_policy");
	sched = sstr(in, "autofp_scheduler");
	if (sched != NULL && sched[0] != '\0' && !one_of(sched, schedulers)) {
		*errp = wfmt(w, "%s: autofp's scheduler is hash, ippair or "
		    "ftp-hash", name);
		return (false);
	}
	if ((rm != NULL && rm[0] != '\0' && !one_of(rm, runmodes)) ||
	    (mpm != NULL && mpm[0] != '\0' && !one_of(mpm, mpms)) ||
	    (prof != NULL && prof[0] != '\0' && !one_of(prof, profiles)) ||
	    (inl != NULL && inl[0] != '\0' && !one_of(inl, inlines)) ||
	    (pol != NULL && pol[0] != '\0' && !one_of(pol, policies))) {
		*errp = wfmt(w, "%s: runmode is autofp, workers or single; mpm "
		    "auto, ac, ac-ks or hs; profile low, medium or high; stream "
		    "inline auto, yes or no; the exception policy one of "
		    "Suricata's", name);
		return (false);
	}
	for (i = 0; i < nitems(memcaps); i++) {
		sz[i] = sstr(in, memcaps[i].key);
		if (sz[i] != NULL && sz[i][0] == '\0')
			sz[i] = NULL;
		if (sz[i] != NULL && !size_ok(sz[i])) {
			*errp = wfmt(w, "%s: %s is a size: 64mb, 512kb, 1gb", name,
			    memcaps[i].key);
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
		*errp = wfmt(w, "%s: a CPU set is CPUs and ranges: 0, 1-3, "
		    "0,2,4-7", name);
		return (false);
	}
	extra = sstr(in, "yaml");
	if (extra != NULL && strlen(extra) > 16 * 1024) {
		*errp = wfmt(w, "%s: its own YAML is 16 KB at most", name);
		return (false);
	}
	/* The keys the form owns are not its to set again: a plugin, a
	 * user or a socket of its own would go past the checks here. */
	for (p = extra; p != NULL && *p != '\0'; p = strchr(p, '\n') != NULL ?
	    strchr(p, '\n') + 1 : NULL)
		for (oi = 0; oi < nitems(owned); oi++)
			if (strncmp(p, owned[oi], strlen(owned[oi])) == 0) {
				*errp = wfmt(w, "%s: its own YAML may not set %.*s, "
				    "which the form does", name, (int)strlen(
				    owned[oi]) - 1, owned[oi]);
				return (false);
			}
	payload = ucl_object_toboolean(ucl_object_lookup(in, "payload"));
	/* eve.json: alerts, and what else it was told to log. */
	fprintf(b, "outputs:\n  - eve-log:\n      enabled: yes\n"
	    "      filetype: regular\n      filename: eve.json\n      types:\n"
	    "        - alert:\n            metadata: yes\n");
	if (payload)
		fprintf(b, "            payload: yes\n"
		    "            payload-printable: yes\n            packet: yes\n");
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "eve"), &it,
	    true)) != NULL)
		fprintf(b, "        - %s\n", ucl_object_tostring(e));
	if (stats > 0)
		fprintf(b, "        - stats:\n            totals: yes\n"
		    "            threads: no\n            deltas: no\n");
	/* Its Lua scripts as outputs, run on what they ask for. */
	if (ucl_array_size(ucl_object_lookup(in, "lua_outputs")) > 0) {
		fprintf(b, "  - lua:\n      enabled: yes\n"
		    "      scripts-dir: @LUADIR@\n      scripts:\n");
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(in,
		    "lua_outputs"), &it, true)) != NULL) {
			if (ucl_object_type(e) != UCL_STRING || !lua_name_ok(
			    ucl_object_tostring(e)) || ucl_object_lookup(
			    ucl_object_lookup(in, "lua"), ucl_object_tostring(e)) ==
			    NULL) {
				*errp = wfmt(w, "%s: a Lua output is one of its "
				    "scripts", name);
				return (false);
			}
			fprintf(b, "        - %s\n", ucl_object_tostring(e));
		}
	}
	/* The packets of its alerts kept, a ring of files. */
	if (ucl_object_toboolean(ucl_object_lookup(in, "pcap_log"))) {
		v = sstr(in, "pcap_log_limit");
		if (!num_of(in, "pcap_log_files", 1, 1000, 10, &k64) || (v !=
		    NULL && v[0] != '\0' && !size_ok(v))) {
			*errp = wfmt(w, "%s: pcap-log's limit is a size, its files "
			    "1 to 1000", name);
			return (false);
		}
		fprintf(b, "  - pcap-log:\n      enabled: yes\n"
		    "      filename: log.pcap\n      limit: %s\n"
		    "      max-files: %jd\n      compression: none\n"
		    "      mode: normal\n      conditional: alerts\n", v != NULL &&
		    v[0] != '\0' ? v : "100mb", (intmax_t)k64);
	}
	if (stats > 0)
		fprintf(b, "stats:\n  enabled: yes\n  interval: %jd\n",
		    (intmax_t)stats);
	else
		fprintf(b, "stats:\n  enabled: no\n");
	/* Lua rules where it has scripts, its directory theirs. */
	it = NULL;
	if (ucl_object_type(ucl_object_lookup(in, "lua")) == UCL_OBJECT &&
	    ucl_object_iterate(ucl_object_lookup(in, "lua"), &it, true) !=
	    NULL)
		fprintf(b, "default-rule-path: @LUADIR@\nsecurity:\n"
		    "  lua:\n    allow-rules: yes\n");
	/* Its plugins, shared objects plugins_ok() finds root's. */
	if (ucl_array_size(ucl_object_lookup(in, "plugins")) > 0) {
		fprintf(b, "plugins:\n");
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(in, "plugins"),
		    &it, true)) != NULL) {
			v = ucl_object_type(e) == UCL_STRING ?
			    ucl_object_tostring(e) : "";
			if (strncmp(v, "/usr/local/lib/", 15) != 0 || strlen(v) >
			    200 || strspn(v, "abcdefghijklmnopqrstuvwxyz"
			    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-") !=
			    strlen(v) || strstr(v, "..") != NULL || strlen(v) < 19 ||
			    strcmp(v + strlen(v) - 3, ".so") != 0) {
				*errp = wfmt(w, "%s: a plugin is a .so under "
				    "/usr/local/lib", name);
				return (false);
			}
			fprintf(b, "  - %s\n", v);
		}
	}
	if ((rm == NULL || rm[0] == '\0') && ucl_array_size(
	    ucl_object_lookup(in, "pairs")) > 0)
		rm = "workers";
	if (rm != NULL && rm[0] != '\0')
		fprintf(b, "runmode: %s\n", rm);
	/* autofp's packets to its workers by flow, as hash keeps a flow's
	 * on one, unless the form says otherwise. */
	if (rm != NULL && strcmp(rm, "autofp") == 0)
		fprintf(b, "autofp-scheduler: %s\n", sched != NULL && sched[0] !=
		    '\0' ? sched : "hash");
	if (pending > 0)
		fprintf(b, "max-pending-packets: %jd\n", (intmax_t)pending);
	if (mpm != NULL && mpm[0] != '\0')
		fprintf(b, "mpm-algo: %s\nspm-algo: %s\n", mpm, strcmp(mpm, "hs")
		    == 0 ? "hs" : "auto");
	if (prof != NULL && prof[0] != '\0')
		fprintf(b, "detect:\n  profile: %s\n  sgh-mpm-context: auto\n",
		    prof);
	/* Its threads on these CPUs alone (cpuset(1) has them). */
	if ((mg != NULL && mg[0] != '\0') || (wk != NULL && wk[0] != '\0')) {
		fprintf(b, "threading:\n  set-cpu-affinity: yes\n"
		    "  cpu-affinity:\n");
		if (mg != NULL && mg[0] != '\0')
			fprintf(b, "    management-cpu-set:\n      cpu: [ %s ]\n",
			    mg);
		if (wk != NULL && wk[0] != '\0')
			fprintf(b, "    worker-cpu-set:\n      cpu: [ %s ]\n"
			    "      mode: exclusive\n", wk);
	}
	if (sz[0] != NULL)
		fprintf(b, "flow:\n  memcap: %s\n", sz[0]);
	if (sz[1] != NULL || sz[2] != NULL || sz[6] != NULL || (inl != NULL &&
	    inl[0] != '\0') || ucl_object_lookup(in, "midstream") != NULL) {
		fprintf(b, "stream:\n");
		if (sz[1] != NULL)
			fprintf(b, "  memcap: %s\n", sz[1]);
		if (inl != NULL && inl[0] != '\0')
			fprintf(b, "  inline: %s\n", inl);
		if (ucl_object_lookup(in, "midstream") != NULL)
			fprintf(b, "  midstream: %s\n", ucl_object_toboolean(
			    ucl_object_lookup(in, "midstream")) ? "true" :
			    "false");
		if (sz[2] != NULL || sz[6] != NULL) {
			fprintf(b, "  reassembly:\n");
			if (sz[2] != NULL)
				fprintf(b, "    memcap: %s\n", sz[2]);
			if (sz[6] != NULL)
				fprintf(b, "    depth: %s\n", sz[6]);
		}
	}
	if (sz[3] != NULL)
		fprintf(b, "defrag:\n  memcap: %s\n", sz[3]);
	if (sz[4] != NULL)
		fprintf(b, "host:\n  memcap: %s\n", sz[4]);
	/* HTTP: what of a body is inspected, libhtp's limits. */
	if (sz[5] != NULL || sz[7] != NULL || sz[8] != NULL) {
		fprintf(b, "app-layer:\n  protocols:\n    http:\n"
		    "      enabled: yes\n");
		if (sz[5] != NULL)
			fprintf(b, "      memcap: %s\n", sz[5]);
		if (sz[7] != NULL || sz[8] != NULL) {
			fprintf(b, "      libhtp:\n        default-config:\n");
			if (sz[7] != NULL)
				fprintf(b, "          request-body-limit: %s\n",
				    sz[7]);
			if (sz[8] != NULL)
				fprintf(b, "          response-body-limit: %s\n",
				    sz[8]);
		}
	}
	if (pol != NULL && pol[0] != '\0')
		fprintf(b, "exception-policy: %s\n", pol);
	if (extra != NULL && extra[strspn(extra, " \t\r\n")] != '\0') {
		fprintf(b, "# The admin's own:\n%s", extra);
		v = extra + strlen(extra);
		if (v > extra && v[-1] != '\n')
			fprintf(b, "\n");
	}
	return (true);
}

/*
 * How it takes packets: by pcap(3) from its interfaces (the default);
 * or by netmap(4), from its interfaces, and where it prevents at L2,
 * between the two of each pair (em0:em1), copy-mode ips both ways, as
 * a bump in the wire; or em0:em0^, between em0 and its host stack.
 * The interfaces the agent watches into ifs.
 */
static bool
capture(struct work *w, const ucl_object_t *in, const char *name,
    int64_t divert, FILE *b, ucl_object_t *ifs, const char **errp)
{
	const ucl_object_t	*e, *pairs;
	ucl_object_iter_t	 it;
	const char		*cap;
	char			 a[24], c[24], *colon;

	cap = sstr(in, "capture");
	pairs = ucl_object_lookup(in, "pairs");
	if (cap == NULL || cap[0] == '\0' || strcmp(cap, "pcap") == 0) {
		if (ucl_array_size(pairs) > 0) {
			*errp = wfmt(w, "%s: pairs of interfaces are netmap's "
			    "(capture netmap)", name);
			return (false);
		}
		fprintf(b, "pcap:\n");
		if (!list_of(w, in, "interfaces", ifname_ok, true, b,
		    "  - interface: ", "\n", name, "interfaces", errp))
			return (false);
		fprintf(b, "\n");
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(in,
		    "interfaces"), &it, true)) != NULL)
			add_if(ifs, ucl_object_tostring(e));
		return (true);
	}
	if (strcmp(cap, "netmap") != 0) {
		*errp = wfmt(w, "%s: capture is pcap or netmap", name);
		return (false);
	}
	if (divert > 0) {
		*errp = wfmt(w, "%s: it prevents by divert or by netmap's pairs, "
		    "not both", name);
		return (false);
	}
	fprintf(b, "netmap:\n");
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "interfaces"),
	    &it, true)) != NULL) {
		if (ucl_object_type(e) != UCL_STRING ||
		    !nm_ifname_ok(ucl_object_tostring(e))) {
			*errp = wfmt(w, "%s: its interfaces are names, or em0^ (a "
			    "host stack)", name);
			return (false);
		}
		fprintf(b, "  - interface: %s\n    threads: auto\n",
		    ucl_object_tostring(e));
		add_if(ifs, ucl_object_tostring(e));
	}
	it = NULL;
	while ((e = ucl_object_iterate(pairs, &it, true)) != NULL) {
		if (ucl_object_type(e) != UCL_STRING || (colon = strchr(
		    ucl_object_tostring(e), ':')) == NULL) {
			*errp = wfmt(w, "%s: a pair is two interfaces, em0:em1 or "
			    "em0:em0^", name);
			return (false);
		}
		snprintf(a, sizeof(a), "%.*s", (int)(colon -
		    ucl_object_tostring(e)), ucl_object_tostring(e));
		snprintf(c, sizeof(c), "%s", colon + 1);
		if (!nm_ifname_ok(a) || !nm_ifname_ok(c) || strcmp(a, c) == 0) {
			*errp = wfmt(w, "%s: a pair is two interfaces, em0:em1 or "
			    "em0:em0^", name);
			return (false);
		}
		/* A bridge's member: the bridge forwards its packets around
		 * the pair, which would see some and stop none. */
		for (int k = 0; k < 2; k++) {
			const char	*br, *ifn;

			ifn = wstrndup(w, k == 0 ? a : c, strcspn(k == 0 ? a : c,
			    "^"));
			if ((br = bridge_holding(w, ifn)) != NULL) {
				*errp = wfmt(w, "%s: %s is a member of %s: netmap's "
				    "pair takes it whole, the bridge's members "
				    "are not its; take it out of the bridge, or "
				    "pair the bridge itself", name, ifn, br);
				return (false);
			}
		}
		fprintf(b, "  - interface: %s\n    threads: auto\n"
		    "    copy-mode: ips\n    copy-iface: %s\n  - interface: %s\n"
		    "    threads: auto\n    copy-mode: ips\n    copy-iface: %s\n",
		    a, c, c, a);
		add_if(ifs, a);
		add_if(ifs, c);
	}
	if (ucl_array_size(ifs) == 0) {
		*errp = wfmt(w, "%s: netmap needs interfaces, or pairs of them",
		    name);
		return (false);
	}
	/* netmap's IPS is a worker's to the end: settings() writes the
	 * runmode, workers unless the form says so. */
	if (ucl_array_size(pairs) > 0 && sstr(in, "runmode") != NULL &&
	    sstr(in, "runmode")[0] != '\0' && strcmp(sstr(in, "runmode"),
	    "workers") != 0) {
		*errp = wfmt(w, "%s: netmap's pairs need the workers runmode",
		    name);
		return (false);
	}
	return (true);
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

/*
 * The Security section's instance: its YAML from the form, with the
 * places the agent fills; the interfaces it watches into ifs.  NULL
 * and why in *errp when the form is not right.
 */
char *
ids_conf_render(struct work *w, const ucl_object_t *in, const char *name,
    const char *host, int64_t divert, ucl_object_t *ifs, const char **errp)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	FILE			*b;
	char			*buf;
	size_t			 len;
	bool			 ruleset, home_any;

	buf = NULL;
	len = 0;
	if ((b = open_memstream(&buf, &len)) == NULL) {
		*errp = strerror(errno);
		return (NULL);
	}
	ruleset = ucl_object_toboolean(ucl_object_lookup(in, "ruleset"));
	fprintf(b, "%%YAML 1.1\n---\n# Written by arcana-agent for the Arcana "
	    "console: the Security section's intrusion detection %s at %s,\n# "
	    "by Suricata, %s.\nvars:\n  address-groups:\n    HOME_NET: \"",
	    name, host, divert > 0 ? "preventing: what ipfw diverts to it" :
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
	if (ucl_object_lookup(in, "home") != NULL && ucl_object_type(
	    ucl_object_lookup(in, "home")) != UCL_ARRAY) {
		*errp = wfmt(w, "%s: home is a list of networks", name);
		goto bad;
	}
	if (home_any && ucl_array_size(ucl_object_lookup(in, "home")) != 1) {
		*errp = wfmt(w, "%s: home (the networks it guards): any stands "
		    "alone, every address", name);
		goto bad;
	}
	if (!home_any)
		fprintf(b, "[");
	if (home_any)
		fprintf(b, "any");
	else if (ucl_array_size(ucl_object_lookup(in, "home")) == 0)
		fprintf(b, "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16");
	else if (!list_of(w, in, "home", prefix_ok, false, b, "", ",", name,
	    "home (the networks it guards, as a.b.c.d/n, x::/n or any)", errp))
		goto bad;
	fprintf(b, "%s\"\n    EXTERNAL_NET: \"%s\"\n", home_any ? "" : "]",
	    home_any ? "any" : "!$HOME_NET");
	fprintf(b, "%sdefault-log-dir: @LOGDIR@\n", groups);
	if (!settings(w, in, name, b, errp))
		goto bad;
	fprintf(b, "logging:\n  default-log-level: notice\n  outputs:\n"
	    "    - console:\n        enabled: no\n    - file:\n        enabled: "
	    "yes\n        level: info\n        filename: suricata.log\n");
	if (!capture(w, in, name, divert, b, ifs, errp))
		goto bad;
	fprintf(b, "\nrule-files:\n  - @RULES@\n");
	/* The agent's, where it is fetched; left out until it is. */
	if (ruleset)
		fprintf(b, "  - @RULESET@\n");
	/* Suricata's own files, which a fresh install has as samples: the
	 * agent names the one there is. */
	fprintf(b, "classification-file: @CLASSIFICATION@\n"
	    "reference-config-file: @REFERENCE@\n"
	    "threshold-file: @THRESHOLD@\n"
	    /* Its own socket: the agent asks it what it runs. */
	    "unix-command:\n  enabled: yes\n  filename: @SOCKET@\n"
	    "run-as:\n  user: root\n");
	return (closed(w, b, &buf, errp));
bad:
	fclose(b);
	free(buf);
	return (NULL);
}

/*
 * An SD-WAN service's instance (Arcana's own): its home the UNIs' prefixes,
 * pcap on the UNIs' interfaces, alerts alone; where the edge itself
 * answers some of the UNIs' traffic it sees one side of those flows
 * (oneside), taken as they come.
 */
char *
ids_conf_sdwan(struct work *w, const ucl_object_t *in, const char *name,
    const char *host, ucl_object_t *ifs, const char **errp)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	FILE			*b;
	char			*buf;
	size_t			 len;

	buf = NULL;
	len = 0;
	if ((b = open_memstream(&buf, &len)) == NULL) {
		*errp = strerror(errno);
		return (NULL);
	}
	fprintf(b, "%%YAML 1.1\n---\n# Written by arcana-agent for the Arcana "
	    "console: SD-WAN service %s at %s.\n# The intrusion detection of "
	    "its security policies (Arcana's own), by Suricata.\nvars:\n  "
	    "address-groups:\n    HOME_NET: \"[", sstr(in, "service") != NULL ?
	    sstr(in, "service") : name, host);
	if (ucl_array_size(ucl_object_lookup(in, "home")) == 0)
		fprintf(b, "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16");
	else if (!list_of(w, in, "home", prefix_ok, false, b, "", ",", name,
	    "home (the UNIs' prefixes)", errp))
		goto bad;
	fprintf(b, "]\"\n    EXTERNAL_NET: \"!$HOME_NET\"\n%s"
	    "default-log-dir: @LOGDIR@\n"
	    "outputs:\n  - eve-log:\n      enabled: yes\n      filetype: regular\n"
	    "      filename: eve.json\n      types:\n        - alert\n"
	    "logging:\n  default-log-level: notice\n  outputs:\n    - console:\n"
	    "        enabled: no\n    - file:\n        enabled: yes\n"
	    "        level: info\n        filename: suricata.log\n"
	    "pcap:\n", groups);
	if (!list_of(w, in, "interfaces", ifname_ok, true, b, "  - interface: ",
	    "\n", name, "interfaces", errp))
		goto bad;
	fprintf(b, "\n");
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "interfaces"),
	    &it, true)) != NULL)
		add_if(ifs, ucl_object_tostring(e));
	fprintf(b, "rule-files:\n  - @RULES@\n");
	if (ucl_object_toboolean(ucl_object_lookup(in, "ruleset")))
		fprintf(b, "  - @RULESET@\n");
	fprintf(b, "classification-file: "
	    "/usr/local/etc/suricata/classification.config\n"
	    "reference-config-file: /usr/local/etc/suricata/reference.config\n"
	    "run-as:\n  user: root\n");
	if (ucl_object_toboolean(ucl_object_lookup(in, "oneside")))
		fprintf(b, "stream:\n  midstream: true\n  async-oneside: true\n"
		    "  drop-invalid: no\n");
	return (closed(w, b, &buf, errp));
bad:
	fclose(b);
	free(buf);
	return (NULL);
}
