/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An edge's SD-WAN and its Security section through the fleet mount
 * (PLAN-SDN-YANG 4.8.1).  The state: arcana-sdwan's sdwan (its state,
 * and the Security section's forms its proxy and IDS instances keep),
 * arcana-probe's targets as its read gives them with the settings
 * running keeps, and arcana-steer's why of each choice, made the JSON
 * the pages have always drawn.  The Security section's change: its
 * forms checked as the console checked them, made the instances named
 * sec- of arcana-sdwan's lists (SD-WAN's own kept as they are), the
 * whole sdwan put into the candidate and committed confirmed, then
 * confirmed; the same as running has, the part set again by
 * sdwan/apply.
 */

#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "app.h"

#define	SEC_PREFIX	"sec-"
#define	SEC_INSTANCES	16
#define	SEC_LIST_MAX	4096	/* addresses, prefixes or names a list */

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_replace_key(o, v, key, 0, true);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		put(o, key, ucl_object_fromstring(v));
}

/* A member of src as to in dst, where src has it. */
static void
cp(ucl_object_t *dst, const char *to, const ucl_object_t *src,
    const char *from)
{
	const ucl_object_t	*v;

	if ((v = jget(src, from)) != NULL && ucl_object_type(v) != UCL_NULL)
		put(dst, to, ucl_object_copy(v));
}

/* A number of src's, where src has it. */
static void
cp_int(ucl_object_t *dst, const char *to, const ucl_object_t *src,
    const char *from)
{

	if (jget(src, from) != NULL)
		put(dst, to, ucl_object_fromint(jint(src, from, 0)));
}

/* A flag of src's, where src has it. */
static void
cp_yes(ucl_object_t *dst, const char *to, const ucl_object_t *src,
    const char *from)
{

	if (jget(src, from) != NULL)
		put(dst, to, ucl_object_frombool(jbool(src, from)));
}

/* A date-and-time as seconds since the epoch, where src has it. */
static void
cp_time(ucl_object_t *dst, const char *to, const ucl_object_t *src,
    const char *from)
{

	if (jstr(src, from) != NULL)
		put(dst, to, ucl_object_fromint(rc_time(jstr(src, from))));
}

/* A leaf-list's strings, an empty array where there are none. */
static ucl_object_t *
strs(const ucl_object_t *v)
{

	return (v != NULL && ucl_object_type(v) == UCL_ARRAY ?
	    ucl_object_copy(v) : ucl_object_typed_new(UCL_ARRAY));
}

/* A leaf-list of 64-bit integers (RFC 7951's strings) as numbers. */
static ucl_object_t *
ints(const ucl_object_t *v)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*arr;

	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		ucl_array_append(arr, ucl_object_fromint(ucl_object_type(e) ==
		    UCL_STRING ? strtoll(ucl_object_tostring(e), NULL, 10) :
		    ucl_object_toint(e)));
	return (arr);
}

/* Whether the len bytes at p have w in them. */
static bool
has(const char *p, size_t len, const char *w)
{
	size_t	n = strlen(w);

	for (size_t i = 0; i + n <= len; i++)
		if (memcmp(p + i, w, n) == 0)
			return (true);
	return (false);
}

static bool
is_sec(const char *name)
{

	return (name != NULL && strncmp(name, SEC_PREFIX, strlen(SEC_PREFIX))
	    == 0);
}

/* A far end's state as the pages say it. */
static const char *
far(const char *s)
{

	if (s == NULL)
		return ("unknown");
	return (strcmp(s, "not-probed") == 0 ? "not probed" : s);
}

/* ---- the state's JSON ------------------------------------------------ */

static ucl_object_t *
candidates(const ucl_object_t *list, bool bfd)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*arr, *c;

	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((v = ucl_object_iterate(list, &it, true)) != NULL) {
		c = ucl_object_typed_new(UCL_OBJECT);
		cp(c, "id", v, "id");
		put_str(c, "via", jstr(v, "via") != NULL ? jstr(v, "via") : "");
		put_str(c, "state", far(jstr(v, "state")));
		if (bfd && jstr(v, "bfd") != NULL)
			put_str(c, "bfd", far(jstr(v, "bfd")));
		ucl_array_append(arr, c);
	}
	return (arr);
}

/* An edge's rules and steering, its node of edge-state e, into o. */
static void
edge_json(ucl_object_t *o, const ucl_object_t *e)
{
	const ucl_object_t	*r, *v;
	ucl_object_iter_t	 it;
	ucl_object_t		*ro, *arr, *c;

	r = jget(e, "rules");
	ro = ucl_object_typed_new(UCL_OBJECT);
	put(ro, "set", ucl_object_fromint(jint(r, "set", 0)));
	put(ro, "rules", ucl_object_fromint(jint(r, "rules", 0)));
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(r, "table"), &it, true)) != NULL)
		if (jstr(v, "name") != NULL)
			ucl_array_append(arr, ucl_object_fromstring(jstr(v,
			    "name")));
	put(ro, "tables", arr);
	put(ro, "objects", ucl_object_fromint(jint(r, "objects", 0)));
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(r, "counter"), &it, true)) !=
	    NULL) {
		c = ucl_object_typed_new(UCL_OBJECT);
		put(c, "rule", ucl_object_fromint(jint(v, "rule", 0)));
		put(c, "pkts", ucl_object_fromint(jint(v, "packets", 0)));
		put(c, "bytes", ucl_object_fromint(jint(v, "octets", 0)));
		cp(c, "text", v, "text");
		ucl_array_append(arr, c);
	}
	put(ro, "counters", arr);
	put(o, "rules", ro);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(e, "steer"), &it, true)) != NULL) {
		c = ucl_object_typed_new(UCL_OBJECT);
		cp(c, "table", v, "table");
		cp(c, "prefix", v, "prefix");
		put(c, "chosen", ucl_object_fromint(jint(v, "chosen", 0)));
		put(c, "candidates", candidates(jget(v, "candidate"), true));
		ucl_array_append(arr, c);
	}
	put(o, "steer", arr);
	put(o, "steered", ucl_object_frombool(jbool(e, "steered")));
	if (ucl_array_size(jget(e, "route")) == 0)
		return;
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(e, "route"), &it, true)) != NULL) {
		c = ucl_object_typed_new(UCL_OBJECT);
		put(c, "fib", ucl_object_fromint(jint(v, "fib", 0)));
		cp(c, "destination", v, "destination");
		put(c, "chosen", ucl_object_fromint(jint(v, "chosen", 0)));
		put(c, "candidates", candidates(jget(v, "candidate"), false));
		ucl_array_append(arr, c);
	}
	put(o, "routes", arr);
}

static void
file_json(ucl_object_t *o, const ucl_object_t *f)
{

	cp(o, "path", f, "path");
	cp_int(o, "size", f, "size");
	cp_time(o, "at", f, "at");
}

static ucl_object_t *
ids_json(const ucl_object_t *d)
{
	const ucl_object_t	*v, *s;
	ucl_object_iter_t	 it;
	ucl_object_t		*o, *arr, *a, *st, *f;
	const char		*c;

	o = ucl_object_typed_new(UCL_OBJECT);
	cp(o, "name", d, "name");
	put(o, "interfaces", strs(jget(d, "interface")));
	put_str(o, "mode", jstr(d, "mode") != NULL && strcmp(jstr(d, "mode"),
	    "prevent") == 0 ? "prevent" : "detect");
	cp_int(o, "divert", d, "divert");
	put(o, "running", ucl_object_frombool(jbool(d, "running")));
	if (jbool(d, "stopped"))
		put(o, "stopped", ucl_object_frombool(true));
	put(o, "alerts_seen", ucl_object_fromint(jint(d, "alerts-seen", 0)));
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(d, "alert"), &it, true)) != NULL) {
		a = ucl_object_typed_new(UCL_OBJECT);
		cp(a, "name", d, "name");
#define	TEXT(k, from)	put_str(a, (k), jstr(v, (from)) != NULL ?	\
			    jstr(v, (from)) : "")
		TEXT("time", "time");
		TEXT("src", "source");
		put(a, "sport", ucl_object_fromint(jint(v, "source-port", 0)));
		TEXT("dst", "destination");
		put(a, "dport", ucl_object_fromint(jint(v, "destination-port",
		    0)));
		TEXT("proto", "proto");
		TEXT("iface", "interface");
		put(a, "sid", ucl_object_fromint(jint(v, "signature-id", 0)));
		put(a, "rev", ucl_object_fromint(jint(v, "rev", 0)));
		TEXT("signature", "name");
		TEXT("category", "category");
		put(a, "severity", ucl_object_fromint(jint(v, "severity", 0)));
		TEXT("action", "action");
#undef	TEXT
		ucl_array_append(arr, a);
	}
	put(o, "alerts", arr);
	if ((s = jget(d, "stats")) != NULL) {
		st = ucl_object_typed_new(UCL_OBJECT);
		put(st, "fields", strs(jget(s, "field")));
		arr = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((v = ucl_object_iterate(jget(s, "series"), &it, true)) !=
		    NULL)
			ucl_array_append(arr, ints(jget(v, "value")));
		put(st, "series", arr);
		if (jstr(s, "flows") != NULL && (f = json_parse(jstr(s,
		    "flows"))) != NULL)
			put(st, "flows", f);
		put(o, "stats", st);
	}
	c = jstr(d, "capture");
	put_str(o, "capture", c != NULL && (strcmp(c, "netmap") == 0 ||
	    strcmp(c, "divert") == 0) ? c : "pcap");
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(d, "pcap"), &it, true)) != NULL) {
		a = ucl_object_typed_new(UCL_OBJECT);
		file_json(a, v);
		cp_int(a, "from", v, "from");
		ucl_array_append(arr, a);
	}
	put(o, "pcaps", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(d, "replay-capture"), &it,
	    true)) != NULL) {
		a = ucl_object_typed_new(UCL_OBJECT);
		file_json(a, v);
		ucl_array_append(arr, a);
	}
	put(o, "captures", arr);
	if (jstr(d, "replay") != NULL && (f = json_parse(jstr(d, "replay"))) !=
	    NULL)
		put(o, "replay", f);
	st = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while ((v = ucl_object_iterate(jget(d, "offload"), &it, true)) != NULL)
		if (jstr(v, "interface") != NULL)
			put(st, jstr(v, "interface"), strs(jget(v,
			    "capability")));
	put(o, "offload", st);
	put_str(o, "group", is_sec(jstr(d, "name")) ? "security" : "sdwan");
	return (o);
}

/* The Security section's forms of instances list: each sec- one's
 * spec, parsed. */
static ucl_object_t *
security_specs(const ucl_object_t *list)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*arr, *s;

	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((v = ucl_object_iterate(list, &it, true)) != NULL)
		if (is_sec(jstr(v, "name")) && jstr(v, "spec") != NULL &&
		    (s = json_parse(jstr(v, "spec"))) != NULL)
			ucl_array_append(arr, s);
	return (arr);
}

static void
clamav_json(ucl_object_t *top, const ucl_object_t *c)
{
	static const char *const db[] = { "name", "name", "file", "file",
	    "built", "built", NULL };
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*o, *arr, *d;

	if (c == NULL)
		return;
	o = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((v = ucl_object_iterate(jget(c, "database"), &it, true)) !=
	    NULL) {
		d = jmap(v, db);
		cp_int(d, "version", v, "version");
		cp_int(d, "signatures", v, "signatures");
		ucl_array_append(arr, d);
	}
	put(o, "databases", arr);
	put(o, "freshclam", ucl_object_frombool(jbool(c, "freshclam")));
	put(o, "conf", ucl_object_frombool(jbool(c, "conf")));
	put(o, "mirrors", strs(jget(c, "mirror")));
	if (ucl_array_size(jget(c, "log")) > 0)
		put(o, "log", strs(jget(c, "log")));
	put(top, "clamav", o);
}

/*
 * The SD-WAN read as the pages have it: sd arcana-sdwan's sdwan (its
 * state, its instances), pr running's probes, rd the probes' read.
 */
static ucl_object_t *
read_json(const ucl_object_t *sd, const ucl_object_t *pr,
    const ucl_object_t *rd)
{
	static const char *const build[] = { "lua", "lua", "profiling",
	    "profiling", "profiling-rules", "profiling_rules",
	    "profiling-locks", "profiling_locks", "hyperscan", "hyperscan",
	    "netmap", "netmap", "ipfw", "ipfw", "plugins", "plugins", NULL };
	const ucl_object_t	*st, *v, *w;
	ucl_object_iter_t	 it, wit;
	ucl_object_t		*top, *arr, *o, *c, *ps;

	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(rd, "target"), &it, true)) != NULL)
		ucl_array_append(arr, probe_target(v, probe_conf(pr, jstr(v,
		    "jail"), jstr(v, "id"), false), false));
	put(top, "targets", arr);
	put(top, "time", ucl_object_fromint(jstr(rd, "time") != NULL ?
	    rc_time(jstr(rd, "time")) : (int64_t)(arc_now() / 1000)));
	put(top, "probing", ucl_object_frombool(jbool(rd, "probing")));
	st = jget(sd, "state");
	edge_json(top, st);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(st, "edge"), &it, true)) != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		cp(o, "jail", v, "jail");
		if (jstr(v, "error") != NULL)
			cp(o, "error", v, "error");
		else
			edge_json(o, v);
		ucl_array_append(arr, o);
	}
	put(top, "edges", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(st, "bird"), &it, true)) != NULL) {
		static const char *const proto[] = { "name", "name", "proto",
		    "proto", "state", "state", "info", "info", NULL };

		o = ucl_object_typed_new(UCL_OBJECT);
		cp(o, "name", v, "name");
		put(o, "fib", ucl_object_fromint(jint(v, "fib", 0)));
		cp(o, "jail", v, "jail");
		put(o, "running", ucl_object_frombool(jbool(v, "running")));
		put(o, "protocols", jmap_each(jget(v, "protocol"), proto));
		ps = ucl_object_typed_new(UCL_ARRAY);
		wit = NULL;
		while ((w = ucl_object_iterate(jget(v, "bfd"), &wit, true)) !=
		    NULL) {
			c = ucl_object_typed_new(UCL_OBJECT);
			cp(c, "address", w, "address");
			cp(c, "interface", w, "interface");
			put_str(c, "state", far(jstr(w, "state")));
			cp(c, "since", w, "since");
			ucl_array_append(ps, c);
		}
		put(o, "bfd", ps);
		ucl_array_append(arr, o);
	}
	put(top, "bird", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(st, "dhcp"), &it, true)) != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		cp(o, "name", v, "name");
		put(o, "fib", ucl_object_fromint(jint(v, "fib", 0)));
		put(o, "running", ucl_object_frombool(jbool(v, "running")));
		ps = ucl_object_typed_new(UCL_ARRAY);
		wit = NULL;
		while ((w = ucl_object_iterate(jget(v, "lease"), &wit, true)) !=
		    NULL) {
			c = ucl_object_typed_new(UCL_OBJECT);
			cp_time(c, "expires", w, "expires");
			cp(c, "id", w, "id");
			cp(c, "address", w, "address");
			cp(c, "name", w, "hostname");
			ucl_array_append(ps, c);
		}
		put(o, "leases", ps);
		ucl_array_append(arr, o);
	}
	put(top, "dhcp", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(st, "dns"), &it, true)) != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		cp(o, "name", v, "name");
		put(o, "fib", ucl_object_fromint(jint(v, "fib", 0)));
		put(o, "running", ucl_object_frombool(jbool(v, "running")));
		cp(o, "tls_cert", v, "tls-cert");
		ucl_array_append(arr, o);
	}
	put(top, "dns", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(st, "proxy"), &it, true)) !=
	    NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		cp(o, "name", v, "name");
		put(o, "fib", ucl_object_fromint(jint(v, "fib", 0)));
		cp(o, "mode", v, "mode");
		put(o, "running", ucl_object_frombool(jbool(v, "running")));
		cp_yes(o, "icap", v, "icap");
		cp(o, "ca", v, "ca");
		put_str(o, "group", is_sec(jstr(v, "name")) ? "security" :
		    "sdwan");
		ucl_array_append(arr, o);
	}
	put(top, "proxy", arr);
	/* The Security section's forms, from the configuration. */
	put(top, "security_proxy", security_specs(jget(sd,
	    "proxy-instance")));
	clamav_json(top, jget(st, "clamav"));
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(st, "ids"), &it, true)) != NULL)
		ucl_array_append(arr, ids_json(v));
	put(top, "ids", arr);
	if ((v = jget(st, "ids-build")) != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		cp(o, "version", v, "version");
		for (size_t i = 0; build[i] != NULL; i += 2)
			cp_yes(o, build[i + 1], v, build[i]);
		put(top, "ids_build", o);
	}
	if ((v = jget(st, "ids-host")) != NULL) {
		static const char *const irq[] = { "irq", "irq", "name", "name",
		    "cpus", "cpus", NULL };

		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "ncpu", ucl_object_fromint(jint(v, "ncpu", 0)));
		put(o, "ndomains", ucl_object_fromint(jint(v, "ndomains", 0)));
		put(o, "irqs", jmap_each(jget(v, "irq"), irq));
		put(top, "ids_host", o);
	}
	if ((v = jget(st, "ids-ruleset")) != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		file_json(o, v);
		put(top, "ids_ruleset", o);
	}
	put(top, "security_ids", security_specs(jget(sd, "ids-instance")));
	o = ucl_object_typed_new(UCL_OBJECT);
	if ((v = jget(st, "record")) != NULL) {
		put(o, "count", ucl_object_fromint(jint(v, "count", 0)));
		put(o, "seq", ucl_object_fromint(jint(v, "sequence", 0)));
		put(o, "untold", ucl_object_fromint(jint(v, "untold", 0)));
		arr = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((w = ucl_object_iterate(jget(v, "last"), &it, true)) !=
		    NULL) {
			c = ucl_object_typed_new(UCL_OBJECT);
			cp_time(c, "t", w, "time");
			put(c, "seq", ucl_object_fromint(jint(w, "sequence", 0)));
			put(c, "rule", ucl_object_fromint(jint(w, "rule", 0)));
			cp(c, "action", w, "action");
			cp(c, "src", w, "source");
			cp(c, "dst", w, "destination");
			cp(c, "iface", w, "interface");
			cp(c, "comment", w, "comment");
			ucl_array_append(arr, c);
		}
		put(o, "last", arr);
	}
	put(top, "record", o);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(st, "key"), &it, true)) != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		cp(o, "interface", v, "interface");
		cp(o, "public", v, "public");
		cp(o, "next", v, "next");
		cp_time(o, "keyed_at", v, "keyed-at");
		cp_int(o, "lifetime", v, "lifetime");
		cp_int(o, "spi_in", v, "spi-in");
		cp_int(o, "spi_out", v, "spi-out");
		cp_yes(o, "pending", v, "pending");
		ucl_array_append(arr, o);
	}
	put(top, "keys", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(jget(st, "fault"), &it, true)) !=
	    NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		cp_time(o, "t", v, "time");
		cp(o, "type", v, "type");
		cp(o, "severity", v, "severity");
		cp(o, "was", v, "was");
		cp(o, "object", v, "object");
		cp(o, "by", v, "by");
		cp(o, "description", v, "description");
		put(o, "cleared", ucl_object_frombool(jbool(v, "cleared")));
		cp_time(o, "cleared_at", v, "cleared-at");
		if (jbool(v, "compressed"))
			put(o, "compressed", ucl_object_frombool(true));
		ucl_array_append(arr, o);
	}
	put(top, "faults", arr);
	return (top);
}

/* The read's entries of key (steer, routes) of an edge: the host's in
 * top, a jail's in its entry of edges; NULL none. */
static ucl_object_t *
steer_entries(ucl_object_t *top, const char *jail, const char *key)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;

	if (jail == NULL || jail[0] == '\0')
		return ((ucl_object_t *)(uintptr_t)jget(top, key));
	while ((e = ucl_object_iterate(jget(top, "edges"), &it, true)) != NULL)
		if (jstr(e, "jail") != NULL && strcmp(jstr(e, "jail"), jail) ==
		    0)
			return ((ucl_object_t *)(uintptr_t)jget(e, key));
	return (NULL);
}

/* The why of a choice, arcana-steer's entry s, into its entry e. */
static void
steer_put(ucl_object_t *e, const ucl_object_t *s)
{

	cp(e, "reason", s, "reason");
	cp(e, "from", s, "from");
	cp_time(e, "since", s, "since");
	cp_int(e, "changes", s, "changes");
}

/* arcana-steer's state into the read's steer entries and routes. */
static void
steer_why(ucl_object_t *top, const ucl_object_t *st)
{
	const ucl_object_t	*p;
	ucl_object_iter_t	 it, eit;
	ucl_object_t		*arr, *e;

	it = NULL;
	while ((p = ucl_object_iterate(jget(st, "policy"), &it, true)) !=
	    NULL) {
		arr = steer_entries(top, jstr(p, "jail"), "steer");
		eit = NULL;
		while (arr != NULL && (e = (ucl_object_t *)(uintptr_t)
		    ucl_object_iterate(arr, &eit, true)) != NULL) {
			if (jstr(e, "table") == NULL || jstr(e, "prefix") ==
			    NULL || jstr(p, "table") == NULL || jstr(p, "prefix")
			    == NULL || strcmp(jstr(e, "table"), jstr(p,
			    "table")) != 0 || strcmp(jstr(e, "prefix"), jstr(p,
			    "prefix")) != 0)
				continue;
			steer_put(e, p);
			cp(e, "pinned", p, "pinned");
			break;
		}
	}
	it = NULL;
	while ((p = ucl_object_iterate(jget(st, "route"), &it, true)) !=
	    NULL) {
		arr = steer_entries(top, jstr(p, "jail"), "routes");
		eit = NULL;
		while (arr != NULL && (e = (ucl_object_t *)(uintptr_t)
		    ucl_object_iterate(arr, &eit, true)) != NULL) {
			if (jstr(e, "destination") == NULL || jstr(p,
			    "destination") == NULL || strcmp(jstr(e,
			    "destination"), jstr(p, "destination")) != 0 ||
			    jint(e, "fib", 0) != jint(p, "fib", 0))
				continue;
			steer_put(e, p);
			break;
		}
	}
}

/* ---- the read: four of the host's, one after another --------------- */

struct sdr {
	api_cb		*cb;
	void		*arg;
	char		 sid[9];
	long long	 after;
	ucl_object_t	*probes;	/* running's */
	ucl_object_t	*read;		/* the probes' read */
	ucl_object_t	*sdwan;
};

static void
sdr_free(struct sdr *r)
{

	if (r->probes != NULL)
		ucl_object_unref(r->probes);
	if (r->read != NULL)
		ucl_object_unref(r->read);
	if (r->sdwan != NULL)
		ucl_object_unref(r->sdwan);
	free(r);
}

static void
sdr_fail(struct sdr *r, int status, const ucl_object_t *o, const char *err)
{

	r->cb(status != 200 ? status : 500, o, err, r->arg);
	sdr_free(r);
}

/* arcana-steer's (an agent without the module read as before). */
static void
sdr_steer_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct sdr	*r = arg;
	ucl_object_t	*top, *d;

	(void)err;
	d = read_json(r->sdwan, r->probes, r->read);
	if (status == 200 && o != NULL)
		steer_why(d, jget(o, "state"));
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "ok", ucl_object_frombool(true));
	put(top, "data", d);
	r->cb(200, top, NULL, r->arg);
	ucl_object_unref(top);
	sdr_free(r);
}

static void
sdr_sdwan_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct sdr	*r = arg;
	char		 url[300];

	/* None kept, nothing known: an edge of nothing yet. */
	if (status != 200 && status != 404) {
		sdr_fail(r, status, o, err);
		return;
	}
	r->sdwan = status == 200 && o != NULL ? ucl_object_copy(o) :
	    ucl_object_typed_new(UCL_OBJECT);
	rc_get(rc_h(url, sizeof(url), r->sid, "arcana-steer:steering"), NULL,
	    sdr_steer_cb, r);
}

static void
sdr_read_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct sdr	*r = arg;
	char		 url[300];

	if (status != 200) {
		sdr_fail(r, status, o, err);
		return;
	}
	r->read = o != NULL ? ucl_object_copy(o) :
	    ucl_object_typed_new(UCL_OBJECT);
	rc_get(rc_h(url, sizeof(url), r->sid, "arcana-sdwan:sdwan"), NULL,
	    sdr_sdwan_cb, r);
}

static void
sdr_probes_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct sdr	*r = arg;
	struct server	*s;
	struct tm	 tm;
	time_t		 t;
	char		 in[80], when[32];

	(void)err;
	for (int i = 0, n = app.nservers; i < n; i++)
		if (strcmp(app.servers[i].id, r->sid) == 0) {
			s = &app.servers[i];
			goto found;
		}
	sdr_fail(r, 404, NULL, "no such host");
	return;
found:
	/* None kept (404): the prober's own settings. */
	r->probes = status == 200 && o != NULL ? ucl_object_copy(o) :
	    ucl_object_typed_new(UCL_OBJECT);
	/* The targets as they are, the samples after the time alone. */
	snprintf(in, sizeof(in), "{}");
	t = (time_t)r->after;
	if (r->after > 0 && gmtime_r(&t, &tm) != NULL && strftime(when,
	    sizeof(when), "%Y-%m-%dT%H:%M:%SZ", &tm) > 0)
		snprintf(in, sizeof(in), "{\"after\":\"%s\"}", when);
	host_yread(s, "arcana-probe:probes/read", in, NULL, false,
	    sdr_read_cb, r);
}

/*
 * Host sid's SD-WAN, the samples after after (seconds since the epoch;
 * 0 all), as the SD-WAN and Security pages draw it; the callback gets
 * {"ok": true, "data": ...}, or the read's failure.
 */
void
sdwan_yread(const char *sid, long long after, api_cb *cb, void *arg)
{
	struct sdr	*r;
	char		 url[300];

	if ((r = calloc(1, sizeof(*r))) == NULL)
		abort();
	r->cb = cb;
	r->arg = arg;
	r->after = after;
	snprintf(r->sid, sizeof(r->sid), "%s", sid);
	rc_get(rc_ds(url, sizeof(url), "running", sid, "arcana-probe:probes"),
	    NULL, sdr_probes_cb, r);
}

/* ---- the Security section's change --------------------------------- */

/* sec- and letters, digits, _ and -: 32 at most, as the agent takes. */
static bool
name_ok(const char *s)
{

	if (s == NULL || strncmp(s, SEC_PREFIX, 4) != 0 || strlen(s) < 5 ||
	    strlen(s) > 32)
		return (false);
	for (size_t i = 4; s[i] != '\0'; i++)
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

/* A domain: labels of letters, digits and -, a dot between them; one
 * leading dot let be. */
static bool
domain_ok(const char *s)
{

	if (s != NULL && s[0] == '.')
		s++;
	if (s == NULL || s[0] == '\0' || strlen(s) > 253 || s[0] == '.' ||
	    s[0] == '-' || s[strlen(s) - 1] == '.' || s[strlen(s) - 1] ==
	    '-' || strstr(s, "..") != NULL)
		return (false);
	for (size_t i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '-' && s[i] != '.')
			return (false);
	return (true);
}

/* Each string of the list at k checked by ok; false, and why. */
static bool
list_ok(const ucl_object_t *in, const char *k, bool (*ok)(const char *),
    bool need, const char *name, const char *what, char *err, size_t errlen)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	int			 n = 0;

	if (jget(in, k) != NULL && ucl_object_type(jget(in, k)) != UCL_ARRAY) {
		snprintf(err, errlen, "%s: %s: a list", name, what);
		return (false);
	}
	while ((e = ucl_object_iterate(jget(in, k), &it, true)) != NULL) {
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
num_ok(const ucl_object_t *in, const char *k, int64_t lo, int64_t hi,
    int64_t def, int64_t *v)
{
	const ucl_object_t	*o;

	if ((o = jget(in, k)) == NULL || ucl_object_type(o) == UCL_NULL) {
		*v = def;
		return (true);
	}
	if (ucl_object_type(o) != UCL_INT)
		return (false);
	*v = ucl_object_toint(o);
	return (*v >= lo && *v <= hi);
}

/* The form's own JSON text: what the agent renders the daemon's of. */
static void
put_spec(ucl_object_t *m, const ucl_object_t *in)
{
	char	*t;

	if ((t = (char *)ucl_object_emit(in, UCL_EMIT_JSON_COMPACT)) != NULL) {
		put_str(m, "spec", t);
		free(t);
	}
}

/*
 * The URL filter of a form as arcana-sdwan's proxy-instance has it:
 * its name, table, mode and host, stopped when the admin stopped it,
 * the form as its spec.
 */
static ucl_object_t *
proxy_one(const ucl_object_t *in, const char *host, char *err,
    size_t errlen)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*o;
	const char		*name, *mode;
	int64_t			 fib, port;

	name = jstr(in, "name");
	mode = jstr(in, "mode") != NULL ? jstr(in, "mode") : "sni";
	if (!name_ok(name)) {
		snprintf(err, errlen, "a name is sec- and letters, digits, _ "
		    "and -, 32 at most");
		return (NULL);
	}
	if (strcmp(mode, "sni") != 0 && strcmp(mode, "inspect") != 0) {
		snprintf(err, errlen, "%s: mode is sni or inspect", name);
		return (NULL);
	}
	if (!num_ok(in, "fib", 0, 65535, 0, &fib) || !num_ok(in, "port", 1,
	    65535, 3128, &port)) {
		snprintf(err, errlen, "%s: fib is a routing table, port 1 to "
		    "65535", name);
		return (NULL);
	}
	if (ucl_object_type(jget(in, "listen")) != UCL_ARRAY) {
		snprintf(err, errlen, "%s: listen: a list of addresses", name);
		return (NULL);
	}
	while ((e = ucl_object_iterate(jget(in, "listen"), &it, true)) != NULL)
		if (ucl_object_type(e) != UCL_STRING || !addr_ok(
		    ucl_object_tostring(e))) {
			snprintf(err, errlen, "%s: listen: %.64s is not an "
			    "address", name, ucl_object_tostring_forced(e));
			return (NULL);
		}
	if (ucl_array_size(jget(in, "listen")) == 0) {
		snprintf(err, errlen, "%s: listen: at least one address", name);
		return (NULL);
	}
	if (!list_ok(in, "allow", prefix_ok, true, name, "allow (the networks "
	    "that may use it)", err, errlen) || !list_ok(in, "deny", domain_ok,
	    false, name, "deny", err, errlen))
		return (NULL);
	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", name);
	put(o, "fib", ucl_object_fromint(fib));
	put_str(o, "mode", mode);
	put_str(o, "host", host);
	if (jbool(in, "stopped"))
		put(o, "stopped", ucl_object_frombool(true));
	put_spec(o, in);
	return (o);
}

/* Suricata's threshold.config lines: suppress, threshold, event_filter
 * or rate_filter with its gen_id and sig_id; # a comment. */
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
		if (i == nitems(kinds) || !has(p, len, "gen_id ") ||
		    !has(p, len, "sig_id ") || strspn(p,
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
	ucl_object_iter_t	 it = NULL;

	while ((e = ucl_object_iterate(ifs, &it, true)) != NULL)
		if (strcmp(ucl_object_tostring(e), name) == 0)
			return;
	ucl_array_append(ifs, ucl_object_fromstring(name));
}

/*
 * The intrusion detection of a form as arcana-sdwan's ids-instance has
 * it: what it watches (its interfaces, both of each netmap pair), how
 * it prevents, its rules and thresholds, its Lua scripts and plugins,
 * the form as its spec.
 */
static ucl_object_t *
ids_one(const ucl_object_t *in, const char *host, char *err, size_t errlen)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*o, *ifs, *lua;
	const char		*name, *rules, *s, *colon;
	char			 a[24];
	int64_t			 divert;

	name = jstr(in, "name");
	if (!name_ok(name)) {
		snprintf(err, errlen, "a name is sec- and letters, digits, _ "
		    "and -, 32 at most");
		return (NULL);
	}
	if (!num_ok(in, "divert", 0, 65535, 0, &divert)) {
		snprintf(err, errlen, "%s: divert is a port, 1 to 65535, or none "
		    "to detect only", name);
		return (NULL);
	}
	rules = jstr(in, "rules");
	if (!thresholds_ok(jstr(in, "thresholds"), name, err, errlen))
		return (NULL);
	if ((rules == NULL || rules[strspn(rules, " \t\r\n")] == '\0') &&
	    !jbool(in, "ruleset")) {
		snprintf(err, errlen, "%s: rules of its own, or the ruleset "
		    "suricata-update keeps, or both", name);
		return (NULL);
	}
	while ((e = ucl_object_iterate(jget(in, "lua"), &it, true)) != NULL)
		if (!lua_name_ok(ucl_object_key(e)) || ucl_object_type(e) !=
		    UCL_STRING) {
			snprintf(err, errlen, "%s: a Lua script is NAME.lua, of "
			    "letters, digits, _ and -, its text", name);
			return (NULL);
		}
	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", name);
	ifs = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((e = ucl_object_iterate(jget(in, "interfaces"), &it, true)) !=
	    NULL)
		if (ucl_object_type(e) == UCL_STRING)
			add_if(ifs, ucl_object_tostring(e));
	it = NULL;
	while ((e = ucl_object_iterate(jget(in, "pairs"), &it, true)) != NULL)
		if (ucl_object_type(e) == UCL_STRING && (colon = strchr((s =
		    ucl_object_tostring(e)), ':')) != NULL) {
			snprintf(a, sizeof(a), "%.*s", (int)(colon - s), s);
			add_if(ifs, a);
			add_if(ifs, colon + 1);
		}
	if (ucl_array_size(ifs) > 0)
		put(o, "interface", ifs);
	else
		ucl_object_unref(ifs);
	if (rules != NULL)
		put_str(o, "rules", rules);
	if (divert > 0)
		put(o, "divert", ucl_object_fromint(divert));
	put_str(o, "host", host);
	put_spec(o, in);
	if (jstr(in, "capture") != NULL && strcmp(jstr(in, "capture"),
	    "netmap") == 0)
		put_str(o, "capture", "netmap");
	/* Its interfaces' offloading turned off as it starts. */
	if (jbool(in, "offload_off"))
		put(o, "offload", ucl_object_frombool(false));
	if (ucl_object_type(jget(in, "lua")) == UCL_OBJECT &&
	    jget(in, "lua")->len > 0) {
		lua = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((e = ucl_object_iterate(jget(in, "lua"), &it, true)) !=
		    NULL) {
			ucl_object_t *l = ucl_object_typed_new(UCL_OBJECT);

			put_str(l, "name", ucl_object_key(e));
			put_str(l, "text", ucl_object_tostring(e));
			ucl_array_append(lua, l);
		}
		put(o, "lua", lua);
	}
	if (ucl_array_size(jget(in, "plugins")) > 0)
		put(o, "plugin", ucl_object_copy(jget(in, "plugins")));
	if (jbool(in, "stopped"))
		put(o, "stopped", ucl_object_frombool(true));
	if (jstr(in, "thresholds") != NULL)
		put_str(o, "thresholds", jstr(in, "thresholds"));
	return (o);
}

struct secsave {
	api_cb	*cb;
	void	*arg;
	char	 sid[9];
	bool	 ids;
	char	 token[33];
	ucl_object_t *list;	/* the instances made of the forms */
};

static void
secsave_free(struct secsave *c)
{

	if (c->list != NULL)
		ucl_object_unref(c->list);
	free(c);
}

/* The callback told as /api's security POST told it. */
static void
secsave_done(struct secsave *c, int status, const ucl_object_t *o,
    const char *err)
{
	ucl_object_t	*r;

	if (status == 200 || status == 204) {
		r = ucl_object_typed_new(UCL_OBJECT);
		put(r, "ok", ucl_object_frombool(true));
		c->cb(200, r, NULL, c->arg);
		ucl_object_unref(r);
	} else
		c->cb(status != 200 ? status : 500, o, err, c->arg);
	secsave_free(c);
}

static void
secsave_ignore(int status, const ucl_object_t *o, const char *err,
    void *arg)
{

	(void)status;
	(void)o;
	(void)err;
	(void)arg;
}

static void
secsave_confirm_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{

	secsave_done(arg, status, o, err);
}

static void
secsave_commit_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{
	struct secsave	*c = arg;
	char		 url[300], body[120];

	if (status != 200 && status != 204) {
		api("POST", rc_h(url, sizeof(url), c->sid, "ietf-netconf:"
		    "discard-changes"), "{\"ietf-netconf:input\":{}}",
		    secsave_ignore, NULL);
		secsave_done(c, status, o, err);
		return;
	}
	snprintf(body, sizeof(body), "{\"ietf-netconf:input\":{\"persist-id\":"
	    "\"%s\"}}", c->token);
	api("POST", rc_h(url, sizeof(url), c->sid, "ietf-netconf:commit"), body,
	    secsave_confirm_cb, c);
}

static void
secsave_edit_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{
	struct secsave	*c = arg;
	uint8_t		 r[16];
	char		 url[300], body[200];

	if (status != 200 && status != 204 && status != 201) {
		secsave_done(c, status, o, err);
		return;
	}
	if (getentropy(r, sizeof(r)) != 0) {
		secsave_done(c, 500, NULL, "no randomness for the commit's "
		    "token");
		return;
	}
	for (size_t i = 0; i < sizeof(r); i++)
		snprintf(c->token + 2 * i, sizeof(c->token) - 2 * i, "%02x",
		    r[i]);
	snprintf(body, sizeof(body), "{\"ietf-netconf:input\":{\"confirmed\":"
	    "[null],\"confirm-timeout\":%d,\"persist\":\"%s\"}}", YC_TIMEOUT,
	    c->token);
	api("POST", rc_h(url, sizeof(url), c->sid, "ietf-netconf:commit"), body,
	    secsave_commit_cb, c);
}

/*
 * Running's sdwan: its instances of the kind, SD-WAN's kept first and
 * the Security section's made of the forms; the whole put into the
 * candidate, or, the same as running has, the part set again.
 */
static void
secsave_running_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{
	struct secsave		*c = arg;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*sd, *was, *arr, *top;
	const char		*key = c->ids ? "ids-instance" :
	    "proxy-instance";
	char			 url[300], in[80], *json;

	if (status != 200 && status != 404) {
		secsave_done(c, status, o, err);
		return;
	}
	sd = status == 200 && o != NULL ? ucl_object_copy(o) :
	    ucl_object_typed_new(UCL_OBJECT);
	was = ucl_object_copy(sd);
	arr = ucl_object_typed_new(UCL_ARRAY);
	while ((v = ucl_object_iterate(jget(was, key), &it, true)) != NULL)
		if (!is_sec(jstr(v, "name")))
			ucl_array_append(arr, ucl_object_copy(v));
	it = NULL;
	while ((v = ucl_object_iterate(c->list, &it, true)) != NULL)
		ucl_array_append(arr, ucl_object_copy(v));
	if (ucl_array_size(arr) > 0)
		put(sd, key, arr);
	else {
		ucl_object_delete_key(sd, key);
		ucl_object_unref(arr);
	}
	if (ucl_object_compare(was, sd) == 0) {
		ucl_object_unref(was);
		ucl_object_unref(sd);
		snprintf(in, sizeof(in), "{\"part\":\"%s\",\"security\":true}",
		    c->ids ? "ids" : "proxy");
		rc_action(rc_h(url, sizeof(url), c->sid,
		    "arcana-sdwan:sdwan/apply"), in, NULL, secsave_confirm_cb,
		    c);
		return;
	}
	ucl_object_unref(was);
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "arcana-sdwan:sdwan", sd);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	api("PUT", rc_ds(url, sizeof(url), "candidate", c->sid,
	    "arcana-sdwan:sdwan"), json, secsave_edit_cb, c);
	free(json);
}

/*
 * The Security section's forms of a kind (ids, or the URL filters),
 * the whole list, made the host's: the callback gets {"ok": true} or
 * why not (400 for a form not right).
 */
void
security_ysave(const struct server *s, bool ids, const ucl_object_t *forms,
    api_cb *cb, void *arg)
{
	const ucl_object_t	*in, *o2;
	ucl_object_iter_t	 it = NULL, it2;
	struct secsave		*c;
	ucl_object_t		*o;
	char			 err[300], url[300];
	int			 n = 0;

	if ((c = calloc(1, sizeof(*c))) == NULL)
		abort();
	c->cb = cb;
	c->arg = arg;
	c->ids = ids;
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	c->list = ucl_object_typed_new(UCL_ARRAY);
	/* The whole list, always: [] stops them all. */
	if (forms == NULL || ucl_object_type(forms) != UCL_ARRAY) {
		secsave_done(c, 400, NULL, "instances is the whole list of "
		    "them, [] for none");
		return;
	}
	while ((in = ucl_object_iterate(forms, &it, true)) != NULL) {
		if (n++ == SEC_INSTANCES) {
			snprintf(err, sizeof(err), "%d instances at most",
			    SEC_INSTANCES);
			secsave_done(c, 400, NULL, err);
			return;
		}
		err[0] = '\0';
		if ((o = ids ? ids_one(in, s->name, err, sizeof(err)) :
		    proxy_one(in, s->name, err, sizeof(err))) == NULL) {
			secsave_done(c, 400, NULL, err);
			return;
		}
		it2 = NULL;
		while ((o2 = ucl_object_iterate(c->list, &it2, true)) != NULL)
			if (strcmp(jstr(o2, "name"), jstr(o, "name")) == 0) {
				snprintf(err, sizeof(err), "%s is named twice",
				    jstr(o, "name"));
				ucl_object_unref(o);
				secsave_done(c, 400, NULL, err);
				return;
			}
		ucl_array_append(c->list, o);
	}
	rc_get(rc_ds(url, sizeof(url), "running", s->id, "arcana-sdwan:sdwan"),
	    NULL, secsave_running_cb, c);
}
