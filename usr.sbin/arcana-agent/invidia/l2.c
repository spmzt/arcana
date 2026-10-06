/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Bridges, if_bridge(4), and geneve(4) tunnels: what they are, read
 * from what ifconfig(8) says of them, which is the same on a host and
 * in a jail with a network of its own; and changed with ifconfig, every
 * word checked.
 *
 * A bridge's member is in a VLAN untagged (an access port), carries
 * VLANs tagged (a trunk), or both; its place in the spanning tree, the
 * role and the state bridgestp(4) gave it, is read with it.  A member
 * of a bridge takes no address here: its addresses belong on the
 * bridge.  One that has some is shown with them.
 */

#include <sys/param.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

#include "agent.h"

#define	L2_WORDS	96

static void
put(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0,
		    false);
}

static void
putn(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromint(strtoll(v, NULL,
		    10)), key, 0, false);
}

static void
putb(ucl_object_t *o, const char *key, bool v)
{

	ucl_object_insert_key(o, ucl_object_frombool(v), key, 0, false);
}

/* The words of a line, in place; how many. */
static int
words(char *line, char **v, int max)
{
	char	*p, *t;
	int	 n;

	n = 0;
	p = line;
	while (n < max && (t = strsep(&p, " \t")) != NULL)
		if (*t != '\0')
			v[n++] = t;
	return (n);
}

/* "flags=143<LEARNING,DISCOVER>" as ["learning","discover"]. */
static ucl_object_t *
flags_of(struct work *w, const char *word)
{
	ucl_object_t	*a;
	char		*s, *p, *t, *c;

	a = ucl_object_typed_new(UCL_ARRAY);
	if ((s = strchr(word, '<')) == NULL)
		return (a);
	p = wstrdup(w, s + 1);
	p[strcspn(p, ">")] = '\0';
	while ((t = strsep(&p, ",")) != NULL) {
		if (*t == '\0')
			continue;
		for (c = t; *c != '\0'; c++)
			*c = (char)tolower((unsigned char)*c);
		ucl_array_append(a, ucl_object_fromstring(t));
	}
	return (a);
}

static bool
has_flag(const ucl_object_t *flags, const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(flags, &it, true)) != NULL)
		if (strcmp(ucl_object_tostring(o), name) == 0)
			return (true);
	return (false);
}

/* The value after "key: " in text, to the next comma or line's end. */
static const char *
after(struct work *w, const char *text, const char *key)
{
	const char	*p;
	size_t		 n;

	if ((p = strstr(text, key)) == NULL)
		return (NULL);
	p += strlen(key);
	n = strcspn(p, ",\n");
	return (wstrndup(w, p, n));
}

/*
 * One interface's part of ifconfig's output as a bridge, or NULL when
 * it is none.  addrs is what addresses each interface has, by name.
 */
static ucl_object_t *
bridge_of(struct work *w, const char *name, char *block,
    const ucl_object_t *addrs)
{
	ucl_object_t	*b, *members, *m, *fl;
	char		*p, *line, *v[L2_WORDS];
	const char	*tagged, *pvid;
	int		 n, i;
	bool		 is;

	b = ucl_object_typed_new(UCL_OBJECT);
	members = ucl_object_typed_new(UCL_ARRAY);
	m = NULL;
	is = false;
	put(b, "name", name);
	p = block;
	while ((line = strsep(&p, "\n")) != NULL) {
		n = words(line, v, L2_WORDS);
		if (n == 0)
			continue;
		if (strcmp(v[0], "id") == 0 && n >= 8 && strcmp(v[2],
		    "priority") == 0) {
			is = true;
			put(b, "id", v[1]);
			putn(b, "priority", v[3]);
			putn(b, "hellotime", v[5]);
			putn(b, "fwddelay", v[7]);
			continue;
		}
		if (!is)
			continue;
		if (strcmp(v[0], "maxage") == 0) {
			for (i = 0; i + 1 < n; i += 2)
				if (strcmp(v[i], "proto") == 0)
					put(b, "proto", v[i + 1]);
				else
					putn(b, v[i], v[i + 1]);
		} else if (strcmp(v[0], "root") == 0 && n >= 9) {
			put(b, "root", v[2]);
			putn(b, "root_priority", v[4]);
			putn(b, "root_cost", v[6]);
			putn(b, "root_port", v[8]);
		} else if (strcmp(v[0], "bridge") == 0 && n >= 2 && strncmp(
		    v[1], "flags=", 6) == 0) {
			fl = flags_of(w, v[1]);
			putb(b, "vlanfilter", has_flag(fl, "vlanfilter"));
			putb(b, "defqinq", has_flag(fl, "defqinq"));
			ucl_object_unref(fl);
			for (i = 2; i < n; i++)
				if (strncmp(v[i], "defuntagged=", 12) == 0)
					putn(b, "defuntagged", v[i] + 12);
		} else if (strcmp(v[0], "member:") == 0 && n >= 2) {
			m = ucl_object_typed_new(UCL_OBJECT);
			put(m, "name", v[1]);
			fl = flags_of(w, n >= 3 ? v[2] : "");
			putb(m, "stp", has_flag(fl, "stp"));
			ucl_object_insert_key(m, fl, "flags", 0, false);
			if (ucl_object_lookup(addrs, v[1]) != NULL)
				ucl_object_insert_key(m, ucl_object_ref(
				    ucl_object_lookup(addrs, v[1])),
				    "addresses", 0, false);
			ucl_array_append(members, m);
		} else if (m != NULL && (line[0] == '\0' || isspace(
		    (unsigned char)line[0]) || v[0] > line)) {
			/* More of the member: words and their values. */
			pvid = tagged = NULL;
			for (i = 0; i < n; i++) {
				if (i + 1 >= n)
					break;
				if (strcmp(v[i], "port") == 0)
					putn(m, "port", v[++i]);
				else if (strcmp(v[i], "priority") == 0)
					putn(m, "priority", v[++i]);
				else if (strcmp(v[i], "path") == 0 && i + 2 <
				    n) {
					putn(m, "cost", v[i + 2]);
					i += 2;
				} else if (strcmp(v[i], "proto") == 0)
					put(m, "proto", v[++i]);
				else if (strcmp(v[i], "role") == 0)
					put(m, "role", v[++i]);
				else if (strcmp(v[i], "state") == 0)
					put(m, "state", v[++i]);
				else if (strcmp(v[i], "ifmaxaddr") == 0)
					putn(m, "maxaddr", v[++i]);
				else if (strcmp(v[i], "vlan") == 0 && i + 2 <
				    n) {
					put(m, "vlanproto", v[i + 2]);
					i += 2;
				} else if (strcmp(v[i], "untagged") == 0)
					pvid = v[++i];
				else if (strcmp(v[i], "tagged") == 0)
					tagged = v[++i];
			}
			if (pvid != NULL)
				putn(m, "untagged", pvid);
			if (tagged != NULL)
				put(m, "tagged", tagged);
			if (pvid != NULL || tagged != NULL)
				put(m, "mode", tagged != NULL ? "trunk" :
				    "access");
		} else
			m = NULL;
	}
	if (!is) {
		ucl_object_unref(members);
		ucl_object_unref(b);
		return (NULL);
	}
	if (ucl_object_lookup(b, "id") != NULL && ucl_object_lookup(b,
	    "root") != NULL)
		putb(b, "is_root", strcmp(ucl_object_tostring(
		    ucl_object_lookup(b, "id")), ucl_object_tostring(
		    ucl_object_lookup(b, "root"))) == 0);
	ucl_object_insert_key(b, members, "members", 0, false);
	return (b);
}

/*
 * The addresses a bridge has learned, and behind which member each
 * is: "ifconfig bridge0 addr" prints "02:00:00:00:00:01 Vlan1 em0 1193
 * flags=0<>" for each.
 */
#define	L2_LEARNED	500

static void
learned(struct work *w, ucl_object_t *b, const char *name)
{
	struct execres	 res;
	ucl_object_t	*arr, *o;
	char		*argv[4], *text, *p, *line, *v[L2_WORDS];
	int		 n, total;

	argv[0] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[1] = (char *)(uintptr_t)name;
	argv[2] = (char *)(uintptr_t)"addr";
	argv[3] = NULL;
	arr = ucl_object_typed_new(UCL_ARRAY);
	total = 0;
	if (run_exec(w, scope_argv(w, argv), &res) == 0 && res.out != NULL) {
		text = wstrndup(w, res.out, res.outlen);
		p = text;
		while ((line = strsep(&p, "\n")) != NULL) {
			n = words(line, v, L2_WORDS);
			if (n < 4 || strchr(v[0], ':') == NULL)
				continue;
			if (total++ >= L2_LEARNED)
				continue;
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "mac", v[0]);
			if (strncmp(v[1], "Vlan", 4) == 0)
				putn(o, "vlan", v[1] + 4);
			put(o, "member", v[2]);
			putn(o, "expire", v[3]);
			if (n > 4 && strstr(v[4], "STATIC") != NULL)
				putb(o, "static", true);
			if (n > 4 && strstr(v[4], "STICKY") != NULL)
				putb(o, "sticky", true);
			ucl_array_append(arr, o);
		}
	}
	ucl_object_insert_key(b, arr, "learned", 0, false);
	ucl_object_insert_key(b, ucl_object_fromint(total), "learned_total",
	    0, false);
}

/* The same for a geneve tunnel. */
static ucl_object_t *
geneve_of(struct work *w, const char *name, const char *block)
{
	ucl_object_t	*g;
	const char	*v, *p;

	if ((v = after(w, block, "geneve mode: ")) == NULL)
		return (NULL);
	g = ucl_object_typed_new(UCL_OBJECT);
	put(g, "name", name);
	put(g, "mode", v);
	if ((v = after(w, block, "identifier (vni): ")) != NULL && isdigit(
	    (unsigned char)v[0]))
		putn(g, "id", v);
	put(g, "local", after(w, block, "\t\tlocal: "));
	put(g, "remote", after(w, block, "\t\tremote: "));
	put(g, "group", after(w, block, "\t\tgroup: "));
	put(g, "dev", after(w, block, ", dev: "));
	put(g, "portrange", after(w, block, "portrange: "));
	put(g, "ttl", after(w, block, ", ttl: "));
	put(g, "df", after(w, block, ", df: "));
	putb(g, "dscpinherit", strstr(block, ", dscp: inherit") != NULL);
	putb(g, "external", strstr(block, "externally controlled") != NULL);
	if ((p = strstr(block, "ftable mode: ")) != NULL)
		putb(g, "learn", strncmp(p + 13, "learning", 8) == 0);
	if ((v = after(w, block, ", count: ")) != NULL)
		putn(g, "count", v);
	if ((v = after(w, block, ", max: ")) != NULL)
		putn(g, "maxaddr", v);
	if ((v = after(w, block, ", timeout: ")) != NULL)
		putn(g, "timeout", v);
	putb(g, "up", strstr(block, "<UP") != NULL || strstr(block, ",UP") !=
	    NULL);
	return (g);
}

/*
 * {"bridges":[...]} or {"geneves":[...]}, from one run of ifconfig -av,
 * in the jail whose network is asked for when one is.
 */
int
do_l2(struct work *w, bool geneve, struct arc_network_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *arr, *addrs, *list, *o;
	unsigned char	*json;
	char		*argv[3], *text, *p, *line, *name, *block, *q, *next;
	char		*wv[L2_WORDS], *copy;
	const char	*bname;
	int		 pass, n;

	rsp->has_ok = true;
	rsp->ok = false;
	argv[0] = (char *)(uintptr_t)opts.ifconfig_bin;
	/* -v: a geneve tunnel's ttl, df and table are said only so. */
	argv[1] = (char *)(uintptr_t)"-av";
	argv[2] = NULL;
	if (run_exec(w, scope_argv(w, argv), &res) != 0) {
		rsp->error = scope_missing(w, &res, "ifconfig", NULL);
		if (rsp->error == NULL)
			rsp->error = wtext(w, exec_error(w, &res, "ifconfig"));
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	addrs = ucl_object_typed_new(UCL_OBJECT);
	/* First who has which addresses, then the bridges and tunnels. */
	for (pass = 0; pass < 2; pass++) {
		text = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
		for (p = text; p != NULL && *p != '\0'; p = next) {
			/* An interface's part: to the next line at the edge. */
			for (q = p; (q = strchr(q, '\n')) != NULL; q++)
				if (q[1] != '\t' && q[1] != ' ' && q[1] !=
				    '\0')
					break;
			next = q != NULL ? q + 1 : NULL;
			if (q != NULL)
				*q = '\0';
			name = p;
			if ((block = strchr(p, ':')) == NULL)
				continue;
			*block++ = '\0';
			if (pass == 1) {
				bname = wstrdup(w, name);
				o = geneve ? geneve_of(w, bname, block) :
				    bridge_of(w, bname, block, addrs);
				if (o != NULL && !geneve)
					learned(w, o, bname);
				if (o != NULL)
					ucl_array_append(arr, o);
				continue;
			}
			list = NULL;
			copy = wstrdup(w, block);
			while ((line = strsep(&copy, "\n")) != NULL) {
				n = words(line, wv, L2_WORDS);
				if (n < 2 || (strcmp(wv[0], "inet") != 0 &&
				    strcmp(wv[0], "inet6") != 0))
					continue;
				/* Its own link-local address is no setting. */
				if (strncmp(wv[1], "fe80:", 5) == 0)
					continue;
				if (list == NULL)
					list = ucl_object_typed_new(UCL_ARRAY);
				ucl_array_append(list, ucl_object_fromstring(
				    wv[1]));
			}
			if (list != NULL)
				ucl_object_insert_key(addrs, list, name, 0,
				    true);
		}
	}
	ucl_object_unref(addrs);
	ucl_object_insert_key(top, arr, geneve ? "geneves" : "bridges", 0,
	    false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "out of memory";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

/* The bridge name is a member of, or NULL. */
const char *
bridge_holding(struct work *w, const char *ifname)
{
	struct arc_network_rsp	 rsp;
	struct ucl_parser	*p;
	const ucl_object_t	*b, *m;
	ucl_object_t		*o;
	ucl_object_iter_t	 it, mit;
	const char		*found;

	memset(&rsp, 0, sizeof(rsp));
	if (do_l2(w, false, &rsp) != 0 || !rsp.ok || rsp.json == NULL)
		return (NULL);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	o = ucl_parser_add_string(p, rsp.json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	found = NULL;
	it = NULL;
	while (found == NULL && (b = ucl_object_iterate(ucl_object_lookup(o,
	    "bridges"), &it, true)) != NULL) {
		mit = NULL;
		while ((m = ucl_object_iterate(ucl_object_lookup(b, "members"),
		    &mit, true)) != NULL)
			if (strcmp(ucl_object_tostring(ucl_object_lookup(m,
			    "name")), ifname) == 0)
				found = wstrdup(w, ucl_object_tostring(
				    ucl_object_lookup(b, "name")));
	}
	if (o != NULL)
		ucl_object_unref(o);
	return (found);
}

static bool
ifname_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || s[0] == '-' || strlen(s) > 15)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && strchr("._", s[i]) ==
		    NULL)
			return (false);
	return (true);
}

static bool
number_ok(const char *s, long lo, long hi)
{
	char	*end;
	long	 v;

	if (s == NULL || !isdigit((unsigned char)s[0]))
		return (false);
	v = strtol(s, &end, 10);
	return (*end == '\0' && v >= lo && v <= hi);
}

/* none, all, or numbers and ranges of them with commas between. */
static bool
vlans_ok(const char *s)
{
	char	*copy, *p, *t, *dash;

	if (s == NULL || s[0] == '\0' || strlen(s) > 400)
		return (false);
	if (strcmp(s, "none") == 0 || strcmp(s, "all") == 0)
		return (true);
	if ((copy = strdup(s)) == NULL)
		return (false);
	p = copy;
	while ((t = strsep(&p, ",")) != NULL) {
		if ((dash = strchr(t, '-')) != NULL)
			*dash++ = '\0';
		if (!number_ok(t, 1, 4094) || (dash != NULL && (!number_ok(dash,
		    1, 4094) || atoi(dash) < atoi(t)))) {
			free(copy);
			return (false);
		}
	}
	free(copy);
	return (true);
}

static bool
addr_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 64)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isxdigit((unsigned char)s[i]) && strchr(".:%", s[i]) ==
		    NULL && !isalnum((unsigned char)s[i]))
			return (false);
	return (strchr(s, '.') != NULL || strchr(s, ':') != NULL);
}

static const char *const bridge_flags[] = { "stp", "edge", "autoedge", "ptp",
    "autoptp", "learn", "discover", "sticky", "private", "span", "qinq" };
static const struct {
	const char	*name;
	long		 lo, hi;
} bridge_sets[] = {
	{ "priority", 0, 61440 }, { "hellotime", 1, 2 }, { "fwddelay", 4, 30 },
	{ "maxage", 6, 40 }, { "holdcnt", 1, 10 }, { "maxaddr", 0, 1000000 },
	{ "timeout", 0, 1000000 }, { "defuntagged", 1, 4094 },
}, bridge_ifsets[] = {
	{ "ifpriority", 0, 240 }, { "ifpathcost", 0, 200000000 },
	{ "ifmaxaddr", 0, 1000000 },
};

/*
 * The words ifconfig is given after the bridge's name, for the job; or
 * NULL and why not.  n is how many there are.
 */
static const char *
bridge_words(const struct arc_job_spec *sp, const char **out, int *np)
{
	const char *const	*a;
	const char		*verb;
	size_t			 na, i;
	int			 n;

	a = sp->names.v;
	na = sp->names.n;
	verb = sp->verb != NULL ? sp->verb : "";
	n = 0;
	if (!ifname_ok(sp->interface))
		return ("name the bridge");
	if ((strcmp(verb, "addm") == 0 || strcmp(verb, "deletem") == 0) &&
	    na == 1 && ifname_ok(a[0])) {
		out[n++] = verb;
		out[n++] = a[0];
	} else if (strcmp(verb, "access") == 0 && na == 2 && ifname_ok(a[0]) &&
	    number_ok(a[1], 1, 4094)) {
		out[n++] = "ifuntagged";
		out[n++] = a[0];
		out[n++] = a[1];
		out[n++] = "iftagged";
		out[n++] = a[0];
		out[n++] = "none";
	} else if (strcmp(verb, "trunk") == 0 && (na == 2 || na == 3) &&
	    ifname_ok(a[0]) && vlans_ok(a[1]) && (na == 2 || number_ok(a[2], 1,
	    4094))) {
		out[n++] = "iftagged";
		out[n++] = a[0];
		out[n++] = a[1];
		if (na == 3) {
			out[n++] = "ifuntagged";
			out[n++] = a[0];
			out[n++] = a[2];
		} else {
			out[n++] = "-ifuntagged";
			out[n++] = a[0];
		}
	} else if (strcmp(verb, "vlanfilter") == 0 && na == 1 && (strcmp(a[0],
	    "on") == 0 || strcmp(a[0], "off") == 0)) {
		out[n++] = a[0][1] == 'n' ? "vlanfilter" : "-vlanfilter";
	} else if (strcmp(verb, "flag") == 0 && na == 2 && ifname_ok(a[0])) {
		for (i = 0; i < nitems(bridge_flags); i++)
			if (strcmp(a[1] + (a[1][0] == '-'), bridge_flags[i]) ==
			    0)
				break;
		if (i == nitems(bridge_flags))
			return ("a member's flag is one of stp, edge, autoedge, "
			    "ptp, autoptp, learn, discover, sticky, private, "
			    "span, qinq, with - before it to take it away");
		out[n++] = a[1];
		out[n++] = a[0];
	} else if (strcmp(verb, "set") == 0 && na == 2) {
		if (strcmp(a[0], "proto") == 0) {
			if (strcmp(a[1], "stp") != 0 && strcmp(a[1], "rstp") !=
			    0)
				return ("the spanning tree is stp or rstp");
		} else {
			for (i = 0; i < nitems(bridge_sets); i++)
				if (strcmp(a[0], bridge_sets[i].name) == 0)
					break;
			if (i == nitems(bridge_sets) || !number_ok(a[1],
			    bridge_sets[i].lo, bridge_sets[i].hi))
				return ("set one of proto, priority, "
				    "hellotime, fwddelay, maxage, holdcnt, "
				    "maxaddr, timeout, defuntagged, to a "
				    "value it can have");
		}
		out[n++] = a[0];
		out[n++] = a[1];
	} else if (strcmp(verb, "ifset") == 0 && na == 3 && ifname_ok(a[0])) {
		if (strcmp(a[1], "ifvlanproto") == 0) {
			if (strcmp(a[2], "802.1q") != 0 && strcmp(a[2],
			    "802.1ad") != 0)
				return ("a VLAN protocol is 802.1q or 802.1ad");
		} else {
			for (i = 0; i < nitems(bridge_ifsets); i++)
				if (strcmp(a[1], bridge_ifsets[i].name) == 0)
					break;
			if (i == nitems(bridge_ifsets) || !number_ok(a[2],
			    bridge_ifsets[i].lo, bridge_ifsets[i].hi))
				return ("set one of ifpriority, ifpathcost, "
				    "ifmaxaddr, ifvlanproto of a member, to a "
				    "value it can have");
		}
		out[n++] = a[1];
		out[n++] = a[0];
		out[n++] = a[2];
	} else
		return ("a bridge job is addm or deletem and a member; access, "
		    "a member and a VLAN; trunk, a member, its VLANs and "
		    "perhaps the untagged one; vlanfilter on or off; flag, a "
		    "member and a flag; set, or ifset and a member, with "
		    "what to set and its value");
	*np = n;
	return (NULL);
}

static const struct {
	const char	*opt, *word;
} geneve_opts[] = {
	{ "id", "geneveid" }, { "local", "genevelocal" },
	{ "remote", "geneveremote" }, { "group", "genevegroup" },
	{ "dev", "genevedev" }, { "localport", "genevelocalport" },
	{ "remoteport", "geneveremoteport" }, { "ttl", "genevettl" },
	{ "df", "genevedf" }, { "maxaddr", "genevemaxaddr" },
	{ "timeout", "genevetimeout" },
};

/* The same for a geneve tunnel: after its name, or after "create". */
static const char *
geneve_words(struct work *w, const struct arc_job_spec *sp, const char **out,
    int *np)
{
	const char *const	*a;
	const char		*verb, *o, *v;
	size_t			 na, i, k;
	int			 n;
	bool			 create;

	a = sp->names.v;
	na = sp->names.n;
	verb = sp->verb != NULL ? sp->verb : "";
	n = 0;
	if (!ifname_ok(sp->interface) || strncmp(sp->interface, "geneve", 6) !=
	    0)
		return ("name the tunnel: geneve and a number");
	if (strcmp(verb, "flush") == 0 && na <= 1 && (na == 0 || strcmp(a[0],
	    "all") == 0)) {
		out[n++] = na == 1 ? "geneveflushall" : "geneveflush";
		*np = n;
		return (NULL);
	}
	create = strcmp(verb, "create") == 0;
	if ((!create && strcmp(verb, "set") != 0) || na % 2 != 0 || na == 0 ||
	    na > 30)
		return ("a geneve job is create or set, with options and "
		    "their values in pairs, or flush");
	/* The mode is of a new one only, and comes before the rest. */
	for (i = 0; i < na; i += 2)
		if (strcmp(a[i], "mode") == 0) {
			if (!create)
				return ("a tunnel's mode is given when it is "
				    "made, and stays");
			if (strcmp(a[i + 1], "l2") != 0 && strcmp(a[i + 1],
			    "l3") != 0)
				return ("the mode is l2 or l3");
			out[n++] = "genevemode";
			out[n++] = a[i + 1];
		}
	for (i = 0; i < na; i += 2) {
		o = a[i];
		v = a[i + 1];
		if (strcmp(o, "mode") == 0)
			continue;
		if (strcmp(o, "learn") == 0 || strcmp(o, "external") == 0 ||
		    strcmp(o, "dscpinherit") == 0) {
			if (strcmp(v, "on") != 0 && strcmp(v, "off") != 0)
				return ("learn, external and dscpinherit are "
				    "on or off");
			out[n++] = wfmt(w, "%sgeneve%s", v[1] == 'n' ? "" :
			    "-", o);
			continue;
		}
		if (strcmp(o, "portrange") == 0) {
			char	*lo, *hi;

			lo = wstrdup(w, v);
			if ((hi = strchr(lo, '-')) == NULL)
				return ("a port range is two ports with - "
				    "between");
			*hi++ = '\0';
			if (!number_ok(lo, 1, 65535) || !number_ok(hi, 1,
			    65535) || atoi(hi) < atoi(lo))
				return ("a port range is two ports with - "
				    "between");
			out[n++] = "geneveportrange";
			out[n++] = lo;
			out[n++] = hi;
			continue;
		}
		for (k = 0; k < nitems(geneve_opts); k++)
			if (strcmp(o, geneve_opts[k].opt) == 0)
				break;
		if (k == nitems(geneve_opts))
			return ("a geneve option is one of mode, id, local, "
			    "remote, group, dev, localport, remoteport, "
			    "portrange, ttl, df, maxaddr, timeout, learn, "
			    "external, dscpinherit");
		if ((strcmp(o, "id") == 0 && !number_ok(v, 0, 16777215)) ||
		    ((strcmp(o, "local") == 0 || strcmp(o, "remote") == 0 ||
		    strcmp(o, "group") == 0) && !addr_ok(v)) || (strcmp(o,
		    "dev") == 0 && !ifname_ok(v)) || ((strcmp(o, "localport")
		    == 0 || strcmp(o, "remoteport") == 0) && !number_ok(v, 1,
		    65535)) || (strcmp(o, "ttl") == 0 && strcmp(v, "inherit")
		    != 0 && !number_ok(v, 0, 255)) || (strcmp(o, "df") == 0 &&
		    strcmp(v, "set") != 0 && strcmp(v, "unset") != 0 &&
		    strcmp(v, "inherit") != 0) || ((strcmp(o, "maxaddr") == 0 ||
		    strcmp(o, "timeout") == 0) && !number_ok(v, 0, 100000000)))
			return (wfmt(w, "%s is not a value %s can have", v,
			    o));
		out[n++] = geneve_opts[k].word;
		out[n++] = v;
	}
	*np = n;
	return (NULL);
}

/* What is wrong with the job, or NULL: said before it is queued. */
const char *
l2_check(const struct arc_job_spec *sp)
{
	struct work	 w;
	const char	*out[L2_WORDS], *e;
	int		 n;

	if (sp->names.n > 32)
		return ("too many words");
	work_init(&w);
	e = sp->kind == ARC_JOB_KIND_BRIDGE ? bridge_words(sp, out, &n) :
	    geneve_words(&w, sp, out, &n);
	/* Said after the work's memory goes: only fixed words are kept. */
	if (e != NULL && sp->kind == ARC_JOB_KIND_GENEVE && strstr(e,
	    " is not a value ") != NULL)
		e = "an option has a value it cannot have";
	work_free(&w);
	return (e);
}

char *
l2_title(const struct arc_job_spec *sp)
{
	char	*t, *all;
	size_t	 i, len;

	len = 64;
	for (i = 0; i < sp->names.n; i++)
		len += strlen(sp->names.v[i]) + 1;
	if ((all = calloc(1, len)) == NULL)
		return (NULL);
	for (i = 0; i < sp->names.n; i++) {
		strlcat(all, " ", len);
		strlcat(all, sp->names.v[i], len);
	}
	if (asprintf(&t, "%s %s%s%s", sp->interface != NULL ? sp->interface :
	    "?", sp->verb != NULL ? sp->verb : "?", all, sp->persist ?
	    " (kept)" : "") == -1)
		t = NULL;
	free(all);
	return (t);
}

/*
 * Kept for the next boot: the words in rc.conf's ifconfig_<name>, in
 * place of those that set the same thing before.  Two settings are the
 * same when they are the same word, less a - before it, of the same
 * member when the word takes one.
 */
static void
keep(struct work *w, const char *ifname, const char **add, int nadd,
    bool create)
{
	static const struct {
		const char	*word;
		int		 args;
		bool		 member;
	} known[] = {
		{ "addm", 1, true }, { "deletem", 1, true },
		{ "ifuntagged", 2, true }, { "-ifuntagged", 1, true },
		{ "iftagged", 2, true }, { "vlanfilter", 0, false },
		{ "-vlanfilter", 0, false }, { "proto", 1, false },
		{ "priority", 1, false }, { "hellotime", 1, false },
		{ "fwddelay", 1, false }, { "maxage", 1, false },
		{ "holdcnt", 1, false }, { "maxaddr", 1, false },
		{ "timeout", 1, false }, { "defuntagged", 1, false },
		{ "ifpriority", 2, true }, { "ifpathcost", 2, true },
		{ "ifmaxaddr", 2, true }, { "ifvlanproto", 2, true },
		{ "geneveportrange", 2, false },
	};
	const char	*cur, *var, *e, *base, *out[256], *tok[256];
	char		*copy, *p, *t;
	size_t		 k;
	int		 ntok, nout, i, j, args;
	bool		 member, drop;

	var = wfmt(w, "ifconfig_%s", rc_ifname(w, ifname));
	cur = rc_get(w, var);
	copy = wstrdup(w, cur != NULL ? cur : "");
	ntok = 0;
	p = copy;
	while (ntok < 250 && (t = strsep(&p, " \t")) != NULL)
		if (*t != '\0')
			tok[ntok++] = t;
	nout = 0;
	for (i = 0; i < ntok; i += 1 + args) {
		/* How many words belong to this one, and whose it is. */
		args = 0;
		member = false;
		base = tok[i] + (tok[i][0] == '-');
		for (k = 0; k < nitems(known); k++)
			if (strcmp(tok[i], known[k].word) == 0) {
				args = known[k].args;
				member = known[k].member;
				break;
			}
		if (k == nitems(known)) {
			for (k = 0; k < nitems(bridge_flags); k++)
				if (strcmp(base, bridge_flags[k]) == 0) {
					args = 1;
					member = true;
				}
			if (strncmp(base, "geneve", 6) == 0 && strcmp(base,
			    "genevelearn") != 0 && strcmp(base,
			    "geneveexternal") != 0 && strcmp(base,
			    "genevedscpinherit") != 0)
				args = 1;
		}
		if (i + args >= ntok + (args == 0))
			args = ntok - i - 1;
		drop = false;
		for (j = 0; j < nadd && !drop; j++) {
			const char *nb = add[j] + (add[j][0] == '-');

			/* add[] is words and their values, one after another:
			 * only a word of ifconfig's can match one. */
			if (strcmp(nb, base) != 0 && !(strcmp(base, "addm") ==
			    0 && strcmp(nb, "deletem") == 0) && !(strcmp(base,
			    "iftagged") == 0 && strcmp(nb, "iftagged") == 0))
				continue;
			if (member && (j + 1 >= nadd || args < 1 || strcmp(
			    add[j + 1], tok[i + 1]) != 0))
				continue;
			drop = true;
		}
		for (j = 0; !drop && j <= args && nout < 250; j++)
			out[nout++] = tok[i + j];
	}
	/* What takes something away is not itself kept. */
	for (j = 0; j < nadd && nout < 250; ) {
		args = 0;
		for (k = 0; k < nitems(known); k++)
			if (strcmp(add[j], known[k].word) == 0)
				args = known[k].args;
		if (k == nitems(known) && args == 0) {
			base = add[j] + (add[j][0] == '-');
			for (k = 0; k < nitems(bridge_flags); k++)
				if (strcmp(base, bridge_flags[k]) == 0)
					args = 1;
			if (strncmp(base, "geneve", 6) == 0 && strcmp(base,
			    "genevelearn") != 0 && strcmp(base,
			    "geneveexternal") != 0 && strcmp(base,
			    "genevedscpinherit") != 0 && strcmp(base,
			    "geneveportrange") != 0 && strncmp(base,
			    "geneveflush", 11) != 0)
				args = 1;
		}
		if (strcmp(add[j], "deletem") != 0 && add[j][0] != '-' &&
		    strncmp(add[j], "geneveflush", 11) != 0)
			for (i = 0; i <= args && j + i < nadd && nout < 250;
			    i++)
				out[nout++] = add[j + i];
		j += 1 + args;
	}
	t = wcalloc(w, 4096, 1);
	for (i = 0; i < nout; i++) {
		if (i > 0)
			strlcat(t, " ", 4096);
		strlcat(t, out[i], 4096);
	}
	e = NULL;
	(void)rc_set(w, var, "=", t, &e);
	if (create)
		(void)rc_set(w, "cloned_interfaces", "+=", ifname, &e);
}

/* Do the job: ifconfig with the words, and kept when asked. */
int
do_l2_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct execres	 res;
	const char	*out[L2_WORDS], *e;
	char		*argv[L2_WORDS + 4];
	int		 n, i, k;
	bool		 create;

	e = sp->kind == ARC_JOB_KIND_BRIDGE ? bridge_words(sp, out, &n) :
	    geneve_words(w, sp, out, &n);
	if (e != NULL) {
		*errp = e;
		return (-1);
	}
	create = sp->kind == ARC_JOB_KIND_GENEVE && strcmp(sp->verb,
	    "create") == 0;
	k = 0;
	argv[k++] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[k++] = (char *)(uintptr_t)sp->interface;
	if (create)
		argv[k++] = (char *)(uintptr_t)"create";
	for (i = 0; i < n; i++)
		argv[k++] = (char *)(uintptr_t)out[i];
	argv[k] = NULL;
	if (run_exec(w, scope_argv(w, argv), &res) != 0) {
		*errp = scope_missing(w, &res, "ifconfig", NULL);
		if (*errp == NULL)
			*errp = wtext(w, exec_error(w, &res, "ifconfig"));
		return (-1);
	}
	/* A member taken in is brought up: a bridge passes nothing to
	 * one that is down. */
	if (sp->kind == ARC_JOB_KIND_BRIDGE && strcmp(sp->verb, "addm") ==
	    0) {
		argv[1] = (char *)(uintptr_t)sp->names.v[0];
		argv[2] = (char *)(uintptr_t)"up";
		argv[3] = NULL;
		(void)run_exec(w, scope_argv(w, argv), &res);
	}
	if (sp->persist && w->jail == NULL)
		keep(w, sp->interface, out, n, create);
	return (0);
}
