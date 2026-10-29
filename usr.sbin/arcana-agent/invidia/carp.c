/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: carp(4), an address shared by hosts on one network, held by
 * the one that is MASTER of its virtual host (vhid), CARP's own protocol
 * or VRRPv3.  Read and set through carp's generic netlink(4) family, as
 * ifconfig(8) does, so that a vhid's key goes to the kernel and never
 * on a command line; an address of a vhid is added and taken off with
 * ifconfig, and kept in rc.conf as an ifconfig_<if>_alias<n>.
 *
 *	carp-set ifname vhid [word=value ...]
 *		the helper's side (attached to the jail when there is
 *		one): the vhid made or changed, what is not given as it
 *		is, the key read from standard input (none: as it is).
 *		Words: advbase, advskew, version, prio, interval, state
 *		(master or backup).
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_carp.h>
#include <netinet/ip_carp_nl.h>
#include <arpa/inet.h>

#include <netlink/netlink.h>
#include <netlink/netlink_generic.h>
#include <netlink/netlink_route.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_generic.h>
#include <netlink/netlink_snl_route.h>
#include <netlink/netlink_snl_route_parsers.h>

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	CARP_MAX	32		/* vhids of one interface read */

struct vh {
	uint32_t	vhid, state;
	int32_t		advbase, advskew;
	uint8_t		key[CARP_KEY_LEN];
	struct in_addr	peer;
	struct in6_addr	peer6;
	uint8_t		version, prio;
	uint16_t	interval;
};

#define	_OUT(f)	offsetof(struct vh, f)
static const struct snl_attr_parser ap_vh[] = {
	{ .type = CARP_NL_VHID, .off = _OUT(vhid), .cb = snl_attr_get_uint32 },
	{ .type = CARP_NL_STATE, .off = _OUT(state), .cb = snl_attr_get_uint32 },
	{ .type = CARP_NL_ADVBASE, .off = _OUT(advbase), .cb = snl_attr_get_int32 },
	{ .type = CARP_NL_ADVSKEW, .off = _OUT(advskew), .cb = snl_attr_get_int32 },
	{ .type = CARP_NL_KEY, .off = _OUT(key), .cb = snl_attr_get_bytes,
	    .arg_u32 = CARP_KEY_LEN },
	{ .type = CARP_NL_ADDR, .off = _OUT(peer), .cb = snl_attr_get_in_addr },
	{ .type = CARP_NL_ADDR6, .off = _OUT(peer6), .cb = snl_attr_get_in6_addr },
	{ .type = CARP_NL_VERSION, .off = _OUT(version), .cb = snl_attr_get_uint8 },
	{ .type = CARP_NL_VRRP_PRIORITY, .off = _OUT(prio), .cb = snl_attr_get_uint8 },
	{ .type = CARP_NL_VRRP_ADV_INTER, .off = _OUT(interval),
	    .cb = snl_attr_get_uint16 },
};
#undef _OUT
SNL_DECLARE_GENL_PARSER(vh_parser, ap_vh);

/* The vhids of ifname, vhid 0 all of them; -1 when carp is not there. */
static int
vh_get(struct snl_state *ss, int family, const char *ifname, uint32_t vhid,
    struct vh *v, int max)
{
	struct snl_errmsg_data	 e = { 0 };
	struct snl_writer	 nw;
	struct nlmsghdr		*hdr;
	uint32_t		 seq;
	int			 n;

	snl_init_writer(ss, &nw);
	hdr = snl_create_genl_msg_request(&nw, family, CARP_NL_CMD_GET);
	hdr->nlmsg_flags |= NLM_F_DUMP;
	snl_add_msg_attr_string(&nw, CARP_NL_IFNAME, ifname);
	if (vhid != 0)
		snl_add_msg_attr_u32(&nw, CARP_NL_VHID, vhid);
	if ((hdr = snl_finalize_msg(&nw)) == NULL)
		return (-1);
	seq = hdr->nlmsg_seq;
	if (!snl_send_message(ss, hdr))
		return (-1);
	n = 0;
	while ((hdr = snl_read_reply_multi(ss, seq, &e)) != NULL) {
		if (n < max) {
			memset(&v[n], 0, sizeof(v[n]));
			if (snl_parse_nlmsg(ss, hdr, &vh_parser, &v[n])) {
				/* Read, never shown: not kept either. */
				explicit_bzero(v[n].key, sizeof(v[n].key));
				n++;
			}
		}
		snl_clear_lb(ss);
	}
	return (e.error != 0 && n == 0 ? 0 : n);
}

static const char *
state_name(uint32_t s)
{

	return (s == 2 ? "MASTER" : s == 1 ? "BACKUP" : "INIT");
}

static ucl_object_t *
vh_obj(const struct vh *v)
{
	ucl_object_t	*o;
	char		 buf[INET6_ADDRSTRLEN];

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromint(v->vhid), "vhid", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(state_name(v->state)),
	    "state", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(v->version != 0 ?
	    v->version : 2), "version", 0, false);
	if (v->version == 3) {
		ucl_object_insert_key(o, ucl_object_fromint(v->prio), "prio",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromint(v->interval),
		    "interval", 0, false);
	} else {
		ucl_object_insert_key(o, ucl_object_fromint(v->advbase),
		    "advbase", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(v->advskew),
		    "advskew", 0, false);
	}
	if (v->peer.s_addr != INADDR_ANY && inet_ntop(AF_INET, &v->peer, buf,
	    sizeof(buf)) != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(buf), "peer", 0,
		    true);
	if (!IN6_IS_ADDR_UNSPECIFIED(&v->peer6) && inet_ntop(AF_INET6,
	    &v->peer6, buf, sizeof(buf)) != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(buf), "peer6", 0,
		    true);
	return (o);
}

/* Which vhid each address belongs to, from the kernel's addresses. */
static void
addr_vhids(ucl_object_t *ifaces)
{
	struct snl_state	 ss;
	struct snl_errmsg_data	 e = { 0 };
	struct snl_parsed_addr	 a;
	struct nlmsghdr		*hdr;
	struct {
		struct nlmsghdr		hdr;
		struct ifaddrmsg	ifa;
	}			 msg;
	const ucl_object_t	*o, *x;
	ucl_object_iter_t	 it, xt;
	char			 name[IF_NAMESIZE], buf[NI_MAXHOST];

	if (!snl_init(&ss, NETLINK_ROUTE))
		return;
	memset(&msg, 0, sizeof(msg));
	msg.hdr.nlmsg_type = RTM_GETADDR;
	msg.hdr.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	msg.hdr.nlmsg_seq = snl_get_seq(&ss);
	msg.hdr.nlmsg_len = sizeof(msg);
	if (!snl_send_message(&ss, &msg.hdr)) {
		snl_free(&ss);
		return;
	}
	while ((hdr = snl_read_reply_multi(&ss, msg.hdr.nlmsg_seq, &e)) !=
	    NULL) {
		memset(&a, 0, sizeof(a));
		if (!snl_parse_nlmsg(&ss, hdr, &snl_rtm_addr_parser, &a) ||
		    a.ifaf_vhid == 0 || if_indextoname(a.ifa_index, name) ==
		    NULL || (a.ifa_local == NULL && a.ifa_address == NULL) ||
		    getnameinfo(a.ifa_local != NULL ? a.ifa_local :
		    a.ifa_address, (a.ifa_local != NULL ? a.ifa_local :
		    a.ifa_address)->sa_len, buf, sizeof(buf), NULL, 0,
		    NI_NUMERICHOST) != 0) {
			snl_clear_lb(&ss);
			continue;
		}
		it = NULL;
		while ((o = ucl_object_iterate(ifaces, &it, true)) != NULL) {
			if (ucl_object_tostring(ucl_object_lookup(o, "name")) ==
			    NULL || strcmp(ucl_object_tostring(
			    ucl_object_lookup(o, "name")), name) != 0)
				continue;
			xt = NULL;
			while ((x = ucl_object_iterate(ucl_object_lookup(o,
			    "addresses"), &xt, true)) != NULL)
				if (ucl_object_tostring(ucl_object_lookup(x,
				    "address")) != NULL && strcmp(
				    ucl_object_tostring(ucl_object_lookup(x,
				    "address")), buf) == 0)
					ucl_object_insert_key((ucl_object_t *)
					    (uintptr_t)x, ucl_object_fromint(
					    a.ifaf_vhid), "vhid", 0, false);
		}
		snl_clear_lb(&ss);
	}
	snl_free(&ss);
}

/*
 * Into the interfaces' reply: "carp" true when carp(4) is there, each
 * interface's vhids as its "carp", each address's vhid as its "vhid".
 */
void
carp_read(ucl_object_t *top, ucl_object_t *ifaces)
{
	struct snl_state	 ss;
	struct vh		 v[CARP_MAX];
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr;
	const char		*name;
	int			 family, i, n;

	if (!snl_init(&ss, NETLINK_GENERIC)) {
		ucl_object_insert_key(top, ucl_object_frombool(false), "carp", 0,
		    false);
		return;
	}
	family = snl_get_genl_family(&ss, CARP_NL_FAMILY_NAME);
	ucl_object_insert_key(top, ucl_object_frombool(family != 0), "carp", 0,
	    false);
	if (family == 0) {
		snl_free(&ss);
		return;
	}
	it = NULL;
	while ((o = ucl_object_iterate(ifaces, &it, true)) != NULL) {
		if ((name = ucl_object_tostring(ucl_object_lookup(o, "name"))) ==
		    NULL || (n = vh_get(&ss, family, name, 0, v, CARP_MAX)) <= 0)
			continue;
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < n; i++)
			ucl_array_append(arr, vh_obj(&v[i]));
		ucl_object_insert_key((ucl_object_t *)(uintptr_t)o, arr, "carp",
		    0, false);
	}
	snl_free(&ss);
	addr_vhids(ifaces);
}

/* --- the helper: a vhid made or changed --------------------------- */

static bool
num(const char *s, long min, long max, long *out)
{
	const char	*errstr;

	*out = (long)strtonum(s, min, max, &errstr);
	return (errstr == NULL);
}

int
carp_helper(int argc, char **argv)
{
	struct snl_state	 ss;
	struct snl_errmsg_data	 e = { 0 };
	struct snl_writer	 nw;
	struct nlmsghdr		*hdr;
	struct vh		 v;
	char			 key[CARP_KEY_LEN + 2], *eq;
	long			 l, vhid;
	ssize_t			 r;
	size_t			 klen;
	int			 family, i;
	bool			 have;

	if (argc < 3 || strcmp(argv[0], "carp-set") != 0 || !num(argv[2], 1,
	    255, &vhid))
		return (2);
	if (!snl_init(&ss, NETLINK_GENERIC)) {
		fprintf(stderr, "netlink: %s\n", strerror(errno));
		return (1);
	}
	if ((family = snl_get_genl_family(&ss, CARP_NL_FAMILY_NAME)) == 0) {
		fprintf(stderr, "carp(4) is not loaded: kldload carp\n");
		snl_free(&ss);
		return (1);
	}
	/* What it is now, the rest as ifconfig(8) makes a new one. */
	have = vh_get(&ss, family, argv[1], (uint32_t)vhid, &v, 1) == 1;
	if (!have) {
		memset(&v, 0, sizeof(v));
		v.advbase = 1;
		v.version = 2;
		v.prio = 100;
		v.interval = 100;
	}
	v.vhid = (uint32_t)vhid;
	v.state = 0;			/* as it is */
	for (i = 3; i < argc; i++) {
		if ((eq = strchr(argv[i], '=')) == NULL)
			return (2);
		*eq++ = '\0';
		if (strcmp(argv[i], "advbase") == 0 && num(eq, 1, 255, &l))
			v.advbase = (int32_t)l;
		else if (strcmp(argv[i], "advskew") == 0 && num(eq, 0, 254, &l))
			v.advskew = (int32_t)l;
		else if (strcmp(argv[i], "version") == 0 && num(eq, 2, 3, &l) &&
		    (!have || l == v.version))
			v.version = (uint8_t)l;
		else if (strcmp(argv[i], "prio") == 0 && num(eq, 1, 255, &l))
			v.prio = (uint8_t)l;
		else if (strcmp(argv[i], "interval") == 0 && num(eq, 1, 4095,
		    &l))
			v.interval = (uint16_t)l;
		else if (strcmp(argv[i], "state") == 0 && (strcmp(eq,
		    "master") == 0 || strcmp(eq, "backup") == 0))
			v.state = eq[0] == 'm' ? 2 : 1;
		else {
			fprintf(stderr, "%s=%s: %s\n", argv[i], eq, strcmp(argv[i],
			    "version") == 0 && have ? "a vhid's version is set "
			    "when it is made" : "not a value it takes");
			snl_free(&ss);
			return (1);
		}
	}
	/* The key, as ifconfig's pass: up to 19 bytes, the rest zero. */
	memset(key, 0, sizeof(key));
	klen = 0;
	while (klen < sizeof(key) - 1 && (r = read(STDIN_FILENO, key + klen,
	    sizeof(key) - 1 - klen)) > 0)
		klen += (size_t)r;
	key[strcspn(key, "\n")] = '\0';
	if (strlen(key) >= CARP_KEY_LEN) {
		explicit_bzero(key, sizeof(key));
		fprintf(stderr, "a key of 19 characters at most\n");
		snl_free(&ss);
		return (1);
	}
	memset(v.key, 0, sizeof(v.key));
	memcpy(v.key, key, strlen(key));
	explicit_bzero(key, sizeof(key));

	snl_init_writer(&ss, &nw);
	hdr = snl_create_genl_msg_request(&nw, family, CARP_NL_CMD_SET);
	snl_add_msg_attr_u32(&nw, CARP_NL_VHID, v.vhid);
	snl_add_msg_attr_u32(&nw, CARP_NL_STATE, v.state);
	snl_add_msg_attr_s32(&nw, CARP_NL_ADVBASE, v.advbase);
	snl_add_msg_attr_s32(&nw, CARP_NL_ADVSKEW, v.advskew);
	snl_add_msg_attr_string(&nw, CARP_NL_IFNAME, argv[1]);
	snl_add_msg_attr(&nw, CARP_NL_ADDR, sizeof(v.peer), &v.peer);
	snl_add_msg_attr(&nw, CARP_NL_ADDR6, sizeof(v.peer6), &v.peer6);
	snl_add_msg_attr(&nw, CARP_NL_KEY, sizeof(v.key), v.key);
	snl_add_msg_attr_u8(&nw, CARP_NL_VERSION, v.version);
	snl_add_msg_attr_u8(&nw, CARP_NL_VRRP_PRIORITY, v.prio);
	snl_add_msg_attr_u16(&nw, CARP_NL_VRRP_ADV_INTER, v.interval);
	hdr = snl_finalize_msg(&nw);
	explicit_bzero(v.key, sizeof(v.key));
	if (hdr == NULL || !snl_send_message(&ss, hdr) ||
	    !snl_read_reply_code(&ss, hdr->nlmsg_seq, &e) || e.error != 0) {
		fprintf(stderr, "carp vhid %ld on %s: %s\n", vhid, argv[1],
		    strerror(e.error != 0 ? e.error : errno));
		snl_free(&ss);
		return (1);
	}
	snl_free(&ss);
	return (0);
}

/* --- the job ------------------------------------------------------- */

/* "word=value" of the job's args, or NULL. */
static const char *
arg_of(const struct arc_job_spec *sp, const char *word)
{
	size_t	i, n;

	n = strlen(word);
	for (i = 0; i < sp->names.n; i++)
		if (strncmp(sp->names.v[i], word, n) == 0 &&
		    sp->names.v[i][n] == '=')
			return (sp->names.v[i] + n + 1);
	return (NULL);
}

/* The job's vhid, for its title. */
const char *
carp_vhid_of(const struct arc_job_spec *sp)
{
	const char	*v;

	return ((v = arg_of(sp, "vhid")) != NULL ? v : "?");
}

static bool
ifname_ok(const char *s)
{

	if (s == NULL || s[0] == '\0' || strlen(s) >= IF_NAMESIZE)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("._-", *s) == NULL)
			return (false);
	return (true);
}

/* A key rc.conf can keep as a word, and the kernel take whole. */
static bool
key_ok(const char *s)
{

	if (s == NULL || strlen(s) >= CARP_KEY_LEN)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("._-+@%:,/", *s) ==
		    NULL)
			return (false);
	return (true);
}

const char *
carp_check(const struct arc_job_spec *sp)
{
	static const char *const words[] = { "vhid", "advbase", "advskew",
	    "version", "prio", "interval", "state" };
	const char	*v, *eq;
	size_t		 i, k;
	long		 l;

	if (sp->verb == NULL || (strcmp(sp->verb, "add") != 0 &&
	    strcmp(sp->verb, "set") != 0 && strcmp(sp->verb, "remove") != 0))
		return ("carp: a verb, add, set or remove");
	if (!ifname_ok(sp->interface))
		return ("carp: an interface's name");
	if (sp->safe && strcmp(sp->verb, "add") != 0)
		return ("carp: only an address added is taken back by itself: "
		    "not in safe mode");
	for (i = 0; i < sp->names.n; i++) {
		if ((eq = strchr(sp->names.v[i], '=')) == NULL)
			return ("carp: each word word=value");
		for (k = 0; k < nitems(words); k++)
			if ((size_t)(eq - sp->names.v[i]) == strlen(words[k]) &&
			    strncmp(sp->names.v[i], words[k], strlen(words[k])) ==
			    0)
				break;
		if (k == nitems(words))
			return ("carp: the words are vhid, advbase, advskew, "
			    "version, prio, interval and state");
	}
	if ((v = arg_of(sp, "vhid")) == NULL || !num(v, 1, 255, &l))
		return ("carp: a vhid, 1 to 255");
	if ((v = arg_of(sp, "advbase")) != NULL && !num(v, 1, 255, &l))
		return ("carp: advbase is seconds, 1 to 255");
	if ((v = arg_of(sp, "advskew")) != NULL && !num(v, 0, 254, &l))
		return ("carp: advskew is 0 to 254");
	if ((v = arg_of(sp, "version")) != NULL && !num(v, 2, 3, &l))
		return ("carp: version 2 (CARP) or 3 (VRRPv3)");
	if ((v = arg_of(sp, "prio")) != NULL && !num(v, 1, 255, &l))
		return ("carp: a VRRPv3 priority is 1 to 255");
	if ((v = arg_of(sp, "interval")) != NULL && !num(v, 1, 4095, &l))
		return ("carp: a VRRPv3 interval is centiseconds, 1 to 4095");
	if ((v = arg_of(sp, "state")) != NULL && strcmp(v, "master") != 0 &&
	    strcmp(v, "backup") != 0)
		return ("carp: state master or backup");
	if (sp->preshared_key != NULL && sp->preshared_key[0] != '\0' &&
	    !key_ok(sp->preshared_key))
		return ("carp: a key of 19 characters at most, letters, digits "
		    "and ._-+@%:,/");
	if (strcmp(sp->verb, "set") != 0 && (sp->address == NULL ||
	    sp->address[0] == '\0' || strlen(sp->address) > 64))
		return ("carp: the address, with its prefix length");
	return (NULL);
}

/* The vhid made or changed by the helper, here or in the jail. */
static int
vh_set(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	static const char *const pass[] = { "advbase", "advskew", "version",
	    "prio", "interval", "state" };
	struct execres	 res;
	const char	*words[2 + nitems(pass)], *v;
	size_t		 i, n;
	int		 rc;

	n = 0;
	words[n++] = sp->interface;
	words[n++] = arg_of(sp, "vhid");
	for (i = 0; i < nitems(pass); i++)
		if ((v = arg_of(sp, pass[i])) != NULL)
			words[n++] = wfmt(w, "%s=%s", pass[i], v);
	v = sp->preshared_key != NULL ? sp->preshared_key : "";
	exec_set_stdin(v, strlen(v));
	rc = run_exec(w, helper_argv(w, "carp-set", n, words), &res);
	if (rc != 0)
		*errp = res.errlen > 0 ? wfmt(w, "%s", wstrndup(w, res.err,
		    strcspn(res.err, "\n"))) : wtext(w, exec_error(w, &res,
		    "carp-set"));
	return (rc);
}

/*
 * rc.conf's alias lines of the vhid, with what was set: each word
 * replaced where it is and added where it is not.
 */
static int
rc_vh(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	static const struct {
		const char	*arg, *word;
	} map[] = {
		{ "advbase", "advbase" }, { "advskew", "advskew" },
		{ "prio", "vrrpprio" }, { "interval", "vrrpinterval" },
	};
	const char	*line, *v, *tok, *vh;
	char		*out;
	size_t		 i, k, len;
	int		 n;
	bool		 found, skip;

	vh = arg_of(sp, "vhid");
	for (n = 0; n < 64; n++) {
		line = rc_get(w, wfmt(w, "ifconfig_%s_alias%d", sp->interface,
		    n));
		if (line == NULL)
			break;
		if (strstr(line, wfmt(w, "vhid %s ", vh)) == NULL)
			continue;
		/* The key it keeps is no trace's either. */
		if (sp->preshared_key == NULL && (v = strstr(line, "pass ")) !=
		    NULL) {
			v += 5;
			exec_set_hide(wstrndup(w, v, strcspn(v, " ")));
		}
		out = wstrdup(w, "");
		for (tok = line; *tok != '\0'; tok += len) {
			tok += strspn(tok, " ");
			if ((len = strcspn(tok, " ")) == 0)
				break;
			skip = false;
			for (k = 0; k < nitems(map) && !skip; k++)
				if (strlen(map[k].word) == len && strncmp(tok,
				    map[k].word, len) == 0 && arg_of(sp,
				    map[k].arg) != NULL)
					skip = true;
			if (len == 4 && strncmp(tok, "pass", 4) == 0 &&
			    sp->preshared_key != NULL && sp->preshared_key[0] !=
			    '\0')
				skip = true;
			if (skip) {
				/* The word and its value go; put again below. */
				tok += len;
				tok += strspn(tok, " ");
				len = strcspn(tok, " ");
				continue;
			}
			out = wfmt(w, "%s%s%.*s", out, out[0] != '\0' ? " " :
			    "", (int)len, tok);
			/* After "vhid N": what was set. */
			if (len == 4 && strncmp(tok, "vhid", 4) == 0) {
				tok += len;
				tok += strspn(tok, " ");
				len = strcspn(tok, " ");
				out = wfmt(w, "%s %.*s", out, (int)len, tok);
				for (i = 0; i < nitems(map); i++)
					if ((v = arg_of(sp, map[i].arg)) != NULL)
						out = wfmt(w, "%s %s %s", out,
						    map[i].word, v);
				if (sp->preshared_key != NULL &&
				    sp->preshared_key[0] != '\0')
					out = wfmt(w, "%s pass %s", out,
					    sp->preshared_key);
			}
		}
		found = strcmp(out, line) != 0;
		if (found && rc_set(w, wfmt(w, "ifconfig_%s_alias%d",
		    sp->interface, n), "=", out, errp) != 0)
			return (-1);
	}
	return (0);
}

/*
 * add: the vhid made or changed, then the address under it; set: the
 * vhid changed; remove: an address of it taken off, the vhid going with
 * its last.  With persist, rc.conf too: the address a line of its own
 * with the vhid's words (and its key, which rc.conf then holds), loaded
 * at boot with carp in kld_list.
 */
static int	carp_do(struct work *, const struct arc_job_spec *,
		    const char **);

/*
 * The key is in no trace: the programs' words have it hidden, and what
 * they say of rc.conf, which holds it, is not kept.
 */
int
do_carp(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	int	rc;

	exec_set_hide(sp->preshared_key);
	exec_set_secret(sp->persist);
	rc = carp_do(w, sp, errp);
	exec_set_secret(false);
	exec_set_hide(NULL);
	return (rc);
}

static int
carp_do(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct execres	 res;
	const char	*addr, *vh, *spec, *v;
	char		*argv[8], *slash;
	int		 af;

	if ((*errp = carp_check(sp)) != NULL)
		return (-1);
	vh = arg_of(sp, "vhid");
	if (strcmp(sp->verb, "remove") == 0)
		return (do_if_address(w, sp->interface, sp->address, true,
		    sp->persist, errp));
	if (vh_set(w, sp, errp) != 0)
		return (-1);
	if (strcmp(sp->verb, "set") == 0)
		return (sp->persist ? rc_vh(w, sp, errp) : 0);
	/* add */
	addr = sp->address;
	if ((slash = strchr(addr, '/')) == NULL)
		addr = wfmt(w, "%s/%d", addr, strchr(addr, ':') != NULL ? 128 :
		    32);
	af = strchr(addr, ':') != NULL ? AF_INET6 : AF_INET;
	argv[0] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[1] = (char *)(uintptr_t)sp->interface;
	argv[2] = (char *)(uintptr_t)(af == AF_INET ? "inet" : "inet6");
	argv[3] = (char *)(uintptr_t)addr;
	argv[4] = (char *)(uintptr_t)"vhid";
	argv[5] = (char *)(uintptr_t)vh;
	argv[6] = (char *)(uintptr_t)"alias";
	argv[7] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ifconfig"));
		return (-1);
	}
	if (!sp->persist)
		return (0);
	spec = wfmt(w, "vhid %s", vh);
	if ((v = arg_of(sp, "version")) != NULL && strcmp(v, "3") == 0)
		spec = wfmt(w, "%s carpver 3", spec);
	if ((v = arg_of(sp, "advbase")) != NULL)
		spec = wfmt(w, "%s advbase %s", spec, v);
	if ((v = arg_of(sp, "advskew")) != NULL)
		spec = wfmt(w, "%s advskew %s", spec, v);
	if ((v = arg_of(sp, "prio")) != NULL)
		spec = wfmt(w, "%s vrrpprio %s", spec, v);
	if ((v = arg_of(sp, "interval")) != NULL)
		spec = wfmt(w, "%s vrrpinterval %s", spec, v);
	if (sp->preshared_key != NULL && sp->preshared_key[0] != '\0')
		spec = wfmt(w, "%s pass %s", spec, sp->preshared_key);
	spec = wfmt(w, "%s %s", spec, addr);
	if (rc_alias(w, sp->interface, af == AF_INET ? "inet" : "inet6",
	    wstrndup(w, addr, strcspn(addr, "/")), spec, false, errp) != 0 ||
	    rc_set(w, "kld_list", "+=", "carp", errp) != 0) {
		argv[4] = (char *)(uintptr_t)"-alias";
		argv[5] = NULL;
		argv[3] = wstrndup(w, addr, strcspn(addr, "/"));
		(void)run_exec(w, argv, &res);
		return (-1);
	}
	return (0);
}
