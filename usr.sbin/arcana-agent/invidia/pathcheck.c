/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: what this host would do with a packet, and with its reply,
 * none being sent (path-check).  The questions are those asked of a
 * path that does not work, each answered by what the kernel has:
 *
 * - does it come in here at all: the source or the destination is one
 *   of the host's addresses (getifaddrs(3)), or the packet passes
 *   through, by the interface the route back to its source is by,
 *   unless the interface is given;
 * - does the firewall take it in: ipfw's ruleset walked (fwmatch.c),
 *   ipfw(8) list and its tables as the kernel has them now;
 * - is there a route to send it by: the FIB of the interface it came in
 *   on (or the firewall's setfib), netlink(4)'s RTM_GETROUTE, as
 *   route-lookup; and is its next hop's ARP or NDP entry there;
 * - does the host forward at all: net.inet.ip.forwarding;
 * - does the firewall let it out;
 * - does the reply find its way back: the route to the source from
 *   where the reply comes in (the receive route), by the same interface
 *   (symmetric) or another, which strict reverse-path checks
 *   (verrevpath) and states made on another host turn into a drop; and
 *   does the firewall let the reply in and out, a state of the
 *   request's or a rule of its own.
 *
 * Findings say what is wrong in words, worst first.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>
#include <unistd.h>

#include "agent.h"
#include "fwmatch.h"

struct pc {
	struct work	*w;
	ucl_object_t	*top;
	ucl_object_t	*findings;
	struct fwpkt	 base;		/* the host's addresses in it */
	int		 af;
	uint8_t		 src[16], dst[16];
	const char	*srcs, *dsts;
	int		 proto, port, sport;
	/* What the helper said of the network: each interface's FIB,
	 * and the sysctls. */
	char		 ifname[64][16];
	int		 iffib[64];
	size_t		 nif;
	int		 fwd4, fwd6, fw4, fw6;	/* -1: no such sysctl */
	const char	*srcif, *dstif;
	int		 sbest, dbest;
	ucl_object_t	*addrs;
};

static void
put_s(ucl_object_t *o, const char *k, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), k, 0, true);
}

static void
put_b(ucl_object_t *o, const char *k, bool v)
{

	ucl_object_insert_key(o, ucl_object_frombool(v), k, 0, true);
}

static void
put_i(ucl_object_t *o, const char *k, int64_t v)
{

	ucl_object_insert_key(o, ucl_object_fromint(v), k, 0, true);
}

static void
finding(struct pc *c, const char *sev, const char *fmt, ...)
	__printflike(3, 4);

static void
finding(struct pc *c, const char *sev, const char *fmt, ...)
{
	ucl_object_t	*o;
	va_list		 ap;
	char		*s;

	va_start(ap, fmt);
	if (vasprintf(&s, fmt, ap) == -1)
		s = NULL;
	va_end(ap);
	if (s == NULL)
		return;
	o = ucl_object_typed_new(UCL_OBJECT);
	put_s(o, "severity", sev);
	put_s(o, "what", s);
	free(s);
	ucl_array_append(c->findings, o);
}

static int
if_fib(const char *name)
{
	struct ifreq	ifr;
	int		s, fib = 0;

	if ((s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		return (0);
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFFIB, &ifr) == 0)
		fib = ifr.ifr_fib;
	close(s);
	return (fib);
}

static int
plen(int af, const struct sockaddr *m)
{
	const uint8_t	*p;
	int		 n = 0, i, max;

	if (m == NULL)
		return (af == AF_INET ? 32 : 128);
	p = af == AF_INET ? (const uint8_t *)&((const struct sockaddr_in *)
	    (const void *)m)->sin_addr : (const uint8_t *)&((const struct
	    sockaddr_in6 *)(const void *)m)->sin6_addr;
	max = af == AF_INET ? 4 : 16;
	for (i = 0; i < max; i++)
		n += __builtin_popcount(p[i]);
	return (n);
}

static int
sysctl_int(const char *name)
{
	int	v = 0;
	size_t	len = sizeof(v);

	return (sysctlbyname(name, &v, &len, NULL, 0) == 0 ? v : -1);
}

/*
 * The helper's route-addrs, in the network it looks at (the host's, or
 * a jail's): a line of JSON for each address, its interface, prefix,
 * the interface's FIB and whether it is up or a loopback; then one of
 * the sysctls path-check needs.
 */
int
addr_lines(FILE *out)
{
	struct ifaddrs	*ifa, *i;
	const void	*a;
	char		 text[INET6_ADDRSTRLEN];
	int		 af;

	if (getifaddrs(&ifa) == 0) {
		for (i = ifa; i != NULL; i = i->ifa_next) {
			if (i->ifa_addr == NULL)
				continue;
			af = i->ifa_addr->sa_family;
			if (af != AF_INET && af != AF_INET6)
				continue;
			a = af == AF_INET ? (const void *)&((struct sockaddr_in
			    *)(void *)i->ifa_addr)->sin_addr : (const void *)
			    &((struct sockaddr_in6 *)(void *)i->ifa_addr)->
			    sin6_addr;
			inet_ntop(af, a, text, sizeof(text));
			fprintf(out, "{\"address\":\"%s\",\"prefixlen\":%d,"
			    "\"interface\":\"%s\",\"fib\":%d,\"up\":%s,"
			    "\"loopback\":%s}\n", text, plen(af,
			    i->ifa_netmask), i->ifa_name, if_fib(i->ifa_name),
			    (i->ifa_flags & IFF_UP) != 0 ? "true" : "false",
			    (i->ifa_flags & IFF_LOOPBACK) != 0 ? "true" :
			    "false");
		}
		freeifaddrs(ifa);
	}
	fprintf(out, "{\"sysctl\":true,\"forwarding\":%d,\"forwarding6\":%d,"
	    "\"fw\":%d,\"fw6\":%d}\n", sysctl_int("net.inet.ip.forwarding"),
	    sysctl_int("net.inet6.ip6.forwarding"),
	    sysctl_int("net.inet.ip.fw.enable"),
	    sysctl_int("net.inet6.ip6.fw.enable"));
	return (0);
}

static bool
covers(int af, const uint8_t *a, const uint8_t *net, int len)
{
	int	i;

	(void)af;
	for (i = 0; i < len / 8; i++)
		if (a[i] != net[i])
			return (false);
	return (len % 8 == 0 || ((a[i] ^ net[i]) & (0xff << (8 - len % 8))) ==
	    0);
}

static ucl_object_t *
line_obj(const char *line)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	if (line[0] != '{')
		return (NULL);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	o = ucl_parser_add_string(p, line, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	return (o);
}

static void
addr_line(const char *line, void *arg)
{
	struct pc	*c = arg;
	ucl_object_t	*o;
	const char	*ifn, *as;
	uint8_t		 a[16];
	int		 af, n;
	size_t		 i;

	if ((o = line_obj(line)) == NULL)
		return;
	if (ucl_object_lookup(o, "sysctl") != NULL) {
		c->fwd4 = (int)ucl_object_toint(ucl_object_lookup(o,
		    "forwarding"));
		c->fwd6 = (int)ucl_object_toint(ucl_object_lookup(o,
		    "forwarding6"));
		c->fw4 = (int)ucl_object_toint(ucl_object_lookup(o, "fw"));
		c->fw6 = (int)ucl_object_toint(ucl_object_lookup(o, "fw6"));
		ucl_object_unref(o);
		return;
	}
	ifn = ucl_object_tostring(ucl_object_lookup(o, "interface"));
	as = ucl_object_tostring(ucl_object_lookup(o, "address"));
	n = (int)ucl_object_toint(ucl_object_lookup(o, "prefixlen"));
	if (ifn == NULL || as == NULL) {
		ucl_object_unref(o);
		return;
	}
	for (i = 0; i < c->nif && strcmp(c->ifname[i], ifn) != 0; i++)
		;
	if (i == c->nif && c->nif < nitems(c->ifname)) {
		strlcpy(c->ifname[c->nif], ifn, sizeof(c->ifname[0]));
		c->iffib[c->nif++] = (int)ucl_object_toint(ucl_object_lookup(o,
		    "fib"));
	}
	af = strchr(as, ':') != NULL ? AF_INET6 : AF_INET;
	if (inet_pton(af, as, a) == 1) {
		if (c->base.nlocal < FW_LOCAL) {
			c->base.local_af[c->base.nlocal] = af;
			memcpy(c->base.local[c->base.nlocal], a, af ==
			    AF_INET ? 4 : 16);
			strlcpy(c->base.local_if[c->base.nlocal], ifn,
			    sizeof(c->base.local_if[0]));
			c->base.nlocal++;
		}
		/* The network of the interface that covers it: the
		 * longest. */
		if (af == c->af && !ucl_object_toboolean(ucl_object_lookup(o,
		    "loopback"))) {
			if (covers(af, c->src, a, n) && n > c->sbest) {
				c->sbest = n;
				c->srcif = wstrdup(c->w, ifn);
			}
			if (covers(af, c->dst, a, n) && n > c->dbest) {
				c->dbest = n;
				c->dstif = wstrdup(c->w, ifn);
			}
		}
	}
	ucl_array_append(c->addrs, o);
}

/* An interface's FIB, as the helper said. */
static int
fib_of(const struct pc *c, const char *ifn)
{
	size_t	i;

	for (i = 0; ifn != NULL && i < c->nif; i++)
		if (strcmp(c->ifname[i], ifn) == 0)
			return (c->iffib[i]);
	return (0);
}

static void
addresses(struct pc *c, const char **srcif, const char **dstif)
{

	c->addrs = ucl_object_typed_new(UCL_ARRAY);
	c->sbest = c->dbest = -1;
	c->fwd4 = c->fwd6 = c->fw4 = c->fw6 = -1;
	(void)helper_lines(c->w, "route-addrs", 0, NULL, addr_line, c);
	*srcif = c->srcif;
	*dstif = c->dstif;
	ucl_object_insert_key(c->top, c->addrs, "addresses", 0, true);
}

static bool
local(const struct pc *c, const uint8_t *a)
{
	size_t	i;

	for (i = 0; i < c->base.nlocal; i++)
		if (c->base.local_af[i] == c->af && memcmp(c->base.local[i], a,
		    c->af == AF_INET ? 4 : 16) == 0)
			return (true);
	return (false);
}

/* The route the kernel takes to addr in fib: route-lookup's best. */
static void
first_obj(const char *line, void *arg)
{
	ucl_object_t	**o = arg;

	if (*o == NULL)
		*o = line_obj(line);
}

static ucl_object_t *
route(struct pc *c, const char *addr, int fib)
{
	ucl_object_t	*o = NULL;
	const char	*words[2];

	words[0] = addr;
	words[1] = wfmt(c->w, "%d", fib);
	(void)helper_lines(c->w, "route-get", 2, words, first_obj, &o);
	if (o != NULL && ucl_object_lookup(o, "interface") == NULL) {
		ucl_object_unref(o);
		o = NULL;
	}
	return (o);
}

static const char *
str(const ucl_object_t *o, const char *k)
{

	return (ucl_object_tostring(ucl_object_lookup(o, k)));
}

/* The next hop's ARP or NDP entry: its state, or NULL: none. */
struct nb {
	struct pc	*c;
	const char	*addr;
	const char	*state;
};

static void
nb_line(const char *line, void *arg)
{
	struct nb	*n = arg;
	ucl_object_t	*o;

	if (n->state != NULL || (o = line_obj(line)) == NULL)
		return;
	if (str(o, "address") != NULL && strcmp(str(o, "address"), n->addr) ==
	    0)
		n->state = wstrdup(n->c->w, str(o, "state") != NULL ? str(o,
		    "state") : "reachable");
	ucl_object_unref(o);
}

static const char *
neighbor(struct pc *c, const char *addr)
{
	struct nb	 n = { c, addr, NULL };
	const char	*words[2];

	words[0] = c->af == AF_INET ? "4" : "6";
	words[1] = addr;
	(void)helper_lines(c->w, "route-neighs", 2, words, nb_line, &n);
	return (n.state);
}

/* `ipfw list` and its tables, as the kernel has them. */
static bool
ruleset(struct pc *c, struct fwset *set)
{
	struct execres	 res;
	char		*list, *tables;
	char *const	 a1[] = { (char *)(uintptr_t)opts.ipfw_bin,
	    (char *)(uintptr_t)"list", NULL };
	char *const	 a2[] = { (char *)(uintptr_t)opts.ipfw_bin,
	    (char *)(uintptr_t)"table", (char *)(uintptr_t)"all",
	    (char *)(uintptr_t)"list", NULL };

	if (run_exec(c->w, scope_argv(c->w, a1), &res) != 0 || res.status !=
	    0 || res.out == NULL)
		return (false);
	list = wmalloc(c->w, res.outlen + 1);
	memcpy(list, res.out, res.outlen);
	list[res.outlen] = '\0';
	tables = NULL;
	if (run_exec(c->w, scope_argv(c->w, a2), &res) == 0 && res.status ==
	    0 && res.out != NULL) {
		tables = wmalloc(c->w, res.outlen + 1);
		memcpy(tables, res.out, res.outlen);
		tables[res.outlen] = '\0';
	}
	return (fw_parse(set, list, tables) == 0);
}

/* One walk, as JSON. */
static ucl_object_t *
walk(struct pc *c, const struct fwset *set, const struct fwpkt *k,
    struct fwverdict *v)
{
	ucl_object_t	*o, *u, *e;
	size_t		 i;

	fw_eval(set, k, v);
	o = ucl_object_typed_new(UCL_OBJECT);
	put_s(o, "verdict", v->verdict);
	if (strcmp(v->verdict, "none") != 0) {
		put_i(o, "rule", set->rules[v->rule].num);
		put_s(o, "text", set->rules[v->rule].text);
	}
	if (v->by_state)
		put_b(o, "by_state", true);
	if (v->keep)
		put_b(o, "keep_state", true);
	if (v->setfib >= 0)
		put_i(o, "setfib", v->setfib);
	if (v->fwd[0] != '\0')
		put_s(o, "fwd", v->fwd);
	if (v->note != NULL)
		put_s(o, "note", v->note);
	if (v->nuncertain > 0) {
		u = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < v->nuncertain; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_s(e, "text", set->rules[v->uncertain[i]].text);
			put_s(e, "because", v->uncertain_why[i]);
			ucl_array_append(u, e);
		}
		ucl_object_insert_key(o, u, "uncertain", 0, true);
	}
	(void)c;
	return (o);
}

/* A firewall's fwd: the packet goes elsewhere than its route says. */
static void
fwd_note(struct pc *c, const struct fwverdict *v, const struct fwset *set,
    const char *what)
{

	if (strcmp(v->verdict, "fwd") == 0)
		finding(c, "warn", "The firewall sends %s on to %s, not by the "
		    "route: rule %ld (%s)", what, v->fwd[0] != '\0' ? v->fwd :
		    "a next hop of its own", set->rules[v->rule].num,
		    set->rules[v->rule].text);
}

static const char *
where(const struct fwverdict *v, const struct fwset *set)
{
	static char	buf[1100];

	if (strcmp(v->verdict, "none") == 0)
		return ("no rule");
	snprintf(buf, sizeof(buf), "rule %ld (%s)", set->rules[v->rule].num,
	    set->rules[v->rule].text);
	return (buf);
}

int
do_path_check(struct work *w, const char *srcs, const char *dsts,
    const char *proto, uint32_t port, const char *iface, bool has_fib,
    uint32_t fib0, bool reply, struct arc_path_check_rsp *rsp)
{
	static struct fwset	 set;
	struct pc		 c;
	struct fwpkt		 k;
	struct fwverdict	 rin, rout, pin, pout;
	ucl_object_t		*best, *back, *fw, *o;
	const char		*srcif, *dstif, *ingress, *egress, *nh;
	const char		*gw, *ns, *backif;
	unsigned char		*json;
	bool			 src_local, dst_local, fwd, fwd_x, fw_on, fw_x;
	bool			 have_fw, state, sym;
	int			 fib, step, ifib;
	char			 host[256];

	rsp->has_ok = true;
	memset(&pin, 0, sizeof(pin));
	pin.verdict = "none";
	memset(&c, 0, sizeof(c));
	c.w = w;
	c.srcs = srcs;
	c.dsts = dsts;
	if (inet_pton(AF_INET, srcs, c.src) == 1 && inet_pton(AF_INET, dsts,
	    c.dst) == 1)
		c.af = AF_INET;
	else if (inet_pton(AF_INET6, srcs, c.src) == 1 && inet_pton(AF_INET6,
	    dsts, c.dst) == 1)
		c.af = AF_INET6;
	else {
		rsp->error = "the source and the destination are addresses, "
		    "both IPv4 or both IPv6";
		return (0);
	}
	c.proto = proto == NULL || strcmp(proto, "ip") == 0 || proto[0] ==
	    '\0' ? 0 : strcmp(proto, "tcp") == 0 ? IPPROTO_TCP : strcmp(proto,
	    "udp") == 0 ? IPPROTO_UDP : strcmp(proto, "icmp") == 0 ?
	    (c.af == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6) : -1;
	if (c.proto == -1) {
		rsp->error = "the protocol is tcp, udp, icmp or ip";
		return (0);
	}
	c.port = (c.proto == IPPROTO_TCP || c.proto == IPPROTO_UDP) ?
	    (int)port : -1;
	/* A source port an operating system would pick: above them.  A
	 * reply's is the service's, to such a one. */
	c.sport = c.port >= 0 ? 49152 : -1;
	if (reply && c.port >= 0) {
		c.sport = c.port;
		c.port = 49152;
	}
	put_b(c.top, "reply", reply);
	c.top = ucl_object_typed_new(UCL_OBJECT);
	c.findings = ucl_object_typed_new(UCL_ARRAY);
	gethostname(host, sizeof(host));
	put_s(c.top, "host", host);
	c.base.af = c.af;

	addresses(&c, &srcif, &dstif);
	src_local = local(&c, c.src);
	dst_local = local(&c, c.dst);
	o = ucl_object_typed_new(UCL_OBJECT);
	put_b(o, "local", src_local);
	put_s(o, "connected", srcif);
	ucl_object_insert_key(c.top, o, "src", 0, true);
	o = ucl_object_typed_new(UCL_OBJECT);
	put_b(o, "local", dst_local);
	put_s(o, "connected", dstif);
	ucl_object_insert_key(c.top, o, "dst", 0, true);

	fwd_x = (c.af == AF_INET ? c.fwd4 : c.fwd6) != -1;
	fwd = (c.af == AF_INET ? c.fwd4 : c.fwd6) > 0;
	put_b(c.top, "forwarding", fwd);

	/* Where it comes in, and by which FIB it goes on. */
	ingress = NULL;
	fib = has_fib ? (int)fib0 : 0;
	if (iface != NULL && iface[0] != '\0') {
		ingress = iface;
		if (!has_fib)
			fib = fib_of(&c, iface);
	} else if (!src_local) {
		step = step_begin(w, ARC_STEP_KIND_SYSCALL, "netlink(4)",
		    "RTM_GETROUTE %s, FIB %d: where it comes in", srcs, fib);
		if ((back = route(&c, srcs, fib)) != NULL) {
			ingress = wstrdup(w, str(back, "interface"));
			ucl_object_unref(back);
			if (!has_fib)
				fib = fib_of(&c, ingress);
		}
		step_end(w, step, ingress != NULL, NULL);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	put_s(o, "interface", ingress);
	put_s(o, "how", iface != NULL && iface[0] != '\0' ? "given" :
	    src_local ? "made here" : ingress != NULL ? "by the route back to "
	    "the source" : "not known");
	ucl_object_insert_key(c.top, o, "ingress", 0, true);
	if (!src_local && ingress == NULL)
		finding(&c, "warn", "No route back to %s: where a packet from "
		    "it would come in is not known, and a reply could not go "
		    "back", srcs);

	/* The firewall: is it there, and on. */
	fw_x = (c.af == AF_INET ? c.fw4 : c.fw6) != -1;
	fw_on = (c.af == AF_INET ? c.fw4 : c.fw6) > 0;
	have_fw = false;
	if (fw_x && fw_on) {
		step = step_begin(w, ARC_STEP_KIND_EXEC, "ipfw", "list, and "
		    "the tables: the ruleset to walk");
		fw_free(&set);
		have_fw = ruleset(&c, &set);
		step_end(w, step, have_fw, "%zu rules", set.n);
	}
	fw = ucl_object_typed_new(UCL_OBJECT);
	put_b(fw, "on", fw_x && fw_on);

	/* The packet, as the firewall sees it. */
	k = c.base;
	memcpy(k.src, c.src, sizeof(k.src));
	memcpy(k.dst, c.dst, sizeof(k.dst));
	k.proto = c.proto;
	k.sport = c.sport;
	k.dport = c.port;
	k.icmptype = c.proto == IPPROTO_ICMP ? (reply ? 0 : 8) : c.proto ==
	    IPPROTO_ICMPV6 ? (reply ? 129 : 128) : -1;
	k.syn = c.proto == IPPROTO_TCP && !reply;
	k.ack = c.proto == IPPROTO_TCP && reply;
	k.src_local = src_local;
	k.dst_local = dst_local;
	k.fib = fib;
	state = false;

	/* Its route back now, for verrevpath and for the reply. */
	backif = NULL;
	if (!src_local && (back = route(&c, srcs, fib)) != NULL) {
		backif = wstrdup(w, str(back, "interface"));
		ucl_object_unref(back);
	}
	k.src_reach = src_local || backif != NULL;
	k.rpf = ingress == NULL || (backif != NULL && strcmp(backif,
	    ingress) == 0);

	if (!src_local && have_fw) {
		k.out = false;
		k.rcvif = ingress;
		k.xmitif = NULL;
		ucl_object_insert_key(fw, walk(&c, &set, &k, &rin), "in", 0,
		    true);
		state = rin.keep;
		fwd_note(&c, &rin, &set, "it");
		if (strcmp(rin.verdict, "deny") == 0)
			finding(&c, "bad", "The firewall drops it coming in%s%s: "
			    "%s", ingress != NULL ? " on " : "", ingress !=
			    NULL ? ingress : "", where(&rin, &set));
		if (rin.setfib >= 0) {
			fib = rin.setfib;
			k.fib = fib;
		}
	}
	if (fwd_x && !fwd && !src_local && !dst_local)
		finding(&c, "bad", "This host does not forward %s: %s is 0, so "
		    "a packet passing through it is dropped", c.af == AF_INET ?
		    "IPv4" : "IPv6", c.af == AF_INET ? "net.inet.ip.forwarding" :
		    "net.inet6.ip6.forwarding");

	/* The send route. */
	egress = NULL;
	nh = NULL;
	best = NULL;
	if (dst_local) {
		put_b(c.top, "delivered", true);
		finding(&c, "ok", "%s is this host's own: the packet ends here",
		    dsts);
	} else {
		step = step_begin(w, ARC_STEP_KIND_SYSCALL, "netlink(4)",
		    "RTM_GETROUTE %s, FIB %d: the send route", dsts, fib);
		best = route(&c, dsts, fib);
		step_end(w, step, best != NULL, NULL);
		if (best == NULL)
			finding(&c, "bad", "No route to %s in FIB %d: the send "
			    "route is missing, the packet is dropped here", dsts,
			    fib);
		else {
			const char *flags = str(best, "flags");

			egress = wstrdup(w, str(best, "interface"));
			gw = str(best, "gateway");
			nh = gw != NULL && strncmp(gw, "link#", 5) != 0 ?
			    wstrdup(w, gw) : dsts;
			if (flags != NULL && strchr(flags, 'B') != NULL)
				finding(&c, "bad", "The route to %s is a "
				    "blackhole: dropped without a word", dsts);
			else if (flags != NULL && strchr(flags, 'R') != NULL)
				finding(&c, "bad", "The route to %s rejects: "
				    "the sender is told it is unreachable",
				    dsts);
			if (egress != NULL && ingress != NULL && strcmp(egress,
			    ingress) == 0 && !src_local)
				finding(&c, "info", "It goes out by %s, the "
				    "interface it came in on: as a router of one "
				    "interface does (the sender may be told of a "
				    "shorter way, an ICMP redirect)", egress);
			ucl_object_insert_key(c.top, ucl_object_ref(best),
			    "route", 0, true);
		}
	}
	if (egress != NULL && nh != NULL) {
		ns = neighbor(&c, nh);
		o = ucl_object_typed_new(UCL_OBJECT);
		put_s(o, "address", nh);
		put_s(o, "state", ns != NULL ? ns : "none");
		ucl_object_insert_key(c.top, o, "neighbor", 0, true);
		if (ns != NULL && (strcmp(ns, "incomplete") == 0 || strcmp(ns,
		    "failed") == 0 || strcmp(ns, "unreachable") == 0))
			finding(&c, "bad", "The next hop %s does not answer ARP "
			    "or NDP on %s (%s): nothing there takes the "
			    "packet", nh, egress, ns);
	}
	if (best != NULL)
		ucl_object_unref(best);

	if (egress != NULL && have_fw) {
		k.out = true;
		k.rcvif = src_local ? NULL : ingress;
		k.xmitif = egress;
		k.state = state;
		ucl_object_insert_key(fw, walk(&c, &set, &k, &rout), "out", 0,
		    true);
		state = state || rout.keep;
		fwd_note(&c, &rout, &set, "it");
		if (strcmp(rout.verdict, "deny") == 0)
			finding(&c, "bad", "The firewall drops it going out by "
			    "%s: %s", egress, where(&rout, &set));
	}

	/* The reply: in where the request went out, back by the receive
	 * route. */
	sym = true;
	if (!src_local) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ifib = egress != NULL ? fib_of(&c, egress) : fib;
		if (dst_local)
			ifib = fib;
		put_i(o, "fib", ifib);
		back = route(&c, srcs, ifib);
		if (back == NULL) {
			finding(&c, "bad", "No route back to %s in FIB %d: the "
			    "receive route is missing, a reply is dropped here",
			    srcs, ifib);
			sym = false;
		} else {
			backif = wstrdup(w, str(back, "interface"));
			put_s(o, "interface", backif);
			put_s(o, "gateway", str(back, "gateway"));
			sym = ingress == NULL || strcmp(backif, ingress) == 0;
			ucl_object_unref(back);
			if (!sym)
				finding(&c, "warn", "Asymmetric: the request comes "
				    "in on %s, the reply goes back by %s. A state "
				    "of the firewall's, or uRPF (verrevpath), on "
				    "a host the other way, will drop it", ingress,
				    backif);
		}
		put_b(o, "symmetric", sym);
		ucl_object_insert_key(c.top, o, "return", 0, true);
	}
	if (have_fw && (egress != NULL || dst_local)) {
		struct fwpkt	r = c.base;

		memcpy(r.src, c.dst, sizeof(r.src));
		memcpy(r.dst, c.src, sizeof(r.dst));
		r.proto = c.proto;
		r.sport = c.port;
		r.dport = c.sport;
		r.icmptype = c.proto == IPPROTO_ICMP ? 0 : c.proto ==
		    IPPROTO_ICMPV6 ? 129 : -1;
		r.ack = c.proto == IPPROTO_TCP;
		r.src_local = dst_local;
		r.dst_local = src_local;
		r.state = state;
		r.fib = fib;
		r.src_reach = true;
		r.rpf = true;
		if (!dst_local) {
			r.out = false;
			r.rcvif = egress;
			ucl_object_insert_key(fw, walk(&c, &set, &r, &pin),
			    "reply_in", 0, true);
			fwd_note(&c, &pin, &set, "the reply");
			if (strcmp(pin.verdict, "deny") == 0)
				finding(&c, "bad", "The firewall drops the reply "
				    "coming in on %s: %s%s", egress, where(&pin,
				    &set), state ? "" : " (no state of the "
				    "request's here to let it in)");
		}
		if (!src_local && backif != NULL) {
			r.out = true;
			r.rcvif = dst_local ? NULL : egress;
			r.xmitif = backif;
			ucl_object_insert_key(fw, walk(&c, &set, &r, &pout),
			    "reply_out", 0, true);
			if (strcmp(pin.verdict, "fwd") != 0 || dst_local)
				fwd_note(&c, &pout, &set, "the reply");
			if (strcmp(pout.verdict, "deny") == 0)
				finding(&c, "bad", "The firewall drops the reply "
				    "going out by %s: %s", backif, where(&pout,
				    &set));
		}
	}
	ucl_object_insert_key(c.top, fw, "firewall", 0, true);
	put_i(c.top, "fib", fib);
	if (ucl_array_size(c.findings) == 0)
		finding(&c, "ok", "Nothing here stops it, nor its reply");
	ucl_object_insert_key(c.top, c.findings, "findings", 0, true);

	json = ucl_object_emit(c.top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(c.top);
	if (json == NULL) {
		rsp->error = "cannot build the reply";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}
