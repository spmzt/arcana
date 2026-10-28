/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: ietf-interfaces as configuration (RFC 8343, RFC 8344, NMDA's
 * running), and a commit of it (PLAN-SDN-YANG 2.3, step 1).
 *
 * Running is what the kernel has, but what DHCP, SLAAC, the kernel or
 * the neighbour protocols made: an address or neighbour whose origin
 * is not static is left out (RFC 8344 section 4: origin tells them).
 *
 * A commit changes an interface's description, whether it is enabled,
 * its IPv4 MTU (the link's), its network instance (bind-ni-name, its
 * FIB: SIOCSIFFIB), its logical network element (bind-lne-name, a vnet
 * jail: SIOCSIFVNET), and its static IPv4 and IPv6 addresses;
 * makes one a cloner makes (with a gif's or gre's tunnel ends, a vlan's
 * tag and parent), and destroys one; what else the tree changes is
 * refused as not supported yet.  Each is
 * written to Arcana's rc.conf file as rc.d/netif reads it (rcarcana.c's
 * rules), then made the kernel's; failing, what was made is undone and
 * the files put back.
 *
 *	description	ifconfig_<if>_descr
 *	enabled		"down" on ifconfig_<if>, or "up"
 *	ipv4 mtu	"mtu N" on ifconfig_<if>
 *	instance	"fib N" first on ifconfig_<if>
 *	router adv.	its record in rtadvd.conf (rtadv.c), the interface on
 *			rtadvd_interfaces where it sends; rtadvd restarted
 *	made		cloned_interfaces; create_args_<if> for a vlan,
 *			"tunnel a b" first on ifconfig_<if>
 *	destroyed	off cloned_interfaces, its variables dropped
 *	element		ifconfig(8) vnet and -vnet; vnet.interface of the
 *			jail in jail.conf (vnet.c, libjailconf), where the
 *			jail is defined; moved into one alone, what else
 *			it has there the element's own (its root); back
 *			on the host, made live again as given
 *	an address	ifconfig_<if>_alias<n> "inet a/len", "inet6 a/len";
 *			taken out of whichever of ifconfig_<if>,
 *			ifconfig_<if>_ipv6 or the aliases has it, the
 *			aliases after it moved down ("" ends them)
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
#include <syslog.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "agent.h"
#include "collect.h"
#include "varconf.h"

typedef struct ietf_interfaces_interfaces_interface yif;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv4 yip4;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6 yip6;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv4_address yv4;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_address yv6;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv4_neighbor yn4;
typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_neighbor yn6;

#define	ALIAS_MAX	256

/*
 * Running's interfaces: data's, what is not static left out.  The
 * structs are the get's, in a; copies are made where something goes.
 */
int
yif_running(struct ietf_interfaces *data, cbl_yarena *a)
{
	struct ietf_interfaces_interfaces	*c;
	yif					*v;

	if (data->interfaces == NULL || data->interfaces->interface.n == 0)
		return (0);
	if ((c = cbl_yarena_alloc(a, sizeof(*c))) == NULL ||
	    (v = cbl_yarena_alloc(a, data->interfaces->interface.n *
	    sizeof(*v))) == NULL)
		return (ENOMEM);
	memcpy(v, data->interfaces->interface.v,
	    data->interfaces->interface.n * sizeof(*v));
	for (size_t i = 0; i < data->interfaces->interface.n; i++) {
		if (v[i].ip_ipv4 != NULL) {
			yip4	*p;
			yv4	*ad;
			yn4	*nb;
			size_t	 n = 0, m = 0;

			if ((p = cbl_yarena_alloc(a, sizeof(*p))) == NULL ||
			    (ad = cbl_yarena_alloc(a, (v[i].ip_ipv4->address.n
			    + 1) * sizeof(*ad))) == NULL ||
			    (nb = cbl_yarena_alloc(a, (v[i].ip_ipv4->neighbor.n
			    + 1) * sizeof(*nb))) == NULL)
				return (ENOMEM);
			*p = *v[i].ip_ipv4;
			for (size_t k = 0; k < p->address.n; k++)
				if (!p->address.v[k].has_origin ||
				    p->address.v[k].origin ==
				    IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV4_ADDRESS_ORIGIN_STATIC)
					ad[n++] = p->address.v[k];
			for (size_t k = 0; k < p->neighbor.n; k++)
				if (p->neighbor.v[k].has_origin &&
				    p->neighbor.v[k].origin ==
				    IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV4_NEIGHBOR_ORIGIN_STATIC)
					nb[m++] = p->neighbor.v[k];
			p->address.n = n;
			p->address.v = ad;
			p->neighbor.n = m;
			p->neighbor.v = nb;
			v[i].ip_ipv4 = p;
		}
		if (v[i].ip_ipv6 != NULL) {
			yip6	*p;
			yv6	*ad;
			yn6	*nb;
			size_t	 n = 0, m = 0;

			if ((p = cbl_yarena_alloc(a, sizeof(*p))) == NULL ||
			    (ad = cbl_yarena_alloc(a, (v[i].ip_ipv6->address.n
			    + 1) * sizeof(*ad))) == NULL ||
			    (nb = cbl_yarena_alloc(a, (v[i].ip_ipv6->neighbor.n
			    + 1) * sizeof(*nb))) == NULL)
				return (ENOMEM);
			*p = *v[i].ip_ipv6;
			for (size_t k = 0; k < p->address.n; k++)
				if (!p->address.v[k].has_origin ||
				    p->address.v[k].origin ==
				    IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV6_ADDRESS_ORIGIN_STATIC)
					ad[n++] = p->address.v[k];
			for (size_t k = 0; k < p->neighbor.n; k++)
				if (p->neighbor.v[k].has_origin &&
				    p->neighbor.v[k].origin ==
				    IETF_INTERFACES_INTERFACES_INTERFACE_IP_IPV6_NEIGHBOR_ORIGIN_STATIC)
					nb[m++] = p->neighbor.v[k];
			p->address.n = n;
			p->address.v = ad;
			p->neighbor.n = m;
			p->neighbor.v = nb;
			v[i].ip_ipv6 = p;
		}
	}
	*c = *data->interfaces;
	c->interface.v = v;
	data->interfaces = c;
	return (0);
}

typedef struct ietf_interfaces_interfaces_interface_ip_ipv6_v6ur_ipv6_router_advertisements
    yra;

/* Whether rtadvd(8) advertises on ifname: rtadvd_enable, and the
 * interface on rtadvd_interfaces (none listed: every one it has a
 * record of, as rc.d/rtadvd's "auto" does). */
static bool
advertises(struct rca *x, const char *ifname)
{
	const char	*on = rca_get(x, "rtadvd_enable");
	const char	*list = rca_get(x, "rtadvd_interfaces");
	char		*copy, *p, *w;
	bool		 found = false;

	if (on == NULL || (strcasecmp(on, "YES") != 0 && strcasecmp(on,
	    "TRUE") != 0 && strcasecmp(on, "ON") != 0 && strcmp(on, "1") != 0))
		return (false);
	if (list == NULL || list[strspn(list, " \t")] == '\0' ||
	    strcmp(list, "auto") == 0)
		return (true);
	if ((copy = strdup(list)) == NULL)
		return (false);
	for (p = copy; !found && (w = strsep(&p, " \t")) != NULL;)
		found = strcmp(w, ifname) == 0;
	free(copy);
	return (found);
}

/*
 * Each interface's router advertisements (RFC 8349's submodule) as
 * rtadvd.conf has them, its record's (rtadv.c), send-advertisements by
 * rc.conf's rtadvd_enable and rtadvd_interfaces.  The interfaces are the
 * get's, in a: copies made where something changes.
 */
int
yif_rtadv(struct ietf_interfaces *data, cbl_yarena *a)
{
	struct vc_capfile	 f;
	struct rca		 x;
	yif			*v;
	char			 err[256];
	bool			 rc;

	if (data->interfaces == NULL || data->interfaces->interface.n == 0)
		return (0);
	memset(&f, 0, sizeof(f));
	if (vc_cap_read(&f, opts.rtadvd_conf, err, sizeof(err)) == -1)
		return (0);	/* none: nothing advertised */
	rc = rca_open(&x, "rtadvd", err, sizeof(err)) == 0;
	v = (yif *)(uintptr_t)data->interfaces->interface.v;
	for (size_t i = 0; i < data->interfaces->interface.n; i++) {
		const yra *r;
		yra *ra;
		yip6 *p6;

		if (rtadv_read(&f, v[i].name, a, &r) != 0 || r == NULL)
			continue;
		if ((ra = cbl_yarena_alloc(a, sizeof(*ra))) == NULL ||
		    (p6 = cbl_yarena_alloc(a, sizeof(*p6))) == NULL) {
			vc_cap_free(&f);
			if (rc)
				rca_close(&x);
			return (ENOMEM);
		}
		*ra = *r;
		ra->has_send_advertisements = true;
		ra->send_advertisements = rc && advertises(&x, v[i].name);
		if (v[i].ip_ipv6 != NULL)
			*p6 = *v[i].ip_ipv6;
		else
			memset(p6, 0, sizeof(*p6));
		p6->v6ur_ipv6_router_advertisements = ra;
		v[i].ip_ipv6 = p6;
	}
	vc_cap_free(&f);
	if (rc)
		rca_close(&x);
	return (0);
}

/* The router advertisements' node, for two of them compared. */
static const struct cbl_ynode *
ra_node(void)
{
	static const struct cbl_ynode *n;
	static const char *const path[] = { "interface", "ipv6",
	    "router-advertisements" };
	const struct cbl_ynode *c;

	if (n != NULL)
		return (n);
	c = ynode_named("ietf-interfaces", "interfaces");
	for (size_t d = 0; c != NULL && d < nitems(path); d++) {
		const struct cbl_ynode *k = NULL;

		for (uint32_t i = 0; i < c->nchild && k == NULL; i++)
			if (strcmp(c->child[i]->name, path[d]) == 0)
				k = c->child[i];
		c = k;
	}
	return (n = c);
}

/* Whether e's and f's router advertisements differ. */
static bool
ra_differs(const yra *e, const yra *f)
{
	const struct cbl_ynode *n = ra_node();
	struct cbl_ybuf b1 = { NULL, 0, 0 }, b2 = { NULL, 0, 0 };
	bool differ;

	if (e == NULL || f == NULL)
		return (e != f);
	if (n == NULL || cbl_yencode(n, e, &b1) != 0 || cbl_yencode(n, f,
	    &b2) != 0)
		differ = true;
	else
		differ = b1.len != b2.len || memcmp(b1.p, b2.p, b1.len) != 0;
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
	return (differ);
}

/* An address of either family, as the kernel and rc.conf take it; of
 * a point-to-point interface, its far end too. */
union bin {
	struct in_addr	 v4;
	struct in6_addr	 v6;
};

struct addr {
	int		 af;
	const char	*ip;
	int		 plen;
	union bin	 bin;
	const char	*peer;		/* NULL: none */
	union bin	 pbin;
};

static bool
addr_of(int af, const char *ip, bool has, uint8_t plen, struct addr *x)
{

	x->af = af;
	x->ip = ip;
	x->plen = has ? plen : (af == AF_INET ? 32 : 128);
	x->peer = NULL;
	return (ip != NULL && inet_pton(af, ip, &x->bin) == 1);
}

/* x's far end, peer; false, none of x's family. */
static bool
peer_of(const char *peer, struct addr *x)
{

	x->peer = peer;
	return (peer == NULL || inet_pton(x->af, peer, &x->pbin) == 1);
}

static bool
addr_in(const struct addr *v, size_t n, const struct addr *x)
{

	size_t	len = x->af == AF_INET ? sizeof(struct in_addr) :
	    sizeof(struct in6_addr);

	for (size_t i = 0; i < n; i++)
		if (v[i].af == x->af && v[i].plen == x->plen &&
		    memcmp(&v[i].bin, &x->bin, len) == 0 &&
		    (v[i].peer != NULL) == (x->peer != NULL) &&
		    (x->peer == NULL || memcmp(&v[i].pbin, &x->pbin, len) ==
		    0))
			return (true);
	return (false);
}

/* An interface's static addresses, both families, malloc'd. */
static int
addrs_of(const yif *e, struct addr **vp, size_t *np)
{
	struct addr	*v;
	size_t		 n = 0, cap;

	cap = (e != NULL && e->ip_ipv4 != NULL ? e->ip_ipv4->address.n : 0) +
	    (e != NULL && e->ip_ipv6 != NULL ? e->ip_ipv6->address.n : 0);
	if ((v = calloc(cap + 1, sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; e != NULL && e->ip_ipv4 != NULL &&
	    i < e->ip_ipv4->address.n; i++) {
		const yv4 *x = &e->ip_ipv4->address.v[i];

		if (!addr_of(AF_INET, x->ip, x->has_prefix_length,
		    x->prefix_length, &v[n]) || !peer_of(x->arcif_peer,
		    &v[n])) {
			free(v);
			return (EOPNOTSUPP);
		}
		n++;
	}
	for (size_t i = 0; e != NULL && e->ip_ipv6 != NULL &&
	    i < e->ip_ipv6->address.n; i++) {
		const yv6 *x = &e->ip_ipv6->address.v[i];

		if (!addr_of(AF_INET6, x->ip, x->has_prefix_length,
		    x->prefix_length, &v[n]) || !peer_of(x->arcif_peer,
		    &v[n])) {
			free(v);
			return (EOPNOTSUPP);
		}
		n++;
	}
	*vp = v;
	*np = n;
	return (0);
}

/* e but what a commit changes here, as YANG-CBOR. */
static int
rest_of(const yif *e, struct cbl_ybuf *b)
{
	struct ietf_interfaces_interfaces	 c;
	struct ietf_interfaces			 top;
	yif					 x;
	yip4					 p4;
	yip6					 p6;

	x = *e;
	x.description = NULL;
	x.has_enabled = false;
	x.ni_bind_ni_name = NULL;
	x.lne_bind_lne_name = NULL;
	/* An epair's other end: the kernel's to say, and gone from here
	 * when the other end is moved into a jail. */
	x.if_ext_peer_interface = NULL;
	/* A container of addresses alone: as none (the first address
	 * makes it, the last one's going takes it). */
	if (x.ip_ipv4 != NULL) {
		p4 = *x.ip_ipv4;
		p4.address.n = 0;
		p4.address.v = NULL;
		p4.has_mtu = false;
		p4.mtu = 0;
		p4.ni_bind_ni_name = NULL;
		x.ip_ipv4 = memcmp(&p4, &(yip4){ 0 }, sizeof(p4)) == 0 ? NULL :
		    &p4;
	}
	if (x.ip_ipv6 != NULL) {
		p6 = *x.ip_ipv6;
		p6.address.n = 0;
		p6.address.v = NULL;
		p6.has_mtu = false;
		p6.mtu = 0;
		p6.ni_bind_ni_name = NULL;
		p6.v6ur_ipv6_router_advertisements = NULL;
		x.ip_ipv6 = memcmp(&p6, &(yip6){ 0 }, sizeof(p6)) == 0 ? NULL :
		    &p6;
	}
	memset(&c, 0, sizeof(c));
	c.interface.n = 1;
	c.interface.v = &x;
	top.interfaces = &c;
	top.interfaces_state = NULL;
	return (cbl_yencode_member(ynode_named("ietf-interfaces",
	    "interfaces"), &top, b));
}

/* The logical network element e is bound to, a vnet jail; NULL: none. */
static const char *
lne_of(const yif *e)
{

	return (e != NULL && e->lne_bind_lne_name != NULL &&
	    e->lne_bind_lne_name[0] != '\0' ? e->lne_bind_lne_name : NULL);
}

static bool
lne_same(const char *a, const char *b)
{

	return (a == NULL ? b == NULL : b != NULL && strcmp(a, b) == 0);
}

/* Whether a and b differ in more than their logical network element. */
static int
lne_alone(const yif *a, const yif *b, bool *more)
{
	struct ietf_interfaces_interfaces	 c;
	struct ietf_interfaces			 top;
	struct cbl_ybuf				 ba = { NULL, 0, 0 },
						 bb = { NULL, 0, 0 };
	yif					 x;
	int					 error;

	memset(&c, 0, sizeof(c));
	c.interface.n = 1;
	c.interface.v = &x;
	top.interfaces = &c;
	top.interfaces_state = NULL;
	x = *a;
	x.lne_bind_lne_name = NULL;
	if ((error = cbl_yencode_member(ynode_named("ietf-interfaces",
	    "interfaces"), &top, &ba)) == 0) {
		x = *b;
		x.lne_bind_lne_name = NULL;
		error = cbl_yencode_member(ynode_named("ietf-interfaces",
		    "interfaces"), &top, &bb);
	}
	*more = error == 0 && (ba.len != bb.len || memcmp(ba.p, bb.p,
	    ba.len) != 0);
	cbl_ybuf_free(&ba);
	cbl_ybuf_free(&bb);
	return (error);
}

/*
 * ifname taken out of the jail from (back to the host) and given to
 * the jail to, either NULL; kept in jail.conf where the jail is defined
 * in one, said in a warning where it is not.  Half done, put back.
 */
static int
lne_move(struct work *w, cbl_req *req, const char *ifname, const char *from,
    const char *to, const char **errp)
{
	struct cconf	 conf;
	const char	*e;
	bool		 kf, kt;

	conf_read(w, &conf);
	kf = from != NULL && conf_jail(&conf, from) != NULL;
	kt = to != NULL && conf_jail(&conf, to) != NULL;
	if (from != NULL && do_if_vnet(w, ifname, from, true, kf, errp) != 0)
		return (-1);
	if (to != NULL && do_if_vnet(w, ifname, to, false, kt, errp) != 0) {
		if (from != NULL)
			(void)do_if_vnet(w, ifname, from, false, kf, &e);
		return (-1);
	}
	if (req != NULL && ((from != NULL && !kf) || (to != NULL && !kt)))
		(void)cbl_req_ywarn(req, ynode_named("ietf-interfaces",
		    "interfaces")->sid, "not-kept", wfmt(w, "%s: the jail %s is "
		    "in no jail.conf: the move lasts while it runs", ifname,
		    to != NULL && !kt ? to : from));
	return (0);
}

static const yif *
named(const struct ietf_interfaces *t, const char *name)
{

	for (size_t i = 0; t != NULL && t->interfaces != NULL &&
	    i < t->interfaces->interface.n; i++)
		if (strcmp(t->interfaces->interface.v[i].name, name) == 0)
			return (&t->interfaces->interface.v[i]);
	return (NULL);
}

/* The words of s, in w's pool; *np of them. */
static char **
words(struct work *w, const char *s, size_t *np)
{
	char	**v, *p, *t;
	size_t	  n = 0;

	p = wstrdup(w, s != NULL ? s : "");
	v = wcalloc(w, strlen(p) / 2 + 2, sizeof(*v));
	while ((t = strsep(&p, " \t")) != NULL)
		if (*t != '\0')
			v[n++] = t;
	*np = n;
	return (v);
}

static char *
joined(struct work *w, char **v, size_t n)
{
	char	*s = wstrdup(w, "");

	for (size_t i = 0; i < n; i++)
		if (v[i] != NULL)
			s = wfmt(w, "%s%s%s", s, s[0] != '\0' ? " " : "", v[i]);
	return (s);
}

/* Whether word is x's address, with or without its length. */
static bool
is_addr(const char *word, const struct addr *x)
{
	struct addr	y;
	char		buf[INET6_ADDRSTRLEN + 8], *slash;

	(void)snprintf(buf, sizeof(buf), "%s", word);
	if ((slash = strchr(buf, '/')) != NULL)
		*slash = '\0';
	return (addr_of(x->af, buf, false, 0, &y) && memcmp(&y.bin, &x->bin,
	    x->af == AF_INET ? sizeof(struct in_addr) :
	    sizeof(struct in6_addr)) == 0);
}

/*
 * Line s without address x: its family word, the address, and the words
 * of it after (netmask, prefixlen, broadcast and their values, alias);
 * NULL where s has it not.
 */
static const char *
line_without(struct work *w, const char *s, const struct addr *x)
{
	char	**v;
	size_t	  n, i;

	v = words(w, s, &n);
	for (i = 1; i < n; i++)
		if ((strcmp(v[i - 1], "inet") == 0 || strcmp(v[i - 1],
		    "inet6") == 0) && is_addr(v[i], x))
			break;
	if (i >= n)
		return (NULL);
	v[i - 1] = v[i] = NULL;
	/* A point-to-point address's far end, right after it. */
	if (i + 1 < n) {
		union bin	b;

		if (inet_pton(x->af, v[i + 1], &b) == 1)
			v[++i] = NULL;
	}
	for (i++; i < n; i++) {
		if (strcmp(v[i], "alias") == 0) {
			v[i] = NULL;
			continue;
		}
		if ((strcmp(v[i], "netmask") == 0 || strcmp(v[i],
		    "prefixlen") == 0 || strcmp(v[i], "broadcast") == 0) &&
		    i + 1 < n) {
			v[i] = v[i + 1] = NULL;
			i++;
			continue;
		}
		break;
	}
	return (joined(w, v, n));
}

/* An address kept in rc.conf: on rca's lines for interface ri. */
static int
keep_addr(struct work *w, struct rca *x, const char *ri,
    const struct addr *ad, bool add, char *err, size_t errlen)
{
	const char	*al[ALIAS_MAX], *v, *nv;
	const char	*name;
	size_t		 n = 0, at = SIZE_MAX;

	for (; n < ALIAS_MAX; n++) {
		if ((al[n] = rca_get(x, wfmt(w, "ifconfig_%s_alias%zu", ri,
		    n))) == NULL || al[n][0] == '\0')
			break;
		if (at == SIZE_MAX && line_without(w, al[n], ad) != NULL)
			at = n;
	}
	if (add) {
		name = wfmt(w, "ifconfig_%s", ri);
		if (at != SIZE_MAX || ((v = rca_get(x, name)) != NULL &&
		    line_without(w, v, ad) != NULL) || ((v = rca_get(x,
		    wfmt(w, "%s_ipv6", name))) != NULL && line_without(w, v,
		    ad) != NULL))
			return (0);	/* kept already */
		if (n == ALIAS_MAX) {
			(void)snprintf(err, errlen, "too many aliases of %s in "
			    "rc.conf", ri);
			return (E2BIG);
		}
		return (rca_set(x, wfmt(w, "ifconfig_%s_alias%zu", ri, n),
		    wfmt(w, "%s %s/%d%s%s", ad->af == AF_INET ? "inet" :
		    "inet6", ad->ip, ad->plen, ad->peer != NULL ? " " : "",
		    ad->peer != NULL ? ad->peer : ""), err, errlen));
	}
	/* Out of the main lines, which may have it too. */
	for (int k = 0; k < 2; k++) {
		name = wfmt(w, k == 0 ? "ifconfig_%s" : "ifconfig_%s_ipv6", ri);
		if ((v = rca_get(x, name)) != NULL && (nv = line_without(w, v,
		    ad)) != NULL) {
			int error;

			if ((error = rca_set(x, name, nv, err, errlen)) != 0)
				return (error);
		}
	}
	if (at == SIZE_MAX)
		return (0);
	/* The aliases after it moved down; the last one's place ended. */
	for (size_t i = at; i + 1 < n; i++) {
		int error;

		if ((error = rca_set(x, wfmt(w, "ifconfig_%s_alias%zu", ri, i),
		    al[i + 1], err, errlen)) != 0)
			return (error);
	}
	return (rca_set(x, wfmt(w, "ifconfig_%s_alias%zu", ri, n - 1), "",
	    err, errlen));
}

/* "down" on ifconfig_<if>, or off it. */
static int
keep_enabled(struct work *w, struct rca *x, const char *ri, bool up,
    char *err, size_t errlen)
{
	const char	*name = wfmt(w, "ifconfig_%s", ri), *v;
	char		**wv;
	size_t		  n;

	v = rca_get(x, name);
	wv = words(w, v, &n);
	for (size_t i = 0; i < n; i++)
		if (strcmp(wv[i], "down") == 0 || strcmp(wv[i], "up") == 0)
			wv[i] = NULL;
	v = joined(w, wv, n);
	v = wfmt(w, "%s%s%s", v, v[0] != '\0' ? " " : "", up ? "up" : "down");
	return (rca_set(x, name, v, err, errlen));
}

/* The network instance e is bound to, of the interface and both its
 * families alike ("": none, FIB 0); NULL: they differ. */
static const char *
bound_to(const yif *e)
{
	const char	*n = e->ni_bind_ni_name != NULL ? e->ni_bind_ni_name : "";
	const char	*n4 = e->ip_ipv4 != NULL ? e->ip_ipv4->ni_bind_ni_name :
			    NULL;
	const char	*n6 = e->ip_ipv6 != NULL ? e->ip_ipv6->ni_bind_ni_name :
			    NULL;

	if (n[0] == '\0' && n4 != NULL)
		n = n4;
	if (n[0] == '\0' && n6 != NULL)
		n = n6;
	if ((n4 != NULL && strcmp(n4, n) != 0) || (n6 != NULL && strcmp(n6,
	    n) != 0))
		return (NULL);
	return (n);
}

/* "fib N" first on ifconfig_<if>: an address set before it would have
 * its route in FIB 0 (rc_word()'s rule); 0 takes it out. */
static int
keep_fib(struct work *w, struct rca *x, const char *ri, int fib, char *err,
    size_t errlen)
{
	const char	*name = wfmt(w, "ifconfig_%s", ri);
	char		**wv;
	size_t		  n;

	wv = words(w, rca_get(x, name), &n);
	for (size_t i = 0; i + 1 < n; i++)
		if (wv[i] != NULL && strcmp(wv[i], "fib") == 0)
			wv[i] = wv[i + 1] = NULL;
	if (fib == 0)
		return (rca_set(x, name, joined(w, wv, n), err, errlen));
	return (rca_set(x, name, wfmt(w, "fib %d%s%s", fib, n > 0 ? " " : "",
	    joined(w, wv, n)), err, errlen));
}

/* "mtu N" on ifconfig_<if>: replaced where it is, else added. */
static int
keep_mtu(struct work *w, struct rca *x, const char *ri, unsigned mtu,
    char *err, size_t errlen)
{
	const char	*name = wfmt(w, "ifconfig_%s", ri);
	char		**wv;
	size_t		  n, i;

	wv = words(w, rca_get(x, name), &n);
	for (i = 0; i + 1 < n; i++)
		if (strcmp(wv[i], "mtu") == 0)
			break;
	if (i + 1 < n) {
		wv[i + 1] = wfmt(w, "%u", mtu);
		return (rca_set(x, name, joined(w, wv, n), err, errlen));
	}
	return (rca_set(x, name, wfmt(w, "%s%smtu %u", joined(w, wv, n),
	    n > 0 ? " " : "", mtu), err, errlen));
}

/*
 * A cloned interface as do_if_create() makes it, of entry e: its name,
 * a gif's or gre's ends (arcana-interfaces' tunnel), a vlan's tag and
 * the interface it rides (if-extensions, if-vlan-encapsulation).
 */
static void
spec_of(const yif *e, struct arc_job_spec *sp)
{
	const struct ietf_interfaces_interfaces_interface_if_ext_encapsulation_if_vlan_dot1q_vlan *v;

	memset(sp, 0, sizeof(*sp));
	sp->interface = e->name;
	if (e->arcif_tunnel != NULL && e->arcif_tunnel->has_local &&
	    e->arcif_tunnel->has_remote) {
		sp->tunnel_local = e->arcif_tunnel->local.v.m0;
		sp->tunnel_remote = e->arcif_tunnel->remote.v.m0;
	}
	if (e->if_ext_encapsulation != NULL && (v =
	    e->if_ext_encapsulation->if_vlan_dot1q_vlan) != NULL &&
	    v->outer_tag != NULL && v->outer_tag->has_vlan_id) {
		sp->has_id = true;
		sp->id = v->outer_tag->vlan_id;
	}
	sp->parent = e->if_ext_parent_interface;
}

/* A new interface's entry has what spec_of() and the changes of an
 * existing one take, and nothing else: 0, or EOPNOTSUPP. */
static int
created_ok(const yif *a)
{
	struct cbl_ybuf	 b1 = { NULL, 0, 0 }, b2 = { NULL, 0, 0 };
	yif		 x, none;
	int		 error;

	x = *a;
	x.has_type = false;
	x.arcif_tunnel = NULL;
	x.if_ext_parent_interface = NULL;
	x.if_ext_encapsulation = NULL;
	memset(&none, 0, sizeof(none));
	none.name = a->name;
	if ((error = rest_of(&x, &b1)) == 0 && (error = rest_of(&none,
	    &b2)) == 0 && (b1.len != b2.len || memcmp(b1.p, b2.p, b1.len) !=
	    0))
		error = EOPNOTSUPP;
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
	return (error);
}

/* cloned_interfaces with base on it, or off it. */
static int
keep_cloned(struct work *w, struct rca *x, const char *base, bool on,
    char *err, size_t errlen)
{
	char	**wv;
	size_t	  n;
	bool	  there = false;

	wv = words(w, rca_get(x, "cloned_interfaces"), &n);
	for (size_t i = 0; i < n; i++)
		if (strcmp(wv[i], base) == 0) {
			there = true;
			if (!on)
				wv[i] = NULL;
		}
	if (there == on)
		return (0);	/* there already, or not there */
	if (!on)
		return (rca_set(x, "cloned_interfaces", joined(w, wv, n), err,
		    errlen));
	return (rca_set(x, "cloned_interfaces", wfmt(w, "%s%s%s", joined(w,
	    wv, n), n > 0 ? " " : "", base), err, errlen));
}

/* What rc.d/netif needs to make it again at boot: its create_args, a
 * tunnel's ends first on ifconfig_<if>. */
static int
keep_made(struct work *w, struct rca *x, const char *ri,
    const struct arc_job_spec *sp, char *err, size_t errlen)
{
	const char	*name = wfmt(w, "ifconfig_%s", ri);
	char		**wv;
	size_t		  n;
	int		  error = 0;

	if (sp->has_id && sp->parent != NULL)
		error = rca_set(x, wfmt(w, "create_args_%s", ri), wfmt(w,
		    "vlan %u vlandev %s", sp->id, sp->parent), err, errlen);
	if (error != 0 || sp->tunnel_local == NULL)
		return (error);
	wv = words(w, rca_get(x, name), &n);
	for (size_t i = 0; i + 2 < n; i++)
		if (strcmp(wv[i], "tunnel") == 0)
			wv[i] = wv[i + 1] = wv[i + 2] = NULL;
	return (rca_set(x, name, wfmt(w, "tunnel %s %s%s%s", sp->tunnel_local,
	    sp->tunnel_remote, n > 0 ? " " : "", joined(w, wv, n)), err,
	    errlen));
}

/* Every variable rc.d/netif reads of interface ri, dropped. */
static int
forget_made(struct work *w, struct rca *x, const char *ri)
{
	static const char *const v[] = { "ifconfig_%s", "ifconfig_%s_descr",
	    "ifconfig_%s_ipv6", "create_args_%s" };
	int	error = 0;

	for (size_t i = 0; error == 0 && i < nitems(v); i++)
		error = rca_drop(x, wfmt(w, v[i], ri));
	for (size_t i = 0; error == 0 && i < ALIAS_MAX; i++) {
		const char *name = wfmt(w, "ifconfig_%s_alias%zu", ri, i);

		if (rca_get(x, name) == NULL)
			break;
		error = rca_drop(x, name);
	}
	return (error);
}

/* rtadvd.conf as a commit changes it, and whether rtadvd sends. */
struct rtadv_change {
	struct vc_capfile	 f;
	bool			 read, changed, sends;
};

/* The interface's record, or none, in rtadvd.conf; it on
 * rtadvd_interfaces where it advertises (RFC 8349's default: not). */
static int
keep_ra(struct work *w, struct rca *x, struct rtadv_change *rt,
    const char *ifname, const yra *ra, char *err, size_t errlen)
{
	char	**wv;
	size_t	  n;
	bool	  send = ra != NULL && ra->has_send_advertisements &&
		    ra->send_advertisements, there = false;
	int	  error;

	if (!rt->read) {
		if (vc_cap_read(&rt->f, opts.rtadvd_conf, err, errlen) == -1)
			return (errno != 0 ? errno : EIO);
		if ((error = rca_keep(x, opts.rtadvd_conf)) != 0)
			return (error);
		rt->read = true;
	}
	if (ra == NULL)
		(void)vc_cap_remove_record(&rt->f, ifname, err, errlen);
	else if ((error = rtadv_write(&rt->f, ifname, ra, err, errlen)) != 0)
		return (error);
	rt->changed = true;
	wv = words(w, rca_get(x, "rtadvd_interfaces"), &n);
	for (size_t i = 0; i < n; i++)
		if (strcmp(wv[i], ifname) == 0) {
			there = true;
			if (!send)
				wv[i] = NULL;
		}
	if (send && !there)
		error = rca_set(x, "rtadvd_interfaces", wfmt(w, "%s%s%s",
		    joined(w, wv, n), n > 0 ? " " : "", ifname), err, errlen);
	else if (!send && there)
		error = rca_set(x, "rtadvd_interfaces", joined(w, wv, n), err,
		    errlen);
	else
		error = 0;
	if (error == 0 && send) {
		rt->sends = true;
		error = rca_set(x, "rtadvd_enable", "YES", err, errlen);
	}
	return (error);
}

/* rtadvd(8) made to read rtadvd.conf again, or stopped where nothing
 * is advertised. */
static int
rtadvd_again(struct work *w, struct rca *x, const char **errp)
{
	struct execres	 res;
	const char	*list = rca_get(x, "rtadvd_interfaces");
	char		*argv[4];

	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)"rtadvd";
	argv[2] = (char *)(uintptr_t)(list == NULL || list[strspn(list,
	    " \t")] == '\0' ? "onestop" : "onerestart");
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0 && strcmp(argv[2], "onestop") != 0) {
		*errp = wtext(w, exec_error(w, &res, "service rtadvd"));
		return (-1);
	}
	return (0);
}

/* What was made live, to be undone in the other order. */
struct made {
	enum { M_ADDR, M_STATE, M_DESCR, M_MTU, M_CREATE, M_DESTROY,
	    M_FIB, M_RTADV, M_LNE } kind;
	const char	*ifname;
	struct addr	 ad;
	bool		 add;		/* M_ADDR: added; M_STATE: brought up */
	const char	*was;		/* M_DESCR: the description before */
	unsigned	 mtu, was_mtu;	/* M_MTU */
	int		 fib, was_fib;	/* M_FIB */
	const char	*lne, *was_lne;	/* M_LNE: the jails, NULL the host */
	const yif	*entry;		/* M_CREATE, M_DESTROY: its entry */
};

static int	live_addr(struct work *, const char *, const struct addr *,
		    bool, const char **);

/* Interface e made again, as it was: by its spec, its description,
 * addresses and state. */
static int
remake(struct work *w, const yif *e, const char **errp)
{
	struct arc_job_spec	 sp;
	struct if_change	 ch = { 0, NULL, -1, -1, NULL };
	struct addr		*v;
	const char		*made;
	size_t			 n;
	int			 error;

	spec_of(e, &sp);
	if ((error = do_if_create(w, &sp, &made, errp)) != 0)
		return (error);
	if (e->description != NULL && e->description[0] != '\0') {
		ch.descr = e->description;
		(void)do_if_set(w, e->name, &ch, false, errp);
	}
	if (addrs_of(e, &v, &n) == 0) {
		for (size_t i = 0; i < n; i++)
			(void)live_addr(w, e->name, &v[i], true, errp);
		free(v);
	}
	if (!e->has_enabled || e->enabled)
		(void)do_if_state(w, e->name, true, errp);
	return (0);
}

/* The made list grown by one, zeroed; NULL out of memory. */
static struct made *
made_new(struct made **mp, size_t *np, size_t *capp)
{
	struct made	*t;

	if (*np == *capp) {
		*capp = *capp * 2 + 8;
		if ((t = reallocarray(*mp, *capp, sizeof(**mp))) == NULL)
			return (NULL);
		*mp = t;
	}
	t = &(*mp)[(*np)++];
	memset(t, 0, sizeof(*t));
	return (t);
}

static int
live_addr(struct work *w, const char *ifname, const struct addr *ad,
    bool add, const char **errp)
{

	return (ifaddr_change_peer(w, ifname, ad->af, &ad->bin, ad->plen,
	    ad->peer != NULL ? (const void *)&ad->pbin : NULL, add, errp));
}

int
ietf_interfaces_interfaces_edit(cbl_req *req,
    const struct ietf_interfaces *before, const struct ietf_interfaces *after)
{
	const struct ietf_network_instance_network_instances *ni = NULL;
	struct rtadv_change rt;
	struct work	 w;
	struct rca	 x;
	struct made	*m = NULL;
	cbl_yarena	*ya;
	size_t		 nm = 0, cap = 0, nlive = 0;
	char		 err[512];
	const char	*e = NULL;
	bool		 opened = false;
	int		 error = 0;

	err[0] = '\0';
	memset(&rt, 0, sizeof(rt));
	if ((ya = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	/* The instances a bind-ni-name names: FIBs by name. */
	if ((error = yni_instances(ya, &ni)) != 0) {
		cbl_yarena_free(ya);
		return (error);
	}
	work_init(&w);
	/* What is not supported yet: an interface added or taken away,
	 * or of one, more than this commit changes. */
	for (size_t i = 0; error == 0 && after != NULL && after->interfaces !=
	    NULL && i < after->interfaces->interface.n; i++) {
		const yif *a = &after->interfaces->interface.v[i], *b;
		struct cbl_ybuf b1 = { NULL, 0, 0 }, b2 = { NULL, 0, 0 };

		if ((b = named(before, a->name)) == NULL) {
			/* Made: by a cloner, of what spec_of() takes. */
			if (lne_of(a) != NULL) {
				(void)snprintf(err, sizeof(err), "%s: made on "
				    "the host first, then bound to a logical "
				    "network element", a->name);
				error = EOPNOTSUPP;
			} else if (!if_clonable(&w, a->name, NULL) ||
			    strncmp(a->name, "epair", 5) == 0) {
				(void)snprintf(err, sizeof(err), "%s: no such "
				    "interface; a commit makes one a cloner makes "
				    "(gif, gre, vlan, lo, bridge, tap...), an "
				    "epair's two sides not yet", a->name);
				error = EOPNOTSUPP;
			} else if ((error = created_ok(a)) != 0) {
				(void)snprintf(err, sizeof(err), "%s: made with "
				    "its type, tunnel ends, vlan tag and parent, "
				    "description, state, IPv4 MTU and static "
				    "addresses alone, so far", a->name);
				error = EOPNOTSUPP;
			}
		} else if (lne_of(a) != NULL || lne_of(b) != NULL) {
			bool more;

			/* Into a logical network element, or in one: moved
			 * alone (RFC 8530 section 3.1).  Out of one, what it
			 * has is made live again on the host. */
			if (lne_of(a) != NULL && (error = lne_alone(a, b,
			    &more)) == 0 && more) {
				(void)snprintf(err, sizeof(err), "%s: moved "
				    "alone to or from a logical network element; "
				    "what else it has there is changed in the "
				    "element's root", a->name);
				(void)cbl_req_set_yapptag(req,
				    "lne-assignment-failed");
				error = EIO;
			}
		} else if ((error = rest_of(a, &b1)) == 0 &&
		    (error = rest_of(b, &b2)) == 0 && (b1.len != b2.len ||
		    memcmp(b1.p, b2.p, b1.len) != 0)) {
			(void)snprintf(err, sizeof(err), "%s: only its "
			    "description, enabled, IPv4 MTU and static "
			    "addresses are changed here yet", a->name);
			error = EOPNOTSUPP;
		}
		cbl_ybuf_free(&b1);
		cbl_ybuf_free(&b2);
	}
	for (size_t i = 0; error == 0 && before != NULL && before->interfaces
	    != NULL && i < before->interfaces->interface.n; i++)
		if (named(after, before->interfaces->interface.v[i].name) ==
		    NULL && lne_of(&before->interfaces->interface.v[i]) !=
		    NULL) {
			(void)snprintf(err, sizeof(err), "%s: in the logical "
			    "network element %s: given back to the host first",
			    before->interfaces->interface.v[i].name,
			    lne_of(&before->interfaces->interface.v[i]));
			error = EOPNOTSUPP;
		} else if (named(after, before->interfaces->interface.v[i].
		    name) == NULL && (!if_clonable(&w, before->interfaces->interface.v[i].
		    name, NULL) || strncmp(before->interfaces->interface.v[i].
		    name, "epair", 5) == 0)) {
			(void)snprintf(err, sizeof(err), "%s: not one a cloner "
			    "made (or an epair's side): it is not taken away "
			    "by a commit", before->interfaces->interface.v[i].
			    name);
			error = EOPNOTSUPP;
		}
	if (error == 0 && (error = rca_open(&x, "netif", err,
	    sizeof(err))) == 0)
		opened = true;
	/* rc.conf first, every interface; then the kernel. */
	for (size_t i = 0; error == 0 && after != NULL && after->interfaces !=
	    NULL && i < after->interfaces->interface.n; i++) {
		const yif *a = &after->interfaces->interface.v[i];
		const yif *b0 = named(before, a->name), *b;
		const char *ri = rc_ifname(&w, a->name), *base;
		struct arc_job_spec sp;
		struct addr *va, *vb;
		struct made *mk;
		size_t na, nb;
		yif none;
		/* Made by this commit: down, of nothing yet. */
		bool made = b0 == NULL;
		bool up_a, up_b, mtu4;
		const char *da, *db;

		/* Its logical network element: moved. */
		if (!made && (lne_of(a) != NULL || lne_of(b0) != NULL)) {
			if (lne_same(lne_of(a), lne_of(b0)))
				continue;
			if ((mk = made_new(&m, &nm, &cap)) == NULL) {
				error = ENOMEM;
				break;
			}
			mk->kind = M_LNE;
			mk->ifname = wstrdup(&w, a->name);
			mk->lne = lne_of(a) != NULL ? wstrdup(&w, lne_of(a)) :
			    NULL;
			mk->was_lne = lne_of(b0) != NULL ? wstrdup(&w,
			    lne_of(b0)) : NULL;
			nlive++;
			if (lne_of(a) != NULL)
				continue;
			/*
			 * Back on the host, its addresses gone with the move
			 * (if_vmove()): what a has is made live again, its
			 * description, addresses, MTU and state; rc.conf
			 * kept them all along.
			 */
			if (a->description != NULL && a->description[0] !=
			    '\0') {
				if ((mk = made_new(&m, &nm, &cap)) == NULL) {
					error = ENOMEM;
					break;
				}
				mk->kind = M_DESCR;
				mk->ifname = wstrdup(&w, a->name);
				mk->was = "";
				mk->ad.ip = wstrdup(&w, a->description);
				nlive++;
			}
			if (addrs_of(a, &va, &na) == 0) {
				for (size_t k = 0; error == 0 && k < na; k++) {
					if ((mk = made_new(&m, &nm, &cap)) ==
					    NULL) {
						error = ENOMEM;
						break;
					}
					mk->kind = M_ADDR;
					mk->ifname = wstrdup(&w, a->name);
					mk->ad = va[k];
					mk->ad.ip = wstrdup(&w, va[k].ip);
					mk->add = true;
					nlive++;
				}
				free(va);
			}
			if (error == 0 && a->ip_ipv4 != NULL &&
			    a->ip_ipv4->has_mtu) {
				if ((mk = made_new(&m, &nm, &cap)) == NULL) {
					error = ENOMEM;
					break;
				}
				mk->kind = M_MTU;
				mk->ifname = wstrdup(&w, a->name);
				mk->mtu = a->ip_ipv4->mtu;
				nlive++;
			}
			if (error == 0 && (!a->has_enabled || a->enabled)) {
				if ((mk = made_new(&m, &nm, &cap)) == NULL) {
					error = ENOMEM;
					break;
				}
				mk->kind = M_STATE;
				mk->ifname = wstrdup(&w, a->name);
				mk->add = true;
				nlive++;
			}
			if (error != 0)
				break;
			continue;
		}
		memset(&none, 0, sizeof(none));
		none.name = a->name;
		b = made ? &none : b0;
		up_a = !a->has_enabled || a->enabled;
		up_b = !made && (!b->has_enabled || b->enabled);
		da = a->description != NULL ? a->description : "";
		db = b->description != NULL ? b->description : "";
		/* An MTU only where both say one (or the new one does):
		 * none given leaves it.  FreeBSD's IPv4 MTU is the link's
		 * (SIOCSIFMTU). */
		mtu4 = a->ip_ipv4 != NULL && a->ip_ipv4->has_mtu && (b->ip_ipv4 !=
		    NULL && b->ip_ipv4->has_mtu ? a->ip_ipv4->mtu !=
		    b->ip_ipv4->mtu : made);
		if (made) {
			spec_of(a, &sp);
			(void)if_clonable(&w, a->name, &base);
			if ((error = keep_cloned(&w, &x, base, true, err,
			    sizeof(err))) != 0 || (error = keep_made(&w, &x, ri,
			    &sp, err, sizeof(err))) != 0)
				break;
			if ((mk = made_new(&m, &nm, &cap)) == NULL) {
				error = ENOMEM;
				break;
			}
			mk->kind = M_CREATE;
			mk->ifname = wstrdup(&w, a->name);
			mk->entry = a;
		}
		/* Its network instance: its FIB, of both families. */
		{
			const char *ba = bound_to(a), *bb = bound_to(b);
			int fa, fb;

			if (ba == NULL) {
				(void)snprintf(err, sizeof(err), "%s: FreeBSD "
				    "binds an interface, both its address "
				    "families, not one alone", a->name);
				error = EINVAL;
				break;
			}
			fa = ba[0] == '\0' ? 0 : yni_fib(ni, ba);
			fb = bb == NULL || bb[0] == '\0' ? 0 : yni_fib(ni, bb);
			if (fa == -1) {
				(void)snprintf(err, sizeof(err), "%s: no network "
				    "instance %s", a->name, ba);
				error = ENOENT;
				break;
			}
			if (fb == -1)
				fb = 0;
			if (fa != fb) {
				if ((error = keep_fib(&w, &x, ri, fa, err,
				    sizeof(err))) != 0)
					break;
				if ((mk = made_new(&m, &nm, &cap)) == NULL) {
					error = ENOMEM;
					break;
				}
				mk->kind = M_FIB;
				mk->ifname = wstrdup(&w, a->name);
				mk->fib = fa;
				mk->was_fib = fb;
			}
		}
		/* Its router advertisements: rtadvd.conf's record. */
		{
			const yra *ra = a->ip_ipv6 != NULL ?
			    a->ip_ipv6->v6ur_ipv6_router_advertisements : NULL;
			const yra *rb = b->ip_ipv6 != NULL ?
			    b->ip_ipv6->v6ur_ipv6_router_advertisements : NULL;

			if (ra_differs(ra, rb) && (error = keep_ra(&w, &x, &rt,
			    a->name, ra, err, sizeof(err))) != 0)
				break;
		}

		if (a->ip_ipv6 != NULL && b->ip_ipv6 != NULL &&
		    a->ip_ipv6->has_mtu && b->ip_ipv6->has_mtu &&
		    a->ip_ipv6->mtu != b->ip_ipv6->mtu) {
			(void)snprintf(err, sizeof(err), "%s: an IPv6 MTU of "
			    "its own is not supported here yet", a->name);
			error = EOPNOTSUPP;
			break;
		}

		if ((error = addrs_of(a, &va, &na)) != 0) {
			if (error == EOPNOTSUPP)
				(void)snprintf(err, sizeof(err), "%s: an "
				    "address, or its peer, is not one of its "
				    "family", a->name);
			break;
		}
		if ((error = addrs_of(b, &vb, &nb)) != 0) {
			free(va);
			break;
		}
		if (strcmp(da, db) != 0) {
			if (!rc_value_ok(da)) {
				(void)snprintf(err, sizeof(err), "%s: a "
				    "description rc.conf cannot hold: no quote, "
				    "$, ` or \\", a->name);
				error = EINVAL;
			} else
				error = rca_set(&x, wfmt(&w, "ifconfig_%s_descr",
				    ri), da, err, sizeof(err));
		}
		if (error == 0 && up_a != up_b)
			error = keep_enabled(&w, &x, ri, up_a, err, sizeof(err));
		if (error == 0 && mtu4)
			error = keep_mtu(&w, &x, ri, a->ip_ipv4->mtu, err,
			    sizeof(err));
		for (size_t k = 0; error == 0 && k < nb; k++)
			if (!addr_in(va, na, &vb[k]))
				error = keep_addr(&w, &x, ri, &vb[k], false, err,
				    sizeof(err));
		for (size_t k = 0; error == 0 && k < na; k++)
			if (!addr_in(vb, nb, &va[k]))
				error = keep_addr(&w, &x, ri, &va[k], true, err,
				    sizeof(err));
		/* What to make live, in this order. */
		for (size_t k = 0; error == 0 && k < nb + na + 3; k++) {
			struct made	*t;

			if (nm == cap) {
				cap = cap * 2 + 8;
				if ((t = reallocarray(m, cap, sizeof(*m))) ==
				    NULL) {
					error = ENOMEM;
					break;
				}
				m = t;
			}
			t = &m[nm];
			memset(t, 0, sizeof(*t));
			t->ifname = wstrdup(&w, a->name);
			if (k == 0 && strcmp(da, db) != 0) {
				t->kind = M_DESCR;
				t->was = wstrdup(&w, db);
				t->ad.ip = wstrdup(&w, da);
				nm++;
			} else if (k > 0 && k <= nb && !addr_in(va, na,
			    &vb[k - 1])) {
				t->kind = M_ADDR;
				t->ad = vb[k - 1];
				t->ad.ip = wstrdup(&w, vb[k - 1].ip);
				t->add = false;
				nm++;
			} else if (k > nb && k <= nb + na && !addr_in(vb, nb,
			    &va[k - nb - 1])) {
				t->kind = M_ADDR;
				t->ad = va[k - nb - 1];
				t->ad.ip = wstrdup(&w, va[k - nb - 1].ip);
				t->add = true;
				nm++;
			} else if (k == nb + na + 1 && up_a != up_b) {
				t->kind = M_STATE;
				t->add = up_a;
				nm++;
			} else if (k == nb + na + 2 && mtu4) {
				t->kind = M_MTU;
				t->mtu = a->ip_ipv4->mtu;
				t->was_mtu = b->ip_ipv4 != NULL ?
				    b->ip_ipv4->mtu : 0;
				nm++;
			}
		}
		free(va);
		free(vb);
	}
	/* Taken away: off cloned_interfaces, its variables dropped. */
	for (size_t i = 0; error == 0 && before != NULL && before->interfaces
	    != NULL && i < before->interfaces->interface.n; i++) {
		const yif *b = &before->interfaces->interface.v[i];
		const char *base;
		struct made *t;

		if (named(after, b->name) != NULL)
			continue;
		(void)if_clonable(&w, b->name, &base);
		if ((error = keep_cloned(&w, &x, base, false, err,
		    sizeof(err))) != 0 || (error = forget_made(&w, &x,
		    rc_ifname(&w, b->name))) != 0)
			break;
		if ((t = made_new(&m, &nm, &cap)) == NULL) {
			error = ENOMEM;
			break;
		}
		t->kind = M_DESTROY;
		t->ifname = wstrdup(&w, b->name);
		t->entry = b;
	}
	if (error == 0 && rt.changed) {
		struct made *t;

		if (vc_cap_write(&rt.f, opts.rtadvd_conf, 0644, err,
		    sizeof(err)) == -1)
			error = errno != 0 ? errno : EIO;
		else if ((t = made_new(&m, &nm, &cap)) == NULL)
			error = ENOMEM;
		else {
			t->kind = M_RTADV;
			t->ifname = "rtadvd";
		}
	}
	/* rc.conf when more than what is made live alone changes. */
	if (error == 0 && nm > nlive)
		error = rca_write(&x, req, err, sizeof(err));
	if (error != 0) {
		if (error != EEXIST && err[0] != '\0')
			(void)cbl_req_set_yerr(req, err, 0);
		if (opened)
			rca_close(&x);
		if (rt.read)
			vc_cap_free(&rt.f);
		free(m);
		work_free(&w);
		cbl_yarena_free(ya);
		return (error);
	}
	/* The kernel; failing, what was made undone, the files back. */
	for (size_t k = 0; k < nm; k++) {
		struct made *t = &m[k];
		struct if_change ch = { 0, NULL, -1, -1, NULL };

		switch (t->kind) {
		case M_DESCR:
			ch.descr = t->ad.ip;
			error = do_if_set(&w, t->ifname, &ch, false, &e);
			break;
		case M_ADDR:
			error = live_addr(&w, t->ifname, &t->ad, t->add, &e);
			break;
		case M_STATE:
			error = do_if_state(&w, t->ifname, t->add, &e);
			break;
		case M_MTU:
			ch.mtu = t->mtu;
			error = do_if_set(&w, t->ifname, &ch, false, &e);
			break;
		case M_CREATE: {
			struct arc_job_spec	 cs;
			const char		*got;

			spec_of(t->entry, &cs);
			error = do_if_create(&w, &cs, &got, &e);
			break;
		}
		case M_DESTROY:
			error = do_if_destroy(&w, t->ifname, false, &e);
			break;
		case M_FIB:
			ch.fib = t->fib;
			error = do_if_set(&w, t->ifname, &ch, false, &e);
			break;
		case M_RTADV:
			error = rtadvd_again(&w, &x, &e);
			break;
		case M_LNE:
			/* RFC 8530 section 3.1: lne-assignment-failed. */
			if ((error = lne_move(&w, req, t->ifname, t->was_lne,
			    t->lne, &e)) != 0) {
				(void)cbl_req_set_yapptag(req,
				    "lne-assignment-failed");
				error = EIO;
			}
			break;
		}
		if (error == 0)
			continue;
		(void)snprintf(err, sizeof(err), "%s: %s", t->ifname, e != NULL ?
		    e : strerror(error));
		while (k-- > 0) {
			const char *ue = NULL;

			t = &m[k];
			ch.descr = t->kind == M_DESCR ? t->was : NULL;
			ch.mtu = t->kind == M_MTU ? t->was_mtu : 0;
			ch.fib = t->kind == M_FIB ? t->was_fib : -1;
			if ((t->kind == M_LNE && lne_move(&w, NULL, t->ifname,
			    t->lne, t->was_lne, &ue) != 0) ||
			    (t->kind == M_FIB && do_if_set(&w, t->ifname, &ch,
			    false, &ue) != 0) || (t->kind == M_CREATE &&
			    do_if_destroy(&w,
			    t->ifname, false, &ue) != 0) || (t->kind ==
			    M_DESTROY && remake(&w, t->entry, &ue) != 0) ||
			    ((t->kind == M_DESCR || t->kind == M_MTU) &&
			    do_if_set(&w, t->ifname, &ch, false, &ue) != 0) ||
			    (t->kind == M_ADDR &&
			    live_addr(&w, t->ifname, &t->ad, !t->add, &ue) !=
			    0) || (t->kind == M_STATE && do_if_state(&w,
			    t->ifname, !t->add, &ue) != 0))
				logmsg(LOG_ERR, "interfaces: undoing on %s "
				    "failed: %s", t->ifname, ue != NULL ? ue :
				    "?");
		}
		rca_undo(&x);
		/* rtadvd.conf back, read again by rtadvd. */
		if (rt.changed) {
			const char *ue = NULL;

			(void)rtadvd_again(&w, &x, &ue);
		}
		(void)cbl_req_set_yerr(req, err, 0);
		logmsg(LOG_WARNING, "interfaces: %s: rc.conf as it was", err);
		error = error > 0 ? error : EIO;
		break;
	}
	/* Bound by it: told when the jail goes (lneroot.c). */
	for (size_t k = 0; error == 0 && k < nm; k++)
		if (m[k].kind == M_LNE)
			lne_bound(m[k].ifname, m[k].lne, m[k].lne != NULL);
	rca_close(&x);
	if (rt.read)
		vc_cap_free(&rt.f);
	free(m);
	work_free(&w);
	cbl_yarena_free(ya);
	return (error);
}
