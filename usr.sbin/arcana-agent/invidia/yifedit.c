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
 * A commit changes, of an interface there already, its description,
 * whether it is enabled, its IPv4 MTU (the link's), and its static IPv4
 * and IPv6 addresses; what else the tree changes is refused as not
 * supported yet.  Each is
 * written to Arcana's rc.conf file as rc.d/netif reads it (rcarcana.c's
 * rules), then made the kernel's; failing, what was made is undone and
 * the files put back.
 *
 *	description	ifconfig_<if>_descr
 *	enabled		"down" on ifconfig_<if>, or "up"
 *	ipv4 mtu	"mtu N" on ifconfig_<if>
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

/* An address of either family, as the kernel and rc.conf take it. */
struct addr {
	int		 af;
	const char	*ip;
	int		 plen;
	union {
		struct in_addr	 v4;
		struct in6_addr	 v6;
	}		 bin;
};

static bool
addr_of(int af, const char *ip, bool has, uint8_t plen, struct addr *x)
{

	x->af = af;
	x->ip = ip;
	x->plen = has ? plen : (af == AF_INET ? 32 : 128);
	return (ip != NULL && inet_pton(af, ip, &x->bin) == 1);
}

static bool
addr_in(const struct addr *v, size_t n, const struct addr *x)
{

	for (size_t i = 0; i < n; i++)
		if (v[i].af == x->af && v[i].plen == x->plen &&
		    memcmp(&v[i].bin, &x->bin, x->af == AF_INET ?
		    sizeof(struct in_addr) : sizeof(struct in6_addr)) == 0)
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

		if (x->arcif_peer != NULL || !addr_of(AF_INET, x->ip,
		    x->has_prefix_length, x->prefix_length, &v[n])) {
			free(v);
			return (EOPNOTSUPP);
		}
		n++;
	}
	for (size_t i = 0; e != NULL && e->ip_ipv6 != NULL &&
	    i < e->ip_ipv6->address.n; i++) {
		const yv6 *x = &e->ip_ipv6->address.v[i];

		if (x->arcif_peer != NULL || !addr_of(AF_INET6, x->ip,
		    x->has_prefix_length, x->prefix_length, &v[n])) {
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
	/* A container of addresses alone: as none (the first address
	 * makes it, the last one's going takes it). */
	if (x.ip_ipv4 != NULL) {
		p4 = *x.ip_ipv4;
		p4.address.n = 0;
		p4.address.v = NULL;
		p4.has_mtu = false;
		p4.mtu = 0;
		x.ip_ipv4 = memcmp(&p4, &(yip4){ 0 }, sizeof(p4)) == 0 ? NULL :
		    &p4;
	}
	if (x.ip_ipv6 != NULL) {
		p6 = *x.ip_ipv6;
		p6.address.n = 0;
		p6.address.v = NULL;
		p6.has_mtu = false;
		p6.mtu = 0;
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
		    wfmt(w, "%s %s/%d", ad->af == AF_INET ? "inet" : "inet6",
		    ad->ip, ad->plen), err, errlen));
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

/* What was made live, to be undone in the other order. */
struct made {
	enum { M_ADDR, M_STATE, M_DESCR, M_MTU } kind;
	const char	*ifname;
	struct addr	 ad;
	bool		 add;		/* M_ADDR: added; M_STATE: brought up */
	const char	*was;		/* M_DESCR: the description before */
	unsigned	 mtu, was_mtu;	/* M_MTU */
};

static int
live_addr(struct work *w, const char *ifname, const struct addr *ad,
    bool add, const char **errp)
{

	return (ifaddr_change(w, ifname, ad->af, &ad->bin, ad->plen, add,
	    errp));
}

int
ietf_interfaces_interfaces_edit(cbl_req *req,
    const struct ietf_interfaces *before, const struct ietf_interfaces *after)
{
	struct work	 w;
	struct rca	 x;
	struct made	*m = NULL;
	size_t		 nm = 0, cap = 0;
	char		 err[512];
	const char	*e = NULL;
	bool		 opened = false;
	int		 error = 0;

	err[0] = '\0';
	work_init(&w);
	/* What is not supported yet: an interface added or taken away,
	 * or of one, more than this commit changes. */
	for (size_t i = 0; error == 0 && after != NULL && after->interfaces !=
	    NULL && i < after->interfaces->interface.n; i++) {
		const yif *a = &after->interfaces->interface.v[i], *b;
		struct cbl_ybuf b1 = { NULL, 0, 0 }, b2 = { NULL, 0, 0 };

		if ((b = named(before, a->name)) == NULL) {
			(void)snprintf(err, sizeof(err), "%s: an interface "
			    "made by a commit is not supported yet", a->name);
			error = EOPNOTSUPP;
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
		    NULL) {
			(void)snprintf(err, sizeof(err), "%s: an interface taken "
			    "away by a commit is not supported yet",
			    before->interfaces->interface.v[i].name);
			error = EOPNOTSUPP;
		}
	if (error == 0 && (error = rca_open(&x, "netif", err,
	    sizeof(err))) == 0)
		opened = true;
	/* rc.conf first, every interface; then the kernel. */
	for (size_t i = 0; error == 0 && after != NULL && after->interfaces !=
	    NULL && i < after->interfaces->interface.n; i++) {
		const yif *a = &after->interfaces->interface.v[i];
		const yif *b = named(before, a->name);
		const char *ri = rc_ifname(&w, a->name);
		struct addr *va, *vb;
		size_t na, nb;
		bool up_a = !a->has_enabled || a->enabled;
		bool up_b = !b->has_enabled || b->enabled;
		const char *da = a->description != NULL ? a->description : "";
		const char *db = b->description != NULL ? b->description : "";
		/* An MTU only where both say one: none given leaves it.
		 * FreeBSD's IPv4 MTU is the link's (SIOCSIFMTU). */
		bool mtu4 = a->ip_ipv4 != NULL && b->ip_ipv4 != NULL &&
		    a->ip_ipv4->has_mtu && b->ip_ipv4->has_mtu &&
		    a->ip_ipv4->mtu != b->ip_ipv4->mtu;

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
				    "address with a peer, or not one, is not "
				    "supported here yet", a->name);
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
				t->was_mtu = b->ip_ipv4->mtu;
				nm++;
			}
		}
		free(va);
		free(vb);
	}
	if (error == 0 && nm > 0)
		error = rca_write(&x, req, err, sizeof(err));
	if (error != 0) {
		if (error != EEXIST && err[0] != '\0')
			(void)cbl_req_set_yerr(req, err, 0);
		if (opened)
			rca_close(&x);
		free(m);
		work_free(&w);
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
			if (((t->kind == M_DESCR || t->kind == M_MTU) &&
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
		(void)cbl_req_set_yerr(req, err, 0);
		logmsg(LOG_WARNING, "interfaces: %s: rc.conf as it was", err);
		error = error > 0 ? error : EIO;
		break;
	}
	rca_close(&x);
	free(m);
	work_free(&w);
	return (error);
}
