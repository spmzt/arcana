/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: FreeBSD's FIBs as RFC 8529's network instances (PLAN-SDN-YANG
 * 2.6.1, docs/notes/rfc8529.md).  The kernel makes net.fibs FIBs at boot
 * (a vnet jail its own), numbered from 0, and none after; FIB 0 is the
 * host's, ietf-routing's at the top, and each other one an instance, a
 * VRF (arcana-network-instance: the fib case, the vrf-root root).
 *
 * A FIB has no name.  Arcana keeps the names, and the descriptions, in
 * fibs.conf, sh(1) assignments as rc.conf's (libvarconf):
 *
 *	fib2_name="blue"
 *	fib2_description="the blue customer's"
 *
 * A FIB not named there is fibN.  A name is one no other instance has,
 * of printable characters; one of the form fibM is FIB M's alone.  What
 * the file has that cannot be read so is said, not guessed: the
 * variable and why.
 *
 * An instance asked for past the last FIB grows them (2.6.4): net.fibs
 * raised live, as the kernel allows (route_tables.c's sysctl_fibs: more,
 * never fewer), and kept in loader.conf for the next boot, where the
 * kernel makes them; a kernel that will not grow them live gets them
 * at the next boot: a reboot is required, and the caller is told.
 *
 * An interface is bound to the instance whose FIB is its own (ifconfig
 * fib, SIOCSIFFIB, PLAN-SDN-YANG 2.6.3), none in FIB 0, the host's; so
 * are its addresses, of both families: FreeBSD binds an interface, not
 * an address family, and refuses a family bound apart.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include <net/if.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cbl_schema.h"
#include "collect.h"
#include "varconf.h"

typedef struct ietf_network_instance_network_instances_network_instance
    yni;

#define	RT_MAXFIBS	65535		/* the kernel's, route_var.h */
#define	NI_TYPE(x)	IETF_NETWORK_INSTANCE_NETWORK_INSTANCES_NETWORK_INSTANCE_NI_TYPE_##x
#define	ROOT_TYPE(x)	IETF_NETWORK_INSTANCE_NETWORK_INSTANCES_NETWORK_INSTANCE_ROOT_TYPE_##x

static const struct ietf_network_instance_network_instances_network_instance_vrf_root
    vrf_root;

static char *
astrdup(cbl_yarena *a, const char *s)
{
	size_t len = strlen(s) + 1;
	char *p;

	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, s, len);
	return (p);
}

/* net.fibs: how many FIBs the kernel has, this vnet's. */
int
yni_nfibs(void)
{
	int n;
	size_t len = sizeof(n);

	if (sysctlbyname("net.fibs", &n, &len, NULL, 0) == -1)
		return (-1);
	return (n);
}

/* fibM: FIB M's name, M; else -1. */
static long
fib_form(const char *name)
{
	char *end;
	long n;

	if (strncmp(name, "fib", 3) != 0 || !isdigit((unsigned char)name[3]) ||
	    (name[3] == '0' && name[4] != '\0'))
		return (-1);
	n = strtol(name + 3, &end, 10);
	return (*end == '\0' && n >= 0 && n <= 65535 ? n : -1);
}

/* Why name cannot be FIB fib's; NULL: it can. */
static const char *
bad_name(const char *name, int fib)
{
	long m;

	if (name[0] == '\0')
		return ("an empty name");
	for (const char *p = name; *p != '\0'; p++)
		if (!isprint((unsigned char)*p))
			return ("a name of other than printable characters");
	if ((m = fib_form(name)) != -1 && m != fib)
		return ("another FIB's name");
	return (NULL);
}

static int
unread(cbl_yarena *a, struct yunread **u, size_t *nu, const char *var,
    const char *why)
{
	struct yunread *nv;

	if ((nv = cbl_yarena_alloc(a, (*nu + 1) * sizeof(*nv))) == NULL)
		return (ENOMEM);
	if (*nu > 0)
		memcpy(nv, *u, *nu * sizeof(*nv));
	nv[*nu].var = astrdup(a, var);
	nv[*nu].why = why;
	*u = nv;
	(*nu)++;
	return (0);
}

/* FIB n's variable v: its value, or NULL, what is wrong said. */
static const char *
var(const struct vc_file *f, int n, const char *v, cbl_yarena *a,
    struct yunread **u, size_t *nu, int *error)
{
	const struct vc_assign *as;
	char name[32];

	snprintf(name, sizeof(name), "fib%d_%s", n, v);
	if (f == NULL || (as = vc_get(f, name)) == NULL)
		return (NULL);
	if (!vc_settled(f, name) || as->value == NULL) {
		*error = unread(a, u, nu, name,
		    "not settled by reading the file");
		return (NULL);
	}
	return (as->value);
}

int
yni_read(const struct vc_file *f, int nfibs, cbl_yarena *a,
    const struct ietf_network_instance_network_instances **out,
    struct yunread **u, size_t *nu)
{
	struct ietf_network_instance_network_instances *nis;
	yni *v;
	size_t n = 0;
	int error = 0;

	*out = NULL;
	*u = NULL;
	*nu = 0;
	if ((nis = cbl_yarena_alloc(a, sizeof(*nis))) == NULL)
		return (ENOMEM);
	memset(nis, 0, sizeof(*nis));
	if (nfibs > 1 && (v = cbl_yarena_alloc(a, (size_t)(nfibs - 1) *
	    sizeof(*v))) == NULL)
		return (ENOMEM);
	for (int fib = 1; fib < nfibs && error == 0; fib++) {
		const char *name, *why, *desc;
		char def[16], vname[32];

		memset(&v[n], 0, sizeof(v[n]));
		snprintf(def, sizeof(def), "fib%d", fib);
		snprintf(vname, sizeof(vname), "fib%d_name", fib);
		name = var(f, fib, "name", a, u, nu, &error);
		if (name != NULL && (why = bad_name(name, fib)) != NULL) {
			error = unread(a, u, nu, vname, why);
			name = NULL;
		}
		/* Taken by one before it: this one is fibN. */
		for (size_t k = 0; name != NULL && k < n; k++)
			if (strcmp(v[k].name, name) == 0) {
				error = unread(a, u, nu, vname,
				    "another FIB's name");
				name = NULL;
			}
		v[n].name = astrdup(a, name != NULL ? name : def);
		v[n].has_enabled = true;
		v[n].enabled = true;
		if ((desc = var(f, fib, "description", a, u, nu, &error)) !=
		    NULL)
			v[n].description = astrdup(a, desc);
		v[n].ni_type = NI_TYPE(FIB);
		v[n].has_arcni_fib = true;
		v[n].arcni_fib = (uint16_t)fib;
		v[n].root_type = ROOT_TYPE(VRF_ROOT);
		v[n].vrf_root = &vrf_root;
		n++;
	}
	if (error != 0)
		return (error);
	/* Names for FIBs there are not. */
	for (size_t i = 0; f != NULL && i < f->na; i++) {
		const char *nm = f->a[i].name;
		char *end;
		long fib;

		if (strncmp(nm, "fib", 3) != 0)
			continue;
		fib = strtol(nm + 3, &end, 10);
		if (end == nm + 3 || (strcmp(end, "_name") != 0 &&
		    strcmp(end, "_description") != 0))
			continue;
		if (fib == 0)
			error = unread(a, u, nu, nm, "FIB 0 is the host's, "
			    "not an instance");
		else if (fib >= nfibs)
			error = unread(a, u, nu, nm, "no such FIB: net.fibs "
			    "is fewer");
		if (error != 0)
			return (error);
	}
	nis->network_instance.n = n;
	nis->network_instance.v = n > 0 ? v : NULL;
	*out = nis;
	return (0);
}

/* What ni cannot be, said in err; the FIBs below nfibs. */
static int
check(const struct ietf_network_instance_network_instances *ni, int nfibs,
    char *err, size_t errlen)
{
	size_t n = ni != NULL ? ni->network_instance.n : 0;
	const yni *v = n > 0 ? ni->network_instance.v : NULL;

	for (size_t i = 0; i < n; i++) {
		const char *why;

		if (v[i].ni_type != NI_TYPE(FIB) || !v[i].has_arcni_fib) {
			snprintf(err, errlen, "%s: no FIB", v[i].name);
			return (-1);
		}
		if (v[i].arcni_fib >= RT_MAXFIBS) {
			snprintf(err, errlen, "%s: FIB %u, the kernel has at "
			    "most %d", v[i].name, v[i].arcni_fib, RT_MAXFIBS);
			return (-1);
		}
		if (v[i].arcni_fib >= nfibs) {
			snprintf(err, errlen, "%s: FIB %u, net.fibs is %d",
			    v[i].name, v[i].arcni_fib, nfibs);
			return (-1);
		}
		if (v[i].has_enabled && !v[i].enabled) {
			snprintf(err, errlen, "%s: a FIB cannot be disabled",
			    v[i].name);
			return (-1);
		}
		if ((why = bad_name(v[i].name, v[i].arcni_fib)) != NULL) {
			snprintf(err, errlen, "%s: %s", v[i].name, why);
			return (-1);
		}
		for (size_t k = 0; k < i; k++)
			if (v[k].arcni_fib == v[i].arcni_fib) {
				snprintf(err, errlen, "%s, %s: FIB %u twice",
				    v[k].name, v[i].name, v[i].arcni_fib);
				return (-1);
			}
	}
	return (0);
}

/*
 * The FIBs ni asks for, net.fibs raised to them: live (sysctl), and in
 * loader.conf lf, unless it has as many already.  *nfibs: as many as
 * there are now, or will be; *reboot: not live, at the next boot.
 */
int
yni_grow(struct vc_file *lf, int *nfibs,
    const struct ietf_network_instance_network_instances *ni, bool *reboot,
    char *err, size_t errlen)
{
	const struct vc_assign *as;
	unsigned int want = (unsigned int)*nfibs;
	char num[16];

	*reboot = false;
	/* Nothing grown for what is refused after. */
	if (check(ni, RT_MAXFIBS, err, errlen) != 0)
		return (EINVAL);
	for (size_t i = 0; ni != NULL && i < ni->network_instance.n; i++)
		if (ni->network_instance.v[i].has_arcni_fib &&
		    ni->network_instance.v[i].arcni_fib >= want)
			want = ni->network_instance.v[i].arcni_fib + 1u;
	if (want <= (unsigned int)*nfibs)
		return (0);
	/* Kept first: a live raise cannot be taken back. */
	if ((as = vc_get(lf, "net.fibs")) != NULL && !vc_settled(lf,
	    "net.fibs")) {
		snprintf(err, errlen, "loader.conf's net.fibs: not settled by "
		    "reading the file");
		return (EINVAL);
	}
	if (as == NULL || as->value == NULL ||
	    strtoul(as->value, NULL, 10) < want) {
		snprintf(num, sizeof(num), "%u", want);
		if (vc_set(lf, "net.fibs", num, err, errlen) == -1)
			return (errno);
	}
	if (sysctlbyname("net.fibs", NULL, NULL, &want, sizeof(want)) == -1)
		*reboot = true;
	*nfibs = (int)want;
	return (0);
}

/*
 * ni's names and descriptions into fibs.conf f: each instance's FIB its
 * fib leaf's, below nfibs; the name fibN, or none, the variable taken
 * out.  Refused, nothing changed: what cannot be.
 */
int
yni_write(struct vc_file *f, int nfibs,
    const struct ietf_network_instance_network_instances *ni, char *err,
    size_t errlen)
{
	size_t n = ni != NULL ? ni->network_instance.n : 0;
	const yni *v = n > 0 ? ni->network_instance.v : NULL;

	if (check(ni, nfibs, err, errlen) != 0)
		return (EINVAL);
	for (int fib = 1; fib < nfibs; fib++) {
		const yni *e = NULL;
		char name[32], def[16];

		for (size_t i = 0; i < n && e == NULL; i++)
			if (v[i].arcni_fib == fib)
				e = &v[i];
		snprintf(def, sizeof(def), "fib%d", fib);
		snprintf(name, sizeof(name), "fib%d_name", fib);
		if (e != NULL && strcmp(e->name, def) != 0) {
			if (vc_set(f, name, e->name, err, errlen) == -1)
				return (errno);
		} else if (vc_unset(f, name, err, errlen) == -1)
			return (errno);
		snprintf(name, sizeof(name), "fib%d_description", fib);
		if (e != NULL && e->description != NULL) {
			if (vc_set(f, name, e->description, err, errlen) == -1)
				return (errno);
		} else if (vc_unset(f, name, err, errlen) == -1)
			return (errno);
	}
	return (0);
}

typedef struct ietf_interfaces_interfaces_interface yif;
typedef struct ietf_network_instance_bind_ni_name_failed yfailed;

/* The FIB of the instance named name; -1: none such. */
int
yni_fib(const struct ietf_network_instance_network_instances *ni,
    const char *name)
{

	for (size_t i = 0; ni != NULL && i < ni->network_instance.n; i++)
		if (strcmp(ni->network_instance.v[i].name, name) == 0)
			return (ni->network_instance.v[i].arcni_fib);
	return (-1);
}

static const char *
name_of(const struct ietf_network_instance_network_instances *ni, int fib)
{

	for (size_t i = 0; ni != NULL && i < ni->network_instance.n; i++)
		if (ni->network_instance.v[i].arcni_fib == fib)
			return (ni->network_instance.v[i].name);
	return (NULL);
}

int
yni_bind(yif *v, size_t n,
    const struct ietf_network_instance_network_instances *ni, cbl_yarena *a)
{
	struct ifreq ifr;
	int s;

	if ((s = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		return (errno);
	for (size_t i = 0; i < n; i++) {
		const char *name;

		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, v[i].name, sizeof(ifr.ifr_name));
		if (ioctl(s, SIOCGIFFIB, &ifr) != 0 || ifr.ifr_fib == 0 ||
		    (name = name_of(ni, (int)ifr.ifr_fib)) == NULL)
			continue;
		v[i].ni_bind_ni_name = name;
		if (v[i].ip_ipv4 != NULL) {
			struct ietf_interfaces_interfaces_interface_ip_ipv4 *c;

			if ((c = cbl_yarena_alloc(a, sizeof(*c))) == NULL) {
				close(s);
				return (ENOMEM);
			}
			*c = *v[i].ip_ipv4;
			c->ni_bind_ni_name = name;
			v[i].ip_ipv4 = c;
		}
		if (v[i].ip_ipv6 != NULL) {
			struct ietf_interfaces_interfaces_interface_ip_ipv6 *c;

			if ((c = cbl_yarena_alloc(a, sizeof(*c))) == NULL) {
				close(s);
				return (ENOMEM);
			}
			*c = *v[i].ip_ipv6;
			c->ni_bind_ni_name = name;
			v[i].ip_ipv6 = c;
		}
	}
	close(s);
	return (0);
}

/*
 * rc.conf's ifconfig_<if>, the word pair "fib N" in it made fib's: set,
 * or, for 0, taken out (the variable too, were it nothing else); the
 * other words as they were.  rc.conf names an interface with '.', '-',
 * '/' and '+' made '_', as network.subr's ifconfig_up does.
 */
int
yni_rc_fib(struct vc_file *f, const char *ifname, int fib, char *err,
    size_t errlen)
{
	char var[IFNAMSIZ + 16], val[1024], *p, *w, *copy;
	const struct vc_assign *as;
	bool done = false;
	size_t len = 0;

	snprintf(var, sizeof(var), "ifconfig_%s", ifname);
	for (p = var + strlen("ifconfig_"); *p != '\0'; p++)
		if (strchr(".-/+", *p) != NULL)
			*p = '_';
	val[0] = '\0';
	if ((as = vc_get(f, var)) != NULL) {
		if (!vc_settled(f, var) || as->value == NULL) {
			snprintf(err, errlen, "%s: not settled by reading the "
			    "file", var);
			errno = EINVAL;
			return (-1);
		}
		if ((copy = strdup(as->value)) == NULL)
			return (-1);
		/* The words, "fib N" replaced or dropped. */
		for (p = copy; (w = strsep(&p, " \t")) != NULL;) {
			const char *put = w;
			char num[16];

			if (*w == '\0')
				continue;
			if (strcmp(w, "fib") == 0) {
				while (p != NULL && (*p == ' ' || *p == '\t'))
					p++;
				(void)strsep(&p, " \t");
				if (fib == 0 || done)
					continue;
				snprintf(num, sizeof(num), "fib %d", fib);
				put = num;
				done = true;
			}
			len = strlcat(val, len > 0 ? " " : "", sizeof(val));
			len = strlcat(val, put, sizeof(val));
		}
		free(copy);
	}
	if (fib != 0 && !done) {
		char num[16];

		snprintf(num, sizeof(num), "fib %d", fib);
		len = strlcat(val, len > 0 ? " " : "", sizeof(val));
		len = strlcat(val, num, sizeof(val));
	}
	if (len >= sizeof(val)) {
		snprintf(err, errlen, "%s: too long", var);
		errno = EINVAL;
		return (-1);
	}
	if (val[0] == '\0')
		return (as != NULL ? vc_unset(f, var, err, errlen) : 0);
	return (vc_set(f, var, val, err, errlen));
}

static int
failed(cbl_yarena *a, const char *ifname, const char *name,
    const char *why, const yfailed **out)
{
	struct ietf_network_instance_bind_ni_name_failed_interface *i;
	yfailed *fl;

	if ((fl = cbl_yarena_alloc(a, sizeof(*fl))) == NULL ||
	    (i = cbl_yarena_alloc(a, sizeof(*i))) == NULL)
		return (ENOMEM);
	memset(fl, 0, sizeof(*fl));
	i->bind_ni_name = astrdup(a, name);
	fl->name = astrdup(a, ifname);
	fl->interface = i;
	fl->error_info = astrdup(a, why);
	*out = fl;
	return (0);
}

/*
 * Interface ifname bound to the instance named name ("" or NULL: none,
 * FIB 0), by SIOCSIFFIB, and kept in rc.conf f if f is not NULL; v4 and
 * v6, its address families' bind-ni-name if given, are name too.  What
 * cannot be done: 0, *fail the bind-ni-name-failed notification
 * (RFC 8529) saying why, nothing changed.
 */
int
yni_bind_apply(const char *ifname, const char *name, const char *v4,
    const char *v6, const struct ietf_network_instance_network_instances *ni,
    struct vc_file *f, cbl_yarena *a, const yfailed **fail)
{
	struct ifreq ifr;
	char why[256];
	int fib = 0, s, old;

	*fail = NULL;
	if (name == NULL)
		name = "";
	if ((v4 != NULL && strcmp(v4, name) != 0) ||
	    (v6 != NULL && strcmp(v6, name) != 0))
		return (failed(a, ifname, name, "FreeBSD binds an interface, "
		    "both its address families, not one alone", fail));
	if (name[0] != '\0' && (fib = yni_fib(ni, name)) == -1)
		return (failed(a, ifname, name, "no such network instance",
		    fail));
	memset(&ifr, 0, sizeof(ifr));
	if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)) >=
	    sizeof(ifr.ifr_name))
		return (failed(a, ifname, name, "no such interface", fail));
	if ((s = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		return (errno);
	if (ioctl(s, SIOCGIFFIB, &ifr) == -1) {
		snprintf(why, sizeof(why), "%s", errno == ENXIO ?
		    "no such interface" : strerror(errno));
		close(s);
		return (failed(a, ifname, name, why, fail));
	}
	old = ifr.ifr_fib;
	ifr.ifr_fib = fib;
	if (ioctl(s, SIOCSIFFIB, &ifr) == -1) {
		snprintf(why, sizeof(why), "SIOCSIFFIB: %s", strerror(errno));
		close(s);
		return (failed(a, ifname, name, why, fail));
	}
	/* Kept; else the kernel's undone. */
	if (f != NULL && yni_rc_fib(f, ifname, fib, why, sizeof(why)) == -1) {
		ifr.ifr_fib = old;
		(void)ioctl(s, SIOCSIFFIB, &ifr);
		close(s);
		return (failed(a, ifname, name, why, fail));
	}
	close(s);
	return (0);
}
