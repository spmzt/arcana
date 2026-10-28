/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the addresses of a jail.  Live they are changed with
 * jail_setv(3) and the SIOC*ADDR ioctls on the jail's interface;
 * persistently through Superbia's edit of the jail's configuration.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jailconf.h"
#include "agent.h"

/*
 * Add or delete an interface alias with SIOCAIFADDR/SIOCDIFADDR (and
 * their _IN6 forms), as ifconfig(8) does.  libifconfig would do this
 * but is internal to the base system and installs no header.
 */
int
ifaddr_change(struct work *w, const char *ifname, int af, const void *addr,
    int plen, bool add, const char **errp)
{
	struct in_aliasreq	 ifra;
	struct in6_aliasreq	 ifra6;
	struct in6_ifreq	 ifr6;
	struct ifreq		 ifr;
	struct sockaddr_in	*sin;
	int			 s, rc, i, step;

	step = step_begin(w, ARC_STEP_KIND_SYSCALL, af == AF_INET ?
	    (add ? "ioctl(SIOCAIFADDR)" : "ioctl(SIOCDIFADDR)") :
	    (add ? "ioctl(SIOCAIFADDR_IN6)" : "ioctl(SIOCDIFADDR_IN6)"),
	    "%s alias on %s", add ? "add" : "remove", ifname);
	if ((s = socket(af, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1) {
		*errp = wfmt(w, "socket: %s", strerror(errno));
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	if (af == AF_INET && add) {
		memset(&ifra, 0, sizeof(ifra));
		strlcpy(ifra.ifra_name, ifname, sizeof(ifra.ifra_name));
		ifra.ifra_addr.sin_len = sizeof(struct sockaddr_in);
		ifra.ifra_addr.sin_family = AF_INET;
		memcpy(&ifra.ifra_addr.sin_addr, addr, sizeof(struct in_addr));
		ifra.ifra_mask.sin_len = sizeof(struct sockaddr_in);
		ifra.ifra_mask.sin_family = AF_INET;
		ifra.ifra_mask.sin_addr.s_addr = htonl(plen == 0 ? 0 :
		    0xffffffffU << (32 - plen));
		rc = ioctl(s, SIOCAIFADDR, &ifra);
	} else if (af == AF_INET) {
		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, addr, sizeof(struct in_addr));
		rc = ioctl(s, SIOCDIFADDR, &ifr);
	} else if (add) {
		memset(&ifra6, 0, sizeof(ifra6));
		strlcpy(ifra6.ifra_name, ifname, sizeof(ifra6.ifra_name));
		ifra6.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
		ifra6.ifra_addr.sin6_family = AF_INET6;
		memcpy(&ifra6.ifra_addr.sin6_addr, addr,
		    sizeof(struct in6_addr));
		ifra6.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
		ifra6.ifra_prefixmask.sin6_family = AF_INET6;
		for (i = 0; i < plen; i++)
			ifra6.ifra_prefixmask.sin6_addr.s6_addr[i / 8] |=
			    (uint8_t)(0x80 >> (i % 8));
		ifra6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
		ifra6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
		rc = ioctl(s, SIOCAIFADDR_IN6, &ifra6);
	} else {
		memset(&ifr6, 0, sizeof(ifr6));
		strlcpy(ifr6.ifr_name, ifname, sizeof(ifr6.ifr_name));
		ifr6.ifr_addr.sin6_len = sizeof(struct sockaddr_in6);
		ifr6.ifr_addr.sin6_family = AF_INET6;
		memcpy(&ifr6.ifr_addr.sin6_addr, addr, sizeof(struct in6_addr));
		rc = ioctl(s, SIOCDIFADDR_IN6, &ifr6);
	}
	if (rc == -1) {
		*errp = wfmt(w, "%s on %s: %s", add ? "add alias" :
		    "remove alias", ifname, strerror(errno));
		step_end(w, step, false, "%s", strerror(errno));
	} else
		step_end(w, step, true, "%s/%d %s %s", af == AF_INET ?
		    "inet" : "inet6", plen, add ? "added to" : "removed from",
		    ifname);
	close(s);
	return (rc);
}

/*
 * Add or remove an IP address: live with jail_setv(3) (and an interface
 * alias when the interface is known), persistently by editing the
 * jail's block, or both.  With dry-run nothing changes; the reply has
 * the plan in its trace and the diff.
 *
 * The edit is planned and checked first, then the running jail changes,
 * then the file is written and read back by jail(8), and restored if
 * jail(8) does not read it as intended.
 */
int
do_address(struct work *w, const struct arc_address_req *rq,
    struct arc_address_rsp *rsp)
{
	struct jailparam	 jp[3];
	struct jc_conf		 jc;
	struct cconf		 conf;
	const struct cjail	*cj;
	const struct arc_param	*vp;
	struct jc_block		*b;
	struct jc_file		*f;
	unsigned char		 addr[sizeof(struct in6_addr)];
	const char		*name, *key, *ifname, *bare, *cur, *nlist;
	const char		*confval, *e;
	char			*newbuf, *s;
	size_t			 newlen;
	bool			 add, running, vnet, aliased, have_jp;
	bool			 live_done;
	int			 af, plen, jid, step;

	name = rq->jail;
	add = !rq->remove;
	rsp->has_ok = true;
	rsp->ok = false;
	memset(jp, 0, sizeof(jp));
	memset(&jc, 0, sizeof(jc));
	newbuf = NULL;
	newlen = 0;
	f = NULL;
	aliased = have_jp = live_done = false;
	cur = "";
	conf_read(w, &conf);
	cj = conf_jail(&conf, name);

	if (!rq->live && !rq->persist) {
		rsp->error = "say live, persist or both";
		goto out;
	}
	if (!jc_addr_split(rq->address, &af, addr, &plen)) {
		rsp->error = wfmt(w, "'%s' is not an IP address",
		    rq->address);
		goto out;
	}
	key = af == AF_INET ? "ip4.addr" : "ip6.addr";
	if (plen < 0)
		plen = af == AF_INET ? 32 : 128;
	/* The kernel's list holds bare addresses, without a prefix. */
	bare = wstrdup(w, rq->address);
	if ((s = strchr(bare, '/')) != NULL)
		*s = '\0';
	ifname = rq->interface != NULL ? rq->interface :
	    cjail_param1(cj, "interface");

	/* vnet jails have their own network stack: ip4.addr does not apply. */
	vp = cjail_param(cj, "vnet");
	if (vp != NULL && (vp->values.n == 0 ||
	    strcmp(vp->values.v[0], "disable") != 0)) {
		rsp->error = wfmt(w, "jail '%s' is a vnet jail; configure "
		    "addresses inside it instead", name);
		goto out;
	}

	if (rq->persist) {
		if (cj == NULL) {
			rsp->error = wfmt(w, "jail '%s' is not defined in "
			    "any jail.conf; nothing to persist to", name);
			goto out;
		}
		step = step_begin(w, ARC_STEP_KIND_LIB, "jc_load(3)",
		    "libjailconf: %s and its includes", cj->scope);
		if (jc_load(&jc, cj->scope) == -1 ||
		    (b = jc_find(&jc, name, &f)) == NULL) {
			rsp->error = wfmt(w, "cannot find the block of jail "
			    "'%s' in %s%s%s", name, cj->scope,
			    jc.error != NULL ? ": " : "",
			    jc.error != NULL ? jc.error : "");
			step_end(w, step, false, "%s", rsp->error);
			goto out;
		}
		step_end(w, step, true, "block '%s' at %s line %d", name,
		    f->path, b->line);
		/* "iface|addr" in the file when the jail has no interface=. */
		confval = add && rq->interface != NULL &&
		    cjail_param(cj, "interface") == NULL ?
		    wfmt(w, "%s|%s", rq->interface, rq->address) :
		    rq->address;
		step = step_begin(w, ARC_STEP_KIND_LIB, "jc_edit(3)",
		    "%s %s %s %s", key, add ? "+=" : "-=", confval, f->path);
		{
			char ebuf[512];

			/* What jail(8) reads of the jail tells what the
			 * block sets from what it inherits. */
			vp = cjail_param(cj, key);
			if (jc_edit(f, b, key, confval, add, vp != NULL ?
			    vp->values.v : NULL, vp != NULL ? vp->values.n : 0,
			    &newbuf, &newlen, ebuf, sizeof(ebuf)) == -1) {
				rsp->error = wtext(w, wstrdup(w, ebuf));
				step_end(w, step, false, "%s", ebuf);
				goto out;
			}
		}
		wadopt(w, newbuf);
		step_end(w, step, true, "%zu -> %zu bytes", f->len, newlen);
		step = step_begin(w, ARC_STEP_KIND_LIB, "jc_verify(3)",
		    "re-parse; block '%s' %s %s", name,
		    add ? "has" : "lacks", bare);
		if (!jc_verify(f->path, newbuf, newlen, name, key, confval,
		    add)) {
			rsp->error = "the edited configuration does not check "
			    "out; nothing was changed";
			step_end(w, step, false, NULL);
			goto out;
		}
		step_end(w, step, true, NULL);
		s = jc_diff(f->path, f->buf, f->len, newbuf, newlen);
		rsp->diff = wtext(w, wadopt(w, s));
	}

	jid = jail_lookup(w, name);
	running = jid >= 0;
	if (rq->live && !running && !rq->persist) {
		rsp->error = wfmt(w, "jail '%s' is not running", name);
		goto out;
	}
	if (rq->live && running) {
		step = step_begin(w, ARC_STEP_KIND_LIB, "jailparam_get(3)",
		    "jid %d: %s, vnet", jid, key);
		have_jp = true;
		if (jailparam_init(&jp[0], "jid") == -1 ||
		    jailparam_init(&jp[1], key) == -1 ||
		    jailparam_init(&jp[2], "vnet") == -1 ||
		    jailparam_import_raw(&jp[0], &jid, sizeof(jid)) == -1 ||
		    jailparam_get(jp, 3, 0) == -1) {
			rsp->error = wfmt(w, "%s", jail_errmsg);
			step_end(w, step, false, "%s", rsp->error);
			goto out;
		}
		cur = wadopt(w, jailparam_export(&jp[1]));
		if (cur == NULL)
			cur = "";
		s = jailparam_export(&jp[2]);
		vnet = s != NULL && (strcmp(s, "new") == 0 ||
		    strcmp(s, "1") == 0);
		free(s);
		step_end(w, step, true, "%s = %s", key,
		    cur != NULL && *cur != '\0' ? cur : "(none)");
		if (vnet) {
			rsp->error = wfmt(w, "jail '%s' has its own network "
			    "stack (vnet); configure addresses inside it",
			    name);
			goto out;
		}
		if (list_has(key, cur, bare) == add) {
			rsp->error = wfmt(w, "%s %s in the running jail's "
			    "%s", bare, add ? "is already" : "is not", key);
			goto out;
		}
		nlist = list_edit(w, key, cur, bare, add);
		if (rq->dry_run) {
			step = step_begin(w, ARC_STEP_KIND_LIB,
			    "jailparam_set(3)", "dry run: would set %s = %s",
			    key, *nlist != '\0' ? nlist : "(none)");
			step_end(w, step, true, NULL);
		} else {
			if (add && ifname != NULL) {
				if (ifaddr_change(w, ifname, af, addr, plen,
				    true, &rsp->error) == -1)
					goto out;
				aliased = true;
			}
			step = step_begin(w, ARC_STEP_KIND_LIB,
			    "jailparam_set(3)", "JAIL_UPDATE %s = %s", key,
			    *nlist != '\0' ? nlist : "(none)");
			/* jailparam_import(3) does not free what
			 * jailparam_get(3) allocated. */
			free(jp[1].jp_value);
			jp[1].jp_value = NULL;
			if ((*nlist == '\0' ?
			    jailparam_import_raw(&jp[1], NULL, 0) :
			    jailparam_import(&jp[1], nlist)) == -1 ||
			    jailparam_set(jp, 2, JAIL_UPDATE) == -1) {
				rsp->error = wfmt(w, "%s", jail_errmsg);
				step_end(w, step, false, "%s", rsp->error);
				if (aliased)
					(void)ifaddr_change(w, ifname, af,
					    addr, plen, false, &e);
				goto out;
			}
			step_end(w, step, true, NULL);
			live_done = true;
			if (!add && ifname != NULL)
				(void)ifaddr_change(w, ifname, af, addr, plen,
				    false, &e);
		}
		if (ifname == NULL) {
			step = step_begin(w, ARC_STEP_KIND_LIB,
			    "interface alias", "skipped: no interface= for "
			    "this jail and none given");
			step_end(w, step, true, NULL);
		}
	} else if (rq->live) {
		step = step_begin(w, ARC_STEP_KIND_LIB, "live change",
		    "skipped: jail is not running");
		step_end(w, step, true, NULL);
	}

	if (rq->persist && !rq->dry_run) {
		if (write_backup(w, f->path, f->buf, f->len,
		    &rsp->error) == -1)
			goto undo;
		step = step_begin(w, ARC_STEP_KIND_LIB, "jc_write(3)",
		    "%s: mkstemp, fsync, rename(2)", f->path);
		{
			char ebuf[512];

			if (jc_write(f->path, newbuf, newlen, ebuf,
			    sizeof(ebuf)) == -1) {
				rsp->error = wtext(w, wstrdup(w, ebuf));
				step_end(w, step, false, "%s", ebuf);
				goto undo;
			}
			step_end(w, step, true, NULL);
			/* jail(8) has the last word on what it now means. */
			if (!verify_jail8(w, cj->scope, name, key,
			    rq->address, add)) {
				step = step_begin(w, ARC_STEP_KIND_LIB,
				    "jc_write(3)", "%s: restore the previous "
				    "version", f->path);
				if (jc_write(f->path, f->buf, f->len, ebuf,
				    sizeof(ebuf)) == 0)
					step_end(w, step, true, NULL);
				else
					step_end(w, step, false, "%s", ebuf);
				rsp->error = wfmt(w, "jail(8) does not read "
				    "the edited %s as intended; the previous "
				    "version is back", f->path);
				goto undo;
			}
		}
		/* Report the jail as it is configured now. */
		conf_read(w, &conf);
	}
	rsp->ok = true;
	goto out;

undo:
	/* The file is as it was: take the live change back as well. */
	if (live_done) {
		step = step_begin(w, ARC_STEP_KIND_LIB, "jailparam_set(3)",
		    "undo: JAIL_UPDATE %s = %s", key, *cur != '\0' ? cur :
		    "(none)");
		free(jp[1].jp_value);
		jp[1].jp_value = NULL;
		jp[1].jp_flags &= ~JP_RAWVALUE;
		if ((*cur == '\0' ? jailparam_import_raw(&jp[1], NULL, 0) :
		    jailparam_import(&jp[1], cur)) == -1 ||
		    jailparam_set(jp, 2, JAIL_UPDATE) == -1) {
			step_end(w, step, false, "%s", jail_errmsg);
			rsp->error = wfmt(w, "%s; the running jail keeps the "
			    "change", rsp->error);
		} else {
			step_end(w, step, true, NULL);
			if (ifname != NULL)
				(void)ifaddr_change(w, ifname, af, addr, plen,
				    !add, &e);
		}
	}

out:
	rsp->result = jail_current(w, name, &conf);
	if (have_jp)
		jailparam_free(jp, 3);
	jc_free(&jc);
	return (0);
}
