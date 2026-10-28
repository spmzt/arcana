/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An interface of the host given to a jail that has a network of its
 * own, or taken back from it: ifconfig(8) vnet and -vnet.  What is kept
 * is kept where jail(8) reads it, as vnet.interface of the jail in
 * jail.conf, so the jail has the interface again when it next starts.
 */

#include <stdio.h>
#include <string.h>

#include <jailconf.h>

#include "agent.h"

static int
move(struct work *w, const char *ifname, int jid, bool back,
    const char **errp)
{
	struct execres	 res;
	char		*argv[5];

	argv[0] = (char *)(uintptr_t)opts.ifconfig_bin;
	argv[1] = (char *)(uintptr_t)ifname;
	argv[2] = (char *)(uintptr_t)(back ? "-vnet" : "vnet");
	argv[3] = wfmt(w, "%d", jid);
	argv[4] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ifconfig"));
		return (-1);
	}
	return (0);
}

int
do_if_vnet(struct work *w, const char *ifname, const char *jail, bool back,
    bool persist, const char **errp)
{
	struct cconf		 conf;
	const struct cjail	*cj;
	const struct arc_param	*p;
	struct jc_conf		 jc;
	struct jc_file		*f;
	struct jc_block		*b;
	const char		*e;
	char			*newbuf, ebuf[512];
	size_t			 newlen, i;
	bool			 inside, edit, has;
	int			 jid, rc;

	/* The jail runs, with a network of its own: jls says so. */
	if (scope_enter(w, jail, errp) != 0)
		return (-1);
	jid = w->jid;
	inside = if_exists(w, ifname);
	/* The rest is the host's own doing. */
	w->jail = NULL;
	w->jid = 0;
	w->jroot = NULL;
	if (back && !inside) {
		*errp = wfmt(w, "the jail %s has no interface %s", jail, ifname);
		return (-1);
	}
	if (!back && !if_exists(w, ifname)) {
		*errp = inside ? wfmt(w, "the jail %s has %s already", jail,
		    ifname) : wfmt(w, "the host has no interface %s", ifname);
		return (-1);
	}

	rc = -1;
	edit = false;
	newbuf = NULL;
	newlen = 0;
	f = NULL;
	cj = NULL;
	memset(&jc, 0, sizeof(jc));
	if (persist) {
		conf_read(w, &conf);
		if ((cj = conf_jail(&conf, jail)) == NULL) {
			*errp = wfmt(w, "the jail %s is not defined in any "
			    "jail.conf: there is nowhere to keep it", jail);
			return (-1);
		}
		if (jc_load(&jc, cj->scope) == -1 || (b = jc_find(&jc, jail,
		    &f)) == NULL) {
			*errp = wfmt(w, "cannot find the block of the jail %s "
			    "in %s%s%s", jail, cj->scope, jc.error != NULL ?
			    ": " : "", jc.error != NULL ? jc.error : "");
			goto out;
		}
		/* What jail(8) reads there already stays as it is written. */
		p = cjail_param(cj, "vnet.interface");
		has = false;
		for (i = 0; p != NULL && i < p->values.n; i++)
			if (strcmp(p->values.v[i], ifname) == 0)
				has = true;
		if (has == back) {
			if (jc_edit(f, b, "vnet.interface", ifname, !back,
			    p != NULL ? p->values.v : NULL, p != NULL ?
			    p->values.n : 0, &newbuf, &newlen, ebuf,
			    sizeof(ebuf)) == -1) {
				*errp = wtext(w, wstrdup(w, ebuf));
				goto out;
			}
			wadopt(w, newbuf);
			if (!jc_verify(f->path, newbuf, newlen, jail,
			    "vnet.interface", ifname, !back)) {
				*errp = "the edited jail.conf does not check "
				    "out; nothing was changed";
				goto out;
			}
			edit = true;
		}
	}
	if (move(w, ifname, jid, back, errp) != 0)
		goto out;
	if (edit) {
		if (write_backup(w, f->path, f->buf, f->len, errp) == -1 ||
		    jc_write(f->path, newbuf, newlen, ebuf, sizeof(ebuf)) ==
		    -1) {
			if (*errp == NULL)
				*errp = wtext(w, wstrdup(w, ebuf));
			(void)move(w, ifname, jid, !back, &e);
			goto out;
		}
		if (!verify_jail8(w, cj->scope, jail, "vnet.interface", ifname,
		    !back)) {
			(void)jc_write(f->path, f->buf, f->len, ebuf,
			    sizeof(ebuf));
			(void)move(w, ifname, jid, !back, &e);
			*errp = wfmt(w, "jail(8) does not read the edited %s as "
			    "intended; the previous version is back", f->path);
			goto out;
		}
	}
	rc = 0;
out:
	jc_free(&jc);
	return (rc);
}
