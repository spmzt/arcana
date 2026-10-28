/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>

#include "agent.h"
#include "varconf.h"

static void	split_list(struct work *, const char *, const char *const **,
		    size_t *);

/* "a,b,c" as an array of pool strings. */
static void
split_list(struct work *w, const char *list, const char *const **vp,
    size_t *np)
{
	const char	**v;
	const char	*p, *q;
	size_t		 n;

	*vp = NULL;
	*np = 0;
	if (list == NULL || *list == '\0')
		return;
	for (n = 1, p = list; (p = strchr(p, ',')) != NULL; p++)
		n++;
	v = wcalloc(w, n, sizeof(*v));
	for (n = 0, p = list; ; p = q + 1) {
		if ((q = strchr(p, ',')) == NULL) {
			v[n++] = wtext(w, wstrdup(w, p));
			break;
		}
		v[n++] = wtext(w, wstrndup(w, p, (size_t)(q - p)));
	}
	*vp = v;
	*np = n;
}

/*
 * One jail record.  ji is the running jail or NULL, cj its configuration
 * or NULL.  Runtime values win; configured ones describe stopped jails.
 */
void
jail_record(struct work *w, struct arc_jail *j, const char *name,
    const struct jinfo *ji, const struct cjail *cj)
{
	const struct arc_param	*p;

	memset(j, 0, sizeof(*j));
	j->name = wtext(w, name);
	j->has_state = true;
	if (ji == NULL && cj == NULL) {
		j->state = ARC_JAIL_STATE_ABSENT;
		return;
	}
	j->state = ji == NULL ? ARC_JAIL_STATE_STOPPED : ji->dying ?
	    ARC_JAIL_STATE_DYING : ARC_JAIL_STATE_RUNNING;
	j->has_configured = true;
	j->configured = cj != NULL;
	if (cj != NULL) {
		j->scope = wtext(w, cj->scope);
		j->interface = cjail_param1(cj, "interface");
		j->params.v = cj->params;
		j->params.n = cj->nparams;
	}
	if (ji != NULL) {
		j->has_jid = true;
		j->jid = (uint32_t)ji->jid;
		j->hostname = wtext(w, ji->hostname);
		j->path = wtext(w, ji->path);
		split_list(w, ji->ip4, &j->ip4.v, &j->ip4.n);
		split_list(w, ji->ip6, &j->ip6.v, &j->ip6.n);
		j->has_vnet = true;
		j->vnet = ji->vnet;
		/* A jail's own programs: BIRD or wg in one with a network of
		 * its own, OpenSMTPD in any. */
		if (ji->path != NULL)
			plugins_there(w, ji->jid, ji->path, &j->plugins.v,
			    &j->plugins.n);
		/* Its permissions, as the kernel has them. */
		{
			const char	**names, **live;
			size_t		 nn;
			int		 nl;

			if (jail_allow_names(w, &names, &nn) == 0 && (nl =
			    jail_allow_live(w, ji->jid, names, nn, &live)) > 0) {
				j->allow.v = live;
				j->allow.n = (size_t)nl;
			}
		}
		j->osrelease = wtext(w, ji->osrelease);
		j->has_persist = true;
		j->persist = ji->persist;
		j->has_securelevel = true;
		j->securelevel = ji->securelevel;
		j->has_parent = true;
		j->parent = (uint32_t)ji->parent;
		j->has_children = true;
		j->children = (uint32_t)ji->children;
		j->has_nproc = true;
		j->nproc = ji->nproc;
		j->has_rss_kb = true;
		j->rss_kb = ji->rss_kb;
		j->has_cpu_pct = true;
		/* Hundredths of a percent on the wire (decimal64, 2 digits). */
		j->cpu_pct = (int64_t)(ji->cpu_pct * 100.0);
		return;
	}
	j->hostname = cjail_param1(cj, "host.hostname");
	j->path = cjail_param1(cj, "path");
	if ((p = cjail_param(cj, "ip4.addr")) != NULL) {
		j->ip4.v = p->values.v;
		j->ip4.n = p->values.n;
	}
	if ((p = cjail_param(cj, "ip6.addr")) != NULL) {
		j->ip6.v = p->values.v;
		j->ip6.n = p->values.n;
	}
	p = cjail_param(cj, "vnet");
	j->has_vnet = true;
	j->vnet = p != NULL && (p->values.n == 0 ||
	    strcmp(p->values.v[0], "new") == 0);
	j->has_persist = true;
	j->persist = cjail_param(cj, "persist") != NULL;
}

/* rc.conf's word for on. */
static bool
rc_yes(const char *v)
{

	return (v != NULL && (strcasecmp(v, "yes") == 0 || strcasecmp(v,
	    "true") == 0 || strcasecmp(v, "on") == 0 || strcmp(v, "1") == 0));
}

/* What rc.d/jail starts at boot, read once for every jail asked of. */
void
jail_boot_read(struct work *w, struct jboot *b)
{

	b->on = rc_yes(rc_get(w, "jail_enable"));
	b->list = rc_get(w, "jail_list");
	if (b->list != NULL && b->list[strspn(b->list, " \t")] == '\0')
		b->list = NULL;
}

/*
 * The same from the files rc(8) reads for rc.d/jail (libvarconf), the
 * last that sets each winning: what running has, Arcana's file read
 * after the user's.
 */
void
jail_boot_files(struct work *w, struct jboot *b)
{
	struct vc_file	 f;
	const char	*on = NULL;
	char		**paths, err[256];
	size_t		 n;

	memset(b, 0, sizeof(*b));
	if (vc_rc_files(opts.root != NULL ? opts.root : "", "/usr/local",
	    "jail", "arcana", &paths, &n, err, sizeof(err)) != 0) {
		logmsg(LOG_WARNING, "jail_list: %s", err);
		return;
	}
	for (size_t i = 0; i < n; i++) {
		const struct vc_assign *as;

		if (vc_read(&f, VC_SH, paths[i], err, sizeof(err)) == -1) {
			logmsg(LOG_WARNING, "%s: %s", paths[i], err);
			continue;
		}
		if ((as = vc_get(&f, "jail_enable")) != NULL && as->value != NULL)
			on = wstrdup(w, as->value);
		if ((as = vc_get(&f, "jail_list")) != NULL && as->value != NULL)
			b->list = wstrdup(w, as->value);
		vc_free(&f);
	}
	vc_rc_files_free(paths, n);
	b->on = rc_yes(on);
	if (b->list != NULL && b->list[strspn(b->list, " \t")] == '\0')
		b->list = NULL;
}

/* Is name started at boot: on, and the list empty or naming it? */
bool
jail_boot_of(const struct jboot *b, const char *name)
{
	const char	*p;
	size_t		 n, len;

	if (!b->on)
		return (false);
	if (b->list == NULL)
		return (true);
	len = strlen(name);
	for (p = b->list; *p != '\0'; p += n) {
		p += strspn(p, " \t");
		n = strcspn(p, " \t");
		if (n == len && strncmp(p, name, len) == 0)
			return (true);
	}
	return (false);
}

/*
 * name started at boot, or not, by rc.conf alone.  rc.d/jail starts
 * every jail when jail_list is empty, so neither an emptied list nor
 * jail_enable turned on over one is ever left: the list is made of
 * the jails meant, and with none, jail_enable is off.
 */
int
jail_boot_set(struct work *w, const char *name, bool on,
    const struct cconf *conf, const char **errp)
{
	struct jboot	 b;
	const char	*rest, *p;
	size_t		 i, n, len, words;

	jail_boot_read(w, &b);
	if (on) {
		if (!b.on)
			return (rc_set(w, "jail_list", "=", name, errp) != 0 ||
			    rc_set(w, "jail_enable", "=", "YES", errp) != 0 ?
			    -1 : 0);
		if (jail_boot_of(&b, name))
			return (0);
		return (rc_set(w, "jail_list", "+=", name, errp));
	}
	if (!jail_boot_of(&b, name))
		return (0);
	/* The others the list names, or every other jail defined. */
	rest = "";
	words = 0;
	len = strlen(name);
	if (b.list != NULL) {
		for (p = b.list; *p != '\0'; p += n) {
			p += strspn(p, " \t");
			if ((n = strcspn(p, " \t")) == 0)
				break;
			if (n == len && strncmp(p, name, len) == 0)
				continue;
			rest = wfmt(w, "%s%s%.*s", rest, words > 0 ? " " : "",
			    (int)n, p);
			words++;
		}
	} else
		for (i = 0; i < conf->njails; i++)
			if (strcmp(conf->jails[i].name, name) != 0) {
				rest = wfmt(w, "%s%s%s", rest, words > 0 ? " " :
				    "", conf->jails[i].name);
				words++;
			}
	if (words == 0)
		return (rc_set(w, "jail_enable", "=", "NO", errp));
	return (rc_set(w, "jail_list", "=", rest, errp));
}

/* The jail as it is now: re-read runtime state, use conf for the rest. */
struct arc_jail *
jail_current(struct work *w, const char *name, const struct cconf *conf)
{
	struct arc_jail	*j;
	struct jinfo	*list, *ji;
	const char	*e;
	size_t		 n, i;

	list = NULL;
	n = 0;
	(void)jails_running(w, &list, &n, &e);
	ji = NULL;
	for (i = 0; i < n; i++)
		if (list[i].name != NULL && strcmp(list[i].name, name) == 0)
			ji = &list[i];
	if (ji != NULL)
		jails_procstats(w, ji, 1);
	j = wcalloc(w, 1, sizeof(*j));
	jail_record(w, j, name, ji, conf_jail(conf, name));
	if (j->configured) {
		struct jboot	 b;

		jail_boot_read(w, &b);
		j->has_boot = true;
		j->boot = jail_boot_of(&b, name);
	}
	return (j);
}
