/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * SD-WAN: the services the console keeps (sdwan.c of the console), as
 * MEF 70.2 says them.  Overview has the underlays, the edges and the
 * services in tables; Services has one service's parts, each in its
 * own; Document is the whole of it as JSON, checked by the console
 * against the standard before it is kept, its refusals naming the
 * requirement.
 */

#define	_GNU_SOURCE		/* strcasestr(3) */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <math.h>

#include "app.h"

#define	nitems(x)	(sizeof(x) / sizeof((x)[0]))

enum { SD_OVERVIEW, SD_SERVICES, SD_EDGES, SD_PATHS, SD_SECURITY,
    SD_IDENTITIES, SD_DOCUMENT };

#define	PATHS_EVERY_MS	2000	/* the probes read again, on the Paths tab */
#define	MON_BINS	120	/* columns of a monitor chart */
#define	MON_W		600	/* its box */
#define	MON_H		80
#define	MON_KEEP	3600	/* samples kept of a target, as the agent's */
#define	DASH_EVERY_MS	5000	/* and on the dashboard */
#define	SPARK_N		120	/* samples a spark line shows */

static const ucl_object_t *target_of(const char *, const char *);
static bool	 sdwan_modal_service(struct html *);
static const char *csv(const ucl_object_t *, char *, size_t);
static void	 text_field(struct html *, const char *, const char *, const char *,
		    const char *, const char *);
static ucl_object_t *list_of(const char *);
static const ucl_object_t *swvc_shown(void);
static int	 count_change(const char *);
static void	 view_guide(struct html *, bool);
static char	*routes_text(const ucl_object_t *);
static void	 communities_text(const ucl_object_t *, char *, size_t);
static ucl_object_t *communities_of(const char *);
static const ucl_object_t *edge_unlinked(void);
static void	 plan_load(void);
static void	 paths_load(void);
static void	 plan_load(void);
static void	 send(const char *, bool);
static void	 applied_cb(int, const ucl_object_t *, const char *, void *);
static const char *ms(double, char *, size_t);
static void	 view_overview(struct html *);
static void	 view_identities(struct html *);
static const char *host_name(const char *);
static const ucl_object_t *jfind(const ucl_object_t *, const char *,
		    const char *);
static void	 put_str(ucl_object_t *, const char *, const char *);
static void	 put_int(ucl_object_t *, const char *, const char *);
static void	 put_list(ucl_object_t *, const char *, const char *);
static ucl_object_t *merged_from(const ucl_object_t *, const char *const *);
static void	 list_put(ucl_object_t *, const char *, const char *,
		    const char *, ucl_object_t *);

static struct {
	int		 tab;
	ucl_object_t	*doc;		/* /api/sdwan */
	bool		 blocked;	/* the box open waits for something
					 * else first: no button to keep it */
	char		*text;		/* the Document tab's box */
	char		 swvc[72];	/* the service shown */
	char		 error[600];
	char		 note[200];
	bool		 loading, busy;
	ucl_object_t	*plan;		/* /api/sdwan/plan */
	ucl_object_t	*applied;	/* /api/sdwan/apply */
	char		 plan_error[600];
	char		 need_title[128];	/* an install's, for its task */
	double		 plan_at, apply_at;
	bool		 applying;
	ucl_object_t	*paths;		/* sid: /api/servers/<sid>/sdwan data */
	ucl_object_t	*faults;	/* sid: the agent's faults of the day */
	ucl_object_t	*rekeys;	/* /api/sdwan/rekey: the rotations */
	ucl_object_t	*lists;		/* /api/sdwan/lists: the feeds and lists */
	char		 record_filter[80];	/* the record's filter text */
	ucl_object_t	*identities;	/* /api/sdwan/identities */
	ucl_object_t	*audit;		/* /api/sdwan/audit */
	char		 audit_filter[64];
	char		*config;	/* an identity's configuration, shown once */
	char		 config_name[72];
	double		 paths_at;
	int		 mon_span;	/* seconds the monitor charts draw */
	/* The forms: what is edited, and the host's interfaces for a link. */
	char		 edit[80];	/* the id edited, "" for a new one */
	char		 edit2[80];	/* what it belongs to: an end point, a zone */
	char		 link_host[9];
	char		 link_if[32];
	bool		 ep_remote;	/* the end point form: a remote one */
	char		 ucs_kind[8];	/* the underlay form: its tunnel's kind */
	ucl_object_t	*ifs;		/* the link host's interfaces */
	bool		 ifs_loading;
	bool		 show_kept;	/* the Edges tab shows what stays too */
} sd;

/*
 * Identities (SASE-3): who reaches a service from afar, at its remote
 * end points, each with the address the plan gave it and whether it is
 * still authorised; issued here, revoked here.
 */
/*
 * Groups of a remote end point's identities: each a zone (the
 * policies its members get), a pool their addresses come from and the
 * groups its members reach; members of one group reach each other,
 * and two groups neither of which reaches the other are kept apart on
 * the edge.
 */
static void
view_groups(struct html *h)
{
	const ucl_object_t	*s2, *e2, *g, *id, *e;
	ucl_object_iter_t	 sit, eit, git, iit, rit;
	char			 key[300];
	int			 n, members;
	bool			 any_remote;

	h_raw(h, "<div class=\"sd-block sd-groups\"><h3>Groups <small class=\""
	    "dim\">of a remote end point's identities: the zone whose "
	    "policies the members get, the pool their addresses come from, "
	    "and which groups they reach</small><span class=\"pane-actions\">"
	    "<button class=\"ghost small\" data-act=\"sd-group-add\">+ group"
	    "</button></span></h3><table class=\"net sd\"><thead><tr><th>"
	    "Group</th><th>Service</th><th>End point</th><th>Zone</th><th>Pool"
	    "</th><th>Reaches</th><th>Members</th><th></th></tr></thead>"
	    "<tbody>");
	n = 0;
	any_remote = false;
	sit = NULL;
	while ((s2 = ucl_object_iterate(jget(sd.doc, "swvcs"), &sit, true)) !=
	    NULL) {
		eit = NULL;
		while ((e2 = ucl_object_iterate(jget(s2, "end_points"), &eit, true))
		    != NULL) {
			if (jget(e2, "remote") == NULL)
				continue;
			any_remote = true;
			git = NULL;
			while ((g = ucl_object_iterate(jget(jget(e2, "remote"),
			    "groups"), &git, true)) != NULL) {
				n++;
				members = 0;
				iit = NULL;
				while ((id = ucl_object_iterate(jget(jget(e2, "remote"),
				    "identities"), &iit, true)) != NULL)
					if (jstr(id, "group") != NULL && strcmp(jstr(id,
					    "group"), jstr(g, "name")) == 0)
						members++;
				snprintf(key, sizeof(key), "%s|%s|%s", jstr(s2, "id"),
				    jstr(e2, "id"), jstr(g, "name"));
				h_raw(h, "<tr><td><b>");
				h_txt(h, jstr(g, "name"));
				h_raw(h, "</b></td><td>");
				h_txt(h, jstr(s2, "id"));
				h_raw(h, "</td><td class=\"mono\">");
				h_txt(h, jstr(e2, "id"));
				h_raw(h, "</td><td>");
				h_txt(h, jstr(g, "zone"));
				h_raw(h, "</td><td class=\"mono\">");
				if (jstr(g, "pool") != NULL)
					h_txt(h, jstr(g, "pool"));
				else
					h_raw(h, "<span class=\"dim\">the remote's "
					    "prefix</span>");
				h_raw(h, "</td><td>");
				rit = NULL;
				while ((e = ucl_object_iterate(jget(g, "reach"), &rit,
				    true)) != NULL) {
					h_raw(h, "<span class=\"chip\">");
					h_txt(h, ucl_object_tostring_forced(e));
					h_raw(h, "</span> ");
				}
				if (jget(g, "reach") == NULL || ucl_array_size(jget(g,
				    "reach")) == 0)
					h_raw(h, "<span class=\"dim\">its own members"
					    "</span>");
				h_raw(h, "</td><td class=\"num\">");
				h_fmt(h, "%d", members);
				h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" "
				    "data-act=\"sd-group-edit\" title=\"Change it\"");
				h_attr(h, "data-arg", key);
				h_raw(h, ">&#9998;</button><button class=\"icon\" "
				    "data-act=\"sd-group-del\" title=\"Take the group "
				    "away\"");
				h_attr(h, "data-arg", key);
				h_raw(h, ">×</button></td></tr>");
			}
		}
	}
	if (n == 0)
		h_fmt(h, "<tr class=\"empty-row\"><td colspan=\"8\">%s</td></tr>",
		    any_remote ? "No group yet: without one, every identity has "
		    "a zone of its own and reaches every other." : "No group "
		    "yet: a service with a remote end point takes groups of its "
		    "identities.");
	h_raw(h, "</tbody></table></div>");
}

static void
view_identities(struct html *h)
{
	const ucl_object_t	*i;
	ucl_object_iter_t	 it;
	char			 age[32], key[300];
	int			 n;

	h_raw(h, "<div class=\"sd-block\"><h3>Identities <small class=\"dim\">"
	    "who reaches a service from afar: a WireGuard peer each at a "
	    "remote end point, its address the zone's policies apply to</small>"
	    "<span class=\"pane-actions\"><button class=\"ghost small\" "
	    "data-act=\"sd-ident-add\">+ identity</button></span></h3>"
	    "<table class=\"net sd\"><thead><tr><th>Name</th><th>Service</th>"
	    "<th>End point</th><th>Edge</th><th>Zone</th><th>Address</th>"
	    "<th>Issued</th><th>Authorised</th><th>Session</th><th></th></tr>"
	    "</thead><tbody>");
	n = 0;
	it = NULL;
	while (sd.identities != NULL && (i = ucl_object_iterate(jget(
	    sd.identities, "identities"), &it, true)) != NULL) {
		n++;
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(i, "name"));
		h_raw(h, "</b>");
		if (jbool(i, "user"))
			h_raw(h, " <span class=\"dim\">console user</span>");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(i, "swvc"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(i, "end_point"));
		h_raw(h, "</td><td>");
		h_txt(h, host_name(jstr(i, "edge")));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(i, "zone"));
		if (jstr(i, "group") != NULL) {
			h_raw(h, " <span class=\"dim\">· ");
			h_txt(h, jstr(i, "group"));
			h_raw(h, "</span>");
		}
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(i, "address") != NULL ? jstr(i, "address") : "");
		h_raw(h, "</td><td class=\"dim\">");
		if (jint(i, "issued", 0) > 0) {
			fmt_age(age, sizeof(age), (double)jint(i, "issued", 0) * 1000);
			h_txt(h, age);
		} else
			h_raw(h, "by the document");
		h_raw(h, "</td><td>");
		if (!jbool(i, "live"))
			h_raw(h, "<span class=\"warn\">ran out: issue again</span>");
		else if (jint(i, "expires", 0) > 0) {
			fmt_age(age, sizeof(age), (double)jint(i, "expires", 0) * 1000);
			h_raw(h, "until ");
			h_txt(h, age);
		} else
			h_raw(h, "<span class=\"dim\">no end</span>");
		h_raw(h, "</td><td>");
		if (jget(i, "session") == NULL)
			h_raw(h, "<span class=\"dim\">no peer on the edge</span>");
		else if (jint(i, "session.handshake", 0) == 0)
			h_raw(h, "<span class=\"dim\">no handshake yet</span>");
		else {
			char	rx[32], tx[32];

			fmt_age(age, sizeof(age), (double)jint(i, "session.handshake",
			    0) * 1000);
			fmt_bytes(rx, sizeof(rx), (double)jint(i, "session.rx", 0));
			fmt_bytes(tx, sizeof(tx), (double)jint(i, "session.tx", 0));
			h_raw(h, "handshake ");
			h_txt(h, age);
			h_fmt(h, "<br><span class=\"dim\">%s in · %s out", rx, tx);
			if (jstr(i, "session.endpoint") != NULL) {
				h_raw(h, " · from ");
				h_txt(h, jstr(i, "session.endpoint"));
			}
			h_raw(h, "</span>");
		}
		h_raw(h, "</td><td class=\"num\">");
		snprintf(key, sizeof(key), "%s|%s|%s", jstr(i, "swvc"), jstr(i,
		    "end_point"), jstr(i, "name"));
		h_raw(h, "<button class=\"ghost small\" data-act=\"sd-ident-revoke\"");
		h_attr(h, "data-arg", key);
		h_raw(h, ">Revoke</button></td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"10\" class=\"dim\">None yet: a service "
		    "with a remote end point takes identities, issued here or "
		    "written in the document.</td></tr>");
	h_raw(h, "</tbody></table><p class=\"dim\">An identity issued here has "
	    "its key pair made by the console and its configuration shown "
	    "once; a remote end point's <code>reauth</code> is the seconds it "
	    "stays authorised, after which its peer is removed until it is "
	    "issued again; revoked, its peer goes with the apply that follows."
	    "</p></div>");
}

/*
 * The step of Mplify 119's activity flow (§12.1, steps 1 to 13) a change
 * belongs to, by what it makes; the apply runs them in that order, the
 * UNIs enabled last (step 13, R169).
 */
static const char *
step_label(const ucl_object_t *c)
{
	const ucl_object_t	*t, *e;
	ucl_object_iter_t	 it, eit;
	const char		*k;
	bool			 control;

	if ((k = jstr(c, "key")) == NULL)
		return ("");
	if (strcmp(k, "fibs") == 0 || strcmp(k, "forwarding") == 0)
		return ("1 · VRFs");
	if (strcmp(k, "ntp") == 0)
		return ("2 · synchronization");
	if (strncmp(k, "ucs:", 4) == 0)
		return ("3 · UCS UNIs");
	if (strncmp(k, "tvc:", 4) == 0 || strncmp(k, "peer:", 5) == 0)
		return (strstr(k, "/ctvc") != NULL ? "4 · control plane" :
		    "5 · UTVCs");
	if (strncmp(k, "uswekey:", 8) == 0) {
		/* The pair of a control tunnel's interface, or a data one's. */
		control = false;
		it = NULL;
		while (sd.plan != NULL && (t = ucl_object_iterate(jget(sd.plan,
		    "tunnels"), &it, true)) != NULL) {
			eit = NULL;
			while ((e = ucl_object_iterate(jget(t, "ends"), &eit, true))
			    != NULL)
				if (jstr(e, "ifname") != NULL && strcmp(jstr(e,
				    "ifname"), k + 8) == 0 && jbool(t, "control"))
					control = true;
		}
		return (control ? "4 · control plane" : "5 · UTVCs");
	}
	if (strcmp(k, "ipsec") == 0)
		return ("5 · UTVCs");
	if (strncmp(k, "uni:", 4) == 0 || strncmp(k, "rtadvd:", 7) == 0 ||
	    strncmp(k, "dhcp:", 5) == 0)
		return ("6 · SD-WAN UNIs, 13 · enabled");
	if (strncmp(k, "route:", 6) == 0)
		return ("7 · subscriber routing");
	if (strcmp(k, "bird") == 0)
		return ("7 · subscriber routing, 11 · BFD");
	if (strcmp(k, "rules") == 0)
		return ("8 · flows, 9 · zones");
	if (strcmp(k, "steer") == 0)
		return ("10 · policy map");
	if (strcmp(k, "probes") == 0)
		return ("12 · performance monitoring");
	return ("");
}

/* The document changed by a form, sent to be kept. */
static void
doc_send(ucl_object_t *o)
{
	unsigned char	*json;

	json = ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	if (json != NULL)
		send((const char *)json, true);
	free(json);
}

static void
ifs_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	sd.ifs_loading = false;
	if (sd.ifs != NULL)
		ucl_object_unref(sd.ifs);
	sd.ifs = status == 200 && jget(o, "data") != NULL ? ucl_object_copy(
	    jget(o, "data")) : NULL;
}

/* The first address of a family on an interface of the link's host. */
static const char *
link_address(const char *ifn, int af)
{
	const ucl_object_t	*o, *a;
	ucl_object_iter_t	 it, ait;

	it = NULL;
	while (ifn != NULL && (o = ucl_object_iterate(jget(sd.ifs,
	    "interfaces"), &it, true)) != NULL) {
		if (jstr(o, "name") == NULL || strcmp(jstr(o, "name"), ifn) != 0)
			continue;
		ait = NULL;
		while ((a = ucl_object_iterate(jget(o, "addresses"), &ait,
		    true)) != NULL)
			if (jstr(a, "family") != NULL && jstr(a, "address") !=
			    NULL && strcmp(jstr(a, "family"), af == 4 ? "inet" :
			    "inet6") == 0 && strncmp(jstr(a, "address"), "fe80",
			    4) != 0)
				return (jstr(a, "address"));
	}
	return (NULL);
}

/*
 * The interface of the link's host (sd.ifs) that has the address the
 * console reaches its agent at, or NULL: a new address there, or a
 * routing table of its own, may lose the host to the console.
 */
static const char *
way_in_if(const char *sid)
{
	const ucl_object_t	*o, *a;
	ucl_object_iter_t	 it, ait;
	const char		*u, *e;
	char			 host[80];
	int			 i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sid) == 0)
			break;
	if (i == app.nservers || (u = strstr(app.servers[i].uri, "://")) ==
	    NULL)
		return (NULL);
	u += 3;
	if (*u == '[') {
		u++;
		e = strchr(u, ']');
	} else
		e = u + strcspn(u, ":/");
	if (e == NULL || e == u || (size_t)(e - u) >= sizeof(host))
		return (NULL);
	snprintf(host, sizeof(host), "%.*s", (int)(e - u), u);
	it = NULL;
	while ((o = ucl_object_iterate(jget(sd.ifs, "interfaces"), &it,
	    true)) != NULL) {
		ait = NULL;
		while ((a = ucl_object_iterate(jget(o, "addresses"), &ait,
		    true)) != NULL)
			if (jstr(a, "address") != NULL && strcmp(jstr(a,
			    "address"), host) == 0)
				return (jstr(o, "name"));
	}
	return (NULL);
}

/* ---- Reading -------------------------------------------------------- */

static char *
pretty(const ucl_object_t *o)
{
	ucl_object_t	*c;
	char		*s;

	/* The version is said beside the box, not in it. */
	c = ucl_object_copy(o);
	(void)ucl_object_delete_key(c, "version");
	(void)ucl_object_delete_key(c, "changed");
	s = (char *)ucl_object_emit(c, UCL_EMIT_JSON);
	ucl_object_unref(c);
	return (s);
}

static void
doc_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	sd.loading = false;
	if (status != 200) {
		snprintf(sd.error, sizeof(sd.error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
		return;
	}
	if (sd.doc != NULL)
		ucl_object_unref(sd.doc);
	sd.doc = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	free(sd.text);
	sd.text = pretty(sd.doc);
	if (sd.swvc[0] == '\0' || jget(sd.doc, "swvcs") == NULL)
		snprintf(sd.swvc, sizeof(sd.swvc), "%s", jstr(sd.doc,
		    "swvcs.0.id") != NULL ? jstr(sd.doc, "swvcs.0.id") : "");
}

static void	send(const char *, bool);

static void
sd_load(void)
{

	sd.loading = true;
	api("GET", "/api/sdwan", NULL, doc_cb, NULL);
}

void
sdwan_open(void)
{

	app.node = NODE_SDWAN;
	app.jail[0] = '\0';
	app.rail_open = false;
	sd_load();
	if (sd.tab == SD_OVERVIEW)
		plan_load();
}

static void
plan_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200) {
		snprintf(sd.plan_error, sizeof(sd.plan_error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
		if (sd.plan != NULL)
			ucl_object_unref(sd.plan);
		sd.plan = NULL;
		return;
	}
	sd.plan_error[0] = '\0';
	if (sd.plan != NULL)
		ucl_object_unref(sd.plan);
	sd.plan = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	/* The dashboard and Paths want the probes as soon as the plan
	 * says which edges to ask. */
	if (app.node == NODE_SDWAN && (sd.tab == SD_OVERVIEW || sd.tab ==
	    SD_PATHS || sd.tab == SD_SECURITY))
		paths_load();
}

static void
applied_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	bool	was;

	(void)arg;
	(void)err;
	if (status != 200)
		return;
	if (sd.applied != NULL)
		ucl_object_unref(sd.applied);
	sd.applied = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	was = sd.applying;
	sd.applying = jbool(o, "applying");
	/* It ended: what is left to do now. */
	if (was && !sd.applying) {
		toast(strcmp(jstr(o, "apply.state") != NULL ? jstr(o,
		    "apply.state") : "", "done") != 0, "SD-WAN apply %s",
		    jstr(o, "apply.state") != NULL ? jstr(o, "apply.state") :
		    "ended");
		api("GET", "/api/sdwan/plan", NULL, plan_cb, NULL);
	}
}

static void
plan_load(void)
{

	sd.plan_at = sd.apply_at = arc_now();
	api("GET", "/api/sdwan/plan", NULL, plan_cb, NULL);
	api("GET", "/api/sdwan/apply", NULL, applied_cb, NULL);
}

/*
 * The samples an edge was asked for are those after the last it gave,
 * so the earlier ones it already gave are kept in front of them, up
 * to what the agent itself keeps.
 */
static void
samples_merge(ucl_object_t *data, const ucl_object_t *old)
{
	const ucl_object_t	*tg, *ot, *ns, *os, *row;
	ucl_object_iter_t	 it;
	ucl_object_t		*merged;
	int64_t			 first;
	unsigned int		 nn, no, from, i;

	it = NULL;
	while ((tg = ucl_object_iterate(jget(data, "targets"), &it, true)) !=
	    NULL) {
		ot = jfind(jget(old, "targets"), "id", jstr(tg, "id"));
		os = ot != NULL ? jget(ot, "samples") : NULL;
		no = os != NULL ? ucl_array_size(os) : 0;
		if (no == 0)
			continue;
		ns = jget(tg, "samples");
		nn = ns != NULL ? ucl_array_size(ns) : 0;
		first = nn > 0 ? ucl_object_toint(ucl_array_find_index(
		    ucl_array_find_index(ns, 0), 0)) : INT64_MAX;
		merged = ucl_object_typed_new(UCL_ARRAY);
		from = no + nn > MON_KEEP ? no + nn - MON_KEEP : 0;
		for (i = from; i < no; i++) {
			row = ucl_array_find_index(os, i);
			if (ucl_object_toint(ucl_array_find_index(row, 0)) >=
			    first)
				break;
			ucl_array_append(merged, ucl_object_ref(row));
		}
		for (i = 0; i < nn; i++)
			ucl_array_append(merged, ucl_object_ref(
			    ucl_array_find_index(ns, i)));
		ucl_object_replace_key((ucl_object_t *)(uintptr_t)tg, merged,
		    "samples", 0, false);
	}
}

/* The time after which an edge's samples are asked: the last its
 * targets all have, 0 when any has none. */
static int64_t
paths_after(const char *sid)
{
	const ucl_object_t	*tg, *s;
	ucl_object_iter_t	 it;
	int64_t			 after, last;
	unsigned int		 n;
	bool			 any = false;

	after = 0;
	it = NULL;
	while (sd.paths != NULL && (tg = ucl_object_iterate(jget(jget(sd.paths,
	    sid), "targets"), &it, true)) != NULL) {
		s = jget(tg, "samples");
		n = s != NULL ? ucl_array_size(s) : 0;
		last = n > 0 ? ucl_object_toint(ucl_array_find_index(
		    ucl_array_find_index(s, n - 1), 0)) : 0;
		if (!any || last < after)
			after = last;
		any = true;
	}
	return (after);
}

/* What one edge's probes have seen, under its id. */
static void
rekeys_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	if (status != 200 || jget(o, "rekeys") == NULL)
		return;
	if (sd.rekeys != NULL)
		ucl_object_unref(sd.rekeys);
	sd.rekeys = ucl_object_copy(jget(o, "rekeys"));
	if (app.node == NODE_SDWAN && sd.tab == SD_PATHS)
		render();
}

static void
identities_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	if (status != 200)
		return;
	if (sd.identities != NULL)
		ucl_object_unref(sd.identities);
	sd.identities = ucl_object_copy(o);
	if (app.node == NODE_SDWAN && sd.tab == SD_IDENTITIES)
		render();
}

static void
identities_load(void)
{

	api("GET", "/api/sdwan/identities", NULL, identities_cb, NULL);
}

static void
audit_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	if (status != 200)
		return;
	if (sd.audit != NULL)
		ucl_object_unref(sd.audit);
	sd.audit = ucl_object_copy(o);
	if (app.node == NODE_SDWAN && sd.tab == SD_SECURITY)
		render();
}

static void
audit_load(void)
{

	api("GET", "/api/sdwan/audit", NULL, audit_cb, NULL);
}

/* An identity issued: its configuration, shown once. */
static void
issue_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	app.modal_busy = false;
	if (status != 200) {
		snprintf(app.modal_error, sizeof(app.modal_error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
		return;
	}
	free(sd.config);
	sd.config = strdup(jstr(o, "config") != NULL ? jstr(o, "config") : "");
	snprintf(sd.config_name, sizeof(sd.config_name), "%s", jstr(o, "name")
	    != NULL ? jstr(o, "name") : "identity");
	app.modal = MODAL_SD_CONFIG;
	app.modal_error[0] = '\0';
	if (!jbool(o, "applied"))
		toast(true, "Issued, but the edges were not applied: %s", jstr(o,
		    "why") != NULL ? jstr(o, "why") : "");
	identities_load();
}

static void
revoke_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200) {
		toast(true, "Not revoked: %s", jstr(o, "error.message") != NULL ?
		    jstr(o, "error.message") : err != NULL ? err : "no answer");
		return;
	}
	toast(false, "%s revoked%s", jstr(o, "revoked"), jbool(o, "applied") ?
	    ", the edges applied" : ": the edges were not applied");
	identities_load();
}

static void
lists_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	if (status != 200)
		return;
	if (sd.lists != NULL)
		ucl_object_unref(sd.lists);
	sd.lists = ucl_object_copy(o);
	if (app.node == NODE_SDWAN && sd.tab == SD_SECURITY)
		render();
}

static void
lists_put_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200) {
		toast(true, "The lists not kept: %s", jstr(o, "error.message") !=
		    NULL ? jstr(o, "error.message") : err != NULL ? err : "no "
		    "answer");
		return;
	}
	app.modal = MODAL_NONE;
	api("GET", "/api/sdwan/lists", NULL, lists_cb, NULL);
}

/* The feeds as kept, with one changed or added, sent to be kept. */
static void
lists_send(const char *was, ucl_object_t *feed)
{
	ucl_object_t		*body, *feeds;
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;
	unsigned char		*json;

	body = ucl_object_typed_new(UCL_OBJECT);
	if (sd.lists != NULL && jget(sd.lists, "interval") != NULL)
		ucl_object_insert_key(body, ucl_object_copy(jget(sd.lists,
		    "interval")), "interval", 0, false);
	feeds = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while (sd.lists != NULL && (f = ucl_object_iterate(jget(sd.lists,
	    "feeds"), &it, true)) != NULL) {
		if (jstr(f, "name") != NULL && was != NULL && strcmp(jstr(f,
		    "name"), was) == 0)
			continue;
		if (feed != NULL && jstr(f, "name") != NULL && jstr(feed, "name")
		    != NULL && strcmp(jstr(f, "name"), jstr(feed, "name")) == 0)
			continue;
		if (jget(f, "entries") != NULL) {
			/* A pasted one goes back as text. */
			ucl_object_t		*p = ucl_object_typed_new(UCL_OBJECT);
			const ucl_object_t	*e;
			ucl_object_iter_t	 eit = NULL;
			struct html		 b;

			memset(&b, 0, sizeof(b));
			while ((e = ucl_object_iterate(jget(f, "entries"), &eit,
			    true)) != NULL)
				h_fmt(&b, "%s\n", ucl_object_tostring_forced(e));
			ucl_object_insert_key(p, ucl_object_fromstring(jstr(f,
			    "name")), "name", 0, false);
			ucl_object_insert_key(p, ucl_object_fromstring(b.s != NULL ?
			    b.s : ""), "text", 0, false);
			free(b.s);
			ucl_array_append(feeds, p);
		} else
			ucl_array_append(feeds, ucl_object_copy(f));
	}
	if (feed != NULL)
		ucl_array_append(feeds, feed);
	ucl_object_insert_key(body, feeds, "feeds", 0, false);
	json = ucl_object_emit(body, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(body);
	api("PUT", "/api/sdwan/lists", (const char *)json, lists_put_cb, NULL);
	free(json);
}

static void
rekey_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200) {
		toast(true, "The keys not turned: %s", jstr(o, "error.message") !=
		    NULL ? jstr(o, "error.message") : err != NULL ? err : "no "
		    "answer");
		return;
	}
	toast(false, "The keys of %s are being turned, both ends in step",
	    jstr(o, "tunnel"));
	paths_load();
}

/* Does a fault's object (id, id@jail, id@jail/metric) or a target's
 * jail belong to the edge whose jail is jail ("" the host)? */
static bool
of_jail(const char *object, const char *jail)
{
	const char	*at;
	size_t		 n;

	if (object == NULL || (at = strchr(object, '@')) == NULL)
		return (jail[0] == '\0');
	n = strcspn(at + 1, "/");
	return (strlen(jail) == n && strncmp(at + 1, jail, n) == 0);
}

/*
 * The server's sdwan read made the edge's own: a jail's (server/jail)
 * targets, faults, rules and steering, the host's without its jails'.
 */
static void
edge_view(ucl_object_t *data, const char *edge)
{
	const ucl_object_t	*t, *e;
	ucl_object_iter_t	 it;
	ucl_object_t		*keep;
	const char		*jail;

	jail = strchr(edge, '/') != NULL ? strchr(edge, '/') + 1 : "";
	keep = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((t = ucl_object_iterate(jget(data, "targets"), &it, true)) !=
	    NULL)
		if (strcmp(jstr(t, "jail") != NULL ? jstr(t, "jail") : "",
		    jail) == 0)
			ucl_array_append(keep, ucl_object_copy(t));
	ucl_object_replace_key(data, keep, "targets", 0, false);
	keep = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((t = ucl_object_iterate(jget(data, "faults"), &it, true)) !=
	    NULL)
		if (of_jail(jstr(t, "object"), jail))
			ucl_array_append(keep, ucl_object_copy(t));
	ucl_object_replace_key(data, keep, "faults", 0, false);
	if (jail[0] != '\0') {
		e = NULL;
		it = NULL;
		while ((t = ucl_object_iterate(jget(data, "edges"), &it, true)) !=
		    NULL)
			if (jstr(t, "jail") != NULL && strcmp(jstr(t, "jail"),
			    jail) == 0)
				e = t;
		ucl_object_replace_key(data, e != NULL && jget(e, "rules") !=
		    NULL ? ucl_object_copy(jget(e, "rules")) :
		    ucl_object_typed_new(UCL_OBJECT), "rules", 0, false);
		ucl_object_replace_key(data, e != NULL && jget(e, "steer") !=
		    NULL ? ucl_object_copy(jget(e, "steer")) :
		    ucl_object_typed_new(UCL_ARRAY), "steer", 0, false);
	}
	(void)ucl_object_delete_key(data, "edges");
}

static void
paths_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char		*sid = arg;
	ucl_object_t	*data;

	(void)err;
	if (status == 200 && jget(o, "data") != NULL) {
		if (sd.paths == NULL)
			sd.paths = ucl_object_typed_new(UCL_OBJECT);
		data = ucl_object_copy(jget(o, "data"));
		edge_view(data, sid);
		if (jget(sd.paths, sid) != NULL)
			samples_merge(data, jget(sd.paths, sid));
		(void)ucl_object_delete_key(sd.paths, sid);
		ucl_object_insert_key(sd.paths, data, sid, 0, true);
		/* Its faults of the day, as the agent keeps them. */
		if (sd.faults == NULL)
			sd.faults = ucl_object_typed_new(UCL_OBJECT);
		(void)ucl_object_delete_key(sd.faults, sid);
		ucl_object_insert_key(sd.faults, jget(jget(sd.paths, sid),
		    "faults") != NULL ? ucl_object_copy(jget(jget(sd.paths, sid),
		    "faults")) : ucl_object_typed_new(UCL_ARRAY), sid, 0, true);
	}
	free(sid);
}

/* Every edge of the plan's tunnels asked what its probes saw. */
static void
paths_load(void)
{
	const ucl_object_t	*t, *e;
	ucl_object_iter_t	 it, eit;
	ucl_object_t		*asked;
	char			 url[96];

	sd.paths_at = arc_now();
	if (sd.plan == NULL) {
		api("GET", "/api/sdwan/plan", NULL, plan_cb, NULL);
		return;
	}
	asked = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while ((t = ucl_object_iterate(jget(sd.plan, "tunnels"), &it, true)) !=
	    NULL) {
		eit = NULL;
		while ((e = ucl_object_iterate(jget(t, "ends"), &eit, true)) !=
		    NULL) {
			if (jstr(e, "edge") == NULL || ucl_object_lookup(asked,
			    jstr(e, "edge")) != NULL)
				continue;
			ucl_object_insert_key(asked, ucl_object_frombool(true),
			    jstr(e, "edge"), 0, true);
			/* A jail's edge: its server's read, its part kept. */
			snprintf(url, sizeof(url), "/api/servers/%.*s/sdwan",
			    (int)strcspn(jstr(e, "edge"), "/"), jstr(e, "edge"));
			if (paths_after(jstr(e, "edge")) > 0)
				snprintf(url + strlen(url), sizeof(url) - strlen(url),
				    "?after=%lld", (long long)paths_after(jstr(e,
				    "edge")));
			api("GET", url, NULL, paths_cb, strdup(jstr(e, "edge")));
		}
	}
	ucl_object_unref(asked);
	api("GET", "/api/sdwan/rekey", NULL, rekeys_cb, NULL);
	if (sd.tab == SD_SECURITY)
		api("GET", "/api/sdwan/lists", NULL, lists_cb, NULL);
}

/* ---- Small things ---------------------------------------------------- */

static const char *
host_name(const char *id)
{
	static char	 buf[4][160];
	static int	 k;
	const char	*slash;
	int		 i;

	/* An edge that is a vnet jail, server/jail: name/jail. */
	if (id != NULL && (slash = strchr(id, '/')) != NULL) {
		for (i = 0; i < app.nservers; i++)
			if (strlen(app.servers[i].id) == (size_t)(slash - id) &&
			    strncmp(app.servers[i].id, id, slash - id) == 0)
				break;
		k = (k + 1) % 4;
		snprintf(buf[k], sizeof(buf[k]), "%.*s/%s", i < app.nservers ?
		    (int)strlen(app.servers[i].name) : (int)(slash - id), i <
		    app.nservers ? app.servers[i].name : id, slash + 1);
		return (buf[k]);
	}
	for (i = 0; id != NULL && i < app.nservers; i++)
		if (strcmp(app.servers[i].id, id) == 0)
			return (app.servers[i].name);
	return (id != NULL ? id : "?");
}

/* A list's values joined by ", ", or what to say when there are none. */
static void
joined(struct html *h, const ucl_object_t *arr, const char *none)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	int			 n;

	if (arr != NULL && ucl_object_type(arr) == UCL_STRING) {
		h_txt(h, ucl_object_tostring(arr));
		return;
	}
	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (n++ > 0)
			h_raw(h, ", ");
		h_txt(h, ucl_object_tostring_forced(v));
	}
	if (n == 0)
		h_raw(h, none);
}

/* An object's keys and values, "key value; key value". */
static void
criteria(struct html *h, const ucl_object_t *cr)
{
	const ucl_object_t	*v, *p;
	ucl_object_iter_t	 it;
	int			 n;
	char			*s;

	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(cr, &it, true)) != NULL) {
		if (n++ > 0)
			h_raw(h, " ");
		if (strcmp(ucl_object_key(v), "any") == 0) {
			h_raw(h, "<span class=\"crit\">everything</span>");
			continue;
		}
		h_raw(h, "<span class=\"crit\"><b>");
		h_txt(h, ucl_object_key(v));
		h_raw(h, "</b> ");
		if (strcmp(ucl_object_key(v), "performance") == 0 &&
		    (p = jget(v, "primary")) != NULL) {
			h_txt(h, jstr(p, "metric") != NULL ? jstr(p, "metric") :
			    "");
			if (jget(p, "threshold") != NULL)
				h_fmt(h, " ≤ %g", jnum(p, "threshold", 0));
			if (jget(p, "ceiling") != NULL)
				h_fmt(h, ", moved at %g", jnum(p, "ceiling", 0));
		} else if (ucl_object_type(v) == UCL_ARRAY)
			joined(h, v, "none");
		else if (ucl_object_type(v) == UCL_OBJECT) {
			s = (char *)ucl_object_emit(v, UCL_EMIT_JSON_COMPACT);
			h_txt(h, s);
			free(s);
		} else
			h_txt(h, ucl_object_tostring_forced(v));
		h_raw(h, "</span>");
	}
	if (n == 0)
		h_raw(h, "<span class=\"dim\">none</span>");
}

static const char *
bits(int64_t b)
{
	static char	buf[32];

	if (b >= 1000000000)
		snprintf(buf, sizeof(buf), "%g Gbit/s", (double)b / 1e9);
	else if (b >= 1000000)
		snprintf(buf, sizeof(buf), "%g Mbit/s", (double)b / 1e6);
	else if (b >= 1000)
		snprintf(buf, sizeof(buf), "%g kbit/s", (double)b / 1e3);
	else
		snprintf(buf, sizeof(buf), "%lld bit/s", (long long)b);
	return (buf);
}

/* ---- Overview --------------------------------------------------------- */

/* A tunnel's state from its two ends' probes: up, down, or unknown. */
static const char *
tunnel_state(const ucl_object_t *t, double *delay, double *loss)
{
	const ucl_object_t	*e, *tg, *sm, *now;
	unsigned int		 n;
	int			 k, up, down;

	up = down = 0;
	*delay = -1;
	*loss = 0;
	for (k = 0; k < 2; k++) {
		e = ucl_array_find_index(jget(t, "ends"), (unsigned int)k);
		if ((tg = target_of(jstr(e, "edge"), jstr(t, "id"))) == NULL ||
		    jstr(tg, "state") == NULL)
			continue;
		if (strcmp(jstr(tg, "state"), "up") == 0)
			up++;
		else if (strcmp(jstr(tg, "state"), "down") == 0)
			down++;
		n = jget(tg, "samples") != NULL ? ucl_array_size(jget(tg,
		    "samples")) : 0;
		sm = n > 0 ? ucl_array_find_index(jget(tg, "samples"), n - 1) :
		    NULL;
		now = jget(tg, "now");
		if (sm != NULL) {
			if (ucl_object_todouble(ucl_array_find_index(sm, 1)) >
			    *delay)
				*delay = ucl_object_todouble(ucl_array_find_index(
				    sm, 1));
			if (ucl_object_todouble(ucl_array_find_index(sm, 3)) >
			    *loss)
				*loss = ucl_object_todouble(ucl_array_find_index(
				    sm, 3));
		} else if (now != NULL && jint(now, "sent", 0) > 0 && jnum(now,
		    "delay", 0) > *delay)
			*delay = jnum(now, "delay", 0);
	}
	return (down > 0 ? "down" : up == 2 ? "up" : up == 1 ? "half" :
	    "unknown");
}

/*
 * The dashboard: what there is and how it is, in numbers; the edges
 * and their tunnels drawn, each tunnel as its probes see it; then the
 * underlays, edges and services listed.  Every number names the
 * FreeBSD piece that does the work.
 */
static void
view_dashboard(struct html *h)
{
	const ucl_object_t	*v, *e, *t, *ap, *s, *f;
	ucl_object_iter_t	 it, eit;
	const char		*st;
	char			 age[32], b1[32];
	double			 delay, loss, cx, cy, r, ang, x[64], y[64];
	int			 nedges, nlinks, nucs, nsw, nfibs, nt, tup, tdown;
	int			 nfaults, ndone, nsteps, i, k, a, b, prev;

	nedges = nlinks = nucs = nsw = nfibs = nt = tup = tdown = 0;
	it = NULL;
	while ((v = ucl_object_iterate(jget(sd.doc, "ucs"), &it, true)) !=
	    NULL)
		nucs++;
	it = NULL;
	while ((v = ucl_object_iterate(jget(sd.doc, "edges"), &it, true)) !=
	    NULL) {
		if (nedges < 64) {
			nedges++;
			eit = NULL;
			while ((e = ucl_object_iterate(jget(v, "ucs_end_points"),
			    &eit, true)) != NULL)
				nlinks++;
		}
	}
	it = NULL;
	while ((v = ucl_object_iterate(jget(sd.doc, "swvcs"), &it, true)) !=
	    NULL) {
		nsw++;
		if (jint(v, "fib", 0) > nfibs)
			nfibs = (int)jint(v, "fib", 0);
	}
	it = NULL;
	while (sd.plan != NULL && (t = ucl_object_iterate(jget(sd.plan,
	    "tunnels"), &it, true)) != NULL) {
		nt++;
		st = tunnel_state(t, &delay, &loss);
		if (strcmp(st, "up") == 0)
			tup++;
		else if (strcmp(st, "down") == 0)
			tdown++;
	}
	nfaults = 0;
	it = NULL;
	while (sd.faults != NULL && (f = ucl_object_iterate(sd.faults, &it,
	    true)) != NULL) {
		eit = NULL;
		while ((e = ucl_object_iterate(f, &eit, true)) != NULL)
			if (!jbool(e, "cleared"))
				nfaults++;
	}
	ap = jget(sd.applied, "apply");
	ndone = nsteps = 0;
	it = NULL;
	while (ap != NULL && (s = ucl_object_iterate(jget(ap, "steps"), &it,
	    true)) != NULL) {
		nsteps++;
		if (jstr(s, "state") != NULL && strcmp(jstr(s, "state"), "done")
		    == 0)
			ndone++;
	}
	h_raw(h, "<div class=\"tiles sd-tiles\">");
	h_fmt(h, "<div class=\"tile\"><b>%d</b><span>edge%s · FreeBSD hosts "
	    "running arcana-agent</span></div>", nedges, nedges == 1 ? "" : "s");
	h_fmt(h, "<div class=\"tile\"><b>%d</b><span>WAN link%s on %d "
	    "underlay%s · the edges' interfaces</span></div>", nlinks, nlinks ==
	    1 ? "" : "s", nucs, nucs == 1 ? "" : "s");
	h_fmt(h, "<div class=\"tile %s\"><b>%d</b><span>service%s · a routing "
	    "table each, setfib(1), up to fib %d</span></div>", nsw > 0 ? "ok" :
	    "", nsw, nsw == 1 ? "" : "s", nfibs);
	h_fmt(h, "<div class=\"tile %s\"><b>%d</b><span>tunnel%s · %d up, %d "
	    "down · gre, gif, geneve, wg, uswe; IPsec by strongSwan or the "
	    "agents' own keys</span></div>",
	    tdown > 0 ? "warn" : nt > 0 && tup == nt ? "ok" : "", nt, nt == 1 ?
	    "" : "s", tup, tdown);
	h_fmt(h, "<div class=\"tile %s\"><b>%d</b><span>open fault%s · tunnels, "
	    "BFD, BGP, thresholds, crashes, the hosts' resources</span></div>",
	    nfaults >
	    0 ? "warn" : "", nfaults, nfaults == 1 ? "" : "s");
	if (ap != NULL && jstr(ap, "state") != NULL) {
		fmt_age(age, sizeof(age), (double)jint(ap, "started", 0) * 1000);
		h_fmt(h, "<div class=\"tile %s\"><b>%s</b><span>last apply, %s · "
		    "%d of %d steps · ipfw set %d, routes, interfaces</span>"
		    "</div>", strcmp(jstr(ap, "state"), "done") == 0 ? "ok" :
		    "warn", sd.applying ? "applying" : jstr(ap, "state"), age,
		    ndone, nsteps, 30);
	} else
		h_raw(h, "<div class=\"tile\"><b>—</b><span>not applied yet · "
		    "Edges, then Apply</span></div>");
	h_raw(h, "</div>");

	/* The topology: edges around a circle, tunnels between them. */
	if (nedges > 0) {
		h_raw(h, "<div class=\"sd-block\"><h3>Topology <small class=\""
		    "dim\">the edges and the tunnels between them, each as its "
		    "probes see it</small></h3><div class=\"sd-topo-wrap\"><svg "
		    "class=\"sd-topo\" viewBox=\"0 0 640 300\" role=\"img\">");
		cx = 320;
		cy = 150;
		r = nedges > 2 ? 110 : 0;
		i = 0;
		it = NULL;
		while ((v = ucl_object_iterate(jget(sd.doc, "edges"), &it, true))
		    != NULL && i < nedges) {
			if (nedges == 1) {
				x[i] = cx;
				y[i] = cy;
			} else if (nedges == 2) {
				x[i] = i == 0 ? 160 : 480;
				y[i] = cy;
			} else {
				ang = -M_PI / 2 + 2 * M_PI * i / nedges;
				x[i] = cx + r * cos(ang);
				y[i] = cy + r * sin(ang);
			}
			i++;
		}
		/* The tunnels first, under the nodes; a pair's second and
		 * later bow out a little. */
		prev = -1;
		it = NULL;
		while (sd.plan != NULL && (t = ucl_object_iterate(jget(sd.plan,
		    "tunnels"), &it, true)) != NULL) {
			const ucl_object_t	*ea, *eb;
			double			 mx, my, dx, dy, len, ox, oy;

			ea = ucl_array_find_index(jget(t, "ends"), 0);
			eb = ucl_array_find_index(jget(t, "ends"), 1);
			a = b = -1;
			i = 0;
			eit = NULL;
			while ((v = ucl_object_iterate(jget(sd.doc, "edges"),
			    &eit, true)) != NULL && i < nedges) {
				if (jstr(v, "server") != NULL && jstr(ea, "edge")
				    != NULL && strcmp(jstr(v, "server"), jstr(ea,
				    "edge")) == 0)
					a = i;
				if (jstr(v, "server") != NULL && jstr(eb, "edge")
				    != NULL && strcmp(jstr(v, "server"), jstr(eb,
				    "edge")) == 0)
					b = i;
				i++;
			}
			if (a < 0 || b < 0)
				continue;
			st = tunnel_state(t, &delay, &loss);
			k = a * 64 + b;
			prev = prev == k ? prev : -1;
			mx = (x[a] + x[b]) / 2;
			my = (y[a] + y[b]) / 2;
			dx = x[b] - x[a];
			dy = y[b] - y[a];
			len = sqrt(dx * dx + dy * dy);
			ox = len > 0 ? -dy / len * 22 : 0;
			oy = len > 0 ? dx / len * 22 : 0;
			/* Count the tunnels of this pair seen so far. */
			{
				const ucl_object_t	*t2;
				ucl_object_iter_t	 it2 = NULL;
				int			 same = 0;

				while ((t2 = ucl_object_iterate(jget(sd.plan,
				    "tunnels"), &it2, true)) != NULL && t2 != t) {
					const ucl_object_t *fa = ucl_array_find_index(
					    jget(t2, "ends"), 0);
					const ucl_object_t *fb = ucl_array_find_index(
					    jget(t2, "ends"), 1);

					if (jstr(fa, "edge") != NULL && jstr(fb,
					    "edge") != NULL && ((strcmp(jstr(fa,
					    "edge"), jstr(ea, "edge")) == 0 &&
					    strcmp(jstr(fb, "edge"), jstr(eb,
					    "edge")) == 0) || (strcmp(jstr(fa,
					    "edge"), jstr(eb, "edge")) == 0 &&
					    strcmp(jstr(fb, "edge"), jstr(ea,
					    "edge")) == 0)))
						same++;
				}
				ox *= same % 2 == 0 ? same / 2 : -(same + 1) / 2;
				oy *= same % 2 == 0 ? same / 2 : -(same + 1) / 2;
			}
			h_fmt(h, "<g class=\"tun st-%s%s\"><title>", st, jbool(t,
			    "backup") ? " backup" : "");
			h_txt(h, jstr(t, "id"));
			h_fmt(h, ": %s%s%s", st, delay >= 0 ? ", " : "", delay >= 0
			    ? ms(delay, b1, sizeof(b1)) : "");
			if (loss > 0)
				h_fmt(h, ", %.1f%% loss", loss * 100);
			h_fmt(h, "</title><path d=\"M%.0f %.0f Q%.0f %.0f %.0f "
			    "%.0f\"/>", x[a], y[a], mx + ox * 2, my + oy * 2, x[b],
			    y[b]);
			if (jbool(t, "encrypted"))
				h_fmt(h, "<text class=\"lock\" x=\"%.0f\" y=\"%.0f\">"
				    "&#x1F512;</text>", mx + ox - 16, my + oy + 4);
			if (delay >= 0)
				h_fmt(h, "<text class=\"lbl\" x=\"%.0f\" y=\"%.0f\">"
				    "%s%s</text>", mx + ox, my + oy + 4, ms(delay,
				    b1, sizeof(b1)), loss > 0 ? " · loss" : "");
			else
				h_fmt(h, "<text class=\"lbl\" x=\"%.0f\" y=\"%.0f\">"
				    "%s</text>", mx + ox, my + oy + 4, strcmp(st,
				    "unknown") == 0 ? "not measured" : st);
			h_raw(h, "</g>");
		}
		/* Before a plan: the pairs each service joins, as planned. */
		if (sd.plan == NULL || jget(sd.plan, "tunnels") == NULL ||
		    ucl_array_size(jget(sd.plan, "tunnels")) == 0) {
			const ucl_object_t	*sw, *ea, *eb;
			ucl_object_iter_t	 sit, ait, bit;

			sit = NULL;
			while ((sw = ucl_object_iterate(jget(sd.doc, "swvcs"),
			    &sit, true)) != NULL) {
				ait = NULL;
				while ((ea = ucl_object_iterate(jget(sw,
				    "end_points"), &ait, true)) != NULL) {
					bit = NULL;
					while ((eb = ucl_object_iterate(jget(sw,
					    "end_points"), &bit, true)) != NULL) {
						if (eb == ea || jstr(ea, "edge") ==
						    NULL || jstr(eb, "edge") == NULL
						    || strcmp(jstr(ea, "edge"),
						    jstr(eb, "edge")) >= 0)
							continue;
						a = b = -1;
						i = 0;
						eit = NULL;
						while ((v = ucl_object_iterate(jget(
						    sd.doc, "edges"), &eit, true)) !=
						    NULL && i < nedges) {
							if (strcmp(jstr(v, "server"),
							    jstr(ea, "edge")) == 0)
								a = i;
							if (strcmp(jstr(v, "server"),
							    jstr(eb, "edge")) == 0)
								b = i;
							i++;
						}
						if (a < 0 || b < 0)
							continue;
						h_fmt(h, "<g class=\"tun st-unknown\">"
						    "<title>%s: planned</title><path "
						    "d=\"M%.0f %.0f L%.0f %.0f\"/><text "
						    "class=\"lbl\" x=\"%.0f\" y=\"%.0f\">"
						    "planned</text></g>", jstr(sw, "id"),
						    x[a], y[a], x[b], y[b], (x[a] +
						    x[b]) / 2, (y[a] + y[b]) / 2 - 6);
					}
				}
			}
		}
		i = 0;
		it = NULL;
		while ((v = ucl_object_iterate(jget(sd.doc, "edges"), &it, true))
		    != NULL && i < nedges) {
			int	nl = 0, nbo = 0;

			eit = NULL;
			while ((e = ucl_object_iterate(jget(v, "ucs_end_points"),
			    &eit, true)) != NULL) {
				nl++;
				if (jbool(e, "breakout"))
					nbo++;
			}
			h_fmt(h, "<g class=\"node\" transform=\"translate(%.0f "
			    "%.0f)\"><title>", x[i], y[i]);
			h_txt(h, host_name(jstr(v, "server")));
			h_fmt(h, ": %d WAN link%s%s</title><circle r=\"22\"/>"
			    "<text class=\"name\" y=\"4\">", nl, nl == 1 ? "" :
			    "s", nbo > 0 ? ", breaks out" : "");
			h_txt(h, host_name(jstr(v, "server")));
			h_fmt(h, "</text><text class=\"sub\" y=\"36\">%d link%s%s"
			    "</text></g>", nl, nl == 1 ? "" : "s", nbo > 0 ?
			    " · breakout" : "");
			i++;
		}
		h_raw(h, "</svg><ul class=\"glegend\"><li class=\"sd-t up\">up"
		    "</li><li class=\"sd-t half\">up at one end</li><li class="
		    "\"sd-t down\">down</li><li class=\"sd-t backup\">a backup "
		    "tunnel</li><li class=\"text\"><b>🔒</b>encrypted</li></ul>"
		    "</div></div>");
	}
	view_overview(h);
}

/* Whether the box open waits for something else first. */
bool
sdwan_blocked(void)
{

	return (sd.blocked);
}

/* ---- The way through: what to make, and in which order -------------- */

/*
 * The steps of an SD-WAN, as MEF 70.2 builds one: the underlays, the
 * edges and their links on them, then a service with its end points,
 * zones, application flows and policies, then the plan deployed.  Each
 * step is done when the document has it; the first not done is the one
 * to take, and its button opens its form.
 */
enum gstep { G_UCS, G_EDGES, G_LINKS, G_SWVC, G_EPS, G_ZONES, G_FLOWS,
    G_POLICIES, G_DEPLOY, G_N };

static const struct {
	const char	*key;		/* sd-go's argument */
	const char	*title;
	const char	*what;		/* in plain words */
	const char	*add;		/* its button */
} gsteps[G_N] = {
	[G_UCS] = { "ucs", "Underlays", "The networks the edges reach each "
	    "other over: the Internet, an MPLS VPN, LTE. Each says whether "
	    "it is public and which tunnel it carries.", "+ underlay" },
	[G_EDGES] = { "edge", "Edges", "The FreeBSD hosts that carry the "
	    "service: each stands between a subscriber's network and the "
	    "underlays.", "+ edge" },
	[G_LINKS] = { "link", "WAN links", "Where each edge meets each "
	    "underlay: its interface there, the address and the gateway. "
	    "Tunnels run between links on the same underlay.", "+ WAN link" },
	[G_SWVC] = { "service", "A service", "One SD-WAN for one subscriber "
	    "(an SWVC): which underlays it may use, and its own routing "
	    "table on each edge.", "+ service" },
	[G_EPS] = { "ep", "End points", "Where the subscriber's network "
	    "plugs into the service: an interface of an edge (a UNI) and "
	    "its addresses.", "+ end point" },
	[G_ZONES] = { "zone", "Zones", "Groups of the subscriber's "
	    "addresses, by prefix: 'office' as 10.1.0.0/16. What a zone may "
	    "reach is said by its policies.", "+ zone" },
	[G_FLOWS] = { "flow", "Applications", "The traffic the policies "
	    "tell apart, by port, protocol, DSCP or application: 'voice' as "
	    "UDP 5060.", "+ application" },
	[G_POLICIES] = { "policy", "Policies", "How an application is "
	    "carried: encrypted or not, over which underlays, with what "
	    "delay and loss at most, and whether it may go straight to the "
	    "Internet.", "+ policy" },
	[G_DEPLOY] = { "deploy", "Deploy", "The console plans what each "
	    "edge is to have, shows every change, and makes it when you "
	    "say so.", "Review and deploy" },
};

/* The first edge with no WAN link yet, or NULL. */
static const ucl_object_t *
edge_unlinked(void)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(jget(sd.doc, "edges"), &it, true)) !=
	    NULL)
		if (ucl_array_size(jget(e, "ucs_end_points")) == 0)
			return (e);
	return (NULL);
}

static bool
gstep_done(enum gstep g)
{
	const ucl_object_t	*sw = swvc_shown();
	int			 todo;

	switch (g) {
	case G_UCS:
		return (ucl_array_size(jget(sd.doc, "ucs")) > 0);
	case G_EDGES:
		return (ucl_array_size(jget(sd.doc, "edges")) > 0);
	case G_LINKS:
		return (gstep_done(G_EDGES) && edge_unlinked() == NULL);
	case G_SWVC:
		return (sw != NULL);
	case G_EPS:
		return (sw != NULL && ucl_array_size(jget(sw, "end_points")) >
		    0 && ucl_array_size(jget(sw, "ucs")) > 0);
	case G_ZONES:
		return (sw != NULL && ucl_array_size(jget(sw, "zones")) > 0);
	case G_FLOWS:
		return (sw != NULL && ucl_array_size(jget(sw, "flows")) > 0);
	case G_POLICIES:
		return (sw != NULL && ucl_array_size(jget(sw, "policies")) > 0);
	case G_DEPLOY:
		if (sd.plan == NULL || sd.plan_error[0] != '\0')
			return (false);
		todo = count_change("make") + count_change("remake") +
		    count_change("unmake");
		return (todo == 0 && count_change("keep") > 0);
	case G_N:
		break;
	}
	return (false);
}

/*
 * The steps, as a row of them: done, the one to take now, and those
 * after it.  full: each said in words, on the dashboard; else a line of
 * them above a tab, until all are done.
 */
static void
view_guide(struct html *h, bool full)
{
	int	 g, next = -1;

	for (g = 0; g < G_N && next < 0; g++)
		if (!gstep_done((enum gstep)g))
			next = g;
	if (next < 0)
		return;
	h_fmt(h, "<div class=\"sd-guide%s\"><div class=\"sd-guide-head\">"
	    "<h3>Setting up an SD-WAN</h3><span class=\"dim\">step %d of %d"
	    "</span></div>", full ? " full" : "", next + 1, G_N);
	h_raw(h, "<ol>");
	for (g = 0; g < G_N; g++) {
		const char *st = gstep_done((enum gstep)g) ? "done" : g == next ?
		    "now" : "later";

		h_fmt(h, "<li class=\"g-%s\"><span class=\"g-num\">%s</span>"
		    "<div class=\"g-body\"><b>", st, strcmp(st, "done") == 0 ?
		    "✓" : "");
		h_txt(h, gsteps[g].title);
		h_raw(h, "</b>");
		if (full || g == next) {
			h_raw(h, "<p>");
			h_txt(h, gsteps[g].what);
			h_raw(h, "</p>");
		}
		if (g == next) {
			h_raw(h, "<button class=\"primary small\" data-act=\""
			    "sd-go\"");
			h_attr(h, "data-arg", gsteps[g].key);
			h_raw(h, ">");
			h_txt(h, gsteps[g].add);
			h_raw(h, "</button>");
		}
		h_raw(h, "</div></li>");
	}
	h_raw(h, "</ol>");
	if (full)
		h_raw(h, "<p class=\"dim\">Each step is kept as you go, checked "
		    "as far as it goes; nothing changes on a host until you "
		    "deploy, and each change is shown first. The example in "
		    "<b>Document</b> has every step, written for the first two "
		    "hosts.</p>");
	h_raw(h, "</div>");
}

static void
view_overview(struct html *h)
{
	const ucl_object_t	*v, *e, *t, *sw;
	ucl_object_iter_t	 it, eit;
	int			 n;
	bool			 first;

	if (sd.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, sd.error);
		h_raw(h, "</div>");
	}
	/* The underlays. */
	h_raw(h, "<div class=\"sd-block\"><h3>Underlays <small class=\"dim\">"
	    "UCS, MEF 70.2 §12: the carriers the edges reach each other over"
	    "</small><span class=\"pane-actions\"><button class=\"ghost small\" "
	    "data-act=\"sd-ucs-add\">+ underlay</button></span></h3><table "
	    "class=\"net sd\"><thead><tr><th>Id</th><th>Type</th><th>Billing"
	    "</th><th>Tunnels over it</th><th></th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(jget(sd.doc, "ucs"), &it, true)) !=
	    NULL) {
		n++;
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(v, "id"));
		h_fmt(h, "</td><td><span class=\"chip %s\">%s</span></td><td>",
		    jstr(v, "type") != NULL && strcmp(jstr(v, "type"),
		    "public") == 0 ? "warn" : "", jstr(v, "type") != NULL &&
		    strcmp(jstr(v, "type"), "public") == 0 ? "public" :
		    "private");
		h_txt(h, jstr(v, "billing") != NULL ? jstr(v, "billing") : "—");
		h_raw(h, "</td><td>");
		t = jget(v, "tunnel");
		if (t == NULL)
			h_raw(h, "<span class=\"dim\">gre</span>");
		else {
			h_txt(h, jstr(t, "kind"));
			if (jbool(t, "ipsec"))
				h_raw(h, " + IPsec IKEv2");
		}
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" data-act="
		    "\"sd-ucs-edit\" title=\"Change it\"");
		h_attr(h, "data-arg", jstr(v, "id"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "sd-ucs-del\" title=\"Take it away\"");
		h_attr(h, "data-arg", jstr(v, "id"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"5\" class=\"dim\">None yet: add one, "
		    "public (the Internet) or private (an MPLS, a line).</td>"
		    "</tr>");
	h_raw(h, "</tbody></table></div>");

	/* The edges and where each meets its underlays. */
	h_raw(h, "<div class=\"sd-block\"><h3>Edges <small class=\"dim\">"
	    "SD-WAN Edges, the hosts, and their WAN links, one on each "
	    "underlay they reach (UCS End Points, §7.8, §12.3)</small><span "
	    "class=\"pane-actions\"><button class=\"ghost small\" data-act=\""
	    "sd-edge-add\">+ edge</button></span></h3><table class=\"net sd\">"
	    "<thead><tr><th>Host</th><th>WAN link</th><th>Underlay</th><th>"
	    "Interface</th><th>Address</th><th>Bandwidth</th><th></th><th>"
	    "</th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(jget(sd.doc, "edges"), &it, true)) !=
	    NULL) {
		first = true;
		n++;
		eit = NULL;
		while ((e = ucl_object_iterate(jget(v, "ucs_end_points"), &eit,
		    true)) != NULL) {
			h_raw(h, "<tr><td>");
			if (first) {
				h_raw(h, "<b>");
				h_txt(h, host_name(jstr(v, "server")));
				h_raw(h, "</b>");
			}
			first = false;
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(e, "id"));
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(e, "ucs"));
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(e, "interface"));
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(e, "address") != NULL ? jstr(e, "address") :
			    "");
			if (jstr(e, "addressing") != NULL && strcmp(jstr(e,
			    "addressing"), "static") != 0)
				h_fmt(h, " <span class=\"chip\" title=\"The address is "
				    "learned from the host\">%s</span>", strcmp(jstr(e,
				    "addressing"), "dhcp") == 0 ? "DHCP" : "SLAAC");
			if (jint(e, "vrf", 0) > 0)
				h_fmt(h, " <span class=\"dim\">fib %lld</span>", (long
				    long)jint(e, "vrf", 0));
			if (jget(jget(e, "routing"), "bgp") != NULL || jget(jget(e,
			    "routing"), "ospf") != NULL)
				h_raw(h, " <span class=\"chip\" title=\"Routed with the "
				    "underlay by BIRD\">routed</span>");
			if (jstr(e, "gateway") != NULL) {
				h_raw(h, " <span class=\"dim\">via ");
				h_txt(h, jstr(e, "gateway"));
				h_raw(h, "</span>");
			}
			h_raw(h, "</td><td>");
			if (jget(e, "bandwidth") != NULL)
				h_txt(h, bits(jint(e, "bandwidth", 0)));
			h_raw(h, "</td><td>");
			if (jbool(e, "breakout"))
				h_raw(h, "<span class=\"chip\" title=\"Traffic "
				    "for the Internet leaves here\">breakout"
				    "</span> ");
			if (jbool(e, "backup"))
				h_raw(h, "<span class=\"chip\" title=\"Used "
				    "only when nothing else is left\">backup"
				    "</span>");
			h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" "
			    "data-act=\"sd-link-edit\" title=\"Change it\"");
			h_attr(h, "data-arg", jstr(v, "server"));
			h_attr(h, "data-value", jstr(e, "id"));
			h_raw(h, ">&#9998;</button><button class=\"icon\" data-act="
			    "\"sd-link-del\" title=\"Take the link away\"");
			h_attr(h, "data-arg", jstr(v, "server"));
			h_attr(h, "data-value", jstr(e, "id"));
			h_raw(h, ">×</button></td></tr>");
		}
		/* The edge's own line: a link more, or the edge away. */
		h_raw(h, "<tr class=\"sd-edge-row\"><td>");
		if (first) {
			h_raw(h, "<b>");
			h_txt(h, host_name(jstr(v, "server")));
			h_raw(h, "</b>");
		}
		h_raw(h, "</td><td colspan=\"6\"><button class=\"ghost small\" "
		    "data-act=\"sd-link-add\"");
		h_attr(h, "data-arg", jstr(v, "server"));
		h_raw(h, ">+ WAN link</button>");
		if (jget(v, "ntp") != NULL && ucl_array_size(jget(v, "ntp")) > 0) {
			h_raw(h, " <small class=\"dim\">NTP by ");
			joined(h, jget(v, "ntp"), "");
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" data-act="
		    "\"sd-edge-edit\" title=\"Change the edge: its NTP servers\"");
		h_attr(h, "data-arg", jstr(v, "server"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "sd-edge-del\" title=\"Take the edge away, with its links\"");
		h_attr(h, "data-arg", jstr(v, "server"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"8\" class=\"dim\">None yet: add a "
		    "host as an edge, then its WAN links.</td></tr>");
	h_raw(h, "</tbody></table></div>");

	/* The services. */
	h_raw(h, "<div class=\"sd-block\"><h3>Services <small class=\"dim\">"
	    "SWVCs, §9</small></h3><table class=\"net sd\"><thead><tr><th>Id"
	    "</th><th>FIB</th><th>End points</th><th>Underlays</th><th>Zones"
	    "</th><th>Flows</th><th>Policies</th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while ((sw = ucl_object_iterate(jget(sd.doc, "swvcs"), &it, true)) !=
	    NULL) {
		n++;
		h_raw(h, "<tr><td><button class=\"cell-link\" data-act=\""
		    "sd-swvc\"");
		h_attr(h, "data-arg", jstr(sw, "id"));
		h_raw(h, ">");
		h_txt(h, jstr(sw, "id"));
		h_fmt(h, "</button></td><td class=\"num\">%lld</td><td>",
		    (long long)jint(sw, "fib", 0));
		eit = NULL;
		while ((e = ucl_object_iterate(jget(sw, "end_points"), &eit,
		    true)) != NULL) {
			h_raw(h, "<span class=\"chip\">");
			h_txt(h, jstr(e, "id"));
			h_raw(h, " · ");
			h_txt(h, host_name(jstr(e, "edge")));
			h_raw(h, "</span> ");
		}
		h_raw(h, "</td><td>");
		joined(h, jget(sw, "ucs"), "—");
		h_fmt(h, "</td><td class=\"num\">%u</td><td class=\"num\">%u</td>"
		    "<td class=\"num\">%u</td></tr>",
		    jget(sw, "zones") != NULL ? ucl_array_size(jget(sw,
		    "zones")) : 0, jget(sw, "flows") != NULL ? ucl_array_size(
		    jget(sw, "flows")) : 0, jget(sw, "policies") != NULL ?
		    ucl_array_size(jget(sw, "policies")) : 0);
	}
	if (n == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"7\">None yet. "
		    "<button class=\"ghost small\" data-act=\"sd-go\" "
		    "data-arg=\"service\">+ service</button> or start from the "
		    "example in <b>Document</b>.</td></tr>");
	h_raw(h, "</tbody></table></div>");
}

/* ---- One service ------------------------------------------------------ */

static const ucl_object_t *
swvc_shown(void)
{
	const ucl_object_t	*sw;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((sw = ucl_object_iterate(jget(sd.doc, "swvcs"), &it, true)) !=
	    NULL)
		if (jstr(sw, "id") != NULL && strcmp(jstr(sw, "id"), sd.swvc) ==
		    0)
			return (sw);
	return (NULL);
}

static void
addressing(struct html *h, const ucl_object_t *v)
{
	const char	*mode;

	mode = jstr(v, "mode");
	if (v == NULL || mode == NULL || strcmp(mode, "none") == 0) {
		h_raw(h, "<span class=\"dim\">none</span>");
		return;
	}
	if (strcmp(mode, "static") != 0 && strcmp(mode, "dhcp") != 0 &&
	    strcmp(mode, "slaac") != 0) {
		h_txt(h, mode);
		return;
	}
	/* One span: a card keeps the prefix and its gateway together; the
	 * hosts addressed by the edge say by what (dnsmasq, rtadvd). */
	h_raw(h, "<span><span class=\"mono\">");
	h_txt(h, jstr(v, "prefix"));
	h_raw(h, "</span> <span class=\"dim\">via ");
	joined(h, jget(v, "provider"), "—");
	if (strcmp(mode, "dhcp") == 0)
		h_raw(h, " · <span class=\"chip\" title=\"The edge gives the hosts "
		    "their addresses: dnsmasq in the service's table\">DHCP</span>");
	else if (strcmp(mode, "slaac") == 0)
		h_raw(h, " · <span class=\"chip\" title=\"The hosts address "
		    "themselves by the edge's router advertisements: rtadvd\">"
		    "SLAAC</span>");
	h_raw(h, "</span></span>");
}

/* The names of the document's lists of kind, as a select's options. */
static void
nlist_select(struct html *h, const char *label, const char *field,
    const char *kind, const char *cur, const char *hint)
{
	const ucl_object_t	*l;
	ucl_object_iter_t	 it;

	h_raw(h, "<label>");
	h_txt(h, label);
	h_raw(h, "<select");
	h_attr(h, "name", field);
	h_raw(h, "><option value=\"\">none</option>");
	it = NULL;
	while ((l = ucl_object_iterate(jget(sd.doc, "lists"), &it, true)) !=
	    NULL) {
		if (jstr(l, "kind") == NULL || strcmp(jstr(l, "kind"), kind) != 0)
			continue;
		h_raw(h, "<option");
		h_attr(h, "value", jstr(l, "name"));
		if (cur != NULL && strcmp(cur, jstr(l, "name")) == 0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, jstr(l, "name"));
		h_raw(h, "</option>");
	}
	h_raw(h, "</select>");
	if (hint != NULL) {
		h_raw(h, "<small class=\"help\">");
		h_txt(h, hint);
		h_raw(h, "</small>");
	}
	h_raw(h, "</label>");
}

/* A list's items, shortly: the first few and how many. */
static void
nlist_items(struct html *h, const ucl_object_t *l)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int			 n;

	if (jstr(l, "kind") != NULL && strcmp(jstr(l, "kind"), "services") ==
	    0) {
		joined(h, jget(l, "protocols"), "—");
		h_raw(h, " <span class=\"dim\">ports</span> ");
		joined(h, jget(l, "ports"), "any");
		return;
	}
	n = 0;
	it = NULL;
	while ((e = ucl_object_iterate(jget(l, "items"), &it, true)) != NULL) {
		if (n++ == 6)
			continue;
		if (n > 1)
			h_raw(h, ", ");
		if (ucl_object_type(e) == UCL_OBJECT) {
			h_txt(h, jstr(e, "id"));
			if (jint(e, "preference", 0) != 0)
				h_fmt(h, " <span class=\"dim\">%lld</span>",
				    (long long)jint(e, "preference", 0));
		} else
			h_txt(h, ucl_object_tostring_forced(e));
	}
	if (n > 6)
		h_fmt(h, " <span class=\"dim\">and %d more</span>", n - 6);
}

/* The document's named lists: kept once, named where a value would be. */
static void
view_nlists(struct html *h)
{
	const ucl_object_t	*l;
	ucl_object_iter_t	 it;

	h_raw(h, "<div class=\"sd-block sd-nlists\"><h3>Lists <small class=\""
	    "dim\">of the whole document: prefixes, services, UCSs, edges and "
	    "UCS End Points, kept once and named by flows, zones and policies"
	    "</small><span class=\"pane-actions\"><button class=\"ghost "
	    "small\" data-act=\"sd-nlist-add\">+ list</button></span></h3>"
	    "<table class=\"net sd\"><thead><tr><th>Name</th><th>Of</th><th>"
	    "Items</th><th></th></tr></thead><tbody>");
	it = NULL;
	while ((l = ucl_object_iterate(jget(sd.doc, "lists"), &it, true)) !=
	    NULL) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(l, "name"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(l, "kind"));
		h_raw(h, "</td><td class=\"mono\">");
		nlist_items(h, l);
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" "
		    "data-act=\"sd-nlist-edit\" title=\"Change it\"");
		h_attr(h, "data-arg", jstr(l, "name"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "sd-nlist-del\" title=\"Take the list away\"");
		h_attr(h, "data-arg", jstr(l, "name"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (ucl_array_size(jget(sd.doc, "lists")) == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"4\">No list yet: "
		    "branch prefixes, a set of ports, the UCS End Points a "
		    "policy prefers… each kept once, and named where it is "
		    "used.</td></tr>");
	h_raw(h, "</tbody></table></div>");
}

static void
view_service(struct html *h)
{
	const ucl_object_t	*sw, *v, *e, *u, *m;
	ucl_object_iter_t	 it, mit;
	int			 n;

	view_guide(h, false);
	if ((sw = swvc_shown()) == NULL) {
		if (sd.error[0] != '\0') {
			h_raw(h, "<div class=\"notice bad\">");
			h_txt(h, sd.error);
			h_raw(h, "</div>");
		}
		h_raw(h, "<div class=\"empty\"><h2>No service yet</h2><p>A "
		    "service is one SD-WAN for one subscriber: the underlays "
		    "it may use, where its networks plug in, and how each of "
		    "their applications is carried.</p><button class=\"primary"
		    "\" data-act=\"sd-swvc-add\">+ service</button></div>");
		return;
	}
	h_raw(h, "<div class=\"toolbar\">");
	if (ucl_array_size(jget(sd.doc, "swvcs")) > 1) {
		h_raw(h, "<label class=\"inline\">Service <select data-input="
		    "\"sd-swvc\">");
		it = NULL;
		while ((v = ucl_object_iterate(jget(sd.doc, "swvcs"), &it,
		    true)) != NULL) {
			h_raw(h, "<option");
			h_attr(h, "value", jstr(v, "id"));
			if (strcmp(jstr(v, "id"), jstr(sw, "id")) == 0)
				h_raw(h, " selected");
			h_raw(h, ">");
			h_txt(h, jstr(v, "id"));
			h_raw(h, "</option>");
		}
		h_raw(h, "</select></label>");
	} else {
		h_raw(h, "<h3 class=\"inline\">Service ");
		h_txt(h, jstr(sw, "id"));
		h_raw(h, "</h3>");
	}
	h_raw(h, "<button class=\"ghost small\" data-act=\"sd-swvc-add\">+ "
	    "service</button>");
	h_raw(h, "<button class=\"icon\" data-act=\"sd-swvc-edit\" title=\""
	    "Change the service\"");
	h_attr(h, "data-arg", jstr(sw, "id"));
	h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\"sd-swvc-del"
	    "\" title=\"Take the service away\"");
	h_attr(h, "data-arg", jstr(sw, "id"));
	h_raw(h, ">×</button>");
	h_fmt(h, "<span class=\"age\">FIB %lld on its edges · ", (long long)
	    jint(sw, "fib", 0));
	joined(h, jget(sw, "reserved_prefixes"), "no reserved prefixes");
	if (jget(sw, "bfd") != NULL && ucl_object_type(jget(sw, "bfd")) ==
	    UCL_OBJECT)
		h_raw(h, " · BFD");
	/* Its routing domains (Mplify 119 §7.3), where set. */
	{
		const ucl_object_t	*d = jget(sw, "domains"), *b, *s;

		b = jget(d, "breakout");
		s = jget(d, "service");
		if (b != NULL && jint(b, "fib", 0) > 0)
			h_fmt(h, " · breakout in FIB %lld", (long long)jint(b,
			    "fib", 0));
		if (s != NULL && jstr(s, "prefix") != NULL) {
			h_raw(h, " · the tunnels from <span class=\"mono\">");
			h_txt(h, jstr(s, "prefix"));
			h_raw(h, "</span>");
		}
	}
	h_raw(h, "</span></div>");
	if (sd.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, sd.error);
		h_raw(h, "</div>");
	}

	/* End points: where the subscriber meets it. */
	h_raw(h, "<div class=\"sd-block\"><h3>End points <small class=\"dim\">"
	    "each at an SD-WAN UNI, where the subscriber's hosts meet the "
	    "service, §10, §11</small><span class=\"pane-actions\"><button "
	    "class=\"ghost small\" data-act=\"sd-ep-add\">+ end point</button>"
	    "</span></h3><table class=\"net sd\"><thead><tr><th>Id</th><th>Edge"
	    "</th><th>UNI</th><th>IPv4</th><th>IPv6</th><th>Static routes</th>"
	    "<th>Policy map</th><th></th></tr></thead><tbody>");
	it = NULL;
	while ((e = ucl_object_iterate(jget(sw, "end_points"), &it, true)) !=
	    NULL) {
		u = jget(e, "uni");
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(e, "id"));
		h_raw(h, "</td><td>");
		h_txt(h, host_name(jstr(e, "edge")));
		h_raw(h, "</td><td class=\"mono\">");
		if (u == NULL && jget(e, "remote") != NULL) {
			/* A remote end point (SASE-3): the identities' own
			 * WireGuard interface, its prefix theirs. */
			u = jget(e, "remote");
			h_txt(h, jstr(u, "interface"));
			h_fmt(h, " <span class=\"dim\">remote, %u identit%s, port "
			    "%lld</span></td><td class=\"mono\">", jget(u,
			    "identities") != NULL ? ucl_array_size(jget(u,
			    "identities")) : 0, jget(u, "identities") != NULL &&
			    ucl_array_size(jget(u, "identities")) == 1 ? "y" : "ies",
			    (long long)jint(u, "port", 51820));
			h_txt(h, jstr(u, "prefix"));
			h_raw(h, "</td><td class=\"dim\">—</td><td class=\"num\">0"
			    "</td><td>");
			goto map;
		}
		h_txt(h, jstr(u, "interface"));
		if (jint(u, "vlan", 0) > 0)
			h_fmt(h, " <span class=\"dim\">vlan %lld</span>",
			    (long long)jint(u, "vlan", 0));
		h_raw(h, "</td><td>");
		addressing(h, jget(u, "ipv4"));
		h_raw(h, "</td><td>");
		addressing(h, jget(u, "ipv6"));
		h_fmt(h, "</td><td class=\"num\">%u</td><td>", jget(u, "routes")
		    != NULL ? ucl_array_size(jget(u, "routes")) : 0);
map:
		n = 0;
		mit = NULL;
		while ((m = ucl_object_iterate(jget(e, "policy_map"), &mit,
		    true)) != NULL) {
			char	idx[16];

			snprintf(idx, sizeof(idx), "%d", n++);
			h_raw(h, "<div class=\"pmap\"><span class=\"mono\">");
			h_txt(h, jstr(m, "zone"));
			h_raw(h, " · ");
			h_txt(h, jstr(m, "app"));
			h_raw(h, "</span> → ");
			h_txt(h, jstr(m, "ingress") != NULL ? jstr(m,
			    "ingress") : "none");
			if (jstr(m, "egress") != NULL) {
				h_raw(h, " <span class=\"dim\">out</span> ");
				h_txt(h, jstr(m, "egress"));
			}
			h_raw(h, " <button class=\"icon\" data-act=\"sd-map-edit\" "
			    "title=\"Change the rule\"");
			h_attr(h, "data-arg", jstr(e, "id"));
			h_attr(h, "data-value", idx);
			h_raw(h, ">&#9998;</button><button class=\"icon\" data-act="
			    "\"sd-map-del\" title=\"Take the rule away\"");
			h_attr(h, "data-arg", jstr(e, "id"));
			h_attr(h, "data-value", idx);
			h_raw(h, ">×</button></div>");
		}
		if (n == 0)
			h_raw(h, "<span class=\"dim\">the zones' own</span> ");
		h_raw(h, "<button class=\"ghost small\" data-act=\"sd-map-add\"");
		h_attr(h, "data-arg", jstr(e, "id"));
		h_raw(h, ">+ rule</button></td><td class=\"acts\"><button class=\""
		    "icon\" data-act=\"sd-ep-edit\" title=\"Change it\"");
		h_attr(h, "data-arg", jstr(e, "id"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "sd-ep-del\" title=\"Take the end point away\"");
		h_attr(h, "data-arg", jstr(e, "id"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (ucl_array_size(jget(sw, "end_points")) == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"8\">No end point yet: where the subscriber's network plugs in, an interface of an edge and its addresses. "
		    "<button class=\"ghost small\" data-act=\"sd-ep-add\">+ end point</button>"
		    "</td></tr>");
	h_raw(h, "</tbody></table></div>");

	/* Zones. */
	view_nlists(h);
	h_raw(h, "<div class=\"sd-block\"><h3>Zones <small class=\"dim\">"
	    "by source address, §9.5; a zone's rules hold at every end point "
	    "whose map says nothing</small><span class=\"pane-actions\"><button "
	    "class=\"ghost small\" data-act=\"sd-zone-add\">+ zone</button>"
	    "</span></h3><table class=\"net sd\"><thead><tr><th>Name</th><th>"
	    "Prefixes</th><th>Rules, zone-wide</th><th></th></tr></thead>"
	    "<tbody>");
	it = NULL;
	while ((v = ucl_object_iterate(jget(sw, "zones"), &it, true)) != NULL) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(v, "name"));
		h_raw(h, "</td><td class=\"mono\">");
		joined(h, jget(v, "prefixes"), jstr(v, "prefix-list") != NULL ? "" :
		    "—");
		if (jstr(v, "prefix-list") != NULL) {
			h_raw(h, " <span class=\"chip\">list ");
			h_txt(h, jstr(v, "prefix-list"));
			h_raw(h, "</span>");
		}
		h_raw(h, "</td><td>");
		n = 0;
		mit = NULL;
		while ((m = ucl_object_iterate(jget(v, "policies"), &mit,
		    true)) != NULL) {
			char	idx[16];

			snprintf(idx, sizeof(idx), "%d", n++);
			h_raw(h, "<div class=\"pmap\">");
			h_txt(h, jstr(m, "app"));
			h_raw(h, " → ");
			h_txt(h, jstr(m, "policy"));
			h_raw(h, " <button class=\"icon\" data-act=\"sd-zmap-edit\" "
			    "title=\"Change the rule\"");
			h_attr(h, "data-arg", jstr(v, "name"));
			h_attr(h, "data-value", idx);
			h_raw(h, ">&#9998;</button><button class=\"icon\" data-act="
			    "\"sd-zmap-del\" title=\"Take the rule away\"");
			h_attr(h, "data-arg", jstr(v, "name"));
			h_attr(h, "data-value", idx);
			h_raw(h, ">×</button></div>");
		}
		if (n == 0)
			h_raw(h, "<span class=\"dim\">none: dropped unless an end "
			    "point's map says (R112)</span> ");
		h_raw(h, "<button class=\"ghost small\" data-act=\"sd-zmap-add\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">+ rule</button></td><td class=\"acts\"><button class=\""
		    "icon\" data-act=\"sd-zone-edit\" title=\"Change it\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "sd-zone-del\" title=\"Take the zone away\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (ucl_array_size(jget(sw, "zones")) == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"4\">No zone yet: a group of the subscriber's addresses, by prefix, whose applications the policies carry. "
		    "<button class=\"ghost small\" data-act=\"sd-zone-add\">+ zone</button>"
		    "</td></tr>");
	h_raw(h, "</tbody></table></div>");

	/* Application flows, in the order they are matched. */
	h_raw(h, "<div class=\"sd-block\"><h3>Application flows <small class="
	    "\"dim\">what a packet is, by the first that matches, §9.14; the "
	    "rules name them</small><span class=\"pane-actions\"><button class="
	    "\"ghost small\" data-act=\"sd-flow-add\">+ flow</button></span>"
	    "</h3><table class=\"net sd\"><thead><tr><th>#</th><th>Name</th><th>"
	    "Matches</th><th>Group</th><th></th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(jget(sw, "flows"), &it, true)) != NULL) {
		h_fmt(h, "<tr><td class=\"num\">%d</td><td class=\"mono\">", ++n);
		h_txt(h, jstr(v, "name"));
		h_raw(h, "</td><td>");
		criteria(h, jget(v, "criteria"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(v, "group") != NULL ? jstr(v, "group") : "");
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" data-act="
		    "\"sd-flow-edit\" title=\"Change it\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "sd-flow-del\" title=\"Take the flow away\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (ucl_array_size(jget(sw, "flows")) == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"5\">No application yet: traffic named by port, protocol, DSCP or application, for the policies to tell apart. "
		    "<button class=\"ghost small\" data-act=\"sd-flow-add\">+ application</button>"
		    "</td></tr>");
	h_raw(h, "</tbody></table></div>");

	/* Policies. */
	h_raw(h, "<div class=\"sd-block\"><h3>Policies <small class=\"dim\">"
	    "how a flow is carried: which tunnels, the Internet, its "
	    "performance, its bandwidth, §9.12</small><span class=\""
	    "pane-actions\"><button class=\"ghost small\" data-act=\""
	    "sd-policy-add\">+ policy</button></span></h3><table class=\"net "
	    "sd\"><thead><tr><th>Name</th><th>Direction</th><th>Criteria</th>"
	    "<th></th></tr></thead><tbody>");
	it = NULL;
	while ((v = ucl_object_iterate(jget(sw, "policies"), &it, true)) !=
	    NULL) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(v, "name"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(v, "direction"));
		h_raw(h, "</td><td>");
		criteria(h, jget(v, "criteria"));
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" data-act="
		    "\"sd-policy-edit\" title=\"Change it\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "sd-policy-del\" title=\"Take the policy away\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (ucl_array_size(jget(sw, "policies")) == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"4\">No policy yet: how an application is carried, encrypted or not, over which underlays, how fast and how well. "
		    "<button class=\"ghost small\" data-act=\"sd-policy-add\">+ policy</button>"
		    "</td></tr>");
	h_raw(h, "</tbody></table></div>");

	/* Virtual topologies and rate limiters. */
	h_raw(h, "<div class=\"sd-block\"><h3>Virtual topologies <small class="
	    "\"dim\">which end points may reach which, §9.6; Swvc, all to "
	    "all, is always there</small><span class=\"pane-actions\"><button "
	    "class=\"ghost small\" data-act=\"sd-topo-add\">+ topology"
	    "</button></span></h3><table class=\"net sd\"><thead><tr><th>Name"
	    "</th><th>Type</th><th>End points</th><th></th></tr></thead>"
	    "<tbody>");
	it = NULL;
	while ((v = ucl_object_iterate(jget(sw, "topologies"), &it, true)) !=
	    NULL) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(v, "name"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(v, "type"));
		h_raw(h, "</td><td>");
		if (jget(v, "roots") != NULL) {
			h_raw(h, "roots ");
			joined(h, jget(v, "roots"), "—");
			h_raw(h, "; leaves ");
			joined(h, jget(v, "leaves"), "—");
		} else
			joined(h, jget(v, "end_points"), "—");
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" "
		    "data-act=\"sd-topo-edit\" title=\"Change it\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "sd-topo-del\" title=\"Take it away\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (ucl_array_size(jget(sw, "topologies")) == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"4\">None: every "
		    "end point reaches every other. A topology lets some reach "
		    "only some, a hub and its spokes. <button class=\"ghost "
		    "small\" data-act=\"sd-topo-add\">+ topology</button></td>"
		    "</tr>");
	h_raw(h, "</tbody></table></div>");
	h_raw(h, "<div class=\"sd-block\"><h3>Rate limiters <small class=\""
	    "dim\">bandwidth shared by the applications whose policy names "
	    "it, at each end point, §9.9</small><span class=\"pane-actions\">"
	    "<button class=\"ghost small\" data-act=\"sd-lim-add\">+ rate "
	    "limiter</button></span></h3><table class=\"net sd\"><thead><tr>"
	    "<th>Name</th><th>Committed</th><th>At most</th><th></th></tr>"
	    "</thead><tbody>");
	it = NULL;
	while ((v = ucl_object_iterate(jget(sw, "rate_limiters"), &it, true)) !=
	    NULL) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(v, "name"));
		h_raw(h, "</td><td>");
		h_txt(h, bits(jint(v, "commit", 0)));
		h_raw(h, "</td><td>");
		h_txt(h, jget(v, "limit") != NULL && ucl_object_type(jget(v,
		    "limit")) == UCL_INT ? bits(jint(v, "limit", 0)) : "none");
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" "
		    "data-act=\"sd-lim-edit\" title=\"Change it\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "sd-lim-del\" title=\"Take it away\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (ucl_array_size(jget(sw, "rate_limiters")) == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"4\">None. A "
		    "policy may give its applications a bandwidth of their own, "
		    "or name a rate limiter they share. <button class=\"ghost "
		    "small\" data-act=\"sd-lim-add\">+ rate limiter</button>"
		    "</td></tr>");
	h_raw(h, "</tbody></table></div>");
}

/* ---- The edges -------------------------------------------------------- */

static int
count_change(const char *change)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((c = ucl_object_iterate(jget(sd.plan, "changes"), &it, true)) !=
	    NULL)
		if (strcmp(jstr(c, "change"), change) == 0)
			n++;
	return (n);
}

static const char *
change_word(const char *c)
{

	return (strcmp(c, "make") == 0 ? "to make" : strcmp(c, "remake") ==
	    0 ? "to make again" : strcmp(c, "unmake") == 0 ? "to take away" :
	    "as it is");
}

/* A job as a line: its kind and its fields. */
static void
job_line(struct html *h, const ucl_object_t *j)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	char			*s;

	h_raw(h, "<li><b>");
	h_txt(h, jstr(j, "kind"));
	h_raw(h, "</b>");
	it = NULL;
	while ((v = ucl_object_iterate(j, &it, true)) != NULL) {
		if (strcmp(ucl_object_key(v), "kind") == 0 ||
		    ucl_object_key(v)[0] == '_')
			continue;
		h_raw(h, " <span class=\"dim\">");
		h_txt(h, ucl_object_key(v));
		h_raw(h, "</span> ");
		if (ucl_object_type(v) == UCL_ARRAY) {
			s = (char *)ucl_object_emit(v, UCL_EMIT_JSON_COMPACT);
			h_txt(h, s);
			free(s);
		} else
			h_txt(h, ucl_object_tostring_forced(v));
	}
	h_raw(h, "</li>");
}

static void
view_tunnels(struct html *h, const ucl_object_t *tunnels)
{
	const ucl_object_t	*t, *e;
	ucl_object_iter_t	 it;
	int			 k;

	h_raw(h, "<div class=\"sd-block\"><h3>Tunnels <small class=\"dim\">"
	    "TVCs, §7.10: between each two edges of a service, over each two "
	    "of their underlays that reach each other</small></h3><table "
	    "class=\"net sd\"><thead><tr><th>Tunnel</th><th>Kind</th><th>End"
	    "</th><th>End</th><th></th></tr></thead><tbody>");
	it = NULL;
	while ((t = ucl_object_iterate(tunnels, &it, true)) != NULL) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(t, "id"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(t, "kind"));
		if (jbool(t, "ipsec"))
			h_raw(h, " + IPsec");
		h_fmt(h, " <span class=\"dim\">fib %lld</span></td>",
		    (long long)jint(t, "fib", 0));
		for (k = 0; k < 2; k++) {
			e = ucl_array_find_index(jget(t, "ends"),
			    (unsigned int)k);
			h_raw(h, "<td><b>");
			h_txt(h, host_name(jstr(e, "edge")));
			h_raw(h, "</b> <span class=\"mono\">");
			h_txt(h, jstr(e, "ifname"));
			h_raw(h, "</span><small class=\"dim\"> ");
			h_txt(h, jstr(e, "inner4") != NULL ? jstr(e, "inner4") :
			    jstr(e, "inner6") != NULL ? jstr(e, "inner6") : "");
			h_raw(h, " over ");
			h_txt(h, jstr(e, "underlay"));
			h_raw(h, "</small></td>");
		}
		h_raw(h, "<td>");
		h_raw(h, jbool(t, "encrypted") ? "<span class=\"chip\">"
		    "encrypted</span> " : "<span class=\"chip warn\">clear"
		    "</span> ");
		if (jbool(t, "public"))
			h_raw(h, "<span class=\"chip\">public</span> ");
		if (jbool(t, "backup"))
			h_raw(h, "<span class=\"chip\">backup</span>");
		h_raw(h, "</td></tr>");
	}
	if (ucl_array_size(tunnels) == 0)
		h_raw(h, "<tr><td colspan=\"5\" class=\"dim\">None: a service "
		    "with end points on two edges or more has them.</td></tr>");
	h_raw(h, "</tbody></table></div>");
}

/* The last apply: how far it went, each step and how it ended. */
static void
view_applied(struct html *h)
{
	const ucl_object_t	*ap, *s;
	ucl_object_iter_t	 it;
	char			 age[32];
	int			 n, done, failed, undone;

	ap = jget(sd.applied, "apply");
	if (ap == NULL || jstr(ap, "state") == NULL)
		return;
	n = done = failed = undone = 0;
	it = NULL;
	while ((s = ucl_object_iterate(jget(ap, "steps"), &it, true)) != NULL) {
		n++;
		if (strcmp(jstr(s, "state"), "done") == 0)
			done++;
		else if (strcmp(jstr(s, "state"), "failed") == 0 || strcmp(jstr(s,
		    "state"), "undo failed") == 0)
			failed++;
		else if (strcmp(jstr(s, "state"), "undone") == 0)
			undone++;
	}
	fmt_age(age, sizeof(age), (double)jint(ap, "started", 0) * 1000);
	/* Rolled back: a step failed, and what the apply had made before
	 * it was taken away again; the edges are as they were. */
	h_fmt(h, "<div class=\"sd-block sd-applied %s\"><h3>%s <small class="
	    "\"dim\">", strcmp(jstr(ap, "state"), "rolled back") == 0 ? "failed"
	    : jstr(ap, "state"), sd.applying ? "Applying" :
	    strcmp(jstr(ap, "state"), "done") == 0 ? "Last apply: done" :
	    strcmp(jstr(ap, "state"), "rolled back") == 0 ? "Last apply: rolled "
	    "back" : "Last apply: failed");
	h_txt(h, age);
	if (strcmp(jstr(ap, "state"), "rolled back") == 0 && jstr(ap,
	    "failed_step") != NULL) {
		h_fmt(h, " · %d undone after ", undone);
		h_txt(h, jstr(ap, "failed_step"));
		h_raw(h, " failed");
	}
	h_fmt(h, " · %d of %d steps done%s</small></h3>", done, n,
	    failed > 0 ? ", some failed" : "");
	if (sd.applying || failed > 0) {
		h_raw(h, "<ul class=\"sd-steps\">");
		it = NULL;
		while ((s = ucl_object_iterate(jget(ap, "steps"), &it,
		    true)) != NULL) {
			h_fmt(h, "<li class=\"%s\"><span class=\"led\"></span>"
			    "<b>", jstr(s, "state"));
			h_txt(h, jstr(s, "name"));
			h_raw(h, "</b> ");
			h_txt(h, jstr(s, "title"));
			h_fmt(h, " <span class=\"dim\">%s · %s</span>",
			    change_word(jstr(s, "change")), jstr(s, "state"));
			if (jstr(s, "detail") != NULL) {
				h_raw(h, "<small>");
				h_txt(h, jstr(s, "detail"));
				h_raw(h, "</small>");
			}
			h_raw(h, "</li>");
		}
		h_raw(h, "</ul>");
	}
	h_raw(h, "</div>");
}

/* The edges that lack what the services need there: how many things. */
static int
needs_missing(void)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while (sd.plan != NULL && (e = ucl_object_iterate(jget(sd.plan,
	    "needs"), &it, true)) != NULL)
		if (!jbool(e, "there"))
			n++;
	return (n);
}

/*
 * Before using SD-WAN: what it needs that is not FreeBSD's own, and of
 * it what each edge of the kept services lacks.  The apply installs
 * nothing: each is installed first, by hand or with the button here.
 * With brief, only when something is missing.
 */
static void
view_needs(struct html *h, bool brief)
{
	static const struct {
		const char	*package, *what, *when;
	} all[] = {
		{ "strongswan", "strongSwan's IKEv2", "a tunnel under IPsec "
		    "(an underlay with ipsec, or a policy that says encryption)" },
		{ "bird3", "BIRD", "routing at a UNI (static, BGP, OSPF), BFD, "
		    "a control plane, a WAN link routed on its underlay" },
		{ "dnsmasq", "dnsmasq", "DHCP at a UNI" },
		{ "squid", "Squid", "a security policy with url-filter or malware" },
		{ "c-icap c-icap-modules clamav", "c-icap and ClamAV", "a security "
		    "policy with malware; then freshclam, for ClamAV's signatures" },
		{ "suricata", "Suricata", "a security policy with ids; then "
		    "suricata-update, where the policy adds the ruleset" },
	};
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	size_t			 i;
	int			 missing;

	if (sd.plan == NULL)
		return;
	missing = needs_missing();
	if (brief && missing == 0)
		return;
	h_fmt(h, "<section class=\"pane sd-needs\"><h4><span>Before using "
	    "SD-WAN</span></h4><p class=\"%s\">", missing > 0 ? "notice warn" :
	    "dim");
	if (missing > 0)
		h_fmt(h, "%d package%s the services need %s not installed on "
		    "their edges. Install %s first, then deploy: nothing is "
		    "installed by the apply.", missing, missing == 1 ? "" : "s",
		    missing == 1 ? "is" : "are", missing == 1 ? "it" : "them");
	else
		h_raw(h, "SD-WAN is FreeBSD's own (FIBs, ipfw, dummynet, the "
		    "tunnels, local-unbound, rtadvd) but for the packages below, "
		    "which each edge needs installed before a service that uses "
		    "them is deployed; the apply installs nothing.");
	h_raw(h, "</p>");
	if (jget(sd.plan, "needs") != NULL && ucl_array_size(jget(sd.plan,
	    "needs")) > 0) {
		h_raw(h, "<table class=\"net\"><thead><tr><th>Edge</th>"
		    "<th>Package</th><th>For</th><th>Installed</th><th></th>"
		    "</tr></thead><tbody>");
		it = NULL;
		while ((e = ucl_object_iterate(jget(sd.plan, "needs"), &it,
		    true)) != NULL) {
			h_raw(h, "<tr><td>");
			h_txt(h, jstr(e, "name"));
			h_raw(h, "</td><td><code>");
			h_txt(h, jstr(e, "package"));
			h_raw(h, "</code></td><td class=\"dim\">");
			h_txt(h, jstr(e, "what"));
			h_fmt(h, "</td><td>%s</td><td>", jbool(e, "there") ?
			    "<span class=\"chip ok\">yes</span>" : "<span "
			    "class=\"chip bad\">no</span>");
			if (!jbool(e, "there")) {
				h_raw(h, "<code>pkg install ");
				h_txt(h, jstr(e, "package"));
				h_raw(h, "</code> <button class=\"ghost small\" "
				    "data-act=\"sd-need-install\"");
				h_attr(h, "data-arg", jstr(e, "server"));
				h_attr(h, "data-value", jstr(e, "package"));
				h_raw(h, ">Install</button>");
			}
			h_raw(h, "</td></tr>");
		}
		h_raw(h, "</tbody></table>");
	}
	if (!brief) {
		h_raw(h, "<details><summary>Everything SD-WAN may need</summary>"
		    "<table class=\"net\"><thead><tr><th>Package</th><th>Is"
		    "</th><th>Needed for</th></tr></thead><tbody>");
		for (i = 0; i < nitems(all); i++) {
			h_raw(h, "<tr><td><code>");
			h_txt(h, all[i].package);
			h_raw(h, "</code></td><td>");
			h_txt(h, all[i].what);
			h_raw(h, "</td><td class=\"dim\">");
			h_txt(h, all[i].when);
			h_raw(h, "</td></tr>");
		}
		h_raw(h, "</tbody></table></details>");
	}
	h_raw(h, "<div class=\"toolbar\"><button class=\"ghost small\" "
	    "data-act=\"sd-needs-check\">Check again</button></div></section>");
}

static void
view_edges(struct html *h)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it, jit;
	const ucl_object_t	*j;
	const char		*last;
	int			 todo;

	if (sd.plan == NULL && sd.plan_error[0] == '\0') {
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	todo = sd.plan != NULL ? count_change("make") + count_change(
	    "remake") + count_change("unmake") : 0;
	view_guide(h, false);
	view_needs(h, true);
	h_fmt(h, "<div class=\"toolbar\"><button class=\"primary small\" "
	    "data-act=\"sd-apply-ask\"%s title=\"Make on the edges what the "
	    "services say, in Mplify 119's order: FIBs, IPsec, tunnels, their "
	    "far ends, routes, and the UNIs last\">Deploy%s</button><button "
	    "class=\"ghost small\" data-act=\"sd-apply-fresh\"%s title=\""
	    "Everything the console made taken away and made again\">Make "
	    "all again</button><button class=\"ghost small\" data-act=\""
	    "sd-show-kept\" title=\"The changes alone, or everything the edges "
	    "are to have\">%s</button><span class=\"age\">",
	    todo == 0 || sd.applying || needs_missing() > 0 ? " disabled" :
	    "", needs_missing() > 0 ? ": install what is missing first" :
	    todo > 0 ? "" : ": nothing to do", sd.applying ? " disabled" : "",
	    sd.show_kept
	    ? "Changes only" : "Show all");
	if (sd.plan != NULL)
		h_fmt(h, "%d to make, %d to make again, %d to take away, %d as "
		    "they are", count_change("make"), count_change("remake"),
		    count_change("unmake"), count_change("keep"));
	h_raw(h, "</span></div>");
	if (sd.plan_error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, sd.plan_error);
		h_raw(h, "</div>");
		return;
	}
	/* What the plan leaves out, and why. */
	{
		const ucl_object_t	*n;
		ucl_object_iter_t	 nit;

		nit = NULL;
		while ((n = ucl_object_iterate(jget(sd.plan, "notes"), &nit,
		    true)) != NULL) {
			h_raw(h, "<div class=\"notice warn\">");
			h_txt(h, ucl_object_tostring_forced(n));
			h_raw(h, "</div>");
		}
	}
	view_applied(h);
	view_tunnels(h, jget(sd.plan, "tunnels"));
	/*
	 * What each edge is to have, and what becomes of it: by edge, in
	 * the order it is made, the changes alone unless asked for all;
	 * while an apply runs, each edge's steps done so far.
	 */
	h_fmt(h, "<div class=\"sd-block\"><h3>On the edges <small class=\"dim"
	    "\">what each is to have, as jobs, in the order it is made: %s"
	    "</small></h3><table class=\"net sd sd-plan\"><thead><tr><th>Edge"
	    "</th><th title=\"Mplify 119 §12.1, the activity flow's steps 1 to 13\">"
	    "Step</th><th>What</th><th>Change</th><th>Jobs</th></tr>"
	    "</thead><tbody>", todo > 0 && !sd.show_kept ? "the changes" :
	    "everything");
	last = "";
	it = NULL;
	while ((c = ucl_object_iterate(jget(sd.plan, "changes"), &it, true)) !=
	    NULL) {
		if (strcmp(last, jstr(c, "server")) != 0) {
			/* The edge's own line: its counts, and its progress. */
			const ucl_object_t	*c2, *ap, *s;
			ucl_object_iter_t	 it2;
			int			 nmk, nrm, num, nk, done, all, failed;

			nmk = nrm = num = nk = done = all = failed = 0;
			it2 = NULL;
			while ((c2 = ucl_object_iterate(jget(sd.plan, "changes"),
			    &it2, true)) != NULL) {
				if (strcmp(jstr(c2, "server"), jstr(c, "server")) != 0)
					continue;
				if (strcmp(jstr(c2, "change"), "make") == 0)
					nmk++;
				else if (strcmp(jstr(c2, "change"), "remake") == 0)
					nrm++;
				else if (strcmp(jstr(c2, "change"), "unmake") == 0)
					num++;
				else
					nk++;
			}
			ap = jget(sd.applied, "apply");
			it2 = NULL;
			while (sd.applying && (s = ucl_object_iterate(jget(ap,
			    "steps"), &it2, true)) != NULL) {
				if (jstr(s, "server") == NULL || strcmp(jstr(s,
				    "server"), jstr(c, "server")) != 0)
					continue;
				all++;
				if (jstr(s, "state") != NULL && strcmp(jstr(s, "state"),
				    "done") == 0)
					done++;
				else if (jstr(s, "state") != NULL && strcmp(jstr(s,
				    "state"), "failed") == 0)
					failed++;
			}
			h_raw(h, "<tr class=\"sd-edge-head\"><td colspan=\"5\"><b>");
			h_txt(h, jstr(c, "name"));
			h_fmt(h, "</b> <span class=\"dim\">%d to make, %d to make "
			    "again, %d to take away, %d as they are</span>", nmk,
			    nrm, num, nk);
			if (all > 0)
				h_fmt(h, " <span class=\"sd-progress\" title=\"%d of %d "
				    "steps done%s\"><span class=\"bar %s\" style=\"width:"
				    "%d%%\"></span></span> <span class=\"dim\">%d / %d%s"
				    "</span>", done, all, failed > 0 ? ", some failed"
				    : "", failed > 0 ? "failed" : "", all > 0 ? (done +
				    failed) * 100 / all : 0, done, all, failed > 0 ?
				    ", failed" : "");
			h_raw(h, "</td></tr>");
		}
		last = jstr(c, "server");
		if (!sd.show_kept && todo > 0 && strcmp(jstr(c, "change"), "keep")
		    == 0)
			continue;
		h_fmt(h, "<tr class=\"ch-%s\"><td></td><td class=\"dim\" title=\""
		    "Mplify 119 §12.1, the step of its activity flow\">%s</td><td>",
		    jstr(c, "change"), step_label(c));
		h_txt(h, jstr(c, "title"));
		h_fmt(h, "</td><td><span class=\"chip ch-%s\">%s</span></td>"
		    "<td><details><summary>%u</summary><ul class=\"sd-jobs\">",
		    jstr(c, "change"), change_word(jstr(c, "change")),
		    strcmp(jstr(c, "change"), "unmake") == 0 ?
		    ucl_array_size(jget(c, "unmake")) : ucl_array_size(jget(c,
		    "make")));
		jit = NULL;
		while ((j = ucl_object_iterate(jget(c, strcmp(jstr(c, "change"),
		    "unmake") == 0 ? "unmake" : "make"), &jit, true)) != NULL)
			job_line(h, j);
		h_raw(h, "</ul></details></td></tr>");
	}
	h_raw(h, "</tbody></table></div>");
	/* The applies before: when, how they went, what they did. */
	if (jget(sd.applied, "history") != NULL && ucl_array_size(jget(
	    sd.applied, "history")) > 0) {
		const ucl_object_t	*hh, *by;
		ucl_object_iter_t	 bit;
		char			 age[32];
		unsigned int		 n, k;

		h_raw(h, "<div class=\"sd-block\"><h3>Past applies <small class=\""
		    "dim\">the last fifty, the newest first</small></h3><table "
		    "class=\"net sd sd-history\"><thead><tr><th>When</th><th>How"
		    "</th><th>Made</th><th>Again</th><th>Taken away</th><th>"
		    "Failed</th><th>Edges</th></tr></thead><tbody>");
		n = ucl_array_size(jget(sd.applied, "history"));
		for (k = n; k > 0; k--) {
			hh = ucl_array_find_index(jget(sd.applied, "history"), k - 1);
			fmt_age(age, sizeof(age), (double)jint(hh, "started", 0) *
			    1000);
			h_fmt(h, "<tr><td>%s</td><td><span class=\"chip %s\">%s%s"
			    "</span></td><td class=\"num\">%lld</td><td class=\"num"
			    "\">%lld</td><td class=\"num\">%lld</td><td class=\"num\">"
			    "%lld</td><td>", age, jstr(hh, "state") != NULL &&
			    strcmp(jstr(hh, "state"), "done") == 0 ? "st-up" :
			    "st-down", jstr(hh, "state") != NULL ? jstr(hh, "state")
			    : "", jbool(hh, "fresh") ? ", all again" : "", jint(hh,
			    "made", 0), jint(hh, "remade", 0), jint(hh, "unmade", 0),
			    jint(hh, "failed", 0));
			by = jget(hh, "edges");
			bit = NULL;
			while ((hh = ucl_object_iterate(by, &bit, true)) != NULL) {
				h_raw(h, "<span class=\"chip\">");
				h_txt(h, jstr(hh, "name"));
				h_fmt(h, " %lld%s</span> ", jint(hh, "steps", 0),
				    jint(hh, "failed", 0) > 0 ? " · failed" : "");
			}
			h_raw(h, "</td></tr>");
		}
		h_raw(h, "</tbody></table></div>");
	}
}

/* ---- The paths: what the probes see of each tunnel ------------------- */

/* The target an edge probes for a tunnel: its id is the tunnel's. */
static const ucl_object_t *
target_of(const char *sid, const char *tid)
{
	const ucl_object_t	*t;
	ucl_object_iter_t	 it;

	if (sd.paths == NULL || sid == NULL)
		return (NULL);
	it = NULL;
	while ((t = ucl_object_iterate(jget(jget(sd.paths, sid), "targets"),
	    &it, true)) != NULL)
		if (jstr(t, "id") != NULL && strcmp(jstr(t, "id"), tid) == 0)
			return (t);
	return (NULL);
}

static const char *
ms(double v, char *buf, size_t len)
{

	snprintf(buf, len, v >= 100 ? "%.0f ms" : v >= 10 ? "%.1f ms" :
	    "%.2f ms", v);
	return (buf);
}

/* The last samples' delay as a line, loss as marks under it. */
static void
spark(struct html *h, const ucl_object_t *samples)
{
	const ucl_object_t	*s;
	double			 max, v, loss;
	unsigned int		 n, from, i;

	n = samples != NULL ? ucl_array_size(samples) : 0;
	if (n == 0) {
		h_raw(h, "<span class=\"dim\">no sample yet</span>");
		return;
	}
	from = n > SPARK_N ? n - SPARK_N : 0;
	max = 0;
	for (i = from; i < n; i++) {
		s = ucl_array_find_index(samples, i);
		v = ucl_object_todouble(ucl_array_find_index(s, 5));
		if (v > max)
			max = v;
	}
	if (max <= 0)
		max = 1;
	h_fmt(h, "<svg class=\"spark\" viewBox=\"0 0 %d 24\" preserveAspectRatio="
	    "\"none\" aria-hidden=\"true\"><path d=\"", SPARK_N);
	for (i = from; i < n; i++) {
		s = ucl_array_find_index(samples, i);
		v = ucl_object_todouble(ucl_array_find_index(s, 1));
		h_fmt(h, "%c%u %.1f ", i == from ? 'M' : 'L', i - from, 22 -
		    v / max * 20);
	}
	h_raw(h, "\"/>");
	for (i = from; i < n; i++) {
		s = ucl_array_find_index(samples, i);
		loss = ucl_object_todouble(ucl_array_find_index(s, 3));
		if (loss > 0)
			h_fmt(h, "<rect class=\"loss\" x=\"%u\" y=\"22\" width=\"1\""
			    " height=\"2\"/>", i - from);
	}
	h_fmt(h, "</svg><small class=\"dim\">%u samples, up to %s</small>", n -
	    from, ms(max, (char[32]){ 0 }, 32));
}

/* A round figure at or over v, for a chart's top: 1, 2, 5 of a power of ten. */
static double
nice(double v)
{
	double	m = 1;

	if (v <= 0)
		return (1);
	while (v / m >= 10)
		m *= 10;
	while (v / m < 1)
		m /= 10;
	return (v / m <= 1 ? m : v / m <= 2 ? 2 * m : v / m <= 5 ? 5 * m : 10 *
	    m);
}

static void
mon_ago(char *buf, size_t len, double secs)
{

	if (secs < 90)
		snprintf(buf, len, "%.0f s ago", secs);
	else if (secs < 5400)
		snprintf(buf, len, "%.0f min ago", secs / 60);
	else
		snprintf(buf, len, "%.1f h ago", secs / 3600);
}

struct monbin {
	double		delay, ipdv, min, max;	/* sums, the least, the most */
	long long	sent, lost;
	int		n;
};

/*
 * A tunnel's monitor: its two ends' samples over the span, binned
 * into columns, as three charts, the delay (its mean a line, its
 * least to most a band), the variation and the loss, each with the
 * service's threshold where there is one, and the faults of the
 * tunnel as bands of time; a column hovered tells its figures.
 */
static void
monitor(struct html *h, const ucl_object_t *t)
{
	static const char *const titles[] = { "Delay", "Variation", "Loss" };
	const ucl_object_t	*e, *tg, *s, *row, *sw, *tca, *fl, *f;
	ucl_object_iter_t	 fit;
	struct monbin		 bins[2][MON_BINS], *bn;
	const char		*tid, *obj, *sev;
	double			 now, t0, w, top[3], thr[3], v, x, y, y2, ft, fc;
	char			 tip[500], when[32], b1[32], b2[32];
	unsigned int		 n, i;
	int			 span, k, b, p, len;
	bool			 any = false, drawing;

	span = sd.mon_span > 0 ? sd.mon_span : 900;
	now = arc_now() / 1000;
	t0 = now - span;
	w = (double)span / MON_BINS;
	tid = jstr(t, "id");
	memset(bins, 0, sizeof(bins));
	for (k = 0; k < 2; k++) {
		e = ucl_array_find_index(jget(t, "ends"), (unsigned int)k);
		tg = target_of(jstr(e, "edge"), tid);
		s = tg != NULL ? jget(tg, "samples") : NULL;
		n = s != NULL ? ucl_array_size(s) : 0;
		for (i = 0; i < n; i++) {
			row = ucl_array_find_index(s, i);
			b = (int)((ucl_object_todouble(ucl_array_find_index(row,
			    0)) - t0) / w);
			if (b < 0 || b >= MON_BINS)
				continue;
			bn = &bins[k][b];
			v = ucl_object_todouble(ucl_array_find_index(row, 4));
			if (bn->n == 0 || v < bn->min)
				bn->min = v;
			v = ucl_object_todouble(ucl_array_find_index(row, 5));
			if (bn->n == 0 || v > bn->max)
				bn->max = v;
			bn->delay += ucl_object_todouble(ucl_array_find_index(row,
			    1));
			bn->ipdv += ucl_object_todouble(ucl_array_find_index(row,
			    2));
			bn->sent += ucl_object_toint(ucl_array_find_index(row, 6));
			bn->lost += ucl_object_toint(ucl_array_find_index(row, 6))
			    - ucl_object_toint(ucl_array_find_index(row, 7));
			bn->n++;
			any = true;
		}
	}
	/* The service's thresholds, drawn where set (Mplify 119 §11.4). */
	sw = jfind(jget(sd.doc, "swvcs"), "id", jstr(t, "swvc"));
	tca = sw != NULL ? jget(sw, "tca") : NULL;
	thr[0] = tca != NULL ? jnum(tca, "delay", 0) : 0;
	thr[1] = tca != NULL ? jnum(tca, "ipdv", 0) : 0;
	thr[2] = tca != NULL ? jnum(tca, "loss", 0) * 100 : 0;
	h_raw(h, "<div class=\"sd-mon\">");
	if (!any) {
		h_fmt(h, "<p class=\"dim\">No sample in the last %d min to draw: "
		    "the ends' probes have not reported yet, or not for that "
		    "long.</p></div>", span / 60);
		return;
	}
	for (p = 0; p < 3; p++) {
		top[p] = thr[p] * 1.15;
		for (k = 0; k < 2; k++)
			for (b = 0; b < MON_BINS; b++) {
				bn = &bins[k][b];
				if (bn->n == 0)
					continue;
				v = p == 0 ? bn->max : p == 1 ? bn->ipdv / bn->n :
				    bn->sent > 0 ? 100.0 * bn->lost / bn->sent : 0;
				if (v > top[p])
					top[p] = v;
			}
		top[p] = nice(top[p] > 0 ? top[p] : p == 2 ? 1 : 0.1);
	}
	for (p = 0; p < 3; p++) {
		h_fmt(h, "<div class=\"sd-mon-side\"><h5>%s <small class=\"dim\">"
		    "up to %s%s</small></h5><svg class=\"sd-chart\" viewBox=\"0 0 "
		    "%d %d\" preserveAspectRatio=\"none\" role=\"img\">", titles[p],
		    p == 2 ? (snprintf(b1, sizeof(b1), "%.3g", top[p]), b1) :
		    ms(top[p], b1, sizeof(b1)), p == 2 ? "%" : "", MON_W, MON_H);
		/* The faults of the tunnel on each end, as bands of time. */
		for (k = 0; k < 2; k++) {
			e = ucl_array_find_index(jget(t, "ends"), (unsigned int)k);
			fl = sd.faults != NULL ? jget(sd.faults, jstr(e, "edge")) :
			    NULL;
			fit = NULL;
			while (fl != NULL && (f = ucl_object_iterate(fl, &fit, true))
			    != NULL) {
				obj = jstr(f, "object");
				len = tid != NULL ? (int)strlen(tid) : 0;
				if (obj == NULL || tid == NULL || strncmp(obj, tid,
				    (size_t)len) != 0 || (obj[len] != '\0' && obj[len]
				    != '/'))
					continue;
				ft = (double)jint(f, "t", 0);
				fc = jbool(f, "cleared") ? (double)jint(f,
				    "cleared_at", 0) : now;
				if (fc < t0 || ft > now)
					continue;
				if (ft < t0)
					ft = t0;
				sev = jstr(f, "severity");
				h_fmt(h, "<rect class=\"fault %s\" x=\"%.2f\" y=\"0\" "
				    "width=\"%.2f\" height=\"%d\"><title>", sev != NULL
				    && (strcmp(sev, "Major") == 0 || strcmp(sev,
				    "Critical") == 0) ? "major" : "minor", (ft - t0) /
				    span * MON_W, (fc - ft) / span * MON_W > 1 ? (fc -
				    ft) / span * MON_W : 1, MON_H);
				h_txt(h, jstr(f, "description") != NULL ? jstr(f,
				    "description") : "");
				h_raw(h, "</title></rect>");
			}
		}
		if (thr[p] > 0)
			h_fmt(h, "<line class=\"thr\" x1=\"0\" x2=\"%d\" y1=\"%.2f\" "
			    "y2=\"%.2f\"><title>threshold %.3g%s</title></line>",
			    MON_W, MON_H - 4 - thr[p] / top[p] * (MON_H - 10), MON_H -
			    4 - thr[p] / top[p] * (MON_H - 10), thr[p], p == 2 ?
			    "%" : " ms");
		for (k = 0; k < 2; k++) {
			if (p == 0) {
				/* The least to the most, as a band. */
				h_fmt(h, "<path class=\"band e%d\" d=\"", k);
				drawing = false;
				for (b = 0; b <= MON_BINS; b++) {
					bn = b < MON_BINS ? &bins[k][b] : NULL;
					if (bn == NULL || bn->n == 0) {
						if (drawing) {
							/* Back along the least. */
							for (i = (unsigned int)b; i-- > 0 &&
							    bins[k][i].n > 0;)
								h_fmt(h, "L%.1f %.2f ", (i + 0.5) *
								    MON_W / MON_BINS, MON_H - 4 -
								    bins[k][i].min / top[0] * (MON_H
								    - 10));
							h_raw(h, "Z ");
						}
						drawing = false;
						continue;
					}
					h_fmt(h, "%c%.1f %.2f ", drawing ? 'L' : 'M', (b +
					    0.5) * MON_W / MON_BINS, MON_H - 4 - bn->max /
					    top[0] * (MON_H - 10));
					drawing = true;
				}
				h_raw(h, "\"/>");
			}
			if (p < 2) {
				h_fmt(h, "<path class=\"mean e%d\" d=\"", k);
				drawing = false;
				for (b = 0; b < MON_BINS; b++) {
					bn = &bins[k][b];
					if (bn->n == 0) {
						drawing = false;
						continue;
					}
					v = (p == 0 ? bn->delay : bn->ipdv) / bn->n;
					h_fmt(h, "%c%.1f %.2f ", drawing ? 'L' : 'M', (b +
					    0.5) * MON_W / MON_BINS, MON_H - 4 - v / top[p] *
					    (MON_H - 10));
					drawing = true;
				}
				h_raw(h, "\"/>");
			} else
				for (b = 0; b < MON_BINS; b++) {
					bn = &bins[k][b];
					if (bn->n == 0 || bn->sent == 0 || bn->lost == 0)
						continue;
					v = 100.0 * bn->lost / bn->sent;
					y = MON_H - 4 - v / top[2] * (MON_H - 10);
					h_fmt(h, "<rect class=\"lost e%d\" x=\"%.2f\" y=\""
					    "%.2f\" width=\"%.2f\" height=\"%.2f\"/>", k, (b +
					    (k == 0 ? 0.05 : 0.5)) * MON_W / MON_BINS, y,
					    0.45 * MON_W / MON_BINS, MON_H - 4 - y);
				}
		}
		/* The hover: a column's figures of both ends. */
		for (b = 0; b < MON_BINS; b++) {
			if (bins[0][b].n == 0 && bins[1][b].n == 0)
				continue;
			mon_ago(when, sizeof(when), span - (b + 0.5) * w);
			snprintf(tip, sizeof(tip), "%s", when);
			for (k = 0; k < 2; k++) {
				bn = &bins[k][b];
				if (bn->n == 0)
					continue;
				e = ucl_array_find_index(jget(t, "ends"),
				    (unsigned int)k);
				len = (int)strlen(tip);
				snprintf(tip + len, sizeof(tip) - (size_t)len,
				    "\nfrom %.24s: delay %s (%s to %s), variation %s, "
				    "loss %.1f%% of %lld", host_name(jstr(e, "edge")),
				    ms(bn->delay / bn->n, b1, sizeof(b1)), ms(bn->min,
				    b2, sizeof(b2)), ms(bn->max, (char[32]){ 0 }, 32),
				    ms(bn->ipdv / bn->n, (char[32]){ 0 }, 32), bn->sent
				    > 0 ? 100.0 * bn->lost / bn->sent : 0, bn->sent);
			}
			h_fmt(h, "<rect class=\"hit\" x=\"%.2f\" y=\"0\" width=\"%.2f\" "
			    "height=\"%d\"><title>", b * (double)MON_W / MON_BINS,
			    (double)MON_W / MON_BINS, MON_H);
			h_txt(h, tip);
			h_raw(h, "</title></rect>");
		}
		h_raw(h, "</svg><div class=\"ecmp-axis\"><span>");
		mon_ago(when, sizeof(when), span);
		h_txt(h, when);
		h_raw(h, "</span><span>now</span></div></div>");
	}
	/* The key: each end's colour, the thresholds, the faults. */
	h_raw(h, "<ul class=\"ecmp-key sd-mon-key\">");
	for (k = 0; k < 2; k++) {
		e = ucl_array_find_index(jget(t, "ends"), (unsigned int)k);
		h_fmt(h, "<li><i class=\"e%d\"></i><span>from <b>", k);
		h_txt(h, host_name(jstr(e, "edge")));
		h_raw(h, "</b>, as its probes see the far end</span></li>");
	}
	if (thr[0] > 0 || thr[1] > 0 || thr[2] > 0)
		h_raw(h, "<li><i class=\"thr\"></i><span>the service's threshold"
		    "</span></li>");
	h_raw(h, "<li><i class=\"fault\"></i><span>a fault of the tunnel, while "
	    "it was open</span></li></ul>");
	(void)y2;
	(void)x;
	h_raw(h, "</div>");
}

static void
view_paths(struct html *h)
{
	const ucl_object_t	*t, *e, *tg, *now, *sm, *f, *d;
	ucl_object_iter_t	 it, eit, fit;
	const char		*st;
	char			 b1[32], b2[32], b3[32], age[32];
	unsigned int		 n;
	int			 k, nf;

	if (sd.plan == NULL) {
		h_raw(h, sd.plan_error[0] != '\0' ? "<div class=\"notice bad\">" :
		    "<div class=\"loader\"></div>");
		if (sd.plan_error[0] != '\0') {
			h_txt(h, sd.plan_error);
			h_raw(h, "</div>");
		}
		return;
	}
	h_raw(h, "<div class=\"ecmp-head\"><p class=\"dim ecmp-note\">Each edge "
	    "pings the far end of each of its tunnels through the service's "
	    "table, as its probe settings say; of each eval interval it keeps "
	    "the one-way delay (half the round trip), its variation, the "
	    "loss, the least and the most. Read every two seconds while this "
	    "is open; the charts draw what the agents keep, an hour of "
	    "samples unless the service's probe says otherwise.</p>");
	{
		static const int	 secs[] = { 300, 900, 3600 };
		size_t			 i;
		int			 span = sd.mon_span > 0 ? sd.mon_span : 900;

		h_raw(h, "<nav class=\"sub sd-span\" title=\"How far back the "
		    "charts draw\">");
		for (i = 0; i < nitems(secs); i++)
			h_fmt(h, "<button class=\"ghost small%s\" data-act=\"sd-span"
			    "\" data-arg=\"%d\">%d min</button>", span == secs[i] ?
			    " on" : "", secs[i], secs[i] / 60);
		h_raw(h, "</nav></div>");
	}
	it = NULL;
	while ((t = ucl_object_iterate(jget(sd.plan, "tunnels"), &it, true)) !=
	    NULL) {
		h_raw(h, "<div class=\"sd-block sd-path\"><h3><span class=\"mono"
		    "\">");
		h_txt(h, jstr(t, "id"));
		h_fmt(h, "</span> <small class=\"dim\">%s%s%s%s</small></h3>"
		    "<table class=\"net sd\"><thead><tr><th>From</th><th>State"
		    "</th><th>Delay</th><th>Variation</th><th>Loss</th><th>"
		    "Least / most</th><th>Probes</th><th>Last samples</th></tr>"
		    "</thead><tbody>", jstr(t, "kind"), jbool(t, "ipsec") ?
		    " + IPsec" : "", jbool(t, "public") ? ", public" : "",
		    jbool(t, "backup") ? ", backup" : "");
		for (k = 0; k < 2; k++) {
			e = ucl_array_find_index(jget(t, "ends"), (unsigned int)k);
			tg = target_of(jstr(e, "edge"), jstr(t, "id"));
			h_raw(h, "<tr><td><b>");
			h_txt(h, host_name(jstr(e, "edge")));
			h_raw(h, "</b> <span class=\"mono dim\">");
			h_txt(h, jstr(e, "ifname"));
			h_raw(h, "</span></td>");
			if (tg == NULL) {
				h_raw(h, "<td colspan=\"7\" class=\"dim\">not "
				    "probed: not applied, or not read yet</td>"
				    "</tr>");
				continue;
			}
			st = jstr(tg, "state") != NULL ? jstr(tg, "state") :
			    "unknown";
			fmt_age(age, sizeof(age), (double)jint(tg, "since", 0) *
			    1000);
			h_fmt(h, "<td><span class=\"chip st-%s\">%s</span> <small "
			    "class=\"dim\">", st, st);
			h_txt(h, age);
			h_raw(h, "</small>");
			/* BFD's word on it, when the service watches by BFD. */
			{
				const ucl_object_t	*bi, *bs;
				ucl_object_iter_t	 iit, sit;
				const char		*far = jstr(tg, "address");

				iit = NULL;
				while (far != NULL && (bi = ucl_object_iterate(jget(
				    jget(sd.paths, jstr(e, "edge")), "bird"), &iit,
				    true)) != NULL) {
					sit = NULL;
					while ((bs = ucl_object_iterate(jget(bi, "bfd"),
					    &sit, true)) != NULL)
						if (jstr(bs, "address") != NULL && strcmp(
						    jstr(bs, "address"), far) == 0)
							h_fmt(h, " <span class=\"chip st-%s\" "
							    "title=\"BFD, by BIRD\">bfd %s"
							    "</span>", jstr(bs, "state"),
							    jstr(bs, "state"));
				}
			}
			if (jstr(tg, "error") != NULL) {
				h_raw(h, "<small class=\"bad\">");
				h_txt(h, jstr(tg, "error"));
				h_raw(h, "</small>");
			}
			/* The last whole sample, with the one in progress. */
			n = jget(tg, "samples") != NULL ? ucl_array_size(jget(tg,
			    "samples")) : 0;
			sm = n > 0 ? ucl_array_find_index(jget(tg, "samples"),
			    n - 1) : NULL;
			now = jget(tg, "now");
			if (sm != NULL) {
				h_fmt(h, "</td><td class=\"num\">%s</td><td "
				    "class=\"num\">%s</td><td class=\"num\">%.1f%%"
				    "</td><td class=\"num\">%s / %s</td>",
				    ms(ucl_object_todouble(ucl_array_find_index(
				    sm, 1)), b1, sizeof(b1)), ms(
				    ucl_object_todouble(ucl_array_find_index(sm,
				    2)), b2, sizeof(b2)), ucl_object_todouble(
				    ucl_array_find_index(sm, 3)) * 100, ms(
				    ucl_object_todouble(ucl_array_find_index(sm,
				    4)), b3, sizeof(b3)), ms(ucl_object_todouble(
				    ucl_array_find_index(sm, 5)), (char[32]){ 0 },
				    32));
			} else if (now != NULL && jint(now, "sent", 0) > 0) {
				h_fmt(h, "</td><td class=\"num\">%s</td><td "
				    "class=\"num\">%s</td><td class=\"num\">%.1f%%"
				    "</td><td class=\"dim\">so far</td>", ms(jnum(
				    now, "delay", 0), b1, sizeof(b1)), ms(jnum(now,
				    "ipdv", 0), b2, sizeof(b2)), jnum(now, "loss",
				    0) * 100);
			} else
				h_raw(h, "</td><td class=\"dim\" colspan=\"4\">"
				    "nothing yet</td>");
			h_fmt(h, "<td class=\"num\">%lld / %lld</td><td>",
			    (long long)jint(tg, "received", 0), (long long)jint(
			    tg, "sent", 0));
			spark(h, jget(tg, "samples"));
			h_raw(h, "</td></tr>");
		}
		h_raw(h, "</tbody></table>");
		monitor(h, t);
		h_raw(h, "</div>");
	}
	if (jget(sd.plan, "tunnels") == NULL || ucl_array_size(jget(sd.plan,
	    "tunnels")) == 0)
		h_raw(h, "<p class=\"dim\">No tunnel: a service with end points "
		    "on two edges or more has them.</p>");
	/* The uswe tunnels' keys: each end's, when they were set and the
	 * half-life they turn at; a rotation on its way; one by hand. */
	n = 0;
	it = NULL;
	while ((t = ucl_object_iterate(jget(sd.plan, "tunnels"), &it, true)) !=
	    NULL) {
		const ucl_object_t	*rk;
		bool			 first;

		if (jstr(t, "kind") == NULL || strcmp(jstr(t, "kind"), "uswe") != 0)
			continue;
		if (n++ == 0)
			h_raw(h, "<div class=\"sd-block\"><h3>Keys <small class=\""
			    "dim\">a uswe tunnel's SAs are keyed by the edges "
			    "themselves from a pair each (X25519, HKDF, setkey); the "
			    "console turns them at the half-life of their lifetime, "
			    "both ends in step, inbound before outbound, so no packet "
			    "is lost (Mplify 119 R110, R112)</small></h3><table class"
			    "=\"net sd\"><thead><tr><th>Tunnel</th><th>Edge</th><th>"
			    "Interface</th><th>Public half</th><th>Keyed</th><th>Turn"
			    "</th><th>Rotation</th><th></th></tr></thead><tbody>");
		rk = sd.rekeys != NULL ? jget(sd.rekeys, jstr(t, "id")) : NULL;
		first = true;
		eit = NULL;
		while ((e = ucl_object_iterate(jget(t, "ends"), &eit, true)) !=
		    NULL) {
			const ucl_object_t	*kk = NULL, *x;
			ucl_object_iter_t	 kit = NULL;
			long long		 at, life, left;

			while (sd.paths != NULL && (x = ucl_object_iterate(jget(
			    jget(sd.paths, jstr(e, "edge")), "keys"), &kit, true))
			    != NULL)
				if (jstr(x, "interface") != NULL && jstr(e, "ifname")
				    != NULL && strcmp(jstr(x, "interface"), jstr(e,
				    "ifname")) == 0)
					kk = x;
			h_raw(h, "<tr><td class=\"mono\">");
			if (first)
				h_txt(h, jstr(t, "id"));
			h_raw(h, "</td><td><b>");
			h_txt(h, host_name(jstr(e, "edge")));
			h_raw(h, "</b></td><td class=\"mono\">");
			h_txt(h, jstr(e, "ifname") != NULL ? jstr(e, "ifname") : "");
			h_raw(h, "</td><td class=\"mono dim\" title=\"");
			h_txt(h, kk != NULL && jstr(kk, "public") != NULL ? jstr(kk,
			    "public") : "");
			h_raw(h, "\">");
			if (kk != NULL && jstr(kk, "public") != NULL)
				h_fmt(h, "%.12s…%s", jstr(kk, "public"), jstr(kk, "next")
				    != NULL ? " <span class=\"chip\">next made</span>" :
				    "");
			else
				h_raw(h, "<span class=\"dim\">no pair yet</span>");
			h_raw(h, "</td><td>");
			at = kk != NULL ? jint(kk, "keyed_at", 0) : 0;
			life = kk != NULL ? jint(kk, "lifetime", 0) : 0;
			if (at > 0) {
				fmt_age(age, sizeof(age), (double)at * 1000);
				h_txt(h, age);
			}
			h_raw(h, "</td><td>");
			if (at > 0 && life > 0) {
				left = at + life / 2 - (long long)(arc_now() / 1000);
				if (left <= 0)
					h_raw(h, "<span class=\"chip warn\">due</span>");
				else
					h_fmt(h, "in %lld min", (left + 59) / 60);
			}
			if (kk != NULL && jbool(kk, "pending"))
				h_raw(h, " <span class=\"chip warn\">half done</span>");
			h_raw(h, "</td><td>");
			if (first && rk != NULL && jstr(rk, "state") != NULL) {
				fmt_age(age, sizeof(age), (double)jint(rk, "at", 0) *
				    1000);
				h_fmt(h, "<span class=\"chip %s\">%s</span> <span class"
				    "=\"dim\">%s, %s</span>", strcmp(jstr(rk, "state"),
				    "done") == 0 ? "st-up" : strcmp(jstr(rk, "state"),
				    "failed") == 0 ? "st-down" : "warn", jstr(rk,
				    "state"), jstr(rk, "step") != NULL ? jstr(rk,
				    "step") : "", age);
				if (jstr(rk, "why") != NULL) {
					h_raw(h, "<br><small class=\"dim\">");
					h_txt(h, jstr(rk, "why"));
					h_raw(h, "</small>");
				}
			}
			h_raw(h, "</td><td class=\"right\">");
			if (first) {
				h_raw(h, "<button class=\"ghost small\" data-act=\""
				    "sd-rekey\"");
				h_attr(h, "data-arg", jstr(t, "id"));
				h_raw(h, " title=\"A new pair on each end, the SAs "
				    "from them put in beside the old, the old taken out"
				    "\">turn the keys</button>");
			}
			h_raw(h, "</td></tr>");
			first = false;
		}
	}
	if (n > 0)
		h_raw(h, "</tbody></table></div>");
	/* The steering: each edge's far prefixes, by which tunnel each goes
	 * now, and the others in the order the console gave. */
	h_raw(h, "<div class=\"sd-block\"><h3>Steering <small class=\"dim\">"
	    "each far prefix by the first tunnel of its policy's order that "
	    "is not down, chosen on the edge; the order is the console's, by "
	    "the policy's performance criteria</small></h3><table class=\"net "
	    "sd\"><thead><tr><th>Edge</th><th>Prefix</th><th>Policy</th><th>"
	    "Goes by</th><th>Then</th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while (sd.paths != NULL && (f = ucl_object_iterate(sd.paths, &it,
	    true)) != NULL) {
		fit = NULL;
		while ((e = ucl_object_iterate(jget(f, "steer"), &fit, true)) !=
		    NULL) {
			const ucl_object_t	*c;
			ucl_object_iter_t	 cit;
			long long		 chosen;
			int			 i;

			n++;
			chosen = jint(e, "chosen", -1);
			h_raw(h, "<tr><td><b>");
			h_txt(h, host_name(ucl_object_key(f)));
			h_raw(h, "</b></td><td class=\"mono\">");
			h_txt(h, jstr(e, "prefix"));
			h_raw(h, "</td><td class=\"mono dim\">");
			h_txt(h, jstr(e, "table") != NULL ? jstr(e, "table") : "");
			h_raw(h, "</td><td>");
			if (chosen < 0)
				h_raw(h, "<span class=\"chip st-down\">no tunnel "
				    "up</span>");
			h_raw(h, "</td><td class=\"dim\">");
			i = 0;
			cit = NULL;
			while ((c = ucl_object_iterate(jget(e, "candidates"),
			    &cit, true)) != NULL) {
				if (i == chosen) {
					/* Into the Goes by cell: drawn in place
					 * of the empty one above. */
					;
				}
				h_fmt(h, "%s<span class=\"%s\">", i > 0 ? ", " : "",
				    i == chosen ? "chosen" : "");
				h_txt(h, jstr(c, "id"));
				h_fmt(h, " <small>%s</small></span>", jstr(c,
				    "state") != NULL ? jstr(c, "state") : "");
				i++;
			}
			h_raw(h, "</td></tr>");
		}
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"5\" class=\"dim\">None: a policy "
		    "with a far prefix to reach has entries once applied.</td>"
		    "</tr>");
	h_raw(h, "</tbody></table></div>");
	/* The faults of the day, as each edge keeps them (Mplify 119
	 * §11.3): type, severity, what it is of, who saw it; the open
	 * ones first, then the cleared. */
	h_raw(h, "<div class=\"sd-block\"><h3>Faults <small class=\"dim\">of "
	    "the day, as the edges keep them: tunnels and BFD, BGP "
	    "neighbours, threshold crossings, CPU and memory; open first"
	    "</small></h3><ul class=\"sd-faults\">");
	nf = 0;
	for (k = 0; k < 2; k++) {
		it = NULL;
		while (sd.faults != NULL && (f = ucl_object_iterate(sd.faults,
		    &it, true)) != NULL) {
			fit = NULL;
			while ((e = ucl_object_iterate(f, &fit, true)) != NULL) {
				if (jbool(e, "cleared") != (k == 1))
					continue;
				if (nf++ >= 60)
					break;
				fmt_age(age, sizeof(age), (double)jint(e, k == 1 ?
				    "cleared_at" : "t", 0) * 1000);
				h_fmt(h, "<li class=\"st-%s sev-%s\"><span class=\"led\">"
				    "</span><span class=\"chip\">%s</span> <b>", k == 1
				    ? "up" : "down", jstr(e, "severity") != NULL ?
				    jstr(e, "severity") : "", jstr(e, "severity") !=
				    NULL ? jstr(e, "severity") : "");
				h_txt(h, host_name(ucl_object_key(f)));
				h_raw(h, "</b> <span class=\"dim\">");
				h_txt(h, jstr(e, "type") != NULL ? jstr(e, "type") :
				    "");
				h_raw(h, "</span> <span class=\"mono\">");
				h_txt(h, jstr(e, "object") != NULL ? jstr(e, "object")
				    : "");
				h_raw(h, "</span> ");
				h_txt(h, jstr(e, "description") != NULL ? jstr(e,
				    "description") : "");
				h_raw(h, " <span class=\"dim\">");
				h_txt(h, age);
				if (jstr(e, "by") != NULL) {
					h_raw(h, " · by ");
					h_txt(h, jstr(e, "by"));
				}
				h_raw(h, "</span></li>");
			}
		}
	}
	(void)eit;
	(void)d;
	if (nf == 0)
		h_raw(h, "<li class=\"dim\">None.</li>");
	h_raw(h, "</ul></div>");
	/* The hosts' addresses at the UNIs: each edge's dnsmasq instances,
	 * a service each, and the leases they gave. */
	h_raw(h, "<div class=\"sd-block\"><h3>Addresses given <small class=\"dim"
	    "\">DHCP at the UNIs: dnsmasq, an instance of each service on each "
	    "edge, in the service's table; the leases it gave</small></h3><table "
	    "class=\"net sd sd-dhcp\"><thead><tr><th>Edge</th><th>Instance</th>"
	    "<th>State</th><th>Address</th><th>Host</th><th>Client</th><th>"
	    "Expires</th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while (sd.paths != NULL && (f = ucl_object_iterate(sd.paths, &it,
	    true)) != NULL) {
		const ucl_object_t	*di, *ls;
		ucl_object_iter_t	 dit, lit;
		unsigned int		 nl;

		dit = NULL;
		while ((di = ucl_object_iterate(jget(f, "dhcp"), &dit, true)) !=
		    NULL) {
			nl = jget(di, "leases") != NULL ? ucl_array_size(jget(di,
			    "leases")) : 0;
			n++;
			h_raw(h, "<tr><td><b>");
			h_txt(h, host_name(ucl_object_key(f)));
			h_fmt(h, "</b></td><td class=\"mono\">%s <span class=\"dim\">"
			    "fib %lld</span></td><td><span class=\"chip st-%s\">%s"
			    "</span></td><td class=\"dim\" colspan=\"4\">%u lease%s"
			    "</td></tr>", jstr(di, "name"), (long long)jint(di,
			    "fib", 0), jbool(di, "running") ? "up" : "down", jbool(
			    di, "running") ? "running" : "not running", nl, nl == 1
			    ? "" : "s");
			lit = NULL;
			while ((ls = ucl_object_iterate(jget(di, "leases"), &lit,
			    true)) != NULL) {
				fmt_age(age, sizeof(age), (double)jint(ls, "expires",
				    0) * 1000);
				h_raw(h, "<tr><td></td><td></td><td></td><td class=\""
				    "mono\">");
				h_txt(h, jstr(ls, "address") != NULL ? jstr(ls,
				    "address") : "");
				h_raw(h, "</td><td>");
				h_txt(h, jstr(ls, "name") != NULL ? jstr(ls, "name") :
				    "");
				h_raw(h, "</td><td class=\"mono dim\">");
				h_txt(h, jstr(ls, "id") != NULL ? jstr(ls, "id") : "");
				h_raw(h, "</td><td class=\"dim\">");
				/* An expiry ahead reads as "in"; fmt_age says ago. */
				if ((double)jint(ls, "expires", 0) * 1000 > arc_now())
					h_fmt(h, "in %.0f min", ((double)jint(ls,
					    "expires", 0) * 1000 - arc_now()) / 60000);
				else
					h_txt(h, age);
				h_raw(h, "</td></tr>");
			}
		}
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"7\" class=\"dim\">No DHCP at a UNI: an "
		    "end point whose hosts are addressed by DHCP gets an instance "
		    "once applied.</td></tr>");
	h_raw(h, "</tbody></table></div>");
	/* Routing at the UNIs: each edge's BIRD instances, a service each,
	 * and their protocols as birdc lists them. */
	h_raw(h, "<div class=\"sd-block\"><h3>Routing <small class=\"dim\">BGP "
	    "or OSPF with the subscriber at a UNI, iBGP between the edges: a "
	    "BIRD instance of each service on each edge, in the service's "
	    "table</small></h3><table class=\"net sd sd-bird\"><thead><tr><th>"
	    "Edge</th><th>Instance</th><th>Protocol</th><th>State</th><th>"
	    "Info</th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while (sd.paths != NULL && (f = ucl_object_iterate(sd.paths, &it,
	    true)) != NULL) {
		fit = NULL;
		while ((e = ucl_object_iterate(jget(f, "bird"), &fit, true)) !=
		    NULL) {
			const ucl_object_t	*pr;
			ucl_object_iter_t	 pit;
			bool			 first = true;

			n++;
			pit = NULL;
			while ((pr = ucl_object_iterate(jget(e, "protocols"), &pit,
			    true)) != NULL || first) {
				h_raw(h, "<tr><td><b>");
				h_txt(h, first ? host_name(ucl_object_key(f)) : "");
				h_raw(h, "</b></td><td class=\"mono\">");
				if (first) {
					h_txt(h, jstr(e, "name"));
					h_fmt(h, " <small class=\"dim\">fib %lld%s"
					    "</small>", jint(e, "fib", 0), jbool(e,
					    "running") ? "" : ", not running");
				}
				h_raw(h, "</td><td class=\"mono\">");
				if (pr != NULL) {
					h_txt(h, jstr(pr, "name") != NULL ? jstr(pr,
					    "name") : "");
					h_raw(h, " <small class=\"dim\">");
					h_txt(h, jstr(pr, "proto") != NULL ? jstr(pr,
					    "proto") : "");
					h_raw(h, "</small>");
				}
				h_fmt(h, "</td><td><span class=\"chip st-%s\">", pr !=
				    NULL && jstr(pr, "state") != NULL && strcmp(jstr(
				    pr, "state"), "up") == 0 ? "up" : "down");
				h_txt(h, pr != NULL && jstr(pr, "state") != NULL ?
				    jstr(pr, "state") : jbool(e, "running") ? "no "
				    "protocol" : "down");
				h_raw(h, "</span></td><td class=\"dim\">");
				h_txt(h, pr != NULL && jstr(pr, "info") != NULL ? jstr(
				    pr, "info") : "");
				h_raw(h, "</td></tr>");
				first = false;
				if (pr == NULL)
					break;
			}
		}
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"5\" class=\"dim\">None: a UNI with "
		    "bgp or ospf in its service has one once applied.</td></tr>");
	h_raw(h, "</tbody></table></div>");
}

/* ---- The document ----------------------------------------------------- */

/*
 * Intrusion detection on the edges (SASE-4): each edge's Suricata
 * instances, with how many alerts each read, and the latest alerts of
 * them all, newest first as each edge keeps them.
 */
static void
view_ids(struct html *h)
{
	static const struct tcol	cols[] = {
		{ "Time", "time", false }, { "Edge", "edge", false },
		{ "Signature", "signature", false }, { "Severity", "severity",
		true }, { "From", "src", false }, { "To", "dst", false },
		{ "Interface", "iface", false },
	};
	const ucl_object_t	*v, *di, *a, **rows;
	ucl_object_iter_t	 it, dit, ait;
	ucl_object_t		*all, *c;
	int			 n, r;

	h_raw(h, "<div class=\"sd-block\"><h3>Intrusion detection <small "
	    "class=\"dim\">Suricata on each edge, a plugin installed there by "
	    "hand, an instance of each service whose policies have ids, "
	    "watching the service's UNIs by libpcap (detect), or in their "
	    "way, by ipfw's divert(4) (prevent); each alert comes as an "
	    "event, sdwan-ids</small></h3><table class=\"net sd\"><thead><tr>"
	    "<th>Edge</th><th>Instance</th><th>Interfaces</th><th>Mode</th>"
	    "<th>State</th><th>Alerts</th></tr></thead><tbody>");
	n = 0;
	all = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while (sd.paths != NULL && (v = ucl_object_iterate(sd.paths, &it, true))
	    != NULL) {
		dit = NULL;
		while ((di = ucl_object_iterate(jget(v, "ids"), &dit, true)) !=
		    NULL) {
			const ucl_object_t	*f;
			ucl_object_iter_t	 fit = NULL;

			n++;
			h_raw(h, "<tr><td><b>");
			h_txt(h, host_name(ucl_object_key(v)));
			h_raw(h, "</b></td><td class=\"mono\">");
			h_txt(h, jstr(di, "name"));
			h_raw(h, "</td><td class=\"mono\">");
			while ((f = ucl_object_iterate(jget(di, "interfaces"),
			    &fit, true)) != NULL) {
				h_txt(h, ucl_object_tostring_forced(f));
				h_raw(h, " ");
			}
			h_raw(h, "</td><td>");
			if (jint(di, "divert", 0) > 0)
				h_fmt(h, "prevent <small class=\"dim\">ipfw divert "
				    "%lld</small>", (long long)jint(di, "divert", 0));
			else
				h_raw(h, "detect <small class=\"dim\">libpcap"
				    "</small>");
			h_fmt(h, "</td><td><span class=\"chip st-%s\">%s</span>"
			    "</td><td>%lld</td></tr>", jbool(di, "running") ? "up" :
			    "down", jbool(di, "running") ? "running" : "not running",
			    (long long)jint(di, "alerts_seen", 0));
			ait = NULL;
			while ((a = ucl_object_iterate(jget(di, "alerts"), &ait,
			    true)) != NULL) {
				c = ucl_object_copy(a);
				ucl_object_replace_key(c, ucl_object_fromstring(
				    host_name(ucl_object_key(v))), "edge", 0, false);
				ucl_array_append(all, c);
			}
		}
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"6\" class=\"dim\">None: no policy "
		    "has ids, or nothing is applied yet.</td></tr>");
	h_raw(h, "</tbody></table>");
	if (ucl_array_size(all) > 0) {
		h_raw(h, "<h4>Latest alerts</h4><table class=\"net sd\">");
		tbl_head(h, "sd-ids", cols, 7, 0);
		h_raw(h, "<tbody>");
		rows = tbl_rows("sd-ids", all, cols, 7, app.filter);
		for (r = 0; (a = rows[r]) != NULL; r++) {
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(a, "time") != NULL ? jstr(a, "time") : "");
			h_raw(h, "</td><td>");
			h_txt(h, jstr(a, "edge"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(a, "signature") != NULL ? jstr(a,
			    "signature") : "");
			h_fmt(h, " <small class=\"dim\">sid %lld</small>",
			    (long long)jint(a, "sid", 0));
			h_fmt(h, "</td><td><span class=\"chip st-%s\">%lld</span>"
			    "</td><td class=\"mono\">", jint(a, "severity", 3) <= 1 ?
			    "down" : "half", (long long)jint(a, "severity", 0));
			h_txt(h, jstr(a, "src") != NULL ? jstr(a, "src") : "");
			h_fmt(h, ":%lld</td><td class=\"mono\">", (long long)jint(
			    a, "sport", 0));
			h_txt(h, jstr(a, "dst") != NULL ? jstr(a, "dst") : "");
			h_fmt(h, ":%lld <small class=\"dim\">", (long long)jint(a,
			    "dport", 0));
			h_txt(h, jstr(a, "proto") != NULL ? jstr(a, "proto") : "");
			h_raw(h, "</small></td><td class=\"mono\">");
			h_txt(h, jstr(a, "iface") != NULL ? jstr(a, "iface") : "");
			h_raw(h, "</td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table>");
	}
	ucl_object_unref(all);
	h_raw(h, "</div>");
}

/*
 * The service in MEF 118.1's terms (SASE-5): the Zero Trust Framework's
 * parts as Arcana has them, then the Access Control Policies, Subject
 * Actor to Target Actor, as the policy map gives them, the Policy End
 * Points, the Continuous Monitoring and the audit trail.
 */
static void
view_zt(struct html *h, const ucl_object_t *sw)
{
	static const struct tcol	acols[] = {
		{ "When", "when", false }, { "Event", "event", false },
		{ "Policy Action", "action", false }, { "Policy", "policy",
		false }, { "Where", "where", false }, { "Who", "who", false },
		{ "Why", "why", false },
	};
	const ucl_object_t	*z, *pm, *pol, *cr, *adz, *e, *ep, *a, **rows;
	ucl_object_iter_t	 it, pit, eit;
	const char		*zn, *pn, *ing;
	char			 tgt[600];
	int			 nid, n, r;

	h_raw(h, "<div class=\"sd-block\"><h3>Zero trust <small class=\"dim\">"
	    "MEF 118.1: Subject Actors reach Target Actors only as a Policy "
	    "Allows; with no Policy, they are Blocked</small></h3><p class=\""
	    "dim\">The console is the Policy Administration Point (the "
	    "document), the Policy Decision Point (its plan) and the Policy "
	    "Information Point (identities, sessions, lists); each edge is a "
	    "Policy End Point, its Policy Enforcement Point ipfw with the "
	    "functions below. The Identity Provider is the console: an "
	    "identity is authenticated by its WireGuard key, and its Role "
	    "is its zone. The console's users, each by a security key, are "
	    "System Administrators: they alone change the Policies.</p>");
	/* Access Control Policies: a zone's policies, and the end points'
	 * own map, each a pair with its Policy Action. */
	h_raw(h, "<h4>Access Control Policies <small class=\"dim\">Subject "
	    "Actor to Target Actor, by application flow</small></h4><table "
	    "class=\"net sd\"><thead><tr><th>Subject Actor</th><th>Application "
	    "flow</th><th>Target Actors</th><th>Policy Action</th><th>Policy"
	    "</th><th>Security policy</th><th>Where</th></tr></thead><tbody>");
	n = 0;
	for (int pass = 0; pass < 2; pass++) {
		it = NULL;
		while ((pass == 0 && (z = ucl_object_iterate(jget(sw, "zones"),
		    &it, true)) != NULL) || (pass == 1 && (z =
		    ucl_object_iterate(jget(sw, "end_points"), &it, true)) !=
		    NULL)) {
			pit = NULL;
			while ((pm = ucl_object_iterate(jget(z, pass == 0 ?
			    "policies" : "policy_map"), &pit, true)) != NULL) {
				zn = pass == 0 ? jstr(z, "name") : jstr(pm, "zone");
				pn = pass == 0 ? jstr(pm, "policy") : jstr(pm,
				    "ingress");
				ing = pn;
				pol = pn != NULL ? jfind(jget(sw, "policies"),
				    "name", pn) : NULL;
				cr = jget(pol, "criteria");
				/* Who the Subject is: the zone's hosts, and
				 * the identities whose Role it is. */
				nid = 0;
				eit = NULL;
				while (sd.identities != NULL && (e =
				    ucl_object_iterate(jget(sd.identities,
				    "identities"), &eit, true)) != NULL)
					if (jstr(e, "zone") != NULL && zn != NULL &&
					    strcmp(jstr(e, "zone"), zn) == 0 &&
					    jstr(e, "swvc") != NULL && strcmp(jstr(e,
					    "swvc"), jstr(sw, "id")) == 0)
						nid++;
				/* The Targets: the destination zones the
				 * policy allows (Self when it says none,
				 * R62), and the Internet where it breaks
				 * out. */
				tgt[0] = '\0';
				adz = jget(cr, "allowed-destination-zones");
				if (adz != NULL && ucl_object_type(adz) ==
				    UCL_STRING)
					snprintf(tgt, sizeof(tgt), "every zone");
				else if (adz != NULL) {
					const ucl_object_t	*d;
					ucl_object_iter_t	 dit = NULL;

					while ((d = ucl_object_iterate(adz, &dit,
					    true)) != NULL)
						snprintf(tgt + strlen(tgt), sizeof(tgt) -
						    strlen(tgt), "%s%s", tgt[0] != '\0' ?
						    ", " : "", strcmp(
						    ucl_object_tostring_forced(d),
						    "Self") == 0 && zn != NULL ? zn :
						    ucl_object_tostring_forced(d));
				} else if (pol != NULL && zn != NULL)
					snprintf(tgt, sizeof(tgt), "%s", zn);
				if (jstr(cr, "internet-breakout") != NULL &&
				    strcmp(jstr(cr, "internet-breakout"),
				    "disabled") != 0)
					snprintf(tgt + strlen(tgt), sizeof(tgt) -
					    strlen(tgt), "%sthe Internet", tgt[0] !=
					    '\0' ? ", " : "");
				n++;
				h_raw(h, "<tr><td><b>");
				h_txt(h, zn != NULL ? zn : "?");
				h_raw(h, "</b>");
				if (nid > 0)
					h_fmt(h, " <small class=\"dim\">and %d "
					    "identit%s</small>", nid, nid == 1 ? "y" :
					    "ies");
				h_raw(h, "</td><td>");
				h_txt(h, jstr(pm, "app") != NULL ? jstr(pm, "app") :
				    "");
				h_raw(h, "</td><td>");
				h_txt(h, tgt[0] != '\0' ? tgt : "none");
				if (pol != NULL)
					h_raw(h, "</td><td><span class=\"chip st-up\">"
					    "Allow</span></td><td>");
				else
					h_raw(h, "</td><td><span class=\"chip "
					    "st-down\">Block</span></td><td>");
				h_txt(h, ing != NULL ? ing : "none");
				h_raw(h, "</td><td>");
				if (jstr(cr, "af-security-ingress") != NULL)
					h_txt(h, jstr(cr, "af-security-ingress"));
				else
					h_raw(h, "<span class=\"dim\">—</span>");
				h_raw(h, "</td><td>");
				if (pass == 0)
					h_raw(h, "every end point");
				else {
					h_raw(h, "end point ");
					h_txt(h, jstr(z, "id"));
				}
				h_raw(h, "</td></tr>");
			}
		}
	}
	h_fmt(h, "<tr class=\"dim\"><td>any other</td><td>any</td><td>any</td>"
	    "<td><span class=\"chip st-down\">Block</span></td><td colspan=\"3\">"
	    "no Policy: Blocked (§7)%s</td></tr></tbody></table>", n == 0 ?
	    "; this service has none yet" : "");
	/* The Policy End Points: each edge of the service, its
	 * enforcement as the agent reads. */
	h_raw(h, "<h4>Policy End Points <small class=\"dim\">the edges, "
	    "where the Policies are enforced</small></h4><table class=\"net "
	    "sd\"><thead><tr><th>Edge</th><th>Policy Enforcement</th></tr>"
	    "</thead><tbody>");
	n = 0;
	it = NULL;
	while ((ep = ucl_object_iterate(jget(sd.doc, "edges"), &it, true)) !=
	    NULL) {
		const ucl_object_t	*st = sd.paths != NULL ? jget(sd.paths,
		    jstr(ep, "server")) : NULL, *x;
		ucl_object_iter_t	 xit;
		bool			 here = false;

		eit = NULL;
		while ((e = ucl_object_iterate(jget(sw, "end_points"), &eit,
		    true)) != NULL)
			if (jstr(e, "edge") != NULL && strcmp(jstr(e, "edge"),
			    jstr(ep, "server")) == 0)
				here = true;
		if (!here)
			continue;
		n++;
		h_raw(h, "<tr><td><b>");
		h_txt(h, host_name(jstr(ep, "server")));
		h_fmt(h, "</b></td><td>ipfw, set 30, %lld rule%s", (long long)jint(
		    jget(st, "rules"), "rules", 0), jint(jget(st, "rules"),
		    "rules", 0) == 1 ? "" : "s");
		xit = NULL;
		while ((x = ucl_object_iterate(jget(st, "dns"), &xit, true)) !=
		    NULL)
			h_raw(h, "; unbound, DNS filter");
		xit = NULL;
		while ((x = ucl_object_iterate(jget(st, "proxy"), &xit, true)) !=
		    NULL)
			h_fmt(h, "; Squid, URL filter%s", jbool(x, "icap") ?
			    "; c-icap and ClamAV, malware" : "");
		xit = NULL;
		while ((x = ucl_object_iterate(jget(st, "ids"), &xit, true)) !=
		    NULL)
			h_fmt(h, "; Suricata, %s", jint(x, "divert", 0) > 0 ?
			    "intrusion prevented" : "intrusion detected");
		if (st == NULL)
			h_raw(h, " <span class=\"dim\">(not read yet)</span>");
		h_raw(h, "</td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"2\" class=\"dim\">None: the service "
		    "has no end point yet.</td></tr>");
	h_raw(h, "</tbody></table>");
	/* Continuous Monitoring: by time, the remote end points'
	 * re-authorisation; by event, what the edges log and alert. */
	h_raw(h, "<h4>Continuous Monitoring <small class=\"dim\">§18</small>"
	    "</h4><ul class=\"sd-list\">");
	it = NULL;
	n = 0;
	while ((ep = ucl_object_iterate(jget(sw, "end_points"), &it, true)) !=
	    NULL) {
		if ((a = jget(ep, "remote")) == NULL)
			continue;
		n++;
		h_raw(h, "<li><b>By time</b>, end point ");
		h_txt(h, jstr(ep, "id"));
		if (jint(a, "reauth", 0) > 0)
			h_fmt(h, ": every identity authenticates again after "
			    "%lld min (t), Blocked until then", (long long)jint(a,
			    "reauth", 0) / 60);
		else
			h_raw(h, ": none (t is None); a revoked identity is "
			    "Blocked at once");
		h_raw(h, "</li>");
	}
	if (n == 0)
		h_raw(h, "<li><b>By time</b>: none, the service has no remote "
		    "end point</li>");
	h_raw(h, "<li><b>By event</b>: each deny a policy logs (the record "
	    "below), each Suricata alert, each fault, as events of the edges"
	    "</li></ul>");
	/* The audit trail: an Audit Event for each Policy Action, the
	 * chain of it checked by the console. */
	h_raw(h, "<h4>Audit Events <small class=\"dim\">§13.1: each Policy "
	    "Action and each change to the Policies, kept by the console, "
	    "each event's HMAC chained to the one before</small><span class=\""
	    "pane-actions\"><input type=\"search\" data-input=\""
	    "sd-audit-filter\" placeholder=\"filter: an identity, a zone, a "
	    "key\"");
	h_attr(h, "value", sd.audit_filter);
	h_raw(h, "><a class=\"ghost small\" href=\"/api/sdwan/audit.csv\" "
	    "download=\"sdwan-audit.csv\" title=\"The audit trail as CSV\">CSV"
	    "</a></span></h4>");
	if (sd.audit == NULL)
		h_raw(h, "<p class=\"dim\">Reading…</p>");
	else {
		if (jbool(sd.audit, "intact"))
			h_fmt(h, "<p><span class=\"chip st-up\">intact</span> "
			    "<span class=\"dim\">%lld event%s, the chain whole"
			    "</span></p>", (long long)jint(sd.audit, "count", 0),
			    jint(sd.audit, "count", 0) == 1 ? "" : "s");
		else
			h_fmt(h, "<p><span class=\"chip st-down\">altered</span> "
			    "the chain breaks at event %lld: it was changed, or "
			    "one was taken away or put in, after it was "
			    "written</p>", (long long)jint(sd.audit, "broken_at",
			    0));
		h_raw(h, "<table class=\"net sd\">");
		tbl_head(h, "sd-audit", acols, 7, 0);
		h_raw(h, "<tbody>");
		rows = tbl_rows("sd-audit", jget(sd.audit, "events"), acols, 7,
		    sd.audit_filter[0] != '\0' ? sd.audit_filter : app.filter);
		for (r = 0; (a = rows[r]) != NULL; r++) {
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(a, "when") != NULL ? jstr(a, "when") : "");
			h_raw(h, "</td><td>");
			h_txt(h, jstr(a, "event") != NULL ? jstr(a, "event") : "");
			h_fmt(h, "</td><td><span class=\"chip st-%s\">",
			    jstr(a, "action") != NULL && strcmp(jstr(a, "action"),
			    "Block") == 0 ? "down" : jstr(a, "action") != NULL &&
			    strcmp(jstr(a, "action"), "Allow") == 0 ? "up" :
			    "half");
			h_txt(h, jstr(a, "action") != NULL ? jstr(a, "action") :
			    "");
			h_raw(h, "</span></td><td>");
			h_txt(h, jstr(a, "policy") != NULL ? jstr(a, "policy") :
			    "");
			h_raw(h, "</td><td>");
			h_txt(h, jstr(a, "where") != NULL ? jstr(a, "where") : "");
			h_raw(h, "</td><td>");
			h_txt(h, jstr(a, "who") != NULL ? jstr(a, "who") : "");
			h_raw(h, "</td><td>");
			h_txt(h, jstr(a, "why") != NULL ? jstr(a, "why") : "");
			h_raw(h, "<small class=\"dim\"> ");
			h_txt(h, jstr(a, "how") != NULL ? jstr(a, "how") : "");
			h_raw(h, "</small></td></tr>");
		}
		if (r == 0)
			h_raw(h, "<tr><td colspan=\"7\" class=\"dim\">None yet."
			    "</td></tr>");
		free(rows);
		h_raw(h, "</tbody></table>");
	}
	h_raw(h, "</div>");
}

/*
 * The security policies of the service shown (MEF 88): each a name and
 * its criteria, where a policy's af-security-ingress or -egress names
 * it; what each denied comes with the counts (SASE-1).
 */
static void
view_security(struct html *h)
{
	const ucl_object_t	*sw, *v, *cr, *b, *pol, *pc;
	ucl_object_iter_t	 it, pit;
	char			 age[32];
	int			 n;

	if ((sw = swvc_shown()) == NULL) {
		h_raw(h, "<div class=\"empty\"><h2>No service yet</h2><p>The "
		    "security policies are a service's: what its networks may "
		    "reach, which names they may look up, what is scanned. Add "
		    "a service first.</p><button class=\"primary\" data-act=\""
		    "sd-go\" data-arg=\"service\">+ service</button></div>");
		return;
	}
	if (ucl_array_size(jget(sd.doc, "swvcs")) > 1) {
		h_raw(h, "<div class=\"toolbar\"><label class=\"inline\">"
		    "Service <select data-input=\"sd-swvc\">");
		it = NULL;
		while ((v = ucl_object_iterate(jget(sd.doc, "swvcs"), &it,
		    true)) != NULL) {
			h_raw(h, "<option");
			h_attr(h, "value", jstr(v, "id"));
			if (strcmp(jstr(v, "id"), jstr(sw, "id")) == 0)
				h_raw(h, " selected");
			h_raw(h, ">");
			h_txt(h, jstr(v, "id"));
			h_raw(h, "</option>");
		}
		h_raw(h, "</select></label></div>");
	}
	view_zt(h, sw);
	h_raw(h, "<h2 class=\"sd-sect\">Security Functions</h2>");
	h_raw(h, "<div class=\"sd-block\"><h3>Security policies <small class=\""
	    "dim\">MEF 88, by name (§9.10): addresses allowed and denied "
	    "(ipfw tables), domains denied and DNS kept to the provider's "
	    "resolver (unbound), a rate limit (dummynet), a log; a flow's "
	    "policy names one by af-security-ingress or -egress; what each "
	    "denied, counted on the edges' rules since they were made</small>"
	    "<span class=\"pane-actions\"><button class=\"ghost small\" data-act="
	    "\"sd-secpol-add\">+ policy</button></span></h3><table class=\"net "
	    "sd\"><thead><tr><th>Name</th><th>Addresses</th><th>Denied</th><th>"
	    "DNS</th><th>Rate</th><th>Log</th><th>Malware</th><th>IDS</th><th>"
	    "Named by</th>"
	    "<th></th></tr>"
	    "</thead><tbody>");
	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(jget(sw, "security_policies"), &it,
	    true)) != NULL) {
		const ucl_object_t	*f, *cn;
		ucl_object_iter_t	 fit, cit;
		char			 tbl[64];
		long long		 pkts = 0, bytes = 0;

		/* The deny rules of this policy, by its tables' names, on
		 * every edge: sw<fib>_s<n>d4 and d6. */
		snprintf(tbl, sizeof(tbl), "table(sw%lld_s%dd", (long long)jint(sw,
		    "fib", 0), n);
		fit = NULL;
		while (sd.paths != NULL && (f = ucl_object_iterate(sd.paths, &fit,
		    true)) != NULL) {
			cit = NULL;
			while ((cn = ucl_object_iterate(jget(jget(f, "rules"),
			    "counters"), &cit, true)) != NULL)
				if (jstr(cn, "text") != NULL && strncmp(jstr(cn, "text"),
				    "deny", 4) == 0 && strstr(jstr(cn, "text"), tbl) !=
				    NULL) {
					pkts += jint(cn, "pkts", 0);
					bytes += jint(cn, "bytes", 0);
				}
		}
		n++;
		cr = jget(v, "criteria");
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(v, "name"));
		h_raw(h, "</td><td>");
		b = jget(cr, "ip-block");
		if (b != NULL) {
			h_fmt(h, "<span class=\"chip st-up\">%u allowed</span> <span "
			    "class=\"chip st-down\">%u denied</span>", jget(b,
			    "allow") != NULL ? ucl_array_size(jget(b, "allow")) : 0,
			    jget(b, "deny") != NULL ? ucl_array_size(jget(b, "deny"))
			    : 0);
		} else
			h_raw(h, "<span class=\"dim\">—</span>");
		h_raw(h, "</td><td>");
		if (pkts > 0)
			h_fmt(h, "<b>%lld</b> packet%s, %lld bytes", pkts, pkts == 1 ?
			    "" : "s", bytes);
		else
			h_raw(h, "<span class=\"dim\">none</span>");
		h_raw(h, "</td><td>");
		b = jget(cr, "dns-domain-filter");
		if (b != NULL)
			h_fmt(h, "<span class=\"chip st-down\">%u domain%s denied"
			    "</span> ", jget(b, "deny") != NULL ? ucl_array_size(
			    jget(b, "deny")) : 0, jget(b, "deny") != NULL &&
			    ucl_array_size(jget(b, "deny")) == 1 ? "" : "s");
		if (jbool(cr, "dns-protocol-filter"))
			h_raw(h, "<span class=\"chip\">provider's resolver only"
			    "</span>");
		if (b == NULL && !jbool(cr, "dns-protocol-filter"))
			h_raw(h, "<span class=\"dim\">—</span>");
		h_raw(h, "</td><td>");
		if (jget(cr, "rate-limit") != NULL)
			h_fmt(h, "%lld kbit/s", jint(cr, "rate-limit", 0) / 1000);
		else
			h_raw(h, "<span class=\"dim\">—</span>");
		h_raw(h, "</td><td>");
		h_raw(h, jbool(cr, "log") ? "yes" : "<span class=\"dim\">no</span>");
		h_raw(h, "</td><td>");
		h_raw(h, jbool(cr, "malware") ? "scanned" : "<span class=\"dim\">"
		    "no</span>");
		h_raw(h, "</td><td>");
		if ((b = jget(cr, "ids")) != NULL) {
			unsigned	nr = jget(b, "rules") != NULL ?
			    ucl_array_size(jget(b, "rules")) : 0;

			h_fmt(h, "%s, %u rule%s%s", jstr(b, "mode") != NULL ?
			    jstr(b, "mode") : "detect", nr, nr == 1 ? "" : "s",
			    jbool(b, "ruleset") ? " and the ruleset" : "");
		} else
			h_raw(h, "<span class=\"dim\">no</span>");
		h_raw(h, "</td><td class=\"dim\">");
		pit = NULL;
		while ((pol = ucl_object_iterate(jget(sw, "policies"), &pit, true))
		    != NULL) {
			pc = jget(pol, "criteria");
			if ((jstr(pc, "af-security-ingress") != NULL && strcmp(jstr(
			    pc, "af-security-ingress"), jstr(v, "name")) == 0) ||
			    (jstr(pc, "af-security-egress") != NULL && strcmp(jstr(
			    pc, "af-security-egress"), jstr(v, "name")) == 0)) {
				h_txt(h, jstr(pol, "name"));
				h_raw(h, " ");
			}
		}
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" data-act=\""
		    "sd-secpol-edit\" title=\"Change it\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "sd-secpol-del\" title=\"Take the policy away\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"10\" class=\"dim\">None yet.</td></tr>");
	h_raw(h, "</tbody></table></div>");
	/* The lists the policies name: feeds the console fetches, and
	 * pasted ones, each as kept with its version. */
	h_fmt(h, "<div class=\"sd-block\"><h3>Lists <small class=\"dim\">named "
	    "by a policy's ip-block or dns-domain-filter: feeds the console's "
	    "host fetches every %lld hours with the base system's fetch(3), "
	    "and lists pasted here; prefixes go to the policy's tables, "
	    "domains to its DNS filter; a feed that fails keeps its last"
	    "</small><span class=\"pane-actions\"><button class=\"ghost small\" "
	    "data-act=\"sd-list-add\">+ list</button><button class=\"ghost "
	    "small\" data-act=\"sd-lists-fetch\" title=\"Every feed fetched now"
	    "\">Fetch now</button></span></h3><table class=\"net sd\"><thead><tr>"
	    "<th>Name</th><th>From</th><th>Entries</th><th>Version</th><th>"
	    "Fetched</th><th></th></tr></thead><tbody>", sd.lists != NULL ?
	    jint(sd.lists, "interval", 6) : 6);
	n = 0;
	it = NULL;
	while (sd.lists != NULL && (v = ucl_object_iterate(jget(sd.lists,
	    "feeds"), &it, true)) != NULL) {
		const ucl_object_t	*st = jget(jget(sd.lists, "lists"), jstr(v,
		    "name"));

		n++;
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(v, "name"));
		h_raw(h, "</td><td class=\"mono dim\">");
		h_txt(h, jstr(v, "url") != NULL ? jstr(v, "url") : "pasted");
		h_raw(h, "</td><td>");
		if (st != NULL)
			h_fmt(h, "%lld", jint(st, "count", 0));
		h_raw(h, "</td><td>");
		if (st != NULL)
			h_fmt(h, "%lld", jint(st, "version", 0));
		h_raw(h, "</td><td>");
		if (st != NULL && jget(st, "fetched_at") != NULL) {
			fmt_age(age, sizeof(age), (double)jint(st, "fetched_at", 0) *
			    1000);
			h_txt(h, age);
		}
		if (st != NULL && jstr(st, "error") != NULL) {
			h_raw(h, " <span class=\"chip st-down\" title=\"");
			h_txt(h, jstr(st, "error"));
			h_raw(h, "\">failed</span>");
		}
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" data-act=\""
		    "sd-list-edit\" title=\"Change it\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">&#9998;</button><button class=\"icon\" data-act=\""
		    "sd-list-del\" title=\"Take the list away\"");
		h_attr(h, "data-arg", jstr(v, "name"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"6\" class=\"dim\">None yet.</td></tr>");
	h_raw(h, "</tbody></table></div>");
	/* The record: what the edges' logged security rules saw, as each
	 * agent keeps a day of it, the latest first; a filter on the text,
	 * a CSV of what is shown. */
	{
		struct html	csvb;
		int		shown = 0;

		memset(&csvb, 0, sizeof(csvb));
		h_fmt(&csvb, "time,edge,rule,action,source,destination,interface,"
		    "comment\n");
		h_raw(h, "<div class=\"sd-block\"><h3>Record <small class=\"dim\">"
		    "what the policies' deny rules logged on each edge (ipfw's "
		    "log to the routing socket, read by the agent, a day kept); "
		    "the latest first</small><span class=\"pane-actions\"><input "
		    "type=\"search\" data-input=\"sd-record-filter\" placeholder=\""
		    "filter: an address, a policy, an edge\"");
		h_attr(h, "value", sd.record_filter);
		h_raw(h, "><a class=\"ghost small\" href=\"/api/sdwan/record.csv\" "
		    "download=\"sdwan-record.csv\" title=\"Every edge's record of "
		    "the day as CSV, from the console\">CSV</a></span></h3><table "
		    "class=\"net sd\"><thead><tr><th>When</th><th>Edge</th><th>Rule"
		    "</th><th>Action</th><th>From</th><th>To</th><th>Interface</th>"
		    "<th>Policy</th></tr></thead><tbody>");
		it = NULL;
		while (sd.paths != NULL && (v = ucl_object_iterate(sd.paths, &it,
		    true)) != NULL) {
			const ucl_object_t	*re;
			ucl_object_iter_t	 rit = NULL;
			char			 line[400];

			while ((re = ucl_object_iterate(jget(jget(v, "record"),
			    "last"), &rit, true)) != NULL) {
				snprintf(line, sizeof(line), "%s %lld %s %s %s %s %s",
				    host_name(ucl_object_key(v)), jint(re, "rule", 0),
				    jstr(re, "action") != NULL ? jstr(re, "action") : "",
				    jstr(re, "src") != NULL ? jstr(re, "src") : "",
				    jstr(re, "dst") != NULL ? jstr(re, "dst") : "",
				    jstr(re, "iface") != NULL ? jstr(re, "iface") : "",
				    jstr(re, "comment") != NULL ? jstr(re, "comment") :
				    "");
				if (sd.record_filter[0] != '\0' && strcasestr(line,
				    sd.record_filter) == NULL)
					continue;
				if (++shown > 500)
					break;
				fmt_age(age, sizeof(age), (double)jint(re, "t", 0) *
				    1000);
				h_raw(h, "<tr><td class=\"dim\">");
				h_txt(h, age);
				h_raw(h, "</td><td><b>");
				h_txt(h, host_name(ucl_object_key(v)));
				h_fmt(h, "</b></td><td class=\"mono\">%lld</td><td>",
				    jint(re, "rule", 0));
				h_txt(h, jstr(re, "action") != NULL ? jstr(re, "action") :
				    "");
				h_raw(h, "</td><td class=\"mono\">");
				h_txt(h, jstr(re, "src") != NULL ? jstr(re, "src") : "");
				h_raw(h, "</td><td class=\"mono\">");
				h_txt(h, jstr(re, "dst") != NULL ? jstr(re, "dst") : "");
				h_raw(h, "</td><td class=\"mono dim\">");
				h_txt(h, jstr(re, "iface") != NULL ? jstr(re, "iface") :
				    "");
				h_raw(h, "</td><td class=\"dim\">");
				h_txt(h, jstr(re, "comment") != NULL ? jstr(re, "comment")
				    : "");
				h_raw(h, "</td></tr>");
			}
		}
		if (shown == 0)
			h_raw(h, "<tr><td colspan=\"8\" class=\"dim\">Nothing logged "
			    "yet: a policy with log sends what it denies here.</td>"
			    "</tr>");
		h_raw(h, "</tbody></table></div>");
		free(csvb.s);
	}
	/* The DNS filters on the edges: each edge's unbound instances, a
	 * service each, as the edges' reads tell them. */
	h_raw(h, "<div class=\"sd-block\"><h3>DNS filters <small class=\"dim\">"
	    "the base system's unbound, an instance of each service whose "
	    "policies filter DNS, on each edge in the service's table, on the "
	    "UNIs' provider addresses; the denied domains do not resolve, and "
	    "with the protocol filter every query from the UNI is sent to it"
	    "</small></h3><table class=\"net sd\"><thead><tr><th>Edge</th><th>"
	    "Instance</th><th>State</th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while (sd.paths != NULL && (v = ucl_object_iterate(sd.paths, &it, true))
	    != NULL) {
		const ucl_object_t	*di;
		ucl_object_iter_t	 dit = NULL;

		while ((di = ucl_object_iterate(jget(v, "dns"), &dit, true)) !=
		    NULL) {
			n++;
			h_raw(h, "<tr><td><b>");
			h_txt(h, host_name(ucl_object_key(v)));
			h_fmt(h, "</b></td><td class=\"mono\">%s <span class=\"dim\">"
			    "fib %lld</span></td><td><span class=\"chip st-%s\">%s"
			    "</span></td></tr>", jstr(di, "name"), (long long)jint(di,
			    "fib", 0), jbool(di, "running") ? "up" : "down", jbool(
			    di, "running") ? "running" : "not running");
		}
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"3\" class=\"dim\">None: no policy "
		    "filters DNS, or nothing is applied yet.</td></tr>");
	h_raw(h, "</tbody></table></div>");
	/* The proxies on the edges (SASE-4): each edge's Squid instances,
	 * a service each, with the CA of one that opens TLS. */
	h_raw(h, "<div class=\"sd-block\"><h3>URL filters <small class=\"dim\">"
	    "Squid on each edge, a plugin installed there by hand, an instance "
	    "of each service whose policies filter URLs, in the service's "
	    "table; HTTP and TLS from the end points are forwarded to it; it "
	    "looks at the TLS names (sni) or opens TLS with a CA of its own "
	    "(inspect), which the clients then trust</small></h3><table class="
	    "\"net sd\"><thead><tr><th>Edge</th><th>Instance</th><th>Mode</th>"
	    "<th>State</th><th>CA</th></tr></thead><tbody>");
	n = 0;
	it = NULL;
	while (sd.paths != NULL && (v = ucl_object_iterate(sd.paths, &it, true))
	    != NULL) {
		const ucl_object_t	*pi;
		ucl_object_iter_t	 pit = NULL;

		while ((pi = ucl_object_iterate(jget(v, "proxy"), &pit, true)) !=
		    NULL) {
			n++;
			h_raw(h, "<tr><td><b>");
			h_txt(h, host_name(ucl_object_key(v)));
			h_fmt(h, "</b></td><td class=\"mono\">%s <span class=\"dim\">"
			    "fib %lld</span></td><td>%s</td><td><span class=\"chip "
			    "st-%s\">%s</span></td><td>", jstr(pi, "name"), (long long)
			    jint(pi, "fib", 0), jstr(pi, "mode") != NULL ? jstr(pi,
			    "mode") : "", jbool(pi, "running") ? "up" : "down",
			    jbool(pi, "running") ? "running" : "not running");
			if (jstr(pi, "ca") != NULL) {
				h_raw(h, "<a class=\"ghost small\" download=\"");
				h_txt(h, host_name(ucl_object_key(v)));
				h_raw(h, "-");
				h_txt(h, jstr(pi, "name"));
				h_raw(h, "-ca.crt\" href=\"data:application/x-x509-ca-cert"
				    ";charset=utf-8,");
				{
					const char	*c = jstr(pi, "ca");
					char		 enc[8192];
					size_t		 i, k;

					for (i = 0, k = 0; c[i] != '\0' && k + 4 <
					    sizeof(enc); i++) {
						if (c[i] == '\n')
							k += (size_t)snprintf(enc + k, sizeof(enc)
							    - k, "%%0A");
						else if (c[i] == '+' || c[i] == '/' || c[i] ==
						    '=' || c[i] == ' ' || c[i] == '%' || c[i]
						    == '#' || c[i] == '&')
							k += (size_t)snprintf(enc + k, sizeof(enc)
							    - k, "%%%02X", (unsigned char)c[i]);
						else
							enc[k++] = c[i];
					}
					enc[k] = '\0';
					h_raw(h, enc);
				}
				h_raw(h, "\" title=\"The instance's CA certificate, for "
				    "the clients to trust where TLS is opened\">"
				    "certificate</a>");
			} else
				h_raw(h, "<span class=\"dim\">—</span>");
			h_raw(h, "</td></tr>");
		}
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"5\" class=\"dim\">None: no policy "
		    "filters URLs, or nothing is applied yet.</td></tr>");
	h_raw(h, "</tbody></table></div>");
	view_ids(h);
}

static void
view_document(struct html *h)
{

	h_fmt(h, "<p class=\"dim\">The whole of it as JSON: <code>ucs</code>, "
	    "<code>edges</code> and <code>swvcs</code>, named as MEF 70.2 names "
	    "them. <b>Check</b> asks the console whether it is one the "
	    "standard allows; <b>Keep</b> keeps it as version %lld. What it "
	    "says no to names the requirement.</p>", (long long)jint(sd.doc,
	    "version", 0) + 1);
	if (sd.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, sd.error);
		h_raw(h, "</div>");
	} else if (sd.note[0] != '\0') {
		h_raw(h, "<div class=\"notice info\">");
		h_txt(h, sd.note);
		h_raw(h, "</div>");
	}
	h_raw(h, "<form data-form=\"sd-doc\" class=\"sd-doc\"><textarea name="
	    "\"text\" rows=\"28\" spellcheck=\"false\" class=\"mono\">");
	h_txt(h, sd.text != NULL ? sd.text : "");
	h_fmt(h, "</textarea><div class=\"actions\"><button class=\"ghost "
	    "small\" name=\"how\" value=\"check\"%s>Check</button><button "
	    "class=\"small\" name=\"how\" value=\"keep\"%s>Keep</button>"
	    "<button type=\"button\" class=\"ghost small\" data-act=\""
	    "sd-example\" title=\"A service with two edges, written out, to "
	    "be made your own before it is kept\">Start from an example"
	    "</button><button type=\"button\" class=\"ghost small\" "
	    "data-act=\"sd-revert\">Back to the kept one</button>"
	    "<span class=\"sep\"></span><button type=\"button\" class=\""
	    "ghost small\" data-act=\"sd-export\" data-arg=\"json\" title=\""
	    "The kept one as a JSON file, to keep elsewhere or to start "
	    "another from\">Export JSON</button><button type=\"button\" "
	    "class=\"ghost small\" data-act=\"sd-export\" data-arg=\"yaml\" "
	    "title=\"The kept one as a YAML file\">YAML</button><label class="
	    "\"button ghost small\" title=\"A document from a JSON or YAML "
	    "file, put in the box as JSON: check it, then keep it\">Import"
	    "<input type=\"file\" accept=\"application/json,.json,"
	    "application/yaml,.yaml,.yml\" data-file=\"sd-import\" hidden>"
	    "</label></div></form>",
	    sd.busy ? " disabled" : "", sd.busy ? " disabled" : "");
}

void
view_sdwan(struct html *h)
{

	h_raw(h, "<section class=\"sdwan\">");
	h_fmt(h, "<nav class=\"tabs\"><button class=\"tab%s\" data-act=\""
	    "sd-tab\" data-arg=\"overview\">Dashboard</button><button class=\""
	    "tab%s\" data-act=\"sd-tab\" data-arg=\"services\">Services"
	    "</button><button class=\"tab%s\" data-act=\"sd-tab\" data-arg=\""
	    "edges\" title=\"What the edges are to have, and Apply\">Edges"
	    "</button><button class=\"tab%s\" data-act=\"sd-tab\" data-arg=\""
	    "paths\" title=\"What the edges' probes see of each tunnel: "
	    "delay, variation, loss\">Paths</button><button class=\"tab%s\" "
	    "data-act=\"sd-tab\" data-arg=\"security\" title=\"The security "
	    "policies of each service, MEF 88\">Security</button><button class="
	    "\"tab%s\" data-act=\"sd-tab\" data-arg=\"identities\" title=\"Who "
	    "reaches a service from afar: the remote end points' identities, "
	    "issued and revoked\">Identities</button><button class="
	    "\"tab%s\" data-act=\"sd-tab\" data-arg=\"document\" title=\"All of "
	    "it as JSON, checked against MEF 70.2\">Document</button></nav>",
	    sd.tab == SD_OVERVIEW ? " on" : "", sd.tab == SD_SERVICES ? " on" :
	    "", sd.tab == SD_EDGES ? " on" : "", sd.tab == SD_PATHS ? " on" :
	    "", sd.tab == SD_SECURITY ? " on" : "", sd.tab == SD_IDENTITIES ?
	    " on" : "", sd.tab == SD_DOCUMENT ? " on" : "");
	if (sd.doc == NULL) {
		if (sd.error[0] != '\0') {
			h_raw(h, "<div class=\"notice bad\">");
			h_txt(h, sd.error);
			h_raw(h, "</div>");
		} else
			h_raw(h, "<div class=\"loader\"></div>");
	} else if (sd.tab == SD_SERVICES)
		view_service(h);
	else if (sd.tab == SD_EDGES)
		view_edges(h);
	else if (sd.tab == SD_PATHS)
		view_paths(h);
	else if (sd.tab == SD_IDENTITIES) {
		view_groups(h);
		view_identities(h);
	}
	else if (sd.tab == SD_SECURITY)
		view_security(h);
	else if (sd.tab == SD_DOCUMENT)
		view_document(h);
	else {
		/* Not set up yet: the way through first. */
		view_guide(h, true);
		view_needs(h, false);
		view_dashboard(h);
	}
	h_raw(h, "</section>");
}

/* ---- The forms: underlays, edges, WAN links --------------------------- */

/* The element of a list whose key is the value. */
static const ucl_object_t *
jfind(const ucl_object_t *arr, const char *key, const char *value)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while (value != NULL && (e = ucl_object_iterate(arr, &it, true)) !=
	    NULL)
		if (jstr(e, key) != NULL && strcmp(jstr(e, key), value) == 0)
			return (e);
	return (NULL);
}

/* A checkbox as the bridge sends it: true or false, or "1" by hand. */
static bool
checked(const ucl_object_t *f, const char *name)
{
	const ucl_object_t	*v;

	if ((v = jget(f, name)) == NULL)
		return (false);
	if (ucl_object_type(v) == UCL_BOOLEAN)
		return (ucl_object_toboolean(v));
	return (ucl_object_tostring_forced(v) != NULL && (strcmp(
	    ucl_object_tostring_forced(v), "1") == 0 || strcmp(
	    ucl_object_tostring_forced(v), "true") == 0));
}

/* Is the string in the list? */
static bool
jfind_str(const ucl_object_t *arr, const char *s)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;

	it = NULL;
	while (s != NULL && (v = ucl_object_iterate(arr, &it, true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(v), s) == 0)
			return (true);
	return (false);
}

static const ucl_object_t *
ucs_by(const char *id)
{

	return (id != NULL ? jfind(jget(sd.doc, "ucs"), "id", id) : NULL);
}

static const ucl_object_t *
edge_by(const char *sid)
{

	return (sid != NULL ? jfind(jget(sd.doc, "edges"), "server", sid) :
	    NULL);
}

static void
option(struct html *h, const char *value, const char *label,
    const char *current)
{

	h_raw(h, "<option");
	h_attr(h, "value", value);
	if (current != NULL && strcmp(current, value) == 0)
		h_raw(h, " selected");
	h_raw(h, ">");
	h_txt(h, label);
	h_raw(h, "</option>");
}

bool
sdwan_modal(struct html *h)
{
	const ucl_object_t	*u, *t, *e, *o, *lk;
	ucl_object_iter_t	 it;
	const char		*v, *ifn;
	char			 buf[120];
	int			 i, n;

	sd.blocked = false;
	if (sdwan_modal_service(h))
		return (true);
	if (app.modal == MODAL_SD_UCS) {
		u = ucs_by(sd.edit);
		t = jget(u, "tunnel");
		h_fmt(h, "<form data-form=\"sd-ucs\"><h2>%s</h2><p>A carrier the "
		    "edges reach each other over (an Underlay Connectivity "
		    "Service, MEF 70.2 §12): the Internet, an MPLS, a line. Each "
		    "edge gets a WAN link on it; tunnels go between the links, "
		    "the kind said here.</p><input type=\"hidden\" name=\"was\"",
		    u != NULL ? "An underlay, changed" : "An underlay");
		h_attr(h, "value", sd.edit);
		h_raw(h, "><label>Id<input name=\"id\" spellcheck=\"false\" "
		    "autocomplete=\"off\" maxlength=\"64\" placeholder=\"internet\""
		    " autofocus");
		h_attr(h, "value", u != NULL ? jstr(u, "id") : "");
		h_raw(h, "></label><div class=\"two\"><label>Type<select name=\""
		    "type\">");
		option(h, "public", "public: the Internet, shared", jstr(u,
		    "type"));
		option(h, "private", "private: an MPLS, a line, yours", jstr(u,
		    "type"));
		h_raw(h, "</select></label><label>Billing<select name=\""
		    "billing\">");
		option(h, "flat-rate", "flat rate", jstr(u, "billing"));
		option(h, "usage-based", "by usage", jstr(u, "billing"));
		option(h, "other", "other", jstr(u, "billing"));
		h_raw(h, "</select></label></div><div class=\"two\"><label>Tunnel "
		    "over it<select name=\"kind\" data-input=\"sd-ucs-kind\">");
		option(h, "gre", "gre: gre(4), IP in IP with a key", jstr(t,
		    "kind") != NULL ? jstr(t, "kind") : "gre");
		option(h, "gif", "gif: gif(4), IP in IP", jstr(t, "kind"));
		option(h, "geneve", "geneve: over UDP, a VNI each", jstr(t,
		    "kind"));
		option(h, "wg", "wg: WireGuard, encrypted by itself", jstr(t,
		    "kind"));
		option(h, "uswe", "uswe: Mplify 119, IPsec keyed by the edges",
		    jstr(t, "kind"));
		h_raw(h, "</select></label>");
		/* wg and uswe encrypt by themselves: no IPsec under them. */
		if (strcmp(sd.ucs_kind, "wg") != 0 && strcmp(sd.ucs_kind,
		    "uswe") != 0)
			h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" "
			    "name=\"ipsec\" value=\"1\"%s> IPsec IKEv2 under it, "
			    "by strongSwan<small>Required on a public underlay by "
			    "a policy that says so.</small></label>", t != NULL &&
			    jbool(t, "ipsec") ? " checked" : "");
		h_raw(h, "</div>");
		if (strcmp(sd.ucs_kind, "uswe") != 0)
			return (true);
		/* A USWE tunnel's SAs: the base system's ipsec(4) and
		 * setkey, the keys made and derived by the agents. */
		h_raw(h, "<fieldset><legend>uswe <small class=\"dim\">an "
		    "ipsec(4) interface each end, ESP in tunnel mode, the keys "
		    "derived by the two agents from a pair each (Mplify 119 "
		    "§10)</small></legend><div class=\"two\"><label>Algorithms"
		    "<select name=\"algorithms\">");
		option(h, "aes-cbc-hmac-sha2-256", "AES-256-CBC with HMAC-SHA-256",
		    jstr(t, "algorithms"));
		option(h, "aes-gcm-16", "AES-256-GCM", jstr(t, "algorithms"));
		h_fmt(h, "</select></label><div><label class=\"toggle\"><input "
		    "type=\"checkbox\" name=\"esn\" value=\"1\"%s> Extended "
		    "sequence numbers (ESN)</label><label class=\"toggle\"><input "
		    "type=\"checkbox\" name=\"encap\" value=\"1\"%s> ESP in UDP, "
		    "port 4500 (through NAT)</label></div></div>", t ==
		    NULL || jget(t, "esn") == NULL || jbool(t, "esn") ? " checked" :
		    "", t == NULL || jget(t, "encap") == NULL || jbool(t, "encap")
		    ? " checked" : "");
		{
			char	lt[32];

			snprintf(lt, sizeof(lt), "%lld", (long long)jint(t,
			    "lifetime", 0));
			text_field(h, "Keys turned every, seconds", "lifetime",
			    jint(t, "lifetime", 0) > 0 ? lt : "", "86400", "120 "
			    "seconds to a year; both ends turn them at the half "
			    "of it.");
		}
		{
			char	ms[32];

			snprintf(ms, sizeof(ms), "%lld", (long long)jint(t, "mss",
			    0));
			text_field(h, "TCP MSS clamped to", "mss", jstr(t, "mss") !=
			    NULL ? jstr(t, "mss") : jint(t, "mss", 0) > 0 ? ms : "",
			    "auto", "On the tunnels over it, by ipfw tcp-setmss: "
			    "auto for the tunnel's kind (and IPsec under it), a "
			    "number of bytes, or empty for none.");
			snprintf(ms, sizeof(ms), "%lld", (long long)jint(t, "mtu",
			    0));
			text_field(h, "Tunnel MTU", "mtu", jstr(t, "mtu") != NULL ?
			    jstr(t, "mtu") : jint(t, "mtu", 0) > 0 ? ms : "", "auto",
			    "The tunnel interfaces' MTU (ifconfig mtu): auto takes "
			    "the tunnel's overhead off 1500, so the inner packets "
			    "are not fragmented; a number of bytes, 1280 to 9000; "
			    "or empty for the kernel's.");
		}
		h_raw(h, "</fieldset>");
		return (true);
	}
	if (app.modal == MODAL_SD_EDGE) {
		char	ntp[600];
		size_t	elen;

		e = edge_by(sd.edit);
		h_fmt(h, "<form data-form=\"sd-edge\"><h2>%s</h2><p>A host "
		    "running arcana-agent that stands between the subscriber "
		    "and the underlays (an SD-WAN Edge, §7.8). Its WAN links "
		    "come next, one on each underlay it reaches.</p><input "
		    "type=\"hidden\" name=\"was\"", e != NULL ? "An edge, changed" :
		    "An edge");
		h_attr(h, "value", sd.edit);
		h_raw(h, ">");
		/* A host, or a vnet jail on it (server/jail): any host, as
		 * each may have its jails as edges beside itself. */
		elen = strcspn(sd.edit, "/");
		for (i = n = 0; i < app.nservers; i++)
			if (e == NULL || (strlen(app.servers[i].id) == elen &&
			    strncmp(app.servers[i].id, sd.edit, elen) == 0))
				n++;
		if (n == 0) {
			sd.blocked = true;
			h_raw(h, "<div class=\"notice\">The console has no host "
			    "yet. A host joins the console from <b>Devices</b>, + "
			    "host, with arcana-agent on it.</div>");
		} else {
			h_raw(h, "<label>Host<select name=\"host\" autofocus>");
			for (i = 0; i < app.nservers; i++) {
				if (e != NULL && (strlen(app.servers[i].id) != elen ||
				    strncmp(app.servers[i].id, sd.edit, elen) != 0))
					continue;
				option(h, app.servers[i].id, app.servers[i].name,
				    NULL);
			}
			h_raw(h, "</select></label>");
			text_field(h, "Jail", "jail", e != NULL && sd.edit[elen] ==
			    '/' ? sd.edit + elen + 1 : "", "none: the host itself",
			    e != NULL ? "Fixed once the edge is made." : "A vnet "
			    "jail on the host to be the edge instead: its own "
			    "network (interfaces, routes, ipfw), its tunnels "
			    "measured and steered there (jexec, ifconfig -j). "
			    "Empty: the host itself.");
		}
		/* Rarely set: folded, open only when it is. */
		h_raw(h, "<details class=\"sd-more\"");
		if (e != NULL && ucl_array_size(jget(e, "ntp")) > 0)
			h_raw(h, " open");
		h_raw(h, "><summary>Advanced</summary>");
		text_field(h, "NTP servers", "ntp", e != NULL ? csv(jget(e, "ntp"),
		    ntp, sizeof(ntp)) : "", "0.freebsd.pool.ntp.org", "Only if "
		    "the host does not keep time already: the edge's clock "
		    "lines up faults and key turns with the other edges "
		    "(ntpd). Empty: the host as it is.");
		/* A host-as-subscriber edge, and one whose BIRD is its own. */
		h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" name=\""
		    "own_table\" value=\"1\"%s> Host as subscriber: the service's "
		    "overlay in the host's own routing table (0), its uplinks in "
		    "tables of their own (each link's VRF), its UNI left where "
		    "it is; nothing of the host's jails and daemons moves. Its "
		    "breakout needs the service's breakout domain to have a fib "
		    "of its own.</label><label class=\"toggle\"><input type=\""
		    "checkbox\" name=\"host_bird\" value=\"1\"%s> The host runs "
		    "its own BIRD: no service with BFD or routing at a UNI may "
		    "put one here</label><label class=\"toggle\"><input type=\""
		    "checkbox\" name=\"transit\" value=\"1\"%s> Carries transit: "
		    "what the other edges exchange may pass through it, and break "
		    "out here, when their direct tunnels are down (off for an edge "
		    "on a usage-billed or thin link)</label>", e != NULL && jbool(e, "own_table") ?
		    " checked" : "", e != NULL && jbool(e, "host_bird") ?
		    " checked" : "", e != NULL && jget(e, "transit") != NULL &&
		    !jbool(e, "transit") ? "" : " checked");
		/* The uplink each destination set goes out by, and what else
		 * of BGP reaches the kernel. */
		{
			const ucl_object_t	*bs;
			ucl_object_iter_t	 bit = NULL;
			char			 btext[2000];

			btext[0] = '\0';
			while (e != NULL && (bs = ucl_object_iterate(jget(e,
			    "breakout_sets"), &bit, true)) != NULL && strlen(btext) + 200
			    < sizeof(btext))
				snprintf(btext + strlen(btext), sizeof(btext) - strlen(
				    btext), "%s%s %s", btext[0] != '\0' ? "\n" : "", jstr(bs,
				    "set") != NULL ? jstr(bs, "set") : "", jstr(bs, "via") !=
				    NULL ? jstr(bs, "via") : "");
			h_raw(h, "<label>Breakout by destination set<textarea name=\""
			    "breakout_sets\" rows=\"2\" spellcheck=\"false\" placeholder=\""
			    "country lte\">");
			h_txt(h, btext);
			h_fmt(h, "</textarea><small>One a line: a set of a service here "
			    "(by its name) and the UCS end point of this edge it goes "
			    "out by, a breakout with a gateway.</small></label><label>"
			    "BGP routes into the kernel<select name=\"bgp_import\"><option "
			    "value=\"all\"%s>All of them</option><option value=\"sets\"%s>"
			    "Only the destination sets': the kernel keeps its own default "
			    "route</option></select></label>", e != NULL && jstr(e,
			    "bgp_import") != NULL && strcmp(jstr(e, "bgp_import"), "sets")
			    == 0 ? "" : " selected", e != NULL && jstr(e, "bgp_import") !=
			    NULL && strcmp(jstr(e, "bgp_import"), "sets") == 0 ?
			    " selected" : "");
		}
		h_raw(h, "</details>");
		/* What it does to the host, before anything is done. */
		h_raw(h, "<details class=\"sd-effects\"" );
		if (e == NULL)
			h_raw(h, " open");
		h_raw(h, "><summary>What this changes on the host</summary><ul>"
		    "<li>IP forwarding turned on, for IPv4 and IPv6 (<code>"
		    "net.inet.ip.forwarding</code>, <code>net.inet6.ip6."
		    "forwarding</code>), kept in <code>/etc/sysctl.conf</code>."
		    "</li><li>With NTP servers: <code>ntpd</code>(8) set to them, "
		    "in <code>/etc/ntp.conf</code> and <code>rc.conf</code>."
		    "</li><li>A WAN link left <b>Static</b> with no routing "
		    "table of its own, as a link is unless you change it, is "
		    "not touched: its address stays as the host has it. Only "
		    "a link you set to DHCP gets <code>dhclient</code>, to "
		    "SLAAC <code>rtsol</code>, and only one given a table "
		    "(VRF) is put in it (<code>ifconfig fib</code>); BIRD for "
		    "its BGP or OSPF where it has them. The link the console "
		    "reaches the host through is said, and kept as it is "
		    "unless you agree. <a href=\"https://spmzt.github.io/"
		    "arcana-docs/sdwan/apply.html#what-an-edge-changes-on-its-"
		    "host\" target=\"_blank\" rel=\"noopener\">More</a></li><li>Once a service uses it: more routing tables "
		    "(<code>net.fibs</code>), the service's tunnels (gre(4), "
		    "gif(4), geneve(4), wg(4), ipsec(4)) in its table, its "
		    "routes, <code>ipfw</code>(8) rules in set 30, and BIRD, "
		    "strongSwan, local-unbound, Squid or Suricata as the "
		    "service asks.</li></ul><p>Nothing changes until you <b>"
		    "Deploy</b>, and each change is listed first. What the "
		    "console made it can take away again.</p></details>");
		return (true);
	}
	if (app.modal == MODAL_SD_LINK) {
		e = edge_by(sd.link_host);
		lk = sd.edit[0] != '\0' ? jfind(jget(e, "ucs_end_points"), "id",
		    sd.edit) : NULL;
		h_fmt(h, "<form data-form=\"sd-link\"><h2>%s on %s</h2><p>Where "
		    "the host meets an underlay: the interface, its address on "
		    "it, and the gateway (a UCS End Point, §12.3). Tunnels to "
		    "the other edges' links on the same underlay start here."
		    "</p><input type=\"hidden\" name=\"host\"", lk != NULL ? "A "
		    "WAN link, changed" : "A WAN link", host_name(sd.link_host));
		h_attr(h, "value", sd.link_host);
		h_raw(h, "><input type=\"hidden\" name=\"was\"");
		h_attr(h, "value", sd.edit);
		h_raw(h, ">");
		if (ucl_array_size(jget(sd.doc, "ucs")) == 0) {
			sd.blocked = true;
			h_raw(h, "<div class=\"notice\">No underlay yet: a WAN "
			    "link is an edge's interface on one. <button class="
			    "\"ghost small\" data-act=\"sd-ucs-add\">+ underlay"
			    "</button></div>");
			return (true);
		}
		h_raw(h, "<div class=\"two\"><label>Underlay<select name=\"ucs\">");
		it = NULL;
		while ((u = ucl_object_iterate(jget(sd.doc, "ucs"), &it, true)) !=
		    NULL)
			option(h, jstr(u, "id"), jstr(u, "id"), jstr(lk, "ucs"));
		h_raw(h, "</select></label><label>Id<input name=\"id\" spellcheck="
		    "\"false\" autocomplete=\"off\" maxlength=\"64\" placeholder=\""
		    "the host and the underlay, if empty\"");
		h_attr(h, "value", lk != NULL ? jstr(lk, "id") : "");
		h_raw(h, "></label></div>");
		/* The interface: from the host's own list, when it answers. */
		ifn = sd.link_if[0] != '\0' ? sd.link_if : lk != NULL ? jstr(lk,
		    "interface") : NULL;
		h_raw(h, "<label>Interface");
		if (sd.ifs_loading)
			h_raw(h, "<span class=\"dim\"> · asking the host</span>");
		if (sd.ifs != NULL && jget(sd.ifs, "interfaces") != NULL) {
			h_raw(h, "<select name=\"interface\" data-input=\"sd-link-if"
			    "\">");
			it = NULL;
			while ((o = ucl_object_iterate(jget(sd.ifs, "interfaces"),
			    &it, true)) != NULL) {
				if (jstr(o, "name") == NULL || strncmp(jstr(o,
				    "name"), "lo", 2) == 0 || strncmp(jstr(o, "name"),
				    "pflog", 5) == 0 || strncmp(jstr(o, "name"),
				    "enc", 3) == 0)
					continue;
				v = link_address(jstr(o, "name"), 4);
				if (v == NULL)
					v = link_address(jstr(o, "name"), 6);
				snprintf(buf, sizeof(buf), "%s%s%s", jstr(o, "name"),
				    v != NULL ? " · " : "", v != NULL ? v : "");
				option(h, jstr(o, "name"), buf, ifn);
				if (ifn == NULL)
					ifn = jstr(o, "name");
			}
			h_raw(h, "</select>");
		} else {
			h_raw(h, "<input name=\"interface\" spellcheck=\"false\" "
			    "autocomplete=\"off\" placeholder=\"vtnet0\"");
			h_attr(h, "value", ifn != NULL ? ifn : "");
			h_raw(h, ">");
		}
		h_raw(h, "</label>");
		/* The way the console reaches this host: said, and to be
		 * agreed to before it is given DHCP, SLAAC or a table. */
		{
			const char	*wi = way_in_if(sd.link_host);

			if (wi != NULL && ifn != NULL && strcmp(wi, ifn) == 0) {
				/* The host's name for it, escaped. */
				h_raw(h, "<div class=\"notice warn\"><b>The "
				    "console reaches this host through ");
				h_txt(h, wi);
				h_raw(h, ".</b> Static "
				    "addressing and no table of its own leave it "
				    "as it is. DHCP or SLAAC may give it another "
				    "address, and a table of its own (VRF) moves "
				    "its replies there: either can lose the host "
				    "to the console. <label class=\"toggle\"><input "
				    "type=\"checkbox\" name=\"wayin_ok\"> I reach it "
				    "another way too, or its address and routes "
				    "stay</label> <a href=\"https://spmzt.github.io/"
				    "arcana-docs/sdwan/apply.html#what-an-edge-"
				    "changes-on-its-host\" target=\"_blank\" rel="
				    "\"noopener\">What an edge changes</a></div>");
			}
		}
		h_raw(h, "<div class=\"two\"><label>Address<input name=\""
		    "address\" spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"the interface's\"");
		v = lk != NULL && sd.link_if[0] == '\0' ? jstr(lk, "address") :
		    link_address(ifn, 4) != NULL ? link_address(ifn, 4) :
		    link_address(ifn, 6);
		h_attr(h, "value", v != NULL ? v : "");
		h_raw(h, "><small>The tunnels' outer address here.</small></label>"
		    "<label>Gateway<input name=\"gateway\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"for breakout\"");
		h_attr(h, "value", lk != NULL && jstr(lk, "gateway") != NULL ?
		    jstr(lk, "gateway") : "");
		h_raw(h, "></label></div><div class=\"two\"><label>Bandwidth, bits "
		    "per second<input name=\"bandwidth\" inputmode=\"numeric\" "
		    "placeholder=\"100000000\"");
		if (lk != NULL && jget(lk, "bandwidth") != NULL) {
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(lk,
			    "bandwidth", 0));
			h_attr(h, "value", buf);
		}
		h_fmt(h, "></label><div><label class=\"toggle\"><input type=\""
		    "checkbox\" name=\"breakout\" value=\"1\"%s> Breakout: the "
		    "Internet is reached here</label><label class=\"toggle\">"
		    "<input type=\"checkbox\" name=\"backup\" value=\"1\"%s> "
		    "Backup: used only when nothing else is left</label>"
		    "<label class=\"toggle\"><input type=\"checkbox\" name=\"nat\" "
		    "value=\"1\"%s> Behind NAT (CGNAT): the far WireGuard peers "
		    "get no endpoint for it; this end finds them and its "
		    "keepalive holds the mapping</label></div></div>", lk != NULL
		    && jbool(lk, "breakout") ? " checked" : "", lk != NULL &&
		    jbool(lk, "backup") ? " checked" : "", lk != NULL && jbool(lk,
		    "nat") ? " checked" : "");
		/* Relays toward edges: a process of yours on the host (FEC,
		 * obfuscation) the wg peer points at, reaching the far
		 * underlay at its port; one a line. */
		{
			const ucl_object_t	*rl;
			ucl_object_iter_t	 rit;
			char			 rtext[1200];
			size_t			 rn = 0;

			rtext[0] = '\0';
			rit = NULL;
			while (lk != NULL && (rl = ucl_object_iterate(jget(lk,
			    "relay"), &rit, true)) != NULL && rn < sizeof(rtext) -
			    200)
				rn += (size_t)snprintf(rtext + rn, sizeof(rtext) - rn,
				    "%s %s %lld\n", jstr(rl, "to") != NULL ? jstr(rl,
				    "to") : "", jstr(rl, "endpoint") != NULL ? jstr(rl,
				    "endpoint") : "", (long long)jint(rl, "port", 0));
			h_raw(h, "<label>Relays, WireGuard only<textarea name=\""
			    "relay\" rows=\"2\" spellcheck=\"false\" placeholder=\"edge "
			    "127.0.0.1:51821 14350\">");
			h_txt(h, rtext);
			h_raw(h, "</textarea><small>One a line: the far edge's id, "
			    "the relay's listener here that the wg peer points at "
			    "(host:port), and the port the relay reaches the far "
			    "underlay at. The relay process is yours; its flow goes "
			    "by this uplink's table.</small></label>");
		}
		/* How the interface is addressed and routed (Mplify 119
		 * §12.2.3): by DHCP or SLAAC the address is learned from the
		 * host at each plan; a table of its own; BGP or OSPF with the
		 * underlay by a BIRD instance of the edge. */
		{
			const ucl_object_t	*rt = lk != NULL ? jget(lk, "routing") :
			    NULL, *bg = jget(rt, "bgp"), *os = jget(rt, "ospf");
			char			 nb[32], lb3[300];

			h_raw(h, "<details class=\"sd-more\"");
			if (rt != NULL || (lk != NULL && (jstr(lk, "addressing") !=
			    NULL || jget(lk, "vrf") != NULL)))
				h_raw(h, " open");
			h_raw(h, "><summary>Addressed and routed <small class=\"dim"
			    "\">Mplify 119 §12.2.3; all optional</small></summary>"
			    "<fieldset><div class=\"two\"><label>The interface's "
			    "address<select name=\"addressing\">");
			option(h, "static", "Static: as given above", lk != NULL ?
			    jstr(lk, "addressing") : NULL);
			option(h, "dhcp", "DHCP: dhclient, learned at each plan", lk
			    != NULL ? jstr(lk, "addressing") : NULL);
			option(h, "slaac", "SLAAC: router advertisements, rtsol", lk
			    != NULL ? jstr(lk, "addressing") : NULL);
			h_raw(h, "</select><small>Static leaves the interface as "
			    "it is: nothing of its address is changed. With DHCP or "
			    "SLAAC the address above may stay empty: the edge's is "
			    "read from the host when a plan is made.</small></label>");
			snprintf(nb, sizeof(nb), "%lld", lk != NULL ? (long long)
			    jint(lk, "vrf", 0) : 0LL);
			text_field(h, "Routing table (VRF)", "vrf", lk != NULL &&
			    jint(lk, "vrf", 0) > 0 ? nb : "", "3", "A table of the "
			    "underlay's own (setfib): the interface and the tunnels' "
			    "outer packets go by it (§12.2.3.4).");
			h_raw(h, "</div><div class=\"two\">");
			snprintf(nb, sizeof(nb), "%lld", lk != NULL ? (long long)
			    jint(lk, "preference", 0) : 0LL);
			text_field(h, "Preference", "preference", lk != NULL &&
			    jint(lk, "preference", 0) > 0 ? nb : "", "10", "Its "
			    "place among this edge's uplinks, the higher first: the "
			    "steering's order where a policy names no end points, "
			    "and the breakout taken first. 0 to 65535.");
			text_field(h, "Beacon", "beacon", lk != NULL && jstr(lk,
			    "beacon") != NULL ? jstr(lk, "beacon") : "", "the gateway",
			    "An address probed by this uplink where the edge has "
			    "several breakouts: when it stops answering, the next "
			    "breakout takes the default route. Empty: the gateway "
			    "itself.");
			h_raw(h, "</div><div class=\"two\">");
			snprintf(nb, sizeof(nb), "%lld", (long long)jint(bg, "as", 0));
			text_field(h, "BGP: the underlay's AS", "bgp_as", jint(bg,
			    "as", 0) > 0 ? nb : "", "65000", "With a neighbour, BGP "
			    "with the underlay by BIRD (§12.2.3.5).");
			text_field(h, "BGP neighbours", "bgp_neighbors", csv(jget(bg,
			    "neighbors"), lb3, sizeof(lb3)), "192.0.2.254", "Addresses,"
			    " by commas.");
			h_raw(h, "</div><div class=\"two\">");
			text_field(h, "BGP password", "bgp_password", jstr(bg,
			    "password"), "", "TCP MD5, if agreed.");
			snprintf(nb, sizeof(nb), "%lld", (long long)jint(os, "area",
			    0));
			text_field(h, "OSPF area", "ospf_area", os != NULL ? nb : "",
			    "0", "Set, OSPF with the underlay on the interface.");
			h_raw(h, "</div><div class=\"two\"><label>BGP family<select "
			    "name=\"bgp_fam\">");
			option(h, "both", "IPv4 and IPv6", jstr(bg, "family"));
			option(h, "ipv4", "IPv4", jstr(bg, "family"));
			option(h, "ipv6", "IPv6", jstr(bg, "family"));
			h_raw(h, "</select></label>");
			snprintf(nb, sizeof(nb), "%lld", (long long)jint(bg,
			    "hold_time", 0));
			text_field(h, "BGP hold time, seconds", "bgp_hold", jint(bg,
			    "hold_time", 0) > 0 ? nb : "", "90", NULL);
			h_raw(h, "</div><div class=\"two\">");
			snprintf(nb, sizeof(nb), "%lld", (long long)jint(bg,
			    "distance", 0));
			text_field(h, "BGP distance", "bgp_dist", jint(bg, "distance",
			    0) > 0 ? nb : "", "20", "1 to 255: how much its routes "
			    "are believed against others.");
			communities_text(jget(bg, "communities"), lb3, sizeof(lb3));
			text_field(h, "BGP communities", "bgp_comm", lb3,
			    "65000:100", "as:value, by commas.");
			h_raw(h, "</div><div class=\"two\">");
			snprintf(nb, sizeof(nb), "%lld", (long long)jint(os, "cost",
			    0));
			text_field(h, "OSPF cost", "ospf_cost", jint(os, "cost", 0) >
			    0 ? nb : "", "10", NULL);
			snprintf(nb, sizeof(nb), "%lld", (long long)jint(os, "hello",
			    0));
			text_field(h, "OSPF hello, seconds", "ospf_hello", jint(os,
			    "hello", 0) > 0 ? nb : "", "10", NULL);
			h_raw(h, "</div><div class=\"two\">");
			snprintf(nb, sizeof(nb), "%lld", (long long)jint(os, "dead",
			    0));
			text_field(h, "OSPF dead, seconds", "ospf_dead", jint(os,
			    "dead", 0) > 0 ? nb : "", "40", NULL);
			h_raw(h, "</div></fieldset></details>");
		}
		return (true);
	}
	return (false);
}

/* A list's values as one comma line, into buf. */
static const char *
csv(const ucl_object_t *arr, char *buf, size_t len)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	int			 n;

	buf[0] = '\0';
	n = 0;
	it = NULL;
	while ((v = ucl_object_iterate(arr, &it, true)) != NULL)
		snprintf(buf + strlen(buf), len - strlen(buf), "%s%s", n++ > 0 ?
		    ", " : "", ucl_object_tostring_forced(v));
	return (buf);
}

/* A comma line as a list: numbers as numbers, the rest as text. */
static ucl_object_t *
list_of(const char *text)
{
	ucl_object_t	*arr;
	char		*copy, *p, *tok;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (text == NULL)
		return (arr);
	copy = strdup(text);
	p = copy;
	while ((tok = strsep(&p, ",")) != NULL) {
		while (*tok == ' ' || *tok == '\t')
			tok++;
		while (strlen(tok) > 0 && (tok[strlen(tok) - 1] == ' ' ||
		    tok[strlen(tok) - 1] == '\t'))
			tok[strlen(tok) - 1] = '\0';
		if (*tok == '\0')
			continue;
		if (strspn(tok, "0123456789") == strlen(tok))
			ucl_array_append(arr, ucl_object_fromint(strtoll(tok, NULL,
			    10)));
		else
			ucl_array_append(arr, ucl_object_fromstring(tok));
	}
	free(copy);
	return (arr);
}

static void
text_field(struct html *h, const char *label, const char *name,
    const char *value, const char *hint, const char *small)
{

	h_raw(h, "<label>");
	h_txt(h, label);
	h_fmt(h, "<input name=\"%s\" spellcheck=\"false\" autocomplete=\"off\"",
	    name);
	h_attr(h, "placeholder", hint != NULL ? hint : "");
	h_attr(h, "value", value != NULL ? value : "");
	h_raw(h, ">");
	if (small != NULL) {
		h_raw(h, "<small>");
		h_txt(h, small);
		h_raw(h, "</small>");
	}
	h_raw(h, "</label>");
}

/* The criteria's one value as text: a list joined, a scalar as it is. */
static const char *
crit_text(const ucl_object_t *cr, const char *key, char *buf, size_t len)
{
	const ucl_object_t	*v;

	if ((v = jget(cr, key)) == NULL)
		return ("");
	if (ucl_object_type(v) == UCL_ARRAY)
		return (csv(v, buf, len));
	snprintf(buf, len, "%s", ucl_object_tostring_forced(v));
	return (buf);
}

/* The modals of a service's parts: true when one was drawn. */
static bool
sdwan_modal_service(struct html *h)
{
	const ucl_object_t	*sw, *o, *cr, *v, *u, *e, *m, *a;
	ucl_object_iter_t	 it;
	char			 buf[600], b2[64];
	const char		*ifn, *val;
	int			 i, n, fib;
	bool			 edit;
	char			 lb[600], lb2[300];

	sw = swvc_shown();
	if (app.modal == MODAL_SD_NLIST) {
		static const char *const kinds[] = { "prefixes", "services",
		    "ucs", "edges", "ucs-end-points" };
		static const char *const kwords[] = { "prefixes",
		    "services: protocols, ports", "UCSs", "edges",
		    "UCS End Points" };
		const char	*kind;
		size_t		 k, bo;

		o = sd.edit[0] != '\0' ? jfind(jget(sd.doc, "lists"), "name",
		    sd.edit) : NULL;
		kind = jstr(o, "kind") != NULL ? jstr(o, "kind") : "prefixes";
		h_fmt(h, "<form data-form=\"sd-nlist\"><h2>%s</h2><p>Kept once in "
		    "the document, and named where its values would be: a "
		    "flow's addresses or services, a zone's prefixes, the ways "
		    "a policy may take.</p><input type=\"hidden\" name=\"was\"",
		    o != NULL ? "A list, changed" : "A list");
		h_attr(h, "value", sd.edit);
		h_raw(h, "><div class=\"two\">");
		text_field(h, "Name", "name", jstr(o, "name"), "branches",
		    "Letters, digits, _ and -.");
		h_raw(h, "<label>Of<select name=\"kind\">");
		for (k = 0; k < nitems(kinds); k++)
			h_fmt(h, "<option value=\"%s\"%s>%s</option>", kinds[k],
			    strcmp(kind, kinds[k]) == 0 ? " selected" : "",
			    kwords[k]);
		h_raw(h, "</select></label></div>");
		/* Items a line each; a UCS End Point with its preference. */
		buf[0] = '\0';
		bo = 0;
		it = NULL;
		while ((e = ucl_object_iterate(jget(o, "items"), &it, true)) !=
		    NULL && bo < sizeof(buf) - 80) {
			if (ucl_object_type(e) == UCL_OBJECT)
				bo += (size_t)snprintf(buf + bo, sizeof(buf) - bo,
				    "%s %lld\n", jstr(e, "id"), (long long)jint(e,
				    "preference", 0));
			else
				bo += (size_t)snprintf(buf + bo, sizeof(buf) - bo,
				    "%s\n", ucl_object_tostring_forced(e));
		}
		h_raw(h, "<label>Items<textarea name=\"items\" rows=\"6\" "
		    "class=\"mono\" spellcheck=\"false\" placeholder=\""
		    "10.1.8.0/22&#10;2001:db8:9::/48\">");
		h_txt(h, buf);
		h_raw(h, "</textarea><small class=\"help\">A line each: a prefix, a "
		    "UCS's id, an edge (its server), or a UCS End Point's id and "
		    "its preference (the higher taken first). Not for services."
		    "</small></label>");
		pfxlist_select(h, "Prefixes from the console's list", "pfx_console",
		    "Added to the items when kept (Network, Prefix lists).");
		h_raw(h, "<div class=\"two\">");
		text_field(h, "Protocols", "protocols", csv(jget(o, "protocols"),
		    lb, sizeof(lb)), "tcp, udp", "Services only: as an AFS's "
		    "PROTV4.");
		text_field(h, "Ports", "ports", csv(jget(o, "ports"), lb2,
		    sizeof(lb2)), "443, 8443", "Services only: as DPORT; empty "
		    "for any.");
		h_raw(h, "</div>");
		return (true);
	}
	if (app.modal == MODAL_SD_SWVC) {
		o = sd.edit[0] != '\0' ? jfind(jget(sd.doc, "swvcs"), "id",
		    sd.edit) : NULL;
		edit = o != NULL;
		fib = 1;
		it = NULL;
		while ((v = ucl_object_iterate(jget(sd.doc, "swvcs"), &it, true))
		    != NULL)
			if (jint(v, "fib", 0) >= fib)
				fib = (int)jint(v, "fib", 0) + 1;
		h_fmt(h, "<form data-form=\"sd-swvc\"><h2>%s</h2><p>A service "
		    "joins the subscriber's sites (an SWVC, MEF 70.2 §9): each "
		    "edge gives it a routing table of its own (setfib), the "
		    "tunnels between its edges go in it, and the policies say "
		    "how each flow is carried.</p><input type=\"hidden\" name=\""
		    "was\"", edit ? "A service, changed" : "A service");
		h_attr(h, "value", sd.edit);
		h_raw(h, "><div class=\"two\">");
		text_field(h, "Id", "id", edit ? jstr(o, "id") : "", "office", NULL);
		snprintf(buf, sizeof(buf), "%lld", edit ? (long long)jint(o, "fib",
		    1) : (long long)fib);
		text_field(h, "Routing table (FIB)", "fib", buf, "1", "1 or more, "
		    "one a service; net.fibs is raised on the edges as needed.");
		h_raw(h, "</div>");
		text_field(h, "Reserved prefixes", "reserved", edit ? csv(jget(o,
		    "reserved_prefixes"), buf, sizeof(buf)) : "100.64.0.0/24, "
		    "fd00:64::/64", "100.64.0.0/24, fd00:64::/64", "The tunnels' "
		    "inner addresses come from these, a /31 or /127 each "
		    "(§9.4).");
		{
			const ucl_object_t	*d = edit ? jget(o, "domains") : NULL;
			const ucl_object_t	*ds = jget(d, "service"), *db = jget(d,
			    "breakout"), *du = jget(d, "subscriber");
			char			 nb[32], rt[200];

			/* NAT64 at one edge, CLAT at the UNIs that say so. */
			h_raw(h, "<fieldset><legend>NAT64 <small class=\"dim\">RFC 6146, "
			    "Arcana's own: the service's IPv6 hosts reach the "
			    "Internet's IPv4 through one edge (ipfw nat64lsn); a UNI "
			    "with a CLAT prefix carries its IPv4 hosts there as IPv6 "
			    "(RFC 6877)</small></legend><div class=\"two\">");
			text_field(h, "NAT64 prefix", "n64_prefix", jstr(jget(o, "nat64"),
			    "prefix"), "64:ff9b::/96", "An IPv6 /96: the IPv4 Internet "
			    "as the hosts see it. Empty: no NAT64.");
			text_field(h, "NAT64 pool", "n64_pool", jstr(jget(o, "nat64"),
			    "pool"), "192.0.2.64/26", "IPv4 addresses the translated "
			    "flows go out from, taken out by the breakout's NAT.");
			h_raw(h, "</div><label>NAT64 edge<select name=\"n64_edge\">");
			option(h, "", "none", jstr(jget(o, "nat64"), "edge") != NULL ?
			    jstr(jget(o, "nat64"), "edge") : "");
			{
				const ucl_object_t	*ne;
				ucl_object_iter_t	 nit = NULL;

				while ((ne = ucl_object_iterate(jget(sd.doc, "edges"),
				    &nit, true)) != NULL)
					option(h, jstr(ne, "server"), host_name(jstr(ne,
					    "server")), jstr(jget(o, "nat64"), "edge") !=
					    NULL ? jstr(jget(o, "nat64"), "edge") : "");
			}
			h_raw(h, "</select></label></fieldset>");
			/* Destination sets by BGP attribute: lines of a name, AS
			 * numbers and as:value communities. */
			{
				const ucl_object_t	*xs, *xm;
				ucl_object_iter_t	 xit = NULL, xmit;
				char			 stext[4000];

				stext[0] = '\0';
				while ((xs = ucl_object_iterate(jget(o, "bgp_sets"), &xit,
				    true)) != NULL && strlen(stext) + 200 < sizeof(stext)) {
					snprintf(stext + strlen(stext), sizeof(stext) -
					    strlen(stext), "%s%s", stext[0] != '\0' ? "\n" : "",
					    jstr(xs, "name") != NULL ? jstr(xs, "name") : "");
					xmit = NULL;
					while ((xm = ucl_object_iterate(jget(xs, "as_path"),
					    &xmit, true)) != NULL && strlen(stext) + 20 <
					    sizeof(stext))
						snprintf(stext + strlen(stext), sizeof(stext) -
						    strlen(stext), " %lld", (long long)
						    ucl_object_toint(xm));
					xmit = NULL;
					while ((xm = ucl_object_iterate(jget(xs, "communities"),
					    &xmit, true)) != NULL && strlen(stext) + 20 <
					    sizeof(stext))
						snprintf(stext + strlen(stext), sizeof(stext) -
						    strlen(stext), " %lld:%lld", (long long)
						    ucl_object_toint(ucl_array_find_index(xm, 0)),
						    (long long)ucl_object_toint(ucl_array_find_index(
						    xm, 1)));
				}
				h_raw(h, "<label>Destination sets by BGP attribute<textarea "
				    "name=\"bgp_sets\" rows=\"3\" spellcheck=\"false\" "
				    "placeholder=\"country 64600 64601 64600:100\">");
				h_txt(h, stext);
				h_raw(h, "</textarea><small>One a line: a name, then the AS "
				    "numbers any of which in a route's path puts it in the "
				    "set, and as:value communities any of which does. An "
				    "edge names the uplink each set goes out by (Arcana's "
				    "own, by BIRD alone).</small></label>");
			}
			h_raw(h, "<fieldset><legend>Routing domains <small class=\""
			    "dim\">Mplify 119 §7.3: each a table, a route "
			    "distinguisher, route targets and an MPLS label; all "
			    "optional</small></legend><div class=\"two\">");
			snprintf(nb, sizeof(nb), "%lld", (long long)jint(db, "fib",
			    0));
			text_field(h, "Breakout domain: FIB", "dom_bfib", jint(db,
			    "fib", 0) > 0 ? nb : "", "2", "A table of its own for "
			    "the Internet: the default route there, the UNIs' routes "
			    "imported into it (R20-R26); the service's table holds "
			    "no default route then.");
			text_field(h, "Service domain: prefix", "dom_sprefix", jstr(
			    ds, "prefix"), "100.64.0.0/24", "The tunnels' addresses "
			    "come from it (else from the reserved prefixes).");
			h_raw(h, "</div><div class=\"two\">");
			snprintf(nb, sizeof(nb), "%lld", (long long)jint(ds, "fib",
			    0));
			text_field(h, "Service domain: FIB", "dom_sfib", jint(ds,
			    "fib", 0) > 0 ? nb : "", "3", "Kept for the control "
			    "plane interface (119-4).");
			text_field(h, "Route distinguishers", "dom_rd", (jstr(ds,
			    "rd") != NULL || jstr(db, "rd") != NULL || jstr(du, "rd")
			    != NULL) ? (snprintf(rt, sizeof(rt), "%s, %s, %s", jstr(
			    ds, "rd") != NULL ? jstr(ds, "rd") : "", jstr(db, "rd") !=
			    NULL ? jstr(db, "rd") : "", jstr(du, "rd") != NULL ?
			    jstr(du, "rd") : ""), rt) : "", "64600:1, 64600:2, "
			    "64600:3", "Service, breakout, subscriber: ASN:n or "
			    "A.B.C.D:n each, by commas (R16).");
			h_raw(h, "</div><div class=\"two\">");
			text_field(h, "Route targets", "dom_rt", (jget(ds, "rt") !=
			    NULL || jget(db, "rt") != NULL || jget(du, "rt") != NULL)
			    ? (snprintf(rt, sizeof(rt), "%s, %s, %s", csv(jget(ds,
			    "rt"), lb, sizeof(lb)), csv(jget(db, "rt"), lb2, sizeof(
			    lb2)), csv(jget(du, "rt"), nb, sizeof(nb))), rt) : "",
			    "64600:1, 64600:2, 64600:3", "One each, in the same "
			    "order (R17).");
			text_field(h, "Labels", "dom_label", (jint(ds, "label", 0) >
			    0 || jint(db, "label", 0) > 0 || jint(du, "label", 0) >
			    0) ? (snprintf(rt, sizeof(rt), "%lld, %lld, %lld", (long
			    long)jint(ds, "label", 0), (long long)jint(db, "label",
			    0), (long long)jint(du, "label", 0)), rt) : "", "1001, "
			    "1002, 1003", "MPLS labels, 16 to 1048575, in the same "
			    "order (R19); for the tunnel format to come.");
			h_raw(h, "</div></fieldset>");
		}
		h_raw(h, "<fieldset><legend>Underlays it uses</legend>");
		n = 0;
		it = NULL;
		while ((v = ucl_object_iterate(jget(sd.doc, "ucs"), &it, true)) !=
		    NULL) {
			h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" "
			    "name=\"ucs_%d\"", n++);
			h_attr(h, "value", jstr(v, "id"));
			if (!edit || jget(o, "ucs") == NULL || jfind_str(jget(o,
			    "ucs"), jstr(v, "id")))
				h_raw(h, " checked");
			h_raw(h, "> ");
			h_txt(h, jstr(v, "id"));
			h_raw(h, "</label>");
		}
		if (n == 0)
			h_raw(h, "<small>No underlay yet: the dashboard adds "
			    "them.</small>");
		h_raw(h, "</fieldset><div class=\"two\">");
		snprintf(buf, sizeof(buf), "%lld", (long long)jint(o, "as", 0));
		text_field(h, "Provider AS", "as", edit && jget(o, "as") != NULL ?
		    buf : "", "64512", "For BGP at a UNI and between the edges; "
		    "64512 if empty.");
		text_field(h, "iBGP password", "md5", edit ? jstr(o, "md5") : "",
		    "", "TCP MD5 on the sessions between the edges (Mplify 119 "
		    "R12); empty for none.");
		h_raw(h, "</div><div class=\"two\"><label>Control plane<select "
		    "name=\"cp_host\">");
		option(h, "", "none: iBGP between every two edges", edit && jget(o,
		    "control_plane") != NULL ? jstr(jget(o, "control_plane"),
		    "host") : "");
		for (i = 0; i < app.nservers; i++)
			if (edge_by(app.servers[i].id) != NULL)
				option(h, app.servers[i].id, app.servers[i].name, edit
				    && jget(o, "control_plane") != NULL ? jstr(jget(o,
				    "control_plane"), "host") : "");
		h_raw(h, "</select><small>An edge of the service whose BIRD "
		    "reflects the others' routes (RFC 4456, Mplify 119 §8.3): "
		    "each edge peers with it alone.</small></label>");
		text_field(h, "Cluster id", "cp_cluster", edit && jget(o,
		    "control_plane") != NULL ? jstr(jget(o, "control_plane"),
		    "cluster_id") : "", "", "The reflector's, an IPv4 address; its "
		    "router id if empty.");
		h_raw(h, "</div><div class=\"two\"><label>Control tunnel over"
		    "<select name=\"cp_ctvc\">");
		option(h, "", "none: the iBGP by the data tunnels", edit && jget(o,
		    "control_plane") != NULL ? jstr(jget(o, "control_plane"),
		    "ctvc") : "");
		it = NULL;
		while ((v = ucl_object_iterate(jget(sd.doc, "ucs"), &it, true)) !=
		    NULL)
			option(h, jstr(v, "id"), jstr(v, "id"), edit && jget(o,
			    "control_plane") != NULL ? jstr(jget(o, "control_plane"),
			    "ctvc") : "");
		h_raw(h, "</select><small>A tunnel of the control plane's own "
		    "from each edge to the host over this underlay (the CTVC, "
		    "Mplify 119 R5, R6), carrying the iBGP and nothing else.</small>"
		    "</label>");
		snprintf(buf, sizeof(buf), "%lld", (long long)jint(jget(o,
		    "intervals"), "eval", 1000));
		text_field(h, "Evaluation interval, ms", "eval", buf, "1000", "The "
		    "probes' sample, and how often the manager looks (§9.7).");
		h_raw(h, "</div><div class=\"two\">");
		h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" name=\""
		    "bfd\" value=\"1\"%s> BFD on the tunnels, by BIRD</label>", edit
		    && jget(o, "bfd") != NULL && ucl_object_type(jget(o, "bfd")) ==
		    UCL_OBJECT ? " checked" : "");
		snprintf(buf, sizeof(buf), "%lld", (long long)jint(jget(o, "bfd"),
		    "interval", 200));
		text_field(h, "BFD interval, ms", "bfd_interval", buf, "200", "100 "
		    "to 300; three missed and the tunnel is down.");
		h_fmt(h, "<label>iBGP between the edges<select name=\"ibgp\">"
		    "<option value=\"tunnel\"%s>By each tunnel: a session between its "
		    "ends</option><option value=\"loopback\"%s>Between loopbacks: "
		    "one session with each edge, multihop, over every tunnel at once "
		    "(ECMP); a third edge carries the traffic while every direct "
		    "tunnel is down; needs BFD</option></select></label>", edit &&
		    jstr(o, "ibgp") != NULL && strcmp(jstr(o, "ibgp"), "loopback") ==
		    0 ? "" : " selected", edit && jstr(o, "ibgp") != NULL && strcmp(
		    jstr(o, "ibgp"), "loopback") == 0 ? " selected" : "");
		h_raw(h, "</div><fieldset><legend>Threshold crossing alerts: a "
		    "fault when a tunnel's metric passes one (Mplify 119 §11.4)"
		    "</legend><div class=\"two\">");
		v = jget(o, "tca");
		snprintf(buf, sizeof(buf), "%g", jnum(v, "delay", 0));
		text_field(h, "Delay, ms", "tca_delay", jget(v, "delay") != NULL ?
		    buf : "", "none", NULL);
		snprintf(buf, sizeof(buf), "%g", jnum(v, "ipdv", 0));
		text_field(h, "Variation, ms", "tca_ipdv", jget(v, "ipdv") != NULL ?
		    buf : "", "none", NULL);
		h_raw(h, "</div><div class=\"two\">");
		snprintf(buf, sizeof(buf), "%g", jnum(v, "loss", 0));
		text_field(h, "Loss, a fraction", "tca_loss", jget(v, "loss") != NULL
		    ? buf : "", "none", "0.01 is one percent.");
		snprintf(buf, sizeof(buf), "%lld", (long long)jint(v, "damping", 1));
		text_field(h, "Damping, intervals in a row", "tca_damping", buf,
		    "1", NULL);
		h_raw(h, "</div></fieldset>");
		{
			const ucl_object_t	*imp = jget(o, "importance"), *pb =
			    jget(o, "probe"), *iv = jget(o, "intervals");
			char			 lb[400];
			static const struct {
				const char	*key, *label, *ph, *help;
			} probes[] = {
				{ "interval", "Probe every, ms", "1000", NULL },
				{ "size", "Probe size, bytes", "64", NULL },
				{ "dscp", "Probe DSCP", "0", "As the traffic it "
				    "stands for: 46 for voice." },
				{ "timeout", "A reply waited for, ms", "1000", NULL },
				{ "down", "Down after so many missed", "3", NULL },
				{ "up", "Up after so many replies", "3", NULL },
				{ "history", "Samples kept", "3600", NULL },
				{ "report", "Reported every so many intervals",
				    "1", NULL },
			};

			h_raw(h, "<details class=\"sd-more\"><summary>Application "
			    "groups, importance, probes and timers</summary>");
			h_raw(h, "<div class=\"two\">");
			text_field(h, "Application groups", "groups", csv(jget(o,
			    "groups"), lb, sizeof(lb)), "voip, web", "Names that "
			    "group applications, by commas; a rule may name a "
			    "group (§9.13).");
			h_raw(h, "</div><div class=\"two\">");
			text_field(h, "Importance levels", "imp_levels", csv(jget(
			    imp, "levels"), lb, sizeof(lb)), "high, normal, low",
			    "From the most important, by commas: a policy names "
			    "one, and the more important is carried first when "
			    "bandwidth is short (§9.11).");
			text_field(h, "Importance by default", "imp_default", jstr(
			    imp, "default"), "normal", NULL);
			h_raw(h, "</div><div class=\"two\">");
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(jget(o,
			    "bfd"), "multiplier", 3));
			text_field(h, "BFD: missed before down", "bfd_mult", buf,
			    "3", "2 to 10.");
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(iv,
			    "arrival", 100));
			text_field(h, "A sample arrives within, ms", "iv_arrival",
			    buf, "100", "Shorter than the evaluation interval "
			    "(§9.7).");
			h_raw(h, "</div><div class=\"two\">");
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(iv, "ir",
			    500));
			text_field(h, "Information rate interval, ms", "iv_ir", buf,
			    "500", "1000 at most.");
			h_raw(h, "</div><fieldset><legend>The probes on the "
			    "tunnels <small class=\"dim\">STAMP-like, the agent's "
			    "own; empty: as the agent has them</small></legend>"
			    "<div class=\"two\">");
			for (i = 0; i < (int)nitems(probes); i++) {
				char	name[24];

				snprintf(name, sizeof(name), "pb_%s", probes[i].key);
				snprintf(buf, sizeof(buf), "%lld", (long long)jint(pb,
				    probes[i].key, 0));
				text_field(h, probes[i].label, name, jget(pb,
				    probes[i].key) != NULL ? buf : "", probes[i].ph,
				    probes[i].help);
				if (i % 2 == 1 && i + 1 < (int)nitems(probes))
					h_raw(h, "</div><div class=\"two\">");
			}
			h_raw(h, "</div></fieldset></details>");
		}
		return (true);
	}
	if (sw == NULL)
		return (false);
	if (app.modal == MODAL_SD_LIMITER) {
		o = sd.edit[0] != '\0' ? jfind(jget(sw, "rate_limiters"), "name",
		    sd.edit) : NULL;
		h_fmt(h, "<form data-form=\"sd-lim\"><h2>%s</h2><p>A bandwidth "
		    "the applications whose policy names it share at each end "
		    "point (§9.9): what they are promised, and what they may "
		    "take at most when there is room (dummynet(4) pipes on the "
		    "edges).</p><input type=\"hidden\" name=\"was\"", o != NULL ?
		    "A rate limiter, changed" : "A rate limiter");
		h_attr(h, "value", sd.edit);
		h_raw(h, ">");
		text_field(h, "Name", "name", jstr(o, "name"), "bulk", NULL);
		h_raw(h, "<div class=\"two\">");
		snprintf(buf, sizeof(buf), "%lld", (long long)jint(o, "commit", 0));
		text_field(h, "Committed, bits per second", "commit", o != NULL ?
		    buf : "", "10000000", "What they always have.");
		snprintf(buf, sizeof(buf), "%lld", (long long)jint(o, "limit", 0));
		text_field(h, "At most, bits per second", "limit", o != NULL &&
		    ucl_object_type(jget(o, "limit")) == UCL_INT ? buf : "",
		    "none", "As much as there is, if empty.");
		h_raw(h, "</div>");
		return (true);
	}
	if (app.modal == MODAL_SD_TOPO) {
		const ucl_object_t	*ep;

		o = sd.edit[0] != '\0' ? jfind(jget(sw, "topologies"), "name",
		    sd.edit) : NULL;
		h_fmt(h, "<form data-form=\"sd-topo\"><h2>%s</h2><p>Which end "
		    "points reach which (§9.6): all those in it reach each "
		    "other; with roots, a root reaches every leaf and a leaf "
		    "only the roots, a hub and its spokes. A policy names the "
		    "topology its applications keep to.</p><input type=\"hidden"
		    "\" name=\"was\"", o != NULL ? "A topology, changed" :
		    "A topology");
		h_attr(h, "value", sd.edit);
		h_raw(h, ">");
		if (ucl_array_size(jget(sw, "end_points")) < 2) {
			sd.blocked = true;
			h_raw(h, "<div class=\"notice\">A topology is of two end "
			    "points at least: the service has fewer. <button "
			    "class=\"ghost small\" data-act=\"sd-ep-add\">+ end "
			    "point</button></div>");
			return (true);
		}
		text_field(h, "Name", "name", jstr(o, "name"), "hub", NULL);
		h_raw(h, "<table class=\"net sd\"><thead><tr><th>End point</th>"
		    "<th>In it</th></tr></thead><tbody>");
		it = NULL;
		n = 0;
		while ((ep = ucl_object_iterate(jget(sw, "end_points"), &it,
		    true)) != NULL) {
			const char	*role = jfind_str(jget(o, "roots"), jstr(ep,
			    "id")) ? "root" : jfind_str(jget(o, "leaves"),
			    jstr(ep, "id")) ? "leaf" : jfind_str(jget(o,
			    "end_points"), jstr(ep, "id")) ? "member" : "";

			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(ep, "id"));
			h_raw(h, "</td><td>");
			h_fmt(h, "<input type=\"hidden\" name=\"ep_%d\"", n);
			h_attr(h, "value", jstr(ep, "id"));
			h_fmt(h, "><select name=\"role_%d\">", n++);
			option(h, "", "not in it", role);
			option(h, "member", "in it: reaches all the others",
			    role);
			option(h, "root", "a root: reaches every leaf", role);
			option(h, "leaf", "a leaf: reaches the roots alone",
			    role);
			h_raw(h, "</select></td></tr>");
		}
		h_raw(h, "</tbody></table>");
		return (true);
	}
	if (app.modal == MODAL_SD_ZONE) {
		o = sd.edit[0] != '\0' ? jfind(jget(sw, "zones"), "name", sd.edit)
		    : NULL;
		h_fmt(h, "<form data-form=\"sd-zone\"><h2>%s</h2><p>Hosts by "
		    "their source address (§9.5): the rules of a zone say what "
		    "its flows may do, at every end point whose own map says "
		    "nothing.</p><input type=\"hidden\" name=\"was\"", o != NULL ?
		    "A zone, changed" : "A zone");
		h_attr(h, "value", sd.edit);
		h_raw(h, ">");
		text_field(h, "Name", "name", jstr(o, "name"), "staff", NULL);
		v = jget(o, "prefixes");
		text_field(h, "Prefixes", "prefixes", v != NULL && ucl_object_type(
		    v) == UCL_ARRAY ? csv(v, buf, sizeof(buf)) : "", "10.1.0.0/16, "
		    "2001:db8:1::/48", "Empty: the Default zone, every host no "
		    "other zone names (one service has one).");
		nlist_select(h, "And the prefixes of the list", "prefix_list",
		    "prefixes", jstr(o, "prefix-list"), "Kept once, under Lists.");
		pfxlist_select(h, "Prefixes from the console's list", "pfx_console",
		    "Added to the zone's when kept (Network, Prefix lists).");
		return (true);
	}
	if (app.modal == MODAL_SD_CONFIG) {
		h_raw(h, "<form data-form=\"none\"><h2>");
		h_txt(h, sd.config_name);
		h_raw(h, ", its WireGuard configuration</h2><p>Shown once: the "
		    "private key is kept nowhere by the console. Give it to the "
		    "person as their <code>wg-quick</code> configuration; to be "
		    "had again, the identity is issued again.</p><textarea "
		    "readonly rows=\"14\" class=\"mono\" spellcheck=\"false\">");
		h_txt(h, sd.config != NULL ? sd.config : "");
		h_raw(h, "</textarea><div class=\"actions\"><button type=\""
		    "button\" class=\"primary\" data-act=\"sd-config-done\">Done, "
		    "I have it</button></div></form>");
		return (true);
	}
	if (app.modal == MODAL_SD_GROUP) {
		const ucl_object_t	*s2, *e2, *z, *g = NULL;
		ucl_object_iter_t	 sit, eit, zit;
		char			 at[200], atv[200], *p, *q, reach[600];

		/* sd.edit: swvc|end_point|name of the one changed, or "". */
		snprintf(at, sizeof(at), "%s", sd.edit);
		p = strchr(at, '|');
		q = p != NULL ? strchr(p + 1, '|') : NULL;
		if (p != NULL && q != NULL) {
			*p++ = '\0';
			*q++ = '\0';
			s2 = jfind(jget(sd.doc, "swvcs"), "id", at);
			e2 = jfind(jget(s2, "end_points"), "id", p);
			g = jfind(jget(jget(e2, "remote"), "groups"), "name", q);
			snprintf(atv, sizeof(atv), "%s|%s", at, p);
		} else
			atv[0] = '\0';
		h_fmt(h, "<form data-form=\"sd-group\"><h2>%s</h2><p>Of a remote "
		    "end point's identities: its members' flows get the "
		    "policies of its zone, their addresses come from its pool, "
		    "and they reach each other and the members of the groups "
		    "named; two groups neither of which names the other are "
		    "kept apart on the edge.</p><input type=\"hidden\" name=\"was\"",
		    g != NULL ? "A group, changed" : "A group");
		h_attr(h, "value", sd.edit);
		h_raw(h, "><label>At<select name=\"at\">");
		sit = NULL;
		while ((s2 = ucl_object_iterate(jget(sd.doc, "swvcs"), &sit, true))
		    != NULL) {
			eit = NULL;
			while ((e2 = ucl_object_iterate(jget(s2, "end_points"), &eit,
			    true)) != NULL) {
				if (jget(e2, "remote") == NULL)
					continue;
				snprintf(at, sizeof(at), "%s|%s", jstr(s2, "id"), jstr(
				    e2, "id"));
				h_raw(h, "<option");
				h_attr(h, "value", at);
				if (strcmp(at, atv) == 0)
					h_raw(h, " selected");
				h_raw(h, ">");
				h_txt(h, jstr(s2, "id"));
				h_raw(h, " · ");
				h_txt(h, jstr(e2, "id"));
				h_raw(h, " on ");
				h_txt(h, host_name(jstr(e2, "edge")));
				h_raw(h, "</option>");
			}
		}
		h_raw(h, "</select></label><div class=\"two\">");
		text_field(h, "Name", "name", jstr(g, "name"), "staff", NULL);
		h_raw(h, "<label>Zone<input name=\"zone\" list=\"sd-zones\" "
		    "required spellcheck=\"false\" placeholder=\"office\"");
		h_attr(h, "value", jstr(g, "zone") != NULL ? jstr(g, "zone") : "");
		h_raw(h, "></label><datalist id=\"sd-zones\">");
		sit = NULL;
		while ((s2 = ucl_object_iterate(jget(sd.doc, "swvcs"), &sit, true))
		    != NULL) {
			zit = NULL;
			while ((z = ucl_object_iterate(jget(s2, "zones"), &zit, true))
			    != NULL) {
				h_raw(h, "<option");
				h_attr(h, "value", jstr(z, "name"));
				h_raw(h, ">");
			}
		}
		h_raw(h, "</datalist></div><div class=\"two\">");
		text_field(h, "Pool", "pool", jstr(g, "pool"), "100.65.0.64/26",
		    "Inside the remote's prefix, not holding the edge's own "
		    "address, the first. Empty: anywhere in the prefix outside "
		    "the pools.");
		text_field(h, "Reaches", "reach", csv(jget(g, "reach"), reach,
		    sizeof(reach)), "contractors", "Groups of this end point, "
		    "comma-separated; its own members always.");
		h_raw(h, "</div>");
		return (true);
	}
	if (app.modal == MODAL_SD_IDENTITY) {
		const ucl_object_t	*s2, *e2, *z, *k, *g;
		ucl_object_iter_t	 sit, eit, zit, kit, git;

		h_raw(h, "<form data-form=\"sd-identity\"><h2>An identity</h2><p>"
		    "Someone reaching a service from afar, by WireGuard, at one of "
		    "its remote end points (SASE-3): a console user, by the name "
		    "of their sign-in key, or a name of its own. The key pair is "
		    "made here, and the configuration shown once.</p>");
		{
			bool	any = false;

			sit = NULL;
			while ((s2 = ucl_object_iterate(jget(sd.doc, "swvcs"),
			    &sit, true)) != NULL) {
				eit = NULL;
				while ((e2 = ucl_object_iterate(jget(s2,
				    "end_points"), &eit, true)) != NULL)
					if (jget(e2, "remote") != NULL)
						any = true;
			}
			if (!any) {
				sd.blocked = true;
				h_raw(h, "<div class=\"notice\">No remote end point "
				    "yet: one is where people reach a service from "
				    "afar, a WireGuard interface of an edge. Add one "
				    "to a service, under <b>End points</b>.</div>");
				return (true);
			}
		}
		h_raw(h, "<label>At<select name=\"at\">");
		sit = NULL;
		while ((s2 = ucl_object_iterate(jget(sd.doc, "swvcs"), &sit, true))
		    != NULL) {
			eit = NULL;
			while ((e2 = ucl_object_iterate(jget(s2, "end_points"), &eit,
			    true)) != NULL) {
				if (jget(e2, "remote") == NULL)
					continue;
				h_raw(h, "<option");
				h_fmt(h, " value=\"%s|%s\">", jstr(s2, "id"), jstr(e2,
				    "id"));
				h_txt(h, jstr(s2, "id"));
				h_raw(h, " · ");
				h_txt(h, jstr(e2, "id"));
				h_raw(h, " on ");
				h_txt(h, host_name(jstr(e2, "edge")));
				h_raw(h, "</option>");
			}
		}
		h_raw(h, "</select></label>");
		text_field(h, "Name", "name", NULL, "alice", "A console user's "
		    "sign-in key name, or any name.");
		h_raw(h, "<datalist id=\"sd-users\">");
		kit = NULL;
		while ((k = ucl_object_iterate(app.keys, &kit, true)) != NULL) {
			h_raw(h, "<option");
			h_attr(h, "value", jstr(k, "name"));
			h_raw(h, ">");
		}
		h_raw(h, "</datalist><fieldset class=\"toggles\"><label class=\""
		    "toggle\"><input type=\"checkbox\" name=\"user\"><span>A "
		    "console user <em>the name is one of the sign-in keys'</em>"
		    "</span></label></fieldset>");
		h_raw(h, "<div class=\"two\"><label>Group <small class=\"dim\">"
		    "of the end point's</small><input name=\"group\" list=\""
		    "sd-groups\" spellcheck=\"false\" placeholder=\"staff\"></label>"
		    "<datalist id=\"sd-groups\">");
		sit = NULL;
		while ((s2 = ucl_object_iterate(jget(sd.doc, "swvcs"), &sit, true))
		    != NULL) {
			eit = NULL;
			while ((e2 = ucl_object_iterate(jget(s2, "end_points"), &eit,
			    true)) != NULL) {
				git = NULL;
				while ((g = ucl_object_iterate(jget(jget(e2, "remote"),
				    "groups"), &git, true)) != NULL) {
					h_raw(h, "<option");
					h_attr(h, "value", jstr(g, "name"));
					h_raw(h, ">");
				}
			}
		}
		h_raw(h, "</datalist><label>Zone <small class=\"dim\">when in no "
		    "group</small><input name=\"zone\" list=\"sd-zones\" "
		    "spellcheck=\"false\" placeholder=\"staff\"></label>"
		    "<datalist id=\"sd-zones\">");
		sit = NULL;
		while ((s2 = ucl_object_iterate(jget(sd.doc, "swvcs"), &sit, true))
		    != NULL) {
			zit = NULL;
			while ((z = ucl_object_iterate(jget(s2, "zones"), &zit, true))
			    != NULL) {
				h_raw(h, "<option");
				h_attr(h, "value", jstr(z, "name"));
				h_raw(h, ">");
			}
		}
		h_raw(h, "</datalist></div>");
		return (true);
	}
	if (app.modal == MODAL_SD_LIST) {
		const ucl_object_t	*lf = sd.edit[0] != '\0' && sd.lists != NULL ?
		    jfind(jget(sd.lists, "feeds"), "name", sd.edit) : NULL;
		char			*text = NULL;

		h_fmt(h, "<form data-form=\"sd-list\"><h2>%s</h2><p>A list for the "
		    "security policies: a feed the console's host fetches on its "
		    "schedule, or entries pasted here, one a line, prefixes and "
		    "domain names, # for a note.</p><input type=\"hidden\" name=\""
		    "was\"", lf != NULL ? "A list, changed" : "A list");
		h_attr(h, "value", sd.edit);
		h_raw(h, ">");
		text_field(h, "Name", "name", jstr(lf, "name"), "blocked", NULL);
		text_field(h, "Feed URL", "url", jstr(lf, "url"), "https://…/"
		    "list.txt", "Empty for a pasted list.");
		if (lf != NULL && jget(lf, "entries") != NULL) {
			const ucl_object_t	*e;
			ucl_object_iter_t	 eit = NULL;
			struct html		 b;

			memset(&b, 0, sizeof(b));
			while ((e = ucl_object_iterate(jget(lf, "entries"), &eit,
			    true)) != NULL)
				h_fmt(&b, "%s\n", ucl_object_tostring_forced(e));
			text = b.s;
		}
		h_raw(h, "<label>Entries<textarea name=\"text\" rows=\"8\">");
		h_txt(h, text != NULL ? text : "");
		h_raw(h, "</textarea></label>");
		free(text);
		return (true);
	}
	if (app.modal == MODAL_SD_SECPOL) {
		o = sd.edit[0] != '\0' ? jfind(jget(sw, "security_policies"),
		    "name", sd.edit) : NULL;
		cr = jget(o, "criteria");
		h_fmt(h, "<form data-form=\"sd-secpol\"><h2>%s</h2><p>A security "
		    "policy (MEF 88): what a flow's traffic may not do, where a "
		    "policy names it by af-security-ingress or -egress. Each "
		    "part is optional.</p><input type=\"hidden\" name=\"was\"", o !=
		    NULL ? "A security policy, changed" : "A security policy");
		h_attr(h, "value", sd.edit);
		h_raw(h, ">");
		text_field(h, "Name", "name", jstr(o, "name"), "guard", NULL);
		v = jget(jget(cr, "ip-block"), "allow");
		text_field(h, "Addresses allowed", "allow", v != NULL &&
		    ucl_object_type(v) == UCL_ARRAY ? csv(v, buf, sizeof(buf)) : "",
		    "10.1.0.0/16", "Prefixes let through before the denied are "
		    "looked at (ip-block).");
		v = jget(jget(cr, "ip-block"), "deny");
		text_field(h, "Addresses denied", "deny", v != NULL &&
		    ucl_object_type(v) == UCL_ARRAY ? csv(v, buf, sizeof(buf)) : "",
		    "192.0.2.0/24, 2001:db8:bad::/48", "Prefixes dropped, as "
		    "source or destination (ip-block).");
		v = jget(jget(cr, "ip-block"), "lists");
		text_field(h, "Address lists", "iplists", v != NULL &&
		    ucl_object_type(v) == UCL_ARRAY ? csv(v, buf, sizeof(buf)) : "",
		    "blocked", "Lists by name (the Security tab's), their "
		    "prefixes denied (ip-block).");
		v = jget(jget(cr, "dns-domain-filter"), "deny");
		text_field(h, "Domains denied", "domains", v != NULL &&
		    ucl_object_type(v) == UCL_ARRAY ? csv(v, buf, sizeof(buf)) : "",
		    "ads.example, tracker.example", "Names that do not resolve, "
		    "with everything under them (dns-domain-filter).");
		v = jget(jget(cr, "dns-domain-filter"), "lists");
		text_field(h, "Domain lists", "dnslists", v != NULL &&
		    ucl_object_type(v) == UCL_ARRAY ? csv(v, buf, sizeof(buf)) : "",
		    "blocked", "Lists by name, their domains denied.");
		h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" name=\""
		    "dnsproto\" value=\"1\"%s> DNS only to the provider's resolver "
		    "(dns-protocol-filter)</label>", jbool(cr, "dns-protocol-filter")
		    ? " checked" : "");
		snprintf(buf, sizeof(buf), "%lld", (long long)jint(cr, "rate-limit",
		    0));
		text_field(h, "Rate limit, bits per second", "rate", jget(cr,
		    "rate-limit") != NULL ? buf : "", "2000000", "A cap on the "
		    "flow's traffic, by dummynet (rate-limit); empty for none.");
		h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" name=\""
		    "log\" value=\"1\"%s> Log what is denied (log)</label>", jbool(
		    cr, "log") ? " checked" : "");
		/* URLs, by a proxy on the edge (SASE-4): a plugin, Squid. */
		{
			const char	*mode = jstr(jget(cr, "url-filter"), "mode");

			h_fmt(h, "<label>URL filter <select name=\"urlmode\"><option "
			    "value=\"\"%s>none</option><option value=\"sni\"%s>the "
			    "TLS names looked at, nothing opened (sni)</option>"
			    "<option value=\"inspect\"%s>TLS opened with the edge's "
			    "CA (inspect)</option></select><small>By Squid on the "
			    "edge, a plugin installed there by hand; HTTP and TLS "
			    "from the end points go through it (url-filter).</small>"
			    "</label>", mode == NULL ? " selected" : "", mode != NULL
			    && strcmp(mode, "sni") == 0 ? " selected" : "", mode !=
			    NULL && strcmp(mode, "inspect") == 0 ? " selected" : "");
			v = jget(jget(cr, "url-filter"), "deny");
			text_field(h, "URL domains denied", "urldomains", v != NULL &&
			    ucl_object_type(v) == UCL_ARRAY ? csv(v, buf, sizeof(buf))
			    : "", "bad.example", "Sites refused, with everything "
			    "under them, by name in TLS or HTTP.");
			v = jget(jget(cr, "url-filter"), "lists");
			text_field(h, "URL domain lists", "urllists", v != NULL &&
			    ucl_object_type(v) == UCL_ARRAY ? csv(v, buf, sizeof(buf))
			    : "", "blocked", "Lists by name, their domains refused.");
			v = jget(jget(cr, "url-filter"), "allow");
			text_field(h, "URL domains allowed", "urlallow", v != NULL &&
			    ucl_object_type(v) == UCL_ARRAY ? csv(v, buf, sizeof(buf))
			    : "", "ok.bad.example", "Let through whatever the denied "
			    "domains and lists say: a site under a denied one, a "
			    "list's mistake.");
		}
		/* Malware, by c-icap and ClamAV behind the same Squid. */
		h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" name=\""
		    "malware\" value=\"1\"%s> Scan for malware (malware)<small>"
		    "What comes back over HTTP, and over TLS where it is opened "
		    "(inspect), scanned by ClamAV through c-icap, behind the "
		    "same Squid: plugins installed by hand (c-icap, "
		    "c-icap-modules, clamav and its signatures).</small></label>",
		    jbool(cr, "malware") ? " checked" : "");
		/* Intrusion detection, by Suricata on the UNIs (SASE-4). */
		{
			const ucl_object_t	*ids = jget(cr, "ids"), *r;
			ucl_object_iter_t	 rit = NULL;

			const char		*m = jstr(ids, "mode");

			h_fmt(h, "<label>Intrusion detection <select name=\""
			    "idsmode\"><option value=\"\"%s>none</option><option "
			    "value=\"detect\"%s>alerts, nothing stopped (detect)"
			    "</option><option value=\"prevent\"%s>in the way, what "
			    "a drop rule matches stopped (prevent)</option></select>"
			    "<small>By Suricata on the edges, a plugin installed "
			    "there by hand, on the service's UNIs; what it finds "
			    "comes as events (ids). Where it prevents, ipfw diverts "
			    "the UNIs' traffic through it, and while it is not "
			    "running nothing passes there.</small></label>", ids ==
			    NULL ? " selected" : "", ids != NULL && (m == NULL ||
			    strcmp(m, "prevent") != 0) ? " selected" : "", m !=
			    NULL && strcmp(m, "prevent") == 0 ? " selected" : "");
			h_raw(h, "<label>Rules of its own<textarea name=\"idsrules\" "
			    "rows=\"4\" placeholder=\"alert http any any -&gt; "
			    "$HOME_NET any (msg:&quot;...&quot;; sid:1000001; rev:1;)"
			    "\">");
			while ((r = ucl_object_iterate(jget(ids, "rules"), &rit,
			    true)) != NULL) {
				h_txt(h, ucl_object_tostring_forced(r));
				h_raw(h, "\n");
			}
			h_raw(h, "</textarea><small>Suricata rules, one a line; "
			    "the edge checks them (suricata -T) before they run."
			    "</small></label>");
			h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" "
			    "name=\"idsruleset\" value=\"1\"%s> Add the ruleset "
			    "suricata-update keeps on the edge<small>%s</small>"
			    "</label>", jbool(ids, "ruleset") ? " checked" : "",
			    "Emerging Threats Open, fetched on the edge by its "
			    "Security page's Fetch the ruleset (suricata-update); "
			    "left out until it is.");
		}
		return (true);
	}
	if (app.modal == MODAL_SD_FLOW) {
		static const char *const apps[] = { "dns", "http", "https", "ssh",
		    "sip", "ntp", "smtp", "imap", "pop3", "ldap", "rdp", "snmp",
		    "syslog", "ike", "bgp", "quic", "dhcp", "icmp" };

		o = sd.edit[0] != '\0' ? jfind(jget(sw, "flows"), "name", sd.edit)
		    : NULL;
		cr = jget(o, "criteria");
		h_fmt(h, "<form data-form=\"sd-flow\"><h2>%s</h2><p>What a packet "
		    "is (an Application Flow Specification, §9.14): the first "
		    "flow that matches names it, so the order of the list "
		    "counts. Everything said here must hold at once.</p><input "
		    "type=\"hidden\" name=\"was\"", o != NULL ? "A flow, changed" :
		    "A flow");
		h_attr(h, "value", sd.edit);
		h_raw(h, "><div class=\"two\">");
		text_field(h, "Name", "name", jstr(o, "name"), "voice", NULL);
		text_field(h, "Group", "group", jstr(o, "group"), "none", "Flows of "
		    "a group share a rule by the group's name (§9.13).");
		h_raw(h, "</div>");
		h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" name=\""
		    "any\" value=\"1\"%s> Everything: the last flow, what no other "
		    "matched</label>", cr != NULL && jget(cr, "any") != NULL ?
		    " checked" : "");
		h_raw(h, "<fieldset class=\"sd-apps\"><legend>Applications, by "
		    "port (APPID, Table 8)</legend>");
		for (i = 0; i < (int)(sizeof(apps) / sizeof(apps[0])); i++) {
			h_fmt(h, "<label class=\"toggle inline\"><input type=\""
			    "checkbox\" name=\"app_%s\" value=\"1\"%s> %s</label>",
			    apps[i], jfind_str(jget(cr, "appid"), apps[i]) ?
			    " checked" : "", apps[i]);
		}
		h_raw(h, "</fieldset><div class=\"two\">");
		text_field(h, "DSCP", "dscp", crit_text(cr, "dscp", buf, sizeof(buf)),
		    "46", "Numbers, with commas.");
		text_field(h, "Protocol", "proto", crit_text(cr, jget(cr,
		    "nextheadv6") != NULL ? "nextheadv6" : "protv4", buf,
		    sizeof(buf)), "tcp, udp", "tcp, udp, icmp, a number.");
		h_raw(h, "</div><div class=\"two\">");
		text_field(h, "Destination ports", "dport", crit_text(cr, "dport",
		    buf, sizeof(buf)), "80, 443", NULL);
		text_field(h, "Source ports", "sport", crit_text(cr, "sport", buf,
		    sizeof(buf)), "", NULL);
		h_raw(h, "</div><div class=\"two\">");
		text_field(h, "From prefixes", "src", crit_text(cr, jget(cr,
		    "sav6") != NULL ? "sav6" : "sav4", buf, sizeof(buf)),
		    "10.1.0.0/24", "IPv4 or IPv6, not both in one flow.");
		text_field(h, "To prefixes", "dst", crit_text(cr, jget(cr, "dav6")
		    != NULL ? "dav6" : "dav4", buf, sizeof(buf)), "10.2.0.0/24",
		    NULL);
		h_raw(h, "</div><div class=\"two\">");
		nlist_select(h, "Or from a list", "src_list", "prefixes",
		    jstr(cr, "src-list"), "Instead of the prefixes above.");
		nlist_select(h, "Or to a list", "dst_list", "prefixes", jstr(cr,
		    "dst-list"), NULL);
		h_raw(h, "</div><div class=\"two\">");
		nlist_select(h, "Services of a list", "service_list", "services",
		    jstr(cr, "service-list"), "Its protocols and ports, instead "
		    "of those above.");
		nlist_select(h, "From or to a list", "sdst_list", "prefixes",
		    jstr(cr, "sdst-list"), NULL);
		h_raw(h, "</div><details class=\"sd-more\"");
		if (jget(cr, "sdav4") != NULL || jget(cr, "sdav6") != NULL ||
		    jget(cr, "sdport") != NULL || jget(cr, "ethertype") != NULL)
			h_raw(h, " open");
		h_raw(h, "><summary>Either way, and by EtherType</summary><div "
		    "class=\"two\">");
		text_field(h, "From or to prefixes", "both", crit_text(cr, jget(cr,
		    "sdav6") != NULL ? "sdav6" : "sdav4", buf, sizeof(buf)),
		    "10.9.0.0/16", "Traffic of these, whichever way it goes.");
		text_field(h, "From or to ports", "sdport", crit_text(cr,
		    "sdport", buf, sizeof(buf)), "5060", NULL);
		h_raw(h, "</div>");
		text_field(h, "EtherType", "ethertype", crit_text(cr, "ethertype",
		    buf, sizeof(buf)), "0x88cc", "Frames of another protocol than "
		    "IP, by number.");
		h_raw(h, "</details>");
		return (true);
	}
	if (app.modal == MODAL_SD_POLICY) {
		static const struct {
			const char	*key, *label, *hint;
			const char	*values[5];
			const char	*words[5];
		} picks[] = {
			{ "encryption", "Encryption", "What the tunnels must be.",
			    { "", "required-always", "required-public-only",
			    "optional", NULL }, { "as the underlay is", "always "
			    "encrypted", "encrypted on a public underlay",
			    "optional", NULL } },
			{ "public-private", "Underlays", NULL, { "", "private-only",
			    "either", NULL }, { "any", "private only", "either",
			    NULL } },
			{ "internet-breakout", "Internet breakout", "Enabled: "
			    "Internet traffic leaves by a breakout link.", { "",
			    "enabled", "disabled", NULL }, { "disabled (R57)",
			    "enabled", "disabled", NULL } },
			{ "backup", "Backup links", NULL, { "", "enabled",
			    "disabled", NULL }, { "not used (R65)", "used when "
			    "nothing else is left", "not used", NULL } },
			{ "billing-method", "Billing", NULL, { "", "flat-rate-only",
			    "usage-based-only", "either", NULL }, { "either",
			    "flat rate only", "usage based only", "either", NULL } },
		};
		const char *const	metrics[] = { "", "delay", "ipdv", "loss" };
		const char *const	mwords[] = { "none", "delay", "variation",
		    "loss" };
		const ucl_object_t	*pf, *pr;
		int			 k;

		o = sd.edit[0] != '\0' ? jfind(jget(sw, "policies"), "name",
		    sd.edit) : NULL;
		cr = jget(o, "criteria");
		pf = jget(cr, "performance");
		pr = jget(pf, "primary");
		h_fmt(h, "<form data-form=\"sd-policy\"><h2>%s</h2><p>How a flow "
		    "is carried (a Policy, §9.12): which tunnels may carry it, "
		    "whether it may leave for the Internet, the performance it "
		    "wants, which the console steers it by, and its bandwidth, "
		    "by dummynet. What is left unsaid takes the standard's "
		    "default.</p><input type=\"hidden\" name=\"was\"", o != NULL ?
		    "A policy, changed" : "A policy");
		h_attr(h, "value", sd.edit);
		h_raw(h, "><div class=\"two\">");
		text_field(h, "Name", "name", jstr(o, "name"), "realtime", NULL);
		h_raw(h, "<label>Direction<select name=\"direction\" data-input=\""
		    "sd-policy-dir\">");
		val = sd.edit2[0] != '\0' ? sd.edit2 : jstr(o, "direction") != NULL
		    ? jstr(o, "direction") : "ingress";
		option(h, "ingress", "ingress: as it comes in at a UNI", val);
		option(h, "egress", "egress: as it leaves by a UNI", val);
		h_raw(h, "</select></label></div>");
		if (strcmp(val, "egress") == 0) {
			h_raw(h, "<label>Egress block<select name=\"egress-block\">");
			option(h, "allow", "allow", jstr(cr, "egress-block") != NULL ?
			    jstr(cr, "egress-block") : "allow");
			option(h, "discard", "discard: the flow is dropped leaving "
			    "by the UNI (R85)", jstr(cr, "egress-block"));
			h_raw(h, "</select></label>");
			h_raw(h, "<label>Security policy<select name=\"af-security-egress\">");
			option(h, "", "none", jstr(cr, "af-security-egress"));
			it = NULL;
			while ((m = ucl_object_iterate(jget(sw, "security_policies"), &it,
			    true)) != NULL)
				option(h, jstr(m, "name"), jstr(m, "name"), jstr(cr, "af-security-egress"));
			h_raw(h, "</select><small>What it is let through, under <b>"
			    "Security</b> (MEF 88).</small></label>");
			return (true);
		}
		h_raw(h, "<div class=\"two\">");
		for (k = 0; k < (int)(sizeof(picks) / sizeof(picks[0])); k++) {
			h_raw(h, "<label>");
			h_txt(h, picks[k].label);
			h_fmt(h, "<select name=\"%s\">", picks[k].key);
			for (i = 0; picks[k].values[i] != NULL; i++)
				option(h, picks[k].values[i], picks[k].words[i],
				    jstr(cr, picks[k].key) != NULL ? jstr(cr,
				    picks[k].key) : "");
			h_raw(h, "</select>");
			if (picks[k].hint != NULL) {
				h_raw(h, "<small>");
				h_txt(h, picks[k].hint);
				h_raw(h, "</small>");
			}
			h_raw(h, "</label>");
		}
		/* Destination zones: All, Self, or a list. */
		v = jget(cr, "allowed-destination-zones");
		text_field(h, "Destination zones", "zones", v == NULL ? "" :
		    ucl_object_type(v) == UCL_STRING ? ucl_object_tostring(v) :
		    csv(v, buf, sizeof(buf)), "Self", "All, or zones with commas; "
		    "Self alone if empty (R62).");
		/* The optional parts folded until wanted: performance and
		 * bandwidth, open when the policy has either. */
		h_raw(h, "</div><details class=\"sd-more\"");
		if (pr != NULL || jget(cr, "bandwidth") != NULL || jget(cr,
		    "rate-limiter") != NULL || jget(cr, "business-importance") !=
		    NULL)
			h_raw(h, " open");
		h_raw(h, "><summary>Performance and bandwidth <small class=\"dim\">"
		    "optional</small></summary>");
		h_raw(h, "<fieldset><legend>Performance: the tunnel is "
		    "chosen by it (§9.12.2.9)</legend><div class=\"two\"><label>"
		    "Metric<select name=\"metric\">");
		for (i = 0; i < 4; i++)
			option(h, metrics[i], mwords[i], jstr(pr, "metric") != NULL ?
			    jstr(pr, "metric") : "");
		h_raw(h, "</select><small>Delay and variation in ms, loss as a "
		    "fraction (0.01 is 1%).</small></label>");
		snprintf(buf, sizeof(buf), "%g", jnum(pr, "threshold", 0));
		text_field(h, "Threshold", "threshold", jget(pr, "threshold") != NULL
		    ? buf : "", "30", "Met: the tunnel does; the best of those "
		    "that meet it is taken.");
		h_raw(h, "</div><div class=\"two\">");
		snprintf(buf, sizeof(buf), "%g", jnum(pr, "ceiling", 0));
		text_field(h, "Ceiling", "ceiling", jget(pr, "ceiling") != NULL ?
		    buf : "", "50", "The tunnel in use is left until it passes "
		    "this (R73).");
		snprintf(buf, sizeof(buf), "%g", jnum(pr, "remediation", 0));
		text_field(h, "Remediation", "remediation", jget(pr, "remediation")
		    != NULL ? buf : "", "", "Below this, back to the tunnel "
		    "(R75).");
		h_raw(h, "</div></fieldset><fieldset><legend>Bandwidth, by "
		    "dummynet (§9.12.2.11)</legend><div class=\"two\">");
		v = jget(cr, "bandwidth");
		h_raw(h, "<label>Rate limiter<select name=\"limiter\">");
		option(h, "", "its own, below", v != NULL && ucl_object_type(v) ==
		    UCL_STRING ? ucl_object_tostring(v) : "");
		it = NULL;
		while ((m = ucl_object_iterate(jget(sw, "rate_limiters"), &it,
		    true)) != NULL)
			option(h, jstr(m, "name"), jstr(m, "name"), v != NULL &&
			    ucl_object_type(v) == UCL_STRING ? ucl_object_tostring(v)
			    : "");
		h_raw(h, "</select><small>Shared by every flow that names it."
		    "</small></label>");
		h_raw(h, "<label>Importance<select name=\"importance\">");
		option(h, "", "the service's default", jstr(cr,
		    "business-importance"));
		it = NULL;
		while ((m = ucl_object_iterate(jget(jget(sw, "importance"),
		    "levels"), &it, true)) != NULL)
			option(h, ucl_object_tostring_forced(m),
			    ucl_object_tostring_forced(m), jstr(cr,
			    "business-importance"));
		h_raw(h, "</select></label></div><div class=\"two\">");
		snprintf(buf, sizeof(buf), "%lld", (long long)jint(v, "commit", 0));
		text_field(h, "Commit, bits per second", "commit", v != NULL &&
		    ucl_object_type(v) == UCL_OBJECT ? buf : "", "", "Its share "
		    "under contention.");
		snprintf(buf, sizeof(buf), "%lld", (long long)jint(v, "limit", 0));
		text_field(h, "Limit, bits per second", "limit", v != NULL &&
		    ucl_object_type(v) == UCL_OBJECT && jget(v, "limit") != NULL &&
		    ucl_object_type(jget(v, "limit")) == UCL_INT ? buf : "", "",
		    "At most; empty for none.");
		h_raw(h, "</div></fieldset></details><div class=\"two\">");
		h_raw(h, "<label>Keeps to the topology<select name=\"topology\">");
		option(h, "", "Swvc: every end point", jstr(cr,
		    "virtual-topology"));
		it = NULL;
		while ((m = ucl_object_iterate(jget(sw, "topologies"), &it, true)) !=
		    NULL)
			option(h, jstr(m, "name"), jstr(m, "name"), jstr(cr,
			    "virtual-topology"));
		h_raw(h, "</select><small>The end points its flows may go between "
		    "(§9.6).</small></label>");
		h_raw(h, "<label>Security policy<select name=\"af-security-ingress\">");
		option(h, "", "none", jstr(cr, "af-security-ingress"));
		it = NULL;
		while ((m = ucl_object_iterate(jget(sw, "security_policies"), &it,
		    true)) != NULL)
			option(h, jstr(m, "name"), jstr(m, "name"), jstr(cr, "af-security-ingress"));
		h_raw(h, "</select><small>What it is let through, under <b>"
		    "Security</b> (MEF 88).</small></label>");
		h_raw(h, "</div>");
		{
			const ucl_object_t	*sc;
			char			 sec[300];
			size_t			 so = 0;

			sec[0] = '\0';
			it = NULL;
			while ((sc = ucl_object_iterate(jget(jget(cr, "performance"),
			    "secondary"), &it, true)) != NULL && so < sizeof(sec))
				so += (size_t)snprintf(sec + so, sizeof(sec) - so,
				    "%s%s %g", so > 0 ? ", " : "", jstr(sc, "metric") !=
				    NULL ? jstr(sc, "metric") : "", jnum(sc,
				    "threshold", 0));
			text_field(h, "Also at most", "secondary", sec, "loss 0.01, "
			    "ipdv 10", "Other metrics a tunnel is to meet, each a "
			    "metric and its threshold, by commas (§9.12.2.9).");
			h_raw(h, "<div class=\"two\">");
			nlist_select(h, "Over the UCSs of a list", "ucs_list", "ucs",
			    jstr(cr, "ucs-list"), NULL);
			nlist_select(h, "To the edges of a list", "edge_list",
			    "edges", jstr(cr, "edge-list"), NULL);
			h_raw(h, "</div>");
			nlist_select(h, "From the UCS End Points of a list",
			    "ucs_end_point_list", "ucs-end-points", jstr(cr,
			    "ucs-end-point-list"), "Only tunnels from these, the "
			    "higher preference first while it meets the "
			    "performance.");
		}
		return (true);
	}
	if (app.modal == MODAL_SD_EP) {
		o = sd.edit[0] != '\0' ? jfind(jget(sw, "end_points"), "id",
		    sd.edit) : NULL;
		u = jget(o, "uni");
		h_fmt(h, "<form data-form=\"sd-ep\"><h2>%s</h2><p>Where the "
		    "subscriber's hosts meet the service (an SWVC End Point at "
		    "an SD-WAN UNI, §10, §11): an interface of an edge, put in "
		    "the service's routing table, with the address the edge has "
		    "for them.</p><input type=\"hidden\" name=\"was\"", o != NULL ?
		    "An end point, changed" : "An end point");
		h_attr(h, "value", sd.edit);
		h_raw(h, ">");
		if (ucl_array_size(jget(sd.doc, "edges")) == 0) {
			sd.blocked = true;
			h_raw(h, "<div class=\"notice\">No edge yet: an end point "
			    "is an interface of one. <button class=\"ghost small"
			    "\" data-act=\"sd-go\" data-arg=\"edge\">+ edge"
			    "</button></div>");
			return (true);
		}
		h_raw(h, "<div class=\"two\">");
		text_field(h, "Id", "id", jstr(o, "id"), "hq", NULL);
		h_raw(h, "<label>Edge<select name=\"edge\" data-input=\"sd-ep-edge"
		    "\">");
		it = NULL;
		while ((e = ucl_object_iterate(jget(sd.doc, "edges"), &it, true))
		    != NULL)
			option(h, jstr(e, "server"), host_name(jstr(e, "server")),
			    sd.link_host[0] != '\0' ? sd.link_host : jstr(o, "edge"));
		h_raw(h, "</select></label></div>");
		h_raw(h, "<label>What plugs in here<select name=\"kind\" "
		    "data-input=\"sd-ep-kind\">");
		option(h, "uni", "The subscriber's network: an interface of the "
		    "edge (a UNI)", sd.ep_remote ? "remote" : "uni");
		option(h, "remote", "People from afar: a WireGuard interface (a "
		    "remote end point)", sd.ep_remote ? "remote" : "uni");
		h_raw(h, "</select></label>");
		if (sd.ep_remote) {
			const ucl_object_t	*r = jget(o, "remote");

			h_raw(h, "<div class=\"two\">");
			text_field(h, "WireGuard interface", "rif", jstr(r,
			    "interface"), "wg10", "Made on the edge, in the "
			    "service's routing table (wg(4)).");
			text_field(h, "Their addresses from", "rprefix", jstr(r,
			    "prefix"), "100.65.0.0/24", "One address an identity, "
			    "kept for it; /30 or larger.");
			h_raw(h, "</div><div class=\"two\">");
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(r,
			    "port", 0));
			text_field(h, "UDP port", "rport", jint(r, "port", 0) > 0 ?
			    buf : "", "51820", NULL);
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(r,
			    "reauth", 0) / 3600);
			text_field(h, "Authorised for, hours", "rauth", jint(r,
			    "reauth", 0) > 0 ? buf : "", "720", "After it, an "
			    "identity's peer goes until it is issued again; an "
			    "hour to a year. Empty: it does not lapse.");
			h_raw(h, "</div><p class=\"dim\">Who may come in is issued "
			    "under <b>Identities</b>, each with a zone and a key "
			    "pair of its own.</p>");
			return (true);
		}
		h_raw(h, "<div class=\"two\">");
		ifn = sd.link_if[0] != '\0' ? sd.link_if : jstr(u, "interface");
		h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" name=\""
		    "host_addressed\" value=\"1\"%s> The host has the UNI's "
		    "addresses already (a bridge of its jails, say): none is "
		    "added or taken away</label>", u != NULL && jbool(u,
		    "host_addressed") ? " checked" : "");
		h_raw(h, "<label>Interface");
		if (sd.ifs_loading)
			h_raw(h, "<span class=\"dim\"> · asking the host</span>");
		if (sd.ifs != NULL && jget(sd.ifs, "interfaces") != NULL) {
			h_raw(h, "<select name=\"interface\" data-input=\"sd-link-if"
			    "\">");
			it = NULL;
			while ((a = ucl_object_iterate(jget(sd.ifs, "interfaces"),
			    &it, true)) != NULL) {
				if (jstr(a, "name") == NULL || strncmp(jstr(a,
				    "name"), "pflog", 5) == 0 || strncmp(jstr(a,
				    "name"), "enc", 3) == 0)
					continue;
				option(h, jstr(a, "name"), jstr(a, "name"), ifn);
			}
			h_raw(h, "</select>");
		} else {
			h_raw(h, "<input name=\"interface\" spellcheck=\"false\" "
			    "autocomplete=\"off\" placeholder=\"vtnet2\"");
			h_attr(h, "value", ifn != NULL ? ifn : "");
			h_raw(h, ">");
		}
		h_raw(h, "<small>The LAN side; a VLAN on it if a tag is given."
		    "</small></label>");
		snprintf(buf, sizeof(buf), "%lld", (long long)jint(u, "vlan", 0));
		text_field(h, "VLAN tag", "vlan", jint(u, "vlan", 0) > 0 ? buf : "",
		    "none", NULL);
		h_raw(h, "</div>");
		/* Each address family folded away until it is wanted: one of
		 * the two is enough (R100); the mode's Off keeps it out. */
		v = jget(u, "ipv4");
		h_raw(h, "<details class=\"sd-more\"");
		if (jstr(v, "prefix") != NULL)
			h_raw(h, " open");
		h_raw(h, "><summary>IPv4 at the UNI <small class=\"dim\">empty, or "
		    "Off: none</small></summary><div class=\"two\">");
		text_field(h, "IPv4 subnet", "p4", jstr(v, "prefix"), "10.1.0.0/24",
		    "The hosts' subnet (§11.4).");
		text_field(h, "The edge's IPv4 address", "a4", jget(v, "provider") !=
		    NULL ? ucl_object_tostring_forced(ucl_array_find_index(jget(v,
		    "provider"), 0)) : "", "10.1.0.1", "Their gateway, on the "
		    "interface.");
		h_raw(h, "</div><div class=\"two\"><label>The hosts' IPv4 addresses"
		    "<select name=\"m4\">");
		option(h, "static", "Static: the hosts set their own", jstr(v,
		    "mode"));
		option(h, "dhcp", "DHCP: given by the edge (dnsmasq)", jstr(v,
		    "mode"));
		option(h, "none", "Off: no IPv4 at this UNI", jstr(v, "mode"));
		h_raw(h, "</select><small>With DHCP the edge runs dnsmasq in the "
		    "service's table, giving the subnet less what is reserved."
		    "</small></label>");
		text_field(h, "Reserved, not given out", "r4", csv(jget(v, "reserved"), lb, sizeof(lb)), "10.1.0.0/28, 10.1.0.200/30", "Prefixes inside the "
		    "subnet, by commas (§11.4).");
		h_raw(h, "</div><div class=\"two\">");
		text_field(h, "DNS servers told", "d4", csv(jget(v, "dns"), lb2, sizeof(lb2)),
		    "10.1.0.1", "IPv4 addresses, by commas.");
		text_field(h, "Lease", "l4", jstr(v, "lease"), "12h", "m, h or d.");
		h_raw(h, "</div></details>");
		v = jget(u, "ipv6");
		h_raw(h, "<details class=\"sd-more\"");
		if (jstr(v, "prefix") != NULL || (jstr(v, "mode") != NULL && strcmp(
		    jstr(v, "mode"), "ll-only") == 0))
			h_raw(h, " open");
		h_raw(h, "><summary>IPv6 at the UNI <small class=\"dim\">empty, or "
		    "Off: none</small></summary><div class=\"two\">");
		text_field(h, "IPv6 subnet", "p6", jstr(v, "prefix"), "2001:db8:1::/"
		    "64", NULL);
		text_field(h, "The edge's IPv6 address", "a6", jget(v, "provider") !=
		    NULL ? ucl_object_tostring_forced(ucl_array_find_index(jget(v,
		    "provider"), 0)) : "", "2001:db8:1::1", NULL);
		h_raw(h, "</div><div class=\"two\"><label>The hosts' IPv6 addresses"
		    "<select name=\"m6\">");
		option(h, "static", "Static: the hosts set their own", jstr(v,
		    "mode"));
		option(h, "slaac", "SLAAC: by the edge's advertisements (rtadvd)",
		    jstr(v, "mode"));
		option(h, "dhcp", "DHCPv6: given by the edge (dnsmasq)", jstr(v,
		    "mode"));
		option(h, "ll-only", "Link-local only: no subnet", jstr(v,
		    "mode"));
		option(h, "none", "Off: no IPv6 at this UNI", jstr(v, "mode"));
		h_raw(h, "</select><small>SLAAC by the base system's rtadvd, a "
		    "/64; DHCPv6 by dnsmasq, the hosts told to ask by its "
		    "advertisements.</small></label>");
		text_field(h, "Reserved, not given out", "r6", csv(jget(v, "reserved"), lb, sizeof(lb)), "2001:db8:1::/120", "Prefixes inside the subnet, "
		    "by commas (§11.5).");
		h_raw(h, "</div><div class=\"two\">");
		text_field(h, "DNS servers told", "d6", csv(jget(v, "dns"), lb2, sizeof(lb2)),
		    "2001:db8:1::1", "IPv6 addresses, by commas (RDNSS with SLAAC).");
		text_field(h, "Lease", "l6", jstr(v, "lease"), "12h", "DHCPv6 only.");
		h_raw(h, "</div></details>");
		v = jget(o, "nat");
		text_field(h, "NAT public prefix", "nat", v != NULL && ucl_object_type(
		    v) == UCL_OBJECT ? jstr(v, "public_prefix") : "", "198.51.100.0/"
		    "30", "For breakout: the hosts are translated to its first "
		    "address, by ipfw nat (§10.5). Empty: none.");
		{
			const ucl_object_t	*bgp = jget(u, "bgp"), *ospf = jget(u,
			    "ospf");
			char			*rt;
			char			 nb[400], cm[400];

			h_raw(h, "<details class=\"sd-more\"");
			if (jget(u, "routes") != NULL || bgp != NULL || ospf != NULL ||
			    jget(u, "max_frame") != NULL)
				h_raw(h, " open");
			h_raw(h, "><summary>Routes behind it, BGP, OSPF, and more"
			    "</summary>");
			v = jget(o, "nat");
			text_field(h, "Not translated", "natx", v != NULL &&
			    ucl_object_type(v) == UCL_OBJECT ? csv(jget(v,
			    "exceptions"), nb, sizeof(nb)) : "", "10.0.0.0/8",
			    "Destinations reached without NAT, by commas.");
			rt = routes_text(jget(u, "routes"));
			h_raw(h, "<label>Static routes<textarea name=\"routes\" "
			    "rows=\"3\" class=\"mono\" spellcheck=\"false\" "
			    "placeholder=\"10.2.0.0/16 10.1.0.254\">");
			h_txt(h, rt);
			free(rt);
			h_raw(h, "</textarea><small>The subscriber's networks behind "
			    "a router of theirs at this UNI: a line each, the "
			    "prefix, the next hop, and a distance if it is to be "
			    "(§11.6.1).</small></label>");
			h_raw(h, "<fieldset><legend>BGP with the subscriber <small "
			    "class=\"dim\">§11.6.2, by BIRD; empty: none</small>"
			    "</legend><div class=\"two\">");
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(bgp,
			    "as", 0));
			text_field(h, "Their AS", "bgp_as", bgp != NULL ? buf : "",
			    "65010", NULL);
			text_field(h, "Their addresses", "bgp_nb", csv(jget(bgp,
			    "neighbors"), nb, sizeof(nb)), "10.1.0.2", "At the UNI, "
			    "by commas.");
			h_raw(h, "</div><div class=\"two\"><label>Family<select "
			    "name=\"bgp_fam\">");
			option(h, "both", "IPv4 and IPv6", jstr(bgp, "family"));
			option(h, "ipv4", "IPv4", jstr(bgp, "family"));
			option(h, "ipv6", "IPv6", jstr(bgp, "family"));
			h_raw(h, "</select></label>");
			text_field(h, "Password (TCP MD5)", "bgp_pw", jstr(bgp,
			    "password"), "", NULL);
			h_raw(h, "</div><div class=\"two\">");
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(bgp,
			    "hold_time", 0));
			text_field(h, "Hold time, seconds", "bgp_hold", jint(bgp,
			    "hold_time", 0) > 0 ? buf : "", "90", NULL);
			communities_text(jget(bgp, "communities"), cm, sizeof(cm));
			text_field(h, "Communities", "bgp_comm", cm, "65000:100",
			    "Put on the routes learned, by commas.");
			h_raw(h, "</div></fieldset><fieldset><legend>OSPF with the "
			    "subscriber <small class=\"dim\">§11.6.3, by BIRD; "
			    "empty area: none</small></legend><div class=\"two\">");
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(ospf,
			    "area", 0));
			text_field(h, "Area", "ospf_area", ospf != NULL ? buf : "",
			    "0", "0 the backbone.");
			h_raw(h, "<label>Family<select name=\"ospf_fam\">");
			option(h, "ipv4", "IPv4 (OSPFv2)", jstr(ospf, "family"));
			option(h, "ipv6", "IPv6 (OSPFv3)", jstr(ospf, "family"));
			option(h, "both", "Both", jstr(ospf, "family"));
			h_raw(h, "</select></label></div><div class=\"two\">");
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(ospf,
			    "cost", 0));
			text_field(h, "Cost", "ospf_cost", jint(ospf, "cost", 0) > 0
			    ? buf : "", "10", NULL);
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(ospf,
			    "hello", 0));
			text_field(h, "Hello, seconds", "ospf_hello", jint(ospf,
			    "hello", 0) > 0 ? buf : "", "10", NULL);
			h_raw(h, "</div></fieldset><div class=\"two\">");
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(u,
			    "max_frame", 0));
			text_field(h, "Largest frame, bytes", "mf", jint(u,
			    "max_frame", 0) > 0 ? buf : "", "1522", "1522 or more "
			    "(R126). Empty: the interface's own.");
			text_field(h, "CLAT prefix", "clat", jstr(jget(u, "clat"),
			    "prefix"), "", "An IPv6 /96 of this UNI's own: its IPv4 "
			    "hosts reach the IPv4 Internet through the service's NAT64 "
			    "(RFC 6877). Empty: none.");
			v = jget(o, "availability");
			snprintf(buf, sizeof(buf), "%g", v != NULL ?
			    ucl_object_todouble(v) : 0.0);
			text_field(h, "Availability promised, %", "avail", v != NULL ?
			    buf : "", "99.9", NULL);
			h_raw(h, "</div></details>");
		}
		return (true);
	}
	if (app.modal == MODAL_SD_MAP) {
		bool	zone_wide = sd.edit2[0] == 'z';
		const char	*owner = sd.edit2 + 1;
		int	idx = sd.edit[0] != '\0' ? atoi(sd.edit) : -1;

		if (zone_wide) {
			e = jfind(jget(sw, "zones"), "name", owner);
			m = idx >= 0 ? ucl_array_find_index(jget(e, "policies"),
			    (unsigned int)idx) : NULL;
		} else {
			e = jfind(jget(sw, "end_points"), "id", owner);
			m = idx >= 0 ? ucl_array_find_index(jget(e, "policy_map"),
			    (unsigned int)idx) : NULL;
		}
		h_fmt(h, "<form data-form=\"sd-map\"><h2>A rule %s %s</h2><p>%s"
		    "</p><input type=\"hidden\" name=\"owner\"", zone_wide ? "of "
		    "zone" : "at", owner, zone_wide ? "The flow, or the group, "
		    "and the policy that carries it from this zone, wherever an "
		    "end point's own map says nothing (§9.5)." : "What a flow of "
		    "a zone gets at this end point (the Policy Map, §10.4): it "
		    "comes before the zone's own rule (R109).");
		h_attr(h, "value", sd.edit2);
		h_raw(h, "><input type=\"hidden\" name=\"was\"");
		h_attr(h, "value", sd.edit);
		h_raw(h, ">");
		if ((!zone_wide && ucl_array_size(jget(sw, "zones")) == 0) ||
		    (ucl_array_size(jget(sw, "flows")) == 0 &&
		    ucl_array_size(jget(sw, "groups")) == 0)) {
			sd.blocked = true;
			h_raw(h, "<div class=\"notice\">A rule is of a zone's "
			    "applications: the service has no ");
			h_raw(h, !zone_wide && ucl_array_size(jget(sw, "zones")) ==
			    0 ? "zone" : "application");
			h_raw(h, " yet. <button class=\"ghost small\" data-act=\"");
			h_raw(h, !zone_wide && ucl_array_size(jget(sw, "zones")) ==
			    0 ? "sd-zone-add\">+ zone" : "sd-flow-add\">+ "
			    "application");
			h_raw(h, "</button></div>");
			return (true);
		}
		h_raw(h, "<div class=\"two\">");
		if (!zone_wide) {
			h_raw(h, "<label>Zone<select name=\"zone\">");
			it = NULL;
			while ((v = ucl_object_iterate(jget(sw, "zones"), &it, true))
			    != NULL)
				option(h, jstr(v, "name"), jstr(v, "name"), jstr(m,
				    "zone"));
			option(h, "Internet", "Internet: what comes in from it",
			    jstr(m, "zone"));
			h_raw(h, "</select></label>");
		}
		h_raw(h, "<label>Flow or group<select name=\"app\">");
		it = NULL;
		while ((v = ucl_object_iterate(jget(sw, "flows"), &it, true)) !=
		    NULL)
			option(h, jstr(v, "name"), jstr(v, "name"), jstr(m, "app"));
		it = NULL;
		while ((v = ucl_object_iterate(jget(sw, "groups"), &it, true)) !=
		    NULL) {
			snprintf(b2, sizeof(b2), "%s (a group)",
			    ucl_object_tostring_forced(v));
			option(h, ucl_object_tostring_forced(v), b2, jstr(m, "app"));
		}
		h_raw(h, "</select></label></div><div class=\"two\">");
		h_fmt(h, "<label>%s<select name=\"ingress\">", zone_wide ? "Policy"
		    : "Ingress policy");
		val = zone_wide ? jstr(m, "policy") : jstr(m, "ingress");
		if (!zone_wide)
			option(h, "", "none: the zone's own rule", val);
		option(h, "Block", "Block: dropped", val);
		it = NULL;
		while ((v = ucl_object_iterate(jget(sw, "policies"), &it, true))
		    != NULL)
			if (jstr(v, "direction") != NULL && strcmp(jstr(v,
			    "direction"), "ingress") == 0)
				option(h, jstr(v, "name"), jstr(v, "name"), val);
		h_raw(h, "</select></label>");
		if (!zone_wide) {
			h_raw(h, "<label>Egress policy<select name=\"egress\">");
			option(h, "", "none", jstr(m, "egress"));
			it = NULL;
			while ((v = ucl_object_iterate(jget(sw, "policies"), &it,
			    true)) != NULL)
				if (jstr(v, "direction") != NULL && strcmp(jstr(v,
				    "direction"), "egress") == 0)
					option(h, jstr(v, "name"), jstr(v, "name"), jstr(
					    m, "egress"));
			h_raw(h, "</select></label>");
		}
		h_raw(h, "</div>");
		return (true);
	}
	return (false);
}

/* The forms' answers: the document changed and kept. */
static bool
sd_forms(const char *form, const ucl_object_t *f)
{
	ucl_object_t		*doc, *arr, *o, *t, *links;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*id, *was, *v;
	char			 buf[160];
	unsigned int		 i, n;

	if (strcmp(form, "sd-ucs") != 0 && strcmp(form, "sd-edge") != 0 &&
	    strcmp(form, "sd-link") != 0 && strcmp(form, "sd-nlist") != 0 &&
	    strcmp(form, "sd-group") != 0)
		return (false);
	if (sd.doc == NULL)
		return (true);
	doc = ucl_object_copy(sd.doc);
	if (strcmp(form, "sd-group") == 0) {
		ucl_object_t	*r;
		char		 at[200], *p, *q;

		id = jstr(f, "name") != NULL ? jstr(f, "name") : "";
		was = jstr(f, "was") != NULL ? jstr(f, "was") : "";
		snprintf(at, sizeof(at), "%s", jstr(f, "at") != NULL ? jstr(f,
		    "at") : "");
		p = strchr(at, '|');
		if (id[0] == '\0' || p == NULL || jstr(f, "zone") == NULL || jstr(f,
		    "zone")[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "A group "
			    "has a name, an end point and a zone");
			ucl_object_unref(doc);
			return (true);
		}
		*p++ = '\0';
		r = (ucl_object_t *)(uintptr_t)jget(jfind(jget(jfind(jget(doc,
		    "swvcs"), "id", at), "end_points"), "id", p), "remote");
		if (r == NULL) {
			snprintf(app.modal_error, sizeof(app.modal_error), "No such "
			    "remote end point");
			ucl_object_unref(doc);
			return (true);
		}
		/* was: swvc|end_point|name; the name is what is replaced. */
		q = strrchr(was, '|');
		{
			static const char *const keys[] = { "name", "zone", "pool",
			    "reach", NULL };

			o = merged_from(q != NULL ? jfind(jget(r, "groups"),
			    "name", q + 1) : NULL, keys);
		}
		put_str(o, "name", id);
		put_str(o, "zone", jstr(f, "zone"));
		put_str(o, "pool", jstr(f, "pool"));
		put_list(o, "reach", jstr(f, "reach"));
		list_put(r, "groups", "name", q != NULL ? q + 1 : "", o);
		app.modal = MODAL_NONE;
		doc_send(doc);
		return (true);
	}
	if (strcmp(form, "sd-nlist") == 0) {
		ucl_object_t	*items, *one;
		char		*copy, *it2, *line, idb[80];
		long		 pref;

		id = jstr(f, "name") != NULL ? jstr(f, "name") : "";
		was = jstr(f, "was") != NULL ? jstr(f, "was") : "";
		v = jstr(f, "kind") != NULL ? jstr(f, "kind") : "prefixes";
		if (id[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "A list "
			    "has a name");
			ucl_object_unref(doc);
			return (true);
		}
		{
			static const char *const keys[] = { "name", "kind",
			    "protocols", "ports", "items", NULL };

			o = merged_from(jfind(jget(doc, "lists"), "name", was),
			    keys);
		}
		put_str(o, "name", id);
		put_str(o, "kind", v);
		if (strcmp(v, "services") == 0) {
			put_list(o, "protocols", jstr(f, "protocols"));
			put_list(o, "ports", jstr(f, "ports"));
		} else {
			items = ucl_object_typed_new(UCL_ARRAY);
			{
				char	*more = pfxlist_joined(jstr(f, "pfx_console"),
				    "\n");

				if (asprintf(&copy, "%s\n%s", jstr(f, "items") != NULL ?
				    jstr(f, "items") : "", more != NULL ? more : "") ==
				    -1)
					abort();
				free(more);
			}
			for (it2 = copy; (line = strsep(&it2, "\n")) != NULL; ) {
				line += strspn(line, " \t,");
				line[strcspn(line, "\r")] = '\0';
				if (line[0] == '\0')
					continue;
				if (strcmp(v, "ucs-end-points") == 0 && sscanf(line,
				    "%79s %ld", idb, &pref) == 2) {
					one = ucl_object_typed_new(UCL_OBJECT);
					put_str(one, "id", idb);
					ucl_object_insert_key(one, ucl_object_fromint(
					    pref), "preference", 0, false);
					ucl_array_append(items, one);
				} else {
					line[strcspn(line, " \t,")] = '\0';
					ucl_array_append(items,
					    ucl_object_fromstring(line));
				}
			}
			free(copy);
			ucl_object_insert_key(o, items, "items", 0, false);
		}
		list_put(doc, "lists", "name", was, o);
		app.modal = MODAL_NONE;
		doc_send(doc);
		return (true);
	}
	if (strcmp(form, "sd-ucs") == 0) {
		id = jstr(f, "id") != NULL ? jstr(f, "id") : "";
		was = jstr(f, "was") != NULL ? jstr(f, "was") : "";
		if (id[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "An "
			    "underlay has an id");
			ucl_object_unref(doc);
			return (true);
		}
		if ((arr = (ucl_object_t *)(uintptr_t)jget(doc, "ucs")) == NULL) {
			arr = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(doc, arr, "ucs", 0, false);
		}
		{
			static const char *const keys[] = { "id", "type",
			    "billing", "tunnel", NULL };
			static const char *const tkeys[] = { "kind", "algorithms",
			    "esn", "encap", "lifetime", "ipsec", "mss", "mtu",
			    NULL };
			const ucl_object_t	*old = jfind(arr, "id", was);

			/* What the form does not know of the underlay and its
			 * tunnel stays as it was. */
			o = merged_from(old, keys);
			t = merged_from(old != NULL ? jget(old, "tunnel") : NULL,
			    tkeys);
		}
		ucl_object_insert_key(o, ucl_object_fromstring(id), "id", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(jstr(f, "type") !=
		    NULL ? jstr(f, "type") : "public"), "type", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(jstr(f, "billing")
		    != NULL ? jstr(f, "billing") : "flat-rate"), "billing", 0,
		    false);
		ucl_object_insert_key(t, ucl_object_fromstring(jstr(f, "kind") !=
		    NULL ? jstr(f, "kind") : "gre"), "kind", 0, false);
		if (jstr(f, "kind") != NULL && strcmp(jstr(f, "kind"), "uswe") ==
		    0) {
			ucl_object_insert_key(t, ucl_object_fromstring(jstr(f,
			    "algorithms") != NULL ? jstr(f, "algorithms") :
			    "aes-cbc-hmac-sha2-256"), "algorithms", 0, false);
			ucl_object_insert_key(t, ucl_object_frombool(checked(f,
			    "esn")), "esn", 0, false);
			ucl_object_insert_key(t, ucl_object_frombool(checked(f,
			    "encap")), "encap", 0, false);
			put_int(t, "lifetime", jstr(f, "lifetime"));
		} else if (checked(f, "ipsec") && (jstr(f, "kind") == NULL ||
		    strcmp(jstr(f, "kind"), "wg") != 0))
			ucl_object_insert_key(t, ucl_object_frombool(true), "ipsec",
			    0, false);
		if (jstr(f, "mss") != NULL && strcmp(jstr(f, "mss"), "auto") == 0)
			put_str(t, "mss", "auto");
		else
			put_int(t, "mss", jstr(f, "mss"));
		/* The tunnels' MTU: auto takes the overhead off 1500. */
		if (jstr(f, "mtu") != NULL && strcmp(jstr(f, "mtu"), "auto") == 0)
			put_str(t, "mtu", "auto");
		else
			put_int(t, "mtu", jstr(f, "mtu"));
		ucl_object_insert_key(o, t, "tunnel", 0, false);
		/* In the place of the one changed, else at the end. */
		n = ucl_array_size(arr);
		for (i = 0; was[0] != '\0' && i < n; i++) {
			e = ucl_array_find_index(arr, i);
			if (jstr(e, "id") != NULL && strcmp(jstr(e, "id"), was) ==
			    0) {
				ucl_object_unref(ucl_array_replace_index(arr, o,
				    i));
				break;
			}
		}
		if (was[0] == '\0' || i == n)
			ucl_array_append(arr, o);
		/* The links and services named it: renamed with it. */
		if (was[0] != '\0' && strcmp(was, id) != 0) {
			const ucl_object_t	*ed, *lk, *sw;
			ucl_object_iter_t	 eit, lit, sit;

			eit = NULL;
			while ((ed = ucl_object_iterate(jget(doc, "edges"), &eit,
			    true)) != NULL) {
				lit = NULL;
				while ((lk = ucl_object_iterate(jget(ed,
				    "ucs_end_points"), &lit, true)) != NULL)
					if (jstr(lk, "ucs") != NULL && strcmp(jstr(
					    lk, "ucs"), was) == 0) {
						ucl_object_t *l = (ucl_object_t *)
						    (uintptr_t)lk;

						(void)ucl_object_delete_key(l, "ucs");
						ucl_object_insert_key(l,
						    ucl_object_fromstring(id), "ucs",
						    0, false);
					}
			}
			sit = NULL;
			while ((sw = ucl_object_iterate(jget(doc, "swvcs"), &sit,
			    true)) != NULL) {
				ucl_object_t	*ul = (ucl_object_t *)(uintptr_t)
				    jget(sw, "ucs");

				n = ul != NULL ? ucl_array_size(ul) : 0;
				for (i = 0; i < n; i++)
					if (strcmp(ucl_object_tostring_forced(
					    ucl_array_find_index(ul, i)), was) == 0)
						ucl_object_unref(
						    ucl_array_replace_index(ul,
						    ucl_object_fromstring(id), i));
			}
		}
	} else if (strcmp(form, "sd-edge") == 0) {
		ucl_object_t	*ed;
		char		 eid[160];
		const char	*jl, *q;

		id = jstr(f, "host");
		was = jstr(f, "was") != NULL ? jstr(f, "was") : "";
		if (id == NULL || id[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "Pick a "
			    "host");
			ucl_object_unref(doc);
			return (true);
		}
		/* A jail's edge is server/jail; once made, it stays. */
		jl = jstr(f, "jail") != NULL ? jstr(f, "jail") : "";
		for (q = jl; *q != '\0'; q++)
			if (!isalnum((unsigned char)*q) && strchr("-_.", *q) ==
			    NULL) {
				snprintf(app.modal_error, sizeof(app.modal_error),
				    "A jail's name is letters, digits, - _ and .");
				ucl_object_unref(doc);
				return (true);
			}
		if (was[0] != '\0')
			snprintf(eid, sizeof(eid), "%s", was);
		else if (jl[0] != '\0')
			snprintf(eid, sizeof(eid), "%s/%s", id, jl);
		else
			snprintf(eid, sizeof(eid), "%s", id);
		if (was[0] == '\0' && jfind(jget(doc, "edges"), "server", eid) !=
		    NULL) {
			snprintf(app.modal_error, sizeof(app.modal_error), "%s is "
			    "an edge already", host_name(eid));
			ucl_object_unref(doc);
			return (true);
		}
		id = eid;
		if ((arr = (ucl_object_t *)(uintptr_t)jget(doc, "edges")) ==
		    NULL) {
			arr = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(doc, arr, "edges", 0, false);
		}
		ed = (ucl_object_t *)(uintptr_t)jfind(arr, "server", was);
		if (ed == NULL) {
			ed = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(ed, ucl_object_fromstring(id),
			    "server", 0, false);
			ucl_object_insert_key(ed, ucl_object_typed_new(UCL_ARRAY),
			    "ucs_end_points", 0, false);
			ucl_array_append(arr, ed);
		}
		(void)ucl_object_delete_key(ed, "own_table");
		if (checked(f, "own_table"))
			ucl_object_insert_key(ed, ucl_object_frombool(true),
			    "own_table", 0, false);
		(void)ucl_object_delete_key(ed, "host_bird");
		if (checked(f, "host_bird"))
			ucl_object_insert_key(ed, ucl_object_frombool(true),
			    "host_bird", 0, false);
		(void)ucl_object_delete_key(ed, "transit");
		if (!checked(f, "transit"))
			ucl_object_insert_key(ed, ucl_object_frombool(false),
			    "transit", 0, false);
		(void)ucl_object_delete_key(ed, "bgp_import");
		if (jstr(f, "bgp_import") != NULL && strcmp(jstr(f, "bgp_import"),
		    "sets") == 0)
			put_str(ed, "bgp_import", "sets");
		(void)ucl_object_delete_key(ed, "breakout_sets");
		if ((v = jstr(f, "breakout_sets")) != NULL && v[0] != '\0') {
			ucl_object_t	*bss = ucl_object_typed_new(UCL_ARRAY);
			char		*copy = strdup(v), *it2 = copy, *line;

			while (it2 != NULL && (line = strsep(&it2, "\n")) != NULL) {
				char	sn[80], via[80];

				if (sscanf(line, "%79s %79s", sn, via) == 2) {
					ucl_object_t	*bs = ucl_object_typed_new(UCL_OBJECT);

					put_str(bs, "set", sn);
					put_str(bs, "via", via);
					ucl_array_append(bss, bs);
				}
			}
			free(copy);
			if (ucl_array_size(bss) > 0)
				ucl_object_insert_key(ed, bss, "breakout_sets", 0, false);
			else
				ucl_object_unref(bss);
		}
		(void)ucl_object_delete_key(ed, "ntp");
		if ((v = jstr(f, "ntp")) != NULL && v[0] != '\0')
			ucl_object_insert_key(ed, list_of(v), "ntp", 0, false);
	} else {
		ucl_object_t	*ed;

		id = jstr(f, "host");
		was = jstr(f, "was") != NULL ? jstr(f, "was") : "";
		if ((ed = (ucl_object_t *)(uintptr_t)jfind(jget(doc, "edges"),
		    "server", id)) == NULL) {
			ucl_object_unref(doc);
			return (true);
		}
		/* Not the console's way in, unless agreed to (above). */
		{
			const char	*wi = way_in_if(id);

			if (wi != NULL && jstr(f, "interface") != NULL &&
			    strcmp(wi, jstr(f, "interface")) == 0 &&
			    !checked(f, "wayin_ok") && (((v = jstr(f,
			    "addressing")) != NULL && v[0] != '\0' && strcmp(v,
			    "static") != 0) || ((v = jstr(f, "vrf")) != NULL &&
			    v[0] != '\0' && strtoll(v, NULL, 10) > 0))) {
				snprintf(app.modal_error, sizeof(app.modal_error),
				    "The console reaches this host through %s: "
				    "DHCP, SLAAC or a table of its own there may "
				    "lose it. Tick that you reach it another way "
				    "too, or leave the link static.", wi);
				ucl_object_unref(doc);
				return (true);
			}
		}
		if (jstr(f, "interface") == NULL || jstr(f, "interface")[0] ==
		    '\0' || jstr(f, "ucs") == NULL) {
			snprintf(app.modal_error, sizeof(app.modal_error), "A link "
			    "is on an interface, on an underlay");
			ucl_object_unref(doc);
			return (true);
		}
		if ((links = (ucl_object_t *)(uintptr_t)jget(ed,
		    "ucs_end_points")) == NULL) {
			links = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(ed, links, "ucs_end_points", 0,
			    false);
		}
		{
			static const char *const keys[] = { "id", "ucs", "interface",
			    "address", "gateway", "bandwidth", "breakout", "backup",
			    "addressing", "vrf", "routing", "preference", "nat", "relay",
			    NULL };

			o = merged_from(jfind(links, "id", was), keys);
		}
		if (jstr(f, "id") != NULL && jstr(f, "id")[0] != '\0')
			snprintf(buf, sizeof(buf), "%s", jstr(f, "id"));
		else
			snprintf(buf, sizeof(buf), "%s-%s", host_name(id), jstr(f,
			    "ucs"));
		ucl_object_insert_key(o, ucl_object_fromstring(buf), "id", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(jstr(f, "ucs")),
		    "ucs", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(jstr(f,
		    "interface")), "interface", 0, false);
		if ((v = jstr(f, "address")) != NULL && v[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromstring(v),
			    "address", 0, false);
		if ((v = jstr(f, "gateway")) != NULL && v[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromstring(v),
			    "gateway", 0, false);
		if ((v = jstr(f, "bandwidth")) != NULL && v[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromint(strtoll(v, NULL,
			    10)), "bandwidth", 0, false);
		if (checked(f, "breakout"))
			ucl_object_insert_key(o, ucl_object_frombool(true),
			    "breakout", 0, false);
		if (checked(f, "backup"))
			ucl_object_insert_key(o, ucl_object_frombool(true),
			    "backup", 0, false);
		if (checked(f, "nat"))
			ucl_object_insert_key(o, ucl_object_frombool(true), "nat",
			    0, false);
		if ((v = jstr(f, "relay")) != NULL && v[0] != '\0') {
			ucl_object_t	*rls = ucl_object_typed_new(UCL_ARRAY);
			char		*copy = strdup(v), *it2 = copy, *line;

			while (it2 != NULL && (line = strsep(&it2, "\n")) != NULL) {
				char	to[80], ep[96];
				long	port;

				if (sscanf(line, "%79s %95s %ld", to, ep, &port) == 3) {
					ucl_object_t	*rl = ucl_object_typed_new(
					    UCL_OBJECT);

					put_str(rl, "to", to);
					put_str(rl, "endpoint", ep);
					ucl_object_insert_key(rl, ucl_object_fromint(
					    port), "port", 0, false);
					ucl_array_append(rls, rl);
				}
			}
			free(copy);
			if (ucl_array_size(rls) > 0)
				ucl_object_insert_key(o, rls, "relay", 0, false);
			else
				ucl_object_unref(rls);
		}
		if ((v = jstr(f, "addressing")) != NULL && v[0] != '\0' && strcmp(v,
		    "static") != 0)
			ucl_object_insert_key(o, ucl_object_fromstring(v),
			    "addressing", 0, false);
		if ((v = jstr(f, "vrf")) != NULL && v[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromint(strtoll(v, NULL,
			    10)), "vrf", 0, false);
		if ((v = jstr(f, "preference")) != NULL && v[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromint(strtoll(v, NULL,
			    10)), "preference", 0, false);
		if ((v = jstr(f, "beacon")) != NULL && v[0] != '\0')
			put_str(o, "beacon", v);
		{
			ucl_object_t	*rt = ucl_object_typed_new(UCL_OBJECT), *bg;

			if ((v = jstr(f, "bgp_as")) != NULL && v[0] != '\0') {
				bg = ucl_object_typed_new(UCL_OBJECT);
				put_str(bg, "family", jstr(f, "bgp_fam") != NULL &&
				    jstr(f, "bgp_fam")[0] != '\0' ? jstr(f,
				    "bgp_fam") : "both");
				put_int(bg, "as", v);
				put_int(bg, "hold_time", jstr(f, "bgp_hold"));
				put_int(bg, "distance", jstr(f, "bgp_dist"));
				if (jstr(f, "bgp_comm") != NULL && jstr(f,
				    "bgp_comm")[0] != '\0')
					ucl_object_insert_key(bg, communities_of(
					    jstr(f, "bgp_comm")), "communities", 0,
					    false);
				if ((v = jstr(f, "bgp_neighbors")) != NULL && v[0] !=
				    '\0')
					ucl_object_insert_key(bg, list_of(v), "neighbors",
					    0, false);
				if ((v = jstr(f, "bgp_password")) != NULL && v[0] !=
				    '\0')
					put_str(bg, "password", v);
				ucl_object_insert_key(rt, bg, "bgp", 0, false);
			}
			if ((v = jstr(f, "ospf_area")) != NULL && v[0] != '\0') {
				bg = ucl_object_typed_new(UCL_OBJECT);
				put_str(bg, "family", "both");
				put_int(bg, "area", v);
				put_int(bg, "cost", jstr(f, "ospf_cost"));
				put_int(bg, "hello", jstr(f, "ospf_hello"));
				put_int(bg, "dead", jstr(f, "ospf_dead"));
				ucl_object_insert_key(rt, bg, "ospf", 0, false);
			}
			if (ucl_object_iterate(rt, &(ucl_object_iter_t){ NULL }, true)
			    == NULL)
				ucl_object_unref(rt);
			else
				ucl_object_insert_key(o, rt, "routing", 0, false);
		}
		n = ucl_array_size(links);
		for (i = 0; was[0] != '\0' && i < n; i++) {
			e = ucl_array_find_index(links, i);
			if (jstr(e, "id") != NULL && strcmp(jstr(e, "id"), was) ==
			    0) {
				ucl_object_unref(ucl_array_replace_index(links, o,
				    i));
				break;
			}
		}
		if (was[0] == '\0' || i == n)
			ucl_array_append(links, o);
	}
	(void)it;
	app.modal = MODAL_NONE;
	doc_send(doc);
	return (true);
}

/* The mutable copy of the service shown, in a copy of the document. */
static ucl_object_t *
swvc_mut(ucl_object_t *doc)
{

	return ((ucl_object_t *)(uintptr_t)jfind(jget(doc, "swvcs"), "id",
	    sd.swvc));
}

/*
 * An object a form edits, begun from the one it replaces: a copy of
 * that, less the keys the form sets itself (NULL-ended), so what the
 * form does not know of stays as it was; a new object when there was
 * none.
 */
static ucl_object_t *
merged_from(const ucl_object_t *old, const char *const *keys)
{
	ucl_object_t	*o;
	size_t		 i;

	if (old == NULL || ucl_object_type(old) != UCL_OBJECT)
		return (ucl_object_typed_new(UCL_OBJECT));
	o = ucl_object_copy(old);
	for (i = 0; keys[i] != NULL; i++)
		(void)ucl_object_delete_key(o, keys[i]);
	return (o);
}

/* In a list of objects: the one whose key is was replaced, else o added. */
static void
list_put(ucl_object_t *owner, const char *list, const char *key,
    const char *was, ucl_object_t *o)
{
	ucl_object_t		*arr;
	const ucl_object_t	*e;
	unsigned int		 i, n;

	if ((arr = (ucl_object_t *)(uintptr_t)jget(owner, list)) == NULL) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		ucl_object_insert_key(owner, arr, list, 0, false);
	}
	n = ucl_array_size(arr);
	for (i = 0; was != NULL && was[0] != '\0' && i < n; i++) {
		e = ucl_array_find_index(arr, i);
		if (jstr(e, key) != NULL && strcmp(jstr(e, key), was) == 0) {
			ucl_object_unref(ucl_array_replace_index(arr, o, i));
			return;
		}
	}
	ucl_array_append(arr, o);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL && v[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0, false);
}

static void
put_int(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL && v[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromint(strtoll(v, NULL, 10)),
		    key, 0, false);
}

static void
put_num(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL && v[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromdouble(strtod(v, NULL)),
		    key, 0, false);
}

static void
put_list(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL && v[0] != '\0')
		ucl_object_insert_key(o, list_of(v), key, 0, false);
}


/* A UNI's static routes as lines: "prefix next-hop [distance]". */
static char *
routes_text(const ucl_object_t *routes)
{
	const ucl_object_t	*r;
	ucl_object_iter_t	 it;
	struct html		 b;

	memset(&b, 0, sizeof(b));
	it = NULL;
	while ((r = ucl_object_iterate(routes, &it, true)) != NULL) {
		h_fmt(&b, "%s %s", jstr(r, "prefix") != NULL ? jstr(r,
		    "prefix") : "", jstr(r, "next_hop") != NULL ? jstr(r,
		    "next_hop") : "");
		if (jget(r, "distance") != NULL)
			h_fmt(&b, " %lld", (long long)jint(r, "distance", 0));
		h_raw(&b, "\n");
	}
	return (b.s != NULL ? h_take(&b) : strdup(""));
}

static ucl_object_t *
routes_of(const char *text)
{
	ucl_object_t	*arr, *r;
	char		*copy, *p, *line, *w[3];
	int		 n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (text == NULL)
		return (arr);
	p = copy = strdup(text);
	while ((line = strsep(&p, "\n")) != NULL) {
		for (n = 0; n < 3 && (w[n] = strsep(&line, " \t")) != NULL; )
			if (w[n][0] != '\0')
				n++;
		if (n < 2)
			continue;
		r = ucl_object_typed_new(UCL_OBJECT);
		put_str(r, "prefix", w[0]);
		put_str(r, "next_hop", w[1]);
		if (n == 3)
			put_int(r, "distance", w[2]);
		ucl_array_append(arr, r);
	}
	free(copy);
	return (arr);
}

/* BGP communities as "as:value, ...", and back as [[as, value], ...]. */
static void
communities_text(const ucl_object_t *c, char *buf, size_t len)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	size_t			 o = 0;

	buf[0] = '\0';
	it = NULL;
	while ((e = ucl_object_iterate(c, &it, true)) != NULL && o < len)
		o += (size_t)snprintf(buf + o, len - o, "%s%lld:%lld", o > 0 ?
		    ", " : "", (long long)ucl_object_toint(ucl_array_find_index(
		    e, 0)), (long long)ucl_object_toint(ucl_array_find_index(e,
		    1)));
}

static ucl_object_t *
communities_of(const char *text)
{
	const ucl_object_t	*e;
	ucl_object_t		*words, *arr, *pair;
	ucl_object_iter_t	 it;
	const char		*w, *c;

	arr = ucl_object_typed_new(UCL_ARRAY);
	words = list_of(text);
	it = NULL;
	while ((e = ucl_object_iterate(words, &it, true)) != NULL) {
		w = ucl_object_tostring(e);
		if ((c = strchr(w, ':')) == NULL)
			continue;
		pair = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(pair, ucl_object_fromint(strtoll(w, NULL, 10)));
		ucl_array_append(pair, ucl_object_fromint(strtoll(c + 1, NULL,
		    10)));
		ucl_array_append(arr, pair);
	}
	ucl_object_unref(words);
	return (arr);
}

/* A rate limiter's or a topology's form, into the service. */
static bool
sd_small_forms(const char *form, const ucl_object_t *f)
{
	ucl_object_t	*doc, *sw, *o, *eps, *roots, *leaves;
	const char	*was, *id, *role;
	char		 name[24];
	int		 i;

	if (sd.doc == NULL)
		return (true);
	if (jstr(f, "name") == NULL || jstr(f, "name")[0] == '\0') {
		snprintf(app.modal_error, sizeof(app.modal_error), "It has a "
		    "name");
		return (true);
	}
	was = jstr(f, "was") != NULL ? jstr(f, "was") : "";
	doc = ucl_object_copy(sd.doc);
	if ((sw = swvc_mut(doc)) == NULL) {
		ucl_object_unref(doc);
		return (true);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", jstr(f, "name"));
	if (strcmp(form, "sd-lim") == 0) {
		put_int(o, "commit", jstr(f, "commit") != NULL && jstr(f,
		    "commit")[0] != '\0' ? jstr(f, "commit") : "0");
		if (jstr(f, "limit") != NULL && jstr(f, "limit")[0] != '\0')
			put_int(o, "limit", jstr(f, "limit"));
		else
			ucl_object_insert_key(o, ucl_object_typed_new(UCL_NULL),
			    "limit", 0, false);
		list_put(sw, "rate_limiters", "name", was, o);
	} else {
		eps = ucl_object_typed_new(UCL_ARRAY);
		roots = ucl_object_typed_new(UCL_ARRAY);
		leaves = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < 256; i++) {
			snprintf(name, sizeof(name), "ep_%d", i);
			if ((id = jstr(f, name)) == NULL)
				break;
			snprintf(name, sizeof(name), "role_%d", i);
			role = jstr(f, name) != NULL ? jstr(f, name) : "";
			if (role[0] != '\0')
				ucl_array_append(strcmp(role, "member") == 0 ?
				    eps : strcmp(role, "root") == 0 ? roots :
				    leaves, ucl_object_fromstring(id));
		}
		/* With roots or leaves, rooted; the members are leaves. */
		if (ucl_array_size(roots) > 0 || ucl_array_size(leaves) > 0) {
			ucl_object_t	*e;

			while ((e = ucl_array_pop_first(eps)) != NULL)
				ucl_array_append(leaves, e);
			put_str(o, "type", "rooted-multipoint");
			ucl_object_insert_key(o, roots, "roots", 0, false);
			ucl_object_insert_key(o, leaves, "leaves", 0, false);
			ucl_object_unref(eps);
		} else {
			put_str(o, "type", "multipoint-to-multipoint");
			ucl_object_insert_key(o, eps, "end_points", 0, false);
			ucl_object_unref(roots);
			ucl_object_unref(leaves);
		}
		list_put(sw, "topologies", "name", was, o);
	}
	app.modal = MODAL_NONE;
	doc_send(doc);
	return (true);
}

/* The service's parts: the forms' answers into the document. */
static bool
sd_service_forms(const char *form, const ucl_object_t *f)
{
	ucl_object_t		*doc, *sw, *o, *cr, *t, *u, *arr;
	const ucl_object_t	*old;
	const char		*was, *v;
	char			 name[32], buf[160];
	int			 i;

	if (strcmp(form, "sd-identity") == 0) {
		ucl_object_t	*b;
		unsigned char	*json;
		char		 at[200], *p;

		if (jstr(f, "name") == NULL || jstr(f, "name")[0] == '\0' ||
		    jstr(f, "at") == NULL || ((jstr(f, "zone") == NULL || jstr(f,
		    "zone")[0] == '\0') && (jstr(f, "group") == NULL || jstr(f,
		    "group")[0] == '\0'))) {
			snprintf(app.modal_error, sizeof(app.modal_error), "An "
			    "identity has a name, an end point and a zone or a "
			    "group");
			return (true);
		}
		snprintf(at, sizeof(at), "%s", jstr(f, "at"));
		if ((p = strchr(at, '|')) == NULL)
			return (true);
		*p++ = '\0';
		b = ucl_object_typed_new(UCL_OBJECT);
		put_str(b, "swvc", at);
		put_str(b, "end_point", p);
		put_str(b, "name", jstr(f, "name"));
		if (jstr(f, "group") != NULL && jstr(f, "group")[0] != '\0')
			put_str(b, "group", jstr(f, "group"));
		else
			put_str(b, "zone", jstr(f, "zone"));
		ucl_object_insert_key(b, ucl_object_frombool(checked(f, "user")),
		    "user", 0, false);
		json = ucl_object_emit(b, UCL_EMIT_JSON_COMPACT);
		ucl_object_unref(b);
		app.modal_busy = true;
		api("POST", "/api/sdwan/identities", (const char *)json, issue_cb,
		    NULL);
		free(json);
		return (true);
	}
	if (strcmp(form, "sd-list") == 0) {
		ucl_object_t	*lf;

		if (jstr(f, "name") == NULL || jstr(f, "name")[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "A list "
			    "has a name");
			return (true);
		}
		lf = ucl_object_typed_new(UCL_OBJECT);
		put_str(lf, "name", jstr(f, "name"));
		if (jstr(f, "url") != NULL && jstr(f, "url")[0] != '\0')
			put_str(lf, "url", jstr(f, "url"));
		else
			put_str(lf, "text", jstr(f, "text") != NULL ? jstr(f, "text") :
			    "");
		lists_send(jstr(f, "was"), lf);
		return (true);
	}
	if (strcmp(form, "sd-lim") == 0 || strcmp(form, "sd-topo") == 0)
		return (sd_small_forms(form, f));
	if (strcmp(form, "sd-swvc") != 0 && strcmp(form, "sd-zone") != 0 &&
	    strcmp(form, "sd-flow") != 0 && strcmp(form, "sd-policy") != 0 &&
	    strcmp(form, "sd-ep") != 0 && strcmp(form, "sd-map") != 0 &&
	    strcmp(form, "sd-secpol") != 0)
		return (false);
	if (sd.doc == NULL)
		return (true);
	was = jstr(f, "was") != NULL ? jstr(f, "was") : "";
	doc = ucl_object_copy(sd.doc);
	if (strcmp(form, "sd-swvc") == 0) {
		if (jstr(f, "id") == NULL || jstr(f, "id")[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "A "
			    "service has an id");
			ucl_object_unref(doc);
			return (true);
		}
		old = was[0] != '\0' ? jfind(jget(doc, "swvcs"), "id", was) : NULL;
		o = old != NULL ? ucl_object_copy(old) : ucl_object_typed_new(
		    UCL_OBJECT);
		for (i = 0; i < 12; i++) {
			static const char *const keys[] = { "id", "fib", "as",
			    "md5", "reserved_prefixes", "ucs", "bfd", "intervals",
			    "tca", "domains", "control_plane", NULL };

			if (keys[i] == NULL)
				break;
			(void)ucl_object_delete_key(o, keys[i]);
		}
		put_str(o, "id", jstr(f, "id"));
		put_int(o, "fib", jstr(f, "fib") != NULL && jstr(f, "fib")[0] !=
		    '\0' ? jstr(f, "fib") : "1");
		put_int(o, "as", jstr(f, "as"));
		put_str(o, "md5", jstr(f, "md5"));
		if (jstr(f, "cp_host") != NULL && jstr(f, "cp_host")[0] != '\0') {
			ucl_object_t	*cp;

			cp = ucl_object_typed_new(UCL_OBJECT);
			put_str(cp, "host", jstr(f, "cp_host"));
			if (jstr(f, "cp_cluster") != NULL && jstr(f, "cp_cluster")[0]
			    != '\0')
				put_str(cp, "cluster_id", jstr(f, "cp_cluster"));
			if (jstr(f, "cp_ctvc") != NULL && jstr(f, "cp_ctvc")[0] != '\0')
				put_str(cp, "ctvc", jstr(f, "cp_ctvc"));
			ucl_object_insert_key(o, cp, "control_plane", 0, false);
		}
		put_list(o, "reserved_prefixes", jstr(f, "reserved"));
		(void)ucl_object_delete_key(o, "nat64");
		if ((v = jstr(f, "n64_prefix")) != NULL && v[0] != '\0') {
			ucl_object_t	*n64 = ucl_object_typed_new(UCL_OBJECT);

			put_str(n64, "prefix", v);
			if ((v = jstr(f, "n64_pool")) != NULL && v[0] != '\0')
				put_str(n64, "pool", v);
			if ((v = jstr(f, "n64_edge")) != NULL && v[0] != '\0')
				put_str(n64, "edge", v);
			ucl_object_insert_key(o, n64, "nat64", 0, false);
		}
		(void)ucl_object_delete_key(o, "bgp_sets");
		if ((v = jstr(f, "bgp_sets")) != NULL && v[0] != '\0') {
			ucl_object_t	*sets = ucl_object_typed_new(UCL_ARRAY);
			char		*copy = strdup(v), *it2 = copy, *line, *tok;

			while (it2 != NULL && (line = strsep(&it2, "\n")) != NULL) {
				ucl_object_t	*xs, *ap, *cm, *pair;
				char		*lp = line, *colon;

				while ((tok = strsep(&lp, " \t\r")) != NULL && tok[0] ==
				    '\0')
					;
				if (tok == NULL)
					continue;
				xs = ucl_object_typed_new(UCL_OBJECT);
				put_str(xs, "name", tok);
				ap = ucl_object_typed_new(UCL_ARRAY);
				cm = ucl_object_typed_new(UCL_ARRAY);
				while ((tok = strsep(&lp, " \t\r")) != NULL) {
					if (tok[0] == '\0')
						continue;
					if ((colon = strchr(tok, ':')) != NULL) {
						*colon++ = '\0';
						pair = ucl_object_typed_new(UCL_ARRAY);
						ucl_array_append(pair, ucl_object_fromint(strtoll(
						    tok, NULL, 10)));
						ucl_array_append(pair, ucl_object_fromint(strtoll(
						    colon, NULL, 10)));
						ucl_array_append(cm, pair);
					} else
						ucl_array_append(ap, ucl_object_fromint(strtoll(
						    tok, NULL, 10)));
				}
				ucl_object_insert_key(xs, ap, "as_path", 0, false);
				ucl_object_insert_key(xs, cm, "communities", 0, false);
				ucl_array_append(sets, xs);
			}
			free(copy);
			if (ucl_array_size(sets) > 0)
				ucl_object_insert_key(o, sets, "bgp_sets", 0, false);
			else
				ucl_object_unref(sets);
		}
		/* The routing domains: the three in order where a field has
		 * three values by commas; each only with something in it. */
		{
			static const char *const dn[] = { "service", "breakout",
			    "subscriber" };
			ucl_object_t	*dom, *dd, *rds, *rts, *lbs;
			const char	*fibk[] = { "dom_sfib", "dom_bfib", NULL };
			int		 k;

			rds = list_of(jstr(f, "dom_rd"));
			rts = list_of(jstr(f, "dom_rt"));
			lbs = list_of(jstr(f, "dom_label"));
			dom = ucl_object_typed_new(UCL_OBJECT);
			for (k = 0; k < 3; k++) {
				const ucl_object_t	*x;

				dd = ucl_object_typed_new(UCL_OBJECT);
				if (fibk[k] != NULL && jstr(f, fibk[k]) != NULL &&
				    jstr(f, fibk[k])[0] != '\0')
					put_int(dd, "fib", jstr(f, fibk[k]));
				if (k == 0 && jstr(f, "dom_sprefix") != NULL && jstr(
				    f, "dom_sprefix")[0] != '\0')
					put_str(dd, "prefix", jstr(f, "dom_sprefix"));
				x = ucl_array_find_index(rds, (unsigned int)k);
				if (x != NULL && ucl_object_tostring(x)[0] != '\0')
					put_str(dd, "rd", ucl_object_tostring(x));
				x = ucl_array_find_index(rts, (unsigned int)k);
				if (x != NULL && ucl_object_tostring(x)[0] != '\0')
					ucl_object_insert_key(dd, list_of(
					    ucl_object_tostring(x)), "rt", 0, false);
				x = ucl_array_find_index(lbs, (unsigned int)k);
				if (x != NULL && ucl_object_tostring(x)[0] != '\0')
					put_int(dd, "label", ucl_object_tostring(x));
				if (ucl_object_iterate(dd, &(ucl_object_iter_t){
				    NULL }, true) == NULL)
					ucl_object_unref(dd);
				else
					ucl_object_insert_key(dom, dd, dn[k], 0, false);
			}
			ucl_object_unref(rds);
			ucl_object_unref(rts);
			ucl_object_unref(lbs);
			if (ucl_object_iterate(dom, &(ucl_object_iter_t){ NULL },
			    true) == NULL)
				ucl_object_unref(dom);
			else
				ucl_object_insert_key(o, dom, "domains", 0, false);
		}
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < 64; i++) {
			snprintf(name, sizeof(name), "ucs_%d", i);
			if ((v = jstr(f, name)) != NULL && v[0] != '\0')
				ucl_array_append(arr, ucl_object_fromstring(v));
		}
		ucl_object_insert_key(o, arr, "ucs", 0, false);
		if (checked(f, "bfd")) {
			t = ucl_object_typed_new(UCL_OBJECT);
			put_int(t, "interval", jstr(f, "bfd_interval") != NULL &&
			    jstr(f, "bfd_interval")[0] != '\0' ? jstr(f,
			    "bfd_interval") : "200");
			put_int(t, "multiplier", jstr(f, "bfd_mult") != NULL &&
			    jstr(f, "bfd_mult")[0] != '\0' ? jstr(f, "bfd_mult") :
			    "3");
			ucl_object_insert_key(o, t, "bfd", 0, false);
		}
		(void)ucl_object_delete_key(o, "ibgp");
		if (jstr(f, "ibgp") != NULL && strcmp(jstr(f, "ibgp"), "loopback") ==
		    0)
			put_str(o, "ibgp", "loopback");
		/* What is folded under "more". */
		(void)ucl_object_delete_key(o, "groups");
		(void)ucl_object_delete_key(o, "importance");
		(void)ucl_object_delete_key(o, "probe");
		put_list(o, "groups", jstr(f, "groups"));
		if (jstr(f, "imp_levels") != NULL && jstr(f, "imp_levels")[0] !=
		    '\0') {
			t = ucl_object_typed_new(UCL_OBJECT);
			put_list(t, "levels", jstr(f, "imp_levels"));
			put_str(t, "default", jstr(f, "imp_default"));
			ucl_object_insert_key(o, t, "importance", 0, false);
		}
		{
			static const char *const pk[] = { "interval", "size",
			    "dscp", "timeout", "down", "up", "history", "report" };
			char	 name[24];
			size_t	 k;

			t = ucl_object_typed_new(UCL_OBJECT);
			for (k = 0; k < nitems(pk); k++) {
				snprintf(name, sizeof(name), "pb_%s", pk[k]);
				put_int(t, pk[k], jstr(f, name));
			}
			if (ucl_object_iterate(t, &(ucl_object_iter_t){ NULL },
			    true) != NULL)
				ucl_object_insert_key(o, t, "probe", 0, false);
			else
				ucl_object_unref(t);
		}
		if ((jstr(f, "tca_delay") != NULL && jstr(f, "tca_delay")[0] !=
		    '\0') || (jstr(f, "tca_ipdv") != NULL && jstr(f, "tca_ipdv")[0]
		    != '\0') || (jstr(f, "tca_loss") != NULL && jstr(f,
		    "tca_loss")[0] != '\0')) {
			t = ucl_object_typed_new(UCL_OBJECT);
			put_num(t, "delay", jstr(f, "tca_delay"));
			put_num(t, "ipdv", jstr(f, "tca_ipdv"));
			put_num(t, "loss", jstr(f, "tca_loss"));
			put_int(t, "damping", jstr(f, "tca_damping") != NULL && jstr(
			    f, "tca_damping")[0] != '\0' ? jstr(f, "tca_damping") :
			    "1");
			ucl_object_insert_key(o, t, "tca", 0, false);
		}
		t = old != NULL && jget(old, "intervals") != NULL ?
		    ucl_object_copy(jget(old, "intervals")) :
		    ucl_object_typed_new(UCL_OBJECT);
		(void)ucl_object_delete_key(t, "eval");
		put_int(t, "eval", jstr(f, "eval") != NULL && jstr(f, "eval")[0] !=
		    '\0' ? jstr(f, "eval") : "1000");
		if (jstr(f, "iv_arrival") != NULL && jstr(f, "iv_arrival")[0] !=
		    '\0') {
			(void)ucl_object_delete_key(t, "arrival");
			put_int(t, "arrival", jstr(f, "iv_arrival"));
		}
		if (jstr(f, "iv_ir") != NULL && jstr(f, "iv_ir")[0] != '\0') {
			(void)ucl_object_delete_key(t, "ir");
			put_int(t, "ir", jstr(f, "iv_ir"));
		}
		if (jget(t, "arrival") == NULL)
			ucl_object_insert_key(t, ucl_object_fromint(100), "arrival",
			    0, false);
		if (jget(t, "ir") == NULL)
			ucl_object_insert_key(t, ucl_object_fromint(500), "ir", 0,
			    false);
		ucl_object_insert_key(o, t, "intervals", 0, false);
		if (old == NULL) {
			ucl_object_insert_key(o, ucl_object_typed_new(UCL_ARRAY),
			    "zones", 0, false);
			ucl_object_insert_key(o, ucl_object_typed_new(UCL_ARRAY),
			    "flows", 0, false);
			ucl_object_insert_key(o, ucl_object_typed_new(UCL_ARRAY),
			    "policies", 0, false);
			ucl_object_insert_key(o, ucl_object_typed_new(UCL_ARRAY),
			    "end_points", 0, false);
		}
		list_put(doc, "swvcs", "id", was, o);
		snprintf(sd.swvc, sizeof(sd.swvc), "%s", jstr(f, "id"));
		app.modal = MODAL_NONE;
		doc_send(doc);
		return (true);
	}
	if ((sw = swvc_mut(doc)) == NULL) {
		ucl_object_unref(doc);
		app.modal = MODAL_NONE;
		return (true);
	}
	if (strcmp(form, "sd-zone") == 0) {
		if (jstr(f, "name") == NULL || jstr(f, "name")[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "A zone "
			    "has a name");
			ucl_object_unref(doc);
			return (true);
		}
		old = jfind(jget(sw, "zones"), "name", was);
		o = old != NULL ? ucl_object_copy(old) : ucl_object_typed_new(
		    UCL_OBJECT);
		(void)ucl_object_delete_key(o, "name");
		(void)ucl_object_delete_key(o, "prefixes");
		(void)ucl_object_delete_key(o, "prefix-list");
		put_str(o, "name", jstr(f, "name"));
		put_str(o, "prefix-list", jstr(f, "prefix_list"));
		/* The console's list's prefixes, added to those typed. */
		{
			char	*more = pfxlist_joined(jstr(f, "pfx_console"), ", ");
			char	*both = NULL;

			if (more != NULL && more[0] != '\0' && asprintf(&both,
			    "%s%s%s", jstr(f, "prefixes") != NULL ? jstr(f,
			    "prefixes") : "", jstr(f, "prefixes") != NULL && jstr(f,
			    "prefixes")[0] != '\0' ? ", " : "", more) == -1)
				abort();
			free(more);
			if (both != NULL)
				put_list(o, "prefixes", both);
			else if (jstr(f, "prefixes") != NULL && jstr(f,
			    "prefixes")[0] != '\0')
				put_list(o, "prefixes", jstr(f, "prefixes"));
			else if (jget(o, "prefix-list") == NULL)
				ucl_object_insert_key(o, ucl_object_fromstring(
				    "Default"), "prefixes", 0, false);
			free(both);
		}
		if (jget(o, "policies") == NULL)
			ucl_object_insert_key(o, ucl_object_typed_new(UCL_ARRAY),
			    "policies", 0, false);
		list_put(sw, "zones", "name", was, o);
	} else if (strcmp(form, "sd-secpol") == 0) {
		ucl_object_t	*cr, *b;

		if (jstr(f, "name") == NULL || jstr(f, "name")[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "A "
			    "security policy has a name");
			ucl_object_unref(doc);
			return (true);
		}
		{
			static const char *const keys[] = { "name", "criteria",
			    NULL };

			o = merged_from(jfind(jget(sw, "security_policies"),
			    "name", was), keys);
		}
		put_str(o, "name", jstr(f, "name"));
		cr = ucl_object_typed_new(UCL_OBJECT);
		if ((jstr(f, "allow") != NULL && jstr(f, "allow")[0] != '\0') ||
		    (jstr(f, "deny") != NULL && jstr(f, "deny")[0] != '\0') ||
		    (jstr(f, "iplists") != NULL && jstr(f, "iplists")[0] != '\0')) {
			b = ucl_object_typed_new(UCL_OBJECT);
			if (jstr(f, "allow") != NULL && jstr(f, "allow")[0] != '\0')
				put_list(b, "allow", jstr(f, "allow"));
			if (jstr(f, "deny") != NULL && jstr(f, "deny")[0] != '\0')
				put_list(b, "deny", jstr(f, "deny"));
			if (jstr(f, "iplists") != NULL && jstr(f, "iplists")[0] != '\0')
				put_list(b, "lists", jstr(f, "iplists"));
			ucl_object_insert_key(cr, b, "ip-block", 0, false);
		}
		if ((jstr(f, "domains") != NULL && jstr(f, "domains")[0] != '\0') ||
		    (jstr(f, "dnslists") != NULL && jstr(f, "dnslists")[0] != '\0')) {
			b = ucl_object_typed_new(UCL_OBJECT);
			if (jstr(f, "domains") != NULL && jstr(f, "domains")[0] != '\0')
				put_list(b, "deny", jstr(f, "domains"));
			if (jstr(f, "dnslists") != NULL && jstr(f, "dnslists")[0] !=
			    '\0')
				put_list(b, "lists", jstr(f, "dnslists"));
			ucl_object_insert_key(cr, b, "dns-domain-filter", 0, false);
		}
		if (checked(f, "dnsproto"))
			ucl_object_insert_key(cr, ucl_object_frombool(true),
			    "dns-protocol-filter", 0, false);
		if (jstr(f, "rate") != NULL && jstr(f, "rate")[0] != '\0')
			put_int(cr, "rate-limit", jstr(f, "rate"));
		if (checked(f, "log"))
			ucl_object_insert_key(cr, ucl_object_frombool(true), "log", 0,
			    false);
		if (jstr(f, "urlmode") != NULL && jstr(f, "urlmode")[0] != '\0') {
			b = ucl_object_typed_new(UCL_OBJECT);
			put_str(b, "mode", jstr(f, "urlmode"));
			if (jstr(f, "urldomains") != NULL && jstr(f, "urldomains")[0]
			    != '\0')
				put_list(b, "deny", jstr(f, "urldomains"));
			if (jstr(f, "urllists") != NULL && jstr(f, "urllists")[0] !=
			    '\0')
				put_list(b, "lists", jstr(f, "urllists"));
			if (jstr(f, "urlallow") != NULL && jstr(f, "urlallow")[0] !=
			    '\0')
				put_list(b, "allow", jstr(f, "urlallow"));
			ucl_object_insert_key(cr, b, "url-filter", 0, false);
		}
		if (checked(f, "malware"))
			ucl_object_insert_key(cr, ucl_object_frombool(true),
			    "malware", 0, false);
		if (jstr(f, "idsmode") != NULL && jstr(f, "idsmode")[0] != '\0') {
			ucl_object_t	*rl = ucl_object_typed_new(UCL_ARRAY);
			const char	*t = jstr(f, "idsrules"), *e;

			b = ucl_object_typed_new(UCL_OBJECT);
			put_str(b, "mode", jstr(f, "idsmode"));
			while (t != NULL && *t != '\0') {
				size_t	n;

				e = strchr(t, '\n');
				n = e != NULL ? (size_t)(e - t) : strlen(t);
				while (n > 0 && (t[n - 1] == '\r' || t[n - 1] == ' '))
					n--;
				while (n > 0 && *t == ' ') {
					t++;
					n--;
				}
				if (n > 0 && *t != '#')
					ucl_array_append(rl, ucl_object_fromlstring(t,
					    n));
				t = e != NULL ? e + 1 : NULL;
			}
			if (ucl_array_size(rl) > 0)
				ucl_object_insert_key(b, rl, "rules", 0, false);
			else
				ucl_object_unref(rl);
			if (checked(f, "idsruleset"))
				ucl_object_insert_key(b, ucl_object_frombool(true),
				    "ruleset", 0, false);
			ucl_object_insert_key(cr, b, "ids", 0, false);
		}
		ucl_object_insert_key(o, cr, "criteria", 0, false);
		list_put(sw, "security_policies", "name", was, o);
	} else if (strcmp(form, "sd-flow") == 0) {
		static const char *const apps[] = { "dns", "http", "https", "ssh",
		    "sip", "ntp", "smtp", "imap", "pop3", "ldap", "rdp", "snmp",
		    "syslog", "ike", "bgp", "quic", "dhcp", "icmp" };
		bool	v6;

		if (jstr(f, "name") == NULL || jstr(f, "name")[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "A flow "
			    "has a name");
			ucl_object_unref(doc);
			return (true);
		}
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", jstr(f, "name"));
		put_str(o, "group", jstr(f, "group"));
		cr = ucl_object_typed_new(UCL_OBJECT);
		if (checked(f, "any"))
			ucl_object_insert_key(cr, ucl_object_frombool(true), "any", 0,
			    false);
		else {
			arr = ucl_object_typed_new(UCL_ARRAY);
			for (i = 0; i < (int)(sizeof(apps) / sizeof(apps[0])); i++) {
				snprintf(name, sizeof(name), "app_%s", apps[i]);
				if (checked(f, name))
					ucl_array_append(arr, ucl_object_fromstring(
					    apps[i]));
			}
			if (ucl_array_size(arr) > 0)
				ucl_object_insert_key(cr, arr, "appid", 0, false);
			else
				ucl_object_unref(arr);
			put_list(cr, "dscp", jstr(f, "dscp"));
			v6 = (jstr(f, "src") != NULL && strchr(jstr(f, "src"), ':') !=
			    NULL) || (jstr(f, "dst") != NULL && strchr(jstr(f, "dst"),
			    ':') != NULL);
			put_list(cr, v6 ? "nextheadv6" : "protv4", jstr(f, "proto"));
			put_list(cr, "dport", jstr(f, "dport"));
			put_list(cr, "sport", jstr(f, "sport"));
			put_list(cr, v6 ? "sav6" : "sav4", jstr(f, "src"));
			put_list(cr, v6 ? "dav6" : "dav4", jstr(f, "dst"));
			put_list(cr, jstr(f, "both") != NULL && strchr(jstr(f,
			    "both"), ':') != NULL ? "sdav6" : "sdav4", jstr(f,
			    "both"));
			put_list(cr, "sdport", jstr(f, "sdport"));
			put_list(cr, "ethertype", jstr(f, "ethertype"));
			put_str(cr, "src-list", jstr(f, "src_list"));
			put_str(cr, "dst-list", jstr(f, "dst_list"));
			put_str(cr, "sdst-list", jstr(f, "sdst_list"));
			put_str(cr, "service-list", jstr(f, "service_list"));
			if (ucl_object_lookup(cr, "appid") == NULL && jget(cr, "dscp")
			    == NULL && jget(cr, v6 ? "nextheadv6" : "protv4") == NULL
			    && jget(cr, "dport") == NULL && jget(cr, "sport") == NULL
			    && jget(cr, v6 ? "sav6" : "sav4") == NULL && jget(cr, v6 ?
			    "dav6" : "dav4") == NULL && jget(cr, "sdav4") == NULL &&
			    jget(cr, "sdav6") == NULL && jget(cr, "sdport") ==
			    NULL && jget(cr, "ethertype") == NULL && jget(cr,
			    "src-list") == NULL && jget(cr, "dst-list") == NULL &&
			    jget(cr, "sdst-list") == NULL && jget(cr,
			    "service-list") == NULL) {
				snprintf(app.modal_error, sizeof(app.modal_error),
				    "A flow matches something: an application, a "
				    "DSCP, a protocol, ports or prefixes, or "
				    "everything");
				ucl_object_unref(cr);
				ucl_object_unref(o);
				ucl_object_unref(doc);
				return (true);
			}
		}
		ucl_object_insert_key(o, cr, "criteria", 0, false);
		list_put(sw, "flows", "name", was, o);
	} else if (strcmp(form, "sd-policy") == 0) {
		static const char *const picks[] = { "encryption",
		    "public-private", "internet-breakout", "backup",
		    "billing-method", NULL };

		if (jstr(f, "name") == NULL || jstr(f, "name")[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "A "
			    "policy has a name");
			ucl_object_unref(doc);
			return (true);
		}
		old = jfind(jget(sw, "policies"), "name", was);
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", jstr(f, "name"));
		put_str(o, "direction", jstr(f, "direction") != NULL ? jstr(f,
		    "direction") : "ingress");
		cr = ucl_object_typed_new(UCL_OBJECT);
		if (jstr(f, "direction") != NULL && strcmp(jstr(f, "direction"),
		    "egress") == 0) {
			put_str(cr, "egress-block", jstr(f, "egress-block"));
			put_str(cr, "af-security-egress", jstr(f,
			    "af-security-egress"));
		} else {
			for (i = 0; picks[i] != NULL; i++)
				put_str(cr, picks[i], jstr(f, picks[i]));
			if ((v = jstr(f, "zones")) != NULL && v[0] != '\0') {
				if (strcmp(v, "All") == 0)
					put_str(cr, "allowed-destination-zones", "All");
				else
					put_list(cr, "allowed-destination-zones", v);
			}
			put_str(cr, "business-importance", jstr(f, "importance"));
			if ((v = jstr(f, "limiter")) != NULL && v[0] != '\0')
				put_str(cr, "bandwidth", v);
			else if (jstr(f, "commit") != NULL && jstr(f, "commit")[0] !=
			    '\0') {
				t = ucl_object_typed_new(UCL_OBJECT);
				put_int(t, "commit", jstr(f, "commit"));
				if (jstr(f, "limit") != NULL && jstr(f, "limit")[0] !=
				    '\0')
					put_int(t, "limit", jstr(f, "limit"));
				else
					ucl_object_insert_key(t, ucl_object_typed_new(
					    UCL_NULL), "limit", 0, false);
				ucl_object_insert_key(cr, t, "bandwidth", 0, false);
			}
			if ((v = jstr(f, "metric")) != NULL && v[0] != '\0') {
				ucl_object_t	*pf, *pr;

				pf = ucl_object_typed_new(UCL_OBJECT);
				pr = ucl_object_typed_new(UCL_OBJECT);
				put_str(pr, "metric", v);
				put_num(pr, "threshold", jstr(f, "threshold"));
				put_num(pr, "ceiling", jstr(f, "ceiling"));
				put_num(pr, "remediation", jstr(f, "remediation"));
				ucl_object_insert_key(pf, pr, "primary", 0, false);
				if (jstr(f, "secondary") != NULL && jstr(f,
				    "secondary")[0] != '\0') {
					ucl_object_t		*sa, *words, *one;
					const ucl_object_t	*wv;
					ucl_object_iter_t	 wit;
					char			 met[16];
					double			 th;

					sa = ucl_object_typed_new(UCL_ARRAY);
					words = list_of(jstr(f, "secondary"));
					wit = NULL;
					while ((wv = ucl_object_iterate(words, &wit,
					    true)) != NULL)
						if (sscanf(ucl_object_tostring(wv),
						    "%15s %lf", met, &th) == 2) {
							one = ucl_object_typed_new(
							    UCL_OBJECT);
							put_str(one, "metric", met);
							ucl_object_insert_key(one,
							    ucl_object_fromdouble(th),
							    "threshold", 0, false);
							ucl_array_append(sa, one);
						}
					ucl_object_unref(words);
					ucl_object_insert_key(pf, sa, "secondary", 0,
					    false);
				}
				ucl_object_insert_key(cr, pf, "performance", 0, false);
			}
			put_str(cr, "virtual-topology", jstr(f, "topology"));
			put_str(cr, "af-security-ingress", jstr(f,
			    "af-security-ingress"));
			put_str(cr, "ucs-list", jstr(f, "ucs_list"));
			put_str(cr, "edge-list", jstr(f, "edge_list"));
			put_str(cr, "ucs-end-point-list", jstr(f,
			    "ucs_end_point_list"));
		}
		ucl_object_insert_key(o, cr, "criteria", 0, false);
		list_put(sw, "policies", "name", was, o);
	} else if (strcmp(form, "sd-ep") == 0) {
		bool	rem = jstr(f, "kind") != NULL && strcmp(jstr(f, "kind"),
		    "remote") == 0;

		/* A UNI has an interface; a remote its wg interface and the
		 * prefix (rif, rprefix). */
		if (jstr(f, "id") == NULL || jstr(f, "id")[0] == '\0' || jstr(f,
		    "edge") == NULL || (!rem && (jstr(f, "interface") == NULL ||
		    jstr(f, "interface")[0] == '\0')) || (rem && (jstr(f, "rif")
		    == NULL || jstr(f, "rif")[0] == '\0' || jstr(f, "rprefix") ==
		    NULL || jstr(f, "rprefix")[0] == '\0'))) {
			snprintf(app.modal_error, sizeof(app.modal_error), rem ? "A "
			    "remote end point has an id, an edge, a wg interface "
			    "and the prefix its identities' addresses come from" :
			    "An end point has an id, an edge and an interface");
			ucl_object_unref(doc);
			return (true);
		}
		old = jfind(jget(sw, "end_points"), "id", was);
		o = old != NULL ? ucl_object_copy(old) : ucl_object_typed_new(
		    UCL_OBJECT);
		(void)ucl_object_delete_key(o, "id");
		(void)ucl_object_delete_key(o, "edge");
		(void)ucl_object_delete_key(o, "nat");
		(void)ucl_object_delete_key(o, "availability");
		put_str(o, "id", jstr(f, "id"));
		put_str(o, "edge", jstr(f, "edge"));
		if (jstr(f, "kind") != NULL && strcmp(jstr(f, "kind"), "remote") ==
		    0) {
			/* Its identities stay as they were issued. */
			t = jget(old, "remote") != NULL ? ucl_object_copy(jget(old,
			    "remote")) : ucl_object_typed_new(UCL_OBJECT);
			for (i = 0; i < 4; i++) {
				static const char *const keys[] = { "interface",
				    "prefix", "port", "reauth" };

				(void)ucl_object_delete_key(t, keys[i]);
			}
			put_str(t, "interface", jstr(f, "rif"));
			put_str(t, "prefix", jstr(f, "rprefix"));
			put_int(t, "port", jstr(f, "rport"));
			if (jstr(f, "rauth") != NULL && jstr(f, "rauth")[0] != '\0')
				ucl_object_insert_key(t, ucl_object_fromint(strtoll(
				    jstr(f, "rauth"), NULL, 10) * 3600), "reauth", 0,
				    false);
			(void)ucl_object_delete_key(o, "uni");
			(void)ucl_object_delete_key(o, "remote");
			ucl_object_insert_key(o, t, "remote", 0, false);
			if (jget(o, "policy_map") == NULL)
				ucl_object_insert_key(o, ucl_object_typed_new(
				    UCL_ARRAY), "policy_map", 0, false);
			list_put(sw, "end_points", "id", was, o);
			goto kept;
		}
		(void)ucl_object_delete_key(o, "remote");
		put_num(o, "availability", jstr(f, "avail"));
		u = jget(old, "uni") != NULL ? ucl_object_copy(jget(old, "uni")) :
		    ucl_object_typed_new(UCL_OBJECT);
		(void)ucl_object_delete_key(o, "uni");
		for (i = 0; i < 11; i++) {
			static const char *const keys[] = { "id", "interface",
			    "vlan", "ipv4", "ipv6", "routes", "bgp", "ospf",
			    "max_frame", "host_addressed", "clat" };

			(void)ucl_object_delete_key(u, keys[i]);
		}
		put_int(u, "max_frame", jstr(f, "mf"));
		if (jstr(f, "clat") != NULL && jstr(f, "clat")[0] != '\0') {
			ucl_object_t	*cl = ucl_object_typed_new(UCL_OBJECT);

			put_str(cl, "prefix", jstr(f, "clat"));
			ucl_object_insert_key(u, cl, "clat", 0, false);
		}
		if (checked(f, "host_addressed"))
			ucl_object_insert_key(u, ucl_object_frombool(true),
			    "host_addressed", 0, false);
		if (jstr(f, "routes") != NULL && strspn(jstr(f, "routes"),
		    " \t\n") != strlen(jstr(f, "routes")))
			ucl_object_insert_key(u, routes_of(jstr(f, "routes")),
			    "routes", 0, false);
		if (jstr(f, "bgp_as") != NULL && jstr(f, "bgp_as")[0] != '\0') {
			t = ucl_object_typed_new(UCL_OBJECT);
			put_str(t, "family", jstr(f, "bgp_fam"));
			put_int(t, "as", jstr(f, "bgp_as"));
			put_list(t, "neighbors", jstr(f, "bgp_nb"));
			put_str(t, "password", jstr(f, "bgp_pw"));
			put_int(t, "hold_time", jstr(f, "bgp_hold"));
			if (jstr(f, "bgp_comm") != NULL && jstr(f, "bgp_comm")[0] !=
			    '\0')
				ucl_object_insert_key(t, communities_of(jstr(f,
				    "bgp_comm")), "communities", 0, false);
			ucl_object_insert_key(u, t, "bgp", 0, false);
		}
		if (jstr(f, "ospf_area") != NULL && jstr(f, "ospf_area")[0] !=
		    '\0') {
			t = ucl_object_typed_new(UCL_OBJECT);
			put_str(t, "family", jstr(f, "ospf_fam"));
			put_int(t, "area", jstr(f, "ospf_area"));
			put_int(t, "cost", jstr(f, "ospf_cost"));
			put_int(t, "hello", jstr(f, "ospf_hello"));
			ucl_object_insert_key(u, t, "ospf", 0, false);
		}
		snprintf(buf, sizeof(buf), "uni-%s", jstr(f, "id"));
		put_str(u, "id", jstr(old != NULL ? jget(old, "uni") : NULL, "id")
		    != NULL ? jstr(jget(old, "uni"), "id") : buf);
		put_str(u, "interface", jstr(f, "interface"));
		put_int(u, "vlan", jstr(f, "vlan"));
		for (i = 0; i < 2; i++) {
			const char	*pk = i == 0 ? "p4" : "p6", *ak = i == 0 ? "a4" :
			    "a6", *mk = i == 0 ? "m4" : "m6", *rk = i == 0 ? "r4" :
			    "r6", *dk = i == 0 ? "d4" : "d6", *lk = i == 0 ? "l4" :
			    "l6";

			t = ucl_object_typed_new(UCL_OBJECT);
			if (jstr(f, mk) != NULL && strcmp(jstr(f, mk), "none") == 0)
				put_str(t, "mode", "none");
			else if (i == 1 && jstr(f, mk) != NULL && strcmp(jstr(f, mk),
			    "ll-only") == 0)
				put_str(t, "mode", "ll-only");
			else if (jstr(f, pk) != NULL && jstr(f, pk)[0] != '\0') {
				put_str(t, "mode", jstr(f, mk) != NULL && jstr(f, mk)[0]
				    != '\0' ? jstr(f, mk) : "static");
				put_str(t, "prefix", jstr(f, pk));
				arr = ucl_object_typed_new(UCL_ARRAY);
				if (jstr(f, ak) != NULL && jstr(f, ak)[0] != '\0')
					ucl_array_append(arr, ucl_object_fromstring(
					    jstr(f, ak)));
				ucl_object_insert_key(t, arr, "provider", 0, false);
				/* What the edge's addressing takes. */
				if (jstr(f, rk) != NULL && jstr(f, rk)[0] != '\0')
					ucl_object_insert_key(t, list_of(jstr(f, rk)),
					    "reserved", 0, false);
				if (jstr(f, dk) != NULL && jstr(f, dk)[0] != '\0')
					ucl_object_insert_key(t, list_of(jstr(f, dk)),
					    "dns", 0, false);
				if (jstr(f, lk) != NULL && jstr(f, lk)[0] != '\0')
					put_str(t, "lease", jstr(f, lk));
			} else
				put_str(t, "mode", "none");
			ucl_object_insert_key(u, t, i == 0 ? "ipv4" : "ipv6", 0,
			    false);
		}
		ucl_object_insert_key(o, u, "uni", 0, false);
		if (jstr(f, "nat") != NULL && jstr(f, "nat")[0] != '\0') {
			t = ucl_object_typed_new(UCL_OBJECT);
			put_str(t, "ip_version", "ipv4");
			put_str(t, "public_prefix", jstr(f, "nat"));
			put_list(t, "exceptions", jstr(f, "natx"));
			ucl_object_insert_key(o, t, "nat", 0, false);
		}
		if (jget(o, "policy_map") == NULL)
			ucl_object_insert_key(o, ucl_object_typed_new(UCL_ARRAY),
			    "policy_map", 0, false);
		list_put(sw, "end_points", "id", was, o);
kept:
		;
	} else {
		/* A rule: at an end point ("e<id>") or of a zone ("z<name>"). */
		const char	*owner = jstr(f, "owner");
		ucl_object_t	*ow;
		bool		 zone_wide;

		if (owner == NULL || owner[0] == '\0') {
			ucl_object_unref(doc);
			return (true);
		}
		zone_wide = owner[0] == 'z';
		ow = (ucl_object_t *)(uintptr_t)(zone_wide ? jfind(jget(sw,
		    "zones"), "name", owner + 1) : jfind(jget(sw, "end_points"),
		    "id", owner + 1));
		if (ow == NULL) {
			ucl_object_unref(doc);
			return (true);
		}
		o = ucl_object_typed_new(UCL_OBJECT);
		if (zone_wide) {
			put_str(o, "app", jstr(f, "app"));
			put_str(o, "policy", jstr(f, "ingress"));
			if (jstr(o, "policy") == NULL) {
				snprintf(app.modal_error, sizeof(app.modal_error), "A "
				    "zone's rule names a policy, or Block");
				ucl_object_unref(o);
				ucl_object_unref(doc);
				return (true);
			}
		} else {
			put_str(o, "zone", jstr(f, "zone"));
			put_str(o, "app", jstr(f, "app"));
			put_str(o, "ingress", jstr(f, "ingress"));
			put_str(o, "egress", jstr(f, "egress"));
		}
		if ((arr = (ucl_object_t *)(uintptr_t)jget(ow, zone_wide ?
		    "policies" : "policy_map")) == NULL) {
			arr = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(ow, arr, zone_wide ? "policies" :
			    "policy_map", 0, false);
		}
		if (was[0] != '\0' && (unsigned int)atoi(was) < ucl_array_size(arr))
			ucl_object_unref(ucl_array_replace_index(arr, o,
			    (unsigned int)atoi(was)));
		else
			ucl_array_append(arr, o);
	}
	app.modal = MODAL_NONE;
	doc_send(doc);
	return (true);
}

/* A part of the service taken out: by its name, or a rule by its place. */
static void
sd_service_remove(const char *what, const char *arg, const char *value)
{
	ucl_object_t		*doc, *sw, *arr;
	const ucl_object_t	*e;
	unsigned int		 i, n;
	const char		*list, *key;

	if (sd.doc == NULL)
		return;
	doc = ucl_object_copy(sd.doc);
	if (strcmp(what, "swvc") == 0) {
		arr = (ucl_object_t *)(uintptr_t)jget(doc, "swvcs");
		key = "id";
	} else if ((sw = swvc_mut(doc)) == NULL) {
		ucl_object_unref(doc);
		return;
	} else if (strcmp(what, "map") == 0 || strcmp(what, "zmap") == 0) {
		ucl_object_t	*ow = (ucl_object_t *)(uintptr_t)(strcmp(what,
		    "zmap") == 0 ? jfind(jget(sw, "zones"), "name", arg) : jfind(
		    jget(sw, "end_points"), "id", arg));

		arr = (ucl_object_t *)(uintptr_t)jget(ow, strcmp(what, "zmap") ==
		    0 ? "policies" : "policy_map");
		if (arr != NULL && (unsigned int)atoi(value) < ucl_array_size(arr))
			ucl_object_unref(ucl_array_delete(arr, (ucl_object_t *)
			    (uintptr_t)ucl_array_find_index(arr, (unsigned int)atoi(
			    value))));
		doc_send(doc);
		return;
	} else {
		list = strcmp(what, "zone") == 0 ? "zones" : strcmp(what, "flow")
		    == 0 ? "flows" : strcmp(what, "policy") == 0 ? "policies" :
		    strcmp(what, "secpol") == 0 ? "security_policies" :
		    strcmp(what, "lim") == 0 ? "rate_limiters" : strcmp(what,
		    "topo") == 0 ? "topologies" : "end_points";
		key = strcmp(what, "ep") == 0 ? "id" : "name";
		arr = (ucl_object_t *)(uintptr_t)jget(sw, list);
	}
	n = arr != NULL ? ucl_array_size(arr) : 0;
	for (i = 0; i < n; i++) {
		e = ucl_array_find_index(arr, i);
		if (jstr(e, key) != NULL && strcmp(jstr(e, key), arg) == 0) {
			ucl_object_unref(ucl_array_delete(arr, (ucl_object_t *)
			    (uintptr_t)e));
			break;
		}
	}
	if (strcmp(what, "swvc") == 0)
		sd.swvc[0] = '\0';
	doc_send(doc);
}

/* An underlay, an edge or a link taken out of the document. */
static void
sd_remove(const char *what, const char *arg, const char *value)
{
	ucl_object_t		*doc, *arr;
	const ucl_object_t	*e;
	unsigned int		 i, n;
	const char		*key, *id;

	if (sd.doc == NULL)
		return;
	doc = ucl_object_copy(sd.doc);
	if (strcmp(what, "link") == 0) {
		arr = (ucl_object_t *)(uintptr_t)jget(jfind(jget(doc, "edges"),
		    "server", arg), "ucs_end_points");
		key = "id";
		id = value;
	} else {
		arr = (ucl_object_t *)(uintptr_t)jget(doc, strcmp(what, "ucs") ==
		    0 ? "ucs" : "edges");
		key = strcmp(what, "ucs") == 0 ? "id" : "server";
		id = arg;
	}
	n = arr != NULL ? ucl_array_size(arr) : 0;
	for (i = 0; i < n; i++) {
		e = ucl_array_find_index(arr, i);
		if (jstr(e, key) != NULL && strcmp(jstr(e, key), id) == 0) {
			ucl_object_unref(ucl_array_delete(arr, (ucl_object_t *)
			    (uintptr_t)e));
			break;
		}
	}
	doc_send(doc);
}

/* ---- What is done ---------------------------------------------------- */

static void
sent_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	bool	keep = arg != NULL;

	sd.busy = false;
	if (status != 200) {
		snprintf(sd.error, sizeof(sd.error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
		sd.note[0] = '\0';
		return;
	}
	sd.error[0] = '\0';
	if (!keep) {
		snprintf(sd.note, sizeof(sd.note), "It is one MEF 70.2 allows, "
		    "as far as the console checks.");
		return;
	}
	snprintf(sd.note, sizeof(sd.note), "Kept as version %lld.",
	    (long long)jint(o, "version", 0));
	toast(false, "SD-WAN kept");
	doc_cb(status, o, err, NULL);
	/* The plan was of the document before: made again when wanted. */
	if (sd.plan != NULL)
		ucl_object_unref(sd.plan);
	sd.plan = NULL;
}

/* The box's text sent, with the version it was made from. */
static void
send(const char *text, bool keep)
{
	ucl_object_t	*o;
	unsigned char	*json;

	/* What is in the box: JSON, or YAML pasted in. */
	if ((o = data_parse(text, sd.error, sizeof(sd.error))) == NULL ||
	    ucl_object_type(o) != UCL_OBJECT) {
		if (o != NULL)
			ucl_object_unref(o);
		snprintf(sd.error, sizeof(sd.error), "It is not JSON or YAML, "
		    "or not an object.");
		sd.note[0] = '\0';
		return;
	}
	(void)ucl_object_delete_key(o, "version");
	ucl_object_insert_key(o, ucl_object_fromint(jint(sd.doc, "version",
	    0)), "version", 0, false);
	json = ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	sd.busy = true;
	api(keep ? "PUT" : "POST", keep ? "/api/sdwan" : "/api/sdwan/check",
	    (char *)json, sent_cb, keep ? (void *)1 : NULL);
	free(json);
}

/* An example to start from: two edges, each a host the console has. */
static void
example(void)
{
	struct html	 b;
	const char	*a, *z;

	a = app.nservers > 0 ? app.servers[0].id : "HOST-A";
	z = app.nservers > 1 ? app.servers[1].id : a;
	memset(&b, 0, sizeof(b));
	h_fmt(&b, "{\n"
	    "\t\"ucs\": [\n"
	    "\t\t{\"id\": \"internet\", \"type\": \"public\", \"billing\": "
	    "\"flat-rate\",\n\t\t \"tunnel\": {\"kind\": \"gre\", \"ipsec\": "
	    "true}},\n"
	    "\t\t{\"id\": \"mpls\", \"type\": \"private\", \"billing\": "
	    "\"usage-based\",\n\t\t \"tunnel\": {\"kind\": \"geneve\"}}\n"
	    "\t],\n"
	    "\t\"edges\": [\n"
	    "\t\t{\"server\": \"%s\", \"ucs_end_points\": [\n"
	    "\t\t\t{\"id\": \"hq-inet\", \"ucs\": \"internet\", \"interface\": "
	    "\"vtnet0\", \"address\": \"192.0.2.10\",\n\t\t\t \"gateway\": "
	    "\"192.0.2.1\", \"breakout\": true},\n"
	    "\t\t\t{\"id\": \"hq-mpls\", \"ucs\": \"mpls\", \"interface\": "
	    "\"vtnet1\", \"address\": \"10.99.0.1\"}]},\n"
	    "\t\t{\"server\": \"%s\", \"ucs_end_points\": [\n"
	    "\t\t\t{\"id\": \"br-inet\", \"ucs\": \"internet\", \"interface\": "
	    "\"vtnet0\", \"address\": \"198.51.100.20\"},\n"
	    "\t\t\t{\"id\": \"br-mpls\", \"ucs\": \"mpls\", \"interface\": "
	    "\"vtnet1\", \"address\": \"10.99.0.2\",\n\t\t\t \"backup\": true}]}\n"
	    "\t],\n"
	    "\t\"swvcs\": [{\n"
	    "\t\t\"id\": \"office\", \"fib\": 1, \"ucs\": [\"internet\", "
	    "\"mpls\"],\n"
	    "\t\t\"reserved_prefixes\": [\"100.64.0.0/24\", \"fd00:64::/64\"],\n"
	    "\t\t\"domains\": {\"service\": {\"prefix\": \"100.64.0.0/24\", "
	    "\"rd\": \"64600:1\", \"label\": 1001},\n"
	    "\t\t\t\"breakout\": {\"fib\": 2, \"rd\": \"64600:2\", \"label\": "
	    "1002},\n\t\t\t\"subscriber\": {\"rd\": \"64600:3\", \"label\": "
	    "1003}},\n"
	    "\t\t\"intervals\": {\"eval\": 1000, \"arrival\": 100, \"ir\": 500},\n"
	    "\t\t\"zones\": [{\"name\": \"staff\", \"prefixes\": \"Default\",\n"
	    "\t\t\t\"policies\": [{\"app\": \"voice\", \"policy\": \"realtime\"},"
	    "\n\t\t\t\t{\"app\": \"rest\", \"policy\": \"standard\"}]}],\n"
	    "\t\t\"flows\": [\n"
	    "\t\t\t{\"name\": \"voice\", \"criteria\": {\"dscp\": [46]}},\n"
	    "\t\t\t{\"name\": \"rest\", \"criteria\": {\"any\": true}}\n"
	    "\t\t],\n"
	    "\t\t\"policies\": [\n"
	    "\t\t\t{\"name\": \"realtime\", \"direction\": \"ingress\", "
	    "\"criteria\": {\n"
	    "\t\t\t\t\"encryption\": \"required-public-only\",\n"
	    "\t\t\t\t\"allowed-destination-zones\": \"All\",\n"
	    "\t\t\t\t\"performance\": {\"primary\": {\"metric\": \"delay\", "
	    "\"threshold\": 30, \"ceiling\": 50},\n"
	    "\t\t\t\t\t\"secondary\": [{\"metric\": \"loss\", \"threshold\": "
	    "0.01}]}}},\n"
	    "\t\t\t{\"name\": \"standard\", \"direction\": \"ingress\", "
	    "\"criteria\": {\n"
	    "\t\t\t\t\"encryption\": \"required-public-only\",\n"
	    "\t\t\t\t\"allowed-destination-zones\": \"All\",\n"
	    "\t\t\t\t\"internet-breakout\": \"enabled\",\n"
	    "\t\t\t\t\"af-security-ingress\": \"guard\"}}\n"
	    "\t\t],\n"
	    "\t\t\"security_policies\": [\n"
	    "\t\t\t{\"name\": \"guard\", \"criteria\": {\n"
	    "\t\t\t\t\"ip-block\": {\"deny\": [\"192.0.2.0/24\"]},\n"
	    "\t\t\t\t\"dns-domain-filter\": {\"deny\": [\"ads.example\"]},\n"
	    "\t\t\t\t\"dns-protocol-filter\": true,\n"
	    "\t\t\t\t\"log\": true}}\n"
	    "\t\t],\n"
	    "\t\t\"end_points\": [\n"
	    "\t\t\t{\"id\": \"hq\", \"edge\": \"%s\", \"uni\": {\"id\": "
	    "\"hq-lan\", \"interface\": \"vtnet2\",\n"
	    "\t\t\t\t\"ipv4\": {\"mode\": \"static\", \"prefix\": "
	    "\"10.10.0.0/24\", \"provider\": [\"10.10.0.1\"]}},\n"
	    "\t\t\t \"nat\": {\"ip_version\": \"ipv4\", \"public_prefix\": "
	    "\"192.0.2.8/30\"}},\n"
	    "\t\t\t{\"id\": \"branch\", \"edge\": \"%s\", \"uni\": {\"id\": "
	    "\"br-lan\", \"interface\": \"vtnet2\",\n"
	    "\t\t\t\t\"ipv4\": {\"mode\": \"static\", \"prefix\": "
	    "\"10.20.0.0/24\", \"provider\": [\"10.20.0.1\"]}}},\n"
	    "\t\t\t{\"id\": \"road\", \"edge\": \"%s\", \"remote\": {"
	    "\"interface\": \"wg5\", \"prefix\": \"10.30.0.0/24\",\n"
	    "\t\t\t\t\"port\": 51820,\n"
	    "\t\t\t\t\"groups\": [{\"name\": \"staff\", \"zone\": \"staff\", "
	    "\"pool\": \"10.30.0.64/26\"},\n"
	    "\t\t\t\t\t{\"name\": \"guests\", \"zone\": \"staff\"}],\n"
	    "\t\t\t\t\"identities\": [{\"name\": \"alice\", "
	    "\"zone\": \"staff\",\n\t\t\t\t\t\"public_key\": "
	    "\"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\"},\n"
	    "\t\t\t\t\t{\"name\": \"carol\", \"group\": \"staff\", "
	    "\"public_key\": \"HIgo9xNzJMWLKASShiTqIYNW7HVnKq0pjaZxmvZ6rKA=\"}]}}\n"
	    "\t\t]\n"
	    "\t}]\n"
	    "}\n", a, z, a, z, a);
	free(sd.text);
	sd.text = b.s;
	sd.error[0] = '\0';
	snprintf(sd.note, sizeof(sd.note), "An example, not kept: interfaces "
	    "and addresses are to be made your own.");
}

static void
apply_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200) {
		sd.applying = false;
		toast(true, "Not applied: %s", jstr(o, "error.message") != NULL ?
		    jstr(o, "error.message") : err != NULL ? err : "no answer");
		return;
	}
	api("GET", "/api/sdwan/apply", NULL, applied_cb, NULL);
}

bool
sdwan_form(const char *form, const ucl_object_t *f)
{
	const char	*text;

	if (sd_forms(form, f) || sd_service_forms(form, f))
		return (true);
	if (strcmp(form, "sd-doc") != 0)
		return (false);
	text = jstr(f, "text") != NULL ? jstr(f, "text") : "";
	/* What was typed stays in the box while it is asked. */
	free(sd.text);
	sd.text = strdup(text);
	send(text, jstr(f, "how") != NULL && strcmp(jstr(f, "how"), "keep") ==
	    0);
	return (true);
}

bool
sdwan_action(const char *act, const char *arg, const char *value)
{

	if (strcmp(act, "select-sdwan") == 0) {
		sdwan_open();
		return (true);
	}
	if (strcmp(act, "sd-go") == 0) {
		/* A step of the way through: its tab, and its form. */
		const ucl_object_t	*e;

		if (strcmp(arg, "ucs") == 0 || strcmp(arg, "edge") == 0) {
			sd.tab = SD_OVERVIEW;
			return (sdwan_action(strcmp(arg, "ucs") == 0 ?
			    "sd-ucs-add" : "sd-edge-add", "", ""));
		}
		if (strcmp(arg, "link") == 0 && (e = edge_unlinked()) != NULL) {
			sd.tab = SD_OVERVIEW;
			return (sdwan_action("sd-link-add", jstr(e, "server"),
			    ""));
		}
		if (strcmp(arg, "deploy") == 0) {
			sd.tab = SD_EDGES;
			plan_load();
			return (true);
		}
		sd.tab = SD_SERVICES;
		if (strcmp(arg, "service") == 0)
			return (sdwan_action("sd-swvc-add", "", ""));
		/* The end point's own form, always: a service without
		 * underlays yet is the check's to say, not a detour into
		 * the service form that leaves no end point behind. */
		if (strcmp(arg, "ep") == 0)
			return (sdwan_action("sd-ep-add", "", ""));
		if (strcmp(arg, "zone") == 0)
			return (sdwan_action("sd-zone-add", "", ""));
		if (strcmp(arg, "flow") == 0)
			return (sdwan_action("sd-flow-add", "", ""));
		if (strcmp(arg, "policy") == 0)
			return (sdwan_action("sd-policy-add", "", ""));
		return (true);
	}
	if (strcmp(act, "input:sd-ucs-kind") == 0) {
		snprintf(sd.ucs_kind, sizeof(sd.ucs_kind), "%s", value);
		return (true);
	}
	if (strcmp(act, "sd-ucs-add") == 0 || strcmp(act, "sd-ucs-edit") == 0) {
		snprintf(sd.edit, sizeof(sd.edit), "%s", strcmp(act,
		    "sd-ucs-edit") == 0 ? arg : "");
		/* What the form shows besides follows the tunnel's kind. */
		snprintf(sd.ucs_kind, sizeof(sd.ucs_kind), "%s", jstr(jget(
		    ucs_by(sd.edit), "tunnel"), "kind") != NULL ? jstr(jget(
		    ucs_by(sd.edit), "tunnel"), "kind") : "gre");
		app.modal = MODAL_SD_UCS;
		app.modal_error[0] = '\0';
		return (true);
	}
	if (strcmp(act, "sd-edge-add") == 0 || strcmp(act, "sd-edge-edit") ==
	    0) {
		snprintf(sd.edit, sizeof(sd.edit), "%s", strcmp(act,
		    "sd-edge-edit") == 0 ? arg : "");
		app.modal = MODAL_SD_EDGE;
		app.modal_error[0] = '\0';
		return (true);
	}
	if (strcmp(act, "sd-link-add") == 0 || strcmp(act, "sd-link-edit") ==
	    0) {
		char	url[96];

		snprintf(sd.link_host, sizeof(sd.link_host), "%s", arg);
		snprintf(sd.edit, sizeof(sd.edit), "%s", strcmp(act,
		    "sd-link-edit") == 0 ? value : "");
		sd.link_if[0] = '\0';
		if (sd.ifs != NULL)
			ucl_object_unref(sd.ifs);
		sd.ifs = NULL;
		sd.ifs_loading = true;
		snprintf(url, sizeof(url), "/api/servers/%s/net/interfaces", arg);
		api("GET", url, NULL, ifs_cb, NULL);
		app.modal = MODAL_SD_LINK;
		app.modal_error[0] = '\0';
		return (true);
	}
	if (strcmp(act, "input:sd-link-if") == 0) {
		snprintf(sd.link_if, sizeof(sd.link_if), "%s", value);
		return (true);
	}
	if (strcmp(act, "input:sd-policy-dir") == 0) {
		snprintf(sd.edit2, sizeof(sd.edit2), "%s", value);
		return (true);
	}
	if (strcmp(act, "input:sd-ep-kind") == 0) {
		sd.ep_remote = strcmp(value, "remote") == 0;
		return (true);
	}
	if (strcmp(act, "input:sd-ep-edge") == 0) {
		char	url[96];

		snprintf(sd.link_host, sizeof(sd.link_host), "%s", value);
		sd.link_if[0] = '\0';
		if (sd.ifs != NULL)
			ucl_object_unref(sd.ifs);
		sd.ifs = NULL;
		sd.ifs_loading = true;
		snprintf(url, sizeof(url), "/api/servers/%s/net/interfaces", value);
		api("GET", url, NULL, ifs_cb, NULL);
		return (true);
	}
	/* A rate limiter or a virtual topology of the service. */
	if (strcmp(act, "sd-lim-add") == 0 || strcmp(act, "sd-lim-edit") == 0 ||
	    strcmp(act, "sd-topo-add") == 0 || strcmp(act, "sd-topo-edit") ==
	    0) {
		snprintf(sd.edit, sizeof(sd.edit), "%s", strstr(act, "-edit") !=
		    NULL ? arg : "");
		app.modal = strncmp(act, "sd-lim", 6) == 0 ? MODAL_SD_LIMITER :
		    MODAL_SD_TOPO;
		app.modal_error[0] = '\0';
		return (true);
	}
	if (strcmp(act, "sd-nlist-add") == 0 || strcmp(act, "sd-nlist-edit") ==
	    0) {
		snprintf(sd.edit, sizeof(sd.edit), "%s", strstr(act, "-edit") !=
		    NULL ? arg : "");
		app.modal = MODAL_SD_NLIST;
		app.modal_error[0] = '\0';
		return (true);
	}
	if (strcmp(act, "sd-group-add") == 0 || strcmp(act, "sd-group-edit") ==
	    0) {
		snprintf(sd.edit, sizeof(sd.edit), "%s", strstr(act, "-edit") !=
		    NULL ? arg : "");
		app.modal = MODAL_SD_GROUP;
		app.modal_error[0] = '\0';
		return (true);
	}
	if (strcmp(act, "sd-group-del") == 0) {
		confirm("Take the group away", "Its members keep their addresses "
		    "but have no zone until they are issued again into a group "
		    "or with a zone; the document will not pass the check "
		    "until then.", "Take away", true, "", "do-sd-group-del", arg,
		    "");
		return (true);
	}
	if (strcmp(act, "do-sd-group-del") == 0) {
		ucl_object_t	*doc, *arr;
		char		 a[300], *p, *q;
		unsigned int	 i;

		if (sd.doc == NULL)
			return (true);
		snprintf(a, sizeof(a), "%s", arg);
		p = strchr(a, '|');
		q = p != NULL ? strchr(p + 1, '|') : NULL;
		if (p == NULL || q == NULL)
			return (true);
		*p++ = '\0';
		*q++ = '\0';
		doc = ucl_object_copy(sd.doc);
		arr = (ucl_object_t *)(uintptr_t)jget(jget(jfind(jget(jfind(jget(
		    doc, "swvcs"), "id", a), "end_points"), "id", p), "remote"),
		    "groups");
		for (i = 0; arr != NULL && i < ucl_array_size(arr); i++)
			if (jstr(ucl_array_find_index(arr, i), "name") != NULL &&
			    strcmp(jstr(ucl_array_find_index(arr, i), "name"), q) ==
			    0) {
				ucl_object_unref(ucl_array_delete(arr, (ucl_object_t *)
				    (uintptr_t)ucl_array_find_index(arr, i)));
				break;
			}
		doc_send(doc);
		return (true);
	}
	if (strcmp(act, "sd-nlist-del") == 0) {
		char	body[300];

		snprintf(body, sizeof(body), "The list %s goes out of the "
		    "document; a flow, zone or policy that names it will not pass "
		    "the check until it is changed.", arg);
		confirm("Take the list away", body, "Take away", true, "",
		    "do-sd-nlist-del", arg, "");
		return (true);
	}
	if (strcmp(act, "do-sd-nlist-del") == 0) {
		ucl_object_t	*doc;

		if (sd.doc == NULL)
			return (true);
		doc = ucl_object_copy(sd.doc);
		{
			ucl_object_t		*arr = (ucl_object_t *)(uintptr_t)
			    jget(doc, "lists");
			const ucl_object_t	*e;
			unsigned int		 i;

			for (i = 0; i < ucl_array_size(arr); i++) {
				e = ucl_array_find_index(arr, i);
				if (jstr(e, "name") != NULL && strcmp(jstr(e,
				    "name"), arg) == 0) {
					ucl_object_unref(ucl_array_delete(arr,
					    (ucl_object_t *)(uintptr_t)e));
					break;
				}
			}
		}
		doc_send(doc);
		return (true);
	}
	if (strcmp(act, "sd-lim-del") == 0 || strcmp(act, "sd-topo-del") == 0) {
		char	body[300], daction[40];

		snprintf(daction, sizeof(daction), "do-%s", act);
		snprintf(body, sizeof(body), "%s goes out of the document; a "
		    "policy that names it will not pass the check until it is "
		    "changed. Nothing is made or unmade until Deploy.", arg);
		confirm("Take it away", body, "Take away", true, "", daction,
		    arg, "");
		return (true);
	}
	if (strcmp(act, "do-sd-lim-del") == 0 || strcmp(act, "do-sd-topo-del") ==
	    0) {
		sd_service_remove(strstr(act, "lim") != NULL ? "lim" : "topo",
		    arg, value);
		return (true);
	}
	/* The service's parts: a form each, a word before taking one away. */
	if (strncmp(act, "sd-swvc-", 8) == 0 || strncmp(act, "sd-zone-", 8) ==
	    0 || strncmp(act, "sd-flow-", 8) == 0 || strncmp(act, "sd-policy-",
	    10) == 0 || strncmp(act, "sd-ep-", 6) == 0 || strncmp(act,
	    "sd-map-", 7) == 0 || strncmp(act, "sd-zmap-", 8) == 0 || strncmp(
	    act, "sd-secpol-", 10) == 0) {
		const char	*what, *verb;
		char		 kind[12], body[300];

		what = act + 3;
		verb = strrchr(act, '-') + 1;
		snprintf(kind, sizeof(kind), "%.*s", (int)(verb - what - 1), what);
		if (strcmp(verb, "add") == 0 || strcmp(verb, "edit") == 0) {
			snprintf(sd.edit, sizeof(sd.edit), "%s", strcmp(verb, "edit")
			    == 0 ? (strcmp(kind, "map") == 0 || strcmp(kind, "zmap")
			    == 0 ? value : arg) : "");
			sd.edit2[0] = '\0';
			if (strcmp(kind, "map") == 0 || strcmp(kind, "zmap") == 0)
				snprintf(sd.edit2, sizeof(sd.edit2), "%c%s",
				    strcmp(kind, "zmap") == 0 ? 'z' : 'e', arg);
			app.modal = strcmp(kind, "swvc") == 0 ? MODAL_SD_SWVC :
			    strcmp(kind, "zone") == 0 ? MODAL_SD_ZONE : strcmp(kind,
			    "flow") == 0 ? MODAL_SD_FLOW : strcmp(kind, "policy") ==
			    0 ? MODAL_SD_POLICY : strcmp(kind, "ep") == 0 ?
			    MODAL_SD_EP : strcmp(kind, "secpol") == 0 ?
			    MODAL_SD_SECPOL : MODAL_SD_MAP;
			app.modal_error[0] = '\0';
			if (app.modal == MODAL_SD_EP) {
				const ucl_object_t	*ep = jfind(jget(swvc_shown(),
				    "end_points"), "id", sd.edit);
				const ucl_object_t	*ed = jget(sd.doc, "edges");
				const char		*host = ep != NULL ? jstr(ep,
				    "edge") : ed != NULL && ucl_array_size(ed) > 0 ?
				    jstr(ucl_array_find_index(ed, 0), "server") :
				    NULL;

				if (host != NULL)
					sdwan_action("input:sd-ep-edge", "", host);
				sd.ep_remote = ep != NULL && jget(ep, "remote") !=
				    NULL;
			}
			return (true);
		}
		if (strcmp(verb, "del") == 0) {
			char	daction[40];

			snprintf(daction, sizeof(daction), "do-%s", act);
			snprintf(body, sizeof(body), strcmp(kind, "swvc") == 0 ?
			    "The service %s goes out of the document with all "
			    "its parts; its tunnels, rules and tables are taken "
			    "off the edges at the next Apply." : strcmp(kind,
			    "map") == 0 || strcmp(kind, "zmap") == 0 ? "The rule "
			    "goes out of the document (%s). Nothing is made or "
			    "unmade until Apply." : "The %s goes out of the "
			    "document; what names it will not pass the check "
			    "until changed. Nothing is made or unmade until "
			    "Apply.", strcmp(kind, "map") == 0 || strcmp(kind,
			    "zmap") == 0 || strcmp(kind, "swvc") == 0 ? arg : kind);
			confirm("Take it away", body, "Take away", true, "", daction,
			    arg, value);
			return (true);
		}
	}
	if (strncmp(act, "do-sd-", 6) == 0 && strrchr(act, '-') != NULL &&
	    strcmp(strrchr(act, '-'), "-del") == 0 && (strncmp(act + 6, "swvc",
	    4) == 0 || strncmp(act + 6, "zone", 4) == 0 || strncmp(act + 6,
	    "flow", 4) == 0 || strncmp(act + 6, "policy", 6) == 0 || strncmp(
	    act + 6, "ep-", 3) == 0 || strncmp(act + 6, "map", 3) == 0 ||
	    strncmp(act + 6, "zmap", 4) == 0 || strncmp(act + 6, "secpol", 6)
	    == 0)) {
		char	kind[12];

		snprintf(kind, sizeof(kind), "%.*s", (int)(strrchr(act, '-') -
		    (act + 6)), act + 6);
		sd_service_remove(kind, arg, value);
		return (true);
	}
	if (strcmp(act, "sd-ucs-del") == 0) {
		char	body[300];

		snprintf(body, sizeof(body), "The underlay %s goes out of the "
		    "document, with nothing else changed: links and services "
		    "that name it will not pass the check until they are "
		    "changed too. Nothing is made or unmade until Apply.", arg);
		confirm("Take the underlay away", body, "Take away", true, "",
		    "do-sd-ucs-del", arg, "");
		return (true);
	}
	if (strcmp(act, "sd-edge-del") == 0) {
		char	body[300];

		snprintf(body, sizeof(body), "The edge %s goes out of the "
		    "document with its WAN links; services with an end point "
		    "on it will not pass the check until changed. Nothing is "
		    "made or unmade until Apply.", host_name(arg));
		confirm("Take the edge away", body, "Take away", true, "",
		    "do-sd-edge-del", arg, "");
		return (true);
	}
	if (strcmp(act, "sd-link-del") == 0) {
		char	body[300];

		snprintf(body, sizeof(body), "The WAN link %s of %s goes out of "
		    "the document. Nothing is made or unmade until Apply.",
		    value, host_name(arg));
		confirm("Take the link away", body, "Take away", true, "",
		    "do-sd-link-del", arg, value);
		return (true);
	}
	if (strcmp(act, "do-sd-ucs-del") == 0) {
		sd_remove("ucs", arg, value);
		return (true);
	}
	if (strcmp(act, "do-sd-edge-del") == 0) {
		sd_remove("edge", arg, value);
		return (true);
	}
	if (strcmp(act, "do-sd-link-del") == 0) {
		sd_remove("link", arg, value);
		return (true);
	}
	if (strncmp(act, "sd-", 3) != 0 && strcmp(act, "input:sd-swvc") != 0 &&
	    strcmp(act, "do-sd-apply-fresh") != 0 && strcmp(act,
	    "file:sd-import") != 0)
		return (false);
	if (strcmp(act, "sd-tab") == 0) {
		sd.tab = strcmp(arg, "services") == 0 ? SD_SERVICES :
		    strcmp(arg, "edges") == 0 ? SD_EDGES : strcmp(arg,
		    "paths") == 0 ? SD_PATHS : strcmp(arg, "security") == 0 ?
		    SD_SECURITY : strcmp(arg, "identities") == 0 ? SD_IDENTITIES :
		    strcmp(arg, "document") == 0 ? SD_DOCUMENT : SD_OVERVIEW;
		if (sd.tab == SD_EDGES || sd.tab == SD_OVERVIEW)
			plan_load();
		else if (sd.tab == SD_PATHS || sd.tab == SD_SECURITY)
			paths_load();
		if (sd.tab == SD_SECURITY) {
			identities_load();
			audit_load();
		}
		else if (sd.tab == SD_IDENTITIES)
			identities_load();
		sd.note[0] = '\0';
		if (sd.tab != SD_DOCUMENT)
			sd.error[0] = '\0';
	} else if (strcmp(act, "sd-span") == 0)
		sd.mon_span = atoi(arg);
	else if (strcmp(act, "sd-swvc") == 0) {
		snprintf(sd.swvc, sizeof(sd.swvc), "%s", arg);
		sd.tab = SD_SERVICES;
	} else if (strcmp(act, "input:sd-swvc") == 0)
		snprintf(sd.swvc, sizeof(sd.swvc), "%s", value);
	else if (strcmp(act, "input:sd-audit-filter") == 0)
		snprintf(sd.audit_filter, sizeof(sd.audit_filter), "%s", value);
	else if (strcmp(act, "input:sd-record-filter") == 0)
		snprintf(sd.record_filter, sizeof(sd.record_filter), "%s", value);
	else if (strcmp(act, "sd-example") == 0)
		example();
	else if (strcmp(act, "sd-export") == 0 && sd.doc != NULL) {
		char	name[64];

		/* As it is kept, written for people to read. */
		snprintf(name, sizeof(name), "sdwan-v%lld", (long long)jint(
		    sd.doc, "version", 0));
		export_save(name, sd.doc, strcmp(arg, "yaml") == 0);
	} else if (strcmp(act, "file:sd-import") == 0) {
		ucl_object_t	*o;

		/* Read and laid out, not kept: Check, then Keep. */
		sd.error[0] = sd.note[0] = '\0';
		o = value[0] != '\0' ? data_parse(value, sd.error,
		    sizeof(sd.error)) : NULL;
		if (o == NULL || ucl_object_type(o) != UCL_OBJECT)
			snprintf(sd.error, sizeof(sd.error), "%s: not a JSON or "
			    "YAML document (or larger than 4 MiB)", arg);
		else {
			free(sd.text);
			sd.text = pretty(o);
			snprintf(sd.note, sizeof(sd.note), "Read from %s and put "
			    "in the box, not kept yet: Check it, then Keep.", arg);
		}
		if (o != NULL)
			ucl_object_unref(o);
		sd.tab = SD_DOCUMENT;
	}
	else if (strcmp(act, "sd-list-add") == 0 || strcmp(act, "sd-list-edit")
	    == 0) {
		snprintf(sd.edit, sizeof(sd.edit), "%s", strcmp(act, "sd-list-edit")
		    == 0 ? arg : "");
		app.modal = MODAL_SD_LIST;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "sd-ident-add") == 0) {
		app.modal = MODAL_SD_IDENTITY;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "sd-ident-revoke") == 0) {
		/* arg: swvc|end_point|name */
		confirm("Revoke the identity", "Its peer is removed from the edge "
		    "by the apply that follows; it can be issued again, with a "
		    "new key.", "Revoke", true, "", "do-sd-ident-revoke", arg, "");
	} else if (strcmp(act, "do-sd-ident-revoke") == 0) {
		char	url[400], a[300], *p, *q;

		snprintf(a, sizeof(a), "%s", arg);
		p = strchr(a, '|');
		q = p != NULL ? strchr(p + 1, '|') : NULL;
		if (p != NULL && q != NULL) {
			*p++ = '\0';
			*q++ = '\0';
			snprintf(url, sizeof(url), "/api/sdwan/identities?swvc=%s&"
			    "end_point=%s&name=%s", a, p, q);
			api("DELETE", url, NULL, revoke_cb, NULL);
		}
	} else if (strcmp(act, "sd-config-done") == 0) {
		free(sd.config);
		sd.config = NULL;
		app.modal = MODAL_NONE;
	} else if (strcmp(act, "sd-list-del") == 0) {
		confirm("Take it away", "The list goes; a policy that names it "
		    "will not pass the check until changed.", "Take away", true, "",
		    "do-sd-list-del", arg, value);
	} else if (strcmp(act, "do-sd-list-del") == 0) {
		lists_send(arg, NULL);
	} else if (strcmp(act, "sd-lists-fetch") == 0) {
		api("POST", "/api/sdwan/lists/fetch", "{}", lists_put_cb, NULL);
	} else if (strcmp(act, "sd-rekey") == 0) {
		ucl_object_t	*o;
		unsigned char	*json;

		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(arg), "tunnel", 0,
		    false);
		json = ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
		ucl_object_unref(o);
		api("POST", "/api/sdwan/rekey", (const char *)json, rekey_cb, NULL);
		free(json);
	} else if (strcmp(act, "sd-apply") == 0 || strcmp(act,
	    "do-sd-apply-fresh") == 0) {
		sd.applying = true;
		api("POST", "/api/sdwan/apply", strcmp(act, "sd-apply") == 0 ?
		    "{}" : "{\"fresh\":true}", apply_cb, NULL);
	} else if (strcmp(act, "sd-needs-check") == 0) {
		plan_load();
	} else if (strcmp(act, "sd-need-install") == 0) {
		/* Asked for here, by who looks: a pkg-install job there. */
		struct server	*s = NULL;
		char		*q, *json;
		int		 k;

		for (k = 0; k < app.nservers; k++)
			if (strcmp(app.servers[k].id, arg) == 0)
				s = &app.servers[k];
		if (s == NULL || value[0] == '\0' || strspn(value,
		    "abcdefghijklmnopqrstuvwxyz0123456789-_.+") !=
		    strlen(value))
			return (true);
		q = json_quote(value);
		if (asprintf(&json, "{\"kind\":\"pkg-install\",\"packages\":"
		    "[%s]}", q) == -1)
			abort();
		free(q);
		snprintf(sd.need_title, sizeof(sd.need_title), "pkg install %s",
		    value);
		job_send_host(s, json, sd.need_title, JOB_PACKAGES, "");
	} else if (strcmp(act, "sd-apply-ask") == 0) {
		char	body[400];

		snprintf(body, sizeof(body), "On the edges, as jobs in Mplify "
		    "119's order: %d to make, %d to make again, %d to take away; "
		    "%d stay as they are. Every job the host can undo runs in "
		    "safe mode, confirmed by the console's next read of it; when "
		    "a step fails, everything this apply made before it is taken "
		    "away again (rolled back), and what it took away at its start "
		    "stays away. The UNIs come last.", count_change("make"),
		    count_change("remake"), count_change("unmake"), count_change(
		    "keep"));
		confirm("Deploy to the edges", body, "Deploy", false, "",
		    "sd-apply", "", "");
	} else if (strcmp(act, "sd-show-kept") == 0) {
		sd.show_kept = !sd.show_kept;
	} else if (strcmp(act, "sd-apply-fresh") == 0)
		confirm("Make all again", "Everything the console made on the "
		    "edges is taken away and made again: tunnels go down for a "
		    "while.", "Make all again", true, "", "do-sd-apply-fresh",
		    "", "");
	else if (strcmp(act, "sd-revert") == 0) {
		free(sd.text);
		sd.text = sd.doc != NULL ? pretty(sd.doc) : NULL;
		sd.error[0] = sd.note[0] = '\0';
	}
	return (true);
}

void
sdwan_tick(double now)
{
	static double	at;

	if (app.node == NODE_SDWAN && app.visible && ((sd.tab == SD_PATHS &&
	    now - sd.paths_at > PATHS_EVERY_MS) || (sd.tab == SD_OVERVIEW &&
	    now - sd.paths_at > DASH_EVERY_MS)))
		paths_load();
	if (app.node == NODE_SDWAN && app.visible && sd.tab == SD_OVERVIEW &&
	    sd.applied == NULL && now - sd.apply_at > 5000) {
		sd.apply_at = now;
		api("GET", "/api/sdwan/apply", NULL, applied_cb, NULL);
	}
	if (app.node == NODE_SDWAN && app.visible && sd.tab == SD_EDGES &&
	    sd.applying && now - sd.apply_at > 1000) {
		sd.apply_at = now;
		api("GET", "/api/sdwan/apply", NULL, applied_cb, NULL);
	}
	/* Kept elsewhere meanwhile: read again, unless a change is typed. */
	if (app.node != NODE_SDWAN || !app.visible || sd.tab == SD_DOCUMENT ||
	    sd.loading || now - at < 30000)
		return;
	at = now;
	sd_load();
}
