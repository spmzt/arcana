/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * How a nexthop group shares out what it carries, as the agents sampled
 * it, beside the weights it was given.  The sending side is the host the
 * group is on: each of its next hops leaves by an interface, and what
 * that interface sent is its share.  The receiving side is the hosts the
 * gateways are: what the interface with the gateway's address received
 * is its share.  Both come from the samples each agent keeps by itself
 * (the history), so they are there when the page is opened.
 *
 * An interface's traffic is all of it, not only the group's: an
 * interface that carries more than the group's routes counts that too.
 * Next hops that leave by one interface, or arrive at one, are one
 * share, as the samples cannot tell them apart.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"

#define	nitems(x)	(sizeof(x) / sizeof((x)[0]))

#define	EC_SHARES	6	/* shares of a group told apart, a colour each */
#define	EC_BINS		60	/* columns of a chart */
#define	EC_SAMPLES	1000	/* samples of an interface looked at */
#define	EC_GROUPS_MS	15000	/* the groups of every host, read again */
#define	EC_IFS_MS	15000	/* every host's interfaces, for addresses */
#define	CW		360	/* a chart's box */
#define	CH		110

/* The colour of a share, by its place in the group: never by its size. */
static const char *const colours[EC_SHARES] = { "var(--nh-1)",
    "var(--nh-2)", "var(--nh-3)", "var(--nh-4)", "var(--nh-5)",
    "var(--nh-6)" };

struct share {
	char		 gws[96];	/* the gateways it is of */
	char		 where[96];	/* host · interface */
	char		 key[96];	/* what makes it this share */
	int		 srv;		/* whose samples; -1 none */
	char		 ifn[16];
	long long	 weight;
	double		 bin[EC_BINS];	/* bytes a second, each column */
	bool		 has[EC_BINS];
	double		 sum;		/* over the columns all shares have */
	char		 why[96];	/* not sampled: why */
};

/* Of each host, for the network section: its groups. */
struct ehost {
	char		 sid[9];
	ucl_object_t	*fams;
	bool		 loading;
	double		 asked;
	char		 error[160];
};

static struct {
	int		 span;		/* seconds drawn */
	struct ehost	 eh[MAX_SERVERS];
	double		 ifs_asked;
} ec = { .span = 900 };

bool
ecmp_shown(void)
{

	return ((app.node == NODE_NETWORK && app.netsect == NETSECT_GROUPS) ||
	    (app.node == NODE_HOST && app.tab == TAB_NETWORK &&
	    app.net.kind == NET_NHGROUPS && net_scope()[0] == '\0'));
}


static struct ehost *
ehost(const char *sid, bool make)
{
	int	i;

	for (i = 0; i < MAX_SERVERS; i++)
		if (strcmp(ec.eh[i].sid, sid) == 0)
			return (&ec.eh[i]);
	for (i = 0; make && i < MAX_SERVERS; i++)
		if (ec.eh[i].sid[0] == '\0') {
			snprintf(ec.eh[i].sid, sizeof(ec.eh[i].sid), "%s", sid);
			return (&ec.eh[i]);
		}
	return (NULL);
}

static void
groups_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ehost	*e;
	char		*sid;

	sid = arg;
	e = ehost(sid, false);
	free(sid);
	if (e == NULL)
		return;
	e->loading = false;
	if (status != 200 || !jbool(o, "ok")) {
		snprintf(e->error, sizeof(e->error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	e->error[0] = '\0';
	if (e->fams != NULL)
		ucl_object_unref(e->fams);
	e->fams = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o,
	    "data.statistics.route-nhgrp-information.nhgrp-table.rt-family"));
}

/*
 * While the shares are drawn: the samples are read by the history's
 * own tick; here every host's interfaces, for who has a gateway's
 * address, and in the network section every host's groups.
 */
void
ecmp_tick(double now)
{
	struct ehost	*e;
	char		 url[160];
	int		 i;

	if (!ecmp_shown() || !app.visible)
		return;
	if (now - ec.ifs_asked > EC_IFS_MS) {
		ec.ifs_asked = now;
		topo_poll_all();
	}
	if (app.node != NODE_NETWORK)
		return;
	for (i = 0; i < app.nservers; i++) {
		if ((e = ehost(app.servers[i].id, true)) == NULL ||
		    (e->loading && now - e->asked < 30000) ||
		    now - e->asked < EC_GROUPS_MS)
			continue;
		e->loading = true;
		e->asked = now;
		snprintf(url, sizeof(url), "/api/servers/%s/net/nhgroups?"
		    "family=all", app.servers[i].id);
		api("GET", url, NULL, groups_cb, strdup(app.servers[i].id));
	}
}

static int
srv_index(const struct server *s)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (&app.servers[i] == s)
			return (i);
	return (-1);
}

static void
append(char *buf, size_t len, const char *what)
{
	size_t	n;

	n = strlen(buf);
	if (strstr(buf, what) == NULL)
		snprintf(buf + n, len - n, "%s%s", n > 0 ? ", " : "", what);
}

/*
 * The shares of group g of server s, as the sender's interfaces sent
 * (recv false) or the gateways' hosts received; how many.  Each column
 * of the window is what the samples in it averaged; a column counts
 * only where every share sampled has one, so that the shares are of
 * the same moments.
 */
static int
shares(const struct server *s, const ucl_object_t *g, bool recv,
    struct share *sh, double t1)
{
	static double		 t[EC_SAMPLES], v[EC_SAMPLES];
	const ucl_object_t	*n;
	ucl_object_iter_t	 it;
	double			 t0, w, acc[EC_BINS];
	char			 ifn[16], jail[64], key[96];
	const char		*gw, *nif;
	int			 ns, k, i, b, cnt[EC_BINS], m, srv, si;

	ns = 0;
	si = srv_index(s);
	it = NULL;
	while ((n = ucl_object_iterate(jget(g, "nhop-weights"), &it, true)) !=
	    NULL) {
		gw = jstr(n, "nh-gw") != NULL ? jstr(n, "nh-gw") : "?";
		nif = jstr(n, "nh-interface") != NULL ? jstr(n,
		    "nh-interface") : "";
		srv = si;
		snprintf(ifn, sizeof(ifn), "%s", nif);
		jail[0] = '\0';
		if (recv && (srv = topo_gw_owner(gw, si, nif, ifn, sizeof(ifn),
		    jail, sizeof(jail))) == -1)
			snprintf(key, sizeof(key), "?%s", gw);
		else
			snprintf(key, sizeof(key), "%d/%s/%s", srv, jail, ifn);
		for (k = 0; k < ns; k++)
			if (strcmp(sh[k].key, key) == 0)
				break;
		if (k == ns) {
			if (ns == EC_SHARES)
				continue;
			memset(&sh[k], 0, sizeof(sh[k]));
			snprintf(sh[k].key, sizeof(sh[k].key), "%s", key);
			sh[k].srv = -1;
			if (recv && srv == -1)
				snprintf(sh[k].why, sizeof(sh[k].why), "%s",
				    strncmp(gw, "fe80:", 5) == 0 || strncmp(gw,
				    "169.254.", 8) == 0 ? "no host of this "
				    "console has it on that link, or several do" :
				    "not a host of this console");
			else if (jail[0] != '\0')
				snprintf(sh[k].why, sizeof(sh[k].why), "in jail "
				    "%.40s of %.30s: a jail's interfaces are not "
				    "sampled", jail, app.servers[srv].name);
			else {
				sh[k].srv = srv;
				snprintf(sh[k].ifn, sizeof(sh[k].ifn), "%s", ifn);
				snprintf(sh[k].where, sizeof(sh[k].where),
				    "%.30s · %s", app.servers[srv].name, ifn);
			}
			ns++;
		}
		append(sh[k].gws, sizeof(sh[k].gws), gw);
		sh[k].weight += jint(n, "nh-weight", 1);
	}
	t0 = t1 - ec.span;
	w = (double)ec.span / EC_BINS;
	for (k = 0; k < ns; k++) {
		if (sh[k].srv == -1)
			continue;
		m = usage_if_rates(app.servers[sh[k].srv].id, sh[k].ifn, !recv,
		    t0, t, v, EC_SAMPLES);
		if (m == -1) {
			snprintf(sh[k].why, sizeof(sh[k].why), "%s is not "
			    "among what its agent samples", sh[k].ifn);
			sh[k].srv = -1;
			continue;
		}
		memset(acc, 0, sizeof(acc));
		memset(cnt, 0, sizeof(cnt));
		for (i = 0; i < m; i++) {
			b = (int)((t[i] - t0) / w);
			if (b < 0 || b >= EC_BINS)
				continue;
			acc[b] += v[i];
			cnt[b]++;
		}
		for (b = 0; b < EC_BINS; b++)
			if (cnt[b] > 0) {
				sh[k].bin[b] = acc[b] / cnt[b];
				sh[k].has[b] = true;
			}
	}
	/* The columns every sampled share has. */
	for (b = 0; b < EC_BINS; b++) {
		for (k = 0, m = 0; k < ns; k++)
			if (sh[k].srv != -1 && !sh[k].has[b])
				break;
			else if (sh[k].srv != -1)
				m++;
		if (k < ns || m == 0)
			for (k = 0; k < ns; k++)
				sh[k].has[b] = false;
	}
	for (k = 0; k < ns; k++)
		for (b = 0; b < EC_BINS; b++)
			if (sh[k].has[b])
				sh[k].sum += sh[k].bin[b];
	return (ns);
}

static void
ago(char *buf, size_t len, double secs)
{

	if (secs < 90)
		snprintf(buf, len, "%.0f s ago", secs);
	else if (secs < 5400)
		snprintf(buf, len, "%.0f min ago", secs / 60);
	else
		snprintf(buf, len, "%.1f h ago", secs / 3600);
}

/*
 * One side of a group, drawn: each column the shares of that moment,
 * stacked to the whole; the weights as dashed lines where the shares
 * would meet if they were kept; and beside it each share, what it
 * carried against what it was given.
 */
static void
side(struct html *h, const struct server *s, const ucl_object_t *g,
    bool recv, double t1)
{
	struct share	 sh[EC_SHARES];
	char		 rate[24], tip[512], when[24];
	double		 all, y, cw, hgt, wsum, cum, mean;
	long long	 wtotal;
	int		 ns, k, b, sampled, cols, nlen;

	ns = shares(s, g, recv, sh, t1);
	all = 0;
	wtotal = 0;
	sampled = 0;
	for (k = 0; k < ns; k++) {
		all += sh[k].sum;
		wtotal += sh[k].weight;
		if (sh[k].srv != -1)
			sampled++;
	}
	for (b = 0, cols = 0; b < EC_BINS; b++)
		for (k = 0; k < ns; k++)
			if (sh[k].has[b]) {
				cols++;
				break;
			}
	h_fmt(h, "<div class=\"ecmp-side\"><h5>%s</h5>", recv ? "Received, "
	    "at the gateways" : "Sent, by its interfaces");
	if (sampled == 0) {
		h_raw(h, "<p class=\"dim\">");
		h_raw(h, recv ? "None of its gateways is a host of this "
		    "console whose interfaces are sampled: what they receive "
		    "is not known here." : "Its interfaces are not among "
		    "what the agent samples.");
		h_raw(h, "</p></div>");
		return;
	}
	if (cols == 0 || all <= 0) {
		h_fmt(h, "<p class=\"dim\">Nothing %s in the last %d min, or "
		    "no samples yet: the agents sample every few seconds."
		    "</p></div>", recv ? "received" : "sent", ec.span / 60);
		return;
	}
	cw = (double)CW / EC_BINS;
	h_fmt(h, "<svg class=\"ecmp-chart\" viewBox=\"0 0 %d %d\" "
	    "preserveAspectRatio=\"none\" role=\"img\"><title>The share of "
	    "each over the last %d min</title>", CW, CH, ec.span / 60);
	for (b = 0; b < EC_BINS; b++) {
		mean = 0;
		for (k = 0; k < ns; k++)
			if (sh[k].has[b])
				mean += sh[k].bin[b];
		if (mean <= 0)
			continue;
		y = CH;
		ago(when, sizeof(when), ec.span - (b + 0.5) * ec.span /
		    EC_BINS);
		snprintf(tip, sizeof(tip), "%s", when);
		for (k = 0; k < ns; k++) {
			if (!sh[k].has[b])
				continue;
			hgt = CH * sh[k].bin[b] / mean;
			y -= hgt;
			/* A gap of the surface between columns. */
			h_fmt(h, "<rect x=\"%.2f\" y=\"%.2f\" width=\"%.2f\" "
			    "height=\"%.2f\" fill=\"%s\"/>", b * cw, y, cw >
			    2 ? cw - 1 : cw, hgt, colours[k]);
			fmt_rate(rate, sizeof(rate), sh[k].bin[b]);
			nlen = (int)strlen(tip);
			snprintf(tip + nlen, sizeof(tip) - (size_t)nlen,
			    "\n%.40s: %.0f%% (%s)", sh[k].gws, 100 *
			    sh[k].bin[b] / mean, rate);
		}
		/* The hover: the whole column, bigger than any of its parts. */
		h_fmt(h, "<rect class=\"hit\" x=\"%.2f\" y=\"0\" width=\"%.2f\" "
		    "height=\"%d\"><title>", b * cw, cw, CH);
		h_txt(h, tip);
		h_raw(h, "</title></rect>");
	}
	/* The weights: where the shares would meet. */
	cum = 0;
	for (k = 0; k + 1 < ns && wtotal > 0; k++) {
		cum += (double)sh[k].weight / wtotal;
		h_fmt(h, "<line class=\"ecmp-weight\" x1=\"0\" x2=\"%d\" "
		    "y1=\"%.2f\" y2=\"%.2f\"/>", CW, CH - CH * cum, CH - CH *
		    cum);
	}
	h_raw(h, "</svg><div class=\"ecmp-axis\"><span>");
	ago(when, sizeof(when), ec.span);
	h_txt(h, when);
	h_raw(h, "</span><span>now</span></div><ul class=\"ecmp-key\">");
	wsum = wtotal > 0 ? (double)wtotal : 1;
	for (k = 0; k < ns; k++) {
		h_fmt(h, "<li><i style=\"background:%s\"></i><span class=\""
		    "mono\">", colours[k]);
		h_txt(h, sh[k].gws);
		h_raw(h, "</span>");
		if (sh[k].srv == -1) {
			h_raw(h, "<small class=\"dim\">");
			h_txt(h, sh[k].why);
			h_fmt(h, " · weight %.0f%%</small></li>", 100 *
			    sh[k].weight / wsum);
			continue;
		}
		fmt_rate(rate, sizeof(rate), cols > 0 ? sh[k].sum / cols : 0);
		h_fmt(h, "<b>%.0f%%</b><small>of weight %.0f%% · ", 100 *
		    sh[k].sum / all, 100 * sh[k].weight / wsum);
		h_txt(h, sh[k].where);
		h_raw(h, " · ");
		h_txt(h, rate);
		h_raw(h, "</small></li>");
	}
	h_raw(h, "</ul><ul class=\"glegend\"><li class=\"ecmp-w\">where the "
	    "shares would meet, by the next hops' weights</li></ul></div>");
}

/* A group's two sides, as its host's page and the section draw it. */
void
ecmp_group(struct html *h, const struct server *s, const ucl_object_t *g)
{
	double	t1;

	t1 = arc_now() / 1000;
	h_raw(h, "<div class=\"ecmp\">");
	side(h, s, g, false, t1);
	side(h, s, g, true, t1);
	h_raw(h, "</div>");
}

/* How far back the shares are drawn. */
static void
spans(struct html *h)
{
	static const int	 secs[] = { 300, 900, 3600 };
	size_t			 i;

	h_raw(h, "<nav class=\"sub ecmp-span\" title=\"How far back: the "
	    "agents keep what they sampled, an hour unless set otherwise"
	    "\">");
	for (i = 0; i < nitems(secs); i++)
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"ecmp-span\" "
		    "data-arg=\"%d\">%d min</button>", ec.span == secs[i] ?
		    " on" : "", secs[i], secs[i] / 60);
	h_raw(h, "</nav>");
}

static const char note[] = "<p class=\"dim ecmp-note\">What each next hop "
    "carried, as the agents sampled their interfaces, beside the weight it "
    "was given (dashed). An interface's traffic is all of it, not only the "
    "group's; next hops by one interface are one share.</p>";

/* The host page's: above its groups, how far back. */
void
ecmp_head(struct html *h)
{

	h_raw(h, "<div class=\"ecmp-head\">");
	spans(h);
	h_raw(h, note);
	h_raw(h, "</div>");
}

/* The network section's tab: every host's groups, each side by side. */
void
view_ecmp(struct html *h)
{
	const ucl_object_t	*fam, *g;
	ucl_object_iter_t	 it, git;
	struct ehost		*e;
	int			 i, n, waiting;

	h_raw(h, "<div class=\"ecmp-page\"><div class=\"ecmp-head\">");
	spans(h);
	h_raw(h, note);
	h_raw(h, "</div>");
	n = 0;
	waiting = 0;
	for (i = 0; i < app.nservers; i++) {
		e = ehost(app.servers[i].id, false);
		if (e == NULL || (e->fams == NULL && e->error[0] == '\0')) {
			waiting++;
			continue;
		}
		if (e->fams == NULL)
			continue;
		it = NULL;
		while ((fam = ucl_object_iterate(e->fams, &it, true)) != NULL) {
			git = NULL;
			while ((g = ucl_object_iterate(jget(fam,
			    "nhgrp-entry"), &git, true)) != NULL) {
				if (app.filter[0] != '\0' && strstr(
				    app.servers[i].name, app.filter) == NULL)
					continue;
				n++;
				h_raw(h, "<section class=\"pane ecmp-group\"><h4>"
				    "<span>");
				h_txt(h, app.servers[i].name);
				h_fmt(h, " <small>group %lld · ",
				    (long long)jint(g, "nhgrp-index", 0));
				h_txt(h, jstr(fam, "address-family") != NULL ?
				    jstr(fam, "address-family") : "");
				h_fmt(h, " · %lld route%s</small></span></h4>",
				    (long long)jint(g, "nhg-refcnt", 0), jint(g,
				    "nhg-refcnt", 0) == 1 ? "" : "s");
				ecmp_group(h, &app.servers[i], g);
				h_raw(h, "</section>");
			}
		}
	}
	if (n == 0)
		h_raw(h, waiting > 0 ? "<div class=\"empty\"><div class="
		    "\"loader\"></div></div>" : "<div class=\"empty\"><h2>No "
		    "nexthop groups</h2><p>No route of any host has several "
		    "next hops. One is made by a route with several gateways, "
		    "<code>10.0.0.1@2,10.0.0.2@1</code>.</p></div>");
	h_raw(h, "</div>");
}

bool
ecmp_action(const char *act, const char *arg, const char *value)
{

	(void)value;
	if (strcmp(act, "ecmp-span") == 0) {
		ec.span = atoi(arg) >= 60 && atoi(arg) <= 86400 ? atoi(arg) :
		    900;
		return (true);
	}
	if (strcmp(act, "netsect-tab") == 0) {
		app.netsect = strcmp(arg, "groups") == 0 ? NETSECT_GROUPS :
		    strcmp(arg, "traceroute") == 0 ? NETSECT_TRACE :
		    strcmp(arg, "bgp") == 0 ? NETSECT_BGP : strcmp(arg,
		    "ospf") == 0 ? NETSECT_OSPF : strcmp(arg, "bfd") == 0 ?
		    NETSECT_BFD : strcmp(arg, "lists") == 0 ? NETSECT_PREFIXES :
		    NETSECT_MAP;
		if (app.netsect == NETSECT_PREFIXES)
			pfxlists_load();
		ec.ifs_asked = 0;
		if (app.netsect == NETSECT_GROUPS)
			ecmp_tick(arc_now());
		else if (app.netsect >= NETSECT_BGP)
			topo_bird_now();
		return (true);
	}
	return (false);
}
