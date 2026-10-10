/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Network section's Traceroute: the way from a host to an address,
 * hop by hop, asked again and again as mtr(8) does, each hop with how
 * many probes it lost and how long the others took.  Where a hop is a
 * host of this console it is named, with the interface the probe came
 * in by; and of the host it starts from and every such host on the way,
 * the interface it sends on towards the address and that interface's
 * MTU, as its routing table and its interfaces say: the smallest of
 * those is as large as the path's MTU can be.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	MTR_HOPS	31	/* ttl 1 to 30 */
#define	MTR_EVERY	1000	/* ms between two rounds */

struct mhop {
	char	addr[64];
	int	sent, recv;
	int	addrs;		/* how many answered at this ttl, over time */
	double	last, best, worst, sum, sum2;
	char	note[8];
};

/* Of a host of this console's: which way it sends to the address. */
struct egress {
	bool	asked, known;
	char	ifn[16];
	char	gw[64];
};

static struct {
	int		 from;		/* app.servers */
	char		 to[64];
	char		 to_host[9];	/* the host picked as the end, or "" */
	bool		 running, busy;
	int		 rounds;
	int		 maxttl;	/* the hops of the last round */
	bool		 reached;
	double		 asked;
	char		 error[200];
	int		 gen;		/* answers to an older start are dropped */
	struct mhop	 hop[MTR_HOPS];
	struct egress	 out[MAX_SERVERS];
} mt = { .from = -1 };

static int
srv_of(const char *sid)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sid) == 0)
			return (i);
	return (-1);
}

static void
round_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*h;
	ucl_object_iter_t	 it;
	struct mhop		*m;
	double			 rtt;
	int			 ttl, gen;

	gen = (int)(intptr_t)arg;
	if (gen != mt.gen)
		return;
	mt.busy = false;
	if (status != 200 || !jbool(o, "ok")) {
		snprintf(mt.error, sizeof(mt.error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		mt.running = false;
		return;
	}
	mt.error[0] = '\0';
	mt.rounds++;
	mt.maxttl = 0;
	it = NULL;
	while ((h = ucl_object_iterate(jget(o, "data.hops"), &it, true)) !=
	    NULL) {
		if ((ttl = (int)jint(h, "ttl", 0)) <= 0 || ttl >= MTR_HOPS)
			continue;
		if (ttl > mt.maxttl)
			mt.maxttl = ttl;
		m = &mt.hop[ttl];
		m->sent++;
		if (jbool(h, "lost") || jstr(h, "address") == NULL)
			continue;
		if (m->addr[0] != '\0' && strcmp(m->addr, jstr(h, "address")) !=
		    0)
			m->addrs++;
		else if (m->addr[0] == '\0')
			m->addrs = 1;
		snprintf(m->addr, sizeof(m->addr), "%s", jstr(h, "address"));
		snprintf(m->note, sizeof(m->note), "%s", jstr(h, "note") !=
		    NULL ? jstr(h, "note") : "");
		rtt = jnum(h, "rtt", 0);
		m->recv++;
		m->last = rtt;
		if (m->recv == 1 || rtt < m->best)
			m->best = rtt;
		if (rtt > m->worst)
			m->worst = rtt;
		m->sum += rtt;
		m->sum2 += rtt * rtt;
	}
	mt.reached = jbool(o, "data.reached");
}

static void
egress_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct egress	*e;
	int		 s;

	(void)err;
	s = (int)(intptr_t)arg;
	if (s < 0 || s >= MAX_SERVERS)
		return;
	e = &mt.out[s];
	if (status != 200 || !jbool(o, "ok") || jget(o, "data.best") == NULL)
		return;
	e->known = true;
	snprintf(e->ifn, sizeof(e->ifn), "%s", jstr(o, "data.best.interface") !=
	    NULL ? jstr(o, "data.best.interface") : "");
	snprintf(e->gw, sizeof(e->gw), "%s", jstr(o, "data.best.gateway") !=
	    NULL ? jstr(o, "data.best.gateway") : "");
}

/* Which way a host of ours sends to the address: asked once a start. */
static void
egress_ask(int s)
{
	char	url[200];

	if (s < 0 || s >= app.nservers || mt.out[s].asked)
		return;
	mt.out[s].asked = true;
	snprintf(url, sizeof(url), "/api/servers/%s/net/lookup?to=%s",
	    app.servers[s].id, mt.to);
	api("GET", url, NULL, egress_cb, (void *)(intptr_t)s);
}

void
mtr_tick(double now)
{
	char	url[200];
	int	ttl, s;
	char	ifn[16], jail[64];

	if (app.node != NODE_NETWORK || app.netsect != NETSECT_TRACE ||
	    !mt.running || mt.busy || now - mt.asked < MTR_EVERY ||
	    mt.from < 0 || mt.from >= app.nservers)
		return;
	mt.busy = true;
	mt.asked = now;
	snprintf(url, sizeof(url), "/api/servers/%s/net/traceroute?to=%s",
	    app.servers[mt.from].id, mt.to);
	api("GET", url, NULL, round_cb, (void *)(intptr_t)mt.gen);
	/* The hosts of ours on the way: which way each sends on. */
	egress_ask(mt.from);
	for (ttl = 1; ttl <= mt.maxttl; ttl++)
		if (mt.hop[ttl].addr[0] != '\0' && (s = topo_addr_owner(
		    mt.hop[ttl].addr, ifn, sizeof(ifn), jail, sizeof(jail))) >=
		    0 && jail[0] == '\0')
			egress_ask(s);
}

/* An address to go to: as typed, or a host of ours picked. */
static bool
valid_addr(const char *s)
{

	return (s[0] != '\0' && strlen(s) < 64 && s[strspn(s,
	    "0123456789abcdefABCDEF.:")] == '\0');
}

static void
start(void)
{

	memset(mt.hop, 0, sizeof(mt.hop));
	memset(mt.out, 0, sizeof(mt.out));
	mt.rounds = mt.maxttl = 0;
	mt.reached = false;
	mt.error[0] = '\0';
	mt.gen++;
	mt.busy = false;
	mt.asked = 0;
	if (mt.from < 0 || mt.from >= app.nservers) {
		snprintf(mt.error, sizeof(mt.error), "Pick the host it starts "
		    "from");
		return;
	}
	if (!valid_addr(mt.to)) {
		snprintf(mt.error, sizeof(mt.error), "An IPv4 or IPv6 address, "
		    "or a host of this console picked");
		return;
	}
	mt.running = true;
	mtr_tick(arc_now());
}

bool
mtr_action(const char *act, const char *arg, const char *value)
{
	const char	*a;
	int		 s;

	if (strcmp(act, "input:mtr-from") == 0) {
		mt.from = srv_of(value);
		mt.running = false;
		return (true);
	}
	if (strcmp(act, "input:mtr-host") == 0) {
		snprintf(mt.to_host, sizeof(mt.to_host), "%s", value);
		if ((s = srv_of(value)) >= 0 && (a = topo_host_addr(s, 0)) !=
		    NULL)
			snprintf(mt.to, sizeof(mt.to), "%.*s", (int)strcspn(a,
			    "%/"), a);
		mt.running = false;
		return (true);
	}
	if (strcmp(act, "input:mtr-to") == 0) {
		snprintf(mt.to, sizeof(mt.to), "%.*s", (int)strcspn(value, " "),
		    value);
		mt.to_host[0] = '\0';
		mt.running = false;
		return (true);
	}
	if (strcmp(act, "mtr-start") == 0) {
		start();
		return (true);
	}
	if (strcmp(act, "mtr-stop") == 0) {
		mt.running = false;
		mt.gen++;
		mt.busy = false;
		return (true);
	}
	(void)arg;
	return (false);
}

static void
ms(struct html *h, double v, bool have)
{

	if (have)
		h_fmt(h, "<td class=\"num\">%.1f</td>", v);
	else
		h_raw(h, "<td class=\"num dim\">—</td>");
}

/* Where a host of ours sends on: its interface and that one's MTU. */
static int
egress_cell(struct html *h, int s)
{
	const struct egress	*e;
	int			 mtu;

	if (s < 0 || !(e = &mt.out[s])->known || e->ifn[0] == '\0') {
		h_raw(h, "<td class=\"dim\">…</td><td class=\"num dim\">—</td>");
		return (0);
	}
	mtu = topo_if_mtu(s, e->ifn);
	h_raw(h, "<td class=\"mono\">");
	h_txt(h, e->ifn);
	if (e->gw[0] != '\0' && strncmp(e->gw, "link#", 5) != 0) {
		h_raw(h, " <small class=\"dim\">via ");
		h_txt(h, e->gw);
		h_raw(h, "</small>");
	}
	h_raw(h, "</td>");
	if (mtu > 0)
		h_fmt(h, "<td class=\"num\">%d</td>", mtu);
	else
		h_raw(h, "<td class=\"num dim\">—</td>");
	return (mtu);
}

void
view_traceroute(struct html *h)
{
	const struct mhop	*m;
	char			 ifn[16], jail[64];
	double			 avg, sd, worst;
	int			 i, ttl, s, mtu, pmtu, loss;

	if (mt.from < 0 && app.nservers > 0)
		mt.from = app.sel >= 0 && app.sel < app.nservers ? app.sel : 0;
	h_raw(h, "<div class=\"mtr\"><div class=\"toolbar mtr-form\"><label>"
	    "From<select data-input=\"mtr-from\">");
	for (i = 0; i < app.nservers; i++) {
		h_raw(h, "<option");
		h_attr(h, "value", app.servers[i].id);
		if (i == mt.from)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, app.servers[i].name);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label><label>To<select data-input=\"mtr-host\">"
	    "<option value=\"\">an address…</option>");
	for (i = 0; i < app.nservers; i++) {
		h_raw(h, "<option");
		h_attr(h, "value", app.servers[i].id);
		if (strcmp(mt.to_host, app.servers[i].id) == 0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, app.servers[i].name);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label><label>Address<input data-input=\"mtr-to\" "
	    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\""
	    "192.0.2.10 or 2001:db8::10\"");
	h_attr(h, "value", mt.to);
	h_raw(h, "></label>");
	if (mt.running)
		h_raw(h, "<button class=\"small\" data-act=\"mtr-stop\">Stop"
		    "</button>");
	else
		h_raw(h, "<button class=\"primary small\" data-act=\"mtr-start\">"
		    "Start</button>");
	if (mt.rounds > 0)
		h_fmt(h, "<span class=\"tally\">%d round%s%s</span>", mt.rounds,
		    mt.rounds == 1 ? "" : "s", mt.running ? ", going on" : "");
	h_raw(h, "</div>");
	if (mt.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, mt.error);
		h_raw(h, "</div>");
	}
	if (mt.rounds == 0) {
		h_raw(h, mt.running ? "<div class=\"empty\"><div class=\"loader\">"
		    "</div></div>" : "<p class=\"dim mtr-note\">A probe a hop, a "
		    "round every second, as <code>mtr</code> does: each hop with "
		    "what it lost and how long the rest took, in milliseconds. "
		    "Where a hop is a host of this console it is named, with "
		    "the interface it was reached by; of each of ours on the way, "
		    "the interface it sends on towards the address and its "
		    "MTU.</p>");
		h_raw(h, "</div>");
		return;
	}
	h_raw(h, "<table class=\"net mtr-table\"><thead><tr><th>#</th><th>"
	    "Address</th><th>Host of ours</th><th>Sends on</th><th class=\""
	    "num\">MTU</th><th class=\"num\">Loss</th><th class=\"num\">Sent"
	    "</th><th class=\"num\">Last</th><th class=\"num\">Avg</th><th "
	    "class=\"num\">Best</th><th class=\"num\">Worst</th><th class=\""
	    "num\">StDev</th><th></th></tr></thead><tbody>");
	/* Where it starts: the host itself. */
	h_raw(h, "<tr class=\"mtr-src\"><td class=\"num\">0</td><td class=\"dim\">"
	    "—</td><td><b>");
	h_txt(h, app.servers[mt.from].name);
	h_raw(h, "</b></td>");
	pmtu = egress_cell(h, mt.from);
	h_raw(h, "<td colspan=\"7\" class=\"dim\">where it starts</td><td></td>"
	    "</tr>");
	worst = 1;
	for (ttl = 1; ttl <= mt.maxttl; ttl++)
		if (mt.hop[ttl].recv > 0 && mt.hop[ttl].worst > worst)
			worst = mt.hop[ttl].worst;
	for (ttl = 1; ttl <= mt.maxttl; ttl++) {
		m = &mt.hop[ttl];
		loss = m->sent > 0 ? (m->sent - m->recv) * 100 / m->sent : 0;
		avg = m->recv > 0 ? m->sum / m->recv : 0;
		sd = m->recv > 1 ? sqrt(fmax(0, m->sum2 / m->recv - avg *
		    avg)) : 0;
		s = m->addr[0] != '\0' ? topo_addr_owner(m->addr, ifn,
		    sizeof(ifn), jail, sizeof(jail)) : -1;
		h_fmt(h, "<tr class=\"%s%s\"><td class=\"num\">%d</td><td class="
		    "\"mono\">", s >= 0 ? "ours" : "", loss >= 50 ? " lossy" :
		    "", ttl);
		h_txt(h, m->addr[0] != '\0' ? m->addr : "???");
		if (m->addrs > 1)
			h_fmt(h, " <small class=\"dim\" title=\"Several answered "
			    "at this hop over the rounds: more than one way\">"
			    "+%d</small>", m->addrs - 1);
		if (m->note[0] != '\0') {
			h_raw(h, " <small class=\"err\">");
			h_txt(h, m->note);
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td>");
		if (s >= 0) {
			h_raw(h, "<b>");
			h_txt(h, app.servers[s].name);
			h_raw(h, "</b>");
			if (jail[0] != '\0') {
				h_raw(h, " <small class=\"dim\">jail ");
				h_txt(h, jail);
				h_raw(h, "</small>");
			}
			h_raw(h, " <small class=\"dim\">in ");
			h_txt(h, ifn);
			h_raw(h, "</small>");
		}
		h_raw(h, "</td>");
		if (s >= 0 && jail[0] == '\0') {
			mtu = egress_cell(h, s);
			if (mtu > 0 && (pmtu == 0 || mtu < pmtu))
				pmtu = mtu;
		} else
			h_raw(h, "<td></td><td></td>");
		h_fmt(h, "<td class=\"num%s\">%d%%</td><td class=\"num\">%d</td>",
		    loss > 0 ? " warn" : "", loss, m->sent);
		ms(h, m->last, m->recv > 0);
		ms(h, avg, m->recv > 0);
		ms(h, m->best, m->recv > 0);
		ms(h, m->worst, m->recv > 0);
		ms(h, sd, m->recv > 1);
		/* How long, beside the others: the best to the worst. */
		h_raw(h, "<td class=\"mtr-bar\">");
		if (m->recv > 0)
			h_fmt(h, "<span style=\"left:%.1f%%;width:%.1f%%\" "
			    "title=\"best %.1f · avg %.1f · worst %.1f ms\"><i "
			    "style=\"left:%.1f%%\"></i></span>", 100 * m->best /
			    worst, fmax(1.5, 100 * (m->worst - m->best) / worst),
			    m->best, avg, m->worst, m->worst > m->best ? 100 *
			    (avg - m->best) / (m->worst - m->best) : 0);
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table>");
	if (pmtu > 0)
		h_fmt(h, "<p class=\"dim mtr-note\">The path's MTU is at most "
		    "<b>%d</b>: the smallest of the interfaces of this console's "
		    "hosts it leaves by%s.</p>", pmtu, mt.reached ? "" : "; the "
		    "address has not answered yet");
	else if (!mt.reached)
		h_raw(h, "<p class=\"dim mtr-note\">The address has not answered "
		    "yet.</p>");
	h_raw(h, "</div>");
}
