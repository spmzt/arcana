/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Network › Tunnel quality: every tunnel of the host (or of the vnet
 * jail picked), each either measured, with its delay, delay variation
 * and loss and their trend, or offered to be: a monitor, set by the
 * monitor job, probes the tunnel's far end by ICMP echo through its
 * routing table, outside SD-WAN and untouched by it.  The tunnels come
 * from the interfaces read (a tunnel's ends, a point-to-point address's
 * far end), the measurements from the monitors read, read again every
 * few seconds while shown.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	MON_TICK_MS	3000

static struct {
	struct res	 r;		/* the monitors read */
	double		 fetched;
	char		 edit[72];	/* the monitor or tunnel in the dialog */
	char		 ifname[32];
	char		 address[64];
	int		 fib;
} mn;

static void
mn_load(const char *sid)
{
	char	url[96];

	snprintf(url, sizeof(url), "/api/servers/%s/monitors", sid);
	res_load(&mn.r, sid, url);
}

void
monitors_refresh(void)
{

	res_drop(&mn.r);
}

/* While shown, read again every few seconds, the last read kept. */
void
monitors_tick(double now)
{
	struct server	*s;

	if (!app.visible || app.node != NODE_HOST || app.tab != TAB_NETWORK ||
	    app.net.kind != NET_MONITORS || mn.r.loading || mn.r.o == NULL ||
	    now - mn.fetched < MON_TICK_MS || (s = cur_server()) == NULL)
		return;
	mn.fetched = now;
	mn_load(s->id);
}

/* Is this interface a tunnel: its ends said, or a far end to reach? */
static bool
is_tunnel(const ucl_object_t *o)
{
	static const char *const kinds[] = { "gre", "gif", "wg", "ipsec",
	    "me", "tun", "ovpn", "vxlan", "geneve" };
	const ucl_object_t	*a;
	ucl_object_iter_t	 it;
	const char		*name;
	size_t			 i, n;

	if (jstr(o, "tunnel.local") != NULL)
		return (true);
	it = NULL;
	while ((a = ucl_object_iterate(jget(o, "addresses"), &it, true)) !=
	    NULL)
		if (jstr(a, "destination") != NULL)
			return (true);
	name = jstr(o, "name") != NULL ? jstr(o, "name") : "";
	for (i = 0; i < nitems(kinds); i++) {
		n = strlen(kinds[i]);
		if (strncmp(name, kinds[i], n) == 0 && name[n] >= '0' &&
		    name[n] <= '9')
			return (true);
	}
	return (false);
}

/* A tunnel's far end to probe: a point-to-point address's, inet first. */
static const char *
far_end(const ucl_object_t *o)
{
	const ucl_object_t	*a;
	ucl_object_iter_t	 it;
	const char		*v6;

	v6 = NULL;
	it = NULL;
	while ((a = ucl_object_iterate(jget(o, "addresses"), &it, true)) !=
	    NULL) {
		if (jstr(a, "destination") == NULL)
			continue;
		if (strchr(jstr(a, "destination"), ':') == NULL)
			return (jstr(a, "destination"));
		if (v6 == NULL && strncmp(jstr(a, "destination"), "fe80", 4) != 0)
			v6 = jstr(a, "destination");
	}
	return (v6);
}

/* The monitor on this interface, in the scope shown, or NULL: over the
 * tunnel, or (underlay) under it, ul-<if> as the fleet's Overlay ›
 * Quality names it. */
static const ucl_object_t *
monitor_of(const char *ifname, bool underlay)
{
	const ucl_object_t	*m;
	ucl_object_iter_t	 it;
	const char		*j;

	it = NULL;
	while ((m = ucl_object_iterate(jget(mn.r.o, "monitors"), &it, true)) !=
	    NULL) {
		j = jstr(m, "jail") != NULL ? jstr(m, "jail") : "";
		if (strcmp(j, net_scope()) == 0 && jstr(m, "interface") != NULL &&
		    strcmp(jstr(m, "interface"), ifname) == 0 && jstr(m, "id") !=
		    NULL && (strncmp(jstr(m, "id"), "ul-", 3) == 0) == underlay)
			return (m);
	}
	return (NULL);
}

/* The last whole sample's metric, else the interval's so far. */
static double
metric(const ucl_object_t *m, int col, const char *now_key, bool *has)
{
	const ucl_object_t	*sm, *last;
	unsigned int		 n;

	sm = jget(m, "samples");
	n = sm != NULL ? ucl_array_size(sm) : 0;
	*has = true;
	if (n > 0) {
		last = ucl_array_find_index(sm, n - 1);
		return (ucl_object_todouble(ucl_array_find_index(last, col)));
	}
	if (jint(m, "now.recv", 0) > 0 || (col == 3 && jint(m, "now.sent", 0) >
	    0))
		return (ucl_object_todouble(jget(m, now_key)));
	*has = false;
	return (0);
}

static void
ms_td(struct html *h, double v, bool has, double threshold)
{

	if (!has) {
		h_raw(h, "<td class=\"num dim\">–</td>");
		return;
	}
	h_fmt(h, "<td class=\"num%s\">%.*f ms</td>", threshold > 0 && v >
	    threshold ? " over" : "", v >= 100 ? 0 : v >= 10 ? 1 : 2, v);
}

/* One monitored tunnel's row; a monitor left without its interface
 * gets one too, by its own name. */
static void
monitor_row(struct html *h, const char *ifname, const ucl_object_t *m)
{
	const char	*st;
	double		 v;
	bool		 has;

	st = jstr(m, "state") != NULL ? jstr(m, "state") : "unknown";
	h_raw(h, "<tr class=\"mon\"><td><b>");
	h_txt(h, ifname);
	h_raw(h, "</b>");
	if (jstr(m, "id") != NULL && strcmp(jstr(m, "id"), ifname) != 0) {
		h_raw(h, "<small>");
		h_txt(h, jstr(m, "id"));
		h_raw(h, "</small>");
	}
	h_raw(h, "</td><td><code>");
	h_txt(h, jstr(m, "address"));
	h_raw(h, "</code>");
	if (jint(m, "fib", 0) > 0)
		h_fmt(h, "<small>fib %lld</small>", (long long)jint(m, "fib", 0));
	h_fmt(h, "</td><td><span class=\"chip st-%s\"", strcmp(st, "up") == 0 ?
	    "up" : strcmp(st,
	    "down") == 0 || strcmp(st, "error") == 0 ? "down" : "unknown");
	if (jstr(m, "error") != NULL)
		h_attr(h, "title", jstr(m, "error"));
	h_raw(h, ">");
	h_txt(h, st);
	h_raw(h, "</span>");
	if (jstr(m, "error") != NULL) {
		h_raw(h, "<small class=\"dim\">");
		h_txt(h, jstr(m, "error"));
		h_raw(h, "</small>");
	}
	h_raw(h, "</td>");
	v = metric(m, 1, "now.delay", &has);
	ms_td(h, v, has, ucl_object_todouble(jget(m, "tca.delay")));
	v = metric(m, 2, "now.ipdv", &has);
	ms_td(h, v, has, ucl_object_todouble(jget(m, "tca.ipdv")));
	v = metric(m, 3, "now.loss", &has);
	if (has)
		h_fmt(h, "<td class=\"num%s\">%.1f %%</td>", jget(m, "tca.loss") !=
		    NULL && ucl_object_todouble(jget(m, "tca.loss")) > 0 && v >
		    ucl_object_todouble(jget(m, "tca.loss")) ? " over" : "", v *
		    100);
	else
		h_raw(h, "<td class=\"num dim\">–</td>");
	h_raw(h, "<td>");
	probe_spark(h, jget(m, "samples"));
	h_raw(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
	    "data-act=\"mon-edit\" title=\"Change how it is measured\"");
	h_attr(h, "data-arg", jstr(m, "id"));
	h_raw(h, ">Change</button> <button class=\"ghost small\" "
	    "data-act=\"mon-remove\" title=\"No longer measured\"");
	h_attr(h, "data-arg", jstr(m, "id"));
	h_raw(h, ">Stop</button></td></tr>");
}

void
view_monitors(struct html *h, struct server *s, const ucl_object_t *ifaces)
{
	const ucl_object_t	*o, *m;
	ucl_object_iter_t	 it;
	const char		*name, *far;
	int			 tunnels;

	if (!res_shown(h, &mn.r, s->id, mn_load, "mon-retry"))
		return;
	if (mn.fetched == 0)
		mn.fetched = arc_now();
	h_raw(h, "<p class=\"dim mon-about\">Each tunnel's far end probed by "
	    "ICMP echo through its routing table, outside SD-WAN: the "
	    "one-way delay (half the round trip), its variation from one "
	    "answer to the next, and the share lost, per sample. Read again "
	    "every few seconds.</p>");
	if (jget(mn.r.o, "probing") != NULL && !jbool(mn.r.o, "probing"))
		h_raw(h, "<div class=\"notice warn\">The agent's prober is not "
		    "running: it needs root to probe.</div>");
	h_raw(h, "<table class=\"tbl net mon\"><thead><tr><th>Tunnel</th><th>"
	    "Far end</th><th>State</th><th class=\"num\">Delay</th><th "
	    "class=\"num\" title=\"The mean difference between one answer's "
	    "delay and the next's\">Variation</th><th class=\"num\">Loss</th>"
	    "<th>Trend</th><th></th></tr></thead><tbody>");
	tunnels = 0;
	it = NULL;
	while ((o = ucl_object_iterate(ifaces, &it, true)) != NULL) {
		if ((name = jstr(o, "name")) == NULL || !is_tunnel(o))
			continue;
		if (app.filter[0] != '\0' && strstr(name, app.filter) == NULL)
			continue;
		tunnels++;
		if ((m = monitor_of(name, false)) != NULL) {
			monitor_row(h, name, m);
			/* Its underlay too, where measured. */
			if ((m = monitor_of(name, true)) != NULL)
				monitor_row(h, name, m);
			continue;
		}
		far = far_end(o);
		h_raw(h, "<tr class=\"mon off\"><td><b>");
		h_txt(h, name);
		h_raw(h, "</b>");
		if (jstr(o, "tunnel.remote") != NULL) {
			h_raw(h, "<small>over ");
			h_txt(h, jstr(o, "tunnel.remote"));
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td>");
		if (far != NULL) {
			h_raw(h, "<code>");
			h_txt(h, far);
			h_raw(h, "</code>");
		} else
			h_raw(h, "<span class=\"dim\">to be given</span>");
		h_raw(h, "</td><td colspan=\"5\" class=\"dim\">Not measured</td>"
		    "<td class=\"acts\"><button class=\"small\" data-act=\""
		    "mon-add\"");
		h_attr(h, "data-arg", name);
		h_fmt(h, " data-value=\"%s %lld\">Measure</button></td></tr>",
		    far != NULL ? far : "-", (long long)jint(o, "fib", 0));
	}
	/* Monitors whose interface is gone, or that name none. */
	it = NULL;
	while ((m = ucl_object_iterate(jget(mn.r.o, "monitors"), &it, true)) !=
	    NULL) {
		const ucl_object_t	*io;
		ucl_object_iter_t	 iit;
		bool			 seen = false;
		const char		*j = jstr(m, "jail") != NULL ? jstr(m,
					    "jail") : "";

		if (strcmp(j, net_scope()) != 0)
			continue;
		iit = NULL;
		while (jstr(m, "interface") != NULL && (io = ucl_object_iterate(
		    ifaces, &iit, true)) != NULL)
			if (jstr(io, "name") != NULL && strcmp(jstr(io, "name"),
			    jstr(m, "interface")) == 0 && is_tunnel(io))
				seen = true;
		if (!seen) {
			tunnels++;
			monitor_row(h, jstr(m, "interface") != NULL ? jstr(m,
			    "interface") : jstr(m, "id"), m);
		}
	}
	if (tunnels == 0)
		h_raw(h, "<tr class=\"empty-row\"><td colspan=\"8\">No tunnel "
		    "here: gre, gif, WireGuard, IPsec or another with a far "
		    "end.</td></tr>");
	h_raw(h, "</tbody></table>");
	h_raw(h, "<p class=\"freebsd-note dim\">FreeBSD: a raw ICMP socket "
	    "set to the tunnel's routing table (SO_SETFIB), its DSCP by "
	    "IP_TOS or IPV6_TCLASS; a tunnel down or up again, or a metric "
	    "over its threshold, is an event workflows can begin on.</p>");
}

/* The measuring dialog: a new monitor on a tunnel, or one changed. */
bool
monitor_modal(struct html *h)
{
	const ucl_object_t	*m, *it_m;
	ucl_object_iter_t	 it;
	char			 buf[32];

	m = NULL;
	it = NULL;
	while (mn.edit[0] != '\0' && (it_m = ucl_object_iterate(jget(mn.r.o,
	    "monitors"), &it, true)) != NULL)
		if (jstr(it_m, "id") != NULL && strcmp(jstr(it_m, "id"),
		    mn.edit) == 0)
			m = it_m;
	h_raw(h, "<form data-form=\"mon-set\"><h2>");
	h_txt(h, m != NULL ? "How it is measured" : "Measure the tunnel");
	h_raw(h, "</h2><p>Its far end probed by ICMP echo through its routing "
	    "table, a sample of each interval kept: the delay, its variation "
	    "and the loss. A threshold crossed, or the tunnel down, is an "
	    "event.</p><div class=\"two\"><label>Name<input name=\"name\" "
	    "required maxlength=\"63\" spellcheck=\"false\" autocomplete=\"off\"");
	h_attr(h, "value", m != NULL ? jstr(m, "id") : mn.ifname);
	if (m != NULL)
		h_raw(h, " readonly");
	h_raw(h, "></label><label>Tunnel<input name=\"interface\" "
	    "spellcheck=\"false\" autocomplete=\"off\"");
	h_attr(h, "value", m != NULL && jstr(m, "interface") != NULL ? jstr(m,
	    "interface") : mn.ifname);
	h_raw(h, "></label></div><div class=\"two\"><label>Far end<input "
	    "name=\"address\" required spellcheck=\"false\" autocomplete="
	    "\"off\" placeholder=\"10.0.0.2\"");
	h_attr(h, "value", m != NULL ? jstr(m, "address") : mn.address);
	h_raw(h, "><small>The tunnel's inner address at the other end: a "
	    "WireGuard peer's, typed.</small></label><label>Routing table "
	    "(FIB)<input name=\"fib\" inputmode=\"numeric\"");
	snprintf(buf, sizeof(buf), "%lld", m != NULL ? (long long)jint(m,
	    "fib", 0) : (long long)mn.fib);
	h_attr(h, "value", buf);
	h_raw(h, "></label></div><div class=\"two\"><label>Every (ms)<input "
	    "name=\"interval\" inputmode=\"numeric\"");
	snprintf(buf, sizeof(buf), "%lld", m != NULL ? (long long)jint(m,
	    "interval", 500) : 500LL);
	h_attr(h, "value", buf);
	h_raw(h, "></label><label>A sample of (ms)<input name=\"eval\" "
	    "inputmode=\"numeric\"");
	snprintf(buf, sizeof(buf), "%lld", m != NULL ? (long long)jint(m,
	    "eval", 10000) : 10000LL);
	h_attr(h, "value", buf);
	h_raw(h, "></label></div><div class=\"two\"><label>Size (bytes)<input "
	    "name=\"size\" inputmode=\"numeric\"");
	snprintf(buf, sizeof(buf), "%lld", m != NULL ? (long long)jint(m,
	    "size", 64) : 64LL);
	h_attr(h, "value", buf);
	h_raw(h, "></label><label>DSCP<input name=\"dscp\" inputmode=\""
	    "numeric\"");
	snprintf(buf, sizeof(buf), "%lld", m != NULL ? (long long)jint(m,
	    "dscp", 0) : 0LL);
	h_attr(h, "value", buf);
	h_raw(h, "></label></div><fieldset><legend>Thresholds, empty for none"
	    "</legend><div class=\"three\"><label>Delay over (ms)<input name="
	    "\"delay-max\" inputmode=\"decimal\"");
	if (m != NULL && ucl_object_todouble(jget(m, "tca.delay")) > 0) {
		snprintf(buf, sizeof(buf), "%g", ucl_object_todouble(jget(m,
		    "tca.delay")));
		h_attr(h, "value", buf);
	}
	h_raw(h, "></label><label>Variation over (ms)<input name=\"ipdv-max\" "
	    "inputmode=\"decimal\"");
	if (m != NULL && ucl_object_todouble(jget(m, "tca.ipdv")) > 0) {
		snprintf(buf, sizeof(buf), "%g", ucl_object_todouble(jget(m,
		    "tca.ipdv")));
		h_attr(h, "value", buf);
	}
	h_raw(h, "></label><label>Loss over (%)<input name=\"loss-max\" "
	    "inputmode=\"decimal\"");
	if (m != NULL && ucl_object_todouble(jget(m, "tca.loss")) > 0) {
		snprintf(buf, sizeof(buf), "%g", ucl_object_todouble(jget(m,
		    "tca.loss")) * 100);
		h_attr(h, "value", buf);
	}
	h_raw(h, "></label></div></fieldset>");
	return (true);
}

static void
mon_send(struct server *s, const char *verb, const char *const *w, size_t n,
    const char *title)
{
	char	*json, extra[96], *q;

	extra[0] = '\0';
	if (net_scope()[0] != '\0') {
		q = json_quote(net_scope());
		snprintf(extra, sizeof(extra), ",\"jail\":%s", q);
		free(q);
	}
	json = job_json("monitor", verb, w, n, NULL, extra[0] != '\0' ? extra :
	    NULL);
	job_send(s, json, title, JOB_MONITOR, net_scope()[0] != '\0' ?
	    net_scope() : s->name);
}

bool
monitor_form(const char *form, const ucl_object_t *f)
{
	static const char *const keys[] = { "name", "interface", "address",
	    "fib", "interval", "eval", "size", "dscp", "delay-max", "ipdv-max",
	    "loss-max" };
	struct server	*s;
	const char	*w[16];
	char		 buf[16][128], title[160];
	size_t		 i, n;

	if (strcmp(form, "mon-set") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	n = 0;
	for (i = 0; i < nitems(keys); i++) {
		if (jstr(f, keys[i]) == NULL || jstr(f, keys[i])[0] == '\0')
			continue;
		snprintf(buf[n], sizeof(buf[n]), "%s=%s", keys[i], jstr(f,
		    keys[i]));
		w[n] = buf[n];
		n++;
	}
	snprintf(title, sizeof(title), "monitor set %s", jstr(f, "name") !=
	    NULL ? jstr(f, "name") : "");
	mon_send(s, "set", w, n, title);
	app.modal = MODAL_NONE;
	return (true);
}

bool
monitor_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	const char	*w[1];
	char		 word[96], title[120], body[300];

	if (strncmp(act, "mon-", 4) != 0)
		return (false);
	if (strcmp(act, "mon-retry") == 0) {
		res_drop(&mn.r);
		render();
		return (true);
	}
	if ((s = cur_server()) == NULL || arg == NULL)
		return (true);
	if (strcmp(act, "mon-add") == 0) {
		/* value: the far end ("-" for none) and the table. */
		mn.edit[0] = '\0';
		snprintf(mn.ifname, sizeof(mn.ifname), "%s", arg);
		mn.address[0] = '\0';
		mn.fib = 0;
		if (value != NULL) {
			if (sscanf(value, "%63s %d", mn.address, &mn.fib) < 1 ||
			    strcmp(mn.address, "-") == 0)
				mn.address[0] = '\0';
		}
		app.modal = MODAL_MONITOR;
		app.modal_error[0] = '\0';
		return (true);
	}
	if (strcmp(act, "mon-edit") == 0) {
		snprintf(mn.edit, sizeof(mn.edit), "%s", arg);
		app.modal = MODAL_MONITOR;
		app.modal_error[0] = '\0';
		return (true);
	}
	if (strcmp(act, "mon-remove") == 0) {
		snprintf(body, sizeof(body), "The tunnel's monitor %s stops: its "
		    "samples are gone with it. The tunnel itself is not touched.",
		    arg);
		confirm("Stop measuring?", body, "Stop", true, "",
		    "mon-do-remove", arg, "");
		return (true);
	}
	if (strcmp(act, "mon-do-remove") == 0) {
		snprintf(word, sizeof(word), "name=%s", arg);
		w[0] = word;
		snprintf(title, sizeof(title), "monitor remove %s", arg);
		mon_send(s, "remove", w, 1, title);
		return (true);
	}
	return (false);
}
