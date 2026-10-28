/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * A host's FEC relay tab: UDPspeeder (net/udpspeeder, a plugin), run by
 * Arcana's own rc script, arcana_relay, one relay or several (each a
 * profile), as the agent's speeder read has it: how each is set, the
 * redundant packets it adds for each group size, and what the FEC costs
 * each way, measured from the relay's own --report lines.  Its flags
 * from a form, its ratios changed while it runs (by its fifo, the tunnel
 * kept), started, stopped, enabled.  Each change is a job, in safe mode
 * on the host: a relay often carries the tunnel the console reaches the
 * host by, and a change it cannot answer after is undone.  The admin's
 * own relay, run by the port's rc script (speederv2), is shown as read,
 * never changed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	FIFO_DEFAULT	"/var/run/arcana_relay/fifo"
#define	RELAY_TICK_MS	5000
#define	CMP_SAMPLES	30		/* the last samples a comparison averages */
#define	CMP_RAW		"fec-raw"	/* the monitor without FEC: the underlay */
#define	CMP_TUN		"fec-tunnel"	/* the monitor with it: the tunnel */

static struct {
	struct res	 r;		/* the speeder read */
	struct res	 m;		/* the monitors read: the comparison */
	double		 fetched;
	bool		 compare;	/* the comparison's form open */
	bool		 conf;		/* the flags' form open */
	bool		 picked;	/* where, chosen by hand: jail */
	char		 jail[64];	/* "" the host */
	char		 prof[40];	/* the relay picked: a profile, "" the
					 * plain one (arcana_relay_flags) */
	char		 shown[40];	/* the one shown, and its jobs': the
					 * pick while the read has it */
	bool		 port;		/* the admin's relay picked, the port's
					 * rc script's: read alone */
	bool		 adding;	/* a new profile's form open */
} rl;

/* Read again at the next draw. */
void
relay_refresh(void)
{

	res_drop(&rl.r);
	res_drop(&rl.m);
}

static void
rl_load_monitors(const char *sid)
{
	char	url[96];

	snprintf(url, sizeof(url), "/api/servers/%s/monitors", sid);
	res_load(&rl.m, sid, url);
}

static void rl_load(const char *);

/* While shown, both read again every few seconds, the last kept. */
void
relay_tick(double now)
{
	struct server	*s;

	if (!app.visible || app.node != NODE_HOST || app.tab != TAB_RELAY ||
	    rl.r.loading || rl.r.o == NULL || now - rl.fetched <
	    RELAY_TICK_MS || (s = cur_server()) == NULL)
		return;
	rl.fetched = now;
	rl_load(s->id);
	rl_load_monitors(s->id);
}

/* Where the relay is looked for: picked here, else where the host says
 * the plugin is, else the host. */
static const char *
rl_where(struct server *s)
{
	const char	*at;

	if (rl.picked)
		return (rl.jail);
	at = plugin_anywhere(s, "speederv2");
	return (at != NULL ? at : "");
}

static void
rl_load(const char *sid)
{
	struct server	*s;
	char		 url[128], q[80];

	if (strcmp(sid, rl.r.sid) != 0)
		rl.picked = false;
	q[0] = '\0';
	if ((s = cur_server()) != NULL && rl_where(s)[0] != '\0')
		snprintf(q, sizeof(q), "?jail=%s", rl_where(s));
	snprintf(url, sizeof(url), "/api/servers/%s/speeder%s", sid, q);
	res_load(&rl.r, sid, url);
}

/*
 * A job's extra: the jail it is done in; on the host, safe mode, so a
 * change that cuts the console's own way to the host is undone.
 */
static const char *
rl_extra(struct server *s)
{
	static char	 extra[120];
	char		*q;

	if (rl_where(s)[0] == '\0')
		return (",\"safe\":true");
	q = json_quote(rl_where(s));
	snprintf(extra, sizeof(extra), ",\"jail\":%s", q);
	free(q);
	return (extra);
}

/* A relay job; for one of several, its profile= added (not to enable and
 * disable, which are every relay's). */
static void
rl_send(struct server *s, const char *verb, const char *const *words,
    size_t n, const char *title)
{
	const char	*w[20];
	char		*json, pw[64];
	size_t		 i;

	if (rl.shown[0] != '\0' && strcmp(verb, "enable") != 0 && strcmp(verb,
	    "disable") != 0 && n < nitems(w)) {
		for (i = 0; i < n; i++)
			w[i] = words[i];
		snprintf(pw, sizeof(pw), "profile=%s", rl.shown);
		w[n++] = pw;
		words = w;
	}
	json = job_json("speeder", verb, words, n, NULL, rl_extra(s));
	job_send(s, json, title, JOB_RELAY, rl_where(s)[0] != '\0' ?
	    rl_where(s) : s->name);
}

/* Its package being installed where the tab looks. */
static bool
rl_installing(const struct server *s, const char *jail)
{
	const struct op	*o;
	int		 i;

	for (i = 0; i < app.nops; i++) {
		o = &app.ops[i];
		if (o->state == OP_RUNNING && o->what == JOB_RELAY && strcmp(
		    o->sid, s->id) == 0 && strcmp(o->target, jail) == 0 &&
		    strncmp(o->title, "pkg install ", 12) == 0)
			return (true);
	}
	return (false);
}

/* A monitor job, where the relay is: the comparison's. */
static void
rl_monitor_send(struct server *s, const char *verb, const char *const *w,
    size_t n, const char *title)
{
	char	*json, extra[96], *q;

	extra[0] = '\0';
	if (rl_where(s)[0] != '\0') {
		q = json_quote(rl_where(s));
		snprintf(extra, sizeof(extra), ",\"jail\":%s", q);
		free(q);
	}
	json = job_json("monitor", verb, w, n, NULL, extra[0] != '\0' ? extra :
	    NULL);
	job_send(s, json, title, JOB_RELAY, rl_where(s)[0] != '\0' ?
	    rl_where(s) : s->name);
}

static void
chip(struct html *h, bool on, const char *yes, const char *no)
{

	h_fmt(h, "<span class=\"chip %s\">%s</span> ", on ? "st-up" : "st-down",
	    on ? yes : no);
}

/* A term and its value in the settings list, when it has one. */
static void
dt(struct html *h, const char *term, const char *value)
{

	if (value == NULL || value[0] == '\0')
		return;
	h_raw(h, "<dt>");
	h_txt(h, term);
	h_raw(h, "</dt><dd>");
	h_txt(h, value);
	h_raw(h, "</dd>");
}

static void
dt_int(struct html *h, const char *term, const ucl_object_t *o,
    const char *key, const char *unit)
{
	char	buf[64];

	if (jget(o, key) == NULL)
		return;
	snprintf(buf, sizeof(buf), "%lld%s", (long long)jint(o, key, 0), unit);
	dt(h, term, buf);
}

/* A per cent, or a dash. */
static void
pct(struct html *h, const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	if ((v = jget(o, key)) == NULL) {
		h_raw(h, "<td class=\"num dim\">–</td>");
		return;
	}
	h_fmt(h, "<td class=\"num\">%.1f %%</td>", ucl_object_todouble(v));
}

static void
bytes_td(struct html *h, const ucl_object_t *o, const char *key,
    const char *suffix)
{
	const ucl_object_t	*v;
	char			 buf[32];

	if ((v = jget(o, key)) == NULL) {
		h_raw(h, "<td class=\"num dim\">–</td>");
		return;
	}
	fmt_bytes(buf, sizeof(buf), (int64_t)ucl_object_todouble(v));
	h_fmt(h, "<td class=\"num\">%s%s</td>", buf, suffix);
}

/* Each way: what went in plain, out with FEC, and what that cost. */
static void
report_table(struct html *h, const ucl_object_t *rep)
{
	static const struct {
		const char	*key, *title;
	} ways[] = {
		{ "client_to_server", "To the server" },
		{ "server_to_client", "To the client" },
	};
	const ucl_object_t	*w;
	size_t			 i;

	h_raw(h, "<table class=\"tbl relay-report\"><thead><tr><th>Way</th>"
	    "<th class=\"num\">Plain</th><th class=\"num\">With FEC</th>"
	    "<th class=\"num\">Overhead</th><th class=\"num\" title=\""
	    "Over the last interval\">Lately</th><th class=\"num\" title=\""
	    "Plain bytes a second, lately\">Rate</th><th></th></tr></thead>"
	    "<tbody>");
	for (i = 0; i < nitems(ways); i++) {
		w = jget(rep, ways[i].key);
		h_fmt(h, "<tr><td>%s</td>", ways[i].title);
		bytes_td(h, w, "plain_bytes", "");
		bytes_td(h, w, "fec_bytes", "");
		pct(h, w, "overhead");
		pct(h, w, "overhead_now");
		bytes_td(h, w, "plain_rate", "/s");
		h_raw(h, "<td></td></tr>");
	}
	h_raw(h, "</tbody></table>");
	if (jget(rep, "interval") != NULL)
		h_fmt(h, "<p class=\"dim\">Counted by the relay since it "
		    "started; Lately and the rate are of its last %lld s "
		    "between two reports.</p>", (long long)jint(rep, "interval",
		    0));
}

/* For each group size: the redundant packets, and what they cost. */
static void
groups_table(struct html *h, const ucl_object_t *groups)
{
	const ucl_object_t	*g;
	ucl_object_iter_t	 it;
	long long		 x, y;

	h_raw(h, "<table class=\"tbl relay-groups\"><thead><tr><th class=\""
	    "num\">Group of</th><th class=\"num\">Redundant</th><th class=\""
	    "num\">More packets</th><th></th></tr></thead><tbody>");
	it = NULL;
	while ((g = ucl_object_iterate(groups, &it, true)) != NULL) {
		x = (long long)ucl_object_toint(ucl_array_find_index(g, 0));
		y = (long long)ucl_object_toint(ucl_array_find_index(g, 1));
		h_fmt(h, "<tr><td class=\"num\">%lld</td><td class=\"num\">%lld"
		    "</td><td class=\"num\">+%lld %%</td><td></td></tr>", x, y, x > 0 ?
		    y * 100 / x : 0);
	}
	h_raw(h, "</tbody></table>");
}

static void
input(struct html *h, const char *label, const char *name, const char *value,
    const char *placeholder, const char *help)
{

	h_raw(h, "<label>");
	h_txt(h, label);
	h_raw(h, "<input");
	h_attr(h, "name", name);
	h_attr(h, "value", value != NULL ? value : "");
	if (placeholder != NULL)
		h_attr(h, "placeholder", placeholder);
	h_raw(h, " spellcheck=\"false\" autocomplete=\"off\">");
	if (help != NULL) {
		h_raw(h, "<small>");
		h_txt(h, help);
		h_raw(h, "</small>");
	}
	h_raw(h, "</label>");
}

/* The flags' form, filled from what is set; a new relay's with its name. */
static void
conf_form(struct html *h, const ucl_object_t *o)
{
	char	num[32], fifo[96];
	bool	server;

	server = jstr(o, "role") != NULL && strcmp(jstr(o, "role"), "server") ==
	    0;
	h_raw(h, "<form data-form=\"rl-conf\" class=\"set-form relay-conf\">"
	    "<h3>");
	h_txt(h, rl.adding ? "Another relay" : "The relay's flags");
	h_raw(h, "</h3><p class=\"dim\">Written to <code>");
	if (rl.adding)
		h_raw(h, "arcana_relay_&lt;name&gt;_flags</code>, the name added "
		    "to <code>arcana_relay_profiles");
	else if (rl.shown[0] != '\0') {
		h_raw(h, "arcana_relay_");
		h_txt(h, rl.shown);
		h_raw(h, "_flags");
	} else
		h_raw(h, "arcana_relay_flags");
	h_raw(h, "</code> in rc.conf, each word checked; the relay restarted "
	    "when it runs. Both ends need the same mode, key and ratios' "
	    "scheme.</p>");
	if (rl.adding)
		h_raw(h, "<label>Name<input name=\"profile\" required "
		    "pattern=\"[A-Za-z0-9_]{1,32}\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"lte\"><small>Letters, "
		    "digits and _: a profile of Arcana's rc script, run under "
		    "rc.subr's name arcana_relay_&lt;name&gt;, its syslog tag "
		    "and its variables' prefix.</small></label>");
	h_raw(h, "<div class=\"two\"><label>Role<select name=\"role\">");
	h_fmt(h, "<option value=\"client\"%s>client: takes plain packets, "
	    "sends them with FEC</option><option value=\"server\"%s>server: "
	    "takes FEC, gives back plain</option></select></label>", server ?
	    "" : " selected", server ? " selected" : "");
	h_fmt(h, "<label>Mode<select name=\"mode\"><option value=\"\">0, the "
	    "relay's default</option><option value=\"0\"%s>0: less bandwidth, "
	    "packets split to fit</option><option value=\"1\"%s>1: less "
	    "latency, packets kept whole</option></select></label></div>",
	    jint(o, "mode", -1) == 0 ? " selected" : "", jint(o, "mode", -1) ==
	    1 ? " selected" : "");
	h_raw(h, "<div class=\"two\">");
	input(h, "Listen", "listen", jstr(o, "listen"), "127.0.0.1:51821",
	    "Where it takes packets: a client, from the tunnel (WireGuard's "
	    "endpoint); a server, from the far relay.");
	input(h, "Remote", "remote", jstr(o, "remote"), "192.0.2.1:14350",
	    "Where it sends them: a client, to the far relay; a server, to "
	    "the tunnel's own port.");
	h_raw(h, "</div><div class=\"two\">");
	input(h, "Ratios (FEC)", "fec", jstr(o, "fec"), "20:10",
	    "x:y adds y redundant packets for every x; 1:2,2:3,8:4,20:10 "
	    "sets them by group size.");
	snprintf(num, sizeof(num), "%lld", (long long)jint(o, "mtu", 0));
	input(h, "MTU", "mtu", jget(o, "mtu") != NULL ? num : NULL, "1250",
	    "Mode 0 splits to fit it; mode 1 checks packets against it.");
	h_raw(h, "</div><div class=\"two\">");
	snprintf(num, sizeof(num), "%lld", (long long)jint(o, "timeout", 0));
	input(h, "Timeout (ms)", "timeout", jget(o, "timeout") != NULL ? num :
	    NULL, "8", "How long a packet waits for its group.");
	snprintf(num, sizeof(num), "%lld", (long long)jint(o, "report_every", 10));
	input(h, "Report every (s)", "report", num, "10",
	    "Its counters, logged: what this tab measures the overhead by. "
	    "0 for none.");
	h_raw(h, "</div><div class=\"two\">");
	/* Its own fifo under the rc script's directory: the plain relay's
	 * fifo, a profile's <name>.fifo. */
	if (rl.shown[0] != '\0')
		snprintf(fifo, sizeof(fifo), "/var/run/arcana_relay/%s.fifo",
		    rl.shown);
	else
		snprintf(fifo, sizeof(fifo), "%s", FIFO_DEFAULT);
	input(h, "Fifo", "fifo", jstr(o, "flags") != NULL ? jstr(o, "fifo") :
	    rl.adding ? "" : fifo, rl.adding ? "/var/run/arcana_relay/<name>.fifo"
	    : fifo, "The ratios are changed through it while the relay runs, "
	    "the tunnel kept up. Empty for none.");
	h_fmt(h, "<label>Key<input type=\"password\" name=\"key\" "
	    "autocomplete=\"off\" placeholder=\"%s\"><small>A simple XOR, the "
	    "same at both ends; kept in rc.conf, never shown here.</small>"
	    "</label></div>", jbool(o, "key") ? "kept as it is" : "none");
	if (jbool(o, "key"))
		h_raw(h, "<label class=\"toggle\"><input type=\"checkbox\" "
		    "name=\"nokey\"><span>Take the key away</span></label>");
	input(h, "More options", "extra", jstr(o, "extra"), "--sock-buf 2048",
	    "speederv2's own, passed on: --jitter, --interval, --queue-len, "
	    "--sock-buf, --out-addr, --log-level and the like.");
	/* rc.subr's service jail: the relay held to its addresses. */
	h_fmt(h, "<div class=\"two\"><label class=\"toggle\"><input type=\""
	    "checkbox\" name=\"svcj\"%s><span>In a service jail of its own"
	    "</span><small>rc.subr(8)'s <code>_svcj</code>: a jail of the "
	    "host's root, its sockets held to the addresses beside "
	    "(<code>net_basic</code>, or the options already set).</small>"
	    "</label>", jbool(o, "svcj") ? " checked" : "");
	{
		char	ips[200], *p;

		snprintf(ips, sizeof(ips), "%s", jstr(o, "svcj_ipaddrs") !=
		    NULL ? jstr(o, "svcj_ipaddrs") : "");
		for (p = ips; *p != '\0'; p++)
			if (*p == ' ')
				*p = ',';
		input(h, "Its addresses", "svcj_ipaddrs", ips,
		    "192.0.2.2,127.0.0.1", "_svcj_ipaddrs, by commas: those it "
		    "listens at and sends from. Empty: all of the host's.");
	}
	h_raw(h, "</div><div class=\"actions\">");
	if (jstr(o, "flags") != NULL || rl.adding)
		h_fmt(h, "<button type=\"button\" class=\"ghost\" data-act=\""
		    "%s\">Cancel</button>", rl.adding ? "rl-add" : "rl-conf");
	h_raw(h, "<button class=\"primary\">Write the flags</button></div>"
	    "</form>");
}

/* The comparison's monitor by its name, where the relay is. */
static const ucl_object_t *
cmp_monitor(struct server *s, const char *name)
{
	const ucl_object_t	*m;
	ucl_object_iter_t	 it;
	const char		*j;

	it = NULL;
	while ((m = ucl_object_iterate(jget(rl.m.o, "monitors"), &it, true)) !=
	    NULL) {
		j = jstr(m, "jail") != NULL ? jstr(m, "jail") : "";
		if (strcmp(j, rl_where(s)) == 0 && jstr(m, "id") != NULL &&
		    strcmp(jstr(m, "id"), name) == 0)
			return (m);
	}
	return (NULL);
}

/* A monitor's last samples, averaged: delay, variation, loss; false
 * with none answered yet. */
static bool
cmp_means(const ucl_object_t *m, double *delay, double *ipdv, double *loss)
{
	const ucl_object_t	*sm, *row;
	unsigned int		 n, from, i;
	double			 sd, si, sent, recv;
	int			 k;

	sm = m != NULL ? jget(m, "samples") : NULL;
	n = sm != NULL ? ucl_array_size(sm) : 0;
	from = n > CMP_SAMPLES ? n - CMP_SAMPLES : 0;
	sd = si = sent = recv = 0;
	k = 0;
	for (i = from; i < n; i++) {
		row = ucl_array_find_index(sm, i);
		sent += ucl_object_todouble(ucl_array_find_index(row, 6));
		recv += ucl_object_todouble(ucl_array_find_index(row, 7));
		if (ucl_object_todouble(ucl_array_find_index(row, 7)) > 0) {
			sd += ucl_object_todouble(ucl_array_find_index(row, 1));
			si += ucl_object_todouble(ucl_array_find_index(row, 2));
			k++;
		}
	}
	if (sent <= 0)
		return (false);
	*loss = (sent - recv) / sent;
	*delay = k > 0 ? sd / k : 0;
	*ipdv = k > 0 ? si / k : 0;
	return (true);
}

static void
cmp_cell(struct html *h, bool has, double v, const char *fmt)
{

	if (!has)
		h_raw(h, "<td class=\"num dim\">–</td>");
	else
		h_fmt(h, fmt, v);
}

/* Without FEC and with it, side by side, and what FEC changed. */
static void
compare_table(struct html *h, struct server *s, const ucl_object_t *o)
{
	const ucl_object_t	*raw, *tun;
	double			 rd, ri, rl_, td, ti, tl;
	bool			 hr, ht;

	raw = cmp_monitor(s, CMP_RAW);
	tun = cmp_monitor(s, CMP_TUN);
	hr = cmp_means(raw, &rd, &ri, &rl_);
	ht = cmp_means(tun, &td, &ti, &tl);
	h_raw(h, "<table class=\"tbl relay-compare\"><thead><tr><th></th>"
	    "<th class=\"num\" title=\"The underlay, straight to the far "
	    "relay's host\">Without FEC</th><th class=\"num\" title=\"Through "
	    "the tunnel the relay carries\">With FEC</th><th class=\"num\">"
	    "FEC's part</th><th></th></tr></thead><tbody><tr><td>Delay</td>");
	cmp_cell(h, hr, rd, "<td class=\"num\">%.2f ms</td>");
	cmp_cell(h, ht, td, "<td class=\"num\">%.2f ms</td>");
	cmp_cell(h, hr && ht, td - rd, "<td class=\"num\">%+.2f ms</td>");
	h_raw(h, "<td></td></tr><tr><td>Variation</td>");
	cmp_cell(h, hr, ri, "<td class=\"num\">%.2f ms</td>");
	cmp_cell(h, ht, ti, "<td class=\"num\">%.2f ms</td>");
	cmp_cell(h, hr && ht, ti - ri, "<td class=\"num\">%+.2f ms</td>");
	h_raw(h, "<td></td></tr><tr><td>Loss</td>");
	cmp_cell(h, hr, rl_ * 100, "<td class=\"num\">%.2f %%</td>");
	cmp_cell(h, ht, tl * 100, "<td class=\"num\">%.2f %%</td>");
	cmp_cell(h, hr && ht, (tl - rl_) * 100, "<td class=\"num\">%+.2f %%"
	    "</td>");
	h_raw(h, "<td></td></tr><tr><td>Overhead</td><td class=\"num dim\">"
	    "–</td>");
	cmp_cell(h, jget(o, "report.client_to_server.overhead_now") != NULL,
	    ucl_object_todouble(jget(o, "report.client_to_server.overhead_now")),
	    "<td class=\"num\">%.1f %%</td>");
	h_raw(h, "<td class=\"num dim\">to the server, lately</td><td></td>"
	    "</tr></tbody></table>");
	h_fmt(h, "<p class=\"dim\">Each the mean of its last %d samples: "
	    "without FEC, ICMP straight to <code>", CMP_SAMPLES);
	h_txt(h, raw != NULL ? jstr(raw, "address") : "?");
	h_raw(h, "</code>; with it, through the tunnel to <code>");
	h_txt(h, tun != NULL ? jstr(tun, "address") : "?");
	h_raw(h, "</code>. A network that filters may treat ICMP unlike the "
	    "relay's UDP: the underlay's figures are then its ICMP's. "
	    "<button class=\"ghost small\" data-act=\"rl-compare-stop\">"
	    "Stop comparing</button></p>");
}

/* The comparison's form: the tunnel's far end, the underlay's. */
static void
compare_form(struct html *h, const ucl_object_t *o)
{
	char		 host[80];
	const char	*r, *c;
	size_t		 n;

	host[0] = '\0';
	/* The far relay's host, from remote= (a client's). */
	if ((r = jstr(o, "remote")) != NULL && jstr(o, "role") != NULL &&
	    strcmp(jstr(o, "role"), "client") == 0 && (c = strrchr(r, ':')) !=
	    NULL) {
		n = (size_t)(c - r);
		if (r[0] == '[' && n >= 2)
			snprintf(host, sizeof(host), "%.*s", (int)(n - 2), r + 1);
		else
			snprintf(host, sizeof(host), "%.*s", (int)n, r);
	}
	h_raw(h, "<form data-form=\"rl-compare\" class=\"set-form\"><h3>"
	    "Measure what FEC does</h3><p class=\"dim\">Two monitors, probed "
	    "side by side: one straight over the underlay to the far relay's "
	    "host, one through the tunnel the relay carries. Their loss, "
	    "delay and variation, compared.</p><div class=\"two\"><label>"
	    "Tunnel's far end<input name=\"tunnel\" required spellcheck="
	    "\"false\" autocomplete=\"off\" placeholder=\"10.0.0.2\"><small>"
	    "An address at the other end of the tunnel over the relay."
	    "</small></label><label>Tunnel interface<input name=\"interface\" "
	    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\"wg0\">"
	    "<small>Its table is the tunnel's.</small></label></div><div "
	    "class=\"two\"><label>Underlay to the far relay<input name="
	    "\"raw\" required spellcheck=\"false\" autocomplete=\"off\"");
	h_attr(h, "value", host);
	h_raw(h, " placeholder=\"192.0.2.1\"><small>The far relay's host, "
	    "reached as the relay reaches it.</small></label><label>Its "
	    "routing table<input name=\"fib\" inputmode=\"numeric\" value="
	    "\"0\"><small>The relay's own: 0 unless it runs in another."
	    "</small></label></div><div class=\"actions\"><button type=\"button\" "
	    "class=\"ghost\" data-act=\"rl-compare\">Cancel</button><button "
	    "class=\"primary\">Compare</button></div></form>");
}

/* The overhead each way over the intervals the log has, as lines. */
static void
series_chart(struct html *h, const ucl_object_t *series)
{
	const ucl_object_t	*row;
	unsigned int		 n, i;
	double			 max, v;
	int			 way;

	n = series != NULL ? ucl_array_size(series) : 0;
	if (n < 2)
		return;
	max = 10;
	for (i = 0; i < n; i++) {
		row = ucl_array_find_index(series, i);
		for (way = 1; way <= 2; way++)
			if ((v = ucl_object_todouble(ucl_array_find_index(row,
			    way))) > max)
				max = v;
	}
	h_fmt(h, "<figure class=\"relay-series\"><svg viewBox=\"0 0 %u 60\" "
	    "preserveAspectRatio=\"none\" role=\"img\" aria-label=\"The FEC's "
	    "overhead each way over the last %u intervals\">", n - 1, n);
	for (way = 1; way <= 2; way++) {
		h_fmt(h, "<path class=\"w%d\" d=\"", way);
		for (i = 0; i < n; i++) {
			row = ucl_array_find_index(series, i);
			v = ucl_object_todouble(ucl_array_find_index(row, way));
			if (v < 0)
				v = 0;
			h_fmt(h, "%c%u %.1f ", i == 0 ? 'M' : 'L', i, 58 - v /
			    max * 56);
		}
		h_raw(h, "\"/>");
	}
	h_fmt(h, "</svg><figcaption class=\"dim\"><span class=\"w1\">— to the "
	    "server</span> <span class=\"w2\">— to the client</span>, the "
	    "overhead of each of the last %u intervals, up to %.0f %%"
	    "</figcaption></figure>", n, max);
}

/*
 * The relay shown: the admin's when picked and read, else the profile
 * picked, else the first profile when there are some and
 * arcana_relay_flags is not set, else the plain one (o).
 */
static const ucl_object_t *
rl_relay(const ucl_object_t *o)
{
	const ucl_object_t	*p, *first;
	ucl_object_iter_t	 it;

	if (rl.port && jget(o, "speederv2") != NULL) {
		rl.shown[0] = '\0';
		return (jget(o, "speederv2"));
	}
	rl.port = false;
	first = NULL;
	it = NULL;
	while ((p = ucl_object_iterate(jget(o, "profiles"), &it, true)) !=
	    NULL) {
		if (jstr(p, "name") == NULL)
			continue;
		if (first == NULL)
			first = p;
		if (strcmp(jstr(p, "name"), rl.prof) == 0) {
			snprintf(rl.shown, sizeof(rl.shown), "%s", rl.prof);
			return (p);
		}
	}
	/* None picked, or not (or not yet) read: the plain one while it is
	 * set or alone, else the first of them. */
	if (first == NULL || jstr(o, "flags") != NULL) {
		rl.shown[0] = '\0';
		return (o);
	}
	snprintf(rl.shown, sizeof(rl.shown), "%s", jstr(first, "name"));
	return (first);
}

/* Several relays: one picked to be shown, another added; the admin's
 * own, the port's rc script's, beside them to read. */
static void
relays_bar(struct html *h, const ucl_object_t *o)
{
	const ucl_object_t	*p;
	ucl_object_iter_t	 it;

	h_raw(h, "<div class=\"toolbar\"><nav class=\"sub relays\" "
	    "aria-label=\"Relays\">");
	if (jstr(o, "flags") != NULL || jget(o, "profiles") == NULL)
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"rl-pick\" "
		    "data-arg=\"\" title=\"arcana_relay_flags\">the plain one"
		    "</button>", rl.shown[0] == '\0' && !rl.port && !rl.adding ?
		    " on" : "");
	it = NULL;
	while ((p = ucl_object_iterate(jget(o, "profiles"), &it, true)) !=
	    NULL) {
		if (jstr(p, "name") == NULL)
			continue;
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"rl-pick\"",
		    strcmp(jstr(p, "name"), rl.shown) == 0 && !rl.port &&
		    !rl.adding ? " on" : "");
		h_attr(h, "data-arg", jstr(p, "name"));
		h_raw(h, "><span class=\"dot ");
		h_raw(h, jbool(p, "running") ? "st-up" : "st-down");
		h_raw(h, "\"></span>");
		h_txt(h, jstr(p, "name"));
		h_raw(h, "</button>");
	}
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"rl-add\">+ "
	    "Another relay</button>", rl.adding ? " on" : "");
	if ((p = jget(o, "speederv2")) != NULL) {
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"rl-pick-port\""
		    " title=\"The admin's own relay, run by the port's rc script "
		    "(speederv2_flags): read here, never changed\"><span class=\""
		    "dot %s\"></span>speederv2, the admin's</button>", rl.port ?
		    " on" : "", jbool(p, "running") ? "st-up" : "st-down");
	}
	h_raw(h, "</nav></div>");
	if (jstr(o, "flags") != NULL && jget(o, "profiles") != NULL)
		h_raw(h, "<p class=\"notice warn\">The plain relay's "
		    "<code>arcana_relay_flags</code> is set but not run: the rc "
		    "script runs the relays of <code>arcana_relay_profiles</code> "
		    "while it lists any.</p>");
}

void
view_relay(struct html *h, struct server *s)
{
	const ucl_object_t	*o, *e, *lines, *l, *top;
	ucl_object_iter_t	 it;
	bool			 running, enabled, set;

	h_raw(h, "<div class=\"toolbar\"><label class=\"secpick\">Where "
	    "<select data-input=\"rl-where\"><option value=\"\"");
	if (rl_where(s)[0] == '\0')
		h_raw(h, " selected");
	h_raw(h, ">the host</option>");
	it = NULL;
	while (s->list != NULL && (e = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		if (jstr(e, "name") == NULL || jstr(e, "state") == NULL ||
		    strcmp(jstr(e, "state"), "running") != 0)
			continue;
		h_raw(h, "<option");
		h_attr(h, "value", jstr(e, "name"));
		if (strcmp(rl_where(s), jstr(e, "name")) == 0)
			h_raw(h, " selected");
		h_raw(h, ">jail ");
		h_txt(h, jstr(e, "name"));
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label><small class=\"help\">UDPspeeder's relay "
	    "on the host, or in a jail</small></div>");
	if (!res_shown(h, &rl.r, s->id, rl_load, "rl-retry"))
		return;
	o = rl.r.o;
	h_raw(h, "<section class=\"sysview relayview\">");
	if (!jbool(o, "installed")) {
		h_raw(h, "<div class=\"notice warn sec-missing\"><span>UDPspeeder "
		    "is not installed ");
		if (jstr(o, "jail") != NULL) {
			h_raw(h, "in jail ");
			h_txt(h, jstr(o, "jail"));
		} else
			h_raw(h, "on this host");
		h_fmt(h, ": a plugin, the port net/udpspeeder.</span><button "
		    "class=\"primary small\" data-act=\"rl-install\"%s>%s"
		    "</button></div>", rl_installing(s, rl_where(s)) ?
		    " disabled" : "", rl_installing(s, rl_where(s)) ?
		    "Installing…" : "Install udpspeeder");
		h_raw(h, "<div class=\"empty\"><p>No FEC relay here.</p><p "
		    "class=\"dim\">speederv2 carries a tunnel's UDP over a lossy "
		    "link with forward error correction: redundant packets, so a "
		    "lost one is made again at the far end rather than sent "
		    "again.</p></div></section>");
		return;
	}
	top = o;
	o = rl_relay(top);
	relays_bar(h, top);
	if (rl.adding) {
		conf_form(h, NULL);
		h_raw(h, "</section>");
		return;
	}
	running = jbool(o, "running");
	/* The admin's relay has its own enable; it is read, not run. */
	enabled = jbool(rl.port ? o : top, "enabled");
	set = jstr(o, "flags") != NULL;
	h_raw(h, "<div class=\"toolbar\">");
	if (jstr(top, "jail") != NULL) {
		h_raw(h, "<span class=\"chip\">in jail ");
		h_txt(h, jstr(top, "jail"));
		h_raw(h, "</span> ");
	}
	if (rl.port)
		h_raw(h, "<span class=\"chip\">the admin's, read only</span> ");
	chip(h, enabled, "Enabled at boot", "Not at boot");
	chip(h, running, "Running", "Stopped");
	if (jstr(o, "role") != NULL) {
		h_raw(h, "<span class=\"chip\">");
		h_txt(h, jstr(o, "role"));
		h_raw(h, "</span> ");
	}
	h_raw(h, "<span class=\"grow\"></span>");
	if (set && !rl.port) {
		h_fmt(h, "<button class=\"ghost small\" data-act=\"%s\">%s"
		    "</button> ", running ? "rl-restart" : "rl-start", running ?
		    "Restart" : "Start");
		if (running)
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "rl-stop\">Stop</button> ");
		h_fmt(h, "<button class=\"ghost small\" data-act=\"%s\" title="
		    "\"%s\">%s</button> <button class=\"small%s\" data-act=\""
		    "rl-conf\">Configure</button>", enabled ? "rl-disable" :
		    "rl-enable", jget(top, "profiles") != NULL ?
		    "arcana_relay_enable: every relay of Arcana's on the host" :
		    "arcana_relay_enable", enabled ? "Disable" : "Enable",
		    rl.conf ? " on" : "");
		if (rl.shown[0] != '\0')
			h_raw(h, " <button class=\"ghost small danger\" data-act=\""
			    "rl-remove\">Remove</button>");
	}
	h_raw(h, "</div>");
	if (rl.port) {
		h_raw(h, "<p class=\"notice\">The port's own rc script, "
		    "<code>speederv2</code>, runs this relay from <code>"
		    "speederv2_flags</code>; it is yours, and Arcana only "
		    "reads it. Arcana's relays are profiles of its own script, "
		    "<code>arcana_relay</code>.</p>");
		if (!set)
			h_raw(h, "<p class=\"dim\"><code>speederv2_flags</code> is "
			    "empty.</p>");
	} else if (!set || rl.conf) {
		if (!set && rl.shown[0] == '\0')
			h_raw(h, "<p class=\"notice\">The relay is installed but "
			    "not set up: <code>arcana_relay_flags</code> is empty."
			    "</p>");
		conf_form(h, o);
	}
	if (set) {
		h_raw(h, "<div class=\"relay-grid\"><div><h3>How it is set</h3>"
		    "<dl class=\"kv\">");
		dt(h, "Role", jstr(o, "role"));
		dt(h, "Listens at", jstr(o, "listen"));
		dt(h, "Sends to", jstr(o, "remote"));
		dt_int(h, "Mode", o, "mode", "");
		dt_int(h, "MTU", o, "mtu", "");
		dt(h, "Ratios", jstr(o, "fec"));
		dt_int(h, "Timeout", o, "timeout", " ms");
		dt_int(h, "Reports every", o, "report_every", " s");
		dt(h, "Fifo", jstr(o, "fifo"));
		dt(h, "Key", jbool(o, "key") ? "set (not shown)" : "none");
		dt(h, "More", jstr(o, "extra"));
		if (jbool(o, "svcj")) {
			char	jn[64];

			snprintf(jn, sizeof(jn), "svcj-%s%s%s", rl.port ?
			    "speederv2" : "arcana_relay", rl.shown[0] != '\0' ?
			    "_" : "", rl.shown);
			dt(h, "Service jail", jn);
			dt(h, "Its addresses", jstr(o, "svcj_ipaddrs") != NULL ?
			    jstr(o, "svcj_ipaddrs") : "all of the host's");
			dt(h, "It may", jstr(o, "svcj_options"));
		} else
			dt(h, "Service jail", "none");
		h_raw(h, "</dl><p class=\"dim\"><code>");
		h_txt(h, jstr(o, "flags"));
		h_raw(h, "</code></p>");
		/* The ratios changed while it runs; not the admin's. */
		if (!rl.port) {
			h_raw(h, "<form data-form=\"rl-fec\" class=\"inline-form\">"
			    "<label>Ratios<input name=\"fec\" spellcheck=\"false\" "
			    "autocomplete=\"off\" placeholder=\"20:10\"");
			h_attr(h, "value", jstr(o, "fec") != NULL ? jstr(o, "fec") :
			    "");
			h_fmt(h, "></label><button class=\"small\">Change</button>"
			    "<small class=\"help\">%s</small></form>", !running ?
			    "Kept for its next start." : jstr(o, "fifo") != NULL ?
			    "Sent through its fifo: the tunnel stays up." :
			    "Without a fifo it is restarted to take them.");
		}
		h_raw(h, "</div>");
		h_raw(h, "<div><h3>What the FEC costs</h3>");
		if (jget(o, "report") != NULL)
			report_table(h, jget(o, "report"));
		else
			h_fmt(h, "<p class=\"dim\">Nothing measured yet: %s</p>",
			    jint(o, "report_every", 0) <= 0 ? "the relay logs its counters with --report (Report "
			    "every, in its flags), and this tab reads them from "
			    "its log." : "no report in its log yet.");
		series_chart(h, jget(o, "series"));
		if (jget(o, "fec_groups") != NULL) {
			h_raw(h, "<h3>Redundancy by group size</h3>");
			groups_table(h, jget(o, "fec_groups"));
		}
		h_raw(h, "</div></div>");
		/* With FEC and without: two monitors, compared. */
		h_raw(h, "<section class=\"relay-impact\"><h3>What FEC does to "
		    "the tunnel</h3>");
		if (rl.m.o == NULL && !rl.m.loading)
			rl_load_monitors(s->id);
		if (cmp_monitor(s, CMP_RAW) != NULL || cmp_monitor(s, CMP_TUN) !=
		    NULL)
			compare_table(h, s, o);
		else if (rl.compare)
			compare_form(h, o);
		else
			h_raw(h, "<p class=\"dim\">Loss, delay and variation "
			    "with FEC and without, measured side by side. "
			    "<button class=\"small\" data-act=\"rl-compare\">"
			    "Measure what FEC does</button></p>");
		h_raw(h, "</section>");
	}
	lines = jget(o, "log");
	if (lines != NULL && ucl_array_size(lines) > 0) {
		h_raw(h, "<details class=\"relay-log\"><summary>Its last lines in ");
		h_txt(h, jstr(top, "log_path") != NULL ? jstr(top, "log_path") :
		    "the log");
		h_raw(h, "</summary><pre class=\"out\">");
		it = NULL;
		while ((l = ucl_object_iterate(lines, &it, true)) != NULL) {
			h_txt(h, ucl_object_tostring(l));
			h_raw(h, "\n");
		}
		h_raw(h, "</pre></details>");
	}
	h_raw(h, "<p class=\"freebsd-note dim\">FreeBSD: Arcana's own rc "
	    "script, arcana_relay, runs each relay as a profile of rc.subr(8) "
	    "(service arcana_relay start &lt;name&gt;) under daemon(8), which "
	    "restarts it and sends its lines to syslogd(8) tagged "
	    "arcana_relay_&lt;name&gt;; rc.conf's arcana_relay_profiles lists "
	    "them and arcana_relay_&lt;name&gt;_flags are each one's words, "
	    "or arcana_relay_flags the one relay's. rc.subr runs each in a "
	    "service jail of its own with _svcj, held to _svcj_ipaddrs. The "
	    "port's own script, speederv2, keeps running the admin's relay. "
	    "The overhead is kept in the host's history beside its "
	    "interfaces' rates (Utilization).</p></section>");
}

static struct server *
rl_server(void)
{
	struct server	*s;

	if ((s = cur_server()) == NULL)
		toast(true, "No host is chosen");
	return (s);
}

/* A field of a form, or "". */
static const char *
fv(const ucl_object_t *f, const char *key)
{

	return (jstr(f, key) != NULL ? jstr(f, key) : "");
}

bool
relay_form(const char *form, const ucl_object_t *f)
{
	static const char *const keys[] = { "role", "listen", "remote", "mode",
	    "mtu", "fec", "timeout", "report", "key", "extra" };
	struct server	*s;
	const char	*words[16], *w[1];
	char		 buf[16][300], title[160];
	size_t		 i, n;

	if (strcmp(form, "rl-compare") == 0) {
		char		 a[4][128], t[96];
		const char	*w2[4];
		size_t		 k;

		if ((s = rl_server()) == NULL)
			return (true);
		/* Without FEC: the underlay, in the relay's table. */
		snprintf(a[0], sizeof(a[0]), "name=" CMP_RAW);
		snprintf(a[1], sizeof(a[1]), "address=%s", fv(f, "raw"));
		snprintf(a[2], sizeof(a[2]), "fib=%s", fv(f, "fib")[0] != '\0' ?
		    fv(f, "fib") : "0");
		for (k = 0; k < 3; k++)
			w2[k] = a[k];
		snprintf(t, sizeof(t), "monitor set " CMP_RAW);
		rl_monitor_send(s, "set", w2, 3, t);
		/* With it: through the tunnel, its table the interface's. */
		snprintf(a[0], sizeof(a[0]), "name=" CMP_TUN);
		snprintf(a[1], sizeof(a[1]), "address=%s", fv(f, "tunnel"));
		k = 2;
		if (fv(f, "interface")[0] != '\0')
			snprintf(a[k++], sizeof(a[0]), "interface=%s", fv(f,
			    "interface"));
		for (size_t x = 0; x < k; x++)
			w2[x] = a[x];
		snprintf(t, sizeof(t), "monitor set " CMP_TUN);
		rl_monitor_send(s, "set", w2, k, t);
		rl.compare = false;
		return (true);
	}
	if (strcmp(form, "rl-fec") == 0) {
		if ((s = rl_server()) == NULL)
			return (true);
		w[0] = fv(f, "fec");
		snprintf(title, sizeof(title), "speederv2%s%s: ratios %s",
		    rl.shown[0] != '\0' ? " " : "", rl.shown, w[0]);
		rl_send(s, "fec", w, 1, title);
		return (true);
	}
	if (strcmp(form, "rl-conf") != 0)
		return (false);
	if ((s = rl_server()) == NULL)
		return (true);
	if (rl.adding) {
		/* The new relay's name; the job then carries profile=. */
		snprintf(rl.prof, sizeof(rl.prof), "%s", fv(f, "profile"));
		snprintf(rl.shown, sizeof(rl.shown), "%s", rl.prof);
		rl.adding = false;
	}
	n = 0;
	for (i = 0; i < nitems(keys); i++) {
		if (fv(f, keys[i])[0] == '\0')
			continue;
		snprintf(buf[n], sizeof(buf[n]), "%s=%s", keys[i], fv(f,
		    keys[i]));
		words[n] = buf[n];
		n++;
	}
	/* An empty fifo is none, said so: the relay's own default is none. */
	snprintf(buf[n], sizeof(buf[n]), "fifo=%s", fv(f, "fifo"));
	words[n] = buf[n];
	n++;
	if (jbool(f, "nokey") && fv(f, "key")[0] == '\0')
		words[n++] = "nokey";
	/* Its service jail, said either way; its addresses with it. */
	words[n++] = jbool(f, "svcj") ? "svcj=yes" : "svcj=no";
	if (jbool(f, "svcj")) {
		snprintf(buf[n], sizeof(buf[n]), "svcj_ipaddrs=%s", fv(f,
		    "svcj_ipaddrs"));
		words[n] = buf[n];
		n++;
	}
	snprintf(title, sizeof(title), "speederv2%s%s: a %s from %s to %s",
	    rl.shown[0] != '\0' ? " " : "", rl.shown, fv(f, "role"), fv(f,
	    "listen"), fv(f, "remote"));
	rl_send(s, "conf", words, n, title);
	explicit_bzero(buf, sizeof(buf));
	rl.conf = false;
	return (true);
}

bool
relay_action(const char *act, const char *arg, const char *value)
{
	static const struct {
		const char	*act, *verb, *title;
	} verbs[] = {
		{ "rl-start", "start", "speederv2: start" },
		{ "rl-restart", "restart", "speederv2: restart" },
		{ "rl-enable", "enable", "speederv2: enable and start" },
		{ "rl-do-stop", "stop", "speederv2: stop" },
		{ "rl-do-disable", "disable", "speederv2: stop and disable" },
	};
	struct server	*s;
	char		*json, *qj, title[160];
	const char	*jail;
	size_t		 i;

	if (strcmp(act, "input:rl-where") == 0) {
		rl.picked = true;
		snprintf(rl.jail, sizeof(rl.jail), "%s", value != NULL ? value :
		    "");
		rl.conf = rl.adding = rl.port = false;
		rl.prof[0] = rl.shown[0] = '\0';
		res_drop(&rl.r);
		render();
		return (true);
	}
	if (strncmp(act, "rl-", 3) != 0)
		return (false);
	if (strcmp(act, "rl-retry") == 0) {
		res_drop(&rl.r);
		render();
		return (true);
	}
	if (strcmp(act, "rl-conf") == 0) {
		rl.conf = !rl.conf;
		return (true);
	}
	if (strcmp(act, "rl-pick") == 0) {
		snprintf(rl.prof, sizeof(rl.prof), "%s", arg != NULL ? arg : "");
		snprintf(rl.shown, sizeof(rl.shown), "%s", rl.prof);
		rl.conf = rl.adding = rl.port = false;
		return (true);
	}
	if (strcmp(act, "rl-pick-port") == 0) {
		rl.port = true;
		rl.conf = rl.adding = false;
		return (true);
	}
	if (strcmp(act, "rl-add") == 0) {
		rl.adding = !rl.adding;
		rl.conf = rl.port = false;
		return (true);
	}
	if (strcmp(act, "rl-compare") == 0) {
		rl.compare = !rl.compare;
		return (true);
	}
	if (strcmp(act, "rl-compare-stop") == 0 && (s = rl_server()) != NULL) {
		const char	*w1[1];
		const struct {
			const char	*name, *word;
		} both[] = { { CMP_RAW, "name=" CMP_RAW },
		    { CMP_TUN, "name=" CMP_TUN } };

		for (i = 0; i < nitems(both); i++)
			if (cmp_monitor(s, both[i].name) != NULL) {
				w1[0] = both[i].word;
				snprintf(title, sizeof(title), "monitor remove %s",
				    both[i].name);
				rl_monitor_send(s, "remove", w1, 1, title);
			}
		return (true);
	}
	if ((s = rl_server()) == NULL)
		return (true);
	if (strcmp(act, "rl-remove") == 0) {
		snprintf(title, sizeof(title), "Remove the relay %s?", rl.shown);
		confirm(title, "It is stopped, its arcana_relay_<name>_flags "
		    "unset and its name taken out of arcana_relay_profiles. A "
		    "tunnel carried by it is down. On the host the job is in "
		    "safe mode, and is undone if the console cannot reach the "
		    "host after it.", "Remove", true, "", "rl-do-remove", "", "");
		return (true);
	}
	if (strcmp(act, "rl-do-remove") == 0) {
		snprintf(title, sizeof(title), "speederv2 %s: remove", rl.shown);
		rl_send(s, "remove", NULL, 0, title);
		return (true);
	}
	if (strcmp(act, "rl-stop") == 0 || strcmp(act, "rl-disable") == 0) {
		confirm(strcmp(act, "rl-stop") == 0 ? "Stop the relay?" :
		    "Stop and disable the relay?", "What goes through it stops: "
		    "a tunnel carried by it is down until it starts again. On "
		    "the host the job is in safe mode, and is undone if the "
		    "console cannot reach the host after it.", "Stop", true, "",
		    strcmp(act, "rl-stop") == 0 ? "rl-do-stop" :
		    "rl-do-disable", "", "");
		return (true);
	}
	if (strcmp(act, "rl-install") == 0) {
		jail = rl_where(s);
		qj = json_quote(jail);
		if (asprintf(&json, "{\"kind\":\"pkg-install\",\"packages\":"
		    "[\"udpspeeder\"]%s%s}", jail[0] != '\0' ? ",\"jail\":" : "",
		    jail[0] != '\0' ? qj : "") == -1)
			abort();
		free(qj);
		snprintf(title, sizeof(title), "pkg install udpspeeder%s%s",
		    jail[0] != '\0' ? " in " : "", jail);
		job_send(s, json, title, JOB_RELAY, jail);
		return (true);
	}
	for (i = 0; i < nitems(verbs); i++)
		if (strcmp(act, verbs[i].act) == 0) {
			snprintf(title, sizeof(title), "%s", verbs[i].title);
			/* speederv2 <name>: start, for one of several. */
			if (rl.shown[0] != '\0' && strcmp(verbs[i].verb,
			    "enable") != 0 && strcmp(verbs[i].verb, "disable") != 0)
				snprintf(title, sizeof(title), "speederv2 %s%s",
				    rl.shown, verbs[i].title + 9);
			rl_send(s, verbs[i].verb, NULL, 0, title);
			return (true);
		}
	return (false);
}
