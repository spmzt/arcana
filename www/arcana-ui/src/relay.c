/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * A host's FEC relay tab: UDPspeeder (net/udpspeeder, a plugin), the
 * speederv2 service, as the agent's speeder read has it: how it is set,
 * the redundant packets it adds for each group size, and what the FEC
 * costs each way, measured from the relay's own --report lines.  Its
 * flags from a form, its ratios changed while it runs (by its fifo, the
 * tunnel kept), started, stopped, enabled.  Each change is a job, in safe
 * mode on the host: a relay often carries the tunnel the console reaches
 * the host by, and a change it cannot answer after is undone.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	FIFO_DEFAULT	"/var/run/speederv2/fifo"

static struct {
	struct res	 r;		/* the speeder read */
	bool		 conf;		/* the flags' form open */
	bool		 picked;	/* where, chosen by hand: jail */
	char		 jail[64];	/* "" the host */
} rl;

/* Read again at the next draw. */
void
relay_refresh(void)
{

	res_drop(&rl.r);
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

static void
rl_send(struct server *s, const char *verb, const char *const *words,
    size_t n, const char *title)
{
	char	*json;

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
		    "started; \"of late\" and the rates are of its last %lld s "
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

/* The flags' form, filled from what is set. */
static void
conf_form(struct html *h, const ucl_object_t *o)
{
	char	num[32];
	bool	server;

	server = jstr(o, "role") != NULL && strcmp(jstr(o, "role"), "server") ==
	    0;
	h_raw(h, "<form data-form=\"rl-conf\" class=\"set-form relay-conf\">"
	    "<h3>The relay's flags</h3><p class=\"dim\">Written to "
	    "<code>speederv2_flags</code> in rc.conf, each word checked; the "
	    "relay restarted when it runs. Both ends need the same mode, key "
	    "and ratios' scheme.</p><div class=\"two\"><label>Role<select "
	    "name=\"role\">");
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
	input(h, "Fifo", "fifo", jstr(o, "flags") != NULL ? jstr(o, "fifo") :
	    FIFO_DEFAULT, FIFO_DEFAULT, "The ratios are changed through it "
	    "while the relay runs, the tunnel kept up. Empty for none.");
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
	h_raw(h, "<div class=\"actions\">");
	if (jstr(o, "flags") != NULL)
		h_raw(h, "<button type=\"button\" class=\"ghost\" data-act=\""
		    "rl-conf\">Cancel</button>");
	h_raw(h, "<button class=\"primary\">Write the flags</button></div>"
	    "</form>");
}

void
view_relay(struct html *h, struct server *s)
{
	const ucl_object_t	*o, *e, *lines, *l;
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
	running = jbool(o, "running");
	enabled = jbool(o, "enabled");
	set = jstr(o, "flags") != NULL;
	h_raw(h, "<div class=\"toolbar\">");
	if (jstr(o, "jail") != NULL) {
		h_raw(h, "<span class=\"chip\">in jail ");
		h_txt(h, jstr(o, "jail"));
		h_raw(h, "</span> ");
	}
	chip(h, enabled, "Enabled at boot", "Not at boot");
	chip(h, running, "Running", "Stopped");
	if (jstr(o, "role") != NULL) {
		h_raw(h, "<span class=\"chip\">");
		h_txt(h, jstr(o, "role"));
		h_raw(h, "</span> ");
	}
	h_raw(h, "<span class=\"grow\"></span>");
	if (set) {
		h_fmt(h, "<button class=\"ghost small\" data-act=\"%s\">%s"
		    "</button> ", running ? "rl-restart" : "rl-start", running ?
		    "Restart" : "Start");
		if (running)
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "rl-stop\">Stop</button> ");
		h_fmt(h, "<button class=\"ghost small\" data-act=\"%s\">%s"
		    "</button> <button class=\"small%s\" data-act=\"rl-conf\">"
		    "Configure</button>", enabled ? "rl-disable" : "rl-enable",
		    enabled ? "Disable" : "Enable", rl.conf ? " on" : "");
	}
	h_raw(h, "</div>");
	if (!set || rl.conf) {
		if (!set)
			h_raw(h, "<p class=\"notice\">The relay is installed but "
			    "not set up: <code>speederv2_flags</code> is empty.</p>");
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
		h_raw(h, "</dl><p class=\"dim\"><code>");
		h_txt(h, jstr(o, "flags"));
		h_raw(h, "</code></p>");
		/* The ratios changed while it runs. */
		h_raw(h, "<form data-form=\"rl-fec\" class=\"inline-form\"><label>"
		    "Ratios<input name=\"fec\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"20:10\"");
		h_attr(h, "value", jstr(o, "fec") != NULL ? jstr(o, "fec") : "");
		h_fmt(h, "></label><button class=\"small\">Change</button><small "
		    "class=\"help\">%s</small></form></div>", !running ? "Kept for "
		    "its next start." : jstr(o, "fifo") != NULL ? "Sent through "
		    "its fifo: the tunnel stays up." : "Without a fifo it is "
		    "restarted to take them.");
		h_raw(h, "<div><h3>What the FEC costs</h3>");
		if (jget(o, "report") != NULL)
			report_table(h, jget(o, "report"));
		else
			h_fmt(h, "<p class=\"dim\">Nothing measured yet: %s</p>",
			    jint(o, "report_every", 0) <= 0 ? "the relay logs its counters with --report (Report "
			    "every, in its flags), and this tab reads them from "
			    "its log." : "no report in its log yet.");
		if (jget(o, "fec_groups") != NULL) {
			h_raw(h, "<h3>Redundancy by group size</h3>");
			groups_table(h, jget(o, "fec_groups"));
		}
		h_raw(h, "</div></div>");
	}
	lines = jget(o, "log");
	if (lines != NULL && ucl_array_size(lines) > 0) {
		h_raw(h, "<details class=\"relay-log\"><summary>Its last lines in ");
		h_txt(h, jstr(o, "log_path") != NULL ? jstr(o, "log_path") :
		    "the log");
		h_raw(h, "</summary><pre class=\"out\">");
		it = NULL;
		while ((l = ucl_object_iterate(lines, &it, true)) != NULL) {
			h_txt(h, ucl_object_tostring(l));
			h_raw(h, "\n");
		}
		h_raw(h, "</pre></details>");
	}
	h_raw(h, "<p class=\"freebsd-note dim\">FreeBSD: the port's rc "
	    "script runs speederv2 under daemon(8), which restarts it and "
	    "sends its lines to syslogd(8); rc.conf's speederv2_flags are its "
	    "words.</p></section>");
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

	if (strcmp(form, "rl-fec") == 0) {
		if ((s = rl_server()) == NULL)
			return (true);
		w[0] = fv(f, "fec");
		snprintf(title, sizeof(title), "speederv2: ratios %s", w[0]);
		rl_send(s, "fec", w, 1, title);
		return (true);
	}
	if (strcmp(form, "rl-conf") != 0)
		return (false);
	if ((s = rl_server()) == NULL)
		return (true);
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
	snprintf(title, sizeof(title), "speederv2: a %s from %s to %s",
	    fv(f, "role"), fv(f, "listen"), fv(f, "remote"));
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

	(void)arg;
	if (strcmp(act, "input:rl-where") == 0) {
		rl.picked = true;
		snprintf(rl.jail, sizeof(rl.jail), "%s", value != NULL ? value :
		    "");
		rl.conf = false;
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
	if ((s = rl_server()) == NULL)
		return (true);
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
			rl_send(s, verbs[i].verb, NULL, 0, verbs[i].title);
			return (true);
		}
	return (false);
}
