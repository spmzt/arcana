/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's firewall, ipfw(8), laid out as a ruleset is written here: a
 * main chain that packets walk in the order of the numbers, through
 * NAT and the state checks, and from which it calls the parts that say
 * what is let in, out and through.  Each part of that layout has a tab
 * of its own, with the rules whose numbers are its own.
 *
 * A rule is changed now, in the kernel; kept, in the file the host
 * loads when it starts; or both.  "Apply" makes the kept rules the
 * whole ruleset without a gap, through set 1, and takes them back
 * unless the console still reaches the host afterwards.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#ifndef nitems
#define	nitems(x)	(sizeof(x) / sizeof((x)[0]))
#endif

static const struct sect {
	int		 lo, hi;
	const char	*name;
	const char	*what;
	bool		 called;	/* reached by call or skipto */
} sects[] = {
	{ 1, 8, "Outgoing jump", "IPv6 link-locals are called first, then "
	    "what goes out skips the incoming half of the chain.", false },
	{ 9, 99, "Before incoming NAT", "What comes in, before it is "
	    "translated: the silent drops, the dangerous packets, what is "
	    "for this host and what is forwarded.", false },
	{ 100, 199, "Incoming NAT", "Addresses translated on the way in.",
	    false },
	{ 200, 299, "Check-state after incoming NAT", "A packet of a "
	    "connection that was let through before passes here.", false },
	{ 300, 399, "Incoming NAT64", "IPv6 to IPv4 and back: NAT64 and "
	    "CLAT.", false },
	{ 400, 499, "After incoming NAT", "What comes in, once translated.",
	    false },
	{ 500, 599, "Before outgoing NAT", "What goes out, before it is "
	    "translated: from this host, and forwarded.", false },
	{ 600, 699, "Outgoing NAT", "Addresses translated on the way out.",
	    false },
	{ 700, 799, "Check-state after outgoing NAT", "A packet of a known "
	    "connection passes here.", false },
	{ 800, 999, "After outgoing NAT", "What goes out, once translated; "
	    "and at its end, everything else is denied.", false },
	{ 1000, 1999, "IPv6 to me before incoming NAT", "", true },
	{ 2000, 2999, "IPv4 to me before incoming NAT", "", true },
	{ 3000, 3999, "IPv6 to me after incoming NAT", "", true },
	{ 4000, 4999, "IPv4 to me after incoming NAT", "", true },
	{ 5000, 5999, "IPv6 from me before outgoing NAT", "", true },
	{ 6000, 6999, "IPv4 from me before outgoing NAT", "", true },
	{ 7000, 7999, "IPv6 from me after outgoing NAT", "", true },
	{ 8000, 8999, "IPv4 from me after outgoing NAT", "", true },
	{ 9000, 9099, "IPv6 link-locals only", "Neighbour discovery and "
	    "what else lives on the link.", true },
	{ 9100, 9199, "Silent drop", "Incoming, dropped without a line in "
	    "the log.", true },
	{ 9200, 9999, "Dangerous packets", "Incoming, dropped and logged: "
	    "spoofed, malformed, from where nothing should come.", true },
	{ 10000, 10999, "IPv6 incoming forward", "", true },
	{ 11000, 11999, "IPv4 incoming forward", "", true },
	{ 12000, 12999, "IPv6 outgoing forward", "", true },
	{ 13000, 13999, "IPv4 outgoing forward", "", true },
};

static struct {
	char		 sid[9];
	ucl_object_t	*data;
	bool		 loading;
	char		 error[300];
	double		 fetched;
	int		 sect;		/* -1: the layout itself */
	bool		 file_open;	/* the kept rules, as a text */
	char		*text;
	char		 sha[65];
	bool		 file_loading;
	char		 file_error[300];
	char		 file_note[160];
} fw = { .sect = -1 };

/*
 * The layout as rules, for a host that keeps none yet: the main chain
 * with its calls, each part ending in its return, SSH and what the
 * host itself sends let through, and the rest denied.  It is a text to
 * be made the host's own before it is applied.
 */
static const char skeleton[] =
    "add 00001 call 9000 ipv6 from any to any\n"
    "add 00005 skipto 500 all from any to any out\n"
    "add 00020 call 9100 all from any to any in\n"
    "add 00030 call 9200 all from any to any in\n"
    "add 00050 call 1000 ipv6 from any to me6 in\n"
    "add 00060 call 2000 ipv4 from any to me in\n"
    "add 00070 call 10000 ipv6 from not me6 to not me6 in\n"
    "add 00080 call 11000 ipv4 from not me to not me in\n"
    "add 00099 reass all from any to any in\n"
    "add 00200 check-state\n"
    "add 00400 call 9200 all from any to any in\n"
    "add 00410 call 3000 ipv6 from any to me6 in\n"
    "add 00420 call 4000 ipv4 from any to me in\n"
    "add 00510 call 5000 ipv6 from me6 to any out\n"
    "add 00520 call 6000 ipv4 from me to any out\n"
    "add 00530 call 12000 ipv6 from not me6 to not me6 out\n"
    "add 00540 call 13000 ipv4 from not me to not me out\n"
    "add 00700 check-state\n"
    "add 00810 call 7000 ipv6 from me6 to any out\n"
    "add 00820 call 8000 ipv4 from me to any out\n"
    "add 00999 deny log all from any to any\n"
    "add 01000 allow ipv6 from me6 to me6 in\n"
    "add 01001 allow tcp from any to me6 22 in\n"
    "add 01100 allow icmp6 from any to any in\n"
    "add 01999 return via any\n"
    "add 02000 allow ipv4 from me to me in\n"
    "add 02001 allow tcp from any to me 22 in\n"
    "add 02100 allow icmp from any to me in\n"
    "add 02999 return via any\n"
    "add 03999 return via any\n"
    "add 04999 return via any\n"
    "add 05000 allow ipv6 from me6 to me6 out\n"
    "add 05001 allow ipv6 from me6 to any record-state out\n"
    "add 05999 return via any\n"
    "add 06000 allow ipv4 from me to me out\n"
    "add 06101 allow ipv4 from me to any record-state out\n"
    "add 06999 return via any\n"
    "add 07000 allow ipv6 from me6 to me6 out\n"
    "add 07001 allow ipv6 from me6 to any keep-state out\n"
    "add 07999 return via any\n"
    "add 08000 allow ipv4 from me to me out\n"
    "add 08001 allow ipv4 from me to any keep-state out\n"
    "add 08999 return via any\n"
    "add 09000 allow icmp6 from :: to ff02::/16\n"
    "add 09001 allow icmp6 from fe80::/10 to fe80::/10\n"
    "add 09002 allow icmp6 from fe80::/10 to ff02::/16\n"
    "add 09099 return via any\n"
    "add 09100 deny udp from any to 255.255.255.255 1900 in\n"
    "add 09199 return via any\n"
    "add 09200 deny log ipv6 from any to any ext6hdr rthdr0 in\n"
    "add 09251 deny log tcp from any to any tcpflags fin,psh,urg in\n"
    "add 09253 deny log tcp from any to any tcpflags syn,fin in\n"
    "add 09999 return via any\n"
    "add 10999 return via any\n"
    "add 11999 return via any\n"
    "add 12999 return via any\n"
    "add 13999 return via any\n";

static void
fw_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid;

	sid = arg;
	if (strcmp(sid, fw.sid) != 0) {
		free(sid);
		return;
	}
	free(sid);
	fw.loading = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(fw.error, sizeof(fw.error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	fw.error[0] = '\0';
	if (fw.data != NULL)
		ucl_object_unref(fw.data);
	fw.data = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
	fw.fetched = arc_now();
}

static void
file_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*what;

	what = arg;
	fw.file_loading = false;
	if (status != 200 || !jbool(o, "ok")) {
		snprintf(fw.file_error, sizeof(fw.file_error), "%s", status ==
		    200 && jstr(o, "error") != NULL ? jstr(o, "error") : err !=
		    NULL ? err : "no answer");
		free(what);
		return;
	}
	fw.file_error[0] = '\0';
	/* A check leaves what is being written as it is. */
	if (strcmp(what, "check") != 0) {
		free(fw.text);
		fw.text = strdup(jstr(o, "text") != NULL ? jstr(o, "text") :
		    "");
		snprintf(fw.sha, sizeof(fw.sha), "%s", jstr(o, "sha256") !=
		    NULL ? jstr(o, "sha256") : "");
	}
	snprintf(fw.file_note, sizeof(fw.file_note), "%s", strcmp(what,
	    "check") == 0 ? "ipfw has nothing against it." : strcmp(what,
	    "write") == 0 ? "Kept. Apply makes it the host's ruleset." : "");
	if (strcmp(what, "write") == 0) {
		struct server	*s;

		if ((s = cur_server()) != NULL) {
			fw.loading = false;
			refresh_firewall(s, true);
		}
	}
	free(what);
}

static void
file_read(struct server *s)
{
	char	url[96];

	fw.file_loading = true;
	fw.file_note[0] = '\0';
	snprintf(url, sizeof(url), "/api/servers/%s/ipfw/rules", s->id);
	api("GET", url, NULL, file_cb, strdup("read"));
}

void
refresh_firewall(struct server *s, bool again)
{
	char	url[96];

	if (!app.online || fw.loading)
		return;
	if (strcmp(fw.sid, s->id) != 0) {
		if (fw.data != NULL)
			ucl_object_unref(fw.data);
		fw.data = NULL;
		fw.error[0] = '\0';
		fw.file_open = false;
		free(fw.text);
		fw.text = NULL;
	} else if (!again && (fw.data != NULL || fw.error[0] != '\0'))
		return;
	snprintf(fw.sid, sizeof(fw.sid), "%s", s->id);
	fw.loading = true;
	snprintf(url, sizeof(url), "/api/servers/%s/net/ipfw", s->id);
	api("GET", url, NULL, fw_cb, strdup(s->id));
}

static int
count(const ucl_object_t *arr, int lo, int hi)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((o = ucl_object_iterate(arr, &it, true)) != NULL)
		if (jint(o, "num", 0) >= lo && jint(o, "num", 0) <= hi)
			n++;
	return (n);
}

static bool
has_num(const ucl_object_t *arr, int64_t num)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(arr, &it, true)) != NULL)
		if (jint(o, "num", 0) == num)
			return (true);
	return (false);
}

static void
bytes(char *buf, size_t len, int64_t n)
{
	static const char *const units[] = { "B", "kB", "MB", "GB", "TB" };
	double	v;
	int	u;

	v = (double)n;
	for (u = 0; v >= 1000 && u < 4; u++)
		v /= 1000;
	snprintf(buf, len, u == 0 ? "%.0f %s" : v < 10 ? "%.2f %s" : "%.1f %s",
	    v, units[u]);
}

/* The rows of a part: what the kernel has, and what is only kept. */
static ucl_object_t *
rows_of(int lo, int hi)
{
	const ucl_object_t	*o;
	ucl_object_t		*arr, *r;
	ucl_object_iter_t	 it;
	const ucl_object_t	*live, *kept;

	live = jget(fw.data, "rules");
	kept = jget(fw.data, "kept");
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((o = ucl_object_iterate(live, &it, true)) != NULL) {
		if (jint(o, "num", 0) < lo || jint(o, "num", 0) > hi)
			continue;
		r = ucl_object_copy(o);
		ucl_object_insert_key(r, ucl_object_fromstring(jbool(o,
		    "disabled") ? "set off" : has_num(kept, jint(o, "num",
		    0)) ? "now, kept" : "now only"), "where", 0, false);
		ucl_array_append(arr, r);
	}
	it = NULL;
	while ((o = ucl_object_iterate(kept, &it, true)) != NULL) {
		if (jint(o, "num", 0) < lo || jint(o, "num", 0) > hi ||
		    has_num(live, jint(o, "num", 0)))
			continue;
		r = ucl_object_copy(o);
		ucl_object_insert_key(r, ucl_object_fromstring("kept, not "
		    "loaded"), "where", 0, false);
		ucl_array_append(arr, r);
	}
	return (arr);
}

void
view_firewall(struct html *h, struct server *s)
{
	static const struct tcol	cols[] = {
		{ "Number", "num", true }, { "Rule", "text", false },
		{ "Packets", "pkts", true }, { "Bytes", "bytes", true },
		{ "Where", "where", false },
	};
	const ucl_object_t		**rows, *o, *live, *kept;
	ucl_object_iter_t		  it;
	ucl_object_t			 *arr;
	const struct sect		 *sc;
	char				  age[32], buf[32];
	size_t				  i;
	bool				  mine, loaded;
	int				  r, n, next;

	mine = fw.data != NULL && strcmp(fw.sid, s->id) == 0;
	live = mine ? jget(fw.data, "rules") : NULL;
	kept = mine ? jget(fw.data, "kept") : NULL;
	loaded = mine && jbool(fw.data, "loaded");
	h_raw(h, "<div class=\"toolbar\"><div class=\"fw-state\">");
	if (mine) {
		h_fmt(h, "<span class=\"chip %s\">%s</span>", loaded && jbool(
		    fw.data, "enabled") ? "ok" : "warn", !loaded ? "ipfw is not "
		    "in the kernel" : jbool(fw.data, "enabled") ? "on" : "off");
		h_fmt(h, "<span class=\"dim\">%d rules now · %d kept in "
		    "<code>", (int)ucl_array_size(live), (int)ucl_array_size(
		    kept));
		h_txt(h, jstr(fw.data, "path"));
		h_raw(h, "</code></span>");
	}
	h_raw(h, "</div>");
	if (loaded) {
		h_fmt(h, "<button class=\"ghost small\" data-act=\"fw-onoff\" "
		    "data-arg=\"%s\" title=\"net.inet.ip.fw.enable, and "
		    "firewall_enable in rc.conf\">%s</button>", jbool(fw.data,
		    "enabled") ? "disable" : "enable", jbool(fw.data,
		    "enabled") ? "Turn off" : "Turn on");
		h_raw(h, "<button class=\"small\" data-act=\"fw-apply\" title="
		    "\"The kept rules become the whole ruleset, without a gap: "
		    "loaded into set 1 while it is off, then swapped with set "
		    "0\">Apply the kept rules</button>");
	}
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"fw-file\">Kept "
	    "rules as text</button><input class=\"filter\" id=\"filter\" "
	    "data-input=\"filter\" placeholder=\"Filter rows\" autocomplete=\""
	    "off\" spellcheck=\"false\"", fw.file_open ? " on" : "");
	h_attr(h, "value", app.filter);
	h_raw(h, "><span class=\"age\">");
	if (fw.loading && strcmp(fw.sid, s->id) == 0)
		h_raw(h, "reading…");
	else if (mine) {
		fmt_age(age, sizeof(age), fw.fetched);
		h_txt(h, age);
	}
	h_raw(h, "</span><button class=\"icon\" data-act=\"refresh\" title=\""
	    "Read again\">⟳</button></div>");
	if (strcmp(fw.sid, s->id) == 0 && fw.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, fw.error);
		h_raw(h, "</div>");
	}
	if (!mine) {
		h_raw(h, "<div class=\"empty\"><p>Reading the firewall…</p>"
		    "</div>");
		return;
	}
	if (!loaded)
		h_raw(h, "<div class=\"notice info\">ipfw is not in this "
		    "host's kernel. Arcana loads no module by itself: load "
		    "<code>ipfw</code> from the Kernel tab, with <code>"
		    "net.inet.ip.fw.default_to_accept=1</code> set in the "
		    "loader first if the host is reached over the network, "
		    "since an empty ipfw denies everything. The kept rules "
		    "can be written meanwhile.</div>");

	/* The kept rules as one text, to be read, checked and replaced. */
	if (fw.file_open) {
		h_raw(h, "<section class=\"pane fw-file\"><h4>The kept rules"
		    "</h4><p class=\"dim\">ipfw's own commands, one a line: "
		    "<code>add</code> and a number for a rule, and <code>table"
		    "</code>, <code>nat</code> and <code>nat64…</code> lines "
		    "for what the rules use. No <code>set</code>, <code>flush"
		    "</code> or <code>delete</code>: applying does those. The "
		    "host loads this file when it starts.</p>");
		if (fw.file_error[0] != '\0') {
			h_raw(h, "<div class=\"notice bad\">");
			h_txt(h, fw.file_error);
			h_raw(h, "</div>");
		} else if (fw.file_note[0] != '\0') {
			h_raw(h, "<div class=\"notice info\">");
			h_txt(h, fw.file_note);
			h_raw(h, "</div>");
		}
		h_raw(h, "<form data-form=\"fw-text\"><textarea name=\"text\" "
		    "rows=\"18\" spellcheck=\"false\" class=\"mono\">");
		h_txt(h, fw.text != NULL ? fw.text : "");
		h_fmt(h, "</textarea><div class=\"actions\"><button class=\""
		    "ghost small\" name=\"how\" value=\"check\"%s>Check"
		    "</button><button class=\"small\" name=\"how\" value=\""
		    "write\"%s>Keep</button>", fw.file_loading ? " disabled" :
		    "", fw.file_loading ? " disabled" : "");
		if (fw.text == NULL || fw.text[0] == '\0')
			h_raw(h, "<button type=\"button\" class=\"ghost small\" "
			    "data-act=\"fw-skeleton\" title=\"The layout as "
			    "rules: the chain with its calls, each part with "
			    "its return, SSH and what the host sends let "
			    "through, the rest denied. To be made this "
			    "host's own before it is applied\">Start from the "
			    "layout</button>");
		h_raw(h, "</div></form></section>");
	}

	/* A tab for the layout, and one for each of its parts. */
	h_fmt(h, "<nav class=\"fw-tabs\"><button class=\"ghost small%s\" "
	    "data-act=\"fw-sect\" data-arg=\"-1\">Layout</button>",
	    fw.sect == -1 ? " on" : "");
	for (i = 0; i < nitems(sects); i++) {
		if (i == 10)
			h_raw(h, "<span class=\"sep\">called</span>");
		n = count(live, sects[i].lo, sects[i].hi);
		h_fmt(h, "<button class=\"ghost small%s%s\" data-act=\"fw-sect\" "
		    "data-arg=\"%zu\" title=\"%d to %d\">%s<small>%d</small>"
		    "</button>", fw.sect == (int)i ? " on" : "", n == 0 &&
		    count(kept, sects[i].lo, sects[i].hi) == 0 ? " none" : "",
		    i, sects[i].lo, sects[i].hi, sects[i].name, n);
	}
	h_raw(h, "</nav>");
	if (fw.sect < 0 || fw.sect >= (int)nitems(sects)) {
		h_raw(h, "<table class=\"net fw-layout\"><thead><tr><th>Numbers"
		    "</th><th>Part</th><th>Now</th><th>Kept</th><th></th></tr>"
		    "</thead><tbody>");
		for (i = 0; i < nitems(sects); i++) {
			if (i == 0 || i == 10)
				h_fmt(h, "<tr class=\"group\"><td colspan=\"5\">%s"
				    "</td></tr>", i == 0 ? "The chain every "
				    "packet walks, in the order of the numbers" :
				    "The parts the chain calls, each ending in "
				    "its return");
			h_fmt(h, "<tr class=\"pick\" data-act=\"fw-sect\" "
			    "data-arg=\"%zu\"><td class=\"dim\">%d–%d</td><td><b>"
			    "%s</b><small class=\"dim\">%s</small></td><td>%d"
			    "</td><td>%d</td><td class=\"dim\">›</td></tr>", i,
			    sects[i].lo, sects[i].hi, sects[i].name,
			    sects[i].what, count(live, sects[i].lo,
			    sects[i].hi), count(kept, sects[i].lo,
			    sects[i].hi));
		}
		h_raw(h, "</tbody></table>");
		n = count(live, 14000, 65534) + count(live, 0, 0);
		if (n > 0)
			h_fmt(h, "<p class=\"dim\">%d rules have numbers "
			    "outside the layout; the last, 65535, is ipfw's "
			    "own.</p>", n);
		if (ucl_array_size(jget(fw.data, "tables")) > 0) {
			h_raw(h, "<p><b>Tables</b> ");
			it = NULL;
			while ((o = ucl_object_iterate(jget(fw.data, "tables"),
			    &it, true)) != NULL) {
				h_raw(h, "<span class=\"chip\">");
				h_txt(h, ucl_object_tostring_forced(o));
				h_raw(h, "</span> ");
			}
			h_raw(h, "</p>");
		}
		if (ucl_array_size(jget(fw.data, "nat")) > 0) {
			h_raw(h, "<p><b>NAT</b></p><pre class=\"mono\">");
			it = NULL;
			while ((o = ucl_object_iterate(jget(fw.data, "nat"),
			    &it, true)) != NULL) {
				h_txt(h, ucl_object_tostring_forced(o));
				h_raw(h, "\n");
			}
			h_raw(h, "</pre>");
		}
		return;
	}
	sc = &sects[fw.sect];
	h_fmt(h, "<h4 class=\"family\">%s <small class=\"dim\">%d to %d%s"
	    "</small></h4>", sc->name, sc->lo, sc->hi, sc->called ?
	    ", called from the chain" : "");
	if (sc->what[0] != '\0')
		h_fmt(h, "<p class=\"dim\">%s</p>", sc->what);
	arr = rows_of(sc->lo, sc->hi);
	/* The next number free in the part, for a new rule. */
	next = sc->lo;
	it = NULL;
	while ((o = ucl_object_iterate(arr, &it, true)) != NULL)
		if (jint(o, "num", 0) >= next && jint(o, "num", 0) < sc->hi -
		    1 && !(sc->called && jint(o, "num", 0) == sc->hi))
			next = (int)jint(o, "num", 0) + 1;
	h_fmt(h, "<form data-form=\"fw-add\" class=\"fw-add\"><input name=\""
	    "num\" inputmode=\"numeric\" size=\"6\" value=\"%d\" title=\"The "
	    "rule's number: %d to %d here\"><input name=\"rule\" spellcheck=\""
	    "false\" autocomplete=\"off\" placeholder=\"allow tcp from any to "
	    "me 443 in\"><label class=\"toggle\" title=\"Added to what the "
	    "kernel has, at once\"><input type=\"checkbox\" name=\"live\"%s>"
	    "<span>now</span></label><label class=\"toggle\" title=\"Written "
	    "into the kept rules, which the host loads when it starts and "
	    "Apply loads\"><input type=\"checkbox\" name=\"persist\" checked>"
	    "<span>keep</span></label><button class=\"small\">Add</button>"
	    "</form>", next, sc->lo, sc->hi, loaded ? " checked" : "");
	h_raw(h, "<table class=\"net fw-rules\">");
	tbl_head(h, "fwrules", cols, 5, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("fwrules", arr, cols, 5, app.filter);
	for (r = 0; (o = rows[r]) != NULL; r++) {
		const char	*where = jstr(o, "where");
		bool		 now = strncmp(where, "now", 3) == 0 || strcmp(
		    where, "set off") == 0;

		h_fmt(h, "<tr class=\"%s\"", now ? "" : "off");
		h_fmt(h, " data-rule=\"%lld\"><td><b>%05lld</b></td><td class="
		    "\"mono rule\">", (long long)jint(o, "num", 0), (long long)
		    jint(o, "num", 0));
		h_txt(h, jstr(o, "text"));
		h_raw(h, "</td><td>");
		if (now)
			h_fmt(h, "%lld", (long long)jint(o, "pkts", 0));
		h_raw(h, "</td><td>");
		if (now) {
			bytes(buf, sizeof(buf), jint(o, "bytes", 0));
			h_txt(h, buf);
		}
		h_fmt(h, "</td><td><span class=\"chip%s\">", strcmp(where,
		    "now, kept") == 0 ? "" : " dim");
		h_txt(h, where);
		h_fmt(h, "</span></td><td class=\"acts\"><button class=\"ghost "
		    "small\" data-act=\"fw-del\" data-arg=\"%lld\" data-value=\""
		    "%s\">Delete</button></td></tr>", (long long)jint(o, "num",
		    0), strcmp(where, "now, kept") == 0 ? "both" : now ? "live" :
		    "kept");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (ucl_array_size(arr) == 0)
		h_raw(h, "<div class=\"empty\"><p>No rule in this part.</p>"
		    "</div>");
	ucl_object_unref(arr);
}

static void
fw_job(struct server *s, const char *json, const char *title)
{

	job_send_host(s, strdup(json), title, JOB_FIREWALL, "");
}

bool
firewall_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	struct html	 b;
	const char	*rule, *how;
	char		*copy, *p, *w, *q, url[96], title[200];
	int		 num, lo, hi;
	bool		 first;

	if (strcmp(form, "fw-add") != 0 && strcmp(form, "fw-text") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(form, "fw-text") == 0) {
		how = jstr(f, "how") != NULL ? jstr(f, "how") : "write";
		rule = jstr(f, "text") != NULL ? jstr(f, "text") : "";
		/* What was typed stays in the box while it is asked. */
		free(fw.text);
		fw.text = strdup(rule);
		memset(&b, 0, sizeof(b));
		/* The last line ends as the others do. */
		if (asprintf(&copy, "%s%s", rule, rule[0] != '\0' && rule[
		    strlen(rule) - 1] != '\n' ? "\n" : "") == -1)
			abort();
		q = json_quote(copy);
		free(copy);
		h_fmt(&b, "{\"text\":%s,\"sha256\":\"%s\",\"check\":%s}", q,
		    fw.sha, strcmp(how, "check") == 0 ? "true" : "false");
		free(q);
		fw.file_loading = true;
		fw.file_note[0] = '\0';
		snprintf(url, sizeof(url), "/api/servers/%s/ipfw/rules", s->id);
		api("POST", url, b.s, file_cb, strdup(strcmp(how, "check") ==
		    0 ? "check" : "write"));
		free(b.s);
		return (true);
	}
	num = jstr(f, "num") != NULL ? atoi(jstr(f, "num")) : 0;
	rule = jstr(f, "rule") != NULL ? jstr(f, "rule") : "";
	lo = fw.sect >= 0 ? sects[fw.sect].lo : 1;
	hi = fw.sect >= 0 ? sects[fw.sect].hi : 65534;
	if (num < lo || num > hi) {
		toast(true, "A rule of this part has a number from %d to %d",
		    lo, hi);
		return (true);
	}
	if (rule[strspn(rule, " \t")] == '\0') {
		toast(true, "Write the rule: allow tcp from any to me 443 in");
		return (true);
	}
	if (!jbool(f, "live") && !jbool(f, "persist")) {
		toast(true, "Now, kept, or both");
		return (true);
	}
	/* The rule's words, each one of the job's. */
	memset(&b, 0, sizeof(b));
	h_fmt(&b, "{\"kind\":\"ipfw\",\"verb\":\"add\",\"args\":[\"%d\"", num);
	copy = strdup(rule);
	p = copy;
	first = true;
	while ((w = strsep(&p, " \t")) != NULL) {
		if (*w == '\0')
			continue;
		/* "add" and a number before the rule say what is known. */
		if (first && strcmp(w, "add") == 0)
			continue;
		first = false;
		q = json_quote(w);
		h_fmt(&b, ",%s", q);
		free(q);
	}
	free(copy);
	h_fmt(&b, "],\"live\":%s,\"persist\":%s}", jbool(f, "live") ? "true" :
	    "false", jbool(f, "persist") ? "true" : "false");
	snprintf(title, sizeof(title), "ipfw add %d %.140s", num, rule);
	fw_job(s, b.s, title);
	free(b.s);
	return (true);
}

bool
firewall_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 json[256], title[96], body[500];

	if (strncmp(act, "fw-", 3) != 0 && strncmp(act, "do-fw-", 6) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "fw-sect") == 0) {
		fw.sect = atoi(arg);
		if (fw.sect < -1 || fw.sect >= (int)nitems(sects))
			fw.sect = -1;
	} else if (strcmp(act, "fw-file") == 0) {
		fw.file_open = !fw.file_open;
		fw.file_error[0] = fw.file_note[0] = '\0';
		if (fw.file_open)
			file_read(s);
	} else if (strcmp(act, "fw-skeleton") == 0) {
		free(fw.text);
		fw.text = strdup(skeleton);
		snprintf(fw.file_note, sizeof(fw.file_note), "The layout, not "
		    "kept yet: make it this host's own, then Keep.");
	} else if (strcmp(act, "fw-apply") == 0) {
		snprintf(body, sizeof(body), "The %d kept rules become the "
		    "whole ruleset of %s, in place of the %d it has now. They "
		    "are loaded into set 1 while it is off and swapped with "
		    "set 0, so that no packet meets half a ruleset. The rules "
		    "of now wait in set 1: if the console cannot reach the "
		    "host afterwards, the host swaps them back by itself.",
		    (int)ucl_array_size(jget(fw.data, "kept")), s->name,
		    (int)ucl_array_size(jget(fw.data, "rules")));
		confirm("Apply the kept rules", body, "Apply", true, "",
		    "do-fw-apply", "", "");
	} else if (strcmp(act, "do-fw-apply") == 0) {
		fw_job(s, "{\"kind\":\"ipfw\",\"verb\":\"apply\",\"safe\":true}",
		    "ipfw apply");
	} else if (strcmp(act, "fw-onoff") == 0 && (strcmp(arg, "enable") ==
	    0 || strcmp(arg, "disable") == 0)) {
		snprintf(body, sizeof(body), arg[0] == 'e' ? "The firewall of "
		    "%s is turned on: its rules decide what passes from now "
		    "on, and it is on when the host starts. If the console "
		    "cannot reach the host afterwards, the host turns it off "
		    "again by itself." : "The firewall of %s is turned off: "
		    "everything passes, now and when the host starts.",
		    s->name);
		confirm(arg[0] == 'e' ? "Turn the firewall on" : "Turn the "
		    "firewall off", body, arg[0] == 'e' ? "Turn on" :
		    "Turn off", true, "", "do-fw-onoff", arg, "");
	} else if (strcmp(act, "do-fw-onoff") == 0 && (strcmp(arg,
	    "enable") == 0 || strcmp(arg, "disable") == 0)) {
		snprintf(json, sizeof(json), "{\"kind\":\"ipfw\",\"verb\":\"%s\","
		    "\"persist\":true%s}", arg, arg[0] == 'e' ? ",\"safe\":true" :
		    "");
		snprintf(title, sizeof(title), "ipfw %s", arg);
		fw_job(s, json, title);
	} else if (strcmp(act, "fw-del") == 0 && atoi(arg) > 0) {
		snprintf(json, sizeof(json), "{\"kind\":\"ipfw\",\"verb\":"
		    "\"delete\",\"args\":[\"%d\"],\"live\":%s,\"persist\":%s}",
		    atoi(arg), strcmp(value, "kept") == 0 ? "false" : "true",
		    strcmp(value, "live") == 0 ? "false" : "true");
		snprintf(title, sizeof(title), "ipfw delete %d", atoi(arg));
		fw_job(s, json, title);
	}
	return (true);
}
