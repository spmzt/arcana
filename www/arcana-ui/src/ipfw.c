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

#define	FW_LAYOUT	(-1)	/* the parts, listed */
#define	FW_DYNAMIC	(-2)	/* the connections let through now */
#define	FW_TEXT		(-3)	/* the kept rules, as a text */
#define	FW_TABLES	(-4)	/* the tables and what is in them */
#define	FW_OBJECTS	(-5)	/* NAT instances, pipes and queues */
#define	FW_DIFF		(-6)	/* what Apply would change */
#define	FW_TRACE	(-7)	/* a packet followed through the rules */
#define	FW_LOG		(-8)	/* what the rules with log wrote down */
#define	FW_FIRST	FW_LOG
#define	FW_PREV		2048	/* rules whose counters are remembered */
#define	FW_HITS		60	/* a rule's rates kept, the newest last */
#define	FW_HITS_EVERY	5000	/* ms between two looks while a part is shown */

static struct {
	char		 sid[9];
	ucl_object_t	*data;
	bool		 loading;
	char		 error[300];
	double		 fetched;
	int		 sect;		/* a part; or one of the views below */
	bool		 rail_hosts;	/* the tree of hosts is wanted back */
	long long	 edit;		/* the rule being changed, or 0 */
	long long	 move;		/* the number offered for it, or 0 */
	char		 jail[256];	/* the vnet jail whose it is, or "" */
	/* The counters at the look before, for what each took since. */
	struct {
		long long	num, pkts;
	}		 prev[FW_PREV];
	int		 nprev;
	double		 prev_at;
	/* Each rule's packets a second at the last looks, to draw. */
	struct {
		long long	num;
		float		r[FW_HITS];
		int		n;
	}		 hits[FW_PREV];
	int		 nhits;
	/* A packet to follow: what was asked, as it was typed. */
	char		 t_proto[8], t_src[64], t_dst[64], t_port[8], t_if[16];
	bool		 t_out, t_asked;
	/* The kernel's own: the packets of an address it decided on. */
	char		 k_addr[64];
	int		 k_secs;
	ucl_object_t	*k_data;
	char		 typed[400];	/* the rule being typed, for its words */
	bool		 k_loading;
	char		 k_error[300];
	ucl_object_t	*log;		/* the lines of the security log */
	bool		 log_loading;
	char		 log_error[200];
	bool		 dyn_paused;
	bool		 file_open;	/* the kept rules, as a text */
	char		*text;
	char		 sha[65];
	bool		 file_loading;
	char		 file_error[300];
	char		 file_note[160];
} fw = { .sect = FW_LAYOUT };

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

static double	rate_of(long long, long long);

/* The rates since the look before, each appended to its rule's. */
static void
hits_add(void)
{
	const ucl_object_t	*r;
	ucl_object_iter_t	 it;
	long long		 num;
	double			 rate;
	int			 i;

	it = NULL;
	while ((r = ucl_object_iterate(jget(fw.data, "rules"), &it, true)) !=
	    NULL) {
		num = jint(r, "num", 0);
		if (jbool(r, "disabled") || (rate = rate_of(num, jint(r,
		    "pkts", 0))) < 0)
			continue;
		for (i = 0; i < fw.nhits && fw.hits[i].num != num; i++)
			;
		if (i == fw.nhits) {
			if (fw.nhits == FW_PREV)
				continue;
			fw.hits[fw.nhits].num = num;
			fw.hits[fw.nhits++].n = 0;
		}
		if (fw.hits[i].n == FW_HITS) {
			memmove(fw.hits[i].r, fw.hits[i].r + 1,
			    (FW_HITS - 1) * sizeof(float));
			fw.hits[i].n--;
		}
		fw.hits[i].r[fw.hits[i].n++] = (float)rate;
	}
}

/* Has the rule taken as many a second at every look? */
static bool
flat(int i)
{
	int	k;

	for (k = 1; k < fw.hits[i].n; k++)
		if (fw.hits[i].r[k] != fw.hits[i].r[0])
			return (false);
	return (true);
}

/*
 * A rule's packets a second over the last looks, as a line: its
 * highest at the top, each look a step to the right.
 */
static void
hits_line(struct html *h, long long num)
{
	float	max;
	int	i, k;

	for (i = 0; i < fw.nhits && fw.hits[i].num != num; i++)
		;
	if (i == fw.nhits || fw.hits[i].n < 2)
		return;
	max = 0;
	for (k = 0; k < fw.hits[i].n; k++)
		if (fw.hits[i].r[k] > max)
			max = fw.hits[i].r[k];
	h_fmt(h, " <svg class=\"hits\" viewBox=\"0 0 %d 16\" preserveAspect"
	    "Ratio=\"none\" role=\"img\"><title>Packets a second at the "
	    "last %d looks, %ds apart; at most %.1f/s</title><polyline "
	    "points=\"", FW_HITS - 1, fw.hits[i].n, FW_HITS_EVERY / 1000,
	    (double)max);
	/* Over the whole width, however many there are yet; a rate that
	 * does not change is a line in the middle. */
	for (k = 0; k < fw.hits[i].n; k++)
		h_fmt(h, "%.2f,%.1f ", (double)(FW_HITS - 1) * k /
		    (fw.hits[i].n - 1), max <= 0 ? 15.0 : flat(i) ? 8.0 :
		    15.0 - 14.0 * (double)fw.hits[i].r[k] / (double)max);
	h_raw(h, "\"/></svg>");
}

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
	if (fw.data != NULL) {
		const ucl_object_t	*r;
		ucl_object_iter_t	 it;

		/* What each rule had counted, for its rate since. */
		fw.nprev = 0;
		it = NULL;
		while ((r = ucl_object_iterate(jget(fw.data, "rules"), &it,
		    true)) != NULL && fw.nprev < FW_PREV)
			if (!jbool(r, "disabled")) {
				fw.prev[fw.nprev].num = jint(r, "num", 0);
				fw.prev[fw.nprev++].pkts = jint(r, "pkts", 0);
			}
		fw.prev_at = fw.fetched;
		ucl_object_unref(fw.data);
	}
	fw.data = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
	fw.fetched = arc_now();
	hits_add();
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
	if (strcmp(what, "rc") == 0)
		snprintf(fw.file_note, sizeof(fw.file_note), "From %s, not "
		    "kept yet: look it over, then Keep.", jstr(o, "rc_file") !=
		    NULL ? jstr(o, "rc_file") : "the firewall's file");
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
	char	url[400];

	fw.file_loading = true;
	fw.file_note[0] = '\0';
	snprintf(url, sizeof(url), "/api/servers/%s/ipfw/rules%s%s", s->id,
	    fw.jail[0] != '\0' ? "?jail=" : "", fw.jail);
	api("GET", url, NULL, file_cb, strdup("read"));
}

/* The file the firewall loads now, rc.conf's firewall_type, as kept. */
static void
file_read_rc(struct server *s)
{
	char	url[400];

	fw.file_loading = true;
	fw.file_note[0] = '\0';
	snprintf(url, sizeof(url), "/api/servers/%s/ipfw/rules?from=rc%s%s",
	    s->id, fw.jail[0] != '\0' ? "&jail=" : "", fw.jail);
	api("GET", url, NULL, file_cb, strdup("rc"));
}

void
refresh_firewall(struct server *s, bool again)
{
	char	url[400];

	if (!app.online || fw.loading)
		return;
	if (strcmp(fw.sid, s->id) != 0) {
		fw.jail[0] = '\0';
		fw.nprev = 0;
		fw.nhits = 0;
		if (fw.data != NULL)
			ucl_object_unref(fw.data);
		fw.data = NULL;
		fw.error[0] = '\0';
		fw.file_open = false;
		free(fw.text);
		fw.text = NULL;
		/* The kernel's trace was of that host. */
		if (fw.k_data != NULL)
			ucl_object_unref(fw.k_data);
		fw.k_data = NULL;
		fw.k_error[0] = '\0';
	} else if (!again && (fw.data != NULL || fw.error[0] != '\0'))
		return;
	snprintf(fw.sid, sizeof(fw.sid), "%s", s->id);
	fw.loading = true;
	snprintf(url, sizeof(url), "/api/servers/%s/net/ipfw%s%s", s->id,
	    fw.jail[0] != '\0' ? "?jail=" : "", fw.jail);
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

/* The text a rule has where it is kept, or NULL. */
static const char *
kept_text(long long num)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(jget(fw.data, "kept"), &it, true)) !=
	    NULL)
		if (jint(o, "num", 0) == num)
			return (jstr(o, "text"));
	return (NULL);
}

/*
 * The firewall's own side bar, in place of the tree of hosts while its
 * tab is shown: the way back, and then the layout, a line for each
 * part.  False when the tree is what is wanted.
 */
bool
firewall_rail(struct html *h)
{
	const ucl_object_t	*live, *kept;
	struct server		*s;
	size_t			 i;
	int			 n, k;
	bool			 mine;

	s = cur_server();
	if (app.node != NODE_HOST || app.tab != TAB_FIREWALL || s == NULL ||
	    fw.rail_hosts)
		return (false);
	mine = fw.data != NULL && strcmp(fw.sid, s->id) == 0;
	live = mine ? jget(fw.data, "rules") : NULL;
	kept = mine ? jget(fw.data, "kept") : NULL;
	if (app.rail_open)
		h_raw(h, "<div class=\"scrim\" data-act=\"rail-toggle\"></div>");
	h_fmt(h, "<aside class=\"rail fwrail%s\"><div class=\"rail-head\">"
	    "<button class=\"ghost small back\" data-act=\"fw-rail\" title=\""
	    "Back to the hosts and their jails\">‹ Hosts</button><span class="
	    "\"label\">Firewall</span></div><ul class=\"tree\">",
	    app.rail_open ? " open" : "");
	h_fmt(h, "<li class=\"titem host-of fw%s\" data-act=\"fw-jail\" "
	    "data-arg=\"\" title=\"The host's own firewall\"><span class=\""
	    "name\">", fw.jail[0] == '\0' ? " selected" : "");
	h_txt(h, s->name);
	h_raw(h, "</span></li>");
	/* A jail with a network of its own has a firewall of its own. */
	{
		const ucl_object_t	*j;
		ucl_object_iter_t	 jit;

		jit = NULL;
		while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
		    "jails"), &jit, true)) != NULL) {
			if (jstr(j, "name") == NULL || !jbool(j, "vnet") ||
			    jstr(j, "state") == NULL || strcmp(jstr(j,
			    "state"), "running") != 0)
				continue;
			h_fmt(h, "<li class=\"titem fw jailfw%s\" data-act=\""
			    "fw-jail\"", strcmp(fw.jail, jstr(j, "name")) ==
			    0 ? " selected" : "");
			h_attr(h, "data-arg", jstr(j, "name"));
			h_raw(h, " title=\"The firewall of this jail's own "
			    "network\"><span class=\"twig\">└</span><span "
			    "class=\"name\">");
			h_txt(h, jstr(j, "name"));
			h_raw(h, "</span></li>");
		}
	}
	h_fmt(h, "<li class=\"titem fw%s\" data-act=\"fw-sect\" data-arg=\"%d\">"
	    "<span class=\"name\">Overview</span><span class=\"count\">%d"
	    "</span></li>", fw.sect == FW_LAYOUT ? " selected" : "", FW_LAYOUT,
	    (int)ucl_array_size(live));
	h_fmt(h, "<li class=\"titem fw%s\" data-act=\"fw-sect\" data-arg=\"%d\" "
	    "title=\"The connections the stateful rules let through, now\">"
	    "<span class=\"name\">Dynamic states</span><span class=\"count\">"
	    "%lld</span></li>", fw.sect == FW_DYNAMIC ? " selected" : "",
	    FW_DYNAMIC, mine ? (long long)jint(fw.data, "dynamic_total", 0) :
	    0LL);
	h_fmt(h, "<li class=\"titem fw%s\" data-act=\"fw-sect\" data-arg=\"%d\">"
	    "<span class=\"name\">Kept rules as text</span><span class=\""
	    "count\">%d</span></li>", fw.sect == FW_TEXT ? " selected" : "",
	    FW_TEXT, (int)ucl_array_size(kept));
	{
		static const struct {
			int		 sect;
			const char	*name, *title;
		} more[] = {
			{ FW_DIFF, "What Apply would change", "The kept rules "
			    "beside what the kernel has" },
			{ FW_TRACE, "Follow a packet", "Which rules a packet "
			    "meets, and what becomes of it" },
			{ FW_TABLES, "Tables", "The tables and what is in them" },
			{ FW_OBJECTS, "NAT and pipes", "NAT and NAT64 instances, "
			    "pipes, queues and schedulers" },
			{ FW_LOG, "Logged packets", "What the rules with log "
			    "wrote into the security log" },
		};
		size_t	m;

		for (m = 0; m < nitems(more); m++)
			h_fmt(h, "<li class=\"titem fw%s\" data-act=\"fw-sect\" "
			    "data-arg=\"%d\" title=\"%s\"><span class=\"name\">"
			    "%s</span></li>", fw.sect == more[m].sect ?
			    " selected" : "", more[m].sect, more[m].title,
			    more[m].name);
	}
	for (i = 0; i < nitems(sects); i++) {
		if (i == 0 || i == 10)
			h_fmt(h, "<li class=\"tgroup\">%s</li>", i == 0 ?
			    "The chain" : "Called from the chain");
		n = count(live, sects[i].lo, sects[i].hi);
		k = count(kept, sects[i].lo, sects[i].hi);
		h_fmt(h, "<li class=\"titem fw%s%s\" data-act=\"fw-sect\" "
		    "data-arg=\"%zu\" title=\"%d to %d\"><span class=\"num\">%d"
		    "</span><span class=\"name\">%s</span><span class=\"count\">"
		    "%d</span></li>", fw.sect == (int)i ? " selected" : "",
		    n == 0 && k == 0 ? " none" : "", i, sects[i].lo,
		    sects[i].hi, sects[i].lo, sects[i].name, n);
	}
	h_raw(h, "</ul></aside>");
	return (true);
}

/* Is the tree of hosts shown where the firewall's side bar would be? */
bool
firewall_rail_away(void)
{

	return (app.node == NODE_HOST && app.tab == TAB_FIREWALL &&
	    fw.rail_hosts);
}

static void
view_dynamic(struct html *h)
{
	static const struct tcol	cols[] = {
		{ "Rule", "num", true }, { "Kind", "kind", false },
		{ "Flow", "flow", false }, { "Packets", "pkts", true },
		{ "Bytes", "bytes", true }, { "Expires in", "ttl", true },
	};
	const ucl_object_t		**rows, *o;
	char				  buf[32];
	int				  r, n;

	h_fmt(h, "<h4 class=\"family\">Dynamic states <small class=\"dim\">"
	    "%lld now, as <code>ipfw -D show</code> has them</small><button "
	    "class=\"ghost small live%s\" data-act=\"fw-live\" title=\"Read "
	    "again every two seconds while this is shown\"><span class=\""
	    "led\"></span>Live</button></h4><p class=\"dim\">A connection a "
	    "rule with keep-state or record-state let through: its packets "
	    "pass at check-state for as long as it lives. The rule is the "
	    "one that made it.</p>", (long long)jint(fw.data, "dynamic_total",
	    0), fw.dyn_paused ? "" : " on");
	h_raw(h, "<table class=\"net fw-dyn\">");
	tbl_head(h, "fwdyn", cols, 6, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("fwdyn", jget(fw.data, "dynamic"), cols, 6, app.filter);
	for (r = 0, n = 0; (o = rows[r]) != NULL && r < 800; r++, n++) {
		h_fmt(h, "<tr class=\"pick\" data-act=\"fw-goto\" data-arg=\""
		    "%lld\" title=\"To the rule that made it\"><td><b>%05lld"
		    "</b></td><td>", (long long)jint(o, "num", 0), (long long)
		    jint(o, "num", 0));
		h_txt(h, jstr(o, "kind"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(o, "flow"));
		bytes(buf, sizeof(buf), jint(o, "bytes", 0));
		h_fmt(h, "</td><td>%lld</td><td>%s</td><td>%lld s</td></tr>",
		    (long long)jint(o, "pkts", 0), buf, (long long)jint(o,
		    "ttl", 0));
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (n == 0)
		h_raw(h, "<div class=\"empty\"><p>No connection is being "
		    "tracked.</p></div>");
	if (jint(fw.data, "dynamic_total", 0) > (int64_t)ucl_array_size(jget(
	    fw.data, "dynamic")))
		h_fmt(h, "<p class=\"dim\">The first %d of them.</p>", (int)
		    ucl_array_size(jget(fw.data, "dynamic")));
}

static void
view_text(struct html *h)
{
	const char	*type;

	h_raw(h, "<h4 class=\"family\">The kept rules</h4><p class=\"dim\">"
	    "ipfw's own commands, one a line: <code>add</code> and a number "
	    "for a rule, and <code>table</code>, <code>nat</code> and <code>"
	    "nat64…</code> lines for what the rules use. No <code>set</code>, "
	    "<code>flush</code> or <code>delete</code>: applying does those. "
	    "The host loads this file when it starts.</p>");
	if (fw.file_error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, fw.file_error);
		h_raw(h, "</div>");
	} else if (fw.file_note[0] != '\0') {
		h_raw(h, "<div class=\"notice info\">");
		h_txt(h, fw.file_note);
		h_raw(h, "</div>");
	}
	h_raw(h, "<form data-form=\"fw-text\" class=\"fw-file\"><textarea name="
	    "\"text\" rows=\"22\" spellcheck=\"false\" class=\"mono\">");
	h_txt(h, fw.text != NULL ? fw.text : "");
	h_fmt(h, "</textarea><div class=\"actions\"><button class=\"ghost "
	    "small\" name=\"how\" value=\"check\"%s>Check</button><button "
	    "class=\"small\" name=\"how\" value=\"write\"%s>Keep</button>",
	    fw.file_loading ? " disabled" : "", fw.file_loading ? " disabled" :
	    "");
	if (fw.text == NULL || fw.text[0] == '\0')
		h_raw(h, "<button type=\"button\" class=\"ghost small\" "
		    "data-act=\"fw-skeleton\" title=\"The layout as rules: the "
		    "chain with its calls, each part with its return, SSH and "
		    "what the host sends let through, the rest denied. To be "
		    "made this host's own before it is applied\">Start from "
		    "the layout</button>");
	/*
	 * The file the firewall loads now, when it is not the kept one:
	 * rc.conf's firewall_type naming a file.  A jail's rc.conf is not
	 * read with the rules, so a jail is offered it always.
	 */
	type = jstr(jget(fw.data, "rc"), "firewall_type");
	if (fw.jail[0] != '\0' || (type != NULL && type[0] == '/' &&
	    (jstr(fw.data, "path") == NULL || strcmp(type, jstr(fw.data,
	    "path")) != 0))) {
		h_fmt(h, "<button type=\"button\" class=\"ghost small\" "
		    "data-act=\"fw-load-rc\"%s title=\"", fw.file_loading ?
		    " disabled" : "");
		if (type != NULL)
			h_txt(h, type);
		else
			h_raw(h, "The file rc.conf's firewall_type names");
		h_raw(h, ", which the firewall loads now, here as kept rules: "
		    "kept once Keep is pressed\">Load the current file"
		    "</button>");
	}
	h_raw(h, "</div></form>");
}

static void	fw_job(struct server *, const char *, const char *);
static void	rule_args(struct html *, const char *);

/* Packets a second a rule took since the look before; -1 unknown. */
static double
rate_of(long long num, long long pkts)
{
	double	secs;
	int	i;

	secs = (fw.fetched - fw.prev_at) / 1000;
	if (fw.nprev == 0 || secs < 0.5)
		return (-1);
	for (i = 0; i < fw.nprev; i++)
		if (fw.prev[i].num == num)
			return (pkts >= fw.prev[i].pkts ? (double)(pkts -
			    fw.prev[i].pkts) / secs : -1);
	return (-1);
}

/* An ipfw job of what is not a rule: verb, then its words. */
static void
object_job(struct server *s, const char *verb, const char *words, bool keep)
{
	struct html	b;
	char		title[220];

	memset(&b, 0, sizeof(b));
	h_fmt(&b, "{\"kind\":\"ipfw\",\"verb\":\"%s\",\"args\":[\"\"", verb);
	rule_args(&b, words);
	h_fmt(&b, "]%s}", keep ? ",\"persist\":true" : "");
	/* rule_args begins each word with a comma: the first has none. */
	memmove(strstr(b.s, "[\"\",") + 1, strstr(b.s, "[\"\",") + 4, strlen(
	    strstr(b.s, "[\"\",") + 4) + 1);
	snprintf(title, sizeof(title), "ipfw %s %.180s", verb, words);
	fw_job(s, b.s, title);
	free(b.s);
}

/* The tables: each with what is in it, to add to and take from. */
static void
view_tables(struct html *h)
{
	static const struct tcol cols[] = {
		{ "Key", "key", false }, { "Value", "value", false },
	};
	const ucl_object_t	**rows, *t, *e;
	ucl_object_iter_t	  it;
	char			  key[96];
	int			  r, n;

	h_raw(h, "<h4 class=\"family\">Tables</h4><p class=\"dim\">What a "
	    "rule names as <code>table(name)</code>: addresses, networks, "
	    "interfaces or numbers, looked up in one step however many "
	    "there are. An entry is added and taken away now; with "
	    "<b>keep</b> the same words are a line of the kept rules, which "
	    "<b>Kept rules as text</b> shows.</p><form data-form=\"fw-table\""
	    " class=\"fw-add\"><input name=\"name\" spellcheck=\"false\" "
	    "autocomplete=\"off\" placeholder=\"a new table's name\" size=\""
	    "18\"><select name=\"type\"><option>addr</option><option>iface"
	    "</option><option>number</option><option>flow</option></select>"
	    "<label class=\"toggle\"><input type=\"checkbox\" name=\"persist\""
	    " checked><span>keep</span></label><button class=\"small\">"
	    "Create</button></form>");
	n = 0;
	it = NULL;
	while ((t = ucl_object_iterate(jget(fw.data, "tables"), &it, true)) !=
	    NULL) {
		if (jstr(t, "name") == NULL)
			continue;
		n++;
		snprintf(key, sizeof(key), "fwtable-%.60s", jstr(t, "name"));
		h_raw(h, "<section class=\"pane fwtable\">");
		box_head(h, key, "h4");
		h_raw(h, "<span>");
		h_txt(h, jstr(t, "name"));
		h_raw(h, "</span><span class=\"chip dim\">");
		h_txt(h, jstr(t, "type"));
		h_fmt(h, "</span><span class=\"chip\">%lld entries</span>"
		    "<button class=\"ghost small danger\" data-act=\""
		    "fw-table-destroy\"", (long long)jint(t, "count", 0));
		h_attr(h, "data-arg", jstr(t, "name"));
		h_raw(h, ">Destroy</button></h4>");
		if (box_shut(key)) {
			h_raw(h, "</section>");
			continue;
		}
		h_raw(h, "<form data-form=\"fw-entry\" class=\"fw-add\"><input "
		    "type=\"hidden\" name=\"table\"");
		h_attr(h, "value", jstr(t, "name"));
		h_raw(h, "><input name=\"key\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"10.0.0.0/8, 2001:db8::/32"
		    ", em0\"><input name=\"value\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"a value, or nothing\" "
		    "size=\"14\"><label class=\"toggle\"><input type=\"checkbox\""
		    " name=\"persist\"><span>keep</span></label><button class="
		    "\"small\">Add</button></form><table class=\"net fwentries\">");
		tbl_head(h, key, cols, 2, 1);
		h_raw(h, "<tbody>");
		rows = tbl_rows(key, jget(t, "entries"), cols, 2, app.filter);
		for (r = 0; (e = rows[r]) != NULL; r++) {
			h_raw(h, "<tr><td class=\"mono\"><b>");
			h_txt(h, jstr(e, "key"));
			h_raw(h, "</b></td><td class=\"mono\">");
			h_txt(h, jstr(e, "value"));
			h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" "
			    "data-act=\"fw-entry-del\" title=\"Take it out of "
			    "the table\"");
			h_attr(h, "data-arg", jstr(t, "name"));
			h_attr(h, "data-value", jstr(e, "key"));
			h_raw(h, ">×</button></td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table>");
		if (jint(t, "count", 0) > (int64_t)ucl_array_size(jget(t,
		    "entries")))
			h_fmt(h, "<p class=\"dim\">The first %d of %lld.</p>",
			    (int)ucl_array_size(jget(t, "entries")),
			    (long long)jint(t, "count", 0));
		h_raw(h, "</section>");
	}
	if (n == 0)
		h_raw(h, "<div class=\"empty small\"><p>No table.</p></div>");
}

/* NAT instances, pipes and queues: shown as ipfw shows them. */
static void
view_objects(struct html *h)
{
	static const char *const kinds[] = { "nat", "nat64lsn", "nat64stl",
	    "nat64clat", "nptv6", "pipe", "queue", "sched" };
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	size_t			 i;

	h_raw(h, "<h4 class=\"family\">NAT, pipes and queues</h4><p class=\""
	    "dim\">What a rule names by a number or a name and is made "
	    "apart from the rules: a NAT instance (<code>nat 1 config if "
	    "em0 same_ports</code>), NAT64 and NPTv6 (<code>nat64lsn NAT64 "
	    "create prefix4 192.0.2.0/24</code>), a pipe, queue or "
	    "scheduler of dummynet (<code>pipe 1 config bw 10Mbit/s</code>)."
	    " The words are ipfw's; with <b>keep</b> they are a line of the "
	    "kept rules too.</p>");
	/* A NAT instance, asked for by what it is, not in ipfw's words. */
	h_raw(h, "<form data-form=\"fw-nat\" class=\"fw-obj\"><b>NAT</b>"
	    "<label>number<input name=\"num\" inputmode=\"numeric\" size=\"5\""
	    " placeholder=\"1\"></label><label>on<select name=\"on\"><option "
	    "value=\"if\">the address of interface</option><option value=\"ip"
	    "\">the address</option></select></label><input name=\"what\" "
	    "spellcheck=\"false\" autocomplete=\"off\" size=\"14\" "
	    "placeholder=\"em0, or 192.0.2.1\"><span class=\"opts\">"
	    "<label class=\"toggle\" title=\"Keep the ports as they are when "
	    "it can\"><input type=\"checkbox\" name=\"same_ports\" checked>"
	    "<span>same ports</span></label><label class=\"toggle\" title=\""
	    "Only what comes from private addresses\"><input type=\"checkbox\" "
	    "name=\"unreg_only\"><span>private only</span></label><label "
	    "class=\"toggle\" title=\"Forget the translations when the "
	    "interface's address changes\"><input type=\"checkbox\" name=\""
	    "reset\"><span>reset</span></label><label class=\"toggle\" title=\""
	    "Drop what comes in and was not asked for\"><input type=\"checkbox"
	    "\" name=\"deny_in\"><span>deny in</span></label><label class=\""
	    "toggle\"><input type=\"checkbox\" name=\"log\"><span>log</span>"
	    "</label></span><textarea name=\"redirects\" rows=\"2\" "
	    "spellcheck=\"false\" placeholder=\"ports sent on, one a line: "
	    "tcp 10.0.0.5:80 8080\"></textarea><label class=\"toggle\"><input "
	    "type=\"checkbox\" name=\"persist\" checked><span>keep</span>"
	    "</label><button class=\"small\">Configure</button></form>");
	/* A pipe of dummynet: how fast, how late, how lossy. */
	h_raw(h, "<form data-form=\"fw-pipe\" class=\"fw-obj\"><b>Pipe</b>"
	    "<label>number<input name=\"num\" inputmode=\"numeric\" size=\"5\""
	    " placeholder=\"1\"></label><label>bandwidth<input name=\"bw\" "
	    "inputmode=\"decimal\" size=\"6\" placeholder=\"no limit\"><select "
	    "name=\"unit\"><option>Kbit/s</option><option selected>Mbit/s"
	    "</option><option>Gbit/s</option></select></label><label>delay"
	    "<input name=\"delay\" inputmode=\"numeric\" size=\"5\" "
	    "placeholder=\"0\"><span class=\"dim\">ms</span></label><label>"
	    "loss<input name=\"plr\" inputmode=\"decimal\" size=\"5\" "
	    "placeholder=\"0\"><span class=\"dim\">%</span></label><label>"
	    "queue<input name=\"queue\" inputmode=\"numeric\" size=\"5\" "
	    "placeholder=\"50\"><span class=\"dim\">slots</span></label>"
	    "<label>for<select name=\"mask\"><option value=\"\">all at once"
	    "</option><option value=\"src\">each source address</option>"
	    "<option value=\"dst\">each destination address</option></select>"
	    "</label><label class=\"toggle\"><input type=\"checkbox\" name=\""
	    "persist\" checked><span>keep</span></label><button class=\"small"
	    "\">Configure</button></form>");
	h_raw(h, "<form data-form=\"fw-object\" class=\"fw-add\" title=\""
	    "Anything else, in ipfw's own words\"><select name=\"kind\">");
	for (i = 0; i < nitems(kinds); i++)
		h_fmt(h, "<option>%s</option>", kinds[i]);
	h_raw(h, "</select><input name=\"words\" spellcheck=\"false\" "
	    "autocomplete=\"off\" placeholder=\"1 config if em0 same_ports; "
	    "or 1 delete\"><label class=\"toggle\"><input type=\"checkbox\" "
	    "name=\"persist\" checked><span>keep</span></label><button class="
	    "\"small\">Do</button></form><h4 class=\"family\">NAT</h4>");
	if (ucl_array_size(jget(fw.data, "nat")) == 0)
		h_raw(h, "<p class=\"dim\">No NAT instance, or ipfw_nat is "
		    "not in the kernel.</p>");
	else {
		h_raw(h, "<pre class=\"mono\">");
		it = NULL;
		while ((o = ucl_object_iterate(jget(fw.data, "nat"), &it,
		    true)) != NULL) {
			h_txt(h, ucl_object_tostring_forced(o));
			h_raw(h, "\n");
		}
		h_raw(h, "</pre>");
	}
	h_raw(h, "<h4 class=\"family\">Pipes</h4>");
	if (ucl_array_size(jget(fw.data, "pipes")) == 0)
		h_raw(h, "<p class=\"dim\">No pipe, or dummynet is not in the "
		    "kernel.</p>");
	else {
		h_raw(h, "<pre class=\"mono\">");
		it = NULL;
		while ((o = ucl_object_iterate(jget(fw.data, "pipes"), &it,
		    true)) != NULL) {
			h_txt(h, ucl_object_tostring_forced(o));
			h_raw(h, "\n");
		}
		h_raw(h, "</pre>");
	}
}

static const ucl_object_t *
rule_at(const ucl_object_t *arr, long long num, bool live)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(arr, &it, true)) != NULL)
		if (jint(o, "num", 0) == num && !(live && jbool(o,
		    "disabled")))
			return (o);
	return (NULL);
}

/* What Apply would do: the kept rules beside those of the kernel. */
static void
view_diff(struct html *h)
{
	const ucl_object_t	*live, *kept, *o, *k;
	ucl_object_iter_t	 it;
	int			 add, del, differ;

	live = jget(fw.data, "rules");
	kept = jget(fw.data, "kept");
	h_raw(h, "<h4 class=\"family\">What Apply would change</h4><p class="
	    "\"dim\">Apply makes the kept rules the whole ruleset. Beside "
	    "what the kernel has now, that is these rules more, these "
	    "fewer, and these whose words are not the same: which may be "
	    "only how ipfw writes a rule back (<code>dst-port</code> for a "
	    "port, a name for a number), and may be a rule that was "
	    "changed on one side.</p><table class=\"net fw-diff\"><thead><tr>"
	    "<th></th><th>Number</th><th>Rule</th></tr></thead><tbody>");
	add = del = differ = 0;
	it = NULL;
	while ((k = ucl_object_iterate(kept, &it, true)) != NULL) {
		if ((o = rule_at(live, jint(k, "num", 0), true)) == NULL) {
			add++;
			h_fmt(h, "<tr class=\"d-add pick\" data-act=\"fw-goto\" "
			    "data-arg=\"%lld\"><td>+ added</td><td><b>%05lld</b>"
			    "</td><td class=\"mono\">", (long long)jint(k, "num",
			    0), (long long)jint(k, "num", 0));
			h_txt(h, jstr(k, "text"));
			h_raw(h, "</td></tr>");
		} else if (jstr(o, "text") != NULL && jstr(k, "text") != NULL &&
		    strcmp(jstr(o, "text"), jstr(k, "text")) != 0) {
			differ++;
			h_fmt(h, "<tr class=\"d-chg pick\" data-act=\"fw-goto\" "
			    "data-arg=\"%lld\"><td>~ differs</td><td><b>%05lld"
			    "</b></td><td class=\"mono\"><del>", (long long)
			    jint(k, "num", 0), (long long)jint(k, "num", 0));
			h_txt(h, jstr(o, "text"));
			h_raw(h, "</del><br><ins>");
			h_txt(h, jstr(k, "text"));
			h_raw(h, "</ins></td></tr>");
		}
	}
	it = NULL;
	while ((o = ucl_object_iterate(live, &it, true)) != NULL) {
		if (jbool(o, "disabled") || jint(o, "num", 0) == 65535 ||
		    rule_at(kept, jint(o, "num", 0), false) != NULL)
			continue;
		del++;
		h_fmt(h, "<tr class=\"d-del pick\" data-act=\"fw-goto\" "
		    "data-arg=\"%lld\"><td>− removed</td><td><b>%05lld</b></td>"
		    "<td class=\"mono\">", (long long)jint(o, "num", 0),
		    (long long)jint(o, "num", 0));
		h_txt(h, jstr(o, "text"));
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table>");
	if (add + del + differ == 0)
		h_raw(h, "<div class=\"empty small\"><p>Nothing: the kernel "
		    "has the kept rules, number for number and word for "
		    "word.</p></div>");
	else
		h_fmt(h, "<p><b>%d</b> added · <b>%d</b> removed · <b>%d</b> "
		    "with other words. <button class=\"small\" data-act=\""
		    "fw-apply\">Apply the kept rules</button></p>", add, del,
		    differ);
}

/*
 * A packet followed through the rules of the kernel, as well as a page
 * can: a rule's words are read for what they ask of the protocol, the
 * addresses, the port, the direction and the interface, and each rule
 * matches, does not, or cannot be told (me, a table that was cut off,
 * an option not known here).  What cannot be told is taken as matching
 * and said so.
 */
enum { T_NO, T_YES, T_MAYBE };

static bool
v4(const char *s, unsigned int *ip, int *plen)
{
	unsigned int	a, b, c, d;
	int		n, len;

	len = 32;
	n = 0;
	if (sscanf(s, "%u.%u.%u.%u%n", &a, &b, &c, &d, &n) != 4 || a > 255 ||
	    b > 255 || c > 255 || d > 255)
		return (false);
	if (s[n] == '/')
		len = atoi(s + n + 1);
	else if (s[n] != '\0')
		return (false);
	if (len < 0 || len > 32)
		return (false);
	*ip = a << 24 | b << 16 | c << 8 | d;
	*plen = len;
	return (true);
}

static int
in_net(const char *addr, const char *net)
{
	unsigned int	a, n, mask;
	int		pa, pn;

	if (!v4(addr, &a, &pa) || !v4(net, &n, &pn))
		return (strchr(addr, ':') != NULL && strchr(net, ':') !=
		    NULL ? (strcmp(addr, net) == 0 ? T_YES : T_MAYBE) : T_NO);
	mask = pn == 0 ? 0 : 0xffffffffu << (32 - pn);
	return ((a & mask) == (n & mask) ? T_YES : T_NO);
}

/* Does the address answer the rule's word for one? */
static int
addr_match(const char *addr, const char *word)
{
	const ucl_object_t	*t, *e;
	ucl_object_iter_t	 it, eit;
	char			 name[64];
	int			 r, best;

	if (strcmp(word, "any") == 0)
		return (T_YES);
	if (addr[0] == '\0')
		return (T_MAYBE);
	if (strcmp(word, "me") == 0 || strcmp(word, "me6") == 0)
		return ((strchr(addr, ':') != NULL) == (word[2] == '6') ?
		    T_MAYBE : T_NO);
	if (strncmp(word, "table(", 6) == 0) {
		snprintf(name, sizeof(name), "%.*s", (int)strcspn(word + 6,
		    ",)"), word + 6);
		it = NULL;
		while ((t = ucl_object_iterate(jget(fw.data, "tables"), &it,
		    true)) != NULL) {
			if (jstr(t, "name") == NULL || strcmp(jstr(t, "name"),
			    name) != 0)
				continue;
			best = T_NO;
			eit = NULL;
			while ((e = ucl_object_iterate(jget(t, "entries"),
			    &eit, true)) != NULL)
				if ((r = in_net(addr, jstr(e, "key") != NULL ?
				    jstr(e, "key") : "")) == T_YES)
					return (T_YES);
				else if (r == T_MAYBE)
					best = T_MAYBE;
			return (jint(t, "count", 0) > (int64_t)ucl_array_size(
			    jget(t, "entries")) ? T_MAYBE : best);
		}
		return (T_MAYBE);
	}
	if (strchr(word, '.') != NULL || strchr(word, ':') != NULL)
		return (in_net(addr, word));
	return (T_MAYBE);
}

static bool
is_number_list(const char *w)
{

	return (w[0] != '\0' && w[strspn(w, "0123456789,-")] == '\0');
}

static int
port_match(const char *port, const char *list)
{
	char	*copy, *it, *one, *dash;
	int	 p, r;

	if (port[0] == '\0')
		return (T_MAYBE);
	p = atoi(port);
	r = T_NO;
	copy = strdup(list);
	for (it = copy; (one = strsep(&it, ",")) != NULL; ) {
		if ((dash = strchr(one, '-')) != NULL) {
			*dash = '\0';
			if (p >= atoi(one) && p <= atoi(dash + 1))
				r = T_YES;
		} else if (atoi(one) == p)
			r = T_YES;
	}
	free(copy);
	return (r);
}

#define	AND(r, x)	do {						\
	int _x = (x);							\
	if (_x == T_NO)							\
		(r) = T_NO;						\
	else if (_x == T_MAYBE && (r) == T_YES)				\
		(r) = T_MAYBE;						\
} while (0)

/*
 * Whether the packet asked about matches the rule; *actp is where the
 * rule's action begins in v, *argp the number after skipto, call or nat.
 */
static int
rule_match(char **v, int n, const char **actp, int *argp)
{
	const char	*proto;
	int		 i, r, x;
	bool		 six, not;

	i = 0;
	*argp = 0;
	/* prob 0.5, and what else comes before the action. */
	if (i < n && strcmp(v[i], "prob") == 0)
		i += 2;
	if (i >= n)
		return (T_NO);
	*actp = v[i];
	if (strcmp(v[i], "skipto") == 0 || strcmp(v[i], "call") == 0 ||
	    strcmp(v[i], "nat") == 0 || strcmp(v[i], "divert") == 0 ||
	    strcmp(v[i], "pipe") == 0 || strcmp(v[i], "queue") == 0 ||
	    strcmp(v[i], "setfib") == 0 || strcmp(v[i], "tee") == 0 ||
	    strcmp(v[i], "fwd") == 0 || strcmp(v[i], "forward") == 0 ||
	    strcmp(v[i], "unreach") == 0 || strcmp(v[i], "unreach6") == 0 ||
	    strcmp(v[i], "nat64lsn") == 0 || strcmp(v[i], "nat64stl") == 0 ||
	    strcmp(v[i], "nat64clat") == 0 || strcmp(v[i], "nptv6") == 0 ||
	    strcmp(v[i], "netgraph") == 0 || strcmp(v[i], "ngtee") == 0) {
		if (i + 1 < n)
			*argp = atoi(v[i + 1]);
		i += 2;
	} else if (strcmp(v[i], "check-state") == 0) {
		/* A state there may be: only the kernel knows. */
		return (T_MAYBE);
	} else
		i++;
	/* log, logamount n, tag n, altq name: not what is matched. */
	while (i < n && (strcmp(v[i], "log") == 0 || strcmp(v[i],
	    "logamount") == 0 || strcmp(v[i], "tag") == 0 || strcmp(v[i],
	    "untag") == 0 || strcmp(v[i], "altq") == 0))
		i += strcmp(v[i], "log") == 0 ? 1 : 2;
	if (i >= n)
		return (T_YES);
	r = T_YES;
	six = strchr(fw.t_dst, ':') != NULL || strchr(fw.t_src, ':') != NULL;
	proto = v[i++];
	if (strcmp(proto, "ip") != 0 && strcmp(proto, "all") != 0) {
		if (strcmp(proto, "ip4") == 0 || strcmp(proto, "ipv4") == 0)
			AND(r, six ? T_NO : T_YES);
		else if (strcmp(proto, "ip6") == 0 || strcmp(proto, "ipv6") ==
		    0)
			AND(r, six ? T_YES : T_NO);
		else if (proto[0] == '{' || proto[0] == '(')
			AND(r, T_MAYBE);
		else if (strcmp(proto, "from") == 0)
			i--;
		else
			AND(r, strcmp(proto, fw.t_proto) == 0 || (strcmp(proto,
			    "ipv6-icmp") == 0 && strcmp(fw.t_proto, "icmp") ==
			    0 && six) ? T_YES : T_NO);
	}
	if (i < n && strcmp(v[i], "from") == 0) {
		i++;
		not = i < n && strcmp(v[i], "not") == 0;
		if (not)
			i++;
		if (i < n) {
			x = addr_match(fw.t_src, v[i++]);
			AND(r, not ? (x == T_YES ? T_NO : x == T_NO ? T_YES :
			    T_MAYBE) : x);
		}
		/* A source port: not asked for here. */
		if (i < n && is_number_list(v[i])) {
			AND(r, T_MAYBE);
			i++;
		}
	}
	if (i < n && strcmp(v[i], "to") == 0) {
		i++;
		not = i < n && strcmp(v[i], "not") == 0;
		if (not)
			i++;
		if (i < n) {
			x = addr_match(fw.t_dst, v[i++]);
			AND(r, not ? (x == T_YES ? T_NO : x == T_NO ? T_YES :
			    T_MAYBE) : x);
		}
		if (i < n && is_number_list(v[i]))
			AND(r, port_match(fw.t_port, v[i++]));
	}
	for (; i < n && r != T_NO; i++) {
		if (strcmp(v[i], "in") == 0)
			AND(r, fw.t_out ? T_NO : T_YES);
		else if (strcmp(v[i], "out") == 0)
			AND(r, fw.t_out ? T_YES : T_NO);
		else if ((strcmp(v[i], "via") == 0 || strcmp(v[i], "recv") ==
		    0 || strcmp(v[i], "xmit") == 0) && i + 1 < n) {
			if (strcmp(v[i], "recv") == 0 && fw.t_out)
				AND(r, T_MAYBE);
			else if (strcmp(v[i], "xmit") == 0 && !fw.t_out)
				AND(r, T_NO);
			else if (fw.t_if[0] == '\0' || strcmp(v[i + 1],
			    "any") == 0 || strchr(v[i + 1], '*') != NULL ||
			    strncmp(v[i + 1], "table(", 6) == 0)
				AND(r, strcmp(v[i + 1], "any") == 0 ? T_YES :
				    T_MAYBE);
			else
				AND(r, strcmp(v[i + 1], fw.t_if) == 0 ? T_YES :
				    T_NO);
			i++;
		} else if (strcmp(v[i], "dst-port") == 0 && i + 1 < n)
			AND(r, port_match(fw.t_port, v[++i]));
		else if (strcmp(v[i], "keep-state") == 0 || strcmp(v[i],
		    "record-state") == 0 || strcmp(v[i], "setup") == 0 ||
		    strncmp(v[i], ":", 1) == 0 || strcmp(v[i], "//") == 0)
			;	/* the first packet of a connection is asked about */
		else if (strcmp(v[i], "established") == 0)
			AND(r, T_NO);
		else if (strcmp(v[i], "//") == 0)
			break;
		else
			AND(r, T_MAYBE);
	}
	return (r);
}

static int
num_cmp(const void *a, const void *b)
{
	int64_t	x, y;

	x = jint(*(const ucl_object_t *const *)a, "num", 0);
	y = jint(*(const ucl_object_t *const *)b, "num", 0);
	return (x < y ? -1 : x > y);
}

static void	view_ktrace(struct html *);

static void
view_trace_fw(struct html *h)
{
	const ucl_object_t	**rules, *o;
	ucl_object_iter_t	  it;
	const char		 *act, *verdict;
	char			 *copy, *p, *w, *v[128];
	int			  n, nr, i, r, arg, steps, stack[16], sp;
	bool			  unsure;

	h_raw(h, "<h4 class=\"family\">Follow a packet</h4><p class=\"dim\">"
	    "The first packet of a connection, walked through the rules "
	    "the kernel has now: which it meets, where it is sent on, and "
	    "what becomes of it. A rule the page cannot judge (me, a state, "
	    "an option it does not know) is taken as met and marked; the "
	    "kernel alone knows.</p><form data-form=\"fw-trace\" class=\""
	    "fw-add fw-trace\"><select name=\"proto\">");
	{
		static const char *const protos[] = { "tcp", "udp", "icmp",
		    "ip" };
		size_t	k;

		for (k = 0; k < nitems(protos); k++)
			h_fmt(h, "<option%s>%s</option>", strcmp(fw.t_proto,
			    protos[k]) == 0 ? " selected" : "", protos[k]);
	}
	h_raw(h, "</select><input name=\"src\" spellcheck=\"false\" "
	    "autocomplete=\"off\" placeholder=\"from 203.0.113.9\"");
	h_attr(h, "value", fw.t_src);
	h_raw(h, "><input name=\"dst\" spellcheck=\"false\" autocomplete=\""
	    "off\" placeholder=\"to 192.0.2.1\"");
	h_attr(h, "value", fw.t_dst);
	h_raw(h, "><input name=\"port\" inputmode=\"numeric\" size=\"6\" "
	    "placeholder=\"port\"");
	h_attr(h, "value", fw.t_port);
	h_fmt(h, "><select name=\"dir\"><option value=\"in\"%s>coming in"
	    "</option><option value=\"out\"%s>going out</option></select>"
	    "<input name=\"iface\" spellcheck=\"false\" autocomplete=\"off\" "
	    "size=\"8\" placeholder=\"on em0\"", fw.t_out ? "" : " selected",
	    fw.t_out ? " selected" : "");
	h_attr(h, "value", fw.t_if);
	h_raw(h, "><button class=\"small\">Follow</button></form>");
	if (!fw.t_asked) {
		view_ktrace(h);
		return;
	}
	nr = (int)ucl_array_size(jget(fw.data, "rules"));
	if ((rules = calloc((size_t)nr + 1, sizeof(*rules))) == NULL)
		abort();
	nr = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(fw.data, "rules"), &it, true)) !=
	    NULL)
		if (!jbool(o, "disabled"))
			rules[nr++] = o;
	qsort(rules, (size_t)nr, sizeof(*rules), num_cmp);
	h_raw(h, "<ol class=\"fw-steps\">");
	verdict = NULL;
	unsure = false;
	sp = 0;
	steps = 0;
	for (i = 0; i < nr && verdict == NULL && steps < 400; i++) {
		o = rules[i];
		copy = strdup(jstr(o, "text") != NULL ? jstr(o, "text") : "");
		n = 0;
		p = copy;
		while (n < 127 && (w = strsep(&p, " \t")) != NULL)
			if (*w != '\0')
				v[n++] = w;
		act = "";
		r = rule_match(v, n, &act, &arg);
		if (r == T_NO) {
			free(copy);
			continue;
		}
		steps++;
		if (r == T_MAYBE)
			unsure = true;
		h_fmt(h, "<li class=\"%s pick\" data-act=\"fw-goto\" data-arg=\""
		    "%lld\"><b>%05lld</b> <code>", r == T_YES ? "met" :
		    "maybe", (long long)jint(o, "num", 0), (long long)jint(o,
		    "num", 0));
		h_txt(h, jstr(o, "text"));
		h_fmt(h, "</code> <span class=\"chip%s\">%s</span> ", r ==
		    T_YES ? "" : " warn", r == T_YES ? "met" : "may be met");
		if (strcmp(act, "allow") == 0 || strcmp(act, "accept") == 0 ||
		    strcmp(act, "pass") == 0 || strcmp(act, "permit") == 0)
			verdict = "let through";
		else if (strcmp(act, "deny") == 0 || strcmp(act, "drop") == 0)
			verdict = "dropped";
		else if (strcmp(act, "reject") == 0 || strncmp(act, "unreach",
		    7) == 0 || strcmp(act, "reset") == 0 || strcmp(act,
		    "reset6") == 0 || strcmp(act, "abort") == 0)
			verdict = "refused, and its sender told";
		else if (strcmp(act, "fwd") == 0 || strcmp(act, "forward") ==
		    0 || strcmp(act, "divert") == 0)
			verdict = "handed on, away from the rules";
		else if (strcmp(act, "skipto") == 0 && arg > 0) {
			h_fmt(h, "<small>on to %d</small>", arg);
			while (i + 1 < nr && jint(rules[i + 1], "num", 0) < arg)
				i++;
		} else if (strcmp(act, "call") == 0 && arg > 0 && sp < 16) {
			h_fmt(h, "<small>into %d, and back</small>", arg);
			stack[sp++] = i;
			while (i + 1 < nr && jint(rules[i + 1], "num", 0) < arg)
				i++;
		} else if (strcmp(act, "return") == 0) {
			if (sp > 0) {
				i = stack[--sp];
				h_fmt(h, "<small>back after %05lld</small>",
				    (long long)jint(rules[i], "num", 0));
			}
		} else if (strcmp(act, "check-state") == 0)
			h_raw(h, "<small>passes here once a rule kept its "
			    "state; a first packet goes on</small>");
		else if (strncmp(act, "nat", 3) == 0 || strcmp(act, "nptv6") ==
		    0)
			h_fmt(h, "<small>translated by %s %d, and on (when "
			    "net.inet.ip.fw.one_pass is 0)</small>", act, arg);
		else
			h_raw(h, "<small>and on</small>");
		h_raw(h, "</li>");
		free(copy);
	}
	free(rules);
	h_raw(h, "</ol>");
	h_fmt(h, "<div class=\"notice %s\"><b>%s</b>%s</div>", verdict ==
	    NULL ? "warn" : strcmp(verdict, "let through") == 0 ? "info" :
	    "bad", verdict != NULL ? verdict : "No rule decides it, which "
	    "ipfw's last rule then does", unsure ? ", if every rule marked "
	    "\"may be met\" is, and none before it decided otherwise." :
	    ".");
	view_ktrace(h);
}

static void
ktrace_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	fw.k_loading = false;
	if (fw.k_data != NULL)
		ucl_object_unref(fw.k_data);
	fw.k_data = NULL;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(fw.k_error, sizeof(fw.k_error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	fw.k_error[0] = '\0';
	fw.k_data = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
}

/*
 * The kernel's own answer: for some seconds, the packets of an address
 * as ipfw decided them, each with the rule that did (arcana-agent's
 * fw-trace, ipfw:::rule-matched told to dtrace).
 */
static void
view_ktrace(struct html *h)
{
	static const struct tcol cols[] = {
		{ "ms", "ms", true }, { "Verdict", "verdict", false },
		{ "Way", "direction", false }, { "Interface", "interface",
		false }, { "Proto", "proto", true }, { "From", "source", false },
		{ "To", "destination", false }, { "Rule", "rule", true },
	};
	const ucl_object_t	**rows, *o;
	const char		*addr, *v;
	int			  r;

	addr = fw.k_addr[0] != '\0' ? fw.k_addr : fw.t_dst[0] != '\0' ?
	    fw.t_dst : fw.t_src;
	h_raw(h, "<h4 class=\"family\">What the kernel decides</h4><p class="
	    "\"dim\">Not a reading of the rules: the packets to or from an "
	    "address that really cross the firewall, for some seconds, each "
	    "with the rule that decided it, as the kernel tells it "
	    "(ipfw's rule-matched probe, through dtrace; the host needs "
	    "<code>kldload dtraceall</code>).</p><form data-form=\"fw-ktrace"
	    "\" class=\"fw-add fw-trace\"><input name=\"address\" spellcheck="
	    "\"false\" autocomplete=\"off\" placeholder=\"address, 192.0.2.1"
	    "\"");
	h_attr(h, "value", addr);
	h_fmt(h, "><input name=\"seconds\" inputmode=\"numeric\" size=\"4\" "
	    "value=\"%d\" title=\"How long to watch, 1 to 60 seconds\"><span "
	    "class=\"dim\">s</span><button class=\"small\"%s>%s</button>"
	    "</form>", fw.k_secs > 0 ? fw.k_secs : 10, fw.k_loading ?
	    " disabled" : "", fw.k_loading ? "Watching…" : "Watch the "
	    "kernel");
	if (fw.k_error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, fw.k_error);
		h_raw(h, "</div>");
	}
	if (fw.k_data == NULL)
		return;
	h_raw(h, "<table class=\"net ktrace\">");
	tbl_head(h, "fwktrace", cols, 8, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("fwktrace", jget(fw.k_data, "packets"), cols, 8,
	    app.filter);
	for (r = 0; (o = rows[r]) != NULL; r++) {
		v = jstr(o, "verdict") != NULL ? jstr(o, "verdict") : "?";
		h_fmt(h, "<tr><td class=\"dim\">%lld</td><td><span class=\"chip"
		    "%s\">", (long long)jint(o, "ms", 0), strcmp(v, "pass") ==
		    0 ? "" : strcmp(v, "deny") == 0 ? " bad" : " warn");
		h_txt(h, v);
		h_raw(h, "</span></td><td>");
		h_txt(h, jstr(o, "direction"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(o, "interface"));
		h_fmt(h, "</td><td>%s</td><td class=\"mono\">", jint(o,
		    "proto", 0) == 6 ? "tcp" : jint(o, "proto", 0) == 17 ?
		    "udp" : jint(o, "proto", 0) == 1 || jint(o, "proto", 0) ==
		    58 ? "icmp" : "ip");
		h_txt(h, jstr(o, "source"));
		if (jint(o, "sport", 0) != 0)
			h_fmt(h, " :%lld", (long long)jint(o, "sport", 0));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(o, "destination"));
		if (jint(o, "dport", 0) != 0)
			h_fmt(h, " :%lld", (long long)jint(o, "dport", 0));
		h_fmt(h, "</td><td><button class=\"ghost small\" data-act=\""
		    "fw-goto\" data-arg=\"%lld\" title=\"To the rule\">%05lld"
		    "</button></td></tr>", (long long)jint(o, "rule", 0),
		    (long long)jint(o, "rule", 0));
	}
	h_raw(h, "</tbody></table>");
	if (r == 0)
		h_raw(h, "<div class=\"empty small\"><p>No packet of it crossed "
		    "the firewall while the kernel was watched.</p></div>");
	else
		h_fmt(h, "<p class=\"dim\">%d packet%s in %lld s%s.</p>", r,
		    r == 1 ? "" : "s", (long long)jint(fw.k_data, "seconds", 0),
		    r >= jint(fw.k_data, "limit", 0) ? ", as many as were "
		    "asked for" : "");
	free(rows);
}

static void
fwlog_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	fw.log_loading = false;
	if (fw.log != NULL)
		ucl_object_unref(fw.log);
	fw.log = NULL;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(fw.log_error, sizeof(fw.log_error), "%s", status ==
		    200 && jstr(o, "error") != NULL ? jstr(o, "error") : err !=
		    NULL ? err : "no answer");
		return;
	}
	fw.log_error[0] = '\0';
	fw.log = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
}

static void
fwlog_read(struct server *s)
{
	char	url[128];

	if (fw.log_loading)
		return;
	fw.log_loading = true;
	snprintf(url, sizeof(url), "/api/servers/%s/log?name=security&filter="
	    "ipfw%%3A&lines=300", s->id);
	api("GET", url, NULL, fwlog_cb, NULL);
}

/* What the rules with log wrote into the security log. */
static void
view_fwlog(struct html *h)
{
	static const struct tcol cols[] = {
		{ "Time", "time", false }, { "What ipfw wrote", "text",
		false },
	};
	const ucl_object_t	**rows, *o;
	int			  n, i;

	h_raw(h, "<h4 class=\"family\">Logged packets <button class=\"ghost "
	    "small\" data-act=\"fw-sect\" data-arg=\"-8\">Read again</button>"
	    "</h4><p class=\"dim\">A rule with <code>log</code> in it writes "
	    "a line for each packet it meets, up to its <code>logamount"
	    "</code>, into <code>/var/log/security</code>, when <code>"
	    "net.inet.ip.fw.verbose</code> is 1");
	if (jget(fw.data, "verbose") != NULL)
		h_fmt(h, " (it is %s on this host)", jbool(fw.data, "verbose") ?
		    "1" : "0: set it under Sysctl");
	h_raw(h, ". The newest first.</p>");
	if (fw.log_error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, fw.log_error);
		h_raw(h, "</div>");
	}
	if (fw.log == NULL) {
		h_raw(h, fw.log_loading ? "<div class=\"empty\"><p>Reading…"
		    "</p></div>" : "");
		return;
	}
	h_raw(h, "<table class=\"net logs fwlog\">");
	tbl_head(h, "fwlog", cols, 2, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("fwlog", jget(fw.log, "lines"), cols, 2, app.filter);
	for (n = 0; rows[n] != NULL; n++)
		;
	for (i = 0; i < n; i++) {
		o = rows[tbl_sorted("fwlog") ? i : n - 1 - i];
		h_raw(h, "<tr><td class=\"when\">");
		h_txt(h, jstr(o, "time"));
		h_raw(h, "</td><td class=\"msg\">");
		h_txt(h, jstr(o, "text"));
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (n == 0)
		h_raw(h, "<div class=\"empty small\"><p>No line of ipfw's in "
		    "the security log.</p></div>");
}

static bool
words_ok(const char *s)
{

	return (s[0] != '\0' && strlen(s) < 400 && s[strspn(s, "abcdefghijklm"
	    "nopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._:/,-@{}!()="
	    "<>*+%[]")] == '\0');
}

/*
 * The words that may come next in a rule being typed, by ipfw's order:
 * the action (with its number, for one that names a rule or a pipe),
 * then what it is (ip, tcp…), from an address to an address, then
 * the options.  Each offered as the whole line with it, for the
 * field's list: the browser shows those that begin as typed.
 */
static void
rule_words(struct html *h)
{
	static const char *const actions[] = { "allow", "deny", "reject",
	    "count", "skipto", "call", "return", "check-state", "nat",
	    "pipe", "queue", "fwd", "divert", "tee", "setfib", "tag",
	    "unreach", "reset", "log" };
	static const char *const protos[] = { "ip", "all", "tcp", "udp",
	    "icmp", "ipv6-icmp", "ip4", "ip6" };
	static const char *const addrs[] = { "any", "me", "me6", "not" };
	static const char *const opts[] = { "in", "out", "via", "recv",
	    "xmit", "keep-state", "record-state", "setup", "established",
	    "frag", "limit", "tcpflags", "icmptypes", "//" };
	static const char *const numbered[] = { "skipto", "call", "nat",
	    "pipe", "queue", "setfib", "tag", "divert", "tee", "unreach" };
	const char *const	*list;
	const ucl_object_t	*t;
	ucl_object_iter_t	 it;
	char			 copy[400], *p, *w, *v[64], head[400], extra[96];
	int			 n, nl, i, from, to;
	size_t			 k;
	bool			 tbl;

	h_raw(h, "<datalist id=\"fw-words\">");
	snprintf(copy, sizeof(copy), "%s", fw.typed);
	n = 0;
	p = copy;
	while (n < 63 && (w = strsep(&p, " \t")) != NULL)
		if (*w != '\0')
			v[n++] = w;
	/* The words done are those before the last space. */
	k = strlen(fw.typed);
	if (k > 0 && fw.typed[k - 1] != ' ' && n > 0)
		n--;
	snprintf(head, sizeof(head), "%.*s", (int)(k > 0 && fw.typed[k - 1] !=
	    ' ' ? strrchr(fw.typed, ' ') != NULL ? strrchr(fw.typed, ' ') -
	    fw.typed + 1 : 0 : k), fw.typed);
	from = to = -1;
	for (i = 0; i < n; i++) {
		if (strcmp(v[i], "from") == 0)
			from = i;
		else if (strcmp(v[i], "to") == 0)
			to = i;
	}
	list = NULL;
	nl = 0;
	tbl = false;
	extra[0] = '\0';
	if (n == 0) {
		list = actions;
		nl = (int)nitems(actions);
	} else if (to >= 0 && to == n - 1) {
		list = addrs;
		nl = (int)nitems(addrs);
		tbl = true;
	} else if (to >= 0) {
		list = opts;
		nl = (int)nitems(opts);
	} else if (from >= 0 && from == n - 1) {
		list = addrs;
		nl = (int)nitems(addrs);
		tbl = true;
	} else if (from >= 0) {
		snprintf(extra, sizeof(extra), "to");
	} else {
		for (k = 0; k < nitems(numbered); k++)
			if (strcmp(v[n - 1], numbered[k]) == 0)
				break;
		if (k < nitems(numbered)) {
			/* A rule's number: where each part begins. */
			if (strcmp(v[n - 1], "skipto") == 0 || strcmp(v[n - 1],
			    "call") == 0)
				for (k = 0; k < nitems(sects); k++)
					h_fmt(h, "<option value=\"%s%d\">%s"
					    "</option>", head, sects[k].lo,
					    sects[k].name);
		} else {
			/* After the action and its number: what it is, or
			 * from, when it was already said. */
			list = protos;
			nl = (int)nitems(protos);
			for (i = 0; i < n; i++)
				for (k = 0; k < nitems(protos); k++)
					if (strcmp(v[i], protos[k]) == 0)
						list = NULL;
			if (list == NULL)
				snprintf(extra, sizeof(extra), "from");
		}
	}
	for (i = 0; i < nl; i++) {
		snprintf(copy, sizeof(copy), "%s%s", head, list[i]);
		h_raw(h, "<option");
		h_attr(h, "value", copy);
		h_raw(h, "></option>");
	}
	if (extra[0] != '\0') {
		snprintf(copy, sizeof(copy), "%s%s", head, extra);
		h_raw(h, "<option");
		h_attr(h, "value", copy);
		h_raw(h, "></option>");
	}
	/* The host's tables, as an address. */
	it = NULL;
	while (tbl && (t = ucl_object_iterate(jget(fw.data, "tables"), &it,
	    true)) != NULL)
		if (jstr(t, "name") != NULL) {
			snprintf(copy, sizeof(copy), "%stable(%s)", head,
			    jstr(t, "name"));
			h_raw(h, "<option");
			h_attr(h, "value", copy);
			h_raw(h, "></option>");
		}
	h_raw(h, "</datalist>");
}

/* A field of digits, and how many at most; "" when empty is allowed. */
static const char *
digits(const ucl_object_t *f, const char *name, size_t max)
{
	const char	*v;

	v = jstr(f, name) != NULL ? jstr(f, name) : "";
	if (strlen(v) > max || v[strspn(v, "0123456789")] != '\0')
		return (NULL);
	return (v);
}

/* A field of a number that may have a fraction: 10, 2.5. */
static const char *
decimal(const ucl_object_t *f, const char *name)
{
	const char	*v;

	v = jstr(f, name) != NULL ? jstr(f, name) : "";
	if (strlen(v) > 12 || v[strspn(v, "0123456789.")] != '\0' ||
	    strchr(v, '.') != strrchr(v, '.'))
		return (NULL);
	return (v);
}

/* The NAT form as ipfw's words: "1 config if em0 same_ports ...". */
static bool
nat_words(const ucl_object_t *f, char *w, size_t len)
{
	static const char *const flags[] = { "same_ports", "unreg_only",
	    "reset", "deny_in", "log" };
	const char	*num, *what, *on, *rd;
	char		*copy, *line, *p, *a, *b, *c;
	size_t		 i;

	on = jstr(f, "on") != NULL && strcmp(jstr(f, "on"), "ip") == 0 ?
	    "ip" : "if";
	what = jstr(f, "what") != NULL ? jstr(f, "what") : "";
	if ((num = digits(f, "num", 5)) == NULL || num[0] == '\0' ||
	    atoi(num) < 1 || atoi(num) > 65535) {
		toast(true, "A NAT instance has a number, 1 to 65535");
		return (false);
	}
	if (what[0] == '\0' || strchr(what, ' ') != NULL || !words_ok(what)) {
		toast(true, on[1] == 'f' ? "Which interface's address: em0" :
		    "Which address: 192.0.2.1");
		return (false);
	}
	snprintf(w, len, "%s config %s %s", num, on, what);
	for (i = 0; i < nitems(flags); i++)
		if (jbool(f, flags[i])) {
			strlcat(w, " ", len);
			strlcat(w, flags[i], len);
		}
	/* Each line a port sent on: proto inside:port outside. */
	rd = jstr(f, "redirects") != NULL ? jstr(f, "redirects") : "";
	copy = strdup(rd);
	for (p = copy; (line = strsep(&p, "\n")) != NULL;) {
		a = strtok(line, " \t\r");
		if (a == NULL)
			continue;
		b = strtok(NULL, " \t\r");
		c = strtok(NULL, " \t\r");
		if ((strcmp(a, "tcp") != 0 && strcmp(a, "udp") != 0) || b ==
		    NULL || c == NULL || strtok(NULL, " \t\r") != NULL ||
		    !words_ok(b) || !words_ok(c) || strchr(b, ':') == NULL) {
			toast(true, "A port sent on is tcp or udp, the address "
			    "and port inside, and the port outside: tcp "
			    "10.0.0.5:80 8080");
			free(copy);
			return (false);
		}
		strlcat(w, " redirect_port ", len);
		strlcat(w, a, len);
		strlcat(w, " ", len);
		strlcat(w, b, len);
		strlcat(w, " ", len);
		strlcat(w, c, len);
	}
	free(copy);
	return (true);
}

/* The pipe form as ipfw's words: "1 config bw 10Mbit/s delay 20". */
static bool
pipe_words(const ucl_object_t *f, char *w, size_t len)
{
	const char	*num, *bw, *delay, *plr, *queue, *unit, *mask;
	char		 frac[24];

	num = digits(f, "num", 5);
	bw = decimal(f, "bw");
	delay = digits(f, "delay", 6);
	plr = decimal(f, "plr");
	queue = digits(f, "queue", 5);
	if (num == NULL || num[0] == '\0' || atoi(num) < 1 || atoi(num) >
	    65535) {
		toast(true, "A pipe has a number, 1 to 65535");
		return (false);
	}
	if (bw == NULL || delay == NULL || plr == NULL || queue == NULL ||
	    (plr[0] != '\0' && atof(plr) > 100)) {
		toast(true, "Bandwidth, delay, loss and queue are numbers; the "
		    "loss a percentage, 0 to 100");
		return (false);
	}
	unit = jstr(f, "unit") != NULL && (strcmp(jstr(f, "unit"), "Kbit/s") ==
	    0 || strcmp(jstr(f, "unit"), "Gbit/s") == 0) ? jstr(f, "unit") :
	    "Mbit/s";
	snprintf(w, len, "%s config", num);
	/* Unset is ipfw's own: no limit, no delay, nothing lost. */
	if (bw[0] != '\0') {
		strlcat(w, " bw ", len);
		strlcat(w, bw, len);
		strlcat(w, unit, len);
	}
	if (delay[0] != '\0') {
		strlcat(w, " delay ", len);
		strlcat(w, delay, len);
	}
	/* ipfw's plr is a probability, 0 to 1. */
	if (plr[0] != '\0') {
		snprintf(frac, sizeof(frac), " plr %g", atof(plr) / 100.0);
		strlcat(w, frac, len);
	}
	if (queue[0] != '\0') {
		strlcat(w, " queue ", len);
		strlcat(w, queue, len);
	}
	mask = jstr(f, "mask") != NULL ? jstr(f, "mask") : "";
	if (strcmp(mask, "src") == 0)
		strlcat(w, " mask src-ip 0xffffffff", len);
	else if (strcmp(mask, "dst") == 0)
		strlcat(w, " mask dst-ip 0xffffffff", len);
	return (true);
}

/* The forms of the views above; true when form is one of them. */
static bool
more_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*a, *b;
	char		 words[500];

	if (strcmp(form, "fw-table") != 0 && strcmp(form, "fw-entry") != 0 &&
	    strcmp(form, "fw-object") != 0 && strcmp(form, "fw-trace") != 0 &&
	    strcmp(form, "fw-ktrace") != 0 && strcmp(form, "fw-nat") != 0 &&
	    strcmp(form, "fw-pipe") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(form, "fw-nat") == 0 || strcmp(form, "fw-pipe") == 0) {
		if (form[3] == 'n' ? nat_words(f, words, sizeof(words)) :
		    pipe_words(f, words, sizeof(words)))
			object_job(s, form[3] == 'n' ? "nat" : "pipe", words,
			    jbool(f, "persist"));
		return (true);
	}
	if (strcmp(form, "fw-ktrace") == 0) {
		char	url[512];

		a = jstr(f, "address") != NULL ? jstr(f, "address") : "";
		if (a[0] == '\0' || strlen(a) >= sizeof(fw.k_addr) ||
		    a[strspn(a, "0123456789abcdefABCDEF.:")] != '\0') {
			toast(true, "The kernel is watched for an IPv4 or IPv6 "
			    "address");
			return (true);
		}
		snprintf(fw.k_addr, sizeof(fw.k_addr), "%s", a);
		fw.k_secs = jstr(f, "seconds") != NULL ? atoi(jstr(f,
		    "seconds")) : 10;
		if (fw.k_secs < 1 || fw.k_secs > 60)
			fw.k_secs = 10;
		if (fw.k_loading)
			return (true);
		fw.k_loading = true;
		fw.k_error[0] = '\0';
		snprintf(url, sizeof(url), "/api/servers/%s/ipfw/trace?address="
		    "%s&seconds=%d%s%s", s->id, fw.k_addr, fw.k_secs,
		    fw.jail[0] != '\0' ? "&jail=" : "", fw.jail);
		api("GET", url, NULL, ktrace_cb, NULL);
		return (true);
	}
	if (strcmp(form, "fw-trace") == 0) {
		snprintf(fw.t_proto, sizeof(fw.t_proto), "%s", jstr(f,
		    "proto") != NULL ? jstr(f, "proto") : "tcp");
		snprintf(fw.t_src, sizeof(fw.t_src), "%s", jstr(f, "src") !=
		    NULL ? jstr(f, "src") : "");
		snprintf(fw.t_dst, sizeof(fw.t_dst), "%s", jstr(f, "dst") !=
		    NULL ? jstr(f, "dst") : "");
		snprintf(fw.t_port, sizeof(fw.t_port), "%s", jstr(f, "port") !=
		    NULL ? jstr(f, "port") : "");
		snprintf(fw.t_if, sizeof(fw.t_if), "%s", jstr(f, "iface") !=
		    NULL ? jstr(f, "iface") : "");
		fw.t_out = jstr(f, "dir") != NULL && strcmp(jstr(f, "dir"),
		    "out") == 0;
		fw.t_asked = true;
		return (true);
	}
	if (strcmp(form, "fw-table") == 0) {
		a = jstr(f, "name") != NULL ? jstr(f, "name") : "";
		b = jstr(f, "type") != NULL ? jstr(f, "type") : "addr";
		if (a[0] == '\0' || a[strspn(a, "abcdefghijklmnopqrstuvwxyz"
		    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")] != '\0' ||
		    strcmp(a, "all") == 0) {
			toast(true, "A table's name is letters, digits and "
			    "_ . -");
			return (true);
		}
		snprintf(words, sizeof(words), "%s create type %s", a, b);
	} else if (strcmp(form, "fw-entry") == 0) {
		a = jstr(f, "key") != NULL ? jstr(f, "key") : "";
		b = jstr(f, "value") != NULL ? jstr(f, "value") : "";
		if (!words_ok(a) || strchr(a, ' ') != NULL || (b[0] != '\0' &&
		    (!words_ok(b) || strchr(b, ' ') != NULL))) {
			toast(true, "A key is an address, a network, an "
			    "interface or a number; its value one word");
			return (true);
		}
		snprintf(words, sizeof(words), "%s add %s%s%s", jstr(f,
		    "table") != NULL ? jstr(f, "table") : "", a, b[0] != '\0' ?
		    " " : "", b);
	} else {
		a = jstr(f, "words") != NULL ? jstr(f, "words") : "";
		b = jstr(f, "kind") != NULL ? jstr(f, "kind") : "nat";
		if (!words_ok(a) || strchr(a, ' ') == NULL) {
			toast(true, "Its number or name, and what to do: 1 "
			    "config if em0");
			return (true);
		}
		object_job(s, b, a, jbool(f, "persist"));
		return (true);
	}
	object_job(s, "table", words, jbool(f, "persist"));
	return (true);
}

/* The actions of the views above; true when act is one of them. */
static bool
more_action(struct server *s, const char *act, const char *arg,
    const char *value)
{
	const ucl_object_t	*o, **rules;
	ucl_object_iter_t	 it;
	char			 words[400], body[400];
	long long		 before, after, cur;
	int			 n, i;

	if (strcmp(act, "fw-entry-del") == 0) {
		snprintf(words, sizeof(words), "%s delete %s", arg, value);
		object_job(s, "table", words, false);
	} else if (strcmp(act, "fw-table-destroy") == 0) {
		snprintf(body, sizeof(body), "ipfw table %s destroy, on %s: "
		    "the table and what is in it. ipfw refuses while a rule "
		    "names it.", arg, s->name);
		confirm("Destroy the table", body, "Destroy", true, "",
		    "do-fw-table-destroy", arg, "");
	} else if (strcmp(act, "do-fw-table-destroy") == 0) {
		snprintf(words, sizeof(words), "%s destroy", arg);
		object_job(s, "table", words, false);
	} else if (strcmp(act, "fw-drop") == 0 && fw.sect >= 0) {
		/*
		 * A rule dropped before or after another of the part: its
		 * row opened with a number between that one and its
		 * neighbour on that side, for Save to move it there.
		 */
		long long	 at, lo, hi, x;
		const char	*colon;

		cur = atoll(arg);
		at = atoll(value);
		colon = strchr(value, ':');
		lo = sects[fw.sect].lo - 1;
		hi = sects[fw.sect].hi + 1;
		n = (int)ucl_array_size(jget(fw.data, "rules")) + (int)
		    ucl_array_size(jget(fw.data, "kept"));
		if ((rules = calloc((size_t)n + 1, sizeof(*rules))) == NULL)
			abort();
		n = 0;
		it = NULL;
		while ((o = ucl_object_iterate(jget(fw.data, "rules"), &it,
		    true)) != NULL)
			rules[n++] = o;
		it = NULL;
		while ((o = ucl_object_iterate(jget(fw.data, "kept"), &it,
		    true)) != NULL)
			rules[n++] = o;
		if (colon != NULL && strcmp(colon + 1, "before") == 0) {
			hi = at;
			for (i = 0; i < n; i++)
				if ((x = jint(rules[i], "num", 0)) < at && x >
				    lo && x != cur)
					lo = x;
		} else {
			lo = at;
			for (i = 0; i < n; i++)
				if ((x = jint(rules[i], "num", 0)) > at && x <
				    hi && x != cur)
					hi = x;
		}
		free(rules);
		if (cur <= 0 || at <= 0)
			return (true);
		if (hi - lo < 2)
			toast(true, "No number is free between %05lld and "
			    "%05lld: give one of them another first", lo, hi);
		else {
			fw.edit = cur;
			fw.move = (lo + hi) / 2;
			/* Where it already is: nothing to move. */
			if (fw.move == cur)
				fw.move = 0;
		}
	} else if (strcmp(act, "fw-move") == 0 && fw.edit > 0 && fw.sect >=
	    0) {
		/*
		 * A number half way to the next but one rule on that
		 * side: the rule's place once it is saved with it.
		 */
		n = (int)ucl_array_size(jget(fw.data, "rules")) + (int)
		    ucl_array_size(jget(fw.data, "kept"));
		if ((rules = calloc((size_t)n + 1, sizeof(*rules))) == NULL)
			abort();
		n = 0;
		it = NULL;
		while ((o = ucl_object_iterate(jget(fw.data, "rules"), &it,
		    true)) != NULL)
			rules[n++] = o;
		it = NULL;
		while ((o = ucl_object_iterate(jget(fw.data, "kept"), &it,
		    true)) != NULL)
			rules[n++] = o;
		qsort(rules, (size_t)n, sizeof(*rules), num_cmp);
		cur = fw.edit;
		before = sects[fw.sect].lo - 1;
		after = sects[fw.sect].hi + 1;
		if (arg[0] == 'u') {
			/* Between the two rules above this one. */
			long long	p1 = -1, p2 = sects[fw.sect].lo - 1;

			for (i = 0; i < n; i++) {
				long long	x = jint(rules[i], "num", 0);

				if (x >= cur || x < sects[fw.sect].lo)
					continue;
				if (x != p1) {
					p2 = p1 == -1 ? p2 : p1;
					p1 = x;
				}
			}
			before = p1 == -1 ? cur : p2;
			after = p1 == -1 ? cur : p1;
		} else {
			long long	n1 = -1, n2 = -1;

			for (i = 0; i < n; i++) {
				long long	x = jint(rules[i], "num", 0);

				if (x <= cur || x > sects[fw.sect].hi)
					continue;
				if (n1 == -1)
					n1 = x;
				else if (x != n1 && n2 == -1)
					n2 = x;
			}
			before = n1 == -1 ? cur : n1;
			after = n1 == -1 ? cur : n2 == -1 ? sects[fw.sect].hi +
			    1 : n2;
		}
		free(rules);
		if (after - before < 2)
			toast(true, before == after ? "It is the %s of its "
			    "part already" : "No number is free there: give "
			    "one of the two rules another first", arg[0] ==
			    'u' ? "first" : "last");
		else
			fw.move = (before + after) / 2;
	} else
		return (false);
	return (true);
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
	const char			 *kt;
	char				  age[32], buf[32];
	size_t				  i;
	bool				  mine, loaded, on;
	int				  r, n, next;

	mine = fw.data != NULL && strcmp(fw.sid, s->id) == 0;
	live = mine ? jget(fw.data, "rules") : NULL;
	kept = mine ? jget(fw.data, "kept") : NULL;
	loaded = mine && jbool(fw.data, "loaded");
	on = loaded && jbool(fw.data, "enabled");
	h_raw(h, "<div class=\"toolbar fwbar\">");
	if (firewall_rail_away())
		h_raw(h, "<button class=\"ghost small\" data-act=\"fw-rail\" "
		    "title=\"The firewall's parts, in the side bar\">Layout ›"
		    "</button>");
	if (fw.jail[0] != '\0') {
		h_raw(h, "<span class=\"chip\" title=\"The firewall of this "
		    "jail's own network: its rules are kept in the jail\">"
		    "jail ");
		h_txt(h, fw.jail);
		h_raw(h, "</span>");
	}
	if (mine) {
		/* The light is the switch: what it shows, pressed, changes. */
		if (loaded)
			h_fmt(h, "<button class=\"switch%s\" data-act=\"fw-onoff\" "
			    "data-arg=\"%s\" role=\"switch\" aria-checked=\"%s\" "
			    "title=\"%s. net.inet.ip.fw.enable now, and "
			    "firewall_enable in rc.conf\"><i></i><span>%s</span>"
			    "</button>", on ? " on" : "", on ? "disable" :
			    "enable", on ? "true" : "false", on ? "The firewall "
			    "is on: press to turn it off" : "The firewall is "
			    "off, and everything passes: press to turn it on",
			    on ? "On" : "Off");
		else
			h_raw(h, "<span class=\"chip warn\">ipfw is not in the "
			    "kernel</span>");
		h_fmt(h, "<span class=\"fw-count\"><b>%d</b> rules now · <b>%d"
		    "</b> kept · <b>%lld</b> states</span>", (int)
		    ucl_array_size(live), (int)ucl_array_size(kept),
		    (long long)jint(fw.data, "dynamic_total", 0));
	}
	if (loaded)
		h_raw(h, "<button class=\"small\" data-act=\"fw-apply\" title="
		    "\"The kept rules become the whole ruleset, without a gap: "
		    "loaded into set 1 while it is off, then swapped with set "
		    "0\">Apply the kept rules</button>");
	h_raw(h, "<input class=\"filter\" id=\"filter\" data-input=\"filter\" "
	    "placeholder=\"Filter rows\" autocomplete=\"off\" spellcheck=\""
	    "false\"");
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
	/*
	 * On a phone the side bar is a drawer: the chain is a strip above
	 * the rules instead, scrolled sideways, the parts that have rules
	 * and the one shown.
	 */
	h_fmt(h, "<nav class=\"fw-strip\" aria-label=\"The firewall's parts\">"
	    "<button class=\"ghost small%s\" data-act=\"fw-sect\" data-arg="
	    "\"%d\">Overview</button><button class=\"ghost small%s\" "
	    "data-act=\"fw-sect\" data-arg=\"%d\">States</button>",
	    fw.sect == FW_LAYOUT ? " on" : "", FW_LAYOUT, fw.sect ==
	    FW_DYNAMIC ? " on" : "", FW_DYNAMIC);
	for (i = 0; i < nitems(sects); i++) {
		n = count(live, sects[i].lo, sects[i].hi) + count(kept,
		    sects[i].lo, sects[i].hi);
		if (n == 0 && fw.sect != (int)i)
			continue;
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"fw-sect\" "
		    "data-arg=\"%zu\"><small>%d</small> %s</button>", fw.sect ==
		    (int)i ? " on" : "", i, sects[i].lo, sects[i].name);
	}
	h_fmt(h, "<button class=\"ghost small%s\" data-act=\"fw-sect\" "
	    "data-arg=\"%d\">As text</button><button class=\"ghost small%s\" "
	    "data-act=\"fw-sect\" data-arg=\"%d\">Follow a packet</button>"
	    "</nav>", fw.sect == FW_TEXT ? " on" : "", FW_TEXT, fw.sect ==
	    FW_TRACE ? " on" : "", FW_TRACE);
	if (!loaded)
		h_raw(h, "<div class=\"notice info\">ipfw is not in this "
		    "host's kernel. Arcana loads no module by itself: load "
		    "<code>ipfw</code> from the Kernel tab, with <code>"
		    "net.inet.ip.fw.default_to_accept=1</code> set in the "
		    "loader first if the host is reached over the network, "
		    "since an empty ipfw denies everything. The kept rules "
		    "can be written meanwhile.</div>");
	if (fw.sect == FW_DYNAMIC) {
		view_dynamic(h);
		return;
	}
	if (fw.sect == FW_TEXT) {
		view_text(h);
		return;
	}
	if (fw.sect == FW_TABLES) {
		view_tables(h);
		return;
	}
	if (fw.sect == FW_OBJECTS) {
		view_objects(h);
		return;
	}
	if (fw.sect == FW_DIFF) {
		view_diff(h);
		return;
	}
	if (fw.sect == FW_TRACE) {
		view_trace_fw(h);
		return;
	}
	if (fw.sect == FW_LOG) {
		view_fwlog(h);
		return;
	}
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
				h_fmt(h, "<span class=\"chip\" data-act=\"fw-sect\""
				    " data-arg=\"%d\">", FW_TABLES);
				h_txt(h, jstr(o, "name"));
				h_fmt(h, " · %lld</span> ", (long long)jint(o,
				    "count", 0));
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
	    "</small><button class=\"ghost small live%s\" data-act=\"fw-live\""
	    " title=\"Read the counters again every %d seconds while this is "
	    "shown, and draw what each rule takes\"><span class=\"led\">"
	    "</span>Live</button></h4>", sc->name, sc->lo, sc->hi,
	    sc->called ? ", called from the chain" : "", fw.dyn_paused ? "" :
	    " on", FW_HITS_EVERY / 1000);
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
	    "false\" autocomplete=\"off\" list=\"fw-words\" data-input=\""
	    "fw-rule\" placeholder=\"allow tcp from any to me 443 in\"><label class=\"toggle\" title=\"Added to what the "
	    "kernel has, at once\"><input type=\"checkbox\" name=\"live\"%s>"
	    "<span>now</span></label><label class=\"toggle\" title=\"Written "
	    "into the kept rules, which the host loads when it starts and "
	    "Apply loads\"><input type=\"checkbox\" name=\"persist\" checked>"
	    "<span>keep</span></label><button class=\"small\">Add</button>"
	    "</form>", next, sc->lo, sc->hi, loaded ? " checked" : "");
	rule_words(h);
	h_raw(h, "<table class=\"net fw-rules\">");
	tbl_head(h, "fwrules", cols, 5, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("fwrules", arr, cols, 5, app.filter);
	for (r = 0; (o = rows[r]) != NULL; r++) {
		const char	*where = jstr(o, "where");
		bool		 now = strncmp(where, "now", 3) == 0 || strcmp(
		    where, "set off") == 0;
		bool		 keptr = strcmp(where, "now, kept") == 0 ||
		    !now;
		long long	 num = (long long)jint(o, "num", 0);

		if (fw.edit == num) {
			/*
			 * Being changed, in its own row: its words as they
			 * are kept, which are the ones that were written,
			 * or as ipfw says them.
			 */
			kt = kept_text(num);
			h_fmt(h, "<tr class=\"editing\" data-rule=\"%lld\"><td "
			    "colspan=\"5\"><form data-form=\"fw-edit\" class="
			    "\"fw-add\"><button type=\"button\" class=\"icon\" "
			    "data-act=\"fw-move\" data-arg=\"up\" title=\"A "
			    "number before the rule above: Save moves it "
			    "there\">▲</button><button type=\"button\" class="
			    "\"icon\" data-act=\"fw-move\" data-arg=\"down\" "
			    "title=\"A number after the rule below\">▼"
			    "</button><input name=\"num\" inputmode=\""
			    "numeric\" size=\"6\" value=\"%lld\"><input name="
			    "\"rule\" spellcheck=\"false\" autocomplete=\"off\""
			    " list=\"fw-words\" data-input=\"fw-rule\"",
			    num, fw.move > 0 ? fw.move : num);
			h_attr(h, "value", kt != NULL ? kt : jstr(o, "text"));
			h_fmt(h, "><label class=\"toggle\"><input type=\""
			    "checkbox\" name=\"live\"%s><span>now</span></label>"
			    "<label class=\"toggle\"><input type=\"checkbox\" "
			    "name=\"persist\"%s><span>keep</span></label>"
			    "<button class=\"small\">Save</button><button type="
			    "\"button\" class=\"ghost small danger\" data-act="
			    "\"fw-del\" data-arg=\"%lld\" data-value=\"%s\">"
			    "Delete</button><button type=\"button\" class=\""
			    "ghost small\" data-act=\"fw-edit\" data-arg=\"0\">"
			    "Cancel</button></form></td></tr>", now && loaded ?
			    " checked" : "", keptr ? " checked" : "", num,
			    strcmp(where, "now, kept") == 0 ? "both" : now ?
			    "live" : "kept");
			continue;
		}
		h_fmt(h, "<tr class=\"pick%s\" data-act=\"fw-edit\" data-arg=\""
		    "%lld\" data-rule=\"%lld\" draggable=\"true\" data-reorder="
		    "\"fw\" title=\"Press to change it; drag it to another "
		    "place\"><td><b>%05lld</b></td><td class=\"mono rule\">",
		    now ? "" : " off", num, num, num);
		h_txt(h, jstr(o, "text"));
		h_raw(h, "</td><td>");
		if (now) {
			double	rate = rate_of(num, jint(o, "pkts", 0));

			h_fmt(h, "<span class=\"pk\">%lld", (long long)jint(o,
			    "pkts", 0));
			if (rate >= 0.05)
				h_fmt(h, " <small class=\"rate\" title=\"Since "
				    "the look before\">+%.1f/s</small>", rate);
			else if (jint(o, "pkts", 0) == 0 && strcmp(where,
			    "set off") != 0)
				h_raw(h, " <small class=\"dim never\" title=\""
				    "No packet has matched it since its "
				    "counter was last cleared\">never</small>");
			hits_line(h, num);
			h_raw(h, "</span>");
		}
		h_raw(h, "</td><td>");
		if (now) {
			bytes(buf, sizeof(buf), jint(o, "bytes", 0));
			h_txt(h, buf);
		}
		h_fmt(h, "</td><td><span class=\"chip%s\">", strcmp(where,
		    "now, kept") == 0 ? "" : " dim");
		h_txt(h, where);
		h_raw(h, "</span></td></tr>");
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

	char	*q, *withjail;

	if (fw.jail[0] == '\0' || json[0] != '{') {
		job_send_host(s, strdup(json), title, JOB_FIREWALL, "");
		return;
	}
	/* Of the jail whose firewall is shown. */
	q = json_quote(fw.jail);
	if (asprintf(&withjail, "{\"jail\":%s,%s", q, json + 1) == -1)
		abort();
	free(q);
	job_send_host(s, withjail, title, JOB_FIREWALL, fw.jail);
}

/* The words of a rule as the job's args, after its number. */
static void
rule_args(struct html *b, const char *rule)
{
	char	*copy, *p, *w, *q;
	bool	 first;

	copy = strdup(rule);
	p = copy;
	first = true;
	while ((w = strsep(&p, " \t")) != NULL) {
		if (*w == '\0')
			continue;
		/* "add" before the rule says what is known. */
		if (first && strcmp(w, "add") == 0)
			continue;
		first = false;
		q = json_quote(w);
		h_fmt(b, ",%s", q);
		free(q);
	}
	free(copy);
}

/* The dynamic states change by themselves: read again while shown. */
void
firewall_tick(double now)
{
	struct server	*s;

	/* The states every two seconds; a part's counters every five, but
	 * not while a rule of it is being changed. */
	if (app.node != NODE_HOST || app.tab != TAB_FIREWALL || (fw.sect !=
	    FW_DYNAMIC && (fw.sect < 0 || fw.edit != 0)) || fw.dyn_paused ||
	    !app.visible || fw.loading || (s = cur_server()) == NULL ||
	    strcmp(fw.sid, s->id) != 0 || now - fw.fetched < (fw.sect ==
	    FW_DYNAMIC ? 2000 : FW_HITS_EVERY))
		return;
	refresh_firewall(s, true);
}

bool
firewall_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	struct html	 b;
	const char	*rule, *how;
	char		*copy, *q, url[400], title[200], del[200];
	const ucl_object_t *o;
	ucl_object_iter_t it;
	int		 num, lo, hi;
	bool		 edit, was_live, was_kept;

	if (more_form(form, f))
		return (true);
	if (strcmp(form, "fw-add") != 0 && strcmp(form, "fw-text") != 0 &&
	    strcmp(form, "fw-edit") != 0)
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
		snprintf(url, sizeof(url), "/api/servers/%s/ipfw/rules%s%s",
		    s->id, fw.jail[0] != '\0' ? "?jail=" : "", fw.jail);
		api("POST", url, b.s, file_cb, strdup(strcmp(how, "check") ==
		    0 ? "check" : "write"));
		free(b.s);
		return (true);
	}
	edit = strcmp(form, "fw-edit") == 0;
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
	/*
	 * A rule changed is the old one deleted where it was and the new
	 * one added where it is to be: two jobs, in that order.
	 */
	if (edit && fw.edit > 0) {
		was_live = was_kept = false;
		it = NULL;
		while ((o = ucl_object_iterate(jget(fw.data, "rules"), &it,
		    true)) != NULL)
			if (jint(o, "num", 0) == fw.edit)
				was_live = true;
		was_kept = kept_text(fw.edit) != NULL;
		if (was_live || was_kept) {
			snprintf(del, sizeof(del), "{\"kind\":\"ipfw\",\"verb\":"
			    "\"delete\",\"args\":[\"%lld\"],\"live\":%s,"
			    "\"persist\":%s}", fw.edit, was_live ? "true" :
			    "false", was_kept ? "true" : "false");
			snprintf(title, sizeof(title), "ipfw delete %lld",
			    fw.edit);
			fw_job(s, del, title);
		}
	}
	memset(&b, 0, sizeof(b));
	h_fmt(&b, "{\"kind\":\"ipfw\",\"verb\":\"add\",\"args\":[\"%d\"", num);
	rule_args(&b, rule);
	h_fmt(&b, "],\"live\":%s,\"persist\":%s}", jbool(f, "live") ? "true" :
	    "false", jbool(f, "persist") ? "true" : "false");
	snprintf(title, sizeof(title), "ipfw add %d %.140s", num, rule);
	fw_job(s, b.s, title);
	free(b.s);
	fw.edit = 0;
	fw.move = 0;
	return (true);
}

bool
firewall_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 json[256], title[96], body[500];
	size_t		 i;

	/* A rule being typed: the words that may come next follow it. */
	if (strcmp(act, "input:fw-rule") == 0) {
		snprintf(fw.typed, sizeof(fw.typed), "%s", value != NULL ? value :
		    "");
		return (true);
	}
	if (strncmp(act, "fw-", 3) != 0 && strncmp(act, "do-fw-", 6) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "fw-sect") == 0) {
		fw.sect = atoi(arg);
		fw.edit = 0;
		app.rail_open = false;
		fw.move = 0;
		if (fw.sect < FW_FIRST || fw.sect >= (int)nitems(sects))
			fw.sect = FW_LAYOUT;
		if (fw.sect == FW_LOG)
			fwlog_read(s);
		if (fw.sect == FW_TEXT) {
			fw.file_error[0] = fw.file_note[0] = '\0';
			file_read(s);
		}
		if (fw.sect == FW_DYNAMIC) {
			fw.loading = false;
			refresh_firewall(s, true);
		}
	} else if (strcmp(act, "fw-rail") == 0) {
		fw.rail_hosts = !fw.rail_hosts;
	} else if (strcmp(act, "fw-live") == 0) {
		fw.dyn_paused = !fw.dyn_paused;
	} else if (strcmp(act, "fw-edit") == 0) {
		fw.edit = atoll(arg) == fw.edit ? 0 : atoll(arg);
		fw.move = 0;
	} else if (strcmp(act, "fw-jail") == 0) {
		/* Another firewall: the host's, or a jail's own. */
		snprintf(fw.jail, sizeof(fw.jail), "%s", arg);
		if (fw.data != NULL)
			ucl_object_unref(fw.data);
		fw.data = NULL;
		if (fw.k_data != NULL)
			ucl_object_unref(fw.k_data);
		fw.k_data = NULL;
		fw.k_error[0] = '\0';
		fw.error[0] = '\0';
		fw.nprev = 0;
		fw.nhits = 0;
		fw.edit = fw.move = 0;
		fw.loading = false;
		free(fw.text);
		fw.text = NULL;
		fw.sect = FW_LAYOUT;
		refresh_firewall(s, true);
	} else if (more_action(s, act, arg, value)) {
		;
	} else if (strcmp(act, "fw-goto") == 0) {
		/* The part a rule's number is of, and the rule in it. */
		for (i = 0; i < nitems(sects); i++)
			if (atoi(arg) >= sects[i].lo && atoi(arg) <=
			    sects[i].hi)
				fw.sect = (int)i;
	} else if (strcmp(act, "fw-load-rc") == 0) {
		file_read_rc(s);
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
		fw.edit = 0;
	}
	return (true);
}
