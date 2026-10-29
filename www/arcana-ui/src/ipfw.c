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
#define	FW_QOS		(-9)	/* dummynet's pipes, schedulers, queues */
#define	FW_ALIASES	(-10)	/* names for lists and values, $name */
#define	FW_FIRST	FW_ALIASES
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
	int		 edit_k;	/* which of its number's rows */
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
	/* A packet to follow: what was asked, as it was typed, and the
	 * agent's answer (path-check), of which one walk is shown. */
	char		 t_proto[8], t_src[64], t_dst[64], t_port[8], t_if[16];
	char		 t_dir[12];	/* in, out, reply_in, reply_out */
	bool		 t_asked, t_loading;
	char		 t_error[300];
	ucl_object_t	*t_data;
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
	char		 file_error[600];
	char		 file_note[300];
	/* What the host stops a Keep at to ask first (its error-app-tag),
	 * and what was accepted so far, JSON strings with commas. */
	char		 file_tag[64];
	char		 file_acc[200];
	/* The sysctls Apply needs: asked for in the page when one is not
	 * set, set by jobs, read again, and Apply then goes on. */
	bool		 ask;
	int		 setting;	/* their jobs not finished yet */
	bool		 then_apply;
	double		 set_at;	/* when the last of them finished */
	double		 asked_at;	/* when the read on its way was asked */
	char		 set_error[600];
} fw = { .sect = FW_LAYOUT, .t_proto = "tcp", .t_dir = "in" };

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
static void	apply_ask(struct server *, bool);

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
	struct server	*s;
	char		*sid;

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
	/* Apply's sysctls set: a read asked after that says if they are. */
	if (fw.then_apply && fw.setting == 0 && (s = cur_server()) != NULL &&
	    strcmp(s->id, fw.sid) == 0) {
		if (fw.asked_at < fw.set_at)
			refresh_firewall(s, true);
		else
			apply_ask(s, true);
	}
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
		/* A warning to accept (rc.conf's): asked on the page. */
		snprintf(fw.file_tag, sizeof(fw.file_tag), "%s", status ==
		    200 && jstr(o, "error_tag") != NULL ? jstr(o,
		    "error_tag") : "");
		free(what);
		return;
	}
	fw.file_error[0] = fw.file_tag[0] = fw.file_acc[0] = '\0';
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
	/* The host's first Keep moved its boot to Arcana's script. */
	if (strcmp(what, "write") == 0 && jstr(o, "migrated") != NULL)
		snprintf(fw.file_note, sizeof(fw.file_note), "Kept, and "
		    "migrated from %s: the host boots these rules by Arcana's "
		    "own script from now on, its own files as they were. "
		    "Apply makes them the host's ruleset.", jstr(o,
		    "migrated"));
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

	/* One for this host on its way is waited for, not another's. */
	if (!app.online || (fw.loading && strcmp(fw.sid, s->id) == 0))
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
		fw.ask = fw.then_apply = false;
		fw.setting = 0;
		fw.set_error[0] = '\0';
		/* The kernel's trace was of that host. */
		if (fw.k_data != NULL)
			ucl_object_unref(fw.k_data);
		fw.k_data = NULL;
		fw.k_error[0] = '\0';
	} else if (!again && (fw.data != NULL || fw.error[0] != '\0'))
		return;
	snprintf(fw.sid, sizeof(fw.sid), "%s", s->id);
	fw.loading = true;
	fw.asked_at = arc_now();
	snprintf(url, sizeof(url), "net/ipfw%s%s", fw.jail[0] != '\0' ?
	    "?jail=" : "", fw.jail);
	host_read(s, url, "read the firewall", true, fw_cb, strdup(s->id));
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
	const ucl_object_t	*o, *k;
	ucl_object_t		*arr, *r;
	ucl_object_iter_t	 it, kit;
	const ucl_object_t	*live, *kept;
	bool			*used;
	char			 where[32];
	int			 nk, i, pass;

	live = jget(fw.data, "rules");
	kept = jget(fw.data, "kept");
	nk = (int)ucl_array_size(kept);
	if ((used = calloc((size_t)nk + 1, sizeof(*used))) == NULL)
		abort();
	arr = ucl_object_typed_new(UCL_ARRAY);
	/*
	 * Each rule of the kernel's set 0 beside the kept rule of its
	 * number with its words (as ipfw writes them back, "norm"), so
	 * that two rules of one number are two rows, each with its own.
	 */
	it = NULL;
	while ((o = ucl_object_iterate(live, &it, true)) != NULL) {
		if (jint(o, "num", 0) < lo || jint(o, "num", 0) > hi)
			continue;
		r = ucl_object_copy(o);
		if (jbool(o, "disabled"))
			snprintf(where, sizeof(where), "set off");
		else if (jint(o, "set", 0) != 0)
			snprintf(where, sizeof(where), "set %lld", (long long)
			    jint(o, "set", 0));
		else {
			snprintf(where, sizeof(where), "now only");
			for (pass = 0; pass < 2 && strcmp(where, "now only") == 0;
			    pass++) {
				kit = NULL;
				i = 0;
				while ((k = ucl_object_iterate(kept, &kit, true)) !=
				    NULL) {
					if (!used[i] && jint(k, "num", 0) == jint(o,
					    "num", 0) && jstr(o, "text") != NULL &&
					    ((jstr(k, pass == 0 ? "norm" : "text") !=
					    NULL && strcmp(jstr(k, pass == 0 ? "norm" :
					    "text"), jstr(o, "text")) == 0))) {
						used[i] = true;
						snprintf(where, sizeof(where),
						    "now, kept");
						ucl_object_insert_key(r,
						    ucl_object_fromstring(jstr(k,
						    "text")), "ktext", 0, false);
						if (jstr(k, "source") != NULL)
							ucl_object_insert_key(r,
							    ucl_object_fromstring(jstr(k,
							    "source")), "ksrc", 0, false);
						break;
					}
					i++;
				}
			}
		}
		ucl_object_insert_key(r, ucl_object_fromstring(where), "where",
		    0, false);
		ucl_array_append(arr, r);
	}
	kit = NULL;
	i = 0;
	while ((k = ucl_object_iterate(kept, &kit, true)) != NULL) {
		if (!used[i++] && jint(k, "num", 0) >= lo && jint(k, "num", 0) <=
		    hi) {
			r = ucl_object_copy(k);
			ucl_object_insert_key(r, ucl_object_fromstring(jstr(k,
			    "text")), "ktext", 0, false);
			if (jstr(k, "source") != NULL)
				ucl_object_insert_key(r, ucl_object_fromstring(
				    jstr(k, "source")), "ksrc", 0, false);
			ucl_object_insert_key(r, ucl_object_fromstring("kept, "
			    "not loaded"), "where", 0, false);
			ucl_array_append(arr, r);
		}
	}
	free(used);
	/* Which of its number's rows each is, in the order they came. */
	it = NULL;
	while ((o = ucl_object_iterate(arr, &it, true)) != NULL) {
		const ucl_object_t	*q;
		ucl_object_iter_t	 qit = NULL;
		int			 n = 0;

		while ((q = ucl_object_iterate(arr, &qit, true)) != NULL &&
		    q != o)
			if (jint(q, "num", 0) == jint(o, "num", 0))
				n++;
		ucl_object_insert_key((ucl_object_t *)(uintptr_t)o,
		    ucl_object_fromint(n), "k", 0, false);
	}
	return (arr);
}

/* Is a row one Arcana changes: set 0's, or kept? */
static bool
row_ours(const ucl_object_t *r)
{
	const char	*w = jstr(r, "where");

	return (w != NULL && (strcmp(w, "now only") == 0 || strcmp(w,
	    "now, kept") == 0 || strcmp(w, "kept, not loaded") == 0));
}

/* The row of a number's k-th rule, a copy to unref; NULL for none. */
static ucl_object_t *
row_find(long long num, int k)
{
	ucl_object_t		*arr, *r;
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	arr = rows_of(1, 65534);
	r = NULL;
	it = NULL;
	while ((o = ucl_object_iterate(arr, &it, true)) != NULL)
		if (jint(o, "num", 0) == num && jint(o, "k", 0) == k) {
			r = ucl_object_copy(o);
			break;
		}
	ucl_object_unref(arr);
	return (r);
}

/* How many rows of Arcana's a number has. */
static int
num_rows(long long num)
{
	ucl_object_t		*arr;
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	int			 n;

	arr = rows_of((int)num, (int)num);
	n = 0;
	it = NULL;
	while ((o = ucl_object_iterate(arr, &it, true)) != NULL)
		if (row_ours(o))
			n++;
	ucl_object_unref(arr);
	return (n);
}

/* The words a row's rule is named by to the host: as kept, or as the
 * kernel lists it. */
static const char *
row_words(const ucl_object_t *r)
{

	return (jstr(r, "ktext") != NULL ? jstr(r, "ktext") : jstr(r,
	    "text"));
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
		h_raw(h, "<div class=\"scrim rail-scrim\" data-act=\"rail-toggle\"></div>");
	h_fmt(h, "<aside class=\"rail fwrail%s\"><div class=\"rail-head\">"
	    "<button class=\"ghost small back\" data-act=\"fw-rail\" title=\""
	    "Back to the side bar's pages\">‹ Back</button><span class="
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
			{ FW_ALIASES, "Aliases", "Names for address lists, port "
			    "lists and values, written $name in a rule" },
			{ FW_TABLES, "Tables", "The tables and what is in them" },
			{ FW_QOS, "QoS", "dummynet's pipes, schedulers and "
			    "queues, and the rules that send to them" },
			{ FW_OBJECTS, "NAT", "NAT and NAT64 instances, and "
			    "anything else in ipfw's words" },
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
		/* rc.conf's warning: accepted, kept again. */
		if (fw.file_tag[0] != '\0' && !fw.file_loading) {
			h_raw(h, " <button class=\"small\" data-act=\""
			    "fw-file-accept\">Accept ");
			h_txt(h, fw.file_tag);
			h_raw(h, " and keep again</button>");
		}
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
	 * the script rc.conf's firewall_script names, when it is the
	 * host's own and not rc.firewall, else a file firewall_type names.
	 * A jail's rc.conf is not read with the rules, so a jail is
	 * offered it always.
	 */
	type = jstr(jget(fw.data, "rc"), "firewall_script");
	if (type == NULL || type[0] != '/' || strcmp(type, "/etc/rc.firewall")
	    == 0)
		type = jstr(jget(fw.data, "rc"), "firewall_type");
	if (fw.jail[0] != '\0' || (type != NULL && type[0] == '/' &&
	    (jstr(fw.data, "path") == NULL || strcmp(type, jstr(fw.data,
	    "path")) != 0))) {
		h_fmt(h, "<button type=\"button\" class=\"ghost small\" "
		    "data-act=\"fw-load-rc\"%s title=\"", fw.file_loading ?
		    " disabled" : "");
		if (type != NULL && type[0] == '/')
			h_txt(h, type);
		else
			h_raw(h, "The script rc.conf's firewall_script names, or "
			    "the file its firewall_type names");
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

/* The alias the form shows, to be changed; "" a new one. */
static char	alias_edit[33];

/* How many kept rules name $name. */
static int
alias_uses(const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it = NULL;
	char			 w[48];
	const char		*src, *p;
	int			 n = 0;

	snprintf(w, sizeof(w), "$%s", name);
	while ((o = ucl_object_iterate(jget(fw.data, "kept"), &it, true)) !=
	    NULL) {
		if ((src = jstr(o, "source")) == NULL)
			continue;
		for (p = src; (p = strstr(p, w)) != NULL; p += strlen(w))
			if (p[strlen(w)] == '\0' || p[strlen(w)] == ' ') {
				n++;
				break;
			}
	}
	return (n);
}

/*
 * The aliases: names for what rules say again and again.  An address
 * list is a table of its name, so that changing it changes no rule; a
 * port list and a value are written into each rule that names them.
 */
static void
view_aliases(struct html *h)
{
	const ucl_object_t	*a;
	ucl_object_iter_t	 it;
	int			 n, u;

	h_raw(h, "<h4 class=\"family\">Aliases</h4><p class=\"dim\">A name "
	    "for what rules say again and again, written <code>$name</code> "
	    "in a rule: <b>addresses</b>, a list of addresses and networks, "
	    "is an ipfw table of its name (the rule says <code>table(name)"
	    "</code>, so changing the list changes the table and no rule); "
	    "<b>ports</b> (80,443,8000-8080) and a <b>value</b> (an "
	    "interface, an address) are written into each rule that names "
	    "them, which are written again, kept and now, when it changes. "
	    "The kept rules stay ipfw's own commands, loaded at boot as they "
	    "are; a rule's own words, its aliases in them, are a comment "
	    "line before it.</p>");
	{
		const ucl_object_t	*e = NULL;
		const char		*kind;

		it = NULL;
		while (alias_edit[0] != '\0' && (a = ucl_object_iterate(jget(
		    fw.data, "aliases"), &it, true)) != NULL)
			if (jstr(a, "name") != NULL && strcmp(jstr(a, "name"),
			    alias_edit) == 0)
				e = a;
		kind = e != NULL && jstr(e, "kind") != NULL ? jstr(e, "kind") :
		    "addr";
		/* An id: the page's patch makes no other form of it. */
		h_raw(h, "<form id=\"fw-alias-form\" data-form=\"fw-alias\" "
		    "class=\"fw-add\"><input "
		    "name=\"name\" spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"lan\" size=\"12\" maxlength=\"32\"");
		h_attr(h, "value", e != NULL ? jstr(e, "name") : "");
		h_fmt(h, "><select name=\"kind\"><option value=\"addr\"%s>"
		    "addresses</option><option value=\"ports\"%s>ports"
		    "</option><option value=\"value\"%s>value</option>"
		    "</select><input name=\"value\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"10.0.0.0/8 "
		    "192.168.1.0/24, or 80,443, or vtnet0\" size=\"36\"",
		    strcmp(kind, "addr") == 0 ? " selected" : "",
		    strcmp(kind, "ports") == 0 ? " selected" : "",
		    strcmp(kind, "value") == 0 ? " selected" : "");
		h_attr(h, "value", e != NULL ? jstr(e, "value") : "");
		h_raw(h, "><button class=\"small\">Keep</button></form>");
	}
	h_raw(h, "<table class=\"net fwaliases\"><thead><tr><th>Name</th>"
	    "<th>Kind</th><th>What it is</th><th>Rules</th><th></th></tr>"
	    "</thead><tbody>");
	n = 0;
	it = NULL;
	while ((a = ucl_object_iterate(jget(fw.data, "aliases"), &it, true)) !=
	    NULL) {
		if (jstr(a, "name") == NULL)
			continue;
		n++;
		u = alias_uses(jstr(a, "name"));
		h_raw(h, "<tr class=\"pick\" data-act=\"fw-alias-edit\"");
		h_attr(h, "data-arg", jstr(a, "name"));
		h_raw(h, "><td class=\"mono\"><b>$");
		h_txt(h, jstr(a, "name"));
		h_raw(h, "</b></td><td>");
		h_txt(h, strcmp(jstr(a, "kind"), "addr") == 0 ? "addresses "
		    "(a table)" : jstr(a, "kind"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(a, "value"));
		h_fmt(h, "</td><td>%d</td><td class=\"acts\"><button class=\""
		    "icon\" data-act=\"fw-alias-del\" title=\"%s\"%s", u,
		    u > 0 ? "A rule names it: it stays while one does" :
		    "Delete it", u > 0 ? " disabled" : "");
		h_attr(h, "data-arg", jstr(a, "name"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"5\" class=\"dim\">No alias yet: "
		    "name a list of the addresses your rules keep saying, and "
		    "write $name in them.</td></tr>");
	h_raw(h, "</tbody></table>");
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
		    "size=\"14\">");
		if (jstr(t, "type") == NULL || strcmp(jstr(t, "type"), "addr") == 0)
			pfxlist_select(h, "or every prefix of", "pfx", NULL, false);
		h_raw(h, "<label class=\"toggle\"><input type=\"checkbox\""
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

	h_raw(h, "<h4 class=\"family\">NAT</h4><p class=\""
	    "dim\">What a rule names by a number or a name and is made "
	    "apart from the rules: a NAT instance (<code>nat 1 config if "
	    "em0 same_ports</code>), NAT64 and NPTv6 (<code>nat64lsn NAT64 "
	    "create prefix4 192.0.2.0/24</code>), or anything else in "
	    "ipfw's own words; dummynet's pipes and queues are under QoS."
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
}

/*
 * What Apply would do: the kept rules beside set 0's of the kernel,
 * paired by number and words as ipfw writes them back (a kept rule's
 * "norm"), so that how ipfw writes a rule is no difference; two rules
 * of a number are paired one with one.  *addp, *delp, *chgp counted;
 * h NULL to count alone.
 */
static void
diff_rows(struct html *h, int *addp, int *delp, int *chgp, char *gone,
    size_t glen)
{
	const ucl_object_t	*live, *kept, *o, *k;
	ucl_object_iter_t	 it, kit;
	bool			*kused, *lused;
	int			 nl, nk, i, j, pass;

	live = jget(fw.data, "rules");
	kept = jget(fw.data, "kept");
	nl = (int)ucl_array_size(live);
	nk = (int)ucl_array_size(kept);
	if ((kused = calloc((size_t)nk + 1, 1)) == NULL || (lused = calloc(
	    (size_t)nl + 1, 1)) == NULL)
		abort();
	*addp = *delp = *chgp = 0;
	if (gone != NULL && glen > 0)
		gone[0] = '\0';
#define	OURS(o)	(!jbool((o), "disabled") && jint((o), "set", 0) == 0 && \
	    jint((o), "num", 0) != 65535)
	/* The same: by norm, then by the words as kept. */
	for (pass = 0; pass < 2; pass++) {
		kit = NULL;
		for (j = 0; (k = ucl_object_iterate(kept, &kit, true)) != NULL;
		    j++) {
			if (kused[j])
				continue;
			it = NULL;
			for (i = 0; (o = ucl_object_iterate(live, &it, true)) !=
			    NULL; i++)
				if (!lused[i] && OURS(o) && jint(o, "num", 0) ==
				    jint(k, "num", 0) && jstr(o, "text") != NULL &&
				    jstr(k, pass == 0 ? "norm" : "text") != NULL &&
				    strcmp(jstr(o, "text"), jstr(k, pass == 0 ?
				    "norm" : "text")) == 0) {
					kused[j] = lused[i] = true;
					break;
				}
		}
	}
	/* Of one number, the rest paired in order: other words. */
	kit = NULL;
	for (j = 0; (k = ucl_object_iterate(kept, &kit, true)) != NULL; j++) {
		if (kused[j])
			continue;
		it = NULL;
		for (i = 0; (o = ucl_object_iterate(live, &it, true)) != NULL;
		    i++)
			if (!lused[i] && OURS(o) && jint(o, "num", 0) == jint(k,
			    "num", 0))
				break;
		if (o != NULL) {
			kused[j] = lused[i] = true;
			(*chgp)++;
			if (h == NULL)
				continue;
			h_fmt(h, "<tr class=\"d-chg pick\" data-act=\"fw-goto\" "
			    "data-arg=\"%lld\"><td>~ differs</td><td><b>%05lld"
			    "</b></td><td class=\"mono\"><del>", (long long)
			    jint(k, "num", 0), (long long)jint(k, "num", 0));
			h_txt(h, jstr(o, "text"));
			h_raw(h, "</del><br><ins>");
			h_txt(h, jstr(k, "norm") != NULL ? jstr(k, "norm") : jstr(k,
			    "text"));
			h_raw(h, "</ins></td></tr>");
		} else {
			kused[j] = true;
			(*addp)++;
			if (h == NULL)
				continue;
			h_fmt(h, "<tr class=\"d-add pick\" data-act=\"fw-goto\" "
			    "data-arg=\"%lld\"><td>+ added</td><td><b>%05lld</b>"
			    "</td><td class=\"mono\">", (long long)jint(k, "num",
			    0), (long long)jint(k, "num", 0));
			h_txt(h, jstr(k, "text"));
			h_raw(h, "</td></tr>");
		}
	}
	it = NULL;
	for (i = 0; (o = ucl_object_iterate(live, &it, true)) != NULL; i++) {
		if (lused[i] || !OURS(o))
			continue;
		(*delp)++;
		if (gone != NULL && strlen(gone) + 8 < glen)
			snprintf(gone + strlen(gone), glen - strlen(gone),
			    "%s%05lld", gone[0] != '\0' ? ", " : "", (long long)
			    jint(o, "num", 0));
		if (h == NULL)
			continue;
		h_fmt(h, "<tr class=\"d-del pick\" data-act=\"fw-goto\" "
		    "data-arg=\"%lld\"><td>− removed</td><td><b>%05lld</b></td>"
		    "<td class=\"mono\">", (long long)jint(o, "num", 0),
		    (long long)jint(o, "num", 0));
		h_txt(h, jstr(o, "text"));
		h_raw(h, "</td></tr>");
	}
#undef	OURS
	free(kused);
	free(lused);
}

static void
view_diff(struct html *h)
{
	int	add, del, differ;

	h_raw(h, "<h4 class=\"family\">What Apply would change</h4><p class="
	    "\"dim\">Apply makes the kept rules the whole of set 0, the rules "
	    "Arcana keeps; SD-WAN's sets and the default rule are not "
	    "touched. Each kept rule is set beside the kernel's as ipfw "
	    "writes it back (ipfw -n), so a rule written another way, "
	    "<code>all</code> for <code>ip</code> or a port's name, is not a "
	    "difference.</p><table class=\"net fw-diff\"><thead><tr><th></th>"
	    "<th>Number</th><th>Rule</th></tr></thead><tbody>");
	diff_rows(h, &add, &del, &differ, NULL, 0);
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

/* Is a sysctl the read lists one Apply needs and the kernel has not? */
static bool
needs_it(const ucl_object_t *t)
{

	return (jbool(t, "needed") && (jget(t, "value") == NULL || jint(t,
	    "value", 0) != jint(t, "want", 1)));
}

/* How many of the sysctls Apply needs are not set as it needs them. */
static int
needs_missing(void)
{
	const ucl_object_t	*t;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((t = ucl_object_iterate(jget(fw.data, "tunables"), &it, true)) !=
	    NULL)
		if (needs_it(t))
			n++;
	return (n);
}

/* What the sysctl does, as sysctl -d would say it at more length. */
static const char *
tunable_does(const char *name)
{

	if (strcmp(name, "net.inet.ip.fw.dyn_keep_states") == 0)
		return ("It keeps the states a rule made when the rule is "
		    "deleted, until they expire, instead of dropping them with "
		    "it.");
	if (strcmp(name, "net.inet.ip.fw.tables_sets") == 0)
		return ("It gives each set its own table names, as NAT64 and "
		    "NPTv6 instances have already, and a set swap then moves "
		    "the tables with the rules.");
	return ("");
}

/*
 * Apply, asked for: the sysctls it needs asked about first, in the
 * page, when one is not set; then what would change, confirmed.  set:
 * "Set and apply" was pressed, and with no rule to be gone it applies.
 */
static void
apply_ask(struct server *s, bool set)
{
	char	body[900], gone[200], lost[400];
	int	add, del, chg;

	fw.then_apply = false;
	if (needs_missing() > 0) {
		if (set)
			snprintf(fw.set_error, sizeof(fw.set_error), "Set, and "
			    "read again: still not as Apply needs them. Nothing "
			    "was applied.");
		fw.ask = true;
		return;
	}
	fw.ask = false;
	fw.set_error[0] = '\0';
	/* What would go is said first: rules the kernel runs with that
	 * are not kept. */
	diff_rows(NULL, &add, &del, &chg, gone, sizeof(gone));
	if (set && del == 0) {
		fw_job(s, "{\"kind\":\"ipfw\",\"verb\":\"apply\",\"safe\":true}",
		    "ipfw apply");
		return;
	}
	lost[0] = '\0';
	if (del > 0)
		snprintf(lost, sizeof(lost), "%d rule%s the kernel has now "
		    "%s not kept and would be gone: %s. Keep %s first "
		    "(What Apply would change) if %s wanted. ", del, del ==
		    1 ? "" : "s", del == 1 ? "is" : "are", gone, del == 1 ?
		    "it" : "them", del == 1 ? "it is" : "they are");
	snprintf(body, sizeof(body), "%sThe kept rules become the whole "
	    "of set 0 on %s: %d added, %d removed, %d with other words. "
	    "They are loaded into set 1 while it is off and swapped "
	    "with set 0, so that no packet meets half a ruleset. The "
	    "rules of now wait in set 1: if the console cannot reach "
	    "the host afterwards, the host swaps them back by itself.",
	    lost, s->name, add, del, chg);
	confirm(del > 0 ? "Apply: rules would be gone" : "Apply the kept "
	    "rules", body, "Apply", true, del > 0 ? "apply" : "",
	    "do-fw-apply", "", "");
}

/*
 * The sysctls Apply needs and the kernel has not, asked about in the
 * page: what each does, why Apply needs it, and a button that sets
 * them at once and for the next boot, then applies.
 */
static void
view_ask(struct html *h)
{
	const ucl_object_t	*t;
	ucl_object_iter_t	 it;
	int			 n;

	n = needs_missing();
	h_fmt(h, "<div class=\"notice warn fw-ask\" role=\"group\" aria-label="
	    "\"Apply needs sysctls\"><p><b>Apply needs %s set first.</b></p>"
	    "<dl>", n == 1 ? "a sysctl" : "these sysctls");
	it = NULL;
	while ((t = ucl_object_iterate(jget(fw.data, "tunables"), &it, true)) !=
	    NULL) {
		if (!needs_it(t))
			continue;
		h_raw(h, "<dt><code>");
		h_txt(h, jstr(t, "name") != NULL ? jstr(t, "name") : "");
		if (jget(t, "value") != NULL)
			h_fmt(h, "</code> is %lld; Apply needs %lld</dt><dd>",
			    (long long)jint(t, "value", 0), (long long)jint(t,
			    "want", 1));
		else
			h_fmt(h, "</code> is not in this kernel; Apply needs "
			    "%lld</dt><dd>", (long long)jint(t, "want", 1));
		h_txt(h, tunable_does(jstr(t, "name") != NULL ? jstr(t,
		    "name") : ""));
		h_raw(h, " Apply needs it as ");
		h_txt(h, jstr(t, "why") != NULL ? jstr(t, "why") : "");
		h_raw(h, "</dd>");
	}
	h_fmt(h, "</dl><p class=\"dim\">Set and apply sets %s now and in "
	    "%s, so that the host starts with %s too, reads the firewall "
	    "again, and applies only once %s set.</p>", n == 1 ? "it" :
	    "them", fw.jail[0] != '\0' ? "the jail's /etc/sysctl.conf" :
	    "/etc/sysctl.conf", n == 1 ? "it" : "them", n == 1 ? "it reads" :
	    "they read");
	if (fw.set_error[0] != '\0') {
		h_raw(h, "<p class=\"fw-ask-error\">");
		h_txt(h, fw.set_error);
		h_raw(h, "</p>");
	}
	h_fmt(h, "<p><button class=\"small\" data-act=\"fw-set-apply\"%s>%s"
	    "</button> <button class=\"ghost small\" data-act=\"fw-ask-no\">"
	    "Not now</button></p></div>", fw.setting > 0 || fw.then_apply ?
	    " disabled" : "", fw.setting > 0 || fw.then_apply ? "Setting…" :
	    "Set and apply");
}

/*
 * A job of the firewall's finished: one of Apply's sysctls among them,
 * set, or refused by the kernel and why.
 */
void
firewall_job_done(const char *title, bool ok, const char *err)
{
	const char	*name;
	size_t		 l;

	if (fw.setting == 0 || strncmp(title, "sysctl net.inet.ip.fw.", 22) !=
	    0)
		return;
	if (--fw.setting == 0)
		fw.set_at = arc_now();
	if (ok)
		return;
	fw.then_apply = false;
	name = title + 7;
	l = strcspn(name, "=");
	snprintf(fw.set_error + strlen(fw.set_error), sizeof(fw.set_error) -
	    strlen(fw.set_error), "%sThe kernel refused %.*s=1: %s.%s Nothing "
	    "was applied.", fw.set_error[0] != '\0' ? " " : "", (int)l, name,
	    err != NULL ? err : "failed", strncmp(name,
	    "net.inet.ip.fw.tables_sets", l) == 0 ? " The kernel changes it "
	    "only while every rule that uses a table is in set 0: SD-WAN's "
	    "rules in its own set, or another tool's, keep it as it is "
	    "while they are loaded. Kept in /etc/sysctl.conf it is set at "
	    "boot, before any rule." : "");
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
trace_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	fw.t_loading = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(fw.t_error, sizeof(fw.t_error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	fw.t_error[0] = '\0';
	if (fw.t_data != NULL)
		ucl_object_unref(fw.t_data);
	fw.t_data = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
}

/* What a walk's verdict comes to, in words. */
static const char *
verdict_words(const ucl_object_t *w)
{
	const char	*v = jstr(w, "verdict");

	if (v == NULL || strcmp(v, "none") == 0)
		return ("No rule decides it: the ruleset is empty, and ipfw's "
		    "default does");
	if (strcmp(v, "allow") == 0)
		return (jbool(w, "by_state") ? "Let through, by the state a "
		    "rule kept of its connection" : "Let through");
	if (strcmp(v, "deny") == 0)
		return ("Dropped");
	if (strcmp(v, "fwd") == 0)
		return ("Sent on to another next hop than the route's");
	if (strcmp(v, "unknown") == 0)
		return ("Not known: a table decides where it goes");
	return (jstr(w, "note") != NULL ? jstr(w, "note") : v);
}

/*
 * A packet followed through the ruleset by the agent (path-check): the
 * rules it meets, in the kernel's own order, call and return, skipto
 * and check-state followed as ip_fw2.c does; what it could not judge
 * said.  Nothing is sent.
 */
static void
view_trace_fw(struct html *h)
{
	const ucl_object_t	*d, *w, *st, *c;
	ucl_object_iter_t	 it;
	const char		*vd, *how, *t;
	char			 q[400];
	bool			 maybe, off;

	h_raw(h, "<h4 class=\"family\">Follow a packet</h4><p class=\"dim\">"
	    "The first packet of a connection, or its reply, walked through "
	    "the rules the kernel has now by the agent, which follows call "
	    "and return, skipto and check-state as the kernel does, and "
	    "knows the host's addresses and tables: which rules it meets, "
	    "where it is sent on, and what becomes of it. A rule it cannot "
	    "judge (a state, a user, an option it does not know) is marked. "
	    "Nothing is sent.</p><form data-form=\"fw-trace\" class=\""
	    "fw-add fw-trace\" id=\"fw-trace-form\"><select name=\"proto\">");
	{
		static const char *const protos[] = { "tcp", "udp", "sctp",
		    "icmp", "ip" };
		size_t	k;

		for (k = 0; k < nitems(protos); k++)
			h_fmt(h, "<option%s>%s</option>", strcmp(fw.t_proto,
			    protos[k]) == 0 ? " selected" : "", protos[k]);
	}
	h_raw(h, "</select><input name=\"src\" spellcheck=\"false\" "
	    "autocomplete=\"off\" placeholder=\"from 203.0.113.9\" required");
	h_attr(h, "value", fw.t_src);
	h_raw(h, "><input name=\"dst\" spellcheck=\"false\" autocomplete=\""
	    "off\" placeholder=\"to 192.0.2.1\" required");
	h_attr(h, "value", fw.t_dst);
	h_raw(h, "><input name=\"port\" inputmode=\"numeric\" size=\"6\" "
	    "placeholder=\"port\"");
	h_attr(h, "value", fw.t_port);
	h_fmt(h, "><select name=\"dir\" title=\"Which walk to show: the "
	    "packet coming in, going out, or its reply\"><option value=\"in\""
	    "%s>coming in</option><option value=\"out\"%s>going out</option>"
	    "<option value=\"reply_in\"%s>its reply, coming in</option>"
	    "<option value=\"reply_out\"%s>its reply, going out</option>"
	    "</select><input name=\"iface\" spellcheck=\"false\" "
	    "autocomplete=\"off\" size=\"8\" placeholder=\"in on em0\" "
	    "title=\"The interface it comes in on; else the one the route "
	    "back to its source is by\"", strcmp(fw.t_dir, "in") == 0 ? " "
	    "selected" : "", strcmp(fw.t_dir, "out") == 0 ? " selected" : "",
	    strcmp(fw.t_dir, "reply_in") == 0 ? " selected" : "", strcmp(
	    fw.t_dir, "reply_out") == 0 ? " selected" : "");
	h_attr(h, "value", fw.t_if);
	h_fmt(h, "><button class=\"small\"%s>Follow</button></form>",
	    fw.t_loading ? " disabled" : "");
	if (fw.t_error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, fw.t_error);
		h_raw(h, "</div>");
	}
	if (fw.t_loading)
		h_raw(h, "<div class=\"loader\"></div>");
	d = fw.t_data;
	if (d == NULL || !fw.t_asked) {
		view_ktrace(h);
		return;
	}
	/* Where it is at this host: in by, out by, for the walk shown. */
	h_raw(h, "<p class=\"fw-tctx\">");
	if (jbool(d, "src.local"))
		h_raw(h, "<span class=\"chip\">from this host</span>");
	else {
		h_raw(h, "<span class=\"chip\">in on ");
		h_txt(h, jstr(d, "ingress.interface") != NULL ? jstr(d,
		    "ingress.interface") : "? (no route back to its source)");
		h_raw(h, "</span>");
	}
	if (jbool(d, "dst.local"))
		h_raw(h, "<span class=\"chip good\">to this host</span>");
	else if (jget(d, "route") != NULL) {
		h_raw(h, "<span class=\"chip\">out by ");
		h_txt(h, jstr(d, "route.interface"));
		if (jstr(d, "route.gateway") != NULL && strncmp(jstr(d,
		    "route.gateway"), "link#", 5) != 0) {
			h_raw(h, " via ");
			h_txt(h, jstr(d, "route.gateway"));
		}
		h_fmt(h, ", FIB %lld</span>", (long long)jint(d, "fib", 0));
	} else
		h_raw(h, "<span class=\"chip bad\">no route to it</span>");
	if (jget(d, "firewall.on") != NULL && !jbool(d, "firewall.on"))
		h_raw(h, "<span class=\"chip warn\" title=\"net.inet.ip.fw."
		    "enable is 0: nothing of the ruleset stops a packet now; "
		    "what it would do, turned on, is shown\">firewall off"
		    "</span>");
	snprintf(q, sizeof(q), "#/troubleshoot?src=%s&dst=%s&proto=%s&port=%s",
	    fw.t_src, fw.t_dst, fw.t_proto, fw.t_port);
	h_raw(h, "<a class=\"ghost small\"");
	h_attr(h, "href", q);
	h_raw(h, " title=\"The same packet followed across every host and "
	    "jail, and its reply\">Across the hosts ›</a></p>");
	snprintf(q, sizeof(q), "firewall.%s", fw.t_dir);
	w = jget(d, q);
	if (w == NULL) {
		h_fmt(h, "<div class=\"notice info\">%s</div>", strcmp(fw.t_dir,
		    "in") == 0 ? "It is this host's own packet: nothing comes "
		    "in. See it going out." : strncmp(fw.t_dir, "reply", 5) ==
		    0 ? "No reply walked: the packet does not get out, or the "
		    "firewall has no ruleset." : "It does not go out: the "
		    "packet is this host's, or has no route, or the firewall "
		    "has no ruleset.");
		view_ktrace(h);
		return;
	}
	h_raw(h, "<ol class=\"fw-steps\">");
	maybe = false;
	it = NULL;
	while ((st = ucl_object_iterate(jget(w, "walk"), &it, true)) != NULL) {
		how = jstr(st, "how") != NULL ? jstr(st, "how") : "";
		if (strncmp(how, "may be met", 10) == 0)
			maybe = true;
		h_fmt(h, "<li class=\"%s pick\" data-act=\"fw-goto\" data-arg=\""
		    "%lld\"><b>%05lld</b> <code>", strncmp(how, "may be met",
		    10) == 0 ? "maybe" : strncmp(how, "decides", 7) == 0 ?
		    "decides" : "met", (long long)jint(st, "rule", 0),
		    (long long)jint(st, "rule", 0));
		/* Its words, the number before them written already. */
		t = jstr(st, "text") != NULL ? jstr(st, "text") : "";
		t += strspn(t, "0123456789");
		t += strspn(t, " ");
		h_txt(h, t);
		h_raw(h, "</code> <small>");
		h_txt(h, how);
		h_raw(h, "</small></li>");
	}
	h_raw(h, "</ol>");
	vd = jstr(w, "verdict");
	off = jget(d, "firewall.on") != NULL && !jbool(d, "firewall.on");
	h_fmt(h, "<div class=\"notice %s\"><b>", off ? "info" : vd == NULL ||
	    strcmp(vd, "deny") == 0 || strcmp(vd, "unknown") == 0 ? "bad" :
	    strcmp(vd, "allow") == 0 ? "info" : "warn");
	if (off)
		h_raw(h, "Were the firewall on: ");
	h_txt(h, verdict_words(w));
	h_raw(h, "</b>");
	if (jint(w, "rule", 0) != 0)
		h_fmt(h, " by rule %lld", (long long)jint(w, "rule", 0));
	if (jstr(w, "fwd") != NULL) {
		h_raw(h, ", to ");
		h_txt(h, jstr(w, "fwd"));
	}
	if (jint(w, "setfib", -1) >= 0)
		h_fmt(h, "; routed in FIB %lld from then on", (long long)jint(
		    w, "setfib", 0));
	if (jbool(w, "keep_state"))
		h_raw(h, "; a state kept for its reply");
	h_raw(h, maybe ? ", if no rule marked \"may be met\" decided "
	    "otherwise first." : ".");
	h_raw(h, "</div>");
	if (ucl_array_size(jget(w, "uncertain")) > 0) {
		h_raw(h, "<details class=\"fw-unsure\"><summary>What it could "
		    "not judge</summary><ul>");
		it = NULL;
		while ((c = ucl_object_iterate(jget(w, "uncertain"), &it,
		    true)) != NULL) {
			h_raw(h, "<li><code>");
			h_txt(h, jstr(c, "text"));
			h_raw(h, "</code> <span class=\"dim\">");
			h_txt(h, jstr(c, "because"));
			h_raw(h, "</span></li>");
		}
		h_raw(h, "</ul></details>");
	}
	view_ktrace(h);
}

static void
ktrace_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	fw.k_loading = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		/* What was shown stays, the error beside it. */
		snprintf(fw.k_error, sizeof(fw.k_error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	fw.k_error[0] = '\0';
	if (fw.k_data != NULL)
		ucl_object_unref(fw.k_data);
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
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		/* What was shown stays, the error beside it. */
		snprintf(fw.log_error, sizeof(fw.log_error), "%s", status ==
		    200 && jstr(o, "error") != NULL ? jstr(o, "error") : err !=
		    NULL ? err : "no answer");
		return;
	}
	fw.log_error[0] = '\0';
	if (fw.log != NULL)
		ucl_object_unref(fw.log);
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
	    "<>*+%[]$")] == '\0');
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
	    "sctp", "icmp", "ipv6-icmp", "ip4", "ip6" };
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
	/* The aliases: an address list where an address goes, any of them
	 * after the protocol. */
	it = NULL;
	while (n > 0 && (t = ucl_object_iterate(jget(fw.data, "aliases"), &it,
	    true)) != NULL)
		if (jstr(t, "name") != NULL && (tbl || strcmp(jstr(t, "kind"),
		    "addr") != 0)) {
			snprintf(copy, sizeof(copy), "%s$%s", head, jstr(t,
			    "name"));
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


/* ---- QoS: dummynet's pipes, schedulers and queues, by forms ---------- */

static struct {
	char	kind[8];	/* pipe, sched, queue or rule */
	long	num;		/* the one changed; 0 for a new one */
} qos;

static void
bw_text(char *buf, size_t len, int64_t b)
{

	if (b <= 0)
		snprintf(buf, len, "no limit");
	else if (b % 1000000000 == 0)
		snprintf(buf, len, "%lld Gbit/s", (long long)(b / 1000000000));
	else if (b >= 1000000)
		snprintf(buf, len, "%g Mbit/s", (double)b / 1e6);
	else
		snprintf(buf, len, "%g Kbit/s", (double)b / 1e3);
}

/* Who a mask makes a flow of its own. */
static void
per_text(char *buf, size_t len, const ucl_object_t *m)
{
	int	src, dst;

	src = m != NULL ? (int)jint(m, "src", 0) : 0;
	dst = m != NULL ? (int)jint(m, "dst", 0) : 0;
	if (src == 0 && dst == 0)
		snprintf(buf, len, "all at once");
	else if (src != 0 && dst != 0)
		snprintf(buf, len, "each source /%d to destination /%d", src,
		    dst);
	else if (src != 0)
		snprintf(buf, len, src == 32 ? "each source address" :
		    "each source /%d", src);
	else
		snprintf(buf, len, dst == 32 ? "each destination address" :
		    "each destination /%d", dst);
}

static const ucl_object_t *
qos_find(const char *list, long num)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(jget(jget(fw.data, "qos"), list), &it,
	    true)) != NULL)
		if (jint(o, "num", 0) == num)
			return (o);
	return (NULL);
}

/* A row's change and removal. */
static void
qos_acts(struct html *h, const char *kind, long long num)
{

	h_fmt(h, "<td class=\"acts\"><button class=\"icon\" data-act=\""
	    "fw-qos-edit\" data-arg=\"%s\" data-value=\"%lld\" title=\"Change "
	    "it\">✎</button><button class=\"icon\" data-act=\"fw-qos-del\" "
	    "data-arg=\"%s\" data-value=\"%lld\" title=\"Take it away, and "
	    "out of the kept rules\">×</button></td>", kind, num, kind, num);
}

static void
view_qos(struct html *h)
{
	static const struct tcol pc[] = {
		{ "Pipe", "num", true }, { "Bandwidth", "bw", true },
		{ "Delay ms", "delay", true }, { "Loss", "plr", true },
		{ "Queue", "slots", true }, { "For", NULL, false },
		{ "", NULL, false },
	};
	static const struct tcol sc[] = {
		{ "Scheduler", "num", true }, { "Type", "type", false },
		{ "Bandwidth", "bw", true }, { "For", NULL, false },
		{ "Queues", NULL, false }, { "", NULL, false },
		{ "", NULL, false },
	};
	static const struct tcol qc[] = {
		{ "Queue", "num", true }, { "Scheduler", "sched", true },
		{ "Weight", "weight", true }, { "Slots", "slots", true },
		{ "For", NULL, false }, { "", NULL, false },
		{ "", NULL, false },
	};
	static const struct tcol rc[] = {
		{ "Rule", "num", true }, { "Words", "text", false },
		{ "Packets", "pkts", true }, { "Bytes", "bytes", true },
	};
	const ucl_object_t	*q, **rows, *o, *x;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr;
	char			 buf[96];
	int			 n;

	q = jget(fw.data, "qos");
	h_raw(h, "<h4 class=\"family\">QoS</h4><p class=\"dim\">dummynet(4), "
	    "the firewall's traffic shaper. A <b>pipe</b> is a link: how "
	    "fast, how late and how lossy. A <b>scheduler</b> shares a "
	    "pipe's bandwidth among the <b>queues</b> that feed it, by "
	    "their weights (WF2Q+), or keeps each flow's delay down "
	    "(FQ-CoDel). A <b>rule</b> sends packets to a pipe, or to a "
	    "queue. Each is kept in the kept rules, before the rules.</p>");
	if (q == NULL) {
		h_raw(h, "<p class=\"notice\">dummynet is not in the kernel: it "
		    "is loaded on the Kernel tab (<code>dummynet</code>).</p>");
		return;
	}
	h_raw(h, "<div class=\"toolbar\"><button class=\"ghost small\" "
	    "data-act=\"fw-qos-new\" data-arg=\"pipe\">+ pipe</button><button "
	    "class=\"ghost small\" data-act=\"fw-qos-new\" data-arg=\"sched\">+ "
	    "scheduler</button><button class=\"ghost small\" data-act=\""
	    "fw-qos-new\" data-arg=\"queue\">+ queue</button><button class=\""
	    "ghost small\" data-act=\"fw-qos-new\" data-arg=\"rule\">+ rule"
	    "</button></div>");
	/* Pipes. */
	h_raw(h, "<h5>Pipes</h5><table class=\"net qos-pipes\">");
	tbl_head(h, "qos-pipes", pc, 7, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("qos-pipes", jget(q, "pipes"), pc, 7, NULL);
	for (n = 0; (o = rows[n]) != NULL; n++) {
		h_fmt(h, "<tr><td><b>%lld</b></td>", (long long)jint(o, "num",
		    0));
		bw_text(buf, sizeof(buf), jint(o, "bw", 0));
		h_fmt(h, "<td>%s</td><td>%lld</td>", buf, (long long)jint(o,
		    "delay", 0));
		if (jget(o, "plr") != NULL)
			h_fmt(h, "<td>%g%%</td>", ucl_object_todouble(jget(o,
			    "plr")) * 100);
		else
			h_raw(h, "<td>—</td>");
		if (jget(o, "bytes") != NULL)
			h_fmt(h, "<td>%lld KB</td>", (long long)jint(o, "bytes",
			    0) / 1024);
		else
			h_fmt(h, "<td>%lld slots</td>", (long long)jint(o,
			    "slots", 50));
		per_text(buf, sizeof(buf), jget(o, "mask"));
		h_fmt(h, "<td>%s</td>", buf);
		qos_acts(h, "pipe", (long long)jint(o, "num", 0));
		h_raw(h, "</tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"7\" class=\"dim\">No pipe.</td></tr>");
	free(rows);
	h_raw(h, "</tbody></table>");
	/* Schedulers. */
	h_raw(h, "<h5>Schedulers</h5><table class=\"net qos-scheds\">");
	tbl_head(h, "qos-scheds", sc, 7, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("qos-scheds", jget(q, "scheds"), sc, 7, NULL);
	for (n = 0; (o = rows[n]) != NULL; n++) {
		h_fmt(h, "<tr><td><b>%lld</b></td><td>", (long long)jint(o,
		    "num", 0));
		h_txt(h, jstr(o, "type") != NULL ? jstr(o, "type") : "");
		bw_text(buf, sizeof(buf), jint(o, "bw", 0));
		h_fmt(h, "</td><td>%s</td>", buf);
		per_text(buf, sizeof(buf), jget(o, "mask"));
		h_fmt(h, "<td>%s</td><td>", buf);
		it = NULL;
		while ((x = ucl_object_iterate(jget(o, "queues"), &it, true)) !=
		    NULL)
			h_fmt(h, "%lld ", (long long)ucl_object_toint(x));
		h_raw(h, "</td><td class=\"dim\">");
		h_txt(h, jstr(o, "params") != NULL ? jstr(o, "params") : "");
		h_raw(h, "</td>");
		qos_acts(h, "sched", (long long)jint(o, "num", 0));
		h_raw(h, "</tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"7\" class=\"dim\">No scheduler."
		    "</td></tr>");
	free(rows);
	h_raw(h, "</tbody></table>");
	/* Queues. */
	h_raw(h, "<h5>Queues</h5><table class=\"net qos-queues\">");
	tbl_head(h, "qos-queues", qc, 7, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("qos-queues", jget(q, "queues"), qc, 7, NULL);
	for (n = 0; (o = rows[n]) != NULL; n++) {
		h_fmt(h, "<tr><td><b>%lld</b></td><td>%lld</td><td>%lld</td>",
		    (long long)jint(o, "num", 0), (long long)jint(o, "sched", 0),
		    (long long)jint(o, "weight", 0));
		if (jget(o, "bytes") != NULL)
			h_fmt(h, "<td>%lld KB</td>", (long long)jint(o, "bytes",
			    0) / 1024);
		else
			h_fmt(h, "<td>%lld</td>", (long long)jint(o, "slots",
			    50));
		per_text(buf, sizeof(buf), jget(o, "mask"));
		h_fmt(h, "<td>%s</td><td class=\"dim\">", buf);
		h_txt(h, jstr(o, "red") != NULL ? jstr(o, "red") : "");
		h_raw(h, "</td>");
		qos_acts(h, "queue", (long long)jint(o, "num", 0));
		h_raw(h, "</tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"7\" class=\"dim\">No queue.</td></tr>");
	free(rows);
	h_raw(h, "</tbody></table>");
	/* The rules that send to them. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((o = ucl_object_iterate(jget(fw.data, "rules"), &it, true)) !=
	    NULL)
		if (jstr(o, "text") != NULL && (strstr(jstr(o, "text"),
		    "pipe ") != NULL || strstr(jstr(o, "text"), "queue ") !=
		    NULL))
			ucl_array_append(arr, ucl_object_ref((ucl_object_t *)
			    (uintptr_t)o));
	h_raw(h, "<h4 class=\"family\">Rules that send to them</h4><table "
	    "class=\"net qos-rules\">");
	tbl_head(h, "qos-rules", rc, 4, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("qos-rules", arr, rc, 4, NULL);
	for (n = 0; (o = rows[n]) != NULL; n++) {
		h_fmt(h, "<tr class=\"pick\" data-act=\"fw-goto\" data-arg=\""
		    "%lld\"><td><b>%05lld</b></td><td class=\"mono\">", (long
		    long)jint(o, "num", 0), (long long)jint(o, "num", 0));
		h_txt(h, jstr(o, "text"));
		h_fmt(h, "</td><td>%lld</td><td>%lld</td></tr>", (long long)
		    jint(o, "pkts", 0), (long long)jint(o, "bytes", 0));
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"4\" class=\"dim\">None yet: <b>+ "
		    "rule</b> sends some traffic to a pipe or a queue.</td>"
		    "</tr>");
	free(rows);
	ucl_object_unref(arr);
	h_raw(h, "</tbody></table>");
}

static void
per_select(struct html *h, const ucl_object_t *m)
{
	int	src, dst;

	src = m != NULL ? (int)jint(m, "src", 0) : 0;
	dst = m != NULL ? (int)jint(m, "dst", 0) : 0;
	h_fmt(h, "<label>for<select name=\"mask\"><option value=\"\"%s>all at "
	    "once</option><option value=\"src\"%s>each source address"
	    "</option><option value=\"dst\"%s>each destination address"
	    "</option></select></label>", src == 0 && dst == 0 ? " selected" :
	    "", src != 0 ? " selected" : "", src == 0 && dst != 0 ?
	    " selected" : "");
}

/* An object number's field: fixed when it is being changed. */
static void
num_field(struct html *h, const char *label)
{

	h_fmt(h, "<label>%s<input name=\"num\" inputmode=\"numeric\" size=\"5\" "
	    "placeholder=\"1\"", label);
	if (qos.num > 0)
		h_fmt(h, " value=\"%ld\" readonly", qos.num);
	h_raw(h, "></label>");
}

bool
firewall_qos_modal(struct html *h)
{
	static const char *const types[] = { "wf2q+", "fifo", "rr", "prio",
	    "qfq", "fq_codel", "fq_pie" };
	const ucl_object_t	*o, *x;
	ucl_object_iter_t	 it;
	char			 v[32];
	size_t			 i;
	double			 bw;

	if (app.modal != MODAL_FW_QOS)
		return (false);
	h_fmt(h, "<form data-form=\"fw-qos\"><h2>%s%s</h2>", qos.num > 0 ?
	    "Change " : "A new ", strcmp(qos.kind, "pipe") == 0 ? "pipe" :
	    strcmp(qos.kind, "sched") == 0 ? "scheduler" : strcmp(qos.kind,
	    "queue") == 0 ? "queue" : "rule");
	if (strcmp(qos.kind, "pipe") == 0) {
		o = qos.num > 0 ? qos_find("pipes", qos.num) : NULL;
		h_raw(h, "<p>A link of dummynet: what goes through it goes no "
		    "faster, comes later and is lost as it says. Empty, ipfw's "
		    "own: no limit, no delay, nothing lost.</p>");
		num_field(h, "Number");
		bw = o != NULL ? (double)jint(o, "bw", 0) : 0;
		h_raw(h, "<label>Bandwidth<input name=\"bw\" inputmode=\"decimal\" "
		    "size=\"8\" placeholder=\"no limit\"");
		if (bw > 0) {
			snprintf(v, sizeof(v), "%g", bw >= 1e6 ? bw / 1e6 : bw /
			    1e3);
			h_attr(h, "value", v);
		}
		h_fmt(h, "><select name=\"unit\"><option%s>Kbit/s</option><option"
		    "%s>Mbit/s</option><option>Gbit/s</option></select></label>",
		    bw > 0 && bw < 1e6 ? " selected" : "", bw == 0 || bw >= 1e6 ?
		    " selected" : "");
		h_raw(h, "<label>Delay, ms<input name=\"delay\" inputmode=\""
		    "numeric\" size=\"6\" placeholder=\"0\"");
		if (o != NULL && jint(o, "delay", 0) > 0) {
			snprintf(v, sizeof(v), "%lld", (long long)jint(o, "delay",
			    0));
			h_attr(h, "value", v);
		}
		h_raw(h, "></label><label>Loss, %<input name=\"plr\" inputmode=\""
		    "decimal\" size=\"6\" placeholder=\"0\"");
		if (o != NULL && jget(o, "plr") != NULL) {
			snprintf(v, sizeof(v), "%g", ucl_object_todouble(jget(o,
			    "plr")) * 100);
			h_attr(h, "value", v);
		}
		h_raw(h, "></label><label>Queue, slots<input name=\"queue\" "
		    "inputmode=\"numeric\" size=\"6\" placeholder=\"50\"");
		if (o != NULL && jget(o, "slots") != NULL) {
			snprintf(v, sizeof(v), "%lld", (long long)jint(o, "slots",
			    50));
			h_attr(h, "value", v);
		}
		h_raw(h, "></label>");
		per_select(h, o != NULL ? jget(o, "mask") : NULL);
	} else if (strcmp(qos.kind, "sched") == 0) {
		o = qos.num > 0 ? qos_find("scheds", qos.num) : NULL;
		h_raw(h, "<p>How a pipe's bandwidth is shared among the queues "
		    "that feed it. A scheduler has the number of the pipe whose "
		    "bandwidth it shares.</p>");
		num_field(h, "Pipe");
		h_raw(h, "<label>Type<select name=\"type\">");
		for (i = 0; i < nitems(types); i++) {
			snprintf(v, sizeof(v), "%s", types[i]);
			h_raw(h, "<option");
			if (o != NULL && jstr(o, "type") != NULL && strcasecmp(
			    jstr(o, "type"), types[i]) == 0)
				h_raw(h, " selected");
			h_fmt(h, ">%s</option>", types[i]);
		}
		h_raw(h, "</select></label>");
		per_select(h, o != NULL ? jget(o, "mask") : NULL);
		h_raw(h, "<fieldset class=\"fq\"><legend>FQ-CoDel and FQ-PIE"
		    "</legend><label>target, ms<input name=\"target\" "
		    "inputmode=\"numeric\" size=\"5\" placeholder=\"5\"></label>"
		    "<label>interval, ms <small>FQ-CoDel's</small><input name=\""
		    "interval\" inputmode=\"numeric\" size=\"5\" placeholder=\""
		    "100\"></label><label "
		    "class=\"toggle\"><input type=\"checkbox\" name=\"ecn\"> ECN"
		    "</label></fieldset>");
	} else if (strcmp(qos.kind, "queue") == 0) {
		o = qos.num > 0 ? qos_find("queues", qos.num) : NULL;
		h_raw(h, "<p>A share of a scheduler's pipe: of the queues that "
		    "feed one scheduler, each gets bandwidth in the measure of "
		    "its weight, 1 to 100.</p>");
		num_field(h, "Number");
		h_raw(h, "<label>Scheduler<select name=\"sched\">");
		it = NULL;
		while ((x = ucl_object_iterate(jget(jget(fw.data, "qos"),
		    "scheds"), &it, true)) != NULL)
			h_fmt(h, "<option%s>%lld</option>", o != NULL && jint(o,
			    "sched", 0) == jint(x, "num", -1) ? " selected" : "",
			    (long long)jint(x, "num", 0));
		h_raw(h, "</select></label><label>Weight<input name=\"weight\" "
		    "inputmode=\"numeric\" size=\"4\" placeholder=\"1\"");
		if (o != NULL) {
			snprintf(v, sizeof(v), "%lld", (long long)jint(o, "weight",
			    1));
			h_attr(h, "value", v);
		}
		h_raw(h, "></label><label>Queue, slots<input name=\"queue\" "
		    "inputmode=\"numeric\" size=\"6\" placeholder=\"50\"");
		if (o != NULL && jget(o, "slots") != NULL) {
			snprintf(v, sizeof(v), "%lld", (long long)jint(o, "slots",
			    50));
			h_attr(h, "value", v);
		}
		h_raw(h, "></label>");
		per_select(h, o != NULL ? jget(o, "mask") : NULL);
	} else {
		h_raw(h, "<p>Traffic sent to a pipe or a queue: a rule of the "
		    "firewall, now and kept. One that matches is shaped and "
		    "goes on (<code>net.inet.ip.fw.one_pass</code> says whether "
		    "the next rules see it again).</p><label>Rule number<input "
		    "name=\"num\" inputmode=\"numeric\" size=\"5\" "
		    "placeholder=\"5000\"></label><label>To<select name=\""
		    "target\">");
		it = NULL;
		while ((x = ucl_object_iterate(jget(jget(fw.data, "qos"),
		    "pipes"), &it, true)) != NULL)
			h_fmt(h, "<option value=\"pipe %lld\">pipe %lld</option>",
			    (long long)jint(x, "num", 0), (long long)jint(x,
			    "num", 0));
		it = NULL;
		while ((x = ucl_object_iterate(jget(jget(fw.data, "qos"),
		    "queues"), &it, true)) != NULL)
			h_fmt(h, "<option value=\"queue %lld\">queue %lld</option>",
			    (long long)jint(x, "num", 0), (long long)jint(x,
			    "num", 0));
		h_raw(h, "</select></label><label>Protocol<select name=\"proto\">"
		    "<option>ip</option><option>tcp</option><option>udp"
		    "</option><option>icmp</option></select></label><label>From"
		    "<input name=\"from\" spellcheck=\"false\" placeholder=\"any"
		    "\"></label><label>To address<input name=\"to\" spellcheck=\""
		    "false\" placeholder=\"any\"></label><label>Its port<input "
		    "name=\"port\" inputmode=\"numeric\" size=\"6\" placeholder="
		    "\"any\"></label><label>Way<select name=\"dir\"><option value="
		    "\"\">in and out</option><option>in</option><option>out"
		    "</option></select></label><label>Interface<input name=\"via"
		    "\" spellcheck=\"false\" size=\"8\" placeholder=\"any\">"
		    "</label>");
	}
	h_raw(h, "<label class=\"toggle\"><input type=\"checkbox\" name=\""
	    "persist\" checked> Keep it <small>a line of the kept rules, made "
	    "again at boot</small></label>");
	return (true);
}

/* Something an address field may hold: an address, a network, any. */
static bool
addr_ok(const char *a)
{

	return (a[0] == '\0' || (strlen(a) < 64 && a[strspn(a,
	    "0123456789abcdefABCDEF.:/")] == '\0') || strcmp(a, "any") == 0 ||
	    strcmp(a, "me") == 0);
}

static bool
qos_form(const ucl_object_t *f)
{
	struct server	*s;
	struct html	 b;
	const char	*num, *t, *a;
	char		 words[600], extra[200], title[200];
	bool		 keep;

	if ((s = cur_server()) == NULL)
		return (true);
	keep = jbool(f, "persist");
	if (strcmp(qos.kind, "pipe") == 0) {
		if (!pipe_words(f, words, sizeof(words)))
			return (true);
		object_job(s, "pipe", words, keep);
	} else if (strcmp(qos.kind, "sched") == 0 || strcmp(qos.kind,
	    "queue") == 0) {
		num = digits(f, "num", 5);
		if (num == NULL || atoi(num) < 1 || atoi(num) > 65535) {
			snprintf(app.modal_error, sizeof(app.modal_error), "A "
			    "number, 1 to 65535");
			return (true);
		}
		if (qos.kind[0] == 's') {
			t = jstr(f, "type") != NULL ? jstr(f, "type") : "wf2q+";
			if (t[strspn(t, "abcdefghijklmnopqrstuvwxyz_+2")] != '\0') {
				snprintf(app.modal_error, sizeof(app.modal_error),
				    "A type of those listed");
				return (true);
			}
			/* The mask before the type: after the type's own
			 * words ipfw takes no other, and says so only. */
			a = jstr(f, "mask") != NULL ? jstr(f, "mask") : "";
			snprintf(words, sizeof(words), "%s config pipe %s%s type "
			    "%s", num, num, strcmp(a, "src") == 0 ? " mask src-ip "
			    "0xffffffff" : strcmp(a, "dst") == 0 ? " mask dst-ip "
			    "0xffffffff" : "", t);
			if (strncmp(t, "fq_", 3) == 0) {
				if ((a = digits(f, "target", 5)) != NULL && a[0] !=
				    '\0') {
					snprintf(extra, sizeof(extra), " target %sms",
					    a);
					strlcat(words, extra, sizeof(words));
				}
				/* FQ-PIE has none. */
				if (strcmp(t, "fq_codel") == 0 && (a = digits(f,
				    "interval", 6)) != NULL && a[0] != '\0') {
					snprintf(extra, sizeof(extra), " interval "
					    "%sms", a);
					strlcat(words, extra, sizeof(words));
				}
				strlcat(words, jbool(f, "ecn") ? " ecn" : " noecn",
				    sizeof(words));
			}
		} else {
			t = digits(f, "sched", 5);
			a = digits(f, "weight", 3);
			if (t == NULL || t[0] == '\0' || a == NULL || (a[0] !=
			    '\0' && (atoi(a) < 1 || atoi(a) > 100))) {
				snprintf(app.modal_error, sizeof(app.modal_error),
				    "A scheduler, and a weight 1 to 100");
				return (true);
			}
			snprintf(words, sizeof(words), "%s config sched %s weight "
			    "%s", num, t, a[0] != '\0' ? a : "1");
			if ((a = digits(f, "queue", 5)) != NULL && a[0] != '\0') {
				snprintf(extra, sizeof(extra), " queue %s", a);
				strlcat(words, extra, sizeof(words));
			}
		}
		t = jstr(f, "mask") != NULL ? jstr(f, "mask") : "";
		if (qos.kind[0] == 'q' && strcmp(t, "src") == 0)
			strlcat(words, " mask src-ip 0xffffffff", sizeof(words));
		else if (qos.kind[0] == 'q' && strcmp(t, "dst") == 0)
			strlcat(words, " mask dst-ip 0xffffffff", sizeof(words));
		object_job(s, qos.kind, words, keep);
	} else {
		const char	*tgt, *proto, *from, *to, *port, *dir, *via;

		num = digits(f, "num", 5);
		tgt = jstr(f, "target");
		proto = jstr(f, "proto") != NULL ? jstr(f, "proto") : "ip";
		from = jstr(f, "from") != NULL ? jstr(f, "from") : "";
		to = jstr(f, "to") != NULL ? jstr(f, "to") : "";
		port = digits(f, "port", 5);
		dir = jstr(f, "dir") != NULL ? jstr(f, "dir") : "";
		via = jstr(f, "via") != NULL ? jstr(f, "via") : "";
		if (num == NULL || atoi(num) < 1 || atoi(num) > 65534 || tgt ==
		    NULL || (strncmp(tgt, "pipe ", 5) != 0 && strncmp(tgt,
		    "queue ", 6) != 0) || !addr_ok(from) || !addr_ok(to) ||
		    port == NULL || via[strspn(via, "abcdefghijklmnopqrstuvwxyz"
		    "0123456789._")] != '\0' || (strcmp(proto, "ip") != 0 &&
		    strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0 &&
		    strcmp(proto, "sctp") != 0 && strcmp(proto, "icmp") !=
		    0) || (port[0] != '\0' && strcmp(proto, "tcp") != 0 &&
		    strcmp(proto, "udp") != 0 && strcmp(proto, "sctp") != 0)) {
			snprintf(app.modal_error, sizeof(app.modal_error), "A rule "
			    "number 1 to 65534, a pipe or queue, addresses or any; "
			    "a port is of tcp or udp");
			return (true);
		}
		snprintf(words, sizeof(words), "%s %s from %s to %s", tgt, proto,
		    from[0] != '\0' ? from : "any", to[0] != '\0' ? to : "any");
		if (port[0] != '\0') {
			snprintf(extra, sizeof(extra), " dst-port %s", port);
			strlcat(words, extra, sizeof(words));
		}
		if (strcmp(dir, "in") == 0 || strcmp(dir, "out") == 0) {
			strlcat(words, " ", sizeof(words));
			strlcat(words, dir, sizeof(words));
		}
		if (via[0] != '\0') {
			strlcat(words, " via ", sizeof(words));
			strlcat(words, via, sizeof(words));
		}
		memset(&b, 0, sizeof(b));
		h_fmt(&b, "{\"kind\":\"ipfw\",\"verb\":\"add\",\"args\":[\"%d\"",
		    atoi(num));
		rule_args(&b, words);
		h_fmt(&b, "],\"live\":true,\"persist\":%s}", keep ? "true" :
		    "false");
		snprintf(title, sizeof(title), "ipfw add %d %.140s", atoi(num),
		    words);
		fw_job(s, b.s, title);
		free(b.s);
	}
	app.modal = MODAL_NONE;
	return (true);
}

/* The forms of the views above; true when form is one of them. */
static bool
more_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*a, *b;
	char		 words[500];

	if (strcmp(form, "fw-alias") == 0) {
		a = jstr(f, "name") != NULL ? jstr(f, "name") : "";
		b = jstr(f, "value") != NULL ? jstr(f, "value") : "";
		if ((s = cur_server()) == NULL)
			return (true);
		if (a[0] == '$')
			a++;
		if (a[0] == '\0' || a[strspn(a, "abcdefghijklmnopqrstuvwxyz"
		    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")] != '\0' ||
		    (a[0] >= '0' && a[0] <= '9') || strlen(a) > 32) {
			toast(true, "An alias's name is letters, digits and _, "
			    "not a digit first");
			return (true);
		}
		if (!words_ok(b) || strchr(b, '$') != NULL) {
			toast(true, "Its addresses with blanks between, its ports "
			    "with commas, or one word");
			return (true);
		}
		/* An address list's entries with commas or blanks between. */
		{
			char	vb[400], *c;

			snprintf(vb, sizeof(vb), "%s", b);
			if (strcmp(jstr(f, "kind") != NULL ? jstr(f, "kind") :
			    "", "addr") == 0)
				for (c = vb; *c != '\0'; c++)
					if (*c == ',')
						*c = ' ';
			snprintf(words, sizeof(words), "%s %s %s", a, jstr(f,
			    "kind") != NULL ? jstr(f, "kind") : "addr", vb);
		}
		object_job(s, "alias", words, true);
		return (true);
	}
	if (strcmp(form, "fw-table") != 0 && strcmp(form, "fw-entry") != 0 &&
	    strcmp(form, "fw-object") != 0 && strcmp(form, "fw-trace") != 0 &&
	    strcmp(form, "fw-ktrace") != 0 && strcmp(form, "fw-nat") != 0 &&
	    strcmp(form, "fw-qos") != 0)
		return (false);
	if (strcmp(form, "fw-qos") == 0)
		return (qos_form(f));
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(form, "fw-nat") == 0) {
		if (nat_words(f, words, sizeof(words)))
			object_job(s, "nat", words, jbool(f, "persist"));
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
		snprintf(fw.t_dir, sizeof(fw.t_dir), "%s", jstr(f, "dir") !=
		    NULL ? jstr(f, "dir") : "in");
		if (fw.t_src[strspn(fw.t_src, "0123456789abcdefABCDEF.:")] !=
		    '\0' || fw.t_dst[strspn(fw.t_dst, "0123456789abcdefABCDEF"
		    ".:")] != '\0' || fw.t_src[0] == '\0' || fw.t_dst[0] ==
		    '\0') {
			toast(true, "A packet is followed from one IPv4 or IPv6 "
			    "address to another");
			return (true);
		}
		if (fw.t_loading)
			return (true);
		fw.t_asked = true;
		fw.t_loading = true;
		fw.t_error[0] = '\0';
		{
			char	url[640];

			snprintf(url, sizeof(url), "/api/servers/%s/ipfw/path?"
			    "src=%s&dst=%s&proto=%s&port=%s&interface=%s%s%s",
			    s->id, fw.t_src, fw.t_dst, fw.t_proto, fw.t_port,
			    fw.t_if, fw.jail[0] != '\0' ? "&jail=" : "",
			    fw.jail);
			api("GET", url, NULL, trace_cb, NULL);
		}
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
		/* A console prefix list: an entry a prefix, a job each. */
		if (jstr(f, "pfx") != NULL && jstr(f, "pfx")[0] != '\0') {
			const ucl_object_t	*l = pfxlist_get(jstr(f, "pfx")), *e;
			ucl_object_iter_t	 it = NULL;
			int			 n = 0;

			while ((e = ucl_object_iterate(jget(l, "prefixes"), &it,
			    true)) != NULL && n < 512) {
				snprintf(words, sizeof(words), "%s add %s%s%s",
				    jstr(f, "table") != NULL ? jstr(f, "table") : "",
				    ucl_object_tostring_forced(e), b[0] != '\0' ? " " :
				    "", b);
				object_job(s, "table", words, jbool(f, "persist"));
				n++;
			}
			if (n == 0)
				toast(true, "The list %s is empty, or unknown", jstr(f,
				    "pfx"));
			if (a[0] == '\0')
				return (true);
		}
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
/*
 * The numbers of a part that have a rule of Arcana's: 1 now (set 0), 2
 * kept, 3 both.  65536 of them, to free.
 */
static uint8_t *
taken_in(int lo, int hi)
{
	ucl_object_t		*arr;
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	uint8_t			*t;
	const char		*w;

	if ((t = calloc(65537, 1)) == NULL)
		abort();
	arr = rows_of(lo, hi);
	it = NULL;
	while ((o = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (!row_ours(o))
			continue;
		w = jstr(o, "where");
		t[jint(o, "num", 0)] |= strncmp(w, "now", 3) == 0 ? 1 : 0;
		t[jint(o, "num", 0)] |= strcmp(w, "now only") != 0 ? 2 : 0;
	}
	ucl_object_unref(arr);
	return (t);
}

/*
 * Room for a rule just after number anchor (after) or just before it:
 * *tp the number it takes, and pairs, from and to with the farthest
 * first, that move the rules in its way on by one when no number is
 * free there (the next rules make room, as BASIC's lines did).
 * *sidesp has what the pairs touch, now (1) and kept (2).  False, and
 * why, when the part has no room left.
 */
static bool
plan_place(const uint8_t *taken, int lo, int hi, long long anchor,
    bool after, long long *tp, char *pairs, size_t plen, int *sidesp,
    char *why, size_t wlen)
{
	long long	j, m, n2;
	size_t		off;

	pairs[0] = '\0';
	*sidesp = 0;
	off = 0;
	if (after) {
		if (anchor + 1 > hi) {
			snprintf(why, wlen, "%05lld is the end of this part: no "
			    "number after it", anchor);
			return (false);
		}
		if (!taken[anchor + 1]) {
			for (n2 = anchor + 1; n2 <= hi && !taken[n2]; n2++)
				;
			*tp = (anchor + n2) / 2;
			if (*tp <= anchor)
				*tp = anchor + 1;
			return (true);
		}
		for (j = anchor + 1; j <= hi && taken[j]; j++)
			;
		if (j > hi) {
			snprintf(why, wlen, "No number is free after %05lld up to "
			    "the end of this part (%05d): the rules there are "
			    "packed; move one to another part first", anchor, hi);
			return (false);
		}
		for (m = j - 1; m >= anchor + 1; m--) {
			off += (size_t)snprintf(pairs + off, plen > off ? plen -
			    off : 0, "%s%lld %lld", off > 0 ? " " : "", m, m + 1);
			*sidesp |= taken[m];
		}
		*tp = anchor + 1;
		return (off < plen);
	}
	if (anchor - 1 < lo) {
		snprintf(why, wlen, "%05lld is the start of this part: no number "
		    "before it", anchor);
		return (false);
	}
	if (!taken[anchor - 1]) {
		for (n2 = anchor - 1; n2 >= lo && !taken[n2]; n2--)
			;
		*tp = (anchor + n2 + 1) / 2;
		if (*tp >= anchor)
			*tp = anchor - 1;
		return (true);
	}
	for (j = anchor - 1; j >= lo && taken[j]; j--)
		;
	if (j < lo) {
		snprintf(why, wlen, "No number is free before %05lld down to the "
		    "start of this part (%05d): the rules there are packed; "
		    "move one to another part first", anchor, lo);
		return (false);
	}
	for (m = j + 1; m <= anchor - 1; m++) {
		off += (size_t)snprintf(pairs + off, plen > off ? plen - off : 0,
		    "%s%lld %lld", off > 0 ? " " : "", m, m - 1);
		*sidesp |= taken[m];
	}
	*tp = anchor - 1;
	return (off < plen);
}

/*
 * The rule being changed placed just after or before anchor: where a
 * number is free, it is offered (Save moves it, with its words as
 * they are in the box); where none is, the rules in its way are moved
 * on by one first, asked.  Its own move goes in the same job when it
 * is its number's only rule, and is Save's otherwise.
 */
static void
place_rule(long long anchor, bool after)
{
	uint8_t		*taken;
	long long	 cur, t;
	char		 pairs[1200], why[200], arg[1300], body[1400];
	char		 readable[900];
	int		 sides, alone, lo, hi;

	cur = fw.edit;
	lo = sects[fw.sect].lo;
	hi = sects[fw.sect].hi;
	taken = taken_in(lo, hi);
	alone = num_rows(cur) <= 1;
	if (!plan_place(taken, lo, hi, anchor, after, &t, pairs, sizeof(pairs),
	    &sides, why, sizeof(why))) {
		toast(true, "%s", why);
		free(taken);
		return;
	}
	sides |= taken[cur];
	free(taken);
	if (pairs[0] == '\0') {
		fw.move = t == cur ? 0 : t;
		return;
	}
	snprintf(arg, sizeof(arg), "%d %d %s%s", (sides & 1) != 0, (sides &
	    2) != 0, pairs, "");
	if (alone)
		snprintf(arg + strlen(arg), sizeof(arg) - strlen(arg),
		    " %lld %lld", cur, t);
	/* The pairs said as a sentence: 01702 becomes 01703, ... */
	{
		char		*copy, *p, *f, *t2;
		size_t		 o = 0;

		copy = strdup(pairs);
		p = copy;
		readable[0] = '\0';
		while ((f = strsep(&p, " ")) != NULL && (t2 = strsep(&p, " ")) !=
		    NULL)
			o += (size_t)snprintf(readable + o, sizeof(readable) > o ?
			    sizeof(readable) - o : 0, "%s%05lld becomes %05lld",
			    o > 0 ? ", " : "", atoll(f), atoll(t2));
		free(copy);
	}
	snprintf(body, sizeof(body), "No number is free there, so the rules in "
	    "the way move on by one, the farthest first: %s%s. Then this rule "
	    "takes %05lld%s. No rule is deleted: each is put at its new number "
	    "before its old one goes, and nothing is done if a number is not "
	    "free by then.", readable, (sides & 3) == 3 ? ", now "
	    "and in the kept rules" : (sides & 1) ? ", now" : ", in the kept "
	    "rules", t, alone ? "" : " when you Save, as it shares its number "
	    "with another rule");
	confirm("Make room for the rule", body, "Move them", false, NULL,
	    "do-fw-renumber", arg, alone ? "" : "move");
	if (!alone)
		fw.move = t;
}

static bool
more_action(struct server *s, const char *act, const char *arg,
    const char *value)
{
	char			 words[400], body[400];
	long long		 cur;

	if (strcmp(act, "fw-alias-edit") == 0) {
		snprintf(alias_edit, sizeof(alias_edit), "%s", arg);
		return (true);
	}
	if (strcmp(act, "fw-alias-del") == 0) {
		snprintf(words, sizeof(words), "%s delete", arg);
		object_job(s, "alias", words, true);
		alias_edit[0] = '\0';
		return (true);
	}
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
		 * A rule dropped before or after another of the part: placed
		 * there, the rules in its way moved on by one when no number
		 * is free (asked first).  Dropped above its place, it goes
		 * before the rule that follows the one dropped on; below,
		 * after the one before, so that the rules made to move are
		 * never the dropped one.
		 */
		uint8_t		*taken;
		long long	 at, x;
		const char	*slash, *colon;
		bool		 after;

		cur = atoll(arg);
		fw.edit = cur;
		fw.edit_k = (slash = strchr(arg, '/')) != NULL ? atoi(slash + 1) :
		    0;
		fw.move = 0;
		at = atoll(value);
		colon = strchr(value, ':');
		after = colon == NULL || strcmp(colon + 1, "before") != 0;
		if (cur <= 0 || at <= 0)
			return (true);
		taken = taken_in(sects[fw.sect].lo, sects[fw.sect].hi);
		if (num_rows(cur) <= 1)
			taken[cur] = 0;
		if (after && at < cur) {
			for (x = at + 1; x < cur && !taken[x]; x++)
				;
			free(taken);
			if (x >= cur)
				return (true);	/* already there */
			place_rule(x, false);
		} else if (!after && at > cur) {
			for (x = at - 1; x > cur && !taken[x]; x--)
				;
			free(taken);
			if (x <= cur)
				return (true);
			place_rule(x, true);
		} else {
			free(taken);
			place_rule(at, after);
		}
	} else if (strcmp(act, "fw-move") == 0 && fw.edit > 0 && fw.sect >=
	    0) {
		/*
		 * One place up or down: past the rule above or below.  A
		 * rule that shares its number goes past its twin first.
		 */
		uint8_t		*taken;
		long long	 x;
		int		 nr;

		cur = fw.edit;
		nr = num_rows(cur);
		taken = taken_in(sects[fw.sect].lo, sects[fw.sect].hi);
		if (arg[0] == 'u') {
			if (fw.edit_k > 0) {
				free(taken);
				place_rule(cur, false);
				return (true);
			}
			for (x = cur - 1; x >= sects[fw.sect].lo && !taken[x]; x--)
				;
			free(taken);
			if (x < sects[fw.sect].lo)
				toast(true, "It is the first of its part already");
			else
				place_rule(x, false);
		} else {
			if (fw.edit_k < nr - 1) {
				free(taken);
				place_rule(cur, true);
				return (true);
			}
			for (x = cur + 1; x <= sects[fw.sect].hi && !taken[x]; x++)
				;
			free(taken);
			if (x > sects[fw.sect].hi)
				toast(true, "It is the last of its part already");
			else
				place_rule(x, true);
		}
	} else if (strcmp(act, "do-fw-renumber") == 0) {
		/* "live kept from to ...": one job, the host checking it
		 * whole before it moves anything. */
		struct html	 b;
		char		*copy, *p, *w;
		int		 live, kept, k;

		copy = strdup(arg);
		p = copy;
		live = (w = strsep(&p, " ")) != NULL ? atoi(w) : 0;
		kept = (w = strsep(&p, " ")) != NULL ? atoi(w) : 0;
		memset(&b, 0, sizeof(b));
		h_raw(&b, "{\"kind\":\"ipfw\",\"verb\":\"renumber\",\"args\":[");
		k = 0;
		while ((w = strsep(&p, " ")) != NULL)
			if (*w != '\0' && strspn(w, "0123456789") == strlen(w))
				h_fmt(&b, "%s\"%s\"", k++ > 0 ? "," : "", w);
		h_fmt(&b, "],\"live\":%s,\"persist\":%s}", live ? "true" :
		    "false", kept ? "true" : "false");
		/* The title: the pairs, after the two sides' flags. */
		{
			const char	*t = arg;
			int		 sk;

			for (sk = 0; sk < 2 && t != NULL; sk++)
				t = (t = strchr(t, ' ')) != NULL ? t + 1 : NULL;
			snprintf(words, sizeof(words), "ipfw renumber %.300s",
			    t != NULL ? t : "");
		}
		fw_job(s, b.s, words);
		free(b.s);
		free(copy);
		/* Its own move is Save's when it shares its number. */
		if (value == NULL || value[0] == '\0')
			fw.edit = fw.move = 0;
	} else
		return (false);
	return (true);
}

/* The part a rule's number is in, or -1. */
static int
sect_of(long long num)
{
	size_t	i;

	for (i = 0; i < nitems(sects); i++)
		if (num >= sects[i].lo && num <= sects[i].hi)
			return ((int)i);
	return (-1);
}

/*
 * The chain drawn: the parts every packet walks down the left, the
 * parts they call on the right, an arrow for each call or skipto a
 * rule makes, and on each part how many rules it has and what they take
 * a second (while Live counters are read).  Pressed, a part opens.
 */
#define	CH_W	200
#define	CH_H	30
#define	CH_GAP	8
#define	CH_X2	430
#define	CH_CW	250
static void
chain_graph(struct html *h, const ucl_object_t *live,
    const ucl_object_t *kept)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	double			 rate[nitems(sects)], r;
	int			 n[nitems(sects)], k[nitems(sects)], i, j, to;
	int			 x1, y1, x2, y2, ymax;
	char			 edges[64][2];
	const char		*t, *p;
	int			 ne = 0, e;
	bool			 dup;

	for (i = 0; i < (int)nitems(sects); i++) {
		n[i] = count(live, sects[i].lo, sects[i].hi);
		k[i] = count(kept, sects[i].lo, sects[i].hi);
		rate[i] = 0;
	}
	/* What each part takes, and whom it calls. */
	it = NULL;
	while ((o = ucl_object_iterate(live, &it, true)) != NULL) {
		if ((i = sect_of(jint(o, "num", 0))) < 0)
			continue;
		if ((r = rate_of(jint(o, "num", 0), jint(o, "pkts", 0))) > 0)
			rate[i] += r;
		/* The action is the rule's first word, after a prob or a
		 * set (ipfw -S show writes "call 9000 ip6 from ..."). */
		t = jstr(o, "text") != NULL ? jstr(o, "text") : "";
		if (strncmp(t, "set ", 4) == 0) {
			t += 4 + strspn(t + 4, "0123456789");
			t += strspn(t, " ");
		}
		if (strncmp(t, "prob ", 5) == 0) {
			t += 5;
			t += strcspn(t, " ");
			t += strspn(t, " ");
		}
		if (strncmp(t, "call ", 5) == 0)
			p = t + 5;
		else if (strncmp(t, "skipto ", 7) == 0)
			p = t + 7;
		else
			continue;
		if ((to = sect_of(atoi(p))) < 0 || to == i || ne == 64)
			continue;
		dup = false;
		for (e = 0; e < ne; e++)
			if (edges[e][0] == i && edges[e][1] == to)
				dup = true;
		if (!dup) {
			edges[ne][0] = (char)i;
			edges[ne][1] = (char)to;
			ne++;
		}
	}
	ymax = 14 + 15 * (CH_H + CH_GAP);
	h_fmt(h, "<div class=\"fwchain-wrap\"><svg class=\"fwchain\" viewBox=\""
	    "0 0 %d %d\" role=\"img\" aria-label=\"The chain of the "
	    "firewall's parts\"><defs><marker id=\"fwarrow\" viewBox=\"0 0 "
	    "8 8\" refX=\"7\" refY=\"4\" markerWidth=\"6\" markerHeight="
	    "\"6\" orient=\"auto\"><path d=\"M0 0L8 4L0 8z\"/></marker>"
	    "</defs>", CH_X2 + CH_CW + 10, ymax);
	h_fmt(h, "<text class=\"head\" x=\"%d\" y=\"9\">The chain, down</text>"
	    "<text class=\"head\" x=\"%d\" y=\"9\">Called from it</text>",
	    10, CH_X2);
	/* The calls first, under the boxes. */
	for (e = 0; e < ne; e++) {
		i = edges[e][0];
		j = edges[e][1];
		if (i < 10) {
			x1 = 10 + CH_W;
			y1 = 14 + i * (CH_H + CH_GAP) * 3 / 2 + CH_H / 2;
		} else {
			x1 = CH_X2;
			y1 = 14 + (i - 10) * (CH_H + CH_GAP) + CH_H / 2;
		}
		if (j < 10) {
			x2 = 10 + CH_W;
			y2 = 14 + j * (CH_H + CH_GAP) * 3 / 2 + CH_H / 2;
		} else {
			x2 = CH_X2;
			y2 = 14 + (j - 10) * (CH_H + CH_GAP) + CH_H / 2;
		}
		h_fmt(h, "<path class=\"call%s\" d=\"M%d %dC%d %d %d %d %d %d\" "
		    "marker-end=\"url(#fwarrow)\"><title>%s %s %s</title></path>",
		    j < 10 ? " skip" : "", x1, y1, x1 + 80, y1, x2 - 80, y2,
		    x2, y2, sects[i].name, j < 10 ? "skips to" : "calls",
		    sects[j].name);
	}
	for (i = 0; i < (int)nitems(sects); i++) {
		if (i < 10) {
			x1 = 10;
			y1 = 14 + i * (CH_H + CH_GAP) * 3 / 2;
			x2 = CH_W;
		} else {
			x1 = CH_X2;
			y1 = 14 + (i - 10) * (CH_H + CH_GAP);
			x2 = CH_CW;
		}
		h_fmt(h, "<g class=\"part%s%s\" data-act=\"fw-sect\" data-arg=\""
		    "%d\" transform=\"translate(%d,%d)\"><title>%d to %d: %s"
		    "</title><rect width=\"%d\" height=\"%d\" rx=\"6\"/>"
		    "<text class=\"num\" x=\"8\" y=\"14\">%d</text><text class="
		    "\"name\" x=\"8\" y=\"28\">", n[i] == 0 && k[i] == 0 ?
		    " none" : "", fw.sect == i ? " on" : "", i, x1, y1,
		    sects[i].lo, sects[i].hi, sects[i].what[0] != '\0' ?
		    sects[i].what : sects[i].name, x2, CH_H, sects[i].lo);
		h_txt(h, sects[i].name);
		h_fmt(h, "</text><text class=\"stat\" x=\"%d\" y=\"14\">%d",
		    x2 - 8, n[i]);
		if (k[i] != n[i])
			h_fmt(h, " · %d kept", k[i]);
		h_raw(h, "</text>");
		if (rate[i] >= 0.05)
			h_fmt(h, "<text class=\"rate\" x=\"%d\" y=\"28\">+%.1f"
			    "/s</text>", x2 - 8, rate[i]);
		h_raw(h, "</g>");
		/* Down the chain. */
		if (i < 9)
			h_fmt(h, "<path class=\"down\" d=\"M%d %dL%d %d\" "
			    "marker-end=\"url(#fwarrow)\"/>", x1 + 40, y1 + CH_H,
			    x1 + 40, y1 + (CH_H + CH_GAP) * 3 / 2);
	}
	h_raw(h, "</svg><ul class=\"glegend\"><li class=\"fw-down\">down the "
	    "chain, part to part</li><li class=\"fw-call\">call: there and "
	    "back</li><li class=\"fw-skip\">skipto: there, not back</li><li "
	    "class=\"box dashed\">a part no rule is in</li><li class=\"fw-rate"
	    "\"><b>12/s</b> packets a second, now</li></ul></div>");
}

/* A count in a few characters: 950, 12.4k, 3.1M, 2.0G. */
static void
count_text(char *buf, size_t len, int64_t n)
{

	if (n < 1000)
		snprintf(buf, len, "%lld", (long long)n);
	else if (n < 1000000)
		snprintf(buf, len, "%.1fk", n / 1e3);
	else if (n < 1000000000)
		snprintf(buf, len, "%.1fM", n / 1e6);
	else
		snprintf(buf, len, "%.1fG", n / 1e9);
}

static int
pkts_desc(const void *a, const void *b)
{
	int64_t	x, y;

	x = jint(*(const ucl_object_t *const *)a, "pkts", 0);
	y = jint(*(const ucl_object_t *const *)b, "pkts", 0);
	return (x > y ? -1 : x < y);
}

/* Does a rule decide where a packet goes, rather than pass it on? */
static bool
decides(const char *t)
{
	static const char *const passes[] = { "call", "return", "skipto",
	    "count", "reass", "check-state", "tag", "untag", "setdscp",
	    "setmark", "tcp-setmss", "setfib" };
	size_t	i, n;

	if (t == NULL)
		return (false);
	if (strncmp(t, "prob ", 5) == 0) {
		t += 5 + strcspn(t + 5, " ");
		t += strspn(t, " ");
	}
	for (i = 0; i < nitems(passes); i++) {
		n = strlen(passes[i]);
		if (strncmp(t, passes[i], n) == 0 && (t[n] == ' ' || t[n] ==
		    '\0'))
			return (false);
	}
	return (true);
}

/*
 * What the rules take, beside the chain: the rules that decide most, a
 * bar each long as its packets, its rate while Live reads (a call, a
 * return, a skipto pass every packet on and are left out); and those
 * that never matched since their counters were cleared: a rule that
 * never takes a packet is dead, or shadowed by one before it (count,
 * check-state and return left out).  The kernel's own last rule and
 * those of a disabled set are left out of both.  A row opens its rule.
 */
#define	BUSIEST	8
#define	NEVER	12
static void
rule_load(struct html *h, const ucl_object_t *live)
{
	const ucl_object_t	**v, *o;
	ucl_object_iter_t	  it;
	char			  buf[32];
	const char		 *t;
	int64_t			  max;
	int			  n, k, shown, never;
	double			  rate;

	if ((n = (int)ucl_array_size(live)) == 0)
		return;
	if ((v = calloc((size_t)n + 1, sizeof(*v))) == NULL)
		abort();
	n = 0;
	it = NULL;
	while ((o = ucl_object_iterate(live, &it, true)) != NULL)
		if (jint(o, "num", 0) != 65535 && !jbool(o, "disabled"))
			v[n++] = o;
	qsort(v, (size_t)n, sizeof(*v), pkts_desc);
	h_raw(h, "<div class=\"fwload\"><section><h4 class=\"family\">The "
	    "rules that decide most <small class=\"dim\">packets since the "
	    "counters were cleared</small></h4>");
	max = 0;
	for (k = 0; k < n && max == 0; k++)
		if (decides(jstr(v[k], "text")))
			max = jint(v[k], "pkts", 0);
	if (max == 0)
		h_raw(h, "<p class=\"dim\">No rule has decided a packet yet."
		    "</p>");
	else {
		h_raw(h, "<ol class=\"fwbusy\">");
		for (k = 0, shown = 0; k < n && shown < BUSIEST && jint(v[k],
		    "pkts", 0) > 0; k++) {
			if (!decides(jstr(v[k], "text")))
				continue;
			shown++;
			count_text(buf, sizeof(buf), jint(v[k], "pkts", 0));
			h_fmt(h, "<li class=\"pick\" data-act=\"fw-goto\" data-arg="
			    "\"%lld\"", (long long)jint(v[k], "num", 0));
			h_attr(h, "title", jstr(v[k], "text"));
			h_fmt(h, "><b>%05lld</b><span class=\"track\"><i style="
			    "\"width:%.1f%%\"></i></span><span class=\"val\">%s",
			    (long long)jint(v[k], "num", 0), 100.0 * (double)jint(
			    v[k], "pkts", 0) / (double)max, buf);
			rate = rate_of(jint(v[k], "num", 0), jint(v[k], "pkts",
			    0));
			if (rate >= 0.05)
				h_fmt(h, " <small class=\"rate\">+%.1f/s</small>",
				    rate);
			h_raw(h, "</span><code>");
			h_txt(h, jstr(v[k], "text"));
			h_raw(h, "</code></li>");
		}
		h_raw(h, "</ol>");
	}
	h_raw(h, "</section><section><h4 class=\"family\">Never matched "
	    "<small class=\"dim\">dead, or shadowed by a rule before</small>"
	    "</h4>");
	/* In the order of the chain. */
	qsort(v, (size_t)n, sizeof(*v), num_cmp);
	never = 0;
	for (k = 0; k < n; k++) {
		t = jstr(v[k], "text") != NULL ? jstr(v[k], "text") : "";
		if (jint(v[k], "pkts", 0) == 0 && strncmp(t, "count", 5) != 0 &&
		    strncmp(t, "check-state", 11) != 0 && strncmp(t, "return",
		    6) != 0)
			never++;
	}
	if (never == 0)
		h_raw(h, "<p class=\"dim\">Every rule has taken a packet.</p>");
	else {
		h_fmt(h, "<p class=\"dim\"><b>%d</b> of %d rules.</p><ul class=\""
		    "fwnever\">", never, n);
		for (k = 0, shown = 0; k < n && shown < NEVER; k++) {
			t = jstr(v[k], "text") != NULL ? jstr(v[k], "text") : "";
			if (jint(v[k], "pkts", 0) != 0 || strncmp(t, "count",
			    5) == 0 || strncmp(t, "check-state", 11) == 0 ||
			    strncmp(t, "return", 6) == 0)
				continue;
			shown++;
			h_fmt(h, "<li class=\"pick\" data-act=\"fw-goto\" data-arg="
			    "\"%lld\"><b>%05lld</b> <code>", (long long)jint(v[k],
			    "num", 0), (long long)jint(v[k], "num", 0));
			h_txt(h, t);
			h_raw(h, "</code></li>");
		}
		if (never > NEVER)
			h_fmt(h, "<li class=\"dim\">and %d more, in the parts "
			    "above</li>", never - NEVER);
		h_raw(h, "</ul>");
	}
	h_raw(h, "</section></div>");
	free(v);
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
	char				  buf[32];
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
	h_raw(h, ">");
	if (mine)
		fresh(h, fw.fetched, fw.loading, fw.error);
	h_raw(h, "<button class=\"icon\" data-act=\"refresh\" title=\""
	    "Read again\"><svg class=\"ti\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M20 12a8 8 0 1 1-2.3-5.7M20 4v4h-4\"/></svg></button></div>");
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
	if (fw.ask)
		view_ask(h);
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
	if (fw.sect == FW_ALIASES) {
		view_aliases(h);
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
	if (fw.sect == FW_QOS) {
		view_qos(h);
		return;
	}
	if (fw.sect < 0 || fw.sect >= (int)nitems(sects)) {
		chain_graph(h, live, kept);
		rule_load(h, live);
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
	    "<span>keep</span></label>", next, sc->lo, sc->hi, loaded ?
	    " checked" : "");
	/* A console prefix list beside the rule: kept as a table, the
	 * list's name after pl_, which the rule names as table(pl_name). */
	pfxlist_select(h, "A prefix list as a table", "pfx", "Made as table "
	    "pl_<name> from the list when the rule is added; write table(pl_"
	    "<name>) in the rule for it.", false);
	h_raw(h, "<button class=\"small\">Add</button></form>");
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
		int		 rk = (int)jint(o, "k", 0);

		if (fw.edit == num && fw.edit_k == rk && row_ours(o)) {
			/*
			 * Being changed, in its own row: its words as they
			 * are kept, which are the ones that were written,
			 * or as ipfw says them.
			 */
			kt = jstr(o, "ksrc") != NULL ? jstr(o, "ksrc") : jstr(o,
			    "ktext");
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
			    "\"fw-del\" data-arg=\"%lld/%d\" data-value=\"%s\">"
			    "Delete</button><button type=\"button\" class=\""
			    "ghost small\" data-act=\"fw-edit\" data-arg=\"0\">"
			    "Cancel</button></form></td></tr>", now && loaded ?
			    " checked" : "", keptr ? " checked" : "", num, rk,
			    strcmp(where, "now, kept") == 0 ? "both" : now ?
			    "live" : "kept");
			continue;
		}
		if (row_ours(o))
			h_fmt(h, "<tr class=\"pick%s\" data-act=\"fw-edit\" "
			    "data-arg=\"%lld/%d\" data-rule=\"%lld\" draggable=\""
			    "true\" data-reorder=\"fw\" title=\"Press to change "
			    "it; drag it to another place\"><td><b>%05lld</b></td>"
			    "<td class=\"mono rule\">", now ? "" : " off", num, rk,
			    num, num);
		else
			/* Another set's: SD-WAN's own, the default rule's,
			 * or the rules Apply holds back. Not changed here. */
			h_fmt(h, "<tr class=\"off\" data-rule=\"%lld\" title=\""
			    "%s\"><td><b>%05lld</b></td><td class=\"mono "
			    "rule\">", num, strcmp(where, "set off") == 0 ?
			    "Held back by Apply in safe mode until it is "
			    "confirmed: not changed here" : "Of another set than "
			    "the kept rules' (set 0): SD-WAN's or the default "
			    "rule's, not changed here", num);
		/* Kept with aliases: its own words, ipfw's when hovered. */
		{
			const char	*src = jstr(o, "ksrc");

			if (src != NULL) {
				h_raw(h, "<span class=\"aliased\"");
				h_attr(h, "title", jstr(o, "text"));
				h_raw(h, ">");
				h_txt(h, src);
				h_raw(h, "</span>");
			} else
				h_txt(h, jstr(o, "text"));
		}
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
		/* No shell reads it: its quotes are not ipfw's. */
		if (strlen(w) >= 2 && (w[0] == '"' || w[0] == '\'') &&
		    w[strlen(w) - 1] == w[0]) {
			w[strlen(w) - 1] = '\0';
			w++;
		}
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
		h_fmt(&b, "{\"text\":%s,\"sha256\":\"%s\",\"check\":%s,"
		    "\"accept\":[%s]}", q, fw.sha, strcmp(how, "check") == 0 ?
		    "true" : "false", fw.file_acc);
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
	 * A rule changed is one job: the host has ipfw read the new one
	 * first, then takes the old one away and puts the new one in, and
	 * puts the old one back if ipfw does not take the new.
	 */
	memset(&b, 0, sizeof(b));
	if (edit && fw.edit > 0) {
		ucl_object_t	*row;

		/* The rule as it is, named by its words: another rule of
		 * its number stays. */
		row = row_find(fw.edit, fw.edit_k);
		was_live = was_kept = row != NULL && row_ours(row);
		(void)del;
		(void)o;
		(void)it;
		if (was_live || was_kept) {
			h_fmt(&b, "{\"kind\":\"ipfw\",\"verb\":\"replace\","
			    "\"args\":[\"%lld\",\"%d\"", fw.edit, num);
			rule_args(&b, rule);
			q = json_quote(row_words(row));
			h_fmt(&b, "],\"text\":%s,\"live\":%s,\"persist\":%s}", q,
			    jbool(f, "live") ? "true" : "false", jbool(f,
			    "persist") ? "true" : "false");
			free(q);
			ucl_object_unref(row);
			snprintf(title, sizeof(title), "ipfw %lld changed: %d "
			    "%.130s", fw.edit, num, rule);
			fw_job(s, b.s, title);
			free(b.s);
			fw.edit = 0;
			fw.move = 0;
			return (true);
		}
		if (row != NULL)
			ucl_object_unref(row);
	}
	/* The prefix list picked: its table made, or filled again, and
	 * its entries added, before the rule that names it. */
	if (jstr(f, "pfx") != NULL && jstr(f, "pfx")[0] != '\0') {
		const ucl_object_t	*l = pfxlist_get(jstr(f, "pfx")), *e;
		ucl_object_iter_t	 it = NULL;
		char			 words[400];
		int			 n = 0;

		snprintf(words, sizeof(words), "pl_%s create or-flush type addr",
		    jstr(f, "pfx"));
		object_job(s, "table", words, jbool(f, "persist"));
		while ((e = ucl_object_iterate(jget(l, "prefixes"), &it, true)) !=
		    NULL && n++ < 512) {
			snprintf(words, sizeof(words), "pl_%s add %s", jstr(f,
			    "pfx"), ucl_object_tostring_forced(e));
			object_job(s, "table", words, jbool(f, "persist"));
		}
	}
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
	char		 json[256], title[96], body[900];
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
	if (strcmp(act, "fw-qos-new") == 0 || strcmp(act, "fw-qos-edit") == 0) {
		snprintf(qos.kind, sizeof(qos.kind), "%s", arg);
		qos.num = act[7] == 'e' && value != NULL ? atol(value) : 0;
		app.modal = MODAL_FW_QOS;
		app.modal_error[0] = '\0';
		return (true);
	}
	if (strcmp(act, "fw-qos-del") == 0) {
		snprintf(body, sizeof(body), "%s %s taken away, now and from the "
		    "kept rules. A rule that sends to it stays, and sends to "
		    "nothing.", strcmp(arg, "sched") == 0 ? "The scheduler" :
		    strcmp(arg, "queue") == 0 ? "The queue" : "The pipe", value);
		confirm("Take it away", body, "Take away", true, "",
		    "do-fw-qos-del", arg, value);
		return (true);
	}
	if (strcmp(act, "do-fw-qos-del") == 0) {
		if (strcmp(arg, "pipe") == 0 || strcmp(arg, "sched") == 0 ||
		    strcmp(arg, "queue") == 0) {
			snprintf(body, sizeof(body), "%ld delete", atol(value));
			object_job(s, arg, body, true);
		}
		return (true);
	}
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
		/* "num/k": the number's k-th row, two rules of a number
		 * being two rows. */
		const char	*slash = strchr(arg, '/');
		int		 k = slash != NULL ? atoi(slash + 1) : 0;

		if (atoll(arg) == fw.edit && k == fw.edit_k)
			fw.edit = 0;
		else {
			fw.edit = atoll(arg);
			fw.edit_k = k;
		}
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
		fw.ask = fw.then_apply = false;
		fw.setting = 0;
		fw.set_error[0] = '\0';
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
	} else if (strcmp(act, "fw-file-accept") == 0) {
		/* The warning accepted, the same text kept again. */
		if (fw.file_tag[0] != '\0' && fw.text != NULL &&
		    strlen(fw.file_acc) + strlen(fw.file_tag) + 4 <
		    sizeof(fw.file_acc)) {
			struct html	b;
			char		url[400], *q;

			snprintf(fw.file_acc + strlen(fw.file_acc),
			    sizeof(fw.file_acc) - strlen(fw.file_acc),
			    "%s\"%s\"", fw.file_acc[0] != '\0' ? "," : "",
			    fw.file_tag);
			fw.file_tag[0] = '\0';
			memset(&b, 0, sizeof(b));
			q = json_quote(fw.text);
			h_fmt(&b, "{\"text\":%s,\"sha256\":\"%s\",\"accept\":"
			    "[%s]}", q, fw.sha, fw.file_acc);
			free(q);
			fw.file_loading = true;
			snprintf(url, sizeof(url), "/api/servers/%s/ipfw/rules"
			    "%s%s", s->id, fw.jail[0] != '\0' ? "?jail=" : "",
			    fw.jail);
			api("POST", url, b.s, file_cb, strdup("write"));
			free(b.s);
		}
	} else if (strcmp(act, "fw-skeleton") == 0) {
		free(fw.text);
		fw.text = strdup(skeleton);
		snprintf(fw.file_note, sizeof(fw.file_note), "The layout, not "
		    "kept yet: make it this host's own, then Keep.");
	} else if (strcmp(act, "fw-apply") == 0) {
		fw.set_error[0] = '\0';
		apply_ask(s, false);
	} else if (strcmp(act, "fw-ask-no") == 0) {
		fw.ask = fw.then_apply = false;
		fw.setting = 0;
		fw.set_error[0] = '\0';
	} else if (strcmp(act, "fw-set-apply") == 0 && fw.setting == 0) {
		const ucl_object_t	*t;
		ucl_object_iter_t	 it;
		char			*q, *qj, *j;

		/* Each at once and in sysctl.conf, as the sysctl page sets
		 * one; the firewall is read again once they are done. */
		fw.set_error[0] = '\0';
		fw.then_apply = true;
		it = NULL;
		while ((t = ucl_object_iterate(jget(fw.data, "tunables"), &it,
		    true)) != NULL) {
			if (!needs_it(t) || jstr(t, "name") == NULL)
				continue;
			q = json_quote(jstr(t, "name"));
			qj = json_quote(fw.jail);
			if (asprintf(&j, "{\"kind\":\"sysctl\",\"args\":[%s,\"%lld\"]"
			    ",\"persist\":true%s%s}", q, (long long)jint(t, "want",
			    1), fw.jail[0] != '\0' ? ",\"jail\":" : "",
			    fw.jail[0] != '\0' ? qj : "") == -1)
				abort();
			free(q);
			free(qj);
			snprintf(title, sizeof(title), "sysctl %s=%lld%s%s",
			    jstr(t, "name"), (long long)jint(t, "want", 1),
			    fw.jail[0] != '\0' ? " in " : "", fw.jail);
			fw.setting++;
			job_send_host(s, j, title, JOB_FIREWALL, fw.jail);
		}
		if (fw.setting == 0)
			apply_ask(s, true);
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
		/* That rule alone, named by its words: another of its
		 * number stays. */
		const char	*slash = strchr(arg, '/');
		ucl_object_t	*row;
		struct html	 b;

		if ((row = row_find(atoll(arg), slash != NULL ? atoi(slash + 1) :
		    0)) == NULL || !row_ours(row)) {
			toast(true, "That rule is not there any more: the page "
			    "reads the firewall again");
			if (row != NULL)
				ucl_object_unref(row);
			refresh_firewall(s, true);
			return (true);
		}
		memset(&b, 0, sizeof(b));
		h_fmt(&b, "{\"kind\":\"ipfw\",\"verb\":\"delete\",\"args\":"
		    "[\"%d\"", atoi(arg));
		rule_args(&b, row_words(row));
		h_fmt(&b, "],\"live\":%s,\"persist\":%s}", strcmp(value, "kept") ==
		    0 ? "false" : "true", strcmp(value, "live") == 0 ? "false" :
		    "true");
		snprintf(title, sizeof(title), "ipfw delete %d %.60s", atoi(arg),
		    row_words(row));
		fw_job(s, b.s, title);
		free(b.s);
		ucl_object_unref(row);
		fw.edit = 0;
	}
	return (true);
}
