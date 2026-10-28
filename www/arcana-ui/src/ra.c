/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An interface's router advertisements, on the Network tab's
 * Interfaces: RFC 8349's ipv6-router-advertisements with arcana-ra's
 * augments, as the host's rtadvd.conf(5) has them (rtadvd(8),
 * rtadvctl(8)).  Read from the host's running datastore, and beside it
 * what rtadvd sends now, from operational (rtadvctl show).  Edited
 * here, a copy; saved as the NACM page saves: the node put in the
 * host's candidate (RFC 8527), committed confirmed with a token of the
 * page's own, confirmed at once.  A warning the host stops at (its
 * error-app-tag, rc-conf-files for one) is shown with a way to accept
 * it and commit again.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "app.h"

#define	RA_KEY		"ietf-ipv6-unicast-routing:ipv6-router-advertisements"
#define	ST_KEY		"arcana-ra:rtadvd"
#define	TIMEOUT		120		/* seconds a commit waits */

static struct {
	char		 sid[16];	/* the host */
	char		 ifname[32];	/* its interface shown */
	bool		 open;
	ucl_object_t	*read;		/* running's node; NULL: none yet */
	ucl_object_t	*oper;		/* operational's rtadvd; NULL: none */
	ucl_object_t	*edit;		/* the copy edited, NULL: none */
	bool		 loading;
	bool		 busy;		/* a save on its way */
	unsigned	 gen;
	char		 error[512];
	char		 note[512];	/* how the last save went */
	char		 tag[64];	/* a warning to accept, its app-tag */
	char		 token[40];	/* a commit waiting: its persist */
	double		 until;		/* and when the host undoes it (ms) */
} ra;

/* The host's paths: the node below a datastore's root, or an rpc's. */
static void
url_of(char *buf, size_t len, const char *ds, const char *tail)
{

	if (ds == NULL)
		snprintf(buf, len, "/restconf/data/arcana-fleet:fleet/host=%s%s",
		    ra.sid, tail);
	else
		snprintf(buf, len, "/restconf/ds/ietf-datastores:%s/"
		    "arcana-fleet:fleet/host=%s/ietf-interfaces:interfaces/"
		    "interface=%s/ietf-ip:ipv6/" RA_KEY "%s", ds, ra.sid,
		    ra.ifname, tail);
}

static const char *
rc_why(const ucl_object_t *o, const char *err)
{
	const char	*m;

	if ((m = jstr(o, "ietf-restconf:errors.error.0.error-message")) !=
	    NULL)
		return (m);
	return (err != NULL ? err : "the console did not answer");
}

static void
drop_all(void)
{

	if (ra.read != NULL)
		ucl_object_unref(ra.read);
	if (ra.oper != NULL)
		ucl_object_unref(ra.oper);
	if (ra.edit != NULL)
		ucl_object_unref(ra.edit);
	ra.read = ra.oper = ra.edit = NULL;
}

static void
read_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	unsigned	gen = (unsigned)(uintptr_t)arg;
	const ucl_object_t *n;

	if (gen != ra.gen)
		return;
	ra.loading = false;
	if (ra.read != NULL)
		ucl_object_unref(ra.read);
	ra.read = NULL;
	if (status == 404 || (status == 200 && jget(o, RA_KEY) == NULL))
		ra.error[0] = '\0';	/* no record yet: an empty form */
	else if (status != 200 || (n = jget(o, RA_KEY)) == NULL)
		snprintf(ra.error, sizeof(ra.error), "%s", rc_why(o, err));
	else {
		ra.error[0] = '\0';
		ra.read = ucl_object_copy(n);
	}
	render();
}

static void
oper_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	unsigned	gen = (unsigned)(uintptr_t)arg;
	const ucl_object_t *n;

	(void)err;
	if (gen != ra.gen)
		return;
	if (ra.oper != NULL)
		ucl_object_unref(ra.oper);
	ra.oper = NULL;
	if (status == 200 && (n = jget(o, RA_KEY "." ST_KEY)) != NULL)
		ra.oper = ucl_object_copy(n);
	render();
}

static void
ra_load(void)
{
	char	url[320];

	ra.loading = true;
	ra.gen++;
	url_of(url, sizeof(url), "running", "");
	api("GET", url, NULL, read_cb, (void *)(uintptr_t)ra.gen);
	url_of(url, sizeof(url), "operational", "/" ST_KEY);
	api("GET", url, NULL, oper_cb, (void *)(uintptr_t)ra.gen);
}

/* The panel opened for an interface of the host shown. */
static void
ra_open(const char *sid, const char *ifname)
{

	if (strcmp(sid, ra.sid) != 0 || strcmp(ifname, ra.ifname) != 0) {
		drop_all();
		ra.error[0] = ra.note[0] = ra.token[0] = ra.tag[0] = '\0';
		snprintf(ra.sid, sizeof(ra.sid), "%s", sid);
		snprintf(ra.ifname, sizeof(ra.ifname), "%s", ifname);
	}
	ra.open = true;
	ra_load();
}

/* The node as configuration: the read's, what rtadvd reports left out. */
static ucl_object_t *
config_of(const ucl_object_t *o)
{
	ucl_object_t	*c;

	c = o != NULL ? ucl_object_copy(o) : ucl_object_typed_new(UCL_OBJECT);
	ucl_object_delete_key(c, ST_KEY);
	return (c);
}

static ucl_object_t *
editing(void)
{

	if (ra.edit == NULL)
		ra.edit = config_of(ra.read);
	return (ra.edit);
}

/* The array at key of o, made when not there. */
static ucl_object_t *
array_at(ucl_object_t *o, const char *key)
{
	ucl_object_t	*a;

	if ((a = (ucl_object_t *)(uintptr_t)jget(o, key)) == NULL ||
	    ucl_object_type(a) != UCL_ARRAY) {
		a = ucl_object_typed_new(UCL_ARRAY);
		ucl_object_replace_key(o, a, key, 0, true);
	}
	return (a);
}

/* Element i of an array. */
static ucl_object_t *
nth(const ucl_object_t *a, int64_t i)
{
	ucl_object_iter_t	 it = NULL;
	const ucl_object_t	*x;
	int64_t			 k = 0;

	if (a == NULL || i < 0)
		return (NULL);
	while ((x = ucl_object_iterate(a, &it, true)) != NULL)
		if (k++ == i)
			return ((ucl_object_t *)(uintptr_t)x);
	return (NULL);
}

static void
remove_at(ucl_object_t *a, int64_t i)
{
	ucl_object_t	*x;

	if ((x = nth(a, i)) != NULL)
		ucl_object_unref(ucl_array_delete(a, x));
}

/* ---- The form ---------------------------------------------------------- */

/* A number of the node, or "" where not set. */
static const char *
numtext(const ucl_object_t *o, const char *key, char *buf, size_t len)
{

	if (jget(o, key) == NULL)
		return ("");
	snprintf(buf, len, "%lld", (long long)jint(o, key, 0));
	return (buf);
}

/* A number's input: its value where set, rtadvd's default as the
 * placeholder, the capability named in its title. */
static void
num_field(struct html *h, const ucl_object_t *o, const char *key,
    const char *name, const char *label, const char *dflt, const char *title)
{
	char	buf[32];

	h_raw(h, "<label>");
	h_txt(h, label);
	h_fmt(h, "<input name=\"%s\" type=\"number\" min=\"0\" size=\"8\"", name);
	h_attr(h, "value", numtext(o, key, buf, sizeof(buf)));
	h_attr(h, "placeholder", dflt);
	h_attr(h, "title", title);
	h_raw(h, "></label>");
}

/* A flag's checkbox: as set, or rtadvd's default where not. */
static void
bool_field(struct html *h, const ucl_object_t *o, const char *key,
    const char *name, const char *label, bool dflt, const char *title)
{
	bool	on = jget(o, key) != NULL ? jbool(o, key) : dflt;

	h_raw(h, "<label class=\"check\"><span><input type=\"checkbox\"");
	h_fmt(h, " name=\"%s\"%s", name, on ? " checked" : "");
	h_attr(h, "title", title);
	h_raw(h, "> ");
	h_txt(h, label);
	h_raw(h, "</span></label>");
}

static void
pref_select(struct html *h, const char *name, const char *v, const char *title)
{
	static const char *const prefs[] = { "high", "medium", "low" };

	h_fmt(h, "<select name=\"%s\"", name);
	h_attr(h, "title", title);
	h_raw(h, ">");
	for (size_t i = 0; i < 3; i++)
		h_fmt(h, "<option value=\"%s\"%s>%s</option>", prefs[i],
		    strcmp(prefs[i], v != NULL ? v : "medium") == 0 ?
		    " selected" : "", prefs[i]);
	h_raw(h, "</select>");
}

/* A list of the node as a table that sorts and filters, a row's key
 * column first, a way to take the row away, and a form that adds one. */
struct lcol {
	const char	*title, *key;
	bool		 num;
};

static void
list_table(struct html *h, const char *id, const char *what,
    const ucl_object_t *arr, const struct lcol *cols, int ncol)
{
	struct tcol		 tc[8];
	const ucl_object_t	**rows;
	size_t			 i;
	int			 c;

	for (c = 0; c < ncol; c++) {
		tc[c].title = cols[c].title;
		tc[c].key = cols[c].key;
		tc[c].num = cols[c].num;
	}
	h_fmt(h, "<table class=\"net ra-list\" data-list=\"%s\">", what);
	tbl_head(h, id, tc, ncol, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows(id, arr, tc, ncol, app.filter);
	for (i = 0; rows[i] != NULL; i++) {
		int64_t	at = 0;
		char	place[24];

		/* Its place in the array, for the button: the row's. */
		for (int64_t k = 0; nth(arr, k) != NULL; k++)
			if (nth(arr, k) == rows[i])
				at = k;
		snprintf(place, sizeof(place), "%lld", (long long)at);
		h_raw(h, "<tr>");
		for (c = 0; c < ncol; c++) {
			const ucl_object_t *v = jget(rows[i], cols[c].key);
			char	buf[64];

			h_raw(h, "<td>");
			if (v == NULL)
				h_raw(h, "<span class=\"dim\">—</span>");
			else if (ucl_object_type(v) == UCL_BOOLEAN)
				h_txt(h, ucl_object_toboolean(v) ? "yes" : "no");
			else if (ucl_object_type(v) == UCL_INT) {
				snprintf(buf, sizeof(buf), "%lld",
				    (long long)ucl_object_toint(v));
				h_txt(h, buf);
			} else
				h_txt(h, ucl_object_tostring(v));
			h_raw(h, "</td>");
		}
		h_raw(h, "<td><button class=\"icon\" data-act=\"ra-del\" "
		    "title=\"Take it away\"");
		h_attr(h, "data-arg", what);
		h_attr(h, "data-value", place);
		h_raw(h, ">×</button></td></tr>");
	}
	if (i == 0)
		h_fmt(h, "<tr><td colspan=\"%d\" class=\"dim\">None.</td></tr>",
		    ncol + 1);
	free(rows);
	h_raw(h, "</tbody></table>");
}

static void
view_state(struct html *h)
{
	static const struct lcol pcols[] = { { "Prefix", "prefix", false },
	    { "From", "origin", false }, { "Valid", "valid-lifetime", true },
	    { "Preferred", "preferred-lifetime", true },
	    { "On-link", "on-link-flag", false },
	    { "Autonomous", "autonomous-flag", false } };
	static const struct lcol rcols[] = { { "Prefix", "prefix", false },
	    { "Preference", "preference", false },
	    { "Lifetime", "lifetime", true } };
	static const struct lcol dcols[] = { { "Server", "address", false },
	    { "Lifetime", "lifetime", true } };
	static const struct lcol scols[] = { { "Domain", "domain", false },
	    { "Lifetime", "lifetime", true } };
	static const struct lcol p64cols[] = { { "Prefix", "prefix", false },
	    { "Lifetime", "lifetime", true } };
	const ucl_object_t *o = ra.oper;
	char	buf[64];

	h_raw(h, "<div class=\"ra-state\"><h4>As rtadvd(8) sends it</h4>");
	if (o == NULL) {
		h_raw(h, "<p class=\"dim\">rtadvd(8) does not run on this "
		    "host, or was not started with this interface: rtadvctl(8) "
		    "show has nothing of it. Saving with “Advertise” on "
		    "starts it (rc.conf rtadvd_enable, rtadvd_interfaces)."
		    "</p></div>");
		return;
	}
	h_raw(h, "<p class=\"dim\">rtadvctl(8) show, read from the host's "
	    "operational datastore.</p><dl class=\"kv\">");
#define	KV(label, text) do {						\
	h_raw(h, "<dt>" label "</dt><dd>");				\
	h_txt(h, text);							\
	h_raw(h, "</dd>");						\
} while (0)
	KV("Interface", jstr(o, "flags") != NULL ? jstr(o, "flags") : "");
	KV("Status", jstr(o, "status") != NULL ? jstr(o, "status") : "");
	snprintf(buf, sizeof(buf), "%lld s / %lld s", (long long)jint(o,
	    "min-rtr-adv-interval", 0), (long long)jint(o,
	    "max-rtr-adv-interval", 0));
	KV("Interval, least / most", buf);
	snprintf(buf, sizeof(buf), "%lld s", (long long)jint(o,
	    "default-lifetime", 0));
	KV("Router lifetime", buf);
	snprintf(buf, sizeof(buf), "%s%s%s, preference %s", jbool(o,
	    "managed-flag") ? "M" : "", jbool(o, "other-config-flag") ? "O" :
	    "", !jbool(o, "managed-flag") && !jbool(o, "other-config-flag") ?
	    "none" : "", jstr(o, "router-preference") != NULL ? jstr(o,
	    "router-preference") : "medium");
	KV("Flags", buf);
	snprintf(buf, sizeof(buf), "%lld ms / %lld ms, hop limit %lld",
	    (long long)jint(o, "reachable-time", 0), (long long)jint(o,
	    "retrans-timer", 0), (long long)jint(o, "cur-hop-limit", 0));
	KV("Reachable / retrans", buf);
	snprintf(buf, sizeof(buf), "%s", jint(o, "link-mtu", 0) > 0 ?
	    numtext(o, "link-mtu", buf, sizeof(buf)) : "none");
	KV("MTU option", buf);
	KV("Interface's own prefixes", jbool(o, "interface-prefixes") ?
	    "advertised" : "not advertised");
	KV("Next / last sent", "");
	h_raw(h, "<dd>");
	h_txt(h, jstr(o, "next-send") != NULL ? jstr(o, "next-send") :
	    "never");
	h_raw(h, " / ");
	h_txt(h, jstr(o, "last-send") != NULL ? jstr(o, "last-send") :
	    "never");
	h_raw(h, "</dd>");
#undef KV
	h_raw(h, "</dl>");
	if (jget(o, "prefix") != NULL) {
		h_raw(h, "<h5>Prefixes</h5>");
		list_table(h, "ra-st-prefix", "st-prefix", jget(o, "prefix"),
		    pcols, 6);
	}
	if (jget(o, "route") != NULL) {
		h_raw(h, "<h5>Routes</h5>");
		list_table(h, "ra-st-route", "st-route", jget(o, "route"),
		    rcols, 3);
	}
	if (jget(o, "rdnss") != NULL) {
		h_raw(h, "<h5>DNS servers</h5>");
		list_table(h, "ra-st-rdnss", "st-rdnss", jget(o, "rdnss"),
		    dcols, 2);
	}
	if (jget(o, "dnssl") != NULL) {
		h_raw(h, "<h5>Search list</h5>");
		list_table(h, "ra-st-dnssl", "st-dnssl", jget(o, "dnssl"),
		    scols, 2);
	}
	if (jget(o, "pref64") != NULL) {
		h_raw(h, "<h5>NAT64 prefixes</h5>");
		list_table(h, "ra-st-pref64", "st-pref64", jget(o, "pref64"),
		    p64cols, 2);
	}
	h_raw(h, "</div>");
}

void
view_ra(struct html *h, struct server *s)
{
	static const struct lcol pcols[] = { { "Prefix", "prefix-spec", false },
	    { "On-link", "on-link-flag", false },
	    { "Autonomous", "autonomous-flag", false },
	    { "Valid", "valid-lifetime", true },
	    { "Preferred", "preferred-lifetime", true },
	    { "Valid counts down", "arcana-ra:valid-lifetime-decrements",
	    false }, { "Preferred counts down",
	    "arcana-ra:preferred-lifetime-decrements", false } };
	static const struct lcol rcols[] = { { "Prefix", "prefix", false },
	    { "Preference", "preference", false },
	    { "Lifetime", "lifetime", true } };
	static const struct lcol dcols[] = { { "Server", "address", false },
	    { "Lifetime", "lifetime", true } };
	static const struct lcol scols[] = { { "Domain", "domain", false },
	    { "Lifetime", "lifetime", true } };
	static const struct lcol p64cols[] = { { "Prefix", "prefix", false },
	    { "Lifetime", "lifetime", true } };
	const ucl_object_t	*o;
	ucl_object_t		*other;
	ucl_object_iter_t	 it = NULL;
	const ucl_object_t	*x;
	int64_t			 i;

	if (!ra.open || strcmp(ra.sid, s->id) != 0)
		return;
	o = ra.edit != NULL ? ra.edit : ra.read;
	h_raw(h, "<section class=\"ra\" id=\"ra\"><h3 class=\"secsub\">Router "
	    "advertisements on ");
	h_txt(h, ra.ifname);
	h_raw(h, " <button class=\"icon\" data-act=\"ra-close\" title=\"Close\">"
	    "×</button></h3><p class=\"dim\">What rtadvd(8) sends on the "
	    "interface, its record in rtadvd.conf(5), with every capability "
	    "the file takes; saved to the host's running configuration by a "
	    "confirmed commit (RFC 8349 ietf-ipv6-router-advertisements, "
	    "Arcana's arcana-ra for the rest). The host reloads rtadvd "
	    "(rtadvctl reload) or restarts it where the interfaces it runs "
	    "on change.</p>");
	if (ra.error[0] != '\0') {
		h_raw(h, "<p class=\"err\">");
		h_txt(h, ra.error);
		h_raw(h, " <button class=\"ghost small\" data-act=\"ra-retry\">"
		    "Read again</button></p>");
	}
	if (ra.note[0] != '\0') {
		h_raw(h, "<p class=\"note\">");
		h_txt(h, ra.note);
		if (ra.tag[0] != '\0' && !ra.busy) {
			h_raw(h, " <button class=\"small\" data-act=\"ra-accept\">"
			    "Accept ");
			h_txt(h, ra.tag);
			h_raw(h, " and commit again</button>");
		}
		if (ra.token[0] != '\0' && !ra.busy)
			h_fmt(h, " <button class=\"ghost small\" data-act=\""
			    "ra-cancel\">Undo now</button> <small class=\"dim\">"
			    "%d s left</small>", (int)((ra.until - arc_now()) /
			    1000));
		h_raw(h, "</p>");
	}
	if (ra.loading && ra.read == NULL && ra.edit == NULL) {
		h_raw(h, "<p class=\"dim\">Reading…</p></section>");
		return;
	}
	h_raw(h, "<div class=\"ra-two\"><div>");
	h_raw(h, "<form class=\"secform\" data-form=\"ra-main\"><h4>The "
	    "advertisement</h4>");
	bool_field(h, o, "send-advertisements", "send", "Advertise on this "
	    "interface", false, "rtadvd(8) run on it: rc.conf rtadvd_enable "
	    "and rtadvd_interfaces");
	num_field(h, o, "max-rtr-adv-interval", "maxinterval", "Most seconds "
	    "between advertisements", "600", "rtadvd.conf(5) maxinterval: 4 to "
	    "1800");
	num_field(h, o, "min-rtr-adv-interval", "mininterval", "Least seconds "
	    "between", "a third of the most", "rtadvd.conf(5) mininterval: 3 "
	    "to 3/4 of maxinterval");
	num_field(h, o, "default-lifetime", "rltime", "Router lifetime (s)",
	    "1800", "rtadvd.conf(5) rltime: 0, or maxinterval to 9000; 0 "
	    "says this is no default router");
	num_field(h, o, "cur-hop-limit", "chlim", "Hop limit", "64",
	    "rtadvd.conf(5) chlim");
	num_field(h, o, "reachable-time", "rtime", "Reachable time (ms)", "0",
	    "rtadvd.conf(5) rtime: 0 leaves it to the hosts");
	num_field(h, o, "retrans-timer", "retrans", "Retrans timer (ms)", "0",
	    "rtadvd.conf(5) retrans: 0 leaves it to the hosts");
	h_raw(h, "<label>Router preference ");
	pref_select(h, "pref", jstr(o, "arcana-ra:router-preference"),
	    "rtadvd.conf(5) raflags h or l (RFC 4191)");
	h_raw(h, "</label>");
	bool_field(h, o, "managed-flag", "managed", "Managed addresses (M): "
	    "DHCPv6 gives addresses", false, "rtadvd.conf(5) raflags m");
	bool_field(h, o, "other-config-flag", "other", "Other configuration "
	    "(O): DHCPv6 gives the rest", false, "rtadvd.conf(5) raflags o");
	num_field(h, o, "link-mtu", "mtu", "MTU option", "0: none",
	    "rtadvd.conf(5) mtu");
	bool_field(h, o, "arcana-ra:link-mtu-auto", "mtuauto", "MTU option: "
	    "the interface's own", false, "rtadvd.conf(5) mtu=auto");
	bool_field(h, o, "arcana-ra:interface-prefixes", "ifprefixes",
	    "Advertise the interface's own prefixes", true, "off: "
	    "rtadvd.conf(5) noifprefix, the prefixes below alone");
	bool_field(h, o, "arcana-ra:source-link-layer-address", "lladdr",
	    "Source link-layer address option", true, "off: rtadvd.conf(5) "
	    "nolladdr");
	num_field(h, o, "arcana-ra:clock-skew", "clockskew", "Clock skew "
	    "allowed (s)", "0", "rtadvd.conf(5) clockskew, for prefixes whose "
	    "lifetimes count down");
	h_raw(h, "<div class=\"actions\"><button class=\"small\">Keep</button>"
	    "</div></form>");

	h_raw(h, "<h4>Prefixes</h4><p class=\"dim\">rtadvd.conf(5) addr, "
	    "prefixlen, pinfoflags, vltime, pltime, vltimedecr, pltimedecr.</p>");
	list_table(h, "ra-prefix", "prefix-list.prefix", jget(o,
	    "prefix-list.prefix"), pcols, 7);
	h_raw(h, "<form class=\"secform\" data-form=\"ra-prefix\"><label>Prefix "
	    "<input name=\"prefix\" required placeholder=\"2001:db8:1::/64\" "
	    "size=\"24\"></label><label>Valid (s) <input name=\"valid\" "
	    "type=\"number\" placeholder=\"2592000\"></label><label>Preferred "
	    "(s) <input name=\"preferred\" type=\"number\" placeholder=\""
	    "604800\"></label><label class=\"check\"><span><input type=\""
	    "checkbox\" name=\"onlink\" checked> On-link (L)</span></label>"
	    "<label class=\"check\"><span><input type=\"checkbox\" name=\"auto\" "
	    "checked> Autonomous (A): hosts make addresses</span></label>"
	    "<label class=\"check\"><span><input type=\"checkbox\" name=\"vdecr\">"
	    " Valid counts down</span></label><label class=\"check\"><span>"
	    "<input type=\"checkbox\" name=\"pdecr\"> Preferred counts down"
	    "</span></label><div class=\"actions\"><button class=\"small\">"
	    "Add</button></div></form>");

	h_raw(h, "<h4>Routes (RFC 4191)</h4><p class=\"dim\">rtadvd.conf(5) "
	    "rtprefix, rtplen, rtflags, rtltime.</p>");
	list_table(h, "ra-route", "arcana-ra:route", jget(o, "arcana-ra:route"),
	    rcols, 3);
	h_raw(h, "<form class=\"secform\" data-form=\"ra-route\"><label>Prefix "
	    "<input name=\"prefix\" required placeholder=\"2001:db8:100::/48\" "
	    "size=\"24\"></label><label>Preference ");
	pref_select(h, "pref", "medium", "rtflags");
	h_raw(h, "</label><label>Lifetime (s) <input name=\"lifetime\" type=\""
	    "number\" placeholder=\"the router lifetime\"></label><div class=\""
	    "actions\"><button class=\"small\">Add</button></div></form>");

	h_raw(h, "<h4>DNS servers (RFC 8106 RDNSS)</h4><p class=\"dim\">"
	    "rtadvd.conf(5) rdnss, rdnssltime.</p>");
	list_table(h, "ra-rdnss", "arcana-ra:rdnss", jget(o, "arcana-ra:rdnss"),
	    dcols, 2);
	h_raw(h, "<form class=\"secform\" data-form=\"ra-rdnss\"><label>Server "
	    "<input name=\"address\" required placeholder=\"2001:db8::53\" "
	    "size=\"24\"></label><label>Lifetime (s) <input name=\"lifetime\" "
	    "type=\"number\" placeholder=\"3/2 of the most interval\"></label>"
	    "<div class=\"actions\"><button class=\"small\">Add</button></div>"
	    "</form>");

	h_raw(h, "<h4>Search list (RFC 8106 DNSSL)</h4><p class=\"dim\">"
	    "rtadvd.conf(5) dnssl, dnsslltime.</p>");
	list_table(h, "ra-dnssl", "arcana-ra:dnssl", jget(o, "arcana-ra:dnssl"),
	    scols, 2);
	h_raw(h, "<form class=\"secform\" data-form=\"ra-dnssl\"><label>Domain "
	    "<input name=\"domain\" required placeholder=\"example.com\" "
	    "size=\"24\"></label><label>Lifetime (s) <input name=\"lifetime\" "
	    "type=\"number\" placeholder=\"3/2 of the most interval\"></label>"
	    "<div class=\"actions\"><button class=\"small\">Add</button></div>"
	    "</form>");

	h_raw(h, "<h4>NAT64 prefixes (RFC 8781 PREF64)</h4><p class=\"dim\">"
	    "rtadvd.conf(5) pref64, pref64len (96, 64, 56, 48, 40 or 32), "
	    "pref64lifetime.</p>");
	list_table(h, "ra-pref64", "arcana-ra:pref64", jget(o,
	    "arcana-ra:pref64"), p64cols, 2);
	h_raw(h, "<form class=\"secform\" data-form=\"ra-pref64\"><label>Prefix "
	    "<input name=\"prefix\" required placeholder=\"64:ff9b::/96\" "
	    "size=\"24\"></label><label>Lifetime (s) <input name=\"lifetime\" "
	    "type=\"number\" max=\"65528\" placeholder=\"3 router lifetimes\">"
	    "</label><div class=\"actions\"><button class=\"small\">Add</button>"
	    "</div></form>");

	h_raw(h, "<h4>Other capabilities</h4><p class=\"dim\">Fields of the "
	    "record no leaf above holds, as rtadvd.conf(5) has them (name#"
	    "number, name=string, name): kept as written.</p><ul class=\""
	    "chips\">");
	other = (ucl_object_t *)(uintptr_t)jget(o, "arcana-ra:other-capability");
	i = 0;
	while ((x = ucl_object_iterate(other, &it, true)) != NULL) {
		char	buf[24];

		h_raw(h, "<li class=\"chip mono\"><span>");
		h_txt(h, ucl_object_tostring(x));
		h_raw(h, "</span><button class=\"icon\" data-act=\"ra-del\" "
		    "data-arg=\"arcana-ra:other-capability\"");
		snprintf(buf, sizeof(buf), "%lld", (long long)i++);
		h_attr(h, "data-value", buf);
		h_raw(h, ">×</button></li>");
	}
	h_raw(h, "</ul><form class=\"secform\" data-form=\"ra-other\"><label>"
	    "Field <input name=\"text\" required placeholder=\"hatime#100\" "
	    "size=\"24\" pattern=\"[^:\\n]*\"></label><div class=\"actions\">"
	    "<button class=\"small\">Add</button></div></form>");

	if (ra.edit != NULL)
		h_fmt(h, "<p class=\"saveline\"><button data-act=\"ra-save\"%s>"
		    "Save to the host</button> <button class=\"ghost\" data-act=\""
		    "ra-discard\">Discard the changes</button> <small class=\""
		    "dim\">Put in the host's candidate and committed confirmed, "
		    "confirmed at once; undone by the host in %d s if not.</small>"
		    "</p>", ra.busy ? " disabled" : "", TIMEOUT);
	h_raw(h, "</div>");
	view_state(h);
	h_raw(h, "</div></section>");
}

/* ---- Saving ------------------------------------------------------------ */

static void
cancel_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	ra.busy = false;
	if (status == 204 || status == 200) {
		ra.token[0] = '\0';
		snprintf(ra.note, sizeof(ra.note), "Undone: the advertisements "
		    "are as they were.");
	} else
		snprintf(ra.note, sizeof(ra.note), "Not undone: %s", rc_why(o,
		    err));
	ra_load();
	render();
}

static void
confirm_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	ra.busy = false;
	if (status == 204 || status == 200) {
		ra.token[0] = '\0';
		snprintf(ra.note, sizeof(ra.note), "Saved: rtadvd.conf holds "
		    "the record, and rtadvd(8) sends by it.");
		if (ra.edit != NULL)
			ucl_object_unref(ra.edit);
		ra.edit = NULL;
		toast(false, "Router advertisements saved");
	} else
		snprintf(ra.note, sizeof(ra.note), "Not confirmed (%s): the "
		    "host undoes the change at the timeout.", rc_why(o, err));
	ra_load();
	render();
}

static void
commit_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	url[320], body[160];

	(void)arg;
	if (status != 204 && status != 200) {
		const char	*tag = jstr(o,
		    "ietf-restconf:errors.error.0.error-app-tag");

		ra.busy = false;
		ra.token[0] = '\0';
		/* A warning the host stops at: offered to be accepted, where
		 * its tag is a plain word (it goes into a query). */
		snprintf(ra.tag, sizeof(ra.tag), "%s", h_word(tag, ""));
		snprintf(ra.note, sizeof(ra.note), "Not committed: %s",
		    rc_why(o, err));
		render();
		return;
	}
	snprintf(ra.note, sizeof(ra.note), "Committed; confirming.");
	url_of(url, sizeof(url), NULL, "/ietf-netconf:commit");
	snprintf(body, sizeof(body), "{\"ietf-netconf:input\":{\"persist-id\":"
	    "\"%s\"}}", ra.token);
	api("POST", url, body, confirm_cb, NULL);
	render();
}

/* The candidate committed confirmed, with the warnings accepted. */
static void
commit(const char *accept)
{
	uint8_t	r[16];
	char	url[400], body[200];

	if (getentropy(r, sizeof(r)) != 0) {
		ra.busy = false;
		snprintf(ra.note, sizeof(ra.note), "Not saved: no randomness "
		    "for the commit's token");
		render();
		return;
	}
	for (size_t i = 0; i < sizeof(r); i++)
		snprintf(ra.token + 2 * i, sizeof(ra.token) - 2 * i, "%02x",
		    r[i]);
	ra.until = arc_now() + TIMEOUT * 1000.0;
	url_of(url, sizeof(url), NULL, "/ietf-netconf:commit");
	if (h_word(accept, NULL) != NULL)
		snprintf(url + strlen(url), sizeof(url) - strlen(url),
		    "?arcana-accept=%s", accept);
	snprintf(body, sizeof(body), "{\"ietf-netconf:input\":{\"confirmed\":"
	    "[null],\"confirm-timeout\":%d,\"persist\":\"%s\"}}", TIMEOUT,
	    ra.token);
	api("POST", url, body, commit_cb, NULL);
}

static void
put_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 204 && status != 200 && status != 201) {
		ra.busy = false;
		snprintf(ra.note, sizeof(ra.note), "Not saved: %s", rc_why(o,
		    err));
		render();
		return;
	}
	commit(NULL);
}

static void
save(void)
{
	ucl_object_t	*top;
	char		 url[320], *json;

	if (ra.edit == NULL || ra.busy)
		return;
	ra.busy = true;
	ra.note[0] = ra.tag[0] = '\0';
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_ref(ra.edit), RA_KEY, 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	url_of(url, sizeof(url), "candidate", "");
	api("PUT", url, json, put_cb, NULL);
	free(json);
}

/* ---- Actions and forms ------------------------------------------------- */

bool
ra_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 url[320], body[160];

	if (strncmp(act, "ra-", 3) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "ra-open") == 0) {
		ra_open(s->id, arg);
		return (true);
	}
	if (strcmp(act, "ra-close") == 0) {
		ra.open = false;
		return (true);
	}
	if (strcmp(act, "ra-retry") == 0) {
		ra.error[0] = '\0';
		ra_load();
		return (true);
	}
	if (strcmp(act, "ra-save") == 0) {
		save();
		return (true);
	}
	if (strcmp(act, "ra-accept") == 0 && ra.tag[0] != '\0' && !ra.busy) {
		char	tag[64];

		snprintf(tag, sizeof(tag), "%s", ra.tag);
		ra.busy = true;
		ra.tag[0] = '\0';
		commit(tag);
		return (true);
	}
	if (strcmp(act, "ra-discard") == 0) {
		if (ra.edit != NULL)
			ucl_object_unref(ra.edit);
		ra.edit = NULL;
		return (true);
	}
	if (strcmp(act, "ra-cancel") == 0 && ra.token[0] != '\0') {
		ra.busy = true;
		url_of(url, sizeof(url), NULL, "/ietf-netconf:cancel-commit");
		snprintf(body, sizeof(body), "{\"ietf-netconf:input\":{"
		    "\"persist-id\":\"%s\"}}", ra.token);
		api("POST", url, body, cancel_cb, NULL);
		return (true);
	}
	if (strcmp(act, "ra-del") == 0 && arg != NULL && value != NULL) {
		ucl_object_t	*o = editing(), *a;

		if (strcmp(arg, "prefix-list.prefix") == 0) {
			ucl_object_t	*pl;

			if ((pl = (ucl_object_t *)(uintptr_t)jget(o,
			    "prefix-list")) == NULL)
				return (true);
			a = array_at(pl, "prefix");
		} else
			a = array_at(o, arg);
		remove_at(a, strtoll(value, NULL, 10));
	}
	return (true);
}

/* A form's number into the node at key, or the key taken out where the
 * field is empty. */
static void
set_num(ucl_object_t *o, const char *key, const ucl_object_t *f,
    const char *name)
{
	const char	*v = jstr(f, name);

	if (v == NULL || v[0] == '\0')
		ucl_object_delete_key(o, key);
	else
		ucl_object_replace_key(o, ucl_object_fromint(strtoll(v, NULL,
		    10)), key, 0, true);
}

static bool
checked(const ucl_object_t *f, const char *name)
{

	return (jget(f, name) != NULL && (jbool(f, name) || (jstr(f, name) !=
	    NULL && strcmp(jstr(f, name), "on") == 0)));
}

/* A flag into the node; where it is rtadvd's default and was not set,
 * left out: the file stays as short as it was. */
static void
set_bool(ucl_object_t *o, const char *key, const ucl_object_t *f,
    const char *name, bool dflt)
{
	bool	on = checked(f, name);

	if (on == dflt && jget(o, key) == NULL)
		return;
	ucl_object_replace_key(o, ucl_object_frombool(on), key, 0, true);
}

bool
ra_form(const char *form, const ucl_object_t *f)
{
	ucl_object_t	*o, *e;
	const char	*v;

	if (strncmp(form, "ra-", 3) != 0)
		return (false);
	o = editing();
	if (strcmp(form, "ra-main") == 0) {
		set_bool(o, "send-advertisements", f, "send", false);
		set_num(o, "max-rtr-adv-interval", f, "maxinterval");
		set_num(o, "min-rtr-adv-interval", f, "mininterval");
		set_num(o, "default-lifetime", f, "rltime");
		set_num(o, "cur-hop-limit", f, "chlim");
		set_num(o, "reachable-time", f, "rtime");
		set_num(o, "retrans-timer", f, "retrans");
		v = jstr(f, "pref");
		if (v != NULL && strcmp(v, "medium") != 0)
			ucl_object_replace_key(o, ucl_object_fromstring(v),
			    "arcana-ra:router-preference", 0, true);
		else
			ucl_object_delete_key(o, "arcana-ra:router-preference");
		set_bool(o, "managed-flag", f, "managed", false);
		set_bool(o, "other-config-flag", f, "other", false);
		set_num(o, "link-mtu", f, "mtu");
		set_bool(o, "arcana-ra:link-mtu-auto", f, "mtuauto", false);
		set_bool(o, "arcana-ra:interface-prefixes", f, "ifprefixes",
		    true);
		set_bool(o, "arcana-ra:source-link-layer-address", f, "lladdr",
		    true);
		set_num(o, "arcana-ra:clock-skew", f, "clockskew");
		return (true);
	}
	e = ucl_object_typed_new(UCL_OBJECT);
	if (strcmp(form, "ra-prefix") == 0) {
		ucl_object_t	*pl;

		if ((v = jstr(f, "prefix")) == NULL || strchr(v, '/') == NULL) {
			ucl_object_unref(e);
			toast(true, "A prefix with its length is needed");
			return (true);
		}
		ucl_object_insert_key(e, ucl_object_fromstring(v),
		    "prefix-spec", 0, true);
		set_num(e, "valid-lifetime", f, "valid");
		set_num(e, "preferred-lifetime", f, "preferred");
		ucl_object_insert_key(e, ucl_object_frombool(checked(f,
		    "onlink")), "on-link-flag", 0, true);
		ucl_object_insert_key(e, ucl_object_frombool(checked(f,
		    "auto")), "autonomous-flag", 0, true);
		if (checked(f, "vdecr"))
			ucl_object_insert_key(e, ucl_object_frombool(true),
			    "arcana-ra:valid-lifetime-decrements", 0, true);
		if (checked(f, "pdecr"))
			ucl_object_insert_key(e, ucl_object_frombool(true),
			    "arcana-ra:preferred-lifetime-decrements", 0, true);
		if ((pl = (ucl_object_t *)(uintptr_t)jget(o, "prefix-list")) ==
		    NULL) {
			pl = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(o, pl, "prefix-list", 0, true);
		}
		ucl_array_append(array_at(pl, "prefix"), e);
	} else if (strcmp(form, "ra-route") == 0) {
		if ((v = jstr(f, "prefix")) == NULL || strchr(v, '/') == NULL) {
			ucl_object_unref(e);
			toast(true, "A prefix with its length is needed");
			return (true);
		}
		ucl_object_insert_key(e, ucl_object_fromstring(v), "prefix", 0,
		    true);
		if (jstr(f, "pref") != NULL && strcmp(jstr(f, "pref"),
		    "medium") != 0)
			ucl_object_insert_key(e, ucl_object_fromstring(jstr(f,
			    "pref")), "preference", 0, true);
		set_num(e, "lifetime", f, "lifetime");
		ucl_array_append(array_at(o, "arcana-ra:route"), e);
	} else if (strcmp(form, "ra-rdnss") == 0) {
		if ((v = jstr(f, "address")) == NULL || v[0] == '\0') {
			ucl_object_unref(e);
			return (true);
		}
		ucl_object_insert_key(e, ucl_object_fromstring(v), "address", 0,
		    true);
		set_num(e, "lifetime", f, "lifetime");
		ucl_array_append(array_at(o, "arcana-ra:rdnss"), e);
	} else if (strcmp(form, "ra-dnssl") == 0) {
		if ((v = jstr(f, "domain")) == NULL || v[0] == '\0') {
			ucl_object_unref(e);
			return (true);
		}
		ucl_object_insert_key(e, ucl_object_fromstring(v), "domain", 0,
		    true);
		set_num(e, "lifetime", f, "lifetime");
		ucl_array_append(array_at(o, "arcana-ra:dnssl"), e);
	} else if (strcmp(form, "ra-pref64") == 0) {
		if ((v = jstr(f, "prefix")) == NULL || strchr(v, '/') == NULL) {
			ucl_object_unref(e);
			toast(true, "A prefix with its length is needed");
			return (true);
		}
		ucl_object_insert_key(e, ucl_object_fromstring(v), "prefix", 0,
		    true);
		set_num(e, "lifetime", f, "lifetime");
		ucl_array_append(array_at(o, "arcana-ra:pref64"), e);
	} else if (strcmp(form, "ra-other") == 0) {
		ucl_object_unref(e);
		if ((v = jstr(f, "text")) == NULL || v[0] == '\0')
			return (true);
		ucl_array_append(array_at(o, "arcana-ra:other-capability"),
		    ucl_object_fromstring(v));
	} else
		ucl_object_unref(e);
	return (true);
}

/* A commit waiting: its countdown drawn again each second. */
void
ra_tick(double now)
{
	static double	last;

	if (ra.token[0] == '\0' || now - last < 1000)
		return;
	last = now;
	if (now > ra.until + 2000) {
		ra.token[0] = '\0';
		snprintf(ra.note, sizeof(ra.note), "The host undid the change "
		    "that was not confirmed.");
		ra_load();
	}
	render();
}
