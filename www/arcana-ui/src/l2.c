/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Bridges and geneve tunnels of a host, or of a jail with a network of
 * its own.  A bridge is drawn as the switch it is: a port for each
 * member, coloured by what the spanning tree made of it, with the VLAN
 * it is in untagged (an access port) or those it carries tagged (a
 * trunk).  A member that has an address is marked: its addresses
 * belong on the bridge.  A geneve tunnel has its mode, its identifier
 * and where it leads, and each of its options to be set.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	char	bridge[16];	/* the member being set is of this bridge */
	char	member[16];
	char	mode[8];	/* "access", "trunk", or "" */
	char	geneve[16];	/* the tunnel being set, or "+" for a new */
} l2;

static void
l2_job(struct server *s, const char *kind, const char *ifname,
    const char *verb, const char *args, bool persist)
{
	char	*json, title[200];

	if (asprintf(&json, "{\"kind\":\"%s\",\"interface\":\"%s\",\"verb\":"
	    "\"%s\",\"args\":[%s],\"persist\":%s}", kind, ifname, verb, args,
	    persist ? "true" : "false") == -1)
		abort();
	snprintf(title, sizeof(title), "%s %s", ifname, verb);
	job_send(s, json, title, JOB_IFACE, ifname);
}

static bool
word_ok(const char *s, const char *more)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 400)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <=
		    'z') || (s[i] >= 'A' && s[i] <= 'Z') || strchr(more,
		    s[i]) != NULL))
			return (false);
	return (true);
}

static bool
flag_of(const ucl_object_t *m, const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(jget(m, "flags"), &it, true)) != NULL)
		if (strcmp(ucl_object_tostring_forced(o), name) == 0)
			return (true);
	return (false);
}

void
view_bridges(struct html *h, struct server *s, const ucl_object_t *bridges)
{
	static const struct tcol	cols[] = {
		{ "Member", "name", false }, { "Port", "port", true },
		{ "Mode", "mode", false }, { "Untagged", "untagged", true },
		{ "Tagged", "tagged", false }, { "Role", "role", false },
		{ "State", "state", false }, { "Cost", "cost", true },
	};
	const ucl_object_t		**rows, *b, *m, *a;
	ucl_object_iter_t		  it, mit, ait;
	const char			 *name, *state, *role, *mn;
	char				  id[40];
	int				  r, n;
	bool				  first;

	(void)s;
	n = 0;
	it = NULL;
	while ((b = ucl_object_iterate(bridges, &it, true)) != NULL) {
		n++;
		name = jstr(b, "name") != NULL ? jstr(b, "name") : "";
		snprintf(id, sizeof(id), "bridge-%.20s", name);
		h_raw(h, "<section class=\"pane bridge\">");
		box_head(h, id, "h4");
		h_raw(h, "<span>");
		h_txt(h, name);
		h_fmt(h, "</span><span class=\"chip%s\">%s</span>", jbool(b,
		    "vlanfilter") ? "" : " dim", jbool(b, "vlanfilter") ?
		    "filters VLANs" : "no VLAN filtering");
		h_raw(h, "<span class=\"chip dim\">");
		h_txt(h, jstr(b, "proto"));
		h_raw(h, "</span>");
		if (jbool(b, "is_root"))
			h_raw(h, "<span class=\"chip\" title=\"Every other "
			    "bridge of the network reckons its paths to this "
			    "one\">root of the spanning tree</span>");
		h_fmt(h, "<button class=\"ghost small\" data-act=\"br-filter\" "
		    "data-value=\"%s\"", jbool(b, "vlanfilter") ? "off" : "on");
		h_attr(h, "data-arg", name);
		h_fmt(h, ">%s</button></h4>", jbool(b, "vlanfilter") ? "Stop "
		    "filtering VLANs" : "Filter VLANs");
		/* Folded: its name and what it is, and no more. */
		if (box_shut(id)) {
			h_raw(h, "</section>");
			continue;
		}
		h_raw(h, "<p class=\"dim\">");
		if (!jbool(b, "is_root")) {
			h_raw(h, "The root is <code>");
			h_txt(h, jstr(b, "root"));
			h_fmt(h, "</code>, priority %lld, through port %lld at "
			    "a cost of %lld. ", (long long)jint(b,
			    "root_priority", 0), (long long)jint(b, "root_port",
			    0), (long long)jint(b, "root_cost", 0));
		}
		h_raw(h, "This bridge is <code>");
		h_txt(h, jstr(b, "id"));
		h_fmt(h, "</code>, priority %lld; hello %lld s, forward delay "
		    "%lld s, max age %lld s.</p>", (long long)jint(b,
		    "priority", 0), (long long)jint(b, "hellotime", 0),
		    (long long)jint(b, "fwddelay", 0), (long long)jint(b,
		    "maxage", 0));

		/* The ports, as on the front of a switch. */
		h_raw(h, "<div class=\"ports\">");
		mit = NULL;
		while ((m = ucl_object_iterate(jget(b, "members"), &mit,
		    true)) != NULL) {
			state = jstr(m, "state");
			role = jstr(m, "role");
			mn = jstr(m, "name") != NULL ? jstr(m, "name") : "";
			h_fmt(h, "<div class=\"port st-%s%s\" data-act=\""
			    "br-pick\"", !jbool(m, "stp") ? "nostp" : state !=
			    NULL ? state : "unknown", strcmp(l2.bridge, name) ==
			    0 && strcmp(l2.member, mn) == 0 ? " sel" : "");
			h_attr(h, "data-arg", name);
			h_attr(h, "data-value", mn);
			h_attr(h, "title", !jbool(m, "stp") ? "Not in the "
			    "spanning tree: it forwards whatever the tree "
			    "says" : state != NULL && strcmp(state,
			    "forwarding") == 0 ? "Forwarding" : state != NULL &&
			    (strcmp(state, "discarding") == 0 || strcmp(state,
			    "blocking") == 0) ? "Not forwarding: the spanning "
			    "tree holds it back, since another path leads the "
			    "same way" : "On its way to forwarding");
			h_raw(h, "><i class=\"led\"></i><b>");
			h_txt(h, mn);
			h_fmt(h, "</b><small>port %lld", (long long)jint(m,
			    "port", 0));
			if (jbool(m, "stp") && role != NULL) {
				h_raw(h, " · ");
				h_txt(h, role);
				h_raw(h, " · ");
				h_txt(h, state);
			}
			h_raw(h, "</small><span class=\"vl\">");
			if (jstr(m, "mode") == NULL)
				h_raw(h, "no VLAN");
			else if (strcmp(jstr(m, "mode"), "access") == 0)
				h_fmt(h, "access %lld", (long long)jint(m,
				    "untagged", 0));
			else {
				h_raw(h, "trunk ");
				h_txt(h, jstr(m, "tagged"));
				if (jget(m, "untagged") != NULL)
					h_fmt(h, " · native %lld", (long long)
					    jint(m, "untagged", 0));
			}
			h_raw(h, "</span>");
			if (ucl_array_size(jget(m, "addresses")) > 0)
				h_raw(h, "<span class=\"warn\" title=\"A member "
				    "of a bridge should have no address: it "
				    "belongs on the bridge\">has an address"
				    "</span>");
			h_raw(h, "</div>");
		}
		h_raw(h, "</div><ul class=\"map-legend static\"><li class=\""
		    "p-fwd\">forwarding</li><li class=\"p-learn\">learning"
		    "</li><li class=\"p-block\">held back</li><li class=\""
		    "p-off\">not in the spanning tree</li></ul>");

		/* The member picked: what it is to be. */
		if (strcmp(l2.bridge, name) == 0 && l2.member[0] != '\0') {
			mit = NULL;
			while ((m = ucl_object_iterate(jget(b, "members"), &mit,
			    true)) != NULL)
				if (strcmp(jstr(m, "name"), l2.member) == 0)
					break;
			if (m != NULL) {
				h_raw(h, "<form data-form=\"br-port\" class=\""
				    "br-port\"><b>");
				h_txt(h, l2.member);
				h_fmt(h, "</b><select name=\"mode\"><option "
				    "value=\"access\"%s>access port</option>"
				    "<option value=\"trunk\"%s>trunk</option>"
				    "</select><label>untagged VLAN<input name="
				    "\"untagged\" inputmode=\"numeric\" size=\""
				    "5\"", jstr(m, "mode") == NULL || strcmp(
				    jstr(m, "mode"), "access") == 0 ?
				    " selected" : "", jstr(m, "mode") != NULL &&
				    strcmp(jstr(m, "mode"), "trunk") == 0 ?
				    " selected" : "");
				if (jget(m, "untagged") != NULL)
					h_fmt(h, " value=\"%lld\"", (long long)
					    jint(m, "untagged", 0));
				h_raw(h, "></label><label>tagged VLANs (a "
				    "trunk's)<input name=\"tagged\" spellcheck="
				    "\"false\" placeholder=\"10-20,30 or all\"");
				h_attr(h, "value", jstr(m, "tagged"));
				h_raw(h, "></label><label class=\"toggle\">"
				    "<input type=\"checkbox\" name=\"persist\">"
				    "<span>keep in rc.conf</span></label>"
				    "<button class=\"small\">Set</button>");
				h_fmt(h, "<button type=\"button\" class=\"ghost "
				    "small\" data-act=\"br-flag\" data-arg=\"%s"
				    "stp\">%s</button>", jbool(m, "stp") ? "-" :
				    "", jbool(m, "stp") ? "Out of the spanning "
				    "tree" : "Into the spanning tree");
				h_fmt(h, "<button type=\"button\" class=\"ghost "
				    "small\" data-act=\"br-flag\" data-arg=\"%s"
				    "edge\" title=\"An edge port leads to a "
				    "host, not to another bridge: it forwards "
				    "at once\">%s</button>", flag_of(m, "edge") ?
				    "-" : "", flag_of(m, "edge") ? "Not an "
				    "edge port" : "Edge port");
				h_raw(h, "<button type=\"button\" class=\"ghost "
				    "small danger\" data-act=\"br-del\">Take "
				    "out of the bridge</button></form>");
				if (ucl_array_size(jget(m, "addresses")) > 0) {
					h_raw(h, "<div class=\"notice warn\">");
					h_txt(h, l2.member);
					h_raw(h, " has ");
					first = true;
					ait = NULL;
					while ((a = ucl_object_iterate(jget(m,
					    "addresses"), &ait, true)) !=
					    NULL) {
						h_raw(h, first ? "<code>" :
						    ", <code>");
						h_txt(h,
						    ucl_object_tostring_forced(
						    a));
						h_raw(h, "</code>");
						first = false;
					}
					h_raw(h, ". A member's addresses belong "
					    "on the bridge: no more can be "
					    "added to it from here, and these "
					    "can be removed under Interfaces."
					    "</div>");
				}
			}
		}
		snprintf(id, sizeof(id), "br-%.20s", name);
		h_raw(h, "<table class=\"net brmembers\">");
		tbl_head(h, id, cols, 8, 0);
		h_raw(h, "<tbody>");
		rows = tbl_rows(id, jget(b, "members"), cols, 8, app.filter);
		for (r = 0; (m = rows[r]) != NULL; r++) {
			h_raw(h, "<tr class=\"pick\" data-act=\"br-pick\"");
			h_attr(h, "data-arg", name);
			h_attr(h, "data-value", jstr(m, "name"));
			h_raw(h, "><td><b>");
			h_txt(h, jstr(m, "name"));
			h_fmt(h, "</b></td><td>%lld</td><td>", (long long)jint(
			    m, "port", 0));
			h_txt(h, jstr(m, "mode") != NULL ? jstr(m, "mode") :
			    "—");
			h_raw(h, "</td><td>");
			if (jget(m, "untagged") != NULL)
				h_fmt(h, "%lld", (long long)jint(m, "untagged",
				    0));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(m, "tagged"));
			h_raw(h, "</td><td>");
			h_txt(h, jbool(m, "stp") ? jstr(m, "role") : "—");
			h_raw(h, "</td><td>");
			h_txt(h, jbool(m, "stp") ? jstr(m, "state") : "—");
			h_fmt(h, "</td><td class=\"dim\">%lld</td></tr>",
			    (long long)jint(m, "cost", 0));
		}
		free(rows);
		h_raw(h, "</tbody></table><form data-form=\"br-add\" class=\""
		    "kmod-load\"><input type=\"hidden\" name=\"bridge\"");
		h_attr(h, "value", name);
		h_raw(h, "><input name=\"member\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"an interface to take "
		    "in: epair0a, em1\"><label class=\"toggle\"><input type=\""
		    "checkbox\" name=\"persist\"><span>keep in rc.conf</span>"
		    "</label><button class=\"ghost small\">Add member</button>"
		    "</form></section>");
	}
	if (n == 0)
		h_raw(h, "<div class=\"empty\"><p>No bridge here. One is made "
		    "under Interfaces, with + interface.</p></div>");
}

static void
opt(struct html *h, const char *label, const char *name, const char *value,
    const char *hint)
{

	h_fmt(h, "<label>%s<input name=\"%s\" spellcheck=\"false\" "
	    "autocomplete=\"off\" placeholder=\"%s\"", label, name, hint);
	h_attr(h, "value", value != NULL ? value : "");
	h_raw(h, "></label>");
}

/* An address as ifconfig printed it, "[a]:port" or "a:port": the address. */
static const char *
bare(const char *s)
{
	static char	 buf[80];
	char		*p;

	if (s == NULL)
		return ("");
	snprintf(buf, sizeof(buf), "%s", s[0] == '[' ? s + 1 : s);
	if (s[0] == '[')
		buf[strcspn(buf, "]")] = '\0';
	else if ((p = strrchr(buf, ':')) != NULL)
		*p = '\0';
	return (buf);
}

static void
geneve_form(struct html *h, const ucl_object_t *g)
{
	char	num[24];
	bool	new = g == NULL;

	h_raw(h, "<form data-form=\"gn-set\" class=\"gn-set\">");
	if (new)
		h_raw(h, "<label>Name<input name=\"name\" spellcheck=\"false\" "
		    "placeholder=\"geneve0\"></label><label>Mode<select name="
		    "\"mode\"><option value=\"l2\">l2: Ethernet frames, to "
		    "put in a bridge</option><option value=\"l3\">l3: IP "
		    "packets, routed</option></select></label>");
	num[0] = '\0';
	if (g != NULL && jget(g, "id") != NULL)
		snprintf(num, sizeof(num), "%lld", (long long)jint(g, "id", 0));
	opt(h, "Identifier (VNI)", "id", num, "0 to 16777215");
	opt(h, "Local address", "local", g != NULL ? bare(jstr(g, "local")) :
	    "", "this host's, on the network under it");
	opt(h, "Remote host", "remote", g != NULL ? bare(jstr(g, "remote")) :
	    "", "one host: or a group below");
	opt(h, "Multicast group", "group", g != NULL ? bare(jstr(g, "group")) :
	    "", "239.0.0.1, ff08::db8:1");
	opt(h, "Device for the group", "dev", g != NULL ? jstr(g, "dev") : "",
	    "em0");
	opt(h, "TTL", "ttl", g != NULL ? jstr(g, "ttl") : "", "0 to 255, or "
	    "inherit");
	h_fmt(h, "<label>Don't fragment<select name=\"df\"><option value=\"\">"
	    "as it is</option><option value=\"set\"%s>set</option><option "
	    "value=\"unset\"%s>unset</option><option value=\"inherit\"%s>"
	    "inherit from the packet inside</option></select></label>",
	    g != NULL && jstr(g, "df") != NULL && strcmp(jstr(g, "df"),
	    "set") == 0 ? " selected" : "", g != NULL && jstr(g, "df") !=
	    NULL && strcmp(jstr(g, "df"), "unset") == 0 ? " selected" : "",
	    g != NULL && jstr(g, "df") != NULL && strcmp(jstr(g, "df"),
	    "inherit") == 0 ? " selected" : "");
	opt(h, "Port range", "portrange", g != NULL ? jstr(g, "portrange") :
	    "", "49152-65535");
	num[0] = '\0';
	if (g != NULL && jget(g, "maxaddr") != NULL)
		snprintf(num, sizeof(num), "%lld", (long long)jint(g,
		    "maxaddr", 0));
	opt(h, "Forwarding table, at most", "maxaddr", num, "entries");
	num[0] = '\0';
	if (g != NULL && jget(g, "timeout") != NULL)
		snprintf(num, sizeof(num), "%lld", (long long)jint(g,
		    "timeout", 0));
	opt(h, "An entry is forgotten after", "timeout", num, "seconds");
	h_fmt(h, "<label class=\"toggle\" title=\"Where each address inside "
	    "is, learned from what arrives\"><input type=\"checkbox\" name=\""
	    "learn\"%s><span>learn</span></label><label class=\"toggle\" "
	    "title=\"The traffic class copied from the packet inside\"><input "
	    "type=\"checkbox\" name=\"dscpinherit\"%s><span>inherit DSCP"
	    "</span></label><label class=\"toggle\" title=\"Its forwarding "
	    "is set from outside, not learned\"><input type=\"checkbox\" name="
	    "\"external\"%s><span>externally controlled</span></label>"
	    "<label class=\"toggle\"><input type=\"checkbox\" name=\""
	    "persist\"><span>keep in rc.conf</span></label><div class=\""
	    "actions\"><button class=\"small\">%s</button><button type=\""
	    "button\" class=\"ghost small\" data-act=\"gn-pick\" data-arg=\"\">"
	    "Cancel</button></div></form>", g == NULL || jbool(g, "learn") ?
	    " checked" : "", g != NULL && jbool(g, "dscpinherit") ?
	    " checked" : "", g != NULL && jbool(g, "external") ? " checked" :
	    "", new ? "Create" : "Set");
}

void
view_geneve(struct html *h, struct server *s, const ucl_object_t *geneves)
{
	static const struct tcol	cols[] = {
		{ "Tunnel", "name", false }, { "Mode", "mode", false },
		{ "VNI", "id", true }, { "Local", "local", false },
		{ "To", "remote", false }, { "TTL", "ttl", false },
		{ "DF", "df", false },
	};
	const ucl_object_t		**rows, *g;
	const char			 *name;
	int				  r;

	(void)s;
	h_fmt(h, "<div class=\"toolbar\"><button class=\"ghost small%s\" "
	    "data-act=\"gn-pick\" data-arg=\"+\">+ geneve tunnel</button>"
	    "<span class=\"dim\">l2 carries Ethernet frames, for a bridge; l3 "
	    "carries IP packets, and is routed. A tunnel leads to one host, "
	    "or to a multicast group.</span></div>", strcmp(l2.geneve, "+") ==
	    0 ? " on" : "");
	if (strcmp(l2.geneve, "+") == 0)
		geneve_form(h, NULL);
	h_raw(h, "<table class=\"net geneve\">");
	tbl_head(h, "geneve", cols, 7, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("geneve", geneves, cols, 7, app.filter);
	for (r = 0; (g = rows[r]) != NULL; r++) {
		name = jstr(g, "name") != NULL ? jstr(g, "name") : "";
		h_fmt(h, "<tr class=\"pick%s\" data-act=\"gn-pick\"", strcmp(
		    l2.geneve, name) == 0 ? " selected" : "");
		h_attr(h, "data-arg", name);
		h_raw(h, "><td><b>");
		h_txt(h, name);
		h_fmt(h, "</b>%s</td><td><span class=\"chip\">", jbool(g,
		    "up") ? "" : " <span class=\"chip dim\">down</span>");
		h_txt(h, jstr(g, "mode"));
		h_raw(h, "</span></td><td>");
		if (jget(g, "id") != NULL)
			h_fmt(h, "%lld", (long long)jint(g, "id", 0));
		else
			h_raw(h, "<span class=\"dim\">not set</span>");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(g, "local"));
		h_raw(h, "</td><td>");
		if (jstr(g, "group") != NULL) {
			h_raw(h, "<span class=\"chip dim\">group</span> ");
			h_txt(h, jstr(g, "group"));
			if (jstr(g, "dev") != NULL) {
				h_raw(h, " on ");
				h_txt(h, jstr(g, "dev"));
			}
		} else
			h_txt(h, jstr(g, "remote"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(g, "ttl"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(g, "df"));
		h_raw(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
		    "data-act=\"gn-flush\"");
		h_attr(h, "data-arg", name);
		h_raw(h, " title=\"Forget where the addresses inside are\">"
		    "Flush</button></td></tr>");
		if (strcmp(l2.geneve, name) == 0) {
			h_raw(h, "<tr class=\"editing\"><td colspan=\"8\">");
			geneve_form(h, g);
			h_raw(h, "</td></tr>");
		}
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (ucl_array_size(geneves) == 0 && strcmp(l2.geneve, "+") != 0)
		h_raw(h, "<div class=\"empty\"><p>No geneve tunnel here.</p>"
		    "</div>");
}

bool
l2_form(const char *form, const ucl_object_t *f)
{
	static const char *const opts[] = { "id", "local", "remote", "group",
	    "dev", "ttl", "df", "portrange", "maxaddr", "timeout" };
	struct server	*s;
	struct html	 b;
	const char	*v, *mode, *name;
	char		 args[600];
	size_t		 i;
	bool		 new;

	if (strcmp(form, "br-port") != 0 && strcmp(form, "br-add") != 0 &&
	    strcmp(form, "gn-set") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(form, "br-add") == 0) {
		v = jstr(f, "member") != NULL ? jstr(f, "member") : "";
		name = jstr(f, "bridge") != NULL ? jstr(f, "bridge") : "";
		if (!word_ok(v, "._") || !word_ok(name, "._") || strlen(v) >
		    15) {
			toast(true, "Name the interface to take in");
			return (true);
		}
		snprintf(args, sizeof(args), "\"%s\"", v);
		l2_job(s, "bridge", name, "addm", args, jbool(f, "persist"));
		return (true);
	}
	if (strcmp(form, "br-port") == 0) {
		mode = jstr(f, "mode") != NULL ? jstr(f, "mode") : "";
		if (l2.member[0] == '\0')
			return (true);
		if (strcmp(mode, "trunk") == 0) {
			v = jstr(f, "tagged") != NULL ? jstr(f, "tagged") : "";
			if (!word_ok(v, ",-")) {
				toast(true, "A trunk's VLANs are numbers and "
				    "ranges with commas between, or all: "
				    "10-20,30");
				return (true);
			}
			if (jstr(f, "untagged") != NULL && jstr(f,
			    "untagged")[0] != '\0')
				snprintf(args, sizeof(args), "\"%s\",\"%s\","
				    "\"%d\"", l2.member, v, atoi(jstr(f,
				    "untagged")));
			else
				snprintf(args, sizeof(args), "\"%s\",\"%s\"",
				    l2.member, v);
			l2_job(s, "bridge", l2.bridge, "trunk", args, jbool(f,
			    "persist"));
		} else {
			if (jstr(f, "untagged") == NULL || atoi(jstr(f,
			    "untagged")) < 1 || atoi(jstr(f, "untagged")) >
			    4094) {
				toast(true, "An access port is in one VLAN, 1 "
				    "to 4094");
				return (true);
			}
			snprintf(args, sizeof(args), "\"%s\",\"%d\"", l2.member,
			    atoi(jstr(f, "untagged")));
			l2_job(s, "bridge", l2.bridge, "access", args, jbool(f,
			    "persist"));
		}
		return (true);
	}
	/* A geneve tunnel made, or one that is there set. */
	new = strcmp(l2.geneve, "+") == 0;
	name = new ? jstr(f, "name") : l2.geneve;
	if (name == NULL || strncmp(name, "geneve", 6) != 0 || !word_ok(name,
	    "") || strlen(name) > 15) {
		toast(true, "A tunnel is named geneve and a number");
		return (true);
	}
	memset(&b, 0, sizeof(b));
	if (new)
		h_fmt(&b, "\"mode\",\"%s\"", jstr(f, "mode") != NULL && strcmp(
		    jstr(f, "mode"), "l3") == 0 ? "l3" : "l2");
	for (i = 0; i < sizeof(opts) / sizeof(opts[0]); i++) {
		v = jstr(f, opts[i]);
		if (v == NULL || v[0] == '\0')
			continue;
		if (!word_ok(v, ".:-%")) {
			toast(true, "%s is not a value %s can have", v,
			    opts[i]);
			free(b.s);
			return (true);
		}
		h_fmt(&b, "%s\"%s\",\"%s\"", b.len > 0 ? "," : "", opts[i], v);
	}
	h_fmt(&b, "%s\"learn\",\"%s\",\"dscpinherit\",\"%s\",\"external\","
	    "\"%s\"", b.len > 0 ? "," : "", jbool(f, "learn") ? "on" : "off",
	    jbool(f, "dscpinherit") ? "on" : "off", jbool(f, "external") ?
	    "on" : "off");
	l2_job(s, "geneve", name, new ? "create" : "set", b.s, jbool(f,
	    "persist"));
	free(b.s);
	l2.geneve[0] = '\0';
	return (true);
}

bool
l2_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 args[80], body[300];

	if (strncmp(act, "br-", 3) != 0 && strncmp(act, "gn-", 3) != 0 &&
	    strcmp(act, "do-br-del") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "br-pick") == 0) {
		if (strcmp(l2.bridge, arg) == 0 && strcmp(l2.member, value) ==
		    0)
			l2.member[0] = '\0';
		else {
			snprintf(l2.bridge, sizeof(l2.bridge), "%s", arg);
			snprintf(l2.member, sizeof(l2.member), "%s", value);
		}
	} else if (strcmp(act, "br-filter") == 0 && word_ok(arg, "._") &&
	    (strcmp(value, "on") == 0 || strcmp(value, "off") == 0)) {
		snprintf(args, sizeof(args), "\"%s\"", value);
		l2_job(s, "bridge", arg, "vlanfilter", args, false);
	} else if (strcmp(act, "br-flag") == 0 && l2.member[0] != '\0' &&
	    word_ok(arg, "-")) {
		snprintf(args, sizeof(args), "\"%s\",\"%s\"", l2.member, arg);
		l2_job(s, "bridge", l2.bridge, "flag", args, false);
	} else if (strcmp(act, "br-del") == 0 && l2.member[0] != '\0') {
		snprintf(body, sizeof(body), "%s is taken out of %s: what is "
		    "behind it no longer reaches the others through the "
		    "bridge.", l2.member, l2.bridge);
		confirm("Take the member out", body, "Take out", true, "",
		    "do-br-del", "", "");
	} else if (strcmp(act, "do-br-del") == 0 && l2.member[0] != '\0') {
		snprintf(args, sizeof(args), "\"%s\"", l2.member);
		l2_job(s, "bridge", l2.bridge, "deletem", args, false);
		l2.member[0] = '\0';
	} else if (strcmp(act, "gn-pick") == 0) {
		if (strcmp(l2.geneve, arg) == 0)
			l2.geneve[0] = '\0';
		else
			snprintf(l2.geneve, sizeof(l2.geneve), "%s", arg);
	} else if (strcmp(act, "gn-flush") == 0 && word_ok(arg, "")) {
		l2_job(s, "geneve", arg, "flush", "\"all\"", false);
	}
	return (true);
}
