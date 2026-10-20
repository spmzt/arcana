/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Security, IDS/IPS: an intrusion detection's rules of its own, as a
 * table.  They are its form's rules, a rule a line as Suricata reads
 * them; one disabled is the line commented out, kept.  A rule is added
 * or changed as its parts (action, protocol, addresses, ports,
 * direction, message, sid, rev and its other options) or the whole as
 * text; each change applies the list again, so suricata -T checks it
 * before it replaces what runs.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	OWN_MAX		512
#define	OWN_SID_FIRST	1000000	/* sids of local rules, by convention */

static struct {
	char	name[40];	/* the instance whose rules are shown */
	int	edit;		/* the rule in the form; OWN_MAX a new one,
				 * -1 none */
	bool	text;		/* the whole as text */
	bool	thr;		/* the threshold form open */
	bool	lua;		/* the Lua form open */
	char	thr_kind[16];	/* its kind, which says its fields */
} own = { .edit = -1, .thr_kind = "suppress" };

/* More lines than OWN_MAX in the rules read: a change would lose
 * those past it, so none is made until the text is cut by hand. */
static bool	own_cut;

/* The host changed: no instance of the one before is open. */
void
idsown_reset(void)
{

	own.name[0] = '\0';
	own.edit = -1;
	own.text = own.thr = own.lua = false;
}

/* A line of the rules: a rule, on or off, or a comment kept. */
struct oline {
	char	*text;		/* as written, without the "# " of one off */
	bool	 rule;
	bool	 on;
};

/* A rule's parts, as the form has them. */
struct rparts {
	char	action[16], proto[24], src[256], sport[96], dir[4];
	char	dst[256], dport[96], msg[256], opts[2048];
	long	sid, rev;
};

static const char *const actions[] = { "alert", "drop", "reject",
    "rejectsrc", "rejectdst", "rejectboth", "pass" };

static bool
is_rule(const char *s)
{
	size_t	i, n;

	for (i = 0; i < nitems(actions); i++) {
		n = strlen(actions[i]);
		if (strncmp(s, actions[i], n) == 0 && s[n] == ' ')
			return (strchr(s, '(') != NULL);
	}
	return (false);
}

/* The rules text in lines; *np their count.  Empty lines left out. */
static struct oline *
lines_of(const char *text, int *np)
{
	struct oline	*v;
	char		*copy, *it, *line, *p;
	int		 n;

	v = calloc(OWN_MAX, sizeof(*v));
	if (v == NULL || (copy = strdup(text != NULL ? text : "")) == NULL)
		abort();
	n = 0;
	own_cut = false;
	for (it = copy; (line = strsep(&it, "\n")) != NULL;) {
		if (n == OWN_MAX) {
			if (line[strspn(line, " \t\r")] != '\0')
				own_cut = true;
			continue;
		}
		p = line + strspn(line, " \t\r");
		if (*p == '\0')
			continue;
		v[n].on = *p != '#';
		if (!v[n].on) {
			p++;
			p += strspn(p, " \t");
		}
		v[n].rule = is_rule(p);
		if (!v[n].rule) {
			/* A comment: kept as it was written. */
			p = line + strspn(line, " \t\r");
			v[n].on = false;
		}
		if ((v[n].text = strdup(p)) == NULL)
			abort();
		v[n].text[strcspn(v[n].text, "\r")] = '\0';
		n++;
	}
	free(copy);
	*np = n;
	return (v);
}

static char *
text_of(const struct oline *v, int n)
{
	char	*out, *t;
	int	 i;

	if ((out = strdup("")) == NULL)
		abort();
	for (i = 0; i < n; i++) {
		if (v[i].text == NULL)
			continue;
		if (asprintf(&t, "%s%s%s\n", out, v[i].rule && !v[i].on ?
		    "# " : "", v[i].text) == -1)
			abort();
		free(out);
		out = t;
	}
	return (out);
}

static void
lines_free(struct oline *v, int n)
{
	int	i;

	for (i = 0; i < n; i++)
		free(v[i].text);
	free(v);
}

/* The header's words: brackets ([a, b]) keep their spaces. */
static int
header_words(const char *s, char w[7][256])
{
	int	n, depth;
	size_t	k;

	n = 0;
	while (*s != '\0' && *s != '(' && n < 7) {
		s += strspn(s, " \t");
		if (*s == '\0' || *s == '(')
			break;
		k = 0;
		depth = 0;
		while (*s != '\0' && (depth > 0 || (*s != ' ' && *s != '\t' &&
		    *s != '('))) {
			if (*s == '[')
				depth++;
			else if (*s == ']')
				depth--;
			if (k < 255)
				w[n][k++] = *s;
			s++;
		}
		w[n][k] = '\0';
		n++;
	}
	return (n);
}

/* A rule into its parts; false when it is not one the form can take. */
static bool
parts_of(const char *rule, struct rparts *r)
{
	char		 w[7][256], opt[1024], *val;
	const char	*p, *end;
	size_t		 k, len;
	bool		 quoted;

	memset(r, 0, sizeof(*r));
	if (header_words(rule, w) != 7 || (p = strchr(rule, '(')) == NULL ||
	    (end = strrchr(rule, ')')) == NULL || end < p)
		return (false);
	snprintf(r->action, sizeof(r->action), "%s", w[0]);
	snprintf(r->proto, sizeof(r->proto), "%s", w[1]);
	snprintf(r->src, sizeof(r->src), "%s", w[2]);
	snprintf(r->sport, sizeof(r->sport), "%s", w[3]);
	snprintf(r->dir, sizeof(r->dir), "%s", w[4]);
	snprintf(r->dst, sizeof(r->dst), "%s", w[5]);
	snprintf(r->dport, sizeof(r->dport), "%s", w[6]);
	/* Its options, each up to a ; that is not escaped nor quoted. */
	for (p++; p < end;) {
		p += strspn(p, " \t");
		k = 0;
		quoted = false;
		while (p < end && (quoted || *p != ';')) {
			if (*p == '\\' && p + 1 < end) {
				if (k < sizeof(opt) - 2) {
					opt[k++] = p[0];
					opt[k++] = p[1];
				}
				p += 2;
				continue;
			}
			if (*p == '"')
				quoted = !quoted;
			if (k < sizeof(opt) - 1)
				opt[k++] = *p;
			p++;
		}
		opt[k] = '\0';
		if (p < end)
			p++;
		if (k == 0)
			continue;
		val = strchr(opt, ':');
		if (val != NULL && strncmp(opt, "msg:", 4) == 0) {
			val++;
			val += strspn(val, " ");
			len = strlen(val);
			if (len >= 2 && val[0] == '"' && val[len - 1] == '"') {
				val[len - 1] = '\0';
				val++;
			}
			/* As it reads: \" a ", \; a ;, \\ a \. */
			for (k = 0; *val != '\0' && k < sizeof(r->msg) - 1;
			    val++) {
				if (*val == '\\' && val[1] != '\0')
					val++;
				r->msg[k++] = *val;
			}
			r->msg[k] = '\0';
		} else if (val != NULL && strncmp(opt, "sid:", 4) == 0)
			r->sid = strtol(val + 1, NULL, 10);
		else if (val != NULL && strncmp(opt, "rev:", 4) == 0)
			r->rev = strtol(val + 1, NULL, 10);
		else {
			len = strlen(r->opts);
			snprintf(r->opts + len, sizeof(r->opts) - len, "%s%s;",
			    len > 0 ? " " : "", opt);
		}
	}
	return (true);
}

/* The parts back into a rule; the message escaped as Suricata reads. */
static char *
rule_of(const struct rparts *r)
{
	char	 msg[600], opts[2100], *t;
	size_t	 k, n;
	int	 i;

	for (i = 0, k = 0; r->msg[i] != '\0' && k < sizeof(msg) - 3; i++) {
		if (r->msg[i] == '"' || r->msg[i] == ';' || r->msg[i] == '\\')
			msg[k++] = '\\';
		msg[k++] = r->msg[i];
	}
	msg[k] = '\0';
	snprintf(opts, sizeof(opts), "%s", r->opts);
	n = strlen(opts);
	while (n > 0 && (opts[n - 1] == ' ' || opts[n - 1] == '\n'))
		opts[--n] = '\0';
	if (asprintf(&t, "%s %s %s %s %s %s %s (msg:\"%s\"; %s%ssid:%ld; "
	    "rev:%ld;)", r->action, r->proto, r->src, r->sport, r->dir, r->dst,
	    r->dport, msg, opts, n > 0 ? (opts[n - 1] == ';' ? " " : "; ") :
	    "", r->sid, r->rev > 0 ? r->rev : 1) == -1)
		abort();
	return (t);
}

static long
sid_next(const struct oline *v, int n)
{
	struct rparts	r;
	long		max;
	int		i;

	max = OWN_SID_FIRST - 1;
	for (i = 0; i < n; i++)
		if (v[i].rule && parts_of(v[i].text, &r) && r.sid > max)
			max = r.sid;
	return (max + 1);
}

/* How many rules of its own a form has, on and off. */
int
idsown_count(const char *rules)
{
	struct oline	*v;
	int		 n, i, c;

	v = lines_of(rules, &n);
	for (i = c = 0; i < n; i++)
		if (v[i].rule)
			c++;
	lines_free(v, n);
	return (c);
}

bool
idsown_active(void)
{

	return (own.name[0] != '\0');
}

static void
field(struct html *h, const char *label, const char *name, const char *v,
    const char *ph, const char *help)
{

	h_fmt(h, "<label>%s <input name=\"%s\" spellcheck=\"false\" "
	    "autocomplete=\"off\"", label, name);
	h_attr(h, "value", v);
	h_attr(h, "placeholder", ph);
	h_raw(h, ">");
	if (help != NULL)
		h_fmt(h, "<small class=\"help\">%s</small>", help);
	h_raw(h, "</label>");
}

static void
rule_form(struct html *h, const struct rparts *r, bool raw, const char *text)
{
	static const char *const dirs[] = { "->", "<>", "=>" };
	size_t	i;

	h_raw(h, "<form class=\"secform\" data-form=\"own-rule\"><h4>");
	h_raw(h, own.edit == OWN_MAX ? "A rule of its own" : "Change the rule");
	h_raw(h, "</h4>");
	if (raw) {
		/* One the form cannot take apart: as text. */
		h_raw(h, "<label>The rule <textarea name=\"raw\" rows=\"3\" "
		    "spellcheck=\"false\">");
		h_txt(h, text);
		h_raw(h, "</textarea></label>");
	} else {
		h_raw(h, "<div class=\"rowform\"><label>Action <select name=\""
		    "action\">");
		for (i = 0; i < nitems(actions); i++) {
			h_fmt(h, "<option%s>%s</option>", strcmp(r->action,
			    actions[i]) == 0 ? " selected" : "", actions[i]);
		}
		h_raw(h, "</select></label>");
		field(h, "Protocol", "proto", r->proto, "tcp", NULL);
		h_raw(h, "</div><div class=\"rowform\">");
		field(h, "From", "src", r->src, "$EXTERNAL_NET", NULL);
		field(h, "Port", "sport", r->sport, "any", NULL);
		h_raw(h, "<label>Way <select name=\"dir\">");
		for (i = 0; i < nitems(dirs); i++)
			h_fmt(h, "<option%s>%s</option>", strcmp(r->dir, dirs[i]) ==
			    0 ? " selected" : "", dirs[i]);
		h_raw(h, "</select></label>");
		field(h, "To", "dst", r->dst, "$HOME_NET", NULL);
		field(h, "Port", "dport", r->dport, "any", NULL);
		h_raw(h, "</div>");
		field(h, "Message", "msg", r->msg, "LOCAL telnet to the LAN",
		    "what the alert says");
		h_raw(h, "<label>Options <textarea name=\"opts\" rows=\"2\" "
		    "spellcheck=\"false\" placeholder=\"flow:established,"
		    "to_server; content:&quot;USER root&quot;; "
		    "classtype:attempted-admin;\">");
		h_txt(h, r->opts);
		h_raw(h, "</textarea><small class=\"help\">the rule's other "
		    "options, each ended by ; as Suricata writes them</small>"
		    "</label><div class=\"rowform\">");
		h_fmt(h, "<label>Sid <input name=\"sid\" type=\"number\" "
		    "min=\"1\" required value=\"%ld\"><small class=\"help\">"
		    "1000000 and above: local rules</small></label><label>Rev "
		    "<input name=\"rev\" type=\"number\" min=\"1\" value=\"%ld\">"
		    "</label></div>", r->sid, r->rev > 0 ? r->rev : 1);
	}
	h_raw(h, "<div class=\"actions\"><button type=\"button\" class=\"ghost\" "
	    "data-act=\"own-cancel\">Cancel</button><button type=\"submit\" "
	    "class=\"primary\"");
	if (sec_ids_busy())
		h_raw(h, " disabled");
	h_raw(h, ">Save</button></div></form>");
}

static const struct tcol cols[] = {
	{ "State", NULL, false }, { "Sid", NULL, true },
	{ "Action", NULL, false }, { "What", NULL, false },
	{ "Message", NULL, false },
};

/* An instance's thresholds and suppressions, as threshold.config's
 * lines: a table, and a form for one more. */
static void
view_thresholds(struct html *h, const char *text)
{
	static const char *const kinds[] = { "suppress", "threshold",
	    "event_filter", "rate_filter" };
	static const char *const kind_names[] = { "Suppress",
	    "Threshold", "Event filter", "Rate filter" };
	struct oline	*v;
	char		 key[24];
	int		 n, i, shown;
	size_t		 k;
	bool		 sup, rate;

	h_raw(h, "<div class=\"toolbar\"><strong>Thresholds and "
	    "suppression</strong><span class=\"grow\"></span><button "
	    "class=\"ghost\" data-act=\"thr-new\">Add</button></div><p "
	    "class=\"dim\">Its threshold.config (threshold-file): an alert "
	    "suppressed, for every address or one; one told at most so many "
	    "times in so long (threshold, event_filter); a rate_filter's "
	    "action changed past a rate, a drop for one that prevents.</p>");
	if (own.thr) {
		sup = strcmp(own.thr_kind, "suppress") == 0;
		rate = strcmp(own.thr_kind, "rate_filter") == 0;
		h_raw(h, "<form class=\"secform\" data-form=\"thr-add\"><div "
		    "class=\"rowform\"><label>Kind <select name=\"kind\" "
		    "data-input=\"thr-kind\">");
		for (k = 0; k < nitems(kinds); k++)
			h_fmt(h, "<option value=\"%s\"%s>%s</option>", kinds[k],
			    strcmp(own.thr_kind, kinds[k]) == 0 ? " selected" :
			    "", kind_names[k]);
		h_raw(h, "</select></label><label>Sid <input name=\"sid\" "
		    "type=\"number\" min=\"0\" required><small class=\"help\">"
		    "0 with gen 0: every rule</small></label><label>Gen <input "
		    "name=\"gid\" type=\"number\" min=\"0\" value=\"1\">"
		    "</label><label>Track <select name=\"track\">");
		if (sup)
			h_raw(h, "<option value=\"\">every address</option>"
			    "<option>by_src</option><option>by_dst</option>"
			    "<option>by_either</option>");
		else
			h_raw(h, "<option>by_src</option><option>by_dst</option>"
			    "<option>by_both</option><option>by_rule</option>");
		h_raw(h, "</select></label></div><div class=\"rowform\">");
		if (sup)
			h_raw(h, "<label>Address <input name=\"ip\" "
			    "spellcheck=\"false\" placeholder=\"10.0.0.5 or "
			    "10.0.0.0/24\"><small class=\"help\">of this one "
			    "alone (track by_src unless another is picked)"
			    "</small></label>");
		else {
			if (!rate)
				h_raw(h, "<label>Type <select name=\"type\">"
				    "<option>limit</option><option>threshold"
				    "</option><option>both</option></select>"
				    "</label>");
			h_raw(h, "<label>Count <input name=\"count\" type=\""
			    "number\" min=\"1\" required value=\"1\"></label>"
			    "<label>Seconds <input name=\"seconds\" type=\""
			    "number\" min=\"1\" required value=\"60\"></label>");
			if (rate)
				h_raw(h, "<label>Then <select name=\"new_action\">"
				    "<option>drop</option><option>alert</option>"
				    "<option>reject</option><option>pass</option>"
				    "</select></label><label>For seconds <input "
				    "name=\"timeout\" type=\"number\" min=\"1\" "
				    "required value=\"60\"></label>");
		}
		h_raw(h, "</div><div class=\"actions\"><button type=\"button\" "
		    "class=\"ghost\" data-act=\"thr-cancel\">Cancel</button>"
		    "<button type=\"submit\" class=\"primary\"");
		if (sec_ids_busy())
			h_raw(h, " disabled");
		h_raw(h, ">Add</button></div></form>");
	}
	v = lines_of(text, &n);
	for (i = shown = 0; i < n; i++)
		if (v[i].text[0] != '#')
			shown++;
	if (shown == 0) {
		h_raw(h, "<p class=\"dim\">None: every alert is told.</p>");
		lines_free(v, n);
		return;
	}
	h_raw(h, "<table class=\"net thresholds\"><thead><tr><th>Kind</th>"
	    "<th>What</th><th></th></tr></thead><tbody>");
	for (i = 0; i < n; i++) {
		if (v[i].text[0] == '#')
			continue;
		snprintf(key, sizeof(key), "%.*s", (int)strcspn(v[i].text,
		    " "), v[i].text);
		h_raw(h, "<tr><td>");
		h_txt(h, key);
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, v[i].text + strlen(key) + strspn(v[i].text +
		    strlen(key), " "));
		h_fmt(h, "</td><td class=\"acts\"><button class=\"ghost small "
		    "danger\" data-act=\"thr-del\" data-arg=\"%d\">Delete"
		    "</button></td></tr>", i);
	}
	h_raw(h, "</tbody></table>");
	lines_free(v, n);
}

/* Its Lua scripts: for rules (lua:NAME.lua;) and as outputs. */
static void
view_lua(struct html *h, const ucl_object_t *f)
{
	const ucl_object_t	*e, *outs;
	ucl_object_iter_t	 it;
	bool			 out;

	h_raw(h, "<div class=\"toolbar\"><strong>Lua scripts</strong><span "
	    "class=\"grow\"></span><button class=\"ghost\" data-act=\""
	    "lua-new\">Add</button></div><p class=\"dim\">A rule runs one by "
	    "its <code>lua:NAME.lua;</code> keyword; one marked an output "
	    "runs on what it asks for (Suricata's Lua output). Lua rules are "
	    "allowed where it has scripts alone (security.lua.allow-rules).</p>");
	if (own.lua) {
		h_raw(h, "<form class=\"secform\" data-form=\"lua-add\"><div "
		    "class=\"rowform\"><label>Name <input name=\"name\" "
		    "required spellcheck=\"false\" placeholder=\"http-ua.lua\" "
		    "pattern=\"[A-Za-z0-9_-]{1,32}\\.lua\"></label></div>"
		    "<label>Script <textarea name=\"text\" rows=\"8\" "
		    "spellcheck=\"false\" placeholder=\"function init (args) "
		    "...\"></textarea></label><label class=\"check\"><input "
		    "type=\"checkbox\" name=\"output\"> An output <small "
		    "class=\"help\">not a rule's: it is run on what its init "
		    "asks for</small></label><div class=\"actions\"><button "
		    "type=\"button\" class=\"ghost\" data-act=\"lua-cancel\">"
		    "Cancel</button><button type=\"submit\" class=\"primary\">"
		    "Add</button></div></form>");
	}
	if (jget(f, "lua") == NULL || ucl_object_type(jget(f, "lua")) !=
	    UCL_OBJECT) {
		h_raw(h, "<p class=\"dim\">None.</p>");
		return;
	}
	outs = jget(f, "lua_outputs");
	h_raw(h, "<table class=\"net luas\"><thead><tr><th>Script</th><th>"
	    "Size</th><th>Runs</th><th></th></tr></thead><tbody>");
	it = NULL;
	while ((e = ucl_object_iterate(jget(f, "lua"), &it, true)) != NULL) {
		const ucl_object_t	*o;
		ucl_object_iter_t	 oit;

		out = false;
		oit = NULL;
		while ((o = ucl_object_iterate(outs, &oit, true)) != NULL)
			if (strcmp(ucl_object_tostring(o), ucl_object_key(e)) ==
			    0)
				out = true;
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, ucl_object_key(e));
		h_fmt(h, "</td><td>%zu B</td><td>%s</td><td class=\"acts\">",
		    strlen(ucl_object_tostring(e)), out ? "as an output" :
		    "by rules");
		h_raw(h, "<button class=\"ghost small danger\" data-act=\""
		    "lua-del\"");
		h_attr(h, "data-arg", ucl_object_key(e));
		h_raw(h, ">Delete</button></td></tr>");
	}
	h_raw(h, "</tbody></table>");
}

void
view_idsown(struct html *h)
{
	const ucl_object_t	*f;
	struct oline		*v;
	struct rparts		 r;
	char			*sel;
	int			 n, i, shown;
	bool			 raw;

	if ((f = sec_ids_spec(own.name)) == NULL) {
		own.name[0] = '\0';
		h_raw(h, "<div class=\"empty\"><p>It is not there any more."
		    "</p></div>");
		return;
	}
	v = lines_of(jstr(f, "rules"), &n);
	h_raw(h, "<div class=\"toolbar\"><button class=\"ghost\" data-act=\""
	    "own-back\">← Instances</button><strong>");
	h_txt(h, own.name);
	h_raw(h, ": rules of its own</strong><span class=\"grow\"></span>"
	    "<button class=\"ghost\" data-act=\"own-text\">");
	h_raw(h, own.text ? "As a table" : "As text");
	h_raw(h, "</button><button class=\"primary\" data-act=\"own-new\">"
	    "Add a rule</button></div><p class=\"dim\">Its rules besides the "
	    "ruleset's, in its own rules file; one disabled stays there "
	    "commented out. Each change is checked by <code>suricata -T"
	    "</code> before it replaces what runs.</p>");
	if (own.text) {
		sel = text_of(v, n);
		h_raw(h, "<form class=\"secform\" data-form=\"own-all\"><label>"
		    "Its rules, a line each <textarea name=\"rules\" rows=\"12\" "
		    "spellcheck=\"false\">");
		h_txt(h, sel);
		free(sel);
		h_raw(h, "</textarea></label><div class=\"actions\"><button "
		    "type=\"submit\" class=\"primary\"");
		if (sec_ids_busy())
			h_raw(h, " disabled");
		h_raw(h, ">Save</button></div></form>");
		lines_free(v, n);
		return;
	}
	if (own.edit == OWN_MAX) {
		memset(&r, 0, sizeof(r));
		snprintf(r.action, sizeof(r.action), "alert");
		snprintf(r.proto, sizeof(r.proto), "tcp");
		snprintf(r.src, sizeof(r.src), "any");
		snprintf(r.sport, sizeof(r.sport), "any");
		snprintf(r.dir, sizeof(r.dir), "->");
		snprintf(r.dst, sizeof(r.dst), "$HOME_NET");
		snprintf(r.dport, sizeof(r.dport), "any");
		r.sid = sid_next(v, n);
		r.rev = 1;
		rule_form(h, &r, false, NULL);
	} else if (own.edit >= 0 && own.edit < n && v[own.edit].rule) {
		/* One the form cannot take apart is changed as text. */
		raw = !parts_of(v[own.edit].text, &r);
		rule_form(h, &r, raw, v[own.edit].text);
	}
	for (i = shown = 0; i < n; i++)
		if (v[i].rule)
			shown++;
	if (shown == 0) {
		h_raw(h, "<div class=\"empty\"><p>No rules of its own.</p><p "
		    "class=\"dim\">Add a rule: what Suricata alerts on or, where "
		    "it prevents, drops, beside the ruleset's.</p></div>");
		lines_free(v, n);
		view_thresholds(h, jstr(f, "thresholds"));
		view_lua(h, f);
		return;
	}
	h_raw(h, "<table class=\"net ownrules\">");
	tbl_head(h, "ownrules", cols, 5, 1);
	h_raw(h, "<tbody>");
	for (i = 0; i < n; i++) {
		if (!v[i].rule)
			continue;
		h_raw(h, "<tr><td>");
		h_raw(h, v[i].on ? "<span class=\"chip st-up\">on</span>" :
		    "<span class=\"chip st-down\">off</span>");
		if (parts_of(v[i].text, &r)) {
			h_fmt(h, "</td><td class=\"mono\">%ld</td><td class=\""
			    "mono\">", r.sid);
			h_txt(h, r.action);
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, r.proto);
			h_raw(h, " ");
			h_txt(h, r.src);
			h_raw(h, " ");
			h_txt(h, r.sport);
			h_raw(h, " ");
			h_txt(h, r.dir);
			h_raw(h, " ");
			h_txt(h, r.dst);
			h_raw(h, " ");
			h_txt(h, r.dport);
			h_raw(h, "</td><td>");
			h_txt(h, r.msg);
		} else {
			h_raw(h, "</td><td></td><td></td><td class=\"mono\" "
			    "colspan=\"2\">");
			h_txt(h, v[i].text);
		}
		h_fmt(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
		    "data-act=\"own-edit\" data-arg=\"%d\">Change</button>"
		    "<button class=\"ghost small\" data-act=\"own-toggle\" "
		    "data-arg=\"%d\">%s</button><button class=\"ghost small "
		    "danger\" data-act=\"own-del\" data-arg=\"%d\">Delete"
		    "</button></td></tr>", i, i, v[i].on ? "Disable" : "Enable",
		    i);
	}
	h_raw(h, "</tbody></table>");
	lines_free(v, n);
	view_thresholds(h, jstr(f, "thresholds"));
	view_lua(h, f);
}

/* A line added to an instance's thresholds, the list applied. */
static void
thr_append(const char *name, const char *line)
{
	const ucl_object_t	*spec;
	const char		*was;
	char			*t;
	size_t			 len;

	if ((spec = sec_ids_spec(name)) == NULL)
		return;
	was = jstr(spec, "thresholds") != NULL ? jstr(spec, "thresholds") : "";
	len = strlen(was);
	if (asprintf(&t, "%s%s%s\n", was, len > 0 && was[len - 1] != '\n' ?
	    "\n" : "", line) == -1)
		abort();
	sec_ids_set(name, "thresholds", t);
	free(t);
}

/* A field the line takes: digits only, or an address of the words
 * threshold.config allows. */
static const char *
thr_val(const ucl_object_t *f, const char *k, bool num)
{
	const char	*v = jstr(f, k);

	if (v == NULL || v[0] == '\0')
		return (NULL);
	if (strspn(v, num ? "0123456789" : "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/$![],_-") != strlen(v))
		return (NULL);
	return (v);
}

/* The lines, one replaced (or added at OWN_MAX, or dropped with NULL),
 * applied. */
static void
apply(struct oline *v, int n, int at, const char *text, bool on)
{
	char	*all, *dup;

	if (own_cut || (at == OWN_MAX && n >= OWN_MAX)) {
		toast(true, "More than %d lines of rules: change them as text, "
		    "or in the instance's form", OWN_MAX);
		return;
	}
	if (at == OWN_MAX && n < OWN_MAX) {
		at = n++;
		v[at].rule = true;
		v[at].text = NULL;
	}
	if (at >= 0 && at < n) {
		/* text may be the line's own: copied before it is freed. */
		dup = text != NULL ? strdup(text) : NULL;
		free(v[at].text);
		v[at].text = dup;
		v[at].on = on;
	}
	all = text_of(v, n);
	sec_ids_set(own.name, "rules", all);
	free(all);
}

bool
idsown_form(const char *form, const ucl_object_t *f)
{
	const ucl_object_t	*spec;
	struct oline		*v;
	struct rparts		 r;
	char			*t;
	int			 n;
	bool			 on;

	if (strcmp(form, "own-all") == 0) {
		sec_ids_set(own.name, "rules", jstr(f, "rules") != NULL ? jstr(f,
		    "rules") : "");
		own.text = false;
		return (true);
	}
	if (strcmp(form, "thr-add") == 0) {
		const char	*kind, *sid, *gid, *track, *ip, *type, *cnt,
				*sec, *na, *to;
		char		 line[400];

		kind = jstr(f, "kind") != NULL ? jstr(f, "kind") : "suppress";
		sid = thr_val(f, "sid", true);
		gid = thr_val(f, "gid", true);
		track = thr_val(f, "track", false);
		ip = thr_val(f, "ip", false);
		type = thr_val(f, "type", false);
		cnt = thr_val(f, "count", true);
		sec = thr_val(f, "seconds", true);
		na = thr_val(f, "new_action", false);
		to = thr_val(f, "timeout", true);
		if (sid == NULL || (strcmp(kind, "suppress") != 0 && (track ==
		    NULL || cnt == NULL || sec == NULL)) || (strcmp(kind,
		    "rate_filter") == 0 && (na == NULL || to == NULL)) ||
		    (jstr(f, "ip") != NULL && jstr(f, "ip")[0] != '\0' &&
		    ip == NULL)) {
			toast(true, "A sid, and what its kind needs: a track, a "
			    "count and seconds; an address of letters, digits "
			    "and . : / $ ! [ ] , - alone");
			return (true);
		}
		/* An address given with no track is by its source. */
		if (strcmp(kind, "suppress") == 0 && track == NULL && ip != NULL)
			track = "by_src";
		if (strcmp(kind, "suppress") == 0)
			snprintf(line, sizeof(line), "suppress gen_id %s, sig_id "
			    "%s%s%s%s%s", gid != NULL ? gid : "1", sid, track !=
			    NULL ? ", track " : "", track != NULL ? track : "",
			    track != NULL && ip != NULL ? ", ip " : "", track !=
			    NULL && ip != NULL ? ip : "");
		else if (strcmp(kind, "rate_filter") == 0)
			snprintf(line, sizeof(line), "rate_filter gen_id %s, "
			    "sig_id %s, track %s, count %s, seconds %s, "
			    "new_action %s, timeout %s", gid != NULL ? gid : "1",
			    sid, track, cnt, sec, na, to);
		else
			snprintf(line, sizeof(line), "%s gen_id %s, sig_id %s, "
			    "type %s, track %s, count %s, seconds %s",
			    strcmp(kind, "threshold") == 0 ? "threshold" :
			    "event_filter", gid != NULL ? gid : "1", sid, type !=
			    NULL ? type : "limit", track, cnt, sec);
		thr_append(own.name, line);
		own.thr = false;
		return (true);
	}
	if (strcmp(form, "lua-add") == 0) {
		const char	*nm = jstr(f, "name"), *keys[2];
		ucl_object_t	*lua, *outs, *vals[2];
		size_t		 len;

		if ((spec = sec_ids_spec(own.name)) == NULL || nm == NULL ||
		    (len = strlen(nm)) < 5 || len > 36 || strcmp(nm + len - 4,
		    ".lua") != 0 || strspn(nm, "abcdefghijklmnopqrstuvwxyz"
		    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != len - 4) {
			toast(true, "A script is NAME.lua: letters, digits, _ "
			    "and -");
			return (true);
		}
		/* The form stays, with its text, while a change is applied. */
		if (sec_ids_busy()) {
			toast(true, "The last change is being applied: again in a "
			    "moment");
			return (true);
		}
		lua = jget(spec, "lua") != NULL ? ucl_object_copy(jget(spec,
		    "lua")) : ucl_object_typed_new(UCL_OBJECT);
		ucl_object_replace_key(lua, ucl_object_fromstring(jstr(f,
		    "text") != NULL ? jstr(f, "text") : ""), nm, 0, true);
		outs = jget(spec, "lua_outputs") != NULL ? ucl_object_copy(
		    jget(spec, "lua_outputs")) : ucl_object_typed_new(UCL_ARRAY);
		if (jbool(f, "output"))
			ucl_array_append(outs, ucl_object_fromstring(nm));
		keys[0] = "lua";
		keys[1] = "lua_outputs";
		vals[0] = lua;
		vals[1] = outs;
		sec_ids_set_objs(own.name, keys, vals, 2);
		own.lua = false;
		return (true);
	}
	if (strcmp(form, "own-rule") != 0 || (spec = sec_ids_spec(own.name)) ==
	    NULL)
		return (false);
	v = lines_of(jstr(spec, "rules"), &n);
	on = own.edit >= 0 && own.edit < n ? v[own.edit].on : true;
	if (jstr(f, "raw") != NULL) {
		t = strdup(jstr(f, "raw"));
		if (t == NULL)
			abort();
		t[strcspn(t, "\r\n")] = '\0';
	} else {
		memset(&r, 0, sizeof(r));
#define	TAKE(k)	snprintf(r.k, sizeof(r.k), "%s", jstr(f, #k) != NULL &&	\
		    jstr(f, #k)[0] != '\0' ? jstr(f, #k) : "any")
		TAKE(action);
		TAKE(proto);
		TAKE(src);
		TAKE(sport);
		TAKE(dir);
		TAKE(dst);
		TAKE(dport);
#undef	TAKE
		snprintf(r.msg, sizeof(r.msg), "%s", jstr(f, "msg") != NULL ?
		    jstr(f, "msg") : "");
		snprintf(r.opts, sizeof(r.opts), "%s", jstr(f, "opts") != NULL ?
		    jstr(f, "opts") : "");
		r.sid = jstr(f, "sid") != NULL ? strtol(jstr(f, "sid"), NULL,
		    10) : 0;
		r.rev = jstr(f, "rev") != NULL ? strtol(jstr(f, "rev"), NULL,
		    10) : 1;
		if (r.sid <= 0 || strpbrk(r.opts, "()\n") != NULL ||
		    strpbrk(r.msg, "\n") != NULL) {
			toast(true, "A rule needs its sid; its options hold no "
			    "( ) nor lines");
			lines_free(v, n);
			return (true);
		}
		t = rule_of(&r);
	}
	apply(v, n, own.edit, t, on);
	free(t);
	lines_free(v, n);
	own.edit = -1;
	return (true);
}

bool
idsown_action(const char *act, const char *arg, const char *value)
{
	const ucl_object_t	*spec;
	struct oline		*v;
	int			 n, i;

	(void)value;
	if (strcmp(act, "own-open") == 0) {
		snprintf(own.name, sizeof(own.name), "%s", arg);
		own.edit = -1;
		own.text = false;
		render();
		return (true);
	}
	/* An alert suppressed from its source: arg sid|address, value the
	 * instance. */
	if (strcmp(act, "own-suppress") == 0) {
		char	line[200], ip[64];
		long	sid;

		sid = strtol(arg, NULL, 10);
		snprintf(ip, sizeof(ip), "%s", strchr(arg, '|') != NULL ?
		    strchr(arg, '|') + 1 : "");
		if (sid <= 0 || value == NULL || ip[strspn(ip,
		    "0123456789abcdefABCDEF.:")] != '\0')
			return (true);
		if (ip[0] != '\0')
			snprintf(line, sizeof(line), "suppress gen_id 1, sig_id "
			    "%ld, track by_src, ip %s", sid, ip);
		else
			snprintf(line, sizeof(line), "suppress gen_id 1, sig_id "
			    "%ld", sid);
		thr_append(value, line);
		return (true);
	}
	if (strcmp(act, "lua-new") == 0 || strcmp(act, "lua-cancel") == 0) {
		own.lua = strcmp(act, "lua-new") == 0;
		render();
		return (true);
	}
	if (strcmp(act, "lua-del") == 0) {
		char	body[200];

		snprintf(body, sizeof(body), "%s is taken out of %s's scripts "
		    "and its file deleted on the host.", arg, own.name);
		confirm("Delete the script?", body, "Delete", true, NULL,
		    "lua-del-yes", arg, "");
		return (true);
	}
	if (strcmp(act, "lua-del-yes") == 0) {
		const ucl_object_t	*sp, *o;
		ucl_object_iter_t	 oit;
		ucl_object_t		*lua, *outs, *vals[2];
		const char		*keys[2];

		if ((sp = sec_ids_spec(own.name)) == NULL)
			return (true);
		lua = jget(sp, "lua") != NULL ? ucl_object_copy(jget(sp,
		    "lua")) : ucl_object_typed_new(UCL_OBJECT);
		ucl_object_delete_key(lua, arg);
		outs = ucl_object_typed_new(UCL_ARRAY);
		oit = NULL;
		while ((o = ucl_object_iterate(jget(sp, "lua_outputs"), &oit,
		    true)) != NULL)
			if (strcmp(ucl_object_tostring(o), arg) != 0)
				ucl_array_append(outs, ucl_object_copy(o));
		keys[0] = "lua";
		keys[1] = "lua_outputs";
		vals[0] = lua;
		vals[1] = outs;
		sec_ids_set_objs(own.name, keys, vals, 2);
		return (true);
	}
	if (strcmp(act, "thr-new") == 0) {
		own.thr = true;
		render();
		return (true);
	}
	if (strcmp(act, "thr-cancel") == 0) {
		own.thr = false;
		render();
		return (true);
	}
	if (strcmp(act, "input:thr-kind") == 0) {
		if (value != NULL)
			snprintf(own.thr_kind, sizeof(own.thr_kind), "%s", value);
		render();
		return (true);
	}
	if (strcmp(act, "thr-del") == 0) {
		confirm("Delete the threshold?", "The line is taken out of the "
		    "instance's threshold.config: its alerts are told again as "
		    "they come.", "Delete", true, NULL, "thr-del-yes", arg, "");
		return (true);
	}
	if (strcmp(act, "thr-del-yes") == 0) {
		const ucl_object_t	*sp;
		struct oline		*tv;
		char			*t;
		int			 tn, ti;

		if ((sp = sec_ids_spec(own.name)) == NULL)
			return (true);
		tv = lines_of(jstr(sp, "thresholds"), &tn);
		ti = (int)strtol(arg, NULL, 10);
		if (ti >= 0 && ti < tn) {
			free(tv[ti].text);
			tv[ti].text = NULL;
		}
		/* Comments kept as written: no "# " is added. */
		for (ti = 0; ti < tn; ti++)
			tv[ti].rule = false;
		t = text_of(tv, tn);
		sec_ids_set(own.name, "thresholds", t);
		free(t);
		lines_free(tv, tn);
		return (true);
	}
	if (strncmp(act, "own-", 4) != 0)
		return (false);
	if (strcmp(act, "own-back") == 0) {
		own.name[0] = '\0';
		own.edit = -1;
	} else if (strcmp(act, "own-new") == 0) {
		own.edit = OWN_MAX;
		own.text = false;
	} else if (strcmp(act, "own-cancel") == 0)
		own.edit = -1;
	else if (strcmp(act, "own-text") == 0) {
		own.text = !own.text;
		own.edit = -1;
	} else if (strcmp(act, "own-edit") == 0)
		own.edit = (int)strtol(arg, NULL, 10);
	else if (strcmp(act, "own-del") == 0) {
		char	body[200];

		snprintf(body, sizeof(body), "The rule is taken out of %s's "
		    "rules; Disable keeps it, off.", own.name);
		confirm("Delete the rule?", body, "Delete", true, NULL,
		    "own-del-yes", arg, "");
		return (true);
	} else if (strcmp(act, "own-toggle") == 0 || strcmp(act,
	    "own-del-yes") == 0) {
		if ((spec = sec_ids_spec(own.name)) == NULL)
			return (true);
		v = lines_of(jstr(spec, "rules"), &n);
		i = (int)strtol(arg, NULL, 10);
		if (i >= 0 && i < n && v[i].rule)
			apply(v, n, i, strcmp(act, "own-toggle") == 0 ?
			    v[i].text : NULL, !v[i].on);
		lines_free(v, n);
		own.edit = -1;
	}
	render();
	return (true);
}
