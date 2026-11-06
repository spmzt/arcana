/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's mac_do(4) rules, on its Security tab: who may become whom by
 * mdo(1).  Read from the kernel (security.mac.do.*, arcana-sysctl's read
 * action through /api's sysctl) with what sysctl.conf keeps; a change
 * of the rules or of the executables let use them is put in the host's
 * candidate as sysctl.conf's settings (arcana-sysctl's kept), committed
 * confirmed (ycommit.c): set in the kernel at once by sysctl(8), and at
 * boot by rc.d/sysctl_lastload, after kld_list loaded mac_do.  The
 * kernel parses the rules: one it refuses puts sysctl.conf back.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	MD_RULES	"security.mac.do.rules"
#define	MD_PATHS	"security.mac.do.exec_paths"
#define	MD_MAX		1024		/* MAX_RULE_STRING_SIZE */

static void	md_saved(struct ycommit *, int);

static struct {
	char		 sid[9];
	ucl_object_t	*data;		/* arcana-sysctl: value (read), kept */
	bool		 loading;
	char		 error[300];
	struct ycommit	 yc;
} md = { .yc = { .act = "md-yc", .saved = "Saved: the kernel has the "
    "rules, and sysctl.conf keeps them for the next boot.", .undone =
    "Undone: mac_do's rules are as they were.", .done = md_saved } };

/* The kernel's value of name, NULL where it has none. */
static const char *
md_value(const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it = NULL;

	while ((o = ucl_object_iterate(jget(md.data, "value"), &it, true)) !=
	    NULL)
		if (jstr(o, "name") != NULL && strcmp(jstr(o, "name"), name) ==
		    0)
			return (jstr(o, "value") != NULL ? jstr(o, "value") : "");
	return (NULL);
}

/* What sysctl.conf sets name to, NULL for nothing. */
static const char *
md_kept(const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it = NULL;

	while ((o = ucl_object_iterate(jget(md.data, "kept"), &it, true)) !=
	    NULL)
		if (jstr(o, "name") != NULL && strcmp(jstr(o, "name"), name) ==
		    0)
			return (jstr(o, "value") != NULL ? jstr(o, "value") : "");
	return (NULL);
}

/* What sysctl.conf keeps: arcana-sysctl's kept, in running. */
static void
kept_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid = arg;

	(void)err;
	if (strcmp(sid, md.sid) == 0 && status == 200 && md.data != NULL) {
		ucl_object_delete_key(md.data, "kept");
		if (jget(o, "kept") != NULL)
			ucl_object_insert_key(md.data, ucl_object_ref(jget(o,
			    "kept")), "kept", 0, false);
	}
	free(sid);
}

static void
md_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid = arg;
	char	 url[300];

	if (strcmp(sid, md.sid) != 0) {
		free(sid);
		return;
	}
	free(sid);
	md.loading = false;
	if (status != 200 || o == NULL) {
		snprintf(md.error, sizeof(md.error), "%s", err != NULL ? err :
		    "no answer");
		return;
	}
	md.error[0] = '\0';
	if (md.data != NULL)
		ucl_object_unref(md.data);
	md.data = ucl_object_copy(o);
	rc_get(rc_ds(url, sizeof(url), "running", md.sid,
	    "arcana-sysctl:sysctl"), NULL, kept_cb, strdup(md.sid));
}

static void
md_load(struct server *s)
{

	if (md.loading)
		return;
	if (strcmp(md.sid, s->id) != 0) {
		if (md.data != NULL)
			ucl_object_unref(md.data);
		md.data = NULL;
		md.error[0] = '\0';
	}
	snprintf(md.sid, sizeof(md.sid), "%s", s->id);
	md.loading = true;
	host_yread(s, "arcana-sysctl:sysctl/read", "{\"prefix\":"
	    "\"security.mac.do.\"}", "read mac_do's rules", false, md_cb,
	    strdup(s->id));
}

static void
md_saved(struct ycommit *yc, int how)
{
	struct server	*s;

	(void)how;
	if ((s = cur_server()) != NULL && strcmp(s->id, yc->sid) == 0)
		md_load(s);
}

/*
 * The rules as a list, rule i of n: {"from", "to"} each, the text
 * between ; split at its first >, blanks around it gone.
 */
static ucl_object_t *
md_rules(const char *text)
{
	ucl_object_t	*arr, *r;
	char		*copy, *p, *rule, *gt, *e;
	int		 i = 0;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (text == NULL || (copy = strdup(text)) == NULL)
		return (arr);
	for (p = copy; (rule = strsep(&p, ";")) != NULL;) {
		while (*rule == ' ' || *rule == '\t')
			rule++;
		e = rule + strlen(rule);
		while (e > rule && (e[-1] == ' ' || e[-1] == '\t'))
			*--e = '\0';
		if (*rule == '\0')
			continue;
		r = ucl_object_typed_new(UCL_OBJECT);
		if ((gt = strchr(rule, '>')) != NULL) {
			for (e = gt; e > rule && (e[-1] == ' ' || e[-1] == '\t');)
				*--e = '\0';
			*gt++ = '\0';
			while (*gt == ' ' || *gt == '\t')
				gt++;
		}
		ucl_object_insert_key(r, ucl_object_fromstring(rule), "from", 0,
		    true);
		ucl_object_insert_key(r, ucl_object_fromstring(gt != NULL ? gt :
		    ""), "to", 0, true);
		ucl_object_insert_key(r, ucl_object_fromint(i++), "i", 0, true);
		ucl_array_append(arr, r);
	}
	free(copy);
	return (arr);
}

/*
 * The candidate's sysctl.conf settings for mac_do: name set to value
 * (merged into the kept list), committed confirmed.
 */
static void
md_save(struct server *s, const char *name, const char *value)
{
	char	*qn, *qv, *body, url[200];

	qn = json_quote(name);
	qv = json_quote(value);
	if (asprintf(&body, "{\"arcana-sysctl:sysctl\":{\"kept\":[{\"name\":"
	    "%s,\"value\":%s}]}}", qn, qv) == -1)
		abort();
	free(qn);
	free(qv);
	snprintf(url, sizeof(url), "/restconf/ds/ietf-datastores:candidate/"
	    "arcana-fleet:fleet/host=%s/arcana-sysctl:sysctl", s->id);
	if (!ycommit_save(&md.yc, s->id, "PATCH", url, body))
		toast(true, "A change of mac_do's rules is on its way already");
	free(body);
}

/* The rules with rule skip left out (-1: none) and add appended. */
static char *
md_joined(const char *skip, const char *add)
{
	const ucl_object_t	*r;
	ucl_object_t		*rules;
	ucl_object_iter_t	 it = NULL;
	char			*out;
	size_t			 len = 0, cap = MD_MAX + 1;
	long			 k = skip != NULL ? strtol(skip, NULL, 10) : -1;

	if ((out = calloc(1, cap)) == NULL)
		abort();
	rules = md_rules(md_value(MD_RULES));
	while ((r = ucl_object_iterate(rules, &it, true)) != NULL) {
		if (jint(r, "i", -1) == k)
			continue;
		len += (size_t)snprintf(out + len, len < cap ? cap - len : 0,
		    "%s%s>%s", len > 0 ? ";" : "", jstr(r, "from"), jstr(r,
		    "to"));
	}
	if (add != NULL)
		len += (size_t)snprintf(out + len, len < cap ? cap - len : 0,
		    "%s%s", len > 0 ? ";" : "", add);
	ucl_object_unref(rules);
	if (len >= cap) {
		free(out);
		return (NULL);
	}
	return (out);
}

void
view_macdo(struct html *h, struct server *s)
{
	static const struct tcol	cols[] = {
		{ "Who", "from", false }, { "May become", "to", false },
	};
	const ucl_object_t		**rows, *r;
	ucl_object_t			*rules;
	const char			*rv, *pv, *kr, *en;
	int				 i;

	h_raw(h, "<h3 class=\"secsub\" id=\"macdo\">mac_do rules <small "
	    "class=\"dim\">mac_do(4), mdo(1)</small></h3><p class=\"dim\">Who "
	    "may become whom without a password: a user or a group, matched by "
	    "its number, and the users and groups it may take on. They hold "
	    "for the programs named below alone (<span class=\"mono\">"
	    "/usr/bin/mdo</span>). Set in the kernel at once, kept in "
	    "sysctl.conf for the next boot.</p>");
	if (strcmp(md.sid, s->id) != 0 || (md.data == NULL && !md.loading &&
	    md.error[0] == '\0')) {
		md_load(s);
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	if (md.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, md.error);
		h_raw(h, " <button class=\"ghost small\" data-act=\"md-retry\">"
		    "Try again</button></div>");
	}
	if (md.data == NULL) {
		if (md.error[0] == '\0')
			h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	ycommit_note(h, &md.yc);
	if ((rv = md_value(MD_RULES)) == NULL) {
		h_raw(h, "<div class=\"empty\"><p>mac_do is not in the kernel: "
		    "load it under MAC policies above, and its rules are set "
		    "here.</p></div>");
		return;
	}
	pv = md_value(MD_PATHS);
	kr = md_kept(MD_RULES);
	en = md_value("security.mac.do.enabled");
	h_raw(h, "<p>");
	if (en != NULL && strcmp(en, "0") == 0)
		h_raw(h, "<span class=\"chip warn\" title=\"security.mac.do."
		    "enabled is 0: no rule holds\">disabled</span> ");
	if (kr == NULL || strcmp(kr, rv) != 0)
		h_raw(h, "<span class=\"chip warn\" title=\"sysctl.conf does "
		    "not hold these rules: the next boot has others. Saving "
		    "here keeps them\">not kept for boot</span> ");
	h_raw(h, "</p>");
	rules = md_rules(rv);
	if (ucl_array_size(rules) == 0)
		h_raw(h, "<div class=\"empty\"><p>No rules: no one becomes "
		    "anyone by mdo(1).</p></div>");
	else {
		h_raw(h, "<table class=\"net macdo\">");
		tbl_head(h, "macdo", cols, 2, 1);
		h_raw(h, "<tbody>");
		rows = tbl_rows("macdo", rules, cols, 2, app.filter);
		for (i = 0; (r = rows[i]) != NULL; i++) {
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(r, "from"));
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(r, "to"));
			h_raw(h, "</td><td class=\"acts\"><button class=\"ghost "
			    "small\" data-act=\"md-del\"");
			h_attr(h, "data-arg", jstr(r, "i"));
			h_raw(h, ">Remove</button></td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table>");
	}
	ucl_object_unref(rules);
	h_raw(h, "<form class=\"secform\" data-form=\"md-add\"><div class=\""
	    "rowform\"><label>Who <select name=\"type\"><option value=\"uid\">"
	    "user</option><option value=\"gid\">group</option></select>"
	    "</label><label>Number <input name=\"id\" inputmode=\"numeric\" "
	    "size=\"7\" placeholder=\"1001\" autocomplete=\"off\"></label>"
	    "<label>May become <input name=\"to\" class=\"mono\" size=\"32\" "
	    "spellcheck=\"false\" autocomplete=\"off\" value=\"uid=0,gid=*,"
	    "+gid=*\" title=\"Target clauses by commas, as mac_do(4) has "
	    "them: uid=0, gid=*, +gid=. (a supplementary group), any\">"
	    "</label></div><div class=\"actions\"><button type=\"submit\" "
	    "class=\"primary\">Add rule</button></div></form>");
	h_raw(h, "<form class=\"secform\" data-form=\"md-paths\"><div class=\""
	    "rowform\"><label>Programs <input name=\"paths\" class=\"mono\" "
	    "size=\"40\" spellcheck=\"false\" autocomplete=\"off\"");
	h_attr(h, "value", pv != NULL ? pv : "");
	h_raw(h, " title=\"security.mac.do.exec_paths: absolute paths by "
	    "colons; empty, no rule holds\"></label></div><div class=\""
	    "actions\"><button type=\"submit\" class=\"ghost\">Save programs"
	    "</button></div></form>");
}

/* An id as mac_do(4) takes one: a number, maybe negative. */
static bool
md_id_ok(const char *s)
{
	char	*end;

	if (s == NULL || *s == '\0')
		return (false);
	(void)strtol(s, &end, 10);
	return (*end == '\0');
}

bool
macdo_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*v, *to, *type;
	char		*rules, add[400];

	if (strcmp(form, "md-add") != 0 && strcmp(form, "md-paths") != 0)
		return (false);
	if ((s = cur_server()) == NULL || md.data == NULL)
		return (true);
	if (strcmp(form, "md-paths") == 0) {
		v = jstr(f, "paths") != NULL ? jstr(f, "paths") : "";
		if (strlen(v) > MD_MAX || strpbrk(v, "\n\"'#") != NULL) {
			toast(true, "Absolute paths by colons, one line");
			return (true);
		}
		md_save(s, MD_PATHS, v);
		return (true);
	}
	type = jstr(f, "type") != NULL ? jstr(f, "type") : "";
	v = jstr(f, "id");
	to = jstr(f, "to") != NULL ? jstr(f, "to") : "";
	if ((strcmp(type, "uid") != 0 && strcmp(type, "gid") != 0) ||
	    !md_id_ok(v)) {
		toast(true, "A rule is of a user or a group, by its number");
		return (true);
	}
	if (to[0] == '\0' || strpbrk(to, ";>\n\"'#") != NULL) {
		toast(true, "Whom it may become: clauses by commas, as "
		    "uid=0,gid=*");
		return (true);
	}
	snprintf(add, sizeof(add), "%s=%s>%s", type, v, to);
	if ((rules = md_joined(NULL, add)) == NULL) {
		toast(true, "The rules would be longer than the kernel takes "
		    "(%d)", MD_MAX);
		return (true);
	}
	md_save(s, MD_RULES, rules);
	free(rules);
	return (true);
}

bool
macdo_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		*rules;

	(void)value;
	if (strncmp(act, "md-", 3) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (ycommit_action(&md.yc, act))
		return (true);
	if (strcmp(act, "md-retry") == 0) {
		md.error[0] = '\0';
		md_load(s);
	} else if (strcmp(act, "md-del") == 0 && md.data != NULL) {
		if ((rules = md_joined(arg, NULL)) != NULL) {
			md_save(s, MD_RULES, rules);
			free(rules);
		}
	}
	return (true);
}

void
macdo_tick(double now)
{

	ycommit_tick(&md.yc, now);
}
