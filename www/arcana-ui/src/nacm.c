/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's access rules, on its Security tab: ietf-netconf-acm's nacm
 * (RFC 8341) as its agent enforces it, whoever asks: the console's
 * users, each as themselves, and the console itself as "console".  The
 * console's own roles say what its pages offer; these, what the host
 * does.
 *
 * Edited here, a copy; saved, it goes as RESTCONF has it: the node put
 * in the host's candidate (RFC 8527), committed confirmed with a token
 * of the page's own (RFC 6241 section 8.4), then confirmed by that
 * token at once.  The confirm is asked as you are, under the new rules:
 * rules that would refuse you refuse it, and the host undoes them at
 * the timeout.  Bad rules cannot lock the console out.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "app.h"

#define	NACM_KEY	"ietf-netconf-acm:nacm"
#define	TIMEOUT		120		/* seconds a commit waits */

static struct {
	char		 sid[16];	/* the host shown */
	ucl_object_t	*read;		/* its rules as read, counters too */
	ucl_object_t	*edit;		/* the copy edited, NULL: none */
	bool		 loading;
	bool		 busy;		/* a save on its way */
	unsigned	 gen;
	char		 error[512];
	char		 note[512];	/* how the last save went */
	char		 token[40];	/* a commit waiting: its persist */
	double		 until;		/* and when the host undoes it (ms) */
} nc;

/* The host's paths: its entry below a datastore's root. */
static void
url_of(char *buf, size_t len, const char *ds, const char *tail)
{

	if (ds == NULL)
		snprintf(buf, len, "/restconf/data/arcana-fleet:fleet/host=%s%s",
		    nc.sid, tail);
	else
		snprintf(buf, len, "/restconf/ds/ietf-datastores:%s/"
		    "arcana-fleet:fleet/host=%s%s", ds, nc.sid, tail);
}

/* The error a RESTCONF reply gives, or err. */
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
read_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	unsigned	gen = (unsigned)(uintptr_t)arg;
	const ucl_object_t *n;

	if (gen != nc.gen)
		return;
	nc.loading = false;
	if (status != 200 || (n = jget(o, NACM_KEY)) == NULL) {
		snprintf(nc.error, sizeof(nc.error), "%s", rc_why(o, err));
		render();
		return;
	}
	nc.error[0] = '\0';
	if (nc.read != NULL)
		ucl_object_unref(nc.read);
	nc.read = ucl_object_copy(n);
	render();
}

static void
nacm_load(const char *sid)
{
	char	url[200];

	if (strcmp(sid, nc.sid) != 0) {
		if (nc.read != NULL)
			ucl_object_unref(nc.read);
		if (nc.edit != NULL)
			ucl_object_unref(nc.edit);
		nc.read = nc.edit = NULL;
		nc.error[0] = nc.note[0] = nc.token[0] = '\0';
		snprintf(nc.sid, sizeof(nc.sid), "%s", sid);
	}
	nc.loading = true;
	url_of(url, sizeof(url), NULL, "/" NACM_KEY);
	api("GET", url, NULL, read_cb, (void *)(uintptr_t)++nc.gen);
}

/* The rules as configuration: the read's, its counters left out. */
static ucl_object_t *
config_of(const ucl_object_t *o)
{
	ucl_object_t	*c;

	c = o != NULL ? ucl_object_copy(o) : ucl_object_typed_new(UCL_OBJECT);
	ucl_object_delete_key(c, "denied-operations");
	ucl_object_delete_key(c, "denied-data-writes");
	ucl_object_delete_key(c, "denied-notifications");
	return (c);
}

/* The copy edited, made from the read when there is none. */
static ucl_object_t *
editing(void)
{

	if (nc.edit == NULL)
		nc.edit = config_of(nc.read);
	return (nc.edit);
}

/* The member key of o as an array, made when it is not there. */
static ucl_object_t *
array_at(ucl_object_t *o, const char *key)
{
	ucl_object_t	*a;

	if ((a = (ucl_object_t *)(uintptr_t)ucl_object_lookup(o, key)) ==
	    NULL || ucl_object_type(a) != UCL_ARRAY) {
		ucl_object_delete_key(o, key);
		a = ucl_object_typed_new(UCL_ARRAY);
		ucl_object_insert_key(o, a, key, 0, true);
	}
	return (a);
}

static ucl_object_t *
groups_of(ucl_object_t *o)
{
	ucl_object_t	*g;

	if ((g = (ucl_object_t *)(uintptr_t)ucl_object_lookup(o, "groups")) ==
	    NULL) {
		g = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, g, "groups", 0, true);
	}
	return (array_at(g, "group"));
}

/* Words by commas or spaces, an array of strings. */
static ucl_object_t *
words_of(const char *s)
{
	ucl_object_t	*a = ucl_object_typed_new(UCL_ARRAY);
	char		*copy, *p, *w;

	if (s == NULL)
		return (a);
	copy = strdup(s);
	for (p = copy; (w = strsep(&p, ", \t")) != NULL;)
		if (*w != '\0')
			ucl_array_append(a, ucl_object_fromstring(w));
	free(copy);
	return (a);
}

static void
words_out(struct html *h, const ucl_object_t *a)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;
	bool			 first = true;

	while ((v = ucl_object_iterate(a, &it, true)) != NULL) {
		if (!first)
			h_raw(h, ", ");
		h_txt(h, ucl_object_tostring(v));
		first = false;
	}
}

/* The i'th of array a, or NULL. */
static ucl_object_t *
nth(const ucl_object_t *a, int64_t i)
{

	return (i < 0 || a == NULL ? NULL :
	    (ucl_object_t *)(uintptr_t)ucl_array_find_index(a, (unsigned)i));
}

/* ---- Drawing ----------------------------------------------------------- */

static void
select_pd(struct html *h, const char *name, const char *v)
{
	bool	deny = v != NULL && strcmp(v, "deny") == 0;

	h_fmt(h, "<select name=\"%s\"><option value=\"permit\"%s>permit"
	    "</option><option value=\"deny\"%s>deny</option></select>", name,
	    deny ? "" : " selected", deny ? " selected" : "");
}

static void
rule_kind(struct html *h, const ucl_object_t *r)
{

	if (jstr(r, "rpc-name") != NULL) {
		h_raw(h, "rpc ");
		h_txt(h, jstr(r, "rpc-name"));
	} else if (jstr(r, "notification-name") != NULL) {
		h_raw(h, "notification ");
		h_txt(h, jstr(r, "notification-name"));
	} else if (jstr(r, "path") != NULL) {
		h_raw(h, "path ");
		h_txt(h, jstr(r, "path"));
	} else
		h_raw(h, "<span class=\"dim\">anything</span>");
}

static void
view_rulelist(struct html *h, const ucl_object_t *rl, int64_t li)
{
	const ucl_object_t	*rules, *r;
	ucl_object_iter_t	 it = NULL;
	int64_t			 ri = 0, n;

	h_raw(h, "<div class=\"nacm-rl\"><h4>");
	h_txt(h, jstr(rl, "name") != NULL ? jstr(rl, "name") : "?");
	h_raw(h, " <small class=\"dim\">for ");
	words_out(h, jget(rl, "group"));
	h_fmt(h, "</small> <button class=\"ghost small\" data-act=\"nacm-rl-up\" "
	    "data-arg=\"%lld\" title=\"Earlier: rule-lists are read in "
	    "order, the first rule that matches decides\">&uarr;</button>"
	    "<button class=\"ghost small\" data-act=\"nacm-rl-del\" data-arg=\""
	    "%lld\">Remove</button></h4>", (long long)li, (long long)li);
	rules = jget(rl, "rule");
	n = rules != NULL ? (int64_t)ucl_array_size(rules) : 0;
	h_raw(h, "<table class=\"net\"><thead><tr><th>Rule</th><th>Module"
	    "</th><th>What</th><th>Operations</th><th>Action</th><th></th>"
	    "</tr></thead><tbody>");
	while ((r = ucl_object_iterate(rules, &it, true)) != NULL) {
		const char	*act = jstr(r, "action");

		h_raw(h, "<tr><td>");
		h_txt(h, jstr(r, "name") != NULL ? jstr(r, "name") : "");
		if (jstr(r, "comment") != NULL) {
			h_raw(h, "<br><small class=\"dim\">");
			h_txt(h, jstr(r, "comment"));
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "module-name") != NULL ? jstr(r,
		    "module-name") : "*");
		h_raw(h, "</td><td class=\"mono\">");
		rule_kind(h, r);
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "access-operations") != NULL ? jstr(r,
		    "access-operations") : "*");
		h_fmt(h, "</td><td><span class=\"chip %s\">%s</span></td>"
		    "<td class=\"acts\">", act != NULL && strcmp(act, "deny") ==
		    0 ? "st-down" : "st-up", act != NULL ? act : "?");
		if (ri > 0)
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "nacm-rule-up\" data-arg=\"%lld\" data-value=\"%lld\">"
			    "&uarr;</button>", (long long)li, (long long)ri);
		h_fmt(h, "<button class=\"ghost small\" data-act=\"nacm-rule-del\" "
		    "data-arg=\"%lld\" data-value=\"%lld\">Remove</button></td>"
		    "</tr>", (long long)li, (long long)ri);
		ri++;
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"6\" class=\"dim\">No rules: it "
		    "decides nothing.</td></tr>");
	h_fmt(h, "</tbody></table><form class=\"secform\" data-form=\""
	    "nacm-rule\"><input type=\"hidden\" name=\"list\" value=\"%lld\">"
	    "<label>Rule <input name=\"name\" required placeholder=\"name\" "
	    "size=\"10\"></label><label>Module <input name=\"module\" "
	    "value=\"*\" size=\"14\"></label><label>What <select name=\"kind\">"
	    "<option value=\"\">anything</option><option value=\"rpc-name\">"
	    "rpc</option><option value=\"path\">data path</option><option "
	    "value=\"notification-name\">notification</option></select>"
	    "</label><label>Named <input name=\"what\" size=\"14\" "
	    "placeholder=\"job-submit, /if:interfaces\"></label><label>"
	    "Operations <input name=\"ops\" value=\"*\" size=\"14\" "
	    "title=\"* or some of create read update delete exec\"></label>"
	    "<label>Action ", (long long)li);
	select_pd(h, "action", "permit");
	h_raw(h, "</label><div class=\"actions\"><button class=\"small\">Add "
	    "the rule</button></div></form>"
	    "</div>");
}

void
view_nacm(struct html *h, struct server *s)
{
	const ucl_object_t	*o, *g, *rls, *rl;
	ucl_object_iter_t	 it = NULL;
	int64_t			 i = 0;

	h_raw(h, "<h3 class=\"secsub\" id=\"nacm\">Access rules <small "
	    "class=\"dim\">NACM, RFC 8341</small></h3><p class=\"dim\">Who may "
	    "read, change and run what on this host, as its agent holds every "
	    "request to them: the console's users each as themselves, the "
	    "console itself as <span class=\"mono\">console</span>. The "
	    "console's roles say what its pages offer; these, what the host "
	    "does. Rule-lists are read in order and the first rule that "
	    "matches decides; a change of the host no rule permits is refused."
	    "</p>");
	if (strcmp(s->id, nc.sid) != 0 || (nc.read == NULL && !nc.loading &&
	    nc.error[0] == '\0')) {
		nacm_load(s->id);
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	if (nc.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, nc.error);
		h_raw(h, " <button class=\"ghost small\" data-act=\"nacm-retry\">"
		    "Try again</button></div>");
	}
	if (nc.read == NULL) {
		if (nc.error[0] == '\0')
			h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	if (nc.note[0] != '\0') {
		h_fmt(h, "<div class=\"notice%s\">", nc.token[0] != '\0' ?
		    " bad" : "");
		h_txt(h, nc.note);
		if (nc.token[0] != '\0') {
			double left = (nc.until - arc_now()) / 1000;

			h_fmt(h, " <b>%d s</b> <button class=\"ghost small\" "
			    "data-act=\"nacm-cancel\">Undo now</button>",
			    left > 0 ? (int)left : 0);
		}
		h_raw(h, "</div>");
	}
	o = nc.edit != NULL ? nc.edit : nc.read;
	h_fmt(h, "<p>Denied so far: <b>%lld</b> operations, <b>%lld</b> "
	    "writes, <b>%lld</b> notifications.</p>",
	    (long long)jint(nc.read, "denied-operations", 0),
	    (long long)jint(nc.read, "denied-data-writes", 0),
	    (long long)jint(nc.read, "denied-notifications", 0));
	h_raw(h, "<form class=\"secform\" data-form=\"nacm-defaults\"><label "
	    "class=\"check\"><input type=\"checkbox\" name=\"enable\"");
	if (jget(o, "enable-nacm") == NULL || jbool(o, "enable-nacm"))
		h_raw(h, " checked");
	h_raw(h, "> Enforced</label><label>Reads ");
	select_pd(h, "read", jstr(o, "read-default"));
	h_raw(h, "</label><label>Writes ");
	select_pd(h, "write", jstr(o, "write-default") != NULL ? jstr(o,
	    "write-default") : "deny");
	h_raw(h, "</label><label>Operations ");
	select_pd(h, "exec", jstr(o, "exec-default"));
	h_raw(h, "</label><div class=\"actions\"><button class=\"small ghost\" "
	    "title=\"What no rule decides\">Set the defaults</button></div>"
	    "</form>");
	/* Groups. */
	h_raw(h, "<h4>Groups</h4><table class=\"net\"><thead><tr><th>Group"
	    "</th><th>Users</th><th></th></tr></thead><tbody>");
	it = NULL;
	i = 0;
	while ((g = ucl_object_iterate(jget(o, "groups.group"), &it, true)) !=
	    NULL) {
		h_raw(h, "<tr><td>");
		h_txt(h, jstr(g, "name") != NULL ? jstr(g, "name") : "?");
		h_raw(h, "</td><td>");
		words_out(h, jget(g, "user-name"));
		h_fmt(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
		    "data-act=\"nacm-group-del\" data-arg=\"%lld\">Remove"
		    "</button></td></tr>", (long long)i++);
	}
	if (i == 0)
		h_raw(h, "<tr><td colspan=\"3\" class=\"dim\">No groups.</td>"
		    "</tr>");
	h_raw(h, "</tbody></table><form class=\"secform\" data-form=\""
	    "nacm-group\"><label>Group <input name=\"name\" required size=\""
	    "12\"></label><label>Users <input name=\"users\" size=\"30\" "
	    "placeholder=\"console users, by commas\"></label><div class=\""
	    "actions\"><button class=\""
	    "small\">Add or replace</button></div></form>");
	/* Rule-lists, in order. */
	h_raw(h, "<h4>Rule-lists</h4>");
	rls = jget(o, "rule-list");
	it = NULL;
	i = 0;
	while ((rl = ucl_object_iterate(rls, &it, true)) != NULL)
		view_rulelist(h, rl, i++);
	if (i == 0)
		h_raw(h, "<p class=\"dim\">No rule-lists: the defaults decide "
		    "everything.</p>");
	h_raw(h, "<form class=\"secform\" data-form=\"nacm-rl\"><label>"
	    "Rule-list <input name=\"name\" required size=\"12\"></label><label>"
	    "For groups <input name=\"groups\" size=\"20\" placeholder=\"* or "
	    "names\"></label><div class=\"actions\"><button class=\"small\">"
	    "Add</button></div></form>");
	h_raw(h, "<p><button class=\"ghost\" data-act=\"nacm-operators\" "
	    "title=\"A group operators, and a rule-list that lets it change "
	    "this host: add the console's operators of it to the group\">"
	    "Allow console operators</button></p>");
	if (nc.edit != NULL)
		h_fmt(h, "<p class=\"saveline\"><button data-act=\"nacm-save\"%s>"
		    "Save the rules</button> <button class=\"ghost\" data-act=\""
		    "nacm-discard\">Discard the changes</button> <small class=\""
		    "dim\">Committed confirmed and confirmed at once as you: "
		    "rules that would refuse you are undone by the host in %d "
		    "s.</small></p>", nc.busy ? " disabled" : "", TIMEOUT);
}

/* ---- Saving ------------------------------------------------------------ */

static void
cancel_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	nc.busy = false;
	if (status == 204 || status == 200) {
		nc.token[0] = '\0';
		snprintf(nc.note, sizeof(nc.note), "Undone: the rules are as "
		    "they were.");
	} else
		snprintf(nc.note, sizeof(nc.note), "Not undone: %s",
		    rc_why(o, err));
	nacm_load(nc.sid);
	render();
}

static void
confirm_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	nc.busy = false;
	if (status == 204 || status == 200) {
		nc.token[0] = '\0';
		snprintf(nc.note, sizeof(nc.note), "Saved: the host holds "
		    "every request to the new rules.");
		if (nc.edit != NULL)
			ucl_object_unref(nc.edit);
		nc.edit = NULL;
		toast(false, "Access rules saved");
	} else
		/* The commit waits, and is undone at its timeout. */
		snprintf(nc.note, sizeof(nc.note), "Not confirmed (%s): the "
		    "new rules would not let you confirm them, so the host "
		    "undoes them at the timeout.", rc_why(o, err));
	nacm_load(nc.sid);
	render();
}

static void
commit_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	url[200], body[160];

	(void)arg;
	if (status != 204 && status != 200) {
		nc.busy = false;
		nc.token[0] = '\0';
		snprintf(nc.note, sizeof(nc.note), "Not committed: %s",
		    rc_why(o, err));
		render();
		return;
	}
	/* Confirmed at once, as the user, under the new rules. */
	snprintf(nc.note, sizeof(nc.note), "Committed; confirming.");
	url_of(url, sizeof(url), NULL, "/ietf-netconf:commit");
	snprintf(body, sizeof(body), "{\"ietf-netconf:input\":{\"persist-id\":"
	    "\"%s\"}}", nc.token);
	api("POST", url, body, confirm_cb, NULL);
	render();
}

static void
put_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	url[200], body[200];

	(void)arg;
	if (status != 204 && status != 200) {
		nc.busy = false;
		snprintf(nc.note, sizeof(nc.note), "Not saved: %s", rc_why(o,
		    err));
		render();
		return;
	}
	/* Who has it may confirm or undo the commit: 128 bits of the
	 * browser's crypto.getRandomValues(). */
	{
		uint8_t	r[16];

		if (getentropy(r, sizeof(r)) != 0) {
			nc.busy = false;
			snprintf(nc.note, sizeof(nc.note), "Not saved: no "
			    "randomness for the commit's token");
			render();
			return;
		}
		for (size_t i = 0; i < sizeof(r); i++)
			snprintf(nc.token + 2 * i, sizeof(nc.token) - 2 * i,
			    "%02x", r[i]);
	}
	/* The host's timer runs from the commit: ours from before it,
	 * so that the countdown never ends first. */
	nc.until = arc_now() + TIMEOUT * 1000.0;
	url_of(url, sizeof(url), NULL, "/ietf-netconf:commit");
	snprintf(body, sizeof(body), "{\"ietf-netconf:input\":{\"confirmed\":"
	    "[null],\"confirm-timeout\":%d,\"persist\":\"%s\"}}", TIMEOUT,
	    nc.token);
	api("POST", url, body, commit_cb, NULL);
}

static void
save(void)
{
	ucl_object_t	*top;
	char		 url[200], *json;

	if (nc.edit == NULL || nc.busy)
		return;
	nc.busy = true;
	nc.note[0] = '\0';
	top = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(top, ucl_object_ref(nc.edit), NACM_KEY, 0,
	    false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	url_of(url, sizeof(url), "candidate", "/" NACM_KEY);
	api("PUT", url, json, put_cb, NULL);
	free(json);
}

/* ---- Actions and forms ------------------------------------------------- */

/* Element i of a moved one up, or removed. */
static void
move_up(ucl_object_t *a, int64_t i)
{
	ucl_object_t	*x, *prev;

	if (i <= 0 || (x = nth(a, i)) == NULL || (prev = nth(a, i - 1)) ==
	    NULL)
		return;
	x = ucl_array_delete(a, x);
	prev = ucl_array_delete(a, prev);
	/* Put back after what came before them, in the other order. */
	{
		ucl_object_t	*rest = ucl_object_typed_new(UCL_ARRAY), *e;
		unsigned	 k, n = ucl_array_size(a);

		for (k = 0; k < (unsigned)i - 1 && k < n; k++)
			ucl_array_append(rest, ucl_object_ref(nth(a,
			    (int64_t)k)));
		ucl_array_append(rest, x);
		ucl_array_append(rest, prev);
		for (; k < n; k++)
			ucl_array_append(rest, ucl_object_ref(nth(a,
			    (int64_t)k)));
		while (ucl_array_size(a) > 0 && (e = ucl_array_pop_first(a)) !=
		    NULL)
			ucl_object_unref(e);
		while (ucl_array_size(rest) > 0 && (e = ucl_array_pop_first(
		    rest)) != NULL)
			ucl_array_append(a, e);
		ucl_object_unref(rest);
	}
}

static void
remove_at(ucl_object_t *a, int64_t i)
{
	ucl_object_t	*x;

	if ((x = nth(a, i)) != NULL)
		ucl_object_unref(ucl_array_delete(a, x));
}

bool
nacm_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	ucl_object_t	*o, *rls;
	char		 url[200], body[160];

	if (strncmp(act, "nacm-", 5) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "nacm-retry") == 0) {
		nc.error[0] = '\0';
		nacm_load(s->id);
		return (true);
	}
	if (strcmp(act, "nacm-save") == 0) {
		save();
		return (true);
	}
	if (strcmp(act, "nacm-discard") == 0) {
		if (nc.edit != NULL)
			ucl_object_unref(nc.edit);
		nc.edit = NULL;
		return (true);
	}
	if (strcmp(act, "nacm-cancel") == 0 && nc.token[0] != '\0') {
		nc.busy = true;
		url_of(url, sizeof(url), NULL, "/ietf-netconf:cancel-commit");
		snprintf(body, sizeof(body), "{\"ietf-netconf:input\":{"
		    "\"persist-id\":\"%s\"}}", nc.token);
		api("POST", url, body, cancel_cb, NULL);
		return (true);
	}
	o = editing();
	rls = array_at(o, "rule-list");
	if (strcmp(act, "nacm-group-del") == 0)
		remove_at(groups_of(o), strtoll(arg, NULL, 10));
	else if (strcmp(act, "nacm-rl-del") == 0)
		remove_at(rls, strtoll(arg, NULL, 10));
	else if (strcmp(act, "nacm-rl-up") == 0)
		move_up(rls, strtoll(arg, NULL, 10));
	else if (strcmp(act, "nacm-rule-del") == 0)
		remove_at(array_at(nth(rls, strtoll(arg, NULL, 10)), "rule"),
		    strtoll(value, NULL, 10));
	else if (strcmp(act, "nacm-rule-up") == 0)
		move_up(array_at(nth(rls, strtoll(arg, NULL, 10)), "rule"),
		    strtoll(value, NULL, 10));
	else if (strcmp(act, "nacm-operators") == 0) {
		ucl_object_t	*g, *rl, *r, *ga;
		const ucl_object_t *x;
		ucl_object_iter_t it = NULL;
		bool		 have = false;

		while ((x = ucl_object_iterate(groups_of(o), &it, true)) !=
		    NULL)
			have = have || (jstr(x, "name") != NULL &&
			    strcmp(jstr(x, "name"), "operators") == 0);
		if (!have) {
			g = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(g, ucl_object_fromstring(
			    "operators"), "name", 0, false);
			ucl_object_insert_key(g, ucl_object_typed_new(
			    UCL_ARRAY), "user-name", 0, false);
			ucl_array_append(groups_of(o), g);
		}
		rl = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(rl, ucl_object_fromstring("operators"),
		    "name", 0, false);
		ga = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(ga, ucl_object_fromstring("operators"));
		ucl_object_insert_key(rl, ga, "group", 0, false);
		r = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(r, ucl_object_fromstring("changes"),
		    "name", 0, false);
		ucl_object_insert_key(r, ucl_object_fromstring("*"),
		    "module-name", 0, false);
		ucl_object_insert_key(r, ucl_object_fromstring("*"),
		    "access-operations", 0, false);
		ucl_object_insert_key(r, ucl_object_fromstring("permit"),
		    "action", 0, false);
		ucl_object_insert_key(r, ucl_object_fromstring("The console's "
		    "operators of this host may change it."), "comment", 0,
		    false);
		ucl_array_append(array_at(rl, "rule"), r);
		ucl_array_append(rls, rl);
		toast(false, "Group operators: add the console's operators of "
		    "this host to it, then save");
	}
	return (true);
}

bool
nacm_form(const char *form, const ucl_object_t *f)
{
	ucl_object_t	*o, *e, *a;
	const char	*name;

	if (strncmp(form, "nacm-", 5) != 0)
		return (false);
	o = editing();
	name = jstr(f, "name");
	if (strcmp(form, "nacm-defaults") == 0) {
		ucl_object_delete_key(o, "enable-nacm");
		ucl_object_insert_key(o, ucl_object_frombool(jget(f, "enable") !=
		    NULL && (jbool(f, "enable") || (jstr(f, "enable") != NULL &&
		    strcmp(jstr(f, "enable"), "on") == 0))), "enable-nacm", 0,
		    true);
		ucl_object_replace_key(o, ucl_object_fromstring(jstr(f, "read")),
		    "read-default", 0, true);
		ucl_object_replace_key(o, ucl_object_fromstring(jstr(f,
		    "write")), "write-default", 0, true);
		ucl_object_replace_key(o, ucl_object_fromstring(jstr(f, "exec")),
		    "exec-default", 0, true);
		return (true);
	}
	if (name == NULL || name[0] == '\0') {
		toast(true, "A name is needed");
		return (true);
	}
	if (strcmp(form, "nacm-group") == 0) {
		const ucl_object_t	*x;
		ucl_object_iter_t	 it = NULL;
		int64_t			 i = 0;

		a = groups_of(o);
		while ((x = ucl_object_iterate(a, &it, true)) != NULL) {
			if (jstr(x, "name") != NULL && strcmp(jstr(x, "name"),
			    name) == 0)
				break;
			i++;
		}
		if (x != NULL)
			remove_at(a, i);
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromstring(name), "name", 0,
		    true);
		ucl_object_insert_key(e, words_of(jstr(f, "users")),
		    "user-name", 0, false);
		ucl_array_append(a, e);
	} else if (strcmp(form, "nacm-rl") == 0) {
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromstring(name), "name", 0,
		    true);
		ucl_object_insert_key(e, words_of(jstr(f, "groups")), "group", 0,
		    false);
		ucl_array_append(array_at(o, "rule-list"), e);
	} else if (strcmp(form, "nacm-rule") == 0) {
		ucl_object_t	*rl;
		const char	*kind = jstr(f, "kind"), *what = jstr(f, "what");
		const char	*ops = jstr(f, "ops");

		if ((rl = nth(array_at(o, "rule-list"), jstr(f, "list") != NULL ?
		    strtoll(jstr(f, "list"), NULL, 10) : -1)) == NULL)
			return (true);
		if (kind != NULL && kind[0] != '\0' && (what == NULL ||
		    what[0] == '\0')) {
			toast(true, "Name the rpc, path or notification");
			return (true);
		}
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromstring(name), "name", 0,
		    true);
		ucl_object_insert_key(e, ucl_object_fromstring(jstr(f,
		    "module") != NULL && jstr(f, "module")[0] != '\0' ?
		    jstr(f, "module") : "*"), "module-name", 0, false);
		if (kind != NULL && kind[0] != '\0')
			ucl_object_insert_key(e, ucl_object_fromstring(what),
			    kind, 0, true);
		ucl_object_insert_key(e, ucl_object_fromstring(ops != NULL &&
		    ops[0] != '\0' ? ops : "*"), "access-operations", 0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(jstr(f,
		    "action") != NULL ? jstr(f, "action") : "permit"),
		    "action", 0, false);
		ucl_array_append(array_at(rl, "rule"), e);
	}
	return (true);
}

/* A commit waiting: its countdown drawn again each second (now in
 * milliseconds, as arc_now() has it). */
void
nacm_tick(double now)
{
	static double	last;

	if (nc.token[0] == '\0' || now - last < 1000)
		return;
	last = now;
	if (now > nc.until + 2000) {
		nc.token[0] = '\0';
		snprintf(nc.note, sizeof(nc.note), "The host undid the rules "
		    "that were not confirmed.");
		nacm_load(nc.sid);
	}
	render();
}
