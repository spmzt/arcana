/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * A host's Mail tab: OpenSMTPD (mail/opensmtpd, a plugin), as the
 * agent's smtpd read has it.  Its state and queue, with smtpctl's
 * commands; the form its smtpd.conf is rendered from, on the host, and
 * the tables (aliases, virtual users, domains, senders, credentials and
 * the relay's secrets).  Each change is a job; the tab reads the host
 * again when it ends.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	struct res	 r;		/* the smtpd read */
	bool		 conf;		/* the configuration form open */
	bool		 text;		/* smtpd.conf as text, Arcana's own */
	char		 table[72];	/* the table being edited, or "" */
	bool		 picked;	/* where, chosen by hand: jail */
	char		 jail[64];	/* "" the host */
} ml;

/* Read again at the next draw (the Refresh button). */
void
mail_refresh(void)
{

	res_drop(&ml.r);
}

/* Where OpenSMTPD is looked for: the place picked in the tab, else
 * where the host says the plugin is ("" the host itself, a jail's
 * name), else the host. */
static const char *
ml_where(struct server *s)
{
	const char	*at;

	if (ml.picked)
		return (ml.jail);
	at = plugin_anywhere(s, "smtpd");
	return (at != NULL ? at : "");
}

/*
 * The agent's samples (a minute each, a day of them, [t, queued, ok,
 * tempfail, permfail, sessions]): the queue as a line, what was
 * delivered each minute as bars under it.
 */
static void
ml_graph(struct html *h, const ucl_object_t *series)
{
	const ucl_object_t	*a, *b;
	unsigned int		 n, i;
	int64_t			 qmax, dmax, d;

	n = series != NULL ? ucl_array_size(series) : 0;
	if (n < 2) {
		h_raw(h, "<p class=\"dim\">The graphs come with the agent's "
		    "first samples, a minute apart.</p>");
		return;
	}
	qmax = dmax = 1;
	for (i = 0; i < n; i++) {
		a = ucl_array_find_index(series, i);
		if (ucl_object_toint(ucl_array_find_index(a, 1)) > qmax)
			qmax = ucl_object_toint(ucl_array_find_index(a, 1));
		if (i > 0) {
			b = ucl_array_find_index(series, i - 1);
			d = ucl_object_toint(ucl_array_find_index(a, 2)) -
			    ucl_object_toint(ucl_array_find_index(b, 2));
			if (d > dmax)
				dmax = d;
		}
	}
	h_fmt(h, "<figure class=\"mlgraph\"><svg viewBox=\"0 0 %u 60\" "
	    "preserveAspectRatio=\"none\" role=\"img\" aria-label=\"The "
	    "queue and what was delivered each minute\">", n);
	for (i = 1; i < n; i++) {
		a = ucl_array_find_index(series, i);
		b = ucl_array_find_index(series, i - 1);
		/* A counter that went back: smtpd started again. */
		if ((d = ucl_object_toint(ucl_array_find_index(a, 2)) -
		    ucl_object_toint(ucl_array_find_index(b, 2))) <= 0)
			continue;
		h_fmt(h, "<rect class=\"sent\" x=\"%u\" y=\"%.1f\" width=\"1\" "
		    "height=\"%.1f\"/>", i, 60 - (double)d / dmax * 24,
		    (double)d / dmax * 24);
	}
	h_raw(h, "<path class=\"queue\" d=\"");
	for (i = 0; i < n; i++) {
		a = ucl_array_find_index(series, i);
		h_fmt(h, "%c%u %.1f ", i == 0 ? 'M' : 'L', i, 34 - (double)
		    ucl_object_toint(ucl_array_find_index(a, 1)) / qmax * 32);
	}
	h_fmt(h, "\"/></svg><figcaption class=\"dim\">The last %u minutes: "
	    "the queue, up to %lld (the line), and what was delivered each "
	    "minute, up to %lld (the bars)</figcaption></figure>", n,
	    (long long)qmax, (long long)dmax);
}

static void
ml_load(const char *sid)
{
	struct server	*s;
	char		 url[128], q[64];

	/* Another host: its own choice. */
	if (strcmp(sid, ml.r.sid) != 0)
		ml.picked = false;
	q[0] = '\0';
	if ((s = cur_server()) != NULL && ml_where(s)[0] != '\0')
		snprintf(q, sizeof(q), "?jail=%s", ml_where(s));
	snprintf(url, sizeof(url), "/api/servers/%s/smtpd%s", sid, q);
	res_load(&ml.r, sid, url);
}

/* A job's extra: the jail it is done in, when OpenSMTPD is a jail's. */
static const char *
ml_extra(struct server *s)
{
	static char	extra[96];
	char		*q;

	if (ml_where(s)[0] == '\0')
		return (NULL);
	q = json_quote(ml_where(s));
	snprintf(extra, sizeof(extra), ",\"jail\":%s", q);
	free(q);
	return (extra);
}

static void
send(struct server *s, char *json, const char *title)
{

	job_send(s, json, title, JOB_MAIL, ml_where(s)[0] != '\0' ?
	    ml_where(s) : s->name);
}

static void
chip(struct html *h, bool on, const char *yes, const char *no)
{

	h_fmt(h, "<span class=\"chip %s\">%s</span> ", on ? "st-up" : "st-down",
	    on ? yes : no);
}

/* A field of the form, prefilled from the kept form (spec). */
static void
field(struct html *h, const char *label, const char *name, const char *value,
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
		h_raw(h, "<small class=\"help\">");
		h_txt(h, help);
		h_raw(h, "</small>");
	}
	h_raw(h, "</label>");
}

static void
check(struct html *h, const char *label, const char *name, bool on)
{

	h_raw(h, "<label class=\"check\"><input type=\"checkbox\"");
	h_attr(h, "name", name);
	h_fmt(h, "%s> ", on ? " checked" : "");
	h_txt(h, label);
	h_raw(h, "</label>");
}

/* A listener as a line of the form: on [port N] [tls [pki NAME]] [auth]
 * [hostname X] [filter A,B]. */
static void
listener_line(struct html *h, const ucl_object_t *l)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int			 i;

	h_txt(h, jstr(l, "on") != NULL ? jstr(l, "on") : "localhost");
	if (jint(l, "port", 0) > 0)
		h_fmt(h, " port %lld", (long long)jint(l, "port", 0));
	if (jstr(l, "tls") != NULL && strcmp(jstr(l, "tls"), "none") != 0 &&
	    jstr(l, "tls")[0] != '\0') {
		h_fmt(h, " %s", jstr(l, "tls"));
		if (jstr(l, "pki") != NULL) {
			h_raw(h, " pki ");
			h_txt(h, jstr(l, "pki"));
		}
	}
	if (jbool(l, "auth"))
		h_raw(h, " auth");
	if (jstr(l, "hostname") != NULL) {
		h_raw(h, " hostname ");
		h_txt(h, jstr(l, "hostname"));
	}
	it = NULL;
	i = 0;
	while ((e = ucl_object_iterate(jget(l, "filters"), &it, true)) != NULL) {
		h_raw(h, i++ == 0 ? " filter " : ",");
		h_txt(h, ucl_object_tostring(e));
	}
	h_raw(h, "\n");
}

static void
lines_of(struct html *h, const ucl_object_t *arr, const char *key)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((e = ucl_object_iterate(arr, &it, true)) != NULL) {
		if (key != NULL) {
			h_txt(h, jstr(e, key) != NULL ? jstr(e, key) : "");
			if (jstr(e, "args") != NULL && jstr(e, "args")[0] != '\0') {
				h_raw(h, " ");
				h_txt(h, jstr(e, "args"));
			}
		} else
			h_txt(h, ucl_object_type(e) == UCL_STRING ?
			    ucl_object_tostring(e) : "");
		h_raw(h, "\n");
	}
}

/* The configuration form: what smtpd.conf is rendered from. */
static void
conf_form(struct html *h, const ucl_object_t *o)
{
	static const char *const kinds[] = { "maildir", "mbox", "lmtp" };
	static const char *const protos[] = { "smtp+tls", "smtps", "smtp",
	    "smtp+notls", "lmtp" };
	const ucl_object_t	*sp, *del, *rel, *pol, *l;
	ucl_object_iter_t	 it;
	size_t			 i;
	char			 num[24];

	sp = jget(o, "spec");
	del = jget(sp, "delivery");
	rel = jget(sp, "relay");
	pol = jget(sp, "policy");
	h_raw(h, "<form class=\"stack mailconf\" data-form=\"ml-conf\">"
	    "<h4>Listeners</h4><textarea name=\"listeners\" rows=\"3\" "
	    "spellcheck=\"false\" placeholder=\"localhost\n"
	    "em0 port 587 tls pki arcana auth hostname mail.example.org\">");
	it = NULL;
	while ((l = ucl_object_iterate(jget(sp, "listeners"), &it, true)) !=
	    NULL)
		listener_line(h, l);
	if (sp == NULL)
		h_raw(h, "localhost\n");
	h_raw(h, "</textarea><small class=\"help\">One a line: where it "
	    "listens (an interface, localhost, all, an address), then port N, "
	    "tls, tls-require or smtps with pki arcana (this host's "
	    "certificate, Arcana's CA's) or a pki of the own lines, auth "
	    "(the credentials table), hostname NAME, filter A,B.</small>");
	h_raw(h, "<h4>Local mail</h4><label>Domains<textarea name=\"domains\" "
	    "rows=\"2\" spellcheck=\"false\" placeholder=\"example.org\">");
	lines_of(h, jget(sp, "domains"), NULL);
	h_raw(h, "</textarea><small class=\"help\">Delivered here, one a line; "
	    "none for the host's own name alone.</small></label>"
	    "<div class=\"rowform\"><label>Delivered to<select name=\"kind\">");
	for (i = 0; i < nitems(kinds); i++)
		h_fmt(h, "<option%s>%s</option>", del != NULL && jstr(del, "kind")
		    != NULL && strcmp(jstr(del, "kind"), kinds[i]) == 0 ?
		    " selected" : "", kinds[i]);
	h_raw(h, "</select></label>");
	field(h, "Path", "path", del != NULL ? jstr(del, "path") : NULL,
	    "~/Maildir, /var/mail/%u, or an LMTP socket", "maildir's "
	    "directory, mbox's file, or LMTP's socket or host:port; empty "
	    "for OpenSMTPD's default");
	h_raw(h, "</div>");
	check(h, "Aliases (the aliases table)", "aliases", del != NULL &&
	    jbool(del, "aliases"));
	check(h, "Virtual users (the virtuals table)", "virtual", del != NULL
	    && jbool(del, "virtual"));
	h_raw(h, "<h4>Mail out</h4><div class=\"rowform\">");
	field(h, "Smart host", "relay_host", rel != NULL ? jstr(rel, "host") :
	    NULL, "smtp.example.net", "Empty: delivered by MX, straight to "
	    "each domain's servers");
	snprintf(num, sizeof(num), "%lld", (long long)(rel != NULL ? jint(rel,
	    "port", 0) : 0));
	field(h, "Port", "relay_port", num[0] != '0' ? num : NULL, "587", NULL);
	h_raw(h, "<label>By<select name=\"relay_proto\">");
	for (i = 0; i < nitems(protos); i++)
		h_fmt(h, "<option%s>%s</option>", rel != NULL && jstr(rel,
		    "proto") != NULL && strcmp(jstr(rel, "proto"), protos[i]) ==
		    0 ? " selected" : "", protos[i]);
	h_raw(h, "</select></label></div>");
	check(h, "Signs in to it (the secrets table's relay label)",
	    "relay_auth", rel != NULL && jbool(rel, "auth"));
	field(h, "Mail from", "mail_from", rel != NULL ? jstr(rel,
	    "mail_from") : NULL, "@example.org", "The sender's domain, or "
	    "address, mail goes out as; empty for the host's own");
	h_raw(h, "<h4>Policy</h4><div class=\"rowform\">");
	field(h, "Largest message", "max_size", pol != NULL ? jstr(pol,
	    "max_size") : NULL, "35M", NULL);
	snprintf(num, sizeof(num), "%lld", (long long)(pol != NULL ? jint(pol,
	    "max_rcpt", 0) : 0));
	field(h, "Recipients a message", "max_rcpt", num[0] != '0' ? num : NULL,
	    "100", NULL);
	field(h, "Warn the sender after", "bounce_warn", pol != NULL ? jstr(pol,
	    "bounce_warn") : NULL, "4h", "When mail waits this long: 4h, or "
	    "1h,4h,1d");
	h_raw(h, "</div>");
	check(h, "Refuse senders without reverse DNS", "check_rdns", pol !=
	    NULL && jbool(pol, "check_rdns"));
	check(h, "Refuse senders whose reverse DNS does not match forward",
	    "check_fcrdns", pol != NULL && jbool(pol, "check_fcrdns"));
	check(h, "Compress the queue", "queue_compression", pol != NULL &&
	    jbool(pol, "queue_compression"));
	h_raw(h, "<h4>Filters</h4><textarea name=\"filters\" rows=\"2\" "
	    "spellcheck=\"false\" placeholder=\"rspamd\ndkimsign -d "
	    "example.org -s arcana -k /usr/local/etc/mail/dkim/example.org.key\">");
	lines_of(h, jget(sp, "filters"), "name");
	h_raw(h, "</textarea><small class=\"help\">One a line, the port's "
	    "program filter-NAME and its arguments; installed here: ");
	it = NULL;
	i = 0;
	while ((l = ucl_object_iterate(jget(o, "filters"), &it, true)) != NULL) {
		h_raw(h, i++ > 0 ? ", " : "");
		h_txt(h, ucl_object_tostring(l));
	}
	if (i == 0)
		h_raw(h, "none (pkg install opensmtpd-filter-rspamd, "
		    "opensmtpd-filter-dkimsign, opensmtpd-filter-senderscore)");
	h_raw(h, ".</small><h4>Own lines</h4><textarea name=\"own\" rows=\"3\" "
	    "class=\"mono\" spellcheck=\"false\" placeholder=\"# smtpd.conf(5) "
	    "lines the form has not\">");
	h_txt(h, sp != NULL && jstr(sp, "own") != NULL ? jstr(sp, "own") : "");
	h_raw(h, "</textarea><small class=\"help\">Appended as they are; "
	    "what the form owns (listen, table, pki, action, match, filter, "
	    "include) they may not set. The host checks the whole with "
	    "<code>smtpd -n</code> before it is put in place; smtpd starts "
	    "again where it runs.</small><div class=\"toolbar\"><button "
	    "class=\"primary\">Apply</button><button type=\"button\" "
	    "class=\"ghost\" data-act=\"ml-conf-close\">Close</button>"
	    "</div></form>");
}

/* A table's editor: its text, or for the secret ones what to write. */
static void
table_form(struct html *h, const ucl_object_t *o, const char *name)
{
	const ucl_object_t	*t;
	bool			 secret;

	secret = strcmp(name, "credentials") == 0 || strcmp(name, "secrets") ==
	    0;
	t = jget(jget(o, "tables"), name);
	h_raw(h, "<form class=\"stack\" data-form=\"ml-table\"><input "
	    "type=\"hidden\" name=\"name\"");
	h_attr(h, "value", name);
	h_raw(h, "><textarea name=\"text\" rows=\"6\" class=\"mono\" "
	    "spellcheck=\"false\"");
	h_attr(h, "placeholder", strcmp(name, "aliases") == 0 ? "root: "
	    "admin@example.org\npostmaster: root" : strcmp(name, "virtuals") ==
	    0 ? "alice@example.org alice\n@example.org catchall" : strcmp(name,
	    "domains") == 0 ? "example.org" : strcmp(name, "senders") == 0 ?
	    "alice alice@example.org" : strcmp(name, "credentials") == 0 ?
	    "alice her-password" : "relay user@example.net:password");
	h_raw(h, ">");
	if (!secret && t != NULL && ucl_object_type(t) == UCL_STRING)
		h_txt(h, ucl_object_tostring(t));
	h_raw(h, "</textarea><small class=\"help\">");
	h_txt(h, strcmp(name, "credentials") == 0 ? "A user and a password a "
	    "line: the host hashes each with OpenSMTPD's encrypt and keeps "
	    "the clear one nowhere; the table is written whole, root's alone." :
	    strcmp(name, "secrets") == 0 ? "A label, then user:password a "
	    "line (the smart host's sign-in is the relay label); kept on the "
	    "host, root's alone, never shown again." : "Written whole, as "
	    "smtpd.conf's table reads it; smtpd reads it again at once.");
	h_raw(h, "</small><div class=\"toolbar\"><button class=\"danger\">"
	    "Replace the whole table</button></div></form>");
}

/*
 * A table's entries, one a row with Remove; a form that puts entries
 * in by their key, the others kept; and, folded away, the whole table
 * written at once.
 */
static void
entries_view(struct html *h, const ucl_object_t *o, const char *name)
{
	static const struct tcol cols[] = {
		{ "Entry", "key", false }, { "What it is", "value", false },
	};
	const ucl_object_t	*t, *e, **rows, *r;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr, *x;
	char			*copy, *line, *p, *key;
	size_t			 n;
	int			 k;
	bool			 secret;

	secret = strcmp(name, "credentials") == 0 || strcmp(name, "secrets") ==
	    0;
	t = jget(jget(o, "tables"), name);
	arr = ucl_object_typed_new(UCL_ARRAY);
	if (t != NULL && ucl_object_type(t) == UCL_ARRAY) {
		it = NULL;
		while ((e = ucl_object_iterate(t, &it, true)) != NULL) {
			x = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(x, ucl_object_fromstring(
			    ucl_object_tostring(e)), "key", 0, false);
			ucl_object_insert_key(x, ucl_object_fromstring(strcmp(
			    name, "credentials") == 0 ? "a user; the password "
			    "hashed on the host, not shown" : "a sign-in; kept on "
			    "the host, not shown"), "value", 0, false);
			ucl_array_append(arr, x);
		}
	} else if (t != NULL && ucl_object_type(t) == UCL_STRING) {
		copy = strdup(ucl_object_tostring(t));
		p = copy;
		while ((line = strsep(&p, "\n")) != NULL) {
			line += strspn(line, " \t");
			if (line[0] == '\0' || line[0] == '#')
				continue;
			n = strcspn(line, " \t");
			key = strndup(line, n > 0 && line[n - 1] == ':' ? n - 1 :
			    n);
			x = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(x, ucl_object_fromstring(key), "key",
			    0, false);
			ucl_object_insert_key(x, ucl_object_fromstring(line + n +
			    strspn(line + n, " \t")), "value", 0, false);
			ucl_array_append(arr, x);
			free(key);
		}
		free(copy);
	}
	h_raw(h, "<div class=\"toolbar\"><h4>");
	h_txt(h, name);
	h_fmt(h, "</h4><span class=\"grow\"></span><button class=\"ghost "
	    "small\" data-act=\"ml-table-close\">Close</button></div>");
	if (ucl_array_size(arr) == 0)
		h_raw(h, "<p class=\"dim\">No entry yet.</p>");
	else {
		h_raw(h, "<table class=\"net mlentries\">");
		tbl_head(h, "mltable", cols, 2, 1);
		h_raw(h, "<tbody>");
		rows = tbl_rows("mltable", arr, cols, 2, "");
		for (k = 0; (r = rows[k]) != NULL; k++) {
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(r, "key"));
			h_raw(h, "</td><td class=\"mono dim\">");
			h_txt(h, jstr(r, "value"));
			h_raw(h, "</td><td class=\"acts\"><button class=\"ghost "
			    "small danger\" data-act=\"ml-unentry\"");
			h_attr(h, "data-arg", name);
			h_attr(h, "data-value", jstr(r, "key"));
			h_raw(h, ">Remove</button></td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table>");
	}
	ucl_object_unref(arr);
	/* Put in by key: a new one added, one there replaced. */
	h_raw(h, "<form class=\"stack\" data-form=\"ml-entry\"><input "
	    "type=\"hidden\" name=\"name\"");
	h_attr(h, "value", name);
	h_raw(h, "><label class=\"wide\">Add or change<textarea name=\"text\" "
	    "rows=\"3\" class=\"mono\" spellcheck=\"false\"");
	h_attr(h, "placeholder", strcmp(name, "aliases") == 0 ? "postmaster: "
	    "root" : strcmp(name, "virtuals") == 0 ? "alice@example.org alice" :
	    strcmp(name, "domains") == 0 ? "example.net" : strcmp(name,
	    "senders") == 0 ? "alice alice@example.org" : strcmp(name,
	    "credentials") == 0 ? "alice her-password" : "relay "
	    "user@example.net:password");
	h_raw(h, "></textarea><small class=\"help\">A line each, its first "
	    "word its key: a key there already is replaced (a new password, "
	    "another address), a new one added, every other entry kept.");
	if (secret)
		h_raw(h, " Kept on the host, root's alone; the passwords never "
		    "come back to the console.");
	h_raw(h, "</small></label><div class=\"toolbar\"><button class=\""
	    "primary\">Put in</button></div></form>");
	h_raw(h, "<details class=\"secform\"><summary>Replace the whole table"
	    "</summary><p class=\"dim\">What is written here becomes the "
	    "whole table: an entry not in it is gone.</p>");
	(void)secret;
}

/* Is smtpd.conf the admin's own, one Arcana's form did not write? */
static bool
conf_own(const ucl_object_t *o)
{

	return (jstr(o, "conf") != NULL && !jbool(o, "conf_arcana"));
}

/* smtpd.conf as text: checked by smtpd -n, saved with the old kept. */
static void
conftext_view(struct html *h, const ucl_object_t *o)
{

	h_raw(h, "<form class=\"stack\" data-form=\"ml-conftext\"><label class="
	    "\"wide\">");
	h_txt(h, jstr(o, "conf_path") != NULL ? jstr(o, "conf_path") :
	    "smtpd.conf");
	h_raw(h, "<textarea name=\"text\" rows=\"22\" class=\"mono\" "
	    "spellcheck=\"false\">");
	h_txt(h, jstr(o, "conf") != NULL ? jstr(o, "conf") : "");
	h_raw(h, "</textarea><small class=\"help\">smtpd.conf(5) as it is. The "
	    "host checks it with <code>smtpd -n</code> before it is put in "
	    "place, and keeps the one before as smtpd.conf.arcana-old; smtpd "
	    "has no reload, so it starts again where it runs.</small></label>"
	    "<div class=\"toolbar\"><button class=\"ghost\" name=\"how\" "
	    "value=\"check\">Check</button><button class=\"primary\" name=\""
	    "how\" value=\"save\">Save and restart smtpd</button>");
	if (!conf_own(o))
		h_raw(h, "<button type=\"button\" class=\"ghost\" data-act=\""
		    "ml-text-close\">Close</button>");
	h_raw(h, "</div></form>");
}

/* The tables smtpd.conf declares, each a row; one opened below. */
static void
ctables_view(struct html *h, const ucl_object_t *o)
{
	static const struct tcol cols[] = {
		{ "Table", "name", false }, { "Where", "path", false },
		{ "Used for", "kind", false }, { "Entries", "n", true },
	};
	const ucl_object_t	**rows, *r, *t, *open;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr, *x;
	const char		*kind;
	int			 k;

	arr = ucl_object_typed_new(UCL_ARRAY);
	open = NULL;
	it = NULL;
	while ((t = ucl_object_iterate(jget(o, "conf_tables"), &it, true)) !=
	    NULL) {
		x = ucl_object_copy(t);
		ucl_object_insert_key(x, ucl_object_fromint(jget(t, "entries") !=
		    NULL ? (int64_t)ucl_array_size(jget(t, "entries")) : -1), "n",
		    0, false);
		ucl_array_append(arr, x);
		if (jstr(t, "name") != NULL && strcmp(jstr(t, "name"), ml.table)
		    == 0)
			open = t;
	}
	h_raw(h, "<p class=\"dim\">The tables your smtpd.conf declares, at their "
	    "own paths: entries are put in and taken out there, and smtpd reads "
	    "the table again at once (smtpctl update table).</p><table class="
	    "\"net mltables\">");
	tbl_head(h, "mlctables", cols, 4, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("mlctables", arr, cols, 4, "");
	for (k = 0; (r = rows[k]) != NULL; k++) {
		kind = jstr(r, "kind") != NULL ? jstr(r, "kind") : "";
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(r, "name"));
		h_raw(h, "</td><td class=\"mono dim\">");
		h_txt(h, jstr(r, "backend"));
		h_raw(h, ":");
		h_txt(h, jstr(r, "path"));
		h_fmt(h, "</td><td class=\"dim\">%s</td><td>", strcmp(kind, "auth")
		    == 0 ? "signs users in" : strcmp(kind, "relay") == 0 ?
		    "the smart host's sign-in" : "");
		if (!jbool(r, "editable"))
			h_raw(h, "<span class=\"dim\">kept where no file is</span>");
		else if (jstr(r, "error") != NULL) {
			h_raw(h, "<span class=\"dim\">");
			h_txt(h, strcmp(jstr(r, "error"), "No such file or directory")
			    == 0 ? "not written yet" : jstr(r, "error"));
			h_raw(h, "</span>");
		} else
			h_fmt(h, "%lld", (long long)jint(r, "n", 0));
		h_raw(h, "</td><td class=\"acts\">");
		if (jbool(r, "editable")) {
			h_raw(h, "<button class=\"ghost small\" data-act=\"ml-table\"");
			h_attr(h, "data-arg", jstr(r, "name"));
			h_raw(h, ">Open</button>");
		}
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	ucl_object_unref(arr);
	if (open == NULL)
		return;
	/* The one opened: its entries, Remove each, and Add or change. */
	{
		static const struct tcol ecols[] = {
			{ "Entry", "key", false }, { "What it is", "value", false },
		};
		const ucl_object_t	**er;
		bool			 secret = jbool(open, "secret");
		bool			 pw = jstr(open, "backend") != NULL &&
		    strcmp(jstr(open, "backend"), "passwd") == 0;

		kind = jstr(open, "kind") != NULL ? jstr(open, "kind") : "";
		h_raw(h, "<div class=\"toolbar\"><h4>");
		h_txt(h, jstr(open, "name"));
		h_raw(h, " <small class=\"dim mono\">");
		h_txt(h, jstr(open, "path"));
		h_raw(h, "</small></h4><span class=\"grow\"></span><button class=\""
		    "ghost small\" data-act=\"ml-table-close\">Close</button></div>");
		if (ucl_array_size(jget(open, "entries")) == 0)
			h_raw(h, "<p class=\"dim\">No entry yet.</p>");
		else {
			h_raw(h, "<table class=\"net mlentries\">");
			tbl_head(h, "mltable", ecols, 2, 1);
			h_raw(h, "<tbody>");
			er = tbl_rows("mltable", jget(open, "entries"), ecols, 2, "");
			for (k = 0; (r = er[k]) != NULL; k++) {
				h_raw(h, "<tr><td class=\"mono\">");
				h_txt(h, jstr(r, "key"));
				h_raw(h, "</td><td class=\"mono dim\">");
				if (secret)
					h_txt(h, strcmp(kind, "relay") == 0 ? "a sign-in, "
					    "kept on the host, not shown" : "a user; the "
					    "password hashed on the host, not shown");
				else
					h_txt(h, jstr(r, "value") != NULL ? jstr(r,
					    "value") : "");
				h_raw(h, "</td><td class=\"acts\"><button class=\"ghost "
				    "small danger\" data-act=\"ml-unentry\"");
				h_attr(h, "data-arg", jstr(open, "name"));
				h_attr(h, "data-value", jstr(r, "key"));
				h_raw(h, ">Remove</button></td></tr>");
			}
			free(er);
			h_raw(h, "</tbody></table>");
		}
		h_raw(h, "<form class=\"stack\" data-form=\"ml-entry\"><input "
		    "type=\"hidden\" name=\"name\"");
		h_attr(h, "value", jstr(open, "name"));
		h_raw(h, "><label class=\"wide\">Add or change<textarea name=\""
		    "text\" rows=\"3\" class=\"mono\" spellcheck=\"false\"");
		h_attr(h, "placeholder", pw || strcmp(kind, "auth") == 0 ?
		    "alice@example.org her-password" : strcmp(kind, "relay") == 0 ?
		    "relay user@example.net:password" : "postmaster: root");
		h_raw(h, "></textarea><small class=\"help\">A line each, by its "
		    "key: one there already is replaced, a new one added, every "
		    "other entry kept.");
		if (pw)
			h_raw(h, " passwd(5) lines: a user and a password, the "
			    "password hashed with OpenSMTPD's encrypt and written "
			    "as the others are ({SCHEME} included); a user there "
			    "keeps the rest of their line. A whole passwd line is "
			    "taken as it is.");
		else if (strcmp(kind, "auth") == 0)
			h_raw(h, " A user and a password: the password hashed with "
			    "OpenSMTPD's encrypt, the clear one kept nowhere.");
		h_raw(h, "</small></label><div class=\"toolbar\"><button class=\""
		    "primary\">Put in</button></div></form>");
	}
}

void
view_mail(struct html *h, struct server *s)
{
	static const struct tcol cols[] = {
		{ "Envelope", "evpid", false }, { "Kind", "type", false },
		{ "From", "from", false }, { "To", "to", false },
		{ "State", "state", false }, { "Tries", "retries", true },
		{ "Last", "error", false },
	};
	static const char *const tables[] = { "aliases", "virtuals", "domains",
	    "senders", "credentials", "secrets" };
	static const char *const parts[] = { "mda", "mta", "smtp" };
	const ucl_object_t	**rows, *r, *st, *t, *e, *sp;
	ucl_object_iter_t	 it;
	const ucl_object_t	*o;
	size_t			 i;
	int			 k;
	bool			 running;

	/* Where: the host, or any running jail of it, picked here. */
	h_raw(h, "<div class=\"toolbar\"><label class=\"secpick\">Where "
	    "<select data-input=\"ml-where\"><option value=\"\"");
	if (ml_where(s)[0] == '\0')
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
		if (strcmp(ml_where(s), jstr(e, "name")) == 0)
			h_raw(h, " selected");
		h_raw(h, ">jail ");
		h_txt(h, jstr(e, "name"));
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label><small class=\"help\">OpenSMTPD on the "
	    "host, or in a jail, with the host's network or its own</small>"
	    "</div>");
	if (!res_shown(h, &ml.r, s->id, ml_load, "ml-retry"))
		return;
	o = ml.r.o;
	h_raw(h, "<section class=\"sysview mailview\">");
	if (!jbool(o, "installed")) {
		h_raw(h, "<div class=\"notice warn sec-missing\"><span>OpenSMTPD "
		    "is not installed ");
		if (jstr(o, "jail") != NULL) {
			h_raw(h, "in jail ");
			h_txt(h, jstr(o, "jail"));
			h_raw(h, ": a plugin, the port mail/opensmtpd, installed "
			    "there with pkg -j.");
		} else
			h_raw(h, "on this host: a plugin.");
		h_raw(h, "</span><button class=\"primary small\" "
		    "data-act=\"ml-install\">Install opensmtpd</button></div>");
		h_raw(h, "<div class=\"empty\"><p>No mail server here.</p><p "
		    "class=\"dim\">FreeBSD comes with sendmail(8) and dma(8) for "
		    "the host's own mail; OpenSMTPD, a port, serves a domain's."
		    "</p></div></section>");
		return;
	}
	running = jbool(o, "running");
	sp = jget(o, "spec");
	h_raw(h, "<div class=\"toolbar\">");
	if (jstr(o, "jail") != NULL) {
		h_raw(h, "<span class=\"chip\">in jail ");
		h_txt(h, jstr(o, "jail"));
		h_raw(h, "</span> ");
	}
	chip(h, jbool(o, "enabled"), "Enabled at boot", "Not at boot");
	chip(h, running, "Running", "Stopped");
	st = jget(o, "status");
	for (i = 0; running && i < nitems(parts); i++) {
		bool	paused = jstr(st, parts[i]) != NULL && strcmp(jstr(st,
		    parts[i]), "paused") == 0;

		h_fmt(h, "<span class=\"chip %s\">%s %s</span> <button "
		    "class=\"ghost small\" data-act=\"%s\" data-arg=\"%s\">%s"
		    "</button> ", paused ? "st-down" : "st-up", parts[i] ==
		    NULL ? "" : parts[i], paused ? "paused" : "running",
		    paused ? "ml-resume" : "ml-pause", parts[i], paused ?
		    "Resume" : "Pause");
	}
	h_fmt(h, "<span class=\"grow\"></span><button class=\"%s\" "
	    "data-act=\"ml-enable\" data-arg=\"%s\">%s</button></div>",
	    running ? "ghost" : "primary", running ? "no" : "yes", running ?
	    "Stop and disable" : "Enable and start");
	/* At a glance: the queue and the counters that say most. */
	if (running) {
		static const struct {
			const char	*key, *title;
			bool		 warn;	/* more than none: a worry */
		} show[] = {
			{ "scheduler.delivery.ok", "delivered", false },
			{ "scheduler.delivery.tempfail", "deferred", true },
			{ "scheduler.delivery.permfail", "bounced", true },
			{ "smtp.session", "SMTP sessions now", false },
			{ "mta.session", "sessions out now", false },
			{ "uptime.human", "up for", false },
		};

		h_fmt(h, "<div class=\"tiles\"><div class=\"tile%s\"><b>%lld</b>"
		    "<span>in the queue</span></div>", jint(o, "queued", 0) > 0 ?
		    " warn" : " ok", (long long)jint(o, "queued", 0));
		st = jget(o, "stats");
		for (i = 0; st != NULL && i < nitems(show); i++) {
			if ((e = jget(st, show[i].key)) == NULL)
				continue;
			h_fmt(h, "<div class=\"tile%s\"><b>", show[i].warn &&
			    ucl_object_type(e) == UCL_INT && ucl_object_toint(e) > 0
			    ? " warn" : "");
			if (ucl_object_type(e) == UCL_STRING)
				h_txt(h, ucl_object_tostring(e));
			else
				h_fmt(h, "%lld", (long long)ucl_object_toint(e));
			h_raw(h, "</b><span>");
			h_txt(h, show[i].title);
			h_raw(h, "</span></div>");
		}
		h_raw(h, "</div>");
		ml_graph(h, jget(o, "series"));
	} else
		h_raw(h, "<p class=\"dim\">Stopped: nothing is received or sent; "
		    "what waits in the queue waits.</p>");
	/* The host's certificate, when smtpd serves with it. */
	if ((e = jget(o, "pki_cert")) != NULL) {
		char	from[32], to[32];

		day_text(from, sizeof(from), jint(e, "not_before", 0));
		day_text(to, sizeof(to), jint(e, "not_after", 0));
		h_fmt(h, "<p class=\"dim\">Serves with the host's own "
		    "certificate, valid from %s to %s; smtpd is started again "
		    "when the console renews it.</p>", from, to);
	}
	/* The limit over which the queue is a fault. */
	h_fmt(h, "<form class=\"row\" data-form=\"ml-watch\"><label>A fault "
	    "when more than <input type=\"number\" name=\"max\" min=\"0\" "
	    "max=\"999999999\" value=\"%lld\" class=\"narrow\"> are queued "
	    "<small class=\"dim\">0, never</small></label><button class=\""
	    "ghost small\">Save</button></form>", (long long)jint(o,
	    "queue_max", 0));
	/* Its configuration: the form's summary, the form on Edit. */
	h_raw(h, "<h3 class=\"secsub\">Configuration</h3>");
	if (ml.conf) {
		if (conf_own(o))
			h_raw(h, "<div class=\"notice warn\">Applying this form "
			    "replaces your own smtpd.conf with what the form makes; "
			    "the one before is kept as smtpd.conf.arcana-old.</div>");
		conf_form(h, o);
	} else if (conf_own(o) || ml.text) {
		conftext_view(h, o);
		if (conf_own(o))
			h_raw(h, "<details class=\"secform\"><summary>Or set it up "
			    "with Arcana's form instead</summary><p class=\"dim\">The "
			    "form writes the whole of smtpd.conf: your own lines go, "
			    "kept as smtpd.conf.arcana-old.</p><button class=\"ghost\" "
			    "data-act=\"ml-conf\">Open the form</button></details>");
	} else if (sp == NULL)
		h_raw(h, "<div class=\"empty\"><p>No smtpd.conf yet.</p><p class=\""
		    "dim\">Write it yourself, as smtpd.conf(5) has it, or have it "
		    "made from a form: where it listens, the domains delivered "
		    "here, the smart host, its policy and filters. Either way the "
		    "host checks it with smtpd -n before it is put in place.</p>"
		    "<div class=\"toolbar\"><button class=\"primary\" data-act=\""
		    "ml-conf\">Set it up with the form</button><button class=\""
		    "ghost\" data-act=\"ml-text\">Write it as text</button></div>"
		    "</div>");
	else {
		const ucl_object_t	*l, *del, *rel;
		ucl_object_iter_t	 lit;
		int			 n;

		del = jget(sp, "delivery");
		rel = jget(sp, "relay");
		h_raw(h, "<dl class=\"kv\"><dt>Listens on</dt><dd>");
		lit = NULL;
		n = 0;
		while ((l = ucl_object_iterate(jget(sp, "listeners"), &lit,
		    true)) != NULL) {
			h_raw(h, n++ > 0 ? ", " : "");
			h_txt(h, jstr(l, "on") != NULL ? jstr(l, "on") : "?");
			if (jget(l, "port") != NULL)
				h_fmt(h, ":%lld", (long long)jint(l, "port", 0));
			if (jstr(l, "tls") != NULL)
				h_fmt(h, " (%s%s)", jstr(l, "tls"), jbool(l, "auth") ?
				    ", auth" : "");
		}
		h_raw(h, n == 0 ? "nowhere" : "");
		h_raw(h, "</dd><dt>Domains</dt><dd>");
		lit = NULL;
		n = 0;
		while ((l = ucl_object_iterate(jget(sp, "domains"), &lit, true))
		    != NULL) {
			h_raw(h, n++ > 0 ? ", " : "");
			h_txt(h, ucl_object_tostring_forced(l));
		}
		h_raw(h, n == 0 ? "the host's own name" : "");
		h_raw(h, "</dd><dt>Delivered to</dt><dd>");
		h_txt(h, del != NULL && jstr(del, "kind") != NULL ? jstr(del,
		    "kind") : "maildir");
		if (del != NULL && jstr(del, "path") != NULL) {
			h_raw(h, " ");
			h_txt(h, jstr(del, "path"));
		}
		h_raw(h, "</dd><dt>Mail out</dt><dd>");
		if (rel != NULL && jstr(rel, "host") != NULL) {
			h_raw(h, "by ");
			h_txt(h, jstr(rel, "host"));
			h_raw(h, jbool(rel, "auth") ? ", signed in" : "");
		} else
			h_raw(h, "straight to each domain's servers (MX)");
		h_raw(h, "</dd><dt>Filters</dt><dd>");
		lit = NULL;
		n = 0;
		while ((l = ucl_object_iterate(jget(sp, "filters"), &lit, true))
		    != NULL) {
			h_raw(h, n++ > 0 ? ", " : "");
			h_txt(h, jstr(l, "name") != NULL ? jstr(l, "name") : "?");
		}
		h_raw(h, n == 0 ? "none" : "");
		h_raw(h, "</dd></dl><div class=\"actions\"><button class=\"ghost\" "
		    "data-act=\"ml-conf\">Edit</button><button class=\"ghost\" "
		    "data-act=\"ml-text\">Edit as text</button></div>");
	}
	/* The queue, with smtpctl's commands. */
	h_fmt(h, "<h3 class=\"secsub\">Queue%s</h3>", running ? "" :
	    " (smtpd is not running)");
	if (running && jint(o, "queued", 0) > 0) {
		h_fmt(h, "<div class=\"toolbar\"><span>%lld envelope%s</span>"
		    "<span class=\"grow\"></span><button class=\"ghost small\" "
		    "data-act=\"ml-schedule\" data-arg=\"all\">Try all now"
		    "</button><button class=\"ghost small danger\" data-act=\""
		    "ml-remove\" data-arg=\"all\">Remove all</button></div>",
		    (long long)jint(o, "queued", 0), jint(o, "queued", 0) == 1 ?
		    "" : "s");
		h_raw(h, "<table class=\"net mailq\">");
		tbl_head(h, "mailq", cols, 7, 1);
		h_raw(h, "<tbody>");
		rows = tbl_rows("mailq", jget(o, "queue"), cols, 7, "");
		for (k = 0; (r = rows[k]) != NULL; k++) {
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(r, "evpid"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(r, "type"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(r, "from"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(r, "to"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(r, "state"));
			h_fmt(h, "</td><td>%lld</td><td class=\"dim\">",
			    (long long)jint(r, "retries", 0));
			h_txt(h, jstr(r, "error") != NULL ? jstr(r, "error") : "");
			h_raw(h, "</td><td class=\"acts\"><button class=\"ghost "
			    "small\" data-act=\"ml-schedule\"");
			h_attr(h, "data-arg", jstr(r, "evpid"));
			h_raw(h, ">Try now</button><button class=\"ghost small "
			    "danger\" data-act=\"ml-remove\"");
			h_attr(h, "data-arg", jstr(r, "evpid"));
			h_raw(h, ">Remove</button></td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table>");
	} else if (running)
		h_raw(h, "<p class=\"dim\">Empty: nothing waits.</p>");
	/* The tables smtpd.conf declares; else Arcana's own. */
	if (ucl_array_size(jget(o, "conf_tables")) > 0) {
		h_raw(h, "<h3 class=\"secsub\">Tables</h3>");
		ctables_view(h, o);
		goto conf_shown;
	}
	h_raw(h, "<h3 class=\"secsub\">Tables</h3><table class=\"params\">"
	    "<thead><tr><th>Table</th><th>Holds</th><th>Entries</th><th></th>"
	    "</tr></thead><tbody>");
	for (i = 0; i < nitems(tables); i++) {
		static const char *const holds[] = { "local aliases",
		    "virtual users and domains", "the domains delivered here",
		    "who may send as whom", "users and their passwords, hashed",
		    "the smart host's sign-in" };
		long long	n = 0;

		t = jget(jget(o, "tables"), tables[i]);
		if (t != NULL && ucl_object_type(t) == UCL_ARRAY)
			n = (long long)ucl_array_size(t);
		else if (t != NULL && ucl_object_type(t) == UCL_STRING) {
			const char	*p;

			for (p = ucl_object_tostring(t); *p != '\0';
			    p += strcspn(p, "\n"), p += *p == '\n') {
				p += strspn(p, " \t");
				if (*p != '\0' && *p != '\n' && *p != '#')
					n++;
			}
		}
		h_fmt(h, "<tr%s><td class=\"mono\">%s</td><td class=\"dim\">%s"
		    "</td><td>", strcmp(ml.table, tables[i]) == 0 ? " class=\"on\""
		    : "", tables[i], holds[i]);
		if (t == NULL)
			h_raw(h, "<span class=\"dim\">not written yet</span>");
		else
			h_fmt(h, "%lld", n);
		h_fmt(h, "</td><td class=\"acts\"><button class=\"ghost small%s\" "
		    "data-act=\"ml-table\" data-arg=\"%s\">%s</button></td></tr>",
		    strcmp(ml.table, tables[i]) == 0 ? " on" : "", tables[i],
		    strcmp(ml.table, tables[i]) == 0 ? "Open" : t == NULL ?
		    "Start it" : "Open");
	}
	h_raw(h, "</tbody></table>");
	if (ml.table[0] != '\0') {
		entries_view(h, o, ml.table);
		table_form(h, o, ml.table);
		h_raw(h, "</details>");
	}
conf_shown:
	if (conf_own(o) || ml.text)
		goto conf_text_shown;
	h_raw(h, "<details class=\"secform\"><summary>smtpd.conf as written"
	    "</summary><pre class=\"mono naspre\">");
	h_txt(h, jstr(o, "conf") != NULL ? jstr(o, "conf") : "(none yet)");
	h_raw(h, "</pre></details>");
conf_text_shown:
	h_raw(h, "<p class=\"dim\"><b>FreeBSD:</b> OpenSMTPD "
	    "is the port mail/opensmtpd; its queue is /var/spool/smtpd, its "
	    "log /var/log/maillog (the Log tab)");
	if (jstr(o, "mailer") != NULL) {
		h_raw(h, "; sendmail(8) here is <code>");
		h_txt(h, jstr(o, "mailer"));
		h_raw(h, "</code>, mailer.conf(5)'s choice, OpenSMTPD's being "
		    "<code>/usr/local/sbin/smtpctl</code>");
	}
	h_raw(h, ".</p></section>");
}

/* Words of a listener line into its object. */
static ucl_object_t *
listener_of(char *line)
{
	ucl_object_t	*l, *fl;
	char		*w, *c, *it;

	l = ucl_object_typed_new(UCL_OBJECT);
	if ((w = strsep(&line, " \t")) == NULL)
		return (l);
	ucl_object_insert_key(l, ucl_object_fromstring(w), "on", 0, false);
	while ((w = strsep(&line, " \t")) != NULL) {
		if (w[0] == '\0')
			continue;
		if (strcmp(w, "port") == 0 && (w = strsep(&line, " \t")) != NULL)
			ucl_object_insert_key(l, ucl_object_fromint(atoll(w)),
			    "port", 0, false);
		else if (strcmp(w, "tls") == 0 || strcmp(w, "tls-require") == 0
		    || strcmp(w, "smtps") == 0)
			ucl_object_insert_key(l, ucl_object_fromstring(w), "tls",
			    0, false);
		else if (strcmp(w, "pki") == 0 && (w = strsep(&line, " \t")) !=
		    NULL)
			ucl_object_insert_key(l, ucl_object_fromstring(w), "pki",
			    0, false);
		else if (strcmp(w, "auth") == 0)
			ucl_object_insert_key(l, ucl_object_frombool(true), "auth",
			    0, false);
		else if (strcmp(w, "hostname") == 0 && (w = strsep(&line, " \t"))
		    != NULL)
			ucl_object_insert_key(l, ucl_object_fromstring(w),
			    "hostname", 0, false);
		else if (strcmp(w, "filter") == 0 && (w = strsep(&line, " \t"))
		    != NULL) {
			fl = ucl_object_typed_new(UCL_ARRAY);
			for (it = w; (c = strsep(&it, ",")) != NULL;)
				if (c[0] != '\0')
					ucl_array_append(fl, ucl_object_fromstring(c));
			ucl_object_insert_key(l, fl, "filters", 0, false);
		} else {
			ucl_object_unref(l);
			return (NULL);
		}
	}
	return (l);
}

/* A textarea's lines, each a string of the array (or NULL when bad). */
static ucl_object_t *
lines_array(const char *text, bool filters)
{
	ucl_object_t	*arr, *f;
	char		*copy, *it, *line, *name;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if ((copy = strdup(text != NULL ? text : "")) == NULL)
		abort();
	for (it = copy; (line = strsep(&it, "\n")) != NULL;) {
		line[strcspn(line, "\r")] = '\0';
		line += strspn(line, " \t");
		if (line[0] == '\0' || line[0] == '#')
			continue;
		if (!filters) {
			line[strcspn(line, " \t")] = '\0';
			ucl_array_append(arr, ucl_object_fromstring(line));
			continue;
		}
		f = ucl_object_typed_new(UCL_OBJECT);
		name = strsep(&line, " \t");
		ucl_object_insert_key(f, ucl_object_fromstring(name), "name", 0,
		    false);
		if (line != NULL && line[strspn(line, " \t")] != '\0')
			ucl_object_insert_key(f, ucl_object_fromstring(line +
			    strspn(line, " \t")), "args", 0, false);
		ucl_array_append(arr, f);
	}
	free(copy);
	return (arr);
}

static struct server *
ml_server(void)
{
	struct server	*s;

	if ((s = cur_server()) == NULL)
		toast(true, "No host is chosen");
	return (s);
}

bool
mail_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	ucl_object_t	*spec, *ls, *l, *del, *rel, *pol;
	char		*copy, *it, *line, *json, *q, title[96];
	const char	*v, *w[1];

	if (strcmp(form, "ml-conftext") == 0) {
		const char	*w1[1] = { "check" };
		bool		 check;

		if ((s = ml_server()) == NULL || jstr(f, "text") == NULL)
			return (true);
		check = jstr(f, "how") != NULL && strcmp(jstr(f, "how"), "check")
		    == 0;
		send(s, job_json("smtpd", "conf-text", w1, check ? 1 : 0, jstr(f,
		    "text"), ml_extra(s)), check ? "smtpd.conf checked" :
		    "smtpd.conf written");
		if (!check)
			ml.text = false;
		return (true);
	}
	if (strcmp(form, "ml-watch") == 0) {
		if ((s = ml_server()) == NULL || (v = jstr(f, "max")) == NULL ||
		    v[0] == '\0' || v[strspn(v, "0123456789")] != '\0')
			return (true);
		w[0] = v;
		send(s, job_json("smtpd", "watch", w, 1, NULL, ml_extra(s)),
		    strcmp(v, "0") == 0 ? "The queue is no fault, however long" :
		    "The queue's limit set");
		return (true);
	}
	if (strcmp(form, "ml-entry") == 0) {
		if ((s = ml_server()) == NULL || jstr(f, "name") == NULL ||
		    jstr(f, "text") == NULL || jstr(f, "text")[strspn(jstr(f,
		    "text"), " \t\n")] == '\0')
			return (true);
		w[0] = jstr(f, "name");
		snprintf(title, sizeof(title), "smtpd table %s: entries put in",
		    w[0]);
		send(s, job_json("smtpd", "entry", w, 1, jstr(f, "text"),
		    ml_extra(s)), title);
		return (true);
	}
	if (strcmp(form, "ml-table") == 0) {
		if ((s = ml_server()) == NULL || jstr(f, "name") == NULL)
			return (true);
		w[0] = jstr(f, "name");
		snprintf(title, sizeof(title), "smtpd table %s written", w[0]);
		send(s, job_json("smtpd", "table", w, 1, jstr(f, "text") != NULL ?
		    jstr(f, "text") : "", ml_extra(s)), title);
		ml.table[0] = '\0';
		return (true);
	}
	if (strcmp(form, "ml-conf") != 0)
		return (false);
	if ((s = ml_server()) == NULL)
		return (true);
	spec = ucl_object_typed_new(UCL_OBJECT);
	ls = ucl_object_typed_new(UCL_ARRAY);
	if ((copy = strdup(jstr(f, "listeners") != NULL ? jstr(f, "listeners") :
	    "")) == NULL)
		abort();
	for (it = copy; (line = strsep(&it, "\n")) != NULL;) {
		line[strcspn(line, "\r")] = '\0';
		line += strspn(line, " \t");
		if (line[0] == '\0' || line[0] == '#')
			continue;
		if ((l = listener_of(line)) == NULL) {
			toast(true, "A listener is: where it listens, then port, "
			    "tls, pki, auth, hostname or filter words");
			free(copy);
			ucl_object_unref(ls);
			ucl_object_unref(spec);
			return (true);
		}
		ucl_array_append(ls, l);
	}
	free(copy);
	ucl_object_insert_key(spec, ls, "listeners", 0, false);
	ucl_object_insert_key(spec, lines_array(jstr(f, "domains"), false),
	    "domains", 0, false);
	del = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(del, ucl_object_fromstring(jstr(f, "kind") != NULL
	    ? jstr(f, "kind") : "maildir"), "kind", 0, false);
	if ((v = jstr(f, "path")) != NULL && v[0] != '\0')
		ucl_object_insert_key(del, ucl_object_fromstring(v), "path", 0,
		    false);
	ucl_object_insert_key(del, ucl_object_frombool(jbool(f, "aliases")),
	    "aliases", 0, false);
	ucl_object_insert_key(del, ucl_object_frombool(jbool(f, "virtual")),
	    "virtual", 0, false);
	ucl_object_insert_key(spec, del, "delivery", 0, false);
	rel = ucl_object_typed_new(UCL_OBJECT);
	if ((v = jstr(f, "relay_host")) != NULL && v[0] != '\0') {
		ucl_object_insert_key(rel, ucl_object_fromstring(v), "host", 0,
		    false);
		if ((v = jstr(f, "relay_port")) != NULL && atoi(v) > 0)
			ucl_object_insert_key(rel, ucl_object_fromint(atoi(v)),
			    "port", 0, false);
		if ((v = jstr(f, "relay_proto")) != NULL)
			ucl_object_insert_key(rel, ucl_object_fromstring(v), "proto",
			    0, false);
		ucl_object_insert_key(rel, ucl_object_frombool(jbool(f,
		    "relay_auth")), "auth", 0, false);
	}
	if ((v = jstr(f, "mail_from")) != NULL && v[0] != '\0')
		ucl_object_insert_key(rel, ucl_object_fromstring(v), "mail_from",
		    0, false);
	ucl_object_insert_key(spec, rel, "relay", 0, false);
	pol = ucl_object_typed_new(UCL_OBJECT);
	if ((v = jstr(f, "max_size")) != NULL && v[0] != '\0')
		ucl_object_insert_key(pol, ucl_object_fromstring(v), "max_size",
		    0, false);
	if ((v = jstr(f, "max_rcpt")) != NULL && atoi(v) > 0)
		ucl_object_insert_key(pol, ucl_object_fromint(atoi(v)),
		    "max_rcpt", 0, false);
	if ((v = jstr(f, "bounce_warn")) != NULL && v[0] != '\0')
		ucl_object_insert_key(pol, ucl_object_fromstring(v),
		    "bounce_warn", 0, false);
	ucl_object_insert_key(pol, ucl_object_frombool(jbool(f, "check_rdns")),
	    "check_rdns", 0, false);
	ucl_object_insert_key(pol, ucl_object_frombool(jbool(f,
	    "check_fcrdns")), "check_fcrdns", 0, false);
	ucl_object_insert_key(pol, ucl_object_frombool(jbool(f,
	    "queue_compression")), "queue_compression", 0, false);
	ucl_object_insert_key(spec, pol, "policy", 0, false);
	ucl_object_insert_key(spec, lines_array(jstr(f, "filters"), true),
	    "filters", 0, false);
	if ((v = jstr(f, "own")) != NULL && v[0] != '\0')
		ucl_object_insert_key(spec, ucl_object_fromstring(v), "own", 0,
		    false);
	json = (char *)ucl_object_emit(spec, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(spec);
	q = json_quote(json != NULL ? json : "{}");
	free(json);
	/* Over the admin's own file: said to replace it, as warned. */
	if (asprintf(&json, "{\"kind\":\"smtpd\",\"verb\":\"conf\",\"text\":%s%s%s}",
	    q, ml_extra(s) != NULL ? ml_extra(s) : "", conf_own(ml.r.o) ?
	    ",\"force\":true" : "") == -1)
		abort();
	free(q);
	send(s, json, "smtpd.conf from the form");
	ml.conf = false;
	return (true);
}

bool
mail_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	const char	*w[1];
	char		 title[96], body[300];

	if (strcmp(act, "input:ml-where") == 0) {
		ml.picked = true;
		snprintf(ml.jail, sizeof(ml.jail), "%s", value != NULL ? value :
		    "");
		ml.conf = false;
		ml.table[0] = '\0';
		res_drop(&ml.r);
		render();
		return (true);
	}
	if (strncmp(act, "ml-", 3) != 0)
		return (false);
	if (strcmp(act, "ml-retry") == 0) {
		res_drop(&ml.r);
		render();
		return (true);
	}
	if (strcmp(act, "ml-text") == 0) {
		ml.text = true;
		ml.conf = false;
		render();
		return (true);
	}
	if (strcmp(act, "ml-text-close") == 0) {
		ml.text = false;
		render();
		return (true);
	}
	if (strcmp(act, "ml-conf") == 0) {
		ml.conf = true;
		return (true);
	}
	if (strcmp(act, "ml-conf-close") == 0) {
		ml.conf = false;
		return (true);
	}
	if (strcmp(act, "ml-table") == 0) {
		snprintf(ml.table, sizeof(ml.table), "%s", strcmp(ml.table, arg)
		    == 0 ? "" : arg);
		return (true);
	}
	if (strcmp(act, "ml-table-close") == 0) {
		ml.table[0] = '\0';
		return (true);
	}
	if ((s = ml_server()) == NULL)
		return (true);
	if (strcmp(act, "ml-install") == 0) {
		char	*json, *qj;
		const char *jail = ml_where(s);

		/* Where the tab looks: the host, or the jail by pkg -j. */
		qj = json_quote(jail);
		if (asprintf(&json, "{\"kind\":\"pkg-install\",\"packages\":"
		    "[\"opensmtpd\"]%s%s}", jail[0] != '\0' ? ",\"jail\":" : "",
		    jail[0] != '\0' ? qj : "") == -1)
			abort();
		free(qj);
		snprintf(title, sizeof(title), "pkg install opensmtpd%s%s",
		    jail[0] != '\0' ? " in " : "", jail);
		job_send(s, json, title, JOB_MAIL, jail);
		return (true);
	}
	if (strcmp(act, "ml-enable") == 0 && strcmp(arg, "no") == 0) {
		confirm("Stop OpenSMTPD?", "smtpd is stopped and disabled: mail "
		    "to this host is refused, and what is queued waits until it "
		    "runs again.", "Stop", true, NULL, "ml-enable-yes", "no",
		    "");
		return (true);
	}
	if (strcmp(act, "ml-unentry") == 0 && value != NULL) {
		snprintf(body, sizeof(body), "%s is taken out of the %s table; "
		    "every other entry is kept.%s", value, arg, strcmp(arg,
		    "credentials") == 0 ? " The user can no longer sign in." :
		    strcmp(arg, "domains") == 0 ? " Mail for it is no longer "
		    "delivered here." : "");
		confirm("Remove the entry?", body, "Remove", true, NULL,
		    "ml-unentry-yes", arg, value);
		return (true);
	}
	if (strcmp(act, "ml-unentry-yes") == 0 && value != NULL) {
		const char	*w2[2];

		if ((s = ml_server()) == NULL)
			return (true);
		w2[0] = arg;
		w2[1] = value;
		snprintf(title, sizeof(title), "smtpd table %s: %s taken out",
		    arg, value);
		send(s, job_json("smtpd", "unentry", w2, 2, NULL, ml_extra(s)),
		    title);
		return (true);
	}
	if (strcmp(act, "ml-remove") == 0) {
		snprintf(body, sizeof(body), "%s taken out of the queue, never "
		    "delivered, the sender not told.", strcmp(arg, "all") == 0 ?
		    "Every envelope is" : "The envelope is");
		confirm("Remove from the queue?", body, "Remove", true, NULL,
		    "ml-remove-yes", arg, "");
		return (true);
	}
	if (strcmp(act, "ml-enable") == 0 || strcmp(act, "ml-enable-yes")
	    == 0) {
		snprintf(title, sizeof(title), "smtpd %s", strcmp(arg, "yes") ==
		    0 ? "enabled and started" : "stopped and disabled");
		w[0] = strcmp(arg, "yes") == 0 ? "enable=yes" : "enable=no";
		send(s, job_json("smtpd", "enable", w, 1, NULL, ml_extra(s)), title);
		return (true);
	}
	if (strcmp(act, "ml-pause") == 0 || strcmp(act, "ml-resume") == 0 ||
	    strcmp(act, "ml-schedule") == 0 || strcmp(act, "ml-remove-yes")
	    == 0) {
		const char	*verb = strcmp(act, "ml-pause") == 0 ? "pause" :
		    strcmp(act, "ml-resume") == 0 ? "resume" : strcmp(act,
		    "ml-schedule") == 0 ? "schedule" : "remove";

		w[0] = arg;
		snprintf(title, sizeof(title), "smtpd %s %s", verb, arg);
		send(s, job_json("smtpd", verb, w, 1, NULL, ml_extra(s)), title);
		return (true);
	}
	return (false);
}
