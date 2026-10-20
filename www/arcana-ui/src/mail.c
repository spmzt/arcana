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
	char		 table[16];	/* the table being edited, or "" */
} ml;

/* Read again at the next draw (the Refresh button). */
void
mail_refresh(void)
{

	res_drop(&ml.r);
}

static void
ml_load(const char *sid)
{
	char	url[96];

	snprintf(url, sizeof(url), "/api/servers/%s/smtpd", sid);
	res_load(&ml.r, sid, url);
}

static void
send(struct server *s, char *json, const char *title)
{

	job_send(s, json, title, JOB_MAIL, s->name);
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
	h_raw(h, "<form class=\"stack mailconf\" data-form=\"mail-conf\">"
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
	    "class=\"ghost\" data-act=\"mail-conf-close\">Close</button>"
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
	h_raw(h, "<form class=\"stack\" data-form=\"mail-table\"><input "
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
	h_raw(h, "</small><div class=\"toolbar\"><button class=\"primary\">"
	    "Write</button><button type=\"button\" class=\"ghost\" "
	    "data-act=\"mail-table-close\">Close</button></div></form>");
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
	const ucl_object_t	**rows, *r, *st, *t, *e;
	ucl_object_iter_t	 it;
	const ucl_object_t	*o;
	size_t			 i;
	int			 k;
	bool			 running;

	if (!res_shown(h, &ml.r, s->id, ml_load, "mail-retry"))
		return;
	o = ml.r.o;
	h_raw(h, "<section class=\"sysview mailview\">");
	if (!jbool(o, "installed")) {
		h_raw(h, "<div class=\"notice warn sec-missing\"><span>OpenSMTPD "
		    "is not installed on this host: a plugin.</span><button "
		    "class=\"primary small\" data-act=\"sec-install\" data-arg=\""
		    "opensmtpd\">Install opensmtpd</button></div><div "
		    "class=\"empty\"><p>No mail server here.</p><p class=\"dim\">"
		    "FreeBSD comes with sendmail(8) and dma(8) for the host's "
		    "own mail; OpenSMTPD, a port, serves a domain's.</p></div>"
		    "</section>");
		return;
	}
	running = jbool(o, "running");
	h_raw(h, "<div class=\"toolbar\">");
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
		    paused ? "mail-resume" : "mail-pause", parts[i], paused ?
		    "Resume" : "Pause");
	}
	h_fmt(h, "<span class=\"grow\"></span><button class=\"ghost\" "
	    "data-act=\"mail-enable\" data-arg=\"%s\">%s</button><button "
	    "class=\"ghost\" data-act=\"mail-conf\">Configuration</button>"
	    "</div>", running ? "no" : "yes", running ? "Stop and disable" :
	    "Enable and start");
	if (jstr(o, "mailer") != NULL) {
		h_raw(h, "<p class=\"dim\">sendmail(8) on this host is <code>");
		h_txt(h, jstr(o, "mailer"));
		h_raw(h, "</code> (mailer.conf(5)); OpenSMTPD's is <code>"
		    "/usr/local/sbin/smtpctl</code>.</p>");
	}
	if (ml.conf)
		conf_form(h, o);
	/* The queue, with smtpctl's commands. */
	h_fmt(h, "<h3 class=\"secsub\">Queue%s</h3>", running ? "" :
	    " (smtpd is not running)");
	if (running && jint(o, "queued", 0) > 0) {
		h_fmt(h, "<div class=\"toolbar\"><span>%lld envelope%s</span>"
		    "<span class=\"grow\"></span><button class=\"ghost small\" "
		    "data-act=\"mail-schedule\" data-arg=\"all\">Try all now"
		    "</button><button class=\"ghost small danger\" data-act=\""
		    "mail-remove\" data-arg=\"all\">Remove all</button></div>",
		    (long long)jint(o, "queued", 0), jint(o, "queued", 0) == 1 ?
		    "" : "s");
		tbl_head(h, "mailq", cols, 7, 0);
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
			    "small\" data-act=\"mail-schedule\"");
			h_attr(h, "data-arg", jstr(r, "evpid"));
			h_raw(h, ">Try now</button><button class=\"ghost small "
			    "danger\" data-act=\"mail-remove\"");
			h_attr(h, "data-arg", jstr(r, "evpid"));
			h_raw(h, ">Remove</button></td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table>");
	} else if (running)
		h_raw(h, "<p class=\"dim\">Empty: nothing waits.</p>");
	/* Its counters, those that say most. */
	if (running && (st = jget(o, "stats")) != NULL) {
		static const struct {
			const char	*key, *title;
		} show[] = {
			{ "scheduler.delivery.ok", "Delivered" },
			{ "scheduler.delivery.tempfail", "Deferred" },
			{ "scheduler.delivery.permfail", "Bounced" },
			{ "smtp.session", "SMTP sessions now" },
			{ "smtp.session.local", "Local sessions" },
			{ "mta.session", "Sessions out now" },
			{ "queue.bounce", "Bounces" },
			{ "uptime.human", "Up for" },
		};

		h_raw(h, "<h3 class=\"secsub\">Counters</h3><dl class=\"kv\">");
		for (i = 0; i < nitems(show); i++) {
			if ((e = jget(st, show[i].key)) == NULL)
				continue;
			h_raw(h, "<dt>");
			h_txt(h, show[i].title);
			h_raw(h, "</dt><dd>");
			if (ucl_object_type(e) == UCL_STRING)
				h_txt(h, ucl_object_tostring(e));
			else
				h_fmt(h, "%lld", (long long)ucl_object_toint(e));
			h_raw(h, "</dd>");
		}
		h_raw(h, "</dl>");
	}
	/* The tables, each written whole. */
	h_raw(h, "<h3 class=\"secsub\">Tables</h3><div class=\"toolbar\">");
	for (i = 0; i < nitems(tables); i++) {
		t = jget(jget(o, "tables"), tables[i]);
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"mail-table\" "
		    "data-arg=\"%s\">%s%s</button>", strcmp(ml.table, tables[i])
		    == 0 ? " on" : "", tables[i], tables[i], t != NULL ? " ✓"
		    : "");
	}
	h_raw(h, "</div>");
	if (ml.table[0] != '\0') {
		t = jget(jget(o, "tables"), ml.table);
		if (t != NULL && ucl_object_type(t) == UCL_ARRAY) {
			h_raw(h, "<p class=\"dim\">Kept on the host: ");
			it = NULL;
			k = 0;
			while ((e = ucl_object_iterate(t, &it, true)) != NULL) {
				h_raw(h, k++ > 0 ? ", " : "");
				h_txt(h, ucl_object_tostring(e));
			}
			h_raw(h, k == 0 ? "none yet.</p>" : ".</p>");
		}
		table_form(h, o, ml.table);
	}
	h_raw(h, "<h3 class=\"secsub\">smtpd.conf</h3><pre class=\"mono naspre\">");
	h_txt(h, jstr(o, "conf") != NULL ? jstr(o, "conf") : "(none yet)");
	h_raw(h, "</pre><p class=\"dim\"><b>FreeBSD:</b> OpenSMTPD is the port "
	    "mail/opensmtpd; what sendmail(8) is on the host is "
	    "mailer.conf(5)'s choice; its queue is /var/spool/smtpd, its log "
	    "/var/log/maillog (the Log tab).</p></section>");
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

	if (strcmp(form, "mail-table") == 0) {
		if ((s = ml_server()) == NULL || jstr(f, "name") == NULL)
			return (true);
		w[0] = jstr(f, "name");
		snprintf(title, sizeof(title), "smtpd table %s written", w[0]);
		send(s, job_json("smtpd", "table", w, 1, jstr(f, "text") != NULL ?
		    jstr(f, "text") : "", NULL), title);
		ml.table[0] = '\0';
		return (true);
	}
	if (strcmp(form, "mail-conf") != 0)
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
	if (asprintf(&json, "{\"kind\":\"smtpd\",\"verb\":\"conf\",\"text\":%s}",
	    q) == -1)
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

	(void)value;
	if (strncmp(act, "mail-", 5) != 0)
		return (false);
	if (strcmp(act, "mail-retry") == 0) {
		res_drop(&ml.r);
		render();
		return (true);
	}
	if (strcmp(act, "mail-conf") == 0) {
		ml.conf = true;
		return (true);
	}
	if (strcmp(act, "mail-conf-close") == 0) {
		ml.conf = false;
		return (true);
	}
	if (strcmp(act, "mail-table") == 0) {
		snprintf(ml.table, sizeof(ml.table), "%s", strcmp(ml.table, arg)
		    == 0 ? "" : arg);
		return (true);
	}
	if (strcmp(act, "mail-table-close") == 0) {
		ml.table[0] = '\0';
		return (true);
	}
	if ((s = ml_server()) == NULL)
		return (true);
	if (strcmp(act, "mail-enable") == 0 && strcmp(arg, "no") == 0) {
		confirm("Stop OpenSMTPD?", "smtpd is stopped and disabled: mail "
		    "to this host is refused, and what is queued waits until it "
		    "runs again.", "Stop", true, NULL, "mail-enable-yes", "no",
		    "");
		return (true);
	}
	if (strcmp(act, "mail-remove") == 0) {
		snprintf(body, sizeof(body), "%s taken out of the queue, never "
		    "delivered, the sender not told.", strcmp(arg, "all") == 0 ?
		    "Every envelope is" : "The envelope is");
		confirm("Remove from the queue?", body, "Remove", true, NULL,
		    "mail-remove-yes", arg, "");
		return (true);
	}
	if (strcmp(act, "mail-enable") == 0 || strcmp(act, "mail-enable-yes")
	    == 0) {
		snprintf(title, sizeof(title), "smtpd %s", strcmp(arg, "yes") ==
		    0 ? "enabled and started" : "stopped and disabled");
		w[0] = strcmp(arg, "yes") == 0 ? "enable=yes" : "enable=no";
		send(s, job_json("smtpd", "enable", w, 1, NULL, NULL), title);
		return (true);
	}
	if (strcmp(act, "mail-pause") == 0 || strcmp(act, "mail-resume") == 0 ||
	    strcmp(act, "mail-schedule") == 0 || strcmp(act, "mail-remove-yes")
	    == 0) {
		const char	*verb = strcmp(act, "mail-pause") == 0 ? "pause" :
		    strcmp(act, "mail-resume") == 0 ? "resume" : strcmp(act,
		    "mail-schedule") == 0 ? "schedule" : "remove";

		w[0] = arg;
		snprintf(title, sizeof(title), "smtpd %s %s", verb, arg);
		send(s, job_json("smtpd", verb, w, 1, NULL, NULL), title);
		return (true);
	}
	return (false);
}
