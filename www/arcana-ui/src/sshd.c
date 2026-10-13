/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's sshd, or a jail's: what it is set to, as sshd -T says; its
 * banner; its host keys, their fingerprints and the certificates a CA
 * key signed for them; and who signs in, with which keys.  Each change
 * is a job: sshd -t reads it before it is put in place, and sshd is
 * reloaded.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"

static const struct {
	const char	*name;		/* as sshd_config has it */
	const char	*key;		/* as sshd -T says it */
	const char	*values;	/* those it takes; NULL: names; #: a number */
	const char	*help;
} sets[] = {
	{ "PermitRootLogin", "permitrootlogin",
	    "yes|no|prohibit-password|forced-commands-only",
	    "Whether root signs in, and how" },
	{ "PasswordAuthentication", "passwordauthentication", "yes|no",
	    "A password to sign in with" },
	{ "KbdInteractiveAuthentication", "kbdinteractiveauthentication",
	    "yes|no", "Keyboard-interactive, PAM's questions" },
	{ "PubkeyAuthentication", "pubkeyauthentication", "yes|no",
	    "A key to sign in with" },
	{ "AllowUsers", "allowusers", NULL,
	    "Only these sign in: names or patterns, user@host too" },
	{ "AllowGroups", "allowgroups", NULL, "Only those of these groups" },
	{ "DenyUsers", "denyusers", NULL, "These never sign in" },
	{ "DenyGroups", "denygroups", NULL, "Those of these groups never" },
	{ "MaxAuthTries", "maxauthtries", "#", "Tries before a connection "
	    "is closed" },
	{ "X11Forwarding", "x11forwarding", "yes|no", "X11 carried" },
	{ "Port", "port", "#", "The ports it listens on" },
};

#define	NSETS	(sizeof(sets) / sizeof(sets[0]))

static struct {
	char		 sid[9];
	char		 jail[256];
	ucl_object_t	*data;
	bool		 loading;
	char		 error[300];
	char		 set[40];	/* the setting being changed */
	char		 user[64];	/* whose key is being added */
} sh;

static void
ssh_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid;

	sid = arg;
	if (strcmp(sid, sh.sid) != 0) {
		free(sid);
		return;
	}
	free(sid);
	sh.loading = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(sh.error, sizeof(sh.error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	sh.error[0] = '\0';
	if (sh.data != NULL)
		ucl_object_unref(sh.data);
	sh.data = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
}

void
refresh_ssh(struct server *s, bool again)
{
	char	url[400];

	if (!app.online || sh.loading)
		return;
	if (strcmp(sh.sid, s->id) != 0) {
		if (sh.data != NULL)
			ucl_object_unref(sh.data);
		sh.data = NULL;
		sh.error[0] = '\0';
		sh.jail[0] = '\0';
	} else if (!again && (sh.data != NULL || sh.error[0] != '\0'))
		return;
	snprintf(sh.sid, sizeof(sh.sid), "%s", s->id);
	sh.loading = true;
	snprintf(url, sizeof(url), "/api/servers/%s/ssh%s%s", s->id,
	    sh.jail[0] != '\0' ? "?jail=" : "", sh.jail);
	api("GET", url, NULL, ssh_cb, strdup(s->id));
}

/* A job: verb, and each of the rest only when it is given. */
static void
ssh_job(struct server *s, const char *verb, const char *path,
    const char *names, const char *text, const char *user, const char *what)
{
	char	*q, *json, *more, *w, title[400];
	const char *p, *e;

	if (asprintf(&json, "{\"kind\":\"ssh\",\"verb\":\"%s\"", verb) == -1)
		abort();
#define	ADD(key, v) do {						\
	q = json_quote(v);						\
	if (asprintf(&more, "%s,\"" key "\":%s", json, q) == -1)	\
		abort();						\
	free(q);							\
	free(json);							\
	json = more;							\
} while (0)
	if (sh.jail[0] != '\0')
		ADD("jail", sh.jail);
	if (path != NULL)
		ADD("path", path);
	if (text != NULL)
		ADD("text", text);
	if (user != NULL)
		ADD("user", user);
#undef ADD
	if (names != NULL) {
		if (asprintf(&more, "%s,\"args\":[", json) == -1)
			abort();
		free(json);
		json = more;
		for (p = names; *p != '\0'; p = e) {
			p += strspn(p, " \t\r\n,");
			if (*p == '\0')
				break;
			e = p + strcspn(p, " \t\r\n,");
			w = strndup(p, (size_t)(e - p));
			q = json_quote(w);
			free(w);
			if (asprintf(&more, "%s%s%s", json, json[strlen(json) -
			    1] == '[' ? "" : ",", q) == -1)
				abort();
			free(q);
			free(json);
			json = more;
		}
		if (asprintf(&more, "%s]", json) == -1)
			abort();
		free(json);
		json = more;
	}
	if (asprintf(&more, "%s}", json) == -1)
		abort();
	free(json);
	snprintf(title, sizeof(title), "%s%ssshd %s", sh.jail, sh.jail[0] !=
	    '\0' ? ": " : "", what);
	job_send_host(s, more, title, JOB_SSH, "");
}

static void
jail_pick(struct html *h, struct server *s)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;
	const char		*name;

	h_raw(h, "<label class=\"net-jail\" title=\"Whose sshd: the host's, "
	    "or a running jail's\"><select data-input=\"ssh-jail\">");
	h_fmt(h, "<option value=\"\"%s>", sh.jail[0] == '\0' ? " selected" :
	    "");
	h_txt(h, s->name);
	h_raw(h, "</option>");
	it = NULL;
	while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		if ((name = jstr(j, "name")) == NULL || (strcmp(name, sh.jail) !=
		    0 && (jstr(j, "state") == NULL || strcmp(jstr(j, "state"),
		    "running") != 0)))
			continue;
		h_raw(h, "<option");
		h_attr(h, "value", name);
		h_raw(h, strcmp(name, sh.jail) == 0 ? " selected>" : ">");
		h_txt(h, name);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label>");
}

/* A setting's values, as one line. */
static char *
values_of(const char *key)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	char			*s, *n;

	s = strdup("");
	it = NULL;
	while ((v = ucl_object_iterate(jget(jget(sh.data, "settings"), key),
	    &it, true)) != NULL) {
		if (asprintf(&n, "%s%s%s", s, s[0] != '\0' ? " " : "",
		    ucl_object_tostring_forced(v)) == -1)
			abort();
		free(s);
		s = n;
	}
	return (s);
}

static void
day(char *buf, size_t len, int64_t t)
{
	struct tm	tm;
	time_t		tt;

	if (t < 0) {
		snprintf(buf, len, "forever");
		return;
	}
	tt = (time_t)t;
	gmtime_r(&tt, &tm);
	strftime(buf, len, "%Y-%m-%d", &tm);
}

void
view_ssh(struct html *h, struct server *s)
{
	static const struct tcol scols[] = {
		{ "Setting", "name", false }, { "Value", "value", false },
		{ "", NULL, false }, { "", NULL, false },
	};
	static const struct tcol hcols[] = {
		{ "Type", "type", false }, { "Bits", "bits", true },
		{ "Fingerprint", "fingerprint", false }, { "Certificate", NULL,
		false }, { "Valid to", NULL, false },
	};
	static const struct tcol ucols[] = {
		{ "User", "name", false }, { "Uid", "uid", true },
		{ "Shell", "shell", false }, { "Keys file", "keys_file", false },
		{ "Keys", "n", true }, { "", NULL, false },
	};
	static const struct tcol kcols[] = {
		{ "User", "user", false }, { "Type", "type", false },
		{ "Fingerprint", "fingerprint", false }, { "Comment", "comment",
		false }, { "Options", "options", false }, { "", NULL, false },
	};
	ucl_object_t		*arr, *o, *k;
	const ucl_object_t	**rows, *r, *c, *u, *x, *pr;
	ucl_object_iter_t	 it, kit, pit;
	char			*v, when[32];
	size_t			 i;
	int			 n;

	h_raw(h, "<div class=\"toolbar\">");
	jail_pick(h, s);
	h_raw(h, "<input class=\"filter\" id=\"filter\" data-input=\"filter\" "
	    "placeholder=\"Filter\" autocomplete=\"off\" spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "></div>");
	if (sh.error[0] != '\0') {
		h_raw(h, "<p class=\"error\">");
		h_txt(h, sh.error);
		h_raw(h, "</p>");
	}
	if (sh.data == NULL || strcmp(sh.sid, s->id) != 0) {
		h_raw(h, sh.loading ? "<p class=\"dim\">Reading sshd…</p>" : "");
		return;
	}
	h_raw(h, "<p class=\"dim\">The base system's sshd(8), as <code>sshd "
	    "-T</code> says it is set (<code>");
	h_txt(h, jstr(sh.data, "config"));
	h_raw(h, "</code>). A change is read by <code>sshd -t</code> before "
	    "it is put in place, the file before it kept beside it, and sshd "
	    "reloaded.");
	if (jstr(sh.data, "settings_from_file") != NULL) {
		h_raw(h, " <span class=\"chip warn\" title=\"");
		h_txt(h, jstr(sh.data, "settings_from_file"));
		h_raw(h, "\">as the file says: sshd -T could not</span>");
	}
	h_raw(h, "</p>");

	/* Settings. */
	h_raw(h, "<h3>Settings</h3><table class=\"net ssh-set\">");
	tbl_head(h, "ssh-set", scols, 4, 0);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < NSETS; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		v = values_of(sets[i].key);
		ucl_object_insert_key(o, ucl_object_fromstring(sets[i].name),
		    "name", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(v), "value", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)i), "i", 0,
		    false);
		free(v);
		ucl_array_append(arr, o);
	}
	h_raw(h, "<tbody>");
	rows = tbl_rows("ssh-set", arr, scols, 4, app.filter);
	for (n = 0; (r = rows[n]) != NULL; n++) {
		i = (size_t)jint(r, "i", 0);
		h_raw(h, "<tr><td><b>");
		h_txt(h, sets[i].name);
		h_raw(h, "</b></td><td class=\"mono\">");
		h_txt(h, jstr(r, "value")[0] != '\0' ? jstr(r, "value") : "—");
		h_raw(h, "</td><td class=\"dim\">");
		h_txt(h, sets[i].help);
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" "
		    "data-act=\"ssh-set\" title=\"Change it\"");
		h_attr(h, "data-arg", sets[i].name);
		h_raw(h, ">✎</button></td></tr>");
	}
	free(rows);
	ucl_object_unref(arr);
	h_raw(h, "</tbody></table>");

	/* The banner. */
	h_raw(h, "<h3>Banner</h3><form data-form=\"ssh-banner\" class=\""
	    "ssh-banner\"><textarea name=\"text\" rows=\"4\" class=\"mono\" "
	    "spellcheck=\"false\" placeholder=\"What is shown before one "
	    "signs in: none now\">");
	if (jstr(sh.data, "banner_text") != NULL)
		h_txt(h, jstr(sh.data, "banner_text"));
	h_raw(h, "</textarea><div class=\"row\"><button class=\"primary small\">"
	    "Save the banner</button> <small class=\"dim\">kept as "
	    "<code>/etc/ssh/banner</code>; empty, there is none</small></div>"
	    "</form>");

	/* Host keys. */
	h_raw(h, "<h3>Host keys <button class=\"ghost small\" data-act=\""
	    "ssh-sign\" title=\"Each host key signed by your CA's key, for "
	    "52 weeks: its certificate beside it, and sshd told\">Sign with a "
	    "CA key…</button></h3><table class=\"net ssh-hk\">");
	tbl_head(h, "ssh-hk", hcols, 5, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("ssh-hk", jget(sh.data, "host_keys"), hcols, 5,
	    app.filter);
	for (n = 0; (r = rows[n]) != NULL; n++) {
		h_raw(h, "<tr");
		h_attr(h, "title", jstr(r, "path"));
		h_raw(h, "><td>");
		h_txt(h, jstr(r, "type"));
		if (jint(r, "bits", 0) > 0)
			h_fmt(h, "</td><td>%lld</td><td class=\"mono fp\">",
			    (long long)jint(r, "bits", 0));
		else
			h_raw(h, "</td><td>—</td><td class=\"mono fp\">");
		h_txt(h, jstr(r, "fingerprint"));
		h_raw(h, "</td><td class=\"fp\">");
		if ((c = jget(r, "certificate")) != NULL) {
			h_raw(h, "<span class=\"mono\" title=\"The CA's key\">");
			h_txt(h, jstr(c, "ca") != NULL ? jstr(c, "ca") : "");
			h_raw(h, "</span>");
			pit = NULL;
			pr = jget(c, "principals");
			if (ucl_array_size(pr) > 0)
				h_raw(h, "<br><small>for ");
			while ((x = ucl_object_iterate(pr, &pit, true)) != NULL) {
				h_txt(h, ucl_object_tostring(x));
				h_raw(h, " ");
			}
			if (ucl_array_size(pr) > 0)
				h_raw(h, "</small>");
			if (!jbool(r, "certificate_used"))
				h_raw(h, " <span class=\"chip warn\" title=\"No "
				    "HostCertificate line names it\">not used"
				    "</span>");
			day(when, sizeof(when), jint(c, "valid_before", 0));
			h_fmt(h, "</td><td>%s</td></tr>", when);
		} else
			h_raw(h, "—</td><td></td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");

	/* Who signs in, and with which keys. */
	h_raw(h, "<h3>Who signs in</h3><table class=\"net ssh-users\">");
	tbl_head(h, "ssh-users", ucols, 6, 0);
	arr = ucl_object_typed_new(UCL_ARRAY);
	k = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((u = ucl_object_iterate(jget(sh.data, "users"), &it, true)) !=
	    NULL) {
		o = ucl_object_copy(u);
		ucl_object_insert_key(o, ucl_object_fromint((int64_t)
		    ucl_array_size(jget(u, "keys"))), "n", 0, false);
		ucl_array_append(arr, o);
		kit = NULL;
		while ((x = ucl_object_iterate(jget(u, "keys"), &kit, true)) !=
		    NULL) {
			o = ucl_object_copy(x);
			ucl_object_insert_key(o, ucl_object_fromstring(jstr(u,
			    "name")), "user", 0, false);
			ucl_array_append(k, o);
		}
	}
	h_raw(h, "<tbody>");
	rows = tbl_rows("ssh-users", arr, ucols, 6, app.filter);
	for (n = 0; (r = rows[n]) != NULL; n++) {
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(r, "name"));
		h_fmt(h, "</b></td><td>%lld</td><td class=\"mono\">",
		    (long long)jint(r, "uid", 0));
		h_txt(h, jstr(r, "shell"));
		h_raw(h, "</td><td class=\"mono fp\">");
		h_txt(h, jstr(r, "keys_file"));
		h_fmt(h, "</td><td>%lld</td><td class=\"acts\"><button class=\""
		    "ghost small\" data-act=\"ssh-key-add\" title=\"A key "
		    "this user signs in with\"", (long long)jint(r, "n", 0));
		h_attr(h, "data-arg", jstr(r, "name"));
		h_raw(h, ">+ key</button></td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table><h3>Their keys</h3><table class=\"net "
	    "ssh-keys\">");
	tbl_head(h, "ssh-keys", kcols, 6, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("ssh-keys", k, kcols, 6, app.filter);
	for (n = 0; (r = rows[n]) != NULL; n++) {
		h_raw(h, "<tr><td>");
		h_txt(h, jstr(r, "user"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "type"));
		h_raw(h, "</td><td class=\"mono fp\">");
		h_txt(h, jstr(r, "fingerprint"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "comment") != NULL ? jstr(r, "comment") : "");
		h_raw(h, "</td><td class=\"mono opts\">");
		h_txt(h, jstr(r, "options") != NULL ? jstr(r, "options") : "");
		h_raw(h, "</td><td class=\"acts\"><button class=\"icon\" "
		    "data-act=\"ssh-key-del\" title=\"Taken out of their "
		    "authorized_keys\"");
		h_attr(h, "data-arg", jstr(r, "fingerprint"));
		h_attr(h, "data-value", jstr(r, "user"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"6\" class=\"dim\">No keys.</td></tr>");
	free(rows);
	h_raw(h, "</tbody></table>");
	ucl_object_unref(arr);
	ucl_object_unref(k);
}

bool
ssh_modal(struct html *h)
{
	const char	*p, *e;
	char		*v, one[40];
	size_t		 i;

	switch (app.modal) {
	case MODAL_SSH_SET:
		for (i = 0; i < NSETS && strcmp(sets[i].name, sh.set) !=
		    0; i++)
			;
		if (i == NSETS)
			return (false);
		h_raw(h, "<form data-form=\"ssh-set\"><h2>");
		h_txt(h, sets[i].name);
		h_raw(h, "</h2><p>");
		h_txt(h, sets[i].help);
		h_raw(h, ". Read by <code>sshd -t</code> first; the file before "
		    "it kept beside it.</p>");
		v = values_of(sets[i].key);
		if (sets[i].values != NULL && strcmp(sets[i].values, "#") != 0) {
			h_raw(h, "<label>Value<select name=\"value\">");
			for (p = sets[i].values; *p != '\0'; p = *e != '\0' ?
			    e + 1 : e) {
				e = p + strcspn(p, "|");
				snprintf(one, sizeof(one), "%.*s", (int)(e - p), p);
				h_raw(h, "<option");
				h_attr(h, "value", one);
				if (strcmp(v, one) == 0)
					h_raw(h, " selected");
				h_raw(h, ">");
				h_txt(h, one);
				h_raw(h, "</option>");
			}
			h_raw(h, "</select></label>");
		} else {
			h_raw(h, "<label>");
			h_raw(h, sets[i].values == NULL ? "Names, a space between "
			    "them; none to take the line away" : strcmp(
			    sets[i].name, "Port") == 0 ? "Ports, a space between "
			    "them" : "A number");
			h_raw(h, "<input name=\"value\" spellcheck=\"false\" "
			    "autocomplete=\"off\" autofocus");
			h_attr(h, "value", v);
			h_raw(h, "></label>");
		}
		free(v);
		return (true);
	case MODAL_SSH_SIGN:
		h_raw(h, "<form data-form=\"ssh-sign\"><h2>Sign the host keys"
		    "</h2><p>Each host key signed by your certificate "
		    "authority's key, with <code>ssh-keygen -s -h</code>, for 52 "
		    "weeks; its certificate beside it, named by HostCertificate. "
		    "The CA's key is on the host only while ssh-keygen reads it, "
		    "readable by root alone, and kept nowhere: not by the "
		    "console, not in the job.</p><label>The CA's private key"
		    "<textarea name=\"key\" rows=\"8\" class=\"mono\" "
		    "spellcheck=\"false\" placeholder=\"-----BEGIN OPENSSH "
		    "PRIVATE KEY-----\"></textarea></label><label>Principals "
		    "<small>the names clients reach it by, a space between "
		    "them</small><input name=\"principals\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"host.example.org "
		    "host\"></label>");
		return (true);
	case MODAL_SSH_KEY:
		h_raw(h, "<form data-form=\"ssh-key\"><h2>A key ");
		h_txt(h, sh.user);
		h_raw(h, " signs in with</h2><p>One line of authorized_keys, its "
		    "options first if it has any: put into their keys file, "
		    "which is theirs alone.</p><label>Key<textarea name=\"key\" "
		    "rows=\"4\" class=\"mono\" spellcheck=\"false\" autofocus "
		    "placeholder=\"ssh-ed25519 AAAA… user@host\"></textarea>"
		    "</label>");
		return (true);
	default:
		return (false);
	}
}

bool
ssh_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*v, *t;
	char		*line, what[120];

	if (strncmp(form, "ssh-", 4) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(form, "ssh-set") == 0) {
		v = jstr(f, "value") != NULL ? jstr(f, "value") : "";
		snprintf(what, sizeof(what), "set %s", sh.set);
		ssh_job(s, "set", sh.set, v, NULL, NULL, what);
		app.modal = MODAL_NONE;
	} else if (strcmp(form, "ssh-banner") == 0) {
		t = jstr(f, "text") != NULL ? jstr(f, "text") : "";
		if (t[0] != '\0' && t[strlen(t) - 1] != '\n') {
			if (asprintf(&line, "%s\n", t) == -1)
				abort();
			ssh_job(s, "banner", NULL, NULL, line, NULL, "banner");
			free(line);
		} else
			ssh_job(s, "banner", NULL, NULL, t, NULL, "banner");
	} else if (strcmp(form, "ssh-sign") == 0) {
		t = jstr(f, "key") != NULL ? jstr(f, "key") : "";
		if (strstr(t, "PRIVATE KEY") == NULL) {
			snprintf(app.modal_error, sizeof(app.modal_error), "The "
			    "CA's private key, as ssh-keygen wrote it");
			return (true);
		}
		ssh_job(s, "sign", NULL, jstr(f, "principals") != NULL ?
		    jstr(f, "principals") : "", t, NULL, "sign");
		app.modal = MODAL_NONE;
	} else if (strcmp(form, "ssh-key") == 0) {
		t = jstr(f, "key") != NULL ? jstr(f, "key") : "";
		line = strndup(t + strspn(t, " \t\r\n"), strcspn(t + strspn(t,
		    " \t\r\n"), "\r\n"));
		if (line[0] == '\0' || strstr(t, "PRIVATE KEY") != NULL) {
			free(line);
			snprintf(app.modal_error, sizeof(app.modal_error), "A "
			    "public key: one line, ssh-ed25519 AAAA… and on");
			return (true);
		}
		snprintf(what, sizeof(what), "authorize of %s", sh.user);
		ssh_job(s, "authorize", NULL, NULL, line, sh.user, what);
		free(line);
		app.modal = MODAL_NONE;
	}
	return (true);
}

bool
ssh_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 body[600], what[120];

	if (strncmp(act, "ssh-", 4) != 0 && strcmp(act, "input:ssh-jail") !=
	    0 && strcmp(act, "do-ssh-key-del") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "input:ssh-jail") == 0) {
		snprintf(sh.jail, sizeof(sh.jail), "%s", value);
		if (sh.data != NULL)
			ucl_object_unref(sh.data);
		sh.data = NULL;
		sh.error[0] = '\0';
		sh.loading = false;
		refresh_ssh(s, true);
	} else if (strcmp(act, "ssh-set") == 0) {
		snprintf(sh.set, sizeof(sh.set), "%s", arg);
		app.modal = MODAL_SSH_SET;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "ssh-sign") == 0) {
		app.modal = MODAL_SSH_SIGN;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "ssh-key-add") == 0) {
		snprintf(sh.user, sizeof(sh.user), "%s", arg);
		app.modal = MODAL_SSH_KEY;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "ssh-key-del") == 0) {
		snprintf(body, sizeof(body), "The key %s taken out of %s's "
		    "authorized_keys: it signs in with it no more.", arg, value);
		confirm("Take the key away", body, "Take away", true, "",
		    "do-ssh-key-del", arg, value);
	} else if (strcmp(act, "do-ssh-key-del") == 0) {
		snprintf(what, sizeof(what), "unauthorize of %s", value);
		ssh_job(s, "unauthorize", NULL, NULL, arg, value, what);
	}
	return (true);
}
