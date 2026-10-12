/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's certificates, or a jail's: those OpenSSL trusts, as
 * certctl(8) keeps them, and those it does not; each read with OpenSSL
 * on the host, for whom it is, its key and when it ends.  One is given
 * to the host, not trusted, or trusted again: a job, which certctl
 * rehash ends.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"

#define	SOON	(30 * 86400)	/* ending this soon is said */

static struct {
	char		 sid[9];
	char		 jail[256];	/* whose: "" for the host */
	ucl_object_t	*data;
	bool		 loading;
	bool		 untrusted;	/* the list shown */
	char		 error[300];
} ct;

static void
certs_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid;

	sid = arg;
	if (strcmp(sid, ct.sid) != 0) {
		free(sid);
		return;
	}
	free(sid);
	ct.loading = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(ct.error, sizeof(ct.error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	ct.error[0] = '\0';
	if (ct.data != NULL)
		ucl_object_unref(ct.data);
	ct.data = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
}

/* Read the certificates again, or the first time for this host. */
void
refresh_certs(struct server *s, bool again)
{
	char	url[400];

	if (!app.online || ct.loading)
		return;
	if (strcmp(ct.sid, s->id) != 0) {
		if (ct.data != NULL)
			ucl_object_unref(ct.data);
		ct.data = NULL;
		ct.error[0] = '\0';
		ct.jail[0] = '\0';
	} else if (!again && (ct.data != NULL || ct.error[0] != '\0'))
		return;
	snprintf(ct.sid, sizeof(ct.sid), "%s", s->id);
	ct.loading = true;
	snprintf(url, sizeof(url), "/api/servers/%s/certs%s%s", s->id,
	    ct.jail[0] != '\0' ? "?jail=" : "", ct.jail);
	api("GET", url, NULL, certs_cb, strdup(s->id));
}

static void
cert_job(struct server *s, const char *verb, const char *path,
    const char *text)
{
	char	*qj, *qp, *qt, *json, title[400];

	qj = json_quote(ct.jail);
	qp = json_quote(path != NULL ? path : "");
	qt = json_quote(text != NULL ? text : "");
	if (asprintf(&json, "{\"kind\":\"cert\",\"verb\":\"%s\"%s%s%s%s%s%s}",
	    verb, ct.jail[0] != '\0' ? ",\"jail\":" : "", ct.jail[0] != '\0' ?
	    qj : "", path != NULL ? ",\"path\":" : "", path != NULL ? qp : "",
	    text != NULL ? ",\"text\":" : "", text != NULL ? qt : "") == -1)
		abort();
	free(qj);
	free(qp);
	free(qt);
	snprintf(title, sizeof(title), "%s%scertificate %s%s%s", ct.jail,
	    ct.jail[0] != '\0' ? ": " : "", verb, path != NULL ? " " : "",
	    path != NULL ? path : "");
	job_send_host(s, json, title, JOB_CERTS, "");
}

/* A certificate's name as it is best known: its CN, else its subject. */
static const char *
cert_name(const ucl_object_t *c)
{

	if (jstr(c, "cn") != NULL && jstr(c, "cn")[0] != '\0')
		return (jstr(c, "cn"));
	if (jstr(c, "org") != NULL && jstr(c, "org")[0] != '\0')
		return (jstr(c, "org"));
	return (jstr(c, "subject") != NULL ? jstr(c, "subject") : "");
}

static void
jail_pick(struct html *h, struct server *s)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;
	const char		*name;

	h_raw(h, "<label class=\"net-jail\" title=\"Whose certificates: the "
	    "host's, or a running jail's\"><select data-input=\"certs-jail\">");
	h_fmt(h, "<option value=\"\"%s>", ct.jail[0] == '\0' ? " selected" :
	    "");
	h_txt(h, s->name);
	h_raw(h, "</option>");
	it = NULL;
	while (s->list != NULL && (j = ucl_object_iterate(jget(s->list,
	    "jails"), &it, true)) != NULL) {
		if ((name = jstr(j, "name")) == NULL || (strcmp(name, ct.jail) !=
		    0 && (jstr(j, "state") == NULL || strcmp(jstr(j, "state"),
		    "running") != 0)))
			continue;
		h_raw(h, "<option");
		h_attr(h, "value", name);
		h_raw(h, strcmp(name, ct.jail) == 0 ? " selected>" : ">");
		h_txt(h, name);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label>");
}

void
view_certs(struct html *h, struct server *s)
{
	static const struct tcol cols[] = {
		{ "Name", "cn", false }, { "Organisation", "org", false },
		{ "Country", "country", false }, { "Key", "key", false },
		{ "Ends", "not_after", true }, { "Given here", "local", false },
		{ "", NULL, false },
	};
	const ucl_object_t	**rows, *c, *arr;
	ucl_object_iter_t	 it;
	const char		*file, *local, *base;
	char			 day[32];
	struct tm		 tm;
	time_t			 t;
	int64_t			 now, end;
	int			 n, soon, gone;
	bool			 mine;

	mine = ct.data != NULL && strcmp(ct.sid, s->id) == 0;
	now = mine ? jint(ct.data, "now", 0) : 0;
	soon = gone = 0;
	it = NULL;
	while (mine && (c = ucl_object_iterate(jget(ct.data, "trusted"), &it,
	    true)) != NULL) {
		end = jint(c, "not_after", 0);
		if (end < now)
			gone++;
		else if (end < now + SOON)
			soon++;
	}
	h_raw(h, "<div class=\"toolbar\">");
	jail_pick(h, s);
	h_fmt(h, "<nav class=\"sub\"><button class=\"%s\" data-act=\"certs-show"
	    "\" data-arg=\"trusted\">Trusted <span class=\"count\">%d</span>"
	    "</button><button class=\"%s\" data-act=\"certs-show\" data-arg=\""
	    "untrusted\">Not trusted <span class=\"count\">%d</span></button>"
	    "</nav>", ct.untrusted ? "" : "on", mine ? (int)ucl_array_size(
	    jget(ct.data, "trusted")) : 0, ct.untrusted ? "on" : "", mine ?
	    (int)ucl_array_size(jget(ct.data, "untrusted")) : 0);
	h_raw(h, "<button class=\"ghost small\" data-act=\"cert-add\" title=\""
	    "A certificate authority of your own, trusted here\">+ certificate"
	    "</button><button class=\"ghost small\" data-act=\"cert-rehash\" "
	    "title=\"certctl rehash: the store made again from what FreeBSD "
	    "comes with and what this host was given\">Rehash</button>"
	    "<input class=\"filter\" id=\"filter\" data-input=\"filter\" "
	    "placeholder=\"Filter certificates\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "></div>");
	if (ct.error[0] != '\0') {
		h_raw(h, "<p class=\"error\">");
		h_txt(h, ct.error);
		h_raw(h, "</p>");
	}
	if (!mine) {
		h_raw(h, ct.loading ? "<p class=\"dim\">Reading the certificates…"
		    "</p>" : "");
		return;
	}
	h_raw(h, "<p class=\"dim\">What OpenSSL trusts: <code>");
	h_txt(h, jstr(ct.data, "trusted_dir"));
	h_raw(h, "</code>, made by certctl(8) from FreeBSD's own and those "
	    "given here (<code>");
	h_txt(h, jstr(ct.data, "added_dir"));
	h_raw(h, "</code>); one not trusted has a copy in <code>");
	h_txt(h, jstr(ct.data, "distrusted_dir"));
	h_raw(h, "</code>.");
	if (gone > 0)
		h_fmt(h, " <span class=\"chip bad\">%d ended</span>", gone);
	if (soon > 0)
		h_fmt(h, " <span class=\"chip warn\">%d end%s within 30 days"
		    "</span>", soon, soon == 1 ? "s" : "");
	if (!jbool(ct.data, "certctl"))
		h_raw(h, " <span class=\"chip warn\">no certctl here: nothing "
		    "is changed</span>");
	h_raw(h, "</p>");
	arr = jget(ct.data, ct.untrusted ? "untrusted" : "trusted");
	h_raw(h, "<table class=\"net certs\">");
	tbl_head(h, "certs", cols, 7, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("certs", arr, cols, 7, app.filter);
	for (n = 0; (c = rows[n]) != NULL; n++) {
		file = jstr(c, "file");
		local = jstr(c, "local");
		end = jint(c, "not_after", 0);
		h_raw(h, "<tr");
		h_attr(h, "title", jstr(c, "subject"));
		h_raw(h, "><td><b>");
		h_txt(h, cert_name(c));
		h_raw(h, "</b>");
		if (!jbool(c, "self_signed"))
			h_raw(h, " <span class=\"chip\" title=\"Signed by another"
			    "\">intermediate</span>");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(c, "org") != NULL ? jstr(c, "org") : "");
		h_raw(h, "</td><td>");
		h_txt(h, jstr(c, "country") != NULL ? jstr(c, "country") : "");
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(c, "key") != NULL ? jstr(c, "key") : "");
		t = (time_t)end;
		gmtime_r(&t, &tm);
		strftime(day, sizeof(day), "%Y-%m-%d", &tm);
		h_fmt(h, "</td><td class=\"%s\">%s</td><td>", end < now ? "bad" :
		    end < now + SOON ? "warn" : "", day);
		if (local != NULL) {
			h_raw(h, "<span class=\"mono\">");
			h_txt(h, local);
			h_raw(h, "</span>");
		} else if (ct.untrusted)
			h_raw(h, "<span class=\"chip\" title=\"FreeBSD itself "
			    "does not trust it: /usr/share/certs/untrusted\">"
			    "FreeBSD's</span>");
		h_raw(h, "</td><td class=\"acts\">");
		if (!ct.untrusted) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "cert-untrust\" title=\"Not trusted any more: a copy "
			    "among the untrusted, then certctl rehash\"");
			h_attr(h, "data-arg", file);
			h_attr(h, "data-value", cert_name(c));
			h_raw(h, ">Distrust</button>");
			if (local != NULL && (base = strrchr(local, '/')) !=
			    NULL && strstr(local, "/share/certs/untrusted/") ==
			    NULL) {
				h_raw(h, "<button class=\"icon\" data-act=\""
				    "cert-remove\" title=\"Take away the copy "
				    "given here\"");
				h_attr(h, "data-arg", base + 1);
				h_attr(h, "data-value", cert_name(c));
				h_raw(h, ">×</button>");
			}
		} else if (local != NULL) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "cert-trust\" title=\"Trusted again: its copy among "
			    "the untrusted taken away\"");
			h_attr(h, "data-arg", file);
			h_attr(h, "data-value", cert_name(c));
			h_raw(h, ">Trust again</button>");
		}
		h_raw(h, "</td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"7\" class=\"dim\">None.</td></tr>");
	free(rows);
	h_raw(h, "</tbody></table>");
}

bool
certs_modal(struct html *h)
{

	if (app.modal != MODAL_CERT_ADD)
		return (false);
	h_raw(h, "<form data-form=\"cert-add\"><h2>A certificate trusted here"
	    "</h2><p>A certificate authority of your own, as PEM: kept in "
	    "<code>share/certs/trusted</code> under the local base, where "
	    "certctl rehash finds it, and trusted by OpenSSL ");
	if (ct.jail[0] != '\0') {
		h_raw(h, "in the jail <b>");
		h_txt(h, ct.jail);
		h_raw(h, "</b>");
	} else
		h_raw(h, "on the host");
	h_raw(h, ". The certificate alone is kept: no key goes with it.</p>"
	    "<label>Name<input name=\"name\" spellcheck=\"false\" "
	    "autocomplete=\"off\" placeholder=\"example-root\" autofocus>"
	    "</label><label>Certificate<textarea name=\"pem\" rows=\"10\" "
	    "spellcheck=\"false\" class=\"mono\" placeholder=\"-----BEGIN "
	    "CERTIFICATE-----\"></textarea></label>");
	return (true);
}

bool
certs_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*name, *pem, *p;

	if (strcmp(form, "cert-add") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	name = jstr(f, "name") != NULL ? jstr(f, "name") : "";
	pem = jstr(f, "pem") != NULL ? jstr(f, "pem") : "";
	for (p = name; *p != '\0'; p++)
		if (!(*p >= 'a' && *p <= 'z') && !(*p >= 'A' && *p <= 'Z') &&
		    !(*p >= '0' && *p <= '9') && strchr("._-", *p) == NULL)
			break;
	if (name[0] == '\0' || name[0] == '.' || *p != '\0' || strlen(name) >
	    64) {
		snprintf(app.modal_error, sizeof(app.modal_error), "A name of "
		    "letters, digits and ._- only");
		return (true);
	}
	if (strstr(pem, "-----BEGIN CERTIFICATE-----") == NULL) {
		snprintf(app.modal_error, sizeof(app.modal_error), "A "
		    "certificate as PEM, -----BEGIN CERTIFICATE----- and on");
		return (true);
	}
	if (strstr(pem, "PRIVATE KEY") != NULL) {
		snprintf(app.modal_error, sizeof(app.modal_error), "A key is "
		    "not given away: the certificate alone");
		return (true);
	}
	cert_job(s, "add", name, pem);
	app.modal = MODAL_NONE;
	return (true);
}

bool
certs_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 body[600];

	if (strncmp(act, "cert", 4) != 0 && strcmp(act, "input:certs-jail") !=
	    0 && strncmp(act, "do-cert-", 8) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "input:certs-jail") == 0) {
		snprintf(ct.jail, sizeof(ct.jail), "%s", value);
		if (ct.data != NULL)
			ucl_object_unref(ct.data);
		ct.data = NULL;
		ct.error[0] = '\0';
		ct.loading = false;
		refresh_certs(s, true);
	} else if (strcmp(act, "certs-show") == 0)
		ct.untrusted = strcmp(arg, "untrusted") == 0;
	else if (strcmp(act, "cert-add") == 0) {
		app.modal = MODAL_CERT_ADD;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "cert-rehash") == 0)
		cert_job(s, "rehash", NULL, NULL);
	else if (strcmp(act, "cert-untrust") == 0) {
		snprintf(body, sizeof(body), "%s (%s) not trusted by OpenSSL on "
		    "%s%s%s any more: a copy of it among the untrusted, kept "
		    "across a rehash and an upgrade, until it is trusted again.",
		    value, arg, ct.jail[0] != '\0' ? ct.jail : s->name,
		    ct.jail[0] != '\0' ? " of " : "", ct.jail[0] != '\0' ?
		    s->name : "");
		confirm("Distrust the certificate", body, "Distrust", true, "",
		    "do-cert-untrust", arg, "");
	} else if (strcmp(act, "do-cert-untrust") == 0)
		cert_job(s, "untrust", arg, NULL);
	else if (strcmp(act, "cert-trust") == 0)
		cert_job(s, "trust", arg, NULL);
	else if (strcmp(act, "cert-remove") == 0) {
		snprintf(body, sizeof(body), "%s (%s), given to this host, taken "
		    "away: OpenSSL does not trust it here after the rehash.",
		    value, arg);
		confirm("Take the certificate away", body, "Take away", true,
		    "", "do-cert-remove", arg, "");
	} else if (strcmp(act, "do-cert-remove") == 0)
		cert_job(s, "remove", arg, NULL);
	return (true);
}
